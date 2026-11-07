package server

// Port of packages/server/src/token-signing.ts: signs IAM session JWTs with the deployment's `sts.jwt` keys and
// verifies them with the same checks downstream verifiers apply. Verification here proves only the signature and
// claims; IAM additionally requires the stored session row (principals.go), so revocation inside IAM is immediate.

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"math/big"
	"regexp"
	"sync"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

var (
	signingKidPattern      = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	signingAudiencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
)

var signingPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k"}

const maxCachedSigningVerifiers = 32

// invalidSigning is `invalid(field, detail)`: INVALID_CONFIG `sts.jwt.<field> <detail>`.
func invalidSigning(field, detail string) error {
	return core.NewIamError("INVALID_CONFIG", "sts.jwt."+field+" "+detail)
}

// checkedSigningKey is a validated configured JWK.
type checkedSigningKey struct {
	kid string
	alg string
	// signer is the private key of a signing key (nil for a verification key).
	signer    crypto.Signer
	publicJwk *core.Object
}

// checkSigningKey validates one configured JWK and derives its public projection; `signing` keys must be private.
func checkSigningKey(jwk *core.Object, field string, signing bool) (*checkedSigningKey, error) {
	if jwk == nil {
		return nil, invalidSigning(field, "must contain JWK objects")
	}
	pair := ""
	if jwk.Get("kty") == "OKP" && jwk.Get("crv") == "Ed25519" && jwk.Get("alg") == "EdDSA" {
		pair = "EdDSA"
	} else if jwk.Get("kty") == "EC" && jwk.Get("crv") == "P-256" && jwk.Get("alg") == "ES256" {
		pair = "ES256"
	}
	if pair == "" {
		return nil, invalidSigning(field, "keys must be kty OKP/crv Ed25519/alg EdDSA or kty EC/crv P-256/alg ES256")
	}
	kid, ok := jwk.Get("kid").(string)
	if !ok || !signingKidPattern.MatchString(kid) {
		return nil, invalidSigning(field, "keys need a kid matching /^[A-Za-z0-9._-]{1,64}$/")
	}
	if use := jwk.Get("use"); !isUndefined(use) && use != "sig" {
		return nil, invalidSigning(field, "keys must have use 'sig'")
	}
	operation := "verify"
	if signing {
		operation = "sign"
	}
	if ops := jwk.Get("key_ops"); !isUndefined(ops) {
		list, ok := ops.([]any)
		found := false
		for _, item := range list {
			found = found || item == operation
		}
		if !ok || !found {
			return nil, invalidSigning(field, "key_ops must include '"+operation+"'")
		}
	}
	x, okX := jwk.Get("x").(string)
	y, okY := jwk.Get("y").(string)
	if !okX || (pair == "ES256" && !okY) {
		return nil, invalidSigning(field, "keys need their public coordinates")
	}
	d, okD := jwk.Get("d").(string)
	if signing {
		if !okD {
			return nil, invalidSigning(field, "keys must be private keys")
		}
	} else {
		for _, member := range signingPrivateMembers {
			if !isUndefined(jwk.Get(member)) {
				return nil, invalidSigning(field, "must contain public keys only")
			}
		}
	}
	// Parse the key material now, so a broken key fails at construction rather than at the first issuance.
	broken := invalidSigning(field, "key "+kid+" is not a valid "+pair+" key")
	var signer crypto.Signer
	if pair == "EdDSA" {
		if signing {
			seed := nodeBase64Decode(d)
			if len(seed) != ed25519.SeedSize {
				return nil, broken
			}
			private := ed25519.NewKeyFromSeed(seed)
			if base64url(private.Public().(ed25519.PublicKey)) != x {
				return nil, broken
			}
			signer = private
		} else if len(nodeBase64Decode(x)) != ed25519.PublicKeySize {
			return nil, broken
		}
	} else {
		public, err := sjwtECPoint(core.NewObject("crv", "P-256", "x", x, "y", y))
		if err != nil {
			return nil, broken
		}
		if signing {
			scalar := new(big.Int).SetBytes(nodeBase64Decode(d))
			if scalar.Sign() == 0 || scalar.Cmp(elliptic.P256().Params().N) >= 0 {
				return nil, broken
			}
			if _, err := ecdh.P256().NewPrivateKey(scalar.FillBytes(make([]byte, 32))); err != nil {
				return nil, broken
			}
			// The derived public key is the configured point, exported with coordinates padded to 32 bytes.
			if base64url(public.X.FillBytes(make([]byte, 32))) != x || base64url(public.Y.FillBytes(make([]byte, 32))) != y {
				return nil, broken
			}
			signer = &ecdsa.PrivateKey{PublicKey: *public, D: scalar}
		}
	}
	publicJwk := core.NewObject("kty", jwk.Get("kty"), "crv", jwk.Get("crv"), "x", x)
	if pair == "ES256" {
		publicJwk.Set("y", y)
	}
	publicJwk.Set("kid", kid)
	publicJwk.Set("alg", pair)
	publicJwk.Set("use", "sig")
	return &checkedSigningKey{kid: kid, alg: pair, signer: signer, publicJwk: publicJwk}, nil
}

// checkSigningIssuer validates the issuer: an absolute http(s) URL without credentials, query or fragment, matching the
// audience pattern.
func checkSigningIssuer(value string) (string, error) {
	u, err := auth.ParseFetchURL(value)
	if err != nil || (u.Protocol != "https:" && u.Protocol != "http:") || urlUsername(u) != "" || urlPassword(u) != "" ||
		signingURLSearch(u) != "" || signingURLHash(u) != "" || !signingAudiencePattern.MatchString(value) {
		return "", invalidSigning("issuer", "must be an absolute http(s) URL without credentials, query or fragment")
	}
	return value, nil
}

// signingURLSearch is URL#search ("" for an empty query).
func signingURLSearch(u *auth.FetchURL) string {
	if u.RawQuery == "" {
		return ""
	}
	return "?" + u.RawQuery
}

// signingURLHash is URL#hash ("" for an empty fragment).
func signingURLHash(u *auth.FetchURL) string {
	if u.Fragment == "" {
		return ""
	}
	return "#" + u.Fragment
}

// CreateSessionTokenSigner (token-signing.ts createSessionTokenSigner): the deployment's session token signer, or nil
// when sts.jwt is not configured. Every option is validated synchronously (INVALID_CONFIG).
func CreateSessionTokenSigner(options *SessionTokenSigningOptions, issuer string, now func() int64) (result *SessionTokenSigner, err error) {
	if options == nil {
		return nil, nil
	}
	signingKeys := options.SigningKeys
	if len(signingKeys) < 1 || len(signingKeys) > 10 {
		return nil, invalidSigning("signingKeys", "must contain 1 to 10 keys")
	}
	verificationKeys := options.VerificationKeys
	if len(verificationKeys) > 10 {
		return nil, invalidSigning("verificationKeys", "must contain at most 10 keys")
	}
	signing := make([]*checkedSigningKey, 0, len(signingKeys))
	for _, key := range signingKeys {
		checked, err := checkSigningKey(key, "signingKeys", true)
		if err != nil {
			return nil, err
		}
		signing = append(signing, checked)
	}
	retired := make([]*checkedSigningKey, 0, len(verificationKeys))
	for _, key := range verificationKeys {
		checked, err := checkSigningKey(key, "verificationKeys", false)
		if err != nil {
			return nil, err
		}
		retired = append(retired, checked)
	}
	all := append(append([]*checkedSigningKey{}, signing...), retired...)
	kids := map[string]bool{}
	for _, key := range all {
		if kids[key.kid] {
			return nil, invalidSigning("signingKeys", "kid "+key.kid+" is used more than once")
		}
		kids[key.kid] = true
	}
	activeKeyID := signing[0].kid
	if options.ActiveKeyID != nil {
		activeKeyID = *options.ActiveKeyID
	}
	var active *checkedSigningKey
	for _, key := range signing {
		if key.kid == activeKeyID {
			active = key
			break
		}
	}
	if active == nil {
		return nil, invalidSigning("activeKeyId", "must name one of the signing keys")
	}
	issuerValue := issuer
	if options.Issuer != nil {
		issuerValue = *options.Issuer
	}
	if issuerValue, err = checkSigningIssuer(issuerValue); err != nil {
		return nil, err
	}
	configured := options.Audiences
	if len(configured) > 50 {
		return nil, invalidSigning("audiences", "must be an array of at most 50 audiences")
	}
	for _, audience := range configured {
		if !signingAudiencePattern.MatchString(audience) {
			return nil, invalidSigning("audiences", "entries must match /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/")
		}
	}
	audiences := unique(append([]string{issuerValue}, configured...))
	maxLifetimeSeconds := 3600.0
	if options.MaxLifetimeSeconds != nil {
		maxLifetimeSeconds = *options.MaxLifetimeSeconds
	}
	if !core.IsSafeInteger(maxLifetimeSeconds) || maxLifetimeSeconds < 300 || maxLifetimeSeconds > 43200 {
		return nil, invalidSigning("maxLifetimeSeconds", "must be an integer from 300 to 43200")
	}
	if now == nil {
		return nil, invalidSigning("options", "need a clock")
	}
	keys := make([]any, 0, len(all))
	for _, key := range all {
		keys = append(keys, key.publicJwk)
	}
	return &SessionTokenSigner{
		Issuer: issuerValue, Audiences: audiences, MaxLifetimeSeconds: maxLifetimeSeconds,
		active: active, jwks: core.NewObject("keys", keys), now: now, verifiers: map[string]*SessionTokenVerifier{},
	}, nil
}

// SessionTokenSigner is token-signing.ts SessionTokenSigner.
type SessionTokenSigner struct {
	// Issuer The `iss` of every token.
	Issuer string
	// Audiences The audiences tokens may be issued for; always includes the issuer (first).
	Audiences []string
	// MaxLifetimeSeconds Longest allowed `exp - iat`, in seconds.
	MaxLifetimeSeconds float64

	active *checkedSigningKey
	jwks   *core.Object
	now    func() int64

	mu        sync.Mutex
	verifiers map[string]*SessionTokenVerifier
}

// verifier is the cached verifier of an audience (the cache is cleared once it holds 32).
func (s *SessionTokenSigner) verifier(audience string) (*SessionTokenVerifier, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if found, ok := s.verifiers[audience]; ok {
		return found, nil
	}
	maxLifetime := s.MaxLifetimeSeconds
	tolerance := 5.0
	found, err := CreateSessionTokenVerifier(&SessionTokenVerifierOptions{
		Issuer: s.Issuer, Audience: audience, JWKS: s.jwks, ClockToleranceSeconds: &tolerance,
		MaxLifetimeSeconds: &maxLifetime, Now: s.now,
	})
	if err != nil {
		return nil, err
	}
	if len(s.verifiers) >= maxCachedSigningVerifiers {
		s.verifiers = map[string]*SessionTokenVerifier{}
	}
	s.verifiers[audience] = found
	return found, nil
}

// Sign (token-signing.ts SessionTokenSigner.sign): Signs the claims with the active key; the header is `{ alg, kid,
// typ: 'biam-session+jwt' }`.
func (s *SessionTokenSigner) Sign(ctx context.Context, claims *core.Object) (result string, err error) {
	header := core.NewObject("alg", s.active.alg, "kid", s.active.kid, "typ", SessionTokenType)
	return sjwtSign(header, claims, s.active.signer, s.active.alg)
}

// Verify (token-signing.ts SessionTokenSigner.verify): Verifies a token for `audience` ("" for the issuer) with a 5
// second clock tolerance.
func (s *SessionTokenSigner) Verify(ctx context.Context, token string, audience string) (result *core.Object, err error) {
	if audience == "" {
		audience = s.Issuer
	}
	checker, err := s.verifier(audience)
	if err != nil {
		return nil, &SessionTokenError{Reason: "audience"}
	}
	return checker.Verify(ctx, token)
}

// PublicJwks (token-signing.ts SessionTokenSigner.publicJwks): The public members of the signing and verification
// keys, for the JWKS route.
func (s *SessionTokenSigner) PublicJwks() (result *core.Object, err error) {
	keys, _ := s.jwks.Get("keys").([]any)
	copies := make([]any, 0, len(keys))
	for _, key := range keys {
		copies = append(copies, key.(*core.Object).Clone())
	}
	return core.NewObject("keys", copies), nil
}
