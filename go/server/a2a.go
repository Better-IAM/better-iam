package server

// Port of packages/server/src/a2a.ts: IAM-attested A2A agent cards. An agent's A2A server builds its agent card (the
// Agent2Agent protocol's `/.well-known/agent-card.json`) and asks Better IAM to sign it (`agents.signCard`). IAM checks
// that the card's endpoints belong to the agent's registered `url`, sets the card's `provider.organization` to the
// tenant, adds an attestation extension (who the agent is, which organization runs it, that a person sponsors it, when
// the attestation expires), and signs the canonical card (RFC 8785) as a detached JWS, the A2A card signature format.
// Anyone holding the deployment's card keys (`iam.a2a.jwks()`, published at `a2a.jwksUrl`) can then check that a
// remote agent is a registered agent in good standing of a given organization.

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"io"
	"math/big"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// AgentAttestationURI is the URI of the attestation extension IAM adds to `capabilities.extensions` of every card it
// signs.
const AgentAttestationURI = "urn:better-iam:a2a:attestation:v1"

var cardKidPattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var cardPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k"}

const maxCardBytes = 64 * 1024

// a2aInvalid is `invalid(detail)`: INVALID_CONFIG `a2a.<detail>`.
func a2aInvalid(detail string) error {
	return core.NewIamError("INVALID_CONFIG", "a2a."+detail)
}

// cardKeyEntry is a2a.ts CardKey: a validated configured JWK.
type cardKeyEntry struct {
	kid string
	alg string
	// signer is the private key of a signing key (nil for a verification key).
	signer    crypto.Signer
	publicJwk *core.Object
}

// cardKey validates one configured JWK (cardKey); `signing` keys must be private.
func cardKey(jwk *core.Object, field string, signing bool) (*cardKeyEntry, error) {
	if jwk == nil {
		return nil, a2aInvalid(field + " must contain JWK objects")
	}
	alg := ""
	if jwk.Get("kty") == "OKP" && jwk.Get("crv") == "Ed25519" && jwk.Get("alg") == "EdDSA" {
		alg = "EdDSA"
	} else if jwk.Get("kty") == "EC" && jwk.Get("crv") == "P-256" && jwk.Get("alg") == "ES256" {
		alg = "ES256"
	}
	if alg == "" {
		return nil, a2aInvalid(field + " keys must be kty OKP/crv Ed25519/alg EdDSA or kty EC/crv P-256/alg ES256")
	}
	kid, ok := jwk.Get("kid").(string)
	if !ok || !cardKidPattern.MatchString(kid) {
		return nil, a2aInvalid(field + " keys need a kid matching /^[A-Za-z0-9._-]{1,64}$/")
	}
	if use := jwk.Get("use"); !isUndefined(use) && use != "sig" {
		return nil, a2aInvalid(field + " keys must have use 'sig'")
	}
	x, okX := jwk.Get("x").(string)
	y, okY := jwk.Get("y").(string)
	if !okX || (alg == "ES256" && !okY) {
		return nil, a2aInvalid(field + " keys need their public coordinates")
	}
	d, okD := jwk.Get("d").(string)
	if signing {
		if !okD {
			return nil, a2aInvalid(field + " must contain private keys")
		}
	} else {
		for _, name := range cardPrivateMembers {
			if !isUndefined(jwk.Get(name)) {
				return nil, a2aInvalid(field + " must contain public keys only")
			}
		}
	}
	broken := a2aInvalid(field + " key " + kid + " is not a valid " + alg + " key")
	var signer crypto.Signer
	if alg == "EdDSA" {
		if signing {
			seed := nodeBase64Decode(d)
			if len(seed) != ed25519.SeedSize {
				return nil, broken
			}
			private := ed25519.NewKeyFromSeed(seed)
			// The derived public key must be the configured one.
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
	if alg == "ES256" {
		publicJwk.Set("y", y)
	}
	publicJwk.Set("kid", kid)
	publicJwk.Set("alg", alg)
	publicJwk.Set("use", "sig")
	return &cardKeyEntry{kid: kid, alg: alg, signer: signer, publicJwk: publicJwk}, nil
}

// a2aHTTPURL is `httpUrl(value, field)`: an absolute http(s) URL without credentials.
func a2aHTTPURL(value string, field string) (string, error) {
	u, err := auth.ParseFetchURL(value)
	if err != nil || (u.Protocol != "https:" && u.Protocol != "http:") || urlUsername(u) != "" || urlPassword(u) != "" {
		return "", a2aInvalid(field + " must be an absolute http(s) URL without credentials")
	}
	return value, nil
}

// createCardSigner validates the `a2a` option (nil without it).
func createCardSigner(server *ServerContext) (*CardSignerType, error) {
	if server.Options == nil || server.Options.A2a == nil {
		return nil, nil
	}
	options := server.Options.A2a
	signingKeys := options.SigningKeys
	if len(signingKeys) < 1 || len(signingKeys) > 10 {
		return nil, a2aInvalid("signingKeys must contain 1 to 10 keys")
	}
	verificationKeys := options.VerificationKeys
	if len(verificationKeys) > 10 {
		return nil, a2aInvalid("verificationKeys must contain at most 10 keys")
	}
	signing := make([]*cardKeyEntry, 0, len(signingKeys))
	for _, key := range signingKeys {
		checked, err := cardKey(key, "signingKeys", true)
		if err != nil {
			return nil, err
		}
		signing = append(signing, checked)
	}
	retired := make([]*cardKeyEntry, 0, len(verificationKeys))
	for _, key := range verificationKeys {
		checked, err := cardKey(key, "verificationKeys", false)
		if err != nil {
			return nil, err
		}
		retired = append(retired, checked)
	}
	all := append(append([]*cardKeyEntry{}, signing...), retired...)
	kids := map[string]bool{}
	for _, key := range all {
		if kids[key.kid] {
			return nil, a2aInvalid("kid " + key.kid + " is used more than once")
		}
		kids[key.kid] = true
	}
	activeKeyID := signing[0].kid
	if options.ActiveKeyID != nil {
		activeKeyID = *options.ActiveKeyID
	}
	var active *cardKeyEntry
	for _, key := range signing {
		if key.kid == activeKeyID {
			active = key
			break
		}
	}
	if active == nil {
		return nil, a2aInvalid("activeKeyId must name one of the signing keys")
	}
	lifetimeSeconds := 3600.0
	if options.CardLifetimeSeconds != nil {
		lifetimeSeconds = *options.CardLifetimeSeconds
	}
	if !core.IsSafeInteger(lifetimeSeconds) || lifetimeSeconds < 300 || lifetimeSeconds > 604_800 {
		return nil, a2aInvalid("cardLifetimeSeconds must be an integer from 300 to 604800")
	}
	issuer := urlOrigin(server.Config.BaseURL) + server.Config.BasePath
	if options.Issuer != nil {
		checked, err := a2aHTTPURL(*options.Issuer, "issuer")
		if err != nil {
			return nil, err
		}
		issuer = checked
	}
	jwksURL := ""
	if options.JwksURL != nil {
		checked, err := a2aHTTPURL(*options.JwksURL, "jwksUrl")
		if err != nil {
			return nil, err
		}
		jwksURL = checked
	}
	keys := make([]any, 0, len(all))
	for _, key := range all {
		keys = append(keys, key.publicJwk)
	}
	return &CardSignerType{
		server: server, Issuer: issuer, JwksURL: jwksURL, LifetimeSeconds: lifetimeSeconds,
		Jwks: core.NewObject("keys", keys), active: active, all: all,
	}, nil
}

// cardSignerMemo is one context's card signer, or the INVALID_CONFIG error its option fails with.
type cardSignerMemo struct {
	signer *CardSignerType
	err    error
}

// signers holds the card signer of each context (a2a.ts signers, a WeakMap keyed by the context).
var signers sync.Map

// CardSigner (a2a.ts cardSigner): The deployment's card signer, validated once per context; nil without the `a2a`
// option.
func CardSigner(server *ServerContext) (result *CardSignerType, err error) {
	if found, ok := signers.Load(server); ok {
		memo := found.(*cardSignerMemo)
		return memo.signer, memo.err
	}
	signer, err := createCardSigner(server)
	found, _ := signers.LoadOrStore(server, &cardSignerMemo{signer: signer, err: err})
	memo := found.(*cardSignerMemo)
	return memo.signer, memo.err
}

// A2aRuntime is a2a.ts A2aRuntime: `iam.a2a`, the card-signing keys for the route that publishes them.
type A2aRuntime struct {
	server *ServerContext
	signer *CardSignerType
	// configErr is the INVALID_CONFIG error createA2aRuntime throws for an invalid `a2a` option.
	configErr error
	// Enabled Whether cards can be signed (the `a2a` option is set).
	Enabled bool
}

// ConfigError is the INVALID_CONFIG error createA2aRuntime throws for an invalid `a2a` option (nil when it is valid
// or absent); construction checks it.
func (s *A2aRuntime) ConfigError() error { return s.configErr }

// Jwks (a2a.ts A2aRuntime.jwks): The public card keys (signing and retired), for verifiers. Empty without the `a2a`
// option.
func (s *A2aRuntime) Jwks() (result *core.Object, err error) {
	keys := []any{}
	if s.signer != nil {
		list, _ := s.signer.Jwks.Get("keys").([]any)
		for _, key := range list {
			keys = append(keys, key.(*core.Object).Spread())
		}
	}
	return core.NewObject("keys", keys), nil
}

// JwksResponse (a2a.ts A2aRuntime.jwksResponse): A GET response publishing `jwks()`, cacheable for five minutes:
// serve it at `a2a.jwksUrl`.
func (s *A2aRuntime) JwksResponse() (result *http.Response, err error) {
	jwks, err := s.Jwks()
	if err != nil {
		return nil, err
	}
	text, _, err := core.Stringify(jwks)
	if err != nil {
		return nil, err
	}
	body := utf8Bytes(text)
	header := http.Header{}
	header.Set("content-type", "application/jwk-set+json")
	header.Set("cache-control", "public, max-age=300")
	header.Set("access-control-allow-origin", "*")
	return &http.Response{
		Status: "200 OK", StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: header,
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
	}, nil
}

// DelegationTokenReplay is the `replay` option of VerifyDelegationToken: it records a verified token id until it
// expires and returns false when it was seen before, to refuse the replay.
type DelegationTokenReplay func(ctx context.Context, tokenID string, expiresAt float64) (bool, error)

// VerifyDelegationToken (a2a.ts A2aRuntime.verifyDelegationToken): Verifies a delegation token
// (`delegations.issueToken`) this deployment issued, for a service running next to it: the signature with the
// deployment's keys, the type, the issuer, `audience`, `tenantId` when given, and the times. With `live`, also that
// everything it stands on is still in place (the delegation chain, the person, the agents and the agent's key, the
// audience and the scopes), so a revocation takes effect before the token expires. Throws DELEGATION_TOKEN_INVALID
// (401). options holds audience, tenantId, live, clockToleranceSeconds and replay (a DelegationTokenReplay, set with
// SetRaw).
func (s *A2aRuntime) VerifyDelegationToken(ctx context.Context, token string, options *core.Object) (result *core.Object, err error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	signer := s.signer
	if signer == nil {
		return nil, core.NewIamError("FEATURE_DISABLED", "Delegation tokens need the a2a option", 403)
	}
	invalidToken := func(message string) error { return core.NewIamError("DELEGATION_TOKEN_INVALID", message, 401) }
	if options == nil {
		options = core.NewObject()
	}
	if utf16Len(token) > 16_384 {
		return nil, invalidToken("Not a delegation token")
	}
	claims, err := signer.VerifyJwt(ctx, token, core.DelegationTokenType)
	if err != nil {
		return nil, err
	}
	if claims == nil {
		return nil, invalidToken("The delegation token does not verify")
	}
	audience, _ := options.Get("audience").(string)
	expected := core.DelegationTokenExpectations{Issuers: []string{signer.Issuer}, Audience: audience, Now: float64(s.server.Now())}
	if tenantID := options.Get("tenantId"); !isUndefined(tenantID) {
		value := jsString(tenantID)
		expected.TenantID = &value
	}
	if tolerance := options.Get("clockToleranceSeconds"); !isUndefined(tolerance) {
		value := jsNumber(tolerance)
		expected.ClockToleranceSeconds = &value
	}
	read, err := core.ReadDelegationTokenClaims(claims, expected)
	if err != nil {
		return nil, err
	}
	if read.Token == nil {
		return nil, invalidToken(read.Message)
	}
	verified := read.Token
	if truthy(options.Get("live")) {
		err := s.server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			// The record kept at issue time: the token's own key, audience, scopes and session limits.
			record, err := tx.Get(ctx, "delegationTokens", verified.TokenID)
			if err != nil {
				return err
			}
			gone := invalidToken("What the delegation token stands on is no longer in place")
			if record == nil || record.Get("tenantId") != verified.TenantID ||
				record.Get("delegationId") != verified.DelegationID || record.Get("personId") != verified.PersonID ||
				record.Get("agentId") != verified.AgentID || record.Get("audience") != verified.Audience ||
				joinValues(record.Get("scopes"), " ") != strings.Join(verified.Scopes, " ") {
				return gone
			}
			stands, err := TokenStillStands(ctx, s.server, tx, record, s.server.Now())
			if err != nil {
				return err
			}
			if !stands {
				return gone
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	if replay, ok := options.Get("replay").(DelegationTokenReplay); ok && replay != nil {
		fresh, err := replay(ctx, verified.TokenID, verified.ExpiresAt)
		if err != nil {
			return nil, err
		}
		if !fresh {
			return nil, invalidToken("The delegation token was used before")
		}
	}
	model, err := ToModel(verified)
	if err != nil {
		return nil, err
	}
	summary, _ := model.(*core.Object)
	return summary, nil
}

// joinValues is `array.join(separator)` over a stored list (members as JavaScript strings; "" for a non-array).
func joinValues(value any, separator string) string {
	list, ok := value.([]any)
	if !ok {
		return ""
	}
	parts := make([]string, len(list))
	for index, item := range list {
		if !nullish(item) {
			parts[index] = jsString(item)
		}
	}
	return strings.Join(parts, separator)
}

// CreateA2aRuntime builds the A2aRuntime (a2a.ts createA2aRuntime): it validates the `a2a` option (reported by
// ConfigError, which construction checks) and exposes the public keys.
func CreateA2aRuntime(server *ServerContext) *A2aRuntime {
	signer, err := CardSigner(server)
	return &A2aRuntime{server: server, signer: signer, configErr: err, Enabled: signer != nil}
}

// a2aPlain is `plain(value)`: a non-array object.
func a2aPlain(value any) (*core.Object, bool) {
	object, ok := value.(*core.Object)
	return object, ok && object != nil
}

// a2aRefuse is `refuse(message)`: INVALID_INPUT.
func a2aRefuse(message string) error { return core.NewIamError("INVALID_INPUT", message) }

// endpointOn checks a card endpoint: an http(s) URL on the agent's registered origin.
func endpointOn(value any, field string, origin string) error {
	var parsed *auth.FetchURL
	if text, ok := value.(string); ok {
		if u, err := auth.ParseFetchURL(text); err == nil {
			parsed = u
		}
	}
	if parsed == nil || (parsed.Protocol != "https:" && parsed.Protocol != "http:") {
		return a2aRefuse(field + " must be an http(s) URL")
	}
	if urlOrigin(parsed) != origin {
		return a2aRefuse(field + " must be on the agent's registered origin " + origin + " (set the agent's url)")
	}
	return nil
}

// SignAgentCard (a2a.ts signAgentCard): Signs `input` for `agent`: an A2A agent card whose `url` (and every
// `additionalInterfaces[].url`) is on the origin of the agent's registered `url`. The caller has already been
// authorized; the agent must be in good standing. Returns `{ card, attestation, expiresAt }`.
func SignAgentCard(ctx context.Context, server *ServerContext, tenant *core.Object, agent *core.Object, input any) (result *core.Object, err error) {
	signer, err := CardSigner(server)
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, core.NewIamError("FEATURE_DISABLED", "Agent card signing is not enabled (a2a option)", 403)
	}
	profile, _ := agent.Get("agent").(*core.Object)
	if profile == nil || !truthy(profile.Get("url")) {
		return nil, a2aRefuse("Register the agent’s url before signing its card")
	}
	source, ok := a2aPlain(input)
	if !ok {
		return nil, a2aRefuse("card must be an A2A agent card object")
	}
	registered, err := auth.ParseFetchURL(jsString(profile.Get("url")))
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	origin := urlOrigin(registered)
	card := source.Spread()
	card.Delete("signatures")
	name, ok := card.Get("name").(string)
	if !ok || core.JSTrim(name) == "" || utf16Len(name) > 256 {
		return nil, a2aRefuse("card.name must be 1-256 characters")
	}
	if err := endpointOn(card.Get("url"), "card.url", origin); err != nil {
		return nil, err
	}
	// Every endpoint the card offers (A2A 0.3 `additionalInterfaces`, 1.0 `supportedInterfaces`) is pinned the same way.
	for _, field := range []string{"additionalInterfaces", "supportedInterfaces"} {
		interfaces := card.Get(field)
		if isUndefined(interfaces) {
			continue
		}
		list, ok := interfaces.([]any)
		if !ok || len(list) > 16 {
			return nil, a2aRefuse("card." + field + " must list at most 16 interfaces")
		}
		for index, item := range list {
			entry, ok := a2aPlain(item)
			if !ok {
				return nil, a2aRefuse("card." + field + "[" + strconv.Itoa(index) + "] must be an object")
			}
			if err := endpointOn(entry.Get("url"), "card."+field+"["+strconv.Itoa(index)+"].url", origin); err != nil {
				return nil, err
			}
		}
	}
	rawCapabilities := card.Get("capabilities")
	if !isUndefined(rawCapabilities) {
		if _, ok := a2aPlain(rawCapabilities); !ok {
			return nil, a2aRefuse("card.capabilities must be an object")
		}
	}
	capabilities := core.NewObject()
	if given, ok := a2aPlain(rawCapabilities); ok {
		capabilities = given.Spread()
	}
	rawExtensions := capabilities.Get("extensions")
	extensionList, isList := rawExtensions.([]any)
	if !isUndefined(rawExtensions) && !isList {
		return nil, a2aRefuse("card.capabilities.extensions must be an array")
	}
	now := server.Now()
	expiresAt := float64(now) + signer.LifetimeSeconds*1000
	attestation := core.NewObject(
		"issuer", signer.Issuer, "tenantId", tenant.Get("id"), "organization", tenant.Get("name"),
		"agentId", agent.Get("id"), "agentName", agent.Get("name"), "sponsored", true,
		"delegable", profile.Get("delegable") != false,
	)
	if model := profile.Get("model"); !isUndefined(model) {
		attestation.Set("model", model)
	}
	if provider := profile.Get("provider"); !isUndefined(provider) {
		attestation.Set("provider", provider)
	}
	if protocols, ok := profile.Get("protocols").([]any); ok && len(protocols) > 0 {
		attestation.Set("protocols", append([]any{}, protocols...))
	}
	attestation.Set("issuedAt", isoString(float64(now)))
	attestation.Set("expiresAt", isoString(expiresAt))
	// Any attestation already in the card is dropped: only IAM's own, signed below, may stand.
	extensions := []any{}
	for _, item := range extensionList {
		if entry, ok := a2aPlain(item); !ok || entry.Get("uri") != AgentAttestationURI {
			extensions = append(extensions, item)
		}
	}
	extensions = append(extensions, core.NewObject(
		"uri", AgentAttestationURI,
		"description", "This agent is registered with, and attested by, Better IAM.",
		"required", false,
		"params", attestation,
	))
	unsigned := card.Spread()
	// The provider is the organization, reached at the agent's registered origin (never a URL the card chose).
	unsigned.Set("provider", core.NewObject("organization", tenant.Get("name"), "url", origin))
	unsigned.Set("capabilities", capabilities.Spread().Set("extensions", extensions))
	canonical, err := core.CanonicalizeJSON(unsigned)
	if err != nil {
		return nil, a2aRefuse("card must be plain JSON")
	}
	payload := utf8Bytes(canonical)
	if len(payload) > maxCardBytes {
		return nil, a2aRefuse("card must be at most 64 KiB")
	}
	signature, err := signer.Sign(ctx, payload)
	if err != nil {
		return nil, err
	}
	// A copy of exactly what was signed, sharing nothing with the input.
	parsed, err := core.ParseJSONString(canonical)
	if err != nil {
		return nil, err
	}
	signed, _ := parsed.(*core.Object)
	signed.Set("signatures", []any{signature})
	return core.NewObject("card", signed, "attestation", attestation, "expiresAt", expiresAt), nil
}

// CardSignerType is a2a.ts CardSigner.
type CardSignerType struct {
	server          *ServerContext
	Issuer          string
	JwksURL         string
	LifetimeSeconds float64
	Jwks            *core.Object

	active *cardKeyEntry
	all    []*cardKeyEntry
}

// header is the protected header of a signature by the active key with type typ (`jku` when a JWKS URL is set).
func (s *CardSignerType) header(typ string) *core.Object {
	header := core.NewObject("alg", s.active.alg, "kid", s.active.kid, "typ", typ)
	if s.JwksURL != "" {
		header.Set("jku", s.JwksURL)
	}
	return header
}

// jwsSignature is the JWS signature of input with the active key (raw R||S for ES256).
func (s *CardSignerType) jwsSignature(input []byte) ([]byte, error) {
	switch private := s.active.signer.(type) {
	case ed25519.PrivateKey:
		return ed25519.Sign(private, input), nil
	case *ecdsa.PrivateKey:
		digest := crypto.SHA256.New()
		digest.Write(input)
		r, sValue, err := ecdsa.Sign(rand.Reader, private, digest.Sum(nil))
		if err != nil {
			return nil, err
		}
		size := (private.Curve.Params().BitSize + 7) / 8
		signature := make([]byte, 2*size)
		r.FillBytes(signature[:size])
		sValue.FillBytes(signature[size:])
		return signature, nil
	}
	return nil, sjwtFail("JOSENotSupported", "alg "+s.active.alg+" is not supported")
}

// Sign (a2a.ts CardSigner.sign): signs payload as a flattened JWS with the active key and `typ: JOSE`; returns the
// detached signature `{ protected, signature }`.
func (s *CardSignerType) Sign(ctx context.Context, payload []byte) (result *core.Object, err error) {
	headerJSON, _, err := core.Stringify(s.header("JOSE"))
	if err != nil {
		return nil, err
	}
	protected := base64url(utf8Bytes(headerJSON))
	signature, err := s.jwsSignature([]byte(protected + "." + base64url(payload)))
	if err != nil {
		return nil, err
	}
	return core.NewObject("protected", protected, "signature", base64url(signature)), nil
}

// SignJwt (a2a.ts CardSigner.signJwt): Signs `claims` as a compact JWT with the active key and an explicit `typ`
// (never `JOSE`, the card type).
func (s *CardSignerType) SignJwt(ctx context.Context, claims *core.Object, typ string) (result string, err error) {
	headerJSON, _, err := core.Stringify(s.header(typ))
	if err != nil {
		return "", err
	}
	payloadJSON, _, err := core.Stringify(claims)
	if err != nil {
		return "", err
	}
	input := base64url(utf8Bytes(headerJSON)) + "." + base64url(utf8Bytes(payloadJSON))
	signature, err := s.jwsSignature([]byte(input))
	if err != nil {
		return "", err
	}
	return input + "." + base64url(signature), nil
}

// VerifyJwt (a2a.ts CardSigner.verifyJwt): Verifies a compact JWT of type `typ` with the published keys; the
// payload, or nil when it does not verify.
func (s *CardSignerType) VerifyJwt(ctx context.Context, token string, typ string) (result *core.Object, err error) {
	header, err := sjwtDecodeProtectedHeader(token)
	if err != nil {
		return nil, nil
	}
	var found *cardKeyEntry
	for _, item := range s.all {
		if core.StrictEquals(header.Get("kid"), item.kid) && core.StrictEquals(header.Get("alg"), item.alg) {
			found = item
			break
		}
	}
	if found == nil || !core.StrictEquals(header.Get("typ"), typ) || !isUndefined(header.Get("crit")) {
		return nil, nil
	}
	entry, err := sjwtJwsAlgorithm(found.alg)
	if err != nil {
		return nil, nil
	}
	publicKey, err := sjwtImportJwk(entry, found.publicJwk)
	if err != nil {
		return nil, nil
	}
	// compactVerify: three parts, a JSON object header naming an allowed alg, a valid signature, a decodable payload.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil
	}
	parsedHeader, err := sjwtParseHeader(parts[0], "JWSInvalid", "JWS Protected Header is invalid")
	if err != nil || parsedHeader.Get("alg") != found.alg {
		return nil, nil
	}
	signature, err := sjwtDecode(parts[2])
	if err != nil {
		return nil, nil
	}
	if !sjwtVerifySignature(entry, publicKey, signature, []byte(parts[0]+"."+parts[1])) {
		return nil, nil
	}
	payload, err := sjwtDecode(parts[1])
	if err != nil {
		return nil, nil
	}
	text := strings.TrimPrefix(decodeUTF8(payload), string(rune(0xFEFF)))
	claims, err := core.ParseJSONString(text)
	if err != nil {
		return nil, nil
	}
	if object, ok := a2aPlain(claims); ok {
		return object, nil
	}
	return nil, nil
}
