package server

// Port of packages/server/src/sd-jwt.ts: Selective Disclosure JWTs (RFC 9901) as SD-JWT VCs (IETF SD-JWT-based
// Verifiable Credentials), the Token Status List (IETF OAuth Status List) that revokes them, and OpenID4VCI holder
// proofs. Pure functions over the JOSE layer (session_jose.go): issuing, presenting with key binding, and verifying.
// Storage and policy live in vc.go.

import (
	"bytes"
	"compress/zlib"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math"
	"math/big"
	"sort"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// SdJwtVcType is sd-jwt.ts SD_JWT_VC_TYPE: the `typ` of an SD-JWT VC (`vc+sd-jwt`, the earlier name, is accepted
// when verifying).
const SdJwtVcType = "dc+sd-jwt"

// KbJwtType is sd-jwt.ts KB_JWT_TYPE.
const KbJwtType = "kb+jwt"

// StatusListJwtType is sd-jwt.ts STATUS_LIST_JWT_TYPE.
const StatusListJwtType = "statuslist+jwt"

// HolderProofType is sd-jwt.ts HOLDER_PROOF_TYPE.
const HolderProofType = "openid4vci-proof+jwt"

// SdJwtAlgorithms is sd-jwt.ts sdJwtAlgorithms: signature algorithms accepted from holders and issuers.
var SdJwtAlgorithms = []string{"ES256", "ES384", "EdDSA"}

// StatusValid is sd-jwt.ts STATUS_VALID.
const StatusValid = 0

// StatusInvalid is sd-jwt.ts STATUS_INVALID.
const StatusInvalid = 1

// StatusSuspended is sd-jwt.ts STATUS_SUSPENDED.
const StatusSuspended = 2

// ReservedVcClaims is sd-jwt.ts reservedVcClaims: claims that are never selectively disclosable and never come from
// a disclosure (and never object keys that change an object's prototype).
var ReservedVcClaims = newOrderedSet("iss", "sub", "iat", "nbf", "exp", "cnf", "vct", "vct#integrity", "status", "jti", "aud", "_sd", "_sd_alg", "...", "__proto__", "constructor", "prototype")

// SdJwtError is sd-jwt.ts SdJwtError: a presentation or credential that did not verify, with the reason
// (malformed, unsupported-type, unknown-issuer, bad-signature, expired, not-yet-valid, bad-disclosure,
// key-binding-required, bad-key-binding, wrong-audience, wrong-nonce, stale-key-binding, revoked, suspended,
// status-unavailable).
type SdJwtError struct {
	Reason  string
	Message string
}

// Error is the message.
func (e *SdJwtError) Error() string { return e.Message }

// Name is the JavaScript error name.
func (e *SdJwtError) Name() string { return "SdJwtError" }

func sdJwtFail(reason, message string) *SdJwtError { return &SdJwtError{Reason: reason, Message: message} }

// latin1Bytes is Buffer.from(text, 'ascii'/'latin1'): the low byte of each UTF-16 code unit.
func latin1Bytes(text string) []byte {
	units := core.ToUTF16(text)
	out := make([]byte, len(units))
	for index, unit := range units {
		out[index] = byte(unit)
	}
	return out
}

// sdDigestOf is digestOf: SHA-256 of the ASCII form, base64url.
func sdDigestOf(encoded string) string {
	digest := sha256.Sum256(latin1Bytes(encoded))
	return base64url(digest[:])
}

// sdDateNow is Date.now(): the wall clock, in milliseconds.
func sdDateNow() float64 { return float64(time.Now().UnixMilli()) }

func randomBytes(size int) []byte {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return b
}

// randomInt is crypto.randomInt(max): a uniform integer in [0, max).
func randomInt(max int64) int64 {
	value, err := rand.Int(rand.Reader, big.NewInt(max))
	if err != nil {
		panic(err)
	}
	return value.Int64()
}

// SdJwtDisclosure is one disclosure: `[salt, name, value]`, base64url-encoded JSON, and its SHA-256 digest.
type SdJwtDisclosure struct {
	Encoded string
	Digest  string
	Name    string
	Value   any
}

// CreateDisclosure is sd-jwt.ts createDisclosure.
func CreateDisclosure(name string, value any) (SdJwtDisclosure, error) {
	text, _, err := core.Stringify([]any{base64url(randomBytes(16)), name, value})
	if err != nil {
		return SdJwtDisclosure{}, err
	}
	encoded := base64url(utf8Bytes(text))
	return SdJwtDisclosure{Encoded: encoded, Digest: sdDigestOf(encoded), Name: name, Value: value}, nil
}

// sdJwtSign is jose SignJWT(payload).setProtectedHeader(header).sign(key) for the SD-JWT algorithms.
func sdJwtSign(header, payload *core.Object, key crypto.Signer, alg string) (string, error) {
	headerJSON, _, err := core.Stringify(header)
	if err != nil {
		return "", err
	}
	payloadJSON, _, err := core.Stringify(payload)
	if err != nil {
		return "", err
	}
	input := base64url(utf8Bytes(headerJSON)) + "." + base64url(utf8Bytes(payloadJSON))
	var signature []byte
	switch private := key.(type) {
	case ed25519.PrivateKey:
		if alg != "EdDSA" && alg != "Ed25519" {
			return "", &core.TypeError{Message: "Key for the " + alg + " algorithm must be one of type CryptoKey, KeyObject, or JSON Web Key"}
		}
		signature = ed25519.Sign(private, []byte(input))
	case *ecdsa.PrivateKey:
		var hash crypto.Hash
		var curve elliptic.Curve
		switch alg {
		case "ES256":
			hash, curve = crypto.SHA256, elliptic.P256()
		case "ES384":
			hash, curve = crypto.SHA384, elliptic.P384()
		case "ES512":
			hash, curve = crypto.SHA512, elliptic.P521()
		default:
			return "", &core.TypeError{Message: "Key for the " + alg + " algorithm must be one of type CryptoKey, KeyObject, or JSON Web Key"}
		}
		if private.Curve != curve {
			return "", &core.TypeError{Message: "Invalid key curve for the algorithm"}
		}
		digest := hash.New()
		digest.Write([]byte(input))
		r, s, err := ecdsa.Sign(rand.Reader, private, digest.Sum(nil))
		if err != nil {
			return "", err
		}
		size := (private.Curve.Params().BitSize + 7) / 8
		signature = make([]byte, 2*size)
		r.FillBytes(signature[:size])
		s.FillBytes(signature[size:])
	default:
		return "", sjwtFail("JOSENotSupported", "alg "+alg+" is not supported")
	}
	return input + "." + base64url(signature), nil
}

// SdJwtIssueInput is what issueSdJwt takes. Typ "" is SD_JWT_VC_TYPE.
type SdJwtIssueInput struct {
	Alg         string
	Kid         string
	Key         crypto.Signer
	Typ         string
	Plain       *core.Object
	Disclosable *core.Object
	Decoys      int
}

// IssuedSdJwt is the issued form `<jwt>~<disclosure>~...~` and its parts.
type IssuedSdJwt struct {
	SdJwt       string
	Jwt         string
	Disclosures []SdJwtDisclosure
}

// IssueSdJwt (sd-jwt.ts issueSdJwt): Issues an SD-JWT: `plain` claims are visible to anyone holding the credential;
// each `disclosable` claim becomes a disclosure the holder decides to reveal or keep. Random decoy digests hide how
// many claims exist. Returns the issued form `<jwt>~<disclosure>~...~` and its parts.
func IssueSdJwt(ctx context.Context, input SdJwtIssueInput) (*IssuedSdJwt, error) {
	plain := input.Plain
	if plain == nil {
		plain = core.NewObject()
	}
	// What a verifier refuses to accept from a disclosure is never issued as one.
	for _, name := range input.Disclosable.Keys() {
		if ReservedVcClaims.Has(name) || plain.Has(name) {
			return nil, sdJwtFail("bad-disclosure", jsSlice(name, 64)+" cannot be selectively disclosable")
		}
	}
	disclosures := []SdJwtDisclosure{}
	var failed error
	input.Disclosable.Entries(func(name string, value any) bool {
		disclosure, err := CreateDisclosure(name, value)
		if err != nil {
			failed = err
			return false
		}
		disclosures = append(disclosures, disclosure)
		return true
	})
	if failed != nil {
		return nil, failed
	}
	decoys := make([]string, input.Decoys)
	for index := range decoys {
		decoys[index] = sdDigestOf(base64url(randomBytes(32)))
	}
	payload := plain.Spread()
	if len(disclosures) > 0 || len(decoys) > 0 {
		digests := make([]string, 0, len(disclosures)+len(decoys))
		for _, item := range disclosures {
			digests = append(digests, item.Digest)
		}
		digests = append(digests, decoys...)
		sort.Slice(digests, func(i, j int) bool { return compareUTF16(digests[i], digests[j]) < 0 })
		payload.Set("_sd", stringsOf(digests))
		payload.Set("_sd_alg", "sha-256")
	}
	typ := input.Typ
	if typ == "" {
		typ = SdJwtVcType
	}
	jwt, err := sdJwtSign(core.NewObject("alg", input.Alg, "kid", input.Kid, "typ", typ), payload, input.Key, input.Alg)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	b.WriteString(jwt + "~")
	for _, item := range disclosures {
		b.WriteString(item.Encoded + "~")
	}
	return &IssuedSdJwt{SdJwt: b.String(), Jwt: jwt, Disclosures: disclosures}, nil
}

// SplitSdJwtResult is `<jwt>~<d1>~...~<dn>~[<kb-jwt>]` split; KeyBinding is "" when absent.
type SplitSdJwtResult struct {
	Jwt         string
	Disclosures []string
	KeyBinding  string
}

// SplitSdJwt is sd-jwt.ts splitSdJwt.
func SplitSdJwt(value any) (*SplitSdJwtResult, error) {
	text, ok := value.(string)
	if !ok || utf16Len(text) > 65536 || !strings.Contains(text, "~") {
		return nil, sdJwtFail("malformed", "Not an SD-JWT")
	}
	parts := strings.Split(text, "~")
	jwt := parts[0]
	last := parts[len(parts)-1]
	disclosures := append([]string{}, parts[1:len(parts)-1]...)
	if jwt == "" {
		return nil, sdJwtFail("malformed", "Not an SD-JWT")
	}
	for _, item := range disclosures {
		if item == "" {
			return nil, sdJwtFail("malformed", "Not an SD-JWT")
		}
	}
	return &SplitSdJwtResult{Jwt: jwt, Disclosures: disclosures, KeyBinding: last}, nil
}

// ReadDisclosure (sd-jwt.ts readDisclosure): Decodes a disclosure without trusting it (for wallets choosing what to
// reveal).
func ReadDisclosure(encoded string) (name string, value any, err error) {
	decoded, parseErr := core.ParseJSONString(decodeUTF8(nodeBase64Decode(encoded)))
	if parseErr != nil {
		return "", nil, sdJwtFail("bad-disclosure", "A disclosure is not base64url JSON")
	}
	list, ok := decoded.([]any)
	if !ok || len(list) != 3 {
		return "", nil, sdJwtFail("bad-disclosure", "A disclosure is not [salt, name, value]")
	}
	if _, ok := list[0].(string); !ok {
		return "", nil, sdJwtFail("bad-disclosure", "A disclosure is not [salt, name, value]")
	}
	name, ok = list[1].(string)
	if !ok {
		return "", nil, sdJwtFail("bad-disclosure", "A disclosure is not [salt, name, value]")
	}
	return name, list[2], nil
}

// SdJwtPresentOptions are presentSdJwt's options: Disclose nil means 'all'; IssuedAt nil is Date.now().
type SdJwtPresentOptions struct {
	Disclose  []string
	HolderKey crypto.Signer
	Alg       string
	Audience  string
	Nonce     string
	IssuedAt  *float64
}

// PresentSdJwt (sd-jwt.ts presentSdJwt): The holder's presentation: the credential with only the named claims
// disclosed, and a key-binding JWT signed with the holder key over `aud`, `nonce`, `iat` and the hash of everything
// before it.
func PresentSdJwt(credential string, options SdJwtPresentOptions) (string, error) {
	split, err := SplitSdJwt(credential)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(split.Jwt + "~")
	for _, encoded := range split.Disclosures {
		if options.Disclose != nil {
			name, _, err := ReadDisclosure(encoded)
			if err != nil {
				return "", err
			}
			if !containsString(options.Disclose, name) {
				continue
			}
		}
		b.WriteString(encoded + "~")
	}
	presented := b.String()
	issuedAt := sdDateNow()
	if options.IssuedAt != nil {
		issuedAt = *options.IssuedAt
	}
	keyBinding, err := sdJwtSign(core.NewObject("alg", options.Alg, "typ", KbJwtType), core.NewObject(
		"aud", options.Audience, "nonce", options.Nonce, "iat", math.Floor(issuedAt/1000), "sd_hash", sdDigestOf(presented),
	), options.HolderKey, options.Alg)
	if err != nil {
		return "", err
	}
	return presented + keyBinding, nil
}

// sdPublicJwk is publicJwk: the holder key must be a public JWK object.
func sdPublicJwk(value any) (*core.Object, error) {
	jwk, ok := value.(*core.Object)
	if !ok || jwk == nil {
		return nil, sdJwtFail("bad-key-binding", "The credential has no holder key")
	}
	if jwk.Has("d") || jwk.Has("k") {
		return nil, sdJwtFail("bad-key-binding", "The holder key must be public")
	}
	return jwk, nil
}

// sdImportJwk is jose importJWK(jwk, alg) for a verification key: the algorithm must suit the key type, and
// WebCrypto refuses a `use` other than `sig` and a multi-prime RSA key.
func sdImportJwk(jwk *core.Object, alg any) (*sjwtPublicKey, error) {
	name, _ := alg.(string)
	if name == "" {
		return nil, sjwtFail("TypeError", `"alg" argument is required when "jwk.alg" is not present`)
	}
	entry, err := sjwtJwsAlgorithm(name)
	if err != nil {
		return nil, err
	}
	if entry.secret {
		return nil, sjwtFail("JOSENotSupported", "secret keys are not verification keys here")
	}
	if jwk.Get("kty") == "RSA" && !isUndefined(jwk.Get("oth")) {
		return nil, sjwtFail("JOSENotSupported", `RSA JWK "oth" (Other Primes Info) Parameter value is not supported`)
	}
	if use := jwk.Get("use"); !isUndefined(use) && use != "sig" {
		return nil, sjwtFail("TypeError", "Invalid key usage")
	}
	return sjwtImportJwk(entry, jwk)
}

// sdRawKey wraps a public key object (a KeyObject in TypeScript) for the algorithm; a key of another type or curve
// is a TypeError as jose's key check is.
func sdRawKey(key any, alg string) (*sjwtPublicKey, error) {
	entry, err := sjwtJwsAlgorithm(alg)
	if err != nil {
		return nil, err
	}
	mismatch := sjwtFail("TypeError", "Invalid key for the "+alg+" algorithm")
	switch public := key.(type) {
	case *ecdsa.PublicKey:
		if entry.kty != "EC" || public.Curve.Params().Name != entry.crv {
			return nil, mismatch
		}
		return &sjwtPublicKey{key: public}, nil
	case ed25519.PublicKey:
		if entry.kty != "OKP" {
			return nil, mismatch
		}
		return &sjwtPublicKey{key: public}, nil
	case *sjwtPublicKey:
		return public, nil
	}
	return nil, mismatch
}

// sdDecodeJwt is jose decodeProtectedHeader + decodeJwt over a compact JWT, without verifying it.
func sdDecodeJwt(token string) (*core.Object, *core.Object, error) {
	header, err := sjwtDecodeProtectedHeader(token)
	if err != nil {
		return nil, nil, err
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 || parts[1] == "" {
		return nil, nil, sjwtFail("JWTInvalid", "Invalid JWT")
	}
	data, err := sjwtDecode(parts[1])
	if err != nil {
		return nil, nil, sjwtFail("JWTInvalid", "Failed to base64url decode the payload")
	}
	parsed, err := sjwtJSON(data)
	payload, ok := parsed.(*core.Object)
	if err != nil || !ok || payload == nil {
		return nil, nil, sjwtFail("JWTInvalid", "Invalid JWT Claims Set")
	}
	return header, payload, nil
}

// SdJwtVerifyOptions are verifySdJwt's options. IssuerKey resolves `kid`/`iss` to a JWK (*core.Object with `kty`),
// a public key (*ecdsa.PublicKey, ed25519.PublicKey), or nil (not trusted). RequireKeyBinding is required unless it
// is false. Audience and Nonce are checked when their Has flag is set. Now is in milliseconds (nil: Date.now()).
type SdJwtVerifyOptions struct {
	IssuerKey               func(ctx context.Context, kid, issuer string) (any, error)
	RequireKeyBinding       any
	Audience                any
	HasAudience             bool
	Nonce                   any
	HasNonce                bool
	Now                     *float64
	MaxKeyBindingAgeSeconds *float64
	ClockToleranceSeconds   *float64
}

func inAlgorithms(alg any) bool {
	name, ok := alg.(string)
	return ok && containsString(SdJwtAlgorithms, name)
}

// VerifySdJwt (sd-jwt.ts verifySdJwt): Verifies an SD-JWT VC or presentation: the issuer's signature (`issuerKey`
// resolves `kid`/`iss`), validity times, every disclosure against the signed digests, and, for presentations, the
// key-binding JWT (`audience`, `nonce`, freshness, `sd_hash`) with the holder key in `cnf.jwk`. Fails with
// *SdJwtError with the reason. The result is the VerifiedSdJwt record.
func VerifySdJwt(ctx context.Context, value string, options *SdJwtVerifyOptions) (*core.Object, error) {
	split, err := SplitSdJwt(value)
	if err != nil {
		return nil, err
	}
	header, unverified, err := sdDecodeJwt(split.Jwt)
	if err != nil {
		return nil, sdJwtFail("malformed", "The issuer JWT cannot be decoded")
	}
	if typ := header.Get("typ"); typ != SdJwtVcType && typ != "vc+sd-jwt" {
		return nil, sdJwtFail("unsupported-type", "Not an SD-JWT VC")
	}
	kid, kidOK := header.Get("kid").(string)
	if !inAlgorithms(header.Get("alg")) || !kidOK {
		return nil, sdJwtFail("unsupported-type", "Unsupported issuer algorithm")
	}
	alg := header.Get("alg").(string)
	iss, ok := unverified.Get("iss").(string)
	if !ok {
		return nil, sdJwtFail("malformed", "The credential names no issuer")
	}
	found, err := options.IssuerKey(ctx, kid, iss)
	if err != nil {
		return nil, err
	}
	if !truthy(found) || isNilKey(found) {
		return nil, sdJwtFail("unknown-issuer", "The issuer or its key is not trusted")
	}
	var key *sjwtPublicKey
	var keyErr error
	if jwk, isJwk := found.(*core.Object); isJwk && jwk.Has("kty") {
		if key, err = sdImportJwk(jwk, alg); err != nil {
			// The header names an algorithm the issuer's key does not have.
			return nil, sdJwtFail("unsupported-type", "The issuer key does not match the credential algorithm")
		}
	} else {
		key, keyErr = sdRawKey(found, alg)
	}
	now := sdDateNow()
	if options.Now != nil {
		now = *options.Now
	}
	tolerance := 5.0
	if options.ClockToleranceSeconds != nil {
		tolerance = *options.ClockToleranceSeconds
	}
	payload, _, err := sjwtJwtVerify(ctx, split.Jwt, func(context.Context, *core.Object) (*sjwtPublicKey, error) {
		return key, keyErr
	}, sjwtVerifyOptions{algorithms: []string{alg}, currentDate: now, clockTolerance: tolerance, maxTokenAge: core.Undefined})
	if err != nil {
		switch sjwtClassOf(err) {
		case "JWTExpired":
			return nil, sdJwtFail("expired", "The credential has expired")
		case "JWTClaimValidationFailed":
			return nil, sdJwtFail("not-yet-valid", "The credential is not valid yet")
		}
		return nil, sdJwtFail("bad-signature", "The issuer signature does not verify")
	}
	if sdAlg := payload.Get("_sd_alg"); !isUndefined(sdAlg) && sdAlg != "sha-256" {
		return nil, sdJwtFail("unsupported-type", "Unsupported disclosure digest")
	}
	signedDigests := []string{}
	if list, ok := payload.Get("_sd").([]any); ok {
		for _, item := range list {
			if text, ok := item.(string); ok {
				signedDigests = append(signedDigests, text)
			}
		}
	}
	digests := map[string]bool{}
	for _, item := range signedDigests {
		digests[item] = true
	}
	if len(digests) != len(signedDigests) {
		return nil, sdJwtFail("bad-disclosure", "The credential repeats a digest")
	}
	claims := payload.Spread()
	claims.Delete("_sd")
	claims.Delete("_sd_alg")
	used := map[string]bool{}
	disclosed := []string{}
	for _, encoded := range split.Disclosures {
		digest := sdDigestOf(encoded)
		if !digests[digest] || used[digest] {
			return nil, sdJwtFail("bad-disclosure", "A disclosure was not signed by the issuer")
		}
		used[digest] = true
		name, claim, err := ReadDisclosure(encoded)
		if err != nil {
			return nil, err
		}
		if ReservedVcClaims.Has(name) || claims.Has(name) {
			return nil, sdJwtFail("bad-disclosure", "The disclosure of "+jsSlice(name, 64)+" is not allowed")
		}
		claims.Set(name, claim)
		disclosed = append(disclosed, name)
	}
	var holderKey *core.Object
	if cnfJwk := member(payload.Get("cnf"), "jwk"); !isUndefined(cnfJwk) {
		if holderKey, err = sdPublicJwk(cnfJwk); err != nil {
			return nil, err
		}
	}
	var keyBindingClaims *core.Object
	if split.KeyBinding != "" {
		keyBinding := split.KeyBinding
		if holderKey == nil {
			return nil, sdJwtFail("bad-key-binding", "The credential has no holder key")
		}
		kbHeader, err := sjwtDecodeProtectedHeader(keyBinding)
		if err != nil {
			return nil, sdJwtFail("bad-key-binding", "The key-binding JWT cannot be decoded")
		}
		if kbHeader.Get("typ") != KbJwtType || !inAlgorithms(kbHeader.Get("alg")) {
			return nil, sdJwtFail("bad-key-binding", "Not a key-binding JWT")
		}
		kbAlg := kbHeader.Get("alg").(string)
		holder, importErr := sdImportJwk(holderKey, kbAlg)
		if importErr != nil {
			return nil, sdJwtFail("bad-key-binding", "The key-binding signature does not verify")
		}
		kb, _, err := sjwtJwtVerify(ctx, keyBinding, func(context.Context, *core.Object) (*sjwtPublicKey, error) {
			return holder, nil
		}, sjwtVerifyOptions{algorithms: []string{kbAlg}, currentDate: now, clockTolerance: tolerance, maxTokenAge: core.Undefined})
		if err != nil {
			return nil, sdJwtFail("bad-key-binding", "The key-binding signature does not verify")
		}
		if !core.StrictEquals(kb.Get("sd_hash"), sdDigestOf(value[:len(value)-len(keyBinding)])) {
			return nil, sdJwtFail("bad-key-binding", "The key-binding JWT covers another presentation")
		}
		if options.HasAudience && !core.StrictEquals(kb.Get("aud"), options.Audience) {
			return nil, sdJwtFail("wrong-audience", "The presentation is for another verifier")
		}
		if options.HasNonce && !core.StrictEquals(kb.Get("nonce"), options.Nonce) {
			return nil, sdJwtFail("wrong-nonce", "The presentation answers another request")
		}
		iat, iatOK := kb.Get("iat").(float64)
		age := now / 1000
		if iatOK {
			age -= iat
		}
		maxAge := 300.0
		if options.MaxKeyBindingAgeSeconds != nil {
			maxAge = *options.MaxKeyBindingAgeSeconds
		}
		if !iatOK || age > maxAge || age < -tolerance {
			return nil, sdJwtFail("stale-key-binding", "The presentation is too old")
		}
		keyBindingClaims = core.NewObject()
		if aud, ok := kb.Get("aud").(string); ok {
			keyBindingClaims.Set("audience", aud)
		}
		if nonce, ok := kb.Get("nonce").(string); ok {
			keyBindingClaims.Set("nonce", nonce)
		}
		keyBindingClaims.Set("issuedAt", iat*1000)
	} else if options.RequireKeyBinding != false {
		return nil, sdJwtFail("key-binding-required", "A presentation needs a key-binding JWT")
	}
	reference := member(payload.Get("status"), "status_list")
	result := core.NewObject("issuer", payload.Get("iss"), "keyId", kid)
	if vct, ok := payload.Get("vct").(string); ok {
		result.Set("vct", vct)
	}
	result.Set("claims", claims)
	result.Set("disclosed", stringsOf(disclosed))
	if holderKey != nil {
		result.Set("holderKey", holderKey)
	}
	if truthy(reference) {
		index, indexOK := member(reference, "idx").(float64)
		uri, uriOK := member(reference, "uri").(string)
		if indexOK && uriOK {
			result.Set("status", core.NewObject("index", index, "uri", uri))
		}
	}
	if iat, ok := payload.Get("iat").(float64); ok {
		result.Set("issuedAt", iat*1000)
	}
	if exp, ok := payload.Get("exp").(float64); ok {
		result.Set("expiresAt", exp*1000)
	}
	result.Set("keyBound", split.KeyBinding != "")
	if keyBindingClaims != nil {
		result.Set("keyBinding", keyBindingClaims)
	}
	return result, nil
}

// isNilKey reports a typed nil key (a nil *core.Object or key pointer), which TypeScript would see as undefined.
func isNilKey(value any) bool {
	switch key := value.(type) {
	case *core.Object:
		return key == nil
	case *ecdsa.PublicKey:
		return key == nil
	case ed25519.PublicKey:
		return key == nil
	case *sjwtPublicKey:
		return key == nil
	}
	return false
}

// statusPosition is the byte and shift of `index` in a list of `bits`-bit entries (ok false outside the list).
func statusPosition(length int, index, bits float64) (int, uint, bool) {
	perByte := 8 / bits
	position := math.Floor(index / perByte)
	if math.IsNaN(position) || position < 0 || position >= float64(length) {
		return 0, 0, false
	}
	shift := uint(uint32(int32(int64(math.Mod(index, perByte)*bits))) & 31)
	return int(position), shift, true
}

// StatusAt (sd-jwt.ts statusAt): Reads the status of `index` from a raw list of `bits`-bit entries (index 0 is the
// low bits of byte 0).
func StatusAt(bytes []byte, index float64, bits float64) (float64, error) {
	position, shift, ok := statusPosition(len(bytes), index, bits)
	if !ok {
		return 0, sdJwtFail("status-unavailable", "The status index is outside the list")
	}
	return float64((int(bytes[position]) >> shift) & ((1 << uint(bits)) - 1)), nil
}

// errStatusRange is the RangeError setStatusAt throws.
var errStatusRange = errors.New("Status out of range")

// SetStatusAt (sd-jwt.ts setStatusAt): Writes the status of `index` into a raw list.
func SetStatusAt(bytes []byte, index float64, bits float64, value float64) error {
	perByte := 8 / bits
	position := math.Floor(index / perByte)
	if position >= float64(len(bytes)) || value < 0 || value >= float64(int(1)<<uint(bits)) {
		return errStatusRange
	}
	_, shift, ok := statusPosition(len(bytes), index, bits)
	if !ok {
		// A Buffer ignores a write outside its indexes (negative or NaN positions).
		return nil
	}
	mask := ((1 << uint(bits)) - 1) << shift
	bytes[int(position)] = byte((int(bytes[int(position)]) &^ mask) | (int(value) << shift))
	return nil
}

// StatusListInput is what signStatusList takes (times in milliseconds).
type StatusListInput struct {
	URI        string
	Bytes      []byte
	Bits       int
	Alg        string
	Kid        string
	Key        crypto.Signer
	IssuedAt   float64
	ExpiresAt  float64
	TTLSeconds float64
}

// deflate is zlib.deflateSync.
func deflate(data []byte) []byte {
	var buffer bytes.Buffer
	writer := zlib.NewWriter(&buffer)
	_, _ = writer.Write(data)
	_ = writer.Close()
	return buffer.Bytes()
}

// SignStatusList (sd-jwt.ts signStatusList): A Status List Token (JWT, `typ: statuslist+jwt`) for a raw list.
func SignStatusList(ctx context.Context, input StatusListInput) (string, error) {
	return sdJwtSign(core.NewObject("alg", input.Alg, "kid", input.Kid, "typ", StatusListJwtType), core.NewObject(
		"sub", input.URI,
		"iat", math.Floor(input.IssuedAt/1000),
		"exp", math.Floor(input.ExpiresAt/1000),
		"ttl", input.TTLSeconds,
		"status_list", core.NewObject("bits", input.Bits, "lst", base64url(deflate(input.Bytes))),
	), input.Key, input.Alg)
}

// ReadStatusList (sd-jwt.ts readStatusList): Verifies a Status List Token for `uri` and returns its raw list. key is
// a JWK (*core.Object) or a public key; now is in milliseconds (nil: Date.now()).
func ReadStatusList(ctx context.Context, token string, key any, uri string, now *float64) (int, []byte, error) {
	unavailable := sdJwtFail("status-unavailable", "The status list does not verify")
	header, err := sjwtDecodeProtectedHeader(token)
	if err != nil || header.Get("typ") != StatusListJwtType {
		return 0, nil, unavailable
	}
	var verifying *sjwtPublicKey
	if jwk, isJwk := key.(*core.Object); isJwk && jwk != nil && jwk.Has("kty") {
		verifying, err = sdImportJwk(jwk, header.Get("alg"))
	} else {
		alg, _ := header.Get("alg").(string)
		verifying, err = sdRawKey(key, alg)
	}
	if err != nil {
		return 0, nil, unavailable
	}
	at := sdDateNow()
	if now != nil {
		at = *now
	}
	payload, _, err := sjwtJwtVerify(ctx, token, func(context.Context, *core.Object) (*sjwtPublicKey, error) {
		return verifying, nil
	}, sjwtVerifyOptions{algorithms: SdJwtAlgorithms, requiredClaims: []string{"iat", "sub"}, currentDate: at, clockTolerance: 5.0, maxTokenAge: core.Undefined})
	if err != nil || payload.Get("sub") != uri {
		return 0, nil, unavailable
	}
	list := payload.Get("status_list")
	bits, bitsOK := member(list, "bits").(float64)
	lst, lstOK := member(list, "lst").(string)
	if !bitsOK || (bits != 1 && bits != 2 && bits != 4 && bits != 8) || !lstOK {
		return 0, nil, unavailable
	}
	reader, err := zlib.NewReader(bytes.NewReader(nodeBase64Decode(lst)))
	if err != nil {
		return 0, nil, unavailable
	}
	defer reader.Close()
	const maxOutput = 16 * 1024 * 1024
	raw, err := io.ReadAll(io.LimitReader(reader, maxOutput+1))
	if err != nil || len(raw) > maxOutput {
		return 0, nil, unavailable
	}
	return int(bits), raw, nil
}

// HolderProofOptions are verifyHolderProof's options (Now in milliseconds, nil: Date.now(); MaxAgeSeconds nil: 300).
type HolderProofOptions struct {
	Audience      string
	Now           *float64
	MaxAgeSeconds *float64
}

// HolderProof is a verified holder proof: the holder key, its RFC 7638 thumbprint, and the nonce (nil when the proof
// has none).
type HolderProof struct {
	Jwk        *core.Object
	Thumbprint string
	Nonce      *string
}

// jwkThumbprint is jose calculateJwkThumbprint (SHA-256, RFC 7638).
func jwkThumbprint(jwk *core.Object) (string, error) {
	check := func(name, description string) error {
		if text, ok := jwk.Get(name).(string); !ok || text == "" {
			return sjwtFail("JWKInvalid", description+" missing or invalid")
		}
		return nil
	}
	var components *core.Object
	switch jwk.Get("kty") {
	case "EC":
		for _, item := range [][2]string{{"crv", `"crv" (Curve) Parameter`}, {"x", `"x" (X Coordinate) Parameter`}, {"y", `"y" (Y Coordinate) Parameter`}} {
			if err := check(item[0], item[1]); err != nil {
				return "", err
			}
		}
		components = core.NewObject("crv", jwk.Get("crv"), "kty", jwk.Get("kty"), "x", jwk.Get("x"), "y", jwk.Get("y"))
	case "OKP":
		for _, item := range [][2]string{{"crv", `"crv" (Subtype of Key Pair) Parameter`}, {"x", `"x" (Public Key) Parameter`}} {
			if err := check(item[0], item[1]); err != nil {
				return "", err
			}
		}
		components = core.NewObject("crv", jwk.Get("crv"), "kty", jwk.Get("kty"), "x", jwk.Get("x"))
	case "RSA":
		for _, item := range [][2]string{{"e", `"e" (Exponent) Parameter`}, {"n", `"n" (Modulus) Parameter`}} {
			if err := check(item[0], item[1]); err != nil {
				return "", err
			}
		}
		components = core.NewObject("e", jwk.Get("e"), "kty", jwk.Get("kty"), "n", jwk.Get("n"))
	case "oct":
		if err := check("k", `"k" (Key Value) Parameter`); err != nil {
			return "", err
		}
		components = core.NewObject("k", jwk.Get("k"), "kty", jwk.Get("kty"))
	default:
		return "", sjwtFail("JOSENotSupported", `"kty" (Key Type) Parameter missing or unsupported`)
	}
	digest := sha256.Sum256(utf8Bytes(core.MustStringify(components)))
	return base64url(digest[:]), nil
}

// VerifyHolderProof (sd-jwt.ts verifyHolderProof): Verifies an OpenID4VCI holder proof (`typ: openid4vci-proof+jwt`,
// the holder's public key in the `jwk` header): signature, `aud` (the credential issuer), freshness, and the nonce
// the issuer handed out. Returns the holder key and its RFC 7638 thumbprint.
func VerifyHolderProof(ctx context.Context, proof any, options HolderProofOptions) (*HolderProof, error) {
	text, ok := proof.(string)
	if !ok || utf16Len(text) > 8192 {
		return nil, sdJwtFail("malformed", "Invalid proof")
	}
	header, err := sjwtDecodeProtectedHeader(text)
	if err != nil {
		return nil, sdJwtFail("malformed", "Invalid proof")
	}
	if header.Get("typ") != HolderProofType || !inAlgorithms(header.Get("alg")) || !truthy(header.Get("jwk")) {
		return nil, sdJwtFail("malformed", "The proof must be an openid4vci-proof+jwt with a jwk header")
	}
	// OpenID4VCI: exactly one way to name the key.
	if !isUndefined(header.Get("kid")) || !isUndefined(header.Get("x5c")) {
		return nil, sdJwtFail("malformed", "A proof names its key with jwk only (no kid or x5c)")
	}
	jwk, err := sdPublicJwk(header.Get("jwk"))
	if err != nil {
		return nil, err
	}
	alg := header.Get("alg").(string)
	now := sdDateNow()
	if options.Now != nil {
		now = *options.Now
	}
	// jose EmbeddedJWK: the key in the protected header, imported as extractable, must be a public key.
	embedded := func(_ context.Context, protected *core.Object) (*sjwtPublicKey, error) {
		key, ok := protected.Get("jwk").(*core.Object)
		if !ok || key == nil {
			return nil, sjwtFail("JWSInvalid", `"jwk" (JSON Web Key) Header Parameter must be a JSON object`)
		}
		return sdImportJwk(key.Spread(core.NewObject("ext", true)), protected.Get("alg"))
	}
	payload, _, err := sjwtJwtVerify(ctx, text, embedded, sjwtVerifyOptions{
		algorithms: []string{alg}, audience: []string{options.Audience}, currentDate: now, clockTolerance: 5.0, maxTokenAge: core.Undefined,
	})
	if err != nil {
		return nil, sdJwtFail("bad-key-binding", "The proof does not verify for this issuer")
	}
	iat, iatOK := payload.Get("iat").(float64)
	age := now / 1000
	if iatOK {
		age -= iat
	}
	maxAge := 300.0
	if options.MaxAgeSeconds != nil {
		maxAge = *options.MaxAgeSeconds
	}
	if !iatOK || age > maxAge || age < -5 {
		return nil, sdJwtFail("stale-key-binding", "The proof is too old")
	}
	clean := core.NewObject()
	for _, name := range []string{"kty", "crv", "x", "y", "n", "e"} {
		if value := jwk.Get(name); !isUndefined(value) {
			clean.Set(name, value)
		}
	}
	thumbprint, err := jwkThumbprint(clean)
	if err != nil {
		return nil, err
	}
	result := &HolderProof{Jwk: clean, Thumbprint: thumbprint}
	if nonce, ok := payload.Get("nonce").(string); ok {
		result.Nonce = &nonce
	}
	return result, nil
}
