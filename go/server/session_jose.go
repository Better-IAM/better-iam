package server

// The JOSE operations session-tokens.ts, token-signing.ts and web-identity.ts get from `jose` (v6): compact JWS
// verification (jwtVerify with its claim-set checks), local and remote JSON Web Key Sets, JWK import, and compact
// signing (SignJWT). Each check runs in the order jose runs it and fails with the jose error class the TypeScript
// modules map to their failure reasons, so the Go verifiers report the same reasons. Names carry the `sjwt` prefix.

import (
	"context"
	"crypto"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // SHA-256 for RS256, PS256 and ES256
	_ "crypto/sha512" // SHA-384 and SHA-512
	"encoding/base64"
	"errors"
	"io"
	"math"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/core"
)

// sjwtError is a jose error: Class is the jose class name (JWSInvalid, JWTInvalid, JOSEAlgNotAllowed,
// JOSENotSupported, JWKSNoMatchingKey, JWKSMultipleMatchingKeys, JWSSignatureVerificationFailed, JWTExpired,
// JWTClaimValidationFailed, JWKSInvalid, JWKSTimeout, JOSEError, or TypeError for a runtime TypeError/DOMException);
// Claim and Reason are set on claim validation failures.
type sjwtError struct {
	Class   string
	Claim   string
	Reason  string
	Message string
}

func (e *sjwtError) Error() string { return e.Message }

func sjwtFail(class, message string) *sjwtError { return &sjwtError{Class: class, Message: message} }

func sjwtClaimFail(class, message, claim, reason string) *sjwtError {
	return &sjwtError{Class: class, Claim: claim, Reason: reason, Message: message}
}

// sjwtClassOf is the jose class of an error ("" for anything else).
func sjwtClassOf(err error) string {
	var known *sjwtError
	if errors.As(err, &known) {
		return known.Class
	}
	return ""
}

// sjwtDecode is jose's base64url decode under Node 24 (atob after mapping the URL alphabet): `+` and `/` are refused,
// ASCII whitespace is skipped, up to two trailing `=` are accepted on a multiple of four, a length of 4n+1 fails, and
// unused trailing bits are ignored.
func sjwtDecode(value string) ([]byte, error) {
	if strings.ContainsAny(value, "+/") {
		return nil, errors.New("Invalid base64url")
	}
	var b strings.Builder
	for i := 0; i < len(value); i++ {
		switch c := value[i]; c {
		case '\t', '\n', '\f', '\r', ' ':
		case '-':
			b.WriteByte('+')
		case '_':
			b.WriteByte('/')
		default:
			b.WriteByte(c)
		}
	}
	text := b.String()
	if len(text)%4 == 0 {
		if strings.HasSuffix(text, "==") {
			text = text[:len(text)-2]
		} else if strings.HasSuffix(text, "=") {
			text = text[:len(text)-1]
		}
	}
	if len(text)%4 == 1 || strings.Contains(text, "=") {
		return nil, errors.New("The input to be decoded is not correctly encoded.")
	}
	return base64.RawStdEncoding.DecodeString(text)
}

// sjwtJSON is JSON.parse(strictDecoder.decode(bytes)): fatal UTF-8 decoding (a leading BOM is dropped).
func sjwtJSON(data []byte) (any, error) {
	if !utf8.Valid(data) {
		return nil, errors.New("invalid UTF-8")
	}
	text := strings.TrimPrefix(string(data), string(rune(0xFEFF)))
	return core.ParseJSONString(text)
}

// sjwtParseHeader is parseJoseHeader: a base64url JSON object.
func sjwtParseHeader(encoded string, class, message string) (*core.Object, error) {
	data, err := sjwtDecode(encoded)
	if err != nil {
		return nil, sjwtFail(class, message)
	}
	parsed, err := sjwtJSON(data)
	if err != nil {
		return nil, sjwtFail(class, message)
	}
	header, ok := parsed.(*core.Object)
	if !ok || header == nil {
		return nil, sjwtFail(class, message)
	}
	return header, nil
}

// sjwtDecodeProtectedHeader is jose decodeProtectedHeader for a compact token (a TypeError on failure).
func sjwtDecodeProtectedHeader(token string) (*core.Object, error) {
	parts := strings.Split(token, ".")
	invalid := "Invalid Token or Protected Header formatting"
	if (len(parts) != 3 && len(parts) != 5) || parts[0] == "" {
		return nil, sjwtFail("TypeError", invalid)
	}
	return sjwtParseHeader(parts[0], "TypeError", invalid)
}

// sjwtEntry is a JWS algorithm of jose's table.
type sjwtEntry struct {
	alg    string
	kty    string
	crv    string
	hash   crypto.Hash
	pss    bool
	secret bool
	// minRsaBits is set for the RSA algorithms (2048).
	minRsaBits int
}

var sjwtAlgorithms = map[string]sjwtEntry{
	"HS256":   {alg: "HS256", kty: "oct", hash: crypto.SHA256, secret: true},
	"HS384":   {alg: "HS384", kty: "oct", hash: crypto.SHA384, secret: true},
	"HS512":   {alg: "HS512", kty: "oct", hash: crypto.SHA512, secret: true},
	"RS256":   {alg: "RS256", kty: "RSA", hash: crypto.SHA256, minRsaBits: 2048},
	"RS384":   {alg: "RS384", kty: "RSA", hash: crypto.SHA384, minRsaBits: 2048},
	"RS512":   {alg: "RS512", kty: "RSA", hash: crypto.SHA512, minRsaBits: 2048},
	"PS256":   {alg: "PS256", kty: "RSA", hash: crypto.SHA256, pss: true, minRsaBits: 2048},
	"PS384":   {alg: "PS384", kty: "RSA", hash: crypto.SHA384, pss: true, minRsaBits: 2048},
	"PS512":   {alg: "PS512", kty: "RSA", hash: crypto.SHA512, pss: true, minRsaBits: 2048},
	"ES256":   {alg: "ES256", kty: "EC", crv: "P-256", hash: crypto.SHA256},
	"ES384":   {alg: "ES384", kty: "EC", crv: "P-384", hash: crypto.SHA384},
	"ES512":   {alg: "ES512", kty: "EC", crv: "P-521", hash: crypto.SHA512},
	"EdDSA":   {alg: "EdDSA", kty: "OKP", crv: "Ed25519"},
	"Ed25519": {alg: "Ed25519", kty: "OKP", crv: "Ed25519"},
	// The ML-DSA algorithms are in jose's table, but Node 24's WebCrypto cannot import their keys.
	"ML-DSA-44": {alg: "ML-DSA-44", kty: "AKP"},
	"ML-DSA-65": {alg: "ML-DSA-65", kty: "AKP"},
	"ML-DSA-87": {alg: "ML-DSA-87", kty: "AKP"},
}

// sjwtJwsAlgorithm is jose jwsAlgorithm (JOSENotSupported for an unknown alg).
func sjwtJwsAlgorithm(alg string) (sjwtEntry, error) {
	entry, ok := sjwtAlgorithms[alg]
	if !ok {
		return entry, sjwtFail("JOSENotSupported", "alg "+alg+" is not supported either by JOSE or your javascript runtime")
	}
	return entry, nil
}

// sjwtPublicKey is an imported verification key (a WebCrypto public CryptoKey).
type sjwtPublicKey struct {
	key     crypto.PublicKey
	rsaBits int
}

// sjwtMember is Buffer.from(value, 'base64') over a JWK member: Node decodes both alphabets and skips padding.
func sjwtMember(value any) ([]byte, bool) {
	text, ok := value.(string)
	if !ok {
		return nil, false
	}
	return nodeBase64Decode(text), true
}

// sjwtCurve is the named curve of a JWK crv.
func sjwtCurve(crv any) (elliptic.Curve, ecdh.Curve, int) {
	switch crv {
	case "P-256":
		return elliptic.P256(), ecdh.P256(), 32
	case "P-384":
		return elliptic.P384(), ecdh.P384(), 48
	case "P-521":
		return elliptic.P521(), ecdh.P521(), 66
	}
	return nil, nil, 0
}

// sjwtECPoint is the public point of an EC JWK (OpenSSL's affine-coordinate import: the coordinates are big-endian
// integers and the point must be on the curve).
func sjwtECPoint(jwk *core.Object) (*ecdsa.PublicKey, error) {
	invalid := sjwtFail("TypeError", "Invalid keyData")
	curve, exchange, size := sjwtCurve(jwk.Get("crv"))
	if curve == nil {
		return nil, invalid
	}
	xBytes, okX := sjwtMember(jwk.Get("x"))
	yBytes, okY := sjwtMember(jwk.Get("y"))
	if !okX || !okY {
		return nil, invalid
	}
	x, y := new(big.Int).SetBytes(xBytes), new(big.Int).SetBytes(yBytes)
	if x.BitLen() > size*8 || y.BitLen() > size*8 {
		return nil, invalid
	}
	point := make([]byte, 1+2*size)
	point[0] = 4
	x.FillBytes(point[1 : 1+size])
	y.FillBytes(point[1+size:])
	if _, err := exchange.NewPublicKey(point); err != nil {
		return nil, invalid
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}

// sjwtRSAPublic is the public key of an RSA JWK.
func sjwtRSAPublic(jwk *core.Object) (*rsa.PublicKey, error) {
	invalid := sjwtFail("TypeError", "Invalid keyData")
	n, okN := sjwtMember(jwk.Get("n"))
	e, okE := sjwtMember(jwk.Get("e"))
	if !okN || !okE || len(n) == 0 || len(e) == 0 {
		return nil, invalid
	}
	exponent := new(big.Int).SetBytes(e)
	if !exponent.IsInt64() || exponent.Int64() > math.MaxInt32 || exponent.Int64() < 2 {
		return nil, invalid
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent.Int64())}, nil
}

// sjwtImportJwk is jose jwkToKey followed by importWithAlgCache's public check, for a key resolved from a JSON Web
// Key Set: WebCrypto's JWK import (a public key may only be used to verify; a private one only to sign), then
// JWKSInvalid for a private key.
func sjwtImportJwk(entry sjwtEntry, jwk *core.Object) (*sjwtPublicKey, error) {
	if jwk.Get("kty") != entry.kty {
		return nil, sjwtFail("JOSENotSupported", `Invalid or unsupported JWK "alg" (Algorithm) Parameter value`)
	}
	private := truthy(jwk.Get("d")) || truthy(jwk.Get("priv"))
	syntax := sjwtFail("TypeError", "Unsupported key usage")
	if ops, ok := jwk.Get("key_ops").([]any); ok {
		for _, op := range ops {
			if private && op != "sign" || !private && op != "verify" {
				return nil, syntax
			}
		}
	} else if !isUndefined(jwk.Get("key_ops")) {
		return nil, syntax
	}
	invalid := sjwtFail("TypeError", "Invalid keyData")
	switch entry.kty {
	case "RSA":
		public, err := sjwtRSAPublic(jwk)
		if err != nil {
			return nil, err
		}
		if private {
			for _, member := range []string{"d", "p", "q", "dp", "dq", "qi"} {
				if _, ok := jwk.Get(member).(string); !ok {
					return nil, invalid
				}
			}
			return nil, sjwtFail("JWKSInvalid", "JSON Web Key Set members must be public keys")
		}
		return &sjwtPublicKey{key: public, rsaBits: public.N.BitLen()}, nil
	case "EC":
		if jwk.Get("crv") != entry.crv {
			return nil, invalid
		}
		public, err := sjwtECPoint(jwk)
		if err != nil {
			return nil, err
		}
		if private {
			d, ok := sjwtMember(jwk.Get("d"))
			scalar := new(big.Int).SetBytes(d)
			if !ok || scalar.Sign() == 0 || scalar.Cmp(public.Curve.Params().N) >= 0 {
				return nil, invalid
			}
			return nil, sjwtFail("JWKSInvalid", "JSON Web Key Set members must be public keys")
		}
		return &sjwtPublicKey{key: public}, nil
	case "OKP":
		if jwk.Get("crv") != "Ed25519" {
			return nil, invalid
		}
		if private {
			d, ok := sjwtMember(jwk.Get("d"))
			if !ok || len(d) != ed25519.SeedSize {
				return nil, invalid
			}
			return nil, sjwtFail("JWKSInvalid", "JSON Web Key Set members must be public keys")
		}
		x, ok := sjwtMember(jwk.Get("x"))
		if !ok || len(x) != ed25519.PublicKeySize {
			return nil, invalid
		}
		return &sjwtPublicKey{key: ed25519.PublicKey(x)}, nil
	}
	return nil, invalid
}

// sjwtVerifySignature is crypto.subtle.verify for an algorithm and an imported key (false on any failure).
func sjwtVerifySignature(entry sjwtEntry, key *sjwtPublicKey, signature, data []byte) bool {
	switch public := key.key.(type) {
	case ed25519.PublicKey:
		if entry.kty != "OKP" {
			return false
		}
		return ed25519.Verify(public, data, signature)
	case *ecdsa.PublicKey:
		if entry.kty != "EC" {
			return false
		}
		size := (public.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*size {
			return false
		}
		digest := entry.hash.New()
		digest.Write(data)
		r := new(big.Int).SetBytes(signature[:size])
		s := new(big.Int).SetBytes(signature[size:])
		return ecdsa.Verify(public, digest.Sum(nil), r, s)
	case *rsa.PublicKey:
		if entry.kty != "RSA" {
			return false
		}
		digest := entry.hash.New()
		digest.Write(data)
		if entry.pss {
			return rsa.VerifyPSS(public, entry.hash, digest.Sum(nil), signature, &rsa.PSSOptions{SaltLength: entry.hash.Size(), Hash: entry.hash}) == nil
		}
		return rsa.VerifyPKCS1v15(public, entry.hash, digest.Sum(nil), signature) == nil
	}
	return false
}

// sjwtResolver resolves the verification key for a protected header (jose's JWTVerifyGetKey).
type sjwtResolver func(ctx context.Context, header *core.Object) (*sjwtPublicKey, error)

// sjwtVerifyOptions are the jwtVerify options the modules pass.
type sjwtVerifyOptions struct {
	// algorithms is the allowlist (nil for none).
	algorithms []string
	issuer     string
	hasIssuer  bool
	// issuers, when set, is jose's array form of the issuer option: any of them is accepted (hasIssuer must be true).
	issuers []string
	// audience is nil when unset.
	audience []string
	// typ is "" when unset.
	typ            string
	requiredClaims []string
	// clockTolerance is any: a number, or undefined.
	clockTolerance any
	// currentDate is in epoch milliseconds.
	currentDate float64
	// maxTokenAge is any: a number, or undefined.
	maxTokenAge any
}

// sjwtJwtVerify is jose jwtVerify for a compact token: the JWS checks in jose's order (header, crit, b64, alg
// allowlist, key, signature), then the JWT claims set.
func sjwtJwtVerify(ctx context.Context, token string, resolve sjwtResolver, options sjwtVerifyOptions) (*core.Object, *core.Object, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, nil, sjwtFail("JWSInvalid", "Invalid Compact JWS")
	}
	encodedProtected, encodedPayload, encodedSignature := parts[0], parts[1], parts[2]
	header, err := sjwtParseHeader(encodedProtected, "JWSInvalid", "JWS Protected Header is invalid")
	if err != nil {
		return nil, nil, err
	}
	// validateCrit with the recognized b64 extension.
	extensions := []string{}
	if crit := header.Get("crit"); !isUndefined(crit) {
		list, ok := crit.([]any)
		valid := ok && len(list) > 0
		for _, item := range list {
			if text, ok := item.(string); !ok || text == "" {
				valid = false
			}
		}
		if !valid {
			return nil, nil, sjwtFail("JWSInvalid", `"crit" (Critical) Header Parameter MUST be an array of non-empty strings when present`)
		}
		for _, item := range list {
			parameter := item.(string)
			if parameter != "b64" {
				return nil, nil, sjwtFail("JOSENotSupported", `Extension Header Parameter "`+parameter+`" is not recognized`)
			}
			if !header.Has(parameter) || isUndefined(header.Get(parameter)) {
				return nil, nil, sjwtFail("JWSInvalid", `Extension Header Parameter "`+parameter+`" is missing`)
			}
			extensions = append(extensions, parameter)
		}
	}
	b64 := true
	if containsString(extensions, "b64") {
		value, ok := header.Get("b64").(bool)
		if !ok {
			return nil, nil, sjwtFail("JWSInvalid", `The "b64" (base64url-encode payload) Header Parameter must be a boolean`)
		}
		b64 = value
	}
	alg, ok := header.Get("alg").(string)
	if !ok || alg == "" {
		return nil, nil, sjwtFail("JWSInvalid", `JWS "alg" (Algorithm) Header Parameter missing or invalid`)
	}
	if options.algorithms != nil && !containsString(options.algorithms, alg) {
		return nil, nil, sjwtFail("JOSEAlgNotAllowed", `"alg" (Algorithm) Header Parameter value not allowed`)
	}
	if !b64 {
		for i := 0; i < len(encodedPayload); i++ {
			if encodedPayload[i] > 127 {
				return nil, nil, sjwtFail("JWSInvalid", "JWS Compact Serialization payload must use only ASCII characters")
			}
		}
	}
	key, err := resolve(ctx, header)
	if err != nil {
		return nil, nil, err
	}
	entry, err := sjwtJwsAlgorithm(alg)
	if err != nil {
		return nil, nil, err
	}
	for i := 0; i < len(encodedPayload); i++ {
		if encodedPayload[i] > 127 {
			return nil, nil, sjwtFail("JWSInvalid", "The payload is not a valid base64url string")
		}
	}
	data := []byte(encodedProtected + "." + encodedPayload)
	signature, err := sjwtDecode(encodedSignature)
	if err != nil {
		return nil, nil, sjwtFail("JWSInvalid", "Failed to base64url decode the signature")
	}
	if entry.minRsaBits > 0 && key.rsaBits < entry.minRsaBits {
		return nil, nil, sjwtFail("TypeError", alg+" requires key modulusLength to be 2048 bits or larger")
	}
	if !sjwtVerifySignature(entry, key, signature, data) {
		return nil, nil, sjwtFail("JWSSignatureVerificationFailed", "signature verification failed")
	}
	var payloadBytes []byte
	if b64 {
		if payloadBytes, err = sjwtDecode(encodedPayload); err != nil {
			return nil, nil, sjwtFail("JWSInvalid", "Failed to base64url decode the payload")
		}
	} else {
		return nil, nil, sjwtFail("JWTInvalid", "JWTs MUST NOT use unencoded payload")
	}
	payload, err := sjwtClaimsSet(header, payloadBytes, options)
	if err != nil {
		return nil, nil, err
	}
	return payload, header, nil
}

// sjwtNormalizeTyp is jose's normalizeTyp.
func sjwtNormalizeTyp(value string) string {
	normalized := core.JSLower(value)
	if strings.Contains(value, "/") {
		return normalized
	}
	return "application/" + normalized
}

// sjwtAudiencePresent is jose's checkAudiencePresence.
func sjwtAudiencePresent(aud any, accepted []string) bool {
	switch value := aud.(type) {
	case string:
		return containsString(accepted, value)
	case []any:
		for _, candidate := range accepted {
			for _, item := range value {
				if item == candidate {
					return true
				}
			}
		}
	}
	return false
}

// sjwtFinite is jose validateInput: a finite number, else a TypeError.
func sjwtFinite(label string, value float64) (float64, error) {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, sjwtFail("TypeError", "Invalid "+label+" input")
	}
	return value, nil
}

// sjwtSeconds is jose's option number: a number, or undefined (fallback); anything else is a TypeError.
func sjwtSeconds(value any, label string) (float64, bool, error) {
	if isUndefined(value) {
		return 0, false, nil
	}
	number, ok := value.(float64)
	if !ok {
		return 0, false, sjwtFail("TypeError", "Invalid "+label+" option type")
	}
	return number, true, nil
}

// sjwtClaimsSet is jose validateClaimsSet.
func sjwtClaimsSet(header *core.Object, encoded []byte, options sjwtVerifyOptions) (*core.Object, error) {
	parsed, err := sjwtJSON(encoded)
	payload, ok := parsed.(*core.Object)
	if err != nil || !ok || payload == nil {
		return nil, sjwtFail("JWTInvalid", "JWT Claims Set must be a top-level JSON object")
	}
	if options.typ != "" {
		typ, ok := header.Get("typ").(string)
		if !ok || sjwtNormalizeTyp(typ) != sjwtNormalizeTyp(options.typ) {
			return nil, sjwtClaimFail("JWTClaimValidationFailed", `unexpected "typ" JWT header value`, "typ", "check_failed")
		}
	}
	presence := append([]string{}, options.requiredClaims...)
	if !isUndefined(options.maxTokenAge) {
		presence = append(presence, "iat")
	}
	if options.audience != nil {
		presence = append(presence, "aud")
	}
	if options.hasIssuer {
		presence = append(presence, "iss")
	}
	seen := map[string]bool{}
	for i := len(presence) - 1; i >= 0; i-- {
		claim := presence[i]
		if seen[claim] {
			continue
		}
		seen[claim] = true
		if !payload.Has(claim) {
			return nil, sjwtClaimFail("JWTClaimValidationFailed", `missing required "`+claim+`" claim`, claim, "missing")
		}
	}
	unexpected := func(claim string) error {
		return sjwtClaimFail("JWTClaimValidationFailed", `unexpected "`+claim+`" claim value`, claim, "check_failed")
	}
	if options.hasIssuer {
		accepted := options.issuers
		if accepted == nil {
			accepted = []string{options.issuer}
		}
		if iss, isText := payload.Get("iss").(string); !isText || !containsString(accepted, iss) {
			return nil, unexpected("iss")
		}
	}
	if options.audience != nil && !sjwtAudiencePresent(payload.Get("aud"), options.audience) {
		return nil, unexpected("aud")
	}
	tolerance, _, err := sjwtSeconds(options.clockTolerance, "clockTolerance")
	if err != nil {
		return nil, err
	}
	if tolerance, err = sjwtFinite("clockTolerance option", tolerance); err != nil {
		return nil, err
	}
	now, err := sjwtFinite("currentDate option", math.Floor(options.currentDate/1000))
	if err != nil {
		return nil, err
	}
	numericDate := func(claim string, required bool) (float64, bool, error) {
		value := payload.Get(claim)
		if isUndefined(value) && !required {
			return 0, false, nil
		}
		number, ok := value.(float64)
		if !ok {
			return 0, false, sjwtClaimFail("JWTClaimValidationFailed", `"`+claim+`" claim must be a number`, claim, "invalid")
		}
		return number, true, nil
	}
	iat, _, err := numericDate("iat", !isUndefined(options.maxTokenAge))
	if err != nil {
		return nil, err
	}
	nbf, hasNbf, err := numericDate("nbf", false)
	if err != nil {
		return nil, err
	}
	if hasNbf && nbf > now+tolerance {
		return nil, sjwtClaimFail("JWTClaimValidationFailed", `"nbf" claim timestamp check failed`, "nbf", "check_failed")
	}
	exp, hasExp, err := numericDate("exp", false)
	if err != nil {
		return nil, err
	}
	if hasExp && exp <= now-tolerance {
		return nil, sjwtClaimFail("JWTExpired", `"exp" claim timestamp check failed`, "exp", "check_failed")
	}
	if !isUndefined(options.maxTokenAge) {
		maxAge, _, err := sjwtSeconds(options.maxTokenAge, "maxTokenAge")
		if err != nil {
			return nil, err
		}
		if maxAge, err = sjwtFinite("maxTokenAge option", maxAge); err != nil {
			return nil, err
		}
		age := now - iat
		if age-tolerance > maxAge {
			return nil, sjwtClaimFail("JWTExpired", `"iat" claim timestamp check failed (too far in the past)`, "iat", "check_failed")
		}
		if age < -tolerance {
			return nil, sjwtClaimFail("JWTClaimValidationFailed", `"iat" claim timestamp check failed (it should be in the past)`, "iat", "check_failed")
		}
	}
	return payload, nil
}

// sjwtLocalSet is jose createLocalJWKSet: a snapshot of a JSON Web Key Set and the selection rules of its key
// resolver.
type sjwtLocalSet struct {
	keys []*core.Object
}

// sjwtNewLocalSet is createLocalJWKSet (JWKSInvalid when the set is not an object whose keys are all objects).
func sjwtNewLocalSet(jwks any) (*sjwtLocalSet, error) {
	snapshot, ok := core.CloneValue(jwks).(*core.Object)
	malformed := sjwtFail("JWKSInvalid", "JSON Web Key Set malformed")
	if !ok || snapshot == nil {
		return nil, malformed
	}
	list, ok := snapshot.Get("keys").([]any)
	if !ok {
		return nil, malformed
	}
	keys := make([]*core.Object, 0, len(list))
	for _, item := range list {
		key, ok := item.(*core.Object)
		if !ok || key == nil {
			return nil, malformed
		}
		keys = append(keys, key)
	}
	return &sjwtLocalSet{keys: keys}, nil
}

// sjwtUsableJwk is jose's isUsableJWK.
func sjwtUsableJwk(jwk *core.Object, entry sjwtEntry, alg string, kid any) bool {
	if ext := jwk.Get("ext"); !isUndefined(ext) {
		if _, ok := ext.(bool); !ok {
			return false
		}
	}
	if ops := jwk.Get("key_ops"); !isUndefined(ops) {
		list, ok := ops.([]any)
		if !ok {
			return false
		}
		seen := map[string]bool{}
		verify := false
		for _, op := range list {
			text, ok := op.(string)
			if !ok || seen[text] {
				return false
			}
			seen[text] = true
			verify = verify || text == "verify"
		}
		if !verify {
			return false
		}
	}
	if jwk.Get("kty") != entry.kty {
		return false
	}
	if !isUndefined(kid) {
		text, ok := kid.(string)
		if !ok || jwk.Get("kid") != text {
			return false
		}
	}
	if jwkAlg := jwk.Get("alg"); isUndefined(jwkAlg) {
		if entry.kty == "AKP" {
			return false
		}
	} else if jwkAlg != alg {
		return false
	}
	if use := jwk.Get("use"); !isUndefined(use) && use != "sig" {
		return false
	}
	return entry.crv == "" || jwk.Get("crv") == entry.crv
}

// candidates are the keys of the set a header selects: JOSENotSupported for an alg jose cannot select keys for,
// JWKSNoMatchingKey or JWKSMultipleMatchingKeys unless exactly one key matches.
func (s *sjwtLocalSet) candidates(header *core.Object) (sjwtEntry, *core.Object, error) {
	alg, _ := header.Get("alg").(string)
	entry, ok := sjwtAlgorithms[alg]
	if !ok || entry.secret {
		return entry, nil, sjwtFail("JOSENotSupported", `Unsupported "alg" value for a JSON Web Key Set`)
	}
	kid := header.Get("kid")
	var found []*core.Object
	for _, key := range s.keys {
		if sjwtUsableJwk(key, entry, alg, kid) {
			found = append(found, key)
		}
	}
	if len(found) == 0 {
		return entry, nil, sjwtFail("JWKSNoMatchingKey", "no applicable key found in the JSON Web Key Set")
	}
	if len(found) != 1 {
		return entry, nil, sjwtFail("JWKSMultipleMatchingKeys", "multiple matching keys found in the JSON Web Key Set")
	}
	return entry, found[0], nil
}

// resolve is the set's key resolver.
func (s *sjwtLocalSet) resolve(_ context.Context, header *core.Object) (*sjwtPublicKey, error) {
	entry, jwk, err := s.candidates(header)
	if err != nil {
		return nil, err
	}
	return sjwtImportJwk(entry, jwk)
}

// sjwtRemoteSet is jose createRemoteJWKSet: a JSON Web Key Set fetched from a URL, cached for cacheMaxAge and
// refetched on an unknown kid once the cooldown since the last fetch has passed. Its clock is the wall clock, as
// jose's is.
type sjwtRemoteSet struct {
	href             string
	timeout          time.Duration
	cooldownDuration float64
	cacheMaxAge      float64
	client           *http.Client

	mu        sync.Mutex
	local     *sjwtLocalSet
	timestamp float64
	hasStamp  bool
	pending   *sjwtFlight
	reloads   int
	applied   int
}

type sjwtFlight struct {
	done chan struct{}
	err  error
}

func sjwtWallMs() float64 { return float64(time.Now().UnixMilli()) }

func (s *sjwtRemoteSet) freshFor(duration float64) bool {
	return s.hasStamp && sjwtWallMs() < s.timestamp+duration
}

// fetch is jose's fetchJwks: GET without following redirects, 200 only, JSON body.
func (s *sjwtRemoteSet) fetch(ctx context.Context) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, s.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, s.href, nil)
	if err != nil {
		return nil, sjwtFail("TypeError", "fetch failed")
	}
	request.Header.Set("User-Agent", "jose/v6.2.12")
	request.Header.Set("accept", "application/json, application/jwk-set+json")
	response, err := s.client.Do(request)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, sjwtFail("JWKSTimeout", "request timed out")
		}
		return nil, sjwtFail("TypeError", "fetch failed")
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		return nil, sjwtFail("JOSEError", "Expected 200 OK from the JSON Web Key Set HTTP response")
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return nil, sjwtFail("JWKSTimeout", "request timed out")
		}
		return nil, sjwtFail("JOSEError", "Failed to parse the JSON Web Key Set HTTP response as JSON")
	}
	parsed, err := core.ParseJSONString(strings.TrimPrefix(decodeUTF8(body), string(rune(0xFEFF))))
	if err != nil {
		return nil, sjwtFail("JOSEError", "Failed to parse the JSON Web Key Set HTTP response as JSON")
	}
	return parsed, nil
}

// reload fetches the set once for all concurrent callers.
func (s *sjwtRemoteSet) reload(ctx context.Context) error {
	s.mu.Lock()
	flight := s.pending
	if flight == nil {
		s.reloads++
		sequence := s.reloads
		flight = &sjwtFlight{done: make(chan struct{})}
		s.pending = flight
		s.mu.Unlock()
		json, err := s.fetch(context.WithoutCancel(ctx))
		var next *sjwtLocalSet
		if err == nil {
			next, err = sjwtNewLocalSet(json)
		}
		s.mu.Lock()
		if err == nil && sequence > s.applied {
			s.local = next
			s.timestamp, s.hasStamp = sjwtWallMs(), true
			s.applied = sequence
		}
		flight.err = err
		if s.pending == flight {
			s.pending = nil
		}
		close(flight.done)
	}
	s.mu.Unlock()
	<-flight.done
	return flight.err
}

// resolve is the remote set's key resolver.
func (s *sjwtRemoteSet) resolve(ctx context.Context, header *core.Object) (*sjwtPublicKey, error) {
	s.mu.Lock()
	stale := s.local == nil || !s.freshFor(s.cacheMaxAge)
	s.mu.Unlock()
	if stale {
		if err := s.reload(ctx); err != nil {
			return nil, err
		}
	}
	s.mu.Lock()
	local := s.local
	s.mu.Unlock()
	key, err := local.resolve(ctx, header)
	if err != nil && sjwtClassOf(err) == "JWKSNoMatchingKey" {
		s.mu.Lock()
		cooling := s.freshFor(s.cooldownDuration)
		s.mu.Unlock()
		if !cooling {
			if err := s.reload(ctx); err != nil {
				return nil, err
			}
			s.mu.Lock()
			local = s.local
			s.mu.Unlock()
			return local.resolve(ctx, header)
		}
	}
	return key, err
}

// sjwtSign is jose SignJWT(claims).setProtectedHeader(header).sign(key) for an Ed25519 or P-256 private key.
func sjwtSign(header, claims *core.Object, key crypto.Signer, alg string) (string, error) {
	if claims == nil {
		return "", &core.TypeError{Message: "JWT Claims Set MUST be an object"}
	}
	payload := core.CloneValue(claims).(*core.Object)
	for _, claim := range []string{"iat", "nbf", "exp"} {
		if value, ok := payload.Get(claim).(float64); ok && (math.IsNaN(value) || math.IsInf(value, 0)) {
			return "", &core.TypeError{Message: `"` + claim + `" claim must be a finite number`}
		}
	}
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
		signature = ed25519.Sign(private, []byte(input))
	case *ecdsa.PrivateKey:
		digest := crypto.SHA256.New()
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
