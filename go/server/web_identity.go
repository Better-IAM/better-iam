package server

// Port of packages/server/src/web-identity.ts: verification of external OIDC tokens for AssumeRoleWithWebIdentity
// (GitHub Actions, GitLab, Kubernetes, cloud workload identity), plus the validators for OIDC provider and
// web-identity trust settings.
//
// This is a separate verifier from IAM's own session JWTs: algorithms come from each provider's allowlist, the `typ`
// must be absent, `JWT` or `application/jwt` (never `biam-session+jwt` or `at+jwt`), and IAM's own issuer is refused.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"math/bits"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// WebIdentityAlgorithms is web-identity.ts WEB_IDENTITY_ALGORITHMS: the signature algorithms a provider may allow.
// Symmetric algorithms and `none` are never accepted.
var WebIdentityAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"}

// DefaultWebIdentityAlgorithms is web-identity.ts DEFAULT_WEB_IDENTITY_ALGORITHMS: used when a provider does not name
// its algorithms.
var DefaultWebIdentityAlgorithms = []string{"RS256", "ES256"}

const (
	webIdentityMaxTokenLength  = 8192
	webIdentityMaxFetchedKeys  = 32
	webIdentityNegativeCacheMs = 30_000
	webIdentityRefetchCooldown = 30_000
	webIdentityMaxCached       = 1000
)

var (
	webIdentityTokenShape = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)
	webIdentityBase64url  = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	webIdentityClaimKey   = regexp.MustCompile(`^token\.[A-Za-z0-9_:.-]{1,122}$`)
	webIdentitySegment    = regexp.MustCompile(`^[A-Za-z0-9_:.-]{1,64}$`)
	webIdentitySeparators = regexp.MustCompile(`[:/]`)
)

var webIdentityLoopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true}

// webIdentityControl is /[\u0000-\u001f\u007f]/.
func webIdentityControl(s string) bool {
	return hasControl(s) || strings.IndexByte(s, 0x7f) >= 0
}

// WebIdentityFailure is web-identity.ts WebIdentityFailure: a refused external token. Callers turn every reason into
// the same public error; Reason (malformed, type, algorithm, unknown-key, signature, issuer, audience, expired,
// not-yet-valid, too-old, lifetime, claims, jwks-unavailable) is for audits.
type WebIdentityFailure struct {
	Reason string
}

func (e *WebIdentityFailure) Error() string {
	return "The web identity token was not accepted (" + e.Reason + ")"
}

// Name is the JavaScript error name.
func (e *WebIdentityFailure) Name() string { return "WebIdentityFailure" }

// webIdentityKeysUnavailable is raised by the key resolver when keys cannot be obtained.
type webIdentityKeysUnavailable struct{}

func (webIdentityKeysUnavailable) Error() string { return "The provider's keys are unavailable" }

// webIdentityReasonFor maps a verification error to its failure reason.
func webIdentityReasonFor(err error) string {
	if known, ok := err.(*WebIdentityFailure); ok {
		return known.Reason
	}
	if _, ok := err.(webIdentityKeysUnavailable); ok {
		return "jwks-unavailable"
	}
	known, ok := err.(*sjwtError)
	if !ok {
		return "malformed"
	}
	switch known.Class {
	case "JWTExpired":
		if known.Claim == "iat" {
			return "too-old"
		}
		return "expired"
	case "JWTClaimValidationFailed":
		switch {
		case known.Reason == "missing" || known.Reason == "invalid":
			return "claims"
		case known.Claim == "iss":
			return "issuer"
		case known.Claim == "aud":
			return "audience"
		case known.Claim == "nbf" || known.Claim == "iat":
			return "not-yet-valid"
		case known.Claim == "typ":
			return "type"
		}
		return "claims"
	case "JOSEAlgNotAllowed", "JOSENotSupported":
		return "algorithm"
	case "JWKSNoMatchingKey", "JWKSMultipleMatchingKeys":
		return "unknown-key"
	case "JWSSignatureVerificationFailed":
		return "signature"
	}
	return "malformed"
}

// webIdentityBase64urlBytes is the decoded size of a base64url string (0 when it is not one).
func webIdentityBase64urlBytes(value any) int {
	text, ok := value.(string)
	if !ok || !webIdentityBase64url.MatchString(text) {
		return 0
	}
	return len(text) * 6 / 8
}

// webIdentityModulusBits is the bit length of a base64url big-endian integer (leading zero bits excluded).
func webIdentityModulusBits(value any) int {
	if webIdentityBase64urlBytes(value) == 0 {
		return 0
	}
	data := nodeBase64Decode(value.(string))
	index := 0
	for index < len(data) && data[index] == 0 {
		index++
	}
	if index == len(data) {
		return 0
	}
	return (len(data)-index)*8 - bits.LeadingZeros32(uint32(data[index])) + 24
}

var webIdentityPrivateMembers = []string{"d", "p", "q", "dp", "dq", "qi", "k", "oth"}

// webIdentityUsableKey is the allowlisted public members of an acceptable verification key, or nil when the key is
// unusable.
func webIdentityUsableKey(value any) *core.Object {
	key, ok := value.(*core.Object)
	if !ok || key == nil {
		return nil
	}
	for _, member := range webIdentityPrivateMembers {
		if !isUndefined(key.Get(member)) {
			return nil
		}
	}
	if use := key.Get("use"); !isUndefined(use) && use != "sig" {
		return nil
	}
	if ops := key.Get("key_ops"); !isUndefined(ops) {
		list, ok := ops.([]any)
		found := false
		for _, item := range list {
			found = found || item == "verify"
		}
		if !ok || !found {
			return nil
		}
	}
	if kid := key.Get("kid"); !isUndefined(kid) {
		text, ok := kid.(string)
		if !ok || utf16Len(text) > 256 {
			return nil
		}
	}
	if alg := key.Get("alg"); !isUndefined(alg) {
		text, ok := alg.(string)
		if !ok || !containsString(WebIdentityAlgorithms, text) {
			return nil
		}
	}
	common := core.NewObject("kty", key.Get("kty"))
	if !isUndefined(key.Get("kid")) {
		common.Set("kid", key.Get("kid"))
	}
	if !isUndefined(key.Get("alg")) {
		common.Set("alg", key.Get("alg"))
	}
	if !isUndefined(key.Get("use")) {
		common.Set("use", "sig")
	}
	switch key.Get("kty") {
	case "RSA":
		// RSA keys under 2048 bits are refused; e must be present.
		if webIdentityModulusBits(key.Get("n")) < 2048 || webIdentityBase64urlBytes(key.Get("e")) == 0 {
			return nil
		}
		return common.Set("n", key.Get("n")).Set("e", key.Get("e"))
	case "EC":
		if crv := key.Get("crv"); crv != "P-256" && crv != "P-384" && crv != "P-521" {
			return nil
		}
		if webIdentityBase64urlBytes(key.Get("x")) == 0 || webIdentityBase64urlBytes(key.Get("y")) == 0 {
			return nil
		}
		return common.Set("crv", key.Get("crv")).Set("x", key.Get("x")).Set("y", key.Get("y"))
	case "OKP":
		if key.Get("crv") != "Ed25519" || webIdentityBase64urlBytes(key.Get("x")) == 0 {
			return nil
		}
		return common.Set("crv", "Ed25519").Set("x", key.Get("x"))
	}
	return nil
}

// WebIdentityIssuerOptions are the rules of WebIdentityIssuer.
type WebIdentityIssuerOptions struct {
	AllowInsecureLocalhost bool
	// SelfIssuer is IAM's own issuer, which is refused (nil when unset).
	SelfIssuer *string
	// AllowedIssuers pins the accepted issuers (nil when unset).
	AllowedIssuers []string
}

// WebIdentityIssuer validates an issuer: an absolute https URL without credentials, query or fragment, at most 512
// characters (http only for loopback hosts with AllowInsecureLocalhost). IAM's own issuer is refused, and when
// AllowedIssuers is set the issuer must be one of them. Returns the value unchanged; comparisons are exact. Fails with
// INVALID_INPUT.
func WebIdentityIssuer(value any, options WebIdentityIssuerOptions) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" || utf16Len(text) > 512 || webIdentityControl(text) {
		return "", invalidInput("Invalid issuer")
	}
	u, err := auth.ParseFetchURL(text)
	if err != nil {
		return "", invalidInput("The issuer must be an absolute URL")
	}
	insecureLocal := options.AllowInsecureLocalhost && webIdentityLoopbackHosts[u.Hostname]
	if u.Protocol != "https:" && !(insecureLocal && u.Protocol == "http:") {
		return "", invalidInput("The issuer must use https")
	}
	if urlUsername(u) != "" || urlPassword(u) != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(text, "?#") {
		return "", invalidInput("The issuer cannot carry credentials, a query or a fragment")
	}
	if options.SelfIssuer != nil && webIdentityTrimmed(text) == webIdentityTrimmed(*options.SelfIssuer) {
		return "", invalidInput("IAM cannot trust its own issuer as a web identity provider")
	}
	if options.AllowedIssuers != nil && !containsString(options.AllowedIssuers, text) {
		return "", invalidInput("The issuer is not in sts.webIdentity.allowedIssuers")
	}
	return text, nil
}

// webIdentityTrimmed is `issuer.replace(/\/+$/, ”)`.
func webIdentityTrimmed(issuer string) string { return strings.TrimRight(issuer, "/") }

// urlUsername is URL#username.
func urlUsername(u *auth.FetchURL) string {
	if u.User == nil {
		return ""
	}
	return u.User.Username()
}

// urlPassword is URL#password.
func urlPassword(u *auth.FetchURL) string {
	if u.User == nil {
		return ""
	}
	password, _ := u.User.Password()
	return password
}

// urlOrigin is URL#origin: scheme://host[:port] for the special schemes, "null" otherwise.
func urlOrigin(u *auth.FetchURL) string {
	switch u.Protocol {
	case "http:", "https:", "ws:", "wss:", "ftp:":
	default:
		return "null"
	}
	origin := u.Protocol + "//" + u.Hostname
	if u.Port != "" {
		origin += ":" + u.Port
	}
	return origin
}

// urlPathname is URL#pathname (the percent-encoded path; "/" for an empty path of a special URL).
func urlPathname(u *auth.FetchURL) string {
	path := u.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

// WebIdentityJwksURI (web-identity.ts webIdentityJwksUri): Validates a JWKS URL: https on port 443 without
// credentials or a fragment (loopback http with the dev option). options carries allowInsecureLocalhost and
// allowPrivateNetworks.
func WebIdentityJwksURI(value any, options *core.Object) (result string, err error) {
	text, ok := value.(string)
	if !ok || text == "" || utf16Len(text) > 2048 || webIdentityControl(text) {
		return "", invalidInput("Invalid jwksUri")
	}
	_, err = auth.CheckFetchURL(text, auth.SafeFetchAddressOptions{
		AllowInsecureLocalhost: truthy(member(options, "allowInsecureLocalhost")),
		AllowPrivateNetworks:   member(options, "allowPrivateNetworks") == true,
	})
	if err != nil {
		if refused, ok := err.(*auth.SafeFetchError); ok && refused.Reason == "address" {
			return "", invalidInput("The jwksUri must not point at a private address")
		}
		return "", invalidInput("The jwksUri must be an https URL on port 443 without credentials or a fragment")
	}
	return text, nil
}

// WebIdentityKeys (web-identity.ts webIdentityKeys): Validates static provider keys: 1 to 20 public keys (RSA of at
// least 2048 bits, EC P-256/P-384/P-521, OKP Ed25519), `use` absent or `sig`. Returns an allowlisted copy.
func WebIdentityKeys(value any) (result *core.Object, err error) {
	set, ok := value.(*core.Object)
	if !ok || set == nil {
		return nil, invalidInput("jwks must be an object with keys")
	}
	keys, ok := set.Get("keys").([]any)
	if !ok || len(keys) < 1 || len(keys) > 20 {
		return nil, invalidInput("jwks must contain 1 to 20 keys")
	}
	usable := make([]any, 0, len(keys))
	for _, key := range keys {
		checked := webIdentityUsableKey(key)
		if checked == nil {
			return nil, invalidInput("jwks keys must be public RSA (at least 2048 bits), EC (P-256, P-384, P-521) or Ed25519 signature keys")
		}
		usable = append(usable, checked)
	}
	return core.NewObject("keys", usable), nil
}

// WebIdentityWebIdentityAlgorithms (web-identity.ts webIdentityAlgorithms): Validates an algorithm allowlist: a
// non-empty subset of `WEB_IDENTITY_ALGORITHMS` (default RS256 and ES256).
func WebIdentityWebIdentityAlgorithms(value any) (result []string, err error) {
	if isUndefined(value) {
		return append([]string{}, DefaultWebIdentityAlgorithms...), nil
	}
	list, ok := value.([]any)
	valid := ok && len(list) > 0
	algorithms := make([]string, 0, len(list))
	for _, item := range list {
		text, isText := item.(string)
		if !isText || !containsString(WebIdentityAlgorithms, text) {
			valid = false
			break
		}
		algorithms = append(algorithms, text)
	}
	if !valid {
		return nil, invalidInput("algorithms must be a non-empty subset of " + strings.Join(WebIdentityAlgorithms, ", "))
	}
	return unique(algorithms), nil
}

// WebIdentityAudiences (web-identity.ts webIdentityAudiences): Validates the accepted audiences: 1 to 10 strings of
// 1 to 256 characters.
func WebIdentityAudiences(value any) (result []string, err error) {
	list, ok := value.([]any)
	valid := ok && len(list) >= 1 && len(list) <= 10
	audiences := make([]string, 0, len(list))
	for _, item := range list {
		text, isText := item.(string)
		if !isText || text == "" || utf16Len(text) > 256 || webIdentityControl(text) {
			valid = false
			break
		}
		audiences = append(audiences, text)
	}
	if !valid {
		return nil, invalidInput("audiences must contain 1 to 10 strings of at most 256 characters")
	}
	return unique(audiences), nil
}

const (
	webIdentityMaxConditionEntries = 20
	webIdentityConditionAction     = "sts:AssumeRoleWithWebIdentity"
)

// WebIdentityClaimName (web-identity.ts webIdentityClaimName): Validates a flattened claim name as used in
// conditions, `tagClaims` and `sourceIdentityClaim`: `token.<claim>`.
func WebIdentityClaimName(value any) (result string, err error) {
	text, ok := value.(string)
	if !ok || !webIdentityClaimKey.MatchString(text) {
		return "", invalidInput("Claim names must look like token.<claim> (letters, digits, _ : . -)")
	}
	return text, nil
}

// webIdentityPinsSubject is whether a `StringLike` value on `token.sub` names a workload rather than a whole
// platform: any wildcard (`*`, `?`) comes after at least two complete segments (each ended by `:` or `/`).
// `repo:acme/*` and `repo:acme/api:*` pin an owner; `*`, `repo:*` (every repository on the platform) and `repo:acme*`
// (also `acme-evil`) do not.
func webIdentityPinsSubject(value string) bool {
	first := strings.IndexAny(value, "*?")
	if first == -1 {
		return true
	}
	// split(/[:/]/).slice(0, -1).filter(Boolean): the last piece (after the final separator) is not complete.
	pieces := webIdentitySeparators.Split(value[:first], -1)
	pieces = pieces[:len(pieces)-1]
	complete := 0
	for _, piece := range pieces {
		if piece != "" {
			complete++
		}
	}
	return complete >= 2
}

// WebIdentityConditions (web-identity.ts webIdentityConditions): Validates web-identity trust conditions: the core
// condition grammar over `token.<claim>` keys, at most 20 operator/key entries, no policy variables, and a mandatory
// subject pin — a `StringEquals` or `StringLike` entry on `token.sub` whose values are non-empty and, for
// `StringLike`, put any wildcard only after two complete segments (see `pinsSubject`; else WEAK_TRUST_CONDITIONS).
func WebIdentityConditions(value any) (result *core.Object, err error) {
	conditions, ok := value.(*core.Object)
	if !ok || conditions == nil {
		return nil, invalidInput("conditions must be an operator map")
	}
	entries := 0
	for _, operator := range conditions.Keys() {
		attributes, ok := conditions.Get(operator).(*core.Object)
		if !ok || attributes == nil {
			return nil, invalidInput("conditions must map operators to claim keys")
		}
		for _, key := range attributes.Keys() {
			entries++
			if !webIdentityClaimKey.MatchString(key) {
				return nil, invalidInput("Condition key " + key + " must look like token.<claim>")
			}
			expected := attributes.Get(key)
			values, isList := expected.([]any)
			if !isList {
				values = []any{expected}
			}
			for _, item := range values {
				if text, ok := item.(string); ok && strings.Contains(text, "${") {
					return nil, invalidInput("Policy variables are not allowed in web identity conditions")
				}
			}
		}
	}
	if entries > webIdentityMaxConditionEntries {
		return nil, invalidInput("conditions may contain at most 20 entries")
	}
	if err := core.ValidatePolicy(core.NewObject("version", 1.0, "statements", []any{core.NewObject(
		"effect", "allow", "actions", []any{webIdentityConditionAction}, "resources", []any{"trust/*"},
		"conditions", conditions,
	)})); err != nil {
		return nil, err
	}
	pinned := false
	for _, operator := range []string{"StringEquals", "StringLike"} {
		expected := member(conditions.Get(operator), "token.sub")
		if isUndefined(expected) {
			continue
		}
		values, isList := expected.([]any)
		if !isList {
			values = []any{expected}
		}
		every := true
		for _, item := range values {
			text, ok := item.(string)
			if !ok || text == "" || (operator != "StringEquals" && !webIdentityPinsSubject(text)) {
				every = false
				break
			}
		}
		if every {
			pinned = true
			break
		}
	}
	if !pinned {
		return nil, core.NewIamError("WEAK_TRUST_CONDITIONS",
			"Web identity trusts must pin token.sub with StringEquals or StringLike (a wildcard only after two complete segments, such as repo:acme/*)")
	}
	return conditions.Clone(), nil
}

var webIdentityUnsafeSegments = map[string]bool{"__proto__": true, "prototype": true, "constructor": true}

const (
	webIdentityMaxClaimKeys   = 128
	webIdentityMaxClaimDepth  = 3
	webIdentityMaxClaimString = 1024
	webIdentityMaxClaimArray  = 64
)

// webIdentityScalar is a string of at most 1024 characters, a finite number or a boolean.
func webIdentityScalar(value any) bool {
	switch typed := value.(type) {
	case string:
		return utf16Len(typed) <= webIdentityMaxClaimString
	case float64:
		return !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case bool:
		return true
	}
	return false
}

// FlattenClaims (web-identity.ts flattenClaims) flattens a verified payload into `token.<path>` condition keys:
// nested objects to depth 3 joined with '.', segments matching /^[A-Za-z0-9_:.-]{1,64}$/, strings up to 1024
// characters, finite numbers, booleans, and arrays of up to 64 such scalars; at most 128 keys. Anything else is left
// out.
func FlattenClaims(payload *core.Object) *core.Object {
	result := core.NewObject()
	count := 0
	var walk func(value *core.Object, prefix string, depth int)
	walk = func(value *core.Object, prefix string, depth int) {
		for _, name := range value.Keys() {
			if count >= webIdentityMaxClaimKeys {
				return
			}
			if !webIdentitySegment.MatchString(name) || webIdentityUnsafeSegments[name] {
				continue
			}
			key := prefix + "." + name
			if !webIdentityClaimKey.MatchString(key) {
				continue
			}
			item := value.Get(name)
			if webIdentityScalar(item) {
				result.Set(key, item)
				count++
			} else if list, ok := item.([]any); ok {
				every := len(list) <= webIdentityMaxClaimArray
				for _, element := range list {
					if !every {
						break
					}
					every = webIdentityScalar(element)
				}
				if every {
					result.Set(key, append([]any{}, list...))
					count++
				}
			} else if nested, ok := item.(*core.Object); ok && nested != nil && depth < webIdentityMaxClaimDepth {
				walk(nested, key, depth+1)
			}
		}
	}
	walk(payload, "token", 1)
	return result
}

// webIdentityConditionStatement is the policy document a trust's conditions are evaluated as.
func webIdentityConditionDocument(conditions *core.Object, trustID string) *core.Object {
	return core.NewObject("version", 1.0, "statements", []any{core.NewObject(
		"effect", "allow", "actions", []any{webIdentityConditionAction}, "resources", []any{"trust/" + trustID},
		"conditions", conditions,
	)})
}

// MatchWebIdentityConditions (web-identity.ts matchWebIdentityConditions): Evaluates trust conditions against
// flattened claims with the core policy engine (an allow statement for `sts:AssumeRoleWithWebIdentity` on
// `trust/{trustId}`). `failed` lists each unmet entry as `Operator:key`.
func MatchWebIdentityConditions(conditions *core.Object, context *core.Object, trustID string) (result *core.Object, err error) {
	evaluate := func(entries *core.Object) (bool, error) {
		var copied *core.Object
		if context != nil {
			copied = context.Clone()
		} else {
			copied = core.NewObject()
		}
		decision, err := core.EvaluatePolicy(core.EvaluationInput{
			Action: webIdentityConditionAction, Resource: "trust/" + trustID, Context: copied,
			Grants: []any{webIdentityConditionDocument(entries, trustID)},
		})
		return decision.Allowed, err
	}
	failed := []any{}
	if conditions != nil {
		for _, operator := range conditions.Keys() {
			attributes, ok := conditions.Get(operator).(*core.Object)
			if !ok || attributes == nil {
				continue
			}
			for _, key := range attributes.Keys() {
				allowed, err := evaluate(core.NewObject(operator, core.NewObject(key, attributes.Get(key))))
				if err != nil {
					return nil, err
				}
				if !allowed {
					failed = append(failed, operator+":"+key)
				}
			}
		}
	}
	matched := len(failed) == 0
	if matched {
		if matched, err = evaluate(conditions); err != nil {
			return nil, err
		}
	}
	return core.NewObject("matched", matched, "failed", failed), nil
}

// WebIdentityReplayID (web-identity.ts webIdentityReplayId): The replay-cache key of a token at a provider (hex): by
// `jti` when present (non-empty), else by the hash of the token's signed content (`header.payload`). The signature
// segment is left out on purpose: it is malleable without the key (unused trailing base64url bits, and ECDSA's
// (r, s) / (r, n - s) pair), so hashing the whole token would let one token be redeemed several times under
// different spellings.
func WebIdentityReplayID(providerID string, jti string, token string) (result string, err error) {
	signed := ""
	if last := strings.LastIndex(token, "."); last > 0 {
		signed = token[:last]
	}
	suffix := "tok:" + webIdentitySha256(signed)
	if jti != "" {
		suffix = "jti:" + jti
	}
	return webIdentitySha256("wi\n" + providerID + "\n" + suffix), nil
}

func webIdentitySha256(value string) string {
	sum := sha256.Sum256(utf8Bytes(value))
	return hex.EncodeToString(sum[:])
}

// WebIdentityVerifierOptions is web-identity.ts WebIdentityVerifierOptions.
type WebIdentityVerifierOptions struct {
	// JwksCacheSeconds How long fetched keys are used before they are fetched again, in seconds.
	JwksCacheSeconds       float64
	FetchTimeoutMs         float64
	MaxJwksBytes           float64
	AllowPrivateNetworks   bool
	AllowInsecureLocalhost bool
	// FetchJSON A host transport replacing the guarded fetch; the host is responsible for its safety.
	FetchJSON func(context.Context, *auth.FetchURL) (any, error)
	// Now The clock, in epoch milliseconds.
	Now func() float64
	// SelfIssuer IAM's own session token issuer, never accepted from a provider ("" when unset).
	SelfIssuer string
}

// webIdentityCachedKeys are the cached keys of one provider version.
type webIdentityCachedKeys struct {
	updatedAt any
	// fetchedAt is when the current keys were fetched (ms); hasFetched is false before the first success.
	fetchedAt  float64
	hasFetched bool
	keys       *sjwtLocalSet
	// failedAt is when the last fetch failed (ms), for the negative cache.
	failedAt  float64
	hasFailed bool
	pending   *webIdentityFlight
	// local is the imported static key set of a provider configured with `jwks`.
	local *sjwtLocalSet
}

type webIdentityFlight struct {
	done chan struct{}
	keys *sjwtLocalSet
	err  error
}

// WebIdentityVerifier is web-identity.ts WebIdentityVerifier. Fetched keys are cached per provider id (dropped when
// `updatedAt` changes) for `jwksCacheSeconds`, fetched single-flight, remembered as unavailable for 30 s after a
// failure, and refetched on an unknown `kid` at most once per 30 s. Nothing is fetched until a token needs it.
type WebIdentityVerifier struct {
	options WebIdentityVerifierOptions
	cacheMs float64

	mu    sync.Mutex
	cache map[string]*webIdentityCachedKeys
	order []string
}

// CreateWebIdentityVerifier builds the WebIdentityVerifier (web-identity.ts createWebIdentityVerifier).
func CreateWebIdentityVerifier(options *WebIdentityVerifierOptions) *WebIdentityVerifier {
	verifier := &WebIdentityVerifier{cache: map[string]*webIdentityCachedKeys{}}
	if options != nil {
		verifier.options = *options
	}
	verifier.cacheMs = verifier.options.JwksCacheSeconds * 1000
	return verifier
}

func (s *WebIdentityVerifier) now() float64 {
	if s.options.Now == nil {
		return float64(time.Now().UnixMilli())
	}
	return s.options.Now()
}

func (s *WebIdentityVerifier) fetchJSON(ctx context.Context, u *auth.FetchURL) (any, error) {
	if s.options.FetchJSON != nil {
		return s.options.FetchJSON(ctx, u)
	}
	return auth.FetchJSONSafely(ctx, u.Href, auth.SafeFetchOptions{
		TimeoutMs: int64(s.options.FetchTimeoutMs), MaxBytes: int64(s.options.MaxJwksBytes),
		AllowPrivateNetworks: s.options.AllowPrivateNetworks, AllowInsecureLocalhost: s.options.AllowInsecureLocalhost,
	})
}

func (s *WebIdentityVerifier) checkedURL(value any) (*auth.FetchURL, error) {
	text, err := WebIdentityJwksURI(value, core.NewObject("allowInsecureLocalhost", s.options.AllowInsecureLocalhost,
		"allowPrivateNetworks", s.options.AllowPrivateNetworks))
	if err != nil {
		return nil, webIdentityKeysUnavailable{}
	}
	u, err := auth.ParseFetchURL(text)
	if err != nil {
		return nil, webIdentityKeysUnavailable{}
	}
	return u, nil
}

// download fetches a provider's keys: from its jwksUri, or through OIDC discovery.
func (s *WebIdentityVerifier) download(ctx context.Context, provider *core.Object) (*sjwtLocalSet, error) {
	jwksURI := provider.Get("jwksUri")
	if isUndefined(jwksURI) {
		issuer, ok := provider.Get("issuer").(string)
		if !ok {
			return nil, &core.TypeError{Message: "issuer.replace is not a function"}
		}
		discovery, err := auth.ParseFetchURL(webIdentityTrimmed(issuer) + "/.well-known/openid-configuration")
		if err != nil {
			return nil, &core.TypeError{Message: "Invalid URL"}
		}
		target, err := s.checkedURL(discovery.Href)
		if err != nil {
			return nil, err
		}
		document, err := s.fetchJSON(ctx, target)
		if err != nil {
			return nil, err
		}
		found, ok := document.(*core.Object)
		if !ok || found == nil || !core.StrictEquals(found.Get("issuer"), provider.Get("issuer")) {
			return nil, webIdentityKeysUnavailable{}
		}
		jwksURI = found.Get("jwks_uri")
	}
	target, err := s.checkedURL(jwksURI)
	if err != nil {
		return nil, err
	}
	body, err := s.fetchJSON(ctx, target)
	if err != nil {
		return nil, err
	}
	set, ok := body.(*core.Object)
	if !ok || set == nil {
		return nil, webIdentityKeysUnavailable{}
	}
	list, ok := set.Get("keys").([]any)
	if !ok {
		return nil, webIdentityKeysUnavailable{}
	}
	keys := []any{}
	for _, key := range list {
		if usable := webIdentityUsableKey(key); usable != nil {
			keys = append(keys, usable)
		}
	}
	if len(keys) > webIdentityMaxFetchedKeys {
		keys = keys[:webIdentityMaxFetchedKeys]
	}
	if len(keys) == 0 {
		return nil, webIdentityKeysUnavailable{}
	}
	return sjwtNewLocalSet(core.NewObject("keys", keys))
}

// refresh fetches the provider's keys once for all concurrent callers and records the outcome.
func (s *WebIdentityVerifier) refresh(ctx context.Context, provider *core.Object, entry *webIdentityCachedKeys) (*sjwtLocalSet, error) {
	s.mu.Lock()
	flight := entry.pending
	if flight == nil {
		flight = &webIdentityFlight{done: make(chan struct{})}
		entry.pending = flight
		s.mu.Unlock()
		keys, err := s.download(context.WithoutCancel(ctx), provider)
		now := s.now()
		s.mu.Lock()
		if err == nil {
			entry.keys = keys
			entry.fetchedAt, entry.hasFetched = now, true
			entry.hasFailed = false
		} else {
			entry.failedAt, entry.hasFailed = now, true
			keys, err = nil, webIdentityKeysUnavailable{}
		}
		flight.keys, flight.err = keys, err
		entry.pending = nil
		close(flight.done)
	}
	s.mu.Unlock()
	<-flight.done
	return flight.keys, flight.err
}

// entryFor is the cache entry of a provider version (a changed `updatedAt` starts a new one).
func (s *WebIdentityVerifier) entryFor(provider *core.Object) *webIdentityCachedKeys {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := jsString(provider.Get("id"))
	entry, ok := s.cache[id]
	if !ok || !core.StrictEquals(entry.updatedAt, provider.Get("updatedAt")) {
		if !ok && len(s.cache) >= webIdentityMaxCached && len(s.order) > 0 {
			delete(s.cache, s.order[0])
			s.order = s.order[1:]
		}
		entry = &webIdentityCachedKeys{updatedAt: provider.Get("updatedAt")}
		if !ok {
			s.order = append(s.order, id)
		}
		s.cache[id] = entry
	}
	return entry
}

func (s *WebIdentityVerifier) fetchedKeys(ctx context.Context, provider *core.Object) (*sjwtLocalSet, error) {
	entry := s.entryFor(provider)
	now := s.now()
	s.mu.Lock()
	if entry.keys != nil && entry.hasFetched && now-entry.fetchedAt < s.cacheMs {
		keys := entry.keys
		s.mu.Unlock()
		return keys, nil
	}
	if entry.hasFailed && now-entry.failedAt < webIdentityNegativeCacheMs && entry.pending == nil {
		s.mu.Unlock()
		return nil, webIdentityKeysUnavailable{}
	}
	s.mu.Unlock()
	return s.refresh(ctx, provider, entry)
}

// refetchForUnknownKid refetches after an unknown kid, unless the cooldown since the last fetch attempt is still
// running (nil keys then). A failed attempt starts the cooldown too, so an unreachable IdP is not refetched for every
// token with a random kid.
func (s *WebIdentityVerifier) refetchForUnknownKid(ctx context.Context, provider *core.Object) (*sjwtLocalSet, error) {
	entry := s.entryFor(provider)
	s.mu.Lock()
	if flight := entry.pending; flight != nil {
		s.mu.Unlock()
		<-flight.done
		return flight.keys, flight.err
	}
	lastAttempt := math.Inf(-1)
	if entry.hasFetched {
		lastAttempt = entry.fetchedAt
	}
	if entry.hasFailed && entry.failedAt > lastAttempt {
		lastAttempt = entry.failedAt
	}
	s.mu.Unlock()
	if s.now()-lastAttempt < math.Max(webIdentityRefetchCooldown, webIdentityNegativeCacheMs) {
		return nil, nil
	}
	return s.refresh(ctx, provider, entry)
}

// localKeys is the static key set of a provider, imported once per provider version; a changed key list comes with
// a new `updatedAt`.
func (s *WebIdentityVerifier) localKeys(provider *core.Object) (*sjwtLocalSet, error) {
	entry := s.entryFor(provider)
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry.local == nil {
		list, _ := member(provider.Get("jwks"), "keys").([]any)
		usable := []any{}
		for _, key := range list {
			if checked := webIdentityUsableKey(key); checked != nil {
				usable = append(usable, checked)
			}
		}
		local, err := sjwtNewLocalSet(core.NewObject("keys", usable))
		if err != nil {
			return nil, err
		}
		entry.local = local
	}
	return entry.local, nil
}

// webIdentityStrings is a stored list (a TypeError when it is not a list, as spreading it would be). With strict, a
// non-string entry is a TypeError too (jose's algorithms option); otherwise it is left out, as it never equals a
// string claim.
func webIdentityStrings(value any, name string, strict bool) ([]string, error) {
	list, ok := value.([]any)
	if !ok {
		return nil, &core.TypeError{Message: name + " is not iterable"}
	}
	result := make([]string, 0, len(list))
	for _, item := range list {
		text, isText := item.(string)
		if !isText {
			if strict {
				return nil, &core.TypeError{Message: `"algorithms" option must be an array of strings`}
			}
			continue
		}
		result = append(result, text)
	}
	return result, nil
}

func (s *WebIdentityVerifier) check(ctx context.Context, provider *core.Object, token string, keys *sjwtLocalSet) (*core.Object, error) {
	algorithms, err := webIdentityStrings(provider.Get("algorithms"), "provider.algorithms", true)
	if err != nil {
		return nil, err
	}
	audiences, err := webIdentityStrings(provider.Get("audiences"), "provider.audiences", false)
	if err != nil {
		return nil, err
	}
	issuer, _ := provider.Get("issuer").(string)
	payload, _, err := sjwtJwtVerify(ctx, token, keys.resolve, sjwtVerifyOptions{
		algorithms: algorithms, issuer: issuer, hasIssuer: true, audience: audiences,
		requiredClaims: []string{"iss", "sub", "aud", "exp", "iat"}, currentDate: s.now(),
		clockTolerance: provider.Get("clockToleranceSeconds"), maxTokenAge: provider.Get("maxTokenLifetimeSeconds"),
	})
	return payload, err
}

// verifyPayload is the guarded part of Verify: every failure becomes a WebIdentityFailure.
func (s *WebIdentityVerifier) verifyPayload(ctx context.Context, provider *core.Object, token string) (*core.Object, error) {
	if truthy(provider.Get("jwks")) {
		keys, err := s.localKeys(provider)
		if err != nil {
			return nil, err
		}
		return s.check(ctx, provider, token, keys)
	}
	keys, err := s.fetchedKeys(ctx, provider)
	if err != nil {
		return nil, err
	}
	payload, err := s.check(ctx, provider, token, keys)
	if err != nil {
		if sjwtClassOf(err) != "JWKSNoMatchingKey" {
			return nil, err
		}
		refreshed, refetchErr := s.refetchForUnknownKid(ctx, provider)
		if refetchErr != nil {
			return nil, refetchErr
		}
		if refreshed == nil {
			return nil, err
		}
		return s.check(ctx, provider, token, refreshed)
	}
	return payload, nil
}

// Verify (web-identity.ts WebIdentityVerifier.verify): Verifies an external token against a provider (a stored OIDC
// provider record), or fails with a *WebIdentityFailure. The result is the verified identity: issuer, subject, the
// provider audience the token was accepted for, jti (when present), issuedAt, expiresAt (epoch seconds) and context
// (the flattened claims as `token.<claim>` condition keys). A provider record that cannot be read fails with a
// TypeError.
func (s *WebIdentityVerifier) Verify(ctx context.Context, provider *core.Object, token string) (result *core.Object, err error) {
	if utf16Len(token) > webIdentityMaxTokenLength || !webIdentityTokenShape.MatchString(token) {
		return nil, &WebIdentityFailure{Reason: "malformed"}
	}
	header, err := sjwtDecodeProtectedHeader(token)
	if err != nil {
		return nil, &WebIdentityFailure{Reason: "malformed"}
	}
	if typ := header.Get("typ"); !isUndefined(typ) {
		text := ""
		if value, ok := typ.(string); ok {
			text = core.JSLower(value)
		}
		if !strings.Contains(text, "/") {
			text = "application/" + text
		}
		if text != "application/jwt" {
			return nil, &WebIdentityFailure{Reason: "type"}
		}
	}
	if provider == nil {
		return nil, &core.TypeError{Message: "Cannot read properties of undefined (reading 'algorithms')"}
	}
	algorithms, ok := provider.Get("algorithms").([]any)
	if !ok {
		return nil, &core.TypeError{Message: "provider.algorithms.includes is not a function"}
	}
	alg, isText := header.Get("alg").(string)
	allowed := false
	for _, item := range algorithms {
		allowed = allowed || (isText && item == alg)
	}
	if !isText || !allowed || !containsString(WebIdentityAlgorithms, alg) {
		return nil, &WebIdentityFailure{Reason: "algorithm"}
	}
	if kid := header.Get("kid"); !isUndefined(kid) {
		if _, ok := kid.(string); !ok {
			return nil, &WebIdentityFailure{Reason: "malformed"}
		}
	}
	issuer, ok := provider.Get("issuer").(string)
	if !ok {
		return nil, &core.TypeError{Message: "provider.issuer.replace is not a function"}
	}
	if s.options.SelfIssuer != "" && webIdentityTrimmed(issuer) == webIdentityTrimmed(s.options.SelfIssuer) {
		return nil, &WebIdentityFailure{Reason: "issuer"}
	}

	payload, err := s.verifyPayload(ctx, provider, token)
	if err != nil {
		return nil, &WebIdentityFailure{Reason: webIdentityReasonFor(err)}
	}

	iat, okIat := payload.Get("iat").(float64)
	exp, okExp := payload.Get("exp").(float64)
	if !okIat || !okExp {
		return nil, &WebIdentityFailure{Reason: "claims"}
	}
	if maxLifetime, ok := provider.Get("maxTokenLifetimeSeconds").(float64); ok && exp-iat > maxLifetime {
		return nil, &WebIdentityFailure{Reason: "lifetime"}
	}
	sub, ok := payload.Get("sub").(string)
	if !ok || sub == "" || utf16Len(sub) > 512 {
		return nil, &WebIdentityFailure{Reason: "claims"}
	}
	jti := payload.Get("jti")
	if !isUndefined(jti) {
		text, ok := jti.(string)
		if !ok || text == "" || utf16Len(text) > 256 {
			return nil, &WebIdentityFailure{Reason: "claims"}
		}
	}
	aud := payload.Get("aud")
	audiences, isList := aud.([]any)
	if !isList {
		audiences = []any{aud}
	}
	providerAudiences, _ := provider.Get("audiences").([]any)
	var audience any = core.Undefined
	for _, item := range providerAudiences {
		found := false
		for _, candidate := range audiences {
			if core.StrictEquals(candidate, item) {
				found = true
				break
			}
		}
		if found {
			audience = item
			break
		}
	}
	if isUndefined(audience) {
		return nil, &WebIdentityFailure{Reason: "audience"}
	}
	verified := core.NewObject("issuer", provider.Get("issuer"), "subject", sub, "audience", audience)
	if !isUndefined(jti) {
		verified.Set("jti", jti)
	}
	verified.Set("issuedAt", iat)
	verified.Set("expiresAt", exp)
	verified.Set("context", FlattenClaims(payload))
	return verified, nil
}

// Forget (web-identity.ts WebIdentityVerifier.forget): Drops the cached keys of a provider (after an update or
// deletion).
func (s *WebIdentityVerifier) Forget(providerID string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cache[providerID]; ok {
		delete(s.cache, providerID)
		for i, id := range s.order {
			if id == providerID {
				s.order = append(s.order[:i:i], s.order[i+1:]...)
				break
			}
		}
	}
	return nil
}
