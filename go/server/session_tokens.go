package server

// Port of packages/server/src/session-tokens.ts: verification of IAM-signed session JWTs (`format: 'jwt'` role
// sessions and session tokens) for downstream services. IAM itself verifies with the same code path before it checks
// the stored row.
//
// Offline verification learns of revocation only at `exp`; use short lifetimes for high-risk services, or an online
// check (`sts.getCallerIdentity`, or IamSessionTokens.Verify in process).

import (
	"context"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// SessionTokenError is session-tokens.ts SessionTokenError (code INVALID_SESSION_TOKEN, status 401): Reason is
// malformed, too-large, type, algorithm, unknown-key, signature, expired, not-yet-valid, issuer, audience, claims,
// lifetime, kind, jwks or revoked; Message defaults to "The session token is invalid or expired". `reason` is for logs
// and metrics; clients should only see the 401.
type SessionTokenError struct {
	Reason  string
	Message string
}

func (e *SessionTokenError) Error() string {
	if e.Message == "" {
		return "The session token is invalid or expired"
	}
	return e.Message
}

// Code is the error code (INVALID_SESSION_TOKEN).
func (e *SessionTokenError) Code() string { return "INVALID_SESSION_TOKEN" }

// Status is the HTTP status (401).
func (e *SessionTokenError) Status() int { return 401 }

// Name is the JavaScript error name.
func (e *SessionTokenError) Name() string { return "SessionTokenError" }

// SessionTokenAlgorithms is session-tokens.ts SESSION_TOKEN_ALGORITHMS: the only signature algorithms IAM issues or
// accepts for session JWTs.
var SessionTokenAlgorithms = []string{"EdDSA", "ES256"}

// sessionTokenKinds are the session kinds that may be issued as JWTs. User sessions and API keys are never JWTs.
var sessionTokenKinds = []string{"role", "session-token"}

var (
	sessionBearer         = regexp.MustCompile(`^(?i:Bearer) ([^` + jsWhitespace + `]+)$`)
	sessionKidPattern     = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)
	sessionOptionalClaims = []string{"role", "trust", "src_tid", "session_name", "source_identity", "idp", "idp_sub"}
)

// SessionTokenVerifierOptions is session-tokens.ts SessionTokenVerifierOptions.
type SessionTokenVerifierOptions struct {
	// Issuer is the IAM issuer, exactly: `${baseURL.origin}${basePath}` unless `sts.jwt.issuer` overrides it.
	Issuer string
	// Audience is the audience (a string) or audiences ([]string) this service accepts; a token must name one.
	Audience any
	// JWKS is the public keys: a JWK set (*core.Object with keys, for example IamSessionTokens.Jwks()), or the URL of
	// the JWKS route (a string or *url.URL), which must be https except on localhost. A remote set is cached and
	// refetched on an unknown `kid`, at most once per cooldown.
	JWKS any
	// Algorithms is a subset of SessionTokenAlgorithms (nil: both).
	Algorithms []string
	// Kinds is the session kinds accepted (nil: both).
	Kinds []string
	// ClockToleranceSeconds is the tolerated clock skew for `exp` and `nbf`, 0..60 seconds (default 5).
	ClockToleranceSeconds *float64
	// MaxLifetimeSeconds is the longest accepted `exp - iat` in seconds (default 43200).
	MaxLifetimeSeconds *float64
	// Now is the clock, in epoch milliseconds (default: the wall clock).
	Now func() int64
	// CacheMaxAgeSeconds is the remote JWKS cache lifetime in seconds (default 600).
	CacheMaxAgeSeconds *float64
	// CooldownSeconds is the minimum time between remote JWKS refetches triggered by an unknown `kid` (default 30).
	CooldownSeconds *float64
	// TimeoutMs is the remote JWKS fetch timeout in milliseconds (default 5000).
	TimeoutMs *float64
}

// SessionTokenVerifier is session-tokens.ts SessionTokenVerifier.
type SessionTokenVerifier struct {
	issuer         string
	audience       []string
	algorithms     []string
	kinds          []string
	clockTolerance float64
	maxLifetime    float64
	now            func() int64
	resolveKey     sjwtResolver
	// pinned is set for a local set: the algorithm of each kid, checked before any cryptography runs.
	pinned map[string]string
}

// keySetUnavailable is raised by the key resolver when the key set itself cannot be obtained; mapped to reason `jwks`.
type keySetUnavailable struct{}

func (keySetUnavailable) Error() string { return "The key set is unavailable" }

// invalidVerifierOption is the TypeError of a bad verifier option.
func invalidVerifierOption(name string) error {
	return &core.TypeError{Message: "Invalid session token verifier option: " + name}
}

// verifierSeconds is `value ?? fallback`, a finite number within min..max.
func verifierSeconds(value *float64, fallback float64, name string, min, max float64) (float64, error) {
	result := fallback
	if value != nil {
		result = *value
	}
	if math.IsNaN(result) || math.IsInf(result, 0) || result < min || result > max {
		return 0, invalidVerifierOption(name)
	}
	return result, nil
}

// verifierRemoteURL is a remote JWKS URL: https, or http on a loopback host, without credentials or a fragment.
func verifierRemoteURL(value string) (*auth.FetchURL, error) {
	u, err := auth.ParseFetchURL(value)
	if err != nil {
		return nil, invalidVerifierOption("jwks")
	}
	local := webIdentityLoopbackHosts[u.Hostname]
	if u.Protocol != "https:" && !(local && u.Protocol == "http:") {
		return nil, invalidVerifierOption("jwks")
	}
	if urlUsername(u) != "" || urlPassword(u) != "" || u.Fragment != "" {
		return nil, invalidVerifierOption("jwks")
	}
	return u, nil
}

// sessionReasonFor maps jose errors to failure reasons; anything unrecognised is `malformed`.
func sessionReasonFor(err error) string {
	if known, ok := err.(*SessionTokenError); ok {
		return known.Reason
	}
	if _, ok := err.(keySetUnavailable); ok {
		return "jwks"
	}
	known, ok := err.(*sjwtError)
	if !ok {
		return "malformed"
	}
	switch known.Class {
	case "JWTExpired":
		return "expired"
	case "JWTClaimValidationFailed":
		switch {
		case known.Claim == "typ":
			return "type"
		case known.Reason == "missing" || known.Reason == "invalid":
			return "claims"
		case known.Claim == "iss":
			return "issuer"
		case known.Claim == "aud":
			return "audience"
		case known.Claim == "nbf" || known.Claim == "iat":
			return "not-yet-valid"
		}
		return "claims"
	case "JOSEAlgNotAllowed":
		return "algorithm"
	case "JWKSNoMatchingKey", "JWKSMultipleMatchingKeys":
		return "unknown-key"
	case "JWSSignatureVerificationFailed":
		return "signature"
	case "JWKSTimeout", "JWKSInvalid":
		return "jwks"
	}
	return "malformed"
}

// sessionNonEmpty is a string of 1 to max characters.
func sessionNonEmpty(value any, max int) bool {
	text, ok := value.(string)
	return ok && text != "" && utf16Len(text) <= max
}

// sessionNumeric is a finite number.
func sessionNumeric(value any) bool {
	number, ok := value.(float64)
	return ok && !math.IsNaN(number) && !math.IsInf(number, 0)
}

// sessionClaimsOf checks claim types and returns an allowlisted copy; unknown claims are dropped.
func sessionClaimsOf(payload *core.Object) (*core.Object, error) {
	aud := payload.Get("aud")
	audienceValid := sessionNonEmpty(aud, 2048)
	if list, ok := aud.([]any); ok && len(list) > 0 {
		audienceValid = true
		for _, item := range list {
			if !sessionNonEmpty(item, 2048) {
				audienceValid = false
			}
		}
	}
	_, mfa := payload.Get("mfa").(bool)
	if !sessionNonEmpty(payload.Get("iss"), 2048) || !audienceValid || !sessionNonEmpty(payload.Get("sub"), 256) ||
		!sessionNonEmpty(payload.Get("tid"), 256) || !sessionNonEmpty(payload.Get("sid"), 256) ||
		!core.StrictEquals(payload.Get("jti"), payload.Get("sid")) || !sessionNumeric(payload.Get("iat")) || !sessionNumeric(payload.Get("nbf")) ||
		!sessionNumeric(payload.Get("exp")) || !sessionNumeric(payload.Get("auth_time")) || !mfa {
		return nil, &SessionTokenError{Reason: "claims"}
	}
	audience := aud
	if list, ok := aud.([]any); ok {
		audience = append([]any{}, list...)
	}
	claims := core.NewObject(
		"iss", payload.Get("iss"), "aud", audience, "sub", payload.Get("sub"), "tid", payload.Get("tid"),
		"sid", payload.Get("sid"), "jti", payload.Get("sid"), "iat", payload.Get("iat"), "nbf", payload.Get("nbf"),
		"exp", payload.Get("exp"), "auth_time", payload.Get("auth_time"), "kind", payload.Get("kind"),
		"mfa", payload.Get("mfa"),
	)
	for _, name := range sessionOptionalClaims {
		value := payload.Get(name)
		if isUndefined(value) {
			continue
		}
		if !sessionNonEmpty(value, 1024) {
			return nil, &SessionTokenError{Reason: "claims"}
		}
		claims.Set(name, value)
	}
	return claims, nil
}

// CreateSessionTokenVerifier builds an offline verifier for IAM session JWTs (session-tokens.ts
// createSessionTokenVerifier). It enforces the `biam-session+jwt` type, the EdDSA/ES256 allowlist (pinned to each
// key's `alg` for a local key set), the exact issuer, one of the configured audiences, `exp`/`nbf` with clock
// tolerance, the lifetime cap, the accepted kinds and the claim types. Bad options fail with a TypeError.
func CreateSessionTokenVerifier(options *SessionTokenVerifierOptions) (*SessionTokenVerifier, error) {
	if options == nil || !sessionNonEmpty(options.Issuer, 2048) {
		return nil, invalidVerifierOption("issuer")
	}
	var audience []string
	switch value := options.Audience.(type) {
	case string:
		audience = []string{value}
	case []string:
		audience = append([]string{}, value...)
	default:
		return nil, invalidVerifierOption("audience")
	}
	if len(audience) == 0 {
		return nil, invalidVerifierOption("audience")
	}
	for _, item := range audience {
		if !sessionNonEmpty(item, 2048) {
			return nil, invalidVerifierOption("audience")
		}
	}
	algorithms := SessionTokenAlgorithms
	if options.Algorithms != nil {
		algorithms = options.Algorithms
	}
	algorithms = append([]string{}, algorithms...)
	if len(algorithms) == 0 {
		return nil, invalidVerifierOption("algorithms")
	}
	for _, alg := range algorithms {
		if !containsString(SessionTokenAlgorithms, alg) {
			return nil, invalidVerifierOption("algorithms")
		}
	}
	kinds := sessionTokenKinds
	if options.Kinds != nil {
		kinds = options.Kinds
	}
	kinds = append([]string{}, kinds...)
	if len(kinds) == 0 {
		return nil, invalidVerifierOption("kinds")
	}
	for _, kind := range kinds {
		if !containsString(sessionTokenKinds, kind) {
			return nil, invalidVerifierOption("kinds")
		}
	}
	clockTolerance, err := verifierSeconds(options.ClockToleranceSeconds, 5, "clockToleranceSeconds", 0, 60)
	if err != nil {
		return nil, err
	}
	maxLifetime, err := verifierSeconds(options.MaxLifetimeSeconds, 43200, "maxLifetimeSeconds", 1, 10*365*86400)
	if err != nil {
		return nil, err
	}
	now := options.Now
	if now == nil {
		now = func() int64 { return time.Now().UnixMilli() }
	}
	verifier := &SessionTokenVerifier{
		issuer: options.Issuer, audience: audience, algorithms: algorithms, kinds: kinds,
		clockTolerance: clockTolerance, maxLifetime: maxLifetime, now: now,
	}
	remote := ""
	switch value := options.JWKS.(type) {
	case string:
		remote = value
	case *url.URL:
		if value == nil {
			return nil, invalidVerifierOption("jwks")
		}
		remote = value.String()
	}
	if _, isURL := options.JWKS.(*url.URL); isURL || remote != "" || options.JWKS == "" {
		u, err := verifierRemoteURL(remote)
		if err != nil {
			return nil, err
		}
		timeout, err := verifierSeconds(options.TimeoutMs, 5000, "timeoutMs", 1, 60_000)
		if err != nil {
			return nil, err
		}
		cooldown, err := verifierSeconds(options.CooldownSeconds, 30, "cooldownSeconds", 0, 86400)
		if err != nil {
			return nil, err
		}
		cacheMaxAge, err := verifierSeconds(options.CacheMaxAgeSeconds, 600, "cacheMaxAgeSeconds", 1, 86400)
		if err != nil {
			return nil, err
		}
		if timeout != math.Trunc(timeout) {
			return nil, &core.TypeError{Message: `"timeoutDuration" option must be a non-negative integer`}
		}
		set := &sjwtRemoteSet{
			href: u.Href, timeout: time.Duration(timeout) * time.Millisecond, cooldownDuration: cooldown * 1000,
			cacheMaxAge: cacheMaxAge * 1000,
			client:      &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		}
		verifier.resolveKey = func(ctx context.Context, header *core.Object) (*sjwtPublicKey, error) {
			key, err := set.resolve(ctx, header)
			if err != nil {
				if class := sjwtClassOf(err); class == "JWKSNoMatchingKey" || class == "JWKSMultipleMatchingKeys" {
					return nil, err
				}
				return nil, keySetUnavailable{}
			}
			return key, nil
		}
		return verifier, nil
	}
	jwks, _ := options.JWKS.(*core.Object)
	var keys []any
	if jwks != nil {
		keys, _ = jwks.Get("keys").([]any)
	}
	if keys == nil {
		return nil, invalidVerifierOption("jwks")
	}
	verifier.pinned = map[string]string{}
	for _, item := range keys {
		key, isObject := item.(*core.Object)
		if !isObject && !isArray(item) || isObject && key == nil {
			return nil, invalidVerifierOption("jwks")
		}
		if !isObject {
			continue
		}
		kid, okKid := key.Get("kid").(string)
		alg, okAlg := key.Get("alg").(string)
		if okKid && okAlg {
			verifier.pinned[kid] = alg
		}
	}
	local, err := sjwtNewLocalSet(core.NewObject("keys", keys))
	if err != nil {
		return nil, invalidVerifierOption("jwks")
	}
	verifier.resolveKey = local.resolve
	return verifier, nil
}

// Verify (session-tokens.ts SessionTokenVerifier.verify): Verifies a compact session JWT and returns its claims, or
// fails with a *SessionTokenError.
func (s *SessionTokenVerifier) Verify(ctx context.Context, token string) (result *core.Object, err error) {
	claims, err := s.verify(ctx, token)
	if err != nil {
		if known, ok := err.(*SessionTokenError); ok {
			return nil, known
		}
		return nil, &SessionTokenError{Reason: sessionReasonFor(err)}
	}
	return claims, nil
}

func (s *SessionTokenVerifier) verify(ctx context.Context, token string) (*core.Object, error) {
	if utf16Len(token) > MaxSessionTokenLength {
		return nil, &SessionTokenError{Reason: "too-large"}
	}
	if !LooksLikeJwt(token) {
		return nil, &SessionTokenError{Reason: "malformed"}
	}
	header, err := sjwtDecodeProtectedHeader(token)
	if err != nil {
		return nil, &SessionTokenError{Reason: "malformed"}
	}
	kid, ok := header.Get("kid").(string)
	if !ok || !sessionKidPattern.MatchString(kid) {
		return nil, &SessionTokenError{Reason: "unknown-key"}
	}
	alg, ok := header.Get("alg").(string)
	if !ok || !containsString(s.algorithms, alg) {
		return nil, &SessionTokenError{Reason: "algorithm"}
	}
	if s.pinned != nil {
		pinned, ok := s.pinned[kid]
		if !ok {
			return nil, &SessionTokenError{Reason: "unknown-key"}
		}
		if pinned != alg {
			return nil, &SessionTokenError{Reason: "algorithm"}
		}
	}
	payload, _, err := sjwtJwtVerify(ctx, token, s.resolveKey, sjwtVerifyOptions{
		algorithms: s.algorithms, issuer: s.issuer, hasIssuer: true, audience: s.audience, typ: SessionTokenType,
		clockTolerance: s.clockTolerance, currentDate: float64(s.now()),
		requiredClaims: []string{"iss", "sub", "aud", "exp", "iat", "sid", "tid", "kind"}, maxTokenAge: core.Undefined,
	})
	if err != nil {
		return nil, err
	}
	if kind, ok := payload.Get("kind").(string); !ok || !containsString(s.kinds, kind) {
		return nil, &SessionTokenError{Reason: "kind"}
	}
	exp, iat := payload.Get("exp"), payload.Get("iat")
	if !sessionNumeric(exp) || !sessionNumeric(iat) || exp.(float64)-iat.(float64) > s.maxLifetime {
		return nil, &SessionTokenError{Reason: "lifetime"}
	}
	return sessionClaimsOf(payload)
}

// VerifyRequest (session-tokens.ts SessionTokenVerifier.verifyRequest): Verifies the `Authorization: Bearer <jwt>`
// header of a request (the scheme is case-insensitive).
func (s *SessionTokenVerifier) VerifyRequest(ctx context.Context, headers http.Header) (result *core.Object, err error) {
	authorization := ""
	if values := headers.Values("authorization"); len(values) > 0 {
		trimmed := make([]string, len(values))
		for i, value := range values {
			trimmed[i] = strings.Trim(value, " \t\r\n")
		}
		authorization = strings.Join(trimmed, ", ")
	}
	match := sessionBearer.FindStringSubmatch(authorization)
	if match == nil {
		return nil, &SessionTokenError{Reason: "malformed", Message: "A bearer session token is required"}
	}
	return s.Verify(ctx, match[1])
}

// LooksLikeJwt (session-tokens.ts looksLikeJwt): true for a compact JWS shape (three base64url segments of at least
// two characters); says nothing about validity.
func LooksLikeJwt(value any) bool {
	text, ok := value.(string)
	return ok && jwtSegments.MatchString(text)
}

var jwtSegments = regexp.MustCompile(`^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}$`)

// MaxSessionTokenLength is session-tokens.ts MAX_SESSION_TOKEN_LENGTH.
const MaxSessionTokenLength = 4096

// SessionTokenType is session-tokens.ts SESSION_TOKEN_TYPE.
const SessionTokenType = "biam-session+jwt"
