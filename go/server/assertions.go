package server

// Port of packages/server/src/assertions.ts: stateless assertions, short-lived HS256 JSON Web Tokens that describe
// the caller for another service, signed with a key derived from the deployment secret. A downstream service holding
// only the derived key (AssertionKey) verifies them with VerifyAssertion without a database round trip. They grant
// nothing inside IAM itself.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// AssertionClaims are the claims of an assertion (a typed view; the token encodes the claims object in the member
// order iss, sub, aud, iat, exp, jti, tid, kind, mfa, name, roles, groups, method, impersonatorId, email, ext).
type AssertionClaims struct {
	Iss            string       `json:"iss"`
	Sub            string       `json:"sub"`
	Aud            string       `json:"aud"`
	Iat            float64      `json:"iat"`
	Exp            float64      `json:"exp"`
	Jti            string       `json:"jti"`
	Tid            string       `json:"tid"`
	Kind           string       `json:"kind"`
	Mfa            bool         `json:"mfa"`
	Name           string       `json:"name"`
	Roles          []string     `json:"roles"`
	Groups         []string     `json:"groups"`
	Method         string       `json:"method,omitempty"`
	ImpersonatorID string       `json:"impersonatorId,omitempty"`
	Email          string       `json:"email,omitempty"`
	Ext            *core.Object `json:"ext,omitempty"`
}

// encodeSegment is base64url(JSON.stringify(value)).
func encodeSegment(value any) string {
	return base64.RawURLEncoding.EncodeToString(utf8Bytes(core.MustStringify(value)))
}

var assertionHeader = encodeSegment(core.NewObject("alg", "HS256", "typ", "JWT"))
var audiencePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$`)
var hexKey = regexp.MustCompile(`^[0-9a-f]{64}$`)

// AssertionKey is the verification key for a deployment secret: SHA-256 of a purpose-bound derivation, as hex.
func AssertionKey(secret string) string {
	digest := sha256.Sum256(utf8Bytes("better-iam:assertion:" + secret))
	return hex.EncodeToString(digest[:])
}

func signAssertion(key, signingInput string) []byte {
	decoded, _ := hex.DecodeString(key)
	mac := hmac.New(sha256.New, decoded)
	mac.Write(utf8Bytes(signingInput))
	return mac.Sum(nil)
}

// VerifyAssertionOptions are the checks of VerifyAssertion.
type VerifyAssertionOptions struct {
	// Key is one verification key (a string) or several ([]string, during a deployment secret rotation).
	Key      any
	Audience string
	// Issuer is checked when set.
	Issuer *string
	// Now defaults to the current time (epoch milliseconds).
	Now *float64
	// ToleranceSeconds defaults to 30.
	ToleranceSeconds *float64
}

// VerifyAssertion verifies an assertion against the derived key, audience, optional issuer, and time; it returns its
// claims (the decoded JSON object). Failures are INVALID_ASSERTION (401).
func VerifyAssertion(token any, options VerifyAssertionOptions) (*core.Object, error) {
	invalid := func(message string) error { return core.NewIamError("INVALID_ASSERTION", message, 401) }
	text, ok := token.(string)
	if !ok || utf16Len(text) > 16384 {
		return nil, invalid("Malformed assertion")
	}
	parts := strings.Split(text, ".")
	if len(parts) != 3 || parts[0] != assertionHeader {
		return nil, invalid("Malformed assertion")
	}
	var keys []any
	switch value := options.Key.(type) {
	case string:
		keys = []any{value}
	case []string:
		keys = stringsOf(value)
	case []any:
		keys = value
	default:
		return nil, invalid("Invalid verification key")
	}
	if len(keys) == 0 {
		return nil, invalid("Invalid verification key")
	}
	for _, key := range keys {
		if text, ok := key.(string); !ok || !hexKey.MatchString(text) {
			return nil, invalid("Invalid verification key")
		}
	}
	provided := nodeBase64Decode(parts[2])
	// Base64url decoding is lenient (unused trailing bits, padding, stray characters), so only the canonical spelling
	// of a signature is accepted: one assertion has exactly one valid string form.
	if base64.RawURLEncoding.EncodeToString(provided) != parts[2] {
		return nil, invalid("Malformed assertion")
	}
	signingInput := parts[0] + "." + parts[1]
	matched := false
	for _, key := range keys {
		expected := signAssertion(key.(string), signingInput)
		if len(provided) == len(expected) && hmac.Equal(provided, expected) {
			matched = true
			break
		}
	}
	if !matched {
		return nil, invalid("Invalid signature")
	}
	parsed, err := core.ParseJSONString(decodeUTF8(nodeBase64Decode(parts[1])))
	if err != nil {
		return nil, invalid("Malformed assertion")
	}
	now := float64(time.Now().UnixMilli())
	if options.Now != nil {
		now = *options.Now
	}
	nowSeconds := math.Floor(now / 1000)
	tolerance := 30.0
	if options.ToleranceSeconds != nil {
		tolerance = *options.ToleranceSeconds
	}
	claims, isObject := parsed.(*core.Object)
	if !isObject || claims == nil || typeOf(claims.Get("sub")) != "string" || typeOf(claims.Get("tid")) != "string" ||
		typeOf(claims.Get("exp")) != "number" || typeOf(claims.Get("iat")) != "number" {
		return nil, invalid("Malformed assertion")
	}
	if claims.Get("aud") != options.Audience {
		return nil, invalid("Audience mismatch")
	}
	if options.Issuer != nil && claims.Get("iss") != *options.Issuer {
		return nil, invalid("Issuer mismatch")
	}
	exp := claims.Get("exp").(float64)
	iat := claims.Get("iat").(float64)
	if exp+tolerance <= nowSeconds {
		return nil, invalid("Assertion expired")
	}
	if iat-tolerance > nowSeconds {
		return nil, invalid("Assertion not yet valid")
	}
	return claims, nil
}

// objectPrototypeNames are the members every JavaScript object inherits; `name in claims` sees them.
var objectPrototypeNames = map[string]bool{
	"constructor": true, "__defineGetter__": true, "__defineSetter__": true, "hasOwnProperty": true,
	"__lookupGetter__": true, "__lookupSetter__": true, "isPrototypeOf": true, "propertyIsEnumerable": true,
	"toString": true, "valueOf": true, "__proto__": true, "toLocaleString": true,
}

// AssertionsAPI is the `assertions` API group (createAssertionsApi).
type AssertionsAPI struct {
	ctx *ServerContext
	key string
	// newID generates the jti (ID; replaceable in tests).
	newID func() string
}

// CreateAssertionsAPI builds the assertions API group.
func CreateAssertionsAPI(ctx *ServerContext) *AssertionsAPI {
	return &AssertionsAPI{ctx: ctx, key: AssertionKey(ctx.Options.Secret), newID: ID}
}

// assertionAudience validates the audience of an issue request.
func assertionAudience(value any) (string, error) {
	audience, err := Text(value, "audience", 256)
	if err != nil {
		return "", err
	}
	if !audiencePattern.MatchString(audience) {
		return "", invalidInput("audience must be a URL-safe identifier")
	}
	return audience, nil
}

// Issue issues an assertion about the caller for input.audience, authorized as iam:assertions:create on
// iam/{audience} so administrators decide which audiences each role may obtain tokens for. Lifetime is 10 seconds
// to one hour (default five minutes). Role sessions assert the assumed role's identity and no groups. Scoped
// credentials (API keys with scopes, session tokens with a policy or source policy, role sessions with a session
// policy) and delegated agent sessions are refused (ACCESS_DENIED, audited). The result is {token, expiresAt,
// claims}.
func (a *AssertionsAPI) Issue(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	audience, err := assertionAudience(input.Get("audience"))
	if err != nil {
		return nil, err
	}
	// A missing or non-string tenantId reaches the envelope as "", which refuses it as TypeScript refuses undefined.
	tenantID, _ := input.Get("tenantId").(string)
	return Operate(ctx, a.ctx.Operations, credential, tenantID, "iam:assertions:create", audience,
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			sources := func() (*GrantSources, error) {
				return a.ctx.Decisions.GrantSources(ctx, call.Tx, jsString(call.Principal.Identity.Get("id")), jsString(call.Tenant.Get("id")))
			}
			return issueAssertion(call.Principal, call.Tenant, sources, audience, input, a.ctx.Now(), a.ctx.Config.BaseOrigin(), a.key, a.newID)
		}, false)
}

// scopedSession is `principal.session.policy || principal.session.sourcePolicy`.
func scopedSession(session *core.Object) bool {
	return truthy(session.Get("policy")) || truthy(session.Get("sourcePolicy"))
}

// issueAssertion is the body of the issue operation: refusals, lifetime, claims and signature. loadSources reads the
// caller's grant sources (not called for role sessions).
func issueAssertion(principal *Principal, tenant *core.Object, loadSources func() (*GrantSources, error), audience string, input *core.Object, nowMs int64, issuer, key string, newID func() string) (*core.Object, error) {
	session := principal.Session
	kind := session.Get("kind")
	// The roles claim lists the identity's roles (or the assumed role), which would escape any scope-down.
	if scopedSession(session) {
		if kind == "session-token" {
			return nil, NewOperationDenied("Scoped session tokens cannot obtain assertions")
		}
		return nil, NewOperationDenied("Scoped credentials cannot obtain assertions")
	}
	// Likewise a delegated agent session, which is always bounded by its delegation's scope.
	if kind == "delegated" {
		return nil, NewOperationDenied("Delegated agent sessions cannot obtain assertions")
	}
	ttl, err := Integer(coalesce(input.Get("ttlSeconds"), 300.0), "ttlSeconds", 10, 3600)
	if err != nil {
		return nil, err
	}
	issuedAt := math.Floor(float64(nowMs) / 1000)
	var roles, groups []string
	if kind == "role" {
		roles = []string{jsString(session.Get("roleId"))}
		groups = []string{}
	} else {
		sources, err := loadSources()
		if err != nil {
			return nil, err
		}
		set := newOrderedSet()
		for _, binding := range sources.Bindings {
			set.Add(jsString(binding.Get("roleId")))
		}
		roles = set.Values()
		sortStrings(roles)
		groups = unique(sources.GroupIDs)
		sortStrings(groups)
	}
	if roles == nil {
		roles = []string{}
	}
	if groups == nil {
		groups = []string{}
	}
	claims := core.NewObject(
		"iss", issuer,
		"sub", principal.Identity.Get("id"),
		"aud", audience,
		"iat", issuedAt,
		"exp", issuedAt+ttl,
		"jti", newID(),
		"tid", tenant.Get("id"),
		"kind", kind,
		"mfa", session.Get("mfa"),
		"name", principal.Identity.Get("name"),
		"roles", stringsOf(roles),
		"groups", stringsOf(groups),
	)
	if method := session.Get("method"); truthy(method) {
		claims.Set("method", method)
	}
	if impersonator := session.Get("impersonatorId"); truthy(impersonator) {
		claims.Set("impersonatorId", impersonator)
	}
	if email := principal.Identity.Get("email"); truthy(email) {
		claims.Set("email", email)
	}
	if extra := input.Get("claims"); !isUndefined(extra) {
		ext, err := Object(extra)
		if err != nil {
			return nil, err
		}
		if utf16Len(core.MustStringify(ext)) > 4096 {
			return nil, invalidInput("claims must serialize to at most 4 KiB")
		}
		for _, name := range ext.Keys() {
			if claims.Has(name) || objectPrototypeNames[name] {
				return nil, invalidInput("claims cannot redefine " + name)
			}
		}
		claims.Set("ext", ext)
	}
	signingInput := assertionHeader + "." + encodeSegment(claims)
	signature := base64.RawURLEncoding.EncodeToString(signAssertion(key, signingInput))
	return core.NewObject(
		"token", signingInput+"."+signature,
		"expiresAt", (issuedAt+ttl)*1000,
		"claims", claims,
	), nil
}
