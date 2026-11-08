package server

// Port of packages/server/src/temporary-credentials.ts: the issuance core of temporary credentials (STS). Role
// sessions (`roles.assume`, web identity) and session tokens (`sts.getSessionToken`) validate their inputs with the
// helpers below, build a draft session row, and hand it to MintCredential, which issues either a typed opaque token
// (`biam_rol_…`, `biam_sts_…`) or an IAM-signed session JWT and stores the row. The projections at the end
// (TemporaryCredential, CallerIdentity, RoleSessionSummary, AuditSessionContext) are allowlists: they never carry
// hashes, policies, authority ids or the source session id.

import (
	"context"
	"errors"
	"math"
	"regexp"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// SessionNamePattern is temporary-credentials.ts sessionNamePattern: session names and source identities are 2 to
// 64 characters of letters, digits and `+=,.@_-` (as in AWS STS).
var SessionNamePattern = regexp.MustCompile("^[\\w+=,.@-]{2,64}$")

// stsTagValuePattern is /^[\p{L}\p{N}\s_.:/=+\-@]*$/u: letters, digits, (JavaScript) whitespace and `_.:/=+-@`.
var stsTagValuePattern = regexp.MustCompile(`^[\p{L}\p{N}` + jsWhitespace + `_.:/=+\-@]*$`)

// Session JWT audiences are checked with audiencePattern (assertions.go): the same URL-safe identifier shape of at
// most 256 characters that temporary-credentials.ts declares.

const (
	stsMaxTags           = 50
	stsMaxPackedTagBytes = 2048
	stsMaxAudiences      = 5
	// stsDefaultTrustMaxSessionSeconds is a trust's default maximum role session, used when it stores none (or none
	// that is usable).
	stsDefaultTrustMaxSessionSeconds = 3600
)

// stsSliceUTF16 is String.prototype.slice(start, end) over UTF-16 code units.
func stsSliceUTF16(s string, start, end int) string {
	units := core.ToUTF16(s)
	if end > len(units) {
		end = len(units)
	}
	if start >= end {
		return ""
	}
	return core.FromUTF16(units[start:end])
}

// SessionNameValue (temporary-credentials.ts sessionNameValue): A session name, or "" (undefined) when none was
// given.
func SessionNameValue(value any) (string, error) {
	if isUndefined(value) {
		return "", nil
	}
	name, ok := value.(string)
	if !ok || !SessionNamePattern.MatchString(name) {
		return "", invalidInput("sessionName must be 2-64 letters, digits or +=,.@_- characters")
	}
	return name, nil
}

// SourceIdentityValue (temporary-credentials.ts sourceIdentityValue): A caller-stated source identity, or ""
// (undefined) when none was given.
func SourceIdentityValue(value any) (string, error) {
	if isUndefined(value) {
		return "", nil
	}
	name, ok := value.(string)
	if !ok || !SessionNamePattern.MatchString(name) {
		return "", invalidInput("sourceIdentity must be 2-64 letters, digits or +=,.@_- characters")
	}
	return name, nil
}

// SessionTagsValue (temporary-credentials.ts sessionTagsValue): Session tags: at most 50, keys matching
// /^[A-Za-z][A-Za-z0-9_]{0,63}$/ and unique case-insensitively, values of at most 256 characters from the tag value
// charset, and at most 2048 bytes as packed JSON. Undefined (or no tags) gives nil (undefined).
func SessionTagsValue(value any) (*core.Object, error) {
	if isUndefined(value) {
		return nil, nil
	}
	object, ok := value.(*core.Object)
	if !ok || object == nil {
		return nil, invalidInput("tags must be an object of tag keys to string values")
	}
	keys := object.Keys()
	if len(keys) > stsMaxTags {
		return nil, invalidInput("tags may contain at most " + core.NumberString(stsMaxTags) + " entries")
	}
	seen := map[string]bool{}
	tags := core.NewObject()
	for _, key := range keys {
		if !TagKeyPattern.MatchString(key) {
			return nil, invalidInput("Tag keys must start with a letter and use at most 64 letters, digits or underscores")
		}
		folded := core.JSLower(key)
		if seen[folded] {
			return nil, invalidInput("Tag key " + key + " is repeated (tag keys are case-insensitive)")
		}
		seen[folded] = true
		tag, ok := object.Get(key).(string)
		if !ok || utf16Len(tag) > 256 || !stsTagValuePattern.MatchString(tag) {
			return nil, invalidInput("Tag " + key + " must be a string of at most 256 letters, digits, spaces or _.:/=+-@")
		}
		tags.Set(key, tag)
	}
	if len(keys) == 0 {
		return nil, nil
	}
	packed, _, err := core.Stringify(tags)
	if err != nil {
		return nil, err
	}
	if len(utf8Bytes(packed)) > stsMaxPackedTagBytes {
		return nil, invalidInput("tags must pack into at most " + core.NumberString(stsMaxPackedTagBytes) + " bytes")
	}
	return tags, nil
}

// AllowedTagKeysValue (temporary-credentials.ts allowedTagKeysValue): A trust's admitted session tag keys: at most
// 50 distinct tag keys, or exactly ['*'] for any key.
func AllowedTagKeysValue(value any) ([]string, error) {
	message := "allowedTagKeys must be a list of at most " + core.NumberString(stsMaxTags) + " tag keys, or ['*']"
	list, ok := value.([]any)
	if !ok || len(list) > stsMaxTags {
		return nil, invalidInput(message)
	}
	if len(list) == 1 && list[0] == "*" {
		return []string{"*"}, nil
	}
	seen := map[string]bool{}
	keys := make([]string, 0, len(list))
	for _, item := range list {
		key, ok := item.(string)
		if !ok || !TagKeyPattern.MatchString(key) {
			return nil, invalidInput(message)
		}
		folded := core.JSLower(key)
		if seen[folded] {
			return nil, invalidInput("Tag key " + key + " is repeated (tag keys are case-insensitive)")
		}
		seen[folded] = true
		keys = append(keys, key)
	}
	return keys, nil
}

// CredentialFormat (temporary-credentials.ts credentialFormat): The requested credential format; 'opaque' by
// default.
func CredentialFormat(value any) (string, error) {
	if isUndefined(value) {
		return "opaque", nil
	}
	format, _ := value.(string)
	if format != "opaque" && format != "jwt" {
		return "", invalidInput("format must be 'opaque' or 'jwt'")
	}
	return format, nil
}

// AudienceValue (temporary-credentials.ts audienceValue): Requested JWT audiences: 1 to 5 URL-safe identifiers,
// deduplicated, and only with `format: 'jwt'`; nil (undefined) when none were given. Whether each is on the
// deployment's allowlist and permitted to the caller is checked at issuance (MintCredential).
func AudienceValue(value any, format string) ([]string, error) {
	if isUndefined(value) {
		return nil, nil
	}
	if format != "jwt" {
		return nil, invalidInput("audience requires format 'jwt'")
	}
	list, ok := value.([]any)
	if !ok || len(list) < 1 || len(list) > stsMaxAudiences {
		return nil, invalidInput("audience must list 1 to " + core.NumberString(stsMaxAudiences) + " audiences")
	}
	audiences := make([]string, 0, len(list))
	for _, item := range list {
		audience, ok := item.(string)
		if !ok || !audiencePattern.MatchString(audience) {
			return nil, invalidInput("audience entries must be URL-safe identifiers of at most 256 characters")
		}
		audiences = append(audiences, audience)
	}
	return unique(audiences), nil
}

// stsFormatCap is the JWT lifetime cap, or no cap for opaque tokens (and deployments without `sts.jwt`, which refuse
// JWTs anyway).
func stsFormatCap(server *ServerContext, format string) float64 {
	if format == "jwt" && server.SessionTokens != nil {
		return stsSecondsOr(server.SessionTokens.MaxLifetimeSeconds, stsDefaultTrustMaxSessionSeconds)
	}
	return math.Inf(1)
}

// stsSecondsOr is a stored or configured duration limit in seconds, or fallback when it is not a positive safe
// integer. Limits read from storage may be malformed (a string, NaN, a negative number), and Math.min over such a
// value yields NaN, which every range check would accept; this fails closed to the default instead, which the other
// levels then clamp.
func stsSecondsOr(value any, fallback float64) float64 {
	number, ok := core.Normalize(value).(float64)
	if ok && core.IsSafeInteger(number) && number > 0 {
		return number
	}
	return fallback
}

// stsDurationBoundsOf is a DurationBounds object ({ min, max, fallback }, in seconds).
func stsDurationBoundsOf(min, max, fallback float64) *core.Object {
	return core.NewObject("min", min, "max", max, "fallback", fallback)
}

// RoleDurationBounds (temporary-credentials.ts roleDurationBounds): Role session durations: the least of the
// deployment ceiling (`sts.maxRoleSessionSeconds`), the trust's `maxSessionSeconds` (3600 when absent or not a
// positive integer) and, for JWTs, `sts.jwt.maxLifetimeSeconds`; 900 by default or the maximum when that is lower. A
// lower level can only reduce the level above it.
func RoleDurationBounds(server *ServerContext, trust *core.Object, format string) (*core.Object, error) {
	max := math.Min(math.Min(
		stsSecondsOr(float64(server.Config.Sts.MaxRoleSessionSeconds), stsDefaultTrustMaxSessionSeconds),
		stsSecondsOr(trust.Get("maxSessionSeconds"), stsDefaultTrustMaxSessionSeconds)),
		stsFormatCap(server, format))
	return stsDurationBoundsOf(60, max, math.Min(900, max)), nil
}

// SessionTokenDurationBounds (temporary-credentials.ts sessionTokenDurationBounds): Session token durations: the
// least of `sts.maxSessionTokenSeconds` and, for JWTs, `sts.jwt.maxLifetimeSeconds`; 3600 by default or the maximum
// when that is lower. A limit that is not a positive integer counts as 3600.
func SessionTokenDurationBounds(server *ServerContext, format string) (*core.Object, error) {
	max := math.Min(
		stsSecondsOr(float64(server.Config.Sts.MaxSessionTokenSeconds), stsDefaultTrustMaxSessionSeconds),
		stsFormatCap(server, format))
	return stsDurationBoundsOf(60, max, math.Min(3600, max)), nil
}

// DurationWithin (temporary-credentials.ts durationWithin): A requested duration within the bounds (the fallback
// when absent); anything outside is INVALID_INPUT, never clamped.
func DurationWithin(value any, bounds *core.Object) (float64, error) {
	min, max := jsNumber(bounds.Get("min")), jsNumber(bounds.Get("max"))
	seconds, ok := core.Normalize(coalesce(value, bounds.Get("fallback"))).(float64)
	if !ok || !core.IsSafeInteger(seconds) || seconds < min || seconds > max {
		return 0, invalidInput("durationSeconds must be an integer from " + core.NumberString(min) + " to " + core.NumberString(max))
	}
	return seconds, nil
}

// stsRequestedAudiences reads MintCredential's audience list (an in-process caller's []string, or a model []any of
// strings).
func stsRequestedAudiences(value any) []string {
	switch list := value.(type) {
	case []string:
		return list
	case []any:
		out := make([]string, len(list))
		for index, item := range list {
			out[index] = jsString(item)
		}
		return out
	}
	return nil
}

// MintCredential (temporary-credentials.ts mintCredential): Issues a temporary credential for a draft session row
// and stores the row; input is { identity, draft, format, audience? } and the answer { token, session }. The draft
// carries every field except the token material (`tokenHash` and `uniqueKey` are replaced; `format` and `audience`
// are set here). Opaque tokens are typed and checksummed (`biam_rol_…` for role sessions, `biam_sts_…` for session
// tokens). Session JWTs need `sts.jwt` (FEATURE_DISABLED otherwise): every audience must be on the deployment's
// allowlist (INVALID_INPUT), and each one other than the IAM issuer must be allowed as `iam:assertions:create` on
// `iam/{aud}` for the drafted session (ACCESS_DENIED). The token is signed, bounded to 4096 characters, and its
// SHA-256 stored like an opaque token's, so IAM re-validates the row on every use.
func MintCredential(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object) (*core.Object, error) {
	identity, _ := input.Get("identity").(*core.Object)
	draft, _ := input.Get("draft").(*core.Object)
	format := input.Get("format")
	kind := draft.Get("kind")
	if kind != "role" && kind != "session-token" {
		return nil, errors.New("mintCredential issues role sessions and session tokens only")
	}
	row := draft.Clone()
	row.Delete("format")
	row.Delete("audience")
	requested := input.Get("audience")
	if format == "opaque" {
		if !isUndefined(requested) {
			return nil, invalidInput("audience requires format 'jwt'")
		}
		tokenType := "sts"
		if kind == "role" {
			tokenType = "rol"
		}
		token, err := auth.NewCredentialToken(tokenType)
		if err != nil {
			return nil, err
		}
		row.Set("tokenHash", Hash(token))
		row.Set("uniqueKey", row.Get("tokenHash"))
		session, err := tx.Insert(ctx, "sessions", row)
		if err != nil {
			return nil, err
		}
		return core.NewObject("token", token, "session", session), nil
	}
	if format != "jwt" {
		return nil, invalidInput("format must be 'opaque' or 'jwt'")
	}
	signer := server.SessionTokens
	if signer == nil {
		return nil, core.NewIamError("FEATURE_DISABLED", "Session JWTs are not enabled on this deployment (sts.jwt)", 403)
	}
	audience := []string{signer.Issuer}
	if !isUndefined(requested) {
		audience = stsRequestedAudiences(requested)
	}
	if len(audience) < 1 || len(audience) > stsMaxAudiences {
		return nil, invalidInput("audience must list 1 to " + core.NumberString(stsMaxAudiences) + " audiences")
	}
	for _, entry := range audience {
		if !containsString(signer.Audiences, entry) {
			return nil, invalidInput("audience " + entry + " is not an allowed session token audience")
		}
	}
	for _, entry := range audience {
		if entry == signer.Issuer {
			continue
		}
		decision, err := server.Decisions.Decide(ctx, tx, &Principal{Identity: identity, Session: draft}, AuthorizationRequest{
			TenantID: jsString(draft.Get("tenantId")), Action: "iam:assertions:create", Resource: ResourceTarget{Type: "iam", ID: entry},
		}, true)
		if err != nil {
			return nil, err
		}
		if !decision.Allowed {
			return nil, core.NewIamError("ACCESS_DENIED", "This credential may not obtain tokens for audience "+entry, 403)
		}
	}
	issuedAt := math.Floor(jsNumber(draft.Get("createdAt")) / 1000)
	expiresAt := math.Floor(jsNumber(draft.Get("expiresAt")) / 1000)
	if expiresAt-issuedAt > signer.MaxLifetimeSeconds {
		return nil, invalidInput("durationSeconds exceeds the session JWT lifetime of " + core.NumberString(signer.MaxLifetimeSeconds))
	}
	var aud any = stringsOf(audience)
	if len(audience) == 1 {
		aud = audience[0]
	}
	claims := core.NewObject(
		"iss", signer.Issuer,
		"aud", aud,
		"sub", draft.Get("identityId"),
		"tid", draft.Get("tenantId"),
		"sid", draft.Get("id"),
		"jti", draft.Get("id"),
		"iat", issuedAt,
		"nbf", issuedAt,
		"exp", expiresAt,
		"auth_time", math.Floor(jsNumber(draft.Get("authenticatedAt"))/1000),
		"kind", kind,
		"mfa", draft.Get("mfa"),
	)
	for _, pair := range [][2]string{{"roleId", "role"}, {"trustId", "trust"}, {"sourceTenantId", "src_tid"}, {"sessionName", "session_name"}, {"sourceIdentity", "source_identity"}} {
		if value, ok := draft.Get(pair[0]).(string); ok {
			claims.Set(pair[1], value)
		}
	}
	if webIdentity := draft.Get("webIdentity"); truthy(webIdentity) {
		claims.Set("idp", member(webIdentity, "providerId"))
		claims.Set("idp_sub", member(webIdentity, "subject"))
	}
	token, err := signer.Sign(ctx, claims)
	if err != nil {
		return nil, err
	}
	if utf16Len(token) > MaxSessionTokenLength {
		return nil, invalidInput("The session token would exceed " + core.NumberString(MaxSessionTokenLength) + " characters")
	}
	row.Set("tokenHash", Hash(token))
	row.Set("uniqueKey", row.Get("tokenHash"))
	row.Set("format", "jwt")
	row.Set("audience", stringsOf(audience))
	session, err := tx.Insert(ctx, "sessions", row)
	if err != nil {
		return nil, err
	}
	return core.NewObject("token", token, "session", session), nil
}

// stsCredentialFormatOf is the format of a stored session: 'jwt' for session JWTs, 'opaque' otherwise.
func stsCredentialFormatOf(session *core.Object) string {
	if session.Get("format") == "jwt" {
		return "jwt"
	}
	return "opaque"
}

// TemporaryCredential (temporary-credentials.ts temporaryCredential): The issuer response for a stored temporary
// session (an allowlist projection; the token is the only secret).
func TemporaryCredential(token string, session *core.Object, now int64) (*core.Object, error) {
	summary := core.NewObject(
		"id", session.Get("id"),
		"tenantId", session.Get("tenantId"),
		"kind", session.Get("kind"),
		"identityId", session.Get("identityId"),
		"expiresAt", session.Get("expiresAt"),
		"mfa", session.Get("mfa"),
	)
	for _, key := range []string{"roleId", "trustId", "sessionName", "sourceIdentity"} {
		if value, ok := session.Get(key).(string); ok {
			summary.Set(key, value)
		}
	}
	credential := core.NewObject(
		"token", token,
		"tokenType", "Bearer",
		"format", stsCredentialFormatOf(session),
		"expiresAt", session.Get("expiresAt"),
		"expiresIn", math.Max(0, math.Floor((jsNumber(session.Get("expiresAt"))-float64(now))/1000)),
		"session", summary,
	)
	if audience, ok := session.Get("audience").([]any); ok {
		credential.Set("audience", core.CloneValue(audience))
	}
	return credential, nil
}

// stsSessionTagsCopy is `{ ...session.sessionTags }` for a truthy member with own keys; ok is false when the member is
// falsy or has none (`session.sessionTags && Object.keys(session.sessionTags).length`).
func stsSessionTagsCopy(value any) (copied *core.Object, ok bool) {
	switch typed := value.(type) {
	case *core.Object:
		if typed == nil || typed.Len() == 0 {
			return nil, false
		}
		return typed.Clone(), true
	case []any:
		if len(typed) == 0 {
			return nil, false
		}
		copied = core.NewObject()
		for index, item := range typed {
			copied.Set(core.NumberString(float64(index)), core.CloneValue(item))
		}
		return copied, true
	case string:
		if typed == "" {
			return nil, false
		}
		copied = core.NewObject()
		for index, unit := range core.ToUTF16(typed) {
			copied.Set(core.NumberString(float64(index)), core.FromUTF16([]uint16{unit}))
		}
		return copied, true
	}
	return nil, false
}

// CallerIdentity (temporary-credentials.ts callerIdentity): `sts.getCallerIdentity`: an allowlist projection of a
// verified principal.
func CallerIdentity(principal *Principal) (*core.Object, error) {
	identity, session := principal.Identity, principal.Session
	caller := core.NewObject(
		"identityId", identity.Get("id"),
		"identityTenantId", identity.Get("tenantId"),
		"identityKind", identity.Get("kind"),
		"tenantId", session.Get("tenantId"),
		"sessionId", session.Get("id"),
		"sessionKind", session.Get("kind"),
		"format", stsCredentialFormatOf(session),
		"mfa", session.Get("mfa"),
		"authenticatedAt", session.Get("authenticatedAt"),
		"issuedAt", session.Get("createdAt"),
		"expiresAt", session.Get("expiresAt"),
	)
	if method := session.Get("method"); !isUndefined(method) {
		caller.Set("method", method)
	}
	for _, key := range []string{"roleId", "trustId", "sourceTenantId", "sessionName", "sourceIdentity"} {
		if value, ok := session.Get(key).(string); ok {
			caller.Set(key, value)
		}
	}
	if tags, ok := stsSessionTagsCopy(session.Get("sessionTags")); ok {
		caller.Set("sessionTags", tags)
	}
	if audience, ok := session.Get("audience").([]any); ok {
		caller.Set("audience", core.CloneValue(audience))
	}
	if webIdentity := session.Get("webIdentity"); truthy(webIdentity) {
		caller.Set("webIdentity", core.NewObject(
			"providerId", member(webIdentity, "providerId"),
			"issuer", member(webIdentity, "issuer"),
			"subject", member(webIdentity, "subject"),
		))
	}
	for _, key := range []string{"impersonatorId", "agentId", "delegationId"} {
		if value, ok := session.Get(key).(string); ok {
			caller.Set(key, value)
		}
	}
	return caller, nil
}

// RoleSessionSummary (temporary-credentials.ts roleSessionSummary): `roles.listSessions`: an allowlist projection of
// a role session row.
func RoleSessionSummary(session *core.Object) (*core.Object, error) {
	summary := core.NewObject(
		"id", session.Get("id"),
		"roleId", session.Get("roleId"),
		"trustId", session.Get("trustId"),
		"identityId", session.Get("identityId"),
		"mfa", session.Get("mfa"),
		"format", stsCredentialFormatOf(session),
		"createdAt", session.Get("createdAt"),
		"expiresAt", session.Get("expiresAt"),
	)
	for _, key := range []string{"sourceTenantId", "sessionName", "sourceIdentity"} {
		if value, ok := session.Get(key).(string); ok {
			summary.Set(key, value)
		}
	}
	if webIdentity := session.Get("webIdentity"); truthy(webIdentity) {
		summary.Set("webIdentity", core.NewObject(
			"providerId", member(webIdentity, "providerId"),
			"subject", member(webIdentity, "subject"),
		))
	}
	// A cross-tenant role session was issued to a person of another tenant: their address is not the target tenant's
	// to see (its readers hold iam:trust:read, not access to the source tenant's sign-in records).
	sourceTenantID, isString := session.Get("sourceTenantId").(string)
	crossTenant := isString && !stsStrictEqual(sourceTenantID, session.Get("tenantId"))
	if ip, ok := member(session.Get("client"), "ip").(string); ok && !crossTenant {
		summary.Set("clientIp", ip)
	}
	return summary, nil
}

// AuditSessionContext is the session context recorded on an audit event (and its webhook body): which credential
// acted, and for temporary credentials the role, trust, source tenant, session name, source identity and web
// identity behind it; nil for simulated principals. Session ids are identifiers, not credentials; hashes, policies,
// tag values and authority ids are never included.
func AuditSessionContext(session *core.Object) *core.Object {
	if session == nil {
		return nil
	}
	id, ok := session.Get("id").(string)
	if !ok || id == "simulation" {
		return nil
	}
	context := core.NewObject("sessionId", id, "kind", session.Get("kind"))
	for _, key := range []string{"roleId", "trustId", "sourceTenantId", "sessionName", "sourceIdentity"} {
		if value, ok := session.Get(key).(string); ok {
			context.Set(key, value)
		}
	}
	if webIdentity := session.Get("webIdentity"); truthy(webIdentity) {
		context.Set("webIdentityProviderId", member(webIdentity, "providerId"))
		subject, _ := member(webIdentity, "subject").(string)
		context.Set("webIdentitySubject", stsSliceUTF16(subject, 0, 256))
	}
	if session.Get("format") == "jwt" {
		context.Set("format", "jwt")
	}
	// Delegated sessions: the agent that acted for the person, under which delegation.
	for _, key := range []string{"agentId", "delegationId"} {
		if value, ok := session.Get(key).(string); ok {
			context.Set(key, value)
		}
	}
	return context
}

// stsStrictEqual is `a === b` for stored member values: primitives by value (NaN never equal), objects by
// identity; arrays (no identity in the model) are never equal.
func stsStrictEqual(a, b any) bool {
	switch x := a.(type) {
	case nil:
		return b == nil
	case core.UndefinedType:
		return isUndefined(b)
	case string:
		y, ok := b.(string)
		return ok && x == y
	case float64:
		y, ok := b.(float64)
		return ok && x == y
	case bool:
		y, ok := b.(bool)
		return ok && x == y
	case *core.Object:
		y, ok := b.(*core.Object)
		return ok && x == y
	}
	return false
}

// stsValueLess is `a < b` for stored member values: strings by UTF-16 code units, anything else as numbers.
func stsValueLess(a, b any) bool {
	x, xs := a.(string)
	y, ys := b.(string)
	if xs && ys {
		return compareUTF16(x, y) < 0
	}
	return jsNumber(a) < jsNumber(b)
}

// DeleteTemporarySessions (temporary-credentials.ts deleteTemporarySessions): Deletes live role sessions of a role
// in a tenant created before `createdBefore` (eager revocation alongside a watermark), optionally only those of one
// trust or one OIDC provider; filter is { tenantId, roleId, trustId?, providerId?, createdBefore }. Reads through
// the indexed roleId and returns the number of rows deleted.
func DeleteTemporarySessions(ctx context.Context, tx core.IamStore, filter *core.Object) (float64, error) {
	deleted := 0.0
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("roleId", filter.Get("roleId")), nil)
	if err != nil {
		return 0, err
	}
	trustID, providerID := filter.Get("trustId"), filter.Get("providerId")
	for _, session := range sessions {
		if session.Get("kind") != "role" ||
			!stsStrictEqual(session.Get("tenantId"), filter.Get("tenantId")) ||
			(!isUndefined(trustID) && !stsStrictEqual(session.Get("trustId"), trustID)) ||
			(!isUndefined(providerID) && !stsStrictEqual(member(session.Get("webIdentity"), "providerId"), providerID)) ||
			!stsValueLess(session.Get("createdAt"), filter.Get("createdBefore")) {
			continue
		}
		if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
			return 0, err
		}
		deleted++
	}
	return deleted, nil
}
