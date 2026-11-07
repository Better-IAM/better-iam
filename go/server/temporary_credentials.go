package server

// Partial port of packages/server/src/temporary-credentials.ts: auditSessionContext, which every audit event uses.
// The rest of the module (role sessions, session tokens, deleteTemporarySessions, ...) is ported with the STS module.

import (
	"context"
	"regexp"

	"github.com/Better-IAM/better-iam/go/core"
)

// sliceUTF16 is String.prototype.slice(start, end) over UTF-16 code units.
func sliceUTF16(s string, start, end int) string {
	units := core.ToUTF16(s)
	if end > len(units) {
		end = len(units)
	}
	if start >= end {
		return ""
	}
	return core.FromUTF16(units[start:end])
}

// AuditSessionContext is the session context recorded on audit events: which credential acted, with the role,
// trust, names and agent behind a temporary one; nil for simulated principals. Session ids are identifiers, not
// credentials; hashes, policies, tag values and authority ids are never included.
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
		context.Set("webIdentitySubject", sliceUTF16(subject, 0, 256))
	}
	if session.Get("format") == "jwt" {
		context.Set("format", "jwt")
	}
	for _, key := range []string{"agentId", "delegationId"} {
		if value, ok := session.Get(key).(string); ok {
			context.Set(key, value)
		}
	}
	return context
}

// AllowedTagKeysValue (temporary-credentials.ts allowedTagKeysValue): A trust's admitted session tag keys: at most
// 50 distinct tag keys, or exactly ['*'] for any key.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AllowedTagKeysValue(value any) (result []string, err error) {
	err = notImplemented("temporary-credentials.ts allowedTagKeysValue")
	return
}

// AudienceValue (temporary-credentials.ts audienceValue): Requested JWT audiences: 1 to 5 URL-safe identifiers,
// deduplicated, and only with `format: 'jwt'`. Whether each is on the deployment's allowlist and permitted to the
// caller is checked at issuance (`mintCredential`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AudienceValue(value any, format string) (result []string, err error) {
	err = notImplemented("temporary-credentials.ts audienceValue")
	return
}

// CallerIdentity (temporary-credentials.ts callerIdentity): `sts.getCallerIdentity`: an allowlist projection of a
// verified principal.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CallerIdentity(principal *Principal) (result *core.Object, err error) {
	err = notImplemented("temporary-credentials.ts callerIdentity")
	return
}

// CredentialFormat (temporary-credentials.ts credentialFormat): The requested credential format; 'opaque' by
// default.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CredentialFormat(value any) (result string, err error) {
	err = notImplemented("temporary-credentials.ts credentialFormat")
	return
}

// DeleteTemporarySessions (temporary-credentials.ts deleteTemporarySessions): Deletes live role sessions of a role
// in a tenant created before `createdBefore` (eager revocation alongside a watermark), optionally only those of one
// trust or one OIDC provider. Reads through the indexed roleId and returns the number of rows deleted.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeleteTemporarySessions(ctx context.Context, tx core.IamStore, filter *core.Object) (result float64, err error) {
	err = notImplemented("temporary-credentials.ts deleteTemporarySessions")
	return
}

// DurationWithin (temporary-credentials.ts durationWithin): A requested duration within the bounds (the fallback
// when absent); anything outside is INVALID_INPUT, never clamped.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DurationWithin(value any, bounds *core.Object) (result float64, err error) {
	err = notImplemented("temporary-credentials.ts durationWithin")
	return
}

// MintCredential (temporary-credentials.ts mintCredential): Issues a temporary credential for a draft session row
// and stores the row. The draft carries every field except the token material (`tokenHash` and `uniqueKey` are
// replaced; `format` and `audience` are set here). Opaque tokens are typed and checksummed (`biam_rol_…` for role
// sessions, `biam_sts_…` for session tokens). Session JWTs need `sts.jwt` (FEATURE_DISABLED otherwise): every
// audience must be on the deployment's allowlist (INVALID_INPUT), and each one other than the IAM issuer must be
// allowed as `iam:assertions:create` on `iam/{aud}` for the drafted session (ACCESS_DENIED). The token is signed,
// bounded to 4096 characters, and its SHA-256 stored like an opaque token's, so IAM re-validates the row on every
// use.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MintCredential(ctx context.Context, server *ServerContext, tx core.IamStore, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("temporary-credentials.ts mintCredential")
	return
}

// RoleDurationBounds (temporary-credentials.ts roleDurationBounds): Role session durations: the least of the
// deployment ceiling (`sts.maxRoleSessionSeconds`), the trust's `maxSessionSeconds` (3600 when absent or not a
// positive integer) and, for JWTs, `sts.jwt.maxLifetimeSeconds`; 900 by default or the maximum when that is lower. A
// lower level can only reduce the level above it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RoleDurationBounds(server *ServerContext, trust *core.Object, format string) (result *core.Object, err error) {
	err = notImplemented("temporary-credentials.ts roleDurationBounds")
	return
}

// RoleSessionSummary (temporary-credentials.ts roleSessionSummary): `roles.listSessions`: an allowlist projection of
// a role session row.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RoleSessionSummary(session *core.Object) (result *core.Object, err error) {
	err = notImplemented("temporary-credentials.ts roleSessionSummary")
	return
}

// SessionNameValue (temporary-credentials.ts sessionNameValue): A session name, or undefined when none was given.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SessionNameValue(value any) (result string, err error) {
	err = notImplemented("temporary-credentials.ts sessionNameValue")
	return
}

// SessionTagsValue (temporary-credentials.ts sessionTagsValue): Session tags: at most 50, keys matching
// /^[A-Za-z][A-Za-z0-9_]{0,63}$/ and unique case-insensitively, values of at most 256 characters from the tag value
// charset, and at most 2048 bytes as packed JSON. Undefined (or no tags) gives undefined.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SessionTagsValue(value any) (result *core.Object, err error) {
	err = notImplemented("temporary-credentials.ts sessionTagsValue")
	return
}

// SessionTokenDurationBounds (temporary-credentials.ts sessionTokenDurationBounds): Session token durations: the
// least of `sts.maxSessionTokenSeconds` and, for JWTs, `sts.jwt.maxLifetimeSeconds`; 3600 by default or the maximum
// when that is lower. A limit that is not a positive integer counts as 3600.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SessionTokenDurationBounds(server *ServerContext, format string) (result *core.Object, err error) {
	err = notImplemented("temporary-credentials.ts sessionTokenDurationBounds")
	return
}

// SourceIdentityValue (temporary-credentials.ts sourceIdentityValue): A caller-stated source identity, or undefined
// when none was given.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SourceIdentityValue(value any) (result string, err error) {
	err = notImplemented("temporary-credentials.ts sourceIdentityValue")
	return
}

// TemporaryCredential (temporary-credentials.ts temporaryCredential): The issuer response for a stored temporary
// session (an allowlist projection; the token is the only secret).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TemporaryCredential(token string, session *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("temporary-credentials.ts temporaryCredential")
	return
}

// SessionNamePattern is temporary-credentials.ts sessionNamePattern.
var SessionNamePattern = regexp.MustCompile("^[\\w+=,.@-]{2,64}$")
