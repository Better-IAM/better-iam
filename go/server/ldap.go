package server

// Skeleton of packages/server/src/ldap.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// BuildLdapDirectory (ldap.ts buildLdapDirectory): Builds the directory view of a tenant: active people, published
// groups and (optionally) service accounts.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BuildLdapDirectory(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, settings *core.Object, self *Principal) (result *core.Object, err error) {
	err = notImplemented("ldap.ts buildLdapDirectory")
	return
}

// LdapRuntime is ldap.ts createLdapRuntime().
type LdapRuntime struct {
	server *ServerContext
}

// TenantForBase (ldap.ts createLdapRuntime().tenantForBase): The tenant publishing its directory under a normalized
// base DN, with its gateway settings; undefined when none does, it is off, or the organization is not active.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *LdapRuntime) TenantForBase(ctx context.Context, normalizedBaseDn string) (result *core.Object, err error) {
	err = notImplemented("ldap.ts createLdapRuntime().tenantForBase")
	return
}

// ResolveBindName (ldap.ts createLdapRuntime().resolveBindName): The sign-in email of the person a people RDN value
// names (`uid` as the tenant configured it), or the service account a name (or, when names collide, an ID) names;
// undefined when nobody matches. Only active members resolve. `mfa` says how a person's bind must authenticate:
// `none` (the password), `totp` (the password followed by the current authenticator code) or `unavailable` (MFA is
// required but no authenticator is enrolled, which LDAP cannot satisfy), so the gateway makes exactly one sign-in
// attempt per bind.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *LdapRuntime) ResolveBindName(ctx context.Context, tenantID string, kind string, value string) (result *core.Object, err error) {
	err = notImplemented("ldap.ts createLdapRuntime().resolveBindName")
	return
}

// CreateLdapRuntime builds the LdapRuntime (ldap.ts createLdapRuntime). Its methods are stubs until the module is ported.
func CreateLdapRuntime(server *ServerContext) *LdapRuntime {
	return &LdapRuntime{server: server}
}

// LoadLdapSettings (ldap.ts loadLdapSettings): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LoadLdapSettings(ctx context.Context, tx core.IamStore, tenant *core.Object) (result *core.Object, err error) {
	err = notImplemented("ldap.ts loadLdapSettings")
	return
}

// NormalizeBaseDn (ldap.ts normalizeBaseDn): Validates a base DN and returns its comparison form: `attr=value`
// components of letters, digits, spaces, `.`, `_` and `-` (no escapes), lowercased with spaces collapsed, exactly as
// `@better-iam/ldap` normalizes DNs.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func NormalizeBaseDn(value any) (result *core.Object, err error) {
	err = notImplemented("ldap.ts normalizeBaseDn")
	return
}

// SaveLdapSettings (ldap.ts saveLdapSettings): Stores settings and keeps the base DN index in step (a base DN
// belongs to one tenant).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SaveLdapSettings(ctx context.Context, tx core.IamStore, settings *core.Object, previous *core.Object) (result *core.Object, err error) {
	err = notImplemented("ldap.ts saveLdapSettings")
	return
}
