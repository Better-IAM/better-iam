package server

// Port of packages/server/src/context-keys.ts: the registry of context keys the server derives for every decision.
// Decisions assign them, policy lint knows their types, the catalog reserves their names as identity attributes, and
// package rules refuse the ones that describe a session. Lower-precedence context (resolveContext, plugins, identity
// attributes) can never supply them: IsServerOwnedKey names every key that is removed before the server assigns its
// own values.

import (
	"regexp"
	"strings"
)

// ContextKeyType is what a context key holds. `identifier` strings are never timestamps; `timestamp` values are
// ISO-8601 strings.
type ContextKeyType = string

// ContextKey is one registry entry.
type ContextKey struct {
	Name string
	Type ContextKeyType
}

// keyRegistry is an ordered, read-only map of context keys (a TypeScript ReadonlyMap).
type keyRegistry struct {
	entries []ContextKey
	index   map[string]ContextKeyType
}

func newKeyRegistry(entries ...ContextKey) *keyRegistry {
	registry := &keyRegistry{entries: entries, index: map[string]ContextKeyType{}}
	for _, entry := range entries {
		registry.index[entry.Name] = entry.Type
	}
	return registry
}

// Has reports whether the key is registered.
func (r *keyRegistry) Has(key string) bool {
	_, ok := r.index[key]
	return ok
}

// Get returns the key's type.
func (r *keyRegistry) Get(key string) (ContextKeyType, bool) {
	value, ok := r.index[key]
	return value, ok
}

// Entries lists the keys in registry order.
func (r *keyRegistry) Entries() []ContextKey { return append([]ContextKey(nil), r.entries...) }

// Keys lists the key names in registry order.
func (r *keyRegistry) Keys() []string {
	keys := make([]string, len(r.entries))
	for index, entry := range r.entries {
		keys[index] = entry.Name
	}
	return keys
}

// Len is the number of keys.
func (r *keyRegistry) Len() int { return len(r.entries) }

// PrincipalServerKeys are every principal.* and request.* key the server derives, with its type. Optional members
// (OptionalPrincipalServerKeys) are absent when their source is absent; the rest are always present.
var PrincipalServerKeys = newKeyRegistry(
	ContextKey{"principal.id", "identifier"},
	ContextKey{"principal.tenantId", "identifier"},
	ContextKey{"principal.mfa", "boolean"},
	ContextKey{"principal.kind", "identifier"},
	ContextKey{"principal.owner", "boolean"},
	ContextKey{"principal.rootAdmin", "boolean"},
	// 'user' | 'role' | 'api-key' | 'session-token' | 'delegated'.
	ContextKey{"principal.sessionKind", "identifier"},
	ContextKey{"principal.authMethod", "identifier"},
	ContextKey{"principal.impersonated", "boolean"},
	ContextKey{"principal.impersonatorId", "identifier"},
	ContextKey{"principal.groups", "list"},
	ContextKey{"principal.roles", "list"},
	ContextKey{"principal.agreements", "list"},
	ContextKey{"principal.pendingAgreements", "number"},
	// Onboarding flows the person completed (names) and required ones still open.
	ContextKey{"principal.onboarding", "list"},
	ContextKey{"principal.pendingOnboarding", "number"},
	// Teams the person belongs to (team IDs, with the teams above them) and their department with the ones above it.
	ContextKey{"principal.teams", "list"},
	ContextKey{"principal.departments", "list"},
	ContextKey{"principal.departmentId", "identifier"},
	// Spend (billing-service.ts): whether an enforced budget covering the principal is spent, and the spent budgets.
	ContextKey{"principal.spendExceeded", "boolean"},
	ContextKey{"principal.budgetsExceeded", "list"},
	// Privacy (privacy.ts): keys of the consent and legitimate-interest purposes that may be processed now.
	ContextKey{"principal.consents", "list"},
	// Threat detection (threats.ts): the identity's effective risk level and score.
	ContextKey{"principal.riskLevel", "identifier"},
	ContextKey{"principal.riskScore", "number"},
	// License management (licenses.ts): keys of the license products the person holds an active seat for.
	ContextKey{"principal.licenses", "list"},
	// B2B guest collaboration (guests.ts).
	ContextKey{"principal.guest", "boolean"},
	ContextKey{"principal.guestSponsorId", "identifier"},
	ContextKey{"principal.homeTenantId", "identifier"},
	// Session-aware keys: 'simulation' is the session id of simulated principals.
	ContextKey{"principal.sessionId", "identifier"},
	ContextKey{"principal.tokenIssueTime", "timestamp"},
	ContextKey{"principal.authTime", "timestamp"},
	ContextKey{"principal.mfaTime", "timestamp"},
	ContextKey{"principal.sessionTagKeys", "list"},
	ContextKey{"principal.sourceTenantId", "identifier"},
	ContextKey{"principal.sessionName", "identifier"},
	ContextKey{"principal.sourceIdentity", "identifier"},
	ContextKey{"principal.webIdentityProvider", "identifier"},
	ContextKey{"principal.webIdentitySubject", "string"},
	// AI agents (agents.ts).
	ContextKey{"principal.delegated", "boolean"},
	ContextKey{"principal.delegationId", "identifier"},
	ContextKey{"principal.agentId", "identifier"},
	ContextKey{"principal.agentSponsorId", "identifier"},
	ContextKey{"principal.agentModel", "string"},
	ContextKey{"principal.agentProvider", "string"},
	// Delegated sessions: the agents from the person's own delegate to the acting one.
	ContextKey{"principal.delegationChain", "list"},
	ContextKey{"request.time", "timestamp"},
	// The client address the server saw; never set for simulated principals or without a client scope.
	ContextKey{"request.sourceIp", "identifier"},
	// Device posture (devices.ts).
	ContextKey{"request.deviceAssurance", "identifier"},
	ContextKey{"request.deviceManaged", "boolean"},
	ContextKey{"request.deviceCompliant", "boolean"},
	ContextKey{"request.deviceId", "identifier"},
	ContextKey{"request.devicePlatform", "identifier"},
	// Security clearances (clearances.ts), only with options.clearances.
	ContextKey{"principal.clearanceLevel", "identifier"},
	ContextKey{"principal.clearanceRank", "number"},
	ContextKey{"principal.clearanceStatus", "identifier"},
	ContextKey{"principal.clearanceCompartments", "list"},
	ContextKey{"principal.clearanceCitizenship", "list"},
)

// ResourceServerKeys are the resource.* keys the server derives from a resource's classification label (only with
// options.clearances). Written after the resource's attributes, so neither attributes nor application context can
// stand in for them.
var ResourceServerKeys = newKeyRegistry(
	ContextKey{"resource.classification", "identifier"},
	ContextKey{"resource.classificationRank", "number"},
	ContextKey{"resource.compartments", "list"},
	ContextKey{"resource.noforn", "boolean"},
	ContextKey{"resource.releasableTo", "list"},
)

// OptionalResourceServerKeys are resource server keys missing from some decisions.
var OptionalResourceServerKeys = newOrderedSet("resource.classification")

// ClearanceServerKeys are the keys only the server sets once the deployment enables clearances.
var ClearanceServerKeys = newOrderedSet(append([]string{
	"principal.clearanceLevel",
	"principal.clearanceRank",
	"principal.clearanceStatus",
	"principal.clearanceCompartments",
	"principal.clearanceCitizenship",
}, ResourceServerKeys.Keys()...)...)

// TenantServerKeys are the tenant.* keys the server derives about the decision's tenant.
var TenantServerKeys = newKeyRegistry(ContextKey{"tenant.features", "list"})

// OptionalPrincipalServerKeys are server keys missing from some decisions (every operator except Exists is then
// false).
var OptionalPrincipalServerKeys = newOrderedSet(
	"principal.authMethod",
	"principal.impersonatorId",
	"principal.mfaTime",
	"principal.sourceTenantId",
	"principal.sessionName",
	"principal.sourceIdentity",
	"principal.webIdentityProvider",
	"principal.webIdentitySubject",
	"principal.delegationId",
	"principal.agentId",
	"principal.agentSponsorId",
	"principal.agentModel",
	"principal.agentProvider",
	"principal.delegationChain",
	"principal.departmentId",
	"principal.guestSponsorId",
	"principal.homeTenantId",
	"request.sourceIp",
	"request.deviceId",
	"request.devicePlatform",
	"principal.clearanceLevel",
)

// SessionTagPrefix: session tags appear as `principal.sessionTags.<key>` (optional strings), one key per tag.
const SessionTagPrefix = "principal.sessionTags."

// TagKeyPattern is a session tag key: a letter, then letters, digits or underscores, at most 64 characters.
var TagKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// ReservedSessionPrincipalNames are the bare principal names the session keys occupy; identity attributes may not
// use them.
var ReservedSessionPrincipalNames = []string{
	"sessionId",
	"tokenIssueTime",
	"authTime",
	"mfaTime",
	"sourceTenantId",
	"sessionName",
	"sourceIdentity",
	"sessionTags",
	"sessionTagKeys",
	"webIdentityProvider",
	"webIdentitySubject",
	"delegated",
	"delegationId",
	"agentId",
	"agentSponsorId",
	"agentModel",
	"agentProvider",
	"delegationChain",
}

// SessionScopedPrincipalKeys are the session-derived principal keys as policies name them; rules evaluated without a
// session (package rules) refuse them.
var SessionScopedPrincipalKeys = func() []string {
	var keys []string
	for _, name := range ReservedSessionPrincipalNames {
		if name != "sessionTags" {
			keys = append(keys, "principal."+name)
		}
	}
	return keys
}()

// IsServerOwnedKey reports whether only the server may set this context key: a registry member or any
// `principal.sessionTags.` key. The clearance keys count only when clearances is true (the deployment sets
// options.clearances); pass true for the strict reading (the TypeScript default).
func IsServerOwnedKey(key string, clearances bool) bool {
	if !clearances && ClearanceServerKeys.Has(key) {
		return false
	}
	return PrincipalServerKeys.Has(key) || TenantServerKeys.Has(key) || ResourceServerKeys.Has(key) ||
		strings.HasPrefix(key, SessionTagPrefix)
}

// SessionTagName is the context key (`principal.sessionTags.<key>`) for a session tag key, or "" when the key is not
// valid.
func SessionTagName(key string) string {
	if TagKeyPattern.MatchString(key) {
		return SessionTagPrefix + key
	}
	return ""
}
