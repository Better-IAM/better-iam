package server

// Port of packages/server/src/api/service-accounts.ts: the `serviceAccounts` API group (non-human identities of a
// tenant) and the `credentials` API group (their API keys: issue, relabel, rotate, revoke, review).

import (
	"context"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// ServiceAccountsAPI is the `serviceAccounts` API group (packages/server/src/api/service-accounts.ts createServiceAccountsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/serviceAccounts/{method} onto it.
type ServiceAccountsAPI struct {
	server *ServerContext
}

// CreateServiceAccountsAPI builds the `serviceAccounts` API group.
func CreateServiceAccountsAPI(server *ServerContext) *ServiceAccountsAPI {
	return &ServiceAccountsAPI{server: server}
}

// Create is POST {basePath}/serviceAccounts/create. `expiresAt` schedules deactivation: the account's keys stop
// working at that time and the worker disables it.
func (api *ServiceAccountsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsCreateInput]) (Out[apitypes.ServiceAccountsCreateOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	account, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:identities:create", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(rawTenantID)
		if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, ""); err != nil {
			return nil, err
		}
		if err := server.EnforceLimit(ctx, tx, tenant, "serviceAccounts", func(ctx context.Context) (int, error) {
			accounts, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "service"), nil)
			if err != nil {
				return 0, err
			}
			count := 0
			for _, item := range accounts {
				if item.Get("status") != "deleted" {
					count++
				}
			}
			return count, nil
		}); err != nil {
			return nil, err
		}
		name, err := Text(input.Get("name"), "name")
		if err != nil {
			return nil, err
		}
		record := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"kind", "service",
			"name", name,
			"status", "active",
			"emailVerified", false,
			"owner", false,
			"rootAdmin", false,
			"createdAt", float64(server.Wall()),
		)
		if description := input.Get("description"); !isUndefined(description) {
			text, err := Text(description, "description", 512)
			if err != nil {
				return nil, err
			}
			record.Set("description", text)
		}
		if expiresAt := input.Get("expiresAt"); !isUndefined(expiresAt) {
			expiry, err := server.BindingExpiry(expiresAt)
			if err != nil {
				return nil, err
			}
			record.Set("expiresAt", expiry)
		}
		return tx.Insert(ctx, "identities", record)
	}, false)
	var ids []string
	if account != nil {
		ids = []string{jsString(account.Get("id"))}
	}
	result, err := identityAfterChange(ctx, server, rawTenantID, ids, account, err)
	return Out[apitypes.ServiceAccountsCreateOutput]{Value: result}, err
}

// List is POST {basePath}/serviceAccounts/list. Lists the tenant's service accounts, without deleted ones unless you
// ask for them.
func (api *ServiceAccountsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsListInput]) (Out[apitypes.ServiceAccountsListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:identities:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		accounts, err := call.Tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "service"), nil)
		if err != nil {
			return nil, err
		}
		includeDeleted := input.Get("includeDeleted") == true
		list := []any{}
		for _, account := range accounts {
			if includeDeleted || account.Get("status") != "deleted" {
				list = append(list, PublicIdentity(account))
			}
		}
		return list, nil
	}, false)
	return Out[apitypes.ServiceAccountsListOutput]{Value: result}, err
}

// Get is POST {basePath}/serviceAccounts/get. Returns one service account by id.
func (api *ServiceAccountsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsGetInput]) (Out[apitypes.ServiceAccountsGetOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:read", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		account, err := server.ServiceAccount(ctx, call.Tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		return PublicIdentity(account), nil
	}, false)
	return Out[apitypes.ServiceAccountsGetOutput]{Value: result}, err
}

// Update is POST {basePath}/serviceAccounts/update. Renames a service account, changes its description or directory
// attributes, or schedules (epoch milliseconds) or clears (null) its deactivation.
func (api *ServiceAccountsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsUpdateInput]) (Out[apitypes.ServiceAccountsUpdateOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	updated, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		account, err := server.ServiceAccount(ctx, call.Tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if account.Get("status") == "deleted" {
			return nil, core.NewIamError("NOT_FOUND", "Service account has been deleted", 404)
		}
		name, description, attributes, expiresAt := input.Get("name"), input.Get("description"), input.Get("attributes"), input.Get("expiresAt")
		if isUndefined(name) && isUndefined(description) && isUndefined(attributes) && isUndefined(expiresAt) {
			return nil, invalidInput("Nothing to update")
		}
		next := account.Spread()
		if !isUndefined(name) {
			text, err := Text(name, "name")
			if err != nil {
				return nil, err
			}
			next.Set("name", text)
		}
		if !isUndefined(description) {
			text, err := Text(description, "description", 512)
			if err != nil {
				return nil, err
			}
			next.Set("description", text)
		}
		if !isUndefined(attributes) {
			values, err := AttributeValues(server.Catalog.IdentityAttributes, attributes)
			if err != nil {
				return nil, err
			}
			next.Set("attributes", values)
		}
		if expiresAt == nil {
			next.Delete("expiresAt")
		} else if !isUndefined(expiresAt) {
			expiry, err := server.BindingExpiry(expiresAt)
			if err != nil {
				return nil, err
			}
			next.Set("expiresAt", expiry)
		}
		stored, err := call.Tx.Put(ctx, "identities", next)
		if err != nil {
			return nil, err
		}
		return PublicIdentity(stored), nil
	}, false)
	var ids []string
	if updated != nil {
		ids = []string{jsString(updated.Get("id"))}
	}
	result, err := identityAfterChange(ctx, server, tenantID, ids, updated, err)
	return Out[apitypes.ServiceAccountsUpdateOutput]{Value: result}, err
}

// SetStatus is POST {basePath}/serviceAccounts/setStatus. Disabling a service account revokes every API key and
// assumed-role session it holds until it is enabled again.
func (api *ServiceAccountsAPI) SetStatus(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsSetStatusInput]) (Out[apitypes.ServiceAccountsSetStatusOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:update", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		status := input.Get("status")
		if status != "active" && status != "disabled" {
			return nil, invalidInput("Invalid status")
		}
		account, err := server.ServiceAccount(ctx, tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if account.Get("status") == "deleted" {
			return nil, core.NewIamError("NOT_FOUND", "Service account has been deleted", 404)
		}
		if status == "active" && server.IdentityExpired(account) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Extend or clear expiresAt before re-enabling an expired service account", 409)
		}
		stored, err := tx.Put(ctx, "identities", account.Spread(core.NewObject("status", status)))
		if err != nil {
			return nil, err
		}
		id := jsString(account.Get("id"))
		// The status is now this call's: a threats containment is over (released here, or held by this disable).
		if err := EndContainment(ctx, tx, id, server.Now()); err != nil {
			return nil, err
		}
		if status == "disabled" {
			if err := server.RevokeAll(ctx, tx, id); err != nil {
				return nil, err
			}
		}
		return PublicIdentity(stored), nil
	}, false)
	return Out[apitypes.ServiceAccountsSetStatusOutput]{Value: result}, err
}

// Delete is POST {basePath}/serviceAccounts/delete. Deletes a service account, revoking its keys and removing every
// grant it held.
func (api *ServiceAccountsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.ServiceAccountsDeleteInput]) (Out[apitypes.ServiceAccountsDeleteOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:identities:delete", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		account, err := server.ServiceAccount(ctx, tx, identityID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		deleted, err := DeleteIdentity(ctx, server, tx, principal, account)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "identity:delete", jsString(tenantID), jsString(account.Get("id")), "allow", false,
			core.NewObject("kind", "service")); err != nil {
			return nil, err
		}
		return deleted, nil
	}, false)
	return Out[apitypes.ServiceAccountsDeleteOutput]{Value: result}, err
}

// keyScopesSid is the statement ID of a scopes list's compiled session policy.
const keyScopesSid = "KeyScopes"

// ScopesPolicy (api/service-accounts.ts scopesPolicy): a scopes list compiles to a session policy allowing exactly
// those actions on every resource.
func ScopesPolicy(scopes []string) *core.Object {
	return core.NewObject(
		"version", 1.0,
		"statements", []any{core.NewObject("sid", keyScopesSid, "effect", "allow", "actions", stringsOf(scopes), "resources", []any{"*"})},
	)
}

// policyScopes is the scopes list behind a session policy, when the policy is exactly the compiled form (ok false
// otherwise).
func policyScopes(policy any) ([]any, bool) {
	if nullish(policy) {
		return nil, false
	}
	statements, ok := member(policy, "statements").([]any)
	if !ok || len(statements) != 1 {
		return nil, false
	}
	statement := statements[0]
	if nullish(statement) || member(statement, "sid") != keyScopesSid || member(statement, "effect") != "allow" {
		return nil, false
	}
	resources, ok := member(statement, "resources").([]any)
	if !ok || len(resources) != 1 || resources[0] != "*" || truthy(member(statement, "conditions")) {
		return nil, false
	}
	actions, ok := member(statement, "actions").([]any)
	if !ok {
		return nil, false
	}
	return append([]any{}, actions...), true
}

// scopeWildcard is /[*?]|\$\{/.
var scopeWildcard = regexp.MustCompile(`[*?]|\$\{`)

// scopeCovers is whether every action `inner` names is also named by `outer`; a wildcard scope needs an equal or
// broader prefix.
func scopeCovers(outer, inner string) bool {
	if outer == inner {
		return true
	}
	if !scopeWildcard.MatchString(inner) {
		return core.MatchPattern(outer, inner, nil)
	}
	if !strings.HasSuffix(outer, "*") {
		return false
	}
	prefix := strings.TrimSuffix(outer, "*")
	return !scopeWildcard.MatchString(prefix) && strings.HasPrefix(inner, prefix)
}

// withinKeyPolicy is whether a key policy stays within a caller key's own: the same document, or scopes that each
// fall within one of the caller's scopes. Anything else (a broader or an unrelated custom policy, or none) does not.
func withinKeyPolicy(outer, inner any) bool {
	if !truthy(inner) {
		return false
	}
	left, _, leftErr := core.Stringify(outer)
	right, _, rightErr := core.Stringify(inner)
	if leftErr == nil && rightErr == nil && left == right {
		return true
	}
	outerScopes, outerOK := policyScopes(outer)
	innerScopes, innerOK := policyScopes(inner)
	if !outerOK || !innerOK {
		return false
	}
	for _, scope := range innerScopes {
		covered := false
		for _, allowed := range outerScopes {
			if scopeCovers(jsString(allowed), jsString(scope)) {
				covered = true
				break
			}
		}
		if !covered {
			return false
		}
	}
	return true
}

// CredentialSummary (api/service-accounts.ts credentialSummary): an API key as administrators see it: label,
// lifetime, and usage, never token material.
func CredentialSummary(session *core.Object, now int64) (result *core.Object, err error) {
	summary := core.NewObject(
		"id", session.Get("id"),
		"identityId", session.Get("identityId"),
		"createdAt", session.Get("createdAt"),
		"expiresAt", session.Get("expiresAt"),
		"expired", jsNumber(session.Get("expiresAt")) <= float64(now),
		"policy", session.Get("policy"),
		"credentialAuthorityId", session.Get("credentialAuthorityId"),
	)
	if name := session.Get("name"); !isUndefined(name) {
		summary.Set("name", name)
	}
	if description := session.Get("description"); !isUndefined(description) {
		summary.Set("description", description)
	}
	lastSeenAt := session.Get("lastSeenAt")
	if jsNumber(lastSeenAt) > jsNumber(session.Get("createdAt")) {
		summary.Set("lastUsedAt", lastSeenAt)
	}
	if scopes, ok := policyScopes(session.Get("policy")); ok {
		summary.Set("scopes", scopes)
	}
	return summary, nil
}

// CredentialsAPI is the `credentials` API group (packages/server/src/api/service-accounts.ts createCredentialsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/credentials/{method} onto it.
type CredentialsAPI struct {
	server *ServerContext
}

// CreateCredentialsAPI builds the `credentials` API group.
func CreateCredentialsAPI(server *ServerContext) *CredentialsAPI {
	return &CredentialsAPI{server: server}
}

// keyExpiry: a key's expiry may be extended or shortened, but only into the future and at most a year out.
func keyExpiry(value any, now float64) (float64, error) {
	expiresAt, err := Integer(value, "expiresAt", 0, maxSafeInteger)
	if err != nil {
		return 0, err
	}
	if expiresAt <= now {
		return 0, invalidInput("expiresAt must be in the future")
	}
	if expiresAt > now+86400_000*365 {
		return 0, invalidInput("expiresAt must be within one year")
	}
	return expiresAt, nil
}

// apiKey is a tenant session that must be an API key.
func (api *CredentialsAPI) apiKey(ctx context.Context, tx core.IamStore, credentialID any, tenantID string) (*core.Object, error) {
	session, err := api.server.Scoped(ctx, tx, "sessions", credentialID, tenantID)
	if err != nil {
		return nil, err
	}
	if session.Get("kind") != "api-key" {
		return nil, core.NewIamError("INVALID_CREDENTIAL", "Not an API key credential")
	}
	return session, nil
}

// List is POST {basePath}/credentials/list. API keys of the tenant, or of one service account, with their labels and
// last use. `unusedForMs` keeps only keys that have not authenticated a request in that long (including keys never
// used since creation), for hygiene reviews. Token hashes are never returned.
func (api *CredentialsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsListInput]) (Out[apitypes.CredentialsListOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:credentials:read", jsString(coalesce(input.Get("identityId"), tenantID)), func(ctx context.Context, call MutationContext) ([]any, error) {
		filter := core.NewObject("tenantId", tenantID, "kind", "api-key")
		if identityID := input.Get("identityId"); !isUndefined(identityID) {
			text, err := Text(identityID, "identityId")
			if err != nil {
				return nil, err
			}
			filter.Set("identityId", text)
		}
		now := server.Now()
		unusedSince, filtered := 0.0, false
		if unusedFor := input.Get("unusedForMs"); !isUndefined(unusedFor) {
			window, err := Integer(unusedFor, "unusedForMs", 0, 10*365*86400_000)
			if err != nil {
				return nil, err
			}
			unusedSince, filtered = float64(now)-window, true
		}
		sessions, err := call.Tx.Find(ctx, "sessions", filter, nil)
		if err != nil {
			return nil, err
		}
		summaries := []*core.Object{}
		for _, session := range sessions {
			summary, err := CredentialSummary(session, now)
			if err != nil {
				return nil, err
			}
			if filtered {
				used := jsNumber(coalesce(summary.Get("lastUsedAt"), summary.Get("createdAt")))
				if !(used <= unusedSince) {
					continue
				}
			}
			summaries = append(summaries, summary)
		}
		identityNewestFirst(summaries, "createdAt")
		return identityRecordList(summaries), nil
	}, false)
	return Out[apitypes.CredentialsListOutput]{Value: result}, err
}

// Get is POST {basePath}/credentials/get. Returns one API key's label, lifetime, scopes, and last use, without token
// material.
func (api *CredentialsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsGetInput]) (Out[apitypes.CredentialsGetOutput], error) {
	server := api.server
	tenantID, credentialID := input.Get("tenantId"), input.Get("credentialId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:credentials:read", jsString(credentialID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		session, err := api.apiKey(ctx, call.Tx, credentialID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		return CredentialSummary(session, server.Now())
	}, false)
	return Out[apitypes.CredentialsGetOutput]{Value: result}, err
}

// Create is POST {basePath}/credentials/create. Issues an opaque API key for a service account, bounded by the
// issuer's grant authority and an optional session policy. `name` and `description` label the key for reviews; the
// plaintext is returned once. An API key with scopes (or a session policy) issues only keys within them; without
// scopes of their own, they inherit its.
func (api *CredentialsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsCreateInput]) (Out[apitypes.CredentialsCreateOutput], error) {
	server := api.server
	rawTenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:credentials:create", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		tenantID := jsString(rawTenantID)
		authority, err := server.GrantingAuthority(ctx, tx, principal, tenantID, "")
		if err != nil {
			return nil, err
		}
		identity, err := server.Scoped(ctx, tx, "identities", identityID, tenantID)
		if err != nil {
			return nil, err
		}
		if !MachineIdentity(identity) || identity.Get("status") != "active" || server.IdentityExpired(identity) {
			return nil, core.NewIamError("INVALID_IDENTITY", "API keys require an active service account")
		}
		// An agent gets keys only while its sponsor is an active person (agents.ts).
		if identity.Get("kind") == "agent" {
			standing, err := AgentStanding(ctx, server, tx, identity)
			if err != nil {
				return nil, err
			}
			if standing != "ok" {
				return nil, core.NewIamError("INVALID_IDENTITY", "API keys require an agent in good standing")
			}
		}
		policy := input.Get("policy")
		if scopes := input.Get("scopes"); !isUndefined(scopes) {
			if !isUndefined(policy) {
				return nil, invalidInput("Provide either scopes or a session policy")
			}
			list, err := Strings(scopes, "scopes")
			if err != nil {
				return nil, err
			}
			list = unique(list)
			if len(list) == 0 {
				return nil, invalidInput("scopes must name at least one action")
			}
			policy = ScopesPolicy(list)
		}
		// A key never mints a broader key: a caller key with scopes or a session policy passes them on (a new key
		// without its own gets the caller's), and a new key's own scopes must fall within the caller's.
		if callerPolicy := principal.Session.Get("policy"); truthy(callerPolicy) {
			if isUndefined(policy) {
				policy = callerPolicy
			} else if !withinKeyPolicy(callerPolicy, policy) {
				return nil, core.NewIamError("ACCESS_DENIED", "A key can only issue keys within its own scopes or policy", 403)
			}
		}
		if truthy(policy) {
			if err := server.Catalog.Validate(ctx, tx, tenantID, policy); err != nil {
				return nil, err
			}
		}
		// Typed and checksummed (`biam_key_…`) so secret scanners recognise leaked keys.
		raw, err := auth.NewCredentialToken("key")
		if err != nil {
			return nil, err
		}
		// The injected clock, so creation and expiry agree with every other time check.
		now := float64(server.Now())
		duration, err := Integer(coalesce(input.Get("expiresInSeconds"), float64(86400*90)), "expiresInSeconds", 60, 86400*365)
		if err != nil {
			return nil, err
		}
		record := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"identityId", identity.Get("id"),
			"kind", "api-key",
			"tokenHash", Hash(raw),
			"uniqueKey", Hash(raw),
			"createdAt", now,
			"lastSeenAt", now,
			"authenticatedAt", now,
			"expiresAt", now+duration*1000,
			"mfa", false,
			"policy", policy,
			"credentialAuthorityId", authority.Get("id"),
		)
		if name := input.Get("name"); !isUndefined(name) {
			text, err := Text(name, "name", 128)
			if err != nil {
				return nil, err
			}
			record.Set("name", text)
		}
		if description := input.Get("description"); !isUndefined(description) {
			text, err := Text(description, "description", 512)
			if err != nil {
				return nil, err
			}
			record.Set("description", text)
		}
		session, err := tx.Insert(ctx, "sessions", record)
		if err != nil {
			return nil, err
		}
		return core.NewObject("token", raw, "credentialId", session.Get("id"), "expiresAt", session.Get("expiresAt"), "name", session.Get("name")), nil
	}, false)
	return Out[apitypes.CredentialsCreateOutput]{Value: result}, err
}

// Update is POST {basePath}/credentials/update. Relabels a key or moves its expiry (future, at most a year out); the
// token itself never changes.
func (api *CredentialsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsUpdateInput]) (Out[apitypes.CredentialsUpdateOutput], error) {
	server := api.server
	rawTenantID, credentialID := input.Get("tenantId"), input.Get("credentialId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:credentials:create", jsString(credentialID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(rawTenantID)
		session, err := api.apiKey(ctx, tx, credentialID, tenantID)
		if err != nil {
			return nil, err
		}
		name, description, expiresAt := input.Get("name"), input.Get("description"), input.Get("expiresAt")
		if isUndefined(name) && isUndefined(description) && isUndefined(expiresAt) {
			return nil, invalidInput("Nothing to update")
		}
		if !isUndefined(expiresAt) {
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
			if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, identityAuthorityArg(session.Get("credentialAuthorityId"))); err != nil {
				return nil, err
			}
		}
		next := session.Spread()
		if name == nil {
			next.Delete("name")
		} else if !isUndefined(name) {
			text, err := Text(name, "name", 128)
			if err != nil {
				return nil, err
			}
			next.Set("name", text)
		}
		if description == nil {
			next.Delete("description")
		} else if !isUndefined(description) {
			text, err := Text(description, "description", 512)
			if err != nil {
				return nil, err
			}
			next.Set("description", text)
		}
		if !isUndefined(expiresAt) {
			expiry, err := keyExpiry(expiresAt, float64(server.Now()))
			if err != nil {
				return nil, err
			}
			next.Set("expiresAt", expiry)
		}
		stored, err := tx.Put(ctx, "sessions", next)
		if err != nil {
			return nil, err
		}
		return CredentialSummary(stored, server.Now())
	}, false)
	return Out[apitypes.CredentialsUpdateOutput]{Value: result}, err
}

// Revoke is POST {basePath}/credentials/revoke. Deletes an API key at once. Other sessions (user, role) are refused:
// they end through their own flows.
func (api *CredentialsAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsRevokeInput]) (Out[apitypes.CredentialsRevokeOutput], error) {
	server := api.server
	tenantID, credentialID := input.Get("tenantId"), input.Get("credentialId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:credentials:revoke", jsString(credentialID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		if _, err := api.apiKey(ctx, tx, credentialID, jsString(tenantID)); err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "sessions", jsString(credentialID)); err != nil {
			return nil, err
		}
		return core.NewObject("revoked", true), nil
	}, false)
	return Out[apitypes.CredentialsRevokeOutput]{Value: result}, err
}

// Rotate is POST {basePath}/credentials/rotate. Replaces the key material atomically; the old key stops working in
// the same transaction.
func (api *CredentialsAPI) Rotate(ctx context.Context, credential core.CredentialInput, input In[apitypes.CredentialsRotateInput]) (Out[apitypes.CredentialsRotateOutput], error) {
	server := api.server
	rawTenantID, credentialID := input.Get("tenantId"), input.Get("credentialId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:credentials:create", jsString(credentialID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		tenantID := jsString(rawTenantID)
		old, err := server.Scoped(ctx, tx, "sessions", credentialID, tenantID)
		if err != nil {
			return nil, err
		}
		if old.Get("kind") != "api-key" {
			return nil, core.NewIamError("INVALID_CREDENTIAL", "Only API keys can rotate")
		}
		// Rotating hands over the new token, so a key may only rotate keys within its own scopes (as `create`).
		if callerPolicy := principal.Session.Get("policy"); truthy(callerPolicy) && !withinKeyPolicy(callerPolicy, old.Get("policy")) {
			return nil, core.NewIamError("ACCESS_DENIED", "A key can only rotate keys within its own scopes or policy", 403)
		}
		authority, err := server.GrantingAuthority(ctx, tx, principal, tenantID, identityAuthorityArg(old.Get("credentialAuthorityId")))
		if err != nil {
			return nil, err
		}
		raw, err := auth.NewCredentialToken("key")
		if err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "sessions", jsString(old.Get("id"))); err != nil {
			return nil, err
		}
		now := float64(server.Now())
		// The replacement keeps the label, policy, and expiry; its usage history and authentication time
		// (principal.authTime is an API key's creation time) start over.
		replacement := old.Spread(core.NewObject(
			"id", ID(),
			"tokenHash", Hash(raw),
			"uniqueKey", Hash(raw),
			"createdAt", now,
			"lastSeenAt", now,
			"authenticatedAt", now,
			"credentialAuthorityId", authority.Get("id"),
		))
		if _, err := tx.Insert(ctx, "sessions", replacement); err != nil {
			return nil, err
		}
		return core.NewObject("token", raw, "credentialId", replacement.Get("id"), "expiresAt", replacement.Get("expiresAt"), "name", replacement.Get("name")), nil
	}, false)
	return Out[apitypes.CredentialsRotateOutput]{Value: result}, err
}
