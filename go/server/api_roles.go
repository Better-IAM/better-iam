package server

// Port of packages/server/src/api/roles.ts: the `roles` API group and the role helpers configuration sync, policies
// and other modules share (createRole, updateRole, deleteRole, reliedOnByOthers, assertDeniesKept).

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// RolesAPI is the `roles` API group (packages/server/src/api/roles.ts createRolesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/roles/{method} onto it.
type RolesAPI struct {
	server *ServerContext
}

// CreateRolesAPI builds the `roles` API group.
func CreateRolesAPI(server *ServerContext) *RolesAPI {
	return &RolesAPI{server: server}
}

// Assume is POST {basePath}/roles/assume. AssumeRole through an identity trust: a temporary role session
// (`biam_rol_…`, or a session JWT with `format: 'jwt'`) with an optional session name, source identity and tags the
// trust admits. See FlowService.
func (api *RolesAPI) Assume(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesAssumeInput]) (Out[apitypes.RolesAssumeOutput], error) {
	result, err := api.server.Flows.AssumeRole(ctx, credential, input.Body)
	if err != nil {
		return Out[apitypes.RolesAssumeOutput]{}, err
	}
	return Out[apitypes.RolesAssumeOutput]{Value: result}, nil
}

// Create is POST {basePath}/roles/create. A role carries attached policies, an inline document, or a plain
// permissions list (an inline allow over every tenant resource).
func (api *RolesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesCreateInput]) (Out[apitypes.RolesCreateOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:roles:create", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return CreateRole(ctx, api.server, call.Tx, call.Principal, call.Tenant, input.Body)
	}, false)
	return Out[apitypes.RolesCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/roles/delete. Deletes a role together with its bindings and their activations.
func (api *RolesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesDeleteInput]) (Out[apitypes.RolesDeleteOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:roles:delete", jsString(input.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		role, err := api.server.Scoped(ctx, call.Tx, "roles", input.Get("roleId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if err := DeleteRole(ctx, api.server, call.Tx, call.Principal, role); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.RolesDeleteOutput]{Value: result}, err
}

// Get is POST {basePath}/roles/get. Returns one role by id, with its attached policies, inline document, and
// inherited roles.
func (api *RolesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesGetInput]) (Out[apitypes.RolesGetOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:roles:read", jsString(input.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return api.server.Scoped(ctx, call.Tx, "roles", input.Get("roleId"), jsString(tenantID))
	}, false)
	return Out[apitypes.RolesGetOutput]{Value: result}, err
}

// List is POST {basePath}/roles/list. Lists every role in the tenant, including the protected Owner role.
func (api *RolesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesListInput]) (Out[apitypes.RolesListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:roles:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		roles, err := call.Tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		return recordValues(roles), nil
	}, false)
	return Out[apitypes.RolesListOutput]{Value: result}, err
}

// ListBindings is POST {basePath}/roles/listBindings. Who holds a role: live bindings with their identity or group
// summary.
func (api *RolesAPI) ListBindings(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesListBindingsInput]) (Out[apitypes.RolesListBindingsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	roleID := input.Get("roleId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:bindings:read", jsString(roleID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		if _, err := server.Scoped(ctx, tx, "roles", roleID, jsString(tenantID)); err != nil {
			return nil, err
		}
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "roleId", roleID), nil)
		if err != nil {
			return nil, err
		}
		result := []any{}
		for _, binding := range bindings {
			if server.ExpiredBinding(binding) {
				continue
			}
			var subject any = core.Undefined
			if binding.Get("subjectType") == "identity" {
				identity, err := tx.Get(ctx, "identities", jsString(binding.Get("subjectId")))
				if err != nil {
					return nil, err
				}
				if identity != nil && core.StrictEquals(identity.Get("tenantId"), tenantID) {
					subject = core.NewObject("id", identity.Get("id"), "name", identity.Get("name"),
						"email", identity.Get("email"), "kind", identity.Get("kind"))
				}
			} else {
				group, err := tx.Get(ctx, "groups", jsString(binding.Get("subjectId")))
				if err != nil {
					return nil, err
				}
				if group != nil && core.StrictEquals(group.Get("tenantId"), tenantID) {
					subject = core.NewObject("id", group.Get("id"), "name", group.Get("name"))
				}
			}
			entry := binding.Spread()
			entry.SetRaw("subject", subject)
			result = append(result, entry)
		}
		return result, nil
	}, false)
	return Out[apitypes.RolesListBindingsOutput]{Value: result}, err
}

// ListSessions is POST {basePath}/roles/listSessions. Live role sessions in the tenant (of one role or trust when
// given), newest first, as allowlist summaries that never carry tokens, hashes, policies or authority ids. Expired
// sessions, sessions under a revoked or missing trust, and sessions below a role, trust or provider watermark are left
// out. Requires iam:trust:read on the role (or the tenant); `limit` is 1-500 (default 100).
func (api *RolesAPI) ListSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesListSessionsInput]) (Out[apitypes.RolesListSessionsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	roleID := input.Get("roleId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:trust:read", jsString(coalesce(roleID, tenantID)), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 500)
		if err != nil {
			return nil, err
		}
		if !isUndefined(roleID) {
			id, err := Text(roleID, "roleId")
			if err != nil {
				return nil, err
			}
			if _, err := server.Scoped(ctx, tx, "roles", id, jsString(tenantID)); err != nil {
				return nil, err
			}
		}
		var trustID any = core.Undefined
		if raw := input.Get("trustId"); !isUndefined(raw) {
			id, err := Text(raw, "trustId")
			if err != nil {
				return nil, err
			}
			trustID = id
		}
		now := float64(server.Now())
		var rows []*core.Object
		if !isUndefined(roleID) {
			rows, err = tx.Find(ctx, "sessions", core.NewObject("roleId", roleID), nil)
		} else {
			rows, err = tx.Find(ctx, "sessions", core.NewObject("tenantId", tenantID, "kind", "role"), nil)
		}
		if err != nil {
			return nil, err
		}
		// Each trust, role and provider is read once, however many sessions share it.
		records := map[string]*core.Object{}
		read := map[string]bool{}
		record := func(collection string, recordID any) (*core.Object, error) {
			id, ok := recordID.(string)
			if !ok {
				return nil, nil
			}
			key := collection + "/" + id
			if !read[key] {
				found, err := tx.Get(ctx, collection, id)
				if err != nil {
					return nil, err
				}
				records[key], read[key] = found, true
			}
			return records[key], nil
		}
		var live []*core.Object
		for _, session := range rows {
			if session.Get("kind") != "role" || !core.StrictEquals(session.Get("tenantId"), tenantID) ||
				(!isUndefined(trustID) && !core.StrictEquals(session.Get("trustId"), trustID)) ||
				!(jsNumber(session.Get("expiresAt")) > now) {
				continue
			}
			trust, err := record("trusts", session.Get("trustId"))
			if err != nil {
				return nil, err
			}
			role, err := record("roles", session.Get("roleId"))
			if err != nil {
				return nil, err
			}
			var providerWatermark any = core.Undefined
			if webIdentity := session.Get("webIdentity"); truthy(webIdentity) {
				provider, err := record("oidcProviders", member(webIdentity, "providerId"))
				if err != nil {
					return nil, err
				}
				if provider != nil {
					providerWatermark = provider.Get("sessionsRevokedBefore")
				}
			}
			if trust == nil || truthy(trust.Get("revoked")) || !core.StrictEquals(trust.Get("tenantId"), tenantID) ||
				role == nil || !core.StrictEquals(role.Get("tenantId"), tenantID) ||
				RevokedByWatermark(jsNumber(session.Get("createdAt")), trust.Get("sessionsRevokedBefore"),
					role.Get("sessionsRevokedBefore"), providerWatermark) {
				continue
			}
			live = append(live, session)
		}
		sortStable(live, func(a, b *core.Object) int {
			if difference := jsNumber(b.Get("createdAt")) - jsNumber(a.Get("createdAt")); difference != 0 && difference == difference {
				if difference < 0 {
					return -1
				}
				return 1
			}
			return compareUTF16(jsString(a.Get("id")), jsString(b.Get("id")))
		})
		if len(live) > int(limit) {
			live = live[:int(limit)]
		}
		result := []any{}
		for _, session := range live {
			summary, err := RoleSessionSummary(session)
			if err != nil {
				return nil, err
			}
			result = append(result, summary)
		}
		return result, nil
	}, false)
	return Out[apitypes.RolesListSessionsOutput]{Value: result}, err
}

// RevokeSessions is POST {basePath}/roles/revokeSessions. Revokes the role's sessions (classic and web identity)
// issued before `before` (default: every session so far): moves the role's `sessionsRevokedBefore` watermark forward,
// so older sessions are refused on their next use, and deletes the matching rows. Requires iam:roles:revoke-sessions
// on the role and recent authentication; it only removes access, so it is delegable. Audited as
// `role:sessions-revoked`.
func (api *RolesAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesRevokeSessionsInput]) (Out[apitypes.RolesRevokeSessionsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:roles:revoke-sessions", jsString(input.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		role, err := server.Scoped(ctx, tx, "roles", input.Get("roleId"), jsString(tenantID))
		if err != nil {
			return nil, err
		}
		sessionsRevokedBefore, err := NextWatermark(role.Get("sessionsRevokedBefore"), input.Get("before"), float64(server.Now()))
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, "roles", role.Spread(core.NewObject("sessionsRevokedBefore", sessionsRevokedBefore))); err != nil {
			return nil, err
		}
		revoked, err := DeleteTemporarySessions(ctx, tx, core.NewObject(
			"tenantId", role.Get("tenantId"), "roleId", role.Get("id"), "createdBefore", sessionsRevokedBefore,
		))
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "role:sessions-revoked", jsString(tenantID), jsString(role.Get("id")),
			"allow", false, core.NewObject("sessionsRevokedBefore", sessionsRevokedBefore, "revoked", revoked)); err != nil {
			return nil, err
		}
		return core.NewObject("roleId", role.Get("id"), "sessionsRevokedBefore", sessionsRevokedBefore, "revoked", revoked), nil
	}, false)
	return Out[apitypes.RolesRevokeSessionsOutput]{Value: result}, err
}

// Update is POST {basePath}/roles/update. Changes a role's name, description, permissions or inline document,
// attached policies, or inherited roles.
func (api *RolesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesUpdateInput]) (Out[apitypes.RolesUpdateOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:roles:update", jsString(input.Get("roleId")), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return UpdateRole(ctx, api.server, call.Tx, call.Principal, input.Body)
	}, false)
	return Out[apitypes.RolesUpdateOutput]{Value: result}, err
}

// recordValues is a record list as a model array.
func recordValues(records []*core.Object) []any {
	result := make([]any, len(records))
	for index, record := range records {
		result[index] = record
	}
	return result
}

// optionalID is a record's authority or record id as a lookup argument: the string, or "" when it is not one
// (TypeScript passes undefined then).
func optionalID(value any) string {
	text, _ := value.(string)
	return text
}

// statementList turns a canonical-statement set into the list AssertDeniesKept takes.
func statementList(set map[string]bool) []string {
	result := make([]string, 0, len(set))
	for statement := range set {
		result = append(result, statement)
	}
	return result
}

// AssertDeniesKept (api/roles.ts assertDeniesKept): An editor may add denies to a role or policy, but once another
// authority relies on it (see reliedOnByOthers), may not remove or change one: that would widen what the other
// authority's grants allow, beyond the editor's own ceiling. Root may.
func AssertDeniesKept(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, before []string, after []string, relied func(context.Context) (bool, error)) (err error) {
	kept := map[string]bool{}
	for _, statement := range after {
		kept[statement] = true
	}
	every := true
	for _, statement := range before {
		if !kept[statement] {
			every = false
			break
		}
	}
	if every {
		return nil
	}
	root, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return err
	}
	if root {
		return nil
	}
	reliedOn, err := relied(ctx)
	if err != nil {
		return err
	}
	if !reliedOn {
		return nil
	}
	return core.NewIamError("PROTECTED_RESOURCE",
		"Other administrators rely on its deny statements (they bound it, or attached or inherit it); they must detach it before a deny is removed or changed", 403)
}

// inheritance validates a role hierarchy edge set: existing, unprotected, distinct roles of the tenant that do not
// lead back to roleID (hasRole false for a new role).
func inheritance(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, roleID string, hasRole bool, value any) ([]string, error) {
	listed, err := Strings(value, "inherits")
	if err != nil {
		return nil, err
	}
	inherits := unique(listed)
	if len(inherits) > 20 {
		return nil, invalidInput("A role may inherit at most 20 roles")
	}
	for _, inheritedID := range inherits {
		if hasRole && inheritedID == roleID {
			return nil, invalidInput("A role cannot inherit itself")
		}
		inherited, err := server.Scoped(ctx, tx, "roles", inheritedID, tenantID)
		if err != nil {
			return nil, err
		}
		if truthy(inherited.Get("protected")) {
			return nil, core.NewIamError("PROTECTED_RESOURCE", "Protected roles cannot be inherited", 403)
		}
	}
	// Walk the hierarchy from the new parents; reaching this role again would close a cycle.
	if hasRole {
		queue := append([]any(nil), stringsOf(inherits)...)
		visited := map[string]bool{}
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			if core.StrictEquals(current, roleID) {
				return nil, invalidInput("Role inheritance must not form a cycle")
			}
			// Set membership by value: strings by their text, anything else (malformed data) apart from them.
			key := jsString(current)
			if _, isString := current.(string); !isString {
				key = "\x00" + typeOf(current) + ":" + key
			}
			if visited[key] {
				continue
			}
			visited[key] = true
			if len(visited) > 200 {
				return nil, invalidInput("Role hierarchy is too deep")
			}
			parent, err := tx.Get(ctx, "roles", jsString(current))
			if err != nil {
				return nil, err
			}
			if parent != nil {
				if parents, ok := parent.Get("inherits").([]any); ok {
					queue = append(queue, parents...)
				}
			}
		}
	}
	return inherits, nil
}

// roleDocument compiles a permissions list to an inline allow statement over every resource; a document is used as
// given. The result is core.Undefined (no change), nil (clear: document null) or the document.
func roleDocument(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object) (any, error) {
	permissionsValue, document := input.Get("permissions"), input.Get("document")
	if !isUndefined(permissionsValue) && !isUndefined(document) {
		return nil, invalidInput("Provide either permissions or an inline document")
	}
	if document == nil {
		return nil, nil
	}
	if !isUndefined(permissionsValue) {
		permissions, err := Strings(permissionsValue, "permissions")
		if err != nil {
			return nil, err
		}
		if len(permissions) == 0 {
			return nil, invalidInput("permissions must name at least one action")
		}
		document = core.NewObject("version", 1.0, "statements", []any{
			core.NewObject("sid", "RolePermissions", "effect", "allow", "actions", stringsOf(permissions), "resources", []any{"*"}),
		})
	}
	if !isUndefined(document) {
		if err := server.Catalog.Validate(ctx, tx, tenantID, document); err != nil {
			return nil, err
		}
	}
	return document, nil
}

// CreateRole (api/roles.ts createRole): Creates a role under the caller's grant authority; shared by `roles.create`
// and configuration sync.
func CreateRole(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	tenantID := jsString(input.Get("tenantId"))
	authority, err := server.GrantingAuthority(ctx, tx, principal, tenantID, "")
	if err != nil {
		return nil, err
	}
	if err := server.EnforceLimit(ctx, tx, tenant, "roles", func(ctx context.Context) (int, error) {
		roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
		return len(roles), err
	}); err != nil {
		return nil, err
	}
	policyIDs, err := Strings(coalesce(input.Get("policyIds"), []any{}), "policyIds")
	if err != nil {
		return nil, err
	}
	for _, policyID := range policyIDs {
		if _, err := server.Scoped(ctx, tx, "policies", policyID, tenantID); err != nil {
			return nil, err
		}
	}
	document, err := roleDocument(ctx, server, tx, tenantID, input)
	if err != nil {
		return nil, err
	}
	name, err := Text(input.Get("name"), "name")
	if err != nil {
		return nil, err
	}
	role := core.NewObject("id", ID(), "tenantId", tenantID, "name", name, "policyIds", stringsOf(policyIDs),
		"protected", false, "authorityId", authority.Get("id"))
	if value := input.Get("description"); !isUndefined(value) {
		description, err := Text(value, "description", 512)
		if err != nil {
			return nil, err
		}
		role.Set("description", description)
	}
	if truthy(document) {
		role.SetRaw("document", document)
	}
	if value := input.Get("inherits"); !isUndefined(value) {
		inherits, err := inheritance(ctx, server, tx, tenantID, "", false, value)
		if err != nil {
			return nil, err
		}
		if len(inherits) > 0 {
			role.Set("inherits", stringsOf(inherits))
		}
	}
	return tx.Insert(ctx, "roles", role)
}

// UpdateRole (api/roles.ts updateRole): Edits a role the caller's authority issued (or any role, for root);
// protected roles are refused.
func UpdateRole(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	tenantID := jsString(input.Get("tenantId"))
	if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, ""); err != nil {
		return nil, err
	}
	role, err := server.Scoped(ctx, tx, "roles", input.Get("roleId"), tenantID)
	if err != nil {
		return nil, err
	}
	if truthy(role.Get("protected")) {
		return nil, core.NewIamError("PROTECTED_RESOURCE", "Role is protected", 403)
	}
	if err := server.CanEditGrantResource(ctx, tx, principal, role); err != nil {
		return nil, err
	}
	next := role.Spread()
	if value := input.Get("policyIds"); !isUndefined(value) {
		policyIDs, err := Strings(value, "policyIds")
		if err != nil {
			return nil, err
		}
		next.Set("policyIds", stringsOf(policyIDs))
		for _, policyID := range policyIDs {
			if _, err := server.Scoped(ctx, tx, "policies", policyID, tenantID); err != nil {
				return nil, err
			}
		}
	}
	document, err := roleDocument(ctx, server, tx, tenantID, input)
	if err != nil {
		return nil, err
	}
	if document == nil {
		next.Delete("document")
	} else if truthy(document) {
		next.SetRaw("document", document)
	}
	if value := input.Get("name"); !isUndefined(value) {
		name, err := Text(value, "name")
		if err != nil {
			return nil, err
		}
		next.Set("name", name)
	}
	if value := input.Get("description"); !isUndefined(value) {
		description, err := Text(value, "description", 512)
		if err != nil {
			return nil, err
		}
		next.Set("description", description)
	}
	if value := input.Get("inherits"); !isUndefined(value) {
		inherits, err := inheritance(ctx, server, tx, tenantID, jsString(role.Get("id")), true, value)
		if err != nil {
			return nil, err
		}
		if len(inherits) > 0 {
			next.Set("inherits", stringsOf(inherits))
		} else {
			next.Delete("inherits")
		}
	}
	before, err := RoleDenyStatements(ctx, tx, role)
	if err != nil {
		return nil, err
	}
	after, err := RoleDenyStatements(ctx, tx, next)
	if err != nil {
		return nil, err
	}
	if err := AssertDeniesKept(ctx, server, tx, principal, statementList(before), statementList(after), func(ctx context.Context) (bool, error) {
		return ReliedOnByOthers(ctx, tx, jsString(role.Get("tenantId")), role.Get("authorityId"), []string{jsString(role.Get("id"))})
	}); err != nil {
		return nil, err
	}
	return tx.Put(ctx, "roles", next)
}

// inheritingRoles is the roles that inherit from the given role, directly.
func inheritingRoles(ctx context.Context, tx core.IamStore, role *core.Object) ([]*core.Object, error) {
	roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", role.Get("tenantId")), nil)
	if err != nil {
		return nil, err
	}
	var result []*core.Object
	for _, other := range roles {
		if inherits, ok := other.Get("inherits").([]any); ok && includesValue(inherits, role.Get("id")) {
			result = append(result, other)
		}
	}
	return result, nil
}

// includesValue is Array#includes over model values (records by identity).
func includesValue(items []any, value any) bool {
	for _, item := range items {
		if core.StrictEquals(item, value) {
			return true
		}
	}
	return false
}

// joinNames is `records.map((record) => record.name).join(', ')`.
func joinNames(records []*core.Object) string {
	names := make([]string, len(records))
	for index, record := range records {
		if name := record.Get("name"); !nullish(name) {
			names[index] = jsString(name)
		}
	}
	return strings.Join(names, ", ")
}

// DeleteRole (api/roles.ts deleteRole): Deletes a role with its bindings and activations; protected roles are
// refused.
func DeleteRole(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, role *core.Object) (err error) {
	if truthy(role.Get("protected")) {
		return core.NewIamError("PROTECTED_RESOURCE", "Role is protected", 403)
	}
	if err := server.CanEditGrantResource(ctx, tx, principal, role); err != nil {
		return err
	}
	children, err := inheritingRoles(ctx, tx, role)
	if err != nil {
		return err
	}
	if len(children) > 0 {
		return core.NewIamError("RESOURCE_IN_USE", "Roles still inherit it: "+joinNames(children), 409)
	}
	packages, err := tx.Find(ctx, "accessPackages", core.NewObject("tenantId", role.Get("tenantId")), nil)
	if err != nil {
		return err
	}
	var packaged []*core.Object
	for _, pkg := range packages {
		if roleIDs, ok := pkg.Get("roleIds").([]any); ok && includesValue(roleIDs, role.Get("id")) {
			packaged = append(packaged, pkg)
		}
	}
	if len(packaged) > 0 {
		return core.NewIamError("RESOURCE_IN_USE", "Access packages still include it: "+joinNames(packaged), 409)
	}
	// Deleting a role deletes its bindings; one another administrator bound carries its denies for them.
	before, err := RoleDenyStatements(ctx, tx, role)
	if err != nil {
		return err
	}
	if err := AssertDeniesKept(ctx, server, tx, principal, statementList(before), nil, func(ctx context.Context) (bool, error) {
		return ReliedOnByOthers(ctx, tx, jsString(role.Get("tenantId")), role.Get("authorityId"), []string{jsString(role.Get("id"))})
	}); err != nil {
		return err
	}
	bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", role.Get("tenantId"), "roleId", role.Get("id")), nil)
	if err != nil {
		return err
	}
	for _, binding := range bindings {
		if err := tx.Delete(ctx, "bindings", jsString(binding.Get("id"))); err != nil {
			return err
		}
	}
	activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", role.Get("tenantId"), "roleId", role.Get("id")), nil)
	if err != nil {
		return err
	}
	for _, activation := range activations {
		if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
			return err
		}
	}
	return tx.Delete(ctx, "roles", jsString(role.Get("id")))
}

// ReliedOnByOthers (api/roles.ts reliedOnByOthers): Whether an authority other than `authorityId` relies on these
// roles: it issued one of them or a role inheriting one of them, or bound one of those roles to someone. Their
// denies then restrict what that authority granted.
func ReliedOnByOthers(ctx context.Context, tx core.IamStore, tenantID string, authorityID any, roleIDs []string) (result bool, err error) {
	roles, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return false, err
	}
	covered := newOrderedSet(roleIDs...)
	for grew := true; grew; {
		grew = false
		for _, role := range roles {
			id, isString := role.Get("id").(string)
			if !isString || covered.Has(id) {
				continue
			}
			inherits, _ := role.Get("inherits").([]any)
			for _, inherited := range inherits {
				if name, ok := inherited.(string); ok && covered.Has(name) {
					covered.Add(id)
					grew = true
					break
				}
			}
		}
	}
	for _, role := range roles {
		if id, ok := role.Get("id").(string); ok && covered.Has(id) && !core.StrictEquals(role.Get("authorityId"), authorityID) {
			return true, nil
		}
	}
	for _, roleID := range covered.Values() {
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "roleId", roleID), nil)
		if err != nil {
			return false, err
		}
		for _, binding := range bindings {
			if !core.StrictEquals(binding.Get("authorityId"), authorityID) {
				return true, nil
			}
		}
	}
	return false, nil
}
