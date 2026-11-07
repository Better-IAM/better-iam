package server

// Skeleton of packages/server/src/api/roles.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

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

// Assume is POST {basePath}/roles/assume. Exchanges your session for a short-lived role session in a target tenant, through a trust the platform root created.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) Assume(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesAssumeInput]) (Out[apitypes.RolesAssumeOutput], error) {
	return Out[apitypes.RolesAssumeOutput]{}, notImplemented("roles.assume")
}

// Create is POST {basePath}/roles/create. Creates a role from a permissions list, an inline policy document, attached policies, inherited roles, or a mix of them.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesCreateInput]) (Out[apitypes.RolesCreateOutput], error) {
	return Out[apitypes.RolesCreateOutput]{}, notImplemented("roles.create")
}

// Delete is POST {basePath}/roles/delete. Deletes a role together with its bindings and their activations.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesDeleteInput]) (Out[apitypes.RolesDeleteOutput], error) {
	return Out[apitypes.RolesDeleteOutput]{}, notImplemented("roles.delete")
}

// Get is POST {basePath}/roles/get. Returns one role by id, with its attached policies, inline document, and inherited roles.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesGetInput]) (Out[apitypes.RolesGetOutput], error) {
	return Out[apitypes.RolesGetOutput]{}, notImplemented("roles.get")
}

// List is POST {basePath}/roles/list. Lists every role in the tenant, including the protected Owner role.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesListInput]) (Out[apitypes.RolesListOutput], error) {
	return Out[apitypes.RolesListOutput]{}, notImplemented("roles.list")
}

// ListBindings is POST {basePath}/roles/listBindings. Lists who holds a role: its bindings, each with a summary of the person, service account, or group it names.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) ListBindings(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesListBindingsInput]) (Out[apitypes.RolesListBindingsOutput], error) {
	return Out[apitypes.RolesListBindingsOutput]{}, notImplemented("roles.listBindings")
}

// ListSessions is POST {basePath}/roles/listSessions. Lists the live role sessions in the tenant, of one role or trust when given, newest first.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) ListSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesListSessionsInput]) (Out[apitypes.RolesListSessionsOutput], error) {
	return Out[apitypes.RolesListSessionsOutput]{}, notImplemented("roles.listSessions")
}

// RevokeSessions is POST {basePath}/roles/revokeSessions. Ends every role session of a role issued before a point in time, whichever trust or provider issued it.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesRevokeSessionsInput]) (Out[apitypes.RolesRevokeSessionsOutput], error) {
	return Out[apitypes.RolesRevokeSessionsOutput]{}, notImplemented("roles.revokeSessions")
}

// Update is POST {basePath}/roles/update. Changes a role's name, description, permissions or inline document, attached policies, or inherited roles.
//
// STUB: returns NOT_IMPLEMENTED until api/roles.ts is ported.
func (api *RolesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.RolesUpdateInput]) (Out[apitypes.RolesUpdateOutput], error) {
	return Out[apitypes.RolesUpdateOutput]{}, notImplemented("roles.update")
}

// AssertDeniesKept (api/roles.ts assertDeniesKept): An editor may add denies to a role or policy, but once another
// authority relies on it (see reliedOnByOthers), may not remove or change one: that would widen what the other
// authority's grants allow, beyond the editor's own ceiling. Root may.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertDeniesKept(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, before []string, after []string, relied func(context.Context) (bool, error)) (err error) {
	err = notImplemented("api/roles.ts assertDeniesKept")
	return
}

// CreateRole (api/roles.ts createRole): Creates a role under the caller's grant authority; shared by `roles.create`
// and configuration sync.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateRole(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/roles.ts createRole")
	return
}

// DeleteRole (api/roles.ts deleteRole): Deletes a role with its bindings and activations; protected roles are
// refused.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeleteRole(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, role *core.Object) (err error) {
	err = notImplemented("api/roles.ts deleteRole")
	return
}

// ReliedOnByOthers (api/roles.ts reliedOnByOthers): Whether an authority other than `authorityId` relies on these
// roles: it issued one of them or a role inheriting one of them, or bound one of those roles to someone. Their
// denies then restrict what that authority granted.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReliedOnByOthers(ctx context.Context, tx core.IamStore, tenantID string, authorityID any, roleIDs []string) (result bool, err error) {
	err = notImplemented("api/roles.ts reliedOnByOthers")
	return
}

// UpdateRole (api/roles.ts updateRole): Edits a role the caller's authority issued (or any role, for root);
// protected roles are refused.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UpdateRole(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/roles.ts updateRole")
	return
}
