package server

// Skeleton of packages/server/src/api/bindings.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// BindingsAPI is the `bindings` API group (packages/server/src/api/bindings.ts createBindingsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/bindings/{method} onto it.
type BindingsAPI struct {
	server *ServerContext
}

// CreateBindingsAPI builds the `bindings` API group.
func CreateBindingsAPI(server *ServerContext) *BindingsAPI {
	return &BindingsAPI{server: server}
}

// Activate is POST {basePath}/bindings/activate. Activates an eligible binding for yourself so you hold its role for a limited time, or records an approval request when the binding requires one.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) Activate(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsActivateInput]) (Out[apitypes.BindingsActivateOutput], error) {
	return Out[apitypes.BindingsActivateOutput]{}, notImplemented("bindings.activate")
}

// ApproveActivation is POST {basePath}/bindings/approveActivation. Grants a pending activation request, so the requester holds the role from now until the approved duration ends.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) ApproveActivation(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsApproveActivationInput]) (Out[apitypes.BindingsApproveActivationOutput], error) {
	return Out[apitypes.BindingsApproveActivationOutput]{}, notImplemented("bindings.approveActivation")
}

// Create is POST {basePath}/bindings/create. Gives a role to a person, service account, or group under your grant authority, optionally temporary, future-dated, limited to a recurring window, or eligible for just-in-time activation.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsCreateInput]) (Out[apitypes.BindingsCreateOutput], error) {
	return Out[apitypes.BindingsCreateOutput]{}, notImplemented("bindings.create")
}

// Deactivate is POST {basePath}/bindings/deactivate. Ends your own activation early, or withdraws your own pending request.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) Deactivate(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsDeactivateInput]) (Out[apitypes.BindingsDeactivateOutput], error) {
	return Out[apitypes.BindingsDeactivateOutput]{}, notImplemented("bindings.deactivate")
}

// Delete is POST {basePath}/bindings/delete. Removes a binding and every activation of it, so its subject stops holding the role at the next request.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsDeleteInput]) (Out[apitypes.BindingsDeleteOutput], error) {
	return Out[apitypes.BindingsDeleteOutput]{}, notImplemented("bindings.delete")
}

// DenyActivation is POST {basePath}/bindings/denyActivation. Refuses a pending activation request, optionally with a note for the requester.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) DenyActivation(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsDenyActivationInput]) (Out[apitypes.BindingsDenyActivationOutput], error) {
	return Out[apitypes.BindingsDenyActivationOutput]{}, notImplemented("bindings.denyActivation")
}

// List is POST {basePath}/bindings/list. Lists the tenant's bindings, filtered by role, subject, eligibility, or upcoming expiry.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsListInput]) (Out[apitypes.BindingsListOutput], error) {
	return Out[apitypes.BindingsListOutput]{}, notImplemented("bindings.list")
}

// ListActivations is POST {basePath}/bindings/listActivations. Lists activations and activation requests, newest first, filtered by binding, person, role, or status.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) ListActivations(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsListActivationsInput]) (Out[apitypes.BindingsListActivationsOutput], error) {
	return Out[apitypes.BindingsListActivationsOutput]{}, notImplemented("bindings.listActivations")
}

// ListApprovals is POST {basePath}/bindings/listApprovals. Lists the pending activation requests you may decide on, oldest first, with the role and the requester.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) ListApprovals(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsListApprovalsInput]) (Out[apitypes.BindingsListApprovalsOutput], error) {
	return Out[apitypes.BindingsListApprovalsOutput]{}, notImplemented("bindings.listApprovals")
}

// ListMine is POST {basePath}/bindings/listMine. Lists your own bindings, direct and through groups, with any live activation or waiting request, so you can see what you may elevate to.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsListMineInput]) (Out[apitypes.BindingsListMineOutput], error) {
	return Out[apitypes.BindingsListMineOutput]{}, notImplemented("bindings.listMine")
}

// RevokeActivation is POST {basePath}/bindings/revokeActivation. Ends someone else's activation or pending request immediately, for incident response.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) RevokeActivation(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsRevokeActivationInput]) (Out[apitypes.BindingsRevokeActivationOutput], error) {
	return Out[apitypes.BindingsRevokeActivationOutput]{}, notImplemented("bindings.revokeActivation")
}

// Update is POST {basePath}/bindings/update. Changes a binding's start, expiry, access window, or eligibility settings in place.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *BindingsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.BindingsUpdateInput]) (Out[apitypes.BindingsUpdateOutput], error) {
	return Out[apitypes.BindingsUpdateOutput]{}, notImplemented("bindings.update")
}

// AuthoritiesAPI is the `authorities` API group (packages/server/src/api/bindings.ts createAuthoritiesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/authorities/{method} onto it.
type AuthoritiesAPI struct {
	server *ServerContext
}

// CreateAuthoritiesAPI builds the `authorities` API group.
func CreateAuthoritiesAPI(server *ServerContext) *AuthoritiesAPI {
	return &AuthoritiesAPI{server: server}
}

// Create is POST {basePath}/authorities/create. Delegates a new grant authority to an identity, bounded by a ceiling and by your own authority chain.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *AuthoritiesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthoritiesCreateInput]) (Out[apitypes.AuthoritiesCreateOutput], error) {
	return Out[apitypes.AuthoritiesCreateOutput]{}, notImplemented("authorities.create")
}

// Revoke is POST {basePath}/authorities/revoke. Withdraws a grant authority, so everything issued under it, and under authorities delegated from it, stops granting at the next request.
//
// STUB: returns NOT_IMPLEMENTED until api/bindings.ts is ported.
func (api *AuthoritiesAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.AuthoritiesRevokeInput]) (Out[apitypes.AuthoritiesRevokeOutput], error) {
	return Out[apitypes.AuthoritiesRevokeOutput]{}, notImplemented("authorities.revoke")
}

// CreateBinding (api/bindings.ts createBinding): Creates a binding under the caller's grant authority; shared by
// `bindings.create`, invitations, access packages, and configuration sync. A package assignment's bindings carry
// `packageAssignmentId` and a key of their own, so they never collide with, replace, or depend on a binding someone
// granted by hand.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreateBinding(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/bindings.ts createBinding")
	return
}

// DeleteBinding (api/bindings.ts deleteBinding): A binding may be removed by the administrator whose authority
// issued it, or by root.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeleteBinding(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, binding *core.Object) (err error) {
	err = notImplemented("api/bindings.ts deleteBinding")
	return
}
