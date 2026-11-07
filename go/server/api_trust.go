package server

// Skeleton of packages/server/src/api/trust.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// TrustAPI is the `trust` API group (packages/server/src/api/trust.ts createTrustApi): every method runs through the
// operation envelope; the router maps POST {basePath}/trust/{method} onto it.
type TrustAPI struct {
	server *ServerContext
}

// CreateTrustAPI builds the `trust` API group.
func CreateTrustAPI(server *ServerContext) *TrustAPI {
	return &TrustAPI{server: server}
}

// Create is POST {basePath}/trust/create. Creates a trust that lets one source identity assume one role of this tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *TrustAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustCreateInput]) (Out[apitypes.TrustCreateOutput], error) {
	return Out[apitypes.TrustCreateOutput]{}, notImplemented("trust.create")
}

// EvaluateWebIdentity is POST {basePath}/trust/evaluateWebIdentity. Checks what a web-identity trust would conclude about an external token, without issuing anything.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *TrustAPI) EvaluateWebIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustEvaluateWebIdentityInput]) (Out[apitypes.TrustEvaluateWebIdentityOutput], error) {
	return Out[apitypes.TrustEvaluateWebIdentityOutput]{}, notImplemented("trust.evaluateWebIdentity")
}

// List is POST {basePath}/trust/list. Lists the trusts that target this tenant's roles.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *TrustAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustListInput]) (Out[apitypes.TrustListOutput], error) {
	return Out[apitypes.TrustListOutput]{}, notImplemented("trust.list")
}

// Revoke is POST {basePath}/trust/revoke. Revokes a trust so its source can no longer assume the role, and ends the role sessions already issued under it.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *TrustAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustRevokeInput]) (Out[apitypes.TrustRevokeOutput], error) {
	return Out[apitypes.TrustRevokeOutput]{}, notImplemented("trust.revoke")
}

// RevokeSessions is POST {basePath}/trust/revokeSessions. Ends the role sessions issued under one trust before a point in time, without revoking the trust.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *TrustAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustRevokeSessionsInput]) (Out[apitypes.TrustRevokeSessionsOutput], error) {
	return Out[apitypes.TrustRevokeSessionsOutput]{}, notImplemented("trust.revokeSessions")
}

// Update is POST {basePath}/trust/update. Changes a trust's safeguards and options, such as its MFA requirement, ceiling, session length, attribute passing, tag keys, source identity mode, or a web-identity trust's conditions and claim mappi…
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *TrustAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustUpdateInput]) (Out[apitypes.TrustUpdateOutput], error) {
	return Out[apitypes.TrustUpdateOutput]{}, notImplemented("trust.update")
}

// LinksAPI is the `links` API group (packages/server/src/api/trust.ts createLinksApi): every method runs through the
// operation envelope; the router maps POST {basePath}/links/{method} onto it.
type LinksAPI struct {
	server *ServerContext
}

// CreateLinksAPI builds the `links` API group.
func CreateLinksAPI(server *ServerContext) *LinksAPI {
	return &LinksAPI{server: server}
}

// Create is POST {basePath}/links/create. Links the caller's account to another account of theirs in a different tenant, proving control of both.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *LinksAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.LinksCreateInput]) (Out[apitypes.LinksCreateOutput], error) {
	return Out[apitypes.LinksCreateOutput]{}, notImplemented("links.create")
}

// List is POST {basePath}/links/list. Lists the accounts linked to the caller's account, for an account-switcher menu.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *LinksAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.LinksListInput]) (Out[apitypes.LinksListOutput], error) {
	return Out[apitypes.LinksListOutput]{}, notImplemented("links.list")
}

// Revoke is POST {basePath}/links/revoke. Removes a link the person no longer wants.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *LinksAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.LinksRevokeInput]) (Out[apitypes.LinksRevokeOutput], error) {
	return Out[apitypes.LinksRevokeOutput]{}, notImplemented("links.revoke")
}

// Switch is POST {basePath}/links/switch. Opens a fresh session for a linked account, using a recently authenticated credential for that account.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *LinksAPI) Switch(ctx context.Context, credential core.CredentialInput, input In[apitypes.LinksSwitchInput]) (Out[apitypes.LinksSwitchOutput], error) {
	return Out[apitypes.LinksSwitchOutput]{}, notImplemented("links.switch")
}

// RootAPI is the `root` API group (packages/server/src/api/trust.ts createRootApi): every method runs through the
// operation envelope; the router maps POST {basePath}/root/{method} onto it.
type RootAPI struct {
	server *ServerContext
}

// CreateRootAPI builds the `root` API group.
func CreateRootAPI(server *ServerContext) *RootAPI {
	return &RootAPI{server: server}
}

// ListAdministrators is POST {basePath}/root/listAdministrators. Lists the identities that hold the root capability.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *RootAPI) ListAdministrators(ctx context.Context, credential core.CredentialInput, input In[apitypes.RootListAdministratorsInput]) (Out[apitypes.RootListAdministratorsOutput], error) {
	return Out[apitypes.RootListAdministratorsOutput]{}, notImplemented("root.listAdministrators")
}

// SetAdministrator is POST {basePath}/root/setAdministrator. Grants the root capability to a person in the root tenant, or removes it.
//
// STUB: returns NOT_IMPLEMENTED until api/trust.ts is ported.
func (api *RootAPI) SetAdministrator(ctx context.Context, credential core.CredentialInput, input In[apitypes.RootSetAdministratorInput]) (Out[apitypes.RootSetAdministratorOutput], error) {
	return Out[apitypes.RootSetAdministratorOutput]{}, notImplemented("root.setAdministrator")
}
