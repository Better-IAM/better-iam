package server

// Skeleton of packages/server/src/api/tenants.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// TenantsAPI is the `tenants` API group (packages/server/src/api/tenants.ts createTenantsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/tenants/{method} onto it.
type TenantsAPI struct {
	server *ServerContext
}

// CreateTenantsAPI builds the `tenants` API group.
func CreateTenantsAPI(server *ServerContext) *TenantsAPI {
	return &TenantsAPI{server: server}
}

// AcceptInvitation is POST {basePath}/tenants/acceptInvitation (public: no request credential). Redeems an owner invitation: creates the first owner of a pending tenant, activates the tenant, and signs the owner in.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) AcceptInvitation(ctx context.Context, input In[apitypes.TenantsAcceptInvitationInput]) (Out[apitypes.TenantsAcceptInvitationOutput], error) {
	return Out[apitypes.TenantsAcceptInvitationOutput]{}, notImplemented("tenants.acceptInvitation")
}

// Create is POST {basePath}/tenants/create. Creates a child tenant in the pending state under a parent and emails an invitation to its first owner.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsCreateInput]) (Out[apitypes.TenantsCreateOutput], error) {
	return Out[apitypes.TenantsCreateOutput]{}, notImplemented("tenants.create")
}

// Get is POST {basePath}/tenants/get. Returns a tenant with its status, parent, alias, policies, limits, and boundary.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsGetInput]) (Out[apitypes.TenantsGetOutput], error) {
	return Out[apitypes.TenantsGetOutput]{}, notImplemented("tenants.get")
}

// ListChildren is POST {basePath}/tenants/listChildren. Lists the direct children of a tenant, whatever their status.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) ListChildren(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsListChildrenInput]) (Out[apitypes.TenantsListChildrenOutput], error) {
	return Out[apitypes.TenantsListChildrenOutput]{}, notImplemented("tenants.listChildren")
}

// ListInvitations is POST {basePath}/tenants/listInvitations. Lists a tenant's owner invitations without their tokens.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) ListInvitations(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsListInvitationsInput]) (Out[apitypes.TenantsListInvitationsOutput], error) {
	return Out[apitypes.TenantsListInvitationsOutput]{}, notImplemented("tenants.listInvitations")
}

// Lookup is POST {basePath}/tenants/lookup (public: no request credential). Resolves a tenant's public alias, or an address it signs in at, to its ID, name, and type, so a sign-in page can ask for an organization name instead of a tenant ID.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) Lookup(ctx context.Context, input In[apitypes.TenantsLookupInput]) (Out[apitypes.TenantsLookupOutput], error) {
	return Out[apitypes.TenantsLookupOutput]{}, notImplemented("tenants.lookup")
}

// Reparent is POST {basePath}/tenants/reparent. Moves a tenant, with its whole subtree, under a different parent.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) Reparent(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsReparentInput]) (Out[apitypes.TenantsReparentOutput], error) {
	return Out[apitypes.TenantsReparentOutput]{}, notImplemented("tenants.reparent")
}

// ResendInvitation is POST {basePath}/tenants/resendInvitation. Sends an owner invitation again with a new token and a fresh lifetime; the earlier link stops working.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) ResendInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsResendInvitationInput]) (Out[apitypes.TenantsResendInvitationOutput], error) {
	return Out[apitypes.TenantsResendInvitationOutput]{}, notImplemented("tenants.resendInvitation")
}

// RevokeInvitation is POST {basePath}/tenants/revokeInvitation. Cancels an owner invitation so its link can no longer be used.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) RevokeInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsRevokeInvitationInput]) (Out[apitypes.TenantsRevokeInvitationOutput], error) {
	return Out[apitypes.TenantsRevokeInvitationOutput]{}, notImplemented("tenants.revokeInvitation")
}

// RevokeSessions is POST {basePath}/tenants/revokeSessions. Signs everyone out of a tenant at once, keeping your own session unless you pass includeSelf.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsRevokeSessionsInput]) (Out[apitypes.TenantsRevokeSessionsOutput], error) {
	return Out[apitypes.TenantsRevokeSessionsOutput]{}, notImplemented("tenants.revokeSessions")
}

// SetAccessPolicy is POST {basePath}/tenants/setAccessPolicy. Sets organization-wide floors for just-in-time activation that every eligible binding in the tenant must meet.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) SetAccessPolicy(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetAccessPolicyInput]) (Out[apitypes.TenantsSetAccessPolicyOutput], error) {
	return Out[apitypes.TenantsSetAccessPolicyOutput]{}, notImplemented("tenants.setAccessPolicy")
}

// SetAuthPolicy is POST {basePath}/tenants/setAuthPolicy. Sets the tenant's authentication policy: MFA, allowed sign-in methods, session lifetimes, password rules, network restrictions, and impersonation.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) SetAuthPolicy(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetAuthPolicyInput]) (Out[apitypes.TenantsSetAuthPolicyOutput], error) {
	return Out[apitypes.TenantsSetAuthPolicyOutput]{}, notImplemented("tenants.setAuthPolicy")
}

// SetBoundary is POST {basePath}/tenants/setBoundary. Sets a root-controlled permissions boundary on a tenant, capping what anyone in it or in any tenant below it may do.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) SetBoundary(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetBoundaryInput]) (Out[apitypes.TenantsSetBoundaryOutput], error) {
	return Out[apitypes.TenantsSetBoundaryOutput]{}, notImplemented("tenants.setBoundary")
}

// SetLimits is POST {basePath}/tenants/setLimits. Sets the tenant's plan limits, root only: how many people, service accounts, groups, roles, policies, registered resources, and webhooks it may hold.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) SetLimits(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetLimitsInput]) (Out[apitypes.TenantsSetLimitsOutput], error) {
	return Out[apitypes.TenantsSetLimitsOutput]{}, notImplemented("tenants.setLimits")
}

// SetRegion is POST {basePath}/tenants/setRegion. Moves a tenant's home region in a multi-region deployment, root only, so its sign-in is served by that region from then on.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) SetRegion(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetRegionInput]) (Out[apitypes.TenantsSetRegionOutput], error) {
	return Out[apitypes.TenantsSetRegionOutput]{}, notImplemented("tenants.setRegion")
}

// SetSlug is POST {basePath}/tenants/setSlug. Sets, changes, or removes the tenant's public sign-in alias.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) SetSlug(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetSlugInput]) (Out[apitypes.TenantsSetSlugOutput], error) {
	return Out[apitypes.TenantsSetSlugOutput]{}, notImplemented("tenants.setSlug")
}

// SetStatus is POST {basePath}/tenants/setStatus. Suspends, reactivates, or deletes a tenant together with its whole subtree.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) SetStatus(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsSetStatusInput]) (Out[apitypes.TenantsSetStatusOutput], error) {
	return Out[apitypes.TenantsSetStatusOutput]{}, notImplemented("tenants.setStatus")
}

// Update is POST {basePath}/tenants/update. Renames a tenant.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsUpdateInput]) (Out[apitypes.TenantsUpdateOutput], error) {
	return Out[apitypes.TenantsUpdateOutput]{}, notImplemented("tenants.update")
}

// Usage is POST {basePath}/tenants/usage. Returns the tenant's current record counts next to its plan limits, for plan pages and metering.
//
// STUB: returns NOT_IMPLEMENTED until api/tenants.ts is ported.
func (api *TenantsAPI) Usage(ctx context.Context, credential core.CredentialInput, input In[apitypes.TenantsUsageInput]) (Out[apitypes.TenantsUsageOutput], error) {
	return Out[apitypes.TenantsUsageOutput]{}, notImplemented("tenants.usage")
}
