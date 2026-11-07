package server

// Skeleton of packages/server/src/api/identities.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// IdentitiesAPI is the `identities` API group (packages/server/src/api/identities.ts createIdentitiesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/identities/{method} onto it.
type IdentitiesAPI struct {
	server *ServerContext
}

// CreateIdentitiesAPI builds the `identities` API group.
func CreateIdentitiesAPI(server *ServerContext) *IdentitiesAPI {
	return &IdentitiesAPI{server: server}
}

// AcceptInvitation is POST {basePath}/identities/acceptInvitation (public: no request credential). Redeems a member invitation: creates the person's account with the invited email, applies the invitation's roles and groups, and signs them in.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) AcceptInvitation(ctx context.Context, input In[apitypes.IdentitiesAcceptInvitationInput]) (Out[apitypes.IdentitiesAcceptInvitationOutput], error) {
	return Out[apitypes.IdentitiesAcceptInvitationOutput]{}, notImplemented("identities.acceptInvitation")
}

// Create is POST {basePath}/identities/create. Creates a person in the tenant, optionally with a password, a manager, and a scheduled deactivation date.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesCreateInput]) (Out[apitypes.IdentitiesCreateOutput], error) {
	return Out[apitypes.IdentitiesCreateOutput]{}, notImplemented("identities.create")
}

// CreateMany is POST {basePath}/identities/createMany. Creates up to 100 people in one transaction, each with optional attributes, roles, groups, password, and expiry.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) CreateMany(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesCreateManyInput]) (Out[apitypes.IdentitiesCreateManyOutput], error) {
	return Out[apitypes.IdentitiesCreateManyOutput]{}, notImplemented("identities.createMany")
}

// Delete is POST {basePath}/identities/delete. Removes a person or service account for good, leaving a tombstone so audit records still name who acted.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesDeleteInput]) (Out[apitypes.IdentitiesDeleteOutput], error) {
	return Out[apitypes.IdentitiesDeleteOutput]{}, notImplemented("identities.delete")
}

// Export is POST {basePath}/identities/export. Returns everything the tenant stores about one identity as JSON, to answer a data-subject access request.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Export(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesExportInput]) (Out[apitypes.IdentitiesExportOutput], error) {
	return Out[apitypes.IdentitiesExportOutput]{}, notImplemented("identities.export")
}

// Get is POST {basePath}/identities/get. Returns one identity by ID, including the tombstone of a deleted identity.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesGetInput]) (Out[apitypes.IdentitiesGetOutput], error) {
	return Out[apitypes.IdentitiesGetOutput]{}, notImplemented("identities.get")
}

// Impersonate is POST {basePath}/identities/impersonate. Opens a short-lived "view as" session as a member, for support and troubleshooting, and returns its token.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Impersonate(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesImpersonateInput]) (Out[apitypes.IdentitiesImpersonateOutput], error) {
	return Out[apitypes.IdentitiesImpersonateOutput]{}, notImplemented("identities.impersonate")
}

// Invite is POST {basePath}/identities/invite. Invites a person to the tenant by email, with roles and groups they receive when they accept.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Invite(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesInviteInput]) (Out[apitypes.IdentitiesInviteOutput], error) {
	return Out[apitypes.IdentitiesInviteOutput]{}, notImplemented("identities.invite")
}

// LinkProvider is POST {basePath}/identities/linkProvider. Links an external sign-in (OAuth/OIDC or SAML) to an existing account, so that IdP account signs in to it without an account-linking step.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) LinkProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesLinkProviderInput]) (Out[apitypes.IdentitiesLinkProviderOutput], error) {
	return Out[apitypes.IdentitiesLinkProviderOutput]{}, notImplemented("identities.linkProvider")
}

// List is POST {basePath}/identities/list. Lists the tenant's people and service accounts, with filters and paging.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListInput]) (Out[apitypes.IdentitiesListOutput], error) {
	return Out[apitypes.IdentitiesListOutput]{}, notImplemented("identities.list")
}

// ListBindings is POST {basePath}/identities/listBindings. Lists an identity's role bindings, direct and through its groups, with their activation and window state.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) ListBindings(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListBindingsInput]) (Out[apitypes.IdentitiesListBindingsOutput], error) {
	return Out[apitypes.IdentitiesListBindingsOutput]{}, notImplemented("identities.listBindings")
}

// ListGroups is POST {basePath}/identities/listGroups. Lists the groups an identity currently belongs to, with membershipExpiresAt on temporary memberships.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) ListGroups(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListGroupsInput]) (Out[apitypes.IdentitiesListGroupsOutput], error) {
	return Out[apitypes.IdentitiesListGroupsOutput]{}, notImplemented("identities.listGroups")
}

// ListInvitations is POST {basePath}/identities/listInvitations. Lists every member invitation of the tenant, pending or not, without tokens.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) ListInvitations(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListInvitationsInput]) (Out[apitypes.IdentitiesListInvitationsOutput], error) {
	return Out[apitypes.IdentitiesListInvitationsOutput]{}, notImplemented("identities.listInvitations")
}

// ListProviders is POST {basePath}/identities/listProviders. Lists the external sign-ins linked to an account, sorted by provider.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) ListProviders(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListProvidersInput]) (Out[apitypes.IdentitiesListProvidersOutput], error) {
	return Out[apitypes.IdentitiesListProvidersOutput]{}, notImplemented("identities.listProviders")
}

// ListReports is POST {basePath}/identities/listReports. Lists the active people whose manager is this identity, by name.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) ListReports(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListReportsInput]) (Out[apitypes.IdentitiesListReportsOutput], error) {
	return Out[apitypes.IdentitiesListReportsOutput]{}, notImplemented("identities.listReports")
}

// ListSessions is POST {basePath}/identities/listSessions. Lists an identity's unexpired sessions and API keys, most recently used first, without token hashes.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) ListSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesListSessionsInput]) (Out[apitypes.IdentitiesListSessionsOutput], error) {
	return Out[apitypes.IdentitiesListSessionsOutput]{}, notImplemented("identities.listSessions")
}

// Offboard is POST {basePath}/identities/offboard. Disables an identity and removes everything that gave it access in one transaction, handing what it owned to a successor.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Offboard(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesOffboardInput]) (Out[apitypes.IdentitiesOffboardOutput], error) {
	return Out[apitypes.IdentitiesOffboardOutput]{}, notImplemented("identities.offboard")
}

// RequestPasswordReset is POST {basePath}/identities/requestPasswordReset. Emails a member a password-reset link on an administrator's behalf.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) RequestPasswordReset(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesRequestPasswordResetInput]) (Out[apitypes.IdentitiesRequestPasswordResetOutput], error) {
	return Out[apitypes.IdentitiesRequestPasswordResetOutput]{}, notImplemented("identities.requestPasswordReset")
}

// ResendInvitation is POST {basePath}/identities/resendInvitation. Sends a member invitation again with a new token and a fresh lifetime; the earlier link stops working.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) ResendInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesResendInvitationInput]) (Out[apitypes.IdentitiesResendInvitationOutput], error) {
	return Out[apitypes.IdentitiesResendInvitationOutput]{}, notImplemented("identities.resendInvitation")
}

// RevokeInvitation is POST {basePath}/identities/revokeInvitation. Cancels a member invitation so its link can no longer be used.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) RevokeInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesRevokeInvitationInput]) (Out[apitypes.IdentitiesRevokeInvitationOutput], error) {
	return Out[apitypes.IdentitiesRevokeInvitationOutput]{}, notImplemented("identities.revokeInvitation")
}

// RevokeSessions is POST {basePath}/identities/revokeSessions. Ends every session and API key of an identity without disabling it.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesRevokeSessionsInput]) (Out[apitypes.IdentitiesRevokeSessionsOutput], error) {
	return Out[apitypes.IdentitiesRevokeSessionsOutput]{}, notImplemented("identities.revokeSessions")
}

// SetBoundary is POST {basePath}/identities/setBoundary. Sets a root-controlled permissions boundary on one identity, capping what it may do in the tenant whatever its roles grant.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) SetBoundary(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesSetBoundaryInput]) (Out[apitypes.IdentitiesSetBoundaryOutput], error) {
	return Out[apitypes.IdentitiesSetBoundaryOutput]{}, notImplemented("identities.setBoundary")
}

// SetOwner is POST {basePath}/identities/setOwner. Makes a member an owner of the tenant, or removes their ownership.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) SetOwner(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesSetOwnerInput]) (Out[apitypes.IdentitiesSetOwnerOutput], error) {
	return Out[apitypes.IdentitiesSetOwnerOutput]{}, notImplemented("identities.setOwner")
}

// SetStatus is POST {basePath}/identities/setStatus. Disables an identity or re-enables it.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) SetStatus(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesSetStatusInput]) (Out[apitypes.IdentitiesSetStatusOutput], error) {
	return Out[apitypes.IdentitiesSetStatusOutput]{}, notImplemented("identities.setStatus")
}

// UnlinkProvider is POST {basePath}/identities/unlinkProvider. Removes a linked external sign-in; that IdP account no longer signs in to this account.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) UnlinkProvider(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesUnlinkProviderInput]) (Out[apitypes.IdentitiesUnlinkProviderOutput], error) {
	return Out[apitypes.IdentitiesUnlinkProviderOutput]{}, notImplemented("identities.unlinkProvider")
}

// Unlock is POST {basePath}/identities/unlock. Clears the rate-limit counters that lock a person out of sign-in, recovery, and MFA after too many attempts.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Unlock(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesUnlockInput]) (Out[apitypes.IdentitiesUnlockOutput], error) {
	return Out[apitypes.IdentitiesUnlockOutput]{}, notImplemented("identities.unlock")
}

// Update is POST {basePath}/identities/update. Changes an identity's name, declared attributes, email, manager, or scheduled deactivation.
//
// STUB: returns NOT_IMPLEMENTED until api/identities.ts is ported.
func (api *IdentitiesAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.IdentitiesUpdateInput]) (Out[apitypes.IdentitiesUpdateOutput], error) {
	return Out[apitypes.IdentitiesUpdateOutput]{}, notImplemented("identities.update")
}

// AssertOwnerControl (api/identities.ts assertOwnerControl): Deleting, disabling, or scheduling the deactivation of
// an owner removes an owner as surely as `setOwner(false)` or `offboard` does, so it needs the same caller: an owner
// of the tenant in person or a root principal, never iam:identities:update or iam:identities:delete alone. The
// refusal is audited as a denial.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertOwnerControl(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object, message string) (err error) {
	err = notImplemented("api/identities.ts assertOwnerControl")
	return
}

// DeleteIdentity (api/identities.ts deleteIdentity): Deletes an identity: every credential, factor, binding,
// membership, boundary, and link is removed or revoked in the same transaction, and a tombstone without email or
// secrets remains so audit records keep a resolvable principal.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeleteIdentity(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/identities.ts deleteIdentity")
	return
}

// RevokeInvitationsBy (api/identities.ts revokeInvitationsBy): The member invitations an identity sent and nobody
// redeemed yet are revoked when it is disabled or leaves (redemption refuses an inactive inviter anyway; this keeps
// `listInvitations` truthful and the tokens dead if it comes back).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RevokeInvitationsBy(ctx context.Context, tx core.IamStore, identityID string) (err error) {
	err = notImplemented("api/identities.ts revokeInvitationsBy")
	return
}
