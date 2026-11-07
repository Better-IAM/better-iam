package server

// Skeleton of packages/server/src/api/guests.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// GuestsAPI is the `guests` API group (packages/server/src/api/guests.ts createGuestsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/guests/{method} onto it.
type GuestsAPI struct {
	server *ServerContext
}

// CreateGuestsAPI builds the `guests` API group.
func CreateGuestsAPI(server *ServerContext) *GuestsAPI {
	return &GuestsAPI{server: server}
}

// Attest is POST {basePath}/guests/attest. Renews a guest's access, together with everything the invitation granted.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) Attest(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsAttestInput]) (Out[apitypes.GuestsAttestOutput], error) {
	return Out[apitypes.GuestsAttestOutput]{}, notImplemented("guests.attest")
}

// Configure is POST {basePath}/guests/configure. Changes the tenant's cross-tenant access settings: who may join as a guest, where its people may be guests, the default periods, and the guest boundary.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) Configure(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsConfigureInput]) (Out[apitypes.GuestsConfigureOutput], error) {
	return Out[apitypes.GuestsConfigureOutput]{}, notImplemented("guests.configure")
}

// ConvertToMember is POST {basePath}/guests/convertToMember. Makes an active guest an ordinary member of the organization.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) ConvertToMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsConvertToMemberInput]) (Out[apitypes.GuestsConvertToMemberOutput], error) {
	return Out[apitypes.GuestsConvertToMemberOutput]{}, notImplemented("guests.convertToMember")
}

// Get is POST {basePath}/guests/get. Returns one guest with their sponsor, invitation, renewal, access end, and last sign-in.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsGetInput]) (Out[apitypes.GuestsGetOutput], error) {
	return Out[apitypes.GuestsGetOutput]{}, notImplemented("guests.get")
}

// GetSettings is POST {basePath}/guests/getSettings. Returns the tenant's cross-tenant access settings, or the defaults until they are configured.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsGetSettingsInput]) (Out[apitypes.GuestsGetSettingsOutput], error) {
	return Out[apitypes.GuestsGetSettingsOutput]{}, notImplemented("guests.getSettings")
}

// Invite is POST {basePath}/guests/invite. Invites a person from outside the organization as a guest and emails them a personal invitation.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) Invite(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsInviteInput]) (Out[apitypes.GuestsInviteOutput], error) {
	return Out[apitypes.GuestsInviteOutput]{}, notImplemented("guests.invite")
}

// List is POST {basePath}/guests/list. Lists the tenant's guests by name, with their sponsor, access end, next review, and last sign-in.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsListInput]) (Out[apitypes.GuestsListOutput], error) {
	return Out[apitypes.GuestsListOutput]{}, notImplemented("guests.list")
}

// ListInvitations is POST {basePath}/guests/listInvitations. Lists the tenant's guest invitations, newest first, without their tokens.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) ListInvitations(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsListInvitationsInput]) (Out[apitypes.GuestsListInvitationsOutput], error) {
	return Out[apitypes.GuestsListInvitationsOutput]{}, notImplemented("guests.listInvitations")
}

// Mine is POST {basePath}/guests/mine. Lists the active guests the caller sponsors, the soonest review first.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsMineInput]) (Out[apitypes.GuestsMineOutput], error) {
	return Out[apitypes.GuestsMineOutput]{}, notImplemented("guests.mine")
}

// Redeem is POST {basePath}/guests/redeem (public: no request credential). Redeems a guest invitation: creates the guest with the invited address and a password, grants what the invitation grants, and signs them in.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) Redeem(ctx context.Context, input In[apitypes.GuestsRedeemInput]) (Out[apitypes.GuestsRedeemOutput], error) {
	return Out[apitypes.GuestsRedeemOutput]{}, notImplemented("guests.redeem")
}

// Remove is POST {basePath}/guests/remove. Removes a guest: disables them and takes away everything they hold, in one transaction.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) Remove(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsRemoveInput]) (Out[apitypes.GuestsRemoveOutput], error) {
	return Out[apitypes.GuestsRemoveOutput]{}, notImplemented("guests.remove")
}

// ResendInvitation is POST {basePath}/guests/resendInvitation. Sends a pending or lapsed guest invitation again with a new token and a new lifetime.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) ResendInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsResendInvitationInput]) (Out[apitypes.GuestsResendInvitationOutput], error) {
	return Out[apitypes.GuestsResendInvitationOutput]{}, notImplemented("guests.resendInvitation")
}

// RevokeInvitation is POST {basePath}/guests/revokeInvitation. Withdraws a pending guest invitation, so its token stops working.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) RevokeInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsRevokeInvitationInput]) (Out[apitypes.GuestsRevokeInvitationOutput], error) {
	return Out[apitypes.GuestsRevokeInvitationOutput]{}, notImplemented("guests.revokeInvitation")
}

// SetSponsor is POST {basePath}/guests/setSponsor. Gives an active guest a new sponsor and clears a missing-sponsor flag.
//
// STUB: returns NOT_IMPLEMENTED until api/guests.ts is ported.
func (api *GuestsAPI) SetSponsor(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsSetSponsorInput]) (Out[apitypes.GuestsSetSponsorOutput], error) {
	return Out[apitypes.GuestsSetSponsorOutput]{}, notImplemented("guests.setSponsor")
}

// IamGuests is api/guests.ts IamGuests.
type IamGuests struct {
	server *ServerContext
}

// SendReviewReminders (api/guests.ts IamGuests.sendReviewReminders): Emails each sponsor (template `guest-review`)
// about guests whose review is due or whose access ends within `withinDays` (default 14): each review date and each
// access end once, one email covering whatever is due. Requires an email delivery callback.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamGuests) SendReviewReminders(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/guests.ts IamGuests.sendReviewReminders")
	return
}

// Sweep (api/guests.ts IamGuests.sweep): Bookkeeping: marks lapsed invitations and ended guest accounts expired,
// flags guests whose sponsor left (and emails the tenant's owners once, template `guest-sponsor-missing`), and drops
// partner entries naming purged tenants.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *IamGuests) Sweep(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/guests.ts IamGuests.sweep")
	return
}

// CreateGuestsRuntime builds the IamGuests (api/guests.ts createGuestsRuntime). Its methods are stubs until the module is ported.
func CreateGuestsRuntime(server *ServerContext) *IamGuests {
	return &IamGuests{server: server}
}
