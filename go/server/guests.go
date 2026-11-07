package server

// Skeleton of packages/server/src/guests.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AssertGuestAdmitted (guests.ts assertGuestAdmitted): Refuses (GUEST_NOT_ALLOWED, 403) a guest the host's inbound
// settings or the home tenant's outbound settings do not admit. The outbound refusal says only that the person's
// organization does not allow it, never what it configured.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertGuestAdmitted(ctx context.Context, tx core.IamStore, host *core.Object, hostTenantID string, origin *core.Object) (err error) {
	err = notImplemented("guests.ts assertGuestAdmitted")
	return
}

// CanSponsor (guests.ts canSponsor): Whether an identity can sponsor guests of `tenantId` now: an active, unexpired
// person of it who is no guest.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CanSponsor(server *ServerContext, identity *core.Object, tenantID string) (result bool, err error) {
	err = notImplemented("guests.ts canSponsor")
	return
}

// GuestAddress (guests.ts guestAddress): An invited address: a valid email whose domain is spelled as `emailDomain`
// spells it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GuestAddress(value any) (result string, err error) {
	err = notImplemented("guests.ts guestAddress")
	return
}

// GuestBoundary (guests.ts guestBoundary): The ceiling a tenant sets on every guest's decisions, if any
// (decisions.ts reads it for guests only).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GuestBoundary(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("guests.ts guestBoundary")
	return
}

// GuestContext (guests.ts guestContext): the guest keys of a decision: `principal.guest` always, and
// `principal.guestSponsorId` and `principal.homeTenantId` when set. Only an identity acting in its own tenant can be a
// guest there; an assumed role never is.
func GuestContext(identity *core.Object, ownTenant bool) *core.Object {
	var guest any = core.Undefined
	if ownTenant {
		guest = identity.Get("guest")
	}
	keys := core.NewObject("principal.guest", !isUndefined(guest))
	if sponsor, ok := member(guest, "sponsorId").(string); ok {
		keys.Set("principal.guestSponsorId", sponsor)
	}
	if home, ok := member(guest, "homeTenantId").(string); ok {
		keys.Set("principal.homeTenantId", home)
	}
	return keys
}

// GuestOrigin (guests.ts guestOrigin): Where an address comes from: its domain, and the tenant that verified that
// domain (`domainOwners`) unless that is the host itself or a deleted tenant. An address at one of the host's own
// verified domains belongs to a member, so it is refused (GUEST_NOT_ALLOWED): invite the person as a member instead.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GuestOrigin(ctx context.Context, tx core.IamStore, hostTenantID string, address string) (result *core.Object, err error) {
	err = notImplemented("guests.ts guestOrigin")
	return
}

// GuestSettings (guests.ts guestSettings): A tenant's settings: the stored ones, or the defaults.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GuestSettings(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("guests.ts guestSettings")
	return
}

// GuestSponsor (guests.ts guestSponsor): A guest's sponsor by id; refuses (INVALID_SPONSOR) anyone `canSponsor` does
// not accept.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func GuestSponsor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, sponsorID any) (result *core.Object, err error) {
	err = notImplemented("guests.ts guestSponsor")
	return
}

// HandOverGuests (guests.ts handOverGuests): Offboarding (identities.offboard): a leaver who is a guest has their
// guest account closed as `removed`, and the guests the leaver sponsors move to `successor` when that person can
// sponsor (each audited as `guest:sponsor-change`); otherwise they are flagged `sponsorMissing` so the owners assign
// someone.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HandOverGuests(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, leaver *core.Object, successor *core.Object) (result *core.Object, err error) {
	err = notImplemented("guests.ts handOverGuests")
	return
}

// IsGuest (guests.ts isGuest): Whether an identity is a guest: it carries the server-owned `guest` marker.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IsGuest(identity *core.Object) (result bool, err error) {
	err = notImplemented("guests.ts isGuest")
	return
}

// ReadGuestSettings (guests.ts readGuestSettings): A tenant's stored settings, if it saved any.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReadGuestSettings(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("guests.ts readGuestSettings")
	return
}

// ReleaseGuestRecords (guests.ts releaseGuestRecords): Identity deletion (identities.ts `deleteIdentity`): a deleted
// guest's account row goes (the audit trail keeps its history), and the guests the person sponsored are flagged
// `sponsorMissing`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseGuestRecords(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object) (err error) {
	err = notImplemented("guests.ts releaseGuestRecords")
	return
}

// RevokeGuestInvitationsBy (guests.ts revokeGuestInvitationsBy): The pending guest invitations a person sent or
// sponsors are revoked when they are disabled or leave (called by `revokeInvitationsBy` in api/identities.ts).
// Redemption would refuse them anyway; this keeps the list truthful.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RevokeGuestInvitationsBy(ctx context.Context, tx core.IamStore, identityID string) (err error) {
	err = notImplemented("guests.ts revokeGuestInvitationsBy")
	return
}

// SetGuestSponsor (guests.ts setGuestSponsor): Moves a guest to a new sponsor: the identity's marker and the
// account, clearing a missing-sponsor flag.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SetGuestSponsor(ctx context.Context, tx core.IamStore, account *core.Object, guest *core.Object, sponsorID string) (result *core.Object, err error) {
	err = notImplemented("guests.ts setGuestSponsor")
	return
}

// GuestCollections is guests.ts guestCollections.
var GuestCollections = struct {
	Invitations string
	Accounts    string
	Settings    string
}{"guestInvitations", "guestAccounts", "crossTenantAccess"}

// GuestDayMs is guests.ts guestDayMs.
const GuestDayMs = 86400000

// GuestLimits is guests.ts guestLimits.
var GuestLimits = struct {
	AccessDays         float64
	MaxAccessDays      float64
	ReviewEveryDays    float64
	MinReviewEveryDays float64
	MaxReviewEveryDays float64
	InvitationDays     float64
	MaxInvitationDays  float64
	ReminderDays       float64
}{90, 365, 90, 7, 365, 14, 30, 14}
