package server

// Port of packages/server/src/guests.ts: B2B guest collaboration (the API is api_guests.go). People from outside the
// organization, or from another tenant, join as guests: invited by email, vouched for by a sponsor, given limited
// access for a limited time that the sponsor renews (attests), and admitted only when the host's inbound and the home
// organization's outbound cross-tenant access settings both allow it. A guest is an ordinary `kind: 'user'` identity
// of the host tenant carrying the server-owned `Identity.guest` marker (never an attribute, never a new kind), so
// everything tenant-local applies to guests unchanged. Policies see `principal.guest`, `principal.guestSponsorId` and
// `principal.homeTenantId`, and a tenant's `guestBoundary` is a ceiling on every guest's decisions there.

import (
	"context"
	"strings"

	"golang.org/x/net/idna"

	"github.com/Better-IAM/better-iam/go/core"
)

// AssertGuestAdmitted (guests.ts assertGuestAdmitted): Refuses (GUEST_NOT_ALLOWED, 403) a guest the host's inbound
// settings or the home tenant's outbound settings do not admit. The outbound refusal says only that the person's
// organization does not allow it, never what it configured.
func AssertGuestAdmitted(ctx context.Context, tx core.IamStore, host *core.Object, hostTenantID string, origin *core.Object) (err error) {
	if refusal, refused := inboundRefusal(host, origin); refused {
		return core.NewIamError("GUEST_NOT_ALLOWED", refusal, 403)
	}
	if home, ok := origin.Get("homeTenantId").(string); ok && home != "" {
		settings, err := GuestSettings(ctx, tx, home)
		if err != nil {
			return err
		}
		if !outboundAllows(settings, hostTenantID) {
			return core.NewIamError("GUEST_NOT_ALLOWED", "The person’s organization does not allow its members to join this organization as guests", 403)
		}
	}
	return nil
}

// CanSponsor (guests.ts canSponsor): Whether an identity can sponsor guests of `tenantId` now: an active, unexpired
// person of it who is no guest.
func CanSponsor(server *ServerContext, identity *core.Object, tenantID string) (result bool, err error) {
	return canSponsor(server, identity, tenantID), nil
}

// canSponsor is CanSponsor without the error result (it never fails).
func canSponsor(server *ServerContext, identity *core.Object, tenantID string) bool {
	return identity != nil &&
		core.StrictEquals(identity.Get("tenantId"), tenantID) &&
		identity.Get("kind") == "user" &&
		identity.Get("status") == "active" &&
		!server.IdentityExpired(identity) &&
		!isGuest(identity)
}

// emailDomain (guests.ts emailDomain): an address's domain spelled as verified domains and the domain lists are
// (domains.ts `domainName`): lowercase ASCII, an internationalized name in its punycode form (UTS #46 mapping, as
// mail transports convert it), without a trailing dot. INVALID_INPUT for a domain that is not a DNS name.
func emailDomain(address string) (string, error) {
	domain, err := DomainName(domainToASCII(address[strings.LastIndex(address, "@")+1:]))
	if err != nil {
		return "", invalidInput("Invalid email: its domain is not a DNS name")
	}
	return domain, nil
}

// whatwgDomain is the UTS #46 processing of the WHATWG URL standard's domain to ASCII (node:url domainToASCII):
// non-transitional, CheckBidi and CheckJoiners on, CheckHyphens, UseSTD3ASCIIRules and VerifyDnsLength off.
var whatwgDomain = idna.New(
	idna.MapForLookup(),
	idna.Transitional(false),
	idna.BidiRule(),
	idna.CheckJoiners(true),
	idna.CheckHyphens(false),
	idna.StrictDomainName(false),
	idna.VerifyDNSLength(false),
)

// whatwgForbidden are the forbidden domain code points of the WHATWG URL standard (besides C0 controls and DEL).
const whatwgForbidden = "\x00\t\n\r #%/:<>?@[\\]^|"

// domainToASCII is node:url domainToASCII: the ASCII form of a domain, or "" when it is not a valid one.
func domainToASCII(domain string) string {
	ascii, err := whatwgDomain.ToASCII(domain)
	if err != nil {
		return ""
	}
	for _, r := range ascii {
		if r <= 0x1f || r == 0x7f || r == '%' || strings.ContainsRune(whatwgForbidden, r) {
			return ""
		}
	}
	return ascii
}

// GuestAddress (guests.ts guestAddress): An invited address: a valid email whose domain is spelled as `emailDomain`
// spells it.
func GuestAddress(value any) (result string, err error) {
	address, err := Email(value)
	if err != nil {
		return "", err
	}
	domain, err := emailDomain(address)
	if err != nil {
		return "", err
	}
	return address[:strings.LastIndex(address, "@")+1] + domain, nil
}

// GuestBoundary (guests.ts guestBoundary): The ceiling a tenant sets on every guest's decisions, if any
// (decisions.ts reads it for guests only).
func GuestBoundary(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	stored, err := ReadGuestSettings(ctx, tx, tenantID)
	if err != nil || stored == nil {
		return nil, err
	}
	boundary, _ := stored.Get("guestBoundary").(*core.Object)
	return boundary, nil
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
func GuestOrigin(ctx context.Context, tx core.IamStore, hostTenantID string, address string) (result *core.Object, err error) {
	domain, err := emailDomain(address)
	if err != nil {
		return nil, err
	}
	owner, err := tx.Get(ctx, "domainOwners", domain)
	if err != nil {
		return nil, err
	}
	if owner == nil {
		return core.NewObject("domain", domain), nil
	}
	if core.StrictEquals(owner.Get("tenantId"), hostTenantID) {
		return nil, core.NewIamError("GUEST_NOT_ALLOWED", domain+" is a verified domain of this organization: invite the person as a member", 403)
	}
	home, err := tx.Get(ctx, "tenants", jsString(owner.Get("tenantId")))
	if err != nil {
		return nil, err
	}
	if home != nil && home.Get("status") != "deleted" {
		return core.NewObject("domain", domain, "homeTenantId", home.Get("id")), nil
	}
	return core.NewObject("domain", domain), nil
}

// defaultGuestSettings (guests.ts defaultGuestSettings): the settings a tenant has without stored ones.
func defaultGuestSettings() *core.Object {
	return core.NewObject(
		"inbound", core.NewObject("allowGuests", true, "allowedDomains", []any{}, "blockedDomains", []any{}, "partners", []any{}),
		"outbound", core.NewObject("allowGuestInvitations", true, "partners", []any{}),
		"accessDays", GuestLimits.AccessDays,
		"reviewEveryDays", GuestLimits.ReviewEveryDays,
	)
}

// GuestSettings (guests.ts guestSettings): A tenant's settings: the stored ones, or the defaults.
func GuestSettings(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	stored, err := ReadGuestSettings(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if stored == nil {
		return defaultGuestSettings(), nil
	}
	settings := core.NewObject(
		"inbound", stored.Get("inbound"),
		"outbound", stored.Get("outbound"),
		"accessDays", stored.Get("accessDays"),
		"reviewEveryDays", stored.Get("reviewEveryDays"),
	)
	if boundary := stored.Get("guestBoundary"); truthy(boundary) {
		settings.Set("guestBoundary", boundary)
	}
	return settings, nil
}

// GuestSponsor (guests.ts guestSponsor): A guest's sponsor by id; refuses (INVALID_SPONSOR) anyone `canSponsor` does
// not accept.
func GuestSponsor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, sponsorID any) (result *core.Object, err error) {
	id, err := Text(sponsorID, "sponsorId")
	if err != nil {
		return nil, err
	}
	sponsor, err := tx.Get(ctx, "identities", id)
	if err != nil {
		return nil, err
	}
	if !canSponsor(server, sponsor, tenantID) {
		return nil, core.NewIamError("INVALID_SPONSOR", "A guest’s sponsor must be an active member of the organization who is not a guest")
	}
	return sponsor, nil
}

// HandOverGuests (guests.ts handOverGuests): Offboarding (identities.offboard): a leaver who is a guest has their
// guest account closed as `removed`, and the guests the leaver sponsors move to `successor` when that person can
// sponsor (each audited as `guest:sponsor-change`); otherwise they are flagged `sponsorMissing` so the owners assign
// someone.
func HandOverGuests(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, leaver *core.Object, successor *core.Object) (result *core.Object, err error) {
	reassigned, unsponsored := 0.0, 0.0
	leaverID, leaverTenant := jsString(leaver.Get("id")), jsString(leaver.Get("tenantId"))
	own, err := tx.Get(ctx, GuestCollections.Accounts, leaverID)
	if err != nil {
		return nil, err
	}
	if own != nil && core.StrictEquals(own.Get("tenantId"), leaver.Get("tenantId")) && own.Get("status") == "active" {
		if _, err := tx.Put(ctx, GuestCollections.Accounts, own.Spread(core.NewObject(
			"status", "removed",
			"endedAt", float64(server.Now()),
			"endedBy", principal.Identity.Get("id"),
			"removalReason", "Offboarded",
		))); err != nil {
			return nil, err
		}
	}
	var heir *core.Object
	if successor != nil && !core.StrictEquals(successor.Get("id"), leaver.Get("id")) && canSponsor(server, successor, leaverTenant) {
		heir = successor
	}
	accounts, err := tx.Find(ctx, GuestCollections.Accounts, core.NewObject("tenantId", leaver.Get("tenantId"), "sponsorId", leaver.Get("id"), "status", "active"), nil)
	if err != nil {
		return nil, err
	}
	for _, account := range accounts {
		guest, err := tx.Get(ctx, "identities", jsString(account.Get("identityId")))
		if err != nil {
			return nil, err
		}
		if guest == nil || guest.Get("status") == "deleted" {
			continue
		}
		if heir != nil && !core.StrictEquals(heir.Get("id"), guest.Get("id")) {
			heirID := jsString(heir.Get("id"))
			if _, err := SetGuestSponsor(ctx, tx, account, guest, heirID); err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "guest:sponsor-change", leaverTenant, jsString(guest.Get("id")), "allow", false,
				core.NewObject("from", leaver.Get("id"), "to", heir.Get("id"), "reason", "offboarding")); err != nil {
				return nil, err
			}
			reassigned++
			continue
		}
		if err := flagSponsorMissing(ctx, server, tx, principal, account, "offboarding"); err != nil {
			return nil, err
		}
		unsponsored++
	}
	return core.NewObject("reassigned", reassigned, "unsponsored", unsponsored), nil
}

// IsGuest (guests.ts isGuest): Whether an identity is a guest: it carries the server-owned `guest` marker.
func IsGuest(identity *core.Object) (result bool, err error) {
	return isGuest(identity), nil
}

// isGuest is IsGuest without the error result (it never fails).
func isGuest(identity *core.Object) bool {
	return !isUndefined(identity.Get("guest"))
}

// ReadGuestSettings (guests.ts readGuestSettings): A tenant's stored settings, if it saved any.
func ReadGuestSettings(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	stored, err := tx.Get(ctx, GuestCollections.Settings, tenantID)
	if err != nil {
		return nil, err
	}
	if stored != nil && core.StrictEquals(stored.Get("tenantId"), tenantID) {
		return stored, nil
	}
	return nil, nil
}

// ReleaseGuestRecords (guests.ts releaseGuestRecords): Identity deletion (identities.ts `deleteIdentity`): a deleted
// guest's account row goes (the audit trail keeps its history), and the guests the person sponsored are flagged
// `sponsorMissing`.
func ReleaseGuestRecords(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object) (err error) {
	own, err := tx.Get(ctx, GuestCollections.Accounts, jsString(identity.Get("id")))
	if err != nil {
		return err
	}
	if own != nil && core.StrictEquals(own.Get("tenantId"), identity.Get("tenantId")) {
		if err := tx.Delete(ctx, GuestCollections.Accounts, jsString(own.Get("id"))); err != nil {
			return err
		}
	}
	accounts, err := tx.Find(ctx, GuestCollections.Accounts, core.NewObject("tenantId", identity.Get("tenantId"), "sponsorId", identity.Get("id"), "status", "active"), nil)
	if err != nil {
		return err
	}
	for _, account := range accounts {
		if err := flagSponsorMissing(ctx, server, tx, principal, account, "deletion"); err != nil {
			return err
		}
	}
	return nil
}

// RevokeGuestInvitationsBy (guests.ts revokeGuestInvitationsBy): The pending guest invitations a person sent or
// sponsors are revoked when they are disabled or leave (called by `revokeInvitationsBy` in api/identities.ts).
// Redemption would refuse them anyway; this keeps the list truthful.
func RevokeGuestInvitationsBy(ctx context.Context, tx core.IamStore, identityID string) (err error) {
	found := map[string]*core.Object{}
	var order []string
	for _, field := range []string{"invitedBy", "sponsorId"} {
		invitations, err := tx.Find(ctx, GuestCollections.Invitations, core.NewObject(field, identityID, "status", "pending"), nil)
		if err != nil {
			return err
		}
		for _, invitation := range invitations {
			id := jsString(invitation.Get("id"))
			if _, seen := found[id]; !seen {
				order = append(order, id)
			}
			found[id] = invitation
		}
	}
	for _, id := range order {
		invitation := found[id]
		rest := invitation.Spread()
		rest.Delete("uniqueKey")
		reason := "sponsor-inactive"
		if core.StrictEquals(invitation.Get("invitedBy"), identityID) {
			reason = "inviter-inactive"
		}
		if _, err := tx.Put(ctx, GuestCollections.Invitations, rest.Spread(core.NewObject("status", "revoked", "revokedReason", reason))); err != nil {
			return err
		}
	}
	return nil
}

// SetGuestSponsor (guests.ts setGuestSponsor): Moves a guest to a new sponsor: the identity's marker and the
// account, clearing a missing-sponsor flag.
func SetGuestSponsor(ctx context.Context, tx core.IamStore, account *core.Object, guest *core.Object, sponsorID string) (result *core.Object, err error) {
	identity := guest
	if marker := guest.Get("guest"); truthy(marker) {
		next := core.NewObject()
		if object, ok := marker.(*core.Object); ok {
			next = object.Spread()
		}
		next.Set("sponsorId", sponsorID)
		if identity, err = tx.Put(ctx, "identities", guest.Spread(core.NewObject("guest", next))); err != nil {
			return nil, err
		}
	}
	rest := account.Spread()
	rest.Delete("sponsorMissing")
	rest.Delete("sponsorMissingNotifiedAt")
	stored, err := tx.Put(ctx, GuestCollections.Accounts, rest.Spread(core.NewObject("sponsorId", sponsorID)))
	if err != nil {
		return nil, err
	}
	return core.NewObject("account", stored, "identity", identity), nil
}

// domainListed (guests.ts domainListed): whether a domain is one of `entries` or a subdomain of one.
func domainListed(domain string, entries any) bool {
	list, _ := entries.([]any)
	for _, entry := range list {
		text := jsString(entry)
		if domain == text || strings.HasSuffix(domain, "."+text) {
			return true
		}
	}
	return false
}

// partnerEntry is `partners.find((entry) => entry.tenantId === tenantId)`.
func partnerEntry(partners any, tenantID any) *core.Object {
	list, _ := partners.([]any)
	for _, entry := range list {
		if core.StrictEquals(member(entry, "tenantId"), tenantID) {
			object, _ := entry.(*core.Object)
			return object
		}
	}
	return nil
}

// inboundRefusal (guests.ts inboundRefusal): why the host's inbound settings refuse a guest from `origin` (refused
// false when they admit them). A refusal wins (a partner entry with `allow: false`, a blocked domain); a partner entry
// with `allow: true` then admits the guest over the defaults (`allowGuests`, `allowedDomains`).
func inboundRefusal(settings *core.Object, origin *core.Object) (string, bool) {
	inbound := settings.Get("inbound")
	var partner *core.Object
	if home := origin.Get("homeTenantId"); truthy(home) {
		partner = partnerEntry(member(inbound, "partners"), home)
	}
	if partner != nil && !truthy(partner.Get("allow")) {
		return "This organization does not accept guests from the person’s organization", true
	}
	domain := jsString(origin.Get("domain"))
	if domainListed(domain, member(inbound, "blockedDomains")) {
		return "This organization does not accept guests from " + domain, true
	}
	if partner != nil && truthy(partner.Get("allow")) {
		return "", false
	}
	if !truthy(member(inbound, "allowGuests")) {
		return "This organization does not accept guests", true
	}
	allowed, _ := member(inbound, "allowedDomains").([]any)
	if len(allowed) > 0 && !domainListed(domain, allowed) {
		return "This organization accepts guests only from its allowed domains", true
	}
	return "", false
}

// outboundAllows (guests.ts outboundAllows): whether a home tenant's outbound settings let its people become guests
// of `hostTenantId`.
func outboundAllows(settings *core.Object, hostTenantID string) bool {
	outbound := settings.Get("outbound")
	if partner := partnerEntry(member(outbound, "partners"), hostTenantID); partner != nil {
		return truthy(partner.Get("allow"))
	}
	return truthy(member(outbound, "allowGuestInvitations"))
}

// flagSponsorMissing (guests.ts flagSponsorMissing): flags a guest whose sponsor is leaving, audited as
// `guest:sponsor-missing` (the worker emails the owners).
func flagSponsorMissing(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, account *core.Object, reason string) error {
	if truthy(account.Get("sponsorMissing")) {
		return nil
	}
	if _, err := tx.Put(ctx, GuestCollections.Accounts, account.Spread(core.NewObject("sponsorMissing", true))); err != nil {
		return err
	}
	return server.Events.Audit(ctx, tx, principal, "guest:sponsor-missing", jsString(account.Get("tenantId")), jsString(account.Get("identityId")), "allow", false,
		core.NewObject("sponsorId", account.Get("sponsorId"), "reason", reason))
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
