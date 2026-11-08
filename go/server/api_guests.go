package server

// Port of packages/server/src/api/guests.ts: B2B guest collaboration (guests.go): email invitations and their public
// redemption, the guest directory, sponsor attestation, sponsor changes, removal, conversion to a member, and the
// tenant's cross-tenant access settings. Actions `iam:guests:read`, `iam:guests:invite`, `iam:guests:manage` and
// `iam:guests:settings` on `iam/guests`, `iam/guests/{identityId}`, `iam/guests/invitations[/{id}]` and
// `iam/guests/settings`.

import (
	"context"
	"errors"
	"math"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
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

var guestAccountStatuses = []string{"active", "expired", "removed", "converted"}
var guestInvitationStatuses = []string{"pending", "redeemed", "revoked", "expired"}

func guestResource(identityID string) string        { return "guests/" + identityID }
func invitationResource(invitationID string) string { return "guests/invitations/" + invitationID }
func guestPendingKey(address string) string         { return "pending:" + address }
func guestISO(at any) string                        { return isoString(jsNumber(at)) }

// guestInvitationToken is a new invitation token: `biam_gst_` and 43 random base64url characters, a prefix secret
// scanners can look for.
func guestInvitationToken() string { return "biam_gst_" + Token() }

// guestStatusIn is `set.has(value)` over a list of statuses (false for a value that is not a string).
func guestStatusIn(value any, statuses []string) bool {
	text, ok := value.(string)
	return ok && containsString(statuses, text)
}

// guestFlag (api/guests.ts flag) requires a boolean.
func guestFlag(value any, name string) (bool, error) {
	flag, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be a boolean")
	}
	return flag, nil
}

// guestFields (api/guests.ts fields): an object whose keys are all among `allowed`.
func guestFields(value any, name string, allowed []string) (*core.Object, error) {
	record, err := Object(value)
	if err != nil {
		return nil, err
	}
	for _, key := range record.Keys() {
		if !containsString(allowed, key) {
			return nil, invalidInput("Unknown " + name + " setting " + key)
		}
	}
	return record, nil
}

// guestDomainList (api/guests.ts domainList): lowercase domains, each checked like a verified domain, deduplicated
// and sorted.
func guestDomainList(value any, name string) ([]any, error) {
	entries, err := Strings(value, name)
	if err != nil {
		return nil, err
	}
	set := newOrderedSet()
	for _, entry := range entries {
		domain, err := DomainName(entry)
		if err != nil {
			return nil, err
		}
		set.Add(domain)
	}
	domains := set.Values()
	sort.SliceStable(domains, func(i, j int) bool { return compareUTF16(domains[i], domains[j]) < 0 })
	return stringsOf(domains), nil
}

// guestPartnerList (api/guests.ts partnerList): partner organizations by tenant ID: existing tenants other than this
// one, each named once.
func guestPartnerList(ctx context.Context, tx core.IamStore, tenantID string, value any, name string) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) > 100 {
		return nil, invalidInput(name + " must list at most 100 organizations")
	}
	partners := []*core.Object{}
	for _, item := range list {
		entry, err := guestFields(item, name, []string{"tenantId", "allow"})
		if err != nil {
			return nil, err
		}
		partnerID, err := Text(entry.Get("tenantId"), name+".tenantId")
		if err != nil {
			return nil, err
		}
		allowed, err := guestFlag(entry.Get("allow"), name+".allow")
		if err != nil {
			return nil, err
		}
		if partnerID == tenantID {
			return nil, invalidInput(name + " cannot name this organization")
		}
		for _, partner := range partners {
			if partner.Get("tenantId") == partnerID {
				return nil, invalidInput(name + " names " + partnerID + " more than once")
			}
		}
		partner, err := tx.Get(ctx, "tenants", partnerID)
		if err != nil {
			return nil, err
		}
		if partner == nil || partner.Get("status") == "deleted" {
			return nil, invalidInput(name + ": unknown organization " + partnerID)
		}
		partners = append(partners, core.NewObject("tenantId", partnerID, "allow", allowed))
	}
	sortStable(partners, func(a, b *core.Object) int {
		left, right := jsString(a.Get("tenantId")), jsString(b.Get("tenantId"))
		switch {
		case compareUTF16(left, right) < 0:
			return -1
		case compareUTF16(left, right) > 0:
			return 1
		}
		return 0
	})
	out := make([]any, len(partners))
	for index, partner := range partners {
		out[index] = partner
	}
	return out, nil
}

// guestOwnSession (api/guests.ts ownSession): a person's own session in the tenant: an ordinary user session or
// their API key, of that tenant.
func guestOwnSession(principal *Principal, tenantID string, what string) error {
	if !ActsInOwnRight(principal.Session) ||
		!core.StrictEquals(principal.Session.Get("tenantId"), tenantID) ||
		!core.StrictEquals(principal.Identity.Get("tenantId"), tenantID) {
		return core.NewIamError("ACCESS_DENIED", what+" from an ordinary session of the organization", 403)
	}
	return nil
}

// guestCallerSponsor (api/guests.ts callerSponsor): the caller as the sponsor of the guests they invite, when they
// can sponsor guests themselves.
func guestCallerSponsor(server *ServerContext, principal *Principal, tenantID string) (*core.Object, error) {
	if !ActsInOwnRight(principal.Session) ||
		!core.StrictEquals(principal.Session.Get("tenantId"), tenantID) ||
		!canSponsor(server, principal.Identity, tenantID) {
		return nil, core.NewIamError("INVALID_SPONSOR", "Name a sponsor (sponsorId): only an active member of the organization who is not a guest can sponsor guests")
	}
	return principal.Identity, nil
}

// guestDecide is ctx.decisions.decide on an `iam` resource (internal resource) and its `allowed`.
func guestDecide(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID, action, resourceID string) (bool, error) {
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
	}, true)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// authorizeOtherSponsor (api/guests.ts): naming someone other than oneself as a guest's sponsor makes them
// accountable for the guest, and gives the guest whatever policies grant on `principal.guestSponsorId`, so it needs
// what giving a guest another sponsor needs: iam:guests:manage (here on iam/guests/invitations). Checked before the
// sponsor is validated, so it reveals nothing about them; the refusal is audited as a denial.
func authorizeOtherSponsor(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, sponsorID any) error {
	id, err := Text(sponsorID, "sponsorId")
	if err != nil {
		return err
	}
	if core.StrictEquals(principal.Identity.Get("id"), id) && ActsInOwnRight(principal.Session) &&
		core.StrictEquals(principal.Session.Get("tenantId"), tenantID) {
		return nil
	}
	allowed, err := guestDecide(ctx, server, tx, principal, tenantID, "iam:guests:manage", "guests/invitations")
	if err != nil {
		return err
	}
	if !allowed {
		return NewOperationDenied("Naming someone else as the sponsor needs iam:guests:manage")
	}
	return nil
}

// assertOwnerExpiryControl (api/guests.ts): moving the access end of a guest who owns the organization (or is a root
// administrator) changes an owner's expiry, so it needs what `identities.update` asks for: an owner of the tenant in
// person or a root caller; and an end (`next`) is never given to the last active owner, nor to the last owner without
// one.
func assertOwnerExpiryControl(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, identity *core.Object, next any) error {
	if truthy(identity.Get("rootAdmin")) {
		root, err := server.RootPrincipal(ctx, tx, principal)
		if err != nil {
			return err
		}
		if !root {
			return core.NewIamError("ACCESS_DENIED", "Root capability is protected", 403)
		}
	}
	if err := AssertOwnerControl(ctx, server, tx, principal, identity, "Only an owner can change an owner’s expiry"); err != nil {
		return err
	}
	if !truthy(identity.Get("owner")) || isUndefined(next) {
		return nil
	}
	if err := server.ProtectLastOwner(ctx, tx, identity); err != nil {
		return err
	}
	if _, ok := identity.Get("expiresAt").(float64); !ok {
		owners, err := tx.Find(ctx, "identities", core.NewObject("tenantId", identity.Get("tenantId"), "owner", true, "status", "active"), nil)
		if err != nil {
			return err
		}
		another := false
		for _, other := range owners {
			if _, ends := other.Get("expiresAt").(float64); !core.StrictEquals(other.Get("id"), identity.Get("id")) && !ends {
				another = true
				break
			}
		}
		if !another {
			return core.NewIamError("LAST_OWNER", "The last owner without an expiry cannot be given one", 409)
		}
	}
	return nil
}

// guestNames (api/guests.ts nameReader): display names by identity ID, each read once per call (undefined for an
// identity that does not exist).
type guestNames struct {
	tx    core.IamStore
	names map[string]any
}

func nameReader(tx core.IamStore) *guestNames {
	return &guestNames{tx: tx, names: map[string]any{}}
}

func (n *guestNames) of(ctx context.Context, identityID any) (any, error) {
	key := jsString(identityID)
	if name, ok := n.names[key]; ok {
		return name, nil
	}
	identity, err := n.tx.Get(ctx, "identities", key)
	if err != nil {
		return nil, err
	}
	var name any = core.Undefined
	if identity != nil {
		name = identity.Get("name")
	}
	n.names[key] = name
	return name, nil
}

// loadGuest (api/guests.ts): a guest's account and identity in the tenant; NOT_FOUND for anyone else.
func loadGuest(ctx context.Context, tx core.IamStore, tenantID string, identityID string) (*core.Object, *core.Object, error) {
	account, err := tx.Get(ctx, GuestCollections.Accounts, identityID)
	if err != nil {
		return nil, nil, err
	}
	var identity *core.Object
	if account != nil && core.StrictEquals(account.Get("tenantId"), tenantID) {
		if identity, err = tx.Get(ctx, "identities", jsString(account.Get("identityId"))); err != nil {
			return nil, nil, err
		}
	}
	if account == nil || identity == nil || !core.StrictEquals(identity.Get("tenantId"), tenantID) || identity.Get("status") == "deleted" {
		return nil, nil, core.NewIamError("NOT_FOUND", "Guest not found", 404)
	}
	return account, identity, nil
}

// assertNewcomer (api/guests.ts): refuses an address that already belongs to someone in the tenant. A former guest's
// disabled account keeps its address, so the refusal says how to go on: delete that account first.
func assertNewcomer(ctx context.Context, tx core.IamStore, tenantID string, address string) error {
	found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", address), nil)
	if err != nil {
		return err
	}
	if len(found) > 0 {
		existing := found[0]
		message := "Someone with this email address already belongs to this organization"
		if truthy(existing.Get("guest")) && existing.Get("status") == "disabled" {
			message = "This address belongs to a former guest whose disabled account still holds it: delete that account to invite the address again"
		}
		return core.NewIamError("CONFLICT", message, 409)
	}
	return nil
}

// claimPendingKey (api/guests.ts): makes way for a pending invitation to `address`: another one still open is a
// conflict, and one that lapsed without the worker noticing is marked expired first. `except` is the invitation
// being sent again ("" for none).
func claimPendingKey(ctx context.Context, tx core.IamStore, tenantID string, address string, now float64, except string) error {
	open, err := tx.Find(ctx, GuestCollections.Invitations, core.NewObject("tenantId", tenantID, "uniqueKey", guestPendingKey(address)), nil)
	if err != nil {
		return err
	}
	for _, invitation := range open {
		if except != "" && core.StrictEquals(invitation.Get("id"), except) {
			continue
		}
		if jsNumber(invitation.Get("expiresAt")) > now {
			return core.NewIamError("CONFLICT", "This address already has a pending guest invitation: send it again or revoke it", 409)
		}
		rest := invitation.Spread()
		rest.Delete("uniqueKey")
		if _, err := tx.Put(ctx, GuestCollections.Invitations, rest.Spread(core.NewObject("status", "expired"))); err != nil {
			return err
		}
	}
	return nil
}

// guestAccountStatus (api/guests.ts accountStatus): the account's status as it stands: an active account whose
// access end passed is expired already.
func guestAccountStatus(server *ServerContext, account *core.Object, identity *core.Object) any {
	if account.Get("status") == "active" && server.IdentityExpired(identity) {
		return "expired"
	}
	return account.Get("status")
}

// guestView (api/guests.ts): a guest as administrators and sponsors see them.
func guestView(ctx context.Context, server *ServerContext, tx core.IamStore, account *core.Object, identity *core.Object, names *guestNames) (*core.Object, error) {
	sponsorName, err := names.of(ctx, account.Get("sponsorId"))
	if err != nil {
		return nil, err
	}
	signIns, err := tx.Get(ctx, "authSignIns", jsString(identity.Get("id")))
	if err != nil {
		return nil, err
	}
	view := core.NewObject(
		"identityId", identity.Get("id"),
		"tenantId", identity.Get("tenantId"),
		"name", identity.Get("name"),
	)
	if truthy(identity.Get("email")) {
		view.Set("email", identity.Get("email"))
	}
	view.Set("status", identity.Get("status"))
	view.Set("accountStatus", guestAccountStatus(server, account, identity))
	view.Set("sponsorId", account.Get("sponsorId"))
	if !isUndefined(sponsorName) {
		view.Set("sponsorName", sponsorName)
	}
	view.Set("sponsorMissing", account.Get("sponsorMissing") == true)
	if truthy(account.Get("homeTenantId")) {
		view.Set("homeTenantId", account.Get("homeTenantId"))
	}
	if home := member(identity.Get("guest"), "homeDomain"); truthy(home) {
		view.Set("homeDomain", home)
	}
	view.Set("invitationId", account.Get("invitationId"))
	view.Set("invitedBy", account.Get("invitedBy"))
	view.Set("redeemedAt", account.Get("redeemedAt"))
	if value := account.Get("attestedAt"); !isUndefined(value) {
		view.Set("attestedAt", value)
	}
	if value := account.Get("attestedBy"); !isUndefined(value) {
		view.Set("attestedBy", value)
	}
	view.Set("reviewDueAt", account.Get("reviewDueAt"))
	if value := identity.Get("expiresAt"); !isUndefined(value) {
		view.Set("expiresAt", value)
	}
	if signIns != nil {
		if last, ok := signIns.Get("lastAt").(float64); ok {
			view.Set("lastSignInAt", last)
		}
	}
	return view, nil
}

// invitationView (api/guests.ts): a guest invitation without its token.
func invitationView(ctx context.Context, server *ServerContext, invitation *core.Object, names *guestNames) (*core.Object, error) {
	sponsorName, err := names.of(ctx, invitation.Get("sponsorId"))
	if err != nil {
		return nil, err
	}
	inviterName, err := names.of(ctx, invitation.Get("invitedBy"))
	if err != nil {
		return nil, err
	}
	status := invitation.Get("status")
	if status == "pending" && jsNumber(invitation.Get("expiresAt")) <= float64(server.Now()) {
		status = "expired"
	}
	view := core.NewObject(
		"id", invitation.Get("id"),
		"tenantId", invitation.Get("tenantId"),
		"email", invitation.Get("email"),
		"status", status,
		"sponsorId", invitation.Get("sponsorId"),
	)
	if !isUndefined(sponsorName) {
		view.Set("sponsorName", sponsorName)
	}
	view.Set("invitedBy", invitation.Get("invitedBy"))
	if !isUndefined(inviterName) {
		view.Set("inviterName", inviterName)
	}
	if value := invitation.Get("message"); !isUndefined(value) {
		view.Set("message", value)
	}
	view.Set("roleIds", invitation.Get("roleIds"))
	view.Set("groupIds", invitation.Get("groupIds"))
	view.Set("packageIds", invitation.Get("packageIds"))
	view.Set("accessDays", invitation.Get("accessDays"))
	if truthy(invitation.Get("homeTenantId")) {
		view.Set("homeTenantId", invitation.Get("homeTenantId"))
	}
	view.Set("expiresAt", invitation.Get("expiresAt"))
	view.Set("createdAt", invitation.Get("createdAt"))
	view.Set("sentAt", invitation.Get("sentAt"))
	for _, key := range []string{"redeemedAt", "identityId", "revokedAt", "revokedBy", "revokedReason"} {
		if value := invitation.Get(key); !isUndefined(value) {
			view.Set(key, value)
		}
	}
	return view, nil
}

// guestSettingsView (api/guests.ts settingsView): a tenant's cross-tenant access settings as `getSettings` and
// `configure` return them.
func guestSettingsView(tenantID string, settings *core.Object, stored *core.Object) *core.Object {
	view := core.NewObject(
		"tenantId", tenantID,
		"configured", stored != nil,
		"inbound", settings.Get("inbound"),
		"outbound", settings.Get("outbound"),
		"accessDays", settings.Get("accessDays"),
		"reviewEveryDays", settings.Get("reviewEveryDays"),
	)
	if boundary := settings.Get("guestBoundary"); truthy(boundary) {
		view.Set("guestBoundary", boundary)
	}
	if stored != nil {
		view.Set("updatedAt", stored.Get("updatedAt"))
		view.Set("updatedBy", stored.Get("updatedBy"))
	}
	return view
}

// authorizeGrants (api/guests.ts): what an invitation may grant, authorized like `identities.invite` and
// `packages.assign`: iam:bindings:create on each role (never a protected one) under the caller's grant authority,
// iam:groups:update on each group (never a team's backing group) plus the authorities of the group's own bindings and,
// when a license product is assigned to one of the groups, iam:licenses:assign (api/groups.ts), and
// iam:packages:assign on each package with the rights to assign it by hand. Returns the grant authority the roles and
// groups are made under ("" when the invitation grants neither).
func authorizeGrants(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, roleIDs, groupIDs, packageIDs []string) (string, error) {
	authorityID := ""
	if len(roleIDs) > 0 || len(groupIDs) > 0 {
		authority, err := server.GrantingAuthority(ctx, tx, principal, tenantID, "")
		if err != nil {
			return "", err
		}
		authorityID = jsString(authority.Get("id"))
	}
	for _, roleID := range roleIDs {
		role, err := server.Scoped(ctx, tx, "roles", roleID, tenantID)
		if err != nil {
			return "", err
		}
		if truthy(role.Get("protected")) {
			return "", core.NewIamError("PROTECTED_RESOURCE", "Use owner transfer for protected roles", 403)
		}
		if err := Allow(ctx, server, tx, principal, tenantID, "iam:bindings:create", jsString(role.Get("id")), "grant this role"); err != nil {
			return "", err
		}
	}
	for _, groupID := range groupIDs {
		group, err := server.Scoped(ctx, tx, "groups", groupID, tenantID)
		if err != nil {
			return "", err
		}
		if err := AssertNotTeamGroup(group); err != nil {
			return "", err
		}
		if err := Allow(ctx, server, tx, principal, tenantID, "iam:groups:update", groupID, "add to this group"); err != nil {
			return "", err
		}
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupID), nil)
		if err != nil {
			return "", err
		}
		for _, binding := range bindings {
			if _, err := server.GrantingAuthority(ctx, tx, principal, tenantID, identityAuthorityArg(binding.Get("authorityId"))); err != nil {
				return "", err
			}
		}
	}
	// The guest claims the seats of licensed groups (re-checked at redemption, inviterStillGrants).
	if err := AssertMayClaimLicenses(ctx, server, tx, principal, tenantID, groupIDs,
		"A group you invite the guest into carries license seats; that needs iam:licenses:assign"); err != nil {
		return "", err
	}
	for _, packageID := range packageIDs {
		pkg, err := server.Scoped(ctx, tx, "accessPackages", packageID, tenantID)
		if err != nil {
			return "", err
		}
		if err := Allow(ctx, server, tx, principal, tenantID, "iam:packages:assign", jsString(pkg.Get("id")), "assign this package"); err != nil {
			return "", err
		}
		if _, err := AuthorizePackage(ctx, server, tx, principal, pkg, nil); err != nil {
			return "", err
		}
	}
	return authorityID, nil
}

// inviterStillGrants (api/guests.ts): an invitation grants no more than its inviter could grant directly, at
// redemption as when it was sent: the inviter must still be active and hold iam:guests:invite, the invitation's grant
// authority, iam:bindings:create on each role, iam:groups:update on each group with the authorities of the group's
// bindings (and iam:licenses:assign when a license product is assigned to one of them), and iam:packages:assign on
// each package with the rights to assign it by hand. Returns the inviter as a simulated principal, under whom the
// grants are made.
func inviterStillGrants(ctx context.Context, server *ServerContext, tx core.IamStore, invitation *core.Object, tenantID string) (*Principal, error) {
	refused := func(message ...string) error {
		text := "The inviter can no longer grant this access"
		if len(message) > 0 {
			text = message[0]
		}
		return core.NewIamError("INVITATION_INVALID", text)
	}
	inviter, err := tx.Get(ctx, "identities", jsString(invitation.Get("invitedBy")))
	if err != nil {
		return nil, err
	}
	if inviter == nil || inviter.Get("status") != "active" || server.IdentityExpired(inviter) {
		return nil, refused("The inviter can no longer invite guests")
	}
	asInviter := server.Decisions.SimulatedPrincipal(inviter, true)
	may := func(action, resourceID string) (bool, error) {
		return guestDecide(ctx, server, tx, asInviter, tenantID, action, resourceID)
	}
	holds := func(authorityID any) bool {
		_, err := server.GrantingAuthority(ctx, tx, asInviter, tenantID, identityAuthorityArg(authorityID))
		return err == nil
	}
	if allowed, err := may("iam:guests:invite", "guests/invitations"); err != nil {
		return nil, err
	} else if !allowed {
		return nil, refused("The inviter can no longer invite guests")
	}
	if authorityID := invitation.Get("authorityId"); !isUndefined(authorityID) && !holds(authorityID) {
		return nil, refused()
	}
	for _, roleID := range flowStrings(invitation.Get("roleIds")) {
		role, err := tx.Get(ctx, "roles", roleID)
		if err != nil {
			return nil, err
		}
		if role == nil || !core.StrictEquals(role.Get("tenantId"), tenantID) || truthy(role.Get("protected")) {
			return nil, refused()
		}
		if allowed, err := may("iam:bindings:create", jsString(role.Get("id"))); err != nil {
			return nil, err
		} else if !allowed {
			return nil, refused()
		}
	}
	groupIDs := flowStrings(invitation.Get("groupIds"))
	for _, groupID := range groupIDs {
		group, err := tx.Get(ctx, "groups", groupID)
		if err != nil {
			return nil, err
		}
		if group == nil || !core.StrictEquals(group.Get("tenantId"), tenantID) {
			return nil, refused()
		}
		team, err := IsTeamGroup(group)
		if err != nil {
			return nil, err
		}
		if team {
			return nil, refused()
		}
		if allowed, err := may("iam:groups:update", jsString(group.Get("id"))); err != nil {
			return nil, err
		} else if !allowed {
			return nil, refused()
		}
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", group.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, binding := range bindings {
			if !holds(binding.Get("authorityId")) {
				return nil, refused()
			}
		}
	}
	// Groups that carry license seats, then or since, need the inviter's iam:licenses:assign.
	if err := AssertMayClaimLicenses(ctx, server, tx, asInviter, tenantID, groupIDs, ""); err != nil {
		var denied *OperationDenied
		if !errors.As(err, &denied) {
			return nil, err
		}
		return nil, refused()
	}
	for _, packageID := range flowStrings(invitation.Get("packageIds")) {
		pkg, err := tx.Get(ctx, "accessPackages", packageID)
		if err != nil {
			return nil, err
		}
		if pkg == nil || !core.StrictEquals(pkg.Get("tenantId"), tenantID) {
			return nil, refused()
		}
		if allowed, err := may("iam:packages:assign", jsString(pkg.Get("id"))); err != nil {
			return nil, err
		} else if !allowed {
			return nil, refused()
		}
		if _, err := AuthorizePackage(ctx, server, tx, asInviter, pkg, nil); err != nil {
			if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
				return nil, err
			}
			return nil, refused()
		}
	}
	return asInviter, nil
}

// sendGuestInvitation (api/guests.ts sendInvitation): emails a guest invitation (template `guest-invitation`) with its
// token.
func sendGuestInvitation(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, invitation *core.Object, secret string, names *guestNames) error {
	inviterName, err := names.of(ctx, invitation.Get("invitedBy"))
	if err != nil {
		return err
	}
	sponsorName, err := names.of(ctx, invitation.Get("sponsorId"))
	if err != nil {
		return err
	}
	tenantID := jsString(tenant.Get("id"))
	payload := core.NewObject("tenantId", tenantID, "tenantName", tenant.Get("name"))
	if truthy(inviterName) {
		payload.Set("inviterName", inviterName)
	}
	if truthy(sponsorName) {
		payload.Set("sponsorName", sponsorName)
	}
	if message := invitation.Get("message"); truthy(message) {
		payload.Set("message", message)
	}
	payload.Set("token", secret)
	payload.Set("expiresAt", guestISO(invitation.Get("expiresAt")))
	_, err = server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
		TenantID: tenantID, Kind: "email", To: jsString(invitation.Get("email")), Template: "guest-invitation", Payload: payload,
	})
	return err
}

// guestEndPointer is a number-or-undefined end as RetimeAssignment takes it.
func guestEndPointer(end any) *float64 {
	if value, ok := end.(float64); ok {
		return &value
	}
	return nil
}

// followAccessEnd (api/guests.ts): moves the end of what the invitation granted (the account's tracked bindings,
// memberships and package assignments) from `previous`, the end they were last given (`grantsEndAt`), to `next`
// (undefined: no end). Grants whose end was changed since, and package assignments the package's maximum duration
// would not allow, keep theirs. A package assignment lengthens only the memberships it created at redemption
// (`grants.packageMembershipIds`). When the end moves later and `claim` is given, it is first shown the groups whose
// memberships move (convertToMember asks it for iam:licenses:assign).
func followAccessEnd(ctx context.Context, server *ServerContext, tx core.IamStore, account *core.Object, previous any, next any, actorID string, claim func(groupIDs []string) error) error {
	if isUndefined(previous) || core.StrictEquals(previous, next) {
		return nil
	}
	retime := func(record *core.Object) *core.Object {
		rest := record.Spread()
		rest.Delete("expiresAt")
		if isUndefined(next) {
			return rest
		}
		return rest.Set("expiresAt", next)
	}
	grants := account.Get("grants")
	tenantID, identityID := account.Get("tenantId"), account.Get("identityId")
	var bindings []*core.Object
	for _, bindingID := range flowStrings(member(grants, "bindingIds")) {
		binding, err := tx.Get(ctx, "bindings", bindingID)
		if err != nil {
			return err
		}
		if binding == nil || !core.StrictEquals(binding.Get("tenantId"), tenantID) || binding.Get("subjectType") != "identity" ||
			!core.StrictEquals(binding.Get("subjectId"), identityID) || !core.StrictEquals(binding.Get("expiresAt"), previous) {
			continue
		}
		bindings = append(bindings, binding)
	}
	var members []*core.Object
	for _, membershipID := range flowStrings(member(grants, "membershipIds")) {
		membership, err := tx.Get(ctx, "groupMembers", membershipID)
		if err != nil {
			return err
		}
		if membership == nil || !core.StrictEquals(membership.Get("tenantId"), tenantID) ||
			!core.StrictEquals(membership.Get("identityId"), identityID) || !core.StrictEquals(membership.Get("expiresAt"), previous) {
			continue
		}
		members = append(members, membership)
	}
	type packaged struct{ pkg, assignment *core.Object }
	var assignments []packaged
	for _, assignmentID := range flowStrings(member(grants, "packageAssignmentIds")) {
		assignment, err := tx.Get(ctx, "packageAssignments", assignmentID)
		if err != nil {
			return err
		}
		if assignment == nil || !core.StrictEquals(assignment.Get("tenantId"), tenantID) ||
			!core.StrictEquals(assignment.Get("identityId"), identityID) || !core.StrictEquals(assignment.Get("expiresAt"), previous) {
			continue
		}
		pkg, err := tx.Get(ctx, "accessPackages", jsString(assignment.Get("packageId")))
		if err != nil {
			return err
		}
		if pkg == nil || !core.StrictEquals(pkg.Get("tenantId"), tenantID) {
			continue
		}
		if maxDuration := pkg.Get("maxDurationMs"); !isUndefined(maxDuration) &&
			(isUndefined(next) || jsNumber(next) > float64(server.Now())+jsNumber(maxDuration)) {
			continue
		}
		assignments = append(assignments, packaged{pkg: pkg, assignment: assignment})
	}
	// Accounts redeemed before the package memberships were recorded lengthen the assignments' own memberships.
	created := func(assignment *core.Object) []string {
		if recorded := member(grants, "packageMembershipIds"); !nullish(recorded) {
			return flowStrings(recorded)
		}
		return flowStrings(assignment.Get("membershipIds"))
	}
	if claim != nil && (isUndefined(next) || jsNumber(next) > jsNumber(previous)) {
		groupIDs := make([]string, 0, len(members))
		for _, membership := range members {
			groupIDs = append(groupIDs, jsString(membership.Get("groupId")))
		}
		for _, entry := range assignments {
			lengthened := created(entry.assignment)
			for _, membershipID := range flowStrings(entry.assignment.Get("membershipIds")) {
				if !containsString(lengthened, membershipID) {
					continue
				}
				membership, err := tx.Get(ctx, "groupMembers", membershipID)
				if err != nil {
					return err
				}
				if membership != nil && core.StrictEquals(membership.Get("packageAssignmentId"), entry.assignment.Get("id")) &&
					server.LiveMembership(membership) && containsString(flowStrings(entry.pkg.Get("groupIds")), jsString(membership.Get("groupId"))) {
					groupIDs = append(groupIDs, jsString(membership.Get("groupId")))
				}
			}
		}
		if err := claim(groupIDs); err != nil {
			return err
		}
	}
	for _, binding := range bindings {
		if _, err := tx.Put(ctx, "bindings", retime(binding)); err != nil {
			return err
		}
	}
	for _, membership := range members {
		if _, err := tx.Put(ctx, "groupMembers", retime(membership)); err != nil {
			return err
		}
	}
	// Teams that sync their members from these groups follow the new end (teams.ts).
	groups := newOrderedSet()
	for _, membership := range members {
		groups.Add(jsString(membership.Get("groupId")))
	}
	for _, groupID := range groups.Values() {
		if _, err := SyncTeamsFromGroups(ctx, server, tx, jsString(tenantID), core.NewObject("groupId", groupID, "actorId", actorID)); err != nil {
			return err
		}
	}
	for _, entry := range assignments {
		if _, err := RetimeAssignment(ctx, server, tx, entry.pkg, entry.assignment, guestEndPointer(next), created(entry.assignment)); err != nil {
			return err
		}
	}
	return nil
}

// attestGuest renews a guest's access; `asSponsor` when the caller is the guest's sponsor acting without
// iam:guests:manage.
func (api *GuestsAPI) attestGuest(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string, identityID string, days any, asSponsor bool) (*core.Object, error) {
	server := api.server
	if core.StrictEquals(principal.Identity.Get("id"), identityID) {
		return nil, NewOperationDenied("Guests cannot renew their own access")
	}
	if isGuest(principal.Identity) {
		return nil, NewOperationDenied("Guests cannot renew guests’ access")
	}
	account, identity, err := loadGuest(ctx, tx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	if asSponsor && (!core.StrictEquals(account.Get("sponsorId"), principal.Identity.Get("id")) || !canSponsor(server, principal.Identity, tenantID)) {
		return nil, core.NewIamError("ACCESS_DENIED", "Only the guest’s sponsor or an administrator can renew their access", 403)
	}
	if account.Get("status") != "active" || !truthy(identity.Get("guest")) || identity.Get("status") != "active" || server.IdentityExpired(identity) {
		return nil, core.NewIamError("INVALID_TRANSITION", "This guest is disabled or their access has ended: an administrator can restore it (a later expiresAt, then re-enable the account), or delete the account and invite the person again", 409)
	}
	settings, err := GuestSettings(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	accessDays, err := Integer(coalesce(days, settings.Get("accessDays")), "days", 1, GuestLimits.MaxAccessDays)
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	expiresAt := now + accessDays*GuestDayMs
	// A guest who owns the organization keeps an owner's protection: their sponsor alone cannot move their end.
	if err := assertOwnerExpiryControl(ctx, server, tx, principal, identity, expiresAt); err != nil {
		return nil, err
	}
	previous := identity.Get("expiresAt")
	updated, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("expiresAt", expiresAt)))
	if err != nil {
		return nil, err
	}
	actorID := jsString(principal.Identity.Get("id"))
	if err := followAccessEnd(ctx, server, tx, account, account.Get("grantsEndAt"), expiresAt, actorID, nil); err != nil {
		return nil, err
	}
	reviewDueAt := math.Min(now+jsNumber(settings.Get("reviewEveryDays"))*GuestDayMs, expiresAt)
	renewed, err := tx.Put(ctx, GuestCollections.Accounts, account.Spread(core.NewObject(
		"attestedAt", now,
		"attestedBy", principal.Identity.Get("id"),
		"reviewDueAt", reviewDueAt,
		"grantsEndAt", expiresAt,
	)))
	if err != nil {
		return nil, err
	}
	metadata := core.NewObject("days", accessDays, "expiresAt", expiresAt, "reviewDueAt", reviewDueAt, "asSponsor", asSponsor)
	if !isUndefined(previous) {
		metadata.Set("previousExpiresAt", previous)
	}
	if err := server.Events.Audit(ctx, tx, principal, "guest:attest", tenantID, jsString(identity.Get("id")), "allow", false, metadata); err != nil {
		return nil, err
	}
	return guestView(ctx, server, tx, renewed, updated, nameReader(tx))
}

// guestStringList is `[...new Set(strings(value ?? [], name))]`.
func guestStringList(value any, name string) ([]string, error) {
	list, err := Strings(coalesce(value, []any{}), name)
	if err != nil {
		return nil, err
	}
	return unique(list), nil
}

// guestsDeliveryConfigured is `options.authentication?.sendEmail`.
func guestsDeliveryConfigured(server *ServerContext) bool {
	options := server.Options
	return options != nil && options.Authentication != nil && options.Authentication.SendEmail != nil
}

// Attest is POST {basePath}/guests/attest. Renews a guest's access: their access (and what the invitation granted with
// it) now ends `days` from now (1 to 365, default the tenant's `accessDays`), and the next review is due after the
// tenant's `reviewEveryDays`. The guest's sponsor may do it without any permission; anyone else needs
// iam:guests:manage on iam/guests/{identityId}. Guests renew nobody's access, their own included. An ended or disabled
// guest is refused (INVALID_TRANSITION). Audited as `guest:attest`.
func (api *GuestsAPI) Attest(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsAttestInput]) (Out[apitypes.GuestsAttestOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.GuestsAttestOutput]{}, err
	}
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.GuestsAttestOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.GuestsAttestOutput]{}, err
	}
	sponsoring, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		account, err := tx.Get(ctx, GuestCollections.Accounts, identityID)
		if err != nil {
			return false, err
		}
		return account != nil && core.StrictEquals(account.Get("tenantId"), tenantID) &&
			core.StrictEquals(account.Get("sponsorId"), authenticated.Identity.Get("id")), nil
	})
	if err != nil {
		return Out[apitypes.GuestsAttestOutput]{}, err
	}
	// Anyone but the sponsor goes through the permission check (and its audit).
	if !sponsoring {
		view, err := Operate(ctx, server.Operations, credential, tenantID, "iam:guests:manage", guestResource(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
			return api.attestGuest(ctx, call.Tx, call.Principal, tenantID, identityID, input.Get("days"), false)
		}, false)
		if err != nil {
			return Out[apitypes.GuestsAttestOutput]{}, err
		}
		return Out[apitypes.GuestsAttestOutput]{Value: view}, nil
	}
	view, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := server.Auth.AssertTenantActive(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := guestOwnSession(principal, tenantID, "Sponsors renew their guests’ access"); err != nil {
			return nil, err
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "A guest’s access cannot be renewed while impersonating", 403)
		}
		return api.attestGuest(ctx, tx, principal, tenantID, identityID, input.Get("days"), true)
	})
	if err != nil {
		return Out[apitypes.GuestsAttestOutput]{}, err
	}
	return Out[apitypes.GuestsAttestOutput]{Value: view}, nil
}

// guestNext is the `next` copy configure edits: inbound and outbound copied, the rest as the current settings.
func guestNext(current *core.Object) *core.Object {
	next := core.NewObject(
		"inbound", guestShallow(current.Get("inbound")),
		"outbound", guestShallow(current.Get("outbound")),
		"accessDays", current.Get("accessDays"),
		"reviewEveryDays", current.Get("reviewEveryDays"),
	)
	if boundary := current.Get("guestBoundary"); truthy(boundary) {
		next.Set("guestBoundary", boundary)
	}
	return next
}

// guestShallow is `{ ...value }`.
func guestShallow(value any) *core.Object {
	if object, ok := value.(*core.Object); ok && object != nil {
		return object.Spread()
	}
	return core.NewObject()
}

// guestPartnerPairs is `list.map((partner) => ({ tenantId: partner.tenantId, allow: partner.allow }))`.
func guestPartnerPairs(list any) []any {
	items, _ := list.([]any)
	out := make([]any, len(items))
	for index, partner := range items {
		out[index] = core.NewObject("tenantId", member(partner, "tenantId"), "allow", member(partner, "allow"))
	}
	return out
}

// Configure is POST {basePath}/guests/configure. Changes the tenant's cross-tenant access settings; only the fields
// given change (inside `inbound` and `outbound` too). Domains are lowercase host names matching themselves and their
// subdomains; partners name existing tenants other than this one; `guestBoundary` is validated like any policy (null
// removes it). Requires recent authentication and iam:guests:settings on iam/guests/settings; audited as
// `guest:settings`.
func (api *GuestsAPI) Configure(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsConfigureInput]) (Out[apitypes.GuestsConfigureOutput], error) {
	server := api.server
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:settings", "guests/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		// A misspelled setting (a `guestBoundry`) must fail rather than leave the tenant as it was.
		if _, err := guestFields(input.Body, "guest", []string{"tenantId", "inbound", "outbound", "accessDays", "reviewEveryDays", "guestBoundary"}); err != nil {
			return nil, err
		}
		stored, err := ReadGuestSettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		current, err := GuestSettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		next := guestNext(current)
		nextInbound, _ := next.Get("inbound").(*core.Object)
		nextOutbound, _ := next.Get("outbound").(*core.Object)
		changed := []string{}
		if raw := input.Get("inbound"); !isUndefined(raw) {
			inbound, err := guestFields(raw, "inbound", []string{"allowGuests", "allowedDomains", "blockedDomains", "partners"})
			if err != nil {
				return nil, err
			}
			if value := inbound.Get("allowGuests"); !isUndefined(value) {
				allow, err := guestFlag(value, "inbound.allowGuests")
				if err != nil {
					return nil, err
				}
				nextInbound.Set("allowGuests", allow)
			}
			if value := inbound.Get("allowedDomains"); !isUndefined(value) {
				domains, err := guestDomainList(value, "inbound.allowedDomains")
				if err != nil {
					return nil, err
				}
				nextInbound.Set("allowedDomains", domains)
			}
			if value := inbound.Get("blockedDomains"); !isUndefined(value) {
				domains, err := guestDomainList(value, "inbound.blockedDomains")
				if err != nil {
					return nil, err
				}
				nextInbound.Set("blockedDomains", domains)
			}
			if value := inbound.Get("partners"); !isUndefined(value) {
				partners, err := guestPartnerList(ctx, tx, tenantID, value, "inbound.partners")
				if err != nil {
					return nil, err
				}
				nextInbound.Set("partners", partners)
			}
			for _, key := range inbound.Keys() {
				changed = append(changed, "inbound."+key)
			}
		}
		if raw := input.Get("outbound"); !isUndefined(raw) {
			outbound, err := guestFields(raw, "outbound", []string{"allowGuestInvitations", "partners"})
			if err != nil {
				return nil, err
			}
			if value := outbound.Get("allowGuestInvitations"); !isUndefined(value) {
				allow, err := guestFlag(value, "outbound.allowGuestInvitations")
				if err != nil {
					return nil, err
				}
				nextOutbound.Set("allowGuestInvitations", allow)
			}
			if value := outbound.Get("partners"); !isUndefined(value) {
				partners, err := guestPartnerList(ctx, tx, tenantID, value, "outbound.partners")
				if err != nil {
					return nil, err
				}
				nextOutbound.Set("partners", partners)
			}
			for _, key := range outbound.Keys() {
				changed = append(changed, "outbound."+key)
			}
		}
		if raw := input.Get("accessDays"); !isUndefined(raw) {
			days, err := Integer(raw, "accessDays", 1, GuestLimits.MaxAccessDays)
			if err != nil {
				return nil, err
			}
			next.Set("accessDays", days)
			changed = append(changed, "accessDays")
		}
		if raw := input.Get("reviewEveryDays"); !isUndefined(raw) {
			days, err := Integer(raw, "reviewEveryDays", GuestLimits.MinReviewEveryDays, GuestLimits.MaxReviewEveryDays)
			if err != nil {
				return nil, err
			}
			next.Set("reviewEveryDays", days)
			changed = append(changed, "reviewEveryDays")
		}
		if raw := input.Get("guestBoundary"); !isUndefined(raw) {
			if raw == nil {
				next.Delete("guestBoundary")
			} else {
				if err := server.Catalog.Validate(ctx, tx, tenantID, raw); err != nil {
					return nil, err
				}
				next.Set("guestBoundary", raw)
			}
			changed = append(changed, "guestBoundary")
		}
		if len(changed) == 0 {
			return nil, invalidInput("Nothing to change")
		}
		record := core.NewObject("id", tenantID, "tenantId", tenantID).Assign(next)
		record.Set("updatedAt", float64(server.Now()))
		record.Set("updatedBy", principal.Identity.Get("id"))
		if stored != nil {
			if _, err := tx.Put(ctx, GuestCollections.Settings, record); err != nil {
				return nil, err
			}
		} else if _, err := tx.Insert(ctx, GuestCollections.Settings, record); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "guest:settings", tenantID, tenantID, "allow", false, core.NewObject(
			"changed", stringsOf(changed),
			"allowGuests", nextInbound.Get("allowGuests"),
			"allowedDomains", nextInbound.Get("allowedDomains"),
			"blockedDomains", nextInbound.Get("blockedDomains"),
			"inboundPartners", guestPartnerPairs(nextInbound.Get("partners")),
			"allowGuestInvitations", nextOutbound.Get("allowGuestInvitations"),
			"outboundPartners", guestPartnerPairs(nextOutbound.Get("partners")),
			"accessDays", next.Get("accessDays"),
			"reviewEveryDays", next.Get("reviewEveryDays"),
			"guestBoundary", !isUndefined(next.Get("guestBoundary")),
		)); err != nil {
			return nil, err
		}
		return guestSettingsView(tenantID, next, record), nil
	}, false)
	if err != nil {
		return Out[apitypes.GuestsConfigureOutput]{}, err
	}
	return Out[apitypes.GuestsConfigureOutput]{Value: view}, nil
}

// ConvertToMember is POST {basePath}/guests/convertToMember. Makes an active guest an ordinary member: the `guest`
// marker goes, the guest account closes as `converted`, and the access end stays unless `clearExpiry` removes it
// together with the end of what the invitation granted. Requires recent authentication and iam:guests:manage on
// iam/guests/{identityId}, and with `clearExpiry` iam:licenses:assign when a license product is assigned to a group
// whose membership would lose its end; audited as `guest:convert`.
func (api *GuestsAPI) ConvertToMember(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsConvertToMemberInput]) (Out[apitypes.GuestsConvertToMemberOutput], error) {
	server := api.server
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.GuestsConvertToMemberOutput]{}, err
	}
	clearExpiry := false
	if raw := input.Get("clearExpiry"); !isUndefined(raw) {
		if clearExpiry, err = guestFlag(raw, "clearExpiry"); err != nil {
			return Out[apitypes.GuestsConvertToMemberOutput]{}, err
		}
	}
	converted, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:manage", guestResource(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		// Becoming a member lifts the guest boundary (and, with clearExpiry, the end): guests never make anyone a
		// member, themselves included, as they never renew anyone (attest).
		if core.StrictEquals(principal.Identity.Get("id"), identityID) {
			return nil, NewOperationDenied("Guests cannot make themselves members")
		}
		if isGuest(principal.Identity) {
			return nil, NewOperationDenied("Guests cannot make guests members")
		}
		account, identity, err := loadGuest(ctx, tx, tenantID, identityID)
		if err != nil {
			return nil, err
		}
		if account.Get("status") != "active" || !truthy(identity.Get("guest")) || identity.Get("status") != "active" || server.IdentityExpired(identity) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only an active guest can become a member", 409)
		}
		// Clearing an owner's end changes an owner's expiry.
		if clearExpiry && !isUndefined(identity.Get("expiresAt")) {
			if err := assertOwnerExpiryControl(ctx, server, tx, principal, identity, core.Undefined); err != nil {
				return nil, err
			}
		}
		previous := identity.Get("expiresAt")
		memberRecord := identity.Spread()
		memberRecord.Delete("guest")
		memberRecord.Delete("expiresAt")
		if !clearExpiry && !isUndefined(previous) {
			memberRecord.Set("expiresAt", previous)
		}
		updated, err := tx.Put(ctx, "identities", memberRecord)
		if err != nil {
			return nil, err
		}
		actorID := jsString(principal.Identity.Get("id"))
		// Keeping the guest in a licensed group for good is a claim on its seats, as clearing a membership's end is in
		// the groups API: unlike a renewal, which ends again, it needs iam:licenses:assign (api/groups.ts).
		if clearExpiry {
			if err := followAccessEnd(ctx, server, tx, account, account.Get("grantsEndAt"), core.Undefined, actorID, func(groupIDs []string) error {
				return AssertMayClaimLicenses(ctx, server, tx, principal, tenantID, groupIDs,
					"A group the guest would stay in for good carries license seats; clearing the end needs iam:licenses:assign")
			}); err != nil {
				return nil, err
			}
		}
		closed := account.Spread()
		if clearExpiry {
			closed.Delete("grantsEndAt")
		}
		if _, err := tx.Put(ctx, GuestCollections.Accounts, closed.Spread(core.NewObject(
			"status", "converted",
			"endedAt", float64(server.Now()),
			"endedBy", principal.Identity.Get("id"),
		))); err != nil {
			return nil, err
		}
		metadata := core.NewObject("sponsorId", account.Get("sponsorId"), "clearExpiry", clearExpiry)
		if !isUndefined(previous) {
			metadata.Set("expiresAt", previous)
		}
		if err := server.Events.Audit(ctx, tx, principal, "guest:convert", tenantID, jsString(identity.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return PublicIdentity(updated), nil
	}, false)
	if err != nil {
		return Out[apitypes.GuestsConvertToMemberOutput]{}, err
	}
	result, err := AfterIdentityChange(ctx, server, jsString(input.Get("tenantId")), []string{jsString(converted.Get("id"))}, converted)
	if err != nil {
		return Out[apitypes.GuestsConvertToMemberOutput]{}, err
	}
	return Out[apitypes.GuestsConvertToMemberOutput]{Value: result}, nil
}

// Get is POST {basePath}/guests/get. One guest. Requires iam:guests:read on iam/guests/{identityId}.
func (api *GuestsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsGetInput]) (Out[apitypes.GuestsGetOutput], error) {
	server := api.server
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.GuestsGetOutput]{}, err
	}
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:read", guestResource(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		account, identity, err := loadGuest(ctx, call.Tx, jsString(call.Tenant.Get("id")), identityID)
		if err != nil {
			return nil, err
		}
		return guestView(ctx, server, call.Tx, account, identity, nameReader(call.Tx))
	}, false)
	if err != nil {
		return Out[apitypes.GuestsGetOutput]{}, err
	}
	return Out[apitypes.GuestsGetOutput]{Value: view}, nil
}

// GetSettings is POST {basePath}/guests/getSettings. The tenant's cross-tenant access settings (the defaults until
// configured). Requires iam:guests:read on iam/guests/settings.
func (api *GuestsAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsGetSettingsInput]) (Out[apitypes.GuestsGetSettingsOutput], error) {
	view, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:guests:read", "guests/settings", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		settings, err := GuestSettings(ctx, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		stored, err := ReadGuestSettings(ctx, call.Tx, tenantID)
		if err != nil {
			return nil, err
		}
		return guestSettingsView(tenantID, settings, stored), nil
	}, false)
	if err != nil {
		return Out[apitypes.GuestsGetSettingsOutput]{}, err
	}
	return Out[apitypes.GuestsGetSettingsOutput]{Value: view}, nil
}

// Invite is POST {basePath}/guests/invite. Invites a person from outside the organization (or from another tenant) as
// a guest: emails them a personal invitation (template `guest-invitation`) to redeem within `expiresInDays`. Refused
// when the address already belongs to someone here or has a pending invitation (CONFLICT), is on one of the tenant's
// own verified domains, or when the tenant's inbound or the person's organization's outbound settings do not admit it
// (GUEST_NOT_ALLOWED). The sponsor is the caller unless `sponsorId` names another member. Roles, groups and packages
// are authorized now like `identities.invite` and granted at redemption under the caller's authority. Requires
// iam:guests:invite on iam/guests/invitations and an email delivery callback; audited as `guest:invite`.
func (api *GuestsAPI) Invite(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsInviteInput]) (Out[apitypes.GuestsInviteOutput], error) {
	server := api.server
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:invite", "guests/invitations", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		if !guestsDeliveryConfigured(server) {
			return nil, core.NewIamError("DELIVERY_REQUIRED", "Guest invitations require an email delivery callback")
		}
		if tenant.Get("status") != "active" {
			return nil, core.NewIamError("TENANT_INACTIVE", "Tenant must be active")
		}
		if tenant.Get("parentId") == nil {
			return nil, invalidInput("The platform tenant does not take guests")
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Guests cannot be invited while impersonating", 403)
		}
		// Redemption re-checks the inviter's rights as the inviter acting in their own right (inviterStillGrants); an
		// assumed role is not there to re-check, so an invitation sent from one could never be redeemed.
		if principal.Session.Get("kind") == "role" {
			return nil, NewOperationDenied("Guests are invited from your own session, not an assumed role")
		}
		tenantID := jsString(tenant.Get("id"))
		to, err := GuestAddress(input.Get("email"))
		if err != nil {
			return nil, err
		}
		settings, err := GuestSettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		accessDays, err := Integer(coalesce(input.Get("accessDays"), settings.Get("accessDays")), "accessDays", 1, GuestLimits.MaxAccessDays)
		if err != nil {
			return nil, err
		}
		lifetime, err := Integer(coalesce(input.Get("expiresInDays"), GuestLimits.InvitationDays), "expiresInDays", 1, GuestLimits.MaxInvitationDays)
		if err != nil {
			return nil, err
		}
		message := ""
		if raw := input.Get("message"); !isUndefined(raw) {
			text, err := Text(raw, "message", 1000)
			if err != nil {
				return nil, err
			}
			message = core.JSTrim(text)
		}
		roleIDs, err := guestStringList(input.Get("roleIds"), "roleIds")
		if err != nil {
			return nil, err
		}
		groupIDs, err := guestStringList(input.Get("groupIds"), "groupIds")
		if err != nil {
			return nil, err
		}
		packageIDs, err := guestStringList(input.Get("packageIds"), "packageIds")
		if err != nil {
			return nil, err
		}
		if err := assertNewcomer(ctx, tx, tenantID, to); err != nil {
			return nil, err
		}
		origin, err := GuestOrigin(ctx, tx, tenantID, to)
		if err != nil {
			return nil, err
		}
		if err := AssertGuestAdmitted(ctx, tx, settings, tenantID, origin); err != nil {
			return nil, err
		}
		sponsorID := input.Get("sponsorId")
		var sponsor *core.Object
		if !isUndefined(sponsorID) {
			if err := authorizeOtherSponsor(ctx, server, tx, principal, tenantID, sponsorID); err != nil {
				return nil, err
			}
			if sponsor, err = GuestSponsor(ctx, server, tx, tenantID, sponsorID); err != nil {
				return nil, err
			}
		} else if sponsor, err = guestCallerSponsor(server, principal, tenantID); err != nil {
			return nil, err
		}
		authorityID, err := authorizeGrants(ctx, server, tx, principal, tenantID, roleIDs, groupIDs, packageIDs)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		if err := claimPendingKey(ctx, tx, tenantID, to, now, ""); err != nil {
			return nil, err
		}
		secret := guestInvitationToken()
		invitation := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", guestPendingKey(to),
			"email", to,
			"tokenHash", Hash(secret),
			"sponsorId", sponsor.Get("id"),
			"invitedBy", principal.Identity.Get("id"),
		)
		if message != "" {
			invitation.Set("message", message)
		}
		invitation.Set("roleIds", stringsOf(roleIDs))
		invitation.Set("groupIds", stringsOf(groupIDs))
		invitation.Set("packageIds", stringsOf(packageIDs))
		if authorityID != "" {
			invitation.Set("authorityId", authorityID)
		}
		invitation.Set("accessDays", accessDays)
		homeTenantID := origin.Get("homeTenantId")
		if truthy(homeTenantID) {
			invitation.Set("homeTenantId", homeTenantID)
		}
		invitation.Set("expiresAt", now+lifetime*GuestDayMs)
		invitation.Set("createdAt", now)
		invitation.Set("sentAt", now)
		invitation.Set("status", "pending")
		if _, err := tx.Insert(ctx, GuestCollections.Invitations, invitation); err != nil {
			return nil, err
		}
		names := nameReader(tx)
		if err := sendGuestInvitation(ctx, server, tx, tenant, invitation, secret, names); err != nil {
			return nil, err
		}
		metadata := core.NewObject(
			"email", to,
			"sponsorId", sponsor.Get("id"),
			"roleIds", stringsOf(roleIDs),
			"groupIds", stringsOf(groupIDs),
			"packageIds", stringsOf(packageIDs),
			"accessDays", accessDays,
			"expiresAt", invitation.Get("expiresAt"),
		)
		if truthy(homeTenantID) {
			metadata.Set("homeTenantId", homeTenantID)
		}
		if err := server.Events.Audit(ctx, tx, principal, "guest:invite", tenantID, jsString(invitation.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return invitationView(ctx, server, invitation, names)
	}, false)
	if err != nil {
		return Out[apitypes.GuestsInviteOutput]{}, err
	}
	return Out[apitypes.GuestsInviteOutput]{Value: view}, nil
}

// List is POST {basePath}/guests/list. The tenant's guests by name, optionally those of one sponsor, one account
// `status`, or whose access ends within `expiringWithinDays`; `limit`/`offset` page through them. Requires
// iam:guests:read on iam/guests.
func (api *GuestsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsListInput]) (Out[apitypes.GuestsListOutput], error) {
	server := api.server
	limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
	if err != nil {
		return Out[apitypes.GuestsListOutput]{}, err
	}
	offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
	if err != nil {
		return Out[apitypes.GuestsListOutput]{}, err
	}
	status := input.Get("status")
	if !isUndefined(status) && !guestStatusIn(status, guestAccountStatuses) {
		return Out[apitypes.GuestsListOutput]{}, invalidInput("status must be active, expired, removed or converted")
	}
	var sponsorID any = core.Undefined
	if raw := input.Get("sponsorId"); !isUndefined(raw) {
		text, err := Text(raw, "sponsorId")
		if err != nil {
			return Out[apitypes.GuestsListOutput]{}, err
		}
		sponsorID = text
	}
	var within any = core.Undefined
	if raw := input.Get("expiringWithinDays"); !isUndefined(raw) {
		days, err := Integer(raw, "expiringWithinDays", 0, 3650)
		if err != nil {
			return Out[apitypes.GuestsListOutput]{}, err
		}
		within = days
	}
	page, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:read", "guests", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(call.Tenant.Get("id"))
		var horizon any = core.Undefined
		if !isUndefined(within) {
			horizon = float64(server.Now()) + jsNumber(within)*GuestDayMs
		}
		filter := core.NewObject("tenantId", tenantID)
		if !isUndefined(sponsorID) {
			filter.Set("sponsorId", sponsorID)
		}
		accounts, err := tx.Find(ctx, GuestCollections.Accounts, filter, nil)
		if err != nil {
			return nil, err
		}
		type row struct{ account, identity *core.Object }
		var rows []row
		for _, account := range accounts {
			identity, err := tx.Get(ctx, "identities", jsString(account.Get("identityId")))
			if err != nil {
				return nil, err
			}
			if identity == nil || !core.StrictEquals(identity.Get("tenantId"), tenantID) || identity.Get("status") == "deleted" {
				continue
			}
			if !isUndefined(status) && !core.StrictEquals(guestAccountStatus(server, account, identity), status) {
				continue
			}
			if !isUndefined(horizon) {
				expiresAt := identity.Get("expiresAt")
				if isUndefined(expiresAt) || jsNumber(expiresAt) > jsNumber(horizon) {
					continue
				}
			}
			rows = append(rows, row{account: account, identity: identity})
		}
		sortStable(rows, func(a, b row) int {
			if order := localeCompare(jsString(a.identity.Get("name")), jsString(b.identity.Get("name"))); order != 0 {
				return order
			}
			if compareUTF16(jsString(a.identity.Get("id")), jsString(b.identity.Get("id"))) < 0 {
				return -1
			}
			return 1
		})
		names := nameReader(tx)
		guests := []any{}
		start := int(math.Min(offset, float64(len(rows))))
		end := int(math.Min(offset+limit, float64(len(rows))))
		for _, entry := range rows[start:end] {
			view, err := guestView(ctx, server, tx, entry.account, entry.identity, names)
			if err != nil {
				return nil, err
			}
			guests = append(guests, view)
		}
		return core.NewObject("guests", guests, "total", float64(len(rows))), nil
	}, false)
	if err != nil {
		return Out[apitypes.GuestsListOutput]{}, err
	}
	return Out[apitypes.GuestsListOutput]{Value: page}, nil
}

// ListInvitations is POST {basePath}/guests/listInvitations. The tenant's guest invitations, newest first, optionally
// one `status` (a lapsed pending invitation counts as expired). Tokens are never returned. Requires iam:guests:read on
// iam/guests/invitations.
func (api *GuestsAPI) ListInvitations(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsListInvitationsInput]) (Out[apitypes.GuestsListInvitationsOutput], error) {
	server := api.server
	status := input.Get("status")
	if !isUndefined(status) && !guestStatusIn(status, guestInvitationStatuses) {
		return Out[apitypes.GuestsListInvitationsOutput]{}, invalidInput("status must be pending, redeemed, revoked or expired")
	}
	views, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:read", "guests/invitations", func(ctx context.Context, call MutationContext) ([]any, error) {
		names := nameReader(call.Tx)
		invitations, err := call.Tx.Find(ctx, GuestCollections.Invitations, core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sortStable(invitations, ByNewest)
		views := []any{}
		for _, invitation := range invitations {
			view, err := invitationView(ctx, server, invitation, names)
			if err != nil {
				return nil, err
			}
			if isUndefined(status) || core.StrictEquals(view.Get("status"), status) {
				views = append(views, view)
			}
		}
		return views, nil
	}, false)
	if err != nil {
		return Out[apitypes.GuestsListInvitationsOutput]{}, err
	}
	return Out[apitypes.GuestsListInvitationsOutput]{Value: views}, nil
}

// Mine is POST {basePath}/guests/mine. The active guests the caller sponsors, the soonest review first; needs only an
// ordinary session of the tenant (no permission).
func (api *GuestsAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsMineInput]) (Out[apitypes.GuestsMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.GuestsMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.GuestsMineOutput]{}, err
	}
	views, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := guestOwnSession(principal, tenantID, "The guests you sponsor are listed"); err != nil {
			return nil, err
		}
		names := nameReader(tx)
		accounts, err := tx.Find(ctx, GuestCollections.Accounts, core.NewObject("tenantId", tenantID, "sponsorId", principal.Identity.Get("id"), "status", "active"), nil)
		if err != nil {
			return nil, err
		}
		views := []*core.Object{}
		for _, account := range accounts {
			identity, err := tx.Get(ctx, "identities", jsString(account.Get("identityId")))
			if err != nil {
				return nil, err
			}
			if identity == nil || !core.StrictEquals(identity.Get("tenantId"), tenantID) || identity.Get("status") == "deleted" {
				continue
			}
			view, err := guestView(ctx, server, tx, account, identity, names)
			if err != nil {
				return nil, err
			}
			views = append(views, view)
		}
		sortStable(views, func(a, b *core.Object) int {
			if difference := jsNumber(a.Get("reviewDueAt")) - jsNumber(b.Get("reviewDueAt")); difference != 0 {
				if difference < 0 {
					return -1
				}
				return 1
			}
			if order := localeCompare(jsString(a.Get("name")), jsString(b.Get("name"))); order != 0 {
				return order
			}
			if compareUTF16(jsString(a.Get("identityId")), jsString(b.Get("identityId"))) < 0 {
				return -1
			}
			return 1
		})
		out := make([]any, len(views))
		for index, view := range views {
			out[index] = view
		}
		return out, nil
	})
	if err != nil {
		return Out[apitypes.GuestsMineOutput]{}, err
	}
	return Out[apitypes.GuestsMineOutput]{Value: views}, nil
}

// Redeem is POST {basePath}/guests/redeem (public: no request credential). Redeems a guest invitation with the
// invitee's name and a new password, creates the guest identity (email verified), and signs them in with a password
// session. The invitation must be pending and unexpired, the tenant's inbound and the home organization's outbound
// settings must still admit the person, the inviter must still be able to grant what the invitation grants, and the
// sponsor must still be able to sponsor (INVITATION_INVALID otherwise). Separation-of-duties rules and enforced
// invariants apply. Rate limited per tenant, client address and token; audited as `guest:redeem`.
func (api *GuestsAPI) Redeem(ctx context.Context, input In[apitypes.GuestsRedeemInput]) (Out[apitypes.GuestsRedeemOutput], error) {
	server := api.server
	authService := server.Auth
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.GuestsRedeemOutput]{}, err
	}
	presented, err := Text(input.Get("token"), "token", 512)
	if err != nil {
		return Out[apitypes.GuestsRedeemOutput]{}, err
	}
	name, err := Text(input.Get("name"), "name")
	if err != nil {
		return Out[apitypes.GuestsRedeemOutput]{}, err
	}
	// The guest signs in with this password from now on (the tenant's password rules apply when it is set).
	password, ok := input.Get("password").(string)
	if !ok {
		return Out[apitypes.GuestsRedeemOutput]{}, invalidInput("A password is required")
	}
	// Counted outside the transaction, so a refusal cannot roll the counters back. The client's own budget comes first
	// (with the network steps): a client refused there spends none of the budget every invitee shares.
	ip := ""
	if client := authService.CurrentClient(ctx); client != nil {
		ip = client.IP
	}
	if ip != "" {
		key, ok := core.IPCounterKey(ip)
		if !ok {
			key = ip
		}
		limit := int64(20)
		if err := authService.LimitAttempt(ctx, tenantID, "guest-redeem:ip:"+key, auth.LimitAttemptOptions{Limit: &limit}); err != nil {
			return Out[apitypes.GuestsRedeemOutput]{}, err
		}
	}
	shared := int64(500)
	if err := authService.LimitAttempt(ctx, tenantID, "guest-redeem", auth.LimitAttemptOptions{Limit: &shared, SkipClient: ip != ""}); err != nil {
		return Out[apitypes.GuestsRedeemOutput]{}, err
	}
	perToken := int64(10)
	if err := authService.LimitAttempt(ctx, tenantID, "guest-redeem:"+Hash(presented), auth.LimitAttemptOptions{Limit: &perToken, SkipClient: true}); err != nil {
		return Out[apitypes.GuestsRedeemOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		realmID := jsString(realm.Get("id"))
		if err := authService.AssertTenantActive(ctx, tx, realmID); err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, GuestCollections.Invitations, core.NewObject("tenantId", realmID, "tokenHash", Hash(presented)), nil)
		if err != nil {
			return nil, err
		}
		var invitation *core.Object
		if len(found) > 0 {
			invitation = found[0]
		}
		now := float64(server.Now())
		if invitation == nil || invitation.Get("status") != "pending" || jsNumber(invitation.Get("expiresAt")) <= now {
			return nil, core.NewIamError("INVITATION_INVALID", "Invitation is invalid")
		}
		// Either side may have changed its settings (or verified the domain) since the invitation was sent.
		settings, err := GuestSettings(ctx, tx, realmID)
		if err != nil {
			return nil, err
		}
		address := jsString(invitation.Get("email"))
		origin, err := GuestOrigin(ctx, tx, realmID, address)
		if err != nil {
			return nil, err
		}
		if err := AssertGuestAdmitted(ctx, tx, settings, realmID, origin); err != nil {
			return nil, err
		}
		asInviter, err := inviterStillGrants(ctx, server, tx, invitation, realmID)
		if err != nil {
			return nil, err
		}
		sponsor, err := tx.Get(ctx, "identities", jsString(invitation.Get("sponsorId")))
		if err != nil {
			return nil, err
		}
		if !canSponsor(server, sponsor, realmID) {
			return nil, core.NewIamError("INVITATION_INVALID", "The sponsor can no longer sponsor guests")
		}
		guardrails, err := InvariantSnapshot(ctx, server, tx, realmID, "iam:identities:create")
		if err != nil {
			return nil, err
		}
		created, err := authService.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: realmID, Email: address, Name: name, Password: password, HasPassword: true, EmailVerified: true,
		})
		if err != nil {
			return nil, err
		}
		expiresAt := now + jsNumber(invitation.Get("accessDays"))*GuestDayMs
		marker := core.NewObject("sponsorId", sponsor.Get("id"), "since", now, "homeDomain", origin.Get("domain"))
		homeTenantID := origin.Get("homeTenantId")
		if truthy(homeTenantID) {
			marker.Set("homeTenantId", homeTenantID)
		}
		identity, err := tx.Put(ctx, "identities", created.Spread(core.NewObject("expiresAt", expiresAt, "guest", marker)))
		if err != nil {
			return nil, err
		}
		identityID := jsString(identity.Get("id"))
		bindingIDs, membershipIDs, assignmentIDs, packageMembershipIDs := []any{}, []any{}, []any{}, []any{}
		for _, roleID := range flowStrings(invitation.Get("roleIds")) {
			binding, err := tx.Insert(ctx, "bindings", core.NewObject(
				"id", ID(),
				"tenantId", realmID,
				"uniqueKey", "identity:"+identityID+":"+roleID+":"+jsString(invitation.Get("authorityId")),
				"subjectType", "identity",
				"subjectId", identityID,
				"roleId", roleID,
				"authorityId", invitation.Get("authorityId"),
				"expiresAt", expiresAt,
			))
			if err != nil {
				return nil, err
			}
			bindingIDs = append(bindingIDs, binding.Get("id"))
		}
		for _, groupID := range flowStrings(invitation.Get("groupIds")) {
			membership, err := tx.Insert(ctx, "groupMembers", core.NewObject(
				"id", ID(),
				"tenantId", realmID,
				"uniqueKey", groupID+":"+identityID,
				"groupId", groupID,
				"identityId", identityID,
				"expiresAt", expiresAt,
			))
			if err != nil {
				return nil, err
			}
			membershipIDs = append(membershipIDs, membership.Get("id"))
			if _, err := SyncTeamsFromGroups(ctx, server, tx, realmID, core.NewObject("groupId", groupID, "actorId", invitation.Get("invitedBy"))); err != nil {
				return nil, err
			}
		}
		for _, packageID := range flowStrings(invitation.Get("packageIds")) {
			pkg, err := server.Scoped(ctx, tx, "accessPackages", packageID, realmID)
			if err != nil {
				return nil, err
			}
			// A package's maximum duration can end its assignment before the guest's access.
			end := expiresAt
			if maxDuration := pkg.Get("maxDurationMs"); !isUndefined(maxDuration) {
				end = math.Min(expiresAt, now+jsNumber(maxDuration))
			}
			assigned, err := AssignPackage(ctx, server, tx, asInviter, pkg, core.NewObject(
				"identityId", identityID,
				"expiresAt", end,
				"justification", "Guest invitation "+jsString(invitation.Get("id")),
			), nil)
			if err != nil {
				return nil, err
			}
			assignment, _ := assigned.Get("assignment").(*core.Object)
			assignmentIDs = append(assignmentIDs, member(assignment, "id"))
			for _, membershipID := range flowStrings(member(assignment, "membershipIds")) {
				packageMembershipIDs = append(packageMembershipIDs, membershipID)
			}
		}
		if err := SodAssertIdentity(ctx, server, tx, realmID, identityID); err != nil {
			return nil, err
		}
		if err := InvariantVerify(ctx, server, tx, realmID, guardrails); err != nil {
			return nil, err
		}
		account := core.NewObject(
			"id", identityID,
			"tenantId", realmID,
			"identityId", identityID,
			"sponsorId", sponsor.Get("id"),
			"email", address,
		)
		if truthy(homeTenantID) {
			account.Set("homeTenantId", homeTenantID)
		}
		account.Set("source", "invitation")
		account.Set("invitationId", invitation.Get("id"))
		account.Set("invitedBy", invitation.Get("invitedBy"))
		account.Set("redeemedAt", now)
		account.Set("reviewDueAt", math.Min(now+jsNumber(settings.Get("reviewEveryDays"))*GuestDayMs, expiresAt))
		account.Set("status", "active")
		account.Set("grants", core.NewObject(
			"bindingIds", bindingIDs,
			"membershipIds", membershipIDs,
			"packageAssignmentIds", assignmentIDs,
			"packageMembershipIds", packageMembershipIDs,
		))
		account.Set("grantsEndAt", expiresAt)
		if _, err := tx.Insert(ctx, GuestCollections.Accounts, account); err != nil {
			return nil, err
		}
		rest := invitation.Spread()
		rest.Delete("uniqueKey")
		if _, err := tx.Put(ctx, GuestCollections.Invitations, rest.Spread(core.NewObject(
			"status", "redeemed",
			"redeemedAt", now,
			"identityId", identityID,
		))); err != nil {
			return nil, err
		}
		metadata := core.NewObject(
			"invitationId", invitation.Get("id"),
			"invitedBy", invitation.Get("invitedBy"),
			"sponsorId", sponsor.Get("id"),
			"roleIds", invitation.Get("roleIds"),
			"groupIds", invitation.Get("groupIds"),
			"packageIds", invitation.Get("packageIds"),
			"expiresAt", expiresAt,
		)
		if truthy(homeTenantID) {
			metadata.Set("homeTenantId", homeTenantID)
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", realmID,
			"actorId", identityID,
			"action", "guest:redeem",
			"resourceId", identityID,
			"timestamp", now,
			"outcome", "allow",
			"metadata", metadata,
		)); err != nil {
			return nil, err
		}
		// The guest just set a password: a password sign-in, refused like one where the tenant does not accept them.
		issued, err := authService.CompleteAuthentication(ctx, tx, identity, "password", "")
		if err != nil {
			return nil, err
		}
		return enrollment(identity, issued), nil
	})
	if err != nil {
		return Out[apitypes.GuestsRedeemOutput]{}, err
	}
	// Birthright rules that test identity.guest apply now rather than at the next scheduled reconcile.
	after, err := AfterIdentityChange(ctx, server, tenantID, []string{jsString(member(result.Get("identity"), "id"))}, result)
	if err != nil {
		return Out[apitypes.GuestsRedeemOutput]{}, err
	}
	return Out[apitypes.GuestsRedeemOutput]{Value: after}, nil
}

// Remove is POST {basePath}/guests/remove. Removes a guest in one transaction: disables the identity, ends its
// sessions, keys and delegations, removes every role binding, group and team membership, package assignment,
// activation and relationship it holds (whichever authority granted them), cancels its pending requests and
// invitations, revokes the grant authorities it holds, and closes the guest account as `removed`. An owner is refused
// (transfer ownership first). Requires recent authentication and iam:guests:manage on iam/guests/{identityId};
// audited as `guest:remove` with the reason and counts.
func (api *GuestsAPI) Remove(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsRemoveInput]) (Out[apitypes.GuestsRemoveOutput], error) {
	server := api.server
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.GuestsRemoveOutput]{}, err
	}
	removal, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:manage", guestResource(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		reasonText, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		reason := core.JSTrim(reasonText)
		tenantID := jsString(tenant.Get("id"))
		account, identity, err := loadGuest(ctx, tx, tenantID, identityID)
		if err != nil {
			return nil, err
		}
		if status := account.Get("status"); status == "removed" || status == "converted" {
			return nil, core.NewIamError("INVALID_TRANSITION", "This guest was already removed or became a member", 409)
		}
		if core.StrictEquals(identity.Get("id"), principal.Identity.Get("id")) {
			return nil, invalidInput("You cannot remove yourself")
		}
		if truthy(identity.Get("owner")) {
			return nil, invalidInput("This guest owns the organization: transfer ownership first")
		}
		guestID := jsString(identity.Get("id"))
		actorID := jsString(principal.Identity.Get("id"))
		nowMs := server.Now()
		now := float64(nowMs)
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", guestID), nil)
		if err != nil {
			return nil, err
		}
		bindingCount, membershipCount, packageCount := 0.0, 0.0, 0.0
		// Package assignments first: they own their bindings and memberships, whichever authority issued them.
		assignments, err := tx.Find(ctx, "packageAssignments", core.NewObject("tenantId", tenantID, "identityId", guestID), nil)
		if err != nil {
			return nil, err
		}
		for _, assignment := range assignments {
			removed, err := RevokeAssignment(ctx, server, tx, assignment)
			if err != nil {
				return nil, err
			}
			bindingCount += jsNumber(member(removed, "bindings"))
			membershipCount += jsNumber(member(removed, "memberships"))
			packageCount++
		}
		activations, err := tx.Find(ctx, "bindingActivations", core.NewObject("tenantId", tenantID, "identityId", guestID), nil)
		if err != nil {
			return nil, err
		}
		for _, activation := range activations {
			if err := tx.Delete(ctx, "bindingActivations", jsString(activation.Get("id"))); err != nil {
				return nil, err
			}
		}
		bindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", guestID), nil)
		if err != nil {
			return nil, err
		}
		for _, binding := range bindings {
			if err := tx.Delete(ctx, "bindings", jsString(binding.Get("id"))); err != nil {
				return nil, err
			}
			bindingCount++
		}
		// Team memberships go first, taking the team-managed group memberships with them (teams.ts).
		if _, err := RemoveFromAllTeams(ctx, tx, tenantID, guestID, nowMs); err != nil {
			return nil, err
		}
		if _, err := ReleaseDepartments(ctx, tx, tenantID, guestID, nowMs, ""); err != nil {
			return nil, err
		}
		groups := newOrderedSet()
		memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", guestID), nil)
		if err != nil {
			return nil, err
		}
		for _, membership := range memberships {
			if err := tx.Delete(ctx, "groupMembers", jsString(membership.Get("id"))); err != nil {
				return nil, err
			}
			groups.Add(jsString(membership.Get("groupId")))
			membershipCount++
		}
		for _, groupID := range groups.Values() {
			if _, err := SyncTeamsFromGroups(ctx, server, tx, tenantID, core.NewObject("groupId", groupID, "actorId", actorID)); err != nil {
				return nil, err
			}
		}
		tuples, err := tx.Find(ctx, "relationships", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", guestID), nil)
		if err != nil {
			return nil, err
		}
		for _, tuple := range tuples {
			if err := tx.Delete(ctx, "relationships", jsString(tuple.Get("id"))); err != nil {
				return nil, err
			}
		}
		requests, err := tx.Find(ctx, "accessRequests", core.NewObject("tenantId", tenantID, "requesterId", guestID, "status", "pending"), nil)
		if err != nil {
			return nil, err
		}
		for _, request := range requests {
			if _, err := tx.Put(ctx, "accessRequests", request.Spread(core.NewObject("status", "cancelled", "reviewedAt", now))); err != nil {
				return nil, err
			}
		}
		packageRequests, err := tx.Find(ctx, "packageRequests", core.NewObject("tenantId", tenantID, "identityId", guestID, "status", "pending"), nil)
		if err != nil {
			return nil, err
		}
		for _, request := range packageRequests {
			if _, err := tx.Put(ctx, "packageRequests", request.Spread(core.NewObject("status", "cancelled", "decidedAt", now))); err != nil {
				return nil, err
			}
		}
		authorities, err := tx.Find(ctx, "grantAuthorities", core.NewObject("tenantId", tenantID, "identityId", guestID), nil)
		if err != nil {
			return nil, err
		}
		for _, authority := range authorities {
			if !truthy(authority.Get("revoked")) {
				if _, err := tx.Put(ctx, "grantAuthorities", authority.Spread(core.NewObject("revoked", true))); err != nil {
					return nil, err
				}
			}
		}
		if _, err := RevokeDelegationsOf(ctx, server, tx, identity, actorID); err != nil {
			return nil, err
		}
		if err := server.RevokeAll(ctx, tx, guestID); err != nil {
			return nil, err
		}
		if err := RevokeInvitationsBy(ctx, tx, guestID); err != nil {
			return nil, err
		}
		disabled, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("status", "disabled")))
		if err != nil {
			return nil, err
		}
		// A removed guest stays disabled: a threats containment of it can no longer be released.
		if err := EndContainment(ctx, tx, guestID, nowMs); err != nil {
			return nil, err
		}
		removed, err := tx.Put(ctx, GuestCollections.Accounts, account.Spread(core.NewObject(
			"status", "removed",
			"endedAt", now,
			"endedBy", principal.Identity.Get("id"),
			"removalReason", reason,
		)))
		if err != nil {
			return nil, err
		}
		counts := core.NewObject(
			"sessions", float64(len(sessions)),
			"bindings", bindingCount,
			"memberships", membershipCount,
			"packages", packageCount,
		)
		if err := server.Events.Audit(ctx, tx, principal, "guest:remove", tenantID, guestID, "allow", false,
			core.NewObject("reason", reason, "sponsorId", account.Get("sponsorId")).Assign(counts)); err != nil {
			return nil, err
		}
		view, err := guestView(ctx, server, tx, removed, disabled, nameReader(tx))
		if err != nil {
			return nil, err
		}
		return core.NewObject("guest", view).Assign(counts), nil
	}, false)
	if err != nil {
		return Out[apitypes.GuestsRemoveOutput]{}, err
	}
	// A disabled identity claims no license seat: reconciling releases the guest's seats (licenses.ts), as
	// identities.setStatus does.
	result, err := AfterIdentityChange(ctx, server, jsString(input.Get("tenantId")), []string{identityID}, removal)
	if err != nil {
		return Out[apitypes.GuestsRemoveOutput]{}, err
	}
	return Out[apitypes.GuestsRemoveOutput]{Value: result}, nil
}

// ResendInvitation is POST {basePath}/guests/resendInvitation. Sends a pending or lapsed guest invitation again with a
// new token (the earlier one stops working) and a new lifetime (`expiresInDays`, default 14). The address and the
// cross-tenant settings are checked again, and so are the sponsor (INVALID_SPONSOR) and the inviter's rights
// (INVITATION_INVALID). Requires iam:guests:invite on iam/guests/invitations/{id}; audited as
// `guest:invitation-resend`.
func (api *GuestsAPI) ResendInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsResendInvitationInput]) (Out[apitypes.GuestsResendInvitationOutput], error) {
	server := api.server
	invitationID, err := Text(input.Get("invitationId"), "invitationId")
	if err != nil {
		return Out[apitypes.GuestsResendInvitationOutput]{}, err
	}
	lifetime, err := Integer(coalesce(input.Get("expiresInDays"), GuestLimits.InvitationDays), "expiresInDays", 1, GuestLimits.MaxInvitationDays)
	if err != nil {
		return Out[apitypes.GuestsResendInvitationOutput]{}, err
	}
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:invite", invitationResource(invitationID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		if !guestsDeliveryConfigured(server) {
			return nil, core.NewIamError("DELIVERY_REQUIRED", "Guest invitations require an email delivery callback")
		}
		if tenant.Get("status") != "active" {
			return nil, core.NewIamError("TENANT_INACTIVE", "Tenant must be active")
		}
		tenantID := jsString(tenant.Get("id"))
		invitation, err := server.Scoped(ctx, tx, GuestCollections.Invitations, invitationID, tenantID)
		if err != nil {
			return nil, err
		}
		if status := invitation.Get("status"); status != "pending" && status != "expired" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a pending or lapsed invitation can be sent again", 409)
		}
		address := jsString(invitation.Get("email"))
		if err := assertNewcomer(ctx, tx, tenantID, address); err != nil {
			return nil, err
		}
		origin, err := GuestOrigin(ctx, tx, tenantID, address)
		if err != nil {
			return nil, err
		}
		settings, err := GuestSettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		if err := AssertGuestAdmitted(ctx, tx, settings, tenantID, origin); err != nil {
			return nil, err
		}
		// Only an invitation that can still be redeemed goes out: its sponsor must still be able to sponsor, and its
		// inviter still grant what it grants (INVITATION_INVALID), as redemption checks again.
		if _, err := GuestSponsor(ctx, server, tx, tenantID, invitation.Get("sponsorId")); err != nil {
			return nil, err
		}
		if _, err := inviterStillGrants(ctx, server, tx, invitation, tenantID); err != nil {
			return nil, err
		}
		now := float64(server.Now())
		if err := claimPendingKey(ctx, tx, tenantID, address, now, jsString(invitation.Get("id"))); err != nil {
			return nil, err
		}
		secret := guestInvitationToken()
		rest := invitation.Spread()
		rest.Delete("homeTenantId")
		next := rest.Spread(core.NewObject(
			"uniqueKey", guestPendingKey(address),
			"tokenHash", Hash(secret),
			"status", "pending",
			"expiresAt", now+lifetime*GuestDayMs,
			"sentAt", now,
		))
		if home := origin.Get("homeTenantId"); truthy(home) {
			next.Set("homeTenantId", home)
		}
		renewed, err := tx.Put(ctx, GuestCollections.Invitations, next)
		if err != nil {
			return nil, err
		}
		names := nameReader(tx)
		if err := sendGuestInvitation(ctx, server, tx, tenant, renewed, secret, names); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "guest:invitation-resend", tenantID, jsString(invitation.Get("id")), "allow", false,
			core.NewObject("email", address, "expiresAt", renewed.Get("expiresAt"))); err != nil {
			return nil, err
		}
		return invitationView(ctx, server, renewed, names)
	}, false)
	if err != nil {
		return Out[apitypes.GuestsResendInvitationOutput]{}, err
	}
	return Out[apitypes.GuestsResendInvitationOutput]{Value: view}, nil
}

// RevokeInvitation is POST {basePath}/guests/revokeInvitation. Revokes a pending guest invitation; its token stops
// working. Requires iam:guests:manage on iam/guests/invitations/{id}; audited as `guest:invitation-revoke`.
func (api *GuestsAPI) RevokeInvitation(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsRevokeInvitationInput]) (Out[apitypes.GuestsRevokeInvitationOutput], error) {
	server := api.server
	invitationID, err := Text(input.Get("invitationId"), "invitationId")
	if err != nil {
		return Out[apitypes.GuestsRevokeInvitationOutput]{}, err
	}
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:manage", invitationResource(invitationID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		invitation, err := server.Scoped(ctx, tx, GuestCollections.Invitations, invitationID, tenantID)
		if err != nil {
			return nil, err
		}
		if invitation.Get("status") != "pending" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a pending invitation can be revoked", 409)
		}
		rest := invitation.Spread()
		rest.Delete("uniqueKey")
		revoked, err := tx.Put(ctx, GuestCollections.Invitations, rest.Spread(core.NewObject(
			"status", "revoked",
			"revokedAt", float64(server.Now()),
			"revokedBy", principal.Identity.Get("id"),
		)))
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "guest:invitation-revoke", tenantID, jsString(invitation.Get("id")), "allow", false,
			core.NewObject("email", invitation.Get("email"))); err != nil {
			return nil, err
		}
		return invitationView(ctx, server, revoked, nameReader(tx))
	}, false)
	if err != nil {
		return Out[apitypes.GuestsRevokeInvitationOutput]{}, err
	}
	return Out[apitypes.GuestsRevokeInvitationOutput]{Value: view}, nil
}

// SetSponsor is POST {basePath}/guests/setSponsor. Gives an active guest a new sponsor (an active member who is not a
// guest), clearing a missing-sponsor flag. Requires recent authentication and iam:guests:manage on
// iam/guests/{identityId}; audited as `guest:sponsor-change`.
func (api *GuestsAPI) SetSponsor(ctx context.Context, credential core.CredentialInput, input In[apitypes.GuestsSetSponsorInput]) (Out[apitypes.GuestsSetSponsorOutput], error) {
	server := api.server
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return Out[apitypes.GuestsSetSponsorOutput]{}, err
	}
	view, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:guests:manage", guestResource(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		// The sponsor renews the guest and policies grant on principal.guestSponsorId: guests never choose one, their
		// own included, as they never renew anyone (attest).
		if core.StrictEquals(principal.Identity.Get("id"), identityID) || isGuest(principal.Identity) {
			return nil, NewOperationDenied("Guests cannot change a guest’s sponsor")
		}
		account, identity, err := loadGuest(ctx, tx, tenantID, identityID)
		if err != nil {
			return nil, err
		}
		if account.Get("status") != "active" || !truthy(identity.Get("guest")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only an active guest has a sponsor to change", 409)
		}
		sponsor, err := GuestSponsor(ctx, server, tx, tenantID, input.Get("sponsorId"))
		if err != nil {
			return nil, err
		}
		moved, err := SetGuestSponsor(ctx, tx, account, identity, jsString(sponsor.Get("id")))
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "guest:sponsor-change", tenantID, jsString(identity.Get("id")), "allow", false,
			core.NewObject("from", account.Get("sponsorId"), "to", sponsor.Get("id"), "reason", "administrator")); err != nil {
			return nil, err
		}
		movedAccount, _ := moved.Get("account").(*core.Object)
		movedIdentity, _ := moved.Get("identity").(*core.Object)
		return guestView(ctx, server, tx, movedAccount, movedIdentity, nameReader(tx))
	}, false)
	if err != nil {
		return Out[apitypes.GuestsSetSponsorOutput]{}, err
	}
	return Out[apitypes.GuestsSetSponsorOutput]{Value: view}, nil
}

// IamGuests is api/guests.ts IamGuests: the guest scheduler jobs on the instance (`iam.guests`); run both hourly.
type IamGuests struct {
	server *ServerContext
}

// SendReviewReminders (api/guests.ts IamGuests.sendReviewReminders): Emails each sponsor (template `guest-review`)
// about guests whose review is due or whose access ends within `withinDays` (default 14): each review date and each
// access end once, one email covering whatever is due. Requires an email delivery callback.
func (s *IamGuests) SendReviewReminders(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	withinDays, err := Integer(coalesce(member(input, "withinDays"), GuestLimits.ReminderDays), "withinDays", 1, 90)
	if err != nil {
		return nil, err
	}
	if !guestsDeliveryConfigured(server) {
		return nil, core.NewIamError("DELIVERY_REQUIRED", "Guest review reminders require an email delivery callback")
	}
	var tenantIDs []string
	if raw := member(input, "tenantId"); !isUndefined(raw) {
		tenantID, err := Text(raw, "tenantId")
		if err != nil {
			return nil, err
		}
		tenantIDs = []string{tenantID}
	} else {
		accounts, err := server.Store.Find(ctx, GuestCollections.Accounts, core.NewObject("status", "active"), nil)
		if err != nil {
			return nil, err
		}
		set := newOrderedSet()
		for _, account := range accounts {
			set.Add(jsString(account.Get("tenantId")))
		}
		tenantIDs = set.Values()
		sort.SliceStable(tenantIDs, func(i, j int) bool { return compareUTF16(tenantIDs[i], tenantIDs[j]) < 0 })
	}
	sent := []any{}
	inactive, quiet := 0.0, 0.0
	for _, tenantID := range tenantIDs {
		// Counted once the tenant's transaction committed.
		result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (guestReminderOutcome, error) {
			return s.remindTenant(ctx, tx, tenantID, withinDays)
		})
		if err != nil {
			return nil, err
		}
		switch {
		case result.inactive:
			inactive++
		case len(result.sent) == 0:
			quiet++
		default:
			sent = append(sent, result.sent...)
		}
	}
	return core.NewObject("sent", sent, "skipped", core.NewObject("inactive", inactive, "quiet", quiet)), nil
}

// guestReminderOutcome is one tenant's reminders: inactive, or the reminders sent.
type guestReminderOutcome struct {
	inactive bool
	sent     []any
}

// remindTenant is one tenant's transaction of sendReviewReminders.
func (s *IamGuests) remindTenant(ctx context.Context, tx core.IamStore, tenantID string, withinDays float64) (guestReminderOutcome, error) {
	server := s.server
	sent := []any{}
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return guestReminderOutcome{}, err
	}
	if tenant == nil || tenant.Get("status") != "active" {
		return guestReminderOutcome{inactive: true}, nil
	}
	now := float64(server.Now())
	horizon := now + withinDays*GuestDayMs
	// Reminder marks (lifecycle.ts) remember each guest and due date reminded; they outlive the due date.
	marks, err := tx.Find(ctx, "expiryReminderMarks", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return guestReminderOutcome{}, err
	}
	reminded := map[string]*core.Object{}
	for _, mark := range marks {
		reminded[jsString(mark.Get("uniqueKey"))] = mark
	}
	accounts, err := tx.Find(ctx, GuestCollections.Accounts, core.NewObject("tenantId", tenantID, "status", "active"), nil)
	if err != nil {
		return guestReminderOutcome{}, err
	}
	sortStable(accounts, func(a, b *core.Object) int {
		if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
			return -1
		}
		return 1
	})
	for _, account := range accounts {
		guest, err := tx.Get(ctx, "identities", jsString(account.Get("identityId")))
		if err != nil {
			return guestReminderOutcome{}, err
		}
		if guest == nil || !core.StrictEquals(guest.Get("tenantId"), tenantID) || guest.Get("status") != "active" ||
			server.IdentityExpired(guest) || !isGuest(guest) {
			continue
		}
		guestID := jsString(guest.Get("id"))
		reviewDueAt := account.Get("reviewDueAt")
		reviewKey := "guest-review:" + guestID + ":" + jsString(reviewDueAt)
		// A reminded review stays reminded while it is outstanding: its mark is kept alive past the end it was given,
		// so the purge cannot let it go out again.
		if reviewMark, ok := reminded[reviewKey]; ok && jsNumber(reviewMark.Get("expiresAt")) <= horizon {
			if _, err := tx.Put(ctx, "expiryReminderMarks", reviewMark.Spread(core.NewObject("expiresAt", horizon+withinDays*GuestDayMs))); err != nil {
				return guestReminderOutcome{}, err
			}
		}
		// The review and the access end are each reminded once per date, so a review reminder that went unanswered
		// does not stand in for the warning that the access is about to end. One email covers whatever is due.
		type event struct {
			key       string
			at, until float64
		}
		review := jsNumber(reviewDueAt)
		expiresAt := guest.Get("expiresAt")
		reviewUntil := review
		if !isUndefined(expiresAt) {
			reviewUntil = math.Max(review, jsNumber(expiresAt))
		}
		candidates := []event{{key: reviewKey, at: review, until: reviewUntil}}
		if !isUndefined(expiresAt) {
			candidates = append(candidates, event{key: "guest-end:" + guestID + ":" + jsString(expiresAt), at: jsNumber(expiresAt), until: jsNumber(expiresAt)})
		}
		var due []event
		for _, candidate := range candidates {
			if _, marked := reminded[candidate.key]; candidate.at <= horizon && !marked {
				due = append(due, candidate)
			}
		}
		if len(due) == 0 {
			continue
		}
		dueAt := due[0].at
		for _, item := range due[1:] {
			dueAt = math.Min(dueAt, item.at)
		}
		sponsor, err := tx.Get(ctx, "identities", jsString(account.Get("sponsorId")))
		if err != nil {
			return guestReminderOutcome{}, err
		}
		if !canSponsor(server, sponsor, tenantID) || !truthy(sponsor.Get("email")) {
			continue
		}
		payload := core.NewObject(
			"tenantId", tenantID,
			"tenantName", tenant.Get("name"),
			"guestId", guestID,
			"guestName", guest.Get("name"),
		)
		if truthy(guest.Get("email")) {
			payload.Set("guestEmail", guest.Get("email"))
		}
		payload.Set("dueAt", isoString(dueAt))
		payload.Set("reviewDueAt", guestISO(reviewDueAt))
		if !isUndefined(expiresAt) {
			payload.Set("expiresAt", guestISO(expiresAt))
		}
		if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: tenantID, Kind: "email", To: jsString(sponsor.Get("email")), Template: "guest-review", Payload: payload,
		}); err != nil {
			return guestReminderOutcome{}, err
		}
		for _, item := range due {
			if _, err := tx.Insert(ctx, "expiryReminderMarks", core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"uniqueKey", item.key,
				"identityId", guestID,
				"expiresAt", item.until+withinDays*GuestDayMs,
			)); err != nil {
				return guestReminderOutcome{}, err
			}
		}
		metadata := core.NewObject("sponsorId", sponsor.Get("id"), "dueAt", dueAt)
		if !isUndefined(expiresAt) {
			metadata.Set("expiresAt", expiresAt)
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", "deployment-operator",
			"action", "guest:review-reminder",
			"resourceId", guestID,
			"timestamp", now,
			"outcome", "allow",
			"metadata", metadata,
		)); err != nil {
			return guestReminderOutcome{}, err
		}
		sent = append(sent, core.NewObject("tenantId", tenantID, "guestId", guestID, "sponsorId", sponsor.Get("id"), "dueAt", dueAt))
	}
	return guestReminderOutcome{sent: sent}, nil
}

// guestSweepKeys are the members of a sweep result, in the TypeScript order.
var guestSweepKeys = []string{"invitationsExpired", "accountsExpired", "accountsRestored", "sponsorsMissing", "ownersNotified", "partnersRemoved"}

// noGuestSweep is the zero sweep result.
func noGuestSweep() map[string]float64 {
	result := map[string]float64{}
	for _, key := range guestSweepKeys {
		result[key] = 0
	}
	return result
}

// sweepTenant (api/guests.ts) is one tenant's guest bookkeeping (see `IamGuests.sweep`); returns what it changed.
func (s *IamGuests) sweepTenant(ctx context.Context, tx core.IamStore, tenantID string) (map[string]float64, error) {
	server := s.server
	result := noGuestSweep()
	now := float64(server.Now())
	tenant, err := tx.Get(ctx, "tenants", tenantID)
	if err != nil {
		return nil, err
	}
	record := func(action, resourceID string, metadata *core.Object) error {
		return server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", "deployment-operator",
			"action", action,
			"resourceId", resourceID,
			"timestamp", now,
			"outcome", "allow",
			"metadata", metadata,
		))
	}
	invitations, err := tx.Find(ctx, GuestCollections.Invitations, core.NewObject("tenantId", tenantID, "status", "pending"), nil)
	if err != nil {
		return nil, err
	}
	for _, invitation := range invitations {
		if jsNumber(invitation.Get("expiresAt")) <= now {
			rest := invitation.Spread()
			rest.Delete("uniqueKey")
			if _, err := tx.Put(ctx, GuestCollections.Invitations, rest.Spread(core.NewObject("status", "expired"))); err != nil {
				return nil, err
			}
			result["invitationsExpired"]++
		}
	}
	var owners []*core.Object
	ownersRead := false
	active, err := tx.Find(ctx, GuestCollections.Accounts, core.NewObject("tenantId", tenantID, "status", "active"), nil)
	if err != nil {
		return nil, err
	}
	expired, err := tx.Find(ctx, GuestCollections.Accounts, core.NewObject("tenantId", tenantID, "status", "expired"), nil)
	if err != nil {
		return nil, err
	}
	for _, account := range append(active, expired...) {
		identity, err := tx.Get(ctx, "identities", jsString(account.Get("identityId")))
		if err != nil {
			return nil, err
		}
		if identity == nil || !core.StrictEquals(identity.Get("tenantId"), tenantID) || identity.Get("status") == "deleted" {
			// The identity is gone: its account goes with it (deleteIdentity removes it too).
			if err := tx.Delete(ctx, GuestCollections.Accounts, jsString(account.Get("id"))); err != nil {
				return nil, err
			}
			continue
		}
		identityID := jsString(identity.Get("id"))
		if account.Get("status") == "active" && server.IdentityExpired(identity) {
			endedAt := coalesce(identity.Get("expiresAt"), now)
			if account, err = tx.Put(ctx, GuestCollections.Accounts, account.Spread(core.NewObject("status", "expired", "endedAt", endedAt))); err != nil {
				return nil, err
			}
			if err := record("guest:expire", identityID, core.NewObject("sponsorId", account.Get("sponsorId"), "expiresAt", endedAt)); err != nil {
				return nil, err
			}
			result["accountsExpired"]++
		} else if account.Get("status") == "expired" && identity.Get("status") == "active" && !server.IdentityExpired(identity) && isGuest(identity) {
			// An administrator gave the guest a later end and enabled them again.
			rest := account.Spread()
			rest.Delete("endedAt")
			rest.Delete("endedBy")
			if account, err = tx.Put(ctx, GuestCollections.Accounts, rest.Spread(core.NewObject("status", "active"))); err != nil {
				return nil, err
			}
			result["accountsRestored"]++
		}
		if account.Get("status") != "active" {
			continue
		}
		sponsor, err := tx.Get(ctx, "identities", jsString(account.Get("sponsorId")))
		if err != nil {
			return nil, err
		}
		var sponsorName any = core.Undefined
		if sponsor != nil && core.StrictEquals(sponsor.Get("tenantId"), tenantID) {
			sponsorName = sponsor.Get("name")
		}
		if canSponsor(server, sponsor, tenantID) {
			if truthy(account.Get("sponsorMissing")) || !isUndefined(account.Get("sponsorMissingNotifiedAt")) {
				rest := account.Spread()
				rest.Delete("sponsorMissing")
				rest.Delete("sponsorMissingNotifiedAt")
				if _, err := tx.Put(ctx, GuestCollections.Accounts, rest); err != nil {
					return nil, err
				}
			}
			continue
		}
		if !truthy(account.Get("sponsorMissing")) {
			if account, err = tx.Put(ctx, GuestCollections.Accounts, account.Spread(core.NewObject("sponsorMissing", true))); err != nil {
				return nil, err
			}
			if err := record("guest:sponsor-missing", identityID, core.NewObject("sponsorId", account.Get("sponsorId"))); err != nil {
				return nil, err
			}
			result["sponsorsMissing"]++
		}
		// The owners hear about each guest once per loss, when the deployment can email and the tenant is active.
		if isUndefined(account.Get("sponsorMissingNotifiedAt")) && tenant != nil && tenant.Get("status") == "active" && guestsDeliveryConfigured(server) {
			if !ownersRead {
				ownersRead = true
				found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "owner", true, "status", "active"), nil)
				if err != nil {
					return nil, err
				}
				for _, owner := range found {
					if truthy(owner.Get("email")) && !server.IdentityExpired(owner) {
						owners = append(owners, owner)
					}
				}
			}
			for _, owner := range owners {
				payload := core.NewObject(
					"tenantId", tenantID,
					"tenantName", tenant.Get("name"),
					"guestId", identityID,
					"guestName", identity.Get("name"),
				)
				if truthy(identity.Get("email")) {
					payload.Set("guestEmail", identity.Get("email"))
				}
				if truthy(sponsorName) {
					payload.Set("sponsorName", sponsorName)
				}
				if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
					TenantID: tenantID, Kind: "email", To: jsString(owner.Get("email")), Template: "guest-sponsor-missing", Payload: payload,
				}); err != nil {
					return nil, err
				}
				result["ownersNotified"]++
			}
			if len(owners) > 0 {
				if _, err := tx.Put(ctx, GuestCollections.Accounts, account.Spread(core.NewObject("sponsorMissingNotifiedAt", now))); err != nil {
					return nil, err
				}
			}
		}
	}
	// Partner entries naming tenants that were purged since can never match again.
	stored, err := ReadGuestSettings(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		existing := func(list any) ([]any, int, error) {
			items, _ := list.([]any)
			kept := []any{}
			for _, partner := range items {
				found, err := tx.Get(ctx, "tenants", jsString(member(partner, "tenantId")))
				if err != nil {
					return nil, 0, err
				}
				if found != nil {
					kept = append(kept, partner)
				}
			}
			return kept, len(items), nil
		}
		storedInbound, storedOutbound := guestShallow(stored.Get("inbound")), guestShallow(stored.Get("outbound"))
		inbound, inboundCount, err := existing(storedInbound.Get("partners"))
		if err != nil {
			return nil, err
		}
		outbound, outboundCount, err := existing(storedOutbound.Get("partners"))
		if err != nil {
			return nil, err
		}
		removed := float64(inboundCount - len(inbound) + (outboundCount - len(outbound)))
		if removed != 0 {
			if _, err := tx.Put(ctx, GuestCollections.Settings, stored.Spread(core.NewObject(
				"inbound", storedInbound.Set("partners", inbound),
				"outbound", storedOutbound.Set("partners", outbound),
			))); err != nil {
				return nil, err
			}
			if err := record("guest:settings", tenantID, core.NewObject("partnersRemoved", removed)); err != nil {
				return nil, err
			}
			result["partnersRemoved"] += removed
		}
	}
	return result, nil
}

// Sweep (api/guests.ts IamGuests.sweep): Bookkeeping: marks lapsed invitations and ended guest accounts expired,
// flags guests whose sponsor left (and emails the tenant's owners once, template `guest-sponsor-missing`), and drops
// partner entries naming purged tenants. One transaction per tenant.
func (s *IamGuests) Sweep(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	filter := core.NewObject()
	if raw := member(input, "tenantId"); !isUndefined(raw) {
		tenantID, err := Text(raw, "tenantId")
		if err != nil {
			return nil, err
		}
		filter.Set("tenantId", tenantID)
	}
	totals := noGuestSweep()
	tenantIDs := newOrderedSet()
	invitations, err := server.Store.Find(ctx, GuestCollections.Invitations, filter.Spread(core.NewObject("status", "pending")), nil)
	if err != nil {
		return nil, err
	}
	for _, invitation := range invitations {
		tenantIDs.Add(jsString(invitation.Get("tenantId")))
	}
	for _, status := range []string{"active", "expired"} {
		accounts, err := server.Store.Find(ctx, GuestCollections.Accounts, filter.Spread(core.NewObject("status", status)), nil)
		if err != nil {
			return nil, err
		}
		for _, account := range accounts {
			tenantIDs.Add(jsString(account.Get("tenantId")))
		}
	}
	settings, err := server.Store.Find(ctx, GuestCollections.Settings, filter, nil)
	if err != nil {
		return nil, err
	}
	for _, stored := range settings {
		tenantIDs.Add(jsString(stored.Get("tenantId")))
	}
	ids := tenantIDs.Values()
	sort.SliceStable(ids, func(i, j int) bool { return compareUTF16(ids[i], ids[j]) < 0 })
	for _, tenantID := range ids {
		// Counted once the tenant's transaction committed.
		swept, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (map[string]float64, error) {
			return s.sweepTenant(ctx, tx, tenantID)
		})
		if err != nil {
			return nil, err
		}
		for _, key := range guestSweepKeys {
			totals[key] += swept[key]
		}
	}
	out := core.NewObject()
	for _, key := range guestSweepKeys {
		out.Set(key, totals[key])
	}
	return out, nil
}

// CreateGuestsRuntime builds the IamGuests (api/guests.ts createGuestsRuntime).
func CreateGuestsRuntime(server *ServerContext) *IamGuests {
	return &IamGuests{server: server}
}
