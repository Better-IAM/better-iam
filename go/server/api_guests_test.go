package server

// Guests API tests, after tests/guests.test.ts, tests/guests-access.test.ts, tests/guests-edges.test.ts,
// tests/guests-hardening.test.ts and tests/guests-lifecycle.test.ts: invitations (validation, email, conflicts,
// revocation, resending, lapsing), cross-tenant access settings (defaults, validation, audit, inbound and outbound
// admission), the guest directory, sponsor renewals, sponsor changes, the scheduler jobs (sweep and reminders), and
// what happens to guests when people leave. Members are created through the auth service (identities.create waits on
// package automation), and guests whose redemption the test does not exercise are seeded as redemption stores them
// (seedGuest); steps that reach another unit's stub (redemption's separation-of-duties check, package automation,
// packages.allow, ...) skip until that unit is ported.

import (
	"context"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

type guestFixture struct {
	*orgFixture
}

func newGuestFixture(t *testing.T, mutate func(options *BetterIamOptions)) *guestFixture {
	t.Helper()
	return &guestFixture{orgFixture: newOrgFixture(t, mutate)}
}

func guestTestPassword(name string) string { return "a strong " + name + " password" }

// person creates `{name}@acme.test` with a password through the auth service (organizationFixture member).
func (f *guestFixture) person(name string) *core.Object {
	f.t.Helper()
	return f.createPerson(name+"@acme.test", name)
}

func (f *guestFixture) createPerson(email, name string) *core.Object {
	f.t.Helper()
	identity, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: f.tenantID, Email: email, Name: name, Password: guestTestPassword(name), HasPassword: true,
		})
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return identity
}

// seedGuest stores `{name}@partner.test` as redemption stores a guest without grants: the identity with its access
// end and guest marker, and its active guest account.
func (f *guestFixture) seedGuest(name, sponsorID string, accessDays float64) *core.Object {
	f.t.Helper()
	now := f.now()
	expiresAt := now + accessDays*GuestDayMs
	identity, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		created, err := f.iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{
			TenantID: f.tenantID, Email: name + "@partner.test", Name: name, Password: guestTestPassword(name), HasPassword: true,
			EmailVerified: true,
		})
		if err != nil {
			return nil, err
		}
		identity, err := tx.Put(ctx, "identities", created.Spread(core.NewObject(
			"expiresAt", expiresAt,
			"guest", core.NewObject("sponsorId", sponsorID, "since", now, "homeDomain", "partner.test"),
		)))
		if err != nil {
			return nil, err
		}
		id := identity.Get("id")
		_, err = tx.Insert(ctx, GuestCollections.Accounts, core.NewObject(
			"id", id, "tenantId", f.tenantID, "identityId", id, "sponsorId", sponsorID, "email", name+"@partner.test",
			"source", "invitation", "invitationId", "invitation-"+name, "invitedBy", f.ownerID, "redeemedAt", now,
			"reviewDueAt", expiresAt, "status", "active",
			"grants", core.NewObject("bindingIds", []any{}, "membershipIds", []any{}, "packageAssignmentIds", []any{}, "packageMembershipIds", []any{}),
			"grantsEndAt", expiresAt,
		))
		return identity, err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return identity
}

// guestLogin signs a guest in with their password.
func (f *guestFixture) guestLogin(name string) core.CredentialInput {
	f.t.Helper()
	result, err := f.iam.Auth.SignIn(f.ctx, core.NewObject("tenantId", f.tenantID, "email", name+"@partner.test", "password", guestTestPassword(name)))
	requirePorted(f.t, err)
	return core.CredentialInput{Token: jsString(result.Get("token"))}
}

func (f *guestFixture) body(members ...any) *core.Object {
	body := core.NewObject("tenantId", f.tenantID)
	for index := 0; index+1 < len(members); index += 2 {
		body.Set(members[index].(string), members[index+1])
	}
	return body
}

func (f *guestFixture) invite(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Guests.Invite(f.ctx, credential, Input[apitypes.GuestsInviteInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *guestFixture) mustInvite(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	invitation, err := f.invite(credential, members...)
	requirePorted(f.t, err)
	return invitation
}

func (f *guestFixture) invitations(credential core.CredentialInput, members ...any) []*core.Object {
	f.t.Helper()
	return f.items(f.iam.API.Guests.ListInvitations(f.ctx, credential, Input[apitypes.GuestsListInvitationsInput](f.body(members...))))
}

func (f *guestFixture) attest(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Guests.Attest(f.ctx, credential, Input[apitypes.GuestsAttestInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *guestFixture) get(credential core.CredentialInput, identityID any) (*core.Object, error) {
	out, err := f.iam.API.Guests.Get(f.ctx, credential, Input[apitypes.GuestsGetInput](f.body("identityId", identityID)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *guestFixture) mustGet(credential core.CredentialInput, identityID any) *core.Object {
	f.t.Helper()
	view, err := f.get(credential, identityID)
	requirePorted(f.t, err)
	return view
}

func (f *guestFixture) list(credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	return f.object(f.iam.API.Guests.List(f.ctx, credential, Input[apitypes.GuestsListInput](f.body(members...))))
}

func (f *guestFixture) mine(credential core.CredentialInput) []*core.Object {
	f.t.Helper()
	return f.items(f.iam.API.Guests.Mine(f.ctx, credential, Input[apitypes.GuestsMineInput](f.body())))
}

func (f *guestFixture) setSponsor(credential core.CredentialInput, identityID, sponsorID any) (*core.Object, error) {
	out, err := f.iam.API.Guests.SetSponsor(f.ctx, credential, Input[apitypes.GuestsSetSponsorInput](f.body("identityId", identityID, "sponsorId", sponsorID)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *guestFixture) configure(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Guests.Configure(f.ctx, credential, Input[apitypes.GuestsConfigureInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *guestFixture) settings(credential core.CredentialInput) *core.Object {
	f.t.Helper()
	return f.object(f.iam.API.Guests.GetSettings(f.ctx, credential, Input[apitypes.GuestsGetSettingsInput](f.body())))
}

func (f *guestFixture) revoke(credential core.CredentialInput, invitationID any) (*core.Object, error) {
	out, err := f.iam.API.Guests.RevokeInvitation(f.ctx, credential, Input[apitypes.GuestsRevokeInvitationInput](f.body("invitationId", invitationID)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *guestFixture) resend(credential core.CredentialInput, members ...any) (*core.Object, error) {
	out, err := f.iam.API.Guests.ResendInvitation(f.ctx, credential, Input[apitypes.GuestsResendInvitationInput](f.body(members...)))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (f *guestFixture) redeem(members ...any) (*core.Object, error) {
	body := core.NewObject("tenantId", f.tenantID)
	for index := 0; index+1 < len(members); index += 2 {
		body.Set(members[index].(string), members[index+1])
	}
	out, err := f.iam.API.Guests.Redeem(f.ctx, Input[apitypes.GuestsRedeemInput](body))
	if err != nil {
		return nil, err
	}
	object, _ := out.Value.(*core.Object)
	return object, nil
}

// token is the newest guest invitation token emailed to `address` (delivers the outbox first).
func (f *guestFixture) token(address string) string {
	f.t.Helper()
	f.dispatch()
	f.mu.Lock()
	defer f.mu.Unlock()
	for index := len(f.inbox) - 1; index >= 0; index-- {
		message := f.inbox[index]
		if message.Template == "guest-invitation" && message.To == strings.ToLower(address) && message.Payload["token"] != "" {
			return message.Payload["token"]
		}
	}
	f.t.Fatalf("no guest invitation was emailed to %s", address)
	return ""
}

func (f *guestFixture) sweep(input *core.Object) *core.Object {
	f.t.Helper()
	result, err := f.iam.Guests.Sweep(f.ctx, input)
	requirePorted(f.t, err)
	return result
}

func (f *guestFixture) remind(input *core.Object) (*core.Object, error) {
	return f.iam.Guests.SendReviewReminders(f.ctx, input)
}

// verifyDomain records the tenant as the verifier of `domain`, as a verified domain claim does (domains.ts).
func (f *guestFixture) verifyDomain(tenantID, domain string) {
	f.t.Helper()
	f.seed("domainOwners", core.NewObject("id", domain, "tenantId", tenantID, "domainId", "domain-"+domain, "verifiedAt", f.now()))
}

// administrator is a member holding a role with `permissions`, signed in.
func (f *guestFixture) administrator(name string, permissions ...string) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	identity := f.person(name)
	actions := make([]any, len(permissions))
	for index, permission := range permissions {
		actions[index] = permission
	}
	role := f.createRole(f.owner, "name", name+" role", "permissions", actions)
	f.bind(f.owner, role.Get("id"), "identity", identity.Get("id"))
	return identity, f.login(name)
}

func guestExpectCode(t *testing.T, err error, code string, label ...any) {
	t.Helper()
	if err == nil {
		t.Fatalf("%v: expected %s, got success", label, code)
	}
	known := iamError(t, err)
	if known.Code == "NOT_IMPLEMENTED" && code != "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	if known.Code != code {
		t.Fatalf("%v: expected %s, got %s: %s", label, code, known.Code, known.Message)
	}
}

func guestExpectError(t *testing.T, err error, code, message string) {
	t.Helper()
	guestExpectCode(t, err, code)
	if known := iamError(t, err); known.Message != message {
		t.Fatalf("expected message %q, got %q", message, known.Message)
	}
}

func guestJSON(t *testing.T, value any) string {
	t.Helper()
	text, _, err := core.Stringify(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func guestExpectJSON(t *testing.T, label string, value any, want string) {
	t.Helper()
	if got := guestJSON(t, value); got != want {
		t.Fatalf("%s:\n got %s\nwant %s", label, got, want)
	}
}

func guestIDs(items []*core.Object, key string) []string {
	ids := make([]string, len(items))
	for index, item := range items {
		ids[index] = jsString(item.Get(key))
	}
	return ids
}

func guestViews(t *testing.T, page *core.Object) []*core.Object {
	t.Helper()
	list, _ := page.Get("guests").([]any)
	views := make([]*core.Object, len(list))
	for index, item := range list {
		views[index] = item.(*core.Object)
	}
	return views
}

func guestExpectIDs(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("%s: got %v, want %v", label, got, want)
	}
}

const zeroSweep = `{"invitationsExpired":0,"accountsExpired":0,"accountsRestored":0,"sponsorsMissing":0,"ownersNotified":0,"partnersRemoved":0}`

func TestGuestInvitationEmailListAndRedemption(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	invitedAt := f.now()
	invitation := f.mustInvite(f.owner, "email", "Gina@Partner.test", "sponsorId", aliceID, "message", "  Welcome to the launch project  ",
		"accessDays", 30.0, "expiresInDays", 7.0)
	want := core.NewObject(
		"id", invitation.Get("id"), "tenantId", f.tenantID, "email", "gina@partner.test", "status", "pending",
		"sponsorId", aliceID, "sponsorName", "alice", "invitedBy", f.ownerID, "inviterName", "Acme owner",
		"message", "Welcome to the launch project", "roleIds", []any{}, "groupIds", []any{}, "packageIds", []any{},
		"accessDays", 30.0, "expiresAt", invitedAt+7*dayMs, "createdAt", invitedAt, "sentAt", invitedAt,
	)
	guestExpectJSON(t, "invitation", invitation, guestJSON(t, want))
	// Only the token's hash is stored; the address holds the pending slot.
	stored := f.find(GuestCollections.Invitations, core.NewObject("tenantId", f.tenantID))
	if len(stored) != 1 || stored[0].Get("uniqueKey") != "pending:gina@partner.test" {
		t.Fatalf("stored invitation: %s", guestJSON(t, stored))
	}
	// The invitee gets a personal email with the token.
	token := f.token("gina@partner.test")
	email := f.messages(f.tenantID, "guest-invitation")[0]
	if email.To != "gina@partner.test" {
		t.Fatalf("email to %s", email.To)
	}
	if !regexp.MustCompile(`^biam_gst_[A-Za-z0-9_-]{43}$`).MatchString(token) {
		t.Fatalf("token %q", token)
	}
	wantPayload := map[string]string{
		"tenantId": f.tenantID, "tenantName": "Acme", "inviterName": "Acme owner", "sponsorName": "alice",
		"message": "Welcome to the launch project", "token": token, "expiresAt": isoString(invitedAt + 7*dayMs),
	}
	if guestJSON(t, core.Normalize(email.Payload)) != guestJSON(t, core.Normalize(wantPayload)) {
		t.Fatalf("payload %v", email.Payload)
	}
	if stored[0].Get("tokenHash") == token || stored[0].Get("tokenHash") != Hash(token) {
		t.Fatal("the token must be stored only as its hash")
	}
	guestExpectJSON(t, "listInvitations", stringsOfObjects(f.invitations(f.owner)), guestJSON(t, []any{invitation}))

	// The invitation is audited.
	invites := f.auditTrail(f.tenantID, "guest:invite")
	if len(invites) != 1 {
		t.Fatalf("invite events: %d", len(invites))
	}
	guestExpectJSON(t, "invite metadata", invites[0].Get("metadata"), guestJSON(t, core.NewObject(
		"email", "gina@partner.test", "sponsorId", aliceID, "roleIds", []any{}, "groupIds", []any{}, "packageIds", []any{},
		"accessDays", 30.0, "expiresAt", invitedAt+7*dayMs,
	)))

	// Redemption creates the guest with a verified address, an access end and a sponsor, and signs them in.
	f.clock.Add(60_000)
	redeemedAt := f.now()
	result, err := f.redeem("token", token, "name", "Gina", "password", guestTestPassword("Gina"))
	requirePorted(t, err)
	identity := result.Get("identity").(*core.Object)
	guestID := jsString(identity.Get("id"))
	if identity.Get("email") != "gina@partner.test" || identity.Get("emailVerified") != true || identity.Get("expiresAt") != redeemedAt+30*dayMs {
		t.Fatalf("redeemed identity: %s", guestJSON(t, identity))
	}
	guestExpectJSON(t, "guest marker", identity.Get("guest"), guestJSON(t, core.NewObject("sponsorId", aliceID, "since", redeemedAt, "homeDomain", "partner.test")))
	if identity.Has("passwordHash") {
		t.Fatal("the public identity must not carry the password hash")
	}
	// The invitation is spent.
	redeemed := f.invitations(f.owner)[0]
	if redeemed.Get("status") != "redeemed" || redeemed.Get("redeemedAt") != redeemedAt || redeemed.Get("identityId") != guestID {
		t.Fatalf("redeemed invitation: %s", guestJSON(t, redeemed))
	}
	if spent := f.find(GuestCollections.Invitations, core.NewObject("tenantId", f.tenantID)); spent[0].Has("uniqueKey") {
		t.Fatal("a redeemed invitation gives up its pending slot")
	}
	_, err = f.redeem("token", token, "name", "Gina again", "password", guestTestPassword("Gina"))
	guestExpectCode(t, err, "INVITATION_INVALID")
	view := f.mustGet(f.owner, guestID)
	guestExpectJSON(t, "guest view", view, guestJSON(t, core.NewObject(
		"identityId", guestID, "tenantId", f.tenantID, "name", "Gina", "email", "gina@partner.test", "status", "active",
		"accountStatus", "active", "sponsorId", aliceID, "sponsorName", "alice", "sponsorMissing", false,
		"homeDomain", "partner.test", "invitationId", invitation.Get("id"), "invitedBy", f.ownerID, "redeemedAt", redeemedAt,
		"reviewDueAt", redeemedAt+30*dayMs, "expiresAt", redeemedAt+30*dayMs, "lastSignInAt", redeemedAt,
	)))
	guestExpectJSON(t, "mine", stringsOfObjects(f.mine(f.login("alice"))), guestJSON(t, []any{view}))
	guestExpectJSON(t, "mine of the owner", stringsOfObjects(f.mine(f.owner)), "[]")
	redeems := f.auditTrail(f.tenantID, "guest:redeem")
	if len(redeems) != 1 || redeems[0].Get("actorId") != guestID || redeems[0].Get("resourceId") != guestID {
		t.Fatalf("redeem events: %s", guestJSON(t, redeems))
	}
}

// stringsOfObjects is a list of records as a model array.
func stringsOfObjects(items []*core.Object) []any {
	out := make([]any, len(items))
	for index, item := range items {
		out[index] = item
	}
	return out
}

func TestGuestInvitationValidation(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	invite := func(members ...any) error {
		_, err := f.invite(f.owner, append([]any{"email", "val@partner.test"}, members...)...)
		return err
	}
	for _, input := range [][]any{
		{"email", "not an address"}, {"email", 42.0}, {"accessDays", 0.0}, {"accessDays", 366.0}, {"accessDays", 1.5},
		{"expiresInDays", 0.0}, {"expiresInDays", 31.0}, {"message", strings.Repeat("x", 1001)}, {"roleIds", "role"},
		{"groupIds", []any{42.0}}, {"packageIds", core.NewObject()},
	} {
		guestExpectCode(t, invite(input...), "INVALID_INPUT", input...)
	}
	// Sponsors are active members who are not guests.
	gus := f.seedGuest("gus", f.ownerID, 90)
	bob := f.person("bob")
	f.change("identities", jsString(bob.Get("id")), "status", "disabled")
	for _, sponsorID := range []string{jsString(gus.Get("id")), jsString(bob.Get("id")), "missing", ""} {
		code := "INVALID_SPONSOR"
		if sponsorID == "" {
			code = "INVALID_INPUT"
		}
		guestExpectCode(t, invite("sponsorId", sponsorID), code, sponsorID)
	}
	// An address that already belongs to someone here, or already has a pending invitation.
	for _, email := range []string{"alice@acme.test", "gus@partner.test", "GUS@partner.test"} {
		err := invite("email", email)
		guestExpectCode(t, err, "CONFLICT", email)
		if iamError(t, err).Status != 409 {
			t.Fatalf("%s: status %d", email, iamError(t, err).Status)
		}
	}
	f.mustInvite(f.owner, "email", "val@partner.test", "sponsorId", aliceID)
	guestExpectCode(t, invite(), "CONFLICT")
	// The platform tenant takes no guests.
	_, err := f.iam.API.Guests.Invite(f.ctx, f.credential, Input[apitypes.GuestsInviteInput](core.NewObject("tenantId", f.rootID, "email", "someone@partner.test")))
	guestExpectCode(t, err, "INVALID_INPUT")
	// Nothing was sent for the refused invitations.
	f.dispatch()
	var sent []string
	for _, message := range f.messages(f.tenantID, "guest-invitation") {
		sent = append(sent, message.To)
	}
	guestExpectIDs(t, "sent", sent, "val@partner.test")
	pending := f.invitations(f.owner, "status", "pending")
	if len(pending) != 1 || pending[0].Get("email") != "val@partner.test" || pending[0].Get("sponsorId") != aliceID {
		t.Fatalf("pending: %s", guestJSON(t, pending))
	}
	// Grants are checked like identities.invite (the roles first).
	guestExpectCode(t, invite("email", "new@partner.test", "roleIds", []any{"missing"}), "NOT_FOUND")
	guestExpectCode(t, invite("email", "new@partner.test", "groupIds", []any{"missing"}), "NOT_FOUND")
	guestExpectCode(t, invite("email", "new@partner.test", "packageIds", []any{"missing"}), "NOT_FOUND")
	ownerRoles := f.find("roles", core.NewObject("tenantId", f.tenantID, "uniqueKey", "system:owner"))
	if len(ownerRoles) == 1 {
		err := invite("email", "new@partner.test", "roleIds", []any{ownerRoles[0].Get("id")})
		guestExpectCode(t, err, "PROTECTED_RESOURCE")
	}
}

func TestGuestInvitationsRevokeResendAndLapse(t *testing.T) {
	f := newGuestFixture(t, nil)
	owner := f.owner
	first := f.mustInvite(owner, "email", "jo@partner.test")
	firstToken := f.token("jo@partner.test")
	revoked, err := f.revoke(owner, first.Get("id"))
	requirePorted(t, err)
	if revoked.Get("status") != "revoked" || revoked.Get("revokedAt") != f.now() || revoked.Get("revokedBy") != f.ownerID {
		t.Fatalf("revoked: %s", guestJSON(t, revoked))
	}
	_, err = f.redeem("token", firstToken, "name", "Jo", "password", guestTestPassword("Jo"))
	guestExpectCode(t, err, "INVITATION_INVALID")
	_, err = f.revoke(owner, first.Get("id"))
	guestExpectCode(t, err, "INVALID_TRANSITION")
	_, err = f.resend(owner, "invitationId", first.Get("id"))
	guestExpectCode(t, err, "INVALID_TRANSITION")
	_, err = f.revoke(owner, "missing")
	guestExpectCode(t, err, "NOT_FOUND")
	_, err = f.resend(owner, "invitationId", "missing")
	guestExpectCode(t, err, "NOT_FOUND")

	// Revoking frees the address for a new invitation; sending again rotates its token.
	second := f.mustInvite(owner, "email", "jo@partner.test")
	oldToken := f.token("jo@partner.test")
	f.clock.Add(int64(dayMs))
	resent, err := f.resend(owner, "invitationId", second.Get("id"), "expiresInDays", 3.0)
	requirePorted(t, err)
	if resent.Get("id") != second.Get("id") || resent.Get("status") != "pending" || resent.Get("createdAt") != second.Get("createdAt") ||
		resent.Get("sentAt") != f.now() || resent.Get("expiresAt") != f.now()+3*dayMs {
		t.Fatalf("resent: %s", guestJSON(t, resent))
	}
	newToken := f.token("jo@partner.test")
	if newToken == oldToken {
		t.Fatal("sending again must rotate the token")
	}
	_, err = f.redeem("token", oldToken, "name", "Jo", "password", guestTestPassword("Jo"))
	guestExpectCode(t, err, "INVITATION_INVALID")
	for _, days := range []float64{0, 31} {
		_, err := f.resend(owner, "invitationId", second.Get("id"), "expiresInDays", days)
		guestExpectCode(t, err, "INVALID_INPUT")
	}
	// A lapsed invitation reads as expired at once, cannot be redeemed, and can be sent again.
	f.clock.Add(int64(3 * dayMs))
	guestExpectIDs(t, "expired", guestIDs(f.invitations(owner, "status", "expired"), "id"), jsString(second.Get("id")))
	_, err = f.redeem("token", newToken, "name", "Jo", "password", guestTestPassword("Jo"))
	guestExpectCode(t, err, "INVITATION_INVALID")
	again, err := f.resend(owner, "invitationId", second.Get("id"))
	requirePorted(t, err)
	if again.Get("status") != "pending" || again.Get("expiresAt") != f.now()+14*dayMs {
		t.Fatalf("sent again: %s", guestJSON(t, again))
	}
	// A new invitation to a lapsed address takes over its pending slot.
	f.mustInvite(owner, "email", "kim@partner.test", "expiresInDays", 1.0)
	f.clock.Add(int64(2 * dayMs))
	kim := f.mustInvite(owner, "email", "kim@partner.test")
	var statuses []string
	for _, invitation := range f.invitations(owner) {
		if invitation.Get("email") == "kim@partner.test" {
			marker := "other"
			if invitation.Get("id") == kim.Get("id") {
				marker = "new"
			}
			statuses = append(statuses, marker+":"+jsString(invitation.Get("status")))
		}
	}
	guestExpectIDs(t, "kim", statuses, "new:pending", "other:expired")
	_, err = f.iam.API.Guests.ListInvitations(f.ctx, owner, Input[apitypes.GuestsListInvitationsInput](f.body("status", "lost")))
	guestExpectCode(t, err, "INVALID_INPUT")
	var trail []string
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if action := jsString(event.Get("action")); strings.HasPrefix(action, "guest:invitation-") {
			trail = append(trail, action)
		}
	}
	sort.Strings(trail)
	guestExpectIDs(t, "trail", trail, "guest:invitation-resend", "guest:invitation-resend", "guest:invitation-revoke")
	// The invitation sent again is redeemed with the newest token.
	result, err := f.redeem("token", f.token("jo@partner.test"), "name", "Jo", "password", guestTestPassword("Jo"))
	requirePorted(t, err)
	if member(member(result.Get("identity"), "guest"), "sponsorId") != f.ownerID {
		t.Fatalf("redeemed: %s", guestJSON(t, result))
	}
}

func TestGuestRedemptionChecksItsInput(t *testing.T) {
	f := newGuestFixture(t, nil)
	f.mustInvite(f.owner, "email", "ivy@partner.test")
	token := f.token("ivy@partner.test")
	redeem := func(members ...any) error {
		base := core.NewObject("token", token, "name", "Ivy", "password", guestTestPassword("Ivy"))
		for index := 0; index+1 < len(members); index += 2 {
			base.Set(members[index].(string), members[index+1])
		}
		var flat []any
		base.Entries(func(key string, value any) bool {
			flat = append(flat, key, value)
			return true
		})
		_, err := f.redeem(flat...)
		return err
	}
	for _, input := range [][]any{{"name", ""}, {"password", core.Undefined}, {"password", 42.0}, {"token", ""}} {
		guestExpectCode(t, redeem(input...), "INVALID_INPUT", input...)
	}
	guestExpectCode(t, redeem("token", "biam_gst_unknown"), "INVITATION_INVALID")
	if err := redeem("tenantId", "missing"); err == nil || iamError(t, err).Status != 404 {
		t.Fatalf("an unknown tenant: %v", err)
	}
	if found := f.find("identities", core.NewObject("tenantId", f.tenantID, "email", "ivy@partner.test")); len(found) != 0 {
		t.Fatal("a refused redemption leaves no identity behind")
	}
	if err := redeem("password", "short"); err == nil {
		t.Fatal("a short password is refused")
	} else if known := iamError(t, err); known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	} else if known.Status != 400 {
		t.Fatalf("a short password: %s", known.Message)
	}
	requirePorted(t, redeem())
}

func TestGuestSettingsDefaultValidateAndAudit(t *testing.T) {
	f := newGuestFixture(t, nil)
	beta := f.createTenant("Beta", "", "")
	defaults := f.settings(f.owner)
	guestExpectJSON(t, "defaults", defaults, guestJSON(t, core.NewObject(
		"tenantId", f.tenantID, "configured", false,
		"inbound", core.NewObject("allowGuests", true, "allowedDomains", []any{}, "blockedDomains", []any{}, "partners", []any{}),
		"outbound", core.NewObject("allowGuestInvitations", true, "partners", []any{}),
		"accessDays", 90.0, "reviewEveryDays", 90.0,
	)))
	owner := f.ownerSignIn()
	configured, err := f.configure(owner,
		"inbound", core.NewObject("allowedDomains", []any{"Partner.test", "b.example", "partner.test"}, "partners", []any{core.NewObject("tenantId", beta.id, "allow", true)}),
		"outbound", core.NewObject("allowGuestInvitations", false),
		"accessDays", 30.0,
	)
	requirePorted(t, err)
	if configured.Get("configured") != true || configured.Get("updatedBy") != f.ownerID || configured.Get("updatedAt") != f.now() {
		t.Fatalf("configured: %s", guestJSON(t, configured))
	}
	guestExpectJSON(t, "inbound", configured.Get("inbound"), guestJSON(t, core.NewObject(
		"allowGuests", true, "allowedDomains", []any{"b.example", "partner.test"}, "blockedDomains", []any{},
		"partners", []any{core.NewObject("tenantId", beta.id, "allow", true)},
	)))
	guestExpectJSON(t, "outbound", configured.Get("outbound"), `{"allowGuestInvitations":false,"partners":[]}`)
	if configured.Get("accessDays") != 30.0 || configured.Get("reviewEveryDays") != 90.0 {
		t.Fatalf("periods: %s", guestJSON(t, configured))
	}
	guestExpectJSON(t, "getSettings", f.settings(owner), guestJSON(t, configured))
	// Only the fields given change.
	next, err := f.configure(owner, "inbound", core.NewObject("blockedDomains", []any{"bad.test"}), "reviewEveryDays", 7.0)
	requirePorted(t, err)
	guestExpectJSON(t, "allowed domains kept", member(next.Get("inbound"), "allowedDomains"), `["b.example","partner.test"]`)
	guestExpectJSON(t, "blocked domains", member(next.Get("inbound"), "blockedDomains"), `["bad.test"]`)
	if next.Get("accessDays") != 30.0 || next.Get("reviewEveryDays") != 7.0 {
		t.Fatalf("periods: %s", guestJSON(t, next))
	}
	for _, input := range [][]any{
		{},
		{"guestBoundry", core.NewObject()},
		{"inbound", core.NewObject("allowGuest", true)},
		{"inbound", core.NewObject("allowGuests", "yes")},
		{"inbound", core.NewObject("allowedDomains", []any{"not a domain"})},
		{"inbound", core.NewObject("partners", []any{core.NewObject("tenantId", f.tenantID, "allow", true)})},
		{"inbound", core.NewObject("partners", []any{core.NewObject("tenantId", "missing", "allow", true)})},
		{"inbound", core.NewObject("partners", []any{core.NewObject("tenantId", beta.id, "allow", true), core.NewObject("tenantId", beta.id, "allow", false)})},
		{"inbound", core.NewObject("partners", []any{core.NewObject("tenantId", beta.id)})},
		{"inbound", core.NewObject("partners", "all")},
		{"outbound", core.NewObject("partners", []any{core.NewObject("tenantId", beta.id, "allow", true, "note", "x")})},
		{"outbound", nil},
		{"accessDays", 0.0}, {"accessDays", 366.0}, {"reviewEveryDays", 6.0}, {"reviewEveryDays", 366.0},
	} {
		_, err := f.configure(owner, input...)
		guestExpectCode(t, err, "INVALID_INPUT", input...)
	}
	guestExpectJSON(t, "unknown setting message", iamError(t, func() error {
		_, err := f.configure(owner, "guestBoundry", core.NewObject())
		return err
	}()).Message, `"Unknown guest setting guestBoundry"`)
	// A guest boundary is validated like any policy, and null removes it.
	_, err = f.configure(owner, "guestBoundary", core.NewObject("version", 1.0, "statements", "nope"))
	guestExpectCode(t, err, "INVALID_POLICY")
	bounded, err := f.configure(owner, "guestBoundary", core.NewObject("version", 1.0, "statements", []any{allowStatement("documents:read", "*")}))
	requirePorted(t, err)
	if !bounded.Has("guestBoundary") {
		t.Fatalf("bounded: %s", guestJSON(t, bounded))
	}
	boundary, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return GuestBoundary(ctx, tx, f.tenantID)
	})
	if err != nil || boundary == nil {
		t.Fatalf("guest boundary: %v", err)
	}
	cleared, err := f.configure(owner, "guestBoundary", nil)
	requirePorted(t, err)
	if cleared.Has("guestBoundary") {
		t.Fatalf("cleared: %s", guestJSON(t, cleared))
	}
	events := f.auditTrail(f.tenantID, "guest:settings")
	if len(events) != 4 {
		t.Fatalf("settings events: %d", len(events))
	}
	guestExpectJSON(t, "first settings event", events[0].Get("metadata"), guestJSON(t, core.NewObject(
		"changed", []any{"inbound.allowedDomains", "inbound.partners", "outbound.allowGuestInvitations", "accessDays"},
		"allowGuests", true, "allowedDomains", []any{"b.example", "partner.test"}, "blockedDomains", []any{},
		"inboundPartners", []any{core.NewObject("tenantId", beta.id, "allow", true)},
		"allowGuestInvitations", false, "outboundPartners", []any{},
		"accessDays", 30.0, "reviewEveryDays", 90.0, "guestBoundary", false,
	)))
	// Settings need a recent sign-in.
	f.clock.Add(int64(dayMs))
	_, err = f.configure(f.owner, "accessDays", 60.0)
	guestExpectCode(t, err, "RECENT_AUTH_REQUIRED")
}

func TestGuestInboundSettingsAdmitGuests(t *testing.T) {
	f := newGuestFixture(t, nil)
	globex := f.createTenant("Globex", "", "")
	initech := f.createTenant("Initech", "", "")
	f.verifyDomain(globex.id, "globex.test")
	f.verifyDomain(initech.id, "initech.test")
	f.verifyDomain(f.tenantID, "acme.example")
	owner := f.ownerSignIn()
	invite := func(email string) error {
		_, err := f.invite(owner, "email", email)
		return err
	}
	// The host's own verified domain belongs to members.
	guestExpectError(t, invite("someone@acme.example."), "GUEST_NOT_ALLOWED", "acme.example is a verified domain of this organization: invite the person as a member")
	_, err := f.configure(owner, "inbound", core.NewObject("allowGuests", false, "partners", []any{core.NewObject("tenantId", globex.id, "allow", true)}))
	requirePorted(t, err)
	guestExpectError(t, invite("a@partner.test"), "GUEST_NOT_ALLOWED", "This organization does not accept guests")
	// A partner with allow: true is admitted over allowGuests: false.
	if err := invite("gil@globex.test"); err != nil {
		requirePorted(t, err)
	}
	_, err = f.configure(owner, "inbound", core.NewObject("allowGuests", true, "allowedDomains", []any{"partner.test"},
		"blockedDomains", []any{"bad.partner.test", "globex.test"}, "partners", []any{core.NewObject("tenantId", initech.id, "allow", false), core.NewObject("tenantId", globex.id, "allow", true)}))
	requirePorted(t, err)
	guestExpectError(t, invite("x@other.test"), "GUEST_NOT_ALLOWED", "This organization accepts guests only from its allowed domains")
	guestExpectError(t, invite("x@initech.test"), "GUEST_NOT_ALLOWED", "This organization does not accept guests from the person’s organization")
	guestExpectError(t, invite("x@bad.partner.test"), "GUEST_NOT_ALLOWED", "This organization does not accept guests from bad.partner.test")
	// A blocked domain wins over a partner entry.
	guestExpectError(t, invite("y@globex.test"), "GUEST_NOT_ALLOWED", "This organization does not accept guests from globex.test")
	// Subdomains of an allowed domain are admitted.
	if err := invite("x@eu.partner.test"); err != nil {
		requirePorted(t, err)
	}
	invitations := f.invitations(owner)
	var homes []string
	for _, invitation := range invitations {
		homes = append(homes, jsString(invitation.Get("email"))+"="+jsString(invitation.Get("homeTenantId")))
	}
	sort.Strings(homes)
	guestExpectIDs(t, "home tenants", homes, "gil@globex.test="+globex.id, "x@eu.partner.test=undefined")
}

func TestGuestOutboundSettingsWithoutRevealingThem(t *testing.T) {
	f := newGuestFixture(t, nil)
	globex := f.createTenant("Globex", "", "")
	f.verifyDomain(globex.id, "globex.test")
	outbound := "The person’s organization does not allow its members to join this organization as guests"
	globexOwner := f.signIn(globex.id, "Globex@example.test")
	_, err := f.iam.API.Guests.Configure(f.ctx, globexOwner, Input[apitypes.GuestsConfigureInput](core.NewObject(
		"tenantId", globex.id, "outbound", core.NewObject("allowGuestInvitations", false))))
	requirePorted(t, err)
	for _, email := range []string{"gil@globex.test", "gil@globex.test.", "gil@GLOBEX.test."} {
		_, err := f.invite(f.owner, "email", email)
		guestExpectError(t, err, "GUEST_NOT_ALLOWED", outbound)
	}
	// A partner entry for the host lets its people in over the default.
	_, err = f.iam.API.Guests.Configure(f.ctx, globexOwner, Input[apitypes.GuestsConfigureInput](core.NewObject(
		"tenantId", globex.id, "outbound", core.NewObject("partners", []any{core.NewObject("tenantId", f.tenantID, "allow", true)}))))
	requirePorted(t, err)
	invitation := f.mustInvite(f.owner, "email", "gil@globex.test")
	if invitation.Get("homeTenantId") != globex.id {
		t.Fatalf("invitation: %s", guestJSON(t, invitation))
	}
	// The home organization changing its mind refuses the redemption.
	token := f.token("gil@globex.test")
	_, err = f.iam.API.Guests.Configure(f.ctx, globexOwner, Input[apitypes.GuestsConfigureInput](core.NewObject(
		"tenantId", globex.id, "outbound", core.NewObject("partners", []any{core.NewObject("tenantId", f.tenantID, "allow", false)}))))
	requirePorted(t, err)
	_, err = f.redeem("token", token, "name", "Gil", "password", guestTestPassword("Gil"))
	guestExpectError(t, err, "GUEST_NOT_ALLOWED", outbound)
}

func TestGuestAddressSpelling(t *testing.T) {
	for _, item := range []struct{ input, want string }{
		{"Ann@Partner.Test.", "ann@partner.test"},
		{"bob@bücher.example", "bob@xn--bcher-kva.example"},
		{"bob@BÜCHER.example.", "bob@xn--bcher-kva.example"},
		{"bob@ｂüｃｈｅｒ.example", "bob@xn--bcher-kva.example"},
	} {
		got, err := GuestAddress(item.input)
		if err != nil || got != item.want {
			t.Fatalf("%s: got %q (%v), want %q", item.input, got, err, item.want)
		}
	}
	for _, input := range []string{"x@partner..test", "x@[192.0.2.1]", "x@partner.test.."} {
		_, err := GuestAddress(input)
		expectError(t, err, "INVALID_INPUT", "Invalid email: its domain is not a DNS name")
	}
	_, err := GuestAddress("not an address")
	expectError(t, err, "INVALID_INPUT", "Invalid email")
	if !domainListed("eu.partner.test", []any{"partner.test"}) || domainListed("notpartner.test", []any{"partner.test"}) {
		t.Fatal("domainListed matches a domain and its subdomains only")
	}
}

func TestGuestContextAndMarkers(t *testing.T) {
	guest := identity("g", "org", "guest", core.NewObject("sponsorId", "alice", "homeTenantId", "globex", "since", 1.0))
	guestExpectJSON(t, "own tenant", GuestContext(guest, true), `{"principal.guest":true,"principal.guestSponsorId":"alice","principal.homeTenantId":"globex"}`)
	guestExpectJSON(t, "assumed elsewhere", GuestContext(guest, false), `{"principal.guest":false}`)
	if ok, _ := IsGuest(guest); !ok {
		t.Fatal("a marked identity is a guest")
	}
	if ok, _ := IsGuest(identity("m", "org")); ok {
		t.Fatal("an unmarked identity is no guest")
	}
}

func TestGuestRenewalBySponsorOrAdministrator(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	f.person("bob")
	gina := f.seedGuest("gina", aliceID, 90)
	hal := f.seedGuest("hal", aliceID, 90)
	guestID := jsString(gina.Get("id"))
	firstEnd := f.now() + 90*dayMs
	// A month in, the sponsor renews for 60 days without any permission.
	f.clock.Add(int64(30 * dayMs))
	asAlice := f.login("alice")
	secondEnd := f.now() + 60*dayMs
	renewed, err := f.attest(asAlice, "identityId", guestID, "days", 60.0)
	requirePorted(t, err)
	if renewed.Get("expiresAt") != secondEnd || renewed.Get("attestedAt") != f.now() || renewed.Get("attestedBy") != aliceID ||
		renewed.Get("reviewDueAt") != secondEnd || renewed.Get("accountStatus") != "active" {
		t.Fatalf("renewed: %s", guestJSON(t, renewed))
	}
	if account := f.record(GuestCollections.Accounts, guestID); account.Get("grantsEndAt") != secondEnd {
		t.Fatalf("account: %s", guestJSON(t, account))
	}
	for _, days := range []any{0.0, 366.0, 1.5, "30"} {
		_, err := f.attest(asAlice, "identityId", guestID, "days", days)
		guestExpectCode(t, err, "INVALID_INPUT", days)
	}
	// Nobody else renews without iam:guests:manage; guests never renew, themselves or others.
	_, err = f.attest(f.login("bob"), "identityId", guestID)
	guestExpectCode(t, err, "ACCESS_DENIED")
	_, err = f.attest(f.guestLogin("gina"), "identityId", guestID)
	guestExpectCode(t, err, "ACCESS_DENIED")
	asHal := f.guestLogin("hal")
	for _, identityID := range []any{hal.Get("id"), guestID} {
		_, err := f.attest(asHal, "identityId", identityID)
		guestExpectCode(t, err, "ACCESS_DENIED", identityID)
	}
	owned := f.ownerSignIn()
	_, err = f.attest(owned, "identityId", "missing")
	guestExpectCode(t, err, "NOT_FOUND")
	_, err = f.attest(owned, "identityId", aliceID)
	guestExpectCode(t, err, "NOT_FOUND")
	// An administrator renews with the tenant's default.
	thirdEnd := f.now() + 90*dayMs
	byOwner, err := f.attest(owned, "identityId", guestID)
	requirePorted(t, err)
	if byOwner.Get("expiresAt") != thirdEnd {
		t.Fatalf("renewed by the owner: %s", guestJSON(t, byOwner))
	}
	attests := f.auditTrail(f.tenantID, "guest:attest")
	var actors []string
	for _, event := range attests {
		actors = append(actors, jsString(event.Get("actorId"))+":"+jsString(member(event.Get("metadata"), "asSponsor")))
	}
	guestExpectIDs(t, "attests", actors, aliceID+":true", f.ownerID+":false")
	guestExpectJSON(t, "attest metadata", attests[0].Get("metadata"), guestJSON(t, core.NewObject(
		"days", 60.0, "expiresAt", secondEnd, "reviewDueAt", secondEnd, "asSponsor", true, "previousExpiresAt", firstEnd,
	)))
	// The sponsor's renewal needs no permission check; the administrator's goes through one.
	var manage []string
	for _, event := range f.auditTrail(f.tenantID, "iam:guests:manage") {
		if event.Get("outcome") == "allow" {
			manage = append(manage, jsString(event.Get("actorId")))
		}
	}
	guestExpectIDs(t, "manage", manage, f.ownerID)
}

func TestGuestRenewalRefusedOnceEndedOrDisabled(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	ivy := f.seedGuest("ivy", aliceID, 1)
	jo := f.seedGuest("jo", aliceID, 90)
	f.change("identities", jsString(jo.Get("id")), "status", "disabled")
	f.clock.Add(int64(2 * dayMs))
	asAlice := f.login("alice")
	for _, identityID := range []any{ivy.Get("id"), jo.Get("id")} {
		_, err := f.attest(asAlice, "identityId", identityID)
		guestExpectCode(t, err, "INVALID_TRANSITION", identityID)
	}
	// The ended guest reads as expired straight away.
	view := f.mustGet(f.ownerSignIn(), ivy.Get("id"))
	if view.Get("accountStatus") != "expired" || view.Get("status") != "active" {
		t.Fatalf("ended guest: %s", guestJSON(t, view))
	}
}

func TestGuestOwnerKeepsOwnerProtection(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	gina := f.seedGuest("gina", jsString(alice.Get("id")), 90)
	identityID := gina.Get("id")
	f.change("identities", jsString(identityID), "owner", true)
	_, adminCredential := f.administrator("admin", "iam:guests:manage", "iam:guests:read")
	asAlice := f.login("alice")
	for _, attempt := range []struct {
		credential core.CredentialInput
		days       float64
	}{{asAlice, 365}, {asAlice, 1}, {adminCredential, 365}} {
		_, err := f.attest(attempt.credential, "identityId", identityID, "days", attempt.days)
		guestExpectError(t, err, "ACCESS_DENIED", "Only an owner can change an owner’s expiry")
	}
	if stored := f.record("identities", jsString(identityID)); stored.Get("expiresAt") != gina.Get("expiresAt") {
		t.Fatalf("the end moved: %s", guestJSON(t, stored))
	}
	renewed, err := f.attest(f.ownerSignIn(), "identityId", identityID, "days", 30.0)
	requirePorted(t, err)
	if renewed.Get("expiresAt") != f.now()+30*dayMs {
		t.Fatalf("renewed by an owner: %s", guestJSON(t, renewed))
	}
}

func TestGuestSponsorChange(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice, bob, carol := f.person("alice"), f.person("bob"), f.person("carol")
	aliceID, bobID := jsString(alice.Get("id")), jsString(bob.Get("id"))
	f.change("identities", jsString(carol.Get("id")), "status", "disabled")
	gina := f.seedGuest("gina", aliceID, 90)
	hal := f.seedGuest("hal", f.ownerID, 90)
	owner := f.owner
	for _, sponsorID := range []any{gina.Get("id"), hal.Get("id"), carol.Get("id"), "missing"} {
		_, err := f.setSponsor(owner, gina.Get("id"), sponsorID)
		guestExpectCode(t, err, "INVALID_SPONSOR", sponsorID)
	}
	_, err := f.setSponsor(owner, gina.Get("id"), "")
	guestExpectCode(t, err, "INVALID_INPUT")
	for _, identityID := range []any{"missing", bobID} {
		_, err := f.setSponsor(owner, identityID, bobID)
		guestExpectCode(t, err, "NOT_FOUND", identityID)
	}
	moved, err := f.setSponsor(owner, gina.Get("id"), bobID)
	requirePorted(t, err)
	if moved.Get("sponsorId") != bobID || moved.Get("sponsorName") != "bob" || moved.Get("sponsorMissing") != false {
		t.Fatalf("moved: %s", guestJSON(t, moved))
	}
	if sponsor := member(f.record("identities", jsString(gina.Get("id"))).Get("guest"), "sponsorId"); sponsor != bobID {
		t.Fatalf("marker sponsor %v", sponsor)
	}
	asBob, asAlice := f.login("bob"), f.login("alice")
	guestExpectIDs(t, "mine of bob", guestIDs(f.mine(asBob), "identityId"), jsString(gina.Get("id")))
	guestExpectIDs(t, "mine of alice", guestIDs(f.mine(asAlice), "identityId"))
	// The former sponsor lost the right to renew; the new one has it.
	_, err = f.attest(asAlice, "identityId", gina.Get("id"))
	guestExpectCode(t, err, "ACCESS_DENIED")
	renewed, err := f.attest(asBob, "identityId", gina.Get("id"))
	requirePorted(t, err)
	if renewed.Get("attestedBy") != bobID {
		t.Fatalf("renewed: %s", guestJSON(t, renewed))
	}
	guestExpectIDs(t, "list by sponsor", guestIDs(guestViews(t, f.list(owner, "sponsorId", bobID)), "identityId"), jsString(gina.Get("id")))
	events := f.auditTrail(f.tenantID, "guest:sponsor-change")
	if len(events) != 1 || events[0].Get("actorId") != f.ownerID || events[0].Get("resourceId") != gina.Get("id") {
		t.Fatalf("events: %s", guestJSON(t, events))
	}
	guestExpectJSON(t, "metadata", events[0].Get("metadata"), guestJSON(t, core.NewObject("from", aliceID, "to", bobID, "reason", "administrator")))
	// Guests never choose a sponsor, their own included.
	_, err = f.setSponsor(f.guestLogin("gina"), gina.Get("id"), bobID)
	guestExpectCode(t, err, "ACCESS_DENIED")
}

func TestGuestDirectoryPagesAndFilters(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	names := []string{"dora", "cleo", "bea", "ada"}
	ids := map[string]string{}
	for index, name := range names {
		sponsor := f.ownerID
		if index%2 == 0 {
			sponsor = aliceID
		}
		ids[name] = jsString(f.seedGuest(name, sponsor, float64(10*(index+1))).Get("id"))
	}
	owner := f.owner
	page := f.list(owner)
	if page.Get("total") != 4.0 {
		t.Fatalf("total %v", page.Get("total"))
	}
	guestExpectIDs(t, "by name", guestIDs(guestViews(t, page), "name"), "ada", "bea", "cleo", "dora")
	guestExpectIDs(t, "paged", guestIDs(guestViews(t, f.list(owner, "limit", 2.0, "offset", 1.0)), "name"), "bea", "cleo")
	guestExpectIDs(t, "past the end", guestIDs(guestViews(t, f.list(owner, "offset", 10.0)), "name"))
	guestExpectIDs(t, "of a sponsor", guestIDs(guestViews(t, f.list(owner, "sponsorId", aliceID)), "name"), "bea", "dora")
	guestExpectIDs(t, "expiring", guestIDs(guestViews(t, f.list(owner, "expiringWithinDays", 20.0)), "name"), "cleo", "dora")
	f.clock.Add(int64(15 * dayMs))
	owner = f.ownerSignIn()
	guestExpectIDs(t, "expired", guestIDs(guestViews(t, f.list(owner, "status", "expired")), "name"), "dora")
	guestExpectIDs(t, "active", guestIDs(guestViews(t, f.list(owner, "status", "active")), "name"), "ada", "bea", "cleo")
	for _, input := range [][]any{{"limit", 0.0}, {"limit", 1001.0}, {"offset", -1.0}, {"status", "lost"}, {"sponsorId", ""}, {"expiringWithinDays", 3651.0}} {
		_, err := f.iam.API.Guests.List(f.ctx, owner, Input[apitypes.GuestsListInput](f.body(input...)))
		guestExpectCode(t, err, "INVALID_INPUT", input...)
	}
	// The sponsor's own list: the active guests, the soonest review first.
	// Dora's access ended, but her account is active until the sweep records it.
	guestExpectIDs(t, "mine", guestIDs(f.mine(f.login("alice")), "name"), "dora", "bea")
}

func TestGuestSweep(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice, bob := f.person("alice"), f.person("bob")
	aliceID, bobID := jsString(alice.Get("id")), jsString(bob.Get("id"))
	f.mustInvite(f.owner, "email", "late@partner.test", "expiresInDays", 1.0)
	gina := f.seedGuest("gina", aliceID, 3)
	hal := f.seedGuest("hal", bobID, 30)
	ginaID, halID := jsString(gina.Get("id")), jsString(hal.Get("id"))
	guestExpectJSON(t, "nothing to do", f.sweep(nil), zeroSweep)
	f.clock.Add(int64(2 * dayMs))
	guestExpectJSON(t, "lapsed invitation", f.sweep(nil), strings.Replace(zeroSweep, `"invitationsExpired":0`, `"invitationsExpired":1`, 1))
	late := f.find(GuestCollections.Invitations, core.NewObject("tenantId", f.tenantID, "email", "late@partner.test"))[0]
	if late.Get("status") != "expired" || late.Has("uniqueKey") {
		t.Fatalf("late: %s", guestJSON(t, late))
	}
	// An ended guest reads as expired at once; the sweep records it.
	f.clock.Add(int64(2 * dayMs))
	guestExpectIDs(t, "expired", guestIDs(guestViews(t, f.list(f.ownerSignIn(), "status", "expired")), "identityId"), ginaID)
	guestExpectJSON(t, "ended account", f.sweep(nil), strings.Replace(zeroSweep, `"accountsExpired":0`, `"accountsExpired":1`, 1))
	guestExpectJSON(t, "again", f.sweep(nil), zeroSweep)
	account := f.record(GuestCollections.Accounts, ginaID)
	if account.Get("status") != "expired" || account.Get("endedAt") != gina.Get("expiresAt") {
		t.Fatalf("expired account: %s", guestJSON(t, account))
	}
	// An administrator gives the guest a later end (and the account stays enabled): the account comes back.
	f.change("identities", ginaID, "expiresAt", f.now()+10*dayMs)
	guestExpectJSON(t, "restored", f.sweep(nil), strings.Replace(zeroSweep, `"accountsRestored":0`, `"accountsRestored":1`, 1))
	if restored := f.record(GuestCollections.Accounts, ginaID); restored.Has("endedAt") || restored.Get("status") != "active" {
		t.Fatalf("restored: %s", guestJSON(t, restored))
	}
	// A sponsor who can no longer sponsor leaves the guest flagged, and the owners hear about it once per loss.
	f.mu.Lock()
	f.inbox = nil
	f.mu.Unlock()
	f.change("identities", bobID, "status", "disabled")
	flagged := strings.NewReplacer(`"sponsorsMissing":0`, `"sponsorsMissing":1`, `"ownersNotified":0`, `"ownersNotified":1`).Replace(zeroSweep)
	guestExpectJSON(t, "sponsor left", f.sweep(nil), flagged)
	guestExpectJSON(t, "told once", f.sweep(nil), zeroSweep)
	f.dispatch()
	notices := f.messages(f.tenantID, "guest-sponsor-missing")
	if len(notices) != 1 || notices[0].To != "acme@example.test" {
		t.Fatalf("notices: %+v", notices)
	}
	guestExpectJSON(t, "notice", core.Normalize(notices[0].Payload), guestJSON(t, core.Normalize(map[string]string{
		"tenantId": f.tenantID, "tenantName": "Acme", "guestId": halID, "guestName": "hal", "guestEmail": "hal@partner.test", "sponsorName": "bob",
	})))
	view := f.mustGet(f.owner, halID)
	if view.Get("sponsorMissing") != true || view.Get("sponsorId") != bobID {
		t.Fatalf("flagged view: %s", guestJSON(t, view))
	}
	// The sponsor returns: the flag clears. They leave again: a new loss, a new notice.
	f.change("identities", bobID, "status", "active")
	guestExpectJSON(t, "returned", f.sweep(nil), zeroSweep)
	if f.mustGet(f.owner, halID).Get("sponsorMissing") != false {
		t.Fatal("the flag clears when the sponsor returns")
	}
	f.change("identities", bobID, "status", "disabled")
	guestExpectJSON(t, "left again", f.sweep(nil), flagged)
	// A new sponsor settles it.
	if _, err := f.setSponsor(f.ownerSignIn(), halID, aliceID); err != nil {
		requirePorted(t, err)
	}
	guestExpectJSON(t, "settled", f.sweep(nil), zeroSweep)
	var trail []string
	events := append(f.auditTrail(f.tenantID, "guest:expire"), f.auditTrail(f.tenantID, "guest:sponsor-missing")...)
	sort.SliceStable(events, func(i, j int) bool { return jsNumber(events[i].Get("sequence")) < jsNumber(events[j].Get("sequence")) })
	for _, event := range events {
		trail = append(trail, jsString(event.Get("action"))+":"+jsString(event.Get("actorId"))+":"+jsString(event.Get("resourceId")))
	}
	guestExpectIDs(t, "trail", trail, "guest:expire:deployment-operator:"+ginaID,
		"guest:sponsor-missing:deployment-operator:"+halID, "guest:sponsor-missing:deployment-operator:"+halID)
	// Partner entries naming an organization that no longer exists are dropped.
	initech := organization{id: "initech"}
	f.seed("tenants", core.NewObject("id", "initech", "tenantId", "initech", "name", "Initech", "type", "organization", "parentId", f.rootID, "status", "active", "createdAt", f.now()))
	if _, err := f.configure(f.ownerSignIn(), "inbound", core.NewObject("partners", []any{core.NewObject("tenantId", initech.id, "allow", true)}),
		"outbound", core.NewObject("partners", []any{core.NewObject("tenantId", initech.id, "allow", false)})); err != nil {
		requirePorted(t, err)
	}
	guestExpectJSON(t, "partners kept", f.sweep(core.NewObject("tenantId", f.tenantID)), zeroSweep)
	if err := f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "tenants", initech.id)
	}); err != nil {
		t.Fatal(err)
	}
	guestExpectJSON(t, "partners dropped", f.sweep(core.NewObject("tenantId", f.tenantID)), strings.Replace(zeroSweep, `"partnersRemoved":0`, `"partnersRemoved":2`, 1))
	settings := f.settings(f.ownerSignIn())
	guestExpectJSON(t, "partners", []any{member(settings.Get("inbound"), "partners"), member(settings.Get("outbound"), "partners")}, `[[],[]]`)
}

func TestGuestReviewReminders(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	if _, err := f.configure(f.owner, "reviewEveryDays", 30.0); err != nil {
		requirePorted(t, err)
	}
	start := f.now()
	gina := f.seedGuest("gina", aliceID, 90)
	f.change(GuestCollections.Accounts, jsString(gina.Get("id")), "reviewDueAt", start+30*dayMs)
	hal := f.seedGuest("hal", aliceID, 10)
	ginaID, halID := jsString(gina.Get("id")), jsString(hal.Get("id"))
	for _, days := range []float64{0, 91, 1.5} {
		_, err := f.remind(core.NewObject("withinDays", days))
		guestExpectCode(t, err, "INVALID_INPUT")
	}
	// Hal's access ends in ten days; Gina's review is a month out.
	sent, err := f.remind(nil)
	requirePorted(t, err)
	guestExpectJSON(t, "first run", sent, guestJSON(t, core.NewObject(
		"sent", []any{core.NewObject("tenantId", f.tenantID, "guestId", halID, "sponsorId", aliceID, "dueAt", start+10*dayMs)},
		"skipped", core.NewObject("inactive", 0.0, "quiet", 0.0),
	)))
	f.dispatch()
	reminders := f.messages(f.tenantID, "guest-review")
	if len(reminders) != 1 || reminders[0].To != "alice@acme.test" {
		t.Fatalf("reminders: %+v", reminders)
	}
	end := isoString(start + 10*dayMs)
	guestExpectJSON(t, "reminder", core.Normalize(reminders[0].Payload), guestJSON(t, core.Normalize(map[string]string{
		"tenantId": f.tenantID, "tenantName": "Acme", "guestId": halID, "guestName": "hal", "guestEmail": "hal@partner.test",
		"dueAt": end, "reviewDueAt": end, "expiresAt": end,
	})))
	// Nothing new: nothing sent.
	quiet, err := f.remind(nil)
	requirePorted(t, err)
	guestExpectJSON(t, "quiet", quiet, `{"sent":[],"skipped":{"inactive":0,"quiet":1}}`)
	// Seventeen days on, Gina's review is near; Hal's access has ended, so nobody is reminded about him.
	f.clock.Add(int64(17 * dayMs))
	next, err := f.remind(nil)
	requirePorted(t, err)
	guestExpectJSON(t, "gina", next.Get("sent"), guestJSON(t, []any{core.NewObject("tenantId", f.tenantID, "guestId", ginaID, "sponsorId", aliceID, "dueAt", start+30*dayMs)}))
	// Renewing moves the due date; the new one is reminded when it nears.
	if _, err := f.attest(f.login("alice"), "identityId", ginaID, "days", 20.0); err != nil {
		requirePorted(t, err)
	}
	after, err := f.remind(nil)
	requirePorted(t, err)
	guestExpectJSON(t, "after renewal", after.Get("sent"), "[]")
	f.clock.Add(int64(10 * dayMs))
	renewedDue, err := f.remind(nil)
	requirePorted(t, err)
	guestExpectJSON(t, "renewed due", renewedDue.Get("sent"), guestJSON(t, []any{core.NewObject("tenantId", f.tenantID, "guestId", ginaID, "sponsorId", aliceID, "dueAt", start+37*dayMs)}))
	var events []string
	for _, event := range f.auditTrail(f.tenantID, "guest:review-reminder") {
		events = append(events, jsString(event.Get("actorId"))+":"+jsString(event.Get("resourceId")))
	}
	sort.Strings(events)
	want := []string{"deployment-operator:" + ginaID, "deployment-operator:" + ginaID, "deployment-operator:" + halID}
	sort.Strings(want)
	guestExpectIDs(t, "reminder events", events, want...)
	// A suspended organization is left alone.
	f.change("tenants", f.tenantID, "status", "suspended")
	f.clock.Add(int64(40 * dayMs))
	suspended, err := f.remind(core.NewObject("tenantId", f.tenantID))
	requirePorted(t, err)
	guestExpectJSON(t, "suspended", suspended, `{"sent":[],"skipped":{"inactive":1,"quiet":0}}`)
}

func TestGuestJobsWithoutEmailDelivery(t *testing.T) {
	f := newGuestFixture(t, func(options *BetterIamOptions) { options.Authentication.SendEmail = nil })
	_, err := f.remind(nil)
	guestExpectCode(t, err, "DELIVERY_REQUIRED")
	guestExpectJSON(t, "sweep", f.sweep(nil), zeroSweep)
	_, err = f.invite(f.owner, "email", "x@partner.test")
	guestExpectError(t, err, "DELIVERY_REQUIRED", "Guest invitations require an email delivery callback")
}

func TestGuestsWhenPeopleLeave(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice, bob, carol, dave := f.person("alice"), f.person("bob"), f.person("carol"), f.person("dave")
	aliceID, bobID := jsString(alice.Get("id")), jsString(bob.Get("id"))
	gina := f.seedGuest("gina", aliceID, 90)
	hal := f.seedGuest("hal", aliceID, 90)
	ivy := f.seedGuest("ivy", jsString(carol.Get("id")), 90)
	jo := f.seedGuest("jo", jsString(dave.Get("id")), 90)
	ownerPrincipal := f.iam.Context.Decisions.SimulatedPrincipal(f.record("identities", f.ownerID), true)
	handOver := func(leaver, successor *core.Object) *core.Object {
		t.Helper()
		counts, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			return HandOverGuests(ctx, f.iam.Context, tx, ownerPrincipal, leaver, successor)
		})
		requirePorted(t, err)
		return counts
	}
	// With a successor who can sponsor, the guests move to them.
	guestExpectJSON(t, "first", handOver(alice, bob), `{"reassigned":2,"unsponsored":0}`)
	for _, guest := range []*core.Object{gina, hal} {
		if sponsor := member(f.record("identities", jsString(guest.Get("id"))).Get("guest"), "sponsorId"); sponsor != bobID {
			t.Fatalf("sponsor %v", sponsor)
		}
	}
	// Without one, or with a guest as successor, they are flagged.
	guestExpectJSON(t, "second", handOver(carol, nil), `{"reassigned":0,"unsponsored":1}`)
	guestExpectJSON(t, "third", handOver(dave, f.record("identities", jsString(gina.Get("id")))), `{"reassigned":0,"unsponsored":1}`)
	for _, guest := range []*core.Object{ivy, jo} {
		if view := f.mustGet(f.owner, guest.Get("id")); view.Get("sponsorMissing") != true {
			t.Fatalf("flagged: %s", guestJSON(t, view))
		}
	}
	// Offboarding a guest closes its guest account.
	guestExpectJSON(t, "fourth", handOver(f.record("identities", jsString(hal.Get("id"))), nil), `{"reassigned":0,"unsponsored":0}`)
	closed := f.record(GuestCollections.Accounts, jsString(hal.Get("id")))
	if closed.Get("status") != "removed" || closed.Get("removalReason") != "Offboarded" || closed.Get("endedBy") != f.ownerID {
		t.Fatalf("closed: %s", guestJSON(t, closed))
	}
	var trail []string
	for _, event := range f.find("audit", core.NewObject("tenantId", f.tenantID)) {
		if action := jsString(event.Get("action")); action == "guest:sponsor-change" || action == "guest:sponsor-missing" {
			trail = append(trail, action+" "+guestJSON(t, event.Get("metadata")))
		}
	}
	sort.Strings(trail)
	wantTrail := []string{
		`guest:sponsor-change {"from":"` + aliceID + `","to":"` + bobID + `","reason":"offboarding"}`,
		`guest:sponsor-change {"from":"` + aliceID + `","to":"` + bobID + `","reason":"offboarding"}`,
		`guest:sponsor-missing {"sponsorId":"` + jsString(carol.Get("id")) + `","reason":"offboarding"}`,
		`guest:sponsor-missing {"sponsorId":"` + jsString(dave.Get("id")) + `","reason":"offboarding"}`,
	}
	sort.Strings(wantTrail)
	guestExpectIDs(t, "trail", trail, wantTrail...)
	// The sweep tells the owners about the flagged guests (already audited, so not counted again). Offboarding disabled
	// the leavers.
	for _, leaver := range []*core.Object{alice, carol, dave} {
		f.change("identities", jsString(leaver.Get("id")), "status", "disabled")
	}
	swept := f.sweep(nil)
	if swept.Get("sponsorsMissing") != 0.0 || swept.Get("ownersNotified") != 2.0 {
		t.Fatalf("sweep: %s", guestJSON(t, swept))
	}
}

func TestGuestRecordsReleasedOnDeletion(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	gina := f.seedGuest("gina", aliceID, 90)
	hal := f.seedGuest("hal", f.ownerID, 90)
	ownerPrincipal := f.iam.Context.Decisions.SimulatedPrincipal(f.record("identities", f.ownerID), true)
	release := func(identity *core.Object) {
		t.Helper()
		if err := f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
			return ReleaseGuestRecords(ctx, f.iam.Context, tx, ownerPrincipal, identity)
		}); err != nil {
			t.Fatal(err)
		}
	}
	release(hal)
	if account := f.record(GuestCollections.Accounts, jsString(hal.Get("id"))); account != nil {
		t.Fatalf("the deleted guest's account remains: %s", guestJSON(t, account))
	}
	release(alice)
	view := f.mustGet(f.owner, gina.Get("id"))
	if view.Get("sponsorMissing") != true || view.Get("sponsorId") != aliceID {
		t.Fatalf("flagged: %s", guestJSON(t, view))
	}
	events := f.auditTrail(f.tenantID, "guest:sponsor-missing")
	if len(events) != 1 || events[0].Get("actorId") != f.ownerID || events[0].Get("resourceId") != gina.Get("id") {
		t.Fatalf("events: %s", guestJSON(t, events))
	}
	guestExpectJSON(t, "metadata", events[0].Get("metadata"), guestJSON(t, core.NewObject("sponsorId", aliceID, "reason", "deletion")))
}

func TestGuestInvitationsRevokedWhenInviterOrSponsorLeaves(t *testing.T) {
	f := newGuestFixture(t, nil)
	lead, leadCredential := f.administrator("lead", "iam:guests:invite")
	alice := f.person("alice")
	byLead := f.mustInvite(leadCredential, "email", "a@partner.test")
	forAlice := f.mustInvite(f.owner, "email", "b@partner.test", "sponsorId", alice.Get("id"))
	untouched := f.mustInvite(f.owner, "email", "c@partner.test")
	leadToken := f.token("a@partner.test")
	for _, identityID := range []any{lead.Get("id"), alice.Get("id")} {
		if err := f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
			return RevokeGuestInvitationsBy(ctx, tx, jsString(identityID))
		}); err != nil {
			t.Fatal(err)
		}
	}
	byID := map[any]*core.Object{}
	for _, invitation := range f.invitations(f.owner) {
		byID[invitation.Get("id")] = invitation
	}
	if got := byID[byLead.Get("id")]; got.Get("status") != "revoked" || got.Get("revokedReason") != "inviter-inactive" {
		t.Fatalf("by lead: %s", guestJSON(t, got))
	}
	if got := byID[forAlice.Get("id")]; got.Get("status") != "revoked" || got.Get("revokedReason") != "sponsor-inactive" {
		t.Fatalf("for alice: %s", guestJSON(t, got))
	}
	if got := byID[untouched.Get("id")]; got.Get("status") != "pending" {
		t.Fatalf("untouched: %s", guestJSON(t, got))
	}
	_, err := f.redeem("token", leadToken, "name", "A", "password", guestTestPassword("A"))
	guestExpectCode(t, err, "INVITATION_INVALID")
	// The address can be invited again.
	if again := f.mustInvite(f.owner, "email", "b@partner.test"); again.Get("status") != "pending" {
		t.Fatalf("again: %s", guestJSON(t, again))
	}
}

func TestGuestInvitationsNeedOwnSessionAndManageForAnotherSponsor(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	_, inviterCredential := f.administrator("inviter", "iam:guests:invite")
	// Naming someone else as the sponsor needs iam:guests:manage; naming oneself does not.
	_, err := f.invite(inviterCredential, "email", "a@partner.test", "sponsorId", alice.Get("id"))
	guestExpectError(t, err, "ACCESS_DENIED", "Naming someone else as the sponsor needs iam:guests:manage")
	inviter := f.find("identities", core.NewObject("tenantId", f.tenantID, "email", "inviter@acme.test"))[0]
	self := f.mustInvite(inviterCredential, "email", "b@partner.test", "sponsorId", inviter.Get("id"))
	if self.Get("sponsorId") != inviter.Get("id") {
		t.Fatalf("self: %s", guestJSON(t, self))
	}
	denials := 0
	for _, event := range f.auditTrail(f.tenantID, "iam:guests:invite") {
		if event.Get("outcome") == "deny" {
			denials++
		}
	}
	if denials != 1 {
		t.Fatalf("denials: %d", denials)
	}
	// Guests cannot sponsor: a guest inviting without naming a sponsor is refused.
	gus := f.seedGuest("gus", f.ownerID, 90)
	role := f.createRole(f.owner, "name", "Guest inviter", "permissions", []any{"iam:guests:invite"})
	f.bind(f.owner, role.Get("id"), "identity", gus.Get("id"))
	_, err = f.invite(f.guestLogin("gus"), "email", "c@partner.test")
	guestExpectCode(t, err, "INVALID_SPONSOR")
}

// afterChange accepts an answer whose only failure is the package-automation stub that runs after the operation
// committed (afterIdentityChange), so the committed state can still be checked.
func guestAfterChange(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if known := iamError(t, err); known.Code == "NOT_IMPLEMENTED" && strings.Contains(known.Message, "afterIdentityChange") {
		return
	}
	requirePorted(t, err)
}

func TestGuestConversionToMember(t *testing.T) {
	f := newGuestFixture(t, nil)
	gina := f.seedGuest("gina", f.ownerID, 90)
	hal := f.seedGuest("hal", f.ownerID, 90)
	end := gina.Get("expiresAt")
	owner := f.owner
	convert := func(members ...any) (any, error) {
		out, err := f.iam.API.Guests.ConvertToMember(f.ctx, owner, Input[apitypes.GuestsConvertToMemberInput](f.body(members...)))
		return out.Value, err
	}
	_, err := convert("identityId", gina.Get("id"), "clearExpiry", "yes")
	guestExpectCode(t, err, "INVALID_INPUT")
	answer, err := convert("identityId", gina.Get("id"))
	guestAfterChange(t, err)
	if member, ok := answer.(*core.Object); ok && (member.Has("guest") || member.Get("expiresAt") != end) {
		t.Fatalf("member: %s", guestJSON(t, member))
	}
	stored := f.record("identities", jsString(gina.Get("id")))
	if stored.Has("guest") || stored.Get("expiresAt") != end || stored.Get("status") != "active" {
		t.Fatalf("stored member: %s", guestJSON(t, stored))
	}
	account := f.record(GuestCollections.Accounts, jsString(gina.Get("id")))
	if account.Get("status") != "converted" || account.Get("endedAt") != f.now() || account.Get("endedBy") != f.ownerID || account.Get("grantsEndAt") != end {
		t.Fatalf("account: %s", guestJSON(t, account))
	}
	if view := f.mustGet(owner, gina.Get("id")); view.Get("accountStatus") != "converted" {
		t.Fatalf("view: %s", guestJSON(t, view))
	}
	guestExpectIDs(t, "converted", guestIDs(guestViews(t, f.list(owner, "status", "converted")), "name"), "gina")
	// A member is no guest any more: the guest actions no longer apply.
	_, err = f.attest(owner, "identityId", gina.Get("id"))
	guestExpectCode(t, err, "INVALID_TRANSITION")
	_, err = f.setSponsor(owner, gina.Get("id"), f.ownerID)
	guestExpectCode(t, err, "INVALID_TRANSITION")
	_, err = convert("identityId", gina.Get("id"))
	guestExpectCode(t, err, "INVALID_TRANSITION")
	// Clearing the expiry frees the identity of its end, and the account forgets the grants' end.
	_, err = convert("identityId", hal.Get("id"), "clearExpiry", true)
	guestAfterChange(t, err)
	if cleared := f.record("identities", jsString(hal.Get("id"))); cleared.Has("expiresAt") || cleared.Has("guest") {
		t.Fatalf("cleared: %s", guestJSON(t, cleared))
	}
	if closed := f.record(GuestCollections.Accounts, jsString(hal.Get("id"))); closed.Has("grantsEndAt") {
		t.Fatalf("closed: %s", guestJSON(t, closed))
	}
	var metadata []string
	for _, event := range f.auditTrail(f.tenantID, "guest:convert") {
		metadata = append(metadata, guestJSON(t, event.Get("metadata")))
	}
	guestExpectIDs(t, "converts", metadata,
		guestJSON(t, core.NewObject("sponsorId", f.ownerID, "clearExpiry", false, "expiresAt", end)),
		guestJSON(t, core.NewObject("sponsorId", f.ownerID, "clearExpiry", true, "expiresAt", hal.Get("expiresAt"))))
	// Guests never make anyone a member.
	ivy := f.seedGuest("ivy", f.ownerID, 90)
	_, err = f.iam.API.Guests.ConvertToMember(f.ctx, f.guestLogin("ivy"), Input[apitypes.GuestsConvertToMemberInput](f.body("identityId", ivy.Get("id"))))
	guestExpectCode(t, err, "ACCESS_DENIED")
}

func TestGuestRemoval(t *testing.T) {
	f := newGuestFixture(t, nil)
	alice := f.person("alice")
	ivy := f.seedGuest("ivy", jsString(alice.Get("id")), 90)
	_, adminCredential := f.administrator("admin", "iam:guests:manage", "iam:guests:read")
	remove := func(credential core.CredentialInput, members ...any) (*core.Object, error) {
		out, err := f.iam.API.Guests.Remove(f.ctx, credential, Input[apitypes.GuestsRemoveInput](f.body(members...)))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	for _, reason := range []any{"", strings.Repeat("x", 513), 42.0} {
		_, err := remove(adminCredential, "identityId", ivy.Get("id"), "reason", reason)
		guestExpectCode(t, err, "INVALID_INPUT", reason)
	}
	_, err := remove(adminCredential, "identityId", "missing", "reason", "x")
	guestExpectCode(t, err, "NOT_FOUND")
	removal, err := remove(adminCredential, "identityId", ivy.Get("id"), "reason", "  Project ended  ")
	guestAfterChange(t, err)
	if removal != nil {
		if member(removal.Get("guest"), "accountStatus") != "removed" || member(removal.Get("guest"), "status") != "disabled" {
			t.Fatalf("removal: %s", guestJSON(t, removal))
		}
	}
	account := f.record(GuestCollections.Accounts, jsString(ivy.Get("id")))
	if account.Get("status") != "removed" || account.Get("removalReason") != "Project ended" {
		t.Fatalf("account: %s", guestJSON(t, account))
	}
	if stored := f.record("identities", jsString(ivy.Get("id"))); stored.Get("status") != "disabled" {
		t.Fatalf("identity: %s", guestJSON(t, stored))
	}
	_, err = remove(adminCredential, "identityId", ivy.Get("id"), "reason", "again")
	guestExpectCode(t, err, "INVALID_TRANSITION")
	events := f.auditTrail(f.tenantID, "guest:remove")
	if len(events) != 1 || member(events[0].Get("metadata"), "reason") != "Project ended" {
		t.Fatalf("events: %s", guestJSON(t, events))
	}
	// A former guest's disabled account keeps its address: the refusal says how to go on.
	_, err = f.invite(f.owner, "email", "ivy@partner.test")
	guestExpectError(t, err, "CONFLICT", "This address belongs to a former guest whose disabled account still holds it: delete that account to invite the address again")
}
