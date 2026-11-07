package server

// Certification campaign tests, after tests/certifications.test.ts: snapshots, reviewer decisions, manager reviews,
// reminders, closing, and the automatic-closing worker. The roles, groups and bindings the campaigns review are
// seeded directly in the store (the API groups that write them are ported separately). Steps that revoke a binding
// go through api/bindings.ts deleteBinding; while that is a stub they end the test with a skip.

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const certDay = 86_400_000

// govFixture is a server with a controllable clock, a captured email outbox, an administrator ("admin", holding a
// protected owner-like role under its own grant authority) and helpers to seed roles, groups and bindings.
type govFixture struct {
	*decisionFixture
	clock      *atomic.Int64
	inboxMu    sync.Mutex
	inbox      []auth.DeliveryMessage
	admin      *core.Object
	adminID    string
	adminToken string
	ownerRole  string
}

const adminAuthority = "authority-admin"

func newGovFixture(t *testing.T, mutate func(options *BetterIamOptions)) *govFixture {
	t.Helper()
	clock := &atomic.Int64{}
	clock.Store(1_767_225_600_000)
	f := &govFixture{clock: clock}
	week := int64(7 * certDay)
	base := newDecisionFixture(t, func(options *BetterIamOptions) {
		options.WallClock = func() int64 { return clock.Load() }
		options.Authentication = &auth.Options{
			Now:                  func() int64 { return clock.Load() },
			SessionLifetimeMs:    &week,
			SessionIdleTimeoutMs: &week,
			SendEmail: func(_ context.Context, message auth.DeliveryMessage) error {
				f.inboxMu.Lock()
				defer f.inboxMu.Unlock()
				f.inbox = append(f.inbox, message)
				return nil
			},
		}
		if mutate != nil {
			mutate(options)
		}
	})
	f.decisionFixture = base
	f.admin = f.createIdentity("admin@example.test", "Admin", "a strong admin test password")
	f.adminID = jsString(f.admin.Get("id"))
	f.seed("grantAuthorities", core.NewObject("id", adminAuthority, "tenantId", f.tenantID, "identityId", f.adminID, "ceiling", All(), "revoked", false))
	f.ownerRole = f.role("role-owner", "Owners", true, "*")
	f.bind("binding-owner", f.ownerRole, "identity", f.adminID, adminAuthority)
	f.adminToken = f.signIn(f.admin, false)
	return f
}

func (f *govFixture) now() float64     { return float64(f.clock.Load()) }
func (f *govFixture) advance(ms int64) { f.clock.Add(ms) }

// role seeds a role (and its policy) issued under the administrator's authority, allowing actions on every resource.
func (f *govFixture) role(id, name string, protected bool, actions ...string) string {
	f.t.Helper()
	statement := core.NewObject("effect", "allow", "actions", stringsOf(actions), "resources", []any{"*"})
	f.seed("policies", core.NewObject("id", "policy-"+id, "tenantId", f.tenantID, "name", "P "+name, "document", document(statement), "version", 1.0, "authorityId", adminAuthority))
	record := core.NewObject("id", id, "tenantId", f.tenantID, "name", name, "policyIds", []any{"policy-" + id}, "authorityId", adminAuthority)
	if protected {
		record.Set("protected", true)
	}
	f.seed("roles", record)
	return id
}

// bind seeds a binding under an authority.
func (f *govFixture) bind(id, roleID, subjectType, subjectID, authority string) string {
	f.t.Helper()
	f.seed("bindings", core.NewObject("id", id, "tenantId", f.tenantID, "uniqueKey", subjectType+":"+subjectID+":"+roleID+":"+authority,
		"subjectType", subjectType, "subjectId", subjectID, "roleId", roleID, "authorityId", authority))
	return id
}

// person creates a member `{name}@acme.test`.
func (f *govFixture) person(name string) *core.Object {
	f.t.Helper()
	return f.createIdentity(name+"@acme.test", name, "a strong "+name+" password")
}

// group seeds a group with members.
func (f *govFixture) group(id, name string, members ...string) string {
	f.t.Helper()
	f.seed("groups", core.NewObject("id", id, "tenantId", f.tenantID, "name", name, "createdAt", 1.0))
	for _, identityID := range members {
		f.seed("groupMembers", core.NewObject("id", id+":"+identityID, "tenantId", f.tenantID, "groupId", id, "identityId", identityID))
	}
	return id
}

// change rewrites members of a stored record.
func (f *govFixture) change(collection, id string, members ...any) {
	f.t.Helper()
	record, err := f.iam.Store.Get(context.Background(), collection, id)
	if err != nil || record == nil {
		f.t.Fatalf("%s %s: %v", collection, id, err)
	}
	for index := 0; index+1 < len(members); index += 2 {
		record.Set(members[index].(string), members[index+1])
	}
	f.seed(collection, record)
}

func (f *govFixture) token(identity *core.Object) string { return f.signIn(identity, false) }

func (f *govFixture) dispatch() {
	f.t.Helper()
	if _, err := f.iam.Auth.DispatchOutbox(context.Background(), 0); err != nil {
		f.t.Fatal(err)
	}
}

func (f *govFixture) messages(template string) []auth.DeliveryMessage {
	f.inboxMu.Lock()
	defer f.inboxMu.Unlock()
	var found []auth.DeliveryMessage
	for _, message := range f.inbox {
		if message.Template == template {
			found = append(found, message)
		}
	}
	return found
}

func (f *govFixture) find(collection string, filter *core.Object) []*core.Object {
	f.t.Helper()
	records, err := f.iam.Store.Find(context.Background(), collection, filter, nil)
	if err != nil {
		f.t.Fatal(err)
	}
	return records
}

// call runs an API method with a token credential and a body.
func call[T, O any](method func(context.Context, core.CredentialInput, In[T]) (Out[O], error), token string, body *core.Object) (any, error) {
	out, err := method(context.Background(), core.CredentialInput{Token: token}, Input[T](body))
	return out.Value, err
}

// obj fails the test on an error and returns the object answer.
func (f *govFixture) obj(value any, err error) *core.Object {
	f.t.Helper()
	return okObject(f.t, value, err)
}

// list fails the test on an error and returns the list answer as objects.
func (f *govFixture) list(value any, err error) []*core.Object {
	f.t.Helper()
	return okList(f.t, value, err)
}

// okObject fails the test on an error and returns the object answer.
func okObject(t *testing.T, value any, err error) *core.Object {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	object, ok := value.(*core.Object)
	if !ok {
		t.Fatalf("expected an object, got %#v", value)
	}
	return object
}

// okList fails the test on an error and returns the list answer as objects.
func okList(t *testing.T, value any, err error) []*core.Object {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("expected a list, got %#v", value)
	}
	out := make([]*core.Object, len(list))
	for index, item := range list {
		out[index] = item.(*core.Object)
	}
	return out
}

func expectCodeStatus(t *testing.T, err error, code string, status int) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got no error", code)
	}
	known := iamError(t, err)
	if (code != "" && known.Code != code) || (status != 0 && known.Status != status) {
		t.Fatalf("expected %s %d, got %s %d %q", code, status, known.Code, known.Status, known.Message)
	}
}

// skipUnported ends the test with a skip when err is another module's NOT_IMPLEMENTED stub.
func skipUnported(t *testing.T, err error) {
	t.Helper()
	var known *core.IamError
	if errors.As(err, &known) && known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked on an unported module: %s", known.Message)
	}
}

func expectJSON(t *testing.T, label string, value any, want string) {
	t.Helper()
	if got := stringify(value); got != want {
		t.Errorf("%s = %s, want %s", label, got, want)
	}
}

func itemWhere(items []*core.Object, subject, role string) *core.Object {
	for _, item := range items {
		if item.Get("subjectName") == subject && item.Get("roleName") == role {
			return item
		}
	}
	return nil
}

func decisionList(entries ...*core.Object) []any {
	list := make([]any, len(entries))
	for index, entry := range entries {
		list[index] = entry
	}
	return list
}

func decision(itemID, value string, extra ...any) *core.Object {
	entry := core.NewObject("itemId", itemID, "decision", value)
	for index := 0; index+1 < len(extra); index += 2 {
		entry.Set(extra[index].(string), extra[index+1])
	}
	return entry
}

func TestCertificationsSnapshotDecideAndClose(t *testing.T) {
	f := newGovFixture(t, nil)
	api := f.iam.API.Certifications
	tenant := f.tenantID
	readers := f.role("role-readers", "Readers", false, "documents:read")
	writers := f.role("role-writers", "Writers", false, "documents:write")
	reviewers := f.role("role-reviewers", "Reviewers", false, "iam:certifications:read", "iam:certifications:review")
	alice, bob, carol, dave := f.person("alice"), f.person("bob"), f.person("carol"), f.person("dave")
	aliceID, bobID, carolID, daveID := jsString(alice.Get("id")), jsString(bob.Get("id")), jsString(carol.Get("id")), jsString(dave.Get("id"))
	team := f.group("group-team", "Team", bobID)
	f.bind("b1", readers, "identity", aliceID, adminAuthority)
	f.bind("b2", writers, "identity", bobID, adminAuthority)
	f.bind("b3", readers, "group", team, adminAuthority)
	f.bind("b4", reviewers, "identity", carolID, adminAuthority)
	f.bind("b5", reviewers, "identity", daveID, adminAuthority)
	// A binding issued under another administrator's authority: the closer may not remove it.
	rootBinding := f.bind("b6", writers, "identity", aliceID, f.authority)

	_, err := call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Bad", "reviewerIds", []any{"missing"}))
	expectCodeStatus(t, err, "", 404)
	campaign := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Q3 access review", "reviewerIds", []any{carolID}, "undecided", "revoke")))
	// Owner bindings (protected roles) are never part of a campaign.
	if campaign.Get("items") != 6.0 || campaign.Get("status") != "open" || campaign.Get("reviewerMode") != "named" {
		t.Fatalf("campaign = %s", stringify(campaign))
	}
	expectJSON(t, "progress", campaign.Get("progress"), `{"total":0,"decided":0,"keep":0,"revoke":0}`)
	campaignID := jsString(campaign.Get("id"))
	// Named reviewers are emailed.
	f.dispatch()
	invitations := f.messages("certification-review")
	if len(invitations) != 1 || invitations[0].To != "carol@acme.test" || invitations[0].Payload["campaignName"] != "Q3 access review" || invitations[0].Payload["items"] != "6" {
		t.Fatalf("invitations = %+v", invitations)
	}

	carolToken := f.token(carol)
	view := f.obj(call(api.Get, carolToken, core.NewObject("tenantId", tenant, "campaignId", campaignID, "mine", true)))
	viewItems, _ := view.Get("items").([]any)
	if len(viewItems) != 5 {
		t.Fatalf("carol's view has %d items", len(viewItems))
	}
	all := f.obj(call(api.Get, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID)))
	allItems := f.list(all.Get("items"), nil)
	// Items are ordered by role name, then subject name.
	var order []string
	for _, item := range allItems {
		order = append(order, jsString(item.Get("roleName"))+" "+jsString(item.Get("subjectName")))
	}
	if strings.Join(order, ",") != "Readers alice@acme.test,Readers Team,Reviewers carol@acme.test,Reviewers dave@acme.test,Writers alice@acme.test,Writers bob@acme.test" {
		t.Errorf("order = %v", order)
	}
	carolOwn := itemWhere(allItems, "carol@acme.test", "Reviewers")
	_, err = call(api.Decide, carolToken, core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", decisionList(decision(jsString(carolOwn.Get("id")), "keep"))))
	expectCodeStatus(t, err, "SELF_REVIEW", 403)
	aliceReaders := jsString(itemWhere(allItems, "alice@acme.test", "Readers").Get("id"))
	// Dave holds the review permission but is not a reviewer of this campaign.
	_, err = call(api.Decide, f.token(dave), core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", decisionList(decision(aliceReaders, "keep"))))
	expectCodeStatus(t, err, "", 403)
	// Alice lacks iam:certifications:review altogether.
	_, err = call(api.Decide, f.token(alice), core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", decisionList(decision(aliceReaders, "keep"))))
	expectCodeStatus(t, err, "", 403)
	// Input checks.
	_, err = call(api.Decide, carolToken, core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", []any{}))
	expectError(t, err, "INVALID_INPUT", "decisions must contain 1 to 200 entries")
	_, err = call(api.Decide, carolToken, core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", decisionList(decision(aliceReaders, "maybe"))))
	expectError(t, err, "INVALID_INPUT", "decision must be keep or revoke")
	_, err = call(api.Decide, carolToken, core.NewObject("tenantId", tenant, "campaignId", 7.0, "decisions", decisionList(decision(aliceReaders, "keep"))))
	expectError(t, err, "INVALID_INPUT", "Invalid campaignId")

	recorded := f.obj(call(api.Decide, carolToken, core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", decisionList(
		decision(aliceReaders, "keep"),
		decision(jsString(itemWhere(allItems, "alice@acme.test", "Writers").Get("id")), "revoke", "note", "  Left team  "),
		decision(jsString(itemWhere(allItems, "bob@acme.test", "Writers").Get("id")), "revoke"),
		decision(jsString(itemWhere(allItems, "dave@acme.test", "Reviewers").Get("id")), "keep"),
	))))
	expectJSON(t, "recorded", recorded, `{"recorded":4}`)
	noted, err := f.iam.Store.Get(context.Background(), "certificationItems", jsString(itemWhere(allItems, "alice@acme.test", "Writers").Get("id")))
	if err != nil || noted.Get("note") != "Left team" || noted.Get("decidedBy") != carolID || noted.Get("decidedAt") != f.now() {
		t.Errorf("decided item = %s", stringify(noted))
	}
	listed := f.list(call(api.List, f.adminToken, core.NewObject("tenantId", tenant)))
	expectJSON(t, "list progress", listed[0].Get("progress"), `{"total":6,"decided":4,"keep":2,"revoke":2}`)
	if open := f.list(call(api.List, f.adminToken, core.NewObject("tenantId", tenant, "status", "closed"))); len(open) != 0 {
		t.Errorf("closed campaigns = %d", len(open))
	}

	value, err := call(api.Close, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))
	skipUnported(t, err)
	closed := f.obj(value, err)
	if closed.Get("status") != "closed" || closed.Get("closedBy") != f.adminID {
		t.Fatalf("closed = %s", stringify(closed))
	}
	// Kept: alice Readers, dave Reviewers. Revoked: bob Writers, plus undecided Team and carol (undecided = revoke).
	// Alice's Writers binding belongs to another authority, so the administrator cannot remove it.
	expectJSON(t, "outcomes", closed.Get("outcomes"), `{"kept":2,"revoked":3,"already-removed":0,"revocation-failed":1}`)
	after := f.obj(call(api.Get, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID)))
	var failed *core.Object
	for _, item := range f.list(after.Get("items"), nil) {
		if item.Get("outcome") == "revocation-failed" {
			failed = item
		}
	}
	if failed == nil || failed.Get("bindingId") != rootBinding || !truthy(failed.Get("outcomeDetail")) {
		t.Fatalf("failed item = %v", failed)
	}
	var keys []string
	for _, binding := range f.find("bindings", core.NewObject("tenantId", tenant)) {
		keys = append(keys, jsString(binding.Get("subjectId"))+":"+jsString(binding.Get("roleId")))
	}
	joined := strings.Join(keys, ",")
	for _, kept := range []string{aliceID + ":" + readers, aliceID + ":" + writers} {
		if !strings.Contains(joined, kept) {
			t.Errorf("binding %s was removed", kept)
		}
	}
	for _, removed := range []string{bobID + ":" + writers, team + ":" + readers, carolID + ":" + reviewers} {
		if strings.Contains(joined, removed) {
			t.Errorf("binding %s was kept", removed)
		}
	}
	if deletes := f.find("audit", core.NewObject("tenantId", tenant, "action", "iam:bindings:delete")); len(deletes) != 3 {
		t.Errorf("binding deletions audited: %d", len(deletes))
	}
	_, err = call(api.Decide, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", decisionList(decision(jsString(failed.Get("id")), "keep"))))
	expectCodeStatus(t, err, "CONFLICT", 409)
	_, err = call(api.Close, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))
	expectError(t, err, "CONFLICT", "The campaign is already closed")
	expectJSON(t, "delete", f.obj(call(api.Delete, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))), `{"deleted":true}`)
	if items := f.find("certificationItems", core.NewObject("tenantId", tenant)); len(items) != 0 {
		t.Errorf("items left: %d", len(items))
	}
}

func TestCertificationsScopeByRoleAndSubjectType(t *testing.T) {
	f := newGovFixture(t, nil)
	api := f.iam.API.Certifications
	tenant := f.tenantID
	readers := f.role("role-readers", "Readers", false, "documents:read")
	writers := f.role("role-writers", "Writers", false, "documents:write")
	erinID := jsString(f.person("erin").Get("id"))
	crew := f.group("group-crew", "Crew")
	f.bind("b1", readers, "identity", erinID, adminAuthority)
	f.bind("b2", writers, "identity", erinID, adminAuthority)
	f.bind("b3", readers, "group", crew, adminAuthority)
	// Expired bindings are not reviewed; temporary ones carry their end.
	f.seed("bindings", core.NewObject("id", "b4", "tenantId", tenant, "subjectType", "identity", "subjectId", erinID, "roleId", readers, "authorityId", f.authority, "expiresAt", f.now()-1))
	f.seed("bindings", core.NewObject("id", "b5", "tenantId", tenant, "subjectType", "group", "subjectId", crew, "roleId", writers, "authorityId", f.authority, "expiresAt", f.now()+certDay, "eligible", true))

	scoped := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "  Readers only  ", "roleIds", []any{readers, readers}, "subjectType", "identity")))
	if scoped.Get("items") != 1.0 || scoped.Get("name") != "Readers only" {
		t.Fatalf("scoped = %s", stringify(scoped))
	}
	expectJSON(t, "roleIds", scoped.Get("roleIds"), `["role-readers"]`)
	groups := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Groups", "subjectType", "group")))
	groupItems := f.list(f.obj(call(api.Get, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", groups.Get("id")))).Get("items"), nil)
	if len(groupItems) != 2 || groupItems[1].Get("bindingExpiresAt") != f.now()+certDay || groupItems[1].Get("eligible") != true || groupItems[0].Get("subjectName") != "Crew" {
		t.Errorf("group items = %s", stringify(certRecordList(groupItems)))
	}
	_, err := call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Owners", "roleIds", []any{f.ownerRole}))
	expectError(t, err, "INVALID_INPUT", "Role role-owner cannot be certified")
	_, err = call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Bad", "subjectType", "robot"))
	expectError(t, err, "INVALID_INPUT", "subjectType must be identity or group")
	_, err = call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Bad", "undecided", "maybe"))
	expectError(t, err, "INVALID_INPUT", "undecided must be keep or revoke")
	_, err = call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Bad", "dueAt", f.now()))
	expectError(t, err, "INVALID_INPUT", "dueAt must be a future timestamp in milliseconds")
	_, err = call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Bad", "autoClose", "yes"))
	expectError(t, err, "INVALID_INPUT", "autoClose must be boolean")
	result := f.obj(call(api.Close, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", scoped.Get("id"))))
	expectJSON(t, "outcomes", result.Get("outcomes"), `{"kept":1,"revoked":0,"already-removed":0,"revocation-failed":0}`)
	if bindings := f.find("bindings", core.NewObject("tenantId", tenant, "subjectId", erinID)); len(bindings) != 3 {
		t.Errorf("erin's bindings = %d", len(bindings))
	}
	open := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Open")))
	_, err = call(api.Delete, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", open.Get("id")))
	expectError(t, err, "CONFLICT", "Close the campaign before deleting it")
	// Closing needs recent authentication.
	f.advance(2 * 3_600_000)
	_, err = call(api.Close, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", open.Get("id")))
	expectError(t, err, "RECENT_AUTH_REQUIRED", "Reauthenticate to perform this operation")
}

func TestCertificationsManagerReviewsAndReminders(t *testing.T) {
	f := newGovFixture(t, nil)
	api := f.iam.API.Certifications
	tenant := f.tenantID
	readers := f.role("role-readers", "Readers", false, "documents:read")
	writers := f.role("role-writers", "Writers", false, "documents:write")
	reviewers := f.role("role-reviewers", "Reviewers", false, "iam:certifications:read", "iam:certifications:review")
	// Mia manages Alice and Bob and holds no role at all; Paul manages Dana but is disabled.
	people := map[string]*core.Object{}
	ids := map[string]string{}
	for _, name := range []string{"mia", "alice", "bob", "carl", "dana", "paul", "nina", "rex"} {
		people[name] = f.person(name)
		ids[name] = jsString(people[name].Get("id"))
	}
	f.change("identities", ids["alice"], "managerId", ids["mia"])
	f.change("identities", ids["bob"], "managerId", ids["mia"])
	f.change("identities", ids["dana"], "managerId", ids["paul"])
	f.change("identities", ids["paul"], "status", "disabled")
	team := f.group("group-team", "Team")
	f.bind("b1", readers, "identity", ids["alice"], adminAuthority)
	f.bind("b2", writers, "identity", ids["alice"], adminAuthority)
	f.bind("b3", readers, "identity", ids["bob"], adminAuthority)
	f.bind("b4", readers, "identity", ids["carl"], adminAuthority)
	f.bind("b5", readers, "identity", ids["dana"], adminAuthority)
	f.bind("b6", readers, "group", team, adminAuthority)
	f.bind("b7", reviewers, "identity", ids["nina"], adminAuthority)
	f.bind("b8", reviewers, "identity", ids["rex"], adminAuthority)

	_, err := call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Bad", "reviewerMode", "team"))
	expectError(t, err, "INVALID_INPUT", "reviewerMode must be named or manager")
	dueAt := f.now() + 7*certDay
	campaign := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Manager review", "reviewerMode", "manager", "reviewerIds", []any{ids["nina"]}, "dueAt", dueAt)))
	if campaign.Get("reviewerMode") != "manager" || campaign.Get("items") != 8.0 || campaign.Has("autoClose") {
		t.Fatalf("campaign = %s", stringify(campaign))
	}
	campaignID := jsString(campaign.Get("id"))
	all := f.list(f.obj(call(api.Get, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))).Get("items"), nil)
	item := func(subject, role string) string { return jsString(itemWhere(all, subject, role).Get("id")) }
	var assigned []string
	unassigned := 0
	for _, row := range all {
		if row.Get("reviewerId") == ids["mia"] {
			assigned = append(assigned, jsString(row.Get("subjectName"))+" "+jsString(row.Get("roleName")))
		}
		if isUndefined(row.Get("reviewerId")) {
			unassigned++
		}
	}
	sort.Strings(assigned)
	if strings.Join(assigned, ",") != "alice@acme.test Readers,alice@acme.test Writers,bob@acme.test Readers" || unassigned != 5 {
		t.Errorf("assigned = %v, unassigned = %d", assigned, unassigned)
	}
	// One email per reviewer with their own item count.
	f.dispatch()
	invitations := f.messages("certification-review")
	byRecipient := map[string]auth.DeliveryMessage{}
	for _, message := range invitations {
		byRecipient[message.To] = message
	}
	if len(invitations) != 2 || byRecipient["mia@acme.test"].Payload["items"] != "3" || byRecipient["nina@acme.test"].Payload["items"] != "5" ||
		byRecipient["mia@acme.test"].Payload["dueAt"] != isoString(dueAt) || byRecipient["mia@acme.test"].Payload["campaignId"] != campaignID {
		t.Errorf("invitations = %+v", invitations)
	}

	// The manager's own worklist.
	miaToken := f.token(people["mia"])
	mine := f.list(call(api.ListMine, miaToken, core.NewObject("tenantId", tenant)))
	if len(mine) != 1 || mine[0].Get("id") != campaignID || mine[0].Get("dueAt") != dueAt || mine[0].Get("reviewerMode") != "manager" {
		t.Fatalf("mine = %s", stringify(certRecordList(mine)))
	}
	expectJSON(t, "mine progress", mine[0].Get("progress"), `{"total":3,"decided":0,"keep":0,"revoke":0}`)
	var worklist []string
	for _, row := range f.list(mine[0].Get("items"), nil) {
		worklist = append(worklist, jsString(row.Get("subjectName"))+" "+jsString(row.Get("roleName")))
	}
	if strings.Join(worklist, ",") != "alice@acme.test Readers,bob@acme.test Readers,alice@acme.test Writers" {
		t.Errorf("worklist = %v", worklist)
	}
	if list := f.list(call(api.ListMine, f.token(people["carl"]), core.NewObject("tenantId", tenant))); len(list) != 0 {
		t.Errorf("carl's worklist = %d", len(list))
	}
	f.seed("tenants", core.NewObject("id", "other", "tenantId", "other", "name", "Other", "type", "organization", "parentId", tenant, "status", "active", "createdAt", 1.0))
	_, err = call(api.ListMine, miaToken, core.NewObject("tenantId", "other"))
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)

	// Reminders before anyone decided: Mia for her three, Nina for the five fallback items.
	ninaToken := f.token(people["nina"])
	_, err = call(api.Remind, ninaToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))
	expectCodeStatus(t, err, "", 403)
	expectJSON(t, "remind", f.obj(call(api.Remind, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))), `{"reminded":2,"pending":8}`)
	f.dispatch()
	var reminders []string
	for _, message := range f.messages("certification-reminder") {
		reminders = append(reminders, message.To+" "+message.Payload["pending"])
	}
	sort.Strings(reminders)
	if strings.Join(reminders, ",") != "mia@acme.test 3,nina@acme.test 5" {
		t.Errorf("reminders = %v", reminders)
	}
	if remindAudits := f.find("audit", core.NewObject("tenantId", tenant, "action", "certification:remind")); len(remindAudits) != 1 ||
		stringify(remindAudits[0].Get("metadata")) != `{"reminded":2,"pending":8}` {
		t.Errorf("remind audit = %v", remindAudits)
	}

	// decide(): manager-assigned items belong to the manager; fallback items to the named reviewers.
	decideAs := func(token, itemID string) (any, error) {
		return call(api.Decide, token, core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", decisionList(decision(itemID, "keep"))))
	}
	_, err = decideAs(miaToken, item("alice@acme.test", "Readers"))
	expectCodeStatus(t, err, "", 403)
	_, err = decideAs(ninaToken, item("alice@acme.test", "Readers"))
	expectError(t, err, "ACCESS_DENIED", "This item is assigned to the person's manager")
	_, err = decideAs(ninaToken, item("nina@acme.test", "Reviewers"))
	expectCodeStatus(t, err, "SELF_REVIEW", 403)
	rexToken := f.token(people["rex"])
	_, err = decideAs(rexToken, item("carl@acme.test", "Readers"))
	expectError(t, err, "ACCESS_DENIED", "You are not a reviewer of this campaign")
	_, err = decideAs(rexToken, item("bob@acme.test", "Readers"))
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)
	expectJSON(t, "nina decides", f.obj(call(api.Decide, ninaToken, core.NewObject("tenantId", tenant, "campaignId", campaignID, "decisions", decisionList(
		decision(item("carl@acme.test", "Readers"), "keep"),
		decision(item("dana@acme.test", "Readers"), "revoke"),
	)))), `{"recorded":2}`)
	// Holders of iam:certifications:manage may still decide a manager's item.
	expectJSON(t, "admin decides", f.obj(decideAs(f.adminToken, item("bob@acme.test", "Readers"))), `{"recorded":1}`)

	// review(): the manager decides their own items, and only those.
	review := func(token string, entries []any, tenantID string) (any, error) {
		return call(api.Review, token, core.NewObject("tenantId", tenantID, "campaignId", campaignID, "decisions", entries))
	}
	_, err = review(miaToken, decisionList(decision(item("carl@acme.test", "Readers"), "keep")), tenant)
	expectError(t, err, "ACCESS_DENIED", "This item is not assigned to you")
	_, err = review(miaToken, decisionList(decision("missing", "keep")), tenant)
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)
	_, err = review(miaToken, decisionList(decision(item("alice@acme.test", "Readers"), "keep")), "other")
	expectCodeStatus(t, err, "", 403)
	_, err = review(miaToken, []any{}, tenant)
	expectError(t, err, "INVALID_INPUT", "decisions must contain 1 to 200 entries")
	_, err = review(miaToken, []any{"x"}, tenant)
	expectError(t, err, "INVALID_INPUT", "decision must be keep or revoke")
	_, err = review(miaToken, decisionList(core.NewObject("decision", "keep")), tenant)
	expectError(t, err, "INVALID_INPUT", "Invalid itemId")
	_, err = review(rexToken, decisionList(decision(item("alice@acme.test", "Readers"), "keep")), tenant)
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)
	expectJSON(t, "review", f.obj(review(miaToken, decisionList(
		decision(item("alice@acme.test", "Readers"), "keep"),
		decision(item("alice@acme.test", "Writers"), "revoke", "note", "Moved team"),
	), tenant)), `{"recorded":2}`)
	reviewed := f.find("audit", core.NewObject("tenantId", tenant, "action", "certification:review"))
	if len(reviewed) != 1 || reviewed[0].Get("actorId") != ids["mia"] || reviewed[0].Get("resourceId") != campaignID || reviewed[0].Get("outcome") != "allow" ||
		stringify(reviewed[0].Get("metadata")) != `{"recorded":2,"keep":1,"revoke":1}` {
		t.Errorf("review audit = %s", stringify(certRecordList(reviewed)))
	}
	writersItem, _ := f.iam.Store.Get(context.Background(), "certificationItems", item("alice@acme.test", "Writers"))
	if writersItem.Get("decision") != "revoke" || writersItem.Get("decidedBy") != ids["mia"] || writersItem.Get("note") != "Moved team" {
		t.Errorf("decided writers item = %s", stringify(writersItem))
	}
	expectJSON(t, "mine progress after review", f.list(call(api.ListMine, miaToken, core.NewObject("tenantId", tenant)))[0].Get("progress"), `{"total":3,"decided":3,"keep":2,"revoke":1}`)
	// Only the three unassigned, undecided items remain, all Nina's.
	expectJSON(t, "remind again", f.obj(call(api.Remind, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))), `{"reminded":1,"pending":3}`)

	value, err := call(api.Close, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))
	skipUnported(t, err)
	closed := f.obj(value, err)
	if closed.Get("closedBy") != f.adminID {
		t.Errorf("closedBy = %v", closed.Get("closedBy"))
	}
	expectJSON(t, "outcomes", closed.Get("outcomes"), `{"kept":6,"revoked":2,"already-removed":0,"revocation-failed":0}`)
	var remaining []string
	for _, binding := range f.find("bindings", core.NewObject("tenantId", tenant)) {
		remaining = append(remaining, jsString(binding.Get("subjectId"))+" "+jsString(binding.Get("roleId")))
	}
	joined := strings.Join(remaining, ",")
	if strings.Contains(joined, ids["alice"]+" "+writers) || strings.Contains(joined, ids["dana"]+" "+readers) || !strings.Contains(joined, ids["alice"]+" "+readers) {
		t.Errorf("remaining = %v", remaining)
	}
	_, err = review(miaToken, decisionList(decision(item("bob@acme.test", "Readers"), "keep")), tenant)
	expectError(t, err, "CONFLICT", "The campaign is closed")
	_, err = call(api.Remind, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaignID))
	expectCodeStatus(t, err, "CONFLICT", 409)
	if list := f.list(call(api.ListMine, miaToken, core.NewObject("tenantId", tenant))); len(list) != 0 {
		t.Errorf("worklist after close = %d", len(list))
	}
}

func TestCertificationsRemindNobodyAndRequireDelivery(t *testing.T) {
	f := newGovFixture(t, nil)
	api := f.iam.API.Certifications
	tenant := f.tenantID
	readers := f.role("role-readers", "Readers", false, "documents:read")
	f.bind("b1", readers, "identity", jsString(f.person("erin").Get("id")), adminAuthority)
	campaign := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Open to all")))
	if campaign.Get("reviewerMode") != "named" {
		t.Errorf("reviewerMode = %v", campaign.Get("reviewerMode"))
	}
	expectJSON(t, "remind", f.obj(call(api.Remind, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaign.Get("id")))), `{"reminded":0,"pending":1}`)
	f.dispatch()
	if reminders := f.messages("certification-reminder"); len(reminders) != 0 {
		t.Errorf("reminders = %+v", reminders)
	}
	// The same deployment without an email callback cannot send reminders.
	week := int64(7 * certDay)
	silent, err := New(&BetterIamOptions{
		Database: f.iam.Store, Secret: "http-hygiene-test-secret-with-at-least-32-chars", BaseURL: "http://localhost:3000",
		WallClock:      func() int64 { return f.clock.Load() },
		Authentication: &auth.Options{Now: func() int64 { return f.clock.Load() }, SessionLifetimeMs: &week, SessionIdleTimeoutMs: &week},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(silent.Close)
	_, err = call(silent.API.Certifications.Remind, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", campaign.Get("id")))
	expectError(t, err, "DELIVERY_REQUIRED", "Reminders require an email delivery callback")
}

func TestCertificationWorkerClosesOverdueCampaigns(t *testing.T) {
	f := newGovFixture(t, nil)
	api := f.iam.API.Certifications
	tenant := f.tenantID
	ctx := context.Background()
	readers := f.role("role-readers", "Readers", false, "documents:read")
	writers := f.role("role-writers", "Writers", false, "documents:write")
	certifiers := f.role("role-certifiers", "Certifiers", false, "iam:certifications:manage")
	erinID := jsString(f.person("erin").Get("id"))
	finnID := jsString(f.person("finn").Get("id"))
	gailID := jsString(f.person("gail").Get("id"))
	adam := f.person("adam")
	adamID := jsString(adam.Get("id"))
	f.bind("b1", readers, "identity", erinID, adminAuthority)
	finnBinding := f.bind("b2", readers, "identity", finnID, adminAuthority)
	gailBinding := f.bind("b3", readers, "identity", gailID, adminAuthority)
	f.bind("b4", writers, "identity", erinID, adminAuthority)
	f.bind("b5", certifiers, "identity", adamID, adminAuthority)

	_, err := call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "No date", "autoClose", true))
	expectError(t, err, "INVALID_INPUT", "autoClose requires dueAt")
	due := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Due", "roleIds", []any{readers}, "dueAt", f.now()+certDay, "autoClose", true, "undecided", "revoke")))
	if due.Get("autoClose") != true {
		t.Errorf("autoClose = %v", due.Get("autoClose"))
	}
	later := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Later", "roleIds", []any{readers}, "dueAt", f.now()+10*certDay, "autoClose", true)))
	manual := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Manual", "roleIds", []any{readers}, "dueAt", f.now()+certDay)))
	var erinItem *core.Object
	for _, row := range f.list(f.obj(call(api.Get, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", due.Get("id")))).Get("items"), nil) {
		if row.Get("subjectId") == erinID {
			erinItem = row
		}
	}
	f.obj(call(api.Decide, f.adminToken, core.NewObject("tenantId", tenant, "campaignId", due.Get("id"), "decisions", decisionList(decision(jsString(erinItem.Get("id")), "keep")))))
	// Adam opens a campaign and is deleted before it closes: nothing is revoked on his behalf.
	orphan := f.obj(call(api.Create, f.token(adam), core.NewObject("tenantId", tenant, "name", "Orphan", "roleIds", []any{writers}, "dueAt", f.now()+certDay, "autoClose", true, "undecided", "revoke")))
	f.change("identities", adamID, "status", "deleted")

	expectJSON(t, "nothing due", must(f.iam.CloseOverdueCertifications(ctx, nil)), `{"closed":[],"skipped":3}`)
	f.advance(2 * certDay)
	result, err := f.iam.CloseOverdueCertifications(ctx, nil)
	skipUnported(t, err)
	if err != nil {
		t.Fatal(err)
	}
	if result.Get("skipped") != 1.0 {
		t.Errorf("skipped = %v", result.Get("skipped"))
	}
	closedList, _ := result.Get("closed").([]any)
	closedJSON := map[string]string{}
	for _, entry := range closedList {
		closedJSON[jsString(member(entry, "campaignId"))] = stringify(entry)
	}
	if len(closedList) != 2 ||
		closedJSON[jsString(due.Get("id"))] != `{"tenantId":"`+tenant+`","campaignId":"`+jsString(due.Get("id"))+`","outcomes":{"kept":1,"revoked":2,"already-removed":0,"revocation-failed":0}}` ||
		closedJSON[jsString(orphan.Get("id"))] != `{"tenantId":"`+tenant+`","campaignId":"`+jsString(orphan.Get("id"))+`","outcomes":{"kept":0,"revoked":0,"already-removed":0,"revocation-failed":1}}` {
		t.Fatalf("closed = %s", stringify(closedList))
	}
	// Sessions idle for two days are still valid (a week); sign in again anyway, as an operator would.
	adminToken := f.token(f.admin)
	closedDue := f.obj(call(api.Get, adminToken, core.NewObject("tenantId", tenant, "campaignId", due.Get("id"))))
	if closedDue.Get("status") != "closed" || closedDue.Get("closedBy") != "deployment-operator" || closedDue.Get("closedAt") != f.now() {
		t.Errorf("closed due = %s", stringify(closedDue))
	}
	orphanItems := f.list(f.obj(call(api.Get, adminToken, core.NewObject("tenantId", tenant, "campaignId", orphan.Get("id")))).Get("items"), nil)
	if len(orphanItems) != 1 || orphanItems[0].Get("outcome") != "revocation-failed" || !strings.Contains(jsString(orphanItems[0].Get("outcomeDetail")), "creator") {
		t.Errorf("orphan items = %s", stringify(certRecordList(orphanItems)))
	}
	if status := f.obj(call(api.Get, adminToken, core.NewObject("tenantId", tenant, "campaignId", manual.Get("id")))).Get("status"); status != "open" {
		t.Errorf("manual status = %v", status)
	}
	var remaining []string
	for _, binding := range f.find("bindings", core.NewObject("tenantId", tenant)) {
		remaining = append(remaining, jsString(binding.Get("id")))
	}
	if containsString(remaining, finnBinding) || containsString(remaining, gailBinding) {
		t.Errorf("remaining = %v", remaining)
	}
	if erins := f.find("bindings", core.NewObject("tenantId", tenant, "subjectId", erinID)); len(erins) != 2 {
		t.Errorf("erin's bindings = %d", len(erins))
	}
	autoClosed := f.find("audit", core.NewObject("tenantId", tenant, "action", "certification:auto-close"))
	if len(autoClosed) != 2 {
		t.Fatalf("auto-close audits = %d", len(autoClosed))
	}
	for _, event := range autoClosed {
		if event.Get("resourceId") == due.Get("id") && (event.Get("actorId") != "deployment-operator" || event.Get("outcome") != "allow" ||
			stringify(event.Get("metadata")) != `{"kept":1,"revoked":2,"already-removed":0,"revocation-failed":0}`) {
			t.Errorf("auto-close audit = %s", stringify(event))
		}
	}
	var revoked []string
	for _, event := range f.find("audit", core.NewObject("tenantId", tenant, "action", "iam:bindings:delete")) {
		if event.Get("actorId") == "deployment-operator" {
			revoked = append(revoked, jsString(event.Get("resourceId")))
			if member(event.Get("metadata"), "campaignId") != due.Get("id") {
				t.Errorf("revocation audit = %s", stringify(event))
			}
		}
	}
	sort.Strings(revoked)
	if strings.Join(revoked, ",") != finnBinding+","+gailBinding {
		t.Errorf("revocations = %v", revoked)
	}

	// A second run finds nothing new; a tenant filter limits the sweep.
	expectJSON(t, "second run", must(f.iam.CloseOverdueCertifications(ctx, nil)), `{"closed":[],"skipped":1}`)
	f.seed("tenants", core.NewObject("id", "other", "tenantId", "other", "name", "Other", "type", "organization", "parentId", tenant, "status", "active", "createdAt", 1.0))
	expectJSON(t, "other tenant", must(f.iam.CloseOverdueCertifications(ctx, core.NewObject("tenantId", "other"))), `{"closed":[],"skipped":0}`)
	f.advance(10 * certDay)
	expectJSON(t, "later", must(f.iam.CloseOverdueCertifications(ctx, core.NewObject("tenantId", tenant))),
		`{"closed":[{"tenantId":"`+tenant+`","campaignId":"`+jsString(later.Get("id"))+`","outcomes":{"kept":3,"revoked":0,"already-removed":0,"revocation-failed":0}}],"skipped":0}`)
}

// The worker without revocations: kept and undecided-keep items, a creator who lost the permission, a missing
// tenant filter, and campaigns closed since the scan.
func TestCertificationWorkerWithoutRevocations(t *testing.T) {
	f := newGovFixture(t, nil)
	api := f.iam.API.Certifications
	tenant := f.tenantID
	ctx := context.Background()
	readers := f.role("role-readers", "Readers", false, "documents:read")
	certifiers := f.role("role-certifiers", "Certifiers", false, "iam:certifications:manage")
	erinID := jsString(f.person("erin").Get("id"))
	adam := f.person("adam")
	adamID := jsString(adam.Get("id"))
	f.bind("b1", readers, "identity", erinID, adminAuthority)
	f.bind("b2", certifiers, "identity", adamID, adminAuthority)
	keep := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Keep", "roleIds", []any{readers}, "dueAt", f.now()+certDay, "autoClose", true)))
	revoke := f.obj(call(api.Create, f.token(adam), core.NewObject("tenantId", tenant, "name", "Revoke", "roleIds", []any{readers}, "dueAt", f.now()+certDay, "autoClose", true, "undecided", "revoke")))
	// Adam loses the certification permission: his campaign closes without revoking anything.
	if err := f.iam.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error { return tx.Delete(ctx, "bindings", "b2") }); err != nil {
		t.Fatal(err)
	}
	_, err := f.iam.CloseOverdueCertifications(ctx, core.NewObject("tenantId", 5.0))
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
	_, err = f.iam.CloseOverdueCertifications(ctx, core.NewObject("tenantId", "missing"))
	expectCodeStatus(t, err, "NOT_FOUND", 404)
	f.advance(2 * certDay)
	result := must(f.iam.CloseOverdueCertifications(ctx, core.NewObject("tenantId", tenant)))
	closedList, _ := result.Get("closed").([]any)
	outcomes := map[string]string{}
	for _, entry := range closedList {
		outcomes[jsString(member(entry, "campaignId"))] = stringify(member(entry, "outcomes"))
	}
	if result.Get("skipped") != 0.0 || len(closedList) != 2 ||
		outcomes[jsString(keep.Get("id"))] != `{"kept":1,"revoked":0,"already-removed":0,"revocation-failed":0}` ||
		outcomes[jsString(revoke.Get("id"))] != `{"kept":0,"revoked":0,"already-removed":0,"revocation-failed":1}` {
		t.Errorf("result = %s", stringify(result))
	}
	if bindings := f.find("bindings", core.NewObject("tenantId", tenant, "subjectId", erinID)); len(bindings) != 1 {
		t.Errorf("erin's bindings = %d", len(bindings))
	}
	stored, _ := f.iam.Store.Get(ctx, "certificationCampaigns", jsString(keep.Get("id")))
	if stored.Get("closedBy") != "deployment-operator" || stored.Get("status") != "closed" {
		t.Errorf("stored = %s", stringify(stored))
	}
	// ApplyCampaign needs a principal or an operator.
	_, err = core.Transact(ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return ApplyCampaign(ctx, f.iam.Context, tx, stored, nil, nil)
	})
	expectError(t, err, "INVALID_INPUT", "Closing a campaign needs a principal or an operator")
	// A deleted binding reads as already removed when revoked, kept otherwise.
	open := f.obj(call(api.Create, f.adminToken, core.NewObject("tenantId", tenant, "name", "Gone", "undecided", "revoke")))
	if err := f.iam.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error { return tx.Delete(ctx, "bindings", "b1") }); err != nil {
		t.Fatal(err)
	}
	gone := f.obj(call(api.Close, f.token(f.admin), core.NewObject("tenantId", tenant, "campaignId", open.Get("id"))))
	expectJSON(t, "gone outcomes", gone.Get("outcomes"), `{"kept":0,"revoked":0,"already-removed":1,"revocation-failed":0}`)
}
