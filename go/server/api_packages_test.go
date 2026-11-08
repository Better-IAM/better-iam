package server

// Packages API tests, after tests/access-packages.test.ts, tests/package-requests.test.ts,
// tests/package-review-integrity.test.ts, tests/package-review-requests.test.ts and the extend/hand-over part of
// tests/security-packages.test.ts: bundling, assigning, revoking, expiry, the request and approval flow, shared group
// memberships, hand memberships, request lapse times, and update-cancelled requests. Members are created through the
// auth service (identities.create waits on package automation); steps that reach another unit's NOT_IMPLEMENTED stub
// (configuration sync, offboarding, package rules) skip the rest of the test.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const pkgHour = 3_600_000.0

// pkgFixture is Acme with a Reader role, a Writer role, and an Engineering group that carries Writer (granted by the
// owner; package-requests.test.ts leaves the group without bindings: newPkgFixtureWith(t, false)).
type pkgFixture struct {
	*guestFixture
	reader, writer, engineering *core.Object
}

func newPkgFixture(t *testing.T) *pkgFixture {
	t.Helper()
	return newPkgFixtureWith(t, true)
}

func newPkgFixtureWith(t *testing.T, groupBinding bool) *pkgFixture {
	t.Helper()
	g := newGuestFixture(t, nil)
	f := &pkgFixture{guestFixture: g}
	f.reader = g.createRole(g.owner, "name", "Reader", "permissions", []any{"documents:read"})
	f.writer = g.createRole(g.owner, "name", "Writer", "permissions", []any{"documents:write"})
	f.engineering = g.createGroup("Engineering")
	if groupBinding {
		g.bind(g.owner, f.writer.Get("id"), "group", f.engineering.Get("id"))
	}
	return f
}

func (f *pkgFixture) ok(route string, credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	return f.deptObject("packages/"+route, credential, members...)
}

func (f *pkgFixture) list(route string, credential core.CredentialInput, members ...any) []*core.Object {
	f.t.Helper()
	return f.deptList("packages/"+route, credential, members...)
}

func (f *pkgFixture) fails(code, route string, credential core.CredentialInput, members ...any) *core.IamError {
	f.t.Helper()
	_, err := f.deptCall("packages/"+route, credential, members...)
	expectCodeOrSkip(f.t, err, code)
	return iamError(f.t, err)
}

func (f *pkgFixture) docs(credential core.CredentialInput, action string) bool {
	f.t.Helper()
	return f.can(credential, action, "documents", "a")
}

func (f *pkgFixture) membership(groupID, identityID any) *core.Object {
	f.t.Helper()
	found := f.find("groupMembers", core.NewObject("tenantId", f.tenantID, "groupId", groupID, "identityId", identityID))
	if len(found) == 0 {
		return nil
	}
	return found[0]
}

func (f *pkgFixture) inGroup(groupID any, name string) bool {
	f.t.Helper()
	for _, item := range f.listMembers(groupID) {
		if item.Get("name") == name {
			return true
		}
	}
	return false
}

func (f *pkgFixture) purge() *core.Object {
	f.t.Helper()
	result, err := f.iam.PurgeDeleted(f.ctx, nil)
	requirePorted(f.t, err)
	return result
}

func (f *pkgFixture) storedStatus(requestID any) any {
	f.t.Helper()
	return member(f.record("packageRequests", jsString(requestID)), "status")
}

func pkgIDs(items []*core.Object) []string {
	ids := make([]string, 0, len(items))
	for _, item := range items {
		ids = append(ids, jsString(item.Get("id")))
	}
	return ids
}

func sortedPackageStrings(items ...string) []string {
	out := append([]string(nil), items...)
	sort.Strings(out)
	return out
}

func expectEqualJSON(t *testing.T, label string, got any, want any) {
	t.Helper()
	if a, b := core.MustStringify(got), core.MustStringify(want); a != b {
		t.Fatalf("%s: got %s, want %s", label, a, b)
	}
}

func TestPackagesBundleRolesAndGroupsGrantThemTogetherAndRevokeOnlyWhatTheyAdded(t *testing.T) {
	f := newPkgFixture(t)
	owner := f.owner
	readerID, engineeringID := f.reader.Get("id"), f.engineering.Get("id")
	f.fails("INVALID_INPUT", "create", owner, "name", "Empty")
	f.fails("NOT_FOUND", "create", owner, "name", "Ghost", "roleIds", []any{"missing"})
	var ownerRole *core.Object
	for _, role := range f.listRoles(owner) {
		if truthy(role.Get("protected")) {
			ownerRole = role
		}
	}
	f.fails("PROTECTED_RESOURCE", "create", owner, "name", "Owners", "roleIds", []any{ownerRole.Get("id")})
	kit := f.ok("create", owner, "name", "Engineer kit", "description", "Document access and the Engineering group",
		"roleIds", []any{readerID}, "groupIds", []any{engineeringID})
	if kit.Get("name") != "Engineer kit" || jsNumber(kit.Get("assignments")) != 0 || kit.Has("uniqueKey") {
		t.Fatalf("create answered %s", core.MustStringify(kit))
	}
	expectEqualJSON(t, "roleIds", kit.Get("roleIds"), []any{readerID})
	expectEqualJSON(t, "groupIds", kit.Get("groupIds"), []any{engineeringID})
	f.fails("CONFLICT", "create", owner, "name", "engineer KIT", "roleIds", []any{readerID})
	alice := f.person("alice")
	asAlice := f.login("alice")
	if f.docs(asAlice, "documents:read") {
		t.Fatal("alice reads before the assignment")
	}
	assigned := f.ok("assign", owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"),
		"expiresAt", f.now()+5*dayMs, "justification", "Joined the platform team")
	if assigned.Get("packageName") != "Engineer kit" || assigned.Get("identityName") != "alice" ||
		assigned.Get("identityEmail") != "alice@acme.test" || assigned.Get("expired") != false {
		t.Fatalf("assign answered %s", core.MustStringify(assigned))
	}
	expectEqualJSON(t, "created", assigned.Get("created"), core.NewObject("bindings", 1, "memberships", 1))
	expectEqualJSON(t, "skipped", assigned.Get("skipped"), []any{})
	if !f.docs(asAlice, "documents:read") || !f.docs(asAlice, "documents:write") {
		t.Fatal("the package does not grant")
	}
	// The grants are ordinary records tagged with the assignment and ending with it.
	bindings := f.find("bindings", core.NewObject("tenantId", f.tenantID, "packageAssignmentId", assigned.Get("id")))
	if len(bindings) != 1 || bindings[0].Get("roleId") != readerID || jsNumber(bindings[0].Get("expiresAt")) != f.now()+5*dayMs {
		t.Fatalf("bindings %s", core.MustStringify(objectList(bindings)))
	}
	members := f.find("groupMembers", core.NewObject("tenantId", f.tenantID, "packageAssignmentId", assigned.Get("id")))
	if len(members) != 1 || members[0].Get("groupId") != engineeringID || jsNumber(members[0].Get("expiresAt")) != f.now()+5*dayMs {
		t.Fatalf("memberships %s", core.MustStringify(objectList(members)))
	}
	f.fails("CONFLICT", "assign", owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"))
	if listed := f.list("list", owner); jsNumber(listed[0].Get("assignments")) != 1 {
		t.Fatalf("list %s", core.MustStringify(objectList(listed)))
	}
	held := f.list("listAssignments", owner, "identityId", alice.Get("id"))
	if len(held) != 1 || held[0].Get("packageId") != kit.Get("id") {
		t.Fatalf("listAssignments %s", core.MustStringify(objectList(held)))
	}
	// Bob already holds Reader directly: the package adds a binding of its own beside it and never touches it.
	bob := f.person("bob")
	asBob := f.login("bob")
	direct := f.bind(owner, readerID, "identity", bob.Get("id"))
	partial := f.ok("assign", owner, "packageId", kit.Get("id"), "identityId", bob.Get("id"))
	expectEqualJSON(t, "partial created", partial.Get("created"), core.NewObject("bindings", 1, "memberships", 1))
	expectEqualJSON(t, "partial skipped", partial.Get("skipped"), []any{})
	if containsString(flowStrings(partial.Get("bindingIds")), jsString(direct.Get("id"))) {
		t.Fatal("the package took the direct binding")
	}
	if !f.docs(asBob, "documents:write") {
		t.Fatal("bob cannot write")
	}
	f.ok("revoke", owner, "packageId", kit.Get("id"), "identityId", bob.Get("id"))
	if !f.docs(asBob, "documents:read") || f.docs(asBob, "documents:write") {
		t.Fatal("revoking touched the direct binding or left the group")
	}
	// Nothing is deleted from under a package; revoking clears the way.
	f.fails("RESOURCE_IN_USE", "delete", owner, "packageId", kit.Get("id"))
	revoked := f.ok("revoke", owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"))
	expectEqualJSON(t, "revoked", revoked, core.NewObject("revoked", true, "bindings", 1, "memberships", 1))
	if f.docs(asAlice, "documents:read") || f.docs(asAlice, "documents:write") {
		t.Fatal("revoking left grants")
	}
	f.fails("NOT_FOUND", "revoke", owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"))
	trail := f.auditTrail(f.tenantID, "package:assign")
	if len(trail) != 2 {
		t.Fatalf("package:assign events %d", len(trail))
	}
	var bobEvent *core.Object
	for _, event := range trail {
		if member(event.Get("metadata"), "identityId") == bob.Get("id") {
			bobEvent = event
		}
	}
	metadata := bobEvent.Get("metadata").(*core.Object)
	if metadata.Get("packageName") != "Engineer kit" || jsNumber(metadata.Get("bindings")) != 1 || jsNumber(metadata.Get("memberships")) != 1 {
		t.Fatalf("assign metadata %s", core.MustStringify(metadata))
	}
	expectEqualJSON(t, "metadata skipped", metadata.Get("skipped"), []any{})
	if events := f.auditTrail(f.tenantID, "package:revoke"); len(events) != 2 {
		t.Fatalf("package:revoke events %d", len(events))
	}
	expectEqualJSON(t, "delete", f.ok("delete", owner, "packageId", kit.Get("id")), core.NewObject("deleted", true))
	if listed := f.list("list", owner); len(listed) != 0 {
		t.Fatalf("list after delete %s", core.MustStringify(objectList(listed)))
	}
}

func TestPackagesEnforceTheirRulesEndWithTheirExpiryAndFollowPermissions(t *testing.T) {
	f := newPkgFixture(t)
	owner := f.owner
	vendor := f.ok("create", owner, "name", "Vendor", "roleIds", []any{f.reader.Get("id")}, "groupIds", []any{f.engineering.Get("id")},
		"maxDurationMs", 2*dayMs, "requireJustification", true)
	alice := f.person("alice")
	asAlice := f.login("alice")
	assign := func(members ...any) []any {
		return append([]any{"packageId", vendor.Get("id"), "identityId", alice.Get("id")}, members...)
	}
	// An end date within the cap and a justification are mandatory here.
	if err := f.fails("INVALID_INPUT", "assign", owner, assign("justification", "Audit")...); err.Message != "This package requires an end date (expiresAt)" {
		t.Fatalf("message %q", err.Message)
	}
	if err := f.fails("INVALID_INPUT", "assign", owner, assign("justification", "Audit", "expiresAt", f.now()+3*dayMs)...); err.Message != "expiresAt exceeds the maximum duration of this package" {
		t.Fatalf("message %q", err.Message)
	}
	if err := f.fails("INVALID_INPUT", "assign", owner, assign("expiresAt", f.now()+dayMs)...); err.Message != "This package requires a justification" {
		t.Fatalf("message %q", err.Message)
	}
	f.ok("assign", owner, assign("expiresAt", f.now()+dayMs, "justification", "Quarterly audit")...)
	if !f.docs(asAlice, "documents:read") {
		t.Fatal("not granted")
	}
	f.clock.Add(int64(dayMs) + 1)
	if f.docs(asAlice, "documents:read") || f.docs(asAlice, "documents:write") {
		t.Fatal("still granted after the end")
	}
	if listed := f.list("listAssignments", owner, "packageId", vendor.Get("id")); len(listed) != 0 {
		t.Fatalf("live assignments %d", len(listed))
	}
	ended := f.list("listAssignments", owner, "packageId", vendor.Get("id"), "includeExpired", true)
	if len(ended) != 1 || ended[0].Get("expired") != true {
		t.Fatalf("ended %s", core.MustStringify(objectList(ended)))
	}
	purged := f.purge()
	if jsNumber(purged.Get("expiredBindings")) != 1 || jsNumber(purged.Get("expiredMemberships")) != 1 || jsNumber(purged.Get("expiredAssignments")) != 1 {
		t.Fatalf("purge %s", core.MustStringify(purged))
	}
	// Reassigning after the end starts afresh.
	again := f.ok("assign", owner, assign("expiresAt", f.now()+dayMs, "justification", "Follow-up audit")...)
	expectEqualJSON(t, "again created", again.Get("created"), core.NewObject("bindings", 1, "memberships", 1))
	// Assigning needs the package permission and the right to grant every part of it.
	carol := f.person("carol")
	assigner := f.createRole(owner, "name", "Assigner", "permissions", []any{"iam:packages:read", "iam:packages:assign"})
	f.bind(owner, assigner.Get("id"), "identity", carol.Get("id"))
	asCarol := f.login("carol")
	dave := f.person("dave")
	denied := f.fails("ACCESS_DENIED", "assign", asCarol, "packageId", vendor.Get("id"), "identityId", dave.Get("id"),
		"expiresAt", f.now()+dayMs, "justification", "Onboarding")
	if denied.Message != "Not allowed to grant a packaged role (iam:bindings:create)" {
		t.Fatalf("message %q", denied.Message)
	}
	f.fails("ACCESS_DENIED", "create", asCarol, "name", "Nope", "roleIds", []any{f.reader.Get("id")})
	if names := f.list("list", asCarol); len(names) != 1 || names[0].Get("name") != "Vendor" {
		t.Fatalf("carol lists %s", core.MustStringify(objectList(names)))
	}
	asDave := f.login("dave")
	f.fails("ACCESS_DENIED", "list", asDave)
	// Editing a package changes future assignments only.
	updated := f.ok("update", owner, "packageId", vendor.Get("id"), "groupIds", []any{}, "maxDurationMs", nil, "requireJustification", false)
	expectEqualJSON(t, "updated roleIds", updated.Get("roleIds"), []any{f.reader.Get("id")})
	expectEqualJSON(t, "updated groupIds", updated.Get("groupIds"), []any{})
	if updated.Has("maxDurationMs") || updated.Has("requireJustification") || jsNumber(updated.Get("assignments")) != 1 {
		t.Fatalf("update answered %s", core.MustStringify(updated))
	}
	plain := f.ok("assign", owner, "packageId", vendor.Get("id"), "identityId", dave.Get("id"))
	expectEqualJSON(t, "plain created", plain.Get("created"), core.NewObject("bindings", 1, "memberships", 0))
	if plain.Has("expiresAt") {
		t.Fatal("plain assignment has an end")
	}
	// Offboarding removes the assignment with everything else.
	_, err := f.deptCall("identities/offboard", f.ownerSignIn(), "identityId", alice.Get("id"), "reason", "Contract ended")
	requirePorted(t, err)
	if listed := f.list("listAssignments", owner, "identityId", alice.Get("id"), "includeExpired", true); len(listed) != 0 {
		t.Fatalf("offboarded holder keeps %d assignments", len(listed))
	}
}

func TestPackagesTravelWithTheConfigurationDocument(t *testing.T) {
	f := newPkgFixture(t)
	f.ok("create", f.owner, "name", "Engineer kit", "roleIds", []any{f.reader.Get("id")}, "groupIds", []any{f.engineering.Get("id")},
		"maxDurationMs", 30*dayMs, "requireJustification", true)
	exported, err := f.deptCall("config/export", f.owner)
	requirePorted(t, err)
	expectEqualJSON(t, "exported packages", member(exported, "packages"), parse(t,
		`[{"name":"Engineer kit","roles":["Reader"],"groups":["Engineering"],"maxDurationMs":2592000000,"requireJustification":true}]`))
}

func TestPackageRequestsRouteToApproversAndAssignOnApproval(t *testing.T) {
	f := newPkgFixtureWith(t, false)
	owner := f.owner
	approvers := f.createGroup("Approvers")
	everyone := f.createGroup("Everyone")
	memberRole := f.createRole(owner, "name", "Member", "permissions", []any{"iam:packages:request"})
	f.bind(owner, memberRole.Get("id"), "group", everyone.Get("id"))
	// Approvers decide and, because approval assigns under their authority, may grant every part.
	approverRole := f.createRole(owner, "name", "Package approver", "permissions", []any{"iam:packages:approve", "iam:bindings:create", "iam:groups:update"})
	alice, bob := f.person("alice"), f.person("bob")
	f.person("carol")
	for _, person := range []*core.Object{alice, bob} {
		if _, err := f.addMember("groupId", everyone.Get("id"), "identityId", person.Get("id")); err != nil {
			requirePorted(t, err)
		}
	}
	if _, err := f.addMember("groupId", approvers.Get("id"), "identityId", bob.Get("id")); err != nil {
		requirePorted(t, err)
	}
	f.bind(owner, approverRole.Get("id"), "identity", bob.Get("id"))
	f.deptObject("authorities/create", owner, "identityId", bob.Get("id"), "ceiling",
		parse(t, `{"version":1,"statements":[{"effect":"allow","actions":["documents:*"],"resources":["*"]}]}`))
	kit := f.ok("create", owner, "name", "Engineer kit", "roleIds", []any{f.reader.Get("id")}, "groupIds", []any{f.engineering.Get("id")},
		"approverGroupId", approvers.Get("id"), "requireJustification", true, "maxDurationMs", 30*dayMs)
	asAlice, asBob, asCarol := f.login("alice"), f.login("bob"), f.login("carol")
	request := func(credential core.CredentialInput, members ...any) []any {
		return append([]any{"packageId", kit.Get("id")}, members...)
	}
	// Only requestable packages, only by members holding iam:packages:request, within the package's rules.
	f.fails("INVALID_TRANSITION", "request", asAlice, request(asAlice, "justification", "x", "expiresAt", f.now()+dayMs)...)
	f.ok("update", owner, "packageId", kit.Get("id"), "requestable", true)
	f.fails("ACCESS_DENIED", "request", asCarol, request(asCarol, "justification", "x", "expiresAt", f.now()+dayMs)...)
	f.fails("INVALID_INPUT", "request", asAlice, request(asAlice, "expiresAt", f.now()+dayMs)...)
	f.fails("INVALID_INPUT", "request", asAlice, request(asAlice, "justification", "x", "expiresAt", f.now()+60*dayMs)...)
	first := f.ok("request", asAlice, request(asAlice, "justification", "Joining the platform team", "expiresAt", f.now()+10*dayMs)...)
	if first.Get("status") != "pending" || first.Get("packageName") != "Engineer kit" || first.Get("identityName") != "alice" ||
		jsNumber(first.Get("desiredExpiresAt")) != f.now()+10*dayMs || jsNumber(first.Get("expiresAt")) != f.now()+dayMs {
		t.Fatalf("request answered %s", core.MustStringify(first))
	}
	f.fails("CONFLICT", "request", asAlice, request(asAlice, "justification", "again", "expiresAt", f.now()+dayMs)...)
	f.dispatch()
	sent := f.messages(f.tenantID, "package-request")
	if len(sent) != 1 || sent[0].To != "bob@acme.test" || sent[0].Payload["requesterName"] != "alice" || sent[0].Payload["packageName"] != "Engineer kit" {
		t.Fatalf("package-request messages %+v", sent)
	}
	mine := f.deptObject("packages/listMine", asAlice)
	packages := mine.Get("packages").([]any)
	if len(packages) != 1 {
		t.Fatalf("listMine packages %d", len(packages))
	}
	view := packages[0].(*core.Object)
	if view.Get("name") != "Engineer kit" || view.Get("approverGroupName") != "Approvers" || member(view.Get("pending"), "id") != first.Get("id") ||
		!isUndefined(view.Get("assignment")) || view.Has("roleIds") || view.Has("autoAssign") {
		t.Fatalf("listMine view %s", core.MustStringify(view))
	}
	expectEqualJSON(t, "listMine roles", view.Get("roles"), parse(t, `[{"id":"`+jsString(f.reader.Get("id"))+`","name":"Reader"}]`))
	expectEqualJSON(t, "listMine groups", view.Get("groups"), parse(t, `[{"id":"`+jsString(f.engineering.Get("id"))+`","name":"Engineering"}]`))
	// Deciding takes iam:packages:approve and membership of the approver group; nobody decides on their own.
	f.fails("ACCESS_DENIED", "approveRequest", asAlice, "requestId", first.Get("id"))
	if err := f.fails("ACCESS_DENIED", "approveRequest", owner, "requestId", first.Get("id")); err.Message != "Only the designated approvers may decide" {
		t.Fatalf("message %q", err.Message)
	}
	expectEqualJSON(t, "approvals", pkgIDs(f.list("listApprovals", asBob)), []string{jsString(first.Get("id"))})
	approved := f.ok("approveRequest", asBob, "requestId", first.Get("id"), "note", "Welcome")
	if approved.Get("status") != "approved" || approved.Get("decidedBy") != bob.Get("id") || approved.Get("note") != "Welcome" {
		t.Fatalf("approved %s", core.MustStringify(approved))
	}
	if !f.docs(asAlice, "documents:read") {
		t.Fatal("approval did not grant")
	}
	assignment := f.list("listAssignments", owner, "packageId", kit.Get("id"))[0]
	if assignment.Get("id") != approved.Get("assignmentId") || assignment.Get("identityId") != alice.Get("id") || assignment.Get("assignedBy") != bob.Get("id") ||
		jsNumber(assignment.Get("expiresAt")) != f.now()+10*dayMs || assignment.Get("justification") != "Joining the platform team" {
		t.Fatalf("assignment %s", core.MustStringify(assignment))
	}
	f.dispatch()
	decided := f.messages(f.tenantID, "package-decided")
	if len(decided) != 1 || decided[0].To != "alice@acme.test" || decided[0].Payload["decision"] != "approved" || decided[0].Payload["note"] != "Welcome" {
		t.Fatalf("package-decided messages %+v", decided)
	}
	if approvals := f.list("listApprovals", asBob); len(approvals) != 0 {
		t.Fatalf("approvals left %d", len(approvals))
	}
	mine = f.deptObject("packages/listMine", asAlice)
	if member(member(mine.Get("packages").([]any)[0], "assignment"), "id") != approved.Get("assignmentId") {
		t.Fatalf("listMine after approval %s", core.MustStringify(mine))
	}
	f.fails("CONFLICT", "request", asAlice, request(asAlice, "justification", "more", "expiresAt", f.now()+dayMs)...)
	f.fails("INVALID_TRANSITION", "approveRequest", asBob, "requestId", first.Get("id"))
	// Bob is the only approver, and nobody decides on their own request: his request could reach no one.
	f.fails("INVALID_TRANSITION", "request", asBob, request(asBob, "justification", "Me too", "expiresAt", f.now()+dayMs)...)
	// Cancelling, denying, and lapsing.
	dave := f.person("dave")
	if _, err := f.addMember("groupId", everyone.Get("id"), "identityId", dave.Get("id")); err != nil {
		requirePorted(t, err)
	}
	asDave := f.login("dave")
	second := f.ok("request", asDave, request(asDave, "justification", "Me too", "expiresAt", f.now()+dayMs)...)
	f.fails("ACCESS_DENIED", "cancelRequest", asAlice, "requestId", second.Get("id"))
	if cancelled := f.ok("cancelRequest", asDave, "requestId", second.Get("id")); cancelled.Get("status") != "cancelled" {
		t.Fatalf("cancel answered %s", core.MustStringify(cancelled))
	}
	third := f.ok("request", asDave, request(asDave, "justification", "Curious", "expiresAt", f.now()+dayMs)...)
	denied := f.ok("denyRequest", asBob, "requestId", third.Get("id"), "note", "Not yet")
	if denied.Get("status") != "denied" || denied.Get("decidedBy") != bob.Get("id") || denied.Get("note") != "Not yet" {
		t.Fatalf("denied %s", core.MustStringify(denied))
	}
	f.dispatch()
	decided = f.messages(f.tenantID, "package-decided")
	last := decided[len(decided)-1]
	if last.To != "dave@acme.test" || last.Payload["decision"] != "denied" || last.Payload["note"] != "Not yet" {
		t.Fatalf("last decision message %+v", last)
	}
	erin := f.person("erin")
	if _, err := f.addMember("groupId", everyone.Get("id"), "identityId", erin.Get("id")); err != nil {
		requirePorted(t, err)
	}
	asErin := f.login("erin")
	fourth := f.ok("request", asErin, request(asErin, "justification", "Later", "expiresAt", f.now()+5*dayMs)...)
	f.clock.Add(int64(dayMs) + 1)
	if purged := f.purge(); jsNumber(purged.Get("expiredRequests")) != 1 {
		t.Fatalf("purge %s", core.MustStringify(purged))
	}
	f.fails("INVALID_TRANSITION", "approveRequest", asBob, "requestId", fourth.Get("id"))
	expectEqualJSON(t, "expired requests", pkgIDs(f.list("listRequests", owner, "status", "expired")), []string{jsString(fourth.Get("id"))})
	var statuses []string
	for _, item := range f.list("listRequests", owner, "packageId", kit.Get("id")) {
		statuses = append(statuses, jsString(item.Get("status")))
	}
	expectEqualJSON(t, "statuses", sortedPackageStrings(statuses...), []string{"approved", "cancelled", "denied", "expired"})
	if events := f.auditTrail(f.tenantID, "package:request-approved"); len(events) != 1 {
		t.Fatalf("package:request-approved events %d", len(events))
	}
	// The owner revokes what the approver granted (the assignment owns its records), then deletes the package.
	expectEqualJSON(t, "revoke", f.ok("revoke", owner, "packageId", kit.Get("id"), "identityId", alice.Get("id")),
		core.NewObject("revoked", true, "bindings", 1, "memberships", 1))
	if f.docs(asAlice, "documents:read") {
		t.Fatal("revoked grant still reads")
	}
	f.ok("delete", owner, "packageId", kit.Get("id"))
	if listed := f.list("listRequests", owner); len(listed) != 0 {
		t.Fatalf("requests after delete %d", len(listed))
	}
	f.fails("INVALID_INPUT", "listRequests", owner, "status", "lost")
}

func TestPackageBindingsAreIndependentOfDirectOnes(t *testing.T) {
	f := newPkgFixture(t)
	owner := f.owner
	project := f.ok("create", owner, "name", "Project", "roleIds", []any{f.reader.Get("id")})
	base := f.ok("create", owner, "name", "Base", "roleIds", []any{f.reader.Get("id")})
	alice := f.person("alice")
	asAlice := f.login("alice")
	temporary := f.ok("assign", owner, "packageId", project.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
	permanent := f.ok("assign", owner, "packageId", base.Get("id"), "identityId", alice.Get("id"))
	expectEqualJSON(t, "created", permanent.Get("created"), core.NewObject("bindings", 1, "memberships", 0))
	permanentBinding := flowStrings(permanent.Get("bindingIds"))[0]
	if permanentBinding == flowStrings(temporary.Get("bindingIds"))[0] {
		t.Fatal("the packages share a binding")
	}
	if f.record("bindings", permanentBinding).Has("expiresAt") {
		t.Fatal("the permanent binding has an end")
	}
	// Project ends; Base still grants Reader through its own binding.
	f.clock.Add(int64(2 * dayMs))
	if !f.docs(asAlice, "documents:read") {
		t.Fatal("base no longer grants")
	}
	expectEqualJSON(t, "revoke ended", f.ok("revoke", owner, "packageId", project.Get("id"), "identityId", alice.Get("id")),
		core.NewObject("revoked", true, "bindings", 1, "memberships", 0))
	if f.record("bindings", permanentBinding) == nil || !f.docs(asAlice, "documents:read") {
		t.Fatal("revoking the ended package removed the other's binding")
	}
	// A direct binding beside a package binding survives revoking the package.
	direct := f.bind(owner, f.reader.Get("id"), "identity", alice.Get("id"))
	if direct.Has("packageAssignmentId") {
		t.Fatal("the direct binding is tagged")
	}
	expectEqualJSON(t, "revoke base", f.ok("revoke", owner, "packageId", base.Get("id"), "identityId", alice.Get("id")),
		core.NewObject("revoked", true, "bindings", 1, "memberships", 0))
	if f.record("bindings", jsString(direct.Get("id"))) == nil || !f.docs(asAlice, "documents:read") {
		t.Fatal("revoking removed the direct binding")
	}
}

func TestPackagesThatShareAGroupShareOneMembership(t *testing.T) {
	setup := func(t *testing.T) (*pkgFixture, *core.Object, *core.Object, *core.Object) {
		f := newPkgFixture(t)
		short := f.ok("create", f.owner, "name", "Short", "groupIds", []any{f.engineering.Get("id")})
		long := f.ok("create", f.owner, "name", "Long", "groupIds", []any{f.engineering.Get("id")})
		return f, short, long, f.person("alice")
	}
	t.Run("the longer assignment owns it; revoking it hands the membership to the other", func(t *testing.T) {
		f, short, long, alice := setup(t)
		groupID := f.engineering.Get("id")
		a := f.ok("assign", f.owner, "packageId", short.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
		b := f.ok("assign", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id"))
		expectEqualJSON(t, "skipped", b.Get("skipped"), []any{})
		record := f.membership(groupID, alice.Get("id"))
		if record.Get("packageAssignmentId") != b.Get("id") || record.Has("expiresAt") {
			t.Fatalf("membership %s", core.MustStringify(record))
		}
		f.ok("revoke", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id"))
		handed := f.membership(groupID, alice.Get("id"))
		if handed == nil || handed.Get("id") != record.Get("id") || handed.Get("packageAssignmentId") != a.Get("id") ||
			!core.StrictEquals(handed.Get("expiresAt"), a.Get("expiresAt")) {
			t.Fatalf("handed %s", core.MustStringify(handed))
		}
		if !f.inGroup(groupID, "alice") || !f.docs(f.login("alice"), "documents:write") {
			t.Fatal("alice left the group")
		}
		expectEqualJSON(t, "last revoke", f.ok("revoke", f.owner, "packageId", short.Get("id"), "identityId", alice.Get("id")),
			core.NewObject("revoked", true, "bindings", 0, "memberships", 1))
		if f.membership(groupID, alice.Get("id")) != nil {
			t.Fatal("membership survived")
		}
	})
	t.Run("revoking the shorter assignment first leaves the longer one its membership", func(t *testing.T) {
		f, short, long, alice := setup(t)
		groupID := f.engineering.Get("id")
		f.ok("assign", f.owner, "packageId", short.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
		b := f.ok("assign", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id"))
		expectEqualJSON(t, "revoke short", f.ok("revoke", f.owner, "packageId", short.Get("id"), "identityId", alice.Get("id")),
			core.NewObject("revoked", true, "bindings", 0, "memberships", 0))
		kept := f.membership(groupID, alice.Get("id"))
		if kept.Get("packageAssignmentId") != b.Get("id") || kept.Has("expiresAt") {
			t.Fatalf("kept %s", core.MustStringify(kept))
		}
		f.clock.Add(int64(2 * dayMs))
		if !f.inGroup(groupID, "alice") {
			t.Fatal("alice left the group")
		}
		expectEqualJSON(t, "revoke long", f.ok("revoke", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id")),
			core.NewObject("revoked", true, "bindings", 0, "memberships", 1))
	})
	t.Run("a permanent assignment made first is skipped by the shorter one, which takes over on revoke", func(t *testing.T) {
		f, short, long, alice := setup(t)
		groupID := f.engineering.Get("id")
		b := f.ok("assign", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id"))
		a := f.ok("assign", f.owner, "packageId", short.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
		expectEqualJSON(t, "skipped", a.Get("skipped"), []any{"already a member of group Engineering (through package Long)"})
		if f.membership(groupID, alice.Get("id")).Get("packageAssignmentId") != b.Get("id") {
			t.Fatal("the shorter assignment took the membership")
		}
		f.ok("revoke", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id"))
		handed := f.membership(groupID, alice.Get("id"))
		if handed.Get("packageAssignmentId") != a.Get("id") || !core.StrictEquals(handed.Get("expiresAt"), a.Get("expiresAt")) {
			t.Fatalf("handed %s", core.MustStringify(handed))
		}
		expectEqualJSON(t, "revoke short", f.ok("revoke", f.owner, "packageId", short.Get("id"), "identityId", alice.Get("id")),
			core.NewObject("revoked", true, "bindings", 0, "memberships", 1))
		if f.inGroup(groupID, "alice") {
			t.Fatal("alice is still a member")
		}
	})
	t.Run("shortening an assignment hands the membership to one that needs it longer", func(t *testing.T) {
		f, short, long, alice := setup(t)
		groupID := f.engineering.Get("id")
		permanent := f.ok("assign", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id"))
		threeDays := f.ok("assign", f.owner, "packageId", short.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+3*dayMs)
		if f.membership(groupID, alice.Get("id")).Get("packageAssignmentId") != permanent.Get("id") {
			t.Fatal("the permanent assignment does not own the membership")
		}
		shortened := f.ok("extend", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
		if jsNumber(shortened.Get("expiresAt")) != f.now()+dayMs {
			t.Fatalf("extend answered %s", core.MustStringify(shortened))
		}
		handed := f.membership(groupID, alice.Get("id"))
		if handed.Get("packageAssignmentId") != threeDays.Get("id") || !core.StrictEquals(handed.Get("expiresAt"), threeDays.Get("expiresAt")) {
			t.Fatalf("handed %s", core.MustStringify(handed))
		}
		f.clock.Add(int64(2 * dayMs))
		if !f.inGroup(groupID, "alice") {
			t.Fatal("alice left the group")
		}
		expectEqualJSON(t, "revoke ended", f.ok("revoke", f.owner, "packageId", long.Get("id"), "identityId", alice.Get("id")),
			core.NewObject("revoked", true, "bindings", 0, "memberships", 0))
		expectEqualJSON(t, "revoke short", f.ok("revoke", f.owner, "packageId", short.Get("id"), "identityId", alice.Get("id")),
			core.NewObject("revoked", true, "bindings", 0, "memberships", 1))
		if f.inGroup(groupID, "alice") {
			t.Fatal("alice is still a member")
		}
	})
}

func TestPackagesAndMembershipsHeldByHand(t *testing.T) {
	f := newPkgFixture(t)
	groupID := f.engineering.Get("id")
	kit := f.ok("create", f.owner, "name", "Kit", "groupIds", []any{groupID})
	alice, bob := f.person("alice"), f.person("bob")
	// A permanent hand membership is skipped and survives revoking the package.
	if _, err := f.addMember("groupId", groupID, "identityId", alice.Get("id")); err != nil {
		requirePorted(t, err)
	}
	assigned := f.ok("assign", f.owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
	expectEqualJSON(t, "skipped", assigned.Get("skipped"), []any{"already a member of group Engineering"})
	expectEqualJSON(t, "created", assigned.Get("created"), core.NewObject("bindings", 0, "memberships", 0))
	if f.membership(groupID, alice.Get("id")).Has("packageAssignmentId") {
		t.Fatal("the package took the hand membership")
	}
	expectEqualJSON(t, "revoke", f.ok("revoke", f.owner, "packageId", kit.Get("id"), "identityId", alice.Get("id")),
		core.NewObject("revoked", true, "bindings", 0, "memberships", 0))
	if !f.inGroup(groupID, "alice") || f.membership(groupID, alice.Get("id")).Has("expiresAt") {
		t.Fatal("revoking changed the hand membership")
	}
	// A shorter hand membership is extended to the assignment end and belongs to it.
	if _, err := f.addMember("groupId", groupID, "identityId", bob.Get("id"), "expiresAt", f.now()+dayMs); err != nil {
		requirePorted(t, err)
	}
	before := f.membership(groupID, bob.Get("id"))
	extended := f.ok("assign", f.owner, "packageId", kit.Get("id"), "identityId", bob.Get("id"), "expiresAt", f.now()+3*dayMs)
	expectEqualJSON(t, "extended skipped", extended.Get("skipped"), []any{})
	expectEqualJSON(t, "extended created", extended.Get("created"), core.NewObject("bindings", 0, "memberships", 1))
	after := f.membership(groupID, bob.Get("id"))
	if after.Get("id") != before.Get("id") || jsNumber(after.Get("expiresAt")) != f.now()+3*dayMs || after.Get("packageAssignmentId") != extended.Get("id") {
		t.Fatalf("membership %s", core.MustStringify(after))
	}
	f.clock.Add(int64(2 * dayMs))
	if !f.inGroup(groupID, "bob") {
		t.Fatal("bob left the group")
	}
	expectEqualJSON(t, "revoke bob", f.ok("revoke", f.owner, "packageId", kit.Get("id"), "identityId", bob.Get("id")),
		core.NewObject("revoked", true, "bindings", 0, "memberships", 1))
	if f.inGroup(groupID, "bob") {
		t.Fatal("bob is still a member")
	}
}

// pkgRequesters is the package-review-requests setup: members who may request packages through an Everyone group.
func pkgRequesters(t *testing.T, names ...string) (*pkgFixture, map[string]*core.Object, map[string]core.CredentialInput) {
	t.Helper()
	f := newPkgFixture(t)
	requester := f.createRole(f.owner, "name", "Requester", "permissions", []any{"iam:packages:request"})
	everyone := f.createGroup("Everyone")
	f.bind(f.owner, requester.Get("id"), "group", everyone.Get("id"))
	people := map[string]*core.Object{}
	credentials := map[string]core.CredentialInput{}
	for _, name := range names {
		person := f.person(name)
		if _, err := f.addMember("groupId", everyone.Get("id"), "identityId", person.Get("id")); err != nil {
			requirePorted(t, err)
		}
		people[name] = person
		credentials[name] = f.login(name)
	}
	return f, people, credentials
}

func TestPackageRequestsNeverLapseLaterThanTheEndTheyAskFor(t *testing.T) {
	f, people, as := pkgRequesters(t, "alice", "bob")
	owner := f.owner
	kit := f.ok("create", owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "requestable", true)
	start := f.now()
	long := f.ok("request", as["bob"], "packageId", kit.Get("id"), "expiresAt", start+3*dayMs)
	if long.Get("status") != "pending" || jsNumber(long.Get("desiredExpiresAt")) != start+3*dayMs || jsNumber(long.Get("expiresAt")) != start+dayMs {
		t.Fatalf("long %s", core.MustStringify(long))
	}
	short := f.ok("request", as["alice"], "packageId", kit.Get("id"), "expiresAt", start+4*pkgHour)
	if jsNumber(short.Get("desiredExpiresAt")) != start+4*pkgHour || jsNumber(short.Get("expiresAt")) != start+4*pkgHour {
		t.Fatalf("short %s", core.MustStringify(short))
	}
	f.clock.Add(int64(3 * pkgHour))
	expectEqualJSON(t, "approvals", sortedPackageStrings(pkgIDs(f.list("listApprovals", owner))...),
		sortedPackageStrings(jsString(long.Get("id")), jsString(short.Get("id"))))
	f.clock.Add(int64(2 * pkgHour))
	expectEqualJSON(t, "approvals after lapse", pkgIDs(f.list("listApprovals", owner)), []string{jsString(long.Get("id"))})
	f.fails("INVALID_TRANSITION", "approveRequest", owner, "requestId", short.Get("id"))
	f.fails("INVALID_TRANSITION", "denyRequest", owner, "requestId", short.Get("id"))
	f.fails("INVALID_TRANSITION", "cancelRequest", as["alice"], "requestId", short.Get("id"))
	if f.storedStatus(short.Get("id")) != "pending" {
		t.Fatal("the lapsed request was rewritten")
	}
	listed := f.list("listRequests", owner, "identityId", people["alice"].Get("id"))
	if len(listed) != 1 || listed[0].Get("status") != "expired" {
		t.Fatalf("listRequests %s", core.MustStringify(objectList(listed)))
	}
	mine := f.deptObject("packages/listMine", as["alice"])
	for _, item := range mine.Get("packages").([]any) {
		if member(item, "id") == kit.Get("id") && !isUndefined(member(item, "pending")) {
			t.Fatal("listMine shows the lapsed request pending")
		}
	}
	if f.docs(as["alice"], "documents:read") {
		t.Fatal("the failed approval granted")
	}
	again := f.ok("request", as["alice"], "packageId", kit.Get("id"), "expiresAt", f.now()+4*pkgHour)
	if again.Get("status") != "pending" || again.Get("id") == short.Get("id") {
		t.Fatalf("again %s", core.MustStringify(again))
	}
	if purged := f.purge(); jsNumber(purged.Get("expiredRequests")) != 1 {
		t.Fatalf("purge %s", core.MustStringify(purged))
	}
	if f.storedStatus(short.Get("id")) != "expired" {
		t.Fatal("the worker did not mark the lapsed request")
	}
}

func TestPackagesUpdateCancelsPendingRequestsThatNoLongerFit(t *testing.T) {
	t.Run("requestable false cancels every pending request with a note", func(t *testing.T) {
		f, _, as := pkgRequesters(t, "alice", "bob")
		kit := f.ok("create", f.owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "requestable", true)
		first := f.ok("request", as["alice"], "packageId", kit.Get("id"), "justification", "Needed for the audit", "expiresAt", f.now()+2*dayMs)
		second := f.ok("request", as["bob"], "packageId", kit.Get("id"))
		other := f.ok("create", f.owner, "name", "Other", "roleIds", []any{f.reader.Get("id")}, "requestable", true)
		elsewhere := f.ok("request", as["alice"], "packageId", other.Get("id"))
		// Unchanged rules leave requests alone.
		f.ok("update", f.owner, "packageId", kit.Get("id"), "description", "Same rules", "requestable", true, "requireJustification", false)
		if f.storedStatus(first.Get("id")) != "pending" {
			t.Fatal("an unchanged update cancelled a request")
		}
		f.clock.Add(1000)
		f.ok("update", f.owner, "packageId", kit.Get("id"), "requestable", false)
		listed := f.list("listRequests", f.owner, "packageId", kit.Get("id"))
		if len(listed) != 2 {
			t.Fatalf("listed %d", len(listed))
		}
		for _, item := range listed {
			if item.Get("status") != "cancelled" || jsNumber(item.Get("decidedAt")) != f.now() || item.Get("note") != "The package can no longer be requested" {
				t.Fatalf("cancelled %s", core.MustStringify(item))
			}
		}
		if f.storedStatus(elsewhere.Get("id")) != "pending" || f.storedStatus(second.Get("id")) != "cancelled" {
			t.Fatal("wrong requests cancelled")
		}
		f.fails("INVALID_TRANSITION", "approveRequest", f.owner, "requestId", first.Get("id"))
		f.ok("update", f.owner, "packageId", kit.Get("id"), "requestable", true)
		if f.storedStatus(first.Get("id")) != "cancelled" {
			t.Fatal("making it requestable revived a request")
		}
	})
	t.Run("requireJustification cancels only the requests without one", func(t *testing.T) {
		f, _, as := pkgRequesters(t, "alice", "bob")
		kit := f.ok("create", f.owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "requestable", true)
		justified := f.ok("request", as["alice"], "packageId", kit.Get("id"), "justification", "On-call rotation")
		unjustified := f.ok("request", as["bob"], "packageId", kit.Get("id"))
		f.ok("update", f.owner, "packageId", kit.Get("id"), "requireJustification", true)
		if f.storedStatus(justified.Get("id")) != "pending" {
			t.Fatal("the justified request was cancelled")
		}
		stored := f.record("packageRequests", jsString(unjustified.Get("id")))
		if stored.Get("status") != "cancelled" || stored.Get("note") != "The package now requires a justification" {
			t.Fatalf("unjustified %s", core.MustStringify(stored))
		}
		if approved := f.ok("approveRequest", f.owner, "requestId", justified.Get("id")); approved.Get("status") != "approved" {
			t.Fatalf("approved %s", core.MustStringify(approved))
		}
	})
	t.Run("a new maxDurationMs cancels open-ended requests and those asking to end beyond now plus max", func(t *testing.T) {
		f, _, as := pkgRequesters(t, "alice", "bob", "carol", "dave")
		kit := f.ok("create", f.owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "requestable", true)
		openEnded := f.ok("request", as["alice"], "packageId", kit.Get("id"))
		tooLong := f.ok("request", as["bob"], "packageId", kit.Get("id"), "expiresAt", f.now()+10*dayMs)
		fits := f.ok("request", as["carol"], "packageId", kit.Get("id"), "expiresAt", f.now()+2*dayMs)
		edge := f.ok("request", as["dave"], "packageId", kit.Get("id"), "expiresAt", f.now()+5*dayMs+pkgHour)
		f.clock.Add(int64(pkgHour))
		f.ok("update", f.owner, "packageId", kit.Get("id"), "maxDurationMs", 5*dayMs)
		for _, cancelled := range []*core.Object{openEnded, tooLong} {
			stored := f.record("packageRequests", jsString(cancelled.Get("id")))
			if stored.Get("status") != "cancelled" || stored.Get("note") != "The requested end no longer fits the package" {
				t.Fatalf("cancelled %s", core.MustStringify(stored))
			}
		}
		for _, kept := range []*core.Object{fits, edge} {
			if f.storedStatus(kept.Get("id")) != "pending" {
				t.Fatalf("kept %s", core.MustStringify(kept))
			}
		}
		for _, kept := range []*core.Object{fits, edge} {
			if approved := f.ok("approveRequest", f.owner, "requestId", kept.Get("id")); approved.Get("status") != "approved" {
				t.Fatalf("approved %s", core.MustStringify(approved))
			}
		}
		f.fails("INVALID_TRANSITION", "approveRequest", f.owner, "requestId", tooLong.Get("id"))
	})
	t.Run("does not rewrite a request that already lapsed into a cancellation", func(t *testing.T) {
		f, people, as := pkgRequesters(t, "alice", "bob")
		kit := f.ok("create", f.owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "requestable", true)
		lapsed := f.ok("request", as["alice"], "packageId", kit.Get("id"))
		f.clock.Add(int64(dayMs + pkgHour))
		live := f.ok("request", as["bob"], "packageId", kit.Get("id"))
		f.ok("update", f.owner, "packageId", kit.Get("id"), "requestable", false)
		if f.storedStatus(live.Get("id")) != "cancelled" {
			t.Fatal("the live request was not cancelled")
		}
		reported := f.list("listRequests", f.owner, "identityId", people["alice"].Get("id"))[0]
		if reported.Get("id") != lapsed.Get("id") || reported.Get("status") != "expired" || reported.Has("decidedAt") || reported.Has("note") {
			t.Fatalf("reported %s", core.MustStringify(reported))
		}
	})
}

func TestPackageApprovalOfANoLongerRequestablePackageIsRefusedButDenialWorks(t *testing.T) {
	f, people, as := pkgRequesters(t, "alice")
	kit := f.ok("create", f.owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "requestable", true)
	first := f.ok("request", as["alice"], "packageId", kit.Get("id"))
	stored := f.record("accessPackages", jsString(kit.Get("id")))
	rest := stored.Spread()
	rest.Delete("requestable")
	if _, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return tx.Put(ctx, "accessPackages", rest)
	}); err != nil {
		t.Fatal(err)
	}
	if err := f.fails("INVALID_TRANSITION", "approveRequest", f.owner, "requestId", first.Get("id")); err.Message != "The package is no longer requestable" {
		t.Fatalf("message %q", err.Message)
	}
	if f.storedStatus(first.Get("id")) != "pending" || len(f.list("listAssignments", f.owner, "packageId", kit.Get("id"))) != 0 {
		t.Fatal("the refused approval changed something")
	}
	denied := f.ok("denyRequest", f.owner, "requestId", first.Get("id"), "note", "No longer offered")
	if denied.Get("status") != "denied" || denied.Get("decidedBy") != f.ownerID || denied.Get("note") != "No longer offered" {
		t.Fatalf("denied %s", core.MustStringify(denied))
	}
	_ = people
}

func TestPackageDirectAssignmentFulfilsAPendingRequest(t *testing.T) {
	f, people, as := pkgRequesters(t, "alice")
	kit := f.ok("create", f.owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "requestable", true)
	request := f.ok("request", as["alice"], "packageId", kit.Get("id"))
	expectEqualJSON(t, "approvals", pkgIDs(f.list("listApprovals", f.owner)), []string{jsString(request.Get("id"))})
	assigned := f.ok("assign", f.owner, "packageId", kit.Get("id"), "identityId", people["alice"].Get("id"))
	listed := f.list("listRequests", f.owner, "identityId", people["alice"].Get("id"))
	if len(listed) != 1 || listed[0].Get("status") != "approved" || listed[0].Get("assignmentId") != assigned.Get("id") || listed[0].Get("decidedBy") != f.ownerID {
		t.Fatalf("listed %s", core.MustStringify(objectList(listed)))
	}
	if approvals := f.list("listApprovals", f.owner); len(approvals) != 0 {
		t.Fatalf("approvals left %d", len(approvals))
	}
}

func TestPackagesExtendLengthensOnlyWhatThePackageBundles(t *testing.T) {
	f := newPkgFixture(t)
	owner := f.owner
	kit := f.ok("create", owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "groupIds", []any{f.engineering.Get("id")})
	alice := f.person("alice")
	assigned := f.ok("assign", owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
	// The package loses its group; lengthening then reaches only the binding of the role it still bundles.
	f.ok("update", owner, "packageId", kit.Get("id"), "groupIds", []any{})
	f.fails("INVALID_INPUT", "extend", owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"))
	extended := f.ok("extend", owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"), "expiresAt", nil)
	if extended.Has("expiresAt") {
		t.Fatalf("extend answered %s", core.MustStringify(extended))
	}
	binding := f.record("bindings", flowStrings(assigned.Get("bindingIds"))[0])
	if binding.Has("expiresAt") {
		t.Fatal("the packaged role's binding kept its end")
	}
	groupMember := f.membership(f.engineering.Get("id"), alice.Get("id"))
	if jsNumber(groupMember.Get("expiresAt")) != f.now()+dayMs {
		t.Fatalf("the unbundled group's membership moved: %s", core.MustStringify(groupMember))
	}
	events := f.auditTrail(f.tenantID, "package:extend")
	if len(events) != 1 {
		t.Fatalf("package:extend events %d", len(events))
	}
	metadata := events[0].Get("metadata").(*core.Object)
	if jsNumber(metadata.Get("previousExpiresAt")) != f.now()+dayMs || metadata.Has("expiresAt") {
		t.Fatalf("extend metadata %s", core.MustStringify(metadata))
	}
	// A holder of only iam:packages:assign may shorten but not lengthen.
	carol := f.person("carol")
	assigner := f.createRole(owner, "name", "Assigner", "permissions", []any{"iam:packages:assign"})
	f.bind(owner, assigner.Get("id"), "identity", carol.Get("id"))
	asCarol := f.login("carol")
	shortened := f.ok("extend", asCarol, "packageId", kit.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
	if jsNumber(shortened.Get("expiresAt")) != f.now()+dayMs {
		t.Fatalf("shortened %s", core.MustStringify(shortened))
	}
	if err := f.fails("ACCESS_DENIED", "extend", asCarol, "packageId", kit.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+2*dayMs); !strings.Contains(err.Message, "iam:bindings:create") {
		t.Fatalf("message %q", err.Message)
	}
}

func TestPackageHelpers(t *testing.T) {
	if end, _ := EndOf(nil); end <= 1e308 {
		t.Fatalf("EndOf(nil) = %v", end)
	}
	five := 5.0
	if end, _ := EndOf(&five); end != 5 {
		t.Fatalf("EndOf(5) = %v", end)
	}
	if !packageSameIDs([]string{"a", "b"}, []string{"b", "a"}) || packageSameIDs([]string{"a", "b"}, []string{"a", "c"}) || packageSameIDs([]string{"a"}, []string{"a", "a"}) {
		t.Fatal("packageSameIDs")
	}
	if packageNameKey("  Engineer KIT ") != "name:engineer kit" {
		t.Fatalf("packageNameKey %q", packageNameKey("  Engineer KIT "))
	}
	if _, err := packageBoolean("yes", "requestable"); err == nil || err.Error() == "" || iamError(t, err).Message != "requestable must be boolean" {
		t.Fatalf("packageBoolean %v", err)
	}
}

func TestPackagesRefreshAssignmentFollowsThePackageAndRule(t *testing.T) {
	f := newPkgFixture(t)
	server := f.iam.Context
	kit := f.ok("create", f.owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "groupIds", []any{f.engineering.Get("id")})
	alice := f.person("alice")
	principal, err := f.iam.Authenticate(f.ctx, f.owner)
	if err != nil {
		t.Fatal(err)
	}
	// An automatic assignment under the owner's authority, of a package whose rule moved on to revision 2.
	assignment, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		authority, err := server.GrantingAuthority(ctx, tx, principal, f.tenantID, "")
		if err != nil {
			return nil, err
		}
		pkg, err := tx.Get(ctx, "accessPackages", jsString(kit.Get("id")))
		if err != nil {
			return nil, err
		}
		assigned, err := AssignPackage(ctx, server, tx, principal, pkg, core.NewObject("identityId", alice.Get("id")),
			core.NewObject("authority", authority, "ruleRevision", 1))
		if err != nil {
			return nil, err
		}
		return assigned.Get("assignment").(*core.Object), nil
	})
	requirePorted(t, err)
	if assignment.Get("justification") != AutomaticJustification || jsNumber(assignment.Get("ruleRevision")) != 1 {
		t.Fatalf("automatic assignment %s", core.MustStringify(assignment))
	}
	if summary := f.list("listAssignments", f.owner, "source", "automatic"); len(summary) != 1 || summary[0].Get("automatic") != true || summary[0].Has("ruleRevision") {
		t.Fatalf("automatic listing %s", core.MustStringify(objectList(summary)))
	}
	if manual := f.list("listAssignments", f.owner, "source", "manual"); len(manual) != 0 {
		t.Fatalf("manual listing %d", len(manual))
	}
	f.fails("INVALID_INPUT", "listAssignments", f.owner, "source", "rule")
	f.fails("INVALID_TRANSITION", "extend", f.owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"), "expiresAt", nil)
	refreshed, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		pkg, err := tx.Get(ctx, "accessPackages", jsString(kit.Get("id")))
		if err != nil {
			return nil, err
		}
		pkg = pkg.Spread(core.NewObject("roleIds", []any{f.writer.Get("id")}, "autoAssign", core.NewObject("revision", 2)))
		if _, err := tx.Put(ctx, "accessPackages", pkg); err != nil {
			return nil, err
		}
		authority, err := server.GrantingAuthority(ctx, tx, principal, f.tenantID, "")
		if err != nil {
			return nil, err
		}
		current, err := tx.Get(ctx, "packageAssignments", jsString(assignment.Get("id")))
		if err != nil {
			return nil, err
		}
		return RefreshAssignment(ctx, server, tx, principal, pkg, current, authority)
	})
	requirePorted(t, err)
	if jsNumber(refreshed.Get("removedBindings")) != 1 || jsNumber(refreshed.Get("bindings")) != 1 ||
		jsNumber(refreshed.Get("memberships")) != 0 || jsNumber(refreshed.Get("removedMemberships")) != 0 {
		t.Fatalf("refresh %s", core.MustStringify(refreshed))
	}
	saved := refreshed.Get("assignment").(*core.Object)
	if jsNumber(saved.Get("ruleRevision")) != 2 || len(flowStrings(saved.Get("membershipIds"))) != 1 {
		t.Fatalf("refreshed assignment %s", core.MustStringify(saved))
	}
	binding := f.record("bindings", flowStrings(saved.Get("bindingIds"))[0])
	if binding.Get("roleId") != f.writer.Get("id") || binding.Get("packageAssignmentId") != assignment.Get("id") {
		t.Fatalf("binding %s", core.MustStringify(binding))
	}
	// The rule still holds: its automatic assignment cannot be revoked by hand.
	f.fails("INVALID_TRANSITION", "revoke", f.owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"))
	// Assigning by hand takes it over.
	taken := f.ok("assign", f.owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"))
	if taken.Get("replacedAutomatic") != true || taken.Get("automatic") != false {
		t.Fatalf("take-over %s", core.MustStringify(taken))
	}
}

func TestPackagesRetimeAssignmentLengthensOnlyTheGivenMemberships(t *testing.T) {
	f := newPkgFixture(t)
	server := f.iam.Context
	kit := f.ok("create", f.owner, "name", "Kit", "roleIds", []any{f.reader.Get("id")}, "groupIds", []any{f.engineering.Get("id")})
	alice := f.person("alice")
	assigned := f.ok("assign", f.owner, "packageId", kit.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+dayMs)
	next := f.now() + 3*dayMs
	_, err := core.Transact(f.ctx, f.store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		pkg, err := tx.Get(ctx, "accessPackages", jsString(kit.Get("id")))
		if err != nil {
			return nil, err
		}
		assignment, err := tx.Get(ctx, "packageAssignments", jsString(assigned.Get("id")))
		if err != nil {
			return nil, err
		}
		// An empty set lengthens no membership; the binding of the packaged role still follows.
		return RetimeAssignment(ctx, server, tx, pkg, assignment, &next, []string{})
	})
	requirePorted(t, err)
	if jsNumber(f.record("packageAssignments", jsString(assigned.Get("id"))).Get("expiresAt")) != next {
		t.Fatal("the assignment did not move")
	}
	if jsNumber(f.record("bindings", flowStrings(assigned.Get("bindingIds"))[0]).Get("expiresAt")) != next {
		t.Fatal("the binding did not move")
	}
	if jsNumber(f.membership(f.engineering.Get("id"), alice.Get("id")).Get("expiresAt")) != f.now()+dayMs {
		t.Fatal("a membership outside lengthenOnly moved")
	}
}
