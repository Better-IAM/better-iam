package scim

// Port of tests/scim-manager.test.ts: SCIM enterprise manager mapping against the IAM server.

import (
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

func managerPath() string { return EnterpriseSchema + ":manager.value" }

func replaceManager(id string) *core.Object {
	return obj("op", "replace", "path", managerPath(), "value", id)
}

func (d *directory) setManagerAsAdmin(user, managerID string) {
	d.t.Helper()
	_, err := d.iam.API.Identities.Update(d.ctx, d.owner, server.Input[apitypes.IdentitiesUpdateInput](obj(
		"tenantId", d.tenantID, "identityId", d.identityID(user), "managerId", managerID,
	)))
	requirePorted(d.t, err)
}

func TestManagerSetOnCreateByScimIDCaseExactExternalIDOrUserName(t *testing.T) {
	d := newDirectory(t, nil)
	boss := d.create(obj("userName", "boss@acme.test", "externalId", "EMP-1"))
	bossID := d.identityID(boss)
	byID := d.create(withUser(obj("userName", "a@acme.test"), managedBy(boss)))
	byExternalID := d.create(withUser(obj("userName", "b@acme.test"), managedBy("EMP-1")))
	byUserName := d.create(withUser(obj("userName", "c@acme.test"), managedBy("BOSS@acme.test")))
	wrongCase := d.create(withUser(obj("userName", "d@acme.test"), managedBy("emp-1")))
	for _, user := range []string{byID, byExternalID, byUserName} {
		if d.managerOf(user) != bossID {
			t.Fatalf("manager of %s: %v", user, d.managerOf(user))
		}
	}
	if !core.IsUndefined(d.managerOf(wrongCase)) {
		t.Fatal("externalId must match case-exactly")
	}
	out, err := d.iam.API.Identities.ListReports(d.ctx, d.owner, server.Input[apitypes.IdentitiesListReportsInput](obj("tenantId", d.tenantID, "identityId", bossID)))
	requirePorted(t, err)
	var reports []string
	for _, report := range out.Value.([]any) {
		reports = append(reports, jsString(member(report, "id")))
	}
	sort.Strings(reports)
	want := []string{d.identityID(byID), d.identityID(byExternalID), d.identityID(byUserName)}
	sort.Strings(want)
	if strings.Join(reports, ",") != strings.Join(want, ",") {
		t.Fatalf("reports: %v, want %v", reports, want)
	}

	// Entra ID adds the manager as a bare ID on the manager attribute itself.
	body := d.patch(wrongCase, obj("op", "Add", "path", EnterpriseSchema+":manager", "value", boss))
	sameJSON(t, body.get(EnterpriseSchema), obj("manager", obj("value", boss)))
	if d.managerOf(wrongCase) != bossID {
		t.Fatal("bare manager ID")
	}
}

func TestManagerBackFillsReportsProvisionedBeforeTheirManager(t *testing.T) {
	d := newDirectory(t, nil)
	first := d.create(withUser(obj("userName", "first@acme.test"), managedBy("EMP-9")))
	second := d.create(withUser(obj("userName", "second@acme.test"), managedBy("LEAD@acme.test")))
	assigned := d.create(withUser(obj("userName", "third@acme.test"), managedBy("EMP-9")))
	if !core.IsUndefined(d.managerOf(first)) {
		t.Fatal("manager before the manager exists")
	}
	// A manager an administrator set in the meantime is kept.
	alice := d.member("alice")
	aliceID := jsString(alice.Get("id"))
	d.setManagerAsAdmin(assigned, aliceID)

	lead := d.create(obj("userName", "lead@acme.test", "externalId", "EMP-9"))
	leadID := d.identityID(lead)
	if d.managerOf(first) != leadID || d.managerOf(second) != leadID || d.managerOf(assigned) != aliceID {
		t.Fatalf("back-fill: %v %v %v", d.managerOf(first), d.managerOf(second), d.managerOf(assigned))
	}
}

func TestManagerFollowsPatchAndPutAndClearsTheManagerScimRemoved(t *testing.T) {
	d := newDirectory(t, nil)
	first := d.create(obj("userName", "first-boss@acme.test"))
	second := d.create(obj("userName", "second-boss@acme.test", "externalId", "EMP-2"))
	user := d.create(obj("userName", "user@acme.test"))
	d.patch(user, replaceManager(first))
	if d.managerOf(user) != d.identityID(first) {
		t.Fatal("patch by ID")
	}
	d.patch(user, replaceManager("EMP-2"))
	if d.managerOf(user) != d.identityID(second) {
		t.Fatal("patch by externalId")
	}
	d.patch(user, obj("op", "remove", "path", EnterpriseSchema+":manager"))
	if !core.IsUndefined(d.managerOf(user)) {
		t.Fatal("remove")
	}
	d.put(user, withUser(obj("userName", "user@acme.test"), managedBy(first)))
	if d.managerOf(user) != d.identityID(first) {
		t.Fatal("put")
	}
	d.put(user, obj("userName", "user@acme.test", "title", "Engineer"))
	if !core.IsUndefined(d.managerOf(user)) {
		t.Fatal("put without manager")
	}
	// A SCIM-set manager the IdP replaces with someone not provisioned yet is cleared, then back-filled.
	d.patch(user, replaceManager(first))
	d.patch(user, replaceManager("EMP-3"))
	if !core.IsUndefined(d.managerOf(user)) {
		t.Fatal("not provisioned yet")
	}
	third := d.create(obj("userName", "third-boss@acme.test", "externalId", "EMP-3"))
	if d.managerOf(user) != d.identityID(third) {
		t.Fatal("back-filled")
	}
}

func TestManagerNeverClearsAManagerAnAdministratorSet(t *testing.T) {
	d := newDirectory(t, nil)
	aliceID := jsString(d.member("alice").Get("id"))
	boss := d.create(obj("userName", "boss@acme.test"))
	user := d.create(obj("userName", "user@acme.test"))
	d.setManagerAsAdmin(user, aliceID)
	d.patch(user, obj("op", "replace", "path", "displayName", "value", "User"))
	d.put(user, obj("userName", "user@acme.test"))
	if d.managerOf(user) != aliceID {
		t.Fatal("cleared an administrator's manager")
	}
	// The IdP naming a manager wins; once an administrator overrides it, removing it in SCIM keeps theirs.
	d.patch(user, obj("op", "add", "path", managerPath(), "value", boss))
	if d.managerOf(user) != d.identityID(boss) {
		t.Fatal("the IdP's manager")
	}
	d.setManagerAsAdmin(user, aliceID)
	d.patch(user, obj("op", "remove", "path", EnterpriseSchema+":manager"))
	if d.managerOf(user) != aliceID {
		t.Fatal("cleared an administrator's override")
	}
}

func TestManagerIgnoresCircularManagersAndSettlesReorganizations(t *testing.T) {
	d := newDirectory(t, nil)
	top := d.create(obj("userName", "top@acme.test"))
	a := d.create(obj("userName", "a@acme.test"))
	b := d.create(withUser(obj("userName", "b@acme.test"), managedBy(a)))
	c := d.create(withUser(obj("userName", "c@acme.test"), managedBy(b)))
	topID, aID, bID := d.identityID(top), d.identityID(a), d.identityID(b)
	if d.managerOf(b) != aID {
		t.Fatal("b reports to a")
	}
	// B (or B's report C) as A's manager would be circular: ignored, not an error.
	body := d.patch(a, replaceManager(b))
	sameJSON(t, member(body.get(EnterpriseSchema), "manager"), obj("value", b))
	if !core.IsUndefined(d.managerOf(a)) {
		t.Fatal("circular via b")
	}
	d.patch(a, replaceManager(c))
	if !core.IsUndefined(d.managerOf(a)) {
		t.Fatal("circular via c")
	}
	solo := d.create(withUser(obj("userName", "solo@acme.test"), managedBy("solo@acme.test")))
	if !core.IsUndefined(d.managerOf(solo)) {
		t.Fatal("self")
	}
	// Reorganization: A moves under B and B under Top, and the IdP sends A first.
	d.patch(a, replaceManager(top))
	if d.managerOf(a) != topID {
		t.Fatal("a under top")
	}
	d.patch(a, replaceManager(b))
	if !core.IsUndefined(d.managerOf(a)) {
		t.Fatal("a under b before b moves")
	}
	d.patch(b, replaceManager(top))
	if d.managerOf(b) != topID || d.managerOf(a) != bID || d.managerOf(c) != bID {
		t.Fatalf("settled: %v %v %v", d.managerOf(b), d.managerOf(a), d.managerOf(c))
	}
}

func TestManagerReleasesReportsWhenScimDeletesTheirManager(t *testing.T) {
	d := newDirectory(t, nil)
	boss := d.create(obj("userName", "boss@acme.test", "externalId", "EMP-5"))
	report := d.create(withUser(obj("userName", "report@acme.test"), managedBy("EMP-5")))
	if d.managerOf(report) != d.identityID(boss) {
		t.Fatal("report")
	}
	if got := d.request("Users/"+boss, "DELETE", nil); got.status != 204 {
		t.Fatalf("delete: %d %s", got.status, show(got.body))
	}
	if !core.IsUndefined(d.managerOf(report)) {
		t.Fatal("released")
	}
	returned := d.create(obj("userName", "boss-again@acme.test", "externalId", "EMP-5"))
	if d.managerOf(report) != d.identityID(returned) {
		t.Fatal("relinked")
	}
}

func TestManagerBackFillsAndReleasesManyReportsInOneSave(t *testing.T) {
	d := newDirectory(t, nil)
	var operations []any
	for index := 0; index < 60; index++ {
		reference := "LEAD@acme.test"
		if index%2 == 1 {
			reference = "EMP-7"
		}
		operations = append(operations, obj("method", "POST", "bulkId", "r"+core.NumberString(float64(index)), "path", "/Users",
			"data", withUser(obj("userName", "report-"+core.NumberString(float64(index))+"@acme.test"), managedBy(reference))))
	}
	bulk := d.request("Bulk", "POST", obj("schemas", list(BulkRequestSchema), "Operations", operations))
	for _, item := range bulk.get("Operations").([]any) {
		if member(item, "status") != "201" {
			t.Fatalf("bulk: %s", show(item))
		}
	}
	lead := d.create(obj("userName", "lead@acme.test", "externalId", "EMP-7"))
	leadID := d.identityID(lead)
	reports := func() int {
		return len(find(t, d.store, "identities", obj("tenantId", d.tenantID, "managerId", leadID)))
	}
	if reports() != 60 {
		t.Fatalf("reports: %d", reports())
	}
	if got := d.request("Users/"+lead, "DELETE", nil); got.status != 204 {
		t.Fatalf("delete: %d", got.status)
	}
	if reports() != 0 {
		t.Fatalf("released: %d", reports())
	}
}

func TestManagerTreatsAReferenceNamingTheUserThemselfAsNoManager(t *testing.T) {
	d := newDirectory(t, nil)
	// A self-managed CEO named by its own externalId, which is also another user's userName.
	namesake := d.create(obj("userName", "jdoe"))
	ceo := d.create(withUser(obj("userName", "ceo@acme.test", "externalId", "jdoe"), managedBy("jdoe")))
	if !core.IsUndefined(d.managerOf(ceo)) {
		t.Fatal("self")
	}
	// Back-fill resolves the same way: saving the namesake adopts no one.
	d.patch(namesake, obj("op", "replace", "path", "displayName", "value", "J. Doe"))
	if !core.IsUndefined(d.managerOf(ceo)) {
		t.Fatal("adopted by the namesake")
	}
	// Another user's identical reference still follows precedence: externalId (the CEO) before userName.
	report := d.create(withUser(obj("userName", "report@acme.test"), managedBy("jdoe")))
	if d.managerOf(report) != d.identityID(ceo) {
		t.Fatal("precedence")
	}
	// SCIM deleting the namesake leaves nobody pointing at its disabled identity.
	namesakeID := d.identityID(namesake)
	if got := d.request("Users/"+namesake, "DELETE", nil); got.status != 204 {
		t.Fatalf("delete: %d", got.status)
	}
	if len(find(t, d.store, "identities", obj("tenantId", d.tenantID, "managerId", namesakeID))) != 0 {
		t.Fatal("pointing at the namesake")
	}
	// Updates too: an own externalId that is another userName ignoring case, and an own SCIM ID that is another
	// user's externalId.
	d.create(obj("userName", "e1"))
	lead := d.create(obj("userName", "lead@acme.test"))
	d.put(lead, withUser(obj("userName", "lead@acme.test", "externalId", "E1"), managedBy("E1")))
	if !core.IsUndefined(d.managerOf(lead)) {
		t.Fatal("own externalId")
	}
	d.create(obj("userName", "shadow@acme.test", "externalId", lead))
	d.patch(lead, replaceManager(lead))
	if !core.IsUndefined(d.managerOf(lead)) {
		t.Fatal("own SCIM ID")
	}
}

func TestManagerNeverRevivesReassignsOrRegroupsADeletedIdentity(t *testing.T) {
	d := newDirectory(t, nil)
	boss := d.create(obj("userName", "boss@acme.test"))
	user := d.create(withUser(obj("userName", "gone@acme.test"), managedBy("EMP-8")))
	created := d.request("Groups", "POST", obj("displayName", "Staff", "members", list(obj("value", user))))
	if created.status != 201 {
		t.Fatalf("group: %d %s", created.status, show(created.body))
	}
	group := created.get("id").(string)
	identityID := d.identityID(user)
	_, err := d.iam.API.Identities.Delete(d.ctx, d.owner, server.Input[apitypes.IdentitiesDeleteInput](obj("tenantId", d.tenantID, "identityId", identityID)))
	requirePorted(t, err)

	for _, attempt := range []struct {
		method string
		body   *core.Object
	}{
		{"PATCH", patchOp(replaceManager(boss))},
		{"PUT", withUser(obj("userName", "gone@acme.test", "active", true), managedBy(boss))},
	} {
		response := d.request("Users/"+user, attempt.method, attempt.body)
		if response.status != 403 || response.get("scimType") != "mutability" {
			t.Fatalf("%s: %d %s", attempt.method, response.status, show(response.body))
		}
	}
	// Back-fill skips it, and the IdP's group updates keep it out of the local group (and its mapped roles).
	d.create(obj("userName", "lead@acme.test", "externalId", "EMP-8"))
	renamed := d.request("Groups/"+group, "PATCH", patchOp(obj("op", "replace", "path", "displayName", "value", "Everyone")))
	if renamed.status != 200 {
		t.Fatalf("rename: %d %s", renamed.status, show(renamed.body))
	}
	groupID := get(t, d.store, "scimGroups", group).Get("groupId")
	if len(find(t, d.store, "groupMembers", obj("tenantId", d.tenantID, "groupId", groupID))) != 0 {
		t.Fatal("regrouped")
	}
	tombstone := d.identityOf(user)
	if tombstone.Get("status") != "deleted" || tombstone.Get("emailVerified") != false || !core.IsUndefined(tombstone.Get("email")) || !core.IsUndefined(tombstone.Get("managerId")) {
		t.Fatalf("tombstone: %s", show(tombstone))
	}
	// The IdP can still deprovision it; the tombstone stays deleted.
	if got := d.request("Users/"+user, "DELETE", nil); got.status != 204 {
		t.Fatalf("delete: %d", got.status)
	}
	if get(t, d.store, "identities", identityID).Get("status") != "deleted" {
		t.Fatal("revived")
	}
}

func TestManagerLeavesManagersAloneWithMapManagerFalse(t *testing.T) {
	off := false
	d := newDirectory(t, func(config *Config) { config.MapManager = &off })
	early := d.create(withUser(obj("userName", "early@acme.test"), managedBy("late@acme.test")))
	boss := d.create(obj("userName", "boss@acme.test"))
	report := d.create(withUser(obj("userName", "report@acme.test"), managedBy(boss)))
	d.create(obj("userName", "late@acme.test"))
	body := d.patch(early, replaceManager(boss))
	sameJSON(t, member(body.get(EnterpriseSchema), "manager"), obj("value", boss))
	if !core.IsUndefined(d.managerOf(early)) || !core.IsUndefined(d.managerOf(report)) {
		t.Fatal("mapped with mapManager false")
	}
}
