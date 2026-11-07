package server

// Ports of the tests of packages/server/src/api/groups.ts: tests/membership-expiry.test.ts (temporary and batch
// memberships) and the group parts of tests/server.test.ts. See api_roles_test.go for the fixture.

import (
	"reflect"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

func (f *orgFixture) createGroup(name string, extra ...any) *core.Object {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID, "name", name)
	input.Assign(core.NewObject(extra...))
	return f.object(f.iam.API.Groups.Create(f.ctx, f.owner, Input[apitypes.GroupsCreateInput](input)))
}

func (f *orgFixture) addMember(members ...any) (*core.Object, error) {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID)
	input.Assign(core.NewObject(members...))
	answer, err := f.iam.API.Groups.AddMember(f.ctx, f.owner, Input[apitypes.GroupsAddMemberInput](input))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func (f *orgFixture) updateMember(members ...any) (*core.Object, error) {
	f.t.Helper()
	input := core.NewObject("tenantId", f.tenantID)
	input.Assign(core.NewObject(members...))
	answer, err := f.iam.API.Groups.UpdateMember(f.ctx, f.owner, Input[apitypes.GroupsUpdateMemberInput](input))
	if err != nil {
		return nil, err
	}
	return answer.Value.(*core.Object), nil
}

func (f *orgFixture) listMembers(groupID any) []*core.Object {
	f.t.Helper()
	return f.items(f.iam.API.Groups.ListMembers(f.ctx, f.owner, Input[apitypes.GroupsListMembersInput](core.NewObject("tenantId", f.tenantID, "groupId", groupID))))
}

func TestGroupsTemporaryMembershipsEndByThemselvesAndAreSweptByTheWorker(t *testing.T) {
	f := newOrgFixture(t, nil)
	alice := f.member("alice")
	project := f.createGroup("Project X")
	reader := f.createRole(f.owner, "name", "Reader", "permissions", []any{"documents:read"})
	f.bind(f.owner, reader.Get("id"), "group", project.Get("id"))
	_, err := f.addMember("groupId", project.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()-1)
	expectCode(t, err, "INVALID_INPUT")
	membership, err := f.addMember("groupId", project.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+2*day)
	requirePorted(t, err)
	if membership.Get("expiresAt") != f.now()+2*day {
		t.Fatalf("membership: %s", core.MustStringify(membership))
	}
	_, err = f.addMember("groupId", project.Get("id"), "identityId", alice.Get("id"))
	expectError(t, err, "CONFLICT", "Already a member of this group")
	asAlice := f.login("alice")
	can := func() bool { return f.can(asAlice, "documents:read", "documents", "a") }
	if !can() {
		t.Fatal("a live membership confers the group's grants")
	}
	members := f.listMembers(project.Get("id"))
	if len(members) != 1 || members[0].Get("id") != alice.Get("id") || members[0].Get("membershipExpiresAt") != f.now()+2*day {
		t.Fatalf("members: %s", core.MustStringify(objectsOf(members)))
	}
	groups := f.items(f.iam.API.Identities.ListGroups(f.ctx, f.owner, Input[apitypes.IdentitiesListGroupsInput](core.NewObject("tenantId", f.tenantID, "identityId", alice.Get("id")))))
	if len(groups) != 1 || groups[0].Get("membershipExpiresAt") != f.now()+2*day {
		t.Fatalf("groups: %s", core.MustStringify(objectsOf(groups)))
	}
	// Extending, then letting it lapse.
	extended, err := f.updateMember("groupId", project.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+3*day)
	requirePorted(t, err)
	if extended.Get("expiresAt") != f.now()+3*day {
		t.Fatalf("extended: %s", core.MustStringify(extended))
	}
	report := f.object(f.iam.API.Reports.Access(f.ctx, f.owner, Input[apitypes.ReportsAccessInput](core.NewObject("tenantId", f.tenantID, "withinMs", 7*day))))
	expiring := asList(member(report.Get("bindings"), "expiringMemberships"))
	if len(expiring) != 1 || member(expiring[0], "groupName") != "Project X" || member(expiring[0], "identityName") != "alice" {
		t.Fatalf("expiring memberships: %s", core.MustStringify(expiring))
	}
	f.clock.Add(int64(3*day) + 1)
	if can() {
		t.Fatal("a lapsed membership confers nothing")
	}
	if members := f.listMembers(project.Get("id")); len(members) != 0 {
		t.Fatalf("lapsed members are omitted: %s", core.MustStringify(objectsOf(members)))
	}
	if groups := f.items(f.iam.API.Identities.ListGroups(f.ctx, f.owner, Input[apitypes.IdentitiesListGroupsInput](core.NewObject("tenantId", f.tenantID, "identityId", alice.Get("id"))))); len(groups) != 0 {
		t.Fatalf("lapsed groups are omitted: %s", core.MustStringify(objectsOf(groups)))
	}
	if bindings := f.items(f.iam.API.Identities.ListBindings(f.ctx, f.owner, Input[apitypes.IdentitiesListBindingsInput](core.NewObject("tenantId", f.tenantID, "identityId", alice.Get("id"))))); len(bindings) != 0 {
		t.Fatalf("lapsed group bindings are omitted: %s", core.MustStringify(objectsOf(bindings)))
	}
	// Re-adding a lapsed member renews the membership; clearing the expiry makes it permanent.
	_, err = f.addMember("groupId", project.Get("id"), "identityId", alice.Get("id"))
	requirePorted(t, err)
	if !can() {
		t.Fatal("a renewed membership confers the group's grants again")
	}
	_, err = f.updateMember("groupId", project.Get("id"), "identityId", alice.Get("id"), "expiresAt", f.now()+day)
	requirePorted(t, err)
	permanent, err := f.updateMember("groupId", project.Get("id"), "identityId", alice.Get("id"), "expiresAt", nil)
	requirePorted(t, err)
	if permanent.Has("expiresAt") {
		t.Fatalf("expiresAt null makes the membership permanent: %s", core.MustStringify(permanent))
	}
	_, err = f.updateMember("groupId", project.Get("id"), "identityId", f.ownerID, "expiresAt", nil)
	expectError(t, err, "NOT_FOUND", "Not a member of this group")
	// The purge worker removes lapsed memberships and the activations they carried.
	bob := f.member("bob")
	memberRole := f.createRole(f.owner, "name", "Member", "permissions", []any{"iam:bindings:activate"})
	f.bind(f.owner, memberRole.Get("id"), "identity", bob.Get("id"))
	writer := f.createRole(f.owner, "name", "Writer", "permissions", []any{"documents:write"})
	eligible := f.bind(f.owner, writer.Get("id"), "group", project.Get("id"), "eligible", true)
	_, err = f.addMember("groupId", project.Get("id"), "identityId", bob.Get("id"), "expiresAt", f.now()+60_000)
	requirePorted(t, err)
	asBob := f.login("bob")
	f.ported(f.iam.API.Bindings.Activate(f.ctx, asBob, Input[apitypes.BindingsActivateInput](core.NewObject("tenantId", f.tenantID, "bindingId", eligible.Get("id")))))
	f.clock.Add(60_001)
	purge, err := f.iam.PurgeDeleted(f.ctx, nil)
	requirePorted(t, err)
	if purge.Get("expiredMemberships") != 1.0 {
		t.Fatalf("purge: %s", core.MustStringify(purge))
	}
	activations := f.items(f.iam.API.Bindings.ListActivations(f.ctx, f.owner, Input[apitypes.BindingsListActivationsInput](core.NewObject(
		"tenantId", f.tenantID, "identityId", bob.Get("id"), "includeExpired", true))))
	if len(activations) != 0 {
		t.Fatalf("activations: %s", core.MustStringify(objectsOf(activations)))
	}
	if rows := f.find("groupMembers", core.NewObject("tenantId", f.tenantID, "identityId", bob.Get("id"))); len(rows) != 0 {
		t.Fatalf("group members: %s", core.MustStringify(objectsOf(rows)))
	}
}

func TestGroupsBatchMembershipAddsACohortAndRejectsTheBatchOnOneFailure(t *testing.T) {
	f := newOrgFixture(t, nil)
	alice, bob := f.member("alice"), f.member("bob")
	cohort := f.createGroup("Cohort")
	addMembers := func(members ...any) (*core.Object, error) {
		input := core.NewObject("tenantId", f.tenantID, "groupId", cohort.Get("id"))
		input.Assign(core.NewObject(members...))
		answer, err := f.iam.API.Groups.AddMembers(f.ctx, f.owner, Input[apitypes.GroupsAddMembersInput](input))
		if err != nil {
			return nil, err
		}
		return answer.Value.(*core.Object), nil
	}
	added, err := addMembers("identityIds", []any{alice.Get("id"), bob.Get("id"), alice.Get("id")}, "expiresAt", f.now()+7*day)
	requirePorted(t, err)
	var got [][2]any
	for _, item := range asList(added.Get("members")) {
		got = append(got, [2]any{member(item, "identityId"), member(item, "expiresAt")})
	}
	want := [][2]any{{alice.Get("id"), f.now() + 7*day}, {bob.Get("id"), f.now() + 7*day}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("added: %v", got)
	}
	_, err = addMembers("identityIds", []any{})
	expectError(t, err, "INVALID_INPUT", "Provide 1-100 identityIds")
	carol := f.member("carol")
	// Bob is already a member, so the whole batch is refused and Carol is not added either.
	_, err = addMembers("identityIds", []any{carol.Get("id"), bob.Get("id")})
	expectCode(t, err, "CONFLICT")
	var ids []string
	for _, item := range f.listMembers(cohort.Get("id")) {
		ids = append(ids, jsString(item.Get("id")))
	}
	sort.Strings(ids)
	expected := []string{jsString(alice.Get("id")), jsString(bob.Get("id"))}
	sort.Strings(expected)
	if !reflect.DeepEqual(ids, expected) {
		t.Fatalf("members: %v", ids)
	}
}

func TestGroupsCreateRenameAndDescribe(t *testing.T) {
	f := newOrgFixture(t, nil)
	group := f.createGroup("Editors", "description", "Can edit")
	if group.Get("name") != "Editors" || group.Get("description") != "Can edit" || group.Get("tenantId") != f.tenantID {
		t.Fatalf("group: %s", core.MustStringify(group))
	}
	update := func(members ...any) (*core.Object, error) {
		input := core.NewObject("tenantId", f.tenantID, "groupId", group.Get("id"))
		input.Assign(core.NewObject(members...))
		answer, err := f.iam.API.Groups.Update(f.ctx, f.owner, Input[apitypes.GroupsUpdateInput](input))
		if err != nil {
			return nil, err
		}
		return answer.Value.(*core.Object), nil
	}
	_, err := update()
	expectError(t, err, "INVALID_INPUT", "Nothing to update")
	renamed, err := update("name", "Writers")
	requirePorted(t, err)
	if renamed.Get("name") != "Writers" || renamed.Get("description") != "Can edit" {
		t.Fatalf("renamed: %s", core.MustStringify(renamed))
	}
	fetched := f.object(f.iam.API.Groups.Get(f.ctx, f.owner, Input[apitypes.GroupsGetInput](core.NewObject("tenantId", f.tenantID, "groupId", group.Get("id")))))
	if core.MustStringify(fetched) != core.MustStringify(renamed) {
		t.Fatalf("fetched: %s", core.MustStringify(fetched))
	}
	listed := f.items(f.iam.API.Groups.List(f.ctx, f.owner, Input[apitypes.GroupsListInput](core.NewObject("tenantId", f.tenantID))))
	if len(listed) != 1 || listed[0].Get("id") != group.Get("id") {
		t.Fatalf("listed: %s", core.MustStringify(objectsOf(listed)))
	}
	_, err = f.iam.API.Groups.Get(f.ctx, f.owner, Input[apitypes.GroupsGetInput](core.NewObject("tenantId", f.tenantID, "groupId", "missing")))
	expectCode(t, err, "NOT_FOUND")
	deleted := f.object(f.iam.API.Groups.Delete(f.ctx, f.owner, Input[apitypes.GroupsDeleteInput](core.NewObject("tenantId", f.tenantID, "groupId", group.Get("id")))))
	if deleted.Get("deleted") != true || f.record("groups", jsString(group.Get("id"))) != nil {
		t.Fatalf("deleted: %s", core.MustStringify(deleted))
	}
}
