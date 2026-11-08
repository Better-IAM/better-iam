package server

// Ports of tests/departments.test.ts (the `departments` API group) and the department part of
// tests/security-org.test.ts (syncManagers honors a deny protecting one person). Teams are seeded in the store
// (the teams API is its own unit). Steps that reach another unit's NOT_IMPLEMENTED stub skip the rest of the test.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// deptCall calls a route of the API surface with a body for the fixture's organization.
func (f *orgFixture) deptCall(route string, credential core.CredentialInput, members ...any) (any, error) {
	f.t.Helper()
	body := core.NewObject("tenantId", f.tenantID)
	body.Assign(core.NewObject(members...))
	handler, ok := rpcRoutes[route]
	if !ok {
		f.t.Fatalf("no route %s", route)
	}
	return handler(f.ctx, f.iam.API, credential, body)
}

// deptObject is deptCall for an answer that is one object; another unit's stub skips the rest of the test.
func (f *orgFixture) deptObject(route string, credential core.CredentialInput, members ...any) *core.Object {
	f.t.Helper()
	answer, err := f.deptCall(route, credential, members...)
	requirePorted(f.t, err)
	result, ok := answer.(*core.Object)
	if !ok {
		f.t.Fatalf("%s: expected an object, got %T", route, answer)
	}
	return result
}

// deptList is deptCall for an answer that is a list.
func (f *orgFixture) deptList(route string, credential core.CredentialInput, members ...any) []*core.Object {
	f.t.Helper()
	answer, err := f.deptCall(route, credential, members...)
	requirePorted(f.t, err)
	list, ok := answer.([]any)
	if !ok {
		f.t.Fatalf("%s: expected a list, got %T", route, answer)
	}
	result := make([]*core.Object, len(list))
	for index, item := range list {
		result[index] = item.(*core.Object)
	}
	return result
}

// expectJSONOf compares a value's JSON with the expected text.
func expectJSONOf(t *testing.T, label string, value any, want string) {
	t.Helper()
	got := core.MustStringify(value)
	compact := core.MustStringify(parse(t, want))
	if got != compact {
		t.Fatalf("%s: expected %s, got %s", label, compact, got)
	}
}

// expectMember compares one member of an object (JSON).
func expectMember(t *testing.T, value any, key, want string) {
	t.Helper()
	expectJSONOf(t, key, member(value, key), want)
}

type deptScenario struct {
	*orgFixture
	alice, bob, carol, dave *core.Object
	engineering, platform   *core.Object
}

// newDeptScenario is the test file's scenario(): four members, Engineering (ENG, headed by alice, CC-100) and
// Platform below it (ENG-PLT, headed by bob); documents named `doc-{departmentId}` belong to that department.
func newDeptScenario(t *testing.T) *deptScenario {
	t.Helper()
	f := newOrgFixture(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{
			Actions:            []string{"documents:read", "documents:write"},
			IdentityAttributes: []core.NamedAttribute{{Name: "department", Type: "string"}},
		}
		options.ResolveResource = func(_ context.Context, reference core.ResourceRef) (*ResolvedResource, error) {
			return &ResolvedResource{TenantID: reference.TenantID, Type: reference.Type, ID: reference.ID,
				Attributes: core.NewObject("departmentId", strings.TrimPrefix(reference.ID, "doc-"))}, nil
		}
	})
	s := &deptScenario{orgFixture: f}
	s.alice, s.bob, s.carol, s.dave = f.member("alice"), f.member("bob"), f.member("carol"), f.member("dave")
	s.engineering = f.deptObject("departments/create", f.owner, "name", "Engineering", "code", "ENG", "headId", s.alice.Get("id"), "costCenter", "CC-100")
	s.platform = f.deptObject("departments/create", f.owner, "name", "Platform", "code", "ENG-PLT", "parentId", s.engineering.Get("id"), "headId", s.bob.Get("id"))
	return s
}

func (s *deptScenario) assign(departmentID any, members ...any) *core.Object {
	s.t.Helper()
	return s.deptObject("departments/assign", s.owner, append([]any{"departmentId", departmentID}, members...)...)
}

func pathOf(t *testing.T, value any, key string) []string {
	t.Helper()
	steps, _ := member(value, "path").([]any)
	out := make([]string, len(steps))
	for index, step := range steps {
		out[index] = jsString(member(step, key))
	}
	return out
}

func expectList(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	if want == nil {
		want = []string{}
	}
	if strings.Join(got, "|") != strings.Join(want, "|") || len(got) != len(want) {
		t.Fatalf("%s: expected %v, got %v", label, want, got)
	}
}

func TestDepartmentsBuildATreeWithHeadsCodesAndUniqueNames(t *testing.T) {
	s := newDeptScenario(t)
	expectMember(t, s.engineering, "name", `"Engineering"`)
	expectMember(t, s.engineering, "code", `"ENG"`)
	expectMember(t, s.engineering, "costCenter", `"CC-100"`)
	expectMember(t, member(s.engineering, "head"), "id", core.MustStringify(s.alice.Get("id")))
	expectMember(t, s.engineering, "path", `[]`)
	expectList(t, "platform path", pathOf(t, s.platform, "code"), "ENG")
	// The summary members, in the record's order, then the detail.
	keys := strings.Join(s.engineering.Keys(), ",")
	if keys != "id,tenantId,name,code,headId,costCenter,createdAt,updatedAt,memberCount,totalMemberCount,childCount,teamCount,path,children,head,teams" {
		t.Fatalf("detail members %s", keys)
	}

	_, err := s.deptCall("departments/create", s.owner, "name", "engineering")
	expectCodeOrSkip(t, err, "CONFLICT")
	_, err = s.deptCall("departments/create", s.owner, "name", "Eng 2", "code", "eng")
	expectCodeOrSkip(t, err, "CONFLICT")
	_, err = s.deptCall("departments/update", s.owner, "departmentId", s.engineering.Get("id"), "parentId", s.platform.Get("id"))
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	service := s.deptObject("serviceAccounts/create", s.owner, "name", "ci")
	_, err = s.deptCall("departments/update", s.owner, "departmentId", s.platform.Get("id"), "headId", service.Get("id"))
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	cleared := s.deptObject("departments/update", s.owner, "departmentId", s.platform.Get("id"), "code", nil, "description", "Runs shared infrastructure")
	if cleared.Has("code") {
		t.Fatalf("code kept: %s", core.MustStringify(cleared))
	}
	expectMember(t, cleared, "description", `"Runs shared infrastructure"`)
	audits := s.auditTrail(s.tenantID, "department:update")
	if len(audits) == 0 {
		t.Fatal("no department:update audit event")
	}
	expectMember(t, audits[len(audits)-1].Get("metadata"), "fields", `["code","description"]`)
}

func TestDepartmentsPlacePeopleOneDepartmentEachAndRollCountsUpTheTree(t *testing.T) {
	s := newDeptScenario(t)
	s.assign(s.engineering.Get("id"), "identityIds", []any{s.alice.Get("id"), s.carol.Get("id")})
	moved := s.assign(s.platform.Get("id"), "identityIds", []any{s.bob.Get("id"), s.carol.Get("id")}, "title", "Engineer")
	expectJSONOf(t, "moved", moved, `{"assigned":2,"unchanged":0}`)
	tree := s.deptList("departments/tree", s.owner)
	if len(tree) != 1 {
		t.Fatalf("tree roots %d", len(tree))
	}
	expectMember(t, tree[0], "name", `"Engineering"`)
	expectMember(t, tree[0], "memberCount", `1`)
	expectMember(t, tree[0], "totalMemberCount", `3`)
	children, _ := tree[0].Get("children").([]any)
	if len(children) != 1 {
		t.Fatalf("children %d", len(children))
	}
	expectMember(t, children[0], "name", `"Platform"`)
	expectMember(t, children[0], "memberCount", `2`)
	expectMember(t, member(children[0], "head"), "id", core.MustStringify(s.bob.Get("id")))
	everyone := s.deptList("departments/listMembers", s.owner, "departmentId", s.engineering.Get("id"), "includeSubdepartments", true)
	var rows []string
	for _, view := range everyone {
		rows = append(rows, jsString(view.Get("name"))+":"+jsString(member(view.Get("department"), "name"))+":"+jsString(view.Get("head") == true))
	}
	expectList(t, "members", rows, "alice:Engineering:true", "bob:Platform:true", "carol:Platform:false")
	carol := s.deptObject("departments/ofIdentity", s.owner, "identityId", s.carol.Get("id"))
	expectMember(t, carol.Get("department"), "name", `"Platform"`)
	expectMember(t, carol, "title", `"Engineer"`)
	expectMember(t, carol.Get("head"), "id", core.MustStringify(s.bob.Get("id")))
	expectList(t, "carol path", pathOf(t, carol, "name"), "Engineering", "Platform")

	err := s.store.Transaction(s.ctx, func(ctx context.Context, tx core.IamStore) error {
		tenant := s.tenantID
		if department := must(DepartmentOf(ctx, tx, tenant, jsString(s.carol.Get("id")))); department != jsString(s.platform.Get("id")) {
			t.Fatalf("departmentOf %q", department)
		}
		expectList(t, "path", must(DepartmentPath(ctx, tx, tenant, jsString(s.platform.Get("id")))), jsString(s.engineering.Get("id")), jsString(s.platform.Get("id")))
		expectList(t, "heads", must(DepartmentHeads(ctx, tx, tenant, jsString(s.platform.Get("id")), nil)), jsString(s.bob.Get("id")))
		expectList(t, "heads above", must(DepartmentHeads(ctx, tx, tenant, jsString(s.platform.Get("id")), core.NewObject("includeAncestors", true))),
			jsString(s.bob.Get("id")), jsString(s.alice.Get("id")))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	s.deptObject("departments/unassign", s.owner, "identityId", s.carol.Get("id"))
	none, err := s.deptCall("departments/ofIdentity", s.owner, "identityId", s.carol.Get("id"))
	requirePorted(t, err)
	if none != nil {
		t.Fatalf("expected null, got %s", core.MustStringify(none))
	}
	_, err = s.deptCall("departments/unassign", s.owner, "identityId", s.carol.Get("id"))
	expectCodeOrSkip(t, err, "NOT_FOUND")
}

func TestDepartmentsExposePrincipalDepartmentsToPolicies(t *testing.T) {
	s := newDeptScenario(t)
	role := s.createRole(s.owner, "name", "Engineering documents", "document", parse(t, `{"version":1,"statements":[
		{"effect":"allow","actions":["documents:read"],"resources":["*"],"conditions":{"ArrayContains":{"principal.departments":[`+core.MustStringify(s.engineering.Get("id"))+`]}}},
		{"effect":"allow","actions":["documents:write"],"resources":["*"],"conditions":{"StringEquals":{"principal.departmentId":"${resource.departmentId}"}}}]}`))
	s.bind(s.owner, role.Get("id"), "identity", s.carol.Get("id"))
	carol := s.login("carol")
	check := func(action, departmentID string) bool { return s.can(carol, action, "documents", "doc-"+departmentID) }
	if check("documents:read", "x") {
		t.Fatal("read allowed outside a department")
	}
	s.assign(s.platform.Get("id"), "identityIds", []any{s.carol.Get("id")})
	// Platform sits under Engineering.
	if !check("documents:read", "x") {
		t.Fatal("read refused under Engineering")
	}
	// A policy variable compares the person's own department with the resource's.
	if !check("documents:write", jsString(s.platform.Get("id"))) {
		t.Fatal("write refused in the own department")
	}
	if check("documents:write", jsString(s.engineering.Get("id"))) {
		t.Fatal("write allowed in another department")
	}
}

func TestDepartmentsImportFromAnIdentityAttribute(t *testing.T) {
	s := newDeptScenario(t)
	for _, entry := range []struct {
		person *core.Object
		value  string
	}{{s.carol, "eng"}, {s.dave, "Sales"}, {s.bob, "Platform"}} {
		s.deptObject("identities/update", s.owner, "identityId", entry.person.Get("id"), "attributes", core.NewObject("department", entry.value))
	}
	preview := s.deptObject("departments/importFromAttribute", s.owner, "attribute", "department", "dryRun", true)
	expectMember(t, preview, "dryRun", `true`)
	expectMember(t, preview, "created", `[]`)
	expectMember(t, preview, "assigned", `2`)
	expectMember(t, preview, "unchanged", `0`)
	expectMember(t, preview, "unmatched", `["Sales"]`)
	// alice and the owner have no attribute.
	expectMember(t, preview, "missing", `2`)
	if keys := strings.Join(preview.Keys(), ","); keys != "dryRun,created,assigned,unchanged,unmatched,missing" {
		t.Fatalf("result members %s", keys)
	}
	none, err := s.deptCall("departments/ofIdentity", s.owner, "identityId", s.carol.Get("id"))
	requirePorted(t, err)
	if none != nil {
		t.Fatal("a dry run placed carol")
	}
	applied := s.deptObject("departments/importFromAttribute", s.owner, "attribute", "department", "createMissing", true)
	expectJSONOf(t, "applied", applied, `{"dryRun":false,"created":["Sales"],"assigned":3,"unchanged":0,"unmatched":[],"missing":2}`)
	created := s.auditTrail(s.tenantID, "department:create")
	expectMember(t, created[len(created)-1].Get("metadata"), "source", `"attribute:department"`)
	again := s.deptObject("departments/importFromAttribute", s.owner, "attribute", "department")
	expectMember(t, again, "assigned", `0`)
	expectMember(t, again, "unchanged", `3`)
	_, err = s.deptCall("departments/importFromAttribute", s.owner, "attribute", "title")
	expectCodeOrSkip(t, err, "INVALID_INPUT")
}

func TestDepartmentsTurnHeadsIntoManagersWithoutCreatingCycles(t *testing.T) {
	s := newDeptScenario(t)
	s.assign(s.engineering.Get("id"), "identityIds", []any{s.alice.Get("id")})
	s.assign(s.platform.Get("id"), "identityIds", []any{s.bob.Get("id"), s.carol.Get("id"), s.dave.Get("id")})
	// Dave already reports to Alice; without overwrite he keeps her.
	s.deptObject("identities/update", s.owner, "identityId", s.dave.Get("id"), "managerId", s.alice.Get("id"))
	preview := s.deptObject("departments/syncManagers", s.owner, "dryRun", true)
	expectMember(t, preview, "dryRun", `true`)
	expectMember(t, preview, "kept", `1`)
	expectMember(t, preview, "noHead", `1`)
	updated, _ := preview.Get("updated").([]any)
	var pairs []string
	for _, item := range updated {
		pairs = append(pairs, jsString(member(item, "name"))+" -> "+jsString(member(item, "managerName")))
	}
	sort.Strings(pairs)
	expectList(t, "preview", pairs, "bob -> alice", "carol -> bob")
	var carolEntry any
	for _, item := range updated {
		if member(item, "name") == "carol" {
			carolEntry = item
		}
	}
	expectJSONOf(t, "carol", carolEntry, `{"identityId":`+core.MustStringify(s.carol.Get("id"))+`,"name":"carol","managerId":`+core.MustStringify(s.bob.Get("id"))+`,"managerName":"bob"}`)
	if len(s.auditTrail(s.tenantID, "department:sync-managers")) != 0 {
		t.Fatal("a dry run was audited")
	}
	s.deptObject("departments/syncManagers", s.owner)
	reports := s.deptList("identities/listReports", s.owner, "identityId", s.bob.Get("id"))
	var ids []string
	for _, report := range reports {
		ids = append(ids, jsString(report.Get("id")))
	}
	expectList(t, "reports", ids, jsString(s.carol.Get("id")))
	audits := s.auditTrail(s.tenantID, "department:sync-managers")
	if len(audits) != 1 {
		t.Fatalf("sync audits %d", len(audits))
	}
	expectJSONOf(t, "audit", audits[0].Get("metadata"), `{"updated":2}`)
	forced := s.deptObject("departments/syncManagers", s.owner, "overwrite", true)
	expectJSONOf(t, "forced", forced.Get("updated"), `[{"identityId":`+core.MustStringify(s.dave.Get("id"))+`,"name":"dave","managerId":`+core.MustStringify(s.bob.Get("id"))+`,"managerName":"bob"}]`)
	_, err := s.deptCall("departments/syncManagers", s.owner, "departmentId", "missing")
	expectCodeOrSkip(t, err, "NOT_FOUND")
}

func TestDepartmentsDeleteUnassigningPeopleAndUnfilingTeamsAndHandHeadsOver(t *testing.T) {
	s := newDeptScenario(t)
	_, err := s.deptCall("departments/delete", s.owner, "departmentId", s.engineering.Get("id"))
	expectCodeOrSkip(t, err, "RESOURCE_IN_USE")
	s.assign(s.platform.Get("id"), "identityIds", []any{s.carol.Get("id")})
	s.seed(TeamCollections.Teams, core.NewObject("id", "team-build", "tenantId", s.tenantID, "uniqueKey", "slug:build", "name", "Build", "slug", "build",
		"departmentId", s.platform.Get("id"), "createdAt", s.now(), "updatedAt", s.now()))
	platform := s.deptObject("departments/get", s.owner, "departmentId", s.platform.Get("id"))
	expectJSONOf(t, "teams", platform.Get("teams"), `[{"id":"team-build","name":"Build","slug":"build"}]`)
	expectMember(t, platform, "teamCount", `1`)

	owner := s.ownerSignIn()
	offboarded, err := s.deptCall("identities/offboard", owner, "identityId", s.bob.Get("id"), "reason", "Moved on", "successorId", s.dave.Get("id"))
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		// Offboarding reaches another unit's stub: hand the department over directly and go on.
		t.Logf("offboarding blocked by another unit: %s", known.Message)
		s.deptObject("departments/update", owner, "departmentId", s.platform.Get("id"), "headId", s.dave.Get("id"))
	} else {
		if err != nil {
			t.Fatal(err)
		}
		expectMember(t, offboarded, "departmentsReassigned", `1`)
	}
	expectMember(t, s.deptObject("departments/get", owner, "departmentId", s.platform.Get("id")).Get("head"), "id", core.MustStringify(s.dave.Get("id")))

	removed := s.deptObject("departments/delete", owner, "departmentId", s.platform.Get("id"))
	expectJSONOf(t, "removed", removed, `{"deleted":true,"unassigned":1,"teams":1}`)
	build := s.record(TeamCollections.Teams, "team-build")
	if build.Has("departmentId") {
		t.Fatalf("team still filed: %s", core.MustStringify(build))
	}
	s.deptObject("identities/delete", owner, "identityId", s.alice.Get("id"))
	if s.deptObject("departments/get", owner, "departmentId", s.engineering.Get("id")).Has("head") {
		t.Fatal("a deleted head is still shown")
	}
}

func TestDepartmentsShowPeopleTheirOwnDepartmentAndHeadsThePeopleTheyLead(t *testing.T) {
	s := newDeptScenario(t)
	s.assign(s.engineering.Get("id"), "identityIds", []any{s.alice.Get("id")})
	s.assign(s.platform.Get("id"), "identityIds", []any{s.bob.Get("id"), s.carol.Get("id")}, "title", "Engineer")
	carol := s.login("carol")
	mine := s.deptObject("departments/mine", carol)
	expectMember(t, mine, "leads", `[]`)
	placement := mine.Get("department")
	expectMember(t, member(placement, "department"), "name", `"Platform"`)
	expectMember(t, placement, "title", `"Engineer"`)
	expectMember(t, member(placement, "head"), "id", core.MustStringify(s.bob.Get("id")))
	expectList(t, "path", pathOf(t, placement, "name"), "Engineering", "Platform")
	// Alice heads Engineering, so she sees everyone in it and in Platform below it.
	alice := s.login("alice")
	leads, _ := s.deptObject("departments/mine", alice).Get("leads").([]any)
	if len(leads) != 1 {
		t.Fatalf("leads %d", len(leads))
	}
	expectMember(t, member(leads[0], "department"), "name", `"Engineering"`)
	people, _ := member(leads[0], "people").([]any)
	var rows []string
	for _, person := range people {
		rows = append(rows, jsString(member(person, "name"))+":"+jsString(member(member(person, "department"), "name")))
	}
	expectList(t, "people", rows, "alice:Engineering", "bob:Platform", "carol:Platform")
	// Dave has no department and leads none.
	dave := s.login("dave")
	expectJSONOf(t, "dave", s.deptObject("departments/mine", dave), `{"department":null,"leads":[]}`)
	// Only a person's own session in their organization reads it.
	_, err := s.deptCall("departments/mine", dave, "tenantId", "other-tenant")
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
}

func TestDepartmentsKeepReadsAndChangesBehindTheirPermissions(t *testing.T) {
	s := newDeptScenario(t)
	carol := s.login("carol")
	_, err := s.deptCall("departments/list", carol)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	_, err = s.deptCall("departments/create", carol, "name", "Shadow IT")
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	// The owner lists them in name order with their counts.
	list := s.deptList("departments/list", s.owner)
	var names []string
	for _, item := range list {
		names = append(names, jsString(item.Get("name"))+":"+jsString(item.Get("childCount")))
	}
	expectList(t, "list", names, "Engineering:1", "Platform:0")
}

// tests/security-org.test.ts: syncManagers updates each person only where identities.update would be allowed.
func TestDepartmentsSyncManagersHonorsADenyProtectingOnePerson(t *testing.T) {
	f := newOrgFixture(t, nil)
	ada, head, carol, dave := f.member("ada"), f.member("head"), f.member("carol"), f.member("dave")
	grantRole := f.createRole(f.owner, "name", "Ada's grant", "permissions", []any{"iam:identities:update", "iam:departments:read"})
	f.bind(f.owner, grantRole.Get("id"), "identity", ada.Get("id"))
	protect := f.createRole(f.owner, "name", "Carol is protected", "document", parse(t, `{"version":1,"statements":[
		{"effect":"deny","actions":["iam:identities:update"],"resources":["iam/`+jsString(carol.Get("id"))+`"]}]}`))
	f.bind(f.owner, protect.Get("id"), "identity", ada.Get("id"))
	sales := f.deptObject("departments/create", f.owner, "name", "Sales", "headId", head.Get("id"))
	f.deptObject("departments/assign", f.owner, "departmentId", sales.Get("id"), "identityIds", []any{carol.Get("id"), dave.Get("id")})
	a := f.login("ada")
	_, err := f.deptCall("identities/update", a, "identityId", carol.Get("id"), "managerId", head.Get("id"))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	result := f.deptObject("departments/syncManagers", a)
	updated, _ := result.Get("updated").([]any)
	if len(updated) != 1 || member(updated[0], "identityId") != dave.Get("id") {
		t.Fatalf("updated %s", core.MustStringify(updated))
	}
	expectMember(t, result, "kept", `1`)
	if f.record("identities", jsString(carol.Get("id"))).Has("managerId") {
		t.Fatal("carol got a manager")
	}
	expectMember(t, f.record("identities", jsString(dave.Get("id"))), "managerId", core.MustStringify(head.Get("id")))
	// Without iam:departments:read the sync is refused.
	eve := f.member("eve")
	eveRole := f.createRole(f.owner, "name", "Eve's grant", "permissions", []any{"iam:identities:update"})
	f.bind(f.owner, eveRole.Get("id"), "identity", eve.Get("id"))
	_, err = f.deptCall("departments/syncManagers", f.login("eve"))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
}

// The transaction-level helpers configuration sync uses validate like the API.
func TestDepartmentMutationsValidateLikeTheAPI(t *testing.T) {
	s := newDeptScenario(t)
	mutations := must(DepartmentMutations(s.iam.Context))
	owner := s.ownerSignIn()
	err := s.store.Transaction(s.ctx, func(ctx context.Context, tx core.IamStore) error {
		principal, err := s.iam.Context.Principals.Authenticate(ctx, owner)
		if err != nil {
			return err
		}
		tenant, err := tx.Get(ctx, "tenants", s.tenantID)
		if err != nil {
			return err
		}
		_, err = mutations.CreateDepartment(ctx, tx, principal, tenant, core.NewObject("name", "  "))
		expectError(t, err, "INVALID_INPUT", "Invalid name")
		_, err = mutations.CreateDepartment(ctx, tx, principal, tenant, core.NewObject("name", "Ops", "code", "-x"))
		expectError(t, err, "INVALID_INPUT", "code must use 1-32 letters, digits, dots, underscores, or hyphens")
		_, err = mutations.UpdateDepartment(ctx, tx, principal, tenant, core.NewObject("departmentId", s.platform.Get("id")))
		expectError(t, err, "INVALID_INPUT", "Nothing to update")
		_, err = mutations.DepartmentPerson(ctx, tx, s.tenantID, "missing")
		if err == nil {
			t.Fatal("a missing person was accepted")
		}
		ops, err := mutations.CreateDepartment(ctx, tx, principal, tenant, core.NewObject("name", " Ops ", "description", "", "costCenter", nil))
		if err != nil {
			return err
		}
		expectJSONOf(t, "ops", ops.Get("name"), `"Ops"`)
		if ops.Has("description") || ops.Has("costCenter") || ops.Has("code") {
			t.Fatalf("empty optional members kept: %s", core.MustStringify(ops))
		}
		dave, err := tx.Get(ctx, "identities", jsString(s.dave.Get("id")))
		if err != nil {
			return err
		}
		placed, err := mutations.Place(ctx, tx, principal, ops, dave, "Lead")
		if err != nil || !placed {
			t.Fatalf("place %v %v", placed, err)
		}
		again, err := mutations.Place(ctx, tx, principal, ops, dave, "Lead")
		if err != nil || again {
			t.Fatalf("place again %v %v", again, err)
		}
		retitled, err := mutations.Place(ctx, tx, principal, ops, dave, "")
		if err != nil || !retitled {
			t.Fatalf("retitle %v %v", retitled, err)
		}
		_, err = mutations.DeleteDepartment(ctx, tx, principal, tenant, core.NewObject("departmentId", s.engineering.Get("id")))
		expectError(t, err, "RESOURCE_IN_USE", "Move or delete the departments below it first: Platform")
		removed, err := mutations.DeleteDepartment(ctx, tx, principal, tenant, core.NewObject("departmentId", ops.Get("id")))
		if err != nil {
			return err
		}
		expectJSONOf(t, "removed", removed, `{"unassigned":1,"teams":0}`)
		return nil
	})
	requirePorted(t, err)
}
