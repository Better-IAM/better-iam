package server

// Ports of tests/sod.test.ts (the `sod` API group and the separation-of-duties checks on every granting path) and
// the "separation of duties follows role inheritance" tests of tests/security-engine.test.ts, plus direct checks of
// sod.ts (sodViolations, sodSnapshot / sodVerify, sodAssertIdentity). A granting path that still reaches another
// unit's NOT_IMPLEMENTED stub is logged and passed over (nothing was granted); the rest of the test goes on.

import (
	"context"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// sodRefusedOrStub expects code; another unit's NOT_IMPLEMENTED stub is logged instead (the step granted nothing).
func sodRefusedOrStub(t *testing.T, err error, code string) {
	t.Helper()
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Logf("step blocked by another unit: %s", known.Message)
		return
	}
	expectCodeOrSkip(t, err, code)
}

func TestSodPreventsConflictingGrantsOnEveryGrantingPathAndReportsExistingConflicts(t *testing.T) {
	f := newOrgFixture(t, nil)
	owner := f.owner
	role := func(name string) *core.Object {
		return f.createRole(owner, "name", name, "permissions", []any{"documents:read"})
	}
	requester, approver, auditor := role("Payment requester"), role("Payment approver"), role("Auditor")
	bind := func(roleID, subjectID any, extra ...any) (any, error) {
		return f.deptCall("bindings/create", owner, append([]any{"roleId", roleID, "subjectType", "identity", "subjectId", subjectID}, extra...)...)
	}
	mustBind := func(roleID, subjectID any, subjectType string) {
		t.Helper()
		f.bind(owner, roleID, subjectType, subjectID)
	}
	alice, bob, carol := f.member("alice"), f.member("bob"), f.member("carol")
	mustBind(requester.Get("id"), alice.Get("id"), "identity")
	// Carol's conflict predates the rule.
	mustBind(requester.Get("id"), carol.Get("id"), "identity")
	mustBind(approver.Get("id"), carol.Get("id"), "identity")

	for _, input := range [][]any{
		{"name", "One role", "roleIds", []any{requester.Get("id")}},
		{"name", "Unknown", "roleIds", []any{requester.Get("id"), "missing"}},
		{"name", "Bad mode", "roleIds", []any{requester.Get("id"), approver.Get("id")}, "mode", "maybe"},
	} {
		_, err := f.deptCall("sod/create", owner, input...)
		if err == nil {
			t.Fatalf("accepted %v", input)
		}
		requirePortedFailure(t, err)
	}
	_, err := f.deptCall("sod/create", owner, "name", "One role", "roleIds", []any{requester.Get("id")})
	expectError(t, err, "INVALID_INPUT", "A rule names 2 to 20 conflicting roles")
	_, err = f.deptCall("sod/create", owner, "name", "Bad mode", "roleIds", []any{requester.Get("id"), approver.Get("id")}, "mode", "maybe")
	expectError(t, err, "INVALID_INPUT", "mode must be prevent or detect")
	_, err = f.deptCall("sod/create", owner, "roleIds", []any{requester.Get("id"), approver.Get("id")})
	expectError(t, err, "INVALID_INPUT", "name and roleIds are required")
	var ownerRole *core.Object
	for _, candidate := range f.find("roles", core.NewObject("tenantId", f.tenantID)) {
		if truthy(candidate.Get("protected")) {
			ownerRole = candidate
		}
	}
	_, err = f.deptCall("sod/create", owner, "name", "Owners", "roleIds", []any{ownerRole.Get("id"), auditor.Get("id")})
	expectError(t, err, "INVALID_INPUT", "Owner roles cannot be part of a rule")

	rule := f.deptObject("sod/create", owner, "name", "Payments", "roleIds", []any{requester.Get("id"), approver.Get("id")})
	expectMember(t, rule, "mode", `"prevent"`)
	expectMember(t, rule, "existingViolations", `1`)
	expectStrings(t, core.NewObject("keys", stringsOf(rule.Keys())).Get("keys"),
		"mode", "name", "roleIds", "id", "tenantId", "createdAt", "createdBy", "existingViolations")

	// Direct binding.
	_, err = bind(approver.Get("id"), alice.Get("id"))
	expectError(t, err, "SOD_CONFLICT", "Separation of duties (Payments): one person cannot hold Payment requester and Payment approver")
	if known := iamError(t, err); known.Status != 409 {
		t.Fatalf("status %d", known.Status)
	}
	if bindings := f.find("bindings", core.NewObject("tenantId", f.tenantID, "subjectId", alice.Get("id"))); len(bindings) != 1 {
		t.Fatalf("alice has %d bindings", len(bindings))
	}
	// A future-dated grant counts too: the conflict would begin when it starts.
	_, err = bind(approver.Get("id"), alice.Get("id"), "startsAt", f.now()+dayMs)
	expectCodeOrSkip(t, err, "SOD_CONFLICT")
	// Group membership that would confer the conflicting role.
	approvers := f.createGroup("Approvers")
	mustBind(approver.Get("id"), approvers.Get("id"), "group")
	_, err = f.addMember("groupId", approvers.Get("id"), "identityId", alice.Get("id"))
	sodRefusedOrStub(t, err, "SOD_CONFLICT")
	if _, err := f.addMember("groupId", approvers.Get("id"), "identityId", bob.Get("id")); err != nil {
		known, ok := asIamError(err)
		if !ok || known.Code != "NOT_IMPLEMENTED" {
			t.Fatal(err)
		}
		t.Logf("group membership blocked by another unit: %s", known.Message)
	}
	// Bulk onboarding.
	_, err = f.deptCall("identities/createMany", owner, "identities", []any{core.NewObject(
		"email", "dave@acme.test", "name", "Dave", "roleIds", []any{requester.Get("id")}, "groupIds", []any{approvers.Get("id")},
	)})
	sodRefusedOrStub(t, err, "SOD_CONFLICT")
	if found := f.find("identities", core.NewObject("email", "dave@acme.test")); len(found) != 0 {
		t.Fatal("dave was created")
	}
	// Invitation acceptance runs outside the operation envelope and is checked too.
	_, err = f.deptCall("identities/invite", owner, "email", "erin@acme.test", "roleIds", []any{requester.Get("id")}, "groupIds", []any{approvers.Get("id")})
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Logf("invitation blocked by another unit: %s", known.Message)
	} else {
		if err != nil {
			t.Fatal(err)
		}
		f.dispatch()
		invitations := f.messages(f.tenantID, "member-invitation")
		if len(invitations) == 0 {
			t.Fatal("no invitation was sent")
		}
		_, err = f.iam.Context.Flows.AcceptMemberInvitation(f.ctx, core.NewObject(
			"tenantId", f.tenantID, "token", invitations[len(invitations)-1].Payload["token"], "name", "Erin", "password", "a strong erin password"))
		sodRefusedOrStub(t, err, "SOD_CONFLICT")
		if found := f.find("identities", core.NewObject("email", "erin@acme.test")); len(found) != 0 {
			t.Fatal("erin was created")
		}
	}
	// Access packages materialize bindings too.
	kit, err := f.deptCall("packages/create", owner, "name", "Approver kit", "roleIds", []any{approver.Get("id")})
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Logf("access packages blocked by another unit: %s", known.Message)
	} else {
		if err != nil {
			t.Fatal(err)
		}
		_, err = f.deptCall("packages/assign", owner, "packageId", member(kit, "id"), "identityId", alice.Get("id"))
		sodRefusedOrStub(t, err, "SOD_CONFLICT")
		if assignments := f.find("packageAssignments", core.NewObject("tenantId", f.tenantID, "identityId", alice.Get("id"))); len(assignments) != 0 {
			t.Fatal("the package was assigned")
		}
	}

	// The pre-existing conflict never blocks unrelated grants, and it is reported.
	mustBind(auditor.Get("id"), carol.Get("id"), "identity")
	violations := f.deptList("sod/violations", owner)
	if len(violations) != 1 {
		t.Fatalf("violations %s", core.MustStringify(violations))
	}
	expectJSONOf(t, "violation", violations[0], `{"ruleId":`+core.MustStringify(rule.Get("id"))+`,"ruleName":"Payments","mode":"prevent","identityId":`+
		core.MustStringify(carol.Get("id"))+`,"roleIds":[`+core.MustStringify(requester.Get("id"))+`,`+core.MustStringify(approver.Get("id"))+
		`],"identityName":"carol@acme.test","roleNames":["Payment requester","Payment approver"]}`)
	report, err := f.deptCall("analysis/findings", owner)
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Logf("access analysis blocked by another unit: %s", known.Message)
	} else {
		if err != nil {
			t.Fatal(err)
		}
		findings, _ := member(report, "findings").([]any)
		var sod []any
		for _, finding := range findings {
			if member(finding, "kind") == "separation-of-duties" {
				sod = append(sod, finding)
			}
		}
		if len(sod) != 1 || member(sod[0], "severity") != "high" || member(member(sod[0], "subject"), "id") != carol.Get("id") {
			t.Fatalf("separation-of-duties findings %s", core.MustStringify(sod))
		}
	}
	// One rule's violations.
	if only := f.deptList("sod/violations", owner, "ruleId", "other"); len(only) != 0 {
		t.Fatalf("another rule's violations %s", core.MustStringify(only))
	}

	// Detect mode reports without blocking; switching modes and deleting take effect immediately.
	updated := f.deptObject("sod/update", owner, "ruleId", rule.Get("id"), "mode", "detect")
	expectMember(t, updated, "mode", `"detect"`)
	mustBind(approver.Get("id"), alice.Get("id"), "identity")
	var holders []string
	for _, violation := range f.deptList("sod/violations", owner) {
		holders = append(holders, jsString(violation.Get("identityId")))
	}
	sort.Strings(holders)
	want := []string{jsString(alice.Get("id")), jsString(carol.Get("id"))}
	sort.Strings(want)
	expectList(t, "holders", holders, want...)
	expectJSONOf(t, "deleted", f.deptObject("sod/delete", owner, "ruleId", rule.Get("id")), `{"deleted":true}`)
	if left := f.deptList("sod/violations", owner); len(left) != 0 {
		t.Fatalf("violations after delete %d", len(left))
	}
	if rules := f.deptList("sod/list", owner); len(rules) != 0 {
		t.Fatalf("rules after delete %d", len(rules))
	}
	_, err = f.deptCall("sod/delete", owner, "ruleId", rule.Get("id"))
	expectCodeOrSkip(t, err, "NOT_FOUND")
	_, err = f.deptCall("sod/update", owner, "ruleId", "")
	expectError(t, err, "INVALID_INPUT", "Invalid ruleId")
}

// requirePortedFailure fails the test unless err is a refusal of this unit (any IamError but NOT_IMPLEMENTED).
func requirePortedFailure(t *testing.T, err error) {
	t.Helper()
	if known := iamError(t, err); known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
}

func TestSodRequiresSodPermissions(t *testing.T) {
	f := newOrgFixture(t, nil)
	f.member("mallory")
	mallory := f.login("mallory")
	_, err := f.deptCall("sod/list", mallory)
	if known := iamError(t, err); known.Status != 403 {
		t.Fatalf("expected 403, got %d %s", known.Status, known.Code)
	}
	_, err = f.deptCall("sod/create", mallory, "name", "Payments", "roleIds", []any{"a", "b"})
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
	_, err = f.deptCall("sod/violations", mallory)
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
}

// sodPayments is tests/security-engine.test.ts payments(): alice holds Initiate; Payments makes Initiate and Approve
// conflict.
func sodPayments(t *testing.T) (*orgFixture, *core.Object, *core.Object, func(roleID any) error) {
	t.Helper()
	f := newOrgFixture(t, nil)
	alice := f.member("alice")
	initiate := f.createRole(f.owner, "name", "Initiate", "permissions", []any{"documents:write"})
	approve := f.createRole(f.owner, "name", "Approve", "permissions", []any{"documents:read"})
	f.deptObject("sod/create", f.owner, "name", "Payments", "roleIds", []any{initiate.Get("id"), approve.Get("id")})
	bind := func(roleID any) error {
		_, err := f.deptCall("bindings/create", f.owner, "roleId", roleID, "subjectType", "identity", "subjectId", alice.Get("id"))
		return err
	}
	if err := bind(initiate.Get("id")); err != nil {
		requirePorted(t, err)
	}
	return f, alice, approve, bind
}

func TestSodRefusesBindingARoleThatInheritsTheConflictingRole(t *testing.T) {
	f, _, approve, bind := sodPayments(t)
	lead := f.createRole(f.owner, "name", "Finance lead", "permissions", []any{"iam:roles:read"})
	if _, err := f.updateRole(f.owner, "roleId", lead.Get("id"), "inherits", []any{approve.Get("id")}); err != nil {
		requirePorted(t, err)
	}
	expectCodeOrSkip(t, bind(lead.Get("id")), "SOD_CONFLICT")
}

func TestSodRefusesMakingAHeldRoleInheritTheConflictingRole(t *testing.T) {
	f, _, approve, bind := sodPayments(t)
	helper := f.createRole(f.owner, "name", "Helper", "permissions", []any{"iam:groups:read"})
	if err := bind(helper.Get("id")); err != nil {
		requirePorted(t, err)
	}
	_, err := f.updateRole(f.owner, "roleId", helper.Get("id"), "inherits", []any{approve.Get("id")})
	expectCodeOrSkip(t, err, "SOD_CONFLICT")
}

func TestSodReportsConflictsHeldThroughInheritance(t *testing.T) {
	f, alice, approve, _ := sodPayments(t)
	lead := f.createRole(f.owner, "name", "Finance lead", "permissions", []any{"iam:roles:read"})
	if _, err := f.updateRole(f.owner, "roleId", lead.Get("id"), "inherits", []any{approve.Get("id")}); err != nil {
		requirePorted(t, err)
	}
	// Bound before the rule existed: a detect-only view must still see it.
	f.seed("bindings", core.NewObject("id", "legacy-binding", "tenantId", f.tenantID, "uniqueKey", "legacy-binding",
		"subjectType", "identity", "subjectId", alice.Get("id"), "roleId", lead.Get("id"), "authorityId", "none"))
	violations := f.deptList("sod/violations", f.owner)
	if len(violations) != 1 || violations[0].Get("identityId") != alice.Get("id") {
		t.Fatalf("violations %s", core.MustStringify(violations))
	}
}

// sod.ts directly: groups, inheritance, expired and future-dated bindings, lapsed memberships, deleted identities,
// the snapshot that ignores conflicts predating a rule, and sodAssertIdentity.
func TestSodViolationsSnapshotAndAssertIdentity(t *testing.T) {
	k := newKernel(t, nil)
	now := float64(k.server.Now())
	k.insert("roles",
		core.NewObject("id", "r-a", "tenantId", "t", "name", "A"),
		core.NewObject("id", "r-b", "tenantId", "t", "name", "B"),
		core.NewObject("id", "r-lead", "tenantId", "t", "name", "Lead", "inherits", []any{"r-b"}),
		core.NewObject("id", "r-chief", "tenantId", "t", "name", "Chief", "inherits", []any{"r-lead"}),
	)
	k.insert("identities",
		core.NewObject("id", "u1", "tenantId", "t", "status", "active"),
		core.NewObject("id", "u2", "tenantId", "t", "status", "active"),
		core.NewObject("id", "u3", "tenantId", "t", "status", "deleted"),
		core.NewObject("id", "u4", "tenantId", "t", "status", "active"),
		core.NewObject("id", "u5", "tenantId", "t", "status", "active"),
	)
	k.insert("groupMembers",
		core.NewObject("id", "g1:u2", "tenantId", "t", "groupId", "g1", "identityId", "u2"),
		core.NewObject("id", "g1:u4", "tenantId", "t", "groupId", "g1", "identityId", "u4", "expiresAt", now-1),
	)
	k.insert("bindings",
		// u1: A directly and B through Chief -> Lead -> B.
		core.NewObject("id", "b1", "tenantId", "t", "subjectType", "identity", "subjectId", "u1", "roleId", "r-a"),
		core.NewObject("id", "b2", "tenantId", "t", "subjectType", "identity", "subjectId", "u1", "roleId", "r-chief"),
		// u2: A directly, B through group g1.
		core.NewObject("id", "b3", "tenantId", "t", "subjectType", "identity", "subjectId", "u2", "roleId", "r-a"),
		core.NewObject("id", "b4", "tenantId", "t", "subjectType", "group", "subjectId", "g1", "roleId", "r-b"),
		// u3 is deleted.
		core.NewObject("id", "b5", "tenantId", "t", "subjectType", "identity", "subjectId", "u3", "roleId", "r-a"),
		core.NewObject("id", "b6", "tenantId", "t", "subjectType", "identity", "subjectId", "u3", "roleId", "r-b"),
		// u4: A directly, B only through a lapsed membership.
		core.NewObject("id", "b7", "tenantId", "t", "subjectType", "identity", "subjectId", "u4", "roleId", "r-a"),
		// u5: A directly, B expired, then B starting tomorrow (future-dated grants count).
		core.NewObject("id", "b8", "tenantId", "t", "subjectType", "identity", "subjectId", "u5", "roleId", "r-a"),
		core.NewObject("id", "b9", "tenantId", "t", "subjectType", "identity", "subjectId", "u5", "roleId", "r-b", "expiresAt", now-1),
	)
	rule := core.NewObject("id", "rule", "tenantId", "t", "name", "AB", "roleIds", []any{"r-b", "r-a"}, "mode", "prevent")
	err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		none, err := SodViolations(ctx, k.server, tx, "t", nil, nil)
		if err != nil {
			return err
		}
		if len(none) != 0 {
			t.Fatalf("violations without rules %d", len(none))
		}
		empty, err := SodViolations(ctx, k.server, tx, "t", []*core.Object{}, nil)
		if err != nil || len(empty) != 0 {
			t.Fatalf("an empty rule list %v %v", empty, err)
		}
		found, err := SodViolations(ctx, k.server, tx, "t", []*core.Object{rule}, nil)
		if err != nil {
			return err
		}
		expectJSONOf(t, "violations", objectsToList(found), `[
			{"ruleId":"rule","ruleName":"AB","mode":"prevent","identityId":"u1","roleIds":["r-b","r-a"]},
			{"ruleId":"rule","ruleName":"AB","mode":"prevent","identityId":"u2","roleIds":["r-b","r-a"]}]`)
		only, err := SodViolations(ctx, k.server, tx, "t", []*core.Object{rule}, []string{"u2", "u4"})
		if err != nil || len(only) != 1 || only[0].Get("identityId") != "u2" {
			t.Fatalf("limited to u2, u4: %v %v", only, err)
		}
		if _, err := tx.Insert(ctx, "bindings", core.NewObject("id", "b10", "tenantId", "t", "subjectType", "identity", "subjectId", "u5",
			"roleId", "r-b", "startsAt", now+dayMs)); err != nil {
			return err
		}
		future, err := SodViolations(ctx, k.server, tx, "t", []*core.Object{rule}, []string{"u5"})
		if err != nil || len(future) != 1 {
			t.Fatalf("future-dated grant: %v %v", future, err)
		}
		// No prevent rule, or an action that cannot grant: no snapshot.
		if snapshot, err := SodSnapshot(ctx, k.server, tx, "t", "iam:bindings:create"); err != nil || snapshot != nil {
			t.Fatalf("snapshot without rules %v %v", snapshot, err)
		}
		if _, err := tx.Insert(ctx, "sodRules", rule); err != nil {
			return err
		}
		if snapshot, err := SodSnapshot(ctx, k.server, tx, "t", "iam:roles:read"); err != nil || snapshot != nil {
			t.Fatalf("snapshot for a read %v %v", snapshot, err)
		}
		snapshot, err := SodSnapshot(ctx, k.server, tx, "t", "iam:bindings:create")
		if err != nil {
			return err
		}
		if len(snapshot.Rules) != 1 || !snapshot.Existing["rule:u1"] || !snapshot.Existing["rule:u5"] {
			t.Fatalf("snapshot %v", snapshot.Existing)
		}
		// Conflicts that existed before never block.
		if err := SodVerify(ctx, k.server, tx, "t", snapshot, nil); err != nil {
			t.Fatalf("existing conflicts blocked: %v", err)
		}
		if _, err := tx.Insert(ctx, "bindings", core.NewObject("id", "b11", "tenantId", "t", "subjectType", "identity", "subjectId", "u4", "roleId", "r-lead")); err != nil {
			return err
		}
		expectError(t, SodVerify(ctx, k.server, tx, "t", snapshot, []string{"u4"}), "SOD_CONFLICT", "Separation of duties (AB): one person cannot hold B and A")
		expectError(t, SodAssertIdentity(ctx, k.server, tx, "t", "u1"), "SOD_CONFLICT", "Separation of duties (AB): one person cannot hold B and A")
		if err := SodAssertIdentity(ctx, k.server, tx, "t", "u6"); err != nil {
			t.Fatalf("an identity without a conflict: %v", err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
