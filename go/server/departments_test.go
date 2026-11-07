package server

// Tests of departments.go, ported from tests/departments.test.ts (departmentOf, departmentPath, departmentHeads, the
// policy context, and the offboarding hand-over of heads) at the module level: the departments API belongs to another
// unit.

import (
	"context"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// departmentFixture adds Engineering (headed by alice) with Platform (headed by bob) below it to the org fixture.
func departmentFixture(t *testing.T) *teamOrgFixture {
	t.Helper()
	f := newTeamOrgFixture(t)
	f.insert(DepartmentCollections.Departments,
		core.NewObject("id", "engineering", "tenantId", "org", "uniqueKey", "name:engineering", "name", "Engineering", "code", "ENG", "headId", "alice", "createdAt", 1.0, "updatedAt", 1.0),
		core.NewObject("id", "platform-dept", "tenantId", "org", "uniqueKey", "name:platform", "name", "Platform", "parentId", "engineering", "headId", "bob", "createdAt", 1.0, "updatedAt", 1.0),
		core.NewObject("id", "sales", "tenantId", "org", "uniqueKey", "name:sales", "name", "Sales", "headId", "bob", "createdAt", 1.0, "updatedAt", 1.0),
		core.NewObject("id", "foreign", "tenantId", "project", "uniqueKey", "name:foreign", "name", "Foreign", "createdAt", 1.0, "updatedAt", 1.0),
	)
	f.place("alice", "engineering")
	f.place("bob", "platform-dept")
	f.place("carol", "platform-dept")
	return f
}

func (f *teamOrgFixture) place(identityID, departmentID string) {
	f.insert(DepartmentCollections.Members, core.NewObject("id", "dm-"+identityID, "tenantId", f.tenantID,
		"uniqueKey", "identity:"+identityID, "departmentId", departmentID, "identityId", identityID, "since", 1.0, "assignedBy", "owner"))
}

func TestDepartmentCode(t *testing.T) {
	for _, valid := range []string{"ENG", "FIN-AP", "a", "x.y_z-1", "A234567890123456789012345678901b"} {
		if got, err := DepartmentCode(valid); err != nil || got != valid {
			t.Fatalf("DepartmentCode(%q) = %q, %v", valid, got, err)
		}
	}
	for _, invalid := range []any{"", "-ENG", ".x", "A2345678901234567890123456789012c", "a b", "é", 1.0} {
		_, err := DepartmentCode(invalid)
		expectError(t, err, "INVALID_INPUT", "code must use 1-32 letters, digits, dots, underscores, or hyphens")
	}
}

func TestDepartmentHelpers(t *testing.T) {
	f := departmentFixture(t)
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		if department := must(DepartmentOf(ctx, tx, "org", "carol")); department != "platform-dept" {
			t.Fatalf("carol's department %q", department)
		}
		if department := must(DepartmentOf(ctx, tx, "org", "dave")); department != "" {
			t.Fatalf("dave's department %q", department)
		}
		expectTeamStrings(t, "path", must(DepartmentPath(ctx, tx, "org", "platform-dept")), "engineering", "platform-dept")
		expectTeamStrings(t, "path unknown", must(DepartmentPath(ctx, tx, "org", "missing")))
		expectTeamStrings(t, "path foreign", must(DepartmentPath(ctx, tx, "org", "foreign")))
		expectTeamStrings(t, "heads", must(DepartmentHeads(ctx, tx, "org", "platform-dept", nil)), "bob")
		expectTeamStrings(t, "heads above", must(DepartmentHeads(ctx, tx, "org", "platform-dept", core.NewObject("includeAncestors", true))), "bob", "alice")
		expectTeamStrings(t, "heads unknown", must(DepartmentHeads(ctx, tx, "org", "missing", core.NewObject("includeAncestors", true))))
		membership := must(DepartmentMembership(ctx, tx, "org", "carol"))
		expectObject(t, "membership", membership.Get("departmentId"), `"platform-dept"`)
		if must(DepartmentMembership(ctx, tx, "org", "dave")) != nil {
			t.Fatal("dave has a membership")
		}
		departments := must(TenantDepartments(ctx, tx, "org"))
		if len(departments) != 3 || departments["foreign"] != nil {
			t.Fatalf("tenant departments %d", len(departments))
		}
		expectTeamStrings(t, "chain", orgIDs(must(DepartmentChain(departments, "platform-dept"))), "platform-dept", "engineering")
		all := []*core.Object{departments["engineering"], departments["platform-dept"], departments["sales"]}
		expectTeamStrings(t, "descendants", orgIDs(must(DepartmentDescendants(all, "engineering"))), "platform-dept")

		expectObject(t, "context carol", must(DepartmentContext(ctx, tx, "org", "carol")),
			`{"principal.departmentId":"platform-dept","principal.departments":["engineering","platform-dept"]}`)
		expectObject(t, "context dave", must(DepartmentContext(ctx, tx, "org", "dave")), `{"principal.departments":[]}`)

		department := must(LoadDepartment(ctx, tx, "org", "sales"))
		expectObject(t, "loaded", department.Get("name"), `"Sales"`)
		_, err := LoadDepartment(ctx, tx, "org", "")
		expectError(t, err, "INVALID_INPUT", "Invalid departmentId")
		_, err = LoadDepartment(ctx, tx, "org", nil)
		expectError(t, err, "INVALID_INPUT", "Invalid departmentId")
		_, err = LoadDepartment(ctx, tx, "org", "foreign")
		expectError(t, err, "NOT_FOUND", "Department not found")
		if iamError(t, err).Status != 404 {
			t.Fatal("status")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// A placement in another tenant's department does not count.
	f.place("dave", "foreign")
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		if department := must(DepartmentOf(ctx, tx, "org", "dave")); department != "" {
			t.Fatalf("dave's department %q", department)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}

func TestReleaseDepartments(t *testing.T) {
	f := departmentFixture(t)
	f.advance(1_000)
	var released *core.Object
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		released, err = ReleaseDepartments(ctx, tx, "org", "bob", f.now(), "dave")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "released", released, `{"left":true,"headsReassigned":2,"headsCleared":0}`)
	platform := must(f.store.Get(f.ctx, DepartmentCollections.Departments, "platform-dept"))
	if orgString(platform, "headId") != "dave" || jsNumber(platform.Get("updatedAt")) != float64(f.now()) {
		t.Fatalf("platform %s", core.MustStringify(platform))
	}
	if len(must(f.store.Find(f.ctx, DepartmentCollections.Members, core.NewObject("tenantId", "org", "identityId", "bob"), nil))) != 0 {
		t.Fatal("bob is still placed")
	}

	// Without a successor the departments are left without a head.
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		released, err = ReleaseDepartments(ctx, tx, "org", "alice", f.now(), "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "released alice", released, `{"left":true,"headsReassigned":0,"headsCleared":1}`)
	engineering := must(f.store.Get(f.ctx, DepartmentCollections.Departments, "engineering"))
	if !isUndefined(engineering.Get("headId")) {
		t.Fatalf("engineering %s", core.MustStringify(engineering))
	}
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		released, err = ReleaseDepartments(ctx, tx, "org", "erin", f.now(), "")
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "released nobody", released, `{"left":false,"headsReassigned":0,"headsCleared":0}`)
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		if left := must(RemoveFromDepartment(ctx, tx, "org", "carol")); !left {
			t.Fatal("carol had a department")
		}
		if left := must(RemoveFromDepartment(ctx, tx, "org", "carol")); left {
			t.Fatal("carol still had a department")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
}
