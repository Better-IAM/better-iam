package server

// Tests of org_rules.go, ported from tests/org-birthright.test.ts (what identity.teams and identity.departments hold
// for a person, a synced membership counting only through a source group no package granted, and the packages that
// name a team or department) at the module level: the access package API belongs to another unit.

import (
	"context"
	"slices"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// orgSorted is a sorted copy (the store decides the order of what it finds).
func orgSorted(items []string) []string {
	copied := append([]string(nil), items...)
	slices.Sort(copied)
	return copied
}

func TestOrgFactsForRules(t *testing.T) {
	f := departmentFixture(t)
	// Alice: SRE by hand. Dave: Platform through team sync from Okta, which counts only while he is in Okta by a
	// membership no package created (the caller passes those memberships as directGroupIds).
	engineers := f.team("design", "Design", "")
	engineers.Set("syncGroupIds", []any{"g-okta"})
	f.insert(TeamCollections.Teams, engineers)
	f.member("sre", "alice", "member", 2)
	f.member("design", "dave", "member", 2, "source", "sync")
	f.member("design", "carol", "member", 2, "expiresAt", float64(f.now()))
	var facts *TenantOrgFacts
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		facts, err = LoadOrgFacts(ctx, tx, "org", f.now())
		return err
	})
	orgSkipOnStub(t, err)
	if err != nil {
		t.Fatal(err)
	}
	expectTeamStrings(t, "team IDs", orgSorted(facts.TeamIDs), "design", "platform", "sre")
	expectTeamStrings(t, "department IDs", orgSorted(facts.DepartmentIDs), "engineering", "platform-dept", "sales")
	of := func(identityID string, groups ...string) string {
		t.Helper()
		result, err := facts.Of(identityID, groups)
		orgSkipOnStub(t, err)
		if err != nil {
			t.Fatal(err)
		}
		return core.MustStringify(result)
	}
	if got := of("alice"); got != `{"teams":["platform","sre"],"departments":["engineering"],"licenses":[]}` {
		t.Fatalf("alice: %s", got)
	}
	if got := of("dave"); got != `{"teams":[],"departments":[],"licenses":[]}` {
		t.Fatalf("dave without the source group: %s", got)
	}
	if got := of("dave", "g-okta"); got != `{"teams":["design"],"departments":[],"licenses":[]}` {
		t.Fatalf("dave: %s", got)
	}
	// Carol's ended team membership does not count; her department and the one above it do.
	if got := of("carol"); got != `{"teams":[],"departments":["engineering","platform-dept"],"licenses":[]}` {
		t.Fatalf("carol: %s", got)
	}
}

func TestOrgRuleEnvironmentAndPackagesNaming(t *testing.T) {
	f := departmentFixture(t)
	rule := func(key string, values ...string) *core.Object {
		list := make([]any, len(values))
		for index, value := range values {
			list[index] = value
		}
		return core.NewObject("include", []any{core.NewObject(
			"StringEquals", core.NewObject("principal.kind", "user"),
			"ArrayContains", core.NewObject(key, list),
		)})
	}
	f.insert("accessPackages",
		core.NewObject("id", "pkg-1", "tenantId", "org", "name", "platform tools", "roleIds", []any{}, "groupIds", []any{}, "autoAssign", rule("identity.teams", "platform")),
		core.NewObject("id", "pkg-2", "tenantId", "org", "name", "Backing", "roleIds", []any{}, "groupIds", []any{}, "autoAssign", rule("identity.groups", "g-sre")),
		core.NewObject("id", "pkg-3", "tenantId", "org", "name", "Engineering basics", "roleIds", []any{}, "groupIds", []any{}, "autoAssign", rule("identity.departments", "engineering")),
		core.NewObject("id", "pkg-4", "tenantId", "org", "name", "Manual", "roleIds", []any{}, "groupIds", []any{}),
	)
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		environment, err := OrgRuleEnvironment(ctx, tx, "org")
		orgSkipOnStub(t, err)
		if err != nil {
			return err
		}
		expectObject(t, "environment", environment, `{"teams":["platform","sre"],"departments":["engineering","platform-dept","sales"],"licenses":[]}`)
		names, err := PackagesNaming(ctx, tx, "org", "identity.teams", []string{"platform", "sre"}, []string{"g-platform", "g-sre"})
		orgSkipOnStub(t, err)
		if err != nil {
			return err
		}
		expectTeamStrings(t, "teams", names, "Backing", "platform tools")
		expectTeamStrings(t, "departments", must(PackagesNaming(ctx, tx, "org", "identity.departments", []string{"engineering"}, nil)), "Engineering basics")
		expectTeamStrings(t, "nothing", must(PackagesNaming(ctx, tx, "org", "identity.departments", []string{"sales"}, nil)))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
