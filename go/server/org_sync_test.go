package server

// Configuration as code for teams and departments, after tests/config-org.test.ts: applying teams and departments
// from a document and exporting them back unchanged; membership, role, setting and structure updates with pruning;
// team sync by group name; temporary memberships left alone; dangling references and cycles refused at plan time.
// Steps that reach another unit's stub skip until that unit is ported.

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type orgSyncScenario struct {
	*configFixture
	people map[string]*core.Object
}

func newOrgSyncScenario(t *testing.T) *orgSyncScenario {
	t.Helper()
	f := newConfigFixture(t, nil)
	s := &orgSyncScenario{configFixture: f, people: map[string]*core.Object{}}
	for _, name := range []string{"alice", "bob", "carol", "dave"} {
		s.people[name] = f.member(name)
	}
	configCall(f, f.iam.API.Roles.Create, f.owner, "name", "Reader", "permissions", []any{"documents:read"})
	configCall(f, f.iam.API.Roles.Create, f.owner, "name", "Writer", "permissions", []any{"documents:write"})
	return s
}

const orgSyncBase = `{
  "version": 1,
  "departments": [
    { "name": "Engineering", "code": "ENG", "head": "alice@acme.test", "members": ["alice@acme.test"] },
    { "name": "Platform", "parent": "Engineering", "head": "bob@acme.test", "costCenter": "CC-7", "members": ["bob@acme.test", "carol@acme.test"] }
  ],
  "teams": [
    { "name": "Site Reliability", "slug": "sre", "parent": "platform", "members": ["carol@acme.test"] },
    { "name": "Platform", "slug": "platform", "department": "Platform", "joinPolicy": "request", "maintainers": ["bob@acme.test"], "members": ["alice@acme.test"], "roles": ["Reader"] }
  ]
}`

func (s *orgSyncScenario) teams() []*core.Object {
	s.t.Helper()
	return configObjects(s.t, configCall(s.configFixture, s.iam.API.Teams.List, s.owner))
}

func teamBySlug(teams []*core.Object, slug string) *core.Object {
	for _, team := range teams {
		if team.Get("slug") == slug {
			return team
		}
	}
	return nil
}

func TestConfigOrgAppliesTeamsAndDepartmentsAndExportsThemBack(t *testing.T) {
	s := newOrgSyncScenario(t)
	base := obj(t, orgSyncBase)
	plan := s.plan(s.owner, base, false)
	lines := []string{}
	for _, change := range configObjectsOf(plan.Get("changes")) {
		if kind := jsString(change.Get("kind")); kind == "team" || kind == "department" {
			lines = append(lines, kind+":"+jsString(change.Get("name"))+":"+jsString(change.Get("action")))
		}
	}
	configLines(t, "org changes", lines,
		"department:Engineering:create",
		"department:Platform:create",
		"team:platform:create",
		"team:sre:create",
	)
	s.apply(s.owner, base, false)

	teams := s.teams()
	platform, sre := teamBySlug(teams, "platform"), teamBySlug(teams, "sre")
	if platform == nil || sre == nil || sre.Get("parentId") != platform.Get("id") {
		t.Fatalf("teams = %s", stringify(teams))
	}
	if platform.Get("joinPolicy") != "request" || platform.Get("memberCount") != 2.0 || platform.Get("maintainerCount") != 1.0 {
		t.Fatalf("platform = %s", stringify(platform))
	}
	detail := teamsObject(t, configCall(s.configFixture, s.iam.API.Teams.Get, s.owner, "teamId", platform.Get("id")))
	if member(detail.Get("department"), "name") != "Platform" {
		t.Fatalf("detail department = %s", stringify(detail.Get("department")))
	}
	configLines(t, "team roles", pluck(configObjectsOf(detail.Get("roles")), "roleName"), "Reader")
	// Carol is in SRE, so she holds Reader through Platform.
	carol := s.login("carol")
	decision, err := s.iam.Authorize(s.ctx, AuthorizationRequest{
		Credential: carol, TenantID: s.tenantID, Action: "documents:read", Resource: ResourceTarget{Type: "documents", ID: "a"},
	})
	requirePorted(t, err)
	if !decision.Allowed {
		t.Fatalf("carol is denied: %s", decision.Reason)
	}
	tree := configObjects(t, configCall(s.configFixture, s.iam.API.Departments.Tree, s.owner))
	if tree[0].Get("name") != "Engineering" || member(tree[0].Get("head"), "name") != "alice" {
		t.Fatalf("tree root = %s", stringify(tree[0]))
	}
	child := configObjectsOf(tree[0].Get("children"))[0]
	if child.Get("name") != "Platform" || child.Get("costCenter") != "CC-7" || child.Get("memberCount") != 2.0 {
		t.Fatalf("tree child = %s", stringify(child))
	}

	exported := s.export(s.owner)
	configSameJSON(t, "exported platform", teamBySlug(configObjectsOf(exported.Get("teams")), "platform"), `{
      "name": "Platform", "slug": "platform", "department": "Platform", "joinPolicy": "request", "memberManagement": "maintainers",
      "maintainers": ["bob@acme.test"], "members": ["alice@acme.test"], "roles": ["Reader"]
    }`)
	configLines(t, "exported departments", pluck(configObjectsOf(exported.Get("departments")), "name"), "Engineering", "Platform")
	again := s.plan(s.owner, exported, true)
	if changes := configPending(again); len(changes) != 0 {
		t.Fatalf("export does not converge: %s", stringify(changes))
	}
}

func TestConfigOrgUpdatesAndPrunes(t *testing.T) {
	s := newOrgSyncScenario(t)
	s.apply(s.owner, obj(t, orgSyncBase), false)
	next := obj(t, `{
      "version": 1,
      "departments": [{ "name": "Engineering", "code": "ENG", "head": "alice@acme.test", "members": ["alice@acme.test"] }],
      "teams": [
        { "name": "Platform Engineering", "slug": "platform", "joinPolicy": "closed", "maintainers": ["alice@acme.test"], "members": ["bob@acme.test", "dave@acme.test"], "roles": ["Writer"] }
      ]
    }`)
	plan := s.plan(s.owner, next, true)
	platform := configChangeOf(plan, func(change *core.Object) bool {
		return change.Get("kind") == "team" && change.Get("name") == "platform"
	})
	if platform == nil || platform.Get("action") != "update" {
		t.Fatalf("platform change = %s", stringify(platform))
	}
	fields := syncStringList(platform.Get("fields"))
	for _, field := range []string{"department", "joinPolicy", "maintainers", "members", "name", "roles"} {
		if !containsString(fields, field) {
			t.Fatalf("platform fields %v lack %s", fields, field)
		}
	}
	deletes := []string{}
	for _, change := range configObjectsOf(plan.Get("changes")) {
		if change.Get("action") == "delete" {
			deletes = append(deletes, jsString(change.Get("kind"))+":"+jsString(change.Get("name")))
		}
	}
	configLines(t, "deletes", configSorted(deletes), "department:Platform", "team:sre")
	s.apply(s.owner, next, true)

	teams := s.teams()
	configLines(t, "teams", pluck(teams, "slug"), "platform")
	members := configObjects(t, configCall(s.configFixture, s.iam.API.Teams.ListMembers, s.owner, "teamId", teams[0].Get("id")))
	roles := []string{}
	for _, item := range members {
		roles = append(roles, jsString(item.Get("name"))+":"+jsString(item.Get("role")))
	}
	configLines(t, "members", configSorted(roles), "alice:maintainer", "bob:member", "dave:member")
	detail := teamsObject(t, configCall(s.configFixture, s.iam.API.Teams.Get, s.owner, "teamId", teams[0].Get("id")))
	if detail.Get("name") != "Platform Engineering" || detail.Get("joinPolicy") != "closed" || !isUndefined(detail.Get("department")) {
		t.Fatalf("detail = %s", stringify(detail))
	}
	configLines(t, "team roles", pluck(configObjectsOf(detail.Get("roles")), "roleName"), "Writer")
	departments := configObjects(t, configCall(s.configFixture, s.iam.API.Departments.List, s.owner))
	configLines(t, "departments", pluck(departments, "name"), "Engineering")
	// Bob and Carol lost their department with Platform.
	if placement := configCall(s.configFixture, s.iam.API.Departments.OfIdentity, s.owner, "identityId", s.people["bob"].Get("id")); placement != nil {
		t.Fatalf("bob's department = %s", stringify(placement))
	}
	converged := s.plan(s.owner, next, true)
	if changes := configPending(converged); len(changes) != 0 {
		t.Fatalf("does not converge: %s", stringify(changes))
	}
}

func TestConfigOrgConfiguresTeamSyncByGroupName(t *testing.T) {
	s := newOrgSyncScenario(t)
	document := obj(t, `{
      "version": 1,
      "groups": [{ "name": "Okta: Engineers", "members": ["carol@acme.test", "dave@acme.test"] }],
      "teams": [{ "name": "Engineers", "slug": "engineers", "syncGroups": ["Okta: Engineers"], "maintainers": ["alice@acme.test"] }]
    }`)
	s.apply(s.owner, document, false)
	team := s.teams()[0]
	listMembers := func() []*core.Object {
		return configObjects(t, configCall(s.configFixture, s.iam.API.Teams.ListMembers, s.owner, "teamId", team.Get("id")))
	}
	sources := []string{}
	for _, item := range listMembers() {
		source := "manual"
		if value, ok := item.Get("source").(string); ok {
			source = value
		}
		sources = append(sources, jsString(item.Get("name"))+":"+source)
	}
	configLines(t, "members", configSorted(sources), "alice:manual", "carol:sync", "dave:sync")
	exported := s.export(s.owner)
	exportedTeams := configObjectsOf(exported.Get("teams"))
	if len(exportedTeams) != 1 || exportedTeams[0].Get("slug") != "engineers" {
		t.Fatalf("exported teams = %s", stringify(exportedTeams))
	}
	configSameJSON(t, "syncGroups", exportedTeams[0].Get("syncGroups"), `["Okta: Engineers"]`)
	configSameJSON(t, "maintainers", exportedTeams[0].Get("maintainers"), `["alice@acme.test"]`)
	configSameJSON(t, "members", exportedTeams[0].Get("members"), `[]`)
	converged := s.plan(s.owner, exported, true)
	if changes := configPending(converged); len(changes) != 0 {
		t.Fatalf("does not converge: %s", stringify(changes))
	}
	// Dropping the source stops syncing: the synced members go, the manual maintainer stays.
	s.apply(s.owner, obj(t, `{"version":1,"teams":[{"name":"Engineers","slug":"engineers","syncGroups":[],"maintainers":["alice@acme.test"]}]}`), false)
	configLines(t, "members after", pluck(listMembers(), "name"), "alice")
	known := s.planFails(s.owner, obj(t, `{"version":1,"teams":[{"name":"X","slug":"x","syncGroups":["Nope"]}]}`), false)
	if !strings.Contains(known.Message, "unknown sync group") {
		t.Fatalf("expected an unknown sync group, got %s", known.Message)
	}
}

func TestConfigOrgLeavesTemporaryMembershipsAloneAndRejectsDanglingReferences(t *testing.T) {
	s := newOrgSyncScenario(t)
	base := obj(t, orgSyncBase)
	s.apply(s.owner, base, false)
	team := teamBySlug(s.teams(), "platform")
	configCall(s.configFixture, s.iam.API.Teams.AddMember, s.owner, "teamId", team.Get("id"), "identityId", s.people["dave"].Get("id"),
		"expiresAt", float64(s.clock.Load())+86_400_000)
	if changes := configPending(s.plan(s.owner, base, false)); len(changes) != 0 {
		t.Fatalf("a temporary member shows as drift: %s", stringify(changes))
	}
	s.apply(s.owner, base, false)
	members := configObjects(t, configCall(s.configFixture, s.iam.API.Teams.ListMembers, s.owner, "teamId", team.Get("id")))
	if !containsString(pluck(members, "name"), "dave") {
		t.Fatalf("the temporary member was removed: %s", stringify(members))
	}
	for patch, message := range map[string]string{
		`{"members":["nobody@acme.test"]}`:                              "unknown person",
		`{"roles":["Missing"]}`:                                         "unknown role",
		`{"parent":"ghost"}`:                                            "unknown parent",
		`{"department":"Nowhere"}`:                                      "unknown department",
		`{"maintainers":["bob@acme.test"],"members":["bob@acme.test"]}`: "both maintainer and member",
	} {
		broken := core.NewObject("version", 1, "teams", []any{core.NewObject("name", "Data", "slug", "data").Assign(obj(t, patch))})
		if known := s.planFails(s.owner, broken, false); !strings.Contains(known.Message, message) {
			t.Fatalf("%s: expected %q, got %s", patch, message, known.Message)
		}
	}
	cycle := obj(t, `{"version":1,"teams":[{"name":"A","slug":"a","parent":"b"},{"name":"B","slug":"b","parent":"a"}]}`)
	if known := s.planFails(s.owner, cycle, false); !strings.Contains(known.Message, "cycle") {
		t.Fatalf("expected a cycle, got %s", known.Message)
	}
}

func TestOrgRuleEnvironmentAfterAndCanonical(t *testing.T) {
	state := &OrgState{
		Teams:       []*core.Object{core.NewObject("id", "t1", "slug", "platform"), core.NewObject("id", "t2", "slug", "old")},
		Departments: []*core.Object{core.NewObject("id", "d1", "name", "Engineering")},
	}
	desired := obj(t, `{"version":1,"teams":[{"slug":"platform"},{"slug":"new"}],"departments":[{"name":"Sales"}]}`)
	after, err := OrgRuleEnvironmentAfter(desired, state, true)
	if err != nil {
		t.Fatal(err)
	}
	teams, _ := after.Env.Get("teams").(*orderedSet)
	configLines(t, "teams after prune", teams.Values(), "platform", "new")
	departments, _ := after.Env.Get("departments").(orgDepartmentNames)
	if departments.Has("engineering") || !departments.Has(" SALES ") {
		t.Fatalf("departments after prune = %v", departments)
	}
	kept, err := OrgRuleEnvironmentAfter(desired, state, false)
	if err != nil {
		t.Fatal(err)
	}
	if !kept.Env.Get("departments").(orgDepartmentNames).Has("ENGINEERING") {
		t.Fatal("without prune, the tenant's departments stay")
	}
	names, err := OrgRuleNames(state, obj(t, `{"include":[{"ArrayContains":{"identity.teams":"t1","identity.departments":["d1","dx"]}}]}`))
	requirePorted(t, err)
	configSameJSON(t, "names", names, `{"include":[{"ArrayContains":{"identity.teams":"platform","identity.departments":["Engineering","dx"]}}]}`)
	canonical, err := kept.Canonical(obj(t, `{"include":[{"ArrayContains":{"identity.departments":["engineering","sales"]}}]}`))
	requirePorted(t, err)
	configSameJSON(t, "canonical", canonical, `{"include":[{"ArrayContains":{"identity.departments":["Engineering","Sales"]}}]}`)
}
