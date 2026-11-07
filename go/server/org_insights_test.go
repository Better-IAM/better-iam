package server

// Tests of org_insights.go, ported from "suggests birthright packages from the access most of a department or team
// already holds" in tests/org-birthright.test.ts, at the module level (records instead of the API calls of other units).

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestBirthrightOptions(t *testing.T) {
	expectObject(t, "defaults", must(BirthrightOptions(core.NewObject())), `{"minShare":0.8,"minPeople":3}`)
	expectObject(t, "given", must(BirthrightOptions(core.NewObject("minShare", 0.5, "minPeople", 2.0))), `{"minShare":0.5,"minPeople":2}`)
	expectObject(t, "null", must(BirthrightOptions(core.NewObject("minShare", nil, "minPeople", nil))), `{"minShare":0.8,"minPeople":3}`)
	for _, share := range []any{0.2, 1.01, "0.9", true} {
		_, err := BirthrightOptions(core.NewObject("minShare", share))
		expectError(t, err, "INVALID_INPUT", "minShare must be between 0.5 and 1")
	}
	for _, people := range []any{1.0, 2.5, 100_001.0, "3"} {
		_, err := BirthrightOptions(core.NewObject("minPeople", people))
		if iamError(t, err).Code != "INVALID_INPUT" || !strings.Contains(iamError(t, err).Message, "minPeople") {
			t.Fatalf("minPeople %v: %v", people, err)
		}
	}
}

// birthrightFixture: Engineering (Dave directly) with Platform below it (Alice, Bob, Carol); everyone reads by hand,
// Alice and Bob write by hand, Alice, Bob and Carol edit the wiki.
func birthrightFixture(t *testing.T) *teamOrgFixture {
	t.Helper()
	f := newTeamOrgFixture(t)
	f.insert(DepartmentCollections.Departments,
		core.NewObject("id", "engineering", "tenantId", "org", "uniqueKey", "name:engineering", "name", "Engineering", "createdAt", 1.0, "updatedAt", 1.0),
		core.NewObject("id", "platform-dept", "tenantId", "org", "uniqueKey", "name:platform", "name", "Platform", "parentId", "engineering", "createdAt", 1.0, "updatedAt", 1.0),
	)
	for _, person := range []string{"alice", "bob", "carol"} {
		f.place(person, "platform-dept")
	}
	f.place("dave", "engineering")
	f.insert("roles",
		core.NewObject("id", "reader", "tenantId", "org", "name", "Reader", "permissions", []any{"iam:resources:read"}),
		core.NewObject("id", "writer", "tenantId", "org", "name", "Writer", "permissions", []any{"iam:resources:read"}),
	)
	for _, person := range []string{"alice", "bob", "carol", "dave"} {
		f.insert("bindings", core.NewObject("id", "b-reader-"+person, "tenantId", "org", "roleId", "reader", "subjectType", "identity", "subjectId", person, "createdAt", 1.0))
	}
	for _, person := range []string{"alice", "bob"} {
		f.insert("bindings", core.NewObject("id", "b-writer-"+person, "tenantId", "org", "roleId", "writer", "subjectType", "identity", "subjectId", person, "createdAt", 1.0))
	}
	f.insert("groups", core.NewObject("id", "wiki", "tenantId", "org", "name", "Wiki editors"))
	for _, person := range []string{"alice", "bob", "carol"} {
		f.insert("groupMembers", core.NewObject("id", "gm-wiki-"+person, "tenantId", "org", "uniqueKey", "wiki:"+person, "groupId", "wiki", "identityId", person))
	}
	return f
}

func (f *teamOrgFixture) suggest(kind string, options *core.Object) []*core.Object {
	f.t.Helper()
	var result []*core.Object
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		result, err = SuggestBirthright(ctx, f.server, tx, "org", kind, options)
		return err
	})
	orgSkipOnStub(f.t, err)
	if err != nil {
		f.t.Fatal(err)
	}
	return result
}

// birthrightSummary is `{ unit, people, roles, groups (name share), wouldGrant }` of each suggestion.
func birthrightSummary(suggestions []*core.Object) string {
	parts := []string{}
	for _, item := range suggestions {
		names := func(key string, withShare bool) string {
			list := []string{}
			for _, entry := range item.Get(key).([]any) {
				text := orgString(entry.(*core.Object), "name")
				if withShare {
					text += " " + core.NumberString(jsNumber(entry.(*core.Object).Get("share")))
				}
				list = append(list, text)
			}
			return "[" + strings.Join(list, ",") + "]"
		}
		parts = append(parts, orgString(item.Get("unit").(*core.Object), "name")+" people="+core.NumberString(jsNumber(item.Get("people")))+
			" roles="+names("roles", false)+" groups="+names("groups", true)+" wouldGrant="+core.NumberString(jsNumber(item.Get("wouldGrant"))))
	}
	return strings.Join(parts, "; ")
}

func TestSuggestBirthright(t *testing.T) {
	f := birthrightFixture(t)
	defaults := func(extra ...any) *core.Object {
		options := core.NewObject("minShare", 0.8, "minPeople", 3.0)
		for index := 0; index+1 < len(extra); index += 2 {
			options.Set(extra[index].(string), extra[index+1])
		}
		return options
	}
	suggestions := f.suggest("department", defaults())
	// Everyone in Engineering (with Platform) reads; Platform adds only what Engineering does not.
	if got := birthrightSummary(suggestions); got != "Engineering people=4 roles=[Reader] groups=[] wouldGrant=0; Platform people=3 roles=[] groups=[Wiki editors 1] wouldGrant=0" {
		t.Fatalf("suggestions: %s", got)
	}
	engineering := suggestions[0]
	expectObject(t, "package", engineering.Get("package"), `{"name":"Engineering department basics",`+
		`"description":"Birthright access for everyone in the Engineering department and the departments below it.",`+
		`"roleIds":["reader"],"groupIds":[],"autoAssign":{"include":[{"StringEquals":{"principal.kind":"user"},"ArrayContains":{"identity.departments":["engineering"]}}]}}`)
	expectObject(t, "unit", engineering.Get("unit"), `{"kind":"department","id":"engineering","name":"Engineering"}`)
	expectObject(t, "existing", engineering.Get("existingPackages"), `[]`)

	lower := f.suggest("department", defaults("unitId", "platform-dept", "minShare", 0.6))
	if len(lower) != 1 {
		t.Fatalf("lower: %s", birthrightSummary(lower))
	}
	expectObject(t, "lower roles", lower[0].Get("roles"), `[{"id":"writer","name":"Writer","holders":2,"share":0.67}]`)
	expectObject(t, "lower wouldGrant", lower[0].Get("wouldGrant"), `1`)

	// The suggested package exists (and has assigned Reader automatically): its contents are covered afterwards.
	pkg := engineering.Get("package").(*core.Object).Clone()
	pkg.Assign(core.NewObject("id", "pkg-engineering", "tenantId", "org"))
	f.insert("accessPackages", pkg)
	for _, person := range []string{"alice", "bob", "carol", "dave"} {
		f.insert("packageAssignments", core.NewObject("id", "pa-"+person, "tenantId", "org", "packageId", "pkg-engineering", "identityId", person, "ruleRevision", 1.0))
		f.insert("bindings", core.NewObject("id", "b-auto-"+person, "tenantId", "org", "roleId", "reader", "subjectType", "identity", "subjectId", person, "packageAssignmentId", "pa-"+person, "createdAt", 1.0))
	}
	after := f.suggest("department", defaults())
	if got := birthrightSummary(after); got != "Platform people=3 roles=[] groups=[Wiki editors 1] wouldGrant=0" {
		t.Fatalf("after: %s", got)
	}
	expectObject(t, "existing after", after[0].Get("existingPackages"), `["Engineering department basics"]`)

	// Teams: Platform with SRE below it. SRE's members also count for Platform above it, so the suggestion goes to
	// Platform and SRE does not repeat it.
	for _, person := range []string{"alice", "bob", "carol"} {
		f.member("sre", person, "member", 2)
	}
	f.sync("sre")
	teams := f.suggest("team", defaults())
	if got := birthrightSummary(teams); got != "Platform people=3 roles=[] groups=[Wiki editors 1] wouldGrant=0" {
		t.Fatalf("teams: %s", got)
	}
	if got := f.suggest("team", defaults("unitId", "sre")); len(got) != 0 {
		t.Fatalf("sre: %s", birthrightSummary(got))
	}
	team := teams[0]
	// The Reader role now comes from the package, so only hand-granted access counts.
	expectObject(t, "team roles", team.Get("roles"), `[]`)
	expectObject(t, "team rule", member(team.Get("package"), "autoAssign"), `{"include":[{"StringEquals":{"principal.kind":"user"},"ArrayContains":{"identity.teams":["platform"]}}]}`)
	expectObject(t, "team package name", member(team.Get("package"), "name"), `"Platform team basics"`)
}
