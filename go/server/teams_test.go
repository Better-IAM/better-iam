package server

// Tests of teams.go, ported from tests/teams.test.ts (the helpers other modules use: teamsOf, primaryTeamOf,
// teamMaintainers, isTeamMaintainer; the backing-group sync behind nested teams, temporary memberships, offboarding
// and team sync) at the module level: the teams API itself belongs to another unit.

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// orgFixture is an organization ("org") with people alice, bob, carol and dave, and the teams Platform (bob maintains
// it) with Site Reliability (`sre`) below it, each with its team-managed backing group.
type orgFixture struct {
	*kernel
	tenantID string
}

func newOrgFixture(t *testing.T) *orgFixture {
	t.Helper()
	f := &orgFixture{kernel: newKernel(t, nil), tenantID: "org"}
	f.tenantTree()
	f.insert("identities",
		identity("alice", "org", "email", "alice@acme.test"),
		identity("bob", "org", "email", "bob@acme.test"),
		identity("carol", "org", "email", "carol@acme.test"),
		identity("dave", "org", "email", "dave@acme.test"),
	)
	f.insert("groups",
		core.NewObject("id", "g-platform", "tenantId", "org", "uniqueKey", "team:platform", "name", "team:platform", "teamId", "platform", "createdAt", 1.0),
		core.NewObject("id", "g-sre", "tenantId", "org", "uniqueKey", "team:sre", "name", "team:sre", "teamId", "sre", "createdAt", 1.0),
	)
	f.insert(TeamCollections.Teams,
		f.team("platform", "Platform", ""),
		f.team("sre", "Site Reliability", "platform"),
	)
	f.member("platform", "bob", "maintainer", 1)
	return f
}

func (f *orgFixture) now() int64 { return f.server.Now() }

// team is a team record with its backing group `g-{id}`.
func (f *orgFixture) team(id, name, parentID string) *core.Object {
	record := core.NewObject("id", id, "tenantId", f.tenantID, "uniqueKey", "slug:"+id, "name", name, "slug", id)
	if parentID != "" {
		record.Set("parentId", parentID)
	}
	record.Assign(core.NewObject("groupId", "g-"+id, "joinPolicy", "closed", "memberManagement", "maintainers",
		"createdAt", 1.0, "createdBy", "owner", "updatedAt", 1.0))
	return record
}

// member inserts a direct team membership; extra holds further members (expiresAt, source).
func (f *orgFixture) member(teamID, identityID, role string, addedAt float64, extra ...any) *core.Object {
	record := core.NewObject("id", "tm-"+teamID+"-"+identityID, "tenantId", f.tenantID, "uniqueKey", teamID+":"+identityID,
		"teamId", teamID, "identityId", identityID, "role", role, "addedAt", addedAt, "addedBy", "owner")
	for index := 0; index+1 < len(extra); index += 2 {
		record.Set(extra[index].(string), extra[index+1])
	}
	f.insert(TeamCollections.Members, record)
	return record
}

// sync runs syncTeamGroups in a transaction.
func (f *orgFixture) sync(teamIDs ...string) *core.Object {
	f.t.Helper()
	var result *core.Object
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		result, err = SyncTeamGroups(ctx, tx, f.tenantID, teamIDs, f.now())
		return err
	})
	if err != nil {
		f.t.Fatal(err)
	}
	return result
}

// groupMembers lists `identityId[:expiresAt]` of a group's memberships, sorted.
func (f *orgFixture) groupMembers(groupID string) []string {
	f.t.Helper()
	records := must(f.store.Find(f.ctx, "groupMembers", core.NewObject("tenantId", f.tenantID, "groupId", groupID), nil))
	out := []string{}
	for _, record := range records {
		entry := orgString(record, "identityId")
		if expiresAt := record.Get("expiresAt"); !isUndefined(expiresAt) {
			entry += ":" + core.NumberString(jsNumber(expiresAt))
		}
		out = append(out, entry)
	}
	slices.Sort(out)
	return out
}

func expectStrings(t *testing.T, label string, got []string, want ...string) {
	t.Helper()
	if got == nil {
		got = []string{}
	}
	if want == nil {
		want = []string{}
	}
	if !slices.Equal(got, want) {
		t.Fatalf("%s: got %q, want %q", label, got, want)
	}
}

func expectObject(t *testing.T, label string, got any, want string) {
	t.Helper()
	text, _, err := core.Stringify(got)
	if err != nil {
		t.Fatal(err)
	}
	if text != want {
		t.Fatalf("%s:\n got  %s\n want %s", label, text, want)
	}
}

// orgSkipOnStub skips the rest of a test that reached another unit's stub.
func orgSkipOnStub(t *testing.T, err error) {
	t.Helper()
	var known *core.IamError
	if errors.As(err, &known) && known.Code == "NOT_IMPLEMENTED" && !orgOwnStub(known.Message) {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
}

func orgOwnStub(message string) bool {
	for _, own := range []string{"teams.ts", "team-reviews.ts", "departments.ts", "org-rules.ts", "org-insights.ts"} {
		if strings.Contains(message, own) {
			return true
		}
	}
	return false
}

func TestTeamSlugs(t *testing.T) {
	for _, valid := range []string{"a", "sre", "platform-team", "a1-b2", strings.Repeat("a", 64)} {
		if got, err := TeamSlug(valid); err != nil || got != valid {
			t.Fatalf("TeamSlug(%q) = %q, %v", valid, got, err)
		}
	}
	for _, invalid := range []any{"", "-a", "a-", "Platform", "a_b", strings.Repeat("a", 65), 3.0, nil} {
		_, err := TeamSlug(invalid)
		expectError(t, err, "INVALID_INPUT", "slug must use 1-64 lowercase letters, digits, or inner hyphens")
	}
	cases := map[string]string{
		"Platform Team":                "platform-team",
		"  Site   Reliability!! ":      "site-reliability",
		"Café Ünïcode":                 "cafe-unicode",
		"***":                          "",
		"日本":                           "",
		strings.Repeat("ab ", 30):      strings.TrimRight(strings.Repeat("ab-", 30)[:64], "-"),
		"Ops & On-call / Tier 2":       "ops-on-call-tier-2",
		"ﬁnance":                       "finance",
		strings.Repeat("x", 63) + " y": strings.Repeat("x", 63),
	}
	for name, want := range cases {
		if got := must(SlugFromName(name)); got != want {
			t.Fatalf("SlugFromName(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestTeamChainAndDescendants(t *testing.T) {
	teams := []*core.Object{
		core.NewObject("id", "a"),
		core.NewObject("id", "b", "parentId", "a"),
		core.NewObject("id", "c", "parentId", "b"),
		core.NewObject("id", "d", "parentId", "a"),
		core.NewObject("id", "x", "parentId", "missing"),
		core.NewObject("id", "loop1", "parentId", "loop2"),
		core.NewObject("id", "loop2", "parentId", "loop1"),
	}
	byID, _ := orgByID(teams)
	expectStrings(t, "chain c", orgIDs(must(TeamChain(byID, "c"))), "c", "b", "a")
	expectStrings(t, "chain x", orgIDs(must(TeamChain(byID, "x"))), "x")
	expectStrings(t, "chain loop", orgIDs(must(TeamChain(byID, "loop1"))), "loop1", "loop2")
	expectStrings(t, "chain unknown", orgIDs(must(TeamChain(byID, "nope"))))
	expectStrings(t, "descendants a", orgIDs(must(TeamDescendants(teams, "a"))), "b", "d", "c")
	expectStrings(t, "descendants c", orgIDs(must(TeamDescendants(teams, "c"))))
	expectStrings(t, "descendants loop", orgIDs(must(TeamDescendants(teams, "loop1"))), "loop2")

	// The chain stops after the team and ten levels above it.
	deep := []*core.Object{core.NewObject("id", "t0")}
	for level := 1; level <= 15; level++ {
		deep = append(deep, core.NewObject("id", "t"+core.NumberString(float64(level)), "parentId", "t"+core.NumberString(float64(level-1))))
	}
	deepByID, _ := orgByID(deep)
	if got := len(must(TeamChain(deepByID, "t15"))); got != MaxTeamDepth+1 {
		t.Fatalf("deep chain length %d", got)
	}
}

func TestTeamHelpersFollowNesting(t *testing.T) {
	f := newOrgFixture(t)
	f.member("sre", "alice", "member", 2)
	f.sync("sre")
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		expectStrings(t, "teamsOf", must(TeamsOf(ctx, tx, "org", "alice", nil)), "sre")
		expectStrings(t, "teamsOf ancestors", must(TeamsOf(ctx, tx, "org", "alice", core.NewObject("includeAncestors", true))), "sre", "platform")
		if team := must(PrimaryTeamOf(ctx, tx, "org", "alice", nil)); team != "sre" {
			t.Fatalf("primary team %q", team)
		}
		if team := must(PrimaryTeamOf(ctx, tx, "org", "carol", nil)); team != "" {
			t.Fatalf("carol's primary team %q", team)
		}
		expectStrings(t, "maintainers", must(TeamMaintainers(ctx, tx, "org", "platform", f.now())), "bob")
		if must(IsTeamMaintainer(ctx, tx, "org", "sre", "bob", nil)) {
			t.Fatal("bob maintains sre directly")
		}
		if !must(IsTeamMaintainer(ctx, tx, "org", "sre", "bob", core.NewObject("includeAncestors", true))) {
			t.Fatal("bob does not maintain sre through platform")
		}
		if must(IsTeamMaintainer(ctx, tx, "org", "sre", "alice", core.NewObject("includeAncestors", true))) {
			t.Fatal("alice maintains sre")
		}
		expectObject(t, "team context", must(TeamContext(ctx, tx, "org", "alice", f.now())), `{"principal.teams":["platform","sre"]}`)
		expectObject(t, "team context carol", must(TeamContext(ctx, tx, "org", "carol", f.now())), `{"principal.teams":[]}`)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Alice belongs to Platform's backing group through SRE, Bob directly.
	expectStrings(t, "platform group", f.groupMembers("g-platform"), "alice", "bob")
	expectStrings(t, "sre group", f.groupMembers("g-sre"), "alice")
	memberships := must(f.store.Find(f.ctx, "groupMembers", core.NewObject("tenantId", "org", "groupId", "g-platform", "identityId", "alice"), nil))
	expectObject(t, "membership", memberships[0].Get("teamId"), `"platform"`)
	expectObject(t, "uniqueKey", memberships[0].Get("uniqueKey"), `"g-platform:alice"`)
}

func TestTeamsOfOrdersAndFiltersMemberships(t *testing.T) {
	f := newOrgFixture(t)
	f.insert(TeamCollections.Teams, f.team("design", "Design", ""))
	f.member("design", "alice", "member", 5)
	f.member("sre", "alice", "maintainer", 5)
	f.member("platform", "alice", "member", 9, "expiresAt", float64(f.now()-1))
	// A membership of a team that no longer exists is not reported.
	f.insert(TeamCollections.Members, core.NewObject("id", "tm-gone", "tenantId", "org", "uniqueKey", "gone:alice",
		"teamId", "gone", "identityId", "alice", "role", "member", "addedAt", 1.0, "addedBy", "owner"))
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		expectStrings(t, "teamsOf", must(TeamsOf(ctx, tx, "org", "alice", nil)), "design", "sre")
		at := f.now() - 10
		expectStrings(t, "teamsOf earlier", must(TeamsOf(ctx, tx, "org", "alice", core.NewObject("at", at))), "design", "sre", "platform")
		expectStrings(t, "maintainers sre", must(TeamMaintainers(ctx, tx, "org", "sre", f.now())), "alice")
		if !must(IsTeamMaintainer(ctx, tx, "org", "sre", "alice", nil)) {
			t.Fatal("alice maintains sre")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	live, _ := LiveTeamMember(core.NewObject("expiresAt", 10.0), 9)
	ended, _ := LiveTeamMember(core.NewObject("expiresAt", 10.0), 10)
	permanent, _ := LiveTeamMember(core.NewObject(), 1e15)
	if !live || ended || !permanent {
		t.Fatalf("liveTeamMember: %v %v %v", live, ended, permanent)
	}
}

func TestLoadTeam(t *testing.T) {
	f := newOrgFixture(t)
	f.insert(TeamCollections.Teams, core.NewObject("id", "other-team", "tenantId", "project", "name", "Other", "slug", "other", "groupId", "g-other"))
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		team := must(LoadTeam(ctx, tx, "org", "sre"))
		expectObject(t, "team", team.Get("parentId"), `"platform"`)
		_, err := LoadTeam(ctx, tx, "org", "")
		expectError(t, err, "INVALID_INPUT", "Invalid teamId")
		_, err = LoadTeam(ctx, tx, "org", 3.0)
		expectError(t, err, "INVALID_INPUT", "Invalid teamId")
		_, err = LoadTeam(ctx, tx, "org", "missing")
		expectError(t, err, "NOT_FOUND", "Team not found")
		_, err = LoadTeam(ctx, tx, "org", "other-team")
		expectError(t, err, "NOT_FOUND", "Team not found")
		if iamError(t, err).Status != 404 {
			t.Fatalf("status %d", iamError(t, err).Status)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestSyncTeamGroupsMergesEndsAndCleansUp(t *testing.T) {
	f := newOrgFixture(t)
	now := float64(f.now())
	// Alice: temporary in SRE, permanent in Platform: permanent wins on Platform's group.
	f.member("sre", "alice", "member", 2, "expiresAt", now+3_600_000)
	f.member("platform", "alice", "member", 3)
	// Carol: two temporary memberships: the later end counts.
	f.insert(TeamCollections.Teams, f.team("dba", "DBA", "platform"))
	f.insert("groups", core.NewObject("id", "g-dba", "tenantId", "org", "name", "team:dba", "teamId", "dba"))
	f.member("sre", "carol", "member", 2, "expiresAt", now+1_000)
	f.member("dba", "carol", "member", 2, "expiresAt", now+5_000)
	// Dave is deleted: left out.
	f.insert("identities", identity("erin", "org", "status", "deleted"))
	f.member("sre", "erin", "member", 2)
	result := f.sync("sre", "dba")
	expectObject(t, "result", result, `{"added":6,"removed":0,"updated":0}`)
	expectStrings(t, "platform group", f.groupMembers("g-platform"), "alice", "bob", "carol:"+core.NumberString(now+5_000))
	expectStrings(t, "sre group", f.groupMembers("g-sre"), "alice:"+core.NumberString(now+3_600_000), "carol:"+core.NumberString(now+1_000))
	expectStrings(t, "dba group", f.groupMembers("g-dba"), "carol:"+core.NumberString(now+5_000))
	// Idempotent.
	expectObject(t, "again", f.sync("sre", "dba"), `{"added":0,"removed":0,"updated":0}`)

	// A stale membership record (written by a package, without the team) is rewritten; a membership nobody holds goes,
	// with the person's activations of the group's eligible bindings.
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		records := must(tx.Find(ctx, "groupMembers", core.NewObject("tenantId", "org", "groupId", "g-sre", "identityId", "alice"), nil))
		stale := records[0].Clone()
		stale.Delete("teamId")
		stale.Set("packageAssignmentId", "pa-1")
		if _, err := tx.Put(ctx, "groupMembers", stale); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "bindings", core.NewObject("id", "b-sre", "tenantId", "org", "roleId", "r", "subjectType", "group", "subjectId", "g-sre", "eligible", true)); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "bindings", core.NewObject("id", "b-other", "tenantId", "org", "roleId", "r", "subjectType", "group", "subjectId", "g-platform", "eligible", true)); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "bindingActivations", core.NewObject("id", "act-1", "tenantId", "org", "uniqueKey", "b-sre:carol", "bindingId", "b-sre", "identityId", "carol", "expiresAt", now+100)); err != nil {
			return err
		}
		if _, err := tx.Insert(ctx, "bindingActivations", core.NewObject("id", "act-2", "tenantId", "org", "uniqueKey", "b-other:carol", "bindingId", "b-other", "identityId", "carol", "expiresAt", now+100)); err != nil {
			return err
		}
		return tx.Delete(ctx, TeamCollections.Members, "tm-sre-carol")
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "repair", f.sync("sre"), `{"added":0,"removed":1,"updated":1}`)
	repaired := must(f.store.Find(f.ctx, "groupMembers", core.NewObject("tenantId", "org", "groupId", "g-sre", "identityId", "alice"), nil))[0]
	if !isUndefined(repaired.Get("packageAssignmentId")) || orgString(repaired, "teamId") != "sre" || jsNumber(repaired.Get("expiresAt")) != now+3_600_000 {
		t.Fatalf("repaired membership %s", core.MustStringify(repaired))
	}
	activations := must(f.store.Find(f.ctx, "bindingActivations", core.NewObject("tenantId", "org", "identityId", "carol"), nil))
	expectStrings(t, "activations", orgIDs(activations), "act-2")
	expectStrings(t, "sre group after", f.groupMembers("g-sre"), "alice:"+core.NumberString(now+3_600_000))
	// Carol still reaches Platform through DBA.
	expectStrings(t, "platform group after", f.groupMembers("g-platform"), "alice", "bob", "carol:"+core.NumberString(now+5_000))

	// Ended memberships leave the backing groups when the sync next runs.
	f.advance(3_600_000)
	expectObject(t, "lapsed", f.sync("sre", "dba"), `{"added":0,"removed":3,"updated":0}`)
	expectStrings(t, "platform group lapsed", f.groupMembers("g-platform"), "alice", "bob")
	expectStrings(t, "sre group lapsed", f.groupMembers("g-sre"))
	// Unknown teams change nothing.
	expectObject(t, "unknown", f.sync("nope"), `{"added":0,"removed":0,"updated":0}`)
}

func TestRemoveFromAllTeams(t *testing.T) {
	f := newOrgFixture(t)
	f.member("sre", "alice", "member", 2)
	f.member("platform", "alice", "maintainer", 3)
	f.sync("sre")
	f.insert(TeamCollections.Requests,
		core.NewObject("id", "req-1", "tenantId", "org", "teamId", "platform", "identityId", "alice", "status", "pending", "requestedAt", 1.0, "expiresAt", 9e15),
		core.NewObject("id", "req-2", "tenantId", "org", "teamId", "platform", "identityId", "alice", "status", "denied", "requestedAt", 1.0, "expiresAt", 9e15),
	)
	// A stray backing-group membership written before a repair also goes; ordinary groups stay.
	f.insert("groups", core.NewObject("id", "g-plain", "tenantId", "org", "name", "Plain"))
	f.insert("groupMembers",
		core.NewObject("id", "gm-stray", "tenantId", "org", "uniqueKey", "g-old:alice", "groupId", "g-old", "identityId", "alice", "teamId", "old"),
		core.NewObject("id", "gm-plain", "tenantId", "org", "uniqueKey", "g-plain:alice", "groupId", "g-plain", "identityId", "alice"),
	)
	var removed float64
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		removed, err = RemoveFromAllTeams(ctx, tx, "org", "alice", f.now())
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if removed != 2 {
		t.Fatalf("removed %v", removed)
	}
	expectStrings(t, "memberships", orgIDs(must(f.store.Find(f.ctx, "groupMembers", core.NewObject("tenantId", "org", "identityId", "alice"), nil))), "gm-plain")
	expectStrings(t, "platform group", f.groupMembers("g-platform"), "bob")
	request := must(f.store.Get(f.ctx, TeamCollections.Requests, "req-1"))
	if orgString(request, "status") != "cancelled" || jsNumber(request.Get("decidedAt")) != float64(f.now()) {
		t.Fatalf("request %s", core.MustStringify(request))
	}
	if orgString(must(f.store.Get(f.ctx, TeamCollections.Requests, "req-2")), "status") != "denied" {
		t.Fatal("a decided request changed")
	}
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		removed, err = RemoveFromAllTeams(ctx, tx, "org", "alice", f.now())
		return err
	}); err != nil || removed != 0 {
		t.Fatalf("second removal %v %v", removed, err)
	}
}

func TestTeamGroupGuards(t *testing.T) {
	f := newOrgFixture(t)
	f.insert("groups",
		core.NewObject("id", "g-plain", "tenantId", "org", "name", "Okta: Engineers"),
		core.NewObject("id", "g-foreign", "tenantId", "project", "name", "Elsewhere"),
	)
	if err := AssertNotTeamGroup(nil); err != nil {
		t.Fatal(err)
	}
	if err := AssertNotTeamGroup(core.NewObject("id", "g", "teamId", nil)); err != nil {
		t.Fatal(err)
	}
	err := AssertNotTeamGroup(core.NewObject("id", "g", "teamId", "t"))
	expectError(t, err, "TEAM_MANAGED", "This group belongs to a team; manage its members with the teams API")
	if iamError(t, err).Status != 409 {
		t.Fatal("status")
	}
	if team, _ := IsTeamGroup(core.NewObject("teamId", "t")); !team {
		t.Fatal("IsTeamGroup")
	}
	if team, _ := IsTeamGroup(nil); team {
		t.Fatal("IsTeamGroup nil")
	}
	err = f.tx(func(ctx context.Context, tx core.IamStore) error {
		if err := AssertNoTeamGroups(ctx, tx, []string{"g-plain", "missing"}); err != nil {
			t.Fatal(err)
		}
		expectError(t, AssertNoTeamGroups(ctx, tx, []string{"g-plain", "g-sre"}), "TEAM_MANAGED", "This group belongs to a team; manage its members with the teams API")

		ids := must(TeamSyncGroups(ctx, tx, "org", []any{"g-plain", "g-plain"}))
		expectStrings(t, "sync groups", ids, "g-plain")
		_, err := TeamSyncGroups(ctx, tx, "org", "g-plain")
		expectError(t, err, "INVALID_INPUT", "syncGroupIds must list at most 10 groups")
		eleven := make([]any, 11)
		for index := range eleven {
			eleven[index] = "g-plain"
		}
		_, err = TeamSyncGroups(ctx, tx, "org", eleven)
		expectError(t, err, "INVALID_INPUT", "syncGroupIds must list at most 10 groups")
		_, err = TeamSyncGroups(ctx, tx, "org", []any{"g-foreign"})
		expectError(t, err, "NOT_FOUND", "Group g-foreign not found")
		_, err = TeamSyncGroups(ctx, tx, "org", []any{"g-platform"})
		expectError(t, err, "INVALID_INPUT", "A team cannot sync from another team’s backing group")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestTeamChainBindingsAndRoleDenies(t *testing.T) {
	f := newOrgFixture(t)
	f.insert("bindings",
		core.NewObject("id", "b-platform", "tenantId", "org", "roleId", "reader", "subjectType", "group", "subjectId", "g-platform"),
		core.NewObject("id", "b-sre", "tenantId", "org", "roleId", "writer", "subjectType", "group", "subjectId", "g-sre"),
		core.NewObject("id", "b-person", "tenantId", "org", "roleId", "writer", "subjectType", "identity", "subjectId", "alice"),
	)
	f.insert("policies", core.NewObject("id", "p-deny", "tenantId", "org", "name", "Deny", "document",
		obj(t, `{"version":"2025-01-01","statements":[{"effect":"deny","actions":["*"],"resources":["*"]}]}`)))
	f.insert("roles",
		core.NewObject("id", "reader", "tenantId", "org", "name", "Reader", "document", obj(t, `{"version":"2025-01-01","statements":[{"effect":"allow","actions":["documents:read"],"resources":["*"]}]}`)),
		core.NewObject("id", "fenced", "tenantId", "org", "name", "Fenced", "policyIds", []any{"p-deny"}),
		core.NewObject("id", "child", "tenantId", "org", "name", "Child", "inherits", []any{"reader", "fenced"}),
		core.NewObject("id", "loop", "tenantId", "org", "name", "Loop", "inherits", []any{"loop", "reader"}),
	)
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		expectStrings(t, "sre bindings", orgIDs(must(TeamChainBindings(ctx, tx, "org", []string{"sre"}))), "b-sre", "b-platform")
		expectStrings(t, "platform bindings", orgIDs(must(TeamChainBindings(ctx, tx, "org", []string{"platform", "platform"}))), "b-platform")
		expectStrings(t, "unknown", orgIDs(must(TeamChainBindings(ctx, tx, "org", []string{"nope"}))))
		for role, want := range map[string]bool{"reader": false, "fenced": true, "child": true, "loop": false, "missing": false} {
			if got := must(RoleHoldsDeny(ctx, tx, role)); got != want {
				t.Fatalf("RoleHoldsDeny(%s) = %v", role, got)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestMentionedOrgKeys(t *testing.T) {
	teams := obj(t, `{"statements":[{"effect":"allow","actions":["a"],"resources":["*"],"conditions":{"ArrayContains":{"principal.teams":["t"]}}}]}`)
	departments := obj(t, `{"statements":[{"effect":"allow","actions":["a"],"resources":["*"],"conditions":{"StringEquals":{"resource.departmentId":"${principal.departmentId}"}}}]}`)
	plain := obj(t, `{"statements":[{"effect":"allow","actions":["a"],"resources":["*"]}]}`)
	if got := MentionedOrgKeys([]any{plain}); got.Teams || got.Departments {
		t.Fatalf("plain: %+v", got)
	}
	if got := MentionedOrgKeys([]any{teams}); !got.Teams || got.Departments {
		t.Fatalf("teams: %+v", got)
	}
	if got := MentionedOrgKeys([]any{plain, departments, teams}); !got.Teams || !got.Departments {
		t.Fatalf("both: %+v", got)
	}
}

func TestTeamsSyncingFrom(t *testing.T) {
	f := newOrgFixture(t)
	engineers := f.team("engineers", "Engineers", "")
	engineers.Set("syncGroupIds", []any{"g-okta", "g-other"})
	f.insert(TeamCollections.Teams, engineers)
	err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		expectStrings(t, "okta", orgIDs(must(TeamsSyncingFrom(ctx, tx, "org", "g-okta"))), "engineers")
		expectStrings(t, "none", orgIDs(must(TeamsSyncingFrom(ctx, tx, "org", "g-none"))))
		// Without synced teams and without a source group, the run changes nothing (and reconciles nothing).
		result := must(SyncTeamsFromGroups(ctx, f.server, tx, "org", core.NewObject("teamIds", []any{}, "actorId", "owner")))
		expectObject(t, "nothing", result, `{"added":0,"removed":0,"updated":0,"teams":[]}`)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// TestTeamSyncFollowsSourceGroups is "keeps a team in step with its source groups (team sync)" at the module level.
func TestTeamSyncFollowsSourceGroups(t *testing.T) {
	f := newOrgFixture(t)
	now := float64(f.now())
	f.insert("groups", core.NewObject("id", "g-okta", "tenantId", "org", "name", "Okta: Engineers"))
	f.insert("groupMembers",
		core.NewObject("id", "gm-alice", "tenantId", "org", "uniqueKey", "g-okta:alice", "groupId", "g-okta", "identityId", "alice"),
		core.NewObject("id", "gm-bob", "tenantId", "org", "uniqueKey", "g-okta:bob", "groupId", "g-okta", "identityId", "bob"),
	)
	engineers := f.team("engineers", "Engineers", "")
	engineers.Set("syncGroupIds", []any{"g-okta"})
	f.insert(TeamCollections.Teams, engineers)
	f.insert("groups", core.NewObject("id", "g-engineers", "tenantId", "org", "name", "team:engineers", "teamId", "engineers"))
	run := func(options *core.Object) *core.Object {
		t.Helper()
		var result *core.Object
		err := f.tx(func(ctx context.Context, tx core.IamStore) error {
			var err error
			result, err = SyncTeamsFromGroups(ctx, f.server, tx, "org", options)
			return err
		})
		orgSkipOnStub(t, err)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	members := func() []string {
		records := must(f.store.Find(f.ctx, TeamCollections.Members, core.NewObject("tenantId", "org", "teamId", "engineers"), nil))
		out := []string{}
		for _, record := range records {
			source := "manual"
			if text := orgString(record, "source"); text != "" {
				source = text
			}
			out = append(out, orgString(record, "identityId")+":"+source)
		}
		slices.Sort(out)
		return out
	}
	expectObject(t, "first run", run(core.NewObject("actorId", "owner")), `{"added":2,"removed":0,"updated":0,"teams":["engineers"]}`)
	expectStrings(t, "members", members(), "alice:sync", "bob:sync")
	expectStrings(t, "backing group", f.groupMembers("g-engineers"), "alice", "bob")

	// Group changes flow into the team; manual members stay.
	f.member("engineers", "carol", "member", now)
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		if err := tx.Delete(ctx, "groupMembers", "gm-alice"); err != nil {
			return err
		}
		_, err := tx.Insert(ctx, "groupMembers", core.NewObject("id", "gm-carol", "tenantId", "org", "uniqueKey", "g-okta:carol", "groupId", "g-okta", "identityId", "carol", "expiresAt", now+86_400_000))
		if err != nil {
			return err
		}
		// A temporary source membership makes a temporary synced membership.
		_, err = tx.Insert(ctx, "groupMembers", core.NewObject("id", "gm-dave", "tenantId", "org", "uniqueKey", "g-okta:dave", "groupId", "g-okta", "identityId", "dave", "expiresAt", now+3_600_000))
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "second run", run(core.NewObject("groupId", "g-okta", "actorId", "directory-sync")), `{"added":1,"removed":1,"updated":0,"teams":["engineers"]}`)
	expectStrings(t, "members after", members(), "bob:sync", "carol:manual", "dave:sync")
	records := must(f.store.Find(f.ctx, TeamCollections.Members, core.NewObject("tenantId", "org", "uniqueKey", "engineers:dave"), nil))
	expectObject(t, "dave", records[0].Get("expiresAt"), core.NumberString(now+3_600_000))
	events := must(f.store.Find(f.ctx, "audit", core.NewObject("tenantId", "org", "action", "team:member:remove"), nil))
	if len(events) != 1 || orgString(events[0], "actorId") != "directory-sync" {
		t.Fatalf("remove events %s", core.MustStringify(events))
	}
	expectObject(t, "remove metadata", events[0].Get("metadata"), `{"team":"engineers","source":"sync","identityId":"alice"}`)
	added := must(f.store.Find(f.ctx, "audit", core.NewObject("tenantId", "org", "action", "team:member:add", "resourceId", "engineers"), nil))
	var daveEvent *core.Object
	for _, event := range added {
		if orgString(event.Get("metadata").(*core.Object), "identityId") == "dave" {
			daveEvent = event
		}
	}
	expectObject(t, "add metadata", daveEvent.Get("metadata"), `{"team":"engineers","source":"sync","identityId":"dave","role":"member","expiresAt":`+core.NumberString(now+3_600_000)+`}`)

	// Turning sync off removes the synced members and keeps the manual ones.
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		team := must(tx.Get(ctx, TeamCollections.Teams, "engineers"))
		team.Delete("syncGroupIds")
		_, err := tx.Put(ctx, TeamCollections.Teams, team)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "sync off", run(core.NewObject("teamIds", []any{"engineers"}, "actorId", "owner")), `{"added":0,"removed":2,"updated":0,"teams":["engineers"]}`)
	expectStrings(t, "members off", members(), "carol:manual")
	expectStrings(t, "backing group off", f.groupMembers("g-engineers"), "carol")
}
