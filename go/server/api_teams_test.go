package server

// Teams API tests, after tests/teams.test.ts and tests/team-reviews.test.ts: nested teams with backing groups,
// maintainers managing membership without an administrator permission, members reading their own team, cycles and
// depth, moves, join requests end to end, leaving, and membership reviews. People, roles and groups are seeded in the
// store (bindingsFixture); the teams themselves go through the teams API. Steps that reach another unit's stub
// (teams.ts, api/groups.ts, package automation, ...) skip until that unit is ported.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

type teamsFixture struct {
	*bindingsFixture
	t *testing.T
}

func newTeamsFixture(t *testing.T) *teamsFixture {
	t.Helper()
	return &teamsFixture{bindingsFixture: newBindingsFixture(t), t: t}
}

// teamsCall invokes an API method with a body for the fixture's tenant and skips the test when it reaches another
// unit's stub.
func teamsCall[I, O any](f *teamsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, members ...any) (any, error) {
	f.t.Helper()
	out, err := method(context.Background(), credential, Input[I](f.body(members...)))
	if err != nil {
		skipUnported(f.t, err)
		return nil, err
	}
	return out.Value, nil
}

// mustTeams is teamsCall that fails the test on an error.
func mustTeams[I, O any](f *teamsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, members ...any) any {
	f.t.Helper()
	value, err := teamsCall(f, method, credential, members...)
	if err != nil {
		f.t.Fatalf("unexpected error: %v", err)
	}
	return value
}

func teamsExpectCode(t *testing.T, err error, code string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got success", code)
	}
	known := iamError(t, err)
	if known.Code != code {
		t.Fatalf("expected %s, got %s: %s", code, known.Code, known.Message)
	}
}

func teamsObject(t *testing.T, value any) *core.Object {
	t.Helper()
	object, ok := value.(*core.Object)
	if !ok {
		t.Fatalf("expected an object, got %T", value)
	}
	return object
}

func teamsList(t *testing.T, value any) []any {
	t.Helper()
	list, ok := value.([]any)
	if !ok {
		t.Fatalf("expected a list, got %T", value)
	}
	return list
}

func teamsJSON(t *testing.T, value any) string {
	t.Helper()
	text, _, err := core.Stringify(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func teamsExpectJSON(t *testing.T, value any, want string) {
	t.Helper()
	if got := teamsJSON(t, value); got != want {
		t.Fatalf("got %s\nwant %s", got, want)
	}
}

// pluck is `items.map((item) => item[key])` as strings (a dotted key reads nested members).
func teamsPluck(items []any, key string) []string {
	out := make([]string, len(items))
	for index, item := range items {
		value := item
		for _, part := range strings.Split(key, ".") {
			value = member(value, part)
		}
		out[index] = jsString(value)
	}
	return out
}

func teamsExpectStrings(t *testing.T, got []string, want ...string) {
	t.Helper()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("got %v, want %v", got, want)
	}
}

type teamsScenario struct {
	*teamsFixture
	alice, bob, carol    string
	aliceC, bobC, carolC core.CredentialInput
	platform, sre        *core.Object
}

// teamsScenarioOf is tests/teams.test.ts scenario(): Platform (bob maintains) with SRE below it, and the Reader and
// Writer roles.
func teamsScenarioOf(t *testing.T) *teamsScenario {
	f := newTeamsFixture(t)
	s := &teamsScenario{teamsFixture: f}
	s.alice, s.aliceC = f.member("alice@acme.test", "alice")
	s.bob, s.bobC = f.member("bob@acme.test", "bob")
	s.carol, s.carolC = f.member("carol@acme.test", "carol")
	f.role("reader", "Reader", "documents:read")
	f.role("writer", "Writer", "documents:write")
	teams := f.iam.API.Teams
	s.platform = teamsObject(t, mustTeams(f, teams.Create, f.owner, "name", "Platform", "description", "Runs the platform", "maintainerIds", []any{s.bob}))
	s.sre = teamsObject(t, mustTeams(f, teams.Create, f.owner, "name", "Site Reliability", "slug", "sre", "parentId", s.platform.Get("id")))
	return s
}

// bindGroup binds a seeded role to a team's backing group under the root authority.
func (s *teamsScenario) bindGroup(roleID string, team *core.Object) {
	s.seed("bindings", core.NewObject("id", "binding-"+roleID+"-"+jsString(team.Get("id")), "tenantId", s.tenantID, "subjectType", "group",
		"subjectId", team.Get("groupId"), "roleId", roleID, "authorityId", s.authority))
}

func (s *teamsScenario) canDo(credential core.CredentialInput, action string) bool {
	s.t.Helper()
	return s.authorize(credential.Token, action, "documents", "a").Allowed
}

func TestTeamsValidateBeforeReading(t *testing.T) {
	f := newTeamsFixture(t)
	teams := f.iam.API.Teams
	ctx := context.Background()
	_, err := teams.Get(ctx, f.owner, Input[apitypes.TeamsGetInput](f.body("teamId", 5.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid teamId")
	_, err = teams.ListReviews(ctx, f.owner, Input[apitypes.TeamsListReviewsInput](f.body("status", "bogus")))
	expectError(t, err, "INVALID_INPUT", "status must be one of open, completed, cancelled")
	_, err = teams.GetReview(ctx, f.owner, Input[apitypes.TeamsGetReviewInput](f.body()))
	expectError(t, err, "INVALID_INPUT", "Invalid reviewId")
	_, err = teams.ApproveRequest(ctx, f.owner, Input[apitypes.TeamsApproveRequestInput](f.body()))
	expectError(t, err, "INVALID_INPUT", "Invalid requestId")
	_, err = teams.ListMine(ctx, f.owner, Input[apitypes.TeamsListMineInput](core.NewObject()))
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
	_, err = teams.DenyRequest(ctx, f.owner, Input[apitypes.TeamsDenyRequestInput](f.body("requestId", "missing", "note", strings.Repeat("x", 1001))))
	expectError(t, err, "INVALID_INPUT", "Invalid note")
}

func TestTeamsSelfServiceNeedsOwnSession(t *testing.T) {
	f := newTeamsFixture(t)
	teams := f.iam.API.Teams
	ctx := context.Background()
	mine, err := teams.ListMine(ctx, f.owner, Input[apitypes.TeamsListMineInput](f.body()))
	if err != nil {
		t.Fatal(err)
	}
	teamsExpectJSON(t, mine.Value, `{"reviews":[],"teams":[],"requests":[],"joinable":[]}`)
	_, alice := f.member("alice@acme.test", "alice")
	_, err = teams.ListMine(ctx, alice, Input[apitypes.TeamsListMineInput](core.NewObject("tenantId", "elsewhere")))
	expectError(t, err, "ACCESS_DENIED", "Teams are joined and left from a person’s own session in their organization")
	_, err = teams.Leave(ctx, alice, Input[apitypes.TeamsLeaveInput](core.NewObject("tenantId", "elsewhere", "teamId", "x")))
	expectError(t, err, "ACCESS_DENIED", "Teams are joined and left from a person’s own session in their organization")
}

func TestTeamsHelpers(t *testing.T) {
	if _, err := teamChoice("open", teamJoinPolicies, "joinPolicy"); err == nil {
		t.Fatal("expected a refusal")
	} else {
		expectError(t, err, "INVALID_INPUT", "joinPolicy must be one of closed, request")
	}
	teamsExpectJSON(t, teamPersonOf(core.NewObject("id", "i", "name", "N", "email", "", "status", "active")), `{"id":"i","name":"N","status":"active"}`)
	teamsExpectJSON(t, teamUnknownPerson("gone"), `{"id":"gone","name":"gone","status":"deleted"}`)
	chain := []*core.Object{core.NewObject("id", "c"), core.NewObject("id", "b"), core.NewObject("id", "a")}
	teamsExpectStrings(t, teamIDs(reversedTail(chain)), "a", "b")
	summary := teamSummary(core.NewObject("id", "t", "tenantId", "x", "uniqueKey", "slug:t", "name", "T", "createdBy", "me", "updatedAt", 1.0),
		[]*core.Object{core.NewObject("role", "maintainer"), core.NewObject("role", "member")},
		[]*core.Object{core.NewObject("id", "u", "parentId", "t")})
	teamsExpectJSON(t, summary, `{"id":"t","tenantId":"x","name":"T","updatedAt":1,"memberCount":2,"maintainerCount":1,"childCount":1}`)
	own := &Principal{
		Identity: core.NewObject("id", "p", "tenantId", "org", "kind", "user"),
		Session:  core.NewObject("kind", "user", "tenantId", "org"),
	}
	if !ownUserSession(own, "org") || ownUserSession(own, "other") {
		t.Fatal("ownUserSession")
	}
	viewing := &Principal{Identity: own.Identity, Session: core.NewObject("kind", "user", "tenantId", "org", "impersonatorId", "admin")}
	expectError(t, requireOwnSession(viewing, "org"), "IMPERSONATION_RESTRICTED", "Teams cannot be joined or left while impersonating")
}

func TestTeamsCreatesNestedTeamsWithBackingGroups(t *testing.T) {
	s := teamsScenarioOf(t)
	teams := s.iam.API.Teams
	for key, want := range map[string]any{"name": "Platform", "slug": "platform", "joinPolicy": "closed", "memberManagement": "maintainers", "memberCount": 1.0, "maintainerCount": 1.0} {
		if got := s.platform.Get(key); got != want {
			t.Fatalf("platform.%s = %v, want %v", key, got, want)
		}
	}
	teamsExpectJSON(t, s.platform.Get("path"), `[]`)
	teamsExpectStrings(t, teamsPluck(teamsList(t, s.platform.Get("maintainers")), "id"), s.bob)
	if s.sre.Get("slug") != "sre" || s.sre.Get("parentId") != s.platform.Get("id") {
		t.Fatalf("sre: %s", teamsJSON(t, s.sre))
	}
	teamsExpectStrings(t, teamsPluck(teamsList(t, s.sre.Get("path")), "slug"), "platform")
	group, err := s.iam.Store.Get(context.Background(), "groups", jsString(s.platform.Get("groupId")))
	if err != nil || group == nil {
		t.Fatalf("backing group: %v", err)
	}
	if group.Get("name") != "team:platform" || group.Get("teamId") != s.platform.Get("id") {
		t.Fatalf("backing group: %s", teamsJSON(t, group))
	}
	_, err = teamsCall(s.teamsFixture, teams.Create, s.owner, "name", "platform")
	teamsExpectCode(t, err, "CONFLICT")
	list := teamsList(t, mustTeams(s.teamsFixture, teams.List, s.owner))
	teamsExpectStrings(t, teamsPluck(list, "slug"), "platform", "sre")
	teamsExpectStrings(t, teamsPluck(list, "childCount"), "1", "0")
	top := teamsList(t, mustTeams(s.teamsFixture, teams.List, s.owner, "parentId", nil))
	teamsExpectStrings(t, teamsPluck(top, "slug"), "platform")
}

func TestTeamsChildMembersHoldTheParentsRoles(t *testing.T) {
	s := teamsScenarioOf(t)
	teams := s.iam.API.Teams
	s.bindGroup("reader", s.platform)
	if s.canDo(s.aliceC, "documents:read") {
		t.Fatal("alice reads before joining")
	}
	mustTeams(s.teamsFixture, teams.AddMember, s.owner, "teamId", s.sre.Get("id"), "identityId", s.alice)
	if !s.canDo(s.aliceC, "documents:read") {
		t.Fatal("alice cannot read through SRE")
	}
	detail := teamsObject(t, mustTeams(s.teamsFixture, teams.Get, s.owner, "teamId", s.sre.Get("id")))
	roles := teamsList(t, detail.Get("roles"))
	if len(roles) != 1 || member(roles[0], "roleName") != "Reader" || member(roles[0], "inherited") != true || member(member(roles[0], "team"), "slug") != "platform" {
		t.Fatalf("roles: %s", teamsJSON(t, roles))
	}
	platform := teamsObject(t, mustTeams(s.teamsFixture, teams.Get, s.owner, "teamId", s.platform.Get("id")))
	// Bob directly, Alice through SRE.
	if platform.Get("totalMemberCount") != 2.0 || platform.Get("memberCount") != 1.0 {
		t.Fatalf("platform counts: %s", teamsJSON(t, platform))
	}
	members := teamsList(t, mustTeams(s.teamsFixture, teams.ListMembers, s.owner, "teamId", s.platform.Get("id"), "includeChildTeams", true))
	teamsExpectStrings(t, teamsPluck(members, "name"), "bob", "alice")
	teamsExpectStrings(t, teamsPluck(members, "role"), "maintainer", "member")
	teamsExpectStrings(t, teamsPluck(members, "team.slug"), "platform", "sre")
	mustTeams(s.teamsFixture, teams.RemoveMember, s.owner, "teamId", s.sre.Get("id"), "identityId", s.alice)
	if s.canDo(s.aliceC, "documents:read") {
		t.Fatal("alice still reads after removal")
	}
}

func TestTeamsMaintainersManageMembership(t *testing.T) {
	s := teamsScenarioOf(t)
	teams := s.iam.API.Teams
	// Bob maintains Platform, so he manages SRE below it too.
	mustTeams(s.teamsFixture, teams.AddMember, s.bobC, "teamId", s.sre.Get("id"), "identityId", s.carol, "role", "maintainer")
	mustTeams(s.teamsFixture, teams.AddMember, s.carolC, "teamId", s.sre.Get("id"), "identityId", s.alice)
	// Carol maintains SRE, not Platform.
	_, err := teamsCall(s.teamsFixture, teams.AddMember, s.carolC, "teamId", s.platform.Get("id"), "identityId", s.alice)
	teamsExpectCode(t, err, "ACCESS_DENIED")
	// Settings stay with administrators.
	_, err = teamsCall(s.teamsFixture, teams.Update, s.bobC, "teamId", s.sre.Get("id"), "name", "Ops")
	teamsExpectCode(t, err, "ACCESS_DENIED")
	viaMaintainer := 0
	for _, event := range s.audits("team:member:add") {
		if member(event.Get("metadata"), "via") == "maintainer" {
			viaMaintainer++
		}
	}
	if viaMaintainer != 2 {
		t.Fatalf("team:member:add via maintainer = %d", viaMaintainer)
	}
	standing := false
	for _, event := range s.audits("iam:teams:update") {
		if event.Get("outcome") == "allow" && member(event.Get("metadata"), "via") == "team-maintainer" {
			standing = true
		}
	}
	if !standing {
		t.Fatal("no iam:teams:update audited via team-maintainer")
	}
	// With memberManagement 'admins' maintainers are refused.
	mustTeams(s.teamsFixture, teams.Update, s.owner, "teamId", s.sre.Get("id"), "memberManagement", "admins")
	_, err = teamsCall(s.teamsFixture, teams.RemoveMember, s.carolC, "teamId", s.sre.Get("id"), "identityId", s.alice)
	teamsExpectCode(t, err, "ACCESS_DENIED")
}

func TestTeamsMembersReadTheirOwnTeam(t *testing.T) {
	s := teamsScenarioOf(t)
	teams := s.iam.API.Teams
	mustTeams(s.teamsFixture, teams.AddMember, s.owner, "teamId", s.sre.Get("id"), "identityId", s.alice)
	other := teamsObject(t, mustTeams(s.teamsFixture, teams.Create, s.owner, "name", "Sales"))
	own := teamsObject(t, mustTeams(s.teamsFixture, teams.Get, s.aliceC, "teamId", s.sre.Get("id")))
	if own.Get("slug") != "sre" {
		t.Fatalf("own team: %s", teamsJSON(t, own))
	}
	// Being in SRE makes Alice part of Platform as well.
	mustTeams(s.teamsFixture, teams.ListMembers, s.aliceC, "teamId", s.platform.Get("id"))
	_, err := teamsCall(s.teamsFixture, teams.Get, s.aliceC, "teamId", other.Get("id"))
	teamsExpectCode(t, err, "ACCESS_DENIED")
	_, err = teamsCall(s.teamsFixture, teams.List, s.aliceC)
	teamsExpectCode(t, err, "ACCESS_DENIED")
	// Members are not maintainers.
	_, err = teamsCall(s.teamsFixture, teams.AddMember, s.aliceC, "teamId", s.sre.Get("id"), "identityId", s.carol)
	teamsExpectCode(t, err, "ACCESS_DENIED")
}

func TestTeamsRefuseCyclesDepthAndDeletingParents(t *testing.T) {
	s := teamsScenarioOf(t)
	teams := s.iam.API.Teams
	_, err := teamsCall(s.teamsFixture, teams.Update, s.owner, "teamId", s.platform.Get("id"), "parentId", s.sre.Get("id"))
	expectError(t, err, "INVALID_INPUT", "A team cannot move under itself or its own team")
	_, err = teamsCall(s.teamsFixture, teams.Delete, s.owner, "teamId", s.platform.Get("id"))
	expectError(t, err, "RESOURCE_IN_USE", "Move or delete the teams below it first: Site Reliability")
	parent := s.sre.Get("id")
	for depth := 3; depth <= 10; depth++ {
		parent = teamsObject(t, mustTeams(s.teamsFixture, teams.Create, s.owner, "name", "Level "+jsString(float64(depth)), "parentId", parent)).Get("id")
	}
	_, err = teamsCall(s.teamsFixture, teams.Create, s.owner, "name", "Too deep", "parentId", parent)
	expectError(t, err, "INVALID_INPUT", "Teams nest at most 10 levels deep")
}

func TestTeamsMoveRecomputesBothParents(t *testing.T) {
	s := teamsScenarioOf(t)
	teams := s.iam.API.Teams
	other := teamsObject(t, mustTeams(s.teamsFixture, teams.Create, s.owner, "name", "Data"))
	s.bindGroup("reader", s.platform)
	s.bindGroup("writer", other)
	mustTeams(s.teamsFixture, teams.AddMember, s.owner, "teamId", s.sre.Get("id"), "identityId", s.alice)
	if !s.canDo(s.aliceC, "documents:read") || s.canDo(s.aliceC, "documents:write") {
		t.Fatal("before the move")
	}
	moved := teamsObject(t, mustTeams(s.teamsFixture, teams.Update, s.owner, "teamId", s.sre.Get("id"), "parentId", other.Get("id")))
	teamsExpectStrings(t, teamsPluck(teamsList(t, moved.Get("path")), "slug"), "data")
	if s.canDo(s.aliceC, "documents:read") || !s.canDo(s.aliceC, "documents:write") {
		t.Fatal("after the move")
	}
	top := teamsObject(t, mustTeams(s.teamsFixture, teams.Update, s.owner, "teamId", s.sre.Get("id"), "parentId", nil))
	if !isUndefined(top.Get("parentId")) {
		t.Fatalf("top-level team keeps parentId: %s", teamsJSON(t, top))
	}
	if s.canDo(s.aliceC, "documents:write") {
		t.Fatal("after moving to the top")
	}
	update := s.lastAudit("team:update")
	teamsExpectJSON(t, update.Get("metadata"), `{"team":"sre","fields":["parentId"],"parentId":null,"previousParentId":"`+jsString(other.Get("id"))+`"}`)
}

func TestTeamsJoinRequestsEndToEnd(t *testing.T) {
	s := teamsScenarioOf(t)
	teams := s.iam.API.Teams
	mustTeams(s.teamsFixture, teams.Update, s.owner, "teamId", s.platform.Get("id"), "joinPolicy", "request")
	mine := teamsObject(t, mustTeams(s.teamsFixture, teams.ListMine, s.aliceC))
	teamsExpectStrings(t, teamsPluck(teamsList(t, mine.Get("joinable")), "slug"), "platform")
	_, err := teamsCall(s.teamsFixture, teams.RequestToJoin, s.aliceC, "teamId", s.sre.Get("id"))
	teamsExpectCode(t, err, "INVALID_TRANSITION")
	request := teamsObject(t, mustTeams(s.teamsFixture, teams.RequestToJoin, s.aliceC, "teamId", s.platform.Get("id"), "justification", "On call next week"))
	if request.Get("status") != "pending" || request.Get("justification") != "On call next week" {
		t.Fatalf("request: %s", teamsJSON(t, request))
	}
	_, err = teamsCall(s.teamsFixture, teams.RequestToJoin, s.aliceC, "teamId", s.platform.Get("id"))
	teamsExpectCode(t, err, "CONFLICT")
	var mail map[string]string
	for _, message := range s.dispatch() {
		if message.Template == "team-join-request" {
			if message.To != "bob@acme.test" {
				t.Fatalf("join request mail to %s", message.To)
			}
			mail = message.Payload
		}
	}
	if mail == nil || mail["teamName"] != "Platform" || mail["requesterName"] != "alice" {
		t.Fatalf("join request mail: %v", mail)
	}
	pending := teamsList(t, mustTeams(s.teamsFixture, teams.ListRequests, s.bobC, "teamId", s.platform.Get("id")))
	teamsExpectStrings(t, teamsPluck(pending, "requester.id"), s.alice)
	approved := teamsObject(t, mustTeams(s.teamsFixture, teams.ApproveRequest, s.bobC, "requestId", request.Get("id"), "note", "Welcome"))
	if approved.Get("status") != "approved" || approved.Get("decidedBy") != s.bob || approved.Get("note") != "Welcome" {
		t.Fatalf("approved: %s", teamsJSON(t, approved))
	}
	decided := false
	for _, message := range s.dispatch() {
		if message.Template == "team-join-decided" && message.Payload["decision"] == "approved" && message.Payload["teamName"] == "Platform" {
			decided = true
		}
	}
	if !decided {
		t.Fatal("no team-join-decided mail")
	}
	after := teamsObject(t, mustTeams(s.teamsFixture, teams.ListMine, s.aliceC))
	teamsExpectStrings(t, teamsPluck(teamsList(t, after.Get("teams")), "slug"), "platform")
	teamsExpectStrings(t, teamsPluck(teamsList(t, after.Get("teams")), "role"), "member")
	teamsExpectJSON(t, after.Get("joinable"), `[]`)

	// Nobody decides their own request; carol asks, then withdraws.
	second := teamsObject(t, mustTeams(s.teamsFixture, teams.RequestToJoin, s.carolC, "teamId", s.platform.Get("id")))
	_, err = teamsCall(s.teamsFixture, teams.ApproveRequest, s.carolC, "requestId", second.Get("id"))
	teamsExpectCode(t, err, "ACCESS_DENIED")
	cancelled := teamsObject(t, mustTeams(s.teamsFixture, teams.CancelRequest, s.carolC, "requestId", second.Get("id")))
	if cancelled.Get("status") != "cancelled" {
		t.Fatalf("cancelled: %s", teamsJSON(t, cancelled))
	}
	_, err = teamsCall(s.teamsFixture, teams.DenyRequest, s.bobC, "requestId", second.Get("id"))
	teamsExpectCode(t, err, "INVALID_TRANSITION")

	// Requests lapse after fourteen days.
	third := teamsObject(t, mustTeams(s.teamsFixture, teams.RequestToJoin, s.carolC, "teamId", s.platform.Get("id")))
	s.advance(15 * 86_400_000)
	late := s.signInAgain(s.bob)
	_, err = teamsCall(s.teamsFixture, teams.ApproveRequest, late, "requestId", third.Get("id"))
	teamsExpectCode(t, err, "INVALID_TRANSITION")

	// Alice leaves.
	aliceAgain := s.signInAgain(s.alice)
	mustTeams(s.teamsFixture, teams.Leave, aliceAgain, "teamId", s.platform.Get("id"))
	teamsExpectJSON(t, teamsObject(t, mustTeams(s.teamsFixture, teams.ListMine, aliceAgain)).Get("teams"), `[]`)
}

func TestTeamReviewsDecideAndComplete(t *testing.T) {
	f := newTeamsFixture(t)
	teams := f.iam.API.Teams
	day := 86_400_000.0
	alice, _ := f.member("alice@acme.test", "alice")
	bob, bobC := f.member("bob@acme.test", "bob")
	carol, _ := f.member("carol@acme.test", "carol")
	dave, _ := f.member("dave@acme.test", "dave")
	erin, _ := f.member("erin@acme.test", "erin")
	f.group("contractors", "Contractors")
	f.addMember("contractors", erin)
	team := teamsObject(t, mustTeams(f, teams.Create, f.owner, "name", "Platform", "maintainerIds", []any{bob}, "syncGroupIds", []any{"contractors"}))
	mustTeams(f, teams.AddMembers, f.owner, "teamId", team.Get("id"), "identityIds", []any{alice, carol, dave})
	members := func() []string {
		names := teamsPluck(teamsList(t, mustTeams(f, teams.ListMembers, f.owner, "teamId", team.Get("id"))), "name")
		sort.Strings(names)
		return names
	}
	review := teamsObject(t, mustTeams(f, teams.StartReview, f.owner, "teamId", team.Get("id"), "note", "Quarterly check"))
	// Synced members are reviewed through their source group.
	names := teamsPluck(teamsList(t, review.Get("items")), "person.name")
	sort.Strings(names)
	teamsExpectStrings(t, names, "alice", "bob", "carol", "dave")
	if review.Get("status") != "open" || review.Get("onUndecided") != "keep" || review.Get("dueAt") != f.now()+14*day {
		t.Fatalf("review: %s", teamsJSON(t, review))
	}
	teamsExpectJSON(t, review.Get("counts"), `{"total":4,"keep":0,"remove":0,"undecided":4}`)
	_, err := teamsCall(f, teams.StartReview, f.owner, "teamId", team.Get("id"))
	teamsExpectCode(t, err, "CONFLICT")
	recipients := []string{}
	for _, message := range f.dispatch() {
		if message.Template == "team-review-requested" {
			recipients = append(recipients, message.To)
			if message.Payload["memberCount"] != "4" || message.Payload["note"] != "Quarterly check" {
				t.Fatalf("review mail: %v", message.Payload)
			}
		}
	}
	teamsExpectStrings(t, recipients, "bob@acme.test")

	// The maintainer sees it waiting, without counting their own membership.
	mine := teamsObject(t, mustTeams(f, teams.ListMine, bobC))
	teamsExpectJSON(t, mine.Get("reviews"), `[{"id":"`+jsString(review.Get("id"))+`","team":`+teamsJSON(t, teamRef(team))+`,"dueAt":`+jsString(review.Get("dueAt"))+`,"undecided":3}]`)
	decided := teamsObject(t, mustTeams(f, teams.DecideReview, bobC, "reviewId", review.Get("id"), "decisions", []any{
		core.NewObject("identityId", alice, "decision", "keep"),
		core.NewObject("identityId", carol, "decision", "remove", "note", "Moved to Sales"),
	}))
	teamsExpectJSON(t, decided.Get("counts"), `{"total":4,"keep":1,"remove":1,"undecided":2}`)
	var carolItem *core.Object
	for _, item := range teamsList(t, decided.Get("items")) {
		if member(member(item, "person"), "name") == "carol" {
			carolItem = item.(*core.Object)
		}
	}
	if carolItem == nil || carolItem.Get("decision") != "remove" || carolItem.Get("note") != "Moved to Sales" || member(carolItem.Get("decidedBy"), "name") != "bob" {
		t.Fatalf("carol's item: %v", carolItem)
	}
	_, err = teamsCall(f, teams.DecideReview, bobC, "reviewId", review.Get("id"), "decisions", []any{core.NewObject("identityId", bob, "decision", "keep")})
	expectError(t, err, "ACCESS_DENIED", "Nobody reviews their own membership")
	_, err = teamsCall(f, teams.DecideReview, bobC, "reviewId", review.Get("id"), "decisions", []any{core.NewObject("identityId", erin, "decision", "remove")})
	expectError(t, err, "NOT_FOUND", "This person is not under review")
	// Decisions change nothing until the review completes, and a maintainer completes only a fully decided review.
	teamsExpectStrings(t, members(), "alice", "bob", "carol", "dave", "erin")
	_, err = teamsCall(f, teams.CompleteReview, bobC, "reviewId", review.Get("id"))
	expectError(t, err, "INVALID_TRANSITION", "Decide every person first (2 left); an administrator can complete it early")

	// Members cannot read the review; an administrator completes it early (bob and dave stay: onUndecided keep).
	aliceC := f.signInAgain(alice)
	_, err = teamsCall(f, teams.GetReview, aliceC, "reviewId", review.Get("id"))
	teamsExpectCode(t, err, "ACCESS_DENIED")
	completed := teamsObject(t, mustTeams(f, teams.CompleteReview, f.owner, "reviewId", review.Get("id")))
	if completed.Get("status") != "completed" {
		t.Fatalf("completed: %s", teamsJSON(t, completed))
	}
	teamsExpectJSON(t, completed.Get("outcome"), `{"kept":3,"removed":1,"undecided":2,"gone":0}`)
	teamsExpectStrings(t, members(), "alice", "bob", "dave", "erin")

	// A cancelled review changes nothing and is listed without its items.
	f.advance(1000)
	second := teamsObject(t, mustTeams(f, teams.StartReview, f.owner, "teamId", team.Get("id")))
	cancelled := teamsObject(t, mustTeams(f, teams.CancelReview, f.owner, "reviewId", second.Get("id")))
	if cancelled.Get("status") != "cancelled" || cancelled.Has("items") {
		t.Fatalf("cancelled: %s", teamsJSON(t, cancelled))
	}
	listed := teamsList(t, mustTeams(f, teams.ListReviews, f.owner, "teamId", team.Get("id")))
	teamsExpectStrings(t, teamsPluck(listed, "status"), "cancelled", "completed")
}
