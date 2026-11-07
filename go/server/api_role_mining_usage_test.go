package server

// Access usage, right-sizing, and certification review recommendations (roleMining.usage, rightSize, and
// reviewRecommendations), after tests/access-usage.test.ts and tests/review-recommendations.test.ts.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

type usageScenario struct {
	f                 *directoryFixture
	tenantID          string
	owner             core.CredentialInput
	ownerID           string
	reader, editor    *core.Object
	alice, bob, carol *core.Object
	readers           *core.Object
}

func newUsageScenario(t *testing.T, tracking bool) *usageScenario {
	t.Helper()
	f := newAnalysisFixture(t, func(options *BetterIamOptions) {
		if tracking {
			options.AccessUsage = On[AccessUsageOptions]()
		}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	s := &usageScenario{f: f, tenantID: tenantID, owner: owner}
	s.ownerID = anaID(f.find("identities", core.NewObject("tenantId", tenantID, "owner", true))[0])
	s.reader = f.anaRole(tenantID, "Reader", "document", anaPermissions("documents:read"))
	s.editor = f.anaRole(tenantID, "Editor", "document", anaPermissions("documents:read", "documents:write"))
	s.alice, _ = f.anaMember(tenantID, "alice")
	s.bob, _ = f.anaMember(tenantID, "bob")
	s.carol, _ = f.anaMember(tenantID, "carol")
	s.readers = f.anaGroup(tenantID, "Readers")
	f.anaAddMembers(tenantID, anaID(s.readers), anaID(s.bob))
	f.anaBinding(tenantID, anaID(s.editor), "identity", anaID(s.alice))
	f.anaBinding(tenantID, anaID(s.reader), "group", anaID(s.readers))
	f.anaBinding(tenantID, anaID(s.reader), "identity", anaID(s.carol))
	return s
}

func (s *usageScenario) check(t *testing.T, who *core.Object, action string) bool {
	t.Helper()
	decision, err := s.f.iam.Authorize(s.f.ctx, AuthorizationRequest{
		Credential: s.f.issue(who, false), TenantID: s.tenantID, Action: action,
		Resource: ResourceTarget{Type: "document", ID: "d1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	return decision.Allowed
}

func (s *usageScenario) usage(t *testing.T, credential core.CredentialInput, pairs ...any) *core.Object {
	t.Helper()
	out, err := s.f.iam.API.RoleMining.Usage(s.f.ctx, credential, Input[apitypes.RoleMiningUsageInput](body(append([]any{"tenantId", s.tenantID}, pairs...)...)))
	return anaTryObject(t, out, err)
}

func (s *usageScenario) rightSize(credential core.CredentialInput, pairs ...any) (Out[apitypes.RoleMiningRightSizeOutput], error) {
	return s.f.iam.API.RoleMining.RightSize(s.f.ctx, credential, Input[apitypes.RoleMiningRightSizeInput](body(append([]any{"tenantId", s.tenantID}, pairs...)...)))
}

func TestRoleMiningRecordsUsageAndRightSizes(t *testing.T) {
	s := newUsageScenario(t, true)
	f := s.f
	if !s.check(t, s.alice, "documents:read") || !s.check(t, s.alice, "documents:read") || !s.check(t, s.bob, "documents:read") {
		t.Fatal("expected the reads to be allowed")
	}
	// Denied checks are not usage.
	if s.check(t, s.carol, "documents:write") {
		t.Fatal("carol may not write")
	}
	if _, err := f.iam.AuthorizeMany(f.ctx, BatchAuthorizationRequest{
		Credential: f.issue(s.bob, false), TenantID: s.tenantID,
		Checks: []AuthorizationCheck{{Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "d2"}}},
	}); err != nil {
		t.Fatal(err)
	}

	usage := s.usage(t, s.owner, "identityId", anaID(s.alice))
	records := anaObjects(usage.Get("records"))
	if usage.Get("tracking") != true || len(records) != 1 || records[0].Get("identityId") != anaID(s.alice) ||
		records[0].Get("action") != "documents:read" || stringify(records[0].Get("count")) != "2" {
		t.Fatalf("alice usage = %s", stringify(usage))
	}
	if got := stringify(records[0].Keys()); got != `["identityId","action","firstUsedAt","lastUsedAt","count"]` {
		t.Fatalf("record keys = %s", got)
	}
	bob := anaObjects(s.usage(t, s.owner, "identityId", anaID(s.bob)).Get("records"))
	if len(bob) == 0 || bob[0].Get("action") != "documents:read" || stringify(bob[0].Get("count")) != "2" {
		t.Fatalf("bob usage = %s", stringify(bob))
	}
	if carol := s.usage(t, s.owner, "identityId", anaID(s.carol)).Get("records"); stringify(carol) != `[]` {
		t.Fatalf("carol usage = %s", stringify(carol))
	}
	// The owner's own operations count as usage too (each usage call is an iam:analysis:read).
	ownerActions := pluck(anaObjects(s.usage(t, s.owner, "identityId", s.ownerID).Get("records")), "action")
	if !containsString(ownerActions, "iam:analysis:read") {
		t.Fatalf("owner usage = %v", ownerActions)
	}

	out, err := s.rightSize(s.owner)
	report := anaTryObject(t, out, err)
	if report.Get("tracking") != true || stringify(report.Get("unusedDays")) != "90" || report.Get("complete") != false {
		t.Fatalf("report = %s", stringify(report))
	}
	if _, ok := report.Get("trackingSince").(float64); !ok {
		t.Fatalf("trackingSince = %v", report.Get("trackingSince"))
	}
	if got := stringify(report.Keys()); got != `["generatedAt","unusedDays","tracking","trackingSince","complete","entries","roles"]` {
		t.Fatalf("report keys = %s", got)
	}
	entries := anaObjects(report.Get("entries"))
	var shape []string
	for _, entry := range entries {
		shape = append(shape, jsString(member(entry.Get("identity"), "id"))+"/"+jsString(member(entry.Get("role"), "name"))+"/"+jsString(entry.Get("status")))
	}
	if strings.Join(shape, ",") != anaID(s.carol)+"/Reader/unused,"+anaID(s.alice)+"/Editor/partial" {
		t.Fatalf("entries = %v", shape)
	}
	alice := entries[1]
	if stringify(alice.Get("via")) != `{"type":"identity"}` || stringify(alice.Get("grantedActions")) != "2" ||
		stringify(alice.Get("usedActions")) != `["documents:read"]` || stringify(alice.Get("unusedActions")) != `["documents:write"]` ||
		stringify(alice.Get("unusedCount")) != "1" {
		t.Fatalf("alice = %s", stringify(alice))
	}
	if _, ok := alice.Get("lastUsedAt").(float64); !ok {
		t.Fatalf("alice lastUsedAt = %v", alice.Get("lastUsedAt"))
	}
	roles := map[string]*core.Object{}
	for _, role := range anaObjects(report.Get("roles")) {
		roles[jsString(member(role.Get("role"), "name"))] = role
	}
	if stringify(roles["Editor"].Get("holders")) != "1" || stringify(roles["Editor"].Get("neverUsed")) != `["documents:write"]` {
		t.Fatalf("editor = %s", stringify(roles["Editor"]))
	}
	if stringify(roles["Reader"].Get("holders")) != "2" || stringify(roles["Reader"].Get("neverUsed")) != `[]` ||
		stringify(roles["Reader"].Get("usedActions")) != `["documents:read"]` {
		t.Fatalf("reader = %s", stringify(roles["Reader"]))
	}

	// Once the window is covered, old use no longer counts.
	f.advance(2 * analysisDayMs)
	out, err = s.rightSize(f.ownerSignIn(s.tenantID), "unusedDays", 1.0)
	later := anaTryObject(t, out, err)
	if later.Get("complete") != true {
		t.Fatalf("later = %s", stringify(later))
	}
	sawBob := false
	for _, entry := range anaObjects(later.Get("entries")) {
		if entry.Get("status") != "unused" {
			t.Fatalf("entry = %s", stringify(entry))
		}
		if member(entry.Get("identity"), "id") == anaID(s.bob) {
			sawBob = true
			if got := stringify(entry.Get("via")); got != stringify(body("type", "group", "id", anaID(s.readers), "name", "Readers")) {
				t.Fatalf("bob via = %s", got)
			}
		}
	}
	if !sawBob {
		t.Fatalf("bob missing from %s", stringify(later.Get("entries")))
	}
}

func TestRoleMiningUsageMergesFlushes(t *testing.T) {
	s := newUsageScenario(t, true)
	f := s.f
	s.check(t, s.alice, "documents:read")
	if written := must(f.iam.FlushAccessUsage(f.ctx)).Get("written"); jsNumber(written) <= 0 {
		t.Fatalf("written = %v", written)
	}
	if written := must(f.iam.FlushAccessUsage(f.ctx)).Get("written"); jsNumber(written) != 0 {
		t.Fatalf("written again = %v", written)
	}
	f.advance(60_000)
	s.check(t, s.alice, "documents:read")
	must(f.iam.FlushAccessUsage(f.ctx))
	record := anaObjects(s.usage(t, s.owner, "identityId", anaID(s.alice)).Get("records"))[0]
	if stringify(record.Get("count")) != "2" || jsNumber(record.Get("lastUsedAt"))-jsNumber(record.Get("firstUsedAt")) != 60_000 {
		t.Fatalf("record = %s", stringify(record))
	}
}

func TestRoleMiningUsageWithoutTracking(t *testing.T) {
	s := newUsageScenario(t, false)
	f := s.f
	s.check(t, s.alice, "documents:read")
	if got := stringify(must(f.iam.FlushAccessUsage(f.ctx))); got != `{"written":0}` {
		t.Fatalf("flush = %s", got)
	}
	usage := s.usage(t, s.owner)
	if usage.Get("tracking") != false || stringify(usage.Get("total")) != "0" || stringify(usage.Get("records")) != `[]` {
		t.Fatalf("usage = %s", stringify(usage))
	}
	if got := stringify(usage.Keys()); got != `["tracking","trackingSince","total","records"]` && got != `["tracking","total","records"]` {
		t.Fatalf("usage keys = %s", got)
	}
	if got := stringify(usage); strings.Contains(got, "trackingSince") {
		t.Fatalf("usage = %s", got)
	}
	out, err := s.rightSize(s.owner)
	report := anaTryObject(t, out, err)
	if report.Get("tracking") != false || report.Get("complete") != false || strings.Contains(stringify(report), "trackingSince") {
		t.Fatalf("report = %s", stringify(report))
	}
	_, err = s.rightSize(s.owner, "unusedDays", 0.0)
	expectError(t, err, "INVALID_INPUT", "Invalid unusedDays")
	_, err = f.iam.API.RoleMining.Usage(f.ctx, s.owner, Input[apitypes.RoleMiningUsageInput](body("tenantId", s.tenantID, "limit", 1001.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid limit")
}

// The campaign and its items are seeded as certifications.create writes them; that API group is ported separately.
func TestRoleMiningReviewRecommendations(t *testing.T) {
	f := newAnalysisFixture(t, func(options *BetterIamOptions) { options.AccessUsage = On[AccessUsageOptions]() })
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	alice, _ := f.anaMember(tenantID, "alice")
	bob, _ := f.anaMember(tenantID, "bob")
	carol, _ := f.anaMember(tenantID, "carol")
	dave := f.anaIdentity(tenantID, "dave")
	reader := f.anaRole(tenantID, "Reader", "document", anaPermissions("documents:read"))
	writer := f.anaRole(tenantID, "Writer", "document", anaPermissions("documents:write"))
	team := f.anaGroup(tenantID, "Team")
	bindings := map[string]*core.Object{
		anaID(alice): f.anaBinding(tenantID, anaID(reader), "identity", anaID(alice)),
		anaID(bob):   f.anaBinding(tenantID, anaID(writer), "identity", anaID(bob)),
		anaID(carol): f.anaBinding(tenantID, anaID(reader), "identity", anaID(carol)),
		anaID(dave):  f.anaBinding(tenantID, anaID(reader), "identity", anaID(dave)),
		anaID(team):  f.anaBinding(tenantID, anaID(reader), "group", anaID(team)),
	}
	f.patch("identities", anaID(carol), core.NewObject("status", "disabled"))
	use := func(who *core.Object, action string) {
		if _, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: f.issue(who, false), TenantID: tenantID, Action: action,
			Resource: ResourceTarget{Type: "document", ID: "d1"}}); err != nil {
			t.Fatal(err)
		}
	}
	use(alice, "documents:read")
	f.issue(bob, false)
	// Dave never signs in; support viewing the product as Dave is not Dave signing in.
	f.patch("tenants", tenantID, core.NewObject("authPolicy", body("allowImpersonation", true)))
	actor := must(f.iam.Authenticate(f.ctx, f.ownerSignIn(tenantID)))
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		_, err := f.iam.Auth.IssueImpersonationSession(ctx, tx, &auth.Principal{Identity: actor.Identity, Session: actor.Session}, dave, 3_600_000)
		return err
	})
	campaignID := ID()
	f.seed("certificationCampaigns", core.NewObject("id", campaignID, "tenantId", tenantID, "name", "Q3", "status", "open",
		"createdAt", f.now()))
	itemFor := map[string]string{}
	for subjectID, binding := range bindings {
		itemID := ID()
		itemFor[subjectID] = itemID
		f.seed("certificationItems", core.NewObject("id", itemID, "tenantId", tenantID, "campaignId", campaignID,
			"bindingId", anaID(binding), "subjectType", binding.Get("subjectType"), "subjectId", subjectID,
			"roleId", binding.Get("roleId"), "decision", "pending"))
	}
	recommend := func(credential core.CredentialInput, pairs ...any) (*core.Object, map[string]*core.Object) {
		out, err := f.iam.API.RoleMining.ReviewRecommendations(f.ctx, credential, Input[apitypes.RoleMiningReviewRecommendationsInput](
			body(append([]any{"tenantId", tenantID, "campaignId", campaignID}, pairs...)...)))
		result := anaTryObject(t, out, err)
		byItem := map[string]*core.Object{}
		for _, entry := range anaObjects(result.Get("recommendations")) {
			byItem[jsString(entry.Get("itemId"))] = entry
		}
		return result, byItem
	}
	expect := func(entry *core.Object, members ...any) {
		t.Helper()
		for index := 0; index+1 < len(members); index += 2 {
			if got := entry.Get(members[index].(string)); stringify(got) != stringify(members[index+1]) {
				t.Fatalf("%s: %s = %s, want %s", stringify(entry), members[index], stringify(got), stringify(members[index+1]))
			}
		}
	}

	// Usage only just started: sign-ins are the evidence.
	early, first := recommend(owner, "unusedDays", 30.0)
	if early.Get("usageComplete") != false || stringify(early.Keys()) != `["campaignId","unusedDays","usageComplete","recommendations"]` {
		t.Fatalf("early = %s", stringify(early))
	}
	expect(first[itemFor[anaID(alice)]], "recommendation", "keep", "basis", "sign-in")
	expect(first[itemFor[anaID(bob)]], "recommendation", "keep", "basis", "sign-in")
	expect(first[itemFor[anaID(carol)]], "recommendation", "revoke", "basis", "status", "reason", "The account is disabled.")
	expect(first[itemFor[anaID(dave)]], "recommendation", "revoke", "basis", "sign-in", "reason", "Has never signed in.")
	expect(first[itemFor[anaID(team)]], "recommendation", "none", "reason", "A group's binding; review who belongs to the group instead.")
	// Recommendations are listed by item ID.
	ids := pluck(anaObjects(early.Get("recommendations")), "itemId")
	if stringify(ids) != stringify(anaSortedLocale(ids)) {
		t.Fatalf("order = %v", ids)
	}

	// A month later usage covers the window: Alice used her role again, Bob signed in but never wrote.
	f.advance(31 * analysisDayMs)
	use(alice, "documents:read")
	f.issue(bob, false)
	_, later := recommend(f.ownerSignIn(tenantID), "unusedDays", 30.0)
	expect(later[itemFor[anaID(alice)]], "recommendation", "keep", "basis", "usage", "lastUsedAt", f.now(),
		"reason", "Used 1 of the role's actions in the last 30 days.")
	expect(later[itemFor[anaID(bob)]], "recommendation", "revoke", "basis", "usage",
		"reason", "None of the role's actions were used in the last 30 days.")

	_, err := f.iam.API.RoleMining.ReviewRecommendations(f.ctx, f.ownerSignIn(tenantID), Input[apitypes.RoleMiningReviewRecommendationsInput](
		body("tenantId", tenantID, "campaignId", "missing")))
	expectCode(t, err, "NOT_FOUND")
}

// anaSortedLocale is `[...values].sort((a, b) => a.localeCompare(b))`.
func anaSortedLocale(values []string) []string {
	out := append([]string(nil), values...)
	sort.SliceStable(out, func(i, j int) bool { return localeCompare(out[i], out[j]) < 0 })
	return out
}
