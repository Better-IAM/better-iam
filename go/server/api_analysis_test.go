package server

// Access analysis, after tests/analysis.test.ts, the suppression tests of tests/security-governance.test.ts, and the
// analysis.lintPolicy tests of tests/policy-lint.test.ts. (The scan goes through sod.ts sodViolations and the policy
// linter, which other units port; those tests skip until they land.)

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const analysisMonth = int64(30 * analysisDayMs)

// newAnalysisOrganization is the analysis fixture: sessions last 30 days, so the owner's first session stays valid
// while the clock moves on.
func newAnalysisOrganization(t *testing.T, mutate func(options *BetterIamOptions)) (*directoryFixture, string, core.CredentialInput) {
	t.Helper()
	f := newAnalysisFixture(t, func(options *BetterIamOptions) {
		lifetime := analysisMonth
		options.Authentication.SessionLifetimeMs = &lifetime
		options.Authentication.SessionIdleTimeoutMs = &lifetime
		if mutate != nil {
			mutate(options)
		}
	})
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	return f, tenantID, owner
}

func findingsOf(t *testing.T, f *directoryFixture, credential core.CredentialInput, tenantID string, pairs ...any) *core.Object {
	t.Helper()
	out, err := f.iam.API.Analysis.Findings(f.ctx, credential, Input[apitypes.AnalysisFindingsInput](body(append([]any{"tenantId", tenantID}, pairs...)...)))
	return anaTryObject(t, out, err)
}

func findingList(report *core.Object) []*core.Object { return anaObjects(report.Get("findings")) }

func findingsOfKind(report *core.Object, kind string) []*core.Object {
	var out []*core.Object
	for _, finding := range findingList(report) {
		if finding.Get("kind") == kind {
			out = append(out, finding)
		}
	}
	return out
}

// findingKinds is `kind:subject.name ?? subject.id`, sorted.
func findingKinds(findings []*core.Object) []string {
	var out []string
	for _, finding := range findings {
		subject := finding.Get("subject")
		out = append(out, jsString(finding.Get("kind"))+":"+jsString(coalesce(member(subject, "name"), member(subject, "id"))))
	}
	return anaSorted(out)
}

func subjectField(findings []*core.Object, key string) []string {
	return pluck(pluckObjects(findings, "subject"), key)
}

func (f *directoryFixture) suppress(credential core.CredentialInput, tenantID, findingID, reason string, pairs ...any) (Out[apitypes.AnalysisSuppressOutput], error) {
	return f.iam.API.Analysis.Suppress(f.ctx, credential, Input[apitypes.AnalysisSuppressInput](body(append([]any{
		"tenantId", tenantID, "findingId", findingID, "reason", reason}, pairs...)...)))
}

// anaServiceAccount writes a service account as serviceAccounts.create does.
func (f *directoryFixture) anaServiceAccount(tenantID, name string) *core.Object {
	f.t.Helper()
	account := core.NewObject("id", ID(), "tenantId", tenantID, "kind", "service", "name", name, "status", "active",
		"emailVerified", false, "owner", false, "rootAdmin", false, "createdAt", f.now())
	f.seed("identities", account)
	return account
}

func TestAnalysisReportsRiskyConfiguration(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	admin := f.anaPolicy(tenantID, "Everything", anaDocument(allow(items("*"), items("*"))))
	broad := f.anaPolicy(tenantID, "Documents", anaDocument(allow(items("documents:*"), items("*"))))
	f.anaPolicy(tenantID, "Scoped admin", anaDocument(allow(items("*"), items("*"),
		"conditions", body("Bool", body("principal.mfa", true)))))
	admins := f.anaRole(tenantID, "Admins", "policyIds", items(anaID(admin)))
	editors := f.anaRole(tenantID, "Editors", "policyIds", items(anaID(broad)))
	f.anaRole(tenantID, "Unused", "document", anaPermissions("documents:read"))
	alice := f.anaIdentity(tenantID, "alice")
	bot := f.anaServiceAccount(tenantID, "deploy-bot")
	f.anaBinding(tenantID, anaID(admins), "identity", anaID(alice))
	f.anaBinding(tenantID, anaID(admins), "identity", anaID(bot))
	ghosts := f.anaGroup(tenantID, "Ghosts")
	f.anaBinding(tenantID, anaID(editors), "group", anaID(ghosts))
	// Alice signs in once so she is not yet dormant.
	f.issue(alice, false)

	report := findingsOf(t, f, owner, tenantID)
	// Alice's direct, permanent Admins binding is standing administrator access. Everything's only lint warning
	// (unrestricted-admin) already has its own finding, so no separate policy-lint finding is reported.
	want := anaSorted([]string{
		"admin-without-mfa:alice@acme.test",
		"admin-without-mfa:owner@acme.test",
		"broad-action-wildcard:Documents",
		"empty-group-with-access:Ghosts",
		"service-account-admin:deploy-bot",
		"standing-privileged-access:alice@acme.test",
		"unattached-policy:Scoped admin",
		"unrestricted-admin-policy:Everything",
		"unused-role:Unused",
	})
	if got := findingKinds(findingList(report)); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("findings:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	rank := -1
	for _, finding := range findingList(report) {
		next := analysisSeverityRank[jsString(finding.Get("severity"))]
		if next < rank {
			t.Fatalf("findings are not ordered by severity: %s", stringify(pluck(findingList(report), "severity")))
		}
		rank = next
	}
	if got := stringify(report.Get("summary")); got != `{"high":3,"medium":3,"low":3,"suppressed":0}` {
		t.Fatalf("summary = %s", got)
	}
	if got := stringify(report.Keys()); got != `["generatedAt","dormantDays","summary","findings"]` {
		t.Fatalf("report keys = %s", got)
	}
	if got := stringify(findingList(report)[0].Keys()); got != `["id","kind","severity","title","detail","subject"]` {
		t.Fatalf("finding keys = %s", got)
	}

	// Findings are stable across runs, so they can be suppressed with a reason.
	again := findingsOf(t, f, owner, tenantID)
	if stringify(pluck(findingList(again), "id")) != stringify(pluck(findingList(report), "id")) {
		t.Fatal("finding IDs changed between runs")
	}
	unused := findingsOfKind(report, "unused-role")[0]
	if got := stringify(answer(f.suppress(owner, tenantID, anaID(unused), "Kept for the upcoming audit team"))); got != `{"suppressed":true}` {
		t.Fatalf("suppress = %s", got)
	}
	suppressed := findingsOf(t, f, owner, tenantID)
	if containsString(pluck(findingList(suppressed), "id"), anaID(unused)) || stringify(member(suppressed.Get("summary"), "suppressed")) != "1" {
		t.Fatalf("suppressed = %s", stringify(suppressed))
	}
	all := findingsOf(t, f, owner, tenantID, "includeSuppressed", true)
	var shown *core.Object
	for _, finding := range findingList(all) {
		if anaID(finding) == anaID(unused) {
			shown = finding
		}
	}
	if shown == nil || member(shown.Get("suppressed"), "reason") != "Kept for the upcoming audit team" ||
		stringify(shown.Get("suppressed").(*core.Object).Keys()) != `["reason","by","at"]` {
		t.Fatalf("shown = %s", stringify(shown))
	}
	unsuppressed := answer(f.iam.API.Analysis.Unsuppress(f.ctx, owner, Input[apitypes.AnalysisUnsuppressInput](body(
		"tenantId", tenantID, "findingId", anaID(unused)))))
	if stringify(unsuppressed) != `{"suppressed":false}` {
		t.Fatalf("unsuppress = %s", stringify(unsuppressed))
	}
	if !containsString(pluck(findingList(findingsOf(t, f, owner, tenantID)), "id"), anaID(unused)) {
		t.Fatal("the finding did not show again")
	}
	_, err := f.suppress(owner, tenantID, "not-a-finding", "x")
	expectError(t, err, "INVALID_INPUT", "Unknown finding ID")
}

func TestAnalysisValidatesInput(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	_, err := f.iam.API.Analysis.Findings(f.ctx, owner, Input[apitypes.AnalysisFindingsInput](body("tenantId", tenantID, "dormantDays", 0.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid dormantDays")
	_, err = f.iam.API.Analysis.Findings(f.ctx, owner, Input[apitypes.AnalysisFindingsInput](body("tenantId", tenantID, "dormantDays", 3651.0)))
	expectError(t, err, "INVALID_INPUT", "Invalid dormantDays")
	_, err = f.suppress(owner, tenantID, "not-a-finding", "x")
	expectError(t, err, "INVALID_INPUT", "Unknown finding ID")
	_, err = f.suppress(owner, tenantID, strings.Repeat("a", 65), "x")
	expectError(t, err, "INVALID_INPUT", "Invalid findingId")
	_, err = f.suppress(owner, tenantID, strings.Repeat("a", 24), "")
	expectError(t, err, "INVALID_INPUT", "Invalid reason")
	_, err = f.suppress(owner, tenantID, strings.Repeat("a", 24), "x", "dormantDays", 0.0)
	expectError(t, err, "INVALID_INPUT", "Invalid dormantDays")
	_, err = f.iam.API.Analysis.Unsuppress(f.ctx, owner, Input[apitypes.AnalysisUnsuppressInput](body("tenantId", tenantID)))
	expectError(t, err, "INVALID_INPUT", "Invalid findingId")
	// Unsuppressing a finding that was never suppressed is a no-op.
	if got := stringify(answer(f.iam.API.Analysis.Unsuppress(f.ctx, owner, Input[apitypes.AnalysisUnsuppressInput](body(
		"tenantId", tenantID, "findingId", strings.Repeat("a", 24)))))); got != `{"suppressed":false}` {
		t.Fatalf("unsuppress = %s", got)
	}
	// Members without iam:analysis:read or update cannot run the analysis or change suppressions.
	_, member := f.anaMember(tenantID, "bob")
	_, err = f.iam.API.Analysis.Findings(f.ctx, member, Input[apitypes.AnalysisFindingsInput](body("tenantId", tenantID)))
	expectStatus(t, err, 403)
	_, err = f.suppress(member, tenantID, strings.Repeat("a", 24), "x")
	expectStatus(t, err, 403)
}

func TestAnalysisReportsDormantMembers(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	readers := f.anaRole(tenantID, "Readers", "document", anaPermissions("documents:read"))
	bob := f.anaIdentity(tenantID, "bob")
	f.anaBinding(tenantID, anaID(readers), "identity", anaID(bob))
	robot := f.anaServiceAccount(tenantID, "nightly")
	f.seed("sessions", core.NewObject("id", ID(), "tenantId", tenantID, "identityId", anaID(robot), "kind", "api-key",
		"name", "backup", "tokenHash", ID(), "createdAt", f.now(), "lastSeenAt", f.now(), "expiresAt", f.now()+365*analysisDayMs))
	fresh := findingsOf(t, f, owner, tenantID)
	if len(findingsOfKind(fresh, "dormant-access")) != 0 || len(findingsOfKind(fresh, "stale-api-key")) != 0 {
		t.Fatalf("fresh = %s", stringify(findingKinds(findingList(fresh))))
	}
	f.advance(10 * analysisDayMs)
	// The owner keeps their session alive; Bob never signed in.
	later := findingsOf(t, f, owner, tenantID, "dormantDays", 7.0)
	dormant := findingsOfKind(later, "dormant-access")
	if got := anaSorted(subjectField(dormant, "name")); strings.Join(got, ",") != "bob@acme.test,owner@acme.test" {
		t.Fatalf("dormant = %v", got)
	}
	for _, finding := range dormant {
		name := member(finding.Get("subject"), "name")
		if name == "bob@acme.test" && !strings.Contains(jsString(finding.Get("title")), "never signed in") {
			t.Fatalf("bob = %s", stringify(finding))
		}
		if name == "owner@acme.test" && finding.Get("title") != "owner@acme.test has not signed in for 10 days" {
			t.Fatalf("owner = %s", stringify(finding))
		}
	}
	stale := findingsOfKind(later, "stale-api-key")
	if len(stale) != 1 || stale[0].Get("severity") != "medium" || stale[0].Get("title") != "API key backup has never been used" ||
		member(stale[0].Get("subject"), "type") != "credential" || member(stale[0].Get("subject"), "name") != "backup" {
		t.Fatalf("stale = %s", stringify(stale))
	}
	if detail := jsString(stale[0].Get("detail")); !strings.HasPrefix(detail, "The key belongs to nightly and stays valid until ") {
		t.Fatalf("stale detail = %s", detail)
	}
	_, err := f.iam.API.Analysis.Findings(f.ctx, owner, Input[apitypes.AnalysisFindingsInput](body("tenantId", tenantID, "dormantDays", 0.0)))
	expectCode(t, err, "INVALID_INPUT")

	// Members without iam:analysis:read cannot run the analysis.
	_, err = f.iam.API.Analysis.Findings(f.ctx, f.issue(bob, false), Input[apitypes.AnalysisFindingsInput](body("tenantId", tenantID)))
	expectStatus(t, err, 403)
}

func TestAnalysisReportsStandingAdministratorBindings(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	admins := f.anaRole(tenantID, "Admins", "document", anaDocument(allow(items("*"), items("*"))))
	readers := f.anaRole(tenantID, "Readers", "document", anaPermissions("documents:read"))
	alice := f.anaIdentity(tenantID, "alice")
	bob := f.anaIdentity(tenantID, "bob")
	carol := f.anaIdentity(tenantID, "carol")
	dave := f.anaIdentity(tenantID, "dave")
	bot := f.anaServiceAccount(tenantID, "deploy-bot")
	team := f.anaGroup(tenantID, "Team")
	standing := f.anaBinding(tenantID, anaID(admins), "identity", anaID(alice))
	f.anaBinding(tenantID, anaID(admins), "identity", anaID(bob), "eligible", true)
	f.anaBinding(tenantID, anaID(admins), "identity", anaID(carol), "expiresAt", f.now()+analysisDayMs)
	f.anaBinding(tenantID, anaID(readers), "identity", anaID(dave))
	f.anaBinding(tenantID, anaID(admins), "identity", anaID(bot))
	f.anaBinding(tenantID, anaID(admins), "group", anaID(team))

	found := findingsOfKind(findingsOf(t, f, owner, tenantID), "standing-privileged-access")
	// The owner's protected Owner binding is not reported either.
	if len(found) != 1 || found[0].Get("severity") != "medium" ||
		found[0].Get("title") != "alice@acme.test holds Admins as standing administrator access" ||
		stringify(found[0].Get("subject")) != stringify(body("type", "identity", "id", anaID(alice), "name", "alice@acme.test")) {
		t.Fatalf("found = %s", stringify(found))
	}
	if !strings.Contains(jsString(found[0].Get("detail")), "eligible") {
		t.Fatalf("detail = %v", found[0].Get("detail"))
	}
	f.patch("bindings", anaID(standing), core.NewObject("eligible", true))
	if len(findingsOfKind(findingsOf(t, f, owner, tenantID), "standing-privileged-access")) != 0 {
		t.Fatal("an eligible binding is not standing access")
	}
}

func TestAnalysisReportsUnusedEligibleBindings(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	auditors := f.anaRole(tenantID, "Auditors", "document", anaPermissions("iam:audit:read"))
	elevators := f.anaRole(tenantID, "Elevators", "document", anaPermissions("iam:bindings:activate"))
	alice := f.anaIdentity(tenantID, "alice")
	bob := f.anaIdentity(tenantID, "bob")
	carol := f.anaIdentity(tenantID, "carol")
	team := f.anaGroup(tenantID, "Team")
	for _, person := range []*core.Object{bob, carol} {
		f.anaBinding(tenantID, anaID(elevators), "identity", anaID(person))
	}
	f.anaBinding(tenantID, anaID(auditors), "identity", anaID(alice), "eligible", true)
	used := f.anaBinding(tenantID, anaID(auditors), "identity", anaID(bob), "eligible", true)
	requested := f.anaBinding(tenantID, anaID(auditors), "identity", anaID(carol), "eligible", true, "requireApproval", true)
	f.anaBinding(tenantID, anaID(auditors), "group", anaID(team), "eligible", true)
	// Bob activates his binding (as bindings.activate records it).
	f.seed("bindingActivations", core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", anaID(used)+":"+anaID(bob),
		"bindingId", anaID(used), "identityId", anaID(bob), "roleId", anaID(auditors), "activatedAt", f.now(),
		"expiresAt", f.now()+3_600_000))
	// Carol only asks; a request that is never approved is not an activation. The audit trail names her binding.
	f.seed("bindingActivations", core.NewObject("id", ID(), "tenantId", tenantID, "uniqueKey", anaID(requested)+":"+anaID(carol),
		"bindingId", anaID(requested), "identityId", anaID(carol), "roleId", anaID(auditors), "status", "pending",
		"requestedAt", f.now()))
	if _, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: f.issue(carol, false), TenantID: tenantID,
		Action: "binding:activation-requested", Resource: ResourceTarget{Type: "binding", ID: anaID(requested)}}); err != nil {
		t.Fatal(err)
	}
	unused := func(credential core.CredentialInput) []*core.Object {
		return findingsOfKind(findingsOf(t, f, credential, tenantID, "dormantDays", 7.0), "unused-eligible-binding")
	}

	// Bindings as young as their subjects are not reported yet.
	if found := unused(owner); len(found) != 0 {
		t.Fatalf("young = %s", stringify(found))
	}
	f.advance(10 * analysisDayMs)
	later := unused(f.ownerSignIn(tenantID))
	var subjects []string
	for _, finding := range later {
		subjects = append(subjects, jsString(member(finding.Get("subject"), "type"))+":"+jsString(member(finding.Get("subject"), "name")))
	}
	if got := anaSorted(subjects); strings.Join(got, ",") != "group:Team,identity:alice@acme.test,identity:carol@acme.test" {
		t.Fatalf("unused = %v", got)
	}
	for _, finding := range later {
		switch member(finding.Get("subject"), "id") {
		case anaID(alice):
			if finding.Get("severity") != "low" || finding.Get("title") != "Eligible Auditors binding for alice@acme.test has no recorded activation" ||
				!strings.Contains(jsString(finding.Get("detail")), "no activation") {
				t.Fatalf("alice = %s", stringify(finding))
			}
		case anaID(carol):
			// Carol's request dates the binding from the audit trail.
			if !regexp.MustCompile(`existed for at least \d+ days`).MatchString(jsString(finding.Get("detail"))) {
				t.Fatalf("carol = %s", stringify(finding))
			}
		}
	}
	ids := newOrderedSet(pluck(later, "id")...)
	if ids.Len() != 3 {
		t.Fatalf("ids = %v", ids.Values())
	}
}

func TestAnalysisCountsOnlyRecordedActivations(t *testing.T) {
	f, tenantID, _ := newAnalysisOrganization(t, nil)
	auditors := f.anaRole(tenantID, "Auditors", "document", anaPermissions("iam:audit:read"))
	alice := f.anaIdentity(tenantID, "alice")
	binding := f.anaBinding(tenantID, anaID(auditors), "identity", anaID(alice), "eligible", true)
	f.advance(10 * analysisDayMs)
	unused := func() []string {
		report := findingsOf(t, f, f.ownerSignIn(tenantID), tenantID, "dormantDays", 7.0)
		return subjectField(findingsOfKind(report, "unused-eligible-binding"), "id")
	}
	if got := unused(); stringify(got) != stringify([]string{anaID(alice)}) {
		t.Fatalf("unused = %v", got)
	}

	// Alice holds no permissions, yet authorize() audits each denial under the action and resource ID she names.
	token := f.issue(alice, false)
	forged := []string{"binding:activate", "binding:activation-approved", "binding:break-glass"}
	for _, action := range forged {
		decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: token, TenantID: tenantID, Action: action,
			Resource: ResourceTarget{Type: "anything", ID: anaID(binding)}})
		if err != nil || decision.Allowed {
			t.Fatalf("authorize %s = %+v, %v", action, decision, err)
		}
	}
	audited := f.find("audit", core.NewObject("tenantId", tenantID, "resourceId", anaID(binding)))
	if got := anaSorted(pluck(audited, "action")); stringify(got) != stringify(anaSorted(forged)) {
		t.Fatalf("audited = %v", got)
	}
	// None of those denials is an activation, so the dormant grant stays reported.
	if got := unused(); stringify(got) != stringify([]string{anaID(alice)}) {
		t.Fatalf("unused after forgeries = %v", got)
	}
}

func TestAnalysisReportsManagerLinksAndLoops(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	people := map[string]*core.Object{}
	for _, name := range []string{"alice", "bob", "carol", "dave", "erin", "frank", "gina", "hank"} {
		people[name] = f.anaIdentity(tenantID, name)
	}
	// identities.update and direct writes or imports both leave a managerId on the record.
	link := func(name, managerID string) {
		f.patch("identities", anaID(people[name]), core.NewObject("managerId", managerID))
	}
	manage := func(name, manager string) { link(name, anaID(people[manager])) }
	manage("alice", "bob")
	f.patch("identities", anaID(people["bob"]), core.NewObject("status", "disabled"))
	link("carol", "no-such-identity")
	manage("gina", "dave")
	manage("dave", "erin")
	link("erin", anaID(people["dave"]))
	link("frank", anaID(people["frank"]))
	manage("hank", "gina")

	report := findingsOf(t, f, owner, tenantID)
	orphaned := findingsOfKind(report, "orphaned-manager")
	if got := anaSorted(pluck(orphaned, "title")); stringify(got) != stringify([]string{
		"alice@acme.test's manager bob@acme.test is disabled",
		"carol@acme.test's manager no longer exists",
	}) {
		t.Fatalf("orphaned = %v", got)
	}
	for _, finding := range orphaned {
		if finding.Get("severity") != "low" {
			t.Fatalf("orphaned severity = %s", stringify(finding))
		}
	}
	// Gina and Hank report into the loop without being part of it.
	cycles := findingsOfKind(report, "manager-cycle")
	if got := anaSorted(subjectField(cycles, "name")); strings.Join(got, ",") != "dave@acme.test,erin@acme.test,frank@acme.test" {
		t.Fatalf("cycles = %v", got)
	}
	for _, finding := range cycles {
		if finding.Get("severity") != "medium" {
			t.Fatalf("cycle severity = %s", stringify(finding))
		}
		switch member(finding.Get("subject"), "id") {
		case anaID(people["dave"]):
			if !strings.Contains(jsString(finding.Get("detail")), "dave@acme.test → erin@acme.test → dave@acme.test") {
				t.Fatalf("dave = %s", stringify(finding))
			}
		case anaID(people["frank"]):
			if finding.Get("title") != "frank@acme.test's manager chain loops back to them" {
				t.Fatalf("frank = %s", stringify(finding))
			}
		}
	}
}

func TestAnalysisFindsDeepManagerLoopsInLinearTime(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	// 10,000 people in one reporting chain whose last 30 form a loop, written directly (the API refuses loops).
	const size, loop = 10_000, 30
	createdAt := f.now()
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		for index := 0; index < size; index++ {
			next := index + 1
			if next >= size {
				next = size - loop
			}
			if _, err := tx.Insert(ctx, "identities", core.NewObject(
				"id", fmt.Sprintf("person-%d", index), "tenantId", tenantID, "kind", "user", "name", fmt.Sprintf("person-%d", index),
				"status", "active", "emailVerified", false, "rootAdmin", false, "owner", false, "createdAt", createdAt,
				"managerId", fmt.Sprintf("person-%d", next),
			)); err != nil {
				return err
			}
		}
		return nil
	})
	started := time.Now()
	cycles := findingsOfKind(findingsOf(t, f, owner, tenantID), "manager-cycle")
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("analysis took %s", elapsed)
	}
	// Only the loop's members are reported; the 9,970 people reporting into it are not part of it.
	var want []string
	for index := 0; index < loop; index++ {
		want = append(want, fmt.Sprintf("person-%d", size-loop+index))
	}
	if got := anaSorted(subjectField(cycles, "id")); stringify(got) != stringify(anaSorted(want)) {
		t.Fatalf("cycles = %d %v", len(got), got)
	}
	// A long loop is shortened in the detail, starting and ending with the reported person.
	pattern := regexp.MustCompile(`^person-9985 → person-9986 → (person-\d+ → ){6}person-9993 → … 21 more → person-9985\. `)
	for _, finding := range cycles {
		if member(finding.Get("subject"), "id") == "person-9985" && !pattern.MatchString(jsString(finding.Get("detail"))) {
			t.Fatalf("detail = %s", finding.Get("detail"))
		}
	}
}

func TestAnalysisReportsPolicyLintWarnings(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	f.anaPolicy(tenantID, "Office network", anaDocument(
		allow(items("documents:read"), items("documents/*"), "conditions", body("IpAddress", body("request.ip", "10.0.0.0/8"))),
		allow(items("documents:write"), items("documents/*"), "conditions", body("StringEquals", body("principal.groups", "writers"))),
	))
	// Informational notes alone (a service-wide wildcard) do not make a finding.
	f.anaPolicy(tenantID, "Clean", anaDocument(allow(items("documents:*"), items("documents/*"))))
	f.anaRole(tenantID, "Inline", "document", anaDocument(core.NewObject(
		"effect", "deny", "actions", items("documents:write"), "resources", items("documents/*"),
		"conditions", body("StringEquals", body("resource.type", "secret")),
	)))
	f.anaRole(tenantID, "Plain", "document", anaPermissions("documents:read"))

	lint := findingsOfKind(findingsOf(t, f, owner, tenantID), "policy-lint")
	var subjects []string
	for _, finding := range lint {
		subjects = append(subjects, jsString(member(finding.Get("subject"), "type"))+":"+jsString(member(finding.Get("subject"), "name")))
	}
	if got := anaSorted(subjects); strings.Join(got, ",") != "policy:Office network,role:Inline" {
		t.Fatalf("lint = %v", got)
	}
	for _, finding := range lint {
		detail := jsString(finding.Get("detail"))
		switch member(finding.Get("subject"), "type") {
		case "policy":
			if finding.Get("severity") != "low" || finding.Get("title") != "Policy Office network has 2 lint warnings" ||
				!strings.Contains(detail, "unknown-context-key, array-key-string-operator") {
				t.Fatalf("policy = %s", stringify(finding))
			}
		case "role":
			if finding.Get("title") != "Role Inline's inline document has 2 lint warnings" ||
				!strings.Contains(detail, "optional-key-deny, unknown-context-key") {
				t.Fatalf("role = %s", stringify(finding))
			}
		}
	}
}

func TestAnalysisReadsTrustFlagsFailClosed(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	role := f.anaRole(tenantID, "Reader", "document", anaPermissions("documents:read"))
	rootIdentity := jsString(member(f.root.Get("identity"), "id"))
	// A cross-tenant identity trust whose stored flags are then replaced (an Undefined value removes one).
	trustWith := func(flags ...any) string {
		trust := core.NewObject("id", ID(), "tenantId", tenantID, "kind", "identity", "sourceTenantId", f.rootTenantID(),
			"sourceIdentityId", rootIdentity, "roleId", anaID(role), "requireMfa", true, "ceiling", All(), "revoked", false,
			"passSourceAttributes", false, "maxSessionSeconds", 3600.0, "authorityId", f.authorities[tenantID],
			"createdAt", f.now(), "createdBy", rootIdentity, "updatedAt", f.now())
		for index := 0; index+1 < len(flags); index += 2 {
			if isUndefined(flags[index+1]) {
				trust.Delete(flags[index].(string))
			} else {
				trust.Set(flags[index].(string), flags[index+1])
			}
		}
		f.seed("trusts", trust)
		return anaID(trust)
	}
	open := trustWith("requireMfa", false, "passSourceAttributes", true)
	legacy := trustWith("requireMfa", core.Undefined, "passSourceAttributes", core.Undefined)
	malformed := trustWith("requireMfa", "no", "passSourceAttributes", "false")
	falsy := trustWith("requireMfa", 0.0, "passSourceAttributes", 1.0)
	report := findingsOf(t, f, owner, tenantID)
	subjects := func(kind string) []string { return anaSorted(subjectField(findingsOfKind(report, kind), "id")) }
	// Only the boolean false waives MFA; a missing or malformed flag requires it, so no finding.
	if got := subjects("trust-without-mfa"); stringify(got) != stringify([]string{open}) {
		t.Fatalf("trust-without-mfa = %v", got)
	}
	// Legacy trusts (no field) pass attributes; a malformed value passes nothing, so no finding.
	if got := subjects("trust-passes-foreign-attributes"); stringify(got) != stringify(anaSorted([]string{open, legacy})) {
		t.Fatalf("trust-passes-foreign-attributes = %v", got)
	}
	if containsString(subjects("trust-passes-foreign-attributes"), malformed) || containsString(subjects("trust-without-mfa"), falsy) {
		t.Fatal("a malformed flag made a finding")
	}
}

// After tests/security-governance.test.ts: analysis suppressions accept a finding as it is.

func TestAnalysisRefusesToSuppressFindingsBeforeTheyExist(t *testing.T) {
	f, tenantID, owner := newAnalysisOrganization(t, nil)
	bot := f.anaServiceAccount(tenantID, "deploy-bot")
	predicted := analysisFindingID("service-account-admin", "identity:"+anaID(bot))
	_, err := f.suppress(owner, tenantID, predicted, "Pre-approved")
	anaRefuse(t, err, "INVALID_INPUT")
	expectError(t, err, "INVALID_INPUT", "Unknown finding ID: only a finding reported now can be suppressed")
	everything := f.anaRole(tenantID, "Everything", "document", anaDocument(allow(items("*"), items("*"))))
	f.anaBinding(tenantID, anaID(everything), "identity", anaID(bot))
	report := findingsOf(t, f, owner, tenantID)
	var finding *core.Object
	for _, entry := range findingList(report) {
		if anaID(entry) == predicted {
			finding = entry
		}
	}
	if finding == nil || finding.Get("kind") != "service-account-admin" || finding.Has("suppressed") {
		t.Fatalf("finding = %s", stringify(finding))
	}
	// Once it exists it can be accepted.
	answer(f.suppress(owner, tenantID, predicted, "Accepted"))
	if containsString(pluck(findingList(findingsOf(t, f, owner, tenantID)), "id"), predicted) {
		t.Fatal("the accepted finding is still listed")
	}
	stored := f.record("analysisSuppressions", tenantID+":"+predicted)
	if stored == nil || stringify(stored.Keys()) != `["id","tenantId","findingId","reason","createdBy","createdAt","fingerprint"]` {
		t.Fatalf("suppression = %s", stringify(stored))
	}
}

func TestAnalysisShowsSuppressedFindingsAgainWhenWorse(t *testing.T) {
	f, tenantID, _ := newAnalysisOrganization(t, nil)
	dan := f.anaIdentity(tenantID, "dan")
	reader := f.anaRole(tenantID, "Reader", "document", anaPermissions("documents:read"))
	writer := f.anaRole(tenantID, "Writer", "document", anaPermissions("documents:write"))
	f.anaBinding(tenantID, anaID(reader), "identity", anaID(dan))
	f.issue(dan, false)
	f.advance(91 * analysisDayMs)
	owner := f.ownerSignIn(tenantID)
	id := analysisFindingID("dormant-access", "identity:"+anaID(dan))
	dormant := func() *core.Object {
		for _, finding := range findingList(findingsOf(t, f, owner, tenantID, "includeSuppressed", true)) {
			if anaID(finding) == id {
				return finding
			}
		}
		return nil
	}
	if finding := dormant(); finding == nil || !strings.Contains(jsString(finding.Get("title")), "91 days") {
		t.Fatalf("dormant = %s", stringify(finding))
	}
	answer(f.suppress(owner, tenantID, id, "Seasonal worker"))
	if finding := dormant(); member(finding.Get("suppressed"), "reason") != "Seasonal worker" {
		t.Fatalf("suppressed = %s", stringify(finding))
	}

	// Another day of dormancy changes the title, not what was accepted.
	f.advance(analysisDayMs)
	if finding := dormant(); !strings.Contains(jsString(finding.Get("title")), "92 days") ||
		member(finding.Get("suppressed"), "reason") != "Seasonal worker" {
		t.Fatalf("a day later = %s", stringify(finding))
	}

	// More access on the dormant account is a different risk: it shows again.
	f.anaBinding(tenantID, anaID(writer), "identity", anaID(dan))
	worse := dormant()
	if !strings.Contains(jsString(worse.Get("detail")), "2 role binding(s)") || worse.Has("suppressed") {
		t.Fatalf("worse = %s", stringify(worse))
	}
	report := findingsOf(t, f, owner, tenantID)
	if !containsString(pluck(findingList(report), "id"), id) || stringify(member(report.Get("summary"), "suppressed")) != "0" {
		t.Fatalf("report = %s", stringify(report.Get("summary")))
	}
}

// After tests/policy-lint.test.ts: analysis.lintPolicy.

func lintPolicyCall(f *directoryFixture, credential core.CredentialInput, pairs ...any) (Out[apitypes.AnalysisLintPolicyOutput], error) {
	return f.iam.API.Analysis.LintPolicy(f.ctx, credential, Input[apitypes.AnalysisLintPolicyInput](body(pairs...)))
}

func newLintFixture(t *testing.T) (*directoryFixture, string, core.CredentialInput) {
	t.Helper()
	return newAnalysisOrganization(t, func(options *BetterIamOptions) {
		options.Permissions = &core.PermissionsConfig{
			Actions:            []string{"documents:read", "documents:write"},
			IdentityAttributes: []core.NamedAttribute{{Name: "department", Type: "string"}},
		}
	})
}

var lintNetwork = anaDocument(allow(items("documents:read"), items("*"), "conditions", body("IpAddress", body("request.ip", "10.0.0.0/8"))))

func TestAnalysisLintPolicyLintsCandidatesAndStoredPolicies(t *testing.T) {
	f, tenantID, owner := newLintFixture(t)
	out, err := lintPolicyCall(f, owner, "tenantId", tenantID, "document", lintNetwork)
	candidate := anaTryObject(t, out, err)
	warnings := anaObjects(candidate.Get("warnings"))
	if candidate.Get("valid") != true || len(warnings) != 1 || warnings[0].Get("code") != "unknown-context-key" ||
		stringify(warnings[0].Get("statement")) != "0" {
		t.Fatalf("candidate = %s", stringify(candidate))
	}
	// Keys the application supplies are declared per call; identity attributes come from configuration.
	out, err = lintPolicyCall(f, owner, "tenantId", tenantID, "document", lintNetwork, "contextKeys", items("request.ip"))
	if got := stringify(anaTryObject(t, out, err)); got != `{"valid":true,"warnings":[]}` {
		t.Fatalf("with context keys = %s", got)
	}
	out, err = lintPolicyCall(f, owner, "tenantId", tenantID, "document",
		anaDocument(allow(items("documents:read"), items("*"), "conditions", body("StringEquals", body("principal.department", "x")))))
	if got := stringify(anaTryObject(t, out, err)); got != `{"valid":true,"warnings":[]}` {
		t.Fatalf("identity attribute = %s", got)
	}
	stored := f.anaPolicy(tenantID, "Office network", lintNetwork)
	out, err = lintPolicyCall(f, owner, "tenantId", tenantID, "policyId", anaID(stored))
	if got := stringify(anaTryObject(t, out, err)); got != stringify(candidate) {
		t.Fatalf("stored = %s", got)
	}
}

func TestAnalysisLintPolicyReportsInvalidDocuments(t *testing.T) {
	f, tenantID, owner := newLintFixture(t)
	stored := f.anaPolicy(tenantID, "Office network", lintNetwork)
	_, err := lintPolicyCall(f, owner, "tenantId", tenantID, "policyId", "no-such-policy")
	expectCode(t, err, "NOT_FOUND")

	// Structural and catalog validation turn into an invalid result without warnings. Catalog validation runs first,
	// so a document naming unknown actions is rejected before any pattern matching.
	invalid := answerObject(lintPolicyCall(f, owner, "tenantId", tenantID, "document", body("version", 1.0)))
	if invalid.Get("valid") != false || member(invalid.Get("error"), "code") != "INVALID_POLICY" || stringify(invalid.Get("warnings")) != `[]` {
		t.Fatalf("invalid = %s", stringify(invalid))
	}
	if got := stringify(answer(lintPolicyCall(f, owner, "tenantId", tenantID, "document", anaDocument(
		allow(items("documents:delete"), items("*"), "conditions", body("IpAddress", body("request.ip", "10.0.0.0/8"))),
	)))); got != `{"valid":false,"error":{"code":"INVALID_ACTION","message":"Unknown action documents:delete"},"warnings":[]}` {
		t.Fatalf("unknown action = %s", got)
	}
	many := make([]*core.Object, 0, 30)
	x := make([]any, 128)
	for index := range x {
		x[index] = "x"
	}
	for index := 0; index < 29; index++ {
		many = append(many, allow(x, x))
	}
	many = append(many, core.NewObject("effect", "deny", "actions", items("*"), "resources", items("*")))
	if got := stringify(answer(lintPolicyCall(f, owner, "tenantId", tenantID, "document", anaDocument(many...)))); got != `{"valid":false,"error":{"code":"INVALID_ACTION","message":"Unknown action x"},"warnings":[]}` {
		t.Fatalf("many = %s", got)
	}

	// Exactly one of document and policyId.
	_, err = lintPolicyCall(f, owner, "tenantId", tenantID)
	expectError(t, err, "INVALID_INPUT", "Provide either a document or a policyId")
	_, err = lintPolicyCall(f, owner, "tenantId", tenantID, "document", lintNetwork, "policyId", anaID(stored))
	expectError(t, err, "INVALID_INPUT", "Provide either a document or a policyId")
	_, err = lintPolicyCall(f, owner, "tenantId", tenantID, "policyId", "")
	expectError(t, err, "INVALID_INPUT", "Invalid policyId")
	_, err = lintPolicyCall(f, owner, "tenantId", tenantID, "document", lintNetwork, "contextKeys", "request.ip")
	expectError(t, err, "INVALID_INPUT", "Invalid contextKeys")

	// Members without iam:policies:read cannot lint.
	_, bob := f.anaMember(tenantID, "bob")
	_, err = lintPolicyCall(f, bob, "tenantId", tenantID, "document", lintNetwork)
	expectCode(t, err, "ACCESS_DENIED")
	expectStatus(t, err, 403)
	_, err = lintPolicyCall(f, bob, "tenantId", tenantID, "policyId", anaID(stored))
	expectStatus(t, err, 403)
}
