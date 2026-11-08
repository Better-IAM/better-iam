package server

// Tests of threats.go and threat_response.go: the rule catalog and settings resolution, risk scoring and decay, the
// policy risk context, containment marks, and the response primitives (ports of the response scenarios of
// tests/threats-engine.test.ts, tests/threats-api.test.ts and tests/threats-clearances.test.ts, driven through
// applyResponse / releaseIdentity directly because the threats API group and the engine are other units). The
// fixture is the identities fixture (root tenant, an owner, the bootstrapped root administrator) plus an
// organization tenant under the root for the network and automatic cases.

import (
	"context"
	"math"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestThreatRuleCatalogAndSettings(t *testing.T) {
	if len(ThreatRules) != ThreatRuleIDs.Len() || len(ThreatRules) != 22 {
		t.Fatalf("catalog has %d rules, ids %d", len(ThreatRules), ThreatRuleIDs.Len())
	}
	for index, id := range ThreatRuleIDs.Values() {
		if ThreatRules[index].Get("id") != id {
			t.Fatalf("rule %d is %v, want %s", index, ThreatRules[index].Get("id"), id)
		}
	}
	spray := must(ThreatRule("password-spray"))
	text, _, _ := core.Stringify(spray)
	want := `{"id":"password-spray","title":"Password spray","description":"One network fails password sign-ins for many different people in a short window: someone is trying common passwords across accounts.","category":"sign-in","severity":"high","subject":"network","threshold":10,"windowMs":900000,"tunable":{"threshold":[3,1000],"windowMs":[60000,86400000]},"enabledByDefault":true,"technique":"T1110.003"}`
	if text != want {
		t.Fatalf("password-spray:\n%s\nwant\n%s", text, want)
	}
	persistence := must(ThreatRule("account-takeover-persistence"))
	if text, _, _ := core.Stringify(persistence.Get("tunable")); text != `{"windowMs":[300000,604800000]}` {
		t.Fatalf("persistence tunable %s", text)
	}
	if _, err := ThreatRule("nope"); err == nil || err.Error() != "Unknown threat rule nope" {
		t.Fatalf("unknown rule: %v", err)
	}

	defaults := must(ResolveThreatSettings(nil))
	text, _, _ = core.Stringify(member(defaults.Get("rules"), "brute-force"))
	if text != `{"enabled":true,"severity":"medium","threshold":10,"windowMs":900000}` {
		t.Fatalf("brute-force defaults %s", text)
	}
	text, _, _ = core.Stringify(member(defaults.Get("rules"), "session-hijack"))
	if text != `{"enabled":true,"severity":"high"}` {
		t.Fatalf("session-hijack defaults %s", text)
	}
	rest := defaults.Spread()
	rest.Delete("rules")
	if text, _, _ := core.Stringify(rest); text != `{"trustedNetworks":[],"dormantDays":90,"riskHalfLifeHours":24,"notify":{"owners":false,"emails":[]},"maxAutomaticContainments":3}` {
		t.Fatalf("defaults %s", text)
	}

	// A tenant's own members keep their place (spread), the defaults fill the rest.
	stored := obj(t, `{"id":"t","tenantId":"t","rules":{"brute-force":{"threshold":5,"enabled":false},"new-network":{"everyone":true}},"trustedNetworks":["10.0.0.0/8"],"dormantDays":30,"riskHalfLifeHours":12,"notify":{"owners":true,"emails":["soc@example.test"]},"maxAutomaticContainments":1,"updatedAt":1,"updatedBy":"x"}`)
	resolved := must(ResolveThreatSettings(stored))
	text, _, _ = core.Stringify(member(resolved.Get("rules"), "brute-force"))
	if text != `{"threshold":5,"enabled":false,"severity":"medium","windowMs":900000}` {
		t.Fatalf("brute-force resolved %s", text)
	}
	text, _, _ = core.Stringify(member(resolved.Get("rules"), "new-network"))
	if text != `{"everyone":true,"enabled":true,"severity":"medium"}` {
		t.Fatalf("new-network resolved %s", text)
	}
	if resolved.Get("dormantDays") != 30.0 || resolved.Get("riskHalfLifeHours") != 12.0 || resolved.Get("maxAutomaticContainments") != 1.0 {
		t.Fatalf("resolved %v", resolved)
	}
}

func TestThreatRiskScoring(t *testing.T) {
	const now = int64(1_000_000_000)
	contribution := func(points float64, ageHours float64) *core.Object {
		return core.NewObject("detectionId", "d", "ruleId", "brute-force", "severity", "medium", "points", points, "at", float64(now)-ageHours*threatsHour)
	}
	if score := must(RiskScore([]*core.Object{contribution(50, 0), contribution(50, 0), contribution(25, 0)}, now, 24)); score != 100 {
		t.Fatalf("capped score %v", score)
	}
	if score := must(RiskScore([]*core.Object{contribution(50, 24)}, now, 24)); score != 25 {
		t.Fatalf("one half-life %v", score)
	}
	if score := must(RiskScore([]*core.Object{contribution(25, 12)}, now, 24)); score != 18 {
		t.Fatalf("half a half-life %v", score)
	}
	// A contribution from the future counts in full; a half-life below one hour counts as one hour.
	if score := must(RiskScore([]*core.Object{contribution(10, -5)}, now, 24)); score != 10 {
		t.Fatalf("future %v", score)
	}
	if score := must(RiskScore([]*core.Object{contribution(80, 1)}, now, 0)); score != 40 {
		t.Fatalf("minimum half-life %v", score)
	}
	for score, level := range map[float64]string{0: "none", 9: "none", 10: "low", 39: "low", 40: "medium", 69: "medium", 70: "high", 100: "high"} {
		if got := RiskLevelFor(score); got != level {
			t.Fatalf("level of %v is %s, want %s", score, got, level)
		}
	}
	if !must(RiskLevelAtLeast("high", "medium")) || must(RiskLevelAtLeast("low", "medium")) || must(RiskLevelAtLeast("bogus", "none")) {
		t.Fatal("riskLevelAtLeast")
	}
	if !must(SeverityAtLeast("critical", "high")) || must(SeverityAtLeast("medium", "high")) {
		t.Fatal("severityAtLeast")
	}
	if must(MaxSeverity("low", "high")) != "high" || must(MaxSeverity("critical", "high")) != "critical" || must(MaxSeverity("high", "high")) != "high" {
		t.Fatal("maxSeverity")
	}
	if MaxRiskLevel("none", "low") != "low" || MaxRiskLevel("high", "medium") != "high" {
		t.Fatal("maxRiskLevel")
	}

	if risk := must(EffectiveRisk(nil, now, 24)); risk.Get("score") != 0.0 || risk.Get("level") != "none" {
		t.Fatalf("no record %v", risk)
	}
	record := core.NewObject("id", "i", "tenantId", "t", "identityId", "i", "contributions", []any{contribution(25, 0)}, "score", 25.0, "level", "low")
	if risk := must(EffectiveRisk(record, now, 24)); risk.Get("score") != 25.0 || risk.Get("level") != "low" {
		t.Fatalf("contributions only %v", risk)
	}
	// An unexpired override raises the level and the score to the level's floor; an expired one does not.
	record.Set("override", core.NewObject("level", "high", "reason", "confirmed", "by", "o", "at", 1.0, "expiresAt", float64(now+1)))
	if risk := must(EffectiveRisk(record, now, 24)); risk.Get("score") != 70.0 || risk.Get("level") != "high" {
		t.Fatalf("override %v", risk)
	}
	record.Get("override").(*core.Object).Set("expiresAt", float64(now))
	if risk := must(EffectiveRisk(record, now, 24)); risk.Get("score") != 25.0 || risk.Get("level") != "low" {
		t.Fatalf("expired override %v", risk)
	}
	record.Get("override").(*core.Object).Delete("expiresAt")
	record.Get("override").(*core.Object).Set("level", "medium")
	if risk := must(EffectiveRisk(record, now, 24)); risk.Get("score") != 40.0 || risk.Get("level") != "medium" {
		t.Fatalf("open-ended override %v", risk)
	}
	record.Get("override").(*core.Object).Set("level", "bogus")
	if risk := must(EffectiveRisk(record, now, 24)); !math.IsNaN(jsNumber(risk.Get("score"))) || risk.Get("level") != "bogus" {
		t.Fatalf("unknown override level %v", risk)
	}
}

func TestThreatMentionsRisk(t *testing.T) {
	documents := []any{nil, core.NewObject("version", 1.0, "statements", []any{core.NewObject("effect", "deny", "actions", []any{"*"}, "resources", []any{"*"},
		"condition", core.NewObject("StringEquals", core.NewObject("principal.riskLevel", "high")))})}
	if !MentionsRisk(documents) {
		t.Fatal("risk condition not noticed")
	}
	if MentionsRisk([]any{core.NewObject("version", 1.0, "statements", []any{core.NewObject("effect", "allow", "actions", []any{"*"}, "resources", []any{"*"})})}) {
		t.Fatal("risk noticed where there is none")
	}
}

// threatFixture is the identities fixture with an organization tenant under the root.
type threatFixture struct {
	*identitiesFixture
	orgID string
}

func newThreatFixture(t *testing.T, mutate func(options *BetterIamOptions)) *threatFixture {
	t.Helper()
	f := &threatFixture{identitiesFixture: newIdentitiesFixture(t, mutate), orgID: "org-acme"}
	f.seed("tenants", core.NewObject("id", f.orgID, "tenantId", f.orgID, "name", "Acme", "type", "organization",
		"parentId", f.tenantID, "status", "active", "createdAt", 2.0))
	return f
}

func (f *threatFixture) server() *ServerContext { return f.iam.Context }

// principal is a principal for an identity with a fresh session.
func (f *threatFixture) principal(identity *core.Object, mfa bool) *Principal {
	_, session := f.signIn(identity, mfa)
	return &Principal{Identity: f.get("identities", jsString(identity.Get("id"))), Session: session}
}

func (f *threatFixture) settings(stored string) *core.Object {
	if stored == "" {
		return must(ResolveThreatSettings(nil))
	}
	return must(ResolveThreatSettings(obj(f.t, stored)))
}

// respond runs applyResponse in a transaction.
func (f *threatFixture) respond(tenantID string, request *core.Object, settings, brake *core.Object) (*core.Object, error) {
	return core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return ApplyResponse(ctx, f.server(), tx, tenantID, request, settings, brake)
	})
}

func (f *threatFixture) release(tenantID, identityID string, actor *core.Object, note string) (*core.Object, error) {
	return core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return ReleaseIdentity(ctx, f.server(), tx, tenantID, identityID, actor, note)
	})
}

// threatRequest builds a ResponseRequest about an identity (or anything else with subjectType/subjectID).
func threatRequest(kind, subjectType, subjectID string, actor *core.Object, members ...any) *core.Object {
	request := core.NewObject("action", core.NewObject("kind", kind), "subject", core.NewObject("type", subjectType, "id", subjectID))
	for index := 0; index+1 < len(members); index += 2 {
		key := members[index].(string)
		if key == "durationMs" || key == "keepApiKeys" {
			request.Get("action").(*core.Object).Set(key, members[index+1])
			continue
		}
		request.Set(key, members[index+1])
	}
	if !request.Has("reason") {
		request.Set("reason", "smoke")
	}
	request.SetRaw("actor", actor)
	return request
}

func (f *threatFixture) countAudit(tenantID, action string) int {
	count := 0
	for _, event := range f.find("audit", core.NewObject("tenantId", tenantID, "action", action)) {
		_ = event
		count++
	}
	return count
}

func expectOutcome(t *testing.T, response *core.Object, err error, outcome, reason string) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if response.Get("outcome") != outcome || (reason != "" && response.Get("reason") != reason) || (reason == "" && response.Has("reason")) {
		t.Fatalf("response %v, want %s %s", response, outcome, reason)
	}
}

func TestThreatContainAndRelease(t *testing.T) {
	f := newThreatFixture(t, nil)
	owner := ThreatManualActor(f.principal(f.owner, false))
	settings := f.settings("")
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	_, aliceSession := f.signIn(alice, false)
	f.seed("sessions", session("alice-key", aliceID, f.tenantID, "api-key"))
	f.seed("authDevices", core.NewObject("id", "alice-device", "tenantId", f.tenantID, "identityId", aliceID, "createdAt", 1.0))

	contained, err := f.respond(f.tenantID, threatRequest("contain", "identity", aliceID, owner, "incidentId", "inc-1"), settings, nil)
	expectOutcome(t, contained, err, "applied", "")
	if text, _, _ := core.Stringify(contained.Get("details")); text != `{"sessionsEnded":1}` {
		t.Fatalf("details %s", text)
	}
	if keys := contained.Keys(); jsString(stringsOf(keys)) != "id,tenantId,action,subject,outcome,incidentId,actorId,details,createdAt" {
		t.Fatalf("response members %v", keys)
	}
	if text, _, _ := core.Stringify(contained.Get("subject")); text != `{"type":"identity","id":"`+aliceID+`","name":"alice"}` {
		t.Fatalf("subject %s", text)
	}
	if f.get("identities", aliceID).Get("status") != "disabled" {
		t.Fatal("alice not disabled")
	}
	if f.get("sessions", jsString(aliceSession.Get("id"))) != nil || f.get("sessions", "alice-key") == nil {
		t.Fatal("sessions: the user session ends, the API key stays")
	}
	if f.get("authDevices", "alice-device") != nil {
		t.Fatal("remembered device kept")
	}
	risk := f.get("identityRisk", aliceID)
	if text, _, _ := core.Stringify(risk.Get("contained")); text != `{"at":`+jsString(f.now())+`,"by":"`+f.ownerID+`","reason":"smoke","incidentId":"inc-1"}` {
		t.Fatalf("contained mark %s", text)
	}
	if risk.Get("level") != "none" || risk.Get("score") != 0.0 {
		t.Fatalf("new risk record %v", risk)
	}
	events := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:contain"))
	if len(events) != 1 || events[0].Get("actorId") != f.ownerID {
		t.Fatalf("contain events %v", events)
	}
	if text, _, _ := core.Stringify(events[0].Get("metadata")); text != `{"reason":"smoke","sessionsEnded":1,"incidentId":"inc-1"}` {
		t.Fatalf("contain metadata %s", text)
	}

	again, err := f.respond(f.tenantID, threatRequest("contain", "identity", aliceID, owner), settings, nil)
	expectOutcome(t, again, err, "skipped", "already-applied")
	_, err = f.respond(f.tenantID, threatRequest("contain", "identity", f.ownerID, owner), settings, nil)
	expectError(t, err, "INVALID_INPUT", "You cannot contain yourself")
	missing, err := f.respond(f.tenantID, threatRequest("contain", "tenant", f.tenantID, owner), settings, nil)
	expectOutcome(t, missing, err, "skipped", "not-identity")
	_, err = f.respond(f.tenantID, threatRequest("contain", "identity", "nobody", owner), settings, nil)
	expectError(t, err, "NOT_FOUND", "Resource not found")

	released, err := f.release(f.tenantID, aliceID, owner, "  ok  ")
	if err != nil {
		t.Fatal(err)
	}
	if released.Get("action") != "release" || released.Get("outcome") != "applied" || released.Get("incidentId") != "inc-1" {
		t.Fatalf("release %v", released)
	}
	if text, _, _ := core.Stringify(released.Get("details")); text != `{"note":"ok"}` {
		t.Fatalf("release details %s", text)
	}
	if f.get("identities", aliceID).Get("status") != "active" || f.get("identityRisk", aliceID).Has("contained") {
		t.Fatal("not released")
	}
	releaseEvents := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:release"))
	if text, _, _ := core.Stringify(releaseEvents[0].Get("metadata")); len(releaseEvents) != 1 || text != `{"note":"ok","containedAt":`+jsString(f.now())+`,"incidentId":"inc-1"}` {
		t.Fatalf("release metadata %s", text)
	}
	_, err = f.release(f.tenantID, aliceID, owner, "")
	expectError(t, err, "INVALID_TRANSITION", "The identity is not contained")
	idAfterChange(t, AfterThreatResponses(f.ctx, f.server(), f.tenantID, []*core.Object{contained, released}))
}

func TestThreatNeverReleasesWhatAnotherPathChanged(t *testing.T) {
	f := newThreatFixture(t, nil)
	owner := ThreatManualActor(f.principal(f.owner, false))
	settings := f.settings("")
	contain := func(identityID string) {
		t.Helper()
		response, err := f.respond(f.tenantID, threatRequest("contain", "identity", identityID, owner), settings, nil)
		expectOutcome(t, response, err, "applied", "")
	}

	// Re-enabled by another path (which ends the containment), then disabled for another reason.
	carol := jsString(f.member("carol").Get("id"))
	contain(carol)
	carolRecord := f.get("identities", carol)
	if err := f.iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		if _, err := tx.Put(ctx, "identities", carolRecord.Spread(core.NewObject("status", "active"))); err != nil {
			return err
		}
		return EndContainment(ctx, tx, carol, f.server().Now())
	}); err != nil {
		t.Fatal(err)
	}
	if f.get("identityRisk", carol).Has("contained") {
		t.Fatal("containment mark kept")
	}
	f.seed("identities", f.get("identities", carol).Spread(core.NewObject("status", "disabled")))
	_, err := f.release(f.tenantID, carol, owner, "")
	expectError(t, err, "INVALID_TRANSITION", "The identity is not contained")
	// EndContainment leaves an identity that is not contained alone.
	if err := f.iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		return EndContainment(ctx, tx, "nobody", f.server().Now())
	}); err != nil {
		t.Fatal(err)
	}

	// A suspended agent is held by its kill switch.
	agent := jsString(f.member("agent").Get("id"))
	contain(agent)
	f.seed("identities", f.get("identities", agent).Spread(core.NewObject("agent", core.NewObject("suspended", core.NewObject("at", 1.0)))))
	_, err = f.release(f.tenantID, agent, owner, "")
	expectError(t, err, "INVALID_TRANSITION", "The identity is not contained")

	// An identity that expired while contained is released only once its expiry moves.
	erin := jsString(f.member("erin").Get("id"))
	contain(erin)
	f.seed("identities", f.get("identities", erin).Spread(core.NewObject("expiresAt", f.now()-1)))
	_, err = f.release(f.tenantID, erin, owner, "")
	expectError(t, err, "INVALID_TRANSITION", "Extend or clear expiresAt before releasing an expired identity")

	// A containment nothing else touched is still released.
	dave := jsString(f.member("dave").Get("id"))
	contain(dave)
	released, err := f.release(f.tenantID, dave, owner, "")
	if err != nil || released.Get("outcome") != "applied" || released.Has("details") || released.Has("incidentId") {
		t.Fatalf("release %v %v", released, err)
	}
	if f.get("identities", dave).Get("status") != "active" {
		t.Fatal("dave not active")
	}
}

func TestThreatContainProtections(t *testing.T) {
	f := newThreatFixture(t, nil)
	settings := f.settings("")
	coOwner := f.member("coowner")
	coOwnerID := jsString(coOwner.Get("id"))
	f.seed("identities", coOwner.Spread(core.NewObject("owner", true)))
	analyst := f.member("analyst")
	f.grant("analyst", "identity", jsString(analyst.Get("id")), "iam:threats:*", "iam:identities:*")
	analystActor := ThreatManualActor(f.principal(analyst, false))

	// An owner is contained only by an owner in person or root.
	_, err := f.respond(f.tenantID, threatRequest("contain", "identity", coOwnerID, analystActor), settings, nil)
	expectError(t, err, "ACCESS_DENIED", "Only an owner can contain an owner")
	if f.get("identities", coOwnerID).Get("status") != "active" {
		t.Fatal("co-owner disabled")
	}
	owner := ThreatManualActor(f.principal(f.owner, false))
	contained, err := f.respond(f.tenantID, threatRequest("contain", "identity", coOwnerID, owner), settings, nil)
	expectOutcome(t, contained, err, "applied", "")
	// The last active owner never is.
	root := f.principal(f.rootIdentity, true)
	_, err = f.respond(f.tenantID, threatRequest("contain", "identity", f.ownerID, ThreatManualActor(root)), settings, nil)
	expectError(t, err, "LAST_OWNER", "Cannot remove the final active owner")
	// A root administrator only by root.
	_, err = f.respond(f.tenantID, threatRequest("contain", "identity", jsString(f.rootIdentity.Get("id")), owner), settings, nil)
	expectError(t, err, "ACCESS_DENIED", "Root capability is protected")
	_, err = f.respond(f.tenantID, threatRequest("revoke-sessions", "identity", jsString(f.rootIdentity.Get("id")), owner), settings, nil)
	expectError(t, err, "ACCESS_DENIED", "Root capability is protected")

	// Automatic responses skip owners and root administrators.
	automatic := ThreatAutomaticActor()
	protected, err := f.respond(f.tenantID, threatRequest("contain", "identity", f.ownerID, automatic), settings, nil)
	expectOutcome(t, protected, err, "skipped", "protected")
	protected, err = f.respond(f.tenantID, threatRequest("contain", "identity", jsString(f.rootIdentity.Get("id")), automatic), settings, nil)
	expectOutcome(t, protected, err, "skipped", "protected")
	if protected.Get("actorId") != ThreatActor {
		t.Fatalf("automatic actor %v", protected.Get("actorId"))
	}
	notFound, err := f.respond(f.tenantID, threatRequest("contain", "identity", "nobody", automatic), settings, nil)
	expectOutcome(t, notFound, err, "skipped", "not-found")
	inactive, err := f.respond(f.tenantID, threatRequest("contain", "identity", coOwnerID, automatic), settings, nil)
	expectOutcome(t, inactive, err, "skipped", "already-applied")
	// Identity actions about another subject fall back to identityId.
	bob := jsString(f.member("bob").Get("id"))
	f.seed("identities", f.get("identities", bob).Spread(core.NewObject("status", "disabled")))
	viaIdentity, err := f.respond(f.tenantID, threatRequest("contain", "tenant", f.tenantID, automatic, "identityId", bob), settings, nil)
	expectOutcome(t, viaIdentity, err, "skipped", "inactive")
}

func TestThreatContainmentBrake(t *testing.T) {
	f := newThreatFixture(t, nil)
	settings := f.settings(`{"rules":{},"maxAutomaticContainments":1}`)
	brake := core.NewObject("contained", 0.0)
	automatic := ThreatAutomaticActor()
	erin := jsString(f.member("erin").Get("id"))
	frank := jsString(f.member("frank").Get("id"))
	gina := jsString(f.member("gina").Get("id"))

	first, err := f.respond(f.tenantID, threatRequest("contain", "identity", erin, automatic, "playbookId", "pb-1"), settings, brake)
	expectOutcome(t, first, err, "applied", "")
	if first.Get("playbookId") != "pb-1" || first.Get("actorId") != ThreatActor {
		t.Fatalf("first %v", first)
	}
	second, err := f.respond(f.tenantID, threatRequest("contain", "identity", frank, automatic, "playbookId", "pb-1"), settings, brake)
	expectOutcome(t, second, err, "skipped", "braked")
	third, err := f.respond(f.tenantID, threatRequest("contain", "identity", gina, automatic, "playbookId", "pb-1"), settings, brake)
	expectOutcome(t, third, err, "skipped", "braked")
	if brake.Get("contained") != 1.0 || brake.Get("braked") != 2.0 {
		t.Fatalf("brake %v", brake)
	}
	braked := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:response-braked"))
	if len(braked) != 1 || braked[0].Get("resourceId") != "threats/playbooks/pb-1" || braked[0].Get("actorId") != ThreatActor {
		t.Fatalf("braked events %v", braked)
	}
	if text, _, _ := core.Stringify(braked[0].Get("metadata")); text != `{"threshold":1,"identityId":"`+frank+`","playbookId":"pb-1"}` {
		t.Fatalf("braked metadata %s", text)
	}
	if braked[0].Get("timestamp") != float64(f.server().Now()) || braked[0].Get("outcome") != "allow" {
		t.Fatalf("automatic audit %v", braked[0])
	}
	if f.countAudit(f.tenantID, "threat:contain") != 1 || f.get("identities", frank).Get("status") != "active" {
		t.Fatal("brake did not hold")
	}
}

func TestThreatRevokeSessionsAndForgetDevices(t *testing.T) {
	f := newThreatFixture(t, nil)
	settings := f.settings("")
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	self := f.principal(alice, false)
	_, other := f.signIn(alice, false)
	f.seed("sessions", session("alice-key", aliceID, f.tenantID, "api-key"),
		session("alice-role", "someone", f.orgID, "role", "originalIdentityId", aliceID))
	f.seed("authChallenges", core.NewObject("id", "alice-challenge", "tenantId", f.tenantID, "identityId", aliceID, "expiresAt", 9e15))

	// A person revoking their own sessions keeps the one they respond from; API keys stay by default.
	revoked, err := f.respond(f.tenantID, threatRequest("revoke-sessions", "identity", aliceID, ThreatManualActor(self)), settings, nil)
	expectOutcome(t, revoked, err, "applied", "")
	if text, _, _ := core.Stringify(revoked.Get("details")); text != `{"revoked":2,"keptApiKeys":true}` {
		t.Fatalf("details %s", text)
	}
	if f.get("sessions", jsString(self.Session.Get("id"))) == nil || f.get("sessions", jsString(other.Get("id"))) != nil ||
		f.get("sessions", "alice-key") == nil || f.get("sessions", "alice-role") != nil || f.get("authChallenges", "alice-challenge") != nil {
		t.Fatal("wrong sessions revoked")
	}
	events := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:revoke-sessions"))
	if text, _, _ := core.Stringify(events[0].Get("metadata")); text != `{"revoked":2,"keptApiKeys":true,"reason":"smoke"}` {
		t.Fatalf("metadata %s", text)
	}
	// keepApiKeys: false ends the keys too.
	all, err := f.respond(f.tenantID, threatRequest("revoke-sessions", "identity", aliceID, ThreatAutomaticActor(), "keepApiKeys", false, "reason", "   "), settings, nil)
	expectOutcome(t, all, err, "applied", "")
	if f.get("sessions", "alice-key") != nil || f.get("sessions", jsString(self.Session.Get("id"))) != nil {
		t.Fatal("keys or sessions kept")
	}
	events = f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:revoke-sessions"))
	defaulted := false
	for _, event := range events {
		if member(event.Get("metadata"), "keptApiKeys") == false {
			defaulted = member(event.Get("metadata"), "reason") == "Threat response" && event.Get("actorId") == ThreatActor
		}
	}
	if len(events) != 2 || !defaulted {
		t.Fatal("blank reason not defaulted")
	}

	f.seed("authDevices", core.NewObject("id", "d1", "tenantId", f.tenantID, "identityId", aliceID, "createdAt", 1.0),
		core.NewObject("id", "d2", "tenantId", f.tenantID, "identityId", aliceID, "createdAt", 1.0))
	forgot, err := f.respond(f.tenantID, threatRequest("forget-devices", "identity", aliceID, ThreatAutomaticActor()), settings, nil)
	expectOutcome(t, forgot, err, "applied", "")
	if text, _, _ := core.Stringify(forgot.Get("details")); text != `{"removed":2}` || len(f.find("authDevices", core.NewObject("identityId", aliceID))) != 0 {
		t.Fatalf("forget %s", text)
	}
	skipped, err := f.respond(f.tenantID, threatRequest("forget-devices", "network", "198.51.100.1", ThreatAutomaticActor()), settings, nil)
	expectOutcome(t, skipped, err, "skipped", "not-identity")

	_, err = f.respond(f.tenantID, threatRequest("explode", "identity", aliceID, ThreatAutomaticActor()), settings, nil)
	expectError(t, err, "INVALID_INPUT", "Unknown response action")
}

func TestThreatBlockNetwork(t *testing.T) {
	f := newThreatFixture(t, nil)
	settings := f.settings(`{"rules":{},"trustedNetworks":["203.0.113.0/24"]}`)
	owner := ThreatManualActor(f.principal(f.owner, false))
	root := ThreatManualActor(f.principal(f.rootIdentity, true))
	automatic := ThreatAutomaticActor()
	blocks := func(tenantID string) []string {
		var networks []string
		for _, block := range f.find("authBlocks", core.NewObject("tenantId", tenantID)) {
			networks = append(networks, jsString(block.Get("network")))
		}
		return networks
	}

	// The root tenant's blocks are root's: refused for an owner, skipped for playbooks, applied for root.
	_, err := f.respond(f.tenantID, threatRequest("block-network", "network", "198.51.100.0/24", owner, "durationMs", 30*threatsDay), settings, nil)
	expectError(t, err, "ACCESS_DENIED", "Blocks on the root tenant are set by root administrators")
	skipped, err := f.respond(f.tenantID, threatRequest("block-network", "network", "198.51.100.0/24", automatic), settings, nil)
	expectOutcome(t, skipped, err, "skipped", "protected")
	byRoot, err := f.respond(f.tenantID, threatRequest("block-network", "network", "198.51.100.0/24", root, "durationMs", 60_000.0), settings, nil)
	expectOutcome(t, byRoot, err, "applied", "")
	if got := blocks(f.tenantID); len(got) != 1 || got[0] != "198.51.100.0/24" {
		t.Fatalf("root blocks %v", got)
	}

	// An organization: trusted networks are skipped, blocks are kept, a covering block makes another redundant.
	trusted, err := f.respond(f.orgID, threatRequest("block-network", "identity", "x", automatic, "network", " 203.0.113.7 "), settings, nil)
	expectOutcome(t, trusted, err, "skipped", "trusted-network")
	if text, _, _ := core.Stringify(trusted.Get("subject")); text != `{"type":"network","id":"203.0.113.7"}` {
		t.Fatalf("trusted subject %s", text)
	}
	none, err := f.respond(f.orgID, threatRequest("block-network", "identity", "x", automatic), settings, nil)
	expectOutcome(t, none, err, "skipped", "no-network")
	invalid, err := f.respond(f.orgID, threatRequest("block-network", "network", "not-an-ip", automatic), settings, nil)
	expectOutcome(t, invalid, err, "skipped", "invalid-network")
	_, err = f.respond(f.orgID, threatRequest("block-network", "network", "not-an-ip", root), settings, nil)
	expectError(t, err, "INVALID_INPUT", "network must be an IPv4/IPv6 address or CIDR block")
	_, err = f.respond(f.orgID, threatRequest("block-network", "network", "192.0.2.9", root, "durationMs", 1000.0), settings, nil)
	expectError(t, err, "INVALID_INPUT", "Invalid durationMs")

	blocked, err := f.respond(f.orgID, threatRequest("block-network", "network", "192.0.2.9", root, "durationMs", 3_600_000.0, "incidentId", "inc-9"), settings, nil)
	expectOutcome(t, blocked, err, "applied", "")
	stored := f.find("authBlocks", core.NewObject("tenantId", f.orgID))
	if len(stored) != 1 {
		t.Fatalf("org blocks %v", stored)
	}
	expiresAt := f.now() + 3_600_000
	if text, _, _ := core.Stringify(stored[0]); text != `{"id":"`+jsString(stored[0].Get("id"))+`","tenantId":"`+f.orgID+`","network":"192.0.2.9","reason":"threat: smoke","createdAt":`+jsString(f.now())+`,"createdBy":"`+jsString(f.rootIdentity.Get("id"))+`","expiresAt":`+jsString(expiresAt)+`}` {
		t.Fatalf("block %s", text)
	}
	if text, _, _ := core.Stringify(blocked.Get("details")); text != `{"network":"192.0.2.9","blockId":"`+jsString(stored[0].Get("id"))+`","expiresAt":`+jsString(expiresAt)+`,"renewed":false}` {
		t.Fatalf("details %s", text)
	}
	events := f.find("audit", core.NewObject("tenantId", f.orgID, "action", "threat:block-network"))
	if len(events) != 1 || events[0].Get("resourceId") != "threats/networks/192.0.2.9" {
		t.Fatalf("block events %v", events)
	}
	if text, _, _ := core.Stringify(events[0].Get("metadata")); text != `{"network":"192.0.2.9","expiresAt":`+jsString(expiresAt)+`,"renewed":false,"reason":"smoke","incidentId":"inc-9"}` {
		t.Fatalf("block metadata %s", text)
	}
	redundant, err := f.respond(f.orgID, threatRequest("block-network", "network", "192.0.2.9", automatic, "durationMs", 60_000.0), settings, nil)
	expectOutcome(t, redundant, err, "skipped", "already-applied")
	// A longer block renews the same record; playbooks clamp their duration.
	renewed, err := f.respond(f.orgID, threatRequest("block-network", "network", "192.0.2.9", automatic, "durationMs", 90*threatsDay), settings, nil)
	expectOutcome(t, renewed, err, "applied", "")
	if member(renewed.Get("details"), "renewed") != true || member(renewed.Get("details"), "expiresAt") != f.now()+30*threatsDay {
		t.Fatalf("renewed %v", renewed.Get("details"))
	}
	if len(f.find("authBlocks", core.NewObject("tenantId", f.orgID))) != 1 {
		t.Fatal("renewal added a block")
	}
	// A platform block covering the network makes an organization's redundant.
	f.seed("authBlocks", core.NewObject("id", "platform-block", "tenantId", f.tenantID, "platform", true, "network", "100.64.0.0/10", "reason", "x", "createdAt", 1.0, "createdBy", "r"))
	covered, err := f.respond(f.orgID, threatRequest("block-network", "network", "100.64.1.0/24", automatic), settings, nil)
	expectOutcome(t, covered, err, "skipped", "already-applied")
	// Never the responder's own address.
	rootPrincipal := f.principal(f.rootIdentity, true)
	rootPrincipal.Session = rootPrincipal.Session.Spread(core.NewObject("client", core.NewObject("ip", "198.18.0.5")))
	_, err = f.respond(f.orgID, threatRequest("block-network", "network", "198.18.0.0/16", ThreatManualActor(rootPrincipal)), settings, nil)
	expectError(t, err, "INVALID_INPUT", "That network includes your own address")
}

func TestThreatNotify(t *testing.T) {
	f := newThreatFixture(t, nil)
	settings := f.settings(`{"rules":{},"notify":{"owners":true,"emails":["SOC@example.test","owner@example.test"]}}`)
	automatic := ThreatAutomaticActor()
	f.seed("threatDetections", core.NewObject("id", "det-1", "tenantId", f.tenantID, "ruleId", "audit-tampering", "summary", "The chain broke."))
	incident := core.NewObject("id", "inc-1", "tenantId", f.tenantID, "subject", core.NewObject("type", "tenant", "id", f.tenantID),
		"severity", "high", "title", "Audit trail tampering", "status", "open", "detectionIds", []any{"det-1"}, "detectionCount", 1.0)
	f.seed("threatIncidents", incident)

	noIncident, err := f.respond(f.tenantID, threatRequest("notify", "tenant", f.tenantID, automatic), settings, nil)
	expectOutcome(t, noIncident, err, "skipped", "no-incident")
	noRecipients, err := f.respond(f.tenantID, threatRequest("notify", "tenant", f.tenantID, automatic, "incidentId", "inc-1"), f.settings(""), nil)
	expectOutcome(t, noRecipients, err, "skipped", "no-recipients")

	sent, err := f.respond(f.tenantID, threatRequest("notify", "tenant", f.tenantID, automatic, "incidentId", "inc-1"), settings, nil)
	expectOutcome(t, sent, err, "applied", "")
	if text, _, _ := core.Stringify(sent.Get("details")); text != `{"recipients":2,"severity":"high"}` {
		t.Fatalf("details %s", text)
	}
	events := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:notify"))
	if len(events) != 1 || events[0].Get("resourceId") != "threats/incidents/inc-1" {
		t.Fatalf("notify events %v", events)
	}
	if text, _, _ := core.Stringify(events[0].Get("metadata")); text != `{"recipients":2,"severity":"high","incidentId":"inc-1"}` {
		t.Fatalf("notify metadata %s", text)
	}
	// Playbooks email an incident once, and again when its severity rose.
	again, err := f.respond(f.tenantID, threatRequest("notify", "tenant", f.tenantID, automatic, "incidentId", "inc-1"), settings, nil)
	expectOutcome(t, again, err, "skipped", "already-applied")
	f.seed("threatIncidents", incident.Spread(core.NewObject("severity", "critical")))
	raised, err := f.respond(f.tenantID, threatRequest("notify", "tenant", f.tenantID, automatic, "incidentId", "inc-1"), settings, nil)
	expectOutcome(t, raised, err, "applied", "")
	// People may always send it again.
	owner := ThreatManualActor(f.principal(f.owner, false))
	manual, err := f.respond(f.tenantID, threatRequest("notify", "tenant", f.tenantID, owner, "incidentId", "inc-1"), settings, nil)
	expectOutcome(t, manual, err, "applied", "")

	if _, err := f.iam.Auth.DispatchOutbox(f.ctx, 100); err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	var alerts []string
	for _, message := range f.mail {
		if message.Template == "threat-alert" {
			alerts = append(alerts, message.To)
			if message.Payload["summary"] != "The chain broke." || message.Payload["tenantName"] != jsString(f.get("tenants", f.tenantID).Get("name")) || message.Payload["detections"] != "1" || message.Payload["subjectType"] != "tenant" {
				t.Errorf("payload %v", message.Payload)
			}
		}
	}
	f.mu.Unlock()
	if len(alerts) != 6 {
		t.Fatalf("alerts %v", alerts)
	}

	result, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return NotifyIncident(ctx, f.server(), tx, f.tenantID, incident, settings, nil)
	})
	if err != nil || result.Get("sent") != 2.0 {
		t.Fatalf("notifyIncident %v %v", result, err)
	}
}

func TestThreatNotifyWithoutTransport(t *testing.T) {
	f := newThreatFixture(t, func(options *BetterIamOptions) { options.Authentication.SendEmail = nil })
	settings := f.settings(`{"rules":{},"notify":{"owners":false,"emails":["soc@example.test"]}}`)
	f.seed("threatIncidents", core.NewObject("id", "inc-1", "tenantId", f.tenantID, "subject", core.NewObject("type", "tenant", "id", f.tenantID),
		"severity", "high", "title", "T", "status", "open", "detectionIds", []any{}, "detectionCount", 0.0))
	skipped, err := f.respond(f.tenantID, threatRequest("notify", "tenant", f.tenantID, ThreatAutomaticActor(), "incidentId", "inc-1"), settings, nil)
	expectOutcome(t, skipped, err, "skipped", "no-transport")
	storedIncident := f.get("threatIncidents", "inc-1")
	result, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return NotifyIncident(ctx, f.server(), tx, f.tenantID, storedIncident, settings, nil)
	})
	if err != nil || result.Get("sent") != 0.0 {
		t.Fatalf("notifyIncident %v %v", result, err)
	}
}

func TestThreatSuspendClearance(t *testing.T) {
	off := newThreatFixture(t, nil)
	settings := off.settings("")
	alice := jsString(off.member("alice").Get("id"))
	disabled, err := off.respond(off.tenantID, threatRequest("suspend-clearance", "identity", alice, ThreatAutomaticActor()), settings, nil)
	expectOutcome(t, disabled, err, "skipped", "feature-disabled")
	_, err = off.respond(off.tenantID, threatRequest("suspend-clearance", "identity", alice, ThreatManualActor(off.principal(off.owner, false))), settings, nil)
	expectError(t, err, "FEATURE_DISABLED", "Security clearances are not enabled on this deployment")

	f := newThreatFixture(t, func(options *BetterIamOptions) { options.Clearances = &ClearanceOptions{} })
	settings = f.settings("")
	bob := jsString(f.member("bob").Get("id"))
	automatic := ThreatAutomaticActor()
	none, err := f.respond(f.tenantID, threatRequest("suspend-clearance", "identity", bob, automatic), settings, nil)
	expectOutcome(t, none, err, "skipped", "no-clearance")
	protected, err := f.respond(f.tenantID, threatRequest("suspend-clearance", "identity", f.ownerID, automatic), settings, nil)
	expectOutcome(t, protected, err, "skipped", "protected")
	f.seed("clearances", core.NewObject("id", bob, "tenantId", f.tenantID, "identityId", bob, "level", "secret", "status", "active"))
	suspended, err := f.respond(f.tenantID, threatRequest("suspend-clearance", "identity", bob, automatic, "incidentId", "inc-2", "detectionId", "det-2"), settings, nil)
	expectOutcome(t, suspended, err, "applied", "")
	if suspended.Has("details") {
		t.Fatalf("details %v", suspended)
	}
	record := f.get("clearances", bob)
	if record.Get("status") != "suspended" || member(record.Get("suspended"), "incidentId") != "inc-2" || member(record.Get("suspended"), "by") != ThreatActor {
		t.Fatalf("clearance %v", record)
	}
	history := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "clearance:suspend"))
	if text, _, _ := core.Stringify(history[0].Get("metadata")); len(history) != 1 || text != `{"level":"secret","reason":"smoke","incidentId":"inc-2"}` {
		t.Fatalf("clearance history %s", text)
	}
	response := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:suspend-clearance"))
	if text, _, _ := core.Stringify(response[0].Get("metadata")); len(response) != 1 || text != `{"level":"secret","reason":"smoke","incidentId":"inc-2","detectionId":"det-2"}` {
		t.Fatalf("response metadata %s", text)
	}
	again, err := f.respond(f.tenantID, threatRequest("suspend-clearance", "identity", bob, automatic), settings, nil)
	expectOutcome(t, again, err, "skipped", "already-applied")

	// By hand it takes iam:clearances:suspend besides responding to threats.
	analyst := f.member("analyst")
	f.grant("analyst", "identity", jsString(analyst.Get("id")), "iam:threats:*")
	_, err = f.respond(f.tenantID, threatRequest("suspend-clearance", "identity", bob, ThreatManualActor(f.principal(analyst, false))), settings, nil)
	expectError(t, err, "ACCESS_DENIED", "Suspending a clearance requires iam:clearances:suspend")
	impersonating := f.principal(f.owner, false)
	impersonating.Session = impersonating.Session.Spread(core.NewObject("impersonatorId", "someone"))
	_, err = f.respond(f.tenantID, threatRequest("suspend-clearance", "identity", bob, ThreatManualActor(impersonating)), settings, nil)
	expectError(t, err, "IMPERSONATION_RESTRICTED", "Clearances cannot be changed while impersonating")
}

func TestThreatInvitationsStayRevokedAfterRelease(t *testing.T) {
	f := newThreatFixture(t, nil)
	owner := ThreatManualActor(f.principal(f.owner, false))
	inviter := jsString(f.member("inviter").Get("id"))
	f.seed("memberInvitations", core.NewObject("id", "invite-1", "tenantId", f.tenantID, "inviterId", inviter, "email", "attacker@evil.example",
		"consumed", false, "createdAt", 1.0, "expiresAt", 9e15))
	contained, err := f.respond(f.tenantID, threatRequest("contain", "identity", inviter, owner), f.settings(""), nil)
	expectOutcome(t, contained, err, "applied", "")
	if _, err := f.release(f.tenantID, inviter, owner, ""); err != nil {
		t.Fatal(err)
	}
	if f.get("memberInvitations", "invite-1").Get("revoked") != true {
		t.Fatal("invitation not revoked")
	}
}

func TestThreatRiskContextAndAudit(t *testing.T) {
	f := newThreatFixture(t, nil)
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	agentID := jsString(f.member("agent").Get("id"))
	now := f.server().Now()
	f.seed("identityRisk",
		core.NewObject("id", aliceID, "tenantId", f.tenantID, "identityId", aliceID, "contributions", []any{
			core.NewObject("detectionId", "d", "ruleId", "brute-force", "severity", "medium", "points", 25.0, "at", float64(now)-12*threatsHour)}, "score", 25.0, "level", "low", "updatedAt", 1.0),
		core.NewObject("id", agentID, "tenantId", f.tenantID, "identityId", agentID, "contributions", []any{
			core.NewObject("detectionId", "e", "ruleId", "denial-burst", "severity", "high", "points", 50.0, "at", float64(now))}, "score", 50.0, "level", "medium", "updatedAt", 1.0))
	read := func(principal *Principal) string {
		t.Helper()
		result, err := core.Transact(f.ctx, f.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			return RiskContext(ctx, tx, principal, now)
		})
		if err != nil {
			t.Fatal(err)
		}
		text, _, _ := core.Stringify(result)
		return text
	}
	person := f.principal(alice, false)
	if got := read(person); got != `{"principal.riskLevel":"low","principal.riskScore":18}` {
		t.Fatalf("person %s", got)
	}
	// The tenant's half-life applies.
	f.seed("threatSettings", core.NewObject("id", f.tenantID, "tenantId", f.tenantID, "rules", core.NewObject(), "riskHalfLifeHours", 12.0))
	if got := read(person); got != `{"principal.riskLevel":"low","principal.riskScore":13}` {
		t.Fatalf("half-life %s", got)
	}
	delegated := &Principal{Identity: person.Identity, Session: person.Session.Spread(core.NewObject("agentId", agentID))}
	if got := read(delegated); got != `{"principal.riskLevel":"medium","principal.riskScore":50}` {
		t.Fatalf("delegated %s", got)
	}
	simulated := &Principal{Identity: person.Identity, Session: core.NewObject("id", "simulation")}
	if got := read(simulated); got != `{"principal.riskLevel":"none","principal.riskScore":0}` {
		t.Fatalf("simulated %s", got)
	}
	nobody := &Principal{Identity: core.NewObject("id", "nobody"), Session: core.NewObject("id", "s")}
	if got := read(nobody); got != `{"principal.riskLevel":"none","principal.riskScore":0}` {
		t.Fatalf("no record %s", got)
	}

	// threatAudit: under the person with their session context, or under the threat-detection actor.
	err := f.iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := ThreatAudit(ctx, f.server(), tx, f.tenantID, ThreatManualActor(person), "threat:test-manual", "r1", core.NewObject("a", 1.0)); err != nil {
			return err
		}
		return ThreatAudit(ctx, f.server(), tx, f.tenantID, ThreatAutomaticActor(), "threat:test-automatic", "r2", core.NewObject("b", 2.0))
	})
	if err != nil {
		t.Fatal(err)
	}
	manual := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:test-manual"))[0]
	if manual.Get("actorId") != aliceID || manual.Get("outcome") != "allow" || manual.Get("rootOverride") != false {
		t.Fatalf("manual event %v", manual)
	}
	automatic := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:test-automatic"))[0]
	if automatic.Get("actorId") != ThreatActor || automatic.Get("resourceId") != "r2" || automatic.Get("timestamp") != float64(now) {
		t.Fatalf("automatic event %v", automatic)
	}
	if text, _, _ := core.Stringify(automatic.Get("metadata")); text != `{"b":2}` {
		t.Fatalf("automatic metadata %s", text)
	}
}
