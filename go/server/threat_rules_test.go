package server

// Rule coverage for identity threat detection (tests/threat-rules.test.ts). The TypeScript tests produce every
// scenario through the public API (sign-ins from simulated client addresses, administration calls); here the audit
// events those calls record are built directly, with the shapes the auth service and the server write, and judged by
// EvaluateThreatRules, so what is asserted is what a run would raise. Tests that need the threats module
// (threats.go: rule catalog, settings) skip while it is still another unit's NOT_IMPLEMENTED stub.

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	trMinute = 60_000.0
	trDay    = 24 * 60 * trMinute
	// A fixed instant (2026-09-24T12:00:00Z) the scenarios start from.
	trNoon = 1_790_251_200_000.0
)

// threatsPorted skips the test while a function of the threats module this unit calls is still a NOT_IMPLEMENTED
// stub of another unit.
func threatsPorted(t *testing.T) {
	t.Helper()
	check := func(err error) {
		t.Helper()
		if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
			t.Skip("reached another unit's stub: " + known.Message)
		} else if err != nil {
			t.Fatal(err)
		}
	}
	_, err := ResolveThreatSettings(nil)
	check(err)
	_, err = ThreatRule("brute-force")
	check(err)
	_, err = MaxSeverity("low", "high")
	check(err)
	_, err = SeverityAtLeast("low", "low")
	check(err)
	_, err = EffectiveRisk(core.NewObject("contributions", []any{}), 0, 24)
	check(err)
}

// trSettings resolves stored settings (nil: the defaults).
func trSettings(t *testing.T, stored *core.Object) *core.Object {
	t.Helper()
	threatsPorted(t)
	settings, err := ResolveThreatSettings(stored)
	if err != nil {
		t.Fatal(err)
	}
	return settings
}

// trStored is a stored threatSettings record with the given members.
func trStored(members ...any) *core.Object {
	record := core.NewObject("id", "t1", "tenantId", "t1", "rules", core.NewObject(), "trustedNetworks", []any{},
		"dormantDays", 90.0, "riskHalfLifeHours", 24.0, "notify", core.NewObject("owners", false, "emails", []any{}),
		"maxAutomaticContainments", 3.0, "updatedAt", 1.0, "updatedBy", "owner")
	for index := 0; index+1 < len(members); index += 2 {
		record.Set(members[index].(string), members[index+1])
	}
	return record
}

var trSequence float64

// trEvent is an audit event of tenant t1 (resourceId = actorId, outcome allow) with extra members.
func trEvent(id, actorID, action string, timestamp float64, members ...any) *core.Object {
	trSequence++
	event := core.NewObject("id", id, "tenantId", "t1", "actorId", actorID, "action", action, "resourceId", actorID,
		"timestamp", timestamp, "outcome", "allow")
	for index := 0; index+1 < len(members); index += 2 {
		event.Set(members[index].(string), members[index+1])
	}
	event.Set("sequence", trSequence)
	return event
}

// trFailures are wrong-password (or other reason) sign-ins of one person from ip, a second apart.
func trFailures(prefix, actorID, reason, ip string, from float64, times int) []*core.Object {
	var events []*core.Object
	for index := 0; index < times; index++ {
		events = append(events, trEvent(fmt.Sprintf("%s-%d", prefix, index), actorID, "auth:signin:fail", from+float64(index)*1000,
			"metadata", core.NewObject("reason", reason, "ip", ip, "userAgent", "threat-rules-test")))
	}
	return events
}

func trSignIn(id, actorID, ip string, at float64) *core.Object {
	return trEvent(id, actorID, "auth:session:create", at, "metadata", core.NewObject("ip", ip, "userAgent", "threat-rules-test"))
}

// trFacts answers from fixed identities (by id) and privileged ids.
func trFacts(identities map[string]*core.Object, privileged ...string) ThreatRuleFacts {
	return ThreatRuleFacts{
		Identity: func(_ context.Context, id string) (*core.Object, error) { return identities[id], nil },
		IsPrivileged: func(_ context.Context, id string) (bool, error) {
			return containsString(privileged, id), nil
		},
		IsAdminRole: func(_ context.Context, roleID string) (bool, error) { return roleID == "role-admin", nil },
		HoldsRole: func(_ context.Context, identityID, roleID string) (bool, error) {
			return identityID == "mallory" && roleID == "role-admin", nil
		},
	}
}

func trPeople(ids ...string) map[string]*core.Object {
	people := map[string]*core.Object{}
	for _, id := range ids {
		people[id] = identity(id, "t1", "name", strings.ToUpper(id[:1])+id[1:], "email", id+"@acme.test")
	}
	return people
}

// trEvaluate runs the rules over events (and history) with the settings.
func trEvaluate(t *testing.T, input *ThreatRuleInput) *ThreatRuleResult {
	t.Helper()
	if input.TenantID == "" {
		input.TenantID = "t1"
	}
	if input.Now == 0 {
		input.Now = trNoon + trDay
	}
	result, err := EvaluateThreatRules(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

// trOfRule keeps the candidates of one rule.
func trOfRule(candidates []*core.Object, ruleID string) []*core.Object {
	var kept []*core.Object
	for _, candidate := range candidates {
		if candidate.Get("ruleId") == ruleID {
			kept = append(kept, candidate)
		}
	}
	return kept
}

func trJSON(value any) string { return core.MustStringify(value) }

// trMember reads a dotted path.
func trMember(record *core.Object, path string) any {
	var value any = record
	for _, key := range strings.Split(path, ".") {
		value = member(value, key)
	}
	return value
}

// trExpect compares members (dotted paths) by their JSON text.
func trExpect(t *testing.T, record *core.Object, pairs ...any) {
	t.Helper()
	for index := 0; index+1 < len(pairs); index += 2 {
		path := pairs[index].(string)
		got := trJSON(trMember(record, path))
		want := trJSON(core.Normalize(pairs[index+1]))
		if got != want {
			t.Errorf("%s: got %s, want %s (record %s)", path, got, want, trJSON(record))
		}
	}
}

func TestThreatRulesPasswordSpray(t *testing.T) {
	settings := trSettings(t, nil)
	var people []string
	var history, events []*core.Object
	for index := 0; index < 10; index++ {
		person := fmt.Sprintf("spray%d", index)
		people = append(people, person)
		failure := trFailures("spray-"+person, person, "password", "203.0.113.50", trNoon+float64(index)*1000, 1)
		if index < 9 {
			history = append(history, failure...)
		} else {
			events = append(events, failure...)
		}
	}
	// Nine accounts stay below the threshold.
	nine := trEvaluate(t, &ThreatRuleInput{Events: history, Settings: settings})
	if len(trOfRule(nine.Candidates, "password-spray")) != 0 {
		t.Fatal("nine accounts raised a spray")
	}
	// The tenth account completes the burst; the nine before it are read back from the lookback window.
	result := trEvaluate(t, &ThreatRuleInput{Events: events, History: history, Settings: settings})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	spray := result.Candidates[0]
	trExpect(t, spray,
		"ruleId", "password-spray",
		"severity", "high",
		"subject", core.NewObject("type", "network", "id", "203.0.113.50"),
		"network", "203.0.113.50",
		"title", "Password spray from 203.0.113.50",
		"metadata.peak", 10,
		"metadata.threshold", 10,
		"metadata.accounts", 10,
		"evidence.count", 10,
		"evidence.networks", []string{"203.0.113.50"},
		"evidence.identityIds", people,
	)
	if !isUndefined(spray.Get("identityId")) {
		t.Error("a network is nobody's risk")
	}
	if got := spray.Get("summary"); got != "10 accounts failed password sign-in from 203.0.113.50 within 15 minutes (10 attempts in all)." {
		t.Errorf("summary %v", got)
	}
	// Judged again in a later run (the burst is history now), it keeps its dedupe key.
	again := trEvaluate(t, &ThreatRuleInput{Events: events, History: append(history, events...), Settings: settings})
	if len(again.Candidates) != 1 || again.Candidates[0].Get("dedupeKey") != spray.Get("dedupeKey") {
		t.Fatalf("re-read: %s", trJSON(trObjects(again.Candidates)))
	}
}

func trObjects(records []*core.Object) []any {
	out := make([]any, len(records))
	for index, record := range records {
		out[index] = record
	}
	return out
}

func TestThreatRulesTrustedAndDisabled(t *testing.T) {
	var events []*core.Object
	for index := 0; index < 10; index++ {
		person := fmt.Sprintf("office%d", index)
		events = append(events, trFailures("office-"+person, person, "password", "192.0.2.77", trNoon+float64(index)*1000, 1)...)
	}
	trusted := trSettings(t, trStored("trustedNetworks", []any{"192.0.2.0/24"}))
	if got := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: trusted}).Candidates; len(got) != 0 {
		t.Fatalf("a trusted network was reported: %s", trJSON(trObjects(got)))
	}
	disabled := trSettings(t, trStored("rules", core.NewObject("password-spray", core.NewObject("enabled", false))))
	if got := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: disabled}).Candidates; len(got) != 0 {
		t.Fatalf("a disabled rule fired: %s", trJSON(trObjects(got)))
	}
	// A rule window set by the tenant is read in words.
	defaults := trSettings(t, nil)
	if got := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: defaults}).Candidates; len(got) != 1 {
		t.Fatalf("defaults: %s", trJSON(trObjects(got)))
	}
}

func TestThreatRulesBruteForceSuccess(t *testing.T) {
	settings := trSettings(t, nil)
	people := trPeople("alice", "bob", "carol")
	// Alice was signed in before the attack began.
	history := []*core.Object{trSignIn("alice-before", "alice", "192.0.2.10", trNoon-trMinute)}
	var events []*core.Object
	events = append(events, trFailures("alice-fail", "alice", "password", "198.51.100.7", trNoon, 5)...)
	events = append(events, trSignIn("alice-in", "alice", "198.51.100.7", trNoon+10_000))
	events = append(events, trFailures("bob-fail", "bob", "password", "198.51.100.8", trNoon+20_000, 5)...)
	events = append(events, trSignIn("bob-in", "bob", "192.0.2.44", trNoon+30_000))
	// Four failures stay below the threshold.
	events = append(events, trFailures("carol-fail", "carol", "password", "198.51.100.9", trNoon+40_000, 4)...)
	events = append(events, trSignIn("carol-in", "carol", "198.51.100.9", trNoon+50_000))
	baselines := map[string]*core.Object{}
	result := trEvaluate(t, &ThreatRuleInput{Events: events, History: history, Settings: settings, Baselines: baselines, Facts: trFacts(people)})
	found := trOfRule(result.Candidates, "brute-force-success")
	if len(result.Candidates) != 2 || len(found) != 2 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	byIdentity := map[any]*core.Object{}
	for _, candidate := range found {
		byIdentity[candidate.Get("identityId")] = candidate
	}
	trExpect(t, byIdentity["alice"],
		"severity", "high",
		"network", "198.51.100.7",
		"subject", core.NewObject("type", "identity", "id", "alice", "name", "Alice (alice@acme.test)"),
		"metadata", core.NewObject("failures", 5, "threshold", 5, "windowMs", 30*trMinute, "fromFailingNetwork", true),
		"evidence.count", 6,
		"riskySignIn", true,
		"title", "Sign-in after repeated failures: Alice (alice@acme.test)",
		"summary", "Alice (alice@acme.test) signed in after 5 failed attempts in the preceding 30 minutes, from a network that was failing.",
	)
	trExpect(t, byIdentity["bob"],
		"severity", "medium",
		"network", "192.0.2.44",
		"metadata.failures", 5,
		"metadata.fromFailingNetwork", false,
	)
	if _, ok := byIdentity["carol"]; ok {
		t.Error("four failures raised brute-force-success")
	}
	// Every sign-in is learned into a baseline.
	if trJSON(result.TouchedBaselines) != `["alice","bob","carol"]` {
		t.Errorf("touched %v", result.TouchedBaselines)
	}
	trExpect(t, baselines["alice"],
		"networks", []any{core.NewObject("key", "198.51.100.7", "lastAt", trNoon+10_000)},
		"userAgents", []any{core.NewObject("value", "threat-rules-test", "lastAt", trNoon+10_000)},
		"lastSignInAt", trNoon+10_000,
	)
	// The sign-in ended the streak: signing in again raises nothing.
	later := trSignIn("alice-again", "alice", "198.51.100.7", trNoon+60_000)
	next := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{later}, History: append(history, events...), Settings: settings, Baselines: baselines, Facts: trFacts(people)})
	if len(next.Candidates) != 0 {
		t.Fatalf("again: %s", trJSON(trObjects(next.Candidates)))
	}
}

func TestThreatRulesMfaBombardment(t *testing.T) {
	settings := trSettings(t, nil)
	events := trFailures("mfa", "dave", "mfa", "198.51.100.12", trNoon, 5)
	result := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(trPeople("dave"))})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"ruleId", "mfa-bombardment",
		"severity", "high",
		"identityId", "dave",
		"network", "198.51.100.12",
		"metadata", core.NewObject("peak", 5, "threshold", 5, "windowMs", 15*trMinute, "networks", 1),
		"summary", "Dave (dave@acme.test) had 5 wrong second-factor codes entered within 15 minutes from 198.51.100.12, so someone else likely knows the password.",
	)
}

func TestThreatRulesNewNetwork(t *testing.T) {
	settings := trSettings(t, nil)
	people := trPeople("owner", "member")
	baselines := map[string]*core.Object{}
	// The first sign-in only teaches the network.
	first := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{trSignIn("owner-1", "owner", "192.0.2.10", trNoon)}, Settings: settings, Baselines: baselines, Facts: trFacts(people, "owner")})
	if len(first.Candidates) != 0 {
		t.Fatalf("first: %s", trJSON(trObjects(first.Candidates)))
	}
	second := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{trSignIn("owner-2", "owner", "203.0.113.9", trNoon+trMinute)}, Settings: settings, Baselines: baselines, Facts: trFacts(people, "owner")})
	if len(second.Candidates) != 1 {
		t.Fatalf("second: %s", trJSON(trObjects(second.Candidates)))
	}
	trExpect(t, second.Candidates[0],
		"ruleId", "new-network",
		"severity", "medium",
		"network", "203.0.113.9",
		"metadata", core.NewObject("privileged", true, "knownNetworks", 1),
		"summary", "Owner (owner@acme.test), a privileged account, signed in from 203.0.113.9, a network not seen for them before.",
		"riskySignIn", true,
	)
	// A member is not reported unless the tenant asks for everyone (at low severity).
	trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{trSignIn("member-1", "member", "192.0.2.10", trNoon)}, Settings: settings, Baselines: baselines, Facts: trFacts(people, "owner")})
	quiet := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{trSignIn("member-2", "member", "203.0.113.9", trNoon+trMinute)}, Settings: settings, Baselines: baselines, Facts: trFacts(people, "owner")})
	if len(quiet.Candidates) != 0 {
		t.Fatalf("member: %s", trJSON(trObjects(quiet.Candidates)))
	}
	everyone := trSettings(t, trStored("rules", core.NewObject("new-network", core.NewObject("everyone", true))))
	loud := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{trSignIn("member-3", "member", "198.51.100.3", trNoon+2*trMinute)}, Settings: everyone, Baselines: baselines, Facts: trFacts(people, "owner")})
	if len(loud.Candidates) != 1 {
		t.Fatalf("everyone: %s", trJSON(trObjects(loud.Candidates)))
	}
	trExpect(t, loud.Candidates[0], "severity", "low", "metadata.privileged", false, "metadata.knownNetworks", 2)
}

func TestThreatRulesSessionHijack(t *testing.T) {
	settings := trSettings(t, nil)
	mismatch := func(id string, at float64) *core.Object {
		return trEvent(id, "erin", "auth:session:mismatch", at, "metadata",
			core.NewObject("sessionId", "session-1", "sessionIp", "192.0.2.10", "ip", "203.0.113.66"))
	}
	result := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{mismatch("m1", trNoon), mismatch("m2", trNoon+1000)}, Settings: settings, Facts: trFacts(trPeople("erin"))})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"ruleId", "session-hijack",
		"severity", "high",
		"network", "203.0.113.66",
		"dedupeKey", "session-1",
		"evidence.count", 2,
		"evidence.eventIds", []string{"m1", "m2"},
		"evidence.networks", []string{"203.0.113.66", "192.0.2.10"},
		"metadata", core.NewObject("sessionId", "session-1", "sessionIp", "192.0.2.10", "ip", "203.0.113.66"),
		"summary", "A session of Erin (erin@acme.test) bound to 192.0.2.10 was presented from 203.0.113.66.",
		"occurredAt", trNoon+1000,
	)
}

func TestThreatRulesAccountTakeoverPersistence(t *testing.T) {
	settings := trSettings(t, nil)
	people := trPeople("frank")
	var events []*core.Object
	events = append(events, trFailures("frank-fail", "frank", "password", "198.51.100.40", trNoon, 5)...)
	events = append(events, trSignIn("frank-in", "frank", "198.51.100.40", trNoon+10_000))
	events = append(events, trEvent("frank-change", "frank", "auth:password:change", trNoon+10*trMinute))
	result := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(people)})
	takeover := trOfRule(result.Candidates, "account-takeover-persistence")
	if len(takeover) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, takeover[0],
		"severity", "high",
		"identityId", "frank",
		"evidence", core.NewObject("eventIds", []string{"frank-in", "frank-change"}, "count", 2, "firstAt", trNoon+10_000,
			"lastAt", trNoon+10*trMinute, "actions", []string{"auth:session:create", "auth:password:change"}),
		"metadata", core.NewObject("changedAction", "auth:password:change", "riskySignInRuleId", "brute-force-success",
			"riskySignInAt", trNoon+10_000, "riskySignInKey", "brute-force-success:frank-in"),
		"summary", "Frank (frank@acme.test) changed their password 10 minutes after a risky sign-in (sign-in after repeated failures).",
	)
	// Outside the window, nothing.
	late := append(append([]*core.Object{}, events[:6]...), trEvent("frank-late", "frank", "auth:password:change", trNoon+2*60*trMinute))
	if got := trOfRule(trEvaluate(t, &ThreatRuleInput{Events: late, Settings: settings, Facts: trFacts(people)}).Candidates, "account-takeover-persistence"); len(got) != 0 {
		t.Fatalf("late: %s", trJSON(trObjects(got)))
	}
}

func TestThreatRulesTakeoverFromStoredRiskySignIn(t *testing.T) {
	settings := trSettings(t, nil)
	people := trPeople("grace")
	baseline := func() map[string]*core.Object {
		return map[string]*core.Object{"grace": core.NewObject("id", "grace", "tenantId", "t1", "identityId", "grace",
			"networks", []any{core.NewObject("key", "192.0.2.10", "lastAt", trNoon-trDay)}, "userAgents", []any{},
			"riskySignIn", core.NewObject("at", trNoon-5*trMinute, "detectionId", "detection-1", "ruleId", "new-network"),
			"firstSeenAt", trNoon-10*trDay, "updatedAt", trNoon-trDay)}
	}
	// Enrolling an authenticator after a risky sign-in an earlier run recorded.
	enroll := trEvent("grace-enroll", "grace", "auth:mfa:enable", trNoon)
	facts := trFacts(people)
	result := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{enroll}, Settings: settings, Baselines: baseline(), Facts: facts})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"evidence", core.NewObject("eventIds", []string{"grace-enroll"}, "count", 1, "firstAt", trNoon-5*trMinute, "lastAt", trNoon, "actions", []string{"auth:mfa:enable"}),
		"metadata", core.NewObject("changedAction", "auth:mfa:enable", "riskySignInRuleId", "new-network", "riskySignInAt", trNoon-5*trMinute, "riskySignInDetectionId", "detection-1"),
		"summary", "Grace (grace@acme.test) enrolled an authenticator app 5 minutes after a risky sign-in (sign-in from a new network).",
	)
	// A risky sign-in judged harmless opens no window.
	facts.DetectionStands = func(_ context.Context, detectionID string) (bool, error) { return detectionID != "detection-1", nil }
	if got := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{enroll}, Settings: settings, Baselines: baseline(), Facts: facts}).Candidates; len(got) != 0 {
		t.Fatalf("dismissed: %s", trJSON(trObjects(got)))
	}
	// Someone else's change of grace's methods is not hers.
	other := trEvent("admin-reset", "admin", "auth:mfa:enable", trNoon, "resourceId", "grace")
	if got := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{other}, Settings: settings, Baselines: baseline(), Facts: trFacts(people)}).Candidates; len(got) != 0 {
		t.Fatalf("other actor: %s", trJSON(trObjects(got)))
	}
}

func TestThreatRulesViewAsResponsibility(t *testing.T) {
	settings := trSettings(t, nil)
	var events []*core.Object
	for index := 0; index < 30; index++ {
		events = append(events, trEvent(fmt.Sprintf("deny-%d", index), "member", "documents:read", trNoon+float64(index)*1000,
			"outcome", "deny", "resourceId", "d1", "impersonatorId", "support"))
	}
	result := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(trPeople("member", "support"))})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"ruleId", "denial-burst",
		"identityId", "support",
		"metadata", core.NewObject("peak", 30, "threshold", 30, "windowMs", 10*trMinute, "agent", false, "viewedAs", []string{"member"}),
		"summary", "Support (support@acme.test) was denied 30 times within 10 minutes, across 1 action, all while viewing as someone else.",
	)
}

func TestThreatRulesMassDeletion(t *testing.T) {
	settings := trSettings(t, nil)
	var events []*core.Object
	var deleted []string
	for index := 0; index < 15; index++ {
		target := fmt.Sprintf("person-%d", index)
		deleted = append(deleted, target)
		events = append(events, trEvent(fmt.Sprintf("del-%d", index), "harry", "identity:delete", trNoon+float64(index)*1000, "resourceId", target))
	}
	for index := 0; index < 5; index++ {
		events = append(events, trEvent(fmt.Sprintf("role-%d", index), "harry", "iam:roles:delete", trNoon+float64(20+index)*1000, "resourceId", fmt.Sprintf("role-%d", index)))
	}
	result := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(trPeople("harry"))})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"ruleId", "mass-deletion",
		"severity", "high",
		"identityId", "harry",
		"metadata", core.NewObject("peak", 20, "threshold", 20, "windowMs", 10*trMinute, "identities", 15),
		"evidence.count", 20,
		"evidence.identityIds", deleted,
		"evidence.actions", []string{"identity:delete", "iam:roles:delete"},
		"summary", "Harry (harry@acme.test) deleted or revoked 20 items within 10 minutes.",
	)
}

func TestThreatRulesImpersonationBurst(t *testing.T) {
	settings := trSettings(t, nil)
	var events []*core.Object
	for index := 0; index < 5; index++ {
		events = append(events, trEvent(fmt.Sprintf("imp-%d", index), "ivy", "identity:impersonate", trNoon+float64(index)*60*trMinute, "resourceId", fmt.Sprintf("member-%d", index%3)))
	}
	// Sign-ins made through impersonation teach nothing.
	events = append(events, trEvent("imp-session", "member-0", "auth:session:create", trNoon+6*60*trMinute, "impersonatorId", "ivy", "metadata", core.NewObject("ip", "192.0.2.5")))
	result := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(trPeople("ivy"))})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"ruleId", "impersonation-burst",
		"metadata.targets", 3,
		"summary", "Ivy (ivy@acme.test) started 5 \"view as\" sessions within 1 day, as 3 people.",
	)
	if len(result.TouchedBaselines) != 0 {
		t.Errorf("an impersonated sign-in was learned: %v", result.TouchedBaselines)
	}
}

func TestThreatRulesDenialBurstAgent(t *testing.T) {
	settings := trSettings(t, nil)
	var events []*core.Object
	for index := 0; index < 30; index++ {
		events = append(events, trEvent(fmt.Sprintf("deny-%d", index), "jack", fmt.Sprintf("documents:%s", []string{"read", "write"}[index%2]), trNoon+float64(index)*1000,
			"outcome", "deny", "resourceId", "d1", "sessionContext", core.NewObject("agentId", "agent-1")))
	}
	result := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(trPeople("jack"))})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"metadata", core.NewObject("peak", 30, "threshold", 30, "windowMs", 10*trMinute, "agent", true, "agentId", "agent-1"),
		"evidence.actions", []string{"documents:read", "documents:write"},
		"summary", "Jack (jack@acme.test), acting through an AI agent, was denied 30 times within 10 minutes, across 2 actions.",
	)
}

func TestThreatRulesReconBurst(t *testing.T) {
	settings := trSettings(t, trStored("rules", core.NewObject("recon-burst", core.NewObject("threshold", 20.0))))
	var events []*core.Object
	for index := 0; index < 25; index++ {
		events = append(events, trEvent(fmt.Sprintf("threats-%d", index), "kate", "iam:threats:read", trNoon+float64(index)*100, "resourceId", "t1"))
	}
	quiet := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(trPeople("kate"))})
	if len(quiet.Candidates) != 0 {
		t.Fatalf("the threats console was counted: %s", trJSON(trObjects(quiet.Candidates)))
	}
	for index := 0; index < 20; index++ {
		events = append(events, trEvent(fmt.Sprintf("roles-%d", index), "kate", "iam:roles:read", trNoon+5000+float64(index)*100, "resourceId", "t1"))
	}
	result := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(trPeople("kate"))})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"ruleId", "recon-burst",
		"severity", "low",
		"metadata", core.NewObject("peak", 20, "threshold", 20, "windowMs", 10*trMinute, "kind", "reads"),
		"summary", "Kate (kate@acme.test) made 20 administrative reads within 10 minutes.",
	)
	if !strings.Contains(jsString(result.Candidates[0].Get("dedupeKey")), "kate:reads:") {
		t.Errorf("dedupe key %v", result.Candidates[0].Get("dedupeKey"))
	}
	// Exports count at one fiftieth of the threshold (at least three).
	var exports []*core.Object
	for index := 0; index < 3; index++ {
		exports = append(exports, trEvent(fmt.Sprintf("export-%d", index), "kate", "identity:export", trNoon+float64(index)*1000, "resourceId", fmt.Sprintf("p%d", index)))
	}
	exported := trEvaluate(t, &ThreatRuleInput{Events: exports, Settings: settings, Facts: trFacts(trPeople("kate"))})
	if len(exported.Candidates) != 1 {
		t.Fatalf("exports: %s", trJSON(trObjects(exported.Candidates)))
	}
	trExpect(t, exported.Candidates[0], "metadata", core.NewObject("peak", 3, "threshold", 3, "windowMs", 10*trMinute, "kind", "exports", "exported", 3))
}

func TestThreatRulesGuardrailWeakened(t *testing.T) {
	settings := trSettings(t, nil)
	policy := func(id string, at float64, value any) *core.Object {
		return trEvent(id, "owner", "tenant:auth-policy", at, "resourceId", "t1", "metadata", core.NewObject("authPolicy", value))
	}
	state := &ThreatRuleState{}
	// Without a previous policy the rule only learns.
	first := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{policy("p1", trNoon, core.NewObject("requireMfa", true, "allowedIpRanges", []any{"192.0.2.0/24"}, "notifyNewSignIn", true))}, Settings: settings, State: state, Facts: trFacts(trPeople("owner"))})
	if len(first.Candidates) != 0 || state.AuthPolicy == nil {
		t.Fatalf("first: %s", trJSON(trObjects(first.Candidates)))
	}
	second := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{policy("p2", trNoon+trMinute, core.NewObject("notifyNewSignIn", true))}, Settings: settings, State: state, Facts: trFacts(trPeople("owner"))})
	if len(second.Candidates) != 1 {
		t.Fatalf("second: %s", trJSON(trObjects(second.Candidates)))
	}
	trExpect(t, second.Candidates[0],
		"ruleId", "guardrail-weakened",
		"title", "Security settings weakened: sign-in policy",
		"subject", core.NewObject("type", "tenant", "id", "t1"),
		"identityId", "owner",
		"metadata", core.NewObject("change", "auth-policy", "weakened", []string{"requireMfa", "allowedIpRanges"}),
		"summary", "Owner (owner@acme.test) removed the MFA requirement and the IP allowlist from the tenant sign-in policy.",
	)
	// A cleared policy (null) drops every protection still set.
	third := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{policy("p3", trNoon+2*trMinute, nil)}, Settings: settings, State: state, Facts: trFacts(trPeople("owner"))})
	if len(third.Candidates) != 1 {
		t.Fatalf("third: %s", trJSON(trObjects(third.Candidates)))
	}
	trExpect(t, third.Candidates[0], "metadata.weakened", []string{"notifyNewSignIn"})
	// A lifted network block.
	unblock := trEvent("u1", "deployment-operator", "security:network-unblock", trNoon, "resourceId", "block-1", "metadata", core.NewObject("network", "203.0.113.0/24", "platform", true))
	lifted := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{unblock}, Settings: settings})
	if len(lifted.Candidates) != 1 {
		t.Fatalf("unblock: %s", trJSON(trObjects(lifted.Candidates)))
	}
	trExpect(t, lifted.Candidates[0],
		"summary", "deployment-operator lifted the platform-wide block on 203.0.113.0/24.",
		"metadata", core.NewObject("change", "network-unblock", "network", "203.0.113.0/24", "platform", true, "blockId", "block-1"),
	)
	if !isUndefined(lifted.Candidates[0].Get("identityId")) {
		t.Error("the deployment operator is nobody's risk")
	}
}

func TestThreatRulesDormantReactivated(t *testing.T) {
	settings := trSettings(t, nil)
	baselines := map[string]*core.Object{"liam": core.NewObject("id", "liam", "tenantId", "t1", "identityId", "liam",
		"networks", []any{core.NewObject("key", "192.0.2.10", "lastAt", trNoon-100*trDay)}, "userAgents", []any{},
		"lastSignInAt", trNoon-100*trDay, "firstSeenAt", trNoon-200*trDay, "updatedAt", trNoon-100*trDay)}
	result := trEvaluate(t, &ThreatRuleInput{Events: []*core.Object{trSignIn("liam-in", "liam", "192.0.2.10", trNoon)}, Settings: settings, Baselines: baselines, Facts: trFacts(trPeople("liam"))})
	if len(result.Candidates) != 1 {
		t.Fatalf("candidates: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, result.Candidates[0],
		"ruleId", "dormant-reactivated",
		"severity", "medium",
		"network", "192.0.2.10",
		"metadata", core.NewObject("lastSignInAt", trNoon-100*trDay, "idleDays", 100, "dormantDays", 90),
		"summary", "Liam (liam@acme.test) signed in after 100 days without a sign-in (accounts count as dormant after 90 days).",
	)
	trExpect(t, baselines["liam"], "lastSignInAt", trNoon)
}

func TestThreatRulesPerEventRules(t *testing.T) {
	settings := trSettings(t, nil)
	people := trPeople("mallory", "nina", "root")
	people["root"].Set("rootAdmin", true)
	people["nina"].Set("rootAdmin", true)
	events := []*core.Object{
		trEvent("grant", "mallory", "iam:bindings:create", trNoon, "resourceId", "role-admin"),
		trEvent("grant-2", "mallory", "iam:bindings:create", trNoon+trMinute, "resourceId", "role-admin"),
		trEvent("root", "root", "iam:root:grant", trNoon, "resourceId", "nina"),
		trEvent("replay", "sa-ci", "role:assumed-with-web-identity", trNoon, "resourceId", "role-deploy", "outcome", "deny",
			"metadata", core.NewObject("reason", "replay", "trustId", "trust-1", "issuer", "https://token.actions.example", "subject", "repo:acme/web")),
		trEvent("inv", "deployment-operator", "invariant:broken", trNoon, "resourceId", "inv-1",
			"metadata", core.NewObject("name", "No standing admins", "mode", "enforce", "violations", []any{"mallory", 3.0})),
		trEvent("sig", "signal:src-1", "signal:received", trNoon, "resourceId", "nina",
			"metadata", core.NewObject("sourceId", "src-1", "eventType", "credential-compromise", "identityId", "nina", "jti", "jti-1", "reasonAdmin", "Leaked")),
		trEvent("sig-low", "signal:src-1", "signal:received", trNoon, "resourceId", "nina",
			"metadata", core.NewObject("sourceId", "src-1", "eventType", "risk-level-change", "identityId", "nina", "currentLevel", "LOW")),
	}
	result := trEvaluate(t, &ThreatRuleInput{Events: events, Settings: settings, Facts: trFacts(people)})
	escalation := trOfRule(result.Candidates, "privilege-escalation")
	if len(escalation) != 1 {
		t.Fatalf("escalation: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, escalation[0],
		"identityId", "mallory",
		"evidence.count", 2,
		"evidence.eventIds", []string{"grant", "grant-2"},
		"evidence.actions", []string{"iam:bindings:create"},
		"dedupeKey", fmt.Sprintf("mallory:role-admin:%s", core.NumberString(threatStartOfDay(trNoon))),
		"summary", "Mallory (mallory@acme.test) granted the administrator role role-admin and now holds it.",
	)
	root := trOfRule(result.Candidates, "root-admin-granted")
	if len(root) != 1 {
		t.Fatalf("root: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, root[0], "summary", "Root (root@acme.test) made Nina (nina@acme.test) a root administrator of the deployment.", "metadata.grantedBy", "root")
	replay := trOfRule(result.Candidates, "token-replay")
	if len(replay) != 1 {
		t.Fatalf("replay: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, replay[0],
		"subject", core.NewObject("type", "identity", "id", "sa-ci"),
		"metadata", core.NewObject("roleId", "role-deploy", "trustId", "trust-1", "issuer", "https://token.actions.example", "subject", "repo:acme/web"),
		"summary", "A web identity token was presented a second time to assume role role-deploy as sa-ci (token subject repo:acme/web).",
	)
	invariant := trOfRule(result.Candidates, "invariant-broken")
	if len(invariant) != 1 {
		t.Fatalf("invariant: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, invariant[0],
		"severity", "high",
		"title", "Access invariant broken: No standing admins",
		"summary", "The enforced access invariant \"No standing admins\" stopped holding for 1 identity.",
		"metadata", core.NewObject("name", "No standing admins", "mode", "enforce", "invariantId", "inv-1", "violations", []string{"mallory"}),
		"evidence.identityIds", []string{"mallory"},
	)
	signals := trOfRule(result.Candidates, "upstream-signal")
	if len(signals) != 1 {
		t.Fatalf("signals: %s", trJSON(trObjects(result.Candidates)))
	}
	trExpect(t, signals[0],
		"severity", "high",
		"identityId", "nina",
		"metadata", core.NewObject("sourceId", "src-1", "eventType", "credential-compromise", "jti", "jti-1"),
		"summary", "An upstream identity provider reported credential compromise for Nina (nina@acme.test): Leaked.",
	)
}

func TestThreatRulesCutShortLookbackKeepsDedupeKey(t *testing.T) {
	settings := trSettings(t, nil)
	tenantID := "tenant-cut"
	midnight := 1_790_208_000_000.0 // 2026-09-24T00:00:00Z
	// An integration denied every 12 seconds since midnight: a burst that never pauses.
	events := make([]*core.Object, 3600)
	for index := range events {
		events[index] = core.NewObject("id", fmt.Sprintf("deny-%d", index), "tenantId", tenantID, "actorId", "integration-7",
			"action", "documents:read", "resourceId", "d1", "timestamp", midnight+float64(index)*12_000,
			"sequence", float64(index+1), "outcome", "deny")
	}
	facts := ThreatRuleFacts{
		Identity:     func(context.Context, string) (*core.Object, error) { return nil, nil },
		IsPrivileged: func(context.Context, string) (bool, error) { return false, nil },
		IsAdminRole:  func(context.Context, string) (bool, error) { return false, nil },
		HoldsRole:    func(context.Context, string, string) (bool, error) { return false, nil },
	}
	// One run over [from, to) whose lookback the engine's cap cut at historyFrom.
	run := func(from, to, historyFrom float64) []string {
		var fresh, history []*core.Object
		for _, event := range events {
			at := threatTime(event)
			if at >= from && at < to {
				fresh = append(fresh, event)
			}
			if at >= historyFrom && at < from {
				history = append(history, event)
			}
		}
		cut := historyFrom
		result := trEvaluate(t, &ThreatRuleInput{TenantID: tenantID, Events: fresh, History: history, HistoryFrom: &cut,
			Settings: settings, Baselines: map[string]*core.Object{}, State: &ThreatRuleState{}, Facts: facts, Now: to})
		var keys []string
		for _, candidate := range trOfRule(result.Candidates, "denial-burst") {
			keys = append(keys, jsString(candidate.Get("dedupeKey")))
		}
		return keys
	}
	// Two runs five minutes apart near noon; the cut moves with the newest events, two hours behind them.
	noon := midnight + 12*60*trMinute - trMinute
	first := run(noon-10*trMinute, noon-5*trMinute, noon-130*trMinute)
	second := run(noon-5*trMinute, noon, noon-125*trMinute)
	if len(first) != 1 {
		t.Fatalf("first run: %v", first)
	}
	if trJSON(second) != trJSON(first) {
		t.Fatalf("second run %v, first %v", second, first)
	}
}

func TestThreatRulesWindowAndHelpers(t *testing.T) {
	settings := trSettings(t, nil)
	reach, err := RuleWindowMs(settings)
	if err != nil {
		t.Fatal(err)
	}
	// With the default settings this is one day and fifteen minutes... plus the longest counting window's day:
	// impersonation-burst's one-day window reaches back one day; the others one day and their window.
	if reach != trDay+60*trMinute {
		t.Errorf("reach %v", reach)
	}
	week := trSettings(t, trStored("rules", core.NewObject("impersonation-burst", core.NewObject("windowMs", 7*trDay))))
	if reach, _ := RuleWindowMs(week); reach != 7*trDay {
		t.Errorf("week reach %v", reach)
	}
	// Labels and keys.
	if label, _ := IdentityLabel(nil, "ghost\u0007"); label != "ghost" {
		t.Errorf("label %q", label)
	}
	if label, _ := IdentityLabel(identity("x", "t1", "name", " Zoe ", "email", "zoe@acme.test"), "x"); label != "Zoe (zoe@acme.test)" {
		t.Errorf("label %q", label)
	}
	if label, _ := IdentityLabel(identity("x", "t1", "name", "zoe@acme.test", "email", "zoe@acme.test"), "x"); label != "zoe@acme.test" {
		t.Errorf("label %q", label)
	}
	if got := threatDedupeKey("brute-force", strings.Repeat("a", 500)); utf16Len(got) != 400-len("brute-force")-1 {
		t.Errorf("dedupe key length %d", utf16Len(got))
	}
	if got := threatClean("a\u0085b\u009fc\x7fd\x1fe "); got != "abcde " {
		t.Errorf("clean %q", got)
	}
	for ms, want := range map[float64]string{15 * trMinute: "15 minutes", 60 * trMinute: "1 hour", 7 * trDay: "7 days", 90_000: "2 minutes"} {
		if got := threatInWords(ms); got != want {
			t.Errorf("inWords(%v) = %q, want %q", ms, got, want)
		}
	}
	if got := threatSeries([]string{"a", "b", "c"}); got != "a, b and c" {
		t.Errorf("series %q", got)
	}
	considered, _ := Considered(core.NewObject("id", "e", "action", "threat:detection", "actorId", "x", "resourceId", "y", "timestamp", 1.0))
	if considered {
		t.Error("the module's own events are not considered")
	}
	ids, _ := BaselineIdentityIDs([]*core.Object{
		trSignIn("s1", "p1", "192.0.2.1", trNoon),
		trEvent("s2", "p2", "auth:session:create", trNoon, "impersonatorId", "admin"),
		trEvent("c1", "p3", "auth:password:change", trNoon),
		trEvent("c2", "admin", "auth:password:change", trNoon, "resourceId", "p4"),
		trSignIn("s3", "p1", "192.0.2.1", trNoon),
	})
	if trJSON(ids) != `["p1","p3"]` {
		t.Errorf("baseline ids %v", ids)
	}
}
