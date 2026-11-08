package server

// Port of tests/threats-api.test.ts (the threats API group), plus unit tests of api_threats.go's private validators.
// Steps that reach another unit's NOT_IMPLEMENTED stub (the threats module, its engine, rules and responses) skip the
// rest of the test until that unit lands.

import (
	"context"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const threatsTestHour = 3_600_000

type threatsFixture struct {
	*directoryFixture
	tenantID string
	owner    core.CredentialInput // ownerCredential
	ownerID  string
	inboxMu  sync.Mutex
	inbox    []auth.DeliveryMessage
}

// newThreatsFixture is organizationFixture: an organization "Acme" whose owner is "Owner" <owner@acme.test>, with
// documents:read and documents:write declared, and an outbox captured in inbox.
func newThreatsFixture(t *testing.T) *threatsFixture {
	t.Helper()
	f := &threatsFixture{}
	f.directoryFixture = newAnalysisFixture(t, func(options *BetterIamOptions) {
		options.Authentication.SendEmail = func(_ context.Context, message auth.DeliveryMessage) error {
			f.inboxMu.Lock()
			defer f.inboxMu.Unlock()
			f.inbox = append(f.inbox, message)
			return nil
		}
	})
	f.tenantID, f.owner = f.organization("Acme", "owner@acme.test")
	owners := f.find("identities", core.NewObject("tenantId", f.tenantID, "owner", true))
	f.ownerID = jsString(owners[0].Get("id"))
	return f
}

// threatsCall calls an API method with a body of pairs and returns the answer's model value.
func threatsCall[I, O any](f *threatsFixture, method func(context.Context, core.CredentialInput, In[I]) (Out[O], error), credential core.CredentialInput, pairs ...any) (any, error) {
	out, err := method(f.ctx, credential, Input[I](body(pairs...)))
	return out.Value, err
}

// ok unwraps an answer, skipping the test at another unit's stub and failing it on any other error.
func (f *threatsFixture) ok(value any, err error) any {
	f.t.Helper()
	requirePorted(f.t, err)
	return value
}

func (f *threatsFixture) object(value any, err error) *core.Object {
	f.t.Helper()
	object, isObject := f.ok(value, err).(*core.Object)
	if !isObject {
		f.t.Fatalf("answer is not an object: %#v", value)
	}
	return object
}

func (f *threatsFixture) list(value any, err error) []*core.Object {
	f.t.Helper()
	return threatsAPIObjects(f.ok(value, err))
}

// refused is rejects.toMatchObject({ code }), skipping at another unit's stub.
func (f *threatsFixture) refused(err error, code string) {
	f.t.Helper()
	if err != nil && iamError(f.t, err).Code == "NOT_IMPLEMENTED" && code != "NOT_IMPLEMENTED" {
		f.t.Skipf("blocked by another unit: %s", iamError(f.t, err).Message)
	}
	flagExpectCode(f.t, err, code)
}

// member is f.member: a person of the tenant; signIn issues them a fresh session.
func (f *threatsFixture) member(name string) *core.Object {
	f.t.Helper()
	identity, _ := f.person(f.tenantID, name)
	// A member starts signed out (person also issues a session); signIn hands out each session the test counts.
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", identity.Get("id")), nil)
		if err != nil {
			return err
		}
		for _, session := range sessions {
			if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
				return err
			}
		}
		return nil
	})
	return identity
}

func (f *threatsFixture) signIn(identity *core.Object) core.CredentialInput {
	f.t.Helper()
	return f.issue(f.record("identities", jsString(identity.Get("id"))), false)
}

// memberWith is a person of the tenant holding a role of statements, freshly signed in.
func (f *threatsFixture) memberWith(name string, statements ...*core.Object) (string, core.CredentialInput) {
	f.t.Helper()
	identity, _ := f.person(f.tenantID, name)
	role := f.role(f.tenantID, name+" role", statements...)
	f.bind(f.tenantID, role, "identity", jsString(identity.Get("id")))
	return jsString(identity.Get("id")), f.signIn(identity)
}

func (f *threatsFixture) statusOf(identityID string) any {
	f.t.Helper()
	return f.record("identities", identityID).Get("status")
}

func threatsAdministration() *core.Object {
	return allow(items("iam:threats:*"), items("iam/threats/*"))
}

func threatsFind(records []*core.Object, key, value string) *core.Object {
	for _, record := range records {
		if record.Get(key) == value {
			return record
		}
	}
	return nil
}

func TestThreatsAPIRulesSettingsGuardrailDetectionValidation(t *testing.T) {
	f := newThreatsFixture(t)
	threats := f.iam.API.Threats
	rules := f.list(threatsCall(f, threats.Rules, f.owner, "tenantId", f.tenantID))
	if len(rules) != 22 {
		t.Fatalf("expected 22 rules, got %d", len(rules))
	}
	expectMatch(t, threatsFind(rules, "id", "new-network"), `{"everyone":false,"customized":false}`)
	expectMatch(t, f.object(threatsCall(f, threats.GetSettings, f.owner, "tenantId", f.tenantID)), `{"configured":false,"dormantDays":90}`)
	owner := f.ownerSignIn(f.tenantID)
	for _, bad := range []string{
		`{"rules":{"nope":{"enabled":false}}}`,
		`{"rules":{"brute-force":{"threshold":1}}}`,
		`{"rules":{"session-hijack":{"threshold":5}}}`,
		`{"rules":{"brute-force":{"everyone":true}}}`,
		`{"rules":{"brute-force":{"colour":"red"}}}`,
		`{"trustedNetworks":["0.0.0.0/0"]}`,
		`{"trustedNetworks":["::ffff:0:0/96"]}`,
		`{"trustedNetworks":["not an ip"]}`,
		`{"dormantDays":3}`,
		`{"notify":{"emails":["nope"]}}`,
	} {
		_, err := threats.Configure(f.ctx, owner, Input[apitypes.ThreatsConfigureInput](body("tenantId", f.tenantID).Assign(obj(t, bad))))
		f.refused(err, "INVALID_INPUT")
	}
	view := f.object(threatsCall(f, threats.Configure, owner, "tenantId", f.tenantID,
		"rules", obj(t, `{"brute-force":{"enabled":false,"threshold":20},"new-network":{"everyone":true}}`),
		"trustedNetworks", items("10.0.0.0/8"),
		"notify", obj(t, `{"owners":true}`)))
	expectMatch(t, view, `{"configured":true,"trustedNetworks":["10.0.0.0/8"]}`)
	expectMatch(t, member(view.Get("rules"), "brute-force"), `{"enabled":false,"threshold":20}`)
	audit := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "threat:settings"))
	if len(audit) == 0 {
		t.Fatal("no threat:settings audit event")
	}
	expectMatch(t, audit[0].Get("metadata"), `{"changed":["rules","trustedNetworks","notify"],"disabledRules":["brute-force"]}`)
	detections := f.object(threatsCall(f, threats.ListDetections, f.owner, "tenantId", f.tenantID, "ruleId", "guardrail-weakened"))
	expectMatch(t, detections, `{"total":1}`)
	first := threatsAPIObjects(detections.Get("detections"))[0]
	expectMatch(t, first, `{"identityId":"`+f.ownerID+`","subject":{"type":"tenant"}}`)
	// A null rule clears its adjustments; re-enabling raises nothing.
	f.ok(threatsCall(f, threats.Configure, owner, "tenantId", f.tenantID, "rules", core.NewObject("brute-force", nil)))
	rules = f.list(threatsCall(f, threats.Rules, f.owner, "tenantId", f.tenantID))
	expectMatch(t, threatsFind(rules, "id", "brute-force"), `{"enabled":true,"threshold":10,"customized":false}`)
	// Nobody dismisses a detection about themselves.
	_, err := threatsCall(f, threats.DismissDetection, owner, "tenantId", f.tenantID, "detectionId", first.Get("id"), "reason", "mine")
	f.refused(err, "ACCESS_DENIED")
	summary := f.object(threatsCall(f, threats.Summary, f.owner, "tenantId", f.tenantID))
	expectMatch(t, summary, `{"detections24h":1,"byRule24h":{"guardrail-weakened":1},"openIncidents":{"medium":1},"riskyIdentities":{"low":1}}`)
}

func TestThreatsAPIReportRiskIncidentsRespondReleasePlaybooks(t *testing.T) {
	f := newThreatsFixture(t)
	threats := f.iam.API.Threats
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	first := f.signIn(alice)
	second := f.signIn(alice)
	report := f.object(threatsCall(f, threats.ReportSuspicious, second, "tenantId", f.tenantID, "note", "line one\r\nline two\u0007"))
	expectMatch(t, report, `{"sessionsEnded":1,"devicesForgotten":0}`)
	if _, err := f.iam.Context.Principals.Authenticate(f.ctx, first); errorCodeOf(t, err) != "UNAUTHENTICATED" {
		t.Fatalf("the other session should have ended, got %v", err)
	}
	if _, err := f.iam.Context.Principals.Authenticate(f.ctx, second); err != nil {
		t.Fatalf("the reporting session should stay: %v", err)
	}
	_, err := threatsCall(f, threats.ListDetections, second, "tenantId", f.tenantID)
	f.refused(err, "ACCESS_DENIED")
	detection := f.object(threatsCall(f, threats.GetDetection, f.owner, "tenantId", f.tenantID, "detectionId", report.Get("detectionId")))
	if got := stringify(detection.Get("metadata")); got != `{"note":"line one\nline two"}` {
		t.Fatalf("metadata %s", got)
	}
	risk := f.object(threatsCall(f, threats.GetRisk, f.owner, "tenantId", f.tenantID, "identityId", aliceID))
	expectMatch(t, risk, `{"level":"medium","score":50,"kind":"user"}`)

	// principal.riskLevel reaches decisions.
	role := f.role(f.tenantID, "Readers while safe", allow(items("documents:read"), items("*"),
		"conditions", obj(t, `{"StringEquals":{"principal.riskLevel":"none"}}`)))
	f.bind(f.tenantID, role, "identity", aliceID)
	canRead := func() bool {
		decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: second, TenantID: f.tenantID, Action: "documents:read",
			Resource: ResourceTarget{Type: "document", ID: "d1"}})
		requirePorted(t, err)
		return decision.Allowed
	}
	if canRead() {
		t.Fatal("a person at medium risk should not read")
	}

	owner := f.ownerSignIn(f.tenantID)
	incident := f.object(threatsCall(f, threats.GetIncident, f.owner, "tenantId", f.tenantID, "incidentId", report.Get("incidentId")))
	if detections := threatsAPIObjects(incident.Get("detections")); len(detections) != 1 {
		t.Fatalf("expected one detection, got %d", len(detections))
	}
	actions := pluck(threatsAPIObjects(incident.Get("responses")), "action")
	if strings.Join(sortedStrings(actions), ",") != "forget-devices,revoke-sessions" {
		t.Fatalf("responses %v", actions)
	}
	expectMatch(t, incident.Get("risk"), `{"level":"medium"}`)
	f.ok(threatsCall(f, threats.AddNote, f.owner, "tenantId", f.tenantID, "incidentId", report.Get("incidentId"), "body", "Called alice.\nConfirmed."))
	updated := f.object(threatsCall(f, threats.UpdateIncident, f.owner, "tenantId", f.tenantID, "incidentId", report.Get("incidentId"),
		"status", "investigating", "assigneeId", f.ownerID))
	expectMatch(t, updated, `{"status":"investigating","assigneeId":"`+f.ownerID+`"}`)
	unassigned := f.object(threatsCall(f, threats.UpdateIncident, f.owner, "tenantId", f.tenantID, "incidentId", report.Get("incidentId"), "assigneeId", nil))
	if unassigned.Has("assigneeId") {
		t.Fatal("assigneeId should be gone")
	}

	_, err = threatsCall(f, threats.SetRisk, owner, "tenantId", f.tenantID, "identityId", f.ownerID, "level", "none", "reason", "x")
	f.refused(err, "ACCESS_DENIED")
	raised := f.object(threatsCall(f, threats.SetRisk, owner, "tenantId", f.tenantID, "identityId", aliceID, "level", "high",
		"reason", "confirmed", "expiresInMs", 3_600_000.0))
	expectMatch(t, raised, `{"level":"high","override":{"level":"high","active":true}}`)
	listed := f.object(threatsCall(f, threats.ListRisk, f.owner, "tenantId", f.tenantID, "minLevel", "high"))
	if ids := pluck(threatsAPIObjects(listed.Get("identities")), "identityId"); strings.Join(ids, ",") != aliceID {
		t.Fatalf("listRisk %v", ids)
	}

	contained := f.list(threatsCall(f, threats.Respond, owner, "tenantId", f.tenantID, "identityId", aliceID,
		"actions", items(core.NewObject("kind", "contain"), core.NewObject("kind", "notify")), "reason", "compromised"))
	got := []string{}
	for _, response := range contained {
		got = append(got, jsString(response.Get("action"))+"/"+jsString(response.Get("outcome"))+"/"+jsString(response.Get("reason")))
	}
	if strings.Join(got, ",") != "contain/applied/undefined,notify/skipped/no-recipients" {
		t.Fatalf("responses %v", got)
	}
	if contained[0].Get("incidentId") != report.Get("incidentId") {
		t.Fatal("the response should be filed under the open incident")
	}
	if _, err := f.iam.Context.Principals.Authenticate(f.ctx, second); err == nil {
		t.Fatal("a contained identity's sessions end")
	}
	released := f.object(threatsCall(f, threats.Release, owner, "tenantId", f.tenantID, "identityId", aliceID, "note", "ok"))
	expectMatch(t, released, `{"action":"release","outcome":"applied"}`)
	_, err = threatsCall(f, threats.Release, owner, "tenantId", f.tenantID, "identityId", aliceID)
	f.refused(err, "INVALID_TRANSITION")

	resolved := f.object(threatsCall(f, threats.ResolveIncident, owner, "tenantId", f.tenantID, "incidentId", report.Get("incidentId"),
		"resolution", "false-positive", "note", "Was the VPN."))
	expectMatch(t, resolved, `{"status":"resolved","resolution":"false-positive"}`)
	if resolved.Has("uniqueKey") {
		t.Fatal("a resolved incident has no uniqueKey")
	}
	after := f.object(threatsCall(f, threats.GetRisk, f.owner, "tenantId", f.tenantID, "identityId", aliceID))
	if contributions, _ := after.Get("contributions").([]any); len(contributions) != 0 {
		t.Fatalf("contributions %d", len(contributions))
	}
	if after.Get("level") != "high" { // the override still holds
		t.Fatalf("level %v", after.Get("level"))
	}
	f.ok(threatsCall(f, threats.SetRisk, owner, "tenantId", f.tenantID, "identityId", aliceID, "level", "none", "reason", "clear"))
	if level := f.object(threatsCall(f, threats.GetRisk, f.owner, "tenantId", f.tenantID, "identityId", aliceID)).Get("level"); level != "none" {
		t.Fatalf("level %v", level)
	}
	_, err = threatsCall(f, threats.ResolveIncident, owner, "tenantId", f.tenantID, "incidentId", report.Get("incidentId"), "resolution", "benign")
	f.refused(err, "INVALID_TRANSITION")
	expectStatus(t, err, 409)
	timeline := f.list(threatsCall(f, threats.Timeline, f.owner, "tenantId", f.tenantID, "identityId", aliceID))
	if threatsFind(timeline, "action", "threat:user-report") == nil {
		t.Fatal("the timeline should hold the report")
	}

	playbook := f.object(threatsCall(f, threats.CreatePlaybook, owner, "tenantId", f.tenantID, "name", "Contain reporters",
		"trigger", obj(t, `{"ruleIds":["user-reported"],"minSeverity":"high"}`),
		"actions", parse(t, `[{"kind":"revoke-sessions","keepApiKeys":false},{"kind":"block-network","durationMs":60000}]`)))
	_, err = threatsCall(f, threats.CreatePlaybook, owner, "tenantId", f.tenantID, "name", "contain REPORTERS",
		"trigger", core.NewObject(), "actions", parse(t, `[{"kind":"notify"}]`))
	f.refused(err, "CONFLICT")
	_, err = threatsCall(f, threats.CreatePlaybook, owner, "tenantId", f.tenantID, "name", "dup",
		"trigger", core.NewObject(), "actions", parse(t, `[{"kind":"notify"},{"kind":"notify"}]`))
	f.refused(err, "INVALID_INPUT")
	renamed := f.object(threatsCall(f, threats.UpdatePlaybook, owner, "tenantId", f.tenantID, "playbookId", playbook.Get("id"),
		"name", "Sign reporters out", "description", "d", "enabled", false))
	expectMatch(t, renamed, `{"name":"Sign reporters out","enabled":false,"description":"d"}`)
	if playbooks := f.list(threatsCall(f, threats.ListPlaybooks, f.owner, "tenantId", f.tenantID)); len(playbooks) != 1 {
		t.Fatalf("playbooks %d", len(playbooks))
	}
	deleted := f.object(threatsCall(f, threats.DeletePlaybook, owner, "tenantId", f.tenantID, "playbookId", playbook.Get("id")))
	if stringify(deleted) != `{"deleted":true}` {
		t.Fatalf("delete answered %s", stringify(deleted))
	}

	run := f.object(threatsCall(f, threats.Detect, f.owner, "tenantId", f.tenantID))
	expectMatch(t, run, `{"tenants":1}`)
	incidents := f.object(threatsCall(f, threats.ListIncidents, f.owner, "tenantId", f.tenantID, "status", "resolved"))
	expectMatch(t, incidents, `{"total":1}`)
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && compareUTF16(out[j-1], out[j]) > 0; j-- {
			out[j-1], out[j] = out[j], out[j-1]
		}
	}
	return out
}

func TestThreatsAPIContainsAnOwnerOnlyForAnOwnerInPersonOrRoot(t *testing.T) {
	f := newThreatsFixture(t)
	owner := f.ownerSignIn(f.tenantID)
	coOwner := f.member("coowner")
	coOwnerID := jsString(coOwner.Get("id"))
	_, err := f.iam.API.Identities.SetOwner(f.ctx, owner, Input[apitypes.IdentitiesSetOwnerInput](body("tenantId", f.tenantID, "identityId", coOwnerID, "owner", true)))
	requirePorted(t, err)
	_, analyst := f.memberWith("analyst", threatsAdministration())
	contain := items(core.NewObject("kind", "contain"))
	_, err = threatsCall(f, f.iam.API.Threats.Respond, analyst, "tenantId", f.tenantID, "identityId", coOwnerID, "actions", contain, "reason", "looks odd")
	f.refused(err, "ACCESS_DENIED")
	if f.statusOf(coOwnerID) != "active" {
		t.Fatal("the co-owner should stay active")
	}
	responses := f.list(threatsCall(f, f.iam.API.Threats.Respond, owner, "tenantId", f.tenantID, "identityId", coOwnerID, "actions", contain, "reason", "confirmed"))
	expectMatch(t, responses[0], `{"action":"contain","outcome":"applied"}`)
	if f.statusOf(coOwnerID) != "disabled" {
		t.Fatal("the co-owner should be disabled")
	}
}

func TestThreatsAPILeavesNetworkBlocksOnTheRootTenantToRoot(t *testing.T) {
	f := newThreatsFixture(t)
	rootTenantID := f.rootTenantID()
	api := f.iam.API
	analyst, err := api.ServiceAccounts.Create(f.ctx, f.rootCred, Input[apitypes.ServiceAccountsCreateInput](body("tenantId", rootTenantID, "name", "soc-bot")))
	requirePorted(t, err)
	analystID := jsString(member(analyst.Value, "id"))
	role := f.role(rootTenantID, "Platform SOC", allow(items("iam:threats:*"), items("*")))
	f.bind(rootTenantID, role, "identity", analystID)
	created, err := api.Credentials.Create(f.ctx, f.rootCred, Input[apitypes.CredentialsCreateInput](body("tenantId", rootTenantID, "identityId", analystID)))
	requirePorted(t, err)
	key := core.CredentialInput{Token: jsString(member(created.Value, "token"))}
	blocks := func() []string {
		return pluck(f.find("authBlocks", core.NewObject("tenantId", rootTenantID)), "network")
	}
	_, err = threatsCall(f, api.Threats.Respond, key, "tenantId", rootTenantID, "network", "198.51.100.0/24",
		"actions", items(core.NewObject("kind", "block-network", "durationMs", 30*24*threatsTestHour)), "reason", "suspicious")
	f.refused(err, "ACCESS_DENIED")
	if len(blocks()) != 0 {
		t.Fatal("no block expected")
	}
	byRoot := f.list(threatsCall(f, api.Threats.Respond, f.rootCred, "tenantId", rootTenantID, "network", "198.51.100.0/24",
		"actions", items(core.NewObject("kind", "block-network", "durationMs", 60_000)), "reason", "confirmed"))
	expectMatch(t, byRoot[0], `{"outcome":"applied"}`)

	// A playbook on the root tenant (anyone with iam:threats:manage may write one) never blocks a network.
	f.ok(threatsCall(f, api.Threats.Configure, f.rootCred, "tenantId", rootTenantID, "rules", obj(t, `{"brute-force":{"threshold":3}}`)))
	f.ok(threatsCall(f, api.Threats.CreatePlaybook, f.rootCred, "tenantId", rootTenantID, "name", "Block guessers",
		"trigger", obj(t, `{"ruleIds":["brute-force"]}`), "actions", parse(t, `[{"kind":"block-network"}]`)))
	_, err = f.iam.DetectThreats(f.ctx, core.NewObject("tenantId", rootTenantID))
	requirePorted(t, err)
	client := f.iam.Auth.WithClient(f.ctx, &core.SessionClientInfo{IP: "203.0.113.77", UserAgent: "test"})
	for attempt := 0; attempt < 3; attempt++ {
		_, _ = f.iam.Auth.SignIn(client, core.NewObject("tenantId", rootTenantID, "email", "root@example.test", "password", "not the root password at all"))
	}
	f.iam.Auth.SettleBookkeeping()
	run, err := f.iam.DetectThreats(f.ctx, core.NewObject("tenantId", rootTenantID))
	requirePorted(t, err)
	if jsNumber(run.Get("detections")) <= 0 {
		t.Fatal("expected detections")
	}
	automatic := []string{}
	for _, response := range f.find("threatResponses", core.NewObject("tenantId", rootTenantID, "action", "block-network")) {
		if truthy(response.Get("playbookId")) {
			automatic = append(automatic, jsString(response.Get("outcome"))+"/"+jsString(response.Get("reason")))
		}
	}
	if strings.Join(automatic, ",") != "skipped/protected" {
		t.Fatalf("automatic responses %v", automatic)
	}
	if strings.Join(blocks(), ",") != "198.51.100.0/24" {
		t.Fatalf("blocks %v", blocks())
	}
}

func TestThreatsAPINeverReleasesWhatAnotherPathChanged(t *testing.T) {
	f := newThreatsFixture(t)
	api := f.iam.API
	owner := f.ownerSignIn(f.tenantID)
	contain := func(identityID string) {
		t.Helper()
		f.ok(threatsCall(f, api.Threats.Respond, owner, "tenantId", f.tenantID, "identityId", identityID,
			"actions", items(core.NewObject("kind", "contain")), "reason", "test"))
	}
	release := func(identityID string) (any, error) {
		return threatsCall(f, api.Threats.Release, owner, "tenantId", f.tenantID, "identityId", identityID)
	}
	setStatus := func(identityID, status string) {
		t.Helper()
		_, err := api.Identities.SetStatus(f.ctx, owner, Input[apitypes.IdentitiesSetStatusInput](body("tenantId", f.tenantID, "identityId", identityID, "status", status)))
		requirePorted(t, err)
	}
	// Disabled again by an administrator.
	alice := jsString(f.member("alice").Get("id"))
	contain(alice)
	setStatus(alice, "disabled")
	_, err := release(alice)
	f.refused(err, "INVALID_TRANSITION")
	if f.statusOf(alice) != "disabled" {
		t.Fatal("alice should stay disabled")
	}
	// Offboarded.
	bob := jsString(f.member("bob").Get("id"))
	contain(bob)
	_, err = api.Identities.Offboard(f.ctx, owner, Input[apitypes.IdentitiesOffboardInput](body("tenantId", f.tenantID, "identityId", bob, "reason", "left")))
	requirePorted(t, err)
	_, err = release(bob)
	f.refused(err, "INVALID_TRANSITION")
	if f.statusOf(bob) != "disabled" {
		t.Fatal("bob should stay disabled")
	}
	// Re-enabled, then disabled for another reason.
	carol := jsString(f.member("carol").Get("id"))
	contain(carol)
	setStatus(carol, "active")
	if mark := f.record("identityRisk", carol); mark != nil && !isUndefined(mark.Get("contained")) {
		t.Fatal("the containment mark should be gone")
	}
	setStatus(carol, "disabled")
	_, err = release(carol)
	f.refused(err, "INVALID_TRANSITION")
	// An agent its sponsor suspended as well.
	agent, err := api.Agents.Create(f.ctx, owner, Input[apitypes.AgentsCreateInput](body("tenantId", f.tenantID, "name", "Triage bot", "sponsorId", f.ownerID)))
	requirePorted(t, err)
	agentID := jsString(member(agent.Value, "id"))
	contain(agentID)
	_, err = api.Agents.Suspend(f.ctx, owner, Input[apitypes.AgentsSuspendInput](body("tenantId", f.tenantID, "agentId", agentID, "reason", "prompt injection")))
	requirePorted(t, err)
	_, err = release(agentID)
	f.refused(err, "INVALID_TRANSITION")
	got, err := api.Agents.Get(f.ctx, owner, Input[apitypes.AgentsGetInput](body("tenantId", f.tenantID, "agentId", agentID)))
	requirePorted(t, err)
	if standing := member(got.Value, "standing"); standing != "suspended" {
		t.Fatalf("standing %v", standing)
	}
	// A containment nothing else touched is still released.
	dave := jsString(f.member("dave").Get("id"))
	contain(dave)
	expectMatch(t, f.object(release(dave)), `{"action":"release","outcome":"applied"}`)
	if f.statusOf(dave) != "active" {
		t.Fatal("dave should be active again")
	}
}

func TestThreatsAPIRevokesInvitationsAContainedIdentitySent(t *testing.T) {
	f := newThreatsFixture(t)
	inviterID, inviter := f.memberWith("inviter", allow(items("iam:identities:create"), items("*")))
	_, err := f.iam.API.Identities.Invite(f.ctx, inviter, Input[apitypes.IdentitiesInviteInput](body("tenantId", f.tenantID, "email", "attacker@evil.example")))
	requirePorted(t, err)
	owner := f.ownerSignIn(f.tenantID)
	f.ok(threatsCall(f, f.iam.API.Threats.Respond, owner, "tenantId", f.tenantID, "identityId", inviterID,
		"actions", items(core.NewObject("kind", "contain")), "reason", "taken over"))
	f.ok(threatsCall(f, f.iam.API.Threats.Release, owner, "tenantId", f.tenantID, "identityId", inviterID))
	invitations := f.find("memberInvitations", core.NewObject("inviterId", inviterID))
	if len(invitations) != 1 || invitations[0].Get("revoked") != true {
		t.Fatalf("invitations %s", stringify(threatsAPIList(invitations)))
	}
	if _, err := f.iam.Auth.DispatchOutbox(f.ctx, 0); err != nil {
		t.Fatal(err)
	}
	f.inboxMu.Lock()
	var token string
	for _, sent := range f.inbox {
		if sent.To == "attacker@evil.example" {
			token = sent.Payload["token"]
		}
	}
	f.inboxMu.Unlock()
	if token == "" {
		t.Fatal("the invitation was never sent")
	}
	_, err = f.iam.API.Identities.AcceptInvitation(f.ctx, Input[apitypes.IdentitiesAcceptInvitationInput](body("tenantId", f.tenantID, "token", token, "password", "a strong attacker password")))
	if err == nil {
		t.Fatal("a revoked invitation cannot be accepted")
	}
}

func TestThreatsAPINamesNobodyOnATenantIncidentOnceTwoPeopleAreBehindIt(t *testing.T) {
	f := newThreatsFixture(t)
	threats := f.iam.API.Threats
	aliceID, alice := f.memberWith("alice", threatsAdministration())
	malloryID, mallory := f.memberWith("mallory", threatsAdministration())
	f.ok(threatsCall(f, threats.Configure, alice, "tenantId", f.tenantID, "rules", obj(t, `{"recon-burst":{"enabled":false}}`)))
	opened := threatsAPIObjects(f.object(threatsCall(f, threats.ListIncidents, f.owner, "tenantId", f.tenantID)).Get("incidents"))[0]
	expectMatch(t, opened, `{"subject":{"type":"tenant"},"identityId":"`+aliceID+`"}`)
	f.ok(threatsCall(f, threats.Configure, mallory, "tenantId", f.tenantID, "rules", obj(t, `{"denial-burst":{"enabled":false}}`)))
	detail := f.object(threatsCall(f, threats.GetIncident, f.owner, "tenantId", f.tenantID, "incidentId", opened.Get("id")))
	incident, _ := detail.Get("incident").(*core.Object)
	expectMatch(t, incident, `{"detectionCount":2,"severalIdentities":true}`)
	if incident.Has("identityId") || detail.Has("risk") {
		t.Fatal("nobody is named on the incident")
	}
	// Containing "the incident" no longer contains whoever came first.
	responses := f.list(threatsCall(f, threats.Respond, f.ownerSignIn(f.tenantID), "tenantId", f.tenantID, "incidentId", opened.Get("id"),
		"actions", items(core.NewObject("kind", "contain")), "reason", "settings tampering"))
	expectMatch(t, responses[0], `{"outcome":"skipped","reason":"not-identity"}`)
	if f.statusOf(aliceID) != "active" || f.statusOf(malloryID) != "active" {
		t.Fatal("nobody should be contained")
	}
}

func TestThreatsAPIReportsWeakenedSettingsAndKeepsPeopleFromDecayingTheirOwnRisk(t *testing.T) {
	f := newThreatsFixture(t)
	threats := f.iam.API.Threats
	_, sec := f.memberWith("sec", threatsAdministration())
	// A detection about sec raises their risk; shortening the half-life would erase it at once.
	f.ok(threatsCall(f, threats.ReportSuspicious, sec, "tenantId", f.tenantID))
	_, err := threatsCall(f, threats.Configure, sec, "tenantId", f.tenantID, "riskHalfLifeHours", 1.0)
	f.refused(err, "ACCESS_DENIED")
	expectMatch(t, f.object(threatsCall(f, threats.GetSettings, f.owner, "tenantId", f.tenantID)), `{"riskHalfLifeHours":24}`)

	owner := f.ownerSignIn(f.tenantID)
	f.ok(threatsCall(f, threats.Configure, owner, "tenantId", f.tenantID, "riskHalfLifeHours", 2.0,
		"trustedNetworks", items("198.51.100.0/24"), "maxAutomaticContainments", 0.0, "rules", obj(t, `{"brute-force":{"threshold":1000}}`)))
	guardrails := func() []*core.Object {
		return threatsAPIObjects(f.object(threatsCall(f, threats.ListDetections, f.owner, "tenantId", f.tenantID, "ruleId", "guardrail-weakened")).Get("detections"))
	}
	found := guardrails()
	if len(found) != 1 {
		t.Fatalf("expected one guardrail detection, got %d", len(found))
	}
	expectMatch(t, found[0], `{"identityId":"`+f.ownerID+`","title":"Threat detection weakened","metadata":{"disabledRules":[],
		"weakened":["rules.brute-force.threshold","riskHalfLifeHours","trustedNetworks","maxAutomaticContainments"]}}`)
	// Strengthening them again raises nothing.
	f.ok(threatsCall(f, threats.Configure, owner, "tenantId", f.tenantID, "riskHalfLifeHours", 24.0, "trustedNetworks", items(),
		"maxAutomaticContainments", 3.0, "rules", core.NewObject("brute-force", nil)))
	if len(guardrails()) != 1 {
		t.Fatal("strengthening raises nothing")
	}
}

func TestThreatsAPIKeepsRiskContributionsThroughAShortenedHalfLife(t *testing.T) {
	f := newThreatsFixture(t)
	threats := f.iam.API.Threats
	alice := f.member("alice")
	f.ok(threatsCall(f, threats.ReportSuspicious, f.signIn(alice), "tenantId", f.tenantID))
	f.ok(threatsCall(f, threats.Configure, f.ownerSignIn(f.tenantID), "tenantId", f.tenantID, "riskHalfLifeHours", 1.0))
	f.advance(12 * threatsTestHour)
	// A new detection recomputes the risk under the one-hour half-life: the older contribution is kept.
	f.ok(threatsCall(f, threats.ReportSuspicious, f.signIn(alice), "tenantId", f.tenantID))
	risk := func() *core.Object {
		return f.object(threatsCall(f, threats.GetRisk, f.owner, "tenantId", f.tenantID, "identityId", alice.Get("id")))
	}
	if contributions, _ := risk().Get("contributions").([]any); len(contributions) != 2 {
		t.Fatalf("contributions %d", len(contributions))
	}
	// Restoring the half-life brings the earlier detection's weight back.
	f.ok(threatsCall(f, threats.Configure, f.ownerSignIn(f.tenantID), "tenantId", f.tenantID, "riskHalfLifeHours", 24.0))
	expectMatch(t, risk(), `{"level":"high","score":85}`)
}

func TestThreatsAPINamesPeopleAsTheRulesDoAndGivesIdentitySubjectsTheirKind(t *testing.T) {
	f := newThreatsFixture(t)
	threats := f.iam.API.Threats
	alice := f.member("alice")
	aliceID := jsString(alice.Get("id"))
	report := f.object(threatsCall(f, threats.ReportSuspicious, f.signIn(alice), "tenantId", f.tenantID))
	reported := f.object(threatsCall(f, threats.GetDetection, f.owner, "tenantId", f.tenantID, "detectionId", report.Get("detectionId")))
	wantSubject := `{"type":"identity","id":"` + aliceID + `","name":"alice (alice@acme.test)","kind":"user"}`
	if got := stringify(reported.Get("subject")); got != wantSubject {
		t.Fatalf("subject %s", got)
	}
	if reported.Get("summary") != "alice (alice@acme.test) reported activity on their account that was not them." {
		t.Fatalf("summary %v", reported.Get("summary"))
	}
	detail := f.object(threatsCall(f, threats.GetIncident, f.owner, "tenantId", f.tenantID, "incidentId", report.Get("incidentId")))
	if got := stringify(member(detail.Get("incident"), "subject")); got != wantSubject {
		t.Fatalf("incident subject %s", got)
	}
	if kind := member(threatsAPIObjects(detail.Get("detections"))[0].Get("subject"), "kind"); kind != "user" {
		t.Fatalf("detection kind %v", kind)
	}
	// The kind is looked up when read, never stored.
	for _, stored := range [][2]string{{"threatDetections", jsString(report.Get("detectionId"))}, {"threatIncidents", jsString(report.Get("incidentId"))}} {
		if got := stringify(f.record(stored[0], stored[1]).Get("subject")); got != `{"type":"identity","id":"`+aliceID+`","name":"alice (alice@acme.test)"}` {
			t.Fatalf("stored subject %s", got)
		}
	}

	// An AI agent denied again and again: its detection and incident link to an agent.
	owner := f.ownerSignIn(f.tenantID)
	agent, err := f.iam.API.Agents.Create(f.ctx, owner, Input[apitypes.AgentsCreateInput](body("tenantId", f.tenantID, "name", "Triage bot", "sponsorId", f.ownerID)))
	requirePorted(t, err)
	agentID := jsString(member(agent.Value, "id"))
	created, err := f.iam.API.Credentials.Create(f.ctx, f.owner, Input[apitypes.CredentialsCreateInput](body("tenantId", f.tenantID, "identityId", agentID)))
	requirePorted(t, err)
	token := core.CredentialInput{Token: jsString(member(created.Value, "token"))}
	f.ok(threatsCall(f, threats.Configure, owner, "tenantId", f.tenantID, "rules", obj(t, `{"denial-burst":{"threshold":5},"recon-burst":{"enabled":false}}`)))
	_, err = f.iam.DetectThreats(f.ctx, core.NewObject("tenantId", f.tenantID))
	requirePorted(t, err)
	for attempt := 0; attempt < 5; attempt++ {
		decision, err := f.iam.Authorize(f.ctx, AuthorizationRequest{Credential: token, TenantID: f.tenantID, Action: "documents:read", Resource: ResourceTarget{Type: "document", ID: "d1"}})
		requirePorted(t, err)
		if decision.Allowed {
			t.Fatal("the agent holds no access")
		}
	}
	_, err = f.iam.DetectThreats(f.ctx, core.NewObject("tenantId", f.tenantID))
	requirePorted(t, err)
	denials := threatsAPIObjects(f.object(threatsCall(f, threats.ListDetections, f.owner, "tenantId", f.tenantID, "ruleId", "denial-burst")).Get("detections"))
	if len(denials) == 0 {
		t.Fatal("expected a denial-burst detection")
	}
	expectMatch(t, denials[0].Get("subject"), `{"type":"identity","id":"`+agentID+`","kind":"agent"}`)
	agentIncidents := threatsAPIObjects(f.object(threatsCall(f, threats.ListIncidents, f.owner, "tenantId", f.tenantID, "identityId", agentID)).Get("incidents"))
	if len(agentIncidents) == 0 {
		t.Fatal("expected an incident about the agent")
	}
	expectMatch(t, agentIncidents[0].Get("subject"), `{"id":"`+agentID+`","kind":"agent"}`)
	expectMatch(t, f.object(threatsCall(f, threats.UpdateIncident, f.owner, "tenantId", f.tenantID, "incidentId", agentIncidents[0].Get("id"), "status", "investigating")),
		`{"status":"investigating","subject":{"kind":"agent"}}`)

	// Subjects other than identities have no kind; the settings detection names its author as the rules do.
	weakened := threatsAPIObjects(f.object(threatsCall(f, threats.ListDetections, f.owner, "tenantId", f.tenantID, "ruleId", "guardrail-weakened")).Get("detections"))[0]
	if got := stringify(weakened.Get("subject")); got != `{"type":"tenant","id":"`+f.tenantID+`","name":"Acme"}` {
		t.Fatalf("tenant subject %s", got)
	}
	if !strings.HasPrefix(jsString(weakened.Get("summary")), "Owner (owner@acme.test) turned off 1 detection rule: ") {
		t.Fatalf("summary %v", weakened.Get("summary"))
	}
}

func TestThreatsAPIListsIncidentsInOneStatusOrSeveral(t *testing.T) {
	f := newThreatsFixture(t)
	threats := f.iam.API.Threats
	reports := map[string]any{}
	for _, name := range []string{"alice", "bob", "carol"} {
		person := f.member(name)
		reports[name] = f.object(threatsCall(f, threats.ReportSuspicious, f.signIn(person), "tenantId", f.tenantID)).Get("incidentId")
		f.advance(60_000)
	}
	owner := f.ownerSignIn(f.tenantID)
	f.ok(threatsCall(f, threats.UpdateIncident, owner, "tenantId", f.tenantID, "incidentId", reports["bob"], "status", "investigating"))
	f.ok(threatsCall(f, threats.ResolveIncident, owner, "tenantId", f.tenantID, "incidentId", reports["carol"], "resolution", "true-positive"))
	list := func(status any, page ...any) (string, error) {
		pairs := append([]any{"tenantId", f.tenantID, "status", status}, page...)
		result, err := threatsCall(f, threats.ListIncidents, f.owner, pairs...)
		if err != nil {
			return "", err
		}
		incidents := threatsAPIObjects(member(result, "incidents"))
		return strings.Join(pluck(incidents, "id"), ",") + " / " + core.NumberString(jsNumber(member(result, "total"))), nil
	}
	expect := func(want string, status any, page ...any) {
		t.Helper()
		got, err := list(status, page...)
		requirePorted(t, err)
		if got != want {
			t.Fatalf("listIncidents(%s): %s, want %s", stringify(status), got, want)
		}
	}
	id := func(name string) string { return jsString(reports[name]) }
	// Most recently active first across the statuses asked for.
	expect(id("bob")+","+id("alice")+" / 2", items("open", "investigating"))
	expect(id("alice")+" / 2", items("open", "investigating"), "limit", 1.0, "offset", 1.0)
	expect(id("alice")+" / 1", "open")
	expect(id("alice")+" / 1", items("open", "open"))
	expect(id("carol")+" / 1", items("resolved"))
	expect(id("carol")+","+id("bob")+","+id("alice")+" / 3", items("resolved", "investigating", "open"))
	for _, bad := range []any{items(), items("open", "closed"), "closed", 3.0, items("open", "investigating", "resolved", "open")} {
		_, err := list(bad)
		flagExpectCode(t, err, "INVALID_INPUT")
	}
}

func TestThreatsAPIBoundsTheTimelineWithUntil(t *testing.T) {
	f := newThreatsFixture(t)
	threats := f.iam.API.Threats
	alice := f.member("alice")
	f.ok(threatsCall(f, threats.ReportSuspicious, f.signIn(alice), "tenantId", f.tenantID))
	// A later sign-in (auth events follow the injected clock).
	f.advance(threatsTestHour)
	_, err := f.iam.Auth.SignIn(f.ctx, core.NewObject("tenantId", f.tenantID, "email", "alice@acme.test", "password", "a strong alice password"))
	requirePorted(t, err)
	timeline := func(pairs ...any) ([]*core.Object, error) {
		result, err := threatsCall(f, threats.Timeline, f.owner, append([]any{"tenantId", f.tenantID, "identityId", alice.Get("id")}, pairs...)...)
		return threatsAPIObjects(result), err
	}
	everything, err := timeline("since", 0.0)
	requirePorted(t, err)
	reportedAt := jsNumber(threatsFind(everything, "action", "threat:user-report").Get("timestamp"))
	before := []string{}
	for _, event := range everything {
		if jsNumber(event.Get("timestamp")) <= reportedAt {
			before = append(before, jsString(event.Get("id")))
		}
	}
	if len(before) >= len(everything) {
		t.Fatal("the later sign-in should come after the report")
	}
	bounded, err := timeline("since", 0.0, "until", reportedAt)
	requirePorted(t, err)
	if strings.Join(pluck(bounded, "id"), ",") != strings.Join(before, ",") {
		t.Fatal("until bounds the timeline")
	}
	// Without since, the window is the seven days before until.
	week, err := timeline("until", reportedAt)
	requirePorted(t, err)
	if strings.Join(pluck(week, "id"), ",") != strings.Join(before, ",") {
		t.Fatal("the default window is the week before until")
	}
	for _, bad := range [][]any{
		{"since", reportedAt, "until", reportedAt},
		{"since", reportedAt, "until", reportedAt - 1},
		{"until", -1.0},
		{"until", "soon"},
	} {
		_, err := timeline(bad...)
		flagExpectCode(t, err, "INVALID_INPUT")
	}
}

// --- validators (api_threats.go private helpers) ----------------------------------------------------------------

func TestThreatsAPIMultilineNormalizesLineBreaksAndDropsControls(t *testing.T) {
	got, err := threatsAPIMultiline("  line one\r\nline two\u0007\rthree\n\tfour  ", "note", 1000)
	if err != nil {
		t.Fatal(err)
	}
	if got != "line one\nline two\nthree\n\tfour" {
		t.Fatalf("got %q", got)
	}
	expectError(t, func() error { _, err := threatsAPIMultiline(" \r\n\u0001 ", "body", 10); return err }(), "INVALID_INPUT", "body must be 1-10 characters")
	expectError(t, func() error { _, err := threatsAPIMultiline("abcdefghijk", "body", 10); return err }(), "INVALID_INPUT", "body must be 1-10 characters")
	expectError(t, func() error { _, err := threatsAPIMultiline(strings.Repeat("a", 41), "body", 10); return err }(), "INVALID_INPUT", "Invalid body")
	expectError(t, func() error { _, err := threatsAPIMultiline(3.0, "note", 10); return err }(), "INVALID_INPUT", "Invalid note")
}

func TestThreatsAPITrustedNetworksRefuseWideBlocks(t *testing.T) {
	for network, wide := range map[string]bool{
		"10.0.0.0/8": false, "10.0.0.0/7": true, "0.0.0.0/0": true, "10.1.2.3": false,
		"2001:db8::/32": false, "2001:db8::/31": true, "::ffff:0:0/96": true, "::ffff:10.0.0.0/104": false,
	} {
		if got := threatsAPITooWide(network); got != wide {
			t.Errorf("tooWide(%s) = %v", network, got)
		}
	}
	networks, err := threatsAPITrustedNetworksOf(items(" 10.0.0.0/8 ", "10.0.0.0/8", "192.0.2.1"))
	if err != nil || stringify(networks) != `["10.0.0.0/8","192.0.2.1"]` {
		t.Fatalf("networks %s %v", stringify(networks), err)
	}
	_, err = threatsAPITrustedNetworksOf(items("0.0.0.0/0"))
	expectError(t, err, "INVALID_INPUT", "Trusted networks may be at most /8 (IPv4) or /32 (IPv6) wide")
	_, err = threatsAPITrustedNetworksOf(items("not an ip"))
	expectError(t, err, "INVALID_INPUT", "trustedNetworks entries must be IPv4/IPv6 addresses or CIDR blocks")
	_, err = threatsAPITrustedNetworksOf("10.0.0.0/8")
	expectError(t, err, "INVALID_INPUT", "trustedNetworks must list at most 50 networks")
}

func TestThreatsAPINotifySettings(t *testing.T) {
	current := core.NewObject("owners", false, "emails", items("a@example.test"))
	next, err := threatsAPINotifyOf(obj(t, `{"owners":true}`), current)
	if err != nil || stringify(next) != `{"owners":true,"emails":["a@example.test"]}` {
		t.Fatalf("notify %s %v", stringify(next), err)
	}
	next, err = threatsAPINotifyOf(obj(t, `{"emails":[" B@Example.test ","b@example.test"]}`), current)
	if err != nil || stringify(next) != `{"owners":false,"emails":["b@example.test"]}` {
		t.Fatalf("notify %s %v", stringify(next), err)
	}
	_, err = threatsAPINotifyOf(obj(t, `{"pager":true}`), current)
	expectError(t, err, "INVALID_INPUT", "Unknown notify setting pager")
	_, err = threatsAPINotifyOf(obj(t, `{"owners":"yes"}`), current)
	expectError(t, err, "INVALID_INPUT", "notify.owners must be a boolean")
	_, err = threatsAPINotifyOf(obj(t, `{"emails":["nope"]}`), current)
	expectError(t, err, "INVALID_INPUT", "Invalid email")
	_, err = threatsAPINotifyOf(nil, current)
	expectError(t, err, "INVALID_INPUT", "Expected an object")
}

func TestThreatsAPIResponseActions(t *testing.T) {
	actions, err := threatsAPIResponseActionsOf(parse(t, `[{"kind":"block-network","durationMs":60000},{"kind":"revoke-sessions","keepApiKeys":true}]`), "actions")
	if err != nil || stringify(actions) != `[{"kind":"block-network","durationMs":60000},{"kind":"revoke-sessions","keepApiKeys":true}]` {
		t.Fatalf("actions %s %v", stringify(actions), err)
	}
	for bad, message := range map[string]string{
		`[]`:                                    "actions must list 1-5 response actions",
		`[{"kind":"notify"},{"kind":"notify"}]`: "actions may list each kind of action once",
		`[{"kind":"shout"}]`:                    "actions kind must be one of revoke-sessions, forget-devices, contain, suspend-clearance, block-network, notify",
		`[{"kind":"contain","durationMs":60000}]`:        "durationMs applies to block-network only",
		`[{"kind":"block-network","durationMs":1}]`:      "Invalid durationMs",
		`[{"kind":"contain","keepApiKeys":true}]`:        "keepApiKeys applies to revoke-sessions only",
		`[{"kind":"revoke-sessions","keepApiKeys":"y"}]`: "keepApiKeys must be a boolean",
		`[{"kind":"notify","extra":1}]`:                  "Unknown response action field extra",
	} {
		_, err := threatsAPIResponseActionsOf(parse(t, bad), "actions")
		expectError(t, err, "INVALID_INPUT", message)
	}
	if !threatsAPISuspendsClearances(parse(t, `[{"kind":"notify"},{"kind":"suspend-clearance"}]`)) || threatsAPISuspendsClearances(parse(t, `[{"kind":"notify"}]`)) {
		t.Fatal("suspendsClearances")
	}
}

func TestThreatsAPIPlaybookTriggersAndMetadata(t *testing.T) {
	trigger, err := threatsAPIPlaybookTrigger(obj(t, `{"subjectTypes":["identity","identity"],"minSeverity":"high","ruleIds":["brute-force","user-reported","brute-force"]}`))
	if err != nil || stringify(trigger) != `{"ruleIds":["brute-force","user-reported"],"minSeverity":"high","subjectTypes":["identity"]}` {
		t.Fatalf("trigger %s %v", stringify(trigger), err)
	}
	if trigger, err = threatsAPIPlaybookTrigger(obj(t, `{"ruleIds":null}`)); err != nil || stringify(trigger) != `{}` {
		t.Fatalf("trigger %s %v", stringify(trigger), err)
	}
	_, err = threatsAPIPlaybookTrigger(core.Undefined)
	expectError(t, err, "INVALID_INPUT", "trigger is required ({} matches every detection)")
	_, err = threatsAPIPlaybookTrigger(obj(t, `{"when":"now"}`))
	expectError(t, err, "INVALID_INPUT", "Unknown trigger field when")
	_, err = threatsAPIPlaybookTrigger(obj(t, `{"ruleIds":[]}`))
	expectError(t, err, "INVALID_INPUT", "trigger.ruleIds must list 1-22 detection rules")
	_, err = threatsAPIPlaybookTrigger(obj(t, `{"ruleIds":["nope"]}`))
	expectError(t, err, "INVALID_INPUT", "trigger.ruleIds names an unknown detection rule")
	_, err = threatsAPIPlaybookTrigger(obj(t, `{"subjectTypes":["identity","network","tenant","connection","identity"]}`))
	expectError(t, err, "INVALID_INPUT", "trigger.subjectTypes must list 1-4 subject types")
	_, err = threatsAPIPlaybookTrigger(obj(t, `{"minSeverity":"extreme"}`))
	expectError(t, err, "INVALID_INPUT", "trigger.minSeverity must be one of low, medium, high, critical")
	metadata := threatsAPIPlaybookMetadata(obj(t, `{"id":"p","name":"N","enabled":true,"trigger":{"minSeverity":"high"},
		"actions":[{"kind":"block-network","durationMs":60000},{"kind":"notify"}],"runs":3}`))
	if stringify(metadata) != `{"name":"N","enabled":true,"trigger":{"minSeverity":"high"},"actions":[{"kind":"block-network","durationMs":60000},{"kind":"notify"}]}` {
		t.Fatalf("metadata %s", stringify(metadata))
	}
	name, err := threatsAPIPlaybookName("  Contain  ")
	if err != nil || name != "Contain" {
		t.Fatalf("name %q %v", name, err)
	}
	_, err = threatsAPIPlaybookName(strings.Repeat("n", 101))
	expectError(t, err, "INVALID_INPUT", "Invalid name")
}

func TestThreatsAPIPagingStatusesAndWords(t *testing.T) {
	limit, offset, err := threatsAPIPaging(body("limit", nil))
	if err != nil || limit != 100 || offset != 0 {
		t.Fatalf("paging %v %v %v", limit, offset, err)
	}
	_, _, err = threatsAPIPaging(body("limit", 0.0))
	expectError(t, err, "INVALID_INPUT", "Invalid limit")
	_, _, err = threatsAPIPaging(body("offset", -1.0))
	expectError(t, err, "INVALID_INPUT", "Invalid offset")
	statuses, err := threatsAPIIncidentStatusesOf(items("open", "open", "resolved"))
	if err != nil || strings.Join(statuses, ",") != "open,resolved" {
		t.Fatalf("statuses %v %v", statuses, err)
	}
	_, err = threatsAPIIncidentStatusesOf(items())
	expectError(t, err, "INVALID_INPUT", "status must list 1-3 incident statuses")
	_, err = threatsAPIIncidentStatusesOf("closed")
	expectError(t, err, "INVALID_INPUT", "status must be one of open, investigating, resolved")
	for want, words := range map[string][]string{
		"": {}, "a": {"a"}, "a and b": {"a", "b"}, "a, b and c": {"a", "b", "c"}, "a, b, c and 1 more": {"a", "b", "c", "d"},
	} {
		if got := threatsAPIListed(words, 3); got != want {
			t.Errorf("listed(%v) = %q", words, got)
		}
	}
	if got := threatsAPISlice(strings.Repeat("é", 70), 64); utf16Len(got) != 64 {
		t.Fatalf("slice %d", utf16Len(got))
	}
	if threatsAPIRuleSignature(obj(t, `{"enabled":true,"severity":"high","everyone":"yes"}`)) != `[true,"high",null,null,false]` {
		t.Fatal("rule signature")
	}
	if threatsAPICanonical(obj(t, `{"b":1,"a":{"d":2,"c":3}}`)) != threatsAPICanonical(obj(t, `{"a":{"c":3,"d":2},"b":1}`)) {
		t.Fatal("canonical ignores key order")
	}
}

func TestThreatsAPIRiskViewAndSubjectKinds(t *testing.T) {
	identity := obj(t, `{"id":"i1","tenantId":"t1","name":"Alice","email":"","kind":"user","status":"disabled"}`)
	record := obj(t, `{"id":"i1","tenantId":"t1","identityId":"i1","contributions":[],"score":0,"level":"none",
		"contained":{"at":1,"by":"threat-detection","reason":"r"},"updatedAt":5}`)
	if !truthy(threatsAPIContainment(identity, record)) {
		t.Fatal("a disabled identity with a mark is contained")
	}
	if truthy(threatsAPIContainment(identity.Spread().Set("status", "active"), record)) {
		t.Fatal("an active identity is not contained, whatever the mark says")
	}
	f := newThreatsFixture(t)
	alice := f.member("alice")
	records := []*core.Object{
		core.NewObject("id", "d1", "subject", core.NewObject("type", "identity", "id", alice.Get("id"), "name", "alice")),
		core.NewObject("id", "d2", "subject", core.NewObject("type", "tenant", "id", f.tenantID)),
		core.NewObject("id", "d3", "subject", core.NewObject("type", "identity", "id", "elsewhere")),
	}
	var views []*core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		var err error
		views, err = threatsAPIWithSubjectKinds(ctx, tx, f.tenantID, records, nil)
		return err
	})
	if got := stringify(views[0].Get("subject")); got != `{"type":"identity","id":"`+jsString(alice.Get("id"))+`","name":"alice","kind":"user"}` {
		t.Fatalf("subject %s", got)
	}
	if views[1] != records[1] || views[2] != records[2] || records[0].Get("subject").(*core.Object).Has("kind") {
		t.Fatal("only identity subjects of the tenant gain a kind, and records are never changed")
	}
	if math.IsNaN(threatsAPIHalfLife(core.NewObject("riskHalfLifeHours", 24.0))) {
		t.Fatal("half-life")
	}
}
