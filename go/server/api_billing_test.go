package server

// Ports of tests/billing.test.ts, tests/billing-invoicing.test.ts and tests/security-billing.test.ts (the `billing`
// API group and `iam.billing`), plus tests of the group's own paths that run without the billing ledger. The pure
// pricing tests of those files exercise billing.ts and live with its port. Organizations are created with
// `activate: true` (see api_tenants_test.go) instead of redeeming an owner invitation, and the fixture's owner is
// `Acme@example.test`. Steps that reach another unit's NOT_IMPLEMENTED stub (billing.ts, billing-service.ts,
// billing-plans.ts, billing-invoices.ts) skip the rest of the test.

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const billingDay = 86_400_000.0

// billingFixture is a test file's setup(): Acme, the platform's `api-calls` meter, and fresh root and owner
// sessions (`root`, `owner`) that refresh renews after the clock moves.
type billingFixture struct {
	*orgFixture
	rootID string
	root   core.CredentialInput
	owner  core.CredentialInput
}

// newBillingFixture is organizationFixture with the options a test file needs.
func newBillingFixture(t *testing.T, mutate func(options *BetterIamOptions)) *billingFixture {
	t.Helper()
	f := newOrgFixture(t, mutate)
	return &billingFixture{orgFixture: f, rootID: f.rootID, root: f.credential, owner: f.owner}
}

// call calls a route of the API surface with the body members.
func (b *billingFixture) call(route string, credential core.CredentialInput, members ...any) (any, error) {
	b.t.Helper()
	handler, ok := rpcRoutes[route]
	if !ok {
		b.t.Fatalf("no route %s", route)
	}
	return handler(b.ctx, b.iam.API, credential, core.NewObject(members...))
}

// object is call for an answer that is one object; another unit's stub skips the rest of the test.
func (b *billingFixture) object(route string, credential core.CredentialInput, members ...any) *core.Object {
	b.t.Helper()
	answer, err := b.call(route, credential, members...)
	requirePorted(b.t, err)
	result, ok := answer.(*core.Object)
	if !ok {
		b.t.Fatalf("%s: expected an object, got %T", route, answer)
	}
	return result
}

// list is call for an answer that is a list.
func (b *billingFixture) list(route string, credential core.CredentialInput, members ...any) []*core.Object {
	b.t.Helper()
	answer, err := b.call(route, credential, members...)
	requirePorted(b.t, err)
	return billingTestRecords(b.t, answer)
}

// rejects is `rejects.toMatchObject({ code })`.
func (b *billingFixture) rejects(code string, route string, credential core.CredentialInput, members ...any) {
	b.t.Helper()
	_, err := b.call(route, credential, members...)
	expectCodeOrSkip(b.t, err, code)
}

// ported unwraps a runtime answer.
func (b *billingFixture) ported(value *core.Object, err error) *core.Object {
	b.t.Helper()
	requirePorted(b.t, err)
	return value
}

// advance moves the clock.
func (b *billingFixture) advance(ms float64) { b.clock.Add(int64(ms)) }

// refresh renews the sessions after the clock moved (a fresh TOTP step).
func (b *billingFixture) refresh() {
	b.t.Helper()
	b.advance(30_000)
	b.root = b.complianceRootSignIn()
	b.owner = b.ownerSignIn()
}

// period is periodOf(at, 'UTC').
func (b *billingFixture) period(at float64) string {
	b.t.Helper()
	period, err := PeriodOf(int64(at), "UTC")
	requirePorted(b.t, err)
	return period
}

// shift is shiftPeriod(period, months).
func (b *billingFixture) shift(period string, months float64) string {
	b.t.Helper()
	shifted, err := ShiftPeriod(period, months)
	requirePorted(b.t, err)
	return shifted
}

// bounds is periodBounds(period, 'UTC').
func (b *billingFixture) bounds(period string) (start, end float64) {
	b.t.Helper()
	found, err := PeriodBounds(period, "UTC")
	requirePorted(b.t, err)
	return jsNumber(found.Get("start")), jsNumber(found.Get("end"))
}

// boundsObject is periodBounds(period, 'UTC') as the record it is.
func (b *billingFixture) boundsObject(period string) *core.Object {
	b.t.Helper()
	found, err := PeriodBounds(period, "UTC")
	requirePorted(b.t, err)
	return found
}

// toNextMonth moves the clock to `date` of the next month (00:00 UTC) and renews the sessions.
func (b *billingFixture) toNextMonth(date float64) {
	b.t.Helper()
	start, _ := b.bounds(b.shift(b.period(b.now()), 1))
	b.advance(start + (date-1)*billingDay - b.now())
	b.refresh()
}

// meter creates the platform `api-calls` meter with a price effective from last month.
func (b *billingFixture) apiCalls(credential core.CredentialInput, unit string, price *core.Object) {
	b.t.Helper()
	members := []any{"tenantId", b.rootID, "key", "api-calls", "name", "API calls"}
	if unit != "" {
		members = append(members, "unit", unit)
	}
	b.object("billing/createMeter", credential, members...)
	b.object("billing/setPrice", credential, "tenantId", b.rootID, "meter", "api-calls",
		"effectiveFrom", b.shift(b.period(b.now()), -1), "price", price)
}

// graduatedCalls is 1000 free calls a month, then $0.01 each up to 10 000, then $0.005.
func graduatedCalls() *core.Object {
	return core.NewObject("model", "graduated", "includedQuantity", 1000, "tiers", []any{
		core.NewObject("upTo", 10_000, "unitAmount", 0.01),
		core.NewObject("upTo", nil, "unitAmount", 0.005),
	})
}

// inboxOf is the delivered messages of a template (after dispatching the outbox).
func (b *billingFixture) inboxOf(template string) []auth.DeliveryMessage {
	b.t.Helper()
	b.dispatch()
	b.mu.Lock()
	defer b.mu.Unlock()
	var found []auth.DeliveryMessage
	for _, message := range b.inbox {
		if message.Template == template {
			found = append(found, message)
		}
	}
	return found
}

// ownerEmail is the fixture owner's (normalized) address.
func (b *billingFixture) ownerEmail() string { return jsString(b.org.owner.Get("email")) }

// render renders a delivery as renderDeliveryMessage would.
func billingRender(t *testing.T, message auth.DeliveryMessage, options auth.TemplateOptions) *auth.RenderedMessage {
	t.Helper()
	rendered, err := auth.RenderDeliveryMessage(auth.TemplateMessage{
		Template: message.Template, To: message.To, Payload: message.Payload, TenantID: message.TenantID, SignInURL: message.SignInURL,
	}, options)
	if err != nil || rendered == nil {
		t.Fatalf("render %s: %v", message.Template, err)
	}
	return rendered
}

// billingTestRecords is an answer that is a list of records.
func billingTestRecords(t *testing.T, answer any) []*core.Object {
	t.Helper()
	list, ok := answer.([]any)
	if !ok {
		t.Fatalf("expected a list, got %T", answer)
	}
	result := make([]*core.Object, len(list))
	for index, item := range list {
		result[index] = item.(*core.Object)
	}
	return result
}

// pluck is `list.map((row) => [row[a], row[b], ...])`.
func billingPluck(list []*core.Object, keys ...string) []any {
	out := make([]any, len(list))
	for index, row := range list {
		values := make([]any, len(keys))
		for position, key := range keys {
			values[position] = row.Get(key)
		}
		out[index] = values
	}
	return out
}

// labelOrKey is `row.label ?? row.key`.
func billingLabelOrKey(list []*core.Object) []any {
	out := make([]any, len(list))
	for index, row := range list {
		out[index] = []any{coalesce(row.Get("label"), row.Get("key")), row.Get("amount")}
	}
	return out
}

// rowsOf is a report's rows.
func billingRows(t *testing.T, report *core.Object) []*core.Object {
	t.Helper()
	return billingTestRecords(t, report.Get("rows"))
}

// expectNumber compares a number.
func billingExpectNumber(t *testing.T, label string, got any, want float64) {
	t.Helper()
	if number, ok := core.Normalize(got).(float64); !ok || number != want {
		t.Fatalf("%s: expected %v, got %s", label, want, core.MustStringify(got))
	}
}

// billingCents is `Math.round(micros / 10_000) * 10_000`: invoices bill whole cents.
func billingCents(micros float64) float64 { return billingMathRound(micros/10_000) * 10_000 }

// billingRest is the share of `period` from `from` to its end, as billing rounds it (four decimals).
func (b *billingFixture) rest(from float64, period string) float64 {
	start, end := b.bounds(period)
	return billingMathRound(((end-from)/(end-start))*10_000) / 10_000
}

// ---------------------------------------------------------------------------------------------------------------
// tests/billing.test.ts

// billingSetup is billing.test.ts setup(): Acme with the platform `api-calls` meter and three members.
type billingSetup struct {
	*billingFixture
	alice, bob, carol *core.Object
}

func newBillingSetup(t *testing.T, mutate func(options *BetterIamOptions)) *billingSetup {
	t.Helper()
	b := newBillingFixture(t, mutate)
	b.apiCalls(b.root, "request", graduatedCalls())
	return &billingSetup{billingFixture: b, alice: b.member("alice"), bob: b.member("bob"), carol: b.member("carol")}
}

// record records api-calls usage in Acme as its owner.
func (s *billingSetup) record(identityID any, quantity float64, extra ...any) (any, error) {
	s.t.Helper()
	members := append([]any{"tenantId", s.tenantID, "meter", "api-calls", "quantity", quantity, "identityId", identityID}, extra...)
	return s.call("billing/record", s.owner, members...)
}

func (s *billingSetup) recorded(identityID any, quantity float64, extra ...any) *core.Object {
	s.t.Helper()
	answer, err := s.record(identityID, quantity, extra...)
	requirePorted(s.t, err)
	return answer.(*core.Object)
}

// previousPeriodStart is the first instant of last month.
func (s *billingSetup) previousPeriodStart() float64 {
	start, _ := s.bounds(s.shift(s.period(s.now()), -1))
	return start
}

// project is a project under Acme with its owner signed in.
func (s *billingSetup) project(name string) organization {
	s.t.Helper()
	return s.createTenant(name, s.tenantID, "project")
}

func TestBillingPricesTheAccountTotalOnceAndSharesItOutByPersonMeterAndProject(t *testing.T) {
	s := newBillingSetup(t, nil)
	apollo := s.project("Apollo")
	s.recorded(s.alice.Get("id"), 3000)
	s.recorded(s.bob.Get("id"), 500)
	s.object("billing/record", apollo.credential, "tenantId", apollo.id, "meter", "api-calls", "quantity", 500)
	// 4000 calls, 1000 free: 3000 × $0.01 = $30, shared by quantity (75% / 12.5% / 12.5%).
	byPerson := s.object("billing/spend", s.owner, "tenantId", s.tenantID, "groupBy", "identity")
	expectMatch(t, byPerson.Get("total"), `{"costMicros":30000000,"amount":30,"events":3}`)
	expectMember(t, byPerson, "currency", `"USD"`)
	rows := billingRows(t, byPerson)
	if len(rows) != 3 {
		t.Fatalf("rows: %s", core.MustStringify(rows))
	}
	expectMatch(t, rows[0], `{"key":`+core.MustStringify(s.alice.Get("id"))+`,"costMicros":22500000,"share":75,"label":"alice <alice@acme.test>"}`)
	expectMatch(t, rows[1], `{"key":"(unattributed)","costMicros":3750000}`)
	expectMatch(t, rows[2], `{"key":`+core.MustStringify(s.bob.Get("id"))+`,"costMicros":3750000,"quantities":{"api-calls":500}}`)
	byProject := s.object("billing/spend", s.owner, "tenantId", s.tenantID, "groupBy", "tenant")
	expectJSONOf(t, "by project", billingPluck(billingRows(t, byProject), "label", "amount"), `[["Acme",26.25],["Apollo",3.75]]`)
	// The project's own view covers only its subtree, priced within Acme's account.
	projectView := s.object("billing/spend", apollo.credential, "tenantId", apollo.id)
	projectRows := billingRows(t, projectView)
	if len(projectRows) != 1 {
		t.Fatalf("project rows: %s", core.MustStringify(projectRows))
	}
	expectMatch(t, projectRows[0], `{"key":"api-calls","label":"API calls","costMicros":3750000}`)
	// The platform sees every organization.
	platform := s.list("billing/accounts", s.root, "tenantId", s.rootID)
	if len(platform) != 1 {
		t.Fatalf("accounts: %s", core.MustStringify(platform))
	}
	expectMatch(t, platform[0], `{"accountId":"`+s.tenantID+`","name":"Acme","monthToDateMicros":30000000}`)
	// A negotiated price for Acme wins over the list price from this period on.
	s.object("billing/setPrice", s.root, "tenantId", s.rootID, "meter", "api-calls", "targetTenantId", s.tenantID,
		"price", core.NewObject("model", "per-unit", "unitAmount", 0.002), "note", "Enterprise agreement")
	negotiated := s.object("billing/spend", s.owner, "tenantId", s.tenantID)
	billingExpectNumber(t, "negotiated", member(negotiated.Get("total"), "costMicros"), 8_000_000)
	card := s.object("billing/listPrices", s.owner, "tenantId", s.tenantID, "meter", "api-calls")
	expectMatch(t, card.Get("effective"), `{"targetTenantId":"`+s.tenantID+`","note":"Enterprise agreement"}`)
	if entries, _ := card.Get("entries").([]any); len(entries) != 2 {
		t.Fatalf("entries: %s", core.MustStringify(card.Get("entries")))
	}
	expectMatch(t, s.object("billing/quote", s.owner, "tenantId", s.tenantID, "meter", "api-calls", "quantity", 1000),
		`{"amountMicros":2000000,"amount":2}`)
	// Organizations cannot price platform meters or define keys the platform owns.
	s.rejects("NOT_FOUND", "billing/setPrice", s.owner, "tenantId", s.tenantID, "meter", "api-calls",
		"price", core.NewObject("model", "per-unit", "unitAmount", 0))
	s.rejects("CONFLICT", "billing/createMeter", s.owner, "tenantId", s.tenantID, "key", "api-calls", "name", "Mine")
}

func TestBillingValidatesUsageStaysIdempotentAndRecordsThroughTheTrustedRuntime(t *testing.T) {
	s := newBillingSetup(t, nil)
	aliceID := s.alice.Get("id")
	first := s.recorded(aliceID, 10, "idempotencyKey", "request-1", "tags", core.NewObject("env", "prod"))
	again := s.recorded(aliceID, 10, "idempotencyKey", "request-1")
	expectMatch(t, again, `{"id":`+core.MustStringify(first.Get("id"))+`,"duplicate":true}`)
	_, err := s.record(aliceID, 1, "cost", 1)
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	s.rejects("NOT_FOUND", "billing/record", s.owner, "tenantId", s.tenantID, "meter", "nope")
	_, err = s.record(aliceID, -1)
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	_, err = s.record(aliceID, 1, "occurredAt", s.now()+3_600_000)
	expectCodeOrSkip(t, err, "INVALID_INPUT")
	// The server records without a credential (and without an audit event per call).
	s.ported(s.iam.Billing.Record(s.ctx, core.NewObject("tenantId", s.tenantID, "meter", "api-calls", "quantity", 5,
		"identityId", aliceID, "tags", core.NewObject("env", "staging"))))
	byEnv := s.ported(s.iam.Billing.Spend(s.ctx, core.NewObject("tenantId", s.tenantID, "groupBy", "tag:env")))
	envRows := billingRows(t, byEnv)
	got := make([]any, len(envRows))
	for index, row := range envRows {
		got[index] = []any{row.Get("key"), member(row.Get("quantities"), "api-calls")}
	}
	expectJSONOf(t, "by env", got, `[["prod",10],["staging",5]]`)
	events := s.object("billing/listUsage", s.owner, "tenantId", s.tenantID)
	listed := billingTestRecords(t, events.Get("events"))
	if len(listed) != 2 {
		t.Fatalf("events: %s", core.MustStringify(listed))
	}
	for _, event := range listed {
		if jsNumber(event.Get("quantity")) == 10 {
			expectMatch(t, event, `{"idempotencyKey":"request-1","recordedBy":"`+s.ownerID+`","tags":{"env":"prod"}}`)
		}
	}
	// Archived meters keep their history but refuse new usage.
	s.object("billing/updateMeter", s.root, "tenantId", s.rootID, "key", "api-calls", "archived", true)
	_, err = s.record(aliceID, 1)
	expectCodeOrSkip(t, err, "METER_ARCHIVED")
	s.rejects("RESOURCE_IN_USE", "billing/deleteMeter", s.root, "tenantId", s.rootID, "key", "api-calls")
	// Members without billing permissions can read only their own spend.
	bobSession := s.login("bob")
	s.rejects("ACCESS_DENIED", "billing/spend", bobSession, "tenantId", s.tenantID)
	aliceSession := s.login("alice")
	mine := s.object("billing/mySpend", aliceSession, "tenantId", s.tenantID)
	mineRows := billingRows(t, mine)
	if len(mineRows) != 1 {
		t.Fatalf("mine: %s", core.MustStringify(mineRows))
	}
	expectMatch(t, mineRows[0], `{"key":"api-calls","quantities":{"api-calls":15}}`)
	bobs := s.object("billing/mySpend", bobSession, "tenantId", s.tenantID)
	expectMember(t, bobs, "rows", `[]`)
	s.rejects("INVALID_INPUT", "billing/mySpend", bobSession, "tenantId", s.tenantID, "groupBy", 7)
	// The same routes answer over HTTP.
	overHTTP := billingPost(t, s.iam, aliceSession, "billing/mySpend", `{"tenantId":"`+s.tenantID+`"}`)
	expectJSONOf(t, "total over HTTP", overHTTP.Get("total"), core.MustStringify(mine.Get("total")))
	expectJSONOf(t, "check over HTTP", billingPost(t, s.iam, aliceSession, "billing/check", `{"tenantId":"`+s.tenantID+`"}`),
		`{"allowed":true,"budgets":[]}`)
}

// billingPost calls a route over HTTP with a bearer token and answers its data.
func billingPost(t *testing.T, iam *BetterIam, credential core.CredentialInput, path, body string) *core.Object {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "http://localhost:3000/api/iam/"+path, strings.NewReader(body))
	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-better-iam", "1")
	request.Header.Set("authorization", "Bearer "+credential.Token)
	response := iam.Handle(request)
	parsed, err := core.ParseJSON(response.Body)
	if err != nil {
		t.Fatalf("%s: %d %s", path, response.Status, response.Body)
	}
	if response.Status != 200 {
		if code := member(member(parsed, "error"), "code"); code == "NOT_IMPLEMENTED" {
			t.Skipf("blocked by another unit: %s", jsString(member(member(parsed, "error"), "message")))
		}
		t.Fatalf("%s: %d %s", path, response.Status, response.Body)
	}
	return parsed.(*core.Object).Get("data").(*core.Object)
}

func TestBillingAttributesSpendToTeamsAndDepartmentsReadableByMaintainersAndHeads(t *testing.T) {
	s := newBillingSetup(t, nil)
	alice, bob, carol := s.alice.Get("id"), s.bob.Get("id"), s.carol.Get("id")
	engineering := s.object("departments/create", s.owner, "tenantId", s.tenantID, "name", "Engineering", "code", "ENG",
		"headId", carol, "costCenter", "CC-100")
	s.object("departments/assign", s.owner, "tenantId", s.tenantID, "departmentId", engineering.Get("id"), "identityIds", []any{alice, bob})
	platform := s.object("teams/create", s.owner, "tenantId", s.tenantID, "name", "Platform", "departmentId", engineering.Get("id"),
		"maintainerIds", []any{alice})
	web := s.object("teams/create", s.owner, "tenantId", s.tenantID, "name", "Web", "parentId", platform.Get("id"))
	s.object("teams/addMember", s.owner, "tenantId", s.tenantID, "teamId", web.Get("id"), "identityId", bob)
	s.recorded(alice, 3000)
	s.recorded(bob, 1000)
	s.recorded(carol, 1000)
	// 5000 calls, 4000 billable at $0.01 = $40: alice 24, bob 8, carol 8.
	byTeam := s.object("billing/spend", s.owner, "tenantId", s.tenantID, "groupBy", "team")
	expectJSONOf(t, "by team", billingLabelOrKey(billingRows(t, byTeam)), `[["Platform",24],["(no team)",8],["Web",8]]`)
	// A team's spend includes the teams below it; its maintainers may read it.
	aliceSession := s.login("alice")
	teamView := s.object("billing/teamSpend", aliceSession, "tenantId", s.tenantID, "teamId", platform.Get("id"))
	billingExpectNumber(t, "team total", member(teamView.Get("total"), "amount"), 32)
	expectJSONOf(t, "team rows", billingPluckOne(billingRows(t, teamView), "key"), core.MustStringify([]any{alice, bob}))
	bobSession := s.login("bob")
	s.rejects("ACCESS_DENIED", "billing/teamSpend", bobSession, "tenantId", s.tenantID, "teamId", platform.Get("id"))
	// Maintaining a team reads it only in the team's own tenant (or below), not from the platform's.
	s.rejects("ACCESS_DENIED", "billing/teamSpend", aliceSession, "tenantId", s.rootID, "teamId", platform.Get("id"))
	// Department spend rolls up people in the department; the head reads it.
	carolSession := s.login("carol")
	department := s.object("billing/departmentSpend", carolSession, "tenantId", s.tenantID, "departmentId", engineering.Get("id"),
		"groupBy", "department")
	departmentRows := billingRows(t, department)
	if len(departmentRows) != 1 {
		t.Fatalf("department rows: %s", core.MustStringify(departmentRows))
	}
	expectMatch(t, departmentRows[0], `{"key":`+core.MustStringify(engineering.Get("id"))+`,"label":"Engineering (ENG)","amount":32}`)
	reads := s.list("audit/list", s.owner, "tenantId", s.tenantID, "action", "iam:billing:read")
	// Reads through a role are audited with it; bob's refused attempt is audited as a denial.
	vias := []string{}
	for _, event := range reads {
		if via := member(event.Get("metadata"), "via"); truthy(via) {
			vias = append(vias, jsString(via))
		}
	}
	sort.Strings(vias)
	expectList(t, "vias", vias, "department-head", "team-maintainer")
	// Alice's attempt against the platform tenant is recorded here too, in her own tenant, naming its target.
	var untargeted, targeted []*core.Object
	for _, event := range reads {
		if event.Get("outcome") != "deny" {
			continue
		}
		if truthy(member(event.Get("metadata"), "targetTenantId")) {
			targeted = append(targeted, event)
		} else {
			untargeted = append(untargeted, event)
		}
	}
	if len(untargeted) != 1 || len(targeted) != 1 {
		t.Fatalf("denials: %s", core.MustStringify(reads))
	}
	expectMatch(t, targeted[0], `{"metadata":{"targetTenantId":"`+s.rootID+`"}}`)
}

// pluckOne is `list.map((row) => row[key])`.
func billingPluckOne(list []*core.Object, key string) []any {
	out := make([]any, len(list))
	for index, row := range list {
		out[index] = row.Get(key)
	}
	return out
}

func TestBillingAlertsOnBudgetThresholdsOnceAndEnforcesSpentBudgets(t *testing.T) {
	s := newBillingSetup(t, nil)
	alice, bob, carol := s.alice.Get("id"), s.bob.Get("id"), s.carol.Get("id")
	platform := s.object("teams/create", s.owner, "tenantId", s.tenantID, "name", "Platform", "maintainerIds", []any{alice})
	s.object("teams/addMember", s.owner, "tenantId", s.tenantID, "teamId", platform.Get("id"), "identityId", bob)
	budget := s.object("billing/createBudget", s.owner, "tenantId", s.tenantID, "name", "Platform monthly", "subjectType", "team",
		"subjectId", platform.Get("id"), "amount", 20, "thresholds", []any{50, 100}, "forecastAlerts", false,
		"notify", core.NewObject("emails", []any{"finance@acme.test"}), "enforce", true)
	expectMatch(t, budget, `{"spentMicros":0,"percent":0,"exceeded":false,"subjectName":"Platform"}`)
	s.recorded(bob, 2500) // 1500 billable: $15 (75%).
	firstRun := s.ported(s.iam.Billing.CheckBudgets(s.ctx, core.NewObject()))
	alerts := billingTestRecords(t, firstRun.Get("alerts"))
	if len(alerts) != 1 {
		t.Fatalf("alerts: %s", core.MustStringify(alerts))
	}
	expectMatch(t, alerts[0], `{"budgetId":`+core.MustStringify(budget.Get("budgetId"))+`,"kind":"actual","threshold":50,"recipients":3}`)
	expectMember(t, s.ported(s.iam.Billing.CheckBudgets(s.ctx, core.NewObject())), "alerts", `[]`)
	s.recorded(bob, 1000) // $25 in total.
	secondRun := billingTestRecords(t, s.ported(s.iam.Billing.CheckBudgets(s.ctx, core.NewObject())).Get("alerts"))
	if len(secondRun) != 1 {
		t.Fatalf("second run: %s", core.MustStringify(secondRun))
	}
	expectMatch(t, secondRun[0], `{"threshold":100}`)
	messages := s.inboxOf("spend-alert")
	recipients := []string{}
	for _, message := range messages {
		recipients = append(recipients, message.To)
	}
	sort.Strings(recipients)
	want := []string{"alice@acme.test", "alice@acme.test", "finance@acme.test", "finance@acme.test", s.ownerEmail(), s.ownerEmail()}
	sort.Strings(want)
	expectList(t, "alert recipients", recipients, want...)
	var full *auth.DeliveryMessage
	for index := range messages {
		if messages[index].Payload["threshold"] == "100" {
			full = &messages[index]
		}
	}
	if full == nil {
		t.Fatal("no 100% alert")
	}
	for key, value := range map[string]string{"spent": "$25.00", "amount": "$20.00", "budgetName": "Platform monthly", "subjectName": "Platform"} {
		if full.Payload[key] != value {
			t.Fatalf("payload %s = %q, want %q", key, full.Payload[key], value)
		}
	}
	rendered := billingRender(t, *full, auth.TemplateOptions{Links: &auth.TemplateLinks{
		Billing: func(input auth.BillingLinkInput) string {
			return "https://console.test/cloud/" + input.TenantID + "/billing"
		},
	}})
	if rendered.Subject != "Platform monthly has reached 100% of its budget" ||
		!strings.Contains(rendered.Text, "Platform has spent $25.00 of the $20.00 budget") ||
		!strings.Contains(rendered.Text, "https://console.test/cloud/"+s.tenantID+"/billing") {
		t.Fatalf("rendered: %+v", rendered)
	}
	// The spent budget now refuses the team's usage when asked to enforce.
	bobSession := s.login("bob")
	verdict := s.object("billing/check", bobSession, "tenantId", s.tenantID)
	expectMatch(t, verdict, `{"allowed":false,"blockedBy":{"name":"Platform monthly"}}`)
	_, err := s.record(bob, 1, "enforceBudgets", true)
	expectCodeOrSkip(t, err, "SPEND_LIMIT_REACHED")
	if known := iamError(t, err); known.Status != 402 {
		t.Fatalf("status %d", known.Status)
	}
	// People outside the team are not covered by its budget.
	s.recorded(carol, 1, "enforceBudgets", true)
	listed := s.list("billing/listBudgets", s.owner, "tenantId", s.tenantID)
	expectMatch(t, listed[0], `{"reached":[50,100],"exceeded":true}`)
	s.rejects("CONFLICT", "billing/createBudget", s.owner, "tenantId", s.tenantID, "name", "platform MONTHLY", "amount", 1)
}

func TestBillingClosesAPeriodIntoStatementsWithCreditsAndRefusesLateUsageUntilVoided(t *testing.T) {
	s := newBillingSetup(t, nil)
	alice := s.alice.Get("id")
	lastMonth := s.shift(s.period(s.now()), -1)
	s.recorded(alice, 6000, "occurredAt", s.previousPeriodStart()+3_600_000)
	s.object("billing/setProfile", s.owner, "tenantId", s.tenantID, "companyName", "Acme Corporation",
		"billingEmails", []any{"ap@acme.test"}, "purchaseOrder", "PO-7", "paymentTermsDays", 15)
	credit := s.object("billing/grantCredit", s.root, "tenantId", s.tenantID, "amount", 20, "reason", "Launch promotion")
	// Only root administrators grant credit or close periods.
	s.rejects("ACCESS_DENIED", "billing/grantCredit", s.owner, "tenantId", s.tenantID, "amount", 5, "reason", "x")
	s.rejects("ACCESS_DENIED", "billing/closePeriod", s.owner, "tenantId", s.tenantID)
	draft := s.object("billing/previewStatement", s.owner, "tenantId", s.tenantID, "period", lastMonth)
	expectMatch(t, draft, `{"subtotalMicros":50000000,"creditsMicros":20000000,"totalMicros":30000000}`)

	closed := s.object("billing/closePeriod", s.root, "tenantId", s.rootID)
	expectMatch(t, closed, `{"period":"`+lastMonth+`","skipped":{"existing":0,"empty":0}}`)
	issued := billingTestRecords(t, closed.Get("issued"))
	if len(issued) != 1 {
		t.Fatalf("issued: %s", core.MustStringify(issued))
	}
	expectMatch(t, issued[0], `{"accountId":"`+s.tenantID+`","totalMicros":30000000,"recipients":1}`)
	number := "INV-" + strings.Replace(lastMonth, "-", "", 1) + "-0001"
	expectMember(t, issued[0], "number", `"`+number+`"`)
	// Idempotent: a second run skips the invoiced account.
	billingExpectNumber(t, "skipped", member(s.ported(s.iam.Billing.ClosePeriod(s.ctx, core.NewObject())).Get("skipped"), "existing"), 1)
	mailed := s.inboxOf("billing-statement")
	if len(mailed) == 0 || mailed[0].To != "ap@acme.test" || mailed[0].Payload["total"] != "$30.00" || mailed[0].Payload["period"] != lastMonth {
		t.Fatalf("mailed: %+v", mailed)
	}
	if subject := billingRender(t, mailed[0], auth.TemplateOptions{}).Subject; subject != "Your Better IAM statement "+number+" for "+lastMonth {
		t.Fatalf("subject %q", subject)
	}

	statements := s.list("billing/listStatements", s.owner, "tenantId", s.tenantID)
	if len(statements) != 1 {
		t.Fatalf("statements: %s", core.MustStringify(statements))
	}
	expectMatch(t, statements[0], `{"status":"finalized","total":30,"overdue":false,"tenantName":"Acme"}`)
	statement := s.object("billing/getStatement", s.owner, "tenantId", s.tenantID, "statementId", statements[0].Get("id"))
	expectMatch(t, statement, `{"verified":true,"lines":[{"meter":"api-calls","quantity":6000,"amountMicros":50000000}],`+
		`"billTo":{"companyName":"Acme Corporation","purchaseOrder":"PO-7","emails":["ap@acme.test"]},`+
		`"breakdown":{"identities":[{"id":`+core.MustStringify(alice)+`,"costMicros":50000000}]}}`)
	billingExpectNumber(t, "payment terms", jsNumber(statement.Get("dueAt"))-jsNumber(statement.Get("issuedAt")), 15*billingDay)
	sheet := s.object("billing/exportStatement", s.owner, "tenantId", s.tenantID, "statementId", statement.Get("id"))
	expectMember(t, sheet, "filename", `"`+jsString(statement.Get("number"))+`.csv"`)
	body := jsString(sheet.Get("body"))
	for _, line := range []string{"line,api-calls,API calls,6000,request,50.000000,\r\n", "credit,,,,,-20.000000,\r\n",
		"identity," + jsString(alice) + ",alice,,,50.000000,\r\n"} {
		if !strings.Contains(body, line) {
			t.Fatalf("CSV lacks %q: %s", line, body)
		}
	}
	credits := s.object("billing/listCredits", s.owner, "tenantId", s.tenantID)
	expectMatch(t, credits, `{"balanceMicros":0,"credits":[{"id":`+core.MustStringify(credit.Get("id"))+`,"remainingMicros":0}]}`)

	// The invoiced period is closed to late usage.
	_, err := s.record(alice, 1, "occurredAt", s.previousPeriodStart()+7_200_000)
	expectCodeOrSkip(t, err, "BILLING_PERIOD_CLOSED")
	// Voiding restores the credit and reopens the period; closing again issues a new number.
	s.object("billing/voidStatement", s.root, "tenantId", s.tenantID, "statementId", statement.Get("id"), "reason", "Usage correction")
	billingExpectNumber(t, "restored", s.object("billing/listCredits", s.owner, "tenantId", s.tenantID).Get("balanceMicros"), 20_000_000)
	s.recorded(alice, 1000, "occurredAt", s.previousPeriodStart()+7_200_000)
	reissued := billingTestRecords(t, s.ported(s.iam.Billing.ClosePeriod(s.ctx, core.NewObject("period", lastMonth))).Get("issued"))
	if len(reissued) != 1 {
		t.Fatalf("reissued: %s", core.MustStringify(reissued))
	}
	expectMatch(t, reissued[0], `{"number":"INV-`+strings.Replace(lastMonth, "-", "", 1)+`-0002","totalMicros":40000000}`)
	paid := s.object("billing/markPaid", s.root, "tenantId", s.tenantID, "statementId", reissued[0].Get("statementId"), "reference", "wire-2231")
	expectMatch(t, paid, `{"status":"paid"}`)
	s.rejects("INVALID_INPUT", "billing/closePeriod", s.root, "tenantId", s.rootID, "period", s.period(s.now()))
}

func TestBillingKeepsOrganizationChargebackMetersOffStatementsAndBillsProjectsWithTheirOwnProfile(t *testing.T) {
	s := newBillingSetup(t, nil)
	alice := s.alice.Get("id")
	apollo := s.project("Apollo")
	// An internal meter Acme defines for its own chargeback, with costs reported per event.
	s.object("billing/createMeter", s.owner, "tenantId", s.tenantID, "key", "cloud-compute", "name", "Cloud compute",
		"unit", "vCPU-hour", "pricing", "reported")
	lastMonth := s.shift(s.period(s.now()), -1)
	at := s.previousPeriodStart() + 3_600_000
	s.object("billing/record", s.owner, "tenantId", s.tenantID, "meter", "cloud-compute", "quantity", 12, "cost", 7.5,
		"identityId", alice, "occurredAt", at)
	s.rejects("INVALID_INPUT", "billing/record", s.owner, "tenantId", s.tenantID, "meter", "cloud-compute", "quantity", 1)
	s.recorded(alice, 2000, "occurredAt", at)
	// The project becomes its own billing account: its owner alone may not decide that, the organization does.
	s.rejects("ACCESS_DENIED", "billing/setProfile", apollo.credential, "tenantId", apollo.id, "companyName", "Apollo")
	expectMatch(t, s.object("billing/getProfile", apollo.credential, "tenantId", apollo.id),
		`{"account":{"id":"`+s.tenantID+`","inherited":true},"profile":null}`)
	s.object("billing/setProfile", s.owner, "tenantId", s.tenantID, "targetTenantId", apollo.id, "companyName", "Apollo Ltd")
	// From then on the project's own billing managers keep it up to date.
	updated := s.object("billing/setProfile", apollo.credential, "tenantId", apollo.id, "billingEmails", []any{"billing@apollo.test"})
	expectMatch(t, updated, `{"account":{"id":"`+apollo.id+`","inherited":false},"profile":{"companyName":"Apollo Ltd","billingEmails":["billing@apollo.test"]}}`)
	s.object("billing/record", apollo.credential, "tenantId", apollo.id, "meter", "api-calls", "quantity", 1500, "occurredAt", at)
	spend := s.object("billing/spend", s.owner, "tenantId", s.tenantID, "period", lastMonth, "groupBy", "meter")
	expectJSONOf(t, "by meter", billingPluck(billingRows(t, spend), "key", "amount"), `[["api-calls",15],["cloud-compute",7.5]]`)
	// The platform's view of what it bills leaves Acme's chargeback meter out.
	platform := s.object("billing/spend", s.root, "tenantId", s.rootID, "period", lastMonth, "billableOnly", true)
	expectJSONOf(t, "platform rows", billingPluckOne(billingRows(t, platform), "key"), `["api-calls"]`)
	closed := s.ported(s.iam.Billing.ClosePeriod(s.ctx, core.NewObject()))
	byAccount := core.NewObject()
	for _, entry := range billingTestRecords(t, closed.Get("issued")) {
		byAccount.Set(jsString(entry.Get("accountId")), entry.Get("totalMicros"))
	}
	// Each account gets its own 1000 free calls; the chargeback meter never reaches a statement.
	expectMatch(t, byAccount, `{"`+s.tenantID+`":10000000,"`+apollo.id+`":5000000}`)
	if byAccount.Len() != 2 {
		t.Fatalf("by account: %s", core.MustStringify(byAccount))
	}
	all := s.list("billing/listStatements", s.root, "tenantId", s.rootID)
	if len(all) != 2 {
		t.Fatalf("statements: %s", core.MustStringify(all))
	}
	var acmeID any
	for _, entry := range all {
		if entry.Get("tenantId") == s.tenantID {
			acmeID = entry.Get("id")
		}
	}
	acme := s.object("billing/getStatement", s.owner, "tenantId", s.tenantID, "statementId", acmeID)
	expectJSONOf(t, "acme lines", billingPluckOne(billingTestRecords(t, acme.Get("lines")), "meter"), `["api-calls"]`)
}

func TestBillingRecordsSeatsDailyForEveryActivePersonAndBillsActiveUsers(t *testing.T) {
	s := newBillingSetup(t, nil)
	s.object("billing/createMeter", s.root, "tenantId", s.rootID, "key", "seats", "name", "Active seats", "unit", "seat", "aggregation", "unique")
	s.object("billing/setPrice", s.root, "tenantId", s.rootID, "meter", "seats", "price", core.NewObject("model", "per-unit", "unitAmount", 12))
	first := s.ported(s.iam.Billing.RecordSeats(s.ctx, core.NewObject()))
	// The owner, alice, bob and carol.
	expectMatch(t, first, `{"meter":"seats","recorded":4,"duplicates":0}`)
	expectMatch(t, s.ported(s.iam.Billing.RecordSeats(s.ctx, core.NewObject())), `{"recorded":0,"duplicates":4}`)
	spend := s.ported(s.iam.Billing.Spend(s.ctx, core.NewObject("tenantId", s.tenantID, "groupBy", "meter")))
	rows := billingRows(t, spend)
	if len(rows) != 1 {
		t.Fatalf("rows: %s", core.MustStringify(rows))
	}
	expectMatch(t, rows[0], `{"key":"seats","costMicros":48000000}`)
	perPerson := s.ported(s.iam.Billing.Spend(s.ctx, core.NewObject("tenantId", s.tenantID, "groupBy", "identity")))
	for _, row := range billingRows(t, perPerson) {
		billingExpectNumber(t, "per person", row.Get("costMicros"), 12_000_000)
	}
}

func TestBillingFeedsMeteredInferenceCallsIntoTheLedgerAsTheInferenceMeter(t *testing.T) {
	// The inference module is its own unit: while constructing a server with it reaches a stub, skip.
	probe, err := New(&BetterIamOptions{
		Database: newStore(t), Secret: "billing-test-secret-with-at-least-32-characters", BaseURL: "http://localhost:3000",
		Inference: On[InferenceOptions](),
	})
	requirePorted(t, err)
	probe.Close()
	b := newBillingFixture(t, func(options *BetterIamOptions) { options.Inference = On[InferenceOptions]() })
	provider := b.object("inference/createProvider", b.owner, "tenantId", b.tenantID, "name", "Anthropic", "kind", "anthropic",
		"apiKey", "sk-ant-billing-test-key-0001")
	b.object("inference/createModel", b.owner, "tenantId", b.tenantID, "name", "haiku", "providerId", provider.Get("id"),
		"upstreamModel", "claude-haiku-4-5", "inputPricePerMTok", 1, "outputPricePerMTok", 5)
	outcome, err := b.iam.Inference.Authorize(b.ctx, b.owner, core.NewObject("model", "haiku"))
	requirePorted(t, err)
	if outcome.Has("denied") {
		t.Fatalf("denied: %s", core.MustStringify(outcome))
	}
	_, err = b.iam.Inference.Record(b.ctx, outcome, core.NewObject("model", "haiku", "inputTokens", 1000, "outputTokens", 200))
	requirePorted(t, err)
	spend := b.object("billing/spend", b.owner, "tenantId", b.tenantID, "groupBy", "tag:model")
	rows := billingRows(t, spend)
	if len(rows) != 1 {
		t.Fatalf("rows: %s", core.MustStringify(rows))
	}
	// 1000 × $1/M + 200 × $5/M = $0.002.
	expectMatch(t, rows[0], `{"key":"haiku","costMicros":2000,"quantities":{"inference":1200}}`)
	meters := b.list("billing/listMeters", b.owner, "tenantId", b.tenantID)
	if len(meters) != 1 {
		t.Fatalf("meters: %s", core.MustStringify(meters))
	}
	expectMatch(t, meters[0], `{"key":"inference","pricing":"reported","scope":"platform","inherited":true}`)
}

func TestBillingFindsSpendSpikesAlertsOnThemOnceAndExportsCSV(t *testing.T) {
	s := newBillingSetup(t, nil)
	alice, bob := s.alice.Get("id"), s.bob.Get("id")
	s.object("billing/createMeter", s.root, "tenantId", s.rootID, "key", "builds", "name", "CI builds", "unit", "build")
	s.object("billing/setPrice", s.root, "tenantId", s.rootID, "meter", "builds", "effectiveFrom", s.shift(s.period(s.now()), -1),
		"price", core.NewObject("model", "per-unit", "unitAmount", 1))
	today := s.now() - float64(int64(s.now())%int64(billingDay))
	noonDaysAgo := func(days float64) float64 { return today - days*billingDay + 43_200_000 }
	build := func(identityID any, quantity, daysAgo float64) {
		t.Helper()
		s.ported(s.iam.Billing.Record(s.ctx, core.NewObject("tenantId", s.tenantID, "meter", "builds", "quantity", quantity,
			"identityId", identityID, "occurredAt", noonDaysAgo(daysAgo))))
	}
	for daysAgo := 2.0; daysAgo <= 15; daysAgo++ {
		build(bob, 2, daysAgo)
		build(alice, 1, daysAgo)
	}
	build(bob, 40, 1)
	build(alice, 1, 1)
	found := billingTestRecords(t, s.object("billing/anomalies", s.owner, "tenantId", s.tenantID).Get("anomalies"))
	if len(found) != 2 {
		t.Fatalf("anomalies: %s", core.MustStringify(found))
	}
	expectMatch(t, found[0], `{"dimension":"meter","key":"builds","label":"CI builds","costMicros":41000000,"baselineMicros":3000000}`)
	expectMatch(t, found[1], `{"dimension":"identity","key":`+core.MustStringify(bob)+`,"label":"bob","costMicros":40000000,"baselineMicros":2000000,"factor":20}`)
	// A higher bar reports nothing.
	expectMember(t, s.object("billing/anomalies", s.owner, "tenantId", s.tenantID, "factor", 50), "anomalies", `[]`)
	s.rejects("INVALID_INPUT", "billing/anomalies", s.owner, "tenantId", s.tenantID, "factor", 1)

	// The daily job alerts once per spike.
	first := s.ported(s.iam.Billing.DetectAnomalies(s.ctx, core.NewObject()))
	expectJSONOf(t, "detected", billingPluck(billingTestRecords(t, first.Get("anomalies")), "dimension", "accountId"),
		`[["meter","`+s.tenantID+`"],["identity","`+s.tenantID+`"]]`)
	expectMember(t, s.ported(s.iam.Billing.DetectAnomalies(s.ctx, core.NewObject())), "anomalies", `[]`)
	mails := s.inboxOf("spend-anomaly")
	if len(mails) == 0 || mails[0].To != s.ownerEmail() || mails[0].Payload["count"] != "2" {
		t.Fatalf("mail: %+v", mails)
	}
	if text := billingRender(t, mails[0], auth.TemplateOptions{}).Text; !strings.Contains(text, "Person bob: $40.00 (usually $2.00 a day)") {
		t.Fatalf("text: %s", text)
	}
	if audited := s.list("audit/list", s.owner, "tenantId", s.tenantID, "action", "billing:anomaly"); len(audited) != 2 {
		t.Fatalf("audited: %d", len(audited))
	}

	// CSV of a spend report, guarded against spreadsheet formulas.
	s.object("identities/update", s.owner, "tenantId", s.tenantID, "identityId", alice, "name", `=HYPERLINK("x")`)
	// The TypeScript test runs on the wall clock, mid-month; the fixture's clock starts at 00:00 on the 1st, so the
	// builds above fall in the previous period: export that one.
	exported := s.object("billing/exportSpend", s.owner, "tenantId", s.tenantID, "groupBy", "identity",
		"period", s.period(noonDaysAgo(1)))
	expectMember(t, exported, "contentType", `"text/csv; charset=utf-8"`)
	filename := jsString(exported.Get("filename"))
	if !strings.HasPrefix(filename, "spend-") || !strings.HasSuffix(filename, "-identity.csv") {
		t.Fatalf("filename %s", filename)
	}
	lines := strings.Split(strings.TrimSpace(jsString(exported.Get("body"))), "\r\n")
	if lines[0] != "identity,label,amount_usd,share_percent,events,quantity_builds" {
		t.Fatalf("header %s", lines[0])
	}
	guarded := false
	for _, line := range lines {
		guarded = guarded || strings.Contains(line, `"'=HYPERLINK(""x"")`)
	}
	if !guarded || !strings.HasPrefix(lines[len(lines)-1], "total,,") {
		t.Fatalf("CSV: %v", lines)
	}
}

func TestBillingSpreadsUnattributedSpendOverTeamsWhenAsked(t *testing.T) {
	s := newBillingSetup(t, nil)
	alice, bob := s.alice.Get("id"), s.bob.Get("id")
	platform := s.object("teams/create", s.owner, "tenantId", s.tenantID, "name", "Platform", "maintainerIds", []any{alice})
	web := s.object("teams/create", s.owner, "tenantId", s.tenantID, "name", "Web")
	s.object("teams/addMember", s.owner, "tenantId", s.tenantID, "teamId", web.Get("id"), "identityId", bob)
	s.recorded(alice, 3000)
	s.recorded(bob, 1000)
	// Shared usage nobody on a team caused: 1000 calls.
	s.ported(s.iam.Billing.Record(s.ctx, core.NewObject("tenantId", s.tenantID, "meter", "api-calls", "quantity", 1000)))
	// 5000 calls, 4000 billable at $0.01 = $40: alice 24, bob 8, shared 8.
	plain := s.object("billing/spend", s.owner, "tenantId", s.tenantID, "groupBy", "team")
	expectJSONOf(t, "plain", billingLabelOrKey(billingRows(t, plain)), `[["Platform",24],["(no team)",8],["Web",8]]`)
	shared := s.object("billing/spend", s.owner, "tenantId", s.tenantID, "groupBy", "team", "shareUnattributed", true)
	billingExpectNumber(t, "shared", shared.Get("sharedMicros"), 8_000_000)
	expectJSONOf(t, "shared rows", billingPluck(billingRows(t, shared), "key", "amount", "sharedMicros"),
		core.MustStringify([]any{[]any{platform.Get("id"), 30, 6_000_000}, []any{web.Get("id"), 10, 2_000_000}}))
	sum := 0.0
	for _, row := range billingRows(t, shared) {
		sum += jsNumber(row.Get("costMicros"))
	}
	billingExpectNumber(t, "sum", sum, jsNumber(member(shared.Get("total"), "costMicros")))
}

func TestBillingLetsPoliciesRefuseActionsOnceAnEnforcedBudgetCoveringThePersonIsSpent(t *testing.T) {
	s := newBillingSetup(t, nil)
	bob, alice := s.bob.Get("id"), s.alice.Get("id")
	role := s.object("roles/create", s.owner, "tenantId", s.tenantID, "name", "Writers within budget", "document", obj(t, `{"version":1,"statements":[
		{"effect":"allow","actions":["documents:write"],"resources":["*"]},
		{"effect":"deny","actions":["documents:write"],"resources":["*"],"conditions":{"Bool":{"principal.spendExceeded":true}}}]}`))
	for _, person := range []any{bob, alice} {
		s.object("bindings/create", s.owner, "tenantId", s.tenantID, "roleId", role.Get("id"), "subjectType", "identity", "subjectId", person)
	}
	s.object("billing/createBudget", s.owner, "tenantId", s.tenantID, "name", "Bob monthly", "subjectType", "identity", "subjectId", bob,
		"amount", 5, "enforce", true)
	bobSession, aliceSession := s.login("bob"), s.login("alice")
	if !s.can(bobSession, "documents:write", "document", "plan") {
		t.Fatal("bob may write within budget")
	}
	// 1500 calls, 1000 free: $5 spent, the whole budget.
	s.recorded(bob, 1500)
	// Budget standings are cached for up to 30 seconds.
	s.advance(31_000)
	if s.can(bobSession, "documents:write", "document", "plan") {
		t.Fatal("bob's spent budget refuses the write")
	}
	if !s.can(aliceSession, "documents:write", "document", "plan") {
		t.Fatal("alice is not covered by bob's budget")
	}
	// Identity attributes can never supply the keys.
	_, err := New(&BetterIamOptions{
		Database: newStore(t), Secret: "billing-test-secret-with-at-least-32-characters", BaseURL: "http://localhost:3000",
		Permissions: &core.PermissionsConfig{Actions: []string{"documents:read"},
			IdentityAttributes: []core.NamedAttribute{{Name: "spendExceeded", Type: "boolean"}}},
	})
	expectCodeOrSkip(t, err, "INVALID_CONFIG")
}

func TestBillingAppliesADiscountAMinimumCommitmentCreditAndTaxToStatements(t *testing.T) {
	s := newBillingSetup(t, nil)
	alice := s.alice.Get("id")
	// 6000 calls, 1000 free: $50 of usage.
	s.recorded(alice, 6000, "occurredAt", s.previousPeriodStart()+3_600_000)
	s.rejects("ACCESS_DENIED", "billing/setTerms", s.owner, "tenantId", s.tenantID, "discountPercent", 90)
	terms := s.object("billing/setTerms", s.root, "tenantId", s.tenantID, "discountPercent", 10, "minimumCommitment", 100,
		"taxRatePercent", 20, "taxLabel", "VAT")
	expectMatch(t, terms, `{"discountPercent":10,"minimumCommitment":100,"taxLabel":"VAT"}`)
	expectMatch(t, s.object("billing/getTerms", s.owner, "tenantId", s.tenantID), `{"inherited":false,"taxRatePercent":20}`)
	s.object("billing/grantCredit", s.root, "tenantId", s.tenantID, "amount", 20, "reason", "Goodwill")
	// $50 − 10% = $45; the $100 commitment adds $55; $20 credit leaves $80; 20% VAT: $96.
	closed := s.object("billing/closePeriod", s.root, "tenantId", s.rootID)
	issued := billingTestRecords(t, closed.Get("issued"))
	if len(issued) != 1 {
		t.Fatalf("issued: %s", core.MustStringify(issued))
	}
	expectMatch(t, issued[0], `{"totalMicros":96000000}`)
	statement := s.object("billing/getStatement", s.owner, "tenantId", s.tenantID, "statementId", issued[0].Get("statementId"))
	expectMatch(t, statement, `{"verified":true,"subtotalMicros":50000000,"discount":{"percent":10,"amountMicros":5000000},`+
		`"commitment":{"minimumMicros":100000000,"trueUpMicros":55000000},"creditsMicros":20000000,`+
		`"tax":{"label":"VAT","ratePercent":20,"amountMicros":16000000},"totalMicros":96000000}`)
	sheet := jsString(s.object("billing/exportStatement", s.owner, "tenantId", s.tenantID, "statementId", statement.Get("id")).Get("body"))
	for _, line := range []string{"discount,,10%,,,-5.000000,", "commitment,,minimum commitment true-up,,,55.000000,", "tax,,VAT 20%,,,16.000000,"} {
		if !strings.Contains(sheet, line) {
			t.Fatalf("CSV lacks %q: %s", line, sheet)
		}
	}
	// Clearing terms returns to plain statements for later months.
	cleared := s.object("billing/setTerms", s.root, "tenantId", s.tenantID, "discountPercent", nil, "minimumCommitment", nil,
		"taxRatePercent", nil, "taxLabel", nil)
	if keys := strings.Join(cleared.Keys(), ","); keys != "accountId,inherited,setAt,setBy" {
		t.Fatalf("cleared: %s", core.MustStringify(cleared))
	}
	expectMatch(t, cleared, `{"accountId":"`+s.tenantID+`","inherited":false}`)
	s.rejects("INVALID_INPUT", "billing/setTerms", s.root, "tenantId", s.tenantID, "taxRatePercent", 120)
}

// ---------------------------------------------------------------------------------------------------------------
// tests/security-billing.test.ts

// newSecuritySetup is security-billing.test.ts setup(date): Acme on day `date` of next month with the platform
// `api-calls` meter at $1 a call from last month on.
func newSecuritySetup(t *testing.T, date float64) *billingFixture {
	t.Helper()
	b := newBillingFixture(t, nil)
	b.toNextMonth(date)
	b.apiCalls(b.root, "", core.NewObject("model", "per-unit", "unitAmount", 1))
	return b
}

// securityMember is a person `{name}@acme.test` with a password, created with the fresh owner session.
func (b *billingFixture) securityMember(name string) *core.Object {
	b.t.Helper()
	return b.object("identities/create", b.owner, "tenantId", b.tenantID, "email", name+"@acme.test", "name", name,
		"password", "a strong "+name+" password")
}

// statementOf is a statement as the platform sees it.
func (b *billingFixture) statementOf(statementID any) *core.Object {
	b.t.Helper()
	return b.object("billing/getStatement", b.root, "tenantId", b.rootID, "statementId", statementID)
}

// issuedFor is the closePeriod entry of an account.
func billingIssuedFor(t *testing.T, closed *core.Object, accountID string) *core.Object {
	t.Helper()
	for _, entry := range billingTestRecords(t, closed.Get("issued")) {
		if entry.Get("accountId") == accountID {
			return entry
		}
	}
	return nil
}

func TestBillingPricesUsageOutsideASubscriptionFromTheRateCardAndGrantsAPlanTrialOncePerAccount(t *testing.T) {
	b := newSecuritySetup(t, 20)
	b.object("billing/createPlan", b.root, "tenantId", b.rootID, "key", "team", "name", "Team", "selfServe", true, "trialDays", 14,
		"items", []any{
			core.NewObject("id", "platform", "kind", "fee", "name", "Platform fee", "amount", 99),
			core.NewObject("id", "calls", "kind", "usage", "name", "API calls", "meter", "api-calls",
				"price", core.NewObject("model", "per-unit", "unitAmount", 0.1)),
		})
	// 1000 calls on the 5th, before any subscription: the rate card prices them.
	b.object("billing/record", b.owner, "tenantId", b.tenantID, "meter", "api-calls", "quantity", 1000, "occurredAt", b.now()-15*billingDay)
	first := b.object("billing/subscribe", b.owner, "tenantId", b.tenantID, "plan", "team")
	expectMember(t, first.Get("subscription"), "status", `"trialing"`)
	if first.Has("invoice") {
		t.Fatalf("a trial invoices nothing: %s", core.MustStringify(first))
	}
	// 100 calls while subscribed: the plan prices them.
	b.object("billing/record", b.owner, "tenantId", b.tenantID, "meter", "api-calls", "quantity", 100)
	preview := b.object("billing/previewStatement", b.owner, "tenantId", b.tenantID)
	got := []any{}
	for _, line := range billingTestRecords(t, preview.Get("lines")) {
		if line.Get("meter") == "api-calls" {
			got = append(got, []any{line.Get("quantity"), line.Get("amountMicros"), coalesce(member(line.Get("price"), "source"), "rate-card")})
		}
	}
	expectJSONOf(t, "preview", got, `[[1000,1000000000,"rate-card"],[100,10000000,"plan"]]`)
	b.object("billing/cancelSubscription", b.owner, "tenantId", b.tenantID, "subscriptionId", member(first.Get("subscription"), "id"))

	b.toNextMonth(2)
	closed := b.ported(b.iam.Billing.ClosePeriod(b.ctx, core.NewObject()))
	issued := billingIssuedFor(t, closed, b.tenantID)
	billingExpectNumber(t, "total", b.statementOf(issued.Get("statementId")).Get("totalMicros"), 1_010_000_000)

	// Subscribing to the plan again starts without a trial: the first month is invoiced at once.
	b.advance(18 * billingDay)
	b.refresh()
	again := b.object("billing/subscribe", b.owner, "tenantId", b.tenantID, "plan", "team")
	expectMember(t, again.Get("subscription"), "status", `"active"`)
	if isUndefined(member(again.Get("subscription"), "trialEndsAt")) == false {
		t.Fatalf("no second trial: %s", core.MustStringify(again))
	}
	expectMatch(t, again.Get("invoice"), `{"billingReason":"subscription","status":"finalized"}`)
}

func TestBillingRecordsSeatsUnderKeysCallersCannotClaimAndOneTenantNeverStopsTheJob(t *testing.T) {
	b := newSecuritySetup(t, 10)
	b.object("billing/createMeter", b.root, "tenantId", b.rootID, "key", "seats", "name", "Seats", "unit", "seat-day")
	b.object("billing/setPrice", b.root, "tenantId", b.rootID, "meter", "seats", "price", core.NewObject("model", "per-unit", "unitAmount", 10))
	alice := b.securityMember("alice")
	zeta := b.object("tenants/create", b.root, "parentId", b.rootID, "name", "Zeta", "type", "organization", "ownerEmail", "owner@zeta.test",
		"activate", true, "ownerName", "Zed")
	zetaID := jsString(member(zeta.Get("tenant"), "id"))
	b.object("billing/createMeter", b.owner, "tenantId", b.tenantID, "key", "decoy", "name", "D")
	// The keys the job used to record under, claimed ahead: empty on the seats meter, and on another meter.
	today := billingDayOf(b.now())
	b.object("billing/record", b.owner, "tenantId", b.tenantID, "meter", "seats", "quantity", 0, "identityId", b.ownerID,
		"idempotencyKey", "seat:seats:"+b.ownerID+":"+today)
	b.object("billing/record", b.owner, "tenantId", b.tenantID, "meter", "decoy", "quantity", 0,
		"idempotencyKey", "seat:seats:"+jsString(alice.Get("id"))+":"+today)
	result := b.ported(b.iam.Billing.RecordSeats(b.ctx, core.NewObject()))
	expectMember(t, result, "failedTenants", `[]`)
	acme := b.ported(b.iam.Billing.Spend(b.ctx, core.NewObject("tenantId", b.tenantID, "groupBy", "meter")))
	seatsRow := func(report *core.Object) *core.Object {
		for _, row := range billingRows(t, report) {
			if row.Get("key") == "seats" {
				return row
			}
		}
		return nil
	}
	expectMatch(t, seatsRow(acme), `{"costMicros":20000000,"quantities":{"seats":2}}`)
	other := b.ported(b.iam.Billing.Spend(b.ctx, core.NewObject("tenantId", zetaID, "groupBy", "meter")))
	if jsNumber(member(other.Get("total"), "events")) <= 0 {
		t.Fatalf("zeta: %s", core.MustStringify(other))
	}
	// Still once a day.
	expectMatch(t, b.ported(b.iam.Billing.RecordSeats(b.ctx, core.NewObject())), `{"recorded":0}`)

	// A seat the job recorded under its old key (trusted server code only) still counts for that day.
	b.advance(billingDay)
	b.ported(b.iam.Billing.Record(b.ctx, core.NewObject("tenantId", b.tenantID, "meter", "seats", "quantity", 1, "identityId", b.ownerID,
		"idempotencyKey", "seat:seats:"+b.ownerID+":"+billingDayOf(b.now()))))
	b.ported(b.iam.Billing.RecordSeats(b.ctx, core.NewObject()))
	later := b.ported(b.iam.Billing.Spend(b.ctx, core.NewObject("tenantId", b.tenantID, "groupBy", "meter")))
	expectJSONOf(t, "later seats", seatsRow(later).Get("quantities"), `{"seats":4}`)
}

func TestBillingKeepsACarvedOutProjectUnderTheOrganizationsTaxAndDiscountAndBillsTheCommitmentAnyway(t *testing.T) {
	b := newSecuritySetup(t, 10)
	previous := b.shift(b.period(b.now()), -1)
	b.object("billing/setTerms", b.root, "tenantId", b.tenantID, "taxRatePercent", 20, "taxLabel", "VAT", "discountPercent", 10,
		"minimumCommitment", 1000)
	project := b.object("tenants/create", b.owner, "parentId", b.tenantID, "name", "Shadow", "type", "project", "ownerEmail", "shadow@acme.test")
	projectID := jsString(member(project.Get("tenant"), "id"))
	b.object("billing/setProfile", b.owner, "tenantId", b.tenantID, "targetTenantId", projectID, "companyName", "Acme")
	start, _ := b.bounds(previous)
	b.object("billing/recordMany", b.owner, "tenantId", b.tenantID, "events", []any{
		core.NewObject("tenantId", projectID, "meter", "api-calls", "quantity", 100, "occurredAt", start+2*billingDay),
	})
	closed := b.ported(b.iam.Billing.ClosePeriod(b.ctx, core.NewObject("period", previous)))
	// Acme has no usage of its own but owes its $1000 commitment, plus VAT.
	acme := billingIssuedFor(t, closed, b.tenantID)
	if acme == nil {
		t.Fatalf("no Acme statement: %s", core.MustStringify(closed))
	}
	expectMatch(t, b.statementOf(acme.Get("statementId")), `{"lines":[],"commitment":{"minimumMicros":1000000000,"trueUpMicros":1000000000},`+
		`"tax":{"ratePercent":20,"amountMicros":200000000},"totalMicros":1200000000}`)
	// The project pays Acme's contract rates: $100 − 10%, plus 20% VAT; the commitment is not billed twice.
	shadow := billingIssuedFor(t, closed, projectID)
	statement := b.statementOf(shadow.Get("statementId"))
	expectMatch(t, statement, `{"subtotalMicros":100000000,"discount":{"percent":10,"amountMicros":10000000},`+
		`"tax":{"label":"VAT","ratePercent":20,"amountMicros":18000000},"totalMicros":108000000}`)
	if statement.Has("commitment") {
		t.Fatalf("commitment billed twice: %s", core.MustStringify(statement))
	}
}

func TestBillingKeepsOrganizationsFromAttributingUsageToPlatformIdentitiesOrSpendingPlatformBudgets(t *testing.T) {
	b := newSecuritySetup(t, 10)
	roots := b.find("identities", core.NewObject("tenantId", b.rootID, "email", "root@example.test"))
	rootAdminID := jsString(roots[0].Get("id"))
	// Who set a platform price stays with the platform.
	card := b.object("billing/listPrices", b.owner, "tenantId", b.tenantID, "meter", "api-calls")
	if entries := billingTestRecords(t, card.Get("entries")); entries[0].Has("setBy") || member(card.Get("effective"), "setBy") != core.Undefined {
		t.Fatalf("card: %s", core.MustStringify(card))
	}
	rootCard := b.object("billing/listPrices", b.root, "tenantId", b.rootID, "meter", "api-calls")
	expectMember(t, billingTestRecords(t, rootCard.Get("entries"))[0], "setBy", `"`+rootAdminID+`"`)
	b.object("billing/setTerms", b.root, "tenantId", b.tenantID, "taxRatePercent", 5)
	if b.object("billing/getTerms", b.owner, "tenantId", b.tenantID).Has("setBy") {
		t.Fatal("terms name the root administrator")
	}

	// An enforced platform-wide budget, and an organization chargeback meter at a made-up price.
	b.object("billing/createBudget", b.root, "tenantId", b.rootID, "name", "Platform", "amount", 100, "enforce", true)
	b.object("billing/createMeter", b.owner, "tenantId", b.tenantID, "key", "decoy", "name", "D")
	b.object("billing/setPrice", b.owner, "tenantId", b.tenantID, "meter", "decoy", "price", core.NewObject("model", "per-unit", "unitAmount", 1_000_000))
	b.rejects("NOT_FOUND", "billing/record", b.owner, "tenantId", b.tenantID, "meter", "decoy", "quantity", 1, "identityId", rootAdminID)
	alice := b.securityMember("alice")
	receipt := b.object("billing/record", b.owner, "tenantId", b.tenantID, "meter", "decoy", "quantity", 1, "identityId", alice.Get("id"))
	expectMember(t, receipt, "identityId", core.MustStringify(alice.Get("id")))
	// Platform administrators still attribute to platform identities.
	byRoot := b.object("billing/record", b.root, "tenantId", b.tenantID, "meter", "api-calls", "quantity", 1, "identityId", rootAdminID)
	expectMember(t, byRoot, "identityId", `"`+rootAdminID+`"`)

	// Acme's chargeback spends Acme's own budget, never the platform's.
	b.object("billing/createBudget", b.owner, "tenantId", b.tenantID, "name", "Acme", "amount", 100, "enforce", true)
	b.advance(31_000) // past the budget status cache
	verdict := b.ported(b.iam.Billing.Check(b.ctx, core.NewObject("tenantId", b.tenantID)))
	expectMatch(t, verdict, `{"allowed":false,"blockedBy":{"name":"Acme"}}`)
	for _, budget := range billingTestRecords(t, verdict.Get("budgets")) {
		if budget.Get("name") == "Platform" {
			expectMatch(t, budget, `{"exceeded":false,"spentMicros":1000000}`)
		}
	}
	expectMember(t, b.ported(b.iam.Billing.Check(b.ctx, core.NewObject("tenantId", b.rootID))), "allowed", `true`)
}

func TestBillingReservesBuiltInMeterKeysForThePlatform(t *testing.T) {
	b := newSecuritySetup(t, 10)
	b.rejects("CONFLICT", "billing/createMeter", b.owner, "tenantId", b.tenantID, "key", "inference", "name", "Mine", "pricing", "reported")
}

func TestBillingLetsTeamMaintainersReadTeamSpendOnlyFromTheirOwnSignInSession(t *testing.T) {
	b := newSecuritySetup(t, 10)
	alice := b.securityMember("alice")
	team := b.object("teams/create", b.owner, "tenantId", b.tenantID, "name", "Platform", "maintainerIds", []any{alice.Get("id")})
	b.object("billing/record", b.owner, "tenantId", b.tenantID, "meter", "api-calls", "quantity", 10, "identityId", alice.Get("id"))
	aliceSession := b.login("alice")
	own := b.object("billing/teamSpend", aliceSession, "tenantId", b.tenantID, "teamId", team.Get("id"))
	billingExpectNumber(t, "own", member(own.Get("total"), "costMicros"), 10_000_000)
	// A session token derived from her session is not her acting in her own right.
	minter := b.object("roles/create", b.owner, "tenantId", b.tenantID, "name", "Token minter", "permissions", []any{"iam:session-tokens:create"})
	b.object("bindings/create", b.owner, "tenantId", b.tenantID, "roleId", minter.Get("id"), "subjectType", "identity", "subjectId", alice.Get("id"))
	derived := b.object("sts/getSessionToken", aliceSession)
	b.rejects("ACCESS_DENIED", "billing/teamSpend", core.CredentialInput{Token: jsString(derived.Get("token"))}, "tenantId", b.tenantID, "teamId", team.Get("id"))
}

func TestBillingKeepsPaymentTermsBeyondTheDefaultForRootAdministrators(t *testing.T) {
	b := newSecuritySetup(t, 10)
	b.rejects("ACCESS_DENIED", "billing/setProfile", b.owner, "tenantId", b.tenantID, "paymentTermsDays", 365)
	shorter := b.object("billing/setProfile", b.owner, "tenantId", b.tenantID, "paymentTermsDays", 15)
	expectMember(t, shorter.Get("profile"), "paymentTermsDays", `15`)
	b.object("billing/setProfile", b.root, "tenantId", b.tenantID, "paymentTermsDays", 60)
	// Saving the profile again keeps what the platform granted; asking for more is refused.
	resaved := b.object("billing/setProfile", b.owner, "tenantId", b.tenantID, "companyName", "Acme Corporation", "paymentTermsDays", 60)
	expectMember(t, resaved.Get("profile"), "paymentTermsDays", `60`)
	b.rejects("ACCESS_DENIED", "billing/setProfile", b.owner, "tenantId", b.tenantID, "paymentTermsDays", 90)
}

func TestBillingNeutralizesFormulasInCSVExportsButKeepsPlainNegativeNumbers(t *testing.T) {
	b := newSecuritySetup(t, 10)
	b.object("billing/createInvoiceItem", b.root, "tenantId", b.tenantID, "description", "-1+cmd|' /C calc'!A0", "amount", 5)
	b.object("billing/createInvoiceItem", b.root, "tenantId", b.tenantID, "description", "Service credit", "amount", -2)
	closed := b.ported(b.iam.Billing.ClosePeriod(b.ctx, core.NewObject()))
	issued := billingTestRecords(t, closed.Get("issued"))
	sheet := jsString(b.object("billing/exportStatement", b.owner, "tenantId", b.tenantID, "statementId", issued[0].Get("statementId")).Get("body"))
	if !strings.Contains(sheet, ",'-1+cmd|' /C calc'!A0,") || strings.Contains(sheet, ",-1+cmd") || !strings.Contains(sheet, ",-2.000000,") {
		t.Fatalf("CSV: %s", sheet)
	}
}

func TestBillingRefusesToVoidAnInvoiceWhoseCreditBalanceALaterInvoiceUsedUntilThatOneIsVoided(t *testing.T) {
	b := newSecuritySetup(t, 10)
	// Last month: $20 of charges and a $100 credit item: $80 of account credit carried forward.
	b.object("billing/createInvoiceItem", b.root, "tenantId", b.tenantID, "description", "Setup", "amount", 20)
	b.object("billing/createInvoiceItem", b.root, "tenantId", b.tenantID, "description", "Migration credit", "amount", -100)
	first := billingTestRecords(t, b.ported(b.iam.Billing.ClosePeriod(b.ctx, core.NewObject())).Get("issued"))[0]
	expectMatch(t, b.statementOf(first.Get("statementId")).Get("carryForward"), `{"amountMicros":80000000}`)
	// This month's $50 of usage is paid from that credit.
	b.object("billing/record", b.owner, "tenantId", b.tenantID, "meter", "api-calls", "quantity", 50)
	b.toNextMonth(2)
	second := billingTestRecords(t, b.ported(b.iam.Billing.ClosePeriod(b.ctx, core.NewObject())).Get("issued"))[0]
	expectMatch(t, b.statementOf(second.Get("statementId")), `{"creditsMicros":50000000,"totalMicros":0}`)
	b.rejects("INVALID_TRANSITION", "billing/voidStatement", b.root, "tenantId", b.tenantID, "statementId", first.Get("statementId"), "reason", "Re-rate")
	// Voided in order, the credit is whole again before the credit items go back up for the next invoice.
	b.object("billing/voidStatement", b.root, "tenantId", b.tenantID, "statementId", second.Get("statementId"), "reason", "Re-rate")
	b.object("billing/voidStatement", b.root, "tenantId", b.tenantID, "statementId", first.Get("statementId"), "reason", "Re-rate")
	billingExpectNumber(t, "balance", b.object("billing/listCredits", b.owner, "tenantId", b.tenantID).Get("balanceMicros"), 0)
	amounts := []float64{}
	for _, item := range b.list("billing/listInvoiceItems", b.owner, "tenantId", b.tenantID, "status", "pending") {
		amounts = append(amounts, jsNumber(item.Get("amount")))
	}
	sort.Float64s(amounts)
	expectJSONOf(t, "pending", amounts, `[-100,20]`)
}

// ---------------------------------------------------------------------------------------------------------------
// tests/billing-invoicing.test.ts

// invoicingSetup is billing-invoicing.test.ts setup(): Acme on the 10th of a month with the graduated platform
// `api-calls` meter and alice.
type invoicingSetup struct {
	*billingFixture
	alice *core.Object
}

func newInvoicingSetup(t *testing.T, billing func(options *BillingOptions)) *invoicingSetup {
	t.Helper()
	address, taxID := "1 Main Street\nLondon", "GB123456789"
	b := newBillingFixture(t, func(options *BetterIamOptions) {
		options.Billing = &BillingOptions{Issuer: &InvoiceIssuer{Name: "Better Cloud Ltd", Address: &address, TaxID: &taxID}}
		if billing != nil {
			billing(options.Billing)
		}
	})
	b.toNextMonth(10)
	b.apiCalls(b.root, "request", graduatedCalls())
	alice := b.object("identities/create", b.owner, "tenantId", b.tenantID, "email", "alice@acme.test", "name", "alice")
	return &invoicingSetup{billingFixture: b, alice: alice}
}

func (s *invoicingSetup) record(quantity float64, extra ...any) (any, error) {
	s.t.Helper()
	return s.call("billing/record", s.owner, append([]any{"tenantId", s.tenantID, "meter", "api-calls", "quantity", quantity, "identityId", s.alice.Get("id")}, extra...)...)
}

func (s *invoicingSetup) recorded(quantity float64, extra ...any) {
	s.t.Helper()
	_, err := s.record(quantity, extra...)
	requirePorted(s.t, err)
}

func TestBillingBillsFeesSeatsAndPlanPricesProratesSeatChangesAndBillsTheNextMonthInAdvance(t *testing.T) {
	s := newInvoicingSetup(t, nil)
	month := s.period(s.now())
	started := s.now()
	compact := strings.Replace(month, "-", "", 1)
	team := s.object("billing/createPlan", s.root, "tenantId", s.rootID, "key", "team", "name", "Team", "selfServe", true, "items", []any{
		core.NewObject("id", "platform", "kind", "fee", "name", "Platform fee", "amount", 100),
		core.NewObject("id", "seats", "kind", "seat", "name", "Seats", "unitAmount", 10, "includedSeats", 2),
		core.NewObject("id", "calls", "kind", "usage", "name", "API calls", "meter", "api-calls", "price", core.NewObject("model", "per-unit", "unitAmount", 0.002)),
	})
	expectMatch(t, team, `{"key":"team","subscribers":0,"items":[{"id":"platform","kind":"fee","amount":100,"billing":"advance"},`+
		`{"id":"seats","kind":"seat","unitAmount":10,"includedSeats":2,"billing":"advance"},`+
		`{"id":"calls","kind":"usage","meter":"api-calls","price":{"unitAmount":0.002}}]}`)
	s.object("billing/createPlan", s.root, "tenantId", s.rootID, "key", "enterprise", "name", "Enterprise", "items", []any{
		core.NewObject("id", "platform", "kind", "fee", "amount", 1000),
	})
	// Only root administrators define plans; organizations read the catalog.
	s.rejects("ACCESS_DENIED", "billing/createPlan", s.owner, "tenantId", s.tenantID, "key", "mine", "name", "Mine",
		"items", []any{core.NewObject("id", "fee", "kind", "fee", "amount", 1)})
	s.rejects("INVALID_INPUT", "billing/createPlan", s.root, "tenantId", s.rootID, "key", "bad", "name", "Bad",
		"items", []any{core.NewObject("id", "fee", "kind", "rebate", "amount", 1)})
	catalog := s.list("billing/listPlans", s.owner, "tenantId", s.tenantID)
	expectJSONOf(t, "catalog", billingPluckOne(catalog, "key"), `["enterprise","team"]`)
	for _, plan := range catalog {
		if plan.Has("subscribers") {
			t.Fatalf("subscriber counts are the platform's: %s", core.MustStringify(plan))
		}
	}

	// Account billing managers subscribe to self-serve plans only, and never set trials.
	s.rejects("ACCESS_DENIED", "billing/subscribe", s.owner, "tenantId", s.tenantID, "plan", "enterprise")
	s.rejects("ACCESS_DENIED", "billing/subscribe", s.owner, "tenantId", s.tenantID, "plan", "team", "trialDays", 90)
	subscribed := s.object("billing/subscribe", s.owner, "tenantId", s.tenantID, "plan", "team", "seats", 5)
	// The first invoice bills the rest of this month in advance: the fee and 3 chargeable seats.
	firstShare := s.rest(started, month)
	firstSeats := billingMathRound(3*firstShare*10_000) / 10_000
	firstTotal := billingCents(billingCents(100_000_000*firstShare) + billingCents(10_000_000*firstSeats))
	expectMatch(t, subscribed.Get("subscription"), `{"status":"active","planKey":"team","seats":5,"billedAdvance":["`+month+`"]}`)
	expectMatch(t, subscribed.Get("invoice"), `{"billingReason":"subscription","status":"finalized","number":"INV-`+compact+`-0001",`+
		`"totalMicros":`+core.NumberString(firstTotal)+`,"amountDueMicros":`+core.NumberString(firstTotal)+`}`)
	first := s.object("billing/getStatement", s.owner, "tenantId", s.tenantID, "statementId", member(subscribed.Get("invoice"), "id"))
	expectMember(t, first, "verified", `true`)
	lines := billingTestRecords(t, first.Get("lines"))
	if len(lines) != 2 {
		t.Fatalf("lines: %s", core.MustStringify(lines))
	}
	expectMatch(t, lines[0], `{"kind":"fee","name":"Platform fee","quantity":1,"unitAmountMicros":100000000,"proration":`+core.NumberString(firstShare)+
		`,"servicePeriod":`+core.MustStringify(s.boundsObject(month))+`,"planItemId":"platform"}`)
	expectMatch(t, lines[1], `{"kind":"seat","unit":"seat-month","quantity":`+core.NumberString(firstSeats)+`}`)
	s.rejects("CONFLICT", "billing/subscribe", s.owner, "tenantId", s.tenantID, "plan", "team")
	subscriptionID := member(subscribed.Get("subscription"), "id")

	// Two more seats on the 15th: the rest of the month is charged on the next invoice.
	s.advance(5 * billingDay)
	grownAt := s.now()
	grown := s.object("billing/updateSubscription", s.owner, "tenantId", s.tenantID, "subscriptionId", subscriptionID, "seats", 7)
	prorationMicros := billingCents(2 * 10_000_000 * s.rest(grownAt, month))
	expectMember(t, grown.Get("subscription"), "seats", `7`)
	grownItems := billingTestRecords(t, grown.Get("invoiceItems"))
	if len(grownItems) != 1 {
		t.Fatalf("items: %s", core.MustStringify(grownItems))
	}
	expectMatch(t, grownItems[0], `{"source":"proration","status":"pending","period":"`+month+`","amountMicros":`+core.NumberString(prorationMicros)+`}`)

	// The plan prices API calls for subscribers: no free calls, $0.002 each.
	s.recorded(1000)
	preview := s.object("billing/previewStatement", s.owner, "tenantId", s.tenantID)
	expectMatch(t, billingTestRecords(t, preview.Get("lines"))[0], `{"meter":"api-calls","amountMicros":2000000,"unitAmountMicros":2000,"price":{"model":"per-unit","source":"plan"}}`)

	// Cancelling at the end of the month can be undone until then; only root administrators cancel at once.
	_, end := s.bounds(month)
	canceling := s.object("billing/cancelSubscription", s.owner, "tenantId", s.tenantID, "subscriptionId", subscriptionID)
	expectMatch(t, canceling.Get("subscription"), `{"status":"active","cancelAtPeriodEnd":true,"endsAt":`+core.NumberString(end)+`}`)
	s.rejects("ACCESS_DENIED", "billing/cancelSubscription", s.owner, "tenantId", s.tenantID, "subscriptionId", subscriptionID, "atPeriodEnd", false)
	resumed := s.object("billing/resumeSubscription", s.owner, "tenantId", s.tenantID, "subscriptionId", subscriptionID)
	expectMember(t, resumed, "cancelAtPeriodEnd", `false`)
	if resumed.Has("endsAt") {
		t.Fatalf("resumed: %s", core.MustStringify(resumed))
	}

	// Closing the month: usage at the plan price, the next month's fee and 5 chargeable seats, and the proration.
	s.toNextMonth(2)
	following := s.period(s.now())
	closed := s.ported(s.iam.Billing.ClosePeriod(s.ctx, core.NewObject()))
	monthlyTotal := billingCents(2_000_000 + 100_000_000 + 50_000_000 + prorationMicros)
	issued := billingTestRecords(t, closed.Get("issued"))
	if len(issued) != 1 {
		t.Fatalf("issued: %s", core.MustStringify(issued))
	}
	expectMatch(t, issued[0], `{"accountId":"`+s.tenantID+`","number":"INV-`+compact+`-0002","totalMicros":`+core.NumberString(monthlyTotal)+`}`)
	monthly := s.object("billing/getStatement", s.owner, "tenantId", s.tenantID, "statementId", issued[0].Get("statementId"))
	monthlyLines := billingTestRecords(t, monthly.Get("lines"))
	kinds := make([]any, len(monthlyLines))
	for index, line := range monthlyLines {
		kinds[index] = []any{coalesce(line.Get("kind"), "usage"), line.Get("amountMicros")}
	}
	expectJSONOf(t, "monthly lines", kinds, `[["usage",2000000],["fee",100000000],["seat",50000000],["item",`+core.NumberString(prorationMicros)+`]]`)
	expectJSONOf(t, "service period", monthlyLines[1].Get("servicePeriod"), core.MustStringify(s.boundsObject(following)))
	subscriptions := s.list("billing/listSubscriptions", s.owner, "tenantId", s.tenantID)
	expectJSONOf(t, "billed advance", subscriptions[0].Get("billedAdvance"), `["`+month+`","`+following+`"]`)
	invoiced := s.list("billing/listInvoiceItems", s.owner, "tenantId", s.tenantID, "status", "invoiced")
	if len(invoiced) != 1 {
		t.Fatalf("invoiced: %s", core.MustStringify(invoiced))
	}
	expectMatch(t, invoiced[0], `{"statementId":`+core.MustStringify(monthly.Get("id"))+`}`)

	// Cancelling now credits what is left of the month already paid for.
	canceledAt := s.now()
	ended := s.object("billing/cancelSubscription", s.root, "tenantId", s.tenantID, "subscriptionId", subscriptionID, "atPeriodEnd", false)
	left := s.rest(canceledAt, following)
	expectMember(t, ended.Get("subscription"), "status", `"ended"`)
	expectJSONOf(t, "credits", billingPluckOne(billingTestRecords(t, ended.Get("invoiceItems")), "amountMicros"),
		core.MustStringify([]any{billingCents(-100_000_000 * left), billingCents(-5 * 10_000_000 * left)}))
	if listed := s.list("billing/listSubscriptions", s.owner, "tenantId", s.tenantID); len(listed) != 0 {
		t.Fatalf("subscriptions: %s", core.MustStringify(listed))
	}
	for _, plan := range s.list("billing/listPlans", s.root, "tenantId", s.rootID) {
		if plan.Get("key") == "team" {
			expectMember(t, plan, "subscribers", `0`)
		}
	}
}

func TestBillingStartsTrialsFreeOfChargeKeepsThemAcrossPlanChangesAndBillsTheRestOfTheMonthAfter(t *testing.T) {
	s := newInvoicingSetup(t, nil)
	month := s.period(s.now())
	started := s.now()
	for _, plan := range []struct {
		key       string
		amount    float64
		trialDays float64
	}{{"starter", 20, 14}, {"growth", 50, 0}} {
		members := []any{"tenantId", s.rootID, "key", plan.key, "name", plan.key, "selfServe", true}
		if plan.trialDays > 0 {
			members = append(members, "trialDays", plan.trialDays)
		}
		members = append(members, "items", []any{core.NewObject("id", "fee", "kind", "fee", "name", plan.key+" fee", "amount", plan.amount)})
		s.object("billing/createPlan", s.root, members...)
	}
	trial := s.object("billing/subscribe", s.owner, "tenantId", s.tenantID, "plan", "starter")
	trialEnd := started + 14*billingDay
	expectMatch(t, trial.Get("subscription"), `{"status":"trialing","trialEndsAt":`+core.NumberString(trialEnd)+`}`)
	if trial.Has("invoice") {
		t.Fatalf("a trial invoices nothing: %s", core.MustStringify(trial))
	}

	moved := s.object("billing/changePlan", s.owner, "tenantId", s.tenantID, "subscriptionId", member(trial.Get("subscription"), "id"), "plan", "growth")
	afterTrial := s.rest(trialEnd, month)
	expectMatch(t, moved.Get("subscription"), `{"planKey":"growth","status":"trialing","trialEndsAt":`+core.NumberString(trialEnd)+`,"billedAdvance":["`+month+`"]}`)
	items := billingTestRecords(t, moved.Get("invoiceItems"))
	if len(items) != 1 {
		t.Fatalf("items: %s", core.MustStringify(items))
	}
	expectMatch(t, items[0], `{"source":"proration","amountMicros":`+core.NumberString(billingCents(50_000_000*afterTrial))+`}`)
	all := s.list("billing/listSubscriptions", s.owner, "tenantId", s.tenantID, "includeEnded", true)
	pairs := []string{}
	for _, subscription := range all {
		pairs = append(pairs, jsString(subscription.Get("planKey"))+":"+jsString(subscription.Get("status")))
	}
	sort.Strings(pairs)
	expectList(t, "subscriptions", pairs, "growth:trialing", "starter:ended")

	// An account with no usage is still invoiced for its subscription.
	s.toNextMonth(2)
	closed := billingTestRecords(t, s.ported(s.iam.Billing.ClosePeriod(s.ctx, core.NewObject())).Get("issued"))
	if len(closed) != 1 {
		t.Fatalf("issued: %s", core.MustStringify(closed))
	}
	expectMatch(t, closed[0], `{"accountId":"`+s.tenantID+`","totalMicros":`+core.NumberString(billingCents(billingCents(50_000_000*afterTrial)+50_000_000))+`}`)
}

func TestBillingDraftsInvoicesWithItemsFinalizesThemAndTakesPaymentsAndCreditNotes(t *testing.T) {
	s := newInvoicingSetup(t, func(options *BillingOptions) { off := false; options.AutoFinalize = &off })
	lastMonth := s.shift(s.period(s.now()), -1)
	lastMonthStart, _ := s.bounds(lastMonth)
	compact := strings.Replace(lastMonth, "-", "", 1)
	// 6000 calls last month: 1000 free, then $0.01 each: $50.
	s.recorded(6000, "occurredAt", lastMonthStart+3_600_000)
	s.object("billing/createInvoiceItem", s.root, "tenantId", s.tenantID, "description", "Onboarding workshop", "amount", 200)
	s.object("billing/createInvoiceItem", s.root, "tenantId", s.tenantID, "description", "Service credit", "amount", -30)
	s.rejects("ACCESS_DENIED", "billing/createInvoiceItem", s.owner, "tenantId", s.tenantID, "description", "Free money", "amount", -1000)
	pending := []float64{}
	for _, item := range s.list("billing/listInvoiceItems", s.owner, "tenantId", s.tenantID, "status", "pending") {
		pending = append(pending, jsNumber(item.Get("amount")))
	}
	sort.Float64s(pending)
	expectJSONOf(t, "pending", pending, `[-30,200]`)

	// With autoFinalize off, closing keeps a draft.
	drafted := s.object("billing/closePeriod", s.root, "tenantId", s.rootID)
	expectMatch(t, drafted, `{"period":"`+lastMonth+`","issued":[],"drafted":[{"accountId":"`+s.tenantID+`","totalMicros":220000000}]}`)
	draftID := member(billingTestRecords(t, drafted.Get("drafted"))[0], "statementId")
	draft := s.object("billing/getStatement", s.owner, "tenantId", s.tenantID, "statementId", draftID)
	expectMatch(t, draft, `{"status":"draft","number":"","hash":"","subtotalMicros":220000000}`)
	expectMatch(t, billingTestRecords(t, draft.Get("lines"))[0], `{"meter":"api-calls","quantity":6000,"includedQuantity":1000,`+
		`"tiers":[{"from":1,"to":10000,"quantity":5000,"unitAmountMicros":10000,"amountMicros":50000000}]}`)
	// A draft keeps its month open to late usage and new items; finalizing recomputes it.
	s.recorded(1000, "occurredAt", lastMonthStart+7_200_000)
	s.object("billing/createInvoiceItem", s.root, "tenantId", s.tenantID, "description", "Extra support", "amount", 25, "quantity", 2)
	finalized := s.object("billing/finalizeInvoice", s.root, "tenantId", s.tenantID, "statementId", draftID)
	number := "INV-" + compact + "-0001"
	// $60 of usage + $200 − $30 + 2 × $25.
	expectMatch(t, finalized, `{"status":"finalized","number":"`+number+`","totalMicros":280000000,"amountDueMicros":280000000}`)
	s.rejects("INVALID_TRANSITION", "billing/finalizeInvoice", s.root, "tenantId", s.tenantID, "statementId", draftID)
	if left := s.list("billing/listInvoiceItems", s.owner, "tenantId", s.tenantID, "status", "pending"); len(left) != 0 {
		t.Fatalf("pending: %s", core.MustStringify(left))
	}
	_, err := s.record(1, "occurredAt", lastMonthStart+7_200_000)
	expectCodeOrSkip(t, err, "BILLING_PERIOD_CLOSED")

	// A partial payment, then a credit note against the amount still due.
	partial := s.object("billing/recordPayment", s.root, "tenantId", s.tenantID, "statementId", draftID, "amount", 100,
		"method", "bank_transfer", "reference", "wire-1")
	expectMatch(t, partial.Get("statement"), `{"status":"finalized","amountPaidMicros":100000000,"amountDueMicros":180000000}`)
	s.rejects("INVALID_TRANSITION", "billing/voidStatement", s.root, "tenantId", s.tenantID, "statementId", draftID, "reason", "x")
	shortened := s.object("billing/createCreditNote", s.root, "tenantId", s.tenantID, "statementId", draftID, "amount", 50,
		"reason", "order_change", "memo", "Workshop shortened")
	expectMatch(t, shortened.Get("creditNote"), `{"number":"`+number+`-CN-01","applied":{"dueMicros":50000000,"creditMicros":0,"refundMicros":0}}`)
	expectMember(t, shortened.Get("statement"), "amountDueMicros", `130000000`)

	// A payment processor settles the rest with $10 too much, which becomes credit; redelivery is ignored.
	settled := s.ported(s.iam.Billing.RecordPayment(s.ctx, core.NewObject("number", number, "amount", 140, "method", "card", "idempotencyKey", "pi_123")))
	expectMatch(t, settled, `{"duplicate":false,"statement":{"status":"paid"},"payment":{"overpaymentMicros":10000000,"reference":"pi_123"}}`)
	expectMember(t, s.ported(s.iam.Billing.RecordPayment(s.ctx, core.NewObject("number", number, "amount", 140, "idempotencyKey", "pi_123"))), "duplicate", `true`)

	// Credit notes on a paid invoice become credit, or a refund made elsewhere.
	refunded := s.object("billing/createCreditNote", s.root, "tenantId", s.tenantID, "statementId", draftID, "amount", 20,
		"reason", "product_unsatisfactory", "refund", true)
	expectJSONOf(t, "refund", member(refunded.Get("creditNote"), "applied"), `{"dueMicros":0,"creditMicros":0,"refundMicros":20000000}`)
	credited := s.object("billing/createCreditNote", s.root, "tenantId", s.tenantID, "statementId", draftID, "amount", 5)
	expectMatch(t, credited.Get("creditNote"), `{"number":"`+number+`-CN-03","reason":"other","applied":{"creditMicros":5000000}}`)
	s.rejects("INVALID_INPUT", "billing/createCreditNote", s.root, "tenantId", s.tenantID, "statementId", draftID, "amount", 1000)
	billingExpectNumber(t, "balance", s.object("billing/listCredits", s.owner, "tenantId", s.tenantID).Get("balanceMicros"), 15_000_000)
	if notes := s.list("billing/listCreditNotes", s.owner, "tenantId", s.tenantID, "statementId", draftID); len(notes) != 3 {
		t.Fatalf("notes: %d", len(notes))
	}

	page := s.object("billing/renderInvoice", s.owner, "tenantId", s.tenantID, "statementId", draftID)
	expectMatch(t, page, `{"filename":"`+number+`.html","contentType":"text/html; charset=utf-8"}`)
	body := jsString(page.Get("body"))
	for _, text := range []string{"Better Cloud Ltd", "Tax ID GB123456789", "Invoice " + number, "1,000 included", "Onboarding workshop",
		number + "-CN-01", "wire-1", "Amount due"} {
		if !strings.Contains(body, text) {
			t.Fatalf("invoice lacks %q", text)
		}
	}
}

func TestBillingRemindsBillingContactsBeforeAndAfterTheDueDateAndWritesInvoicesOff(t *testing.T) {
	s := newInvoicingSetup(t, func(options *BillingOptions) { options.PaymentReminderDays = []float64{-3, 0, 7} })
	lastMonth := s.shift(s.period(s.now()), -1)
	start, _ := s.bounds(lastMonth)
	s.recorded(6000, "occurredAt", start+3_600_000)
	closed := s.object("billing/closePeriod", s.root, "tenantId", s.rootID)
	issued := billingTestRecords(t, closed.Get("issued"))[0]
	statementID, number := issued.Get("statementId"), jsString(issued.Get("number"))
	reminders := func() []*core.Object {
		t.Helper()
		return billingTestRecords(t, s.ported(s.iam.Billing.SendPaymentReminders(s.ctx)).Get("reminders"))
	}
	// Due in 30 days: nothing yet.
	if len(reminders()) != 0 {
		t.Fatal("nothing is due yet")
	}
	s.advance(27 * billingDay)
	due := reminders()
	if len(due) != 1 {
		t.Fatalf("reminders: %s", core.MustStringify(due))
	}
	expectMatch(t, due[0], `{"statementId":`+core.MustStringify(statementID)+`,"step":-3,"amountDueMicros":50000000,"recipients":1}`)
	if len(reminders()) != 0 {
		t.Fatal("a step is reminded once")
	}
	// Eight days late: the missed due-date step is skipped for the latest one.
	s.advance(11 * billingDay)
	late := reminders()
	if len(late) != 1 {
		t.Fatalf("late: %s", core.MustStringify(late))
	}
	expectMatch(t, late[0], `{"statementId":`+core.MustStringify(statementID)+`,"step":7}`)
	mails := s.inboxOf("payment-reminder")
	if len(mails) != 2 || mails[0].To != s.ownerEmail() || mails[1].To != s.ownerEmail() {
		t.Fatalf("mails: %+v", mails)
	}
	if subject := billingRender(t, mails[0], auth.TemplateOptions{}).Subject; subject != "Invoice "+number+" is due in 3 days" {
		t.Fatalf("subject %q", subject)
	}
	if subject := billingRender(t, mails[1], auth.TemplateOptions{}).Subject; subject != "Invoice "+number+" is 8 days overdue" {
		t.Fatalf("subject %q", subject)
	}
	s.refresh()
	statements := s.list("billing/listStatements", s.owner, "tenantId", s.tenantID)
	if len(statements) != 1 {
		t.Fatalf("statements: %s", core.MustStringify(statements))
	}
	expectMatch(t, statements[0], `{"overdue":true,"amountDue":50}`)

	writtenOff := s.object("billing/markUncollectible", s.root, "tenantId", s.tenantID, "statementId", statementID)
	expectMember(t, writtenOff, "status", `"uncollectible"`)
	s.advance(30 * billingDay)
	expectMember(t, s.ported(s.iam.Billing.SendPaymentReminders(s.ctx)), "checked", `0`)
	// A late payment still settles it.
	s.refresh()
	paid := s.object("billing/markPaid", s.root, "tenantId", s.tenantID, "statementId", statementID, "reference", "late-wire")
	expectMatch(t, paid, `{"status":"paid","amountPaidMicros":50000000,"amountDueMicros":0}`)
	for _, billing := range []BillingOptions{{PaymentReminderDays: []float64{500}}, {Issuer: &InvoiceIssuer{Name: ""}}} {
		options := billing
		_, err := New(&BetterIamOptions{
			Database: newStore(t), Secret: "billing-test-secret-with-at-least-32-characters", BaseURL: "http://localhost:3000",
			Billing: &options,
		})
		expectCodeOrSkip(t, err, "INVALID_CONFIG")
	}
}

func TestBillingAppliesCouponsAfterTheContractDiscountOnceOrForMonthsAndGivesThemBackWhenVoided(t *testing.T) {
	s := newInvoicingSetup(t, nil)
	month := s.period(s.now())
	launch := s.object("billing/createCoupon", s.root, "tenantId", s.rootID, "code", "launch50", "name", "Launch", "percentOff", 50,
		"duration", "repeating", "durationInMonths", 2, "maxRedemptions", 1)
	expectMatch(t, launch, `{"code":"LAUNCH50","active":true,"redemptions":0}`)
	s.object("billing/createCoupon", s.root, "tenantId", s.rootID, "code", "FLAT10", "amountOff", 10)
	s.rejects("INVALID_INPUT", "billing/createCoupon", s.root, "tenantId", s.rootID, "code", "BOTH", "percentOff", 10, "amountOff", 5)
	s.rejects("ACCESS_DENIED", "billing/createCoupon", s.owner, "tenantId", s.tenantID, "code", "MINE", "percentOff", 100)

	redeemed := s.object("billing/redeemCoupon", s.owner, "tenantId", s.tenantID, "code", "launch50")
	expectMatch(t, redeemed, `{"code":"LAUNCH50","active":true,"appliedInvoices":0}`)
	s.rejects("CONFLICT", "billing/redeemCoupon", s.owner, "tenantId", s.tenantID, "code", "LAUNCH50")
	s.rejects("NOT_FOUND", "billing/redeemCoupon", s.owner, "tenantId", s.tenantID, "code", "NOPE1")
	// Coupons apply in the order they were redeemed.
	s.advance(1000)
	s.object("billing/redeemCoupon", s.owner, "tenantId", s.tenantID, "code", "flat10")
	for _, coupon := range s.list("billing/listCoupons", s.root, "tenantId", s.rootID) {
		if coupon.Get("code") == "LAUNCH50" {
			expectMatch(t, coupon, `{"redemptions":1,"active":false}`)
		}
	}

	// $50 of usage: half off, then $10 off.
	s.recorded(6000)
	s.toNextMonth(2)
	closed := billingTestRecords(t, s.ported(s.iam.Billing.ClosePeriod(s.ctx, core.NewObject())).Get("issued"))
	if len(closed) != 1 {
		t.Fatalf("issued: %s", core.MustStringify(closed))
	}
	expectMatch(t, closed[0], `{"totalMicros":15000000}`)
	statement := s.object("billing/getStatement", s.owner, "tenantId", s.tenantID, "statementId", closed[0].Get("statementId"))
	expectMatch(t, statement, `{"verified":true,"subtotalMicros":50000000,"coupons":[{"code":"LAUNCH50","amountMicros":25000000},{"code":"FLAT10","amountMicros":10000000}]}`)
	sheet := jsString(s.object("billing/exportStatement", s.owner, "tenantId", s.tenantID, "statementId", statement.Get("id")).Get("body"))
	if !strings.Contains(sheet, "coupon,LAUNCH50,Launch,,,-25.000000,") {
		t.Fatalf("CSV: %s", sheet)
	}
	discounts := func() *core.Object {
		t.Helper()
		out := core.NewObject()
		for _, discount := range s.list("billing/listDiscounts", s.owner, "tenantId", s.tenantID) {
			out.Set(jsString(discount.Get("code")), []any{discount.Get("appliedInvoices"), discount.Get("active")})
		}
		return out
	}
	// The repeating coupon still covers this month; the one-off is used up.
	expectMatch(t, discounts(), `{"LAUNCH50":[1,true],"FLAT10":[1,false]}`)

	// Voiding gives the one-off coupon back, and the invoice is issued again the same way.
	s.object("billing/voidStatement", s.root, "tenantId", s.tenantID, "statementId", statement.Get("id"), "reason", "Re-rate")
	expectMatch(t, discounts(), `{"LAUNCH50":[0,true],"FLAT10":[0,true]}`)
	again := billingTestRecords(t, s.ported(s.iam.Billing.ClosePeriod(s.ctx, core.NewObject("period", month))).Get("issued"))
	expectMatch(t, again[0], `{"number":"INV-`+strings.Replace(month, "-", "", 1)+`-0002","totalMicros":15000000}`)
	var launchID any
	for _, discount := range s.list("billing/listDiscounts", s.owner, "tenantId", s.tenantID) {
		if discount.Get("code") == "LAUNCH50" {
			launchID = discount.Get("id")
		}
	}
	removed := s.object("billing/removeDiscount", s.root, "tenantId", s.tenantID, "discountId", launchID)
	expectMatch(t, removed, `{"active":false}`)
	if _, ok := removed.Get("endedAt").(float64); !ok {
		t.Fatalf("removed: %s", core.MustStringify(removed))
	}
}

// ---------------------------------------------------------------------------------------------------------------
// The group's own paths (no billing ledger needed)

// TestBillingSortMatchesV8ForComparatorsThatNeverAnswerZero checks billingSort against V8's binary insertion sort
// for `(a, b) => (a.period < b.period ? 1 : -1) || ...` (equal periods come out in reverse order).
func TestBillingSortMatchesV8ForComparatorsThatNeverAnswerZero(t *testing.T) {
	items := []string{"2026-01:a", "2026-02:b", "2026-01:c", "2026-02:d", "2026-03:e"}
	billingSort(items, func(a, b string) float64 {
		if a[:7] < b[:7] {
			return 1
		}
		return -1
	})
	expectList(t, "sorted", items, "2026-03:e", "2026-02:d", "2026-02:b", "2026-01:c", "2026-01:a")
	numbers := []float64{3, 1, 2, 1}
	billingSort(numbers, func(a, b float64) float64 { return a - b })
	expectJSONOf(t, "numbers", numbers, `[1,1,2,3]`)
	billingExpectNumber(t, "or", billingOr(0, 5), 5)
	billingExpectNumber(t, "or first", billingOr(-1, 5), -1)
}

// TestBillingReadsCheckTheCallersTenantAndRefuseOthers covers mySpend, check and the team/department reads without
// spend: validation first, then the credential's tenant, then the permission (audited as a denial).
func TestBillingReadsCheckTheCallersTenantAndRefuseOthers(t *testing.T) {
	b := newBillingFixture(t, nil)
	b.member("alice")
	alice := b.login("alice")
	b.rejects("INVALID_INPUT", "billing/mySpend", alice, "tenantId", b.tenantID, "groupBy", 7)
	b.rejects("INVALID_INPUT", "billing/mySpend", alice, "tenantId", b.tenantID, "groupBy", "identity")
	b.rejects("INVALID_INPUT", "billing/mySpend", alice, "groupBy", "meter")
	b.rejects("ACCESS_DENIED", "billing/mySpend", alice, "tenantId", b.rootID)
	_, err := b.call("billing/mySpend", alice, "tenantId", b.rootID)
	expectError(t, err, "ACCESS_DENIED", "Spend is read in the credential’s own tenant")
	other := b.createTenant("Globex", "", "")
	_, err = b.call("billing/check", other.credential, "tenantId", b.tenantID)
	expectError(t, err, "ACCESS_DENIED", "Budgets are checked in the credential’s own tenant")
	// A member without iam:billing:read reads no team or department spend; the refusal is recorded.
	_, err = b.call("billing/teamSpend", alice, "tenantId", b.tenantID, "teamId", "team-unknown")
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	_, err = b.call("billing/departmentSpend", alice, "tenantId", b.tenantID, "departmentId", "department-unknown")
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	b.rejects("INVALID_INPUT", "billing/teamSpend", alice, "tenantId", b.tenantID)
	denied := 0
	for _, event := range b.find("audit", core.NewObject("tenantId", b.tenantID, "action", "iam:billing:read")) {
		if event.Get("outcome") == "deny" {
			denied++
		}
	}
	if denied != 2 {
		t.Fatalf("expected 2 recorded denials, got %d", denied)
	}
}

// TestBillingRootOnlyOperationsAndPlatformObjects covers closePeriod, coupons and credits refusals that need no
// ledger: root-only operations refuse others, and platform objects live on the root tenant.
func TestBillingRootOnlyOperationsAndPlatformObjects(t *testing.T) {
	b := newBillingFixture(t, nil)
	b.rejects("ACCESS_DENIED", "billing/closePeriod", b.owner, "tenantId", b.tenantID)
	_, err := b.call("billing/closePeriod", b.root, "tenantId", b.tenantID)
	expectError(t, err, "INVALID_INPUT", "Periods are closed on the platform (root) tenant")
	_, err = b.call("billing/listCoupons", b.root, "tenantId", b.tenantID)
	expectError(t, err, "INVALID_INPUT", "Coupons are managed on the platform (root) tenant")
	_, err = b.call("billing/createPlan", b.root, "tenantId", b.tenantID, "key", "team", "name", "Team")
	expectError(t, err, "INVALID_INPUT", "Plans are managed on the platform (root) tenant")
	b.rejects("ACCESS_DENIED", "billing/listCoupons", b.owner, "tenantId", b.tenantID)

	// Revoking a revoked credit and deleting an invoiced item are refused; a pending item is deleted and audited.
	now := b.now()
	b.seed(BillingCollections.Credits, core.NewObject("id", "credit-1", "tenantId", b.tenantID, "amountMicros", 5_000_000,
		"remainingMicros", 0, "reason", "Promo", "grantedAt", now, "grantedBy", "root", "revokedAt", now))
	_, err = b.call("billing/revokeCredit", b.root, "tenantId", b.tenantID, "creditId", "credit-1")
	expectError(t, err, "INVALID_TRANSITION", "The credit is already revoked")
	_, err = b.call("billing/revokeCredit", b.root, "tenantId", b.tenantID, "creditId", "credit-missing")
	expectError(t, err, "NOT_FOUND", "Resource not found")
	b.seed(BillingCollections.InvoiceItems,
		core.NewObject("id", "item-pending", "tenantId", b.tenantID, "description", "Workshop", "quantity", 1, "unitAmountMicros", 200_000_000,
			"amountMicros", 200_000_000, "status", "pending", "source", "manual", "createdAt", now, "createdBy", "root"),
		core.NewObject("id", "item-invoiced", "tenantId", b.tenantID, "description", "Setup", "quantity", 1, "unitAmountMicros", 10_000_000,
			"amountMicros", 10_000_000, "status", "invoiced", "statementId", "statement-1", "source", "manual", "createdAt", now, "createdBy", "root"))
	_, err = b.call("billing/deleteInvoiceItem", b.root, "tenantId", b.tenantID, "itemId", "item-invoiced")
	expectError(t, err, "INVALID_TRANSITION", "The item is on a finalized invoice; issue a credit note instead")
	b.rejects("ACCESS_DENIED", "billing/deleteInvoiceItem", b.owner, "tenantId", b.tenantID, "itemId", "item-pending")
	expectJSONOf(t, "deleted", b.object("billing/deleteInvoiceItem", b.root, "tenantId", b.tenantID, "itemId", "item-pending"), `{"success":true}`)
	if b.record(BillingCollections.InvoiceItems, "item-pending") != nil {
		t.Fatal("the pending item is deleted")
	}
	audited := b.auditTrail(b.tenantID, "billing:invoice-item-delete")
	if len(audited) != 1 {
		t.Fatalf("audit: %d", len(audited))
	}
	expectJSONOf(t, "metadata", audited[0].Get("metadata"), `{"description":"Workshop","amountMicros":200000000}`)
	expectMember(t, audited[0], "resourceId", `"billing/invoice-items/item-pending"`)
}

// TestBillingDeletesABudgetWithItsAlerts covers deleteBudget on a stored budget.
func TestBillingDeletesABudgetWithItsAlerts(t *testing.T) {
	b := newBillingFixture(t, nil)
	now := b.now()
	b.seed(BillingCollections.Budgets, core.NewObject("id", "budget-1", "tenantId", b.tenantID, "uniqueKey", "name:ops", "name", "Ops",
		"amountMicros", 10_000_000, "period", "month", "thresholds", []any{50, 80, 100}, "forecastAlerts", true,
		"notify", core.NewObject("owners", true, "subject", true, "emails", []any{}), "enforce", false, "subjectType", "tenant",
		"subjectId", b.tenantID, "createdAt", now, "createdBy", b.ownerID, "updatedAt", now, "updatedBy", b.ownerID))
	b.seed(BillingCollections.BudgetAlerts,
		core.NewObject("id", "alert-1", "tenantId", b.tenantID, "budgetId", "budget-1", "kind", "actual", "threshold", 50),
		core.NewObject("id", "alert-2", "tenantId", b.tenantID, "budgetId", "budget-other", "kind", "actual", "threshold", 50))
	_, err := b.call("billing/deleteBudget", b.owner, "tenantId", b.tenantID)
	expectError(t, err, "INVALID_INPUT", "Invalid budgetId")
	_, err = b.call("billing/deleteBudget", b.owner, "tenantId", b.tenantID, "budgetId", "budget-missing")
	expectError(t, err, "NOT_FOUND", "Resource not found")
	expectJSONOf(t, "deleted", b.object("billing/deleteBudget", b.owner, "tenantId", b.tenantID, "budgetId", "budget-1"), `{"success":true}`)
	if b.record(BillingCollections.Budgets, "budget-1") != nil || b.record(BillingCollections.BudgetAlerts, "alert-1") != nil {
		t.Fatal("the budget and its alerts are deleted")
	}
	if b.record(BillingCollections.BudgetAlerts, "alert-2") == nil {
		t.Fatal("other budgets' alerts stay")
	}
	audited := b.auditTrail(b.tenantID, "billing:budget-delete")
	if len(audited) != 1 {
		t.Fatalf("audit: %d", len(audited))
	}
	expectJSONOf(t, "metadata", audited[0].Get("metadata"), `{"budgetId":"budget-1","name":"Ops"}`)
}

// TestBillingRuntimeRecordPaymentFindsTheInvoiceAndIgnoresRedelivery covers iam.billing.recordPayment up to the
// ledger: the invoice by id or number, and a known idempotency key answering the invoice unchanged.
func TestBillingRuntimeRecordPaymentFindsTheInvoiceAndIgnoresRedelivery(t *testing.T) {
	b := newBillingFixture(t, nil)
	_, err := b.iam.Billing.RecordPayment(b.ctx, core.NewObject("amount", 5))
	expectError(t, err, "INVALID_INPUT", "Give statementId or number")
	_, err = b.iam.Billing.RecordPayment(b.ctx, core.NewObject("number", "INV-202601-0009"))
	expectError(t, err, "NOT_FOUND", "Statement not found")
	_, err = b.iam.Billing.RecordPayment(b.ctx, core.NewObject("statementId", 7))
	expectError(t, err, "INVALID_INPUT", "Invalid statementId")
	b.seed(BillingCollections.Statements, core.NewObject("id", "statement-1", "tenantId", b.tenantID, "number", "INV-202601-0001",
		"period", "2026-01", "status", "finalized", "payments", []any{core.NewObject("id", "payment-1", "amountMicros", 1_000_000,
			"method", "card", "reference", "pi_1", "receivedAt", b.now())}))
	again, err := b.iam.Billing.RecordPayment(b.ctx, core.NewObject("number", "INV-202601-0001", "amount", 1, "idempotencyKey", "pi_1"))
	if err != nil {
		t.Fatal(err)
	}
	expectMember(t, again, "duplicate", `true`)
	expectMember(t, again.Get("statement"), "id", `"statement-1"`)
	_, err = b.iam.Billing.RecordPayment(b.ctx, core.NewObject("statementId", "statement-1", "idempotencyKey", strings.Repeat("k", 129)))
	expectError(t, err, "INVALID_INPUT", "Invalid idempotencyKey")
	_, err = b.iam.Billing.RecordMany(b.ctx, nil)
	expectError(t, err, "INVALID_INPUT", "events must list 1-1000 usage events")
	_, err = b.iam.Billing.Check(b.ctx, core.NewObject())
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")
	_, err = b.iam.Billing.Spend(b.ctx, core.NewObject("tenantId", "tenant-missing"))
	expectError(t, err, "NOT_FOUND", "Tenant not found")
}

// TestBillingStatementsAreScopedToTheAccount covers accountStatement and scopedStatement lookups.
func TestBillingStatementsAreScopedToTheAccount(t *testing.T) {
	b := newBillingFixture(t, nil)
	globex := b.createTenant("Globex", "", "")
	b.seed(BillingCollections.Statements, core.NewObject("id", "statement-globex", "tenantId", globex.id, "number", "INV-202601-0001",
		"period", "2026-01", "status", "finalized"))
	// Another account's invoice is not found from Acme, for reads and for the root's root-only operations alike.
	_, err := b.call("billing/getStatement", b.owner, "tenantId", b.tenantID, "statementId", "statement-globex")
	expectError(t, err, "NOT_FOUND", "Statement not found")
	_, err = b.call("billing/voidStatement", b.root, "tenantId", b.tenantID, "statementId", "statement-globex", "reason", "x")
	expectError(t, err, "NOT_FOUND", "Statement not found")
	_, err = b.call("billing/markPaid", b.root, "tenantId", b.tenantID, "statementId", 5)
	expectError(t, err, "INVALID_INPUT", "Invalid statementId")
	_, err = b.call("billing/listCreditNotes", b.owner, "tenantId", b.tenantID, "statementId", "statement-globex")
	expectError(t, err, "NOT_FOUND", "Statement not found")
	_, err = b.call("billing/listInvoiceItems", b.owner, "tenantId", b.tenantID, "status", "draft")
	expectError(t, err, "INVALID_INPUT", "status must be 'pending' or 'invoiced'")
	_, err = b.call("billing/cancelSubscription", b.owner, "tenantId", b.tenantID, "subscriptionId", "subscription-missing")
	expectError(t, err, "NOT_FOUND", "Resource not found")
	_, err = b.call("billing/removeDiscount", b.root, "tenantId", b.tenantID, "discountId", "")
	expectError(t, err, "INVALID_INPUT", "Invalid discountId")
}

// TestBillingLeavesMeteringToTheRuntime makes sure the runtime is wired with the service's settings.
func TestBillingLeavesMeteringToTheRuntime(t *testing.T) {
	b := newBillingFixture(t, nil)
	if b.iam.Billing == nil || b.iam.Billing.server == nil {
		t.Fatal("iam.billing is wired")
	}
	if got, want := b.iam.Billing.Settings, BillingServiceOf(b.iam.Context).Settings; got != want && core.MustStringify(got) != core.MustStringify(want) {
		t.Fatalf("settings %s, want %s", core.MustStringify(got), core.MustStringify(want))
	}
	_ = context.Background()
}

// billingDayOf is `new Date(at).toISOString().slice(0, 10)`.
func billingDayOf(at float64) string { return time.UnixMilli(int64(at)).UTC().Format("2006-01-02") }
