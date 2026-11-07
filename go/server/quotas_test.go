package server

// Port of tests/quotas.test.ts: API usage plans, period limits and their windows, the token-bucket throttle, plan
// resolution (API key, identity, group, tenant default), tenant-scoped counters, usage, reset, validation and the
// HTTP surface. Groups, service accounts and API keys are seeded directly (their API groups are ported separately).

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const quotaTestSecond = 1000.0

// quotaAuditActions lists `{action}:{outcome}` of every quota event.
func (f *flagFixture) quotaAuditActions() []string {
	f.t.Helper()
	events, err := f.iam.Store.Find(context.Background(), "audit", core.NewObject(), nil)
	if err != nil {
		f.t.Fatal(err)
	}
	var out []string
	for _, event := range events {
		if action := jsString(event.Get("action")); strings.HasPrefix(action, "quota:") {
			out = append(out, action+":"+jsString(event.Get("outcome")))
		}
	}
	return out
}

func containsAll(list []string, wanted ...string) bool {
	for _, want := range wanted {
		found := false
		for _, item := range list {
			if item == want {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

func (f *flagFixture) createPlan(input *core.Object) (any, error) {
	out, err := f.iam.API.Quotas.CreatePlan(context.Background(), f.ownerCred, Input[apitypes.QuotasCreatePlanInput](input))
	return out.Value, err
}

func (f *flagFixture) assignPlan(input *core.Object) any {
	f.t.Helper()
	out, err := f.iam.API.Quotas.Assign(context.Background(), f.ownerCred, Input[apitypes.QuotasAssignInput](input))
	return flagAnswer(f.t, out, err)
}

func (f *flagFixture) quotaStatus(credential core.CredentialInput, meter string) *core.Object {
	f.t.Helper()
	out, err := f.iam.API.Quotas.Status(context.Background(), credential, Input[apitypes.QuotasStatusInput](core.NewObject("tenantId", f.tenantID, "meter", meter)))
	return asObject(f.t, flagAnswer(f.t, out, err))
}

func (f *flagFixture) quotaConsume(credential core.CredentialInput, input *core.Object) *core.Object {
	f.t.Helper()
	out, err := f.iam.API.Quotas.Consume(context.Background(), credential, Input[apitypes.QuotasConsumeInput](input))
	return asObject(f.t, flagAnswer(f.t, out, err))
}

// runtimeConsume is iam.quotas.consume({ ...credential, tenantId, meter, ...extra }).
func (f *flagFixture) runtimeConsume(credential core.CredentialInput, meter string, extra ...any) *core.Object {
	f.t.Helper()
	request := core.NewObject("token", credential.Token, "tenantId", f.tenantID, "meter", meter)
	for index := 0; index+1 < len(extra); index += 2 {
		request.Set(extra[index].(string), extra[index+1])
	}
	decision, err := f.iam.Quotas.Consume(context.Background(), request)
	if err != nil {
		f.t.Fatalf("consume: %v", err)
	}
	return decision
}

func dayWindow(t *testing.T, at float64, zone string) *core.Object {
	t.Helper()
	window, err := QuotaWindow("day", int64(at), zone)
	if err != nil {
		t.Fatal(err)
	}
	return window
}

func TestQuotasPeriodLimitsRefuseWithRetryAndStartOver(t *testing.T) {
	f := newFlagFixture(t, nil)
	if _, err := f.createPlan(f.body(`{"tenantId":%q,"name":"free","meter":"requests","limits":[{"period":"day","limit":3},{"period":"month","limit":100}],"alertThresholds":[50,100]}`, f.tenantID)); err != nil {
		t.Fatal(err)
	}
	alice := f.member("alice")
	f.assignPlan(f.body(`{"tenantId":%q,"plan":"free","subjectType":"identity","subjectId":%q}`, f.tenantID, alice.Get("id")))
	token := f.signInID(jsString(alice.Get("id")), false)
	for call := 1; call <= 3; call++ {
		decision := f.runtimeConsume(token, "requests")
		expectMatch(t, decision, `{"allowed":true,"plan":"free","via":"identity"}`)
		expectMatch(t, asList(t, decision.Get("limits"))[0], fmt.Sprintf(`{"period":"day","used":%d,"remaining":%d}`, call, 3-call))
	}
	refused := f.runtimeConsume(token, "requests")
	expectMatch(t, refused, `{"allowed":false,"reason":"day"}`)
	midnight := jsNumber(dayWindow(t, f.now(), "UTC").Get("end"))
	if refused.Get("retryAfterMs") != midnight-f.now() {
		t.Errorf("retryAfterMs %v, want %v", refused.Get("retryAfterMs"), midnight-f.now())
	}
	// A refusal counts nothing.
	expectMatch(t, asList(t, refused.Get("limits"))[1], `{"period":"month","used":3}`)
	_, err := f.iam.Quotas.Enforce(context.Background(), core.NewObject("token", token.Token, "tenantId", f.tenantID, "meter", "requests"))
	var exceeded *QuotaExceededError
	if !errors.As(err, &exceeded) || exceeded.Code != "QUOTA_EXCEEDED" || exceeded.Status != 429 || exceeded.RetryAfterMs == nil || *exceeded.RetryAfterMs != midnight-f.now() {
		t.Errorf("enforce: %v", err)
	}
	if exceeded != nil && exceeded.Message != "The day requests quota of plan free is used up" {
		t.Errorf("enforce message: %s", exceeded.Message)
	}
	expectMatch(t, asList(t, f.quotaStatus(token, "requests").Get("limits"))[0], `{"used":3,"remaining":0}`)
	// Crossing 50% and 100% of the day's limit, and the first refusal, are each recorded once.
	actions := f.quotaAuditActions()
	if !containsAll(actions, "quota:threshold:allow", "quota:exceeded:deny") {
		t.Errorf("audit: %v", actions)
	}
	count := 0
	for _, action := range actions {
		if action == "quota:exceeded:deny" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("quota:exceeded recorded %d times", count)
	}

	f.advance(int64(midnight-f.now()) + 1000)
	fresh := f.signInID(jsString(alice.Get("id")), false)
	if f.runtimeConsume(fresh, "requests").Get("allowed") != true {
		t.Error("the next day's window did not start over")
	}
	// Meters without a plan are unlimited.
	expectMatch(t, f.runtimeConsume(fresh, "exports"), `{"allowed":true,"plan":null}`)
}

func TestQuotasThrottleBurstsWithSharedTokenBucket(t *testing.T) {
	f := newFlagFixture(t, nil)
	if _, err := f.createPlan(f.body(`{"tenantId":%q,"name":"steady","meter":"requests","throttle":{"ratePerSecond":1,"burst":2},"default":true}`, f.tenantID)); err != nil {
		t.Fatal(err)
	}
	for call := 0; call < 2; call++ {
		if f.runtimeConsume(f.ownerCred, "requests").Get("allowed") != true {
			t.Fatalf("call %d refused", call)
		}
	}
	refused := f.runtimeConsume(f.ownerCred, "requests")
	expectMatch(t, refused, `{"allowed":false,"reason":"throttle","via":"default"}`)
	if refused.Get("retryAfterMs") != quotaTestSecond {
		t.Errorf("retryAfterMs %v", refused.Get("retryAfterMs"))
	}
	f.advance(1000)
	if f.runtimeConsume(f.ownerCred, "requests").Get("allowed") != true {
		t.Error("the bucket did not refill")
	}
	// The bucket lives in the database: the next call sees the spent token.
	if f.runtimeConsume(f.ownerCred, "requests").Get("allowed") != false {
		t.Error("the bucket was not shared")
	}
	// A cost above the burst can never succeed: no retry time is given.
	tooBig := f.runtimeConsume(f.ownerCred, "requests", "cost", 5.0)
	expectMatch(t, tooBig, `{"allowed":false,"reason":"throttle"}`)
	if tooBig.Has("retryAfterMs") {
		t.Errorf("retryAfterMs for a cost above the burst: %v", tooBig.Get("retryAfterMs"))
	}
}

func TestQuotasMostSpecificPlanApplies(t *testing.T) {
	f := newFlagFixture(t, nil)
	plan := func(name string, limit int, extra string) error {
		_, err := f.createPlan(f.body(`{"tenantId":%q,"name":%q,"meter":"requests","limits":[{"period":"day","limit":%d}]%s}`, f.tenantID, name, limit, extra))
		return err
	}
	for _, err := range []error{plan("basic", 10, `,"default":true`), plan("team", 100, ""), plan("vip", 1000, `,"priority":5`), plan("ci", 5000, "")} {
		if err != nil {
			t.Fatal(err)
		}
	}
	expectCode(t, plan("other-default", 1, `,"default":true`), "CONFLICT")
	alice := f.member("alice")
	bob := f.member("bob")
	aliceID := jsString(alice.Get("id"))
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		for _, group := range []*core.Object{
			core.NewObject("id", "group-engineers", "tenantId", f.tenantID, "name", "Engineers", "createdAt", f.now()),
			core.NewObject("id", "group-vips", "tenantId", f.tenantID, "name", "VIPs", "createdAt", f.now()),
		} {
			if _, err := tx.Insert(ctx, "groups", group); err != nil {
				return err
			}
			if _, err := tx.Insert(ctx, "groupMembers", core.NewObject("id", ID(), "tenantId", f.tenantID, "groupId", group.Get("id"),
				"identityId", aliceID, "createdAt", f.now())); err != nil {
				return err
			}
		}
		return nil
	})
	f.assignPlan(f.body(`{"tenantId":%q,"plan":"team","subjectType":"group","subjectId":"group-engineers"}`, f.tenantID))
	f.assignPlan(f.body(`{"tenantId":%q,"plan":"vip","subjectType":"group","subjectId":"group-vips"}`, f.tenantID))
	aliceToken := f.signInID(aliceID, false)
	bobToken := f.signInID(jsString(bob.Get("id")), false)
	planOf := func(credential core.CredentialInput) any {
		t.Helper()
		return f.quotaStatus(credential, "requests").Get("plan")
	}
	if got := planOf(bobToken); got != "basic" {
		t.Errorf("bob: %v", got)
	}
	// Of two group plans, the higher priority applies.
	if got := planOf(aliceToken); got != "vip" {
		t.Errorf("alice by group: %v", got)
	}
	f.assignPlan(f.body(`{"tenantId":%q,"plan":"team","subjectType":"identity","subjectId":%q}`, f.tenantID, aliceID))
	if got := planOf(aliceToken); got != "team" {
		t.Errorf("alice by identity: %v", got)
	}

	keyToken := Token() + Token()[:10]
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		if _, err := tx.Insert(ctx, "identities", identity("ci-bot", f.tenantID, "kind", "service", "name", "ci-bot")); err != nil {
			return err
		}
		_, err := tx.Insert(ctx, "sessions", core.NewObject("id", "key-deploy", "tenantId", f.tenantID, "identityId", "ci-bot",
			"kind", "api-key", "name", "deploy", "tokenHash", Hash(keyToken), "createdAt", f.now(), "lastSeenAt", f.now(),
			"authenticatedAt", f.now(), "expiresAt", 9e15, "mfa", false, "credentialAuthorityId", f.authorityID))
		return err
	})
	f.assignPlan(f.body(`{"tenantId":%q,"plan":"ci","subjectType":"apiKey","subjectId":"key-deploy"}`, f.tenantID))
	if got := planOf(core.CredentialInput{Token: keyToken}); got != "ci" {
		t.Errorf("api key: %v", got)
	}
	viaKey, err := f.iam.Quotas.ConsumeFor(context.Background(), core.NewObject("tenantId", f.tenantID, "identityId", "ci-bot", "apiKeyId", "key-deploy", "meter", "requests"))
	if err != nil || viaKey.Get("plan") != "ci" {
		t.Errorf("consumeFor: %v %v", viaKey, err)
	}
	listed, err := f.iam.API.Quotas.ListAssignments(context.Background(), f.ownerCred, Input[apitypes.QuotasListAssignmentsInput](core.NewObject("tenantId", f.tenantID)))
	var entries []string
	for _, entry := range asList(t, flagAnswer(t, listed, err)) {
		entries = append(entries, fmt.Sprintf("%v:%v:%v", entry.Get("plan"), entry.Get("subjectType"), entry.Get("subjectName")))
	}
	sort.Strings(entries)
	if got := strings.Join(entries, ","); got != "ci:apiKey:deploy,team:group:Engineers,team:identity:alice,vip:group:VIPs" {
		t.Errorf("assignments: %s", got)
	}
	unassigned, err := f.iam.API.Quotas.Unassign(context.Background(), f.ownerCred, Input[apitypes.QuotasUnassignInput](
		f.body(`{"tenantId":%q,"meter":"requests","subjectType":"identity","subjectId":%q}`, f.tenantID, aliceID)))
	if got := toJSON(t, flagAnswer(t, unassigned, err)); got != `{"removed":true}` {
		t.Errorf("unassign: %s", got)
	}
	if got := planOf(aliceToken); got != "vip" {
		t.Errorf("alice after unassign: %v", got)
	}
}

func TestQuotasTenantScopedCountersUsageResetAndCleanup(t *testing.T) {
	f := newFlagFixture(t, nil)
	if _, err := f.createPlan(f.body(`{"tenantId":%q,"name":"shared","meter":"exports","scope":"tenant","default":true,"limits":[{"period":"hour","limit":3}]}`, f.tenantID)); err != nil {
		t.Fatal(err)
	}
	alice := f.signInID(jsString(f.member("alice").Get("id")), false)
	bob := f.signInID(jsString(f.member("bob").Get("id")), false)
	f.quotaConsume(alice, f.body(`{"tenantId":%q,"meter":"exports","cost":2}`, f.tenantID))
	expectMatch(t, f.quotaConsume(bob, f.body(`{"tenantId":%q,"meter":"exports","cost":2}`, f.tenantID)), `{"allowed":false,"reason":"hour"}`)
	if f.quotaConsume(bob, f.body(`{"tenantId":%q,"meter":"exports"}`, f.tenantID)).Get("allowed") != true {
		t.Error("the last unit was refused")
	}
	usage, err := f.iam.API.Quotas.Usage(context.Background(), f.ownerCred, Input[apitypes.QuotasUsageInput](f.body(`{"tenantId":%q,"plan":"shared"}`, f.tenantID)))
	views := asList(t, flagAnswer(t, usage, err))
	if len(views) != 1 {
		t.Fatalf("usage: %s", toJSON(t, views))
	}
	expectMatch(t, views[0], `{"subject":"tenant","limits":[{"period":"hour","used":3,"remaining":0}]}`)
	reset, err := f.iam.API.Quotas.Reset(context.Background(), f.ownerCred, Input[apitypes.QuotasResetInput](f.body(`{"tenantId":%q,"plan":"shared"}`, f.tenantID)))
	if got := toJSON(t, flagAnswer(t, reset, err)); got != `{"reset":1}` {
		t.Errorf("reset: %s", got)
	}
	if f.quotaConsume(bob, f.body(`{"tenantId":%q,"meter":"exports","cost":3}`, f.tenantID)).Get("allowed") != true {
		t.Error("the reset did not start the counters over")
	}
	deleted, err := f.iam.API.Quotas.DeletePlan(context.Background(), f.ownerCred, Input[apitypes.QuotasDeletePlanInput](f.body(`{"tenantId":%q,"name":"shared"}`, f.tenantID)))
	expectMatch(t, flagAnswer(t, deleted, err), `{"deleted":true}`)
	if counters, _ := f.iam.Store.Find(context.Background(), "quotaCounters", core.NewObject("tenantId", f.tenantID), nil); len(counters) != 0 {
		t.Errorf("counters left: %d", len(counters))
	}
	if actions := f.quotaAuditActions(); !containsAll(actions, "quota:plan-create:allow", "quota:reset:allow", "quota:plan-delete:allow") {
		t.Errorf("audit: %v", actions)
	}
}

func TestQuotasValidatePlansRefuseOtherTenantsAndServeHTTP(t *testing.T) {
	f := newFlagFixture(t, nil)
	_, err := f.createPlan(f.body(`{"tenantId":%q,"name":"empty","meter":"requests"}`, f.tenantID))
	expectCode(t, err, "INVALID_INPUT")
	for _, limits := range []string{`[{"period":"year","limit":1}]`, `[{"period":"day","limit":0}]`, `[{"period":"day","limit":1},{"period":"day","limit":2}]`} {
		_, err := f.createPlan(f.body(`{"tenantId":%q,"name":"bad","meter":"requests","limits":%s}`, f.tenantID, limits))
		expectCode(t, err, "INVALID_INPUT")
	}
	_, err = f.createPlan(f.body(`{"tenantId":%q,"name":"bad","meter":"Requests!","limits":[{"period":"day","limit":1}]}`, f.tenantID))
	expectCode(t, err, "INVALID_INPUT")
	if _, err := f.createPlan(f.body(`{"tenantId":%q,"name":"free","meter":"requests","default":true,"limits":[{"period":"minute","limit":1}]}`, f.tenantID)); err != nil {
		t.Fatal(err)
	}
	// A session of another tenant cannot count here.
	_, err = f.iam.Quotas.Consume(context.Background(), core.NewObject("token", f.rootCred.Token, "tenantId", f.tenantID, "meter", "requests"))
	expectCode(t, err, "ACCESS_DENIED")
	call := func() *core.Object {
		t.Helper()
		response := f.post("http://localhost:3000", "quotas/consume", fmt.Sprintf(`{"tenantId":%q,"meter":"requests"}`, f.tenantID),
			map[string]string{"authorization": "Bearer " + f.ownerCred.Token})
		data, _ := jsonBody(t, response).Get("data").(*core.Object)
		if data == nil {
			t.Fatalf("HTTP consume: %d %s", response.Status, response.Body)
		}
		return data
	}
	if call().Get("allowed") != true {
		t.Error("the first call was refused")
	}
	expectMatch(t, call(), `{"allowed":false,"reason":"minute"}`)
}

func TestQuotasWindowsStartAtLocalMidnight(t *testing.T) {
	iso := func(ms any) string {
		return time.UnixMilli(int64(jsNumber(ms))).UTC().Format("2006-01-02T15:04:05.000Z")
	}
	window := func(period string, at int64, zone string) *core.Object {
		t.Helper()
		result, err := QuotaWindow(period, at, zone)
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	// 2026-03-08 is the day New York moves to daylight saving time.
	at := time.Date(2026, 3, 8, 15, 0, 0, 0, time.UTC).UnixMilli()
	day := window("day", at, "America/New_York")
	if iso(day.Get("start")) != "2026-03-08T05:00:00.000Z" || iso(day.Get("end")) != "2026-03-09T04:00:00.000Z" {
		t.Errorf("day: %s - %s", iso(day.Get("start")), iso(day.Get("end")))
	}
	if week := window("week", at, "America/New_York"); iso(week.Get("start")) != "2026-03-02T05:00:00.000Z" {
		t.Errorf("week: %s", iso(week.Get("start")))
	}
	month := window("month", at, "Europe/Berlin")
	if iso(month.Get("start")) != "2026-02-28T23:00:00.000Z" || iso(month.Get("end")) != "2026-03-31T22:00:00.000Z" {
		t.Errorf("month: %s - %s", iso(month.Get("start")), iso(month.Get("end")))
	}
	span := func(period string) float64 {
		w := window(period, at, "UTC")
		return jsNumber(w.Get("end")) - jsNumber(w.Get("start"))
	}
	if span("hour") != 3_600_000 || span("day") != 86_400_000 {
		t.Errorf("spans: %v %v", span("hour"), span("day"))
	}
}

func TestQuotasValidationHelpers(t *testing.T) {
	if _, err := QuotaThrottle(obj(t, `{"ratePerSecond":0}`)); err == nil {
		t.Error("a zero rate was accepted")
	}
	throttle, err := QuotaThrottle(obj(t, `{"ratePerSecond":2.5}`))
	if err != nil || toJSON(t, throttle) != `{"ratePerSecond":2.5,"burst":3}` {
		t.Errorf("throttle default burst: %v %v", throttle, err)
	}
	thresholds, err := AlertThresholds(parse(t, `[90,50,90]`))
	if err != nil || fmt.Sprint(thresholds) != "[50 90]" {
		t.Errorf("thresholds: %v %v", thresholds, err)
	}
	limits, err := QuotaLimits(parse(t, `[{"period":"month","limit":10},{"period":"minute","limit":1}]`))
	if err != nil || len(limits) != 2 || limits[0].Get("period") != "minute" {
		t.Errorf("limits order: %v %v", limits, err)
	}
	if _, err := TimeZone("Not/AZone"); err == nil {
		t.Error("an unknown time zone was accepted")
	}
	expectError(t, func() error { _, err := QuotaName("Bad!", "meter"); return err }(), "INVALID_INPUT",
		"meter must be 1-64 lowercase letters, digits and ._- starting with a letter or digit")
}
