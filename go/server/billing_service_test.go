package server

// Tests of billing-service.ts: the pure parts (money formatting, CSV, group-by and anomaly validation, directory
// roll-ups) run on their own; the service scenarios are ports of tests/billing.test.ts and
// tests/billing-invoicing.test.ts driven through the service with seeded records. A scenario that reaches a
// NOT_IMPLEMENTED stub of another unit (billing.ts, billing-plans.ts, billing-invoices.ts) skips the rest of the test.

import (
	"context"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// billSkipUnported skips the test when err is another unit's NOT_IMPLEMENTED stub and fails it on any other error.
func billSkipUnported(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	t.Fatal(err)
}

// billExpectCode expects an IamError with code (skipping on another unit's NOT_IMPLEMENTED stub).
func billExpectCode(t *testing.T, err error, code string) {
	t.Helper()
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" && code != "NOT_IMPLEMENTED" {
		t.Skipf("blocked by another unit: %s", known.Message)
	}
	known, ok := asIamError(err)
	if !ok {
		t.Fatalf("expected %s, got %v", code, err)
	}
	if known.Code != code {
		t.Fatalf("expected %s, got %s: %s", code, known.Code, known.Message)
	}
}

func TestBillingCurrencyTextMatchesIntl(t *testing.T) {
	// Expected values from Intl.NumberFormat('en-US', { style: 'currency', currency }) in Node.
	cases := []struct {
		currency string
		value    float64
		want     string
	}{
		{"USD", 1234.5, "$1,234.50"},
		{"USD", -0.001, "-$0.00"},
		{"USD", 0.125, "$0.13"},
		{"USD", 1234567.125, "$1,234,567.13"},
		{"EUR", 12, "€12.00"},
		{"JPY", 2.5, "¥3"},
		{"JPY", -1234.5, "-¥1,235"},
		{"BHD", 1.0005, "BHD 1.001"},
		{"CAD", 99.995, "CA$100.00"},
		{"XOF", 1500, "F CFA 1,500"},
		{"ABC", 5, "ABC 5.00"},
		{"GBP", 0, "£0.00"},
		{"USD", 999.995, "$1,000.00"},
	}
	for _, c := range cases {
		if got := bsCurrencyText(c.value, c.currency); got != c.want {
			t.Errorf("%s %v: got %q, want %q", c.currency, c.value, got, c.want)
		}
	}
}

func TestBillingSpendCsvMatchesTheTypeScript(t *testing.T) {
	service := &BillingService{}
	report := obj(t, `{"groupBy":"identity","currency":"EUR","rows":[
		{"key":"id-1","label":"Alice <alice@acme.test>","costMicros":12345678,"share":61.7,"events":3,"quantities":{"api-calls":1200.5,"storage":2}},
		{"key":"(unattributed)","costMicros":7654321,"share":38.3,"events":1,"quantities":{"api-calls":10}},
		{"key":"id-3","label":"=HYPERLINK(\"x\"), evil","costMicros":0,"share":0,"events":0,"quantities":{}}
	],"total":{"costMicros":19999999,"events":4}}`)
	got, err := service.SpendCsv(report)
	if err != nil {
		t.Fatal(err)
	}
	want := "identity,label,amount_eur,share_percent,events,quantity_api-calls,quantity_storage\r\n" +
		"id-1,Alice <alice@acme.test>,12.345678,61.7,3,1200.5,2\r\n" +
		"(unattributed),,7.654321,38.3,1,10,0\r\n" +
		"id-3,\"'=HYPERLINK(\"\"x\"\"), evil\",0.000000,0,0,0,0\r\n" +
		"total,,19.999999,100,4,,\r\n"
	if got != want {
		t.Fatalf("spend CSV:\n%q\nwant\n%q", got, want)
	}
}

func TestBillingStatementCsvMatchesTheTypeScript(t *testing.T) {
	service := &BillingService{}
	statement := obj(t, `{"number":"INV-202609-0001","period":"2026-09","currency":"USD","subtotalMicros":25000000,
		"creditsMicros":5000000,"totalMicros":21600000,
		"lines":[{"meter":"api-calls","name":"API calls","quantity":12000,"unit":"request","amountMicros":20000000},
			{"kind":"item","invoiceItemId":"item-1","name":"-1+cmd|calc","quantity":1,"unit":"unit","amountMicros":5000000},
			{"kind":"plan","planItemId":"seat","name":"Seats, \"Pro\"","quantity":-2,"unit":"seat","amountMicros":-1}],
		"discount":{"percent":10,"amountMicros":2500000},"commitment":{"minimumMicros":1,"trueUpMicros":1000000},
		"coupons":[{"discountId":"d","code":"WELCOME","name":"Welcome","amountMicros":500000}],
		"tax":{"label":"VAT","ratePercent":20,"amountMicros":3600000},
		"breakdown":{"tenants":[{"id":"t1","name":"Acme","costMicros":20000000}],"teams":[{"id":"team1","name":"@ops","costMicros":1}],
			"departments":[{"id":"d1","name":"Eng","costMicros":3,"costCenter":"CC-1"},{"id":"d2","name":"Ops","costMicros":2}],
			"identities":[{"id":"i1","name":"Alice","costMicros":4}]}}`)
	got, err := service.StatementCsv(statement)
	if err != nil {
		t.Fatal(err)
	}
	want := "section,id,name,quantity,unit,amount,cost_center\r\n" +
		"line,api-calls,API calls,12000,request,20.000000,\r\n" +
		"item,item-1,'-1+cmd|calc,1,unit,5.000000,\r\n" +
		"plan,seat,\"Seats, \"\"Pro\"\"\",-2,seat,-0.000001,\r\n" +
		"subtotal,,,,,25.000000,\r\n" +
		"discount,,10%,,,-2.500000,\r\n" +
		"commitment,,minimum commitment true-up,,,1.000000,\r\n" +
		"coupon,WELCOME,Welcome,,,-0.500000,\r\n" +
		"credit,,,,,-5.000000,\r\n" +
		"tax,,VAT 20%,,,3.600000,\r\n" +
		"total,INV-202609-0001,2026-09,,USD,21.600000,\r\n" +
		"tenant,t1,Acme,,,20.000000,\r\n" +
		"team,team1,'@ops,,,0.000001,\r\n" +
		"department,d1,Eng,,,0.000003,CC-1\r\n" +
		"department,d2,Ops,,,0.000002,\r\n" +
		"identity,i1,Alice,,,0.000004,\r\n"
	if got != want {
		t.Fatalf("statement CSV:\n%q\nwant\n%q", got, want)
	}
}

func TestBillingCsvCellsAndToFixed(t *testing.T) {
	cases := map[any]string{
		"-12.5":       "-12.5",
		"-1+cmd|calc": "'-1+cmd|calc",
		"+1":          "'+1",
		"@SUM(A1)":    "'@SUM(A1)",
		"\tTab":       "'\tTab",
		"a,b":         `"a,b"`,
		"line\nbreak": "\"line\nbreak\"",
		"plain":       "plain",
		5.0:           "5",
		-5.0:          "-5",
	}
	for value, want := range cases {
		if got := bsCell(value); got != want {
			t.Errorf("cell %q: got %q, want %q", value, got, want)
		}
	}
	if got := bsCell(core.Undefined); got != "" {
		t.Errorf("undefined cell: %q", got)
	}
	if got := bsCell(nil); got != "" {
		t.Errorf("null cell: %q", got)
	}
	for value, want := range map[float64]string{0: "0.000000", -1e-7: "-0.000000", 1e21: "1e+21", 12.3456789: "12.345679"} {
		if got := bsToFixed(value, 6); got != want {
			t.Errorf("toFixed(%v): got %q, want %q", value, got, want)
		}
	}
}

func TestBillingSpendGroupByValidation(t *testing.T) {
	for _, value := range []string{"meter", "identity", "agent", "team", "department", "tenant", "day", "tag:env", "tag:a.b_c:d-1"} {
		got, err := bsSpendGroupBy(value)
		if err != nil || got != value {
			t.Errorf("groupBy %q: %q %v", value, got, err)
		}
	}
	for _, value := range []any{7.0, "tag:", "tag:1env", "Meter", nil} {
		_, err := bsSpendGroupBy(value)
		expectError(t, err, "INVALID_INPUT", "groupBy must be 'meter', 'identity', 'agent', 'team', 'department', 'tenant', 'day' or 'tag:{name}'")
	}
}

func TestBillingDaysBeforeAndAnomalyOptions(t *testing.T) {
	got := bsDaysBefore("2026-03-02", 3)
	want := []string{"2026-02-27", "2026-02-28", "2026-03-01"}
	if len(got) != len(want) {
		t.Fatalf("days before: %v", got)
	}
	for index := range want {
		if got[index] != want[index] {
			t.Fatalf("days before: %v, want %v", got, want)
		}
	}
	k := newKernel(t, nil)
	service := &BillingService{server: k.server, tz: "UTC"}
	options, err := service.anomalyOptions(obj(t, `{"day":"2026-09-22"}`))
	if err != nil {
		t.Fatal(err)
	}
	if options.day != "2026-09-22" || options.baselineDays != 14 || options.factor != 3 || options.minimumMicros != 10_000_000 {
		t.Fatalf("defaults: %+v", options)
	}
	_, err = service.anomalyOptions(obj(t, `{"day":"2026-13-01"}`))
	expectError(t, err, "INVALID_INPUT", "day must be a date such as 2026-09-22")
	_, err = service.anomalyOptions(obj(t, `{"day":"2026-09-22","baselineDays":2}`))
	expectError(t, err, "INVALID_INPUT", "Invalid baselineDays")
	_, err = service.anomalyOptions(obj(t, `{"day":"2026-09-22","factor":1}`))
	expectError(t, err, "INVALID_INPUT", "factor must be a number from 1.1 to 1000")
	_, err = service.anomalyOptions(obj(t, `{"day":"2026-09-22","factor":"3"}`))
	expectError(t, err, "INVALID_INPUT", "factor must be a number from 1.1 to 1000")
}

func TestBillingBuiltInMetersAndSpendMentions(t *testing.T) {
	if builtIn, _ := BuiltInMeterKey("inference"); !builtIn {
		t.Fatal("inference is a built-in meter")
	}
	if builtIn, _ := BuiltInMeterKey("api-calls"); builtIn {
		t.Fatal("api-calls is not built in")
	}
	if builtIn, _ := BuiltInMeterKey("__proto__"); builtIn {
		t.Fatal("__proto__ is not built in")
	}
	spending := parse(t, `{"statements":[{"effect":"deny","actions":["*"],"conditions":{"bool":{"principal.spendExceeded":true}}}]}`)
	plain := parse(t, `{"statements":[{"effect":"allow","actions":["documents:read"]}]}`)
	if !MentionsSpend([]any{plain, spending}) || MentionsSpend([]any{plain}) {
		t.Fatal("MentionsSpend")
	}
}

func TestBillingServiceIsOnePerServer(t *testing.T) {
	k := newKernel(t, nil)
	first := BillingServiceOf(k.server)
	if BillingServiceOf(k.server) != first {
		t.Fatal("billingServiceOf must return the same service")
	}
	if first.Hooks == nil || first.Hooks.service != first {
		t.Fatal("hooks belong to the service")
	}
	other := newKernel(t, nil)
	if BillingServiceOf(other.server) == first {
		t.Fatal("each server has its own service")
	}
	// The hooks never fail the work they bill, whatever happens inside.
	if err := first.Hooks.RecordPriced(k.ctx, k.store, core.NewObject("tenantId", "missing", "meter", "inference", "costMicros", 5.0)); err != nil {
		t.Fatal(err)
	}
}

func TestBillingSettingsRefuseAnInvalidOption(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) {
		options.Billing = &BillingOptions{Currency: str("dollars")}
	})
	service := createBillingService(k.server)
	err := service.BillingSettingsError()
	billExpectCode(t, err, "INVALID_CONFIG")
	expectError(t, err, "INVALID_CONFIG", "billing.currency must be an ISO 4217 code such as USD")
	_, err = service.CurrentPeriod()
	expectError(t, err, "INVALID_CONFIG", "billing.currency must be an ISO 4217 code such as USD")
}

func TestBillingTeamAndDepartmentRollUps(t *testing.T) {
	service := &BillingService{}
	dir := core.NewObject(
		"teams", core.NewObject(
			"platform", core.NewObject("id", "platform", "name", "Platform"),
			"infra", core.NewObject("id", "infra", "name", "Infra", "parentId", "platform"),
			"sre", core.NewObject("id", "sre", "name", "SRE", "parentId", "infra"),
		),
		"departments", map[string]*core.Object{
			"eng":     core.NewObject("id", "eng", "name", "Engineering"),
			"backend": core.NewObject("id", "backend", "name", "Backend", "parentId", "eng"),
		},
	)
	for _, c := range []struct {
		candidate, team string
		want            bool
	}{{"sre", "platform", true}, {"sre", "sre", true}, {"platform", "sre", false}, {"missing", "platform", false}} {
		if got, err := service.TeamWithin(dir, c.candidate, c.team); err != nil || got != c.want {
			t.Errorf("teamWithin(%s, %s) = %v %v", c.candidate, c.team, got, err)
		}
	}
	// A directory whose departments are a Go map (DirectoryFor may keep TenantDepartments' map).
	dir.SetRaw("departments", map[string]*core.Object{
		"eng":     core.NewObject("id", "eng", "name", "Engineering"),
		"backend": core.NewObject("id", "backend", "name", "Backend", "parentId", "eng"),
	})
	if got, _ := service.DepartmentWithin(dir, "backend", "eng"); !got {
		t.Error("backend is within engineering")
	}
	if got, _ := service.DepartmentWithin(dir, "eng", "backend"); got {
		t.Error("engineering is not within backend")
	}
	if names := bsDirectoryValues(dir, "teams"); len(names) != 3 || bsStr(names[0], "id") != "platform" {
		t.Errorf("team values: %v", names)
	}
}

// billScenario is a kernel with root > organization > project tenants, an owner and two people in the organization,
// and a platform `api-calls` meter.
type billScenario struct {
	*kernel
	service *BillingService
}

func newBillScenario(t *testing.T, mutate func(options *BetterIamOptions)) *billScenario {
	t.Helper()
	k := newKernel(t, mutate)
	k.tenantTree()
	k.insert("identities",
		identity("owner", "org", "email", "owner@acme.test", "owner", true),
		identity("alice", "org", "email", "alice@acme.test"),
		identity("bob", "org", "email", "bob@acme.test"),
	)
	now := float64(k.clock.Load())
	k.insert(BillingCollections.Meters, core.NewObject(
		"id", "meter-api", "tenantId", "root", "uniqueKey", "api-calls", "key", "api-calls", "name", "API calls",
		"unit", "request", "aggregation", "sum", "pricing", "rate-card", "archived", false,
		"createdAt", now, "createdBy", "deployment", "updatedAt", now, "updatedBy", "deployment",
	))
	return &billScenario{kernel: k, service: BillingServiceOf(k.server)}
}

func (s *billScenario) record(input string) (*core.Object, error) {
	var result *core.Object
	err := s.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		result, err = s.service.Record(ctx, tx, obj(s.t, input), "deployment", nil)
		return err
	})
	return result, err
}

// Port of 'validates usage, stays idempotent, and records through the trusted runtime' (the service part).
func TestBillingRecordValidatesUsageAndStaysIdempotent(t *testing.T) {
	s := newBillScenario(t, nil)
	first, err := s.record(`{"tenantId":"org","meter":"api-calls","quantity":10,"identityId":"alice","idempotencyKey":"request-1","tags":{"env":"prod"}}`)
	billSkipUnported(t, err)
	again, err := s.record(`{"tenantId":"org","meter":"api-calls","quantity":10,"identityId":"alice","idempotencyKey":"request-1"}`)
	billSkipUnported(t, err)
	if !core.StrictEquals(again.Get("id"), first.Get("id")) || again.Get("duplicate") != true || first.Get("duplicate") != false {
		t.Fatalf("idempotent record: %v then %v", first, again)
	}
	_, err = s.record(`{"tenantId":"org","meter":"api-calls","quantity":1,"identityId":"alice","cost":1}`)
	billExpectCode(t, err, "INVALID_INPUT")
	_, err = s.record(`{"tenantId":"org","meter":"nope"}`)
	billExpectCode(t, err, "NOT_FOUND")
	_, err = s.record(`{"tenantId":"org","meter":"api-calls","quantity":-1,"identityId":"alice"}`)
	billExpectCode(t, err, "INVALID_INPUT")
	future := float64(s.clock.Load() + 3_600_000)
	_, err = s.record(`{"tenantId":"org","meter":"api-calls","quantity":1,"occurredAt":` + core.NumberString(future) + `}`)
	billExpectCode(t, err, "INVALID_INPUT")
	_, err = s.record(`{"tenantId":"org","meter":"api-calls","quantity":1,"idempotencyKey":"request-1"}`)
	if err != nil {
		billSkipUnported(t, err)
	}
	// The usage event and its daily roll-up.
	events, err := s.store.Find(s.ctx, BillingCollections.Usage, core.NewObject("tenantId", "org"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || bsStr(events[0], "uniqueKey") != "idem:request-1" || bsStr(events[0], "recordedBy") != "deployment" {
		t.Fatalf("usage events: %v", events)
	}
	if tags, _ := events[0].Get("tags").(*core.Object); bsStr(tags, "env") != "prod" {
		t.Fatalf("tags: %v", events[0].Get("tags"))
	}
	rollups, err := s.store.Find(s.ctx, BillingCollections.Rollups, core.NewObject("tenantId", "org"), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rollups) != 1 || bsNum(rollups[0], "quantity") != 10 || bsNum(rollups[0], "events") != 1 {
		t.Fatalf("rollups: %v", rollups)
	}
	// Archived meters keep their history but refuse new usage.
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		meter, err := tx.Get(ctx, BillingCollections.Meters, "meter-api")
		if err != nil {
			return err
		}
		_, err = tx.Put(ctx, BillingCollections.Meters, meter.Spread(core.NewObject("archived", true)))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = s.record(`{"tenantId":"org","meter":"api-calls","quantity":1,"identityId":"alice"}`)
	billExpectCode(t, err, "METER_ARCHIVED")
}

// finalizedStatement seeds a finalized invoice of the organization for the previous month.
func (s *billScenario) finalizedStatement(totalMicros float64) *core.Object {
	s.t.Helper()
	now := float64(s.clock.Load())
	statement := core.NewObject(
		"id", "statement-1", "tenantId", "org", "uniqueKey", "period:2025-12", "number", "INV-202512-0001",
		"status", "finalized", "issuedAt", now, "dueAt", now+30*dayMs, "hash", "seal",
		"period", "2025-12", "currency", "USD", "periodStart", 0.0, "periodEnd", 1.0, "lines", []any{},
		"billingReason", "period", "subtotalMicros", totalMicros, "creditsMicros", 0.0, "totalMicros", totalMicros,
		"creditsApplied", []any{},
		"breakdown", core.NewObject("tenants", []any{}, "teams", []any{}, "departments", []any{}, "identities", []any{}),
		"billTo", core.NewObject("name", "Acme", "emails", []any{"billing@acme.test"}),
	)
	s.insert(BillingCollections.Statements, statement)
	return statement
}

// Port of the payment and credit note steps of tests/billing-invoicing.test.ts.
func TestBillingPaymentsCreditNotesAndVoiding(t *testing.T) {
	s := newBillScenario(t, nil)
	statement := s.finalizedStatement(100_000_000)
	var paid *core.Object
	err := s.tx(func(ctx context.Context, tx core.IamStore) error {
		result, err := s.service.RecordPayment(ctx, tx, statement, obj(t, `{"amount":40,"reference":"wire-1"}`), "owner")
		if err != nil {
			return err
		}
		paid, _ = result.Get("statement").(*core.Object)
		return nil
	})
	billSkipUnported(t, err)
	if bsStr(paid, "status") != "finalized" || bsNum(paid, "amountPaidMicros") != 40_000_000 {
		t.Fatalf("partial payment: %v", paid)
	}
	// Voiding an invoice with payments is refused: credit it instead.
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := s.service.VoidStatement(ctx, tx, paid, principalOf(identity("owner", "org"), nil), "mistake")
		return err
	})
	expectError(t, err, "INVALID_TRANSITION", "The invoice has payments or credit notes; issue a credit note instead")
	// A payment above the amount due settles the invoice and keeps the excess as account credit.
	var settled, payment *core.Object
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		result, err := s.service.RecordPayment(ctx, tx, paid, obj(t, `{"amount":70}`), "owner")
		if err != nil {
			return err
		}
		settled, _ = result.Get("statement").(*core.Object)
		payment, _ = result.Get("payment").(*core.Object)
		return nil
	})
	billSkipUnported(t, err)
	if bsStr(settled, "status") != "paid" || bsNum(payment, "overpaymentMicros") != 10_000_000 || bsStr(payment, "method") != "manual" {
		t.Fatalf("overpayment: %v %v", settled, payment)
	}
	credit, err := s.store.Get(s.ctx, BillingCollections.Credits, bsStr(payment, "creditId"))
	if err != nil || credit == nil || bsStr(credit, "reason") != "Overpayment of INV-202512-0001" {
		t.Fatalf("overpayment credit: %v %v", credit, err)
	}
	// A credit note on a paid invoice becomes account credit, numbered after the invoice.
	var note *core.Object
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		result, err := s.service.CreateCreditNote(ctx, tx, settled, obj(t, `{"amount":25,"memo":"  goodwill  "}`), "owner")
		if err != nil {
			return err
		}
		note, _ = result.Get("creditNote").(*core.Object)
		return nil
	})
	billSkipUnported(t, err)
	if bsStr(note, "number") != "INV-202512-0001-CN-01" || bsStr(note, "memo") != "goodwill" || bsStr(note, "reason") != "other" {
		t.Fatalf("credit note: %v", note)
	}
	applied, _ := note.Get("applied").(*core.Object)
	if bsNum(applied, "dueMicros") != 0 || bsNum(applied, "creditMicros") != 25_000_000 || bsNum(applied, "refundMicros") != 0 {
		t.Fatalf("applied: %v", applied)
	}
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := s.service.CreateCreditNote(ctx, tx, settled, obj(t, `{"amount":1000}`), "owner")
		return err
	})
	billExpectCode(t, err, "INVALID_INPUT")
}

func TestBillingStatementTransitionsAreGuarded(t *testing.T) {
	s := newBillScenario(t, nil)
	statement := s.finalizedStatement(10_000_000)
	var written *core.Object
	err := s.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		written, err = s.service.MarkUncollectible(ctx, tx, statement)
		return err
	})
	billSkipUnported(t, err)
	if bsStr(written, "status") != "uncollectible" || bsNum(written, "markedUncollectibleAt") != float64(s.clock.Load()) {
		t.Fatalf("uncollectible: %v", written)
	}
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := s.service.MarkUncollectible(ctx, tx, written)
		return err
	})
	expectError(t, err, "INVALID_TRANSITION", "The invoice is uncollectible")
	draft := statement.Spread(core.NewObject("status", "draft"))
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := s.service.VoidStatement(ctx, tx, draft, principalOf(identity("owner", "org"), nil), "mistake")
		return err
	})
	expectError(t, err, "INVALID_TRANSITION", "Drafts are not voided; finalize the invoice or let the next close refresh it")
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := s.service.FinalizeDraft(ctx, tx, statement, "")
		return err
	})
	expectError(t, err, "INVALID_TRANSITION", "The invoice is finalized")
	// Voiding reopens the period and frees the unique key.
	var voided *core.Object
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		voided, err = s.service.VoidStatement(ctx, tx, statement, principalOf(identity("owner", "org"), nil), "mistake")
		return err
	})
	billSkipUnported(t, err)
	if bsStr(voided, "status") != "void" || bsStr(voided, "uniqueKey") != "void:statement-1" || bsStr(voided, "voidedBy") != "owner" || bsStr(voided, "voidReason") != "mistake" {
		t.Fatalf("voided: %v", voided)
	}
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := s.service.VoidStatement(ctx, tx, voided, principalOf(identity("owner", "org"), nil), "again")
		return err
	})
	expectError(t, err, "INVALID_TRANSITION", "The statement is already void")
}

func TestBillingOwnIdentitiesIncludeSponsoredAgents(t *testing.T) {
	s := newBillScenario(t, nil)
	s.insert("identities",
		identity("agent-1", "org", "kind", "agent", "agent", core.NewObject("sponsorId", "alice")),
		identity("agent-2", "org", "kind", "agent", "agent", core.NewObject("sponsorId", "bob")),
	)
	alice, err := s.store.Get(s.ctx, "identities", "alice")
	if err != nil {
		t.Fatal(err)
	}
	own, err := s.service.OwnIdentities(s.ctx, s.store, alice)
	billSkipUnported(t, err)
	if len(own) != 2 || own[0] != "alice" || own[1] != "agent-1" {
		t.Fatalf("own identities: %v", own)
	}
}

func TestBillingRecordSeatsValidatesKinds(t *testing.T) {
	s := newBillScenario(t, nil)
	_, err := s.service.RecordSeats(s.ctx, obj(t, `{"kinds":["robot"]}`))
	billExpectCode(t, err, "INVALID_INPUT")
	expectError(t, err, "INVALID_INPUT", "kinds must list 'user', 'service' or 'agent'")
	_, err = s.service.RecordSeats(s.ctx, obj(t, `{"kinds":[]}`))
	expectError(t, err, "INVALID_INPUT", "kinds must list 'user', 'service' or 'agent'")
}

func TestBillingClosePeriodRefusesOpenPeriods(t *testing.T) {
	s := newBillScenario(t, nil)
	current, err := s.service.CurrentPeriod()
	billSkipUnported(t, err)
	_, err = s.service.ClosePeriod(s.ctx, core.NewObject("period", current))
	expectError(t, err, "INVALID_INPUT", "Only periods that have ended can be closed")
	_, err = s.service.ClosePeriod(s.ctx, obj(t, `{"draft":"yes"}`))
	expectError(t, err, "INVALID_INPUT", "draft must be a boolean")
}

func TestBillingSubscriptionsResumeOnlyWhenCanceling(t *testing.T) {
	s := newBillScenario(t, nil)
	now := float64(s.clock.Load())
	subscription := core.NewObject("id", "sub-1", "tenantId", "org", "uniqueKey", "plan:plan-1", "planId", "plan-1",
		"planKey", "pro", "planName", "Pro", "startedAt", now, "cancelAtPeriodEnd", false, "seats", 3.0,
		"seatHistory", []any{core.NewObject("at", now, "seats", 3.0)}, "billedAdvance", []any{},
		"createdAt", now, "createdBy", "owner", "updatedAt", now)
	s.insert(BillingCollections.Subscriptions, subscription)
	err := s.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := s.service.ResumeSubscription(ctx, tx, subscription)
		return err
	})
	billExpectCode(t, err, "INVALID_TRANSITION")
	expectError(t, err, "INVALID_TRANSITION", "The subscription is not set to cancel")
	// Same seats: nothing to prorate.
	var updated *core.Object
	err = s.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		updated, err = s.service.UpdateSeats(ctx, tx, subscription, 3, "owner")
		return err
	})
	billSkipUnported(t, err)
	if items, _ := updated.Get("items").([]any); len(items) != 0 {
		t.Fatalf("no proration expected: %v", updated)
	}
}
