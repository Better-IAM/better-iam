package server

// Tests of billing.go, billing_plans.go and billing_invoices.go: the pricing tests of tests/billing.test.ts and
// tests/billing-invoicing.test.ts (the API-level tests there exercise billing-service.ts and api/billing.ts), plus a
// differential test against the TypeScript implementation (testdata/billing.json, written by testdata/billing.mjs).

import (
	"context"
	"math"
	"slices"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

func billJSON(t *testing.T, value any) string {
	t.Helper()
	text, _, err := core.Stringify(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func billSame(t *testing.T, label string, got, want any) {
	t.Helper()
	if a, b := billJSON(t, got), billJSON(t, want); a != b {
		t.Fatalf("%s:\n got  %s\n want %s", label, a, b)
	}
}

// tests/billing.test.ts: "prices per unit, graduated and volume tiers, packages and included units".
func TestBillingPricesPerUnitGraduatedVolumeAndPackages(t *testing.T) {
	graduated := must(PriceSpec(obj(t, `{"model":"graduated","tiers":[{"upTo":100,"unitAmount":1},{"upTo":null,"unitAmount":0.5,"flatAmount":10}]}`)))
	// 100 × $1 + 50 × $0.50 + $10 flat.
	if got := must(PriceQuantity(graduated, 150)); got != 135_000_000 {
		t.Fatalf("graduated: %v", got)
	}
	volume := must(PriceSpec(obj(t, `{"model":"volume","tiers":[{"upTo":100,"unitAmount":1},{"upTo":null,"unitAmount":0.5}]}`)))
	if got := must(PriceQuantity(volume, 150)); got != 75_000_000 {
		t.Fatalf("volume 150: %v", got)
	}
	if got := must(PriceQuantity(volume, 100)); got != 100_000_000 {
		t.Fatalf("volume 100: %v", got)
	}
	packaged := must(PriceSpec(obj(t, `{"model":"package","packageSize":1000,"packageAmount":2}`)))
	if got := must(PriceQuantity(packaged, 1001)); got != 4_000_000 {
		t.Fatalf("package: %v", got)
	}
	included := must(PriceSpec(obj(t, `{"model":"per-unit","unitAmount":0.000002,"includedQuantity":1000000}`)))
	if got := must(PriceQuantity(included, 3_500_000)); got != 5_000_000 {
		t.Fatalf("included: %v", got)
	}
	_, err := PriceSpec(obj(t, `{"model":"graduated","tiers":[{"upTo":5,"unitAmount":1}]}`))
	expectError(t, err, "INVALID_INPUT", "Only the last tier has upTo: null")
}

// tests/billing-invoicing.test.ts: "breaks tiered prices into sub-lines and applies a price minimum and maximum".
func TestBillingBreaksTieredPricesIntoSubLines(t *testing.T) {
	spec := must(PriceSpec(obj(t, `{"model":"graduated","includedQuantity":10,"tiers":[{"upTo":100,"unitAmount":1},{"upTo":null,"unitAmount":0.5,"flatAmount":10}],"minimumAmount":20,"maximumAmount":120}`)))
	// 160 units, 10 free: 100 × $1, then 50 × $0.50 + $10 flat = $135 before the cap.
	billSame(t, "breakdown", must(PriceBreakdown(spec, 160)), obj(t, `{"tiers":[
		{"from":1,"to":100,"quantity":100,"unitAmountMicros":1000000,"amountMicros":100000000},
		{"from":101,"to":null,"quantity":50,"unitAmountMicros":500000,"flatAmountMicros":10000000,"amountMicros":35000000}],
		"includedQuantity":10,"rawMicros":135000000}`))
	if got := must(PriceQuantity(spec, 160)); got != 120_000_000 {
		t.Fatalf("capped: %v", got)
	}
	// Any usage costs at least the minimum; none costs nothing.
	if got := must(PriceQuantity(spec, 15)); got != 20_000_000 {
		t.Fatalf("minimum: %v", got)
	}
	if got := must(PriceQuantity(spec, 0)); got != 0 {
		t.Fatalf("none: %v", got)
	}
	_, err := PriceSpec(obj(t, `{"model":"per-unit","unitAmount":1,"minimumAmount":10,"maximumAmount":5}`))
	expectError(t, err, "INVALID_INPUT", "maximumAmount must not be below minimumAmount")
}

func TestBillingValidatesInputs(t *testing.T) {
	_, err := BillingSettings(obj(t, `{"currency":"usd"}`))
	expectError(t, err, "INVALID_CONFIG", "billing.currency must be an ISO 4217 code such as USD")
	_, err = BillingSettings(obj(t, `{"timeZone":"Mars/Base"}`))
	expectError(t, err, "INVALID_CONFIG", "billing.timeZone must be an IANA time zone")
	_, err = BillingSettings(obj(t, `{"issuer":{"name":" "}}`))
	expectError(t, err, "INVALID_CONFIG", "billing.issuer.name must be text of 1-256 characters")
	_, err = BillingSettings(obj(t, `{"autoFinalize":"yes"}`))
	expectError(t, err, "INVALID_CONFIG", "billing.autoFinalize must be a boolean")
	_, err = BillingSettings(obj(t, `{"paymentReminderDays":[1.5]}`))
	expectError(t, err, "INVALID_CONFIG", "billing.paymentReminderDays must list at most 10 whole days from -60 to 365")
	_, err = BillingSettings(obj(t, `{"statementPrefix":"inv"}`))
	expectError(t, err, "INVALID_CONFIG", "billing.statementPrefix must be 1-16 uppercase letters, digits or hyphens")
	_, err = BillingSettings(obj(t, `{"teamAttribution":"half"}`))
	expectError(t, err, "INVALID_CONFIG", "billing.teamAttribution must be 'split', 'primary' or 'full'")
	from := must(core.ToRecord(BillingOptions{Currency: str("EUR"), Issuer: &InvoiceIssuer{Name: "Better Cloud"}}))
	settings := must(BillingSettings(from))
	if settings.Get("currency") != "EUR" || member(settings.Get("issuer"), "name") != "Better Cloud" {
		t.Fatalf("settings from options: %s", billJSON(t, settings))
	}

	_, err = AmountMicros(-1.0, "unitAmount")
	expectError(t, err, "INVALID_INPUT", "unitAmount must be an amount from 0 to 1000000000")
	_, err = BillingPeriod("2026-13", "")
	expectError(t, err, "INVALID_INPUT", "period must be a month such as 2026-09")
	_, err = MeterKey("API")
	expectError(t, err, "INVALID_INPUT", "meter must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter")
	_, err = UsageTags(obj(t, `{"1x":"a"}`))
	expectError(t, err, "INVALID_INPUT", "Invalid tag name 1x")
	tags := must(UsageTags(obj(t, `{"z":"1","a.b":"2"}`)))
	if billJSON(t, tags) != `{"a.b":"2","z":"1"}` {
		t.Fatalf("tags: %s", billJSON(t, tags))
	}
	if tags, _ := UsageTags(obj(t, `{}`)); tags != nil {
		t.Fatal("empty tags are no tags")
	}
	thresholds := must(BudgetThresholds(parse(t, `["100", 50, " 80 ", 50]`)))
	if !slices.Equal(thresholds, []float64{50, 80, 100}) {
		t.Fatalf("thresholds: %v", thresholds)
	}
	_, err = BudgetThresholds(parse(t, `[0]`))
	expectError(t, err, "INVALID_INPUT", "Invalid thresholds")

	current := obj(t, `{"name":"Calls","unit":"request","aggregation":"sum","pricing":"rate-card","archived":false,"description":"Old"}`)
	updated := must(MeterSettings(obj(t, `{"description":null,"archived":true}`), current))
	if billJSON(t, updated) != `{"name":"Calls","unit":"request","aggregation":"sum","pricing":"rate-card","archived":true}` {
		t.Fatalf("meter settings: %s", billJSON(t, updated))
	}
	_, err = MeterSettings(obj(t, `{"aggregation":"unique"}`), current)
	expectError(t, err, "INVALID_INPUT", "A meter’s aggregation cannot change; create a new meter")
	_, err = MeterSettings(obj(t, `{"name":"Tokens","pricing":"reported","aggregation":"unique"}`), nil)
	expectError(t, err, "INVALID_INPUT", "Reported meters add up their events (aggregation sum)")
	_, err = MeterSettings(obj(t, `{}`), nil)
	expectError(t, err, "INVALID_INPUT", "name is required")

	_, err = PlanKey("Pro")
	expectError(t, err, "INVALID_INPUT", "plan must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter")
	_, err = PlanSettings(obj(t, `{"name":"Pro","items":[{"id":"a","kind":"fee","amount":1},{"id":"a","kind":"fee","amount":2}]}`), nil)
	expectError(t, err, "INVALID_INPUT", "Duplicate item id a")
	_, err = PlanSettings(obj(t, `{"name":"Pro","items":[{"id":"a","kind":"usage","meter":"x","price":{"model":"per-unit","unitAmount":1}},{"id":"b","kind":"usage","meter":"x","price":{"model":"per-unit","unitAmount":1}}]}`), nil)
	expectError(t, err, "INVALID_INPUT", "Two items price x")
	_, err = PlanSettings(obj(t, `{"name":"Pro"}`), nil)
	expectError(t, err, "INVALID_INPUT", "items are required")

	_, err = CouponSettings(obj(t, `{"code":"SAVE10","percentOff":10,"amountOff":5}`), 0)
	expectError(t, err, "INVALID_INPUT", "Give either percentOff or amountOff")
	_, err = CouponSettings(obj(t, `{"code":"SAVE10","percentOff":10,"durationInMonths":3}`), 0)
	expectError(t, err, "INVALID_INPUT", "durationInMonths is only for repeating coupons")
	_, err = CouponCode("ab")
	expectError(t, err, "INVALID_INPUT", "code must be 3-32 letters, digits, - or _")
	if reason := must(CreditNoteReason(core.Undefined)); reason != "other" {
		t.Fatalf("default reason: %s", reason)
	}
	_, err = CreditNoteReason("refund")
	expectError(t, err, "INVALID_INPUT", "reason must be one of duplicate, fraudulent, order_change, product_unsatisfactory, other")
	_, err = InvoiceItemInput(obj(t, `{"description":"x","amount":1,"quantity":0}`))
	expectError(t, err, "INVALID_INPUT", "quantity must be a positive number")
	_, err = InvoiceItemInput(obj(t, `{"description":"x","amount":2e9}`))
	expectError(t, err, "INVALID_INPUT", "amount must be an amount from -1000000000 to 1000000000")
}

func TestBillingMoneyPeriodsAndStatus(t *testing.T) {
	if must(RoundMicros(1.23456789)) != 1.235 || must(RoundCents(1_234_567)) != 1_230_000 || must(UnitsOf(1_235_000)) != 1.24 {
		t.Fatal("rounding")
	}
	if got := must(OverlapShare(0, 30, 10, 40)); got != 0.6667 {
		t.Fatalf("overlap: %v", got)
	}
	if got := must(OverlapShare(10, 10, 0, 40)); got != 0 {
		t.Fatalf("empty overlap: %v", got)
	}
	subscription := obj(t, `{"trialEndsAt":100,"endsAt":200}`)
	for at, want := range map[int64]string{50: "trialing", 150: "active", 200: "ended"} {
		if got := must(SubscriptionStatus(subscription, at)); got != want {
			t.Fatalf("status at %d: %s", at, got)
		}
	}
	redeemed := float64(time.Date(2026, 9, 3, 0, 0, 0, 0, time.UTC).UnixMilli())
	repeating := core.NewObject("duration", "repeating", "durationInMonths", 2.0, "redeemedAt", redeemed, "appliedInvoices", 1.0)
	for period, want := range map[string]bool{"2026-08": false, "2026-09": true, "2026-10": true, "2026-11": false} {
		if got := must(DiscountActive(repeating, period, "UTC")); got != want {
			t.Fatalf("repeating in %s: %v", period, got)
		}
	}
	if must(DiscountActive(obj(t, `{"duration":"once","appliedInvoices":1}`), "2026-09", "UTC")) {
		t.Fatal("a used once coupon is spent")
	}
	if must(DiscountActive(obj(t, `{"duration":"forever","endedAt":1}`), "2026-09", "UTC")) {
		t.Fatal("an ended discount is inactive")
	}
	if got := must(AmountDue(obj(t, `{"status":"finalized","totalMicros":100,"amountPaidMicros":30,"creditNotesMicros":80}`))); got != 0 {
		t.Fatalf("due never below 0: %v", got)
	}
	if got := must(AmountPaid(obj(t, `{"status":"paid","totalMicros":100}`))); got != 100 {
		t.Fatalf("paid: %v", got)
	}
	if got := must(AmountDue(obj(t, `{"status":"draft","totalMicros":70}`))); got != 70 {
		t.Fatalf("draft due: %v", got)
	}
	settings := must(BillingSettings(nil))
	expiry := must(UsageExpiry("2026-09", settings))
	if want := float64(time.Date(2026, 10, 1, 0, 0, 0, 0, time.UTC).UnixMilli()) + 400*86_400_000; expiry != want {
		t.Fatalf("expiry: %v", expiry)
	}
	if quantityText(-0.00004) != "-0" || quantityText(1234567.123456) != "1,234,567.1235" || quantityText(1e-7) != "0" {
		t.Fatal("quantity text")
	}
	if sign, text := localeNumber(-1.005, 2, 2); sign+text != "-1.01" {
		t.Fatalf("locale number: %q", sign+text)
	}
	// Math.round(-100.5) is -100.
	if got := invoiceMoney("XYZ")(-1_005_000); got != "-XYZ\u00a01.00" {
		t.Fatalf("money: %q", got)
	}
	if got := invoiceMoney("USD")(math.Copysign(0, -1)); got != "-$0.00" {
		t.Fatalf("negative zero: %q", got)
	}
	if got := invoiceMoney("US")(1_234_560); got != "US 1.23" {
		t.Fatalf("malformed currency: %q", got)
	}
}

// TestBillingMatchesTypeScript compares the port with the TypeScript implementation over testdata/billing.json.
func TestBillingMatchesTypeScript(t *testing.T) {
	fixture := readFixture(t, "billing.json")
	get := func(key string) any { return fixture.Get(key) }
	object := func(key string) *core.Object { return get(key).(*core.Object) }

	newYork := func(at time.Time) int64 { return at.UnixMilli() }
	billSame(t, "periodOf", []any{
		must(PeriodOf(newYork(time.Date(2026, 3, 1, 3, 0, 0, 0, time.UTC)), "America/New_York")),
		must(PeriodOf(newYork(time.Date(2026, 3, 1, 6, 0, 0, 0, time.UTC)), "America/New_York")),
	}, get("periodOf"))
	billSame(t, "dayOf", must(DayOf(time.Date(2026, 11, 1, 4, 30, 0, 0, time.UTC).UnixMilli(), "Asia/Kolkata")), get("dayOf"))
	billSame(t, "bounds", []any{must(PeriodBounds("2026-03", "America/New_York")), must(PeriodBounds("2026-11", "Europe/London")), must(PeriodBounds("2026-12", "UTC"))}, get("bounds"))
	billSame(t, "shift", []any{must(ShiftPeriod("2026-01", -1)), must(ShiftPeriod("2026-12", 1)), must(ShiftPeriod("2026-05", -17))}, get("shift"))
	billSame(t, "windows", []any{must(WindowPeriods("quarter", "2026-05")), must(WindowPeriods("year", "2026-05")), must(WindowPeriods("month", "2026-05"))}, get("windows"))
	billSame(t, "rollupId", must(RollupID("t1", "2026-09-01", "m1", obj(t, `{"identityId":"i1","teamIds":["a","b"],"tags":{"env":"prod","project":"x"}}`))), get("rollup"))
	billSame(t, "rollupId (bare)", must(RollupID("t1", "2026-09-01", "m1", obj(t, `{"teamIds":[]}`))), get("rollup2"))
	billSame(t, "statementHash", must(StatementHash(object("hashInput"))), get("hash"))

	amountsInput := object("amountsInput")
	amountsInput.SetRaw("credit", func(due float64) float64 { return math.Min(due, 3_000_000) })
	billSame(t, "invoiceAmounts", must(InvoiceAmounts(amountsInput)), get("amounts"))
	billSame(t, "invoiceAmounts (carry forward)", must(InvoiceAmounts(InvoiceAmountsInput{SubtotalMicros: -2_500_000,
		Credit: func(float64) (float64, error) { return 0, nil }})), get("amounts2"))
	billSame(t, "billingSettings", must(BillingSettings(object("settingsInput"))), get("settings"))
	billSame(t, "billingSettings (defaults)", must(BillingSettings(nil)), get("defaultSettings"))

	volume := object("volume")
	spec := must(PriceSpec(object("volumeInput")))
	billSame(t, "priceSpec", spec, volume.Get("spec"))
	billSame(t, "priceBreakdown", must(PriceBreakdown(spec, 30)), volume.Get("breakdown"))
	billSame(t, "priceQuantity", must(PriceQuantity(spec, 30)), volume.Get("quantity"))
	billSame(t, "publicPriceSpec", must(PublicPriceSpec(spec)), volume.Get("public"))

	options := object("invoiceOptions").Spread(core.NewObject("now", float64(time.Date(2026, 11, 7, 0, 0, 0, 0, time.UTC).UnixMilli())))
	if html := must(RenderInvoiceHtml(object("invoice"), options)); html != get("html") {
		t.Fatalf("renderInvoiceHtml:\n got  %s\n want %s", html, get("html"))
	}
	if html := must(RenderInvoiceHtml(object("draft"), obj(t, `{"appName":"Acme IAM"}`))); html != get("htmlDraft") {
		t.Fatalf("renderInvoiceHtml (draft):\n got  %s\n want %s", html, get("htmlDraft"))
	}

	subscription, plan := object("subscription"), object("plan")
	billSame(t, "firstPeriodLines", must(FirstPeriodLines(subscription, plan, "UTC")), get("first"))
	at := float64(time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC).UnixMilli())
	withoutID := func(items []*core.Object) []any {
		out := []any{}
		for _, item := range items {
			copy := item.Spread()
			copy.Delete("id")
			out = append(out, copy)
		}
		return out
	}
	billSame(t, "prorationItems", withoutID(must(ProrationItems(core.NewObject("subscription", subscription, "plan", plan, "at", at,
		"timeZone", "UTC", "seats", obj(t, `{"before":8,"after":4}`), "ending", false, "createdBy", "me")))), get("proration"))
	billSame(t, "prorationItems (ending)", withoutID(must(ProrationItems(core.NewObject("subscription", subscription, "plan", plan, "at", at,
		"timeZone", "UTC", "ending", true, "createdBy", "me")))), get("prorationEnding"))
	billSame(t, "planSettings", must(PlanSettings(object("planInput"), nil)), get("planSettings"))
	billSame(t, "couponSettings", must(CouponSettings(object("couponInput"), 0)), get("coupon"))
	billSame(t, "invoiceItemInput", must(InvoiceItemInput(object("itemInput"))), get("item"))
}

// TestBillingSpendMatchesTypeScript runs the store-backed functions over the fixture's records.
func TestBillingSpendMatchesTypeScript(t *testing.T) {
	fixture := readFixture(t, "billing.json")
	store := fixture.Get("store").(*core.Object)
	k := newKernel(t, nil)
	k.clock.Store(int64(jsNumber(store.Get("now"))))
	records := fixture.Get("records").(*core.Object)
	for _, collection := range records.Keys() {
		k.insert(collection, billObjects(records.Get(collection))...)
	}
	server := k.server
	err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		tenant := func(id string) *core.Object { return must(server.Tenant(ctx, tx, id)) }
		for _, id := range []string{"org", "org2", "proj2", "root"} {
			billSame(t, "accountSpend "+id, must(AccountSpend(ctx, server, tx, tenant(id), "2026-09", nil)), store.Get("accountSpend:"+id))
		}
		cache := map[string]any{}
		for _, id := range []string{"root", "org", "proj"} {
			billSame(t, "scopeSpend "+id, must(ScopeSpend(ctx, server, tx, tenant(id), "2026-09", cache)), store.Get("scopeSpend:"+id))
		}
		if len(cache) != 4 {
			t.Fatalf("cached accounts: %d", len(cache))
		}
		for _, id := range []string{"root", "org", "proj", "proj2"} {
			billSame(t, "accountOf "+id, must(AccountOf(ctx, server, tx, tenant(id))).Get("id"), store.Get("accountOf:"+id))
		}
		for _, id := range []string{"org", "proj", "proj2", "org2"} {
			var terms any = must(AccountTermsOf(ctx, server, tx, tenant(id)))
			if terms.(*core.Object) == nil {
				terms = nil
			}
			billSame(t, "accountTermsOf "+id, terms, store.Get("accountTermsOf:"+id))
		}
		subtree := []string{}
		for _, realm := range must(Subtree(ctx, server, tx, tenant("org"))) {
			subtree = append(subtree, billString(realm, "id"))
		}
		billSame(t, "subtree", subtree, store.Get("subtree:org"))
		for _, period := range []string{"2026-09", "2026-10"} {
			billSame(t, "subscriptionLines "+period, must(SubscriptionLines(ctx, tx, "org", period, "UTC")), store.Get("subscriptionLines:"+period))
		}
		chain := must(server.Ancestry(ctx, tx, tenant("proj")))
		meters := must(MetersFor(ctx, tx, chain))
		keys := make([]string, 0, len(meters))
		for key := range meters {
			keys = append(keys, key)
		}
		slices.Sort(keys)
		byKey := core.NewObject()
		for _, key := range keys {
			byKey.Set(key, meters[key].Get("id"))
		}
		billSame(t, "metersFor", byKey, store.Get("metersFor"))
		billSame(t, "resolveMeter", must(ResolveMeter(ctx, tx, chain, "builds")).Get("id"), store.Get("resolveMeter"))
		m1 := must(tx.Get(ctx, BillingCollections.Meters, "m1"))
		priceID := func(price *core.Object) any {
			if price == nil {
				return nil
			}
			return price.Get("id")
		}
		billSame(t, "priceFor org2", priceID(must(PriceFor(ctx, tx, m1, must(server.Ancestry(ctx, tx, tenant("org2"))), "2026-09"))), store.Get("priceForOrg2"))
		billSame(t, "priceFor proj", priceID(must(PriceFor(ctx, tx, m1, chain, "2026-09"))), store.Get("priceForProj"))
		billSame(t, "priceFor old", priceID(must(PriceFor(ctx, tx, m1, chain, "2025-12"))), store.Get("priceForOld"))
		directory := must(DirectoryFor(ctx, tx, []string{"org", "org"}))
		want := store.Get("directory").(*core.Object)
		billSame(t, "directory teams", stringsOf(directory.Get("teams").(*core.Object).Keys()), want.Get("teams"))
		billSame(t, "directory departments", stringsOf(directory.Get("departments").(*core.Object).Keys()), want.Get("departments"))
		settings := must(BillingSettings(core.NewObject()))
		full := settings.Spread(core.NewObject("teamAttribution", "full"))
		shares := []any{}
		for _, row := range billObjects(store.Get("scopeSpend:org").(*core.Object).Get("rows")) {
			shares = append(shares, []any{
				must(TeamShare(row, "t1", directory, settings, false)),
				must(TeamShare(row, "t1", directory, settings, true)),
				must(TeamShare(row, "t1", directory, full, true)),
				must(InDepartment(row, "d0", directory, false)),
				must(InDepartment(row, "d0", directory, true)),
			})
		}
		billSame(t, "shares", shares, store.Get("shares"))
		attributions := billObjects(store.Get("attributions"))
		for index, input := range billObjects(store.Get("attributionInputs")) {
			result, err := AttributionFor(ctx, server, tx, chain, input, settings)
			want := attributions[index]
			if expected, ok := want.Get("error").(*core.Object); ok {
				expectError(t, err, jsString(expected.Get("code")), jsString(expected.Get("message")))
				continue
			}
			if err != nil {
				t.Fatalf("attributionFor %s: %v", billJSON(t, input), err)
			}
			billSame(t, "attributionFor "+billJSON(t, input), result, want.Get("value"))
		}
		primary := must(AttributionFor(ctx, server, tx, chain, obj(t, `{"identityId":"alice"}`), settings.Spread(core.NewObject("teamAttribution", "primary"))))
		billSame(t, "attributionFor (primary)", primary, store.Get("attributionsPrimary").(*core.Object).Get("value"))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
