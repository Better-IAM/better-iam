package server

// Port of packages/server/src/billing.ts: billing and spend tracking. Meters name what is billed (API calls,
// seat-days, GB-days, AI inference); a rate card prices them; usage events record how much each tenant, person,
// agent, team and department used. Spend is computed per billing account (the nearest tenant with a billing profile,
// else the organization) and period (a calendar month in the billing time zone): each meter's period total is priced
// once with its tiers, then allocated back to the usage that produced it by share of quantity (a blended rate), so
// individual, team, department and project spend always add up to the account's charges. Meters with `pricing:
// 'reported'` carry their cost on each event instead (inference).
//
// Records (meters, prices, rollups, statements, ...) are *core.Object values with the TypeScript member names and
// order. A Directory (directoryFor) is an object {teams, departments} whose members are objects keyed by ID in store
// order. A SpendCache is a map from `{accountId}:{period}` to the account's spend.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"math"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// ---------------------------------------------------------------------------------------------------------------
// Value helpers

// billNumberOf is a number value (Go numbers included) and whether it is one (`typeof value === 'number'`).
func billNumberOf(value any) (float64, bool) {
	number, ok := core.Normalize(value).(float64)
	return number, ok
}

// billFinite is `typeof value === 'number' && Number.isFinite(value)`.
func billFinite(value any) (float64, bool) {
	number, ok := billNumberOf(value)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) {
		return 0, false
	}
	return number, true
}

// billString is a string member ("" when absent or not a string).
func billString(record *core.Object, key string) string {
	if record == nil {
		return ""
	}
	value, _ := record.Get(key).(string)
	return value
}

// billOptString is a string member, or Undefined when it is not a string.
func billOptString(record *core.Object, key string) any {
	if record == nil {
		return core.Undefined
	}
	if value, ok := record.Get(key).(string); ok {
		return value
	}
	return core.Undefined
}

// billNumber is a number member (`record.key` read as a number; NaN when absent).
func billNumber(record *core.Object, key string) float64 {
	if record == nil {
		return math.NaN()
	}
	return jsNumber(record.Get(key))
}

// billNumberOr is `record.key ?? fallback` for a number member.
func billNumberOr(record *core.Object, key string, fallback float64) float64 {
	if record == nil {
		return fallback
	}
	value := record.Get(key)
	if nullish(value) {
		return fallback
	}
	return jsNumber(value)
}

// billHas is `record.key !== undefined`.
func billHas(record *core.Object, key string) bool {
	if record == nil {
		return false
	}
	return !isUndefined(record.Get(key))
}

// billObjects is an array member of objects (non-objects are skipped).
func billObjects(value any) []*core.Object {
	items, _ := value.([]any)
	out := make([]*core.Object, 0, len(items))
	for _, item := range items {
		if record, ok := item.(*core.Object); ok && record != nil {
			out = append(out, record)
		}
	}
	return out
}

// billAnyList turns objects into an array value.
func billAnyList(records []*core.Object) []any {
	out := make([]any, len(records))
	for index, record := range records {
		out[index] = record
	}
	return out
}

// billLess is `a < b` for strings (UTF-16 order).
func billLess(a, b string) bool { return compareUTF16(a, b) < 0 }

// billPad is `String(value).padStart(width, '0')`.
func billPad(value float64, width int) string {
	text := core.NumberString(value)
	for utf16Len(text) < width {
		text = "0" + text
	}
	return text
}

// billSlice is `text.slice(start, end)` (UTF-16 units, clamped).
func billSlice(text string, start, end int) string {
	units := core.ToUTF16(text)
	if start > len(units) {
		start = len(units)
	}
	if end > len(units) {
		end = len(units)
	}
	if end < start {
		return ""
	}
	return core.FromUTF16(units[start:end])
}

// billOrderedTenants is a Map<string, Tenant>: tenants by ID in insertion order.
type billOrderedTenants struct {
	order []string
	byID  map[string]*core.Object
}

func (m *billOrderedTenants) set(tenant *core.Object) {
	id := billString(tenant, "id")
	if m.byID == nil {
		m.byID = map[string]*core.Object{}
	}
	if _, ok := m.byID[id]; !ok {
		m.order = append(m.order, id)
	}
	m.byID[id] = tenant
}

func (m *billOrderedTenants) values() []*core.Object {
	out := make([]*core.Object, len(m.order))
	for index, id := range m.order {
		out[index] = m.byID[id]
	}
	return out
}

// ---------------------------------------------------------------------------------------------------------------
// Collections, terms and settings

// BillingCollections is billing.ts billingCollections.
var BillingCollections = struct {
	Meters        string
	Prices        string
	Usage         string
	Rollups       string
	Budgets       string
	BudgetAlerts  string
	Credits       string
	Profiles      string
	Statements    string
	Terms         string
	InvoiceItems  string
	CreditNotes   string
	Plans         string
	Subscriptions string
	Coupons       string
	Discounts     string
}{"billingMeters", "billingPrices", "billingUsage", "billingRollups", "billingBudgets", "billingBudgetAlerts", "billingCredits", "billingProfiles", "billingStatements", "billingTerms", "billingInvoiceItems", "billingCreditNotes", "billingPlans", "billingSubscriptions", "billingCoupons", "billingDiscounts"}

// TermsOf (billing.ts termsOf): The contract terms of a billing account, if the platform set any.
func TermsOf(ctx context.Context, tx core.IamStore, accountID string) (result *core.Object, err error) {
	found, err := tx.Find(ctx, BillingCollections.Terms, core.NewObject("tenantId", accountID, "uniqueKey", "terms"), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// AccountTermsOf (billing.ts accountTermsOf): The contract terms a billing account's invoices use: its own, else the
// discount and tax of the nearest ancestor with terms, so a sub-account carved out of an organization stays under
// the organization's contract. A minimum commitment is not inherited (each sub-account would owe it again): it stays
// with the account it was set on, which is invoiced for it even in a month without usage.
func AccountTermsOf(ctx context.Context, server *ServerContext, tx core.IamStore, account *core.Object) (result *core.Object, err error) {
	chain, err := server.Ancestry(ctx, tx, account)
	if err != nil {
		return nil, err
	}
	for index, realm := range chain {
		terms, err := TermsOf(ctx, tx, billString(realm, "id"))
		if err != nil {
			return nil, err
		}
		if terms == nil {
			continue
		}
		if index == 0 {
			return terms, nil
		}
		inherited := terms.Spread()
		inherited.Delete("minimumCommitmentMicros")
		return inherited, nil
	}
	return nil, nil
}

var (
	billingCurrencyPattern = regexp.MustCompile(`^[A-Z]{3}$`)
	billingPrefixPattern   = regexp.MustCompile(`^[A-Z0-9][A-Z0-9-]{0,15}$`)
)

// BillingSettings (billing.ts billingSettings): Validates the `billing` option (its model value, nil when absent);
// a bad value fails construction with INVALID_CONFIG.
func BillingSettings(options *core.Object) (result *core.Object, err error) {
	fail := func(message string) error { return invalidConfig("billing." + message) }
	option := func(key string, fallback any) any {
		if options == nil {
			return fallback
		}
		return coalesce(options.Get(key), fallback)
	}
	settings := core.NewObject(
		"currency", option("currency", "USD"),
		"timeZone", option("timeZone", "UTC"),
		"usageRetentionDays", option("usageRetentionDays", 400.0),
		"teamAttribution", option("teamAttribution", "split"),
		"paymentTermsDays", option("paymentTermsDays", 30.0),
		"statementPrefix", option("statementPrefix", "INV"),
		"paymentReminderDays", option("paymentReminderDays", []any{-3.0, 0.0, 7.0, 14.0}),
		"autoFinalize", option("autoFinalize", true),
	)
	if _, ok := settings.Get("autoFinalize").(bool); !ok {
		return nil, fail("autoFinalize must be a boolean")
	}
	if options != nil && !isUndefined(options.Get("issuer")) {
		raw := options.Get("issuer")
		if raw == nil || typeOf(raw) != "object" {
			return nil, fail("issuer must be an object")
		}
		field := func(key string, max int, required bool) error {
			value := member(raw, key)
			if isUndefined(value) && !required {
				return nil
			}
			text, ok := value.(string)
			if !ok || core.JSTrim(text) == "" || utf16Len(text) > max {
				return fail("issuer." + key + " must be text of 1-" + core.NumberString(float64(max)) + " characters")
			}
			return nil
		}
		for _, spec := range []struct {
			key      string
			max      int
			required bool
		}{{"name", 256, true}, {"address", 1024, false}, {"taxId", 64, false}, {"email", 254, false}, {"url", 512, false}, {"paymentInstructions", 2048, false}} {
			if err := field(spec.key, spec.max, spec.required); err != nil {
				return nil, err
			}
		}
		issuer, _ := raw.(*core.Object)
		settings.Set("issuer", issuer.Spread())
	}
	days, isList := settings.Get("paymentReminderDays").([]any)
	valid := isList && len(days) <= 10
	if valid {
		for _, value := range days {
			number, _ := billNumberOf(value)
			if !core.IsSafeInteger(core.Normalize(value)) || number < -60 || number > 365 {
				valid = false
				break
			}
		}
	}
	if !valid {
		return nil, fail("paymentReminderDays must list at most 10 whole days from -60 to 365")
	}
	distinct := []float64{}
	for _, value := range days {
		number, _ := billNumberOf(value)
		if !slices.Contains(distinct, number) {
			distinct = append(distinct, number)
		}
	}
	slices.Sort(distinct)
	sorted := make([]any, len(distinct))
	for index, number := range distinct {
		sorted[index] = number
	}
	settings.Set("paymentReminderDays", sorted)
	if !billingCurrencyPattern.MatchString(jsString(settings.Get("currency"))) {
		return nil, fail("currency must be an ISO 4217 code such as USD")
	}
	if _, err := LoadTimeZone(jsString(settings.Get("timeZone"))); err != nil {
		return nil, fail("timeZone must be an IANA time zone")
	}
	if retention := core.Normalize(settings.Get("usageRetentionDays")); !core.IsSafeInteger(retention) || retention.(float64) < 1 || retention.(float64) > 3650 {
		return nil, fail("usageRetentionDays must be 1-3650")
	}
	switch settings.Get("teamAttribution") {
	case "split", "primary", "full":
	default:
		return nil, fail("teamAttribution must be 'split', 'primary' or 'full'")
	}
	if terms := core.Normalize(settings.Get("paymentTermsDays")); !core.IsSafeInteger(terms) || terms.(float64) < 0 || terms.(float64) > 365 {
		return nil, fail("paymentTermsDays must be 0-365")
	}
	if !billingPrefixPattern.MatchString(jsString(settings.Get("statementPrefix"))) {
		return nil, fail("statementPrefix must be 1-16 uppercase letters, digits or hyphens")
	}
	return settings, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Money and periods

// microsPerUnit is one unit of currency in micros.
const microsPerUnit = 1_000_000

// RoundMicros (billing.ts roundMicros): Rounds micro amounts to a thousandth of a micro (prices per token are
// fractions of a micro).
func RoundMicros(value float64) (result float64, err error) {
	return roundMicros(value), nil
}

func roundMicros(value float64) float64 { return jsMathRound(value*1000) / 1000 }

// RoundCents (billing.ts roundCents): Micros rounded to a whole cent. Invoice amounts (lines, items, discounts, tax)
// are kept in cents so what an invoice shows adds up; spend reports keep fractions of a cent.
func RoundCents(micros float64) (result float64, err error) {
	return roundCents(micros), nil
}

func roundCents(micros float64) float64 { return jsMathRound(micros/10_000) * 10_000 }

// UnitsOf (billing.ts unitsOf): Micros as currency units, rounded to the cent.
func UnitsOf(micros float64) (result float64, err error) {
	return unitsOf(micros), nil
}

func unitsOf(micros float64) float64 { return jsMathRound(micros/10_000) / 100 }

// AmountMicros (billing.ts amountMicros): An amount in currency units (a price or a budget) as micros: finite, 0 to
// one billion units.
func AmountMicros(value any, name string) (result float64, err error) {
	number, ok := billFinite(value)
	if !ok || number < 0 || number > 1e9 {
		return 0, invalidInput(name + " must be an amount from 0 to 1000000000")
	}
	return roundMicros(number * microsPerUnit), nil
}

var billingPeriodPattern = regexp.MustCompile(`^(\d{4})-(0[1-9]|1[0-2])$`)

// BillingPeriod (billing.ts billingPeriod): A billing period `YYYY-MM`. An empty name is the default `period`.
func BillingPeriod(value any, name string) (result string, err error) {
	if name == "" {
		name = "period"
	}
	text, ok := value.(string)
	if !ok || !billingPeriodPattern.MatchString(text) {
		return "", invalidInput(name + " must be a month such as 2026-09")
	}
	return text, nil
}

// billZoneParts are the wall-clock parts of an instant in a time zone (Intl.DateTimeFormat, h23).
type billZoneParts struct {
	year, month, day, hour, minute, second int
}

func zoneParts(at float64, timeZone string) (billZoneParts, error) {
	location, err := LoadTimeZone(timeZone)
	if err != nil {
		return billZoneParts{}, err
	}
	if math.IsNaN(at) || at > 8.64e15 || at < -8.64e15 {
		return billZoneParts{}, &rangeError{"Invalid time value"}
	}
	local := time.UnixMilli(int64(at)).In(location)
	return billZoneParts{local.Year(), int(local.Month()), local.Day(), local.Hour() % 24, local.Minute(), local.Second()}, nil
}

// billDateUTC is Date.UTC(year, monthIndex, day, hours, minutes, seconds).
func billDateUTC(year, monthIndex, day, hours, minutes, seconds int) float64 {
	return float64(time.Date(year, time.Month(monthIndex+1), day, hours, minutes, seconds, 0, time.UTC).UnixMilli())
}

// zoneOffset is local wall-clock time minus UTC at an instant, in milliseconds.
func zoneOffset(at float64, timeZone string) (float64, error) {
	p, err := zoneParts(at, timeZone)
	if err != nil {
		return 0, err
	}
	return billDateUTC(p.year, p.month-1, p.day, p.hour, p.minute, p.second) - math.Floor(at/1000)*1000, nil
}

// localMidnight is the instant of local midnight on a date in a time zone.
func localMidnight(year, month, day int, timeZone string) (float64, error) {
	guess := billDateUTC(year, month-1, day, 0, 0, 0)
	offset, err := zoneOffset(guess, timeZone)
	if err != nil {
		return 0, err
	}
	first := guess - offset
	offset, err = zoneOffset(first, timeZone)
	if err != nil {
		return 0, err
	}
	return guess - offset, nil
}

// PeriodOf (billing.ts periodOf): The billing period an instant falls in.
func PeriodOf(at int64, timeZone string) (result string, err error) {
	return periodOf(float64(at), timeZone)
}

func periodOf(at float64, timeZone string) (string, error) {
	p, err := zoneParts(at, timeZone)
	if err != nil {
		return "", err
	}
	return billPad(float64(p.year), 4) + "-" + billPad(float64(p.month), 2), nil
}

// DayOf (billing.ts dayOf): The local day `YYYY-MM-DD` an instant falls on.
func DayOf(at int64, timeZone string) (result string, err error) {
	return dayOf(float64(at), timeZone)
}

func dayOf(at float64, timeZone string) (string, error) {
	p, err := zoneParts(at, timeZone)
	if err != nil {
		return "", err
	}
	return billPad(float64(p.year), 4) + "-" + billPad(float64(p.month), 2) + "-" + billPad(float64(p.day), 2), nil
}

// ShiftPeriod (billing.ts shiftPeriod): A period `months` after (or before, when negative) another.
func ShiftPeriod(period string, months float64) (result string, err error) {
	return shiftPeriod(period, months), nil
}

func shiftPeriod(period string, months float64) string {
	parts := strings.Split(period, "-")
	year := jsNumber(parts[0])
	month := math.NaN()
	if len(parts) > 1 {
		month = jsNumber(parts[1])
	}
	index := year*12 + (month - 1) + months
	return billPad(math.Floor(index/12), 4) + "-" + billPad(math.Mod(index, 12)+1, 2)
}

// PeriodBounds (billing.ts periodBounds): The first instant of a period and of the next one, as {start, end}.
func PeriodBounds(period string, timeZone string) (result *core.Object, err error) {
	start, end, err := periodBounds(period, timeZone)
	if err != nil {
		return nil, err
	}
	return core.NewObject("start", start, "end", end), nil
}

func periodBounds(period string, timeZone string) (start, end float64, err error) {
	if _, err := BillingPeriod(period, "period"); err != nil {
		return 0, 0, err
	}
	year, month := periodNumbers(period)
	nextYear, nextMonth := periodNumbers(shiftPeriod(period, 1))
	if start, err = localMidnight(year, month, 1, timeZone); err != nil {
		return 0, 0, err
	}
	if end, err = localMidnight(nextYear, nextMonth, 1, timeZone); err != nil {
		return 0, 0, err
	}
	return start, end, nil
}

// periodNumbers is `period.split('-').map(Number)` for a valid period.
func periodNumbers(period string) (int, int) {
	parts := strings.Split(period, "-")
	year := int(jsNumber(parts[0]))
	month := 0
	if len(parts) > 1 {
		month = int(jsNumber(parts[1]))
	}
	return year, month
}

// WindowPeriods (billing.ts windowPeriods): The periods of the budget window containing `period`: the month, its
// calendar quarter, or its year.
func WindowPeriods(kind string, period string) (result []string, err error) {
	month := jsNumber(billSlice(period, 5, 7))
	first := period
	switch kind {
	case "month":
	case "quarter":
		first = shiftPeriod(period, -math.Mod(month-1, 3))
	default:
		first = shiftPeriod(period, -(month - 1))
	}
	length := 12
	switch kind {
	case "month":
		length = 1
	case "quarter":
		length = 3
	}
	result = make([]string, length)
	for index := range result {
		result[index] = shiftPeriod(first, float64(index))
	}
	return result, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Meters and prices

var meterKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)

// MeterKey (billing.ts meterKey): A meter key: 1-64 lowercase letters, digits, `.`, `_` or `-`, starting with a
// letter.
func MeterKey(value any) (result string, err error) {
	text, ok := value.(string)
	if !ok || !meterKeyPattern.MatchString(text) {
		return "", invalidInput("meter must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter")
	}
	return text, nil
}

// MaxMetersPerTenant is billing.ts maxMetersPerTenant: meters per defining tenant.
const MaxMetersPerTenant = 100

// MeterSettings (billing.ts meterSettings): Validated meter settings; `current` supplies values an update leaves
// out.
func MeterSettings(input *core.Object, current *core.Object) (result *core.Object, err error) {
	var name any = core.Undefined
	if raw := input.Get("name"); isUndefined(raw) {
		if current != nil {
			name = current.Get("name")
		}
	} else {
		text, err := Text(raw, "name", 128)
		if err != nil {
			return nil, err
		}
		name = core.JSTrim(text)
	}
	if !truthy(name) {
		return nil, invalidInput("name is required")
	}
	var unit any
	if raw := input.Get("unit"); isUndefined(raw) {
		unit = "unit"
		if current != nil {
			unit = coalesce(current.Get("unit"), "unit")
		}
	} else {
		text, err := Text(raw, "unit", 32)
		if err != nil {
			return nil, err
		}
		unit = core.JSTrim(text)
	}
	currentValue := func(key string) any {
		if current == nil {
			return core.Undefined
		}
		return current.Get(key)
	}
	aggregation := coalesce(coalesce(input.Get("aggregation"), currentValue("aggregation")), "sum")
	if aggregation != "sum" && aggregation != "unique" {
		return nil, invalidInput("aggregation must be 'sum' or 'unique'")
	}
	if current != nil && !isUndefined(input.Get("aggregation")) && !core.StrictEquals(input.Get("aggregation"), current.Get("aggregation")) {
		return nil, invalidInput("A meter’s aggregation cannot change; create a new meter")
	}
	pricing := coalesce(coalesce(input.Get("pricing"), currentValue("pricing")), "rate-card")
	if pricing != "rate-card" && pricing != "reported" {
		return nil, invalidInput("pricing must be 'rate-card' or 'reported'")
	}
	if current != nil && !isUndefined(input.Get("pricing")) && !core.StrictEquals(input.Get("pricing"), current.Get("pricing")) {
		return nil, invalidInput("A meter’s pricing cannot change; create a new meter")
	}
	if pricing == "reported" && aggregation == "unique" {
		return nil, invalidInput("Reported meters add up their events (aggregation sum)")
	}
	archived := coalesce(coalesce(input.Get("archived"), currentValue("archived")), false)
	if _, ok := archived.(bool); !ok {
		return nil, invalidInput("archived must be a boolean")
	}
	var description any = core.Undefined
	switch raw := input.Get("description"); {
	case raw == nil:
	case isUndefined(raw):
		description = currentValue("description")
	default:
		text, err := Text(raw, "description", 512)
		if err != nil {
			return nil, err
		}
		description = core.JSTrim(text)
	}
	result = core.NewObject("name", name, "unit", unit, "aggregation", aggregation, "pricing", pricing, "archived", archived)
	if !isUndefined(description) {
		result.Set("description", description)
	}
	return result, nil
}

func quantityLimit(value any, name string) (float64, error) {
	number, ok := billFinite(value)
	if !ok || number <= 0 || number > 1e15 {
		return 0, invalidInput(name + " must be a positive number")
	}
	return number, nil
}

// PriceSpec (billing.ts priceSpec): Validates a price given in currency units (`unitAmount`, `tiers[].unitAmount` /
// `flatAmount`, `packageAmount`) and returns it in micros. Tiers ascend by `upTo`, and the last one has `upTo:
// null`.
func PriceSpec(value any) (result *core.Object, err error) {
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	model := input.Get("model")
	if model != "per-unit" && model != "graduated" && model != "volume" && model != "package" {
		return nil, invalidInput("model must be 'per-unit', 'graduated', 'volume' or 'package'")
	}
	spec := core.NewObject("model", model)
	if included := input.Get("includedQuantity"); !isUndefined(included) && !core.StrictEquals(included, 0.0) {
		quantity, err := quantityLimit(included, "includedQuantity")
		if err != nil {
			return nil, err
		}
		spec.Set("includedQuantity", quantity)
	}
	switch model {
	case "per-unit":
		amount, err := AmountMicros(input.Get("unitAmount"), "unitAmount")
		if err != nil {
			return nil, err
		}
		spec.Set("unitAmountMicros", amount)
	case "package":
		size, err := quantityLimit(input.Get("packageSize"), "packageSize")
		if err != nil {
			return nil, err
		}
		spec.Set("packageSize", size)
		amount, err := AmountMicros(input.Get("packageAmount"), "packageAmount")
		if err != nil {
			return nil, err
		}
		spec.Set("packageAmountMicros", amount)
	default:
		tiers, ok := input.Get("tiers").([]any)
		if !ok || len(tiers) == 0 || len(tiers) > 20 {
			return nil, invalidInput("tiers must list 1-20 tiers")
		}
		previous := 0.0
		out := make([]any, len(tiers))
		for index, raw := range tiers {
			tier, err := Object(raw)
			if err != nil {
				return nil, err
			}
			last := index == len(tiers)-1
			upToRaw := tier.Get("upTo")
			if (last && upToRaw != nil) || (!last && upToRaw == nil) {
				return nil, invalidInput("Only the last tier has upTo: null")
			}
			var upTo any
			if upToRaw != nil {
				limit, err := quantityLimit(upToRaw, "tiers.upTo")
				if err != nil {
					return nil, err
				}
				if limit <= previous {
					return nil, invalidInput("Tier upTo values must ascend")
				}
				previous = limit
				upTo = limit
			}
			unitAmount, err := AmountMicros(coalesce(tier.Get("unitAmount"), 0.0), "tiers.unitAmount")
			if err != nil {
				return nil, err
			}
			line := core.NewObject("upTo", upTo, "unitAmountMicros", unitAmount)
			if flat := tier.Get("flatAmount"); !isUndefined(flat) && !core.StrictEquals(flat, 0.0) {
				amount, err := AmountMicros(flat, "tiers.flatAmount")
				if err != nil {
					return nil, err
				}
				line.Set("flatAmountMicros", amount)
			}
			out[index] = line
		}
		spec.Set("tiers", out)
	}
	if minimum := input.Get("minimumAmount"); !nullish(minimum) {
		amount, err := AmountMicros(minimum, "minimumAmount")
		if err != nil {
			return nil, err
		}
		spec.Set("minimumAmountMicros", amount)
	}
	if maximum := input.Get("maximumAmount"); !nullish(maximum) {
		amount, err := AmountMicros(maximum, "maximumAmount")
		if err != nil {
			return nil, err
		}
		spec.Set("maximumAmountMicros", amount)
	}
	if billHas(spec, "minimumAmountMicros") && billHas(spec, "maximumAmountMicros") &&
		billNumber(spec, "maximumAmountMicros") < billNumber(spec, "minimumAmountMicros") {
		return nil, invalidInput("maximumAmount must not be below minimumAmount")
	}
	return spec, nil
}

// PriceQuantity (billing.ts priceQuantity): The amount, in micros, a period's quantity costs under a price: its
// tiers, then its minimum and maximum.
func PriceQuantity(spec *core.Object, quantity float64) (result float64, err error) {
	return priceQuantity(spec, quantity), nil
}

func priceQuantity(spec *core.Object, quantity float64) float64 {
	raw := tieredAmount(spec, quantity)
	if quantity <= 0 {
		return raw
	}
	amount := raw
	if billHas(spec, "minimumAmountMicros") {
		amount = billMax(amount, billNumber(spec, "minimumAmountMicros"))
	}
	if billHas(spec, "maximumAmountMicros") {
		amount = billMin(amount, billNumber(spec, "maximumAmountMicros"))
	}
	return roundMicros(amount)
}

// billMax is Math.max of two numbers (NaN wins).
func billMax(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Max(a, b)
}

// billMin is Math.min of two numbers (NaN wins).
func billMin(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Min(a, b)
}

// billTierUpper is `tier.upTo ?? Infinity`.
func billTierUpper(tier *core.Object) float64 {
	if upTo := tier.Get("upTo"); !nullish(upTo) {
		return jsNumber(upTo)
	}
	return math.Inf(1)
}

// PriceBreakdown (billing.ts priceBreakdown): How a quantity is priced, tier by tier, for invoice sub-lines: the
// tiers used, the free units, and what the tiers came to before the price's minimum or maximum.
func PriceBreakdown(spec *core.Object, quantity float64) (result *core.Object, err error) {
	included := billMin(quantity, billNumberOr(spec, "includedQuantity", 0))
	units := billMax(0, quantity-included)
	tiers := []any{}
	model := spec.Get("model")
	if units > 0 && (model == "graduated" || model == "volume") {
		lower := 0.0
		for _, tier := range billObjects(spec.Get("tiers")) {
			upper := billTierUpper(tier)
			unitAmount := billNumber(tier, "unitAmountMicros")
			flat := billNumberOr(tier, "flatAmountMicros", 0)
			upTo := tier.Get("upTo")
			if model == "volume" {
				if upTo != nil && units > jsNumber(upTo) {
					lower = upper
					continue
				}
				line := core.NewObject("from", lower+1, "to", upTo, "quantity", units, "unitAmountMicros", unitAmount)
				if billHas(tier, "flatAmountMicros") {
					line.Set("flatAmountMicros", tier.Get("flatAmountMicros"))
				}
				line.Set("amountMicros", roundMicros(units*unitAmount+flat))
				tiers = append(tiers, line)
				break
			}
			inTier := billMin(units, upper) - lower
			if inTier <= 0 {
				break
			}
			line := core.NewObject("from", lower+1, "to", upTo, "quantity", jsMathRound(inTier*1e6)/1e6, "unitAmountMicros", unitAmount)
			if billHas(tier, "flatAmountMicros") {
				line.Set("flatAmountMicros", tier.Get("flatAmountMicros"))
			}
			line.Set("amountMicros", roundMicros(inTier*unitAmount+flat))
			tiers = append(tiers, line)
			lower = upper
		}
	}
	result = core.NewObject("tiers", tiers)
	if included > 0 {
		result.Set("includedQuantity", included)
	}
	result.Set("rawMicros", tieredAmount(spec, quantity))
	return result, nil
}

// tieredAmount is a quantity's amount under a price's tiers and free units, before its minimum and maximum.
func tieredAmount(spec *core.Object, quantity float64) float64 {
	units := billMax(0, quantity-billNumberOr(spec, "includedQuantity", 0))
	if units == 0 {
		return 0
	}
	switch spec.Get("model") {
	case "per-unit":
		return roundMicros(units * billNumberOr(spec, "unitAmountMicros", 0))
	case "package":
		return roundMicros(math.Ceil(units/billNumberOr(spec, "packageSize", 1)) * billNumberOr(spec, "packageAmountMicros", 0))
	case "volume":
		tiers := billObjects(spec.Get("tiers"))
		var chosen *core.Object
		for _, candidate := range tiers {
			if upTo := candidate.Get("upTo"); upTo == nil || units <= jsNumber(upTo) {
				chosen = candidate
				break
			}
		}
		if chosen == nil {
			chosen = tiers[len(tiers)-1]
		}
		return roundMicros(units*billNumber(chosen, "unitAmountMicros") + billNumberOr(chosen, "flatAmountMicros", 0))
	case "graduated":
		total := 0.0
		lower := 0.0
		for _, tier := range billObjects(spec.Get("tiers")) {
			upper := billTierUpper(tier)
			inTier := billMin(units, upper) - lower
			if inTier <= 0 {
				break
			}
			total += inTier*billNumber(tier, "unitAmountMicros") + billNumberOr(tier, "flatAmountMicros", 0)
			lower = upper
		}
		return roundMicros(total)
	}
	// An unknown model has no amount (undefined in TypeScript).
	return math.NaN()
}

// PublicPriceSpec (billing.ts publicPriceSpec): A price in currency units, as the API shows it.
func PublicPriceSpec(spec *core.Object) (result *core.Object, err error) {
	units := func(micros any) float64 { return jsNumber(micros) / microsPerUnit }
	result = core.NewObject("model", spec.Get("model"))
	if billHas(spec, "unitAmountMicros") {
		result.Set("unitAmount", units(spec.Get("unitAmountMicros")))
	}
	if tiers, ok := spec.Get("tiers").([]any); ok {
		out := make([]any, 0, len(tiers))
		for _, tier := range billObjects(tiers) {
			line := core.NewObject("upTo", tier.Get("upTo"), "unitAmount", units(tier.Get("unitAmountMicros")))
			if billHas(tier, "flatAmountMicros") {
				line.Set("flatAmount", units(tier.Get("flatAmountMicros")))
			}
			out = append(out, line)
		}
		result.Set("tiers", out)
	}
	if billHas(spec, "packageSize") {
		result.Set("packageSize", spec.Get("packageSize"))
	}
	if billHas(spec, "packageAmountMicros") {
		result.Set("packageAmount", units(spec.Get("packageAmountMicros")))
	}
	if billHas(spec, "includedQuantity") {
		result.Set("includedQuantity", spec.Get("includedQuantity"))
	}
	if billHas(spec, "minimumAmountMicros") {
		result.Set("minimumAmount", units(spec.Get("minimumAmountMicros")))
	}
	if billHas(spec, "maximumAmountMicros") {
		result.Set("maximumAmount", units(spec.Get("maximumAmountMicros")))
	}
	return result, nil
}

// ResolveMeter (billing.ts resolveMeter): The meter a key names for a tenant: the one its ancestor nearest the root
// defines.
func ResolveMeter(ctx context.Context, tx core.IamStore, chain []*core.Object, key string) (result *core.Object, err error) {
	for index := len(chain) - 1; index >= 0; index-- {
		found, err := tx.Find(ctx, BillingCollections.Meters, core.NewObject("tenantId", billString(chain[index], "id"), "uniqueKey", key), nil)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			return found[0], nil
		}
	}
	return nil, nil
}

// MetersFor (billing.ts metersFor): Every meter that reaches a tenant, keyed by key (ancestors nearest the root win
// a shared key).
func MetersFor(ctx context.Context, tx core.IamStore, chain []*core.Object) (result map[string]*core.Object, err error) {
	meters := map[string]*core.Object{}
	for index := len(chain) - 1; index >= 0; index-- {
		found, err := tx.Find(ctx, BillingCollections.Meters, core.NewObject("tenantId", billString(chain[index], "id")), nil)
		if err != nil {
			return nil, err
		}
		for _, meter := range found {
			key := billString(meter, "key")
			if _, ok := meters[key]; !ok {
				meters[key] = meter
			}
		}
	}
	return meters, nil
}

// PriceFor (billing.ts priceFor): The price of a meter for a tenant in a period: walking from `chain[0]` up to the
// meter's defining tenant, the first tenant with an entry effective by then (the latest such entry).
func PriceFor(ctx context.Context, tx core.IamStore, meter *core.Object, chain []*core.Object, period string) (result *core.Object, err error) {
	for _, realm := range chain {
		found, err := tx.Find(ctx, BillingCollections.Prices, core.NewObject("tenantId", billString(realm, "id"), "meterId", billString(meter, "id")), nil)
		if err != nil {
			return nil, err
		}
		entries := []*core.Object{}
		for _, entry := range found {
			if compareUTF16(billString(entry, "effectiveFrom"), period) <= 0 {
				entries = append(entries, entry)
			}
		}
		slices.SortStableFunc(entries, func(a, b *core.Object) int {
			if billLess(billString(a, "effectiveFrom"), billString(b, "effectiveFrom")) {
				return 1
			}
			if billString(a, "effectiveFrom") == billString(b, "effectiveFrom") {
				return 0
			}
			return -1
		})
		if len(entries) > 0 {
			return entries[0], nil
		}
		if billString(realm, "id") == billString(meter, "tenantId") {
			break
		}
	}
	return nil, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Usage

var tagKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.:-]{0,63}$`)

// UsageTags (billing.ts usageTags): Validated tags: at most 10, keys like `project` or `env.name`, values up to 128
// characters. Nil means no tags (undefined).
func UsageTags(value any) (result *core.Object, err error) {
	if isUndefined(value) {
		return nil, nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	keys := input.Keys()
	if len(keys) > 10 {
		return nil, invalidInput("tags may hold at most 10 entries")
	}
	if len(keys) == 0 {
		return nil, nil
	}
	sorted := append([]string(nil), keys...)
	slices.SortStableFunc(sorted, func(a, b string) int {
		if billLess(a, b) {
			return -1
		}
		return 1
	})
	tags := core.NewObject()
	for _, key := range sorted {
		if !tagKeyPattern.MatchString(key) {
			return nil, invalidInput("Invalid tag name " + key)
		}
		text, err := Text(input.Get(key), "tags."+key, 128)
		if err != nil {
			return nil, err
		}
		tags.Set(key, text)
	}
	return tags, nil
}

// RollupID (billing.ts rollupId): Deterministic id of the daily bucket for a usage attribution.
func RollupID(tenantID string, day string, meterID string, attribution *core.Object) (result string, err error) {
	orNull := func(key string) any {
		value := attribution.Get(key)
		if isUndefined(value) {
			return nil
		}
		return value
	}
	teamIDs := attribution.Get("teamIds")
	if isUndefined(teamIDs) {
		teamIDs = nil
	}
	text, _, err := core.Stringify([]any{tenantID, day, meterID, orNull("identityId"), orNull("agentId"), teamIDs, orNull("departmentId"), orNull("tags")})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(text))
	return "r_" + base64url(sum[:])[:32], nil
}

// AttributionFor (billing.ts attributionFor): Resolves attribution for an identity recording or causing usage in
// `tenant`. The identity must belong to the tenant or one of its ancestors and not be deleted. An agent's usage is
// attributed to the agent and to its sponsor's teams and department; `teamId` (a team of the identity's tenant)
// replaces the person's own teams. Input: `{ identityId?, agentId?, teamId? }`.
func AttributionFor(ctx context.Context, server *ServerContext, tx core.IamStore, chain []*core.Object, input *core.Object, settings *core.Object) (result *core.Object, err error) {
	result = core.NewObject("teamIds", []any{})
	inChain := func(tenantID any) bool {
		for _, realm := range chain {
			if core.StrictEquals(realm.Get("id"), tenantID) {
				return true
			}
		}
		return false
	}
	if isUndefined(input.Get("identityId")) {
		if !isUndefined(input.Get("teamId")) {
			teamID, err := teamIn(ctx, tx, chain, input.Get("teamId"))
			if err != nil {
				return nil, err
			}
			result.Set("teamIds", []any{teamID})
		}
		return result, nil
	}
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return nil, err
	}
	identity, err := tx.Get(ctx, "identities", identityID)
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.Get("status") == "deleted" || !inChain(identity.Get("tenantId")) {
		return nil, core.NewIamError("NOT_FOUND", "Identity not found", 404)
	}
	result.Set("identityId", identity.Get("id"))
	if !isUndefined(input.Get("agentId")) {
		agentID, err := Text(input.Get("agentId"), "agentId")
		if err != nil {
			return nil, err
		}
		result.Set("agentId", agentID)
	} else if identity.Get("kind") == "agent" {
		result.Set("agentId", identity.Get("id"))
	}
	// Agents count toward the person answerable for them.
	person := billString(identity, "id")
	if identity.Get("kind") == "agent" {
		if sponsor := member(identity.Get("agent"), "sponsorId"); truthy(sponsor) {
			person = jsString(sponsor)
		}
	}
	at := server.Now()
	tenantID := billString(identity, "tenantId")
	if !isUndefined(input.Get("teamId")) {
		teamID, err := teamIn(ctx, tx, chain, input.Get("teamId"))
		if err != nil {
			return nil, err
		}
		result.Set("teamIds", []any{teamID})
	} else {
		teams, err := TeamsOf(ctx, tx, tenantID, person, core.NewObject("at", float64(at)))
		if err != nil {
			return nil, err
		}
		if settings.Get("teamAttribution") == "primary" && len(teams) > 1 {
			teams = teams[:1]
		}
		result.Set("teamIds", stringsOf(teams))
	}
	departmentID, err := DepartmentOf(ctx, tx, tenantID, person)
	if err != nil {
		return nil, err
	}
	teamIDs, _ := result.Get("teamIds").([]any)
	if departmentID == "" && len(teamIDs) > 0 && truthy(teamIDs[0]) {
		team, err := tx.Get(ctx, TeamCollections.Teams, jsString(teamIDs[0]))
		if err != nil {
			return nil, err
		}
		if team != nil {
			departmentID, _ = team.Get("departmentId").(string)
		}
	}
	if departmentID != "" {
		result.Set("departmentId", departmentID)
	}
	return result, nil
}

func teamIn(ctx context.Context, tx core.IamStore, chain []*core.Object, teamID any) (string, error) {
	id, err := Text(teamID, "teamId")
	if err != nil {
		return "", err
	}
	team, err := tx.Get(ctx, TeamCollections.Teams, id)
	if err != nil {
		return "", err
	}
	found := false
	if team != nil {
		for _, realm := range chain {
			if core.StrictEquals(realm.Get("id"), team.Get("tenantId")) {
				found = true
				break
			}
		}
	}
	if !found {
		return "", core.NewIamError("NOT_FOUND", "Team not found", 404)
	}
	return billString(team, "id"), nil
}

// ---------------------------------------------------------------------------------------------------------------
// Billing accounts and profiles

// ProfileOf (billing.ts profileOf): the billing profile of a tenant, if it has one.
func ProfileOf(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	found, err := tx.Find(ctx, BillingCollections.Profiles, core.NewObject("tenantId", tenantID, "uniqueKey", "profile"), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// AccountOf (billing.ts accountOf): The billing account of a tenant: the nearest tenant (itself or above) with a
// profile, else its organization.
func AccountOf(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object) (result *core.Object, err error) {
	chain, err := server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return nil, err
	}
	for index := 0; index < len(chain)-1; index++ {
		profile, err := ProfileOf(ctx, tx, billString(chain[index], "id"))
		if err != nil {
			return nil, err
		}
		if profile != nil {
			return chain[index], nil
		}
	}
	// The organization directly below the root (the root pays for itself).
	if len(chain) > 1 {
		return chain[len(chain)-2], nil
	}
	if len(chain) == 0 {
		return nil, nil
	}
	return chain[0], nil
}

func tenantChildren(ctx context.Context, tx core.IamStore, parentID string) ([]*core.Object, error) {
	found, err := tx.Find(ctx, "tenants", core.NewObject("parentId", parentID), nil)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(found, func(a, b *core.Object) int {
		if billLess(billString(a, "id"), billString(b, "id")) {
			return -1
		}
		return 1
	})
	return found, nil
}

// Subtree (billing.ts subtree): A tenant and every tenant below it.
func Subtree(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object) (result []*core.Object, err error) {
	result = []*core.Object{}
	seen := map[string]bool{}
	queue := []*core.Object{tenant}
	for len(queue) > 0 && len(result) < 100_000 {
		next := queue[0]
		queue = queue[1:]
		id := billString(next, "id")
		if seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, next)
		children, err := tenantChildren(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		queue = append(queue, children...)
	}
	return result, nil
}

// accountTenants is billing.ts accountTenants: the tenants an account pays for: its subtree, minus subtrees of
// tenants that have a profile of their own.
func accountTenants(ctx context.Context, tx core.IamStore, account *core.Object, isRoot bool) ([]*core.Object, error) {
	result := []*core.Object{}
	seen := map[string]bool{}
	queue := []*core.Object{account}
	accountID := billString(account, "id")
	for len(queue) > 0 && len(result) < 100_000 {
		next := queue[0]
		queue = queue[1:]
		id := billString(next, "id")
		if seen[id] {
			continue
		}
		seen[id] = true
		result = append(result, next)
		children, err := tenantChildren(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		for _, child := range children {
			// Below the root every organization is an account of its own.
			if isRoot && id == accountID {
				continue
			}
			profile, err := ProfileOf(ctx, tx, billString(child, "id"))
			if err != nil {
				return nil, err
			}
			if profile != nil {
				continue
			}
			queue = append(queue, child)
		}
	}
	return result, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Spend

// planPricesFor is billing.ts planPricesFor: the prices an account's subscriptions give a meter in a period, oldest
// subscription first: for each subscription whose plan has a usage item for the meter, the days of the period it was
// live on ({spec, planKey, from, to}). A day's usage takes the first window that covers it; usage on days no
// subscription covers (before it started, after it ended) keeps rate-card prices.
func planPricesFor(ctx context.Context, server *ServerContext, tx core.IamStore, accountID string, meter string, period string) ([]*core.Object, error) {
	subscriptions, err := tx.Find(ctx, BillingCollections.Subscriptions, core.NewObject("tenantId", accountID), nil)
	if err != nil {
		return nil, err
	}
	if len(subscriptions) == 0 {
		return []*core.Object{}, nil
	}
	timeZone := billingTimeZone(server)
	start, end, err := periodBounds(period, timeZone)
	if err != nil {
		return nil, err
	}
	windows := []*core.Object{}
	slices.SortStableFunc(subscriptions, bySubscriptionStart)
	for _, subscription := range subscriptions {
		from := billMax(start, billNumber(subscription, "startedAt"))
		to := billMin(end, billNumberOr(subscription, "endsAt", math.Inf(1)))
		if to <= from {
			continue
		}
		plan, err := tx.Get(ctx, BillingCollections.Plans, billString(subscription, "planId"))
		if err != nil {
			return nil, err
		}
		var item *core.Object
		if plan != nil {
			for _, candidate := range billObjects(plan.Get("items")) {
				if candidate.Get("kind") == "usage" && candidate.Get("meter") == meter {
					item = candidate
					break
				}
			}
		}
		if item == nil {
			continue
		}
		spec, ok := item.Get("price").(*core.Object)
		if !ok || spec == nil {
			continue
		}
		fromDay, err := dayOf(from, timeZone)
		if err != nil {
			return nil, err
		}
		toDay, err := dayOf(to-1, timeZone)
		if err != nil {
			return nil, err
		}
		windows = append(windows, core.NewObject("spec", spec, "planKey", plan.Get("key"), "from", fromDay, "to", toDay))
	}
	return windows, nil
}

// bySubscriptionStart orders subscriptions oldest first (`a.startedAt - b.startedAt || (a.id < b.id ? -1 : 1)`).
func bySubscriptionStart(a, b *core.Object) int {
	if difference := billNumber(a, "startedAt") - billNumber(b, "startedAt"); difference != 0 && !math.IsNaN(difference) {
		if difference < 0 {
			return -1
		}
		return 1
	}
	if billLess(billString(a, "id"), billString(b, "id")) {
		return -1
	}
	return 1
}

// billingTimeZone is `ctx.options.billing?.timeZone ?? 'UTC'`.
func billingTimeZone(server *ServerContext) string {
	if server != nil && server.Options != nil && server.Options.Billing != nil && server.Options.Billing.TimeZone != nil {
		return *server.Options.Billing.TimeZone
	}
	return "UTC"
}

// AccountSpend (billing.ts accountSpend): Prices every meter used in an account's tenants during a period and
// allocates the cost to the usage. The result is {accountId, period, charges, rows, totalMicros, billableMicros};
// `cache` (nil for none) keeps results by `{accountId}:{period}` within one call.
func AccountSpend(ctx context.Context, server *ServerContext, tx core.IamStore, account *core.Object, period string, cache map[string]any) (result *core.Object, err error) {
	key := billString(account, "id") + ":" + period
	if cache != nil {
		if cached, ok := cache[key].(*core.Object); ok && cached != nil {
			return cached, nil
		}
	}
	computed, err := computeAccountSpend(ctx, server, tx, account, period)
	if err != nil {
		return nil, err
	}
	if cache != nil {
		cache[key] = computed
	}
	return computed, nil
}

// billPrincipalOf is `row.agentId ?? row.identityId`.
func billPrincipalOf(row *core.Object) (string, bool) {
	if value := row.Get("agentId"); !nullish(value) {
		return jsString(value), true
	}
	if value := row.Get("identityId"); !nullish(value) {
		return jsString(value), true
	}
	return "", false
}

func computeAccountSpend(ctx context.Context, server *ServerContext, tx core.IamStore, account *core.Object, period string) (*core.Object, error) {
	accountChain, err := server.Ancestry(ctx, tx, account)
	if err != nil {
		return nil, err
	}
	accountID := billString(account, "id")
	isRoot := account.Get("parentId") == nil
	tenants, err := accountTenants(ctx, tx, account, isRoot)
	if err != nil {
		return nil, err
	}
	byMeter := map[string][]*core.Object{}
	meterOrder := []string{}
	for _, realm := range tenants {
		rollups, err := tx.Find(ctx, BillingCollections.Rollups, core.NewObject("tenantId", billString(realm, "id"), "period", period), nil)
		if err != nil {
			return nil, err
		}
		for _, rollup := range rollups {
			meterID := billString(rollup, "meterId")
			if _, ok := byMeter[meterID]; !ok {
				meterOrder = append(meterOrder, meterID)
			}
			byMeter[meterID] = append(byMeter[meterID], rollup)
		}
	}
	slices.SortStableFunc(meterOrder, func(a, b string) int {
		if billLess(a, b) {
			return -1
		}
		return 1
	})
	charges := []*core.Object{}
	rows := []*core.Object{}
	for _, meterID := range meterOrder {
		rollups := byMeter[meterID]
		meter, err := tx.Get(ctx, BillingCollections.Meters, meterID)
		if err != nil {
			return nil, err
		}
		first := rollups[0]
		definedAbove := false
		if meter != nil {
			for _, realm := range accountChain[1:] {
				if core.StrictEquals(realm.Get("id"), meter.Get("tenantId")) {
					definedAbove = true
					break
				}
			}
		}
		internal := !definedAbove && !isRoot
		meterOr := func(key string, fallback any) any {
			if meter == nil {
				return fallback
			}
			return coalesce(meter.Get(key), fallback)
		}
		charge := core.NewObject(
			"meterId", meterID,
			"meter", meterOr("key", first.Get("meter")),
			"name", meterOr("name", first.Get("meter")),
			"unit", meterOr("unit", "unit"),
			"definedBy", meterOr("tenantId", ""),
			"internal", internal,
			"aggregation", meterOr("aggregation", "sum"),
			"pricing", meterOr("pricing", "reported"),
			"quantity", 0.0,
			"amountMicros", 0.0,
		)
		charged := make([]*core.Object, len(rollups))
		for index, rollup := range rollups {
			row := core.NewObject("tenantId", rollup.Get("tenantId"), "period", period, "day", rollup.Get("day"), "meterId", meterID, "meter", charge.Get("meter"))
			for _, key := range []string{"identityId", "agentId"} {
				if billHas(rollup, key) {
					row.Set(key, rollup.Get(key))
				}
			}
			row.Set("teamIds", coalesce(rollup.Get("teamIds"), []any{}))
			for _, key := range []string{"departmentId", "tags"} {
				if billHas(rollup, key) {
					row.Set(key, rollup.Get(key))
				}
			}
			row.Set("quantity", rollup.Get("quantity"))
			row.Set("costMicros", 0.0)
			row.Set("events", rollup.Get("events"))
			row.Set("internal", internal)
			charged[index] = row
		}
		quantityOf := func(list []*core.Object) float64 {
			if charge.Get("aggregation") == "unique" {
				seen := map[string]bool{}
				for _, row := range list {
					if principal, ok := billPrincipalOf(row); ok && principal != "" {
						seen[principal] = true
					}
				}
				return float64(len(seen))
			}
			sum := 0.0
			for _, row := range list {
				sum += jsNumber(row.Get("quantity"))
			}
			return sum
		}
		if charge.Get("pricing") == "reported" || meter == nil {
			charge.Set("quantity", quantityOf(charged))
			sum := 0.0
			for index, row := range charged {
				cost := roundMicros(billNumber(rollups[index], "costMicros"))
				row.Set("costMicros", cost)
				sum += cost
			}
			charge.Set("amountMicros", roundMicros(sum))
			charges = append(charges, charge)
		} else {
			// Tiers apply to the account's period total; the meter's own tenant prices meters defined inside the account.
			priceChain := accountChain
			if !definedAbove {
				owner, err := tx.Get(ctx, "tenants", billString(meter, "tenantId"))
				if err != nil {
					return nil, err
				}
				if owner == nil {
					owner = account
				}
				if priceChain, err = server.Ancestry(ctx, tx, owner); err != nil {
					return nil, err
				}
			}
			// A subscription's plan price replaces the rate card for platform meters, for the days it was live only.
			windows := []*core.Object{}
			if definedAbove {
				if windows, err = planPricesFor(ctx, server, tx, accountID, billString(meter, "key"), period); err != nil {
					return nil, err
				}
			}
			// Each row's price: the first plan window covering its day, or the rate card (-1). A `unique` meter counts a
			// person once, at the price of the first window they have usage in.
			groupOf := make([]int, len(charged))
			for index, row := range charged {
				groupOf[index] = -1
				day := billString(row, "day")
				for at, window := range windows {
					if compareUTF16(day, billString(window, "from")) >= 0 && compareUTF16(day, billString(window, "to")) <= 0 {
						groupOf[index] = at
						break
					}
				}
			}
			if charge.Get("aggregation") == "unique" {
				earliest := map[string]int{}
				for index, row := range charged {
					principal, ok := billPrincipalOf(row)
					group := groupOf[index]
					known, isKnown := earliest[principal]
					if ok && principal != "" && group >= 0 && (!isKnown || group < known) {
						earliest[principal] = group
					}
				}
				for index, row := range charged {
					if principal, ok := billPrincipalOf(row); ok && principal != "" {
						if group, known := earliest[principal]; known {
							groupOf[index] = group
						} else {
							groupOf[index] = -1
						}
					}
				}
			}
			groups := []int{}
			for _, group := range groupOf {
				if !slices.Contains(groups, group) {
					groups = append(groups, group)
				}
			}
			slices.Sort(groups)
			for _, group := range groups {
				list := []*core.Object{}
				for index, row := range charged {
					if groupOf[index] == group {
						list = append(list, row)
					}
				}
				part := charge.Spread(core.NewObject("quantity", quantityOf(list)))
				var planned *core.Object
				if group >= 0 && group < len(windows) {
					planned = windows[group]
				}
				var price *core.Object
				if planned == nil {
					if price, err = PriceFor(ctx, tx, meter, priceChain, period); err != nil {
						return nil, err
					}
				}
				quantity := billNumber(part, "quantity")
				switch {
				case planned != nil:
					spec, _ := planned.Get("spec").(*core.Object)
					part.Set("price", core.NewObject("effectiveFrom", period, "setOn", accountID, "spec", spec, "source", "plan", "planKey", planned.Get("planKey")))
					part.Set("amountMicros", priceQuantity(spec, quantity))
				case price == nil:
					part.Set("unpriced", true)
				default:
					spec, _ := price.Get("spec").(*core.Object)
					part.Set("price", core.NewObject("effectiveFrom", price.Get("effectiveFrom"), "setOn", price.Get("tenantId"), "spec", spec, "source", "rate-card"))
					part.Set("amountMicros", priceQuantity(spec, quantity))
				}
				amount := billNumber(part, "amountMicros")
				if amount > 0 && quantity > 0 {
					if part.Get("aggregation") == "unique" {
						// Each person or agent costs the same; their share is spread over their rows by quantity.
						each := amount / quantity
						perPrincipal := map[string][]*core.Object{}
						principals := []string{}
						for _, row := range list {
							if principal, ok := billPrincipalOf(row); ok && principal != "" {
								if _, known := perPrincipal[principal]; !known {
									principals = append(principals, principal)
								}
								perPrincipal[principal] = append(perPrincipal[principal], row)
							}
						}
						for _, principal := range principals {
							rowsOf := perPrincipal[principal]
							total := 0.0
							for _, row := range rowsOf {
								total += jsNumber(row.Get("quantity"))
							}
							for _, row := range rowsOf {
								if total > 0 {
									row.Set("costMicros", roundMicros((each*jsNumber(row.Get("quantity")))/total))
								} else {
									row.Set("costMicros", roundMicros(each/float64(len(rowsOf))))
								}
							}
						}
					} else {
						for _, row := range list {
							row.Set("costMicros", roundMicros((amount*jsNumber(row.Get("quantity")))/quantity))
						}
					}
				}
				charges = append(charges, part)
			}
		}
		rows = append(rows, charged...)
	}
	slices.SortStableFunc(charges, func(a, b *core.Object) int {
		if difference := billNumber(b, "amountMicros") - billNumber(a, "amountMicros"); difference != 0 && !math.IsNaN(difference) {
			if difference < 0 {
				return -1
			}
			return 1
		}
		if billLess(billString(a, "meter"), billString(b, "meter")) {
			return -1
		}
		if billString(a, "meter") == billString(b, "meter") {
			return 0
		}
		return 1
	})
	total, billable := 0.0, 0.0
	for _, charge := range charges {
		total += billNumber(charge, "amountMicros")
		if charge.Get("internal") != true {
			billable += billNumber(charge, "amountMicros")
		}
	}
	return core.NewObject(
		"accountId", accountID,
		"period", period,
		"charges", billAnyList(charges),
		"rows", billAnyList(rows),
		"totalMicros", roundMicros(total),
		"billableMicros", roundMicros(billable),
	), nil
}

// ScopeSpend (billing.ts scopeSpend): Spend of a tenant's subtree in a period: the charged usage of every tenant
// below (and including) it, priced within the billing account each tenant belongs to. For the root this is the whole
// platform. The result is {rows, accounts}.
func ScopeSpend(ctx context.Context, server *ServerContext, tx core.IamStore, scope *core.Object, period string, cache map[string]any) (result *core.Object, err error) {
	tenants, err := Subtree(ctx, server, tx, scope)
	if err != nil {
		return nil, err
	}
	inScope := map[string]bool{}
	for _, realm := range tenants {
		inScope[billString(realm, "id")] = true
	}
	chain, err := server.Ancestry(ctx, tx, scope)
	if err != nil {
		return nil, err
	}
	rootID := billString(chain[len(chain)-1], "id")
	accountIDs := &billOrderedTenants{}
	top, err := AccountOf(ctx, server, tx, scope)
	if err != nil {
		return nil, err
	}
	accountIDs.set(top)
	// Organizations directly below the root, and tenants with a profile, are accounts of their own.
	for _, realm := range tenants[1:] {
		if realm.Get("parentId") == rootID {
			accountIDs.set(realm)
			continue
		}
		profile, err := ProfileOf(ctx, tx, billString(realm, "id"))
		if err != nil {
			return nil, err
		}
		if profile != nil {
			accountIDs.set(realm)
		}
	}
	accounts := []any{}
	rows := []any{}
	for _, account := range accountIDs.values() {
		spend, err := AccountSpend(ctx, server, tx, account, period, cache)
		if err != nil {
			return nil, err
		}
		accounts = append(accounts, spend)
		for _, row := range billObjects(spend.Get("rows")) {
			if inScope[billString(row, "tenantId")] {
				rows = append(rows, row)
			}
		}
	}
	return core.NewObject("rows", rows, "accounts", accounts), nil
}

// SumRows (billing.ts sumRows): Totals of charged rows: {costMicros, events}.
func SumRows(rows []*core.Object) *core.Object {
	cost, events := 0.0, 0.0
	for _, row := range rows {
		cost += billNumber(row, "costMicros")
		events += billNumber(row, "events")
	}
	return core.NewObject("costMicros", roundMicros(cost), "events", events)
}

// DirectoryFor (billing.ts directoryFor): Team and department trees of the tenants in scope, for roll-ups and
// labels: {teams, departments}, each an object of records keyed by ID.
func DirectoryFor(ctx context.Context, tx core.IamStore, tenantIDs []string) (result *core.Object, err error) {
	teams := core.NewObject()
	departments := core.NewObject()
	for _, tenantID := range unique(tenantIDs) {
		found, err := tx.Find(ctx, TeamCollections.Teams, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, team := range found {
			teams.Set(billString(team, "id"), team)
		}
		// tenantDepartments: the tenant's departments by ID, in store order.
		records, err := tx.Find(ctx, DepartmentCollections.Departments, core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		_, order := orgByID(records)
		for _, department := range order {
			departments.Set(billString(department, "id"), department)
		}
	}
	return core.NewObject("teams", teams, "departments", departments), nil
}

// directoryMap is one of a Directory's members as a map by ID.
func directoryMap(directory *core.Object, key string) map[string]*core.Object {
	out := map[string]*core.Object{}
	members, _ := member(directory, key).(*core.Object)
	members.Entries(func(id string, value any) bool {
		if record, ok := value.(*core.Object); ok && record != nil {
			out[id] = record
		}
		return true
	})
	return out
}

// TeamShare (billing.ts teamShare): The share of a row's cost that counts toward `teamId` (and the teams above it
// when `rollUp`).
func TeamShare(row *core.Object, teamID string, directory *core.Object, settings *core.Object, rollUp bool) (result float64, err error) {
	teamIDs := orgStrings(row, "teamIds")
	if len(teamIDs) == 0 {
		return 0, nil
	}
	var teams map[string]*core.Object
	if rollUp {
		teams = directoryMap(directory, "teams")
	}
	matching := 0
	for _, id := range teamIDs {
		if rollUp {
			for _, team := range teamChain(teams, id) {
				if billString(team, "id") == teamID {
					matching++
					break
				}
			}
		} else if id == teamID {
			matching++
		}
	}
	if matching == 0 {
		return 0, nil
	}
	if settings.Get("teamAttribution") == "full" {
		return 1, nil
	}
	return float64(matching) / float64(len(teamIDs)), nil
}

// InDepartment (billing.ts inDepartment): Whether a row's department is `departmentId` or (with `rollUp`) a
// department below it.
func InDepartment(row *core.Object, departmentID string, directory *core.Object, rollUp bool) (result bool, err error) {
	own := row.Get("departmentId")
	if !truthy(own) {
		return false, nil
	}
	if !rollUp {
		return own == departmentID, nil
	}
	for _, department := range departmentChain(directoryMap(directory, "departments"), jsString(own)) {
		if billString(department, "id") == departmentID {
			return true, nil
		}
	}
	return false, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Budgets, credits, statements

// AmountDue (billing.ts amountDue): What is still owed on an invoice: its total less payments and credit notes
// (never below 0).
func AmountDue(statement *core.Object) (result float64, err error) {
	return amountDue(statement), nil
}

func amountDue(statement *core.Object) float64 {
	switch statement.Get("status") {
	case "draft":
		return billNumber(statement, "totalMicros")
	case "void":
		return 0
	}
	return roundMicros(billMax(0, billNumber(statement, "totalMicros")-amountPaid(statement)-billNumberOr(statement, "creditNotesMicros", 0)))
}

// AmountPaid (billing.ts amountPaid): Payments received on an invoice; invoices marked paid before payments were
// recorded count as fully paid.
func AmountPaid(statement *core.Object) (result float64, err error) {
	return amountPaid(statement), nil
}

func amountPaid(statement *core.Object) float64 {
	if billHas(statement, "amountPaidMicros") {
		return billNumber(statement, "amountPaidMicros")
	}
	if statement.Get("status") == "paid" {
		return billNumber(statement, "totalMicros")
	}
	return 0
}

// SubscriptionStatus (billing.ts subscriptionStatus): A subscription's state at an instant.
func SubscriptionStatus(subscription *core.Object, now int64) (result string, err error) {
	at := float64(now)
	if billHas(subscription, "endsAt") && billNumber(subscription, "endsAt") <= at {
		return "ended", nil
	}
	if billHas(subscription, "trialEndsAt") && billNumber(subscription, "trialEndsAt") > at {
		return "trialing", nil
	}
	return "active", nil
}

// DiscountActive (billing.ts discountActive): Whether a redeemed coupon discounts an invoice for `period`: `once`
// until one invoice used it, `repeating` for the invoices of `durationInMonths` months from the month it was
// redeemed, `forever` until removed.
func DiscountActive(discount *core.Object, period string, timeZone string) (result bool, err error) {
	if billHas(discount, "endedAt") {
		return false, nil
	}
	switch discount.Get("duration") {
	case "once":
		return core.StrictEquals(discount.Get("appliedInvoices"), 0.0), nil
	case "repeating":
		from, err := periodOf(billNumber(discount, "redeemedAt"), timeZone)
		if err != nil {
			return false, err
		}
		return compareUTF16(period, from) >= 0 && billLess(period, shiftPeriod(from, billNumberOr(discount, "durationInMonths", 1))), nil
	}
	return true, nil
}

// OverlapShare (billing.ts overlapShare): The share (0-1, four decimals) of `[start, end)` that `[from, to)` covers.
func OverlapShare(start float64, end float64, from float64, to float64) (result float64, err error) {
	return overlapShare(start, end, from, to), nil
}

func overlapShare(start, end, from, to float64) float64 {
	length := end - start
	if length <= 0 {
		return 0
	}
	covered := billMax(0, billMin(end, to)-billMax(start, from))
	return jsMathRound((covered/length)*10_000) / 10_000
}

var thresholdTextPattern = regexp.MustCompile(`^\d{1,4}$`)

// BudgetThresholds (billing.ts budgetThresholds): Validates budget thresholds: 1-10 distinct percentages from 1 to
// 1000, ascending.
func BudgetThresholds(value any) (result []float64, err error) {
	if isUndefined(value) {
		return []float64{50, 80, 100}, nil
	}
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > 10 {
		return nil, invalidInput("thresholds must list 1-10 percentages")
	}
	// Forms send numbers as text ("50, 80, 100").
	numeric := func(item any) any {
		if text, ok := item.(string); ok && thresholdTextPattern.MatchString(core.JSTrim(text)) {
			return jsNumber(core.JSTrim(text))
		}
		return item
	}
	result = []float64{}
	for _, item := range list {
		threshold, err := Integer(numeric(item), "thresholds", 1, 1000)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(result, threshold) {
			result = append(result, threshold)
		}
	}
	slices.Sort(result)
	return result, nil
}

// UsageExpiry (billing.ts usageExpiry): Retention of a usage event recorded for `period`.
func UsageExpiry(period string, settings *core.Object) (result float64, err error) {
	_, end, err := periodBounds(period, jsString(settings.Get("timeZone")))
	if err != nil {
		return 0, err
	}
	return end + billNumber(settings, "usageRetentionDays")*86_400_000, nil
}

// StatementHash (billing.ts statementHash): Statement content hash: what it bills, to whom, under which number
// (payment status is left out).
func StatementHash(statement *core.Object) (result string, err error) {
	content := core.NewObject(
		"number", statement.Get("number"),
		"period", statement.Get("period"),
		"currency", statement.Get("currency"),
		"tenantId", statement.Get("tenantId"),
		"lines", statement.Get("lines"),
		"subtotalMicros", statement.Get("subtotalMicros"),
		"creditsMicros", statement.Get("creditsMicros"),
		"totalMicros", statement.Get("totalMicros"),
		"billTo", statement.Get("billTo"),
		// Contract terms (absent on statements without them, so earlier hashes still verify).
		"discount", statement.Get("discount"),
		"commitment", statement.Get("commitment"),
		"tax", statement.Get("tax"),
		"coupons", statement.Get("coupons"),
		"billingReason", statement.Get("billingReason"),
	)
	text, _, err := core.Stringify(content)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte(text))
	return hex.EncodeToString(sum[:]), nil
}

// InvoiceAmountsInput is the input of invoiceAmounts. InvoiceAmounts also accepts it as a *core.Object with the same
// members, `credit` holding a func(float64) float64 (or func(float64) (float64, error)).
type InvoiceAmountsInput struct {
	SubtotalMicros float64
	// Terms are the account's contract terms (nil for none).
	Terms *core.Object
	// Commitment says whether the minimum commitment applies (the monthly invoice).
	Commitment bool
	Discounts  []*core.Object
	// Credit draws account credit for an amount due and returns what it covered.
	Credit func(dueMicros float64) (float64, error)
}

func invoiceAmountsInput(input any) (InvoiceAmountsInput, error) {
	switch v := input.(type) {
	case InvoiceAmountsInput:
		return v, nil
	case *InvoiceAmountsInput:
		if v != nil {
			return *v, nil
		}
	case *core.Object:
		if v == nil {
			break
		}
		out := InvoiceAmountsInput{SubtotalMicros: billNumber(v, "subtotalMicros"), Commitment: truthy(v.Get("commitment"))}
		if terms, ok := v.Get("terms").(*core.Object); ok {
			out.Terms = terms
		}
		out.Discounts = billObjects(v.Get("discounts"))
		switch credit := v.Get("credit").(type) {
		case func(float64) float64:
			out.Credit = func(due float64) (float64, error) { return credit(due), nil }
		case func(float64) (float64, error):
			out.Credit = credit
		}
		return out, nil
	}
	return InvoiceAmountsInput{}, core.NewIamError("INVALID_INPUT", "invoiceAmounts needs its input")
}

// InvoiceAmounts (billing.ts invoiceAmounts): Turns an invoice's subtotal into its total, in order: the contract
// discount, the minimum-commitment true-up (monthly invoices only), coupon discounts, credit, and tax on what is
// left. A negative balance (credit items larger than the charges) comes back as `carryForwardMicros` for account
// credit, and the total stays 0. `input` is an InvoiceAmountsInput (or its *core.Object form); the result is
// {discount?, commitment?, coupons?, creditsMicros, tax?, totalMicros, carryForwardMicros}.
func InvoiceAmounts(input any) (result *core.Object, err error) {
	in, err := invoiceAmountsInput(input)
	if err != nil {
		return nil, err
	}
	subtotal, terms := in.SubtotalMicros, in.Terms
	contract := 0.0
	if billHas(terms, "discountPercent") && subtotal > 0 {
		contract = roundCents((subtotal * billNumber(terms, "discountPercent")) / 100)
	}
	net := roundMicros(subtotal - contract)
	trueUp := 0.0
	if in.Commitment && billHas(terms, "minimumCommitmentMicros") {
		trueUp = roundCents(billMax(0, billNumber(terms, "minimumCommitmentMicros")-net))
	}
	net = roundMicros(net + trueUp)
	coupons := []any{}
	for _, discount := range in.Discounts {
		if net <= 0 {
			break
		}
		off := billNumberOr(discount, "amountOffMicros", 0)
		if billHas(discount, "percentOff") {
			off = (net * billNumber(discount, "percentOff")) / 100
		}
		amount := roundCents(billMin(net, off))
		if amount <= 0 {
			continue
		}
		coupons = append(coupons, core.NewObject("discountId", discount.Get("id"), "code", discount.Get("code"), "name", discount.Get("name"), "amountMicros", amount))
		net = roundMicros(net - amount)
	}
	carryForward := 0.0
	if net < 0 {
		carryForward = roundMicros(-net)
	}
	due := billMax(0, net)
	credits := 0.0
	if due > 0 {
		covered := 0.0
		if in.Credit != nil {
			if covered, err = in.Credit(due); err != nil {
				return nil, err
			}
		} else {
			covered = math.NaN()
		}
		credits = roundMicros(billMin(due, covered))
	}
	taxable := roundMicros(due - credits)
	tax := 0.0
	if billHas(terms, "taxRatePercent") {
		tax = roundCents((taxable * billNumber(terms, "taxRatePercent")) / 100)
	}
	result = core.NewObject()
	if billHas(terms, "discountPercent") {
		result.Set("discount", core.NewObject("percent", terms.Get("discountPercent"), "amountMicros", contract))
	}
	if in.Commitment && billHas(terms, "minimumCommitmentMicros") {
		result.Set("commitment", core.NewObject("minimumMicros", terms.Get("minimumCommitmentMicros"), "trueUpMicros", trueUp))
	}
	if len(coupons) > 0 {
		result.Set("coupons", coupons)
	}
	result.Set("creditsMicros", credits)
	if billHas(terms, "taxRatePercent") {
		result.Set("tax", core.NewObject("label", coalesce(terms.Get("taxLabel"), "Tax"), "ratePercent", terms.Get("taxRatePercent"), "amountMicros", tax))
	}
	result.Set("totalMicros", roundMicros(taxable+tax))
	result.Set("carryForwardMicros", carryForward)
	return result, nil
}
