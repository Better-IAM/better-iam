package server

// Port of packages/server/src/billing-service.ts: the billing engine behind the `billing` API group and `iam.billing`:
// recording, spend reports, budgets and alerts, statements and credits, subscriptions, the seat recorder, anomaly
// detection and CSV exports.

import (
	"context"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// BillingService is billing-service.ts billingServiceOf(): one per server, shared by the API group, `iam.billing` and
// `ctx.billing`.
type BillingService struct {
	server   *ServerContext
	Settings *core.Object
	Hooks    *BillingHooks

	// settingsErr is the INVALID_CONFIG error of an invalid `billing` option (createBillingService throws it).
	settingsErr error
	tz          string

	statusMu    sync.Mutex
	statusCache map[string]*bsCachedStatus
	statusOrder []string
}

type bsCachedStatus struct {
	at        int64
	updatedAt any
	status    *core.Object
}

// bsServicesMu guards ServerContext.billingService (billing-service.ts `services` WeakMap).
var bsServicesMu sync.Mutex

// BillingServiceOf is billing-service.ts billingServiceOf: the billing service of a server (one per instance). An
// invalid `billing` option leaves the service failing every call with INVALID_CONFIG (BillingSettingsError reports it
// to the composition root).
func BillingServiceOf(server *ServerContext) *BillingService {
	bsServicesMu.Lock()
	defer bsServicesMu.Unlock()
	if server.billingService != nil {
		return server.billingService
	}
	service := createBillingService(server)
	server.billingService = service
	return service
}

// BillingSettingsError is the INVALID_CONFIG error createBillingService throws for an invalid `billing` option; nil
// when the option is valid.
func (s *BillingService) BillingSettingsError() error { return s.settingsErr }

func createBillingService(server *ServerContext) *BillingService {
	service := &BillingService{server: server, statusCache: map[string]*bsCachedStatus{}}
	service.Hooks = &BillingHooks{server: server, service: service}
	var options *core.Object
	if server.Options != nil && server.Options.Billing != nil {
		record, err := core.ToRecord(server.Options.Billing)
		if err != nil {
			service.settingsErr = err
			return service
		}
		options = record
	}
	settings, err := BillingSettings(options)
	if err != nil {
		service.settingsErr = err
		return service
	}
	service.Settings = settings
	service.tz = jsString(settings.Get("timeZone"))
	return service
}

// ready fails with the settings error of an invalid `billing` option.
func (s *BillingService) ready() error { return s.settingsErr }

// --- settings and small helpers ------------------------------------------------------------------------------------

func (s *BillingService) currency() string { return jsString(s.Settings.Get("currency")) }

// fullTeams is `settings.teamAttribution === 'full'`.
func (s *BillingService) fullTeams() bool { return bsIs(s.Settings.Get("teamAttribution"), "full") }

// sendsEmail is `ctx.options.authentication?.sendEmail` (truthy).
func (s *BillingService) sendsEmail() bool {
	options := s.server.Options
	return options != nil && options.Authentication != nil && options.Authentication.SendEmail != nil
}

// bsCalc collects the first error of the billing.ts number helpers (roundMicros, roundCents, unitsOf) so arithmetic
// reads like the TypeScript; callers check err before writing anything.
type bsCalc struct{ err error }

func (c *bsCalc) keep(err error) {
	if err != nil && c.err == nil {
		c.err = err
	}
}

func (c *bsCalc) micros(value float64) float64 {
	result, err := RoundMicros(value)
	c.keep(err)
	return result
}

func (c *bsCalc) cents(value float64) float64 {
	result, err := RoundCents(value)
	c.keep(err)
	return result
}

func (c *bsCalc) units(value float64) float64 {
	result, err := UnitsOf(value)
	c.keep(err)
	return result
}

// bsObjects reads a list of records (a []any of objects or a []*core.Object).
func bsObjects(value any) []*core.Object {
	switch v := value.(type) {
	case []*core.Object:
		return v
	case []any:
		out := make([]*core.Object, 0, len(v))
		for _, item := range v {
			if o, ok := item.(*core.Object); ok && o != nil {
				out = append(out, o)
			}
		}
		return out
	}
	return nil
}

// bsStrings reads a list of strings (a []any or []string); other items are left out.
func bsStrings(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if text, ok := item.(string); ok {
				out = append(out, text)
			}
		}
		return out
	}
	return nil
}

// bsList is a []any of records.
func bsList(items []*core.Object) []any {
	out := make([]any, len(items))
	for index, item := range items {
		out[index] = item
	}
	return out
}

// bsStr is a string member ("" when absent or not a string).
func bsStr(o *core.Object, key string) string {
	text, _ := o.Get(key).(string)
	return text
}

// bsIs is `value === text`.
func bsIs(value any, text string) bool {
	s, ok := value.(string)
	return ok && s == text
}

// bsNum is a numeric member as JavaScript arithmetic reads it (undefined is NaN).
func bsNum(o *core.Object, key string) float64 { return jsNumber(o.Get(key)) }

// bsOrder is `diff || tie` in a sort comparator.
func bsOrder(diff float64, tie int) int {
	if diff != 0 && !math.IsNaN(diff) {
		if diff < 0 {
			return -1
		}
		return 1
	}
	return tie
}

// bsByID is `(a, b) => (a.id < b.id ? -1 : 1)`.
func bsByID(a, b *core.Object) int { return compareUTF16(bsStr(a, "id"), bsStr(b, "id")) }

// bsMax is Math.max(a, b).
func bsMax(a, b float64) float64 { return math.Max(a, b) }

// bsMin is Math.min(a, b).
func bsMin(a, b float64) float64 { return math.Min(a, b) }

// bsOneDecimal rounds to one decimal (Math.round(value * 10) / 10).
func bsOneDecimal(value float64) float64 { return jsMathRound(value*10) / 10 }

// bsMicroRound is Math.round(value * 1e6) / 1e6.
func bsMicroRound(value float64) float64 { return jsMathRound(value*1e6) / 1e6 }

// bsIsoDate is `new Date(at).toISOString().slice(0, 10)`.
func bsIsoDate(at float64) string {
	text := isoString(at)
	if len(text) > 10 {
		return text[:10]
	}
	return text
}

// bsPad is String(value).padStart(width, '0').
func bsPad(value int, width int) string {
	text := strconv.Itoa(value)
	for len(text) < width {
		text = "0" + text
	}
	return text
}

// bsSortStrings is the default Array.prototype.sort of strings.
func bsSortStrings(items []string) []string {
	slices.SortStableFunc(items, compareUTF16)
	return items
}

// bsDirectoryMap reads `dir.teams` or `dir.departments` (billing.ts Directory) as a map by ID.
func bsDirectoryMap(dir *core.Object, key string) map[string]*core.Object {
	switch v := dir.Get(key).(type) {
	case map[string]*core.Object:
		return v
	case *core.Object:
		out := map[string]*core.Object{}
		v.Entries(func(id string, value any) bool {
			if record, ok := value.(*core.Object); ok && record != nil {
				out[id] = record
			}
			return true
		})
		return out
	}
	return map[string]*core.Object{}
}

// bsDirectoryValues is `[...dir.teams.values()]` (insertion order for an ordered map, ID order otherwise).
func bsDirectoryValues(dir *core.Object, key string) []*core.Object {
	switch v := dir.Get(key).(type) {
	case *core.Object:
		var out []*core.Object
		v.Entries(func(_ string, value any) bool {
			if record, ok := value.(*core.Object); ok && record != nil {
				out = append(out, record)
			}
			return true
		})
		return out
	case map[string]*core.Object:
		ids := make([]string, 0, len(v))
		for id := range v {
			ids = append(ids, id)
		}
		bsSortStrings(ids)
		out := make([]*core.Object, 0, len(ids))
		for _, id := range ids {
			out = append(out, v[id])
		}
		return out
	}
	return nil
}

// bsDirectoryGet is `dir.teams.get(id)` (nil when absent).
func bsDirectoryGet(dir *core.Object, key string, id string) *core.Object {
	switch v := dir.Get(key).(type) {
	case map[string]*core.Object:
		return v[id]
	case *core.Object:
		record, _ := v.Get(id).(*core.Object)
		return record
	}
	return nil
}

// bsDirectoryName is `dir.teams.get(id)?.name`.
func bsDirectoryName(dir *core.Object, key string, id string) any {
	record := bsDirectoryGet(dir, key, id)
	if record == nil {
		return core.Undefined
	}
	return record.Get("name")
}

// --- built-in meters and money -------------------------------------------------------------------------------------

type bsBuiltInMeter struct{ name, unit, description string }

// bsBuiltInMeters are the built-in reported meters other modules push to; defined on the root tenant the first time
// they are used.
var bsBuiltInMeters = map[string]bsBuiltInMeter{
	"inference": {
		name:        "AI inference",
		unit:        "token",
		description: "Model calls through inference access control, at each model’s token prices.",
	},
}

// BuiltInMeterKey (billing-service.ts builtInMeterKey): Whether a key names a built-in meter: only the platform (the
// root tenant) defines those.
func BuiltInMeterKey(key string) (result bool, err error) {
	_, result = bsBuiltInMeters[key]
	return result, nil
}

const bsStatusCacheMs = 30_000

const (
	bsUnattributedIdentity   = "(unattributed)"
	bsUnattributedAgent      = "(none)"
	bsUnattributedTeam       = "(no team)"
	bsUnattributedDepartment = "(no department)"
	bsUnattributedTag        = "(untagged)"
)

// bsSharedPools are the groups that hold unattributed spend, per dimension that can share it out.
var bsSharedPools = map[string]string{
	"identity":   bsUnattributedIdentity,
	"agent":      bsUnattributedAgent,
	"team":       bsUnattributedTeam,
	"department": bsUnattributedDepartment,
}

// SpendContextKeys are the policy context keys billing derives (billing-service.ts spendContextKeys).
var SpendContextKeys = []string{"principal.spendExceeded", "principal.budgetsExceeded"}

type bsCurrencyFormat struct {
	symbol string
	digits int
}

// bsCurrencyFormats are the en-US currency symbols and fraction digits (Intl.NumberFormat, CLDR) that differ from the
// default `{code} ` with two digits.
var bsCurrencyFormats = map[string]bsCurrencyFormat{
	"AFN": {"AFN ", 0}, "ALL": {"ALL ", 0}, "AUD": {"A$", 2}, "BHD": {"BHD ", 3},
	"BIF": {"BIF ", 0}, "BRL": {"R$", 2}, "CAD": {"CA$", 2}, "CLP": {"CLP ", 0},
	"CNY": {"CN¥", 2}, "COP": {"COP ", 0}, "DJF": {"DJF ", 0}, "EUR": {"€", 2},
	"GBP": {"£", 2}, "GNF": {"GNF ", 0}, "HKD": {"HK$", 2}, "HUF": {"HUF ", 0},
	"IDR": {"IDR ", 0}, "ILS": {"₪", 2}, "INR": {"₹", 2}, "IQD": {"IQD ", 0},
	"IRR": {"IRR ", 0}, "ISK": {"ISK ", 0}, "JOD": {"JOD ", 3}, "JPY": {"¥", 0},
	"KMF": {"KMF ", 0}, "KPW": {"KPW ", 0}, "KRW": {"₩", 0}, "KWD": {"KWD ", 3},
	"LAK": {"LAK ", 0}, "LBP": {"LBP ", 0}, "LYD": {"LYD ", 3}, "MGA": {"MGA ", 0},
	"MMK": {"MMK ", 0}, "MXN": {"MX$", 2}, "NZD": {"NZ$", 2}, "OMR": {"OMR ", 3},
	"PHP": {"₱", 2}, "PKR": {"PKR ", 0}, "PYG": {"PYG ", 0}, "RWF": {"RWF ", 0},
	"SLL": {"SLL ", 0}, "SOS": {"SOS ", 0}, "SYP": {"SYP ", 0}, "TND": {"TND ", 3},
	"TWD": {"NT$", 2}, "UGX": {"UGX ", 0}, "USD": {"$", 2}, "VND": {"₫", 0},
	"VUV": {"VUV ", 0}, "XAF": {"FCFA ", 0}, "XCD": {"EC$", 2}, "XCG": {"Cg. ", 2},
	"XOF": {"F CFA ", 0}, "XPF": {"CFPF ", 0}, "YER": {"YER ", 0},
}

// FormatMoney (billing-service.ts formatMoney): Formats micros as money in the deployment currency (for emails), as
// `Intl.NumberFormat('en-US', { style: 'currency', currency })` does.
func FormatMoney(micros float64, currency string) (string, error) {
	units, err := UnitsOf(micros)
	if err != nil {
		return "", err
	}
	return bsCurrencyText(units, currency), nil
}

// bsCurrencyText is Intl.NumberFormat('en-US', { style: 'currency', currency }).format(value): the shortest decimal
// of the value rounded half away from zero to the currency's digits, grouped by thousands.
func bsCurrencyText(value float64, currency string) string {
	format, ok := bsCurrencyFormats[currency]
	if !ok {
		format = bsCurrencyFormat{currency + " ", 2}
	}
	if math.IsNaN(value) {
		return format.symbol + "NaN"
	}
	sign := ""
	if math.Signbit(value) {
		sign = "-"
	}
	if math.IsInf(value, 0) {
		return sign + format.symbol + "∞"
	}
	digits := strconv.FormatFloat(math.Abs(value), 'f', -1, 64)
	whole, fraction, _ := strings.Cut(digits, ".")
	if len(fraction) <= format.digits {
		fraction += strings.Repeat("0", format.digits-len(fraction))
	} else {
		up := fraction[format.digits] >= '5'
		number := []byte(whole + fraction[:format.digits])
		if up {
			index := len(number) - 1
			for index >= 0 {
				if number[index] == '9' {
					number[index] = '0'
					index--
					continue
				}
				number[index]++
				break
			}
			if index < 0 {
				number = append([]byte{'1'}, number...)
			}
		}
		whole = string(number[:len(number)-format.digits])
		fraction = string(number[len(number)-format.digits:])
	}
	var grouped strings.Builder
	for index, digit := range whole {
		if index > 0 && (len(whole)-index)%3 == 0 {
			grouped.WriteByte(',')
		}
		grouped.WriteRune(digit)
	}
	text := sign + format.symbol + grouped.String()
	if format.digits > 0 {
		text += "." + fraction
	}
	return text
}

var bsTagGroupPattern = regexp.MustCompile(`^tag:[A-Za-z][A-Za-z0-9_.:-]{0,63}$`)

// bsSpendGroupBy validates how a spend report groups its rows.
func bsSpendGroupBy(value any) (string, error) {
	if text, ok := value.(string); ok {
		switch text {
		case "meter", "identity", "agent", "team", "department", "tenant", "day":
			return text, nil
		}
		if bsTagGroupPattern.MatchString(text) {
			return text, nil
		}
	}
	return "", invalidInput("groupBy must be 'meter', 'identity', 'agent', 'team', 'department', 'tenant', 'day' or 'tag:{name}'")
}

// --- recording -------------------------------------------------------------------------------------------------------

// CurrentPeriod (billing-service.ts billingServiceOf().currentPeriod): the billing period (`YYYY-MM`) of now.
func (s *BillingService) CurrentPeriod() (result string, err error) {
	if err = s.ready(); err != nil {
		return
	}
	return PeriodOf(s.server.Now(), s.tz)
}

func bsReceipt(record *core.Object, duplicate bool) *core.Object {
	out := core.NewObject("id", record.Get("id"), "tenantId", record.Get("tenantId"), "meter", record.Get("meter"),
		"quantity", record.Get("quantity"))
	if value := record.Get("costMicros"); !isUndefined(value) {
		out.Set("costMicros", value)
	}
	out.Set("period", record.Get("period"))
	out.Set("occurredAt", record.Get("occurredAt"))
	if value := record.Get("identityId"); !isUndefined(value) {
		out.Set("identityId", value)
	}
	out.Set("teamIds", record.Get("teamIds"))
	if value := record.Get("departmentId"); !isUndefined(value) {
		out.Set("departmentId", value)
	}
	out.Set("duplicate", duplicate)
	return out
}

// StatementFor (billing-service.ts billingServiceOf().statementFor): The non-void statement of an account for a
// period, if it has been invoiced (nil otherwise).
func (s *BillingService) StatementFor(ctx context.Context, tx core.IamStore, accountID string, period string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	found, err := tx.Find(ctx, BillingCollections.Statements, core.NewObject("tenantId", accountID, "uniqueKey", "period:"+period), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// Record (billing-service.ts billingServiceOf().record): records one usage event (UsageInput) attributed to people,
// teams and departments. extra (RecordExtras) may carry `costMicros`, `agentId`, `sourceId`, `enforceBudgets` and the
// resolved `meter`.
func (s *BillingService) Record(ctx context.Context, tx core.IamStore, input *core.Object, recordedBy string, extra *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	server := s.server
	calc := &bsCalc{}
	tenantID, err := Text(member(input, "tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	if bsIs(tenant.Get("status"), "deleted") {
		return nil, core.NewIamError("INVALID_TRANSITION", "Deleted tenants cannot record usage")
	}
	chain, err := server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return nil, err
	}
	key, err := MeterKey(member(input, "meter"))
	if err != nil {
		return nil, err
	}
	meter, _ := member(extra, "meter").(*core.Object)
	if meter == nil {
		if meter, err = ResolveMeter(ctx, tx, chain, key); err != nil {
			return nil, err
		}
	}
	if meter == nil {
		return nil, core.NewIamError("NOT_FOUND", "Unknown billing meter "+key, 404)
	}
	if truthy(meter.Get("archived")) {
		return nil, core.NewIamError("METER_ARCHIVED", "This meter no longer accepts usage", 409)
	}
	quantity := 1.0
	if raw := member(input, "quantity"); !isUndefined(raw) {
		number, ok := raw.(float64)
		if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number < 0 || number > 1e15 {
			return nil, invalidInput("quantity must be a number from 0 to 1e15")
		}
		quantity = number
	}
	var costMicros *float64
	extraCost := member(extra, "costMicros")
	inputCost := member(input, "cost")
	if bsIs(meter.Get("pricing"), "reported") {
		if !nullish(extraCost) {
			value := jsNumber(extraCost)
			costMicros = &value
		} else if !isUndefined(inputCost) {
			value, err := AmountMicros(inputCost, "cost")
			if err != nil {
				return nil, err
			}
			costMicros = &value
		}
		if costMicros == nil {
			return nil, invalidInput("This meter needs the cost of each event (cost)")
		}
		rounded := calc.micros(*costMicros)
		if calc.err != nil {
			return nil, calc.err
		}
		costMicros = &rounded
	} else if !isUndefined(inputCost) || !isUndefined(extraCost) {
		return nil, invalidInput("This meter is priced from the rate card; leave cost out")
	}
	now := server.Now()
	occurredAt := float64(now)
	if raw := member(input, "occurredAt"); !isUndefined(raw) {
		if occurredAt, err = Integer(raw, "occurredAt", 0, maxSafeInteger); err != nil {
			return nil, err
		}
	}
	if occurredAt > float64(now)+300_000 {
		return nil, invalidInput("occurredAt must not be in the future")
	}
	if occurredAt < float64(now)-366*86_400_000 {
		return nil, invalidInput("occurredAt must be within the last year")
	}
	period, err := PeriodOf(int64(occurredAt), s.tz)
	if err != nil {
		return nil, err
	}
	uniqueKey := ""
	if raw := member(input, "idempotencyKey"); !isUndefined(raw) {
		text, err := Text(raw, "idempotencyKey", 200)
		if err != nil {
			return nil, err
		}
		uniqueKey = "idem:" + text
	} else if sourceID := member(extra, "sourceId"); !isUndefined(sourceID) {
		uniqueKey = "src:" + jsString(meter.Get("key")) + ":" + jsString(sourceID)
	}
	if uniqueKey != "" {
		found, err := tx.Find(ctx, BillingCollections.Usage, core.NewObject("tenantId", tenant.Get("id"), "uniqueKey", uniqueKey), nil)
		if err != nil {
			return nil, err
		}
		if len(found) > 0 {
			existing := found[0]
			if !core.StrictEquals(existing.Get("meterId"), meter.Get("id")) {
				return nil, core.NewIamError("CONFLICT", "This idempotency key was used for another meter", 409)
			}
			return bsReceipt(existing, true), nil
		}
	}
	account, err := AccountOf(ctx, server, tx, tenant)
	if err != nil {
		return nil, err
	}
	// A draft invoice is recomputed when it is finalized, so its period still takes usage.
	invoiced, err := s.StatementFor(ctx, tx, bsStr(account, "id"), period)
	if err != nil {
		return nil, err
	}
	if invoiced != nil && !bsIs(invoiced.Get("status"), "draft") {
		return nil, core.NewIamError("BILLING_PERIOD_CLOSED", period+" has already been invoiced for this billing account", 409)
	}
	// Attribution stays inside the organization: only trusted server code and platform (root tenant) identities
	// attribute usage to the platform's own people and teams, whose budgets and reports it would count toward.
	var recorder *core.Object
	if recordedBy != "deployment" {
		if recorder, err = tx.Get(ctx, "identities", recordedBy); err != nil {
			return nil, err
		}
	}
	attributable := chain
	if !(recordedBy == "deployment" || (recorder != nil && core.StrictEquals(recorder.Get("tenantId"), chain[len(chain)-1].Get("id")))) {
		attributable = chain[:len(chain)-1]
	}
	attributionInput := core.NewObject()
	if value := member(input, "identityId"); !isUndefined(value) {
		attributionInput.Set("identityId", value)
	}
	if value := member(extra, "agentId"); !isUndefined(value) {
		attributionInput.Set("agentId", value)
	}
	if value := member(input, "teamId"); !isUndefined(value) {
		attributionInput.Set("teamId", value)
	}
	attribution, err := AttributionFor(ctx, server, tx, attributable, attributionInput, s.Settings)
	if err != nil {
		return nil, err
	}
	if bsIs(meter.Get("aggregation"), "unique") && !truthy(attribution.Get("identityId")) {
		return nil, invalidInput("Meters that count people need identityId")
	}
	tags, err := UsageTags(member(input, "tags"))
	if err != nil {
		return nil, err
	}
	if truthy(member(extra, "enforceBudgets")) {
		checkInput := core.NewObject()
		if value := attribution.Get("identityId"); !isUndefined(value) {
			checkInput.Set("identityId", value)
		}
		checkInput.Set("meter", meter.Get("key"))
		verdict, err := s.Check(ctx, tx, tenant, checkInput)
		if err != nil {
			return nil, err
		}
		if !truthy(verdict.Get("allowed")) {
			blockedBy, _ := verdict.Get("blockedBy").(*core.Object)
			return nil, core.NewIamError("SPEND_LIMIT_REACHED", "The budget “"+jsString(blockedBy.Get("name"))+"” is spent", 402)
		}
	}
	day, err := DayOf(int64(occurredAt), s.tz)
	if err != nil {
		return nil, err
	}
	bucket := core.NewObject()
	if value := attribution.Get("identityId"); !isUndefined(value) {
		bucket.Set("identityId", value)
	}
	if value := attribution.Get("agentId"); !isUndefined(value) {
		bucket.Set("agentId", value)
	}
	bucket.Set("teamIds", attribution.Get("teamIds"))
	if value := attribution.Get("departmentId"); !isUndefined(value) {
		bucket.Set("departmentId", value)
	}
	if tags != nil {
		bucket.Set("tags", tags)
	}
	bucketID, err := RollupID(bsStr(tenant, "id"), day, bsStr(meter, "id"), bucket)
	if err != nil {
		return nil, err
	}
	existingBucket, err := tx.Get(ctx, BillingCollections.Rollups, bucketID)
	if err != nil {
		return nil, err
	}
	cost := 0.0
	if costMicros != nil {
		cost = *costMicros
	}
	if existingBucket != nil {
		next := existingBucket.Clone()
		next.Set("quantity", bsNum(existingBucket, "quantity")+quantity)
		next.Set("costMicros", calc.micros(bsNum(existingBucket, "costMicros")+cost))
		next.Set("events", bsNum(existingBucket, "events")+1)
		next.Set("updatedAt", float64(now))
		if calc.err != nil {
			return nil, calc.err
		}
		if _, err := tx.Put(ctx, BillingCollections.Rollups, next); err != nil {
			return nil, err
		}
	} else {
		rollup := core.NewObject("id", bucketID, "tenantId", tenant.Get("id"), "period", period, "day", day,
			"meterId", meter.Get("id"), "meter", meter.Get("key"))
		rollup.Assign(bucket.Clone())
		rollup.Set("quantity", quantity)
		rollup.Set("costMicros", cost)
		rollup.Set("events", 1.0)
		rollup.Set("updatedAt", float64(now))
		if _, err := tx.Insert(ctx, BillingCollections.Rollups, rollup); err != nil {
			return nil, err
		}
	}
	expiresAt, err := UsageExpiry(period, s.Settings)
	if err != nil {
		return nil, err
	}
	usage := core.NewObject("id", ID(), "tenantId", tenant.Get("id"))
	if uniqueKey != "" {
		usage.Set("uniqueKey", uniqueKey)
	}
	usage.Set("meterId", meter.Get("id"))
	usage.Set("meter", meter.Get("key"))
	usage.Set("quantity", quantity)
	if costMicros != nil {
		usage.Set("costMicros", *costMicros)
	}
	usage.Assign(bucket.Clone())
	usage.Set("occurredAt", occurredAt)
	usage.Set("period", period)
	usage.Set("day", day)
	usage.Set("recordedAt", float64(now))
	usage.Set("recordedBy", recordedBy)
	if sourceID := member(extra, "sourceId"); !isUndefined(sourceID) {
		usage.Set("sourceId", sourceID)
	}
	usage.Set("rollupId", bucketID)
	usage.Set("expiresAt", expiresAt)
	stored, err := tx.Insert(ctx, BillingCollections.Usage, usage)
	if err != nil {
		return nil, err
	}
	return bsReceipt(stored, false), nil
}

// builtInMeter defines a built-in reported meter on the root tenant the first time a module pushes to it.
func (s *BillingService) builtInMeter(ctx context.Context, tx core.IamStore, chain []*core.Object, key string) (*core.Object, error) {
	known, ok := bsBuiltInMeters[key]
	if !ok {
		return nil, nil
	}
	root := chain[len(chain)-1]
	now := float64(s.server.Now())
	return tx.Insert(ctx, BillingCollections.Meters, core.NewObject(
		"id", ID(), "tenantId", root.Get("id"), "uniqueKey", key, "key", key,
		"name", known.name, "unit", known.unit, "description", known.description,
		"aggregation", "sum", "pricing", "reported", "archived", false,
		"createdAt", now, "createdBy", "deployment", "updatedAt", now, "updatedBy", "deployment",
	))
}

// BillingHooks is billing-service.ts BillingHooks: what other server modules call to feed the ledger.
type BillingHooks struct {
	server  *ServerContext
	service *BillingService
}

// RecordPriced (billing-service.ts BillingHooks.recordPriced): Records already-priced usage in the caller's
// transaction. Never throws: billing problems must not fail the work being billed. A meter the tenant does not have
// yet is defined on the root tenant for the built-in keys (`inference`); other unknown meters are skipped. input is a
// PricedUsageInput: `{ tenantId, meter, costMicros, quantity?, identityId?, agentId?, tags?, sourceId?, occurredAt? }`.
func (s *BillingHooks) RecordPriced(ctx context.Context, tx core.IamStore, input *core.Object) (err error) {
	service := s.service
	if service == nil {
		service = BillingServiceOf(s.server)
	}
	// Billing never fails the work it bills.
	_ = service.recordPriced(ctx, tx, input)
	return nil
}

func (s *BillingService) recordPriced(ctx context.Context, tx core.IamStore, input *core.Object) error {
	if err := s.ready(); err != nil {
		return err
	}
	server := s.server
	tenant, err := tx.Get(ctx, "tenants", jsString(member(input, "tenantId")))
	if err != nil {
		return err
	}
	if tenant == nil || bsIs(tenant.Get("status"), "deleted") {
		return nil
	}
	chain, err := server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return err
	}
	key, err := MeterKey(member(input, "meter"))
	if err != nil {
		return err
	}
	// A built-in meter is always the platform's, even where a tenant defined a meter with its key.
	var meter *core.Object
	if builtIn, _ := BuiltInMeterKey(key); builtIn {
		if meter, err = ResolveMeter(ctx, tx, chain[len(chain)-1:], key); err != nil {
			return err
		}
		if meter == nil {
			if meter, err = s.builtInMeter(ctx, tx, chain, key); err != nil {
				return err
			}
		}
	} else if meter, err = ResolveMeter(ctx, tx, chain, key); err != nil {
		return err
	}
	if meter == nil || truthy(meter.Get("archived")) {
		return nil
	}
	var identity *core.Object
	if identityID := member(input, "identityId"); !isUndefined(identityID) {
		if identity, err = tx.Get(ctx, "identities", jsString(identityID)); err != nil {
			return err
		}
	}
	quantity := 1.0
	if raw := member(input, "quantity"); !nullish(raw) {
		quantity = jsNumber(raw)
	}
	usage := core.NewObject("tenantId", tenant.Get("id"), "meter", key, "quantity", bsMax(0, quantity))
	// Identities outside the tenant's ancestry (or gone) leave the usage unattributed.
	if identity != nil && !bsIs(identity.Get("status"), "deleted") && slices.ContainsFunc(chain, func(realm *core.Object) bool {
		return core.StrictEquals(realm.Get("id"), identity.Get("tenantId"))
	}) {
		usage.Set("identityId", identity.Get("id"))
	}
	if tags := member(input, "tags"); truthy(tags) {
		usage.Set("tags", tags)
	}
	if occurredAt := member(input, "occurredAt"); !isUndefined(occurredAt) {
		usage.Set("occurredAt", occurredAt)
	}
	extra := core.NewObject("meter", meter)
	if bsIs(meter.Get("pricing"), "reported") {
		extra.Set("costMicros", bsMax(0, jsNumber(member(input, "costMicros"))))
	}
	if agentID := member(input, "agentId"); !isUndefined(agentID) {
		extra.Set("agentId", agentID)
	}
	if sourceID := member(input, "sourceId"); !isUndefined(sourceID) {
		extra.Set("sourceId", sourceID)
	}
	_, err = s.Record(ctx, tx, usage, "deployment", extra)
	return err
}

// --- spend reports ---------------------------------------------------------------------------------------------------

// directory reads the teams and departments of the tenants in play, for filters, roll-ups and labels.
func (s *BillingService) directory(ctx context.Context, tx core.IamStore, rows []*core.Object, extra []string) (*core.Object, error) {
	tenantIDs := newOrderedSet(extra...)
	for _, row := range rows {
		tenantIDs.Add(bsStr(row, "tenantId"))
	}
	// Teams and departments live in the person's tenant, often the organization above a project.
	for _, tenantID := range tenantIDs.Values() {
		ancestors, err := s.server.AncestorIDs(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		for _, ancestor := range ancestors {
			tenantIDs.Add(ancestor)
		}
	}
	return DirectoryFor(ctx, tx, tenantIDs.Values())
}

// bsFilters are validated SpendFilters (nil members are absent).
type bsFilters struct {
	meter        *string
	identityID   *string
	teamID       *string
	departmentID *string
	subTenantID  *string
	rollUp       *bool
	billableOnly *bool
}

// weigher is the weight (0-1) with which a row counts under the filters.
func (s *BillingService) weigher(filters bsFilters, dir *core.Object, within map[string]bool) func(row *core.Object) (float64, error) {
	rollUp := filters.rollUp == nil || *filters.rollUp
	return func(row *core.Object) (float64, error) {
		if filters.billableOnly != nil && *filters.billableOnly && truthy(row.Get("internal")) {
			return 0, nil
		}
		if filters.meter != nil && !bsIs(row.Get("meter"), *filters.meter) {
			return 0, nil
		}
		if within != nil && !within[bsStr(row, "tenantId")] {
			return 0, nil
		}
		if filters.identityID != nil && !bsIs(row.Get("identityId"), *filters.identityID) && !bsIs(row.Get("agentId"), *filters.identityID) {
			return 0, nil
		}
		if filters.departmentID != nil {
			inside, err := InDepartment(row, *filters.departmentID, dir, rollUp)
			if err != nil {
				return 0, err
			}
			if !inside {
				return 0, nil
			}
		}
		if filters.teamID != nil {
			return TeamShare(row, *filters.teamID, dir, s.Settings, rollUp)
		}
		return 1, nil
	}
}

func (s *BillingService) validateFilters(ctx context.Context, tx core.IamStore, scope *core.Object, input *core.Object) (bsFilters, map[string]bool, error) {
	server := s.server
	filters := bsFilters{}
	if raw := member(input, "meter"); !isUndefined(raw) {
		key, err := MeterKey(raw)
		if err != nil {
			return filters, nil, err
		}
		filters.meter = &key
	}
	if raw := member(input, "identityId"); !isUndefined(raw) {
		identityID, err := Text(raw, "identityId")
		if err != nil {
			return filters, nil, err
		}
		filters.identityID = &identityID
	}
	if raw := member(input, "rollUp"); !isUndefined(raw) {
		value, ok := raw.(bool)
		if !ok {
			return filters, nil, invalidInput("rollUp must be a boolean")
		}
		filters.rollUp = &value
	}
	if raw := member(input, "billableOnly"); !isUndefined(raw) {
		value, ok := raw.(bool)
		if !ok {
			return filters, nil, invalidInput("billableOnly must be a boolean")
		}
		filters.billableOnly = &value
	}
	var tenants map[string]bool
	inScope := func() (map[string]bool, error) {
		if tenants == nil {
			realms, err := Subtree(ctx, server, tx, scope)
			if err != nil {
				return nil, err
			}
			tenants = map[string]bool{}
			for _, realm := range realms {
				tenants[bsStr(realm, "id")] = true
			}
		}
		return tenants, nil
	}
	// Teams and departments of the scope, or of the organization a project belongs to.
	reachable := func(tenantID string) (bool, error) {
		scoped, err := inScope()
		if err != nil {
			return false, err
		}
		if scoped[tenantID] {
			return true, nil
		}
		ancestors, err := server.AncestorIDs(ctx, tx, bsStr(scope, "id"))
		if err != nil {
			return false, err
		}
		return containsString(ancestors, tenantID), nil
	}
	if raw := member(input, "teamId"); !isUndefined(raw) {
		teamID, err := Text(raw, "teamId")
		if err != nil {
			return filters, nil, err
		}
		team, err := tx.Get(ctx, "teams", teamID)
		if err != nil {
			return filters, nil, err
		}
		ok := false
		if team != nil {
			if ok, err = reachable(bsStr(team, "tenantId")); err != nil {
				return filters, nil, err
			}
		}
		if !ok {
			return filters, nil, core.NewIamError("NOT_FOUND", "Team not found", 404)
		}
		id := bsStr(team, "id")
		filters.teamID = &id
	}
	if raw := member(input, "departmentId"); !isUndefined(raw) {
		departmentID, err := Text(raw, "departmentId")
		if err != nil {
			return filters, nil, err
		}
		department, err := tx.Get(ctx, "departments", departmentID)
		if err != nil {
			return filters, nil, err
		}
		ok := false
		if department != nil {
			if ok, err = reachable(bsStr(department, "tenantId")); err != nil {
				return filters, nil, err
			}
		}
		if !ok {
			return filters, nil, core.NewIamError("NOT_FOUND", "Department not found", 404)
		}
		id := bsStr(department, "id")
		filters.departmentID = &id
	}
	var within map[string]bool
	if raw := member(input, "subTenantId"); !isUndefined(raw) {
		subTenantID, err := Text(raw, "subTenantId")
		if err != nil {
			return filters, nil, err
		}
		sub, err := server.Tenant(ctx, tx, subTenantID)
		if err != nil {
			return filters, nil, err
		}
		scoped, err := inScope()
		if err != nil {
			return filters, nil, err
		}
		if !scoped[bsStr(sub, "id")] {
			return filters, nil, core.NewIamError("NOT_FOUND", "Tenant not found", 404)
		}
		id := bsStr(sub, "id")
		filters.subTenantID = &id
		realms, err := Subtree(ctx, server, tx, sub)
		if err != nil {
			return filters, nil, err
		}
		within = map[string]bool{}
		for _, realm := range realms {
			within[bsStr(realm, "id")] = true
		}
	}
	return filters, within, nil
}

// labelFor is the label of a report key (core.Undefined for none).
func (s *BillingService) labelFor(ctx context.Context, tx core.IamStore, groupBy string, key string, dir *core.Object, meterNames map[string]any) (any, error) {
	if strings.HasPrefix(key, "(") {
		return core.Undefined, nil
	}
	switch groupBy {
	case "identity", "agent":
		identity, err := tx.Get(ctx, "identities", key)
		if err != nil || identity == nil {
			return core.Undefined, err
		}
		if truthy(identity.Get("email")) {
			return jsString(identity.Get("name")) + " <" + jsString(identity.Get("email")) + ">", nil
		}
		return identity.Get("name"), nil
	case "team":
		return bsDirectoryName(dir, "teams", key), nil
	case "department":
		department := bsDirectoryGet(dir, "departments", key)
		if department == nil {
			return core.Undefined, nil
		}
		if truthy(department.Get("code")) {
			return jsString(department.Get("name")) + " (" + jsString(department.Get("code")) + ")", nil
		}
		return department.Get("name"), nil
	case "tenant":
		tenant, err := tx.Get(ctx, "tenants", key)
		if err != nil || tenant == nil {
			return core.Undefined, err
		}
		return tenant.Get("name"), nil
	case "meter":
		if name, ok := meterNames[key]; ok {
			return name, nil
		}
		return core.Undefined, nil
	}
	return core.Undefined, nil
}

// forecastOf projects the current period's total to its end (nil for other periods and the first day).
func (s *BillingService) forecastOf(period string, totalMicros float64) (*core.Object, error) {
	current, err := s.CurrentPeriod()
	if err != nil {
		return nil, err
	}
	if period != current {
		return nil, nil
	}
	bounds, err := PeriodBounds(period, s.tz)
	if err != nil {
		return nil, err
	}
	start, end := bsNum(bounds, "start"), bsNum(bounds, "end")
	elapsed := float64(s.server.Now()) - start
	if elapsed < 86_400_000 {
		return nil, nil
	}
	calc := &bsCalc{}
	costMicros := calc.micros((totalMicros * (end - start)) / elapsed)
	amount := calc.units(costMicros)
	if calc.err != nil {
		return nil, calc.err
	}
	return core.NewObject("costMicros", costMicros, "amount", amount), nil
}

type bsWeighted struct {
	row    *core.Object
	weight float64
}

// weightedRows are the weighted rows of a scope and period under validated filters.
func (s *BillingService) weightedRows(ctx context.Context, tx core.IamStore, scope *core.Object, period string, input *core.Object, cache map[string]any, rowFilter func(*core.Object) bool) ([]bsWeighted, *core.Object, bsFilters, error) {
	filters, within, err := s.validateFilters(ctx, tx, scope, input)
	if err != nil {
		return nil, nil, filters, err
	}
	spend, err := ScopeSpend(ctx, s.server, tx, scope, period, cache)
	if err != nil {
		return nil, nil, filters, err
	}
	rows := bsObjects(spend.Get("rows"))
	dir, err := s.directory(ctx, tx, rows, []string{bsStr(scope, "id")})
	if err != nil {
		return nil, nil, filters, err
	}
	weigh := s.weigher(filters, dir, within)
	var weighted []bsWeighted
	for _, row := range rows {
		if rowFilter != nil && !rowFilter(row) {
			continue
		}
		weight, err := weigh(row)
		if err != nil {
			return nil, nil, filters, err
		}
		if weight > 0 {
			weighted = append(weighted, bsWeighted{row, weight})
		}
	}
	return weighted, dir, filters, nil
}

// bsGroup is one group of a spend report while it is summed (SpendRow).
type bsGroup struct {
	key        string
	costMicros float64
	amount     float64
	share      float64
	events     float64
	quantities *core.Object
	shared     *float64
	label      any
}

// Report (billing-service.ts billingServiceOf().report): the spend of a scope in a period (SpendQuery), grouped,
// with shares, a forecast for the current period, and optionally the unattributed spend shared out (showback).
func (s *BillingService) Report(ctx context.Context, tx core.IamStore, scope *core.Object, query *core.Object, cache map[string]any, rowFilter func(*core.Object) bool) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if cache == nil {
		cache = map[string]any{}
	}
	calc := &bsCalc{}
	var period string
	if raw := member(query, "period"); isUndefined(raw) {
		if period, err = s.CurrentPeriod(); err != nil {
			return nil, err
		}
	} else if period, err = BillingPeriod(raw, "period"); err != nil {
		return nil, err
	}
	groupBy, err := bsSpendGroupBy(coalesce(member(query, "groupBy"), "meter"))
	if err != nil {
		return nil, err
	}
	weighted, dir, filters, err := s.weightedRows(ctx, tx, scope, period, query, cache, rowFilter)
	if err != nil {
		return nil, err
	}
	groups := map[string]*bsGroup{}
	var order []string
	add := func(key string, row *core.Object, weight float64) {
		group := groups[key]
		if group == nil {
			group = &bsGroup{key: key, quantities: core.NewObject()}
			groups[key] = group
			order = append(order, key)
		}
		group.costMicros += bsNum(row, "costMicros") * weight
		group.events += bsNum(row, "events")
		meter := jsString(row.Get("meter"))
		previous := 0.0
		if value := group.quantities.Get(meter); !nullish(value) {
			previous = jsNumber(value)
		}
		group.quantities.Set(meter, previous+bsNum(row, "quantity")*weight)
	}
	// Grouping by team under a team filter keeps to the filter's teams.
	var allowedTeams map[string]bool
	if filters.teamID != nil {
		allowedTeams = map[string]bool{*filters.teamID: true}
		if filters.rollUp == nil || *filters.rollUp {
			descendants, err := TeamDescendants(bsDirectoryValues(dir, "teams"), *filters.teamID)
			if err != nil {
				return nil, err
			}
			for _, team := range descendants {
				allowedTeams[bsStr(team, "id")] = true
			}
		}
	}
	totalMicros := 0.0
	events := 0.0
	for _, entry := range weighted {
		row, weight := entry.row, entry.weight
		totalMicros += bsNum(row, "costMicros") * weight
		events += bsNum(row, "events")
		switch groupBy {
		case "team":
			teamIDs := bsStrings(row.Get("teamIds"))
			if len(teamIDs) == 0 {
				add(bsUnattributedTeam, row, weight)
			}
			each := 1.0
			if !s.fullTeams() {
				each = 1 / float64(len(teamIDs))
			}
			for _, team := range teamIDs {
				if allowedTeams == nil || allowedTeams[team] {
					add(team, row, each)
				}
			}
		case "meter":
			add(jsString(row.Get("meter")), row, weight)
		case "identity":
			add(bsKeyOr(row.Get("identityId"), bsUnattributedIdentity), row, weight)
		case "agent":
			add(bsKeyOr(row.Get("agentId"), bsUnattributedAgent), row, weight)
		case "department":
			add(bsKeyOr(row.Get("departmentId"), bsUnattributedDepartment), row, weight)
		case "tenant":
			add(jsString(row.Get("tenantId")), row, weight)
		case "day":
			add(jsString(row.Get("day")), row, weight)
		default:
			tags, _ := row.Get("tags").(*core.Object)
			add(bsKeyOr(tags.Get(groupBy[4:]), bsUnattributedTag), row, weight)
		}
	}
	totalMicros = calc.micros(totalMicros)
	meterNames := map[string]any{}
	if groupBy == "meter" {
		for _, entry := range weighted {
			meterKey := jsString(entry.row.Get("meter"))
			if _, ok := meterNames[meterKey]; ok {
				continue
			}
			meter, err := tx.Get(ctx, BillingCollections.Meters, bsStr(entry.row, "meterId"))
			if err != nil {
				return nil, err
			}
			if meter != nil {
				meterNames[meterKey] = meter.Get("name")
			}
		}
	}
	// Shared costs: what no person, team or department used is spread over those that did, by their share of spend.
	var sharedMicros *float64
	shareUnattributed := member(query, "shareUnattributed")
	pool, hasPool := bsSharedPools[groupBy]
	if shareUnattributed == true && hasPool && groups[pool] != nil {
		unassigned := groups[pool]
		var others []*bsGroup
		for _, key := range order {
			if key != pool {
				others = append(others, groups[key])
			}
		}
		base := 0.0
		for _, group := range others {
			base += group.costMicros
		}
		if base > 0 {
			for _, group := range others {
				extra := (unassigned.costMicros * group.costMicros) / base
				group.costMicros += extra
				shared := calc.micros(extra)
				group.shared = &shared
			}
			total := calc.micros(unassigned.costMicros)
			sharedMicros = &total
			delete(groups, pool)
			order = slices.DeleteFunc(order, func(key string) bool { return key == pool })
		}
	} else if !isUndefined(shareUnattributed) {
		if _, ok := shareUnattributed.(bool); !ok {
			return nil, invalidInput("shareUnattributed must be a boolean")
		}
	}
	rows := make([]*bsGroup, 0, len(order))
	for _, key := range order {
		group := groups[key]
		group.costMicros = calc.micros(group.costMicros)
		group.amount = calc.units(group.costMicros)
		if totalMicros > 0 {
			group.share = bsOneDecimal((group.costMicros / totalMicros) * 100)
		} else {
			group.share = 0
		}
		for _, meter := range group.quantities.Keys() {
			group.quantities.Set(meter, bsMicroRound(jsNumber(group.quantities.Get(meter))))
		}
		label, err := s.labelFor(ctx, tx, groupBy, group.key, dir, meterNames)
		if err != nil {
			return nil, err
		}
		group.label = label
		rows = append(rows, group)
	}
	if calc.err != nil {
		return nil, calc.err
	}
	slices.SortStableFunc(rows, func(a, b *bsGroup) int {
		return bsOrder(b.costMicros-a.costMicros, bsKeyOrder(a.key, b.key))
	})
	if groupBy == "day" {
		slices.SortStableFunc(rows, func(a, b *bsGroup) int { return bsKeyOrder(a.key, b.key) })
	}
	bounds, err := PeriodBounds(period, s.tz)
	if err != nil {
		return nil, err
	}
	forecast, err := s.forecastOf(period, totalMicros)
	if err != nil {
		return nil, err
	}
	list := make([]any, len(rows))
	for index, group := range rows {
		row := core.NewObject("key", group.key, "costMicros", group.costMicros, "amount", group.amount,
			"share", group.share, "events", group.events, "quantities", group.quantities)
		if group.shared != nil {
			row.Set("sharedMicros", *group.shared)
		}
		if !isUndefined(group.label) {
			row.Set("label", group.label)
		}
		list[index] = row
	}
	totalAmount := calc.units(totalMicros)
	if calc.err != nil {
		return nil, calc.err
	}
	result = core.NewObject("tenantId", scope.Get("id"), "currency", s.Settings.Get("currency"), "period", period,
		"periodStart", bounds.Get("start"), "periodEnd", bounds.Get("end"), "groupBy", groupBy, "rows", list,
		"total", core.NewObject("costMicros", totalMicros, "amount", totalAmount, "events", events))
	if forecast != nil {
		result.Set("forecast", forecast)
	}
	if sharedMicros != nil {
		result.Set("sharedMicros", *sharedMicros)
	}
	return result, nil
}

// bsKeyOr is `value ?? fallback` for a group key.
func bsKeyOr(value any, fallback string) string {
	if nullish(value) {
		return fallback
	}
	return jsString(value)
}

// bsKeyOrder is `a < b ? -1 : 1`.
func bsKeyOrder(a, b string) int {
	if compareUTF16(a, b) < 0 {
		return -1
	}
	return 1
}

// Trend (billing-service.ts billingServiceOf().trend): monthly spend of a scope over the last `months` (1-24,
// default 6) periods under SpendFilters, with the forecast of the current one.
func (s *BillingService) Trend(ctx context.Context, tx core.IamStore, scope *core.Object, input *core.Object, rowFilter func(*core.Object) bool) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	months := 6.0
	if raw := member(input, "months"); !isUndefined(raw) {
		if months, err = Integer(raw, "months", 1, 24); err != nil {
			return nil, err
		}
	}
	cache := map[string]any{}
	current, err := s.CurrentPeriod()
	if err != nil {
		return nil, err
	}
	list := []any{}
	var last *core.Object
	for index := int(months) - 1; index >= 0; index-- {
		period, err := ShiftPeriod(current, float64(-index))
		if err != nil {
			return nil, err
		}
		last, err = s.Report(ctx, tx, scope, input.Spread(core.NewObject("period", period, "groupBy", "meter")), cache, rowFilter)
		if err != nil {
			return nil, err
		}
		total, _ := last.Get("total").(*core.Object)
		list = append(list, core.NewObject("period", last.Get("period"), "costMicros", total.Get("costMicros"), "amount", total.Get("amount")))
	}
	result = core.NewObject("tenantId", scope.Get("id"), "currency", s.Settings.Get("currency"), "months", list)
	if last != nil {
		if forecast, ok := last.Get("forecast").(*core.Object); ok && forecast != nil {
			result.Set("forecast", forecast)
		}
	}
	return result, nil
}

// --- budgets ---------------------------------------------------------------------------------------------------------

// subjectName is the name of a budget's subject (core.Undefined when it is gone).
func (s *BillingService) subjectName(ctx context.Context, tx core.IamStore, subjectType string, subjectID string) (any, error) {
	collection := ""
	switch subjectType {
	case "tenant":
		collection = "tenants"
	case "identity":
		collection = "identities"
	case "team":
		collection = "teams"
	case "department":
		collection = "departments"
	default:
		return core.Undefined, nil
	}
	record, err := tx.Get(ctx, collection, subjectID)
	if err != nil || record == nil {
		return core.Undefined, err
	}
	return record.Get("name"), nil
}

// BudgetStatus (billing-service.ts billingServiceOf().budgetStatus): a budget with its spend in the current window.
func (s *BillingService) BudgetStatus(ctx context.Context, tx core.IamStore, budget *core.Object, cache map[string]any) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if cache == nil {
		cache = map[string]any{}
	}
	server := s.server
	calc := &bsCalc{}
	current, err := s.CurrentPeriod()
	if err != nil {
		return nil, err
	}
	periods, err := WindowPeriods(jsString(budget.Get("period")), current)
	if err != nil {
		return nil, err
	}
	owner, err := server.Tenant(ctx, tx, budget.Get("tenantId"))
	if err != nil {
		return nil, err
	}
	subjectType := jsString(budget.Get("subjectType"))
	subjectID := jsString(budget.Get("subjectId"))
	scope := owner
	if subjectType == "tenant" {
		subject, err := tx.Get(ctx, "tenants", subjectID)
		if err != nil {
			return nil, err
		}
		if subject != nil {
			scope = subject
		}
	}
	_, metered := budget.Get("meters").([]any)
	meters := bsStrings(budget.Get("meters"))
	ownerID := bsStr(owner, "id")
	spent := 0.0
	for _, period := range periods {
		if period > current {
			break
		}
		spend, err := ScopeSpend(ctx, server, tx, scope, period, cache)
		if err != nil {
			return nil, err
		}
		rows := bsObjects(spend.Get("rows"))
		// Chargeback meters an account defines and prices for itself count toward its own budgets, never toward budgets
		// set above it (the platform's), which an organization could otherwise spend with made-up prices.
		foreign := map[*core.Object]bool{}
		for _, account := range bsObjects(spend.Get("accounts")) {
			accountID := jsString(account.Get("accountId"))
			if accountID == ownerID {
				continue
			}
			ancestors, err := server.AncestorIDs(ctx, tx, accountID)
			if err != nil {
				return nil, err
			}
			if containsString(ancestors, ownerID) {
				for _, row := range bsObjects(account.Get("rows")) {
					if truthy(row.Get("internal")) {
						foreign[row] = true
					}
				}
			}
		}
		var dir *core.Object
		if subjectType == "team" || subjectType == "department" {
			if dir, err = s.directory(ctx, tx, rows, []string{ownerID}); err != nil {
				return nil, err
			}
		}
		for _, row := range rows {
			if metered && !containsString(meters, jsString(row.Get("meter"))) {
				continue
			}
			if foreign[row] {
				continue
			}
			weight := 0.0
			switch subjectType {
			case "tenant":
				weight = 1
			case "identity":
				if bsIs(row.Get("identityId"), subjectID) || bsIs(row.Get("agentId"), subjectID) {
					weight = 1
				}
			case "team":
				if weight, err = TeamShare(row, subjectID, dir, s.Settings, true); err != nil {
					return nil, err
				}
			default:
				inside, err := InDepartment(row, subjectID, dir, true)
				if err != nil {
					return nil, err
				}
				if inside {
					weight = 1
				}
			}
			spent += bsNum(row, "costMicros") * weight
		}
	}
	spentMicros := calc.micros(spent)
	first, err := PeriodBounds(periods[0], s.tz)
	if err != nil {
		return nil, err
	}
	last, err := PeriodBounds(periods[len(periods)-1], s.tz)
	if err != nil {
		return nil, err
	}
	start, end := bsNum(first, "start"), bsNum(last, "end")
	elapsed := float64(server.Now()) - start
	var forecastMicros *float64
	if elapsed >= 86_400_000 {
		value := calc.micros((spentMicros * (end - start)) / elapsed)
		forecastMicros = &value
	}
	amountMicros := bsNum(budget, "amountMicros")
	percent := bsOneDecimal((spentMicros / amountMicros) * 100)
	name, err := s.subjectName(ctx, tx, subjectType, subjectID)
	if err != nil {
		return nil, err
	}
	amount := calc.units(amountMicros)
	spentUnits := calc.units(spentMicros)
	if calc.err != nil {
		return nil, calc.err
	}
	result = core.NewObject("budgetId", budget.Get("id"), "tenantId", budget.Get("tenantId"), "name", budget.Get("name"),
		"subjectType", budget.Get("subjectType"), "subjectId", budget.Get("subjectId"))
	if !isUndefined(name) {
		result.Set("subjectName", name)
	}
	result.Set("period", budget.Get("period"))
	result.Set("windowStart", periods[0])
	result.Set("windowEnd", periods[len(periods)-1])
	result.Set("amountMicros", budget.Get("amountMicros"))
	result.Set("amount", amount)
	result.Set("spentMicros", spentMicros)
	result.Set("spent", spentUnits)
	result.Set("percent", percent)
	if forecastMicros != nil {
		result.Set("forecastMicros", *forecastMicros)
		result.Set("forecastPercent", bsOneDecimal((*forecastMicros/amountMicros)*100))
	}
	thresholds, _ := budget.Get("thresholds").([]any)
	reached := []any{}
	for _, threshold := range thresholds {
		if spentMicros >= (amountMicros*jsNumber(threshold))/100 {
			reached = append(reached, threshold)
		}
	}
	result.Set("thresholds", budget.Get("thresholds"))
	result.Set("reached", reached)
	result.Set("exceeded", spentMicros >= amountMicros)
	result.Set("enforce", budget.Get("enforce"))
	if truthy(budget.Get("meters")) {
		result.Set("meters", budget.Get("meters"))
	}
	return result, nil
}

// cachedStatus is a budget's status for enforcement, cached briefly so checks on hot paths stay cheap.
func (s *BillingService) cachedStatus(ctx context.Context, tx core.IamStore, budget *core.Object, cache map[string]any) (*core.Object, error) {
	budgetID := jsString(budget.Get("id"))
	now := s.server.Now()
	s.statusMu.Lock()
	hit := s.statusCache[budgetID]
	s.statusMu.Unlock()
	if hit != nil && core.StrictEquals(hit.updatedAt, budget.Get("updatedAt")) && now-hit.at < bsStatusCacheMs {
		return hit.status, nil
	}
	status, err := s.BudgetStatus(ctx, tx, budget, cache)
	if err != nil {
		return nil, err
	}
	s.statusMu.Lock()
	defer s.statusMu.Unlock()
	if _, exists := s.statusCache[budgetID]; !exists {
		s.statusOrder = append(s.statusOrder, budgetID)
	}
	s.statusCache[budgetID] = &bsCachedStatus{at: now, updatedAt: budget.Get("updatedAt"), status: status}
	if len(s.statusCache) > 10_000 {
		oldest := s.statusOrder[0]
		s.statusOrder = s.statusOrder[1:]
		delete(s.statusCache, oldest)
	}
	return status, nil
}

// Check (billing-service.ts billingServiceOf().check): The enforced budgets covering usage in `tenant` (input
// `{ identityId?, meter? }`): tenant budgets on the tenant or an ancestor, the person's own budgets, and budgets of
// their teams (and parent teams) and departments. Refused once one is spent. Statuses may lag recorded usage by up to
// 30 seconds. The result is a SpendCheck: `{ allowed, budgets, blockedBy? }`.
func (s *BillingService) Check(ctx context.Context, tx core.IamStore, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	statuses, err := s.coveringStatuses(ctx, tx, tenant, member(input, "identityId"), member(input, "meter"), true)
	if err != nil {
		return nil, err
	}
	var blockedBy *core.Object
	for _, status := range statuses {
		if truthy(status.Get("exceeded")) {
			blockedBy = status
			break
		}
	}
	result = core.NewObject("allowed", blockedBy == nil, "budgets", bsList(statuses))
	if blockedBy != nil {
		result.Set("blockedBy", blockedBy)
	}
	return result, nil
}

// coveringStatuses is the (cached) standing of every budget covering usage in `tenant` by `identityID` (of `meter`).
func (s *BillingService) coveringStatuses(ctx context.Context, tx core.IamStore, tenant *core.Object, identityID any, meterValue any, enforcedOnly bool) ([]*core.Object, error) {
	server := s.server
	chain, err := server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return nil, err
	}
	chainIDs := map[string]bool{}
	for _, realm := range chain {
		chainIDs[bsStr(realm, "id")] = true
	}
	var identityIDs, teams, departments []string
	if !isUndefined(identityID) {
		id, err := Text(identityID, "identityId")
		if err != nil {
			return nil, err
		}
		identity, err := tx.Get(ctx, "identities", id)
		if err != nil {
			return nil, err
		}
		if identity != nil {
			person := bsStr(identity, "id")
			if bsIs(identity.Get("kind"), "agent") {
				if sponsor := member(identity.Get("agent"), "sponsorId"); truthy(sponsor) {
					person = jsString(sponsor)
				}
			}
			identityIDs = unique([]string{bsStr(identity, "id"), person})
			tenantID := bsStr(identity, "tenantId")
			if teams, err = TeamsOf(ctx, tx, tenantID, person, core.NewObject("at", float64(server.Now()), "includeAncestors", true)); err != nil {
				return nil, err
			}
			departmentID, err := DepartmentOf(ctx, tx, tenantID, person)
			if err != nil {
				return nil, err
			}
			if departmentID != "" {
				if departments, err = DepartmentPath(ctx, tx, tenantID, departmentID); err != nil {
					return nil, err
				}
			}
		}
	}
	var meter *string
	if !isUndefined(meterValue) {
		key, err := MeterKey(meterValue)
		if err != nil {
			return nil, err
		}
		meter = &key
	}
	cache := map[string]any{}
	var statuses []*core.Object
	for _, realm := range chain {
		filter := core.NewObject("tenantId", realm.Get("id"))
		if enforcedOnly {
			filter.Set("enforce", true)
		}
		budgets, err := tx.Find(ctx, BillingCollections.Budgets, filter, nil)
		if err != nil {
			return nil, err
		}
		for _, budget := range budgets {
			if _, metered := budget.Get("meters").([]any); metered && meter != nil && !containsString(bsStrings(budget.Get("meters")), *meter) {
				continue
			}
			subjectID := jsString(budget.Get("subjectId"))
			covers := false
			switch jsString(budget.Get("subjectType")) {
			case "tenant":
				covers = chainIDs[subjectID]
			case "identity":
				covers = containsString(identityIDs, subjectID)
			case "team":
				covers = containsString(teams, subjectID)
			default:
				covers = containsString(departments, subjectID)
			}
			if covers {
				status, err := s.cachedStatus(ctx, tx, budget, cache)
				if err != nil {
					return nil, err
				}
				statuses = append(statuses, status)
			}
		}
	}
	return statuses, nil
}

// SpendContext (billing-service.ts billingServiceOf().spendContext): Policy context: `principal.budgetsExceeded`
// names every spent budget that covers the principal in `tenant` (tenant budgets up the tree, and for a person of the
// tenant their own, their teams' and their department's), and `principal.spendExceeded` is true when one of them is
// enforced. Statuses may lag usage by up to 30 seconds. identityID "" is none.
func (s *BillingService) SpendContext(ctx context.Context, tx core.IamStore, tenant *core.Object, identityID string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	var identity any = core.Undefined
	if identityID != "" {
		identity = identityID
	}
	statuses, err := s.coveringStatuses(ctx, tx, tenant, identity, core.Undefined, false)
	if err != nil {
		return nil, err
	}
	enforced := false
	names := newOrderedSet()
	for _, status := range statuses {
		if !truthy(status.Get("exceeded")) {
			continue
		}
		if truthy(status.Get("enforce")) {
			enforced = true
		}
		names.Add(jsString(status.Get("name")))
	}
	return core.NewObject("principal.spendExceeded", enforced, "principal.budgetsExceeded", stringsOf(bsSortStrings(names.Values()))), nil
}

func (s *BillingService) emailsOf(ctx context.Context, tx core.IamStore, identityIDs []string) ([]string, error) {
	var result []string
	for _, identityID := range identityIDs {
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return nil, err
		}
		if identity != nil && bsIs(identity.Get("status"), "active") && truthy(identity.Get("email")) {
			result = append(result, jsString(identity.Get("email")))
		}
	}
	return result, nil
}

func (s *BillingService) owners(ctx context.Context, tx core.IamStore, tenantID string) ([]string, error) {
	found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "owner", true, "status", "active"), nil)
	if err != nil {
		return nil, err
	}
	var result []string
	for _, owner := range found {
		if truthy(owner.Get("email")) {
			result = append(result, jsString(owner.Get("email")))
		}
	}
	return result, nil
}

func (s *BillingService) budgetRecipients(ctx context.Context, tx core.IamStore, budget *core.Object) ([]string, error) {
	notify, _ := budget.Get("notify").(*core.Object)
	addresses := newOrderedSet(bsStrings(notify.Get("emails"))...)
	if truthy(notify.Get("owners")) {
		found, err := s.owners(ctx, tx, jsString(budget.Get("tenantId")))
		if err != nil {
			return nil, err
		}
		for _, address := range found {
			addresses.Add(address)
		}
	}
	if truthy(notify.Get("subject")) {
		var subjectIDs []string
		subjectID := jsString(budget.Get("subjectId"))
		switch jsString(budget.Get("subjectType")) {
		case "identity":
			subjectIDs = append(subjectIDs, subjectID)
		case "team":
			team, err := tx.Get(ctx, "teams", subjectID)
			if err != nil {
				return nil, err
			}
			if team != nil {
				maintainers, err := TeamMaintainers(ctx, tx, bsStr(team, "tenantId"), bsStr(team, "id"), s.server.Now())
				if err != nil {
					return nil, err
				}
				subjectIDs = append(subjectIDs, maintainers...)
			}
		case "department":
			department, err := tx.Get(ctx, "departments", subjectID)
			if err != nil {
				return nil, err
			}
			if department != nil {
				heads, err := DepartmentHeads(ctx, tx, bsStr(department, "tenantId"), bsStr(department, "id"), nil)
				if err != nil {
					return nil, err
				}
				subjectIDs = append(subjectIDs, heads...)
			}
		}
		emails, err := s.emailsOf(ctx, tx, subjectIDs)
		if err != nil {
			return nil, err
		}
		for _, address := range emails {
			addresses.Add(address)
		}
	}
	return bsSortStrings(addresses.Values()), nil
}

type bsAlert struct {
	kind      string
	threshold float64
}

// CheckBudgets (billing-service.ts billingServiceOf().checkBudgets): Alerts on budgets: every threshold reached in
// the current window (once each), and a forecast alert when the projection passes 100%. Each alert is audited as
// `billing:budget-alert` (webhooks can forward it) and, with an email transport, sent to the budget's recipients as
// `spend-alert`. A scheduler job; `tenantId` limits it to the budgets that tenant owns.
func (s *BillingService) CheckBudgets(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	server := s.server
	store := server.Store
	budgets, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		filter := core.NewObject()
		if raw := member(input, "tenantId"); !isUndefined(raw) {
			tenantID, err := Text(raw, "tenantId")
			if err != nil {
				return nil, err
			}
			filter.Set("tenantId", tenantID)
		}
		return tx.Find(ctx, BillingCollections.Budgets, filter, nil)
	})
	if err != nil {
		return nil, err
	}
	checked := 0
	alerts := []any{}
	cache := map[string]any{}
	slices.SortStableFunc(budgets, bsByID)
	for _, candidate := range budgets {
		err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			budget, err := tx.Get(ctx, BillingCollections.Budgets, bsStr(candidate, "id"))
			if err != nil || budget == nil {
				return err
			}
			owner, err := tx.Get(ctx, "tenants", jsString(budget.Get("tenantId")))
			if err != nil {
				return err
			}
			// Pending and suspended tenants can still spend; only deleted ones are done.
			if owner == nil || bsIs(owner.Get("status"), "deleted") {
				return nil
			}
			checked++
			status, err := s.BudgetStatus(ctx, tx, budget, cache)
			if err != nil {
				return err
			}
			var due []bsAlert
			reached, _ := status.Get("reached").([]any)
			for _, threshold := range reached {
				due = append(due, bsAlert{"actual", jsNumber(threshold)})
			}
			forecastPercent := 0.0
			if value := status.Get("forecastPercent"); !nullish(value) {
				forecastPercent = jsNumber(value)
			}
			if truthy(budget.Get("forecastAlerts")) && !truthy(status.Get("exceeded")) && forecastPercent >= 100 {
				due = append(due, bsAlert{"forecast", 100})
			}
			budgetID := jsString(budget.Get("id"))
			tenantID := jsString(budget.Get("tenantId"))
			windowStart := jsString(status.Get("windowStart"))
			var fired []bsAlert
			for _, alert := range due {
				uniqueKey := budgetID + ":" + windowStart + ":" + alert.kind + ":" + core.NumberString(alert.threshold)
				found, err := tx.Find(ctx, BillingCollections.BudgetAlerts, core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
				if err != nil {
					return err
				}
				if len(found) > 0 {
					continue
				}
				if _, err := tx.Insert(ctx, BillingCollections.BudgetAlerts, core.NewObject(
					"id", ID(), "tenantId", budget.Get("tenantId"), "uniqueKey", uniqueKey, "budgetId", budget.Get("id"),
					"window", status.Get("windowStart"), "kind", alert.kind, "threshold", alert.threshold,
					"spentMicros", status.Get("spentMicros"), "alertedAt", float64(server.Now()),
				)); err != nil {
					return err
				}
				fired = append(fired, alert)
			}
			if len(fired) == 0 {
				return nil
			}
			var recipients []string
			if s.sendsEmail() {
				if recipients, err = s.budgetRecipients(ctx, tx, budget); err != nil {
					return err
				}
			}
			// One email per check: the highest threshold newly reached (or the forecast warning).
			var actual []bsAlert
			for _, alert := range fired {
				if alert.kind == "actual" {
					actual = append(actual, alert)
				}
			}
			slices.SortStableFunc(actual, func(a, b bsAlert) int { return bsOrder(b.threshold-a.threshold, 0) })
			headline := fired[0]
			if len(actual) > 0 {
				headline = actual[0]
			}
			currency := s.currency()
			spentMicros := jsNumber(status.Get("spentMicros"))
			for _, to := range recipients {
				spentText, err := FormatMoney(spentMicros, currency)
				if err != nil {
					return err
				}
				amountText, err := FormatMoney(bsNum(budget, "amountMicros"), currency)
				if err != nil {
					return err
				}
				payload := core.NewObject("tenantId", budget.Get("tenantId"), "tenantName", owner.Get("name"),
					"budgetId", budget.Get("id"), "budgetName", budget.Get("name"), "subjectType", budget.Get("subjectType"),
					"subjectName", coalesce(status.Get("subjectName"), budget.Get("subjectId")), "kind", headline.kind,
					"threshold", core.NumberString(headline.threshold), "percent", jsString(status.Get("percent")),
					"spent", spentText, "amount", amountText)
				if forecast := status.Get("forecastMicros"); !isUndefined(forecast) {
					forecastText, err := FormatMoney(jsNumber(forecast), currency)
					if err != nil {
						return err
					}
					payload.Set("forecast", forecastText)
				}
				payload.Set("windowStart", status.Get("windowStart"))
				payload.Set("windowEnd", status.Get("windowEnd"))
				if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
					TenantID: tenantID, Kind: "email", To: to, Template: "spend-alert", Payload: payload,
				}); err != nil {
					return err
				}
			}
			for _, alert := range fired {
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(), "tenantId", budget.Get("tenantId"), "actorId", "deployment-operator",
					"action", "billing:budget-alert", "resourceId", "billing/budgets/"+budgetID,
					"timestamp", float64(server.Now()), "outcome", "allow",
					"metadata", core.NewObject("budgetId", budget.Get("id"), "name", budget.Get("name"), "kind", alert.kind,
						"threshold", alert.threshold, "spentMicros", status.Get("spentMicros"),
						"amountMicros", budget.Get("amountMicros"), "window", status.Get("windowStart"),
						"recipients", float64(len(recipients))),
				)); err != nil {
					return err
				}
				alerts = append(alerts, core.NewObject("budgetId", budget.Get("id"), "tenantId", budget.Get("tenantId"),
					"name", budget.Get("name"), "kind", alert.kind, "threshold", alert.threshold,
					"spentMicros", status.Get("spentMicros"), "recipients", float64(len(recipients))))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return core.NewObject("checked", float64(checked), "alerts", alerts), nil
}

// --- statements ------------------------------------------------------------------------------------------------------

type bsWeightedKey struct {
	key    string
	weight float64
}

// allocations sums rows' cost by key for a statement breakdown, largest first.
func bsAllocations(calc *bsCalc, rows []*core.Object, keyOf func(row *core.Object) []bsWeightedKey, names func(key string) any, limit int) []*core.Object {
	totals := map[string]float64{}
	var order []string
	for _, row := range rows {
		for _, entry := range keyOf(row) {
			if _, ok := totals[entry.key]; !ok {
				order = append(order, entry.key)
			}
			totals[entry.key] += bsNum(row, "costMicros") * entry.weight
		}
	}
	var list []*core.Object
	for _, key := range order {
		costMicros := calc.micros(totals[key])
		if costMicros <= 0 {
			continue
		}
		list = append(list, core.NewObject("id", key, "name", coalesce(names(key), key), "costMicros", costMicros))
	}
	slices.SortStableFunc(list, func(a, b *core.Object) int {
		return bsOrder(bsNum(b, "costMicros")-bsNum(a, "costMicros"), bsKeyOrder(bsStr(a, "id"), bsStr(b, "id")))
	})
	if limit > 0 && len(list) > limit {
		list = list[:limit]
	}
	return list
}

// usageLines are the usage lines of an invoice: the billable meters, with the tiers and free units their quantity used.
func bsUsageLines(calc *bsCalc, charges []*core.Object) ([]any, error) {
	lines := []any{}
	for _, charge := range charges {
		if truthy(charge.Get("internal")) {
			continue
		}
		quantity := bsNum(charge, "quantity")
		amountMicros := bsNum(charge, "amountMicros")
		line := core.NewObject("meter", charge.Get("meter"), "name", charge.Get("name"), "unit", charge.Get("unit"),
			"quantity", bsMicroRound(quantity),
			// Invoices bill whole cents; the spend reports keep the exact amount.
			"amountMicros", calc.cents(amountMicros), "pricing", charge.Get("pricing"))
		if price, ok := charge.Get("price").(*core.Object); ok && price != nil {
			spec, _ := price.Get("spec").(*core.Object)
			linePrice := core.NewObject("model", spec.Get("model"), "effectiveFrom", price.Get("effectiveFrom"))
			if bsIs(price.Get("source"), "plan") {
				linePrice.Set("source", "plan")
			}
			line.Set("price", linePrice)
			breakdown, err := PriceBreakdown(spec, quantity)
			if err != nil {
				return nil, err
			}
			if bsIs(spec.Get("model"), "per-unit") {
				line.Set("unitAmountMicros", coalesce(spec.Get("unitAmountMicros"), 0.0))
			}
			if tiers, _ := breakdown.Get("tiers").([]any); len(tiers) > 0 {
				line.Set("tiers", tiers)
			}
			if included := breakdown.Get("includedQuantity"); !isUndefined(included) {
				line.Set("includedQuantity", included)
			}
			if raw := breakdown.Get("rawMicros"); !core.StrictEquals(raw, charge.Get("amountMicros")) {
				line.Set("adjustedFromMicros", raw)
			}
		}
		if truthy(charge.Get("unpriced")) {
			line.Set("unpriced", true)
		}
		lines = append(lines, line)
	}
	return lines, nil
}

// pendingItems are the pending invoice items the account's invoice for `period` bills: those without a period or for
// it or before.
func (s *BillingService) pendingItems(ctx context.Context, tx core.IamStore, accountID string, period string) ([]*core.Object, error) {
	found, err := tx.Find(ctx, BillingCollections.InvoiceItems, core.NewObject("tenantId", accountID, "status", "pending"), nil)
	if err != nil {
		return nil, err
	}
	var items []*core.Object
	for _, item := range found {
		itemPeriod := item.Get("period")
		if isUndefined(itemPeriod) || jsString(itemPeriod) <= period {
			items = append(items, item)
		}
	}
	slices.SortStableFunc(items, func(a, b *core.Object) int {
		return bsOrder(bsNum(a, "createdAt")-bsNum(b, "createdAt"), bsKeyOrder(bsStr(a, "id"), bsStr(b, "id")))
	})
	return items, nil
}

func bsInvoiceItemLine(item *core.Object) *core.Object {
	line := core.NewObject("kind", "item", "name", item.Get("description"), "unit", "unit", "quantity", item.Get("quantity"),
		"unitAmountMicros", item.Get("unitAmountMicros"), "amountMicros", item.Get("amountMicros"), "invoiceItemId", item.Get("id"))
	if subscriptionID := item.Get("subscriptionId"); !isUndefined(subscriptionID) {
		line.Set("subscriptionId", subscriptionID)
	}
	if bsIs(item.Get("source"), "proration") {
		line.Set("description", "Proration")
	}
	return line
}

// DraftStatement (billing-service.ts billingServiceOf().draftStatement): Builds (without storing) an account's
// invoice (a StatementDraft). The monthly invoice for `period` bills the month's usage, the subscriptions' fees and
// seats (arrears for the month, advance for the next), and pending invoice items, and the minimum commitment applies;
// a subscription's first invoice (`first`: `{ lines, subscriptionId }`) bills its first month's advance lines. Then
// the contract discount, coupons, credit (earliest expiry first) and tax.
func (s *BillingService) DraftStatement(ctx context.Context, tx core.IamStore, account *core.Object, period string, cache map[string]any, first *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if cache == nil {
		cache = map[string]any{}
	}
	server := s.server
	calc := &bsCalc{}
	accountID := bsStr(account, "id")
	bounds, err := PeriodBounds(period, s.tz)
	if err != nil {
		return nil, err
	}
	lines := []any{}
	var rows []*core.Object
	invoiceItemIDs := []any{}
	advanceBilled := []any{}
	if first != nil {
		lines = append(lines, bsAnyList(first.Get("lines"))...)
		advanceBilled = []any{core.NewObject("subscriptionId", first.Get("subscriptionId"), "period", period)}
	} else {
		spend, err := AccountSpend(ctx, server, tx, account, period, cache)
		if err != nil {
			return nil, err
		}
		usage, err := bsUsageLines(calc, bsObjects(spend.Get("charges")))
		if err != nil {
			return nil, err
		}
		lines = append(lines, usage...)
		for _, row := range bsObjects(spend.Get("rows")) {
			if !truthy(row.Get("internal")) {
				rows = append(rows, row)
			}
		}
		recurring, err := SubscriptionLines(ctx, tx, accountID, period, s.tz)
		if err != nil {
			return nil, err
		}
		lines = append(lines, bsAnyList(recurring.Get("lines"))...)
		advanceBilled = append([]any{}, bsAnyList(recurring.Get("advance"))...)
		items, err := s.pendingItems(ctx, tx, accountID, period)
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			lines = append(lines, bsInvoiceItemLine(item))
			invoiceItemIDs = append(invoiceItemIDs, item.Get("id"))
		}
	}
	sum := 0.0
	for _, line := range lines {
		sum += jsNumber(member(line, "amountMicros"))
	}
	subtotalMicros := calc.micros(sum)
	if calc.err != nil {
		return nil, calc.err
	}
	start := bsNum(bounds, "start")
	allCredits, err := tx.Find(ctx, BillingCollections.Credits, core.NewObject("tenantId", accountID), nil)
	if err != nil {
		return nil, err
	}
	var credits []*core.Object
	for _, credit := range allCredits {
		// Any credit that is live when the statement is drawn up and was valid at some point in the period.
		expiresAt := credit.Get("expiresAt")
		if isUndefined(credit.Get("revokedAt")) && bsNum(credit, "remainingMicros") > 0 && (isUndefined(expiresAt) || jsNumber(expiresAt) > start) {
			credits = append(credits, credit)
		}
	}
	expiry := func(credit *core.Object) float64 {
		value := credit.Get("expiresAt")
		if nullish(value) {
			return maxSafeInteger
		}
		return jsNumber(value)
	}
	slices.SortStableFunc(credits, func(a, b *core.Object) int {
		return bsOrder(expiry(a)-expiry(b), bsOrder(bsNum(a, "grantedAt")-bsNum(b, "grantedAt"), bsKeyOrder(bsStr(a, "id"), bsStr(b, "id"))))
	})
	allDiscounts, err := tx.Find(ctx, BillingCollections.Discounts, core.NewObject("tenantId", accountID), nil)
	if err != nil {
		return nil, err
	}
	var discounts []*core.Object
	for _, discount := range allDiscounts {
		active, err := DiscountActive(discount, period, s.tz)
		if err != nil {
			return nil, err
		}
		if active {
			discounts = append(discounts, discount)
		}
	}
	slices.SortStableFunc(discounts, func(a, b *core.Object) int {
		return bsOrder(bsNum(a, "redeemedAt")-bsNum(b, "redeemedAt"), bsKeyOrder(bsStr(a, "id"), bsStr(b, "id")))
	})
	creditsApplied := []any{}
	terms, err := AccountTermsOf(ctx, server, tx, account)
	if err != nil {
		return nil, err
	}
	amountsInput := core.NewObject("subtotalMicros", subtotalMicros)
	if terms != nil {
		amountsInput.Set("terms", terms)
	} else {
		amountsInput.Set("terms", core.Undefined)
	}
	amountsInput.Set("commitment", first == nil)
	amountsInput.Set("discounts", bsList(discounts))
	amountsInput.SetRaw("credit", func(dueMicros float64) float64 {
		due := dueMicros
		for _, credit := range credits {
			if due <= 0 {
				break
			}
			amount := calc.micros(bsMin(due, bsNum(credit, "remainingMicros")))
			creditsApplied = append(creditsApplied, core.NewObject("creditId", credit.Get("id"), "amountMicros", amount))
			due = calc.micros(due - amount)
		}
		return calc.micros(dueMicros - due)
	})
	computed, err := InvoiceAmounts(amountsInput)
	if err != nil {
		return nil, err
	}
	if calc.err != nil {
		return nil, calc.err
	}
	carryForwardMicros := computed.Get("carryForwardMicros")
	amounts := computed.Clone()
	amounts.Delete("carryForwardMicros")
	dir, err := s.directory(ctx, tx, rows, []string{accountID})
	if err != nil {
		return nil, err
	}
	tenantNames := map[string]any{}
	for _, row := range rows {
		tenantID := bsStr(row, "tenantId")
		if _, ok := tenantNames[tenantID]; ok {
			continue
		}
		realm, err := tx.Get(ctx, "tenants", tenantID)
		if err != nil {
			return nil, err
		}
		if realm != nil && !nullish(realm.Get("name")) {
			tenantNames[tenantID] = realm.Get("name")
		} else {
			tenantNames[tenantID] = tenantID
		}
	}
	identityNames := map[string]any{}
	for _, row := range rows {
		key := coalesce(row.Get("agentId"), row.Get("identityId"))
		if !truthy(key) {
			continue
		}
		id := jsString(key)
		if _, ok := identityNames[id]; ok {
			continue
		}
		identity, err := tx.Get(ctx, "identities", id)
		if err != nil {
			return nil, err
		}
		if identity != nil && !nullish(identity.Get("name")) {
			identityNames[id] = identity.Get("name")
		} else {
			identityNames[id] = id
		}
	}
	profile, err := ProfileOf(ctx, tx, accountID)
	if err != nil {
		return nil, err
	}
	var emails any
	if profileEmails, _ := profile.Get("billingEmails").([]any); len(profileEmails) > 0 {
		emails = profile.Get("billingEmails")
	} else {
		found, err := s.owners(ctx, tx, accountID)
		if err != nil {
			return nil, err
		}
		emails = stringsOf(found)
	}
	lookup := func(names map[string]any) func(key string) any {
		return func(key string) any {
			if name, ok := names[key]; ok {
				return name
			}
			return core.Undefined
		}
	}
	teamWeight := func(row *core.Object) float64 {
		if s.fullTeams() {
			return 1
		}
		return 1 / float64(len(bsStrings(row.Get("teamIds"))))
	}
	tenants := bsAllocations(calc, rows, func(row *core.Object) []bsWeightedKey {
		return []bsWeightedKey{{bsStr(row, "tenantId"), 1}}
	}, lookup(tenantNames), 0)
	teams := bsAllocations(calc, rows, func(row *core.Object) []bsWeightedKey {
		var keys []bsWeightedKey
		for _, team := range bsStrings(row.Get("teamIds")) {
			keys = append(keys, bsWeightedKey{team, teamWeight(row)})
		}
		return keys
	}, func(key string) any { return bsDirectoryName(dir, "teams", key) }, 50)
	departments := bsAllocations(calc, rows, func(row *core.Object) []bsWeightedKey {
		if departmentID := row.Get("departmentId"); truthy(departmentID) {
			return []bsWeightedKey{{jsString(departmentID), 1}}
		}
		return nil
	}, func(key string) any { return bsDirectoryName(dir, "departments", key) }, 50)
	for _, entry := range departments {
		if costCenter := member(bsDirectoryGet(dir, "departments", bsStr(entry, "id")), "costCenter"); truthy(costCenter) {
			entry.Set("costCenter", costCenter)
		}
	}
	identities := bsAllocations(calc, rows, func(row *core.Object) []bsWeightedKey {
		if key := coalesce(row.Get("agentId"), row.Get("identityId")); truthy(key) {
			return []bsWeightedKey{{jsString(key), 1}}
		}
		return nil
	}, lookup(identityNames), 50)
	if calc.err != nil {
		return nil, calc.err
	}
	billTo := core.NewObject("name", account.Get("name"))
	for _, key := range []string{"companyName", "taxId", "address", "purchaseOrder", "costCenter"} {
		if value := profile.Get(key); truthy(value) {
			billTo.Set(key, value)
		}
	}
	billTo.Set("emails", emails)
	billingReason := "period"
	if first != nil {
		billingReason = "subscription"
	}
	paymentTermsDays := coalesce(profile.Get("paymentTermsDays"), s.Settings.Get("paymentTermsDays"))
	result = core.NewObject("accountId", account.Get("id"), "period", period, "currency", s.Settings.Get("currency"),
		"periodStart", bounds.Get("start"), "periodEnd", bounds.Get("end"), "lines", lines, "billingReason", billingReason,
		"subtotalMicros", subtotalMicros)
	result.Assign(amounts)
	result.Set("creditsApplied", creditsApplied)
	result.Set("breakdown", core.NewObject("tenants", bsList(tenants), "teams", bsList(teams),
		"departments", bsList(departments), "identities", bsList(identities)))
	result.Set("billTo", billTo)
	result.Set("paymentTermsDays", paymentTermsDays)
	result.Set("invoiceItemIds", invoiceItemIDs)
	result.Set("advanceBilled", advanceBilled)
	result.Set("carryForwardMicros", carryForwardMicros)
	return result, nil
}

// bsAnyList is a model array (nil for anything else).
func bsAnyList(value any) []any {
	list, _ := value.([]any)
	return list
}

// bsDraftBody splits a StatementDraft into its statement body and the members only the draft has.
func bsDraftBody(draft *core.Object) (body *core.Object, paymentTermsDays float64, carryForwardMicros float64, invoiceItemIDs []any, advanceBilled []any) {
	body = draft.Clone()
	for _, key := range []string{"accountId", "paymentTermsDays", "carryForwardMicros", "invoiceItemIds", "advanceBilled"} {
		body.Delete(key)
	}
	return body, bsNum(draft, "paymentTermsDays"), bsNum(draft, "carryForwardMicros"),
		bsAnyList(draft.Get("invoiceItemIds")), bsAnyList(draft.Get("advanceBilled"))
}

// saveDraft stores (or refreshes) a monthly invoice as a draft: no number, nothing consumed yet.
func (s *BillingService) saveDraft(ctx context.Context, tx core.IamStore, account *core.Object, draft *core.Object, existing *core.Object) (*core.Object, error) {
	body, paymentTermsDays, _, invoiceItemIDs, advanceBilled := bsDraftBody(draft)
	now := float64(s.server.Now())
	var id any
	if existing != nil {
		id = existing.Get("id")
	} else {
		id = ID()
	}
	record := core.NewObject("id", id, "tenantId", account.Get("id"), "uniqueKey", "period:"+jsString(draft.Get("period")),
		"number", "", "status", "draft", "issuedAt", now, "dueAt", now+paymentTermsDays*86_400_000, "hash", "")
	record.Assign(body)
	if len(invoiceItemIDs) > 0 {
		record.Set("invoiceItemIds", invoiceItemIDs)
	}
	if len(advanceBilled) > 0 {
		record.Set("advanceBilled", advanceBilled)
	}
	if existing != nil {
		return tx.Put(ctx, BillingCollections.Statements, record)
	}
	return tx.Insert(ctx, BillingCollections.Statements, record)
}

// issue finalizes an invoice: numbers it (`{prefix}-{YYYYMM}-{sequence}`), seals its content hash, draws the credit
// it uses, turns a negative balance into account credit, marks its invoice items invoiced and its advance months
// billed, counts its coupons, emails the billing contacts (`billing-statement`) and audits `billing:statement`. An
// invoice with nothing to pay is paid on issue. actorID "" is the deployment operator.
func (s *BillingService) issue(ctx context.Context, tx core.IamStore, account *core.Object, draft *core.Object, uniqueKey string, existing *core.Object, actorID string) (*core.Object, int, error) {
	server := s.server
	calc := &bsCalc{}
	if actorID == "" {
		actorID = "deployment-operator"
	}
	accountID := bsStr(account, "id")
	period := jsString(draft.Get("period"))
	found, err := tx.Find(ctx, BillingCollections.Statements, core.NewObject("period", draft.Get("period")), nil)
	if err != nil {
		return nil, 0, err
	}
	numbered := 0
	for _, statement := range found {
		if truthy(statement.Get("number")) {
			numbered++
		}
	}
	number := jsString(s.Settings.Get("statementPrefix")) + "-" + strings.Replace(period, "-", "", 1) + "-" + bsPad(numbered+1, 4)
	issuedAt := float64(server.Now())
	content, paymentTermsDays, carryForwardMicros, invoiceItemIDs, advanceBilled := bsDraftBody(draft)
	var carryForward *core.Object
	if carryForwardMicros > 0 {
		credit, err := tx.Insert(ctx, BillingCollections.Credits, core.NewObject(
			"id", ID(), "tenantId", accountID, "amountMicros", carryForwardMicros, "remainingMicros", carryForwardMicros,
			"reason", "Credit balance from "+number, "grantedAt", issuedAt, "grantedBy", actorID,
		))
		if err != nil {
			return nil, 0, err
		}
		carryForward = core.NewObject("creditId", credit.Get("id"), "amountMicros", carryForwardMicros)
	}
	settled := bsNum(content, "totalMicros") <= 0
	var id any
	if existing != nil {
		id = existing.Get("id")
	} else {
		id = ID()
	}
	status := "finalized"
	if settled {
		status = "paid"
	}
	record := core.NewObject("id", id, "tenantId", accountID, "uniqueKey", uniqueKey, "number", number, "status", status,
		"issuedAt", issuedAt, "dueAt", issuedAt+paymentTermsDays*86_400_000)
	record.Assign(content)
	if len(invoiceItemIDs) > 0 {
		record.Set("invoiceItemIds", invoiceItemIDs)
	}
	if len(advanceBilled) > 0 {
		record.Set("advanceBilled", advanceBilled)
	}
	if carryForward != nil {
		record.Set("carryForward", carryForward)
	}
	if settled {
		record.Set("paidAt", issuedAt)
	}
	hash, err := StatementHash(content.Spread(core.NewObject("number", number, "tenantId", accountID)))
	if err != nil {
		return nil, 0, err
	}
	record.Set("hash", hash)
	var statement *core.Object
	if existing != nil {
		statement, err = tx.Put(ctx, BillingCollections.Statements, record)
	} else {
		statement, err = tx.Insert(ctx, BillingCollections.Statements, record)
	}
	if err != nil {
		return nil, 0, err
	}
	for _, applied := range bsObjects(content.Get("creditsApplied")) {
		credit, err := tx.Get(ctx, BillingCollections.Credits, jsString(applied.Get("creditId")))
		if err != nil {
			return nil, 0, err
		}
		if credit != nil {
			next := credit.Clone()
			next.Set("remainingMicros", calc.micros(bsMax(0, bsNum(credit, "remainingMicros")-bsNum(applied, "amountMicros"))))
			if calc.err != nil {
				return nil, 0, calc.err
			}
			if _, err := tx.Put(ctx, BillingCollections.Credits, next); err != nil {
				return nil, 0, err
			}
		}
	}
	for _, itemID := range invoiceItemIDs {
		item, err := tx.Get(ctx, BillingCollections.InvoiceItems, jsString(itemID))
		if err != nil {
			return nil, 0, err
		}
		if item != nil && bsIs(item.Get("status"), "pending") {
			next := item.Clone()
			next.Set("status", "invoiced")
			next.Set("statementId", statement.Get("id"))
			if _, err := tx.Put(ctx, BillingCollections.InvoiceItems, next); err != nil {
				return nil, 0, err
			}
		}
	}
	for _, entry := range bsObjects(advanceBilled) {
		subscription, err := tx.Get(ctx, BillingCollections.Subscriptions, jsString(entry.Get("subscriptionId")))
		if err != nil {
			return nil, 0, err
		}
		entryPeriod := jsString(entry.Get("period"))
		if subscription != nil && !containsString(bsStrings(subscription.Get("billedAdvance")), entryPeriod) {
			next := subscription.Clone()
			billed := append(append([]string{}, bsStrings(subscription.Get("billedAdvance"))...), entryPeriod)
			next.Set("billedAdvance", stringsOf(bsSortStrings(billed)))
			if _, err := tx.Put(ctx, BillingCollections.Subscriptions, next); err != nil {
				return nil, 0, err
			}
		}
	}
	for _, coupon := range bsObjects(content.Get("coupons")) {
		discount, err := tx.Get(ctx, BillingCollections.Discounts, jsString(coupon.Get("discountId")))
		if err != nil {
			return nil, 0, err
		}
		if discount != nil {
			next := discount.Clone()
			next.Set("appliedInvoices", bsNum(discount, "appliedInvoices")+1)
			if bsIs(discount.Get("duration"), "once") {
				next.Set("endedAt", issuedAt)
			}
			if _, err := tx.Put(ctx, BillingCollections.Discounts, next); err != nil {
				return nil, 0, err
			}
		}
	}
	var recipients []string
	if s.sendsEmail() {
		billTo, _ := content.Get("billTo").(*core.Object)
		recipients = bsStrings(billTo.Get("emails"))
	}
	currency := s.currency()
	for _, to := range recipients {
		total, err := FormatMoney(bsNum(statement, "totalMicros"), currency)
		if err != nil {
			return nil, 0, err
		}
		subtotal, err := FormatMoney(bsNum(statement, "subtotalMicros"), currency)
		if err != nil {
			return nil, 0, err
		}
		creditsText, err := FormatMoney(bsNum(statement, "creditsMicros"), currency)
		if err != nil {
			return nil, 0, err
		}
		payload := core.NewObject("tenantId", accountID, "tenantName", account.Get("name"), "statementId", statement.Get("id"),
			"number", number, "period", content.Get("period"), "total", total, "subtotal", subtotal, "credits", creditsText,
			"dueAt", bsIsoDate(bsNum(statement, "dueAt")))
		if bsIs(content.Get("billingReason"), "subscription") {
			payload.Set("reason", "subscription")
		}
		if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: accountID, Kind: "email", To: to, Template: "billing-statement", Payload: payload,
		}); err != nil {
			return nil, 0, err
		}
	}
	if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
		"id", ID(), "tenantId", accountID, "actorId", actorID, "action", "billing:statement",
		"resourceId", "billing/statements/"+jsString(statement.Get("id")), "timestamp", issuedAt, "outcome", "allow",
		"metadata", core.NewObject("number", number, "period", content.Get("period"),
			"billingReason", coalesce(content.Get("billingReason"), "period"),
			"subtotalMicros", statement.Get("subtotalMicros"), "creditsMicros", statement.Get("creditsMicros"),
			"totalMicros", statement.Get("totalMicros"), "invoiceItems", float64(len(invoiceItemIDs)),
			"recipients", float64(len(recipients))),
	)); err != nil {
		return nil, 0, err
	}
	return statement, len(recipients), nil
}

// bsBillable is whether a monthly invoice has something to bill: lines, or a minimum commitment the month fell short
// of.
func bsBillable(draft *core.Object) bool {
	if len(bsAnyList(draft.Get("lines"))) > 0 {
		return true
	}
	trueUp := member(draft.Get("commitment"), "trueUpMicros")
	return !nullish(trueUp) && jsNumber(trueUp) > 0
}

// FinalizeDraft (billing-service.ts billingServiceOf().finalizeDraft): Finalizes a draft invoice, recomputed first so
// late usage and new invoice items are on it. Returns `{ statement, recipients }`; actorID "" is the deployment
// operator.
func (s *BillingService) FinalizeDraft(ctx context.Context, tx core.IamStore, statement *core.Object, actorID string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if !bsIs(statement.Get("status"), "draft") {
		return nil, core.NewIamError("INVALID_TRANSITION", "The invoice is "+jsString(statement.Get("status")), 409)
	}
	account, err := s.server.Tenant(ctx, tx, statement.Get("tenantId"))
	if err != nil {
		return nil, err
	}
	period := jsString(statement.Get("period"))
	draft, err := s.DraftStatement(ctx, tx, account, period, nil, nil)
	if err != nil {
		return nil, err
	}
	if !bsBillable(draft) {
		return nil, core.NewIamError("INVALID_TRANSITION", "The invoice has nothing left to bill", 409)
	}
	issued, recipients, err := s.issue(ctx, tx, account, draft, "period:"+period, statement, actorID)
	if err != nil {
		return nil, err
	}
	return core.NewObject("statement", issued, "recipients", float64(recipients)), nil
}

// sweepUsage deletes raw usage events past their retention (daily roll-ups and statements stay).
func (s *BillingService) sweepUsage(ctx context.Context) (int, error) {
	swept := 0
	for round := 0; round < 50; round++ {
		batch, err := core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (int, error) {
			to := float64(s.server.Now())
			limit := 500
			due, err := core.FindOrdered(ctx, tx, BillingCollections.Usage, core.NewObject(), core.OrderOptions{Field: "expiresAt", To: &to, Limit: &limit}, nil)
			if err != nil {
				return 0, err
			}
			for _, record := range due {
				if err := tx.Delete(ctx, BillingCollections.Usage, bsStr(record, "id")); err != nil {
					return 0, err
				}
			}
			return len(due), nil
		})
		if err != nil {
			return 0, err
		}
		swept += batch
		if batch < 500 {
			break
		}
	}
	return swept, nil
}

// ClosePeriod (billing-service.ts billingServiceOf().closePeriod): Invoices a past period (default the previous
// one): one invoice per billing account with something to bill (usage of meters defined above it, subscription fees
// and seats, pending invoice items, a minimum commitment the month fell short of). Accounts already invoiced for the
// period are skipped, so the job can run daily. With `draft` (default: `!billing.autoFinalize`) invoices are kept as
// drafts, refreshed on every run, until finalized. Usage for a finalized period is refused afterwards
// (BILLING_PERIOD_CLOSED); void the invoice to reopen it. Also deletes raw usage events past their retention. input
// is `{ period?, tenantId?, draft? }`.
func (s *BillingService) ClosePeriod(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	server := s.server
	store := server.Store
	current, err := s.CurrentPeriod()
	if err != nil {
		return nil, err
	}
	var period string
	if raw := member(input, "period"); isUndefined(raw) {
		if period, err = ShiftPeriod(current, -1); err != nil {
			return nil, err
		}
	} else if period, err = BillingPeriod(raw, "period"); err != nil {
		return nil, err
	}
	if period >= current {
		return nil, invalidInput("Only periods that have ended can be closed")
	}
	rawDraft := member(input, "draft")
	if !isUndefined(rawDraft) {
		if _, ok := rawDraft.(bool); !ok {
			return nil, invalidInput("draft must be a boolean")
		}
	}
	draftOnly := !truthy(s.Settings.Get("autoFinalize"))
	if value, ok := rawDraft.(bool); ok {
		draftOnly = value
	}
	bounds, err := PeriodBounds(period, s.tz)
	if err != nil {
		return nil, err
	}
	nextPeriod, err := ShiftPeriod(period, 1)
	if err != nil {
		return nil, err
	}
	next, err := PeriodBounds(nextPeriod, s.tz)
	if err != nil {
		return nil, err
	}
	accounts, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		found := map[string]*core.Object{}
		add := func(tenantID string) error {
			realm, err := tx.Get(ctx, "tenants", tenantID)
			if err != nil || realm == nil {
				return err
			}
			account, err := AccountOf(ctx, server, tx, realm)
			if err != nil {
				return err
			}
			found[bsStr(account, "id")] = account
			return nil
		}
		if raw := member(input, "tenantId"); !isUndefined(raw) {
			tenantID, err := Text(raw, "tenantId")
			if err != nil {
				return nil, err
			}
			tenant, err := server.Tenant(ctx, tx, tenantID)
			if err != nil {
				return nil, err
			}
			if err := add(bsStr(tenant, "id")); err != nil {
				return nil, err
			}
		} else {
			tenantIDs := newOrderedSet()
			rollups, err := tx.Find(ctx, BillingCollections.Rollups, core.NewObject("period", period), nil)
			if err != nil {
				return nil, err
			}
			for _, rollup := range rollups {
				tenantIDs.Add(bsStr(rollup, "tenantId"))
			}
			// Subscriptions running in the period or the next (advance billing), and pending invoice items.
			subscriptions, err := tx.Find(ctx, BillingCollections.Subscriptions, nil, nil)
			if err != nil {
				return nil, err
			}
			for _, subscription := range subscriptions {
				endsAt := subscription.Get("endsAt")
				if bsNum(subscription, "startedAt") < bsNum(next, "end") && (isUndefined(endsAt) || jsNumber(endsAt) > bsNum(bounds, "start")) {
					tenantIDs.Add(bsStr(subscription, "tenantId"))
				}
			}
			items, err := tx.Find(ctx, BillingCollections.InvoiceItems, core.NewObject("status", "pending"), nil)
			if err != nil {
				return nil, err
			}
			for _, item := range items {
				itemPeriod := item.Get("period")
				if isUndefined(itemPeriod) || jsString(itemPeriod) <= period {
					tenantIDs.Add(bsStr(item, "tenantId"))
				}
			}
			// A minimum commitment is owed even for a month without usage (terms apply to invoices issued after them).
			allTerms, err := tx.Find(ctx, BillingCollections.Terms, nil, nil)
			if err != nil {
				return nil, err
			}
			for _, terms := range allTerms {
				if !truthy(terms.Get("minimumCommitmentMicros")) {
					continue
				}
				realm, err := tx.Get(ctx, "tenants", bsStr(terms, "tenantId"))
				if err != nil {
					return nil, err
				}
				if realm == nil || !bsIs(realm.Get("status"), "deleted") {
					tenantIDs.Add(bsStr(terms, "tenantId"))
				}
			}
			for _, tenantID := range tenantIDs.Values() {
				if err := add(tenantID); err != nil {
					return nil, err
				}
			}
		}
		list := make([]*core.Object, 0, len(found))
		for _, account := range found {
			list = append(list, account)
		}
		slices.SortStableFunc(list, bsByID)
		return list, nil
	})
	if err != nil {
		return nil, err
	}
	issued := []any{}
	drafted := []any{}
	existingCount, emptyCount := 0, 0
	for _, candidate := range accounts {
		// The platform does not bill itself.
		if parentID, ok := candidate.Lookup("parentId"); ok && parentID == nil {
			continue
		}
		err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			account, err := server.Tenant(ctx, tx, candidate.Get("id"))
			if err != nil {
				return err
			}
			accountID := bsStr(account, "id")
			existing, err := s.StatementFor(ctx, tx, accountID, period)
			if err != nil {
				return err
			}
			if existing != nil && !bsIs(existing.Get("status"), "draft") {
				existingCount++
				return nil
			}
			draft, err := s.DraftStatement(ctx, tx, account, period, nil, nil)
			if err != nil {
				return err
			}
			if !bsBillable(draft) {
				if existing != nil {
					if err := tx.Delete(ctx, BillingCollections.Statements, bsStr(existing, "id")); err != nil {
						return err
					}
				}
				emptyCount++
				return nil
			}
			if draftOnly {
				saved, err := s.saveDraft(ctx, tx, account, draft, existing)
				if err != nil {
					return err
				}
				drafted = append(drafted, core.NewObject("accountId", account.Get("id"), "statementId", saved.Get("id"), "totalMicros", saved.Get("totalMicros")))
				return nil
			}
			statement, recipients, err := s.issue(ctx, tx, account, draft, "period:"+period, existing, "")
			if err != nil {
				return err
			}
			issued = append(issued, core.NewObject("accountId", account.Get("id"), "statementId", statement.Get("id"),
				"number", statement.Get("number"), "totalMicros", statement.Get("totalMicros"), "recipients", float64(recipients)))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	swept, err := s.sweepUsage(ctx)
	if err != nil {
		return nil, err
	}
	return core.NewObject("period", period, "issued", issued, "drafted", drafted,
		"skipped", core.NewObject("existing", float64(existingCount), "empty", float64(emptyCount)),
		"sweptUsage", float64(swept)), nil
}

// VoidStatement (billing-service.ts billingServiceOf().voidStatement): Voids a finalized invoice: its credit is
// restored (and credit it created revoked), its invoice items are pending again, its advance months are unbilled, its
// coupons count one invoice less, and a monthly invoice's period reopens for the account. Invoices with payments or
// credit notes cannot be voided; issue a credit note instead. Nor can one whose credit balance (`carryForward`) a
// later invoice has used, until that invoice is voided.
func (s *BillingService) VoidStatement(ctx context.Context, tx core.IamStore, statement *core.Object, principal *Principal, reason string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	calc := &bsCalc{}
	if bsIs(statement.Get("status"), "void") {
		return nil, core.NewIamError("INVALID_TRANSITION", "The statement is already void", 409)
	}
	if bsIs(statement.Get("status"), "draft") {
		return nil, core.NewIamError("INVALID_TRANSITION", "Drafts are not voided; finalize the invoice or let the next close refresh it", 409)
	}
	creditNotes := 0.0
	if value := statement.Get("creditNotesMicros"); !nullish(value) {
		creditNotes = jsNumber(value)
	}
	if len(bsAnyList(statement.Get("payments"))) > 0 || creditNotes > 0 {
		return nil, core.NewIamError("INVALID_TRANSITION", "The invoice has payments or credit notes; issue a credit note instead", 409)
	}
	// Voiding puts the invoice's credit items back up for the next invoice, so the credit balance they created must
	// still be whole: once a later invoice used it (or it was revoked), voiding would hand the credit out twice.
	carryForward, _ := statement.Get("carryForward").(*core.Object)
	var carried *core.Object
	if carryForward != nil {
		if carried, err = tx.Get(ctx, BillingCollections.Credits, jsString(carryForward.Get("creditId"))); err != nil {
			return nil, err
		}
	}
	if carried != nil && bsNum(carried, "remainingMicros") < bsNum(carried, "amountMicros") {
		return nil, core.NewIamError("INVALID_TRANSITION", "The credit balance this invoice created has been used or revoked; void the invoices that used it first", 409)
	}
	for _, applied := range bsObjects(statement.Get("creditsApplied")) {
		credit, err := tx.Get(ctx, BillingCollections.Credits, jsString(applied.Get("creditId")))
		if err != nil {
			return nil, err
		}
		if credit != nil {
			next := credit.Clone()
			next.Set("remainingMicros", calc.micros(bsMin(bsNum(credit, "amountMicros"), bsNum(credit, "remainingMicros")+bsNum(applied, "amountMicros"))))
			if calc.err != nil {
				return nil, calc.err
			}
			if _, err := tx.Put(ctx, BillingCollections.Credits, next); err != nil {
				return nil, err
			}
		}
	}
	now := float64(s.server.Now())
	if carryForward != nil {
		credit, err := tx.Get(ctx, BillingCollections.Credits, jsString(carryForward.Get("creditId")))
		if err != nil {
			return nil, err
		}
		if credit != nil && isUndefined(credit.Get("revokedAt")) {
			if _, err := tx.Put(ctx, BillingCollections.Credits, credit.Spread(core.NewObject("revokedAt", now))); err != nil {
				return nil, err
			}
		}
	}
	for _, itemID := range bsAnyList(statement.Get("invoiceItemIds")) {
		item, err := tx.Get(ctx, BillingCollections.InvoiceItems, jsString(itemID))
		if err != nil {
			return nil, err
		}
		if item != nil && core.StrictEquals(item.Get("statementId"), statement.Get("id")) {
			rest := item.Clone()
			rest.Delete("statementId")
			rest.Set("status", "pending")
			if _, err := tx.Put(ctx, BillingCollections.InvoiceItems, rest); err != nil {
				return nil, err
			}
		}
	}
	for _, entry := range bsObjects(statement.Get("advanceBilled")) {
		subscription, err := tx.Get(ctx, BillingCollections.Subscriptions, jsString(entry.Get("subscriptionId")))
		if err != nil {
			return nil, err
		}
		entryPeriod := jsString(entry.Get("period"))
		if subscription != nil && containsString(bsStrings(subscription.Get("billedAdvance")), entryPeriod) {
			var billed []string
			for _, value := range bsStrings(subscription.Get("billedAdvance")) {
				if value != entryPeriod {
					billed = append(billed, value)
				}
			}
			if _, err := tx.Put(ctx, BillingCollections.Subscriptions, subscription.Spread(core.NewObject("billedAdvance", stringsOf(billed)))); err != nil {
				return nil, err
			}
		}
	}
	for _, coupon := range bsObjects(statement.Get("coupons")) {
		discount, err := tx.Get(ctx, BillingCollections.Discounts, jsString(coupon.Get("discountId")))
		if err != nil {
			return nil, err
		}
		if discount != nil {
			next := discount.Clone()
			if bsIs(discount.Get("duration"), "once") {
				next.Delete("endedAt")
			}
			next.Set("appliedInvoices", bsMax(0, bsNum(discount, "appliedInvoices")-1))
			if _, err := tx.Put(ctx, BillingCollections.Discounts, next); err != nil {
				return nil, err
			}
		}
	}
	return tx.Put(ctx, BillingCollections.Statements, statement.Spread(core.NewObject(
		"uniqueKey", "void:"+jsString(statement.Get("id")), "status", "void", "voidedAt", now,
		"voidedBy", principal.Identity.Get("id"), "voidReason", reason,
	)))
}

// RecordPayment (billing-service.ts billingServiceOf().recordPayment): Records a payment against a finalized (or
// uncollectible) invoice, the full amount due by default (input `{ amount?, method?, reference?, receivedAt? }`). Once
// payments and credit notes cover the invoice it is paid; a payment above the amount due keeps the excess as account
// credit. Returns `{ statement, payment }`.
func (s *BillingService) RecordPayment(ctx context.Context, tx core.IamStore, statement *core.Object, input *core.Object, actorID string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	calc := &bsCalc{}
	if !bsIs(statement.Get("status"), "finalized") && !bsIs(statement.Get("status"), "uncollectible") {
		return nil, core.NewIamError("INVALID_TRANSITION", "The invoice is "+jsString(statement.Get("status")), 409)
	}
	due, err := AmountDue(statement)
	if err != nil {
		return nil, err
	}
	amount := due
	if raw := member(input, "amount"); !isUndefined(raw) {
		if amount, err = AmountMicros(raw, "amount"); err != nil {
			return nil, err
		}
	}
	if amount <= 0 {
		return nil, invalidInput("amount must be above 0")
	}
	method := "manual"
	if raw := member(input, "method"); !isUndefined(raw) {
		text, err := Text(raw, "method", 32)
		if err != nil {
			return nil, err
		}
		method = core.JSTrim(text)
	}
	reference := ""
	if raw := member(input, "reference"); !isUndefined(raw) {
		text, err := Text(raw, "reference", 128)
		if err != nil {
			return nil, err
		}
		reference = core.JSTrim(text)
	}
	now := float64(s.server.Now())
	receivedAt := now
	if raw := member(input, "receivedAt"); !isUndefined(raw) {
		if receivedAt, err = Integer(raw, "receivedAt", bsNum(statement, "issuedAt")-366*86_400_000, now+60_000); err != nil {
			return nil, err
		}
	}
	applied := calc.micros(bsMin(amount, due))
	overpaymentMicros := calc.micros(amount - applied)
	if calc.err != nil {
		return nil, calc.err
	}
	payment := core.NewObject("id", ID(), "amountMicros", amount, "method", method)
	if reference != "" {
		payment.Set("reference", reference)
	}
	payment.Set("receivedAt", receivedAt)
	payment.Set("recordedBy", actorID)
	if overpaymentMicros > 0 {
		credit, err := tx.Insert(ctx, BillingCollections.Credits, core.NewObject(
			"id", ID(), "tenantId", statement.Get("tenantId"), "amountMicros", overpaymentMicros,
			"remainingMicros", overpaymentMicros, "reason", "Overpayment of "+jsString(statement.Get("number")),
			"grantedAt", now, "grantedBy", actorID,
		))
		if err != nil {
			return nil, err
		}
		payment.Set("overpaymentMicros", overpaymentMicros)
		payment.Set("creditId", credit.Get("id"))
	}
	settled := calc.micros(due-applied) <= 0
	paid, err := AmountPaid(statement)
	if err != nil {
		return nil, err
	}
	payments := append(append([]any{}, bsAnyList(statement.Get("payments"))...), payment)
	update := core.NewObject("payments", payments, "amountPaidMicros", calc.micros(paid+applied))
	if calc.err != nil {
		return nil, calc.err
	}
	if settled {
		update.Set("status", "paid")
		update.Set("paidAt", receivedAt)
		update.Set("paidBy", actorID)
		if reference != "" {
			update.Set("paymentReference", reference)
		}
	}
	next, err := tx.Put(ctx, BillingCollections.Statements, statement.Spread(update))
	if err != nil {
		return nil, err
	}
	return core.NewObject("statement", next, "payment", payment), nil
}

// MarkUncollectible (billing-service.ts billingServiceOf().markUncollectible): Writes a finalized invoice off as
// uncollectible (a later payment still settles it).
func (s *BillingService) MarkUncollectible(ctx context.Context, tx core.IamStore, statement *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if !bsIs(statement.Get("status"), "finalized") {
		return nil, core.NewIamError("INVALID_TRANSITION", "The invoice is "+jsString(statement.Get("status")), 409)
	}
	return tx.Put(ctx, BillingCollections.Statements, statement.Spread(core.NewObject(
		"status", "uncollectible", "markedUncollectibleAt", float64(s.server.Now()),
	)))
}

// CreateCreditNote (billing-service.ts billingServiceOf().createCreditNote): Issues a credit note against a
// finalized, paid or uncollectible invoice, numbered `{invoice}-CN-{nn}` (input `{ amount?, reason?, memo?, refund? }`):
// it first reduces the amount due; the rest (a part already paid) becomes account credit, or is recorded as refunded
// outside Better IAM with `refund`. An invoice the credit notes and payments cover is paid. Returns
// `{ statement, creditNote }`.
func (s *BillingService) CreateCreditNote(ctx context.Context, tx core.IamStore, statement *core.Object, input *core.Object, actorID string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	calc := &bsCalc{}
	status := statement.Get("status")
	if !bsIs(status, "finalized") && !bsIs(status, "paid") && !bsIs(status, "uncollectible") {
		return nil, core.NewIamError("INVALID_TRANSITION", "The invoice is "+jsString(status), 409)
	}
	creditNotes := 0.0
	if value := statement.Get("creditNotesMicros"); !nullish(value) {
		creditNotes = jsNumber(value)
	}
	creditable := calc.micros(bsNum(statement, "totalMicros") - creditNotes)
	if calc.err != nil {
		return nil, calc.err
	}
	amount := creditable
	if raw := member(input, "amount"); !isUndefined(raw) {
		if amount, err = AmountMicros(raw, "amount"); err != nil {
			return nil, err
		}
	}
	if amount <= 0 {
		return nil, invalidInput("amount must be above 0")
	}
	if amount > creditable {
		text, err := FormatMoney(creditable, s.currency())
		if err != nil {
			return nil, err
		}
		return nil, invalidInput("At most " + text + " of the invoice can still be credited")
	}
	reason, err := CreditNoteReason(member(input, "reason"))
	if err != nil {
		return nil, err
	}
	memo := ""
	if raw := member(input, "memo"); !isUndefined(raw) {
		text, err := Text(raw, "memo", 512)
		if err != nil {
			return nil, err
		}
		memo = core.JSTrim(text)
	}
	refund := member(input, "refund")
	if !isUndefined(refund) {
		if _, ok := refund.(bool); !ok {
			return nil, invalidInput("refund must be a boolean")
		}
	}
	due, err := AmountDue(statement)
	if err != nil {
		return nil, err
	}
	dueMicros := calc.micros(bsMin(amount, due))
	rest := calc.micros(amount - dueMicros)
	if calc.err != nil {
		return nil, calc.err
	}
	creditMicros, refundMicros := rest, 0.0
	if refund == true {
		creditMicros, refundMicros = 0, rest
	}
	applied := core.NewObject("dueMicros", dueMicros, "creditMicros", creditMicros, "refundMicros", refundMicros)
	existing, err := tx.Find(ctx, BillingCollections.CreditNotes, core.NewObject("tenantId", statement.Get("tenantId"), "statementId", statement.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	number := jsString(statement.Get("number")) + "-CN-" + bsPad(len(existing)+1, 2)
	now := float64(s.server.Now())
	var creditID any = core.Undefined
	if creditMicros > 0 {
		credit, err := tx.Insert(ctx, BillingCollections.Credits, core.NewObject(
			"id", ID(), "tenantId", statement.Get("tenantId"), "amountMicros", creditMicros, "remainingMicros", creditMicros,
			"reason", "Credit note "+number, "grantedAt", now, "grantedBy", actorID,
		))
		if err != nil {
			return nil, err
		}
		creditID = credit.Get("id")
	}
	note := core.NewObject("id", ID(), "tenantId", statement.Get("tenantId"), "uniqueKey", number, "number", number,
		"statementId", statement.Get("id"), "statementNumber", statement.Get("number"), "amountMicros", amount, "reason", reason)
	if memo != "" {
		note.Set("memo", memo)
	}
	note.Set("applied", applied)
	if truthy(creditID) {
		note.Set("creditId", creditID)
	}
	note.Set("issuedAt", now)
	note.Set("issuedBy", actorID)
	creditNote, err := tx.Insert(ctx, BillingCollections.CreditNotes, note)
	if err != nil {
		return nil, err
	}
	credited := statement.Spread(core.NewObject("creditNotesMicros", calc.micros(creditNotes+amount)))
	if calc.err != nil {
		return nil, calc.err
	}
	settled := false
	if !bsIs(status, "paid") {
		remaining, err := AmountDue(credited)
		if err != nil {
			return nil, err
		}
		settled = remaining <= 0
	}
	update := credited
	if settled {
		update = credited.Spread(core.NewObject("status", "paid", "paidAt", now, "paidBy", actorID))
	}
	next, err := tx.Put(ctx, BillingCollections.Statements, update)
	if err != nil {
		return nil, err
	}
	return core.NewObject("statement", next, "creditNote", creditNote), nil
}

// SendPaymentReminders (billing-service.ts billingServiceOf().sendPaymentReminders): Emails the billing contacts of
// finalized invoices with an amount due (`payment-reminder`) at each step of `billing.paymentReminderDays` relative to
// the due date, once per step (a missed step is skipped for the latest one reached). Audited as
// `billing:payment-reminder`. A scheduler job, run daily.
func (s *BillingService) SendPaymentReminders(ctx context.Context) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	server := s.server
	store := server.Store
	checked := 0
	reminders := []any{}
	steps := bsAnyList(s.Settings.Get("paymentReminderDays"))
	if len(steps) == 0 {
		return core.NewObject("checked", 0.0, "reminders", reminders), nil
	}
	open, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		return tx.Find(ctx, BillingCollections.Statements, core.NewObject("status", "finalized"), nil)
	})
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(open, func(a, b *core.Object) int {
		return bsOrder(bsNum(a, "dueAt")-bsNum(b, "dueAt"), bsKeyOrder(bsStr(a, "id"), bsStr(b, "id")))
	})
	currency := s.currency()
	for _, candidate := range open {
		checked++
		err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			statement, err := tx.Get(ctx, BillingCollections.Statements, bsStr(candidate, "id"))
			if err != nil {
				return err
			}
			if statement == nil || !bsIs(statement.Get("status"), "finalized") {
				return nil
			}
			due, err := AmountDue(statement)
			if err != nil {
				return err
			}
			if due <= 0 {
				return nil
			}
			now := float64(server.Now())
			dueAt := bsNum(statement, "dueAt")
			issuedAt := bsNum(statement, "issuedAt")
			var reached []float64
			for _, value := range steps {
				days := jsNumber(value)
				at := dueAt + days*86_400_000
				if at > issuedAt && at <= now {
					reached = append(reached, days)
				}
			}
			if len(reached) == 0 {
				return nil
			}
			step := reached[len(reached)-1]
			for _, reminder := range bsObjects(statement.Get("reminders")) {
				if bsNum(reminder, "days") >= step {
					return nil
				}
			}
			account, err := tx.Get(ctx, "tenants", jsString(statement.Get("tenantId")))
			if err != nil {
				return err
			}
			billTo, _ := statement.Get("billTo").(*core.Object)
			var recipients []string
			if s.sendsEmail() {
				recipients = bsStrings(billTo.Get("emails"))
			}
			days := jsMathRound((now - dueAt) / 86_400_000)
			for _, to := range recipients {
				amountDue, err := FormatMoney(due, currency)
				if err != nil {
					return err
				}
				total, err := FormatMoney(bsNum(statement, "totalMicros"), currency)
				if err != nil {
					return err
				}
				tenantName := billTo.Get("name")
				if account != nil && !nullish(account.Get("name")) {
					tenantName = account.Get("name")
				}
				payload := core.NewObject("tenantId", statement.Get("tenantId"), "tenantName", tenantName,
					"statementId", statement.Get("id"), "number", statement.Get("number"), "period", statement.Get("period"),
					"amountDue", amountDue, "total", total, "dueAt", bsIsoDate(dueAt), "days", core.NumberString(days),
					"overdue", strconv.FormatBool(now > dueAt))
				if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
					TenantID: jsString(statement.Get("tenantId")), Kind: "email", To: to, Template: "payment-reminder", Payload: payload,
				}); err != nil {
					return err
				}
			}
			history := append(append([]any{}, bsAnyList(statement.Get("reminders"))...),
				core.NewObject("days", step, "at", now, "recipients", float64(len(recipients))))
			if _, err := tx.Put(ctx, BillingCollections.Statements, statement.Spread(core.NewObject("reminders", history))); err != nil {
				return err
			}
			if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(), "tenantId", statement.Get("tenantId"), "actorId", "deployment-operator",
				"action", "billing:payment-reminder", "resourceId", "billing/statements/"+jsString(statement.Get("id")),
				"timestamp", now, "outcome", "allow",
				"metadata", core.NewObject("number", statement.Get("number"), "step", step, "amountDueMicros", due,
					"recipients", float64(len(recipients))),
			)); err != nil {
				return err
			}
			reminders = append(reminders, core.NewObject("statementId", statement.Get("id"), "accountId", statement.Get("tenantId"),
				"number", statement.Get("number"), "step", step, "amountDueMicros", due, "recipients", float64(len(recipients))))
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return core.NewObject("checked", float64(checked), "reminders", reminders), nil
}

// --- subscriptions ---------------------------------------------------------------------------------------------------

func (s *BillingService) planOf(ctx context.Context, tx core.IamStore, subscription *core.Object) (*core.Object, error) {
	plan, err := tx.Get(ctx, BillingCollections.Plans, jsString(subscription.Get("planId")))
	if err != nil {
		return nil, err
	}
	if plan == nil {
		return nil, core.NewIamError("NOT_FOUND", "Billing plan not found", 404)
	}
	return plan, nil
}

func (s *BillingService) assertLive(subscription *core.Object) error {
	status, err := SubscriptionStatus(subscription, s.server.Now())
	if err != nil {
		return err
	}
	if status == "ended" {
		return core.NewIamError("INVALID_TRANSITION", "The subscription has ended", 409)
	}
	return nil
}

func (s *BillingService) insertItems(ctx context.Context, tx core.IamStore, items []*core.Object) error {
	for _, item := range items {
		if _, err := tx.Insert(ctx, BillingCollections.InvoiceItems, item); err != nil {
			return err
		}
	}
	return nil
}

// liveSubscription is the live subscription of an account to a plan; an ended one frees the plan for a new
// subscription.
func (s *BillingService) liveSubscription(ctx context.Context, tx core.IamStore, accountID string, planID string) (*core.Object, error) {
	found, err := tx.Find(ctx, BillingCollections.Subscriptions, core.NewObject("tenantId", accountID, "uniqueKey", "plan:"+planID), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	existing := found[0]
	status, err := SubscriptionStatus(existing, s.server.Now())
	if err != nil {
		return nil, err
	}
	if status != "ended" {
		return existing, nil
	}
	if _, err := tx.Put(ctx, BillingCollections.Subscriptions, existing.Spread(core.NewObject("uniqueKey", "ended:"+jsString(existing.Get("id"))))); err != nil {
		return nil, err
	}
	return nil, nil
}

// Subscribe (billing-service.ts billingServiceOf().subscribe): Subscribes a billing account to a plan with `seats`
// (input `{ seats, trialDays? }`) and the plan's trial (or `trialDays`; 0 for none). The plan's own trial is granted
// once per account: an account that subscribed to the plan before starts without one. Outside a trial the first
// month's advance fees and seats are invoiced at once, prorated from today (a finalized invoice with
// `billingReason: 'subscription'`); after that each monthly invoice bills the month ahead. Returns
// `{ subscription, invoice? }`.
func (s *BillingService) Subscribe(ctx context.Context, tx core.IamStore, account *core.Object, plan *core.Object, input *core.Object, actorID string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if truthy(plan.Get("archived")) {
		return nil, core.NewIamError("INVALID_TRANSITION", "The plan is archived", 409)
	}
	accountID := bsStr(account, "id")
	planID := bsStr(plan, "id")
	live, err := s.liveSubscription(ctx, tx, accountID, planID)
	if err != nil {
		return nil, err
	}
	if live != nil {
		return nil, core.NewIamError("CONFLICT", "The account already subscribes to this plan", 409)
	}
	now := float64(s.server.Now())
	previous, err := tx.Find(ctx, BillingCollections.Subscriptions, core.NewObject("tenantId", accountID), nil)
	if err != nil {
		return nil, err
	}
	subscribedBefore := slices.ContainsFunc(previous, func(subscription *core.Object) bool {
		return core.StrictEquals(subscription.Get("planId"), plan.Get("id"))
	})
	trialDays := 0.0
	if raw := member(input, "trialDays"); !nullish(raw) {
		trialDays = jsNumber(raw)
	} else if !subscribedBefore {
		if value := plan.Get("trialDays"); !nullish(value) {
			trialDays = jsNumber(value)
		}
	}
	seats := member(input, "seats")
	record := core.NewObject("id", ID(), "tenantId", accountID, "uniqueKey", "plan:"+planID, "planId", plan.Get("id"),
		"planKey", plan.Get("key"), "planName", plan.Get("name"), "startedAt", now)
	if trialDays > 0 {
		record.Set("trialEndsAt", now+trialDays*86_400_000)
	}
	record.Set("cancelAtPeriodEnd", false)
	record.Set("seats", seats)
	record.Set("seatHistory", []any{core.NewObject("at", now, "seats", seats)})
	record.Set("billedAdvance", []any{})
	record.Set("createdAt", now)
	record.Set("createdBy", actorID)
	record.Set("updatedAt", now)
	created, err := tx.Insert(ctx, BillingCollections.Subscriptions, record)
	if err != nil {
		return nil, err
	}
	var invoice *core.Object
	if isUndefined(created.Get("trialEndsAt")) {
		first, err := FirstPeriodLines(created, plan, s.tz)
		if err != nil {
			return nil, err
		}
		if lines := bsAnyList(first.Get("lines")); len(lines) > 0 {
			draft, err := s.DraftStatement(ctx, tx, account, jsString(first.Get("period")), map[string]any{},
				core.NewObject("lines", lines, "subscriptionId", created.Get("id")))
			if err != nil {
				return nil, err
			}
			if invoice, _, err = s.issue(ctx, tx, account, draft, "subscription:"+jsString(created.Get("id")), nil, actorID); err != nil {
				return nil, err
			}
		}
	}
	subscription, err := tx.Get(ctx, BillingCollections.Subscriptions, jsString(created.Get("id")))
	if err != nil {
		return nil, err
	}
	result = core.NewObject("subscription", subscription)
	if invoice != nil {
		result.Set("invoice", invoice)
	}
	return result, nil
}

// UpdateSeats (billing-service.ts billingServiceOf().updateSeats): Changes the seat count; seats billed in advance
// for this month are prorated as invoice items. Returns `{ subscription, items }`.
func (s *BillingService) UpdateSeats(ctx context.Context, tx core.IamStore, subscription *core.Object, seats float64, actorID string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if err = s.assertLive(subscription); err != nil {
		return nil, err
	}
	if core.StrictEquals(seats, subscription.Get("seats")) {
		return core.NewObject("subscription", subscription, "items", []any{}), nil
	}
	now := float64(s.server.Now())
	plan, err := s.planOf(ctx, tx, subscription)
	if err != nil {
		return nil, err
	}
	items, err := ProrationItems(core.NewObject("subscription", subscription, "plan", plan, "at", now, "timeZone", s.tz,
		"seats", core.NewObject("before", subscription.Get("seats"), "after", seats), "ending", false, "createdBy", actorID))
	if err != nil {
		return nil, err
	}
	if err := s.insertItems(ctx, tx, items); err != nil {
		return nil, err
	}
	history := append(append([]any{}, bsAnyList(subscription.Get("seatHistory"))...), core.NewObject("at", now, "seats", seats))
	next, err := tx.Put(ctx, BillingCollections.Subscriptions, subscription.Spread(core.NewObject(
		"seats", seats, "seatHistory", history, "updatedAt", now,
	)))
	if err != nil {
		return nil, err
	}
	return core.NewObject("subscription", next, "items", bsList(items)), nil
}

// CancelSubscription (billing-service.ts billingServiceOf().cancelSubscription): Cancels a subscription at the end
// of the month (it keeps running until then, and can be resumed) or now, when the unused part of the month's advance
// fees and seats is credited as invoice items for the next invoice. Returns `{ subscription, items }`.
func (s *BillingService) CancelSubscription(ctx context.Context, tx core.IamStore, subscription *core.Object, atPeriodEnd bool, actorID string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if err = s.assertLive(subscription); err != nil {
		return nil, err
	}
	now := s.server.Now()
	if atPeriodEnd {
		period, err := PeriodOf(now, s.tz)
		if err != nil {
			return nil, err
		}
		bounds, err := PeriodBounds(period, s.tz)
		if err != nil {
			return nil, err
		}
		next, err := tx.Put(ctx, BillingCollections.Subscriptions, subscription.Spread(core.NewObject(
			"cancelAtPeriodEnd", true, "endsAt", bounds.Get("end"), "canceledAt", float64(now), "canceledBy", actorID,
			"updatedAt", float64(now),
		)))
		if err != nil {
			return nil, err
		}
		return core.NewObject("subscription", next, "items", []any{}), nil
	}
	plan, err := s.planOf(ctx, tx, subscription)
	if err != nil {
		return nil, err
	}
	items, err := ProrationItems(core.NewObject("subscription", subscription, "plan", plan, "at", float64(now),
		"timeZone", s.tz, "ending", true, "createdBy", actorID))
	if err != nil {
		return nil, err
	}
	if err := s.insertItems(ctx, tx, items); err != nil {
		return nil, err
	}
	next, err := tx.Put(ctx, BillingCollections.Subscriptions, subscription.Spread(core.NewObject(
		"uniqueKey", "ended:"+jsString(subscription.Get("id")), "cancelAtPeriodEnd", false, "endsAt", float64(now),
		"canceledAt", float64(now), "canceledBy", actorID, "updatedAt", float64(now),
	)))
	if err != nil {
		return nil, err
	}
	return core.NewObject("subscription", next, "items", bsList(items)), nil
}

// ResumeSubscription (billing-service.ts billingServiceOf().resumeSubscription): Undoes a cancellation at the end of
// the month before it takes effect.
func (s *BillingService) ResumeSubscription(ctx context.Context, tx core.IamStore, subscription *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if err = s.assertLive(subscription); err != nil {
		return nil, err
	}
	if !truthy(subscription.Get("cancelAtPeriodEnd")) {
		return nil, core.NewIamError("INVALID_TRANSITION", "The subscription is not set to cancel", 409)
	}
	rest := subscription.Clone()
	rest.Delete("endsAt")
	rest.Delete("canceledAt")
	rest.Delete("canceledBy")
	rest.Set("cancelAtPeriodEnd", false)
	rest.Set("updatedAt", float64(s.server.Now()))
	return tx.Put(ctx, BillingCollections.Subscriptions, rest)
}

// ChangePlan (billing-service.ts billingServiceOf().changePlan): Moves a subscription to another plan now, keeping
// its seats and what is left of its trial: the old plan's unused advance charges are credited and the new plan's
// charges for the rest of the month added, both as proration items for the next invoice. Returns
// `{ subscription, items }`.
func (s *BillingService) ChangePlan(ctx context.Context, tx core.IamStore, subscription *core.Object, plan *core.Object, actorID string) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	if err = s.assertLive(subscription); err != nil {
		return nil, err
	}
	if core.StrictEquals(plan.Get("id"), subscription.Get("planId")) {
		return nil, invalidInput("The subscription is already on this plan")
	}
	if truthy(plan.Get("archived")) {
		return nil, core.NewIamError("INVALID_TRANSITION", "The plan is archived", 409)
	}
	tenantID := bsStr(subscription, "tenantId")
	live, err := s.liveSubscription(ctx, tx, tenantID, bsStr(plan, "id"))
	if err != nil {
		return nil, err
	}
	if live != nil {
		return nil, core.NewIamError("CONFLICT", "The account already subscribes to this plan", 409)
	}
	now := float64(s.server.Now())
	oldPlan, err := s.planOf(ctx, tx, subscription)
	if err != nil {
		return nil, err
	}
	items, err := ProrationItems(core.NewObject("subscription", subscription, "plan", oldPlan, "at", now,
		"timeZone", s.tz, "ending", true, "createdBy", actorID))
	if err != nil {
		return nil, err
	}
	if _, err := tx.Put(ctx, BillingCollections.Subscriptions, subscription.Spread(core.NewObject(
		"uniqueKey", "ended:"+jsString(subscription.Get("id")), "cancelAtPeriodEnd", false, "endsAt", now,
		"canceledAt", now, "canceledBy", actorID, "updatedAt", now,
	))); err != nil {
		return nil, err
	}
	created := core.NewObject("id", ID(), "tenantId", subscription.Get("tenantId"), "uniqueKey", "plan:"+bsStr(plan, "id"),
		"planId", plan.Get("id"), "planKey", plan.Get("key"), "planName", plan.Get("name"), "startedAt", now)
	if trialEndsAt := subscription.Get("trialEndsAt"); !isUndefined(trialEndsAt) && jsNumber(trialEndsAt) > now {
		created.Set("trialEndsAt", trialEndsAt)
	}
	created.Set("cancelAtPeriodEnd", false)
	created.Set("seats", subscription.Get("seats"))
	created.Set("seatHistory", []any{core.NewObject("at", now, "seats", subscription.Get("seats"))})
	created.Set("billedAdvance", []any{})
	created.Set("createdAt", now)
	created.Set("createdBy", actorID)
	created.Set("updatedAt", now)
	first, err := FirstPeriodLines(created, plan, s.tz)
	if err != nil {
		return nil, err
	}
	firstPeriod := first.Get("period")
	for _, line := range bsObjects(first.Get("lines")) {
		items = append(items, core.NewObject(
			"id", ID(), "tenantId", subscription.Get("tenantId"),
			"description", jsString(plan.Get("name"))+": "+jsString(line.Get("name"))+" for the rest of the month",
			"quantity", 1.0, "unitAmountMicros", line.Get("amountMicros"), "amountMicros", line.Get("amountMicros"),
			"period", firstPeriod, "status", "pending", "source", "proration", "subscriptionId", created.Get("id"),
			"createdAt", now, "createdBy", actorID,
		))
	}
	// The rest of this month is billed through those items rather than an invoice of its own.
	if slices.ContainsFunc(bsObjects(plan.Get("items")), func(item *core.Object) bool {
		return !bsIs(item.Get("kind"), "usage") && !bsIs(item.Get("billing"), "arrears")
	}) {
		created.Set("billedAdvance", []any{firstPeriod})
	}
	if err := s.insertItems(ctx, tx, items); err != nil {
		return nil, err
	}
	next, err := tx.Insert(ctx, BillingCollections.Subscriptions, created)
	if err != nil {
		return nil, err
	}
	return core.NewObject("subscription", next, "items", bsList(items)), nil
}

// RecordSeats (billing-service.ts billingServiceOf().recordSeats): Records one seat of `meter` (default `seats`) for
// every active person (or `kinds`) of every tenant the meter reaches, once per day (idempotent): a `sum` meter then
// counts seat-days, a `unique` meter active seats per month. Seats are attributed to the person, their teams and
// department. A tenant that fails is reported in `failedTenants` and the others are still recorded. A scheduler job,
// run daily. input is `{ meter?, tenantId?, kinds? }`.
func (s *BillingService) RecordSeats(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	server := s.server
	store := server.Store
	key, err := MeterKey(coalesce(member(input, "meter"), "seats"))
	if err != nil {
		return nil, err
	}
	rawKinds := coalesce(member(input, "kinds"), []any{"user"})
	var kinds []string
	switch v := rawKinds.(type) {
	case []string:
		rawKinds = stringsOf(v)
	}
	list, ok := rawKinds.([]any)
	valid := ok && len(list) > 0
	if valid {
		for _, kind := range list {
			if !bsIs(kind, "user") && !bsIs(kind, "service") && !bsIs(kind, "agent") {
				valid = false
				break
			}
			kinds = append(kinds, kind.(string))
		}
	}
	if !valid {
		return nil, invalidInput("kinds must list 'user', 'service' or 'agent'")
	}
	day, err := DayOf(server.Now(), s.tz)
	if err != nil {
		return nil, err
	}
	tenants, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		raw := member(input, "tenantId")
		if isUndefined(raw) {
			return tx.Find(ctx, "tenants", core.NewObject("status", "active"), nil)
		}
		tenantID, err := Text(raw, "tenantId")
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		realms, err := Subtree(ctx, server, tx, tenant)
		if err != nil {
			return nil, err
		}
		var active []*core.Object
		for _, realm := range realms {
			if bsIs(realm.Get("status"), "active") {
				active = append(active, realm)
			}
		}
		return active, nil
	})
	if err != nil {
		return nil, err
	}
	recorded, duplicates, skipped := 0, 0, 0
	failed := []any{}
	slices.SortStableFunc(tenants, bsByID)
	for _, realm := range tenants {
		if parentID, ok := realm.Lookup("parentId"); ok && parentID == nil {
			continue
		}
		type seatCounts struct{ recorded, duplicates int }
		counts, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) (*seatCounts, error) {
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			meter, err := ResolveMeter(ctx, tx, chain, key)
			if err != nil {
				return nil, err
			}
			if meter == nil || truthy(meter.Get("archived")) {
				return nil, nil
			}
			found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", realm.Get("id"), "status", "active"), nil)
			if err != nil {
				return nil, err
			}
			var people []*core.Object
			for _, identity := range found {
				if containsString(kinds, bsStr(identity, "kind")) && !server.IdentityExpired(identity) {
					people = append(people, identity)
				}
			}
			slices.SortStableFunc(people, bsByID)
			counts := &seatCounts{}
			for _, identity := range people {
				identityID := bsStr(identity, "id")
				// Seats recorded under the caller-visible `idem:` key of earlier releases (by this job only) still count.
				legacy, err := tx.Find(ctx, BillingCollections.Usage, core.NewObject("tenantId", realm.Get("id"),
					"uniqueKey", "idem:seat:"+key+":"+identityID+":"+day), nil)
				if err != nil {
					return nil, err
				}
				if len(legacy) > 0 && bsIs(legacy[0].Get("recordedBy"), "deployment") && core.StrictEquals(legacy[0].Get("meterId"), meter.Get("id")) {
					counts.duplicates++
					continue
				}
				// A source key (`src:`), which callers of `record` cannot claim ahead of the job.
				seat, err := s.Record(ctx, tx, core.NewObject("tenantId", realm.Get("id"), "meter", key, "quantity", 1.0, "identityId", identityID),
					"deployment", core.NewObject("meter", meter, "sourceId", "seat:"+identityID+":"+day))
				if err != nil {
					return nil, err
				}
				if truthy(seat.Get("duplicate")) {
					counts.duplicates++
				} else {
					counts.recorded++
				}
			}
			return counts, nil
		})
		if err != nil {
			// One tenant's failure never stops the platform-wide job.
			code := "INTERNAL_ERROR"
			if known, ok := asIamError(err); ok {
				code = known.Code
			}
			failed = append(failed, core.NewObject("tenantId", realm.Get("id"), "code", code, "message", errorMessage(err)))
			continue
		}
		if counts == nil {
			skipped++
		} else {
			recorded += counts.recorded
			duplicates += counts.duplicates
		}
	}
	return core.NewObject("meter", key, "day", day, "recorded", float64(recorded), "duplicates", float64(duplicates),
		"skippedTenants", float64(skipped), "failedTenants", failed), nil
}

// OwnIdentities (billing-service.ts billingServiceOf().ownIdentities): Every identity whose spend counts as a
// person's own: themselves and the agents they sponsor.
func (s *BillingService) OwnIdentities(ctx context.Context, tx core.IamStore, identity *core.Object) (result []string, err error) {
	if err = s.ready(); err != nil {
		return
	}
	own := newOrderedSet(bsStr(identity, "id"))
	agents, err := tx.Find(ctx, "identities", core.NewObject("tenantId", identity.Get("tenantId"), "kind", "agent"), nil)
	if err != nil {
		return nil, err
	}
	for _, agent := range agents {
		if core.StrictEquals(member(agent.Get("agent"), "sponsorId"), identity.Get("id")) {
			own.Add(bsStr(agent, "id"))
		}
	}
	return own.Values(), nil
}

// TeamWithin (billing-service.ts billingServiceOf().teamWithin): Whether a team is `teamID` or below it.
func (s *BillingService) TeamWithin(dir *core.Object, candidate string, teamID string) (result bool, err error) {
	chain, err := TeamChain(bsDirectoryMap(dir, "teams"), candidate)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(chain, func(team *core.Object) bool { return bsIs(team.Get("id"), teamID) }), nil
}

// DepartmentWithin (billing-service.ts billingServiceOf().departmentWithin): Whether a department is
// `departmentID` or below it.
func (s *BillingService) DepartmentWithin(dir *core.Object, candidate string, departmentID string) (result bool, err error) {
	chain, err := DepartmentChain(bsDirectoryMap(dir, "departments"), candidate)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(chain, func(department *core.Object) bool { return bsIs(department.Get("id"), departmentID) }), nil
}

// --- anomalies -------------------------------------------------------------------------------------------------------

type bsAnomalyOptions struct {
	day           string
	baselineDays  float64
	factor        float64
	minimumMicros float64
}

var bsDayPattern = regexp.MustCompile(`^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$`)

// anomalyOptions validates anomaly settings (AnomalyOptions: `{ day?, baselineDays?, factor?, minimum? }`).
func (s *BillingService) anomalyOptions(input *core.Object) (bsAnomalyOptions, error) {
	options := bsAnomalyOptions{}
	now := s.server.Now()
	if raw := member(input, "day"); isUndefined(raw) {
		day, err := DayOf(now-86_400_000, s.tz)
		if err != nil {
			return options, err
		}
		options.day = day
	} else if text := jsString(raw); bsDayPattern.MatchString(text) {
		options.day = text
	} else {
		return options, invalidInput("day must be a date such as 2026-09-22")
	}
	options.baselineDays = 14
	if raw := member(input, "baselineDays"); !isUndefined(raw) {
		value, err := Integer(raw, "baselineDays", 3, 90)
		if err != nil {
			return options, err
		}
		options.baselineDays = value
	}
	options.factor = 3
	if raw := member(input, "factor"); !isUndefined(raw) {
		value, ok := raw.(float64)
		if !ok || math.IsNaN(value) || math.IsInf(value, 0) || value < 1.1 || value > 1000 {
			return options, invalidInput("factor must be a number from 1.1 to 1000")
		}
		options.factor = value
	}
	options.minimumMicros = 10 * 1_000_000
	if raw := member(input, "minimum"); !isUndefined(raw) {
		value, err := AmountMicros(raw, "minimum")
		if err != nil {
			return options, err
		}
		options.minimumMicros = value
	}
	return options, nil
}

// bsDaysBefore is the `count` days before `day` (oldest first), as dates.
func bsDaysBefore(day string, count int) []string {
	parts := strings.Split(day, "-")
	numbers := make([]int, 3)
	for index := 0; index < 3 && index < len(parts); index++ {
		numbers[index], _ = strconv.Atoi(parts[index])
	}
	out := make([]string, count)
	for index := range out {
		at := time.Date(numbers[0], time.Month(numbers[1]), numbers[2]-(count-index), 0, 0, 0, 0, time.UTC)
		out[index] = bsIsoDate(float64(at.UnixMilli()))
	}
	return out
}

type bsAnomalyTotal struct{ onDay, before float64 }

// findAnomalies finds spend spikes: people, teams and meters whose spend on `day` (default yesterday) is at least
// `factor` (3) times their average over the `baselineDays` (14) before it and at least `minimum` (10 currency units)
// above it, or new spenders above `minimum`. Rows come from `rowsFor` (charged usage of one scope), so costs follow
// each month's blended rates.
func (s *BillingService) findAnomalies(ctx context.Context, tx core.IamStore, rowsFor func(period string) ([]*core.Object, error), input *core.Object, scopeIDs []string) ([]*core.Object, error) {
	options, err := s.anomalyOptions(input)
	if err != nil {
		return nil, err
	}
	calc := &bsCalc{}
	day := options.day
	baseline := bsDaysBefore(day, int(options.baselineDays))
	window := newOrderedSet(append(append([]string{}, baseline...), day)...)
	periods := newOrderedSet()
	for _, value := range window.Values() {
		if len(value) >= 7 {
			periods.Add(value[:7])
		} else {
			periods.Add(value)
		}
	}
	var rows []*core.Object
	for _, period := range periods.Values() {
		found, err := rowsFor(period)
		if err != nil {
			return nil, err
		}
		for _, row := range found {
			if window.Has(jsString(row.Get("day"))) {
				rows = append(rows, row)
			}
		}
	}
	dir, err := s.directory(ctx, tx, rows, scopeIDs)
	if err != nil {
		return nil, err
	}
	totals := map[string]*bsAnomalyTotal{}
	var order []string
	meterIDs := map[string]string{}
	add := func(key string, row *core.Object, weight float64) {
		entry := totals[key]
		if entry == nil {
			entry = &bsAnomalyTotal{}
			totals[key] = entry
			order = append(order, key)
		}
		if bsIs(row.Get("day"), day) {
			entry.onDay += bsNum(row, "costMicros") * weight
		} else {
			entry.before += bsNum(row, "costMicros") * weight
		}
	}
	for _, row := range rows {
		if principal := coalesce(row.Get("agentId"), row.Get("identityId")); truthy(principal) {
			add("identity|"+jsString(principal), row, 1)
		}
		meter := jsString(row.Get("meter"))
		add("meter|"+meter, row, 1)
		meterIDs[meter] = jsString(row.Get("meterId"))
		teamIDs := bsStrings(row.Get("teamIds"))
		share := 1.0
		if !s.fullTeams() {
			share = 1 / bsMax(1, float64(len(teamIDs)))
		}
		for _, team := range teamIDs {
			add("team|"+team, row, share)
		}
	}
	var found []*core.Object
	for _, compound := range order {
		entry := totals[compound]
		costMicros := calc.micros(entry.onDay)
		baselineMicros := calc.micros(entry.before / options.baselineDays)
		if calc.err != nil {
			return nil, calc.err
		}
		if costMicros < options.minimumMicros || costMicros-baselineMicros < options.minimumMicros {
			continue
		}
		if baselineMicros > 0 && costMicros < baselineMicros*options.factor {
			continue
		}
		parts := strings.Split(compound, "|")
		var factor any
		if baselineMicros > 0 {
			factor = jsMathRound((costMicros/baselineMicros)*10) / 10
		}
		found = append(found, core.NewObject("dimension", parts[0], "key", parts[1], "day", day,
			"costMicros", costMicros, "baselineMicros", baselineMicros, "factor", factor))
	}
	slices.SortStableFunc(found, func(a, b *core.Object) int {
		return bsOrder(bsNum(b, "costMicros")-bsNum(b, "baselineMicros")-(bsNum(a, "costMicros")-bsNum(a, "baselineMicros")),
			bsKeyOrder(bsStr(a, "key"), bsStr(b, "key")))
	})
	if len(found) > 50 {
		found = found[:50]
	}
	for _, anomaly := range found {
		key := bsStr(anomaly, "key")
		var label any = core.Undefined
		switch bsStr(anomaly, "dimension") {
		case "team":
			label = bsDirectoryName(dir, "teams", key)
		case "identity":
			identity, err := tx.Get(ctx, "identities", key)
			if err != nil {
				return nil, err
			}
			if identity != nil {
				label = identity.Get("name")
			}
		default:
			meter, err := tx.Get(ctx, BillingCollections.Meters, meterIDs[key])
			if err != nil {
				return nil, err
			}
			if meter != nil {
				label = meter.Get("name")
			}
		}
		if !isUndefined(label) {
			anomaly.Set("label", label)
		}
	}
	return found, nil
}

// Anomalies (billing-service.ts billingServiceOf().anomalies): spend anomalies within a tenant's subtree, for
// `billing.anomalies` (input AnomalyOptions).
func (s *BillingService) Anomalies(ctx context.Context, tx core.IamStore, scope *core.Object, input *core.Object) (result []*core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	cache := map[string]any{}
	return s.findAnomalies(ctx, tx, func(period string) ([]*core.Object, error) {
		spend, err := ScopeSpend(ctx, s.server, tx, scope, period, cache)
		if err != nil {
			return nil, err
		}
		return bsObjects(spend.Get("rows")), nil
	}, input, []string{bsStr(scope, "id")})
}

// DetectAnomalies (billing-service.ts billingServiceOf().detectAnomalies): Checks every billing account for spend
// spikes on `day` (default yesterday) and alerts once per person, team or meter and day: audited as `billing:anomaly`
// and, with an email transport, one `spend-anomaly` email per account to its billing emails (or owners). A scheduler
// job, run daily after midnight in the billing time zone. input is AnomalyOptions plus `tenantId?`.
func (s *BillingService) DetectAnomalies(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	if err = s.ready(); err != nil {
		return
	}
	server := s.server
	store := server.Store
	rawTenantID := member(input, "tenantId")
	options := core.NewObject()
	if input != nil {
		options = input.Clone()
		options.Delete("tenantId")
	}
	if _, err := s.anomalyOptions(options); err != nil {
		return nil, err
	}
	accounts, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		found := map[string]*core.Object{}
		var candidates []*core.Object
		if isUndefined(rawTenantID) {
			if candidates, err = tx.Find(ctx, "tenants", core.NewObject("status", "active"), nil); err != nil {
				return nil, err
			}
		} else {
			tenantID, err := Text(rawTenantID, "tenantId")
			if err != nil {
				return nil, err
			}
			tenant, err := server.Tenant(ctx, tx, tenantID)
			if err != nil {
				return nil, err
			}
			candidates = []*core.Object{tenant}
		}
		for _, realm := range candidates {
			if parentID, ok := realm.Lookup("parentId"); ok && parentID == nil {
				continue
			}
			account, err := AccountOf(ctx, server, tx, realm)
			if err != nil {
				return nil, err
			}
			if !isUndefined(rawTenantID) || core.StrictEquals(account.Get("id"), realm.Get("id")) {
				found[bsStr(account, "id")] = account
			}
		}
		list := make([]*core.Object, 0, len(found))
		for _, account := range found {
			list = append(list, account)
		}
		slices.SortStableFunc(list, bsByID)
		return list, nil
	})
	if err != nil {
		return nil, err
	}
	checked := 0
	anomalies := []any{}
	currency := s.currency()
	for _, candidate := range accounts {
		err := store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			account, err := server.Tenant(ctx, tx, candidate.Get("id"))
			if err != nil {
				return err
			}
			if bsIs(account.Get("status"), "deleted") {
				return nil
			}
			checked++
			accountID := bsStr(account, "id")
			cache := map[string]any{}
			found, err := s.findAnomalies(ctx, tx, func(period string) ([]*core.Object, error) {
				spend, err := AccountSpend(ctx, server, tx, account, period, cache)
				if err != nil {
					return nil, err
				}
				return bsObjects(spend.Get("rows")), nil
			}, options, []string{accountID})
			if err != nil {
				return err
			}
			var fresh []*core.Object
			for _, anomaly := range found {
				dimension, key, day := bsStr(anomaly, "dimension"), bsStr(anomaly, "key"), bsStr(anomaly, "day")
				uniqueKey := "anomaly:" + dimension + ":" + key + ":" + day
				existing, err := tx.Find(ctx, BillingCollections.BudgetAlerts, core.NewObject("tenantId", accountID, "uniqueKey", uniqueKey), nil)
				if err != nil {
					return err
				}
				if len(existing) > 0 {
					continue
				}
				if _, err := tx.Insert(ctx, BillingCollections.BudgetAlerts, core.NewObject(
					"id", ID(), "tenantId", accountID, "uniqueKey", uniqueKey, "budgetId", "", "window", day,
					"kind", "anomaly", "threshold", coalesce(anomaly.Get("factor"), 0.0),
					"spentMicros", anomaly.Get("costMicros"), "alertedAt", float64(server.Now()),
				)); err != nil {
					return err
				}
				metadata := core.NewObject("dimension", dimension, "key", key)
				if label := anomaly.Get("label"); !isUndefined(label) {
					metadata.Set("label", label)
				}
				metadata.Set("day", day)
				metadata.Set("costMicros", anomaly.Get("costMicros"))
				metadata.Set("baselineMicros", anomaly.Get("baselineMicros"))
				metadata.Set("factor", anomaly.Get("factor"))
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(), "tenantId", accountID, "actorId", "deployment-operator", "action", "billing:anomaly",
					"resourceId", "billing/anomalies/"+dimension+"/"+key, "timestamp", float64(server.Now()),
					"outcome", "allow", "metadata", metadata,
				)); err != nil {
					return err
				}
				fresh = append(fresh, anomaly)
			}
			if len(fresh) == 0 {
				return nil
			}
			var recipients []string
			if s.sendsEmail() {
				profile, err := ProfileOf(ctx, tx, accountID)
				if err != nil {
					return err
				}
				if emails := bsStrings(profile.Get("billingEmails")); len(bsAnyList(profile.Get("billingEmails"))) > 0 {
					recipients = emails
				} else if recipients, err = s.owners(ctx, tx, accountID); err != nil {
					return err
				}
			}
			lines := []any{}
			for index, anomaly := range fresh {
				if index >= 5 {
					break
				}
				what := "Person"
				switch bsStr(anomaly, "dimension") {
				case "meter":
					what = "Meter"
				case "team":
					what = "Team"
				}
				spent, err := FormatMoney(bsNum(anomaly, "costMicros"), currency)
				if err != nil {
					return err
				}
				usual, err := FormatMoney(bsNum(anomaly, "baselineMicros"), currency)
				if err != nil {
					return err
				}
				lines = append(lines, core.NewObject("what", what+" "+jsString(coalesce(anomaly.Get("label"), anomaly.Get("key"))),
					"spent", spent, "usual", usual))
			}
			items := core.MustStringify(lines)
			for _, to := range recipients {
				if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
					TenantID: accountID, Kind: "email", To: to, Template: "spend-anomaly",
					Payload: core.NewObject("tenantId", accountID, "tenantName", account.Get("name"), "day", fresh[0].Get("day"),
						"count", strconv.Itoa(len(fresh)), "items", items),
				}); err != nil {
					return err
				}
			}
			for _, anomaly := range fresh {
				entry := core.NewObject("accountId", accountID)
				entry.Assign(anomaly)
				entry.Set("recipients", float64(len(recipients)))
				anomalies = append(anomalies, entry)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return core.NewObject("checked", float64(checked), "anomalies", anomalies), nil
}

// --- CSV -------------------------------------------------------------------------------------------------------------

// bsToFixed is Number.prototype.toFixed.
func bsToFixed(value float64, digits int) string {
	if math.IsNaN(value) {
		return "NaN"
	}
	if math.Abs(value) >= 1e21 {
		return core.NumberString(value)
	}
	if value == 0 {
		value = 0
	}
	return strconv.FormatFloat(value, 'f', digits, 64)
}

// SpendCsv (billing-service.ts billingServiceOf().spendCsv): A spend report as CSV: one row per group with amount,
// share, events and a column per meter's quantity.
func (s *BillingService) SpendCsv(report *core.Object) (result string, err error) {
	rows := bsObjects(report.Get("rows"))
	meterSet := newOrderedSet()
	for _, row := range rows {
		quantities, _ := row.Get("quantities").(*core.Object)
		for _, meter := range quantities.Keys() {
			meterSet.Add(meter)
		}
	}
	meters := bsSortStrings(meterSet.Values())
	header := []any{report.Get("groupBy"), "label", "amount_" + core.JSLower(jsString(report.Get("currency"))), "share_percent", "events"}
	for _, meter := range meters {
		header = append(header, "quantity_"+meter)
	}
	lines := [][]any{header}
	for _, row := range rows {
		quantities, _ := row.Get("quantities").(*core.Object)
		label := row.Get("label")
		if nullish(label) {
			label = ""
		}
		line := []any{row.Get("key"), label, bsToFixed(bsNum(row, "costMicros")/1_000_000, 6), jsString(row.Get("share")), jsString(row.Get("events"))}
		for _, meter := range meters {
			line = append(line, jsString(coalesce(quantities.Get(meter), 0.0)))
		}
		lines = append(lines, line)
	}
	total, _ := report.Get("total").(*core.Object)
	footer := []any{"total", "", bsToFixed(bsNum(total, "costMicros")/1_000_000, 6), "100", jsString(total.Get("events"))}
	for range meters {
		footer = append(footer, "")
	}
	lines = append(lines, footer)
	return bsCSV(lines), nil
}

// StatementCsv (billing-service.ts billingServiceOf().statementCsv): A statement as CSV: its lines, credit and total,
// then the breakdown sections.
func (s *BillingService) StatementCsv(statement *core.Object) (result string, err error) {
	money := func(micros float64) string { return bsToFixed(micros/1_000_000, 6) }
	rows := [][]any{{"section", "id", "name", "quantity", "unit", "amount", "cost_center"}}
	for _, line := range bsObjects(statement.Get("lines")) {
		section := "line"
		if kind := line.Get("kind"); truthy(kind) && !bsIs(kind, "usage") {
			section = jsString(kind)
		}
		id := coalesce(line.Get("meter"), coalesce(line.Get("planItemId"), coalesce(line.Get("invoiceItemId"), "")))
		rows = append(rows, []any{section, id, line.Get("name"), jsString(line.Get("quantity")), line.Get("unit"), money(bsNum(line, "amountMicros")), ""})
	}
	rows = append(rows, []any{"subtotal", "", "", "", "", money(bsNum(statement, "subtotalMicros")), ""})
	if discount, ok := statement.Get("discount").(*core.Object); ok && discount != nil {
		rows = append(rows, []any{"discount", "", jsString(discount.Get("percent")) + "%", "", "", money(-bsNum(discount, "amountMicros")), ""})
	}
	if commitment, ok := statement.Get("commitment").(*core.Object); ok && commitment != nil && bsNum(commitment, "trueUpMicros") > 0 {
		rows = append(rows, []any{"commitment", "", "minimum commitment true-up", "", "", money(bsNum(commitment, "trueUpMicros")), ""})
	}
	for _, coupon := range bsObjects(statement.Get("coupons")) {
		rows = append(rows, []any{"coupon", coupon.Get("code"), coupon.Get("name"), "", "", money(-bsNum(coupon, "amountMicros")), ""})
	}
	rows = append(rows, []any{"credit", "", "", "", "", money(-bsNum(statement, "creditsMicros")), ""})
	if tax, ok := statement.Get("tax").(*core.Object); ok && tax != nil {
		rows = append(rows, []any{"tax", "", jsString(tax.Get("label")) + " " + jsString(tax.Get("ratePercent")) + "%", "", "", money(bsNum(tax, "amountMicros")), ""})
	}
	rows = append(rows, []any{"total", statement.Get("number"), statement.Get("period"), "", statement.Get("currency"), money(bsNum(statement, "totalMicros")), ""})
	breakdown, _ := statement.Get("breakdown").(*core.Object)
	for _, section := range []struct{ key, name string }{{"tenants", "tenant"}, {"teams", "team"}, {"departments", "department"}, {"identities", "identity"}} {
		for _, entry := range bsObjects(breakdown.Get(section.key)) {
			costCenter := any("")
			if section.key == "departments" {
				costCenter = coalesce(entry.Get("costCenter"), "")
			}
			rows = append(rows, []any{section.name, entry.Get("id"), entry.Get("name"), "", "", money(bsNum(entry, "costMicros")), costCenter})
		}
	}
	return bsCSV(rows), nil
}

var (
	bsFormulaStart = regexp.MustCompile(`^[=+\-@\t\r]`)
	bsPlainNumber  = regexp.MustCompile(`^-?\d+(\.\d+)?$`)
	bsNeedsQuotes  = regexp.MustCompile(`[",\r\n]`)
)

// bsCell is one CSV cell: undefined and null are empty (Array.prototype.join), formulas are prefixed with a quote.
func bsCell(value any) string {
	if nullish(value) {
		return ""
	}
	text := jsString(value)
	safe := text
	if bsFormulaStart.MatchString(text) && !bsPlainNumber.MatchString(text) {
		safe = "'" + text
	}
	if bsNeedsQuotes.MatchString(safe) {
		return `"` + strings.ReplaceAll(safe, `"`, `""`) + `"`
	}
	return safe
}

// bsCSV is RFC 4180 CSV; cells that spreadsheet programs would read as formulas are prefixed with a quote. Only plain
// numbers (`-12.5`) keep a leading minus: `-1+cmd|...` is a formula.
func bsCSV(rows [][]any) string {
	lines := make([]string, len(rows))
	for index, row := range rows {
		cells := make([]string, len(row))
		for column, value := range row {
			cells[column] = bsCell(value)
		}
		lines[index] = strings.Join(cells, ",")
	}
	return strings.Join(lines, "\r\n") + "\r\n"
}

// MentionsSpend (billing-service.ts mentionsSpend): whether any statement of the documents names a spend context
// key, so decisions read budgets only when needed.
func MentionsSpend(documents []any) bool {
	return anyStatementsMention(documents, "principal.spendExceeded") || anyStatementsMention(documents, "principal.budgetsExceeded")
}
