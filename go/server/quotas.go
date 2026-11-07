package server

// Port of packages/server/src/quotas.ts: API usage plans and quotas (like AWS API Gateway usage plans). A plan
// throttles a meter (a token bucket of `ratePerSecond` with room for `burst`) and caps it per minute, hour, day, week
// or month. Plans apply to API keys, agents, people and groups, or to everyone in the tenant by default;
// `iam.quotas.consume` counts use and refuses what a plan does not allow, with the time to retry. Counters live in the
// database, so every server instance sees the same totals.
//
// quotaPlans records: id, tenantId, uniqueKey (the name), name, meter, throttle?, limits, scope, default, priority,
// timeZone, alertThresholds, createdAt, createdBy, updatedAt, updatedBy, description?.
// quotaAssignments records: id, tenantId, uniqueKey `{meter}:{subjectType}:{subjectId}`, planId, meter, subjectType,
// subjectId, createdAt, createdBy.
// quotaCounters records: id `quota:{planId}:{subjectKey}:{suffix}`, tenantId, planId, subjectKey, kind ('window' |
// 'bucket'), period?, windowStart?, windowEnd?, used?, alerted?, exceededAt?, tokens?, updatedAt?, expiresAt.

import (
	"context"
	"math"
	"regexp"
	"sort"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// QuotaExceededError is quotas.ts QuotaExceededError (an IamError; it unwraps to the *core.IamError).
// TypeScript: super( 'QUOTA_EXCEEDED', decision.reason === 'throttle' ? `Too many ${decision.meter} requests; slow down` : `The ${decision.reason} ${decision.meter} quota of plan ${decision.plan} is used up`, 429, );
type QuotaExceededError struct {
	*core.IamError
	Decision     *core.Object
	RetryAfterMs *float64
}

func (e *QuotaExceededError) Unwrap() error { return e.IamError }

// Name is the JavaScript error name.
func (e *QuotaExceededError) Name() string { return "QuotaExceededError" }

// NewQuotaExceededError is `new QuotaExceededError(decision, retryAfterMs)`: the error `enforce` throws, 429 with the
// time to retry (`Retry-After` over HTTP).
func NewQuotaExceededError(decision *core.Object, retryAfterMs *float64) *QuotaExceededError {
	var message string
	if decision.Get("reason") == "throttle" {
		message = "Too many " + jsString(decision.Get("meter")) + " requests; slow down"
	} else {
		message = "The " + jsString(decision.Get("reason")) + " " + jsString(decision.Get("meter")) +
			" quota of plan " + jsString(decision.Get("plan")) + " is used up"
	}
	return &QuotaExceededError{IamError: core.NewIamError("QUOTA_EXCEEDED", message, 429), Decision: decision, RetryAfterMs: retryAfterMs}
}

// quotaPeriods are the period limits a plan may set, shortest first.
var quotaPeriods = []string{"minute", "hour", "day", "week", "month"}

func quotaPeriodIndex(period string) int {
	for index, item := range quotaPeriods {
		if item == period {
			return index
		}
	}
	return -1
}

// --- validation ----------------------------------------------------------------------------------

var quotaNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// AlertThresholds (quotas.ts alertThresholds): percentages of a period limit that record `quota:threshold` once per
// window: at most 5, each 1 to 100, deduplicated and sorted.
func AlertThresholds(value any) (result []float64, err error) {
	if isUndefined(value) {
		return []float64{}, nil
	}
	list, ok := value.([]any)
	if !ok || len(list) > 5 {
		return nil, invalidInput("alertThresholds lists at most 5 percentages")
	}
	result = []float64{}
	seen := map[float64]bool{}
	for _, item := range list {
		threshold, err := Integer(item, "alert threshold", 1, 100)
		if err != nil {
			return nil, err
		}
		if !seen[threshold] {
			seen[threshold] = true
			result = append(result, threshold)
		}
	}
	sort.Float64s(result)
	return result, nil
}

// ConsumeQuota (quotas.ts consumeQuota): Counts `cost` units of `meter` for a subject inside the caller's
// transaction, or refuses without counting anything when the throttle or a period limit would be exceeded. `dryRun`
// reports the status without counting.
func ConsumeQuota(ctx context.Context, server *ServerContext, tx core.IamStore, subject *core.Object, meter string, cost float64, record func(context.Context, core.IamStore, string, *core.Object) error, dryRun bool) (result *core.Object, err error) {
	resolved, err := ResolvePlan(ctx, server, tx, subject, meter)
	if err != nil {
		return nil, err
	}
	if resolved == nil {
		return core.NewObject("allowed", true, "meter", meter, "plan", nil, "cost", cost, "limits", []any{}), nil
	}
	plan, _ := resolved.Get("plan").(*core.Object)
	subjectKey := jsString(resolved.Get("subjectKey"))
	planID := jsString(plan.Get("id"))
	now := float64(server.Now())
	reason := ""
	var retryAfterMs *float64
	// The throttle: a token bucket refilled continuously.
	throttle, _ := plan.Get("throttle").(*core.Object)
	hasThrottle := truthy(plan.Get("throttle"))
	var bucket *core.Object
	tokens := 0.0
	var burst, rate float64
	if hasThrottle {
		burst, rate = jsNumber(member(plan.Get("throttle"), "burst")), jsNumber(member(plan.Get("throttle"), "ratePerSecond"))
		if bucket, err = tx.Get(ctx, QuotaCollections.Counters, quotaCounterID(planID, subjectKey, "bucket")); err != nil {
			return nil, err
		}
		elapsed := math.Inf(1)
		if bucket != nil && !isUndefined(bucket.Get("updatedAt")) {
			elapsed = math.Max(0, now-jsNumber(bucket.Get("updatedAt")))
		}
		held := burst
		if bucket != nil && !nullish(bucket.Get("tokens")) {
			held = jsNumber(bucket.Get("tokens"))
		}
		tokens = quotaMin(burst, held+(elapsed/1000)*rate)
		if tokens < cost && !dryRun {
			reason = "throttle"
			retryAfterMs = nil
			if !(cost > burst) {
				wait := math.Ceil(((cost - tokens) / rate) * 1000)
				retryAfterMs = &wait
			}
		}
	}
	// Period limits: fixed windows.
	type quotaWindowState struct {
		period  string
		limit   float64
		start   float64
		end     float64
		counter *core.Object
	}
	var windows []quotaWindowState
	limits, _ := plan.Get("limits").([]any)
	for _, item := range limits {
		period := jsString(member(item, "period"))
		limit := jsNumber(member(item, "limit"))
		start, end, err := quotaWindowBounds(period, now, jsString(plan.Get("timeZone")))
		if err != nil {
			return nil, err
		}
		counter, err := tx.Get(ctx, QuotaCollections.Counters, quotaCounterID(planID, subjectKey, period+":"+core.NumberString(start)))
		if err != nil {
			return nil, err
		}
		windows = append(windows, quotaWindowState{period: period, limit: limit, start: start, end: end, counter: counter})
		if reason == "" && !dryRun && quotaCounterUsed(counter)+cost > limit {
			reason = period
			retryAfterMs = nil
			if !(cost > limit) {
				wait := end - now
				retryAfterMs = &wait
			}
		}
	}
	allowed := reason == ""
	statuses := func(spent float64) []any {
		out := make([]any, len(windows))
		for index, window := range windows {
			used := quotaCounterUsed(window.counter) + spent
			out[index] = core.NewObject(
				"period", window.period,
				"limit", window.limit,
				"used", used,
				"remaining", math.Max(0, window.limit-used),
				"resetAt", window.end,
			)
		}
		return out
	}
	withThrottle := func(out *core.Object, left float64) *core.Object {
		if hasThrottle {
			copied := core.NewObject()
			if throttle != nil {
				copied = throttle.Clone()
			}
			out.Set("throttle", copied.Set("tokens", math.Floor(left)))
		}
		return out
	}
	if dryRun {
		return withThrottle(core.NewObject(
			"allowed", true, "meter", meter, "plan", plan.Get("name"), "via", resolved.Get("via"), "cost", 0.0, "limits", statuses(0),
		), tokens), nil
	}
	base := func(id string) *core.Object {
		return core.NewObject("id", id, "tenantId", plan.Get("tenantId"), "planId", plan.Get("id"), "subjectKey", subjectKey)
	}
	if !allowed {
		// Recorded once per window, the first time the window refuses.
		var refused *quotaWindowState
		for index := range windows {
			if windows[index].period == reason {
				refused = &windows[index]
				break
			}
		}
		if refused != nil && (refused.counter == nil || isUndefined(refused.counter.Get("exceededAt"))) {
			var counter *core.Object
			if refused.counter != nil {
				counter = refused.counter.Clone()
			} else {
				counter = base(quotaCounterID(planID, subjectKey, refused.period+":"+core.NumberString(refused.start))).
					Set("kind", "window").
					Set("period", refused.period).
					Set("windowStart", refused.start).
					Set("windowEnd", refused.end).
					Set("used", 0.0).
					Set("expiresAt", refused.end+quotaDay)
			}
			next := counter.Set("exceededAt", now)
			if refused.counter != nil {
				_, err = tx.Put(ctx, QuotaCollections.Counters, next)
			} else {
				_, err = tx.Insert(ctx, QuotaCollections.Counters, next)
			}
			if err != nil {
				return nil, err
			}
			if err := record(ctx, tx, "quota:exceeded", core.NewObject(
				"plan", plan.Get("name"),
				"meter", meter,
				"period", refused.period,
				"limit", refused.limit,
				"subject", subjectKey,
			)); err != nil {
				return nil, err
			}
		}
		out := withThrottle(core.NewObject(
			"allowed", false, "meter", meter, "plan", plan.Get("name"), "via", resolved.Get("via"), "cost", cost, "limits", statuses(0),
		), tokens).Set("reason", reason)
		if retryAfterMs != nil {
			out.Set("retryAfterMs", *retryAfterMs)
		}
		return out, nil
	}
	if hasThrottle {
		next := base(quotaCounterID(planID, subjectKey, "bucket")).
			Set("kind", "bucket").
			Set("tokens", tokens-cost).
			Set("updatedAt", now).
			// A full bucket after this long is the same as no record.
			Set("expiresAt", now+math.Ceil((burst/rate)*1000)+quotaMinute)
		if bucket != nil {
			_, err = tx.Put(ctx, QuotaCollections.Counters, next)
		} else {
			_, err = tx.Insert(ctx, QuotaCollections.Counters, next)
		}
		if err != nil {
			return nil, err
		}
	}
	thresholds, _ := plan.Get("alertThresholds").([]any)
	for _, window := range windows {
		used := quotaCounterUsed(window.counter) + cost
		var alerted []any
		if window.counter != nil {
			if list, ok := window.counter.Get("alerted").([]any); ok {
				alerted = list
			}
		}
		var crossed []any
		for _, threshold := range thresholds {
			if used*100 >= jsNumber(threshold)*window.limit && !quotaIncludes(alerted, threshold) {
				crossed = append(crossed, threshold)
			}
		}
		var next *core.Object
		if window.counter != nil {
			next = window.counter.Clone()
		} else {
			next = base(quotaCounterID(planID, subjectKey, window.period+":"+core.NumberString(window.start))).
				Set("kind", "window").
				Set("period", window.period).
				Set("windowStart", window.start).
				Set("windowEnd", window.end).
				Set("expiresAt", window.end+quotaDay)
		}
		next.Set("used", used)
		if len(crossed) > 0 {
			merged := append(append([]any{}, alerted...), crossed...)
			sortStable(merged, func(a, b any) int {
				difference := jsNumber(a) - jsNumber(b)
				if difference < 0 {
					return -1
				}
				if difference > 0 {
					return 1
				}
				return 0
			})
			next.Set("alerted", merged)
		}
		if window.counter != nil {
			_, err = tx.Put(ctx, QuotaCollections.Counters, next)
		} else {
			_, err = tx.Insert(ctx, QuotaCollections.Counters, next)
		}
		if err != nil {
			return nil, err
		}
		for _, threshold := range crossed {
			if err := record(ctx, tx, "quota:threshold", core.NewObject(
				"plan", plan.Get("name"),
				"meter", meter,
				"period", window.period,
				"threshold", threshold,
				"limit", window.limit,
				"used", used,
				"subject", subjectKey,
			)); err != nil {
				return nil, err
			}
		}
	}
	return withThrottle(core.NewObject(
		"allowed", true, "meter", meter, "plan", plan.Get("name"), "via", resolved.Get("via"), "cost", cost, "limits", statuses(cost),
	), tokens-cost), nil
}

// quotaCounterUsed is `counter?.used ?? 0`.
func quotaCounterUsed(counter *core.Object) float64 {
	if counter == nil || nullish(counter.Get("used")) {
		return 0
	}
	return jsNumber(counter.Get("used"))
}

// quotaIncludes is Array.prototype.includes (SameValueZero) for model values.
func quotaIncludes(list []any, value any) bool {
	for _, item := range list {
		if item == value {
			return true
		}
		if a, ok := item.(float64); ok {
			if b, ok := value.(float64); ok && math.IsNaN(a) && math.IsNaN(b) {
				return true
			}
		}
	}
	return false
}

// quotaMin is Math.min of two numbers (NaN when either is NaN).
func quotaMin(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Min(a, b)
}

// quotaCounterID is counterId: `quota:{planId}:{subjectKey}:{suffix}`.
func quotaCounterID(planID, subjectKey, suffix string) string {
	return "quota:" + planID + ":" + subjectKey + ":" + suffix
}

// QuotaLimits (quotas.ts quotaLimits): at most one limit per period, each 1 to 10^12 units, sorted by period.
func QuotaLimits(value any) (result []*core.Object, err error) {
	if isUndefined(value) {
		return []*core.Object{}, nil
	}
	list, ok := value.([]any)
	if !ok || len(list) > len(quotaPeriods) {
		return nil, invalidInput("limits must list at most one limit per period")
	}
	seen := map[string]bool{}
	result = []*core.Object{}
	for _, item := range list {
		entry, err := Object(item)
		if err != nil {
			return nil, err
		}
		period, isString := entry.Get("period").(string)
		if !isString || quotaPeriodIndex(period) < 0 {
			return nil, invalidInput("period must be minute, hour, day, week or month")
		}
		if seen[period] {
			return nil, invalidInput("Only one " + period + " limit per plan")
		}
		seen[period] = true
		limit, err := Integer(entry.Get("limit"), period+" limit", 1, 1_000_000_000_000)
		if err != nil {
			return nil, err
		}
		result = append(result, core.NewObject("period", period, "limit", limit))
	}
	sortStable(result, func(a, b *core.Object) int {
		return quotaPeriodIndex(jsString(a.Get("period"))) - quotaPeriodIndex(jsString(b.Get("period")))
	})
	return result, nil
}

// QuotaName (quotas.ts quotaName): 1-64 lowercase letters, digits and ._- starting with a letter or digit (plan
// names and meters).
func QuotaName(value any, name string) (result string, err error) {
	if name == "" {
		name = "name"
	}
	text, err := Text(value, name, 64)
	if err != nil {
		return "", err
	}
	if !quotaNamePattern.MatchString(text) {
		return "", invalidInput(name + " must be 1-64 lowercase letters, digits and ._- starting with a letter or digit")
	}
	return text, nil
}

// QuotaThrottle (quotas.ts quotaThrottle): `{ ratePerSecond, burst }`, burst defaulting to the rate rounded up (at
// least 1); nil when absent or null.
func QuotaThrottle(value any) (result *core.Object, err error) {
	if nullish(value) {
		return nil, nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	rate, isNumber := core.Normalize(input.Get("ratePerSecond")).(float64)
	if !isNumber || math.IsNaN(rate) || math.IsInf(rate, 0) || rate < 0.001 || rate > 1_000_000 {
		return nil, invalidInput("throttle.ratePerSecond must be 0.001 to 1000000")
	}
	var burst float64
	if isUndefined(input.Get("burst")) {
		burst = math.Max(1, math.Ceil(rate))
	} else if burst, err = Integer(input.Get("burst"), "throttle.burst", 1, 1_000_000_000); err != nil {
		return nil, err
	}
	return core.NewObject("ratePerSecond", rate, "burst", burst), nil
}

// --- windows -------------------------------------------------------------------------------------

const (
	quotaMinute = 60_000.0
	quotaHour   = 60 * quotaMinute
	quotaDay    = 24 * quotaHour
)

// quotaZonedParts are the wall-clock parts of an instant in a time zone.
type quotaZonedParts struct {
	year, month, day, hour, minute, second, weekday int
}

// quotaZoned is zoned(): the wall-clock parts of an instant in a time zone (Intl.DateTimeFormat).
func quotaZoned(at float64, location *time.Location) quotaZonedParts {
	local := time.UnixMilli(int64(math.Floor(at))).In(location)
	return quotaZonedParts{
		year: local.Year(), month: int(local.Month()), day: local.Day(),
		hour: local.Hour() % 24, minute: local.Minute(), second: local.Second(),
		weekday: int(local.Weekday()),
	}
}

// quotaDateUTC is Date.UTC(year, monthIndex, day, hours, minutes, seconds) (fields overflow into the next unit).
func quotaDateUTC(year, monthIndex, day, hours, minutes, seconds int) float64 {
	return float64(time.Date(year, time.Month(monthIndex+1), day, hours, minutes, seconds, 0, time.UTC).UnixMilli())
}

// quotaUTCDate is the UTC calendar date of new Date(Date.UTC(year, monthIndex, day)).
func quotaUTCDate(year, monthIndex, day int) (int, int, int) {
	date := time.Date(year, time.Month(monthIndex+1), day, 0, 0, 0, 0, time.UTC)
	return date.Year(), int(date.Month()), date.Day()
}

// quotaLocalMidnight is the instant a local date's midnight falls on in a time zone (the first instant of that local
// day).
func quotaLocalMidnight(year, month, day int, location *time.Location) float64 {
	guess := quotaDateUTC(year, month-1, day, 0, 0, 0)
	// Two corrections settle the zone offset, including on days a daylight-saving change shifts it.
	for step := 0; step < 2; step++ {
		parts := quotaZoned(guess, location)
		shown := quotaDateUTC(parts.year, parts.month-1, parts.day, parts.hour, parts.minute, parts.second)
		guess -= shown - quotaDateUTC(year, month-1, day, 0, 0, 0)
	}
	return guess
}

// quotaWindowBounds is quotaWindow as numbers.
func quotaWindowBounds(period string, at float64, zone string) (start, end float64, err error) {
	if period == "minute" {
		start = math.Floor(at/quotaMinute) * quotaMinute
		return start, start + quotaMinute, nil
	}
	if period == "hour" {
		start = math.Floor(at/quotaHour) * quotaHour
		return start, start + quotaHour, nil
	}
	location, err := LoadTimeZone(zone)
	if err != nil {
		return 0, 0, err
	}
	if math.IsNaN(at) || math.Abs(at) > 8.64e15 {
		return 0, 0, &rangeError{"Invalid time value"}
	}
	local := quotaZoned(at, location)
	if period == "day" {
		start = quotaLocalMidnight(local.year, local.month, local.day, location)
		year, month, day := quotaUTCDate(local.year, local.month-1, local.day+1)
		return start, quotaLocalMidnight(year, month, day, location), nil
	}
	if period == "week" {
		back := (local.weekday + 6) % 7 // days since Monday
		mondayYear, mondayMonth, mondayDay := quotaUTCDate(local.year, local.month-1, local.day-back)
		followingYear, followingMonth, followingDay := quotaUTCDate(local.year, local.month-1, local.day-back+7)
		return quotaLocalMidnight(mondayYear, mondayMonth, mondayDay, location),
			quotaLocalMidnight(followingYear, followingMonth, followingDay, location), nil
	}
	nextYear, nextMonth, _ := quotaUTCDate(local.year, local.month, 1)
	return quotaLocalMidnight(local.year, local.month, 1, location), quotaLocalMidnight(nextYear, nextMonth, 1, location), nil
}

// QuotaWindow (quotas.ts quotaWindow): The window of a period that contains `at`: minutes and hours in UTC, days,
// ISO weeks and months in `zone`.
func QuotaWindow(period string, at int64, zone string) (result *core.Object, err error) {
	start, end, err := quotaWindowBounds(period, float64(at), zone)
	if err != nil {
		return nil, err
	}
	return core.NewObject("start", start, "end", end), nil
}

// --- resolution ----------------------------------------------------------------------------------

// SubjectOf (quotas.ts subjectOf): The subject of a principal: its API key (for an API-key session), the agent of a
// delegated session, the identity.
func SubjectOf(principal *Principal) (result *core.Object, err error) {
	session := principal.Session
	result = core.NewObject("tenantId", session.Get("tenantId"), "identityId", principal.Identity.Get("id"))
	if session.Get("kind") == "api-key" {
		result.Set("apiKeyId", session.Get("id"))
	}
	if agentID := session.Get("agentId"); truthy(agentID) {
		result.Set("agentId", agentID)
	}
	return result, nil
}

// ResolvePlan (quotas.ts resolvePlan): the plan for a subject and meter, most specific first: an assignment to the
// API key, to the acting agent, to the identity, to one of its groups (the highest priority, then the name), else the
// tenant's default plan for the meter. The answer is { plan, via, subjectKey }, nil when no plan applies.
func ResolvePlan(ctx context.Context, server *ServerContext, tx core.IamStore, subject *core.Object, meter string) (*core.Object, error) {
	tenantID := subject.Get("tenantId")
	plans := map[string]*core.Object{}
	load := func(planID string) (*core.Object, error) {
		if _, ok := plans[planID]; !ok {
			plan, err := tx.Get(ctx, QuotaCollections.Plans, planID)
			if err != nil {
				return nil, err
			}
			if plan != nil && plan.Get("tenantId") == tenantID {
				plans[planID] = plan
			}
		}
		return plans[planID], nil
	}
	assigned := func(subjectType string, subjectID any) (*core.Object, error) {
		found, err := tx.Find(ctx, QuotaCollections.Assignments, core.NewObject(
			"tenantId", tenantID, "uniqueKey", meter+":"+subjectType+":"+jsString(subjectID),
		), nil)
		if err != nil || len(found) == 0 {
			return nil, err
		}
		return load(jsString(found[0].Get("planId")))
	}
	keyOf := func(plan *core.Object, own string) string {
		if plan.Get("scope") == "tenant" {
			return "tenant"
		}
		return own
	}
	resolved := func(plan *core.Object, via, subjectKey string) *core.Object {
		return core.NewObject("plan", plan, "via", via, "subjectKey", subjectKey)
	}
	if apiKeyID := subject.Get("apiKeyId"); truthy(apiKeyID) {
		plan, err := assigned("apiKey", apiKeyID)
		if err != nil {
			return nil, err
		}
		if plan != nil {
			return resolved(plan, "apiKey", keyOf(plan, "key:"+jsString(apiKeyID))), nil
		}
	}
	if agentID := subject.Get("agentId"); truthy(agentID) {
		plan, err := assigned("identity", agentID)
		if err != nil {
			return nil, err
		}
		if plan != nil {
			return resolved(plan, "agent", keyOf(plan, "identity:"+jsString(agentID))), nil
		}
	}
	identityID := jsString(subject.Get("identityId"))
	own, err := assigned("identity", identityID)
	if err != nil {
		return nil, err
	}
	if own != nil {
		return resolved(own, "identity", keyOf(own, "identity:"+identityID)), nil
	}
	sources, err := server.Decisions.GrantSources(ctx, tx, identityID, jsString(tenantID))
	if err != nil {
		return nil, err
	}
	var candidates []*core.Object
	for _, groupID := range sources.GroupIDs {
		plan, err := assigned("group", groupID)
		if err != nil {
			return nil, err
		}
		if plan != nil {
			candidates = append(candidates, plan)
		}
	}
	sortStable(candidates, func(a, b *core.Object) int {
		if difference := jsNumber(b.Get("priority")) - jsNumber(a.Get("priority")); difference != 0 && !math.IsNaN(difference) {
			if difference < 0 {
				return -1
			}
			return 1
		}
		return compareUTF16(jsString(a.Get("name")), jsString(b.Get("name")))
	})
	if len(candidates) > 0 {
		return resolved(candidates[0], "group", keyOf(candidates[0], "identity:"+identityID)), nil
	}
	defaults, err := tx.Find(ctx, QuotaCollections.Plans, core.NewObject("tenantId", tenantID, "meter", meter, "default", true), nil)
	if err != nil {
		return nil, err
	}
	sortStable(defaults, func(a, b *core.Object) int {
		if compareUTF16(jsString(a.Get("name")), jsString(b.Get("name"))) < 0 {
			return -1
		}
		return 1
	})
	if len(defaults) > 0 {
		return resolved(defaults[0], "default", keyOf(defaults[0], "identity:"+identityID)), nil
	}
	return nil, nil
}

// TimeZone (quotas.ts timeZone): an IANA time zone Intl accepts (default UTC).
func TimeZone(value any) (result string, err error) {
	if isUndefined(value) {
		return "UTC", nil
	}
	zone, err := Text(value, "timeZone", 64)
	if err != nil {
		return "", err
	}
	if _, err := LoadTimeZone(zone); err != nil {
		return "", invalidInput("Unknown timeZone")
	}
	return zone, nil
}

// QuotaCollections is quotas.ts quotaCollections.
var QuotaCollections = struct {
	Plans       string
	Assignments string
	Counters    string
}{"quotaPlans", "quotaAssignments", "quotaCounters"}

// RetryAfter is the retry hint the HTTP layer sends as Retry-After (retryAfterMs; 0 for none).
func (e *QuotaExceededError) RetryAfter() float64 {
	if e.RetryAfterMs == nil {
		return 0
	}
	return *e.RetryAfterMs
}
