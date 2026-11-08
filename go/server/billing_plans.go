package server

// Port of packages/server/src/billing-plans.ts: plans and subscriptions, what an account pays every month besides
// usage. A plan holds recurring fees, per-seat fees and its own prices for meters; a subscription ties a billing
// account to a plan with a start, an optional trial, a seat count and an end. Fee and seat items are billed in advance
// (on the invoice closing the month before, or on a first invoice when the subscription starts) or in arrears (on the
// month's own invoice), prorated to the part of the month the subscription was live and out of its trial. Seat changes
// and cancellations of advance-billed items create proration invoice items for the next invoice, as Stripe does.

import (
	"context"
	"math"
	"regexp"
	"slices"

	"github.com/Better-IAM/better-iam/go/core"
)

var (
	planItemIDPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	planKeyPattern    = regexp.MustCompile(`^[a-z][a-z0-9_.-]{0,63}$`)
)

// MaxPlansPerTenant is billing-plans.ts maxPlansPerTenant.
const MaxPlansPerTenant = 100

// PlanKey (billing-plans.ts planKey): A plan key: 1-64 lowercase letters, digits, `.`, `_` or `-`, starting with a
// letter.
func PlanKey(value any) (result string, err error) {
	text, ok := value.(string)
	if !ok || !planKeyPattern.MatchString(text) {
		return "", invalidInput("plan must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter")
	}
	return text, nil
}

// planItems is billing-plans.ts planItems: validates plan items given in currency units (`amount`, `unitAmount`, a
// usage item's `price`).
func planItems(value any) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > 20 {
		return nil, invalidInput("items must list 1-20 plan items")
	}
	ids := map[string]bool{}
	meters := map[string]bool{}
	out := make([]any, len(list))
	for index, raw := range list {
		input, err := Object(raw)
		if err != nil {
			return nil, err
		}
		itemID, ok := input.Get("id").(string)
		if !ok || !planItemIDPattern.MatchString(itemID) {
			return nil, invalidInput("Each item needs an id of 1-64 lowercase letters, digits, - or _")
		}
		if ids[itemID] {
			return nil, invalidInput("Duplicate item id " + itemID)
		}
		ids[itemID] = true
		name, err := Text(coalesce(input.Get("name"), itemID), "items.name", 128)
		if err != nil {
			return nil, err
		}
		name = core.JSTrim(name)
		billing := coalesce(input.Get("billing"), "advance")
		if billing != "advance" && billing != "arrears" {
			return nil, invalidInput("items.billing must be 'advance' or 'arrears'")
		}
		switch input.Get("kind") {
		case "fee":
			amount, err := AmountMicros(input.Get("amount"), "items.amount")
			if err != nil {
				return nil, err
			}
			out[index] = core.NewObject("id", itemID, "kind", "fee", "name", name, "amountMicros", amount, "billing", billing)
		case "seat":
			unitAmount, err := AmountMicros(input.Get("unitAmount"), "items.unitAmount")
			if err != nil {
				return nil, err
			}
			item := core.NewObject("id", itemID, "kind", "seat", "name", name, "unitAmountMicros", unitAmount, "billing", billing)
			if included := input.Get("includedSeats"); !isUndefined(included) && !core.StrictEquals(included, 0.0) {
				seats, err := Integer(included, "items.includedSeats", 0, 1_000_000)
				if err != nil {
					return nil, err
				}
				item.Set("includedSeats", seats)
			}
			out[index] = item
		case "usage":
			meter, err := MeterKey(input.Get("meter"))
			if err != nil {
				return nil, err
			}
			if meters[meter] {
				return nil, invalidInput("Two items price " + meter)
			}
			meters[meter] = true
			price, err := PriceSpec(input.Get("price"))
			if err != nil {
				return nil, err
			}
			out[index] = core.NewObject("id", itemID, "kind", "usage", "name", name, "meter", meter, "price", price)
		default:
			return nil, invalidInput("items.kind must be 'fee', 'seat' or 'usage'")
		}
	}
	return out, nil
}

// PlanSettings (billing-plans.ts planSettings): Validated plan settings; `current` supplies values an update leaves
// out. The result is {name, items, selfServe, archived, description?, trialDays?}.
func PlanSettings(input *core.Object, current *core.Object) (result *core.Object, err error) {
	currentValue := func(key string) any {
		if current == nil {
			return core.Undefined
		}
		return current.Get(key)
	}
	var name any
	if raw := input.Get("name"); isUndefined(raw) {
		name = currentValue("name")
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
	var items any
	if raw := input.Get("items"); isUndefined(raw) {
		items = currentValue("items")
	} else {
		list, err := planItems(raw)
		if err != nil {
			return nil, err
		}
		items = list
	}
	if !truthy(items) {
		return nil, invalidInput("items are required")
	}
	flag := func(value any, fallback any, field string) (any, error) {
		if isUndefined(value) {
			return fallback, nil
		}
		if _, ok := value.(bool); !ok {
			return nil, invalidInput(field + " must be a boolean")
		}
		return value, nil
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
	var trialDays any = core.Undefined
	switch raw := input.Get("trialDays"); {
	case raw == nil:
	case isUndefined(raw):
		trialDays = currentValue("trialDays")
	default:
		days, err := Integer(raw, "trialDays", 1, 365)
		if err != nil {
			return nil, err
		}
		trialDays = days
	}
	selfServe, err := flag(input.Get("selfServe"), coalesce(currentValue("selfServe"), false), "selfServe")
	if err != nil {
		return nil, err
	}
	archived, err := flag(input.Get("archived"), coalesce(currentValue("archived"), false), "archived")
	if err != nil {
		return nil, err
	}
	result = core.NewObject("name", name, "items", items, "selfServe", selfServe, "archived", archived)
	if !isUndefined(description) {
		result.Set("description", description)
	}
	if !isUndefined(trialDays) {
		result.Set("trialDays", trialDays)
	}
	return result, nil
}

// billableWindow is the part of `[start, end)` a subscription is billable in: live and past its trial.
func billableWindow(subscription *core.Object, start, end float64) (from, to float64, ok bool) {
	from = billMax(billMax(start, billNumber(subscription, "startedAt")), billNumberOr(subscription, "trialEndsAt", 0))
	to = billMin(end, billNumberOr(subscription, "endsAt", math.Inf(1)))
	return from, to, to > from
}

// seatMonths is the chargeable seats (above the included ones) from the subscription's seat history, weighted by time
// in `[from, to)`.
func seatMonths(subscription, item *core.Object, start, end, windowFrom, windowTo float64) float64 {
	history := billObjects(subscription.Get("seatHistory"))
	if len(history) == 0 {
		history = []*core.Object{core.NewObject("at", subscription.Get("startedAt"), "seats", subscription.Get("seats"))}
	}
	total := 0.0
	for index, entry := range history {
		next := math.Inf(1)
		if index+1 < len(history) {
			next = billNumberOr(history[index+1], "at", math.Inf(1))
		}
		chargeable := billMax(0, billNumber(entry, "seats")-billNumberOr(item, "includedSeats", 0))
		if !truthy(chargeable) {
			continue
		}
		from := billMax(windowFrom, billNumber(entry, "at"))
		to := billMin(windowTo, next)
		if to > from {
			total += chargeable * overlapShare(start, end, from, to)
		}
	}
	return jsMathRound(total*10_000) / 10_000
}

// itemLine is one fee or seat line for a subscription item over a month and the part of it that is billable.
func itemLine(subscription, item *core.Object, start, end, windowFrom, windowTo float64) *core.Object {
	share := overlapShare(start, end, windowFrom, windowTo)
	if share <= 0 {
		return nil
	}
	description := jsString(subscription.Get("planName")) + ": " + jsString(item.Get("name"))
	servicePeriod := core.NewObject("start", start, "end", end)
	if item.Get("kind") == "fee" {
		amount := billNumber(item, "amountMicros")
		line := core.NewObject("kind", "fee", "name", item.Get("name"), "unit", "month", "quantity", 1.0,
			"unitAmountMicros", item.Get("amountMicros"), "amountMicros", roundCents(amount*share),
			"subscriptionId", subscription.Get("id"), "planItemId", item.Get("id"), "servicePeriod", servicePeriod)
		if share < 1 {
			line.Set("proration", share)
		}
		line.Set("description", description)
		return line
	}
	seats := seatMonths(subscription, item, start, end, windowFrom, windowTo)
	if seats <= 0 {
		return nil
	}
	// Seats are shown as seat-months, so the proration is already in the quantity.
	return core.NewObject("kind", "seat", "name", item.Get("name"), "unit", "seat-month", "quantity", seats,
		"unitAmountMicros", item.Get("unitAmountMicros"), "amountMicros", roundCents(billNumber(item, "unitAmountMicros")*seats),
		"subscriptionId", subscription.Get("id"), "planItemId", item.Get("id"), "servicePeriod", servicePeriod,
		"description", description)
}

// advanceItem is `item.kind !== 'usage' && item.billing !== 'arrears'`.
func advanceItem(item *core.Object) bool {
	return item.Get("kind") != "usage" && item.Get("billing") != "arrears"
}

// SubscriptionLines (billing-plans.ts subscriptionLines): The fee and seat lines an account's invoice for `period`
// carries: arrears items for `period` itself, advance items for the month after it, and advance items of `period`
// that no invoice has billed yet (a trial that ended within the month, a voided subscription invoice). `advance`
// lists the subscription months the invoice pays for in advance, which are marked billed when it is finalized. The
// result is {lines, advance: [{subscriptionId, period}]}.
func SubscriptionLines(ctx context.Context, tx core.IamStore, accountID string, period string, timeZone string) (result *core.Object, err error) {
	lines := []any{}
	advance := []any{}
	hereStart, hereEnd, err := periodBounds(period, timeZone)
	if err != nil {
		return nil, err
	}
	subscriptions, err := tx.Find(ctx, BillingCollections.Subscriptions, core.NewObject("tenantId", accountID), nil)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(subscriptions, bySubscriptionStart)
	for _, subscription := range subscriptions {
		plan, err := tx.Get(ctx, BillingCollections.Plans, billString(subscription, "planId"))
		if err != nil {
			return nil, err
		}
		if plan == nil {
			continue
		}
		items := billObjects(plan.Get("items"))
		if from, to, ok := billableWindow(subscription, hereStart, hereEnd); ok {
			for _, item := range items {
				if item.Get("kind") != "usage" && item.Get("billing") == "arrears" {
					if line := itemLine(subscription, item, hereStart, hereEnd, from, to); line != nil {
						lines = append(lines, line)
					}
				}
			}
		}
		if !slices.ContainsFunc(items, advanceItem) {
			continue
		}
		billed := orgStrings(subscription, "billedAdvance")
		for _, target := range []string{period, shiftPeriod(period, 1)} {
			if slices.Contains(billed, target) {
				continue
			}
			start, end, err := periodBounds(target, timeZone)
			if err != nil {
				return nil, err
			}
			// Only months the subscription runs in.
			if billNumber(subscription, "startedAt") >= end {
				continue
			}
			if billHas(subscription, "endsAt") && billNumber(subscription, "endsAt") <= start {
				continue
			}
			if from, to, ok := billableWindow(subscription, start, end); ok {
				for _, item := range items {
					if advanceItem(item) {
						if line := itemLine(subscription, item, start, end, from, to); line != nil {
							lines = append(lines, line)
						}
					}
				}
			}
			// A month with nothing to bill in advance (a trial) still counts as handled.
			advance = append(advance, core.NewObject("subscriptionId", subscription.Get("id"), "period", target))
		}
	}
	return core.NewObject("lines", lines, "advance", advance), nil
}

// FirstPeriodLines (billing-plans.ts firstPeriodLines): The advance lines of a new subscription's first month (from
// its start, or its trial end, to the month's end). The result is {period, lines}.
func FirstPeriodLines(subscription *core.Object, plan *core.Object, timeZone string) (result *core.Object, err error) {
	period, err := periodOf(billNumber(subscription, "startedAt"), timeZone)
	if err != nil {
		return nil, err
	}
	start, end, err := periodBounds(period, timeZone)
	if err != nil {
		return nil, err
	}
	lines := []any{}
	if from, to, ok := billableWindow(subscription, start, end); ok {
		for _, item := range billObjects(plan.Get("items")) {
			if advanceItem(item) {
				if line := itemLine(subscription, item, start, end, from, to); line != nil {
					lines = append(lines, line)
				}
			}
		}
	}
	return core.NewObject("period", period, "lines", lines), nil
}

// ProrationItems (billing-plans.ts prorationItems): Proration invoice items for a change at `at` to advance-billed
// items of the current month (already paid for): a credit for what the old state no longer uses and a charge for
// what the new one adds, as Stripe prorates. Input: {subscription, plan, at, timeZone, seats?: {before, after},
// ending, createdBy}.
func ProrationItems(input *core.Object) (result []*core.Object, err error) {
	subscription, _ := input.Get("subscription").(*core.Object)
	plan, _ := input.Get("plan").(*core.Object)
	at := billNumber(input, "at")
	timeZone := jsString(input.Get("timeZone"))
	ending := truthy(input.Get("ending"))
	seatsInput, _ := input.Get("seats").(*core.Object)
	period, err := periodOf(at, timeZone)
	if err != nil {
		return nil, err
	}
	result = []*core.Object{}
	if !slices.Contains(orgStrings(subscription, "billedAdvance"), period) {
		return result, nil
	}
	start, end, err := periodBounds(period, timeZone)
	if err != nil {
		return nil, err
	}
	// Only the part of the month after the change and outside the trial was paid for and changes.
	from := billMax(at, billNumberOr(subscription, "trialEndsAt", 0))
	share := overlapShare(start, end, from, end)
	if share <= 0 {
		return result, nil
	}
	planName := jsString(plan.Get("name"))
	newItem := func(description string, amount float64) *core.Object {
		return core.NewObject(
			"id", ID(),
			"tenantId", subscription.Get("tenantId"),
			"description", description,
			"quantity", 1.0,
			"unitAmountMicros", amount,
			"amountMicros", amount,
			"period", period,
			"status", "pending",
			"source", "proration",
			"subscriptionId", subscription.Get("id"),
			"createdAt", at,
			"createdBy", input.Get("createdBy"),
		)
	}
	plural := func(count float64) string {
		if count == 1 {
			return ""
		}
		return "s"
	}
	for _, item := range billObjects(plan.Get("items")) {
		if item.Get("kind") == "usage" || item.Get("billing") == "arrears" {
			continue
		}
		if item.Get("kind") == "fee" && ending {
			amount := roundCents(-billNumber(item, "amountMicros") * share)
			if truthy(amount) {
				result = append(result, newItem("Unused time on "+planName+": "+jsString(item.Get("name")), amount))
			}
		}
		if item.Get("kind") == "seat" {
			included := billNumberOr(item, "includedSeats", 0)
			beforeSeats := billNumber(subscription, "seats")
			afterSeats := beforeSeats
			if seatsInput != nil {
				beforeSeats = billNumberOr(seatsInput, "before", beforeSeats)
				afterSeats = billNumberOr(seatsInput, "after", afterSeats)
			}
			before := billMax(0, beforeSeats-included)
			after := 0.0
			if !ending {
				after = billMax(0, afterSeats-included)
			}
			if before == after {
				continue
			}
			amount := roundCents((after - before) * billNumber(item, "unitAmountMicros") * share)
			var description string
			if after > before {
				added := after - before
				description = core.NumberString(added) + " added seat" + plural(added) + " on " + planName + " for the rest of the month"
			} else {
				removed := before - after
				description = "Unused time on " + core.NumberString(removed) + " seat" + plural(removed) + " of " + planName
			}
			result = append(result, newItem(description, amount))
		}
	}
	return result, nil
}
