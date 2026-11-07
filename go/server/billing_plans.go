package server

// Skeleton of packages/server/src/billing-plans.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// FirstPeriodLines (billing-plans.ts firstPeriodLines): The advance lines of a new subscription's first month (from
// its start, or its trial end, to the month's end).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FirstPeriodLines(subscription *core.Object, plan *core.Object, timeZone string) (result *core.Object, err error) {
	err = notImplemented("billing-plans.ts firstPeriodLines")
	return
}

// PlanKey (billing-plans.ts planKey): A plan key: 1-64 lowercase letters, digits, `.`, `_` or `-`, starting with a
// letter.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PlanKey(value any) (result string, err error) {
	err = notImplemented("billing-plans.ts planKey")
	return
}

// PlanSettings (billing-plans.ts planSettings): Validated plan settings; `current` supplies values an update leaves
// out.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PlanSettings(input *core.Object, current *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-plans.ts planSettings")
	return
}

// ProrationItems (billing-plans.ts prorationItems): Proration invoice items for a change at `at` to advance-billed
// items of the current month (already paid for): a credit for what the old state no longer uses and a charge for
// what the new one adds, as Stripe prorates.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ProrationItems(input *core.Object) (result []*core.Object, err error) {
	err = notImplemented("billing-plans.ts prorationItems")
	return
}

// SubscriptionLines (billing-plans.ts subscriptionLines): The fee and seat lines an account's invoice for `period`
// carries: arrears items for `period` itself, advance items for the month after it, and advance items of `period`
// that no invoice has billed yet (a trial that ended within the month, a voided subscription invoice). `advance`
// lists the subscription months the invoice pays for in advance, which are marked billed when it is finalized.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SubscriptionLines(ctx context.Context, tx core.IamStore, accountID string, period string, timeZone string) (result *core.Object, err error) {
	err = notImplemented("billing-plans.ts subscriptionLines")
	return
}

// MaxPlansPerTenant is billing-plans.ts maxPlansPerTenant.
const MaxPlansPerTenant = 100
