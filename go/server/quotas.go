package server

// Skeleton of packages/server/src/quotas.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

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

// AlertThresholds (quotas.ts alertThresholds): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AlertThresholds(value any) (result []float64, err error) {
	err = notImplemented("quotas.ts alertThresholds")
	return
}

// ConsumeQuota (quotas.ts consumeQuota): Counts `cost` units of `meter` for a subject inside the caller's
// transaction, or refuses without counting anything when the throttle or a period limit would be exceeded. `dryRun`
// reports the status without counting.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ConsumeQuota(ctx context.Context, server *ServerContext, tx core.IamStore, subject *core.Object, meter string, cost float64, record func(context.Context, core.IamStore, string, *core.Object) error, dryRun bool) (result *core.Object, err error) {
	err = notImplemented("quotas.ts consumeQuota")
	return
}

// QuotaLimits (quotas.ts quotaLimits): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func QuotaLimits(value any) (result []*core.Object, err error) {
	err = notImplemented("quotas.ts quotaLimits")
	return
}

// QuotaName (quotas.ts quotaName): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func QuotaName(value any, name string) (result string, err error) {
	err = notImplemented("quotas.ts quotaName")
	return
}

// QuotaThrottle (quotas.ts quotaThrottle): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func QuotaThrottle(value any) (result *core.Object, err error) {
	err = notImplemented("quotas.ts quotaThrottle")
	return
}

// QuotaWindow (quotas.ts quotaWindow): The window of a period that contains `at`: minutes and hours in UTC, days,
// ISO weeks and months in `zone`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func QuotaWindow(period string, at int64, zone string) (result *core.Object, err error) {
	err = notImplemented("quotas.ts quotaWindow")
	return
}

// SubjectOf (quotas.ts subjectOf): The subject of a principal: its API key (for an API-key session), the agent of a
// delegated session, the identity.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SubjectOf(principal *Principal) (result *core.Object, err error) {
	err = notImplemented("quotas.ts subjectOf")
	return
}

// TimeZone (quotas.ts timeZone): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TimeZone(value any) (result string, err error) {
	err = notImplemented("quotas.ts timeZone")
	return
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
