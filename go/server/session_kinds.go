package server

// Port of packages/server/src/session-kinds.ts: session kinds and the rules shared by every code path that branches
// on them. Long-lived credentials (`user`, `api-key`) act in their identity's own right; temporary ones (`role`,
// `session-token`, `delegated`) derive from a source and never pass recent-authentication, ownership or self-service
// checks. Unknown kinds fail closed everywhere.

import (
	"math"

	"github.com/Better-IAM/better-iam/go/core"
)

// TemporarySessionKinds are derived from a source credential, bounded by it, and never usable for self-service.
var TemporarySessionKinds = newOrderedSet("role", "session-token", "delegated")

// ActsInOwnRight reports whether a session acts in its identity's own right (a user session or an API key).
func ActsInOwnRight(session *core.Object) bool {
	kind := session.Get("kind")
	return kind == "user" || kind == "api-key"
}

// RevokedByWatermark reports whether a session issued at createdAt falls under any revocation watermark
// (`sessionsRevokedBefore` of its role, trust or provider): true when it was created strictly before a numeric,
// finite watermark. Missing (non-number) watermarks are ignored.
func RevokedByWatermark(createdAt float64, watermarks ...any) bool {
	for _, watermark := range watermarks {
		value, ok := watermark.(float64)
		if ok && !math.IsInf(value, 0) && !math.IsNaN(value) && createdAt < value {
			return true
		}
	}
	return false
}

// NextWatermark is the next `sessionsRevokedBefore` for a record: max(current ?? 0, before ?? now + 1), so a
// watermark only ever moves forward and never lies in the future. current and before are model values (undefined
// when absent). Fails with INVALID_INPUT when before is not a safe integer >= 0 or is > now + 1.
func NextWatermark(current any, before any, now float64) (float64, error) {
	before = core.Normalize(before)
	if !isUndefined(before) {
		value, ok := before.(float64)
		if !ok || !core.IsSafeInteger(value) || value < 0 || value > now+1 {
			return 0, invalidInput("before must be a time no later than now")
		}
	}
	next := jsNumber(coalesce(core.Normalize(current), 0.0))
	candidate := now + 1
	if !isUndefined(before) {
		candidate = before.(float64)
	}
	return math.Max(next, candidate), nil
}
