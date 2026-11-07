package server

// Skeleton of packages/server/src/policy-lint.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"github.com/Better-IAM/better-iam/go/core"
)

// LintPolicy (policy-lint.ts lintPolicy): Lints a policy document: validates it as storage would, then reports
// statements that grant more than intended, conditions that can never match or silently fail open, and statements
// that are shadowed or duplicated. The context tells the linter which identity attributes, resource attributes, and
// application keys exist. Pattern comparisons are budgeted: past the budget, a `shadowed-allow-skipped` note
// replaces the rest of the shadow check.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LintPolicy(document any, context *core.Object) (result *core.Object, err error) {
	err = notImplemented("policy-lint.ts lintPolicy")
	return
}
