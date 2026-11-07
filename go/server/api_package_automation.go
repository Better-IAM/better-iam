package server

// Skeleton of packages/server/src/api/package-automation.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AfterIdentityChange (api/package-automation.ts afterIdentityChange): Reconciles the license seats and package
// rules for identities an administrator just changed; never throws (the schedules catch up).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AfterIdentityChange(ctx context.Context, server *ServerContext, tenantID string, identityIDs []string, result2 any) (result any, err error) {
	err = notImplemented("api/package-automation.ts afterIdentityChange")
	return
}

// ApproveRule (api/package-automation.ts approveRule): Writes the rule's approval: the grants and removals a run
// would make now, which unattended runs may then apply for the next day without tripping the brakes. Called when a
// person saves a rule or confirms held-back changes.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ApproveRule(ctx context.Context, server *ServerContext, tx core.IamStore, pkg *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/package-automation.ts approveRule")
	return
}

// AutoAssignView (api/package-automation.ts autoAssignView): A rule as administrators see it: owner, whether it
// runs, warnings, and the latest problems.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AutoAssignView(ctx context.Context, server *ServerContext, reader core.IamStore, pkg *core.Object, env *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/package-automation.ts autoAssignView")
	return
}

// PreviewRule (api/package-automation.ts previewRule): What a rule matches (stored, candidate, or neither: keys
// only) and, for a package, what a run would change. Read-only; requires iam:identities:read (checked here) to
// evaluate a rule over the directory.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PreviewRule(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/package-automation.ts previewRule")
	return
}

// ReconcilePackageRules (api/package-automation.ts reconcilePackageRules): The reconciler. Plans from plain reads
// (no transaction), then applies each change in its own transaction under the rule owner's authority, removals
// first. Never runs inside another transaction.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReconcilePackageRules(ctx context.Context, server *ServerContext, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("api/package-automation.ts reconcilePackageRules")
	return
}
