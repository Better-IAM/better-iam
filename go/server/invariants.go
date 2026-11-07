package server

// Skeleton of packages/server/src/invariants.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
)

// CheckInvariants (invariants.ts checkInvariants): The scheduled invariant check: evaluates every invariant of every
// active tenant (or one `tenantId`), remembers the outcome on the invariant, and records `invariant:broken` when an
// invariant starts failing or gains violators and `invariant:restored` when it passes again, so monitored invariants
// reach webhooks and audit exports. A deployment operation: no credential, one transaction per tenant.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CheckInvariants(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("invariants.ts checkInvariants")
	return
}

// EvaluateInvariants (invariants.ts evaluateInvariants): Evaluates invariants against the current state of the
// transaction.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EvaluateInvariants(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, invariants []*core.Object, options *core.Object) (result []*core.Object, err error) {
	err = notImplemented("invariants.ts evaluateInvariants")
	return
}

// InvariantSnapshotState is what InvariantSnapshot keeps: the enforced invariants, the violations that already
// existed, and the invariants that could not be evaluated.
type InvariantSnapshotState struct {
	Invariants  []*core.Object
	Existing    map[string]bool
	Unevaluable map[string]bool
}

// invariantChangingActions are the operations that can change who may do what (invariants.ts accessChangingActions).
var invariantChangingActions = func() *orderedSet {
	set := newOrderedSet()
	for _, action := range []string{
		"roles:update", "roles:delete", "policies:update", "policies:delete", "bindings:create", "bindings:delete",
		"bindings:activate", "bindings:approve", "groups:update", "groups:delete", "identities:create",
		"identities:update", "packages:update", "packages:assign", "packages:approve", "config:apply",
		"access-requests:review", "relationships:create", "relationships:delete", "resources:update",
		"boundaries:update", "authorities:revoke", "resources:delete", "root:grant", "certifications:manage",
		"agreements:manage", "onboarding:manage", "analysis:update", "roles:assume", "trust:create", "trust:update",
		"session-tokens:create", "oidc-providers:create", "oidc-providers:update", "teams:create", "teams:update",
		"teams:delete", "departments:manage", "packages:create", "features:manage", "features:override",
		"billing:manage", "licenses:assign", "licenses:manage", "guests:manage", "guests:settings",
		"clearances:adjudicate", "classifications:manage", "classifications:declassify",
	} {
		set.Add("iam:" + action)
	}
	return set
}()

// narrowingOnly marks the running operation's transaction as one that only narrows access (invariants.ts
// narrowingOnly, a WeakSet of transactions).
var narrowingOnly sync.Map

// NarrowsAccessOnly (invariants.ts narrowsAccessOnly): marks the running operation (inside Operation) as one that
// only narrows access; the mark lives for one operation.
func NarrowsAccessOnly(tx core.IamStore) {
	narrowingOnly.Store(tx, true)
}

// violationKeys are `{invariantId}:{identityId}` of every violation of the results.
func violationKeys(results []*core.Object) map[string]bool {
	keys := map[string]bool{}
	for _, result := range results {
		invariantID := jsString(member(result.Get("invariant"), "id"))
		violations, _ := result.Get("violations").([]any)
		for _, violation := range violations {
			keys[invariantID+":"+jsString(member(member(violation, "identity"), "id"))] = true
		}
	}
	return keys
}

// InvariantSnapshot (invariants.ts invariantSnapshot): before an access-changing operation, the enforced invariants
// and the violations that already exist (nil when there is nothing to enforce).
func InvariantSnapshot(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, action string) (*InvariantSnapshotState, error) {
	narrowingOnly.Delete(tx)
	if !invariantChangingActions.Has(action) {
		return nil, nil
	}
	all, err := tx.Find(ctx, "accessInvariants", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	var invariants []*core.Object
	for _, invariant := range all {
		if invariant.Get("mode") == "enforce" {
			invariants = append(invariants, invariant)
		}
	}
	if len(invariants) == 0 {
		return nil, nil
	}
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	results, err := EvaluateInvariants(ctx, server, tx, tenant, invariants, core.NewObject("unlimited", true))
	if err != nil {
		return nil, err
	}
	unevaluable := map[string]bool{}
	for _, result := range results {
		if truthy(result.Get("error")) {
			unevaluable[jsString(member(result.Get("invariant"), "id"))] = true
		}
	}
	return &InvariantSnapshotState{Invariants: invariants, Existing: violationKeys(results), Unevaluable: unevaluable}, nil
}

// InvariantVerify (invariants.ts invariantVerify): after the operation, refuses (rolling the transaction back) when it
// newly broke an enforced invariant.
func InvariantVerify(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, snapshot *InvariantSnapshotState) error {
	_, narrowing := narrowingOnly.LoadAndDelete(tx)
	if snapshot == nil {
		return nil
	}
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	results, err := EvaluateInvariants(ctx, server, tx, tenant, snapshot.Invariants, core.NewObject("unlimited", true))
	if err != nil {
		return err
	}
	for _, result := range results {
		invariant, _ := result.Get("invariant").(*core.Object)
		// Taking access away for cause is never blocked by an invariant that expects it to remain.
		if narrowing && member(invariant, "expect") == "allow" {
			continue
		}
		id := jsString(member(invariant, "id"))
		// Deleting an invariant's group or resource would otherwise switch enforcement off silently.
		if failure := result.Get("error"); truthy(failure) && !snapshot.Unevaluable[id] {
			return core.NewIamError("INVARIANT_VIOLATION", "Access invariant \""+jsString(member(invariant, "name"))+"\" could no longer be evaluated ("+jsString(member(failure, "message"))+"); change or delete the invariant first", 409)
		}
		violations, _ := result.Get("violations").([]any)
		for _, violation := range violations {
			identity := member(violation, "identity")
			if snapshot.Existing[id+":"+jsString(member(identity, "id"))] {
				continue
			}
			verb := "no longer be allowed"
			if member(invariant, "expect") == "deny" {
				verb = "be allowed"
			}
			resource := member(invariant, "resource")
			return core.NewIamError("INVARIANT_VIOLATION", "Access invariant \""+jsString(member(invariant, "name"))+"\": "+jsString(member(identity, "name"))+" would "+verb+" "+jsString(member(invariant, "action"))+" on "+jsString(member(resource, "type"))+"/"+jsString(member(resource, "id")), 409)
		}
	}
	return nil
}
