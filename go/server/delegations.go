package server

// Skeleton of packages/server/src/delegations.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// ActionsMayOverlap (delegations.ts actionsMayOverlap): Whether some action could match both action patterns
// (conservative: true unless their literal ends disagree).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ActionsMayOverlap(pattern string, scope string) (result bool, err error) {
	err = notImplemented("delegations.ts actionsMayOverlap")
	return
}

// ApprovedConfirmations (delegations.ts approvedConfirmations): The approved, unexpired (and not yet used)
// confirmations of a delegation, as the keys they open.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ApprovedConfirmations(ctx context.Context, tx core.IamStore, delegation *core.Object, now int64) (result map[string]bool, err error) {
	err = notImplemented("delegations.ts approvedConfirmations")
	return
}

// CheckDelegatedSession (delegations.ts checkDelegatedSession): The checks a delegated session passes on every use:
// its delegation is active, unexpired, and names this person and agent in this tenant, and was not revoked after the
// session began; the person is an active person of the tenant; the agent is an agent in good standing (itself and
// its sponsor active) that still accepts delegation; and the agent key the session came from is re-validated under
// its own rules (`revalidate`). Anything else is a 401.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CheckDelegatedSession(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, session *core.Object, revalidate func(context.Context, *Principal) (*Principal, error)) (err error) {
	err = notImplemented("delegations.ts checkDelegatedSession")
	return
}

// ConfirmPatterns (delegations.ts confirmPatterns): Reads a `confirm` list: action patterns (wildcards allowed), at
// most 50; an empty list means none.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ConfirmPatterns(value any) (result []string, err error) {
	err = notImplemented("delegations.ts confirmPatterns")
	return
}

// ConfirmationKey (delegations.ts confirmationKey): the key a confirmation opens: an action on a resource.
func ConfirmationKey(action string, resourceType string, resourceID string) string {
	return action + "|" + resourceType + "/" + resourceID
}

// DelegationAncestors (delegations.ts delegationAncestors): The delegations above a hand-off, nearest first, when
// every one of them is live and names the same person, and its agent is an agent of the tenant that still accepts
// delegation. Undefined when any link is broken (the hand-off may not be used). A delegation the person gave
// directly has no ancestors. `liveAncestors` also checks each agent's standing.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DelegationAncestors(ctx context.Context, tx core.IamStore, delegation *core.Object, now int64) (result []DelegationAncestor, err error) {
	err = notImplemented("delegations.ts delegationAncestors")
	return
}

// DelegationLive (delegations.ts delegationLive): Whether a delegation lets its agent act right now.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DelegationLive(delegation *core.Object, now int64) (result bool, err error) {
	err = notImplemented("delegations.ts delegationLive")
	return
}

// DelegationPending (delegations.ts delegationPending): Whether a request still waits for the person's decision.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DelegationPending(delegation *core.Object, now int64) (result bool, err error) {
	err = notImplemented("delegations.ts delegationPending")
	return
}

// DelegationScope (delegations.ts delegationScope): Reads a delegation scope: `scopes` (an action list, wildcards
// allowed) or a `policy` document, exactly one of them, validated against the tenant's catalog. The scope only ever
// narrows: the delegated session acts with the person's grants, and this becomes one more ceiling over them.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DelegationScope(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("delegations.ts delegationScope")
	return
}

// DelegationSeconds (delegations.ts delegationSeconds): A delegation lifetime in seconds (`expiresInSeconds`),
// within bounds; the fallback is 30 days.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DelegationSeconds(value any) (result float64, err error) {
	err = notImplemented("delegations.ts delegationSeconds")
	return
}

// DeleteDelegatedSessions (delegations.ts deleteDelegatedSessions): Deletes the live delegated sessions of a
// delegation (or of every delegation of an agent); returns the count.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DeleteDelegatedSessions(ctx context.Context, tx core.IamStore, filter *core.Object) (result float64, err error) {
	err = notImplemented("delegations.ts deleteDelegatedSessions")
	return
}

// HandoffSetting (delegations.ts handoffSetting): Reads a `handoff` setting: `{ agents?, depth? }` with agents of
// the tenant (at most 20) and a depth of 1 to 3 (1 by default). `null` means none (for clearing); `undefined` leaves
// the caller's choice alone.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func HandoffSetting(ctx context.Context, tx core.IamStore, tenantID string, value any) (result *core.Object, err error) {
	err = notImplemented("delegations.ts handoffSetting")
	return
}

// LiveAncestors (delegations.ts liveAncestors): `delegationAncestors`, with every agent above also in good standing
// (itself and its sponsor active).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LiveAncestors(ctx context.Context, server *ServerContext, tx core.IamStore, delegation *core.Object, now int64) (result []DelegationAncestor, err error) {
	err = notImplemented("delegations.ts liveAncestors")
	return
}

// PolicyAllowsScope (delegations.ts policyAllowsScope): Whether a policy document allows a whole scope (an action or
// a `*` pattern of actions) outright: some statement allows every action it covers on every resource without
// conditions, and no deny statement could touch any of them. Conservative by design: a document that allows the
// scope only for some resources or under conditions does not count.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PolicyAllowsScope(document *core.Object, scope string) (result bool, err error) {
	err = notImplemented("delegations.ts policyAllowsScope")
	return
}

// RevokeDelegationsOf (delegations.ts revokeDelegationsOf): Ends every delegation that involves an identity (as the
// agent or as the person) and their sessions: used when an identity is deleted. Records stay as `revoked` for the
// audit trail. Returns the number of delegations ended.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RevokeDelegationsOf(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, revokedBy string) (result float64, err error) {
	err = notImplemented("delegations.ts revokeDelegationsOf")
	return
}

// RevokeHandoffsBelow (delegations.ts revokeHandoffsBelow): Revokes every live hand-off below a delegation (at any
// depth) and deletes their sessions, recording `revokedBy`. Returns how many were revoked. Their use is refused
// anyway once a delegation above them ends; this keeps their records honest.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RevokeHandoffsBelow(ctx context.Context, tx core.IamStore, delegation *core.Object, revokedBy string, now int64) (result float64, err error) {
	err = notImplemented("delegations.ts revokeHandoffsBelow")
	return
}

// SpendSetting (delegations.ts spendSetting): Reads a `spend` setting: `{ period, maxTokens?, maxCostUsd?,
// maxRequests? }` with at least one limit. `null` means none (for clearing); `undefined` leaves the caller's choice
// alone.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SpendSetting(value any) (result *core.Object, err error) {
	err = notImplemented("delegations.ts spendSetting")
	return
}

// ConfirmationLimits is delegations.ts confirmationLimits.
var ConfirmationLimits = struct {
	DecideMs             float64
	MinValidSeconds      float64
	MaxValidSeconds      float64
	FallbackValidSeconds float64
}{1800000, 30, 3600, 300}

// DelegationLifetime is delegations.ts delegationLifetime.
var DelegationLifetime = struct {
	MinSeconds      float64
	MaxSeconds      float64
	FallbackSeconds float64
	RequestMs       float64
}{300, 31536000, 2592000, 604800000}

// HandoffLimits is delegations.ts handoffLimits.
var HandoffLimits = struct {
	MaxDepth  float64
	MaxLive   float64
	MaxAgents float64
}{3, 20, 20}

// MaxSessionsPerDelegation is delegations.ts maxSessionsPerDelegation.
const MaxSessionsPerDelegation = 20

// DelegationAncestor is one delegation above a hand-off and its agent (nil slice from DelegationAncestors: a link is
// broken).
type DelegationAncestor struct {
	Delegation *core.Object
	Agent      *core.Object
}

// UseConfirmation uses up the person's approval behind an allowed call of a delegated session (useConfirmation).
// Other sessions are left alone, exactly as in TypeScript.
//
// STUB: consuming an approval (the delegationConfirmations bookkeeping, with its per-transaction memory) is ported
// with delegations.ts. Until then a delegated call whose delegation holds the action back is refused with
// NOT_IMPLEMENTED (fail closed) instead of being allowed without consuming its confirmation; every other call
// behaves exactly as in TypeScript.
var UseConfirmation = func(ctx context.Context, tx core.IamStore, principal *Principal, action, resourceType, resourceID string, now int64) error {
	if principal.Session.Get("kind") != "delegated" {
		return nil
	}
	delegationID, ok := principal.Session.String("delegationId")
	if !ok {
		return nil
	}
	delegation, err := tx.Get(ctx, "delegations", delegationID)
	if err != nil || delegation == nil || !NeedsConfirmation(delegation, action) {
		return err
	}
	return notImplemented("Delegation confirmations (delegations.ts useConfirmation)")
}

// NeedsConfirmation reports whether a delegation requires the person's confirmation for an action
// (delegations.ts needsConfirmation).
func NeedsConfirmation(delegation *core.Object, action string) bool {
	patterns, _ := delegation.Get("confirm").([]any)
	for _, pattern := range patterns {
		if text, ok := pattern.(string); ok && core.MatchPattern(text, action, nil) {
			return true
		}
	}
	return false
}
