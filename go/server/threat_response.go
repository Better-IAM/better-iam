package server

// Skeleton of packages/server/src/threat-response.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AfterThreatResponses (threat-response.ts afterThreatResponses): Post-commit follow-up of responses: reconciles
// access-package rules for identities contained or released (`afterIdentityChange`, which never throws) and clears
// this process's network block cache again after a block, so a read racing the transaction cannot keep the
// pre-change list for a few seconds.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AfterThreatResponses(ctx context.Context, server *ServerContext, tenantID string, responses []*core.Object) (err error) {
	err = notImplemented("threat-response.ts afterThreatResponses")
	return
}

// ApplyResponse (threat-response.ts applyResponse): Takes one response action and records it: inserts the
// `ThreatResponse` row (applied or skipped with a reason) and, when applied, the audit event
// (`threat:revoke-sessions`, `threat:forget-devices`, `threat:contain`, `threat:suspend-clearance` after
// `clearance:suspend`, `threat:block-network`, `threat:notify`). Automatic actors skip protected targets (owners and
// root administrators are never contained, nor their clearances suspended, automatically) and, with a `brake`,
// containments beyond the tenant's `maxAutomaticContainments` (skipped `braked`, audited once per brake as
// `threat:response-braked`), and never block networks on the root tenant. People are refused instead: a root
// administrator only by root, an owner only by an owner in person or root, the last owner (`LAST_OWNER`),
// themselves, networks that cover their own address, blocks on the root tenant unless they are root, and a clearance
// suspension without `iam:clearances:suspend` (as `clearances.suspend` refuses it). Runs inside the caller's
// transaction; after it commits the caller runs `afterThreatResponses` (package reconciliation of contained
// identities, network block caches).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ApplyResponse(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, request *core.Object, settings *core.Object, brake *core.Object) (result *core.Object, err error) {
	err = notImplemented("threat-response.ts applyResponse")
	return
}

// ReleaseIdentity (threat-response.ts releaseIdentity): Lifts a containment: the identity is active again and its
// risk record no longer marks it contained (the risk score is kept). Only an identity the threats module contained
// and that nothing else has disabled, suspended, or re-enabled since can be released (`INVALID_TRANSITION` 409
// otherwise, or when it has expired since); a root administrator only by root. Audited as `threat:release` and kept
// as a `release` response. After commit the caller runs `afterThreatResponses`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleaseIdentity(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, identityID string, actor *core.Object, note string) (result *core.Object, err error) {
	err = notImplemented("threat-response.ts releaseIdentity")
	return
}

// ThreatAudit (threat-response.ts threatAudit): Records an audit event of the threats module: under the responding
// person (with their session context) or under the `threat-detection` actor, stamped with the service clock. Always
// `allow`, so SSF receivers and webhooks see it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ThreatAudit(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, actor *core.Object, action string, resourceID string, metadata *core.Object) (err error) {
	err = notImplemented("threat-response.ts threatAudit")
	return
}
