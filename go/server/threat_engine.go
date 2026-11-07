package server

// Skeleton of packages/server/src/threat-engine.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// DetectThreats (threat-engine.ts detectThreats): Runs detection for every active tenant (or only `tenantId`,
// NOT_FOUND when it does not exist): reads up to `maxEvents` (default 2000, at most 20000) unread audit events per
// tenant (fewer when they hold the sign-ins of more than 500 people, whose baselines the run writes; the rest stays
// pending), verifies their hash chain (a break raises `audit-tampering` and detection continues), evaluates the
// rules, records detections and incidents, updates risk and sign-in baselines, advances the tenant's cursor, and
// runs matching playbooks for new detections (automatic containments braked at `maxAutomaticContainments` per tenant
// and run). A tenant whose evaluation fails, or whose detection settings changed while it was evaluated, records
// nothing and keeps its cursor, so the next run reads the same events again; the other tenants are unaffected. A
// deployment operation for schedulers: no credential. The first run of a tenant starts one day back.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DetectThreats(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("threat-engine.ts detectThreats")
	return
}

// RecomputeRisk (threat-engine.ts recomputeRisk): Recomputes an identity's risk record (`identityRisk`, id =
// identity id) in this tenant: adds `options.add`, drops `options.drop` and, when nothing is added, every
// contribution whose detection was dismissed or resolved as a false positive or benign; prunes contributions older
// than ten half-lives (ten days at least), keeps the newest 50, drops a lapsed override, and stores the effective
// score and level. A level change is audited as `threat:risk-change` (`{from, to, score}`, by `actorId` or the
// `threat-detection` actor). Undefined for identities outside the tenant or deleted, and when there is no record and
// nothing to add.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RecomputeRisk(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, identityID string, settings *core.Object, now int64, actorID string, options *core.Object) (result *core.Object, err error) {
	err = notImplemented("threat-engine.ts recomputeRisk")
	return
}

// RecordDetection (threat-engine.ts recordDetection): Records a candidate once: its `uniqueKey` is
// `{ruleId}:{dedupeKey}`, so a candidate raised again (the same burst or triggering event) returns the existing
// detection with `created: false`. A new detection is `open`, joins its subject's open incident or opens one, is
// audited as `threat:detection` (and `threat:incident-open`) under the `threat-detection` actor, and adds
// `riskPoints[severity]` to its identity's risk (`recomputeRisk`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RecordDetection(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, candidate *core.Object, settings *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("threat-engine.ts recordDetection")
	return
}

// RunPlaybooks (threat-engine.ts runPlaybooks): Runs the tenant's enabled playbooks whose trigger matches a new
// detection, oldest playbook first, each action in order through `applyResponse` under the automatic actor, and
// counts the run on the playbook (`runs`, `lastRunAt`). Containments share `brake` (one per tenant and run). Returns
// every response recorded, applied or skipped; after the transaction commits the caller runs `afterThreatResponses`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RunPlaybooks(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, detection *core.Object, incident *core.Object, settings *core.Object, brake *core.Object) (result []*core.Object, err error) {
	err = notImplemented("threat-engine.ts runPlaybooks")
	return
}
