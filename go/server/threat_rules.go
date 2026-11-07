package server

// Skeleton of packages/server/src/threat-rules.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// BaselineIdentityIDs (threat-rules.ts baselineIdentityIds): Identities whose stored baselines the rules read for
// these events: people who signed in (not through impersonation), whose baselines the sign-in rules compare and
// update, and people who changed their own sign-in methods, for whom account-takeover-persistence reads the risky
// sign-in an earlier run marked. The engine preloads these into `RuleInput.baselines`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BaselineIdentityIDs(events []*core.Object) (result []string, err error) {
	err = notImplemented("threat-rules.ts baselineIdentityIds")
	return
}

// Considered (threat-rules.ts considered): Events the rules read: well formed, and not the threats module's own. The
// engine filters with it too, so a stored event with a missing or mistyped field (one an intruder edited, say) is
// reported by the chain check and otherwise skipped, never stopping detection for its tenant.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Considered(event *core.Object) (result bool, err error) {
	err = notImplemented("threat-rules.ts considered")
	return
}

// EvaluateThreatRules (threat-rules.ts evaluateThreatRules): Evaluates every enabled rule over one run's events.
// Returns the detections to record, oldest first, and the identities whose baselines changed (created, or updated by
// a sign-in); the engine persists those.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EvaluateThreatRules(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("threat-rules.ts evaluateThreatRules")
	return
}

// IdentityLabel (threat-rules.ts identityLabel): How detections name an identity (subject names and summaries): name
// and email where it has both; its id when it is unknown. Detections the threats API records itself use it too.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IdentityLabel(identity *core.Object, identityID string) (result string, err error) {
	err = notImplemented("threat-rules.ts identityLabel")
	return
}

// RuleWindowMs (threat-rules.ts ruleWindowMs): How far before a run's earliest event the engine loads history: the
// longest reach of an enabled rule, at least one day. A counting rule reaches back one window plus the UTC day its
// burst anchor may lie in (`burstAnchor`), so an ongoing burst keeps its dedupe key from run to run;
// brute-force-success reaches back its window. With the default settings this is one day and fifteen minutes.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RuleWindowMs(settings *core.Object) (result float64, err error) {
	err = notImplemented("threat-rules.ts ruleWindowMs")
	return
}
