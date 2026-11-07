package server

// Skeleton of packages/server/src/threats.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// EffectiveRisk (threats.ts effectiveRisk): The score and level in force at `now`: decayed contributions, raised to
// an unexpired override's level.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EffectiveRisk(record *core.Object, now int64, halfLifeHours float64) (result *core.Object, err error) {
	err = notImplemented("threats.ts effectiveRisk")
	return
}

// EndContainment (threats.ts endContainment): Ends the threats module's hold on an identity whose status another
// path changed (identities.setStatus and offboard, service accounts, agents.suspend and resume, lifecycle
// workflows): the containment mark goes, so `threats.release` never re-activates what that path disabled, and a
// later disable is not taken for a containment. The risk score stays. Nothing happens for an identity that is not
// contained.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EndContainment(ctx context.Context, tx core.IamStore, identityID string, now int64) (err error) {
	err = notImplemented("threats.ts endContainment")
	return
}

// MaxSeverity (threats.ts maxSeverity): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MaxSeverity(a string, b string) (result string, err error) {
	err = notImplemented("threats.ts maxSeverity")
	return
}

// MentionsRisk (threats.ts mentionsRisk): true when any statement of the documents refers to principal.riskLevel /
// principal.riskScore (conditions or variables).
func MentionsRisk(documents []any) bool {
	return anyStatementsMention(documents, "principal.risk")
}

// ResolveThreatSettings (threats.ts resolveThreatSettings): Applies rule defaults and deployment defaults to a
// tenant's stored settings (absent when never configured).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ResolveThreatSettings(stored *core.Object) (result *core.Object, err error) {
	err = notImplemented("threats.ts resolveThreatSettings")
	return
}

// RiskContext (threats.ts riskContext): The risk keys for a decision. Simulated principals (invariants, impact
// previews, policy simulation, birthright automation) always get `none`/0 so an incident never flips an invariant or
// stalls automation; a delegated session takes the higher of the person's and the agent's risk.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RiskContext(ctx context.Context, tx core.IamStore, principal *Principal, now int64) (result *core.Object, err error) {
	err = notImplemented("threats.ts riskContext")
	return
}

// RiskLevelAtLeast (threats.ts riskLevelAtLeast): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RiskLevelAtLeast(level string, floor string) (result bool, err error) {
	err = notImplemented("threats.ts riskLevelAtLeast")
	return
}

// RiskScore (threats.ts riskScore): Decayed score of the contributions at `now` (0-100).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RiskScore(contributions []*core.Object, now int64, halfLifeHours float64) (result float64, err error) {
	err = notImplemented("threats.ts riskScore")
	return
}

// SeverityAtLeast (threats.ts severityAtLeast): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SeverityAtLeast(severity string, floor string) (result bool, err error) {
	err = notImplemented("threats.ts severityAtLeast")
	return
}

// ThreatRule (threats.ts threatRule): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ThreatRule(id string) (result *core.Object, err error) {
	err = notImplemented("threats.ts threatRule")
	return
}

// DefaultThreatSettings is threats.ts defaultThreatSettings.
var DefaultThreatSettings = struct {
	DormantDays              float64
	RiskHalfLifeHours        float64
	MaxAutomaticContainments float64
}{90, 24, 3}

// ResponseActionKinds is threats.ts responseActionKinds.
var ResponseActionKinds = []string{"revoke-sessions", "forget-devices", "contain", "suspend-clearance", "block-network", "notify"}

// RiskLevels is threats.ts riskLevels.
var RiskLevels = []string{"none", "low", "medium", "high"}

// RiskPoints is threats.ts riskPoints.
var RiskPoints = struct {
	Low      float64
	Medium   float64
	High     float64
	Critical float64
}{10, 25, 50, 80}

// ThreatActor is threats.ts threatActor.
const ThreatActor = "threat-detection"

// ThreatCollections is threats.ts threatCollections.
var ThreatCollections = struct {
	Detections string
	Incidents  string
	Notes      string
	Risk       string
	Baselines  string
	Cursors    string
	Settings   string
	Playbooks  string
	Responses  string
}{"threatDetections", "threatIncidents", "threatNotes", "identityRisk", "threatBaselines", "threatCursors", "threatSettings", "threatPlaybooks", "threatResponses"}

// ThreatRuleIDs is threats.ts threatRuleIds.
var ThreatRuleIDs = newOrderedSet("password-spray", "brute-force", "brute-force-success", "mfa-bombardment", "session-hijack", "new-network", "dormant-reactivated", "account-takeover-persistence", "privilege-escalation", "root-admin-granted", "mass-deletion", "directory-mass-change", "impersonation-burst", "denial-burst", "classified-access-attempts", "recon-burst", "guardrail-weakened", "token-replay", "audit-tampering", "invariant-broken", "user-reported", "upstream-signal")

// ThreatRules is threats.ts threatRules.
var ThreatRules any // STUB: threats.ts threatRules has no literal form; port it with the module

// ThreatSeverities is threats.ts threatSeverities.
var ThreatSeverities = []string{"low", "medium", "high", "critical"}
