package server

// Port of packages/server/src/threats.ts: identity threat detection and response (ITDR). Detection rules read the
// audit trail each tenant already keeps (sign-ins, failures, session mismatches, administrative changes, directory
// pushes), raise detections, group them into incidents per subject, keep a decaying risk score per identity (exposed
// to policies as principal.riskLevel / principal.riskScore), and run response playbooks. The engine
// (threat_engine.go) is a scheduled job, `iam.detectThreats()`, that reads each tenant's audit chain from a cursor, so
// it also sees events the protocol packages write without fan-out, verifies the chain as it goes, and never slows a
// sign-in.

import (
	"context"
	"errors"
	"math"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	threatsMinute = 60_000.0
	threatsHour   = 60 * threatsMinute
	threatsDay    = 24 * threatsHour
)

// threatsRuleDefinition builds one catalog entry (ThreatRuleDefinition) with the TypeScript member order: id, title,
// description, category, severity, subject, threshold?, windowMs?, tunable?, enabledByDefault, technique.
func threatsRuleDefinition(id, title, description, category, severity, subject string, threshold, windowMs any, tunable *core.Object, enabledByDefault bool, technique string) *core.Object {
	rule := core.NewObject("id", id, "title", title, "description", description, "category", category,
		"severity", severity, "subject", subject)
	if threshold != nil {
		rule.Set("threshold", threshold)
	}
	if windowMs != nil {
		rule.Set("windowMs", windowMs)
	}
	if tunable != nil {
		rule.Set("tunable", tunable)
	}
	rule.Set("enabledByDefault", enabledByDefault)
	rule.Set("technique", technique)
	return rule
}

// threatsTunable is a rule's `tunable` bounds; a nil pair is left out.
func threatsTunable(threshold, windowMs []any) *core.Object {
	out := core.NewObject()
	if threshold != nil {
		out.Set("threshold", threshold)
	}
	if windowMs != nil {
		out.Set("windowMs", windowMs)
	}
	return out
}

func threatsBounds(min, max float64) []any { return []any{min, max} }

// ThreatRules is threats.ts threatRules: the rule catalog, in display order (ThreatRuleDefinition records).
var ThreatRules = []*core.Object{
	threatsRuleDefinition("password-spray", "Password spray",
		"One network fails password sign-ins for many different people in a short window: someone is trying common passwords across accounts.",
		"sign-in", "high", "network", 10.0, 15*threatsMinute,
		threatsTunable(threatsBounds(3, 1000), threatsBounds(threatsMinute, threatsDay)), true, "T1110.003"),
	threatsRuleDefinition("brute-force", "Password guessing",
		"Many failed password sign-ins for one person in a short window.",
		"sign-in", "medium", "identity", 10.0, 15*threatsMinute,
		threatsTunable(threatsBounds(3, 1000), threatsBounds(threatsMinute, threatsDay)), true, "T1110.001"),
	threatsRuleDefinition("brute-force-success", "Sign-in after repeated failures",
		"A person signed in right after a run of failed attempts; high when the success came from a network that was failing.",
		"sign-in", "high", "identity", 5.0, 30*threatsMinute,
		threatsTunable(threatsBounds(2, 1000), threatsBounds(threatsMinute, threatsDay)), true, "T1110"),
	threatsRuleDefinition("mfa-bombardment", "Second-factor guessing",
		"Repeated wrong second-factor codes for one person: the password was right, so someone else probably knows it.",
		"sign-in", "high", "identity", 5.0, 15*threatsMinute,
		threatsTunable(threatsBounds(2, 1000), threatsBounds(threatsMinute, threatsDay)), true, "T1621"),
	threatsRuleDefinition("session-hijack", "Session used from another network",
		"A session bound to one network was presented from another (tenant policy bindSessionsToIp): a stolen cookie or token.",
		"sign-in", "high", "identity", nil, nil, nil, true, "T1550.004"),
	threatsRuleDefinition("new-network", "Sign-in from a new network",
		"A privileged person (owner, root administrator, or holder of an administrator role) signed in from a network not seen for them before.",
		"sign-in", "medium", "identity", nil, nil, nil, true, "T1078"),
	threatsRuleDefinition("dormant-reactivated", "Dormant account signed in",
		"Someone signed in to an account that had not been used for longer than the dormancy period.",
		"account", "medium", "identity", nil, nil, nil, true, "T1078"),
	threatsRuleDefinition("account-takeover-persistence", "Account changes after a risky sign-in",
		"Shortly after a risky sign-in the account changed its sign-in methods (second factor removed, passkey or trusted device added, email or password changed, API key created).",
		"account", "high", "identity", nil, threatsHour,
		threatsTunable(nil, threatsBounds(5*threatsMinute, 7*threatsDay)), true, "T1098"),
	threatsRuleDefinition("privilege-escalation", "Self-granted administrator role",
		"Someone granted an administrator role and now holds it themselves.",
		"privilege", "high", "identity", nil, nil, nil, true, "T1098.003"),
	threatsRuleDefinition("root-admin-granted", "Root administrator granted",
		"A person was made a root administrator of the deployment.",
		"privilege", "high", "identity", nil, nil, nil, true, "T1098"),
	threatsRuleDefinition("mass-deletion", "Mass deletion",
		"One actor deleted or revoked many identities, roles, policies, groups, bindings, keys, or trusts in a short window.",
		"activity", "high", "identity", 20.0, 10*threatsMinute,
		threatsTunable(threatsBounds(3, 10_000), threatsBounds(threatsMinute, threatsDay)), true, "T1531"),
	threatsRuleDefinition("directory-mass-change", "Directory mass change",
		"A SCIM connection updated or deleted many people in a short window.",
		"activity", "medium", "connection", 25.0, 10*threatsMinute,
		threatsTunable(threatsBounds(3, 100_000), threatsBounds(threatsMinute, threatsDay)), true, "T1531"),
	threatsRuleDefinition("impersonation-burst", "Repeated impersonation",
		`One administrator started many "view as" sessions in a day.`,
		"activity", "medium", "identity", 5.0, threatsDay,
		threatsTunable(threatsBounds(2, 1000), threatsBounds(threatsHour, 7*threatsDay)), true, "T1078"),
	threatsRuleDefinition("denial-burst", "Burst of denied requests",
		"One actor was denied many times in a few minutes: probing for access it does not have (agents included).",
		"activity", "medium", "identity", 30.0, 10*threatsMinute,
		threatsTunable(threatsBounds(5, 100_000), threatsBounds(threatsMinute, threatsDay)), true, "T1069"),
	threatsRuleDefinition("classified-access-attempts", "Repeated classified access attempts",
		"One actor was refused classified resources for want of a clearance several times within an hour (security clearances): reading up, or probing for what is classified.",
		"activity", "high", "identity", 3.0, threatsHour,
		threatsTunable(threatsBounds(1, 1000), threatsBounds(threatsMinute, 7*threatsDay)), true, "T1213"),
	threatsRuleDefinition("recon-burst", "Directory enumeration",
		"One actor read identities, bindings, credentials, or the audit trail far more than usual in a short window, or exported many people.",
		"activity", "low", "identity", 300.0, 10*threatsMinute,
		threatsTunable(threatsBounds(20, 1_000_000), threatsBounds(threatsMinute, threatsDay)), true, "T1087"),
	threatsRuleDefinition("guardrail-weakened", "Security settings weakened",
		"The tenant sign-in policy dropped a protection (MFA requirement, IP allowlist, session binding), a network block was lifted, or threat detection was turned off or weakened (a rule, the risk half-life, trusted networks, the containment brake).",
		"integrity", "medium", "tenant", nil, nil, nil, true, "T1562"),
	threatsRuleDefinition("token-replay", "Token replay",
		"A web identity token was presented a second time to assume a role.",
		"sign-in", "high", "identity", nil, nil, nil, true, "T1550"),
	threatsRuleDefinition("audit-tampering", "Audit trail tampering",
		"The tenant audit hash chain no longer verifies: an event was changed, removed, or inserted outside the recorder.",
		"integrity", "critical", "tenant", nil, nil, nil, true, "T1070"),
	threatsRuleDefinition("invariant-broken", "Access invariant broken",
		"A monitored access invariant stopped holding (invariant:broken).",
		"integrity", "medium", "tenant", nil, nil, nil, true, "T1098"),
	threatsRuleDefinition("user-reported", "Reported by the account holder",
		"The person said a sign-in or change on their account was not them (threats.reportSuspicious).",
		"account", "high", "identity", nil, nil, nil, true, "T1078"),
	threatsRuleDefinition("upstream-signal", "Reported by an upstream identity provider",
		"An upstream identity provider reported a compromised credential, a disabled or purged account, a required credential change, or medium or high risk for a person (Shared Signals). The severity follows the event: high for credential compromise and high risk, medium for disabled accounts and medium risk, low for credential changes.",
		"account", "high", "identity", nil, nil, nil, true, "T1078"),
}

// ThreatRule (threats.ts threatRule): the catalog entry of a rule; an unknown id is a programming error (a plain
// Error in TypeScript).
func ThreatRule(id string) (result *core.Object, err error) {
	for _, candidate := range ThreatRules {
		if candidate.Get("id") == id {
			return candidate, nil
		}
	}
	return nil, errors.New("Unknown threat rule " + id)
}

// DefaultThreatSettings is threats.ts defaultThreatSettings.
var DefaultThreatSettings = struct {
	DormantDays              float64
	RiskHalfLifeHours        float64
	MaxAutomaticContainments float64
}{90, 24, 3}

// ResolveThreatSettings (threats.ts resolveThreatSettings): Applies rule defaults and deployment defaults to a
// tenant's stored settings (absent when never configured). The result is ResolvedThreatSettings: {rules,
// trustedNetworks, dormantDays, riskHalfLifeHours, notify, maxAutomaticContainments}, `rules` keyed by rule id.
func ResolveThreatSettings(stored *core.Object) (result *core.Object, err error) {
	rules := core.NewObject()
	var storedRules any = core.Undefined
	if stored != nil {
		storedRules = stored.Get("rules")
	}
	for _, rule := range ThreatRules {
		ruleID := jsString(rule.Get("id"))
		own, _ := coalesce(member(storedRules, ruleID), core.NewObject()).(*core.Object)
		if own == nil {
			own = core.NewObject()
		}
		resolved := own.Spread()
		resolved.Set("enabled", coalesce(own.Get("enabled"), rule.Get("enabledByDefault")))
		resolved.Set("severity", coalesce(own.Get("severity"), rule.Get("severity")))
		if threshold := rule.Get("threshold"); !isUndefined(threshold) {
			resolved.Set("threshold", coalesce(own.Get("threshold"), threshold))
		}
		if windowMs := rule.Get("windowMs"); !isUndefined(windowMs) {
			resolved.Set("windowMs", coalesce(own.Get("windowMs"), windowMs))
		}
		rules.Set(ruleID, resolved)
	}
	storedMember := func(key string) any {
		if stored == nil {
			return core.Undefined
		}
		return stored.Get(key)
	}
	return core.NewObject(
		"rules", rules,
		"trustedNetworks", coalesce(storedMember("trustedNetworks"), []any{}),
		"dormantDays", coalesce(storedMember("dormantDays"), DefaultThreatSettings.DormantDays),
		"riskHalfLifeHours", coalesce(storedMember("riskHalfLifeHours"), DefaultThreatSettings.RiskHalfLifeHours),
		"notify", coalesce(storedMember("notify"), core.NewObject("owners", false, "emails", []any{})),
		"maxAutomaticContainments", coalesce(storedMember("maxAutomaticContainments"), DefaultThreatSettings.MaxAutomaticContainments),
	), nil
}

// RiskThresholds is threats.ts riskThresholds: the lowest score of each level.
var RiskThresholds = struct {
	Low    float64
	Medium float64
	High   float64
}{10, 40, 70}

// RiskScore (threats.ts riskScore): Decayed score of the contributions at `now` (0-100).
func RiskScore(contributions []*core.Object, now int64, halfLifeHours float64) (result float64, err error) {
	return threatsRiskScore(contributions, now, halfLifeHours), nil
}

func threatsRiskScore(contributions []*core.Object, now int64, halfLifeHours float64) float64 {
	halfLifeMs := math.Max(1, halfLifeHours) * threatsHour
	total := 0.0
	for _, contribution := range contributions {
		age := math.Max(0, float64(now)-jsNumber(contribution.Get("at")))
		total += jsNumber(contribution.Get("points")) * math.Pow(0.5, age/halfLifeMs)
	}
	return math.Min(100, jsMathRound(total))
}

// RiskLevelFor (threats.ts riskLevelFor): the level of a score.
func RiskLevelFor(score float64) string {
	if score >= RiskThresholds.High {
		return "high"
	}
	if score >= RiskThresholds.Medium {
		return "medium"
	}
	if score >= RiskThresholds.Low {
		return "low"
	}
	return "none"
}

var threatsLevelRank = map[string]float64{"none": 0, "low": 1, "medium": 2, "high": 3}
var threatsSeverityRank = map[string]float64{"low": 0, "medium": 1, "high": 2, "critical": 3}

// threatsRankAtLeast is `rank[a] >= rank[b]`, false when either is not ranked (undefined compares false in JavaScript).
func threatsRankAtLeast(rank map[string]float64, a, b string) bool {
	ra, okA := rank[a]
	rb, okB := rank[b]
	return okA && okB && ra >= rb
}

// MaxRiskLevel (threats.ts maxRiskLevel): the higher of two levels.
func MaxRiskLevel(a, b string) string {
	if threatsRankAtLeast(threatsLevelRank, a, b) {
		return a
	}
	return b
}

// RiskLevelAtLeast (threats.ts riskLevelAtLeast): whether a level reaches a floor.
func RiskLevelAtLeast(level string, floor string) (result bool, err error) {
	return threatsRankAtLeast(threatsLevelRank, level, floor), nil
}

// SeverityAtLeast (threats.ts severityAtLeast): whether a severity reaches a floor.
func SeverityAtLeast(severity string, floor string) (result bool, err error) {
	return threatsRankAtLeast(threatsSeverityRank, severity, floor), nil
}

// MaxSeverity (threats.ts maxSeverity): the higher of two severities.
func MaxSeverity(a string, b string) (result string, err error) {
	if threatsRankAtLeast(threatsSeverityRank, a, b) {
		return a, nil
	}
	return b, nil
}

// threatsContributions is a risk record's `contributions` as records.
func threatsContributions(record *core.Object) []*core.Object {
	list, _ := record.Get("contributions").([]any)
	out := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if contribution, ok := item.(*core.Object); ok {
			out = append(out, contribution)
		} else {
			out = append(out, core.NewObject())
		}
	}
	return out
}

// EffectiveRisk (threats.ts effectiveRisk): The score and level in force at `now`: decayed contributions, raised to
// an unexpired override's level. The result is {score, level}.
func EffectiveRisk(record *core.Object, now int64, halfLifeHours float64) (result *core.Object, err error) {
	score, level := threatsEffectiveRisk(record, now, halfLifeHours)
	return core.NewObject("score", score, "level", level), nil
}

func threatsEffectiveRisk(record *core.Object, now int64, halfLifeHours float64) (float64, string) {
	if record == nil {
		return 0, "none"
	}
	score := threatsRiskScore(threatsContributions(record), now, halfLifeHours)
	level := RiskLevelFor(score)
	if override, ok := record.Get("override").(*core.Object); ok {
		expiresAt := override.Get("expiresAt")
		if isUndefined(expiresAt) || jsNumber(expiresAt) > float64(now) {
			level = MaxRiskLevel(level, jsString(override.Get("level")))
		}
	}
	floor := 0.0
	switch level {
	case "none":
		floor = 0
	case "low":
		floor = RiskThresholds.Low
	case "medium":
		floor = RiskThresholds.Medium
	case "high":
		floor = RiskThresholds.High
	default:
		// riskThresholds[level] of an unknown level is undefined: Math.max(score, undefined) is NaN.
		floor = math.NaN()
	}
	return math.Max(score, floor), level
}

// RiskContextKeys is threats.ts riskContextKeys: the policy context keys this module fills (decisions.go reads them
// lazily when a document mentions them).
var RiskContextKeys = []string{"principal.riskLevel", "principal.riskScore"}

// MentionsRisk (threats.ts mentionsRisk): true when any statement of the documents refers to principal.riskLevel /
// principal.riskScore (conditions or variables).
func MentionsRisk(documents []any) bool {
	return anyStatementsMention(documents, "principal.risk")
}

// RiskContext (threats.ts riskContext): The risk keys for a decision. Simulated principals (invariants, impact
// previews, policy simulation, birthright automation) always get `none`/0 so an incident never flips an invariant or
// stalls automation; a delegated session takes the higher of the person's and the agent's risk.
func RiskContext(ctx context.Context, tx core.IamStore, principal *Principal, now int64) (result *core.Object, err error) {
	if principal.Session.Get("id") == "simulation" {
		return core.NewObject("principal.riskLevel", "none", "principal.riskScore", 0.0), nil
	}
	ids := []string{jsString(principal.Identity.Get("id"))}
	if agentID := principal.Session.Get("agentId"); truthy(agentID) {
		ids = append(ids, jsString(agentID))
	}
	level := "none"
	score := 0.0
	for _, identityID := range ids {
		record, err := tx.Get(ctx, ThreatCollections.Risk, identityID)
		if err != nil {
			return nil, err
		}
		if record == nil {
			continue
		}
		settings, err := tx.Get(ctx, ThreatCollections.Settings, jsString(record.Get("tenantId")))
		if err != nil {
			return nil, err
		}
		halfLife := DefaultThreatSettings.RiskHalfLifeHours
		if settings != nil {
			halfLife = jsNumber(coalesce(settings.Get("riskHalfLifeHours"), DefaultThreatSettings.RiskHalfLifeHours))
		}
		riskScoreValue, riskLevel := threatsEffectiveRisk(record, now, halfLife)
		level = MaxRiskLevel(level, riskLevel)
		score = math.Max(score, riskScoreValue)
	}
	return core.NewObject("principal.riskLevel", level, "principal.riskScore", score), nil
}

// EndContainment (threats.ts endContainment): Ends the threats module's hold on an identity whose status another
// path changed (identities.setStatus and offboard, service accounts, agents.suspend and resume, lifecycle
// workflows): the containment mark goes, so `threats.release` never re-activates what that path disabled, and a
// later disable is not taken for a containment. The risk score stays. Nothing happens for an identity that is not
// contained.
func EndContainment(ctx context.Context, tx core.IamStore, identityID string, now int64) (err error) {
	record, err := tx.Get(ctx, ThreatCollections.Risk, identityID)
	if err != nil {
		return err
	}
	if record == nil || !truthy(record.Get("contained")) {
		return nil
	}
	rest := record.Spread()
	rest.Delete("contained")
	rest.Set("updatedAt", float64(now))
	_, err = tx.Put(ctx, ThreatCollections.Risk, rest)
	return err
}

// ResponseActionKinds is threats.ts responseActionKinds.
var ResponseActionKinds = []string{"revoke-sessions", "forget-devices", "contain", "suspend-clearance", "block-network", "notify"}

// RiskLevels is threats.ts riskLevels.
var RiskLevels = []string{"none", "low", "medium", "high"}

// RiskPoints is threats.ts riskPoints: risk points per detection severity.
var RiskPoints = struct {
	Low      float64
	Medium   float64
	High     float64
	Critical float64
}{10, 25, 50, 80}

// RiskPointsFor is threats.ts `riskPoints[severity]` (NaN, as undefined arithmetic, for an unknown severity).
func RiskPointsFor(severity string) float64 {
	switch severity {
	case "low":
		return RiskPoints.Low
	case "medium":
		return RiskPoints.Medium
	case "high":
		return RiskPoints.High
	case "critical":
		return RiskPoints.Critical
	}
	return math.NaN()
}

// ThreatActor is threats.ts threatActor: the actor recorded on audit events the detection engine and automatic
// playbooks write.
const ThreatActor = "threat-detection"

// ThreatCollections is threats.ts threatCollections: the storage collections of the threats module; every one is
// tenant-scoped (lifecycle.go tenantCollections).
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

// ThreatSeverities is threats.ts threatSeverities.
var ThreatSeverities = []string{"low", "medium", "high", "critical"}
