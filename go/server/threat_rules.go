package server

// Port of packages/server/src/threat-rules.ts: the detection rules of the threats module (`threatRules` in threats.ts)
// as pure evaluation. Given one run's unread audit events of a tenant, the events before them that the rules'
// windows reach back to, the tenant's settings, and read-only facts about identities and roles, it returns the
// detections to record. Nothing is written here. The engine (threat_engine.go) records the candidates (deduplicated
// by `{ruleId}:{dedupeKey}`), persists the sign-in baselines the rules updated, and keeps `state` on its cursor.
//
// Per-event rules run in chain order, so a risky sign-in earlier in the run opens the account-takeover window for a
// change later in it. Counting rules slide a window over history and new events together and fire only for windows
// that end at a new event, so every event is judged once, and a burst keeps one dedupe key however many runs see it
// (`burstAnchor`).

import (
	"context"
	"math"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/core"
)

// ThreatRuleFacts is threat-rules.ts ThreatRuleFacts: read-only facts the rules may ask about a tenant.
type ThreatRuleFacts struct {
	// Identity by id in this tenant (nil when unknown/deleted).
	Identity func(ctx context.Context, id string) (*core.Object, error)
	// IsPrivileged: owner, rootAdmin, or holds (directly or via a group; live standing binding) a role whose policies
	// grant unconditional `*` or `iam:*` on `*` (analysis.ts unrestrictedAdmin logic).
	IsPrivileged func(ctx context.Context, identityID string) (bool, error)
	// IsAdminRole: the role grants unconditional `*`/`iam:*` on `*`.
	IsAdminRole func(ctx context.Context, roleID string) (bool, error)
	// HoldsRole: the identity holds a live standing binding of the role, directly or through a group membership.
	HoldsRole func(ctx context.Context, identityID, roleID string) (bool, error)
	// DetectionStands: whether a stored detection still stands (not dismissed, and not resolved in an incident closed
	// as a false positive or benign). Nil: every stored detection stands.
	DetectionStands func(ctx context.Context, detectionID string) (bool, error)
}

// ThreatRuleState is threat-rules.ts ThreatRuleState.
type ThreatRuleState struct {
	// AuthPolicy is the tenant sign-in policy as last seen (cursor.authPolicy); nil while unknown. Rules update it when
	// they read tenant:auth-policy.
	AuthPolicy *core.Object
}

// ThreatRuleInput is threat-rules.ts ThreatRuleInput.
type ThreatRuleInput struct {
	TenantID string
	// Events are the unread events of this run, ascending by sequence.
	Events []*core.Object
	// History holds the events in the lookback window before/overlapping Events, ascending by timestamp; it may
	// include ids also in Events (deduplicated by id).
	History []*core.Object
	// HistoryFrom is set when the lookback was cut short: the timestamp of the oldest event loaded.
	HistoryFrom *float64
	// Settings are the resolved threat settings (threats.ts ResolvedThreatSettings).
	Settings *core.Object
	// Baselines by identity id for the identities the engine preloaded (`BaselineIdentityIDs(events)`); rules mutate
	// them in place and create missing ones for people who sign in.
	Baselines map[string]*core.Object
	State     *ThreatRuleState
	Facts     ThreatRuleFacts
	Now       float64
}

// ThreatRuleResult is what evaluateThreatRules returns: the detections to record, oldest first, and the identities whose
// baselines changed, in the order they first changed.
type ThreatRuleResult struct {
	Candidates       []*core.Object
	TouchedBaselines []string
}

const (
	threatMinute = 60_000.0
	threatHour   = 60 * threatMinute
	threatDay    = 24 * threatHour
	// Evidence lists (event ids, networks, identities, actions) keep at most this many entries.
	threatEvidenceLimit = 20
	// Longest `uniqueKey` (`{ruleId}:{dedupeKey}`) a detection may have.
	threatUniqueKeyLimit         = 400
	threatBaselineNetworkLimit   = 25
	threatBaselineUserAgentLimit = 10
	threatUserAgentLength        = 512
	threatAuthSessionCreate      = "auth:session:create"
)

// Actors that stand for the deployment, a protocol, or the application rather than an identity.
var threatSystemActors = map[string]bool{
	"deployment-operator":  true,
	ThreatActor:            true,
	"directory-sync":       true,
	"dynamic-registration": true,
	"access-package":       true,
	"public-intake":        true,
	"application":          true,
}

// Allowed actions mass-deletion counts. Domain events stand in for their operation envelopes where they exist.
var threatDeletionActions = map[string]bool{
	"identity:delete":           true,
	"identity:offboard":         true,
	"iam:roles:delete":          true,
	"iam:policies:delete":       true,
	"iam:groups:delete":         true,
	"iam:bindings:delete":       true,
	"iam:credentials:revoke":    true,
	"iam:trust:revoke":          true,
	"iam:webhooks:delete":       true,
	"iam:resource-types:delete": true,
}

// Refusals recorded for callers nobody authenticated, under the identity they tried to act as.
var threatUnauthenticatedRefusals = map[string]bool{"role:assumed-with-web-identity": true}

// Changes to a person's own sign-in methods that keep an intruder in after a takeover, as summaries word them.
var threatPersistenceChanges = map[string]string{
	"auth:mfa:disable":        "turned off their second factor",
	"auth:mfa:enable":         "enrolled an authenticator app",
	"auth:passkey:create":     "added a passkey",
	"auth:mfa:recovery-codes": "generated new recovery codes",
	"auth:device:trust":       "remembered a device",
	"auth:email:change":       "changed their email address",
	"auth:password:change":    "changed their password",
	"iam:credentials:create":  "created an API key",
}

func threatDroppedFlag(name string) func(before, after *core.Object) bool {
	return func(before, after *core.Object) bool {
		return before.Get(name) == true && after.Get(name) != true
	}
}

func threatNonEmptyList(value any) bool {
	list, ok := value.([]any)
	return ok && len(list) > 0
}

// Protections of the tenant sign-in policy whose removal guardrail-weakened reports.
var threatPolicyProtections = []struct {
	name     string
	label    string
	weakened func(before, after *core.Object) bool
}{
	{"requireMfa", "the MFA requirement", threatDroppedFlag("requireMfa")},
	{"requireMfaForOwners", "the MFA requirement for owners", threatDroppedFlag("requireMfaForOwners")},
	{"bindSessionsToIp", "binding sessions to their network", threatDroppedFlag("bindSessionsToIp")},
	{"allowedIpRanges", "the IP allowlist", func(before, after *core.Object) bool {
		return threatNonEmptyList(before.Get("allowedIpRanges")) && !threatNonEmptyList(after.Get("allowedIpRanges"))
	}},
	{"notifyNewSignIn", "new sign-in notices", threatDroppedFlag("notifyNewSignIn")},
}

// Rules that count events per key in a sliding window (`findBursts`).
var threatCountingRules = []string{
	"password-spray",
	"brute-force",
	"mfa-bombardment",
	"mass-deletion",
	"directory-mass-change",
	"impersonation-burst",
	"denial-burst",
	"classified-access-attempts",
	"recon-burst",
}

// threatTuned is an enabled rule's severity, threshold, and window, with the definition's defaults behind the
// tenant's values.
type threatTuned struct {
	setting   *core.Object
	severity  string
	threshold float64
	windowMs  float64
}

func threatPositive(value any, fallback float64) float64 {
	if number, ok := value.(float64); ok && !math.IsNaN(number) && !math.IsInf(number, 0) && number > 0 {
		return number
	}
	return fallback
}

// threatTunedRule is the rule's tuning when the tenant has it enabled (nil otherwise).
func threatTunedRule(settings *core.Object, ruleID string) (*threatTuned, error) {
	setting, _ := member(settings.Get("rules"), ruleID).(*core.Object)
	if setting == nil || !truthy(setting.Get("enabled")) {
		return nil, nil
	}
	definition, err := ThreatRule(ruleID)
	if err != nil {
		return nil, err
	}
	threshold := 1.0
	if value, ok := definition.Get("threshold").(float64); ok {
		threshold = value
	}
	windowMs := threatHour
	if value, ok := definition.Get("windowMs").(float64); ok {
		windowMs = value
	}
	severity, _ := setting.Get("severity").(string)
	return &threatTuned{
		setting:   setting,
		severity:  severity,
		threshold: threatPositive(setting.Get("threshold"), threshold),
		windowMs:  threatPositive(setting.Get("windowMs"), windowMs),
	}, nil
}

// threatBurstAnchor is the dedupe anchor of a qualifying window ending at `at`: the first event of its cluster, but
// never before the start of the UTC day of `at`. Windows of a day or longer use window-sized buckets instead.
func threatBurstAnchor(clusterStart, at, windowMs float64) float64 {
	if windowMs >= threatDay {
		return math.Floor(at/windowMs) * windowMs
	}
	return math.Max(clusterStart, math.Floor(at/threatDay)*threatDay)
}

// threatBurstReach is the history a counting rule needs for stable anchors: the anchor's day (or bucket) plus one
// window before it.
func threatBurstReach(windowMs float64) float64 {
	if windowMs >= threatDay {
		return windowMs
	}
	return threatDay + windowMs
}

// RuleWindowMs (threat-rules.ts ruleWindowMs): How far before a run's earliest event the engine loads history: the
// longest reach of an enabled rule, at least one day. A counting rule reaches back one window plus the UTC day its
// burst anchor may lie in (`burstAnchor`), so an ongoing burst keeps its dedupe key from run to run;
// brute-force-success reaches back its window. With the default settings this is one day and fifteen minutes.
func RuleWindowMs(settings *core.Object) (result float64, err error) {
	reach := threatDay
	for _, ruleID := range threatCountingRules {
		rule, err := threatTunedRule(settings, ruleID)
		if err != nil {
			return 0, err
		}
		if rule != nil {
			reach = math.Max(reach, threatBurstReach(rule.windowMs))
		}
	}
	success, err := threatTunedRule(settings, "brute-force-success")
	if err != nil {
		return 0, err
	}
	if success != nil {
		reach = math.Max(reach, success.windowMs)
	}
	return reach, nil
}

// BaselineIdentityIDs (threat-rules.ts baselineIdentityIds): Identities whose stored baselines the rules read for
// these events: people who signed in (not through impersonation), whose baselines the sign-in rules compare and
// update, and people who changed their own sign-in methods, for whom account-takeover-persistence reads the risky
// sign-in an earlier run marked. The engine preloads these into `ThreatRuleInput.Baselines`.
func BaselineIdentityIDs(events []*core.Object) (result []string, err error) {
	return threatBaselineIdentityIDs(events), nil
}

func threatBaselineIdentityIDs(events []*core.Object) []string {
	ids := newOrderedSet()
	for _, event := range events {
		action, _ := event.Get("action").(string)
		_, persistence := threatPersistenceChanges[action]
		actorID, actorIsText := event.Get("actorId").(string)
		if (event.Get("action") == threatAuthSessionCreate && !truthy(event.Get("impersonatorId"))) ||
			(persistence && threatSame(event.Get("resourceId"), event.Get("actorId"))) {
			if actorIsText {
				ids.Add(actorID)
			}
		}
	}
	return ids.Values()
}

// threatRiskySignIn is a sign-in a rule flagged, opening the account-takeover-persistence window.
type threatRiskySignIn struct {
	at     float64
	ruleID string
	// The sign-in event, when it was judged in this run.
	eventID string
	// The stored detection, when an earlier run recorded it (the baseline's riskySignIn).
	detectionID string
	// The candidate's unique key, when it was raised in this run.
	uniqueKey string
}

type threatIdentityRead struct {
	identity *core.Object
	err      error
}

// threatRun is one evaluation: its input, memoized reads, and the candidates found so far (merged by unique key).
type threatRun struct {
	ctx              context.Context
	input            *ThreatRuleInput
	identities       map[string]threatIdentityRead
	trustedAddresses map[string]bool
	found            map[string]*core.Object
	foundOrder       []string
}

func (run *threatRun) identity(identityID string) (*core.Object, error) {
	read, ok := run.identities[identityID]
	if !ok {
		var identity *core.Object
		var err error
		if run.input.Facts.Identity != nil {
			identity, err = run.input.Facts.Identity(run.ctx, identityID)
		}
		read = threatIdentityRead{identity, err}
		run.identities[identityID] = read
	}
	return read.identity, read.err
}

// trusted is true when the address lies in one of the tenant's trusted networks, which detections never report.
func (run *threatRun) trusted(ip string) bool {
	trusted, ok := run.trustedAddresses[ip]
	if !ok {
		trusted = false
		networks, _ := run.input.Settings.Get("trustedNetworks").([]any)
		for _, network := range networks {
			if text, isText := network.(string); isText && core.IPMatches(ip, text) {
				trusted = true
				break
			}
		}
		run.trustedAddresses[ip] = trusted
	}
	return trusted
}

func (run *threatRun) add(candidate *core.Object) {
	uniqueKey := jsString(candidate.Get("ruleId")) + ":" + jsString(candidate.Get("dedupeKey"))
	if existing, ok := run.found[uniqueKey]; ok {
		threatMerge(existing, candidate)
		return
	}
	run.found[uniqueKey] = candidate
	run.foundOrder = append(run.foundOrder, uniqueKey)
}

// EvaluateThreatRules (threat-rules.ts evaluateThreatRules): Evaluates every enabled rule over one run's events.
// Returns the detections to record, oldest first, and the identities whose baselines changed (created, or updated by
// a sign-in); the engine persists those.
func EvaluateThreatRules(ctx context.Context, input *ThreatRuleInput) (result *ThreatRuleResult, err error) {
	if input.State == nil {
		input.State = &ThreatRuleState{}
	}
	if input.Baselines == nil {
		input.Baselines = map[string]*core.Object{}
	}
	run := &threatRun{
		ctx:              ctx,
		input:            input,
		identities:       map[string]threatIdentityRead{},
		trustedAddresses: map[string]bool{},
		found:            map[string]*core.Object{},
	}
	combined := make([]*core.Object, 0, len(input.History)+len(input.Events))
	combined = append(combined, input.History...)
	combined = append(combined, input.Events...)
	ordered := threatChronological(combined)
	fresh := map[string]bool{}
	var events []*core.Object
	for _, event := range input.Events {
		if !threatConsidered(event) {
			continue
		}
		id := threatEventText(event, "id")
		if fresh[id] {
			continue
		}
		fresh[id] = true
		events = append(events, event)
	}
	eventContext := &threatEventContext{
		signIns: threatIndexSignIns(ordered),
		risky:   map[string]*threatRiskySignIn{},
		touched: newOrderedSet(),
	}
	for _, event := range events {
		if err := threatEvaluateEvent(run, event, eventContext); err != nil {
			return nil, err
		}
	}
	if err := threatEvaluateCounting(run, ordered, fresh); err != nil {
		return nil, err
	}
	candidates := make([]*core.Object, 0, len(run.foundOrder))
	for _, key := range run.foundOrder {
		candidates = append(candidates, run.found[key])
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		return threatNumber(candidates[i], "occurredAt") < threatNumber(candidates[j], "occurredAt")
	})
	return &ThreatRuleResult{Candidates: candidates, TouchedBaselines: eventContext.touched.Values()}, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Event shapes

// Considered (threat-rules.ts considered): Events the rules read: well formed, and not the threats module's own. The
// engine filters with it too, so a stored event with a missing or mistyped field (one an intruder edited, say) is
// reported by the chain check and otherwise skipped, never stopping detection for its tenant.
func Considered(event *core.Object) (result bool, err error) {
	return threatConsidered(event), nil
}

func threatConsidered(event *core.Object) bool {
	if event == nil {
		return false
	}
	_, idOK := event.Get("id").(string)
	action, actionOK := event.Get("action").(string)
	actorID, actorOK := event.Get("actorId").(string)
	_, resourceOK := event.Get("resourceId").(string)
	timestamp, timestampOK := event.Get("timestamp").(float64)
	return idOK && actionOK && actorOK && resourceOK && timestampOK &&
		!math.IsNaN(timestamp) && !math.IsInf(timestamp, 0) &&
		actorID != ThreatActor && !strings.HasPrefix(action, "threat:")
}

// threatEventText reads a string member of an event (considered events have id, action, actorId and resourceId).
func threatEventText(event *core.Object, key string) string {
	text, _ := event.Get(key).(string)
	return text
}

// threatNumber reads a number member (timestamps of considered events, candidate times).
func threatNumber(record *core.Object, key string) float64 {
	return jsNumber(record.Get(key))
}

func threatTime(event *core.Object) float64 { return threatNumber(event, "timestamp") }

// threatSame is `===` over model values (arrays and objects by reference; separately read arrays never match).
func threatSame(a, b any) bool {
	if _, ok := a.([]any); ok {
		return false
	}
	if _, ok := b.([]any); ok {
		return false
	}
	return a == b
}

// threatChronological is history and new events together, each once, oldest first.
func threatChronological(events []*core.Object) []*core.Object {
	byID := map[string]*core.Object{}
	var order []string
	for _, event := range events {
		if !threatConsidered(event) {
			continue
		}
		id := threatEventText(event, "id")
		if _, seen := byID[id]; !seen {
			order = append(order, id)
		}
		byID[id] = event
	}
	result := make([]*core.Object, len(order))
	for index, id := range order {
		result[index] = byID[id]
	}
	sequenceOf := func(event *core.Object) float64 {
		value := event.Get("sequence")
		if nullish(value) {
			return 0
		}
		return jsNumber(value)
	}
	sort.SliceStable(result, func(i, j int) bool {
		a, b := result[i], result[j]
		if difference := threatTime(a) - threatTime(b); difference != 0 && !math.IsNaN(difference) {
			return difference < 0
		}
		if difference := sequenceOf(a) - sequenceOf(b); difference != 0 && !math.IsNaN(difference) {
			return difference < 0
		}
		return compareUTF16(threatEventText(a, "id"), threatEventText(b, "id")) < 0
	})
	return result
}

// threatRecorded: written by the service that owns the action, not an application `authorize()` call (those record
// only denials and root overrides).
func threatRecorded(event *core.Object) bool {
	return event.Get("rootOverride") != true
}

// threatIdentityActor: actors that are identities (people, service accounts, agents), not the deployment or a SCIM
// connection.
func threatIdentityActor(actorID string) bool {
	return !threatSystemActors[actorID] && !strings.HasPrefix(actorID, "scim:") && !strings.HasPrefix(actorID, "signal:")
}

// threatResponsibleActor: who is behind an event: the administrator of a "view as" session (`impersonatorId`) rather
// than the member it shows as.
func threatResponsibleActor(event *core.Object) string {
	if impersonator, ok := event.Get("impersonatorId").(string); ok && impersonator != "" {
		return impersonator
	}
	return threatEventText(event, "actorId")
}

// threatViewedAs: members a burst's events were performed as, through "view as" sessions of its actor.
func threatViewedAs(events []*core.Object) []string {
	var members []string
	for _, event := range events {
		if actorID := threatEventText(event, "actorId"); threatResponsibleActor(event) != actorID {
			members = append(members, actorID)
		}
	}
	return threatLimited(members)
}

// threatViewing is how a summary notes a burst performed (partly) through "view as" sessions, with `viewedAs`
// metadata.
func threatViewing(events []*core.Object) (string, *core.Object) {
	members := threatViewedAs(events)
	if len(members) == 0 {
		return "", core.NewObject()
	}
	all := true
	for _, event := range events {
		if threatResponsibleActor(event) == threatEventText(event, "actorId") {
			all = false
			break
		}
	}
	whom := "someone else"
	if len(members) != 1 {
		whom = core.NumberString(float64(len(members))) + " other people"
	}
	which := "some"
	if all {
		which = "all"
	}
	return ", " + which + " while viewing as " + whom, core.NewObject("viewedAs", members)
}

// threatAgentInvolvement is how a summary notes a burst an AI agent took part in, with `agent` (and the first
// `agentId` seen) metadata.
func threatAgentInvolvement(who *threatNamed, events []*core.Object) (string, *core.Object) {
	agentID := any(core.Undefined)
	for _, event := range events {
		if value := member(event.Get("sessionContext"), "agentId"); truthy(value) {
			agentID = value
			break
		}
	}
	isAgent := who.identity != nil && who.identity.Get("kind") == "agent"
	agent := isAgent || !isUndefined(agentID)
	clause := ""
	if isAgent {
		clause = " (an AI agent)"
	} else if !isUndefined(agentID) {
		clause = ", acting through an AI agent,"
	}
	metadata := core.NewObject("agent", agent)
	if !isUndefined(agentID) {
		metadata.Set("agentId", agentID)
	}
	return clause, metadata
}

// threatSignInFailure: a failed sign-in the auth service recorded (`auth:signin:fail`), optionally of one reason ("":
// any).
func threatSignInFailure(event *core.Object, reason string) bool {
	recordedReason, ok := member(event.Get("metadata"), "reason").(string)
	return event.Get("action") == "auth:signin:fail" &&
		event.Get("outcome") == "allow" &&
		threatRecorded(event) &&
		ok &&
		(reason == "" || recordedReason == reason)
}

// threatMandatoryRefusal: a decision refused by mandatory access control (security clearances).
func threatMandatoryRefusal(event *core.Object) bool {
	marker, ok := member(event.Get("metadata"), "mandatory").(string)
	return event.Get("outcome") == "deny" && ok && marker != ""
}

// threatOwnSignIn: a sign-in session the person started themselves.
func threatOwnSignIn(event *core.Object) bool {
	return event.Get("action") == threatAuthSessionCreate &&
		event.Get("outcome") == "allow" &&
		!truthy(event.Get("impersonatorId")) &&
		threatRecorded(event)
}

type threatClientNetwork struct {
	ip string
	// `ipCounterKey` form: an IPv4 address, or an IPv6 /64.
	key string
}

func threatClientNetworkOf(value any) *threatClientNetwork {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	key, ok := core.IPCounterKey(text)
	if !ok {
		return nil
	}
	return &threatClientNetwork{ip: text, key: key}
}

// threatReportableKey is the network's key, unless it is trusted (trusted networks never appear in a detection).
func threatReportableKey(run *threatRun, network *threatClientNetwork) (string, bool) {
	if network != nil && !run.trusted(network.ip) {
		return network.key, true
	}
	return "", false
}

// threatReportableNetworks: distinct reportable networks the events came from.
func threatReportableNetworks(run *threatRun, events []*core.Object) []string {
	var keys []string
	for _, event := range events {
		if key, ok := threatReportableKey(run, threatClientNetworkOf(member(event.Get("metadata"), "ip"))); ok {
			keys = append(keys, key)
		}
	}
	return threatDistinct(keys)
}

func threatJSONObject(value any) bool {
	object, ok := value.(*core.Object)
	return ok && object != nil
}

// ---------------------------------------------------------------------------------------------------------------
// Per-event rules

// threatSignInIndex holds sign-in events per person, oldest first: failures of any reason, and sign-ins not made
// through impersonation.
type threatSignInIndex struct {
	failures map[string][]*core.Object
	signIns  map[string][]*core.Object
	// Position of each sign-in in its person's list.
	positions map[string]int
	// Position of each indexed failure and sign-in in the run's chronological order.
	order map[string]int
}

type threatEventContext struct {
	signIns *threatSignInIndex
	// The latest risky sign-in flagged in this run, per identity.
	risky map[string]*threatRiskySignIn
	// Identities whose baselines changed.
	touched *orderedSet
}

func threatIndexSignIns(ordered []*core.Object) *threatSignInIndex {
	index := &threatSignInIndex{
		failures:  map[string][]*core.Object{},
		signIns:   map[string][]*core.Object{},
		positions: map[string]int{},
		order:     map[string]int{},
	}
	for position, event := range ordered {
		actorID := threatEventText(event, "actorId")
		id := threatEventText(event, "id")
		if threatSignInFailure(event, "") {
			index.failures[actorID] = append(index.failures[actorID], event)
		} else if threatOwnSignIn(event) {
			index.signIns[actorID] = append(index.signIns[actorID], event)
			index.positions[id] = len(index.signIns[actorID]) - 1
		} else {
			continue
		}
		index.order[id] = position
	}
	return index
}

// threatFirstIndex is the first index of a time-ordered list whose event passes a test that, once passed, stays
// passed.
func threatFirstIndex(list []*core.Object, test func(event *core.Object) bool) int {
	low, high := 0, len(list)
	for low < high {
		middle := int(uint(low+high) >> 1)
		if test(list[middle]) {
			high = middle
		} else {
			low = middle + 1
		}
	}
	return low
}

// threatFailuresBefore: the person's failed sign-ins in the `windowMs` before a sign-in and after their previous one:
// the streak the sign-in ended, as the auth service's sign-in ledger counts it.
func threatFailuresBefore(index *threatSignInIndex, event *core.Object, windowMs float64) []*core.Object {
	actorID := threatEventText(event, "actorId")
	failures, ok := index.failures[actorID]
	if !ok {
		return nil
	}
	after := -1
	if position, ok := index.positions[threatEventText(event, "id")]; ok && position != 0 {
		if list := index.signIns[actorID]; position-1 < len(list) {
			previous := list[position-1]
			if order, ok := index.order[threatEventText(previous, "id")]; ok {
				after = order
			}
		}
	}
	timestamp := threatTime(event)
	from := timestamp - windowMs
	start := threatFirstIndex(failures, func(failure *core.Object) bool {
		return threatTime(failure) >= from && index.order[threatEventText(failure, "id")] > after
	})
	end := threatFirstIndex(failures, func(failure *core.Object) bool { return threatTime(failure) > timestamp })
	if end < start {
		return nil
	}
	return failures[start:end]
}

func threatEvaluateEvent(run *threatRun, event *core.Object, context *threatEventContext) error {
	switch action := threatEventText(event, "action"); action {
	case threatAuthSessionCreate:
		return threatSignedIn(run, event, context)
	case "auth:session:mismatch":
		return threatSessionMismatch(run, event)
	case "iam:bindings:create":
		return threatBindingCreated(run, event)
	case "iam:root:grant":
		return threatRootGranted(run, event)
	case "tenant:auth-policy":
		return threatAuthPolicyChanged(run, event)
	case "security:network-unblock":
		return threatNetworkUnblocked(run, event)
	case "role:assumed-with-web-identity":
		return threatTokenReplayed(run, event)
	case "invariant:broken":
		return threatInvariantBroken(run, event)
	case "signal:received":
		return threatUpstreamSignal(run, event)
	default:
		if _, ok := threatPersistenceChanges[action]; ok {
			return threatPersistenceChanged(run, event, context.risky)
		}
	}
	return nil
}

// threatCandidate starts a candidate with its rule, severity, title and summary.
func threatCandidate(ruleID, severity, title, summary string) *core.Object {
	return core.NewObject("ruleId", ruleID, "severity", severity, "title", title, "summary", summary)
}

// threatSignedIn: brute-force-success, dormant-reactivated, and new-network judge a sign-in against what came before
// it; then the sign-in is learned into the person's baseline whether or not those rules are enabled.
func threatSignedIn(run *threatRun, event *core.Object, context *threatEventContext) error {
	if !threatOwnSignIn(event) {
		return nil
	}
	settings := run.input.Settings
	identityID := threatEventText(event, "actorId")
	eventID := threatEventText(event, "id")
	timestamp := threatTime(event)
	network := threatClientNetworkOf(member(event.Get("metadata"), "ip"))
	baseline := run.input.Baselines[identityID]
	flag := func(candidate *core.Object) {
		run.add(candidate)
		context.risky[identityID] = &threatRiskySignIn{
			at:        threatNumber(candidate, "occurredAt"),
			ruleID:    jsString(candidate.Get("ruleId")),
			eventID:   eventID,
			uniqueKey: jsString(candidate.Get("ruleId")) + ":" + jsString(candidate.Get("dedupeKey")),
		}
	}

	success, err := threatTunedRule(settings, "brute-force-success")
	if err != nil {
		return err
	}
	var failures []*core.Object
	if success != nil {
		failures = threatFailuresBefore(context.signIns, event, success.windowMs)
	}
	if success != nil && float64(len(failures)) >= success.threshold {
		failing := map[string]bool{}
		for _, failure := range failures {
			if failed := threatClientNetworkOf(member(failure.Get("metadata"), "ip")); failed != nil {
				failing[failed.key] = true
			}
		}
		fromFailing := network != nil && failing[network.key]
		who, err := threatIdentitySubject(run, identityID)
		if err != nil {
			return err
		}
		severity := success.severity
		if !fromFailing {
			severity = threatLowerSeverity[success.severity]
		}
		title, err := threatTitled("brute-force-success", who.label)
		if err != nil {
			return err
		}
		failingClause := ""
		if fromFailing {
			failingClause = ", from a network that was failing"
		}
		candidate := threatCandidate("brute-force-success", severity, title,
			who.label+" signed in after "+threatPlural(float64(len(failures)), "failed attempt", "")+" in the preceding "+threatInWords(success.windowMs)+failingClause+".")
		who.target(candidate)
		threatReportedNetwork(run, candidate, network)
		evidenceEvents := append(append([]*core.Object{}, failures...), event)
		candidate.Set("dedupeKey", threatDedupeKey("brute-force-success", eventID))
		candidate.Set("occurredAt", timestamp)
		candidate.Set("evidence", threatEvidenceOf(run, evidenceEvents, threatEvidenceExtra{}))
		candidate.Set("metadata", core.NewObject(
			"failures", float64(len(failures)),
			"threshold", success.threshold,
			"windowMs", success.windowMs,
			"fromFailingNetwork", fromFailing,
		))
		candidate.Set("riskySignIn", true)
		flag(candidate)
	}

	dormant, err := threatTunedRule(settings, "dormant-reactivated")
	if err != nil {
		return err
	}
	lastSignInAt := any(core.Undefined)
	if baseline != nil {
		lastSignInAt = baseline.Get("lastSignInAt")
	}
	dormantDays := math.Max(1, jsNumber(settings.Get("dormantDays")))
	if dormant != nil && !isUndefined(lastSignInAt) && timestamp-jsNumber(lastSignInAt) >= dormantDays*threatDay {
		idleDays := math.Floor((timestamp - jsNumber(lastSignInAt)) / threatDay)
		who, err := threatIdentitySubject(run, identityID)
		if err != nil {
			return err
		}
		title, err := threatTitled("dormant-reactivated", who.label)
		if err != nil {
			return err
		}
		candidate := threatCandidate("dormant-reactivated", dormant.severity, title,
			who.label+" signed in after "+threatPlural(idleDays, "day", "")+" without a sign-in (accounts count as dormant after "+threatPlural(dormantDays, "day", "")+").")
		who.target(candidate)
		threatReportedNetwork(run, candidate, network)
		candidate.Set("dedupeKey", threatDedupeKey("dormant-reactivated", eventID))
		candidate.Set("occurredAt", timestamp)
		candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{}))
		candidate.Set("metadata", core.NewObject("lastSignInAt", lastSignInAt, "idleDays", idleDays, "dormantDays", dormantDays))
		candidate.Set("riskySignIn", true)
		flag(candidate)
	}

	unfamiliar, err := threatTunedRule(settings, "new-network")
	if err != nil {
		return err
	}
	if unfamiliar != nil && network != nil && baseline != nil {
		known := threatList(baseline.Get("networks"))
		seen := false
		for _, entry := range known {
			if member(entry, "key") == network.key {
				seen = true
				break
			}
		}
		if len(known) > 0 && !seen && !run.trusted(network.ip) {
			privileged := false
			if run.input.Facts.IsPrivileged != nil {
				privileged, err = run.input.Facts.IsPrivileged(run.ctx, identityID)
				if err != nil {
					return err
				}
			}
			if privileged || unfamiliar.setting.Get("everyone") == true {
				who, err := threatIdentitySubject(run, identityID)
				if err != nil {
					return err
				}
				severity := "low"
				privilegedClause := ""
				if privileged {
					severity = unfamiliar.severity
					privilegedClause = ", a privileged account,"
				}
				title, err := threatTitled("new-network", who.label)
				if err != nil {
					return err
				}
				candidate := threatCandidate("new-network", severity, title,
					who.label+privilegedClause+" signed in from "+network.key+", a network not seen for them before.")
				who.target(candidate)
				candidate.Set("network", network.key)
				candidate.Set("dedupeKey", threatDedupeKey("new-network", eventID))
				candidate.Set("occurredAt", timestamp)
				candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{}))
				candidate.Set("metadata", core.NewObject("privileged", privileged, "knownNetworks", float64(len(known))))
				candidate.Set("riskySignIn", true)
				flag(candidate)
			}
		}
	}

	threatLearnSignIn(run.input, event, network, context.touched)
	return nil
}

// threatList reads an array member (a missing or mistyped one reads as empty).
func threatList(value any) []any {
	list, _ := value.([]any)
	return list
}

// threatLearnSignIn records a sign-in on the person's baseline (created on first sight): its network, user agent,
// and time.
func threatLearnSignIn(input *ThreatRuleInput, event *core.Object, network *threatClientNetwork, touched *orderedSet) {
	identityID := threatEventText(event, "actorId")
	timestamp := threatTime(event)
	baseline := input.Baselines[identityID]
	if baseline == nil {
		baseline = core.NewObject(
			"id", identityID,
			"tenantId", input.TenantID,
			"identityId", identityID,
			"networks", []any{},
			"userAgents", []any{},
			"firstSeenAt", timestamp,
			"updatedAt", input.Now,
		)
		input.Baselines[identityID] = baseline
	}
	if network != nil {
		var networks []any
		for _, known := range threatList(baseline.Get("networks")) {
			if member(known, "key") != network.key {
				networks = append(networks, known)
			}
		}
		networks = append(networks, core.NewObject("key", network.key, "lastAt", timestamp))
		baseline.Set("networks", threatLast(networks, threatBaselineNetworkLimit))
	}
	userAgent := ""
	if recordedAgent, ok := member(event.Get("metadata"), "userAgent").(string); ok {
		userAgent = threatSliceUTF16(threatClean(recordedAgent), 0, threatUserAgentLength)
	}
	if userAgent != "" {
		var agents []any
		for _, known := range threatList(baseline.Get("userAgents")) {
			if member(known, "value") != userAgent {
				agents = append(agents, known)
			}
		}
		agents = append(agents, core.NewObject("value", userAgent, "lastAt", timestamp))
		baseline.Set("userAgents", threatLast(agents, threatBaselineUserAgentLimit))
	}
	previous := coalesce(baseline.Get("lastSignInAt"), timestamp)
	baseline.Set("lastSignInAt", math.Max(jsNumber(previous), timestamp))
	baseline.Set("updatedAt", input.Now)
	touched.Add(identityID)
}

// threatLast is `.slice(-limit)`.
func threatLast(list []any, limit int) []any {
	if list == nil {
		list = []any{}
	}
	if len(list) > limit {
		return list[len(list)-limit:]
	}
	return list
}

// threatSessionMismatch is session-hijack: a session bound to one network was presented from another (one detection
// per session).
func threatSessionMismatch(run *threatRun, event *core.Object) error {
	rule, err := threatTunedRule(run.input.Settings, "session-hijack")
	if err != nil {
		return err
	}
	if rule == nil || event.Get("outcome") != "allow" || !threatRecorded(event) {
		return nil
	}
	metadata := event.Get("metadata")
	sessionID, _ := member(metadata, "sessionId").(string)
	sessionIP, _ := member(metadata, "sessionIp").(string)
	ip, hasIP := member(metadata, "ip").(string)
	presented := threatClientNetworkOf(member(metadata, "ip"))
	who, err := threatIdentitySubject(run, threatEventText(event, "actorId"))
	if err != nil {
		return err
	}
	title, err := threatTitled("session-hijack", who.label)
	if err != nil {
		return err
	}
	boundTo := "one network"
	if sessionIP != "" {
		boundTo = threatClean(sessionIP)
	}
	presentedFrom := "another network"
	if hasIP && ip != "" {
		presentedFrom = threatClean(ip)
	}
	candidate := threatCandidate("session-hijack", rule.severity, title,
		"A session of "+who.label+" bound to "+boundTo+" was presented from "+presentedFrom+".")
	who.target(candidate)
	threatReportedNetwork(run, candidate, presented)
	key := threatEventText(event, "id")
	if sessionID != "" {
		key = sessionID
	}
	candidate.Set("dedupeKey", threatDedupeKey("session-hijack", key))
	candidate.Set("occurredAt", threatTime(event))
	var sessionNetworks []string
	if sessionKey, ok := threatReportableKey(run, threatClientNetworkOf(sessionIP)); ok {
		sessionNetworks = []string{sessionKey}
	}
	candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{networks: sessionNetworks}))
	details := core.NewObject()
	if sessionID != "" {
		details.Set("sessionId", sessionID)
	}
	details.Set("sessionIp", sessionIP)
	if hasIP && ip != "" {
		details.Set("ip", ip)
	}
	candidate.Set("metadata", details)
	run.add(candidate)
	return nil
}

// threatPersistenceChanged is account-takeover-persistence: a person changed their own sign-in methods within the
// window after a risky sign-in, flagged earlier in this run or by an earlier run (the baseline's riskySignIn).
func threatPersistenceChanged(run *threatRun, event *core.Object, risky map[string]*threatRiskySignIn) error {
	rule, err := threatTunedRule(run.input.Settings, "account-takeover-persistence")
	if err != nil {
		return err
	}
	action := threatEventText(event, "action")
	actorID := threatEventText(event, "actorId")
	change, known := threatPersistenceChanges[action]
	if rule == nil || !known || event.Get("outcome") != "allow" || threatEventText(event, "resourceId") != actorID {
		return nil
	}
	if strings.HasPrefix(action, "auth:") && !threatRecorded(event) {
		return nil
	}
	var sources []*threatRiskySignIn
	var stored any = core.Undefined
	if baseline := run.input.Baselines[actorID]; baseline != nil {
		stored = baseline.Get("riskySignIn")
	}
	// A risky sign-in an administrator has since judged harmless (dismissed, or closed as a false positive or benign)
	// opens no window.
	if truthy(stored) {
		stands := true
		if run.input.Facts.DetectionStands != nil {
			detectionID, _ := member(stored, "detectionId").(string)
			stands, err = run.input.Facts.DetectionStands(run.ctx, detectionID)
			if err != nil {
				return err
			}
		}
		if stands {
			detectionID, _ := member(stored, "detectionId").(string)
			sources = append(sources, &threatRiskySignIn{
				at:          jsNumber(member(stored, "at")),
				ruleID:      jsString(member(stored, "ruleId")),
				detectionID: detectionID,
			})
		}
	}
	if current := risky[actorID]; current != nil {
		sources = append(sources, current)
	}
	timestamp := threatTime(event)
	var source *threatRiskySignIn
	for _, candidate := range sources {
		if math.Abs(timestamp-candidate.at) <= rule.windowMs && (source == nil || candidate.at > source.at) {
			source = candidate
		}
	}
	if source == nil {
		return nil
	}
	who, err := threatIdentitySubject(run, actorID)
	if err != nil {
		return err
	}
	elapsed := math.Max(0, timestamp-source.at)
	riskyTitle := threatClean(source.ruleID)
	if ThreatRuleIDs.Has(source.ruleID) {
		definition, err := ThreatRule(source.ruleID)
		if err != nil {
			return err
		}
		riskyTitle = core.JSLower(jsString(definition.Get("title")))
	}
	title, err := threatTitled("account-takeover-persistence", who.label)
	if err != nil {
		return err
	}
	after := "less than a minute"
	if elapsed >= threatMinute {
		after = threatAbout(elapsed)
	}
	candidate := threatCandidate("account-takeover-persistence", rule.severity, title,
		who.label+" "+change+" "+after+" after a risky sign-in ("+riskyTitle+").")
	who.target(candidate)
	candidate.Set("dedupeKey", threatDedupeKey("account-takeover-persistence", threatEventText(event, "id")))
	candidate.Set("occurredAt", timestamp)
	eventIDs := []string{}
	count := 1.0
	actions := []string{action}
	if source.eventID != "" {
		eventIDs = append(eventIDs, source.eventID)
		count = 2
		actions = []string{threatAuthSessionCreate, action}
	}
	eventIDs = append(eventIDs, threatEventText(event, "id"))
	candidate.Set("evidence", core.NewObject(
		"eventIds", eventIDs,
		"count", count,
		"firstAt", math.Min(source.at, timestamp),
		"lastAt", math.Max(source.at, timestamp),
		"actions", actions,
	))
	metadata := core.NewObject(
		"changedAction", action,
		"riskySignInRuleId", source.ruleID,
		"riskySignInAt", source.at,
	)
	if source.detectionID != "" {
		metadata.Set("riskySignInDetectionId", source.detectionID)
	}
	if source.uniqueKey != "" {
		metadata.Set("riskySignInKey", source.uniqueKey)
	}
	candidate.Set("metadata", metadata)
	run.add(candidate)
	return nil
}

// threatBindingCreated is privilege-escalation: an administrator role was granted by someone who now holds it.
// Firings are kept to one per actor, role, and UTC day, and root administrators and owners are not judged.
func threatBindingCreated(run *threatRun, event *core.Object) error {
	rule, err := threatTunedRule(run.input.Settings, "privilege-escalation")
	if err != nil {
		return err
	}
	if rule == nil || event.Get("outcome") != "allow" || !threatIdentityActor(threatEventText(event, "actorId")) {
		return nil
	}
	actor, err := run.identity(threatEventText(event, "actorId"))
	if err != nil {
		return err
	}
	if actor == nil || truthy(actor.Get("rootAdmin")) || truthy(actor.Get("owner")) {
		return nil
	}
	actorID := jsString(actor.Get("id"))
	roleID := threatEventText(event, "resourceId")
	if run.input.Facts.IsAdminRole == nil {
		return nil
	}
	admin, err := run.input.Facts.IsAdminRole(run.ctx, roleID)
	if err != nil || !admin {
		return err
	}
	if run.input.Facts.HoldsRole == nil {
		return nil
	}
	holds, err := run.input.Facts.HoldsRole(run.ctx, actorID, roleID)
	if err != nil || !holds {
		return err
	}
	label := threatIdentityLabel(actor, actorID)
	title, err := threatTitled("privilege-escalation", label)
	if err != nil {
		return err
	}
	candidate := threatCandidate("privilege-escalation", rule.severity, title,
		label+" granted the administrator role "+threatClean(roleID)+" and now holds it.")
	candidate.Set("subject", core.NewObject("type", "identity", "id", actorID, "name", label))
	candidate.Set("identityId", actorID)
	candidate.Set("dedupeKey", threatDedupeKey("privilege-escalation", actorID, roleID, threatStartOfDay(threatTime(event))))
	candidate.Set("occurredAt", threatTime(event))
	candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{actions: true}))
	candidate.Set("metadata", core.NewObject("roleId", roleID))
	run.add(candidate)
	return nil
}

// threatRootGranted is root-admin-granted: `iam:root:grant` left its target a root administrator.
func threatRootGranted(run *threatRun, event *core.Object) error {
	rule, err := threatTunedRule(run.input.Settings, "root-admin-granted")
	if err != nil {
		return err
	}
	if rule == nil || event.Get("outcome") != "allow" {
		return nil
	}
	target, err := run.identity(threatEventText(event, "resourceId"))
	if err != nil {
		return err
	}
	if target == nil || !truthy(target.Get("rootAdmin")) {
		return nil
	}
	targetID := jsString(target.Get("id"))
	label := threatIdentityLabel(target, targetID)
	actorID := threatEventText(event, "actorId")
	granter, err := run.identity(actorID)
	if err != nil {
		return err
	}
	grantedBy := threatIdentityLabel(granter, actorID)
	title, err := threatTitled("root-admin-granted", label)
	if err != nil {
		return err
	}
	candidate := threatCandidate("root-admin-granted", rule.severity, title,
		grantedBy+" made "+label+" a root administrator of the deployment.")
	candidate.Set("subject", core.NewObject("type", "identity", "id", targetID, "name", label))
	candidate.Set("identityId", targetID)
	candidate.Set("dedupeKey", threatDedupeKey("root-admin-granted", threatEventText(event, "id")))
	candidate.Set("occurredAt", threatTime(event))
	candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{identityIDs: []string{targetID}, actions: true}))
	candidate.Set("metadata", core.NewObject("grantedBy", actorID))
	run.add(candidate)
	return nil
}

// threatAuthPolicyChanged is guardrail-weakened (sign-in policy): compares the tenant's new sign-in policy with the
// one last seen, then remembers the new one. Without a previous policy the rule only learns.
func threatAuthPolicyChanged(run *threatRun, event *core.Object) error {
	input := run.input
	if event.Get("outcome") != "allow" || !threatRecorded(event) || threatEventText(event, "resourceId") != input.TenantID {
		return nil
	}
	metadata, ok := event.Get("metadata").(*core.Object)
	if !ok || metadata == nil || !metadata.Has("authPolicy") {
		return nil
	}
	policy := metadata.Get("authPolicy")
	if policy != nil && !threatJSONObject(policy) {
		return nil
	}
	after, _ := policy.(*core.Object)
	if after == nil {
		after = core.NewObject()
	}
	before := input.State.AuthPolicy
	input.State.AuthPolicy = after
	rule, err := threatTunedRule(input.Settings, "guardrail-weakened")
	if err != nil {
		return err
	}
	if rule == nil || before == nil {
		return nil
	}
	var labels, names []string
	for _, protection := range threatPolicyProtections {
		if protection.weakened(before, after) {
			labels = append(labels, protection.label)
			names = append(names, protection.name)
		}
	}
	if len(labels) == 0 {
		return nil
	}
	actor, err := threatActorOf(run, threatEventText(event, "actorId"))
	if err != nil {
		return err
	}
	title, err := threatTitled("guardrail-weakened", "sign-in policy")
	if err != nil {
		return err
	}
	candidate := threatCandidate("guardrail-weakened", rule.severity, title,
		actor.label+" removed "+threatSeries(labels)+" from the tenant sign-in policy.")
	candidate.Set("subject", core.NewObject("type", "tenant", "id", input.TenantID))
	if actor.identityID != "" {
		candidate.Set("identityId", actor.identityID)
	}
	candidate.Set("dedupeKey", threatDedupeKey("guardrail-weakened", threatEventText(event, "id")))
	candidate.Set("occurredAt", threatTime(event))
	candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{actions: true}))
	candidate.Set("metadata", core.NewObject("change", "auth-policy", "weakened", names))
	run.add(candidate)
	return nil
}

// threatNetworkUnblocked is guardrail-weakened (network block lifted): every `security:network-unblock`.
func threatNetworkUnblocked(run *threatRun, event *core.Object) error {
	rule, err := threatTunedRule(run.input.Settings, "guardrail-weakened")
	if err != nil {
		return err
	}
	network, isText := member(event.Get("metadata"), "network").(string)
	if rule == nil || event.Get("outcome") != "allow" || !threatRecorded(event) || !isText {
		return nil
	}
	platform := member(event.Get("metadata"), "platform") == true
	actor, err := threatActorOf(run, threatEventText(event, "actorId"))
	if err != nil {
		return err
	}
	title, err := threatTitled("guardrail-weakened", "network block lifted")
	if err != nil {
		return err
	}
	platformWide := ""
	if platform {
		platformWide = "platform-wide "
	}
	candidate := threatCandidate("guardrail-weakened", rule.severity, title,
		actor.label+" lifted the "+platformWide+"block on "+threatClean(network)+".")
	candidate.Set("subject", core.NewObject("type", "tenant", "id", run.input.TenantID))
	if actor.identityID != "" {
		candidate.Set("identityId", actor.identityID)
	}
	candidate.Set("dedupeKey", threatDedupeKey("guardrail-weakened", threatEventText(event, "id")))
	candidate.Set("occurredAt", threatTime(event))
	candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{actions: true}))
	candidate.Set("metadata", core.NewObject(
		"change", "network-unblock",
		"network", network,
		"platform", platform,
		"blockId", threatEventText(event, "resourceId"),
	))
	run.add(candidate)
	return nil
}

// threatTokenReplayed is token-replay: a web identity token refused as already used.
func threatTokenReplayed(run *threatRun, event *core.Object) error {
	rule, err := threatTunedRule(run.input.Settings, "token-replay")
	if err != nil {
		return err
	}
	metadata := event.Get("metadata")
	if rule == nil || event.Get("outcome") != "deny" || member(metadata, "reason") != "replay" {
		return nil
	}
	who, err := threatIdentitySubject(run, threatEventText(event, "actorId"))
	if err != nil {
		return err
	}
	roleID := threatEventText(event, "resourceId")
	details := core.NewObject("roleId", roleID)
	for _, name := range []string{"trustId", "providerId", "issuer", "subject"} {
		if value, ok := member(metadata, name).(string); ok {
			details.Set(name, value)
		}
	}
	external := ""
	if subject, ok := member(metadata, "subject").(string); ok {
		external = threatClean(subject)
	}
	externalClause := ""
	if external != "" {
		externalClause = " (token subject " + external + ")"
	}
	title, err := threatTitled("token-replay", who.label)
	if err != nil {
		return err
	}
	candidate := threatCandidate("token-replay", rule.severity, title,
		"A web identity token was presented a second time to assume role "+threatClean(roleID)+" as "+who.label+externalClause+".")
	who.target(candidate)
	candidate.Set("dedupeKey", threatDedupeKey("token-replay", threatEventText(event, "id")))
	candidate.Set("occurredAt", threatTime(event))
	candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{}))
	candidate.Set("metadata", details)
	run.add(candidate)
	return nil
}

// threatInvariantBroken is invariant-broken: the invariant checker reported a newly broken invariant; enforced ones
// are at least high.
func threatInvariantBroken(run *threatRun, event *core.Object) error {
	rule, err := threatTunedRule(run.input.Settings, "invariant-broken")
	if err != nil {
		return err
	}
	metadata := event.Get("metadata")
	name, isText := member(metadata, "name").(string)
	if rule == nil || threatEventText(event, "actorId") != "deployment-operator" || !isText {
		return nil
	}
	mode := "monitor"
	if member(metadata, "mode") == "enforce" {
		mode = "enforce"
	}
	violations := []string{}
	for _, value := range threatList(member(metadata, "violations")) {
		if text, ok := value.(string); ok {
			violations = append(violations, text)
		}
	}
	failure, hasError := member(metadata, "error").(string)
	detail := ""
	if len(violations) > 0 {
		detail = " for " + threatPlural(float64(len(violations)), "identity", "identities")
	} else if hasError && failure != "" {
		detail = " (" + threatClean(failure) + ")"
	}
	severity := rule.severity
	modeWord := "monitored"
	if mode == "enforce" {
		severity, err = MaxSeverity("high", rule.severity)
		if err != nil {
			return err
		}
		modeWord = "enforced"
	}
	title, err := threatTitled("invariant-broken", threatClean(name))
	if err != nil {
		return err
	}
	candidate := threatCandidate("invariant-broken", severity, title,
		"The "+modeWord+" access invariant \""+threatClean(name)+"\" stopped holding"+detail+".")
	candidate.Set("subject", core.NewObject("type", "tenant", "id", run.input.TenantID))
	candidate.Set("dedupeKey", threatDedupeKey("invariant-broken", threatEventText(event, "id")))
	candidate.Set("occurredAt", threatTime(event))
	candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{identityIDs: violations}))
	shown := violations
	if len(shown) > threatEvidenceLimit {
		shown = shown[:threatEvidenceLimit]
	}
	details := core.NewObject(
		"name", name,
		"mode", mode,
		"invariantId", threatEventText(event, "resourceId"),
		"violations", append([]string{}, shown...),
	)
	if hasError && failure != "" {
		details.Set("error", failure)
	}
	candidate.Set("metadata", details)
	run.add(candidate)
	return nil
}

// threatUpstreamSeverity is the severity of an upstream Shared Signals event about a person; "" for events that raise
// nothing.
func threatUpstreamSeverity(eventType string, currentLevel any) string {
	switch eventType {
	case "credential-compromise":
		return "high"
	case "account-disabled", "account-purged", "account-credential-change-required":
		return "medium"
	case "credential-change":
		return "low"
	case "risk-level-change":
		if currentLevel == "HIGH" {
			return "high"
		}
		if currentLevel == "MEDIUM" {
			return "medium"
		}
	}
	return ""
}

// threatUpstreamSignal is upstream-signal: the Shared Signals receiver matched an upstream provider's event to a
// person of this tenant (`signal:received`, actor `signal:{sourceId}`).
func threatUpstreamSignal(run *threatRun, event *core.Object) error {
	rule, err := threatTunedRule(run.input.Settings, "upstream-signal")
	if err != nil {
		return err
	}
	metadata := event.Get("metadata")
	sourceID, sourceOK := member(metadata, "sourceId").(string)
	eventType, typeOK := member(metadata, "eventType").(string)
	identityID, identityOK := member(metadata, "identityId").(string)
	if rule == nil || event.Get("outcome") != "allow" || !threatRecorded(event) || !sourceOK ||
		threatEventText(event, "actorId") != "signal:"+sourceID || !typeOK || !identityOK {
		return nil
	}
	severity := threatUpstreamSeverity(eventType, member(metadata, "currentLevel"))
	if severity == "" {
		return nil
	}
	who, err := threatIdentitySubject(run, identityID)
	if err != nil {
		return err
	}
	reason := ""
	if text, ok := member(metadata, "reasonAdmin").(string); ok {
		reason = threatClean(text)
	}
	details := core.NewObject("sourceId", sourceID, "eventType", eventType)
	if jti, ok := member(metadata, "jti").(string); ok {
		details.Set("jti", jti)
	}
	for _, name := range []string{"currentLevel", "credentialType"} {
		if value, ok := member(metadata, name).(string); ok {
			details.Set(name, value)
		}
	}
	reasonClause := ""
	if reason != "" {
		reasonClause = ": " + reason
	}
	title, err := threatTitled("upstream-signal", who.label)
	if err != nil {
		return err
	}
	candidate := threatCandidate("upstream-signal", severity, title,
		"An upstream identity provider reported "+strings.ReplaceAll(eventType, "-", " ")+" for "+who.label+reasonClause+".")
	who.target(candidate)
	candidate.Set("dedupeKey", threatDedupeKey("upstream-signal", threatEventText(event, "id")))
	candidate.Set("occurredAt", threatTime(event))
	candidate.Set("evidence", threatEvidenceOf(run, []*core.Object{event}, threatEvidenceExtra{}))
	candidate.Set("metadata", details)
	run.add(candidate)
	return nil
}

// ---------------------------------------------------------------------------------------------------------------
// Counting rules

// threatCounter is what a counting rule counts: the key it counts per and, for distinct counts, the value that must
// differ.
type threatCounter struct {
	key func(event *core.Object) (string, bool)
	// distinct counts distinct values (password spray: accounts) instead of events; nil to count events.
	distinct func(event *core.Object) (string, bool)
}

type threatWindow struct {
	threshold float64
	windowMs  float64
}

// threatBurst is a qualifying burst of one key that this run's events are part of.
type threatBurst struct {
	key string
	// The burst's dedupe anchor (`burstAnchor`).
	anchor float64
	// Events from the start of the first qualifying window to the last qualifying new event, oldest first.
	events []*core.Object
	// The highest count (or distinct count) one window reached.
	peak   float64
	lastAt float64
}

// threatFindBursts slides each key's window over history and new events and reports the windows that end at a new
// event and reach the threshold, grouped by anchor.
func threatFindBursts(ordered []*core.Object, fresh map[string]bool, historyFrom *float64, window threatWindow, counter threatCounter) []*threatBurst {
	byKey := map[string][]*core.Object{}
	var keys []string
	for _, event := range ordered {
		key, ok := counter.key(event)
		if !ok {
			continue
		}
		if _, seen := byKey[key]; !seen {
			keys = append(keys, key)
		}
		byKey[key] = append(byKey[key], event)
	}
	var bursts []*threatBurst
	distinct := counter.distinct
	for _, key := range keys {
		list := byKey[key]
		anyFresh := false
		for _, event := range list {
			if fresh[threatEventText(event, "id")] {
				anyFresh = true
				break
			}
		}
		if !anyFresh {
			continue
		}
		values := map[string]int{}
		count := func(event *core.Object, delta int) {
			if distinct == nil {
				return
			}
			value, ok := distinct(event)
			if !ok {
				return
			}
			next := values[value] + delta
			if next > 0 {
				values[value] = next
			} else {
				delete(values, value)
			}
		}
		type qualifyingWindow struct {
			from, to int
			peak     float64
		}
		qualifying := map[float64]*qualifyingWindow{}
		var anchors []float64
		start := 0
		clusterStart := 0
		for index, event := range list {
			timestamp := threatTime(event)
			if index > 0 && timestamp-threatTime(list[index-1]) > window.windowMs {
				clusterStart = index
			}
			count(event, 1)
			for threatTime(list[start]) < timestamp-window.windowMs {
				count(list[start], -1)
				start++
			}
			if !fresh[threatEventText(event, "id")] {
				continue
			}
			size := float64(index - start + 1)
			if distinct != nil {
				size = float64(len(values))
			}
			if size < window.threshold {
				continue
			}
			// With the lookback cut short, a cluster whose first loaded event lies within a window of the cut may have
			// begun before it: its start is unknown, and the start of the day stands in, as it will for every later run.
			cut := clusterStart == 0 && historyFrom != nil && threatTime(list[0])-*historyFrom <= window.windowMs
			clusterTime := math.Inf(-1)
			if !cut {
				clusterTime = threatTime(list[clusterStart])
			}
			anchor := threatBurstAnchor(clusterTime, timestamp, window.windowMs)
			if burst, ok := qualifying[anchor]; ok {
				burst.to = index
				burst.peak = math.Max(burst.peak, size)
			} else {
				qualifying[anchor] = &qualifyingWindow{from: start, to: index, peak: size}
				anchors = append(anchors, anchor)
			}
		}
		for _, anchor := range anchors {
			burst := qualifying[anchor]
			bursts = append(bursts, &threatBurst{
				key:    key,
				anchor: anchor,
				events: append([]*core.Object{}, list[burst.from:burst.to+1]...),
				peak:   burst.peak,
				lastAt: threatTime(list[burst.to]),
			})
		}
	}
	return bursts
}

func threatBurstMetadata(window threatWindow, burst *threatBurst, extra ...*core.Object) *core.Object {
	metadata := core.NewObject("peak", burst.peak, "threshold", window.threshold, "windowMs", window.windowMs)
	return metadata.Assign(extra...)
}

func (rule *threatTuned) window() threatWindow {
	return threatWindow{threshold: rule.threshold, windowMs: rule.windowMs}
}

func threatEvaluateCounting(run *threatRun, ordered []*core.Object, fresh map[string]bool) error {
	settings := run.input.Settings
	historyFrom := run.input.HistoryFrom

	spray, err := threatTunedRule(settings, "password-spray")
	if err != nil {
		return err
	}
	if spray != nil {
		for _, burst := range threatFindBursts(ordered, fresh, historyFrom, spray.window(), threatCounter{
			key: func(event *core.Object) (string, bool) {
				if !threatSignInFailure(event, "password") {
					return "", false
				}
				return threatReportableKey(run, threatClientNetworkOf(member(event.Get("metadata"), "ip")))
			},
			distinct: func(event *core.Object) (string, bool) { return threatEventText(event, "actorId"), true },
		}) {
			var actors []string
			for _, event := range burst.events {
				actors = append(actors, threatEventText(event, "actorId"))
			}
			accounts := threatDistinct(actors)
			candidate := threatCandidate("password-spray", spray.severity, "Password spray from "+burst.key,
				threatPlural(burst.peak, "account", "")+" failed password sign-in from "+burst.key+" within "+threatInWords(spray.windowMs)+" ("+threatPlural(float64(len(burst.events)), "attempt", "")+" in all).")
			candidate.Set("subject", core.NewObject("type", "network", "id", burst.key))
			candidate.Set("network", burst.key)
			candidate.Set("dedupeKey", threatDedupeKey("password-spray", burst.key, burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{identityIDs: accounts}))
			candidate.Set("metadata", threatBurstMetadata(spray.window(), burst, core.NewObject("accounts", float64(len(accounts)))))
			run.add(candidate)
		}
	}

	for _, pair := range [][2]string{{"brute-force", "password"}, {"mfa-bombardment", "mfa"}} {
		ruleID, reason := pair[0], pair[1]
		rule, err := threatTunedRule(settings, ruleID)
		if err != nil {
			return err
		}
		if rule == nil {
			continue
		}
		for _, burst := range threatFindBursts(ordered, fresh, historyFrom, rule.window(), threatCounter{
			key: func(event *core.Object) (string, bool) {
				if threatSignInFailure(event, reason) {
					return threatEventText(event, "actorId"), true
				}
				return "", false
			},
		}) {
			who, err := threatIdentitySubject(run, burst.key)
			if err != nil {
				return err
			}
			networks := threatReportableNetworks(run, burst.events)
			where := ""
			if len(networks) == 1 {
				where = " from " + networks[0]
			} else if len(networks) > 1 {
				where = " from " + threatPlural(float64(len(networks)), "network", "")
			}
			title, err := threatTitled(ruleID, who.label)
			if err != nil {
				return err
			}
			var summary string
			if ruleID == "brute-force" {
				summary = who.label + " had " + threatPlural(burst.peak, "failed password sign-in", "") + " within " + threatInWords(rule.windowMs) + where + "."
			} else {
				summary = who.label + " had " + threatPlural(burst.peak, "wrong second-factor code", "") + " entered within " + threatInWords(rule.windowMs) + where + ", so someone else likely knows the password."
			}
			candidate := threatCandidate(ruleID, rule.severity, title, summary)
			who.target(candidate)
			if len(networks) == 1 {
				candidate.Set("network", networks[0])
			}
			candidate.Set("dedupeKey", threatDedupeKey(ruleID, burst.key, burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{}))
			candidate.Set("metadata", threatBurstMetadata(rule.window(), burst, core.NewObject("networks", float64(len(networks)))))
			run.add(candidate)
		}
	}

	deletion, err := threatTunedRule(settings, "mass-deletion")
	if err != nil {
		return err
	}
	if deletion != nil {
		for _, burst := range threatFindBursts(ordered, fresh, historyFrom, deletion.window(), threatCounter{
			key: func(event *core.Object) (string, bool) {
				action := threatEventText(event, "action")
				responsible := threatResponsibleActor(event)
				if threatDeletionActions[action] && event.Get("outcome") == "allow" && threatIdentityActor(responsible) &&
					(strings.HasPrefix(action, "iam:") || threatRecorded(event)) {
					return responsible, true
				}
				return "", false
			},
		}) {
			who, err := threatIdentitySubject(run, burst.key)
			if err != nil {
				return err
			}
			var removed []string
			for _, event := range burst.events {
				if strings.HasPrefix(threatEventText(event, "action"), "identity:") {
					removed = append(removed, threatEventText(event, "resourceId"))
				}
			}
			identities := threatDistinct(removed)
			clause, viewed := threatViewing(burst.events)
			title, err := threatTitled("mass-deletion", who.label)
			if err != nil {
				return err
			}
			candidate := threatCandidate("mass-deletion", deletion.severity, title,
				who.label+" deleted or revoked "+threatPlural(burst.peak, "item", "")+" within "+threatInWords(deletion.windowMs)+clause+".")
			who.target(candidate)
			candidate.Set("dedupeKey", threatDedupeKey("mass-deletion", burst.key, burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{identityIDs: identities, actions: true}))
			candidate.Set("metadata", threatBurstMetadata(deletion.window(), burst, core.NewObject("identities", float64(len(identities))), viewed))
			run.add(candidate)
		}
	}

	directory, err := threatTunedRule(settings, "directory-mass-change")
	if err != nil {
		return err
	}
	if directory != nil {
		for _, burst := range threatFindBursts(ordered, fresh, historyFrom, directory.window(), threatCounter{
			key: func(event *core.Object) (string, bool) {
				action := threatEventText(event, "action")
				actorID := threatEventText(event, "actorId")
				if (action == "iam:scim:UpdateUser" || action == "iam:scim:DeleteUser") && event.Get("outcome") == "allow" &&
					strings.HasPrefix(actorID, "scim:") {
					return actorID, true
				}
				return "", false
			},
		}) {
			deletions := 0
			for _, event := range burst.events {
				if threatEventText(event, "action") == "iam:scim:DeleteUser" {
					deletions++
				}
			}
			connection := threatClean(burst.key)
			deletionClause := ""
			if deletions > 0 {
				deletionClause = " (" + threatPlural(float64(deletions), "deletion", "") + " in all)"
			}
			title, err := threatTitled("directory-mass-change", connection)
			if err != nil {
				return err
			}
			candidate := threatCandidate("directory-mass-change", directory.severity, title,
				"SCIM connection "+threatSliceUTF16(connection, len("scim:"), -1)+" updated or deleted people "+threatPlural(burst.peak, "time", "")+" within "+threatInWords(directory.windowMs)+deletionClause+".")
			candidate.Set("subject", core.NewObject("type", "connection", "id", burst.key))
			candidate.Set("dedupeKey", threatDedupeKey("directory-mass-change", burst.key, burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{actions: true}))
			candidate.Set("metadata", threatBurstMetadata(directory.window(), burst, core.NewObject("deletions", float64(deletions))))
			run.add(candidate)
		}
	}

	impersonation, err := threatTunedRule(settings, "impersonation-burst")
	if err != nil {
		return err
	}
	if impersonation != nil {
		for _, burst := range threatFindBursts(ordered, fresh, historyFrom, impersonation.window(), threatCounter{
			key: func(event *core.Object) (string, bool) {
				actorID := threatEventText(event, "actorId")
				if event.Get("action") == "identity:impersonate" && event.Get("outcome") == "allow" && threatRecorded(event) &&
					threatIdentityActor(actorID) {
					return actorID, true
				}
				return "", false
			},
		}) {
			who, err := threatIdentitySubject(run, burst.key)
			if err != nil {
				return err
			}
			var resources []string
			for _, event := range burst.events {
				resources = append(resources, threatEventText(event, "resourceId"))
			}
			targets := threatDistinct(resources)
			title, err := threatTitled("impersonation-burst", who.label)
			if err != nil {
				return err
			}
			candidate := threatCandidate("impersonation-burst", impersonation.severity, title,
				who.label+" started "+threatPlural(burst.peak, "\"view as\" session", "")+" within "+threatInWords(impersonation.windowMs)+", as "+threatPlural(float64(len(targets)), "person", "people")+".")
			who.target(candidate)
			candidate.Set("dedupeKey", threatDedupeKey("impersonation-burst", burst.key, burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{identityIDs: targets}))
			candidate.Set("metadata", threatBurstMetadata(impersonation.window(), burst, core.NewObject("targets", float64(len(targets)))))
			run.add(candidate)
		}
	}

	denial, err := threatTunedRule(settings, "denial-burst")
	if err != nil {
		return err
	}
	if denial != nil {
		for _, burst := range threatFindBursts(ordered, fresh, historyFrom, denial.window(), threatCounter{
			key: func(event *core.Object) (string, bool) {
				responsible := threatResponsibleActor(event)
				if event.Get("outcome") == "deny" && !threatUnauthenticatedRefusals[threatEventText(event, "action")] &&
					threatIdentityActor(responsible) {
					return responsible, true
				}
				return "", false
			},
		}) {
			who, err := threatIdentitySubject(run, burst.key)
			if err != nil {
				return err
			}
			actions := threatDistinct(threatActions(burst.events))
			agentClause, agent := threatAgentInvolvement(who, burst.events)
			viewedClause, viewed := threatViewing(burst.events)
			title, err := threatTitled("denial-burst", who.label)
			if err != nil {
				return err
			}
			candidate := threatCandidate("denial-burst", denial.severity, title,
				who.label+agentClause+" was denied "+threatPlural(burst.peak, "time", "")+" within "+threatInWords(denial.windowMs)+", across "+threatPlural(float64(len(actions)), "action", "")+viewedClause+".")
			who.target(candidate)
			candidate.Set("dedupeKey", threatDedupeKey("denial-burst", burst.key, burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{actions: true}))
			candidate.Set("metadata", threatBurstMetadata(denial.window(), burst, agent, viewed))
			run.add(candidate)
		}
	}

	// Clearance refusals (mandatory access control) per responsible actor: someone reading up, or probing for what is
	// classified. The refusals' marker carries no label, so neither does the detection: it counts the resources only.
	classified, err := threatTunedRule(settings, "classified-access-attempts")
	if err != nil {
		return err
	}
	if classified != nil {
		for _, burst := range threatFindBursts(ordered, fresh, historyFrom, classified.window(), threatCounter{
			key: func(event *core.Object) (string, bool) {
				responsible := threatResponsibleActor(event)
				if threatMandatoryRefusal(event) && !threatUnauthenticatedRefusals[threatEventText(event, "action")] &&
					threatIdentityActor(responsible) {
					return responsible, true
				}
				return "", false
			},
		}) {
			who, err := threatIdentitySubject(run, burst.key)
			if err != nil {
				return err
			}
			var resourceIDs []string
			for _, event := range burst.events {
				resourceIDs = append(resourceIDs, threatEventText(event, "resourceId"))
			}
			resources := len(threatDistinct(resourceIDs))
			agentClause, agent := threatAgentInvolvement(who, burst.events)
			viewedClause, viewed := threatViewing(burst.events)
			title, err := threatTitled("classified-access-attempts", who.label)
			if err != nil {
				return err
			}
			candidate := threatCandidate("classified-access-attempts", classified.severity, title,
				who.label+agentClause+" was refused "+threatPlural(burst.peak, "time", "")+" for want of a clearance within "+threatInWords(classified.windowMs)+", on "+threatPlural(float64(resources), "classified resource", "")+viewedClause+".")
			who.target(candidate)
			candidate.Set("dedupeKey", threatDedupeKey("classified-access-attempts", burst.key, burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{actions: true}))
			candidate.Set("metadata", threatBurstMetadata(classified.window(), burst, core.NewObject("resources", float64(resources)), agent, viewed))
			run.add(candidate)
		}
	}

	recon, err := threatTunedRule(settings, "recon-burst")
	if err != nil {
		return err
	}
	if recon != nil {
		reads := threatFindBursts(ordered, fresh, historyFrom, recon.window(), threatCounter{
			key: func(event *core.Object) (string, bool) {
				action := threatEventText(event, "action")
				responsible := threatResponsibleActor(event)
				if event.Get("outcome") == "allow" && strings.HasPrefix(action, "iam:") && strings.HasSuffix(action, ":read") &&
					action != "iam:threats:read" && threatIdentityActor(responsible) {
					return responsible, true
				}
				return "", false
			},
		})
		for _, burst := range reads {
			who, err := threatIdentitySubject(run, burst.key)
			if err != nil {
				return err
			}
			viewedClause, viewed := threatViewing(burst.events)
			title, err := threatTitled("recon-burst", who.label)
			if err != nil {
				return err
			}
			candidate := threatCandidate("recon-burst", recon.severity, title,
				who.label+" made "+threatPlural(burst.peak, "administrative read", "")+" within "+threatInWords(recon.windowMs)+viewedClause+".")
			who.target(candidate)
			candidate.Set("dedupeKey", threatDedupeKey("recon-burst", burst.key, "reads", burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{actions: true}))
			candidate.Set("metadata", threatBurstMetadata(recon.window(), burst, core.NewObject("kind", "reads"), viewed))
			run.add(candidate)
		}
		exportWindow := threatWindow{
			threshold: math.Max(3, math.Floor(recon.threshold/50)),
			windowMs:  recon.windowMs,
		}
		exports := threatFindBursts(ordered, fresh, historyFrom, exportWindow, threatCounter{
			key: func(event *core.Object) (string, bool) {
				responsible := threatResponsibleActor(event)
				if event.Get("action") == "identity:export" && event.Get("outcome") == "allow" && threatRecorded(event) &&
					threatIdentityActor(responsible) {
					return responsible, true
				}
				return "", false
			},
		})
		for _, burst := range exports {
			who, err := threatIdentitySubject(run, burst.key)
			if err != nil {
				return err
			}
			var resources []string
			for _, event := range burst.events {
				resources = append(resources, threatEventText(event, "resourceId"))
			}
			exported := threatDistinct(resources)
			viewedClause, viewed := threatViewing(burst.events)
			title, err := threatTitled("recon-burst", who.label)
			if err != nil {
				return err
			}
			candidate := threatCandidate("recon-burst", recon.severity, title,
				who.label+" exported "+threatPlural(burst.peak, "identity", "identities")+" within "+threatInWords(recon.windowMs)+viewedClause+".")
			who.target(candidate)
			candidate.Set("dedupeKey", threatDedupeKey("recon-burst", burst.key, "exports", burst.anchor))
			candidate.Set("occurredAt", burst.lastAt)
			candidate.Set("evidence", threatEvidenceOf(run, burst.events, threatEvidenceExtra{identityIDs: exported, actions: true}))
			candidate.Set("metadata", threatBurstMetadata(exportWindow, burst, core.NewObject("kind", "exports", "exported", float64(len(exported))), viewed))
			run.add(candidate)
		}
	}
	return nil
}

func threatActions(events []*core.Object) []string {
	actions := make([]string, 0, len(events))
	for _, event := range events {
		actions = append(actions, threatEventText(event, "action"))
	}
	return actions
}

// ---------------------------------------------------------------------------------------------------------------
// Candidates

// threatNamed is an identity as a detection subject.
type threatNamed struct {
	identity *core.Object
	label    string
	id       string
}

// target sets the subject and, for an identity of this tenant, the identity whose risk the detection raises.
func (who *threatNamed) target(candidate *core.Object) {
	if who.identity != nil {
		candidate.Set("subject", core.NewObject("type", "identity", "id", who.id, "name", who.label))
		candidate.Set("identityId", who.id)
		return
	}
	candidate.Set("subject", core.NewObject("type", "identity", "id", who.id))
}

// threatIdentitySubject is an identity as a detection subject. Only identities of this tenant carry `identityId`
// (risk is kept in the identity's own tenant); an actor from another tenant or one since deleted is still the subject.
func threatIdentitySubject(run *threatRun, identityID string) (*threatNamed, error) {
	identity, err := run.identity(identityID)
	if err != nil {
		return nil, err
	}
	return &threatNamed{identity: identity, label: threatIdentityLabel(identity, identityID), id: identityID}, nil
}

type threatActorLabel struct {
	label      string
	identityID string
}

// threatActorOf is the actor of a tenant-level change: its name, and `identityId` when it is an identity of this
// tenant.
func threatActorOf(run *threatRun, actorID string) (*threatActorLabel, error) {
	var identity *core.Object
	if threatIdentityActor(actorID) {
		var err error
		identity, err = run.identity(actorID)
		if err != nil {
			return nil, err
		}
	}
	if identity != nil {
		return &threatActorLabel{label: threatIdentityLabel(identity, actorID), identityID: jsString(identity.Get("id"))}, nil
	}
	return &threatActorLabel{label: threatClean(actorID)}, nil
}

// IdentityLabel (threat-rules.ts identityLabel): How detections name an identity (subject names and summaries): name
// and email where it has both; its id when it is unknown. Detections the threats API records itself use it too.
func IdentityLabel(identity *core.Object, identityID string) (result string, err error) {
	return threatIdentityLabel(identity, identityID), nil
}

func threatIdentityLabel(identity *core.Object, identityID string) string {
	if identity == nil {
		return threatClean(identityID)
	}
	name := ""
	if value := identity.Get("name"); !nullish(value) {
		name = core.JSTrim(threatClean(jsString(value)))
	}
	email := ""
	if value := identity.Get("email"); truthy(value) {
		email = threatClean(jsString(value))
	}
	if name != "" && email != "" && name != email {
		return name + " (" + email + ")"
	}
	if email != "" {
		return email
	}
	if name != "" {
		return name
	}
	return threatClean(jsString(identity.Get("id")))
}

// threatReportedNetwork sets `network` for a reportable (untrusted) client network.
func threatReportedNetwork(run *threatRun, candidate *core.Object, network *threatClientNetwork) {
	if key, ok := threatReportableKey(run, network); ok {
		candidate.Set("network", key)
	}
}

type threatEvidenceExtra struct {
	identityIDs []string
	networks    []string
	actions     bool
}

// threatEvidenceOf is evidence for the events (oldest first): the last 20 ids, counts, span, and the networks the
// events came from.
func threatEvidenceOf(run *threatRun, events []*core.Object, extra threatEvidenceExtra) *core.Object {
	firstAt := math.Inf(1)
	lastAt := math.Inf(-1)
	for _, event := range events {
		firstAt = math.Min(firstAt, threatTime(event))
		lastAt = math.Max(lastAt, threatTime(event))
	}
	networks := threatLimited(append(threatReportableNetworks(run, events), extra.networks...))
	identityIDs := threatLimited(extra.identityIDs)
	var actions []string
	if extra.actions {
		actions = threatLimited(threatActions(events))
	}
	tail := events
	if len(tail) > threatEvidenceLimit {
		tail = tail[len(tail)-threatEvidenceLimit:]
	}
	eventIDs := make([]string, 0, len(tail))
	for _, event := range tail {
		eventIDs = append(eventIDs, threatEventText(event, "id"))
	}
	evidence := core.NewObject(
		"eventIds", eventIDs,
		"count", float64(len(events)),
		"firstAt", firstAt,
		"lastAt", lastAt,
	)
	if len(networks) > 0 {
		evidence.Set("networks", networks)
	}
	if len(identityIDs) > 0 {
		evidence.Set("identityIds", identityIDs)
	}
	if len(actions) > 0 {
		evidence.Set("actions", actions)
	}
	return evidence
}

// threatTexts reads an array of strings (non-strings skipped).
func threatTexts(value any) []string {
	var texts []string
	for _, item := range threatList(value) {
		if text, ok := item.(string); ok {
			texts = append(texts, text)
		}
	}
	return texts
}

// threatMerge folds another firing of a unique key already found in this run into the first one.
func threatMerge(into, other *core.Object) {
	a, _ := into.Get("evidence").(*core.Object)
	b, _ := other.Get("evidence").(*core.Object)
	if a == nil {
		a = core.NewObject()
	}
	if b == nil {
		b = core.NewObject()
	}
	networks := threatLimited(append(threatTexts(a.Get("networks")), threatTexts(b.Get("networks"))...))
	identityIDs := threatLimited(append(threatTexts(a.Get("identityIds")), threatTexts(b.Get("identityIds"))...))
	actions := threatLimited(append(threatTexts(a.Get("actions")), threatTexts(b.Get("actions"))...))
	eventIDs := threatDistinct(append(threatTexts(a.Get("eventIds")), threatTexts(b.Get("eventIds"))...))
	if len(eventIDs) > threatEvidenceLimit {
		eventIDs = eventIDs[len(eventIDs)-threatEvidenceLimit:]
	}
	evidence := core.NewObject(
		"eventIds", eventIDs,
		"count", jsNumber(a.Get("count"))+jsNumber(b.Get("count")),
		"firstAt", math.Min(jsNumber(a.Get("firstAt")), jsNumber(b.Get("firstAt"))),
		"lastAt", math.Max(jsNumber(a.Get("lastAt")), jsNumber(b.Get("lastAt"))),
	)
	if len(networks) > 0 {
		evidence.Set("networks", networks)
	}
	if len(identityIDs) > 0 {
		evidence.Set("identityIds", identityIDs)
	}
	if len(actions) > 0 {
		evidence.Set("actions", actions)
	}
	into.Set("evidence", evidence)
	into.Set("occurredAt", math.Max(threatNumber(into, "occurredAt"), threatNumber(other, "occurredAt")))
}

// threatDistinct is the distinct values in first-seen order.
func threatDistinct(values []string) []string {
	result := newOrderedSet()
	for _, value := range values {
		result.Add(value)
	}
	return result.Values()
}

// threatLimited is the distinct values in first-seen order, at most `evidenceLimit`.
func threatLimited(values []string) []string {
	result := newOrderedSet()
	for _, value := range values {
		result.Add(value)
		if result.Len() == threatEvidenceLimit {
			break
		}
	}
	return result.Values()
}

// threatDedupeKey is `{part}:{part}...` without control characters, short enough for `{ruleId}:{dedupeKey}` to fit a
// unique key.
func threatDedupeKey(ruleID string, parts ...any) string {
	texts := make([]string, len(parts))
	for index, part := range parts {
		switch value := part.(type) {
		case string:
			texts[index] = value
		case float64:
			texts[index] = core.NumberString(value)
		default:
			texts[index] = jsString(core.Normalize(value))
		}
	}
	return threatSliceUTF16(threatClean(strings.Join(texts, ":")), 0, threatUniqueKeyLimit-utf16Len(ruleID)-1)
}

// threatClean drops control characters (C0, DEL, C1) from text that reaches keys and summaries.
func threatClean(value string) string {
	clean := true
	for index := 0; index < len(value); {
		r, width := utf8.DecodeRuneInString(value[index:])
		if !(r == utf8.RuneError && width == 1) && (r < 32 || (r >= 127 && r <= 159)) {
			clean = false
			break
		}
		index += width
	}
	if clean {
		return value
	}
	var builder strings.Builder
	for index := 0; index < len(value); {
		r, width := utf8.DecodeRuneInString(value[index:])
		// Bytes that do not decode (WTF-8 unpaired surrogates) are kept: their code points lie above U+009F.
		if (r == utf8.RuneError && width == 1) || (r >= 32 && (r < 127 || r > 159)) {
			builder.WriteString(value[index : index+width])
		}
		index += width
	}
	return builder.String()
}

// threatSliceUTF16 is String.prototype.slice(start, end) over UTF-16 code units (end < 0: to the end).
func threatSliceUTF16(value string, start, end int) string {
	ascii := true
	for index := 0; index < len(value); index++ {
		if value[index] >= 0x80 {
			ascii = false
			break
		}
	}
	length := len(value)
	var units []uint16
	if !ascii {
		units = core.ToUTF16(value)
		length = len(units)
	}
	if end < 0 || end > length {
		end = length
	}
	if start > length {
		start = length
	}
	if start >= end {
		return ""
	}
	if ascii {
		return value[start:end]
	}
	return core.FromUTF16(units[start:end])
}

var threatLowerSeverity = map[string]string{
	"critical": "high",
	"high":     "medium",
	"medium":   "low",
	"low":      "low",
}

func threatStartOfDay(at float64) float64 {
	return math.Floor(at/threatDay) * threatDay
}

// threatTitled is a rule's title, followed by what the detection is about when that has a name.
func threatTitled(ruleID string, name string) (string, error) {
	definition, err := ThreatRule(ruleID)
	if err != nil {
		return "", err
	}
	title := jsString(definition.Get("title"))
	if name != "" {
		return title + ": " + name, nil
	}
	return title, nil
}

// threatPlural is `{count} {singular|plural}`; pluralForm "" means `{singular}s`.
func threatPlural(count float64, singular, pluralForm string) string {
	if pluralForm == "" {
		pluralForm = singular + "s"
	}
	if count == 1 {
		return core.NumberString(count) + " " + singular
	}
	return core.NumberString(count) + " " + pluralForm
}

// threatSeries is "a", "a and b", "a, b and c".
func threatSeries(items []string) string {
	if len(items) <= 1 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " and " + items[len(items)-1]
}

// threatInWords is a window length in words, in the largest whole unit that divides it.
func threatInWords(ms float64) string {
	if math.Mod(ms, threatDay) == 0 {
		return threatPlural(ms/threatDay, "day", "")
	}
	if math.Mod(ms, threatHour) == 0 {
		return threatPlural(ms/threatHour, "hour", "")
	}
	if math.Mod(ms, threatMinute) == 0 {
		return threatPlural(ms/threatMinute, "minute", "")
	}
	return threatAbout(ms)
}

// threatRound is Math.round (halves toward +Infinity).
func threatRound(value float64) float64 {
	return math.Floor(value + 0.5)
}

// threatAbout is an elapsed time in words, rounded to the largest unit it reaches.
func threatAbout(ms float64) string {
	if ms >= threatDay {
		return threatPlural(threatRound(ms/threatDay), "day", "")
	}
	if ms >= threatHour {
		return threatPlural(threatRound(ms/threatHour), "hour", "")
	}
	return threatPlural(math.Max(1, threatRound(ms/threatMinute)), "minute", "")
}
