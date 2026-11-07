package server

// Port of packages/server/src/delegations.ts. Delegations: a person lets an AI agent act on their behalf within a
// scope, for a limited time. The agent exchanges its own API key for a short delegated session (`delegations.assume`,
// kind `delegated`) whose identity is the person, so decisions use the person's grants, bounded by the delegation's
// scope, the agent's own ceiling, and any scope-down the agent asked for. Every use re-validates the whole chain: the
// delegation, the person, the agent, its sponsor and the agent key the session came from. Revoking a delegation ends
// its sessions at once.

import (
	"context"
	"math"
	"reflect"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"weak"

	"github.com/Better-IAM/better-iam/go/core"
)

// jsMathRound is Math.round: halves round toward +Infinity.
func jsMathRound(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return value
	}
	floor := math.Floor(value)
	if value-floor >= 0.5 {
		return floor + 1
	}
	return floor
}

// SpendSetting (delegations.ts spendSetting): Reads a `spend` setting: `{ period, maxTokens?, maxCostUsd?,
// maxRequests? }` with at least one limit. `null` means none (for clearing); `undefined` leaves the caller's choice
// alone (both answer nil here; callers only set a cap they were given).
func SpendSetting(value any) (result *core.Object, err error) {
	if nullish(value) {
		return nil, nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	period := input.Get("period")
	if period != "minute" && period != "hour" && period != "day" && period != "month" {
		return nil, invalidInput("spend.period must be 'minute', 'hour', 'day' or 'month'")
	}
	spend := core.NewObject("period", period)
	if maxTokens := input.Get("maxTokens"); !isUndefined(maxTokens) {
		tokens, err := Integer(maxTokens, "spend.maxTokens", 1, 1_000_000_000_000)
		if err != nil {
			return nil, err
		}
		spend.Set("maxTokens", tokens)
	}
	if maxCostUsd := input.Get("maxCostUsd"); !isUndefined(maxCostUsd) {
		// At least one micro-dollar: a smaller cap would round to zero and refuse every call.
		usd, ok := core.Normalize(maxCostUsd).(float64)
		if !ok || math.IsNaN(usd) || math.IsInf(usd, 0) || usd < 0.000001 || usd > 1_000_000 {
			return nil, invalidInput("spend.maxCostUsd must be at least 0.000001 and at most 1000000")
		}
		spend.Set("maxCostMicros", jsMathRound(usd*1_000_000))
	}
	if maxRequests := input.Get("maxRequests"); !isUndefined(maxRequests) {
		requests, err := Integer(maxRequests, "spend.maxRequests", 1, 1_000_000_000)
		if err != nil {
			return nil, err
		}
		spend.Set("maxRequests", requests)
	}
	if !spend.Has("maxTokens") && !spend.Has("maxCostMicros") && !spend.Has("maxRequests") {
		return nil, invalidInput("spend needs maxTokens, maxCostUsd or maxRequests")
	}
	return spend, nil
}

// HandoffLimits is delegations.ts handoffLimits: the deepest chain below a person's own delegation, live hand-offs per
// delegation, and the agents a hand-off setting may name.
var HandoffLimits = struct {
	MaxDepth  float64
	MaxLive   float64
	MaxAgents float64
}{3, 20, 20}

// ConfirmationLimits is delegations.ts confirmationLimits: how long the person has to decide a confirmation request,
// and how long an approval lasts.
var ConfirmationLimits = struct {
	DecideMs             float64
	MinValidSeconds      float64
	MaxValidSeconds      float64
	FallbackValidSeconds float64
}{1800000, 30, 3600, 300}

// ConfirmationKey (delegations.ts confirmationKey): the key a confirmation opens: an action on a resource.
func ConfirmationKey(action string, resourceType string, resourceID string) string {
	return action + "|" + resourceType + "/" + resourceID
}

// NeedsConfirmation reports whether a delegation requires the person's confirmation for an action
// (delegations.ts needsConfirmation).
func NeedsConfirmation(delegation *core.Object, action string) bool {
	patterns, _ := delegation.Get("confirm").([]any)
	for _, pattern := range patterns {
		if core.MatchPattern(jsString(pattern), action, nil) {
			return true
		}
	}
	return false
}

var confirmPatternSyntax = regexp.MustCompile(`^[A-Za-z0-9*?][A-Za-z0-9:_*?.-]{0,127}$`)

// ConfirmPatterns (delegations.ts confirmPatterns): Reads a `confirm` list: action patterns (wildcards allowed), at
// most 50; an empty list means none (nil).
func ConfirmPatterns(value any) (result []string, err error) {
	if isUndefined(value) {
		return nil, nil
	}
	list, err := Strings(value, "confirm")
	if err != nil {
		return nil, err
	}
	patterns := unique(list)
	if len(patterns) > 50 {
		return nil, invalidInput("confirm may list at most 50 actions")
	}
	for _, pattern := range patterns {
		if !confirmPatternSyntax.MatchString(pattern) {
			return nil, invalidInput("Invalid action pattern " + pattern)
		}
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	return patterns, nil
}

// usedConfirmations is delegations.ts usedIn: approvals used inside a transaction still open their call for the rest
// of it (one operation may check the same action more than once); keyed by the transaction handle (held weakly, as the
// TypeScript WeakMap holds it), so they end with it.
type usedConfirmations struct {
	mu   sync.Mutex
	sets map[weak.Pointer[byte]]map[string]bool
}

var usedIn = &usedConfirmations{sets: map[weak.Pointer[byte]]map[string]bool{}}

// handle is the weak key of a transaction handle; ok is false for a handle that is not a pointer (no memory kept).
func (u *usedConfirmations) handle(tx core.IamStore) (key weak.Pointer[byte], target *byte, ok bool) {
	value := reflect.ValueOf(tx)
	if !value.IsValid() || value.Kind() != reflect.Pointer || value.IsNil() {
		return key, nil, false
	}
	target = (*byte)(value.UnsafePointer())
	return weak.Make(target), target, true
}

// get is usedIn.get(tx): the approvals used in this transaction (nil for none).
func (u *usedConfirmations) get(tx core.IamStore) map[string]bool {
	key, _, ok := u.handle(tx)
	if !ok {
		return nil
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.sets[key]
}

// add records an approval used in this transaction (usedIn.set(tx, used.add(id))).
func (u *usedConfirmations) add(tx core.IamStore, id string) {
	key, target, ok := u.handle(tx)
	if !ok {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	used, exists := u.sets[key]
	if !exists {
		used = map[string]bool{}
		u.sets[key] = used
		runtime.AddCleanup(target, func(key weak.Pointer[byte]) {
			u.mu.Lock()
			defer u.mu.Unlock()
			delete(u.sets, key)
		}, key)
	}
	used[id] = true
}

// ApprovedConfirmations (delegations.ts approvedConfirmations): The approved, unexpired (and not yet used)
// confirmations of a delegation, as the keys they open.
func ApprovedConfirmations(ctx context.Context, tx core.IamStore, delegation *core.Object, now int64) (result map[string]bool, err error) {
	keys := map[string]bool{}
	used := usedIn.get(tx)
	found, err := tx.Find(ctx, "delegationConfirmations", core.NewObject(
		"tenantId", delegation.Get("tenantId"), "delegationId", delegation.Get("id"),
	), nil)
	if err != nil {
		return nil, err
	}
	for _, confirmation := range found {
		status := confirmation.Get("status")
		if (status == "approved" && jsNumber(confirmation.Get("expiresAt")) > float64(now)) ||
			(status == "used" && used[jsString(confirmation.Get("id"))]) {
			keys[ConfirmationKey(jsString(confirmation.Get("action")), jsString(confirmation.Get("resourceType")),
				jsString(confirmation.Get("resourceId")))] = true
		}
	}
	return keys, nil
}

// UseConfirmation (delegations.ts useConfirmation): Uses up the person's approval behind an allowed call of a
// delegated session, so each approval opens exactly one call ("confirm one call at a time"): called by a one-shot
// decision inside its transaction, it marks the matching approval `used` (rolled back with a refused operation).
// Actions the delegation does not hold back, and other sessions, are left alone.
var UseConfirmation = func(ctx context.Context, tx core.IamStore, principal *Principal, action, resourceType, resourceID string, now int64) error {
	session := principal.Session
	if session.Get("kind") != "delegated" {
		return nil
	}
	delegationID, ok := session.String("delegationId")
	if !ok {
		return nil
	}
	delegation, err := tx.Get(ctx, "delegations", delegationID)
	if err != nil || delegation == nil || !NeedsConfirmation(delegation, action) {
		return err
	}
	used := usedIn.get(tx)
	found, err := tx.Find(ctx, "delegationConfirmations", core.NewObject(
		"tenantId", delegation.Get("tenantId"), "delegationId", delegation.Get("id"),
	), nil)
	if err != nil {
		return err
	}
	matching := []*core.Object{}
	for _, item := range found {
		if item.Get("action") == action && item.Get("resourceType") == resourceType && item.Get("resourceId") == resourceID {
			matching = append(matching, item)
		}
	}
	// Already used earlier in this very transaction: the same call checked again.
	for _, item := range matching {
		if item.Get("status") == "used" && used[jsString(item.Get("id"))] {
			return nil
		}
	}
	approvals := []*core.Object{}
	for _, item := range matching {
		if item.Get("status") == "approved" && jsNumber(item.Get("expiresAt")) > float64(now) {
			approvals = append(approvals, item)
		}
	}
	if len(approvals) == 0 {
		return nil
	}
	slices.SortStableFunc(approvals, func(a, b *core.Object) int {
		difference := jsNumber(a.Get("expiresAt")) - jsNumber(b.Get("expiresAt"))
		switch {
		case difference < 0:
			return -1
		case difference > 0:
			return 1
		}
		return 0
	})
	approval := approvals[0]
	if _, err := tx.Put(ctx, "delegationConfirmations", approval.Spread(core.NewObject(
		"status", "used", "usedAt", float64(now),
	))); err != nil {
		return err
	}
	usedIn.add(tx, jsString(approval.Get("id")))
	return nil
}

// DelegationLifetime is delegations.ts delegationLifetime: bounds of a delegation's lifetime and of a pending request.
var DelegationLifetime = struct {
	MinSeconds      float64
	MaxSeconds      float64
	FallbackSeconds float64
	RequestMs       float64
}{300, 31536000, 2592000, 604800000}

// MaxSessionsPerDelegation is delegations.ts maxSessionsPerDelegation: live delegated sessions one delegation may hold
// at a time.
const MaxSessionsPerDelegation = 20

const delegationScopeSid = "DelegationScopes"

// delegationScopesPolicy (delegations.ts delegationScopesPolicy): a scope given as actions compiles to an allow on
// every resource; the person's own grants still decide.
func delegationScopesPolicy(scopes []string) *core.Object {
	return core.NewObject(
		"version", 1.0,
		"statements", []any{core.NewObject(
			"sid", delegationScopeSid, "effect", "allow", "actions", stringsOf(scopes), "resources", []any{"*"},
		)},
	)
}

// DelegationScope (delegations.ts delegationScope): Reads a delegation scope: `scopes` (an action list, wildcards
// allowed) or a `policy` document, exactly one of them, validated against the tenant's catalog. The scope only ever
// narrows: the delegated session acts with the person's grants, and this becomes one more ceiling over them. The
// result is `{ policy, scopes? }`.
func DelegationScope(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object) (result *core.Object, err error) {
	scopesValue, policyValue := input.Get("scopes"), input.Get("policy")
	if isUndefined(scopesValue) == isUndefined(policyValue) {
		return nil, invalidInput("Provide either scopes or a policy")
	}
	if !isUndefined(scopesValue) {
		list, err := Strings(scopesValue, "scopes")
		if err != nil {
			return nil, err
		}
		scopes := unique(list)
		if len(scopes) == 0 {
			return nil, invalidInput("scopes must name at least one action")
		}
		policy := delegationScopesPolicy(scopes)
		if err := server.Catalog.Validate(ctx, tx, tenantID, policy); err != nil {
			return nil, err
		}
		return core.NewObject("policy", policy, "scopes", stringsOf(scopes)), nil
	}
	policy, err := Object(policyValue)
	if err != nil {
		return nil, err
	}
	if err := server.Catalog.Validate(ctx, tx, tenantID, policy); err != nil {
		return nil, err
	}
	return core.NewObject("policy", policy), nil
}

// DelegationSeconds (delegations.ts delegationSeconds): A delegation lifetime in seconds (`expiresInSeconds`),
// within bounds; the fallback is 30 days.
func DelegationSeconds(value any) (result float64, err error) {
	if isUndefined(value) {
		return DelegationLifetime.FallbackSeconds, nil
	}
	return Integer(value, "expiresInSeconds", DelegationLifetime.MinSeconds, DelegationLifetime.MaxSeconds)
}

// globEnds is the literal text of a glob before its first wildcard and after its last one.
func globEnds(pattern string) (string, string) {
	first := strings.IndexAny(pattern, "*?")
	if first == -1 {
		return pattern, pattern
	}
	last := strings.LastIndexAny(pattern, "*?")
	return pattern[:first], pattern[last+1:]
}

// ActionsMayOverlap (delegations.ts actionsMayOverlap): Whether some action could match both action patterns
// (conservative: true unless their literal ends disagree).
func ActionsMayOverlap(pattern string, scope string) (result bool, err error) {
	if strings.Contains(pattern, "${") {
		return true, nil
	}
	if !strings.Contains(scope, "*") {
		return core.MatchPattern(pattern, scope, nil), nil
	}
	prefixA, suffixA := globEnds(pattern)
	prefixB, suffixB := globEnds(scope)
	return (strings.HasPrefix(prefixA, prefixB) || strings.HasPrefix(prefixB, prefixA)) &&
		(strings.HasSuffix(suffixA, suffixB) || strings.HasSuffix(suffixB, suffixA)), nil
}

// actionsOverlap is ActionsMayOverlap without the (always nil) error.
func actionsOverlap(pattern, scope string) bool {
	overlap, _ := ActionsMayOverlap(pattern, scope)
	return overlap
}

// policyStatements is `document.statements` of a policy document (nothing for anything else).
func policyStatements(document any) []*core.Object {
	list, _ := member(document, "statements").([]any)
	statements := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if statement, ok := item.(*core.Object); ok && statement != nil {
			statements = append(statements, statement)
		}
	}
	return statements
}

// stringItems is the items of an array member as strings (String(item)); nothing for a non-array.
func stringItems(value any) []string {
	list, _ := value.([]any)
	items := make([]string, len(list))
	for index, item := range list {
		items[index] = jsString(item)
	}
	return items
}

// ownKeyCount is Object.keys(value).length for a truthy value.
func ownKeyCount(value any) int {
	switch v := value.(type) {
	case *core.Object:
		return v.Len()
	case []any:
		return len(v)
	case string:
		return utf16Len(v)
	}
	return 0
}

// PolicyAllowsScope (delegations.ts policyAllowsScope): Whether a policy document allows a whole scope (an action or
// a `*` pattern of actions) outright: some statement allows every action it covers on every resource without
// conditions, and no deny statement could touch any of them. Conservative by design: a document that allows the
// scope only for some resources or under conditions does not count.
func PolicyAllowsScope(document *core.Object, scope string) (result bool, err error) {
	return policyAllowsScope(document, scope), nil
}

func policyAllowsScope(document any, scope string) bool {
	allowed := false
	for _, statement := range policyStatements(document) {
		actions := stringItems(statement.Get("actions"))
		if statement.Get("effect") == "deny" {
			for _, pattern := range actions {
				if actionsOverlap(pattern, scope) {
					return false
				}
			}
			continue
		}
		if conditions := statement.Get("conditions"); truthy(conditions) && ownKeyCount(conditions) > 0 {
			continue
		}
		if !slices.Contains(stringItems(statement.Get("resources")), "*") {
			continue
		}
		// A pattern covers a `*` scope only when its own wildcards are `*` (a `?` or a variable would match less).
		for _, pattern := range actions {
			if (!strings.Contains(scope, "*") || !(strings.Contains(pattern, "?") || strings.Contains(pattern, "${"))) &&
				core.MatchPattern(pattern, scope, nil) {
				allowed = true
				break
			}
		}
	}
	return allowed
}

// DelegationLive (delegations.ts delegationLive): Whether a delegation lets its agent act right now.
func DelegationLive(delegation *core.Object, now int64) (result bool, err error) {
	return delegationLive(delegation, now), nil
}

func delegationLive(delegation *core.Object, now int64) bool {
	return delegation.Get("status") == "active" && jsNumber(delegation.Get("expiresAt")) > float64(now)
}

// DelegationPending (delegations.ts delegationPending): Whether a request still waits for the person's decision.
func DelegationPending(delegation *core.Object, now int64) (result bool, err error) {
	return delegationPending(delegation, now), nil
}

func delegationPending(delegation *core.Object, now int64) bool {
	return delegation.Get("status") == "pending" && jsNumber(delegation.Get("expiresAt")) > float64(now)
}

// HandoffSetting (delegations.ts handoffSetting): Reads a `handoff` setting: `{ agents?, depth? }` with agents of
// the tenant (at most 20) and a depth of 1 to 3 (1 by default). `null` means none (for clearing); `undefined` leaves
// the caller's choice alone (both answer nil here).
func HandoffSetting(ctx context.Context, tx core.IamStore, tenantID string, value any) (result *core.Object, err error) {
	if nullish(value) {
		return nil, nil
	}
	input, err := Object(value)
	if err != nil {
		return nil, err
	}
	depth := 1.0
	if raw := input.Get("depth"); !isUndefined(raw) {
		if depth, err = Integer(raw, "handoff.depth", 1, HandoffLimits.MaxDepth); err != nil {
			return nil, err
		}
	}
	if isUndefined(input.Get("agents")) {
		return core.NewObject("depth", depth), nil
	}
	list, err := Strings(input.Get("agents"), "handoff.agents")
	if err != nil {
		return nil, err
	}
	agents := unique(list)
	if len(agents) == 0 || float64(len(agents)) > HandoffLimits.MaxAgents {
		return nil, invalidInput("handoff.agents must name 1 to " + strconv.Itoa(int(HandoffLimits.MaxAgents)) + " agents")
	}
	for _, agentID := range agents {
		agent, err := tx.Get(ctx, "identities", agentID)
		if err != nil {
			return nil, err
		}
		if agent == nil || agent.Get("kind") != "agent" || agent.Get("tenantId") != tenantID {
			return nil, invalidInput("handoff.agents: " + agentID + " is not an agent of this tenant")
		}
	}
	return core.NewObject("agents", stringsOf(agents), "depth", depth), nil
}

// DelegationAncestor is one delegation above a hand-off and its agent (nil slice from DelegationAncestors: a link is
// broken).
type DelegationAncestor struct {
	Delegation *core.Object
	Agent      *core.Object
}

// DelegationAncestors (delegations.ts delegationAncestors): The delegations above a hand-off, nearest first, when
// every one of them is live and names the same person, and its agent is an agent of the tenant that still accepts
// delegation. Nil when any link is broken (the hand-off may not be used). A delegation the person gave directly has
// no ancestors (an empty, non-nil slice). `liveAncestors` also checks each agent's standing.
func DelegationAncestors(ctx context.Context, tx core.IamStore, delegation *core.Object, now int64) (result []DelegationAncestor, err error) {
	ancestors := []DelegationAncestor{}
	seen := map[string]bool{jsString(delegation.Get("id")): true}
	current := delegation
	for !isUndefined(current.Get("parentId")) {
		if float64(len(ancestors)) >= HandoffLimits.MaxDepth {
			return nil, nil
		}
		parent, err := tx.Get(ctx, "delegations", jsString(current.Get("parentId")))
		if err != nil {
			return nil, err
		}
		if parent == nil || seen[jsString(parent.Get("id"))] || !delegationLive(parent, now) ||
			!core.StrictEquals(parent.Get("tenantId"), delegation.Get("tenantId")) ||
			!core.StrictEquals(parent.Get("subjectId"), delegation.Get("subjectId")) {
			return nil, nil
		}
		agent, err := tx.Get(ctx, "identities", jsString(parent.Get("agentId")))
		if err != nil {
			return nil, err
		}
		if agent == nil || agent.Get("kind") != "agent" || !core.StrictEquals(agent.Get("tenantId"), delegation.Get("tenantId")) ||
			member(agent.Get("agent"), "delegable") == false {
			return nil, nil
		}
		// The key the handing agent acted with must still be one of its live API keys.
		if keyID := current.Get("keyId"); !isUndefined(keyID) {
			key, err := tx.Get(ctx, "sessions", jsString(keyID))
			if err != nil {
				return nil, err
			}
			if key == nil || key.Get("kind") != "api-key" || !core.StrictEquals(key.Get("identityId"), agent.Get("id")) ||
				jsNumber(key.Get("expiresAt")) <= float64(now) {
				return nil, nil
			}
		}
		ancestors = append(ancestors, DelegationAncestor{Delegation: parent, Agent: agent})
		seen[jsString(parent.Get("id"))] = true
		current = parent
	}
	return ancestors, nil
}

// LiveAncestors (delegations.ts liveAncestors): `delegationAncestors`, with every agent above also in good standing
// (itself and its sponsor active). Nil when a link is broken.
func LiveAncestors(ctx context.Context, server *ServerContext, tx core.IamStore, delegation *core.Object, now int64) (result []DelegationAncestor, err error) {
	ancestors, err := DelegationAncestors(ctx, tx, delegation, now)
	if err != nil || ancestors == nil {
		return nil, err
	}
	for _, ancestor := range ancestors {
		// try { ... } catch { return undefined; }: any failure counts as a broken link.
		if err := AssertAgentUsable(ctx, server, tx, ancestor.Agent); err != nil {
			return nil, nil
		}
	}
	return ancestors, nil
}

// revokedDelegation is `{ ...delegation, status: 'revoked', revokedAt, revokedBy, sessionsRevokedBefore: now + 1 }`.
func revokedDelegation(delegation *core.Object, revokedBy string, now int64) *core.Object {
	return delegation.Spread(core.NewObject(
		"status", "revoked", "revokedAt", float64(now), "revokedBy", revokedBy, "sessionsRevokedBefore", float64(now)+1,
	))
}

// RevokeHandoffsBelow (delegations.ts revokeHandoffsBelow): Revokes every live hand-off below a delegation (at any
// depth) and deletes their sessions, recording `revokedBy`. Returns how many were revoked. Their use is refused
// anyway once a delegation above them ends; this keeps their records honest.
func RevokeHandoffsBelow(ctx context.Context, tx core.IamStore, delegation *core.Object, revokedBy string, now int64) (result float64, err error) {
	revoked := 0.0
	pending := []string{jsString(delegation.Get("id"))}
	seen := map[string]bool{pending[0]: true}
	for len(pending) > 0 {
		parentID := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		children, err := tx.Find(ctx, "delegations", core.NewObject("tenantId", delegation.Get("tenantId"), "parentId", parentID), nil)
		if err != nil {
			return 0, err
		}
		for _, child := range children {
			childID := jsString(child.Get("id"))
			if seen[childID] {
				continue
			}
			seen[childID] = true
			// An ended hand-off's own hand-offs ended with it; only live ones are followed down.
			if status := child.Get("status"); status != "active" && status != "pending" {
				continue
			}
			pending = append(pending, childID)
			if _, err := tx.Put(ctx, "delegations", revokedDelegation(child, revokedBy, now)); err != nil {
				return 0, err
			}
			if _, err := DeleteDelegatedSessions(ctx, tx, core.NewObject("delegationId", childID)); err != nil {
				return 0, err
			}
			revoked++
		}
	}
	return revoked, nil
}

// CheckDelegatedSession (delegations.ts checkDelegatedSession): The checks a delegated session passes on every use:
// its delegation is active, unexpired, and names this person and agent in this tenant, and was not revoked after the
// session began; the person is an active person of the tenant; the agent is an agent in good standing (itself and
// its sponsor active) that still accepts delegation; and the agent key the session came from is re-validated under
// its own rules (`revalidate`). Anything else is a 401.
func CheckDelegatedSession(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, session *core.Object, revalidate func(context.Context, *Principal) (*Principal, error)) (err error) {
	revoked := func() error { return core.NewIamError("UNAUTHENTICATED", "Delegation revoked", 401) }
	now := server.Now()
	var delegation, agent, source *core.Object
	if delegationID, ok := session.String("delegationId"); ok {
		if delegation, err = tx.Get(ctx, "delegations", delegationID); err != nil {
			return err
		}
	}
	if agentID, ok := session.String("agentId"); ok {
		if agent, err = tx.Get(ctx, "identities", agentID); err != nil {
			return err
		}
	}
	if sourceID, ok := session.String("sourceSessionId"); ok {
		if source, err = tx.Get(ctx, "sessions", sourceID); err != nil {
			return err
		}
	}
	if delegation == nil ||
		!delegationLive(delegation, now) ||
		!core.StrictEquals(delegation.Get("tenantId"), session.Get("tenantId")) ||
		!core.StrictEquals(delegation.Get("subjectId"), identity.Get("id")) ||
		!core.StrictEquals(delegation.Get("agentId"), session.Get("agentId")) ||
		RevokedByWatermark(jsNumber(session.Get("createdAt")), delegation.Get("sessionsRevokedBefore")) ||
		jsNumber(session.Get("expiresAt")) > jsNumber(delegation.Get("expiresAt")) ||
		identity.Get("kind") != "user" ||
		!core.StrictEquals(identity.Get("tenantId"), session.Get("tenantId")) ||
		agent == nil ||
		agent.Get("kind") != "agent" ||
		!core.StrictEquals(agent.Get("tenantId"), session.Get("tenantId")) ||
		member(agent.Get("agent"), "delegable") == false ||
		source == nil ||
		source.Get("kind") != "api-key" ||
		!core.StrictEquals(source.Get("identityId"), agent.Get("id")) ||
		!core.StrictEquals(source.Get("tenantId"), session.Get("tenantId")) ||
		jsNumber(session.Get("expiresAt")) > jsNumber(source.Get("expiresAt")) ||
		// The session carries the key's issuer authority (a ceiling in decisions); it must still be the key's.
		!core.StrictEquals(session.Get("credentialAuthorityId"), source.Get("credentialAuthorityId")) {
		return revoked()
	}
	if err := AssertAgentUsable(ctx, server, tx, agent); err != nil {
		return err
	}
	// A hand-off works only while every delegation above it does, with its agents in good standing.
	if !isUndefined(delegation.Get("parentId")) {
		ancestors, err := LiveAncestors(ctx, server, tx, delegation, now)
		if err != nil {
			return err
		}
		if ancestors == nil {
			return revoked()
		}
	}
	_, err = revalidate(ctx, &Principal{Identity: agent, Session: source})
	return err
}

// DeleteDelegatedSessions (delegations.ts deleteDelegatedSessions): Deletes the live delegated sessions of a
// delegation (or of every delegation of an agent); returns the count. filter is `{ delegationId }` or `{ agentId }`.
func DeleteDelegatedSessions(ctx context.Context, tx core.IamStore, filter *core.Object) (result float64, err error) {
	deleted := 0.0
	rows, err := tx.Find(ctx, "sessions", core.NewObject("kind", "delegated").Assign(filter), nil)
	if err != nil {
		return 0, err
	}
	for _, session := range rows {
		if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
			return 0, err
		}
		deleted++
	}
	return deleted, nil
}

// RevokeDelegationsOf (delegations.ts revokeDelegationsOf): Ends every delegation that involves an identity (as the
// agent or as the person) and their sessions: used when an identity is deleted. Records stay as `revoked` for the
// audit trail. Returns the number of delegations ended.
func RevokeDelegationsOf(ctx context.Context, server *ServerContext, tx core.IamStore, identity *core.Object, revokedBy string) (result float64, err error) {
	now := server.Now()
	ended := 0.0
	asAgent, err := tx.Find(ctx, "delegations", core.NewObject("tenantId", identity.Get("tenantId"), "agentId", identity.Get("id")), nil)
	if err != nil {
		return 0, err
	}
	asSubject, err := tx.Find(ctx, "delegations", core.NewObject("tenantId", identity.Get("tenantId"), "subjectId", identity.Get("id")), nil)
	if err != nil {
		return 0, err
	}
	found := append(append([]*core.Object{}, asAgent...), asSubject...)
	for _, delegation := range found {
		if status := delegation.Get("status"); status != "active" && status != "pending" {
			continue
		}
		if _, err := tx.Put(ctx, "delegations", revokedDelegation(delegation, revokedBy, now)); err != nil {
			return 0, err
		}
		if _, err := DeleteDelegatedSessions(ctx, tx, core.NewObject("delegationId", delegation.Get("id"))); err != nil {
			return 0, err
		}
		ended++
	}
	// Hand-offs below the ended delegations end with them.
	for _, delegation := range found {
		revoked, err := RevokeHandoffsBelow(ctx, tx, delegation, revokedBy, now)
		if err != nil {
			return 0, err
		}
		ended += revoked
	}
	return ended, nil
}
