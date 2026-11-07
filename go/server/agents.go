package server

// Port of packages/server/src/agents.ts: AI agents as accounts. An agent is an identity of kind `agent`: a machine
// account like a service account (API keys, no sign-in) that always has a sponsor, the person accountable for it. Its
// credentials work only while the sponsor is an active, unexpired person of the same tenant, and every decision it
// takes part in is bounded by the agent's own ceiling (AgentProfile.boundary).

import (
	"context"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// AgentSessionSeconds are the default and bounds of AgentProfile.maxDelegatedSessionSeconds.
var AgentSessionSeconds = struct {
	Min      float64
	Max      float64
	Fallback float64
}{60, 43_200, 3_600}

// pathChars are URI path characters (RFC 3986 pchar and `/`); `*` among them is a wildcard in audience patterns.
const pathChars = `[A-Za-z0-9\-._~!$&'()*+,;=:@%/]`

// httpAudience: scheme, host (a pattern may start it with `*.`), optional port, optional path (case-insensitive).
var httpAudience = regexp.MustCompile(`(?i)^(https?)://(\*\.)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)(:\d{1,5})?(/` + pathChars + `*)?$`)

// otherAudienceBody is any other absolute URI after the `(?!https?:)` check, such as `urn:example:api`.
var otherAudienceBody = regexp.MustCompile(`(?i)^[A-Za-z][A-Za-z0-9+.-]*:` + pathChars + `{1,500}$`)

var httpSchemePrefix = regexp.MustCompile(`(?i)^https?:`)

func otherAudience(value string) bool {
	return !httpSchemePrefix.MatchString(value) && otherAudienceBody.MatchString(value)
}

// globMatch is glob matching where only `*` is special, without regular-expression backtracking.
func globMatch(pattern, value string) bool {
	p, v, star, retry := 0, 0, -1, 0
	pu, vu := core.ToUTF16(pattern), core.ToUTF16(value)
	for v < len(vu) {
		if p < len(pu) && pu[p] != '*' && pu[p] == vu[v] {
			p++
			v++
		} else if p < len(pu) && pu[p] == '*' {
			star = p
			p++
			retry = v
		} else if star != -1 {
			p = star + 1
			retry++
			v = retry
		} else {
			return false
		}
	}
	for p < len(pu) && pu[p] == '*' {
		p++
	}
	return p == len(pu)
}

// AudienceMatches reports whether a token audience pattern matches a requested audience: for http(s) patterns the
// scheme and port must be equal, the host equal (case-insensitively) or a subdomain of a `*.` pattern, and the path
// must match with `*` as a wildcard; other URIs match as a whole, with `*`.
func AudienceMatches(pattern, audience string) bool {
	if utf16Len(audience) > 512 {
		return false
	}
	if wanted := httpAudience.FindStringSubmatch(pattern); wanted != nil {
		given := httpAudience.FindStringSubmatch(audience)
		if given == nil || given[2] != "" || strings.Contains(audience, "*") {
			return false
		}
		if core.JSLower(wanted[1]) != core.JSLower(given[1]) {
			return false
		}
		host, base := core.JSLower(given[3]), core.JSLower(wanted[3])
		if wanted[2] != "" {
			if !strings.HasSuffix(host, "."+base) {
				return false
			}
		} else if host != base {
			return false
		}
		if wanted[4] != given[4] {
			return false
		}
		wantedPath, givenPath := wanted[5], given[5]
		if wantedPath == "" {
			wantedPath = "/"
		}
		if givenPath == "" {
			givenPath = "/"
		}
		return globMatch(wantedPath, givenPath)
	}
	return !httpAudience.MatchString(audience) && otherAudience(audience) && globMatch(pattern, audience)
}

func audienceSyntax(value string, patterns bool) bool {
	if utf16Len(value) > 512 || (!patterns && strings.Contains(value, "*")) {
		return false
	}
	return httpAudience.MatchString(value) || otherAudience(value)
}

// TokenAudienceList reads a list of token audiences (at most 16) for field ("" means tokenAudiences).
func TokenAudienceList(value any, field string) ([]string, error) {
	if field == "" {
		field = "tokenAudiences"
	}
	items, err := Strings(value, field)
	if err != nil {
		return nil, err
	}
	list := unique(items)
	invalid := len(list) > 16
	for _, item := range list {
		if !audienceSyntax(item, true) {
			invalid = true
		}
	}
	if invalid {
		return nil, invalidInput(field + " must list at most 16 absolute URIs (such as https://api.example.com, https://*.example.com or urn:example:api)")
	}
	sortStable(list, compareUTF16)
	return list, nil
}

// TokenAudience reads one requested token audience: an http(s) URL or other absolute URI, without `*`.
func TokenAudience(value any) (string, error) {
	audience, err := Text(value, "audience", 512)
	if err != nil {
		return "", err
	}
	if !audienceSyntax(audience, false) {
		return "", invalidInput("audience must name one service: an http(s) URL without user info, query, fragment or *, or another absolute URI")
	}
	return audience, nil
}

var (
	modelPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$`)
	providerPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	protocolPattern = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,31}$`)
)

// MachineIdentity reports machine accounts: service accounts and agents. They hold API keys and never sign in.
func MachineIdentity(identity *core.Object) bool {
	kind := identity.Get("kind")
	return kind == "service" || kind == "agent"
}

// AgentProfile validates profile fields (an AgentProfileInput model value) over previous (a stored profile, or a
// fresh one with only the sponsor). Policy documents are checked against the tenant's catalog; unknown keys are
// ignored. Returns a new profile object.
func AgentProfile(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object, previous *core.Object) (*core.Object, error) {
	next := previous.Spread()
	optional := func(key string, read func(value any) (any, error)) error {
		value := input.Get(key)
		if isUndefined(value) {
			return nil
		}
		if value == nil {
			next.Delete(key)
			return nil
		}
		validated, err := read(value)
		if err != nil {
			return err
		}
		next.Set(key, validated)
		return nil
	}
	if err := optional("model", func(value any) (any, error) {
		text, ok := value.(string)
		if !ok || !modelPattern.MatchString(text) {
			return nil, invalidInput("model must be 1-128 letters, digits or ._:/@+- characters")
		}
		return text, nil
	}); err != nil {
		return nil, err
	}
	if err := optional("provider", func(value any) (any, error) {
		text, ok := value.(string)
		if !ok || !providerPattern.MatchString(text) {
			return nil, invalidInput("provider must be 1-64 letters, digits or ._- characters")
		}
		return core.JSLower(text), nil
	}); err != nil {
		return nil, err
	}
	if err := optional("purpose", func(value any) (any, error) { return Text(value, "purpose", 1024) }); err != nil {
		return nil, err
	}
	if err := optional("url", func(value any) (any, error) {
		url, err := Text(value, "url", 2048)
		if err != nil {
			return nil, err
		}
		parsed, err := auth.ParseFetchURL(url)
		if err != nil || (parsed.Protocol != "https:" && parsed.Protocol != "http:") {
			return nil, invalidInput("url must be an http(s) URL")
		}
		return url, nil
	}); err != nil {
		return nil, err
	}
	if err := optional("protocols", func(value any) (any, error) {
		items, err := Strings(value, "protocols")
		if err != nil {
			return nil, err
		}
		lowered := make([]string, len(items))
		for index, item := range items {
			lowered[index] = core.JSLower(item)
		}
		list := unique(lowered)
		invalid := len(list) > 16
		for _, item := range list {
			if !protocolPattern.MatchString(item) {
				invalid = true
			}
		}
		if invalid {
			return nil, invalidInput("protocols must list at most 16 short lowercase names")
		}
		sortStable(list, compareUTF16)
		return stringsOf(list), nil
	}); err != nil {
		return nil, err
	}
	if delegable := input.Get("delegable"); !isUndefined(delegable) {
		flag, ok := delegable.(bool)
		if !ok {
			return nil, invalidInput("delegable must be a boolean")
		}
		if flag {
			next.Delete("delegable")
		} else {
			next.Set("delegable", false)
		}
	}
	if err := optional("maxDelegatedSessionSeconds", func(value any) (any, error) {
		return Integer(value, "maxDelegatedSessionSeconds", AgentSessionSeconds.Min, AgentSessionSeconds.Max)
	}); err != nil {
		return nil, err
	}
	if boundary := input.Get("boundary"); !nullish(boundary) {
		if err := server.Catalog.Validate(ctx, tx, tenantID, boundary); err != nil {
			return nil, err
		}
	}
	if err := optional("boundary", func(value any) (any, error) { return value, nil }); err != nil {
		return nil, err
	}
	if err := optional("tokenAudiences", func(value any) (any, error) {
		list, err := TokenAudienceList(value, "")
		if err != nil {
			return nil, err
		}
		return stringsOf(list), nil
	}); err != nil {
		return nil, err
	}
	return next, nil
}

// SponsorFor is the sponsor an agent may have: an active, unexpired person of the agent's tenant.
func SponsorFor(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, sponsorID any) (*core.Object, error) {
	id, err := Text(sponsorID, "sponsorId")
	if err != nil {
		return nil, err
	}
	sponsor, err := tx.Get(ctx, "identities", id)
	if err != nil {
		return nil, err
	}
	if sponsor == nil || sponsor.Get("tenantId") != tenantID || sponsor.Get("kind") != "user" ||
		sponsor.Get("status") != "active" || server.IdentityExpired(sponsor) {
		return nil, core.NewIamError("INVALID_SPONSOR", "An agent sponsor must be an active person of the same tenant")
	}
	return sponsor, nil
}

// AgentStanding is whether (and why not) an agent may act right now: `ok`, `suspended`, `expired`, `deleted`,
// `sponsor-missing` or `sponsor-inactive`.
func AgentStanding(ctx context.Context, server *ServerContext, tx core.IamStore, agent *core.Object) (string, error) {
	switch agent.Get("status") {
	case "deleted":
		return "deleted", nil
	case "active":
	default:
		return "suspended", nil
	}
	if server.IdentityExpired(agent) {
		return "expired", nil
	}
	var sponsor *core.Object
	if sponsorID, ok := member(agent.Get("agent"), "sponsorId").(string); ok {
		found, err := tx.Get(ctx, "identities", sponsorID)
		if err != nil {
			return "", err
		}
		sponsor = found
	}
	if sponsor == nil || sponsor.Get("tenantId") != agent.Get("tenantId") || sponsor.Get("kind") != "user" {
		return "sponsor-missing", nil
	}
	if sponsor.Get("status") != "active" || server.IdentityExpired(sponsor) {
		return "sponsor-inactive", nil
	}
	return "ok", nil
}

// AssertAgentUsable refuses an agent credential (401) unless the agent is in good standing.
func AssertAgentUsable(ctx context.Context, server *ServerContext, tx core.IamStore, agent *core.Object) error {
	if agent.Get("kind") != "agent" || !truthy(agent.Get("agent")) {
		return core.NewIamError("UNAUTHENTICATED", "Agent credential revoked", 401)
	}
	standing, err := AgentStanding(ctx, server, tx, agent)
	if err != nil {
		return err
	}
	if standing == "sponsor-missing" || standing == "sponsor-inactive" {
		return core.NewIamError("UNAUTHENTICATED", "The agent’s sponsor is no longer active", 401)
	}
	if standing != "ok" {
		return core.NewIamError("UNAUTHENTICATED", "Agent disabled", 401)
	}
	return nil
}

// ActingAgent is the agent behind a principal: the identity of an agent's own credential, or the agent of a
// delegated session (nil for none).
func ActingAgent(ctx context.Context, tx core.IamStore, principal *Principal) (*core.Object, error) {
	if principal.Session.Get("kind") == "delegated" {
		agentID, ok := principal.Session.Get("agentId").(string)
		if !ok {
			return nil, nil
		}
		agent, err := tx.Get(ctx, "identities", agentID)
		if err != nil || agent == nil || agent.Get("kind") != "agent" {
			return nil, err
		}
		return agent, nil
	}
	if principal.Identity.Get("kind") == "agent" {
		return principal.Identity, nil
	}
	return nil, nil
}

// AgentDecisionScope is what a decision adds for agents: context keys and the ceilings of the agent and the
// delegation.
type AgentDecisionScope struct {
	Keys       *core.Object
	Boundaries []any
	// Confirm (delegations with `confirm` patterns) turns an otherwise allowed decision for such an action into
	// CONFIRMATION_REQUIRED unless the person approved it; nil when nothing needs confirmation.
	Confirm func(action, resourceType, resourceID string) *core.Decision
	// Authorities are credential issuer authorities whose ceilings apply as well (nil: none).
	Authorities []string
	// AgentIDs are the agents taking part: the acting agent and every agent that handed the work on.
	AgentIDs []string
}

// AgentDecisionScopeOf is the agent part of a decision (agentDecisionScope). nil (with no error) when a delegated
// session's agent or delegation (or one above it) cannot be read or has ended: the decision is refused.
func AgentDecisionScopeOf(ctx context.Context, tx core.IamStore, principal *Principal, now int64) (*AgentDecisionScope, error) {
	session := principal.Session
	delegated := session.Get("kind") == "delegated"
	scope := &AgentDecisionScope{Keys: core.NewObject("principal.delegated", delegated), Boundaries: []any{}, AgentIDs: []string{}}
	agent, err := ActingAgent(ctx, tx, principal)
	if err != nil {
		return nil, err
	}
	if agent == nil {
		if delegated {
			return nil, nil
		}
		return scope, nil
	}
	profile := agent.Get("agent")
	agentID := jsString(agent.Get("id"))
	scope.Keys.Set("principal.agentId", agentID)
	scope.AgentIDs = append(scope.AgentIDs, agentID)
	if sponsorID, ok := member(profile, "sponsorId").(string); ok {
		scope.Keys.Set("principal.agentSponsorId", sponsorID)
	}
	if model, ok := member(profile, "model").(string); ok {
		scope.Keys.Set("principal.agentModel", model)
	}
	if provider, ok := member(profile, "provider").(string); ok {
		scope.Keys.Set("principal.agentProvider", provider)
	}
	if boundary := member(profile, "boundary"); truthy(boundary) {
		scope.Boundaries = append(scope.Boundaries, boundary)
	}
	if !delegated {
		return scope, nil
	}
	var delegation *core.Object
	if delegationID, ok := session.Get("delegationId").(string); ok {
		if delegation, err = tx.Get(ctx, "delegations", delegationID); err != nil {
			return nil, err
		}
	}
	if delegation == nil || delegation.Get("status") != "active" || delegation.Get("agentId") != agentID ||
		delegation.Get("subjectId") != principal.Identity.Get("id") || !truthy(delegation.Get("policy")) {
		return nil, nil
	}
	scope.Keys.Set("principal.delegationId", delegation.Get("id"))
	scope.Boundaries = append(scope.Boundaries, delegation.Get("policy"))
	// A hand-off is bounded by every delegation above it, the ceilings of the agents that handed it on, and the
	// limits of the sessions that did.
	ancestors, err := DelegationAncestors(ctx, tx, delegation, now)
	if err != nil {
		return nil, err
	}
	if ancestors == nil {
		return nil, nil
	}
	handedOn := func(item *core.Object) {
		if ceilings, ok := item.Get("ceilings").([]any); ok {
			scope.Boundaries = append(scope.Boundaries, ceilings...)
		}
		if authorityID, ok := item.Get("authorityId").(string); ok {
			scope.Authorities = append(scope.Authorities, authorityID)
		}
	}
	handedOn(delegation)
	for _, ancestor := range ancestors {
		if !truthy(ancestor.Delegation.Get("policy")) {
			return nil, nil
		}
		scope.AgentIDs = append(scope.AgentIDs, jsString(ancestor.Agent.Get("id")))
		scope.Boundaries = append(scope.Boundaries, ancestor.Delegation.Get("policy"))
		if boundary := member(ancestor.Agent.Get("agent"), "boundary"); truthy(boundary) {
			scope.Boundaries = append(scope.Boundaries, boundary)
		}
		handedOn(ancestor.Delegation)
	}
	chain := []any{}
	for index := len(ancestors) - 1; index >= 0; index-- {
		chain = append(chain, ancestors[index].Agent.Get("id"))
	}
	scope.Keys.Set("principal.delegationChain", append(chain, agentID))
	if confirm, _ := delegation.Get("confirm").([]any); len(confirm) > 0 {
		approved, err := ApprovedConfirmations(ctx, tx, delegation, now)
		if err != nil {
			return nil, err
		}
		scope.Confirm = func(action, resourceType, resourceID string) *core.Decision {
			if NeedsConfirmation(delegation, action) && !approved[ConfirmationKey(action, resourceType, resourceID)] {
				return &core.Decision{Allowed: false, Reason: "CONFIRMATION_REQUIRED", Matched: []string{}}
			}
			return nil
		}
	}
	return scope, nil
}

// HandOverAgents moves the leaver's agents to successor when that is an active person (each audited as
// `agent:sponsor-change`); otherwise they stay with the leaver and are refused until reassigned.
func HandOverAgents(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, leaver *core.Object, successor *core.Object) (reassigned, unsponsored int, err error) {
	var heir *core.Object
	if successor != nil && successor.Get("kind") == "user" && successor.Get("status") == "active" {
		heir = successor
	}
	agents, err := tx.Find(ctx, "identities", core.NewObject("tenantId", leaver.Get("tenantId"), "kind", "agent"), nil)
	if err != nil {
		return 0, 0, err
	}
	for _, agent := range agents {
		if agent.Get("status") == "deleted" || member(agent.Get("agent"), "sponsorId") != leaver.Get("id") {
			continue
		}
		if heir == nil {
			unsponsored++
			continue
		}
		profile, _ := agent.Get("agent").(*core.Object)
		if profile == nil {
			profile = core.NewObject()
		}
		if _, err := tx.Put(ctx, "identities", agent.Spread(core.NewObject("agent", profile.Spread(core.NewObject("sponsorId", heir.Get("id")))))); err != nil {
			return 0, 0, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "agent:sponsor-change", jsString(agent.Get("tenantId")), jsString(agent.Get("id")), "allow", false,
			core.NewObject("from", leaver.Get("id"), "to", heir.Get("id"), "reason", "offboarding")); err != nil {
			return 0, 0, err
		}
		reassigned++
	}
	return reassigned, unsponsored, nil
}

// AgentSummary is an agent as administrators and sponsors see it: the identity's public fields plus its standing.
func AgentSummary(ctx context.Context, server *ServerContext, tx core.IamStore, agent *core.Object) (*core.Object, error) {
	var sponsor *core.Object
	if sponsorID, ok := member(agent.Get("agent"), "sponsorId").(string); ok {
		found, err := tx.Get(ctx, "identities", sponsorID)
		if err != nil {
			return nil, err
		}
		sponsor = found
	}
	profile, _ := agent.Get("agent").(*core.Object)
	if profile == nil {
		profile = core.NewObject("sponsorId", "")
	}
	standing, err := AgentStanding(ctx, server, tx, agent)
	if err != nil {
		return nil, err
	}
	summary := core.NewObject(
		"id", agent.Get("id"), "tenantId", agent.Get("tenantId"), "name", agent.Get("name"), "status", agent.Get("status"),
		"createdAt", agent.Get("createdAt"), "agent", profile.Spread(), "standing", standing,
	)
	for _, key := range []string{"description", "expiresAt", "attributes"} {
		if value := agent.Get(key); !isUndefined(value) {
			summary.Set(key, value)
		}
	}
	if sponsor != nil && sponsor.Get("tenantId") == agent.Get("tenantId") {
		view := core.NewObject("id", sponsor.Get("id"), "name", sponsor.Get("name"), "status", sponsor.Get("status"))
		if email := sponsor.Get("email"); !isUndefined(email) {
			view.Set("email", email)
		}
		summary.Set("sponsor", view)
	}
	return summary, nil
}
