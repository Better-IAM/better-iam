package server

// Port of packages/server/src/delegation-tokens.ts: what delegation tokens (`delegations.issueToken`) stand on,
// shared by issuing them and by live verification (`iam.a2a.verifyDelegationToken(token, { live: true })`): the
// delegation chain, where the token may go, and which scopes it may carry.
//
// An issued token is kept in `delegationTokens` until it expires (DelegationTokenRecord in TypeScript): `{ id (the
// jti), tenantId, delegationId, personId, agentId, keyId, audience, scopes, sessionPolicies, authorityId?,
// createdAt, expiresAt }`.

import (
	"context"
	"slices"

	"github.com/Better-IAM/better-iam/go/core"
)

// TokenBasis is delegation-tokens.ts TokenBasis: a delegation chain as a token names it.
type TokenBasis struct {
	Tenant     *core.Object
	PersonID   string
	Delegation *core.Object
	// Ancestors are the delegations above a hand-off, nearest first, with their agents.
	Ancestors []DelegationAncestor
	// Agents are the agents from the person's own delegate to the one acting now.
	Agents          []*core.Object
	SessionPolicies []any
	// AuthorityIDs are key issuer authorities beyond those the chain records (the acting key's).
	AuthorityIDs []string
}

// AudienceRefusal (delegation-tokens.ts audienceRefusal): The first agent of the chain that may not present
// delegations to `audience`, if any.
func AudienceRefusal(agents []*core.Object, audience string) (result *core.Object, err error) {
	for _, agent := range agents {
		audiences, _ := member(agent.Get("agent"), "tokenAudiences").([]any)
		allowed := false
		for _, pattern := range audiences {
			if AudienceMatches(jsString(pattern), audience) {
				allowed = true
				break
			}
		}
		if !allowed {
			return agent, nil
		}
	}
	return nil, nil
}

// scopeRefusalOf is a ScopeRefusal answer: `{ scope, why }` (why is limit, confirm or deny).
func scopeRefusalOf(scope, why string) *core.Object {
	return core.NewObject("scope", scope, "why", why)
}

// ScopeRefusal (delegation-tokens.ts scopeRefusal): The first scope the chain may not carry (`{ scope, why }`, why
// being limit, confirm or deny), `{ inactive: true }` when an issuer authority of the chain was revoked, or nil when
// it may carry them all. Every scope must be allowed outright by every limit a decision for the acting session applies
// (the delegations and their ceilings, the agents' boundaries, the session's policies, the key issuers' authority,
// the tenant's and the person's boundaries, and the tenant's guest boundary for a guest). None may be one the person
// confirms call by call (`confirm`, anywhere in the chain), nor one a deny statement among the person's own grants
// could touch: a token carries no resource or condition to refine them with.
func ScopeRefusal(ctx context.Context, server *ServerContext, tx core.IamStore, basis *TokenBasis, scopes []string) (result *core.Object, err error) {
	if len(scopes) == 0 {
		return nil, nil
	}
	chain := []*core.Object{basis.Delegation}
	for _, ancestor := range basis.Ancestors {
		chain = append(chain, ancestor.Delegation)
	}
	limits := append([]any{}, basis.SessionPolicies...)
	authorityIDs := newOrderedSet(basis.AuthorityIDs...)
	for _, delegation := range chain {
		limits = append(limits, delegation.Get("policy"))
		if ceilings, ok := delegation.Get("ceilings").([]any); ok {
			limits = append(limits, ceilings...)
		}
		if authorityID, ok := delegation.Get("authorityId").(string); ok {
			authorityIDs.Add(authorityID)
		}
	}
	for _, agent := range basis.Agents {
		if boundary := member(agent.Get("agent"), "boundary"); truthy(boundary) {
			limits = append(limits, boundary)
		}
	}
	for _, authorityID := range authorityIDs.Values() {
		ceilings, ok, err := server.AuthorityChain(ctx, tx, authorityID)
		if err != nil {
			return nil, err
		}
		if !ok {
			return core.NewObject("inactive", true), nil
		}
		limits = append(limits, ceilings...)
	}
	realms, err := server.Ancestry(ctx, tx, basis.Tenant)
	if err != nil {
		return nil, err
	}
	for _, realm := range realms {
		if boundary := realm.Get("boundary"); truthy(boundary) {
			limits = append(limits, boundary)
		}
	}
	boundaries, err := tx.Find(ctx, "principalBoundaries", core.NewObject(
		"tenantId", basis.Tenant.Get("id"), "identityId", basis.PersonID,
	), nil)
	if err != nil {
		return nil, err
	}
	for _, boundary := range boundaries {
		limits = append(limits, boundary.Get("document"))
	}
	// A guest's decisions, delegated ones included, stay within the tenant's guest ceiling (decisions.ts, guests.ts).
	person, err := tx.Get(ctx, "identities", basis.PersonID)
	if err != nil {
		return nil, err
	}
	if person != nil && core.StrictEquals(person.Get("tenantId"), basis.Tenant.Get("id")) && truthy(person.Get("guest")) {
		ceiling, err := GuestBoundary(ctx, tx, jsString(basis.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		if ceiling != nil {
			limits = append(limits, ceiling)
		}
	}
	confirm := []string{}
	for _, delegation := range chain {
		confirm = append(confirm, stringItems(delegation.Get("confirm"))...)
	}
	// Denies of bindings, roles and policies whose author's authority was revoked still apply at decision time, so they
	// bound a token's scopes too (they arrive as deny-only paths in `lapsed`).
	lapsed := []GrantPath{}
	paths, err := server.Decisions.IdentityGrants(ctx, tx, basis.PersonID, jsString(basis.Tenant.Get("id")), nil, &lapsed)
	if err != nil {
		return nil, err
	}
	denies := []string{}
	for _, path := range append(append([]GrantPath{}, paths...), lapsed...) {
		documents := append(append([]any{}, path.Grants...), path.Boundaries...)
		for _, document := range documents {
			for _, statement := range policyStatements(document) {
				if statement.Get("effect") == "deny" {
					denies = append(denies, stringItems(statement.Get("actions"))...)
				}
			}
		}
	}
	for _, scope := range scopes {
		for _, document := range limits {
			if !policyAllowsScope(document, scope) {
				return scopeRefusalOf(scope, "limit"), nil
			}
		}
		if slices.ContainsFunc(confirm, func(pattern string) bool { return actionsOverlap(pattern, scope) }) {
			return scopeRefusalOf(scope, "confirm"), nil
		}
		if slices.ContainsFunc(denies, func(pattern string) bool { return actionsOverlap(pattern, scope) }) {
			return scopeRefusalOf(scope, "deny"), nil
		}
	}
	return nil, nil
}

// TokenStillStands (delegation-tokens.ts tokenStillStands): Re-checks an issued token's record against the current
// state: the delegation and those above it live, the person active, every agent in good standing and still allowed
// the audience, the acting key live, and the scopes still allowed. False when anything the token stands on has
// changed.
func TokenStillStands(ctx context.Context, server *ServerContext, tx core.IamStore, record *core.Object, now int64) (result bool, err error) {
	delegation, err := tx.Get(ctx, "delegations", jsString(record.Get("delegationId")))
	if err != nil {
		return false, err
	}
	tenant, err := tx.Get(ctx, "tenants", jsString(record.Get("tenantId")))
	if err != nil {
		return false, err
	}
	person, err := tx.Get(ctx, "identities", jsString(record.Get("personId")))
	if err != nil {
		return false, err
	}
	agent, err := tx.Get(ctx, "identities", jsString(record.Get("agentId")))
	if err != nil {
		return false, err
	}
	key, err := tx.Get(ctx, "sessions", jsString(record.Get("keyId")))
	if err != nil {
		return false, err
	}
	if delegation == nil || tenant == nil || person == nil || agent == nil || key == nil ||
		!delegationLive(delegation, now) ||
		!core.StrictEquals(delegation.Get("tenantId"), record.Get("tenantId")) ||
		!core.StrictEquals(delegation.Get("subjectId"), record.Get("personId")) ||
		!core.StrictEquals(delegation.Get("agentId"), record.Get("agentId")) ||
		!core.StrictEquals(person.Get("tenantId"), record.Get("tenantId")) ||
		person.Get("status") != "active" ||
		server.IdentityExpired(person) ||
		member(agent.Get("agent"), "delegable") == false ||
		key.Get("kind") != "api-key" ||
		!core.StrictEquals(key.Get("identityId"), agent.Get("id")) ||
		jsNumber(key.Get("expiresAt")) <= float64(now) {
		return false, nil
	}
	realms, err := server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return false, err
	}
	for _, realm := range realms {
		if realm.Get("status") != "active" {
			return false, nil
		}
	}
	// try { await assertAgentUsable(...) } catch { return false; }
	if err := AssertAgentUsable(ctx, server, tx, agent); err != nil {
		return false, nil
	}
	ancestors, err := LiveAncestors(ctx, server, tx, delegation, now)
	if err != nil {
		return false, err
	}
	if ancestors == nil {
		return false, nil
	}
	agents := make([]*core.Object, 0, len(ancestors)+1)
	for index := len(ancestors) - 1; index >= 0; index-- {
		agents = append(agents, ancestors[index].Agent)
	}
	agents = append(agents, agent)
	if outsider, _ := AudienceRefusal(agents, jsString(record.Get("audience"))); outsider != nil {
		return false, nil
	}
	sessionPolicies, _ := record.Get("sessionPolicies").([]any)
	authorityIDs := []string{}
	if authorityID := record.Get("authorityId"); truthy(authorityID) {
		authorityIDs = append(authorityIDs, jsString(authorityID))
	}
	refusal, err := ScopeRefusal(ctx, server, tx, &TokenBasis{
		Tenant:          tenant,
		PersonID:        jsString(record.Get("personId")),
		Delegation:      delegation,
		Ancestors:       ancestors,
		Agents:          agents,
		SessionPolicies: sessionPolicies,
		AuthorityIDs:    authorityIDs,
	}, stringItems(record.Get("scopes")))
	if err != nil {
		return false, err
	}
	return refusal == nil, nil
}
