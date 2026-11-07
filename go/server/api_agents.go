package server

// Port of packages/server/src/api/agents.ts: the `agents` group, AI agents as accounts. Administrators create agents
// with `iam:agents:create` (the caller is the sponsor unless `sponsorId` names another active person), read them with
// `iam:agents:read`, change them with `iam:agents:update` and delete them with `iam:agents:delete`. Keys come from
// `credentials.create` like a service account's. A sponsor manages their own agents without a permission: `listMine`,
// and the `suspend` kill switch (and `resume` when they were the one who suspended it).

import (
	"context"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AuditActivity (api/agents.ts auditActivity): Audit events newest first in a tenant that match `where`, with the
// paging of an activity query (limit 1-500, 100 by default; offset; optional from and to).
func AuditActivity(ctx context.Context, tx core.IamStore, tenantID string, query *core.Object, where func(*core.Object) bool) (result []*core.Object, err error) {
	if query == nil {
		query = core.NewObject()
	}
	limit, err := Integer(coalesce(query.Get("limit"), 100.0), "limit", 1, 500)
	if err != nil {
		return nil, err
	}
	offset, err := Integer(coalesce(query.Get("offset"), 0.0), "offset", 0, 100_000)
	if err != nil {
		return nil, err
	}
	limitInt, offsetInt := int(limit), int(offset)
	order := core.OrderOptions{Field: "timestamp", Direction: "desc", Limit: &limitInt, Offset: &offsetInt}
	if from := query.Get("from"); !isUndefined(from) {
		value, err := Integer(from, "from", 0, maxSafeInteger)
		if err != nil {
			return nil, err
		}
		order.From = &value
	}
	if to := query.Get("to"); !isUndefined(to) {
		value, err := Integer(to, "to", 0, maxSafeInteger)
		if err != nil {
			return nil, err
		}
		order.To = &value
	}
	return core.FindOrdered(ctx, tx, "audit", core.NewObject("tenantId", tenantID), order, where)
}

// personalSession is a person's own session of the tenant (not a role, token, delegated or impersonation session).
func personalSession(principal *Principal, tenantID string) bool {
	return ActsInOwnRight(principal.Session) &&
		principal.Identity.Get("kind") == "user" &&
		principal.Identity.Get("tenantId") == tenantID &&
		principal.Session.Get("tenantId") == tenantID &&
		!truthy(principal.Session.Get("impersonatorId"))
}

// authorizeSponsor: naming someone other than oneself as an agent's sponsor makes them accountable for it and moves
// the agent's spend onto their teams and department, so it needs iam:identities:update on them (which owners and root
// administrators hold). Checked before the sponsor is validated, so it reveals nothing about them.
func authorizeSponsor(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string, sponsorID any) error {
	sponsor, err := Text(sponsorID, "sponsorId")
	if err != nil {
		return err
	}
	if sponsor == principal.Identity.Get("id") && personalSession(principal, tenantID) {
		return nil
	}
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: "iam:identities:update", Resource: ResourceTarget{Type: "iam", ID: sponsor},
	}, true)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return core.NewIamError("ACCESS_DENIED", "Naming another person as the sponsor needs iam:identities:update on them", 403)
	}
	return nil
}

// tokenClaimNames are JWT claim names a signed agent card may not carry at its top level (see `signCard`).
var tokenClaimNames = map[string]bool{
	// RFC 7519 registered claims.
	"iss": true, "sub": true, "aud": true, "exp": true, "nbf": true, "iat": true, "jti": true,
	// Token exchange and proof of possession (RFC 8693, RFC 7800) and common authorization claims.
	"act": true, "may_act": true, "scope": true, "scp": true, "client_id": true, "azp": true, "cnf": true,
	// Delegation tokens (delegations.issueToken).
	"tenant_id": true, "delegation_id": true,
}

// AgentMutationsResult is api/agents.ts agentMutations(): agent changes without a credential.
type AgentMutationsResult struct {
	server *ServerContext
}

// CreateAgent (api/agents.ts agentMutations().createAgent): Registers an agent sponsored by `input.sponsorId`; counts
// toward the tenant's `agents` limit. Audited as `agent:create`.
func (s *AgentMutationsResult) CreateAgent(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object, input *core.Object) (result *core.Object, err error) {
	server := s.server
	tenantID := jsString(tenant.Get("id"))
	name, err := Text(input.Get("name"), "name")
	if err != nil {
		return nil, err
	}
	sponsor, err := SponsorFor(ctx, server, tx, tenantID, input.Get("sponsorId"))
	if err != nil {
		return nil, err
	}
	if err := server.EnforceLimit(ctx, tx, tenant, "agents", func(ctx context.Context) (int, error) {
		agents, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "agent"), nil)
		if err != nil {
			return 0, err
		}
		count := 0
		for _, item := range agents {
			if item.Get("status") != "deleted" {
				count++
			}
		}
		return count, nil
	}); err != nil {
		return nil, err
	}
	createdAt := float64(server.Now())
	profile, err := AgentProfile(ctx, server, tx, tenantID, input, core.NewObject("sponsorId", sponsor.Get("id")))
	if err != nil {
		return nil, err
	}
	agent := core.NewObject(
		"id", ID(), "tenantId", tenantID, "kind", "agent", "name", name, "status", "active", "emailVerified", false,
		"owner", false, "rootAdmin", false, "createdAt", createdAt, "agent", profile,
	)
	if description := input.Get("description"); !isUndefined(description) {
		text, err := Text(description, "description", 512)
		if err != nil {
			return nil, err
		}
		agent.Set("description", text)
	}
	if expiresAt := input.Get("expiresAt"); !isUndefined(expiresAt) {
		expiry, err := server.BindingExpiry(expiresAt)
		if err != nil {
			return nil, err
		}
		agent.Set("expiresAt", expiry)
	}
	if attributes := input.Get("attributes"); !isUndefined(attributes) {
		values, err := AttributeValues(server.Catalog.IdentityAttributes, attributes)
		if err != nil {
			return nil, err
		}
		agent.Set("attributes", values)
	}
	if _, err := tx.Insert(ctx, "identities", agent); err != nil {
		return nil, err
	}
	metadata := core.NewObject("sponsorId", sponsor.Get("id"))
	if model := profile.Get("model"); truthy(model) {
		metadata.Set("model", model)
	}
	if provider := profile.Get("provider"); truthy(provider) {
		metadata.Set("provider", provider)
	}
	if err := server.Events.Audit(ctx, tx, principal, "agent:create", tenantID, jsString(agent.Get("id")), "allow", false, metadata); err != nil {
		return nil, err
	}
	return agent, nil
}

// UpdateAgent (api/agents.ts agentMutations().updateAgent): Changes an agent (see `agents.update`); a new sponsor is
// audited as `agent:sponsor-change`.
func (s *AgentMutationsResult) UpdateAgent(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object, input *core.Object) (result *core.Object, err error) {
	server := s.server
	if agent.Get("status") == "deleted" {
		return nil, core.NewIamError("NOT_FOUND", "Agent has been deleted", 404)
	}
	tenantID := jsString(agent.Get("tenantId"))
	next := agent.Spread()
	if name := input.Get("name"); !isUndefined(name) {
		text, err := Text(name, "name")
		if err != nil {
			return nil, err
		}
		next.Set("name", text)
	}
	if description := input.Get("description"); description == nil {
		next.Delete("description")
	} else if !isUndefined(description) {
		text, err := Text(description, "description", 512)
		if err != nil {
			return nil, err
		}
		next.Set("description", text)
	}
	if attributes := input.Get("attributes"); !isUndefined(attributes) {
		values, err := AttributeValues(server.Catalog.IdentityAttributes, attributes)
		if err != nil {
			return nil, err
		}
		next.Set("attributes", values)
	}
	if expiresAt := input.Get("expiresAt"); expiresAt == nil {
		next.Delete("expiresAt")
	} else if !isUndefined(expiresAt) {
		expiry, err := server.BindingExpiry(expiresAt)
		if err != nil {
			return nil, err
		}
		next.Set("expiresAt", expiry)
	}
	previous, _ := agent.Get("agent").(*core.Object)
	if previous == nil {
		previous = core.NewObject("sponsorId", "")
	}
	profile, err := AgentProfile(ctx, server, tx, tenantID, input, previous.Spread())
	if err != nil {
		return nil, err
	}
	previousSponsor := member(agent.Get("agent"), "sponsorId")
	if sponsorID := input.Get("sponsorId"); !isUndefined(sponsorID) {
		sponsor, err := SponsorFor(ctx, server, tx, tenantID, sponsorID)
		if err != nil {
			return nil, err
		}
		profile = profile.Spread(core.NewObject("sponsorId", sponsor.Get("id")))
	}
	next.Set("agent", profile)
	updated, err := tx.Put(ctx, "identities", next)
	if err != nil {
		return nil, err
	}
	if !core.StrictEquals(previousSponsor, profile.Get("sponsorId")) {
		if err := server.Events.Audit(ctx, tx, principal, "agent:sponsor-change", tenantID, jsString(agent.Get("id")), "allow", false,
			core.NewObject("from", coalesce(previousSponsor, nil), "to", profile.Get("sponsorId"))); err != nil {
			return nil, err
		}
	}
	return updated, nil
}

// DeleteAgent (api/agents.ts agentMutations().deleteAgent): Deletes an agent: revokes every delegation to it, ends its
// sessions, leaves a tombstone. Audited as `identity:delete` with the agent kind and the revoked delegations.
func (s *AgentMutationsResult) DeleteAgent(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object) (result *core.Object, err error) {
	server := s.server
	agentID := jsString(agent.Get("id"))
	delegations, err := RevokeDelegationsOf(ctx, server, tx, agent, jsString(principal.Identity.Get("id")))
	if err != nil {
		return nil, err
	}
	if _, err := DeleteDelegatedSessions(ctx, tx, core.NewObject("agentId", agentID)); err != nil {
		return nil, err
	}
	card, err := tx.Get(ctx, "agentCards", agentID)
	if err != nil {
		return nil, err
	}
	if card != nil {
		if err := tx.Delete(ctx, "agentCards", agentID); err != nil {
			return nil, err
		}
	}
	deleted, err := DeleteIdentity(ctx, server, tx, principal, agent)
	if err != nil {
		return nil, err
	}
	if err := server.Events.Audit(ctx, tx, principal, "identity:delete", jsString(agent.Get("tenantId")), agentID, "allow", false,
		core.NewObject("kind", "agent", "delegationsRevoked", delegations)); err != nil {
		return nil, err
	}
	return deleted, nil
}

// AgentMutations (api/agents.ts agentMutations): Agent changes without a credential, for the `agents` API (which
// authorizes first) and for configuration sync (ai-sync.ts). Every function runs inside the caller's transaction and
// audits like the API.
func AgentMutations(server *ServerContext) (result *AgentMutationsResult, err error) {
	return &AgentMutationsResult{server: server}, nil
}

// AgentsAPI is the `agents` API group (packages/server/src/api/agents.ts createAgentsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/agents/{method} onto it.
type AgentsAPI struct {
	server    *ServerContext
	mutations *AgentMutationsResult
}

// CreateAgentsAPI builds the `agents` API group.
func CreateAgentsAPI(server *ServerContext) *AgentsAPI {
	mutations, _ := AgentMutations(server)
	return &AgentsAPI{server: server, mutations: mutations}
}

// agentRecord is the tenant's agent agentID (NOT_FOUND for anything else).
func (api *AgentsAPI) agentRecord(ctx context.Context, tx core.IamStore, agentID any, tenantID string) (*core.Object, error) {
	agent, err := api.server.Scoped(ctx, tx, "identities", agentID, tenantID)
	if err != nil {
		return nil, err
	}
	if agent.Get("kind") != "agent" {
		return nil, core.NewIamError("NOT_FOUND", "Agent not found", 404)
	}
	return agent, nil
}

// agentDetail is an agent with the credentials and delegations it holds, for its detail page.
func (api *AgentsAPI) agentDetail(ctx context.Context, tx core.IamStore, agent *core.Object) (*core.Object, error) {
	server := api.server
	now := float64(server.Now())
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", agent.Get("id"), "kind", "api-key"), nil)
	if err != nil {
		return nil, err
	}
	live := []*core.Object{}
	for _, session := range sessions {
		if jsNumber(session.Get("expiresAt")) > now {
			live = append(live, session)
		}
	}
	sortStable(live, ByNewest)
	keys := make([]any, 0, len(live))
	for _, session := range live {
		key := core.NewObject("id", session.Get("id"))
		if name := session.Get("name"); !isUndefined(name) {
			key.Set("name", name)
		}
		key.Set("createdAt", session.Get("createdAt"))
		key.Set("expiresAt", session.Get("expiresAt"))
		if jsNumber(session.Get("lastSeenAt")) > jsNumber(session.Get("createdAt")) {
			key.Set("lastUsedAt", session.Get("lastSeenAt"))
		}
		keys = append(keys, key)
	}
	delegations, err := tx.Find(ctx, "delegations", core.NewObject("tenantId", agent.Get("tenantId"), "agentId", agent.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	delegated, err := tx.Find(ctx, "sessions", core.NewObject("kind", "delegated", "agentId", agent.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	liveSessions := 0
	for _, session := range delegated {
		if jsNumber(session.Get("expiresAt")) > now {
			liveSessions++
		}
	}
	active, pending := 0, 0
	for _, item := range delegations {
		current := jsNumber(item.Get("expiresAt")) > now
		if item.Get("status") == "active" && current {
			active++
		}
		if item.Get("status") == "pending" && current {
			pending++
		}
	}
	summary, err := AgentSummary(ctx, server, tx, agent)
	if err != nil {
		return nil, err
	}
	return summary.Spread(core.NewObject(
		"keys", keys,
		"delegations", core.NewObject("active", float64(active), "pending", float64(pending)),
		"liveDelegatedSessions", float64(liveSessions),
	)), nil
}

// suspendAgent suspends an agent: its keys, session tokens and delegated sessions are refused while it is suspended,
// and live delegated sessions and session tokens are ended now. Keys are kept, so `resume` restores the agent as it
// was.
func (api *AgentsAPI) suspendAgent(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object, reason string) (*core.Object, error) {
	server := api.server
	if agent.Get("status") == "deleted" {
		return nil, core.NewIamError("NOT_FOUND", "Agent has been deleted", 404)
	}
	if agent.Get("status") == "disabled" && truthy(member(agent.Get("agent"), "suspended")) {
		return nil, core.NewIamError("CONFLICT", "The agent is already suspended", 409)
	}
	now := server.Now()
	agentID := jsString(agent.Get("id"))
	profile, _ := agent.Get("agent").(*core.Object)
	if profile == nil {
		profile = core.NewObject()
	}
	mark := core.NewObject("by", principal.Identity.Get("id"), "at", float64(now))
	if reason != "" {
		mark.Set("reason", reason)
	}
	suspended, err := tx.Put(ctx, "identities", agent.Spread(core.NewObject(
		"status", "disabled", "agent", profile.Spread(core.NewObject("suspended", mark)),
	)))
	if err != nil {
		return nil, err
	}
	// The kill switch holds the agent now: a threats containment of it can no longer be released.
	if err := EndContainment(ctx, tx, agentID, now); err != nil {
		return nil, err
	}
	sessions, err := DeleteDelegatedSessions(ctx, tx, core.NewObject("agentId", agentID))
	if err != nil {
		return nil, err
	}
	tokens := 0
	own, err := tx.Find(ctx, "sessions", core.NewObject("identityId", agentID), nil)
	if err != nil {
		return nil, err
	}
	for _, session := range own {
		if session.Get("kind") == "api-key" {
			continue
		}
		if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
			return nil, err
		}
		tokens++
	}
	metadata := core.NewObject()
	if reason != "" {
		metadata.Set("reason", reason)
	}
	metadata.Set("delegatedSessionsEnded", sessions)
	metadata.Set("sessionsEnded", float64(tokens))
	if err := server.Events.Audit(ctx, tx, principal, "agent:suspend", jsString(agent.Get("tenantId")), agentID, "allow", false, metadata); err != nil {
		return nil, err
	}
	return AgentSummary(ctx, server, tx, suspended)
}

// resumeAgent lifts a suspension.
func (api *AgentsAPI) resumeAgent(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object) (*core.Object, error) {
	server := api.server
	if agent.Get("status") == "deleted" {
		return nil, core.NewIamError("NOT_FOUND", "Agent has been deleted", 404)
	}
	if agent.Get("status") == "active" {
		return nil, core.NewIamError("CONFLICT", "The agent is not suspended", 409)
	}
	if server.IdentityExpired(agent) {
		return nil, core.NewIamError("INVALID_TRANSITION", "Extend or clear expiresAt before resuming an expired agent", 409)
	}
	current, ok := agent.Get("agent").(*core.Object)
	if !ok || current == nil {
		return nil, &core.TypeError{Message: "Cannot destructure property 'suspended' of 'agent.agent' as it is undefined."}
	}
	profile := current.Spread()
	profile.Delete("suspended")
	resumed, err := tx.Put(ctx, "identities", agent.Spread(core.NewObject("status", "active", "agent", profile)))
	if err != nil {
		return nil, err
	}
	// Resuming a contained agent ends the containment too.
	if err := EndContainment(ctx, tx, jsString(agent.Get("id")), server.Now()); err != nil {
		return nil, err
	}
	if err := server.Events.Audit(ctx, tx, principal, "agent:resume", jsString(agent.Get("tenantId")), jsString(agent.Get("id")), "allow", false, nil); err != nil {
		return nil, err
	}
	return AgentSummary(ctx, server, tx, resumed)
}

// sponsorFn is the work of asSponsorOr: sponsor is true when the caller acts as the agent's sponsor.
type sponsorFn func(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object, sponsor bool) (any, error)

// asSponsorOr runs fn as the agent's sponsor when the caller is that person in their own session, otherwise as an
// administrative operation needing `action` on `iam/{agentId}`.
func (api *AgentsAPI) asSponsorOr(ctx context.Context, credential core.CredentialInput, rawTenantID, rawAgentID any, action string, fn sponsorFn) (any, error) {
	server := api.server
	tenantID, err := Text(rawTenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	agentID, err := Text(rawAgentID, "agentId")
	if err != nil {
		return nil, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	type ownResult struct{ value any }
	own, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*ownResult, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if !personalSession(principal, tenantID) {
			return nil, nil
		}
		agent, err := tx.Get(ctx, "identities", agentID)
		if err != nil {
			return nil, err
		}
		if agent == nil || agent.Get("kind") != "agent" || agent.Get("tenantId") != tenantID ||
			!core.StrictEquals(member(agent.Get("agent"), "sponsorId"), principal.Identity.Get("id")) {
			return nil, nil
		}
		value, err := fn(ctx, tx, principal, agent, true)
		if err != nil {
			return nil, err
		}
		return &ownResult{value: value}, nil
	})
	if err != nil {
		return nil, err
	}
	if own != nil {
		return own.value, nil
	}
	return Operate(ctx, server.Operations, credential, tenantID, action, agentID, func(ctx context.Context, call MutationContext) (any, error) {
		agent, err := api.agentRecord(ctx, call.Tx, agentID, tenantID)
		if err != nil {
			return nil, err
		}
		return fn(ctx, call.Tx, call.Principal, agent, false)
	}, false)
}

// agentsOf is the tenant's agents, newest first.
func agentsOf(ctx context.Context, tx core.IamStore, tenantID any) ([]*core.Object, error) {
	agents, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "agent"), nil)
	if err != nil {
		return nil, err
	}
	sortStable(agents, ByNewest)
	return agents, nil
}

// Activity is POST {basePath}/agents/activity. Returns what an agent did, newest first: the audit events of its own credentials and of the sessions in which it acted for people.
func (api *AgentsAPI) Activity(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsActivityInput]) (Out[apitypes.AgentsActivityOutput], error) {
	value, err := api.asSponsorOr(ctx, credential, input.Get("tenantId"), input.Get("agentId"), "iam:agents:read",
		func(ctx context.Context, tx core.IamStore, _ *Principal, agent *core.Object, _ bool) (any, error) {
			agentID := agent.Get("id")
			events, err := AuditActivity(ctx, tx, jsString(agent.Get("tenantId")), input.Body, func(event *core.Object) bool {
				return core.StrictEquals(event.Get("actorId"), agentID) || core.StrictEquals(member(event.Get("sessionContext"), "agentId"), agentID)
			})
			if err != nil {
				return nil, err
			}
			return objectList(events), nil
		})
	if err != nil {
		return Out[apitypes.AgentsActivityOutput]{}, err
	}
	return Answer[apitypes.AgentsActivityOutput](value), nil
}

// objectList is a list of records as a model array.
func objectList(records []*core.Object) []any {
	list := make([]any, len(records))
	for index, record := range records {
		list[index] = record
	}
	return list
}

// Catalog is POST {basePath}/agents/catalog. Lists the agents people of the tenant may delegate to, with what a person needs to decide.
func (api *AgentsAPI) Catalog(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsCatalogInput]) (Out[apitypes.AgentsCatalogOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.AgentsCatalogOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.AgentsCatalogOutput]{}, err
	}
	listings, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if !personalSession(principal, tenantID) {
			return nil, core.NewIamError("ACCESS_DENIED", "The agent catalog is read from a person’s own session of the tenant", 403)
		}
		agents, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "kind", "agent"), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(agents, func(i, j int) bool {
			return localeCompare(jsString(agents[i].Get("name")), jsString(agents[j].Get("name"))) < 0
		})
		listings := []any{}
		for _, agent := range agents {
			profile, _ := agent.Get("agent").(*core.Object)
			if profile == nil || profile.Get("delegable") == false {
				continue
			}
			standing, err := AgentStanding(ctx, server, tx, agent)
			if err != nil {
				return nil, err
			}
			if standing != "ok" {
				continue
			}
			sponsor, err := tx.Get(ctx, "identities", jsString(profile.Get("sponsorId")))
			if err != nil {
				return nil, err
			}
			listing := core.NewObject("id", agent.Get("id"), "name", agent.Get("name"))
			if description := agent.Get("description"); !isUndefined(description) {
				listing.Set("description", description)
			}
			for _, key := range []string{"purpose", "model", "provider", "url"} {
				if value := profile.Get(key); !isUndefined(value) {
					listing.Set(key, value)
				}
			}
			if protocols := profile.Get("protocols"); !isUndefined(protocols) {
				list, _ := protocols.([]any)
				listing.Set("protocols", append([]any{}, list...))
			}
			if audiences, ok := profile.Get("tokenAudiences").([]any); ok && len(audiences) > 0 {
				listing.Set("tokenAudiences", append([]any{}, audiences...))
			}
			sponsorName := any("")
			if sponsor != nil {
				sponsorName = coalesce(sponsor.Get("name"), "")
			}
			listing.Set("sponsorName", sponsorName)
			listings = append(listings, listing)
		}
		return listings, nil
	})
	if err != nil {
		return Out[apitypes.AgentsCatalogOutput]{}, err
	}
	return Answer[apitypes.AgentsCatalogOutput](listings), nil
}

// Create is POST {basePath}/agents/create. Registers an AI agent with a sponsor and an optional profile.
func (api *AgentsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsCreateInput]) (Out[apitypes.AgentsCreateOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:agents:create", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		tenantID := jsString(tenant.Get("id"))
		sponsorID := input.Get("sponsorId")
		if nullish(sponsorID) {
			sponsorID = core.Undefined
			if personalSession(principal, tenantID) {
				sponsorID = principal.Identity.Get("id")
			}
		}
		if isUndefined(sponsorID) {
			return nil, core.NewIamError("INVALID_SPONSOR", "Name the person accountable for the agent (sponsorId)")
		}
		if given := input.Get("sponsorId"); !isUndefined(given) {
			if err := authorizeSponsor(ctx, server, tx, principal, tenantID, given); err != nil {
				return nil, err
			}
		}
		body := input.Body
		if body == nil {
			body = core.NewObject()
		}
		agent, err := api.mutations.CreateAgent(ctx, tx, principal, tenant, body.Spread(core.NewObject("sponsorId", sponsorID)))
		if err != nil {
			return nil, err
		}
		return AgentSummary(ctx, server, tx, agent)
	}, false)
	if err != nil {
		return Out[apitypes.AgentsCreateOutput]{}, err
	}
	return Answer[apitypes.AgentsCreateOutput](result), nil
}

// Delete is POST {basePath}/agents/delete. Deletes an agent, ending its keys and sessions and revoking every delegation to it.
func (api *AgentsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsDeleteInput]) (Out[apitypes.AgentsDeleteOutput], error) {
	server := api.server
	agentID, err := Text(input.Get("agentId"), "agentId")
	if err != nil {
		return Out[apitypes.AgentsDeleteOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:agents:delete", agentID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		agent, err := api.agentRecord(ctx, call.Tx, input.Get("agentId"), jsString(rawTenantID))
		if err != nil {
			return nil, err
		}
		return api.mutations.DeleteAgent(ctx, call.Tx, call.Principal, agent)
	}, false)
	if err != nil {
		return Out[apitypes.AgentsDeleteOutput]{}, err
	}
	return Answer[apitypes.AgentsDeleteOutput](result), nil
}

// Directory is POST {basePath}/agents/directory. Lists the tenant's agents that hold a current attested A2A card, for finding an agent to work with or hand work to.
func (api *AgentsAPI) Directory(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsDirectoryInput]) (Out[apitypes.AgentsDirectoryOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.AgentsDirectoryOutput]{}, err
	}
	skill, hasSkill := "", false
	if value := input.Get("skill"); !isUndefined(value) {
		if skill, err = Text(value, "skill", 128); err != nil {
			return Out[apitypes.AgentsDirectoryOutput]{}, err
		}
		hasSkill = true
	}
	protocol, hasProtocol := "", false
	if value := input.Get("protocol"); !isUndefined(value) {
		text, err := Text(value, "protocol", 32)
		if err != nil {
			return Out[apitypes.AgentsDirectoryOutput]{}, err
		}
		protocol, hasProtocol = core.JSLower(text), true
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.AgentsDirectoryOutput]{}, err
	}
	entries, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if principal.Session.Get("tenantId") != tenantID && principal.Identity.Get("tenantId") != tenantID {
			return nil, core.NewIamError("ACCESS_DENIED", "The agent directory is read from within the tenant", 403)
		}
		now := float64(server.Now())
		entries := []*core.Object{}
		records, err := tx.Find(ctx, "agentCards", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			if jsNumber(record.Get("expiresAt")) <= now {
				continue
			}
			agent, err := tx.Get(ctx, "identities", jsString(record.Get("agentId")))
			if err != nil {
				return nil, err
			}
			if agent == nil || agent.Get("kind") != "agent" || agent.Get("tenantId") != tenantID {
				continue
			}
			standing, err := AgentStanding(ctx, server, tx, agent)
			if err != nil {
				return nil, err
			}
			if standing != "ok" {
				continue
			}
			if hasProtocol {
				protocols, _ := member(record.Get("attestation"), "protocols").([]any)
				if !containsValue(protocols, protocol) {
					continue
				}
			}
			if hasSkill {
				skills, _ := member(record.Get("card"), "skills").([]any)
				offers := false
				for _, item := range skills {
					entry, ok := item.(*core.Object)
					if !ok || entry == nil {
						continue
					}
					tags, isList := entry.Get("tags").([]any)
					if entry.Get("id") == skill || (isList && containsValue(tags, skill)) {
						offers = true
						break
					}
				}
				if !offers {
					continue
				}
			}
			entries = append(entries, core.NewObject(
				"agentId", agent.Get("id"), "name", agent.Get("name"), "card", record.Get("card"),
				"attestation", record.Get("attestation"), "expiresAt", record.Get("expiresAt"),
			))
		}
		sort.SliceStable(entries, func(i, j int) bool {
			return localeCompare(jsString(entries[i].Get("name")), jsString(entries[j].Get("name"))) < 0
		})
		return entries, nil
	})
	if err != nil {
		return Out[apitypes.AgentsDirectoryOutput]{}, err
	}
	return Answer[apitypes.AgentsDirectoryOutput](objectList(entries)), nil
}

// containsValue is `list.includes(value)` for a string value.
func containsValue(list []any, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// Get is POST {basePath}/agents/get. Returns one agent with its standing, its live API keys, and counts of its delegations.
func (api *AgentsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsGetInput]) (Out[apitypes.AgentsGetOutput], error) {
	value, err := api.asSponsorOr(ctx, credential, input.Get("tenantId"), input.Get("agentId"), "iam:agents:read",
		func(ctx context.Context, tx core.IamStore, _ *Principal, agent *core.Object, _ bool) (any, error) {
			return api.agentDetail(ctx, tx, agent)
		})
	if err != nil {
		return Out[apitypes.AgentsGetOutput]{}, err
	}
	return Answer[apitypes.AgentsGetOutput](value), nil
}

// List is POST {basePath}/agents/list. Lists the tenant's agents, newest first, optionally only one sponsor's or those in one standing.
func (api *AgentsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsListInput]) (Out[apitypes.AgentsListOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:agents:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx := call.Tx
		var sponsorID any = core.Undefined
		if value := input.Get("sponsorId"); !isUndefined(value) {
			text, err := Text(value, "sponsorId")
			if err != nil {
				return nil, err
			}
			sponsorID = text
		}
		agents, err := agentsOf(ctx, tx, rawTenantID)
		if err != nil {
			return nil, err
		}
		summaries := []any{}
		standing := input.Get("standing")
		for _, agent := range agents {
			if agent.Get("status") == "deleted" && input.Get("includeDeleted") != true {
				continue
			}
			if !isUndefined(sponsorID) && !core.StrictEquals(member(agent.Get("agent"), "sponsorId"), sponsorID) {
				continue
			}
			summary, err := AgentSummary(ctx, server, tx, agent)
			if err != nil {
				return nil, err
			}
			if !isUndefined(standing) && !core.StrictEquals(summary.Get("standing"), standing) {
				continue
			}
			summaries = append(summaries, summary)
		}
		return summaries, nil
	}, false)
	if err != nil {
		return Out[apitypes.AgentsListOutput]{}, err
	}
	return Answer[apitypes.AgentsListOutput](result), nil
}

// ListMine is POST {basePath}/agents/listMine. Returns the agents you sponsor, newest first, with the same detail as get.
func (api *AgentsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsListMineInput]) (Out[apitypes.AgentsListMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.AgentsListMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.AgentsListMineOutput]{}, err
	}
	details, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if !personalSession(principal, tenantID) {
			return nil, core.NewIamError("ACCESS_DENIED", "Sponsored agents are listed from a person’s own session of the tenant", 403)
		}
		agents, err := agentsOf(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		details := []any{}
		for _, agent := range agents {
			if agent.Get("status") != "deleted" && core.StrictEquals(member(agent.Get("agent"), "sponsorId"), principal.Identity.Get("id")) {
				detail, err := api.agentDetail(ctx, tx, agent)
				if err != nil {
					return nil, err
				}
				details = append(details, detail)
			}
		}
		return details, nil
	})
	if err != nil {
		return Out[apitypes.AgentsListMineOutput]{}, err
	}
	return Answer[apitypes.AgentsListMineOutput](details), nil
}

// Resume is POST {basePath}/agents/resume. Lifts an agent's suspension, so its kept API keys work again.
func (api *AgentsAPI) Resume(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsResumeInput]) (Out[apitypes.AgentsResumeOutput], error) {
	value, err := api.asSponsorOr(ctx, credential, input.Get("tenantId"), input.Get("agentId"), "iam:agents:update",
		func(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object, sponsor bool) (any, error) {
			if sponsor {
				if !core.StrictEquals(member(member(agent.Get("agent"), "suspended"), "by"), principal.Identity.Get("id")) {
					return nil, core.NewIamError("ACCESS_DENIED", "Only an administrator can resume an agent someone else suspended", 403)
				}
			} else if err := api.server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
			return api.resumeAgent(ctx, tx, principal, agent)
		})
	if err != nil {
		return Out[apitypes.AgentsResumeOutput]{}, err
	}
	return Answer[apitypes.AgentsResumeOutput](value), nil
}

// SignCard is POST {basePath}/agents/signCard. Signs an agent's A2A (Agent2Agent) agent card, so other agents can check that it is a registered agent in good standing of your organization.
func (api *AgentsAPI) SignCard(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsSignCardInput]) (Out[apitypes.AgentsSignCardOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.AgentsSignCardOutput]{}, err
	}
	agentID, err := Text(input.Get("agentId"), "agentId")
	if err != nil {
		return Out[apitypes.AgentsSignCardOutput]{}, err
	}
	sign := func(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object, _ bool) (any, error) {
		standing, err := AgentStanding(ctx, server, tx, agent)
		if err != nil {
			return nil, err
		}
		if standing != "ok" {
			return nil, core.NewIamError("INVALID_IDENTITY", "The agent is not in good standing", 409)
		}
		tenant, err := tx.Get(ctx, "tenants", jsString(agent.Get("tenantId")))
		if err != nil {
			return nil, err
		}
		if tenant == nil {
			return nil, core.NewIamError("NOT_FOUND", "Tenant not found", 404)
		}
		// The card is signed with the keys that sign delegation tokens, and its signed payload is agent-controlled
		// JSON: without token claims at the top level, it can never pass as a delegation token (or any JWT naming a
		// subject, audience, actor or lifetime) with a verifier that skips the `typ` check.
		card := input.Get("card")
		if object, ok := card.(*core.Object); ok && object != nil {
			claims := []string{}
			for _, name := range object.Keys() {
				if tokenClaimNames[name] {
					claims = append(claims, name)
				}
			}
			if len(claims) > 0 {
				plural := "s"
				if len(claims) == 1 {
					plural = ""
				}
				return nil, invalidInput("An agent card may not carry the token claim" + plural + " " + strings.Join(claims, ", "))
			}
		}
		signed, err := SignAgentCard(ctx, server, tenant, agent, card)
		if err != nil {
			return nil, err
		}
		// The latest attested card is the agent's entry in the tenant's directory (`directory`).
		entry := core.NewObject(
			"id", agent.Get("id"), "tenantId", agent.Get("tenantId"), "agentId", agent.Get("id"),
			"card", signed.Get("card"), "attestation", signed.Get("attestation"), "signedAt", float64(server.Now()),
			"expiresAt", signed.Get("expiresAt"),
		)
		existing, err := tx.Get(ctx, "agentCards", jsString(agent.Get("id")))
		if err != nil {
			return nil, err
		}
		if existing != nil {
			_, err = tx.Put(ctx, "agentCards", entry)
		} else {
			_, err = tx.Insert(ctx, "agentCards", entry)
		}
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "agent:card-sign", jsString(agent.Get("tenantId")), jsString(agent.Get("id")), "allow", false,
			core.NewObject("url", jsString(member(signed.Get("card"), "url")), "expiresAt", signed.Get("expiresAt"))); err != nil {
			return nil, err
		}
		return signed, nil
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.AgentsSignCardOutput]{}, err
	}
	type ownResult struct{ value any }
	own, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*ownResult, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		// The agent's own unscoped API key: not a temporary credential minted from it, and not a key whose scopes
		// (session policy) limit what it may do.
		identity, session := principal.Identity, principal.Session
		if identity.Get("id") != agentID || identity.Get("kind") != "agent" || identity.Get("tenantId") != tenantID ||
			session.Get("tenantId") != tenantID || session.Get("kind") != "api-key" || !ActsInOwnRight(session) ||
			truthy(session.Get("impersonatorId")) || truthy(session.Get("policy")) {
			return nil, nil
		}
		value, err := sign(ctx, tx, principal, identity, false)
		if err != nil {
			return nil, err
		}
		return &ownResult{value: value}, nil
	})
	if err != nil {
		return Out[apitypes.AgentsSignCardOutput]{}, err
	}
	if own != nil {
		return Answer[apitypes.AgentsSignCardOutput](own.value), nil
	}
	value, err := api.asSponsorOr(ctx, credential, tenantID, agentID, "iam:agents:update", sign)
	if err != nil {
		return Out[apitypes.AgentsSignCardOutput]{}, err
	}
	return Answer[apitypes.AgentsSignCardOutput](value), nil
}

// Standing is POST {basePath}/agents/standing. Tells whether an agent may act right now and, if not, why.
func (api *AgentsAPI) Standing(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsStandingInput]) (Out[apitypes.AgentsStandingOutput], error) {
	value, err := api.asSponsorOr(ctx, credential, input.Get("tenantId"), input.Get("agentId"), "iam:agents:read",
		func(ctx context.Context, tx core.IamStore, _ *Principal, agent *core.Object, _ bool) (any, error) {
			standing, err := AgentStanding(ctx, api.server, tx, agent)
			if err != nil {
				return nil, err
			}
			return core.NewObject("agentId", agent.Get("id"), "standing", standing), nil
		})
	if err != nil {
		return Out[apitypes.AgentsStandingOutput]{}, err
	}
	return Answer[apitypes.AgentsStandingOutput](value), nil
}

// Suspend is POST {basePath}/agents/suspend. Stops an agent at once (the kill switch) and keeps its API keys for resume.
func (api *AgentsAPI) Suspend(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsSuspendInput]) (Out[apitypes.AgentsSuspendOutput], error) {
	reason := ""
	if value := input.Get("reason"); !isUndefined(value) {
		text, err := Text(value, "reason", 512)
		if err != nil {
			return Out[apitypes.AgentsSuspendOutput]{}, err
		}
		reason = text
	}
	value, err := api.asSponsorOr(ctx, credential, input.Get("tenantId"), input.Get("agentId"), "iam:agents:update",
		func(ctx context.Context, tx core.IamStore, principal *Principal, agent *core.Object, _ bool) (any, error) {
			return api.suspendAgent(ctx, tx, principal, agent, reason)
		})
	if err != nil {
		return Out[apitypes.AgentsSuspendOutput]{}, err
	}
	return Answer[apitypes.AgentsSuspendOutput](value), nil
}

// SuspendAll is POST {basePath}/agents/suspendAll. The organization-wide emergency stop: suspends every active agent of the tenant at once.
func (api *AgentsAPI) SuspendAll(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsSuspendAllInput]) (Out[apitypes.AgentsSuspendAllOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:agents:update", jsString(rawTenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, tenant := call.Tx, call.Principal, call.Tenant
		reason, err := Text(input.Get("reason"), "reason", 512)
		if err != nil {
			return nil, err
		}
		sponsorID, hasSponsor := "", false
		if value := input.Get("sponsorId"); !isUndefined(value) {
			if sponsorID, err = Text(value, "sponsorId"); err != nil {
				return nil, err
			}
			hasSponsor = true
		}
		provider, hasProvider := "", false
		if value := input.Get("provider"); !isUndefined(value) {
			text, err := Text(value, "provider", 64)
			if err != nil {
				return nil, err
			}
			provider, hasProvider = core.JSLower(text), true
		}
		model, hasModel := "", false
		if value := input.Get("model"); !isUndefined(value) {
			if model, err = Text(value, "model", 128); err != nil {
				return nil, err
			}
			hasModel = true
		}
		agents, err := agentsOf(ctx, tx, tenant.Get("id"))
		if err != nil {
			return nil, err
		}
		agentIDs := []any{}
		for _, agent := range agents {
			if agent.Get("status") != "active" {
				continue
			}
			profile := agent.Get("agent")
			if hasSponsor && member(profile, "sponsorId") != sponsorID {
				continue
			}
			if hasProvider && member(profile, "provider") != provider {
				continue
			}
			if hasModel && member(profile, "model") != model {
				continue
			}
			if _, err := api.suspendAgent(ctx, tx, principal, agent, reason); err != nil {
				return nil, err
			}
			agentIDs = append(agentIDs, agent.Get("id"))
		}
		metadata := core.NewObject("reason", reason, "suspended", float64(len(agentIDs)))
		if sponsorID != "" {
			metadata.Set("sponsorId", sponsorID)
		}
		if provider != "" {
			metadata.Set("provider", provider)
		}
		if model != "" {
			metadata.Set("model", model)
		}
		tenantID := jsString(tenant.Get("id"))
		if err := server.Events.Audit(ctx, tx, principal, "agent:suspend-all", tenantID, tenantID, "allow", false, metadata); err != nil {
			return nil, err
		}
		return core.NewObject("suspended", float64(len(agentIDs)), "agentIds", agentIDs), nil
	}, false)
	if err != nil {
		return Out[apitypes.AgentsSuspendAllOutput]{}, err
	}
	return Answer[apitypes.AgentsSuspendAllOutput](result), nil
}

// Update is POST {basePath}/agents/update. Changes an agent's name, description, expiry, attributes, profile, or sponsor.
func (api *AgentsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgentsUpdateInput]) (Out[apitypes.AgentsUpdateOutput], error) {
	server := api.server
	agentID, err := Text(input.Get("agentId"), "agentId")
	if err != nil {
		return Out[apitypes.AgentsUpdateOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:agents:update", agentID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		agent, err := api.agentRecord(ctx, tx, input.Get("agentId"), jsString(rawTenantID))
		if err != nil {
			return nil, err
		}
		if sponsorID := input.Get("sponsorId"); !isUndefined(sponsorID) && !core.StrictEquals(sponsorID, member(agent.Get("agent"), "sponsorId")) {
			if err := authorizeSponsor(ctx, server, tx, principal, jsString(agent.Get("tenantId")), sponsorID); err != nil {
				return nil, err
			}
		}
		body := input.Body
		if body == nil {
			body = core.NewObject()
		}
		updated, err := api.mutations.UpdateAgent(ctx, tx, principal, agent, body)
		if err != nil {
			return nil, err
		}
		return AgentSummary(ctx, server, tx, updated)
	}, false)
	if err != nil {
		return Out[apitypes.AgentsUpdateOutput]{}, err
	}
	return Answer[apitypes.AgentsUpdateOutput](result), nil
}
