package server

// Port of packages/server/src/api/delegations.ts: the `delegations` group, people let AI agents act for them. A person
// grants a delegation directly (`grant`) or approves an agent's request (`request` → `approve` / `deny`); the agent
// then opens short delegated sessions with its own key (`assume`). Delegated sessions act as the person, within the
// delegation's scope and the agent's ceiling, and never pass recent-authentication, ownership or self-service checks.
// The person, the agent's sponsor, the agent itself or an administrator (`iam:delegations:revoke`) can revoke a
// delegation, which ends its sessions at once. Administrators list and read delegations with `iam:delegations:read`.

import (
	"context"
	"math"
	"slices"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// DelegationsAPI is the `delegations` API group (packages/server/src/api/delegations.ts createDelegationsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/delegations/{method} onto it.
type DelegationsAPI struct {
	server *ServerContext
}

// CreateDelegationsAPI builds the `delegations` API group.
func CreateDelegationsAPI(server *ServerContext) *DelegationsAPI {
	return &DelegationsAPI{server: server}
}

func delegationRefuse(message string) error {
	return core.NewIamError("ACCESS_DENIED", message, 403)
}

func delegationNotFound() error {
	return core.NewIamError("NOT_FOUND", "Delegation not found", 404)
}

func delegationInactive() error {
	return core.NewIamError("DELEGATION_INACTIVE", "This delegation is no longer active", 403)
}

// assertPerson: a person in their own session of the tenant (not impersonated).
func delegationAssertPerson(principal *Principal, tenantID string) error {
	if truthy(principal.Session.Get("impersonatorId")) {
		return core.NewIamError("IMPERSONATION_RESTRICTED", "Delegations cannot be managed while impersonating a member", 403)
	}
	if !ActsInOwnRight(principal.Session) || principal.Session.Get("kind") != "user" || principal.Identity.Get("kind") != "user" ||
		principal.Identity.Get("tenantId") != tenantID || principal.Session.Get("tenantId") != tenantID {
		return delegationRefuse("Delegations are decided by a person in their own session of the organization")
	}
	return nil
}

// assertAgentKey: an agent acting with its own API key in its own tenant.
func delegationAssertAgentKey(principal *Principal, tenantID string) error {
	if principal.Identity.Get("kind") != "agent" || principal.Session.Get("kind") != "api-key" ||
		principal.Identity.Get("tenantId") != tenantID || principal.Session.Get("tenantId") != tenantID {
		return delegationRefuse("Only an agent using its own API key can do this")
	}
	return nil
}

// delegableAgent is an agent of the tenant that may receive a delegation right now.
func (api *DelegationsAPI) delegableAgent(ctx context.Context, tx core.IamStore, agentID any, tenantID string) (*core.Object, error) {
	id, err := Text(agentID, "agentId")
	if err != nil {
		return nil, err
	}
	agent, err := tx.Get(ctx, "identities", id)
	if err != nil {
		return nil, err
	}
	if agent == nil || agent.Get("kind") != "agent" || agent.Get("tenantId") != tenantID || agent.Get("status") == "deleted" {
		return nil, core.NewIamError("NOT_FOUND", "Agent not found", 404)
	}
	if member(agent.Get("agent"), "delegable") == false {
		return nil, core.NewIamError("DELEGATION_NOT_ALLOWED", "This agent does not accept delegation", 403)
	}
	standing, err := AgentStanding(ctx, api.server, tx, agent)
	if err != nil {
		return nil, err
	}
	if standing != "ok" {
		return nil, core.NewIamError("INVALID_IDENTITY", "The agent is not in good standing", 409)
	}
	return agent, nil
}

// copyStrings is `[...list]` for a stored string list.
func copyStrings(value any) []any {
	list, _ := value.([]any)
	return append([]any{}, list...)
}

// summary is a delegation as the people and agents involved see it (never session material).
func (api *DelegationsAPI) summary(ctx context.Context, tx core.IamStore, delegation *core.Object) (*core.Object, error) {
	now := api.server.Now()
	agent, err := tx.Get(ctx, "identities", jsString(delegation.Get("agentId")))
	if err != nil {
		return nil, err
	}
	subject, err := tx.Get(ctx, "identities", jsString(delegation.Get("subjectId")))
	if err != nil {
		return nil, err
	}
	status := delegation.Get("status")
	agentSummary := core.NewObject("id", delegation.Get("agentId"), "name", delegation.Get("agentId"))
	if agent != nil {
		agentSummary.Set("name", coalesce(agent.Get("name"), delegation.Get("agentId")))
		if model := member(agent.Get("agent"), "model"); truthy(model) {
			agentSummary.Set("model", model)
		}
		if provider := member(agent.Get("agent"), "provider"); truthy(provider) {
			agentSummary.Set("provider", provider)
		}
	}
	subjectSummary := core.NewObject("id", delegation.Get("subjectId"), "name", delegation.Get("subjectId"))
	if subject != nil {
		subjectSummary.Set("name", coalesce(subject.Get("name"), delegation.Get("subjectId")))
		if email := subject.Get("email"); truthy(email) {
			subjectSummary.Set("email", email)
		}
	}
	result := core.NewObject(
		"id", delegation.Get("id"),
		"tenantId", delegation.Get("tenantId"),
		"status", status,
		"expired", (status == "active" || status == "pending") && jsNumber(delegation.Get("expiresAt")) <= float64(now),
		"agent", agentSummary,
		"subject", subjectSummary,
		"policy", delegation.Get("policy"),
		"requestedBy", delegation.Get("requestedBy"),
		"createdAt", delegation.Get("createdAt"),
		"expiresAt", delegation.Get("expiresAt"),
	)
	if scopes := delegation.Get("scopes"); truthy(scopes) {
		result.Set("scopes", copyStrings(scopes))
	}
	for _, key := range []string{"reason"} {
		if value := delegation.Get(key); !isUndefined(value) {
			result.Set(key, value)
		}
	}
	if lifetimeMs := delegation.Get("lifetimeMs"); !isUndefined(lifetimeMs) {
		result.Set("requestedSeconds", math.Floor(jsNumber(lifetimeMs)/1000))
	}
	for _, key := range []string{"maxSessionSeconds", "decidedAt", "revokedAt", "revokedBy", "lastUsedAt"} {
		if value := delegation.Get(key); !isUndefined(value) {
			result.Set(key, value)
		}
	}
	if confirm, ok := delegation.Get("confirm").([]any); ok && len(confirm) > 0 {
		result.Set("confirm", copyStrings(confirm))
	}
	if handoff := delegation.Get("handoff"); truthy(handoff) {
		summaryHandoff := core.NewObject("depth", member(handoff, "depth"))
		if agents := member(handoff, "agents"); truthy(agents) {
			summaryHandoff.Set("agents", copyStrings(agents))
		}
		result.Set("handoff", summaryHandoff)
	}
	if parentID := delegation.Get("parentId"); !isUndefined(parentID) {
		result.Set("parentId", parentID)
	}
	// delegationSpendStanding answers undefined for a delegation without a cap (its first line), so it is only asked
	// about a delegation that has one.
	spend := delegation.Get("spend")
	if truthy(spend) {
		spent, err := DelegationSpendStanding(ctx, tx, delegation, now)
		if err != nil {
			return nil, err
		}
		if spent != nil {
			summarySpend := core.NewObject("period", member(spend, "period"))
			if maxTokens := member(spend, "maxTokens"); !isUndefined(maxTokens) {
				summarySpend.Set("maxTokens", maxTokens)
			}
			if maxCostMicros := member(spend, "maxCostMicros"); !isUndefined(maxCostMicros) {
				summarySpend.Set("maxCostUsd", jsNumber(maxCostMicros)/1_000_000)
			}
			if maxRequests := member(spend, "maxRequests"); !isUndefined(maxRequests) {
				summarySpend.Set("maxRequests", maxRequests)
			}
			summarySpend.Set("usedTokens", spent.Get("usedTokens"))
			summarySpend.Set("usedCostUsd", jsNumber(spent.Get("usedCostMicros"))/1_000_000)
			summarySpend.Set("usedRequests", spent.Get("usedRequests"))
			summarySpend.Set("resetsAt", spent.Get("resetsAt"))
			result.Set("spend", summarySpend)
		}
	}
	if chain, ok := delegation.Get("chain").([]any); ok && len(chain) > 0 {
		names := make([]any, len(chain))
		for index, agentID := range chain {
			name := agentID
			found, err := tx.Get(ctx, "identities", jsString(agentID))
			if err != nil {
				return nil, err
			}
			if found != nil {
				name = coalesce(found.Get("name"), agentID)
			}
			names[index] = core.NewObject("id", agentID, "name", name)
		}
		result.Set("chain", names)
	}
	return result, nil
}

// summaries is the summary of every delegation.
func (api *DelegationsAPI) summaries(ctx context.Context, tx core.IamStore, delegations []*core.Object) ([]any, error) {
	result := make([]any, len(delegations))
	for index, delegation := range delegations {
		item, err := api.summary(ctx, tx, delegation)
		if err != nil {
			return nil, err
		}
		result[index] = item
	}
	return result, nil
}

// liveBetween is the live (pending or active) delegation between an agent and a person, if any.
func (api *DelegationsAPI) liveBetween(ctx context.Context, tx core.IamStore, tenantID, agentID, subjectID string) (*core.Object, error) {
	now := api.server.Now()
	found, err := tx.Find(ctx, "delegations", core.NewObject("tenantId", tenantID, "agentId", agentID, "subjectId", subjectID), nil)
	if err != nil {
		return nil, err
	}
	// Hand-offs from other agents do not count: they are part of another delegation.
	for _, item := range found {
		if isUndefined(item.Get("parentId")) && (delegationLive(item, now) || delegationPending(item, now)) {
			return item, nil
		}
	}
	return nil, nil
}

// sessionCap reads `maxSessionSeconds` (ok is false when it was not given).
func delegationSessionCap(value any) (float64, bool, error) {
	if isUndefined(value) {
		return 0, false, nil
	}
	seconds, err := Integer(value, "maxSessionSeconds", AgentSessionSeconds.Min, AgentSessionSeconds.Max)
	return seconds, err == nil, err
}

// involved is whether the principal is involved in the delegation: its person (subject), its agent, the agent's
// sponsor, or (for a hand-off) the agent that handed it on (delegator), acting under the delegation above; "" for none.
func (api *DelegationsAPI) involved(ctx context.Context, tx core.IamStore, principal *Principal, delegation *core.Object) (string, error) {
	session := principal.Session
	if truthy(session.Get("impersonatorId")) {
		return "", nil
	}
	// The agent acting under this very delegation (its delegated session) counts as the agent.
	if session.Get("kind") == "delegated" && core.StrictEquals(session.Get("delegationId"), delegation.Get("id")) &&
		core.StrictEquals(session.Get("tenantId"), delegation.Get("tenantId")) {
		return "agent", nil
	}
	if session.Get("kind") == "delegated" && !isUndefined(delegation.Get("parentId")) &&
		core.StrictEquals(session.Get("delegationId"), delegation.Get("parentId")) &&
		core.StrictEquals(session.Get("tenantId"), delegation.Get("tenantId")) {
		return "delegator", nil
	}
	if !ActsInOwnRight(session) {
		return "", nil
	}
	if !core.StrictEquals(session.Get("tenantId"), delegation.Get("tenantId")) {
		return "", nil
	}
	identity := principal.Identity
	if core.StrictEquals(identity.Get("id"), delegation.Get("subjectId")) && identity.Get("kind") == "user" {
		return "subject", nil
	}
	if core.StrictEquals(identity.Get("id"), delegation.Get("agentId")) && identity.Get("kind") == "agent" {
		return "agent", nil
	}
	if identity.Get("kind") == "user" {
		agent, err := tx.Get(ctx, "identities", jsString(delegation.Get("agentId")))
		if err != nil {
			return "", err
		}
		if agent != nil && core.StrictEquals(member(agent.Get("agent"), "sponsorId"), identity.Get("id")) {
			return "sponsor", nil
		}
	}
	return "", nil
}

type delegationFn func(ctx context.Context, tx core.IamStore, principal *Principal, delegation *core.Object) (any, error)

// involvedOr runs fn when the caller is involved in the delegation, else as an operation needing action.
func (api *DelegationsAPI) involvedOr(ctx context.Context, credential core.CredentialInput, input *core.Object, action string, fn delegationFn) (any, error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	delegationID, err := Text(input.Get("delegationId"), "delegationId")
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
		delegation, err := tx.Get(ctx, "delegations", delegationID)
		if err != nil {
			return nil, err
		}
		if delegation == nil || delegation.Get("tenantId") != tenantID {
			return nil, nil
		}
		role, err := api.involved(ctx, tx, principal, delegation)
		if err != nil || role == "" {
			return nil, err
		}
		value, err := fn(ctx, tx, principal, delegation)
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
	return Operate(ctx, server.Operations, credential, tenantID, action, delegationID, func(ctx context.Context, call MutationContext) (any, error) {
		delegation, err := server.Scoped(ctx, call.Tx, "delegations", delegationID, tenantID)
		if err != nil {
			return nil, err
		}
		return fn(ctx, call.Tx, call.Principal, delegation)
	}, false)
}

// revokeDelegation revokes a pending or active delegation, ending its sessions; audited as `delegation:revoke`.
func (api *DelegationsAPI) revokeDelegation(ctx context.Context, tx core.IamStore, principal *Principal, delegation *core.Object, reason string) (*core.Object, error) {
	server := api.server
	if status := delegation.Get("status"); status != "active" && status != "pending" {
		return nil, core.NewIamError("INVALID_TRANSITION", "The delegation is already "+jsString(status), 409)
	}
	now := server.Now()
	// An agent revoking in a delegated session (its own hand-off, or one it handed on) is the one who revoked.
	revokedBy := jsString(principal.Identity.Get("id"))
	if agentID, ok := principal.Session.Get("agentId").(string); ok && principal.Session.Get("kind") == "delegated" {
		revokedBy = agentID
	}
	watermark, err := NextWatermark(delegation.Get("sessionsRevokedBefore"), core.Undefined, float64(now))
	if err != nil {
		return nil, err
	}
	revoked, err := tx.Put(ctx, "delegations", delegation.Spread(core.NewObject(
		"status", "revoked", "revokedAt", float64(now), "revokedBy", revokedBy, "sessionsRevokedBefore", watermark,
	)))
	if err != nil {
		return nil, err
	}
	ended, err := DeleteDelegatedSessions(ctx, tx, core.NewObject("delegationId", delegation.Get("id")))
	if err != nil {
		return nil, err
	}
	handoffs, err := RevokeHandoffsBelow(ctx, tx, delegation, revokedBy, now)
	if err != nil {
		return nil, err
	}
	metadata := core.NewObject("agentId", delegation.Get("agentId"), "subjectId", delegation.Get("subjectId"), "sessionsEnded", ended)
	if handoffs != 0 {
		metadata.Set("handoffsRevoked", handoffs)
	}
	if reason != "" {
		metadata.Set("reason", reason)
	}
	if err := server.Events.Audit(ctx, tx, principal, "delegation:revoke", jsString(delegation.Get("tenantId")), jsString(delegation.Get("id")),
		"allow", false, metadata); err != nil {
		return nil, err
	}
	return api.summary(ctx, tx, revoked)
}

// confirmationSummary is a confirmation request as the person and the agent see it.
func (api *DelegationsAPI) confirmationSummary(ctx context.Context, tx core.IamStore, confirmation *core.Object) (*core.Object, error) {
	agent, err := tx.Get(ctx, "identities", jsString(confirmation.Get("agentId")))
	if err != nil {
		return nil, err
	}
	name := confirmation.Get("agentId")
	if agent != nil {
		name = coalesce(agent.Get("name"), confirmation.Get("agentId"))
	}
	result := core.NewObject(
		"id", confirmation.Get("id"),
		"tenantId", confirmation.Get("tenantId"),
		"delegationId", confirmation.Get("delegationId"),
		"agent", core.NewObject("id", confirmation.Get("agentId"), "name", name),
		"subjectId", confirmation.Get("subjectId"),
		"action", confirmation.Get("action"),
		"resource", core.NewObject("type", confirmation.Get("resourceType"), "id", confirmation.Get("resourceId")),
		"status", confirmation.Get("status"),
		"expired", confirmation.Get("status") != "rejected" && jsNumber(confirmation.Get("expiresAt")) <= float64(api.server.Now()),
		"createdAt", confirmation.Get("createdAt"),
		"expiresAt", confirmation.Get("expiresAt"),
		"validSeconds", confirmation.Get("validSeconds"),
	)
	for _, key := range []string{"reason", "decidedAt"} {
		if value := confirmation.Get(key); !isUndefined(value) {
			result.Set(key, value)
		}
	}
	return result, nil
}

// confirmationScope is which confirmation requests a caller may see: a person's own session sees those addressed to
// them, an agent's own key those it made, and a delegated session those of its delegation. Anyone else is refused.
func delegationConfirmationScope(principal *Principal, tenantID string) (*core.Object, error) {
	session, identity := principal.Session, principal.Identity
	if session.Get("tenantId") != tenantID || truthy(session.Get("impersonatorId")) {
		return nil, delegationRefuse("Confirmation requests are read by the person or the agent involved")
	}
	if delegationID, ok := session.Get("delegationId").(string); ok && session.Get("kind") == "delegated" {
		return core.NewObject("delegationId", delegationID), nil
	}
	if identity.Get("kind") == "agent" && session.Get("kind") == "api-key" {
		return core.NewObject("agentId", identity.Get("id")), nil
	}
	if identity.Get("kind") == "user" && session.Get("kind") == "user" {
		return core.NewObject("subjectId", identity.Get("id")), nil
	}
	return nil, delegationRefuse("Confirmation requests are read by the person or the agent involved")
}

// assumeDelegation issues a delegated session (see Assume).
func (api *DelegationsAPI) assumeDelegation(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	delegationID, err := Text(input.Get("delegationId"), "delegationId")
	if err != nil {
		return nil, err
	}
	sessionName, err := SessionNameValue(input.Get("sessionName"))
	if err != nil {
		return nil, err
	}
	policy := input.Get("policy")
	if !isUndefined(policy) {
		if _, err := Object(policy); err != nil {
			return nil, err
		}
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := delegationAssertAgentKey(principal, tenantID); err != nil {
			return nil, err
		}
		agent := principal.Identity
		delegation, err := tx.Get(ctx, "delegations", delegationID)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		if delegation == nil || delegation.Get("tenantId") != tenantID || !core.StrictEquals(delegation.Get("agentId"), agent.Get("id")) {
			return nil, delegationNotFound()
		}
		if delegation.Get("status") == "pending" && jsNumber(delegation.Get("expiresAt")) > float64(now) {
			return nil, core.NewIamError("DELEGATION_PENDING", "The person has not approved this delegation yet", 409)
		}
		if !delegationLive(delegation, now) {
			return nil, delegationInactive()
		}
		// A hand-off can be used only while every delegation, agent and key above it still can.
		if !isUndefined(delegation.Get("parentId")) {
			ancestors, err := LiveAncestors(ctx, server, tx, delegation, now)
			if err != nil {
				return nil, err
			}
			if ancestors == nil {
				return nil, core.NewIamError("DELEGATION_INACTIVE", "A delegation above this one has ended", 403)
			}
		}
		if member(agent.Get("agent"), "delegable") == false {
			return nil, core.NewIamError("DELEGATION_NOT_ALLOWED", "This agent does not accept delegation", 403)
		}
		subject, err := tx.Get(ctx, "identities", jsString(delegation.Get("subjectId")))
		if err != nil {
			return nil, err
		}
		if subject == nil || subject.Get("kind") != "user" || subject.Get("tenantId") != tenantID || subject.Get("status") != "active" ||
			server.IdentityExpired(subject) {
			return nil, core.NewIamError("DELEGATION_INACTIVE", "The person behind this delegation is not active", 403)
		}
		if !isUndefined(policy) {
			if err := server.Catalog.Validate(ctx, tx, tenantID, policy); err != nil {
				return nil, err
			}
		}
		max := math.Min(
			jsNumber(coalesce(member(agent.Get("agent"), "maxDelegatedSessionSeconds"), AgentSessionSeconds.Fallback)),
			jsNumber(coalesce(delegation.Get("maxSessionSeconds"), AgentSessionSeconds.Max)),
		)
		durationSeconds := math.Min(900, max)
		if raw := input.Get("durationSeconds"); !isUndefined(raw) {
			if durationSeconds, err = Integer(raw, "durationSeconds", AgentSessionSeconds.Min, max); err != nil {
				return nil, err
			}
		}
		// Dead sessions of the delegation are deleted here, so the cap bounds the stored rows too.
		live := 0
		sessions, err := tx.Find(ctx, "sessions", core.NewObject("kind", "delegated", "delegationId", delegationID), nil)
		if err != nil {
			return nil, err
		}
		for _, session := range sessions {
			if jsNumber(session.Get("expiresAt")) <= float64(now) {
				if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
					return nil, err
				}
			} else {
				live++
			}
		}
		if live >= MaxSessionsPerDelegation {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "This delegation holds the maximum number of live sessions", 409)
		}
		token, err := auth.NewCredentialToken("dlg")
		if err != nil {
			return nil, err
		}
		source := principal.Session
		row := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"identityId", subject.Get("id"),
			"kind", "delegated",
			"agentId", agent.Get("id"),
			"delegationId", delegation.Get("id"),
			"sourceSessionId", source.Get("id"),
			"tokenHash", Hash(token),
			"uniqueKey", Hash(token),
			"createdAt", float64(now),
			"lastSeenAt", float64(now),
			// The person last authenticated for this when they decided on the delegation.
			"authenticatedAt", coalesce(delegation.Get("decidedAt"), delegation.Get("createdAt")),
			"expiresAt", math.Min(math.Min(float64(now)+durationSeconds*1000, jsNumber(delegation.Get("expiresAt"))), jsNumber(source.Get("expiresAt"))),
			"mfa", false,
		)
		if !isUndefined(policy) {
			row.Set("policy", policy)
		}
		// The agent key's own limits carry over: its scopes (or session policy) and its issuer's authority bound the
		// delegated session too, as they bound session tokens minted from a key.
		if sourcePolicy := source.Get("policy"); truthy(sourcePolicy) {
			row.Set("sourcePolicy", sourcePolicy)
		}
		if authorityID, ok := source.Get("credentialAuthorityId").(string); ok {
			row.Set("credentialAuthorityId", authorityID)
		}
		if sessionName != "" {
			row.Set("sessionName", sessionName)
		}
		if client := webIdentityClientRecord(server.Auth.CurrentClient(ctx)); client != nil {
			row.Set("client", client)
		}
		session, err := tx.Insert(ctx, "sessions", row)
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, "delegations", delegation.Spread(core.NewObject("lastUsedAt", float64(now)))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "delegation:assume", tenantID, jsString(delegation.Get("id")), "allow", false,
			core.NewObject("subjectId", subject.Get("id"), "sessionId", session.Get("id"), "durationSeconds", durationSeconds)); err != nil {
			return nil, err
		}
		expiresAt := jsNumber(session.Get("expiresAt"))
		sessionResult := core.NewObject(
			"id", session.Get("id"),
			"kind", "delegated",
			"tenantId", tenantID,
			"identityId", subject.Get("id"),
			"agentId", agent.Get("id"),
			"delegationId", delegation.Get("id"),
		)
		if sessionName != "" {
			sessionResult.Set("sessionName", sessionName)
		}
		return core.NewObject(
			"token", token,
			"tokenType", "Bearer",
			"expiresAt", expiresAt,
			"expiresIn", math.Max(0, math.Floor((expiresAt-float64(now))/1000)),
			"session", sessionResult,
		), nil
	})
}

// scopesText is `scopes.join(sep)` for a scope result's `scopes` (ok is false when it has none).
func scopesText(scope *core.Object, separator string) (string, bool) {
	scopes, ok := scope.Get("scopes").([]any)
	if !ok {
		return "", false
	}
	return strings.Join(stringItems(scopes), separator), true
}

// applyDelegationSettings sets the scope, session cap, confirm list, hand-off and spend settings of a new delegation
// (grant and request), in the TypeScript order.
func (api *DelegationsAPI) applyDelegationSettings(ctx context.Context, tx core.IamStore, tenantID string, delegation, scope *core.Object, maxSessionSeconds float64, hasCap bool, input *core.Object) error {
	if scopes := scope.Get("scopes"); truthy(scopes) {
		delegation.Set("scopes", scopes)
	}
	if hasCap {
		delegation.Set("maxSessionSeconds", maxSessionSeconds)
	}
	confirm, err := ConfirmPatterns(input.Get("confirm"))
	if err != nil {
		return err
	}
	if confirm != nil {
		delegation.Set("confirm", stringsOf(confirm))
	}
	handoff, err := HandoffSetting(ctx, tx, tenantID, input.Get("handoff"))
	if err != nil {
		return err
	}
	if handoff != nil {
		delegation.Set("handoff", handoff)
	}
	spend, err := SpendSetting(input.Get("spend"))
	if err != nil {
		return err
	}
	if spend != nil {
		delegation.Set("spend", spend)
	}
	return nil
}

// delegationsSendEmail is `ctx.options.authentication?.sendEmail` set.
func (api *DelegationsAPI) sendsEmail() bool {
	options := api.server.Options
	return options != nil && options.Authentication != nil && options.Authentication.SendEmail != nil
}

// Activity is POST {basePath}/delegations/activity. Returns what happened under a delegation, newest first: its lifecycle and everything the agent did for the person.
//
// Its lifecycle (grant, request, approval, sessions opened, revocation) and every audit event of the agent's sessions
// acting for the person, allowed and denied, including the work handed on to other agents. For the person, the agent,
// the agent's sponsor, or an administrator with `iam:delegations:read`.
func (api *DelegationsAPI) Activity(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsActivityInput]) (Out[apitypes.DelegationsActivityOutput], error) {
	result, err := api.involvedOr(ctx, credential, input.Body, "iam:delegations:read", func(ctx context.Context, tx core.IamStore, _ *Principal, delegation *core.Object) (any, error) {
		// Work handed on to other agents belongs to this delegation's story too.
		rootID := jsString(delegation.Get("id"))
		ids := newOrderedSet(rootID)
		pending := []string{rootID}
		for len(pending) > 0 && ids.Len() <= 1000 {
			parentID := pending[len(pending)-1]
			pending = pending[:len(pending)-1]
			children, err := tx.Find(ctx, "delegations", core.NewObject("tenantId", delegation.Get("tenantId"), "parentId", parentID), nil)
			if err != nil {
				return nil, err
			}
			for _, child := range children {
				childID := jsString(child.Get("id"))
				if !ids.Has(childID) {
					ids.Add(childID)
					pending = append(pending, childID)
				}
			}
		}
		events, err := AuditActivity(ctx, tx, jsString(delegation.Get("tenantId")), input.Body, func(event *core.Object) bool {
			if ids.Has(jsString(coalesce(event.Get("resourceId"), ""))) {
				return true
			}
			delegationID, ok := member(event.Get("sessionContext"), "delegationId").(string)
			return ok && ids.Has(delegationID)
		})
		if err != nil {
			return nil, err
		}
		list := make([]any, len(events))
		for index, event := range events {
			list[index] = event
		}
		return list, nil
	})
	if err != nil {
		return Out[apitypes.DelegationsActivityOutput]{}, err
	}
	return Out[apitypes.DelegationsActivityOutput]{Value: result}, nil
}

// Approve is POST {basePath}/delegations/approve. Approves an agent's pending request, optionally with a different scope, lifetime, or session cap.
//
// The person may narrow (or replace) its scope with `scopes`/`policy`, choose another `expiresInSeconds`, cap
// `maxSessionSeconds`, change `confirm`, state hand-offs (`handoff`; an agent's request for them counts only when the
// person states it here) and set, change or remove (`null`) a spending cap. Needs their own session with a recent
// sign-in. Audited as `delegation:approve`.
func (api *DelegationsAPI) Approve(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsApproveInput]) (Out[apitypes.DelegationsApproveOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsApproveOutput], error) {
		return Out[apitypes.DelegationsApproveOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	delegationID, err := Text(body.Get("delegationId"), "delegationId")
	if err != nil {
		return fail(err)
	}
	maxSessionSeconds, hasCap, err := delegationSessionCap(body.Get("maxSessionSeconds"))
	if err != nil {
		return fail(err)
	}
	var seconds float64
	hasSeconds := !isUndefined(body.Get("expiresInSeconds"))
	if hasSeconds {
		if seconds, err = DelegationSeconds(body.Get("expiresInSeconds")); err != nil {
			return fail(err)
		}
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := delegationAssertPerson(principal, tenantID); err != nil {
			return nil, err
		}
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		delegation, err := tx.Get(ctx, "delegations", delegationID)
		if err != nil {
			return nil, err
		}
		if delegation == nil || delegation.Get("tenantId") != tenantID || !core.StrictEquals(delegation.Get("subjectId"), principal.Identity.Get("id")) {
			return nil, delegationNotFound()
		}
		now := server.Now()
		if !delegationPending(delegation, now) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a pending request can be approved", 409)
		}
		if _, err := api.delegableAgent(ctx, tx, delegation.Get("agentId"), tenantID); err != nil {
			return nil, err
		}
		next := delegation.Spread(core.NewObject("status", "active", "decidedAt", float64(now)))
		if !isUndefined(body.Get("scopes")) || !isUndefined(body.Get("policy")) {
			scope, err := DelegationScope(ctx, server, tx, tenantID, body)
			if err != nil {
				return nil, err
			}
			next.Set("policy", scope.Get("policy"))
			if scopes := scope.Get("scopes"); truthy(scopes) {
				next.Set("scopes", scopes)
			} else {
				next.Delete("scopes")
			}
		}
		lifetime := seconds * 1000
		if !hasSeconds {
			lifetime = jsNumber(coalesce(delegation.Get("lifetimeMs"), DelegationLifetime.FallbackSeconds*1000))
		}
		next.Set("expiresAt", float64(now)+lifetime)
		next.Delete("lifetimeMs")
		if hasCap {
			next.Set("maxSessionSeconds", maxSessionSeconds)
		}
		// The person may add (or drop, with an empty list) actions to confirm one call at a time.
		if !isUndefined(body.Get("confirm")) {
			confirm, err := ConfirmPatterns(body.Get("confirm"))
			if err != nil {
				return nil, err
			}
			if confirm != nil {
				next.Set("confirm", stringsOf(confirm))
			} else {
				next.Delete("confirm")
			}
		}
		// Hand-offs widen what happens in the person's name, so an agent's request for them counts only when the person
		// states it themselves here: a plain approval leaves them out.
		handoff, err := HandoffSetting(ctx, tx, tenantID, body.Get("handoff"))
		if err != nil {
			return nil, err
		}
		if handoff != nil {
			next.Set("handoff", handoff)
		} else {
			next.Delete("handoff")
		}
		// And set, change, or (with null) remove a spending cap.
		if !isUndefined(body.Get("spend")) {
			spend, err := SpendSetting(body.Get("spend"))
			if err != nil {
				return nil, err
			}
			if spend != nil {
				next.Set("spend", spend)
			} else {
				next.Delete("spend")
			}
		}
		approved, err := tx.Put(ctx, "delegations", next)
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "delegation:approve", tenantID, jsString(delegation.Get("id")), "allow", false,
			core.NewObject("agentId", delegation.Get("agentId"), "expiresAt", approved.Get("expiresAt"))); err != nil {
			return nil, err
		}
		return api.summary(ctx, tx, approved)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsApproveOutput]{Value: result}, nil
}

// Assume is POST {basePath}/delegations/assume. Opens a delegated session in which the agent acts for the person, and returns its bearer token once.
//
// The token (`biam_dlg_…`) has the person as its identity, bounded by the delegation's scope, the agent's ceiling and an
// optional scope-down `policy`. Lasts `durationSeconds` (60 up to the agent's `maxDelegatedSessionSeconds` and the
// delegation's `maxSessionSeconds`; 900 or less by default), never past the delegation or the agent's key. Needs the
// agent's own API key; at most 20 live sessions per delegation. Audited as `delegation:assume`.
func (api *DelegationsAPI) Assume(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsAssumeInput]) (Out[apitypes.DelegationsAssumeOutput], error) {
	server := api.server
	if server.Auth.CurrentClient(ctx) == nil && credential.Headers != nil {
		ctx = server.Auth.WithClient(ctx, ClientFromHeaders(server.Options, credential.Headers, server.Config.BaseURL.Href))
	}
	result, err := api.assumeDelegation(ctx, credential, input.Body)
	if err != nil {
		return Out[apitypes.DelegationsAssumeOutput]{}, err
	}
	return Out[apitypes.DelegationsAssumeOutput]{Value: result}, nil
}

// DecideConfirmation is POST {basePath}/delegations/decideConfirmation. Approves or rejects an agent's pending confirmation request.
//
// From the person's own session. An approval allows exactly that action on that resource, once, for the agent acting
// for them, within the request's `validSeconds` (status `used` afterwards). Audited as `delegation:confirm` or
// `delegation:reject`.
func (api *DelegationsAPI) DecideConfirmation(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsDecideConfirmationInput]) (Out[apitypes.DelegationsDecideConfirmationOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsDecideConfirmationOutput], error) {
		return Out[apitypes.DelegationsDecideConfirmationOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	confirmationID, err := Text(body.Get("confirmationId"), "confirmationId")
	if err != nil {
		return fail(err)
	}
	approve, ok := body.Get("approve").(bool)
	if !ok {
		return fail(invalidInput("approve must be a boolean"))
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := delegationAssertPerson(principal, tenantID); err != nil {
			return nil, err
		}
		confirmation, err := tx.Get(ctx, "delegationConfirmations", confirmationID)
		if err != nil {
			return nil, err
		}
		if confirmation == nil || confirmation.Get("tenantId") != tenantID ||
			!core.StrictEquals(confirmation.Get("subjectId"), principal.Identity.Get("id")) {
			return nil, core.NewIamError("NOT_FOUND", "Confirmation request not found", 404)
		}
		now := server.Now()
		if confirmation.Get("status") != "pending" || jsNumber(confirmation.Get("expiresAt")) <= float64(now) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a pending request can be decided", 409)
		}
		delegation, err := tx.Get(ctx, "delegations", jsString(confirmation.Get("delegationId")))
		if err != nil {
			return nil, err
		}
		if delegation == nil || !delegationLive(delegation, now) {
			return nil, delegationInactive()
		}
		status, expiresAt := "rejected", float64(now)
		if approve {
			status, expiresAt = "approved", float64(now)+jsNumber(confirmation.Get("validSeconds"))*1000
		}
		decided, err := tx.Put(ctx, "delegationConfirmations", confirmation.Spread(core.NewObject(
			"status", status, "decidedAt", float64(now), "expiresAt", expiresAt,
		)))
		if err != nil {
			return nil, err
		}
		action := "delegation:reject"
		if approve {
			action = "delegation:confirm"
		}
		if err := server.Events.Audit(ctx, tx, principal, action, tenantID, jsString(delegation.Get("id")), "allow", false, core.NewObject(
			"confirmationId", confirmation.Get("id"),
			"action", confirmation.Get("action"),
			"resource", jsString(confirmation.Get("resourceType"))+"/"+jsString(confirmation.Get("resourceId")),
		)); err != nil {
			return nil, err
		}
		return api.confirmationSummary(ctx, tx, decided)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsDecideConfirmationOutput]{Value: result}, nil
}

// Deny is POST {basePath}/delegations/deny. Turns down an agent's pending request.
//
// Audited as `delegation:deny`.
func (api *DelegationsAPI) Deny(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsDenyInput]) (Out[apitypes.DelegationsDenyOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsDenyOutput], error) {
		return Out[apitypes.DelegationsDenyOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	delegationID, err := Text(body.Get("delegationId"), "delegationId")
	if err != nil {
		return fail(err)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := delegationAssertPerson(principal, tenantID); err != nil {
			return nil, err
		}
		delegation, err := tx.Get(ctx, "delegations", delegationID)
		if err != nil {
			return nil, err
		}
		if delegation == nil || delegation.Get("tenantId") != tenantID || !core.StrictEquals(delegation.Get("subjectId"), principal.Identity.Get("id")) {
			return nil, delegationNotFound()
		}
		if !delegationPending(delegation, server.Now()) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a pending request can be denied", 409)
		}
		denied, err := tx.Put(ctx, "delegations", delegation.Spread(core.NewObject("status", "denied", "decidedAt", float64(server.Now()))))
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "delegation:deny", tenantID, jsString(delegation.Get("id")), "allow", false,
			core.NewObject("agentId", delegation.Get("agentId"))); err != nil {
			return nil, err
		}
		return api.summary(ctx, tx, denied)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsDenyOutput]{Value: result}, nil
}

// Get is POST {basePath}/delegations/get. Returns one delegation to the person, the agent, or the agent's sponsor, or to an administrator.
//
// Agents poll this while a request is pending; administrators need `iam:delegations:read`.
func (api *DelegationsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsGetInput]) (Out[apitypes.DelegationsGetOutput], error) {
	result, err := api.involvedOr(ctx, credential, input.Body, "iam:delegations:read", func(ctx context.Context, tx core.IamStore, _ *Principal, delegation *core.Object) (any, error) {
		return api.summary(ctx, tx, delegation)
	})
	if err != nil {
		return Out[apitypes.DelegationsGetOutput]{}, err
	}
	return Out[apitypes.DelegationsGetOutput]{Value: result}, nil
}

// GetConfirmation is POST {basePath}/delegations/getConfirmation. Returns one confirmation request to the person it asks or to the agent that made it.
//
// Agents poll it while it is pending.
func (api *DelegationsAPI) GetConfirmation(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsGetConfirmationInput]) (Out[apitypes.DelegationsGetConfirmationOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsGetConfirmationOutput], error) {
		return Out[apitypes.DelegationsGetConfirmationOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	confirmationID, err := Text(body.Get("confirmationId"), "confirmationId")
	if err != nil {
		return fail(err)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		scope, err := delegationConfirmationScope(principal, tenantID)
		if err != nil {
			return nil, err
		}
		confirmation, err := tx.Get(ctx, "delegationConfirmations", confirmationID)
		if err != nil {
			return nil, err
		}
		mismatch := false
		if confirmation != nil {
			scope.Entries(func(key string, value any) bool {
				if !core.StrictEquals(confirmation.Get(key), value) {
					mismatch = true
					return false
				}
				return true
			})
		}
		if confirmation == nil || confirmation.Get("tenantId") != tenantID || mismatch {
			return nil, core.NewIamError("NOT_FOUND", "Confirmation request not found", 404)
		}
		return api.confirmationSummary(ctx, tx, confirmation)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsGetConfirmationOutput]{Value: result}, nil
}

// Grant is POST {basePath}/delegations/grant. Lets an agent act for you, within a scope and for a limited time.
//
// `scopes` (actions, wildcards allowed) or a `policy` bound what the agent may do, and it can never do more than the
// person could. Lasts `expiresInSeconds` (5 minutes to a year; 30 days by default); `maxSessionSeconds` caps each
// delegated session below the agent's own limit. Needs the person's own session with a recent sign-in; refused while
// an undecided request or an active delegation already links the two. Audited as `delegation:grant`.
func (api *DelegationsAPI) Grant(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsGrantInput]) (Out[apitypes.DelegationsGrantOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsGrantOutput], error) {
		return Out[apitypes.DelegationsGrantOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	seconds, err := DelegationSeconds(body.Get("expiresInSeconds"))
	if err != nil {
		return fail(err)
	}
	maxSessionSeconds, hasCap, err := delegationSessionCap(body.Get("maxSessionSeconds"))
	if err != nil {
		return fail(err)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := delegationAssertPerson(principal, tenantID); err != nil {
			return nil, err
		}
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		agent, err := api.delegableAgent(ctx, tx, body.Get("agentId"), tenantID)
		if err != nil {
			return nil, err
		}
		existing, err := api.liveBetween(ctx, tx, tenantID, jsString(agent.Get("id")), jsString(principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		if existing != nil {
			message := "You already delegate to this agent; revoke that delegation first"
			if existing.Get("status") == "pending" {
				message = "This agent is waiting for your decision on a request; approve or deny it"
			}
			return nil, core.NewIamError("DELEGATION_EXISTS", message, 409)
		}
		scope, err := DelegationScope(ctx, server, tx, tenantID, body)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		delegation := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"agentId", agent.Get("id"),
			"subjectId", principal.Identity.Get("id"),
			"status", "active",
			"policy", scope.Get("policy"),
			"requestedBy", "subject",
			"createdAt", now,
			"decidedAt", now,
			"expiresAt", now+seconds*1000,
		)
		if err := api.applyDelegationSettings(ctx, tx, tenantID, delegation, scope, maxSessionSeconds, hasCap, body); err != nil {
			return nil, err
		}
		if _, err := tx.Insert(ctx, "delegations", delegation); err != nil {
			return nil, err
		}
		metadata := core.NewObject("agentId", agent.Get("id"), "expiresAt", delegation.Get("expiresAt"))
		if scopes, ok := scopesText(scope, " "); ok {
			metadata.Set("scopes", scopes)
		}
		if err := server.Events.Audit(ctx, tx, principal, "delegation:grant", tenantID, jsString(delegation.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return api.summary(ctx, tx, delegation)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsGrantOutput]{Value: result}, nil
}

// Handoff is POST {basePath}/delegations/handoff. Hands part of the delegation an agent acts under on to another agent, for the same person.
//
// A new delegation from the same person to `agentId`, within `scopes`/`policy`. Needs a delegated session whose
// delegation lets the agent hand on (`handoff`, set by the person) to that agent. The hand-off never allows more than
// the delegations above it, the ceilings of the agents that handed it on, and the limits of the handing session (its
// scope-down policy, its key's scopes and issuer), and it works only while every delegation above it does. It keeps
// the person's `confirm` list (plus any given here) and lasts `expiresInSeconds` (60 seconds up to the delegation
// above; one hour by default). No agent may appear twice in a chain; at most 20 live hand-offs per delegation. Audited
// as `delegation:handoff`.
func (api *DelegationsAPI) Handoff(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsHandoffInput]) (Out[apitypes.DelegationsHandoffOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsHandoffOutput], error) {
		return Out[apitypes.DelegationsHandoffOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	reason, hasReason := "", !isUndefined(body.Get("reason"))
	if hasReason {
		if reason, err = Text(body.Get("reason"), "reason", 1024); err != nil {
			return fail(err)
		}
	}
	maxSessionSeconds, hasCap, err := delegationSessionCap(body.Get("maxSessionSeconds"))
	if err != nil {
		return fail(err)
	}
	seconds := 3600.0
	if raw := body.Get("expiresInSeconds"); !isUndefined(raw) {
		if seconds, err = Integer(raw, "expiresInSeconds", 60, DelegationLifetime.MaxSeconds); err != nil {
			return fail(err)
		}
	}
	extraConfirm, err := ConfirmPatterns(body.Get("confirm"))
	if err != nil {
		return fail(err)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	// Counted outside the transaction (a refusal cannot roll it back), per delegation handing on.
	if delegationID, ok := authenticated.Session.Get("delegationId").(string); ok {
		if err := server.Auth.LimitAttempt(ctx, tenantID, "delegation-handoff:"+delegationID, auth.LimitAttemptOptions{Tier: "sensitive"}); err != nil {
			return fail(err)
		}
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		session := principal.Session
		sessionDelegationID, hasDelegation := session.Get("delegationId").(string)
		sessionAgentID, hasAgent := session.Get("agentId").(string)
		if session.Get("kind") != "delegated" || session.Get("tenantId") != tenantID || !hasDelegation || !hasAgent {
			return nil, delegationRefuse("Only an agent acting for a person (a delegated session) can hand work on")
		}
		now := server.Now()
		parent, err := tx.Get(ctx, "delegations", sessionDelegationID)
		if err != nil {
			return nil, err
		}
		if parent == nil || !delegationLive(parent, now) || parent.Get("tenantId") != tenantID || parent.Get("agentId") != sessionAgentID ||
			!core.StrictEquals(parent.Get("subjectId"), principal.Identity.Get("id")) {
			return nil, delegationInactive()
		}
		if ancestors, err := LiveAncestors(ctx, server, tx, parent, now); err != nil {
			return nil, err
		} else if ancestors == nil {
			return nil, delegationInactive()
		}
		allowed := parent.Get("handoff")
		if !truthy(allowed) || jsNumber(member(allowed, "depth")) < 1 {
			return nil, core.NewIamError("DELEGATION_NOT_ALLOWED", "The person did not allow this delegation to be handed on", 403)
		}
		chain := append(copyStrings(coalesce(parent.Get("chain"), []any{})), parent.Get("agentId"))
		target, err := api.delegableAgent(ctx, tx, body.Get("agentId"), tenantID)
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(chain, func(item any) bool { return core.StrictEquals(item, target.Get("id")) }) {
			return nil, core.NewIamError("DELEGATION_NOT_ALLOWED", "An agent cannot receive a hand-off from its own delegation chain", 403)
		}
		if allowedAgents := member(allowed, "agents"); truthy(allowedAgents) {
			list, _ := allowedAgents.([]any)
			if !slices.ContainsFunc(list, func(item any) bool { return core.StrictEquals(item, target.Get("id")) }) {
				return nil, core.NewIamError("DELEGATION_NOT_ALLOWED", "The person did not allow hand-offs to this agent", 403)
			}
		}
		children, err := tx.Find(ctx, "delegations", core.NewObject("tenantId", tenantID, "parentId", parent.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		live := 0.0
		for _, item := range children {
			if delegationLive(item, now) {
				live++
			}
		}
		if live >= HandoffLimits.MaxLive {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "This delegation holds the maximum number of live hand-offs", 409)
		}
		scope, err := DelegationScope(ctx, server, tx, tenantID, body)
		if err != nil {
			return nil, err
		}
		// The key the handing agent acts with: the hand-off never outlives it, and ends when it is revoked.
		var key *core.Object
		if sourceID, ok := session.Get("sourceSessionId").(string); ok {
			if key, err = tx.Get(ctx, "sessions", sourceID); err != nil {
				return nil, err
			}
		}
		if key == nil || key.Get("kind") != "api-key" || !core.StrictEquals(key.Get("identityId"), parent.Get("agentId")) {
			return nil, delegationInactive()
		}
		nowMs := float64(now)
		delegation := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"agentId", target.Get("id"),
			"subjectId", parent.Get("subjectId"),
			"status", "active",
			"policy", scope.Get("policy"),
			"requestedBy", "handoff",
			"createdAt", nowMs,
			"decidedAt", nowMs,
			"expiresAt", math.Min(math.Min(nowMs+seconds*1000, jsNumber(parent.Get("expiresAt"))), jsNumber(key.Get("expiresAt"))),
			"parentId", parent.Get("id"),
			"chain", chain,
			"keyId", key.Get("id"),
		)
		if scopes := scope.Get("scopes"); truthy(scopes) {
			delegation.Set("scopes", scopes)
		}
		if hasReason {
			delegation.Set("reason", reason)
		}
		caps := []float64{}
		if hasCap {
			caps = append(caps, maxSessionSeconds)
		}
		if parentCap := parent.Get("maxSessionSeconds"); !isUndefined(parentCap) {
			caps = append(caps, jsNumber(parentCap))
		}
		if len(caps) > 0 {
			smallest := caps[0]
			for _, value := range caps[1:] {
				smallest = math.Min(smallest, value)
			}
			delegation.Set("maxSessionSeconds", smallest)
		}
		combined := append(copyStrings(coalesce(parent.Get("confirm"), []any{})), stringsOf(extraConfirm)...)
		confirm, err := ConfirmPatterns(combined)
		if err != nil {
			return nil, err
		}
		if confirm != nil {
			delegation.Set("confirm", stringsOf(confirm))
		}
		if depth := jsNumber(member(allowed, "depth")); depth > 1 {
			handoff := core.NewObject("depth", depth-1)
			if allowedAgents := member(allowed, "agents"); truthy(allowedAgents) {
				handoff.Set("agents", copyStrings(allowedAgents))
			}
			delegation.Set("handoff", handoff)
		}
		// The handing session's own limits travel with the hand-off.
		ceilings := []any{}
		for _, policy := range []any{session.Get("policy"), session.Get("sourcePolicy")} {
			if truthy(policy) {
				ceilings = append(ceilings, policy)
			}
		}
		if len(ceilings) > 0 {
			delegation.Set("ceilings", ceilings)
		}
		if authorityID, ok := session.Get("credentialAuthorityId").(string); ok {
			delegation.Set("authorityId", authorityID)
		}
		// A cap of its own, on top of the caps of the delegations above (which count the hand-off's calls too).
		spend, err := SpendSetting(body.Get("spend"))
		if err != nil {
			return nil, err
		}
		if spend != nil {
			delegation.Set("spend", spend)
		}
		if _, err := tx.Insert(ctx, "delegations", delegation); err != nil {
			return nil, err
		}
		metadata := core.NewObject(
			"parentId", parent.Get("id"),
			"fromAgentId", parent.Get("agentId"),
			"toAgentId", target.Get("id"),
			"depth", float64(len(chain)),
		)
		if scopes, ok := scopesText(scope, " "); ok {
			metadata.Set("scopes", scopes)
		}
		if err := server.Events.Audit(ctx, tx, principal, "delegation:handoff", tenantID, jsString(delegation.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return api.summary(ctx, tx, delegation)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsHandoffOutput]{Value: result}, nil
}

// IssueToken is POST {basePath}/delegations/issueToken. Gives an agent acting for a person a delegation token: a short-lived signed JWT that shows one service outside Better IAM that the agent acts for that person.
//
// A JWT signed with the deployment's `a2a` keys (`typ` `biam-delegation+jwt`) whose `sub` is the person and whose `act`
// claim is the agent, with the agents that handed the work to it nested inside (RFC 8693). `audience` must be one
// service that every agent in the chain lists in its `tokenAudiences`. `scopes` (the delegation's own by default) must
// each be allowed outright by every limit on the session, and none may be an action the person confirms call by call,
// or one a deny among the person's own grants could touch. Lasts `lifetimeSeconds` (30 to 3600; 300 by default), never
// past the session or a delegation in the chain. Needs the `a2a` option. Rate limited per delegation. Audited as
// `delegation:token-issue`.
func (api *DelegationsAPI) IssueToken(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsIssueTokenInput]) (Out[apitypes.DelegationsIssueTokenOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsIssueTokenOutput], error) {
		return Out[apitypes.DelegationsIssueTokenOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	audience, err := TokenAudience(body.Get("audience"))
	if err != nil {
		return fail(err)
	}
	var requested []string
	hasRequested := !isUndefined(body.Get("scopes"))
	if hasRequested {
		list, err := Strings(body.Get("scopes"), "scopes")
		if err != nil {
			return fail(err)
		}
		requested = unique(list)
	}
	lifetime := float64(core.DelegationTokenLimits.DefaultSeconds)
	if raw := body.Get("lifetimeSeconds"); !isUndefined(raw) {
		if lifetime, err = Integer(raw, "lifetimeSeconds", float64(core.DelegationTokenLimits.MinSeconds), float64(core.DelegationTokenLimits.MaxSeconds)); err != nil {
			return fail(err)
		}
	}
	signer, err := CardSigner(server)
	if err != nil {
		return fail(err)
	}
	if signer == nil {
		return fail(core.NewIamError("FEATURE_DISABLED", "Delegation tokens need the deployment’s a2a signing keys", 403))
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	// Counted outside the transaction, per delegation, in a budget of its own.
	if delegationID, ok := authenticated.Session.Get("delegationId").(string); ok {
		limit := int64(120)
		if err := server.Auth.LimitAttempt(ctx, tenantID, "delegation-token:"+delegationID, auth.LimitAttemptOptions{Limit: &limit}); err != nil {
			return fail(err)
		}
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		session := principal.Session
		sessionDelegationID, hasDelegation := session.Get("delegationId").(string)
		sessionAgentID, hasAgent := session.Get("agentId").(string)
		if session.Get("kind") != "delegated" || session.Get("tenantId") != tenantID || !hasDelegation || !hasAgent {
			return nil, delegationRefuse("Only an agent acting for a person (a delegated session) gets delegation tokens")
		}
		now := server.Now()
		delegation, err := tx.Get(ctx, "delegations", sessionDelegationID)
		if err != nil {
			return nil, err
		}
		var ancestors []DelegationAncestor
		if delegation != nil {
			if ancestors, err = LiveAncestors(ctx, server, tx, delegation, now); err != nil {
				return nil, err
			}
		}
		agent, err := tx.Get(ctx, "identities", sessionAgentID)
		if err != nil {
			return nil, err
		}
		tenant, err := tx.Get(ctx, "tenants", tenantID)
		if err != nil {
			return nil, err
		}
		// The agent's API key the session came from: the token is live only while it is.
		var key *core.Object
		if sourceID, ok := session.Get("sourceSessionId").(string); ok {
			if key, err = tx.Get(ctx, "sessions", sourceID); err != nil {
				return nil, err
			}
		}
		if delegation == nil || ancestors == nil || agent == nil || tenant == nil || key == nil ||
			key.Get("kind") != "api-key" || key.Get("identityId") != sessionAgentID ||
			!delegationLive(delegation, now) || delegation.Get("tenantId") != tenantID ||
			!core.StrictEquals(delegation.Get("agentId"), agent.Get("id")) ||
			!core.StrictEquals(delegation.Get("subjectId"), principal.Identity.Get("id")) {
			return nil, delegationInactive()
		}
		// Every agent the work passed through must be allowed to present it to this service.
		agents := make([]*core.Object, 0, len(ancestors)+1)
		for index := len(ancestors) - 1; index >= 0; index-- {
			agents = append(agents, ancestors[index].Agent)
		}
		agents = append(agents, agent)
		if outsider, _ := AudienceRefusal(agents, audience); outsider != nil {
			return nil, core.NewIamError("DELEGATION_NOT_ALLOWED", "Agent "+jsString(outsider.Get("name"))+" may not present delegations to "+audience, 403)
		}
		scopes := requested
		if !hasRequested {
			scopes = stringItems(coalesce(delegation.Get("scopes"), []any{}))
		}
		if scopes == nil {
			scopes = []string{}
		}
		invalidScope := len(scopes) > 50
		for _, scope := range scopes {
			if !core.DelegationTokenScopePattern.MatchString(scope) {
				invalidScope = true
			}
		}
		if invalidScope {
			return nil, invalidInput("scopes must list at most 50 actions or action patterns (letters, digits, :_./- and *)")
		}
		sessionPolicies := []any{}
		for _, policy := range []any{session.Get("policy"), session.Get("sourcePolicy")} {
			if truthy(policy) {
				sessionPolicies = append(sessionPolicies, policy)
			}
		}
		authorityID, hasAuthority := session.Get("credentialAuthorityId").(string)
		authorityIDs := []string{}
		if hasAuthority && authorityID != "" {
			authorityIDs = append(authorityIDs, authorityID)
		}
		refusal, err := ScopeRefusal(ctx, server, tx, &TokenBasis{
			Tenant:          tenant,
			PersonID:        jsString(principal.Identity.Get("id")),
			Delegation:      delegation,
			Ancestors:       ancestors,
			Agents:          agents,
			SessionPolicies: sessionPolicies,
			AuthorityIDs:    authorityIDs,
		}, scopes)
		if err != nil {
			return nil, err
		}
		if refusal != nil && refusal.Has("inactive") {
			return nil, delegationInactive()
		}
		if refusal != nil {
			scope := jsString(refusal.Get("scope"))
			message := "The delegation does not allow " + scope + " outright"
			switch refusal.Get("why") {
			case "confirm":
				message = "The person confirms " + scope + " call by call; a token cannot carry it"
			case "deny":
				message = "A deny statement of the person's own access may touch " + scope
			}
			return nil, core.NewIamError("DELEGATION_NOT_ALLOWED", message, 403)
		}
		issuedAt := math.Floor(float64(now) / 1000)
		expiresAt := issuedAt + lifetime
		bounds := []*core.Object{session, delegation}
		for _, ancestor := range ancestors {
			bounds = append(bounds, ancestor.Delegation)
		}
		for _, item := range bounds {
			expiresAt = math.Min(expiresAt, math.Floor(jsNumber(item.Get("expiresAt"))/1000))
		}
		if expiresAt <= issuedAt {
			return nil, delegationInactive()
		}
		chain := make([]string, len(agents))
		for index, item := range agents {
			chain[index] = jsString(item.Get("id"))
		}
		actor, err := core.NewDelegationActor(chain)
		if err != nil {
			return nil, err
		}
		tokenID := Token()
		claims := core.NewObject(
			"iss", signer.Issuer,
			"sub", principal.Identity.Get("id"),
			"aud", audience,
			"iat", issuedAt,
			"nbf", issuedAt,
			"exp", expiresAt,
			"jti", tokenID,
			"tenant_id", tenantID,
			"delegation_id", delegation.Get("id"),
			"act", actor,
		)
		if len(scopes) > 0 {
			claims.Set("scope", strings.Join(scopes, " "))
		}
		token, err := signer.SignJwt(ctx, claims.Spread(), core.DelegationTokenType)
		if err != nil {
			return nil, err
		}
		// Kept until it expires, so a live verification can re-check what the token stands on.
		record := core.NewObject(
			"id", tokenID,
			"tenantId", tenantID,
			"delegationId", delegation.Get("id"),
			"personId", principal.Identity.Get("id"),
			"agentId", agent.Get("id"),
			"keyId", key.Get("id"),
			"audience", audience,
			"scopes", stringsOf(scopes),
			"sessionPolicies", sessionPolicies,
		)
		if hasAuthority && authorityID != "" {
			record.Set("authorityId", authorityID)
		}
		record.Set("createdAt", float64(now))
		record.Set("expiresAt", expiresAt*1000)
		if _, err := tx.Insert(ctx, "delegationTokens", record); err != nil {
			return nil, err
		}
		metadata := core.NewObject("audience", audience, "tokenId", tokenID, "expiresAt", expiresAt*1000)
		if len(scopes) > 0 {
			metadata.Set("scopes", strings.Join(scopes, " "))
		}
		if err := server.Events.Audit(ctx, tx, principal, "delegation:token-issue", tenantID, jsString(delegation.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return core.NewObject(
			"token", token,
			"tokenType", core.DelegationTokenType,
			"tokenId", tokenID,
			"issuer", signer.Issuer,
			"audience", audience,
			"scopes", stringsOf(scopes),
			"chain", stringsOf(chain),
			"expiresAt", expiresAt*1000,
			"expiresIn", expiresAt-issuedAt,
		), nil
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsIssueTokenOutput]{Value: result}, nil
}

// List is POST {basePath}/delegations/list. Lists the tenant's delegations, newest first, filtered by agent, person, or status.
//
// Needs `iam:delegations:read`.
func (api *DelegationsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsListInput]) (Out[apitypes.DelegationsListOutput], error) {
	server := api.server
	body := input.Body
	rawTenantID := body.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:delegations:read", jsString(rawTenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		filter := core.NewObject("tenantId", rawTenantID)
		if agentID := body.Get("agentId"); !isUndefined(agentID) {
			value, err := Text(agentID, "agentId")
			if err != nil {
				return nil, err
			}
			filter.Set("agentId", value)
		}
		if subjectID := body.Get("subjectId"); !isUndefined(subjectID) {
			value, err := Text(subjectID, "subjectId")
			if err != nil {
				return nil, err
			}
			filter.Set("subjectId", value)
		}
		if status := body.Get("status"); !isUndefined(status) {
			value, err := Text(status, "status", 16)
			if err != nil {
				return nil, err
			}
			filter.Set("status", value)
		}
		found, err := call.Tx.Find(ctx, "delegations", filter, nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(found, ByNewest)
		return api.summaries(ctx, call.Tx, found)
	}, false)
	if err != nil {
		return Out[apitypes.DelegationsListOutput]{}, err
	}
	return Out[apitypes.DelegationsListOutput]{Value: result}, nil
}

// ListConfirmations is POST {basePath}/delegations/listConfirmations. Lists confirmation requests newest first: those addressed to the caller, or those the calling agent made.
//
// For a person, the ones addressed to them; for an agent's own key, every one it made; for a delegated session, those
// of its delegation. `status` filters. Needs no permission.
func (api *DelegationsAPI) ListConfirmations(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsListConfirmationsInput]) (Out[apitypes.DelegationsListConfirmationsOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsListConfirmationsOutput], error) {
		return Out[apitypes.DelegationsListConfirmationsOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		scope, err := delegationConfirmationScope(principal, tenantID)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenantID).Assign(scope)
		if status := body.Get("status"); !isUndefined(status) {
			value, err := Text(status, "status", 16)
			if err != nil {
				return nil, err
			}
			filter.Set("status", value)
		}
		found, err := tx.Find(ctx, "delegationConfirmations", filter, nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(found, ByNewest)
		list := make([]any, len(found))
		for index, item := range found {
			summary, err := api.confirmationSummary(ctx, tx, item)
			if err != nil {
				return nil, err
			}
			list[index] = summary
		}
		return list, nil
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsListConfirmationsOutput]{Value: result}, nil
}

// ListMine is POST {basePath}/delegations/listMine. Returns your own delegations, newest first: the agents acting or asking to act for you, or, for an agent, the people it acts for.
//
// Needs no permission.
func (api *DelegationsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsListMineInput]) (Out[apitypes.DelegationsListMineOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.DelegationsListMineOutput], error) {
		return Out[apitypes.DelegationsListMineOutput]{}, err
	}
	tenantID, err := Text(input.Body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenantID)
		if principal.Identity.Get("kind") == "agent" {
			if err := delegationAssertAgentKey(principal, tenantID); err != nil {
				return nil, err
			}
			filter.Set("agentId", principal.Identity.Get("id"))
		} else {
			if err := delegationAssertPerson(principal, tenantID); err != nil {
				return nil, err
			}
			filter.Set("subjectId", principal.Identity.Get("id"))
		}
		found, err := tx.Find(ctx, "delegations", filter, nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(found, ByNewest)
		return api.summaries(ctx, tx, found)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsListMineOutput]{Value: result}, nil
}

// Request is POST {basePath}/delegations/request. Asks a person to delegate to the calling agent, and emails them the request when the deployment sends email.
//
// The person is named by `subjectId` or `subjectEmail`; the request waits up to seven days for their decision and is
// emailed to them (template `delegation-request`). `reason` is shown to the person; `expiresInSeconds` is how long
// the delegation lasts once approved. Needs the agent's own API key. Requests are rate limited per agent. Audited as
// `delegation:request`.
func (api *DelegationsAPI) Request(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsRequestInput]) (Out[apitypes.DelegationsRequestOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsRequestOutput], error) {
		return Out[apitypes.DelegationsRequestOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	reason, err := Text(body.Get("reason"), "reason", 1024)
	if err != nil {
		return fail(err)
	}
	seconds, err := DelegationSeconds(body.Get("expiresInSeconds"))
	if err != nil {
		return fail(err)
	}
	maxSessionSeconds, hasCap, err := delegationSessionCap(body.Get("maxSessionSeconds"))
	if err != nil {
		return fail(err)
	}
	if isUndefined(body.Get("subjectId")) == isUndefined(body.Get("subjectEmail")) {
		return fail(invalidInput("Provide either subjectId or subjectEmail"))
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	if err := delegationAssertAgentKey(authenticated, tenantID); err != nil {
		return fail(err)
	}
	// Counted outside any transaction, so a refused request cannot roll the attempt back.
	if err := server.Auth.LimitAttempt(ctx, tenantID, "delegation-request:"+jsString(authenticated.Identity.Get("id")),
		auth.LimitAttemptOptions{Tier: "sensitive"}); err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := delegationAssertAgentKey(principal, tenantID); err != nil {
			return nil, err
		}
		agent, err := api.delegableAgent(ctx, tx, principal.Identity.Get("id"), tenantID)
		if err != nil {
			return nil, err
		}
		var subject *core.Object
		if subjectID := body.Get("subjectId"); !isUndefined(subjectID) {
			id, err := Text(subjectID, "subjectId")
			if err != nil {
				return nil, err
			}
			if subject, err = tx.Get(ctx, "identities", id); err != nil {
				return nil, err
			}
		} else {
			address, err := Email(body.Get("subjectEmail"))
			if err != nil {
				return nil, err
			}
			found, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", address), nil)
			if err != nil {
				return nil, err
			}
			if len(found) > 0 {
				subject = found[0]
			}
		}
		if subject == nil || subject.Get("tenantId") != tenantID || subject.Get("kind") != "user" || subject.Get("status") != "active" ||
			server.IdentityExpired(subject) {
			return nil, core.NewIamError("NOT_FOUND", "No active person with that identifier", 404)
		}
		existing, err := api.liveBetween(ctx, tx, tenantID, jsString(agent.Get("id")), jsString(subject.Get("id")))
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, core.NewIamError("DELEGATION_EXISTS", "A request or delegation between this agent and person already exists", 409)
		}
		scope, err := DelegationScope(ctx, server, tx, tenantID, body)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		delegation := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"agentId", agent.Get("id"),
			"subjectId", subject.Get("id"),
			"status", "pending",
			"policy", scope.Get("policy"),
			"requestedBy", "agent",
			"reason", reason,
			"createdAt", now,
			"expiresAt", now+DelegationLifetime.RequestMs,
			"lifetimeMs", seconds*1000,
		)
		if err := api.applyDelegationSettings(ctx, tx, tenantID, delegation, scope, maxSessionSeconds, hasCap, body); err != nil {
			return nil, err
		}
		if _, err := tx.Insert(ctx, "delegations", delegation); err != nil {
			return nil, err
		}
		if email := subject.Get("email"); truthy(email) && api.sendsEmail() {
			scopes, ok := scopesText(scope, ", ")
			if !ok {
				scopes = "a custom policy"
			}
			payload := core.NewObject(
				"delegationId", delegation.Get("id"),
				"agentName", agent.Get("name"),
				"reason", reason,
				"scopes", scopes,
				"days", jsString(math.Max(1, jsMathRound(seconds/86_400))),
			)
			if model := member(agent.Get("agent"), "model"); truthy(model) {
				payload.Set("model", model)
			}
			if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
				TenantID: tenantID, Kind: "email", To: jsString(email), Template: "delegation-request", Payload: payload,
			}); err != nil {
				return nil, err
			}
		}
		metadata := core.NewObject("subjectId", subject.Get("id"))
		if scopes, ok := scopesText(scope, " "); ok {
			metadata.Set("scopes", scopes)
		}
		if err := server.Events.Audit(ctx, tx, principal, "delegation:request", tenantID, jsString(delegation.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return api.summary(ctx, tx, delegation)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsRequestOutput]{Value: result}, nil
}

// RequestConfirmation is POST {basePath}/delegations/requestConfirmation. Asks the person an agent acts for to confirm one action the delegation holds back.
//
// From the agent's delegated session: `action` on `resource`, with a `reason` shown to the person. The request waits up
// to 30 minutes and is emailed to the person (template `delegation-confirmation`); an identical pending request is
// returned as it is. Once approved, that action on that resource is allowed once, within `validSeconds` (30 to 3600;
// 300 by default). Rate limited per delegation. Audited as `delegation:confirmation-request`.
func (api *DelegationsAPI) RequestConfirmation(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsRequestConfirmationInput]) (Out[apitypes.DelegationsRequestConfirmationOutput], error) {
	server := api.server
	body := input.Body
	fail := func(err error) (Out[apitypes.DelegationsRequestConfirmationOutput], error) {
		return Out[apitypes.DelegationsRequestConfirmationOutput]{}, err
	}
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	action, err := Text(body.Get("action"), "action", 256)
	if err != nil {
		return fail(err)
	}
	resource, err := Object(body.Get("resource"))
	if err != nil {
		return fail(err)
	}
	resourceType, err := Text(resource.Get("type"), "resource type", 64)
	if err != nil {
		return fail(err)
	}
	resourceID, err := Text(resource.Get("id"), "resource id", 2048)
	if err != nil {
		return fail(err)
	}
	reason, err := Text(body.Get("reason"), "reason", 1024)
	if err != nil {
		return fail(err)
	}
	validSeconds := ConfirmationLimits.FallbackValidSeconds
	if raw := body.Get("validSeconds"); !isUndefined(raw) {
		if validSeconds, err = Integer(raw, "validSeconds", ConfirmationLimits.MinValidSeconds, ConfirmationLimits.MaxValidSeconds); err != nil {
			return fail(err)
		}
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	sessionDelegationID, hasDelegation := authenticated.Session.Get("delegationId").(string)
	if authenticated.Session.Get("kind") != "delegated" || authenticated.Session.Get("tenantId") != tenantID || !hasDelegation {
		return fail(delegationRefuse("Only an agent acting for a person can ask them to confirm an action"))
	}
	// Counted outside any transaction, so a refused request cannot roll the attempt back.
	if err := server.Auth.LimitAttempt(ctx, tenantID, "delegation-confirm:"+sessionDelegationID, auth.LimitAttemptOptions{}); err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		delegation, err := tx.Get(ctx, "delegations", jsString(principal.Session.Get("delegationId")))
		if err != nil {
			return nil, err
		}
		if delegation == nil {
			return nil, core.NewIamError("UNAUTHENTICATED", "Delegation revoked", 401)
		}
		if !NeedsConfirmation(delegation, action) {
			return nil, invalidInput("This delegation does not hold that action back for confirmation")
		}
		now := server.Now()
		pendingRequests, err := tx.Find(ctx, "delegationConfirmations", core.NewObject(
			"tenantId", tenantID, "delegationId", delegation.Get("id"), "status", "pending",
		), nil)
		if err != nil {
			return nil, err
		}
		for _, item := range pendingRequests {
			if jsNumber(item.Get("expiresAt")) > float64(now) && item.Get("action") == action && item.Get("resourceType") == resourceType &&
				item.Get("resourceId") == resourceID {
				return api.confirmationSummary(ctx, tx, item)
			}
		}
		confirmation := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"delegationId", delegation.Get("id"),
			"agentId", delegation.Get("agentId"),
			"subjectId", delegation.Get("subjectId"),
			"action", action,
			"resourceType", resourceType,
			"resourceId", resourceID,
			"reason", reason,
			"status", "pending",
			"createdAt", float64(now),
			"expiresAt", float64(now)+ConfirmationLimits.DecideMs,
			"validSeconds", validSeconds,
		)
		if _, err := tx.Insert(ctx, "delegationConfirmations", confirmation); err != nil {
			return nil, err
		}
		agent, err := tx.Get(ctx, "identities", jsString(delegation.Get("agentId")))
		if err != nil {
			return nil, err
		}
		if email := principal.Identity.Get("email"); truthy(email) && api.sendsEmail() {
			var agentName any = "An AI agent"
			if agent != nil {
				agentName = coalesce(agent.Get("name"), "An AI agent")
			}
			if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
				TenantID: tenantID, Kind: "email", To: jsString(email), Template: "delegation-confirmation",
				Payload: core.NewObject(
					"delegationId", delegation.Get("id"),
					"confirmationId", confirmation.Get("id"),
					"agentName", agentName,
					"action", action,
					"resource", resourceType+"/"+resourceID,
					"reason", reason,
					"minutes", jsString(jsMathRound(ConfirmationLimits.DecideMs/60_000)),
				),
			}); err != nil {
				return nil, err
			}
		}
		if err := server.Events.Audit(ctx, tx, principal, "delegation:confirmation-request", tenantID, jsString(delegation.Get("id")), "allow", false,
			core.NewObject("confirmationId", confirmation.Get("id"), "action", action, "resource", resourceType+"/"+resourceID)); err != nil {
			return nil, err
		}
		return api.confirmationSummary(ctx, tx, confirmation)
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.DelegationsRequestConfirmationOutput]{Value: result}, nil
}

// Revoke is POST {basePath}/delegations/revoke. Ends a pending or active delegation and deletes its live delegated sessions at once.
//
// The person, the agent (with its own key), the agent's sponsor or an administrator with `iam:delegations:revoke` may
// revoke. Audited as `delegation:revoke`.
func (api *DelegationsAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.DelegationsRevokeInput]) (Out[apitypes.DelegationsRevokeOutput], error) {
	body := input.Body
	reason := ""
	if raw := body.Get("reason"); !isUndefined(raw) {
		value, err := Text(raw, "reason", 512)
		if err != nil {
			return Out[apitypes.DelegationsRevokeOutput]{}, err
		}
		reason = value
	}
	result, err := api.involvedOr(ctx, credential, body, "iam:delegations:revoke", func(ctx context.Context, tx core.IamStore, principal *Principal, delegation *core.Object) (any, error) {
		return api.revokeDelegation(ctx, tx, principal, delegation, reason)
	})
	if err != nil {
		return Out[apitypes.DelegationsRevokeOutput]{}, err
	}
	return Out[apitypes.DelegationsRevokeOutput]{Value: result}, nil
}
