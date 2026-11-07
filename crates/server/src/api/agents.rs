//! Port of `packages/server/src/api/agents.ts`: the `agents` group (AI agents as accounts), the agent mutations
//! configuration sync shares (`agentMutations`), and the paged audit reads of agent activity (`auditActivity`).

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, IdentityKind, OrderOptions, Record, SessionKind, Tenant,
    find_ordered, js as core_js,
};
use futures::future::BoxFuture;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::agents::{agent_profile, agent_standing, agent_summary, sponsor_for};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationResult};
use crate::js::number;
use crate::metrics::locale_compare;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::port::decode;
use crate::session_kinds::acts_in_own_right;
use crate::utils::{by_newest_records, id};
use crate::validation::{integer, text};
use better_iam_types::api::agents;

/// Paging of activity reads: newest first, 1-500 events (100 by default), optionally between `from` and `to`.
/// [`audit_activity`] reads these members from the request object (validating them as TypeScript does); this type
/// documents the shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActivityQuery {
    #[serde(rename = "limit", default, skip_serializing_if = "Option::is_none")]
    pub limit: Option<f64>,
    #[serde(rename = "offset", default, skip_serializing_if = "Option::is_none")]
    pub offset: Option<f64>,
    #[serde(rename = "from", default, skip_serializing_if = "Option::is_none")]
    pub from: Option<f64>,
    #[serde(rename = "to", default, skip_serializing_if = "Option::is_none")]
    pub to: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `query.member ?? fallback`.
fn or_default(value: Option<&Value>, fallback: f64) -> Value {
    match value {
        None | Some(Value::Null) => number(fallback),
        Some(value) => value.clone(),
    }
}

/// Audit events newest first in a tenant that match `where`, with the paging of an activity query (`limit`,
/// `offset`, `from`, `to` of `query`, the request object).
pub async fn audit_activity(
    tx: &Store,
    tenant_id: &str,
    query: &Map<String, Value>,
    r#where: &(dyn Fn(&Record) -> bool + Send + Sync),
) -> IamResult<Vec<Record>> {
    let limit = integer(
        Some(&or_default(query.get("limit"), 100.0)),
        "limit",
        1.0,
        500.0,
    )?;
    let offset = integer(
        Some(&or_default(query.get("offset"), 0.0)),
        "offset",
        0.0,
        100_000.0,
    )?;
    let from = match query.get("from") {
        Some(value) => Some(integer(
            Some(value),
            "from",
            0.0,
            core_js::MAX_SAFE_INTEGER,
        )?),
        None => None,
    };
    let to = match query.get("to") {
        Some(value) => Some(integer(Some(value), "to", 0.0, core_js::MAX_SAFE_INTEGER)?),
        None => None,
    };
    find_ordered(
        tx.as_ref(),
        "audit",
        &Filter::new().eq("tenantId", tenant_id.to_owned()),
        &OrderOptions {
            direction: better_iam_core::Direction::Desc,
            limit: Some(limit as i64),
            offset: Some(offset as i64),
            from,
            to,
            ..OrderOptions::by("timestamp")
        },
        Some(r#where),
    )
    .await
}

/// A person's own session of the tenant (not a role, token, delegated or impersonation session).
fn personal_session(principal: &AuthenticatedPrincipal, tenant_id: &str) -> bool {
    acts_in_own_right(principal.session.kind)
        && principal.identity.kind == IdentityKind::User
        && principal.identity.tenant_id == tenant_id
        && principal.session.tenant_id == tenant_id
        && !impersonating(principal)
}

/// `principal.session.impersonatorId` is truthy.
fn impersonating(principal: &AuthenticatedPrincipal) -> bool {
    principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
}

/// Naming someone other than oneself as an agent's sponsor makes them accountable for it and moves the agent's spend
/// onto their teams and department, so it needs the right to change that person: iam:identities:update on them
/// (which owners and root administrators hold). Checked before the sponsor is validated, so it reveals nothing about
/// them.
async fn authorize_sponsor(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    sponsor_id: Option<&Value>,
) -> IamResult<()> {
    let sponsor = text(sponsor_id, "sponsorId", 256)?;
    if sponsor == principal.identity.id && personal_session(principal, tenant_id) {
        return Ok(());
    }
    let decision = ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: "iam:identities:update".into(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: sponsor,
                },
            },
            true,
        )
        .await?;
    if !decision.allowed {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Naming another person as the sponsor needs iam:identities:update on them",
            403,
        ));
    }
    Ok(())
}

/// JWT claim names a signed agent card may not carry at its top level (see `signCard`).
const TOKEN_CLAIM_NAMES: [&str; 16] = [
    // RFC 7519 registered claims.
    "iss",
    "sub",
    "aud",
    "exp",
    "nbf",
    "iat",
    "jti",
    // Token exchange and proof of possession (RFC 8693, RFC 7800) and common authorization claims.
    "act",
    "may_act",
    "scope",
    "scp",
    "client_id",
    "azp",
    "cnf",
    // Delegation tokens (delegations.issueToken).
    "tenant_id",
    "delegation_id",
];

/// A string member of a record (`record.key`), or "".
fn member<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// `agent.agent?.key` of a stored identity.
fn profile_member<'a>(record: &'a Record, key: &str) -> Option<&'a Value> {
    record.get("agent").and_then(|profile| profile.get(key))
}

/// `tx.find('identities', { tenantId, kind: 'agent' })`.
async fn agents_of(tx: &Store, tenant_id: &str) -> IamResult<Vec<Record>> {
    tx.find(
        "identities",
        &Filter::new()
            .eq("tenantId", tenant_id.to_owned())
            .eq("kind", "agent"),
        &FindOptions::default(),
    )
    .await
}

/// Agent changes without a credential, for the `agents` API (which authorizes first) and for configuration sync
/// (ai-sync.ts). Every function runs inside the caller's transaction and audits like the API.
#[derive(Clone)]
pub struct AgentMutations {
    ctx: Arc<ServerContext>,
}

/// `agentMutations(ctx)`.
pub fn agent_mutations(ctx: &Arc<ServerContext>) -> AgentMutations {
    AgentMutations { ctx: ctx.clone() }
}

impl AgentMutations {
    /// Registers an agent sponsored by `input.sponsorId`; counts toward the tenant's `agents` limit. `input` is the
    /// create request object (`tenantId` is not read) with the sponsor already chosen. Returns the stored record.
    pub async fn create_agent(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant: &Tenant,
        input: &Map<String, Value>,
    ) -> IamResult<Record> {
        let ctx = &self.ctx;
        let name = text(input.get("name"), "name", 256)?;
        let sponsor = sponsor_for(ctx, tx, &tenant.id, input.get("sponsorId")).await?;
        ctx.enforce_limit(
            tenant,
            "agents",
            || async {
                Ok(agents_of(tx, &tenant.id)
                    .await?
                    .iter()
                    .filter(|item| item.get("status").and_then(Value::as_str) != Some("deleted"))
                    .count() as f64)
            },
            None,
        )
        .await?;
        let mut previous = Map::new();
        previous.insert("sponsorId".into(), Value::String(sponsor.id.clone()));
        let mut agent = Map::new();
        agent.insert("id".into(), Value::String(id()));
        agent.insert("tenantId".into(), Value::String(tenant.id.clone()));
        agent.insert("kind".into(), Value::String("agent".into()));
        agent.insert("name".into(), Value::String(name));
        agent.insert("status".into(), Value::String("active".into()));
        agent.insert("emailVerified".into(), Value::Bool(false));
        agent.insert("owner".into(), Value::Bool(false));
        agent.insert("rootAdmin".into(), Value::Bool(false));
        agent.insert("createdAt".into(), number(ctx.now()));
        let profile = agent_profile(ctx, tx, &tenant.id, input, &previous).await?;
        agent.insert("agent".into(), Value::Object(profile.clone()));
        if let Some(description) = input.get("description") {
            agent.insert(
                "description".into(),
                Value::String(text(Some(description), "description", 512)?),
            );
        }
        if let Some(expires_at) = input.get("expiresAt") {
            agent.insert(
                "expiresAt".into(),
                number(ctx.binding_expiry(Some(expires_at))?),
            );
        }
        if let Some(attributes) = input.get("attributes") {
            agent.insert(
                "attributes".into(),
                Value::Object(crate::catalog::attribute_values(
                    &ctx.catalog.identity_attributes,
                    Some(attributes),
                )?),
            );
        }
        let agent = tx.insert("identities", &agent).await?;
        let mut metadata = Map::new();
        metadata.insert("sponsorId".into(), Value::String(sponsor.id.clone()));
        for key in ["model", "provider"] {
            if let Some(value) = profile
                .get(key)
                .filter(|value| crate::js::truthy(Some(value)))
            {
                metadata.insert(key.into(), value.clone());
            }
        }
        ctx.events()?
            .audit(
                tx,
                principal,
                "agent:create",
                &tenant.id,
                member(&agent, "id"),
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await?;
        Ok(agent)
    }

    /// Changes an agent (see `agents.update`); a new sponsor is audited as `agent:sponsor-change`. `input` is the
    /// update request object (`tenantId` and `agentId` are not read). Returns the stored record.
    pub async fn update_agent(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        agent: &Record,
        input: &Map<String, Value>,
    ) -> IamResult<Record> {
        let ctx = &self.ctx;
        if member(agent, "status") == "deleted" {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Agent has been deleted",
                404,
            ));
        }
        let tenant_id = member(agent, "tenantId").to_owned();
        let mut next = agent.clone();
        if let Some(name) = input.get("name") {
            next.insert("name".into(), Value::String(text(Some(name), "name", 256)?));
        }
        match input.get("description") {
            Some(Value::Null) => {
                next.shift_remove("description");
            }
            Some(description) => {
                next.insert(
                    "description".into(),
                    Value::String(text(Some(description), "description", 512)?),
                );
            }
            None => {}
        }
        if let Some(attributes) = input.get("attributes") {
            next.insert(
                "attributes".into(),
                Value::Object(crate::catalog::attribute_values(
                    &ctx.catalog.identity_attributes,
                    Some(attributes),
                )?),
            );
        }
        match input.get("expiresAt") {
            Some(Value::Null) => {
                next.shift_remove("expiresAt");
            }
            Some(expires_at) => {
                next.insert(
                    "expiresAt".into(),
                    number(ctx.binding_expiry(Some(expires_at))?),
                );
            }
            None => {}
        }
        let previous = match agent.get("agent") {
            Some(Value::Object(profile)) => profile.clone(),
            Some(Value::Null) | None => {
                let mut fresh = Map::new();
                fresh.insert("sponsorId".into(), Value::String(String::new()));
                fresh
            }
            Some(_) => Map::new(),
        };
        let mut profile = agent_profile(ctx, tx, &tenant_id, input, &previous).await?;
        let previous_sponsor = profile_member(agent, "sponsorId").cloned();
        if let Some(sponsor_id) = input.get("sponsorId") {
            let sponsor = sponsor_for(ctx, tx, &tenant_id, Some(sponsor_id)).await?;
            profile.insert("sponsorId".into(), Value::String(sponsor.id));
        }
        let new_sponsor = profile.get("sponsorId").cloned().unwrap_or(Value::Null);
        next.insert("agent".into(), Value::Object(profile));
        let updated = tx.put("identities", &next).await?;
        if previous_sponsor.as_ref() != Some(&new_sponsor) {
            let mut metadata = Map::new();
            metadata.insert("from".into(), previous_sponsor.unwrap_or(Value::Null));
            metadata.insert("to".into(), new_sponsor);
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    "agent:sponsor-change",
                    &tenant_id,
                    member(agent, "id"),
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await?;
        }
        Ok(updated)
    }

    /// Deletes an agent: revokes every delegation to it, ends its sessions, leaves a tombstone.
    pub async fn delete_agent(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        agent: &Record,
    ) -> OperationResult<Value> {
        let ctx = &self.ctx;
        let agent_id = member(agent, "id").to_owned();
        let delegations = crate::delegations::revoke_delegations_of(
            ctx,
            tx,
            &Value::Object(agent.clone()),
            &principal.identity.id,
        )
        .await?;
        crate::delegations::delete_delegated_sessions(tx, &json!({ "agentId": agent_id })).await?;
        if tx.get("agentCards", &agent_id).await?.is_some() {
            tx.delete("agentCards", &agent_id).await?;
        }
        let typed: Identity = decode(agent.clone())?;
        let result = crate::api::identities::delete_identity(ctx, tx, principal, &typed).await?;
        let mut metadata = Map::new();
        metadata.insert("kind".into(), Value::String("agent".into()));
        metadata.insert("delegationsRevoked".into(), number(delegations));
        ctx.events()?
            .audit(
                tx,
                principal,
                "identity:delete",
                &typed.tenant_id,
                &agent_id,
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await?;
        Ok(result)
    }
}

/// What `asSponsorOr` runs: `(tx, principal, agent, sponsor)` with the stored agent record.
type SponsorAction<'a> = dyn Fn(Store, AuthenticatedPrincipal, Record, bool) -> BoxFuture<'a, IamResult<Value>>
    + Send
    + Sync
    + 'a;

/// The `agents` group: AI agents as accounts. Administrators create agents with `iam:agents:create` (the caller is
/// the sponsor unless `sponsorId` names another active person), read them with `iam:agents:read`, change them with
/// `iam:agents:update` and delete them with `iam:agents:delete`. Keys come from `credentials.create` like a service
/// account's. A sponsor manages their own agents without a permission: `listMine`, and the `suspend` kill switch (and
/// `resume` when they were the one who suspended it).
pub struct AgentsApi {
    ctx: Arc<ServerContext>,
    mutations: AgentMutations,
}

/// `createAgentsApi(ctx)`.
pub fn create_agents_api(ctx: &Arc<ServerContext>) -> IamResult<AgentsApi> {
    Ok(AgentsApi {
        ctx: ctx.clone(),
        mutations: agent_mutations(ctx),
    })
}

/// `agentRecord(tx, agentId, tenantId)`: an agent of the tenant, NOT_FOUND otherwise.
async fn agent_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    agent_id: Option<&Value>,
    tenant_id: &str,
) -> IamResult<Record> {
    let agent = ctx.scoped(tx, "identities", agent_id, tenant_id).await?;
    if member(&agent, "kind") != "agent" {
        return Err(IamError::with_status("NOT_FOUND", "Agent not found", 404));
    }
    Ok(agent)
}

/// `agentDetail(tx, agent)`: an agent with the credentials and delegations it holds, for its detail page.
async fn agent_detail(ctx: &Arc<ServerContext>, tx: &Store, agent: &Record) -> IamResult<Value> {
    let now = ctx.now();
    let agent_id = member(agent, "id").to_owned();
    let expires = |record: &Record| {
        record
            .get("expiresAt")
            .and_then(core_js::as_number)
            .unwrap_or(f64::NAN)
    };
    let mut keys = tx
        .find(
            "sessions",
            &Filter::new()
                .eq("identityId", agent_id.clone())
                .eq("kind", "api-key"),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|session| expires(session) > now)
        .collect::<Vec<_>>();
    keys.sort_by(by_newest_records);
    let keys: Vec<Value> = keys
        .iter()
        .map(|session| {
            let mut key = Map::new();
            key.insert(
                "id".into(),
                session.get("id").cloned().unwrap_or(Value::Null),
            );
            if let Some(name) = session.get("name") {
                key.insert("name".into(), name.clone());
            }
            key.insert(
                "createdAt".into(),
                session.get("createdAt").cloned().unwrap_or(Value::Null),
            );
            key.insert(
                "expiresAt".into(),
                session.get("expiresAt").cloned().unwrap_or(Value::Null),
            );
            let number_of = |name: &str| session.get(name).and_then(core_js::as_number);
            if let (Some(last_seen), Some(created)) =
                (number_of("lastSeenAt"), number_of("createdAt"))
                && last_seen > created
            {
                key.insert(
                    "lastUsedAt".into(),
                    session.get("lastSeenAt").cloned().unwrap_or(Value::Null),
                );
            }
            Value::Object(key)
        })
        .collect();
    let delegations = tx
        .find(
            "delegations",
            &Filter::new()
                .eq("tenantId", member(agent, "tenantId").to_owned())
                .eq("agentId", agent_id.clone()),
            &FindOptions::default(),
        )
        .await?;
    let count = |status: &str| {
        delegations
            .iter()
            .filter(|item| member(item, "status") == status && expires(item) > now)
            .count() as f64
    };
    let live = tx
        .find(
            "sessions",
            &Filter::new()
                .eq("kind", "delegated")
                .eq("agentId", agent_id.clone()),
            &FindOptions::default(),
        )
        .await?
        .iter()
        .filter(|session| expires(session) > now)
        .count() as f64;
    let mut detail = agent_summary(ctx, tx, agent).await?;
    detail.insert("keys".into(), Value::Array(keys));
    detail.insert(
        "delegations".into(),
        json!({ "active": number(count("active")), "pending": number(count("pending")) }),
    );
    detail.insert("liveDelegatedSessions".into(), number(live));
    Ok(Value::Object(detail))
}

/// Suspends an agent: its keys, session tokens and delegated sessions are refused while it is suspended, and live
/// delegated sessions and session tokens are ended now. Keys are kept, so `resume` restores the agent as it was.
async fn suspend_agent(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    agent: &Record,
    reason: Option<&str>,
) -> IamResult<Value> {
    let status = member(agent, "status");
    if status == "deleted" {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Agent has been deleted",
            404,
        ));
    }
    if status == "disabled" && crate::js::truthy(profile_member(agent, "suspended")) {
        return Err(IamError::with_status(
            "CONFLICT",
            "The agent is already suspended",
            409,
        ));
    }
    let agent_id = member(agent, "id").to_owned();
    let tenant_id = member(agent, "tenantId").to_owned();
    let now = ctx.now();
    let mut next = agent.clone();
    next.insert("status".into(), Value::String("disabled".into()));
    let mut profile = agent
        .get("agent")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let mut suspended = Map::new();
    suspended.insert("by".into(), Value::String(principal.identity.id.clone()));
    suspended.insert("at".into(), number(now));
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        suspended.insert("reason".into(), Value::String(reason.to_owned()));
    }
    profile.insert("suspended".into(), Value::Object(suspended));
    next.insert("agent".into(), Value::Object(profile));
    let suspended = tx.put("identities", &next).await?;
    // The kill switch holds the agent now: a threats containment of it can no longer be released.
    crate::threats::end_containment(tx, &agent_id, now).await?;
    let sessions =
        crate::delegations::delete_delegated_sessions(tx, &json!({ "agentId": agent_id })).await?;
    let mut tokens = 0.0;
    for session in tx
        .find(
            "sessions",
            &Filter::new().eq("identityId", agent_id.clone()),
            &FindOptions::default(),
        )
        .await?
    {
        if member(&session, "kind") == "api-key" {
            continue;
        }
        tx.delete("sessions", member(&session, "id")).await?;
        tokens += 1.0;
    }
    let mut metadata = Map::new();
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        metadata.insert("reason".into(), Value::String(reason.to_owned()));
    }
    metadata.insert("delegatedSessionsEnded".into(), number(sessions));
    metadata.insert("sessionsEnded".into(), number(tokens));
    ctx.events()?
        .audit(
            tx,
            principal,
            "agent:suspend",
            &tenant_id,
            &agent_id,
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    Ok(Value::Object(agent_summary(ctx, tx, &suspended).await?))
}

/// `resumeAgent(tx, principal, agent)`: lifts a suspension.
async fn resume_agent(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    agent: &Record,
) -> IamResult<Value> {
    let status = member(agent, "status");
    if status == "deleted" {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Agent has been deleted",
            404,
        ));
    }
    if status == "active" {
        return Err(IamError::with_status(
            "CONFLICT",
            "The agent is not suspended",
            409,
        ));
    }
    let typed: Identity = decode(agent.clone())?;
    if ctx.identity_expired(&typed) {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            "Extend or clear expiresAt before resuming an expired agent",
            409,
        ));
    }
    // `const { suspended: _gone, ...profile } = agent.agent!` (destructuring undefined throws).
    let mut profile = match agent.get("agent") {
        Some(Value::Object(profile)) => profile.clone(),
        Some(Value::Null) | None => return Err(crate::js::internal_error()),
        Some(_) => Map::new(),
    };
    profile.shift_remove("suspended");
    let mut next = agent.clone();
    next.insert("status".into(), Value::String("active".into()));
    next.insert("agent".into(), Value::Object(profile));
    let resumed = tx.put("identities", &next).await?;
    // Resuming a contained agent ends the containment too.
    crate::threats::end_containment(tx, &typed.id, ctx.now()).await?;
    ctx.events()?
        .audit(
            tx,
            principal,
            "agent:resume",
            &typed.tenant_id,
            &typed.id,
            AuditOutcome::Allow,
            false,
            None,
        )
        .await?;
    Ok(Value::Object(agent_summary(ctx, tx, &resumed).await?))
}

/// The JSON answer of an operation.
fn reply<O>(value: Value) -> IamResult<Reply<O>> {
    Ok(Reply::json(value))
}

impl AgentsApi {
    /// Runs `action_fn` as the agent's sponsor when the caller is that person in their own session, otherwise as an
    /// administrative operation needing `action` on `iam/{agentId}`.
    async fn as_sponsor_or(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        action_fn: &SponsorAction<'_>,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let agent_id = text(input.get("agentId"), "agentId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let own = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id, agent_id) = (&authenticated, &tenant_id, &agent_id);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    if !personal_session(&principal, tenant_id) {
                        return Ok(None);
                    }
                    let Some(agent) = tx.get("identities", agent_id).await? else {
                        return Ok(None);
                    };
                    if member(&agent, "kind") != "agent"
                        || member(&agent, "tenantId") != tenant_id.as_str()
                        || profile_member(&agent, "sponsorId").and_then(Value::as_str)
                            != Some(principal.identity.id.as_str())
                    {
                        return Ok(None);
                    }
                    Ok(Some(action_fn(tx.clone(), principal, agent, true).await?))
                }
            })
            .await?;
        if let Some(value) = own {
            return Ok(value);
        }
        let (tenant_ref, agent_ref) = (&tenant_id, &agent_id);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let agent = agent_record(
                    ctx,
                    &tx,
                    Some(&Value::String(agent_ref.clone())),
                    tenant_ref,
                )
                .await?;
                Ok(action_fn(tx, principal, agent, false).await?)
            })
        });
        ctx.operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                action,
                &agent_id,
                mutation,
                false,
            )
            .await
    }

    /// `agents/activity`: what the agent did, newest first: every audit event recorded for its own credentials and
    /// for the sessions in which it acted for people (allowed and denied). For the agent's sponsor in their own
    /// session, or an administrator with `iam:agents:read`.
    pub async fn activity(
        &self,
        credential: &CredentialInput,
        input: Body<agents::ActivityInput>,
    ) -> IamResult<Reply<agents::ActivityOutput>> {
        let query = input.raw();
        let action: &SponsorAction<'_> = &|tx, _principal, agent, _sponsor| {
            Box::pin(async move {
                let agent_id = member(&agent, "id").to_owned();
                let predicate = |event: &Record| {
                    event.get("actorId").and_then(Value::as_str) == Some(agent_id.as_str())
                        || event
                            .get("sessionContext")
                            .and_then(|context| context.get("agentId"))
                            .and_then(Value::as_str)
                            == Some(agent_id.as_str())
                };
                let events =
                    audit_activity(&tx, member(&agent, "tenantId"), query, &predicate).await?;
                Ok(Value::Array(
                    events.into_iter().map(Value::Object).collect(),
                ))
            })
        };
        reply(
            self.as_sponsor_or(credential, &input, "iam:agents:read", action)
                .await?,
        )
    }

    /// `agents/catalog`: the agents people of the tenant may delegate to: active, delegable agents in good standing,
    /// with what a person needs to decide (name, purpose, model, provider, url, protocols and the sponsor's name). Any
    /// person's own session of the tenant; needs no permission.
    pub async fn catalog(
        &self,
        credential: &CredentialInput,
        input: Body<agents::CatalogInput>,
    ) -> IamResult<Reply<agents::CatalogOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let listings = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id) = (&authenticated, &tenant_id);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    if !personal_session(&principal, tenant_id) {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "The agent catalog is read from a person\u{2019}s own session of the tenant",
                            403,
                        ));
                    }
                    let mut agents = agents_of(&tx, tenant_id).await?;
                    agents.sort_by(|a, b| locale_compare(member(a, "name"), member(b, "name")));
                    let mut listings = Vec::new();
                    for agent in agents {
                        let Some(Value::Object(profile)) = agent.get("agent") else {
                            continue;
                        };
                        if profile.get("delegable") == Some(&Value::Bool(false)) {
                            continue;
                        }
                        let typed: Identity = decode(agent.clone())?;
                        if agent_standing(ctx, &tx, &typed).await? != "ok" {
                            continue;
                        }
                        let sponsor = match profile.get("sponsorId").and_then(Value::as_str) {
                            Some(sponsor_id) => tx.get("identities", sponsor_id).await?,
                            None => None,
                        };
                        let mut listing = Map::new();
                        listing.insert("id".into(), agent.get("id").cloned().unwrap_or(Value::Null));
                        listing.insert(
                            "name".into(),
                            agent.get("name").cloned().unwrap_or(Value::Null),
                        );
                        if let Some(description) = agent.get("description") {
                            listing.insert("description".into(), description.clone());
                        }
                        for key in ["purpose", "model", "provider", "url", "protocols"] {
                            if let Some(value) = profile.get(key) {
                                listing.insert(key.into(), value.clone());
                            }
                        }
                        if let Some(audiences) = profile
                            .get("tokenAudiences")
                            .filter(|value| value.as_array().is_some_and(|list| !list.is_empty()))
                        {
                            listing.insert("tokenAudiences".into(), audiences.clone());
                        }
                        listing.insert(
                            "sponsorName".into(),
                            sponsor
                                .as_ref()
                                .and_then(|sponsor| sponsor.get("name"))
                                .filter(|name| !name.is_null())
                                .cloned()
                                .unwrap_or_else(|| Value::String(String::new())),
                        );
                        listings.push(Value::Object(listing));
                    }
                    Ok(listings)
                }
            })
            .await?;
        reply(Value::Array(listings))
    }

    /// `agents/create`: registers an AI agent. The sponsor (the caller when they are a person of the tenant, else
    /// `sponsorId`) must be an active person of the tenant; the agent stops working whenever its sponsor does. Naming
    /// someone else as the sponsor also needs `iam:identities:update` on them. Counts toward the tenant's `agents`
    /// limit. Audited as the operation plus `agent:create`.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<agents::CreateInput>,
    ) -> IamResult<Reply<agents::CreateOutput>> {
        let ctx = &self.ctx;
        let mutations = &self.mutations;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let given = body.get("sponsorId");
                    let sponsor_id = match given.filter(|value| !value.is_null()) {
                        Some(value) => Some(value.clone()),
                        None => personal_session(&principal, &tenant.id)
                            .then(|| Value::String(principal.identity.id.clone())),
                    };
                    let Some(sponsor_id) = sponsor_id else {
                        return Err(IamError::new(
                            "INVALID_SPONSOR",
                            "Name the person accountable for the agent (sponsorId)",
                        )
                        .into());
                    };
                    if given.is_some() {
                        authorize_sponsor(ctx, &tx, &principal, &tenant.id, given).await?;
                    }
                    let mut request = body.clone();
                    request.insert("sponsorId".into(), sponsor_id);
                    let agent = mutations
                        .create_agent(&tx, &principal, &tenant, &request)
                        .await?;
                    Ok(Value::Object(agent_summary(ctx, &tx, &agent).await?))
                })
            },
        );
        let tenant_id = string_member(&input, "tenantId");
        reply(
            ctx.operations()?
                .operation(
                    credential,
                    input.get("tenantId"),
                    "iam:agents:create",
                    &tenant_id,
                    mutation,
                    false,
                )
                .await?,
        )
    }

    /// `agents/delete`: deletes an agent: its keys and sessions end, every delegation to it is revoked, and a
    /// tombstone keeps audit records resolvable. Needs `iam:agents:delete` and a recent sign-in.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<agents::DeleteInput>,
    ) -> IamResult<Reply<agents::DeleteOutput>> {
        let ctx = &self.ctx;
        let mutations = &self.mutations;
        let body = input.raw();
        let agent_id = text(input.get("agentId"), "agentId", 256)?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                ctx.auth.require_recent(&principal)?;
                let agent = agent_record(
                    ctx,
                    &tx,
                    body.get("agentId"),
                    &string_member(body, "tenantId"),
                )
                .await?;
                mutations.delete_agent(&tx, &principal, &agent).await
            })
        });
        reply(
            ctx.operations()?
                .operation(
                    credential,
                    input.get("tenantId"),
                    "iam:agents:delete",
                    &agent_id,
                    mutation,
                    false,
                )
                .await?,
        )
    }

    /// `agents/directory`: the tenant's agent directory: the current attested A2A card of every agent in good
    /// standing whose attestation has not expired (each agent's latest `signCard`), sorted by name, optionally only
    /// agents offering a `skill` (by skill id or tag) or speaking a `protocol`. For finding the agent to hand work to.
    /// Any credential of the tenant (a person, an agent's key, an agent acting for someone); needs no permission.
    pub async fn directory(
        &self,
        credential: &CredentialInput,
        input: Body<agents::DirectoryInput>,
    ) -> IamResult<Reply<agents::DirectoryOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let skill = match input.get("skill") {
            Some(value) => Some(text(Some(value), "skill", 128)?),
            None => None,
        };
        let protocol = match input.get("protocol") {
            Some(value) => Some(core_js::to_lower(&text(Some(value), "protocol", 32)?)),
            None => None,
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let entries = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id, skill, protocol) =
                    (&authenticated, &tenant_id, &skill, &protocol);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    if principal.session.tenant_id != *tenant_id
                        && principal.identity.tenant_id != *tenant_id
                    {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "The agent directory is read from within the tenant",
                            403,
                        ));
                    }
                    let now = ctx.now();
                    let mut entries: Vec<(String, Map<String, Value>)> = Vec::new();
                    let cards = tx
                        .find(
                            "agentCards",
                            &Filter::new().eq("tenantId", tenant_id.clone()),
                            &FindOptions::default(),
                        )
                        .await?;
                    for record in cards {
                        // `record.expiresAt <= now` (false for a missing or non-numeric value).
                        if record
                            .get("expiresAt")
                            .and_then(core_js::as_number)
                            .is_some_and(|expires| expires <= now)
                        {
                            continue;
                        }
                        let Some(agent) = tx.get("identities", member(&record, "agentId")).await?
                        else {
                            continue;
                        };
                        if member(&agent, "kind") != "agent"
                            || member(&agent, "tenantId") != tenant_id.as_str()
                        {
                            continue;
                        }
                        let typed: Identity = decode(agent.clone())?;
                        if agent_standing(ctx, &tx, &typed).await? != "ok" {
                            continue;
                        }
                        if let Some(protocol) = protocol {
                            let speaks = record
                                .get("attestation")
                                .and_then(|attestation| attestation.get("protocols"))
                                .and_then(Value::as_array)
                                .is_some_and(|protocols| {
                                    protocols.iter().any(|item| item.as_str() == Some(protocol))
                                });
                            if !speaks {
                                continue;
                            }
                        }
                        if let Some(skill) = skill {
                            let skills = record
                                .get("card")
                                .and_then(|card| card.get("skills"))
                                .and_then(Value::as_array)
                                .cloned()
                                .unwrap_or_default();
                            let offers = skills.iter().any(|item| {
                                let Some(entry) = item.as_object() else {
                                    return false;
                                };
                                entry.get("id").and_then(Value::as_str) == Some(skill.as_str())
                                    || entry.get("tags").and_then(Value::as_array).is_some_and(
                                        |tags| tags.iter().any(|tag| tag.as_str() == Some(skill)),
                                    )
                            });
                            if !offers {
                                continue;
                            }
                        }
                        let mut entry = Map::new();
                        entry.insert(
                            "agentId".into(),
                            agent.get("id").cloned().unwrap_or(Value::Null),
                        );
                        entry.insert(
                            "name".into(),
                            agent.get("name").cloned().unwrap_or(Value::Null),
                        );
                        entry.insert(
                            "card".into(),
                            record.get("card").cloned().unwrap_or(Value::Null),
                        );
                        entry.insert(
                            "attestation".into(),
                            record.get("attestation").cloned().unwrap_or(Value::Null),
                        );
                        entry.insert(
                            "expiresAt".into(),
                            record.get("expiresAt").cloned().unwrap_or(Value::Null),
                        );
                        entries.push((member(&agent, "name").to_owned(), entry));
                    }
                    entries.sort_by(|a, b| locale_compare(&a.0, &b.0));
                    Ok(entries
                        .into_iter()
                        .map(|(_, entry)| Value::Object(entry))
                        .collect::<Vec<_>>())
                }
            })
            .await?;
        reply(Value::Array(entries))
    }

    /// `agents/get`: one agent with its standing, live keys (labels only) and delegation counts. Needs
    /// `iam:agents:read`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<agents::GetInput>,
    ) -> IamResult<Reply<agents::GetOutput>> {
        let ctx = &self.ctx;
        let action: &SponsorAction<'_> = &|tx, _principal, agent, _sponsor| {
            Box::pin(async move { agent_detail(ctx, &tx, &agent).await })
        };
        reply(
            self.as_sponsor_or(credential, &input, "iam:agents:read", action)
                .await?,
        )
    }

    /// `agents/list`: the tenant's agents, newest first, optionally of one sponsor or in one standing. Deleted agents
    /// are left out unless `includeDeleted`. Needs `iam:agents:read`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<agents::ListInput>,
    ) -> IamResult<Reply<agents::ListOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let sponsor_id = match body.get("sponsorId") {
                    Some(value) => Some(text(Some(value), "sponsorId", 256)?),
                    None => None,
                };
                let mut agents = agents_of(&tx, &string_member(body, "tenantId")).await?;
                agents.sort_by(by_newest_records);
                let mut summaries = Vec::new();
                for agent in agents {
                    if member(&agent, "status") == "deleted"
                        && body.get("includeDeleted") != Some(&Value::Bool(true))
                    {
                        continue;
                    }
                    if let Some(sponsor_id) = &sponsor_id
                        && profile_member(&agent, "sponsorId").and_then(Value::as_str)
                            != Some(sponsor_id.as_str())
                    {
                        continue;
                    }
                    let summary = agent_summary(ctx, &tx, &agent).await?;
                    if let Some(standing) = body.get("standing")
                        && summary.get("standing") != Some(standing)
                    {
                        continue;
                    }
                    summaries.push(Value::Object(summary));
                }
                Ok(Value::Array(summaries))
            })
        });
        let tenant_id = string_member(&input, "tenantId");
        reply(
            ctx.operations()?
                .operation(
                    credential,
                    input.get("tenantId"),
                    "iam:agents:read",
                    &tenant_id,
                    mutation,
                    false,
                )
                .await?,
        )
    }

    /// `agents/listMine`: the agents the caller sponsors (a person's own session of the tenant); needs no
    /// permission.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<agents::ListMineInput>,
    ) -> IamResult<Reply<agents::ListMineOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let details = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id) = (&authenticated, &tenant_id);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    if !personal_session(&principal, tenant_id) {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Sponsored agents are listed from a person\u{2019}s own session of the tenant",
                            403,
                        ));
                    }
                    let mut agents = agents_of(&tx, tenant_id).await?;
                    agents.sort_by(by_newest_records);
                    let mut details = Vec::new();
                    for agent in agents {
                        if member(&agent, "status") != "deleted"
                            && profile_member(&agent, "sponsorId").and_then(Value::as_str)
                                == Some(principal.identity.id.as_str())
                        {
                            details.push(agent_detail(ctx, &tx, &agent).await?);
                        }
                    }
                    Ok(details)
                }
            })
            .await?;
        reply(Value::Array(details))
    }

    /// `agents/resume`: lifts a suspension. An administrator with `iam:agents:update` needs a recent sign-in; the
    /// sponsor may resume an agent only when they suspended it themselves. Audited as `agent:resume`.
    pub async fn resume(
        &self,
        credential: &CredentialInput,
        input: Body<agents::ResumeInput>,
    ) -> IamResult<Reply<agents::ResumeOutput>> {
        let ctx = &self.ctx;
        let action: &SponsorAction<'_> = &|tx, principal, agent, sponsor| {
            Box::pin(async move {
                if sponsor {
                    let by = profile_member(&agent, "suspended")
                        .and_then(|suspended| suspended.get("by"))
                        .and_then(Value::as_str);
                    if by != Some(principal.identity.id.as_str()) {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Only an administrator can resume an agent someone else suspended",
                            403,
                        ));
                    }
                } else {
                    ctx.auth.require_recent(&principal)?;
                }
                resume_agent(ctx, &tx, &principal, &agent).await
            })
        };
        reply(
            self.as_sponsor_or(credential, &input, "iam:agents:update", action)
                .await?,
        )
    }

    /// `agents/signCard`: signs the agent's A2A agent card (needs the `a2a` option). The card's `url` and every
    /// `additionalInterfaces[].url` must be on the origin of the agent's registered `url`; IAM sets
    /// `provider.organization` to the tenant's name, adds the attestation extension
    /// `urn:better-iam:a2a:attestation:v1` (agent, organization, sponsorship, model, expiry) and signs the canonical
    /// card (RFC 8785) as a detached JWS. A card with JWT or delegation-token claims at its top level (`iss`, `sub`,
    /// `aud`, `exp`, `act`, `scope`, `tenant_id`, ...) is refused, so no signed card reads as a token. The agent must
    /// be in good standing. The agent itself may call this with its own unscoped API key (so its A2A server re-signs
    /// before the attestation expires), as may its sponsor in their own session or an administrator with
    /// `iam:agents:update`. Audited as `agent:card-sign`.
    pub async fn sign_card(
        &self,
        credential: &CredentialInput,
        input: Body<agents::SignCardInput>,
    ) -> IamResult<Reply<agents::SignCardOutput>> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let agent_id = text(input.get("agentId"), "agentId", 256)?;
        let card_input = input.get("card");
        let sign = |tx: Store, principal: AuthenticatedPrincipal, agent: Identity| async move {
            if agent_standing(ctx, &tx, &agent).await? != "ok" {
                return Err(IamError::with_status(
                    "INVALID_IDENTITY",
                    "The agent is not in good standing",
                    409,
                ));
            }
            let Some(tenant) = tx.get("tenants", &agent.tenant_id).await? else {
                return Err(IamError::with_status("NOT_FOUND", "Tenant not found", 404));
            };
            let tenant: Tenant = decode(tenant)?;
            // The card is signed with the keys that sign delegation tokens, and its signed payload is
            // agent-controlled JSON: without token claims at the top level, it can never pass as a delegation token
            // (or any JWT naming a subject, audience, actor or lifetime) with a verifier that skips the `typ` check.
            if let Some(Value::Object(card)) = card_input {
                let claims: Vec<&str> = core_js::keys(card)
                    .into_iter()
                    .map(String::as_str)
                    .filter(|name| TOKEN_CLAIM_NAMES.contains(name))
                    .collect();
                if !claims.is_empty() {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        format!(
                            "An agent card may not carry the token claim{} {}",
                            if claims.len() == 1 { "" } else { "s" },
                            claims.join(", ")
                        ),
                    ));
                }
            }
            let signed = crate::a2a::sign_agent_card(ctx, &tenant, &agent, card_input).await?;
            // The latest attested card is the agent's entry in the tenant's directory (`directory`).
            let mut entry = Map::new();
            entry.insert("id".into(), Value::String(agent.id.clone()));
            entry.insert("tenantId".into(), Value::String(agent.tenant_id.clone()));
            entry.insert("agentId".into(), Value::String(agent.id.clone()));
            entry.insert("card".into(), signed.card.clone());
            entry.insert("attestation".into(), signed.attestation.clone());
            entry.insert("signedAt".into(), number(ctx.now()));
            entry.insert("expiresAt".into(), number(signed.expires_at));
            if tx.get("agentCards", &agent.id).await?.is_some() {
                tx.put("agentCards", &entry).await?;
            } else {
                tx.insert("agentCards", &entry).await?;
            }
            let mut metadata = Map::new();
            metadata.insert(
                "url".into(),
                Value::String(crate::js::js_string(signed.card.get("url"))),
            );
            metadata.insert("expiresAt".into(), number(signed.expires_at));
            ctx.events()?
                .audit(
                    &tx,
                    &principal,
                    "agent:card-sign",
                    &agent.tenant_id,
                    &agent.id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await?;
            Ok(signed.to_json())
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let own = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id, agent_id, sign) =
                    (&authenticated, &tenant_id, &agent_id, &sign);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    // The agent's own unscoped API key: not a temporary credential minted from it, and not a key
                    // whose scopes (session policy) limit what it may do.
                    if principal.identity.id != *agent_id
                        || principal.identity.kind != IdentityKind::Agent
                        || principal.identity.tenant_id != *tenant_id
                        || principal.session.tenant_id != *tenant_id
                        || principal.session.kind != SessionKind::ApiKey
                        || !acts_in_own_right(principal.session.kind)
                        || impersonating(&principal)
                        || principal.session.policy.is_some()
                    {
                        return Ok(None);
                    }
                    let identity = principal.identity.clone();
                    Ok(Some(sign(tx, principal, identity).await?))
                }
            })
            .await?;
        if let Some(signed) = own {
            return reply(signed);
        }
        let action: &SponsorAction<'_> = &|tx, principal, agent, _sponsor| {
            Box::pin(async move {
                let agent: Identity = decode(agent)?;
                sign(tx, principal, agent).await
            })
        };
        let mut request = Map::new();
        request.insert("tenantId".into(), Value::String(tenant_id.clone()));
        request.insert("agentId".into(), Value::String(agent_id.clone()));
        reply(
            self.as_sponsor_or(credential, &request, "iam:agents:update", action)
                .await?,
        )
    }

    /// `agents/standing`: whether the agent may act right now, and why not: `ok`, `suspended`, `expired`,
    /// `sponsor-inactive`, ...
    pub async fn standing(
        &self,
        credential: &CredentialInput,
        input: Body<agents::StandingInput>,
    ) -> IamResult<Reply<agents::StandingOutput>> {
        let ctx = &self.ctx;
        let action: &SponsorAction<'_> = &|tx, _principal, agent, _sponsor| {
            Box::pin(async move {
                let typed: Identity = decode(agent)?;
                let standing = agent_standing(ctx, &tx, &typed).await?;
                Ok(json!({ "agentId": typed.id, "standing": standing }))
            })
        };
        reply(
            self.as_sponsor_or(credential, &input, "iam:agents:read", action)
                .await?,
        )
    }

    /// `agents/suspend`: the kill switch. The agent's sponsor (in their own session) or an administrator with
    /// `iam:agents:update` stops the agent at once: every credential is refused while it is suspended and live
    /// delegated sessions and session tokens end now. API keys are kept for `resume`. Audited as `agent:suspend`.
    pub async fn suspend(
        &self,
        credential: &CredentialInput,
        input: Body<agents::SuspendInput>,
    ) -> IamResult<Reply<agents::SuspendOutput>> {
        let ctx = &self.ctx;
        let reason = match input.get("reason") {
            Some(value) => Some(text(Some(value), "reason", 512)?),
            None => None,
        };
        let reason = reason.as_deref();
        let action: &SponsorAction<'_> = &|tx, principal, agent, _sponsor| {
            Box::pin(async move { suspend_agent(ctx, &tx, &principal, &agent, reason).await })
        };
        reply(
            self.as_sponsor_or(credential, &input, "iam:agents:update", action)
                .await?,
        )
    }

    /// `agents/suspendAll`: the organization-wide emergency stop: suspends every active agent of the tenant at once
    /// (during an incident, for example), each exactly as `suspend` does, optionally only those of one `sponsorId` or
    /// running on one `provider` or `model`. Needs `iam:agents:update` on the tenant and no recent sign-in, so it
    /// works in a hurry. Agents come back one at a time with `resume`. Audited as `agent:suspend-all` with the count,
    /// and `agent:suspend` for each agent.
    pub async fn suspend_all(
        &self,
        credential: &CredentialInput,
        input: Body<agents::SuspendAllInput>,
    ) -> IamResult<Reply<agents::SuspendAllOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let reason = text(body.get("reason"), "reason", 512)?;
                    let sponsor_id = match body.get("sponsorId") {
                        Some(value) => Some(text(Some(value), "sponsorId", 256)?),
                        None => None,
                    };
                    let provider = match body.get("provider") {
                        Some(value) => Some(core_js::to_lower(&text(Some(value), "provider", 64)?)),
                        None => None,
                    };
                    let model = match body.get("model") {
                        Some(value) => Some(text(Some(value), "model", 128)?),
                        None => None,
                    };
                    let mut agent_ids: Vec<Value> = Vec::new();
                    let mut agents = agents_of(&tx, &tenant.id).await?;
                    agents.sort_by(by_newest_records);
                    for agent in agents {
                        if member(&agent, "status") != "active" {
                            continue;
                        }
                        let profile =
                            |key: &str| profile_member(&agent, key).and_then(Value::as_str);
                        if sponsor_id
                            .as_deref()
                            .is_some_and(|wanted| profile("sponsorId") != Some(wanted))
                            || provider
                                .as_deref()
                                .is_some_and(|wanted| profile("provider") != Some(wanted))
                            || model
                                .as_deref()
                                .is_some_and(|wanted| profile("model") != Some(wanted))
                        {
                            continue;
                        }
                        suspend_agent(ctx, &tx, &principal, &agent, Some(&reason)).await?;
                        agent_ids.push(agent.get("id").cloned().unwrap_or(Value::Null));
                    }
                    let mut metadata = Map::new();
                    metadata.insert("reason".into(), Value::String(reason.clone()));
                    metadata.insert("suspended".into(), number(agent_ids.len() as f64));
                    for (key, value) in [
                        ("sponsorId", &sponsor_id),
                        ("provider", &provider),
                        ("model", &model),
                    ] {
                        if let Some(value) = value.as_ref().filter(|value| !value.is_empty()) {
                            metadata.insert(key.into(), Value::String(value.clone()));
                        }
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "agent:suspend-all",
                            &tenant.id,
                            &tenant.id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(json!({
                        "suspended": number(agent_ids.len() as f64),
                        "agentIds": agent_ids,
                    }))
                })
            },
        );
        let tenant_id = string_member(&input, "tenantId");
        reply(
            ctx.operations()?
                .operation(
                    credential,
                    input.get("tenantId"),
                    "iam:agents:update",
                    &tenant_id,
                    mutation,
                    false,
                )
                .await?,
        )
    }

    /// `agents/update`: changes an agent's name, description, attributes, expiry or profile (model, provider,
    /// purpose, url, protocols, delegable, maxDelegatedSessionSeconds, boundary, tokenAudiences; null clears). A new
    /// `sponsorId` must be an active person of the tenant (audited `agent:sponsor-change`), and naming someone other
    /// than the caller needs `iam:identities:update` on them. Changes to the boundary and to `delegable` apply to
    /// live sessions at once. Needs `iam:agents:update`.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<agents::UpdateInput>,
    ) -> IamResult<Reply<agents::UpdateOutput>> {
        let ctx = &self.ctx;
        let mutations = &self.mutations;
        let body = input.raw();
        let agent_id = text(input.get("agentId"), "agentId", 256)?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let agent = agent_record(
                    ctx,
                    &tx,
                    body.get("agentId"),
                    &string_member(body, "tenantId"),
                )
                .await?;
                if let Some(sponsor_id) = body.get("sponsorId")
                    && profile_member(&agent, "sponsorId") != Some(sponsor_id)
                {
                    authorize_sponsor(
                        ctx,
                        &tx,
                        &principal,
                        member(&agent, "tenantId"),
                        Some(sponsor_id),
                    )
                    .await?;
                }
                let updated = mutations
                    .update_agent(&tx, &principal, &agent, body)
                    .await?;
                Ok(Value::Object(agent_summary(ctx, &tx, &updated).await?))
            })
        });
        reply(
            ctx.operations()?
                .operation(
                    credential,
                    input.get("tenantId"),
                    "iam:agents:update",
                    &agent_id,
                    mutation,
                    false,
                )
                .await?,
        )
    }
}
