//! Port of `packages/server/src/api/delegations.ts`.
//!
//! The `delegations` group: people let AI agents act for them. A person grants a delegation directly (`grant`) or
//! approves an agent's request (`request` → `approve` / `deny`); the agent then opens short delegated sessions with
//! its own key (`assume`). Delegated sessions act as the person, within the delegation's scope and the agent's
//! ceiling, and never pass recent-authentication, ownership or self-service checks. The person, the agent's sponsor,
//! the agent itself or an administrator (`iam:delegations:revoke`) can revoke a delegation, which ends its sessions at
//! once. Administrators list and read delegations with `iam:delegations:read`.
//!
//! Delegations and confirmation requests are handled as raw records (`better_iam_core::Record`) for writes, so
//! members this version does not know and the member order of records written by the TypeScript server survive a
//! read-modify-write; typed copies are read where the TypeScript reads typed fields.

use std::collections::HashSet;
use std::sync::Arc;

use better_iam_auth::crypto::{CredentialTokenType, new_credential_token};
use better_iam_auth::outbox::EnqueueInput;
use better_iam_auth::service::base::{LimitAttemptOptions, RateTier};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, DELEGATION_TOKEN_TYPE, Filter,
    FindOptions, IamError, IamResult, IamStoreExt, Identity, IdentityKind, IdentityStatus,
    OutboxKind, PolicyDocument, Record, Session, SessionKind, Tenant, delegation_actor,
    delegation_token_limits, delegation_token_scope, js as core_js,
};
use better_iam_types::api::delegations;
use futures::FutureExt;
use serde_json::{Map, Value, json};

use crate::api::agents::{ActivityQuery, audit_activity};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::delegation_tokens::{
    DelegationTokenRecord, ScopeRefusal, TokenBasis, audience_refusal, scope_refusal,
    token_record_value,
};
use crate::delegations::{
    Delegation, DelegationConfirmation, MAX_SESSIONS_PER_DELEGATION, confirm_patterns,
    confirmation_limits, delegation_lifetime, delegation_live, delegation_pending,
    delegation_scope, delegation_seconds, delete_delegated_sessions, handoff_limits,
    handoff_setting, handoff_value, live_ancestors, needs_confirmation, revoke_handoffs_below,
    spend_setting, spend_value,
};
use crate::js::{js_string, number, truthy};
use crate::port::{Callback, decode, not_ported};
use crate::session_kinds::{acts_in_own_right, next_watermark};
use crate::temporary_credentials::session_name_value;
use crate::utils::{by_newest_records, hash, id, token as random_token};
use crate::validation::{email, integer, object, strings, text};

/// The `delegations` API group (`createDelegationsApi(ctx)`): one method per route `delegations/{method}`.
pub struct DelegationsApi {
    ctx: Arc<ServerContext>,
}

/// `createDelegationsApi(ctx)`.
pub fn create_delegations_api(ctx: &Arc<ServerContext>) -> IamResult<DelegationsApi> {
    Ok(DelegationsApi { ctx: ctx.clone() })
}

fn refuse(message: &str) -> IamError {
    IamError::with_status("ACCESS_DENIED", message, 403)
}

fn not_found(message: &str) -> IamError {
    IamError::with_status("NOT_FOUND", message, 404)
}

fn inactive() -> IamError {
    IamError::with_status(
        "DELEGATION_INACTIVE",
        "This delegation is no longer active",
        403,
    )
}

fn str_member<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn num_member(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

fn impersonating(principal: &AuthenticatedPrincipal) -> bool {
    principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
}

fn sends_email(ctx: &ServerContext) -> bool {
    ctx.options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some())
}

fn strings_value(items: &[String]) -> Value {
    Value::Array(items.iter().cloned().map(Value::String).collect())
}

fn policy_value(policy: &PolicyDocument) -> Value {
    serde_json::to_value(policy).unwrap_or(Value::Null)
}

async fn get_as<T: serde::de::DeserializeOwned>(
    tx: &Store,
    collection: &str,
    id: &str,
) -> IamResult<Option<T>> {
    match tx.get(collection, id).await? {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

/// Default and bounds of `AgentProfile.maxDelegatedSessionSeconds` (`agentSessionSeconds`).
fn agent_session_seconds(key: &str) -> f64 {
    crate::agents::AGENT_SESSION_SECONDS
        .get(key)
        .and_then(Value::as_f64)
        .unwrap_or(f64::NAN)
}

/// A person in their own session of the tenant (not impersonated).
fn assert_person(principal: &AuthenticatedPrincipal, tenant_id: &str) -> IamResult<()> {
    if impersonating(principal) {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Delegations cannot be managed while impersonating a member",
            403,
        ));
    }
    if !acts_in_own_right(principal.session.kind)
        || principal.session.kind != SessionKind::User
        || principal.identity.kind != IdentityKind::User
        || principal.identity.tenant_id != tenant_id
        || principal.session.tenant_id != tenant_id
    {
        return Err(refuse(
            "Delegations are decided by a person in their own session of the organization",
        ));
    }
    Ok(())
}

/// An agent acting with its own API key in its own tenant.
fn assert_agent_key(principal: &AuthenticatedPrincipal, tenant_id: &str) -> IamResult<()> {
    if principal.identity.kind != IdentityKind::Agent
        || principal.session.kind != SessionKind::ApiKey
        || principal.identity.tenant_id != tenant_id
        || principal.session.tenant_id != tenant_id
    {
        return Err(refuse("Only an agent using its own API key can do this"));
    }
    Ok(())
}

/// An agent of the tenant that may receive a delegation right now.
async fn delegable_agent(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    agent_id: Option<&Value>,
    tenant_id: &str,
) -> IamResult<Identity> {
    let agent_id = text(agent_id, "agentId", 256)?;
    let agent: Option<Identity> = get_as(tx, "identities", &agent_id).await?;
    let Some(agent) = agent.filter(|agent| {
        agent.kind == IdentityKind::Agent
            && agent.tenant_id == tenant_id
            && agent.status != IdentityStatus::Deleted
    }) else {
        return Err(not_found("Agent not found"));
    };
    if agent
        .agent
        .as_ref()
        .is_some_and(|profile| profile.delegable == Some(false))
    {
        return Err(IamError::with_status(
            "DELEGATION_NOT_ALLOWED",
            "This agent does not accept delegation",
            403,
        ));
    }
    if crate::agents::agent_standing(ctx, tx, &agent).await? != "ok" {
        return Err(IamError::with_status(
            "INVALID_IDENTITY",
            "The agent is not in good standing",
            409,
        ));
    }
    Ok(agent)
}

/// A delegation as the people and agents involved see it (never session material): `DelegationSummary`.
async fn summary(ctx: &Arc<ServerContext>, tx: &Store, record: &Record) -> IamResult<Value> {
    let now = ctx.now();
    let delegation: Delegation = decode(record.clone())?;
    let agent = tx.get("identities", &delegation.agent_id).await?;
    let subject = tx.get("identities", &delegation.subject_id).await?;
    let name_of = |identity: &Option<Record>, fallback: &str| {
        identity
            .as_ref()
            .and_then(|identity| str_member(identity, "name"))
            .unwrap_or(fallback)
            .to_owned()
    };
    let profile = |key: &str| {
        agent
            .as_ref()
            .and_then(|agent| agent.get("agent"))
            .and_then(|profile| profile.get(key))
            .filter(|value| truthy(Some(value)))
            .cloned()
    };
    let mut agent_view = Map::new();
    agent_view.insert("id".into(), Value::String(delegation.agent_id.clone()));
    agent_view.insert(
        "name".into(),
        Value::String(name_of(&agent, &delegation.agent_id)),
    );
    if let Some(model) = profile("model") {
        agent_view.insert("model".into(), model);
    }
    if let Some(provider) = profile("provider") {
        agent_view.insert("provider".into(), provider);
    }
    let mut subject_view = Map::new();
    subject_view.insert("id".into(), Value::String(delegation.subject_id.clone()));
    subject_view.insert(
        "name".into(),
        Value::String(name_of(&subject, &delegation.subject_id)),
    );
    if let Some(email) = subject
        .as_ref()
        .and_then(|subject| subject.get("email"))
        .filter(|value| truthy(Some(value)))
    {
        subject_view.insert("email".into(), email.clone());
    }
    let mut result = Map::new();
    result.insert("id".into(), Value::String(delegation.id.clone()));
    result.insert(
        "tenantId".into(),
        Value::String(delegation.tenant_id.clone()),
    );
    result.insert("status".into(), Value::String(delegation.status.clone()));
    result.insert(
        "expired".into(),
        Value::Bool(
            (delegation.status == "active" || delegation.status == "pending")
                && delegation.expires_at <= now,
        ),
    );
    result.insert("agent".into(), Value::Object(agent_view));
    result.insert("subject".into(), Value::Object(subject_view));
    result.insert(
        "policy".into(),
        record.get("policy").cloned().unwrap_or(Value::Null),
    );
    result.insert(
        "requestedBy".into(),
        Value::String(delegation.requested_by.clone()),
    );
    result.insert("createdAt".into(), number(delegation.created_at));
    result.insert("expiresAt".into(), number(delegation.expires_at));
    if let Some(scopes) = &delegation.scopes {
        result.insert("scopes".into(), strings_value(scopes));
    }
    if let Some(reason) = &delegation.reason {
        result.insert("reason".into(), Value::String(reason.clone()));
    }
    if let Some(lifetime) = delegation.lifetime_ms {
        result.insert(
            "requestedSeconds".into(),
            number((lifetime / 1000.0).floor()),
        );
    }
    if let Some(seconds) = delegation.max_session_seconds {
        result.insert("maxSessionSeconds".into(), number(seconds));
    }
    if let Some(at) = delegation.decided_at {
        result.insert("decidedAt".into(), number(at));
    }
    if let Some(at) = delegation.revoked_at {
        result.insert("revokedAt".into(), number(at));
    }
    if let Some(by) = &delegation.revoked_by {
        result.insert("revokedBy".into(), Value::String(by.clone()));
    }
    if let Some(at) = delegation.last_used_at {
        result.insert("lastUsedAt".into(), number(at));
    }
    if let Some(confirm) = delegation
        .confirm
        .as_ref()
        .filter(|items| !items.is_empty())
    {
        result.insert("confirm".into(), strings_value(confirm));
    }
    if let Some(handoff) = &delegation.handoff {
        let mut view = Map::new();
        view.insert("depth".into(), number(handoff.depth));
        if let Some(agents) = &handoff.agents {
            view.insert("agents".into(), strings_value(agents));
        }
        result.insert("handoff".into(), Value::Object(view));
    }
    if let Some(parent_id) = &delegation.parent_id {
        result.insert("parentId".into(), Value::String(parent_id.clone()));
    }
    // `delegationSpendStanding` answers nothing for a delegation without a cap.
    if let Some(spend) = &delegation.spend
        && let Some(spent) =
            crate::inference::delegation_spend_standing(tx, &delegation, now).await?
    {
        let mut view = Map::new();
        view.insert("period".into(), Value::String(spend.period.clone()));
        if let Some(tokens) = spend.max_tokens {
            view.insert("maxTokens".into(), number(tokens));
        }
        if let Some(micros) = spend.max_cost_micros {
            view.insert("maxCostUsd".into(), number(micros / 1_000_000.0));
        }
        if let Some(requests) = spend.max_requests {
            view.insert("maxRequests".into(), number(requests));
        }
        view.insert("usedTokens".into(), number(spent.used_tokens));
        view.insert(
            "usedCostUsd".into(),
            number(spent.used_cost_micros / 1_000_000.0),
        );
        view.insert("usedRequests".into(), number(spent.used_requests));
        view.insert("resetsAt".into(), number(spent.resets_at));
        result.insert("spend".into(), Value::Object(view));
    }
    if let Some(chain) = delegation.chain.as_ref().filter(|chain| !chain.is_empty()) {
        let mut items = Vec::new();
        for agent_id in chain {
            let agent = tx.get("identities", agent_id).await?;
            items.push(json!({ "id": agent_id, "name": name_of(&agent, agent_id) }));
        }
        result.insert("chain".into(), Value::Array(items));
    }
    Ok(Value::Object(result))
}

/// The live (pending or active) delegation between an agent and a person, if any.
async fn live_between(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    agent_id: &str,
    subject_id: &str,
) -> IamResult<Option<Delegation>> {
    let now = ctx.now();
    // Hand-offs from other agents do not count: they are part of another delegation.
    for record in tx
        .find(
            "delegations",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("agentId", agent_id)
                .eq("subjectId", subject_id),
            &FindOptions::default(),
        )
        .await?
    {
        let item: Delegation = decode(record)?;
        if item.parent_id.is_none()
            && (delegation_live(&item, now) || delegation_pending(&item, now))
        {
            return Ok(Some(item));
        }
    }
    Ok(None)
}

fn session_cap(value: Option<&Value>) -> IamResult<Option<f64>> {
    match value {
        None => Ok(None),
        Some(value) => integer(
            Some(value),
            "maxSessionSeconds",
            agent_session_seconds("min"),
            agent_session_seconds("max"),
        )
        .map(Some),
    }
}

/// Whether the principal is involved in the delegation: its person, its agent, the agent's sponsor, or (for a
/// hand-off) the agent that handed it on, acting under the delegation above.
async fn involved(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    delegation: &Delegation,
) -> IamResult<Option<&'static str>> {
    let session = &principal.session;
    if impersonating(principal) {
        return Ok(None);
    }
    // The agent acting under this very delegation (its delegated session) counts as the agent.
    if session.kind == SessionKind::Delegated
        && session.delegation_id.as_deref() == Some(delegation.id.as_str())
        && session.tenant_id == delegation.tenant_id
    {
        return Ok(Some("agent"));
    }
    if session.kind == SessionKind::Delegated
        && delegation.parent_id.is_some()
        && session.delegation_id == delegation.parent_id
        && session.tenant_id == delegation.tenant_id
    {
        return Ok(Some("delegator"));
    }
    if !acts_in_own_right(session.kind) {
        return Ok(None);
    }
    if session.tenant_id != delegation.tenant_id {
        return Ok(None);
    }
    let identity = &principal.identity;
    if identity.id == delegation.subject_id && identity.kind == IdentityKind::User {
        return Ok(Some("subject"));
    }
    if identity.id == delegation.agent_id && identity.kind == IdentityKind::Agent {
        return Ok(Some("agent"));
    }
    if identity.kind == IdentityKind::User {
        let agent = tx.get("identities", &delegation.agent_id).await?;
        let sponsor = agent
            .as_ref()
            .and_then(|agent| agent.get("agent"))
            .and_then(|profile| profile.get("sponsorId"))
            .and_then(Value::as_str);
        if sponsor == Some(identity.id.as_str()) {
            return Ok(Some("sponsor"));
        }
    }
    Ok(None)
}

/// What `involvedOr` runs once the caller may act on the delegation.
enum InvolvedRun {
    Revoke(Option<String>),
    Get,
    Activity(Map<String, Value>),
}

async fn run_involved(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    record: Record,
    run: &InvolvedRun,
) -> IamResult<Value> {
    match run {
        InvolvedRun::Revoke(reason) => {
            revoke_delegation(ctx, tx, principal, record, reason.as_deref()).await
        }
        InvolvedRun::Get => summary(ctx, tx, &record).await,
        InvolvedRun::Activity(input) => {
            // The paging is validated as `auditActivity` does, once the caller may read the delegation.
            let query = activity_query(input)?;
            let id = str_member(&record, "id").unwrap_or_default().to_owned();
            let tenant_id = str_member(&record, "tenantId")
                .unwrap_or_default()
                .to_owned();
            // Work handed on to other agents belongs to this delegation's story too.
            let mut ids: indexmap::IndexSet<String> = indexmap::IndexSet::from([id.clone()]);
            let mut pending = vec![id];
            while !pending.is_empty() && ids.len() <= 1000 {
                let parent_id = pending.pop().unwrap_or_default();
                for child in tx
                    .find(
                        "delegations",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("parentId", parent_id),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let child_id = str_member(&child, "id").unwrap_or_default().to_owned();
                    if !ids.contains(&child_id) {
                        ids.insert(child_id.clone());
                        pending.push(child_id);
                    }
                }
            }
            let ids: Arc<HashSet<String>> = Arc::new(ids.into_iter().collect());
            let matcher: Callback = Arc::new(move |args: Vec<Value>| {
                let ids = ids.clone();
                async move {
                    let event = args.into_iter().next().unwrap_or(Value::Null);
                    let resource = event
                        .get("resourceId")
                        .and_then(Value::as_str)
                        .unwrap_or("");
                    let delegation = event
                        .get("sessionContext")
                        .and_then(|context| context.get("delegationId"))
                        .and_then(Value::as_str);
                    Ok(Value::Bool(
                        ids.contains(resource) || delegation.is_some_and(|id| ids.contains(id)),
                    ))
                }
                .boxed()
            });
            let events = audit_activity(tx, &tenant_id, &query, &matcher).await?;
            Ok(serde_json::to_value(events).unwrap_or(Value::Array(Vec::new())))
        }
    }
}

/// Revokes a pending or active delegation, ending its sessions; audited as `delegation:revoke`.
async fn revoke_delegation(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    record: Record,
    reason: Option<&str>,
) -> IamResult<Value> {
    let delegation: Delegation = decode(record.clone())?;
    if delegation.status != "active" && delegation.status != "pending" {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            format!("The delegation is already {}", delegation.status),
            409,
        ));
    }
    let now = ctx.now();
    // An agent revoking in a delegated session (its own hand-off, or one it handed on) is the one who revoked.
    let revoked_by = match (&principal.session.kind, &principal.session.agent_id) {
        (SessionKind::Delegated, Some(agent_id)) => agent_id.clone(),
        _ => principal.identity.id.clone(),
    };
    let mut next = record;
    next.insert("status".into(), Value::String("revoked".into()));
    next.insert("revokedAt".into(), number(now));
    next.insert("revokedBy".into(), Value::String(revoked_by.clone()));
    next.insert(
        "sessionsRevokedBefore".into(),
        number(next_watermark(
            delegation.sessions_revoked_before,
            None,
            now,
        )?),
    );
    let revoked = tx.put("delegations", &next).await?;
    let ended = delete_delegated_sessions(tx, &json!({ "delegationId": delegation.id })).await?;
    let reference = json!({ "id": delegation.id, "tenantId": delegation.tenant_id });
    let handoffs = revoke_handoffs_below(tx, &reference, &revoked_by, now).await?;
    let mut metadata = Map::new();
    metadata.insert("agentId".into(), Value::String(delegation.agent_id.clone()));
    metadata.insert(
        "subjectId".into(),
        Value::String(delegation.subject_id.clone()),
    );
    metadata.insert("sessionsEnded".into(), number(ended));
    if handoffs != 0.0 {
        metadata.insert("handoffsRevoked".into(), number(handoffs));
    }
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        metadata.insert("reason".into(), Value::String(reason.to_owned()));
    }
    ctx.events()?
        .audit(
            tx,
            principal,
            "delegation:revoke",
            &delegation.tenant_id,
            &delegation.id,
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await?;
    summary(ctx, tx, &revoked).await
}

/// A confirmation request as the person and the agent see it (`ConfirmationSummary`).
async fn confirmation_summary(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    record: &Record,
) -> IamResult<Value> {
    let confirmation: DelegationConfirmation = decode(record.clone())?;
    let agent = tx.get("identities", &confirmation.agent_id).await?;
    let agent_name = agent
        .as_ref()
        .and_then(|agent| str_member(agent, "name"))
        .unwrap_or(&confirmation.agent_id)
        .to_owned();
    let mut result = Map::new();
    result.insert("id".into(), Value::String(confirmation.id.clone()));
    result.insert(
        "tenantId".into(),
        Value::String(confirmation.tenant_id.clone()),
    );
    result.insert(
        "delegationId".into(),
        Value::String(confirmation.delegation_id.clone()),
    );
    result.insert(
        "agent".into(),
        json!({ "id": confirmation.agent_id, "name": agent_name }),
    );
    result.insert(
        "subjectId".into(),
        Value::String(confirmation.subject_id.clone()),
    );
    result.insert("action".into(), Value::String(confirmation.action.clone()));
    result.insert(
        "resource".into(),
        json!({ "type": confirmation.resource_type, "id": confirmation.resource_id }),
    );
    result.insert("status".into(), Value::String(confirmation.status.clone()));
    result.insert(
        "expired".into(),
        Value::Bool(confirmation.status != "rejected" && confirmation.expires_at <= ctx.now()),
    );
    result.insert("createdAt".into(), number(confirmation.created_at));
    result.insert("expiresAt".into(), number(confirmation.expires_at));
    result.insert("validSeconds".into(), number(confirmation.valid_seconds));
    if let Some(reason) = &confirmation.reason {
        result.insert("reason".into(), Value::String(reason.clone()));
    }
    if let Some(at) = confirmation.decided_at {
        result.insert("decidedAt".into(), number(at));
    }
    Ok(Value::Object(result))
}

/// Which confirmation requests a caller may see: a person's own session sees those addressed to them, an agent's own
/// key those it made, and a delegated session those of its delegation. Anyone else is refused.
fn confirmation_scope(
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> IamResult<(&'static str, String)> {
    let refused = || refuse("Confirmation requests are read by the person or the agent involved");
    if principal.session.tenant_id != tenant_id || impersonating(principal) {
        return Err(refused());
    }
    if principal.session.kind == SessionKind::Delegated
        && let Some(delegation_id) = &principal.session.delegation_id
    {
        return Ok(("delegationId", delegation_id.clone()));
    }
    if principal.identity.kind == IdentityKind::Agent
        && principal.session.kind == SessionKind::ApiKey
    {
        return Ok(("agentId", principal.identity.id.clone()));
    }
    if principal.identity.kind == IdentityKind::User && principal.session.kind == SessionKind::User
    {
        return Ok(("subjectId", principal.identity.id.clone()));
    }
    Err(refused())
}

/// Validates an activity query exactly as `auditActivity` does (`limit` and `offset` default when nullish; `from`
/// and `to` when given), so the typed query carries what TypeScript would have accepted.
fn activity_query(input: &Map<String, Value>) -> IamResult<ActivityQuery> {
    let nullish = |key: &str| matches!(input.get(key), None | Some(Value::Null));
    let limit = if nullish("limit") {
        None
    } else {
        Some(integer(input.get("limit"), "limit", 1.0, 500.0)?)
    };
    let offset = if nullish("offset") {
        None
    } else {
        Some(integer(input.get("offset"), "offset", 0.0, 100_000.0)?)
    };
    let bound = |key: &str| -> IamResult<Option<f64>> {
        match input.get(key) {
            None => Ok(None),
            Some(value) => integer(Some(value), key, 0.0, crate::js::MAX_SAFE_INTEGER).map(Some),
        }
    };
    let from = bound("from")?;
    let to = bound("to")?;
    Ok(ActivityQuery {
        limit,
        offset,
        from,
        to,
        extra: Map::new(),
    })
}

/// Signs a delegation token's claims with the deployment's `a2a` card signer (`signer.signJwt(claims, typ)`).
async fn sign_delegation_token(
    signer: &Value,
    claims: &Map<String, Value>,
    typ: &str,
) -> IamResult<String> {
    let _ = (signer, claims, typ);
    Err(not_ported("a2a.ts CardSigner.signJwt"))
}

impl DelegationsApi {
    /// Runs `run` when the caller is involved in the delegation, else as an operation needing `action`.
    async fn involved_or(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        run: InvolvedRun,
    ) -> IamResult<Value> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let delegation_id = text(input.get("delegationId"), "delegationId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let own = {
            let (ctx, tenant_id, delegation_id, run) = (&ctx, &tenant_id, &delegation_id, &run);
            ctx.store
                .clone()
                .transaction(move |tx| async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, &authenticated)
                        .await?;
                    let Some(record) = tx.get("delegations", delegation_id).await? else {
                        return Ok(None);
                    };
                    if str_member(&record, "tenantId") != Some(tenant_id.as_str()) {
                        return Ok(None);
                    }
                    let delegation: Delegation = decode(record.clone())?;
                    if involved(&tx, &principal, &delegation).await?.is_none() {
                        return Ok(None);
                    }
                    Ok(Some(run_involved(ctx, &tx, &principal, record, run).await?))
                })
                .await?
        };
        if let Some(value) = own {
            return Ok(value);
        }
        let (ctx_ref, tenant_ref, id_ref, run_ref) = (&ctx, &tenant_id, &delegation_id, &run);
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let record = ctx_ref
                    .scoped(
                        &tx,
                        "delegations",
                        Some(&Value::String(id_ref.clone())),
                        tenant_ref,
                    )
                    .await?;
                Ok(run_involved(ctx_ref, &tx, &principal, record, run_ref).await?)
            })
        });
        ctx.operations()?
            .operation(
                credential,
                Some(&Value::String(tenant_id.clone())),
                action,
                &delegation_id,
                mutation,
                false,
            )
            .await
    }

    /// Issues a delegated session (see `assume`).
    async fn assume_delegation(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
    ) -> IamResult<Value> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let delegation_id = text(input.get("delegationId"), "delegationId", 256)?;
        let session_name = session_name_value(input.get("sessionName"))?;
        let policy = input.get("policy").cloned();
        if policy.is_some() {
            object(policy.as_ref())?;
        }
        let duration = input.get("durationSeconds").cloned();
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        ctx.store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                assert_agent_key(&principal, &tenant_id)?;
                let agent = principal.identity.clone();
                let record = tx.get("delegations", &delegation_id).await?;
                let now = ctx.now();
                let Some(record) = record.filter(|record| {
                    str_member(record, "tenantId") == Some(tenant_id.as_str())
                        && str_member(record, "agentId") == Some(agent.id.as_str())
                }) else {
                    return Err(not_found("Delegation not found"));
                };
                let delegation: Delegation = decode(record.clone())?;
                if delegation.status == "pending" && delegation.expires_at > now {
                    return Err(IamError::with_status(
                        "DELEGATION_PENDING",
                        "The person has not approved this delegation yet",
                        409,
                    ));
                }
                if !delegation_live(&delegation, now) {
                    return Err(inactive());
                }
                // A hand-off can be used only while every delegation, agent and key above it still can.
                if delegation.parent_id.is_some()
                    && live_ancestors(&ctx, &tx, &delegation, now).await?.is_none()
                {
                    return Err(IamError::with_status(
                        "DELEGATION_INACTIVE",
                        "A delegation above this one has ended",
                        403,
                    ));
                }
                if agent
                    .agent
                    .as_ref()
                    .is_some_and(|profile| profile.delegable == Some(false))
                {
                    return Err(IamError::with_status(
                        "DELEGATION_NOT_ALLOWED",
                        "This agent does not accept delegation",
                        403,
                    ));
                }
                let subject: Option<Identity> =
                    get_as(&tx, "identities", &delegation.subject_id).await?;
                let Some(subject) = subject.filter(|subject| {
                    subject.kind == IdentityKind::User
                        && subject.tenant_id == tenant_id
                        && subject.status == IdentityStatus::Active
                        && !ctx.identity_expired(subject)
                }) else {
                    return Err(IamError::with_status(
                        "DELEGATION_INACTIVE",
                        "The person behind this delegation is not active",
                        403,
                    ));
                };
                if let Some(policy) = &policy {
                    ctx.catalog
                        .validate(tx.as_ref(), &tenant_id, policy)
                        .await?;
                }
                let max = agent
                    .agent
                    .as_ref()
                    .and_then(|profile| profile.max_delegated_session_seconds)
                    .unwrap_or(agent_session_seconds("fallback"))
                    .min(
                        delegation
                            .max_session_seconds
                            .unwrap_or(agent_session_seconds("max")),
                    );
                let duration_seconds = match &duration {
                    None => 900f64.min(max),
                    Some(value) => integer(
                        Some(value),
                        "durationSeconds",
                        agent_session_seconds("min"),
                        max,
                    )?,
                };
                // Dead sessions of the delegation are deleted here, so the cap bounds the stored rows too.
                let mut live = 0.0;
                for session in tx
                    .find(
                        "sessions",
                        &Filter::new()
                            .eq("kind", "delegated")
                            .eq("delegationId", delegation_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    if num_member(&session, "expiresAt").unwrap_or(f64::NAN) <= now {
                        tx.delete("sessions", str_member(&session, "id").unwrap_or_default())
                            .await?;
                    } else {
                        live += 1.0;
                    }
                }
                if live >= MAX_SESSIONS_PER_DELEGATION {
                    return Err(IamError::with_status(
                        "LIMIT_EXCEEDED",
                        "This delegation holds the maximum number of live sessions",
                        409,
                    ));
                }
                let token = new_credential_token(CredentialTokenType::Dlg);
                let expires_at = (now + duration_seconds * 1000.0)
                    .min(delegation.expires_at)
                    .min(principal.session.expires_at);
                let mut row = Map::new();
                row.insert("id".into(), Value::String(id()));
                row.insert("tenantId".into(), Value::String(tenant_id.clone()));
                row.insert("identityId".into(), Value::String(subject.id.clone()));
                row.insert("kind".into(), Value::String("delegated".into()));
                row.insert("agentId".into(), Value::String(agent.id.clone()));
                row.insert("delegationId".into(), Value::String(delegation.id.clone()));
                row.insert(
                    "sourceSessionId".into(),
                    Value::String(principal.session.id.clone()),
                );
                row.insert("tokenHash".into(), Value::String(hash(&token)));
                row.insert("uniqueKey".into(), Value::String(hash(&token)));
                row.insert("createdAt".into(), number(now));
                row.insert("lastSeenAt".into(), number(now));
                // The person last authenticated for this when they decided on the delegation.
                row.insert(
                    "authenticatedAt".into(),
                    number(delegation.decided_at.unwrap_or(delegation.created_at)),
                );
                row.insert("expiresAt".into(), number(expires_at));
                row.insert("mfa".into(), Value::Bool(false));
                if let Some(policy) = &policy {
                    row.insert("policy".into(), policy.clone());
                }
                // The agent key's own limits carry over: its scopes (or session policy) and its issuer's authority
                // bound the delegated session too, as they bound session tokens minted from a key.
                if let Some(source_policy) = &principal.session.policy {
                    row.insert("sourcePolicy".into(), policy_value(source_policy));
                }
                if let Some(authority_id) = &principal.session.credential_authority_id {
                    row.insert(
                        "credentialAuthorityId".into(),
                        Value::String(authority_id.clone()),
                    );
                }
                if let Some(name) = &session_name {
                    row.insert("sessionName".into(), Value::String(name.clone()));
                }
                if let Some(client) = ctx.auth.current_client() {
                    let client = serde_json::to_value(client).unwrap_or(Value::Null);
                    if client.as_object().is_some_and(|map| !map.is_empty()) {
                        row.insert("client".into(), client);
                    }
                }
                let session = tx.insert("sessions", &row).await?;
                let session_id = str_member(&session, "id").unwrap_or_default().to_owned();
                let session_expires = num_member(&session, "expiresAt").unwrap_or(expires_at);
                let mut used = record;
                used.insert("lastUsedAt".into(), number(now));
                tx.put("delegations", &used).await?;
                let mut metadata = Map::new();
                metadata.insert("subjectId".into(), Value::String(subject.id.clone()));
                metadata.insert("sessionId".into(), Value::String(session_id.clone()));
                metadata.insert("durationSeconds".into(), number(duration_seconds));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "delegation:assume",
                        &tenant_id,
                        &delegation.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let mut session_view = Map::new();
                session_view.insert("id".into(), Value::String(session_id));
                session_view.insert("kind".into(), Value::String("delegated".into()));
                session_view.insert("tenantId".into(), Value::String(tenant_id.clone()));
                session_view.insert("identityId".into(), Value::String(subject.id.clone()));
                session_view.insert("agentId".into(), Value::String(agent.id.clone()));
                session_view.insert("delegationId".into(), Value::String(delegation.id.clone()));
                if let Some(name) = &session_name {
                    session_view.insert("sessionName".into(), Value::String(name.clone()));
                }
                Ok(json!({
                    "token": token,
                    "tokenType": "Bearer",
                    "expiresAt": number(session_expires),
                    "expiresIn": number(((session_expires - now) / 1000.0).floor().max(0.0)),
                    "session": Value::Object(session_view),
                }))
            })
            .await
    }

    /// `delegations/activity`: what happened under a delegation, newest first: its lifecycle (grant, request,
    /// approval, sessions opened, revocation) and every audit event of the agent's sessions acting for the person,
    /// allowed and denied. For the person, the agent, the agent's sponsor, or an administrator with
    /// `iam:delegations:read`.
    pub async fn activity(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::ActivityInput>,
    ) -> IamResult<Reply<delegations::ActivityOutput>> {
        let run = InvolvedRun::Activity(input.raw().clone());
        let value = self
            .involved_or(credential, input.raw(), "iam:delegations:read", run)
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/approve`: the person approves an agent's request, optionally narrowing (or replacing) its scope
    /// with `scopes`/`policy`, choosing another `expiresInSeconds`, or capping `maxSessionSeconds`. Needs their own
    /// session with a recent sign-in. Audited as `delegation:approve`.
    pub async fn approve(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::ApproveInput>,
    ) -> IamResult<Reply<delegations::ApproveOutput>> {
        let ctx = self.ctx.clone();
        let input = input.raw().clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let delegation_id = text(input.get("delegationId"), "delegationId", 256)?;
        let max_session_seconds = session_cap(input.get("maxSessionSeconds"))?;
        let seconds = match input.get("expiresInSeconds") {
            None => None,
            Some(value) => Some(delegation_seconds(Some(value))?),
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                assert_person(&principal, &tenant_id)?;
                ctx.auth.require_recent(&principal)?;
                let record = tx.get("delegations", &delegation_id).await?;
                let Some(record) = record.filter(|record| {
                    str_member(record, "tenantId") == Some(tenant_id.as_str())
                        && str_member(record, "subjectId") == Some(principal.identity.id.as_str())
                }) else {
                    return Err(not_found("Delegation not found"));
                };
                let delegation: Delegation = decode(record.clone())?;
                let now = ctx.now();
                if !delegation_pending(&delegation, now) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Only a pending request can be approved",
                        409,
                    ));
                }
                delegable_agent(
                    &ctx,
                    &tx,
                    Some(&Value::String(delegation.agent_id.clone())),
                    &tenant_id,
                )
                .await?;
                let mut next = record;
                next.insert("status".into(), Value::String("active".into()));
                next.insert("decidedAt".into(), number(now));
                if input.get("scopes").is_some() || input.get("policy").is_some() {
                    let scope = delegation_scope(&ctx, &tx, &tenant_id, &input).await?;
                    next.insert("policy".into(), scope.policy);
                    match scope.scopes {
                        Some(scopes) => {
                            next.insert("scopes".into(), strings_value(&scopes));
                        }
                        None => {
                            next.shift_remove("scopes");
                        }
                    }
                }
                let lifetime = match seconds {
                    Some(seconds) => seconds * 1000.0,
                    None => delegation
                        .lifetime_ms
                        .unwrap_or(delegation_lifetime::FALLBACK_SECONDS * 1000.0),
                };
                next.insert("expiresAt".into(), number(now + lifetime));
                next.shift_remove("lifetimeMs");
                if let Some(cap) = max_session_seconds {
                    next.insert("maxSessionSeconds".into(), number(cap));
                }
                // The person may add (or drop, with an empty list) actions to confirm one call at a time.
                if input.get("confirm").is_some() {
                    match confirm_patterns(input.get("confirm"))? {
                        Some(confirm) => {
                            next.insert("confirm".into(), strings_value(&confirm));
                        }
                        None => {
                            next.shift_remove("confirm");
                        }
                    }
                }
                // Hand-offs widen what happens in the person's name, so an agent's request for them counts only
                // when the person states it themselves here: a plain approval leaves them out.
                match handoff_setting(&tx, &tenant_id, input.get("handoff")).await? {
                    Some(handoff) => {
                        next.insert("handoff".into(), handoff_value(&handoff));
                    }
                    None => {
                        next.shift_remove("handoff");
                    }
                }
                // And set, change, or (with null) remove a spending cap.
                if input.get("spend").is_some() {
                    match spend_setting(input.get("spend"))? {
                        Some(spend) => {
                            next.insert("spend".into(), spend_value(&spend));
                        }
                        None => {
                            next.shift_remove("spend");
                        }
                    }
                }
                let approved = tx.put("delegations", &next).await?;
                let mut metadata = Map::new();
                metadata.insert("agentId".into(), Value::String(delegation.agent_id.clone()));
                metadata.insert(
                    "expiresAt".into(),
                    approved.get("expiresAt").cloned().unwrap_or(Value::Null),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "delegation:approve",
                        &tenant_id,
                        &delegation.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                summary(&ctx, &tx, &approved).await
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/assume`: the agent opens a delegated session (a `biam_dlg_…` bearer token) to act for the person:
    /// the token's identity is the person, bounded by the delegation's scope, the agent's ceiling and an optional
    /// scope-down `policy`. Lasts `durationSeconds` (60 up to the agent's `maxDelegatedSessionSeconds` and the
    /// delegation's `maxSessionSeconds`; 900 or less by default), never past the delegation or the agent's key. Needs
    /// the agent's own API key; at most 20 live sessions per delegation. Audited as `delegation:assume`.
    pub async fn assume(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::AssumeInput>,
    ) -> IamResult<Reply<delegations::AssumeOutput>> {
        let ctx = &self.ctx;
        let raw = input.raw().clone();
        let value = if ctx.auth.current_client().is_none() && credential.headers.is_some() {
            let client = crate::client_info::client_from_headers(
                ctx.options.http.as_ref(),
                credential.headers.as_deref(),
                ctx.config.base_url.as_str(),
            );
            ctx.auth
                .with_client(client, self.assume_delegation(credential, &raw))
                .await?
        } else {
            self.assume_delegation(credential, &raw).await?
        };
        Ok(Reply::json(value))
    }

    /// `delegations/decideConfirmation`: the person approves (`approve: true`) or rejects an agent's pending
    /// confirmation request from their own session. An approval allows exactly that action on that resource, once, for
    /// the agent acting for them, within the request's `validSeconds` (status `used` afterwards). Audited as
    /// `delegation:confirm` or `delegation:reject`.
    pub async fn decide_confirmation(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::DecideConfirmationInput>,
    ) -> IamResult<Reply<delegations::DecideConfirmationOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let confirmation_id = text(input.get("confirmationId"), "confirmationId", 256)?;
        let Some(approve) = input.get("approve").and_then(Value::as_bool) else {
            return Err(IamError::new("INVALID_INPUT", "approve must be a boolean"));
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                assert_person(&principal, &tenant_id)?;
                let record = tx.get("delegationConfirmations", &confirmation_id).await?;
                let Some(record) = record.filter(|record| {
                    str_member(record, "tenantId") == Some(tenant_id.as_str())
                        && str_member(record, "subjectId") == Some(principal.identity.id.as_str())
                }) else {
                    return Err(not_found("Confirmation request not found"));
                };
                let confirmation: DelegationConfirmation = decode(record.clone())?;
                let now = ctx.now();
                if confirmation.status != "pending" || confirmation.expires_at <= now {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Only a pending request can be decided",
                        409,
                    ));
                }
                let delegation: Option<Delegation> =
                    get_as(&tx, "delegations", &confirmation.delegation_id).await?;
                let Some(delegation) =
                    delegation.filter(|delegation| delegation_live(delegation, now))
                else {
                    return Err(inactive());
                };
                let mut next = record;
                next.insert(
                    "status".into(),
                    Value::String(if approve { "approved" } else { "rejected" }.into()),
                );
                next.insert("decidedAt".into(), number(now));
                next.insert(
                    "expiresAt".into(),
                    number(if approve {
                        now + confirmation.valid_seconds * 1000.0
                    } else {
                        now
                    }),
                );
                let decided = tx.put("delegationConfirmations", &next).await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "confirmationId".into(),
                    Value::String(confirmation.id.clone()),
                );
                metadata.insert("action".into(), Value::String(confirmation.action.clone()));
                metadata.insert(
                    "resource".into(),
                    Value::String(format!(
                        "{}/{}",
                        confirmation.resource_type, confirmation.resource_id
                    )),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        if approve {
                            "delegation:confirm"
                        } else {
                            "delegation:reject"
                        },
                        &tenant_id,
                        &delegation.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                confirmation_summary(&ctx, &tx, &decided).await
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/deny`: the person turns an agent's request down. Audited as `delegation:deny`.
    pub async fn deny(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::DenyInput>,
    ) -> IamResult<Reply<delegations::DenyOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let delegation_id = text(input.get("delegationId"), "delegationId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                assert_person(&principal, &tenant_id)?;
                let record = tx.get("delegations", &delegation_id).await?;
                let Some(record) = record.filter(|record| {
                    str_member(record, "tenantId") == Some(tenant_id.as_str())
                        && str_member(record, "subjectId") == Some(principal.identity.id.as_str())
                }) else {
                    return Err(not_found("Delegation not found"));
                };
                let delegation: Delegation = decode(record.clone())?;
                if !delegation_pending(&delegation, ctx.now()) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Only a pending request can be denied",
                        409,
                    ));
                }
                let mut next = record;
                next.insert("status".into(), Value::String("denied".into()));
                next.insert("decidedAt".into(), number(ctx.now()));
                let denied = tx.put("delegations", &next).await?;
                let mut metadata = Map::new();
                metadata.insert("agentId".into(), Value::String(delegation.agent_id.clone()));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "delegation:deny",
                        &tenant_id,
                        &delegation.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                summary(&ctx, &tx, &denied).await
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/get`: one delegation, for the person, the agent (agents poll this while a request is pending),
    /// the agent's sponsor, or an administrator with `iam:delegations:read`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::GetInput>,
    ) -> IamResult<Reply<delegations::GetOutput>> {
        let value = self
            .involved_or(
                credential,
                input.raw(),
                "iam:delegations:read",
                InvolvedRun::Get,
            )
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/getConfirmation`: one confirmation request, for the person it asks or the agent that asked
    /// (agents poll it while it is pending).
    pub async fn get_confirmation(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::GetConfirmationInput>,
    ) -> IamResult<Reply<delegations::GetConfirmationOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let confirmation_id = text(input.get("confirmationId"), "confirmationId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let (key, expected) = confirmation_scope(&principal, &tenant_id)?;
                let record = tx.get("delegationConfirmations", &confirmation_id).await?;
                let Some(record) = record.filter(|record| {
                    str_member(record, "tenantId") == Some(tenant_id.as_str())
                        && str_member(record, key) == Some(expected.as_str())
                }) else {
                    return Err(not_found("Confirmation request not found"));
                };
                confirmation_summary(&ctx, &tx, &record).await
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/grant`: a person lets an agent act for them: `scopes` (actions, wildcards allowed) or a `policy`
    /// bound what the agent may do, and it can never do more than the person could. Lasts `expiresInSeconds` (5
    /// minutes to a year; 30 days by default); `maxSessionSeconds` caps each delegated session below the agent's own
    /// limit. Needs the person's own session with a recent sign-in; refused while an undecided request or an active
    /// delegation already links the two. Audited as `delegation:grant`.
    pub async fn grant(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::GrantInput>,
    ) -> IamResult<Reply<delegations::GrantOutput>> {
        let ctx = self.ctx.clone();
        let input = input.raw().clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let seconds = delegation_seconds(input.get("expiresInSeconds"))?;
        let max_session_seconds = session_cap(input.get("maxSessionSeconds"))?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                assert_person(&principal, &tenant_id)?;
                ctx.auth.require_recent(&principal)?;
                let agent = delegable_agent(&ctx, &tx, input.get("agentId"), &tenant_id).await?;
                if let Some(existing) =
                    live_between(&ctx, &tx, &tenant_id, &agent.id, &principal.identity.id).await?
                {
                    return Err(IamError::with_status(
                        "DELEGATION_EXISTS",
                        if existing.status == "pending" {
                            "This agent is waiting for your decision on a request; approve or deny it"
                        } else {
                            "You already delegate to this agent; revoke that delegation first"
                        },
                        409,
                    ));
                }
                let scope = delegation_scope(&ctx, &tx, &tenant_id, &input).await?;
                let now = ctx.now();
                let delegation_id = id();
                let expires_at = now + seconds * 1000.0;
                let mut delegation = Map::new();
                delegation.insert("id".into(), Value::String(delegation_id.clone()));
                delegation.insert("tenantId".into(), Value::String(tenant_id.clone()));
                delegation.insert("agentId".into(), Value::String(agent.id.clone()));
                delegation.insert(
                    "subjectId".into(),
                    Value::String(principal.identity.id.clone()),
                );
                delegation.insert("status".into(), Value::String("active".into()));
                delegation.insert("policy".into(), scope.policy.clone());
                delegation.insert("requestedBy".into(), Value::String("subject".into()));
                delegation.insert("createdAt".into(), number(now));
                delegation.insert("decidedAt".into(), number(now));
                delegation.insert("expiresAt".into(), number(expires_at));
                if let Some(scopes) = &scope.scopes {
                    delegation.insert("scopes".into(), strings_value(scopes));
                }
                if let Some(cap) = max_session_seconds {
                    delegation.insert("maxSessionSeconds".into(), number(cap));
                }
                if let Some(confirm) = confirm_patterns(input.get("confirm"))? {
                    delegation.insert("confirm".into(), strings_value(&confirm));
                }
                if let Some(handoff) =
                    handoff_setting(&tx, &tenant_id, input.get("handoff")).await?
                {
                    delegation.insert("handoff".into(), handoff_value(&handoff));
                }
                if let Some(spend) = spend_setting(input.get("spend"))? {
                    delegation.insert("spend".into(), spend_value(&spend));
                }
                let delegation = tx.insert("delegations", &delegation).await?;
                let mut metadata = Map::new();
                metadata.insert("agentId".into(), Value::String(agent.id.clone()));
                metadata.insert("expiresAt".into(), number(expires_at));
                if let Some(scopes) = &scope.scopes {
                    metadata.insert("scopes".into(), Value::String(scopes.join(" ")));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "delegation:grant",
                        &tenant_id,
                        &delegation_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                summary(&ctx, &tx, &delegation).await
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/handoff`: an agent acting for a person hands part of that work on to another agent (for example
    /// one it calls over A2A): a new delegation from the same person to `agentId`, within `scopes`/`policy`. Needs a
    /// delegated session whose delegation lets the agent hand on (`handoff`, set by the person) to that agent. The
    /// hand-off never allows more than the delegations above it, the ceilings of the agents that handed it on, and
    /// the limits of the handing session (its scope-down policy, its key's scopes and issuer), and it works only while
    /// every delegation above it does. It keeps the person's `confirm` list (plus any given here) and lasts
    /// `expiresInSeconds` (60 seconds up to the delegation above; one hour by default). No agent may appear twice in a
    /// chain; at most 20 live hand-offs per delegation. Audited as `delegation:handoff`.
    pub async fn handoff(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::HandoffInput>,
    ) -> IamResult<Reply<delegations::HandoffOutput>> {
        let ctx = self.ctx.clone();
        let input = input.raw().clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let reason = match input.get("reason") {
            None => None,
            Some(value) => Some(text(Some(value), "reason", 1024)?),
        };
        let max_session_seconds = session_cap(input.get("maxSessionSeconds"))?;
        let seconds = match input.get("expiresInSeconds") {
            None => 3600.0,
            Some(value) => integer(
                Some(value),
                "expiresInSeconds",
                60.0,
                delegation_lifetime::MAX_SECONDS,
            )?,
        };
        let extra_confirm = confirm_patterns(input.get("confirm"))?.unwrap_or_default();
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        // Counted outside the transaction (a refusal cannot roll it back), per delegation handing on.
        if let Some(delegation_id) = &authenticated.session.delegation_id {
            ctx.auth
                .limit_attempt(
                    &tenant_id,
                    &format!("delegation-handoff:{delegation_id}"),
                    LimitAttemptOptions {
                        tier: Some(RateTier::Sensitive),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await?;
        }
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let session = principal.session.clone();
                let (Some(session_delegation), Some(session_agent)) =
                    (session.delegation_id.clone(), session.agent_id.clone())
                else {
                    return Err(refuse(
                        "Only an agent acting for a person (a delegated session) can hand work on",
                    ));
                };
                if session.kind != SessionKind::Delegated || session.tenant_id != tenant_id {
                    return Err(refuse(
                        "Only an agent acting for a person (a delegated session) can hand work on",
                    ));
                }
                let now = ctx.now();
                let parent: Option<Delegation> =
                    get_as(&tx, "delegations", &session_delegation).await?;
                let parent = match parent {
                    Some(parent)
                        if delegation_live(&parent, now)
                            && parent.tenant_id == tenant_id
                            && parent.agent_id == session_agent
                            && parent.subject_id == principal.identity.id =>
                    {
                        parent
                    }
                    _ => return Err(inactive()),
                };
                if live_ancestors(&ctx, &tx, &parent, now).await?.is_none() {
                    return Err(inactive());
                }
                let allowed = match &parent.handoff {
                    Some(allowed) if allowed.depth >= 1.0 => allowed.clone(),
                    _ => {
                        return Err(IamError::with_status(
                            "DELEGATION_NOT_ALLOWED",
                            "The person did not allow this delegation to be handed on",
                            403,
                        ));
                    }
                };
                let mut chain = parent.chain.clone().unwrap_or_default();
                chain.push(parent.agent_id.clone());
                let target = delegable_agent(&ctx, &tx, input.get("agentId"), &tenant_id).await?;
                if chain.contains(&target.id) {
                    return Err(IamError::with_status(
                        "DELEGATION_NOT_ALLOWED",
                        "An agent cannot receive a hand-off from its own delegation chain",
                        403,
                    ));
                }
                if let Some(agents) = &allowed.agents
                    && !agents.contains(&target.id)
                {
                    return Err(IamError::with_status(
                        "DELEGATION_NOT_ALLOWED",
                        "The person did not allow hand-offs to this agent",
                        403,
                    ));
                }
                let mut live = 0;
                for record in tx
                    .find(
                        "delegations",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("parentId", parent.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                {
                    let item: Delegation = decode(record)?;
                    if delegation_live(&item, now) {
                        live += 1;
                    }
                }
                if live >= handoff_limits::MAX_LIVE {
                    return Err(IamError::with_status(
                        "LIMIT_EXCEEDED",
                        "This delegation holds the maximum number of live hand-offs",
                        409,
                    ));
                }
                let scope = delegation_scope(&ctx, &tx, &tenant_id, &input).await?;
                // The key the handing agent acts with: the hand-off never outlives it, and ends when it is revoked.
                let key: Option<Session> = match &session.source_session_id {
                    Some(source) => get_as(&tx, "sessions", source).await?,
                    None => None,
                };
                let Some(key) = key.filter(|key| {
                    key.kind == SessionKind::ApiKey && key.identity_id == parent.agent_id
                }) else {
                    return Err(inactive());
                };
                let delegation_id = id();
                let mut delegation = Map::new();
                delegation.insert("id".into(), Value::String(delegation_id.clone()));
                delegation.insert("tenantId".into(), Value::String(tenant_id.clone()));
                delegation.insert("agentId".into(), Value::String(target.id.clone()));
                delegation.insert("subjectId".into(), Value::String(parent.subject_id.clone()));
                delegation.insert("status".into(), Value::String("active".into()));
                delegation.insert("policy".into(), scope.policy.clone());
                delegation.insert("requestedBy".into(), Value::String("handoff".into()));
                delegation.insert("createdAt".into(), number(now));
                delegation.insert("decidedAt".into(), number(now));
                delegation.insert(
                    "expiresAt".into(),
                    number(
                        (now + seconds * 1000.0)
                            .min(parent.expires_at)
                            .min(key.expires_at),
                    ),
                );
                delegation.insert("parentId".into(), Value::String(parent.id.clone()));
                delegation.insert("chain".into(), strings_value(&chain));
                delegation.insert("keyId".into(), Value::String(key.id.clone()));
                if let Some(scopes) = &scope.scopes {
                    delegation.insert("scopes".into(), strings_value(scopes));
                }
                if let Some(reason) = &reason {
                    delegation.insert("reason".into(), Value::String(reason.clone()));
                }
                let cap: Vec<f64> = [max_session_seconds, parent.max_session_seconds]
                    .into_iter()
                    .flatten()
                    .collect();
                if !cap.is_empty() {
                    delegation.insert(
                        "maxSessionSeconds".into(),
                        number(cap.into_iter().fold(f64::INFINITY, f64::min)),
                    );
                }
                let mut inherited = parent.confirm.clone().unwrap_or_default();
                inherited.extend(extra_confirm.iter().cloned());
                if let Some(confirm) = confirm_patterns(Some(&strings_value(&inherited)))? {
                    delegation.insert("confirm".into(), strings_value(&confirm));
                }
                if allowed.depth > 1.0 {
                    let mut handoff = Map::new();
                    handoff.insert("depth".into(), number(allowed.depth - 1.0));
                    if let Some(agents) = &allowed.agents {
                        handoff.insert("agents".into(), strings_value(agents));
                    }
                    delegation.insert("handoff".into(), Value::Object(handoff));
                }
                // The handing session's own limits travel with the hand-off.
                let ceilings: Vec<Value> = [&session.policy, &session.source_policy]
                    .into_iter()
                    .flatten()
                    .map(policy_value)
                    .collect();
                if !ceilings.is_empty() {
                    delegation.insert("ceilings".into(), Value::Array(ceilings));
                }
                if let Some(authority_id) = &session.credential_authority_id {
                    delegation.insert("authorityId".into(), Value::String(authority_id.clone()));
                }
                // A cap of its own, on top of the caps of the delegations above (which count the hand-off's calls
                // too).
                if let Some(spend) = spend_setting(input.get("spend"))? {
                    delegation.insert("spend".into(), spend_value(&spend));
                }
                let delegation = tx.insert("delegations", &delegation).await?;
                let mut metadata = Map::new();
                metadata.insert("parentId".into(), Value::String(parent.id.clone()));
                metadata.insert("fromAgentId".into(), Value::String(parent.agent_id.clone()));
                metadata.insert("toAgentId".into(), Value::String(target.id.clone()));
                metadata.insert("depth".into(), number(chain.len() as f64));
                if let Some(scopes) = &scope.scopes {
                    metadata.insert("scopes".into(), Value::String(scopes.join(" ")));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "delegation:handoff",
                        &tenant_id,
                        &delegation_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                summary(&ctx, &tx, &delegation).await
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/issueToken`: an agent acting for a person (its delegated session) gets a delegation token to show
    /// a service outside Better IAM that it acts for that person: a JWT signed with the deployment's `a2a` keys (`typ`
    /// `biam-delegation+jwt`) whose `sub` is the person and whose `act` claim is the agent, with the agents that
    /// handed the work to it nested inside (RFC 8693). `audience` must be one service that every agent in the chain
    /// lists in its `tokenAudiences`. `scopes` (the delegation's own by default) must each be allowed outright by every
    /// limit on the session. Lasts `lifetimeSeconds` (30 to 3600; 300 by default), never past the session or a
    /// delegation in the chain. Needs the `a2a` option. Rate limited per delegation. Audited as
    /// `delegation:token-issue`.
    pub async fn issue_token(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::IssueTokenInput>,
    ) -> IamResult<Reply<delegations::IssueTokenOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let audience = crate::agents::token_audience(input.get("audience"))?;
        let requested = match input.get("scopes") {
            None => None,
            Some(value) => Some(crate::js::unique(strings(Some(value), "scopes")?)),
        };
        let lifetime = match input.get("lifetimeSeconds") {
            None => delegation_token_limits::DEFAULT_SECONDS,
            Some(value) => integer(
                Some(value),
                "lifetimeSeconds",
                delegation_token_limits::MIN_SECONDS,
                delegation_token_limits::MAX_SECONDS,
            )?,
        };
        let Some(signer) = crate::a2a::card_signer(&ctx)? else {
            return Err(IamError::with_status(
                "FEATURE_DISABLED",
                "Delegation tokens need the deployment\u{2019}s a2a signing keys",
                403,
            ));
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        // Counted outside the transaction, per delegation, in a budget of its own.
        if let Some(delegation_id) = &authenticated.session.delegation_id {
            ctx.auth
                .limit_attempt(
                    &tenant_id,
                    &format!("delegation-token:{delegation_id}"),
                    LimitAttemptOptions {
                        limit: Some(120.0),
                        ..LimitAttemptOptions::default()
                    },
                )
                .await?;
        }
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let session = principal.session.clone();
                let refused = || {
                    refuse(
                        "Only an agent acting for a person (a delegated session) gets delegation tokens",
                    )
                };
                let (Some(session_delegation), Some(session_agent)) =
                    (session.delegation_id.clone(), session.agent_id.clone())
                else {
                    return Err(refused());
                };
                if session.kind != SessionKind::Delegated || session.tenant_id != tenant_id {
                    return Err(refused());
                }
                let now = ctx.now();
                let delegation: Option<Delegation> =
                    get_as(&tx, "delegations", &session_delegation).await?;
                let ancestors = match &delegation {
                    Some(delegation) => live_ancestors(&ctx, &tx, delegation, now).await?,
                    None => None,
                };
                let agent: Option<Identity> = get_as(&tx, "identities", &session_agent).await?;
                let tenant: Option<Tenant> = get_as(&tx, "tenants", &tenant_id).await?;
                // The agent's API key the session came from: the token is live only while it is.
                let key: Option<Session> = match &session.source_session_id {
                    Some(source) => get_as(&tx, "sessions", source).await?,
                    None => None,
                };
                let (Some(delegation), Some(ancestors), Some(agent), Some(tenant), Some(key)) =
                    (delegation, ancestors, agent, tenant, key)
                else {
                    return Err(inactive());
                };
                if key.kind != SessionKind::ApiKey
                    || key.identity_id != session_agent
                    || !delegation_live(&delegation, now)
                    || delegation.tenant_id != tenant_id
                    || delegation.agent_id != agent.id
                    || delegation.subject_id != principal.identity.id
                {
                    return Err(inactive());
                }
                // Every agent the work passed through must be allowed to present it to this service.
                let mut agents: Vec<Identity> = ancestors
                    .iter()
                    .rev()
                    .map(|ancestor| ancestor.agent.clone())
                    .collect();
                agents.push(agent.clone());
                if let Some(outsider) = audience_refusal(&agents, &audience)? {
                    return Err(IamError::with_status(
                        "DELEGATION_NOT_ALLOWED",
                        format!(
                            "Agent {} may not present delegations to {audience}",
                            outsider.name
                        ),
                        403,
                    ));
                }
                let scopes = requested
                    .clone()
                    .or_else(|| delegation.scopes.clone())
                    .unwrap_or_default();
                if scopes.len() > 50 || scopes.iter().any(|scope| !delegation_token_scope(scope)) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "scopes must list at most 50 actions or action patterns (letters, digits, :_./- and *)",
                    ));
                }
                let session_policies: Vec<PolicyDocument> = [&session.policy, &session.source_policy]
                    .into_iter()
                    .flatten()
                    .cloned()
                    .collect();
                let authority_id = session.credential_authority_id.clone();
                let refusal = scope_refusal(
                    &ctx,
                    &tx,
                    &TokenBasis {
                        tenant: tenant.clone(),
                        person_id: principal.identity.id.clone(),
                        delegation: delegation.clone(),
                        ancestors: ancestors.clone(),
                        agents: agents.clone(),
                        session_policies: session_policies.clone(),
                        authority_ids: authority_id.iter().cloned().collect(),
                    },
                    &scopes,
                )
                .await?;
                match refusal {
                    None => {}
                    Some(ScopeRefusal::Inactive) => return Err(inactive()),
                    Some(ScopeRefusal::Scope { scope, why }) => {
                        return Err(IamError::with_status(
                            "DELEGATION_NOT_ALLOWED",
                            match why {
                                "confirm" => format!(
                                    "The person confirms {scope} call by call; a token cannot carry it"
                                ),
                                "deny" => format!(
                                    "A deny statement of the person's own access may touch {scope}"
                                ),
                                _ => format!("The delegation does not allow {scope} outright"),
                            },
                            403,
                        ));
                    }
                }
                let issued_at = (now / 1000.0).floor();
                let expires_at = std::iter::once(session.expires_at)
                    .chain(std::iter::once(delegation.expires_at))
                    .chain(ancestors.iter().map(|ancestor| ancestor.delegation.expires_at))
                    .map(|at| (at / 1000.0).floor())
                    .fold(issued_at + lifetime, f64::min);
                if expires_at <= issued_at {
                    return Err(inactive());
                }
                let chain: Vec<String> = agents.iter().map(|item| item.id.clone()).collect();
                let issuer = js_string(signer.get("issuer"));
                let jti = random_token();
                let actor = delegation_actor(&chain).map_err(|_| crate::js::internal_error())?;
                let mut claims = Map::new();
                claims.insert("iss".into(), Value::String(issuer.clone()));
                claims.insert("sub".into(), Value::String(principal.identity.id.clone()));
                claims.insert("aud".into(), Value::String(audience.clone()));
                claims.insert("iat".into(), number(issued_at));
                claims.insert("nbf".into(), number(issued_at));
                claims.insert("exp".into(), number(expires_at));
                claims.insert("jti".into(), Value::String(jti.clone()));
                claims.insert("tenant_id".into(), Value::String(tenant_id.clone()));
                claims.insert("delegation_id".into(), Value::String(delegation.id.clone()));
                claims.insert(
                    "act".into(),
                    serde_json::to_value(actor).unwrap_or(Value::Null),
                );
                if !scopes.is_empty() {
                    claims.insert("scope".into(), Value::String(scopes.join(" ")));
                }
                let token = sign_delegation_token(&signer, &claims, DELEGATION_TOKEN_TYPE).await?;
                // Kept until it expires, so a live verification can re-check what the token stands on.
                let record = DelegationTokenRecord {
                    id: jti.clone(),
                    delegation_id: delegation.id.clone(),
                    person_id: principal.identity.id.clone(),
                    agent_id: agent.id.clone(),
                    key_id: key.id.clone(),
                    audience: audience.clone(),
                    scopes: scopes.clone(),
                    session_policies: session_policies.clone(),
                    authority_id: authority_id.clone(),
                    created_at: now,
                    expires_at: expires_at * 1000.0,
                    tenant_id: tenant_id.clone(),
                    unique_key: None,
                    extra: Map::new(),
                };
                let policies: Vec<Value> = session_policies.iter().map(policy_value).collect();
                tx.insert("delegationTokens", &token_record_value(&record, &policies))
                    .await?;
                let mut metadata = Map::new();
                metadata.insert("audience".into(), Value::String(audience.clone()));
                metadata.insert("tokenId".into(), Value::String(jti.clone()));
                metadata.insert("expiresAt".into(), number(expires_at * 1000.0));
                if !scopes.is_empty() {
                    metadata.insert("scopes".into(), Value::String(scopes.join(" ")));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "delegation:token-issue",
                        &tenant_id,
                        &delegation.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(json!({
                    "token": token,
                    "tokenType": DELEGATION_TOKEN_TYPE,
                    "tokenId": jti,
                    "issuer": issuer,
                    "audience": audience,
                    "scopes": scopes,
                    "chain": chain,
                    "expiresAt": number(expires_at * 1000.0),
                    "expiresIn": number(expires_at - issued_at),
                }))
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/list`: the tenant's delegations, newest first, filtered by agent, person or status. Needs
    /// `iam:delegations:read`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::ListInput>,
    ) -> IamResult<Reply<delegations::ListOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut filter = Filter::new().eq(
                    "tenantId",
                    body.get("tenantId").cloned().unwrap_or(Value::Null),
                );
                if body.get("agentId").is_some() {
                    filter = filter.eq("agentId", text(body.get("agentId"), "agentId", 256)?);
                }
                if body.get("subjectId").is_some() {
                    filter = filter.eq("subjectId", text(body.get("subjectId"), "subjectId", 256)?);
                }
                if body.get("status").is_some() {
                    filter = filter.eq("status", text(body.get("status"), "status", 16)?);
                }
                let mut found = tx
                    .find("delegations", &filter, &FindOptions::default())
                    .await?;
                found.sort_by(by_newest_records);
                let mut items = Vec::new();
                for delegation in &found {
                    items.push(summary(ctx, &tx, delegation).await?);
                }
                Ok(Value::Array(items))
            })
        });
        let value = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:delegations:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/listConfirmations`: confirmation requests, newest first: for a person, the ones addressed to them;
    /// for an agent's own key, every one it made; for a delegated session, those of its delegation. `status` filters.
    /// Needs no permission.
    pub async fn list_confirmations(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::ListConfirmationsInput>,
    ) -> IamResult<Reply<delegations::ListConfirmationsOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let status = input.get("status").cloned();
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let (key, expected) = confirmation_scope(&principal, &tenant_id)?;
                let mut filter = Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq(key, expected);
                if let Some(status) = &status {
                    filter = filter.eq("status", text(Some(status), "status", 16)?);
                }
                let mut found = tx
                    .find("delegationConfirmations", &filter, &FindOptions::default())
                    .await?;
                found.sort_by(by_newest_records);
                let mut items = Vec::new();
                for item in &found {
                    items.push(confirmation_summary(&ctx, &tx, item).await?);
                }
                Ok(Value::Array(items))
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/listMine`: the caller's own delegations, newest first: for a person, the agents acting (or asking
    /// to act) for them; for an agent with its own key, the people it acts for. Needs no permission.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::ListMineInput>,
    ) -> IamResult<Reply<delegations::ListMineOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let mut filter = Filter::new().eq("tenantId", tenant_id.clone());
                if principal.identity.kind == IdentityKind::Agent {
                    assert_agent_key(&principal, &tenant_id)?;
                    filter = filter.eq("agentId", principal.identity.id.clone());
                } else {
                    assert_person(&principal, &tenant_id)?;
                    filter = filter.eq("subjectId", principal.identity.id.clone());
                }
                let mut found = tx
                    .find("delegations", &filter, &FindOptions::default())
                    .await?;
                found.sort_by(by_newest_records);
                let mut items = Vec::new();
                for delegation in &found {
                    items.push(summary(&ctx, &tx, delegation).await?);
                }
                Ok(Value::Array(items))
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/request`: an agent asks a person (`subjectId`, or `subjectEmail`) to delegate to it: the request
    /// waits up to seven days for their decision and is emailed to them (template `delegation-request`) when the
    /// deployment sends email. `reason` is shown to the person; `expiresInSeconds` is how long the delegation lasts
    /// once approved. Needs the agent's own API key. Requests are rate limited per agent. Audited as
    /// `delegation:request`.
    pub async fn request(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::RequestInput>,
    ) -> IamResult<Reply<delegations::RequestOutput>> {
        let ctx = self.ctx.clone();
        let input = input.raw().clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let reason = text(input.get("reason"), "reason", 1024)?;
        let seconds = delegation_seconds(input.get("expiresInSeconds"))?;
        let max_session_seconds = session_cap(input.get("maxSessionSeconds"))?;
        if input.get("subjectId").is_none() == input.get("subjectEmail").is_none() {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Provide either subjectId or subjectEmail",
            ));
        }
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        assert_agent_key(&authenticated, &tenant_id)?;
        // Counted outside any transaction, so a refused request cannot roll the attempt back.
        ctx.auth
            .limit_attempt(
                &tenant_id,
                &format!("delegation-request:{}", authenticated.identity.id),
                LimitAttemptOptions {
                    tier: Some(RateTier::Sensitive),
                    ..LimitAttemptOptions::default()
                },
            )
            .await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                assert_agent_key(&principal, &tenant_id)?;
                let agent = delegable_agent(
                    &ctx,
                    &tx,
                    Some(&Value::String(principal.identity.id.clone())),
                    &tenant_id,
                )
                .await?;
                let subject: Option<Identity> = if input.get("subjectId").is_some() {
                    let subject_id = text(input.get("subjectId"), "subjectId", 256)?;
                    get_as(&tx, "identities", &subject_id).await?
                } else {
                    let address = email(input.get("subjectEmail"))?;
                    match tx
                        .find(
                            "identities",
                            &Filter::new()
                                .eq("tenantId", tenant_id.clone())
                                .eq("email", address),
                            &FindOptions::default(),
                        )
                        .await?
                        .into_iter()
                        .next()
                    {
                        Some(record) => Some(decode(record)?),
                        None => None,
                    }
                };
                let Some(subject) = subject.filter(|subject| {
                    subject.tenant_id == tenant_id
                        && subject.kind == IdentityKind::User
                        && subject.status == IdentityStatus::Active
                        && !ctx.identity_expired(subject)
                }) else {
                    return Err(not_found("No active person with that identifier"));
                };
                if live_between(&ctx, &tx, &tenant_id, &agent.id, &subject.id)
                    .await?
                    .is_some()
                {
                    return Err(IamError::with_status(
                        "DELEGATION_EXISTS",
                        "A request or delegation between this agent and person already exists",
                        409,
                    ));
                }
                let scope = delegation_scope(&ctx, &tx, &tenant_id, &input).await?;
                let now = ctx.now();
                let delegation_id = id();
                let mut delegation = Map::new();
                delegation.insert("id".into(), Value::String(delegation_id.clone()));
                delegation.insert("tenantId".into(), Value::String(tenant_id.clone()));
                delegation.insert("agentId".into(), Value::String(agent.id.clone()));
                delegation.insert("subjectId".into(), Value::String(subject.id.clone()));
                delegation.insert("status".into(), Value::String("pending".into()));
                delegation.insert("policy".into(), scope.policy.clone());
                delegation.insert("requestedBy".into(), Value::String("agent".into()));
                delegation.insert("reason".into(), Value::String(reason.clone()));
                delegation.insert("createdAt".into(), number(now));
                delegation.insert(
                    "expiresAt".into(),
                    number(now + delegation_lifetime::REQUEST_MS),
                );
                delegation.insert("lifetimeMs".into(), number(seconds * 1000.0));
                if let Some(scopes) = &scope.scopes {
                    delegation.insert("scopes".into(), strings_value(scopes));
                }
                if let Some(cap) = max_session_seconds {
                    delegation.insert("maxSessionSeconds".into(), number(cap));
                }
                if let Some(confirm) = confirm_patterns(input.get("confirm"))? {
                    delegation.insert("confirm".into(), strings_value(&confirm));
                }
                if let Some(handoff) =
                    handoff_setting(&tx, &tenant_id, input.get("handoff")).await?
                {
                    delegation.insert("handoff".into(), handoff_value(&handoff));
                }
                if let Some(spend) = spend_setting(input.get("spend"))? {
                    delegation.insert("spend".into(), spend_value(&spend));
                }
                let delegation = tx.insert("delegations", &delegation).await?;
                if let Some(address) = subject.email.as_ref().filter(|email| !email.is_empty())
                    && sends_email(&ctx)
                {
                    let mut payload = Map::new();
                    payload.insert("delegationId".into(), Value::String(delegation_id.clone()));
                    payload.insert("agentName".into(), Value::String(agent.name.clone()));
                    payload.insert("reason".into(), Value::String(reason.clone()));
                    payload.insert(
                        "scopes".into(),
                        Value::String(match &scope.scopes {
                            Some(scopes) => scopes.join(", "),
                            None => "a custom policy".into(),
                        }),
                    );
                    payload.insert(
                        "days".into(),
                        Value::String(core_js::number_to_string(
                            1f64.max((seconds / 86_400.0).round()),
                        )),
                    );
                    if let Some(model) = agent
                        .agent
                        .as_ref()
                        .and_then(|profile| profile.model.as_ref())
                        .filter(|model| !model.is_empty())
                    {
                        payload.insert("model".into(), Value::String(model.clone()));
                    }
                    ctx.auth
                        .enqueue_delivery(
                            &tx,
                            EnqueueInput {
                                tenant_id: tenant_id.clone(),
                                kind: OutboxKind::Email,
                                to: address.clone(),
                                template: "delegation-request".into(),
                                payload,
                                reference: None,
                            },
                        )
                        .await?;
                }
                let mut metadata = Map::new();
                metadata.insert("subjectId".into(), Value::String(subject.id.clone()));
                if let Some(scopes) = &scope.scopes {
                    metadata.insert("scopes".into(), Value::String(scopes.join(" ")));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "delegation:request",
                        &tenant_id,
                        &delegation_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                summary(&ctx, &tx, &delegation).await
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/requestConfirmation`: an agent acting for a person (with its delegated session) asks them to
    /// confirm one action the delegation holds back (`confirm`): `action` on `resource`, with a `reason` shown to the
    /// person. The request waits up to 30 minutes and is emailed to the person (template `delegation-confirmation`);
    /// an identical pending request is returned as it is. Once approved, that action on that resource is allowed once
    /// (the call uses the approval up), within `validSeconds` (30 to 3600; 300 by default). Rate limited per
    /// delegation. Audited as `delegation:confirmation-request`.
    pub async fn request_confirmation(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::RequestConfirmationInput>,
    ) -> IamResult<Reply<delegations::RequestConfirmationOutput>> {
        let ctx = self.ctx.clone();
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let action = text(input.get("action"), "action", 256)?;
        let resource = object(input.get("resource"))?;
        let resource_type = text(resource.get("type"), "resource type", 64)?;
        let resource_id = text(resource.get("id"), "resource id", 2048)?;
        let reason = text(input.get("reason"), "reason", 1024)?;
        let valid_seconds = match input.get("validSeconds") {
            None => confirmation_limits::FALLBACK_VALID_SECONDS,
            Some(value) => integer(
                Some(value),
                "validSeconds",
                confirmation_limits::MIN_VALID_SECONDS,
                confirmation_limits::MAX_VALID_SECONDS,
            )?,
        };
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let delegation_id = match &authenticated.session.delegation_id {
            Some(delegation_id)
                if authenticated.session.kind == SessionKind::Delegated
                    && authenticated.session.tenant_id == tenant_id =>
            {
                delegation_id.clone()
            }
            _ => {
                return Err(refuse(
                    "Only an agent acting for a person can ask them to confirm an action",
                ));
            }
        };
        // Counted outside any transaction, so a refused request cannot roll the attempt back.
        ctx.auth
            .limit_attempt(
                &tenant_id,
                &format!("delegation-confirm:{delegation_id}"),
                LimitAttemptOptions::default(),
            )
            .await?;
        let value = ctx
            .store
            .clone()
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let current = principal.session.delegation_id.clone().unwrap_or_default();
                let Some(record) = tx.get("delegations", &current).await? else {
                    return Err(IamError::with_status(
                        "UNAUTHENTICATED",
                        "Delegation revoked",
                        401,
                    ));
                };
                if !needs_confirmation(&record, &action) {
                    return Err(IamError::new(
                        "INVALID_INPUT",
                        "This delegation does not hold that action back for confirmation",
                    ));
                }
                let delegation: Delegation = decode(record)?;
                let now = ctx.now();
                let pending = tx
                    .find(
                        "delegationConfirmations",
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("delegationId", delegation.id.clone())
                            .eq("status", "pending"),
                        &FindOptions::default(),
                    )
                    .await?
                    .into_iter()
                    .find(|item| {
                        num_member(item, "expiresAt").unwrap_or(f64::NAN) > now
                            && str_member(item, "action") == Some(action.as_str())
                            && str_member(item, "resourceType") == Some(resource_type.as_str())
                            && str_member(item, "resourceId") == Some(resource_id.as_str())
                    });
                if let Some(pending) = pending {
                    return confirmation_summary(&ctx, &tx, &pending).await;
                }
                let confirmation_id = id();
                let resource_ref = format!("{resource_type}/{resource_id}");
                let mut confirmation = Map::new();
                confirmation.insert("id".into(), Value::String(confirmation_id.clone()));
                confirmation.insert("tenantId".into(), Value::String(tenant_id.clone()));
                confirmation.insert("delegationId".into(), Value::String(delegation.id.clone()));
                confirmation.insert("agentId".into(), Value::String(delegation.agent_id.clone()));
                confirmation.insert(
                    "subjectId".into(),
                    Value::String(delegation.subject_id.clone()),
                );
                confirmation.insert("action".into(), Value::String(action.clone()));
                confirmation.insert("resourceType".into(), Value::String(resource_type.clone()));
                confirmation.insert("resourceId".into(), Value::String(resource_id.clone()));
                confirmation.insert("reason".into(), Value::String(reason.clone()));
                confirmation.insert("status".into(), Value::String("pending".into()));
                confirmation.insert("createdAt".into(), number(now));
                confirmation.insert(
                    "expiresAt".into(),
                    number(now + confirmation_limits::DECIDE_MS),
                );
                confirmation.insert("validSeconds".into(), number(valid_seconds));
                let confirmation = tx.insert("delegationConfirmations", &confirmation).await?;
                let agent = tx.get("identities", &delegation.agent_id).await?;
                if let Some(address) = principal
                    .identity
                    .email
                    .as_ref()
                    .filter(|email| !email.is_empty())
                    && sends_email(&ctx)
                {
                    let agent_name = agent
                        .as_ref()
                        .and_then(|agent| str_member(agent, "name"))
                        .unwrap_or("An AI agent")
                        .to_owned();
                    let mut payload = Map::new();
                    payload.insert("delegationId".into(), Value::String(delegation.id.clone()));
                    payload.insert(
                        "confirmationId".into(),
                        Value::String(confirmation_id.clone()),
                    );
                    payload.insert("agentName".into(), Value::String(agent_name));
                    payload.insert("action".into(), Value::String(action.clone()));
                    payload.insert("resource".into(), Value::String(resource_ref.clone()));
                    payload.insert("reason".into(), Value::String(reason.clone()));
                    payload.insert(
                        "minutes".into(),
                        Value::String(core_js::number_to_string(
                            (confirmation_limits::DECIDE_MS / 60_000.0).round(),
                        )),
                    );
                    ctx.auth
                        .enqueue_delivery(
                            &tx,
                            EnqueueInput {
                                tenant_id: tenant_id.clone(),
                                kind: OutboxKind::Email,
                                to: address.clone(),
                                template: "delegation-confirmation".into(),
                                payload,
                                reference: None,
                            },
                        )
                        .await?;
                }
                let mut metadata = Map::new();
                metadata.insert("confirmationId".into(), Value::String(confirmation_id));
                metadata.insert("action".into(), Value::String(action.clone()));
                metadata.insert("resource".into(), Value::String(resource_ref));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "delegation:confirmation-request",
                        &tenant_id,
                        &delegation.id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                confirmation_summary(&ctx, &tx, &confirmation).await
            })
            .await?;
        Ok(Reply::json(value))
    }

    /// `delegations/revoke`: ends a pending or active delegation and its live sessions at once. The person, the agent
    /// (with its own key), the agent's sponsor or an administrator with `iam:delegations:revoke` may revoke. Audited
    /// as `delegation:revoke`.
    pub async fn revoke(
        &self,
        credential: &CredentialInput,
        input: Body<delegations::RevokeInput>,
    ) -> IamResult<Reply<delegations::RevokeOutput>> {
        let reason = match input.get("reason") {
            None => None,
            Some(value) => Some(text(Some(value), "reason", 512)?),
        };
        let value = self
            .involved_or(
                credential,
                input.raw(),
                "iam:delegations:revoke",
                InvolvedRun::Revoke(reason),
            )
            .await?;
        Ok(Reply::json(value))
    }
}
