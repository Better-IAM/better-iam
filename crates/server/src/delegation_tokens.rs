//! Port of `packages/server/src/delegation-tokens.ts`.
//!
//! What delegation tokens (`delegations.issueToken`) stand on, shared by issuing them and by live verification
//! (`iam.a2a.verifyDelegationToken(token, { live: true })`): the delegation chain, where the token may go, and which
//! scopes it may carry.

use std::sync::Arc;

use better_iam_core::{
    Effect, Filter, FindOptions, IamResult, Identity, IdentityStatus, PolicyDocument, Session,
    SessionKind, Tenant, TenantStatus,
};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::context::{ServerContext, Store};
use crate::contracts::GrantPath;
use crate::delegations::{
    Delegation, DelegationAncestor, actions_may_overlap, delegation_live, live_ancestors,
    policy_allows_scope,
};
use crate::port::decode;

/// An issued delegation token, kept until it expires so a live verification can re-check what it stands on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationTokenRecord {
    /// The token's `jti`.
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "delegationId")]
    pub delegation_id: String,
    #[serde(rename = "personId")]
    pub person_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    /// The API key the acting agent's session came from: the token is live only while the key is.
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "audience")]
    pub audience: String,
    #[serde(rename = "scopes")]
    pub scopes: Vec<String>,
    /// The limits of the session that asked for the token (its scope-down policy and its key's policy).
    #[serde(rename = "sessionPolicies")]
    pub session_policies: Vec<PolicyDocument>,
    /// The issuer authority of the acting agent's key, whose ceilings apply too.
    #[serde(
        rename = "authorityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub authority_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A delegation chain as a token names it (`TokenBasis`).
#[derive(Debug, Clone)]
pub struct TokenBasis {
    pub tenant: Tenant,
    pub person_id: String,
    pub delegation: Delegation,
    /// The delegations above a hand-off, nearest first, with their agents.
    pub ancestors: Vec<DelegationAncestor>,
    /// The agents from the person's own delegate to the one acting now.
    pub agents: Vec<Identity>,
    pub session_policies: Vec<PolicyDocument>,
    /// Key issuer authorities beyond those the chain records (the acting key's).
    pub authority_ids: Vec<String>,
}

/// Why a scope may not be carried: a limit does not allow it outright, the person confirms it, or a deny may touch
/// it (`ScopeRefusal`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScopeRefusal {
    /// `{ scope, why }`: `why` is `limit`, `confirm` or `deny`.
    Scope { scope: String, why: &'static str },
    /// `{ inactive: true }`: an issuer authority of the chain was revoked.
    Inactive,
}

/// The first agent of the chain that may not present delegations to `audience`, if any.
pub fn audience_refusal(agents: &[Identity], audience: &str) -> IamResult<Option<Identity>> {
    for agent in agents {
        let mut allowed = false;
        for pattern in agent
            .agent
            .as_ref()
            .and_then(|profile| profile.token_audiences.as_ref())
            .into_iter()
            .flatten()
        {
            if crate::agents::audience_matches(pattern, audience)? {
                allowed = true;
                break;
            }
        }
        if !allowed {
            return Ok(Some(agent.clone()));
        }
    }
    Ok(None)
}

/// The first scope the chain may not carry, or None when it may carry them all. Every scope must be allowed
/// outright by every limit a decision for the acting session applies (the delegations and their ceilings, the
/// agents' boundaries, the session's policies, the key issuers' authority, the tenant's and the person's
/// boundaries, and the tenant's guest boundary for a guest). None may be one the person confirms call by call
/// (`confirm`, anywhere in the chain), nor one a deny statement among the person's own grants could touch: a token
/// carries no resource or condition to refine them with.
pub async fn scope_refusal(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    basis: &TokenBasis,
    scopes: &[String],
) -> IamResult<Option<ScopeRefusal>> {
    if scopes.is_empty() {
        return Ok(None);
    }
    let chain: Vec<&Delegation> = std::iter::once(&basis.delegation)
        .chain(basis.ancestors.iter().map(|ancestor| &ancestor.delegation))
        .collect();
    let mut limits: Vec<PolicyDocument> = basis.session_policies.clone();
    let mut authority_ids: IndexSet<String> = basis.authority_ids.iter().cloned().collect();
    for delegation in &chain {
        limits.push(delegation.policy.clone());
        limits.extend(delegation.ceilings.clone().unwrap_or_default());
        if let Some(authority_id) = &delegation.authority_id {
            authority_ids.insert(authority_id.clone());
        }
    }
    for agent in &basis.agents {
        if let Some(boundary) = agent
            .agent
            .as_ref()
            .and_then(|profile| profile.boundary.as_ref())
        {
            limits.push(boundary.clone());
        }
    }
    for authority_id in &authority_ids {
        let Some(ceilings) = ctx.authority_chain(tx, authority_id).await? else {
            return Ok(Some(ScopeRefusal::Inactive));
        };
        limits.extend(ceilings);
    }
    for realm in ctx.ancestry(tx, &basis.tenant).await? {
        if let Some(boundary) = realm.boundary {
            limits.push(boundary);
        }
    }
    for boundary in tx
        .find(
            "principalBoundaries",
            &Filter::new()
                .eq("tenantId", basis.tenant.id.clone())
                .eq("identityId", basis.person_id.clone()),
            &FindOptions::default(),
        )
        .await?
    {
        let boundary: crate::models::PrincipalBoundary = decode(boundary)?;
        limits.push(boundary.document);
    }
    // A guest's decisions, delegated ones included, stay within the tenant's guest ceiling (decisions.ts, guests.ts).
    let person: Option<Identity> = match tx.get("identities", &basis.person_id).await? {
        Some(record) => Some(decode(record)?),
        None => None,
    };
    if let Some(person) = &person
        && person.tenant_id == basis.tenant.id
        && person.guest.is_some()
        && let Some(ceiling) = crate::guests::guest_boundary(tx, &basis.tenant.id).await?
    {
        limits.push(ceiling);
    }
    let confirm: Vec<String> = chain
        .iter()
        .flat_map(|delegation| delegation.confirm.clone().unwrap_or_default())
        .collect();
    // Denies of bindings, roles and policies whose author's authority was revoked still apply at decision time, so they
    // bound a token's scopes too (they arrive as deny-only paths in `lapsed`).
    let mut lapsed: Vec<GrantPath> = Vec::new();
    let paths = ctx
        .decisions()?
        .identity_grants(
            tx,
            &basis.person_id,
            &basis.tenant.id,
            None,
            Some(&mut lapsed),
        )
        .await?;
    let denies: Vec<String> = paths
        .iter()
        .chain(lapsed.iter())
        .flat_map(|path| path.grants.iter().chain(path.boundaries.iter()))
        .flat_map(|document| document.statements.iter())
        .filter(|statement| statement.effect == Effect::Deny)
        .flat_map(|statement| statement.actions.iter().cloned())
        .collect();
    for scope in scopes {
        if !limits
            .iter()
            .all(|document| policy_allows_scope(document, scope))
        {
            return Ok(Some(ScopeRefusal::Scope {
                scope: scope.clone(),
                why: "limit",
            }));
        }
        if confirm
            .iter()
            .any(|pattern| actions_may_overlap(pattern, scope))
        {
            return Ok(Some(ScopeRefusal::Scope {
                scope: scope.clone(),
                why: "confirm",
            }));
        }
        if denies
            .iter()
            .any(|pattern| actions_may_overlap(pattern, scope))
        {
            return Ok(Some(ScopeRefusal::Scope {
                scope: scope.clone(),
                why: "deny",
            }));
        }
    }
    Ok(None)
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

/// Re-checks an issued token's record against the current state: the delegation and those above it live, the person
/// active, every agent in good standing and still allowed the audience, the acting key live, and the scopes still
/// allowed. False when anything the token stands on has changed.
pub async fn token_still_stands(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    record: &DelegationTokenRecord,
    now: f64,
) -> IamResult<bool> {
    let delegation: Option<Delegation> = get_as(tx, "delegations", &record.delegation_id).await?;
    let tenant: Option<Tenant> = get_as(tx, "tenants", &record.tenant_id).await?;
    let person: Option<Identity> = get_as(tx, "identities", &record.person_id).await?;
    let agent: Option<Identity> = get_as(tx, "identities", &record.agent_id).await?;
    let key: Option<Session> = get_as(tx, "sessions", &record.key_id).await?;
    let (Some(delegation), Some(tenant), Some(person), Some(agent), Some(key)) =
        (delegation, tenant, person, agent, key)
    else {
        return Ok(false);
    };
    if !delegation_live(&delegation, now)
        || delegation.tenant_id != record.tenant_id
        || delegation.subject_id != record.person_id
        || delegation.agent_id != record.agent_id
        || person.tenant_id != record.tenant_id
        || person.status != IdentityStatus::Active
        || ctx.identity_expired(&person)
        || agent
            .agent
            .as_ref()
            .is_some_and(|profile| profile.delegable == Some(false))
        || key.kind != SessionKind::ApiKey
        || key.identity_id != agent.id
        || key.expires_at <= now
    {
        return Ok(false);
    }
    if ctx
        .ancestry(tx, &tenant)
        .await?
        .iter()
        .any(|realm| realm.status != TenantStatus::Active)
    {
        return Ok(false);
    }
    match crate::agents::assert_agent_usable(ctx, tx, &agent).await {
        Ok(()) => {}
        // A stub of another module is reported rather than read as a refusal (TypeScript never raises it).
        Err(error) if error.code == "NOT_IMPLEMENTED" => return Err(error),
        Err(_) => return Ok(false),
    }
    let Some(ancestors) = live_ancestors(ctx, tx, &delegation, now).await? else {
        return Ok(false);
    };
    let mut agents: Vec<Identity> = ancestors
        .iter()
        .rev()
        .map(|ancestor| ancestor.agent.clone())
        .collect();
    agents.push(agent);
    if audience_refusal(&agents, &record.audience)?.is_some() {
        return Ok(false);
    }
    let refusal = scope_refusal(
        ctx,
        tx,
        &TokenBasis {
            tenant,
            person_id: record.person_id.clone(),
            delegation,
            ancestors,
            agents,
            session_policies: record.session_policies.clone(),
            authority_ids: record.authority_id.iter().cloned().collect(),
        },
        &record.scopes,
    )
    .await?;
    Ok(refusal.is_none())
}

/// The JSON of a token's record, in the member order `issueToken` builds it.
pub fn token_record_value(
    record: &DelegationTokenRecord,
    session_policies: &[Value],
) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("id".into(), Value::String(record.id.clone()));
    map.insert("tenantId".into(), Value::String(record.tenant_id.clone()));
    map.insert(
        "delegationId".into(),
        Value::String(record.delegation_id.clone()),
    );
    map.insert("personId".into(), Value::String(record.person_id.clone()));
    map.insert("agentId".into(), Value::String(record.agent_id.clone()));
    map.insert("keyId".into(), Value::String(record.key_id.clone()));
    map.insert("audience".into(), Value::String(record.audience.clone()));
    map.insert(
        "scopes".into(),
        Value::Array(record.scopes.iter().cloned().map(Value::String).collect()),
    );
    map.insert(
        "sessionPolicies".into(),
        Value::Array(session_policies.to_vec()),
    );
    if let Some(authority_id) = &record.authority_id {
        map.insert("authorityId".into(), Value::String(authority_id.clone()));
    }
    map.insert("createdAt".into(), crate::js::number(record.created_at));
    map.insert("expiresAt".into(), crate::js::number(record.expires_at));
    map
}
