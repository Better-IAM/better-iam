//! Port of `packages/server/src/delegations.ts`.
//!
//! Delegations: a person lets an AI agent act on their behalf within a scope, for a limited time. The agent exchanges
//! its own API key for a short delegated session (`delegations.assume`, kind `delegated`) whose identity is the person,
//! so decisions use the person's grants, bounded by the delegation's scope, the agent's own ceiling, and any scope-down
//! the agent asked for. Every use re-validates the whole chain: the delegation, the person, the agent, its sponsor and
//! the agent key the session came from. Revoking a delegation ends its sessions at once.

use std::collections::HashSet;
use std::sync::{Arc, Mutex, Weak};

use better_iam_core::boxed;
use better_iam_core::{
    AuthenticatedPrincipal, Effect, Filter, FindOptions, IamError, IamResult, IamStore, Identity,
    IdentityKind, PolicyDocument, Record, Session, SessionKind, js as core_js, match_pattern,
};
use indexmap::IndexSet;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::context::{ServerContext, Store};
use crate::port::decode;
use crate::session_kinds::revoked_by_watermark;
use crate::validation::{integer, object, strings};

/// `needsConfirmation(delegation, action)`: whether a delegation requires the person's confirmation for an action.
pub fn needs_confirmation(delegation: &Record, action: &str) -> bool {
    delegation
        .get("confirm")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .any(|pattern| match_pattern(pattern, action, None))
}

/// Approvals used inside a transaction still open their call for the rest of it (one operation may check the same
/// action more than once); keyed by the transaction handle, so they end with it (`usedIn`, a WeakMap).
type UsedEntry = (Weak<dyn IamStore>, HashSet<String>);
static USED_IN: Mutex<Vec<UsedEntry>> = Mutex::new(Vec::new());

fn with_used<R>(tx: &Arc<dyn IamStore>, run: impl FnOnce(&mut HashSet<String>) -> R) -> R {
    let mut entries = USED_IN
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    entries.retain(|(weak, _)| weak.strong_count() > 0);
    let position = entries.iter().position(|(weak, _)| {
        weak.upgrade()
            .is_some_and(|live| std::ptr::addr_eq(Arc::as_ptr(&live), Arc::as_ptr(tx)))
    });
    let index = match position {
        Some(index) => index,
        None => {
            entries.push((Arc::downgrade(tx), HashSet::new()));
            entries.len() - 1
        }
    };
    run(&mut entries[index].1)
}

/// `useConfirmation(tx, principal, action, resourceType, resourceId, now)`: uses up the person's approval behind an
/// allowed call of a delegated session. Other sessions, and calls the delegation does not hold back, are left alone.
pub async fn use_confirmation(
    tx: &Arc<dyn IamStore>,
    principal: &AuthenticatedPrincipal,
    action: &str,
    resource_type: &str,
    resource_id: &str,
    now: f64,
) -> IamResult<()> {
    let session = &principal.session;
    if session.kind != SessionKind::Delegated {
        return Ok(());
    }
    let Some(delegation_id) = &session.delegation_id else {
        return Ok(());
    };
    let Some(delegation) = tx.get("delegations", delegation_id).await? else {
        return Ok(());
    };
    if !needs_confirmation(&delegation, action) {
        return Ok(());
    }
    let string =
        |record: &Record, key: &str| record.get(key).and_then(Value::as_str).map(str::to_owned);
    let tenant_id = string(&delegation, "tenantId").unwrap_or_default();
    let id = string(&delegation, "id").unwrap_or_default();
    let matching: Vec<Record> = tx
        .find(
            "delegationConfirmations",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("delegationId", id),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|item| {
            item.get("action").and_then(Value::as_str) == Some(action)
                && item.get("resourceType").and_then(Value::as_str) == Some(resource_type)
                && item.get("resourceId").and_then(Value::as_str) == Some(resource_id)
        })
        .collect();
    // Already used earlier in this very transaction: the same call checked again.
    let used_here = with_used(tx, |used| {
        matching.iter().any(|item| {
            item.get("status").and_then(Value::as_str) == Some("used")
                && string(item, "id").is_some_and(|id| used.contains(&id))
        })
    });
    if used_here {
        return Ok(());
    }
    let expires = |item: &Record| {
        item.get("expiresAt")
            .and_then(core_js::as_number)
            .unwrap_or(f64::NAN)
    };
    let mut approvals: Vec<&Record> = matching
        .iter()
        .filter(|item| {
            item.get("status").and_then(Value::as_str) == Some("approved") && expires(item) > now
        })
        .collect();
    approvals.sort_by(|a, b| {
        expires(a)
            .partial_cmp(&expires(b))
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    let Some(approval) = approvals.first() else {
        return Ok(());
    };
    let mut updated = (*approval).clone();
    updated.insert("status".into(), Value::String("used".into()));
    updated.insert("usedAt".into(), crate::js::number(now));
    tx.put("delegationConfirmations", &updated).await?;
    if let Some(id) = string(approval, "id") {
        with_used(tx, |used| {
            used.insert(id);
        });
    }
    Ok(())
}

/// Delegations: a person lets an AI agent act on their behalf within a scope, for a limited time. The agent
/// exchanges its own API key for a short delegated session (`delegations.assume`, kind `delegated`) whose identity
/// is the person, so decisions use the person's grants, bounded by the delegation's scope, the agent's own ceiling,
/// and any scope-down the agent asked for. Every use re-validates the whole chain: the delegation, the person, the
/// agent, its sponsor and the agent key the session came from. Revoking a delegation ends its sessions at once.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Delegation {
    /// The agent that may act.
    #[serde(rename = "agentId")]
    pub agent_id: String,
    /// The person it acts for.
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    /// `pending` (an agent asked; the person has not decided), `active`, `denied` (the person refused the request) or
    /// `revoked` (ended early by the person, the agent's sponsor, the agent itself or an administrator).
    #[serde(rename = "status")]
    pub status: String,
    /// What the agent may do for the person: a ceiling over the person's own access, never a grant of its own.
    #[serde(rename = "policy")]
    pub policy: PolicyDocument,
    /// The action list the scope was given as, when it was given as `scopes`.
    #[serde(rename = "scopes", default, skip_serializing_if = "Option::is_none")]
    pub scopes: Option<Vec<String>>,
    /// Who created it: the person granting directly, the agent asking (`delegations.request`), or another agent handing
    /// part of its own delegation on (`delegations.handoff`).
    #[serde(rename = "requestedBy")]
    pub requested_by: String,
    /// The agent's stated reason, shown to the person deciding.
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    /// Pending: when the request lapses undecided. Active: when the delegation ends.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    /// Pending requests: how long the delegation lasts once approved (milliseconds).
    #[serde(
        rename = "lifetimeMs",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lifetime_ms: Option<f64>,
    /// Longest single delegated session in seconds, below the agent's own limit.
    #[serde(
        rename = "maxSessionSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_session_seconds: Option<f64>,
    #[serde(rename = "decidedAt", default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<f64>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
    #[serde(rename = "revokedBy", default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    /// Delegated sessions created before this time are refused (set on revocation).
    #[serde(
        rename = "sessionsRevokedBefore",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub sessions_revoked_before: Option<f64>,
    /// When the agent last opened a delegated session with it.
    #[serde(
        rename = "lastUsedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_used_at: Option<f64>,
    /// Action patterns the person must confirm one call at a time: a delegated session is refused them
    /// (`CONFIRMATION_REQUIRED`) unless the person approved that action on that resource moments before
    /// (`delegations.requestConfirmation`).
    #[serde(rename = "confirm", default, skip_serializing_if = "Option::is_none")]
    pub confirm: Option<Vec<String>>,
    /// The person lets the agent hand parts of this delegation on to other agents (`delegations.handoff`): to any agent
    /// that accepts delegation, or only to `agents`, for `depth` more hand-offs down the line (1 to 3).
    #[serde(rename = "handoff", default, skip_serializing_if = "Option::is_none")]
    pub handoff: Option<DelegationHandoff>,
    /// A hand-off: the delegation it was handed on from. Using it needs every delegation above it live.
    #[serde(rename = "parentId", default, skip_serializing_if = "Option::is_none")]
    pub parent_id: Option<String>,
    /// A hand-off: the agents of the delegations above it, the person's own delegate first.
    #[serde(rename = "chain", default, skip_serializing_if = "Option::is_none")]
    pub chain: Option<Vec<String>>,
    /// A hand-off: the limits of the session that handed it on (its scope-down policy and its key's scopes), ceilings
    /// over every use, so a hand-off never allows more than the handing session could do.
    #[serde(rename = "ceilings", default, skip_serializing_if = "Option::is_none")]
    pub ceilings: Option<Vec<PolicyDocument>>,
    /// A hand-off: the issuer authority of the key behind the handing session, whose ceilings apply too.
    #[serde(
        rename = "authorityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub authority_id: Option<String>,
    /// A hand-off: the API key the handing agent acted with. The hand-off works only while that key does, so revoking a
    /// compromised agent's key also stops what it handed on.
    #[serde(rename = "keyId", default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    /// The person's cap on what AI model calls made under this delegation (and the hand-offs below it) may use per
    /// window: checked and metered like an inference budget (`BUDGET_EXCEEDED` once spent).
    #[serde(rename = "spend", default, skip_serializing_if = "Option::is_none")]
    pub spend: Option<DelegationSpend>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A person's answer to an agent asking to take one sensitive action on their behalf (a human-in-the-loop check,
/// like OpenID CIBA): pending until the person decides or it lapses, then an approval valid for `validSeconds` for
/// exactly that action on that resource.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationConfirmation {
    #[serde(rename = "delegationId")]
    pub delegation_id: String,
    #[serde(rename = "agentId")]
    pub agent_id: String,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "action")]
    pub action: String,
    #[serde(rename = "resourceType")]
    pub resource_type: String,
    #[serde(rename = "resourceId")]
    pub resource_id: String,
    /// The agent's explanation, shown to the person.
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `used` once the approval opened the one call it was for (approvals are single-use).
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    /// Pending: when the request lapses undecided. Approved: when the approval stops opening the action.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    /// How long an approval waits to be used, in seconds.
    #[serde(rename = "validSeconds")]
    pub valid_seconds: f64,
    #[serde(rename = "decidedAt", default, skip_serializing_if = "Option::is_none")]
    pub decided_at: Option<f64>,
    /// When the approval was used.
    #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<f64>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a delegation lets its agent hand on.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationHandoff {
    /// The agents it may hand on to; any delegable agent of the tenant when absent.
    #[serde(rename = "agents", default, skip_serializing_if = "Option::is_none")]
    pub agents: Option<Vec<String>>,
    /// How many hand-offs may follow down the line, 1 to 3.
    #[serde(rename = "depth")]
    pub depth: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A spending cap on a delegation: tokens, cost (micro-dollars) and/or calls per window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DelegationSpend {
    #[serde(rename = "period")]
    pub period: String,
    #[serde(rename = "maxTokens", default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<f64>,
    #[serde(
        rename = "maxCostMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_cost_micros: Option<f64>,
    #[serde(
        rename = "maxRequests",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_requests: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One delegation above a hand-off with the agent that handed the work on (`delegationAncestors` items).
#[derive(Debug, Clone)]
pub struct DelegationAncestor {
    pub delegation: Delegation,
    pub agent: Identity,
}

/// What `delegationScope` reads: the scope as a policy document, and the action list when it was given as `scopes`.
#[derive(Debug, Clone, PartialEq)]
pub struct DelegationScope {
    /// The policy document as given (or compiled from `scopes`), validated against the tenant's catalog.
    pub policy: Value,
    pub scopes: Option<Vec<String>>,
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn str_member<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn num_member(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

/// The JSON of a spending cap, in the member order TypeScript builds it.
pub fn spend_value(spend: &DelegationSpend) -> Value {
    let mut map = Map::new();
    map.insert("period".into(), Value::String(spend.period.clone()));
    if let Some(value) = spend.max_tokens {
        map.insert("maxTokens".into(), crate::js::number(value));
    }
    if let Some(value) = spend.max_cost_micros {
        map.insert("maxCostMicros".into(), crate::js::number(value));
    }
    if let Some(value) = spend.max_requests {
        map.insert("maxRequests".into(), crate::js::number(value));
    }
    Value::Object(map)
}

/// The JSON of a hand-off setting as `handoffSetting` builds it (`{ agents, depth }`, or `{ depth }`).
pub fn handoff_value(handoff: &DelegationHandoff) -> Value {
    let mut map = Map::new();
    if let Some(agents) = &handoff.agents {
        map.insert(
            "agents".into(),
            Value::Array(agents.iter().cloned().map(Value::String).collect()),
        );
    }
    map.insert("depth".into(), crate::js::number(handoff.depth));
    Value::Object(map)
}

/// Reads a `spend` setting: `{ period, maxTokens?, maxCostUsd?, maxRequests? }` with at least one limit. `null`
/// means none (for clearing); `undefined` leaves the caller's choice alone (both read as `None` here: every caller
/// tells them apart before calling).
pub fn spend_setting(value: Option<&Value>) -> IamResult<Option<DelegationSpend>> {
    if matches!(value, None | Some(Value::Null)) {
        return Ok(None);
    }
    let input = object(value)?;
    let period = match input.get("period").and_then(Value::as_str) {
        Some(period @ ("minute" | "hour" | "day" | "month")) => period.to_owned(),
        _ => {
            return Err(invalid(
                "spend.period must be 'minute', 'hour', 'day' or 'month'",
            ));
        }
    };
    let mut spend = DelegationSpend {
        period,
        max_tokens: None,
        max_cost_micros: None,
        max_requests: None,
        extra: Map::new(),
    };
    if let Some(tokens) = input.get("maxTokens") {
        spend.max_tokens = Some(integer(
            Some(tokens),
            "spend.maxTokens",
            1.0,
            1_000_000_000_000.0,
        )?);
    }
    if let Some(usd) = input.get("maxCostUsd") {
        // At least one micro-dollar: a smaller cap would round to zero and refuse every call.
        match usd.as_f64().filter(|_| usd.is_number()) {
            Some(usd) if usd.is_finite() && (0.000001..=1_000_000.0).contains(&usd) => {
                spend.max_cost_micros = Some((usd * 1_000_000.0).round());
            }
            _ => {
                return Err(invalid(
                    "spend.maxCostUsd must be at least 0.000001 and at most 1000000",
                ));
            }
        }
    }
    if let Some(requests) = input.get("maxRequests") {
        spend.max_requests = Some(integer(
            Some(requests),
            "spend.maxRequests",
            1.0,
            1_000_000_000.0,
        )?);
    }
    if spend.max_tokens.is_none() && spend.max_cost_micros.is_none() && spend.max_requests.is_none()
    {
        return Err(invalid("spend needs maxTokens, maxCostUsd or maxRequests"));
    }
    Ok(Some(spend))
}

/// Bounds of hand-offs: the deepest chain below a person's own delegation, and live hand-offs per delegation.
pub mod handoff_limits {
    pub const MAX_DEPTH: f64 = 3.0;
    pub const MAX_LIVE: usize = 20;
    pub const MAX_AGENTS: usize = 20;
}

/// Bounds of confirmation requests: how long the person has to decide, and how long an approval lasts.
pub mod confirmation_limits {
    pub const DECIDE_MS: f64 = 30.0 * 60_000.0;
    pub const MIN_VALID_SECONDS: f64 = 30.0;
    pub const MAX_VALID_SECONDS: f64 = 3_600.0;
    pub const FALLBACK_VALID_SECONDS: f64 = 300.0;
}

/// The key a confirmation opens: an action on a resource.
/// `confirmationKey(action, resourceType, resourceId)`: `{action}|{resourceType}/{resourceId}`.
pub fn confirmation_key(action: &str, resource_type: &str, resource_id: &str) -> String {
    format!("{action}|{resource_type}/{resource_id}")
}

/// `/^[A-Za-z0-9*?][A-Za-z0-9:_*?.-]{0,127}$/`.
fn action_pattern_shape(pattern: &str) -> bool {
    let bytes = pattern.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_alphanumeric() || matches!(bytes[0], b'*' | b'?'))
        && bytes[1..].iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'*' | b'?' | b'.' | b'-')
        })
}

/// Reads a `confirm` list: action patterns (wildcards allowed), at most 50; an empty list means none.
pub fn confirm_patterns(value: Option<&Value>) -> IamResult<Option<Vec<String>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let patterns = crate::js::unique(strings(Some(value), "confirm")?);
    if patterns.len() > 50 {
        return Err(invalid("confirm may list at most 50 actions"));
    }
    for pattern in &patterns {
        if !action_pattern_shape(pattern) {
            return Err(invalid(format!("Invalid action pattern {pattern}")));
        }
    }
    Ok((!patterns.is_empty()).then_some(patterns))
}

/// The approved, unexpired (and not yet used) confirmations of a delegation, as the keys they open.
pub async fn approved_confirmations(
    tx: &Store,
    delegation: &Delegation,
    now: f64,
) -> IamResult<IndexSet<String>> {
    let mut keys = IndexSet::new();
    let found = tx
        .find(
            "delegationConfirmations",
            &Filter::new()
                .eq("tenantId", delegation.tenant_id.clone())
                .eq("delegationId", delegation.id.clone()),
            &FindOptions::default(),
        )
        .await?;
    let used: HashSet<String> = with_used(tx, |used| used.clone());
    for confirmation in found {
        let status = str_member(&confirmation, "status");
        let expires_at = num_member(&confirmation, "expiresAt").unwrap_or(f64::NAN);
        let id = str_member(&confirmation, "id").unwrap_or_default();
        if (status == Some("approved") && expires_at > now)
            || (status == Some("used") && used.contains(id))
        {
            keys.insert(confirmation_key(
                &crate::js::js_string(confirmation.get("action")),
                &crate::js::js_string(confirmation.get("resourceType")),
                &crate::js::js_string(confirmation.get("resourceId")),
            ));
        }
    }
    Ok(keys)
}

/// Bounds of a delegation's lifetime and of a pending request.
pub mod delegation_lifetime {
    pub const MIN_SECONDS: f64 = 300.0;
    pub const MAX_SECONDS: f64 = 365.0 * 86_400.0;
    pub const FALLBACK_SECONDS: f64 = 30.0 * 86_400.0;
    pub const REQUEST_MS: f64 = 7.0 * 86_400_000.0;
}

/// Live delegated sessions one delegation may hold at a time.
pub const MAX_SESSIONS_PER_DELEGATION: f64 = 20.0;

const SCOPE_SID: &str = "DelegationScopes";

/// A scope given as actions compiles to an allow on every resource; the person's own grants still decide.
pub fn delegation_scopes_policy(scopes: &[String]) -> Value {
    serde_json::json!({
        "version": 1,
        "statements": [{
            "sid": SCOPE_SID,
            "effect": "allow",
            "actions": scopes,
            "resources": ["*"],
        }],
    })
}

/// Reads a delegation scope: `scopes` (an action list, wildcards allowed) or a `policy` document, exactly one of
/// them, validated against the tenant's catalog. The scope only ever narrows: the delegated session acts with the
/// person's grants, and this becomes one more ceiling over them.
pub async fn delegation_scope(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
) -> IamResult<DelegationScope> {
    let (scopes, policy) = (input.get("scopes"), input.get("policy"));
    if scopes.is_none() == policy.is_none() {
        return Err(invalid("Provide either scopes or a policy"));
    }
    if let Some(scopes) = scopes {
        let scopes = crate::js::unique(strings(Some(scopes), "scopes")?);
        if scopes.is_empty() {
            return Err(invalid("scopes must name at least one action"));
        }
        let policy = delegation_scopes_policy(&scopes);
        ctx.catalog
            .validate(tx.as_ref(), tenant_id, &policy)
            .await?;
        return Ok(DelegationScope {
            policy,
            scopes: Some(scopes),
        });
    }
    let policy = Value::Object(object(policy)?.clone());
    ctx.catalog
        .validate(tx.as_ref(), tenant_id, &policy)
        .await?;
    Ok(DelegationScope {
        policy,
        scopes: None,
    })
}

/// A delegation lifetime in seconds (`expiresInSeconds`), within bounds; the fallback is 30 days.
pub fn delegation_seconds(value: Option<&Value>) -> IamResult<f64> {
    match value {
        None => Ok(delegation_lifetime::FALLBACK_SECONDS),
        Some(value) => integer(
            Some(value),
            "expiresInSeconds",
            delegation_lifetime::MIN_SECONDS,
            delegation_lifetime::MAX_SECONDS,
        ),
    }
}

fn is_wildcard(byte: u8) -> bool {
    matches!(byte, b'*' | b'?')
}

/// The literal text of a glob before its first wildcard and after its last one.
fn glob_ends(pattern: &str) -> (&str, &str) {
    let bytes = pattern.as_bytes();
    let Some(first) = bytes.iter().position(|byte| is_wildcard(*byte)) else {
        return (pattern, pattern);
    };
    // Wildcards are ASCII, so both cuts fall on character boundaries.
    let last = bytes
        .iter()
        .rposition(|byte| is_wildcard(*byte))
        .unwrap_or(first);
    (&pattern[..first], &pattern[last + 1..])
}

/// Whether some action could match both action patterns (conservative: true unless their literal ends disagree).
pub fn actions_may_overlap(pattern: &str, scope: &str) -> bool {
    if pattern.contains("${") {
        return true;
    }
    if !scope.contains('*') {
        return match_pattern(pattern, scope, None);
    }
    let (prefix_a, suffix_a) = glob_ends(pattern);
    let (prefix_b, suffix_b) = glob_ends(scope);
    (prefix_a.starts_with(prefix_b) || prefix_b.starts_with(prefix_a))
        && (suffix_a.ends_with(suffix_b) || suffix_b.ends_with(suffix_a))
}

/// Whether a policy document allows a whole scope (an action or a `*` pattern of actions) outright: some statement
/// allows every action it covers on every resource without conditions, and no deny statement could touch any of
/// them. Conservative by design: a document that allows the scope only for some resources or under conditions does
/// not count.
pub fn policy_allows_scope(document: &PolicyDocument, scope: &str) -> bool {
    let mut allowed = false;
    for statement in &document.statements {
        if statement.effect == Effect::Deny {
            if statement
                .actions
                .iter()
                .any(|pattern| actions_may_overlap(pattern, scope))
            {
                return false;
            }
            continue;
        }
        if statement
            .conditions
            .as_ref()
            .is_some_and(|conditions| !conditions.is_empty())
        {
            continue;
        }
        if !statement.resources.iter().any(|resource| resource == "*") {
            continue;
        }
        // A pattern covers a `*` scope only when its own wildcards are `*` (a `?` or a variable would match less).
        if statement.actions.iter().any(|pattern| {
            (!scope.contains('*') || !(pattern.contains('?') || pattern.contains("${")))
                && match_pattern(pattern, scope, None)
        }) {
            allowed = true;
        }
    }
    allowed
}

/// Whether a delegation lets its agent act right now.
pub fn delegation_live(delegation: &Delegation, now: f64) -> bool {
    delegation.status == "active" && delegation.expires_at > now
}

/// Whether a request still waits for the person's decision.
pub fn delegation_pending(delegation: &Delegation, now: f64) -> bool {
    delegation.status == "pending" && delegation.expires_at > now
}

/// Reads a `handoff` setting: `{ agents?, depth? }` with agents of the tenant (at most 20) and a depth of 1 to 3 (1
/// by default). `null` means none (for clearing); `undefined` leaves the caller's choice alone (both read as `None`).
pub async fn handoff_setting(
    tx: &Store,
    tenant_id: &str,
    value: Option<&Value>,
) -> IamResult<Option<DelegationHandoff>> {
    if matches!(value, None | Some(Value::Null)) {
        return Ok(None);
    }
    let input = object(value)?;
    let depth = match input.get("depth") {
        None => 1.0,
        Some(depth) => integer(Some(depth), "handoff.depth", 1.0, handoff_limits::MAX_DEPTH)?,
    };
    let Some(agents) = input.get("agents") else {
        return Ok(Some(DelegationHandoff {
            agents: None,
            depth,
            extra: Map::new(),
        }));
    };
    let agents = crate::js::unique(strings(Some(agents), "handoff.agents")?);
    if agents.is_empty() || agents.len() > handoff_limits::MAX_AGENTS {
        return Err(invalid(format!(
            "handoff.agents must name 1 to {} agents",
            handoff_limits::MAX_AGENTS
        )));
    }
    for agent_id in &agents {
        let agent = tx.get("identities", agent_id).await?;
        let usable = agent.as_ref().is_some_and(|agent| {
            str_member(agent, "kind") == Some("agent")
                && str_member(agent, "tenantId") == Some(tenant_id)
        });
        if !usable {
            return Err(invalid(format!(
                "handoff.agents: {agent_id} is not an agent of this tenant"
            )));
        }
    }
    Ok(Some(DelegationHandoff {
        agents: Some(agents),
        depth,
        extra: Map::new(),
    }))
}

/// The delegations above a hand-off, nearest first, when every one of them is live and names the same person, and
/// its agent is an agent of the tenant that still accepts delegation. None when any link is broken (the hand-off may
/// not be used). A delegation the person gave directly has no ancestors. `liveAncestors` also checks each agent's
/// standing.
pub async fn delegation_ancestors(
    tx: &Store,
    delegation: &Delegation,
    now: f64,
) -> IamResult<Option<Vec<DelegationAncestor>>> {
    let mut ancestors: Vec<DelegationAncestor> = Vec::new();
    let mut seen: HashSet<String> = HashSet::from([delegation.id.clone()]);
    let mut current = delegation.clone();
    while let Some(parent_id) = current.parent_id.clone() {
        if ancestors.len() as f64 >= handoff_limits::MAX_DEPTH {
            return Ok(None);
        }
        let Some(parent) = tx.get("delegations", &parent_id).await? else {
            return Ok(None);
        };
        let parent: Delegation = decode(parent)?;
        if seen.contains(&parent.id)
            || !delegation_live(&parent, now)
            || parent.tenant_id != delegation.tenant_id
            || parent.subject_id != delegation.subject_id
        {
            return Ok(None);
        }
        let Some(agent) = tx.get("identities", &parent.agent_id).await? else {
            return Ok(None);
        };
        let agent: Identity = decode(agent)?;
        if agent.kind != IdentityKind::Agent
            || agent.tenant_id != delegation.tenant_id
            || agent
                .agent
                .as_ref()
                .is_some_and(|profile| profile.delegable == Some(false))
        {
            return Ok(None);
        }
        // The key the handing agent acted with must still be one of its live API keys.
        if let Some(key_id) = &current.key_id {
            let key: Option<Session> = match tx.get("sessions", key_id).await? {
                Some(record) => Some(decode(record)?),
                None => None,
            };
            let live = key.is_some_and(|key| {
                key.kind == SessionKind::ApiKey
                    && key.identity_id == agent.id
                    && key.expires_at > now
            });
            if !live {
                return Ok(None);
            }
        }
        seen.insert(parent.id.clone());
        current = parent.clone();
        ancestors.push(DelegationAncestor {
            delegation: parent,
            agent,
        });
    }
    Ok(Some(ancestors))
}

/// `delegationAncestors`, with every agent above also in good standing (itself and its sponsor active).
pub async fn live_ancestors(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    delegation: &Delegation,
    now: f64,
) -> IamResult<Option<Vec<DelegationAncestor>>> {
    let Some(ancestors) = delegation_ancestors(tx, delegation, now).await? else {
        return Ok(None);
    };
    for ancestor in &ancestors {
        match crate::agents::assert_agent_usable(ctx, tx, &ancestor.agent).await {
            Ok(()) => {}
            // A stub of another module is reported rather than read as a broken link (TypeScript never raises it).
            Err(error) if error.code == "NOT_IMPLEMENTED" => return Err(error),
            Err(_) => return Ok(None),
        }
    }
    Ok(Some(ancestors))
}

/// The revoked copy of a delegation record (`{ ...delegation, status: 'revoked', revokedAt, revokedBy,
/// sessionsRevokedBefore }`).
fn revoked_record(record: &Record, revoked_by: &str, now: f64, watermark: f64) -> Record {
    let mut revoked = record.clone();
    revoked.insert("status".into(), Value::String("revoked".into()));
    revoked.insert("revokedAt".into(), crate::js::number(now));
    revoked.insert("revokedBy".into(), Value::String(revoked_by.to_owned()));
    revoked.insert("sessionsRevokedBefore".into(), crate::js::number(watermark));
    revoked
}

fn delegation_filter(delegation_id: &str) -> Value {
    serde_json::json!({ "delegationId": delegation_id })
}

/// Revokes every live hand-off below a delegation (at any depth) and deletes their sessions, recording `revokedBy`.
/// Returns how many were revoked. Their use is refused anyway once a delegation above them ends; this keeps their
/// records honest. `delegation` is an object with its `id` and `tenantId`.
pub async fn revoke_handoffs_below(
    tx: &Store,
    delegation: &Value,
    revoked_by: &str,
    now: f64,
) -> IamResult<f64> {
    let id = crate::js::js_string(delegation.get("id"));
    let tenant_id = delegation.get("tenantId").cloned().unwrap_or(Value::Null);
    let mut revoked = 0.0;
    let mut pending = vec![id.clone()];
    let mut seen: HashSet<String> = HashSet::from([id]);
    while let Some(parent_id) = pending.pop() {
        let children = tx
            .find(
                "delegations",
                &Filter::new()
                    .eq("tenantId", tenant_id.clone())
                    .eq("parentId", parent_id),
                &FindOptions::default(),
            )
            .await?;
        for child in children {
            let child_id = str_member(&child, "id").unwrap_or_default().to_owned();
            if seen.contains(&child_id) {
                continue;
            }
            seen.insert(child_id.clone());
            // An ended hand-off's own hand-offs ended with it; only live ones are followed down.
            let status = str_member(&child, "status");
            if status != Some("active") && status != Some("pending") {
                continue;
            }
            pending.push(child_id.clone());
            tx.put(
                "delegations",
                &revoked_record(&child, revoked_by, now, now + 1.0),
            )
            .await?;
            delete_delegated_sessions(tx, &delegation_filter(&child_id)).await?;
            revoked += 1.0;
        }
    }
    Ok(revoked)
}

/// The checks a delegated session passes on every use: its delegation is active, unexpired, and names this person
/// and agent in this tenant, and was not revoked after the session began; the person is an active person of the
/// tenant; the agent is an agent in good standing (itself and its sponsor active) that still accepts delegation;
/// and the agent key the session came from is re-validated under its own rules (`revalidate`). Anything else is a
/// 401.
pub async fn check_delegated_session(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity: &Identity,
    session: &Session,
    revalidate: &dyn crate::contracts::PrincipalService,
) -> IamResult<()> {
    let revoked = || IamError::with_status("UNAUTHENTICATED", "Delegation revoked", 401);
    let now = ctx.now();
    let delegation: Option<Delegation> = match &session.delegation_id {
        Some(id) => match boxed(|| tx.get("delegations", id)).await? {
            Some(record) => Some(decode(record)?),
            None => None,
        },
        None => None,
    };
    let agent: Option<Identity> = match &session.agent_id {
        Some(id) => match boxed(|| tx.get("identities", id)).await? {
            Some(record) => Some(decode(record)?),
            None => None,
        },
        None => None,
    };
    let source: Option<Session> = match &session.source_session_id {
        Some(id) => match boxed(|| tx.get("sessions", id)).await? {
            Some(record) => Some(decode(record)?),
            None => None,
        },
        None => None,
    };
    let (Some(delegation), Some(agent), Some(source)) = (delegation, agent, source) else {
        return Err(revoked());
    };
    if !delegation_live(&delegation, now)
        || delegation.tenant_id != session.tenant_id
        || delegation.subject_id != identity.id
        || Some(&delegation.agent_id) != session.agent_id.as_ref()
        || revoked_by_watermark(session.created_at, &[delegation.sessions_revoked_before])
        || session.expires_at > delegation.expires_at
        || identity.kind != IdentityKind::User
        || identity.tenant_id != session.tenant_id
        || agent.kind != IdentityKind::Agent
        || agent.tenant_id != session.tenant_id
        || agent
            .agent
            .as_ref()
            .is_some_and(|profile| profile.delegable == Some(false))
        || source.kind != SessionKind::ApiKey
        || source.identity_id != agent.id
        || source.tenant_id != session.tenant_id
        || session.expires_at > source.expires_at
        // The session carries the key's issuer authority (a ceiling in decisions); it must still be the key's.
        || session.credential_authority_id != source.credential_authority_id
    {
        return Err(revoked());
    }
    boxed(|| crate::agents::assert_agent_usable(ctx, tx, &agent)).await?;
    // A hand-off works only while every delegation above it does, with its agents in good standing.
    if delegation.parent_id.is_some()
        && boxed(|| live_ancestors(ctx, tx, &delegation, now))
            .await?
            .is_none()
    {
        return Err(revoked());
    }
    revalidate
        .current_principal(
            tx,
            &AuthenticatedPrincipal {
                identity: agent,
                session: source,
                device_proof: None,
            },
        )
        .await?;
    Ok(())
}

/// Deletes the live delegated sessions of a delegation (or of every delegation of an agent); returns the count.
/// `filter` is `{ delegationId }` or `{ agentId }`.
pub async fn delete_delegated_sessions(tx: &Store, filter: &Value) -> IamResult<f64> {
    let mut query = Filter::new().eq("kind", "delegated");
    if let Some(members) = filter.as_object() {
        for (key, value) in members {
            query = query.eq(key.clone(), value.clone());
        }
    }
    let mut deleted = 0.0;
    for session in tx.find("sessions", &query, &FindOptions::default()).await? {
        tx.delete("sessions", str_member(&session, "id").unwrap_or_default())
            .await?;
        deleted += 1.0;
    }
    Ok(deleted)
}

/// Ends every delegation that involves an identity (as the agent or as the person) and their sessions: used when an
/// identity is deleted. Records stay as `revoked` for the audit trail. Returns the number of delegations ended.
/// `identity` is an object with its `id` and `tenantId`.
pub async fn revoke_delegations_of(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    identity: &Value,
    revoked_by: &str,
) -> IamResult<f64> {
    let now = ctx.now();
    let tenant_id = identity.get("tenantId").cloned().unwrap_or(Value::Null);
    let id = identity.get("id").cloned().unwrap_or(Value::Null);
    let mut ended = 0.0;
    let mut found = tx
        .find(
            "delegations",
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("agentId", id.clone()),
            &FindOptions::default(),
        )
        .await?;
    found.extend(
        tx.find(
            "delegations",
            &Filter::new().eq("tenantId", tenant_id).eq("subjectId", id),
            &FindOptions::default(),
        )
        .await?,
    );
    for delegation in &found {
        let status = str_member(delegation, "status");
        if status != Some("active") && status != Some("pending") {
            continue;
        }
        tx.put(
            "delegations",
            &revoked_record(delegation, revoked_by, now, now + 1.0),
        )
        .await?;
        delete_delegated_sessions(
            tx,
            &delegation_filter(str_member(delegation, "id").unwrap_or_default()),
        )
        .await?;
        ended += 1.0;
    }
    // Hand-offs below the ended delegations end with them.
    for delegation in &found {
        ended +=
            revoke_handoffs_below(tx, &Value::Object(delegation.clone()), revoked_by, now).await?;
    }
    Ok(ended)
}
