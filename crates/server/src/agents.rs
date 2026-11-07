//! Port of `packages/server/src/agents.ts`.
//!
//! AI agents as accounts. An agent is an identity of kind `agent`: a machine account like a service account (API keys,
//! no sign-in) that always has a sponsor, the person accountable for it. Its credentials work only while the sponsor
//! is an active, unexpired person of the same tenant, and every decision it takes part in (its own keys, and sessions
//! in which it acts for someone under a delegation) is bounded by the agent's own ceiling (`AgentProfile.boundary`).

use std::sync::{Arc, LazyLock};

use better_iam_core::{
    AuditOutcome, Filter, FindOptions, IamError, IamResult, Identity, IdentityKind, IdentityStatus,
    Record, js as core_js,
};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::{number, utf16_len};
use crate::port::decode;
use crate::validation::{integer, strings, text};

/// What a decision adds for agents: context keys and the ceilings of the agent and the delegation.
#[derive(Clone)]
pub struct AgentDecisionScope {
    pub keys: Map<String, Value>,
    pub boundaries: Vec<better_iam_core::PolicyDocument>,
    /// Delegations with `confirm` patterns: turns an otherwise allowed decision for such an action into a refusal
    /// (`CONFIRMATION_REQUIRED`) unless the person approved that action on that resource and the approval is still
    /// valid. Undefined when nothing needs confirmation.
    pub confirm: Option<crate::contracts::ConfirmGate>,
    /// Credential issuer authorities whose ceilings apply as well (the keys behind the sessions that handed work on).
    pub authorities: Option<Vec<String>>,
    /// The agents taking part: the acting agent (its own key or a delegated session) and, after hand-offs, every agent
    /// that handed the work on. Empty when no agent acts. Security clearances require each of them to dominate a label.
    pub agent_ids: Vec<String>,
}

/// What `agents.update` and `agents.create` accept for the profile; null clears an optional field. The functions
/// below read these members from the raw request object, so `null` (clear) and absent (keep) stay apart and values
/// of the wrong type are refused with the TypeScript messages; this type documents the shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentProfileInput {
    #[serde(rename = "model", default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(rename = "provider", default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(rename = "purpose", default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(rename = "url", default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "protocols", default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    #[serde(rename = "delegable", default, skip_serializing_if = "Option::is_none")]
    pub delegable: Option<bool>,
    #[serde(
        rename = "maxDelegatedSessionSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_delegated_session_seconds: Option<f64>,
    #[serde(rename = "boundary", default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<better_iam_core::PolicyDocument>,
    #[serde(
        rename = "tokenAudiences",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub token_audiences: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// An agent as administrators and sponsors see it: the identity's public fields plus its standing. [`agent_summary`]
/// builds it as JSON in the TypeScript member order; this type documents the shape.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentSummary {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(
        rename = "attributes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub attributes: Option<IndexMap<String, better_iam_core::Json>>,
    #[serde(rename = "agent")]
    pub agent: better_iam_core::AgentProfile,
    #[serde(rename = "standing")]
    pub standing: String,
    #[serde(rename = "sponsor", default, skip_serializing_if = "Option::is_none")]
    pub sponsor: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Default and bounds of `AgentProfile.maxDelegatedSessionSeconds`.
pub static AGENT_SESSION_SECONDS: LazyLock<Value> =
    LazyLock::new(|| json!({"min":60,"max":43200,"fallback":3600}));

/// `agentSessionSeconds.min`.
pub const AGENT_SESSION_SECONDS_MIN: f64 = 60.0;
/// `agentSessionSeconds.max`.
pub const AGENT_SESSION_SECONDS_MAX: f64 = 43_200.0;
/// `agentSessionSeconds.fallback`.
pub const AGENT_SESSION_SECONDS_FALLBACK: f64 = 3_600.0;

/// URI path characters (RFC 3986 pchar and `/`); `*` among them is a wildcard in audience patterns.
const PATH_CHARS: &str = r"[A-Za-z0-9\-._~!$&'()*+,;=:@%/]";

/// An http(s) audience: scheme, host (a pattern may start it with `*.`), optional port, optional path. No user info,
/// query or fragment. (The TypeScript expression is case-insensitive; its character classes already list both cases,
/// so only the scheme is spelled out here. `\d` is ASCII in JavaScript.)
static HTTP_AUDIENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(
        r"^([Hh][Tt][Tt][Pp][Ss]?)://(\*\.)?([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*)(:[0-9]{{1,5}})?(/{PATH_CHARS}*)?$"
    ))
    .expect("valid regex")
});

/// Any other absolute URI, such as `urn:example:api` (the `(?!https?:)` lookahead is checked separately).
static OTHER_AUDIENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(&format!(r"^[A-Za-z][A-Za-z0-9+.-]*:{PATH_CHARS}{{1,500}}$")).expect("valid regex")
});

static MODEL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$").expect("valid regex"));
static PROVIDER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$").expect("valid regex"));
static PROTOCOL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9.-]{0,31}$").expect("valid regex"));

/// `otherAudience.test(value)`, with the `(?!https?:)` lookahead (case-insensitive).
fn other_audience(value: &str) -> bool {
    let lower = value
        .get(..6)
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| value.to_ascii_lowercase());
    !lower.starts_with("http:") && !lower.starts_with("https:") && OTHER_AUDIENCE.is_match(value)
}

/// Glob matching where only `*` is special (any characters), in linear-ish time: no regular expression backtracking.
fn glob_match(pattern: &str, value: &str) -> bool {
    let pattern: Vec<u16> = pattern.encode_utf16().collect();
    let value: Vec<u16> = value.encode_utf16().collect();
    let star_unit = u16::from(b'*');
    let mut p = 0usize;
    let mut v = 0usize;
    let mut star: Option<usize> = None;
    let mut retry = 0usize;
    while v < value.len() {
        if p < pattern.len() && pattern[p] != star_unit && pattern[p] == value[v] {
            p += 1;
            v += 1;
        } else if pattern.get(p) == Some(&star_unit) {
            star = Some(p);
            p += 1;
            retry = v;
        } else if let Some(at) = star {
            p = at + 1;
            retry += 1;
            v = retry;
        } else {
            return false;
        }
    }
    while pattern.get(p) == Some(&star_unit) {
        p += 1;
    }
    p == pattern.len()
}

/// Whether a token audience pattern matches a requested audience. For http(s) patterns the scheme and port must be
/// equal, the host equal (case-insensitively) or, for `*.example.com`, a subdomain of it, and the path must match
/// with `*` as a wildcard (no path means `/`); a `*` never reaches across the host. Other URIs match as a whole,
/// with `*`.
pub fn audience_matches(pattern: &str, audience: &str) -> bool {
    if utf16_len(audience) > 512 {
        return false;
    }
    if let Some(wanted) = HTTP_AUDIENCE.captures(pattern) {
        let Some(given) = HTTP_AUDIENCE.captures(audience) else {
            return false;
        };
        if given.get(2).is_some() || audience.contains('*') {
            return false;
        }
        let group = |captures: &regex::Captures<'_>, index: usize| {
            captures
                .get(index)
                .map(|found| found.as_str().to_owned())
                .unwrap_or_default()
        };
        if !group(&wanted, 1).eq_ignore_ascii_case(&group(&given, 1)) {
            return false;
        }
        let host = group(&given, 3).to_ascii_lowercase();
        let base = group(&wanted, 3).to_ascii_lowercase();
        let host_ok = if wanted.get(2).is_some() {
            host.ends_with(&format!(".{base}"))
        } else {
            host == base
        };
        if !host_ok {
            return false;
        }
        if group(&wanted, 4) != group(&given, 4) {
            return false;
        }
        let path = |captures: &regex::Captures<'_>| {
            let found = group(captures, 5);
            if found.is_empty() {
                "/".to_owned()
            } else {
                found
            }
        };
        return glob_match(&path(&wanted), &path(&given));
    }
    !HTTP_AUDIENCE.is_match(audience) && other_audience(audience) && glob_match(pattern, audience)
}

/// Whether a value is a well-formed audience (`patterns`: with `*` where audience patterns allow it).
fn audience_syntax(value: &str, patterns: bool) -> bool {
    if utf16_len(value) > 512 || (!patterns && value.contains('*')) {
        return false;
    }
    // The host part of the http(s) form cannot hold `*` beyond a leading `*.`.
    HTTP_AUDIENCE.is_match(value) || other_audience(value)
}

/// `[...new Set(items)]`: the first occurrence of each item, in order.
fn unique(items: Vec<String>) -> Vec<String> {
    let mut seen = indexmap::IndexSet::new();
    for item in items {
        seen.insert(item);
    }
    seen.into_iter().collect()
}

/// `list.sort()`: UTF-16 code unit order.
fn sort_utf16(list: &mut [String]) {
    list.sort_by(|left, right| core_js::cmp_utf16(left, right));
}

/// Reads a list of token audiences (at most 16): http(s) URLs such as `https://api.example.com` or
/// `https://*.example.com/v1/*` (no user info, query or fragment), or other absolute URIs such as
/// `urn:example:api`.
pub fn token_audience_list(value: Option<&Value>, field: Option<&str>) -> IamResult<Vec<String>> {
    let field = field.unwrap_or("tokenAudiences");
    let mut list = unique(strings(value, field)?);
    if list.len() > 16 || list.iter().any(|item| !audience_syntax(item, true)) {
        return Err(IamError::new(
            "INVALID_INPUT",
            format!(
                "{field} must list at most 16 absolute URIs (such as https://api.example.com, https://*.example.com or urn:example:api)"
            ),
        ));
    }
    sort_utf16(&mut list);
    Ok(list)
}

/// Reads one requested token audience: an http(s) URL or other absolute URI, without `*`.
pub fn token_audience(value: Option<&Value>) -> IamResult<String> {
    let audience = text(value, "audience", 512)?;
    if !audience_syntax(&audience, false) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "audience must name one service: an http(s) URL without user info, query, fragment or *, or another absolute URI",
        ));
    }
    Ok(audience)
}

/// Machine accounts: service accounts and agents. They hold API keys and never sign in.
pub fn machine_identity(identity: &better_iam_core::Identity) -> bool {
    matches!(
        identity.kind,
        better_iam_core::IdentityKind::Service | better_iam_core::IdentityKind::Agent
    )
}

/// `new URL(value)` restricted to http(s): the `url` profile field.
fn http_url(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|parsed| matches!(parsed.scheme(), "http" | "https"))
}

/// Validates profile fields over `previous` (a stored profile, or a fresh one with only the sponsor). Policy
/// documents are checked against the tenant's catalog; unknown keys are ignored. Returns a new profile object.
///
/// `input` is the request object (`AgentProfileInput` members are read from it: absent keeps a field, `null` clears
/// it); `previous` is the stored profile as JSON, whose member order (and unknown members) the result keeps.
pub async fn agent_profile(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
    previous: &Map<String, Value>,
) -> IamResult<Map<String, Value>> {
    let mut next = previous.clone();
    // `optional(key, value, read)`: undefined keeps, null deletes, anything else is read.
    fn optional(
        next: &mut Map<String, Value>,
        key: &str,
        value: Option<&Value>,
        read: impl FnOnce(&Value) -> IamResult<Value>,
    ) -> IamResult<()> {
        match value {
            None => {}
            Some(Value::Null) => {
                next.shift_remove(key);
            }
            Some(value) => {
                let read = read(value)?;
                next.insert(key.to_owned(), read);
            }
        }
        Ok(())
    }
    optional(
        &mut next,
        "model",
        input.get("model"),
        |value| match value {
            Value::String(model) if MODEL_PATTERN.is_match(model) => Ok(value.clone()),
            _ => Err(IamError::new(
                "INVALID_INPUT",
                "model must be 1-128 letters, digits or ._:/@+- characters",
            )),
        },
    )?;
    optional(
        &mut next,
        "provider",
        input.get("provider"),
        |value| match value {
            Value::String(provider) if PROVIDER_PATTERN.is_match(provider) => {
                Ok(Value::String(core_js::to_lower(provider)))
            }
            _ => Err(IamError::new(
                "INVALID_INPUT",
                "provider must be 1-64 letters, digits or ._- characters",
            )),
        },
    )?;
    optional(&mut next, "purpose", input.get("purpose"), |value| {
        Ok(Value::String(text(Some(value), "purpose", 1024)?))
    })?;
    optional(&mut next, "url", input.get("url"), |value| {
        let url = text(Some(value), "url", 2048)?;
        if !http_url(&url) {
            return Err(IamError::new("INVALID_INPUT", "url must be an http(s) URL"));
        }
        Ok(Value::String(url))
    })?;
    optional(&mut next, "protocols", input.get("protocols"), |value| {
        let mut list = unique(
            strings(Some(value), "protocols")?
                .iter()
                .map(|item| core_js::to_lower(item))
                .collect(),
        );
        if list.len() > 16 || list.iter().any(|item| !PROTOCOL_PATTERN.is_match(item)) {
            return Err(IamError::new(
                "INVALID_INPUT",
                "protocols must list at most 16 short lowercase names",
            ));
        }
        sort_utf16(&mut list);
        Ok(Value::Array(list.into_iter().map(Value::String).collect()))
    })?;
    if let Some(delegable) = input.get("delegable") {
        let Value::Bool(delegable) = delegable else {
            return Err(IamError::new(
                "INVALID_INPUT",
                "delegable must be a boolean",
            ));
        };
        if *delegable {
            next.shift_remove("delegable");
        } else {
            next.insert("delegable".into(), Value::Bool(false));
        }
    }
    optional(
        &mut next,
        "maxDelegatedSessionSeconds",
        input.get("maxDelegatedSessionSeconds"),
        |value| {
            Ok(number(integer(
                Some(value),
                "maxDelegatedSessionSeconds",
                AGENT_SESSION_SECONDS_MIN,
                AGENT_SESSION_SECONDS_MAX,
            )?))
        },
    )?;
    if let Some(boundary) = input.get("boundary").filter(|value| !value.is_null()) {
        ctx.catalog
            .validate(tx.as_ref(), tenant_id, boundary)
            .await?;
    }
    optional(&mut next, "boundary", input.get("boundary"), |value| {
        Ok(value.clone())
    })?;
    optional(
        &mut next,
        "tokenAudiences",
        input.get("tokenAudiences"),
        |value| {
            Ok(Value::Array(
                token_audience_list(Some(value), None)?
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ))
        },
    )?;
    Ok(next)
}

/// `tx.get<Identity>('identities', id)` decoded; None when absent.
async fn identity_of(tx: &Store, identity_id: &str) -> IamResult<Option<Identity>> {
    match tx.get("identities", identity_id).await? {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

/// A sponsor is an active, unexpired person of the agent's tenant.
pub async fn sponsor_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    sponsor_id: Option<&Value>,
) -> IamResult<better_iam_core::Identity> {
    let sponsor_id = text(sponsor_id, "sponsorId", 256)?;
    match identity_of(tx, &sponsor_id).await? {
        Some(sponsor)
            if sponsor.tenant_id == tenant_id
                && sponsor.kind == IdentityKind::User
                && sponsor.status == IdentityStatus::Active
                && !ctx.identity_expired(&sponsor) =>
        {
            Ok(sponsor)
        }
        _ => Err(IamError::new(
            "INVALID_SPONSOR",
            "An agent sponsor must be an active person of the same tenant",
        )),
    }
}

/// Whether (and why not) an agent may act right now: itself active and unexpired, its sponsor too. One of `ok`,
/// `suspended`, `expired`, `deleted`, `sponsor-missing` and `sponsor-inactive`.
pub async fn agent_standing(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    agent: &better_iam_core::Identity,
) -> IamResult<String> {
    let standing = |value: &str| Ok(value.to_owned());
    if agent.status == IdentityStatus::Deleted {
        return standing("deleted");
    }
    if agent.status != IdentityStatus::Active {
        return standing("suspended");
    }
    if ctx.identity_expired(agent) {
        return standing("expired");
    }
    let sponsor = match agent.agent.as_ref() {
        Some(profile) => identity_of(tx, &profile.sponsor_id).await?,
        None => None,
    };
    let Some(sponsor) = sponsor.filter(|sponsor| {
        sponsor.tenant_id == agent.tenant_id && sponsor.kind == IdentityKind::User
    }) else {
        return standing("sponsor-missing");
    };
    if sponsor.status != IdentityStatus::Active || ctx.identity_expired(&sponsor) {
        return standing("sponsor-inactive");
    }
    standing("ok")
}

/// Refuses an agent credential (401) unless the agent is an agent of `tenantId` in good standing.
pub async fn assert_agent_usable(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    agent: &better_iam_core::Identity,
) -> IamResult<()> {
    if agent.kind != IdentityKind::Agent || agent.agent.is_none() {
        return Err(IamError::with_status(
            "UNAUTHENTICATED",
            "Agent credential revoked",
            401,
        ));
    }
    let standing = agent_standing(ctx, tx, agent).await?;
    if standing == "sponsor-missing" || standing == "sponsor-inactive" {
        return Err(IamError::with_status(
            "UNAUTHENTICATED",
            "The agent\u{2019}s sponsor is no longer active",
            401,
        ));
    }
    if standing != "ok" {
        return Err(IamError::with_status(
            "UNAUTHENTICATED",
            "Agent disabled",
            401,
        ));
    }
    Ok(())
}

/// Offboarding: the leaver's agents move to `successor` when that is an active person (each audited as
/// `agent:sponsor-change`); otherwise they stay with the leaver and are refused until an administrator reassigns
/// them. Returns `{ reassigned, unsponsored }`.
pub async fn hand_over_agents(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    leaver: &better_iam_core::Identity,
    successor: Option<&better_iam_core::Identity>,
) -> IamResult<Value> {
    let mut reassigned = 0.0;
    let mut unsponsored = 0.0;
    let heir = successor.filter(|successor| {
        successor.kind == IdentityKind::User && successor.status == IdentityStatus::Active
    });
    let agents = tx
        .find(
            "identities",
            &Filter::new()
                .eq("tenantId", leaver.tenant_id.clone())
                .eq("kind", "agent"),
            &FindOptions::default(),
        )
        .await?;
    for agent in agents {
        let sponsor_id = agent
            .get("agent")
            .and_then(|profile| profile.get("sponsorId"));
        if agent.get("status").and_then(Value::as_str) == Some("deleted")
            || sponsor_id.and_then(Value::as_str) != Some(leaver.id.as_str())
        {
            continue;
        }
        let Some(heir) = heir else {
            unsponsored += 1.0;
            continue;
        };
        let mut next = agent.clone();
        let mut profile = agent
            .get("agent")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        profile.insert("sponsorId".into(), Value::String(heir.id.clone()));
        next.insert("agent".into(), Value::Object(profile));
        tx.put("identities", &next).await?;
        let mut metadata = Map::new();
        metadata.insert("from".into(), Value::String(leaver.id.clone()));
        metadata.insert("to".into(), Value::String(heir.id.clone()));
        metadata.insert("reason".into(), Value::String("offboarding".into()));
        let agent_tenant = agent
            .get("tenantId")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let agent_id = agent.get("id").and_then(Value::as_str).unwrap_or_default();
        ctx.events()?
            .audit(
                tx,
                principal,
                "agent:sponsor-change",
                agent_tenant,
                agent_id,
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await?;
        reassigned += 1.0;
    }
    let mut counts = Map::new();
    counts.insert("reassigned".into(), number(reassigned));
    counts.insert("unsponsored".into(), number(unsponsored));
    Ok(Value::Object(counts))
}

/// `agentSummary(ctx, tx, agent)`: an agent as administrators and sponsors see it, from its stored record (so the
/// profile keeps its stored members and order): `id`, `tenantId`, `name`, `status`, `createdAt`, `agent`,
/// `standing`, then `description`, `expiresAt`, `attributes` and `sponsor` when present.
pub async fn agent_summary(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    agent: &Record,
) -> IamResult<Map<String, Value>> {
    let typed: Identity = decode(agent.clone())?;
    let sponsor = match typed.agent.as_ref() {
        Some(profile) => tx.get("identities", &profile.sponsor_id).await?,
        None => None,
    };
    let member = |key: &str| agent.get(key).cloned().unwrap_or(Value::Null);
    let mut summary = Map::new();
    summary.insert("id".into(), member("id"));
    summary.insert("tenantId".into(), member("tenantId"));
    summary.insert("name".into(), member("name"));
    summary.insert("status".into(), member("status"));
    summary.insert("createdAt".into(), member("createdAt"));
    summary.insert(
        "agent".into(),
        match agent.get("agent") {
            Some(Value::Object(profile)) => Value::Object(profile.clone()),
            Some(Value::Null) | None => json!({ "sponsorId": "" }),
            // `{ ...value }` of a primitive copies nothing.
            Some(_) => Value::Object(Map::new()),
        },
    );
    summary.insert(
        "standing".into(),
        Value::String(agent_standing(ctx, tx, &typed).await?),
    );
    for key in ["description", "expiresAt", "attributes"] {
        if let Some(value) = agent.get(key) {
            summary.insert(key.into(), value.clone());
        }
    }
    if let Some(sponsor) = sponsor
        && sponsor.get("tenantId").and_then(Value::as_str) == Some(typed.tenant_id.as_str())
    {
        let mut card = Map::new();
        card.insert(
            "id".into(),
            sponsor.get("id").cloned().unwrap_or(Value::Null),
        );
        card.insert(
            "name".into(),
            sponsor.get("name").cloned().unwrap_or(Value::Null),
        );
        card.insert(
            "status".into(),
            sponsor.get("status").cloned().unwrap_or(Value::Null),
        );
        if let Some(email) = sponsor.get("email") {
            card.insert("email".into(), email.clone());
        }
        summary.insert("sponsor".into(), Value::Object(card));
    }
    Ok(summary)
}

/// The agent part of a decision. Every principal gets `principal.delegated`; an agent's own credential and a
/// delegated session also get `principal.agentId`, `principal.agentSponsorId`, `principal.agentModel` and
/// `principal.agentProvider` (when set), plus the agent's `boundary` as a ceiling. A delegated session adds
/// `principal.delegationId` and the delegation's scope as a ceiling, read live so narrowing or revoking a
/// delegation applies at once, and `principal.delegationChain` (the agents from the person's own delegate to this
/// one). A hand-off adds the scopes of the delegations above it and the ceilings of the agents that handed it on.
/// Undefined when a delegated session's agent or delegation (or one above it) cannot be read or has ended: the
/// decision is refused.
pub async fn agent_decision_scope(
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    now: Option<f64>,
) -> IamResult<Option<crate::agents::AgentDecisionScope>> {
    use better_iam_core::SessionKind;
    let now = now.unwrap_or_else(crate::utils::date_now);
    let session = &principal.session;
    let delegated = session.kind == SessionKind::Delegated;
    let mut scope = AgentDecisionScope {
        keys: Map::new(),
        boundaries: Vec::new(),
        confirm: None,
        authorities: None,
        agent_ids: Vec::new(),
    };
    scope
        .keys
        .insert("principal.delegated".into(), Value::Bool(delegated));
    let Some(agent) = acting_agent(tx, principal).await? else {
        return Ok(if delegated { None } else { Some(scope) });
    };
    scope
        .keys
        .insert("principal.agentId".into(), Value::String(agent.id.clone()));
    scope.agent_ids.push(agent.id.clone());
    if let Some(profile) = &agent.agent {
        scope.keys.insert(
            "principal.agentSponsorId".into(),
            Value::String(profile.sponsor_id.clone()),
        );
        if let Some(model) = &profile.model {
            scope
                .keys
                .insert("principal.agentModel".into(), Value::String(model.clone()));
        }
        if let Some(provider) = &profile.provider {
            scope.keys.insert(
                "principal.agentProvider".into(),
                Value::String(provider.clone()),
            );
        }
        if let Some(boundary) = &profile.boundary {
            scope.boundaries.push(boundary.clone());
        }
    }
    if delegated {
        let delegation = match &session.delegation_id {
            Some(id) => tx.get("delegations", id).await?,
            None => None,
        };
        let Some(record) = delegation else {
            return Ok(None);
        };
        let text = |key: &str| record.get(key).and_then(Value::as_str);
        let policy = record
            .get("policy")
            .filter(|value| !value.is_null() && value.as_bool() != Some(false))
            .and_then(|value| {
                serde_json::from_value::<better_iam_core::PolicyDocument>(value.clone()).ok()
            });
        let (Some(policy), true) = (
            policy,
            text("status") == Some("active")
                && text("agentId") == Some(agent.id.as_str())
                && text("subjectId") == Some(principal.identity.id.as_str()),
        ) else {
            return Ok(None);
        };
        let Ok(typed) =
            serde_json::from_value::<crate::delegations::Delegation>(Value::Object(record.clone()))
        else {
            return Ok(None);
        };
        scope.keys.insert(
            "principal.delegationId".into(),
            Value::String(text("id").unwrap_or_default().to_owned()),
        );
        scope.boundaries.push(policy);
        // A hand-off is bounded by every delegation above it, the ceilings of the agents that handed it on, and the
        // limits of the sessions that did (their scope-down policies, key scopes and key issuers' authority).
        let Some(ancestors) = crate::delegations::delegation_ancestors(tx, &typed, now).await?
        else {
            return Ok(None);
        };
        let handed_on = |scope: &mut AgentDecisionScope, item: &crate::delegations::Delegation| {
            scope
                .boundaries
                .extend(item.ceilings.clone().unwrap_or_default());
            if let Some(authority_id) = &item.authority_id {
                scope
                    .authorities
                    .get_or_insert_with(Vec::new)
                    .push(authority_id.clone());
            }
        };
        handed_on(&mut scope, &typed);
        for ancestor in &ancestors {
            scope.agent_ids.push(ancestor.agent.id.clone());
            scope.boundaries.push(ancestor.delegation.policy.clone());
            if let Some(boundary) = ancestor
                .agent
                .agent
                .as_ref()
                .and_then(|p| p.boundary.clone())
            {
                scope.boundaries.push(boundary);
            }
            handed_on(&mut scope, &ancestor.delegation);
        }
        let mut chain: Vec<Value> = ancestors
            .iter()
            .rev()
            .map(|ancestor| Value::String(ancestor.agent.id.clone()))
            .collect();
        chain.push(Value::String(agent.id.clone()));
        scope
            .keys
            .insert("principal.delegationChain".into(), Value::Array(chain));
        if typed
            .confirm
            .as_ref()
            .is_some_and(|confirm| !confirm.is_empty())
        {
            let approved = crate::delegations::approved_confirmations(tx, &typed, now).await?;
            let record = record.clone();
            scope.confirm = Some(Arc::new(
                move |action: &str, resource_type: &str, resource_id: &str| {
                    let key =
                        crate::delegations::confirmation_key(action, resource_type, resource_id);
                    (crate::delegations::needs_confirmation(&record, action)
                        && !approved.contains(&key))
                    .then(|| better_iam_core::Decision {
                        allowed: false,
                        reason: "CONFIRMATION_REQUIRED".into(),
                        matched: Vec::new(),
                    })
                },
            ));
        }
    }
    Ok(Some(scope))
}

/// `actingAgent(tx, principal)`: the agent behind a principal: the identity of an agent's own credential, or the
/// agent of a delegated session.
pub async fn acting_agent(
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
) -> IamResult<Option<better_iam_core::Identity>> {
    use better_iam_core::{IdentityKind, SessionKind};
    if principal.session.kind == SessionKind::Delegated {
        let Some(agent_id) = &principal.session.agent_id else {
            return Ok(None);
        };
        let agent = match tx.get("identities", agent_id).await? {
            Some(record) => {
                serde_json::from_value::<better_iam_core::Identity>(Value::Object(record)).ok()
            }
            None => None,
        };
        return Ok(agent.filter(|agent| agent.kind == IdentityKind::Agent));
    }
    Ok((principal.identity.kind == IdentityKind::Agent).then(|| principal.identity.clone()))
}
