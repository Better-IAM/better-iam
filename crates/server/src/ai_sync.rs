//! Port of `packages/server/src/ai-sync.ts`: configuration as code for AI (the `agents`, `inferenceModels` and
//! `inferenceBudgets` kinds of sync.ts). Agents by name with their sponsor by email, the tenant's own models by name
//! with their provider by name, and inference budgets by name with their subject by group name, person email or
//! agent name. API keys, provider keys and delegations are runtime state and never synced. Providers hold secret
//! keys, so they are managed through the API and only named here.

use std::sync::Arc;

use better_iam_core::{
    AuthenticatedPrincipal, Filter, FindOptions, IamResult, Identity, Record, Tenant, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::agents::token_audience_list;
use crate::api::agents::agent_mutations;
use crate::api::inference::{inference_mutations, js_json};
use crate::context::{ServerContext, Store};
use crate::contracts::OperationResult;
use crate::inference::{InferenceProvider, inference_enabled, visible_providers};
use crate::js::{internal_error, invalid_input, number};
use crate::sync::{ConfigAllow, TenantConfig};
use crate::validation::{integer, object, strings, text};

/// A planned AI change set: one `{ change, desired?, record? }` per item (`AiPlanned` in TypeScript), where `change`
/// is a `ConfigChange`, `desired` the document's item and `record` the stored record it matches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AiPlan {
    #[serde(rename = "agents")]
    pub agents: Vec<Value>,
    #[serde(rename = "models")]
    pub models: Vec<Value>,
    #[serde(rename = "budgets")]
    pub budgets: Vec<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The tenant's AI state in configuration form. Records are kept as stored, so updates write back every member.
#[derive(Debug, Clone, PartialEq)]
pub struct AiState {
    /// The tenant's agents that are not deleted.
    pub agents: Vec<Record>,
    /// The tenant's own models (inherited ones belong to the tenant that defines them).
    pub models: Vec<Record>,
    /// Providers the tenant may use, nearest first.
    pub providers: Vec<InferenceProvider>,
    pub budgets: Vec<Record>,
    pub inference: bool,
}

/// An agent in a configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantConfigAgent {
    #[serde(rename = "name")]
    pub name: String,
    /// The accountable person, by email (an active person of the tenant).
    #[serde(rename = "sponsor")]
    pub sponsor: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "purpose", default, skip_serializing_if = "Option::is_none")]
    pub purpose: Option<String>,
    #[serde(rename = "model", default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(rename = "provider", default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    #[serde(rename = "url", default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    #[serde(rename = "protocols", default, skip_serializing_if = "Option::is_none")]
    pub protocols: Option<Vec<String>>,
    /// Default true.
    #[serde(rename = "delegable", default, skip_serializing_if = "Option::is_none")]
    pub delegable: Option<bool>,
    #[serde(
        rename = "maxDelegatedSessionSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_delegated_session_seconds: Option<f64>,
    /// A policy document object, passed through as the document gives it.
    #[serde(rename = "boundary", default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<Value>,
    /// Services the agent may present delegations to (`delegations.issueToken`).
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

/// An inference budget in a configuration document. `subject` is `'tenant'`, `{ group }`, `{ identity }` (a person
/// by email) or `{ agent }` (by name).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantConfigInferenceBudget {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "subject")]
    pub subject: Value,
    /// Default `shared` (always shared for a person or an agent).
    #[serde(rename = "scope", default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(rename = "period")]
    pub period: crate::inference::BudgetPeriod,
    #[serde(rename = "maxTokens", default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<f64>,
    #[serde(
        rename = "maxCostUsd",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_cost_usd: Option<f64>,
    #[serde(
        rename = "maxRequests",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_requests: Option<f64>,
    #[serde(rename = "models", default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
    #[serde(
        rename = "alertAtPercent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub alert_at_percent: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A model of the tenant in a configuration document.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TenantConfigInferenceModel {
    #[serde(rename = "name")]
    pub name: String,
    /// A provider of this tenant or an ancestor, by name.
    #[serde(rename = "provider")]
    pub provider: String,
    #[serde(rename = "upstreamModel")]
    pub upstream_model: String,
    #[serde(
        rename = "displayName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub display_name: Option<String>,
    #[serde(rename = "family", default, skip_serializing_if = "Option::is_none")]
    pub family: Option<String>,
    #[serde(rename = "tier", default, skip_serializing_if = "Option::is_none")]
    pub tier: Option<String>,
    #[serde(
        rename = "contextWindow",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub context_window: Option<f64>,
    #[serde(
        rename = "maxOutputTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_output_tokens: Option<f64>,
    #[serde(
        rename = "inputPricePerMTok",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub input_price_per_m_tok: Option<f64>,
    #[serde(
        rename = "outputPricePerMTok",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub output_price_per_m_tok: Option<f64>,
    #[serde(
        rename = "cachedInputPricePerMTok",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cached_input_price_per_m_tok: Option<f64>,
    /// Models the gateway tries, in order, when this one's provider fails.
    #[serde(rename = "fallbacks", default, skip_serializing_if = "Option::is_none")]
    pub fallbacks: Option<Vec<String>>,
    /// Provider-run tools: `deny` or `policy` (`allow`, the default, is left out).
    #[serde(
        rename = "providerTools",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_tools: Option<String>,
    /// Default true.
    #[serde(rename = "enabled", default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

// --- Helpers --------------------------------------------------------------------------------------------------------

/// `value.trim().toLowerCase()`.
fn lower(value: &str) -> String {
    core_js::to_lower(core_js::trim(value))
}

const PERIODS: [&str; 4] = ["minute", "hour", "day", "month"];

/// A string member of a record (`""` when absent or not a string).
fn member<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

/// `a.name < b.name ? -1 : a.name > b.name ? 1 : 0`.
fn by_name(a: &Record, b: &Record) -> std::cmp::Ordering {
    core_js::cmp_utf16(member(a, "name"), member(b, "name"))
}

/// A typed document item as the JSON object TypeScript compares and reports (undefined members left out).
fn as_json<T: Serialize>(value: &T) -> Map<String, Value> {
    match serde_json::to_value(value).map(js_json) {
        Ok(Value::Object(map)) => map,
        _ => Map::new(),
    }
}

/// Inserts `value` unless it is `undefined` (`compact`).
fn put(out: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(value) = value {
        out.insert(key.into(), value.clone());
    }
}

/// `value?.length ? [...value] : undefined` for an array member.
fn non_empty(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| value.as_array().is_some_and(|items| !items.is_empty()))
}

fn optional_text(
    item: &Map<String, Value>,
    key: &str,
    label: &str,
    max: usize,
) -> IamResult<Option<String>> {
    match item.get(key) {
        None | Some(Value::Null) => Ok(None),
        value => text(value, &format!("{label} {key}"), max).map(Some),
    }
}

fn optional_number(item: &Map<String, Value>, key: &str, label: &str) -> IamResult<Option<f64>> {
    match item.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(value)) => {
            let value = core_js::number_value(value);
            if value.is_finite() && value >= 0.0 {
                Ok(Some(value))
            } else {
                Err(invalid_input(format!(
                    "{label}: {key} must be a non-negative number"
                )))
            }
        }
        Some(_) => Err(invalid_input(format!(
            "{label}: {key} must be a non-negative number"
        ))),
    }
}

/// `integer(item[key], label, min, max)` unless the member is undefined or null.
fn optional_integer(
    item: &Map<String, Value>,
    key: &str,
    name: &str,
    min: f64,
    max: f64,
) -> IamResult<Option<f64>> {
    match item.get(key) {
        None | Some(Value::Null) => Ok(None),
        value => integer(value, name, min, max).map(Some),
    }
}

/// `[...new Set(items)].sort()`.
fn unique_sorted(items: Vec<String>) -> Vec<String> {
    let mut list = crate::js::unique(items);
    crate::js::sort_strings(&mut list);
    list
}

/// Refuses two items whose names differ only in case or surrounding spaces.
fn unique_names<'a>(names: impl Iterator<Item = &'a String>, kind: &str) -> IamResult<()> {
    let mut seen: IndexSet<String> = IndexSet::new();
    for name in names {
        if !seen.insert(lower(name)) {
            return Err(invalid_input(format!("Duplicate {kind} {name}")));
        }
    }
    Ok(())
}

/// A model's `providerTools` in a document: `deny` or `policy`, or undefined for `allow` (the default).
fn provider_tools_setting(value: Option<&Value>, label: &str) -> IamResult<Option<String>> {
    match value {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(mode)) if mode == "allow" => Ok(None),
        Some(Value::String(mode)) if mode == "deny" || mode == "policy" => Ok(Some(mode.clone())),
        Some(_) => Err(invalid_input(format!(
            "{label}: providerTools must be 'allow', 'deny' or 'policy'"
        ))),
    }
}

// --- Parsing --------------------------------------------------------------------------------------------------------

pub fn parse_agents_config(items: &[Map<String, Value>]) -> IamResult<Vec<TenantConfigAgent>> {
    let mut parsed = Vec::new();
    for raw in items {
        let item = object(Some(&Value::Object(raw.clone())))?.clone();
        let name = text(item.get("name"), "agent name", 200)?;
        let label = format!("Agent {name}");
        let sponsor = core_js::to_lower(&text(
            item.get("sponsor"),
            &format!("{label} sponsor"),
            320,
        )?);
        if let Some(delegable) = item.get("delegable")
            && !delegable.is_boolean()
        {
            return Err(invalid_input(format!(
                "{label}: delegable must be a boolean"
            )));
        }
        let boundary = match item.get("boundary") {
            None | Some(Value::Null) => None,
            Some(value) => {
                object(Some(value))?;
                Some(value.clone())
            }
        };
        let description = optional_text(&item, "description", &label, 512)?;
        let purpose = optional_text(&item, "purpose", &label, 1024)?;
        let model = optional_text(&item, "model", &label, 128)?;
        let provider =
            optional_text(&item, "provider", &label, 64)?.map(|value| core_js::to_lower(&value));
        let url = optional_text(&item, "url", &label, 2048)?;
        let protocols = match item.get("protocols") {
            None | Some(Value::Null) => None,
            value => Some(unique_sorted(
                strings(value, &format!("{label} protocols"))?
                    .iter()
                    .map(|protocol| core_js::to_lower(protocol))
                    .collect(),
            )),
        };
        let delegable = (item.get("delegable") == Some(&Value::Bool(false))).then_some(false);
        let max_delegated_session_seconds = optional_integer(
            &item,
            "maxDelegatedSessionSeconds",
            &format!("{label} maxDelegatedSessionSeconds"),
            60.0,
            43_200.0,
        )?;
        let token_audiences = match item.get("tokenAudiences") {
            None | Some(Value::Null) => None,
            value => Some(token_audience_list(
                value,
                Some(&format!("{label} tokenAudiences")),
            )?),
        };
        parsed.push(TenantConfigAgent {
            name,
            sponsor,
            description,
            purpose,
            model,
            provider,
            url,
            protocols,
            delegable,
            max_delegated_session_seconds,
            boundary,
            token_audiences,
            extra: Map::new(),
        });
    }
    unique_names(parsed.iter().map(|item| &item.name), "agent")?;
    Ok(parsed)
}

pub fn parse_models_config(
    items: &[Map<String, Value>],
) -> IamResult<Vec<TenantConfigInferenceModel>> {
    let mut parsed = Vec::new();
    for raw in items {
        let item = object(Some(&Value::Object(raw.clone())))?.clone();
        let name = text(item.get("name"), "model name", 128)?;
        let label = format!("Model {name}");
        if let Some(enabled) = item.get("enabled")
            && !enabled.is_boolean()
        {
            return Err(invalid_input(format!("{label}: enabled must be a boolean")));
        }
        let count =
            |key: &str| optional_integer(&item, key, &format!("{label} {key}"), 1.0, 100_000_000.0);
        let provider = text(item.get("provider"), &format!("{label} provider"), 200)?;
        let upstream_model = text(
            item.get("upstreamModel"),
            &format!("{label} upstreamModel"),
            256,
        )?;
        let display_name = optional_text(&item, "displayName", &label, 128)?;
        let family = optional_text(&item, "family", &label, 64)?;
        let tier = optional_text(&item, "tier", &label, 64)?;
        let context_window = count("contextWindow")?;
        let max_output_tokens = count("maxOutputTokens")?;
        let input_price_per_m_tok = optional_number(&item, "inputPricePerMTok", &label)?;
        let output_price_per_m_tok = optional_number(&item, "outputPricePerMTok", &label)?;
        let cached_input_price_per_m_tok =
            optional_number(&item, "cachedInputPricePerMTok", &label)?;
        let fallbacks = match item.get("fallbacks") {
            None | Some(Value::Null) => None,
            value => Some(strings(value, &format!("{label} fallbacks"))?),
        };
        let provider_tools = provider_tools_setting(item.get("providerTools"), &label)?;
        let enabled = (item.get("enabled") == Some(&Value::Bool(false))).then_some(false);
        parsed.push(TenantConfigInferenceModel {
            name,
            provider,
            upstream_model,
            display_name,
            family,
            tier,
            context_window,
            max_output_tokens,
            input_price_per_m_tok,
            output_price_per_m_tok,
            cached_input_price_per_m_tok,
            fallbacks,
            provider_tools,
            enabled,
            extra: Map::new(),
        });
    }
    unique_names(parsed.iter().map(|item| &item.name), "model")?;
    Ok(parsed)
}

/// Whom a budget covers: `'tenant'`, `{ group }`, `{ identity }` (lowercased) or `{ agent }`.
fn budget_subject(value: Option<&Value>, label: &str) -> IamResult<Value> {
    if value.and_then(Value::as_str) == Some("tenant") {
        return Ok(Value::String("tenant".into()));
    }
    let subject = object(value)?;
    let keys = core_js::keys(subject);
    if keys.len() == 1 && (keys[0] == "group" || keys[0] == "agent") {
        let key = keys[0].clone();
        let name = text(subject.get(&key), &format!("{label} subject"), 200)?;
        let mut out = Map::new();
        out.insert(key, Value::String(name));
        return Ok(Value::Object(out));
    }
    if keys.len() == 1 && keys[0] == "identity" {
        let email = core_js::to_lower(&text(
            subject.get("identity"),
            &format!("{label} subject"),
            320,
        )?);
        let mut out = Map::new();
        out.insert("identity".into(), Value::String(email));
        return Ok(Value::Object(out));
    }
    Err(invalid_input(format!(
        "{label}: subject must be 'tenant', {{ group }}, {{ identity }} or {{ agent }}"
    )))
}

pub fn parse_budgets_config(
    items: &[Map<String, Value>],
) -> IamResult<Vec<TenantConfigInferenceBudget>> {
    let mut parsed = Vec::new();
    for raw in items {
        let item = object(Some(&Value::Object(raw.clone())))?.clone();
        let name = core_js::trim(&text(item.get("name"), "budget name", 100)?).to_owned();
        let label = format!("Budget {name}");
        let Some(period) = item
            .get("period")
            .and_then(Value::as_str)
            .filter(|period| PERIODS.contains(period))
        else {
            return Err(invalid_input(format!(
                "{label}: period must be minute, hour, day or month"
            )));
        };
        let period = period.to_owned();
        if let Some(scope) = item.get("scope")
            && scope.as_str() != Some("shared")
            && scope.as_str() != Some("each")
        {
            return Err(invalid_input(format!(
                "{label}: scope must be shared or each"
            )));
        }
        let subject = budget_subject(item.get("subject"), &label)?;
        let pooled = subject.as_str() == Some("tenant")
            || subject
                .as_object()
                .is_some_and(|map| map.contains_key("group"));
        let scope = (item.get("scope").and_then(Value::as_str) == Some("each") && pooled)
            .then(|| "each".to_owned());
        let max_tokens =
            optional_integer(&item, "maxTokens", &format!("{label} maxTokens"), 1.0, 1e15)?;
        let max_cost_usd = optional_number(&item, "maxCostUsd", &label)?;
        let max_requests = optional_integer(
            &item,
            "maxRequests",
            &format!("{label} maxRequests"),
            1.0,
            1_000_000_000.0,
        )?;
        let models = match item.get("models") {
            None | Some(Value::Null) => None,
            value => Some(unique_sorted(strings(value, &format!("{label} models"))?)),
        };
        let alert_at_percent = optional_integer(
            &item,
            "alertAtPercent",
            &format!("{label} alertAtPercent"),
            1.0,
            100.0,
        )?;
        if max_tokens.is_none() && max_cost_usd.is_none() && max_requests.is_none() {
            return Err(invalid_input(format!(
                "{label}: set maxTokens, maxCostUsd or maxRequests"
            )));
        }
        parsed.push(TenantConfigInferenceBudget {
            name,
            subject,
            scope,
            period,
            max_tokens,
            max_cost_usd,
            max_requests,
            models,
            alert_at_percent,
            extra: Map::new(),
        });
    }
    unique_names(parsed.iter().map(|item| &item.name), "budget")?;
    Ok(parsed)
}

// --- State and export -----------------------------------------------------------------------------------------------

pub async fn read_ai_state(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<AiState> {
    let find = |collection: &'static str, filter: Filter| async move {
        tx.find(collection, &filter, &FindOptions::default()).await
    };
    let mut agents: Vec<Record> = find(
        "identities",
        Filter::new().eq("tenantId", tenant_id).eq("kind", "agent"),
    )
    .await?
    .into_iter()
    .filter(|agent| member(agent, "status") != "deleted")
    .collect();
    agents.sort_by(by_name);
    let inference = inference_enabled(ctx);
    let (models, providers, budgets) = if inference {
        let mut models = find("inferenceModels", Filter::new().eq("tenantId", tenant_id)).await?;
        models.sort_by(by_name);
        let providers = visible_providers(ctx, tx, tenant_id).await?;
        let mut budgets = find("inferenceBudgets", Filter::new().eq("tenantId", tenant_id)).await?;
        budgets.sort_by(by_name);
        (models, providers, budgets)
    } else {
        (Vec::new(), Vec::new(), Vec::new())
    };
    Ok(AiState {
        agents,
        models,
        providers,
        budgets,
        inference,
    })
}

/// `Names`: identity emails and group names by ID.
struct Names {
    identity_emails: IndexMap<String, String>,
    group_names: IndexMap<String, String>,
}

/// A map of strings from a JSON object member of the environment.
fn string_map(env: &Value, key: &str) -> IndexMap<String, String> {
    env.get(key)
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value.as_str().map(|text| (key.clone(), text.to_owned()))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl Names {
    fn from_env(env: &Value) -> Self {
        Self {
            identity_emails: string_map(env, "identityEmails"),
            group_names: string_map(env, "groupNames"),
        }
    }
}

fn exported_agent(agent: &Record, names: &Names) -> Map<String, Value> {
    let profile = agent.get("agent").and_then(Value::as_object);
    let field = |key: &str| profile.and_then(|profile| profile.get(key));
    let mut out = Map::new();
    out.insert(
        "name".into(),
        agent.get("name").cloned().unwrap_or(Value::Null),
    );
    let sponsor_id = field("sponsorId");
    let sponsor = match sponsor_id {
        None | Some(Value::Null) => names.identity_emails.get("").cloned(),
        Some(id) => names
            .identity_emails
            .get(&crate::js::js_string(Some(id)))
            .cloned(),
    }
    .map(Value::String)
    .or_else(|| sponsor_id.filter(|id| !id.is_null()).cloned())
    .unwrap_or_else(|| Value::String(String::new()));
    out.insert("sponsor".into(), sponsor);
    put(&mut out, "description", agent.get("description"));
    put(&mut out, "purpose", field("purpose"));
    put(&mut out, "model", field("model"));
    put(&mut out, "provider", field("provider"));
    put(&mut out, "url", field("url"));
    put(&mut out, "protocols", non_empty(field("protocols")));
    if field("delegable") == Some(&Value::Bool(false)) {
        out.insert("delegable".into(), Value::Bool(false));
    }
    put(
        &mut out,
        "maxDelegatedSessionSeconds",
        field("maxDelegatedSessionSeconds"),
    );
    put(&mut out, "boundary", field("boundary"));
    put(
        &mut out,
        "tokenAudiences",
        non_empty(field("tokenAudiences")),
    );
    out
}

fn exported_model(model: &Record, providers: &[InferenceProvider]) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert(
        "name".into(),
        model.get("name").cloned().unwrap_or(Value::Null),
    );
    let provider_id = member(model, "providerId");
    let provider = providers
        .iter()
        .find(|provider| provider.id == provider_id)
        .map(|provider| Value::String(provider.name.clone()))
        .or_else(|| model.get("providerId").cloned())
        .unwrap_or(Value::Null);
    out.insert("provider".into(), provider);
    put(&mut out, "upstreamModel", model.get("upstreamModel"));
    for key in [
        "displayName",
        "family",
        "tier",
        "contextWindow",
        "maxOutputTokens",
        "inputPricePerMTok",
        "outputPricePerMTok",
        "cachedInputPricePerMTok",
    ] {
        put(&mut out, key, model.get(key));
    }
    put(&mut out, "fallbacks", non_empty(model.get("fallbacks")));
    if let Some(mode) = model
        .get("providerTools")
        .filter(|mode| mode.as_str() == Some("deny") || mode.as_str() == Some("policy"))
    {
        out.insert("providerTools".into(), mode.clone());
    }
    if model.get("enabled") == Some(&Value::Bool(false)) {
        out.insert("enabled".into(), Value::Bool(false));
    }
    out
}

fn exported_budget(budget: &Record, state: &AiState, names: &Names) -> Map<String, Value> {
    let subject_type = member(budget, "subjectType");
    let subject_id = member(budget, "subjectId");
    let single = |key: &str, value: String| {
        let mut map = Map::new();
        map.insert(key.into(), Value::String(value));
        Value::Object(map)
    };
    let subject = if subject_type == "group" {
        single(
            "group",
            names
                .group_names
                .get(subject_id)
                .cloned()
                .unwrap_or_else(|| subject_id.to_owned()),
        )
    } else if subject_type == "identity" {
        match state
            .agents
            .iter()
            .find(|agent| member(agent, "id") == subject_id)
        {
            Some(agent) => single("agent", member(agent, "name").to_owned()),
            None => single(
                "identity",
                names
                    .identity_emails
                    .get(subject_id)
                    .cloned()
                    .unwrap_or_else(|| subject_id.to_owned()),
            ),
        }
    } else {
        Value::String("tenant".into())
    };
    let mut out = Map::new();
    out.insert(
        "name".into(),
        budget.get("name").cloned().unwrap_or(Value::Null),
    );
    out.insert("subject".into(), subject);
    if member(budget, "scope") == "each" && subject_type != "identity" {
        out.insert("scope".into(), Value::String("each".into()));
    }
    put(&mut out, "period", budget.get("period"));
    put(&mut out, "maxTokens", budget.get("maxTokens"));
    if let Some(micros) = budget.get("maxCostMicros") {
        let micros = core_js::as_number(micros).unwrap_or(f64::NAN);
        out.insert("maxCostUsd".into(), number(micros / 1_000_000.0));
    }
    put(&mut out, "maxRequests", budget.get("maxRequests"));
    if let Some(Value::Array(models)) = non_empty(budget.get("models")) {
        let mut sorted: Vec<Value> = models.clone();
        sorted.sort_by(|a, b| {
            core_js::cmp_utf16(
                &crate::js::js_string(Some(a)),
                &crate::js::js_string(Some(b)),
            )
        });
        out.insert("models".into(), Value::Array(sorted));
    }
    put(&mut out, "alertAtPercent", budget.get("alertAtPercent"));
    out
}

/// The AI part of an export, each kind only when the tenant has some (so other exports stay unchanged). `names`
/// carries `identityEmails` and `groupNames` (ID to email or name).
pub fn export_ai(state: &AiState, names: &Value) -> IamResult<Value> {
    let names = Names::from_env(names);
    let mut config = Map::new();
    if !state.agents.is_empty() {
        config.insert(
            "agents".into(),
            Value::Array(
                state
                    .agents
                    .iter()
                    .map(|agent| Value::Object(exported_agent(agent, &names)))
                    .collect(),
            ),
        );
    }
    if !state.models.is_empty() {
        config.insert(
            "inferenceModels".into(),
            Value::Array(
                state
                    .models
                    .iter()
                    .map(|model| Value::Object(exported_model(model, &state.providers)))
                    .collect(),
            ),
        );
    }
    if !state.budgets.is_empty() {
        config.insert(
            "inferenceBudgets".into(),
            Value::Array(
                state
                    .budgets
                    .iter()
                    .map(|budget| Value::Object(exported_budget(budget, state, &names)))
                    .collect(),
            ),
        );
    }
    Ok(Value::Object(config))
}

// --- Planning -------------------------------------------------------------------------------------------------------

/// One planned item: `{ change, desired?, record? }`.
fn change(
    kind: &str,
    name: &str,
    before: Option<Map<String, Value>>,
    after: Option<Map<String, Value>>,
    desired: Option<Value>,
    record: Option<&Record>,
) -> Value {
    let mut change = Map::new();
    change.insert("kind".into(), Value::String(kind.to_owned()));
    change.insert("name".into(), Value::String(name.to_owned()));
    let mut planned = Map::new();
    match (before, after) {
        (None, after) => {
            change.insert("action".into(), Value::String("create".into()));
            if let Some(after) = after {
                change.insert("after".into(), Value::Object(after));
            }
            planned.insert("change".into(), Value::Object(change));
            if let Some(desired) = desired {
                planned.insert("desired".into(), desired);
            }
        }
        (Some(before), None) => {
            change.insert("action".into(), Value::String("delete".into()));
            change.insert("before".into(), Value::Object(before));
            planned.insert("change".into(), Value::Object(change));
            if let Some(record) = record {
                planned.insert("record".into(), Value::Object(record.clone()));
            }
        }
        (Some(before), Some(after)) => {
            let fields = crate::sync::diff_fields(&before, &after);
            if fields.is_empty() {
                change.insert("action".into(), Value::String("unchanged".into()));
            } else {
                change.insert("action".into(), Value::String("update".into()));
                change.insert(
                    "fields".into(),
                    Value::Array(fields.into_iter().map(Value::String).collect()),
                );
                change.insert("before".into(), Value::Object(before));
                change.insert("after".into(), Value::Object(after));
            }
            planned.insert("change".into(), Value::Object(change));
            if let Some(desired) = desired {
                planned.insert("desired".into(), desired);
            }
            if let Some(record) = record {
                planned.insert("record".into(), Value::Object(record.clone()));
            }
        }
    }
    Value::Object(planned)
}

/// Plans the AI kinds a document names (a kind the document leaves out is left alone). Sponsors must be people of
/// the tenant now; budget groups must exist after the apply (`groupNamesAfter`); a budget's agent must be an agent
/// now or one this document creates; a model's provider must be visible to the tenant. `env` carries
/// `identityEmails`, `groupNames`, `identitiesByEmail`, `groupNamesAfter` and `prune`.
pub fn plan_ai(desired: &TenantConfig, state: &AiState, env: &Value) -> IamResult<AiPlan> {
    let names = Names::from_env(env);
    let identities_by_email = env.get("identitiesByEmail").and_then(Value::as_object);
    let person = |email: &str| identities_by_email.and_then(|map| map.get(email));
    let group_names_after: IndexSet<String> = env
        .get("groupNamesAfter")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    let prune = env.get("prune") == Some(&Value::Bool(true));
    let mut plan = AiPlan {
        agents: Vec::new(),
        models: Vec::new(),
        budgets: Vec::new(),
        extra: Map::new(),
    };
    if !state.inference
        && (desired.inference_models.is_some() || desired.inference_budgets.is_some())
    {
        return Err(invalid_input(
            "inferenceModels and inferenceBudgets need the inference option on this deployment",
        ));
    }

    if let Some(agents) = &desired.agents {
        let mut existing: IndexMap<String, &Record> = IndexMap::new();
        for agent in &state.agents {
            let key = lower(member(agent, "name"));
            if existing.contains_key(&key) {
                return Err(invalid_input(format!(
                    "More than one agent is named {}; rename one before syncing agents",
                    member(agent, "name")
                )));
            }
            existing.insert(key, agent);
        }
        for agent in agents {
            let sponsor = person(&agent.sponsor);
            if !sponsor
                .is_some_and(|sponsor| sponsor.get("kind").and_then(Value::as_str) == Some("user"))
            {
                return Err(invalid_input(format!(
                    "Agent {}: no person {}",
                    agent.name, agent.sponsor
                )));
            }
            let record = existing.get(&lower(&agent.name)).copied();
            plan.agents.push(change(
                "agent",
                &agent.name,
                record.map(|record| exported_agent(record, &names)),
                Some(as_json(agent)),
                Some(Value::Object(as_json(agent))),
                record,
            ));
        }
        if prune {
            for record in &state.agents {
                if !agents
                    .iter()
                    .any(|agent| lower(&agent.name) == lower(member(record, "name")))
                {
                    plan.agents.push(change(
                        "agent",
                        member(record, "name"),
                        Some(exported_agent(record, &names)),
                        None,
                        None,
                        Some(record),
                    ));
                }
            }
        }
    }

    if let Some(models) = &desired.inference_models {
        let existing: IndexMap<&str, &Record> = state
            .models
            .iter()
            .map(|model| (member(model, "name"), model))
            .collect();
        for model in models {
            if !state
                .providers
                .iter()
                .any(|provider| provider.name == model.provider)
            {
                return Err(invalid_input(format!(
                    "Model {}: no provider named {} (create providers through the API)",
                    model.name, model.provider
                )));
            }
            let record = existing.get(model.name.as_str()).copied();
            plan.models.push(change(
                "inferenceModel",
                &model.name,
                record.map(|record| exported_model(record, &state.providers)),
                Some(as_json(model)),
                Some(Value::Object(as_json(model))),
                record,
            ));
        }
        if prune {
            for record in &state.models {
                if !models
                    .iter()
                    .any(|model| model.name == member(record, "name"))
                {
                    plan.models.push(change(
                        "inferenceModel",
                        member(record, "name"),
                        Some(exported_model(record, &state.providers)),
                        None,
                        None,
                        Some(record),
                    ));
                }
            }
        }
    }

    if let Some(budgets) = &desired.inference_budgets {
        let mut agents_after: IndexSet<String> = state
            .agents
            .iter()
            .map(|agent| lower(member(agent, "name")))
            .collect();
        for agent in desired.agents.iter().flatten() {
            agents_after.insert(lower(&agent.name));
        }
        let mut existing: IndexMap<String, &Record> = IndexMap::new();
        for budget in &state.budgets {
            existing.insert(lower(member(budget, "name")), budget);
        }
        for budget in budgets {
            if let Some(subject) = budget.subject.as_object() {
                if let Some(group) = subject.get("group").and_then(Value::as_str)
                    && !group_names_after.contains(group)
                {
                    return Err(invalid_input(format!(
                        "Budget {}: no group {group}",
                        budget.name
                    )));
                }
                if let Some(identity) = subject.get("identity").and_then(Value::as_str)
                    && person(identity).is_none()
                {
                    return Err(invalid_input(format!(
                        "Budget {}: no identity {identity}",
                        budget.name
                    )));
                }
                if let Some(agent) = subject.get("agent").and_then(Value::as_str)
                    && !agents_after.contains(&lower(agent))
                {
                    return Err(invalid_input(format!(
                        "Budget {}: no agent {agent}",
                        budget.name
                    )));
                }
            }
            let record = existing.get(&lower(&budget.name)).copied();
            plan.budgets.push(change(
                "inferenceBudget",
                &budget.name,
                record.map(|record| exported_budget(record, state, &names)),
                Some(as_json(budget)),
                Some(Value::Object(as_json(budget))),
                record,
            ));
        }
        if prune {
            for record in &state.budgets {
                if !budgets
                    .iter()
                    .any(|budget| lower(&budget.name) == lower(member(record, "name")))
                {
                    plan.budgets.push(change(
                        "inferenceBudget",
                        member(record, "name"),
                        Some(exported_budget(record, state, &names)),
                        None,
                        None,
                        Some(record),
                    ));
                }
            }
        }
    }
    Ok(plan)
}

// --- Applying -------------------------------------------------------------------------------------------------------

/// What `applyAi` needs from the configuration apply: the authorizer, ordinary group name to ID (including groups
/// this apply created), and the tenant's people by lowercase email.
pub struct AiApplyEnv<'a> {
    /// Authorizes one change like the equivalent API call.
    pub allow: &'a ConfigAllow,
    pub group_ids: &'a IndexMap<String, String>,
    pub identities_by_email: &'a IndexMap<String, Identity>,
}

/// The `change` of a planned item.
fn change_of(item: &Value) -> (&str, &str) {
    let change = item.get("change");
    let field = |key: &str| {
        change
            .and_then(|change| change.get(key))
            .and_then(Value::as_str)
            .unwrap_or("")
    };
    (field("action"), field("name"))
}

/// The stored record of a planned item (`record!`).
fn record_of(item: &Value) -> IamResult<Record> {
    item.get("record")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(internal_error)
}

/// The document item of a planned item (`desired!`).
fn desired_of<T: serde::de::DeserializeOwned>(item: &Value) -> IamResult<T> {
    item.get("desired")
        .cloned()
        .and_then(|value| serde_json::from_value(value).ok())
        .ok_or_else(internal_error)
}

fn text_or_null(value: &Option<String>) -> Value {
    value.clone().map_or(Value::Null, Value::String)
}

fn number_or_null(value: Option<f64>) -> Value {
    value.map_or(Value::Null, number)
}

fn strings_or_null(value: &Option<Vec<String>>) -> Value {
    value.as_ref().map_or(Value::Null, |items| {
        Value::Array(items.iter().cloned().map(Value::String).collect())
    })
}

/// `profileOf(agent)`: the agent's description and profile, null for what the document leaves out.
fn profile_of(agent: &TenantConfigAgent) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("description".into(), text_or_null(&agent.description));
    out.insert("purpose".into(), text_or_null(&agent.purpose));
    out.insert("model".into(), text_or_null(&agent.model));
    out.insert("provider".into(), text_or_null(&agent.provider));
    out.insert("url".into(), text_or_null(&agent.url));
    out.insert("protocols".into(), strings_or_null(&agent.protocols));
    out.insert(
        "delegable".into(),
        Value::Bool(agent.delegable != Some(false)),
    );
    out.insert(
        "maxDelegatedSessionSeconds".into(),
        number_or_null(agent.max_delegated_session_seconds),
    );
    out.insert(
        "boundary".into(),
        agent.boundary.clone().unwrap_or(Value::Null),
    );
    out.insert(
        "tokenAudiences".into(),
        strings_or_null(&agent.token_audiences),
    );
    out
}

/// `modelInput(model, providers)`: the model's API input, null for what the document leaves out.
fn model_input(
    model: &TenantConfigInferenceModel,
    providers: &[InferenceProvider],
) -> IamResult<Map<String, Value>> {
    // `providers.find(...)!.id`: planning checked the provider exists.
    let provider = providers
        .iter()
        .find(|provider| provider.name == model.provider)
        .ok_or_else(internal_error)?;
    let mut out = Map::new();
    out.insert("providerId".into(), Value::String(provider.id.clone()));
    out.insert(
        "upstreamModel".into(),
        Value::String(model.upstream_model.clone()),
    );
    out.insert("displayName".into(), text_or_null(&model.display_name));
    out.insert("family".into(), text_or_null(&model.family));
    out.insert("tier".into(), text_or_null(&model.tier));
    out.insert("contextWindow".into(), number_or_null(model.context_window));
    out.insert(
        "maxOutputTokens".into(),
        number_or_null(model.max_output_tokens),
    );
    out.insert(
        "inputPricePerMTok".into(),
        number_or_null(model.input_price_per_m_tok),
    );
    out.insert(
        "outputPricePerMTok".into(),
        number_or_null(model.output_price_per_m_tok),
    );
    out.insert(
        "cachedInputPricePerMTok".into(),
        number_or_null(model.cached_input_price_per_m_tok),
    );
    out.insert("fallbacks".into(), strings_or_null(&model.fallbacks));
    out.insert("providerTools".into(), text_or_null(&model.provider_tools));
    out.insert("enabled".into(), Value::Bool(model.enabled != Some(false)));
    Ok(out)
}

/// Applies a planned AI change set inside the configuration apply transaction. `upsert` creates and updates (agents
/// first, so budgets can name them), `delete` removes (budgets first, then models and agents); both by default.
/// Every change is authorized like the equivalent API call (`allow`).
pub async fn apply_ai(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant: &Tenant,
    plan: &AiPlan,
    env: &AiApplyEnv<'_>,
    phase: Option<&str>,
) -> OperationResult<()> {
    let phase = phase.unwrap_or("all");
    let tenant_id = tenant.id.as_str();
    let agents = agent_mutations(ctx);
    let inference = inference_mutations(ctx);
    let person_id = |email: &str| -> IamResult<String> {
        env.identities_by_email
            .get(email)
            .map(|person| person.id.clone())
            .ok_or_else(|| invalid_input(format!("No person {email}")))
    };

    if phase != "delete" {
        for item in &plan.agents {
            let (action, name) = change_of(item);
            if action == "create" {
                let desired: TenantConfigAgent = desired_of(item)?;
                env.allow
                    .allow(
                        "iam:agents:create",
                        tenant_id,
                        &format!("create agent {}", desired.name),
                    )
                    .await?;
                let mut profile = profile_of(&desired);
                let description = profile.shift_remove("description").unwrap_or(Value::Null);
                let mut input = Map::new();
                input.insert("name".into(), Value::String(desired.name.clone()));
                input.insert(
                    "sponsorId".into(),
                    Value::String(person_id(&desired.sponsor)?),
                );
                if !description.is_null() {
                    input.insert("description".into(), description);
                }
                for (key, value) in profile {
                    if !value.is_null() {
                        input.insert(key, value);
                    }
                }
                agents.create_agent(tx, principal, tenant, &input).await?;
            } else if action == "update" {
                let record = record_of(item)?;
                let desired: TenantConfigAgent = desired_of(item)?;
                env.allow
                    .allow(
                        "iam:agents:update",
                        member(&record, "id"),
                        &format!("update agent {name}"),
                    )
                    .await?;
                let mut input = Map::new();
                input.insert("name".into(), Value::String(desired.name.clone()));
                input.insert(
                    "sponsorId".into(),
                    Value::String(person_id(&desired.sponsor)?),
                );
                input.extend(profile_of(&desired));
                agents.update_agent(tx, principal, &record, &input).await?;
            }
        }
        let providers = visible_providers(ctx, tx, tenant_id).await?;
        for item in &plan.models {
            let (action, name) = change_of(item);
            if action == "create" {
                let desired: TenantConfigInferenceModel = desired_of(item)?;
                env.allow
                    .allow(
                        "iam:inference:manage",
                        tenant_id,
                        &format!("create model {}", desired.name),
                    )
                    .await?;
                let mut input = Map::new();
                input.insert("name".into(), Value::String(desired.name.clone()));
                for (key, value) in model_input(&desired, &providers)? {
                    if !value.is_null() {
                        input.insert(key, value);
                    }
                }
                inference
                    .create_model(tx, principal, tenant_id, &input)
                    .await?;
            } else if action == "update" {
                let desired: TenantConfigInferenceModel = desired_of(item)?;
                env.allow
                    .allow(
                        "iam:inference:manage",
                        tenant_id,
                        &format!("update model {name}"),
                    )
                    .await?;
                let mut input = Map::new();
                input.insert("name".into(), Value::String(desired.name.clone()));
                input.extend(model_input(&desired, &providers)?);
                inference
                    .update_model(tx, principal, tenant_id, &input)
                    .await?;
            }
        }
        let agent_ids: IndexMap<String, String> = tx
            .find(
                "identities",
                &Filter::new().eq("tenantId", tenant_id).eq("kind", "agent"),
                &FindOptions::default(),
            )
            .await?
            .iter()
            .filter(|agent| member(agent, "status") != "deleted")
            .map(|agent| (lower(member(agent, "name")), member(agent, "id").to_owned()))
            .collect();
        for item in &plan.budgets {
            let (action, name) = change_of(item);
            if action != "create" && action != "update" {
                continue;
            }
            env.allow
                .allow(
                    "iam:inference:manage",
                    tenant_id,
                    &format!("{action} budget {name}"),
                )
                .await?;
            let budget: TenantConfigInferenceBudget = desired_of(item)?;
            let subject = budget.subject.as_object();
            let field = |key: &str| {
                subject
                    .and_then(|subject| subject.get(key))
                    .and_then(Value::as_str)
            };
            let subject_type = match subject {
                None => "tenant",
                Some(subject) if subject.contains_key("group") => "group",
                Some(_) => "identity",
            };
            let mut input = Map::new();
            input.insert("name".into(), Value::String(budget.name.clone()));
            input.insert("subjectType".into(), Value::String(subject_type.into()));
            if subject.is_some() {
                let subject_id = if let Some(group) = field("group") {
                    match env.group_ids.get(group) {
                        Some(id) => id.clone(),
                        None => tx
                            .find(
                                "groups",
                                &Filter::new().eq("tenantId", tenant_id),
                                &FindOptions::default(),
                            )
                            .await?
                            .iter()
                            .find(|record| member(record, "name") == group)
                            .map(|record| member(record, "id").to_owned())
                            .unwrap_or_default(),
                    }
                } else if let Some(agent) = field("agent") {
                    agent_ids.get(&lower(agent)).cloned().unwrap_or_default()
                } else {
                    person_id(field("identity").unwrap_or(""))?
                };
                input.insert("subjectId".into(), Value::String(subject_id));
            }
            input.insert(
                "scope".into(),
                Value::String(budget.scope.clone().unwrap_or_else(|| "shared".into())),
            );
            input.insert("period".into(), Value::String(budget.period.clone()));
            input.insert("maxTokens".into(), number_or_null(budget.max_tokens));
            input.insert("maxCostUsd".into(), number_or_null(budget.max_cost_usd));
            input.insert("maxRequests".into(), number_or_null(budget.max_requests));
            input.insert("models".into(), strings_or_null(&budget.models));
            input.insert(
                "alertAtPercent".into(),
                number_or_null(budget.alert_at_percent),
            );
            let record = item.get("record").and_then(Value::as_object);
            inference
                .save_budget(tx, principal, tenant_id, &input, record)
                .await?;
        }
    }
    if phase != "upsert" {
        for item in &plan.budgets {
            let (action, name) = change_of(item);
            if action == "delete" {
                env.allow
                    .allow(
                        "iam:inference:manage",
                        tenant_id,
                        &format!("delete budget {name}"),
                    )
                    .await?;
                inference
                    .delete_budget(tx, principal, &record_of(item)?)
                    .await?;
            }
        }
        for item in &plan.models {
            let (action, name) = change_of(item);
            if action == "delete" {
                env.allow
                    .allow(
                        "iam:inference:manage",
                        tenant_id,
                        &format!("delete model {name}"),
                    )
                    .await?;
                inference
                    .delete_model(tx, tenant_id, Some(&Value::String(name.to_owned())))
                    .await?;
            }
        }
        for item in &plan.agents {
            let (action, name) = change_of(item);
            if action == "delete" {
                let record = record_of(item)?;
                env.allow
                    .allow(
                        "iam:agents:delete",
                        member(&record, "id"),
                        &format!("delete agent {name}"),
                    )
                    .await?;
                // As `agents.delete`: removing an agent needs a fresh sign-in in person.
                ctx.auth.require_recent(principal)?;
                agents.delete_agent(tx, principal, &record).await?;
            }
        }
    }
    Ok(())
}
