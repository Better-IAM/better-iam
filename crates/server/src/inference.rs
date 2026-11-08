//! Port of `packages/server/src/inference.ts`.
//!
//! Inference access control: which people, service accounts and AI agents may call which AI models, how much they
//! may spend, and what they did. Models are defined per tenant and inherited by sub-tenants; each one is a resource
//! of type `model` that policies grant `inference:invoke` on (`model/claude-*`, conditions on `resource.tier`, ...).
//! Upstream provider keys are sealed with the deployment secret and only ever leave storage inside the server (the
//! gateway). Budgets cap tokens and cost per hour, day or month for a tenant, a group or one identity (an agent's
//! budget also covers the sessions in which it acts for people). Every call is metered.

use std::sync::{Arc, LazyLock};

use better_iam_auth::{decrypt_secret, encrypt_secret};
use better_iam_core::{
    AttributeType, AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions,
    IamError, IamPlugin, IamResult, IdentityKind, ResourceRef, ResourceTypeDefinition, SessionKind,
    match_pattern,
};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::context::{ServerContext, Store};
use crate::delegations::Delegation;
use crate::js::{self, cmp_utf16, invalid_input, is_safe_integer, js_string, number, type_of};
use crate::models::GroupMember;
use crate::options::{
    AuthorizationRequest, BetterIamOptions, InferenceOptions, ResolvedResource, ResourceTarget,
};
use crate::port::decode;
use crate::utils::id;
use crate::validation::{integer, text};

/// A budget's window. `minute` budgets are rate limits (requests or tokens per minute): `minute`, `hour`, `day` or
/// `month`.
pub type BudgetPeriod = String;

/// A budget as a check reports it: how much is left in the current window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BudgetStanding {
    #[serde(rename = "budgetId")]
    pub budget_id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "period")]
    pub period: crate::inference::BudgetPeriod,
    #[serde(rename = "windowStart")]
    pub window_start: f64,
    #[serde(rename = "resetsAt")]
    pub resets_at: f64,
    #[serde(rename = "usedTokens")]
    pub used_tokens: f64,
    #[serde(rename = "usedCostMicros")]
    pub used_cost_micros: f64,
    /// Calls metered in the window.
    #[serde(rename = "usedRequests")]
    pub used_requests: f64,
    #[serde(
        rename = "remainingTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub remaining_tokens: Option<f64>,
    #[serde(
        rename = "remainingCostMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub remaining_cost_micros: Option<f64>,
    #[serde(
        rename = "remainingRequests",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub remaining_requests: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A spending cap: tokens, cost and/or calls per period, for a tenant, a group or an identity, over some models.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceBudget {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    /// The tenant, group or identity the budget covers.
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    /// `shared`: one pool for everyone covered; `each`: every identity covered gets the full amount.
    #[serde(rename = "scope")]
    pub scope: String,
    #[serde(rename = "period")]
    pub period: crate::inference::BudgetPeriod,
    #[serde(rename = "maxTokens", default, skip_serializing_if = "Option::is_none")]
    pub max_tokens: Option<f64>,
    #[serde(
        rename = "maxCostMicros",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_cost_micros: Option<f64>,
    /// The most calls per window (a rate limit for agents that loop).
    #[serde(
        rename = "maxRequests",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_requests: Option<f64>,
    /// Model name patterns the budget counts (every model when absent).
    #[serde(rename = "models", default, skip_serializing_if = "Option::is_none")]
    pub models: Option<Vec<String>>,
    /// Emits `inference:budget-alert` once per window when usage crosses this share of a limit.
    #[serde(
        rename = "alertAtPercent",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub alert_at_percent: Option<f64>,
    /// Set by a platform (root) administrator: only a platform administrator may change or remove it.
    #[serde(rename = "platform", default, skip_serializing_if = "Option::is_none")]
    pub platform: Option<bool>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
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

/// Usage of one budget pool in one window.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceCounter {
    #[serde(rename = "budgetId")]
    pub budget_id: String,
    /// `shared`, or the identity for `each` budgets.
    #[serde(rename = "subjectKey")]
    pub subject_key: String,
    #[serde(rename = "windowStart")]
    pub window_start: f64,
    #[serde(rename = "windowEnd")]
    pub window_end: f64,
    #[serde(rename = "tokens")]
    pub tokens: f64,
    #[serde(rename = "costMicros")]
    pub cost_micros: f64,
    #[serde(rename = "requests")]
    pub requests: f64,
    #[serde(rename = "alerted", default, skip_serializing_if = "Option::is_none")]
    pub alerted: Option<bool>,
    #[serde(rename = "exceeded", default, skip_serializing_if = "Option::is_none")]
    pub exceeded: Option<bool>,
    /// When the retention sweep may delete the counter.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
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

/// A model people may call, under a public name, served by a provider of the same tenant or an ancestor.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceModel {
    /// The public model name (`uniqueKey`), used in requests and in policies as `model/{name}`.
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    /// The provider's own model name the gateway sends upstream.
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
    /// A free-form tier for policies, such as `frontier` or `small`.
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
    /// Prices in US dollars per million tokens; usage cost is metered in micro-dollars.
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
    /// Models the gateway tries, in order, when this one's provider is unreachable, rate limited or failing (at most
    /// 5): each only if the caller may use it and it speaks the same wire format.
    #[serde(rename = "fallbacks", default, skip_serializing_if = "Option::is_none")]
    pub fallbacks: Option<Vec<String>>,
    /// Tools the provider runs itself that a request may ask for (web search, code execution, remote MCP servers,
    /// computer use, ...): `allow` (unset) passes them, `deny` refuses any, `policy` checks `inference:use-tool` on
    /// each `model-tool/{kind}`. Tools the caller runs itself (functions) are never checked.
    #[serde(
        rename = "providerTools",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_tools: Option<String>,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
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

/// An upstream model provider account. The key is sealed; administrators see only its last four characters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceProvider {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "kind")]
    pub kind: crate::inference::ProviderKind,
    #[serde(rename = "baseUrl")]
    pub base_url: String,
    #[serde(rename = "keySealed")]
    pub key_sealed: String,
    #[serde(rename = "keyHint")]
    pub key_hint: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "keyRotatedAt")]
    pub key_rotated_at: f64,
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

/// Token counts reported for one call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceTokenUsage {
    #[serde(rename = "inputTokens")]
    pub input_tokens: f64,
    #[serde(rename = "outputTokens")]
    pub output_tokens: f64,
    #[serde(
        rename = "cacheReadTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_read_tokens: Option<f64>,
    #[serde(
        rename = "cacheWriteTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_write_tokens: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One metered model call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InferenceUsageRecord {
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(
        rename = "delegationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub delegation_id: Option<String>,
    #[serde(
        rename = "sessionKind",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_kind: Option<String>,
    #[serde(rename = "model")]
    pub model: String,
    #[serde(rename = "providerId")]
    pub provider_id: String,
    #[serde(rename = "inputTokens")]
    pub input_tokens: f64,
    #[serde(rename = "outputTokens")]
    pub output_tokens: f64,
    #[serde(
        rename = "cacheReadTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_read_tokens: Option<f64>,
    #[serde(
        rename = "cacheWriteTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_write_tokens: Option<f64>,
    #[serde(rename = "costMicros")]
    pub cost_micros: f64,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "latencyMs", default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
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

/// The outcome of an invocation check (never contains provider secrets): `{ allowed: true, model, budgets }`, or
/// `{ allowed: false, reason, model?, budget?, tool? }` with `reason` one of `ACCESS_DENIED`, `BUDGET_EXCEEDED`,
/// `MODEL_DISABLED` and `TOOL_NOT_ALLOWED`. The members are declared in the order TypeScript writes both shapes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvocationCheck {
    pub allowed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<PublicModel>,
    /// When allowed: the standing of every covering budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budgets: Option<Vec<BudgetStanding>>,
    /// For BUDGET_EXCEEDED: the exhausted budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<BudgetStanding>,
    /// For TOOL_NOT_ALLOWED: the first provider tool refused.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool: Option<String>,
}

impl InvocationCheck {
    fn denied(reason: &str, model: PublicModel) -> Self {
        Self {
            allowed: false,
            reason: Some(reason.to_owned()),
            model: Some(model),
            budgets: None,
            budget: None,
            tool: None,
        }
    }

    /// The check as TypeScript returns it (members in its order, JavaScript numbers).
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("allowed".into(), Value::Bool(self.allowed));
        if let Some(reason) = &self.reason {
            out.insert("reason".into(), Value::String(reason.clone()));
        }
        if let Some(model) = &self.model {
            out.insert("model".into(), model.to_json());
        }
        if let Some(budgets) = &self.budgets {
            out.insert(
                "budgets".into(),
                Value::Array(budgets.iter().map(BudgetStanding::to_json).collect()),
            );
        }
        if let Some(budget) = &self.budget {
            out.insert("budget".into(), budget.to_json());
        }
        if let Some(tool) = &self.tool {
            out.insert("tool".into(), Value::String(tool.clone()));
        }
        Value::Object(out)
    }
}

/// What a gateway reports after a call.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvocationRecord {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "model")]
    pub model: String,
    #[serde(rename = "status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "latencyMs", default, skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,
    /// The provider's Responses API response id, recorded as the caller's (gateway only).
    #[serde(
        rename = "responseId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub response_id: Option<String>,
    #[serde(rename = "inputTokens")]
    pub input_tokens: f64,
    #[serde(rename = "outputTokens")]
    pub output_tokens: f64,
    #[serde(
        rename = "cacheReadTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_read_tokens: Option<f64>,
    #[serde(
        rename = "cacheWriteTokens",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub cache_write_tokens: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A provider's secret material for the gateway: its kind, base URL and opened key. Server-side only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProviderCredential {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "kind")]
    pub kind: crate::inference::ProviderKind,
    #[serde(rename = "baseUrl")]
    pub base_url: String,
    #[serde(rename = "apiKey")]
    pub api_key: String,
    /// Set when an organization (not the platform) owns a provider with a custom base URL: upstream calls must go
    /// through the SSRF guard with these address rules, since the organization chose where they go.
    #[serde(rename = "guard", default, skip_serializing_if = "Option::is_none")]
    pub guard: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Upstream API families the gateway can pass requests to: `anthropic`, `openai` or `openai-compatible`.
pub type ProviderKind = String;

/// What a model allows of provider-run tools: any (`allow`, the default), none (`deny`), or those policies allow one
/// by one (`policy`).
pub type ProviderToolsMode = String;

/// Which provider serves a public model (`PublicModel.provider`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicModelProvider {
    pub id: String,
    pub name: String,
    pub kind: ProviderKind,
}

/// A model as callers see it: never the provider key, only which provider serves it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicModel {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "inherited")]
    pub inherited: bool,
    #[serde(rename = "provider")]
    pub provider: PublicModelProvider,
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
    #[serde(rename = "fallbacks", default, skip_serializing_if = "Option::is_none")]
    pub fallbacks: Option<Vec<String>>,
    /// Provider-run tools: `deny` or `policy` when set (see `InferenceModel.providerTools`).
    #[serde(
        rename = "providerTools",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub provider_tools: Option<String>,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl PublicModel {
    /// The model as TypeScript returns it: `name`, `tenantId`, `inherited`, `provider`, `upstreamModel`, `enabled`,
    /// then the optional members, `fallbacks` and `providerTools`.
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("name".into(), Value::String(self.name.clone()));
        out.insert("tenantId".into(), Value::String(self.tenant_id.clone()));
        out.insert("inherited".into(), Value::Bool(self.inherited));
        let mut provider = Map::new();
        provider.insert("id".into(), Value::String(self.provider.id.clone()));
        provider.insert("name".into(), Value::String(self.provider.name.clone()));
        provider.insert("kind".into(), Value::String(self.provider.kind.clone()));
        out.insert("provider".into(), Value::Object(provider));
        out.insert(
            "upstreamModel".into(),
            Value::String(self.upstream_model.clone()),
        );
        out.insert("enabled".into(), Value::Bool(self.enabled));
        let texts = [
            ("displayName", &self.display_name),
            ("family", &self.family),
            ("tier", &self.tier),
        ];
        for (key, value) in texts {
            if let Some(value) = value {
                out.insert(key.into(), Value::String(value.clone()));
            }
        }
        let numbers = [
            ("contextWindow", self.context_window),
            ("maxOutputTokens", self.max_output_tokens),
            ("inputPricePerMTok", self.input_price_per_m_tok),
            ("outputPricePerMTok", self.output_price_per_m_tok),
            ("cachedInputPricePerMTok", self.cached_input_price_per_m_tok),
        ];
        for (key, value) in numbers {
            if let Some(value) = value {
                out.insert(key.into(), number(value));
            }
        }
        if let Some(fallbacks) = &self.fallbacks {
            out.insert(
                "fallbacks".into(),
                Value::Array(fallbacks.iter().cloned().map(Value::String).collect()),
            );
        }
        if let Some(mode) = &self.provider_tools {
            out.insert("providerTools".into(), Value::String(mode.clone()));
        }
        for (key, value) in &self.extra {
            if !out.contains_key(key) {
                out.insert(key.clone(), value.clone());
            }
        }
        Value::Object(out)
    }
}

impl BudgetStanding {
    /// The standing as TypeScript returns it (JavaScript numbers).
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("budgetId".into(), Value::String(self.budget_id.clone()));
        out.insert("name".into(), Value::String(self.name.clone()));
        out.insert("period".into(), Value::String(self.period.clone()));
        out.insert("windowStart".into(), number(self.window_start));
        out.insert("resetsAt".into(), number(self.resets_at));
        out.insert("usedTokens".into(), number(self.used_tokens));
        out.insert("usedCostMicros".into(), number(self.used_cost_micros));
        out.insert("usedRequests".into(), number(self.used_requests));
        if let Some(value) = self.remaining_tokens {
            out.insert("remainingTokens".into(), number(value));
        }
        if let Some(value) = self.remaining_cost_micros {
            out.insert("remainingCostMicros".into(), number(value));
        }
        if let Some(value) = self.remaining_requests {
            out.insert("remainingRequests".into(), number(value));
        }
        Value::Object(out)
    }
}

impl InferenceTokenUsage {
    /// Token counts without cache reads or writes.
    pub fn new(input_tokens: f64, output_tokens: f64) -> Self {
        Self {
            input_tokens,
            output_tokens,
            cache_read_tokens: None,
            cache_write_tokens: None,
            extra: Map::new(),
        }
    }
}

/// The resource type and action the inference module adds to the permission catalog.
pub const INFERENCE_RESOURCE_TYPE: &str = "model";
pub const INFERENCE_ACTION: &str = "inference:invoke";
/// Tools the provider runs itself (web search, code execution, remote MCP servers, ...), as resources of this type
/// named by kind (`model-tool/web_search`, `model-tool/mcp:{host}`), checked with `inference:use-tool` for models
/// whose `providerTools` is `policy`.
pub const INFERENCE_TOOL_RESOURCE_TYPE: &str = "model-tool";
/// The action decided on each `model-tool/{kind}` a request asks for, for models whose `providerTools` is `policy`.
pub const INFERENCE_TOOL_ACTION: &str = "inference:use-tool";

pub const PROVIDER_TOOLS_MODES: &[&str] = &["allow", "deny", "policy"];
/// A provider tool id: its kind, or `mcp:{host}` / `mcp:{connector}` for remote MCP servers.
pub static PROVIDER_TOOL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9_.:-]{0,254}$").expect("pattern"));

pub const PROVIDER_KINDS: &[&str] = &["anthropic", "openai", "openai-compatible"];
/// The public endpoint of each kind; `openai-compatible` always needs a base URL.
pub const PROVIDER_BASE_URLS: &[(&str, Option<&str>)] = &[
    ("anthropic", Some("https://api.anthropic.com")),
    ("openai", Some("https://api.openai.com")),
    ("openai-compatible", None),
];

/// `providerBaseUrls[kind]`: the public endpoint of a provider kind (None for `openai-compatible` and unknown kinds).
pub fn provider_base_url(kind: &str) -> Option<&'static str> {
    PROVIDER_BASE_URLS
        .iter()
        .find(|(name, _)| *name == kind)
        .and_then(|(_, url)| *url)
}

/// Reads a list of provider tool ids (at most 64), deduplicated.
pub fn provider_tool_list(value: Option<&Value>) -> IamResult<Vec<String>> {
    let Some(Value::Array(items)) = value else {
        return Err(invalid_input("tools must be a list"));
    };
    let refused = || {
        invalid_input(
            "tools must list at most 64 provider tool ids (such as web_search or mcp:tools.example.com)",
        )
    };
    let mut tools: IndexSet<String> = IndexSet::new();
    let mut other = false;
    for item in items {
        match item {
            Value::String(tool) => {
                tools.insert(tool.clone());
            }
            _ => other = true,
        }
    }
    if other
        || tools.len() > 64
        || tools
            .iter()
            .any(|tool| !PROVIDER_TOOL_PATTERN.is_match(tool))
    {
        return Err(refused());
    }
    Ok(tools.into_iter().collect())
}

static MODEL_NAME_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$").expect("pattern"));
static RESPONSE_ID_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]{1,200}$").expect("pattern"));
const MINUTE: f64 = 60_000.0;
const HOUR: f64 = 3_600_000.0;
const DAY: f64 = 86_400_000.0;

/// `Math.round(x)` for the non-negative amounts metering computes (halves round up).
fn js_round(value: f64) -> f64 {
    let floor = value.floor();
    if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    }
}

/// Whether the deployment enabled inference (`inference` option).
pub fn inference_enabled(ctx: &ServerContext) -> bool {
    ctx.options
        .inference
        .as_ref()
        .is_some_and(|toggle| toggle.enabled())
}

/// The `inference` options object (empty when the option is `true`).
pub fn inference_settings(ctx: &ServerContext) -> InferenceOptions {
    ctx.options
        .inference
        .as_ref()
        .and_then(|toggle| toggle.options())
        .cloned()
        .unwrap_or_default()
}

/// Refuses inference calls on deployments that did not enable it.
pub fn assert_inference(ctx: &ServerContext) -> IamResult<()> {
    if !inference_enabled(ctx) {
        return Err(IamError::with_status(
            "FEATURE_DISABLED",
            "Inference is not enabled on this deployment",
            403,
        ));
    }
    Ok(())
}

/// The catalog entries of the inference module: the `model` and `model-tool` types.
struct InferencePlugin;

#[async_trait::async_trait]
impl IamPlugin for InferencePlugin {
    fn id(&self) -> &str {
        "better-iam:inference"
    }

    fn resource_types(&self) -> IndexMap<String, ResourceTypeDefinition> {
        let attributes = |items: &[(&str, AttributeType)]| {
            items
                .iter()
                .map(|(name, kind)| ((*name).to_owned(), *kind))
                .collect::<IndexMap<String, AttributeType>>()
        };
        let mut types = IndexMap::new();
        types.insert(
            INFERENCE_RESOURCE_TYPE.to_owned(),
            ResourceTypeDefinition {
                description: Some(
                    "An AI model callers may invoke through the inference gateway".to_owned(),
                ),
                actions: Some(vec![INFERENCE_ACTION.to_owned()]),
                attributes: Some(attributes(&[
                    ("provider", AttributeType::String),
                    ("providerKind", AttributeType::String),
                    ("upstreamModel", AttributeType::String),
                    ("family", AttributeType::String),
                    ("tier", AttributeType::String),
                    ("contextWindow", AttributeType::Number),
                    ("inputPricePerMTok", AttributeType::Number),
                    ("outputPricePerMTok", AttributeType::Number),
                    ("enabled", AttributeType::Boolean),
                ])),
                ..ResourceTypeDefinition::default()
            },
        );
        types.insert(
            INFERENCE_TOOL_RESOURCE_TYPE.to_owned(),
            ResourceTypeDefinition {
                description: Some(
                    "A tool the model provider runs itself (web search, code execution, a remote MCP server, ...)"
                        .to_owned(),
                ),
                actions: Some(vec![INFERENCE_TOOL_ACTION.to_owned()]),
                attributes: Some(attributes(&[
                    ("kind", AttributeType::String),
                    ("host", AttributeType::String),
                ])),
                ..ResourceTypeDefinition::default()
            },
        );
        types
    }
}

/// The catalog entries the module contributes when enabled: the `model` type and `inference:invoke`. The options are
/// validated here, once, at construction (as TypeScript reads them: the options model keeps values a Rust type could
/// not hold).
pub fn inference_plugins(options: &BetterIamOptions) -> IamResult<Vec<Arc<dyn IamPlugin>>> {
    let model = crate::options_value::options_value(options);
    let inference = js::member(Some(&model), "inference");
    if !js::truthy(inference) {
        return Ok(Vec::new());
    }
    let inference = inference.expect("truthy");
    if type_of(inference) == "object" {
        let days = js::member(Some(inference), "usageRetentionDays");
        if let Some(days) = days {
            let valid = js::as_number(days)
                .is_some_and(|days| is_safe_integer(days) && (1.0..=3650.0).contains(&days));
            if !valid {
                return Err(IamError::new(
                    "INVALID_CONFIG",
                    "inference.usageRetentionDays must be 1 to 3650",
                ));
            }
        }
        for key in [
            "allowCustomBaseUrls",
            "allowInsecureLocalhost",
            "allowPrivateNetworks",
        ] {
            if let Some(value) = js::member(Some(inference), key)
                && !value.is_boolean()
            {
                return Err(IamError::new(
                    "INVALID_CONFIG",
                    format!("inference.{key} must be a boolean"),
                ));
            }
        }
    } else if inference != &Value::Bool(true) {
        return Err(IamError::new(
            "INVALID_CONFIG",
            "inference must be true or an options object",
        ));
    }
    Ok(vec![Arc::new(InferencePlugin)])
}

/// A public model name.
pub fn model_name(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(name)) if MODEL_NAME_PATTERN.is_match(name) => Ok(name.clone()),
        _ => Err(invalid_input(
            "Model names use 1-128 letters, digits or ._:/@+- characters and start with a letter or digit",
        )),
    }
}

/// A non-negative price in dollars per million tokens (at most 10 000).
pub fn price(value: Option<&Value>, name: &str) -> IamResult<f64> {
    match value.and_then(js::as_number) {
        Some(price) if price.is_finite() && (0.0..=10_000.0).contains(&price) => Ok(price),
        _ => Err(invalid_input(format!(
            "{name} must be a price from 0 to 10000 dollars per million tokens"
        ))),
    }
}

/// The encryption context of a provider's key: binds the ciphertext to its record.
pub fn provider_key_context(provider_id: &str) -> String {
    format!("inference-provider:{provider_id}")
}

/// Seals a provider key for storage with the current deployment secret.
pub fn seal_provider_key(secret: &str, provider_id: &str, key: &str) -> String {
    encrypt_secret(key, secret, &provider_key_context(provider_id))
}

/// Opens a provider's sealed key with the current secret or any previous one (`rotateSecrets` re-seals).
pub fn open_provider_key(ctx: &ServerContext, provider: &InferenceProvider) -> IamResult<String> {
    let mut secrets = vec![ctx.options.secret.clone()];
    secrets.extend(ctx.options.previous_secrets.clone().unwrap_or_default());
    decrypt_secret(
        &provider.key_sealed,
        &secrets,
        &provider_key_context(&provider.id),
    )
}

/// A provider key: 8 to 4096 printable characters without whitespace.
pub fn provider_key(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(key))
            if (8..=4096).contains(&js::utf16_len(key)) && !js::has_js_whitespace(key) =>
        {
            Ok(key.clone())
        }
        _ => Err(invalid_input(
            "apiKey must be 8-4096 characters without whitespace",
        )),
    }
}

/// A provider base URL: https without credentials, query or fragment (http on loopback only with
/// `allowInsecureLocalhost`); the trailing slash is removed.
pub fn base_url(value: Option<&Value>, settings: &InferenceOptions) -> IamResult<String> {
    let raw = text(value, "baseUrl", 2048)?;
    let url =
        url::Url::parse(&raw).map_err(|_| invalid_input("baseUrl must be an absolute URL"))?;
    let hostname = url.host_str().unwrap_or("");
    let loopback = ["localhost", "127.0.0.1", "[::1]"].contains(&hostname);
    let secure = url.scheme() == "https"
        || (url.scheme() == "http" && loopback && settings.allow_insecure_localhost == Some(true));
    if !url.username().is_empty()
        || url.password().is_some_and(|password| !password.is_empty())
        || url.query().is_some_and(|query| !query.is_empty())
        || url.fragment().is_some_and(|fragment| !fragment.is_empty())
        || !secure
    {
        return Err(invalid_input(
            "baseUrl must be an https URL without credentials or query",
        ));
    }
    Ok(url.as_str().trim_end_matches('/').to_owned())
}

/// The tenant and its ancestors, nearest first, for inherited models and providers.
async fn realm_chain(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Vec<better_iam_core::Tenant>> {
    let tenant = ctx.tenant(tx, tenant_id).await?;
    ctx.ancestry(tx, &tenant).await
}

/// A provider visible from a tenant: its own or an ancestor's.
pub async fn visible_provider(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    provider_id: &str,
) -> IamResult<Option<InferenceProvider>> {
    let Some(record) = tx.get("inferenceProviders", provider_id).await? else {
        return Ok(None);
    };
    let provider: InferenceProvider = decode(record)?;
    let chain = realm_chain(ctx, tx, tenant_id).await?;
    Ok(chain
        .iter()
        .any(|realm| realm.id == provider.tenant_id)
        .then_some(provider))
}

/// Every provider a tenant may use (its own and its ancestors'), nearest first.
pub async fn visible_providers(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Vec<InferenceProvider>> {
    let mut providers = Vec::new();
    for realm in realm_chain(ctx, tx, tenant_id).await? {
        for record in tx
            .find(
                "inferenceProviders",
                &Filter::new().eq("tenantId", realm.id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            providers.push(decode::<InferenceProvider>(record)?);
        }
    }
    Ok(providers)
}

/// A model definition with the provider that serves it (absent when the provider is gone or not visible).
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedModel {
    pub model: InferenceModel,
    pub provider: Option<InferenceProvider>,
}

/// The nearest definition of a model name for a tenant (its own, else the closest ancestor's), with its provider.
pub async fn resolve_model(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    name: &str,
) -> IamResult<Option<ResolvedModel>> {
    for realm in realm_chain(ctx, tx, tenant_id).await? {
        let found = tx
            .find(
                "inferenceModels",
                &Filter::new()
                    .eq("tenantId", realm.id.clone())
                    .eq("uniqueKey", name),
                &FindOptions::default(),
            )
            .await?;
        if let Some(record) = found.into_iter().next() {
            let model: InferenceModel = decode(record)?;
            let provider = visible_provider(ctx, tx, &realm.id, &model.provider_id).await?;
            return Ok(Some(ResolvedModel { model, provider }));
        }
    }
    Ok(None)
}

/// Every model visible from a tenant: its own and inherited ones, the nearest definition of each name winning.
pub async fn visible_models(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
) -> IamResult<Vec<ResolvedModel>> {
    let mut seen: IndexMap<String, ResolvedModel> = IndexMap::new();
    for realm in realm_chain(ctx, tx, tenant_id).await? {
        for record in tx
            .find(
                "inferenceModels",
                &Filter::new().eq("tenantId", realm.id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            let model: InferenceModel = decode(record)?;
            if !seen.contains_key(&model.name) {
                let provider = visible_provider(ctx, tx, &realm.id, &model.provider_id).await?;
                seen.insert(model.name.clone(), ResolvedModel { model, provider });
            }
        }
    }
    let mut result: Vec<ResolvedModel> = seen.into_values().collect();
    result.sort_by(|a, b| crate::metrics::locale_compare(&a.model.name, &b.model.name));
    Ok(result)
}

/// A model as callers see it from `tenant_id`.
pub fn public_model(
    model: &InferenceModel,
    provider: Option<&InferenceProvider>,
    tenant_id: &str,
) -> PublicModel {
    PublicModel {
        name: model.name.clone(),
        tenant_id: model.tenant_id.clone(),
        inherited: model.tenant_id != tenant_id,
        provider: match provider {
            Some(provider) => PublicModelProvider {
                id: provider.id.clone(),
                name: provider.name.clone(),
                kind: provider.kind.clone(),
            },
            None => PublicModelProvider {
                id: model.provider_id.clone(),
                name: "(missing)".to_owned(),
                kind: "openai-compatible".to_owned(),
            },
        },
        upstream_model: model.upstream_model.clone(),
        display_name: model.display_name.clone(),
        family: model.family.clone(),
        tier: model.tier.clone(),
        context_window: model.context_window,
        max_output_tokens: model.max_output_tokens,
        input_price_per_m_tok: model.input_price_per_m_tok,
        output_price_per_m_tok: model.output_price_per_m_tok,
        cached_input_price_per_m_tok: model.cached_input_price_per_m_tok,
        fallbacks: model
            .fallbacks
            .as_ref()
            .filter(|fallbacks| !fallbacks.is_empty())
            .cloned(),
        provider_tools: model
            .provider_tools
            .as_ref()
            .filter(|mode| !mode.is_empty() && mode.as_str() != "allow")
            .cloned(),
        enabled: model.enabled && provider.is_some(),
        extra: Map::new(),
    }
}

/// A model as the policy engine sees it: `resource.provider`, `resource.tier`, `resource.inputPricePerMTok`, ...
fn model_attributes(
    model: &InferenceModel,
    provider: Option<&InferenceProvider>,
) -> Map<String, Value> {
    let mut attributes = Map::new();
    attributes.insert(
        "provider".into(),
        Value::String(provider.map(|p| p.name.clone()).unwrap_or_default()),
    );
    attributes.insert(
        "providerKind".into(),
        Value::String(provider.map(|p| p.kind.clone()).unwrap_or_default()),
    );
    attributes.insert(
        "upstreamModel".into(),
        Value::String(model.upstream_model.clone()),
    );
    attributes.insert(
        "enabled".into(),
        Value::Bool(model.enabled && provider.is_some()),
    );
    if let Some(family) = &model.family {
        attributes.insert("family".into(), Value::String(family.clone()));
    }
    if let Some(tier) = &model.tier {
        attributes.insert("tier".into(), Value::String(tier.clone()));
    }
    let numbers = [
        ("contextWindow", model.context_window),
        ("inputPricePerMTok", model.input_price_per_m_tok),
        ("outputPricePerMTok", model.output_price_per_m_tok),
    ];
    for (key, value) in numbers {
        if let Some(value) = value {
            attributes.insert(key.into(), number(value));
        }
    }
    attributes
}

/// The decision engine's resolver for `model/{name}` when inference is enabled: the nearest definition's
/// attributes. Undefined for other types (the caller resolves those); NOT_FOUND for a model the tenant cannot see.
pub async fn resolve_model_resource(
    ctx: &ServerContext,
    tx: &Store,
    reference: &ResourceRef,
) -> IamResult<Option<ResolvedResource>> {
    // Provider tools are named, not registered: `model-tool/{kind}` or `model-tool/mcp:{host}`.
    if reference.kind == INFERENCE_TOOL_RESOURCE_TYPE && inference_enabled(ctx) {
        if !PROVIDER_TOOL_PATTERN.is_match(&reference.id) {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "Unknown provider tool",
                404,
            ));
        }
        let mut attributes = Map::new();
        match reference.id.find(':').filter(|colon| *colon > 0) {
            Some(colon) => {
                attributes.insert(
                    "kind".into(),
                    Value::String(reference.id[..colon].to_owned()),
                );
                attributes.insert(
                    "host".into(),
                    Value::String(reference.id[colon + 1..].to_owned()),
                );
            }
            None => {
                attributes.insert("kind".into(), Value::String(reference.id.clone()));
            }
        }
        return Ok(Some(ResolvedResource {
            tenant_id: reference.tenant_id.clone(),
            kind: INFERENCE_TOOL_RESOURCE_TYPE.to_owned(),
            id: reference.id.clone(),
            attributes: Some(attributes),
            classification: None,
        }));
    }
    if reference.kind != INFERENCE_RESOURCE_TYPE || !inference_enabled(ctx) {
        return Ok(None);
    }
    let Some(found) = resolve_model(ctx, tx, &reference.tenant_id, &reference.id).await? else {
        return Err(IamError::with_status("NOT_FOUND", "Model not found", 404));
    };
    Ok(Some(ResolvedResource {
        tenant_id: reference.tenant_id.clone(),
        kind: INFERENCE_RESOURCE_TYPE.to_owned(),
        id: reference.id.clone(),
        attributes: Some(model_attributes(&found.model, found.provider.as_ref())),
        classification: None,
    }))
}

/// A budget window, as [start, end) in epoch milliseconds.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct BudgetWindow {
    pub start: f64,
    pub end: f64,
}

/// `Date.UTC(year, month, 1)` with `month` counted from 0 (12 rolls over into the next year).
fn month_start(year: i64, month: i64) -> f64 {
    let (year, month) = (year + month.div_euclid(12), month.rem_euclid(12));
    better_iam_core::js::days_from_civil(year, month + 1, 1) as f64 * DAY
}

/// The current window of a period (UTC), as [start, end).
pub fn budget_window(period: &str, now: f64) -> BudgetWindow {
    match period {
        "minute" => {
            let start = (now / MINUTE).floor() * MINUTE;
            BudgetWindow {
                start,
                end: start + MINUTE,
            }
        }
        "hour" => {
            let start = (now / HOUR).floor() * HOUR;
            BudgetWindow {
                start,
                end: start + HOUR,
            }
        }
        "day" => {
            let start = (now / DAY).floor() * DAY;
            BudgetWindow {
                start,
                end: start + DAY,
            }
        }
        _ => {
            let days = (now / DAY).floor() as i64;
            let (year, month, _) = better_iam_core::js::civil_from_days(days);
            BudgetWindow {
                start: month_start(year, month - 1),
                end: month_start(year, month),
            }
        }
    }
}

/// Cost of a call in micro-dollars: tokens × dollars per million tokens (cached input at its own price when set).
pub fn usage_cost(model: &InferenceModel, usage: &InferenceTokenUsage) -> f64 {
    let cached = usage.cache_read_tokens.unwrap_or(0.0);
    let input = model.input_price_per_m_tok.unwrap_or(0.0);
    let cost = usage.input_tokens * input
        + usage.cache_write_tokens.unwrap_or(0.0) * input
        + cached * model.cached_input_price_per_m_tok.unwrap_or(input)
        + usage.output_tokens * model.output_price_per_m_tok.unwrap_or(0.0);
    js_round(cost * 1000.0) / 1000.0
}

/// Tokens a budget counts for a call: input (including cache reads and writes) plus output.
pub fn usage_tokens(usage: &InferenceTokenUsage) -> f64 {
    usage.input_tokens
        + usage.output_tokens
        + usage.cache_read_tokens.unwrap_or(0.0)
        + usage.cache_write_tokens.unwrap_or(0.0)
}

/// Who a call is attributed to: the identity, the agent behind the credential, the delegation it acts under, and
/// the identity's groups.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct UsageSubject {
    pub tenant_id: String,
    pub identity_id: String,
    pub agent_id: Option<String>,
    pub delegation_id: Option<String>,
    /// For a hand-off: the agents that handed the work on, whose own budgets count the call too.
    pub chain_agent_ids: Option<Vec<String>>,
    pub group_ids: IndexSet<String>,
    /// In a delegated session: the groups of the acting agent (and of the agents that handed the work on), so a group
    /// budget on agents counts what they do for people as well as what they do with their own keys.
    pub agent_group_ids: Option<IndexSet<String>>,
}

/// The agent acting for a principal: a delegated session's agent, else the identity itself when it is an agent.
fn acting_agent(principal: &AuthenticatedPrincipal) -> Option<String> {
    if principal.session.kind == SessionKind::Delegated {
        principal.session.agent_id.clone()
    } else if principal.identity.kind == IdentityKind::Agent {
        Some(principal.identity.id.clone())
    } else {
        None
    }
}

async fn live_group_ids(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    into: &mut IndexSet<String>,
) -> IamResult<()> {
    for record in tx
        .find(
            "groupMembers",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("identityId", identity_id),
            &FindOptions::default(),
        )
        .await?
    {
        let member: GroupMember = decode(record)?;
        if ctx.live_membership(&member) {
            into.insert(member.group_id.clone());
        }
    }
    Ok(())
}

/// The subject of a principal's calls in `tenantId`.
pub async fn usage_subject(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> IamResult<UsageSubject> {
    let mut group_ids = IndexSet::new();
    live_group_ids(ctx, tx, tenant_id, &principal.identity.id, &mut group_ids).await?;
    let agent_id = acting_agent(principal);
    let delegated = principal.session.kind == SessionKind::Delegated;
    let delegation_id = if delegated {
        principal.session.delegation_id.clone()
    } else {
        None
    };
    let chain = match &delegation_id {
        Some(delegation_id) => match tx.get("delegations", delegation_id).await? {
            Some(record) => decode::<Delegation>(record)?.chain,
            None => None,
        },
        None => None,
    };
    let mut agent_group_ids = IndexSet::new();
    if delegated {
        let acting = agent_id
            .iter()
            .chain(chain.iter().flatten())
            .cloned()
            .collect::<Vec<_>>();
        for acting_id in acting {
            live_group_ids(ctx, tx, tenant_id, &acting_id, &mut agent_group_ids).await?;
        }
    }
    Ok(UsageSubject {
        tenant_id: tenant_id.to_owned(),
        identity_id: principal.identity.id.clone(),
        agent_id,
        delegation_id,
        chain_agent_ids: chain.filter(|chain| !chain.is_empty()),
        group_ids,
        agent_group_ids: (!agent_group_ids.is_empty()).then_some(agent_group_ids),
    })
}

/// A delegation's spending cap (`Delegation.spend`) as a budget: one shared pool per window, over every model, whose
/// counters are kept under the id `delegation:{delegationId}`. None for a delegation without a cap.
pub fn delegation_budget(delegation: &Delegation) -> Option<InferenceBudget> {
    let spend = delegation.spend.as_ref()?;
    Some(InferenceBudget {
        name: "Delegation spending limit".to_owned(),
        subject_type: "identity".to_owned(),
        subject_id: delegation.subject_id.clone(),
        scope: "shared".to_owned(),
        period: spend.period.clone(),
        max_tokens: spend.max_tokens,
        max_cost_micros: spend.max_cost_micros,
        max_requests: spend.max_requests,
        models: None,
        alert_at_percent: None,
        platform: None,
        created_at: delegation.created_at,
        updated_at: delegation.decided_at.unwrap_or(delegation.created_at),
        id: format!("delegation:{}", delegation.id),
        tenant_id: delegation.tenant_id.clone(),
        unique_key: None,
        extra: Map::new(),
    })
}

/// How much of a delegation's spending cap is used in the current window (undefined without a cap).
pub async fn delegation_spend_standing(
    tx: &Store,
    delegation: &Delegation,
    now: f64,
) -> IamResult<Option<BudgetStanding>> {
    let Some(budget) = delegation_budget(delegation) else {
        return Ok(None);
    };
    let window = budget_window(&budget.period, now);
    let counter = read_counter(tx, &counter_id(&budget.id, "shared", window.start)).await?;
    Ok(Some(standing_of(&budget, &window, counter.as_ref())))
}

/// The budgets that cover a subject's use of a model, with the counter key each one uses.
async fn covering_budgets(
    tx: &Store,
    subject: &UsageSubject,
    model: &str,
) -> IamResult<Vec<(InferenceBudget, String)>> {
    let mut covering = Vec::new();
    for record in tx
        .find(
            "inferenceBudgets",
            &Filter::new().eq("tenantId", subject.tenant_id.clone()),
            &FindOptions::default(),
        )
        .await?
    {
        let budget: InferenceBudget = decode(record)?;
        if let Some(models) = budget.models.as_ref().filter(|models| !models.is_empty())
            && !models
                .iter()
                .any(|pattern| match_pattern(pattern, model, None))
        {
            continue;
        }
        let via_agent_group = budget.subject_type == "group"
            && !subject.group_ids.contains(&budget.subject_id)
            && subject
                .agent_group_ids
                .as_ref()
                .is_some_and(|ids| ids.contains(&budget.subject_id));
        let covers = match budget.subject_type.as_str() {
            "tenant" => budget.subject_id == subject.tenant_id,
            "group" => subject.group_ids.contains(&budget.subject_id) || via_agent_group,
            _ => {
                budget.subject_id == subject.identity_id
                    || subject.agent_id.as_deref() == Some(budget.subject_id.as_str())
                    // An agent's budget also counts the work it handed on to other agents.
                    || subject
                        .chain_agent_ids
                        .as_ref()
                        .is_some_and(|chain| chain.contains(&budget.subject_id))
            }
        };
        if !covers {
            continue;
        }
        // An identity budget on an agent counts everything the agent does, for anyone; a per-identity group budget
        // that covers the call through the agent's group counts it against the agent.
        let subject_key = if budget.subject_type == "identity" || budget.scope == "shared" {
            "shared".to_owned()
        } else if let Some(agent_id) = subject
            .agent_id
            .as_ref()
            .filter(|agent| via_agent_group && !agent.is_empty())
        {
            agent_id.clone()
        } else {
            subject.identity_id.clone()
        };
        covering.push((budget, subject_key));
    }
    // The person's spending caps on the delegation the call is made under and on every delegation above it
    // (hand-offs).
    let mut delegation_id = subject.delegation_id.clone();
    let mut depth = 0;
    while let Some(current) = delegation_id.take() {
        if depth > 3 {
            break;
        }
        let Some(record) = tx.get("delegations", &current).await? else {
            break;
        };
        let delegation: Delegation = decode(record)?;
        if let Some(budget) = delegation_budget(&delegation) {
            covering.push((budget, "shared".to_owned()));
        }
        delegation_id = delegation.parent_id.clone();
        depth += 1;
    }
    covering.sort_by(|a, b| cmp_utf16(&a.0.id, &b.0.id));
    Ok(covering)
}

fn counter_id(budget_id: &str, subject_key: &str, window_start: f64) -> String {
    format!(
        "{budget_id}:{subject_key}:{}",
        js::number_to_string(window_start)
    )
}

async fn read_counter(tx: &Store, key: &str) -> IamResult<Option<InferenceCounter>> {
    match tx.get("inferenceCounters", key).await? {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

/// A budget's standing in a window, from its counter (absent: nothing used yet).
pub fn standing_of(
    budget: &InferenceBudget,
    window: &BudgetWindow,
    counter: Option<&InferenceCounter>,
) -> BudgetStanding {
    let used_tokens = counter.map_or(0.0, |counter| counter.tokens);
    let used_cost_micros = counter.map_or(0.0, |counter| counter.cost_micros);
    let used_requests = counter.map_or(0.0, |counter| counter.requests);
    BudgetStanding {
        budget_id: budget.id.clone(),
        name: budget.name.clone(),
        period: budget.period.clone(),
        window_start: window.start,
        resets_at: window.end,
        used_tokens,
        used_cost_micros,
        used_requests,
        remaining_tokens: budget.max_tokens.map(|max| (max - used_tokens).max(0.0)),
        remaining_cost_micros: budget
            .max_cost_micros
            .map(|max| (max - used_cost_micros).max(0.0)),
        remaining_requests: budget
            .max_requests
            .map(|max| (max - used_requests).max(0.0)),
        extra: Map::new(),
    }
}

/// A budget covering a subject's use of a model, with its counter key and its standing in the current window.
#[derive(Debug, Clone, PartialEq)]
pub struct CoveringBudget {
    pub budget: InferenceBudget,
    pub subject_key: String,
    pub standing: BudgetStanding,
}

/// The standing of every budget covering a subject's use of a model, in the current windows.
pub async fn budget_standings(
    ctx: &ServerContext,
    tx: &Store,
    subject: &UsageSubject,
    model: &str,
) -> IamResult<Vec<CoveringBudget>> {
    let now = ctx.now();
    let mut result = Vec::new();
    for (budget, subject_key) in covering_budgets(tx, subject, model).await? {
        let window = budget_window(&budget.period, now);
        let counter = read_counter(tx, &counter_id(&budget.id, &subject_key, window.start)).await?;
        let standing = standing_of(&budget, &window, counter.as_ref());
        result.push(CoveringBudget {
            budget,
            subject_key,
            standing,
        });
    }
    Ok(result)
}

fn decision_request(tenant_id: &str, action: &str, kind: &str, id: &str) -> AuthorizationRequest {
    AuthorizationRequest {
        credential: CredentialInput::default(),
        tenant_id: tenant_id.to_owned(),
        action: action.to_owned(),
        resource: ResourceTarget {
            kind: kind.to_owned(),
            id: id.to_owned(),
        },
    }
}

/// `input.tenantId` as TypeScript passes it on to `ctx.tenant` (which refuses anything but a valid ID).
fn input_tenant(input: &Value) -> IamResult<String> {
    text(input.get("tenantId"), "tenantId", 256)
}

/// Whether a principal may call a model now: the model must be visible and enabled, `inference:invoke` on
/// `model/{name}` must be allowed (denials are audited like any decision), and no covering budget may be exhausted
/// (`estimatedTokens`, when given, must fit in what remains, priced at the model's input price). The first refusal
/// of a budget in a window is audited as `inference:budget-exceeded`.
///
/// `input` is `{ tenantId, model, estimatedTokens?, tools? }` as the caller received it.
pub async fn check_invocation(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    input: &Value,
) -> IamResult<InvocationCheck> {
    assert_inference(ctx)?;
    let name = model_name(input.get("model"))?;
    let estimate = match input.get("estimatedTokens") {
        None => 0.0,
        Some(value) => integer(Some(value), "estimatedTokens", 0.0, 100_000_000.0)?,
    };
    let tools = match input.get("tools") {
        None => Vec::new(),
        Some(value) => provider_tool_list(Some(value))?,
    };
    let tenant_id = input_tenant(input)?;
    let Some(found) = resolve_model(ctx, tx, &tenant_id, &name).await? else {
        return Err(IamError::with_status("NOT_FOUND", "Model not found", 404));
    };
    let model = public_model(&found.model, found.provider.as_ref(), &tenant_id);
    let decision = ctx
        .operations()?
        .recorded_decision(
            tx,
            principal,
            &decision_request(&tenant_id, INFERENCE_ACTION, INFERENCE_RESOURCE_TYPE, &name),
        )
        .await?;
    if !decision.allowed {
        return Ok(InvocationCheck::denied("ACCESS_DENIED", model));
    }
    if !model.enabled {
        return Ok(InvocationCheck::denied("MODEL_DISABLED", model));
    }
    // Provider-run tools the request asks for, by the model's setting.
    let mode = found
        .model
        .provider_tools
        .clone()
        .filter(|mode| !mode.is_empty())
        .unwrap_or_else(|| "allow".to_owned());
    let asked: &[String] = if mode == "allow" { &[] } else { &tools };
    for tool in asked {
        let mut allowed = false;
        if mode == "policy" {
            allowed = ctx
                .operations()?
                .recorded_decision(
                    tx,
                    principal,
                    &decision_request(
                        &tenant_id,
                        INFERENCE_TOOL_ACTION,
                        INFERENCE_TOOL_RESOURCE_TYPE,
                        tool,
                    ),
                )
                .await?
                .allowed;
        } else {
            // Refused by the model itself: audited like a denied decision.
            let mut metadata = Map::new();
            metadata.insert("model".into(), Value::String(name.clone()));
            metadata.insert("providerTools".into(), Value::String("deny".into()));
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    INFERENCE_TOOL_ACTION,
                    &tenant_id,
                    &format!("{INFERENCE_TOOL_RESOURCE_TYPE}/{tool}"),
                    AuditOutcome::Deny,
                    false,
                    Some(metadata),
                )
                .await?;
        }
        if !allowed {
            let mut check = InvocationCheck::denied("TOOL_NOT_ALLOWED", model);
            check.tool = Some(tool.clone());
            return Ok(check);
        }
    }
    let subject = usage_subject(ctx, tx, principal, &tenant_id).await?;
    let estimate_cost = usage_cost(&found.model, &InferenceTokenUsage::new(estimate, 0.0));
    let mut budgets = Vec::new();
    for CoveringBudget {
        budget,
        subject_key,
        standing: current,
    } in budget_standings(ctx, tx, &subject, &name).await?
    {
        let over_tokens = budget
            .max_tokens
            .is_some_and(|max| current.used_tokens + estimate > max);
        let over_cost = budget
            .max_cost_micros
            .is_some_and(|max| current.used_cost_micros + estimate_cost > max);
        let exhausted = budget
            .max_tokens
            .is_some_and(|max| current.used_tokens >= max)
            || budget
                .max_cost_micros
                .is_some_and(|max| current.used_cost_micros >= max)
            || budget
                .max_requests
                .is_some_and(|max| current.used_requests >= max);
        if over_tokens || over_cost || exhausted {
            note_exceeded(ctx, tx, principal, &budget, &subject_key, &current).await?;
            let mut check = InvocationCheck::denied("BUDGET_EXCEEDED", model);
            check.budget = Some(current);
            return Ok(check);
        }
        budgets.push(current);
    }
    Ok(InvocationCheck {
        allowed: true,
        reason: None,
        model: Some(model),
        budgets: Some(budgets),
        budget: None,
        tool: None,
    })
}

/// Audits the first refusal of a budget in a window (`inference:budget-exceeded`) and marks the counter.
async fn note_exceeded(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    budget: &InferenceBudget,
    subject_key: &str,
    current: &BudgetStanding,
) -> IamResult<()> {
    let key = counter_id(&budget.id, subject_key, current.window_start);
    let counter = tx.get("inferenceCounters", &key).await?;
    if let Some(counter) = &counter
        && js::truthy(counter.get("exceeded"))
    {
        return Ok(());
    }
    match counter {
        Some(mut next) => {
            next.insert("exceeded".into(), Value::Bool(true));
            tx.put("inferenceCounters", &next).await?;
        }
        None => {
            let mut next = Map::new();
            next.insert("id".into(), Value::String(key.clone()));
            next.insert("tenantId".into(), Value::String(budget.tenant_id.clone()));
            next.insert("budgetId".into(), Value::String(budget.id.clone()));
            next.insert("subjectKey".into(), Value::String(subject_key.to_owned()));
            next.insert("windowStart".into(), number(current.window_start));
            next.insert("windowEnd".into(), number(current.resets_at));
            next.insert("tokens".into(), number(0.0));
            next.insert("costMicros".into(), number(0.0));
            next.insert("requests".into(), number(0.0));
            next.insert("exceeded".into(), Value::Bool(true));
            next.insert("expiresAt".into(), number(current.resets_at + 35.0 * DAY));
            tx.insert("inferenceCounters", &next).await?;
        }
    }
    let mut metadata = Map::new();
    metadata.insert("budget".into(), Value::String(budget.name.clone()));
    metadata.insert("period".into(), Value::String(budget.period.clone()));
    metadata.insert("windowStart".into(), number(current.window_start));
    ctx.events()?
        .audit(
            tx,
            principal,
            "inference:budget-exceeded",
            &budget.tenant_id,
            &budget.id,
            AuditOutcome::Deny,
            false,
            Some(metadata),
        )
        .await
}

fn response_record_id(tenant_id: &str, response_id: &str) -> String {
    format!("{tenant_id}:{response_id}")
}

/// Whether `responseId` was created through the gateway in `tenantId` by the same caller as `principal`, at the
/// provider `providerId` (so a provider that echoes someone else's response id cannot claim it for another
/// provider's key).
pub async fn owns_inference_response(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    response_id: &str,
    provider_id: &str,
) -> IamResult<bool> {
    if !RESPONSE_ID_PATTERN.is_match(response_id) {
        return Ok(false);
    }
    let Some(record) = tx
        .get(
            "inferenceResponses",
            &response_record_id(tenant_id, response_id),
        )
        .await?
    else {
        return Ok(false);
    };
    let string = |key: &str| record.get(key).and_then(Value::as_str);
    let expires_at = record.get("expiresAt").and_then(js::as_number);
    if string("tenantId") != Some(tenant_id)
        || string("providerId") != Some(provider_id)
        || expires_at.is_some_and(|expires| expires <= ctx.now())
    {
        return Ok(false);
    }
    let agent_id = acting_agent(principal);
    Ok(string("identityId") == Some(principal.identity.id.as_str())
        && record.get("agentId") == agent_id.map(Value::String).as_ref())
}

/// Meters one call: stores a usage record (cost from the model's prices) and adds it to every covering budget's
/// counter. A counter crossing a budget's `alertAtPercent` is audited once per window as `inference:budget-alert`.
///
/// `input` is an `InvocationRecord` (`{ tenantId, model, inputTokens, outputTokens, cacheReadTokens?,
/// cacheWriteTokens?, status?, requestId?, latencyMs?, responseId? }`) as the caller received it.
pub async fn record_invocation(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    input: &Value,
) -> IamResult<InferenceUsageRecord> {
    assert_inference(ctx)?;
    let name = model_name(input.get("model"))?;
    let limit = 100_000_000.0;
    let mut usage = InferenceTokenUsage::new(
        integer(input.get("inputTokens"), "inputTokens", 0.0, limit)?,
        integer(input.get("outputTokens"), "outputTokens", 0.0, limit)?,
    );
    if let Some(value) = input.get("cacheReadTokens") {
        usage.cache_read_tokens = Some(integer(Some(value), "cacheReadTokens", 0.0, limit)?);
    }
    if let Some(value) = input.get("cacheWriteTokens") {
        usage.cache_write_tokens = Some(integer(Some(value), "cacheWriteTokens", 0.0, limit)?);
    }
    let tenant_id = input_tenant(input)?;
    let Some(found) = resolve_model(ctx, tx, &tenant_id, &name).await? else {
        return Err(IamError::with_status("NOT_FOUND", "Model not found", 404));
    };
    let now = ctx.now();
    let subject = usage_subject(ctx, tx, principal, &tenant_id).await?;
    let retention_days = inference_settings(ctx).usage_retention_days.unwrap_or(90.0);
    let cost_micros = usage_cost(&found.model, &usage);
    let expires_at = now + retention_days * DAY;
    let record_id = id();
    let mut record = Map::new();
    record.insert("id".into(), Value::String(record_id.clone()));
    record.insert("tenantId".into(), Value::String(tenant_id.clone()));
    record.insert(
        "identityId".into(),
        Value::String(principal.identity.id.clone()),
    );
    record.insert(
        "sessionKind".into(),
        Value::String(principal.session.kind.as_str().to_owned()),
    );
    record.insert("model".into(), Value::String(name.clone()));
    record.insert(
        "providerId".into(),
        Value::String(found.model.provider_id.clone()),
    );
    record.insert("inputTokens".into(), number(usage.input_tokens));
    record.insert("outputTokens".into(), number(usage.output_tokens));
    if let Some(tokens) = usage.cache_read_tokens {
        record.insert("cacheReadTokens".into(), number(tokens));
    }
    if let Some(tokens) = usage.cache_write_tokens {
        record.insert("cacheWriteTokens".into(), number(tokens));
    }
    record.insert("costMicros".into(), number(cost_micros));
    let status = if input.get("status") == Some(&Value::String("error".into())) {
        "error"
    } else {
        "ok"
    };
    record.insert("status".into(), Value::String(status.into()));
    record.insert("createdAt".into(), number(now));
    record.insert("expiresAt".into(), number(expires_at));
    if let Some(agent_id) = subject.agent_id.as_ref().filter(|agent| !agent.is_empty()) {
        record.insert("agentId".into(), Value::String(agent_id.clone()));
    }
    if let Some(delegation_id) = &principal.session.delegation_id {
        record.insert("delegationId".into(), Value::String(delegation_id.clone()));
    }
    if let Some(value) = input.get("requestId") {
        record.insert(
            "requestId".into(),
            Value::String(text(Some(value), "requestId", 128)?),
        );
    }
    if let Some(value) = input.get("latencyMs") {
        record.insert(
            "latencyMs".into(),
            number(integer(Some(value), "latencyMs", 0.0, 86_400_000.0)?),
        );
    }
    tx.insert("inferenceUsage", &record).await?;
    // A Responses API response belongs to whoever created it first; ids are the provider's and never reused.
    if let Some(response_id) = input.get("responseId") {
        let response_text = js_string(Some(response_id));
        if RESPONSE_ID_PATTERN.is_match(&response_text) {
            let key = response_record_id(&tenant_id, &response_text);
            if tx.get("inferenceResponses", &key).await?.is_none() {
                let mut response = Map::new();
                response.insert("id".into(), Value::String(key));
                response.insert("tenantId".into(), Value::String(tenant_id.clone()));
                response.insert("responseId".into(), response_id.clone());
                response.insert(
                    "identityId".into(),
                    Value::String(principal.identity.id.clone()),
                );
                if let Some(agent_id) = acting_agent(principal) {
                    response.insert("agentId".into(), Value::String(agent_id));
                }
                response.insert("model".into(), Value::String(name.clone()));
                response.insert(
                    "providerId".into(),
                    Value::String(found.model.provider_id.clone()),
                );
                response.insert("createdAt".into(), number(now));
                response.insert("expiresAt".into(), number(expires_at));
                tx.insert("inferenceResponses", &response).await?;
            }
        }
    }
    // The spend ledger (billing-service.ts), in the same transaction; it never throws and is idempotent on sourceId.
    if let Some(billing) = ctx.billing() {
        let mut priced = Map::new();
        priced.insert("tenantId".into(), Value::String(tenant_id.clone()));
        priced.insert("meter".into(), Value::String("inference".into()));
        priced.insert("costMicros".into(), number(cost_micros));
        priced.insert(
            "quantity".into(),
            number(usage.input_tokens + usage.output_tokens),
        );
        priced.insert(
            "identityId".into(),
            Value::String(principal.identity.id.clone()),
        );
        if let Some(agent_id) = record.get("agentId") {
            priced.insert("agentId".into(), agent_id.clone());
        }
        let mut tags = Map::new();
        tags.insert("model".into(), Value::String(name.clone()));
        tags.insert(
            "provider".into(),
            Value::String(found.model.provider_id.clone()),
        );
        priced.insert("tags".into(), Value::Object(tags));
        priced.insert("sourceId".into(), Value::String(record_id.clone()));
        billing.record_priced(tx, &Value::Object(priced)).await;
    }
    let tokens = usage_tokens(&usage);
    for CoveringBudget {
        budget,
        subject_key,
        standing: current,
    } in budget_standings(ctx, tx, &subject, &name).await?
    {
        let key = counter_id(&budget.id, &subject_key, current.window_start);
        let counter = read_counter(tx, &key).await?;
        let next_tokens = counter.as_ref().map_or(0.0, |counter| counter.tokens) + tokens;
        let next_cost = js_round(
            (counter.as_ref().map_or(0.0, |counter| counter.cost_micros) + cost_micros) * 1000.0,
        ) / 1000.0;
        let next_requests = counter.as_ref().map_or(0.0, |counter| counter.requests) + 1.0;
        let was_alerted = counter
            .as_ref()
            .is_some_and(|counter| counter.alerted == Some(true));
        let mut next = Map::new();
        next.insert("id".into(), Value::String(key.clone()));
        next.insert("tenantId".into(), Value::String(budget.tenant_id.clone()));
        next.insert("budgetId".into(), Value::String(budget.id.clone()));
        next.insert("subjectKey".into(), Value::String(subject_key.clone()));
        next.insert("windowStart".into(), number(current.window_start));
        next.insert("windowEnd".into(), number(current.resets_at));
        next.insert("tokens".into(), number(next_tokens));
        next.insert("costMicros".into(), number(next_cost));
        next.insert("requests".into(), number(next_requests));
        next.insert("expiresAt".into(), number(current.resets_at + 35.0 * DAY));
        if was_alerted {
            next.insert("alerted".into(), Value::Bool(true));
        }
        if counter
            .as_ref()
            .is_some_and(|counter| counter.exceeded == Some(true))
        {
            next.insert("exceeded".into(), Value::Bool(true));
        }
        let crossed = match budget.alert_at_percent {
            Some(threshold) if !was_alerted => {
                budget
                    .max_tokens
                    .is_some_and(|max| next_tokens * 100.0 >= max * threshold)
                    || budget
                        .max_cost_micros
                        .is_some_and(|max| next_cost * 100.0 >= max * threshold)
                    || budget
                        .max_requests
                        .is_some_and(|max| next_requests * 100.0 >= max * threshold)
            }
            _ => false,
        };
        if crossed {
            next.insert("alerted".into(), Value::Bool(true));
        }
        if counter.is_some() {
            tx.put("inferenceCounters", &next).await?;
        } else {
            tx.insert("inferenceCounters", &next).await?;
        }
        if crossed {
            let mut metadata = Map::new();
            metadata.insert("budget".into(), Value::String(budget.name.clone()));
            metadata.insert(
                "percent".into(),
                number(budget.alert_at_percent.unwrap_or_default()),
            );
            metadata.insert("period".into(), Value::String(budget.period.clone()));
            metadata.insert("usedTokens".into(), number(next_tokens));
            metadata.insert("usedCostMicros".into(), number(next_cost));
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    "inference:budget-alert",
                    &budget.tenant_id,
                    &budget.id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await?;
        }
    }
    decode(record)
}

/// A provider's secret material for the gateway: its kind, base URL and opened key. Server-side only. `guard` is set
/// (`{ anyPort, allowInsecureLocalhost, allowPrivateNetworks }`) when an organization owns a provider with a custom
/// base URL.
pub async fn provider_credential(
    ctx: &ServerContext,
    tx: &Store,
    provider: &InferenceProvider,
) -> IamResult<ProviderCredential> {
    let mut credential = ProviderCredential {
        id: provider.id.clone(),
        kind: provider.kind.clone(),
        base_url: provider.base_url.clone(),
        api_key: open_provider_key(ctx, provider)?,
        guard: None,
        extra: Map::new(),
    };
    if Some(provider.base_url.as_str()) != provider_base_url(&provider.kind) {
        let realm = ctx.tenant(tx, &provider.tenant_id).await?;
        if realm.kind != "root" || realm.parent_id.is_some() {
            let settings = inference_settings(ctx);
            let mut guard = Map::new();
            guard.insert("anyPort".into(), Value::Bool(true));
            guard.insert(
                "allowInsecureLocalhost".into(),
                Value::Bool(settings.allow_insecure_localhost == Some(true)),
            );
            guard.insert(
                "allowPrivateNetworks".into(),
                Value::Bool(settings.allow_private_networks == Some(true)),
            );
            credential.guard = Some(Value::Object(guard));
        }
    }
    Ok(credential)
}
