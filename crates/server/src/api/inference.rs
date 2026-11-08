//! Port of `packages/server/src/api/inference.ts`: the `inference` API group (AI model access for people, service
//! accounts and agents), the model and budget mutations configuration sync shares (`inferenceMutations`), and the
//! server-side runtime `iam.inference` (`createInferenceRuntime`).

use std::sync::Arc;

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    Identity, IdentityKind, Record, ResourceRef, Session, SessionKind, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde_json::{Map, Value};
use std::sync::LazyLock;

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::decisions::{decide_on, prepared_labeling};
use crate::inference::{
    INFERENCE_ACTION, INFERENCE_RESOURCE_TYPE, InferenceCounter, InferenceModel,
    InferenceUsageRecord, PROVIDER_KINDS, PROVIDER_TOOLS_MODES, ProviderCredential, PublicModel,
    assert_inference, base_url, budget_standings, budget_window, check_invocation,
    inference_settings, model_name, owns_inference_response, price, provider_base_url,
    provider_credential, provider_key, public_model, record_invocation, resolve_model,
    seal_provider_key, standing_of, usage_subject, visible_models, visible_provider,
};
use crate::inference_gateway::{
    GatewayAuthorization, GatewayRuntime, InferenceGateway, InferenceGatewayOptions,
    create_inference_gateway,
};
use crate::js::{invalid_input, number, number_to_string, truthy};
use crate::metrics::locale_compare;
use crate::port::decode;
use crate::utils::{id, token as new_ticket};
use crate::validation::{integer, strings, text};
use better_iam_types::api::inference;

/// How long a check's ticket may be redeemed with `inference.record`.
const TICKET_LIFETIME_MS: f64 = 3_600_000.0;
const MAX_SAFE_INTEGER: f64 = 9_007_199_254_740_991.0;
const DAY_MS: f64 = 86_400_000.0;

/// `tierPattern`: a short identifier (`family`, `tier`).
static TIER_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$").expect("pattern"));
/// A budget's model name pattern.
static MODEL_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9*?][A-Za-z0-9._:/@+*?-]{0,127}$").expect("pattern"));

// --- Record helpers -------------------------------------------------------------------------------------------------

/// A string member of a record (`""` when absent or not a string).
fn member<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

/// A number member of a record (NaN when absent, as arithmetic on `undefined` gives in JavaScript).
fn num(record: &Record, key: &str) -> f64 {
    record
        .get(key)
        .and_then(core_js::as_number)
        .unwrap_or(f64::NAN)
}

/// `Math.round`.
fn js_round(value: f64) -> f64 {
    (value + 0.5).floor()
}

/// `a ?? b` over JSON members (`undefined` is `None`).
fn coalesce<'a>(a: Option<&'a Value>, b: Option<&'a Value>) -> Option<&'a Value> {
    match a {
        None | Some(Value::Null) => b,
        some => some,
    }
}

/// `input.x === undefined ? previous?.x : (input.x ?? undefined)`.
fn replaced<'a>(input: Option<&'a Value>, previous: Option<&'a Value>) -> Option<&'a Value> {
    match input {
        None => previous,
        Some(Value::Null) => None,
        some => some,
    }
}

fn not_found(message: &str) -> IamError {
    IamError::with_status("NOT_FOUND", message, 404)
}

fn conflict(message: &str) -> IamError {
    IamError::with_status("CONFLICT", message, 409)
}

/// A typed value as TypeScript writes it: integral doubles as JSON integers.
pub(crate) fn js_json(value: Value) -> Value {
    match value {
        Value::Number(n) => number(core_js::number_value(&n)),
        Value::Array(items) => Value::Array(items.into_iter().map(js_json).collect()),
        Value::Object(map) => {
            Value::Object(map.into_iter().map(|(k, v)| (k, js_json(v))).collect())
        }
        other => other,
    }
}

/// An `AuthenticatedPrincipal` from the JSON object TypeScript passes around (`{ identity, session, deviceProof? }`).
fn principal_from_json(value: Option<&Value>) -> IamResult<AuthenticatedPrincipal> {
    let object = value
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let identity = object
        .get("identity")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let session = object
        .get("session")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    Ok(AuthenticatedPrincipal {
        identity: decode(identity)?,
        session: decode(session)?,
        device_proof: object
            .get("deviceProof")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

/// `principal` as the TypeScript object encodes.
fn principal_json(principal: &AuthenticatedPrincipal) -> Value {
    let mut out = Map::new();
    out.insert(
        "identity".into(),
        serde_json::to_value(&principal.identity).map_or(Value::Null, js_json),
    );
    out.insert(
        "session".into(),
        serde_json::to_value(&principal.session).map_or(Value::Null, js_json),
    );
    if let Some(proof) = &principal.device_proof {
        out.insert("deviceProof".into(), Value::String(proof.clone()));
    }
    Value::Object(out)
}

// --- Views ----------------------------------------------------------------------------------------------------------

/// `publicProvider(provider, tenantId)`: a provider as administrators see it, never the key.
fn public_provider(provider: &Record, tenant_id: &str) -> Value {
    let mut out = Map::new();
    for key in ["id", "tenantId", "name", "kind", "baseUrl", "keyHint"] {
        out.insert(
            key.into(),
            provider.get(key).cloned().unwrap_or(Value::Null),
        );
    }
    for key in ["createdAt", "updatedAt", "keyRotatedAt"] {
        if let Some(value) = provider.get(key) {
            out.insert(key.into(), value.clone());
        }
    }
    out.insert(
        "inherited".into(),
        Value::Bool(member(provider, "tenantId") != tenant_id),
    );
    Value::Object(out)
}

/// `keyHint(key)`: the last four characters.
fn key_hint(key: &str) -> String {
    let units: Vec<u16> = key.encode_utf16().collect();
    let tail = &units[units.len().saturating_sub(4)..];
    format!("…{}", String::from_utf16_lossy(tail))
}

/// One row of a usage report.
#[derive(Debug, Clone)]
struct UsageRow {
    key: String,
    label: Option<String>,
    requests: f64,
    errors: f64,
    input_tokens: f64,
    output_tokens: f64,
    cache_read_tokens: f64,
    cache_write_tokens: f64,
    cost_micros: f64,
    cost_usd: f64,
}

impl UsageRow {
    /// `emptyRow(key, label)`.
    fn empty(key: &str, label: Option<String>) -> Self {
        Self {
            key: key.to_owned(),
            label,
            requests: 0.0,
            errors: 0.0,
            input_tokens: 0.0,
            output_tokens: 0.0,
            cache_read_tokens: 0.0,
            cache_write_tokens: 0.0,
            cost_micros: 0.0,
            cost_usd: 0.0,
        }
    }

    /// `addUsage(row, record)`.
    fn add(&mut self, record: &Record) {
        self.requests += 1.0;
        if member(record, "status") == "error" {
            self.errors += 1.0;
        }
        self.input_tokens += num(record, "inputTokens");
        self.output_tokens += num(record, "outputTokens");
        self.cache_read_tokens += optional_count(record, "cacheReadTokens");
        self.cache_write_tokens += optional_count(record, "cacheWriteTokens");
        self.cost_micros =
            js_round((self.cost_micros + num(record, "costMicros")) * 1000.0) / 1000.0;
        self.cost_usd = js_round(self.cost_micros) / 1_000_000.0;
    }

    fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("key".into(), Value::String(self.key.clone()));
        if let Some(label) = &self.label {
            out.insert("label".into(), Value::String(label.clone()));
        }
        out.insert("requests".into(), number(self.requests));
        out.insert("errors".into(), number(self.errors));
        out.insert("inputTokens".into(), number(self.input_tokens));
        out.insert("outputTokens".into(), number(self.output_tokens));
        out.insert("cacheReadTokens".into(), number(self.cache_read_tokens));
        out.insert("cacheWriteTokens".into(), number(self.cache_write_tokens));
        out.insert("costMicros".into(), number(self.cost_micros));
        out.insert("costUsd".into(), number(self.cost_usd));
        Value::Object(out)
    }
}

/// `record.x ?? 0`.
fn optional_count(record: &Record, key: &str) -> f64 {
    match record.get(key) {
        None | Some(Value::Null) => 0.0,
        Some(value) => core_js::as_number(value).unwrap_or(f64::NAN),
    }
}

/// `new Date(ms).toISOString().slice(0, 10)`.
fn iso_day(ms: f64) -> String {
    core_js::iso_string(ms)
        .map(|text| text.chars().take(10).collect())
        .unwrap_or_default()
}

/// `aggregate(records, groupBy, from, to, labels)`: usage by one dimension, largest cost first. Returns the report's
/// members (`from`, `to`, `groupBy`, `rows`, `totals`).
fn aggregate(
    records: &[Record],
    group_by: &str,
    from: f64,
    to: f64,
    labels: &IndexMap<String, String>,
) -> Map<String, Value> {
    let mut rows: IndexMap<String, UsageRow> = IndexMap::new();
    let mut totals = UsageRow::empty("total", None);
    for record in records {
        let key = match group_by {
            "identity" => member(record, "identityId").to_owned(),
            "agent" => match record.get("agentId") {
                None | Some(Value::Null) => "(none)".to_owned(),
                Some(value) => crate::js::js_string(Some(value)),
            },
            "model" => member(record, "model").to_owned(),
            _ => iso_day((num(record, "createdAt") / DAY_MS).floor() * DAY_MS),
        };
        let row = rows
            .entry(key.clone())
            .or_insert_with(|| UsageRow::empty(&key, labels.get(&key).cloned()));
        row.add(record);
        totals.add(record);
    }
    let mut list: Vec<UsageRow> = rows.into_values().collect();
    list.sort_by(|a, b| {
        let by_cost = b.cost_micros - a.cost_micros;
        let by_requests = b.requests - a.requests;
        let order = if by_cost != 0.0 && !by_cost.is_nan() {
            by_cost
        } else if by_requests != 0.0 && !by_requests.is_nan() {
            by_requests
        } else if core_js::cmp_utf16(&a.key, &b.key) == std::cmp::Ordering::Less {
            -1.0
        } else {
            1.0
        };
        if order < 0.0 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    let mut out = Map::new();
    out.insert("from".into(), number(from));
    out.insert("to".into(), number(to));
    out.insert("groupBy".into(), Value::String(group_by.to_owned()));
    out.insert(
        "rows".into(),
        Value::Array(list.iter().map(UsageRow::to_json).collect()),
    );
    out.insert("totals".into(), totals.to_json());
    out
}

/// The enabled models a principal may invoke in a tenant, decided like `inference:invoke` without recording.
async fn invocable_models(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
) -> IamResult<Vec<PublicModel>> {
    let tenant = ctx.tenant(tx, tenant_id).await?;
    let decisions = ctx.decisions()?;
    let prepared = decisions
        .prepare_decision(tx, principal, &tenant, INFERENCE_ACTION)
        .await?;
    // Security clearances: label every model under the scheme the prepared decision already read.
    let labeling = prepared_labeling(&prepared);
    let mut result = Vec::new();
    for found in visible_models(ctx, tx, tenant_id).await? {
        let view = public_model(&found.model, found.provider.as_ref(), tenant_id);
        if !view.enabled {
            continue;
        }
        let resource = decisions
            .resolve(
                tx,
                &ResourceRef {
                    tenant_id: tenant_id.to_owned(),
                    kind: INFERENCE_RESOURCE_TYPE.to_owned(),
                    id: found.model.name.clone(),
                },
                false,
                None,
                labeling.as_ref(),
            )
            .await?;
        let decision = decide_on(&prepared, &resource, None)?;
        if decision.allowed {
            result.push(view);
        }
    }
    Ok(result)
}

fn models_json(models: &[PublicModel]) -> Value {
    Value::Array(models.iter().map(PublicModel::to_json).collect())
}

// --- Mutations ------------------------------------------------------------------------------------------------------

/// `inferenceMutations(ctx)`: model and budget changes without a credential, for the `inference` API (which
/// authorizes first) and for configuration sync (sync.ts, ai-sync.ts). Every function runs inside the caller's
/// transaction. Inputs are the request objects TypeScript receives (`null` clears an optional member).
pub struct InferenceMutations {
    ctx: Arc<ServerContext>,
}

/// Model and budget changes without a credential, for the `inference` API (which authorizes first) and for
/// configuration sync (sync.ts, ai-sync.ts). Every function runs inside the caller's transaction.
pub fn inference_mutations(ctx: &Arc<ServerContext>) -> InferenceMutations {
    InferenceMutations { ctx: ctx.clone() }
}

fn platform_only(what: &str) -> IamError {
    IamError::with_status(
        "ACCESS_DENIED",
        format!("Only a platform administrator can {what}"),
        403,
    )
}

impl InferenceMutations {
    /// A model on a parent organization's provider runs on that organization's upstream key, at the prices and limits
    /// the model sets: only a platform administrator may publish or change one, so an organization cannot price calls
    /// on the platform's account at nothing or lift the platform's caps. Turning such a model off stays open to it.
    async fn assert_provider_control(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        provider_ids: &[Option<&str>],
    ) -> IamResult<()> {
        for provider_id in provider_ids.iter().flatten() {
            let provider = tx.get("inferenceProviders", provider_id).await?;
            if let Some(provider) = provider
                && member(&provider, "tenantId") != tenant_id
                && !self.ctx.root_principal(tx, principal).await?
            {
                return Err(platform_only(
                    "publish or change a model on a parent organization’s provider",
                ));
            }
        }
        Ok(())
    }

    /// `ownModel(tx, tenantId, name)`: a model of this tenant, NOT_FOUND otherwise.
    pub async fn own_model(
        &self,
        tx: &Store,
        tenant_id: &str,
        name: Option<&Value>,
    ) -> IamResult<Record> {
        let unique_key = model_name(name)?;
        tx.find(
            "inferenceModels",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("uniqueKey", unique_key),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| not_found("Model not found in this tenant"))
    }

    /// `applyModelFields(next, input)`: the optional members of a model input onto a model record.
    pub fn apply_model_fields(
        &self,
        next: &mut Record,
        input: &Map<String, Value>,
    ) -> IamResult<()> {
        for (key, max) in [("displayName", 128), ("family", 64), ("tier", 64)] {
            match input.get(key) {
                None => {}
                Some(Value::Null) => {
                    next.shift_remove(key);
                }
                Some(value) => {
                    let value_text = text(Some(value), key, max)?;
                    if key != "displayName" && !TIER_PATTERN.is_match(&value_text) {
                        return Err(invalid_input(format!("{key} must be a short identifier")));
                    }
                    next.insert(key.into(), Value::String(value_text));
                }
            }
        }
        for key in [
            "contextWindow",
            "maxOutputTokens",
            "inputPricePerMTok",
            "outputPricePerMTok",
            "cachedInputPricePerMTok",
        ] {
            match input.get(key) {
                None => {}
                Some(Value::Null) => {
                    next.shift_remove(key);
                }
                Some(value) => {
                    let parsed = if key == "contextWindow" || key == "maxOutputTokens" {
                        integer(Some(value), key, 1.0, 100_000_000.0)?
                    } else {
                        price(Some(value), key)?
                    };
                    next.insert(key.into(), number(parsed));
                }
            }
        }
        if let Some(value) = input.get("upstreamModel") {
            next.insert(
                "upstreamModel".into(),
                Value::String(text(Some(value), "upstreamModel", 256)?),
            );
        }
        match input.get("fallbacks") {
            Some(Value::Null) => {
                next.shift_remove("fallbacks");
            }
            Some(value) => {
                let mut fallbacks: IndexSet<String> = IndexSet::new();
                for name in strings(Some(value), "fallbacks")? {
                    fallbacks.insert(model_name(Some(&Value::String(name)))?);
                }
                if fallbacks.len() > 5 {
                    return Err(invalid_input("fallbacks may name at most 5 models"));
                }
                if fallbacks.contains(member(next, "name")) {
                    return Err(invalid_input("A model cannot fall back to itself"));
                }
                if fallbacks.is_empty() {
                    next.shift_remove("fallbacks");
                } else {
                    next.insert(
                        "fallbacks".into(),
                        Value::Array(fallbacks.into_iter().map(Value::String).collect()),
                    );
                }
            }
            None => {}
        }
        match input.get("providerTools") {
            None => {}
            Some(Value::Null) => {
                next.shift_remove("providerTools");
            }
            Some(Value::String(mode)) if mode == "allow" => {
                next.shift_remove("providerTools");
            }
            Some(value) => {
                let Some(mode) = value
                    .as_str()
                    .filter(|mode| PROVIDER_TOOLS_MODES.contains(mode))
                else {
                    return Err(invalid_input(
                        "providerTools must be 'allow', 'deny' or 'policy'",
                    ));
                };
                next.insert("providerTools".into(), Value::String(mode.to_owned()));
            }
        }
        if let Some(value) = input.get("enabled") {
            let Value::Bool(enabled) = value else {
                return Err(invalid_input("enabled must be a boolean"));
            };
            next.insert("enabled".into(), Value::Bool(*enabled));
        }
        Ok(())
    }

    /// `budgetView(tx, budget)`: a budget without its `uniqueKey`, with `maxCostUsd`, the subject's name and, for
    /// shared pools, the standing in the current window.
    pub async fn budget_view(&self, tx: &Store, budget: &Record) -> IamResult<Value> {
        let mut view: Map<String, Value> = budget
            .iter()
            .filter(|(key, _)| key.as_str() != "uniqueKey")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if let Some(micros) = budget.get("maxCostMicros") {
            let micros = core_js::as_number(micros).unwrap_or(f64::NAN);
            view.insert("maxCostUsd".into(), number(micros / 1_000_000.0));
        }
        let subject_type = member(budget, "subjectType");
        let subject_id = member(budget, "subjectId");
        if subject_type == "group" {
            if let Some(group) = tx.get("groups", subject_id).await? {
                view.insert(
                    "subjectName".into(),
                    group.get("name").cloned().unwrap_or(Value::Null),
                );
            }
        } else if subject_type == "identity"
            && let Some(identity) = tx.get("identities", subject_id).await?
        {
            let name = match identity.get("email") {
                None | Some(Value::Null) => identity.get("name").cloned(),
                email => email.cloned(),
            };
            view.insert("subjectName".into(), name.unwrap_or(Value::Null));
        }
        if subject_type == "identity" || member(budget, "scope") == "shared" {
            let typed: crate::inference::InferenceBudget = decode(budget.clone())?;
            let window = budget_window(&typed.period, self.ctx.now());
            let counter = tx
                .get(
                    "inferenceCounters",
                    &format!("{}:shared:{}", typed.id, number_to_string(window.start)),
                )
                .await?
                .map(decode::<InferenceCounter>)
                .transpose()?;
            view.insert(
                "standing".into(),
                standing_of(&typed, &window, counter.as_ref()).to_json(),
            );
        }
        Ok(Value::Object(view))
    }

    /// `budgetFields(tx, tenantId, input, previous)`: the validated, user-controlled fields of a budget.
    pub async fn budget_fields(
        &self,
        tx: &Store,
        tenant_id: &str,
        input: &Map<String, Value>,
        previous: Option<&Record>,
    ) -> IamResult<Map<String, Value>> {
        let ctx = &self.ctx;
        let prev = |key: &str| previous.and_then(|record| record.get(key));
        let name = core_js::trim(&text(
            coalesce(input.get("name"), prev("name")),
            "name",
            100,
        )?)
        .to_owned();
        let subject_type = coalesce(input.get("subjectType"), prev("subjectType"))
            .and_then(Value::as_str)
            .filter(|kind| ["tenant", "group", "identity"].contains(kind))
            .ok_or_else(|| invalid_input("subjectType must be 'tenant', 'group' or 'identity'"))?
            .to_owned();
        let subject_id = if subject_type == "tenant" {
            tenant_id.to_owned()
        } else {
            let subject_id = text(
                coalesce(input.get("subjectId"), prev("subjectId")),
                "subjectId",
                256,
            )?;
            if subject_type == "group" {
                ctx.scoped(
                    tx,
                    "groups",
                    Some(&Value::String(subject_id.clone())),
                    tenant_id,
                )
                .await?;
            } else {
                ctx.active_identity(tx, &subject_id, tenant_id).await?;
            }
            subject_id
        };
        let shared = Value::String("shared".into());
        let scope = coalesce(coalesce(input.get("scope"), prev("scope")), Some(&shared))
            .and_then(Value::as_str)
            .filter(|scope| ["shared", "each"].contains(scope))
            .ok_or_else(|| invalid_input("scope must be 'shared' or 'each'"))?
            .to_owned();
        let period = coalesce(input.get("period"), prev("period"))
            .and_then(Value::as_str)
            .filter(|period| ["minute", "hour", "day", "month"].contains(period))
            .ok_or_else(|| invalid_input("period must be 'minute', 'hour', 'day' or 'month'"))?
            .to_owned();
        let mut fields = Map::new();
        fields.insert(
            "uniqueKey".into(),
            Value::String(format!("name:{}", core_js::to_lower(&name))),
        );
        fields.insert("name".into(), Value::String(name));
        fields.insert("subjectType".into(), Value::String(subject_type.clone()));
        fields.insert("subjectId".into(), Value::String(subject_id));
        fields.insert(
            "scope".into(),
            Value::String(if subject_type == "identity" {
                "shared".into()
            } else {
                scope
            }),
        );
        fields.insert("period".into(), Value::String(period));
        if let Some(max_tokens) = replaced(input.get("maxTokens"), prev("maxTokens")) {
            fields.insert(
                "maxTokens".into(),
                number(integer(Some(max_tokens), "maxTokens", 1.0, 1e15)?),
            );
        }
        let max_cost = match input.get("maxCostUsd") {
            None => prev("maxCostMicros").cloned(),
            Some(Value::Null) => None,
            Some(value) => Some(number(js_round(
                price(Some(value), "maxCostUsd")? * 1_000_000.0,
            ))),
        };
        if let Some(value) = input.get("maxCostUsd")
            && !value.is_null()
            && core_js::as_number(value).is_some_and(|cost| cost <= 0.0)
        {
            return Err(invalid_input("maxCostUsd must be positive"));
        }
        if let Some(max_cost) = max_cost {
            fields.insert("maxCostMicros".into(), max_cost);
        }
        if let Some(max_requests) = replaced(input.get("maxRequests"), prev("maxRequests")) {
            fields.insert(
                "maxRequests".into(),
                number(integer(
                    Some(max_requests),
                    "maxRequests",
                    1.0,
                    1_000_000_000.0,
                )?),
            );
        }
        if !fields.contains_key("maxTokens")
            && !fields.contains_key("maxCostMicros")
            && !fields.contains_key("maxRequests")
        {
            return Err(invalid_input(
                "A budget needs at least one of maxTokens, maxCostUsd and maxRequests",
            ));
        }
        if let Some(models) = replaced(input.get("models"), prev("models")) {
            let list = crate::js::unique(strings(Some(models), "models")?);
            for pattern in &list {
                if !MODEL_PATTERN.is_match(pattern) {
                    return Err(invalid_input(format!("Invalid model pattern {pattern}")));
                }
            }
            if !list.is_empty() {
                fields.insert(
                    "models".into(),
                    Value::Array(list.into_iter().map(Value::String).collect()),
                );
            }
        }
        if let Some(alert) = replaced(input.get("alertAtPercent"), prev("alertAtPercent")) {
            fields.insert(
                "alertAtPercent".into(),
                number(integer(Some(alert), "alertAtPercent", 1.0, 100.0)?),
            );
        }
        Ok(fields)
    }

    /// `createModel(tx, principal, tenantId, input)`: publishes a model of this tenant.
    pub async fn create_model(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        input: &Map<String, Value>,
    ) -> IamResult<PublicModel> {
        let ctx = &self.ctx;
        let name = model_name(input.get("name"))?;
        if !tx
            .find(
                "inferenceModels",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("uniqueKey", name.clone()),
                &FindOptions::default(),
            )
            .await?
            .is_empty()
        {
            return Err(conflict("A model with this name exists in this tenant"));
        }
        let provider_id = text(input.get("providerId"), "providerId", 256)?;
        let provider = visible_provider(ctx, tx, tenant_id, &provider_id)
            .await?
            .ok_or_else(|| not_found("Provider not found"))?;
        self.assert_provider_control(tx, principal, tenant_id, &[Some(&provider.id)])
            .await?;
        let now = ctx.now();
        let mut model = Map::new();
        model.insert("id".into(), Value::String(id()));
        model.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        model.insert("uniqueKey".into(), Value::String(name.clone()));
        model.insert("name".into(), Value::String(name));
        model.insert("providerId".into(), Value::String(provider.id.clone()));
        model.insert(
            "upstreamModel".into(),
            Value::String(text(input.get("upstreamModel"), "upstreamModel", 256)?),
        );
        model.insert("enabled".into(), Value::Bool(true));
        model.insert("createdAt".into(), number(now));
        model.insert("updatedAt".into(), number(now));
        self.apply_model_fields(&mut model, input)?;
        tx.insert("inferenceModels", &model).await?;
        let typed: InferenceModel = decode(model)?;
        Ok(public_model(&typed, Some(&provider), tenant_id))
    }

    /// `updateModel(tx, principal, tenantId, input)`: changes a model of this tenant (null clears an optional field).
    pub async fn update_model(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        input: &Map<String, Value>,
    ) -> IamResult<PublicModel> {
        let ctx = &self.ctx;
        let model = self.own_model(tx, tenant_id, input.get("name")).await?;
        let mut next = model.clone();
        next.insert("updatedAt".into(), number(ctx.now()));
        if let Some(value) = input.get("providerId") {
            let provider_id = text(Some(value), "providerId", 256)?;
            let provider = visible_provider(ctx, tx, tenant_id, &provider_id)
                .await?
                .ok_or_else(|| not_found("Provider not found"))?;
            next.insert("providerId".into(), Value::String(provider.id));
        }
        self.apply_model_fields(&mut next, input)?;
        // Turning a model off never needs more than managing the tenant's models.
        let only_disables = next.get("enabled") == Some(&Value::Bool(false)) && {
            let mut left = next.clone();
            match model.get("enabled") {
                Some(enabled) => {
                    left.insert("enabled".into(), enabled.clone());
                }
                None => {
                    left.shift_remove("enabled");
                }
            }
            left.insert("updatedAt".into(), Value::from(0));
            let mut right = model.clone();
            right.insert("updatedAt".into(), Value::from(0));
            core_js::stringify_object(&left) == core_js::stringify_object(&right)
        };
        if !only_disables {
            self.assert_provider_control(
                tx,
                principal,
                tenant_id,
                &[
                    model.get("providerId").and_then(Value::as_str),
                    next.get("providerId").and_then(Value::as_str),
                ],
            )
            .await?;
        }
        let saved = tx.put("inferenceModels", &next).await?;
        let typed: InferenceModel = decode(saved)?;
        let provider = visible_provider(ctx, tx, tenant_id, &typed.provider_id).await?;
        Ok(public_model(&typed, provider.as_ref(), tenant_id))
    }

    /// `deleteModel(tx, tenantId, name)`.
    pub async fn delete_model(
        &self,
        tx: &Store,
        tenant_id: &str,
        name: Option<&Value>,
    ) -> IamResult<()> {
        let model = self.own_model(tx, tenant_id, name).await?;
        tx.delete("inferenceModels", member(&model, "id")).await
    }

    /// Creates a budget, or replaces `previous`; names are unique regardless of case.
    pub async fn save_budget(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        input: &Map<String, Value>,
        previous: Option<&Record>,
    ) -> IamResult<Record> {
        let ctx = &self.ctx;
        // A cap the platform put on an organization binds the organization's own administrators.
        let platform = ctx.root_principal(tx, principal).await?;
        if previous.is_some_and(|previous| truthy(previous.get("platform"))) && !platform {
            return Err(platform_only("change a budget the platform set"));
        }
        let fields = self.budget_fields(tx, tenant_id, input, previous).await?;
        let previous_id = previous.map(|previous| member(previous, "id"));
        let clash = tx
            .find(
                "inferenceBudgets",
                &Filter::new().eq("tenantId", tenant_id).eq(
                    "uniqueKey",
                    fields.get("uniqueKey").cloned().unwrap_or(Value::Null),
                ),
                &FindOptions::default(),
            )
            .await?
            .iter()
            .any(|other| Some(member(other, "id")) != previous_id);
        if clash {
            return Err(conflict("A budget with this name exists"));
        }
        let now = ctx.now();
        let mut budget = fields;
        match previous {
            Some(previous) => {
                budget.insert(
                    "id".into(),
                    Value::String(member(previous, "id").to_owned()),
                );
                budget.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
                budget.insert(
                    "createdAt".into(),
                    previous.get("createdAt").cloned().unwrap_or(Value::Null),
                );
                budget.insert("updatedAt".into(), number(now));
            }
            None => {
                budget.insert("id".into(), Value::String(id()));
                budget.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
                budget.insert("createdAt".into(), number(now));
                budget.insert("updatedAt".into(), number(now));
            }
        }
        if platform {
            budget.insert("platform".into(), Value::Bool(true));
        } else {
            budget.shift_remove("platform");
        }
        if previous.is_some() {
            tx.put("inferenceBudgets", &budget).await?;
        } else {
            tx.insert("inferenceBudgets", &budget).await?;
        }
        Ok(budget)
    }

    /// Deletes a budget and its counters.
    pub async fn delete_budget(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        budget: &Record,
    ) -> IamResult<()> {
        if truthy(budget.get("platform")) && !self.ctx.root_principal(tx, principal).await? {
            return Err(platform_only("remove a budget the platform set"));
        }
        let budget_id = member(budget, "id").to_owned();
        tx.delete("inferenceBudgets", &budget_id).await?;
        for counter in tx
            .find(
                "inferenceCounters",
                &Filter::new().eq("budgetId", budget_id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            tx.delete("inferenceCounters", member(&counter, "id"))
                .await?;
        }
        Ok(())
    }
}

// --- The API group --------------------------------------------------------------------------------------------------

/// The `inference` API group (`createInferenceApi(ctx)`): one method per route `inference/{method}`.
///
/// AI model access for people, service accounts and agents. Administrators with `iam:inference:manage` register
/// upstream providers (keys are sealed and never returned), the models callers use, and budgets;
/// `iam:inference:read` reads them and the usage reports. Access to a model is an ordinary policy decision:
/// `inference:invoke` on `model/{name}`. Callers check their own access (`check`, `listMine`) and see their own
/// usage (`myUsage`); an external gateway redeems the ticket a check returns with `record` (`iam:inference:record`).
/// Requires the `inference` option.
pub struct InferenceApi {
    ctx: Arc<ServerContext>,
    mutations: InferenceMutations,
}

/// `createInferenceApi(ctx)`.
pub fn create_inference_api(ctx: &Arc<ServerContext>) -> IamResult<InferenceApi> {
    Ok(InferenceApi {
        ctx: ctx.clone(),
        mutations: inference_mutations(ctx),
    })
}

fn reply<O>(value: Value) -> IamResult<Reply<O>> {
    Ok(Reply::json(value))
}

/// `ownProvider(tx, providerId, tenantId)`.
async fn own_provider(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    provider_id: Option<&Value>,
    tenant_id: &str,
) -> IamResult<Record> {
    ctx.scoped(tx, "inferenceProviders", provider_id, tenant_id)
        .await
}

/// Custom base URLs point the gateway (and the provider key) somewhere else: root, or opted in by the deployment.
async fn allowed_base_url(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    kind: &str,
    value: Option<&Value>,
) -> IamResult<String> {
    let fallback = provider_base_url(kind);
    let Some(value) = value else {
        return fallback
            .map(str::to_owned)
            .ok_or_else(|| invalid_input("An openai-compatible provider needs a baseUrl"));
    };
    let settings = inference_settings(ctx);
    let url = base_url(Some(value), &settings)?;
    if Some(url.as_str()) != fallback
        && settings.allow_custom_base_urls != Some(true)
        && !ctx.root_principal(tx, principal).await?
    {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Only a root administrator can point a provider at a custom base URL on this deployment",
            403,
        ));
    }
    Ok(url)
}

/// `usageRange(input)`: `from` (default: the start of this month, UTC) and `to` (default: now).
fn usage_range(ctx: &ServerContext, input: &Map<String, Value>) -> IamResult<(f64, f64)> {
    let now = ctx.now();
    let to = match input.get("to") {
        Some(value) => integer(Some(value), "to", 0.0, MAX_SAFE_INTEGER)?,
        None => now,
    };
    let from = match input.get("from") {
        Some(value) => integer(Some(value), "from", 0.0, MAX_SAFE_INTEGER)?,
        None => budget_window("month", now).start,
    };
    if from > to {
        return Err(invalid_input("from must not be after to"));
    }
    Ok((from, to))
}

/// `records(tx, filter, from, to)`: usage records between `from` and `to`.
async fn usage_records(tx: &Store, filter: &Filter, from: f64, to: f64) -> IamResult<Vec<Record>> {
    Ok(tx
        .find("inferenceUsage", filter, &FindOptions::default())
        .await?
        .into_iter()
        .filter(|record| {
            let created = num(record, "createdAt");
            created >= from && created <= to
        })
        .collect())
}

/// `labelsFor(tx, ids)`: the email (or name) of each identity.
async fn labels_for(tx: &Store, ids: IndexSet<String>) -> IamResult<IndexMap<String, String>> {
    let mut labels = IndexMap::new();
    for key in ids {
        if let Some(identity) = tx.get("identities", &key).await? {
            let label = match identity.get("email") {
                Some(Value::String(email)) => email.clone(),
                _ => member(&identity, "name").to_owned(),
            };
            labels.insert(key, label);
        }
    }
    Ok(labels)
}

impl InferenceApi {
    /// Runs `mutation` as the operation `action` on `iam/{resource_id}` in the input's tenant.
    async fn operate(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                resource_id,
                mutation,
                false,
            )
            .await
    }

    /// `inference/createProvider`: registers an upstream provider account. `kind` is `anthropic`, `openai` or
    /// `openai-compatible` (which needs a `baseUrl`); the key is sealed with the deployment secret and only its last
    /// four characters are ever shown. A custom base URL needs a root administrator unless the deployment sets
    /// `inference.allowCustomBaseUrls`. Needs `iam:inference:manage` and a recent sign-in.
    pub async fn create_provider(
        &self,
        credential: &CredentialInput,
        input: Body<inference::CreateProviderInput>,
    ) -> IamResult<Reply<inference::CreateProviderOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let name = core_js::trim(&text(body.get("name"), "name", 100)?).to_owned();
                    let kind = body
                        .get("kind")
                        .and_then(Value::as_str)
                        .filter(|kind| PROVIDER_KINDS.contains(kind))
                        .ok_or_else(|| {
                            invalid_input(format!(
                                "kind must be one of {}",
                                PROVIDER_KINDS.join(", ")
                            ))
                        })?
                        .to_owned();
                    let api_key = provider_key(body.get("apiKey"))?;
                    let unique_key = format!("name:{}", core_js::to_lower(&name));
                    if !tx
                        .find(
                            "inferenceProviders",
                            &Filter::new()
                                .eq("tenantId", tenant.id.clone())
                                .eq("uniqueKey", unique_key.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                        .is_empty()
                    {
                        return Err(conflict("A provider with this name exists").into());
                    }
                    let now = ctx.now();
                    let provider_id = id();
                    let mut provider = Map::new();
                    provider.insert("id".into(), Value::String(provider_id.clone()));
                    provider.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    provider.insert("uniqueKey".into(), Value::String(unique_key));
                    provider.insert("name".into(), Value::String(name));
                    provider.insert("kind".into(), Value::String(kind.clone()));
                    let url =
                        allowed_base_url(ctx, &tx, &principal, &kind, body.get("baseUrl")).await?;
                    provider.insert("baseUrl".into(), Value::String(url));
                    provider.insert(
                        "keySealed".into(),
                        Value::String(seal_provider_key(
                            &ctx.options.secret,
                            &provider_id,
                            &api_key,
                        )),
                    );
                    provider.insert("keyHint".into(), Value::String(key_hint(&api_key)));
                    provider.insert("createdAt".into(), number(now));
                    provider.insert("updatedAt".into(), number(now));
                    provider.insert("keyRotatedAt".into(), number(now));
                    tx.insert("inferenceProviders", &provider).await?;
                    Ok(public_provider(&provider, &tenant.id))
                })
            },
        );
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:manage",
                &resource,
                mutation,
            )
            .await?,
        )
    }

    /// `inference/updateProvider`: renames a provider, moves its base URL, or replaces its key (`apiKey`). Needs
    /// `iam:inference:manage` and a recent sign-in.
    pub async fn update_provider(
        &self,
        credential: &CredentialInput,
        input: Body<inference::UpdateProviderInput>,
    ) -> IamResult<Reply<inference::UpdateProviderOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let body = input.raw();
        let resource = text(body.get("providerId"), "providerId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let provider =
                        own_provider(ctx, &tx, body.get("providerId"), &tenant.id).await?;
                    let mut next = provider.clone();
                    next.insert("updatedAt".into(), number(ctx.now()));
                    if let Some(value) = body.get("name") {
                        let name = core_js::trim(&text(Some(value), "name", 100)?).to_owned();
                        let unique_key = format!("name:{}", core_js::to_lower(&name));
                        next.insert("name".into(), Value::String(name));
                        next.insert("uniqueKey".into(), Value::String(unique_key.clone()));
                        let clash = tx
                            .find(
                                "inferenceProviders",
                                &Filter::new()
                                    .eq("tenantId", tenant.id.clone())
                                    .eq("uniqueKey", unique_key),
                                &FindOptions::default(),
                            )
                            .await?
                            .iter()
                            .any(|other| member(other, "id") != member(&provider, "id"));
                        if clash {
                            return Err(conflict("A provider with this name exists").into());
                        }
                    }
                    if let Some(value) = body.get("baseUrl") {
                        let url = allowed_base_url(
                            ctx,
                            &tx,
                            &principal,
                            member(&provider, "kind"),
                            Some(value),
                        )
                        .await?;
                        next.insert("baseUrl".into(), Value::String(url));
                    }
                    // The sealed key is write-only: pointing the provider somewhere else must not send it along, so a
                    // new base URL needs the key again.
                    if next.get("baseUrl") != provider.get("baseUrl")
                        && body.get("apiKey").is_none()
                    {
                        return Err(invalid_input(
                            "Changing the base URL needs the provider key (apiKey) again",
                        )
                        .into());
                    }
                    if let Some(value) = body.get("apiKey") {
                        let api_key = provider_key(Some(value))?;
                        next.insert(
                            "keySealed".into(),
                            Value::String(seal_provider_key(
                                &ctx.options.secret,
                                member(&provider, "id"),
                                &api_key,
                            )),
                        );
                        next.insert("keyHint".into(), Value::String(key_hint(&api_key)));
                        let updated = next.get("updatedAt").cloned().unwrap_or(Value::Null);
                        next.insert("keyRotatedAt".into(), updated);
                    }
                    let saved = tx.put("inferenceProviders", &next).await?;
                    Ok(public_provider(&saved, &tenant.id))
                })
            },
        );
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:manage",
                &resource,
                mutation,
            )
            .await?,
        )
    }

    /// `inference/deleteProvider`: deletes a provider no model uses (RESOURCE_IN_USE otherwise). Needs
    /// `iam:inference:manage`.
    pub async fn delete_provider(
        &self,
        credential: &CredentialInput,
        input: Body<inference::DeleteProviderInput>,
    ) -> IamResult<Reply<inference::DeleteProviderOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let body = input.raw();
        let resource = text(body.get("providerId"), "providerId", 256)?;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let provider = own_provider(ctx, &tx, body.get("providerId"), &tenant.id).await?;
                let provider_id = member(&provider, "id").to_owned();
                if !tx
                    .find(
                        "inferenceModels",
                        &Filter::new().eq("providerId", provider_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                    .is_empty()
                {
                    return Err(IamError::with_status(
                        "RESOURCE_IN_USE",
                        "Models still use this provider",
                        409,
                    )
                    .into());
                }
                tx.delete("inferenceProviders", &provider_id).await?;
                Ok(serde_json::json!({ "deleted": true }))
            })
        });
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:manage",
                &resource,
                mutation,
            )
            .await?,
        )
    }

    /// `inference/listProviders`: the providers models of this tenant may use, its own and its ancestors'. Needs
    /// `iam:inference:read`.
    pub async fn list_providers(
        &self,
        credential: &CredentialInput,
        input: Body<inference::ListProvidersInput>,
    ) -> IamResult<Reply<inference::ListProvidersOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut result: Vec<Value> = Vec::new();
                for realm in ctx.ancestry(&tx, &tenant).await? {
                    for provider in tx
                        .find(
                            "inferenceProviders",
                            &Filter::new().eq("tenantId", realm.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        result.push(public_provider(&provider, &tenant.id));
                    }
                }
                let inherited = |value: &Value| value.get("inherited") == Some(&Value::Bool(true));
                let name = |value: &Value| {
                    value
                        .get("name")
                        .and_then(Value::as_str)
                        .unwrap_or("")
                        .to_owned()
                };
                result.sort_by(|a, b| {
                    inherited(a)
                        .cmp(&inherited(b))
                        .then_with(|| locale_compare(&name(a), &name(b)))
                });
                Ok(Value::Array(result))
            })
        });
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(credential, body, "iam:inference:read", &resource, mutation)
                .await?,
        )
    }

    /// `inference/createModel`: publishes a model under a public `name`, served by a provider of this tenant or an
    /// ancestor as `upstreamModel`. Sub-tenants inherit the model. Needs `iam:inference:manage`.
    pub async fn create_model(
        &self,
        credential: &CredentialInput,
        input: Body<inference::CreateModelInput>,
    ) -> IamResult<Reply<inference::CreateModelOutput>> {
        assert_inference(&self.ctx)?;
        let mutations = &self.mutations;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    Ok(mutations
                        .create_model(&tx, &principal, &tenant.id, body)
                        .await?
                        .to_json())
                })
            },
        );
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:manage",
                &resource,
                mutation,
            )
            .await?,
        )
    }

    /// `inference/updateModel`: changes a model of this tenant (null clears an optional field); `enabled: false`
    /// stops every call at once.
    pub async fn update_model(
        &self,
        credential: &CredentialInput,
        input: Body<inference::UpdateModelInput>,
    ) -> IamResult<Reply<inference::UpdateModelOutput>> {
        assert_inference(&self.ctx)?;
        let mutations = &self.mutations;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    Ok(mutations
                        .update_model(&tx, &principal, &tenant.id, body)
                        .await?
                        .to_json())
                })
            },
        );
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:manage",
                &resource,
                mutation,
            )
            .await?,
        )
    }

    /// `inference/deleteModel`: removes a model of this tenant (an inherited model of the same name becomes visible
    /// again).
    pub async fn delete_model(
        &self,
        credential: &CredentialInput,
        input: Body<inference::DeleteModelInput>,
    ) -> IamResult<Reply<inference::DeleteModelOutput>> {
        assert_inference(&self.ctx)?;
        let mutations = &self.mutations;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                mutations
                    .delete_model(&tx, &tenant.id, body.get("name"))
                    .await?;
                Ok(serde_json::json!({ "deleted": true }))
            })
        });
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:manage",
                &resource,
                mutation,
            )
            .await?,
        )
    }

    /// `inference/listModels`: every model visible to the tenant (own and inherited). Needs `iam:inference:read`.
    pub async fn list_models(
        &self,
        credential: &CredentialInput,
        input: Body<inference::ListModelsInput>,
    ) -> IamResult<Reply<inference::ListModelsOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let models: Vec<PublicModel> = visible_models(ctx, &tx, &tenant.id)
                    .await?
                    .iter()
                    .map(|found| public_model(&found.model, found.provider.as_ref(), &tenant.id))
                    .collect();
                Ok(models_json(&models))
            })
        });
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(credential, body, "iam:inference:read", &resource, mutation)
                .await?,
        )
    }

    /// `inference/listMine`: the enabled models the caller may invoke in the tenant (for a model picker), evaluated
    /// like `inference:invoke` decisions without recording them. Any credential of the tenant; needs no permission.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<inference::ListMineInput>,
    ) -> IamResult<Reply<inference::ListMineOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let models = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id) = (&authenticated, &tenant_id);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    invocable_models(ctx, &tx, &principal, tenant_id).await
                }
            })
            .await?;
        reply(models_json(&models))
    }

    /// `inference/setBudget`: creates or (with `budgetId`) replaces a budget. Calls that would exceed a budget are
    /// refused with BUDGET_EXCEEDED. Needs `iam:inference:manage`.
    pub async fn set_budget(
        &self,
        credential: &CredentialInput,
        input: Body<inference::SetBudgetInput>,
    ) -> IamResult<Reply<inference::SetBudgetOutput>> {
        assert_inference(&self.ctx)?;
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
                    let previous = match body.get("budgetId") {
                        Some(budget_id) => Some(
                            ctx.scoped(&tx, "inferenceBudgets", Some(budget_id), &tenant.id)
                                .await?,
                        ),
                        None => None,
                    };
                    let budget = mutations
                        .save_budget(&tx, &principal, &tenant.id, body, previous.as_ref())
                        .await?;
                    Ok(mutations.budget_view(&tx, &budget).await?)
                })
            },
        );
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:manage",
                &resource,
                mutation,
            )
            .await?,
        )
    }

    /// `inference/deleteBudget`.
    pub async fn delete_budget(
        &self,
        credential: &CredentialInput,
        input: Body<inference::DeleteBudgetInput>,
    ) -> IamResult<Reply<inference::DeleteBudgetOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let mutations = &self.mutations;
        let body = input.raw();
        let resource = text(body.get("budgetId"), "budgetId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let budget = ctx
                        .scoped(&tx, "inferenceBudgets", body.get("budgetId"), &tenant.id)
                        .await?;
                    mutations.delete_budget(&tx, &principal, &budget).await?;
                    Ok(serde_json::json!({ "deleted": true }))
                })
            },
        );
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:manage",
                &resource,
                mutation,
            )
            .await?,
        )
    }

    /// `inference/listBudgets`: the tenant's budgets, with the current window's standing of each shared pool. Needs
    /// `iam:inference:read`.
    pub async fn list_budgets(
        &self,
        credential: &CredentialInput,
        input: Body<inference::ListBudgetsInput>,
    ) -> IamResult<Reply<inference::ListBudgetsOutput>> {
        assert_inference(&self.ctx)?;
        let mutations = &self.mutations;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut budgets = tx
                    .find(
                        "inferenceBudgets",
                        &Filter::new().eq("tenantId", tenant.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                budgets.sort_by(|a, b| locale_compare(member(a, "name"), member(b, "name")));
                let mut views = Vec::new();
                for budget in &budgets {
                    views.push(mutations.budget_view(&tx, budget).await?);
                }
                Ok(Value::Array(views))
            })
        });
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(credential, body, "iam:inference:read", &resource, mutation)
                .await?,
        )
    }

    /// `inference/usage`: usage between `from` (default: start of this month, UTC) and `to` (default: now),
    /// optionally for one identity, agent or model, grouped by `identity`, `agent`, `model` or `day`. Needs
    /// `iam:inference:read`.
    pub async fn usage(
        &self,
        credential: &CredentialInput,
        input: Body<inference::UsageInput>,
    ) -> IamResult<Reply<inference::UsageOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let (from, to) = usage_range(ctx, body)?;
                let model_group = Value::String("model".into());
                let group_by = coalesce(body.get("groupBy"), Some(&model_group))
                    .and_then(Value::as_str)
                    .filter(|group| ["identity", "agent", "model", "day"].contains(group))
                    .ok_or_else(|| {
                        invalid_input("groupBy must be 'identity', 'agent', 'model' or 'day'")
                    })?
                    .to_owned();
                let mut filter = Filter::new().eq("tenantId", tenant.id.clone());
                if let Some(value) = body.get("identityId") {
                    filter = filter.eq("identityId", text(Some(value), "identityId", 256)?);
                }
                if let Some(value) = body.get("agentId") {
                    filter = filter.eq("agentId", text(Some(value), "agentId", 256)?);
                }
                if let Some(value) = body.get("model") {
                    filter = filter.eq("model", model_name(Some(value))?);
                }
                let found = usage_records(&tx, &filter, from, to).await?;
                let labels = if group_by == "identity" || group_by == "agent" {
                    let key = if group_by == "identity" {
                        "identityId"
                    } else {
                        "agentId"
                    };
                    let ids: IndexSet<String> = found
                        .iter()
                        .filter(|record| truthy(record.get(key)))
                        .map(|record| crate::js::js_string(record.get(key)))
                        .collect();
                    labels_for(&tx, ids).await?
                } else {
                    IndexMap::new()
                };
                Ok(Value::Object(aggregate(
                    &found, &group_by, from, to, &labels,
                )))
            })
        });
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(credential, body, "iam:inference:read", &resource, mutation)
                .await?,
        )
    }

    /// `inference/myUsage`: the caller's own usage by model between `from` and `to`, plus the standing of every
    /// budget that covers them for each model they used or may use. Any credential of the tenant; needs no
    /// permission.
    pub async fn my_usage(
        &self,
        credential: &CredentialInput,
        input: Body<inference::MyUsageInput>,
    ) -> IamResult<Reply<inference::MyUsageOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let (from, to) = usage_range(ctx, input.raw())?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let report = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id) = (&authenticated, &tenant_id);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    if principal.session.tenant_id != *tenant_id {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Usage is read in the credential’s own tenant",
                            403,
                        ));
                    }
                    let found = usage_records(
                        &tx,
                        &Filter::new()
                            .eq("tenantId", tenant_id.clone())
                            .eq("identityId", principal.identity.id.clone()),
                        from,
                        to,
                    )
                    .await?;
                    let mut report = aggregate(&found, "model", from, to, &IndexMap::new());
                    let subject = usage_subject(ctx, &tx, &principal, tenant_id).await?;
                    let mut seen: IndexMap<String, Value> = IndexMap::new();
                    let mut names: IndexSet<String> = found
                        .iter()
                        .map(|record| member(record, "model").to_owned())
                        .collect();
                    for item in visible_models(ctx, &tx, tenant_id).await? {
                        names.insert(item.model.name.clone());
                    }
                    for name in &names {
                        for covering in budget_standings(ctx, &tx, &subject, name).await? {
                            seen.insert(
                                covering.standing.budget_id.clone(),
                                covering.standing.to_json(),
                            );
                        }
                    }
                    report.insert("budgets".into(), Value::Array(seen.into_values().collect()));
                    Ok(Value::Object(report))
                }
            })
            .await?;
        reply(report)
    }

    /// `inference/check`: whether the caller may invoke `model` now (access, enabled, budgets with an optional
    /// `estimatedTokens`, and the provider-run `tools` the request asks for). Allowed checks carry a single-use
    /// `ticket` (valid one hour) an external gateway redeems with `record` after the call. Denials are audited like
    /// any decision.
    pub async fn check(
        &self,
        credential: &CredentialInput,
        input: Body<inference::CheckInput>,
    ) -> IamResult<Reply<inference::CheckOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = text(body.get("tenantId"), "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let result = ctx
            .store
            .transaction(|tx| {
                let (authenticated, tenant_id) = (&authenticated, &tenant_id);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let mut request = Map::new();
                    request.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    for key in ["model", "estimatedTokens", "tools"] {
                        if let Some(value) = body.get(key) {
                            request.insert(key.into(), value.clone());
                        }
                    }
                    let result =
                        check_invocation(ctx, &tx, &principal, &Value::Object(request)).await?;
                    let mut out = match result.to_json() {
                        Value::Object(out) => out,
                        _ => Map::new(),
                    };
                    if !result.allowed {
                        return Ok(Value::Object(out));
                    }
                    let model = result
                        .model
                        .as_ref()
                        .map(|model| model.name.clone())
                        .unwrap_or_default();
                    let ticket = new_ticket();
                    let now = ctx.now();
                    let session = &principal.session;
                    let agent_id = if session.kind == SessionKind::Delegated {
                        session.agent_id.clone()
                    } else if principal.identity.kind == IdentityKind::Agent {
                        Some(principal.identity.id.clone())
                    } else {
                        None
                    };
                    let mut record = Map::new();
                    record.insert("id".into(), Value::String(ticket.clone()));
                    record.insert("tenantId".into(), Value::String(tenant_id.clone()));
                    record.insert(
                        "identityId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("sessionId".into(), Value::String(session.id.clone()));
                    record.insert(
                        "sessionKind".into(),
                        Value::String(session.kind.as_str().to_owned()),
                    );
                    if let Some(agent_id) = agent_id {
                        record.insert("agentId".into(), Value::String(agent_id));
                    }
                    if let Some(delegation_id) = &session.delegation_id {
                        record.insert("delegationId".into(), Value::String(delegation_id.clone()));
                    }
                    record.insert("model".into(), Value::String(model));
                    record.insert("createdAt".into(), number(now));
                    record.insert("expiresAt".into(), number(now + TICKET_LIFETIME_MS));
                    tx.insert("inferenceTickets", &record).await?;
                    out.insert("ticket".into(), Value::String(ticket));
                    Ok(Value::Object(out))
                }
            })
            .await?;
        reply(result)
    }

    /// `inference/record`: an external gateway meters a call it made after `check`: the ticket names the caller as
    /// the check saw them (their session may have ended since) and the model; token counts come from the provider's
    /// response. Single use. Needs `iam:inference:record` (a gateway's service account).
    pub async fn record(
        &self,
        credential: &CredentialInput,
        input: Body<inference::RecordInput>,
    ) -> IamResult<Reply<inference::RecordOutput>> {
        assert_inference(&self.ctx)?;
        let ctx = &self.ctx;
        let body = input.raw();
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let ticket_id = text(body.get("ticket"), "ticket", 256)?;
                let ticket = tx.get("inferenceTickets", &ticket_id).await?;
                let Some(ticket) = ticket.filter(|ticket| {
                    member(ticket, "tenantId") == tenant.id
                        // `ticket.expiresAt <= ctx.now()` refuses (NaN compares false, as in JavaScript).
                        && !matches!(
                            num(ticket, "expiresAt").partial_cmp(&ctx.now()),
                            Some(std::cmp::Ordering::Less | std::cmp::Ordering::Equal)
                        )
                }) else {
                    return Err(IamError::with_status(
                        "INVALID_TICKET",
                        "Unknown, used or expired inference ticket",
                        400,
                    )
                    .into());
                };
                tx.delete("inferenceTickets", member(&ticket, "id")).await?;
                // Metered as the caller the check saw, not re-authenticated: an ended session (or a deleted caller)
                // must not let a call it was allowed escape the budgets it counts against.
                let caller = ticket_caller(&tx, &ticket, &tenant.id).await?;
                let mut request = Map::new();
                request.insert("tenantId".into(), Value::String(tenant.id.clone()));
                request.insert(
                    "model".into(),
                    ticket.get("model").cloned().unwrap_or(Value::Null),
                );
                for key in [
                    "inputTokens",
                    "outputTokens",
                    "cacheReadTokens",
                    "cacheWriteTokens",
                    "status",
                    "requestId",
                    "latencyMs",
                ] {
                    if let Some(value) = body.get(key) {
                        request.insert(key.into(), value.clone());
                    }
                }
                let record = record_invocation(ctx, &tx, &caller, &Value::Object(request)).await?;
                let mut out = Map::new();
                out.insert("recorded".into(), Value::Bool(true));
                out.insert("costMicros".into(), number(record.cost_micros));
                Ok(Value::Object(out))
            })
        });
        let resource = string_member(body, "tenantId");
        reply(
            self.operate(
                credential,
                body,
                "iam:inference:record",
                &resource,
                mutation,
            )
            .await?,
        )
    }
}

/// The caller an inference ticket names, as the check saw them: the identity (a deleted stand-in when it is gone)
/// and the session (rebuilt from the ticket when it has ended), with the ticket's session kind, agent and delegation.
async fn ticket_caller(
    tx: &Store,
    ticket: &Record,
    tenant_id: &str,
) -> IamResult<AuthenticatedPrincipal> {
    let identity_id = member(ticket, "identityId").to_owned();
    let created_at = num(ticket, "createdAt");
    let identity: Identity = match tx.get("identities", &identity_id).await? {
        Some(record) => decode(record)?,
        None => {
            let mut stand_in = Map::new();
            stand_in.insert("id".into(), Value::String(identity_id.clone()));
            stand_in.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            stand_in.insert("kind".into(), Value::String("user".into()));
            stand_in.insert("name".into(), Value::String(identity_id.clone()));
            stand_in.insert("status".into(), Value::String("deleted".into()));
            stand_in.insert("emailVerified".into(), Value::Bool(false));
            stand_in.insert("owner".into(), Value::Bool(false));
            stand_in.insert("rootAdmin".into(), Value::Bool(false));
            stand_in.insert("createdAt".into(), number(created_at));
            decode(stand_in)?
        }
    };
    let stored = tx.get("sessions", member(ticket, "sessionId")).await?;
    let mut session = match &stored {
        Some(record) => record.clone(),
        None => {
            let mut rebuilt = Map::new();
            rebuilt.insert(
                "id".into(),
                ticket.get("sessionId").cloned().unwrap_or(Value::Null),
            );
            rebuilt.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
            rebuilt.insert("identityId".into(), Value::String(identity_id));
            rebuilt.insert("createdAt".into(), number(created_at));
            rebuilt.insert("lastSeenAt".into(), number(created_at));
            rebuilt.insert(
                "expiresAt".into(),
                ticket.get("expiresAt").cloned().unwrap_or(Value::Null),
            );
            rebuilt.insert("mfa".into(), Value::Bool(false));
            // Members the Rust session type requires; TypeScript's stand-in leaves them out and never reads them.
            rebuilt.insert("tokenHash".into(), Value::String(String::new()));
            rebuilt.insert("authenticatedAt".into(), number(created_at));
            rebuilt
        }
    };
    let kind = match ticket.get("sessionKind") {
        None | Some(Value::Null) => stored
            .as_ref()
            .and_then(|record| record.get("kind"))
            .filter(|kind| !kind.is_null())
            .cloned()
            .unwrap_or_else(|| Value::String("user".into())),
        Some(kind) => kind.clone(),
    };
    session.insert("kind".into(), kind);
    if let Some(agent_id) = ticket.get("agentId")
        && session.get("kind").and_then(Value::as_str) == Some("delegated")
    {
        session.insert("agentId".into(), agent_id.clone());
    }
    if let Some(delegation_id) = ticket.get("delegationId") {
        session.insert("delegationId".into(), delegation_id.clone());
    }
    let session: Session = decode(session)?;
    Ok(AuthenticatedPrincipal {
        identity,
        session,
        device_proof: None,
    })
}

// --- The runtime ----------------------------------------------------------------------------------------------------

/// A checked call the in-process gateway may make: the caller, the model and the provider credential.
#[derive(Debug, Clone)]
pub struct GatewayPermit {
    pub principal: AuthenticatedPrincipal,
    pub tenant_id: String,
    /// The allowed check (`InvocationCheck` with `allowed: true`) as TypeScript returns it.
    pub check: Value,
    pub upstream_model: String,
    pub provider: ProviderCredential,
}

impl GatewayPermit {
    /// The permit as the TypeScript object encodes (`provider` carries the opened key: never expose it).
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("principal".into(), principal_json(&self.principal));
        out.insert("tenantId".into(), Value::String(self.tenant_id.clone()));
        out.insert("check".into(), self.check.clone());
        out.insert(
            "upstreamModel".into(),
            Value::String(self.upstream_model.clone()),
        );
        out.insert(
            "provider".into(),
            serde_json::to_value(&self.provider).map_or(Value::Null, js_json),
        );
        Value::Object(out)
    }
}

/// What `iam.inference.authorize` answers as TypeScript returns it: the permit, or `{ denied: check }`.
pub fn authorization_json(outcome: &GatewayAuthorization) -> Value {
    match outcome {
        GatewayAuthorization::Permit(permit) => permit.to_json(),
        GatewayAuthorization::Denied(check) => {
            let mut out = Map::new();
            out.insert("denied".into(), check.to_json());
            Value::Object(out)
        }
    }
}

/// `iam.inference`: the server-side half of inference, for the gateway and for applications that call models
/// themselves. `authorize` checks a credential for a model and returns the opened provider credential (never expose
/// it); `record` meters a call; `gateway` builds the HTTP gateway.
pub fn create_inference_runtime(ctx: &Arc<ServerContext>) -> IamResult<InferenceRuntime> {
    Ok(InferenceRuntime { ctx: ctx.clone() })
}

/// `createInferenceRuntime(ctx)`: `models`, `gateway`, `authorize`, `ownsResponse` and `record` (see
/// api/inference.ts).
#[derive(Clone)]
pub struct InferenceRuntime {
    ctx: Arc<ServerContext>,
}

impl InferenceRuntime {
    /// The enabled models a credential may invoke in its session's tenant (or `tenantId`), as TypeScript returns them.
    pub async fn models(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&str>,
    ) -> IamResult<Value> {
        Ok(models_json(
            &self.public_models(credential, tenant_id).await?,
        ))
    }

    /// [`InferenceRuntime::models`] as the typed views.
    pub async fn public_models(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&str>,
    ) -> IamResult<Vec<PublicModel>> {
        let ctx = &self.ctx;
        assert_inference(ctx)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let tenant_id = tenant_id.map(str::to_owned);
        ctx.store
            .transaction(|tx| {
                let (authenticated, tenant_id) = (&authenticated, &tenant_id);
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let tenant_id = tenant_id
                        .clone()
                        .unwrap_or_else(|| principal.session.tenant_id.clone());
                    invocable_models(ctx, &tx, &principal, &tenant_id).await
                }
            })
            .await
    }

    /// The HTTP inference gateway: Anthropic `POST /v1/messages` (and `/v1/messages/count_tokens`), OpenAI `POST
    /// /v1/chat/completions`, `/v1/responses` and `/v1/embeddings`, and `GET /v1/models`, authorized and metered per
    /// caller. Mount it on any route.
    pub fn gateway(&self, options: Option<&InferenceGatewayOptions>) -> InferenceGateway {
        create_inference_gateway(Arc::new(self.clone()), options)
    }

    /// Authenticates `credential`, checks `model` for it in the credential's tenant (or `tenantId`), with the
    /// provider-run `tools` the request asks for, and on success returns the permit with the provider's opened key.
    /// Fails with FEATURE_DISABLED when inference is off.
    pub async fn authorize(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<GatewayAuthorization> {
        let ctx = &self.ctx;
        assert_inference(ctx)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        ctx.store
            .transaction(|tx| {
                let authenticated = &authenticated;
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let tenant_value = match input.get("tenantId") {
                        None | Some(Value::Null) => {
                            Value::String(principal.session.tenant_id.clone())
                        }
                        Some(value) => value.clone(),
                    };
                    let tenant_id = crate::js::js_string(Some(&tenant_value));
                    let mut request = Map::new();
                    request.insert("tenantId".into(), tenant_value);
                    for key in ["model", "estimatedTokens", "tools"] {
                        if let Some(value) = input.get(key) {
                            request.insert(key.into(), value.clone());
                        }
                    }
                    let check =
                        check_invocation(ctx, &tx, &principal, &Value::Object(request)).await?;
                    if !check.allowed {
                        return Ok(GatewayAuthorization::Denied(Box::new(check)));
                    }
                    let name = check
                        .model
                        .as_ref()
                        .map(|model| model.name.clone())
                        .unwrap_or_default();
                    let found = resolve_model(ctx, &tx, &tenant_id, &name).await?;
                    let Some((model, provider)) = found
                        .and_then(|found| found.provider.map(|provider| (found.model, provider)))
                    else {
                        return Err(not_found("Model provider not found"));
                    };
                    let provider = provider_credential(ctx, &tx, &provider).await?;
                    Ok(GatewayAuthorization::Permit(Box::new(GatewayPermit {
                        principal,
                        tenant_id,
                        check: check.to_json(),
                        upstream_model: model.upstream_model,
                        provider,
                    })))
                }
            })
            .await
    }

    /// Whether a Responses API response was created through the gateway by the permit's caller, at its provider.
    pub async fn owns_response(
        &self,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        provider_id: &str,
        response_id: &str,
    ) -> IamResult<bool> {
        let ctx = &self.ctx;
        let (principal, tenant_id, provider_id, response_id) = (
            principal.clone(),
            tenant_id.to_owned(),
            provider_id.to_owned(),
            response_id.to_owned(),
        );
        ctx.store
            .transaction(|tx| async move {
                owns_inference_response(
                    ctx,
                    &tx,
                    &principal,
                    &tenant_id,
                    &response_id,
                    &provider_id,
                )
                .await
            })
            .await
    }

    /// Meters a call made under a permit (its `principal` and `tenantId`): `usage` is an `InvocationRecord` without
    /// `tenantId`.
    pub async fn record(
        &self,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        usage: &Value,
    ) -> IamResult<InferenceUsageRecord> {
        let ctx = &self.ctx;
        let mut request = usage.as_object().cloned().unwrap_or_default();
        request.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        let request = Value::Object(request);
        let principal = principal.clone();
        ctx.store
            .transaction(|tx| {
                let (principal, request) = (&principal, &request);
                async move { record_invocation(ctx, &tx, principal, request).await }
            })
            .await
    }

    /// The conformance server's `call` for a member of this object.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let arg = |index: usize| args.get(index);
        let credential = || crate::api::credential_from_json(arg(0));
        let permit = || -> IamResult<(AuthenticatedPrincipal, String)> {
            let permit = arg(0);
            Ok((
                principal_from_json(permit.and_then(|permit| permit.get("principal")))?,
                crate::js::js_string(permit.and_then(|permit| permit.get("tenantId"))),
            ))
        };
        match method {
            "models" => Some(
                self.models(&credential(), arg(1).and_then(Value::as_str))
                    .await,
            ),
            "authorize" => Some(
                self.authorize(&credential(), arg(1).unwrap_or(&Value::Null))
                    .await
                    .map(|outcome| authorization_json(&outcome)),
            ),
            "ownsResponse" => Some(
                async {
                    let (principal, tenant_id) = permit()?;
                    let provider_id = arg(0)
                        .and_then(|permit| permit.get("provider"))
                        .and_then(|provider| provider.get("id"))
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let response_id = crate::js::js_string(arg(1));
                    self.owns_response(&principal, &tenant_id, &provider_id, &response_id)
                        .await
                        .map(Value::Bool)
                }
                .await,
            ),
            "record" => Some(
                async {
                    let (principal, tenant_id) = permit()?;
                    let record = self
                        .record(&principal, &tenant_id, arg(1).unwrap_or(&Value::Null))
                        .await?;
                    Ok(serde_json::to_value(&record).map_or(Value::Null, js_json))
                }
                .await,
            ),
            "gateway" => {
                // The handler is a function: JSON callers get its encoding (`{"$function": name}`). Options that are
                // functions in TypeScript (`fetch`, `onError`) have no JSON form and keep their defaults.
                let options = arg(0);
                let text = |key: &str| {
                    options
                        .and_then(|options| options.get(key))
                        .and_then(Value::as_str)
                        .map(str::to_owned)
                };
                let count = |key: &str| {
                    options
                        .and_then(|options| options.get(key))
                        .and_then(core_js::as_number)
                };
                let _gateway = self.gateway(Some(&InferenceGatewayOptions {
                    base_path: text("basePath"),
                    timeout_ms: count("timeoutMs"),
                    anthropic_version: text("anthropicVersion"),
                    max_body_bytes: count("maxBodyBytes"),
                    ..InferenceGatewayOptions::default()
                }));
                let mut encoded = Map::new();
                encoded.insert("$function".into(), Value::String("anonymous".into()));
                Some(Ok(Value::Object(encoded)))
            }
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl GatewayRuntime for InferenceRuntime {
    async fn authorize(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<GatewayAuthorization> {
        InferenceRuntime::authorize(self, credential, input).await
    }

    async fn record(&self, permit: &GatewayPermit, usage: &Value) -> IamResult<Value> {
        let record =
            InferenceRuntime::record(self, &permit.principal, &permit.tenant_id, usage).await?;
        Ok(serde_json::to_value(&record).map_or(Value::Null, js_json))
    }

    async fn models(&self, credential: &CredentialInput) -> IamResult<Vec<PublicModel>> {
        self.public_models(credential, None).await
    }

    async fn owns_response(&self, permit: &GatewayPermit, response_id: &str) -> IamResult<bool> {
        InferenceRuntime::owns_response(
            self,
            &permit.principal,
            &permit.tenant_id,
            &permit.provider.id,
            response_id,
        )
        .await
    }
}
