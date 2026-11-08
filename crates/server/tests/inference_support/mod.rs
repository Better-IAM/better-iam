//! Shared setup of the inference suites (tests/inference.test.ts, tests/inference-gateway.test.ts,
//! tests/security-inference.test.ts): the organization fixture with the `inference` option, providers, models and
//! budgets written as `inference.createProvider`, `inference.createModel` and `inference.setBudget` write them (so the
//! suites do not depend on the `inference` API group), and a gateway runtime built the way `createInferenceRuntime`
//! builds `iam.inference` (`authorize`, `record`, `models`, `ownsResponse`) over the module's functions.

#![allow(dead_code)]

use std::sync::{Arc, Mutex};

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, IamError, IamResult, IamStoreExt, Record,
    ResourceRef,
};
use better_iam_server::api::inference::GatewayPermit;
use better_iam_server::context::ServerContext;
use better_iam_server::inference::{
    INFERENCE_ACTION, INFERENCE_RESOURCE_TYPE, InferenceUsageRecord, InvocationCheck, PublicModel,
    assert_inference, check_invocation, owns_inference_response, provider_credential, public_model,
    record_invocation, resolve_model, seal_provider_key, visible_models,
};
use better_iam_server::inference_gateway::{
    GatewayAuthorization, GatewayFetch, GatewayRuntime, InferenceGateway, InferenceGatewayOptions,
    UpstreamResponse, create_inference_gateway,
};
use better_iam_server::options::{AuthorizationRequest, InferenceOptions, ResourceTarget, Toggle};
use better_iam_server::safe_fetch::{FetchBody, FetchError, FetchRequest};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::organization_fixture::{Org, organization};

pub const SECRET: &str = "organization-fixture-secret-with-32-characters";

/// The organization fixture with `inference` set (`true` when `options` is None).
pub async fn inference_org(options: Option<InferenceOptions>) -> Org {
    organization(move |configure| {
        configure.inference = Some(match options {
            Some(options) => Toggle::Options(options),
            None => Toggle::Flag(true),
        });
    })
    .await
}

fn key_hint(key: &str) -> String {
    let chars: Vec<char> = key.chars().collect();
    let tail: String = chars[chars.len().saturating_sub(4)..].iter().collect();
    format!("…{tail}")
}

/// A provider as `inference.createProvider` stores it.
pub async fn create_provider(
    f: &Org,
    tenant_id: &str,
    name: &str,
    kind: &str,
    api_key: &str,
    base_url: Option<&str>,
) -> Record {
    let id = better_iam_server::utils::id();
    let now = f.now();
    let base_url = base_url
        .map(str::to_owned)
        .or_else(|| better_iam_server::inference::provider_base_url(kind).map(str::to_owned))
        .expect("base URL");
    f.insert(
        "inferenceProviders",
        json!({
            "id": id,
            "tenantId": tenant_id,
            "uniqueKey": format!("name:{}", name.to_lowercase()),
            "name": name,
            "kind": kind,
            "baseUrl": base_url,
            "keySealed": seal_provider_key(SECRET, &id, api_key),
            "keyHint": key_hint(api_key),
            "createdAt": now,
            "updatedAt": now,
            "keyRotatedAt": now,
        }),
    )
    .await
}

/// A model as `inference.createModel` stores it, with the optional fields of `extra`.
pub async fn create_model(
    f: &Org,
    tenant_id: &str,
    name: &str,
    provider_id: &str,
    upstream_model: &str,
    extra: Value,
) -> Record {
    let now = f.now();
    let mut model = json!({
        "id": better_iam_server::utils::id(),
        "tenantId": tenant_id,
        "uniqueKey": name,
        "name": name,
        "providerId": provider_id,
        "upstreamModel": upstream_model,
        "enabled": true,
        "createdAt": now,
        "updatedAt": now,
    });
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        model[key] = value;
    }
    f.insert("inferenceModels", model).await
}

/// `inference.updateModel`: sets (or, with null, removes) fields of a model found by name.
pub async fn update_model(f: &Org, tenant_id: &str, name: &str, changes: Value) {
    let mut model = f
        .find(
            "inferenceModels",
            Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("uniqueKey", name),
        )
        .await
        .into_iter()
        .next()
        .expect("model");
    for (key, value) in changes.as_object().cloned().unwrap_or_default() {
        if value.is_null() {
            model.shift_remove(&key);
        } else {
            model.insert(key, value);
        }
    }
    model.insert("updatedAt".into(), json!(f.now()));
    f.put("inferenceModels", model).await;
}

/// A budget as `inference.setBudget` stores it (`fields` holds subjectType, subjectId, scope, period and limits).
pub async fn set_budget(f: &Org, tenant_id: &str, name: &str, fields: Value) -> Record {
    let now = f.now();
    let mut budget = Map::new();
    budget.insert("id".into(), json!(better_iam_server::utils::id()));
    budget.insert("tenantId".into(), json!(tenant_id));
    budget.insert(
        "uniqueKey".into(),
        json!(format!("name:{}", name.to_lowercase())),
    );
    budget.insert("name".into(), json!(name));
    let fields = fields.as_object().cloned().unwrap_or_default();
    let subject_type = fields["subjectType"].as_str().unwrap().to_owned();
    budget.insert("subjectType".into(), json!(subject_type));
    budget.insert(
        "subjectId".into(),
        if subject_type == "tenant" {
            json!(tenant_id)
        } else {
            fields["subjectId"].clone()
        },
    );
    let scope = fields.get("scope").cloned().unwrap_or(json!("shared"));
    budget.insert(
        "scope".into(),
        if subject_type == "identity" {
            json!("shared")
        } else {
            scope
        },
    );
    budget.insert("period".into(), fields["period"].clone());
    for key in [
        "maxTokens",
        "maxCostMicros",
        "maxRequests",
        "models",
        "alertAtPercent",
    ] {
        if let Some(value) = fields.get(key) {
            budget.insert(key.into(), value.clone());
        }
    }
    budget.insert("createdAt".into(), json!(now));
    budget.insert("updatedAt".into(), json!(now));
    f.insert("inferenceBudgets", Value::Object(budget)).await
}

pub fn id_of(record: &Record) -> String {
    record["id"].as_str().unwrap().to_owned()
}

/// The gateway runtime `createInferenceRuntime(ctx)` builds, over the inference module.
pub struct Runtime {
    pub ctx: Arc<ServerContext>,
}

impl Runtime {
    pub fn new(f: &Org) -> Arc<Self> {
        Arc::new(Self {
            ctx: f.iam.ctx.clone(),
        })
    }

    async fn principal(&self, credential: &CredentialInput) -> IamResult<AuthenticatedPrincipal> {
        self.ctx.principals()?.authenticate(credential).await
    }

    /// `iam.inference.authorize(credential, input)`.
    pub async fn authorize_value(
        &self,
        credential: &CredentialInput,
        input: Value,
    ) -> IamResult<GatewayAuthorization> {
        self.authorize(credential, &input).await
    }

    /// `iam.inference.record(permit, usage)` with the record it stores.
    pub async fn record_usage(
        &self,
        permit: &GatewayPermit,
        usage: Value,
    ) -> IamResult<InferenceUsageRecord> {
        let ctx = self.ctx.clone();
        let principal = permit.principal.clone();
        let mut input = usage.as_object().cloned().unwrap_or_default();
        input.insert("tenantId".into(), json!(permit.tenant_id));
        let input = Value::Object(input);
        self.ctx
            .store
            .transaction(|tx| async move { record_invocation(&ctx, &tx, &principal, &input).await })
            .await
    }

    /// The invocation check of `api.inference.check` (without the ticket).
    pub async fn check(
        &self,
        credential: &CredentialInput,
        input: Value,
    ) -> IamResult<InvocationCheck> {
        let authenticated = self.principal(credential).await?;
        let ctx = self.ctx.clone();
        self.ctx
            .store
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                check_invocation(&ctx, &tx, &principal, &input).await
            })
            .await
    }
}

#[async_trait::async_trait]
impl GatewayRuntime for Runtime {
    async fn authorize(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<GatewayAuthorization> {
        assert_inference(&self.ctx)?;
        let authenticated = self.principal(credential).await?;
        let ctx = self.ctx.clone();
        let input = input.clone();
        self.ctx
            .store
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let tenant_id = input
                    .get("tenantId")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
                    .unwrap_or_else(|| principal.session.tenant_id.clone());
                let mut check_input = Map::new();
                check_input.insert("tenantId".into(), json!(tenant_id));
                check_input.insert(
                    "model".into(),
                    input.get("model").cloned().unwrap_or(Value::Null),
                );
                for key in ["estimatedTokens", "tools"] {
                    if let Some(value) = input.get(key) {
                        check_input.insert(key.into(), value.clone());
                    }
                }
                let check =
                    check_invocation(&ctx, &tx, &principal, &Value::Object(check_input)).await?;
                if !check.allowed {
                    return Ok(GatewayAuthorization::Denied(Box::new(check)));
                }
                let name = check.model.as_ref().expect("model").name.clone();
                let provider = resolve_model(&ctx, &tx, &tenant_id, &name)
                    .await?
                    .and_then(|found| found.provider.map(|provider| (found.model, provider)));
                let Some((model, provider)) = provider else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Model provider not found",
                        404,
                    ));
                };
                let provider = provider_credential(&ctx, &tx, &provider).await?;
                Ok(GatewayAuthorization::Permit(Box::new(GatewayPermit {
                    principal,
                    tenant_id,
                    check: check.to_json(),
                    upstream_model: model.upstream_model,
                    provider,
                })))
            })
            .await
    }

    async fn record(&self, permit: &GatewayPermit, usage: &Value) -> IamResult<Value> {
        let record = self.record_usage(permit, usage.clone()).await?;
        Ok(serde_json::to_value(record).unwrap())
    }

    async fn models(&self, credential: &CredentialInput) -> IamResult<Vec<PublicModel>> {
        assert_inference(&self.ctx)?;
        let authenticated = self.principal(credential).await?;
        let ctx = self.ctx.clone();
        self.ctx
            .store
            .transaction(|tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                let tenant_id = principal.session.tenant_id.clone();
                let mut result = Vec::new();
                for found in visible_models(&ctx, &tx, &tenant_id).await? {
                    let view = public_model(&found.model, found.provider.as_ref(), &tenant_id);
                    if !view.enabled {
                        continue;
                    }
                    let decision = ctx
                        .decisions()?
                        .decide(
                            &tx,
                            &principal,
                            &AuthorizationRequest {
                                credential: CredentialInput::default(),
                                tenant_id: tenant_id.clone(),
                                action: INFERENCE_ACTION.to_owned(),
                                resource: ResourceTarget {
                                    kind: INFERENCE_RESOURCE_TYPE.to_owned(),
                                    id: found.model.name.clone(),
                                },
                            },
                            false,
                        )
                        .await?;
                    if decision.allowed {
                        result.push(view);
                    }
                }
                Ok(result)
            })
            .await
    }

    async fn owns_response(&self, permit: &GatewayPermit, response_id: &str) -> IamResult<bool> {
        let ctx = self.ctx.clone();
        let permit = permit.clone();
        let response_id = response_id.to_owned();
        self.ctx
            .store
            .transaction(|tx| async move {
                owns_inference_response(
                    &ctx,
                    &tx,
                    &permit.principal,
                    &permit.tenant_id,
                    &response_id,
                    &permit.provider.id,
                )
                .await
            })
            .await
    }
}

/// `iam.inference.authorize` expecting a permit.
pub async fn permit(runtime: &Runtime, token: &str, model: &str) -> GatewayPermit {
    match runtime
        .authorize_value(&bearer(token), json!({ "model": model }))
        .await
        .expect("authorize")
    {
        GatewayAuthorization::Permit(permit) => *permit,
        GatewayAuthorization::Denied(denied) => {
            panic!("denied: {}", denied.reason.unwrap_or_default())
        }
    }
}

pub fn bearer(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

pub fn token_of(credential: &CredentialInput) -> String {
    credential.token.clone().unwrap()
}

/// One request the fake provider received.
#[derive(Debug, Clone)]
pub struct Upstream {
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Value,
}

impl Upstream {
    pub fn header(&self, name: &str) -> Option<String> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.clone())
    }
}

/// `sse(events)`: server-sent events with optional event names.
pub fn sse(events: &[(Option<&str>, Value)]) -> String {
    events
        .iter()
        .map(|(event, data)| {
            let data = match data {
                Value::String(text) => text.clone(),
                other => better_iam_core::js::stringify(other),
            };
            match event {
                Some(event) => format!("event: {event}\ndata: {data}\n\n"),
                None => format!("data: {data}\n\n"),
            }
        })
        .collect()
}

fn json_response(status: u16, body: Value, extra: &[(&str, &str)]) -> UpstreamResponse {
    let mut headers = vec![("content-type".to_owned(), "application/json".to_owned())];
    for (name, value) in extra {
        headers.push(((*name).to_owned(), (*value).to_owned()));
    }
    UpstreamResponse::new(status, headers, better_iam_core::js::stringify(&body))
}

/// A response whose body arrives in 17-byte pieces, splitting events across chunks.
fn chunked_stream(text: String) -> UpstreamResponse {
    let bytes = text.into_bytes();
    let chunks: Vec<Result<Bytes, FetchError>> = bytes
        .chunks(17)
        .map(|chunk| Ok(Bytes::copy_from_slice(chunk)))
        .collect();
    UpstreamResponse::streaming(
        200,
        vec![("content-type".to_owned(), "text/event-stream".to_owned())],
        futures::stream::iter(chunks),
    )
}

/// What the fake provider answers for a request.
pub fn fake_answer(url: &str, body: &Value, calls: usize) -> UpstreamResponse {
    if url.ends_with("/v1/messages/count_tokens") {
        return json_response(200, json!({ "input_tokens": 42 }), &[]);
    }
    if url.ends_with("/embeddings") {
        return json_response(
            200,
            json!({
                "object": "list",
                "model": body["model"],
                "data": [{ "object": "embedding", "index": 0, "embedding": [0.1, 0.2] }],
                "usage": { "prompt_tokens": 9, "total_tokens": 9 },
            }),
            &[],
        );
    }
    if url.ends_with("/responses") {
        let response = |usage: Value| json!({ "id": format!("resp_{calls}"), "object": "response", "model": body["model"], "usage": usage });
        let used = json!({
            "input_tokens": 30,
            "input_tokens_details": { "cached_tokens": 10 },
            "output_tokens": 12,
            "output_tokens_details": { "reasoning_tokens": 4 },
            "total_tokens": 42,
        });
        if body["stream"] != json!(true) {
            return json_response(200, response(used), &[]);
        }
        let text = sse(&[
            (
                Some("response.created"),
                json!({ "type": "response.created", "response": response(Value::Null) }),
            ),
            (
                Some("response.output_text.delta"),
                json!({ "type": "response.output_text.delta", "delta": "Hi" }),
            ),
            (
                Some("response.completed"),
                json!({ "type": "response.completed", "response": response(used) }),
            ),
        ]);
        return UpstreamResponse::new(
            200,
            vec![("content-type".to_owned(), "text/event-stream".to_owned())],
            text,
        );
    }
    let anthropic = url.ends_with("/v1/messages");
    if body["stream"] != json!(true) {
        let answer = if anthropic {
            json!({
                "id": "msg_1",
                "type": "message",
                "model": body["model"],
                "content": [{ "type": "text", "text": "Hello" }],
                "usage": { "input_tokens": 10, "output_tokens": 20, "cache_read_input_tokens": 5 },
            })
        } else {
            json!({
                "id": "chatcmpl_1",
                "object": "chat.completion",
                "model": body["model"],
                "choices": [{ "index": 0, "message": { "role": "assistant", "content": "Hi" } }],
                "usage": { "prompt_tokens": 12, "completion_tokens": 8, "prompt_tokens_details": { "cached_tokens": 2 } },
            })
        };
        return json_response(200, answer, &[("request-id", "req_upstream")]);
    }
    let text = if anthropic {
        sse(&[
            (
                Some("message_start"),
                json!({ "type": "message_start", "message": { "usage": { "input_tokens": 10, "output_tokens": 1 } } }),
            ),
            (
                Some("content_block_delta"),
                json!({ "type": "content_block_delta", "delta": { "type": "text_delta", "text": "Hel" } }),
            ),
            (
                Some("message_delta"),
                json!({ "type": "message_delta", "usage": { "output_tokens": 25 } }),
            ),
            (Some("message_stop"), json!({ "type": "message_stop" })),
        ])
    } else {
        sse(&[
            (
                None,
                json!({ "choices": [{ "delta": { "content": "Hi" } }], "usage": null }),
            ),
            (
                None,
                json!({ "choices": [], "usage": { "prompt_tokens": 7, "completion_tokens": 3 } }),
            ),
            (None, json!("[DONE]")),
        ])
    };
    chunked_stream(text)
}

/// Reads a fetch request the way the fake provider records it.
pub fn upstream_of(request: &FetchRequest) -> Upstream {
    let body = match &request.body {
        Some(FetchBody::Text(text)) => serde_json::from_str(text).unwrap(),
        Some(FetchBody::Bytes(bytes)) => serde_json::from_slice(bytes).unwrap(),
        None => Value::Null,
    };
    Upstream {
        url: request.url.clone(),
        headers: request.headers.clone(),
        body,
    }
}

/// A fake provider: records each request and answers from the model and `stream` flag.
pub fn fake_upstream() -> (Arc<Mutex<Vec<Upstream>>>, GatewayFetch) {
    let calls: Arc<Mutex<Vec<Upstream>>> = Arc::new(Mutex::new(Vec::new()));
    let recorded = calls.clone();
    let fetch: GatewayFetch = Arc::new(move |request: FetchRequest| {
        let upstream = upstream_of(&request);
        let count = {
            let mut calls = recorded.lock().unwrap();
            calls.push(upstream.clone());
            calls.len()
        };
        let answer = fake_answer(&upstream.url, &upstream.body, count);
        Box::pin(async move { Ok(answer) })
    });
    (calls, fetch)
}

/// The gateway's own test setup: Acme with `inference: { allowCustomBaseUrls: true }`, an Anthropic provider and an
/// OpenAI-compatible router, the models `sonnet` and `open-model`, and a gateway mounted at `/ai` over a fake
/// provider.
pub struct GatewaySetup {
    pub f: Org,
    pub runtime: Arc<Runtime>,
    pub calls: Arc<Mutex<Vec<Upstream>>>,
    pub fetch: GatewayFetch,
    pub gateway: InferenceGateway,
    pub anthropic: Record,
    pub router: Record,
}

pub async fn gateway_setup() -> GatewaySetup {
    let f = inference_org(Some(InferenceOptions {
        allow_custom_base_urls: Some(true),
        ..InferenceOptions::default()
    }))
    .await;
    let tenant = f.tenant_id.clone();
    let anthropic = create_provider(
        &f,
        &tenant,
        "Anthropic",
        "anthropic",
        "sk-ant-provider-key-9999",
        None,
    )
    .await;
    let router = create_provider(
        &f,
        &tenant,
        "Router",
        "openai-compatible",
        "sk-router-key-8888",
        Some("https://router.example/api/v1"),
    )
    .await;
    create_model(
        &f,
        &tenant,
        "sonnet",
        &id_of(&anthropic),
        "claude-sonnet-5",
        json!({ "inputPricePerMTok": 3, "outputPricePerMTok": 15, "cachedInputPricePerMTok": 0.3 }),
    )
    .await;
    create_model(
        &f,
        &tenant,
        "open-model",
        &id_of(&router),
        "vendor/open-model-70b",
        json!({ "inputPricePerMTok": 1, "outputPricePerMTok": 1 }),
    )
    .await;
    let (calls, fetch) = fake_upstream();
    let runtime = Runtime::new(&f);
    let gateway = create_inference_gateway(
        runtime.clone(),
        Some(&InferenceGatewayOptions {
            base_path: Some("/ai".to_owned()),
            fetch: Some(fetch.clone()),
            ..InferenceGatewayOptions::default()
        }),
    );
    GatewaySetup {
        f,
        runtime,
        calls,
        fetch,
        gateway,
        anthropic,
        router,
    }
}

/// A gateway request: POST with a JSON body, or GET without one.
pub fn gateway_request(
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> http::Request<Bytes> {
    let mut builder = http::Request::builder()
        .method(if body.is_some() { "POST" } else { "GET" })
        .uri(format!("http://gateway.test/ai{path}"));
    if let Some(token) = token {
        builder = builder.header("authorization", format!("Bearer {token}"));
    }
    builder = builder.header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    let body = body
        .map(|body| Bytes::from(body.to_string()))
        .unwrap_or_default();
    builder.body(body).unwrap()
}

/// Usage per model, as `inference.usage({ groupBy: 'model' })` reports it: requests, tokens and cost.
pub async fn usage_by_model(f: &Org) -> Vec<Value> {
    let records = f
        .find(
            "inferenceUsage",
            Filter::new().eq("tenantId", f.tenant_id.clone()),
        )
        .await;
    let mut rows: indexmap::IndexMap<String, (f64, f64, f64, f64, f64)> = indexmap::IndexMap::new();
    for record in records {
        let model = record["model"].as_str().unwrap().to_owned();
        let row = rows.entry(model).or_default();
        let number = |key: &str| record.get(key).and_then(Value::as_f64).unwrap_or(0.0);
        row.0 += 1.0;
        row.1 += number("inputTokens");
        row.2 += number("outputTokens");
        row.3 += number("cacheReadTokens");
        row.4 += number("costMicros");
    }
    let mut rows: Vec<Value> = rows
        .into_iter()
        .map(|(key, (requests, input, output, cached, cost))| {
            json!({
                "key": key,
                "requests": requests,
                "inputTokens": input,
                "outputTokens": output,
                "cacheReadTokens": cached,
                "costMicros": (cost * 1000.0).round() / 1000.0,
            })
        })
        .collect();
    rows.sort_by(|a, b| a["key"].as_str().cmp(&b["key"].as_str()));
    rows
}

/// Every audit event of the organization, oldest first.
pub async fn audit_actions(f: &Org) -> Vec<String> {
    f.find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
        .await
        .into_iter()
        .map(|event| event["action"].as_str().unwrap_or_default().to_owned())
        .collect()
}

/// `iam.authorize` for a model.
pub async fn may_invoke(f: &Org, token: &str, model: &str) -> bool {
    f.iam
        .authorize(&AuthorizationRequest {
            credential: bearer(token),
            tenant_id: f.tenant_id.clone(),
            action: INFERENCE_ACTION.to_owned(),
            resource: ResourceTarget {
                kind: INFERENCE_RESOURCE_TYPE.to_owned(),
                id: model.to_owned(),
            },
        })
        .await
        .expect("authorize")
        .allowed
}

pub fn model_ref(f: &Org, name: &str) -> ResourceRef {
    ResourceRef {
        tenant_id: f.tenant_id.clone(),
        kind: INFERENCE_RESOURCE_TYPE.to_owned(),
        id: name.to_owned(),
    }
}
