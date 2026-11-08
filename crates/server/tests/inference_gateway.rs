//! The inference gateway: ported from tests/inference-gateway.test.ts and the stored-reference case of
//! tests/security-inference.test.ts. The gateway runs over the runtime `createInferenceRuntime` builds
//! (inference_support), with providers, models and budgets written as the `inference` API group writes them.

mod inference_support;
mod organization_fixture;

use std::sync::Arc;

use better_iam_server::inference_gateway::{
    GatewayFetch, GatewayResponse, GatewayRuntime, InferenceGatewayOptions, UpstreamResponse,
    UsageFormat, create_inference_gateway, provider_tools_of, stored_reference, usage_from,
};
use better_iam_server::safe_fetch::FetchRequest;
use bytes::Bytes;
use inference_support::{
    GatewaySetup, create_model, create_provider, fake_answer, gateway_request, gateway_setup,
    id_of, set_budget, sse, token_of, update_model, upstream_of, usage_by_model,
};
use organization_fixture::{assert_matches, body, ok, run};
use serde_json::{Map, Value, json};

async fn call(
    s: &GatewaySetup,
    path: &str,
    token: Option<&str>,
    body: Option<Value>,
    headers: &[(&str, &str)],
) -> GatewayResponse {
    s.gateway
        .handle(&gateway_request(path, token, body, headers))
        .await
}

fn header(response: &GatewayResponse, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}

async fn json_of(response: GatewayResponse) -> Value {
    let text = response.into_body().text().await.unwrap();
    serde_json::from_str(&text).unwrap()
}

async fn text_of(response: GatewayResponse) -> String {
    response.into_body().text().await.unwrap()
}

fn owner(s: &GatewaySetup) -> String {
    token_of(&s.f.owner_credential)
}

fn calls(s: &GatewaySetup) -> Vec<inference_support::Upstream> {
    s.calls.lock().unwrap().clone()
}

fn object(value: Value) -> Map<String, Value> {
    value.as_object().cloned().unwrap()
}

/// A role allowing `statements` to an identity of the organization.
async fn grant(s: &GatewaySetup, identity_id: &str, statements: Value) {
    s.f.grant(identity_id, statements).await;
}

async fn agent_key(s: &GatewaySetup, name: &str, resources: Value) -> (String, String) {
    let f = &s.f;
    let agent = ok(f
        .iam
        .api
        .agents
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "name": name })),
        )
        .await);
    let agent_id = agent["id"].as_str().unwrap().to_owned();
    grant(
        s,
        &agent_id,
        json!([{ "effect": "allow", "actions": ["inference:invoke"], "resources": resources }]),
    )
    .await;
    let key = ok(f
        .iam
        .api
        .credentials
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "identityId": agent_id })),
        )
        .await);
    (agent_id, key["token"].as_str().unwrap().to_owned())
}

#[test]
fn passes_anthropic_messages_through_with_the_sealed_key_and_meters_the_usage() {
    run(|| async move {
        let s = gateway_setup().await;
        let response = call(
            &s,
            "/v1/messages",
            Some(&owner(&s)),
            Some(json!({ "model": "sonnet", "max_tokens": 256, "messages": [{ "role": "user", "content": "Hello" }] })),
            &[],
        )
        .await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            header(&response, "x-better-iam-model").as_deref(),
            Some("sonnet")
        );
        assert_eq!(
            header(&response, "x-upstream-request-id").as_deref(),
            Some("req_upstream")
        );
        assert!(header(&response, "x-better-iam-request-id").is_some());
        assert_matches(
            &json_of(response).await,
            json!({ "model": "sonnet", "content": [{ "text": "Hello" }] }),
        );
        let sent = calls(&s).remove(0);
        assert_eq!(sent.url, "https://api.anthropic.com/v1/messages");
        assert_eq!(
            sent.header("x-api-key").as_deref(),
            Some("sk-ant-provider-key-9999")
        );
        assert_eq!(
            sent.header("anthropic-version").as_deref(),
            Some("2023-06-01")
        );
        assert_eq!(sent.header("authorization"), None);
        assert_eq!(sent.body["model"], json!("claude-sonnet-5"));
        // 10 × $3 + 5 cached × $0.30 + 20 × $15 per million = 331.5 micro-dollars.
        let rows = usage_by_model(&s.f).await;
        assert_eq!(rows.len(), 1);
        assert_matches(
            &rows[0],
            json!({ "key": "sonnet", "inputTokens": 10.0, "outputTokens": 20.0, "cacheReadTokens": 5.0, "costMicros": 331.5 }),
        );
    });
}

#[test]
fn streams_server_sent_events_untouched_and_meters_them_when_the_stream_ends() {
    run(|| async move {
        let s = gateway_setup().await;
        let token = owner(&s);
        let response = call(
            &s,
            "/v1/messages",
            None,
            Some(json!({ "model": "sonnet", "max_tokens": 64, "stream": true, "messages": [] })),
            &[("x-api-key", &token), ("anthropic-version", "2023-06-01")],
        )
        .await;
        assert_eq!(
            header(&response, "content-type").as_deref(),
            Some("text/event-stream")
        );
        assert_eq!(
            header(&response, "cache-control").as_deref(),
            Some("no-cache")
        );
        let text = text_of(response).await;
        assert!(text.contains("event: message_start"));
        assert!(text.contains("\"output_tokens\":25"));
        let rows = usage_by_model(&s.f).await;
        assert_eq!(rows.len(), 1);
        assert_matches(
            &rows[0],
            json!({ "key": "sonnet", "inputTokens": 10.0, "outputTokens": 25.0, "requests": 1.0 }),
        );
    });
}

#[test]
fn serves_openai_chat_completions_from_an_openai_compatible_provider_streaming_usage_too() {
    run(|| async move {
        let s = gateway_setup().await;
        let plain = call(
            &s,
            "/v1/chat/completions",
            Some(&owner(&s)),
            Some(
                json!({ "model": "open-model", "messages": [{ "role": "user", "content": "Hi" }] }),
            ),
            &[],
        )
        .await;
        assert_eq!(plain.status(), 200);
        let first = calls(&s).remove(0);
        assert_eq!(first.url, "https://router.example/api/v1/chat/completions");
        assert_eq!(
            first.header("authorization").as_deref(),
            Some("Bearer sk-router-key-8888")
        );
        let streamed = call(
            &s,
            "/v1/chat/completions",
            Some(&owner(&s)),
            Some(json!({ "model": "open-model", "stream": true, "messages": [] })),
            &[],
        )
        .await;
        assert_eq!(
            calls(&s)[1].body["stream_options"],
            json!({ "include_usage": true })
        );
        assert!(text_of(streamed).await.contains("[DONE]"));
        // 10 + 2 cached input and 8 output, then 7 input and 3 output.
        let rows = usage_by_model(&s.f).await;
        assert_eq!(rows.len(), 1);
        assert_matches(
            &rows[0],
            json!({ "key": "open-model", "requests": 2.0, "inputTokens": 17.0, "outputTokens": 11.0, "cacheReadTokens": 2.0 }),
        );
    });
}

#[test]
fn refuses_callers_models_formats_and_budgets_in_each_apis_own_error_shape() {
    run(|| async move {
        let s = gateway_setup().await;
        let alice = s.f.member("alice").await;
        let alice_token = token_of(&s.f.sign_in(&alice).await);

        let anonymous = call(
            &s,
            "/v1/messages",
            None,
            Some(json!({ "model": "sonnet", "messages": [] })),
            &[],
        )
        .await;
        assert_eq!(anonymous.status(), 401);
        assert_matches(
            &json_of(anonymous).await,
            json!({ "type": "error", "error": { "type": "authentication_error" } }),
        );

        let bogus = call(
            &s,
            "/v1/chat/completions",
            Some("not-a-real-credential-token-value-xyz"),
            Some(json!({ "model": "open-model" })),
            &[],
        )
        .await;
        assert_eq!(bogus.status(), 401);
        assert_matches(
            &json_of(bogus).await,
            json!({ "error": { "code": "UNAUTHENTICATED" } }),
        );

        let denied = call(
            &s,
            "/v1/messages",
            Some(&alice_token),
            Some(json!({ "model": "sonnet", "messages": [] })),
            &[],
        )
        .await;
        assert_eq!(denied.status(), 403);
        assert_matches(
            &json_of(denied).await,
            json!({ "error": { "type": "permission_error", "code": "ACCESS_DENIED" } }),
        );

        let wrong_format = call(
            &s,
            "/v1/chat/completions",
            Some(&owner(&s)),
            Some(json!({ "model": "sonnet" })),
            &[],
        )
        .await;
        assert_eq!(wrong_format.status(), 400);
        assert_matches(
            &json_of(wrong_format).await,
            json!({ "error": { "code": "WRONG_FORMAT", "message": "Model sonnet is served by an anthropic provider; use POST /v1/messages" } }),
        );

        let unknown = call(
            &s,
            "/v1/messages",
            Some(&owner(&s)),
            Some(json!({ "model": "missing" })),
            &[],
        )
        .await;
        assert_eq!(unknown.status(), 404);

        let tenant = s.f.tenant_id.clone();
        set_budget(
            &s.f,
            &tenant,
            "Tight",
            json!({ "subjectType": "identity", "subjectId": s.f.owner_id, "period": "hour", "maxTokens": 100 }),
        )
        .await;
        let too_big = call(
            &s,
            "/v1/messages",
            Some(&owner(&s)),
            Some(json!({ "model": "sonnet", "max_tokens": 4096, "messages": [] })),
            &[],
        )
        .await;
        assert_eq!(too_big.status(), 429);
        let retry: f64 = header(&too_big, "retry-after").unwrap().parse().unwrap();
        assert!(retry > 0.0);
        assert_matches(
            &json_of(too_big).await,
            json!({ "error": { "type": "rate_limit_error", "code": "BUDGET_EXCEEDED" } }),
        );
        assert!(calls(&s).is_empty());

        // Routes the gateway does not serve, and requests it cannot read.
        let missing = call(&s, "/v1/unknown", Some(&owner(&s)), None, &[]).await;
        assert_eq!(missing.status(), 404);
        let outside = s
            .gateway
            .handle(
                &http::Request::builder()
                    .uri("http://gateway.test/v1/messages")
                    .body(Bytes::new())
                    .unwrap(),
            )
            .await;
        assert_eq!(outside.status(), 404);
        let garbage = s
            .gateway
            .handle(
                &http::Request::builder()
                    .method("POST")
                    .uri("http://gateway.test/ai/v1/messages")
                    .header("authorization", format!("Bearer {}", owner(&s)))
                    .body(Bytes::from_static(b"[1]"))
                    .unwrap(),
            )
            .await;
        assert_eq!(garbage.status(), 400);
        assert_matches(
            &json_of(garbage).await,
            json!({ "error": { "code": "INVALID_INPUT", "message": "The request body must be a JSON object" } }),
        );
        let nameless = call(&s, "/v1/messages", Some(&owner(&s)), Some(json!({})), &[]).await;
        assert_matches(
            &json_of(nameless).await,
            json!({ "error": { "code": "INVALID_INPUT", "message": "model is required" } }),
        );
    });
}

#[test]
fn refuses_bodies_larger_than_the_limit() {
    run(|| async move {
        let s = gateway_setup().await;
        let gateway = create_inference_gateway(
            s.runtime.clone(),
            Some(&InferenceGatewayOptions {
                base_path: Some("/ai/".to_owned()),
                fetch: Some(s.fetch.clone()),
                max_body_bytes: Some(64.0),
                ..InferenceGatewayOptions::default()
            }),
        );
        let large = gateway
            .handle(&gateway_request(
                "/v1/messages",
                Some(&owner(&s)),
                Some(json!({ "model": "sonnet", "messages": [{ "role": "user", "content": "x".repeat(100) }] })),
                &[],
            ))
            .await;
        assert_eq!(large.status(), 413);
        assert_matches(
            &json_of(large).await,
            json!({ "type": "error", "error": { "type": "request_too_large", "code": "TOO_LARGE" } }),
        );
        let small = gateway
            .handle(&gateway_request(
                "/v1/messages",
                Some(&owner(&s)),
                Some(json!({ "model": "sonnet", "messages": [] })),
                &[],
            ))
            .await;
        assert_eq!(small.status(), 200);
    });
}

#[test]
fn caps_output_tokens_at_the_models_limit_and_limits_requests_per_minute() {
    run(|| async move {
        let s = gateway_setup().await;
        let tenant = s.f.tenant_id.clone();
        update_model(&s.f, &tenant, "sonnet", json!({ "maxOutputTokens": 1000 })).await;
        update_model(
            &s.f,
            &tenant,
            "open-model",
            json!({ "maxOutputTokens": 500 }),
        )
        .await;
        let ask = |model: &'static str, extra: Value| {
            let mut input = json!({ "model": model, "messages": [] });
            for (key, value) in extra.as_object().cloned().unwrap_or_default() {
                input[key] = value;
            }
            let path = if model == "sonnet" {
                "/v1/messages"
            } else {
                "/v1/chat/completions"
            };
            let request = gateway_request(path, Some(&owner(&s)), Some(input), &[]);
            let gateway = s.gateway.clone();
            async move { gateway.handle(&request).await.status() }
        };
        assert_eq!(ask("sonnet", json!({ "max_tokens": 64_000 })).await, 200);
        assert_eq!(ask("sonnet", json!({ "max_tokens": 200 })).await, 200);
        assert_eq!(ask("open-model", json!({})).await, 200);
        assert_eq!(
            calls(&s)
                .iter()
                .map(|sent| sent.body["max_tokens"].clone())
                .collect::<Vec<_>>(),
            [json!(1000), json!(200), json!(500)]
        );

        // A per-minute budget is a rate limit: the third request in a minute waits for the next one.
        set_budget(
            &s.f,
            &tenant,
            "Two per minute",
            json!({ "subjectType": "identity", "subjectId": s.f.owner_id, "period": "minute", "maxRequests": 2 }),
        )
        .await;
        s.f.advance(60_000.0 - (s.f.now() % 60_000.0));
        assert_eq!(ask("sonnet", json!({ "max_tokens": 10 })).await, 200);
        assert_eq!(ask("sonnet", json!({ "max_tokens": 10 })).await, 200);
        let limited = s
            .gateway
            .handle(&gateway_request(
                "/v1/messages",
                Some(&owner(&s)),
                Some(json!({ "model": "sonnet", "messages": [], "max_tokens": 10 })),
                &[],
            ))
            .await;
        assert_eq!(limited.status(), 429);
        assert_matches(
            &json_of(limited).await,
            json!({ "error": { "code": "BUDGET_EXCEEDED" } }),
        );
        s.f.advance(60_000.0);
        assert_eq!(ask("sonnet", json!({ "max_tokens": 10 })).await, 200);
    });
}

#[test]
fn falls_back_to_the_next_model_the_caller_may_use_when_a_provider_is_overloaded() {
    run(|| async move {
        let s = gateway_setup().await;
        let tenant = s.f.tenant_id.clone();
        create_model(
            &s.f,
            &tenant,
            "haiku",
            &id_of(&s.anthropic),
            "claude-haiku-4-5",
            json!({}),
        )
        .await;
        // open-model speaks the other wire format and is skipped; haiku is next.
        update_model(
            &s.f,
            &tenant,
            "sonnet",
            json!({ "fallbacks": ["open-model", "haiku"] }),
        )
        .await;
        let recorded = s.calls.clone();
        let overloaded: GatewayFetch = Arc::new(move |request: FetchRequest| {
            let upstream = upstream_of(&request);
            let count = {
                let mut calls = recorded.lock().unwrap();
                calls.push(upstream.clone());
                calls.len()
            };
            let answer = if upstream.body["model"] == json!("claude-sonnet-5") {
                UpstreamResponse::new(
                    529,
                    vec![("content-type".to_owned(), "application/json".to_owned())],
                    r#"{"type":"error","error":{"type":"overloaded_error","message":"Overloaded"}}"#,
                )
            } else {
                fake_answer(&upstream.url, &upstream.body, count)
            };
            Box::pin(async move { Ok(answer) })
        });
        let gateway = create_inference_gateway(
            s.runtime.clone(),
            Some(&InferenceGatewayOptions {
                base_path: Some("/ai".to_owned()),
                fetch: Some(overloaded),
                ..InferenceGatewayOptions::default()
            }),
        );
        let ask = |token: String| {
            let gateway = gateway.clone();
            async move {
                gateway
                    .handle(&gateway_request(
                        "/v1/messages",
                        Some(&token),
                        Some(json!({ "model": "sonnet", "max_tokens": 64, "messages": [] })),
                        &[],
                    ))
                    .await
            }
        };
        let response = ask(owner(&s)).await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            header(&response, "x-better-iam-model").as_deref(),
            Some("haiku")
        );
        assert_eq!(
            header(&response, "x-better-iam-fallback-from").as_deref(),
            Some("sonnet")
        );
        assert_matches(&json_of(response).await, json!({ "model": "haiku" }));
        let rows = usage_by_model(&s.f).await;
        assert_matches(
            rows.iter()
                .find(|row| row["key"] == json!("sonnet"))
                .unwrap(),
            json!({ "requests": 1.0, "outputTokens": 0.0 }),
        );
        assert_matches(
            rows.iter()
                .find(|row| row["key"] == json!("haiku"))
                .unwrap(),
            json!({ "requests": 1.0, "outputTokens": 20.0 }),
        );
        let failed =
            s.f.find(
                "inferenceUsage",
                better_iam_core::Filter::new().eq("model", "sonnet"),
            )
            .await;
        assert_eq!(failed[0]["status"], json!("error"));

        // A caller who may not use the fallback gets the provider's answer instead.
        let (_, key) = agent_key(&s, "Sonnet only", json!(["model/sonnet"])).await;
        let refused = ask(key).await;
        assert_eq!(refused.status(), 529);
        assert_eq!(header(&refused, "x-better-iam-fallback-from"), None);
    });
}

#[test]
fn lists_the_models_a_caller_may_use_in_either_format_for_agents_too() {
    run(|| async move {
        let s = gateway_setup().await;
        let (agent_id, key) = agent_key(&s, "Coder", json!(["model/open-*"])).await;
        let openai = call(&s, "/v1/models", Some(&key), None, &[]).await;
        assert_eq!(openai.status(), 200);
        assert_matches(
            &json_of(openai).await,
            json!({ "object": "list", "data": [{ "id": "open-model", "object": "model", "owned_by": "Router" }] }),
        );
        let anthropic = call(
            &s,
            "/v1/models",
            Some(&owner(&s)),
            None,
            &[("anthropic-version", "2023-06-01")],
        )
        .await;
        let listed = json_of(anthropic).await;
        assert_eq!(
            listed["data"]
                .as_array()
                .unwrap()
                .iter()
                .map(|model| model["id"].clone())
                .collect::<Vec<_>>(),
            [json!("open-model"), json!("sonnet")]
        );
        assert_matches(
            &listed,
            json!({ "has_more": false, "first_id": "open-model", "last_id": "sonnet", "data": [{ "type": "model", "display_name": "open-model" }, { "type": "model", "display_name": "sonnet" }] }),
        );
        let completion = call(
            &s,
            "/v1/chat/completions",
            Some(&key),
            Some(json!({ "model": "open-model" })),
            &[],
        )
        .await;
        assert_eq!(completion.status(), 200);
        let usage =
            s.f.find(
                "inferenceUsage",
                better_iam_core::Filter::new().eq("tenantId", s.f.tenant_id.clone()),
            )
            .await;
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0]["agentId"], json!(agent_id));
    });
}

#[test]
fn serves_the_responses_api_and_embeddings_and_keeps_each_callers_conversations_their_own() {
    run(|| async move {
        let s = gateway_setup().await;
        let tenant = s.f.tenant_id.clone();
        update_model(
            &s.f,
            &tenant,
            "open-model",
            json!({ "maxOutputTokens": 500 }),
        )
        .await;
        let owner = owner(&s);
        let first = call(
            &s,
            "/v1/responses",
            Some(&owner),
            Some(json!({ "model": "open-model", "input": "Hi", "max_output_tokens": 9999 })),
            &[],
        )
        .await;
        assert_eq!(first.status(), 200);
        assert_matches(
            &json_of(first).await,
            json!({ "id": "resp_1", "object": "response", "model": "open-model" }),
        );
        let sent = calls(&s);
        assert_eq!(sent[0].url, "https://router.example/api/v1/responses");
        assert_matches(
            &sent[0].body,
            json!({ "model": "vendor/open-model-70b", "max_output_tokens": 500 }),
        );

        // Streamed, with the id taken from response.created and usage from response.completed.
        let streamed = call(
            &s,
            "/v1/responses",
            Some(&owner),
            Some(json!({ "model": "open-model", "input": "More", "stream": true, "previous_response_id": "resp_1" })),
            &[],
        )
        .await;
        assert_eq!(streamed.status(), 200);
        assert!(
            text_of(streamed)
                .await
                .contains("event: response.completed")
        );
        assert_eq!(calls(&s)[1].body.get("stream_options"), None);
        let continued = call(
            &s,
            "/v1/responses",
            Some(&owner),
            Some(json!({ "model": "open-model", "input": "And again", "previous_response_id": "resp_2" })),
            &[],
        )
        .await;
        assert_eq!(continued.status(), 200);

        // Someone else, even with access to the model, cannot continue the owner's conversation.
        let alice = s.f.member("alice").await;
        grant(
            &s,
            &alice,
            json!([{ "effect": "allow", "actions": ["inference:invoke"], "resources": ["model/open-model"] }]),
        )
        .await;
        let alice_token = token_of(&s.f.sign_in(&alice).await);
        let sent = calls(&s).len();
        let stolen = call(
            &s,
            "/v1/responses",
            Some(&alice_token),
            Some(json!({ "model": "open-model", "input": "What did they say?", "previous_response_id": "resp_1" })),
            &[],
        )
        .await;
        assert_eq!(stolen.status(), 404);
        assert_matches(
            &json_of(stolen).await,
            json!({ "error": { "code": "RESPONSE_NOT_FOUND" } }),
        );
        for refused in [
            json!({ "previous_response_id": "../resp_1" }),
            json!({ "conversation": "conv_123" }),
            json!({ "background": true }),
        ] {
            let mut input = json!({ "model": "open-model", "input": "x" });
            for (key, value) in object(refused) {
                input[key] = value;
            }
            let answer = call(&s, "/v1/responses", Some(&alice_token), Some(input), &[]).await;
            assert_eq!(answer.status(), 400);
        }
        assert_eq!(calls(&s).len(), sent);
        assert_eq!(
            call(
                &s,
                "/v1/responses",
                Some(&alice_token),
                Some(json!({ "model": "open-model", "input": "Hi" })),
                &[],
            )
            .await
            .status(),
            200
        );

        // Embeddings: input tokens only, and no output limit is added.
        let embedded = call(
            &s,
            "/v1/embeddings",
            Some(&owner),
            Some(json!({ "model": "open-model", "input": "text" })),
            &[],
        )
        .await;
        assert_eq!(embedded.status(), 200);
        assert_matches(
            &json_of(embedded).await,
            json!({ "model": "open-model", "usage": { "prompt_tokens": 9 } }),
        );
        let embedding_call = calls(&s).pop().unwrap();
        assert_eq!(
            embedding_call.url,
            "https://router.example/api/v1/embeddings"
        );
        let mut keys: Vec<String> = object(embedding_call.body).keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, ["input", "model"]);

        // Three owner responses and one of Alice's (20 input, 10 cached, 12 output each), plus 9 embedding tokens.
        let rows = usage_by_model(&s.f).await;
        assert_eq!(rows.len(), 1);
        assert_matches(
            &rows[0],
            json!({
                "key": "open-model",
                "requests": 5.0,
                "inputTokens": (4 * 20 + 9) as f64,
                "cacheReadTokens": (4 * 10) as f64,
                "outputTokens": (4 * 12) as f64,
            }),
        );
        // The streamed response was recorded as the owner's from response.created.
        let responses =
            s.f.find(
                "inferenceResponses",
                better_iam_core::Filter::new().eq("tenantId", tenant.clone()),
            )
            .await;
        let mut ids: Vec<String> = responses
            .iter()
            .map(|record| record["responseId"].as_str().unwrap().to_owned())
            .collect();
        ids.sort();
        assert_eq!(ids, ["resp_1", "resp_2", "resp_3", "resp_4"]);
    });
}

#[test]
fn governs_the_tools_the_provider_runs_itself_per_model_and_by_policy() {
    run(|| async move {
        let s = gateway_setup().await;
        let tenant = s.f.tenant_id.clone();
        update_model(
            &s.f,
            &tenant,
            "open-model",
            json!({ "providerTools": "policy" }),
        )
        .await;
        update_model(&s.f, &tenant, "sonnet", json!({ "providerTools": "deny" })).await;
        let models = s.runtime.models(&s.f.owner_credential).await.unwrap();
        assert_eq!(
            models
                .iter()
                .map(|model| (model.name.as_str(), model.provider_tools.as_deref()))
                .collect::<Vec<_>>(),
            [("open-model", Some("policy")), ("sonnet", Some("deny"))]
        );
        let alice = s.f.member("alice").await;
        grant(
            &s,
            &alice,
            json!([
                { "effect": "allow", "actions": ["inference:invoke"], "resources": ["model/open-model", "model/sonnet"] },
                { "effect": "allow", "actions": ["inference:use-tool"], "resources": ["model-tool/web_search", "model-tool/mcp:*.acme.test"] },
            ]),
        )
        .await;
        let token = token_of(&s.f.sign_in(&alice).await);
        let respond = |tools: Value| {
            let request = gateway_request(
                "/v1/responses",
                Some(&token),
                Some(json!({ "model": "open-model", "input": "Hi", "tools": tools })),
                &[],
            );
            let gateway = s.gateway.clone();
            async move { gateway.handle(&request).await }
        };
        assert_eq!(
            respond(json!([{ "type": "web_search_preview" }]))
                .await
                .status(),
            200
        );
        assert_eq!(
            respond(json!([{ "type": "mcp", "server_label": "kb", "server_url": "https://kb.acme.test/mcp" }]))
                .await
                .status(),
            200
        );
        // Functions the caller runs itself are not provider tools.
        assert_eq!(
            respond(json!([{ "type": "function", "name": "lookup", "parameters": {} }]))
                .await
                .status(),
            200
        );
        let sent = calls(&s).len();
        let interpreter =
            respond(json!([{ "type": "code_interpreter", "container": { "type": "auto" } }])).await;
        assert_eq!(interpreter.status(), 403);
        let body = json_of(interpreter).await;
        assert_eq!(body["error"]["code"], json!("TOOL_NOT_ALLOWED"));
        assert!(
            body["error"]["message"]
                .as_str()
                .unwrap()
                .contains("code_interpreter")
        );
        let elsewhere = respond(json!([{ "type": "mcp", "server_label": "x", "server_url": "https://tools.evil.example/mcp" }])).await;
        assert_eq!(elsewhere.status(), 403);
        assert_eq!(calls(&s).len(), sent);
        assert_eq!(
            call(
                &s,
                "/v1/chat/completions",
                Some(&token),
                Some(json!({ "model": "open-model", "messages": [], "web_search_options": {} })),
                &[],
            )
            .await
            .status(),
            200
        );

        // A model that allows no provider tools: custom tools still pass, server tools and MCP servers do not.
        let messages = |extra: Value| {
            let mut input = json!({ "model": "sonnet", "max_tokens": 16, "messages": [] });
            for (key, value) in object(extra) {
                input[key] = value;
            }
            let request = gateway_request("/v1/messages", Some(&token), Some(input), &[]);
            let gateway = s.gateway.clone();
            async move { gateway.handle(&request).await }
        };
        assert_eq!(
            messages(
                json!({ "tools": [{ "name": "lookup", "input_schema": { "type": "object" } }] })
            )
            .await
            .status(),
            200
        );
        let search = messages(
            json!({ "tools": [{ "type": "web_search_20250305", "name": "web_search", "max_uses": 2 }] }),
        )
        .await;
        assert_eq!(search.status(), 403);
        assert_matches(
            &json_of(search).await,
            json!({ "type": "error", "error": { "type": "permission_error", "code": "TOOL_NOT_ALLOWED" } }),
        );
        assert_eq!(
            messages(json!({ "mcp_servers": [{ "type": "url", "url": "https://kb.acme.test/mcp", "name": "kb" }] }))
                .await
                .status(),
            403
        );
        // A model's own refusal is audited like a denied decision.
        let refusals =
            s.f.find(
                "audit",
                better_iam_core::Filter::new()
                    .eq("action", "inference:use-tool")
                    .eq("resourceId", "model-tool/web_search"),
            )
            .await;
        assert!(!refusals.is_empty());
        // Counting tokens runs no tool.
        assert_eq!(
            call(
                &s,
                "/v1/messages/count_tokens",
                Some(&token),
                Some(json!({ "model": "sonnet", "messages": [], "tools": [{ "type": "web_search_20250305", "name": "web_search" }] })),
                &[],
            )
            .await
            .status(),
            200
        );
    });
}

#[test]
fn refuses_what_it_cannot_check() {
    run(|| async move {
        let s = gateway_setup().await;
        let tenant = s.f.tenant_id.clone();
        update_model(
            &s.f,
            &tenant,
            "open-model",
            json!({ "providerTools": "deny" }),
        )
        .await;
        let owner = owner(&s);
        let respond = |extra: Value| {
            let mut input = json!({ "model": "open-model", "input": "Hi" });
            for (key, value) in object(extra) {
                input[key] = value;
            }
            let request = gateway_request("/v1/responses", Some(&owner), Some(input), &[]);
            let gateway = s.gateway.clone();
            async move { gateway.handle(&request).await }
        };
        let many: Vec<Value> = (0..257)
            .map(|index| json!({ "type": "function", "name": format!("f{index}"), "parameters": {} }))
            .collect();
        let refused = respond(json!({ "tools": many })).await;
        assert_eq!(refused.status(), 400);
        assert_matches(
            &json_of(refused).await,
            json!({ "error": { "message": "A request may list at most 256 tools and 64 MCP servers" } }),
        );
        assert_eq!(
            respond(json!({ "prompt": { "id": "pmpt_1" } }))
                .await
                .status(),
            403
        );
        for input in [
            json!([{ "type": "item_reference", "id": "msg_someone_elses" }]),
            json!([{ "role": "user", "content": [{ "type": "input_file", "file_id": "file-abc" }] }]),
        ] {
            let refused = respond(json!({ "input": input })).await;
            assert_eq!(refused.status(), 400);
            assert_matches(
                &json_of(refused).await,
                json!({ "error": { "code": "UNSUPPORTED_PARAMETER" } }),
            );
        }
        assert_eq!(
            call(
                &s,
                "/v1/messages",
                Some(&owner),
                Some(json!({ "model": "sonnet", "messages": [], "container": "container_1" })),
                &[],
            )
            .await
            .status(),
            400
        );
        assert!(calls(&s).is_empty());

        // A response continues only at the provider that answered it.
        let other = create_provider(
            &s.f,
            &tenant,
            "Echo",
            "openai-compatible",
            "sk-echo-key-7777",
            Some("https://echo.example/v1"),
        )
        .await;
        create_model(
            &s.f,
            &tenant,
            "echo-model",
            &id_of(&other),
            "echo",
            json!({}),
        )
        .await;
        update_model(
            &s.f,
            &tenant,
            "open-model",
            json!({ "providerTools": null }),
        )
        .await;
        let first = json_of(respond(json!({})).await).await;
        assert_eq!(
            respond(json!({ "previous_response_id": first["id"] }))
                .await
                .status(),
            200
        );
        let echo = call(
            &s,
            "/v1/responses",
            Some(&owner),
            Some(json!({ "model": "echo-model", "input": "Hi", "previous_response_id": first["id"] })),
            &[],
        )
        .await;
        assert_eq!(echo.status(), 404);
        // The echo provider is reached through its own base URL, which drops the duplicate /v1.
        let echoed = call(
            &s,
            "/v1/responses",
            Some(&owner),
            Some(json!({ "model": "echo-model", "input": "Hi" })),
            &[],
        )
        .await;
        assert_eq!(echoed.status(), 200);
        assert_eq!(
            calls(&s).pop().unwrap().url,
            "https://echo.example/v1/responses"
        );
    });
}

#[test]
fn meters_a_stream_the_client_closes_before_its_final_usage_event() {
    run(|| async move {
        let s = gateway_setup().await;
        // A provider that streams the start of an answer and then keeps the connection open.
        let hanging: GatewayFetch = Arc::new(|_request: FetchRequest| {
            let events = sse(&[
                (
                    Some("response.created"),
                    json!({ "type": "response.created", "response": { "id": "resp_h", "usage": null } }),
                ),
                (
                    Some("response.output_text.delta"),
                    json!({ "type": "response.output_text.delta", "delta": "x".repeat(400) }),
                ),
            ]);
            let first = futures::stream::once(async move { Ok(Bytes::from(events)) });
            let answer = UpstreamResponse::streaming(
                200,
                vec![("content-type".to_owned(), "text/event-stream".to_owned())],
                futures::StreamExt::chain(first, futures::stream::pending()),
            );
            Box::pin(async move { Ok(answer) })
        });
        let gateway = create_inference_gateway(
            s.runtime.clone(),
            Some(&InferenceGatewayOptions {
                base_path: Some("/ai".to_owned()),
                fetch: Some(hanging),
                ..InferenceGatewayOptions::default()
            }),
        );
        let streamed = gateway
            .handle(&gateway_request(
                "/v1/responses",
                Some(&owner(&s)),
                Some(json!({ "model": "open-model", "input": "x".repeat(4000), "stream": true })),
                &[],
            ))
            .await;
        let mut body = streamed.into_body();
        assert!(body.chunk().await.unwrap().is_ok());
        drop(body);
        // The metering of a dropped stream runs on the runtime: let it finish.
        for _ in 0..50 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            if !usage_by_model(&s.f).await.is_empty() {
                break;
            }
        }
        let rows = usage_by_model(&s.f).await;
        // No final counts: the request's size stands in for the input, the text streamed so far for the output.
        assert_matches(
            &rows[0],
            json!({ "key": "open-model", "requests": 1.0, "outputTokens": 100.0 }),
        );
        assert!(rows[0]["inputTokens"].as_f64().unwrap() >= 1000.0);
        // The response named in response.created is the caller's.
        let responses =
            s.f.find(
                "inferenceResponses",
                better_iam_core::Filter::new().eq("responseId", "resp_h"),
            )
            .await;
        assert_eq!(responses.len(), 1);
    });
}

#[test]
fn names_provider_tools_the_way_policies_see_them() {
    assert_eq!(
        provider_tools_of(
            "/v1/responses",
            &object(json!({
                "tools": [
                    { "type": "web_search_preview_2025_03_11" },
                    { "type": "function", "name": "x" },
                    { "type": "custom", "name": "y" },
                    { "type": "mcp", "server_url": "https://KB.Acme.Test:8443/mcp" },
                    { "type": "mcp", "connector_id": "connector_googledrive" },
                    { "type": "mcp", "server_url": "not a url" },
                    { "type": "image_generation" },
                ],
            }))
        ),
        [
            "web_search",
            "mcp:kb.acme.test",
            "mcp:connector_googledrive",
            "mcp:invalid",
            "image_generation",
        ]
    );
    assert_eq!(
        provider_tools_of(
            "/v1/messages",
            &object(json!({
                "tools": [
                    { "type": "code_execution_20250825", "name": "code_execution" },
                    { "name": "lookup", "input_schema": {} },
                    { "type": "computer_20250124", "name": "computer" },
                ],
                "mcp_servers": [{ "type": "url", "url": "http://[::1]:9000/mcp" }],
            }))
        ),
        ["code_execution", "computer", "mcp:_::1_"]
    );
    // Only canonical http(s) URLs name a host: tricks that parse differently elsewhere read as invalid.
    assert_eq!(
        provider_tools_of(
            "/v1/messages",
            &object(json!({
                "mcp_servers": [
                    { "url": "https://kb.acme.test" },
                    { "url": "https://evil.example./mcp" },
                    { "url": "https://kb.acme.test\\@evil.example/mcp" },
                    { "url": "https://user@kb.acme.test/mcp" },
                    { "url": "https://kb.acme.test:443/mcp" },
                ],
            }))
        ),
        ["mcp:kb.acme.test", "mcp:evil.example", "mcp:invalid"]
    );
    assert_eq!(
        provider_tools_of(
            "/v1/responses",
            &object(json!({ "prompt": { "id": "pmpt_1" } }))
        ),
        ["prompt"]
    );
    assert_eq!(
        provider_tools_of(
            "/v1/chat/completions",
            &object(json!({ "web_search_options": {}, "prompt": {} }))
        ),
        ["web_search"]
    );
}

#[test]
fn finds_stored_provider_object_references_in_every_shape_the_provider_accepts_them() {
    for body in [
        json!({ "tools": [{ "type": "code_interpreter", "container": { "type": "auto", "file_ids": ["file-x"] } }] }),
        json!({ "tools": [{ "type": "file_search", "vector_store_ids": ["vs_other_tenant"] }] }),
        json!({ "tools": [{ "type": "image_generation", "input_image_mask": { "file_id": "file-mask" } }] }),
        json!({ "input": [{ "type": "function_call_output", "call_id": "c", "output": [{ "type": "input_file", "file_id": "file-y" }] }] }),
        json!({ "messages": [{ "role": "user", "content": [{ "type": "tool_result", "tool_use_id": "t", "content": [{ "type": "document", "source": { "type": "file", "file_id": "f" } }] }] }] }),
        json!({ "input": [{ "type": "item_reference", "id": "msg_1" }] }),
    ] {
        assert!(
            stored_reference("/v1/responses", &object(body.clone())).is_some(),
            "{body}"
        );
    }
    assert_eq!(
        stored_reference(
            "/v1/responses",
            &object(json!({
                "model": "gpt",
                "input": [{ "role": "user", "content": [{ "type": "input_text", "text": "file_id: nothing here" }] }],
                "tools": [{ "type": "function", "name": "fetch", "parameters": { "type": "object", "properties": { "file_id": { "type": "string" } } } }],
            }))
        ),
        None
    );
    // Too deep to search counts as a reference.
    let mut deep = json!({});
    for _ in 0..70 {
        deep = json!({ "next": deep });
    }
    assert_eq!(
        stored_reference("/v1/responses", &object(deep)),
        Some("too-complex")
    );
    assert_eq!(
        stored_reference(
            "/v1/messages",
            &object(json!({ "container": { "id": "c" } }))
        ),
        Some("container")
    );
}

#[test]
fn reads_usage_in_each_providers_format() {
    let anthropic = usage_from(
        UsageFormat::Anthropic,
        Some(&json!({ "input_tokens": 10, "output_tokens": 20, "cache_read_input_tokens": 5, "cache_creation_input_tokens": 3 })),
    )
    .unwrap();
    assert_eq!(
        (
            anthropic.input_tokens,
            anthropic.output_tokens,
            anthropic.cache_read_tokens,
            anthropic.cache_write_tokens
        ),
        (10.0, 20.0, Some(5.0), Some(3.0))
    );
    let openai = usage_from(
        UsageFormat::Openai,
        Some(&json!({ "prompt_tokens": 12, "completion_tokens": 8, "prompt_tokens_details": { "cached_tokens": 2 } })),
    )
    .unwrap();
    assert_eq!(
        (
            openai.input_tokens,
            openai.output_tokens,
            openai.cache_read_tokens
        ),
        (10.0, 8.0, Some(2.0))
    );
    let responses = usage_from(
        UsageFormat::Responses,
        Some(&json!({ "input_tokens": 30, "input_tokens_details": { "cached_tokens": 10 }, "output_tokens": 12 })),
    )
    .unwrap();
    assert_eq!(
        (
            responses.input_tokens,
            responses.output_tokens,
            responses.cache_read_tokens
        ),
        (20.0, 12.0, Some(10.0))
    );
    assert!(usage_from(UsageFormat::Openai, Some(&json!(null))).is_none());
    assert!(usage_from(UsageFormat::Openai, None).is_none());
    // Counts that are not non-negative safe integers count as 0.
    let odd = usage_from(
        UsageFormat::Anthropic,
        Some(&json!({ "input_tokens": -1, "output_tokens": 1.5 })),
    )
    .unwrap();
    assert_eq!((odd.input_tokens, odd.output_tokens), (0.0, 0.0));
}

#[test]
fn counts_anthropic_tokens_for_callers_who_may_use_the_model_without_metering() {
    run(|| async move {
        let s = gateway_setup().await;
        let tenant = s.f.tenant_id.clone();
        update_model(&s.f, &tenant, "sonnet", json!({ "maxOutputTokens": 1000 })).await;
        let counted = call(
            &s,
            "/v1/messages/count_tokens",
            Some(&owner(&s)),
            Some(
                json!({ "model": "sonnet", "messages": [{ "role": "user", "content": "Hello" }] }),
            ),
            &[],
        )
        .await;
        assert_eq!(counted.status(), 200);
        assert_eq!(json_of(counted).await, json!({ "input_tokens": 42 }));
        let sent = calls(&s).remove(0);
        assert_eq!(
            sent.url,
            "https://api.anthropic.com/v1/messages/count_tokens"
        );
        assert_eq!(
            sent.body,
            json!({ "model": "claude-sonnet-5", "messages": [{ "role": "user", "content": "Hello" }] })
        );
        assert!(usage_by_model(&s.f).await.is_empty());

        let bob = s.f.member("bob").await;
        let bob_token = token_of(&s.f.sign_in(&bob).await);
        let refused = call(
            &s,
            "/v1/messages/count_tokens",
            Some(&bob_token),
            Some(json!({ "model": "sonnet", "messages": [] })),
            &[],
        )
        .await;
        assert_eq!(refused.status(), 403);
        assert_matches(
            &json_of(refused).await,
            json!({ "type": "error", "error": { "code": "ACCESS_DENIED" } }),
        );
        let wrong_format = call(
            &s,
            "/v1/responses",
            Some(&owner(&s)),
            Some(json!({ "model": "sonnet", "input": "x" })),
            &[],
        )
        .await;
        assert_eq!(wrong_format.status(), 400);
        assert_matches(
            &json_of(wrong_format).await,
            json!({ "error": { "code": "WRONG_FORMAT" } }),
        );
    });
}

#[test]
fn reports_an_unreachable_provider() {
    run(|| async move {
        let s = gateway_setup().await;
        let errors = Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen = errors.clone();
        let failing: GatewayFetch = Arc::new(|_request: FetchRequest| {
            Box::pin(async move {
                Err(better_iam_server::safe_fetch::FetchError {
                    message: "connect ECONNREFUSED".to_owned(),
                    cause: None,
                })
            })
        });
        let gateway = create_inference_gateway(
            s.runtime.clone(),
            Some(&InferenceGatewayOptions {
                fetch: Some(failing),
                on_error: Some(Arc::new(move |error| {
                    seen.lock().unwrap().push(format!("{error:?}"))
                })),
                ..InferenceGatewayOptions::default()
            }),
        );
        let request = http::Request::builder()
            .method("POST")
            .uri("http://gateway.test/v1/chat/completions")
            .header("authorization", format!("Bearer {}", owner(&s)))
            .body(Bytes::from(
                json!({ "model": "open-model", "messages": [] }).to_string(),
            ))
            .unwrap();
        let response = gateway.handle(&request).await;
        assert_eq!(response.status(), 502);
        assert_matches(
            &json_of(response).await,
            json!({ "error": { "type": "server_error", "code": "UPSTREAM_UNAVAILABLE" } }),
        );
        assert_eq!(errors.lock().unwrap().len(), 1);
        // The failed call is metered as an error without tokens.
        let rows = usage_by_model(&s.f).await;
        assert_matches(
            &rows[0],
            json!({ "key": "open-model", "requests": 1.0, "inputTokens": 0.0, "outputTokens": 0.0 }),
        );
    });
}
