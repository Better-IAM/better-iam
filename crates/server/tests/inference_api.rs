//! The `inference` API group and the `iam.inference` runtime: ported from tests/inference.test.ts and the
//! administration and budget parts of tests/security-inference.test.ts.

mod organization_fixture;

use better_iam_core::{CredentialInput, PermissionsConfig};
use better_iam_server::api::inference::GatewayPermit;
use better_iam_server::inference_gateway::GatewayAuthorization as Authorization;
use better_iam_server::options::{
    AuthorizationRequest, BetterIamOptions, InferenceOptions, ResourceTarget, Toggle,
};
use better_iam_server::secrets::SecretRotationOptions;
use better_iam_server::{BetterIam, better_iam};
use organization_fixture::{Org, assert_matches, bearer, body, code, fails, ok, organization, run};
use serde_json::{Value, json};

const PROVIDER_KEY: &str = "sk-ant-secret-provider-key-0042";
const SECRET: &str = "organization-fixture-secret-with-32-characters";

fn with_inference(options: &mut BetterIamOptions) {
    options.inference = Some(Toggle::Flag(true));
}

fn merged(base: Value, extra: Value) -> Value {
    let mut out = base.as_object().cloned().unwrap_or_default();
    for (key, value) in extra.as_object().cloned().unwrap_or_default() {
        out.insert(key, value);
    }
    Value::Object(out)
}

struct Setup {
    f: Org,
    provider: Value,
    alice: String,
    alice_session: CredentialInput,
    role: Value,
}

/// Acme with inference on, one Anthropic provider, a frontier and a small model, and alice limited to small ones.
async fn setup() -> Setup {
    let f = organization(with_inference).await;
    let api = &f.iam.api.inference;
    let provider = ok(api
        .create_provider(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "Anthropic",
                "kind": "anthropic",
                "apiKey": PROVIDER_KEY,
            })),
        )
        .await);
    ok(api
        .create_model(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "opus",
                "providerId": provider["id"],
                "upstreamModel": "claude-opus-5-5",
                "tier": "frontier",
                "inputPricePerMTok": 5,
                "outputPricePerMTok": 25,
            })),
        )
        .await);
    ok(api
        .create_model(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "haiku",
                "providerId": provider["id"],
                "upstreamModel": "claude-haiku-4-5",
                "tier": "small",
                "inputPricePerMTok": 1,
                "outputPricePerMTok": 5,
            })),
        )
        .await);
    let alice = f.member("alice").await;
    let role = ok(f
        .iam
        .api
        .roles
        .create(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "name": "Small models",
                "document": {
                    "version": 1,
                    "statements": [{
                        "effect": "allow",
                        "actions": ["inference:invoke"],
                        "resources": ["model/*"],
                        "conditions": { "StringEquals": { "resource.tier": "small" } },
                    }],
                },
            })),
        )
        .await);
    bind(&f, &role, &alice).await;
    let alice_session = f.sign_in(&alice).await;
    Setup {
        f,
        provider,
        alice,
        alice_session,
        role,
    }
}

async fn bind(f: &Org, role: &Value, subject_id: &str) {
    ok(f.iam
        .api
        .bindings
        .create(
            &f.owner_credential,
            body(json!({
                "tenantId": f.tenant_id,
                "roleId": role["id"],
                "subjectType": "identity",
                "subjectId": subject_id,
            })),
        )
        .await);
}

async fn authorize(iam: &BetterIam, credential: &CredentialInput, model: &str) -> Authorization {
    iam.inference
        .authorize(credential, &json!({ "model": model }))
        .await
        .expect("authorized or denied")
}

/// `permit(f, token, model)`: the permit, panicking with `denied: {reason}` otherwise.
async fn permit(f: &Org, credential: &CredentialInput, model: &str) -> GatewayPermit {
    match authorize(&f.iam, credential, model).await {
        Authorization::Permit(permit) => *permit,
        Authorization::Denied(check) => panic!("denied: {}", check.to_json()["reason"]),
    }
}

/// Whether the credential is refused `model` (`'denied' in outcome`), and the refusal.
async fn denied(f: &Org, credential: &CredentialInput, model: &str) -> Option<Value> {
    match authorize(&f.iam, credential, model).await {
        Authorization::Permit(_) => None,
        Authorization::Denied(check) => Some(check.to_json()),
    }
}

async fn record(f: &Org, permit: &GatewayPermit, usage: Value) -> Value {
    let record = f
        .iam
        .inference
        .record(&permit.principal, &permit.tenant_id, &usage)
        .await
        .expect("metered");
    serde_json::to_value(record).unwrap()
}

async fn check(f: &Org, credential: &CredentialInput, input: Value) -> Value {
    ok(f.iam
        .api
        .inference
        .check(
            credential,
            body(merged(json!({ "tenantId": f.tenant_id }), input)),
        )
        .await)
}

fn names(list: &Value) -> Vec<String> {
    list.as_array()
        .unwrap()
        .iter()
        .map(|item| item["name"].as_str().unwrap().to_owned())
        .collect()
}

// --- inference catalog and access -----------------------------------------------------------------------------------

#[test]
fn seals_provider_keys_and_decides_model_access_with_ordinary_policies() {
    run(|| async {
        let Setup {
            f,
            provider,
            alice_session,
            ..
        } = setup().await;
        assert_matches(
            &provider,
            json!({ "kind": "anthropic", "baseUrl": "https://api.anthropic.com", "keyHint": "…0042" }),
        );
        let providers = ok(f
            .iam
            .api
            .inference
            .list_providers(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        assert!(!providers.to_string().contains(PROVIDER_KEY));
        let stored = f
            .store()
            .get("inferenceProviders", provider["id"].as_str().unwrap())
            .await
            .unwrap()
            .unwrap();
        assert!(!Value::Object(stored).to_string().contains(PROVIDER_KEY));

        assert_matches(
            &check(&f, &alice_session, json!({ "model": "opus" })).await,
            json!({ "allowed": false, "reason": "ACCESS_DENIED" }),
        );
        let allowed = check(&f, &alice_session, json!({ "model": "haiku" })).await;
        assert_matches(
            &allowed,
            json!({
                "allowed": true,
                "model": { "name": "haiku", "tier": "small", "provider": { "name": "Anthropic", "kind": "anthropic" } },
            }),
        );
        assert!(allowed["ticket"].is_string());
        let missing = fails(
            f.iam
                .api
                .inference
                .check(
                    &alice_session,
                    body(json!({ "tenantId": f.tenant_id, "model": "nope" })),
                )
                .await,
        );
        assert_eq!(code(&missing), "NOT_FOUND");
        let mine = |credential: CredentialInput| {
            let f = &f;
            async move {
                names(&ok(f
                    .iam
                    .api
                    .inference
                    .list_mine(&credential, body(json!({ "tenantId": f.tenant_id })))
                    .await))
            }
        };
        assert_eq!(mine(alice_session.clone()).await, vec!["haiku"]);
        assert_eq!(
            mine(f.owner_credential.clone()).await,
            vec!["haiku", "opus"]
        );

        // The same decision through the generic authorize API.
        let decision = f
            .iam
            .authorize(&AuthorizationRequest {
                credential: alice_session.clone(),
                tenant_id: f.tenant_id.clone(),
                action: "inference:invoke".into(),
                resource: ResourceTarget {
                    kind: "model".into(),
                    id: "haiku".into(),
                },
            })
            .await
            .unwrap();
        assert!(decision.allowed);

        // Disabling a model stops it for everyone.
        ok(f.iam
            .api
            .inference
            .update_model(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "haiku", "enabled": false })),
            )
            .await);
        assert_matches(
            &check(&f, &alice_session, json!({ "model": "haiku" })).await,
            json!({ "allowed": false, "reason": "MODEL_DISABLED" }),
        );

        // The gateway runtime opens the key server-side only.
        let owner = permit(&f, &f.owner_credential, "opus").await;
        assert_eq!(owner.provider.api_key, PROVIDER_KEY);
        assert_eq!(owner.provider.kind, "anthropic");
        assert_eq!(owner.upstream_model, "claude-opus-5-5");
    });
}

#[test]
fn lets_only_root_or_the_deployment_point_providers_at_custom_urls_and_inherits_models() {
    run(|| async {
        let Setup { f, .. } = setup().await;
        let api = &f.iam.api.inference;
        let refused = fails(
            api.create_provider(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Self hosted",
                    "kind": "openai-compatible",
                    "apiKey": "local-key-123456",
                    "baseUrl": "https://llm.internal.example/v1",
                })),
            )
            .await,
        );
        assert_eq!(code(&refused), "ACCESS_DENIED");
        // The platform defines a provider and model once, at the root tenant; organizations inherit them.
        let shared = ok(api
            .create_provider(
                &f.root_credential,
                body(json!({
                    "tenantId": f.root_tenant,
                    "name": "Platform vLLM",
                    "kind": "openai-compatible",
                    "apiKey": "platform-key-123456",
                    "baseUrl": "https://llm.platform.example/v1",
                })),
            )
            .await);
        ok(api
            .create_model(
                &f.root_credential,
                body(json!({
                    "tenantId": f.root_tenant,
                    "name": "llama-local",
                    "providerId": shared["id"],
                    "upstreamModel": "meta-llama/Llama-4",
                    "tier": "small",
                })),
            )
            .await);
        let models = ok(api
            .list_models(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        let llama = models
            .as_array()
            .unwrap()
            .iter()
            .find(|model| model["name"] == "llama-local")
            .unwrap();
        assert_matches(
            llama,
            json!({ "inherited": true, "provider": { "id": shared["id"], "kind": "openai-compatible" } }),
        );
        // An organization may shadow an inherited name with its own model.
        let own = ok(api
            .list_providers(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        let pairs: Vec<(String, bool)> = own
            .as_array()
            .unwrap()
            .iter()
            .map(|item| {
                (
                    item["name"].as_str().unwrap().to_owned(),
                    item["inherited"].as_bool().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            pairs,
            vec![
                ("Anthropic".to_owned(), false),
                ("Platform vLLM".to_owned(), true)
            ]
        );
    });
}

fn deployment(f: &Org, secret: &str, previous: Option<&str>) -> BetterIam {
    let mut options = BetterIamOptions::new(f.store(), secret, organization_fixture::ORIGIN);
    options.previous_secrets = previous.map(|previous| vec![previous.to_owned()]);
    options.permissions = Some(PermissionsConfig {
        actions: Some(vec!["documents:read".into(), "documents:write".into()]),
        ..PermissionsConfig::default()
    });
    options.inference = Some(Toggle::Flag(true));
    better_iam(options).expect("valid options")
}

#[test]
fn re_seals_provider_keys_when_the_deployment_secret_rotates() {
    run(|| async {
        let Setup { f, .. } = setup().await;
        let rotated = deployment(
            &f,
            "a-brand-new-deployment-secret-of-32-chars",
            Some(SECRET),
        );
        let report = rotated
            .rotate_secrets(&SecretRotationOptions {
                dry_run: false,
                batch_size: None,
                limit: None,
            })
            .await
            .unwrap();
        assert_eq!(report.resealed.get("inferenceProviders"), Some(&1.0));
        let opened = |iam: BetterIam| {
            let credential = f.owner_credential.clone();
            async move {
                match authorize(&iam, &credential, "opus").await {
                    Authorization::Permit(permit) => permit.provider.api_key.clone(),
                    Authorization::Denied(check) => panic!("denied: {}", check.to_json()),
                }
            }
        };
        assert_eq!(opened(rotated).await, PROVIDER_KEY);
        // Without the previous secret the key is still readable: it was re-sealed with the new one.
        let fresh = deployment(&f, "a-brand-new-deployment-secret-of-32-chars", None);
        assert_eq!(opened(fresh).await, PROVIDER_KEY);
    });
}

#[test]
fn validates_its_options_at_construction() {
    run(|| async {
        let f = organization(|_| {}).await;
        for days in [0.0, 1.5] {
            let mut options =
                BetterIamOptions::new(f.store(), SECRET, organization_fixture::ORIGIN);
            options.inference = Some(Toggle::Options(InferenceOptions {
                usage_retention_days: Some(days),
                ..InferenceOptions::default()
            }));
            let error = better_iam(options).err().expect("refused");
            assert_eq!(code(&error), "INVALID_CONFIG");
        }
    });
}

#[test]
fn is_refused_on_deployments_without_the_inference_option() {
    run(|| async {
        let f = organization(|_| {}).await;
        let error = fails(
            f.iam
                .api
                .inference
                .list_models(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id })),
                )
                .await,
        );
        assert_eq!(code(&error), "FEATURE_DISABLED");
    });
}

// --- budgets and metering -------------------------------------------------------------------------------------------

async fn set_budget(f: &Org, credential: &CredentialInput, input: Value) -> Value {
    ok(f.iam
        .api
        .inference
        .set_budget(
            credential,
            body(merged(json!({ "tenantId": f.tenant_id }), input)),
        )
        .await)
}

async fn audit_actions(f: &Org) -> Vec<String> {
    ok(f.iam
        .api
        .audit
        .list(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id })),
        )
        .await)
    .as_array()
    .unwrap()
    .iter()
    .map(|event| event["action"].as_str().unwrap().to_owned())
    .collect()
}

#[test]
fn meters_calls_refuses_exhausted_budgets_until_the_window_resets_and_reports_usage() {
    run(|| async {
        let Setup {
            f,
            alice,
            alice_session,
            ..
        } = setup().await;
        let budget = set_budget(
            &f,
            &f.owner_credential,
            json!({
                "name": "Daily per person",
                "subjectType": "tenant",
                "scope": "each",
                "period": "day",
                "maxTokens": 1000,
                "alertAtPercent": 80,
            }),
        )
        .await;
        assert_matches(
            &budget,
            json!({ "subjectId": f.tenant_id, "scope": "each", "maxTokens": 1000 }),
        );
        let used = permit(&f, &alice_session, "haiku").await;
        let budgets = used.check["budgets"].clone();
        assert_eq!(budgets.as_array().unwrap().len(), 1);
        assert_matches(
            &budgets[0],
            json!({ "budgetId": budget["id"], "remainingTokens": 1000 }),
        );
        let metered = record(
            &f,
            &used,
            json!({ "model": "haiku", "inputTokens": 600, "outputTokens": 300 }),
        )
        .await;
        // 600 × $1 + 300 × $5 per million tokens = 2100 micro-dollars.
        assert_matches(
            &metered,
            json!({ "identityId": alice, "costMicros": 2100, "status": "ok" }),
        );

        let estimate = |tokens: u64| json!({ "model": "haiku", "estimatedTokens": tokens });
        assert_matches(
            &check(&f, &alice_session, estimate(50)).await,
            json!({ "allowed": true }),
        );
        assert_matches(
            &check(&f, &alice_session, estimate(200)).await,
            json!({
                "allowed": false,
                "reason": "BUDGET_EXCEEDED",
                "budget": { "budgetId": budget["id"], "usedTokens": 900, "remainingTokens": 100 },
            }),
        );
        check(&f, &alice_session, estimate(200)).await;
        // The owner has their own share of an `each` budget.
        assert_matches(
            &check(&f, &f.owner_credential, estimate(900)).await,
            json!({ "allowed": true }),
        );

        let actions = audit_actions(&f).await;
        assert_eq!(
            actions
                .iter()
                .filter(|action| *action == "inference:budget-exceeded")
                .count(),
            1
        );
        assert!(
            actions
                .iter()
                .any(|action| action == "inference:budget-alert")
        );

        let report = ok(f
            .iam
            .api
            .inference
            .usage(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "groupBy": "identity" })),
            )
            .await);
        assert_eq!(report["rows"].as_array().unwrap().len(), 1);
        assert_matches(
            &report["rows"][0],
            json!({
                "key": alice,
                "label": "alice@acme.test",
                "requests": 1,
                "inputTokens": 600,
                "outputTokens": 300,
                "costMicros": 2100,
            }),
        );
        let mine = ok(f
            .iam
            .api
            .inference
            .my_usage(&alice_session, body(json!({ "tenantId": f.tenant_id })))
            .await);
        assert_matches(&mine["totals"], json!({ "requests": 1, "costUsd": 0.0021 }));
        assert_eq!(mine["budgets"].as_array().unwrap().len(), 1);
        assert_matches(
            &mine["budgets"][0],
            json!({ "budgetId": budget["id"], "usedTokens": 900 }),
        );

        // The next day starts a fresh window.
        f.advance(86_400_000.0);
        let fresh = f.sign_in(&alice).await;
        assert_matches(
            &check(&f, &fresh, estimate(900)).await,
            json!({ "allowed": true }),
        );
    });
}

#[test]
fn caps_an_agent_across_everything_it_does_including_on_peoples_behalf() {
    run(|| async {
        let Setup {
            f,
            alice,
            alice_session,
            role,
            ..
        } = setup().await;
        let agent = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "Summarizer" })),
            )
            .await);
        let agent_id = agent["id"].as_str().unwrap().to_owned();
        bind(&f, &role, &agent_id).await;
        let key = ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": agent_id })),
            )
            .await);
        let key = bearer(key["token"].as_str().unwrap());
        let cap = set_budget(
            &f,
            &f.owner_credential,
            json!({
                "name": "Summarizer cap",
                "subjectType": "identity",
                "subjectId": agent_id,
                "period": "month",
                "maxCostUsd": 0.001,
            }),
        )
        .await;
        assert_matches(&cap, json!({ "maxCostMicros": 1000, "maxCostUsd": 0.001 }));
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": f.tenant_id,
                    "agentId": agent_id,
                    "scopes": ["inference:invoke"],
                })),
            )
            .await);
        let delegated = ok(f
            .iam
            .api
            .delegations
            .assume(
                &key,
                body(json!({ "tenantId": f.tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        let delegated = bearer(delegated["token"].as_str().unwrap());
        // Acting for alice: alice's access (small models only), metered to alice and to the agent.
        assert_matches(
            &denied(&f, &delegated, "opus").await.expect("denied"),
            json!({ "reason": "ACCESS_DENIED" }),
        );
        let on_behalf = permit(&f, &delegated, "haiku").await;
        let metered = record(
            &f,
            &on_behalf,
            json!({ "model": "haiku", "inputTokens": 500, "outputTokens": 100 }),
        )
        .await;
        assert_matches(
            &metered,
            json!({
                "identityId": alice,
                "agentId": agent_id,
                "delegationId": delegation["id"],
                "sessionKind": "delegated",
                "costMicros": 1000,
            }),
        );
        // The agent's cap is spent, for its own key too; alice herself is not capped.
        assert_matches(
            &denied(&f, &key, "haiku").await.expect("denied"),
            json!({ "reason": "BUDGET_EXCEEDED", "budget": { "budgetId": cap["id"] } }),
        );
        assert!(denied(&f, &alice_session, "haiku").await.is_none());
        // A call without an agent groups under '(none)'.
        let own = permit(&f, &alice_session, "haiku").await;
        record(
            &f,
            &own,
            json!({ "model": "haiku", "inputTokens": 1, "outputTokens": 0 }),
        )
        .await;
        let by_agent = ok(f
            .iam
            .api
            .inference
            .usage(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "groupBy": "agent" })),
            )
            .await);
        let rows = by_agent["rows"].as_array().unwrap();
        assert_eq!(rows.len(), 2);
        assert_matches(
            &rows[0],
            json!({ "key": agent_id, "label": "Summarizer", "costMicros": 1000 }),
        );
        assert_matches(&rows[1], json!({ "key": "(none)", "requests": 1 }));
    });
}

#[test]
fn rate_limits_calls_per_window_with_max_requests() {
    run(|| async {
        let Setup {
            f,
            alice,
            alice_session,
            ..
        } = setup().await;
        let limit = set_budget(
            &f,
            &f.owner_credential,
            json!({
                "name": "Three calls an hour",
                "subjectType": "identity",
                "subjectId": alice,
                "period": "hour",
                "maxRequests": 3,
            }),
        )
        .await;
        assert_matches(
            &limit,
            json!({ "maxRequests": 3, "standing": { "usedRequests": 0, "remainingRequests": 3 } }),
        );
        for _ in 0..3 {
            let used = permit(&f, &alice_session, "haiku").await;
            record(
                &f,
                &used,
                json!({ "model": "haiku", "inputTokens": 1, "outputTokens": 1 }),
            )
            .await;
        }
        assert_matches(
            &denied(&f, &alice_session, "haiku").await.expect("denied"),
            json!({
                "reason": "BUDGET_EXCEEDED",
                "budget": { "budgetId": limit["id"], "usedRequests": 3, "remainingRequests": 0 },
            }),
        );
        let empty = fails(
            f.iam
                .api
                .inference
                .set_budget(
                    &f.owner_credential,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "name": "Empty",
                        "subjectType": "tenant",
                        "period": "day",
                    })),
                )
                .await,
        );
        assert_eq!(code(&empty), "INVALID_INPUT");
        f.advance(3_600_000.0);
        let fresh = f.sign_in(&alice).await;
        assert!(denied(&f, &fresh, "haiku").await.is_none());
    });
}

#[test]
fn lets_an_external_gateway_redeem_a_check_ticket_once() {
    run(|| async {
        let Setup {
            f,
            alice,
            alice_session,
            ..
        } = setup().await;
        let gateway = ok(f
            .iam
            .api
            .service_accounts
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "LLM gateway" })),
            )
            .await);
        let recorder = ok(f
            .iam
            .api
            .roles
            .create(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Inference recorder",
                    "document": {
                        "version": 1,
                        "statements": [{ "effect": "allow", "actions": ["iam:inference:record"], "resources": ["iam/*"] }],
                    },
                })),
            )
            .await);
        bind(&f, &recorder, gateway["id"].as_str().unwrap()).await;
        let gateway_key = ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": gateway["id"] })),
            )
            .await);
        let gateway_key = bearer(gateway_key["token"].as_str().unwrap());
        let allowed = check(&f, &alice_session, json!({ "model": "haiku" })).await;
        let ticket = allowed["ticket"]
            .as_str()
            .expect("an allowed check")
            .to_owned();
        let redeem = |credential: CredentialInput, tokens: u64| {
            let (f, ticket) = (&f, ticket.clone());
            async move {
                f.iam
                    .api
                    .inference
                    .record(
                        &credential,
                        body(json!({
                            "tenantId": f.tenant_id,
                            "ticket": ticket,
                            "inputTokens": tokens,
                            "outputTokens": tokens,
                        })),
                    )
                    .await
            }
        };
        // Alice cannot meter her own calls.
        let own = fails(redeem(alice_session.clone(), 0).await);
        assert_eq!(code(&own), "ACCESS_DENIED");
        assert_eq!(
            ok(redeem(gateway_key.clone(), 1000).await),
            json!({ "recorded": true, "costMicros": 6000 })
        );
        let again = fails(redeem(gateway_key.clone(), 1).await);
        assert_eq!(code(&again), "INVALID_TICKET");
        let report = ok(f
            .iam
            .api
            .inference
            .usage(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "identityId": alice })),
            )
            .await);
        assert_matches(
            &report["totals"],
            json!({ "requests": 1, "costMicros": 6000 }),
        );
    });
}

// --- security: inference administration (tests/security-inference.test.ts) ------------------------------------------

/// Acme with inference on and a provider the platform owns at the root tenant.
async fn platform(allow_custom_base_urls: bool) -> (Org, Value) {
    let f = organization(|options| {
        options.inference = Some(Toggle::Options(InferenceOptions {
            allow_custom_base_urls: allow_custom_base_urls.then_some(true),
            ..InferenceOptions::default()
        }))
    })
    .await;
    let provider = ok(f
        .iam
        .api
        .inference
        .create_provider(
            &f.root_credential,
            body(json!({
                "tenantId": f.root_tenant,
                "name": "Platform Anthropic",
                "kind": "anthropic",
                "apiKey": "sk-ant-platform-owned-key-9999",
            })),
        )
        .await);
    (f, provider)
}

#[test]
fn keeps_models_on_a_parent_organizations_provider_in_the_platforms_hands() {
    run(|| async {
        let (f, provider) = platform(false).await;
        let api = &f.iam.api.inference;
        let model = |prices: (u32, u32)| {
            body(json!({
                "tenantId": f.tenant_id,
                "name": "opus",
                "providerId": provider["id"],
                "upstreamModel": "claude-opus-5-5",
                "inputPricePerMTok": prices.0,
                "outputPricePerMTok": prices.1,
            }))
        };
        let refused = fails(api.create_model(&f.owner_credential, model((0, 0))).await);
        assert_eq!(code(&refused), "ACCESS_DENIED");
        // The platform may set one up for the organization; the organization may turn it off, not reprice it.
        ok(api.create_model(&f.root_credential, model((5, 25))).await);
        let repriced = fails(
            api.update_model(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "name": "opus", "inputPricePerMTok": 0 })),
            )
            .await,
        );
        assert_eq!(code(&repriced), "ACCESS_DENIED");
        assert_matches(
            &ok(api
                .update_model(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "name": "opus", "enabled": false })),
                )
                .await),
            json!({ "enabled": false }),
        );
    });
}

#[test]
fn lets_only_the_platform_change_or_remove_a_budget_it_set_on_an_organization() {
    run(|| async {
        let (f, _) = platform(false).await;
        let api = &f.iam.api.inference;
        let cap = set_budget(
            &f,
            &f.root_credential,
            json!({ "name": "Platform cap", "subjectType": "tenant", "period": "month", "maxCostUsd": 1 }),
        )
        .await;
        let removed = fails(
            api.delete_budget(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "budgetId": cap["id"] })),
            )
            .await,
        );
        assert_eq!(code(&removed), "ACCESS_DENIED");
        let lifted = fails(
            api.set_budget(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "budgetId": cap["id"],
                    "name": "Platform cap",
                    "subjectType": "tenant",
                    "period": "month",
                    "maxCostUsd": 1_000_000,
                })),
            )
            .await,
        );
        assert_eq!(code(&lifted), "ACCESS_DENIED");
        // The organization's own budgets stay its own.
        let own = set_budget(
            &f,
            &f.owner_credential,
            json!({ "name": "Team cap", "subjectType": "tenant", "period": "day", "maxTokens": 1000 }),
        )
        .await;
        assert_matches(
            &ok(api
                .delete_budget(
                    &f.owner_credential,
                    body(json!({ "tenantId": f.tenant_id, "budgetId": own["id"] })),
                )
                .await),
            json!({ "deleted": true }),
        );
        assert_matches(
            &ok(api
                .delete_budget(
                    &f.root_credential,
                    body(json!({ "tenantId": f.tenant_id, "budgetId": cap["id"] })),
                )
                .await),
            json!({ "deleted": true }),
        );
    });
}

#[test]
fn needs_the_provider_key_again_to_move_a_provider_and_guards_base_urls_an_organization_chose() {
    run(|| async {
        let (f, _) = platform(true).await;
        let api = &f.iam.api.inference;
        let provider = ok(api
            .create_provider(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Self-hosted",
                    "kind": "openai-compatible",
                    "apiKey": "org-secret-key-1234",
                    "baseUrl": "https://llm.acme.example",
                })),
            )
            .await);
        let moved = fails(
            api.update_provider(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "providerId": provider["id"],
                    "baseUrl": "https://collector.evil.example",
                })),
            )
            .await,
        );
        assert_eq!(code(&moved), "INVALID_INPUT");
        assert_matches(
            &ok(api
                .update_provider(
                    &f.owner_credential,
                    body(json!({
                        "tenantId": f.tenant_id,
                        "providerId": provider["id"],
                        "baseUrl": "https://llm2.acme.example",
                        "apiKey": "org-secret-key-5678",
                    })),
                )
                .await),
            json!({ "baseUrl": "https://llm2.acme.example" }),
        );
        ok(api
            .create_model(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "local",
                    "providerId": provider["id"],
                    "upstreamModel": "llama",
                })),
            )
            .await);
        ok(f.iam
            .api
            .policies
            .create(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Models",
                    "document": {
                        "version": 1,
                        "statements": [{ "effect": "allow", "actions": ["inference:invoke"], "resources": ["*"] }],
                    },
                })),
            )
            .await);
        let permit = permit(&f, &f.owner_credential, "local").await;
        assert_matches(
            permit.provider.guard.as_ref().expect("a guard"),
            json!({ "anyPort": true, "allowPrivateNetworks": false }),
        );
    });
}

#[test]
fn counts_what_agents_do_for_people_against_a_group_budget_on_the_agents() {
    run(|| async {
        let f = organization(with_inference).await;
        let owner = &f.owner_credential;
        let tenant_id = f.tenant_id.clone();
        let provider = ok(f
            .iam
            .api
            .inference
            .create_provider(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Anthropic",
                    "kind": "anthropic",
                    "apiKey": "sk-ant-org-key-000000",
                })),
            )
            .await);
        ok(f.iam
            .api
            .inference
            .create_model(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "haiku",
                    "providerId": provider["id"],
                    "upstreamModel": "claude-haiku-4-5",
                })),
            )
            .await);
        let invoke = ok(f
            .iam
            .api
            .roles
            .create(
                owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Models",
                    "document": {
                        "version": 1,
                        "statements": [{ "effect": "allow", "actions": ["inference:invoke"], "resources": ["model/*"] }],
                    },
                })),
            )
            .await);
        let alice = f.member("alice").await;
        let agent = ok(f
            .iam
            .api
            .agents
            .create(
                owner,
                body(json!({ "tenantId": tenant_id, "name": "Looper" })),
            )
            .await);
        let agent_id = agent["id"].as_str().unwrap().to_owned();
        for subject_id in [&alice, &agent_id] {
            bind(&f, &invoke, subject_id).await;
        }
        let bots = ok(f
            .iam
            .api
            .groups
            .create(
                owner,
                body(json!({ "tenantId": tenant_id, "name": "Bots" })),
            )
            .await);
        ok(f.iam
            .api
            .groups
            .add_member(
                owner,
                body(
                    json!({ "tenantId": tenant_id, "groupId": bots["id"], "identityId": agent_id }),
                ),
            )
            .await);
        set_budget(
            &f,
            owner,
            json!({
                "name": "Bots: 2 calls a day",
                "subjectType": "group",
                "subjectId": bots["id"],
                "period": "day",
                "maxRequests": 2,
            }),
        )
        .await;
        let key = ok(f
            .iam
            .api
            .credentials
            .create(
                owner,
                body(json!({ "tenantId": tenant_id, "identityId": agent_id })),
            )
            .await);
        let key = bearer(key["token"].as_str().unwrap());
        let own = permit(&f, &key, "haiku").await;
        record(
            &f,
            &own,
            json!({ "model": "haiku", "inputTokens": 10, "outputTokens": 10 }),
        )
        .await;
        let alice_session = f.sign_in(&alice).await;
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &alice_session,
                body(json!({
                    "tenantId": tenant_id,
                    "agentId": agent_id,
                    "scopes": ["inference:invoke"],
                })),
            )
            .await);
        let delegated = ok(f
            .iam
            .api
            .delegations
            .assume(
                &key,
                body(json!({ "tenantId": tenant_id, "delegationId": delegation["id"] })),
            )
            .await);
        let delegated = bearer(delegated["token"].as_str().unwrap());
        let for_alice = permit(&f, &delegated, "haiku").await;
        record(
            &f,
            &for_alice,
            json!({ "model": "haiku", "inputTokens": 10, "outputTokens": 10 }),
        )
        .await;
        // Two calls used the group's allowance, whichever credential made them.
        for credential in [&delegated, &key] {
            assert_matches(
                &denied(&f, credential, "haiku").await.expect("denied"),
                json!({ "reason": "BUDGET_EXCEEDED" }),
            );
        }
    });
}
