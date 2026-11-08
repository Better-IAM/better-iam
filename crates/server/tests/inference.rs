//! Inference access control, budgets and metering: ported from tests/inference.test.ts and the budget and
//! stored-reference cases of tests/security-inference.test.ts. Providers, models and budgets are written as the
//! `inference` API group writes them, and `iam.inference` (`authorize`, `record`) is the runtime of
//! `createInferenceRuntime` built over the module (inference_support), so the suites run without that API group.

mod inference_support;
mod organization_fixture;

use better_iam_core::{Filter, IamStoreExt};
use better_iam_server::better_iam;
use better_iam_server::inference::{
    BudgetWindow, INFERENCE_RESOURCE_TYPE, InferenceModel, InferenceTokenUsage, base_url,
    budget_window, inference_plugins, model_name, price, provider_key, provider_tool_list,
    resolve_model_resource, usage_cost, visible_models, visible_providers,
};
use better_iam_server::inference_gateway::{GatewayAuthorization, GatewayRuntime};
use better_iam_server::options::{BetterIamOptions, InferenceOptions, Toggle};
use better_iam_server::secrets::SecretRotationOptions;
use inference_support::{
    Runtime, SECRET, audit_actions, bearer, create_model, create_provider, id_of, inference_org,
    may_invoke, model_ref, permit, set_budget, token_of, update_model,
};
use organization_fixture::{Org, body, code, ok, organization, run};
use serde_json::{Value, json};

const PROVIDER_KEY: &str = "sk-ant-secret-provider-key-0042";

struct Setup {
    f: Org,
    runtime: std::sync::Arc<Runtime>,
    provider: better_iam_core::Record,
    alice: String,
    alice_token: String,
    role: String,
}

/// Acme with inference on, one Anthropic provider, a frontier and a small model, and alice limited to small ones.
async fn setup() -> Setup {
    let f = inference_org(None).await;
    let tenant = f.tenant_id.clone();
    let provider = create_provider(&f, &tenant, "Anthropic", "anthropic", PROVIDER_KEY, None).await;
    create_model(
        &f,
        &tenant,
        "opus",
        &id_of(&provider),
        "claude-opus-5-5",
        json!({ "tier": "frontier", "inputPricePerMTok": 5, "outputPricePerMTok": 25 }),
    )
    .await;
    create_model(
        &f,
        &tenant,
        "haiku",
        &id_of(&provider),
        "claude-haiku-4-5",
        json!({ "tier": "small", "inputPricePerMTok": 1, "outputPricePerMTok": 5 }),
    )
    .await;
    let alice = f.member("alice").await;
    let role = f
        .grant(
            &alice,
            json!([{
                "effect": "allow",
                "actions": ["inference:invoke"],
                "resources": ["model/*"],
                "conditions": { "StringEquals": { "resource.tier": "small" } },
            }]),
        )
        .await;
    let alice_token = token_of(&f.sign_in(&alice).await);
    let runtime = Runtime::new(&f);
    Setup {
        f,
        runtime,
        provider,
        alice,
        alice_token,
        role,
    }
}

fn owner_token(f: &Org) -> String {
    token_of(&f.owner_credential)
}

fn check_json(check: &better_iam_server::inference::InvocationCheck) -> Value {
    check.to_json()
}

fn matches(actual: &Value, expected: Value) {
    organization_fixture::assert_matches(actual, expected);
}

#[test]
fn seals_provider_keys_and_decides_model_access_with_ordinary_policies() {
    run(|| async move {
        let Setup {
            f,
            runtime,
            provider,
            alice_token,
            ..
        } = setup().await;
        matches(
            &Value::Object(provider.clone()),
            json!({ "kind": "anthropic", "baseUrl": "https://api.anthropic.com", "keyHint": "…0042" }),
        );
        let stored = f
            .store()
            .get("inferenceProviders", &id_of(&provider))
            .await
            .unwrap()
            .unwrap();
        assert!(!Value::Object(stored).to_string().contains(PROVIDER_KEY));

        let tenant = f.tenant_id.clone();
        let check = |token: String, model: &'static str| {
            let runtime = runtime.clone();
            let tenant = tenant.clone();
            async move {
                runtime
                    .check(
                        &bearer(&token),
                        json!({ "tenantId": tenant, "model": model }),
                    )
                    .await
            }
        };
        matches(
            &check_json(&check(alice_token.clone(), "opus").await.unwrap()),
            json!({ "allowed": false, "reason": "ACCESS_DENIED" }),
        );
        matches(
            &check_json(&check(alice_token.clone(), "haiku").await.unwrap()),
            json!({
                "allowed": true,
                "model": { "name": "haiku", "tier": "small", "provider": { "name": "Anthropic", "kind": "anthropic" } },
            }),
        );
        assert_eq!(
            code(&check(alice_token.clone(), "nope").await.unwrap_err()),
            "NOT_FOUND"
        );
        // The models alice may use (`listMine`): the enabled ones her policies allow.
        let mine: Vec<String> = runtime
            .models(&bearer(&alice_token))
            .await
            .unwrap()
            .into_iter()
            .map(|model| model.name)
            .collect();
        assert_eq!(mine, ["haiku"]);
        let all: Vec<String> = runtime
            .models(&f.owner_credential)
            .await
            .unwrap()
            .into_iter()
            .map(|model| model.name)
            .collect();
        assert_eq!(all, ["haiku", "opus"]);

        // The same decision through the generic authorize API.
        assert!(may_invoke(&f, &alice_token, "haiku").await);

        // Disabling a model stops it for everyone.
        update_model(&f, &tenant, "haiku", json!({ "enabled": false })).await;
        matches(
            &check_json(&check(alice_token.clone(), "haiku").await.unwrap()),
            json!({ "allowed": false, "reason": "MODEL_DISABLED" }),
        );

        // The gateway runtime opens the key server-side only.
        let owner = permit(&runtime, &owner_token(&f), "opus").await;
        assert_eq!(owner.provider.api_key, PROVIDER_KEY);
        assert_eq!(owner.provider.kind, "anthropic");
        assert_eq!(owner.provider.guard, None);
        assert_eq!(owner.upstream_model, "claude-opus-5-5");
    });
}

#[test]
fn inherits_models_and_providers_from_the_platform() {
    run(|| async move {
        let Setup { f, .. } = setup().await;
        // The platform defines a provider and model once, at the root tenant; organizations inherit them.
        let root = f.root_tenant.clone();
        let shared = create_provider(
            &f,
            &root,
            "Platform vLLM",
            "openai-compatible",
            "platform-key-123456",
            Some("https://llm.platform.example/v1"),
        )
        .await;
        create_model(
            &f,
            &root,
            "llama-local",
            &id_of(&shared),
            "meta-llama/Llama-4",
            json!({ "tier": "small" }),
        )
        .await;
        let ctx = f.iam.ctx.clone();
        let tenant = f.tenant_id.clone();
        let (models, providers) = f
            .store()
            .transaction(|tx| async move {
                let models = visible_models(&ctx, &tx, &tenant).await?;
                let providers = visible_providers(&ctx, &tx, &tenant).await?;
                Ok((models, providers))
            })
            .await
            .unwrap();
        let llama = models
            .iter()
            .find(|found| found.model.name == "llama-local")
            .unwrap();
        let view = better_iam_server::inference::public_model(
            &llama.model,
            llama.provider.as_ref(),
            &f.tenant_id,
        );
        matches(
            &view.to_json(),
            json!({ "inherited": true, "provider": { "id": id_of(&shared), "kind": "openai-compatible" } }),
        );
        assert_eq!(
            models
                .iter()
                .map(|found| found.model.name.as_str())
                .collect::<Vec<_>>(),
            ["haiku", "llama-local", "opus"]
        );
        // Own providers first, then the inherited ones.
        assert_eq!(
            providers
                .iter()
                .map(|provider| (provider.name.as_str(), provider.tenant_id != f.tenant_id))
                .collect::<Vec<_>>(),
            [("Anthropic", false), ("Platform vLLM", true)]
        );
        // A root provider's custom base URL is the platform's choice: no SSRF guard on it.
        let owner = permit(&Runtime::new(&f), &owner_token(&f), "llama-local").await;
        assert_eq!(owner.provider.guard, None);
        assert_eq!(owner.provider.base_url, "https://llm.platform.example/v1");
    });
}

#[test]
fn guards_base_urls_an_organization_chose() {
    run(|| async move {
        let f = inference_org(Some(InferenceOptions {
            allow_custom_base_urls: Some(true),
            ..InferenceOptions::default()
        }))
        .await;
        let tenant = f.tenant_id.clone();
        let provider = create_provider(
            &f,
            &tenant,
            "Self-hosted",
            "openai-compatible",
            "org-secret-key-1234",
            Some("https://llm2.acme.example"),
        )
        .await;
        create_model(&f, &tenant, "local", &id_of(&provider), "llama", json!({})).await;
        f.grant(
            &f.owner_id,
            json!([{ "effect": "allow", "actions": ["inference:invoke"], "resources": ["*"] }]),
        )
        .await;
        let granted = permit(&Runtime::new(&f), &owner_token(&f), "local").await;
        assert_eq!(
            granted.provider.guard,
            Some(
                json!({ "anyPort": true, "allowInsecureLocalhost": false, "allowPrivateNetworks": false })
            )
        );
    });
}

#[test]
fn re_seals_provider_keys_when_the_deployment_secret_rotates() {
    run(|| async move {
        let Setup { f, .. } = setup().await;
        let new_secret = "a-brand-new-deployment-secret-of-32-chars";
        let mut options =
            BetterIamOptions::new(f.store(), new_secret, organization_fixture::ORIGIN);
        options.previous_secrets = Some(vec![SECRET.to_owned()]);
        options.inference = Some(Toggle::Flag(true));
        let rotated = better_iam(options).unwrap();
        let result = rotated
            .rotate_secrets(&SecretRotationOptions::default())
            .await
            .unwrap();
        assert_eq!(result.resealed.get("inferenceProviders"), Some(&1.0));
        let runtime = std::sync::Arc::new(Runtime {
            ctx: rotated.ctx.clone(),
        });
        let granted = permit(&runtime, &owner_token(&f), "opus").await;
        assert_eq!(granted.provider.api_key, PROVIDER_KEY);
        // Without the previous secret the key is still readable: it was re-sealed with the new one.
        let mut options =
            BetterIamOptions::new(f.store(), new_secret, organization_fixture::ORIGIN);
        options.inference = Some(Toggle::Flag(true));
        let fresh = better_iam(options).unwrap();
        let runtime = std::sync::Arc::new(Runtime {
            ctx: fresh.ctx.clone(),
        });
        let granted = permit(&runtime, &owner_token(&f), "opus").await;
        assert_eq!(granted.provider.api_key, PROVIDER_KEY);
    });
}

#[test]
fn validates_its_options_at_construction() {
    run(|| async move {
        let f = organization(|_| {}).await;
        for inference in [
            json!({ "usageRetentionDays": 0 }),
            json!({ "usageRetentionDays": 1.5 }),
            json!("yes"),
            json!({ "allowCustomBaseUrls": "yes" }),
        ] {
            let options = BetterIamOptions::from_model(
                f.store(),
                json!({
                    "database": {},
                    "secret": SECRET,
                    "baseURL": organization_fixture::ORIGIN,
                    "inference": inference,
                }),
            );
            let error = inference_plugins(&options).err().expect("refused");
            assert_eq!(error.code, "INVALID_CONFIG", "{inference}");
        }
        let mut options = BetterIamOptions::new(f.store(), SECRET, organization_fixture::ORIGIN);
        options.inference = Some(Toggle::Options(InferenceOptions {
            usage_retention_days: Some(0.0),
            ..InferenceOptions::default()
        }));
        assert_eq!(
            better_iam(options).err().expect("refused").code,
            "INVALID_CONFIG"
        );
        let mut options = BetterIamOptions::new(f.store(), SECRET, organization_fixture::ORIGIN);
        options.inference = Some(Toggle::Flag(false));
        assert!(inference_plugins(&options).unwrap().is_empty());
        options.inference = Some(Toggle::Flag(true));
        let plugins = inference_plugins(&options).unwrap();
        assert_eq!(plugins[0].id(), "better-iam:inference");
        let types = plugins[0].resource_types();
        assert_eq!(types.keys().collect::<Vec<_>>(), ["model", "model-tool"]);
        assert_eq!(
            types["model"].actions.as_deref(),
            Some(&["inference:invoke".to_owned()][..])
        );
    });
}

#[test]
fn is_refused_on_deployments_without_the_inference_option() {
    run(|| async move {
        let f = organization(|_| {}).await;
        let runtime = Runtime::new(&f);
        let error = runtime
            .check(
                &f.owner_credential,
                json!({ "tenantId": f.tenant_id, "model": "haiku" }),
            )
            .await
            .unwrap_err();
        assert_eq!(code(&error), "FEATURE_DISABLED");
        assert_eq!(error.status, 403);
        let error = runtime
            .authorize(&f.owner_credential, &json!({ "model": "haiku" }))
            .await
            .unwrap_err();
        assert_eq!(code(&error), "FEATURE_DISABLED");
        // Without the option, `model/...` is no inference resource.
        let ctx = f.iam.ctx.clone();
        let reference = model_ref(&f, "haiku");
        let resolved = f
            .store()
            .transaction(|tx| async move { resolve_model_resource(&ctx, &tx, &reference).await })
            .await
            .unwrap();
        assert!(resolved.is_none());
    });
}

#[test]
fn resolves_models_and_provider_tools_for_the_decision_engine() {
    run(|| async move {
        let Setup { f, .. } = setup().await;
        let resolve = |kind: &'static str, id: &'static str| {
            let ctx = f.iam.ctx.clone();
            let reference = better_iam_core::ResourceRef {
                tenant_id: f.tenant_id.clone(),
                kind: kind.to_owned(),
                id: id.to_owned(),
            };
            let store = f.store();
            async move {
                store
                    .transaction(
                        |tx| async move { resolve_model_resource(&ctx, &tx, &reference).await },
                    )
                    .await
            }
        };
        let model = resolve(INFERENCE_RESOURCE_TYPE, "haiku")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Value::Object(model.attributes.unwrap()),
            json!({
                "provider": "Anthropic",
                "providerKind": "anthropic",
                "upstreamModel": "claude-haiku-4-5",
                "enabled": true,
                "tier": "small",
                "inputPricePerMTok": 1,
                "outputPricePerMTok": 5,
            })
        );
        assert_eq!(
            code(
                &resolve(INFERENCE_RESOURCE_TYPE, "missing")
                    .await
                    .unwrap_err()
            ),
            "NOT_FOUND"
        );
        let tool = resolve("model-tool", "mcp:kb.acme.test")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            Value::Object(tool.attributes.unwrap()),
            json!({ "kind": "mcp", "host": "kb.acme.test" })
        );
        let tool = resolve("model-tool", "web_search").await.unwrap().unwrap();
        assert_eq!(
            Value::Object(tool.attributes.unwrap()),
            json!({ "kind": "web_search" })
        );
        let error = resolve("model-tool", "Web Search").await.unwrap_err();
        assert_eq!(
            (code(&error), error.message.as_str()),
            ("NOT_FOUND", "Unknown provider tool")
        );
        assert!(resolve("document", "x").await.unwrap().is_none());
    });
}

#[test]
fn meters_calls_refuses_exhausted_budgets_until_the_window_resets() {
    run(|| async move {
        let Setup {
            f,
            runtime,
            alice,
            alice_token,
            ..
        } = setup().await;
        let tenant = f.tenant_id.clone();
        let budget = set_budget(
            &f,
            &tenant,
            "Daily per person",
            json!({ "subjectType": "tenant", "scope": "each", "period": "day", "maxTokens": 1000, "alertAtPercent": 80 }),
        )
        .await;
        let budget_id = id_of(&budget);
        let used = permit(&runtime, &alice_token, "haiku").await;
        let budgets = used.check["budgets"].as_array().unwrap();
        assert_eq!(budgets.len(), 1);
        matches(
            &budgets[0],
            json!({ "budgetId": budget_id, "remainingTokens": 1000 }),
        );
        let record = runtime
            .record_usage(
                &used,
                json!({ "model": "haiku", "inputTokens": 600, "outputTokens": 300 }),
            )
            .await
            .unwrap();
        // 600 × $1 + 300 × $5 per million tokens = 2100 micro-dollars.
        assert_eq!(record.identity_id, alice);
        assert_eq!(record.cost_micros, 2100.0);
        assert_eq!(record.status, "ok");
        assert_eq!(record.session_kind.as_deref(), Some("user"));

        let check = |token: String, estimated: Option<u32>| {
            let runtime = runtime.clone();
            let tenant = tenant.clone();
            async move {
                let mut input = json!({ "tenantId": tenant, "model": "haiku" });
                if let Some(estimated) = estimated {
                    input["estimatedTokens"] = json!(estimated);
                }
                runtime
                    .check(&bearer(&token), input)
                    .await
                    .unwrap()
                    .to_json()
            }
        };
        matches(
            &check(alice_token.clone(), Some(50)).await,
            json!({ "allowed": true }),
        );
        matches(
            &check(alice_token.clone(), Some(200)).await,
            json!({
                "allowed": false,
                "reason": "BUDGET_EXCEEDED",
                "budget": { "budgetId": budget_id, "usedTokens": 900, "remainingTokens": 100 },
            }),
        );
        check(alice_token.clone(), Some(200)).await;
        // The owner has their own share of an `each` budget.
        matches(
            &check(owner_token(&f), Some(900)).await,
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
        let counters = f
            .find(
                "inferenceCounters",
                Filter::new().eq("budgetId", budget_id.clone()),
            )
            .await;
        assert_eq!(counters.len(), 1);
        matches(
            &Value::Object(counters[0].clone()),
            json!({ "subjectKey": alice, "tokens": 900, "costMicros": 2100, "requests": 1, "alerted": true, "exceeded": true }),
        );
        let usage = f
            .find(
                "inferenceUsage",
                Filter::new().eq("tenantId", tenant.clone()),
            )
            .await;
        assert_eq!(usage.len(), 1);
        assert_eq!(
            usage[0].keys().map(String::as_str).collect::<Vec<_>>(),
            [
                "id",
                "tenantId",
                "identityId",
                "sessionKind",
                "model",
                "providerId",
                "inputTokens",
                "outputTokens",
                "costMicros",
                "status",
                "createdAt",
                "expiresAt",
            ]
        );
        assert_eq!(
            usage[0]["expiresAt"].as_f64().unwrap() - usage[0]["createdAt"].as_f64().unwrap(),
            90.0 * 86_400_000.0
        );

        // The next day starts a fresh window.
        f.advance(86_400_000.0);
        let fresh = token_of(&f.sign_in(&alice).await);
        matches(&check(fresh, Some(900)).await, json!({ "allowed": true }));
    });
}

#[test]
fn caps_an_agent_across_everything_it_does_including_on_peoples_behalf() {
    run(|| async move {
        let Setup {
            f,
            runtime,
            alice,
            alice_token,
            role,
            ..
        } = setup().await;
        let tenant = f.tenant_id.clone();
        let agent = ok(f
            .iam
            .api
            .agents
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "name": "Summarizer" })),
            )
            .await);
        let agent_id = agent["id"].as_str().unwrap().to_owned();
        ok(f.iam
            .api
            .bindings
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "roleId": role, "subjectType": "identity", "subjectId": agent_id })),
            )
            .await);
        let key = ok(f
            .iam
            .api
            .credentials
            .create(
                &f.owner_credential,
                body(json!({ "tenantId": tenant, "identityId": agent_id })),
            )
            .await);
        let key_token = key["token"].as_str().unwrap().to_owned();
        let cap = set_budget(
            &f,
            &tenant,
            "Summarizer cap",
            json!({ "subjectType": "identity", "subjectId": agent_id, "period": "month", "maxCostMicros": 1000 }),
        )
        .await;
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &bearer(&alice_token),
                body(json!({ "tenantId": tenant, "agentId": agent_id, "scopes": ["inference:invoke"] })),
            )
            .await);
        let delegation_id = delegation["id"].as_str().unwrap().to_owned();
        let delegated = ok(f
            .iam
            .api
            .delegations
            .assume(
                &bearer(&key_token),
                body(json!({ "tenantId": tenant, "delegationId": delegation_id })),
            )
            .await);
        let delegated_token = delegated["token"].as_str().unwrap().to_owned();
        // Acting for alice: alice's access (small models only), metered to alice and to the agent.
        match runtime
            .authorize(&bearer(&delegated_token), &json!({ "model": "opus" }))
            .await
            .unwrap()
        {
            GatewayAuthorization::Denied(denied) => {
                assert_eq!(denied.reason.as_deref(), Some("ACCESS_DENIED"))
            }
            GatewayAuthorization::Permit(_) => panic!("opus is not alice's"),
        }
        let on_behalf = permit(&runtime, &delegated_token, "haiku").await;
        let record = runtime
            .record_usage(
                &on_behalf,
                json!({ "model": "haiku", "inputTokens": 500, "outputTokens": 100 }),
            )
            .await
            .unwrap();
        assert_eq!(record.identity_id, alice);
        assert_eq!(record.agent_id.as_deref(), Some(agent_id.as_str()));
        assert_eq!(
            record.delegation_id.as_deref(),
            Some(delegation_id.as_str())
        );
        assert_eq!(record.session_kind.as_deref(), Some("delegated"));
        assert_eq!(record.cost_micros, 1000.0);
        // The agent's cap is spent, for its own key too; alice herself is not capped.
        match runtime
            .authorize(&bearer(&key_token), &json!({ "model": "haiku" }))
            .await
            .unwrap()
        {
            GatewayAuthorization::Denied(denied) => matches(
                &denied.to_json(),
                json!({ "reason": "BUDGET_EXCEEDED", "budget": { "budgetId": id_of(&cap) } }),
            ),
            GatewayAuthorization::Permit(_) => panic!("the agent's cap is spent"),
        }
        assert!(matches!(
            runtime
                .authorize(&bearer(&alice_token), &json!({ "model": "haiku" }))
                .await
                .unwrap(),
            GatewayAuthorization::Permit(_)
        ));
        // A call without an agent carries no agentId.
        let own = runtime
            .record_usage(
                &permit(&runtime, &alice_token, "haiku").await,
                json!({ "model": "haiku", "inputTokens": 1, "outputTokens": 0 }),
            )
            .await
            .unwrap();
        assert_eq!(own.agent_id, None);
        assert_eq!(own.delegation_id, None);
    });
}

#[test]
fn rate_limits_calls_per_window_with_max_requests() {
    run(|| async move {
        let Setup {
            f,
            runtime,
            alice,
            alice_token,
            ..
        } = setup().await;
        let tenant = f.tenant_id.clone();
        let limit = set_budget(
            &f,
            &tenant,
            "Three calls an hour",
            json!({ "subjectType": "identity", "subjectId": alice, "period": "hour", "maxRequests": 3 }),
        )
        .await;
        for _ in 0..3 {
            let granted = permit(&runtime, &alice_token, "haiku").await;
            runtime
                .record_usage(
                    &granted,
                    json!({ "model": "haiku", "inputTokens": 1, "outputTokens": 1 }),
                )
                .await
                .unwrap();
        }
        match runtime
            .authorize(&bearer(&alice_token), &json!({ "model": "haiku" }))
            .await
            .unwrap()
        {
            GatewayAuthorization::Denied(denied) => matches(
                &denied.to_json(),
                json!({
                    "reason": "BUDGET_EXCEEDED",
                    "budget": { "budgetId": id_of(&limit), "usedRequests": 3, "remainingRequests": 0 },
                }),
            ),
            GatewayAuthorization::Permit(_) => panic!("rate limited"),
        }
        f.advance(3_600_000.0);
        let fresh = token_of(&f.sign_in(&alice).await);
        assert!(matches!(
            runtime
                .authorize(&bearer(&fresh), &json!({ "model": "haiku" }))
                .await
                .unwrap(),
            GatewayAuthorization::Permit(_)
        ));
    });
}

#[test]
fn counts_what_agents_do_for_people_against_a_group_budget_on_the_agents() {
    run(|| async move {
        let f = inference_org(None).await;
        let tenant = f.tenant_id.clone();
        let owner = f.owner_credential.clone();
        let provider = create_provider(
            &f,
            &tenant,
            "Anthropic",
            "anthropic",
            "sk-ant-org-key-000000",
            None,
        )
        .await;
        create_model(
            &f,
            &tenant,
            "haiku",
            &id_of(&provider),
            "claude-haiku-4-5",
            json!({}),
        )
        .await;
        let alice = f.member("alice").await;
        let agent = ok(f
            .iam
            .api
            .agents
            .create(
                &owner,
                body(json!({ "tenantId": tenant, "name": "Looper" })),
            )
            .await);
        let agent_id = agent["id"].as_str().unwrap().to_owned();
        let statements = json!([{ "effect": "allow", "actions": ["inference:invoke"], "resources": ["model/*"] }]);
        f.grant(&alice, statements.clone()).await;
        f.grant(&agent_id, statements).await;
        let bots = ok(f
            .iam
            .api
            .groups
            .create(&owner, body(json!({ "tenantId": tenant, "name": "Bots" })))
            .await);
        let bots_id = bots["id"].as_str().unwrap().to_owned();
        ok(f.iam
            .api
            .groups
            .add_member(
                &owner,
                body(json!({ "tenantId": tenant, "groupId": bots_id, "identityId": agent_id })),
            )
            .await);
        set_budget(
            &f,
            &tenant,
            "Bots: 2 calls a day",
            json!({ "subjectType": "group", "subjectId": bots_id, "period": "day", "maxRequests": 2 }),
        )
        .await;
        let key = ok(f
            .iam
            .api
            .credentials
            .create(
                &owner,
                body(json!({ "tenantId": tenant, "identityId": agent_id })),
            )
            .await);
        let key_token = key["token"].as_str().unwrap().to_owned();
        let runtime = Runtime::new(&f);
        let own = permit(&runtime, &key_token, "haiku").await;
        runtime
            .record_usage(
                &own,
                json!({ "model": "haiku", "inputTokens": 10, "outputTokens": 10 }),
            )
            .await
            .unwrap();
        let alice_token = token_of(&f.sign_in(&alice).await);
        let delegation = ok(f
            .iam
            .api
            .delegations
            .grant(
                &bearer(&alice_token),
                body(json!({ "tenantId": tenant, "agentId": agent_id, "scopes": ["inference:invoke"] })),
            )
            .await);
        let delegated = ok(f
            .iam
            .api
            .delegations
            .assume(
                &bearer(&key_token),
                body(json!({ "tenantId": tenant, "delegationId": delegation["id"] })),
            )
            .await);
        let delegated_token = delegated["token"].as_str().unwrap().to_owned();
        let for_alice = permit(&runtime, &delegated_token, "haiku").await;
        runtime
            .record_usage(
                &for_alice,
                json!({ "model": "haiku", "inputTokens": 10, "outputTokens": 10 }),
            )
            .await
            .unwrap();
        // Two calls used the group's allowance, whichever credential made them.
        for token in [&delegated_token, &key_token] {
            match runtime
                .authorize(&bearer(token), &json!({ "model": "haiku" }))
                .await
                .unwrap()
            {
                GatewayAuthorization::Denied(denied) => {
                    assert_eq!(denied.reason.as_deref(), Some("BUDGET_EXCEEDED"))
                }
                GatewayAuthorization::Permit(_) => panic!("the group's allowance is spent"),
            }
        }
    });
}

#[test]
fn validates_names_prices_keys_and_base_urls() {
    assert_eq!(
        model_name(Some(&json!("claude-opus-5.5"))).unwrap(),
        "claude-opus-5.5"
    );
    for bad in [
        json!(""),
        json!("-x"),
        json!("a b"),
        json!(5),
        json!("a".repeat(129)),
    ] {
        assert_eq!(
            model_name(Some(&bad)).unwrap_err().message,
            "Model names use 1-128 letters, digits or ._:/@+- characters and start with a letter or digit"
        );
    }
    assert_eq!(price(Some(&json!(0.3)), "inputPricePerMTok").unwrap(), 0.3);
    for bad in [json!(-1), json!(10_001), json!("1")] {
        assert_eq!(
            price(Some(&bad), "maxCostUsd").unwrap_err().message,
            "maxCostUsd must be a price from 0 to 10000 dollars per million tokens"
        );
    }
    assert!(provider_key(Some(&json!("sk-12345"))).is_ok());
    for bad in [json!("short"), json!("has space here"), json!(12345678)] {
        assert_eq!(
            provider_key(Some(&bad)).unwrap_err().message,
            "apiKey must be 8-4096 characters without whitespace"
        );
    }
    let settings = InferenceOptions::default();
    assert_eq!(
        base_url(Some(&json!("https://llm.example/v1/")), &settings).unwrap(),
        "https://llm.example/v1"
    );
    assert_eq!(
        base_url(Some(&json!("https://LLM.example")), &settings).unwrap(),
        "https://llm.example"
    );
    for bad in [
        "http://llm.example",
        "https://user:pw@llm.example",
        "https://llm.example/?q=1",
        "https://llm.example/#x",
        "http://localhost:8080",
    ] {
        assert_eq!(
            base_url(Some(&json!(bad)), &settings).unwrap_err().message,
            "baseUrl must be an https URL without credentials or query",
            "{bad}"
        );
    }
    assert_eq!(
        base_url(Some(&json!("not a url")), &settings)
            .unwrap_err()
            .message,
        "baseUrl must be an absolute URL"
    );
    assert_eq!(
        base_url(None, &settings).unwrap_err().message,
        "Invalid baseUrl"
    );
    let local = InferenceOptions {
        allow_insecure_localhost: Some(true),
        ..InferenceOptions::default()
    };
    assert_eq!(
        base_url(Some(&json!("http://localhost:8080/")), &local).unwrap(),
        "http://localhost:8080"
    );
    assert_eq!(
        provider_tool_list(Some(&json!([
            "web_search",
            "web_search",
            "mcp:kb.acme.test"
        ])))
        .unwrap(),
        ["web_search", "mcp:kb.acme.test"]
    );
    assert_eq!(
        provider_tool_list(Some(&json!("web_search")))
            .unwrap_err()
            .message,
        "tools must be a list"
    );
    assert!(provider_tool_list(Some(&json!(["Web Search"]))).is_err());
    assert!(provider_tool_list(Some(&json!([1]))).is_err());
}

#[test]
fn computes_windows_and_costs() {
    // 2026-12-15T10:20:30Z.
    let now = 1_797_330_030_000.0;
    assert_eq!(
        budget_window("minute", now),
        BudgetWindow {
            start: 1_797_330_000_000.0,
            end: 1_797_330_060_000.0
        }
    );
    assert_eq!(
        budget_window("hour", now),
        BudgetWindow {
            start: 1_797_328_800_000.0,
            end: 1_797_332_400_000.0
        }
    );
    assert_eq!(
        budget_window("day", now),
        BudgetWindow {
            start: 1_797_292_800_000.0,
            end: 1_797_379_200_000.0
        }
    );
    // December rolls over into January of the next year.
    assert_eq!(
        budget_window("month", now),
        BudgetWindow {
            start: 1_796_083_200_000.0,
            end: 1_798_761_600_000.0
        }
    );
    let model: InferenceModel = serde_json::from_value(json!({
        "id": "m", "tenantId": "t", "name": "sonnet", "providerId": "p", "upstreamModel": "u",
        "enabled": true, "createdAt": 0, "updatedAt": 0,
        "inputPricePerMTok": 3, "outputPricePerMTok": 15, "cachedInputPricePerMTok": 0.3,
    }))
    .unwrap();
    let mut usage = InferenceTokenUsage::new(10.0, 20.0);
    usage.cache_read_tokens = Some(5.0);
    // 10 × $3 + 5 cached × $0.30 + 20 × $15 per million = 331.5 micro-dollars.
    assert_eq!(usage_cost(&model, &usage), 331.5);
    usage.cache_write_tokens = Some(100.0);
    assert_eq!(usage_cost(&model, &usage), 631.5);
}
