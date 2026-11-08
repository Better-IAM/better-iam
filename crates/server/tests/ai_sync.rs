//! Configuration as code for AI agents, models and budgets (ai-sync.ts through `config.plan`, `config.apply` and
//! `config.export`): ported from tests/config-ai.test.ts.

mod organization_fixture;

use better_iam_core::{CredentialInput, IamError, IamResult};
use better_iam_server::api::Reply;
use better_iam_server::options::Toggle;
use organization_fixture::{Org, assert_matches, body, code, ok, organization, run};
use serde_json::{Value, json};

struct Scenario {
    f: Org,
    tenant_id: String,
    owner: CredentialInput,
}

async fn scenario(inference: bool) -> Scenario {
    let f = organization(|options| {
        if inference {
            options.inference = Some(Toggle::Flag(true));
        }
    })
    .await;
    let tenant_id = f.tenant_id.clone();
    let owner = f.owner_credential.clone();
    f.member("alice").await;
    f.member("bob").await;
    if inference {
        ok(f.iam
            .api
            .inference
            .create_provider(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Anthropic",
                    "kind": "anthropic",
                    "apiKey": "sk-ant-provider-key-0001",
                })),
            )
            .await);
    }
    Scenario {
        f,
        tenant_id,
        owner,
    }
}

fn boundary() -> Value {
    json!({
        "version": 1,
        "statements": [{ "effect": "allow", "actions": ["documents:*"], "resources": ["document/*"] }],
    })
}

fn base() -> Value {
    json!({
        "version": 1,
        "groups": [{ "name": "Engineers", "members": ["alice@acme.test"] }],
        "agents": [
            {
                "name": "Triage",
                "sponsor": "alice@acme.test",
                "purpose": "Sorts incoming tickets",
                "model": "claude-sonnet-5",
                "provider": "anthropic",
                "protocols": ["a2a", "mcp"],
                "maxDelegatedSessionSeconds": 1800,
                "boundary": boundary(),
                "tokenAudiences": ["https://tickets.example.com"],
            },
            { "name": "Reporter", "sponsor": "bob@acme.test", "delegable": false },
        ],
        "inferenceModels": [
            {
                "name": "sonnet",
                "provider": "Anthropic",
                "upstreamModel": "claude-sonnet-5",
                "tier": "frontier",
                "maxOutputTokens": 8000,
                "inputPricePerMTok": 3,
                "outputPricePerMTok": 15,
                "providerTools": "policy",
            },
            { "name": "haiku", "provider": "Anthropic", "upstreamModel": "claude-haiku-4-5", "enabled": false },
        ],
        "inferenceBudgets": [
            {
                "name": "Engineers daily",
                "subject": { "group": "Engineers" },
                "scope": "each",
                "period": "day",
                "maxCostUsd": 20,
            },
            { "name": "Triage rate", "subject": { "agent": "Triage" }, "period": "minute", "maxRequests": 30 },
            {
                "name": "Tenant monthly",
                "subject": "tenant",
                "period": "month",
                "maxTokens": 10_000_000,
                "models": ["sonnet"],
                "alertAtPercent": 80,
            },
        ],
    })
}

const AI_KINDS: [&str; 3] = ["agent", "inferenceModel", "inferenceBudget"];

/// `${kind}:${name}:${action}` of the AI changes of a plan.
fn ai(plan: &Value) -> Vec<String> {
    plan["changes"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|change| AI_KINDS.contains(&change["kind"].as_str().unwrap()))
        .map(|change| {
            format!(
                "{}:{}:{}",
                change["kind"].as_str().unwrap(),
                change["name"].as_str().unwrap(),
                change["action"].as_str().unwrap()
            )
        })
        .collect()
}

async fn plan(s: &Scenario, input: Value) -> IamResult<Value> {
    s.f.iam
        .api
        .config
        .plan(&s.owner, body(input))
        .await
        .and_then(Reply::into_value)
}

async fn apply(s: &Scenario, input: Value) -> Value {
    ok(s.f.iam.api.config.apply(&s.owner, body(input)).await)
}

async fn list(s: &Scenario, group: &str) -> Vec<Value> {
    let input = json!({ "tenantId": s.tenant_id });
    let api = &s.f.iam.api;
    let result = match group {
        "agents" => ok(api.agents.list(&s.owner, body(input)).await),
        "models" => ok(api.inference.list_models(&s.owner, body(input)).await),
        "budgets" => ok(api.inference.list_budgets(&s.owner, body(input)).await),
        _ => unreachable!("{group}"),
    };
    result.as_array().unwrap().clone()
}

fn find<'a>(items: &'a [Value], name: &str) -> &'a Value {
    items
        .iter()
        .find(|item| item["name"] == name)
        .unwrap_or_else(|| panic!("no {name}"))
}

#[test]
fn applies_agents_models_and_budgets_from_a_document_and_exports_them_back_unchanged() {
    run(|| async {
        let s = scenario(true).await;
        let planned = plan(&s, json!({ "tenantId": s.tenant_id, "config": base() }))
            .await
            .unwrap();
        assert_eq!(
            ai(&planned),
            vec![
                "agent:Reporter:create",
                "agent:Triage:create",
                "inferenceModel:haiku:create",
                "inferenceModel:sonnet:create",
                "inferenceBudget:Engineers daily:create",
                "inferenceBudget:Tenant monthly:create",
                "inferenceBudget:Triage rate:create",
            ]
        );
        apply(&s, json!({ "tenantId": s.tenant_id, "config": base() })).await;

        let agents = list(&s, "agents").await;
        assert_matches(
            find(&agents, "Triage"),
            json!({
                "standing": "ok",
                "sponsor": { "email": "alice@acme.test" },
                "agent": {
                    "purpose": "Sorts incoming tickets",
                    "provider": "anthropic",
                    "protocols": ["a2a", "mcp"],
                    "maxDelegatedSessionSeconds": 1800,
                    "boundary": boundary(),
                    "tokenAudiences": ["https://tickets.example.com"],
                },
            }),
        );
        assert_eq!(
            find(&agents, "Reporter")["agent"]["delegable"],
            json!(false)
        );
        let models: Vec<Value> = list(&s, "models")
            .await
            .iter()
            .map(|model| {
                json!([
                    model["name"],
                    model["enabled"],
                    model.get("maxOutputTokens")
                ])
            })
            .collect();
        assert_eq!(
            models,
            vec![json!(["haiku", false, null]), json!(["sonnet", true, 8000])]
        );
        let budgets: Vec<Value> = list(&s, "budgets")
            .await
            .iter()
            .map(|budget| {
                json!([
                    budget["name"],
                    budget["subjectType"],
                    budget.get("subjectName"),
                    budget["period"]
                ])
            })
            .collect();
        assert_eq!(
            budgets,
            vec![
                json!(["Engineers daily", "group", "Engineers", "day"]),
                json!(["Tenant monthly", "tenant", null, "month"]),
                json!(["Triage rate", "identity", "Triage", "minute"]),
            ]
        );

        // The export reads back as the same document: planning it again changes nothing.
        let exported = ok(s
            .f
            .iam
            .api
            .config
            .export(&s.owner, body(json!({ "tenantId": s.tenant_id })))
            .await);
        let exported_agents = exported["agents"].as_array().unwrap();
        assert!(
            exported_agents.iter().any(|agent| {
                agent["name"] == "Triage" && agent["sponsor"] == "alice@acme.test"
            })
        );
        assert!(
            exported["inferenceBudgets"]
                .as_array()
                .unwrap()
                .iter()
                .any(|budget| budget
                    == &json!({ "name": "Triage rate", "subject": { "agent": "Triage" }, "period": "minute", "maxRequests": 30 }))
        );
        let again = plan(&s, json!({ "tenantId": s.tenant_id, "config": exported }))
            .await
            .unwrap();
        let changed: Vec<&Value> = again["changes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|change| change["action"] != "unchanged")
            .collect();
        assert!(changed.is_empty(), "{changed:?}");
    });
}

#[test]
fn updates_in_place_and_prunes_what_the_document_no_longer_names() {
    run(|| async {
        let s = scenario(true).await;
        apply(&s, json!({ "tenantId": s.tenant_id, "config": base() })).await;
        let mut next = base();
        let mut triage = next["agents"][0].clone();
        triage["sponsor"] = json!("bob@acme.test");
        triage["purpose"] = json!("Routes tickets");
        next["agents"] = json!([triage]);
        let mut sonnet = next["inferenceModels"][0].clone();
        sonnet["outputPricePerMTok"] = json!(12);
        next["inferenceModels"] = json!([sonnet]);
        let mut rate = next["inferenceBudgets"][1].clone();
        rate["maxRequests"] = json!(10);
        next["inferenceBudgets"] = json!([rate]);
        let planned = plan(
            &s,
            json!({ "tenantId": s.tenant_id, "config": next, "prune": true }),
        )
        .await
        .unwrap();
        let lines: Vec<String> = planned["changes"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|change| AI_KINDS.contains(&change["kind"].as_str().unwrap()))
            .map(|change| {
                let fields = change["fields"]
                    .as_array()
                    .map(|fields| {
                        fields
                            .iter()
                            .map(|field| field.as_str().unwrap())
                            .collect::<Vec<_>>()
                            .join(",")
                    })
                    .unwrap_or_default();
                format!(
                    "{}:{}:{}:{}",
                    change["kind"].as_str().unwrap(),
                    change["name"].as_str().unwrap(),
                    change["action"].as_str().unwrap(),
                    fields
                )
            })
            .collect();
        assert_eq!(
            lines,
            vec![
                "agent:Reporter:delete:",
                "agent:Triage:update:purpose,sponsor",
                "inferenceModel:haiku:delete:",
                "inferenceModel:sonnet:update:outputPricePerMTok",
                "inferenceBudget:Engineers daily:delete:",
                "inferenceBudget:Tenant monthly:delete:",
                "inferenceBudget:Triage rate:update:maxRequests",
            ]
        );
        apply(
            &s,
            json!({ "tenantId": s.tenant_id, "config": next, "prune": true }),
        )
        .await;
        let agents: Vec<Value> = list(&s, "agents")
            .await
            .iter()
            .map(|agent| {
                json!([
                    agent["name"],
                    agent["sponsor"]["email"],
                    agent["agent"]["purpose"]
                ])
            })
            .collect();
        assert_eq!(
            agents,
            vec![json!(["Triage", "bob@acme.test", "Routes tickets"])]
        );
        let models: Vec<Value> = list(&s, "models")
            .await
            .iter()
            .map(|model| json!([model["name"], model["outputPricePerMTok"]]))
            .collect();
        assert_eq!(models, vec![json!(["sonnet", 12])]);
        let budgets: Vec<Value> = list(&s, "budgets")
            .await
            .iter()
            .map(|budget| json!([budget["name"], budget["maxRequests"]]))
            .collect();
        assert_eq!(budgets, vec![json!(["Triage rate", 10])]);
        let audit = ok(s
            .f
            .iam
            .api
            .audit
            .list(
                &s.owner,
                body(json!({ "tenantId": s.tenant_id, "action": "agent:sponsor-change" })),
            )
            .await);
        assert_eq!(audit.as_array().unwrap().len(), 1);
    });
}

fn message_contains(error: &IamError, text: &str) {
    assert!(
        error.message.contains(text),
        "expected {text:?} in {:?}",
        error.message
    );
}

#[test]
fn refuses_documents_naming_things_that_do_not_exist() {
    run(|| async {
        let s = scenario(true).await;
        let refused = |config: Value| {
            let s = &s;
            async move {
                let mut document = json!({ "version": 1 });
                for (key, value) in config.as_object().unwrap() {
                    document[key] = value.clone();
                }
                plan(s, json!({ "tenantId": s.tenant_id, "config": document }))
                    .await
                    .expect_err("refused")
            }
        };
        let error =
            refused(json!({ "agents": [{ "name": "Ghost", "sponsor": "nobody@acme.test" }] }))
                .await;
        assert_eq!(code(&error), "INVALID_INPUT");
        message_contains(&error, "no person");
        let error = refused(json!({
            "inferenceModels": [{ "name": "x", "provider": "Missing", "upstreamModel": "x-1" }],
        }))
        .await;
        message_contains(&error, "no provider named Missing");
        let error = refused(json!({
            "inferenceBudgets": [{ "name": "B", "subject": { "agent": "Nobody" }, "period": "day", "maxRequests": 1 }],
        }))
        .await;
        message_contains(&error, "no agent Nobody");
        let error = refused(json!({
            "inferenceBudgets": [{ "name": "B", "subject": "tenant", "period": "day" }],
        }))
        .await;
        assert_eq!(code(&error), "INVALID_INPUT");
        let error = refused(json!({
            "agents": [
                { "name": "Twin", "sponsor": "alice@acme.test" },
                { "name": "twin", "sponsor": "alice@acme.test" },
            ],
        }))
        .await;
        message_contains(&error, "Duplicate agent");

        let plain = scenario(false).await;
        let error = plan(
            &plain,
            json!({
                "tenantId": plain.tenant_id,
                "config": {
                    "version": 1,
                    "inferenceModels": [{ "name": "x", "provider": "A", "upstreamModel": "x" }],
                },
            }),
        )
        .await
        .expect_err("refused");
        message_contains(&error, "inference option");
    });
}
