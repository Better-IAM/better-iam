//! The Rust kernel against what the TypeScript kernel answered for the same inputs (`tests/fixtures/kernel.json`,
//! written by `generate-kernel.mjs` from the built TypeScript packages): configuration validation, the catalog,
//! tenant policies, access windows, hosts, issuers, metrics, webhook endpoint rules and the standalone reader.

mod common;

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_core::{IamError, js};
use better_iam_server::access_policy::tenant_access_policy;
use better_iam_server::catalog::{Catalog, attribute_type_name};
use better_iam_server::context::{access_window, inside_window, slug};
use better_iam_server::hosts::normalize_host;
use better_iam_server::metrics::create_metrics;
use better_iam_server::models::AccessWindow;
use better_iam_server::observe::{IamSpan, SpanKind, SpanOutcome};
use better_iam_server::options::{BetterIamOptions, ServerConfig, resolve_config};
use better_iam_server::standalone_config::{ConfigRuntime, options_from_config};
use better_iam_server::tenant_policy::{tenant_auth_policy, tenant_limits};
use better_iam_server::web_identity::{IssuerRules, web_identity_issuer};
use common::{assert_outcome, assert_same, fixture, memory_store};
use serde_json::{Map, Value, json};

fn cases(kernel: &Value, key: &str) -> Vec<Value> {
    kernel[key].as_array().expect("cases").clone()
}

fn base_model(input: &Value) -> Value {
    let mut model = json!({
        "database": {},
        "secret": "kernel-fixture-secret-with-at-least-32-chars",
        "baseURL": "https://iam.example.com",
    });
    for (key, value) in input.as_object().expect("input object") {
        model[key] = value.clone();
    }
    model
}

/// The ServerConfig as the fixture generator projects it.
fn project(config: &ServerConfig) -> Value {
    let web = &config.sts.web_identity;
    json!({
        "baseURL": config.base_url.as_str(),
        "basePath": config.base_path,
        "trustedOrigins": config.trusted_origins.iter().collect::<Vec<_>>(),
        "hierarchy": serde_json::to_value(&config.hierarchy).unwrap(),
        "maxDepth": config.max_depth,
        "tenantDefined": config.tenant_defined,
        "strictResourceTypes": config.strict_resource_types,
        "linkedOnboarding": config.linked_onboarding,
        "invitationLifetimeMs": if config.invitation_lifetime_ms.is_nan() { Value::Null } else { json!(config.invitation_lifetime_ms) },
        "accessRequestLifetimeMs": config.access_request_lifetime_ms,
        "accessRequestMaxDurationSeconds": config.access_request_max_duration_seconds,
        "webhookTimeoutMs": config.webhook_timeout_ms,
        "tenantDefaults": serde_json::to_value(&config.tenant_defaults).unwrap(),
        "sts": {
            "maxRoleSessionSeconds": config.sts.max_role_session_seconds,
            "maxSessionTokenSeconds": config.sts.max_session_token_seconds,
            "maxSessionTokensPerIdentity": config.sts.max_session_tokens_per_identity,
            "webIdentity": {
                "enabled": web.enabled,
                "allowedIssuers": web.allowed_issuers,
                "jwksCacheSeconds": web.jwks_cache_seconds,
                "fetchTimeoutMs": web.fetch_timeout_ms,
                "maxJwksBytes": web.max_jwks_bytes,
                "maxExchangesPerWindow": web.max_exchanges_per_window,
                "maxSessionsPerTrust": web.max_sessions_per_trust,
                "allowPrivateNetworks": web.allow_private_networks,
                "allowInsecureLocalhost": web.allow_insecure_localhost,
            },
        },
        "hosts": {
            "patterns": config.hosts.patterns.iter().map(|pattern| json!({
                "source": pattern.source,
                "hasRegion": pattern.has_region,
                "suffix": pattern.suffix,
                "sample": pattern.fill("acme", None),
            })).collect::<Vec<_>>(),
            "customHostnames": config.hosts.custom_hostnames,
            "cnameTarget": config.hosts.cname_target,
            "signInPath": config.hosts.sign_in_path,
            "forwardedHost": config.hosts.forwarded_host,
            "enabled": config.hosts.enabled,
        },
        "regions": config.regions.as_ref().map(|regions| json!({
            "current": regions.current,
            "regions": serde_json::to_value(&regions.regions).unwrap(),
        })),
        "signals": {
            "allowPrivateNetworks": config.signals.allow_private_networks,
            "allowInsecureLocalhost": config.signals.allow_insecure_localhost,
            "pushPath": config.signals.push_path,
        },
        "clearances": config.clearances.map(|clearances| json!({ "appliesToRoot": clearances.applies_to_root })),
    })
}

fn options_for(input: &Value) -> BetterIamOptions {
    BetterIamOptions::from_model(memory_store(), base_model(input))
}

#[test]
fn resolve_config_matches_typescript() {
    let kernel = fixture("kernel.json");
    let cases = cases(&kernel, "resolveConfig");
    assert!(cases.len() > 80);
    for case in &cases {
        let options = options_for(&case["input"]);
        let name = format!("resolveConfig {}", js::stringify(&case["input"]));
        assert_outcome(
            &name,
            resolve_config(&options).map(|config| project(&config)),
            case,
        );
    }
}

#[test]
fn catalog_matches_typescript() {
    let kernel = fixture("kernel.json");
    for case in cases(&kernel, "catalog") {
        let options = options_for(&case["input"]);
        let name = format!("catalog {}", js::stringify(&case["input"]));
        let outcome = resolve_config(&options).and_then(|config| {
            let catalog = Catalog::new(&options, &[], &config)?;
            Ok(json!({
                "actions": catalog.actions.iter().skip(221).collect::<Vec<_>>(),
                "actionCount": catalog.actions.len(),
                "actionTypes": serde_json::to_value(&catalog.action_types).unwrap(),
                "resourceTypes": catalog.resource_types.values().map(|kind| json!({
                    "name": kind.name,
                    "source": kind.source,
                    "description": kind.description,
                    "actions": kind.actions,
                    "attributes": kind.attributes.iter().map(|(key, kind)| (key.clone(), json!(attribute_type_name(*kind)))).collect::<Map<_, _>>(),
                    "parent": kind.parent,
                    "managed": kind.managed,
                    "relations": kind.relations,
                })).collect::<Vec<_>>(),
                "namespaces": catalog.namespaces.iter().collect::<Vec<_>>(),
                "identityAttributes": catalog.identity_attributes.iter().map(|(key, kind)| (key.clone(), json!(attribute_type_name(*kind)))).collect::<Map<_, _>>(),
                "reservedAttributes": catalog.reserved_attributes.map(|names| names.iter().collect::<Vec<_>>()),
            }))
        });
        assert_outcome(&name, outcome, &case);
    }
}

#[test]
fn tenant_policies_match_typescript() {
    let kernel = fixture("kernel.json");
    for case in cases(&kernel, "authPolicy") {
        let outcome = tenant_auth_policy(Some(&case["input"]))
            .map(|policy| serde_json::to_value(policy).unwrap());
        assert_outcome(&format!("authPolicy {}", case["input"]), outcome, &case);
    }
    for case in cases(&kernel, "limits") {
        let outcome =
            tenant_limits(Some(&case["input"])).map(|limits| serde_json::to_value(limits).unwrap());
        assert_outcome(&format!("limits {}", case["input"]), outcome, &case);
    }
    for case in cases(&kernel, "accessPolicy") {
        let outcome = tenant_access_policy(Some(&case["input"]))
            .map(|policy| serde_json::to_value(policy).unwrap());
        assert_outcome(&format!("accessPolicy {}", case["input"]), outcome, &case);
    }
}

#[test]
fn windows_and_binding_times_match_typescript() {
    let kernel = fixture("kernel.json");
    for case in cases(&kernel, "windows") {
        let outcome =
            access_window(Some(&case["input"])).map(|window| serde_json::to_value(window).unwrap());
        assert_outcome(&format!("accessWindow {}", case["input"]), outcome, &case);
    }
    for case in cases(&kernel, "inside") {
        let window: AccessWindow = serde_json::from_value(case["window"].clone()).unwrap();
        for result in case["results"].as_array().unwrap() {
            let at = result[0].as_f64().unwrap();
            assert_eq!(
                inside_window(&window, at).unwrap(),
                result[1].as_bool().unwrap(),
                "insideWindow {} at {at}",
                case["window"]
            );
        }
    }
    let now = kernel["now"].as_f64().unwrap();
    let ctx = common::context(
        BetterIamOptions::new(memory_store(), "x".repeat(32), "https://iam.example.com"),
        now,
    );
    for case in cases(&kernel, "bindingTimes") {
        let input = &case["input"];
        assert_outcome(
            &format!("bindingStart {input}"),
            ctx.binding_start(Some(input)).map(Value::from),
            &case["start"],
        );
        assert_outcome(
            &format!("bindingExpiry {input}"),
            ctx.binding_expiry(Some(input)).map(Value::from),
            &case["expiry"],
        );
    }
    for case in cases(&kernel, "slugs") {
        assert_outcome(
            &format!("slug {}", case["input"]),
            slug(Some(&case["input"])).map(Value::String),
            &case,
        );
    }
}

#[test]
fn hosts_and_issuers_match_typescript() {
    let kernel = fixture("kernel.json");
    for case in cases(&kernel, "hosts") {
        let input = case["input"].as_str();
        assert_eq!(
            normalize_host(input)
                .map(Value::String)
                .unwrap_or(Value::Null),
            case["result"],
            "normalizeHost {}",
            case["input"]
        );
    }
    for case in cases(&kernel, "issuers") {
        let rules = IssuerRules {
            allow_insecure_localhost: case["allowInsecureLocalhost"].as_bool().unwrap(),
            self_issuer: Some("https://iam.example.com/api/iam"),
            allowed_issuers: None,
        };
        assert_outcome(
            &format!("webIdentityIssuer {}", case["input"]),
            web_identity_issuer(Some(&case["input"]), &rules).map(Value::String),
            &case,
        );
    }
}

fn span_of(value: &Value) -> IamSpan {
    let kind = match value["kind"].as_str().unwrap() {
        "operation" => SpanKind::Operation,
        "authorize" => SpanKind::Authorize,
        "authorizeMany" => SpanKind::AuthorizeMany,
        "listAccessible" => SpanKind::ListAccessible,
        "auth" => SpanKind::Auth,
        _ => SpanKind::Http,
    };
    let outcome = match value["outcome"].as_str().unwrap() {
        "ok" => SpanOutcome::Ok,
        "denied" => SpanOutcome::Denied,
        _ => SpanOutcome::Error,
    };
    IamSpan {
        kind,
        name: value["name"].as_str().unwrap().to_owned(),
        tenant_id: None,
        request_id: None,
        outcome,
        code: value["code"].as_str().map(str::to_owned),
        status: value["status"].as_u64().map(|status| status as u16),
        duration_ms: value["durationMs"].as_f64().unwrap(),
    }
}

#[test]
fn metrics_render_byte_identical() {
    let kernel = fixture("kernel.json");
    let spans: Vec<IamSpan> = kernel["metrics"]["spans"]
        .as_array()
        .unwrap()
        .iter()
        .map(span_of)
        .collect();
    for case in kernel["metrics"]["cases"].as_array().unwrap() {
        let options = serde_json::from_value(case["options"].clone()).unwrap();
        let metrics = create_metrics(&options).unwrap();
        for span in &spans {
            metrics.on_span(span);
        }
        assert_eq!(metrics.render(), case["render"].as_str().unwrap());
        assert_same(
            "metrics snapshot",
            &serde_json::to_value(metrics.snapshot()).unwrap(),
            &case["snapshot"],
        );
    }
}

#[test]
fn locale_compare_matches_icu() {
    // Pairs and signs of String#localeCompare recorded from Node (generated by go/server/testdata/locale-compare.mjs).
    let pairs = common::fixture("locale-compare.json");
    let mut checked = 0;
    for pair in pairs["pairs"].as_array().unwrap() {
        let (a, b, sign) = (
            pair[0].as_str().unwrap(),
            pair[1].as_str().unwrap(),
            pair[2].as_i64().unwrap(),
        );
        let ordering = better_iam_server::metrics::locale_compare(a, b) as i64;
        assert_eq!(ordering, sign, "localeCompare({a:?}, {b:?})");
        checked += 1;
    }
    assert!(checked > 1000);
}

#[test]
fn webhook_endpoint_rules_match_typescript() {
    let kernel = fixture("kernel.json");
    for case in cases(&kernel, "webhookUrls") {
        let base_url = case["baseURL"].as_str().unwrap();
        let mut options = BetterIamOptions::new(memory_store(), "x".repeat(32), base_url);
        options.events = Some(better_iam_server::options::EventOptions {
            allow_private_networks: Some(case["allowPrivateNetworks"].as_bool().unwrap()),
            ..Default::default()
        });
        let ctx = common::context(options, 0.0);
        assert_outcome(
            &format!("webhookUrl {} on {base_url}", case["input"]),
            ctx.events()
                .unwrap()
                .webhook_url(Some(&case["input"]))
                .map(Value::String),
            &case,
        );
    }
    let ctx = common::context(
        BetterIamOptions::new(memory_store(), "x".repeat(32), "https://iam.example.com"),
        0.0,
    );
    for case in cases(&kernel, "webhookEvents") {
        assert_outcome(
            &format!("webhookEvents {}", case["input"]),
            ctx.events()
                .unwrap()
                .webhook_events(Some(&case["input"]))
                .map(|events| json!(events)),
            &case,
        );
    }
}

fn runtime(conformance: bool) -> ConfigRuntime {
    let mut env = HashMap::new();
    env.insert(
        "KERNEL_SECRET".to_owned(),
        "from-the-environment-at-least-32-chars".to_owned(),
    );
    let mut runtime = ConfigRuntime {
        env: Some(env),
        open_store: Some(Arc::new(|_| Ok(memory_store()))),
        ..ConfigRuntime::default()
    };
    if conformance {
        runtime.now = Some(Arc::new(|| 1_767_225_600_000.0));
        runtime.deliver = Some(Arc::new(|_, _| Box::pin(async { Ok(()) })));
        runtime.scripted = Some(Arc::new(|_| {
            Arc::new(|_| Box::pin(async { Ok(Value::Null) }))
        }));
    }
    runtime
}

#[test]
fn standalone_reader_matches_typescript() {
    let kernel = fixture("kernel.json");
    for case in cases(&kernel, "reader") {
        let name = format!("optionsFromConfig {}", js::stringify(&case["config"]));
        let outcome: Result<Value, IamError> = options_from_config(
            &case["config"],
            &runtime(case["conformance"] == json!(true)),
        )
        .and_then(|options| {
            let config = resolve_config(&options)?;
            Ok(json!({
                "secret": options.secret,
                "previousSecrets": options.previous_secrets,
                "config": project(&config),
            }))
        });
        assert_outcome(&name, outcome, &case);
    }
}

#[test]
fn client_info_matches_typescript() {
    use better_iam_server::client_info::client_from_headers;
    use better_iam_server::options::HttpOptions;
    use better_iam_server::standalone_config::client_info_function;
    let kernel = fixture("kernel.json");
    for case in cases(&kernel, "clientInfo") {
        let headers: Vec<(String, String)> = case["headers"]
            .as_array()
            .unwrap()
            .iter()
            .map(|pair| {
                (
                    pair[0].as_str().unwrap().to_owned(),
                    pair[1].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        let http = case["spec"].as_object().map(|spec| HttpOptions {
            client_info: Some(client_info_function(spec)),
            ..HttpOptions::default()
        });
        let client = client_from_headers(http.as_ref(), Some(&headers), "https://iam.example.com");
        assert_same(
            &format!("clientInfo {} {}", case["spec"], case["headers"]),
            &client
                .map(|client| serde_json::to_value(client).unwrap())
                .unwrap_or(Value::Null),
            &case["result"],
        );
    }
}
