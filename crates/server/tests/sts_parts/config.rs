//! Port of `tests/sts-config.test.ts`: `options.sts` defaults, limits and refusals.
//!
//! The refusal cases are checked on the options as TypeScript's validator sees them (`resolveStsConfig` over the JSON
//! value, which can carry the wrong types the Rust option types cannot), and through `resolve_config` and
//! `better_iam` whenever the JSON has a typed form. `fetchJson` is a callback, so the case that gives it a string
//! exists only in the JSON form.

use std::sync::Arc;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::{IamError, IamStore};
use better_iam_server::better_iam;
use better_iam_server::options::{
    BetterIamOptions, ResolvedStsConfig, ResolvedWebIdentityConfig, StsOptions,
    StsWebIdentityOptions, resolve_config, resolve_sts_config,
};
use serde_json::{Value, json};

const SELF_ISSUER: &str = "http://localhost:3000/api/iam";

fn options(sts: Option<StsOptions>) -> BetterIamOptions {
    let database: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(":memory:")).expect("sqlite");
    let mut options = BetterIamOptions::new(
        database,
        "sts-config-test-secret-with-32-characters",
        "http://localhost:3000",
    );
    options.sts = sts;
    options
}

fn defaults() -> ResolvedStsConfig {
    ResolvedStsConfig {
        max_role_session_seconds: 3600.0,
        max_session_token_seconds: 43200.0,
        max_session_tokens_per_identity: 50.0,
        web_identity: ResolvedWebIdentityConfig {
            enabled: false,
            allowed_issuers: None,
            jwks_cache_seconds: 600.0,
            fetch_timeout_ms: 5000.0,
            max_jwks_bytes: 65536.0,
            max_exchanges_per_window: 600.0,
            max_sessions_per_trust: 1000.0,
            allow_private_networks: false,
            allow_insecure_localhost: false,
        },
    }
}

#[test]
fn applies_the_defaults() {
    assert_eq!(resolve_config(&options(None)).unwrap().sts, defaults());
    assert_eq!(resolve_sts_config(None, SELF_ISSUER).unwrap(), defaults());
}

#[test]
fn constructs_better_iam_with_defaults_and_with_every_bound_at_its_limit() {
    assert!(better_iam(options(None)).is_ok());
    assert!(better_iam(options(Some(StsOptions::default()))).is_ok());
    for edge in ["min", "max"] {
        let pick = |min: f64, max: f64| if edge == "min" { min } else { max };
        let sts = StsOptions {
            max_role_session_seconds: Some(pick(900.0, 43200.0)),
            max_session_token_seconds: Some(pick(900.0, 129_600.0)),
            max_session_tokens_per_identity: Some(pick(1.0, 1000.0)),
            jwt: None,
            web_identity: Some(StsWebIdentityOptions {
                enabled: Some(true),
                allowed_issuers: Some(vec!["https://token.actions.githubusercontent.com".into()]),
                jwks_cache_seconds: Some(pick(60.0, 3600.0)),
                fetch_timeout_ms: Some(pick(500.0, 10_000.0)),
                max_jwks_bytes: Some(pick(1024.0, 1_048_576.0)),
                max_exchanges_per_window: Some(pick(1.0, 100_000.0)),
                max_sessions_per_trust: Some(pick(1.0, 100_000.0)),
                allow_private_networks: Some(true),
                allow_insecure_localhost: Some(true),
                fetch_json: Some(Arc::new(|_| Box::pin(async { Ok(json!({})) }))),
            }),
        };
        assert!(better_iam(options(Some(sts.clone()))).is_ok(), "{edge}");
        let resolved = resolve_config(&options(Some(sts.clone()))).unwrap().sts;
        assert_eq!(
            resolved.max_role_session_seconds,
            sts.max_role_session_seconds.unwrap()
        );
        assert_eq!(
            resolved.max_session_token_seconds,
            sts.max_session_token_seconds.unwrap()
        );
        assert_eq!(
            resolved.max_session_tokens_per_identity,
            sts.max_session_tokens_per_identity.unwrap()
        );
        let web = sts.web_identity.unwrap();
        assert!(resolved.web_identity.enabled);
        assert_eq!(
            resolved.web_identity.allowed_issuers,
            Some(vec![
                "https://token.actions.githubusercontent.com".to_owned()
            ])
        );
        assert_eq!(
            resolved.web_identity.jwks_cache_seconds,
            web.jwks_cache_seconds.unwrap()
        );
        assert!(resolved.web_identity.allow_private_networks);
        assert!(resolved.web_identity.allow_insecure_localhost);
    }
}

fn invalid_cases() -> Vec<(&'static str, Value)> {
    vec![
        (
            "maxRoleSessionSeconds",
            json!({ "maxRoleSessionSeconds": 899 }),
        ),
        (
            "maxRoleSessionSeconds",
            json!({ "maxRoleSessionSeconds": 43201 }),
        ),
        (
            "maxRoleSessionSeconds",
            json!({ "maxRoleSessionSeconds": 1000.5 }),
        ),
        (
            "maxRoleSessionSeconds",
            json!({ "maxRoleSessionSeconds": "3600" }),
        ),
        (
            "maxSessionTokenSeconds",
            json!({ "maxSessionTokenSeconds": 899 }),
        ),
        (
            "maxSessionTokenSeconds",
            json!({ "maxSessionTokenSeconds": 129_601 }),
        ),
        (
            "maxSessionTokensPerIdentity",
            json!({ "maxSessionTokensPerIdentity": 0 }),
        ),
        (
            "maxSessionTokensPerIdentity",
            json!({ "maxSessionTokensPerIdentity": 1001 }),
        ),
        (
            "webIdentity.jwksCacheSeconds",
            json!({ "webIdentity": { "jwksCacheSeconds": 59 } }),
        ),
        (
            "webIdentity.jwksCacheSeconds",
            json!({ "webIdentity": { "jwksCacheSeconds": 3601 } }),
        ),
        (
            "webIdentity.fetchTimeoutMs",
            json!({ "webIdentity": { "fetchTimeoutMs": 499 } }),
        ),
        (
            "webIdentity.fetchTimeoutMs",
            json!({ "webIdentity": { "fetchTimeoutMs": 10_001 } }),
        ),
        (
            "webIdentity.maxJwksBytes",
            json!({ "webIdentity": { "maxJwksBytes": 1023 } }),
        ),
        (
            "webIdentity.maxJwksBytes",
            json!({ "webIdentity": { "maxJwksBytes": 1_048_577 } }),
        ),
        (
            "webIdentity.maxExchangesPerWindow",
            json!({ "webIdentity": { "maxExchangesPerWindow": 0 } }),
        ),
        (
            "webIdentity.maxExchangesPerWindow",
            json!({ "webIdentity": { "maxExchangesPerWindow": 100_001 } }),
        ),
        (
            "webIdentity.maxSessionsPerTrust",
            json!({ "webIdentity": { "maxSessionsPerTrust": 0 } }),
        ),
        (
            "webIdentity.maxSessionsPerTrust",
            json!({ "webIdentity": { "maxSessionsPerTrust": 100_001 } }),
        ),
        (
            "webIdentity.enabled",
            json!({ "webIdentity": { "enabled": "yes" } }),
        ),
        (
            "webIdentity.allowPrivateNetworks",
            json!({ "webIdentity": { "allowPrivateNetworks": 1 } }),
        ),
        (
            "webIdentity.allowInsecureLocalhost",
            json!({ "webIdentity": { "allowInsecureLocalhost": "true" } }),
        ),
        (
            "webIdentity.fetchJson",
            json!({ "webIdentity": { "fetchJson": "https://proxy" } }),
        ),
        ("webIdentity", json!({ "webIdentity": "on" })),
        ("options", json!("on")),
        (
            "webIdentity.allowedIssuers",
            json!({ "webIdentity": { "allowedIssuers": "https://token.actions.githubusercontent.com" } }),
        ),
        (
            "webIdentity.allowedIssuers",
            json!({ "webIdentity": {
                "allowedIssuers": (0..101).map(|i| format!("https://idp{i}.example.com")).collect::<Vec<_>>(),
            } }),
        ),
        (
            "webIdentity.allowedIssuers",
            json!({ "webIdentity": { "allowedIssuers": ["http://idp.example.com"] } }),
        ),
        (
            "webIdentity.allowedIssuers",
            json!({ "webIdentity": { "allowedIssuers": ["https://idp.example.com/?a"] } }),
        ),
        (
            "webIdentity.allowedIssuers",
            json!({ "webIdentity": {
                "allowedIssuers": ["http://localhost:3000/api/iam"],
                "allowInsecureLocalhost": true,
            } }),
        ),
    ]
}

#[track_caller]
fn assert_config_error(error: &IamError, field: &str) {
    assert_eq!(error.code, "INVALID_CONFIG", "{field}: {}", error.message);
    assert!(
        error.message.starts_with(&format!("sts.{field} ")),
        "{field}: {}",
        error.message
    );
}

#[test]
fn refuses_every_invalid_setting() {
    for (field, sts) in invalid_cases() {
        let error = resolve_sts_config(Some(&sts), SELF_ISSUER).expect_err(field);
        assert_config_error(&error, field);
        // The typed options, when the JSON has a typed form (the callback-only `fetchJson` case has none).
        let callback = sts.pointer("/webIdentity/fetchJson").is_some();
        if let (false, Ok(typed)) = (callback, serde_json::from_value::<StsOptions>(sts.clone())) {
            let error = resolve_config(&options(Some(typed.clone()))).expect_err(field);
            assert_config_error(&error, field);
            let built = better_iam(options(Some(typed)));
            assert_eq!(
                built.err().map(|error| error.code),
                Some("INVALID_CONFIG".to_owned()),
                "{field}"
            );
        }
    }
}

#[test]
fn accepts_loopback_issuers_only_with_allow_insecure_localhost_and_deduplicates_the_allowlist() {
    let sts = StsOptions {
        web_identity: Some(StsWebIdentityOptions {
            allow_insecure_localhost: Some(true),
            allowed_issuers: Some(vec![
                "http://127.0.0.1:9000".into(),
                "http://127.0.0.1:9000".into(),
            ]),
            ..StsWebIdentityOptions::default()
        }),
        ..StsOptions::default()
    };
    let resolved = resolve_config(&options(Some(sts))).unwrap().sts;
    assert_eq!(
        resolved.web_identity.allowed_issuers,
        Some(vec!["http://127.0.0.1:9000".to_owned()])
    );
}
