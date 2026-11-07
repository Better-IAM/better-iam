//! Port of `tests/web-identity-verifier.test.ts`: external OIDC token verification for AssumeRoleWithWebIdentity
//! (static and fetched keys, caching), claim flattening, trust conditions and the provider validators.

mod common;
mod jwt_keys;

use std::collections::HashMap;
use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex};

use better_iam_core::IamError;
use better_iam_server::options::{FetchJsonFn, ResolvedWebIdentityConfig};
use better_iam_server::web_identity::{
    IssuerRules, WEB_IDENTITY_ALGORITHMS, WebIdentityFailure, WebIdentityTokenVerifier,
    flatten_claims, match_web_identity_conditions, web_identity_algorithms, web_identity_audiences,
    web_identity_claim_name, web_identity_conditions, web_identity_issuer, web_identity_jwks_uri,
    web_identity_keys, web_identity_replay_id, web_identity_verifier,
};
use common::assert_same;
use jwt_keys::{
    Signer, TestKey, generate_test_key, rsa_key, rsa_test_key, sign_test_jwt, tamper_payload,
};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

const ISSUER: &str = "https://token.actions.githubusercontent.com";
const AUDIENCE: &str = "https://iam.example.com";
const START: f64 = 1_790_078_400_000.0; // Date.UTC(2026, 8, 22, 12, 0, 0)
const JWKS_URI: &str = "https://token.actions.githubusercontent.com/.well-known/jwks";
const DISCOVERY: &str =
    "https://token.actions.githubusercontent.com/.well-known/openid-configuration";

static RSA: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("RS256", "rsa-1"));
static RSA_PSS: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("PS256", "pss-1"));
static EC: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("ES256", "ec-1"));
static ED: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("EdDSA", "ed-1"));
static OTHER: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("RS256", "rsa-2"));
static STRANGER: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("RS256", "stranger"));

fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test thread");
}

/// The test's clock, fetched URLs and served documents.
#[derive(Clone)]
struct State {
    clock: Arc<AtomicU64>,
    fetched: Arc<Mutex<Vec<String>>>,
    documents: Arc<Mutex<HashMap<String, Value>>>,
}

impl State {
    fn now(&self) -> f64 {
        f64::from_bits(self.clock.load(Ordering::SeqCst))
    }
    fn advance(&self, ms: f64) {
        self.clock
            .store((self.now() + ms).to_bits(), Ordering::SeqCst);
    }
    fn fetched(&self) -> Vec<String> {
        self.fetched.lock().unwrap().clone()
    }
    fn set(&self, url: &str, document: Value) {
        self.documents
            .lock()
            .unwrap()
            .insert(url.to_owned(), document);
    }
    fn remove(&self, url: &str) {
        self.documents.lock().unwrap().remove(url);
    }
}

fn config() -> ResolvedWebIdentityConfig {
    ResolvedWebIdentityConfig {
        enabled: true,
        allowed_issuers: None,
        jwks_cache_seconds: 600.0,
        fetch_timeout_ms: 5000.0,
        max_jwks_bytes: 65536.0,
        max_exchanges_per_window: 30.0,
        max_sessions_per_trust: 100.0,
        allow_private_networks: false,
        allow_insecure_localhost: false,
    }
}

fn setup_with(self_issuer: Option<&str>) -> (State, WebIdentityTokenVerifier) {
    let state = State {
        clock: Arc::new(AtomicU64::new(START.to_bits())),
        fetched: Arc::default(),
        documents: Arc::default(),
    };
    let fetch_state = state.clone();
    let fetch_json: FetchJsonFn = Arc::new(move |url: url::Url| {
        let state = fetch_state.clone();
        Box::pin(async move {
            state.fetched.lock().unwrap().push(url.as_str().to_owned());
            tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            state
                .documents
                .lock()
                .unwrap()
                .get(url.as_str())
                .cloned()
                .ok_or_else(|| IamError::new("NOT_FOUND", "not found"))
        })
    });
    let clock = state.clock.clone();
    let verifier = web_identity_verifier(
        &config(),
        Some(fetch_json),
        Arc::new(move || f64::from_bits(clock.load(Ordering::SeqCst))),
        self_issuer,
    );
    (state, verifier)
}

fn setup() -> (State, WebIdentityTokenVerifier) {
    setup_with(None)
}

fn provider(overrides: Value) -> Value {
    let mut provider = json!({
        "id": "provider-1",
        "issuer": ISSUER,
        "audiences": [AUDIENCE, "sts.amazonaws.com"],
        "jwks": { "keys": [RSA.public_jwk, RSA_PSS.public_jwk, EC.public_jwk, ED.public_jwk] },
        "algorithms": WEB_IDENTITY_ALGORITHMS,
        "maxTokenLifetimeSeconds": 3600,
        "clockToleranceSeconds": 30,
        "updatedAt": 1,
    });
    for (name, value) in overrides.as_object().cloned().unwrap_or_default() {
        if value.is_null() {
            provider.as_object_mut().unwrap().shift_remove(&name);
        } else {
            provider[name] = value;
        }
    }
    provider
}

fn payload(clock: f64, overrides: Value) -> Value {
    let iat = (clock / 1000.0).floor() as i64;
    let mut payload = json!({
        "iss": ISSUER,
        "sub": "repo:acme/api:ref:refs/heads/main",
        "aud": AUDIENCE,
        "iat": iat,
        "nbf": iat,
        "exp": iat + 300,
        "jti": "jti-1",
        "repository": "acme/api",
        "repository_owner": "acme",
        "ref": "refs/heads/main",
    });
    for (name, value) in overrides.as_object().cloned().unwrap_or_default() {
        if value.is_null() {
            payload.as_object_mut().unwrap().shift_remove(&name);
        } else {
            payload[name] = value;
        }
    }
    payload
}

fn token(key: &TestKey, payload: &Value) -> String {
    sign_test_jwt(Signer::Key(key), payload, json!({}))
}

fn failure<T: std::fmt::Debug>(result: Result<T, IamError>) -> String {
    match result {
        Ok(value) => panic!("expected a WebIdentityFailure, got {value:?}"),
        Err(error) => {
            WebIdentityFailure::from_error(&error)
                .unwrap_or_else(|| panic!("not a WebIdentityFailure: {error:?}"))
                .reason
        }
    }
}

// --- web identity verification with static keys ------------------------------------------------------------------

#[test]
fn accepts_tokens_of_every_algorithm() {
    run(|| async {
        for key in [&*RSA, &*RSA_PSS, &*EC, &*ED] {
            let (state, verifier) = setup();
            let verified = verifier
                .verify_token(
                    &provider(json!({})),
                    &token(key, &payload(state.now(), json!({}))),
                )
                .await
                .unwrap_or_else(|error| panic!("{}: {error:?}", key.alg));
            let iat = (state.now() / 1000.0).floor();
            assert_eq!(verified.issuer, ISSUER);
            assert_eq!(verified.subject, "repo:acme/api:ref:refs/heads/main");
            assert_eq!(verified.audience, AUDIENCE);
            assert_eq!(verified.jti.as_deref(), Some("jti-1"));
            assert_eq!(verified.issued_at, iat);
            assert_eq!(verified.expires_at, iat + 300.0);
            assert_eq!(
                verified.context["token.sub"],
                "repo:acme/api:ref:refs/heads/main"
            );
            assert_eq!(verified.context["token.repository"], "acme/api");
            assert!(state.fetched().is_empty());
        }
    });
}

#[test]
fn matches_one_of_several_audiences_from_a_token_audience_array() {
    run(|| async {
        let (state, verifier) = setup();
        let token = token(
            &RSA,
            &payload(
                state.now(),
                json!({ "aud": ["other", "sts.amazonaws.com"] }),
            ),
        );
        let verified = verifier
            .verify_token(&provider(json!({})), &token)
            .await
            .unwrap();
        assert_eq!(verified.audience, "sts.amazonaws.com");
    });
}

#[test]
fn accepts_typ_absent_jwt_and_application_jwt_only() {
    run(|| async {
        let (state, verifier) = setup();
        let body = payload(state.now(), json!({}));
        for typ in [
            Value::Null,
            json!("JWT"),
            json!("jwt"),
            json!("application/jwt"),
        ] {
            let token = sign_test_jwt(Signer::Key(&RSA), &body, json!({ "typ": typ }));
            assert!(
                verifier
                    .verify_token(&provider(json!({})), &token)
                    .await
                    .is_ok(),
                "{typ}"
            );
        }
        for typ in [
            json!("biam-session+jwt"),
            json!("at+jwt"),
            json!("application/at+jwt"),
            json!("dpop+jwt"),
            json!(7),
        ] {
            let token = sign_test_jwt(Signer::Key(&RSA), &body, json!({ "typ": typ }));
            assert_eq!(
                failure(verifier.verify_token(&provider(json!({})), &token).await),
                "type",
                "{typ}"
            );
        }
    });
}

#[test]
fn refuses_every_class_of_bad_token_with_a_reason() {
    run(|| async {
        let (state, verifier) = setup();
        let (_, with_self) = setup_with(Some("http://localhost:3000/api/iam"));
        let now = (state.now() / 1000.0).floor() as i64;
        let clock = state.now();
        let good = token(&RSA, &payload(clock, json!({})));
        let signed = |overrides: Value| token(&RSA, &payload(clock, overrides));
        let cases: Vec<(&str, String, &str, Value)> = vec![
            (
                "HS256",
                sign_test_jwt(
                    Signer::Hs256(b"secret"),
                    &payload(clock, json!({})),
                    json!({}),
                ),
                "algorithm",
                json!({}),
            ),
            (
                "alg none",
                sign_test_jwt(Signer::None, &payload(clock, json!({})), json!({})),
                "algorithm",
                json!({}),
            ),
            (
                "an alg the provider does not allow",
                good.clone(),
                "algorithm",
                json!({ "algorithms": ["ES256"] }),
            ),
            (
                "an unknown kid",
                token(&OTHER, &payload(clock, json!({}))),
                "unknown-key",
                json!({}),
            ),
            (
                "a tampered payload",
                tamper_payload(&good, json!({ "sub": "repo:evil/api" })),
                "signature",
                json!({}),
            ),
            (
                "a wrong issuer",
                signed(json!({ "iss": "https://evil" })),
                "issuer",
                json!({}),
            ),
            (
                "a wrong audience",
                signed(json!({ "aud": "other" })),
                "audience",
                json!({}),
            ),
            (
                "an expired token",
                signed(json!({ "iat": now - 400, "exp": now - 60 })),
                "expired",
                json!({}),
            ),
            (
                "a future nbf",
                signed(json!({ "nbf": now + 120 })),
                "not-yet-valid",
                json!({}),
            ),
            (
                "a future iat",
                signed(json!({ "iat": now + 120, "exp": now + 300 })),
                "not-yet-valid",
                json!({}),
            ),
            (
                "a token older than the provider allows",
                signed(json!({ "iat": now - 3700, "exp": now + 300 })),
                "too-old",
                json!({}),
            ),
            (
                "a lifetime over the cap",
                signed(json!({ "exp": now + 3601 })),
                "lifetime",
                json!({}),
            ),
            (
                "a missing sub",
                signed(json!({ "sub": null })),
                "claims",
                json!({}),
            ),
            (
                "a missing exp",
                signed(json!({ "exp": null })),
                "claims",
                json!({}),
            ),
            (
                "a long sub",
                signed(json!({ "sub": "x".repeat(513) })),
                "claims",
                json!({}),
            ),
            (
                "a numeric sub",
                signed(json!({ "sub": 42 })),
                "claims",
                json!({}),
            ),
            (
                "a numeric jti",
                signed(json!({ "jti": 42 })),
                "claims",
                json!({}),
            ),
            ("garbage", "not a token".to_owned(), "malformed", json!({})),
            (
                "an oversized token",
                format!("{good}{}", "A".repeat(8192)),
                "malformed",
                json!({}),
            ),
            (
                "IAM's own issuer",
                good.clone(),
                "issuer",
                json!({ "issuer": "http://localhost:3000/api/iam" }),
            ),
        ];
        for (name, token, expected, changes) in cases {
            let target = if changes.get("issuer").is_some() {
                &with_self
            } else {
                &verifier
            };
            let reason = failure(target.verify_token(&provider(changes), &token).await);
            assert_eq!((name, reason.as_str()), (name, expected));
        }
    });
}

#[test]
fn ignores_unusable_static_keys() {
    run(|| async {
        let (state, verifier) = setup();
        let weak = rsa_test_key(rsa_key(1024), "RS256", "weak");
        let mut weak_jwk = weak.public_jwk.clone();
        weak_jwk.shift_remove("use");
        let token = token(&weak, &payload(state.now(), json!({})));
        let config = provider(json!({ "jwks": { "keys": [weak_jwk, EC.public_jwk] } }));
        assert_eq!(
            failure(verifier.verify_token(&config, &token).await),
            "unknown-key"
        );
    });
}

// --- web identity key fetching and caching -----------------------------------------------------------------------

#[test]
fn fetches_keys_from_jwks_uri_once_and_caches_them() {
    run(|| async {
        let (state, verifier) = setup();
        state.set(JWKS_URI, json!({ "keys": [RSA.public_jwk] }));
        let config = provider(json!({ "jwks": null, "jwksUri": JWKS_URI }));
        verifier
            .verify_token(&config, &token(&RSA, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        verifier
            .verify_token(
                &config,
                &token(&RSA, &payload(state.now(), json!({ "jti": "jti-2" }))),
            )
            .await
            .unwrap();
        assert_eq!(state.fetched(), [JWKS_URI]);
        state.advance(601_000.0);
        verifier
            .verify_token(&config, &token(&RSA, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        assert_eq!(state.fetched(), [JWKS_URI, JWKS_URI]);
    });
}

#[test]
fn fetches_single_flight_for_concurrent_verifications() {
    run(|| async {
        let (state, verifier) = setup();
        state.set(JWKS_URI, json!({ "keys": [RSA.public_jwk] }));
        let config = provider(json!({ "jwks": null, "jwksUri": JWKS_URI }));
        let token = token(&RSA, &payload(state.now(), json!({})));
        let results =
            futures::future::join_all((0..4).map(|_| verifier.verify_token(&config, &token))).await;
        assert!(results.iter().all(Result::is_ok));
        assert_eq!(state.fetched(), [JWKS_URI]);
    });
}

#[test]
fn uses_oidc_discovery_when_the_provider_names_no_keys() {
    run(|| async {
        let (state, verifier) = setup();
        state.set(DISCOVERY, json!({ "issuer": ISSUER, "jwks_uri": JWKS_URI }));
        state.set(JWKS_URI, json!({ "keys": [EC.public_jwk] }));
        let config = provider(json!({ "jwks": null }));
        let verified = verifier
            .verify_token(&config, &token(&EC, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        assert_eq!(verified.subject, "repo:acme/api:ref:refs/heads/main");
        assert_eq!(state.fetched(), [DISCOVERY, JWKS_URI]);
    });
}

#[test]
fn refuses_a_discovery_document_for_another_issuer_and_caches_the_failure() {
    run(|| async {
        let (state, verifier) = setup();
        state.set(
            DISCOVERY,
            json!({ "issuer": "https://evil.example", "jwks_uri": JWKS_URI }),
        );
        state.set(JWKS_URI, json!({ "keys": [EC.public_jwk] }));
        let config = provider(json!({ "jwks": null }));
        let token1 = token(&EC, &payload(state.now(), json!({})));
        assert_eq!(
            failure(verifier.verify_token(&config, &token1).await),
            "jwks-unavailable"
        );
        assert_eq!(
            failure(verifier.verify_token(&config, &token1).await),
            "jwks-unavailable"
        );
        assert_eq!(state.fetched(), [DISCOVERY]);
        state.set(DISCOVERY, json!({ "issuer": ISSUER, "jwks_uri": JWKS_URI }));
        state.advance(31_000.0);
        verifier
            .verify_token(&config, &token(&EC, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        assert_eq!(state.fetched(), [DISCOVERY, DISCOVERY, JWKS_URI]);
    });
}

#[test]
fn refuses_a_discovery_jwks_uri_that_breaks_the_url_rules() {
    run(|| async {
        let (state, verifier) = setup();
        state.set(
            DISCOVERY,
            json!({ "issuer": ISSUER, "jwks_uri": "http://token.actions.githubusercontent.com/jwks" }),
        );
        let token = token(&EC, &payload(state.now(), json!({})));
        assert_eq!(
            failure(
                verifier
                    .verify_token(&provider(json!({ "jwks": null })), &token)
                    .await
            ),
            "jwks-unavailable"
        );
        assert_eq!(state.fetched(), [DISCOVERY]);
    });
}

#[test]
fn refetches_on_an_unknown_kid_at_most_once_per_cooldown() {
    run(|| async {
        let (state, verifier) = setup();
        state.set(JWKS_URI, json!({ "keys": [RSA.public_jwk] }));
        let config = provider(json!({ "jwks": null, "jwksUri": JWKS_URI }));
        verifier
            .verify_token(&config, &token(&RSA, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        // The IdP rotates in a new key; within the cooldown the unknown kid is refused without a fetch.
        state.set(
            JWKS_URI,
            json!({ "keys": [RSA.public_jwk, OTHER.public_jwk] }),
        );
        state.advance(10_000.0);
        assert_eq!(
            failure(
                verifier
                    .verify_token(&config, &token(&OTHER, &payload(state.now(), json!({}))))
                    .await
            ),
            "unknown-key"
        );
        assert_eq!(state.fetched().len(), 1);
        state.advance(21_000.0);
        verifier
            .verify_token(&config, &token(&OTHER, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        assert_eq!(state.fetched().len(), 2);
        // A kid the IdP never published is refused, and the cooldown stops a refetch storm.
        for _ in 0..3 {
            assert_eq!(
                failure(
                    verifier
                        .verify_token(&config, &token(&STRANGER, &payload(state.now(), json!({}))))
                        .await
                ),
                "unknown-key"
            );
        }
        assert_eq!(state.fetched().len(), 2);
    });
}

#[test]
fn keeps_the_unknown_kid_cooldown_while_the_idp_is_failing() {
    run(|| async {
        let (state, verifier) = setup();
        state.set(JWKS_URI, json!({ "keys": [RSA.public_jwk] }));
        let config = provider(json!({ "jwks": null, "jwksUri": JWKS_URI }));
        verifier
            .verify_token(&config, &token(&RSA, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        assert_eq!(state.fetched().len(), 1);
        // The JWKS endpoint goes down while the cached keys are still fresh but older than the cooldown.
        state.remove(JWKS_URI);
        state.advance(31_000.0);
        let mut reasons = Vec::new();
        for _ in 0..3 {
            reasons.push(failure(
                verifier
                    .verify_token(&config, &token(&STRANGER, &payload(state.now(), json!({}))))
                    .await,
            ));
            state.advance(5_000.0);
        }
        assert_eq!(reasons, ["jwks-unavailable", "unknown-key", "unknown-key"]);
        // One refetch attempt, not one per token.
        assert_eq!(state.fetched().len(), 2);
        // Tokens with a known kid keep verifying from the cache meanwhile.
        verifier
            .verify_token(&config, &token(&RSA, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        assert_eq!(state.fetched().len(), 2);
        // Once the cooldown after the failed attempt has run out, an unknown kid may refetch again.
        state.set(
            JWKS_URI,
            json!({ "keys": [RSA.public_jwk, STRANGER.public_jwk] }),
        );
        state.advance(30_000.0);
        verifier
            .verify_token(&config, &token(&STRANGER, &payload(state.now(), json!({}))))
            .await
            .unwrap();
        assert_eq!(state.fetched().len(), 3);
    });
}

#[test]
fn drops_cached_keys_when_the_provider_changes_or_is_forgotten() {
    run(|| async {
        let (state, verifier) = setup();
        state.set(JWKS_URI, json!({ "keys": [RSA.public_jwk] }));
        let config = provider(json!({ "jwks": null, "jwksUri": JWKS_URI }));
        let changed = provider(json!({ "jwks": null, "jwksUri": JWKS_URI, "updatedAt": 2 }));
        let token = token(&RSA, &payload(state.now(), json!({})));
        verifier.verify_token(&config, &token).await.unwrap();
        verifier.verify_token(&changed, &token).await.unwrap();
        assert_eq!(state.fetched().len(), 2);
        verifier.forget_provider("provider-1");
        verifier.verify_token(&changed, &token).await.unwrap();
        assert_eq!(state.fetched().len(), 3);
    });
}

#[test]
fn filters_fetched_keys() {
    run(|| async {
        let (state, verifier) = setup();
        let mut enc = EC.public_jwk.clone();
        enc.insert("use".into(), json!("enc"));
        state.set(
            JWKS_URI,
            json!({ "keys": [RSA.private_jwk, enc, { "kty": "oct", "k": "c2VjcmV0", "kid": "hmac" }] }),
        );
        let config = provider(json!({ "jwks": null, "jwksUri": JWKS_URI }));
        assert_eq!(
            failure(
                verifier
                    .verify_token(&config, &token(&RSA, &payload(state.now(), json!({}))))
                    .await
            ),
            "jwks-unavailable"
        );
    });
}

#[test]
fn reports_a_failing_transport_as_jwks_unavailable() {
    run(|| async {
        let (state, verifier) = setup();
        let config = provider(json!({ "jwks": null, "jwksUri": JWKS_URI }));
        assert_eq!(
            failure(
                verifier
                    .verify_token(&config, &token(&RSA, &payload(state.now(), json!({}))))
                    .await
            ),
            "jwks-unavailable"
        );
    });
}

// --- claim flattening ----------------------------------------------------------------------------------------------

#[test]
fn flattens_nested_claims_within_the_limits() {
    let many: Vec<Value> = (0..65).map(|i| json!(i)).collect();
    let input = json!({
        "sub": "system:serviceaccount:ci:deployer",
        "aud": ["a", "b"],
        "exp": 1,
        "admin": false,
        "kubernetes.io": {
            "namespace": "ci",
            "serviceaccount": { "name": "deployer", "uid": "u-1", "deeper": { "tooDeep": true } },
            "pod": null,
        },
        "long": "x".repeat(1025),
        "exactly": "y".repeat(1024),
        "mixed": ["a", { "b": 1 }],
        "many": many,
        "bad key": "v",
        "__proto__": "polluted",
    });
    let flattened = flatten_claims(input.as_object().unwrap());
    assert_same(
        "flattened",
        &Value::Object(flattened),
        &json!({
            "token.sub": "system:serviceaccount:ci:deployer",
            "token.aud": ["a", "b"],
            "token.exp": 1,
            "token.admin": false,
            "token.kubernetes.io.namespace": "ci",
            "token.kubernetes.io.serviceaccount.name": "deployer",
            "token.kubernetes.io.serviceaccount.uid": "u-1",
            "token.exactly": "y".repeat(1024),
        }),
    );
}

#[test]
fn keeps_at_most_128_keys() {
    let mut wide = Map::new();
    for i in 0..200 {
        wide.insert(format!("c{i}"), json!(i));
    }
    let flattened = flatten_claims(&wide);
    assert_eq!(flattened.len(), 128);
    assert_eq!(flattened["token.c127"], 127);
    assert!(!flattened.contains_key("token.c128"));
}

// --- web identity trust conditions -------------------------------------------------------------------------------

#[test]
fn accepts_a_subject_pin_and_returns_a_copy() {
    let conditions = json!({
        "StringLike": { "token.sub": "repo:acme/api:*" },
        "StringEquals": { "token.aud": "https://iam.example.com", "token.repository_owner": "acme" },
    });
    let validated = web_identity_conditions(Some(&conditions)).unwrap();
    assert_same("conditions", &validated, &conditions);
}

#[test]
fn refuses_weak_subject_conditions() {
    for (name, conditions) in [
        (
            "no subject condition",
            json!({ "StringEquals": { "token.repository_owner": "acme" } }),
        ),
        (
            "a leading * wildcard",
            json!({ "StringLike": { "token.sub": "*" } }),
        ),
        (
            "a leading ? wildcard",
            json!({ "StringLike": { "token.sub": "?repo:acme/api" } }),
        ),
        (
            "one wildcard among values",
            json!({ "StringLike": { "token.sub": ["repo:acme/api:*", "*"] } }),
        ),
        (
            "an empty subject",
            json!({ "StringEquals": { "token.sub": "" } }),
        ),
        (
            "a negated subject condition",
            json!({ "StringNotEquals": { "token.sub": "repo:evil/api" } }),
        ),
        (
            "a case-insensitive subject match",
            json!({ "StringEqualsIgnoreCase": { "token.sub": "repo:acme" } }),
        ),
    ] {
        let error = web_identity_conditions(Some(&conditions)).unwrap_err();
        assert_eq!(error.code, "WEAK_TRUST_CONDITIONS", "{name}");
        assert_eq!(error.status, 400, "{name}");
    }
}

#[test]
fn refuses_malformed_conditions() {
    let mut many = Map::new();
    many.insert("token.sub".into(), json!("repo:a"));
    for i in 0..20 {
        many.insert(format!("token.c{i}"), json!("v"));
    }
    let pinned = json!({ "StringEquals": { "token.sub": "repo:acme/api:ref:refs/heads/main" } });
    for (name, conditions) in [
        (
            "a non-token key",
            json!({ "StringEquals": { "principal.id": "x", "token.sub": "repo:a" } }),
        ),
        (
            "a policy variable",
            json!({ "StringEquals": { "token.sub": "repo:${principal.id}" } }),
        ),
        ("more than 20 entries", json!({ "StringEquals": many })),
        ("an array", json!([pinned])),
        (
            "a non-object operator entry",
            json!({ "StringEquals": "token.sub" }),
        ),
    ] {
        let error = web_identity_conditions(Some(&conditions)).unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT", "{name}");
    }
    let with = |name: &str, entry: Value| {
        let mut conditions = pinned.clone();
        conditions[name] = entry;
        conditions
    };
    assert_eq!(
        web_identity_conditions(Some(&with("Regex", json!({ "token.sub": ".*" }))))
            .unwrap_err()
            .code,
        "INVALID_POLICY"
    );
    assert_eq!(
        web_identity_conditions(Some(&with(
            "NumericEquals",
            json!({ "token.run_number": "one" })
        )))
        .unwrap_err()
        .code,
        "INVALID_POLICY"
    );
}

#[test]
fn matches_conditions_against_flattened_claims() {
    let context = flatten_claims(
        json!({
            "sub": "repo:acme/api:ref:refs/heads/main",
            "repository_owner": "acme",
            "groups": ["deployers", "ci"],
            "run_number": 7,
        })
        .as_object()
        .unwrap(),
    );
    let conditions = json!({
        "StringLike": { "token.sub": "repo:acme/api:*" },
        "StringEquals": { "token.repository_owner": "acme" },
        "ArrayContains": { "token.groups": "deployers" },
        "NumericGreaterThan": { "token.run_number": 5 },
    });
    assert_same(
        "matched",
        &match_web_identity_conditions(&conditions, &context, "trust-1").unwrap(),
        &json!({ "matched": true, "failed": [] }),
    );
    let mut failing = conditions.clone();
    failing["StringEquals"] =
        json!({ "token.repository_owner": "evil", "token.environment": "prod" });
    failing["Exists"] = json!({ "token.environment": true });
    assert_same(
        "failed",
        &match_web_identity_conditions(&failing, &context, "trust-1").unwrap(),
        &json!({
            "matched": false,
            "failed": [
                "StringEquals:token.repository_owner",
                "StringEquals:token.environment",
                "Exists:token.environment",
            ],
        }),
    );
}

// --- web identity validators -------------------------------------------------------------------------------------

#[test]
fn validates_issuers() {
    let local = IssuerRules::default();
    let check = |value: Value, rules: &IssuerRules<'_>| web_identity_issuer(Some(&value), rules);
    assert_eq!(check(json!(ISSUER), &local).unwrap(), ISSUER);
    assert_eq!(
        check(json!("https://gitlab.example.com/"), &local).unwrap(),
        "https://gitlab.example.com/"
    );
    let insecure = IssuerRules {
        allow_insecure_localhost: true,
        ..IssuerRules::default()
    };
    assert_eq!(
        check(json!("http://localhost:9000"), &insecure).unwrap(),
        "http://localhost:9000"
    );
    for value in [
        json!("http://idp.example.com"),
        json!("http://localhost:9000"),
        json!("https://user:pass@idp.example.com"),
        json!("https://idp.example.com/?tenant=1"),
        json!("https://idp.example.com/#x"),
        json!("idp.example.com"),
        json!(format!("https://idp.example.com/{}", "a".repeat(512))),
        json!(42),
    ] {
        assert_eq!(
            check(value.clone(), &local).unwrap_err().code,
            "INVALID_INPUT",
            "{value}"
        );
    }
    let own = IssuerRules {
        self_issuer: Some("https://iam.example.com/api/iam"),
        ..IssuerRules::default()
    };
    assert!(
        check(json!("https://iam.example.com/api/iam/"), &own)
            .unwrap_err()
            .message
            .contains("own issuer")
    );
    let gitlab = vec!["https://gitlab.com".to_owned()];
    let pinned = IssuerRules {
        allowed_issuers: Some(&gitlab),
        ..IssuerRules::default()
    };
    assert!(
        check(json!(ISSUER), &pinned)
            .unwrap_err()
            .message
            .contains("allowedIssuers")
    );
    let github = vec![ISSUER.to_owned()];
    let allowed = IssuerRules {
        allowed_issuers: Some(&github),
        ..IssuerRules::default()
    };
    assert_eq!(check(json!(ISSUER), &allowed).unwrap(), ISSUER);
}

#[test]
fn validates_jwks_urls() {
    let local = json!({ "allowInsecureLocalhost": false });
    let check = |value: &str, options: &Value| web_identity_jwks_uri(Some(&json!(value)), options);
    assert_eq!(
        check("https://idp.example.com/jwks", &local).unwrap(),
        "https://idp.example.com/jwks"
    );
    assert_eq!(
        check("https://idp.example.com:443/jwks", &local).unwrap(),
        "https://idp.example.com:443/jwks"
    );
    assert_eq!(
        check(
            "http://127.0.0.1:9000/jwks",
            &json!({ "allowInsecureLocalhost": true })
        )
        .unwrap(),
        "http://127.0.0.1:9000/jwks"
    );
    for value in [
        "http://idp.example.com/jwks",
        "https://idp.example.com:8443/jwks",
        "https://user@idp.example.com/jwks",
        "https://idp.example.com/jwks#k",
        "https://10.0.0.1/jwks",
        "https://[::1]/jwks",
        "/jwks",
    ] {
        assert_eq!(
            check(value, &local).unwrap_err().code,
            "INVALID_INPUT",
            "{value}"
        );
    }
}

#[test]
fn validates_static_keys() {
    let mut rsa_ext = RSA.public_jwk.clone();
    rsa_ext.insert("ext".into(), json!(true));
    let validated = web_identity_keys(Some(
        &json!({ "keys": [rsa_ext, EC.public_jwk, ED.public_jwk] }),
    ))
    .unwrap();
    assert_eq!(validated["keys"].as_array().unwrap().len(), 3);
    assert_same(
        "rsa key",
        &validated["keys"][0],
        &json!({
            "kty": "RSA", "kid": "rsa-1", "alg": "RS256", "use": "sig",
            "n": RSA.public_jwk["n"], "e": RSA.public_jwk["e"],
        }),
    );
    let weak = rsa_test_key(rsa_key(1024), "RS256", "weak");
    let mut weak_jwk = weak.public_jwk.clone();
    for member in ["kid", "alg", "use"] {
        weak_jwk.shift_remove(member);
    }
    let p256k = json!({
        "kty": "EC", "crv": "secp256k1",
        "x": EC.public_jwk["x"], "y": EC.public_jwk["y"],
    });
    let mut enc = EC.public_jwk.clone();
    enc.insert("use".into(), json!("enc"));
    let mut hs = EC.public_jwk.clone();
    hs.insert("alg".into(), json!("HS256"));
    let twenty_one: Vec<Value> = (0..21)
        .map(|_| Value::Object(EC.public_jwk.clone()))
        .collect();
    for value in [
        Some(json!({ "keys": [] })),
        Some(json!({ "keys": twenty_one })),
        Some(json!({ "keys": [RSA.private_jwk] })),
        Some(json!({ "keys": [weak_jwk] })),
        Some(json!({ "keys": [p256k] })),
        Some(json!({ "keys": [enc] })),
        Some(json!({ "keys": [hs] })),
        Some(json!({ "keys": [{ "kty": "oct", "k": "c2VjcmV0" }] })),
        Some(json!([EC.public_jwk])),
        None,
    ] {
        assert_eq!(
            web_identity_keys(value.as_ref()).unwrap_err().code,
            "INVALID_INPUT"
        );
    }
}

#[test]
fn validates_algorithms_audiences_and_claim_names() {
    assert_eq!(web_identity_algorithms(None).unwrap(), ["RS256", "ES256"]);
    assert_eq!(
        web_identity_algorithms(Some(&json!(["EdDSA", "EdDSA", "PS256"]))).unwrap(),
        ["EdDSA", "PS256"]
    );
    for value in [
        json!([]),
        json!(["HS256"]),
        json!(["none"]),
        json!(["ES512"]),
        json!("RS256"),
    ] {
        assert_eq!(
            web_identity_algorithms(Some(&value)).unwrap_err().code,
            "INVALID_INPUT"
        );
    }
    assert_eq!(
        web_identity_audiences(Some(&json!([
            "sts.amazonaws.com",
            "sts.amazonaws.com",
            "api"
        ])))
        .unwrap(),
        ["sts.amazonaws.com", "api"]
    );
    let eleven: Vec<Value> = (0..11).map(|i| json!(format!("a{i}"))).collect();
    for value in [
        json!([]),
        json!([""]),
        json!(["x".repeat(257)]),
        json!(eleven),
    ] {
        assert_eq!(
            web_identity_audiences(Some(&value)).unwrap_err().code,
            "INVALID_INPUT"
        );
    }
    assert_eq!(
        web_identity_claim_name(Some(&json!("token.repository_owner"))).unwrap(),
        "token.repository_owner"
    );
    assert_eq!(
        web_identity_claim_name(Some(&json!("token.kubernetes.io.namespace"))).unwrap(),
        "token.kubernetes.io.namespace"
    );
    for value in [
        json!("repository_owner"),
        json!("token."),
        json!("principal.id"),
        json!("token.a b"),
        json!(42),
    ] {
        assert_eq!(
            web_identity_claim_name(Some(&value)).unwrap_err().code,
            "INVALID_INPUT"
        );
    }
}

fn sha256(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

#[test]
fn derives_replay_ids_from_the_jti_or_the_signed_content() {
    let replay = |provider: &str, jti: Option<&str>, token: &str| {
        web_identity_replay_id(provider, jti, token).unwrap()
    };
    let by_jti = replay("provider-1", Some("jti-1"), "h.p.sig-a");
    assert_eq!(by_jti.len(), 64);
    assert!(by_jti.chars().all(|c| c.is_ascii_hexdigit()));
    assert_eq!(replay("provider-1", Some("jti-1"), "h.q.sig-b"), by_jti);
    assert_ne!(replay("provider-2", Some("jti-1"), "h.p.sig-a"), by_jti);
    let by_token = replay("provider-1", None, "h.p.sig-a");
    assert_ne!(by_token, by_jti);
    // A different spelling of the signature is the same token; different signed content is not.
    assert_eq!(replay("provider-1", None, "h.p.sig-other"), by_token);
    assert_ne!(replay("provider-1", None, "h.q.sig-a"), by_token);
    assert!(!by_token.contains("h.p"));
    assert_eq!(by_jti, sha256("wi\nprovider-1\njti:jti-1"));
    assert_eq!(
        by_token,
        sha256(&format!("wi\nprovider-1\ntok:{}", sha256("h.p")))
    );
    // An empty jti counts as absent.
    assert_eq!(replay("provider-1", Some(""), "h.p.sig-a"), by_token);
}

#[test]
fn gives_malleated_signatures_of_one_token_the_same_replay_id() {
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use p256::ecdsa::signature::Verifier;
    let key = generate_test_key("ES256", "malleable");
    let token = token(
        &key,
        &json!({
            "iss": "https://idp.example.test",
            "aud": "better-iam",
            "sub": "repo:acme/app:ref:refs/heads/main",
            "iat": 1_800_000_000i64,
            "exp": 1_800_000_300i64,
        }),
    );
    let parts: Vec<&str> = token.split('.').collect();
    let (header, body, signature) = (parts[0], parts[1], parts[2]);
    // (1) ECDSA malleability: (r, s) and (r, n - s) both verify.
    let raw = URL_SAFE_NO_PAD.decode(signature).unwrap();
    let n = rsa::BigUint::parse_bytes(
        b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
        16,
    )
    .unwrap();
    let s = rsa::BigUint::from_bytes_be(&raw[32..]);
    let flipped_s = (&n - &s).to_bytes_be();
    let mut flipped = raw[..32].to_vec();
    flipped.extend(std::iter::repeat_n(0u8, 32 - flipped_s.len()));
    flipped.extend(flipped_s);
    let malleated = format!("{header}.{body}.{}", URL_SAFE_NO_PAD.encode(&flipped));
    assert_ne!(malleated, token);
    let x = URL_SAFE_NO_PAD
        .decode(key.public_jwk["x"].as_str().unwrap())
        .unwrap();
    let y = URL_SAFE_NO_PAD
        .decode(key.public_jwk["y"].as_str().unwrap())
        .unwrap();
    let point = p256::EncodedPoint::from_affine_coordinates(
        x.as_slice().into(),
        y.as_slice().into(),
        false,
    );
    let public = p256::ecdsa::VerifyingKey::from_encoded_point(&point).unwrap();
    let verifies = |value: &str| {
        let parts: Vec<&str> = value.split('.').collect();
        let signature =
            p256::ecdsa::Signature::from_slice(&URL_SAFE_NO_PAD.decode(parts[2]).unwrap()).unwrap();
        public
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .is_ok()
    };
    assert!(verifies(&token));
    assert!(verifies(&malleated));
    assert_eq!(
        web_identity_replay_id("p", None, &malleated).unwrap(),
        web_identity_replay_id("p", None, &token).unwrap()
    );
}

#[test]
fn accepts_high_s_es256_signatures_as_webcrypto_does() {
    run(|| async {
        let (state, verifier) = setup();
        let token = token(&EC, &payload(state.now(), json!({})));
        let parts: Vec<&str> = token.split('.').collect();
        use base64::Engine;
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let raw = URL_SAFE_NO_PAD.decode(parts[2]).unwrap();
        let n = rsa::BigUint::parse_bytes(
            b"ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551",
            16,
        )
        .unwrap();
        let s = rsa::BigUint::from_bytes_be(&raw[32..]);
        let flipped_s = (&n - &s).to_bytes_be();
        let mut flipped = raw[..32].to_vec();
        flipped.extend(std::iter::repeat_n(0u8, 32 - flipped_s.len()));
        flipped.extend(flipped_s);
        let malleated = format!(
            "{}.{}.{}",
            parts[0],
            parts[1],
            URL_SAFE_NO_PAD.encode(&flipped)
        );
        assert!(
            verifier
                .verify_token(&provider(json!({})), &malleated)
                .await
                .is_ok()
        );
    });
}
