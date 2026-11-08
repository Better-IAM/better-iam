//! Port of `tests/session-token-signing.test.ts` (session JWT signing and offline verification), plus the
//! `spec/vectors/session-jwt.json` vectors.

mod common;
mod jwt_keys;

use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use better_iam_server::contracts::SessionTokenSigner;
use better_iam_server::options::SessionTokenSigningOptions;
use better_iam_server::session_tokens::{
    SESSION_TOKEN_ALGORITHMS, SESSION_TOKEN_TYPE, SessionTokenError,
    create_session_token_verifier_with, looks_like_jwt, looks_like_jwt_value,
};
use better_iam_server::token_signing::{SessionTokenSigning, session_token_signer};
use common::{assert_same, read_json};
use jwt_keys::{
    Signer, TestKey, decode_test_jwt, generate_test_key, sign_test_jwt, tamper_payload,
};
use serde_json::{Map, Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const ISSUER: &str = "http://localhost:3000/api/iam";
const START: f64 = 1_790_078_400_000.0; // Date.UTC(2026, 8, 22, 12, 0, 0)

static ED: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("EdDSA", "ed-1"));
static EC: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("ES256", "ec-1"));
static RETIRED_ED: LazyLock<TestKey> = LazyLock::new(|| generate_test_key("EdDSA", "ed-old"));

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

/// A settable test clock (epoch milliseconds).
#[derive(Clone)]
struct Clock(Arc<AtomicU64>);

impl Clock {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(START.to_bits())))
    }
    fn get(&self) -> f64 {
        f64::from_bits(self.0.load(Ordering::SeqCst))
    }
    fn advance(&self, ms: f64) {
        self.0.store((self.get() + ms).to_bits(), Ordering::SeqCst);
    }
    fn now(&self) -> better_iam_server::context::NowFn {
        let clock = self.0.clone();
        Arc::new(move || f64::from_bits(clock.load(Ordering::SeqCst)))
    }
}

fn options_of(value: Value) -> SessionTokenSigningOptions {
    serde_json::from_value(value).expect("signing options")
}

fn signer_with(clock: &Clock, overrides: Value) -> SessionTokenSigning {
    let mut options = json!({ "signingKeys": [ED.private_jwk, EC.private_jwk] });
    for (name, value) in overrides.as_object().cloned().unwrap_or_default() {
        options[name] = value;
    }
    session_token_signer(Some(&options_of(options)), ISSUER, clock.now())
        .expect("valid options")
        .expect("a signer")
}

fn claims(clock: &Clock, overrides: Value) -> Map<String, Value> {
    let iat = (clock.get() / 1000.0).floor();
    let mut claims = json!({
        "iss": ISSUER,
        "aud": ISSUER,
        "sub": "identity-1",
        "tid": "tenant-1",
        "sid": "session-1",
        "jti": "session-1",
        "iat": iat,
        "nbf": iat,
        "exp": iat + 900.0,
        "auth_time": iat - 60.0,
        "kind": "role",
        "mfa": true,
        "role": "role-1",
        "trust": "trust-1",
    })
    .as_object()
    .cloned()
    .unwrap();
    for (name, value) in overrides.as_object().cloned().unwrap_or_default() {
        if value.is_null() {
            claims.shift_remove(&name);
        } else {
            claims.insert(name, value);
        }
    }
    // Integral numbers as JSON integers (as JavaScript writes them).
    for value in claims.values_mut() {
        if let Some(number) = value.as_f64()
            && number.fract() == 0.0
        {
            *value = json!(number as i64);
        }
    }
    claims
}

fn claims_value(claims: &Map<String, Value>) -> Value {
    Value::Object(claims.clone())
}

fn reason<T: std::fmt::Debug>(result: Result<T, SessionTokenError>) -> String {
    match result {
        Ok(value) => panic!("expected a SessionTokenError, got {value:?}"),
        Err(error) => error.reason,
    }
}

fn invalid_config(options: Value) -> better_iam_core::IamError {
    let clock = Clock::new();
    match session_token_signer(Some(&options_of(options)), ISSUER, clock.now()) {
        Ok(_) => panic!("expected INVALID_CONFIG"),
        Err(error) => error,
    }
}

#[test]
fn returns_none_when_sts_jwt_is_not_configured() {
    let clock = Clock::new();
    assert!(
        session_token_signer(None, ISSUER, clock.now())
            .unwrap()
            .is_none()
    );
}

#[test]
fn refuses_invalid_configuration() {
    let with = |key: &TestKey, patch: Value| {
        let mut jwk = key.private_jwk.clone();
        for (name, value) in patch.as_object().cloned().unwrap_or_default() {
            if value.is_null() {
                jwk.shift_remove(&name);
            } else {
                jwk.insert(name, value);
            }
        }
        Value::Object(jwk)
    };
    let eleven: Vec<Value> = (0..11)
        .map(|i| with(&ED, json!({ "kid": format!("k{i}") })))
        .collect();
    let eleven_public: Vec<Value> = (0..11)
        .map(|i| {
            let mut jwk = RETIRED_ED.public_jwk.clone();
            jwk.insert("kid".into(), json!(format!("v{i}")));
            Value::Object(jwk)
        })
        .collect();
    let rsa =
        json!({ "kty": "RSA", "n": "x", "e": "AQAB", "d": "y", "kid": "rsa", "alg": "RS256" });
    let p384 = generate_test_key("ES384", "p384");
    let mut reused = RETIRED_ED.public_jwk.clone();
    reused.insert("kid".into(), json!("ed-1"));
    let cases: Vec<(&str, Value, &str)> = vec![
        (
            "no signing keys",
            json!({ "signingKeys": [] }),
            "sts.jwt.signingKeys",
        ),
        (
            "more than ten signing keys",
            json!({ "signingKeys": eleven }),
            "sts.jwt.signingKeys",
        ),
        (
            "an RSA key",
            json!({ "signingKeys": [rsa] }),
            "sts.jwt.signingKeys",
        ),
        (
            "an ES384 key",
            json!({ "signingKeys": [p384.private_jwk] }),
            "sts.jwt.signingKeys",
        ),
        (
            "a key without alg",
            json!({ "signingKeys": [with(&ED, json!({ "alg": null }))] }),
            "signingKeys",
        ),
        (
            "a public signing key",
            json!({ "signingKeys": [ED.public_jwk] }),
            "must be private keys",
        ),
        (
            "a bad kid",
            json!({ "signingKeys": [with(&ED, json!({ "kid": "has space" }))] }),
            "kid",
        ),
        (
            "a missing kid",
            json!({ "signingKeys": [with(&ED, json!({ "kid": null }))] }),
            "kid",
        ),
        (
            "use enc",
            json!({ "signingKeys": [with(&ED, json!({ "use": "enc" }))] }),
            "use 'sig'",
        ),
        (
            "key_ops without sign",
            json!({ "signingKeys": [with(&ED, json!({ "key_ops": ["verify"] }))] }),
            "key_ops",
        ),
        (
            "a key whose public part does not match",
            json!({ "signingKeys": [with(&ED, json!({ "x": RETIRED_ED.public_jwk["x"] }))] }),
            "not a valid EdDSA key",
        ),
        (
            "duplicate kids",
            json!({ "signingKeys": [ED.private_jwk, with(&EC, json!({ "kid": "ed-1" }))] }),
            "more than once",
        ),
        (
            "a kid reused by a verification key",
            json!({ "signingKeys": [ED.private_jwk], "verificationKeys": [reused] }),
            "more than once",
        ),
        (
            "a private verification key",
            json!({ "signingKeys": [ED.private_jwk], "verificationKeys": [RETIRED_ED.private_jwk] }),
            "sts.jwt.verificationKeys must contain public keys only",
        ),
        (
            "more than ten verification keys",
            json!({ "signingKeys": [ED.private_jwk], "verificationKeys": eleven_public }),
            "sts.jwt.verificationKeys",
        ),
        (
            "an unknown activeKeyId",
            json!({ "signingKeys": [ED.private_jwk], "activeKeyId": "ed-old" }),
            "sts.jwt.activeKeyId",
        ),
        (
            "maxLifetimeSeconds 299",
            json!({ "signingKeys": [ED.private_jwk], "maxLifetimeSeconds": 299 }),
            "maxLifetime",
        ),
        (
            "maxLifetimeSeconds 43201",
            json!({ "signingKeys": [ED.private_jwk], "maxLifetimeSeconds": 43201 }),
            "maxLifetime",
        ),
        (
            "a bad audience",
            json!({ "signingKeys": [ED.private_jwk], "audiences": ["-bad"] }),
            "sts.jwt.audiences",
        ),
        (
            "an issuer with a query",
            json!({ "signingKeys": [ED.private_jwk], "issuer": "https://iam.example.com/?x=1" }),
            "sts.jwt.issuer",
        ),
        (
            "a relative issuer",
            json!({ "signingKeys": [ED.private_jwk], "issuer": "/api/iam" }),
            "sts.jwt.issuer",
        ),
    ];
    for (name, options, message) in cases {
        let error = invalid_config(options);
        assert_eq!(error.code, "INVALID_CONFIG", "{name}");
        assert!(
            error.message.contains(message),
            "{name}: {} should contain {message}",
            error.message
        );
    }
}

#[test]
fn defaults_the_issuer_active_key_audiences_and_lifetime() {
    let clock = Clock::new();
    let result = signer_with(
        &clock,
        json!({ "audiences": ["billing-api", ISSUER, "billing-api"] }),
    );
    assert_eq!(result.issuer(), ISSUER);
    assert_eq!(
        result.audiences(),
        [ISSUER.to_owned(), "billing-api".to_owned()]
    );
    assert_eq!(result.max_lifetime_seconds(), 3600.0);
}

#[test]
fn publishes_only_allowlisted_public_members() {
    let clock = Clock::new();
    let result = signer_with(
        &clock,
        json!({ "verificationKeys": [RETIRED_ED.public_jwk] }),
    );
    let keys = serde_json::to_value(result.public_jwks()).unwrap();
    let keys = keys.as_array().unwrap();
    let kids: Vec<&str> = keys
        .iter()
        .map(|key| key["kid"].as_str().unwrap())
        .collect();
    assert_eq!(kids, ["ed-1", "ec-1", "ed-old"]);
    for key in keys {
        assert_eq!(key["use"], "sig");
        for member in key.as_object().unwrap().keys() {
            assert!(["kty", "crv", "x", "y", "kid", "alg", "use"].contains(&member.as_str()));
        }
    }
    assert_same(
        "first key",
        &keys[0],
        &json!({ "kty": "OKP", "crv": "Ed25519", "x": ED.public_jwk["x"], "kid": "ed-1", "alg": "EdDSA", "use": "sig" }),
    );
    assert_eq!(keys[1]["kty"], "EC");
    assert_eq!(keys[1]["crv"], "P-256");
    assert_eq!(keys[1]["y"], EC.public_jwk["y"]);
    assert_eq!(keys[1]["alg"], "ES256");
    let text = better_iam_core::js::stringify(&Value::Array(keys.clone()));
    assert!(!text.contains(ED.private_jwk["d"].as_str().unwrap()));
}

#[test]
fn round_trips_eddsa_and_es256_tokens() {
    run(|| async {
        for (alg, kid) in [("EdDSA", "ed-1"), ("ES256", "ec-1")] {
            let clock = Clock::new();
            let result = signer_with(&clock, json!({ "activeKeyId": kid }));
            let expected = claims(&clock, json!({}));
            let token = result.sign_json(&expected);
            assert!(looks_like_jwt(&token));
            let (header, payload) = decode_test_jwt(&token);
            assert_same(
                "header",
                &header,
                &json!({ "alg": alg, "kid": kid, "typ": SESSION_TOKEN_TYPE }),
            );
            assert_same("payload", &payload, &claims_value(&expected));
            let verified = result.verify_detailed(&token, None).await.unwrap();
            assert_same(
                "verified",
                &Value::Object(verified.to_json()),
                &claims_value(&expected),
            );
        }
    });
}

#[test]
fn signs_with_keys_whose_metadata_lists_sign_and_verify_key_ops() {
    run(|| async {
        for (key, kid, alg) in [(&*ED, "ed-1", "EdDSA"), (&*EC, "ec-1", "ES256")] {
            let clock = Clock::new();
            let mut jwk = key.private_jwk.clone();
            jwk.insert("use".into(), json!("sig"));
            jwk.insert("key_ops".into(), json!(["sign", "verify"]));
            jwk.insert("ext".into(), json!(true));
            let result = signer_with(&clock, json!({ "signingKeys": [jwk], "activeKeyId": kid }));
            let token = result.sign_json(&claims(&clock, json!({})));
            assert_same(
                "header",
                &decode_test_jwt(&token).0,
                &json!({ "alg": alg, "kid": kid, "typ": SESSION_TOKEN_TYPE }),
            );
            assert!(result.verify_detailed(&token, None).await.is_ok());
        }
    });
}

#[test]
fn checks_the_audience_it_is_asked_for() {
    run(|| async {
        let clock = Clock::new();
        let result = signer_with(&clock, json!({ "audiences": ["billing-api"] }));
        let token = result.sign_json(&claims(&clock, json!({ "aud": [ISSUER, "billing-api"] })));
        let verified = result
            .verify_detailed(&token, Some("billing-api"))
            .await
            .unwrap();
        assert_eq!(verified.aud, json!([ISSUER, "billing-api"]));
        let downstream = result.sign_json(&claims(&clock, json!({ "aud": "billing-api" })));
        assert_eq!(
            reason(result.verify_detailed(&downstream, None).await),
            "audience"
        );
        assert_eq!(
            reason(result.verify_detailed(&token, Some("other-api")).await),
            "audience"
        );
    });
}

#[test]
fn drops_unknown_claims_from_the_result() {
    run(|| async {
        let clock = Clock::new();
        let result = signer_with(&clock, json!({}));
        let token = result.sign_json(&claims(&clock, json!({ "extra": "x" })));
        let verified = result.verify_detailed(&token, None).await.unwrap();
        assert!(!verified.to_json().contains_key("extra"));
    });
}

#[test]
fn refuses_forged_confused_and_out_of_policy_tokens() {
    run(|| async {
        let clock = Clock::new();
        let result = signer_with(&clock, json!({ "maxLifetimeSeconds": 900 }));
        let good = result.sign_json(&claims(&clock, json!({})));
        let base = claims_value(&claims(&clock, json!({})));
        let now = (clock.get() / 1000.0).floor();
        let x = ED.public_jwk["x"].as_str().unwrap().as_bytes().to_vec();
        let none = sign_test_jwt(
            Signer::None,
            &base,
            json!({ "typ": SESSION_TOKEN_TYPE, "kid": "ed-1" }),
        );
        let sign = |overrides: Value| result.sign_json(&claims(&clock, overrides));
        let cases: Vec<(&str, String, &str)> = vec![
            (
                "tampered payload",
                tamper_payload(&good, json!({ "sub": "identity-2" })),
                "signature",
            ),
            ("alg none without a signature", none.clone(), "malformed"),
            (
                "alg none with a fake signature",
                format!("{none}AAAA"),
                "algorithm",
            ),
            (
                "HS256 keyed with the public x",
                sign_test_jwt(
                    Signer::Hs256(&x),
                    &base,
                    json!({ "typ": SESSION_TOKEN_TYPE, "kid": "ed-1" }),
                ),
                "algorithm",
            ),
            (
                "the alg swapped on a kid",
                sign_test_jwt(
                    Signer::Key(&ED),
                    &base,
                    json!({ "typ": SESSION_TOKEN_TYPE, "alg": "ES256" }),
                ),
                "algorithm",
            ),
            (
                "a JWT typ",
                sign_test_jwt(Signer::Key(&ED), &base, json!({ "typ": "JWT" })),
                "type",
            ),
            (
                "an at+jwt typ",
                sign_test_jwt(Signer::Key(&ED), &base, json!({ "typ": "at+jwt" })),
                "type",
            ),
            (
                "no typ",
                sign_test_jwt(Signer::Key(&ED), &base, json!({ "typ": null })),
                "type",
            ),
            (
                "an unknown kid",
                sign_test_jwt(
                    Signer::Key(&RETIRED_ED),
                    &base,
                    json!({ "typ": SESSION_TOKEN_TYPE }),
                ),
                "unknown-key",
            ),
            (
                "no kid",
                sign_test_jwt(
                    Signer::Key(&ED),
                    &base,
                    json!({ "typ": SESSION_TOKEN_TYPE, "kid": null }),
                ),
                "unknown-key",
            ),
            (
                "a wrong issuer",
                sign(json!({ "iss": "https://evil.example" })),
                "issuer",
            ),
            (
                "a wrong audience",
                sign(json!({ "aud": "https://evil.example" })),
                "audience",
            ),
            (
                "an expired token",
                sign(json!({ "exp": now - 10.0 })),
                "expired",
            ),
            (
                "a future nbf",
                sign(json!({ "nbf": now + 60.0 })),
                "not-yet-valid",
            ),
            (
                "a lifetime over the cap",
                sign(json!({ "exp": now + 901.0 })),
                "lifetime",
            ),
            ("a user kind", sign(json!({ "kind": "user" })), "kind"),
            (
                "an api-key kind",
                sign(json!({ "kind": "api-key" })),
                "kind",
            ),
            ("a missing tid", sign(json!({ "tid": null })), "claims"),
            (
                "a jti that is not the sid",
                sign(json!({ "jti": "other" })),
                "claims",
            ),
            ("a non-boolean mfa", sign(json!({ "mfa": "yes" })), "claims"),
            ("a numeric role", sign(json!({ "role": 7 })), "claims"),
            ("a garbage string", "not-a-jwt".to_owned(), "malformed"),
            (
                "a header that is not JSON",
                "aaaa.bbbb.cccc".to_owned(),
                "malformed",
            ),
            (
                "an oversized token",
                format!("{good}{}", "A".repeat(4096)),
                "too-large",
            ),
        ];
        for (name, token, expected) in cases {
            assert_eq!(
                (
                    name,
                    reason(result.verify_detailed(&token, None).await).as_str()
                ),
                (name, expected)
            );
        }
    });
}

#[test]
fn tolerates_five_seconds_of_clock_skew() {
    run(|| async {
        let clock = Clock::new();
        let result = signer_with(&clock, json!({}));
        let now = (clock.get() / 1000.0).floor();
        let token = result.sign_json(&claims(&clock, json!({ "exp": now + 60.0 })));
        clock.advance(63_000.0);
        assert!(result.verify_detailed(&token, None).await.is_ok());
        clock.advance(3_000.0);
        assert_eq!(
            reason(result.verify_detailed(&token, None).await),
            "expired"
        );
    });
}

#[test]
fn keeps_verifying_tokens_of_a_retired_key_during_rotation() {
    run(|| async {
        let clock = Clock::new();
        let before = session_token_signer(
            Some(&options_of(
                json!({ "signingKeys": [RETIRED_ED.private_jwk] }),
            )),
            ISSUER,
            clock.now(),
        )
        .unwrap()
        .unwrap();
        let token = before.sign_json(&claims(&clock, json!({})));
        let during = signer_with(
            &clock,
            json!({ "verificationKeys": [RETIRED_ED.public_jwk] }),
        );
        assert_eq!(
            during.verify_detailed(&token, None).await.unwrap().sid,
            "session-1"
        );
        assert_eq!(
            decode_test_jwt(&during.sign_json(&claims(&clock, json!({})))).0["kid"],
            "ed-1"
        );
        // Removing the kid from both lists revokes its tokens.
        assert_eq!(
            reason(
                signer_with(&clock, json!({}))
                    .verify_detailed(&token, None)
                    .await
            ),
            "unknown-key"
        );
    });
}

/// A JWKS route on 127.0.0.1 answering `body()`; counts hits.
async fn serve(
    body: Arc<std::sync::Mutex<Value>>,
) -> (String, Arc<AtomicU64>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let hits = Arc::new(AtomicU64::new(0));
    let counter = hits.clone();
    let handle = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            counter.fetch_add(1, Ordering::SeqCst);
            let text = better_iam_core::js::stringify(&body.lock().unwrap().clone());
            tokio::spawn(async move {
                let mut buffer = vec![0u8; 8192];
                let mut read = Vec::new();
                while !read.windows(4).any(|window| window == b"\r\n\r\n") {
                    let Ok(count) = socket.read(&mut buffer).await else {
                        return;
                    };
                    if count == 0 {
                        return;
                    }
                    read.extend_from_slice(&buffer[..count]);
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                    text.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.shutdown().await;
            });
        }
    });
    (
        format!("http://127.0.0.1:{port}/api/iam/.well-known/jwks.json"),
        hits,
        handle,
    )
}

#[test]
fn verifies_against_a_remote_jwks_and_refetches_on_an_unknown_kid() {
    run(|| async {
        let clock = Clock::new();
        let keys = Arc::new(std::sync::Mutex::new(json!({ "keys": [ED.public_jwk] })));
        let (url, hits, handle) = serve(keys.clone()).await;
        let verifier = create_session_token_verifier_with(
            &json!({ "issuer": ISSUER, "audience": ISSUER, "jwks": url, "cooldownSeconds": 0 }),
            Some(clock.now()),
        )
        .unwrap();
        let first = session_token_signer(
            Some(&options_of(json!({ "signingKeys": [ED.private_jwk] }))),
            ISSUER,
            clock.now(),
        )
        .unwrap()
        .unwrap();
        let verified = verifier
            .verify_detailed(&first.sign_json(&claims(&clock, json!({}))))
            .await
            .unwrap();
        assert_eq!(verified.kind, "role");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        verifier
            .verify_detailed(&first.sign_json(&claims(&clock, json!({}))))
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // A new kid appears at the JWKS route; the verifier refetches once.
        *keys.lock().unwrap() = json!({ "keys": [ED.public_jwk, EC.public_jwk] });
        let second = session_token_signer(
            Some(&options_of(json!({ "signingKeys": [EC.private_jwk] }))),
            ISSUER,
            clock.now(),
        )
        .unwrap()
        .unwrap();
        verifier
            .verify_detailed(&second.sign_json(&claims(&clock, json!({}))))
            .await
            .unwrap();
        assert_eq!(hits.load(Ordering::SeqCst), 2);
        handle.abort();
    });
}

#[test]
fn reports_an_unreachable_jwks_as_reason_jwks() {
    run(|| async {
        let clock = Clock::new();
        let (url, _, handle) = serve(Arc::new(std::sync::Mutex::new(json!({ "keys": [] })))).await;
        handle.abort();
        let _ = handle.await;
        let verifier = create_session_token_verifier_with(
            &json!({ "issuer": ISSUER, "audience": ISSUER, "jwks": url }),
            Some(clock.now()),
        )
        .unwrap();
        let token = signer_with(&clock, json!({})).sign_json(&claims(&clock, json!({})));
        assert_eq!(reason(verifier.verify_detailed(&token).await), "jwks");
    });
}

#[test]
fn refuses_insecure_remote_jwks_urls_and_bad_options() {
    let clock = Clock::new();
    let jwks = json!({ "keys": signer_with(&clock, json!({})).public_jwks() });
    let refused = |options: Value| create_session_token_verifier_with(&options, None).is_err();
    assert!(refused(
        json!({ "issuer": ISSUER, "audience": ISSUER, "jwks": "http://iam.example.com/jwks" })
    ));
    assert!(refused(
        json!({ "issuer": ISSUER, "audience": [], "jwks": jwks })
    ));
    assert!(refused(
        json!({ "issuer": ISSUER, "audience": ISSUER, "jwks": jwks, "clockToleranceSeconds": 61 })
    ));
    assert!(refused(
        json!({ "issuer": ISSUER, "audience": ISSUER, "jwks": jwks, "algorithms": ["RS256"] })
    ));
    let error = create_session_token_verifier_with(
        &json!({ "issuer": ISSUER, "audience": [], "jwks": jwks }),
        None,
    )
    .err()
    .unwrap();
    assert_eq!(error.name, "TypeError");
    assert_eq!(
        error.message,
        "Invalid session token verifier option: audience"
    );
}

#[test]
fn accepts_any_configured_audience_and_restricts_algorithms_and_kinds() {
    run(|| async {
        let clock = Clock::new();
        let result = signer_with(&clock, json!({ "audiences": ["billing-api"] }));
        let verifier = create_session_token_verifier_with(
            &json!({
                "issuer": ISSUER,
                "audience": ["billing-api", "reports-api"],
                "jwks": { "keys": result.public_jwks() },
                "algorithms": ["ES256"],
                "kinds": ["session-token"],
            }),
            Some(clock.now()),
        )
        .unwrap();
        let ec_signer = signer_with(
            &clock,
            json!({ "activeKeyId": "ec-1", "audiences": ["billing-api"] }),
        );
        let token = ec_signer.sign_json(&claims(
            &clock,
            json!({ "aud": "billing-api", "kind": "session-token" }),
        ));
        assert_eq!(
            verifier.verify_detailed(&token).await.unwrap().kind,
            "session-token"
        );
        assert_eq!(
            reason(
                verifier
                    .verify_detailed(
                        &result.sign_json(&claims(&clock, json!({ "aud": "billing-api" })))
                    )
                    .await
            ),
            "algorithm"
        );
        assert_eq!(
            reason(
                verifier
                    .verify_detailed(
                        &ec_signer.sign_json(&claims(&clock, json!({ "aud": "billing-api" })))
                    )
                    .await
            ),
            "kind"
        );
    });
}

#[test]
fn verify_request_takes_a_case_insensitive_bearer_header() {
    run(|| async {
        let clock = Clock::new();
        let result = signer_with(&clock, json!({}));
        let verifier = create_session_token_verifier_with(
            &json!({ "issuer": ISSUER, "audience": ISSUER, "jwks": { "keys": result.public_jwks() } }),
            Some(clock.now()),
        )
        .unwrap();
        let token = result.sign_json(&claims(&clock, json!({})));
        let request = |headers: Value| json!({ "headers": headers });
        assert_eq!(
            verifier
                .verify_request_detailed(&request(
                    json!({ "authorization": format!("bearer {token}") })
                ))
                .await
                .unwrap()
                .sid,
            "session-1"
        );
        assert_eq!(
            verifier
                .verify_request_detailed(&request(
                    json!({ "Authorization": format!("BEARER {token}") })
                ))
                .await
                .unwrap()
                .sid,
            "session-1"
        );
        assert!(
            verifier
                .verify_request_detailed(&request(json!([[
                    "authorization",
                    format!("Bearer {token}")
                ]])))
                .await
                .is_ok()
        );
        let missing = verifier.verify_request_detailed(&request(json!({}))).await;
        assert_eq!(
            missing.as_ref().err().unwrap().message,
            "A bearer session token is required"
        );
        assert_eq!(reason(missing), "malformed");
        assert_eq!(
            reason(
                verifier
                    .verify_request_detailed(&request(
                        json!({ "authorization": format!("Basic {token}") })
                    ))
                    .await
            ),
            "malformed"
        );
        assert_eq!(
            reason(
                verifier
                    .verify_request_detailed(&request(
                        json!({ "authorization": format!("Bearer  {token}") })
                    ))
                    .await
            ),
            "malformed"
        );
    });
}

#[test]
fn exposes_a_stable_error_shape() {
    run(|| async {
        let clock = Clock::new();
        let error = signer_with(&clock, json!({}))
            .verify("not-a-jwt", None)
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_SESSION_TOKEN");
        assert_eq!(error.status, 401);
        let detailed = signer_with(&clock, json!({}))
            .verify_detailed("not-a-jwt", None)
            .await
            .unwrap_err();
        assert_eq!(detailed.reason, "malformed");
        assert_eq!(SESSION_TOKEN_ALGORITHMS, ["EdDSA", "ES256"]);
        assert!(!looks_like_jwt("a.b"));
        assert!(!looks_like_jwt_value(Some(&json!(42))));
        assert!(!looks_like_jwt("biam_ses_abc"));
    });
}

// --- spec/vectors/session-jwt.json -------------------------------------------------------------------------------

fn fixed_clock(now: f64) -> better_iam_server::context::NowFn {
    Arc::new(move || now)
}

fn expect_session_error(name: &str, result: Result<Value, SessionTokenError>, output: &Value) {
    match (result, output.get("$error")) {
        (Err(error), Some(expected)) => {
            assert_eq!(error.reason, expected["reason"], "{name}: reason");
            assert_eq!(error.message, expected["message"], "{name}: message");
        }
        (Ok(value), None) => assert_same(name, &value, output),
        (Ok(value), Some(expected)) => panic!("{name}: expected {expected}, got {value}"),
        (Err(error), None) => panic!("{name}: expected {output}, got {}", error.reason),
    }
}

#[test]
fn session_jwt_vectors() {
    run(|| async {
        let file = read_json("spec/vectors/session-jwt.json");
        for case in file["cases"].as_array().unwrap() {
            let name = case["name"].as_str().unwrap();
            let input = &case["input"];
            let output = &case["output"];
            if name.starts_with("looksLikeJwt") {
                assert_eq!(
                    json!(looks_like_jwt_value(input.get("value"))),
                    *output,
                    "{name}"
                );
                continue;
            }
            let now = input["now"].as_f64().unwrap();
            if let Some(verifier) = input.get("verifier") {
                let verifier =
                    create_session_token_verifier_with(verifier, Some(fixed_clock(now))).unwrap();
                let result = verifier
                    .verify_value(input.get("token"))
                    .await
                    .map(|claims| Value::Object(claims.to_json()));
                expect_session_error(name, result, output);
                continue;
            }
            let options: SessionTokenSigningOptions =
                serde_json::from_value(input["options"].clone()).unwrap();
            let issuer = input["issuer"].as_str().unwrap();
            let signer = match session_token_signer(Some(&options), issuer, fixed_clock(now)) {
                Ok(signer) => signer.unwrap(),
                Err(error) => {
                    let expected = &output["$error"];
                    assert_eq!(error.code, expected["code"], "{name}: code");
                    assert_eq!(error.message, expected["message"], "{name}: message");
                    assert_eq!(json!(error.status), expected["status"], "{name}: status");
                    continue;
                }
            };
            assert!(
                output.get("$error").is_none() || input.get("token").is_some(),
                "{name}"
            );
            if let Some(claims) = input.get("claims") {
                let token = signer.sign_json(claims.as_object().unwrap());
                let (header, payload) = decode_test_jwt(&token);
                assert_same(&format!("{name}: header"), &header, &output["header"]);
                assert_same(&format!("{name}: payload"), &payload, &output["payload"]);
                if header["alg"] == "EdDSA" {
                    // Ed25519 is deterministic: the very same token.
                    assert_eq!(token, output["token"], "{name}: token");
                } else {
                    // ES256 is randomized: both tokens verify.
                    assert!(signer.verify_detailed(&token, None).await.is_ok(), "{name}");
                    let recorded = output["token"].as_str().unwrap();
                    assert!(
                        signer.verify_detailed(recorded, None).await.is_ok(),
                        "{name}"
                    );
                }
                continue;
            }
            if let Some(token) = input.get("token") {
                let token = token.as_str().unwrap();
                let audience = input.get("audience").and_then(Value::as_str);
                let result = signer
                    .verify_detailed(token, audience)
                    .await
                    .map(|claims| Value::Object(claims.to_json()));
                expect_session_error(name, result, output);
                continue;
            }
            let actual = json!({
                "issuer": signer.issuer(),
                "audiences": signer.audiences(),
                "maxLifetimeSeconds": signer.max_lifetime_seconds(),
                "jwks": { "keys": signer.public_jwks() },
            });
            assert_same(name, &actual, output);
        }
    });
}
