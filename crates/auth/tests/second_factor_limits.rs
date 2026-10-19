//! Port of `tests/second-factor-limits.test.ts` (per-person second-factor limits, failed-attempt bookkeeping, and
//! the rate limiter storage).

mod support;

use std::sync::Arc;
use std::time::Duration;

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::types::{ConsumeInput, PasskeyOptions};
use better_iam_auth::{
    AuthOptions, MemoryRateLimiterOptions, create_auth, create_memory_rate_limiter,
    create_store_rate_limiter,
};
use better_iam_core::{IamStoreExt, record};
use serde_json::{Value, json};
use support::*;

/// `{name}@acme.test` with an authenticator, past the time step the enrollment used.
struct Enrolled {
    id: String,
    name: String,
    secret: String,
    recovery_codes: Vec<String>,
}

async fn enrolled(f: &Fixture, name: &str) -> Enrolled {
    let identity = f
        .person(
            "org",
            &format!("{name}@acme.test"),
            name,
            &format!("a strong {name} password"),
            true,
            false,
        )
        .await;
    let first = session(
        f.sign_in(
            "org",
            &format!("{name}@acme.test"),
            &format!("a strong {name} password"),
        )
        .await
        .unwrap(),
    );
    let (secret, confirmed) = enroll(f, &first.token).await;
    f.clock.advance(31_000.0);
    Enrolled {
        id: identity.id,
        name: name.to_owned(),
        secret,
        recovery_codes: confirmed.recovery_codes,
    }
}

impl Enrolled {
    async fn challenge(&self, f: &Fixture) -> String {
        let result = f
            .sign_in(
                "org",
                &format!("{}@acme.test", self.name),
                &format!("a strong {} password", self.name),
            )
            .await
            .unwrap();
        result.mfa().expect("Expected MFA").challenge.clone()
    }
}

fn wrong(right: &str) -> String {
    format!(
        "{:06}",
        (right.parse::<u32>().unwrap() + 500_000) % 1_000_000
    )
}

async fn verify(
    f: &Fixture,
    challenge: &str,
    code: &str,
) -> Result<better_iam_auth::MfaSessionResult, better_iam_core::IamError> {
    f.auth
        .verify_mfa(&json!({ "tenantId": "org", "challenge": challenge, "code": code }))
        .await
}

#[tokio::test]
async fn does_not_grant_fresh_code_guesses_with_every_correct_password() {
    let f = server(|_| {}).await;
    let alice = enrolled(&f, "alice").await;
    let first = alice.challenge(&f).await;
    for _ in 0..3 {
        assert_eq!(
            code(verify(&f, &first, &wrong(&f.totp(&alice.secret))).await),
            "INVALID_MFA"
        );
    }
    let second = alice.challenge(&f).await;
    for _ in 0..2 {
        assert_eq!(
            code(verify(&f, &second, &wrong(&f.totp(&alice.secret))).await),
            "INVALID_MFA"
        );
    }
    let third = alice.challenge(&f).await;
    let limited = verify(&f, &third, &wrong(&f.totp(&alice.secret)))
        .await
        .unwrap_err();
    assert_eq!(
        (limited.code.as_str(), limited.status),
        ("RATE_LIMITED", 429)
    );
    assert_eq!(
        code(verify(&f, &third, &f.totp(&alice.secret)).await),
        "RATE_LIMITED"
    );
    let bob = enrolled(&f, "bob").await;
    let bob_challenge = bob.challenge(&f).await;
    assert_eq!(
        code(verify(&f, &bob_challenge, &wrong(&f.totp(&bob.secret))).await),
        "INVALID_MFA"
    );
    let identity: better_iam_core::Identity =
        serde_json::from_value(Value::Object(f.get("identities", &alice.id).await.unwrap()))
            .unwrap();
    assert!(f.auth.reset_rate_limits(&identity).await.unwrap().supported);
    assert!(
        verify(&f, &third, &f.totp(&alice.secret))
            .await
            .unwrap()
            .session
            .mfa
    );
}

#[tokio::test]
async fn limits_recovery_code_guesses_per_person_across_challenges() {
    let f = server(|_| {}).await;
    let alice = enrolled(&f, "alice").await;
    let recover = |challenge: String, code: String| {
        let auth = f.auth.clone();
        async move {
            auth.recover_mfa(&json!({ "tenantId": "org", "challenge": challenge, "code": code }))
                .await
        }
    };
    let first = alice.challenge(&f).await;
    for attempt in 0..3 {
        assert_eq!(
            code(recover(first.clone(), format!("not-a-recovery-code-{attempt}")).await),
            "INVALID_MFA"
        );
    }
    let second = alice.challenge(&f).await;
    for attempt in 0..2 {
        assert_eq!(
            code(recover(second.clone(), format!("still-not-one-{attempt}")).await),
            "INVALID_MFA"
        );
    }
    let third = alice.challenge(&f).await;
    assert_eq!(
        code(recover(third.clone(), alice.recovery_codes[0].clone()).await),
        "RATE_LIMITED"
    );
    assert_eq!(
        code(verify(&f, &third, &wrong(&f.totp(&alice.secret))).await),
        "INVALID_MFA"
    );
}

#[tokio::test]
async fn caps_emailed_mfa_codes_per_person_however_many_sign_ins_ask_for_them() {
    let f = server(|options| options.mfa_email_codes = Some(true)).await;
    f.set_policy("org", Some(json!({ "requireMfa": true })))
        .await;
    f.person(
        "org",
        "carol@acme.test",
        "Carol",
        "a strong carol password",
        true,
        false,
    )
    .await;
    let challenge = || async {
        let result = f
            .sign_in("org", "carol@acme.test", "a strong carol password")
            .await
            .unwrap();
        let mfa = result.mfa().expect("MFA").clone();
        assert_eq!(mfa.email_code_available, Some(true));
        mfa.challenge
    };
    let request = |challenge: String| {
        let auth = f.auth.clone();
        async move {
            auth.request_mfa_code(&json!({ "tenantId": "org", "challenge": challenge }))
                .await
        }
    };
    let first = challenge().await;
    for _ in 0..3 {
        request(first.clone()).await.unwrap();
    }
    let second = challenge().await;
    for _ in 0..2 {
        request(second.clone()).await.unwrap();
    }
    assert_eq!(code(request(challenge().await).await), "RATE_LIMITED");
    f.auth.dispatch_outbox(None).await.unwrap();
    assert_eq!(
        f.messages("mfa-code")
            .iter()
            .filter(|message| message.to == "carol@acme.test")
            .count(),
        5
    );
}

#[tokio::test]
async fn limits_starting_passkey_second_factors_per_person() {
    let f = server(|options| {
        options.passkeys = Some(PasskeyOptions {
            rp_id: "localhost".to_owned(),
            rp_name: None,
        });
    })
    .await;
    let alice = enrolled(&f, "alice").await;
    let begin = |challenge: String| {
        let auth = f.auth.clone();
        async move {
            auth.begin_passkey_mfa(&json!({ "tenantId": "org", "challenge": challenge }))
                .await
        }
    };
    let first = alice.challenge(&f).await;
    for _ in 0..3 {
        assert_eq!(code(begin(first.clone()).await), "FEATURE_DISABLED");
    }
    let second = alice.challenge(&f).await;
    for _ in 0..2 {
        assert_eq!(code(begin(second.clone()).await), "FEATURE_DISABLED");
    }
    assert_eq!(code(begin(alice.challenge(&f).await).await), "RATE_LIMITED");
}

#[tokio::test(flavor = "multi_thread")]
async fn answers_a_wrong_password_without_waiting_for_the_failure_to_be_recorded() {
    let store = sqlite_adapter(SqliteAdapterOptions::new(":memory:")).unwrap();
    store.migrate().await.unwrap();
    let gate = Arc::new(tokio::sync::Notify::new());
    let held = gate.clone();
    let mut options = AuthOptions::new(
        store.clone(),
        "bookkeeping-test-secret-with-32-characters",
        "http://localhost:3000",
    );
    // Holds the failure record's transaction open until the test lets it finish.
    options.on_audit = Some(Arc::new(move |_tx, event| {
        let held = held.clone();
        Box::pin(async move {
            if event.get("action").and_then(Value::as_str) == Some("auth:signin:fail") {
                held.notified().await;
            }
            Ok(())
        })
    }));
    let auth = create_auth(options).unwrap();
    let at = now_ms();
    store
        .transaction(|tx| async move {
            tx.insert(
                "tenants",
                &record(json!({ "id": "org", "tenantId": "org", "name": "org", "parentId": null, "type": "root", "status": "active", "createdAt": at })),
            )
            .await
        })
        .await
        .unwrap();
    let creator = auth.clone();
    let alice = store
        .transaction(|tx| async move {
            creator
                .create_identity(
                    &tx,
                    better_iam_auth::service::CreateIdentityInput {
                        tenant_id: "org".to_owned(),
                        email: "alice@example.test".to_owned(),
                        name: "Alice".to_owned(),
                        password: Some("a strong alice password".to_owned()),
                        ..Default::default()
                    },
                )
                .await
        })
        .await
        .unwrap();
    let body =
        json!({ "tenantId": "org", "email": "alice@example.test", "password": "not the password" });
    let attempt = auth.sign_in(&body);
    let outcome = tokio::time::timeout(Duration::from_secs(2), attempt).await;
    gate.notify_waiters();
    gate.notify_one();
    assert_eq!(
        outcome
            .expect("answered before the record was written")
            .unwrap_err()
            .code,
        "INVALID_CREDENTIALS"
    );
    auth.settle_bookkeeping().await;
    assert_eq!(
        store.get("authSignIns", &alice.id).await.unwrap().unwrap()["failedAttempts"],
        1
    );
}

#[tokio::test]
async fn records_wrong_passwords_given_to_reauthenticate_and_change_password() {
    let f = server(|_| {}).await;
    let alice = f
        .person(
            "org",
            "alice@acme.test",
            "alice",
            "a strong alice password",
            true,
            false,
        )
        .await;
    let signed_in = session(
        f.sign_in_from(
            Some(client(Some("203.0.113.7"), Some("laptop"), None)),
            "org",
            "alice@acme.test",
            "a strong alice password",
        )
        .await
        .unwrap(),
    );
    let credential = token(&signed_in.token);
    let guesser = || Some(client(Some("198.51.100.9"), Some("curl/8"), None));
    for password in ["guess one", "guess two"] {
        let body = json!({ "password": password });
        let refused = f
            .auth
            .with_client(guesser(), f.auth.reauthenticate(&credential, &body))
            .await;
        assert_eq!(code(refused), "INVALID_CREDENTIALS");
    }
    let body =
        json!({ "currentPassword": "guess three", "password": "a brand new alice password" });
    assert_eq!(
        code(
            f.auth
                .with_client(guesser(), f.auth.change_password(&credential, &body))
                .await
        ),
        "INVALID_CREDENTIALS"
    );
    f.auth.settle_bookkeeping().await;
    let ledger = f.get("authSignIns", &alice.id).await.unwrap();
    assert_eq!(ledger["failedAttempts"], 3);
    assert_json(
        &ledger["lastFailedClient"],
        &json!({ "ip": "198.51.100.9", "userAgent": "curl/8" }),
    );
    let failures = f.failures("org", &alice.id).await;
    assert_eq!(failures.len(), 3);
    for event in &failures {
        assert_json(
            &event["metadata"],
            &json!({ "reason": "password", "ip": "198.51.100.9", "userAgent": "curl/8" }),
        );
    }
    let again = session(
        f.auth
            .reauthenticate(
                &credential,
                &json!({ "password": "a strong alice password" }),
            )
            .await
            .unwrap(),
    );
    assert_eq!(
        again
            .session
            .previous_sign_in
            .as_ref()
            .unwrap()
            .failed_attempts,
        3.0
    );
}

fn input(key: &str, limit: f64, window_ms: f64, now: f64) -> ConsumeInput {
    ConsumeInput {
        key: key.to_owned(),
        tenant_id: "t".to_owned(),
        limit,
        window_ms,
        now,
    }
}

#[tokio::test]
async fn bounds_the_in_memory_limiter_dropping_expired_counters_first_and_then_the_oldest() {
    assert!(
        create_memory_rate_limiter(MemoryRateLimiterOptions {
            max_keys: Some(0.0)
        })
        .err()
        .unwrap()
        .message
        .contains("maxKeys")
    );
    let limiter = create_memory_rate_limiter(MemoryRateLimiterOptions {
        max_keys: Some(2.0),
    })
    .unwrap();
    assert!(
        limiter
            .consume(input("a", 1.0, 1_000.0, 0.0))
            .await
            .unwrap()
    );
    assert!(
        !limiter
            .consume(input("a", 1.0, 1_000.0, 0.0))
            .await
            .unwrap()
    );
    assert!(
        limiter
            .consume(input("b", 1.0, 10_000.0, 0.0))
            .await
            .unwrap()
    );
    assert!(
        limiter
            .consume(input("c", 1.0, 1_000.0, 5_000.0))
            .await
            .unwrap()
    );
    assert!(
        !limiter
            .consume(input("b", 1.0, 1_000.0, 5_000.0))
            .await
            .unwrap()
    );
    assert!(
        limiter
            .consume(input("d", 1.0, 1_000.0, 5_000.0))
            .await
            .unwrap()
    );
    assert!(
        !limiter
            .consume(input("c", 1.0, 1_000.0, 5_000.0))
            .await
            .unwrap()
    );
    assert!(
        limiter
            .consume(input("b", 1.0, 1_000.0, 5_000.0))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn keeps_the_in_memory_limiter_cheap_when_flooded_with_fresh_keys() {
    let limiter = create_memory_rate_limiter(MemoryRateLimiterOptions::default()).unwrap();
    let started = std::time::Instant::now();
    for index in 0..120_000 {
        limiter
            .consume(input(&format!("k{index}"), 5.0, 60_000.0, 0.0))
            .await
            .unwrap();
    }
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(
        limiter
            .consume(input("k0", 1.0, 60_000.0, 0.0))
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn deletes_expired_store_counters_including_those_of_made_up_tenants() {
    let store = sqlite_adapter(SqliteAdapterOptions::new(":memory:")).unwrap();
    store.migrate().await.unwrap();
    let limiter = create_store_rate_limiter(store.clone());
    let day = 24.0 * 60.0 * 60_000.0;
    for index in 0..30 {
        limiter
            .consume(ConsumeInput {
                key: format!("key-{index}"),
                tenant_id: if index % 3 != 0 {
                    "org".to_owned()
                } else {
                    format!("ghost-{index}")
                },
                limit: 5.0,
                window_ms: 60_000.0,
                now: 1_000.0 + f64::from(index),
            })
            .await
            .unwrap();
    }
    assert_eq!(
        store
            .find("authRateLimits", &Default::default(), &Default::default())
            .await
            .unwrap()
            .len(),
        30
    );
    let fresh = |now: f64| ConsumeInput {
        key: "fresh".to_owned(),
        tenant_id: "org".to_owned(),
        limit: 5.0,
        window_ms: 60_000.0,
        now,
    };
    assert!(limiter.consume(fresh(2.0 * day)).await.unwrap());
    let mut ids = Vec::new();
    for _ in 0..200 {
        ids = store
            .find("authRateLimits", &Default::default(), &Default::default())
            .await
            .unwrap()
            .iter()
            .map(|row| row["id"].as_str().unwrap().to_owned())
            .collect();
        if ids == ["fresh"] {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(ids, vec!["fresh".to_owned()]);
    for _ in 1..5 {
        limiter.consume(fresh(2.0 * day)).await.unwrap();
    }
    assert!(!limiter.consume(fresh(2.0 * day)).await.unwrap());
}
