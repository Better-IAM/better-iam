//! Port of `tests/brute-force.test.ts` (the authentication-service parts; the server's options map onto
//! `AuthOptions`).

mod support;

use better_iam_auth::types::RateLimitOptions;
use better_iam_auth::{AuthOptions, create_auth};
use support::*;

const PASSWORD: &str = "a strong tenant owner password";

async fn fixture(ip_attempts: Option<f64>, alerts: Option<f64>) -> (Fixture, String, String) {
    let f = server(|options| {
        options.rate_limits = Some(RateLimitOptions {
            attempts: Some(10.0),
            sensitive_attempts: Some(10.0),
            window_ms: Some(90_000.0),
            ip_attempts,
            limiter: None,
        });
        options.failed_sign_in_alerts = alerts;
    })
    .await;
    let owner = f
        .person("root", "owner@example.test", "Owner", PASSWORD, true, false)
        .await;
    let bob = f
        .person("root", "bob@example.test", "Bob", PASSWORD, false, false)
        .await;
    (f, owner.id, bob.id)
}

async fn attempt(
    f: &Fixture,
    email: &str,
    password: &str,
    ip: Option<&str>,
) -> Result<better_iam_auth::SignInResult, better_iam_core::IamError> {
    let from = ip.map(|ip| client(Some(ip), Some("curl/8"), None));
    f.sign_in_from(from, "root", email, password).await
}

#[tokio::test]
async fn caps_attempts_per_client_ip_across_accounts_and_flows_independently_of_the_per_account_limits()
 {
    let (f, owner, _) = fixture(Some(3.0), None).await;
    let sprayer = "198.51.100.9";
    for email in [
        "owner@example.test",
        "bob@example.test",
        "nobody@example.test",
    ] {
        assert_eq!(
            code(attempt(&f, email, "wrong", Some(sprayer)).await),
            "INVALID_CREDENTIALS"
        );
    }
    let refused = attempt(&f, "carol@example.test", "wrong", Some(sprayer))
        .await
        .unwrap_err();
    assert_eq!(
        (refused.code.as_str(), refused.status),
        ("RATE_LIMITED", 429)
    );
    assert_eq!(f.auth.rate_limit_window_ms(), 90_000.0);
    let body = serde_json::json!({ "tenantId": "root", "email": "owner@example.test" });
    let reset = f.auth.with_client(
        Some(client(Some(sprayer), None, None)),
        f.auth.request_password_reset(&body),
    );
    assert_eq!(code(reset.await), "RATE_LIMITED");
    // Refused attempts are not counted against the accounts they named.
    f.auth.settle_bookkeeping().await;
    assert_eq!(f.failures("root", &owner).await.len(), 1);
    assert_eq!(
        code(attempt(&f, "owner@example.test", "wrong", Some("203.0.113.7")).await),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        code(attempt(&f, "owner@example.test", "wrong", None).await),
        "INVALID_CREDENTIALS"
    );
    let session = attempt(&f, "owner@example.test", PASSWORD, Some("203.0.113.7"))
        .await
        .unwrap();
    assert!(session.session().is_some());
    // Unlocking a person clears their own counters, never the network's.
    let identity: better_iam_core::Identity = serde_json::from_value(serde_json::Value::Object(
        f.get("identities", &owner).await.unwrap(),
    ))
    .unwrap();
    f.auth.reset_rate_limits(&identity).await.unwrap();
    assert_eq!(
        code(attempt(&f, "owner@example.test", PASSWORD, Some(sprayer)).await),
        "RATE_LIMITED"
    );
    // The option is validated like the other limits.
    let mut options = AuthOptions::new(
        f.store.clone(),
        "brute-force-test-secret-with-at-least-32-chars",
        "http://localhost:3000",
    );
    options.rate_limits = Some(RateLimitOptions {
        ip_attempts: Some(-1.0),
        ..Default::default()
    });
    assert!(
        create_auth(options)
            .err()
            .unwrap()
            .message
            .contains("ipAttempts")
    );
}

#[tokio::test]
async fn emails_a_person_once_per_streak_when_their_failed_attempts_reach_the_threshold() {
    let (f, _, _) = fixture(None, Some(2.0)).await;
    let guesser = "198.51.100.9";
    let alerts = |f: &Fixture| f.messages("sign-in-failures");
    assert_eq!(
        code(attempt(&f, "owner@example.test", "wrong", Some(guesser)).await),
        "INVALID_CREDENTIALS"
    );
    f.auth.settle_bookkeeping().await;
    f.auth.dispatch_outbox(None).await.unwrap();
    assert_eq!(alerts(&f).len(), 0);
    assert_eq!(
        code(attempt(&f, "owner@example.test", "wrong again", Some(guesser)).await),
        "INVALID_CREDENTIALS"
    );
    f.auth.settle_bookkeeping().await;
    f.auth.dispatch_outbox(None).await.unwrap();
    let sent = alerts(&f);
    assert_eq!(sent.len(), 1);
    assert_eq!(sent[0].to, "owner@example.test");
    assert_eq!(sent[0].payload["attempts"], "2");
    assert_eq!(sent[0].payload["ip"], guesser);
    assert_eq!(sent[0].payload["userAgent"], "curl/8");
    let time = sent[0].payload["time"].as_str().unwrap();
    assert!(time.len() > 11 && time.as_bytes()[4] == b'-' && time.as_bytes()[10] == b'T');
    // Further failures in the same streak stay quiet; a sign-in ends the streak and a new one alerts again.
    assert_eq!(
        code(attempt(&f, "owner@example.test", "and again", Some(guesser)).await),
        "INVALID_CREDENTIALS"
    );
    f.auth.settle_bookkeeping().await;
    f.auth.dispatch_outbox(None).await.unwrap();
    assert_eq!(alerts(&f).len(), 1);
    let signed_in = attempt(&f, "owner@example.test", PASSWORD, Some("203.0.113.7"))
        .await
        .unwrap();
    let previous = signed_in
        .session()
        .unwrap()
        .session
        .previous_sign_in
        .clone()
        .unwrap();
    assert_eq!(previous.failed_attempts, 3.0);
    for password in ["x", "y"] {
        assert_eq!(
            code(attempt(&f, "owner@example.test", password, Some(guesser)).await),
            "INVALID_CREDENTIALS"
        );
    }
    f.auth.settle_bookkeeping().await;
    f.auth.dispatch_outbox(None).await.unwrap();
    assert_eq!(alerts(&f).len(), 2);
    // Unverified addresses never receive the alert, and the option needs a mail transport.
    for password in ["x", "y", "z"] {
        assert_eq!(
            code(attempt(&f, "bob@example.test", password, Some(guesser)).await),
            "INVALID_CREDENTIALS"
        );
    }
    f.auth.settle_bookkeeping().await;
    f.auth.dispatch_outbox(None).await.unwrap();
    assert!(
        alerts(&f)
            .iter()
            .all(|message| message.to != "bob@example.test")
    );
    let mut options = AuthOptions::new(
        f.store.clone(),
        "brute-force-test-secret-with-at-least-32-chars",
        "http://localhost:3000",
    );
    options.failed_sign_in_alerts = Some(3.0);
    assert_eq!(
        create_auth(options).err().unwrap().message,
        "failedSignInAlerts requires sendEmail"
    );
    let mut options = AuthOptions::new(
        f.store.clone(),
        "brute-force-test-secret-with-at-least-32-chars",
        "http://localhost:3000",
    );
    options.failed_sign_in_alerts = Some(5_000.0);
    options.send_email = Some(better_iam_auth::delivery_fn(|_| async { Ok(()) }));
    assert!(
        create_auth(options)
            .err()
            .unwrap()
            .message
            .contains("failedSignInAlerts")
    );
}
