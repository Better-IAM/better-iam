//! Port of `tests/sign-in-insight.test.ts` and `tests/security-activity.test.ts`.

mod support;

use better_iam_auth::types::RateLimitOptions;
use better_iam_core::{SessionClientInfo, VerifyAuditChainOptions, verify_audit_chain};
use serde_json::{Value, json};
use support::*;

const PASSWORD: &str = "a strong tenant owner password";

async fn fixture(attempts: Option<f64>) -> (Fixture, String) {
    let f = server(|options| {
        if let Some(attempts) = attempts {
            options.rate_limits = Some(RateLimitOptions {
                attempts: Some(attempts),
                ..Default::default()
            });
        }
    })
    .await;
    let owner = f
        .person("root", "owner@example.test", "Owner", PASSWORD, true, false)
        .await;
    (f, owner.id)
}

async fn sign_in(
    f: &Fixture,
    password: &str,
    from: Option<SessionClientInfo>,
) -> Result<better_iam_auth::SignInResult, better_iam_core::IamError> {
    f.sign_in_from(from, "root", "owner@example.test", password)
        .await
}

fn client_json(client: &SessionClientInfo) -> Value {
    serde_json::to_value(client).unwrap()
}

#[tokio::test]
async fn counts_wrong_passwords_stamps_the_previous_sign_in_on_the_next_session_and_shows_both_in_the_trail()
 {
    let (f, owner) = fixture(None).await;
    let laptop = client(Some("203.0.113.7"), Some("Mozilla/5.0 (Macintosh)"), None);
    let guesser = client(Some("198.51.100.9"), Some("curl/8"), None);
    assert_eq!(
        code(sign_in(&f, "not the password", Some(guesser.clone())).await),
        "INVALID_CREDENTIALS"
    );
    f.clock.advance(1_000.0);
    assert_eq!(
        code(sign_in(&f, "still wrong", Some(guesser.clone())).await),
        "INVALID_CREDENTIALS"
    );
    let second_failure_at = f.clock.now();
    f.auth.settle_bookkeeping().await;
    let ledger = f.get("authSignIns", &owner).await.unwrap();
    assert_eq!(ledger["failedAttempts"], 2);
    assert_eq!(ledger["lastFailedAt"].as_f64(), Some(second_failure_at));
    assert_eq!(ledger["lastFailedClient"], client_json(&guesser));
    assert!(ledger.get("lastAt").is_none());
    assert_eq!(f.failures("root", &owner).await.len(), 2);
    f.clock.advance(1_000.0);
    let first = session(sign_in(&f, PASSWORD, Some(laptop.clone())).await.unwrap());
    assert_json(
        &serde_json::to_value(first.session.previous_sign_in.clone().unwrap()).unwrap(),
        &json!({ "failedAttempts": 2, "lastFailedAt": second_failure_at, "lastFailedClient": client_json(&guesser) }),
    );
    let ledger = f.get("authSignIns", &owner).await.unwrap();
    assert_json(
        &Value::Object(ledger),
        &json!({
            "id": owner, "tenantId": "root", "identityId": owner, "lastAt": first.session.created_at,
            "lastClient": client_json(&laptop), "failedAttempts": 0,
        }),
    );
    f.clock.advance(60_000.0);
    let second = session(sign_in(&f, PASSWORD, Some(laptop.clone())).await.unwrap());
    assert_json(
        &serde_json::to_value(second.session.previous_sign_in.clone().unwrap()).unwrap(),
        &json!({ "failedAttempts": 0, "lastAt": first.session.created_at, "lastClient": client_json(&laptop) }),
    );
    let current = f.auth.get_session(&token(&second.token)).await.unwrap();
    assert_eq!(
        current.session.previous_sign_in,
        second.session.previous_sign_in
    );
    assert_eq!(current.session.id, second.session.id);
    let events = f
        .auth
        .list_security_events(&token(&second.token), &json!({ "limit": 20 }))
        .await
        .unwrap();
    let failed: Vec<_> = events
        .iter()
        .filter(|event| event.action == "auth:signin:fail")
        .collect();
    assert_eq!(failed.len(), 2);
    assert_json(
        &Value::Object(failed[0].metadata.clone().unwrap()),
        &json!({ "reason": "password", "ip": "198.51.100.9", "userAgent": "curl/8" }),
    );
    let created: Vec<_> = events
        .iter()
        .filter(|event| event.action == "auth:session:create")
        .collect();
    assert_json(
        &Value::Object(created[0].metadata.clone().unwrap()),
        &json!({ "method": "password", "ip": "203.0.113.7", "userAgent": "Mozilla/5.0 (Macintosh)" }),
    );
    assert!(!serde_json::to_string(&events).unwrap().contains(PASSWORD));
    // Events appended outside the refused transactions still form one valid chain.
    let mut chain = f.find("audit", json!({ "tenantId": "root" })).await;
    chain.sort_by(|a, b| {
        a["sequence"]
            .as_f64()
            .partial_cmp(&b["sequence"].as_f64())
            .unwrap()
    });
    let verification = verify_audit_chain(&chain, &VerifyAuditChainOptions::default());
    assert!(verification.valid, "{verification:?}");
    assert_eq!(verification.checked as usize, chain.len());
}

#[tokio::test]
async fn ignores_unknown_addresses_attempts_the_rate_limiter_refused_and_disabled_accounts() {
    let (f, owner) = fixture(Some(3.0)).await;
    assert_eq!(
        code(f.sign_in("root", "nobody@example.test", "whatever").await),
        "INVALID_CREDENTIALS"
    );
    f.auth.settle_bookkeeping().await;
    assert_eq!(f.failures("root", &owner).await.len(), 0);
    assert_eq!(
        f.find("authSignIns", json!({ "tenantId": "root" }))
            .await
            .len(),
        0
    );
    for _ in 0..3 {
        assert_eq!(
            code(sign_in(&f, "wrong", None).await),
            "INVALID_CREDENTIALS"
        );
    }
    assert_eq!(code(sign_in(&f, "wrong", None).await), "RATE_LIMITED");
    f.auth.settle_bookkeeping().await;
    assert_eq!(f.failures("root", &owner).await.len(), 3);
    let ledger = f.get("authSignIns", &owner).await.unwrap();
    assert_eq!(ledger["failedAttempts"], 3);
    assert!(ledger.get("lastFailedClient").is_none());
    // A disabled account is refused like a wrong password and records nothing.
    f.patch("identities", &owner, json!({ "status": "disabled" }))
        .await;
    let identity: better_iam_core::Identity =
        serde_json::from_value(Value::Object(f.get("identities", &owner).await.unwrap())).unwrap();
    f.auth.reset_rate_limits(&identity).await.unwrap();
    assert_eq!(
        code(sign_in(&f, PASSWORD, None).await),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        code(sign_in(&f, "wrong", None).await),
        "INVALID_CREDENTIALS"
    );
    f.auth.settle_bookkeeping().await;
    assert_eq!(f.failures("root", &owner).await.len(), 3);
    assert_eq!(
        f.get("authSignIns", &owner).await.unwrap()["failedAttempts"],
        3
    );
}

#[tokio::test]
async fn counts_wrong_authenticator_and_recovery_codes_once_the_password_was_right() {
    let (f, owner) = fixture(None).await;
    let first = session(sign_in(&f, PASSWORD, None).await.unwrap());
    let (secret, enrolled) = enroll(&f, &first.token).await;
    let previous = enrolled.session.previous_sign_in.clone().unwrap();
    assert_eq!(previous.failed_attempts, 0.0);
    assert_eq!(previous.last_at, Some(first.session.created_at));
    f.clock.advance(31_000.0);
    let challenge = sign_in(&f, PASSWORD, Some(client(Some("198.51.100.9"), None, None)))
        .await
        .unwrap();
    let challenge = challenge.mfa().expect("Expected MFA").challenge.clone();
    let right = f.totp(&secret);
    let wrong = format!("{:06}", (right.parse::<u32>().unwrap() + 1) % 1_000_000);
    assert_eq!(
        code(
            f.auth
                .verify_mfa(&json!({ "tenantId": "root", "challenge": challenge, "code": wrong }))
                .await
        ),
        "INVALID_MFA"
    );
    assert_eq!(
        code(
            f.auth
                .recover_mfa(&json!({ "tenantId": "root", "challenge": challenge, "code": "not-a-recovery-code" }))
                .await
        ),
        "INVALID_MFA"
    );
    f.auth.settle_bookkeeping().await;
    let reasons: Vec<Value> = f
        .failures("root", &owner)
        .await
        .iter()
        .map(|event| event["metadata"]["reason"].clone())
        .collect();
    assert_eq!(reasons, vec![json!("mfa"), json!("recovery-code")]);
    // An invalid challenge is not an attempt against anyone.
    assert_eq!(
        code(
            f.auth
                .verify_mfa(
                    &json!({ "tenantId": "root", "challenge": "x".repeat(40), "code": right })
                )
                .await
        ),
        "INVALID_CHALLENGE"
    );
    f.auth.settle_bookkeeping().await;
    assert_eq!(f.failures("root", &owner).await.len(), 2);
    let verified = f
        .auth
        .verify_mfa(&json!({ "tenantId": "root", "challenge": challenge, "code": right }))
        .await
        .unwrap();
    let previous = verified.session.previous_sign_in.clone().unwrap();
    assert_eq!(previous.failed_attempts, 2.0);
    assert_eq!(previous.last_at, Some(enrolled.session.created_at));
    assert_eq!(previous.last_failed_at, Some(f.clock.now()));
    let ledger = f.get("authSignIns", &owner).await.unwrap();
    assert_eq!(ledger["failedAttempts"], 0);
    assert_eq!(ledger["lastAt"].as_f64(), Some(verified.session.created_at));
}

mod security_activity {
    use super::*;

    async fn fixture(notifications: bool) -> Fixture {
        let f = server(|options| options.sign_in_notifications = Some(notifications)).await;
        f.person("root", "owner@example.test", "Owner", PASSWORD, true, false)
            .await;
        f
    }

    #[tokio::test]
    async fn emails_a_person_about_sessions_from_unfamiliar_clients_only_and_lists_their_own_authentication_trail()
     {
        let f = fixture(true).await;
        let alerts = |f: &Fixture| f.messages("new-sign-in");
        session(sign_in(&f, PASSWORD, None).await.unwrap());
        f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(alerts(&f).len(), 0);
        let laptop = client(
            Some("203.0.113.7"),
            Some("Mozilla/5.0 (Macintosh)"),
            Some("Laptop"),
        );
        let first = session(sign_in(&f, PASSWORD, Some(laptop.clone())).await.unwrap());
        f.auth.dispatch_outbox(None).await.unwrap();
        let sent = alerts(&f);
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].to, "owner@example.test");
        assert_eq!(sent[0].payload["sessionId"], first.session.id.as_str());
        assert_eq!(sent[0].payload["method"], "password");
        assert_eq!(sent[0].payload["userAgent"], "Mozilla/5.0 (Macintosh)");
        assert_eq!(sent[0].payload["ip"], "203.0.113.7");
        assert_eq!(sent[0].payload["label"], "Laptop");
        sign_in(&f, PASSWORD, Some(laptop)).await.unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(alerts(&f).len(), 1);
        sign_in(
            &f,
            PASSWORD,
            Some(client(
                Some("198.51.100.2"),
                Some("Mozilla/5.0 (iPhone)"),
                None,
            )),
        )
        .await
        .unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(alerts(&f).len(), 2);
        f.set_policy("root", Some(json!({ "notifyNewSignIn": false })))
            .await;
        sign_in(
            &f,
            PASSWORD,
            Some(client(Some("192.0.2.9"), Some("curl/8"), None)),
        )
        .await
        .unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(alerts(&f).len(), 2);
        let events = f
            .auth
            .list_security_events(&token(&first.token), &json!({ "limit": 10 }))
            .await
            .unwrap();
        assert!(events.len() >= 5);
        assert!(events.iter().all(|event| event.action.starts_with("auth:")));
        assert!(events[0].timestamp >= events.last().unwrap().timestamp);
        let actions: Vec<&str> = events.iter().map(|event| event.action.as_str()).collect();
        assert!(actions.contains(&"auth:session:create"));
        assert!(actions.contains(&"auth:identity:create"));
        assert!(!serde_json::to_string(&events).unwrap().contains("actorId"));
        assert_eq!(
            code(
                f.auth
                    .list_security_events(&token(&first.token), &json!({ "limit": 0 }))
                    .await
            ),
            "INVALID_INPUT"
        );
        let root_events: Vec<String> = f
            .find("audit", json!({ "tenantId": "root" }))
            .await
            .into_iter()
            .filter(|event| event["actorId"] != first.session.identity_id.as_str())
            .map(|event| event["id"].as_str().unwrap().to_owned())
            .collect();
        assert!(!root_events.is_empty());
        assert!(events.iter().all(|event| !root_events.contains(&event.id)));
    }

    #[tokio::test]
    async fn stays_silent_when_the_deployment_leaves_notifications_off() {
        let f = fixture(false).await;
        sign_in(
            &f,
            PASSWORD,
            Some(client(
                Some("203.0.113.7"),
                Some("Mozilla/5.0 (Macintosh)"),
                None,
            )),
        )
        .await
        .unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(f.messages("new-sign-in").len(), 0);
        f.set_policy("root", Some(json!({ "notifyNewSignIn": true })))
            .await;
        sign_in(
            &f,
            PASSWORD,
            Some(client(
                Some("203.0.113.8"),
                Some("Mozilla/5.0 (Windows)"),
                None,
            )),
        )
        .await
        .unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(f.messages("new-sign-in").len(), 1);
    }
}
