//! Ports of the authentication-service parts of `tests/tenant-auth-policy.test.ts`, `tests/network-blocks.test.ts`,
//! `tests/ip-allowlist.test.ts`, `tests/session-binding.test.ts` and `tests/session-limits.test.ts`. Tenant policies
//! and blocks are written to storage directly (the server's `tenants.setAuthPolicy` and `security.blockNetwork`
//! validate and write them in the server port).

mod support;

use better_iam_auth::service::CreateIdentityInput;
use better_iam_core::{IamStoreExt, Identity, ip_matches, is_ip_range, record};
use serde_json::{Value, json};
use support::*;

const DAY: f64 = 86_400_000.0;

async fn owner(f: &Fixture) -> Identity {
    let input = CreateIdentityInput {
        tenant_id: "org".to_owned(),
        email: "owner@acme.test".to_owned(),
        name: "Owner".to_owned(),
        password: Some("a strong tenant owner password".to_owned()),
        owner: Some(true),
        email_verified: Some(true),
        ..Default::default()
    };
    let auth = f.auth.clone();
    f.store
        .transaction(|tx| async move { auth.create_identity(&tx, input).await })
        .await
        .unwrap()
}

async fn member(f: &Fixture, name: &str) -> Identity {
    f.person(
        "org",
        &format!("{name}@acme.test"),
        name,
        &format!("a strong {name} password"),
        true,
        false,
    )
    .await
}

async fn sign_in(
    f: &Fixture,
    name: &str,
) -> Result<better_iam_auth::SignInResult, better_iam_core::IamError> {
    f.sign_in(
        "org",
        &format!("{name}@acme.test"),
        &format!("a strong {name} password"),
    )
    .await
}

async fn from(
    f: &Fixture,
    ip: &str,
    name: &str,
) -> Result<better_iam_auth::SignInResult, better_iam_core::IamError> {
    f.sign_in_from(
        Some(client(Some(ip), Some("test"), None)),
        "org",
        &format!("{name}@acme.test"),
        &format!("a strong {name} password"),
    )
    .await
}

async fn get_session_from(
    f: &Fixture,
    ip: Option<&str>,
    session_token: &str,
) -> Result<better_iam_auth::service::sessions::SessionInfo, better_iam_core::IamError> {
    let credential = token(session_token);
    let call = f.auth.get_session(&credential);
    f.auth
        .with_client(ip.map(|ip| client(Some(ip), Some("test"), None)), call)
        .await
}

#[tokio::test]
async fn restricts_sign_in_methods_and_records_the_method_on_sessions() {
    let f = server(|options| options.passwordless_email = Some(true)).await;
    member(&f, "alice").await;
    let login = session(sign_in(&f, "alice").await.unwrap());
    assert_eq!(
        login.session.method.map(|method| method.as_str()),
        Some("password")
    );
    f.set_policy(
        "org",
        Some(json!({ "allowedMethods": ["passwordless-email"] })),
    )
    .await;
    for password in ["a strong alice password", "wrong"] {
        assert_eq!(
            code(f.sign_in("org", "alice@acme.test", password).await),
            "METHOD_NOT_ALLOWED"
        );
    }
    assert_eq!(
        code(
            f.auth
                .reauthenticate(
                    &token(&login.token),
                    &json!({ "password": "a strong alice password" })
                )
                .await
        ),
        "METHOD_NOT_ALLOWED"
    );
    f.auth
        .start_passwordless(&json!({ "tenantId": "org", "destination": "alice@acme.test", "channel": "email", "kind": "code" }))
        .await
        .unwrap();
    f.auth.dispatch_outbox(None).await.unwrap();
    let code_value = f.inbox.last("code").payload["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let via_email = session(
        f.auth
            .finish_passwordless(&json!({ "tenantId": "org", "destination": "alice@acme.test", "token": code_value }))
            .await
            .unwrap(),
    );
    assert_eq!(
        via_email.session.method.map(|method| method.as_str()),
        Some("passwordless-email")
    );
    let info = f.auth.get_session(&token(&via_email.token)).await.unwrap();
    assert_eq!(
        info.session.method.map(|method| method.as_str()),
        Some("passwordless-email")
    );
    f.set_policy("org", None).await;
    assert!(sign_in(&f, "alice").await.unwrap().session().is_some());
    // An SMS-only policy also blocks passkey and email starts.
    f.set_policy(
        "org",
        Some(json!({ "allowedMethods": ["passwordless-sms"] })),
    )
    .await;
    assert_eq!(
        code(
            f.auth
                .start_passwordless(&json!({ "tenantId": "org", "destination": "alice@acme.test", "channel": "email", "kind": "code" }))
                .await
        ),
        "METHOD_NOT_ALLOWED"
    );
}

#[tokio::test]
async fn caps_sign_in_attempts_and_enforces_a_minimum_password_length_per_tenant() {
    let f = server(|_| {}).await;
    member(&f, "alice").await;
    owner(&f).await;
    let owner_session = session(
        f.sign_in("org", "owner@acme.test", "a strong tenant owner password")
            .await
            .unwrap(),
    );
    f.set_policy(
        "org",
        Some(json!({ "maxAttempts": 2, "minPasswordLength": 20 })),
    )
    .await;
    assert_eq!(
        code(f.sign_in("org", "alice@acme.test", "wrong").await),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        code(f.sign_in("org", "alice@acme.test", "wrong").await),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        code(
            f.sign_in("org", "alice@acme.test", "a strong alice password")
                .await
        ),
        "RATE_LIMITED"
    );
    let short = CreateIdentityInput {
        tenant_id: "org".to_owned(),
        email: "bob@acme.test".to_owned(),
        name: "Bob".to_owned(),
        password: Some("twelve chars!".to_owned()),
        ..Default::default()
    };
    let auth = f.auth.clone();
    let refused = f
        .store
        .transaction(|tx| async move { auth.create_identity(&tx, short).await })
        .await;
    assert_eq!(code(refused), "WEAK_PASSWORD");
    assert_eq!(
        code(
            f.auth
                .change_password(
                    &token(&owner_session.token),
                    &json!({ "currentPassword": "a strong tenant owner password", "password": "short but > 12" })
                )
                .await
        ),
        "WEAK_PASSWORD"
    );
}

#[tokio::test]
async fn can_require_mfa_for_owners_only() {
    let f = server(|_| {}).await;
    member(&f, "alice").await;
    owner(&f).await;
    let owner_session = session(
        f.sign_in("org", "owner@acme.test", "a strong tenant owner password")
            .await
            .unwrap(),
    );
    f.set_policy("org", Some(json!({ "requireMfaForOwners": true })))
        .await;
    assert_eq!(
        code(f.auth.get_session(&token(&owner_session.token)).await),
        "MFA_REQUIRED"
    );
    let challenge = f
        .sign_in("org", "owner@acme.test", "a strong tenant owner password")
        .await
        .unwrap();
    let challenge = challenge.mfa().expect("owner MFA").clone();
    assert!(challenge.enrollment_required);
    assert!(sign_in(&f, "alice").await.unwrap().session().is_some());
    let credential = better_iam_auth::types::MfaCredential::Challenge {
        tenant_id: "org".to_owned(),
        challenge: challenge.challenge,
    };
    let enrollment = f.auth.begin_mfa(&credential).await.unwrap();
    let confirmed = f
        .auth
        .confirm_mfa(&better_iam_auth::service::mfa::ConfirmMfaInput {
            credential,
            code: f.totp(&enrollment.secret),
            remember_device: false,
        })
        .await
        .unwrap();
    assert!(confirmed.session.mfa);
    assert_eq!(
        code(f.auth.disable_mfa(&token(&confirmed.token)).await),
        "MFA_REQUIRED"
    );
}

#[tokio::test]
async fn caps_concurrent_sessions_per_member_and_lets_administrators_trigger_password_resets() {
    let f = server(|_| {}).await;
    let alice = member(&f, "alice").await;
    f.set_policy("org", Some(json!({ "maxSessions": 2 }))).await;
    let first = session(sign_in(&f, "alice").await.unwrap());
    f.clock.advance(1000.0);
    let second = session(sign_in(&f, "alice").await.unwrap());
    f.clock.advance(1000.0);
    let third = session(sign_in(&f, "alice").await.unwrap());
    assert_eq!(
        code(f.auth.get_session(&token(&first.token)).await),
        "UNAUTHENTICATED"
    );
    assert_eq!(
        f.auth
            .get_session(&token(&second.token))
            .await
            .unwrap()
            .session
            .id,
        second.session.id
    );
    assert_eq!(
        f.auth
            .list_sessions(&token(&third.token))
            .await
            .unwrap()
            .len(),
        2
    );
    let auth = f.auth.clone();
    let stored = alice.clone();
    f.store
        .transaction(|tx| async move { auth.issue_password_reset(&tx, &stored).await })
        .await
        .unwrap();
    f.auth.dispatch_outbox(None).await.unwrap();
    let reset = f.inbox.last("password-reset");
    assert_eq!(reset.to, "alice@acme.test");
    f.auth
        .reset_password(&json!({ "tenantId": "org", "token": reset.payload["token"], "password": "a brand new alice password" }))
        .await
        .unwrap();
    assert!(
        f.sign_in("org", "alice@acme.test", "a brand new alice password")
            .await
            .unwrap()
            .session()
            .is_some()
    );
}

#[tokio::test]
async fn shortens_session_lifetimes_and_requires_mfa_for_everyone_in_the_tenant() {
    let f = server(|options| {
        options.session_lifetime_ms = Some(7.0 * DAY);
        options.session_idle_timeout_ms = Some(7.0 * DAY);
    })
    .await;
    member(&f, "bob").await;
    f.set_policy(
        "org",
        Some(json!({ "sessionLifetimeMs": 600_000, "sessionIdleTimeoutMs": 120_000 })),
    )
    .await;
    let bob = session(sign_in(&f, "bob").await.unwrap());
    assert_eq!(bob.session.expires_at - bob.session.created_at, 600_000.0);
    f.clock.advance(90_000.0);
    assert_eq!(
        f.auth
            .get_session(&token(&bob.token))
            .await
            .unwrap()
            .session
            .id,
        bob.session.id
    );
    f.clock.advance(120_000.0);
    assert_eq!(
        code(f.auth.get_session(&token(&bob.token)).await),
        "UNAUTHENTICATED"
    );
    let active = session(sign_in(&f, "bob").await.unwrap());
    for _ in 0..9 {
        f.clock.advance(60_000.0);
        f.auth.get_session(&token(&active.token)).await.unwrap();
    }
    f.clock.advance(90_000.0);
    assert_eq!(
        code(f.auth.get_session(&token(&active.token)).await),
        "UNAUTHENTICATED"
    );
    f.set_policy("org", Some(json!({ "requireMfa": true })))
        .await;
    let challenge = sign_in(&f, "bob")
        .await
        .unwrap()
        .mfa()
        .expect("MFA required")
        .clone();
    assert!(challenge.enrollment_required);
    let credential = better_iam_auth::types::MfaCredential::Challenge {
        tenant_id: "org".to_owned(),
        challenge: challenge.challenge,
    };
    let enrollment = f.auth.begin_mfa(&credential).await.unwrap();
    let enrolled = f
        .auth
        .confirm_mfa(&better_iam_auth::service::mfa::ConfirmMfaInput {
            credential,
            code: f.totp(&enrollment.secret),
            remember_device: false,
        })
        .await
        .unwrap();
    assert!(enrolled.session.mfa);
    assert_eq!(
        enrolled.session.method.map(|method| method.as_str()),
        Some("password")
    );
    assert_eq!(
        code(f.auth.disable_mfa(&token(&enrolled.token)).await),
        "MFA_REQUIRED"
    );
}

async fn block(
    f: &Fixture,
    id: &str,
    tenant: &str,
    network: &str,
    expires_at: Option<f64>,
    platform: bool,
) {
    let mut row = record(json!({
        "id": id, "tenantId": tenant, "network": network, "reason": "test", "createdAt": f.clock.now(),
        "createdBy": "usr_root",
    }));
    if let Some(at) = expires_at {
        row.insert("expiresAt".to_owned(), json!(at));
    }
    if platform {
        row.insert("platform".to_owned(), json!(true));
    }
    f.store
        .transaction(|tx| async move { tx.insert("authBlocks", &row).await })
        .await
        .unwrap();
    f.auth.invalidate_network_blocks();
}

#[tokio::test]
async fn platform_network_blocks_stop_sign_ins_counters_and_live_sessions_until_lifted_or_lapsed() {
    let f = server(|_| {}).await;
    let alice = member(&f, "alice").await;
    let early = session(from(&f, "198.51.100.9", "alice").await.unwrap());
    block(
        &f,
        "blk_1",
        "root",
        "198.51.100.0/24",
        Some(f.clock.now() + 3_600_000.0),
        true,
    )
    .await;
    assert_eq!(
        from(&f, "198.51.100.9", "alice").await.unwrap_err(),
        better_iam_core::IamError::with_status(
            "IP_BLOCKED",
            "Sign-in from this network is blocked",
            403
        )
    );
    let reset = json!({ "tenantId": "org", "email": "alice@acme.test" });
    assert_eq!(
        code(
            f.auth
                .with_client(
                    Some(client(Some("198.51.100.200"), None, None)),
                    f.auth.request_password_reset(&reset)
                )
                .await
        ),
        "IP_BLOCKED"
    );
    assert_eq!(
        code(
            f.sign_in_from(
                Some(client(Some("198.51.100.200"), None, None)),
                "root",
                "root@example.test",
                ROOT_PASSWORD
            )
            .await
        ),
        "IP_BLOCKED"
    );
    f.auth.settle_bookkeeping().await;
    assert!(f.failures("org", &alice.id).await.is_empty());
    assert_eq!(
        code(f.auth.get_session(&token(&early.token)).await),
        "IP_BLOCKED"
    );
    assert!(
        from(&f, "203.0.113.7", "alice")
            .await
            .unwrap()
            .session()
            .is_some()
    );
    // Lifting it restores the network at once.
    f.store
        .transaction(|tx| async move { tx.delete("authBlocks", "blk_1").await })
        .await
        .unwrap();
    f.auth.invalidate_network_blocks();
    assert!(
        from(&f, "198.51.100.9", "alice")
            .await
            .unwrap()
            .session()
            .is_some()
    );
    // A timed block lapses by itself.
    block(
        &f,
        "blk_2",
        "root",
        "198.51.100.9",
        Some(f.clock.now() + 60_000.0),
        true,
    )
    .await;
    assert_eq!(code(from(&f, "198.51.100.9", "alice").await), "IP_BLOCKED");
    f.clock.advance(61_000.0);
    assert!(
        from(&f, "198.51.100.9", "alice")
            .await
            .unwrap()
            .session()
            .is_some()
    );
}

#[tokio::test]
async fn organization_network_blocks_apply_to_that_organization_only() {
    let f = server(|_| {}).await;
    member(&f, "alice").await;
    block(&f, "blk_org", "org", "192.0.2.0/24", None, false).await;
    assert_eq!(code(from(&f, "192.0.2.5", "alice").await), "IP_BLOCKED");
    let root_attempt = f
        .sign_in_from(
            Some(client(Some("192.0.2.5"), None, None)),
            "root",
            "root@example.test",
            ROOT_PASSWORD,
        )
        .await
        .unwrap();
    assert!(root_attempt.mfa().is_some());
    // Blocks are cached for a few seconds per process.
    f.store
        .transaction(|tx| async move { tx.delete("authBlocks", "blk_org").await })
        .await
        .unwrap();
    assert_eq!(code(from(&f, "192.0.2.5", "alice").await), "IP_BLOCKED");
    f.clock.advance(5_000.0);
    assert!(
        from(&f, "192.0.2.5", "alice")
            .await
            .unwrap()
            .session()
            .is_some()
    );
}

#[test]
fn validates_ranges_and_exposes_the_matching_helpers() {
    assert!(is_ip_range("203.0.113.0/24"));
    assert!(is_ip_range("2001:db8::/32"));
    assert!(is_ip_range("203.0.113.9"));
    assert!(!is_ip_range("office"));
    assert!(!is_ip_range("203.0.113.0/33"));
    assert!(ip_matches("203.0.113.9", "203.0.113.0/24"));
    assert!(!ip_matches("203.0.114.9", "203.0.113.0/24"));
    assert!(ip_matches("2001:db8:1::5", "2001:db8::/32"));
    assert!(!ip_matches("203.0.113.9", "2001:db8::/32"));
}

#[tokio::test]
async fn refuses_sign_ins_and_later_use_from_outside_the_allowed_networks_when_an_ip_is_known() {
    let f = server(|_| {}).await;
    member(&f, "alice").await;
    let outside = session(from(&f, "198.51.100.7", "alice").await.unwrap());
    f.set_policy(
        "org",
        Some(json!({ "allowedIpRanges": ["203.0.113.0/24", "2001:db8::/32"] })),
    )
    .await;
    let refused = from(&f, "198.51.100.7", "alice").await.unwrap_err();
    assert_eq!(
        (refused.code.as_str(), refused.status),
        ("IP_NOT_ALLOWED", 403)
    );
    let inside = session(from(&f, "203.0.113.42", "alice").await.unwrap());
    assert_eq!(
        inside
            .session
            .client
            .as_ref()
            .and_then(|client| client.ip.as_deref()),
        Some("203.0.113.42")
    );
    assert!(
        from(&f, "2001:db8:cafe::1", "alice")
            .await
            .unwrap()
            .session()
            .is_some()
    );
    assert!(sign_in(&f, "alice").await.unwrap().session().is_some());
    assert_eq!(
        code(f.auth.get_session(&token(&outside.token)).await),
        "IP_NOT_ALLOWED"
    );
    assert_eq!(
        f.auth
            .get_session(&token(&inside.token))
            .await
            .unwrap()
            .identity
            .email
            .as_deref(),
        Some("alice@acme.test")
    );
    f.set_policy("org", None).await;
    assert_eq!(
        f.auth
            .get_session(&token(&outside.token))
            .await
            .unwrap()
            .session
            .id,
        outside.session.id
    );
}

#[tokio::test]
async fn refuses_a_bound_session_from_another_address_records_it_and_leaves_unbound_cases_alone() {
    let f = server(|_| {}).await;
    member(&f, "alice").await;
    let bound = session(from(&f, "203.0.113.7", "alice").await.unwrap());
    assert_eq!(
        get_session_from(&f, Some("198.51.100.9"), &bound.token)
            .await
            .unwrap()
            .session
            .id,
        bound.session.id
    );
    f.set_policy("org", Some(json!({ "bindSessionsToIp": true })))
        .await;
    assert_eq!(
        get_session_from(&f, Some("203.0.113.7"), &bound.token)
            .await
            .unwrap()
            .session
            .id,
        bound.session.id
    );
    let mismatch = get_session_from(&f, Some("198.51.100.9"), &bound.token)
        .await
        .unwrap_err();
    assert_eq!(
        (mismatch.code.as_str(), mismatch.status),
        ("SESSION_NETWORK_MISMATCH", 401)
    );
    let events = f
        .auth
        .with_client(
            Some(client(Some("203.0.113.7"), Some("test"), None)),
            f.auth
                .list_security_events(&token(&bound.token), &json!({ "limit": 5 })),
        )
        .await
        .unwrap();
    let recorded = events
        .iter()
        .find(|event| event.action == "auth:session:mismatch")
        .expect("mismatch event");
    assert_json(
        &Value::Object(recorded.metadata.clone().unwrap()),
        &json!({ "sessionId": bound.session.id, "sessionIp": "203.0.113.7", "ip": "198.51.100.9", "userAgent": "test" }),
    );
    let away = session(from(&f, "198.51.100.9", "alice").await.unwrap());
    assert_eq!(
        get_session_from(&f, Some("198.51.100.9"), &away.token)
            .await
            .unwrap()
            .session
            .id,
        away.session.id
    );
    assert_eq!(
        code(get_session_from(&f, Some("203.0.113.7"), &away.token).await),
        "SESSION_NETWORK_MISMATCH"
    );
    let bare = session(sign_in(&f, "alice").await.unwrap());
    assert_eq!(
        get_session_from(&f, Some("198.51.100.9"), &bare.token)
            .await
            .unwrap()
            .session
            .id,
        bare.session.id
    );
    assert_eq!(
        get_session_from(&f, None, &bound.token)
            .await
            .unwrap()
            .session
            .id,
        bound.session.id
    );
}

#[tokio::test]
async fn reports_the_lifetime_idle_timeout_and_idle_expiry_in_force_honouring_the_tenant_policy() {
    let f = server(|options| {
        options.session_lifetime_ms = Some(600_000.0);
        options.session_idle_timeout_ms = Some(240_000.0);
    })
    .await;
    f.person(
        "root",
        "owner@example.test",
        "Owner",
        "a strong tenant owner password",
        true,
        false,
    )
    .await;
    let signed = session(
        f.sign_in(
            "root",
            "owner@example.test",
            "a strong tenant owner password",
        )
        .await
        .unwrap(),
    );
    let first = f.auth.get_session(&token(&signed.token)).await.unwrap();
    assert_json(
        &serde_json::to_value(first.limits).unwrap(),
        &json!({ "lifetimeMs": 600_000, "idleTimeoutMs": 240_000, "idleExpiresAt": f.clock.now() + 240_000.0, "now": f.clock.now() }),
    );
    assert_eq!(first.session.expires_at, f.clock.now() + 600_000.0);
    f.set_policy("root", Some(json!({ "sessionIdleTimeoutMs": 120_000 })))
        .await;
    f.clock.advance(60_000.0);
    let shortened = f.auth.get_session(&token(&signed.token)).await.unwrap();
    assert_eq!(shortened.limits.idle_timeout_ms, 120_000.0);
    assert_eq!(shortened.limits.idle_expires_at, f.clock.now() + 120_000.0);
    assert_eq!(shortened.session.last_seen_at, f.clock.now());
    while signed.session.expires_at - f.clock.now() > 120_000.0 {
        f.clock.advance(90_000.0);
        let touched = f.auth.get_session(&token(&signed.token)).await.unwrap();
        assert_eq!(
            touched.limits.idle_expires_at,
            (f.clock.now() + 120_000.0).min(signed.session.expires_at)
        );
    }
    let ending = f.auth.get_session(&token(&signed.token)).await.unwrap();
    assert_eq!(ending.limits.idle_expires_at, signed.session.expires_at);
    assert!(ending.limits.idle_expires_at < f.clock.now() + 120_000.0);
    f.clock.advance(120_001.0);
    assert_eq!(
        code(f.auth.get_session(&token(&signed.token)).await),
        "UNAUTHENTICATED"
    );
}
