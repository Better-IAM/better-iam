//! Ports of the authentication-service parts of `tests/security-e15e8e-auth.test.ts` (display names, passwordless
//! codes, mailed links, passkey decoys, reauthentication, identity expiry), `tests/trusted-devices.test.ts` and
//! `tests/session-metadata.test.ts`.

mod support;

use better_iam_auth::types::PasskeyOptions;
use serde_json::json;
use support::*;

const DAY: f64 = 86_400_000.0;

async fn member(f: &Fixture, name: &str) -> better_iam_core::Identity {
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

#[tokio::test]
async fn replaces_control_characters_in_display_names_at_self_sign_up() {
    let f = server(|options| options.sign_up_enabled = Some(true)).await;
    let created = f
        .auth
        .sign_up(&json!({
            "tenantId": "org", "email": "mallory@acme.test", "name": "Mallory\r\nBcc: victim@example.test",
            "password": "a strong mallory password",
        }))
        .await
        .unwrap();
    assert_eq!(created.identity.name, "Mallory  Bcc: victim@example.test");
}

#[tokio::test]
async fn keeps_only_the_newest_code_or_link_of_a_destination_valid() {
    let f = server(|options| options.passwordless_email = Some(true)).await;
    member(&f, "alice").await;
    let start = |kind: &str| {
        let body = json!({ "tenantId": "org", "destination": "alice@acme.test", "channel": "email", "kind": kind });
        let auth = f.auth.clone();
        async move { auth.start_passwordless(&body).await.unwrap() }
    };
    let latest = || async {
        f.auth.dispatch_outbox(None).await.unwrap();
        let sent: Vec<_> = f
            .inbox
            .all()
            .into_iter()
            .filter(|message| message.to == "alice@acme.test")
            .collect();
        sent.last().unwrap().payload["token"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    start("code").await;
    let first = latest().await;
    start("magic-link").await;
    let link = latest().await;
    start("code").await;
    let second = latest().await;
    let finish = |value: &str| {
        let body = json!({ "tenantId": "org", "destination": "alice@acme.test", "token": value });
        let auth = f.auth.clone();
        async move { auth.finish_passwordless(&body).await }
    };
    for stale in [&first, &link] {
        if *stale != second {
            assert_eq!(code(finish(stale).await), "INVALID_CHALLENGE");
        }
    }
    assert!(finish(&second).await.unwrap().session().is_some());
}

#[tokio::test]
async fn drops_a_password_set_before_the_address_was_proven_at_the_first_emailed_sign_in() {
    let f = server(|options| {
        options.passwordless_email = Some(true);
        options.sign_up_enabled = Some(true);
    })
    .await;
    f.auth
        .sign_up(&json!({ "tenantId": "org", "email": "victim@acme.test", "name": "Victim", "password": "attacker chosen password" }))
        .await
        .unwrap();
    assert_eq!(
        code(
            f.sign_in("org", "victim@acme.test", "attacker chosen password")
                .await
        ),
        "EMAIL_UNVERIFIED"
    );
    f.auth
        .start_passwordless(&json!({ "tenantId": "org", "destination": "victim@acme.test", "channel": "email", "kind": "magic-link" }))
        .await
        .unwrap();
    f.auth.dispatch_outbox(None).await.unwrap();
    let link = f.inbox.last("magic-link").payload["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let owner = f
        .auth
        .finish_passwordless(
            &json!({ "tenantId": "org", "destination": "victim@acme.test", "token": link }),
        )
        .await
        .unwrap();
    assert!(owner.session().is_some());
    assert_eq!(
        code(
            f.sign_in("org", "victim@acme.test", "attacker chosen password")
                .await
        ),
        "INVALID_CREDENTIALS"
    );
    let events: Vec<_> = f
        .find("audit", json!({ "tenantId": "org" }))
        .await
        .into_iter()
        .filter(|event| event["action"] == "auth:password:clear")
        .collect();
    assert_eq!(events.len(), 1);
}

#[tokio::test]
async fn leaves_administrator_created_accounts_alone_at_their_first_emailed_sign_in() {
    let f = server(|options| {
        options.passwordless_email = Some(true);
        options.require_email_verification = Some(false);
    })
    .await;
    member(&f, "carol").await;
    let earlier = session(sign_in(&f, "carol").await.unwrap());
    f.auth
        .start_passwordless(&json!({ "tenantId": "org", "destination": "carol@acme.test", "channel": "email", "kind": "code" }))
        .await
        .unwrap();
    f.auth.dispatch_outbox(None).await.unwrap();
    let value = f.inbox.last("code").payload["token"]
        .as_str()
        .unwrap()
        .to_owned();
    f.auth
        .finish_passwordless(
            &json!({ "tenantId": "org", "destination": "carol@acme.test", "token": value }),
        )
        .await
        .unwrap();
    assert_eq!(
        f.auth
            .authenticate(&token(&earlier.token))
            .await
            .unwrap()
            .identity
            .email
            .as_deref(),
        Some("carol@acme.test")
    );
    assert!(sign_in(&f, "carol").await.unwrap().session().is_some());
}

#[tokio::test]
async fn mailed_links_are_bound_to_the_address_they_were_sent_to() {
    let f = server(|_| {}).await;
    let alice = member(&f, "alice").await;
    let auth = f.auth.clone();
    let stored = alice.clone();
    better_iam_core::IamStoreExt::transaction(f.store.as_ref(), |tx| async move {
        auth.issue_password_reset(&tx, &stored).await
    })
    .await
    .unwrap();
    f.auth.dispatch_outbox(None).await.unwrap();
    let reset = f.inbox.last("password-reset").payload["token"]
        .as_str()
        .unwrap()
        .to_owned();
    f.patch(
        "identities",
        &alice.id,
        json!({ "email": "alice.new@acme.test" }),
    )
    .await;
    assert_eq!(
        code(
            f.auth
                .reset_password(&json!({ "tenantId": "org", "token": reset, "password": "a brand new alice password" }))
                .await
        ),
        "INVALID_CHALLENGE"
    );
}

#[tokio::test]
async fn answers_passkey_sign_in_starts_alike_for_unknown_addresses_and_accounts_without_passkeys()
{
    let f = server(|options| {
        options.passkeys = Some(PasskeyOptions {
            rp_id: "localhost".to_owned(),
            rp_name: Some("IAM".to_owned()),
        });
    })
    .await;
    member(&f, "alice").await;
    let begin = |email: &str| {
        let body = json!({ "tenantId": "org", "email": email });
        let auth = f.auth.clone();
        async move { auth.begin_passkey_authentication(&body).await.unwrap() }
    };
    let known = begin("alice@acme.test").await;
    let unknown = begin("nobody@acme.test").await;
    for answer in [&known, &unknown] {
        assert_eq!(
            answer.options["allowCredentials"].as_array().unwrap().len(),
            1
        );
        assert!(!answer.challenge_id.is_empty());
    }
    assert_eq!(
        begin("nobody@acme.test").await.options["allowCredentials"],
        unknown.options["allowCredentials"]
    );
}

#[tokio::test]
async fn refuses_an_expired_password_once_verified_so_fresh_sessions_cannot_dodge_password_max_age_days()
 {
    let f = server(|options| {
        options.session_lifetime_ms = Some(7.0 * DAY);
        options.session_idle_timeout_ms = Some(7.0 * DAY);
    })
    .await;
    f.set_policy("org", Some(json!({ "passwordMaxAgeDays": 30 })))
        .await;
    member(&f, "alice").await;
    f.clock.advance(29.0 * DAY);
    let first = session(sign_in(&f, "alice").await.unwrap());
    let renewed = session(
        f.auth
            .reauthenticate(
                &token(&first.token),
                &json!({ "password": "a strong alice password" }),
            )
            .await
            .unwrap(),
    );
    f.clock.advance(2.0 * DAY);
    assert_eq!(
        code(
            f.auth
                .reauthenticate(
                    &token(&renewed.token),
                    &json!({ "password": "wrong password!!" })
                )
                .await
        ),
        "INVALID_CREDENTIALS"
    );
    assert_eq!(
        code(
            f.auth
                .reauthenticate(
                    &token(&renewed.token),
                    &json!({ "password": "a strong alice password" })
                )
                .await
        ),
        "PASSWORD_EXPIRED"
    );
}

#[tokio::test]
async fn refuses_sign_in_and_session_resolution_past_expires_at_before_the_purge_worker_runs() {
    let f = server(|_| {}).await;
    let alice = member(&f, "alice").await;
    f.patch(
        "identities",
        &alice.id,
        json!({ "expiresAt": f.clock.now() + DAY }),
    )
    .await;
    let signed_in = session(sign_in(&f, "alice").await.unwrap());
    assert_eq!(
        f.auth
            .authenticate(&token(&signed_in.token))
            .await
            .unwrap()
            .identity
            .id,
        alice.id
    );
    f.clock.advance(DAY + 1.0);
    assert_eq!(
        f.get("identities", &alice.id).await.unwrap()["status"],
        "active"
    );
    assert_eq!(
        code(f.auth.authenticate(&token(&signed_in.token)).await),
        "UNAUTHENTICATED"
    );
    assert_eq!(
        code(f.auth.get_session(&token(&signed_in.token)).await),
        "UNAUTHENTICATED"
    );
    assert_eq!(code(sign_in(&f, "alice").await), "INVALID_CREDENTIALS");
    let sessions = f.find("sessions", json!({ "identityId": alice.id })).await;
    assert!(
        sessions
            .iter()
            .all(|row| row["id"] == signed_in.session.id.as_str())
    );
    f.auth.settle_bookkeeping().await;
    assert!(f.failures("org", &alice.id).await.is_empty());
}

#[tokio::test]
async fn lets_a_remembered_browser_skip_mfa_within_the_policy_window_and_forgets_it_on_revocation_or_credential_change()
 {
    let f = server(|options| {
        options.session_lifetime_ms = Some(7.0 * DAY);
        options.session_idle_timeout_ms = Some(DAY);
    })
    .await;
    member(&f, "alice").await;
    let first = session(sign_in(&f, "alice").await.unwrap());
    let (secret, _) = enroll(&f, &first.token).await;
    let alice_sign_in = |device: Option<&str>| {
        let mut body = json!({ "tenantId": "org", "email": "alice@acme.test", "password": "a strong alice password" });
        if let Some(device) = device {
            body["deviceToken"] = json!(device);
        }
        let auth = f.auth.clone();
        async move { auth.sign_in(&body).await.unwrap() }
    };
    let verify = |challenge: String, remember: bool| {
        f.clock.advance(30_000.0);
        let body = json!({ "tenantId": "org", "challenge": challenge, "code": f.totp(&secret), "rememberDevice": remember });
        let auth = f.auth.clone();
        async move { auth.verify_mfa(&body).await.unwrap() }
    };
    let challenge = alice_sign_in(None)
        .await
        .mfa()
        .expect("Alice must require MFA")
        .challenge
        .clone();
    let remembered = verify(challenge, true).await;
    let device_token = remembered.device_token.clone().expect("device token");
    assert!(device_token.len() >= 32);
    assert_eq!(
        remembered.device_expires_at,
        Some(f.clock.now() + 30.0 * DAY)
    );
    assert!(remembered.session.trusted_device_id.is_none());
    let quick = session(alice_sign_in(Some(&device_token)).await);
    assert!(quick.session.mfa);
    assert_eq!(
        quick.session.method.map(|method| method.as_str()),
        Some("password")
    );
    let devices = f
        .auth
        .list_trusted_devices(&token(&quick.token))
        .await
        .unwrap();
    assert_eq!(devices.len(), 1);
    assert_eq!(
        quick.session.trusted_device_id.as_deref(),
        Some(devices[0].id.as_str())
    );
    assert_eq!(devices[0].last_used_at, f.clock.now());
    assert!(
        !serde_json::to_string(&devices)
            .unwrap()
            .contains("tokenHash")
    );
    for candidate in [
        "nonsense".to_owned(),
        format!("{device_token}x"),
        "a".repeat(40),
    ] {
        assert!(alice_sign_in(Some(&candidate)).await.mfa().is_some());
    }
    f.set_policy("org", Some(json!({ "trustedDeviceDays": 7 })))
        .await;
    let challenge = alice_sign_in(Some(&"x".repeat(40)))
        .await
        .mfa()
        .unwrap()
        .challenge
        .clone();
    let again = verify(challenge, true).await;
    assert_eq!(again.device_expires_at, Some(f.clock.now() + 7.0 * DAY));
    assert_eq!(
        f.auth
            .list_trusted_devices(&token(&again.token))
            .await
            .unwrap()
            .len(),
        2
    );
    f.set_policy("org", Some(json!({ "trustedDeviceDays": 0 })))
        .await;
    assert!(alice_sign_in(Some(&device_token)).await.mfa().is_some());
    let challenge = alice_sign_in(None).await.mfa().unwrap().challenge.clone();
    assert!(verify(challenge, true).await.device_token.is_none());
    f.set_policy("org", None).await;
    f.clock.advance(8.0 * DAY);
    assert!(
        alice_sign_in(again.device_token.as_deref())
            .await
            .mfa()
            .is_some()
    );
    let still = session(alice_sign_in(Some(&device_token)).await);
    assert_eq!(
        f.auth
            .list_trusted_devices(&token(&still.token))
            .await
            .unwrap()
            .len(),
        1
    );
    f.clock.advance(6.0 * 60_000.0);
    let devices = f
        .auth
        .list_trusted_devices(&token(&still.token))
        .await
        .unwrap();
    let device_id = devices[0].id.clone();
    assert_eq!(
        code(
            f.auth
                .revoke_trusted_device(&token(&still.token), &json!({ "deviceId": device_id }))
                .await
        ),
        "RECENT_AUTH_REQUIRED"
    );
    let fresh = session(alice_sign_in(Some(&device_token)).await);
    f.auth
        .revoke_trusted_device(&token(&fresh.token), &json!({ "deviceId": device_id }))
        .await
        .unwrap();
    assert!(alice_sign_in(Some(&device_token)).await.mfa().is_some());
    let challenge = alice_sign_in(None).await.mfa().unwrap().challenge.clone();
    let before = verify(challenge, true).await;
    let before_device = before.device_token.clone().unwrap();
    f.auth
        .change_password(
            &token(&before.token),
            &json!({ "currentPassword": "a strong alice password", "password": "a brand new alice password!" }),
        )
        .await
        .unwrap();
    let after = f
        .auth
        .sign_in(&json!({
            "tenantId": "org", "email": "alice@acme.test", "password": "a brand new alice password!",
            "deviceToken": before_device,
        }))
        .await
        .unwrap();
    assert!(after.mfa().is_some());
    let trail: Vec<String> = f
        .find("audit", json!({ "tenantId": "org" }))
        .await
        .into_iter()
        .map(|event| event["action"].as_str().unwrap().to_owned())
        .collect();
    assert!(trail.contains(&"auth:device:trust".to_owned()));
    assert!(trail.contains(&"auth:device:revoke".to_owned()));
}

#[tokio::test]
async fn the_deployment_can_switch_remembered_devices_off_and_rejects_nonsense_lifetimes() {
    let f = server(|options| options.trusted_device_lifetime_ms = Some(0.0)).await;
    member(&f, "alice").await;
    let first = session(sign_in(&f, "alice").await.unwrap());
    let (secret, _) = enroll(&f, &first.token).await;
    let challenge = sign_in(&f, "alice")
        .await
        .unwrap()
        .mfa()
        .unwrap()
        .challenge
        .clone();
    f.clock.advance(30_000.0);
    let verified = f
        .auth
        .verify_mfa(&json!({ "tenantId": "org", "challenge": challenge, "code": f.totp(&secret), "rememberDevice": true }))
        .await
        .unwrap();
    assert!(verified.device_token.is_none());
    let mut options = better_iam_auth::AuthOptions::new(
        f.store.clone(),
        "trusted-devices-test-secret-with-32-chars!!",
        "http://localhost:3000",
    );
    options.trusted_device_lifetime_ms = Some(1000.0);
    assert!(
        better_iam_auth::create_auth(options)
            .err()
            .unwrap()
            .message
            .contains("Trusted device lifetime")
    );
}

#[tokio::test]
async fn records_client_details_and_signs_out_every_other_session_with_recent_authentication() {
    let f = server(|_| {}).await;
    member(&f, "alice").await;
    let laptop = session(
        f.sign_in_from(
            Some(client(
                Some("203.0.113.7"),
                Some("Mozilla/5.0 (Macintosh)"),
                Some("Laptop\u{0007} "),
            )),
            "org",
            "alice@acme.test",
            "a strong alice password",
        )
        .await
        .unwrap(),
    );
    let recorded = laptop.session.client.clone().unwrap();
    assert_eq!(recorded.ip.as_deref(), Some("203.0.113.7"));
    assert_eq!(recorded.label.as_deref(), Some("Laptop"));
    let phone = session(sign_in(&f, "alice").await.unwrap());
    let other = session(sign_in(&f, "alice").await.unwrap());
    let listed = f.auth.list_sessions(&token(&phone.token)).await.unwrap();
    assert_eq!(listed.len(), 3);
    assert_eq!(listed.iter().filter(|item| item.current).count(), 1);
    f.clock.advance(6.0 * 60_000.0);
    assert_eq!(
        code(f.auth.revoke_other_sessions(&token(&phone.token)).await),
        "RECENT_AUTH_REQUIRED"
    );
    let fresh = session(sign_in(&f, "alice").await.unwrap());
    let revoked = f
        .auth
        .revoke_other_sessions(&token(&fresh.token))
        .await
        .unwrap();
    assert_eq!(revoked.revoked, 3);
    for gone in [&laptop, &phone, &other] {
        assert_eq!(
            code(f.auth.authenticate(&token(&gone.token)).await),
            "UNAUTHENTICATED"
        );
    }
    assert_eq!(
        f.auth
            .list_sessions(&token(&fresh.token))
            .await
            .unwrap()
            .len(),
        1
    );
    f.auth.sign_out(&token(&fresh.token)).await.unwrap();
    assert_eq!(
        code(f.auth.authenticate(&token(&fresh.token)).await),
        "UNAUTHENTICATED"
    );
}
