//! Port of `tests/auth.test.ts`.

mod support;

use better_iam_auth::service::mfa::ConfirmMfaInput;
use better_iam_auth::types::{MfaCredential, SignInResult};
use better_iam_auth::{AuthOptions, create_auth, decrypt_secret, encrypt_secret};
use better_iam_core::{IamStoreExt, Identity, Tenant, TenantStatus, record};
use serde_json::{Value, json};
use support::*;

const DAY: f64 = 24.0 * 60.0 * 60_000.0;

mod tenant_authentication_and_session_revocation {
    use super::*;

    #[tokio::test]
    async fn keeps_identical_email_addresses_separate_across_tenants_and_rejects_forged_tenant_headers()
     {
        let f = fixture().await;
        let first = f.identity("org", false, None).await;
        let second = f.identity("sibling", false, None).await;
        let login = session(
            f.sign_in("org", "SAME@example.com", PASSWORD)
                .await
                .unwrap(),
        );
        let mut credential = token(&login.token);
        credential.headers = Some(vec![("x-tenant-id".to_owned(), "sibling".to_owned())]);
        let principal = f.auth.authenticate(&credential).await.unwrap();
        assert_eq!(principal.identity.id, first.id);
        assert_ne!(principal.identity.id, second.id);
        assert_eq!(principal.identity.tenant_id, "org");
        let info =
            serde_json::to_value(f.auth.get_session(&token(&login.token)).await.unwrap()).unwrap();
        assert!(info["identity"].get("passwordHash").is_none());
        let sessions =
            serde_json::to_value(f.auth.list_sessions(&token(&login.token)).await.unwrap())
                .unwrap();
        assert!(sessions[0].get("tokenHash").is_none());
        assert!(sessions[0].get("uniqueKey").is_none());
        let stored = f.get("identities", &first.id).await.unwrap();
        assert!(
            stored["passwordHash"]
                .as_str()
                .unwrap()
                .starts_with("$argon2id$")
        );
    }

    #[tokio::test]
    async fn checks_current_ancestor_status_and_session_expiry_on_each_use() {
        let f = fixture().await;
        f.identity("project", false, None).await;
        let login = session(
            f.sign_in("project", "same@example.com", PASSWORD)
                .await
                .unwrap(),
        );
        let set_status = |status: TenantStatus| {
            let store = f.store.clone();
            async move {
                store
                    .transaction(|tx| async move {
                        let mut parent: Tenant = serde_json::from_value(Value::Object(
                            tx.get("tenants", "org").await?.unwrap(),
                        ))
                        .unwrap();
                        parent.status = status;
                        tx.put("tenants", &record(serde_json::to_value(&parent).unwrap()))
                            .await?;
                        Ok(())
                    })
                    .await
                    .unwrap();
            }
        };
        set_status(TenantStatus::Suspended).await;
        assert_eq!(
            code(f.auth.authenticate(&token(&login.token)).await),
            "TENANT_UNAVAILABLE"
        );
        set_status(TenantStatus::Active).await;
        f.clock.advance(8.0 * DAY);
        assert_eq!(
            code(f.auth.authenticate(&token(&login.token)).await),
            "UNAUTHENTICATED"
        );
    }

    #[tokio::test]
    async fn uses_host_prefixed_https_cookies_and_applies_the_same_idle_checks_to_persisted_protocol_session_ids()
     {
        let f = fixture().await;
        f.identity("org", false, None).await;
        let login = f.session("org").await;
        let plain = format!("better-iam.session={}", login.token);
        assert_eq!(
            code(f.auth.authenticate(&headers(&[("cookie", &plain)])).await),
            "UNAUTHENTICATED"
        );
        let prefixed = format!("__Host-better-iam.session={}", login.token);
        assert_eq!(
            f.auth
                .authenticate(&headers(&[("cookie", &prefixed)]))
                .await
                .unwrap()
                .session
                .id,
            login.session.id
        );
        f.clock.advance(23.0 * 60.0 * 60_000.0);
        assert_eq!(
            f.auth
                .validate_session_id(&login.session.id)
                .await
                .unwrap()
                .session
                .last_seen_at,
            f.clock.now()
        );
        f.clock.advance(DAY);
        assert_eq!(
            code(f.auth.validate_session_id(&login.session.id).await),
            "UNAUTHENTICATED"
        );
        assert_eq!(
            code(f.auth.authenticate(&token(&login.token)).await),
            "UNAUTHENTICATED"
        );
    }

    #[tokio::test]
    async fn persists_failed_login_rate_limits_outside_failed_transactions() {
        let f = fixture().await;
        for _ in 0..10 {
            assert_eq!(
                code(f.sign_in("org", "unknown@example.com", PASSWORD).await),
                "INVALID_CREDENTIALS"
            );
        }
        let limited = f
            .sign_in("org", "unknown@example.com", PASSWORD)
            .await
            .unwrap_err();
        assert_eq!(limited.code, "RATE_LIMITED");
        assert_eq!(limited.status, 429);
        // `Object.assign(error, { retryAfterMs: windowMs })`: the refusal itself carries the window.
        assert_eq!(
            limited
                .details
                .as_ref()
                .and_then(|details| details.retry_after_ms),
            Some(f.auth.rate_limit_window_ms())
        );
        f.clock.advance(16.0 * 60_000.0);
        assert_eq!(
            code(f.sign_in("org", "unknown@example.com", PASSWORD).await),
            "INVALID_CREDENTIALS"
        );
    }

    #[tokio::test]
    async fn requires_verified_email_by_default_for_signup_and_consumes_verification_once() {
        let f = fixture().await;
        let result = f
            .auth
            .sign_up(&json!({ "tenantId": "org", "email": "new@example.com", "name": "New", "password": PASSWORD }))
            .await
            .unwrap();
        assert!(result.verification_required);
        assert!(
            serde_json::to_value(&result).unwrap()["identity"]
                .get("passwordHash")
                .is_none()
        );
        assert_eq!(
            code(f.sign_in("org", "new@example.com", PASSWORD).await),
            "EMAIL_UNVERIFIED"
        );
        let stored = serde_json::to_string(&f.all("outbox").await).unwrap();
        assert!(!stored.contains("\"token\":"));
        let dispatched = f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(
            (
                dispatched.delivered,
                dispatched.failed,
                dispatched.abandoned
            ),
            (1, 0, 0)
        );
        let verification = f.inbox.token(0);
        assert_eq!(
            code(
                f.auth
                    .verify_email(&json!({ "tenantId": "sibling", "token": verification }))
                    .await
            ),
            "INVALID_CHALLENGE"
        );
        let input = json!({ "tenantId": "org", "token": verification });
        let (a, b) = tokio::join!(f.auth.verify_email(&input), f.auth.verify_email(&input));
        assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
        assert!(
            !session(f.sign_in("org", "new@example.com", PASSWORD).await.unwrap())
                .token
                .is_empty()
        );
        assert_eq!(f.all("outbox").await[0]["payload"], json!({}));
        assert_eq!(
            code(
                f.auth
                    .sign_up(&json!({ "tenantId": "root", "email": "bad@example.com", "name": "Bad", "password": PASSWORD }))
                    .await
            ),
            "FORBIDDEN"
        );
    }

    #[tokio::test]
    async fn revokes_sessions_immediately_after_password_changes_and_enforces_recent_authentication()
     {
        let f = fixture().await;
        f.identity("org", false, None).await;
        let login = f.session("org").await;
        f.clock.advance(6.0 * 60_000.0);
        let change = json!({ "currentPassword": PASSWORD, "password": "replacement-password" });
        assert_eq!(
            code(f.auth.change_password(&token(&login.token), &change).await),
            "RECENT_AUTH_REQUIRED"
        );
        let fresh = session(
            f.auth
                .reauthenticate(&token(&login.token), &json!({ "password": PASSWORD }))
                .await
                .unwrap(),
        );
        f.auth
            .change_password(&token(&fresh.token), &change)
            .await
            .unwrap();
        assert_eq!(
            code(f.auth.authenticate(&token(&login.token)).await),
            "UNAUTHENTICATED"
        );
        assert_eq!(
            code(f.auth.authenticate(&token(&fresh.token)).await),
            "UNAUTHENTICATED"
        );
        assert!(
            !session(
                f.sign_in("org", "same@example.com", "replacement-password")
                    .await
                    .unwrap()
            )
            .token
            .is_empty()
        );
    }
}

fn challenge_of(result: &SignInResult) -> String {
    result.mfa().expect("Expected MFA").challenge.clone()
}

mod mfa_enrollment_challenges_and_account_recovery {
    use super::*;

    #[tokio::test]
    async fn allows_root_mfa_enrollment_from_a_restricted_challenge_rejects_replay_and_keeps_mfa_after_password_recovery()
     {
        let f = fixture().await;
        let root = f.identity("root", true, None).await;
        let login = f
            .sign_in("root", "same@example.com", PASSWORD)
            .await
            .unwrap();
        let mfa = login.mfa().expect("Expected MFA");
        assert!(mfa.enrollment_required);
        assert_eq!(
            code(f.auth.authenticate(&token(&mfa.challenge)).await),
            "UNAUTHENTICATED"
        );
        let credential = MfaCredential::Challenge {
            tenant_id: "root".to_owned(),
            challenge: mfa.challenge.clone(),
        };
        let enrollment = f.auth.begin_mfa(&credential).await.unwrap();
        let stored = serde_json::to_string(&f.get("authMfa", &root.id).await.unwrap()).unwrap();
        assert!(!stored.contains(&enrollment.secret));
        let verified = f
            .auth
            .confirm_mfa(&ConfirmMfaInput {
                credential,
                code: f.totp(&enrollment.secret),
                remember_device: false,
            })
            .await
            .unwrap();
        assert_eq!(verified.recovery_codes.len(), 10);
        assert!(
            f.auth
                .authenticate(&token(&verified.token))
                .await
                .unwrap()
                .session
                .mfa
        );
        let next = challenge_of(
            &f.sign_in("root", "same@example.com", PASSWORD)
                .await
                .unwrap(),
        );
        assert_eq!(
            code(
                f.auth
                    .begin_mfa(&MfaCredential::Challenge {
                        tenant_id: "root".to_owned(),
                        challenge: next.clone(),
                    })
                    .await
            ),
            "MFA_REQUIRED"
        );
        let verify = |code: String| json!({ "tenantId": "root", "challenge": next, "code": code });
        assert_eq!(
            code(f.auth.verify_mfa(&verify(f.totp(&enrollment.secret))).await),
            "INVALID_MFA"
        );
        f.clock.advance(30_000.0);
        f.auth
            .verify_mfa(&verify(f.totp(&enrollment.secret)))
            .await
            .unwrap();
        assert_eq!(
            code(f.auth.verify_mfa(&verify(f.totp(&enrollment.secret))).await),
            "INVALID_CHALLENGE"
        );
        f.auth
            .request_password_reset(&json!({ "tenantId": "root", "email": "same@example.com" }))
            .await
            .unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        let reset = f.inbox.last("password-reset").payload["token"]
            .as_str()
            .unwrap()
            .to_owned();
        f.auth
            .reset_password(
                &json!({ "tenantId": "root", "token": reset, "password": "replacement-password" }),
            )
            .await
            .unwrap();
        assert_eq!(
            code(f.auth.authenticate(&token(&verified.token)).await),
            "UNAUTHENTICATED"
        );
        let after = f
            .sign_in("root", "same@example.com", "replacement-password")
            .await
            .unwrap();
        let after = after.mfa().expect("Expected MFA");
        assert!(!after.enrollment_required);
    }

    #[tokio::test]
    async fn accepts_each_mfa_recovery_code_only_once_even_across_simultaneous_login_challenges() {
        let f = fixture().await;
        f.identity("org", false, None).await;
        let login = f.session("org").await;
        let credential = MfaCredential::Credential(token(&login.token));
        let enrollment = f.auth.begin_mfa(&credential).await.unwrap();
        let enabled = f
            .auth
            .confirm_mfa(&ConfirmMfaInput {
                credential,
                code: f.totp(&enrollment.secret),
                remember_device: false,
            })
            .await
            .unwrap();
        let first = challenge_of(
            &f.sign_in("org", "same@example.com", PASSWORD)
                .await
                .unwrap(),
        );
        let second = challenge_of(
            &f.sign_in("org", "same@example.com", PASSWORD)
                .await
                .unwrap(),
        );
        let recover = |challenge: &str| json!({ "tenantId": "org", "challenge": challenge, "code": enabled.recovery_codes[0] });
        let (first, second) = (recover(&first), recover(&second));
        let (a, b) = tokio::join!(f.auth.recover_mfa(&first), f.auth.recover_mfa(&second));
        assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
        let stored = serde_json::to_string(&f.all("authMfa").await).unwrap();
        assert!(!stored.contains(&enabled.recovery_codes[0]));
    }

    #[tokio::test]
    async fn rotates_recovery_codes_atomically_and_prohibits_disabling_root_mfa() {
        let f = fixture().await;
        f.identity("root", true, None).await;
        let challenge = challenge_of(
            &f.sign_in("root", "same@example.com", PASSWORD)
                .await
                .unwrap(),
        );
        let credential = MfaCredential::Challenge {
            tenant_id: "root".to_owned(),
            challenge,
        };
        let enrollment = f.auth.begin_mfa(&credential).await.unwrap();
        let enabled = f
            .auth
            .confirm_mfa(&ConfirmMfaInput {
                credential,
                code: f.totp(&enrollment.secret),
                remember_device: false,
            })
            .await
            .unwrap();
        let rotated = f
            .auth
            .regenerate_recovery_codes(&token(&enabled.token))
            .await
            .unwrap();
        assert_eq!(rotated.recovery_codes.len(), 10);
        assert!(!rotated.recovery_codes.contains(&enabled.recovery_codes[0]));
        assert_eq!(
            code(f.auth.disable_mfa(&token(&enabled.token)).await),
            "MFA_REQUIRED"
        );
        let again = challenge_of(
            &f.sign_in("root", "same@example.com", PASSWORD)
                .await
                .unwrap(),
        );
        assert_eq!(
            code(
                f.auth
                    .recover_mfa(&json!({ "tenantId": "root", "challenge": again, "code": enabled.recovery_codes[0] }))
                    .await
            ),
            "INVALID_MFA"
        );
        f.auth
            .recover_mfa(&json!({ "tenantId": "root", "challenge": again, "code": rotated.recovery_codes[0] }))
            .await
            .unwrap();
    }
}

mod passwordless_and_delivery {
    use super::*;

    #[tokio::test]
    async fn delivers_encrypted_outbox_messages_with_deduplication_identifiers_and_verifies_passwordless_codes_once()
     {
        let f = fixture().await;
        f.identity("org", false, None).await;
        f.auth
            .start_passwordless(&json!({
                "tenantId": "org", "destination": "same@example.com", "channel": "email", "kind": "code"
            }))
            .await
            .unwrap();
        let sealed = serde_json::to_string(&f.all("outbox").await).unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        let code_value = f.inbox.token(0);
        assert!(!sealed.contains(&format!("\"{code_value}\"")));
        assert_eq!(
            code(
                f.auth
                    .finish_passwordless(&json!({ "tenantId": "sibling", "destination": "same@example.com", "token": code_value }))
                    .await
            ),
            "INVALID_CHALLENGE"
        );
        assert_eq!(
            code(
                f.auth
                    .finish_passwordless(&json!({ "tenantId": "org", "destination": "other@example.com", "token": code_value }))
                    .await
            ),
            "INVALID_CHALLENGE"
        );
        let input =
            json!({ "tenantId": "org", "destination": "same@example.com", "token": code_value });
        let (a, b) = tokio::join!(
            f.auth.finish_passwordless(&input),
            f.auth.finish_passwordless(&input)
        );
        assert_eq!([a.is_ok(), b.is_ok()].iter().filter(|ok| **ok).count(), 1);
        let dispatched = f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(
            (
                dispatched.delivered,
                dispatched.failed,
                dispatched.abandoned
            ),
            (0, 0, 0)
        );
    }

    #[tokio::test]
    async fn requires_verified_phone_ownership_before_sms_login() {
        let f = fixture().await;
        f.identity("org", false, None).await;
        let login = f.session("org").await;
        let start = json!({ "tenantId": "org", "destination": "+15551234567", "channel": "sms", "kind": "code" });
        f.auth.start_passwordless(&start).await.unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        assert_eq!(f.inbox.len(), 0);
        f.auth
            .start_phone_verification(&token(&login.token), &json!({ "phone": "+15551234567" }))
            .await
            .unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        f.auth
            .confirm_phone_verification(
                &token(&login.token),
                &json!({ "phone": "+15551234567", "code": f.inbox.token(0) }),
            )
            .await
            .unwrap();
        f.auth.start_passwordless(&start).await.unwrap();
        f.auth.dispatch_outbox(None).await.unwrap();
        let finished = f
            .auth
            .finish_passwordless(&json!({ "tenantId": "org", "destination": "+15551234567", "token": f.inbox.token(1) }))
            .await
            .unwrap();
        assert!(!session(finished).token.is_empty());
    }

    #[tokio::test]
    async fn binds_sealed_values_to_their_purpose_and_validates_enabled_feature_configuration() {
        let f = fixture().await;
        let sealed = encrypt_secret("private value", SECRET, "tenant:a");
        assert_eq!(
            decrypt_secret(&sealed, &[SECRET], "tenant:a").unwrap(),
            "private value"
        );
        assert!(decrypt_secret(&sealed, &[SECRET], "tenant:b").is_err());
        let mut options = AuthOptions::new(f.store.clone(), SECRET, "https://iam.example.com");
        options.sign_up_enabled = Some(true);
        assert!(
            create_auth(options)
                .err()
                .unwrap()
                .message
                .contains("sendEmail")
        );
        let mut options = AuthOptions::new(f.store.clone(), SECRET, "https://iam.example.com");
        options.passwordless_sms = Some(true);
        assert!(
            create_auth(options)
                .err()
                .unwrap()
                .message
                .contains("sendSms")
        );
    }
}

#[tokio::test]
async fn registers_and_authenticates_real_passkey_assertions_while_rejecting_wrong_tenant_origin_and_replay()
 {
    let f = fixture().await;
    let user: Identity = f.identity("org", false, None).await;
    let login = f.session("org").await;
    let registration = f
        .auth
        .begin_passkey_registration(&token(&login.token))
        .await
        .unwrap();
    let mut authenticator = VirtualAuthenticator::new("iam.example.com", "https://iam.example.com");
    let response = authenticator.register(registration.options["challenge"].as_str().unwrap());
    f.auth
        .finish_passkey_registration(
            &token(&login.token),
            &json!({ "challengeId": registration.challenge_id, "response": response }),
        )
        .await
        .unwrap();
    let authentication = f
        .auth
        .begin_passkey_authentication(&json!({ "tenantId": "org", "email": "same@example.com" }))
        .await
        .unwrap();
    let challenge = authentication.options["challenge"]
        .as_str()
        .unwrap()
        .to_owned();
    let assertion = authenticator.assert_with(&challenge, &user.id, None, 1, 0x05);
    let finish = |tenant: &str, response: &Value| json!({ "tenantId": tenant, "challengeId": authentication.challenge_id, "response": response });
    assert_eq!(
        code(
            f.auth
                .finish_passkey_authentication(&finish("sibling", &assertion))
                .await
        ),
        "INVALID_CHALLENGE"
    );
    let wrong_origin = authenticator.assert_with(
        &challenge,
        &user.id,
        Some("https://attacker.example"),
        1,
        0x05,
    );
    assert!(
        f.auth
            .finish_passkey_authentication(&finish("org", &wrong_origin))
            .await
            .is_err()
    );
    let authenticated = f
        .auth
        .finish_passkey_authentication(&finish("org", &assertion))
        .await
        .unwrap();
    assert!(
        f.auth
            .authenticate(&token(&authenticated.token))
            .await
            .unwrap()
            .session
            .mfa
    );
    assert_eq!(
        code(
            f.auth
                .finish_passkey_authentication(&finish("org", &assertion))
                .await
        ),
        "INVALID_CHALLENGE"
    );
    let keys = f
        .auth
        .list_passkeys(&token(&authenticated.token))
        .await
        .unwrap();
    assert_eq!(keys.len(), 1);
    f.auth
        .delete_passkey(&token(&authenticated.token), &json!({ "id": keys[0].id }))
        .await
        .unwrap();
    assert_eq!(
        code(f.auth.authenticate(&token(&authenticated.token)).await),
        "UNAUTHENTICATED"
    );
    let _ = &mut authenticator;
}
