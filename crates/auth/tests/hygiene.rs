//! Port of `tests/auth-session-hygiene.test.ts` (the authentication-service parts: sign-in results, prefixed
//! tokens, `requireRecent`, `verifyStepUpCode`, `limitAttempt`, `mfaAuthenticatedAt`). Role sessions, API keys and
//! the server's session-kind helpers are exercised with the server port.

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::service::LimitAttemptOptions;
use better_iam_auth::service::base::RateTier;
use better_iam_auth::{
    CREDENTIAL_TOKEN_KINDS, CREDENTIAL_TOKEN_SCAN_PATTERN, hash_token, new_credential_token_named,
    parse_credential_token,
};
use better_iam_core::{
    AuthenticatedPrincipal, IamStore, IamStoreExt, Identity, SessionKind, instrument_store, record,
};
use serde_json::{Value, json};
use support::*;

const DAY: f64 = 86_400_000.0;

fn no_secret_fields(value: &impl serde::Serialize) {
    let text = serde_json::to_string(value).unwrap();
    assert!(!text.contains("tokenHash"), "{text}");
    assert!(!text.contains("uniqueKey"), "{text}");
}

fn user_token(token: &str) -> bool {
    token.len() == 58
        && token.starts_with("biam_ses_")
        && token[9..]
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || c == b'_' || c == b'-')
}

async fn stored_session(f: &Fixture, token: &str) -> better_iam_core::Record {
    let mut rows = f
        .find("sessions", json!({ "tokenHash": hash_token(token) }))
        .await;
    assert_eq!(rows.len(), 1);
    rows.remove(0)
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

async fn member_sign_in(f: &Fixture, name: &str) -> better_iam_auth::SignInResult {
    f.sign_in(
        "org",
        &format!("{name}@acme.test"),
        &format!("a strong {name} password"),
    )
    .await
    .unwrap()
}

#[tokio::test]
async fn sign_in_results_never_carry_token_hash_or_unique_key() {
    let f = server(|_| {}).await;
    member(&f, "alice").await;
    let signed_in = session(member_sign_in(&f, "alice").await);
    assert!(signed_in.session.id.starts_with("ses_"));
    no_secret_fields(&signed_in);
    member(&f, "bob").await;
    let first = session(member_sign_in(&f, "bob").await);
    let (secret, confirmed) = enroll(&f, &first.token).await;
    assert!(confirmed.session.mfa);
    no_secret_fields(&confirmed);
    let challenge = member_sign_in(&f, "bob")
        .await
        .mfa()
        .expect("Bob must require MFA")
        .challenge
        .clone();
    f.clock.advance(30_000.0);
    let verified = f
        .auth
        .verify_mfa(&json!({ "tenantId": "org", "challenge": challenge, "code": f.totp(&secret) }))
        .await
        .unwrap();
    assert!(verified.session.mfa);
    no_secret_fields(&verified);
    no_secret_fields(&f.auth.list_sessions(&token(&verified.token)).await.unwrap());
}

#[tokio::test]
async fn issues_checksummed_biam_ses_tokens_that_parse() {
    let f = server(|_| {}).await;
    member(&f, "alice").await;
    let signed_in = session(member_sign_in(&f, "alice").await);
    assert!(user_token(&signed_in.token));
    assert_eq!(
        parse_credential_token(&signed_in.token).map(|kind| kind.as_str()),
        Some("ses")
    );
    let scan = regex_lookaround_free_scan(&format!("key={};", signed_in.token));
    assert_eq!(scan.as_deref(), Some(signed_in.token.as_str()));
    assert_eq!(
        f.auth
            .authenticate(&token(&signed_in.token))
            .await
            .unwrap()
            .session
            .kind,
        SessionKind::User
    );
}

/// `credentialTokenScanPattern` needs lookbehind, which the `regex` crate lacks; the pattern's documented fallback
/// with explicit boundary checks finds the same tokens.
fn regex_lookaround_free_scan(text: &str) -> Option<String> {
    assert!(CREDENTIAL_TOKEN_SCAN_PATTERN.starts_with("(?<![A-Za-z0-9_-])"));
    let pattern = regex::Regex::new("biam_(?:ses|key|rol|sts|dlg)_[A-Za-z0-9_-]{49}").unwrap();
    let boundary =
        |c: Option<char>| c.is_none_or(|c| !(c.is_ascii_alphanumeric() || c == '_' || c == '-'));
    pattern
        .find_iter(text)
        .find(|found| {
            boundary(text[..found.start()].chars().last())
                && boundary(text[found.end()..].chars().next())
        })
        .map(|found| found.as_str().to_owned())
}

#[test]
fn exposes_the_token_helpers_with_one_kind_per_type() {
    assert_eq!(
        CREDENTIAL_TOKEN_KINDS,
        [
            ("ses", "user"),
            ("key", "api-key"),
            ("rol", "role"),
            ("sts", "session-token"),
            ("dlg", "delegated")
        ]
    );
    for kind in ["ses", "key", "rol", "sts", "dlg"] {
        let token = new_credential_token_named(kind).unwrap();
        assert!(token.starts_with(&format!("biam_{kind}_")) && token.len() == 58);
        assert_eq!(
            parse_credential_token(&token).map(|kind| kind.as_str()),
            Some(kind)
        );
    }
    let token = new_credential_token_named("key").unwrap();
    for value in [
        token[..token.len() - 1].to_owned(),
        format!("{token}A"),
        token.replace("biam_key_", "biam_xyz_"),
        format!("biam_ses_{}", &token[9..52]),
        String::new(),
    ] {
        assert_eq!(parse_credential_token(&value), None, "{value}");
    }
}

#[tokio::test]
async fn refuses_a_token_with_a_bad_checksum_before_reading_storage() {
    let calls = Arc::new(AtomicUsize::new(0));
    let counter = calls.clone();
    let base = sqlite_adapter(SqliteAdapterOptions::new(":memory:")).unwrap();
    base.migrate().await.unwrap();
    let instrumented = instrument_store(
        base,
        Arc::new(move |_| {
            counter.fetch_add(1, Ordering::SeqCst);
        }),
        None,
    );
    let f = server(|options| options.store = instrumented.clone()).await;
    member(&f, "alice").await;
    let signed_in = session(member_sign_in(&f, "alice").await);
    let at = signed_in.token.len() - 6;
    let replaced = if &signed_in.token[at..at + 1] == "A" {
        "B"
    } else {
        "A"
    };
    let flipped = format!(
        "{}{}{}",
        &signed_in.token[..at],
        replaced,
        &signed_in.token[at + 1..]
    );
    assert_eq!(parse_credential_token(&flipped), None);
    calls.store(0, Ordering::SeqCst);
    let bearer = format!("Bearer {flipped}");
    let cookie = format!("better-iam.session={flipped}");
    for input in [
        token(&flipped),
        headers(&[("authorization", &bearer)]),
        headers(&[("cookie", &cookie)]),
    ] {
        let error = f.auth.authenticate(&input).await.unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status),
            ("UNAUTHENTICATED", 401)
        );
    }
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    f.auth.authenticate(&token(&signed_in.token)).await.unwrap();
    assert!(calls.load(Ordering::SeqCst) > 0);
}

#[tokio::test]
async fn keeps_legacy_unprefixed_user_tokens_working_until_they_expire() {
    let f = server(|_| {}).await;
    let owner = member(&f, "owner").await;
    let legacy = format!("{:x<43}", "legacy_user_token-");
    assert_eq!(legacy.len(), 43);
    let now = f.clock.now();
    let row = record(json!({
        "id": "ses_legacy_row", "tenantId": "org", "identityId": owner.id, "kind": "user",
        "tokenHash": hash_token(&legacy), "uniqueKey": hash_token(&legacy), "createdAt": now, "lastSeenAt": now,
        "expiresAt": now + DAY, "authenticatedAt": now, "mfa": false,
    }));
    f.store
        .transaction(|tx| async move { tx.insert("sessions", &row).await })
        .await
        .unwrap();
    assert_eq!(
        f.auth
            .authenticate(&token(&legacy))
            .await
            .unwrap()
            .session
            .id,
        "ses_legacy_row"
    );
    f.clock.advance(DAY);
    assert_eq!(
        code(f.auth.authenticate(&token(&legacy)).await),
        "UNAUTHENTICATED"
    );
}

#[tokio::test]
async fn require_recent_refuses_temporary_credentials_and_accepts_fresh_user_and_api_key_sessions()
{
    let f = server(|_| {}).await;
    member(&f, "owner").await;
    let owner = session(member_sign_in(&f, "owner").await);
    let user = f.auth.authenticate(&token(&owner.token)).await.unwrap();
    f.auth.require_recent(&user).unwrap();
    let with = |change: &dyn Fn(&mut AuthenticatedPrincipal)| {
        let mut principal = user.clone();
        change(&mut principal);
        principal
    };
    let key = with(&|principal| principal.session.kind = SessionKind::ApiKey);
    f.auth.require_recent(&key).unwrap();
    for (principal, expected) in [
        (
            with(&|principal| principal.session.kind = SessionKind::Role),
            "RECENT_AUTH_REQUIRED",
        ),
        (
            with(&|principal| principal.session.kind = SessionKind::SessionToken),
            "RECENT_AUTH_REQUIRED",
        ),
        (
            with(&|principal| principal.session.kind = SessionKind::Delegated),
            "RECENT_AUTH_REQUIRED",
        ),
        (
            with(&|principal| principal.session.source_session_id = Some("ses_source".to_owned())),
            "RECENT_AUTH_REQUIRED",
        ),
        (
            with(&|principal| {
                principal.session.kind = SessionKind::Role;
                principal.session.impersonator_id = Some("usr_admin".to_owned());
            }),
            "IMPERSONATION_RESTRICTED",
        ),
    ] {
        let error = f.auth.require_recent(&principal).unwrap_err();
        assert_eq!(error.code, expected);
        assert_eq!(error.status, 403);
        if principal.session.kind == SessionKind::Role && expected == "RECENT_AUTH_REQUIRED" {
            assert_eq!(
                error.message,
                "Temporary credentials cannot perform this operation; use a signed-in session"
            );
        }
    }
    f.clock.advance(5.0 * 60_000.0 + 1.0);
    assert_eq!(code(f.auth.require_recent(&user)), "RECENT_AUTH_REQUIRED");
}

#[tokio::test]
async fn verify_step_up_code_accepts_a_first_hand_totp_code_once_and_refuses_wrong_codes_and_missing_enrollment()
 {
    let f = server(|_| {}).await;
    let carol = member(&f, "carol").await;
    let first = session(member_sign_in(&f, "carol").await);
    let (secret, _) = enroll(&f, &first.token).await;
    let step_up = |subject_id: String, code: String| {
        let auth = f.auth.clone();
        let store = f.store.clone();
        async move {
            store
                .transaction(|tx| async move {
                    let current: Identity = serde_json::from_value(Value::Object(
                        tx.get("identities", &subject_id).await?.unwrap(),
                    ))
                    .unwrap();
                    auth.verify_step_up_code(&tx, &current, &code).await
                })
                .await
        }
    };
    f.clock.advance(30_000.0);
    let current = f.totp(&secret);
    assert_eq!(
        step_up(carol.id.clone(), current.clone())
            .await
            .unwrap()
            .verified_at,
        f.clock.now()
    );
    let replay = step_up(carol.id.clone(), current).await.unwrap_err();
    assert_eq!((replay.code.as_str(), replay.status), ("INVALID_MFA", 401));
    f.clock.advance(90_000.0);
    let valid = f.totp(&secret);
    let wrong = format!(
        "{:06}",
        (valid.parse::<u32>().unwrap() + 500_000) % 1_000_000
    );
    assert_eq!(code(step_up(carol.id.clone(), wrong).await), "INVALID_MFA");
    assert_eq!(
        code(step_up(carol.id.clone(), "abcdef".to_owned()).await),
        "INVALID_MFA"
    );
    let steps = f
        .find("audit", json!({ "tenantId": "org", "actorId": carol.id }))
        .await
        .into_iter()
        .filter(|event| event["action"] == "auth:mfa:step-up")
        .count();
    assert_eq!(steps, 1);
    let dave = member(&f, "dave").await;
    let error = step_up(dave.id.clone(), "123456".to_owned())
        .await
        .unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.status),
        ("MFA_NOT_ENROLLED", 403)
    );
    // A service identity, even with a planted copy of Carol's authenticator record.
    let robot = record(json!({
        "id": "svc_robot", "tenantId": "org", "kind": "service", "name": "robot", "status": "active",
        "emailVerified": false, "rootAdmin": false, "owner": false, "createdAt": f.clock.now(),
    }));
    f.store
        .transaction(|tx| async move { tx.insert("identities", &robot).await })
        .await
        .unwrap();
    assert_eq!(
        code(step_up("svc_robot".to_owned(), "123456".to_owned()).await),
        "MFA_NOT_ENROLLED"
    );
    f.clock.advance(30_000.0);
    let mut planted = f.get("authMfa", &carol.id).await.unwrap();
    assert_eq!(planted["enabled"], true);
    planted.insert("id".to_owned(), json!("svc_robot"));
    planted.insert("lastUsedStep".to_owned(), json!(-1));
    f.store
        .transaction(|tx| async move { tx.insert("authMfa", &planted).await })
        .await
        .unwrap();
    let fresh = f.totp(&secret);
    let error = step_up("svc_robot".to_owned(), fresh.clone())
        .await
        .unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.status),
        ("MFA_NOT_ENROLLED", 403)
    );
    assert_eq!(
        f.get("authMfa", "svc_robot").await.unwrap()["lastUsedStep"],
        -1
    );
    assert_eq!(
        step_up(carol.id.clone(), fresh).await.unwrap().verified_at,
        f.clock.now()
    );
}

#[tokio::test]
async fn limit_attempt_applies_a_dedicated_per_subject_budget() {
    let f = server(|_| {}).await;
    let limited = LimitAttemptOptions {
        limit: Some(2.0),
        ..Default::default()
    };
    f.auth
        .limit_attempt("org", "web-identity:trust-1", limited)
        .await
        .unwrap();
    f.auth
        .limit_attempt("org", "web-identity:trust-1", limited)
        .await
        .unwrap();
    let refusal = f
        .auth
        .limit_attempt("org", "web-identity:trust-1", limited)
        .await
        .unwrap_err();
    assert_eq!(
        (refusal.code.as_str(), refusal.status),
        ("RATE_LIMITED", 429)
    );
    assert!(f.auth.rate_limit_window_ms() > 0.0);
    f.auth
        .limit_attempt("org", "web-identity:trust-2", limited)
        .await
        .unwrap();
    f.auth
        .limit_attempt(
            "org",
            "step-up:someone",
            LimitAttemptOptions {
                tier: Some(RateTier::Sensitive),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        code(
            f.auth
                .limit_attempt(
                    "org",
                    "x",
                    LimitAttemptOptions {
                        limit: Some(0.5),
                        ..Default::default()
                    }
                )
                .await
        ),
        "INVALID_INPUT"
    );
}

#[tokio::test]
async fn limit_attempt_ignores_the_tenants_max_attempts_when_a_dedicated_limit_is_given() {
    let f = server(|_| {}).await;
    f.set_policy("org", Some(json!({ "maxAttempts": 1 }))).await;
    f.auth
        .limit_attempt("org", "sign-in:capped", LimitAttemptOptions::default())
        .await
        .unwrap();
    assert_eq!(
        code(
            f.auth
                .limit_attempt("org", "sign-in:capped", LimitAttemptOptions::default())
                .await
        ),
        "RATE_LIMITED"
    );
    let busy = LimitAttemptOptions {
        limit: Some(12.0),
        ..Default::default()
    };
    for _ in 0..12 {
        f.auth
            .limit_attempt("org", "web-identity:busy", busy)
            .await
            .unwrap();
    }
    let refusal = f
        .auth
        .limit_attempt("org", "web-identity:busy", busy)
        .await
        .unwrap_err();
    assert_eq!(
        (refusal.code.as_str(), refusal.status),
        ("RATE_LIMITED", 429)
    );
    f.set_policy("org", Some(json!({ "maxAttempts": 100 })))
        .await;
    let strict = LimitAttemptOptions {
        limit: Some(1.0),
        ..Default::default()
    };
    f.auth
        .limit_attempt("org", "web-identity:strict", strict)
        .await
        .unwrap();
    assert_eq!(
        code(
            f.auth
                .limit_attempt("org", "web-identity:strict", strict)
                .await
        ),
        "RATE_LIMITED"
    );
}

#[tokio::test]
async fn mfa_authenticated_at_is_recorded_for_first_hand_factors_only() {
    let f = server(|_| {}).await;
    // Root's MFA session, enrolled from the login challenge.
    let challenge = f
        .sign_in("root", "root@example.test", ROOT_PASSWORD)
        .await
        .unwrap();
    let challenge = challenge.mfa().expect("root MFA").challenge.clone();
    let credential = better_iam_auth::types::MfaCredential::Challenge {
        tenant_id: "root".to_owned(),
        challenge,
    };
    let enrollment = f.auth.begin_mfa(&credential).await.unwrap();
    let root_session = f
        .auth
        .confirm_mfa(&better_iam_auth::service::mfa::ConfirmMfaInput {
            credential,
            code: f.totp(&enrollment.secret),
            remember_device: true,
        })
        .await
        .unwrap();
    // Root administrators are never remembered.
    assert!(root_session.device_token.is_none());
    let root = stored_session(&f, &root_session.token).await;
    assert_eq!(root["mfa"], true);
    assert_eq!(root["mfaAuthenticatedAt"], root["createdAt"]);
    member(&f, "alice").await;
    let password = stored_session(&f, &session(member_sign_in(&f, "alice").await).token).await;
    assert!(password.get("mfaAuthenticatedAt").is_none());
    member(&f, "bob").await;
    let first = session(member_sign_in(&f, "bob").await);
    let (secret, _) = enroll(&f, &first.token).await;
    let challenge = member_sign_in(&f, "bob")
        .await
        .mfa()
        .expect("Bob MFA")
        .challenge
        .clone();
    f.clock.advance(30_000.0);
    let verified = f
        .auth
        .verify_mfa(&json!({ "tenantId": "org", "challenge": challenge, "code": f.totp(&secret), "rememberDevice": true }))
        .await
        .unwrap();
    let device_token = verified.device_token.clone().expect("device token");
    assert_eq!(
        stored_session(&f, &verified.token).await["mfaAuthenticatedAt"].as_f64(),
        Some(f.clock.now())
    );
    f.clock.advance(60_000.0);
    let remembered = session(
        f.auth
            .sign_in(&json!({ "tenantId": "org", "email": "bob@acme.test", "password": "a strong bob password", "deviceToken": device_token }))
            .await
            .unwrap(),
    );
    let row = stored_session(&f, &remembered.token).await;
    assert_eq!(row["mfa"], true);
    assert!(row.get("trustedDeviceId").is_some());
    assert!(row.get("mfaAuthenticatedAt").is_none());
    // Impersonation inherits the actor's MFA flag, never a factor time.
    f.set_policy("org", Some(json!({ "allowImpersonation": true })))
        .await;
    member(&f, "owner").await;
    let owner = f
        .auth
        .authenticate(&token(&session(member_sign_in(&f, "owner").await).token))
        .await
        .unwrap();
    let target: Identity = serde_json::from_value(Value::Object(
        f.get("identities", password["identityId"].as_str().unwrap())
            .await
            .unwrap(),
    ))
    .unwrap();
    let auth = f.auth.clone();
    let view_as = f
        .store
        .transaction(|tx| async move {
            auth.issue_impersonation_session(&tx, &owner, &target, 30.0 * 60_000.0)
                .await
        })
        .await
        .unwrap();
    assert!(user_token(&view_as.token));
    let impersonation = stored_session(&f, &view_as.token).await;
    assert!(impersonation["impersonatorId"].is_string());
    assert!(impersonation.get("mfaAuthenticatedAt").is_none());
    no_secret_fields(&view_as.session);
    let _: Arc<dyn IamStore> = f.store.clone();
}
