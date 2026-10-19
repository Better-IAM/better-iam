//! Port of `tests/mfa-email-codes.test.ts`.

mod support;

use serde_json::json;
use support::*;

async fn fixture(deployment_default: Option<bool>) -> Fixture {
    let f = server(|options| options.mfa_email_codes = deployment_default).await;
    f.person(
        "root",
        "alice@example.test",
        "Alice",
        "a strong alice password",
        true,
        false,
    )
    .await;
    f
}

async fn sign_in(f: &Fixture, email: &str, password: &str) -> better_iam_auth::SignInResult {
    f.sign_in("root", email, password).await.unwrap()
}

async fn alice(f: &Fixture) -> better_iam_auth::SignInResult {
    sign_in(f, "alice@example.test", "a strong alice password").await
}

fn last_code(f: &Fixture) -> String {
    f.last("mfa-code")
}

trait Last {
    fn last(&self, template: &str) -> String;
}

impl Last for Fixture {
    fn last(&self, template: &str) -> String {
        self.inbox.last(template).payload["code"]
            .as_str()
            .unwrap()
            .to_owned()
    }
}

#[tokio::test]
async fn lets_a_member_without_an_authenticator_complete_a_required_mfa_with_a_single_use_emailed_code()
 {
    let f = fixture(None).await;
    f.set_policy("root", Some(json!({ "requireMfa": true })))
        .await;
    // Off by default: the challenge offers enrollment only, and asking for a code is refused.
    let plain = alice(&f).await;
    let plain = plain.mfa().expect("MFA expected");
    assert!(plain.enrollment_required);
    assert_eq!(plain.email_code_available, None);
    assert_eq!(
        code(
            f.auth
                .request_mfa_code(&json!({ "tenantId": "root", "challenge": plain.challenge }))
                .await
        ),
        "FEATURE_DISABLED"
    );
    // The tenant opts in.
    f.set_policy(
        "root",
        Some(json!({ "requireMfa": true, "mfaEmailCodes": true })),
    )
    .await;
    let offered = alice(&f).await;
    let offered = offered.mfa().expect("MFA expected").clone();
    assert!(offered.enrollment_required);
    assert_eq!(offered.email_code_available, Some(true));
    let verify =
        |code: &str| json!({ "tenantId": "root", "challenge": offered.challenge, "code": code });
    assert_eq!(
        code(f.auth.verify_mfa(&verify("000000")).await),
        "MFA_NOT_ENROLLED"
    );
    let requested = f
        .auth
        .request_mfa_code(&json!({ "tenantId": "root", "challenge": offered.challenge }))
        .await
        .unwrap();
    assert!(requested.expires_at <= f.clock.now() + 5.0 * 60_000.0);
    f.auth.dispatch_outbox(None).await.unwrap();
    let first = last_code(&f);
    assert!(first.len() == 6 && first.bytes().all(|c| c.is_ascii_digit()));
    let other = if first == "111111" {
        "222222"
    } else {
        "111111"
    };
    assert_eq!(code(f.auth.verify_mfa(&verify(other)).await), "INVALID_MFA");
    // Requesting again replaces the code; the old one stops working; the new one signs in with mfa: true.
    f.auth
        .request_mfa_code(&json!({ "tenantId": "root", "challenge": offered.challenge }))
        .await
        .unwrap();
    f.auth.dispatch_outbox(None).await.unwrap();
    let fresh = last_code(&f);
    if fresh != first {
        assert_eq!(
            code(f.auth.verify_mfa(&verify(&first)).await),
            "INVALID_MFA"
        );
    }
    let mut remember = verify(&fresh);
    remember["rememberDevice"] = json!(true);
    let session = f.auth.verify_mfa(&remember).await.unwrap();
    assert!(session.session.mfa);
    assert!(session.device_token.is_some());
    assert_eq!(
        code(f.auth.verify_mfa(&verify(&fresh)).await),
        "INVALID_CHALLENGE"
    );
    // Codes never outlive the five-minute login challenge.
    let later = alice(&f).await;
    let later = later.mfa().expect("MFA expected").clone();
    let timed = f
        .auth
        .request_mfa_code(&json!({ "tenantId": "root", "challenge": later.challenge }))
        .await
        .unwrap();
    assert!(timed.expires_at <= f.clock.now() + 5.0 * 60_000.0);
    f.auth.dispatch_outbox(None).await.unwrap();
    let expiring = last_code(&f);
    f.clock.advance(5.0 * 60_000.0 + 1_000.0);
    assert_eq!(
        code(
            f.auth
                .verify_mfa(
                    &json!({ "tenantId": "root", "challenge": later.challenge, "code": expiring })
                )
                .await
        ),
        "INVALID_CHALLENGE"
    );
}

#[tokio::test]
async fn never_offers_codes_to_root_administrators_or_to_people_with_an_authenticator_and_honours_the_deployment_default()
 {
    let f = fixture(Some(true)).await;
    f.set_policy("root", Some(json!({ "requireMfa": true })))
        .await;
    let first_challenge = alice(&f).await.mfa().expect("MFA expected").clone();
    assert_eq!(first_challenge.email_code_available, Some(true));
    // Root: authenticator only.
    let root = sign_in(&f, "root@example.test", ROOT_PASSWORD).await;
    let root = root.mfa().expect("Root must require MFA");
    assert_eq!(root.email_code_available, None);
    assert_eq!(
        code(
            f.auth
                .request_mfa_code(&json!({ "tenantId": "root", "challenge": root.challenge }))
                .await
        ),
        "FEATURE_DISABLED"
    );
    // Once Alice enrolls an authenticator, codes are no longer offered and the authenticator is checked.
    f.auth
        .request_mfa_code(&json!({ "tenantId": "root", "challenge": first_challenge.challenge }))
        .await
        .unwrap();
    f.auth.dispatch_outbox(None).await.unwrap();
    let first = f
        .auth
        .verify_mfa(&json!({ "tenantId": "root", "challenge": first_challenge.challenge, "code": last_code(&f) }))
        .await
        .unwrap();
    enroll(&f, &first.token).await;
    let enrolled = alice(&f).await;
    let enrolled = enrolled.mfa().expect("MFA expected");
    assert!(!enrolled.enrollment_required);
    assert_eq!(enrolled.email_code_available, None);
    assert_eq!(
        code(
            f.auth
                .request_mfa_code(&json!({ "tenantId": "root", "challenge": enrolled.challenge }))
                .await
        ),
        "FEATURE_DISABLED"
    );
    // A tenant can switch the deployment default off.
    f.set_policy(
        "root",
        Some(json!({ "requireMfa": true, "mfaEmailCodes": false })),
    )
    .await;
    let identity_id = first.session.identity_id.clone();
    f.store
        .transaction(|tx| async move { tx.delete("authMfa", &identity_id).await })
        .await
        .unwrap();
    let off = alice(&f).await;
    assert_eq!(off.mfa().expect("MFA expected").email_code_available, None);
}

use better_iam_core::IamStoreExt;
