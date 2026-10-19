//! Port of `tests/password-policy.test.ts` (the tenant-policy validation cases belong to the server's
//! `tenants.setAuthPolicy` and are ported with it).

mod support;

use std::sync::{Arc, Mutex};

use better_iam_auth::password_policy::{PasswordPolicyOptions, PwnedPasswordsOptions};
use better_iam_auth::service::CreateIdentityInput;
use better_iam_auth::{character_classes, is_common_password, pwned_passwords};
use better_iam_core::{IamError, IamStoreExt, Identity};
use serde_json::{Value, json};
use sha1::{Digest, Sha1};
use support::*;

#[test]
fn screens_common_sequential_and_low_variety_passwords_and_counts_character_classes() {
    for weak in [
        "password1234",
        "P@ssw0rd1234",
        "aaaaaaaaaaaaaa",
        "abababababab",
        "qwertyuiopasdf",
        "abcdefghijklmnop",
        "987654321098",
        "Correct Horse Battery Staple",
    ] {
        assert!(is_common_password(weak), "{weak}");
    }
    for fine in ["a strong alice password", "twelve chars!", "Tr0ub4dor&3xyz"] {
        assert!(!is_common_password(fine), "{fine}");
    }
    assert_eq!(character_classes("abc"), 1);
    assert_eq!(character_classes("aB3!"), 4);
    assert_eq!(character_classes("a strong password"), 2);
}

#[tokio::test]
async fn checks_breaches_with_k_anonymity_and_fails_open_unless_configured_otherwise() {
    let password = "a password from a breach";
    let digest = better_iam_auth::util::hex(Sha1::digest(password.as_bytes())).to_uppercase();
    let requested: Arc<Mutex<Vec<String>>> = Arc::default();
    let corpus = |count: u32| -> better_iam_auth::password_policy::PwnedFetchFn {
        let requested = requested.clone();
        let suffix = digest[5..].to_owned();
        Arc::new(move |url, headers, _| {
            requested.lock().unwrap().push(url.clone());
            assert!(headers.contains(&("add-padding".to_owned(), "true".to_owned())));
            let body = format!("0000000000000000000000000000000000A:1\r\n{suffix}:{count}\r\n");
            Box::pin(async move { Ok((200, body)) })
        })
    };
    let options = |fetch, threshold: Option<f64>, fail_closed: bool| PwnedPasswordsOptions {
        threshold,
        fail_closed,
        timeout_ms: None,
        endpoint: None,
        fetch: Some(fetch),
    };
    assert!(
        pwned_passwords(options(corpus(3), None, false))(password.to_owned())
            .await
            .unwrap()
    );
    let first = requested.lock().unwrap()[0].clone();
    assert_eq!(
        first,
        format!("https://api.pwnedpasswords.com/range/{}", &digest[..5])
    );
    assert!(!first.contains(&digest[5..]));
    assert!(
        !pwned_passwords(options(corpus(3), Some(10.0), false))(password.to_owned())
            .await
            .unwrap()
    );
    assert!(
        !pwned_passwords(options(corpus(3), None, false))("an entirely different one".to_owned())
            .await
            .unwrap()
    );
    let offline: better_iam_auth::password_policy::PwnedFetchFn =
        Arc::new(|_, _, _| Box::pin(async { Err("offline".to_owned()) }));
    assert!(
        !pwned_passwords(options(offline.clone(), None, false))(password.to_owned())
            .await
            .unwrap()
    );
    let error = pwned_passwords(options(offline, None, true))(password.to_owned())
        .await
        .unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.status),
        ("PASSWORD_CHECK_UNAVAILABLE", 503)
    );
}

async fn create(f: &Fixture, name: &str, password: &str) -> Result<Identity, IamError> {
    let input = CreateIdentityInput {
        tenant_id: "org".to_owned(),
        email: format!("{}@acme.test", name.to_lowercase().replace(' ', ".")),
        name: name.to_owned(),
        password: Some(password.to_owned()),
        email_verified: Some(true),
        ..Default::default()
    };
    let auth = f.auth.clone();
    f.store
        .transaction(|tx| async move { auth.create_identity(&tx, input).await })
        .await
}

async fn sign_in(f: &Fixture, email: &str, password: &str) -> String {
    session(f.sign_in("org", email, password).await.unwrap()).token
}

#[tokio::test]
async fn applies_deployment_screening_breach_corpus_custom_rule_common_list_to_every_password_path()
{
    let f = server(|options| {
        options.password_policy = Some(PasswordPolicyOptions {
            block_common_passwords: None,
            is_breached: Some(Arc::new(|password| {
                Box::pin(async move { Ok(password == "a breached but long password") })
            })),
            check: Some(Arc::new(|password, context| {
                Box::pin(async move {
                    Ok(
                        (password.to_lowercase().contains("acme") && !context.tenant_id.is_empty())
                            .then(|| "Do not use the company name".to_owned()),
                    )
                })
            })),
        });
    })
    .await;
    assert_eq!(
        code(create(&f, "Bob", "a breached but long password").await),
        "BREACHED_PASSWORD"
    );
    let error = create(&f, "Bob", "my acme password is long")
        .await
        .unwrap_err();
    assert_eq!(
        (error.code.as_str(), error.message.as_str()),
        ("WEAK_PASSWORD", "Do not use the company name")
    );
    assert_eq!(
        code(create(&f, "Bob", "password1234").await),
        "WEAK_PASSWORD"
    );
    create(&f, "Bob", "a strong bob password").await.unwrap();
    let bob = sign_in(&f, "bob@acme.test", "a strong bob password").await;
    assert_eq!(
        code(
            f.auth
                .change_password(
                    &token(&bob),
                    &json!({ "currentPassword": "a strong bob password", "password": "a breached but long password" })
                )
                .await
        ),
        "BREACHED_PASSWORD"
    );
}

#[tokio::test]
async fn enforces_tenant_complexity_and_personal_information_rules() {
    let f = server(|_| {}).await;
    f.set_policy("org", Some(json!({ "passwordMinClasses": 3 })))
        .await;
    assert_eq!(
        code(create(&f, "Dave", "a strong dave password").await),
        "WEAK_PASSWORD"
    );
    create(&f, "Dave", "Strong Pass For D 42").await.unwrap();
    f.set_policy("org", Some(json!({ "passwordRejectPersonalInfo": true })))
        .await;
    assert_eq!(
        code(create(&f, "Erin Walsh", "walsh has a long password").await),
        "WEAK_PASSWORD"
    );
    assert_eq!(
        code(create(&f, "Frank", "my name is frank really").await),
        "WEAK_PASSWORD"
    );
    create(&f, "Erin Walsh", "a long unrelated passphrase")
        .await
        .unwrap();
    f.set_policy("org", Some(json!({ "minPasswordLength": 20 })))
        .await;
    let error = create(&f, "Hal", "short but long enough").await;
    assert!(error.is_ok());
    let error = create(&f, "Ian", "nineteen characters").await.unwrap_err();
    assert_eq!(
        error.message,
        "Password must contain at least 20 characters in this organization"
    );
}

#[tokio::test]
async fn refuses_reuse_within_the_tenant_history_and_keeps_a_bounded_history() {
    let f = server(|_| {}).await;
    f.set_policy("org", Some(json!({ "passwordHistory": 2 })))
        .await;
    create(&f, "Alice", "first alice passphrase").await.unwrap();
    let change = |from: &'static str, to: &'static str| {
        let f = &f;
        async move {
            let session = sign_in(f, "alice@acme.test", from).await;
            f.auth
                .change_password(
                    &token(&session),
                    &json!({ "currentPassword": from, "password": to }),
                )
                .await
        }
    };
    change("first alice passphrase", "second alice passphrase")
        .await
        .unwrap();
    assert_eq!(
        code(change("second alice passphrase", "first alice passphrase").await),
        "PASSWORD_REUSED"
    );
    let error = change("second alice passphrase", "second alice passphrase")
        .await
        .unwrap_err();
    assert_eq!(error.code, "PASSWORD_REUSED");
    assert_eq!(
        error.message,
        "Password must differ from your last 2 passwords"
    );
    change("second alice passphrase", "third alice passphrase")
        .await
        .unwrap();
    // Two back is outside a history of 2 (current + one previous).
    change("third alice passphrase", "first alice passphrase")
        .await
        .unwrap();
    let alice = f
        .find("identities", json!({ "email": "alice@acme.test" }))
        .await
        .remove(0);
    assert_eq!(
        f.find("passwordHistory", json!({ "identityId": alice["id"] }))
            .await
            .len(),
        3
    );
    assert!(alice["passwordChangedAt"].is_number());
}

#[tokio::test]
async fn expires_passwords_after_the_maximum_age_and_recovers_through_reset() {
    let f = server(|_| {}).await;
    f.set_policy("org", Some(json!({ "passwordMaxAgeDays": 30 })))
        .await;
    create(&f, "Gina", "a strong gina password").await.unwrap();
    sign_in(&f, "gina@acme.test", "a strong gina password").await;
    f.clock.advance(31.0 * 86_400_000.0);
    let expired = f
        .sign_in("org", "gina@acme.test", "a strong gina password")
        .await
        .unwrap_err();
    assert_eq!(
        (expired.code.as_str(), expired.status),
        ("PASSWORD_EXPIRED", 403)
    );
    assert_eq!(
        code(
            f.sign_in("org", "gina@acme.test", "not the right password")
                .await
        ),
        "INVALID_CREDENTIALS"
    );
    let gina: Identity = serde_json::from_value(Value::Object(
        f.find("identities", json!({ "email": "gina@acme.test" }))
            .await
            .remove(0),
    ))
    .unwrap();
    let auth = f.auth.clone();
    f.store
        .transaction(|tx| async move { auth.issue_password_reset(&tx, &gina).await })
        .await
        .unwrap();
    f.auth.dispatch_outbox(None).await.unwrap();
    let reset = f.inbox.last("password-reset");
    f.auth
        .reset_password(&json!({ "tenantId": "org", "token": reset.payload["token"], "password": "a renewed gina password" }))
        .await
        .unwrap();
    sign_in(&f, "gina@acme.test", "a renewed gina password").await;
}
