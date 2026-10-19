//! Mixed fleet: the TypeScript auth service and the Rust one share a SQLite file (`fixtures/auth-fleet.mjs`).
//!
//! TypeScript signs people in, enrolls an authenticator, registers a passkey and queues a sealed delivery; Rust
//! authenticates the TypeScript session token, verifies the TypeScript argon2id hash, opens the sealed authenticator
//! secret and outbox payload, consumes the TypeScript challenge digests and verifies the stored passkey. Then Rust
//! writes the same kinds of records and TypeScript uses each of them.
//!
//! Needs a Node that can load the workspace's better-sqlite3 (`BETTER_IAM_NODE`, else `node` on PATH) and the built
//! TypeScript packages (`pnpm build`); without them the test reports itself skipped.

mod support;

use std::path::PathBuf;
use std::process::Command;
use std::sync::{Arc, Mutex};

use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_auth::types::{DeliveryMessage, PasskeyOptions};
use better_iam_auth::util::{base64url, node_base64_decode};
use better_iam_auth::{AuthOptions, create_auth, delivery_fn, totp};
use better_iam_core::IamStore;
use p256::ecdsa::signature::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{VirtualAuthenticator, code, session, token};

const SECRET: &str = "auth-fleet-secret-with-at-least-32-characters";
const ORIGIN: &str = "https://iam.example.com";

fn node() -> String {
    std::env::var("BETTER_IAM_NODE").unwrap_or_else(|_| "node".to_owned())
}

fn script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/auth-fleet.mjs")
}

fn run(args: &[&str]) -> Result<Value, String> {
    let output = Command::new(node())
        .arg(script())
        .args(args)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).into_owned());
    }
    let text = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(text.lines().last().unwrap_or_default())
        .map_err(|error| format!("{error}: {text}"))
}

fn assertion(
    key: &p256::ecdsa::SigningKey,
    credential_id: &str,
    challenge: &str,
    user_id: &str,
    counter: u32,
) -> Value {
    let mut auth_data = Sha256::digest(b"iam.example.com").to_vec();
    auth_data.push(0x05);
    auth_data.extend_from_slice(&counter.to_be_bytes());
    let client_data = serde_json::to_vec(
        &json!({ "type": "webauthn.get", "challenge": challenge, "origin": ORIGIN }),
    )
    .unwrap();
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&Sha256::digest(&client_data));
    let signature: p256::ecdsa::Signature = key.sign(&signed);
    json!({
        "id": credential_id,
        "rawId": credential_id,
        "type": "public-key",
        "clientExtensionResults": {},
        "response": {
            "clientDataJSON": base64url(&client_data),
            "authenticatorData": base64url(&auth_data),
            "signature": base64url(signature.to_der().as_bytes()),
            "userHandle": base64url(user_id.as_bytes()),
        },
    })
}

#[tokio::test(flavor = "multi_thread")]
async fn typescript_and_rust_share_sessions_passwords_sealed_secrets_challenges_and_passkeys() {
    let directory = tempfile::tempdir().expect("temporary directory");
    let file = directory
        .path()
        .join("auth-fleet.sqlite")
        .to_string_lossy()
        .into_owned();
    let written = match run(&["write", &file]) {
        Ok(written) => written,
        Err(error) => {
            eprintln!("SKIPPED: the TypeScript side could not run ({error})");
            return;
        }
    };
    let store: Arc<dyn IamStore> =
        sqlite_adapter(SqliteAdapterOptions::new(file.clone())).expect("store");
    store.migrate().await.expect("migrate");
    let deliveries: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
    let mut options = AuthOptions::new(store.clone(), SECRET, ORIGIN);
    options.passkeys = Some(PasskeyOptions {
        rp_id: "iam.example.com".to_owned(),
        rp_name: None,
    });
    let inbox = deliveries.clone();
    options.send_email = Some(delivery_fn(move |message| {
        let inbox = inbox.clone();
        async move {
            inbox.lock().unwrap().push(message);
            Ok(())
        }
    }));
    let auth = create_auth(options).expect("auth");

    // TypeScript's session token, password hash and authenticator.
    let principal = auth
        .authenticate(&token(written["token"].as_str().unwrap()))
        .await
        .unwrap();
    assert_eq!(
        principal.identity.id,
        written["identityId"].as_str().unwrap()
    );
    let signed_in = auth
        .sign_in(&json!({ "tenantId": "org", "email": "ts@example.test", "password": "a typescript fleet password" }))
        .await
        .unwrap();
    assert!(signed_in.session().is_some());
    let mfa_input = json!({ "tenantId": "org", "email": "mfa@example.test", "password": "a typescript mfa password" });
    let mfa_sign_in = || auth.sign_in(&mfa_input);
    let challenge = mfa_sign_in()
        .await
        .unwrap()
        .mfa()
        .expect("MFA")
        .challenge
        .clone();
    let secret = written["mfaSecret"].as_str().unwrap();
    let code_ahead = totp::generate(secret, better_iam_core::js::now_ms() + 30_000.0).unwrap();
    let mfa = auth
        .verify_mfa(&json!({ "tenantId": "org", "challenge": challenge, "code": code_ahead }))
        .await
        .unwrap();
    assert!(mfa.session.mfa);
    let challenge = mfa_sign_in()
        .await
        .unwrap()
        .mfa()
        .expect("MFA")
        .challenge
        .clone();
    let recovered = auth
        .recover_mfa(
            &json!({ "tenantId": "org", "challenge": challenge, "code": written["recoveryCode"] }),
        )
        .await
        .unwrap();
    assert!(recovered.session.mfa);

    // TypeScript's passkey.
    let passkey = &written["passkey"];
    let ts_key =
        p256::ecdsa::SigningKey::from_slice(&node_base64_decode(passkey["d"].as_str().unwrap()))
            .unwrap();
    let begun = auth
        .begin_passkey_authentication(&json!({ "tenantId": "org", "email": "ts@example.test" }))
        .await
        .unwrap();
    let response = assertion(
        &ts_key,
        passkey["credentialId"].as_str().unwrap(),
        begun.options["challenge"].as_str().unwrap(),
        written["identityId"].as_str().unwrap(),
        3,
    );
    let passkey_session = auth
        .finish_passkey_authentication(
            &json!({ "tenantId": "org", "challengeId": begun.challenge_id, "response": response }),
        )
        .await
        .unwrap();
    assert_eq!(
        passkey_session.session.method.map(|method| method.as_str()),
        Some("passkey")
    );

    // TypeScript's sealed delivery, and the challenge digest behind its link.
    let dispatched = auth.dispatch_outbox(None).await.unwrap();
    assert!(dispatched.delivered >= 1);
    let reset = deliveries
        .lock()
        .unwrap()
        .iter()
        .find(|message| message.template == "password-reset" && message.to == "ts@example.test")
        .cloned()
        .expect("TypeScript's password-reset delivery");
    auth.reset_password(&json!({ "tenantId": "org", "token": reset.payload["token"], "password": "a rust chosen password" }))
        .await
        .unwrap();
    assert_eq!(
        code(
            auth.authenticate(&token(written["token"].as_str().unwrap()))
                .await
        ),
        "UNAUTHENTICATED"
    );

    // Rust writes the same kinds of records for TypeScript to use.
    let create = |email: &str, password: &str| {
        let auth = auth.clone();
        let store = store.clone();
        let input = better_iam_auth::service::CreateIdentityInput {
            tenant_id: "org".to_owned(),
            email: email.to_owned(),
            name: email.split('@').next().unwrap().to_owned(),
            password: Some(password.to_owned()),
            email_verified: Some(true),
            ..Default::default()
        };
        async move {
            better_iam_core::IamStoreExt::transaction(store.as_ref(), |tx| async move {
                auth.create_identity(&tx, input).await
            })
            .await
            .unwrap()
        }
    };
    let rs = create("rs@example.test", "a rust fleet password").await;
    let rs_session = session(
        auth.sign_in(&json!({ "tenantId": "org", "email": "rs@example.test", "password": "a rust fleet password" }))
            .await
            .unwrap(),
    );
    let key = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    let registration = auth
        .begin_passkey_registration(&token(&rs_session.token))
        .await
        .unwrap();
    auth.finish_passkey_registration(
        &token(&rs_session.token),
        &json!({
            "challengeId": registration.challenge_id,
            "response": key.register(registration.options["challenge"].as_str().unwrap()),
        }),
    )
    .await
    .unwrap();
    create("rsmfa@example.test", "a rust mfa password").await;
    let fixture_view = support::Fixture {
        store: store.clone(),
        auth: auth.clone(),
        clock: support::Clock::new(0.0),
        inbox: support::Inbox::default(),
    };
    let first = session(
        auth.sign_in(&json!({ "tenantId": "org", "email": "rsmfa@example.test", "password": "a rust mfa password" }))
            .await
            .unwrap(),
    );
    let (rust_secret, _) = enroll_now(&fixture_view, &first.token).await;
    auth.request_password_reset(&json!({ "tenantId": "org", "email": "rs@example.test" }))
        .await
        .unwrap();
    let (d, x, y) = key.export();
    let verified = run(&[
        "verify",
        &file,
        &json!({
            "token": rs_session.token,
            "identityId": rs.id,
            "password": "a rust fleet password",
            "mfaPassword": "a rust mfa password",
            "mfaSecret": rust_secret,
            "passkey": { "credentialId": key.id(), "d": d, "x": x, "y": y },
        })
        .to_string(),
    ])
    .expect("TypeScript verification");
    for check in [
        "rustSession",
        "rustPassword",
        "mfaChallenge",
        "rustMfa",
        "outbox",
        "rustPasskey",
    ] {
        assert_eq!(verified["checks"][check], true, "{check}: {verified}");
    }
}

/// Enrolls with the real clock (the fixture view's clock is not the service's).
async fn enroll_now(
    f: &support::Fixture,
    session_token: &str,
) -> (String, better_iam_auth::service::mfa::ConfirmedMfa) {
    let credential = better_iam_auth::types::MfaCredential::Credential(token(session_token));
    let enrollment = f.auth.begin_mfa(&credential).await.unwrap();
    let confirmed = f
        .auth
        .confirm_mfa(&better_iam_auth::service::mfa::ConfirmMfaInput {
            credential,
            code: totp::generate(&enrollment.secret, better_iam_core::js::now_ms()).unwrap(),
            remember_device: false,
        })
        .await
        .unwrap();
    (enrollment.secret, confirmed)
}
