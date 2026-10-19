//! Ports of `tests/passkey-discovery.test.ts`, `tests/passkey-metadata.test.ts` and `tests/passkey-mfa.test.ts`
//! (with the virtual authenticator of `tests/support/webauthn.ts`).

mod support;

use better_iam_auth::types::{PasskeyOptions, RateLimitOptions};
use better_iam_auth::util::base64url;
use better_iam_core::Identity;
use serde_json::{Value, json};
use support::*;

const ORIGIN: &str = "https://iam.example.com";

async fn passkey_server(configure: impl FnOnce(&mut better_iam_auth::AuthOptions)) -> Fixture {
    server(|options| {
        options.base_url = ORIGIN.to_owned();
        options.passkeys = Some(PasskeyOptions {
            rp_id: "iam.example.com".to_owned(),
            rp_name: Some("IAM".to_owned()),
        });
        configure(options);
    })
    .await
}

/// A person with a session and a registered passkey.
async fn person(f: &Fixture, name: &str, label: Option<&str>) -> (Identity, VirtualAuthenticator) {
    let identity = f
        .person(
            "root",
            &format!("{name}@example.test"),
            name,
            &format!("a strong {name} password"),
            true,
            false,
        )
        .await;
    let signed_in = session(
        f.sign_in(
            "root",
            &format!("{name}@example.test"),
            &format!("a strong {name} password"),
        )
        .await
        .unwrap(),
    );
    let authenticator = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    register(f, &signed_in.token, &authenticator, label).await;
    (identity, authenticator)
}

async fn register(
    f: &Fixture,
    session_token: &str,
    authenticator: &VirtualAuthenticator,
    label: Option<&str>,
) -> Value {
    let registration = f
        .auth
        .begin_passkey_registration(&token(session_token))
        .await
        .unwrap();
    let mut input = json!({
        "challengeId": registration.challenge_id,
        "response": authenticator.register(registration.options["challenge"].as_str().unwrap()),
    });
    if let Some(label) = label {
        input["name"] = json!(label);
    }
    serde_json::to_value(
        f.auth
            .finish_passkey_registration(&token(session_token), &input)
            .await
            .unwrap(),
    )
    .unwrap()
}

fn challenge(options: &Value) -> String {
    options["challenge"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn signs_a_person_in_from_the_credential_alone_refuses_foreign_or_mismatched_credentials_and_keeps_the_email_flow()
 {
    let f = passkey_server(|options| {
        options.rate_limits = Some(RateLimitOptions {
            attempts: Some(3.0),
            ..Default::default()
        });
        options.now = None;
    })
    .await;
    let (alice, mut alice_key) = person(&f, "alice", Some("alice's key")).await;
    let (bob, mut bob_key) = person(&f, "bob", Some("bob's key")).await;
    let discovery = f
        .auth
        .begin_passkey_authentication(&json!({ "tenantId": "root" }))
        .await
        .unwrap();
    assert!(discovery.options.get("allowCredentials").is_none());
    assert_eq!(discovery.options["userVerification"], "required");
    let finish = |id: &str, response: Value| json!({ "tenantId": "root", "challengeId": id, "response": response });
    let signed_in = f
        .auth
        .finish_passkey_authentication(&finish(
            &discovery.challenge_id,
            alice_key.assert(&challenge(&discovery.options), &alice.id, None),
        ))
        .await
        .unwrap();
    assert_eq!(signed_in.session.identity_id, alice.id);
    assert_eq!(
        signed_in.session.method.map(|method| method.as_str()),
        Some("passkey")
    );
    assert!(signed_in.session.mfa);
    assert_eq!(
        code(
            f.auth
                .finish_passkey_authentication(&finish(
                    &discovery.challenge_id,
                    bob_key.assert(&challenge(&discovery.options), &bob.id, None),
                ))
                .await
        ),
        "INVALID_CHALLENGE"
    );
    let again = f
        .auth
        .begin_passkey_authentication(&json!({ "tenantId": "root" }))
        .await
        .unwrap();
    assert_eq!(
        code(
            f.auth
                .finish_passkey_authentication(&finish(
                    &again.challenge_id,
                    bob_key.assert(&challenge(&again.options), &alice.id, None),
                ))
                .await
        ),
        "INVALID_PASSKEY"
    );
    let mut stranger = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    let third = f
        .auth
        .begin_passkey_authentication(&json!({ "tenantId": "root" }))
        .await
        .unwrap();
    assert_eq!(
        code(
            f.auth
                .finish_passkey_authentication(&finish(
                    &third.challenge_id,
                    stranger.assert(&challenge(&third.options), &alice.id, None),
                ))
                .await
        ),
        "INVALID_PASSKEY"
    );
    // Discovery starts are anonymous, so their allowance is ten times the ordinary one (per address).
    for _ in 0..27 {
        f.auth
            .begin_passkey_authentication(&json!({ "tenantId": "root" }))
            .await
            .unwrap();
    }
    assert_eq!(
        code(
            f.auth
                .begin_passkey_authentication(&json!({ "tenantId": "root" }))
                .await
        ),
        "RATE_LIMITED"
    );
    let named = f
        .auth
        .begin_passkey_authentication(&json!({ "tenantId": "root", "email": "bob@example.test" }))
        .await
        .unwrap();
    let ids: Vec<&str> = named.options["allowCredentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![base64url(&bob_key.credential_id)]);
    let bob_session = f
        .auth
        .finish_passkey_authentication(&finish(
            &named.challenge_id,
            bob_key.assert(&challenge(&named.options), &bob.id, None),
        ))
        .await
        .unwrap();
    assert_eq!(bob_session.session.identity_id, bob.id);
    // A disabled account cannot sign in by discovery either.
    f.patch("identities", &alice.id, json!({ "status": "disabled" }))
        .await;
    let start = json!({ "tenantId": "root" });
    let blocked = f
        .auth
        .with_client(
            Some(client(Some("203.0.113.9"), None, None)),
            f.auth.begin_passkey_authentication(&start),
        )
        .await
        .unwrap();
    assert_eq!(
        code(
            f.auth
                .finish_passkey_authentication(&finish(
                    &blocked.challenge_id,
                    alice_key.assert(&challenge(&blocked.options), &alice.id, None),
                ))
                .await
        ),
        "UNAUTHENTICATED"
    );
}

#[tokio::test]
async fn labels_passkeys_records_when_they_were_added_and_used_and_lets_people_rename_them() {
    let f = passkey_server(|_| {}).await;
    let alice = f
        .person(
            "root",
            "alice@example.test",
            "Alice",
            "a strong alice password",
            true,
            false,
        )
        .await;
    let signed_in = session(
        f.sign_in("root", "alice@example.test", "a strong alice password")
            .await
            .unwrap(),
    );
    let credential = token(&signed_in.token);
    let laptop_key = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    let laptop = register(&f, &signed_in.token, &laptop_key, Some("Work laptop")).await;
    assert_eq!(laptop["name"], "Work laptop");
    f.clock.advance(60_000.0);
    let unnamed_key = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    let unnamed = register(&f, &signed_in.token, &unnamed_key, None).await;
    assert_eq!(unnamed["name"], "This device");
    let listed = serde_json::to_value(f.auth.list_passkeys(&credential).await.unwrap()).unwrap();
    let names: Vec<&str> = listed
        .as_array()
        .unwrap()
        .iter()
        .map(|key| key["name"].as_str().unwrap())
        .collect();
    assert_eq!(names, vec!["This device", "Work laptop"]);
    assert_eq!(listed[1]["id"], laptop["id"]);
    assert_eq!(
        listed[1]["createdAt"].as_f64(),
        Some(f.clock.now() - 60_000.0)
    );
    assert_eq!(listed[1]["deviceType"], "singleDevice");
    assert_eq!(listed[1]["backedUp"], false);
    assert_eq!(listed[1]["transports"], json!(["internal"]));
    assert!(listed[1].get("lastUsedAt").is_none());
    assert!(!listed.to_string().contains("publicKey"));
    f.clock.advance(60_000.0);
    let begun = f
        .auth
        .begin_passkey_authentication(&json!({ "tenantId": "root", "email": "alice@example.test" }))
        .await
        .unwrap();
    let mut laptop_key = laptop_key;
    let passkey_session = f
        .auth
        .finish_passkey_authentication(&json!({
            "tenantId": "root",
            "challengeId": begun.challenge_id,
            "response": laptop_key.assert(&challenge(&begun.options), &alice.id, None),
        }))
        .await
        .unwrap();
    assert_eq!(
        passkey_session.session.method.map(|method| method.as_str()),
        Some("passkey")
    );
    let after = serde_json::to_value(f.auth.list_passkeys(&credential).await.unwrap()).unwrap();
    let find = |id: &Value| {
        after
            .as_array()
            .unwrap()
            .iter()
            .find(|key| key["id"] == *id)
            .unwrap()
            .clone()
    };
    assert_eq!(
        find(&laptop["id"])["lastUsedAt"].as_f64(),
        Some(f.clock.now())
    );
    assert!(find(&unnamed["id"]).get("lastUsedAt").is_none());
    // Renaming needs no recent authentication, is audited, and is validated.
    f.clock.advance(10.0 * 60_000.0);
    let renamed = f
        .auth
        .rename_passkey(
            &credential,
            &json!({ "id": laptop["id"], "name": "  YubiKey 5C  " }),
        )
        .await
        .unwrap();
    assert_eq!(renamed.name.as_deref(), Some("YubiKey 5C"));
    assert_eq!(
        code(
            f.auth
                .rename_passkey(&credential, &json!({ "id": laptop["id"], "name": "   " }))
                .await
        ),
        "INVALID_INPUT"
    );
    assert_eq!(
        code(
            f.auth
                .rename_passkey(
                    &credential,
                    &json!({ "id": laptop["id"], "name": "x".repeat(65) })
                )
                .await
        ),
        "INVALID_INPUT"
    );
    assert_eq!(
        code(
            f.auth
                .rename_passkey(&credential, &json!({ "id": "pk_missing", "name": "Nope" }))
                .await
        ),
        "NOT_FOUND"
    );
    let events: Vec<(Value, Value)> = f
        .find("audit", json!({ "tenantId": "root", "actorId": alice.id }))
        .await
        .into_iter()
        .map(|event| {
            (
                event["action"].clone(),
                event
                    .get("metadata")
                    .map_or(Value::Null, |m| m["name"].clone()),
            )
        })
        .collect();
    for expected in [
        (json!("auth:passkey:create"), json!("Work laptop")),
        (json!("auth:passkey:create"), json!("This device")),
        (json!("auth:passkey:rename"), json!("YubiKey 5C")),
    ] {
        assert!(events.contains(&expected), "{expected:?}");
    }
}

async fn mfa_fixture() -> (Fixture, Identity) {
    let f = passkey_server(|_| {}).await;
    let alice = f
        .person(
            "root",
            "alice@example.test",
            "Alice",
            "a strong alice password",
            true,
            false,
        )
        .await;
    (f, alice)
}

async fn alice_sign_in(f: &Fixture) -> better_iam_auth::SignInResult {
    f.sign_in("root", "alice@example.test", "a strong alice password")
        .await
        .unwrap()
}

#[tokio::test]
async fn offers_a_registered_passkey_at_the_mfa_step_and_issues_an_mfa_session_from_a_valid_assertion_only()
 {
    let (f, alice) = mfa_fixture().await;
    let mut key = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    let plain = session(alice_sign_in(&f).await);
    register(&f, &plain.token, &key, None).await;
    f.set_policy("root", Some(json!({ "requireMfa": true })))
        .await;
    let login = alice_sign_in(&f).await;
    let login = login.mfa().expect("MFA expected").clone();
    assert!(!login.enrollment_required);
    assert_eq!(login.authenticator_enrolled, Some(false));
    assert_eq!(login.passkey_available, Some(true));
    let mfa_credential = better_iam_auth::types::MfaCredential::Challenge {
        tenant_id: "root".to_owned(),
        challenge: login.challenge.clone(),
    };
    assert_eq!(
        code(f.auth.begin_mfa(&mfa_credential).await),
        "MFA_REQUIRED"
    );
    assert_eq!(
        code(
            f.auth
                .confirm_mfa(&better_iam_auth::service::mfa::ConfirmMfaInput {
                    credential: mfa_credential,
                    code: "123456".to_owned(),
                    remember_device: false,
                })
                .await
        ),
        "MFA_REQUIRED"
    );
    let begun = f
        .auth
        .begin_passkey_mfa(&json!({ "tenantId": "root", "challenge": login.challenge }))
        .await
        .unwrap();
    let ids: Vec<&str> = begun.options["allowCredentials"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, vec![base64url(&key.credential_id)]);
    let finish = |tenant: &str, response: Value, remember: bool| json!({ "tenantId": tenant, "challengeId": begun.challenge_id, "response": response, "rememberDevice": remember });
    let wrong_origin = key.assert(
        &challenge(&begun.options),
        &alice.id,
        Some("https://attacker.example"),
    );
    assert_eq!(
        code(
            f.auth
                .finish_passkey_mfa(&finish("root", wrong_origin, false))
                .await
        ),
        "INVALID_PASSKEY"
    );
    let elsewhere = key.assert(&challenge(&begun.options), &alice.id, None);
    assert_eq!(
        code(
            f.auth
                .finish_passkey_mfa(&finish("elsewhere", elsewhere, false))
                .await
        ),
        "INVALID_CHALLENGE"
    );
    let good = key.assert(&challenge(&begun.options), &alice.id, None);
    let mfa_session = f
        .auth
        .finish_passkey_mfa(&finish("root", good, true))
        .await
        .unwrap();
    assert!(mfa_session.session.mfa);
    assert_eq!(
        mfa_session.session.method.map(|method| method.as_str()),
        Some("password")
    );
    assert!(mfa_session.device_token.is_some());
    assert_eq!(
        f.auth
            .get_session(&token(&mfa_session.token))
            .await
            .unwrap()
            .identity
            .id,
        alice.id
    );
    let replay = key.assert(&challenge(&begun.options), &alice.id, None);
    assert_eq!(
        code(
            f.auth
                .finish_passkey_mfa(&finish("root", replay, false))
                .await
        ),
        "INVALID_CHALLENGE"
    );
    assert_eq!(
        code(
            f.auth
                .begin_passkey_mfa(&json!({ "tenantId": "root", "challenge": login.challenge }))
                .await
        ),
        "INVALID_CHALLENGE"
    );
    let listed = f
        .auth
        .list_passkeys(&token(&mfa_session.token))
        .await
        .unwrap();
    f.auth
        .delete_passkey(&token(&mfa_session.token), &json!({ "id": listed[0].id }))
        .await
        .unwrap();
    let bare = alice_sign_in(&f).await;
    let bare = bare.mfa().expect("MFA expected");
    assert_eq!(bare.passkey_available, None);
    assert_eq!(
        code(
            f.auth
                .begin_passkey_mfa(&json!({ "tenantId": "root", "challenge": bare.challenge }))
                .await
        ),
        "FEATURE_DISABLED"
    );
}

#[tokio::test]
async fn refuses_an_assertion_once_the_underlying_sign_in_challenge_has_expired() {
    let (f, alice) = mfa_fixture().await;
    let mut key = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    let plain = session(alice_sign_in(&f).await);
    register(&f, &plain.token, &key, None).await;
    f.set_policy("root", Some(json!({ "requireMfa": true })))
        .await;
    let login = alice_sign_in(&f).await.mfa().expect("MFA expected").clone();
    f.clock.advance(4.0 * 60_000.0);
    let begun = f
        .auth
        .begin_passkey_mfa(&json!({ "tenantId": "root", "challenge": login.challenge }))
        .await
        .unwrap();
    f.clock.advance(2.0 * 60_000.0);
    let assertion = key.assert(&challenge(&begun.options), &alice.id, None);
    assert_eq!(
        code(
            f.auth
                .finish_passkey_mfa(&json!({ "tenantId": "root", "challengeId": begun.challenge_id, "response": assertion }))
                .await
        ),
        "INVALID_CHALLENGE"
    );
}

#[tokio::test]
async fn verifies_packed_self_attestation_and_refuses_bad_signatures_and_counters() {
    let (f, alice) = mfa_fixture().await;
    let plain = session(alice_sign_in(&f).await);
    let key = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    // Packed self attestation: the credential key signs authData || clientDataHash.
    let registration = f
        .auth
        .begin_passkey_registration(&token(&plain.token))
        .await
        .unwrap();
    let options_challenge = challenge(&registration.options);
    let unsigned = key.register(&options_challenge);
    let attestation = better_iam_auth::webauthn::hexagon_decode(
        unsigned["response"]["attestationObject"].as_str().unwrap(),
        true,
    );
    let decoded = better_iam_auth::webauthn::cbor::decode_first(&attestation).unwrap();
    let auth_data = decoded
        .get_str("authData")
        .unwrap()
        .as_bytes()
        .unwrap()
        .to_vec();
    let client_data = better_iam_auth::webauthn::hexagon_decode(
        unsigned["response"]["clientDataJSON"].as_str().unwrap(),
        true,
    );
    let mut signed = auth_data.clone();
    signed.extend_from_slice(&<sha2::Sha256 as sha2::Digest>::digest(&client_data));
    use better_iam_auth::webauthn::cbor::Cbor;
    let statement = |signature: Vec<u8>| {
        Cbor::Map(vec![
            (Cbor::Text("alg".to_owned()), Cbor::Number(-7.0)),
            (Cbor::Text("sig".to_owned()), Cbor::Bytes(signature)),
        ])
    };
    let mut forged = key.sign(&signed);
    let last = forged.len() - 1;
    forged[last] ^= 1;
    let bad = key.register_with(
        &options_challenge,
        "packed",
        statement(forged),
        0x45,
        json!(["usb"]),
    );
    assert_eq!(
        code(
            f.auth
                .finish_passkey_registration(
                    &token(&plain.token),
                    &json!({ "challengeId": registration.challenge_id, "response": bad })
                )
                .await
        ),
        "INVALID_PASSKEY"
    );
    let good = key.register_with(
        &options_challenge,
        "packed",
        statement(key.sign(&signed)),
        0x45,
        json!(["usb"]),
    );
    let created = f
        .auth
        .finish_passkey_registration(
            &token(&plain.token),
            &json!({ "challengeId": registration.challenge_id, "response": good }),
        )
        .await
        .unwrap();
    assert_eq!(created.name, "Security key");
    // Without user verification the registration is refused.
    let registration = f
        .auth
        .begin_passkey_registration(&token(&plain.token))
        .await
        .unwrap();
    let other = VirtualAuthenticator::new("iam.example.com", ORIGIN);
    let unverified = other.register_with(
        &challenge(&registration.options),
        "none",
        Cbor::Map(vec![]),
        0x41,
        json!([]),
    );
    assert_eq!(
        code(
            f.auth
                .finish_passkey_registration(
                    &token(&plain.token),
                    &json!({ "challengeId": registration.challenge_id, "response": unverified })
                )
                .await
        ),
        "INVALID_PASSKEY"
    );
    // A counter that does not move forward is refused; a later one is accepted.
    let begun = f
        .auth
        .begin_passkey_authentication(&json!({ "tenantId": "root", "email": "alice@example.test" }))
        .await
        .unwrap();
    let finish = |response: Value| json!({ "tenantId": "root", "challengeId": begun.challenge_id, "response": response });
    let first = key.assert_with(&challenge(&begun.options), &alice.id, None, 5, 0x05);
    f.auth
        .finish_passkey_authentication(&finish(first))
        .await
        .unwrap();
    let begun = f
        .auth
        .begin_passkey_authentication(&json!({ "tenantId": "root", "email": "alice@example.test" }))
        .await
        .unwrap();
    let finish = |response: Value| json!({ "tenantId": "root", "challengeId": begun.challenge_id, "response": response });
    let stale = key.assert_with(&challenge(&begun.options), &alice.id, None, 5, 0x05);
    assert_eq!(
        code(f.auth.finish_passkey_authentication(&finish(stale)).await),
        "INVALID_PASSKEY"
    );
    let unverified = key.assert_with(&challenge(&begun.options), &alice.id, None, 6, 0x01);
    assert_eq!(
        code(
            f.auth
                .finish_passkey_authentication(&finish(unverified))
                .await
        ),
        "INVALID_PASSKEY"
    );
    let fresh = key.assert_with(&challenge(&begun.options), &alice.id, None, 6, 0x05);
    f.auth
        .finish_passkey_authentication(&finish(fresh))
        .await
        .unwrap();
}
