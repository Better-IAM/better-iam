//! The Rust WebAuthn verifier against `@simplewebauthn/server`'s own verdicts (`fixtures/webauthn.json`, written by
//! `fixtures/generate-webauthn.mjs`): the same responses are accepted or refused, and accepted registrations yield
//! the same stored public key, credential ID, AAGUID, counter and backup state.

use better_iam_auth::util::{base64url, node_base64_decode};
use better_iam_auth::webauthn::{
    StoredCredential, verify_authentication_response, verify_registration_response,
};
use serde_json::Value;

fn fixtures() -> Value {
    let path =
        std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/webauthn.json");
    serde_json::from_str(&std::fs::read_to_string(path).expect("fixture file"))
        .expect("fixture JSON")
}

#[tokio::test]
async fn agrees_with_simplewebauthn_on_every_fixture() {
    let fixtures = fixtures();
    let origins = vec![fixtures["origin"].as_str().unwrap().to_owned()];
    let rp_id = fixtures["rpId"].as_str().unwrap();
    let cases = fixtures["cases"].as_array().unwrap();
    assert!(cases.len() >= 30);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let expected = &case["expected"];
        let challenge = case["challenge"].as_str().unwrap();
        if case["kind"] == "registration" {
            let result =
                verify_registration_response(&case["response"], challenge, &origins, rp_id, true)
                    .await;
            if expected.get("error").is_some() {
                assert!(
                    result.is_err(),
                    "{name}: expected a refusal, got {result:?}"
                );
                continue;
            }
            let result = result.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                result.verified,
                expected["verified"].as_bool().unwrap(),
                "{name}"
            );
            if !result.verified {
                continue;
            }
            let info = result.info.unwrap();
            assert_eq!(info.fmt, expected["fmt"].as_str().unwrap(), "{name}");
            assert_eq!(info.aaguid, expected["aaguid"].as_str().unwrap(), "{name}");
            assert_eq!(
                info.credential_id,
                expected["credentialId"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                base64url(&info.public_key),
                expected["publicKey"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                f64::from(info.counter),
                expected["counter"].as_f64().unwrap(),
                "{name}"
            );
            assert_eq!(
                info.device_type,
                expected["deviceType"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                info.backed_up,
                expected["backedUp"].as_bool().unwrap(),
                "{name}"
            );
        } else {
            let credential = &case["credential"];
            let stored = StoredCredential {
                id: credential["id"].as_str().unwrap().to_owned(),
                public_key: node_base64_decode(credential["publicKey"].as_str().unwrap()),
                counter: credential["counter"].as_f64().unwrap(),
            };
            let result = verify_authentication_response(
                &case["response"],
                challenge,
                &origins,
                rp_id,
                true,
                &stored,
            );
            if expected.get("error").is_some() {
                assert!(
                    result.is_err(),
                    "{name}: expected a refusal, got {result:?}"
                );
                continue;
            }
            let result = result.unwrap_or_else(|error| panic!("{name}: {error}"));
            assert_eq!(
                result.verified,
                expected["verified"].as_bool().unwrap(),
                "{name}"
            );
            assert_eq!(
                f64::from(result.new_counter),
                expected["newCounter"].as_f64().unwrap(),
                "{name}"
            );
            assert_eq!(
                result.user_verified,
                expected["userVerified"].as_bool().unwrap(),
                "{name}"
            );
        }
    }
}
