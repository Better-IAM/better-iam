//! The auth-owned vectors of `spec/vectors` (produced by the TypeScript implementation): password hashes, sealed
//! secrets, credential tokens and token hashes, TOTP, and challenge digests.

use std::path::PathBuf;

use better_iam_auth::crypto::{
    credential_token_check, decrypt_secret, encrypt_secret_with_iv, hash_token,
    new_credential_token_named, new_id, new_token, open_secret, parse_credential_token,
};
use better_iam_auth::passwords::{Argon2Type, HashOptions, hash_with_salt, verify_sync};
use better_iam_auth::service::base::digest_challenge;
use better_iam_auth::service::mfa::check_totp_code;
use better_iam_auth::totp;
use better_iam_auth::util::node_base64_decode;
use serde_json::Value;

fn cases(file: &str) -> Vec<Value> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/vectors")
        .join(format!("{file}.json"));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|_| panic!("vector file {}", path.display()));
    let parsed: Value = serde_json::from_str(&text).expect("vector JSON");
    parsed["cases"].as_array().expect("cases").clone()
}

fn undefined(value: &Value) -> bool {
    value.get("$undefined") == Some(&Value::Bool(true))
}

fn error_code(value: &Value) -> Option<&str> {
    value
        .get("$error")
        .and_then(|error| error.get("code"))
        .and_then(Value::as_str)
}

fn is_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|c| c.is_ascii_alphanumeric() || c == b'-' || c == b'_')
}

#[test]
fn passwords() {
    let mut checked = 0;
    for case in cases("passwords") {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let password = input["password"].as_str().unwrap();
        if name.starts_with("hash") {
            let phc = case["output"]
                .get("phc")
                .and_then(Value::as_str)
                .or_else(|| case["output"].as_str())
                .unwrap();
            let salt_text = phc.split('$').nth(4).unwrap();
            let salt = node_base64_decode(salt_text);
            let mut options = HashOptions::default();
            if let Some(extra) = input.get("options") {
                if extra["type"] == "argon2i" {
                    options.kind = Argon2Type::Argon2i;
                }
                if let Some(m) = extra["memoryCost"].as_u64() {
                    options.memory_cost = m as u32;
                }
                if let Some(t) = extra["timeCost"].as_u64() {
                    options.time_cost = t as u32;
                }
                if let Some(p) = extra["parallelism"].as_u64() {
                    options.parallelism = p as u32;
                }
            }
            assert_eq!(
                hash_with_salt(password, &salt, &options).unwrap(),
                phc,
                "{name}"
            );
            assert!(verify_sync(phc, password).unwrap(), "{name} verifies");
        } else {
            let phc = input["phc"].as_str().unwrap();
            assert_eq!(
                verify_sync(phc, password).unwrap(),
                case["output"].as_bool().unwrap(),
                "{name}"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, 14);
}

fn secrets_of(value: &Value) -> Vec<String> {
    match value {
        Value::String(secret) => vec![secret.clone()],
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().unwrap().to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

#[test]
fn secrets() {
    let mut checked = 0;
    for case in cases("secrets") {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let output = &case["output"];
        let context = input
            .get("context")
            .and_then(Value::as_str)
            .unwrap_or("better-iam");
        if name.starts_with("seal") {
            let iv = node_base64_decode(output["iv"].as_str().unwrap());
            let sealed = encrypt_secret_with_iv(
                input["value"].as_str().unwrap(),
                input["secret"].as_str().unwrap(),
                context,
                &iv,
            );
            assert_eq!(sealed, output["sealed"].as_str().unwrap(), "{name}");
        } else if name.starts_with("open") {
            let secrets = secrets_of(&input["secrets"]);
            let opened = match input["value"].as_str() {
                Some(value) => open_secret(value, &secrets, context),
                None => None,
            };
            if undefined(output) {
                assert_eq!(opened, None, "{name}");
            } else {
                let (value, index) = opened.unwrap_or_else(|| panic!("{name} opens"));
                assert_eq!(value, output["value"].as_str().unwrap(), "{name}");
                assert_eq!(index as u64, output["index"].as_u64().unwrap(), "{name}");
            }
        } else {
            let secrets = secrets_of(&input["secrets"]);
            let result = decrypt_secret(input["value"].as_str().unwrap(), &secrets, context);
            match error_code(output) {
                Some(code) => {
                    let error = result.unwrap_err();
                    assert_eq!(error.code, code, "{name}");
                    assert_eq!(error.message, output["$error"]["message"].as_str().unwrap());
                    assert_eq!(error.status, 400);
                }
                None => assert_eq!(result.unwrap(), output.as_str().unwrap(), "{name}"),
            }
        }
        checked += 1;
    }
    assert_eq!(checked, 31);
}

#[test]
fn tokens() {
    let mut checked = 0;
    for case in cases("tokens") {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let output = &case["output"];
        if name.starts_with("new ") && name.contains(" token ") && !name.contains("unknown") {
            let kind = input["type"].as_str().unwrap();
            // Random parts come from the TypeScript seeded generator: check the recorded token and a fresh one.
            for token in [
                output["token"].as_str().unwrap().to_owned(),
                new_credential_token_named(kind).unwrap(),
            ] {
                assert_eq!(token.len(), 58, "{name}");
                assert_eq!(
                    parse_credential_token(&token).map(|kind| kind.as_str()),
                    Some(kind),
                    "{name}"
                );
                assert_eq!(credential_token_check(&token[..52]), token[52..], "{name}");
            }
            let recorded = output["token"].as_str().unwrap();
            assert_eq!(&recorded[..52], output["body"].as_str().unwrap());
            assert_eq!(&recorded[52..], output["check"].as_str().unwrap());
            assert_eq!(
                hash_token(recorded),
                output["hash"].as_str().unwrap(),
                "{name}"
            );
        } else if name == "new token of unknown type" {
            let error = new_credential_token_named(input["type"].as_str().unwrap()).unwrap_err();
            assert_eq!(error.code, error_code(output).unwrap());
            assert_eq!(error.message, output["$error"]["message"].as_str().unwrap());
        } else if name.starts_with("parse") {
            let parsed = input["value"].as_str().and_then(parse_credential_token);
            if undefined(output) {
                assert_eq!(parsed, None, "{name}");
            } else {
                assert_eq!(
                    parsed.map(|kind| kind.as_str()),
                    output["type"].as_str(),
                    "{name}"
                );
            }
        } else if name.starts_with("checksum of") {
            let token = input["token"].as_str().unwrap();
            assert_eq!(
                credential_token_check(&token[..52]),
                output["check"].as_str().unwrap(),
                "{name}"
            );
            assert_eq!(
                parse_credential_token(token).map(|kind| kind.as_str()),
                output["parsed"]["type"].as_str(),
                "{name}"
            );
        } else if name.starts_with("hashToken") {
            assert_eq!(
                hash_token(input["value"].as_str().unwrap()),
                output["authHashToken"].as_str().unwrap(),
                "{name}"
            );
        } else if name == "newToken" {
            assert_eq!(output.as_str().unwrap().len(), 43);
            let token = new_token();
            assert_eq!(token.len(), 43);
            assert!(is_base64url(&token));
        } else if name.starts_with("newId") {
            let prefix = input.get("prefix").and_then(Value::as_str).unwrap_or("id");
            let recorded = output.as_str().unwrap();
            let fresh = new_id(prefix);
            for id in [recorded, fresh.as_str()] {
                let (head, tail) = id.split_once('_').unwrap();
                assert_eq!(head, prefix, "{name}");
                assert_eq!(tail.len(), 22, "{name}");
                assert!(is_base64url(tail));
            }
        } else {
            // Server-owned formats (server ids and tokens, sameHash, verifiable-credential offers).
            continue;
        }
        checked += 1;
    }
    assert_eq!(checked, 34);
}

#[test]
fn totp_vectors() {
    let mut checked = 0;
    for case in cases("totp") {
        let name = case["name"].as_str().unwrap();
        let input = &case["input"];
        let output = &case["output"];
        if name == "generateSecret(20)" {
            let recorded = output.as_str().unwrap();
            let bytes = totp::base32_decode(recorded).unwrap();
            assert_eq!(bytes.len(), 20);
            assert!(
                bytes.iter().all(|byte| *byte < 0x80),
                "otplib's ascii key encoding clears high bits"
            );
            assert_eq!(totp::secret_from_bytes(&bytes), recorded);
            let fresh = totp::generate_secret(20);
            assert_eq!(fresh.len(), 32);
            assert!(
                totp::base32_decode(&fresh)
                    .unwrap()
                    .iter()
                    .all(|byte| *byte < 0x80)
            );
        } else if name.starts_with("generate") {
            let epoch = input["epoch"].as_f64().unwrap();
            assert_eq!(
                totp::generate(input["secret"].as_str().unwrap(), epoch).unwrap(),
                output.as_str().unwrap(),
                "{name}"
            );
        } else if name.starts_with("checkDelta") {
            let delta = totp::check_delta(
                input["code"].as_str().unwrap(),
                input["secret"].as_str().unwrap(),
                input["epoch"].as_f64().unwrap(),
                1,
            );
            assert_eq!(delta, output.as_i64(), "{name}");
        } else if name.starts_with("keyuri") {
            assert_eq!(
                totp::keyuri(
                    input["account"].as_str().unwrap(),
                    input["issuer"].as_str().unwrap(),
                    input["secret"].as_str().unwrap()
                ),
                output.as_str().unwrap(),
                "{name}"
            );
        } else if name.starts_with("checkTotp") {
            let result = check_totp_code(
                input["secret"].as_str().unwrap(),
                input["code"].as_str().unwrap(),
                input["now"].as_f64().unwrap(),
                input["lastUsedStep"].as_f64().unwrap(),
            );
            match error_code(output) {
                Some(code) => {
                    let error = result.unwrap_err();
                    assert_eq!(error.code, code, "{name}");
                    assert_eq!(
                        error.message,
                        output["$error"]["message"].as_str().unwrap(),
                        "{name}"
                    );
                    assert_eq!(error.status, 401);
                }
                None => assert_eq!(result.unwrap(), output.as_f64().unwrap(), "{name}"),
            }
        } else {
            panic!("unknown TOTP vector {name}");
        }
        checked += 1;
    }
    assert_eq!(checked, 33);
}

#[test]
fn challenge_digests() {
    let mut checked = 0;
    for case in cases("derivations") {
        let name = case["name"].as_str().unwrap();
        if !name.starts_with("digestChallenge") {
            continue;
        }
        let input = &case["input"];
        assert_eq!(
            digest_challenge(
                input["secret"].as_str().unwrap(),
                input["tenantId"].as_str().unwrap(),
                input["token"].as_str().unwrap()
            ),
            case["output"].as_str().unwrap(),
            "{name}"
        );
        checked += 1;
    }
    assert_eq!(checked, 3);
}
