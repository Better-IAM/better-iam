//! Key management: the `keys` API group, `iam.kms.maintain()` and the service helpers of kms.rs. Ported from
//! tests/kms.test.ts and tests/kms-security.test.ts, plus mixed-fleet checks against key material, ciphertexts,
//! signatures and MACs the TypeScript implementation produced (tests/fixtures/kms_node_vectors.json, made with
//! `node:crypto` exactly as kms.ts makes them).
//!
//! Members and their grants come from the organization fixture (written as `identities.create`, `roles.create` and
//! `bindings.create` write them).

mod organization_fixture;

use std::sync::{Arc, Mutex};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use better_iam_core::{
    CredentialInput, Filter, IamPlugin, IamResult, IamStoreExt, OperationHookInput, PluginHooks,
    Record,
};
use better_iam_server::kms::{KmsServiceUse, kms_decrypt_for, kms_encrypt_for};
use better_iam_server::options::{BetterIamOptions, ResolvedResource, ServerAuthOptions};
use bytes::Bytes;
use organization_fixture::{
    ORIGIN, Org, assert_matches, bearer, body, code, fails, ok, organization, run,
};
use serde_json::{Value, json};

const DAY: f64 = 86_400_000.0;
const SECRET: &str = "organization-fixture-secret-with-32-characters";

/// A JavaScript number as the API answers it (`1`, not `1.0`).
fn n(value: f64) -> Value {
    better_iam_server::js::number(value)
}

fn b64url(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn unb64url(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).expect("base64url")
}

async fn audit_of(f: &Org, action: &str) -> Vec<Record> {
    f.find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
        .await
        .into_iter()
        .filter(|event| event["action"] == action)
        .collect()
}

/// A member holding one inline role document (none when `statements` is empty), and a fresh session.
async fn member_with(f: &Org, name: &str, statements: Value) -> (String, CredentialInput) {
    let person = f.member(name).await;
    if statements.as_array().is_some_and(|items| !items.is_empty()) {
        f.grant(&person, statements).await;
    }
    let credential = f.sign_in(&person).await;
    (person, credential)
}

/// A member with one inline role bound until `expires_at` (when given); returns the binding id too.
async fn member_bound(
    f: &Org,
    name: &str,
    statements: Value,
    expires_at: Option<f64>,
) -> (String, String, CredentialInput) {
    let person = f.member(name).await;
    let authority = f
        .find(
            "grantAuthorities",
            Filter::new().eq("tenantId", f.tenant_id.clone()),
        )
        .await
        .into_iter()
        .next()
        .expect("authority")["id"]
        .clone();
    let role_id = better_iam_server::utils::id();
    f.insert(
        "roles",
        json!({
            "id": role_id,
            "tenantId": f.tenant_id,
            "name": format!("{name} keys"),
            "policyIds": [],
            "document": { "version": 1, "statements": statements },
            "protected": false,
            "authorityId": authority,
        }),
    )
    .await;
    let binding_id = better_iam_server::utils::id();
    let mut binding = json!({
        "id": binding_id,
        "tenantId": f.tenant_id,
        "subjectType": "identity",
        "subjectId": person,
        "roleId": role_id,
        "authorityId": authority,
    });
    if let Some(expires_at) = expires_at {
        binding["expiresAt"] = n(expires_at);
    }
    f.insert("bindings", binding).await;
    let credential = f.sign_in(&person).await;
    (person, binding_id, credential)
}

fn key_admin() -> Value {
    json!([{ "effect": "allow", "actions": ["iam:kms:*"], "resources": ["iam/kms", "iam/kms/*"] }])
}

/// `{ tenantId, ...input }`.
fn with_tenant(f: &Org, input: Value) -> Value {
    let mut input = input;
    input["tenantId"] = json!(f.tenant_id);
    input
}

async fn create_key(f: &Org, credential: &CredentialInput, input: Value) -> Value {
    ok(f.iam
        .api
        .keys
        .create(credential, body(with_tenant(f, input)))
        .await)
}

async fn encrypt(f: &Org, credential: &CredentialInput, input: Value) -> Value {
    ok(f.iam
        .api
        .keys
        .encrypt(credential, body(with_tenant(f, input)))
        .await)
}

async fn decrypt(
    f: &Org,
    credential: &CredentialInput,
    input: Value,
) -> better_iam_core::IamResult<Value> {
    f.iam
        .api
        .keys
        .decrypt(credential, body(with_tenant(f, input)))
        .await
        .map(|reply| reply.into_value().unwrap())
}

fn denied(result: IamResult<Value>) {
    match result {
        Ok(value) => panic!("expected ACCESS_DENIED, got {value}"),
        Err(error) => assert_eq!(error.code, "ACCESS_DENIED", "{error:?}"),
    }
}

/// The DER of a PEM block.
fn pem_der(pem: &str) -> Vec<u8> {
    let body: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    STANDARD.decode(body).expect("PEM body")
}

#[test]
fn encrypts_and_decrypts_under_an_alias_bound_to_the_encryption_context() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        let key = create_key(
            &f,
            &owner,
            json!({ "description": "Customer records", "alias": "alias/customers", "tags": { "team": "payments" } }),
        )
        .await;
        assert_matches(
            &key,
            json!({
                "keySpec": "aes-256-gcm",
                "keyUsage": "encrypt",
                "state": "enabled",
                "currentVersion": 1,
                "aliases": ["alias/customers"],
                "tags": { "team": "payments" },
                "algorithms": [],
            }),
        );
        assert!(!key.to_string().to_lowercase().contains("material"));
        let key_id = key["id"].as_str().unwrap().to_owned();

        let sealed = encrypt(
            &f,
            &owner,
            json!({ "keyId": "alias/customers", "plaintext": "card on file: 4242", "encryptionContext": { "record": "cus_1" } }),
        )
        .await;
        assert_matches(&sealed, json!({ "keyId": key_id, "keyVersion": 1 }));
        let ciphertext = sealed["ciphertext"].as_str().unwrap().to_owned();
        assert!(ciphertext.starts_with(&format!("kms1.{key_id}.1.t.")));
        assert!(!ciphertext.contains("4242"));

        assert_eq!(
            decrypt(
                &f,
                &owner,
                json!({ "ciphertext": ciphertext, "encryptionContext": { "record": "cus_1" } })
            )
            .await
            .unwrap(),
            json!({ "plaintext": "card on file: 4242", "keyId": key_id, "keyVersion": 1 })
        );

        // A different context, or a flipped byte, fails the same way and is audited as a denied decrypt.
        let error = decrypt(
            &f,
            &owner,
            json!({ "ciphertext": ciphertext, "encryptionContext": { "record": "cus_2" } }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status),
            ("INVALID_CIPHERTEXT", 400)
        );
        // Flipped mid-payload: the last character of base64 may carry padding bits, which parsing refuses first.
        let at = ciphertext.len() - 12;
        let flipped = if &ciphertext[at..at + 1] == "A" {
            "B"
        } else {
            "A"
        };
        let tampered = format!("{}{flipped}{}", &ciphertext[..at], &ciphertext[at + 1..]);
        let error = decrypt(
            &f,
            &owner,
            json!({ "ciphertext": tampered, "encryptionContext": { "record": "cus_1" } }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_CIPHERTEXT");
        // Insisting on another key refuses before decrypting.
        let other = create_key(&f, &owner, json!({})).await;
        let error = decrypt(
            &f,
            &owner,
            json!({ "ciphertext": ciphertext, "encryptionContext": { "record": "cus_1" }, "keyId": other["id"] }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_CIPHERTEXT");

        let decrypts = audit_of(&f, "iam:kms:decrypt").await;
        assert_eq!(
            decrypts
                .iter()
                .filter(|event| event["outcome"] == "allow")
                .count(),
            1
        );
        assert_eq!(
            decrypts
                .iter()
                .filter(|event| event["outcome"] == "deny"
                    && event["metadata"]["reason"] == "invalid-ciphertext")
                .count(),
            2
        );
        let allowed = decrypts
            .iter()
            .find(|event| event["outcome"] == "allow")
            .unwrap();
        assert_eq!(allowed["resourceId"], json!(format!("kms/{key_id}")));
        assert_matches(
            &allowed["metadata"],
            json!({ "keyId": key_id, "keyVersion": 1, "encryptionContext": { "record": "cus_1" } }),
        );
        // (The plaintext itself: ids and chain hashes are random hex that may contain any four digits.)
        assert!(
            !Value::Object(allowed.clone())
                .to_string()
                .contains("card on file")
        );

        // Binary plaintexts come back as base64.
        let bytes: Vec<u8> = (0..40u8).map(|i| i.wrapping_mul(37)).collect();
        let binary = encrypt(
            &f,
            &owner,
            json!({ "keyId": key_id, "plaintextBase64": STANDARD.encode(&bytes) }),
        )
        .await;
        assert_eq!(
            decrypt(&f, &owner, json!({ "ciphertext": binary["ciphertext"] }))
                .await
                .unwrap(),
            json!({ "plaintextBase64": STANDARD.encode(&bytes), "keyId": key_id, "keyVersion": 1 })
        );

        // The material is sealed at rest: nothing in the store opens without the deployment secret.
        let versions = f
            .find(
                "kmsKeyVersions",
                Filter::new().eq("tenantId", f.tenant_id.clone()),
            )
            .await;
        assert!(
            versions
                .iter()
                .all(|version| version["materialSealed"].is_string())
        );
        assert!(!json!(versions).to_string().contains("PRIVATE KEY"));
    });
}

#[test]
fn rotates_on_demand_and_on_schedule_while_old_ciphertexts_keep_decrypting() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({ "rotationPeriodDays": 30 })).await;
        assert_eq!(key["nextRotationAt"], n(f.now() + 30.0 * DAY));
        let key_id = key["id"].clone();
        let first = encrypt(&f, &owner, json!({ "keyId": key_id, "plaintext": "v1" })).await;
        let rotated = ok(keys
            .rotate(&owner, body(with_tenant(&f, json!({ "keyId": key_id }))))
            .await);
        assert_eq!(rotated["currentVersion"], json!(2));
        let second = encrypt(&f, &owner, json!({ "keyId": key_id, "plaintext": "v2" })).await;
        assert_eq!(second["keyVersion"], json!(2));

        f.advance(31.0 * DAY);
        let owner = f.session(&f.owner_id, false).await;
        assert_eq!(
            f.iam.kms.maintain(None).await.unwrap(),
            json!({
                "rotated": [{ "tenantId": f.tenant_id, "keyId": key_id, "keyVersion": 3 }],
                "destroyed": [],
                "grantsRemoved": 0,
            })
        );
        // Once rotated, nothing is due until the next period.
        assert_eq!(
            f.iam.kms.maintain(None).await.unwrap()["rotated"],
            json!([])
        );
        for (sealed, plaintext) in [(&first, "v1"), (&second, "v2")] {
            assert_eq!(
                decrypt(&f, &owner, json!({ "ciphertext": sealed["ciphertext"] }))
                    .await
                    .unwrap()["plaintext"],
                json!(plaintext)
            );
        }
        let versions = ok(keys
            .list_versions(&owner, body(with_tenant(&f, json!({ "keyId": key_id }))))
            .await);
        let summary: Vec<Value> = versions
            .as_array()
            .unwrap()
            .iter()
            .map(|version| json!([version["version"], version["origin"], version["current"]]))
            .collect();
        assert_eq!(
            summary,
            vec![
                json!([3, "automatic", true]),
                json!([2, "rotate", false]),
                json!([1, "create", false])
            ]
        );
        assert!(
            audit_of(&f, "kms:key-rotate")
                .await
                .iter()
                .any(|event| event["actorId"] == "deployment-operator")
        );

        // Clearing the period stops automatic rotation.
        let manual = ok(keys
            .update(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key_id, "rotationPeriodDays": null }),
                )),
            )
            .await);
        assert!(manual.get("rotationPeriodDays").is_none());
        assert!(manual.get("nextRotationAt").is_none());
    });
}

#[test]
fn issues_data_keys_for_envelope_encryption() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({})).await;
        let data_key = ok(keys
            .generate_data_key(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key["id"], "encryptionContext": { "bucket": "invoices" } }),
                )),
            )
            .await);
        assert_eq!(data_key["bytes"], json!(32));
        let plaintext_key = STANDARD
            .decode(data_key["plaintextBase64"].as_str().unwrap())
            .unwrap();
        assert_eq!(plaintext_key.len(), 32);
        let unwrapped = decrypt(
            &f,
            &owner,
            json!({ "ciphertext": data_key["ciphertext"], "encryptionContext": { "bucket": "invoices" } }),
        )
        .await
        .unwrap();
        assert_eq!(unwrapped["plaintextBase64"], data_key["plaintextBase64"]);

        let without_plaintext = ok(keys
            .generate_data_key(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key["id"], "bytes": 16, "includePlaintext": false }),
                )),
            )
            .await);
        assert!(without_plaintext.get("plaintextBase64").is_none());
        assert_eq!(without_plaintext["bytes"], json!(16));
        let error = fails(
            keys.generate_data_key(
                &owner,
                body(with_tenant(&f, json!({ "keyId": key["id"], "bytes": 20 }))),
            )
            .await,
        );
        assert_eq!(error.message, "bytes must be 16, 24, 32 or 64");

        // Re-encrypting moves a ciphertext to another key and context without exposing the plaintext.
        let next = create_key(&f, &owner, json!({})).await;
        let moved = ok(keys
            .re_encrypt(
                &owner,
                body(with_tenant(
                    &f,
                    json!({
                        "ciphertext": data_key["ciphertext"],
                        "sourceEncryptionContext": { "bucket": "invoices" },
                        "destinationKeyId": next["id"],
                        "destinationEncryptionContext": { "bucket": "archive" },
                    }),
                )),
            )
            .await);
        assert_matches(
            &moved,
            json!({ "keyId": next["id"], "sourceKeyId": key["id"], "keyVersion": 1 }),
        );
        assert_eq!(
            decrypt(
                &f,
                &owner,
                json!({ "ciphertext": moved["ciphertext"], "encryptionContext": { "bucket": "archive" } })
            )
            .await
            .unwrap()["plaintextBase64"],
            data_key["plaintextBase64"]
        );
        // One id links the decrypt and encrypt events of the re-encryption.
        let linked: Vec<Value> = f
            .find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
            .await
            .into_iter()
            .filter_map(|event| {
                event
                    .get("metadata")
                    .and_then(|metadata| metadata.get("reEncryptId"))
                    .cloned()
            })
            .collect();
        assert_eq!(linked.len(), 2);
        assert_eq!(linked[0], linked[1]);
    });
}

#[test]
fn signs_and_verifies_with_ecdsa_ed25519_and_rsa_keys_offline_too() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let message = "release 1.2.3 sha256:abcdef";
        for (spec, usage, algorithm) in [
            ("ecc-p256", None, "ES256"),
            ("ecc-p384", None, "ES384"),
            ("ed25519", None, "EdDSA"),
            ("rsa-2048", Some("sign"), "PS256"),
        ] {
            let mut input = json!({ "keySpec": spec });
            if let Some(usage) = usage {
                input["keyUsage"] = json!(usage);
            }
            let key = create_key(&f, &owner, input).await;
            assert_eq!(key["algorithms"][0], json!(algorithm));
            let signed = ok(keys
                .sign(
                    &owner,
                    body(with_tenant(
                        &f,
                        json!({ "keyId": key["id"], "message": message }),
                    )),
                )
                .await);
            assert_eq!(signed["algorithm"], json!(algorithm));
            assert_matches(
                &ok(keys
                    .verify(
                        &owner,
                        body(with_tenant(
                            &f,
                            json!({ "keyId": key["id"], "message": message, "signature": signed["signature"] }),
                        )),
                    )
                    .await),
                json!({ "valid": true, "keyVersion": 1 }),
            );
            assert_eq!(
                ok(keys
                    .verify(
                        &owner,
                        body(with_tenant(
                            &f,
                            json!({ "keyId": key["id"], "message": format!("{message}!"), "signature": signed["signature"] }),
                        )),
                    )
                    .await)["valid"],
                json!(false)
            );
            // Anyone holding the public key verifies without calling IAM.
            let published = ok(keys
                .public_key(&owner, body(with_tenant(&f, json!({ "keyId": key["id"] }))))
                .await);
            let der = pem_der(published["publicKeyPem"].as_str().unwrap());
            let signature = unb64url(signed["signature"].as_str().unwrap());
            let verified = offline_verify(algorithm, &der, message.as_bytes(), &signature);
            assert!(verified, "{algorithm} verifies offline");
            assert_matches(
                &published["jwk"],
                json!({ "kid": format!("{}.1", key["id"].as_str().unwrap()), "use": "sig" }),
            );
        }
        // Encryption keys cannot sign, signing keys cannot encrypt.
        let aes = create_key(&f, &owner, json!({})).await;
        let error = fails(
            keys.sign(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": aes["id"], "message": message }),
                )),
            )
            .await,
        );
        assert_eq!(error.code, "INVALID_INPUT");
        let error = fails(
            keys.create(
                &owner,
                body(with_tenant(&f, json!({ "keySpec": "rsa-2048" }))),
            )
            .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_INPUT",
                "keyUsage is required for rsa-2048 (encrypt or sign)"
            )
        );
    });
}

/// Verifies a signature with an SPKI public key, as `crypto.verify` does offline.
fn offline_verify(algorithm: &str, der: &[u8], message: &[u8], signature: &[u8]) -> bool {
    use p256::pkcs8::DecodePublicKey;
    use rsa::signature::Verifier;
    match algorithm {
        "ES256" => {
            let key = p256::ecdsa::VerifyingKey::from_public_key_der(der).unwrap();
            let signature = p256::ecdsa::Signature::from_der(signature).unwrap();
            key.verify(message, &signature).is_ok()
        }
        "ES384" => {
            let key = p384::ecdsa::VerifyingKey::from_public_key_der(der).unwrap();
            let signature = p384::ecdsa::Signature::from_der(signature).unwrap();
            key.verify(message, &signature).is_ok()
        }
        "EdDSA" => {
            let key = ed25519_dalek::VerifyingKey::try_from(&der[12..]).unwrap();
            let signature = ed25519_dalek::Signature::from_slice(signature).unwrap();
            key.verify(message, &signature).is_ok()
        }
        _ => {
            let key = rsa::RsaPublicKey::from_public_key_der(der).unwrap();
            let signature = rsa::pss::Signature::try_from(signature).unwrap();
            rsa::pss::VerifyingKey::<sha2::Sha256>::new(key)
                .verify(message, &signature)
                .is_ok()
        }
    }
}

#[test]
fn encrypts_small_secrets_with_rsa_oaep_keys() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(
            &f,
            &owner,
            json!({ "keySpec": "rsa-2048", "keyUsage": "encrypt" }),
        )
        .await;
        let sealed = encrypt(
            &f,
            &owner,
            json!({ "keyId": key["id"], "plaintext": "short secret", "encryptionContext": { "purpose": "test" } }),
        )
        .await;
        assert_eq!(
            decrypt(
                &f,
                &owner,
                json!({ "ciphertext": sealed["ciphertext"], "encryptionContext": { "purpose": "test" } })
            )
            .await
            .unwrap()["plaintext"],
            json!("short secret")
        );
        assert_eq!(
            decrypt(&f, &owner, json!({ "ciphertext": sealed["ciphertext"] }))
                .await
                .unwrap_err()
                .code,
            "INVALID_CIPHERTEXT"
        );
        let error = fails(
            keys.encrypt(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key["id"], "plaintext": "x".repeat(300) }),
                )),
            )
            .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_INPUT",
                "rsa-2048 keys encrypt at most 190 bytes; encrypt a data key instead"
            )
        );
        let published = ok(keys
            .public_key(&owner, body(with_tenant(&f, json!({ "keyId": key["id"] }))))
            .await);
        assert_matches(&published["jwk"], json!({ "use": "enc", "kty": "RSA" }));
        // No `alg`: KMS ciphertexts bind a label, so a plain offline RSA-OAEP-256 encrypter would not produce one.
        assert!(published["jwk"].get("alg").is_none());
    });
}

#[test]
fn computes_macs_and_signs_and_verifies_jwts() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let hmac = create_key(&f, &owner, json!({ "keySpec": "hmac-sha256" })).await;
        let mac = ok(keys
            .generate_mac(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": hmac["id"], "message": "webhook body" }),
                )),
            )
            .await);
        assert_eq!(mac["algorithm"], json!("HS256"));
        for (message, valid) in [("webhook body", true), ("webhook body.", false)] {
            assert_eq!(
                ok(keys
                    .verify_mac(
                        &owner,
                        body(with_tenant(
                            &f,
                            json!({ "keyId": hmac["id"], "message": message, "mac": mac["mac"] }),
                        )),
                    )
                    .await)["valid"],
                json!(valid)
            );
        }

        let signer = create_key(
            &f,
            &owner,
            json!({ "keySpec": "ecc-p256", "alias": "alias/tokens" }),
        )
        .await;
        let signer_id = signer["id"].as_str().unwrap().to_owned();
        let issued = ok(keys
            .sign_jwt(
                &owner,
                body(with_tenant(
                    &f,
                    json!({
                        "keyId": "alias/tokens",
                        "claims": { "sub": "svc_1", "aud": "billing", "iss": "acme" },
                        "expiresInSeconds": 300,
                    }),
                )),
            )
            .await);
        assert_eq!(issued["algorithm"], json!("ES256"));
        let token = issued["token"].as_str().unwrap().to_owned();
        let parts: Vec<&str> = token.split('.').collect();
        let header: Value = serde_json::from_slice(&unb64url(parts[0])).unwrap();
        let claims: Value = serde_json::from_slice(&unb64url(parts[1])).unwrap();
        assert_eq!(
            header,
            json!({ "alg": "ES256", "kid": format!("{signer_id}.1"), "typ": "JWT" })
        );
        assert_eq!(
            claims["exp"].as_f64().unwrap() - claims["iat"].as_f64().unwrap(),
            300.0
        );
        // The JWKS verifies it offline (JOSE signature encoding).
        let jwks = ok(keys
            .jwks(&owner, body(with_tenant(&f, json!({ "keyId": signer_id }))))
            .await);
        let jwk = jwks["keys"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["kid"] == header["kid"])
            .unwrap()
            .clone();
        {
            use rsa::signature::Verifier;
            let point = p256::EncodedPoint::from_affine_coordinates(
                unb64url(jwk["x"].as_str().unwrap()).as_slice().into(),
                unb64url(jwk["y"].as_str().unwrap()).as_slice().into(),
                false,
            );
            let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point).unwrap();
            let signature = p256::ecdsa::Signature::from_slice(&unb64url(parts[2])).unwrap();
            assert!(
                key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
                    .is_ok()
            );
        }
        let verify_jwt = |credential: CredentialInput, input: Value| {
            let keys = keys.clone();
            let input = with_tenant(&f, input);
            async move { ok(keys.verify_jwt(&credential, body(input)).await) }
        };
        assert_matches(
            &verify_jwt(
                owner.clone(),
                json!({ "token": token, "audience": "billing", "issuer": "acme" }),
            )
            .await,
            json!({ "valid": true, "claims": { "sub": "svc_1" } }),
        );
        assert_matches(
            &verify_jwt(
                owner.clone(),
                json!({ "token": token, "audience": "other" }),
            )
            .await,
            json!({ "valid": false, "reason": "audience" }),
        );
        // After rotation the old token still verifies by its kid; a forged one does not.
        ok(keys
            .rotate(&owner, body(with_tenant(&f, json!({ "keyId": signer_id }))))
            .await);
        assert_eq!(
            verify_jwt(owner.clone(), json!({ "token": token })).await["valid"],
            json!(true)
        );
        let mut forged_claims = claims.clone();
        forged_claims["sub"] = json!("admin");
        let forged = format!(
            "{}.{}.{}",
            parts[0],
            b64url(forged_claims.to_string()),
            parts[2]
        );
        assert_matches(
            &verify_jwt(owner.clone(), json!({ "token": forged })).await,
            json!({ "valid": false, "reason": "signature" }),
        );
        f.advance(10.0 * 60_000.0);
        let owner = f.session(&f.owner_id, false).await;
        assert_matches(
            &verify_jwt(owner.clone(), json!({ "token": token })).await,
            json!({ "valid": false, "reason": "expired" }),
        );

        // HMAC keys sign HS256 tokens.
        let hs = ok(keys
            .sign_jwt(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": hmac["id"], "claims": { "sub": "x" } }),
                )),
            )
            .await);
        assert_eq!(hs["algorithm"], json!("HS256"));
        assert_eq!(
            verify_jwt(owner.clone(), json!({ "token": hs["token"] })).await["valid"],
            json!(true)
        );
    });
}

#[test]
fn authorizes_by_key_tags_and_encryption_context_and_refuses_other_tenants() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let payments = create_key(&f, &owner, json!({ "tags": { "team": "payments" } })).await;
        let research = create_key(&f, &owner, json!({ "tags": { "team": "research" } })).await;
        let (alice_id, alice) = member_with(
            &f,
            "alice",
            json!([
                {
                    "effect": "allow",
                    "actions": ["iam:kms:encrypt", "iam:kms:decrypt"],
                    "resources": ["iam/kms/*"],
                    "conditions": {
                        "StringEquals": {
                            "resource.tags.team": "payments",
                            "resource.encryptionContext.app": "billing",
                        },
                    },
                },
                {
                    "effect": "allow",
                    "actions": ["iam:kms:read"],
                    "resources": ["iam/kms/*"],
                    "conditions": { "StringEquals": { "resource.tags.team": "payments" } },
                },
            ]),
        )
        .await;
        let sealed = encrypt(
            &f,
            &alice,
            json!({ "keyId": payments["id"], "plaintext": "ok", "encryptionContext": { "app": "billing" } }),
        )
        .await;
        for (key, app) in [(&payments, "crm"), (&research, "billing")] {
            let error = fails(
                keys.encrypt(
                    &alice,
                    body(with_tenant(
                        &f,
                        json!({ "keyId": key["id"], "plaintext": "no", "encryptionContext": { "app": app } }),
                    )),
                )
                .await,
            );
            assert_eq!(code(&error), "ACCESS_DENIED");
        }
        assert_eq!(
            decrypt(
                &f,
                &alice,
                json!({ "ciphertext": sealed["ciphertext"], "encryptionContext": { "app": "billing" } })
            )
            .await
            .unwrap()["plaintext"],
            json!("ok")
        );
        // Listing shows only the keys a tag-scoped reader may read.
        let listed = ok(keys.list(&alice, body(with_tenant(&f, json!({})))).await);
        let ids: Vec<Value> = listed["keys"]
            .as_array()
            .unwrap()
            .iter()
            .map(|key| key["id"].clone())
            .collect();
        assert_eq!(ids, vec![payments["id"].clone()]);
        assert_eq!(
            ok(keys.list(&owner, body(with_tenant(&f, json!({})))).await)["total"],
            json!(2)
        );
        // Management is a separate permission.
        let error = fails(
            keys.disable(
                &alice,
                body(with_tenant(&f, json!({ "keyId": payments["id"] }))),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert!(
            audit_of(&f, "iam:kms:update")
                .await
                .iter()
                .any(|event| event["outcome"] == "deny" && event["actorId"] == json!(alice_id))
        );

        // A tag-scoped administrator cannot re-tag a key out of their reach.
        let (_, admin) = member_with(
            &f,
            "adam",
            json!([{
                "effect": "allow",
                "actions": ["iam:kms:*"],
                // Creating names the key collection (`iam/kms`); everything else names the key.
                "resources": ["iam/kms", "iam/kms/*"],
                "conditions": { "StringEquals": { "resource.tags.team": "payments" } },
            }]),
        )
        .await;
        let error = fails(
            keys.update(
                &admin,
                body(with_tenant(
                    &f,
                    json!({ "keyId": payments["id"], "tags": { "team": "research" } }),
                )),
            )
            .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "ACCESS_DENIED",
                "Those tags would take the key out of your reach"
            )
        );
        assert_matches(
            &ok(keys
                .update(
                    &admin,
                    body(with_tenant(
                        &f,
                        json!({ "keyId": payments["id"], "tags": { "team": "payments", "env": "prod" } }),
                    )),
                )
                .await),
            json!({ "tags": { "team": "payments", "env": "prod" } }),
        );
        // And may only create keys carrying their tag.
        let error = fails(
            keys.create(
                &admin,
                body(with_tenant(&f, json!({ "tags": { "team": "research" } }))),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_matches(
            &create_key(&f, &admin, json!({ "tags": { "team": "payments" } })).await,
            json!({ "tags": { "team": "payments" } }),
        );

        // Another organization's owner cannot use Acme's keys, even knowing their ids.
        let (globex_tenant, _, globex) = f
            .activate(
                &f.root_tenant.clone(),
                "Globex",
                "organization",
                "owner@globex.test",
            )
            .await;
        let error = fails(
            keys.decrypt(
                &globex,
                body(with_tenant(
                    &f,
                    json!({ "ciphertext": sealed["ciphertext"], "encryptionContext": { "app": "billing" } }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            keys.decrypt(
                &globex,
                body(json!({
                    "tenantId": globex_tenant,
                    "ciphertext": sealed["ciphertext"],
                    "encryptionContext": { "app": "billing" },
                })),
            )
            .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
    });
}

#[test]
fn delegates_key_use_through_grants_that_never_exceed_the_grantor() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({})).await;
        let key_id = key["id"].clone();
        let sealed = encrypt(
            &f,
            &owner,
            json!({ "keyId": key_id, "plaintext": "billing data", "encryptionContext": { "app": "billing", "record": "7" } }),
        )
        .await;
        let crm = encrypt(
            &f,
            &owner,
            json!({ "keyId": key_id, "plaintext": "crm data", "encryptionContext": { "app": "crm" } }),
        )
        .await;
        let (bob_id, bob) = member_with(&f, "bob", json!([])).await;
        let bob_decrypt = |ciphertext: Value, context: Value| {
            decrypt(
                &f,
                &bob,
                json!({ "ciphertext": ciphertext, "encryptionContext": context }),
            )
        };
        denied(
            bob_decrypt(
                sealed["ciphertext"].clone(),
                json!({ "app": "billing", "record": "7" }),
            )
            .await,
        );

        let create_grant = |credential: CredentialInput, input: Value| {
            let keys = keys.clone();
            let input = with_tenant(&f, input);
            async move {
                keys.create_grant(&credential, body(input))
                    .await
                    .map(|reply| reply.into_value().unwrap())
            }
        };
        let grant = create_grant(
            owner.clone(),
            json!({
                "keyId": key_id,
                "granteeType": "identity",
                "granteeId": bob_id,
                "operations": ["decrypt"],
                "constraints": { "encryptionContextSubset": { "app": "billing" } },
                "name": "billing worker",
            }),
        )
        .await
        .unwrap();
        assert_matches(&grant, json!({ "operations": ["decrypt"], "active": true }));
        assert_eq!(
            bob_decrypt(
                sealed["ciphertext"].clone(),
                json!({ "app": "billing", "record": "7" })
            )
            .await
            .unwrap()["plaintext"],
            json!("billing data")
        );
        let used = audit_of(&f, "iam:kms:decrypt")
            .await
            .into_iter()
            .find(|event| event["actorId"] == json!(bob_id) && event["outcome"] == "allow")
            .unwrap();
        assert_eq!(used["metadata"]["grantId"], grant["id"]);
        // Outside the constraint, or another operation, the grant does not apply.
        denied(bob_decrypt(crm["ciphertext"].clone(), json!({ "app": "crm" })).await);
        let error = fails(
            keys.encrypt(
                &bob,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key_id, "plaintext": "x", "encryptionContext": { "app": "billing" } }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Constraints only fit context operations; unknown operations are refused.
        let signer = create_key(&f, &owner, json!({ "keySpec": "ed25519" })).await;
        let error = create_grant(
            owner.clone(),
            json!({
                "keyId": signer["id"],
                "granteeType": "identity",
                "granteeId": bob_id,
                "operations": ["sign"],
                "constraints": { "encryptionContextEquals": { "a": "b" } },
            }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_INPUT",
                "Encryption context constraints apply only to encrypt, decrypt and generate-data-key grants"
            )
        );
        let error = create_grant(
            owner.clone(),
            json!({ "keyId": signer["id"], "granteeType": "identity", "granteeId": bob_id, "operations": ["decrypt"] }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_INPUT",
                "A sign key's grants may allow read, sign, verify"
            )
        );

        // A grantor with the grant permission but without decrypt cannot hand out decrypt.
        let (_, carol) = member_with(
            &f,
            "carol",
            json!([{ "effect": "allow", "actions": ["iam:kms:grant", "iam:kms:encrypt", "iam:kms:read"], "resources": ["iam/kms/*"] }]),
        )
        .await;
        let error = create_grant(
            carol.clone(),
            json!({ "keyId": key_id, "granteeType": "identity", "granteeId": bob_id, "operations": ["decrypt"] }),
        )
        .await
        .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "ACCESS_DENIED",
                "You may not grant decrypt: you do not hold it"
            )
        );
        assert_matches(
            &create_grant(
                carol.clone(),
                json!({ "keyId": key_id, "granteeType": "identity", "granteeId": bob_id, "operations": ["encrypt"] }),
            )
            .await
            .unwrap(),
            json!({ "operations": ["encrypt"] }),
        );

        // Groups are not grantees (membership changes would move key access around unseen).
        let error = create_grant(
            owner.clone(),
            json!({ "keyId": key_id, "granteeType": "group", "granteeId": "some-group", "operations": ["decrypt"] }),
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        // The grantee's own explicit denies still win over a grant.
        let (dana_id, dana) = member_with(
            &f,
            "dana",
            json!([{
                "effect": "deny",
                "actions": ["iam:kms:decrypt"],
                "resources": ["iam/kms/*"],
                "conditions": { "StringEquals": { "resource.encryptionContext.record": "7" } },
            }]),
        )
        .await;
        create_grant(
            owner.clone(),
            json!({ "keyId": key_id, "granteeId": dana_id, "operations": ["decrypt"] }),
        )
        .await
        .unwrap();
        assert_matches(
            &decrypt(
                &f,
                &dana,
                json!({ "ciphertext": crm["ciphertext"], "encryptionContext": { "app": "crm" } }),
            )
            .await
            .unwrap(),
            json!({ "plaintext": "crm data" }),
        );
        denied(
            decrypt(
                &f,
                &dana,
                json!({ "ciphertext": sealed["ciphertext"], "encryptionContext": { "app": "billing", "record": "7" } }),
            )
            .await,
        );

        // The grantee can retire its own grant; others cannot.
        let error = fails(
            keys.retire_grant(
                &carol,
                body(with_tenant(&f, json!({ "grantId": grant["id"] }))),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        ok(keys
            .retire_grant(
                &bob,
                body(with_tenant(&f, json!({ "grantId": grant["id"] }))),
            )
            .await);
        assert_eq!(audit_of(&f, "kms:grant-retire").await.len(), 1);
        denied(
            bob_decrypt(
                sealed["ciphertext"].clone(),
                json!({ "app": "billing", "record": "7" }),
            )
            .await,
        );
        let grantees = |grants: Value| {
            let mut ids: Vec<String> = grants
                .as_array()
                .unwrap()
                .iter()
                .map(|item| item["granteeId"].as_str().unwrap().to_owned())
                .collect();
            ids.sort();
            ids
        };
        let mut expected = vec![bob_id.clone(), dana_id.clone()];
        expected.sort();
        assert_eq!(
            grantees(ok(keys
                .list_grants(&owner, body(with_tenant(&f, json!({ "keyId": key_id }))))
                .await)),
            expected
        );

        // Lapsed grants stop working and the maintenance job removes them.
        let brief = create_grant(
            owner.clone(),
            json!({
                "keyId": key_id,
                "granteeType": "identity",
                "granteeId": bob_id,
                "operations": ["decrypt"],
                "expiresAt": f.now() + 60_000.0,
            }),
        )
        .await
        .unwrap();
        f.advance(120_000.0);
        denied(
            bob_decrypt(
                sealed["ciphertext"].clone(),
                json!({ "app": "billing", "record": "7" }),
            )
            .await,
        );
        assert_eq!(
            f.iam.kms.maintain(None).await.unwrap()["grantsRemoved"],
            json!(1)
        );
        assert!(
            !ok(keys
                .list_grants(&owner, body(with_tenant(&f, json!({ "keyId": key_id }))))
                .await)
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["id"] == brief["id"])
        );
    });
}

#[test]
fn disables_schedules_deletion_cancels_and_destroys_keys() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({ "alias": "alias/old" })).await;
        let key_id = key["id"].clone();
        let sealed = encrypt(
            &f,
            &owner,
            json!({ "keyId": key_id, "plaintext": "soon unreadable" }),
        )
        .await;
        let by_id = || with_tenant(&f, json!({ "keyId": key_id }));
        ok(keys.disable(&owner, body(by_id())).await);
        let error = decrypt(&f, &owner, json!({ "ciphertext": sealed["ciphertext"] }))
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.status),
            ("KEY_STATE_INVALID", 409)
        );
        assert!(
            audit_of(&f, "iam:kms:decrypt")
                .await
                .iter()
                .any(|event| event["metadata"]["reason"] == "key-state")
        );
        ok(keys.enable(&owner, body(by_id())).await);
        assert_matches(
            &decrypt(&f, &owner, json!({ "ciphertext": sealed["ciphertext"] }))
                .await
                .unwrap(),
            json!({ "plaintext": "soon unreadable" }),
        );

        let error = fails(
            keys.schedule_deletion(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key_id, "waitingDays": 3 }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
        let pending = ok(keys
            .schedule_deletion(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key_id, "waitingDays": 7 }),
                )),
            )
            .await);
        assert_matches(
            &pending,
            json!({ "state": "pending-deletion", "deletionDate": n(f.now() + 7.0 * DAY) }),
        );
        let error = fails(keys.enable(&owner, body(by_id())).await);
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "KEY_STATE_INVALID",
                "A key that is pending deletion cannot be enabled"
            )
        );
        let restored = ok(keys.cancel_deletion(&owner, body(by_id())).await);
        assert_eq!(restored["state"], json!("disabled"));
        assert!(restored.get("deletionDate").is_none());

        ok(keys
            .schedule_deletion(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key_id, "waitingDays": 7 }),
                )),
            )
            .await);
        f.advance(6.0 * DAY);
        assert_eq!(
            f.iam.kms.maintain(None).await.unwrap()["destroyed"],
            json!([])
        );
        f.advance(2.0 * DAY);
        assert_eq!(
            f.iam.kms.maintain(None).await.unwrap()["destroyed"],
            json!([{ "tenantId": f.tenant_id, "keyId": key_id }])
        );
        let owner = f.session(&f.owner_id, false).await;
        for reference in [key_id.clone(), json!("alias/old")] {
            let error = fails(
                keys.get(&owner, body(with_tenant(&f, json!({ "keyId": reference }))))
                    .await,
            );
            assert_eq!(code(&error), "NOT_FOUND");
        }
        assert_eq!(
            decrypt(&f, &owner, json!({ "ciphertext": sealed["ciphertext"] }))
                .await
                .unwrap_err()
                .code,
            "NOT_FOUND"
        );
        assert!(
            f.find(
                "kmsKeyVersions",
                Filter::new().eq("tenantId", f.tenant_id.clone())
            )
            .await
            .is_empty()
        );
        assert!(
            audit_of(&f, "kms:key-destroy")
                .await
                .iter()
                .any(|event| event["actorId"] == "deployment-operator"
                    && event["metadata"]["keySpec"] == "aes-256-gcm")
        );
    });
}

#[test]
fn moves_aliases_between_keys_of_the_same_kind() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let first = create_key(&f, &owner, json!({ "alias": "alias/app" })).await;
        let second = create_key(&f, &owner, json!({})).await;
        let signer = create_key(&f, &owner, json!({ "keySpec": "ecc-p256" })).await;
        let error = fails(
            keys.create_alias(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "alias": "alias/app", "keyId": second["id"] }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "CONFLICT");
        let error = fails(
            keys.update_alias(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "alias": "alias/app", "keyId": signer["id"] }),
                )),
            )
            .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_INPUT",
                "An alias can only move to a key of the same kind and usage"
            )
        );
        ok(keys
            .update_alias(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "alias": "alias/app", "keyId": second["id"] }),
                )),
            )
            .await);
        let sealed = encrypt(
            &f,
            &owner,
            json!({ "keyId": "alias/app", "plaintext": "x" }),
        )
        .await;
        assert_eq!(sealed["keyId"], second["id"]);
        let aliases = ok(keys
            .list_aliases(&owner, body(with_tenant(&f, json!({}))))
            .await);
        assert_eq!(aliases.as_array().unwrap().len(), 1);
        assert_matches(
            &aliases[0],
            json!({ "name": "alias/app", "keyId": second["id"] }),
        );
        assert_eq!(
            ok(keys
                .get(
                    &owner,
                    body(with_tenant(&f, json!({ "keyId": first["id"] })))
                )
                .await)["aliases"],
            json!([])
        );
        ok(keys
            .delete_alias(
                &owner,
                body(with_tenant(&f, json!({ "alias": "alias/app" }))),
            )
            .await);
        let error = fails(
            keys.encrypt(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": "alias/app", "plaintext": "x" }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "NOT_FOUND");
        let error = fails(
            keys.create_alias(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "alias": "not-an-alias", "keyId": first["id"] }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "INVALID_INPUT");
    });
}

#[test]
fn reseals_key_material_when_the_deployment_secret_rotates_and_serves_http() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({})).await;
        let sealed = encrypt(
            &f,
            &owner,
            json!({ "keyId": key["id"], "plaintext": "survives rotation" }),
        )
        .await;
        let mut options = BetterIamOptions::new(
            f.store(),
            "a brand new deployment secret with 32+ chars",
            ORIGIN,
        );
        options.previous_secrets = Some(vec![SECRET.into()]);
        options.resolve_resource = Some(Arc::new(|reference| {
            Box::pin(async move { Ok(ResolvedResource::of(&reference)) })
        }));
        let at = f.now();
        options.authentication = Some(ServerAuthOptions {
            session_lifetime_ms: Some(7.0 * DAY),
            session_idle_timeout_ms: Some(7.0 * DAY),
            now: Some(Arc::new(move || at)),
            ..ServerAuthOptions::default()
        });
        let rotated = better_iam_server::better_iam(options).expect("valid options");
        let result = rotated
            .rotate_secrets(&better_iam_server::secrets::SecretRotationOptions::default())
            .await
            .unwrap();
        assert_eq!(result.resealed.get("kmsKeyVersions"), Some(&1.0));
        assert!(
            rotated
                .rotate_secrets(&better_iam_server::secrets::SecretRotationOptions {
                    dry_run: true,
                    ..Default::default()
                })
                .await
                .unwrap()
                .done
        );
        let token = owner.token.clone().unwrap();
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri(format!("{ORIGIN}/api/iam/keys/decrypt"))
            .header("content-type", "application/json")
            .header("x-better-iam", "1")
            .header("authorization", format!("Bearer {token}"))
            .body(Bytes::from(
                json!({ "tenantId": f.tenant_id, "ciphertext": sealed["ciphertext"] }).to_string(),
            ))
            .unwrap();
        let response = rotated.handler(request).await;
        assert_eq!(response.status().as_u16(), 200);
        let answer: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(answer["data"]["plaintext"], json!("survives rotation"));
    });
}

// ---- tests/kms-security.test.ts --------------------------------------------------------------------------------

#[test]
fn stops_a_grant_once_its_creator_loses_the_access_it_passed_on() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({})).await;
        let sealed = encrypt(
            &f,
            &owner,
            json!({ "keyId": key["id"], "plaintext": "payroll" }),
        )
        .await;
        // Gina's key access lasts an hour; she grants herself and Bob decrypt.
        let (gina_id, _, gina) =
            member_bound(&f, "gina", key_admin(), Some(f.now() + 3_600_000.0)).await;
        let (bob_id, bob) = member_with(&f, "bob", json!([])).await;
        for grantee in [&gina_id, &bob_id] {
            ok(keys
                .create_grant(
                    &gina,
                    body(with_tenant(
                        &f,
                        json!({ "keyId": key["id"], "granteeId": grantee, "operations": ["decrypt"] }),
                    )),
                )
                .await);
        }
        let ciphertext = json!({ "ciphertext": sealed["ciphertext"] });
        assert_matches(
            &decrypt(&f, &bob, ciphertext.clone()).await.unwrap(),
            json!({ "plaintext": "payroll" }),
        );
        f.advance(2.0 * 3_600_000.0);
        // Her binding expired: neither her self-grant nor Bob's grant works any more.
        let gina_again = f.sign_in(&gina_id).await;
        denied(decrypt(&f, &gina_again, ciphertext.clone()).await);
        denied(decrypt(&f, &bob, ciphertext.clone()).await);

        // Deleting the creator's binding does the same.
        let (_, hana_binding, hana) = member_bound(&f, "hana", key_admin(), None).await;
        let (ivan_id, ivan) = member_with(&f, "ivan", json!([])).await;
        ok(keys
            .create_grant(
                &hana,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key["id"], "granteeId": ivan_id, "operations": ["decrypt"] }),
                )),
            )
            .await);
        assert_matches(
            &decrypt(&f, &ivan, ciphertext.clone()).await.unwrap(),
            json!({ "plaintext": "payroll" }),
        );
        f.store()
            .transaction(|tx| async move { tx.delete("bindings", &hana_binding).await })
            .await
            .unwrap();
        denied(decrypt(&f, &ivan, ciphertext.clone()).await);
    });
}

#[test]
fn carries_the_creators_conditional_denies_into_every_use_of_a_grant() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({})).await;
        let secret = encrypt(
            &f,
            &owner,
            json!({ "keyId": key["id"], "plaintext": "TOP SECRET", "encryptionContext": { "class": "secret" } }),
        )
        .await;
        let internal = encrypt(
            &f,
            &owner,
            json!({ "keyId": key["id"], "plaintext": "internal", "encryptionContext": { "class": "internal" } }),
        )
        .await;
        let mut statements = key_admin();
        statements.as_array_mut().unwrap().push(json!({
            "effect": "deny",
            "actions": ["iam:kms:decrypt"],
            "resources": ["iam/kms/*"],
            "conditions": { "StringEquals": { "resource.encryptionContext.class": "secret" } },
        }));
        let (_, gina) = member_with(&f, "gina", statements).await;
        let (bob_id, bob) = member_with(&f, "bob", json!([])).await;
        ok(keys
            .create_grant(
                &gina,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key["id"], "granteeId": bob_id, "operations": ["decrypt"] }),
                )),
            )
            .await);
        assert_matches(
            &decrypt(
                &f,
                &bob,
                json!({ "ciphertext": internal["ciphertext"], "encryptionContext": { "class": "internal" } }),
            )
            .await
            .unwrap(),
            json!({ "plaintext": "internal" }),
        );
        denied(
            decrypt(
                &f,
                &bob,
                json!({ "ciphertext": secret["ciphertext"], "encryptionContext": { "class": "secret" } }),
            )
            .await,
        );
    });
}

#[test]
fn authorizes_alias_names_so_nobody_can_squat_on_a_name_others_use() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        // Mallory manages sandbox keys, and aliases under alias/sandbox/ only.
        let (_, mallory) = member_with(
            &f,
            "mallory",
            json!([
                {
                    "effect": "allow",
                    "actions": ["iam:kms:*"],
                    "resources": ["iam/kms", "iam/kms/*"],
                    "conditions": { "StringEquals": { "resource.tags.team": "sandbox" } },
                },
                { "effect": "allow", "actions": ["iam:kms:create"], "resources": ["iam/kms"] },
                { "effect": "allow", "actions": ["iam:kms:update"], "resources": ["iam/kms/alias/sandbox/*"] },
            ]),
        )
        .await;
        let own = create_key(&f, &mallory, json!({ "tags": { "team": "sandbox" } })).await;
        let error = fails(
            keys.create_alias(
                &mallory,
                body(with_tenant(
                    &f,
                    json!({ "alias": "alias/prod/payments", "keyId": own["id"] }),
                )),
            )
            .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "ACCESS_DENIED",
                "You may not manage the alias alias/prod/payments"
            )
        );
        let error = fails(
            keys.create(
                &mallory,
                body(with_tenant(
                    &f,
                    json!({ "tags": { "team": "sandbox" }, "alias": "alias/prod/billing" }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        assert_matches(
            &ok(keys
                .create_alias(
                    &mallory,
                    body(with_tenant(
                        &f,
                        json!({ "alias": "alias/sandbox/test", "keyId": own["id"] }),
                    )),
                )
                .await),
            json!({ "name": "alias/sandbox/test" }),
        );
    });
}

struct Spy(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl PluginHooks for Spy {
    async fn after_operation(&self, _input: &OperationHookInput, result: &Value) -> IamResult<()> {
        self.0.lock().unwrap().push(result.clone());
        Ok(())
    }
}

struct SpyPlugin(Arc<Mutex<Vec<Value>>>);

#[async_trait::async_trait]
impl IamPlugin for SpyPlugin {
    fn id(&self) -> &str {
        "spy"
    }
    fn hooks(&self) -> Option<Arc<dyn PluginHooks>> {
        Some(Arc::new(Spy(self.0.clone())))
    }
}

#[test]
fn never_shows_plaintexts_data_keys_or_tokens_to_plugins() {
    run(|| async {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let plugin = SpyPlugin(seen.clone());
        let f = organization(move |options| options.plugins = Some(vec![Arc::new(plugin)])).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({})).await;
        let sealed = encrypt(
            &f,
            &owner,
            json!({ "keyId": key["id"], "plaintext": "hunter2" }),
        )
        .await;
        decrypt(&f, &owner, json!({ "ciphertext": sealed["ciphertext"] }))
            .await
            .unwrap();
        let data_key = ok(keys
            .generate_data_key(&owner, body(with_tenant(&f, json!({ "keyId": key["id"] }))))
            .await);
        let signer = create_key(&f, &owner, json!({ "keySpec": "ed25519" })).await;
        let jwt = ok(keys
            .sign_jwt(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": signer["id"], "claims": { "sub": "x" } }),
                )),
            )
            .await);
        let seen = seen.lock().unwrap().clone();
        let text = json!(seen).to_string();
        assert!(!text.contains("hunter2"));
        assert!(!text.contains(data_key["plaintextBase64"].as_str().unwrap()));
        assert!(!text.contains(jwt["token"].as_str().unwrap()));
        assert!(seen.len() > 3);
    });
}

#[test]
fn answers_callers_from_other_tenants_the_same_whether_a_key_exists_or_not() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let key = create_key(
            &f,
            &f.owner_credential,
            json!({ "keySpec": "ecc-p256", "alias": "alias/signing" }),
        )
        .await;
        let (_, _, globex) = f
            .activate(
                &f.root_tenant.clone(),
                "Globex",
                "organization",
                "owner@globex.test",
            )
            .await;
        for (key_id, algorithm) in [
            (key["id"].clone(), None),
            (json!("alias/signing"), None),
            (json!("alias/missing"), None),
            (key["id"].clone(), Some("RS256")),
        ] {
            let mut input = json!({ "keyId": key_id, "message": "x" });
            if let Some(algorithm) = algorithm {
                input["algorithm"] = json!(algorithm);
            }
            let error = fails(keys.sign(&globex, body(with_tenant(&f, input))).await);
            assert_eq!(
                (error.code.as_str(), error.message.as_str()),
                ("ACCESS_DENIED", "Access denied")
            );
        }
    });
}

#[test]
fn lets_policies_limit_the_tokens_a_caller_may_mint_apart_from_raw_signatures() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let signer = create_key(&f, &f.owner_credential, json!({ "keySpec": "ecc-p256" })).await;
        let (_, minter) = member_with(
            &f,
            "minter",
            json!([{
                "effect": "allow",
                "actions": ["iam:kms:sign"],
                "resources": ["iam/kms/*"],
                "conditions": {
                    "Bool": { "resource.jwt": true },
                    "StringEquals": { "resource.jwt.iss": "https://acme.test" },
                },
            }]),
        )
        .await;
        assert_matches(
            &ok(keys
                .sign_jwt(
                    &minter,
                    body(with_tenant(
                        &f,
                        json!({ "keyId": signer["id"], "claims": { "iss": "https://acme.test", "sub": "svc" } }),
                    )),
                )
                .await),
            json!({ "algorithm": "ES256" }),
        );
        let error = fails(
            keys.sign_jwt(
                &minter,
                body(with_tenant(
                    &f,
                    json!({ "keyId": signer["id"], "claims": { "iss": "https://evil.test", "sub": "svc" } }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        let error = fails(
            keys.sign(
                &minter,
                body(with_tenant(
                    &f,
                    json!({ "keyId": signer["id"], "message": "x" }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
    });
}

#[test]
fn refuses_tokens_with_critical_headers_or_malformed_times_and_non_canonical_encodings() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let hmac = create_key(&f, &owner, json!({ "keySpec": "hmac-sha256" })).await;
        let hmac_id = hmac["id"].as_str().unwrap().to_owned();
        let mac_of = |message: String| {
            let keys = keys.clone();
            let input = with_tenant(&f, json!({ "keyId": hmac_id, "message": message }));
            let owner = owner.clone();
            async move {
                ok(keys.generate_mac(&owner, body(input)).await)["mac"]
                    .as_str()
                    .unwrap()
                    .to_owned()
            }
        };
        let sign = |header: Value, claims: Value| {
            let mut full = json!({ "alg": "HS256", "kid": format!("{hmac_id}.1") });
            for (name, value) in header.as_object().unwrap() {
                full[name] = value.clone();
            }
            let input = format!(
                "{}.{}",
                b64url(full.to_string()),
                b64url(claims.to_string())
            );
            let mac = mac_of(input.clone());
            async move { format!("{input}.{}", mac.await) }
        };
        let verify = |token: String| {
            let keys = keys.clone();
            let input = with_tenant(&f, json!({ "token": token }));
            let owner = owner.clone();
            async move { ok(keys.verify_jwt(&owner, body(input)).await) }
        };
        assert_matches(
            &verify(sign(json!({}), json!({ "sub": "ok" })).await).await,
            json!({ "valid": true }),
        );
        assert_matches(
            &verify(sign(json!({ "crit": ["exp"] }), json!({ "sub": "x" })).await).await,
            json!({ "valid": false, "reason": "header" }),
        );
        assert_matches(
            &verify(sign(json!({}), json!({ "exp": "9999999999" })).await).await,
            json!({ "valid": false, "reason": "claims" }),
        );
        // A MAC spelled with non-canonical trailing bits is not accepted as the same MAC.
        let mac = mac_of("m".into()).await;
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let last = mac.chars().last().unwrap();
        let index = alphabet.find(last).unwrap() ^ 1;
        let twin = format!("{}{}", &mac[..mac.len() - 1], &alphabet[index..index + 1]);
        assert_eq!(
            better_iam_auth::util::node_base64_decode(&twin),
            better_iam_auth::util::node_base64_decode(&mac)
        );
        let error = fails(
            keys.verify_mac(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": hmac_id, "message": "m", "mac": twin }),
                )),
            )
            .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_INPUT", "mac must be canonical base64")
        );
    });
}

/// `kmsEncryptFor(ctx, tx, tenantId, keyRef, plaintext, context, use)` in a transaction of its own.
async fn seal(
    f: &Org,
    key_ref: &str,
    plaintext: &str,
    context: Value,
    r#use: Option<Value>,
) -> IamResult<Value> {
    let ctx = f.iam.ctx.clone();
    let tenant = f.tenant_id.clone();
    let (key_ref, plaintext) = (key_ref.to_owned(), plaintext.to_owned());
    f.store()
        .transaction(move |tx| async move {
            kms_encrypt_for(
                &ctx,
                &tx,
                &tenant,
                &key_ref,
                &plaintext,
                &context,
                r#use.as_ref(),
            )
            .await
        })
        .await
}

/// `kmsDecryptFor(ctx, tx, tenantId, sealed, context, use)` in a transaction of its own.
async fn unseal(f: &Org, sealed: Value, context: Value, r#use: Option<Value>) -> IamResult<String> {
    let ctx = f.iam.ctx.clone();
    let tenant = f.tenant_id.clone();
    f.store()
        .transaction(move |tx| async move {
            kms_decrypt_for(&ctx, &tx, &tenant, &sealed, &context, r#use.as_ref()).await
        })
        .await
}

#[test]
fn protects_stored_values_of_any_size_under_an_aes_key_only_service_helpers() {
    run(|| async {
        let f = organization(|_| {}).await;
        let owner = f.owner_credential.clone();
        let aes = create_key(&f, &owner, json!({ "alias": "alias/vault" })).await;
        let rsa = create_key(
            &f,
            &owner,
            json!({ "keySpec": "rsa-2048", "keyUsage": "encrypt" }),
        )
        .await;
        let vault = json!({ "via": "vault" });
        let large = format!("{} and a tail", "x".repeat(200_000));
        let context = json!("secret-1");
        let sealed = seal(
            &f,
            "alias/vault",
            &large,
            context.clone(),
            Some(vault.clone()),
        )
        .await
        .unwrap();
        assert_eq!(sealed["keyId"], aes["id"]);
        // Neither the plaintext nor its base64url encoding shows through. The
        // ciphertext is ~267k random base64url characters, so a short marker
        // such as "tail" would turn up by chance (~1.6% of runs). " and a tail"
        // contains spaces, which base64url never produces, and "eHh4" is the
        // encoding of "xxx" at any alignment, so 64 characters of it cannot
        // occur by chance.
        let ciphertext = sealed["ciphertext"].as_str().unwrap();
        assert!(!ciphertext.contains(" and a tail"));
        assert!(!ciphertext.contains(&"x".repeat(64)));
        assert!(!ciphertext.contains(&"eHh4".repeat(16)));
        assert_eq!(
            unseal(&f, sealed.clone(), context.clone(), Some(vault.clone()))
                .await
                .unwrap(),
            large
        );
        let error = unseal(&f, sealed.clone(), json!("secret-2"), Some(vault.clone()))
            .await
            .unwrap_err();
        assert_eq!(error.code, "INVALID_CIPHERTEXT");
        // The payload cannot be moved under another wrapped data key.
        let other = seal(
            &f,
            aes["id"].as_str().unwrap(),
            "other",
            context.clone(),
            None,
        )
        .await
        .unwrap();
        let wrapped = other["ciphertext"]
            .as_str()
            .unwrap()
            .split('~')
            .next()
            .unwrap()
            .to_owned();
        let payload = sealed["ciphertext"]
            .as_str()
            .unwrap()
            .split('~')
            .nth(1)
            .unwrap()
            .to_owned();
        let error = unseal(
            &f,
            json!({ "ciphertext": format!("{wrapped}~{payload}") }),
            context.clone(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_CIPHERTEXT");
        // A ciphertext that names another key than the one it carries is refused.
        let error = unseal(
            &f,
            json!({ "ciphertext": sealed["ciphertext"], "keyId": rsa["id"] }),
            context.clone(),
            None,
        )
        .await
        .unwrap_err();
        assert_eq!(error.code, "INVALID_CIPHERTEXT");
        let error = seal(&f, rsa["id"].as_str().unwrap(), "x", context.clone(), None)
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "INVALID_INPUT",
                "Only aes-256-gcm keys can protect stored values"
            )
        );
        // Without a principal the uses are audited as the deployment operator, with `via`.
        let mut audited: Vec<(String, Value)> = f
            .find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
            .await
            .into_iter()
            .filter(|event| event["actorId"] == "deployment-operator")
            .map(|event| {
                (
                    event["action"].as_str().unwrap().to_owned(),
                    Value::Object(event.clone())["metadata"]["via"].clone(),
                )
            })
            .collect();
        // The store lists events by id: compare them as a set.
        audited.sort_by(|a, b| (&a.0, a.1.to_string()).cmp(&(&b.0, b.1.to_string())));
        assert_eq!(
            audited,
            vec![
                ("iam:kms:decrypt".to_owned(), json!("vault")),
                ("iam:kms:encrypt".to_owned(), json!("service")),
                ("iam:kms:encrypt".to_owned(), json!("vault")),
            ]
        );
        // With a principal, the caller is the actor.
        let principal = f
            .iam
            .ctx
            .principals()
            .unwrap()
            .authenticate(&owner)
            .await
            .unwrap();
        let acting = json!({
            "via": "vault",
            "principal": better_iam_server::conformance::principal_json(&principal),
        });
        seal(
            &f,
            "alias/vault",
            "x",
            json!({ "secret": "s" }),
            Some(acting),
        )
        .await
        .unwrap();
        assert!(
            audit_of(&f, "iam:kms:encrypt")
                .await
                .iter()
                .any(|event| event["actorId"] == json!(f.owner_id)
                    && event["metadata"]["via"] == "vault"
                    && event["metadata"]["encryptionContextKeys"] == json!(["secret"]))
        );
        let _ = KmsServiceUse {
            via: "vault".into(),
            principal: Some(principal),
        };
    });
}

#[test]
fn opens_one_call_per_confirmation_for_an_agent_acting_for_a_person() {
    run(|| async {
        let f = organization(|_| {}).await;
        let api = f.iam.api.clone();
        let owner = f.owner_credential.clone();
        let (_, alice) = member_with(
            &f,
            "alice",
            json!([{ "effect": "allow", "actions": ["iam:kms:encrypt", "iam:kms:decrypt"], "resources": ["iam/kms/*"] }]),
        )
        .await;
        let key = create_key(&f, &owner, json!({})).await;
        let ciphertext = encrypt(
            &f,
            &alice,
            json!({ "keyId": key["id"], "plaintext": "record-1" }),
        )
        .await["ciphertext"]
            .clone();
        let agent = ok(api
            .agents
            .create(&owner, body(with_tenant(&f, json!({ "name": "Helper" }))))
            .await);
        let agent_key = ok(api
            .credentials
            .create(
                &owner,
                body(with_tenant(&f, json!({ "identityId": agent["id"] }))),
            )
            .await);
        let delegation = ok(api
            .delegations
            .grant(
                &alice,
                body(with_tenant(
                    &f,
                    json!({ "agentId": agent["id"], "scopes": ["iam:kms:decrypt"], "confirm": ["iam:kms:decrypt"] }),
                )),
            )
            .await);
        let assumed = ok(api
            .delegations
            .assume(
                &bearer(agent_key["token"].as_str().unwrap()),
                body(with_tenant(&f, json!({ "delegationId": delegation["id"] }))),
            )
            .await);
        let acting = bearer(assumed["token"].as_str().unwrap());
        let open = || decrypt(&f, &acting, json!({ "ciphertext": ciphertext }));
        denied(open().await);
        let request = ok(api
            .delegations
            .request_confirmation(
                &acting,
                body(with_tenant(
                    &f,
                    json!({
                        "action": "iam:kms:decrypt",
                        "resource": { "type": "iam", "id": format!("kms/{}", key["id"].as_str().unwrap()) },
                        "reason": "Decrypt one record for you",
                        "validSeconds": 3600,
                    }),
                )),
            )
            .await);
        ok(api
            .delegations
            .decide_confirmation(
                &alice,
                body(with_tenant(
                    &f,
                    json!({ "confirmationId": request["id"], "approve": true }),
                )),
            )
            .await);
        assert_matches(&open().await.unwrap(), json!({ "plaintext": "record-1" }));
        // The approval is used up: the next decrypt needs another one.
        denied(open().await);
        let confirmations = ok(api
            .delegations
            .list_confirmations(&alice, body(with_tenant(&f, json!({}))))
            .await);
        let listed = confirmations
            .as_array()
            .cloned()
            .or_else(|| confirmations["confirmations"].as_array().cloned())
            .unwrap_or_default();
        assert_eq!(
            listed
                .iter()
                .find(|item| item["id"] == request["id"])
                .unwrap()["status"],
            json!("used")
        );
    });
}

#[test]
fn never_lets_a_change_of_tags_or_aliases_open_a_key_to_the_one_making_it() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let key = create_key(&f, &owner, json!({ "tags": { "team": "payments" } })).await;
        let ciphertext = encrypt(
            &f,
            &owner,
            json!({ "keyId": key["id"], "plaintext": "card on file: 4242" }),
        )
        .await["ciphertext"]
            .clone();
        // Manages every key, decrypts only the search team's, and never under a production alias.
        let (_, operator) = member_with(
            &f,
            "keyops",
            json!([
                { "effect": "allow", "actions": ["iam:kms:update", "iam:kms:read"], "resources": ["iam/kms/*"] },
                {
                    "effect": "allow",
                    "actions": ["iam:kms:decrypt"],
                    "resources": ["iam/kms/*"],
                    "conditions": { "StringEquals": { "resource.tags.team": "search" } },
                },
                {
                    "effect": "deny",
                    "actions": ["iam:kms:decrypt"],
                    "resources": ["iam/kms/*"],
                    "conditions": { "ArrayContains": { "resource.aliases": "alias/prod-search" } },
                },
            ]),
        )
        .await;
        let error = fails(
            keys.update(
                &operator,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key["id"], "tags": { "team": "search" } }),
                )),
            )
            .await,
        );
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            (
                "ACCESS_DENIED",
                "That change would give you iam:kms:decrypt on this key"
            )
        );
        denied(decrypt(&f, &operator, json!({ "ciphertext": ciphertext })).await);
        // Tags that open nothing new are fine.
        assert_matches(
            &ok(keys
                .update(
                    &operator,
                    body(with_tenant(
                        &f,
                        json!({ "keyId": key["id"], "tags": { "team": "payments", "owner": "ops" } }),
                    )),
                )
                .await),
            json!({ "tags": { "team": "payments", "owner": "ops" } }),
        );
        // A search key under a production alias: dropping the alias would lift the deny.
        let search = create_key(
            &f,
            &owner,
            json!({ "tags": { "team": "search" }, "alias": "alias/prod-search" }),
        )
        .await;
        let error = fails(
            keys.delete_alias(
                &operator,
                body(with_tenant(&f, json!({ "alias": "alias/prod-search" }))),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        // Moving it away would too; the owner may.
        let spare = create_key(&f, &owner, json!({ "tags": { "team": "payments" } })).await;
        let error = fails(
            keys.update_alias(
                &operator,
                body(with_tenant(
                    &f,
                    json!({ "alias": "alias/prod-search", "keyId": spare["id"] }),
                )),
            )
            .await,
        );
        assert_eq!(code(&error), "ACCESS_DENIED");
        ok(keys
            .delete_alias(
                &owner,
                body(with_tenant(&f, json!({ "alias": "alias/prod-search" }))),
            )
            .await);
        assert_eq!(
            ok(keys
                .get(
                    &operator,
                    body(with_tenant(&f, json!({ "keyId": search["id"] })))
                )
                .await)["aliases"],
            json!([])
        );
    });
}

// ---- mixed fleet ----------------------------------------------------------------------------------------------

/// Keys whose material the TypeScript implementation generated and sealed: the Rust server decrypts, verifies and
/// signs with them, and what it signs verifies with the stored public key.
#[test]
fn uses_key_material_ciphertexts_and_signatures_made_by_the_typescript_implementation() {
    run(|| async {
        let vectors: Value =
            serde_json::from_str(include_str!("fixtures/kms_node_vectors.json")).unwrap();
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        for (name, spec, usage) in [
            ("aes", "aes-256-gcm", "encrypt"),
            ("hmac", "hmac-sha256", "mac"),
            ("p256", "ecc-p256", "sign"),
            ("ed25519", "ed25519", "sign"),
            ("rsa", "rsa-2048", "sign"),
            ("rsaEnc", "rsa-2048", "encrypt"),
        ] {
            let key_id = if name == "rsaEnc" {
                "node-rsa-enc".to_owned()
            } else {
                format!("node-{name}")
            };
            f.insert(
                "kmsKeys",
                json!({
                    "id": key_id,
                    "tenantId": f.tenant_id,
                    "keySpec": spec,
                    "keyUsage": usage,
                    "state": "enabled",
                    "currentVersion": 1,
                    "tags": {},
                    "createdAt": n(f.now()),
                    "createdBy": f.owner_id,
                    "updatedAt": n(f.now()),
                }),
            )
            .await;
            let mut version = json!({
                "id": better_iam_server::utils::id(),
                "tenantId": f.tenant_id,
                "uniqueKey": format!("{key_id}:1"),
                "keyId": key_id,
                "version": 1,
                "wrapper": "secret",
                "materialSealed": vectors[name]["material"],
                "createdAt": n(f.now()),
                "origin": "create",
            });
            if let Some(pem) = vectors[name].get("publicKeyPem") {
                version["publicKeyPem"] = pem.clone();
            }
            f.insert("kmsKeyVersions", version).await;
        }
        assert_eq!(
            decrypt(
                &f,
                &owner,
                json!({ "ciphertext": vectors["aes"]["ciphertext"], "encryptionContext": { "app": "billing" } })
            )
            .await
            .unwrap()["plaintext"],
            json!("from node")
        );
        assert_eq!(
            decrypt(
                &f,
                &owner,
                json!({ "ciphertext": vectors["rsaEnc"]["ciphertext"] })
            )
            .await
            .unwrap()["plaintext"],
            json!("oaep from node")
        );
        assert_eq!(
            ok(keys
                .verify_mac(
                    &owner,
                    body(with_tenant(
                        &f,
                        json!({ "keyId": "node-hmac", "message": "hello", "mac": vectors["hmac"]["mac"] }),
                    )),
                )
                .await)["valid"],
            json!(true)
        );
        for name in ["p256", "ed25519", "rsa"] {
            let key_id = format!("node-{name}");
            assert_eq!(
                ok(keys
                    .verify(
                        &owner,
                        body(with_tenant(
                            &f,
                            json!({ "keyId": key_id, "message": "hello", "signature": vectors[name]["signature"] }),
                        )),
                    )
                    .await)["valid"],
                json!(true),
                "{name} signature from node"
            );
            let signed = ok(keys
                .sign(
                    &owner,
                    body(with_tenant(
                        &f,
                        json!({ "keyId": key_id, "message": "from rust" }),
                    )),
                )
                .await);
            assert_eq!(
                ok(keys
                    .verify(
                        &owner,
                        body(with_tenant(
                            &f,
                            json!({ "keyId": key_id, "message": "from rust", "signature": signed["signature"] }),
                        )),
                    )
                    .await)["valid"],
                json!(true),
                "{name} signature from rust"
            );
        }
        // The fingerprint of a version is the first 16 characters of the base64url SHA-256 of its public PEM.
        let versions = ok(keys
            .list_versions(
                &owner,
                body(with_tenant(&f, json!({ "keyId": "node-p256" }))),
            )
            .await);
        let pem = vectors["p256"]["publicKeyPem"].as_str().unwrap();
        let digest = {
            use sha2::Digest;
            b64url(sha2::Sha256::digest(pem.as_bytes()))
        };
        assert_eq!(versions[0]["publicKeyFingerprint"], json!(&digest[..16]));
    });
}

// ---- validation -------------------------------------------------------------------------------------------------

#[test]
fn validates_inputs_before_anything_is_looked_up() {
    run(|| async {
        let f = organization(|_| {}).await;
        let keys = f.iam.api.keys.clone();
        let owner = f.owner_credential.clone();
        let message = |result: IamResult<Value>| result.unwrap_err().message;
        let create = |input: Value| {
            let keys = keys.clone();
            let input = with_tenant(&f, input);
            let owner = owner.clone();
            async move {
                keys.create(&owner, body(input))
                    .await
                    .map(|reply| reply.into_value().unwrap())
            }
        };
        assert_eq!(
            message(create(json!({ "keySpec": "aes-128" })).await),
            "keySpec must be one of aes-256-gcm, hmac-sha256, hmac-sha384, hmac-sha512, ecc-p256, ecc-p384, ed25519, rsa-2048, rsa-3072, rsa-4096"
        );
        assert_eq!(
            message(create(json!({ "keySpec": "ecc-p256", "keyUsage": "encrypt" })).await),
            "ecc-p256 keys support keyUsage sign"
        );
        assert_eq!(
            message(create(json!({ "tags": { "bad key": "x" } })).await),
            "Invalid tag key bad key"
        );
        assert_eq!(
            message(create(json!({ "tags": { "team": 1 } })).await),
            "Tag team must be a string of at most 256 characters"
        );
        assert_eq!(
            message(create(json!({ "alias": "alias/" })).await),
            "alias must be alias/{name} with letters, digits, slashes, underscores or hyphens"
        );
        assert_eq!(
            message(create(json!({ "rotationPeriodDays": 0 })).await),
            "Invalid rotationPeriodDays"
        );
        let key = create(json!({})).await.unwrap();
        let encrypt_input = |input: Value| {
            let keys = keys.clone();
            let mut input = with_tenant(&f, input);
            input["keyId"] = key["id"].clone();
            let owner = owner.clone();
            async move {
                keys.encrypt(&owner, body(input))
                    .await
                    .map(|reply| reply.into_value().unwrap())
            }
        };
        assert_eq!(
            message(encrypt_input(json!({})).await),
            "Provide either plaintext or plaintextBase64"
        );
        assert_eq!(
            message(encrypt_input(json!({ "plaintext": "a", "plaintextBase64": "YQ" })).await),
            "Provide either plaintext or plaintextBase64"
        );
        assert_eq!(
            message(encrypt_input(json!({ "plaintext": 1 })).await),
            "plaintext must be a string"
        );
        assert_eq!(
            message(encrypt_input(json!({ "plaintext": "x".repeat(4097) })).await),
            "plaintext is longer than 4096 bytes"
        );
        assert_eq!(
            message(
                encrypt_input(json!({ "plaintext": "x", "encryptionContext": { "k": "" } })).await
            ),
            "encryptionContext values must be non-empty strings of at most 1024 characters"
        );
        assert_eq!(
            message(
                encrypt_input(
                    json!({ "plaintext": "x", "encryptionContext": { "__proto__": "v" } })
                )
                .await
            ),
            "Invalid encryptionContext key __proto__"
        );
        let error = decrypt(&f, &owner, json!({ "ciphertext": "kms1.x.1.t" }))
            .await
            .unwrap_err();
        assert_eq!(
            (error.code.as_str(), error.message.as_str()),
            ("INVALID_CIPHERTEXT", "The ciphertext is not valid")
        );
        // A non-canonical ciphertext spelling is refused before any lookup.
        let sealed = encrypt(&f, &owner, json!({ "keyId": key["id"], "plaintext": "x" })).await;
        let text = sealed["ciphertext"].as_str().unwrap();
        let payload = text.rsplit('.').next().unwrap();
        let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
        let last = payload.chars().last().unwrap();
        let index = alphabet.find(last).unwrap() ^ 1;
        let twin = format!("{}{}", &text[..text.len() - 1], &alphabet[index..index + 1]);
        if better_iam_auth::util::node_base64_decode(&twin[text.len() - payload.len()..])
            == better_iam_auth::util::node_base64_decode(payload)
        {
            assert_eq!(
                decrypt(&f, &owner, json!({ "ciphertext": twin }))
                    .await
                    .unwrap_err()
                    .code,
                "INVALID_CIPHERTEXT"
            );
        }
        let error = fails(
            keys.list(&owner, body(with_tenant(&f, json!({ "state": "gone" }))))
                .await,
        );
        assert_eq!(error.message, "Invalid state");
        let error = fails(
            keys.sign(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "keyId": key["id"], "message": "x", "format": "pem" }),
                )),
            )
            .await,
        );
        assert_eq!(error.message, "format must be der or jose");
        let error = fails(
            keys.verify_jwt(&owner, body(with_tenant(&f, json!({ "token": "a.b" }))))
                .await,
        );
        assert_eq!(error.message, "token must be a compact JWS");
        let error = fails(
            keys.verify_jwt(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "token": format!("{}.{}.", b64url("{}"), b64url("{}")) }),
                )),
            )
            .await,
        );
        assert_eq!(error.message, "The token has no KMS kid; pass keyId");
        let error = fails(
            keys.verify_jwt(
                &owner,
                body(with_tenant(
                    &f,
                    json!({ "token": format!("{}.{}.", b64url("[1]"), b64url("{}")) }),
                )),
            )
            .await,
        );
        assert_eq!(error.message, "The token header is not valid JSON");
    });
}
