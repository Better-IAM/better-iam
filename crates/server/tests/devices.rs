//! The `devices` API group and device posture: ported from tests/device-posture.test.ts and
//! tests/device-proof.test.ts. The TypeScript tests prove device keys with the client package's `createDeviceProver`;
//! here a small prover signs the same proofs (compact JWS, `typ: device-proof+jwt`, `kid` = the key's RFC 7638
//! thumbprint, over `{ iat, sid }`). The browser key store case of device-posture.test.ts tests the client package
//! (IndexedDB), which has no Rust counterpart in the server crate.

mod organization_fixture;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{CredentialInput, Filter, IamStoreExt};
use better_iam_server::options::{AuthorizationRequest, ResourceTarget};
use bytes::Bytes;
use http::Method;
use organization_fixture::{
    ORIGIN, Org, assert_matches, bearer, body, code, fails, ok, organization, run,
};
use p256::ecdsa::signature::Signer;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

const HOUR: f64 = 3_600_000.0;

fn b64(bytes: impl AsRef<[u8]>) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

fn sha256_b64(text: &str) -> String {
    b64(Sha256::digest(text.as_bytes()))
}

/// A device key that signs proofs: EC P-256 (ES256) or Ed25519 (EdDSA).
enum DeviceKey {
    Ec(p256::ecdsa::SigningKey),
    Ed(ed25519_dalek::SigningKey),
}

struct Prover {
    key: DeviceKey,
    jwk: Value,
    kid: String,
}

impl Prover {
    /// `generateKeyPair('ES256')`, the public JWK and its thumbprint.
    fn ec() -> Self {
        let key = loop {
            if let Ok(key) = p256::ecdsa::SigningKey::from_slice(&rand::random::<[u8; 32]>()) {
                break key;
            }
        };
        let point = key.verifying_key().to_encoded_point(false);
        let (x, y) = (b64(point.x().unwrap()), b64(point.y().unwrap()));
        let kid = sha256_b64(&format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{x}","y":"{y}"}}"#
        ));
        Prover {
            key: DeviceKey::Ec(key),
            jwk: json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y }),
            kid,
        }
    }

    /// `generateKeyPair('EdDSA', { crv: 'Ed25519' })`.
    fn ed() -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(&rand::random::<[u8; 32]>());
        let x = b64(key.verifying_key().to_bytes());
        let kid = sha256_b64(&format!(r#"{{"crv":"Ed25519","kty":"OKP","x":"{x}"}}"#));
        Prover {
            key: DeviceKey::Ed(key),
            jwk: json!({ "kty": "OKP", "crv": "Ed25519", "x": x }),
            kid,
        }
    }

    fn alg(&self) -> &'static str {
        match self.key {
            DeviceKey::Ec(_) => "ES256",
            DeviceKey::Ed(_) => "EdDSA",
        }
    }

    /// A compact JWS over `payload` with the given protected header, signed with this key.
    fn sign(&self, header: &Value, payload: &Value) -> String {
        let input = format!("{}.{}", b64(header.to_string()), b64(payload.to_string()));
        let signature = match &self.key {
            DeviceKey::Ec(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input.as_bytes());
                signature.to_bytes().to_vec()
            }
            DeviceKey::Ed(key) => key.sign(input.as_bytes()).to_bytes().to_vec(),
        };
        format!("{input}.{}", b64(signature))
    }

    fn header(&self) -> Value {
        json!({ "alg": self.alg(), "typ": "device-proof+jwt", "kid": self.kid })
    }

    /// The proof `prover.headers(sessionId)` sends, issued at `now_ms`.
    fn proof(&self, session_id: &str, now_ms: f64) -> String {
        self.sign(
            &self.header(),
            &json!({ "iat": (now_ms / 1000.0).floor() as i64, "sid": session_id }),
        )
    }
}

/// A signed-in person: the bearer token and the session id.
struct SignedIn {
    token: String,
    session_id: String,
}

async fn sign_in(f: &Org, identity_id: &str) -> SignedIn {
    let credential = f.sign_in(identity_id).await;
    let principal = f.iam.authenticate(&credential).await.expect("session");
    SignedIn {
        token: credential.token.unwrap(),
        session_id: principal.session.id,
    }
}

/// `{ headers: { authorization: 'Bearer …', 'x-better-iam-device': proof } }`.
fn with_proof(token: &str, proof: &str) -> CredentialInput {
    CredentialInput {
        headers: Some(vec![
            ("authorization".into(), format!("Bearer {token}")),
            ("x-better-iam-device".into(), proof.to_owned()),
        ]),
        token: None,
    }
}

fn headers_only(token: &str) -> CredentialInput {
    CredentialInput {
        headers: Some(vec![("authorization".into(), format!("Bearer {token}"))]),
        token: None,
    }
}

fn compliant_only() -> Value {
    json!([{
        "effect": "allow",
        "actions": ["documents:read"],
        "resources": ["*"],
        "conditions": { "Bool": { "request.deviceCompliant": true } },
    }])
}

/// `setup()`: alice with a role that reads documents only from a compliant device, signed in, with a prover.
struct Setup {
    f: Org,
    alice: String,
    signed_in: SignedIn,
    prover: Prover,
}

impl Setup {
    async fn new() -> Self {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let signed_in = sign_in(&f, &alice).await;
        f.grant(&alice, compliant_only()).await;
        Setup {
            f,
            alice,
            signed_in,
            prover: Prover::ec(),
        }
    }

    fn credential(&self) -> CredentialInput {
        bearer(&self.signed_in.token)
    }

    /// `withDevice(sessionId)`.
    fn with_device_for(&self, session_id: &str) -> CredentialInput {
        with_proof(
            &self.signed_in.token,
            &self.prover.proof(session_id, self.f.now()),
        )
    }

    fn with_device(&self) -> CredentialInput {
        self.with_device_for(&self.signed_in.session_id)
    }

    async fn can_read(&self, credential: CredentialInput) -> bool {
        self.f
            .iam
            .authorize(&AuthorizationRequest {
                credential,
                tenant_id: self.f.tenant_id.clone(),
                action: "documents:read".into(),
                resource: ResourceTarget {
                    kind: "document".into(),
                    id: "d1".into(),
                },
            })
            .await
            .expect("decision")
            .allowed
    }

    async fn enroll(&self, credential: &CredentialInput, input: Value) -> Value {
        ok(self.f.iam.api.devices.enroll(credential, body(input)).await)
    }

    async fn check(&self, credential: &CredentialInput) -> Value {
        ok(self
            .f
            .iam
            .api
            .devices
            .check(credential, body(json!({ "tenantId": self.f.tenant_id })))
            .await)
    }
}

async fn audit_actions(f: &Org, action: &str) -> Vec<Value> {
    f.find("audit", Filter::new().eq("tenantId", f.tenant_id.clone()))
        .await
        .into_iter()
        .filter(|event| event["action"] == action)
        .map(Value::Object)
        .collect()
}

#[test]
fn enrolls_a_device_key_verifies_proofs_bound_to_the_session_and_reports_assurance() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let enrolled = s
            .enroll(
                &s.with_device(),
                json!({
                    "tenantId": f.tenant_id,
                    "name": "Alice laptop",
                    "platform": "macos",
                    "publicKey": s.prover.jwk,
                }),
            )
            .await;
        assert_eq!(enrolled["keyId"], json!(s.prover.kid));
        let again = fails(
            f.iam
                .api
                .devices
                .enroll(
                    &s.with_device(),
                    body(json!({
                        "tenantId": f.tenant_id,
                        "name": "Again",
                        "platform": "macos",
                        "publicKey": s.prover.jwk,
                    })),
                )
                .await,
        );
        assert_eq!(code(&again), "CONFLICT");

        let absent = s.check(&s.credential()).await;
        assert_matches(
            &absent,
            json!({ "assurance": "none", "proof": "absent", "managed": false }),
        );
        let verified = s.check(&s.with_device()).await;
        assert_matches(
            &verified,
            json!({
                "assurance": "registered",
                "proof": "verified",
                "deviceId": enrolled["device"]["id"],
                "platform": "macos",
                "compliant": false,
            }),
        );
        assert!(
            verified["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("not-managed"))
        );

        // A proof made for another session does not transfer.
        let other = s.check(&s.with_device_for("ses_someone_else")).await;
        assert_matches(&other, json!({ "assurance": "none", "proof": "invalid" }));
        // Garbage in the header is "no device", never an error.
        let garbage = s.check(&with_proof(&s.signed_in.token, "not.a.jws")).await;
        assert_matches(&garbage, json!({ "assurance": "none", "proof": "invalid" }));

        let mine = ok(f
            .iam
            .api
            .devices
            .mine(&s.with_device(), body(json!({ "tenantId": f.tenant_id })))
            .await);
        let mine = mine.as_array().unwrap();
        assert_eq!(mine.len(), 1);
        assert_matches(
            &mine[0],
            json!({ "id": enrolled["device"]["id"], "current": true }),
        );
    });
}

#[test]
fn turns_mdm_posture_into_compliance_that_policies_can_require() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let enrolled = s
            .enroll(
                &s.with_device(),
                json!({
                    "tenantId": f.tenant_id,
                    "name": "Alice laptop",
                    "platform": "macos",
                    "publicKey": s.prover.jwk,
                }),
            )
            .await;
        let device_id = enrolled["device"]["id"].clone();
        // Without a compliant device the policy grants nothing.
        assert!(!s.can_read(headers_only(&s.signed_in.token)).await);
        assert!(!s.can_read(s.with_device()).await);

        let owner = f.session(&f.owner_id, false).await;
        let integration = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Jamf", "vendor": "jamf" })),
            )
            .await);
        ok(f.iam
            .api
            .devices
            .configure(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "requireEncrypted": true,
                    "minOsVersions": { "macos": "14.0" },
                })),
            )
            .await);
        let report = |posture: Value, os_version: &str| {
            f.iam.api.devices.report(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "integrationId": integration["id"],
                    "devices": [{
                        "externalId": "jamf-42",
                        "platform": "macos",
                        "serialNumber": "C02XYZ",
                        "osVersion": os_version,
                        "ownerEmail": "alice@acme.test",
                        "posture": posture,
                    }],
                })),
            )
        };
        // The MDM record does not know the key yet: the self-enrolled device stays unmanaged.
        let first = ok(report(
            json!({ "compliant": true, "encrypted": true }),
            "14.5 (23F79)",
        )
        .await);
        assert_eq!(first["created"], json!(1));
        assert!(!s.can_read(s.with_device()).await);

        // The agent the MDM deployed reports the key it enrolled: the key moves onto the managed record.
        let keyed = ok(f
            .iam
            .api
            .devices
            .report(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "integrationId": integration["id"],
                    "devices": [{
                        "externalId": "jamf-42",
                        "platform": "macos",
                        "osVersion": "14.5",
                        "ownerEmail": "alice@acme.test",
                        "keyThumbprint": s.prover.kid,
                        "posture": { "compliant": true, "encrypted": true },
                    }],
                })),
            )
            .await);
        assert_eq!(keyed["updated"], json!(1));
        let check = s.check(&s.with_device()).await;
        assert_matches(
            &check,
            json!({ "assurance": "compliant", "managed": true, "compliant": true }),
        );
        assert_ne!(check["deviceId"], device_id);
        let old = ok(f
            .iam
            .api
            .devices
            .get(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "deviceId": device_id })),
            )
            .await);
        assert_eq!(old["status"], json!("retired"));
        assert!(s.can_read(s.with_device()).await);
        // The same session without the proof, or another session with a replayed header, is refused.
        assert!(!s.can_read(headers_only(&s.signed_in.token)).await);
        let second = sign_in(f, &s.alice).await;
        let replayed = s.prover.proof(&s.signed_in.session_id, f.now());
        assert!(!s.can_read(with_proof(&second.token, &replayed)).await);

        // Posture drift flips compliance and is audited once.
        let drift = ok(f
            .iam
            .api
            .devices
            .report(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "integrationId": integration["id"],
                    "devices": [{
                        "externalId": "jamf-42",
                        "platform": "macos",
                        "osVersion": "13.6",
                        "posture": { "compliant": true, "encrypted": true },
                    }],
                })),
            )
            .await);
        assert_eq!(drift["complianceChanged"], json!(1));
        let reasons = s.check(&s.with_device()).await;
        assert_matches(
            &reasons,
            json!({ "assurance": "managed", "compliant": false }),
        );
        assert!(
            reasons["reasons"]
                .as_array()
                .unwrap()
                .contains(&json!("os-too-old"))
        );
        assert!(!s.can_read(s.with_device()).await);
        // Only the drift changed the verdict (the record was created compliant and stayed so when the key moved).
        let changes = audit_actions(f, "device:compliance-change").await;
        assert_eq!(changes.len(), 1);
        assert_matches(
            &changes[0]["metadata"],
            json!({ "from": true, "to": false }),
        );
        assert!(!audit_actions(f, "device:report").await.is_empty());
    });
}

#[test]
fn binds_keys_to_managed_records_with_single_use_enrollment_codes() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let owner = f.session(&f.owner_id, false).await;
        let integration = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "name": "Intune", "vendor": "intune" })),
            )
            .await);
        ok(f.iam
            .api
            .devices
            .report(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "integrationId": integration["id"],
                    "devices": [{
                        "externalId": "intune-7",
                        "platform": "windows",
                        "osVersion": "10.0.22631",
                        "ownerIdentityId": s.alice,
                        "posture": { "compliant": true },
                    }],
                })),
            )
            .await);
        let listed = ok(f
            .iam
            .api
            .devices
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": f.tenant_id, "managed": true })),
            )
            .await);
        let managed = listed["devices"][0].clone();
        assert_matches(
            &managed,
            json!({ "platform": "windows", "ownerIdentityId": s.alice, "keys": 0 }),
        );

        let enrollment = ok(f
            .iam
            .api
            .devices
            .create_enrollment(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "deviceId": managed["id"],
                    "ownerIdentityId": s.alice,
                })),
            )
            .await);
        let code_text = enrollment["code"].as_str().unwrap().to_owned();
        assert!(code_text.starts_with("biam_"));
        // Someone else cannot use a code issued for alice.
        let mallory_id = f.member("mallory").await;
        let mallory = sign_in(f, &mallory_id).await;
        let mallory_prover = Prover::ec();
        let refused = fails(
            f.iam
                .api
                .devices
                .enroll(
                    &with_proof(
                        &mallory.token,
                        &mallory_prover.proof(&mallory.session_id, f.now()),
                    ),
                    body(json!({
                        "tenantId": f.tenant_id,
                        "name": "x",
                        "platform": "windows",
                        "publicKey": mallory_prover.jwk,
                        "enrollmentCode": code_text,
                    })),
                )
                .await,
        );
        assert_eq!(code(&refused), "ACCESS_DENIED");
        let bound = s
            .enroll(
                &s.with_device(),
                json!({
                    "tenantId": f.tenant_id,
                    "name": "ignored",
                    "platform": "windows",
                    "publicKey": s.prover.jwk,
                    "enrollmentCode": code_text,
                }),
            )
            .await;
        assert_eq!(bound["device"]["id"], managed["id"]);
        let check = s.check(&s.with_device()).await;
        assert_matches(
            &check,
            json!({ "assurance": "compliant", "deviceId": managed["id"] }),
        );
        // The code is spent.
        let another = Prover::ec();
        let spent = fails(
            f.iam
                .api
                .devices
                .enroll(
                    &with_proof(
                        &s.signed_in.token,
                        &another.proof(&s.signed_in.session_id, f.now()),
                    ),
                    body(json!({
                        "tenantId": f.tenant_id,
                        "name": "again",
                        "platform": "windows",
                        "publicKey": another.jwk,
                        "enrollmentCode": code_text,
                    })),
                )
                .await,
        );
        assert_eq!(code(&spent), "INVALID_INPUT");
        assert_eq!(spent.message, "Invalid or expired enrollment code");

        // Retiring the device ends what its proofs prove.
        ok(f.iam
            .api
            .devices
            .retire(
                &owner,
                body(json!({ "tenantId": f.tenant_id, "deviceId": managed["id"] })),
            )
            .await);
        assert_eq!(s.check(&s.with_device()).await["assurance"], json!("none"));
    });
}

#[test]
fn keeps_administration_reports_and_policy_defaults_behind_the_right_permissions() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let denied = fails(
            f.iam
                .api
                .devices
                .list(&s.credential(), body(json!({ "tenantId": f.tenant_id })))
                .await,
        );
        assert_eq!(code(&denied), "ACCESS_DENIED");
        let owner = f.session(&f.owner_id, false).await;
        let integration = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "CrowdStrike",
                    "vendor": "crowdstrike",
                })),
            )
            .await);
        let refused = fails(
            f.iam
                .api
                .devices
                .report(
                    &s.credential(),
                    body(json!({
                        "tenantId": f.tenant_id,
                        "integrationId": integration["id"],
                        "devices": [{ "externalId": "x", "platform": "linux", "posture": {} }],
                    })),
                )
                .await,
        );
        assert_eq!(code(&refused), "ACCESS_DENIED");
        // policies.test fills the always-present device keys.
        let document = json!({ "version": 1, "statements": compliant_only() });
        let tested = ok(f
            .iam
            .api
            .policies
            .test(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "document": document,
                    "action": "documents:read",
                    "resource": "document/d1",
                })),
            )
            .await);
        assert_eq!(tested["allowed"], json!(false));
        let compliant = ok(f
            .iam
            .api
            .policies
            .test(
                &f.owner_credential,
                body(json!({
                    "tenantId": f.tenant_id,
                    "document": document,
                    "action": "documents:read",
                    "resource": "document/d1",
                    "context": { "request.deviceCompliant": true },
                })),
            )
            .await);
        assert_eq!(compliant["allowed"], json!(true));
    });
}

#[test]
fn carries_the_device_proof_through_the_http_transport() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        s.enroll(
            &s.with_device(),
            json!({
                "tenantId": f.tenant_id,
                "name": "Phone",
                "platform": "ios",
                "publicKey": s.prover.jwk,
            }),
        )
        .await;
        let request = http::Request::builder()
            .method(Method::POST)
            .uri(format!("{ORIGIN}/api/iam/devices/check"))
            .header("content-type", "application/json")
            .header("x-better-iam", "1")
            .header("authorization", format!("Bearer {}", s.signed_in.token))
            .header(
                "x-better-iam-device",
                s.prover.proof(&s.signed_in.session_id, f.now()),
            )
            .body(Bytes::from(json!({ "tenantId": f.tenant_id }).to_string()))
            .unwrap();
        let response = f.iam.handler(request).await;
        assert_eq!(response.status().as_u16(), 200);
        let answer: Value = serde_json::from_slice(response.body()).unwrap();
        assert_eq!(answer["data"]["assurance"], json!("registered"));
    });
}

#[test]
fn moves_a_reported_key_only_off_its_owners_own_active_record() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let tenant_id = f.tenant_id.clone();
        let laptop = s
            .enroll(
                &s.with_device(),
                json!({
                    "tenantId": tenant_id,
                    "name": "Laptop",
                    "platform": "macos",
                    "publicKey": s.prover.jwk,
                }),
            )
            .await["device"]["id"]
            .clone();
        let owner = f.session(&f.owner_id, false).await;
        let jamf = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Jamf", "vendor": "jamf" })),
            )
            .await)["id"]
            .clone();
        let contractor = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Contractor MDM",
                    "vendor": "custom",
                })),
            )
            .await)["id"]
            .clone();
        let report = |integration_id: Value, external_id: &str, owner_email: Option<&str>| {
            let mut device = json!({
                "externalId": external_id,
                "platform": "macos",
                "keyThumbprint": s.prover.kid,
                "posture": { "compliant": true },
            });
            if let Some(email) = owner_email {
                device["ownerEmail"] = json!(email);
            }
            f.iam.api.devices.report(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "integrationId": integration_id,
                    "devices": [device],
                })),
            )
        };
        let presenting = || async { s.check(&s.with_device()).await["deviceId"].clone() };

        // A report naming nobody, or someone else, takes nothing.
        ok(report(contractor.clone(), "c-1", None).await);
        f.member("mallory").await;
        ok(report(contractor.clone(), "c-2", Some("mallory@acme.test")).await);
        assert_eq!(presenting().await, laptop);
        // A device marked lost keeps its key dead.
        ok(f.iam
            .api
            .devices
            .update(
                &owner,
                body(json!({ "tenantId": tenant_id, "deviceId": laptop, "status": "lost" })),
            )
            .await);
        ok(report(jamf.clone(), "jamf-1", Some("alice@acme.test")).await);
        assert_eq!(presenting().await, Value::Null);
        let lost = ok(f
            .iam
            .api
            .devices
            .get(
                &owner,
                body(json!({ "tenantId": tenant_id, "deviceId": laptop })),
            )
            .await);
        assert_eq!(lost["status"], json!("lost"));
        // Found again: the managed record takes the key over.
        ok(f.iam
            .api
            .devices
            .update(
                &owner,
                body(json!({ "tenantId": tenant_id, "deviceId": laptop, "status": "active" })),
            )
            .await);
        ok(report(jamf.clone(), "jamf-1", Some("alice@acme.test")).await);
        let managed = presenting().await;
        assert!(managed.is_string());
        assert_ne!(managed, laptop);
        // Another integration cannot take it off Jamf's record, even naming the owner.
        ok(report(contractor.clone(), "c-3", Some("alice@acme.test")).await);
        assert_eq!(presenting().await, managed);
    });
}

#[test]
fn writes_a_throttled_check_in_that_flips_compliance_and_audits_the_flip_once() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let tenant_id = f.tenant_id.clone();
        let owner = f.session(&f.owner_id, false).await;
        let integration = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Jamf", "vendor": "jamf" })),
            )
            .await)["id"]
            .clone();
        ok(f.iam
            .api
            .devices
            .configure(
                &owner,
                body(json!({ "tenantId": tenant_id, "maxCheckInAgeHours": 1 })),
            )
            .await);
        let start = f.now();
        let report = |checked_in_at: f64| {
            f.iam.api.devices.report(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "integrationId": integration,
                    "devices": [{
                        "externalId": "jamf-7",
                        "platform": "macos",
                        "posture": { "compliant": true },
                        "checkedInAt": checked_in_at,
                    }],
                })),
            )
        };
        ok(report(start).await);
        // The stored check-in has just gone stale; the vendor's timestamp of the new one is fresh but within a minute.
        f.advance(HOUR + 500.0);
        assert_eq!(
            ok(report(start + 30_000.0).await)["complianceChanged"],
            json!(1)
        );
        let listed = ok(f
            .iam
            .api
            .devices
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": tenant_id, "managed": true })),
            )
            .await);
        assert_matches(
            &listed["devices"][0],
            json!({
                "lastCheckInAt": better_iam_server::js::number(start + 30_000.0),
                "compliance": { "compliant": true },
            }),
        );
        assert_eq!(
            ok(report(start + 59_000.0).await)["complianceChanged"],
            json!(0)
        );
        assert_eq!(audit_actions(f, "device:compliance-change").await.len(), 1);
    });
}

#[test]
fn binds_codes_to_an_existing_device_only_for_those_who_manage_that_device() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let tenant_id = f.tenant_id.clone();
        let owner = f.session(&f.owner_id, false).await;
        // A service account (`serviceAccounts.create`) with a role for enrollment codes only.
        let helpdesk = better_iam_server::utils::id();
        f.insert(
            "identities",
            json!({
                "id": helpdesk,
                "tenantId": tenant_id,
                "kind": "service",
                "name": "helpdesk",
                "status": "active",
                "emailVerified": false,
                "rootAdmin": false,
                "owner": false,
                "createdAt": f.now(),
            }),
        )
        .await;
        f.grant(
            &helpdesk,
            json!([{
                "effect": "allow",
                "actions": ["iam:devices:manage"],
                "resources": ["iam/devices/enrollments"],
            }]),
        )
        .await;
        let key = ok(f
            .iam
            .api
            .credentials
            .create(
                &owner,
                body(json!({ "tenantId": tenant_id, "identityId": helpdesk })),
            )
            .await);
        let key = bearer(key["token"].as_str().unwrap());
        let integration = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Intune", "vendor": "intune" })),
            )
            .await)["id"]
            .clone();
        ok(f.iam
            .api
            .devices
            .report(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "integrationId": integration,
                    "devices": [{
                        "externalId": "kiosk-1",
                        "platform": "windows",
                        "posture": { "compliant": true },
                    }],
                })),
            )
            .await);
        let kiosk = ok(f
            .iam
            .api
            .devices
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": tenant_id, "managed": true })),
            )
            .await)["devices"][0]["id"]
            .clone();
        let refused = fails(
            f.iam
                .api
                .devices
                .create_enrollment(
                    &key,
                    body(json!({
                        "tenantId": tenant_id,
                        "deviceId": kiosk,
                        "ownerIdentityId": s.alice,
                    })),
                )
                .await,
        );
        assert_eq!(code(&refused), "ACCESS_DENIED");
        assert_eq!(
            refused.message,
            "A code for an existing device requires iam:devices:manage on that device"
        );
        let listed = ok(f
            .iam
            .api
            .devices
            .list_enrollments(&owner, body(json!({ "tenantId": tenant_id })))
            .await);
        assert_eq!(listed.as_array().unwrap().len(), 0);
        // Codes for new devices are what the grant is for; the owner may still bind the kiosk.
        let fresh = ok(f
            .iam
            .api
            .devices
            .create_enrollment(&key, body(json!({ "tenantId": tenant_id })))
            .await);
        assert!(fresh["code"].as_str().unwrap().starts_with("biam_denr_"));
        ok(f.iam
            .api
            .devices
            .create_enrollment(
                &owner,
                body(json!({ "tenantId": tenant_id, "deviceId": kiosk })),
            )
            .await);
        // The refusal was audited as a deny.
        let denies: Vec<Value> = f
            .find("audit", Filter::new().eq("tenantId", tenant_id.clone()))
            .await
            .into_iter()
            .filter(|event| event["action"] == "iam:devices:manage" && event["outcome"] == "deny")
            .map(Value::Object)
            .collect();
        assert_eq!(denies.len(), 1);
    });
}

#[test]
fn enrols_only_a_key_the_caller_holds_from_a_recent_sign_in() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let tenant_id = f.tenant_id.clone();
        let input = |public_key: &Value| {
            json!({
                "tenantId": tenant_id,
                "name": "Laptop",
                "platform": "linux",
                "publicKey": public_key,
            })
        };
        // No proof at all.
        let missing = fails(
            f.iam
                .api
                .devices
                .enroll(&s.credential(), body(input(&s.prover.jwk)))
                .await,
        );
        assert_eq!(code(&missing), "INVALID_INPUT");
        // Mallory saw Alice's public key and enrols it first, signing with her own key: refused.
        let mallory_id = f.member("mallory").await;
        let mallory = sign_in(f, &mallory_id).await;
        let mallory_prover = Prover::ec();
        let stolen = fails(
            f.iam
                .api
                .devices
                .enroll(
                    &with_proof(
                        &mallory.token,
                        &mallory_prover.proof(&mallory.session_id, f.now()),
                    ),
                    body(input(&s.prover.jwk)),
                )
                .await,
        );
        assert_eq!(code(&stolen), "INVALID_INPUT");
        // A proof Alice made for her own session proves nothing for Mallory's.
        let replayed = fails(
            f.iam
                .api
                .devices
                .enroll(
                    &with_proof(
                        &mallory.token,
                        &s.prover.proof(&s.signed_in.session_id, f.now()),
                    ),
                    body(input(&s.prover.jwk)),
                )
                .await,
        );
        assert_eq!(code(&replayed), "INVALID_INPUT");
        // Alice enrols her key.
        let device = s.enroll(&s.with_device(), input(&s.prover.jwk)).await["device"]["id"].clone();

        // Hours later, her (possibly stolen) session can neither add a key nor retire her device.
        f.advance(6.0 * HOUR);
        let thief = Prover::ec();
        let late = fails(
            f.iam
                .api
                .devices
                .enroll(
                    &with_proof(
                        &s.signed_in.token,
                        &thief.proof(&s.signed_in.session_id, f.now()),
                    ),
                    body(input(&thief.jwk)),
                )
                .await,
        );
        assert_eq!(code(&late), "RECENT_AUTH_REQUIRED");
        let retire = fails(
            f.iam
                .api
                .devices
                .retire_mine(
                    &s.credential(),
                    body(json!({ "tenantId": tenant_id, "deviceId": device })),
                )
                .await,
        );
        assert_eq!(code(&retire), "RECENT_AUTH_REQUIRED");
    });
}

#[test]
fn counts_a_device_as_registered_only_for_a_session_acting_in_another_tenant() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let tenant_id = f.tenant_id.clone();
        s.enroll(
            &s.with_device(),
            json!({
                "tenantId": tenant_id,
                "name": "Laptop",
                "platform": "macos",
                "publicKey": s.prover.jwk,
            }),
        )
        .await;
        let owner = f.session(&f.owner_id, false).await;
        let integration = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Jamf", "vendor": "jamf" })),
            )
            .await)["id"]
            .clone();
        ok(f.iam
            .api
            .devices
            .report(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "integrationId": integration,
                    "devices": [{
                        "externalId": "jamf-9",
                        "platform": "macos",
                        "ownerEmail": "alice@acme.test",
                        "keyThumbprint": s.prover.kid,
                        "posture": { "compliant": true },
                    }],
                })),
            )
            .await);
        let home = f.iam.authenticate(&s.with_device()).await.unwrap();
        let store = f.store();
        let presented = better_iam_server::devices::presented(&store, &home, f.now())
            .await
            .expect("a verified device");
        assert_eq!(presented.assurance, "compliant");
        // The same identity and proof acting in another tenant, as a cross-tenant role session does: that tenant
        // neither manages the device nor set the requirements it was judged by.
        let mut elsewhere = home.clone();
        elsewhere.session.tenant_id = f.root_tenant.clone();
        let presented = better_iam_server::devices::presented_device(&store, &elsewhere, f.now())
            .await
            .unwrap()
            .expect("a verified device");
        assert_matches(
            &presented,
            json!({
                "assurance": "registered",
                "compliance": { "managed": false, "compliant": false },
            }),
        );
    });
}

#[test]
fn keeps_the_presenting_device_in_view_when_a_role_session_re_decides_its_assumption() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let tenant_id = f.tenant_id.clone();
        s.enroll(
            &s.with_device(),
            json!({
                "tenantId": tenant_id,
                "name": "Laptop",
                "platform": "linux",
                "publicKey": s.prover.jwk,
            }),
        )
        .await;
        f.grant(
            &s.alice,
            json!([{
                "effect": "allow",
                "actions": ["iam:roles:assume"],
                "resources": ["*"],
                "conditions": { "StringEquals": { "request.deviceAssurance": "registered" } },
            }]),
        )
        .await;
        let writer = ok(f
            .iam
            .api
            .roles
            .create(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "name": "Writer",
                    "document": {
                        "version": 1,
                        "statements": [{
                            "effect": "allow",
                            "actions": ["documents:write"],
                            "resources": ["*"],
                        }],
                    },
                })),
            )
            .await);
        let trust = ok(f
            .iam
            .api
            .trust
            .create(
                &f.root_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "sourceTenantId": tenant_id,
                    "sourceIdentityId": s.alice,
                    "roleId": writer["id"],
                    "requireMfa": false,
                })),
            )
            .await);
        let assumed = ok(f
            .iam
            .api
            .roles
            .assume(
                &s.with_device(),
                body(json!({ "tenantId": tenant_id, "trustId": trust["id"] })),
            )
            .await);
        let token = assumed["token"].as_str().unwrap().to_owned();
        let session_id = assumed["session"]["id"].as_str().unwrap().to_owned();
        let write = |credential: CredentialInput| {
            let request = AuthorizationRequest {
                credential,
                tenant_id: tenant_id.clone(),
                action: "documents:write".into(),
                resource: ResourceTarget {
                    kind: "document".into(),
                    id: "d1".into(),
                },
            };
            async move { f.iam.authorize(&request).await }
        };
        let with_device = with_proof(&token, &s.prover.proof(&session_id, f.now()));
        assert!(write(with_device).await.unwrap().allowed);
        // Without the device, the right to the role no longer holds.
        let error = write(headers_only(&token)).await.unwrap_err();
        assert_eq!(code(&error), "UNAUTHENTICATED");
    });
}

// --- tests/device-proof.test.ts ------------------------------------------------------------------------------

/// Headers for `devices.enroll`: the session plus a proof signed with the key being enrolled.
fn enrolling(signed_in: &SignedIn, prover: &Prover, now: f64) -> CredentialInput {
    with_proof(&signed_in.token, &prover.proof(&signed_in.session_id, now))
}

#[test]
fn accepts_only_well_formed_proofs_from_enrolled_keys_bound_to_the_presenting_session() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice = f.member("alice").await;
        let signed_in = sign_in(&f, &alice).await;
        let sid = signed_in.session_id.clone();
        let ec = Prover::ec();
        ok(f.iam
            .api
            .devices
            .enroll(
                &enrolling(&signed_in, &ec, f.now()),
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Laptop",
                    "platform": "linux",
                    "publicKey": ec.jwk,
                })),
            )
            .await);
        let now = (f.now() / 1000.0).floor() as i64;
        let check = |proof: String| {
            let f = &f;
            let token = signed_in.token.clone();
            async move {
                ok(f.iam
                    .api
                    .devices
                    .check(
                        &with_proof(&token, &proof),
                        body(json!({ "tenantId": f.tenant_id })),
                    )
                    .await)["assurance"]
                    .clone()
            }
        };
        let good = ec.header();
        let with = |extra: Value| {
            let mut header = good.clone();
            for (key, value) in extra.as_object().unwrap() {
                header[key] = value.clone();
            }
            header
        };
        assert_eq!(
            check(ec.sign(&good, &json!({ "iat": now, "sid": sid }))).await,
            json!("registered")
        );
        // typ must be exact.
        assert_eq!(
            check(ec.sign(
                &with(json!({ "typ": "JWT" })),
                &json!({ "iat": now, "sid": sid })
            ))
            .await,
            json!("none")
        );
        // Key material from the header is never used, even when it is the enrolled key.
        assert_eq!(
            check(ec.sign(
                &with(json!({ "jwk": ec.jwk })),
                &json!({ "iat": now, "sid": sid })
            ))
            .await,
            json!("none")
        );
        assert_eq!(
            check(ec.sign(
                &with(json!({ "jku": "https://attacker.example/jwks" })),
                &json!({ "iat": now, "sid": sid })
            ))
            .await,
            json!("none")
        );
        // iat is bounded both ways.
        assert_eq!(
            check(ec.sign(&good, &json!({ "iat": now - 3600, "sid": sid }))).await,
            json!("none")
        );
        assert_eq!(
            check(ec.sign(&good, &json!({ "iat": now + 3600, "sid": sid }))).await,
            json!("none")
        );
        assert_eq!(
            check(ec.sign(&good, &json!({ "sid": sid }))).await,
            json!("none")
        );
        // The session binding is the presenting session, not a caller-chosen id.
        assert_eq!(
            check(ec.sign(&good, &json!({ "iat": now, "sid": "ses_other" }))).await,
            json!("none")
        );
        // A tid other than the session's tenant is refused; the session's own tenant is accepted.
        assert_eq!(
            check(ec.sign(&good, &json!({ "iat": now, "sid": sid, "tid": "other" }))).await,
            json!("none")
        );
        assert_eq!(
            check(ec.sign(
                &good,
                &json!({ "iat": now, "sid": sid, "tid": f.tenant_id })
            ))
            .await,
            json!("registered")
        );
        // An unknown key id, or a signature by another key under the enrolled kid.
        let stranger = Prover::ec();
        assert_eq!(check(stranger.proof(&sid, f.now())).await, json!("none"));
        assert_eq!(
            check(stranger.sign(&good, &json!({ "iat": now, "sid": sid }))).await,
            json!("none")
        );
        // The algorithm is pinned by the stored key type.
        let ed = Prover::ed();
        ok(f.iam
            .api
            .devices
            .enroll(
                &enrolling(&signed_in, &ed, f.now()),
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Phone",
                    "platform": "android",
                    "publicKey": ed.jwk,
                })),
            )
            .await);
        assert_eq!(
            check(ed.sign(&ed.header(), &json!({ "iat": now, "sid": sid }))).await,
            json!("registered")
        );
        let mut es256 = ed.header();
        es256["alg"] = json!("ES256");
        assert_eq!(
            check(ed.sign(&es256, &json!({ "iat": now, "sid": sid }))).await,
            json!("none")
        );
        // Oversized headers are ignored.
        assert_eq!(check("a".repeat(5000)).await, json!("none"));
    });
}

#[test]
fn does_not_let_one_persons_device_vouch_for_another_persons_session() {
    run(|| async {
        let f = organization(|_| {}).await;
        let alice_id = f.member("alice").await;
        let bob_id = f.member("bob").await;
        let alice = sign_in(&f, &alice_id).await;
        let bob = sign_in(&f, &bob_id).await;
        let ec = Prover::ec();
        ok(f.iam
            .api
            .devices
            .enroll(
                &enrolling(&alice, &ec, f.now()),
                body(json!({
                    "tenantId": f.tenant_id,
                    "name": "Alice laptop",
                    "platform": "macos",
                    "publicKey": ec.jwk,
                })),
            )
            .await);
        let result = ok(f
            .iam
            .api
            .devices
            .check(
                &with_proof(&bob.token, &ec.proof(&bob.session_id, f.now())),
                body(json!({ "tenantId": f.tenant_id })),
            )
            .await);
        assert_eq!(result["assurance"], json!("none"));
    });
}

// --- module checks (devices.ts) ----------------------------------------------------------------------------------

#[test]
fn judges_compliance_and_resolves_settings_as_typescript_does() {
    use better_iam_server::devices::{
        assurance_of, compare_os_versions, default_device_settings, evaluate_compliance,
        is_os_version, resolve_device_settings,
    };
    let record = |value: Value| value.as_object().unwrap().clone();
    // Stored settings over the defaults; malformed members fall back.
    let resolved = resolve_device_settings(Some(&record(json!({
        "requireEncrypted": true,
        "blockJailbroken": "no",
        "minOsVersions": { "macos": "14.0", "ios": "not a version", "plan9": "1" },
        "maxCheckInAgeHours": 721,
    }))));
    assert!(resolved.require_encrypted);
    assert!(resolved.block_jailbroken);
    assert_eq!(resolved.max_check_in_age_hours, 24.0);
    assert_eq!(
        serde_json::Value::Object(resolved.to_json()),
        json!({
            "requireEncrypted": true,
            "requireScreenLock": false,
            "requireFirewall": false,
            "requireEdr": false,
            "blockJailbroken": true,
            "minOsVersions": { "macos": "14.0" },
            "maxCheckInAgeHours": 24,
        })
    );
    assert_eq!(resolve_device_settings(None), default_device_settings());
    assert!(is_os_version(Some(&json!("14.5.1"))));
    assert!(!is_os_version(Some(&json!("14..5"))));
    assert!(!is_os_version(Some(&json!("1.2.3.4.5.6.7.8.9"))));
    assert!(!is_os_version(Some(&json!(14))));
    assert_eq!(compare_os_versions("14.0", "14"), 0);
    assert_eq!(compare_os_versions("13.6", "14.0"), -1);
    assert_eq!(compare_os_versions("14.0.1", "14"), 1);

    let now = 1_000_000_000.0;
    let integration = record(json!({
        "id": "int-1", "tenantId": "t1", "status": "active", "trustVendorCompliance": true,
    }));
    let device = record(json!({
        "id": "d1", "tenantId": "t1", "platform": "macos", "status": "active",
        "source": { "integrationId": "int-1", "externalId": "x" },
        "posture": { "integrationId": "int-1", "reportedAt": now, "compliant": true, "osVersion": "14.5" },
        "lastCheckInAt": now,
    }));
    let settings = default_device_settings();
    let result = evaluate_compliance(&device, Some(&integration), &settings, now);
    assert!(result.compliant && result.managed && result.reasons.is_empty());
    assert_eq!(assurance_of(&result, true), "compliant");
    assert_eq!(assurance_of(&result, false), "none");
    // Unmanaged, disabled, stale, and posture from another integration.
    let unmanaged = evaluate_compliance(&device, None, &settings, now);
    assert_eq!(unmanaged.reasons, vec!["not-managed".to_owned()]);
    let mut disabled = integration.clone();
    disabled.insert("status".into(), json!("disabled"));
    assert_eq!(
        evaluate_compliance(&device, Some(&disabled), &settings, now).reasons,
        vec!["integration-disabled".to_owned()]
    );
    let stale = evaluate_compliance(&device, Some(&integration), &settings, now + 25.0 * HOUR);
    assert_eq!(stale.reasons, vec!["stale".to_owned()]);
    let mut moved = device.clone();
    moved.insert(
        "posture".into(),
        json!({ "integrationId": "int-0", "reportedAt": now }),
    );
    assert_eq!(
        evaluate_compliance(&moved, Some(&integration), &settings, now).reasons,
        vec!["stale".to_owned()]
    );
    // Requirements, in TypeScript's order.
    let mut strict = default_device_settings();
    strict.require_encrypted = true;
    strict.require_screen_lock = true;
    strict.require_firewall = true;
    strict.require_edr = true;
    strict.min_os_versions.insert("macos".into(), json!("15.0"));
    let mut lost = device.clone();
    lost.insert("status".into(), json!("lost"));
    lost.insert(
        "posture".into(),
        json!({ "integrationId": "int-1", "reportedAt": now, "compliant": false, "jailbroken": true }),
    );
    assert_eq!(
        evaluate_compliance(&lost, Some(&integration), &strict, now).reasons,
        [
            "lost",
            "vendor-noncompliant",
            "not-encrypted",
            "no-screen-lock",
            "no-firewall",
            "edr-unhealthy",
            "jailbroken",
            "os-unknown",
        ]
        .map(str::to_owned)
        .to_vec()
    );
    let too_old = evaluate_compliance(&device, Some(&integration), &strict, now);
    assert!(too_old.reasons.contains(&"os-too-old".to_owned()));
}

#[test]
fn releases_the_devices_of_a_deleted_identity() {
    run(|| async {
        let s = Setup::new().await;
        let f = &s.f;
        let tenant_id = f.tenant_id.clone();
        let laptop = s
            .enroll(
                &s.with_device(),
                json!({
                    "tenantId": tenant_id,
                    "name": "Laptop",
                    "platform": "macos",
                    "publicKey": s.prover.jwk,
                }),
            )
            .await["device"]["id"]
            .clone();
        let owner = f.session(&f.owner_id, false).await;
        let integration = ok(f
            .iam
            .api
            .devices
            .create_integration(
                &owner,
                body(json!({ "tenantId": tenant_id, "name": "Jamf", "vendor": "jamf" })),
            )
            .await)["id"]
            .clone();
        ok(f.iam
            .api
            .devices
            .report(
                &f.owner_credential,
                body(json!({
                    "tenantId": tenant_id,
                    "integrationId": integration,
                    "devices": [{
                        "externalId": "jamf-1",
                        "platform": "windows",
                        "ownerIdentityId": s.alice,
                        "posture": { "compliant": true },
                    }],
                })),
            )
            .await);
        let managed = ok(f
            .iam
            .api
            .devices
            .list(
                &f.owner_credential,
                body(json!({ "tenantId": tenant_id, "managed": true })),
            )
            .await)["devices"][0]["id"]
            .clone();
        // A key alice bound to the managed record, and a code issued for her.
        let code = ok(f
            .iam
            .api
            .devices
            .create_enrollment(
                &owner,
                body(json!({ "tenantId": tenant_id, "deviceId": managed })),
            )
            .await)["code"]
            .clone();
        let phone = Prover::ec();
        ok(f.iam
            .api
            .devices
            .enroll(
                &with_proof(
                    &s.signed_in.token,
                    &phone.proof(&s.signed_in.session_id, f.now()),
                ),
                body(json!({
                    "tenantId": tenant_id,
                    "name": "x",
                    "platform": "windows",
                    "publicKey": phone.jwk,
                    "enrollmentCode": code,
                })),
            )
            .await);
        ok(f.iam
            .api
            .devices
            .create_enrollment(
                &owner,
                body(json!({ "tenantId": tenant_id, "ownerIdentityId": s.alice })),
            )
            .await);
        let alice_id = s.alice.clone();
        let store = f.store();
        let now = f.now();
        store
            .transaction(|tx| async move {
                let record = tx.get("identities", &alice_id).await?.unwrap();
                let identity: better_iam_core::Identity = better_iam_server::port::decode(record)?;
                better_iam_server::devices::release_devices_of(&tx, &identity, now).await
            })
            .await
            .unwrap();
        let get = |device_id: Value| {
            f.iam.api.devices.get(
                &f.owner_credential,
                body(json!({ "tenantId": tenant_id, "deviceId": device_id })),
            )
        };
        let retired = ok(get(laptop).await);
        assert_matches(&retired, json!({ "status": "retired", "keys": 0 }));
        let released = ok(get(managed).await);
        assert_matches(&released, json!({ "status": "active", "keys": 0 }));
        assert!(released.get("ownerIdentityId").is_none());
        assert!(
            f.find(
                "deviceEnrollments",
                Filter::new().eq("ownerIdentityId", s.alice.clone())
            )
            .await
            .is_empty()
        );
    });
}
