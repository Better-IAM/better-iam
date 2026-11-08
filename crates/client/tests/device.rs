//! Registered-device proofs (`@better-iam/client/device`, as tests/device-posture.test.ts uses them): the proof
//! format, caching, validation, key stores, and a proof carried through the HTTP transport to a real server.

mod support;

#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_client::device::{
    DEVICE_PROOF_HEADER, DeviceKeyPair, DeviceKeyStore, DeviceProverOptions, create_device_prover,
    indexed_db_key_store, memory_key_store,
};
use better_iam_client::{BoxError, ClientOptions, Error, FetchError, create_iam_client};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use support::{run, server_fetch};

fn decode(segment: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(segment).expect("base64url")
}

fn segment_json(segment: &str) -> Value {
    serde_json::from_slice(&decode(segment)).expect("JSON segment")
}

fn code(error: Error) -> String {
    error.code().expect("an IamClientError").to_owned()
}

fn clock(start: f64) -> (Arc<Mutex<f64>>, better_iam_client::device::Clock) {
    let now = Arc::new(Mutex::new(start));
    let reader = now.clone();
    (now, Arc::new(move || *reader.lock().unwrap()))
}

#[test]
fn signs_es256_proofs_bound_to_the_session_with_the_rfc7638_key_id() {
    run(|| async {
        let (_, now) = clock(1_700_000_123_456.0);
        let prover = create_device_prover(DeviceProverOptions {
            store: Some(memory_key_store()),
            now: Some(now),
            ..DeviceProverOptions::default()
        })
        .unwrap();
        let jwk = prover.public_jwk().await.unwrap();
        assert_eq!((jwk.kty.as_str(), jwk.crv.as_str()), ("EC", "P-256"));
        assert_eq!((decode(&jwk.x).len(), decode(&jwk.y).len()), (32, 32));
        let canonical = format!(
            r#"{{"crv":"P-256","kty":"EC","x":"{}","y":"{}"}}"#,
            jwk.x, jwk.y
        );
        let thumbprint = URL_SAFE_NO_PAD.encode(Sha256::digest(canonical.as_bytes()));
        assert_eq!(prover.key_id().await.unwrap(), thumbprint);

        let proof = prover.proof("ses_1", Some("ten_1")).await.unwrap();
        let parts: Vec<&str> = proof.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(
            segment_json(parts[0]),
            json!({ "alg": "ES256", "typ": "device-proof+jwt", "kid": thumbprint })
        );
        assert_eq!(
            String::from_utf8(decode(parts[1])).unwrap(),
            r#"{"iat":1700000123,"sid":"ses_1","tid":"ten_1"}"#
        );
        let mut point = vec![4u8];
        point.extend(decode(&jwk.x));
        point.extend(decode(&jwk.y));
        let key = VerifyingKey::from_sec1_bytes(&point).unwrap();
        let signature = Signature::from_slice(&decode(parts[2])).unwrap();
        key.verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &signature)
            .expect("a valid ES256 signature");
        let without_tenant = prover.proof("ses_1", None).await.unwrap();
        assert_eq!(
            String::from_utf8(decode(without_tenant.split('.').nth(1).unwrap())).unwrap(),
            r#"{"iat":1700000123,"sid":"ses_1"}"#
        );
    });
}

#[test]
fn reuses_a_proof_for_four_minutes_per_session_and_tenant() {
    run(|| async {
        let (now, reader) = clock(1_000_000.0);
        let prover = create_device_prover(DeviceProverOptions {
            now: Some(reader),
            ..DeviceProverOptions::default()
        })
        .unwrap();
        let first = prover.proof("ses_1", None).await.unwrap();
        *now.lock().unwrap() += 239_999.0;
        assert_eq!(prover.proof("ses_1", None).await.unwrap(), first);
        assert_ne!(prover.proof("ses_1", Some("ten_1")).await.unwrap(), first);
        *now.lock().unwrap() += 1.0;
        let renewed = prover.proof("ses_1", None).await.unwrap();
        assert_ne!(renewed, first);
        // A clock that moves backwards never reuses a proof issued "in the future".
        *now.lock().unwrap() -= 10_000.0;
        assert_ne!(prover.proof("ses_1", None).await.unwrap(), renewed);
        // Many sessions in a row each get their own proof.
        let mut proofs = std::collections::HashSet::new();
        for index in 0..20 {
            proofs.insert(prover.proof(&format!("ses_{index}"), None).await.unwrap());
        }
        assert_eq!(proofs.len(), 20);
        // Proofs of one key share the key id.
        assert_eq!(
            segment_json(first.split('.').next().unwrap())["kid"],
            json!(prover.key_id().await.unwrap())
        );
    });
}

#[test]
fn validates_options_ids_and_the_clock() {
    run(|| async {
        let refused = |options: DeviceProverOptions| match create_device_prover(options) {
            Ok(_) => "ok".to_owned(),
            Err(error) => error
                .client()
                .map(|error| format!("{} {}", error.code, error.message))
                .unwrap(),
        };
        assert_eq!(
            refused(DeviceProverOptions {
                algorithm: Some("RS256".into()),
                ..DeviceProverOptions::default()
            }),
            "INVALID_CONFIG Device proofs support only the ES256 algorithm"
        );
        for scope in ["has a space", "", &"s".repeat(65)] {
            assert_eq!(
                refused(DeviceProverOptions {
                    scope: Some(scope.to_owned()),
                    ..DeviceProverOptions::default()
                }),
                "INVALID_CONFIG scope must be 1 to 64 printable characters without spaces"
            );
        }
        assert_eq!(
            refused(DeviceProverOptions {
                scope: Some("identity-1".into()),
                algorithm: Some("ES256".into()),
                ..DeviceProverOptions::default()
            }),
            "ok"
        );
        let prover = create_device_prover(DeviceProverOptions::default()).unwrap();
        for bad in ["has space", "", "é"] {
            let error = prover.proof(bad, None).await.unwrap_err();
            assert_eq!(
                error.client().unwrap().message,
                "sessionId must be 1 to 256 printable characters without spaces"
            );
        }
        let error = prover.proof("ses_1", Some("bad tenant")).await.unwrap_err();
        assert_eq!(
            error.client().unwrap().message,
            "tenantId must be 1 to 256 printable characters without spaces"
        );
        let (_, nan) = (0, Arc::new(|| f64::NAN) as better_iam_client::device::Clock);
        let broken = create_device_prover(DeviceProverOptions {
            now: Some(nan),
            ..DeviceProverOptions::default()
        })
        .unwrap();
        let error = broken.proof("ses_1", None).await.unwrap_err();
        assert_eq!(
            (code(error.clone()), error.client().unwrap().message.clone()),
            (
                "INVALID_CONFIG".to_owned(),
                "now() must return milliseconds".to_owned()
            )
        );
    });
}

#[test]
fn sends_no_proof_header_without_a_session_and_reports_failures_to_on_error() {
    run(|| async {
        let errors = Arc::new(AtomicUsize::new(0));
        let seen = errors.clone();
        let prover = create_device_prover(DeviceProverOptions {
            on_error: Some(Arc::new(move |error: &Error| {
                assert_eq!(error.code(), Some("INVALID_INPUT"));
                seen.fetch_add(1, Ordering::SeqCst);
                panic!("a hook that fails never fails the request");
            })),
            ..DeviceProverOptions::default()
        })
        .unwrap();
        assert!(prover.headers(None, None).await.is_empty());
        assert!(prover.headers(Some(""), None).await.is_empty());
        assert!(prover.headers(Some("bad id"), None).await.is_empty());
        assert_eq!(errors.load(Ordering::SeqCst), 1);
        let headers = prover.headers(Some("ses_1"), None).await;
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, DEVICE_PROOF_HEADER);
        assert_eq!(headers[0].1, prover.proof("ses_1", None).await.unwrap());
    });
}

/// A store whose first `fail` calls fail, counting saves.
struct FlakyStore {
    inner: Arc<dyn DeviceKeyStore>,
    fail: AtomicUsize,
    saves: AtomicUsize,
}

#[async_trait::async_trait]
impl DeviceKeyStore for FlakyStore {
    async fn load(&self) -> Result<Option<DeviceKeyPair>, BoxError> {
        let left = self.fail.load(Ordering::SeqCst);
        if left > 0
            && self
                .fail
                .compare_exchange(left, left - 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            return Err(Arc::new(FetchError("storage unavailable".into())));
        }
        self.inner.load().await
    }

    async fn save(&self, pair: &DeviceKeyPair) -> Result<(), BoxError> {
        self.saves.fetch_add(1, Ordering::SeqCst);
        self.inner.save(pair).await
    }

    async fn clear(&self) -> Result<(), BoxError> {
        self.inner.clear().await
    }
}

#[test]
fn keeps_the_key_in_its_store_retries_failed_loads_and_starts_over_after_reset() {
    run(|| async {
        let shared = memory_key_store();
        let store = Arc::new(FlakyStore {
            inner: shared.clone(),
            fail: AtomicUsize::new(1),
            saves: AtomicUsize::new(0),
        });
        let prover = create_device_prover(DeviceProverOptions {
            store: Some(store.clone()),
            ..DeviceProverOptions::default()
        })
        .unwrap();
        // A failure is not remembered: the next call tries again.
        let error = prover.key_id().await.unwrap_err();
        assert!(matches!(error, Error::Other(_)));
        assert_eq!(error.to_string(), "storage unavailable");
        let first = prover.key_id().await.unwrap();
        assert_eq!(store.saves.load(Ordering::SeqCst), 1);
        // Another prover on the same store uses the stored key.
        let sibling = create_device_prover(DeviceProverOptions {
            store: Some(shared.clone()),
            ..DeviceProverOptions::default()
        })
        .unwrap();
        assert_eq!(sibling.key_id().await.unwrap(), first);
        let proof = prover.proof("ses_1", None).await.unwrap();
        prover.reset().await.unwrap();
        assert!(shared.load().await.unwrap().is_none());
        let second = prover.key_id().await.unwrap();
        assert_ne!(second, first);
        assert_ne!(prover.proof("ses_1", None).await.unwrap(), proof);
        // Concurrent first uses settle on one key.
        let fresh = create_device_prover(DeviceProverOptions::default()).unwrap();
        let (a, b) = futures::join!(fresh.key_id(), fresh.key_id());
        assert_eq!(a.unwrap(), b.unwrap());
    });
}

#[test]
fn the_indexed_db_store_needs_a_key_database_and_keeps_only_non_extractable_keys() {
    run(|| async {
        let error = indexed_db_key_store(Some("")).err().unwrap();
        assert_eq!(
            error.client().unwrap().message,
            "indexedDbKeyStore needs a database name of 1 to 128 characters"
        );
        assert!(indexed_db_key_store(Some(&"n".repeat(129))).is_err());
        let store = indexed_db_key_store(None).unwrap();
        let unsupported = store.load().await.unwrap_err();
        let unsupported = unsupported
            .downcast_ref::<better_iam_client::IamClientError>()
            .unwrap();
        assert_eq!(unsupported.code, "UNSUPPORTED_ENVIRONMENT");
        assert_eq!(
            unsupported.message,
            "IndexedDB is not available here; use memoryKeyStore() or your own DeviceKeyStore outside browsers"
        );
        // An extractable private key is refused before the database is opened.
        let extractable = DeviceKeyPair::from_signing_key(p256::ecdsa::SigningKey::random(
            &mut rand::rngs::OsRng,
        ));
        assert!(extractable.extractable());
        let refused = store.save(&extractable).await.unwrap_err();
        assert_eq!(
            refused
                .downcast_ref::<better_iam_client::IamClientError>()
                .unwrap()
                .message,
            "indexedDbKeyStore keeps only non-extractable private keys"
        );
        assert!(!DeviceKeyPair::generate().extractable());
        // A prover over it reports the store's client error as is.
        let prover = create_device_prover(DeviceProverOptions {
            store: Some(Arc::new(store)),
            ..DeviceProverOptions::default()
        })
        .unwrap();
        assert_eq!(
            code(prover.key_id().await.unwrap_err()),
            "UNSUPPORTED_ENVIRONMENT"
        );
    });
}

#[test]
fn carries_the_device_proof_through_the_http_transport() {
    organization_fixture::run(|| async {
        let f = organization_fixture::organization(|_| {}).await;
        let alice = f.member("alice").await;
        let credential = f.sign_in(&alice).await;
        let prover = create_device_prover(DeviceProverOptions {
            store: Some(memory_key_store()),
            ..DeviceProverOptions::default()
        })
        .unwrap();
        let session_id: Arc<Mutex<Option<String>>> = Arc::default();
        let (headers_prover, current) = (prover.clone(), session_id.clone());
        let client = create_iam_client(
            ClientOptions::new("http://localhost:3000")
                .token(credential.token.clone().unwrap())
                .fetch(server_fetch(f.iam.http.clone()))
                .headers_fn(move || {
                    let (prover, id) = (headers_prover.clone(), current.lock().unwrap().clone());
                    async move { Ok(prover.headers(id.as_deref(), None).await) }
                }),
        )
        .unwrap();
        let session = client.auth().get_session().await.unwrap();
        *session_id.lock().unwrap() = Some(session.session.id.clone());
        let enrolled: Value = client
            .request(
                "devices/enroll",
                &json!({
                    "tenantId": f.tenant_id,
                    "name": "Phone",
                    "platform": "ios",
                    "publicKey": prover.public_jwk().await.unwrap(),
                }),
            )
            .await
            .expect("enrolled");
        assert_eq!(enrolled["keyId"], json!(prover.key_id().await.unwrap()));
        let check = client
            .devices()
            .check(better_iam_types::api::devices::CheckInput {
                tenant_id: f.tenant_id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(check.assurance).unwrap(),
            json!("registered")
        );
        // Without a known session id no proof travels, which the server reads as "no device".
        *session_id.lock().unwrap() = None;
        let check = client
            .devices()
            .check(better_iam_types::api::devices::CheckInput {
                tenant_id: f.tenant_id.clone(),
            })
            .await
            .unwrap();
        assert_eq!(
            serde_json::to_value(check.assurance).unwrap(),
            json!("none")
        );
    });
}
