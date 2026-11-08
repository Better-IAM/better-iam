//! Shared helpers of the SAML tests: the key fixtures (written once by `selfsigned`, valid until 2126), an IdP that
//! signs like the TypeScript tests' `xml-crypto` helper, `xml-encryption`'s template for encrypted assertions, an
//! in-memory store with tenants, and HTTP helpers.

#![allow(dead_code)]

use std::future::Future;
use std::io::Read;
use std::path::Path;
use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use better_iam_adapter_sqlite::{SqliteAdapterOptions, sqlite_adapter};
use better_iam_core::{AuthenticatedPrincipal, IamStore, IamStoreExt, js};
use better_iam_saml::dsig::{self, Action, Selector, SignOptions, SignReference};
use better_iam_saml::keys::{base64_decode, base64_encode, public_key};
use better_iam_saml::service::{HttpRequest, HttpResponse};
use bytes::Bytes;
use rand::RngCore;
use rsa::Oaep;
use serde_json::{Value, json};

pub const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";

/// A key pair of the fixtures.
#[derive(Debug, Clone)]
pub struct KeyPair {
    pub private: String,
    pub cert: String,
}

pub fn fixture(name: &str) -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures")
            .join(name),
    )
    .unwrap()
}

pub fn keys(name: &str) -> KeyPair {
    KeyPair {
        private: fixture(&format!("{name}.key.pem")),
        cert: fixture(&format!("{name}.cert.pem")),
    }
}

/// Runs a test body on a runtime with large stacks (debug-build futures are big).
pub fn run<F, Fut>(body: F)
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = ()> + 'static,
{
    std::thread::Builder::new()
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime")
                .block_on(body());
        })
        .expect("thread")
        .join()
        .expect("test body");
}

/// `new Date(ms).toISOString()`.
pub fn iso(ms: f64) -> String {
    js::iso_string(ms).unwrap()
}

pub fn now() -> f64 {
    js::now_ms()
}

pub fn uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

pub fn b64(text: &str) -> String {
    base64_encode(text.as_bytes())
}

/// The TypeScript tests' `sign(xml, type, key)`: an enveloped exclusive-c14n RSA-SHA256 signature of the `type`
/// element, placed after its `Issuer`.
pub fn sign(xml: &str, kind: &str, key: &KeyPair) -> String {
    dsig::compute_signature(
        xml,
        &SignOptions {
            private_key: key.private.clone(),
            public_cert: Some(key.cert.clone()),
            signature_algorithm: dsig::RSA_SHA256.to_owned(),
            canonicalization_algorithm: dsig::EXC_C14N.to_owned(),
            references: vec![SignReference {
                selector: Selector::local(kind),
                transforms: vec![
                    dsig::ENVELOPED_SIGNATURE.to_owned(),
                    dsig::EXC_C14N.to_owned(),
                ],
                digest_algorithm: dsig::SHA256.to_owned(),
            }],
            location: Selector::local(kind).child("Issuer"),
            action: Action::After,
        },
    )
    .unwrap()
}

/// `xml-encryption`'s `encrypt(content, { aes256-gcm, rsa-oaep-mgf1p })`.
pub fn encrypt(content: &str, cert: &str) -> String {
    let mut key = [0u8; 32];
    let mut iv = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut key);
    rand::thread_rng().fill_bytes(&mut iv);
    let cipher = Aes256Gcm::new_from_slice(&key).unwrap();
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&iv), content.as_bytes())
        .unwrap();
    let mut payload = iv.to_vec();
    payload.extend(encrypted);
    let wrapped_key = public_key(cert)
        .unwrap()
        .encrypt(&mut rand::thread_rng(), Oaep::new::<sha1::Sha1>(), &key)
        .unwrap();
    let body: String = cert
        .split("-----BEGIN CERTIFICATE-----")
        .nth(1)
        .and_then(|rest| rest.split("-----END CERTIFICATE-----").next())
        .unwrap()
        .chars()
        .filter(|c| *c != '\n' && *c != '\r' && *c != '|')
        .collect();
    let key_info = format!(
        "\n<KeyInfo xmlns=\"http://www.w3.org/2000/09/xmldsig#\">\n  <e:EncryptedKey xmlns:e=\"http://www.w3.org/2001/04/xmlenc#\">\n    <e:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\">\n      <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\" />\n    </e:EncryptionMethod>\n    <KeyInfo>\n      <X509Data><X509Certificate>{body}</X509Certificate></X509Data>\n    </KeyInfo>\n    <e:CipherData>\n      <e:CipherValue>{}</e:CipherValue>\n    </e:CipherData>\n  </e:EncryptedKey>\n</KeyInfo>\n",
        base64_encode(&wrapped_key)
    );
    format!(
        "\n<xenc:EncryptedData Type=\"http://www.w3.org/2001/04/xmlenc#Element\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">\n  <xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2009/xmlenc11#aes256-gcm\" />\n  {key_info}\n  <xenc:CipherData>\n    <xenc:CipherValue>{}</xenc:CipherValue>\n  </xenc:CipherData>\n</xenc:EncryptedData>\n",
        base64_encode(&payload)
    )
}

/// An in-memory store with active organizations.
pub async fn store_with_tenants(ids: &[&str]) -> Arc<dyn IamStore> {
    let store = sqlite_adapter(SqliteAdapterOptions::new(":memory:")).unwrap();
    store.migrate().await.unwrap();
    let ids: Vec<String> = ids.iter().map(|id| (*id).to_owned()).collect();
    store
        .transaction(|tx| async move {
            for id in ids {
                let record = json!({
                    "id": id, "tenantId": id, "name": id, "type": "organization",
                    "parentId": null, "status": "active", "createdAt": now(),
                });
                tx.insert("tenants", record.as_object().unwrap()).await?;
            }
            Ok(())
        })
        .await
        .unwrap();
    store
}

/// A signed-in administrator of tenant `a`, as the TypeScript tests stub `authenticate`.
pub fn principal() -> AuthenticatedPrincipal {
    AuthenticatedPrincipal {
        identity: serde_json::from_value(json!({
            "id": "admin-a", "tenantId": "a", "kind": "user", "name": "Admin", "status": "active",
            "emailVerified": true, "rootAdmin": false, "owner": false, "createdAt": now(),
        }))
        .unwrap(),
        session: serde_json::from_value(json!({
            "id": "session", "tenantId": "a", "identityId": "admin-a", "tokenHash": "x", "createdAt": now(),
            "expiresAt": now() + 3_600_000.0, "lastSeenAt": now(), "authenticatedAt": now(), "mfa": false,
            "kind": "user",
        }))
        .unwrap(),
        device_proof: None,
    }
}

/// The request ID of the AuthnRequest a login URL carries.
pub fn request_id(url: &str) -> String {
    let parsed = url::Url::parse(url).unwrap();
    let encoded = parsed
        .query_pairs()
        .find(|(key, _)| key == "SAMLRequest")
        .unwrap()
        .1
        .into_owned();
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(&base64_decode(&encoded)[..])
        .read_to_string(&mut xml)
        .unwrap();
    let start = xml.find(" ID=\"").unwrap() + 5;
    xml[start..start + xml[start..].find('"').unwrap()].to_owned()
}

/// The inflated AuthnRequest of a login URL.
pub fn authn_request(url: &str) -> String {
    let parsed = url::Url::parse(url).unwrap();
    let encoded = parsed
        .query_pairs()
        .find(|(key, _)| key == "SAMLRequest")
        .unwrap()
        .1
        .into_owned();
    let mut xml = String::new();
    flate2::read::DeflateDecoder::new(&base64_decode(&encoded)[..])
        .read_to_string(&mut xml)
        .unwrap();
    xml
}

pub fn get(url: &str) -> HttpRequest {
    http::Request::builder()
        .method("GET")
        .uri(url)
        .body(Bytes::new())
        .unwrap()
}

/// A form POST (`application/x-www-form-urlencoded`), with a cookie when given.
pub fn post_form(url: &str, form: &[(&str, &str)], cookie: Option<&str>) -> HttpRequest {
    let body = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(form.iter())
        .finish();
    let mut builder = http::Request::builder()
        .method("POST")
        .uri(url)
        .header("content-type", "application/x-www-form-urlencoded");
    if let Some(cookie) = cookie {
        builder = builder.header("cookie", cookie);
    }
    builder.body(Bytes::from(body)).unwrap()
}

pub fn header(response: &HttpResponse, name: &str) -> Option<String> {
    response
        .headers()
        .get(name)
        .map(|value| value.to_str().unwrap().to_owned())
}

pub fn json_body(response: &HttpResponse) -> Value {
    serde_json::from_slice(response.body()).unwrap()
}

/// Whether `actual` contains every member of `expected` with the same value (`toMatchObject`).
pub fn matches(actual: &Value, expected: &Value) -> bool {
    match (actual, expected) {
        (Value::Object(actual), Value::Object(expected)) => expected
            .iter()
            .all(|(key, value)| actual.get(key).is_some_and(|member| matches(member, value))),
        (Value::Array(actual), Value::Array(expected)) => {
            actual.len() == expected.len()
                && actual.iter().zip(expected).all(|(a, e)| matches(a, e))
        }
        (actual, expected) => actual == expected,
    }
}

#[track_caller]
pub fn assert_matches(actual: &Value, expected: Value) {
    assert!(
        matches(actual, &expected),
        "\n  actual:   {actual}\n  expected: {expected}"
    );
}
