//! Shared helpers of the package tests: the organization fixture of the server tests (tests/support/organization.ts),
//! card keys, the base card, and the IAM instance as the gate takes it.

#![allow(dead_code)]

#[path = "../../../server/tests/organization_fixture/mod.rs"]
pub mod organization_fixture;

use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_a2a::{
    A2aAuthorization, A2aCheck, A2aDelegations, A2aError, A2aIam, A2aPrincipal, A2aResourceRef,
    Body, CardJwks, Clock, transport,
};
use better_iam_core::CredentialInput;
use better_iam_server::options::Jwk;
use http_body_util::BodyExt;
use serde_json::{Map, Value, json};

#[allow(unused_imports)]
pub use organization_fixture::{Org, assert_matches, bearer, body, ok, organization, run};

/// `cardKey(kid)`: a fresh Ed25519 private JWK as `KeyObject#export({ format: 'jwk' })` gives it, with kid, alg and
/// use.
pub fn card_key(kid: &str) -> Jwk {
    let secret: [u8; 32] = rand::random();
    let key = ed25519_dalek::SigningKey::from_bytes(&secret);
    let jwk = json!({
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(secret),
        "x": URL_SAFE_NO_PAD.encode(key.verifying_key().as_bytes()),
        "kty": "OKP",
        "kid": kid,
        "alg": "EdDSA",
        "use": "sig",
    });
    jwk.as_object().unwrap().clone()
}

/// `baseCard(url)`.
pub fn base_card(url: &str) -> Map<String, Value> {
    json!({
        "protocolVersion": "0.3.0",
        "name": "Triage",
        "description": "Sorts incoming requests",
        "url": url,
        "version": "1.2.0",
        "capabilities": { "streaming": true },
        "defaultInputModes": ["text/plain"],
        "defaultOutputModes": ["text/plain"],
        "skills": [
            { "id": "summarize", "name": "Summarize", "description": "Summarizes a document", "tags": ["docs"] },
            { "id": "purge", "name": "Purge", "description": "Deletes archived documents", "tags": ["docs"] },
        ],
    })
    .as_object()
    .unwrap()
    .clone()
}

/// The fixture's IAM instance as the gate takes it (`iam: f.iam`).
pub struct OrgIam(pub Arc<Org>);

#[async_trait]
impl A2aIam for OrgIam {
    async fn authenticate(&self, credential: &CredentialInput) -> Result<A2aPrincipal, A2aError> {
        A2aIam::authenticate(&self.0.iam, credential).await
    }

    async fn authorize(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        action: &str,
        resource: &A2aResourceRef,
    ) -> Result<A2aAuthorization, A2aError> {
        A2aIam::authorize(&self.0.iam, credential, tenant_id, action, resource).await
    }

    async fn authorize_many(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        checks: &[A2aCheck],
    ) -> Result<Vec<A2aAuthorization>, A2aError> {
        A2aIam::authorize_many(&self.0.iam, credential, tenant_id, checks).await
    }

    fn delegations(&self) -> Option<&dyn A2aDelegations> {
        A2aIam::delegations(&self.0.iam)
    }
}

/// `f.now` as a clock.
pub fn clock(f: &Arc<Org>) -> Clock {
    let f = f.clone();
    Arc::new(move || f.now())
}

/// `f.iam.a2a.jwks()`.
pub fn jwks(f: &Org) -> CardJwks {
    CardJwks::from_value(&f.iam.a2a.jwks()).expect("a key set")
}

/// `f.iam.a2a.jwksResponse()` as a fetched response.
pub fn jwks_response(f: &Org) -> http::Response<Body> {
    let (parts, bytes) = f.iam.a2a.jwks_response().into_parts();
    http::Response::from_parts(parts, transport::full(bytes))
}

/// A response's status and body text.
pub async fn read(response: http::Response<Body>) -> (u16, String) {
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// A response's status and JSON body.
pub async fn read_json(response: http::Response<Body>) -> (u16, Value) {
    let (status, text) = read(response).await;
    (status, serde_json::from_str(&text).unwrap_or(Value::Null))
}

/// A JSON response (`Response.json(body)`).
pub fn json_response(body: &Value) -> http::Response<Body> {
    http::Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(transport::full(body.to_string()))
        .unwrap()
}

/// A request's JSON body.
pub async fn request_json(request: http::Request<Body>) -> Value {
    let bytes = request
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    serde_json::from_slice(&bytes).expect("JSON body")
}

/// The id of a created record.
pub fn id_of(value: &Value) -> String {
    value["id"].as_str().expect("an id").to_owned()
}

/// `agents.create` + `credentials.create`: an agent and its key token.
pub async fn agent_with_key(f: &Org, input: Value) -> (String, String) {
    let mut input = input.as_object().cloned().unwrap_or_default();
    input.insert("tenantId".into(), Value::String(f.tenant_id.clone()));
    let agent = ok(f
        .iam
        .api
        .agents
        .create(&f.owner_credential, body(Value::Object(input)))
        .await);
    let id = id_of(&agent);
    let key = ok(f
        .iam
        .api
        .credentials
        .create(
            &f.owner_credential,
            body(json!({ "tenantId": f.tenant_id, "identityId": id })),
        )
        .await);
    (id, key["token"].as_str().unwrap().to_owned())
}
