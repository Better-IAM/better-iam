//! Port of `tests/http-session-tokens.test.ts`: the session JWT key set route, the session-token gauge, the pre-wired
//! `sts` and `oidcProviders` route groups, and the strip of token hashes from any `session` object in a JSON answer.

use std::sync::Arc;

use better_iam_auth::{CredentialTokenType, new_credential_token};
use better_iam_core::{IamPlugin, IamResult, PluginEndpoint, PluginEndpointContext};
use better_iam_server::http::{PUBLIC_API_METHODS, ROUTE_GROUPS};
use better_iam_server::metrics::MetricsOptions;
use better_iam_server::observe::ObservabilityOptions;
use better_iam_server::options::Toggle;
use better_iam_server::utils::{hash, id};
use serde_json::{Map, Value, json};

use crate::jwt_keys::generate_test_key;
use crate::support::*;

const JWKS: &str = "http://localhost:3000/api/iam/.well-known/jwks.json";
const PUBLIC_MEMBERS: [&str; 7] = ["kty", "crv", "x", "y", "kid", "alg", "use"];

#[test]
fn publishes_the_public_members_of_the_signing_and_verification_keys() {
    run(|| async {
        let active = generate_test_key("EdDSA", "k1");
        let next = generate_test_key("ES256", "k2");
        let retired = generate_test_key("EdDSA", "k0");
        let jwt = json!({
            "signingKeys": [active.private_jwk, next.private_jwk],
            "verificationKeys": [retired.public_jwk],
        });
        let f = ok!(
            organization_fixture(|options| options.sts = Some(sts(json!({ "jwt": jwt })))).await
        );
        let response = get_url(&f.iam, JWKS, &[]).await;
        assert_eq!(response.status(), 200);
        assert_eq!(
            header(&response, "content-type"),
            Some("application/jwk-set+json")
        );
        assert_eq!(
            header(&response, "cache-control"),
            Some("public, max-age=300")
        );
        assert_eq!(header(&response, "x-content-type-options"), Some("nosniff"));
        let body = response_json(&response);
        let keys = body["keys"].as_array().unwrap();
        let kids: Vec<&Value> = keys.iter().map(|key| &key["kid"]).collect();
        assert_eq!(kids, [&json!("k1"), &json!("k2"), &json!("k0")]);
        for key in keys {
            assert!(
                key.as_object()
                    .unwrap()
                    .keys()
                    .all(|member| PUBLIC_MEMBERS.contains(&member.as_str()))
            );
            assert!(key.get("d").is_none());
            assert_eq!(key["use"], "sig");
        }
        matches(
            &keys[1],
            &json!({ "kty": "EC", "crv": "P-256", "alg": "ES256" }),
        );
        same(&body, &f.iam.session_tokens.as_ref().unwrap().jwks());
        // The key set is a GET resource only; the standard CORS refusal applies to untrusted origins.
        let foreign = get_url(&f.iam, JWKS, &[("origin", "https://evil.example")]).await;
        assert_eq!(foreign.status(), 403);
        assert_eq!(response_json(&foreign)["error"]["code"], "UNTRUSTED_ORIGIN");
    });
}

#[test]
fn answers_404_with_the_error_envelope_when_sts_jwt_is_not_configured() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let response = get_url(&f.iam, JWKS, &[]).await;
        assert_eq!(response.status(), 404);
        assert_eq!(header(&response, "cache-control"), Some("no-store"));
        same(
            &response_json(&response),
            &json!({ "error": { "code": "NOT_FOUND", "message": "Endpoint not found" } }),
        );
    });
}

#[test]
fn counts_live_session_tokens() {
    run(|| async {
        let f = ok!(organization_fixture(|options| {
            options.observability = Some(ObservabilityOptions {
                on_span: None,
                metrics: Some(Toggle::Options(MetricsOptions {
                    bearer_token: Some("scrape-token".into()),
                    gauges: Some(true),
                    ..MetricsOptions::default()
                })),
            });
        })
        .await);
        let scrape = || async {
            response_text(
                &get_url(
                    &f.iam,
                    "http://localhost:3000/api/iam/metrics",
                    &[("authorization", "Bearer scrape-token")],
                )
                .await,
            )
        };
        assert!(
            scrape()
                .await
                .contains("better_iam_sessions_live{kind=\"session-token\"} 0")
        );
        let source = f
            .find(
                "sessions",
                json!({ "identityId": f.owner_id, "kind": "user" }),
            )
            .await
            .into_iter()
            .next()
            .expect("owner session");
        let token = new_credential_token(CredentialTokenType::Sts);
        let token_hash = hash(&token);
        let now = f.now();
        f.insert(
            "sessions",
            json!({
                "id": id(),
                "tenantId": f.tenant_id,
                "identityId": f.owner_id,
                "kind": "session-token",
                "sourceSessionId": source["id"],
                "tokenHash": token_hash,
                "uniqueKey": token_hash,
                "createdAt": now,
                "lastSeenAt": now,
                "authenticatedAt": source["authenticatedAt"],
                "expiresAt": now + 3_600_000.0,
                "mfa": false,
            }),
        )
        .await;
        assert!(
            scrape()
                .await
                .contains("better_iam_sessions_live{kind=\"session-token\"} 1")
        );
        f.advance(3_600_000.0);
        assert!(
            scrape()
                .await
                .contains("better_iam_sessions_live{kind=\"session-token\"} 0")
        );
    });
}

#[test]
fn pre_wires_the_sts_and_oidc_providers_groups_and_the_public_web_identity_exchange() {
    run(|| async {
        assert!(ROUTE_GROUPS.contains(&"sts"));
        assert!(ROUTE_GROUPS.contains(&"oidcProviders"));
        assert!(PUBLIC_API_METHODS.contains(&"sts/assumeRoleWithWebIdentity"));
        let f = ok!(organization_fixture(|_| {}).await);
        let authorization = format!("Bearer {}", token_of(&f.owner_credential));
        let unknown = f
            .post(
                "sts/noSuchMethod",
                json!({}),
                &[("authorization", &authorization)],
            )
            .await;
        assert_eq!(unknown.status(), 404);
    });
}

#[test]
fn sign_in_bodies_carry_no_token_hash() {
    run(|| async {
        let f = ok!(organization_fixture(|_| {}).await);
        let response = f
            .post(
                "auth/signIn",
                json!({ "tenantId": f.tenant_id, "email": "owner@acme.test", "password": OWNER_PASSWORD }),
                &[],
            )
            .await;
        assert_eq!(response.status(), 200);
        let text = response_text(&response);
        let body = response_json(&response);
        let token = str_of(&body["data"], "token").to_owned();
        assert!(token.starts_with("biam_ses_"));
        assert!(body["data"]["session"]["id"].is_string());
        assert!(body["data"]["session"].get("tokenHash").is_none());
        assert!(body["data"]["session"].get("uniqueKey").is_none());
        assert!(!text.contains(&hash(&token)));
    });
}

struct Leaky;

struct LeakySession;

#[async_trait::async_trait]
impl PluginEndpoint for LeakySession {
    fn path(&self) -> &str {
        "session"
    }
    fn action(&self) -> &str {
        "leaky:run"
    }
    fn validate(&self, input: &Value) -> IamResult<Map<String, Value>> {
        let mut out = Map::new();
        if let Some(tenant_id) = input.get("tenantId") {
            out.insert("tenantId".into(), tenant_id.clone());
        }
        Ok(out)
    }
    async fn handler(
        &self,
        _context: PluginEndpointContext,
        _input: Map<String, Value>,
    ) -> IamResult<Value> {
        Ok(json!({
            "note": "kept",
            "session": { "id": "ses-1", "tokenHash": "hash", "uniqueKey": "hash", "expiresAt": 1 },
        }))
    }
}

#[async_trait::async_trait]
impl IamPlugin for Leaky {
    fn id(&self) -> &str {
        "leaky"
    }
    fn actions(&self) -> Vec<String> {
        vec!["leaky:run".into()]
    }
    fn endpoints(&self) -> Vec<Arc<dyn PluginEndpoint>> {
        vec![Arc::new(LeakySession)]
    }
}

#[test]
fn strips_token_hash_and_unique_key_from_any_top_level_session_object() {
    run(|| async {
        let f = ok!(
            organization_fixture(|options| options.plugins = Some(vec![Arc::new(Leaky)])).await
        );
        let authorization = format!("Bearer {}", token_of(&f.owner_credential));
        let response = f
            .post(
                "plugins/leaky/session",
                json!({ "tenantId": f.tenant_id }),
                &[("authorization", &authorization)],
            )
            .await;
        reached!(response);
        assert_eq!(response.status(), 200);
        same(
            &response_json(&response),
            &json!({ "data": { "note": "kept", "session": { "id": "ses-1", "expiresAt": 1 } } }),
        );
    });
}
