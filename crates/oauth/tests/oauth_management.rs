//! Port of tests/oauth-management.test.ts: client management, connected apps, resource servers, DPoP and PAR.

mod common;

use std::collections::HashSet;
use std::sync::{Arc, Mutex};

use better_iam_core::{Filter, IamError, IamStore};
use better_iam_oauth::{
    AccessTokenVerifierOptions, OAuthResourceServer, ProtectedRequest,
    create_access_token_verifier, create_oauth_provider,
};
use common::provider::*;
use common::*;
use serde_json::{Value, json};

const API: &str = "https://api.example.test";

async fn seed() -> Arc<dyn IamStore> {
    let store = memory_store().await;
    seed_tenants(&store, &["root", "a", "b"]).await;
    for (id, tenant, kind) in [
        ("user-a", "a", "user"),
        ("user-a2", "a", "user"),
        ("user-b", "b", "user"),
        ("service-a", "a", "service"),
    ] {
        seed_identity(&store, id, tenant, kind).await;
    }
    store
}

fn api_server(scopes: &[&str]) -> OAuthResourceServer {
    OAuthResourceServer {
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        ..OAuthResourceServer::default()
    }
}

async fn fixture(store: &Arc<dyn IamStore>) -> ProviderFixture {
    provider_fixture(store, |config, _| {
        config
            .resource_servers
            .insert(API.into(), api_server(&["invoices:read", "invoices:write"]));
    })
    .await
}

async fn audit_actions(store: &Arc<dyn IamStore>) -> Vec<String> {
    find(store, "audit", Filter::new().eq("tenantId", "a"))
        .await
        .iter()
        .map(|event| event["action"].as_str().unwrap_or_default().to_owned())
        .collect()
}

fn lifetime(jwt: &str) -> f64 {
    let claims = claims_of(jwt);
    claims["exp"].as_f64().unwrap() - claims["iat"].as_f64().unwrap()
}

#[test]
fn lists_reads_updates_and_rotates_clients_without_exposing_secrets() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store).await;
        let provider = &f.provider;
        let registered = provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "machine", "name": "Machine", "redirectUris": [],
                    "grantTypes": ["client_credentials"], "serviceAccountId": "service-a",
                    "scopes": ["profile", "invoices:read"], "resources": [API],
                }),
            )
            .await
            .expect("register");
        let secret = registered["clientSecret"].as_str().unwrap().to_owned();
        provider
            .register_client(&admin(), &json!({ "tenantId": "a", "clientId": "spa", "name": "SPA", "public": true, "redirectUris": [API] }))
            .await
            .expect("spa");
        let listed = provider
            .list_clients(&admin(), &json!({ "tenantId": "a" }))
            .await
            .expect("list");
        assert_eq!(
            listed
                .iter()
                .map(|client| client["clientId"].clone())
                .collect::<Vec<_>>(),
            vec![json!("machine"), json!("spa")]
        );
        let machine = &listed[0];
        assert_eq!(machine["name"], json!("Machine"));
        assert_eq!(machine["public"], json!(false));
        assert_eq!(machine["grantTypes"], json!(["client_credentials"]));
        assert_eq!(machine["scopes"], json!(["profile", "invoices:read"]));
        assert_eq!(machine["resources"], json!([API]));
        assert_eq!(machine["serviceAccountId"], json!("service-a"));
        assert_eq!(machine["requireDpop"], json!(false));
        assert_eq!(machine["revoked"], json!(false));
        assert!(machine["createdAt"].as_f64().unwrap() > 0.0);
        assert!(!serde_json::to_string(&listed).unwrap().contains(&secret));
        assert!(
            provider
                .list_clients(&admin(), &json!({ "tenantId": "b" }))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            provider
                .list_clients(&member(), &json!({ "tenantId": "a" }))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(f.denied().contains(&"iam:oauth:clients:read".to_owned()));
        assert_eq!(
            provider
                .get_client(&admin(), &json!({ "tenantId": "b", "clientId": "machine" }))
                .await
                .unwrap_err()
                .status,
            404
        );
        let unknown = provider
            .register_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "x", "name": "X", "redirectUris": [API], "resources": ["https://unknown.example.test"] }),
            )
            .await
            .unwrap_err();
        assert_eq!(unknown.code, "INVALID_INPUT");
        let issue = |secret: String, scope: &'static str| {
            let f = &f;
            async move {
                f.token(
                    &[("grant_type", "client_credentials"), ("scope", scope)],
                    &[("authorization", &basic("machine", &secret))],
                )
                .await
            }
        };
        assert_eq!(issue(secret.clone(), "profile").await.status, 200);
        let rotated = provider
            .rotate_client_secret(&admin(), &json!({ "tenantId": "a", "clientId": "machine" }))
            .await
            .expect("rotate");
        let rotated_secret = rotated["clientSecret"].as_str().unwrap().to_owned();
        assert_ne!(rotated_secret, secret);
        assert_eq!(issue(secret.clone(), "profile").await.status, 401);
        assert_eq!(issue(rotated_secret.clone(), "profile").await.status, 200);
        let read = provider
            .get_client(&admin(), &json!({ "tenantId": "a", "clientId": "machine" }))
            .await
            .unwrap();
        assert!(read["secretRotatedAt"].as_f64().unwrap() > 0.0);
        assert!(
            !serde_json::to_string(&find(&store, "oauthClients", Filter::new()).await)
                .unwrap()
                .contains(&rotated_secret)
        );
        assert_eq!(
            provider
                .rotate_client_secret(&admin(), &json!({ "tenantId": "a", "clientId": "spa" }))
                .await
                .unwrap_err()
                .code,
            "INVALID_INPUT"
        );
        assert_eq!(
            provider
                .rotate_client_secret(
                    &member(),
                    &json!({ "tenantId": "a", "clientId": "machine" })
                )
                .await
                .unwrap_err()
                .status,
            403
        );
        let renamed = provider
            .update_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "machine", "name": "Billing sync" }),
            )
            .await
            .unwrap();
        assert_eq!(renamed["name"], json!("Billing sync"));
        assert_eq!(renamed["tokensRevoked"], json!(false));
        assert!(
            !find(
                &store,
                "oauthArtifacts",
                Filter::new().eq("clientId", "machine")
            )
            .await
            .is_empty()
        );
        let narrowed = provider
            .update_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "machine", "scopes": ["invoices:read"] }),
            )
            .await
            .unwrap();
        assert_eq!(narrowed["scopes"], json!(["invoices:read"]));
        assert_eq!(narrowed["tokensRevoked"], json!(true));
        assert!(
            find(
                &store,
                "oauthArtifacts",
                Filter::new().eq("clientId", "machine")
            )
            .await
            .is_empty()
        );
        assert_eq!(issue(rotated_secret.clone(), "profile").await.status, 400);
        assert_eq!(
            provider
                .update_client(&admin(), &json!({ "tenantId": "a", "clientId": "spa", "grantTypes": ["client_credentials"] }))
                .await
                .unwrap_err()
                .code,
            "INVALID_INPUT"
        );
        assert_eq!(
            provider
                .update_client(
                    &member(),
                    &json!({ "tenantId": "a", "clientId": "spa", "name": "Mine" })
                )
                .await
                .unwrap_err()
                .status,
            403
        );
        assert!(f.denied().contains(&"iam:oauth:clients:update".to_owned()));
        provider
            .revoke_client(&admin(), &json!({ "tenantId": "a", "clientId": "spa" }))
            .await
            .expect("revoke");
        let remaining = provider
            .list_clients(&admin(), &json!({ "tenantId": "a" }))
            .await
            .unwrap();
        assert_eq!(
            remaining
                .iter()
                .map(|client| client["clientId"].clone())
                .collect::<Vec<_>>(),
            vec![json!("machine")]
        );
        let all = provider
            .list_clients(
                &admin(),
                &json!({ "tenantId": "a", "includeRevoked": true }),
            )
            .await
            .unwrap();
        assert!(
            all.iter().any(
                |client| client["clientId"] == json!("spa") && client["revoked"] == json!(true)
            )
        );
        let actions = audit_actions(&store).await;
        for action in [
            "iam:oauth:RegisterClient",
            "iam:oauth:RotateClientSecret",
            "iam:oauth:UpdateClient",
            "iam:oauth:RevokeClient",
        ] {
            assert!(actions.contains(&action.to_owned()), "{action}");
        }
    });
}

#[test]
fn lists_and_revokes_connected_apps_extending_one_consent_per_browser_session() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store).await;
        let provider = &f.provider;
        provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "web", "name": "Web app", "public": true,
                    "redirectUris": [format!("{}/callback", f.origin)], "scopes": ["openid", "profile", "email", "offline_access"],
                    "logoUri": "https://app.example.test/logo.png", "policyUri": "https://app.example.test/privacy", "firstParty": true,
                }),
            )
            .await
            .expect("register");
        let mut user = Browser::default();
        let (details, first_tokens) = f
            .authorize(&mut user, "web", "openid profile offline_access", &[], &[])
            .await;
        assert_eq!(details["clientName"], json!("Web app"));
        assert_eq!(details["resources"], json!([]));
        assert_eq!(
            details["client"],
            json!({ "name": "Web app", "logoUri": "https://app.example.test/logo.png", "policyUri": "https://app.example.test/privacy", "firstParty": true })
        );
        let branded = provider
            .update_client(&admin(), &json!({ "tenantId": "a", "clientId": "web", "logoUri": null, "tosUri": "https://app.example.test/terms" }))
            .await
            .unwrap();
        assert_eq!(branded["tosUri"], json!("https://app.example.test/terms"));
        assert_eq!(branded["firstParty"], json!(true));
        assert!(branded.get("logoUri").is_none());
        assert_eq!(
            provider
                .update_client(&admin(), &json!({ "tenantId": "a", "clientId": "web", "clientUri": "http://app.example.test" }))
                .await
                .unwrap_err()
                .code,
            "INVALID_INPUT"
        );
        let grants = provider
            .list_grants(&member(), &json!({ "tenantId": "a" }))
            .await
            .unwrap();
        assert_eq!(grants.len(), 1);
        assert_eq!(grants[0]["tenantId"], json!("a"));
        assert_eq!(grants[0]["identityId"], json!("user-a"));
        assert_eq!(grants[0]["clientId"], json!("web"));
        assert_eq!(grants[0]["clientName"], json!("Web app"));
        let scopes = grants[0]["scopes"].as_array().unwrap();
        assert!(scopes.contains(&json!("openid")) && scopes.contains(&json!("profile")));
        assert!(grants[0]["createdAt"].as_f64().unwrap() > 0.0);
        f.authorize(
            &mut user,
            "web",
            "openid profile email offline_access",
            &[],
            &[],
        )
        .await;
        let grants = provider
            .list_grants(&member(), &json!({ "tenantId": "a" }))
            .await
            .unwrap();
        assert_eq!(grants.len(), 1);
        assert!(
            grants[0]["scopes"]
                .as_array()
                .unwrap()
                .contains(&json!("email"))
        );
        assert_eq!(
            provider
                .list_grants(
                    &member(),
                    &json!({ "tenantId": "a", "identityId": "user-a2" })
                )
                .await
                .unwrap_err()
                .status,
            403
        );
        assert!(f.denied().contains(&"iam:oauth:grants:read".to_owned()));
        assert!(
            provider
                .list_grants(
                    &admin(),
                    &json!({ "tenantId": "a", "identityId": "user-a2" })
                )
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            provider
                .list_grants(
                    &admin(),
                    &json!({ "tenantId": "b", "identityId": "user-a" })
                )
                .await
                .unwrap_err()
                .status,
            404
        );
        assert_eq!(
            provider
                .revoke_grant(
                    &member(),
                    &json!({ "tenantId": "a", "grantId": "f".repeat(64) })
                )
                .await
                .unwrap_err()
                .status,
            404
        );
        provider
            .revoke_grant(
                &member(),
                &json!({ "tenantId": "a", "grantId": grants[0]["id"] }),
            )
            .await
            .expect("revoke");
        assert!(
            provider
                .list_grants(&member(), &json!({ "tenantId": "a" }))
                .await
                .unwrap()
                .is_empty()
        );
        let refused = f
            .token(
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", "web"),
                    (
                        "refresh_token",
                        first_tokens["refresh_token"].as_str().unwrap(),
                    ),
                ],
                &[],
            )
            .await;
        assert_eq!(refused.status, 400);
        assert_eq!(refused.json()["error"], json!("invalid_grant"));
        let mut again = Browser::default();
        let (_, second) = f
            .authorize(&mut again, "web", "openid offline_access", &[], &[])
            .await;
        assert_eq!(
            provider
                .list_grants(&member(), &json!({ "tenantId": "a" }))
                .await
                .unwrap()
                .len(),
            1
        );
        assert_eq!(
            provider
                .revoke_grants(&member(), &json!({ "tenantId": "a", "clientId": "other" }))
                .await
                .unwrap(),
            json!({ "revoked": 0 })
        );
        assert_eq!(
            provider
                .revoke_grants(&member(), &json!({ "tenantId": "a", "clientId": "web" }))
                .await
                .unwrap(),
            json!({ "revoked": 1 })
        );
        let refreshed = f
            .token(
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", "web"),
                    ("refresh_token", second["refresh_token"].as_str().unwrap()),
                ],
                &[],
            )
            .await;
        assert_eq!(refreshed.status, 400);
        let actions = audit_actions(&store).await;
        assert_eq!(
            actions
                .iter()
                .filter(|action| *action == "iam:oauth:RevokeGrant")
                .count(),
            2
        );
    });
}

#[test]
fn issues_audience_restricted_jwt_access_tokens_that_resource_servers_verify_offline() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store).await;
        let provider = &f.provider;
        let machine = provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "machine", "name": "Machine", "redirectUris": [],
                    "grantTypes": ["client_credentials"], "serviceAccountId": "service-a", "scopes": ["invoices:read"], "resources": [API],
                }),
            )
            .await
            .unwrap();
        let auth = basic("machine", machine["clientSecret"].as_str().unwrap());
        let body = [
            ("grant_type", "client_credentials"),
            ("scope", "invoices:read"),
            ("resource", API),
        ];
        let response = f.token(&body, &[("authorization", &auth)]).await;
        assert_eq!(response.status, 200, "{}", response.body);
        let issued = response.json();
        assert_eq!(issued["token_type"], json!("Bearer"));
        let access_token = issued["access_token"].as_str().unwrap().to_owned();
        assert_eq!(access_token.split('.').count(), 3);
        let verifier = create_access_token_verifier(AccessTokenVerifierOptions {
            issuer: format!("{}/oidc", f.origin),
            audience: vec![API.into()],
            ..AccessTokenVerifierOptions::default()
        })
        .unwrap();
        let verified = verifier
            .verify(&access_token, &["invoices:read".into()])
            .await
            .expect("verified");
        assert_eq!(verified.client_id, "machine");
        assert_eq!(verified.tenant_id.as_deref(), Some("a"));
        assert_eq!(verified.identity_id.as_deref(), Some("service-a"));
        assert_eq!(verified.scopes, vec!["invoices:read".to_owned()]);
        assert_eq!(verified.audience, vec![API.to_owned()]);
        assert!(verified.bound_key.is_none());
        let insufficient = verifier
            .verify(&access_token, &["invoices:write".into()])
            .await
            .unwrap_err();
        assert_eq!(
            (insufficient.code.as_str(), insufficient.status),
            ("INSUFFICIENT_SCOPE", 403)
        );
        let elsewhere = create_access_token_verifier(AccessTokenVerifierOptions {
            issuer: format!("{}/oidc", f.origin),
            audience: vec!["https://other.example.test".into()],
            jwks: Some(json!({ "keys": [f.public_key] })),
            ..AccessTokenVerifierOptions::default()
        })
        .unwrap();
        assert_eq!(
            elsewhere
                .verify(&access_token, &[])
                .await
                .unwrap_err()
                .status,
            401
        );
        assert_eq!(
            verifier
                .verify(&format!("{access_token}x"), &[])
                .await
                .unwrap_err()
                .code,
            "INVALID_TOKEN"
        );
        assert!(
            verifier
                .challenge(
                    &IamError::with_status("INSUFFICIENT_SCOPE", "x", 403),
                    Some("api"),
                    None,
                    &[]
                )
                .contains("error=\"insufficient_scope\"")
        );
        assert_eq!(lifetime(&access_token), 900.0);
        let updated = provider
            .update_client(&admin(), &json!({ "tenantId": "a", "clientId": "machine", "accessTokenTtl": 120, "refreshTokenTtl": 3600 }))
            .await
            .unwrap();
        assert_eq!(updated["accessTokenTtl"], json!(120));
        assert_eq!(updated["refreshTokenTtl"], json!(3600));
        assert_eq!(updated["tokensRevoked"], json!(false));
        let shorter = f.token(&body, &[("authorization", &auth)]).await.json();
        assert_eq!(lifetime(shorter["access_token"].as_str().unwrap()), 120.0);
        let restored = provider
            .update_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "machine", "accessTokenTtl": null }),
            )
            .await
            .unwrap();
        assert!(restored.get("accessTokenTtl").is_none());
        assert_eq!(
            provider
                .update_client(
                    &admin(),
                    &json!({ "tenantId": "a", "clientId": "machine", "accessTokenTtl": 5 })
                )
                .await
                .unwrap_err()
                .code,
            "INVALID_INPUT"
        );
        let other = provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "other", "name": "Other", "redirectUris": [],
                    "grantTypes": ["client_credentials"], "serviceAccountId": "service-a", "scopes": ["invoices:read"],
                }),
            )
            .await
            .unwrap();
        let refused = f
            .token(
                &body,
                &[(
                    "authorization",
                    &basic("other", other["clientSecret"].as_str().unwrap()),
                )],
            )
            .await;
        assert_eq!(refused.status, 400);
        assert_eq!(refused.json()["error"], json!("invalid_target"));
    });
}

#[test]
fn applies_a_resource_servers_access_token_lifetime() {
    run(|| async {
        let store = seed().await;
        let f = provider_fixture(&store, |config, _| {
            config.resource_servers.insert(
                API.into(),
                OAuthResourceServer {
                    scopes: vec!["invoices:read".into()],
                    access_token_ttl: Some(300.0),
                    ..OAuthResourceServer::default()
                },
            );
        })
        .await;
        let client = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "machine", "name": "Machine", "redirectUris": [],
                    "grantTypes": ["client_credentials"], "serviceAccountId": "service-a", "scopes": ["invoices:read"], "resources": [API],
                }),
            )
            .await
            .unwrap();
        let issued = f
            .token(
                &[
                    ("grant_type", "client_credentials"),
                    ("scope", "invoices:read"),
                    ("resource", API),
                ],
                &[(
                    "authorization",
                    &basic("machine", client["clientSecret"].as_str().unwrap()),
                )],
            )
            .await
            .json();
        assert_eq!(lifetime(issued["access_token"].as_str().unwrap()), 300.0);
        assert_eq!(issued["expires_in"], json!(300));
    });
}

#[test]
fn binds_tokens_to_dpop_keys_and_verifies_proofs_at_the_resource_server() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store).await;
        let bound = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "bound", "name": "Bound", "redirectUris": [],
                    "grantTypes": ["client_credentials"], "serviceAccountId": "service-a", "scopes": ["invoices:read"],
                    "resources": [API], "requireDpop": true,
                }),
            )
            .await
            .unwrap();
        let auth = basic("bound", bound["clientSecret"].as_str().unwrap());
        let body = [
            ("grant_type", "client_credentials"),
            ("scope", "invoices:read"),
            ("resource", API),
        ];
        assert_eq!(
            f.token(&body, &[("authorization", &auth)]).await.status,
            400
        );
        let key = DpopKey::new();
        let proof = key.proof("POST", &format!("{}/oidc/token", f.origin), None);
        let response = f
            .token(&body, &[("authorization", &auth), ("dpop", &proof)])
            .await;
        assert_eq!(response.status, 200, "{}", response.body);
        let issued = response.json();
        assert_eq!(issued["token_type"], json!("DPoP"));
        let access_token = issued["access_token"].as_str().unwrap().to_owned();
        let verifier = create_access_token_verifier(AccessTokenVerifierOptions {
            issuer: format!("{}/oidc", f.origin),
            audience: vec![API.into()],
            jwks: Some(json!({ "keys": [f.public_key] })),
            ..AccessTokenVerifierOptions::default()
        })
        .unwrap();
        assert_eq!(
            verifier
                .verify(&access_token, &[])
                .await
                .unwrap_err()
                .status,
            401
        );
        let request = |dpop: Option<String>, scheme: &str| ProtectedRequest {
            authorization: Some(format!("{scheme} {access_token}")),
            dpop,
            method: "get".into(),
            url: format!("{API}/invoices?page=2"),
        };
        let presented = key.proof("GET", &format!("{API}/invoices"), Some(&access_token));
        let verified = verifier
            .verify_request(&request(Some(presented.clone()), "DPoP"), &[])
            .await
            .expect("verified");
        assert!(verified.bound_key.is_some());
        assert_eq!(verified.client_id, "bound");
        assert_eq!(
            verifier
                .verify_request(&request(Some(presented), "DPoP"), &[])
                .await
                .unwrap_err()
                .status,
            401
        );
        let wrong_method = key.proof("POST", &format!("{API}/invoices"), Some(&access_token));
        assert_eq!(
            verifier
                .verify_request(&request(Some(wrong_method), "DPoP"), &[])
                .await
                .unwrap_err()
                .status,
            401
        );
        let foreign = DpopKey::new().proof("GET", &format!("{API}/invoices"), Some(&access_token));
        assert_eq!(
            verifier
                .verify_request(&request(Some(foreign), "DPoP"), &[])
                .await
                .unwrap_err()
                .status,
            401
        );
        let bearer = key.proof("GET", &format!("{API}/invoices"), Some(&access_token));
        assert_eq!(
            verifier
                .verify_request(&request(Some(bearer), "Bearer"), &[])
                .await
                .unwrap_err()
                .status,
            401
        );
        assert_eq!(
            verifier
                .verify_request(&request(None, "DPoP"), &[])
                .await
                .unwrap_err()
                .status,
            401
        );
        f.provider
            .update_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "bound", "requireDpop": false }),
            )
            .await
            .unwrap();
        let enabled = f
            .provider
            .update_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "bound", "requireDpop": true }),
            )
            .await
            .unwrap();
        assert_eq!(enabled["tokensRevoked"], json!(true));
    });
}

#[test]
fn supports_pushed_authorization_requests_and_can_require_them_per_client() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store).await;
        let origin = f.origin.clone();
        let discovery = get_url(&format!("{origin}/oidc/.well-known/openid-configuration"))
            .await
            .json();
        assert_eq!(
            discovery["pushed_authorization_request_endpoint"],
            json!(format!("{origin}/oidc/request"))
        );
        assert!(
            discovery["dpop_signing_alg_values_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("ES256"))
        );
        f.provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "par", "name": "PAR", "public": true,
                    "redirectUris": [format!("{origin}/callback")], "requirePushedAuthorization": true,
                }),
            )
            .await
            .unwrap();
        let callback = format!("{origin}/callback");
        let challenge = sha256_b64url("verifier");
        let params = [
            ("client_id", "par"),
            ("response_type", "code"),
            ("redirect_uri", callback.as_str()),
            ("scope", "openid"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        let direct = get_url(&format!("{origin}/oidc/auth?{}", form(&params))).await;
        assert_eq!(direct.status, 303);
        assert!(
            direct.location().contains("error=invalid_request"),
            "{}",
            direct.location()
        );
        let pushed = fetch(
            "POST",
            &format!("{origin}/oidc/request"),
            &[("content-type", "application/x-www-form-urlencoded")],
            Some(&form(&params)),
        )
        .await;
        assert_eq!(pushed.status, 201, "{}", pushed.body);
        let request_uri = pushed.json()["request_uri"].as_str().unwrap().to_owned();
        assert!(request_uri.starts_with("urn:ietf:params:oauth:request_uri:"));
        let via_par = get_url(&format!(
            "{origin}/oidc/auth?{}",
            form(&[("client_id", "par"), ("request_uri", &request_uri)])
        ))
        .await;
        assert_eq!(via_par.status, 303, "{}", via_par.body);
        assert!(
            via_par.location().contains("/interactions/"),
            "{}",
            via_par.location()
        );
        let client = f
            .provider
            .get_client(&admin(), &json!({ "tenantId": "a", "clientId": "par" }))
            .await
            .unwrap();
        assert_eq!(client["requirePushedAuthorization"], json!(true));
    });
}

#[test]
fn authenticates_clients_with_private_key_jwt_assertions_and_rotates_their_keys() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store).await;
        let origin = f.origin.clone();
        let (first_private, first_public) = ec_key();
        let (second_private, second_public) = ec_key();
        let jwk = |public: &Value, kid: &str| {
            let mut key = public.clone();
            key["kid"] = json!(kid);
            key["alg"] = json!("ES256");
            key["use"] = json!("sig");
            key
        };
        let registered = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "signed", "name": "Signed", "redirectUris": [],
                    "grantTypes": ["client_credentials"], "serviceAccountId": "service-a", "scopes": ["profile"],
                    "tokenEndpointAuthMethod": "private_key_jwt", "jwks": { "keys": [jwk(&first_public, "one")] },
                }),
            )
            .await
            .unwrap();
        assert!(registered.get("clientSecret").is_none());
        let read = f
            .provider
            .get_client(&admin(), &json!({ "tenantId": "a", "clientId": "signed" }))
            .await
            .unwrap();
        assert_eq!(read["tokenEndpointAuthMethod"], json!("private_key_jwt"));
        assert_eq!(read["keyIds"], json!(["one"]));
        let assertion = |key: &Value, kid: &str| {
            let now = (now_ms() / 1000.0).floor();
            sign(
                key,
                "ES256",
                json!({ "kid": kid }),
                json!({ "jti": uuid::Uuid::new_v4().to_string(), "iss": "signed", "sub": "signed", "aud": format!("{origin}/oidc"), "iat": now, "exp": now + 60.0 }),
            )
        };
        let exchange = |client_assertion: String| {
            let f = &f;
            async move {
                f.token(
                    &[
                        ("grant_type", "client_credentials"),
                        ("scope", "profile"),
                        ("client_id", "signed"),
                        (
                            "client_assertion_type",
                            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
                        ),
                        ("client_assertion", &client_assertion),
                    ],
                    &[],
                )
                .await
            }
        };
        let signed = assertion(&first_private, "one");
        let accepted = exchange(signed.clone()).await;
        assert_eq!(accepted.status, 200, "{}", accepted.body);
        assert_eq!(exchange(signed).await.status, 401);
        assert_eq!(
            exchange(assertion(&second_private, "one")).await.status,
            401
        );
        let rotated = f
            .provider
            .update_client(&admin(), &json!({ "tenantId": "a", "clientId": "signed", "jwks": { "keys": [jwk(&second_public, "two")] } }))
            .await
            .unwrap();
        assert_eq!(rotated["keyIds"], json!(["two"]));
        assert_eq!(rotated["tokensRevoked"], json!(false));
        assert_eq!(
            exchange(assertion(&second_private, "two")).await.status,
            200
        );
        assert_eq!(exchange(assertion(&first_private, "one")).await.status, 401);
        assert_eq!(
            f.provider
                .rotate_client_secret(&admin(), &json!({ "tenantId": "a", "clientId": "signed" }))
                .await
                .unwrap_err()
                .code,
            "INVALID_INPUT"
        );
        let base = json!({
            "tenantId": "a", "name": "Bad", "redirectUris": [], "grantTypes": ["client_credentials"],
            "serviceAccountId": "service-a", "tokenEndpointAuthMethod": "private_key_jwt",
        });
        let with = |extra: Value| {
            let mut input = base.clone();
            for (key, value) in extra.as_object().unwrap() {
                input[key] = value.clone();
            }
            input
        };
        let mut private_jwk = first_private.clone();
        private_jwk["kid"] = json!("x");
        for input in [
            with(json!({ "clientId": "private", "jwks": { "keys": [private_jwk] } })),
            with(json!({ "clientId": "keyless" })),
            with(
                json!({ "clientId": "secret-with-keys", "tokenEndpointAuthMethod": "client_secret_basic", "jwks": { "keys": [jwk(&first_public, "one")] } }),
            ),
            with(json!({ "clientId": "insecure", "jwksUri": "http://keys.example.test/jwks" })),
        ] {
            assert_eq!(
                f.provider
                    .register_client(&admin(), &input)
                    .await
                    .unwrap_err()
                    .code,
                "INVALID_INPUT",
                "{input}"
            );
        }
    });
}

#[test]
fn sends_back_channel_logout_tokens_and_revokes_consents_when_iam_sessions_end() {
    run(|| async {
        let store = seed().await;
        let received: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
        let sink = received.clone();
        let rp = serve(Arc::new(move |request: HttpRequest| {
            let sink = sink.clone();
            Box::pin(async move {
                let body = String::from_utf8_lossy(request.body()).into_owned();
                let token = url::form_urlencoded::parse(body.as_bytes())
                    .find(|(key, _)| key == "logout_token")
                    .map(|(_, value)| value.into_owned())
                    .unwrap_or_default();
                sink.lock().unwrap().push(token);
                text_response(
                    if request.uri().path() == "/fail" {
                        500
                    } else {
                        204
                    },
                    "",
                )
            })
        }))
        .await;
        let f = fixture(&store).await;
        let origin = f.origin.clone();
        for (client_id, path) in [("web", "/logout"), ("flaky", "/fail")] {
            f.provider
                .register_client(
                    &admin(),
                    &json!({
                        "tenantId": "a", "clientId": client_id, "name": client_id, "public": true,
                        "redirectUris": [format!("{origin}/callback")], "scopes": ["openid", "offline_access"],
                        "backchannelLogoutUri": format!("{rp}{path}"),
                    }),
                )
                .await
                .unwrap();
        }
        let web_client = f
            .provider
            .get_client(&admin(), &json!({ "tenantId": "a", "clientId": "web" }))
            .await
            .unwrap();
        assert_eq!(
            web_client["backchannelLogoutUri"],
            json!(format!("{rp}/logout"))
        );
        let mut user = Browser::default();
        let (_, web) = f
            .authorize(&mut user, "web", "openid offline_access", &[], &[])
            .await;
        f.authorize(&mut user, "flaky", "openid offline_access", &[], &[])
            .await;
        assert_eq!(
            f.provider
                .list_grants(&member(), &json!({ "tenantId": "a" }))
                .await
                .unwrap()
                .len(),
            2
        );
        assert_eq!(
            f.provider.logout_ended_sessions(None).await.unwrap(),
            json!({ "sessions": 0, "grants": 0, "notified": 0, "failures": [] })
        );
        delete(&store, "sessions", "session-a").await;
        let result = f
            .provider
            .logout_ended_sessions(Some("user-a"))
            .await
            .unwrap();
        assert_eq!(
            result,
            json!({ "sessions": 1, "grants": 2, "notified": 1, "failures": [{ "clientId": "flaky", "identityId": "user-a" }] })
        );
        let received = received.lock().unwrap().clone();
        assert_eq!(received.len(), 2);
        let logout = claims_of(&received[0]);
        assert_eq!(logout["iss"], json!(format!("{origin}/oidc")));
        assert_eq!(logout["sub"], json!("user-a"));
        assert_eq!(
            logout["events"],
            json!({ "http://schemas.openid.net/event/backchannel-logout": {} })
        );
        assert!(["web", "flaky"].contains(&logout["aud"].as_str().unwrap()));
        assert!(logout.get("nonce").is_none());
        insert(
            &store,
            "sessions",
            serde_json::to_value(user_session("session-a", "a", "user-a", 100_000.0)).unwrap(),
        )
        .await;
        assert!(
            f.provider
                .list_grants(&member(), &json!({ "tenantId": "a" }))
                .await
                .unwrap()
                .is_empty()
        );
        let refreshed = f
            .token(
                &[
                    ("grant_type", "refresh_token"),
                    ("client_id", "web"),
                    ("refresh_token", web["refresh_token"].as_str().unwrap()),
                ],
                &[],
            )
            .await;
        assert_eq!(refreshed.status, 400);
        assert_eq!(
            f.provider.logout_ended_sessions(None).await.unwrap()["sessions"],
            json!(0)
        );
        f.provider
            .update_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "web", "backchannelLogoutUri": null }),
            )
            .await
            .unwrap();
        let cleared = f
            .provider
            .get_client(&admin(), &json!({ "tenantId": "a", "clientId": "web" }))
            .await
            .unwrap();
        assert!(cleared.get("backchannelLogoutUri").is_none());
    });
}

#[test]
fn exchanges_an_account_token_for_a_narrower_delegated_token() {
    run(|| async {
        const REPORTS: &str = "https://reports.example.test";
        let store = seed().await;
        let refused_subjects: Arc<Mutex<HashSet<String>>> = Arc::new(Mutex::new(HashSet::new()));
        let policy = refused_subjects.clone();
        let f = provider_fixture(&store, move |config, _| {
            config
                .resource_servers
                .insert(API.into(), api_server(&["invoices:read"]));
            config.resource_servers.insert(
                REPORTS.into(),
                api_server(&["reports:read", "reports:write"]),
            );
            config.authorize_token_exchange = Some(Arc::new(move |request| {
                let policy = policy.clone();
                Box::pin(
                    async move { Ok(!policy.lock().unwrap().contains(&request.subject_client_id)) },
                )
            }));
        })
        .await;
        let origin = f.origin.clone();
        f.provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "web", "name": "Web", "public": true,
                    "redirectUris": [format!("{origin}/callback")], "scopes": ["openid", "invoices:read"], "resources": [API],
                }),
            )
            .await
            .unwrap();
        let gateway = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "gateway", "name": "Invoice API", "redirectUris": [],
                    "grantTypes": ["urn:ietf:params:oauth:grant-type:token-exchange"], "scopes": ["reports:read"], "resources": [REPORTS],
                }),
            )
            .await
            .unwrap();
        let public_exchange = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "public-exchange", "name": "X", "public": true, "redirectUris": [],
                    "grantTypes": ["urn:ietf:params:oauth:grant-type:token-exchange"],
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(public_exchange.code, "INVALID_INPUT");
        let discovery = get_url(&format!("{origin}/oidc/.well-known/openid-configuration"))
            .await
            .json();
        assert!(
            discovery["grant_types_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("urn:ietf:params:oauth:grant-type:token-exchange"))
        );
        let mut user = Browser::default();
        let (_, tokens) = f
            .authorize(
                &mut user,
                "web",
                "openid invoices:read",
                &[("resource", API)],
                &[("resource", API)],
            )
            .await;
        let subject = tokens["access_token"].as_str().unwrap().to_owned();
        assert_eq!(subject.split('.').count(), 3);
        let gateway_auth = basic("gateway", gateway["clientSecret"].as_str().unwrap());
        let exchange = |extra: Vec<(&'static str, String)>| {
            let f = &f;
            let gateway_auth = gateway_auth.clone();
            async move {
                let mut body: Vec<(&str, &str)> = vec![
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:access_token",
                    ),
                ];
                for (key, value) in &extra {
                    body.push((key, value.as_str()));
                }
                f.token(&body, &[("authorization", &gateway_auth)]).await
            }
        };
        let response = exchange(vec![
            ("subject_token", subject.clone()),
            ("resource", REPORTS.into()),
        ])
        .await;
        assert_eq!(response.status, 200, "{}", response.body);
        let exchanged = response.json();
        assert_eq!(
            exchanged["issued_token_type"],
            json!("urn:ietf:params:oauth:token-type:access_token")
        );
        assert_eq!(exchanged["token_type"], json!("Bearer"));
        assert_eq!(exchanged["scope"], json!("reports:read"));
        let exchanged_token = exchanged["access_token"].as_str().unwrap().to_owned();
        let verified = create_access_token_verifier(AccessTokenVerifierOptions {
            issuer: format!("{origin}/oidc"),
            audience: vec![REPORTS.into()],
            jwks: Some(json!({ "keys": [f.public_key] })),
            ..AccessTokenVerifierOptions::default()
        })
        .unwrap()
        .verify(&exchanged_token, &["reports:read".into()])
        .await
        .expect("verified");
        assert_eq!(verified.subject.as_deref(), Some("user-a"));
        assert_eq!(verified.client_id, "gateway");
        assert_eq!(verified.tenant_id.as_deref(), Some("a"));
        assert_eq!(
            verified
                .actor
                .as_ref()
                .and_then(|actor| actor.get("sub"))
                .cloned(),
            Some(json!("gateway"))
        );
        assert!(verified.identity_id.is_none());
        assert!(verified.expires_at <= claims_of(&subject)["exp"].as_f64().unwrap());
        let chained = exchange(vec![
            ("subject_token", exchanged_token),
            ("resource", REPORTS.into()),
        ])
        .await
        .json();
        assert_eq!(
            claims_of(chained["access_token"].as_str().unwrap())["act"],
            json!({ "sub": "gateway", "act": { "sub": "gateway" } })
        );
        let (_, plain) = f
            .authorize(&mut Browser::default(), "web", "openid", &[], &[])
            .await;
        let opaque = exchange(vec![
            (
                "subject_token",
                plain["access_token"].as_str().unwrap().to_owned(),
            ),
            ("audience", REPORTS.into()),
        ])
        .await;
        assert_eq!(opaque.status, 200, "{}", opaque.body);
        let failure = |extra: Vec<(&'static str, String)>| {
            let exchange = &exchange;
            async move {
                let result = exchange(extra).await;
                (result.status, result.json()["error"].clone())
            }
        };
        assert_eq!(
            failure(vec![
                ("subject_token", subject.clone()),
                ("resource", REPORTS.into()),
                ("scope", "reports:write".into())
            ])
            .await,
            (400, json!("invalid_scope"))
        );
        assert_eq!(
            failure(vec![
                ("subject_token", subject.clone()),
                ("resource", API.into())
            ])
            .await,
            (400, json!("invalid_target"))
        );
        assert_eq!(
            failure(vec![
                ("subject_token", "not-a-token".into()),
                ("resource", REPORTS.into())
            ])
            .await,
            (400, json!("invalid_grant"))
        );
        assert_eq!(
            failure(vec![
                ("subject_token", subject.clone()),
                ("resource", REPORTS.into()),
                ("actor_token", "x".into()),
                (
                    "actor_token_type",
                    "urn:ietf:params:oauth:token-type:access_token".into()
                ),
            ])
            .await,
            (400, json!("invalid_request"))
        );
        refused_subjects.lock().unwrap().insert("web".into());
        assert_eq!(
            failure(vec![
                ("subject_token", subject.clone()),
                ("resource", REPORTS.into())
            ])
            .await,
            (400, json!("access_denied"))
        );
        refused_subjects.lock().unwrap().clear();
        let mut user_record = get(&store, "identities", "user-a").await.unwrap();
        user_record.insert("status".into(), json!("disabled"));
        put(&store, "identities", Value::Object(user_record)).await;
        assert_eq!(
            failure(vec![
                ("subject_token", subject.clone()),
                ("resource", REPORTS.into())
            ])
            .await,
            (400, json!("invalid_grant"))
        );
        let actions = audit_actions(&store).await;
        assert_eq!(
            actions
                .iter()
                .filter(|action| *action == "iam:oauth:TokenExchange")
                .count(),
            3
        );
    });
}

#[test]
fn rejects_invalid_resource_server_configuration() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store).await;
        let base = |configure: &dyn Fn(&mut better_iam_oauth::OAuthProviderConfig)| {
            let mut config = better_iam_oauth::OAuthProviderConfig {
                issuer: "https://issuer.example.test".into(),
                trusted_origins: vec!["https://issuer.example.test".into()],
                resource_servers: Default::default(),
                ..f.provider_config()
            };
            configure(&mut config);
            create_oauth_provider(config)
                .map(|_| ())
                .unwrap_err()
                .message
        };
        assert!(
            base(&|config| {
                config
                    .resource_servers
                    .insert("not a uri".into(), api_server(&["a"]));
            })
            .contains("absolute URIs")
        );
        assert!(
            base(&|config| {
                config
                    .resource_servers
                    .insert(format!("{API}#x"), api_server(&["a"]));
            })
            .contains("fragment")
        );
        assert!(
            base(&|config| {
                config.resource_servers.insert(API.into(), api_server(&[]));
            })
            .contains("scope identifiers")
        );
        assert!(
            base(&|config| config.dpop_nonce_secret = Some("short".into())).contains("32 bytes")
        );
    });
}
