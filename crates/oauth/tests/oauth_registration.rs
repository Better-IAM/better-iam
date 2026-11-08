//! Port of tests/oauth-registration.test.ts: dynamic client registration and protected resource metadata.

mod common;

use std::sync::Arc;

use better_iam_core::{Filter, IamError, IamStore};
use better_iam_oauth::{
    AccessTokenVerifierOptions, GuardOutcome, OAuthResourceServer,
    ProtectedResourceMetadataOptions, RegistrationConfig, RegistrationPolicy, ResourceGuardOptions,
    create_access_token_verifier, create_protected_resource_handler, create_resource_guard,
    protected_resource_metadata, protected_resource_metadata_url,
};
use bytes::Bytes;
use common::provider::*;
use common::*;
use serde_json::{Value, json};

const API: &str = "https://mcp.example.test/mcp";

async fn seed() -> Arc<dyn IamStore> {
    let store = memory_store().await;
    for id in ["a", "b"] {
        insert(
            &store,
            "tenants",
            json!({ "id": id, "tenantId": id, "name": id, "type": "organization", "parentId": null, "status": "active", "createdAt": now_ms() }),
        )
        .await;
    }
    insert(
        &store,
        "identities",
        json!({
            "id": "user-a", "tenantId": "a", "name": "Ada", "kind": "user", "email": "ada@example.test",
            "emailVerified": true, "status": "active", "rootAdmin": false, "owner": false, "createdAt": now_ms(),
        }),
    )
    .await;
    store
}

async fn fixture(
    store: &Arc<dyn IamStore>,
    registration: Option<RegistrationConfig>,
) -> ProviderFixture {
    provider_fixture(store, move |config, _| {
        config.resource_servers.insert(
            API.into(),
            OAuthResourceServer {
                scopes: vec!["mcp:tools".into()],
                ..OAuthResourceServer::default()
            },
        );
        config.registration = registration;
    })
    .await
}

fn public_client(origin: &str) -> Value {
    json!({
        "client_name": "MCP host",
        "redirect_uris": [format!("{origin}/callback")],
        "token_endpoint_auth_method": "none",
        "grant_types": ["authorization_code", "refresh_token"],
        "response_types": ["code"],
    })
}

fn with(base: &Value, changes: Value) -> Value {
    let mut out = base.clone();
    for (key, value) in changes.as_object().unwrap() {
        if value.is_null() {
            out.as_object_mut().unwrap().remove(key);
        } else {
            out[key] = value.clone();
        }
    }
    out
}

async fn register(origin: &str, body: &Value, headers: &[(&str, &str)]) -> (u16, Value) {
    let mut all = vec![("content-type", "application/json")];
    all.extend_from_slice(headers);
    let response = fetch(
        "POST",
        &format!("{origin}/oidc/reg"),
        &all,
        Some(&body.to_string()),
    )
    .await;
    let parsed =
        serde_json::from_str(&response.body).unwrap_or_else(|_| json!({ "text": response.body }));
    (response.status, parsed)
}

#[test]
fn registers_public_clients_with_a_tenant_registration_token_bound_to_that_tenant_and_its_limits() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store, Some(RegistrationConfig::default())).await;
        let origin = f.origin.clone();
        let discovery = get_url(&format!("{origin}/oidc/.well-known/openid-configuration"))
            .await
            .json();
        assert_eq!(
            discovery["registration_endpoint"],
            json!(format!("{origin}/oidc/reg"))
        );
        assert!(
            discovery["code_challenge_methods_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("S256"))
        );
        let issued = f
            .provider
            .create_registration_token(
                &admin(),
                &json!({ "tenantId": "a", "name": "Claude", "scopes": ["openid", "offline_access", "mcp:tools"], "resources": [API] }),
            )
            .await
            .expect("token");
        let token = issued["token"].as_str().unwrap().to_owned();
        assert!(
            regex::Regex::new("^[A-Za-z0-9_-]{43}$")
                .unwrap()
                .is_match(&token)
        );
        assert_eq!(issued["maxClients"], json!(1));
        assert_eq!(issued["used"], json!(0));
        assert_eq!(issued["allowConfidential"], json!(false));
        let client = public_client(&origin);
        assert_eq!(register(&origin, &client, &[]).await.0, 401);
        let bearer = format!("Bearer {token}");
        let (status, registered) = register(
            &origin,
            &with(&client, json!({ "tenant_id": "b" })),
            &[("authorization", &bearer)],
        )
        .await;
        assert_eq!(status, 201, "{registered}");
        assert_eq!(registered["client_name"], json!("MCP host"));
        assert_eq!(registered["token_endpoint_auth_method"], json!("none"));
        assert_eq!(
            registered["scope"],
            json!("openid offline_access mcp:tools")
        );
        assert_eq!(registered["tenant_id"], json!("a"));
        assert!(registered.get("client_secret").is_none());
        let client_id = registered["client_id"].as_str().unwrap().to_owned();
        let read = f
            .provider
            .get_client(&admin(), &json!({ "tenantId": "a", "clientId": client_id }))
            .await
            .unwrap();
        assert_eq!(read["tenantId"], json!("a"));
        assert_eq!(read["public"], json!(true));
        assert_eq!(read["resources"], json!([API]));
        assert_eq!(read["registeredVia"], issued["id"]);
        assert_eq!(
            f.provider
                .get_client(&admin(), &json!({ "tenantId": "b", "clientId": client_id }))
                .await
                .unwrap_err()
                .status,
            404
        );
        assert_eq!(
            register(&origin, &client, &[("authorization", &bearer)])
                .await
                .0,
            401
        );
        let tokens = f
            .provider
            .list_registration_tokens(&admin(), &json!({ "tenantId": "a" }))
            .await
            .unwrap();
        assert_eq!(tokens.len(), 1);
        assert_eq!(tokens[0]["id"], issued["id"]);
        assert_eq!(tokens[0]["used"], json!(1));
        assert_eq!(tokens[0]["name"], json!("Claude"));
        assert!(
            !serde_json::to_string(&find(&store, "oauthRegistrationTokens", Filter::new()).await)
                .unwrap()
                .contains(&token)
        );
        let verifier_value = random_b64(32);
        let challenge = sha256_b64url(&verifier_value);
        let callback = format!("{origin}/callback");
        let mut browser = Browser::default();
        let mut result = browser
            .get(&format!(
                "{origin}/oidc/auth?{}",
                form(&[
                    ("client_id", &client_id),
                    ("response_type", "code"),
                    ("redirect_uri", &callback),
                    ("scope", "mcp:tools offline_access"),
                    ("resource", API),
                    ("prompt", "consent"),
                    ("code_challenge", &challenge),
                    ("code_challenge_method", "S256"),
                ])
            ))
            .await;
        let mut redirect = result.location();
        result = browser
            .visit(
                "POST",
                &absolute(&redirect, &origin),
                &[("origin", &origin)],
                None,
            )
            .await;
        redirect = result.location();
        let mut i = 0;
        while i < 5 && !redirect.contains("/callback?") {
            result = browser.get(&absolute(&redirect, &origin)).await;
            redirect = result.location();
            i += 1;
        }
        let code = query_param(&absolute(&redirect, &origin), "code")
            .unwrap_or_else(|| panic!("{} {}", result.status, result.body));
        let tokens = fetch(
            "POST",
            &format!("{origin}/oidc/token"),
            &[("content-type", "application/x-www-form-urlencoded")],
            Some(&form(&[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
                ("code", &code),
                ("code_verifier", &verifier_value),
                ("redirect_uri", &callback),
                ("resource", API),
            ])),
        )
        .await
        .json();
        let mut public = f.public_key.clone();
        public.as_object_mut().unwrap().remove("use");
        let verified = create_access_token_verifier(AccessTokenVerifierOptions {
            issuer: format!("{origin}/oidc"),
            audience: vec![API.into()],
            jwks: Some(json!({ "keys": [public] })),
            ..AccessTokenVerifierOptions::default()
        })
        .unwrap()
        .verify(
            tokens["access_token"].as_str().unwrap_or_default(),
            &["mcp:tools".into()],
        )
        .await
        .expect("verified");
        assert_eq!(verified.subject.as_deref(), Some("user-a"));
        assert_eq!(verified.client_id, client_id);
        assert_eq!(verified.tenant_id.as_deref(), Some("a"));
        let actions: Vec<String> = find(&store, "audit", Filter::new().eq("tenantId", "a"))
            .await
            .iter()
            .map(|event| event["action"].as_str().unwrap().to_owned())
            .collect();
        assert!(actions.contains(&"iam:oauth:CreateRegistrationToken".into()));
        assert!(actions.contains(&"iam:oauth:RegisterClient".into()));
    });
}

#[test]
fn refuses_registrations_outside_the_token_limits() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store, Some(RegistrationConfig::default())).await;
        let origin = f.origin.clone();
        let issued = f
            .provider
            .create_registration_token(
                &admin(),
                &json!({ "tenantId": "a", "name": "Many", "maxClients": 20 }),
            )
            .await
            .unwrap();
        let bearer = format!("Bearer {}", issued["token"].as_str().unwrap());
        let client = public_client(&origin);
        let refused = |body: Value| {
            let origin = origin.clone();
            let bearer = bearer.clone();
            async move {
                let (status, body) = register(&origin, &body, &[("authorization", &bearer)]).await;
                assert_eq!(status, 400, "{body}");
                body["error"].clone()
            }
        };
        assert_eq!(
            refused(with(&client, json!({ "token_endpoint_auth_method": null }))).await,
            json!("invalid_client_metadata")
        );
        assert_eq!(
            refused(with(
                &client,
                json!({ "grant_types": ["client_credentials"] })
            ))
            .await,
            json!("invalid_client_metadata")
        );
        assert_eq!(
            refused(with(
                &client,
                json!({ "redirect_uris": ["http://evil.example.test/cb"] })
            ))
            .await,
            json!("invalid_client_metadata")
        );
        assert_eq!(
            refused(with(
                &client,
                json!({ "jwks_uri": "https://keys.example.test/jwks" })
            ))
            .await,
            json!("invalid_client_metadata")
        );
        assert_eq!(
            refused(with(&client, json!({ "scope": "openid iam" }))).await,
            json!("invalid_client_metadata")
        );
        let (status, native) = register(
            &origin,
            &with(&client, json!({ "application_type": "native", "redirect_uris": ["com.example.desktop:/oauth/callback"] })),
            &[("authorization", &bearer)],
        )
        .await;
        assert_eq!(status, 201, "{native}");
        assert_eq!(
            native["scope"],
            json!("openid profile email offline_access")
        );
        let tokens = f
            .provider
            .list_registration_tokens(&admin(), &json!({ "tenantId": "a" }))
            .await
            .unwrap();
        f.provider
            .revoke_registration_token(
                &admin(),
                &json!({ "tenantId": "a", "tokenId": tokens[0]["id"] }),
            )
            .await
            .unwrap();
        assert_eq!(
            register(&origin, &client, &[("authorization", &bearer)])
                .await
                .0,
            401
        );
        assert_eq!(
            f.provider
                .create_registration_token(
                    &admin(),
                    &json!({ "tenantId": "a", "name": "X", "scopes": ["nope"] })
                )
                .await
                .unwrap_err()
                .code,
            "INVALID_INPUT"
        );
        assert_eq!(
            f.provider
                .create_registration_token(&member(), &json!({ "tenantId": "a", "name": "X" }))
                .await
                .unwrap_err()
                .status,
            403
        );
        assert_eq!(
            f.provider
                .revoke_registration_token(
                    &admin(),
                    &json!({ "tenantId": "b", "tokenId": tokens[0]["id"] })
                )
                .await
                .unwrap_err()
                .status,
            404
        );
    });
}

#[test]
fn admits_anonymous_registrations_the_host_maps_to_a_tenant_up_to_its_limit() {
    run(|| async {
        let store = seed().await;
        let registration = RegistrationConfig {
            anonymous: Some(Arc::new(|request| {
                Box::pin(async move {
                    let tenant = request
                        .headers
                        .iter()
                        .find(|(name, _)| name == "x-tenant")
                        .map(|(_, value)| value.clone());
                    Ok(
                        (tenant.as_deref() == Some("a")).then(|| RegistrationPolicy {
                            tenant_id: "a".into(),
                            max_clients: Some(1.0),
                            scopes: Some(vec!["openid".into()]),
                            ..RegistrationPolicy::default()
                        }),
                    )
                })
            })),
        };
        let f = fixture(&store, Some(registration)).await;
        let origin = f.origin.clone();
        let client = public_client(&origin);
        assert_eq!(register(&origin, &client, &[]).await.0, 401);
        let (status, first) = register(&origin, &client, &[("x-tenant", "a")]).await;
        assert_eq!(status, 201, "{first}");
        assert_eq!(first["tenant_id"], json!("a"));
        assert_eq!(first["scope"], json!("openid"));
        let (status, second) = register(&origin, &client, &[("x-tenant", "a")]).await;
        assert_eq!(status, 400);
        assert_eq!(second["error"], json!("access_denied"));
        let listed = f
            .provider
            .list_clients(&admin(), &json!({ "tenantId": "a" }))
            .await
            .unwrap();
        assert_eq!(
            listed
                .iter()
                .map(|client| client["registeredVia"].clone())
                .collect::<Vec<_>>(),
            vec![json!("anonymous")]
        );
    });
}

#[test]
fn keeps_registration_closed_unless_configured() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store, None).await;
        let discovery = get_url(&format!(
            "{}/oidc/.well-known/openid-configuration",
            f.origin
        ))
        .await
        .json();
        assert!(discovery.get("registration_endpoint").is_none());
        assert!(register(&f.origin, &public_client(&f.origin), &[]).await.0 >= 400);
    });
}

fn metadata_options() -> ProtectedResourceMetadataOptions {
    ProtectedResourceMetadataOptions {
        resource: API.into(),
        authorization_servers: vec!["https://id.example.test/oidc".into()],
        scopes: Some(vec!["mcp:tools".into()]),
        resource_name: Some("Acme MCP".into()),
        ..ProtectedResourceMetadataOptions::default()
    }
}

fn request(method: &str, url: &str, headers: &[(&str, &str)]) -> HttpRequest {
    let mut builder = http::Request::builder().method(method).uri(url);
    for (name, value) in headers {
        builder = builder.header(*name, *value);
    }
    builder.body(Bytes::new()).unwrap()
}

#[test]
fn publishes_rfc_9728_protected_resource_metadata_and_points_challenges_at_it() {
    run(|| async {
        let options = metadata_options();
        assert_eq!(
            protected_resource_metadata_url(API).unwrap(),
            "https://mcp.example.test/.well-known/oauth-protected-resource/mcp"
        );
        assert_eq!(
            protected_resource_metadata_url("https://api.example.test/").unwrap(),
            "https://api.example.test/.well-known/oauth-protected-resource"
        );
        let metadata = protected_resource_metadata(&options).unwrap();
        assert_eq!(metadata["resource"], json!(API));
        assert_eq!(
            metadata["authorization_servers"],
            json!(["https://id.example.test/oidc"])
        );
        assert_eq!(metadata["scopes_supported"], json!(["mcp:tools"]));
        assert_eq!(metadata["bearer_methods_supported"], json!(["header"]));
        assert_eq!(metadata["resource_name"], json!("Acme MCP"));
        let handler = create_protected_resource_handler(&options).unwrap();
        let url = protected_resource_metadata_url(API).unwrap();
        let served = handler.handle(&request("GET", &url, &[])).expect("served");
        assert_eq!(served.status(), 200);
        assert_eq!(
            served.headers().get("access-control-allow-origin").unwrap(),
            "*"
        );
        let body: Value = serde_json::from_slice(served.body()).unwrap();
        assert_eq!(body["resource"], json!(API));
        assert!(
            handler
                .handle(&request("GET", "https://mcp.example.test/mcp", &[]))
                .is_none()
        );
        assert_eq!(
            handler
                .handle(&request("POST", &url, &[]))
                .unwrap()
                .status(),
            405
        );
        assert!(
            protected_resource_metadata(&ProtectedResourceMetadataOptions {
                authorization_servers: vec![],
                ..options.clone()
            })
            .is_err()
        );
        let challenge = create_access_token_verifier(AccessTokenVerifierOptions {
            issuer: "https://id.example.test/oidc".into(),
            audience: vec![API.into()],
            jwks: Some(json!({ "keys": [] })),
            ..AccessTokenVerifierOptions::default()
        })
        .unwrap()
        .challenge(
            &IamError::with_status("INSUFFICIENT_SCOPE", "x", 403),
            None,
            Some(&url),
            &["mcp:tools".into()],
        );
        assert!(
            challenge.contains(
                "Bearer error=\"insufficient_scope\", resource_metadata=\"https://mcp.example.test/.well-known/oauth-protected-resource/mcp\", scope=\"mcp:tools\""
            ),
            "{challenge}"
        );
    });
}

#[test]
fn guards_an_api_metadata_challenges_without_and_with_errors_scopes_and_verified_tokens() {
    run(|| async {
        let issuer = "https://id.example.test/oidc";
        let (signing, public) = rsa_key(0, "test-key");
        let mut public = public;
        public.as_object_mut().unwrap().remove("use");
        let guard = create_resource_guard(ResourceGuardOptions {
            metadata: ProtectedResourceMetadataOptions {
                resource: API.into(),
                authorization_servers: vec![issuer.into()],
                scopes: Some(vec!["mcp:tools".into(), "mcp:admin".into()]),
                ..ProtectedResourceMetadataOptions::default()
            },
            required_scopes: vec!["mcp:tools".into()],
            jwks: Some(json!({ "keys": [public] })),
            ..ResourceGuardOptions::default()
        })
        .unwrap();
        let token = |scope: &str, audience: &str| {
            let now = (now_ms() / 1000.0).floor();
            sign(
                &signing,
                "RS256",
                json!({ "kid": "test-key", "typ": "at+jwt" }),
                json!({ "client_id": "mcp-host", "scope": scope, "tenant_id": "a", "iss": issuer, "aud": audience, "sub": "user-a", "iat": now, "exp": now + 300.0 }),
            )
        };
        let call = |authorization: Option<String>| {
            let guard = &guard;
            async move {
                let headers: Vec<(&str, &str)> = authorization
                    .as_deref()
                    .map(|value| vec![("authorization", value)])
                    .unwrap_or_default();
                guard.check(&request("GET", API, &headers), &[]).await
            }
        };
        let response = |outcome: GuardOutcome| match outcome {
            GuardOutcome::Response(response) => response,
            GuardOutcome::Token(token) => panic!("unexpected token {token:?}"),
        };
        let metadata = response(
            guard
                .check(&request("GET", &guard.metadata_url, &[]), &[])
                .await,
        );
        assert_eq!(metadata.status(), 200);
        let anonymous = response(call(None).await);
        assert_eq!(anonymous.status(), 401);
        assert_eq!(
            anonymous
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap(),
            format!(
                "Bearer resource_metadata=\"{}\", scope=\"mcp:tools\"",
                guard.metadata_url
            )
        );
        let forged = response(call(Some("Bearer not.a.token".into())).await);
        assert_eq!(forged.status(), 401);
        assert!(
            forged
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("error=\"invalid_token\"")
        );
        assert_eq!(
            response(
                call(Some(format!(
                    "Bearer {}",
                    token("mcp:tools", "https://other.example.test")
                )))
                .await
            )
            .status(),
            401
        );
        let narrow = response(
            guard
                .check(
                    &request(
                        "GET",
                        API,
                        &[(
                            "authorization",
                            &format!("Bearer {}", token("mcp:tools", API)),
                        )],
                    ),
                    &["mcp:admin".into()],
                )
                .await,
        );
        assert_eq!(narrow.status(), 403);
        let body: Value = serde_json::from_slice(narrow.body()).unwrap();
        assert_eq!(body["error"], json!("insufficient_scope"));
        assert!(
            narrow
                .headers()
                .get("www-authenticate")
                .unwrap()
                .to_str()
                .unwrap()
                .contains("scope=\"mcp:tools mcp:admin\"")
        );
        match call(Some(format!(
            "Bearer {}",
            token("mcp:tools mcp:admin", API)
        )))
        .await
        {
            GuardOutcome::Token(token) => {
                assert_eq!(token.subject.as_deref(), Some("user-a"));
                assert_eq!(token.client_id, "mcp-host");
                assert_eq!(token.tenant_id.as_deref(), Some("a"));
            }
            GuardOutcome::Response(response) => panic!("refused: {}", response.status()),
        }
    });
}
