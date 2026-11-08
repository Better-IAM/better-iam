//! Port of tests/oauth.test.ts: the provider and the federated sign-in flows.

mod common;

use std::sync::{Arc, Mutex, OnceLock};

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, IamError, IamStore, Identity, Session,
};
use better_iam_oauth::{
    ConnectionKind, DevicePageInput, FederatedIdentity, MappedProfile, OAuthLoginConfig,
    OAuthLoginConnection, OAuthProvider, OAuthProviderConfig, create_oauth_login,
    create_oauth_provider, create_provider_adapter,
};
use bytes::Bytes;
use common::*;
use serde_json::{Map, Value, json};

async fn seed(store: &Arc<dyn IamStore>) {
    for id in ["root", "a", "b"] {
        insert(
            store,
            "tenants",
            json!({
                "id": id, "tenantId": id, "name": id,
                "type": if id == "root" { "root" } else { "organization" },
                "parentId": if id == "root" { Value::Null } else { json!("root") },
                "status": "active", "createdAt": now_ms(),
            }),
        )
        .await;
    }
    for id in ["a", "b"] {
        insert(
            store,
            "identities",
            json!({
                "id": format!("user-{id}"), "tenantId": id, "name": id, "kind": "user", "emailVerified": true,
                "email": "same@example.test", "status": "active", "rootAdmin": false, "owner": false, "createdAt": now_ms(),
            }),
        )
        .await;
    }
    insert(
        store,
        "identities",
        json!({
            "id": "service-a", "tenantId": "a", "name": "Service A", "kind": "service", "emailVerified": false,
            "status": "active", "rootAdmin": false, "owner": false, "createdAt": now_ms(),
        }),
    )
    .await;
    let mut user = get(store, "identities", "user-a").await.unwrap();
    user.insert("attributes".into(), json!({ "department": "finance" }));
    put(store, "identities", Value::Object(user)).await;
    insert(
        store,
        "groupMembers",
        json!({ "id": "member-a", "tenantId": "a", "groupId": "group-a", "identityId": "user-a" }),
    )
    .await;
    insert(
        store,
        "bindings",
        json!({ "id": "binding-direct", "tenantId": "a", "subjectType": "identity", "subjectId": "user-a", "roleId": "role-direct", "authorityId": "authority-a" }),
    )
    .await;
    insert(
        store,
        "bindings",
        json!({ "id": "binding-group", "tenantId": "a", "subjectType": "group", "subjectId": "group-a", "roleId": "role-group", "authorityId": "authority-a" }),
    )
    .await;
    insert(
        store,
        "bindings",
        json!({ "id": "binding-expired", "tenantId": "a", "subjectType": "identity", "subjectId": "user-a", "roleId": "role-expired", "authorityId": "authority-a", "expiresAt": now_ms() - 1000.0 }),
    )
    .await;
    insert(
        store,
        "identities",
        json!({
            "id": "service-b", "tenantId": "b", "name": "Service B", "kind": "service", "emailVerified": false,
            "status": "active", "rootAdmin": false, "owner": false, "createdAt": now_ms(),
        }),
    )
    .await;
}

fn identity_of(record: Map<String, Value>) -> Identity {
    serde_json::from_value(Value::Object(record)).expect("identity")
}

fn session(id: &str, tenant: &str, identity: &str, lifetime: f64, mfa: bool) -> Session {
    serde_json::from_value(json!({
        "id": id, "tenantId": tenant, "identityId": identity, "kind": "user", "tokenHash": "irrelevant",
        "createdAt": now_ms(), "authenticatedAt": now_ms(), "lastSeenAt": now_ms(), "expiresAt": now_ms() + lifetime, "mfa": mfa,
    }))
    .expect("session")
}

fn forbidden() -> IamError {
    IamError::with_status("FORBIDDEN", "Forbidden", 403)
}

/// The provider fixture: one server answering interactions (with the `admin` credential) and the provider mount.
async fn provider_fixture(store: &Arc<dyn IamStore>) -> (OAuthProvider, String) {
    let slot: Slot<OAuthProvider> = Arc::new(OnceLock::new());
    let handler_slot = slot.clone();
    let handler: Handler = Arc::new(move |request: HttpRequest| {
        let slot = handler_slot.clone();
        Box::pin(async move {
            let provider = slot.get().expect("provider").clone();
            if request.uri().path().starts_with("/interactions/") {
                let result = if request.method() == http::Method::POST {
                    provider
                        .complete_interaction(
                            &request,
                            &CredentialInput {
                                headers: None,
                                token: Some("admin".into()),
                            },
                            true,
                        )
                        .await
                } else {
                    provider
                        .interaction_details(&request)
                        .await
                        .map(|details| json_response(200, &details))
                };
                return result
                    .unwrap_or_else(|error| text_response(error.status, &error.to_string()));
            }
            provider.node_handler(&request).await
        })
    });
    let origin = serve(handler).await;
    let principal = AuthenticatedPrincipal {
        identity: identity_of(get(store, "identities", "user-a").await.unwrap()),
        session: session("session-a", "a", "user-a", 100_000.0, true),
        device_proof: None,
    };
    insert(
        store,
        "sessions",
        serde_json::to_value(&principal.session).unwrap(),
    )
    .await;
    let (signing, _) = rsa_key(0, "test-key");
    let config = provider_config(store, &origin, signing, principal);
    let provider = create_oauth_provider(config).expect("provider");
    let _ = slot.set(provider.clone());
    (provider, origin)
}

pub fn provider_config(
    store: &Arc<dyn IamStore>,
    origin: &str,
    signing: Value,
    principal: AuthenticatedPrincipal,
) -> OAuthProviderConfig {
    let interaction_origin = origin.to_owned();
    OAuthProviderConfig {
        store: store.clone(),
        issuer: format!("{origin}/oidc"),
        jwks: json!({ "keys": [signing] }),
        cookie_keys: vec!["test-key-with-at-least-32-characters-long".into()],
        encryption_key: ENCRYPTION_KEY.clone(),
        authenticate: Arc::new(move |credential: CredentialInput| {
            let principal = principal.clone();
            Box::pin(async move {
                if credential.token.as_deref() != Some("admin") {
                    return Err(forbidden());
                }
                Ok(principal)
            })
        }),
        validate_session: None,
        live_grants: None,
        client_allowed: None,
        authorize: Arc::new(|(credential, _, _)| {
            Box::pin(async move {
                if credential.token.as_deref() != Some("admin") {
                    return Err(forbidden());
                }
                Ok(())
            })
        }),
        interaction_url: Arc::new(move |uid: &str| {
            format!("{interaction_origin}/interactions/{uid}")
        }),
        render_device_page: Arc::new(|input: DevicePageInput| {
            Box::pin(async move { Ok(format!("<html><body>{}</body></html>", input.form)) })
        }),
        render_logout_page: Arc::new(|form: String| {
            Box::pin(async move { Ok(format!("<html><body>{form}</body></html>")) })
        }),
        trusted_origins: vec![origin.to_owned()],
        scopes: None,
        resource_servers: Default::default(),
        require_pushed_authorization_requests: false,
        dpop_nonce_secret: None,
        authorize_token_exchange: None,
        registration: None,
        trust_proxy: false,
        allow_insecure_localhost: true,
    }
}

static ENCRYPTION_KEY: std::sync::LazyLock<String> = std::sync::LazyLock::new(random_key_b64);

fn admin() -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some("admin".into()),
    }
}

#[test]
fn serves_discovery_and_pkce_only_authorization_without_a_development_login_ui() {
    run(|| async {
        let store = memory_store().await;
        seed(&store).await;
        let (provider, origin) = provider_fixture(&store).await;
        let discovery_response =
            get_url(&format!("{origin}/oidc/.well-known/openid-configuration")).await;
        assert_eq!(discovery_response.status, 200);
        let discovery = discovery_response.json();
        assert_eq!(discovery["issuer"], json!(format!("{origin}/oidc")));
        assert_eq!(
            discovery["authorization_endpoint"],
            json!(format!("{origin}/oidc/auth"))
        );
        assert_eq!(
            discovery["token_endpoint"],
            json!(format!("{origin}/oidc/token"))
        );
        assert_eq!(discovery["response_types_supported"], json!(["code"]));
        assert!(
            discovery["grant_types_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("urn:ietf:params:oauth:grant-type:device_code"))
        );
        assert!(discovery.get("registration_endpoint").is_none());
        provider
            .register_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "web", "name": "Web", "public": true, "redirectUris": [format!("{origin}/callback")] }),
            )
            .await
            .expect("register");
        let authorize = format!(
            "{}?{}",
            discovery["authorization_endpoint"].as_str().unwrap(),
            form(&[
                ("client_id", "web"),
                ("response_type", "code"),
                ("redirect_uri", &format!("{origin}/callback")),
                ("scope", "openid")
            ])
        );
        let missing_pkce = get_url(&authorize).await;
        assert_eq!(missing_pkce.status, 303);
        assert!(
            missing_pkce.location().contains("error=invalid_request"),
            "{}",
            missing_pkce.location()
        );
    });
}

#[test]
fn issues_tenant_bound_machine_tokens_introspects_and_immediately_revokes_clients() {
    run(|| async {
        let store = memory_store().await;
        seed(&store).await;
        let (provider, origin) = provider_fixture(&store).await;
        let client = provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "machine", "name": "Machine", "redirectUris": [],
                    "grantTypes": ["client_credentials"], "serviceAccountId": "service-a", "scopes": ["profile"],
                }),
            )
            .await
            .expect("register");
        let secret = client["clientSecret"].as_str().unwrap().to_owned();
        let authorization = basic("machine", &secret);
        let form_type = ("content-type", "application/x-www-form-urlencoded");
        let token_response = fetch(
            "POST",
            &format!("{origin}/oidc/token"),
            &[("authorization", &authorization), form_type],
            Some("grant_type=client_credentials&scope=profile"),
        )
        .await;
        assert_eq!(token_response.status, 200, "{}", token_response.body);
        let token = token_response.json();
        let access_token = token["access_token"].as_str().unwrap().to_owned();
        assert!(!access_token.is_empty());
        let introspection = fetch(
            "POST",
            &format!("{origin}/oidc/token/introspection"),
            &[("authorization", &authorization), form_type],
            Some(&form(&[("token", &access_token)])),
        )
        .await;
        assert_eq!(introspection.status, 200);
        let details = introspection.json();
        assert_eq!(details["active"], json!(true));
        assert_eq!(details["tenant_id"], json!("a"));
        assert_eq!(details["identity_id"], json!("service-a"));
        let stored =
            serde_json::to_string(&find(&store, "oauthArtifacts", Default::default()).await)
                .unwrap();
        assert!(!stored.contains(&access_token));
        let clients =
            serde_json::to_string(&find(&store, "oauthClients", Default::default()).await).unwrap();
        assert!(!clients.contains(&secret));
        let mut service = get(&store, "identities", "service-a").await.unwrap();
        service.insert("status".into(), json!("disabled"));
        put(&store, "identities", Value::Object(service.clone())).await;
        let disabled = fetch(
            "POST",
            &format!("{origin}/oidc/token/introspection"),
            &[("authorization", &authorization), form_type],
            Some(&form(&[("token", &access_token)])),
        )
        .await;
        assert_eq!(disabled.status, 401);
        service.insert("status".into(), json!("active"));
        put(&store, "identities", Value::Object(service)).await;
        provider
            .revoke_client(&admin(), &json!({ "tenantId": "a", "clientId": "machine" }))
            .await
            .expect("revoke");
        let revoked = fetch(
            "POST",
            &format!("{origin}/oidc/token"),
            &[("authorization", &authorization), form_type],
            Some("grant_type=client_credentials"),
        )
        .await;
        assert_eq!(revoked.status, 401);
    });
}

#[test]
fn rejects_unauthenticated_registration_and_immutable_client_tenant_rebinding() {
    run(|| async {
        let store = memory_store().await;
        seed(&store).await;
        let (provider, _origin) = provider_fixture(&store).await;
        let forged = provider
            .register_client(
                &CredentialInput { headers: None, token: Some("forged".into()) },
                &json!({ "tenantId": "a", "clientId": "machine", "name": "Machine", "redirectUris": [], "grantTypes": ["client_credentials"], "serviceAccountId": "service-a" }),
            )
            .await
            .unwrap_err();
        assert_eq!(forged.status, 403);
        provider
            .register_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "machine", "name": "Machine", "redirectUris": [], "grantTypes": ["client_credentials"], "serviceAccountId": "service-a" }),
            )
            .await
            .expect("register");
        let rebind = provider
            .register_client(
                &admin(),
                &json!({ "tenantId": "b", "clientId": "machine", "name": "Machine", "redirectUris": [], "grantTypes": ["client_credentials"], "serviceAccountId": "service-b" }),
            )
            .await
            .unwrap_err();
        assert_eq!(rebind.status, 409);
        let public = provider
            .register_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "bad-public", "name": "Bad", "redirectUris": [], "public": true, "grantTypes": ["client_credentials"], "serviceAccountId": "service-a" }),
            )
            .await
            .unwrap_err();
        assert_eq!(public.code, "INVALID_INPUT");
    });
}

async fn pkce_refresh_family(concurrent: bool) {
    let store = memory_store().await;
    seed(&store).await;
    let (provider, origin) = provider_fixture(&store).await;
    provider
        .register_client(
            &admin(),
            &json!({
                "tenantId": "a", "clientId": "public-web", "name": "Web", "public": true,
                "redirectUris": [format!("{origin}/callback")], "scopes": ["openid", "profile", "offline_access", "iam"],
            }),
        )
        .await
        .expect("register");
    let verifier = random_b64(32);
    let mut browser = Browser::default();
    let callback = format!("{origin}/callback");
    let challenge = sha256_b64url(&verifier);
    let params = form(&[
        ("client_id", "public-web"),
        ("response_type", "code"),
        ("redirect_uri", &callback),
        ("scope", "openid profile offline_access iam"),
        ("prompt", "consent"),
        ("state", "state"),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let mut result = browser.get(&format!("{origin}/oidc/auth?{params}")).await;
    let mut redirect = result.location();
    assert!(
        redirect.contains("/interactions/"),
        "{} {}",
        result.status,
        result.body
    );
    let details = browser.get(&absolute(&redirect, &origin)).await;
    assert_eq!(details.json()["tenantId"], json!("a"), "{}", details.body);
    let csrf = browser
        .visit("POST", &absolute(&redirect, &origin), &[], None)
        .await;
    assert_eq!(csrf.status, 403);
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
        .unwrap_or_else(|| panic!("no code: {} {}", result.status, result.body));
    let exchange = |body: String| {
        let url = format!("{origin}/oidc/token");
        async move {
            fetch(
                "POST",
                &url,
                &[("content-type", "application/x-www-form-urlencoded")],
                Some(&body),
            )
            .await
        }
    };
    let token_response = exchange(form(&[
        ("grant_type", "authorization_code"),
        ("client_id", "public-web"),
        ("code", &code),
        ("code_verifier", &verifier),
        ("redirect_uri", &callback),
    ]))
    .await;
    assert_eq!(token_response.status, 200, "{}", token_response.body);
    let tokens = token_response.json();
    let refresh_token = tokens["refresh_token"]
        .as_str()
        .expect("refresh token")
        .to_owned();
    let id_token = claims_of(tokens["id_token"].as_str().unwrap());
    assert_eq!(id_token["sub"], json!("user-a"));
    assert_eq!(id_token["tenant_id"], json!("a"));
    let userinfo = fetch(
        "GET",
        &format!("{origin}/oidc/me"),
        &[(
            "authorization",
            &format!("Bearer {}", tokens["access_token"].as_str().unwrap()),
        )],
        None,
    )
    .await;
    assert_eq!(userinfo.status, 200, "{}", userinfo.body);
    let info = userinfo.json();
    assert_eq!(info["sub"], json!("user-a"));
    assert_eq!(info["roles"], json!(["role-direct", "role-group"]));
    assert_eq!(info["groups"], json!(["group-a"]));
    assert_eq!(info["attributes"], json!({ "department": "finance" }));
    let rotate = exchange(form(&[
        ("grant_type", "refresh_token"),
        ("client_id", "public-web"),
        ("refresh_token", &refresh_token),
    ]))
    .await;
    assert_eq!(rotate.status, 200, "{}", rotate.body);
    let rotated = rotate.json();
    let rotated_refresh = rotated["refresh_token"].as_str().unwrap().to_owned();
    assert_ne!(rotated_refresh, refresh_token);
    if concurrent {
        let body = form(&[
            ("grant_type", "refresh_token"),
            ("client_id", "public-web"),
            ("refresh_token", &rotated_refresh),
        ]);
        let (first, second) = tokio::join!(exchange(body.clone()), exchange(body.clone()));
        let raced = [first, second];
        assert!(
            raced
                .iter()
                .filter(|response| response.status == 200)
                .count()
                <= 1
        );
        assert!(raced.iter().any(|response| response.status == 400));
        for response in &raced {
            if response.status == 200 {
                let issued = response.json();
                let revoked = exchange(form(&[
                    ("grant_type", "refresh_token"),
                    ("client_id", "public-web"),
                    ("refresh_token", issued["refresh_token"].as_str().unwrap()),
                ]))
                .await;
                assert_eq!(revoked.status, 400);
            }
        }
    }
    let replay = exchange(form(&[
        ("grant_type", "refresh_token"),
        ("client_id", "public-web"),
        ("refresh_token", &refresh_token),
    ]))
    .await;
    assert_eq!(replay.status, 400);
    assert_eq!(replay.json()["error"], json!("invalid_grant"));
    let family = exchange(form(&[
        ("grant_type", "refresh_token"),
        ("client_id", "public-web"),
        ("refresh_token", &rotated_refresh),
    ]))
    .await;
    assert_eq!(family.status, 400);
    assert_eq!(family.json()["error"], json!("invalid_grant"));
}

#[test]
fn completes_pkce_and_invalidates_refresh_families_on_replay() {
    run(|| async { pkce_refresh_family(false).await });
}

#[test]
fn completes_pkce_and_invalidates_refresh_families_on_concurrent_replay() {
    run(|| async { pkce_refresh_family(true).await });
}

#[test]
fn persists_provider_artifacts_across_adapter_instances_enforces_scope_and_consumes_atomically() {
    run(|| async {
        let store = memory_store().await;
        seed(&store).await;
        let (provider, _origin) = provider_fixture(&store).await;
        provider
            .register_client(&admin(), &json!({ "tenantId": "a", "clientId": "web", "name": "Web", "redirectUris": ["https://app.test/callback"] }))
            .await
            .expect("register");
        let factory =
            create_provider_adapter(store.clone(), &ENCRYPTION_KEY, None, None).expect("adapter");
        let first = factory.model("RefreshToken");
        let second = factory.model("RefreshToken");
        insert(&store, "oauthGrantSessions", json!({ "id": hash("grant"), "tenantId": "a", "sessionId": "session-a", "identityId": "user-a" })).await;
        let payload = |value: Value| value.as_object().cloned().unwrap();
        first
            .upsert("refresh-secret", &payload(json!({ "clientId": "web", "accountId": "user-a", "grantId": "grant", "jti": "refresh-secret" })), Some(60.0))
            .await
            .expect("upsert");
        assert_eq!(
            second.find("refresh-secret").await.unwrap().unwrap()["accountId"],
            json!("user-a")
        );
        let foreign = first
            .upsert(
                "foreign",
                &payload(json!({ "clientId": "web", "accountId": "user-b" })),
                Some(60.0),
            )
            .await
            .unwrap_err();
        assert_eq!(
            foreign.oidc().map(|error| error.error.as_str()),
            Some("invalid_grant")
        );
        let (one, two) = tokio::join!(
            first.consume("refresh-secret"),
            second.consume("refresh-secret")
        );
        assert_eq!(
            [one.is_ok(), two.is_ok()].iter().filter(|ok| **ok).count(),
            1
        );
        assert!(first.find("refresh-secret").await.unwrap().is_none());
        second.revoke_by_grant_id("grant").await.expect("revoke");
        assert!(first.find("refresh-secret").await.unwrap().is_none());
        insert(&store, "oauthGrantSessions", json!({ "id": hash("session-grant"), "tenantId": "a", "sessionId": "session-a", "identityId": "user-a" })).await;
        let session = factory.model("Session");
        session
            .upsert("anonymous", &payload(json!({ "uid": "uid" })), Some(60.0))
            .await
            .expect("anonymous");
        session
            .upsert(
                "anonymous",
                &payload(json!({ "uid": "uid", "accountId": "user-a", "authorizations": { "web": { "grantId": "session-grant" } } })),
                Some(60.0),
            )
            .await
            .expect("login");
        assert_eq!(
            session.find_by_uid("uid").await.unwrap().unwrap()["accountId"],
            json!("user-a")
        );
        let rebound = session
            .upsert(
                "anonymous",
                &payload(json!({ "uid": "uid", "accountId": "user-b" })),
                Some(60.0),
            )
            .await
            .unwrap_err();
        assert_eq!(
            rebound.oidc().map(|error| error.error.as_str()),
            Some("invalid_grant")
        );
        insert(&store, "oauthGrantSessions", json!({ "id": hash("live-grant"), "tenantId": "a", "sessionId": "session-a", "identityId": "user-a" })).await;
        first
            .upsert(
                "another-refresh",
                &payload(
                    json!({ "clientId": "web", "accountId": "user-a", "grantId": "live-grant" }),
                ),
                Some(60.0),
            )
            .await
            .expect("upsert");
        delete(&store, "sessions", "session-a").await;
        assert!(first.find("another-refresh").await.unwrap().is_none());
    });
}

/// An OIDC provider stub: discovery, JWKS and a token endpoint signing ID tokens with the fixture key.
#[derive(Default)]
struct OidcStub {
    origin: String,
    nonce: String,
    challenge: String,
    bad_nonce: bool,
    exchanges: usize,
}

#[test]
fn verifies_oidc_signatures_nonce_and_pkce_while_preventing_callback_replay_or_email_linking() {
    run(|| async {
        let store = memory_store().await;
        seed(&store).await;
        let state = Arc::new(Mutex::new(OidcStub::default()));
        let (signing, public) = rsa_key(0, "test-key");
        let handler_state = state.clone();
        let handler: Handler = Arc::new(move |request: HttpRequest| {
            let state = handler_state.clone();
            let signing = signing.clone();
            let public = public.clone();
            Box::pin(async move {
                let origin = state.lock().unwrap().origin.clone();
                match request.uri().path() {
                    "/.well-known/openid-configuration" => json_response(
                        200,
                        &json!({
                            "issuer": origin, "authorization_endpoint": format!("{origin}/authorize"),
                            "token_endpoint": format!("{origin}/token"), "jwks_uri": format!("{origin}/jwks"),
                            "response_types_supported": ["code"], "subject_types_supported": ["public"],
                            "id_token_signing_alg_values_supported": ["RS256"],
                        }),
                    ),
                    "/jwks" => json_response(200, &json!({ "keys": [public] })),
                    "/token" => {
                        let body = String::from_utf8_lossy(request.body()).into_owned();
                        let verifier = url::form_urlencoded::parse(body.as_bytes())
                            .find(|(key, _)| key == "code_verifier")
                            .map(|(_, value)| value.into_owned())
                            .unwrap_or_default();
                        let mut stub = state.lock().unwrap();
                        assert_eq!(sha256_b64url(&verifier), stub.challenge);
                        stub.exchanges += 1;
                        let now = (now_ms() / 1000.0).floor();
                        let jwt = sign(
                            &signing,
                            "RS256",
                            json!({ "kid": "test-key" }),
                            json!({
                                "nonce": if stub.bad_nonce { "wrong".to_owned() } else { stub.nonce.clone() },
                                "email": "same@example.test", "email_verified": true, "name": "Federated",
                                "iss": origin, "aud": "login", "sub": "stable-subject", "iat": now, "exp": now + 300.0,
                            }),
                        );
                        json_response(
                            200,
                            &json!({ "access_token": "provider-access-token", "token_type": "Bearer", "id_token": jwt, "expires_in": 300 }),
                        )
                    }
                    _ => json_response(404, &json!({})),
                }
            })
        });
        let origin = serve(handler).await;
        state.lock().unwrap().origin = origin.clone();
        let identities: Arc<Mutex<Vec<FederatedIdentity>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = identities.clone();
        let login = create_oauth_login(OAuthLoginConfig {
            store: store.clone(),
            connections: vec![OAuthLoginConnection {
                id: "login-a".into(),
                tenant_id: "a".into(),
                kind: ConnectionKind::Oidc,
                issuer: Some(origin.clone()),
                client_id: "login".into(),
                redirect_uri: format!("{origin}/callback"),
                map_attributes: Some(Arc::new(|claims: &Map<String, Value>| {
                    let mut out = Map::new();
                    out.insert("upstreamSubject".into(), claims["sub"].clone());
                    Some(out)
                })),
                trust_scim_provisioned: Some(json!(["scim-1"])),
                ..OAuthLoginConnection::default()
            }],
            allow_insecure_localhost: true,
            complete_authentication: Arc::new(move |identity: FederatedIdentity| {
                let recorded = recorded.clone();
                Box::pin(async move {
                    recorded.lock().unwrap().push(identity);
                    Ok(json!({ "verified": true }))
                })
            }),
            authenticate: None,
            trusted_origins: None,
            base_path: None,
        })
        .expect("login");
        let begin = login.begin("login-a", None, None).await.expect("begin");
        {
            let mut stub = state.lock().unwrap();
            stub.nonce = query_param(&begin.url, "nonce").unwrap();
            stub.challenge = query_param(&begin.url, "code_challenge").unwrap();
        }
        let returned = format!("{origin}/callback?code=valid&state={}", begin.state);
        let forged = login
            .callback("login-a", &returned, "forged")
            .await
            .unwrap_err();
        assert_eq!(forged.code, "OAUTH_STATE");
        let (one, two) = tokio::join!(
            login.callback("login-a", &returned, &begin.binding),
            login.callback("login-a", &returned, &begin.binding)
        );
        assert_eq!(
            [one.is_ok(), two.is_ok()].iter().filter(|ok| **ok).count(),
            1,
            "{one:?} {two:?}"
        );
        assert_eq!(state.lock().unwrap().exchanges, 1);
        let recorded: Vec<Value> = identities
            .lock()
            .unwrap()
            .iter()
            .map(FederatedIdentity::to_value)
            .collect();
        assert_eq!(
            recorded,
            vec![json!({
                "tenantId": "a", "providerId": "login-a", "issuer": origin, "subject": "stable-subject",
                "email": "same@example.test", "emailVerified": true, "name": "Federated",
                "attributes": { "upstreamSubject": "stable-subject" }, "trustScimProvisioned": ["scim-1"],
            })]
        );
        let bad_trust = create_oauth_login(OAuthLoginConfig {
            store: store.clone(),
            connections: vec![OAuthLoginConnection {
                id: "bad-trust".into(),
                tenant_id: "a".into(),
                kind: ConnectionKind::Oidc,
                issuer: Some(origin.clone()),
                client_id: "login".into(),
                redirect_uri: format!("{origin}/other-callback"),
                trust_scim_provisioned: Some(json!("yes")),
                ..OAuthLoginConnection::default()
            }],
            allow_insecure_localhost: true,
            complete_authentication: Arc::new(|_| Box::pin(async { Ok(Value::Null) })),
            authenticate: None,
            trusted_origins: None,
            base_path: None,
        })
        .unwrap_err();
        assert!(bad_trust.message.contains("trustScimProvisioned"));
        let again = login.begin("login-a", None, None).await.expect("begin");
        {
            let mut stub = state.lock().unwrap();
            stub.nonce = query_param(&again.url, "nonce").unwrap();
            stub.challenge = query_param(&again.url, "code_challenge").unwrap();
            stub.bad_nonce = true;
        }
        let failed = login
            .callback(
                "login-a",
                &format!("{origin}/callback?code=valid&state={}", again.state),
                &again.binding,
            )
            .await;
        assert!(failed.is_err());
        assert_eq!(identities.lock().unwrap().len(), 1);
    });
}

#[test]
fn supports_configured_oauth2_identity_mapping_and_explicit_browser_bound_account_linking() {
    run(|| async {
        let store = memory_store().await;
        seed(&store).await;
        let handler: Handler = Arc::new(|request: HttpRequest| {
            Box::pin(async move {
                let authorization = request
                    .headers()
                    .get("authorization")
                    .and_then(|v| v.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                match request.uri().path() {
                    "/token" => json_response(
                        200,
                        &json!({ "access_token": "verified-token", "token_type": "Bearer" }),
                    ),
                    "/profile" if authorization == "Bearer verified-token" => json_response(
                        200,
                        &json!({ "id": "provider-subject", "mail": "same@example.test" }),
                    ),
                    _ => json_response(401, &json!({})),
                }
            })
        });
        let origin = serve(handler).await;
        let principal = Arc::new(Mutex::new(AuthenticatedPrincipal {
            identity: identity_of(get(&store, "identities", "user-a").await.unwrap()),
            session: session("link-session", "a", "user-a", 600_000.0, false),
            device_proof: None,
        }));
        let completed: Arc<Mutex<Vec<FederatedIdentity>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = completed.clone();
        let auth_principal = principal.clone();
        let login = create_oauth_login(OAuthLoginConfig {
            store: store.clone(),
            allow_insecure_localhost: true,
            trusted_origins: Some(vec![origin.clone()]),
            connections: vec![OAuthLoginConnection {
                id: "custom".into(),
                kind: ConnectionKind::Oauth2,
                tenant_id: "a".into(),
                client_id: "custom".into(),
                issuer: Some(origin.clone()),
                redirect_uri: format!("{origin}/callback"),
                authorization_endpoint: Some(format!("{origin}/authorize")),
                token_endpoint: Some(format!("{origin}/token")),
                user_info_endpoint: Some(format!("{origin}/profile")),
                map_profile: Some(Arc::new(|profile: &Map<String, Value>| MappedProfile {
                    subject: json!(profile["id"].as_str().unwrap_or_default()),
                    email: profile["mail"].as_str().map(str::to_owned),
                    email_verified: Some(true),
                    name: None,
                })),
                ..OAuthLoginConnection::default()
            }],
            authenticate: Some(Arc::new(move |credential: CredentialInput| {
                let principal = auth_principal.clone();
                Box::pin(async move {
                    let authorization = credential
                        .headers
                        .unwrap_or_default()
                        .into_iter()
                        .find(|(name, _)| name.eq_ignore_ascii_case("authorization"))
                        .map(|(_, value)| value);
                    if authorization.as_deref() != Some("Bearer local-session") {
                        return Err(forbidden());
                    }
                    Ok(principal.lock().unwrap().clone())
                })
            })),
            complete_authentication: Arc::new(move |identity: FederatedIdentity| {
                let recorded = recorded.clone();
                Box::pin(async move {
                    recorded.lock().unwrap().push(identity);
                    Ok(json!({ "linked": true }))
                })
            }),
            base_path: None,
        })
        .expect("login");
        let request = |origin_header: Option<&str>| {
            let mut builder = http::Request::builder()
                .method("POST")
                .uri(format!("{origin}/oauth/login/custom"))
                .header("authorization", "Bearer local-session")
                .header("content-type", "application/json")
                .header("x-better-iam", "1");
            if let Some(value) = origin_header {
                builder = builder.header("origin", value);
            }
            builder.body(Bytes::new()).unwrap()
        };
        let forged = login.handler(&request(None)).await.expect("handled");
        assert_eq!(forged.status(), 403);
        let response = login
            .handler(&request(Some(&origin)))
            .await
            .expect("handled");
        assert_eq!(response.status(), 200);
        let body: Value = serde_json::from_slice(response.body()).unwrap();
        let url = body["url"].as_str().unwrap().to_owned();
        let cookie = response
            .headers()
            .get("set-cookie")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert!(!cookie.contains("__Host-"));
        assert!(!cookie.contains("Secure"));
        let binding = cookie
            .split(';')
            .next()
            .unwrap()
            .split('=')
            .nth(1)
            .unwrap()
            .to_owned();
        let state = query_param(&url, "state").unwrap();
        let linked = login
            .callback(
                "custom",
                &format!("{origin}/callback?code=verified&state={state}"),
                &binding,
            )
            .await
            .expect("callback");
        assert_eq!(linked, json!({ "linked": true }));
        let recorded: Vec<Value> = completed
            .lock()
            .unwrap()
            .iter()
            .map(FederatedIdentity::to_value)
            .collect();
        assert_eq!(
            recorded,
            vec![json!({
                "tenantId": "a", "providerId": "custom", "issuer": origin, "subject": "provider-subject",
                "email": "same@example.test", "emailVerified": true,
                "linkingIdentityId": "user-a", "linkingSessionId": "link-session",
            })]
        );
        principal.lock().unwrap().identity.root_admin = true;
        let refused = login
            .begin(
                "custom",
                Some(&CredentialInput {
                    headers: Some(vec![(
                        "authorization".into(),
                        "Bearer local-session".into(),
                    )]),
                    token: None,
                }),
                None,
            )
            .await
            .unwrap_err();
        assert_eq!(refused.status, 403);
    });
}
