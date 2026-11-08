//! Port of tests/oauth-mcp-integration.test.ts: MCP authorization end to end.

mod common;
#[allow(unused_imports)]
#[path = "../../server/tests/organization_fixture/mod.rs"]
mod organization_fixture;

use std::sync::{Arc, OnceLock};

use better_iam_oauth::{
    DevicePageInput, GuardOutcome, OAuthProvider, OAuthProviderConfig, OAuthResourceServer,
    ProtectedResourceMetadataOptions, RegistrationConfig, RegistrationPolicy, ResourceGuard,
    ResourceGuardOptions, create_oauth_provider, create_resource_guard,
};
use common::host::protocol_host;
use common::{
    Browser, Handler, HttpRequest, Slot, absolute, fetch, form, get_url, json_response,
    query_param, random_b64, random_key_b64, rsa_key, serve, sha256_b64url, text_response,
};
use organization_fixture::organization;
use serde_json::json;

#[test]
fn discovers_registers_consents_and_calls_a_guarded_mcp_server() {
    organization_fixture::run(|| async {
        let fixture = organization(|_| {}).await;
        let tenant_id = fixture.tenant_id.clone();
        let alice_id = fixture.member("alice").await;
        let alice = fixture.sign_in(&alice_id).await;
        let alice_credential = alice.clone();
        let provider_slot: Slot<OAuthProvider> = Arc::new(OnceLock::new());
        let guard_slot: Slot<ResourceGuard> = Arc::new(OnceLock::new());
        let (handler_provider, handler_guard) = (provider_slot.clone(), guard_slot.clone());
        let handler: Handler = Arc::new(move |request: HttpRequest| {
            let (provider_slot, guard_slot) = (handler_provider.clone(), handler_guard.clone());
            let alice = alice_credential.clone();
            Box::pin(async move {
                let provider = provider_slot.get().expect("provider").clone();
                let path = request.uri().path().to_owned();
                if path.starts_with("/interactions/") {
                    let result = if request.method() == http::Method::POST {
                        provider.complete_interaction(&request, &alice, true).await
                    } else {
                        provider
                            .interaction_details(&request)
                            .await
                            .map(|details| json_response(200, &details))
                    };
                    return result
                        .unwrap_or_else(|error| text_response(error.status, &error.to_string()));
                }
                if path == "/mcp" || path.starts_with("/.well-known/oauth-protected-resource") {
                    let guard = guard_slot.get().expect("guard");
                    return match guard.check(&request, &[]).await {
                        GuardOutcome::Response(response) => response,
                        GuardOutcome::Token(token) => json_response(
                            200,
                            &json!({ "jsonrpc": "2.0", "result": { "user": token.subject, "tenant": token.tenant_id } }),
                        ),
                    };
                }
                provider.node_handler(&request).await
            })
        });
        let origin = serve(handler).await;
        let resource = format!("{origin}/mcp");
        let host = protocol_host(&fixture.iam).expect("protocol host");
        let (signing, _) = rsa_key(0, "mcp-key");
        let interaction_origin = origin.clone();
        let registration_tenant = tenant_id.clone();
        let registration_resource = resource.clone();
        let mut resource_servers = indexmap::IndexMap::new();
        resource_servers.insert(
            resource.clone(),
            OAuthResourceServer {
                scopes: vec!["mcp:tools".into()],
                ..OAuthResourceServer::default()
            },
        );
        let provider = create_oauth_provider(OAuthProviderConfig {
            store: host.store.clone(),
            issuer: format!("{origin}/oidc"),
            jwks: json!({ "keys": [signing] }),
            cookie_keys: vec!["mcp-integration-cookie-key-with-32-characters".into()],
            encryption_key: random_key_b64(),
            authenticate: host.authenticate.clone(),
            validate_session: Some(host.validate_session.clone()),
            live_grants: Some(host.live_grants.clone()),
            client_allowed: Some(host.client_allowed.clone()),
            authorize: host.authorize.clone(),
            interaction_url: Arc::new(move |uid: &str| {
                format!("{interaction_origin}/interactions/{uid}")
            }),
            render_device_page: Arc::new(|input: DevicePageInput| {
                Box::pin(async move { Ok(input.form) })
            }),
            render_logout_page: Arc::new(|form: String| Box::pin(async move { Ok(form) })),
            trusted_origins: vec![origin.clone()],
            scopes: None,
            resource_servers,
            require_pushed_authorization_requests: false,
            dpop_nonce_secret: None,
            authorize_token_exchange: None,
            registration: Some(RegistrationConfig {
                anonymous: Some(Arc::new(move |_| {
                    let (tenant_id, resource) =
                        (registration_tenant.clone(), registration_resource.clone());
                    Box::pin(async move {
                        Ok(Some(RegistrationPolicy {
                            tenant_id,
                            scopes: Some(vec![
                                "openid".into(),
                                "offline_access".into(),
                                "mcp:tools".into(),
                            ]),
                            resources: Some(vec![resource]),
                            ..RegistrationPolicy::default()
                        }))
                    })
                })),
            }),
            trust_proxy: false,
            allow_insecure_localhost: true,
        })
        .expect("provider");
        let _ = provider_slot.set(provider.clone());
        let guard = create_resource_guard(ResourceGuardOptions {
            metadata: ProtectedResourceMetadataOptions {
                resource: resource.clone(),
                authorization_servers: vec![format!("{origin}/oidc")],
                scopes: Some(vec!["mcp:tools".into()]),
                ..ProtectedResourceMetadataOptions::default()
            },
            required_scopes: vec!["mcp:tools".into()],
            ..ResourceGuardOptions::default()
        })
        .expect("guard");
        let _ = guard_slot.set(guard);

        // 1. Unauthenticated call: the challenge names the protected resource metadata.
        let first = get_url(&resource).await;
        assert_eq!(first.status, 401);
        let challenge = first.header("www-authenticate").unwrap();
        let metadata_url = regex::Regex::new(r#"resource_metadata="([^"]+)""#)
            .unwrap()
            .captures(&challenge)
            .unwrap()[1]
            .to_owned();
        let metadata = get_url(&metadata_url).await.json();
        assert_eq!(metadata["resource"], json!(resource));

        // 2. Authorization server metadata (RFC 8414 path insertion for an issuer with a path).
        let issuer =
            url::Url::parse(metadata["authorization_servers"][0].as_str().unwrap()).unwrap();
        let server8414 = get_url(&format!(
            "{}/.well-known/oauth-authorization-server{}",
            issuer.origin().ascii_serialization(),
            issuer.path()
        ))
        .await
        .json();
        assert_eq!(server8414["issuer"], json!(format!("{origin}/oidc")));
        assert!(
            server8414["code_challenge_methods_supported"]
                .as_array()
                .unwrap()
                .contains(&json!("S256"))
        );

        // 3. Dynamic registration, anonymously, as MCP hosts do.
        let registration = fetch(
            "POST",
            server8414["registration_endpoint"].as_str().unwrap(),
            &[("content-type", "application/json")],
            Some(
                &json!({
                    "client_name": "Example MCP host",
                    "redirect_uris": [format!("{origin}/callback")],
                    "token_endpoint_auth_method": "none",
                    "grant_types": ["authorization_code", "refresh_token"],
                    "response_types": ["code"],
                })
                .to_string(),
            ),
        )
        .await
        .json();
        let client_id = registration["client_id"]
            .as_str()
            .expect("client id")
            .to_owned();

        // 4. Authorization code with PKCE and the resource; Alice consents.
        let verifier = random_b64(32);
        let challenge = sha256_b64url(&verifier);
        let callback_uri = format!("{origin}/callback");
        let mut browser = Browser::default();
        let mut step = browser
            .get(&format!(
                "{}?{}",
                server8414["authorization_endpoint"].as_str().unwrap(),
                form(&[
                    ("client_id", &client_id),
                    ("response_type", "code"),
                    ("redirect_uri", &callback_uri),
                    ("scope", "mcp:tools offline_access"),
                    ("resource", &resource),
                    ("code_challenge", &challenge),
                    ("code_challenge_method", "S256"),
                    ("state", "xyz"),
                ])
            ))
            .await;
        let mut location = step.location();
        let details = browser.get(&absolute(&location, &origin)).await.json();
        assert_eq!(details["tenantId"], json!(tenant_id));
        assert_eq!(details["clientName"], json!("Example MCP host"));
        assert_eq!(details["resources"], json!([resource]));
        step = browser
            .visit(
                "POST",
                &absolute(&location, &origin),
                &[("origin", &origin)],
                None,
            )
            .await;
        location = step.location();
        let mut i = 0;
        while i < 5 && !location.contains("/callback?") {
            step = browser.get(&absolute(&location, &origin)).await;
            location = step.location();
            i += 1;
        }
        let callback = absolute(&location, &origin);
        assert_eq!(
            query_param(&callback, "state").as_deref(),
            Some("xyz"),
            "{} {}",
            step.status,
            step.body
        );
        let code = query_param(&callback, "code").expect("code");
        let token_endpoint = server8414["token_endpoint"].as_str().unwrap().to_owned();
        let tokens = fetch(
            "POST",
            &token_endpoint,
            &[("content-type", "application/x-www-form-urlencoded")],
            Some(&form(&[
                ("grant_type", "authorization_code"),
                ("client_id", &client_id),
                ("code", &code),
                ("code_verifier", &verifier),
                ("redirect_uri", &callback_uri),
                ("resource", &resource),
            ])),
        )
        .await
        .json();
        let refresh_token = tokens["refresh_token"]
            .as_str()
            .expect("refresh token")
            .to_owned();

        // 5. The MCP call succeeds for Alice in her organization.
        let access_token = tokens["access_token"].as_str().unwrap().to_owned();
        let call = fetch(
            "GET",
            &resource,
            &[("authorization", &format!("Bearer {access_token}"))],
            None,
        )
        .await;
        assert_eq!(call.status, 200, "{}", call.body);
        assert_eq!(
            call.json()["result"],
            json!({ "user": alice_id, "tenant": tenant_id })
        );

        // 6. IAM authorization governs registration tokens: the owner may issue one, Alice may not.
        let issued = provider
            .create_registration_token(
                &fixture.owner_credential,
                &json!({ "tenantId": tenant_id, "name": "IDE plugin" }),
            )
            .await
            .expect("owner may issue");
        assert!(
            issued["token"]
                .as_str()
                .is_some_and(|token| !token.is_empty())
        );
        let denied = provider
            .create_registration_token(&alice, &json!({ "tenantId": tenant_id, "name": "Mine" }))
            .await
            .unwrap_err();
        assert_eq!(denied.status, 403);

        // 7. Signing out ends the grant: the refresh token stops working once ended sessions are swept.
        fixture.iam.auth.sign_out(&alice).await.expect("signed out");
        provider.logout_ended_sessions(None).await.expect("swept");
        let refreshed = fetch(
            "POST",
            &token_endpoint,
            &[("content-type", "application/x-www-form-urlencoded")],
            Some(&form(&[
                ("grant_type", "refresh_token"),
                ("client_id", &client_id),
                ("refresh_token", &refresh_token),
            ])),
        )
        .await;
        assert_eq!(refreshed.status, 400);
    });
}
