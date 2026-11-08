//! Port of tests/security-oauth.test.ts: a client's service account stands behind the client's own tokens only, and
//! the dynamic registration gate cannot be sidestepped by spelling the route differently.

mod common;

use std::sync::Arc;

use better_iam_core::{Filter, IamStore};
use better_iam_oauth::{
    AccessTokenVerifierOptions, OAuthResourceServer, RegistrationConfig,
    create_access_token_verifier,
};
use common::provider::*;
use common::*;
use serde_json::json;

const API: &str = "https://api.example.test";
const REPORTS: &str = "https://reports.example.test";

async fn seed() -> Arc<dyn IamStore> {
    let store = memory_store().await;
    seed_tenants(&store, &["root", "a"]).await;
    seed_identity(&store, "user-a", "a", "user").await;
    seed_identity(&store, "service-a", "a", "service").await;
    store
}

fn server(scopes: &[&str]) -> OAuthResourceServer {
    OAuthResourceServer {
        scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
        ..OAuthResourceServer::default()
    }
}

async fn fixture(
    store: &Arc<dyn IamStore>,
    registration: Option<RegistrationConfig>,
) -> ProviderFixture {
    provider_fixture(store, move |config, _| {
        config
            .resource_servers
            .insert(API.into(), server(&["invoices:read"]));
        config
            .resource_servers
            .insert(REPORTS.into(), server(&["reports:read"]));
        if registration.is_some() {
            config.registration = registration;
        }
    })
    .await
}

/// A person's authorization-code token for `client_id`.
async fn authorize(f: &ProviderFixture, client_id: &str, secret: &str) -> String {
    let mut browser = Browser::default();
    let origin = f.origin.clone();
    let verifier = random_b64(32);
    let challenge = sha256_b64url(&verifier);
    let callback = format!("{origin}/callback");
    let params = form(&[
        ("client_id", client_id),
        ("response_type", "code"),
        ("redirect_uri", &callback),
        ("scope", "openid invoices:read"),
        ("prompt", "consent"),
        ("state", "state"),
        ("resource", API),
        ("code_challenge", &challenge),
        ("code_challenge_method", "S256"),
    ]);
    let mut result = browser.get(&format!("{origin}/oidc/auth?{params}")).await;
    let mut redirect = result.location();
    browser.get(&absolute(&redirect, &origin)).await;
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
    let response = f
        .token(
            &[
                ("grant_type", "authorization_code"),
                ("client_id", client_id),
                ("code", &code),
                ("code_verifier", &verifier),
                ("redirect_uri", &callback),
                ("resource", API),
            ],
            &[("authorization", &basic(client_id, secret))],
        )
        .await;
    assert_eq!(response.status, 200, "{}", response.body);
    response.json()["access_token"].as_str().unwrap().to_owned()
}

#[test]
fn names_the_service_account_only_on_the_clients_own_tokens_never_on_a_persons_and_exchange_keeps_the_person()
 {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store, None).await;
        let web = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "web", "name": "Web",
                    "grantTypes": ["authorization_code", "refresh_token", "client_credentials"], "serviceAccountId": "service-a",
                    "redirectUris": [format!("{}/callback", f.origin)], "scopes": ["openid", "invoices:read"], "resources": [API],
                }),
            )
            .await
            .unwrap();
        let gateway = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "gateway", "name": "Gateway", "redirectUris": [],
                    "grantTypes": ["urn:ietf:params:oauth:grant-type:token-exchange"], "scopes": ["reports:read"], "resources": [REPORTS],
                }),
            )
            .await
            .unwrap();
        let web_secret = web["clientSecret"].as_str().unwrap().to_owned();
        let personal = authorize(&f, "web", &web_secret).await;
        assert_eq!(claims_of(&personal)["sub"], json!("user-a"));
        assert!(claims_of(&personal).get("identity_id").is_none());
        let view = create_access_token_verifier(AccessTokenVerifierOptions {
            issuer: format!("{}/oidc", f.origin),
            audience: vec![API.into()],
            jwks: Some(json!({ "keys": [f.public_key] })),
            ..AccessTokenVerifierOptions::default()
        })
        .unwrap()
        .verify(&personal, &[])
        .await
        .unwrap();
        assert!(view.identity_id.is_none());
        let exchanged = f
            .token(
                &[
                    (
                        "grant_type",
                        "urn:ietf:params:oauth:grant-type:token-exchange",
                    ),
                    (
                        "subject_token_type",
                        "urn:ietf:params:oauth:token-type:access_token",
                    ),
                    ("subject_token", &personal),
                    ("resource", REPORTS),
                ],
                &[(
                    "authorization",
                    &basic("gateway", gateway["clientSecret"].as_str().unwrap()),
                )],
            )
            .await
            .json();
        assert_eq!(
            claims_of(exchanged["access_token"].as_str().unwrap())["sub"],
            json!("user-a")
        );
        let own = f
            .token(
                &[
                    ("grant_type", "client_credentials"),
                    ("resource", API),
                    ("scope", "invoices:read"),
                ],
                &[("authorization", &basic("web", &web_secret))],
            )
            .await
            .json();
        assert_eq!(
            claims_of(own["access_token"].as_str().unwrap())["identity_id"],
            json!("service-a")
        );
    });
}

#[test]
fn refuses_to_exchange_a_token_once_its_app_is_disconnected_and_gives_dpop_only_clients_no_bearer_token()
 {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store, None).await;
        let web = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "web", "name": "Web", "redirectUris": [format!("{}/callback", f.origin)],
                    "scopes": ["openid", "invoices:read"], "resources": [API],
                }),
            )
            .await
            .unwrap();
        let exchange_client = |client_id: &str, dpop: bool| {
            json!({
                "tenantId": "a", "clientId": client_id, "name": client_id, "redirectUris": [], "requireDpop": dpop,
                "grantTypes": ["urn:ietf:params:oauth:grant-type:token-exchange"], "scopes": ["reports:read"], "resources": [REPORTS],
            })
        };
        let gateway = f
            .provider
            .register_client(&admin(), &exchange_client("gateway", false))
            .await
            .unwrap();
        let strict = f
            .provider
            .register_client(&admin(), &exchange_client("strict", true))
            .await
            .unwrap();
        let personal = authorize(&f, "web", web["clientSecret"].as_str().unwrap()).await;
        let exchange = |client_id: &'static str, secret: String| {
            let f = &f;
            let personal = personal.clone();
            async move {
                f.token(
                    &[
                        (
                            "grant_type",
                            "urn:ietf:params:oauth:grant-type:token-exchange",
                        ),
                        (
                            "subject_token_type",
                            "urn:ietf:params:oauth:token-type:access_token",
                        ),
                        ("subject_token", &personal),
                        ("resource", REPORTS),
                    ],
                    &[("authorization", &basic(client_id, &secret))],
                )
                .await
            }
        };
        let gateway_secret = gateway["clientSecret"].as_str().unwrap().to_owned();
        assert_eq!(
            exchange(
                "strict",
                strict["clientSecret"].as_str().unwrap().to_owned()
            )
            .await
            .status,
            400
        );
        assert_eq!(
            exchange("gateway", gateway_secret.clone()).await.status,
            200
        );
        f.provider
            .revoke_grants(&admin(), &json!({ "tenantId": "a", "clientId": "web" }))
            .await
            .unwrap();
        let refused = exchange("gateway", gateway_secret).await;
        assert_eq!(refused.status, 400);
        assert_eq!(refused.json()["error"], json!("invalid_grant"));
    });
}

#[test]
fn does_not_answer_max_age_or_prompt_login_with_an_older_sign_in() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store, None).await;
        let origin = f.origin.clone();
        f.provider
            .register_client(
                &admin(),
                &json!({ "tenantId": "a", "clientId": "web", "name": "Web", "public": true, "redirectUris": [format!("{origin}/callback")], "scopes": ["openid"] }),
            )
            .await
            .unwrap();
        let mut browser = Browser::default();
        let verifier = random_b64(32);
        let challenge = sha256_b64url(&verifier);
        let callback = format!("{origin}/callback");
        let started = browser
            .get(&format!(
                "{origin}/oidc/auth?{}",
                form(&[
                    ("client_id", "web"),
                    ("response_type", "code"),
                    ("redirect_uri", &callback),
                    ("scope", "openid"),
                    ("state", "state"),
                    ("max_age", "0"),
                    ("code_challenge", &challenge),
                    ("code_challenge_method", "S256"),
                ])
            ))
            .await;
        let interaction = absolute(&started.location(), &origin);
        assert!(
            interaction.contains("/interactions/"),
            "{} {}",
            started.status,
            started.body
        );
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        let completed = browser
            .visit("POST", &interaction, &[("origin", &origin)], None)
            .await;
        assert_eq!(completed.status, 401, "{}", completed.body);
    });
}

#[test]
fn gates_dynamic_registration_however_the_route_is_spelled() {
    run(|| async {
        let store = seed().await;
        let f = fixture(&store, Some(RegistrationConfig::default())).await;
        let body = json!({
            "redirect_uris": ["https://x.example.test/cb"],
            "token_endpoint_auth_method": "none",
            "grant_types": ["authorization_code"],
        })
        .to_string();
        for path in [
            "/oidc/reg",
            "/oidc/REG",
            "/oidc/reg/",
            "/oidc/Reg",
            "/oidc/%72eg",
        ] {
            let response = fetch(
                "POST",
                &format!("{}{path}", f.origin),
                &[("content-type", "application/json")],
                Some(&body),
            )
            .await;
            assert!(
                [401, 404].contains(&response.status),
                "{path}: {}",
                response.status
            );
            if response.status == 401 {
                assert!(
                    response
                        .header("www-authenticate")
                        .unwrap_or_default()
                        .contains("invalid_token"),
                    "{path}"
                );
            }
        }
        assert!(find(&store, "oauthClients", Filter::new()).await.is_empty());
    });
}
