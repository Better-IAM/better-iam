//! Flows of the provider the TypeScript suites do not drive end to end (they come from `oidc-provider` there): the
//! device authorization grant, RP-initiated logout, refresh token introspection and revocation.

mod common;

use std::sync::Arc;

use better_iam_core::IamStore;
use common::provider::*;
use common::*;
use serde_json::json;

async fn seed() -> Arc<dyn IamStore> {
    let store = memory_store().await;
    seed_tenants(&store, &["root", "a"]).await;
    seed_identity(&store, "user-a", "a", "user").await;
    store
}

fn hidden(html: &str, name: &str) -> Option<String> {
    let pattern = regex::Regex::new(&format!(r#"name="{name}" value="([^"]*)""#)).unwrap();
    pattern
        .captures(html)
        .map(|captures| captures[1].to_owned())
}

#[test]
fn completes_the_device_authorization_grant() {
    run(|| async {
        let store = seed().await;
        let f = provider_fixture(&store, |_, _| {}).await;
        let origin = f.origin.clone();
        f.provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "tv", "name": "Living room TV", "public": true, "redirectUris": [],
                    "grantTypes": ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"],
                    "scopes": ["openid", "offline_access"],
                }),
            )
            .await
            .expect("register");
        let started = fetch(
            "POST",
            &format!("{origin}/oidc/device/auth"),
            &[("content-type", "application/x-www-form-urlencoded")],
            Some(&form(&[("client_id", "tv"), ("scope", "openid")])),
        )
        .await;
        assert_eq!(started.status, 200, "{}", started.body);
        let device = started.json();
        let user_code = device["user_code"].as_str().unwrap().to_owned();
        assert!(
            regex::Regex::new("^[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}$")
                .unwrap()
                .is_match(&user_code)
        );
        assert_eq!(
            device["verification_uri"],
            json!(format!("{origin}/oidc/device"))
        );
        assert_eq!(device["expires_in"], json!(600));
        let device_code = device["device_code"].as_str().unwrap().to_owned();
        let poll = || {
            let f = &f;
            let device_code = device_code.clone();
            async move {
                f.token(
                    &[
                        ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
                        ("client_id", "tv"),
                        ("device_code", &device_code),
                    ],
                    &[],
                )
                .await
            }
        };
        let pending = poll().await;
        assert_eq!(pending.status, 400);
        assert_eq!(pending.json()["error"], json!("authorization_pending"));
        let mut browser = Browser::default();
        let page = browser.get(&format!("{origin}/oidc/device")).await;
        assert_eq!(page.status, 200);
        let xsrf = hidden(&page.body, "xsrf").expect("xsrf");
        let confirm = browser
            .visit(
                "POST",
                &format!("{origin}/oidc/device"),
                &[("content-type", "application/x-www-form-urlencoded")],
                Some(&form(&[
                    ("xsrf", &xsrf),
                    ("user_code", &user_code.to_lowercase()),
                ])),
            )
            .await;
        assert_eq!(confirm.status, 200, "{}", confirm.body);
        assert!(confirm.body.contains("op.deviceConfirmForm"));
        let xsrf = hidden(&confirm.body, "xsrf").expect("xsrf");
        let submitted = browser
            .visit(
                "POST",
                &format!("{origin}/oidc/device"),
                &[("content-type", "application/x-www-form-urlencoded")],
                Some(&form(&[
                    ("xsrf", &xsrf),
                    ("user_code", &user_code),
                    ("confirm", "yes"),
                ])),
            )
            .await;
        assert_eq!(submitted.status, 303, "{}", submitted.body);
        let interaction = absolute(&submitted.location(), &origin);
        assert!(interaction.contains("/interactions/"));
        let details = browser.get(&interaction).await.json();
        assert_eq!(details["clientId"], json!("tv"));
        let resumed = browser
            .visit("POST", &interaction, &[("origin", &origin)], None)
            .await;
        assert_eq!(resumed.status, 303);
        let success = browser.get(&absolute(&resumed.location(), &origin)).await;
        assert_eq!(success.status, 200, "{}", success.body);
        let issued = poll().await;
        assert_eq!(issued.status, 200, "{}", issued.body);
        let tokens = issued.json();
        assert_eq!(
            claims_of(tokens["id_token"].as_str().unwrap())["sub"],
            json!("user-a")
        );
        let replay = poll().await;
        assert_eq!(replay.status, 400);
        assert_eq!(replay.json()["error"], json!("invalid_grant"));
    });
}

#[test]
fn ends_sessions_then_introspects_and_revokes_refresh_tokens() {
    run(|| async {
        let store = seed().await;
        let f = provider_fixture(&store, |_, _| {}).await;
        let origin = f.origin.clone();
        let registered = f
            .provider
            .register_client(
                &admin(),
                &json!({
                    "tenantId": "a", "clientId": "web", "name": "Web",
                    "redirectUris": [format!("{origin}/callback")], "postLogoutRedirectUris": [format!("{origin}/bye")],
                    "scopes": ["openid", "offline_access"],
                }),
            )
            .await
            .unwrap();
        let secret = registered["clientSecret"].as_str().unwrap().to_owned();
        let auth = basic("web", &secret);
        let mut browser = Browser::default();
        let (_, tokens) = f
            .authorize(
                &mut browser,
                "web",
                "openid offline_access",
                &[],
                &[("client_secret", &secret)],
            )
            .await;
        let refresh = tokens["refresh_token"].as_str().unwrap().to_owned();
        let form_type = ("content-type", "application/x-www-form-urlencoded");
        // RP-initiated logout: the logout page posts back to the confirmation endpoint; offline consents persist.
        let bye = format!("{origin}/bye");
        let page = browser
            .get(&format!(
                "{origin}/oidc/session/end?{}",
                form(&[
                    ("client_id", "web"),
                    ("post_logout_redirect_uri", &bye),
                    ("state", "s1")
                ])
            ))
            .await;
        assert_eq!(page.status, 200, "{}", page.body);
        assert!(page.body.contains("op.logoutForm"), "{}", page.body);
        let xsrf = hidden(&page.body, "xsrf").expect("xsrf");
        let confirmed = browser
            .visit(
                "POST",
                &format!("{origin}/oidc/session/end/confirm"),
                &[form_type],
                Some(&form(&[("xsrf", &xsrf), ("logout", "yes")])),
            )
            .await;
        assert_eq!(confirmed.status, 303, "{}", confirmed.body);
        assert_eq!(confirmed.location(), format!("{bye}?state=s1"));
        let unregistered = browser
            .get(&format!(
                "{origin}/oidc/session/end?{}",
                form(&[
                    ("client_id", "web"),
                    ("post_logout_redirect_uri", "https://evil.example.test/")
                ])
            ))
            .await;
        assert_eq!(unregistered.status, 400);
        let introspect = |token: String| {
            let (origin, auth) = (origin.clone(), auth.clone());
            async move {
                fetch(
                    "POST",
                    &format!("{origin}/oidc/token/introspection"),
                    &[
                        ("authorization", &auth),
                        ("content-type", "application/x-www-form-urlencoded"),
                    ],
                    Some(&form(&[("token", &token)])),
                )
                .await
            }
        };
        let introspected = introspect(refresh.clone()).await.json();
        assert_eq!(introspected["active"], json!(true), "{introspected}");
        assert_eq!(introspected["client_id"], json!("web"));
        assert_eq!(introspected["sub"], json!("user-a"));
        assert!(introspected.get("token_type").is_none());
        let revoked = fetch(
            "POST",
            &format!("{origin}/oidc/token/revocation"),
            &[("authorization", &auth), form_type],
            Some(&form(&[("token", &refresh)])),
        )
        .await;
        assert_eq!(revoked.status, 200);
        assert_eq!(
            introspect(refresh.clone()).await.json(),
            json!({ "active": false })
        );
        let jwt = introspect(tokens["id_token"].as_str().unwrap().to_owned()).await;
        assert_eq!(jwt.status, 400);
        assert_eq!(jwt.json()["error"], json!("unsupported_token_type"));
        let jwks = get_url(&format!("{origin}/oidc/jwks")).await;
        assert_eq!(jwks.status, 200);
        let keys = jwks.json();
        assert_eq!(keys["keys"][0]["kid"], json!("test-key"));
        assert!(keys["keys"][0].get("d").is_none());
    });
}
