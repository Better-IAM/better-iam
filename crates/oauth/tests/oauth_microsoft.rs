//! Port of tests/oauth-microsoft.test.ts: Microsoft Entra ID sign-in.

mod common;

use std::sync::{Arc, Mutex};

use better_iam_core::IamStore;
use better_iam_oauth::{
    ConnectionKind, FederatedIdentity, LoginHints, OAuthLogin, OAuthLoginConfig,
    OAuthLoginConnection, create_oauth_login,
};
use bytes::Bytes;
use common::*;
use serde_json::{Value, json};

const CONTOSO: &str = "72f988bf-86f1-41af-91ab-2d7cd011db47";
const FABRIKAM: &str = "0b6c1f2a-5d3e-4c4f-9a1b-2c3d4e5f6a7b";

/// What the fake Entra puts into the next ID token.
#[derive(Clone, Default)]
struct Issued {
    tid: String,
    iss: Option<String>,
    xms_edov: Option<bool>,
}

struct Entra {
    store: Arc<dyn IamStore>,
    origin: String,
    issued: Arc<Mutex<Issued>>,
    nonce: Arc<Mutex<String>>,
}

async fn entra() -> Entra {
    let store = memory_store().await;
    insert(
        &store,
        "tenants",
        json!({ "id": "a", "tenantId": "a", "name": "A", "type": "organization", "parentId": null, "status": "active", "createdAt": now_ms() }),
    )
    .await;
    let issued = Arc::new(Mutex::new(Issued {
        tid: CONTOSO.into(),
        ..Issued::default()
    }));
    let nonce = Arc::new(Mutex::new(String::new()));
    let origin_slot: Slot<String> = Arc::new(std::sync::OnceLock::new());
    let (private, public) = rsa_key(1, "entra");
    let (handler_issued, handler_nonce, handler_origin) =
        (issued.clone(), nonce.clone(), origin_slot.clone());
    let handler: Handler = Arc::new(move |request: HttpRequest| {
        let issued = handler_issued.lock().unwrap().clone();
        let nonce = handler_nonce.lock().unwrap().clone();
        let origin = handler_origin.get().cloned().unwrap_or_default();
        let private = private.clone();
        let public = public.clone();
        Box::pin(async move {
            let path = request.uri().path().to_owned();
            let directory = path.split('/').nth(1).unwrap_or_default().to_owned();
            if path.ends_with("/v2.0/.well-known/openid-configuration") {
                let issuer_directory = if ["organizations", "common"].contains(&directory.as_str())
                {
                    "{tenantid}".to_owned()
                } else {
                    directory.clone()
                };
                return json_response(
                    200,
                    &json!({
                        "issuer": format!("{origin}/{issuer_directory}/v2.0"),
                        "authorization_endpoint": format!("{origin}/{directory}/oauth2/v2.0/authorize"),
                        "token_endpoint": format!("{origin}/{directory}/oauth2/v2.0/token"),
                        "jwks_uri": format!("{origin}/{directory}/discovery/v2.0/keys"),
                        "response_types_supported": ["code"],
                        "id_token_signing_alg_values_supported": ["RS256"],
                    }),
                );
            }
            if path.ends_with("/discovery/v2.0/keys") {
                return json_response(200, &json!({ "keys": [public] }));
            }
            if path.ends_with("/oauth2/v2.0/token") {
                let now = (now_ms() / 1000.0).floor();
                let mut claims = json!({
                    "nonce": nonce, "tid": issued.tid, "email": "ada@contoso.test", "name": "Ada",
                    "iss": issued.iss.clone().unwrap_or_else(|| format!("{origin}/{}/v2.0", issued.tid)),
                    "aud": "entra-client", "sub": format!("pairwise-{}", issued.tid), "iat": now, "exp": now + 300.0,
                });
                if let Some(edov) = issued.xms_edov {
                    claims["xms_edov"] = json!(edov);
                }
                let id_token = sign(&private, "RS256", json!({ "kid": "entra" }), claims);
                return json_response(
                    200,
                    &json!({ "access_token": "at", "token_type": "Bearer", "id_token": id_token, "expires_in": 300 }),
                );
            }
            json_response(404, &json!({}))
        })
    });
    let origin = serve(handler).await;
    let _ = origin_slot.set(origin.clone());
    Entra {
        store,
        origin,
        issued,
        nonce,
    }
}

struct Login {
    service: Arc<OAuthLogin>,
    identities: Arc<Mutex<Vec<FederatedIdentity>>>,
}

impl Entra {
    fn login(
        &self,
        configure: impl FnOnce(&mut OAuthLoginConnection),
    ) -> better_iam_core::IamResult<Login> {
        let identities: Arc<Mutex<Vec<FederatedIdentity>>> = Arc::new(Mutex::new(Vec::new()));
        let recorded = identities.clone();
        let mut connection = OAuthLoginConnection {
            id: "entra".into(),
            tenant_id: "a".into(),
            kind: ConnectionKind::Microsoft,
            issuer: Some(self.origin.clone()),
            client_id: "entra-client".into(),
            client_secret: Some("entra-secret".into()),
            redirect_uri: format!("{}/callback", self.origin),
            allowed_microsoft_tenants: Some(vec![CONTOSO.to_uppercase()]),
            ..OAuthLoginConnection::default()
        };
        configure(&mut connection);
        let service = create_oauth_login(OAuthLoginConfig {
            store: self.store.clone(),
            allow_insecure_localhost: true,
            connections: vec![connection],
            complete_authentication: Arc::new(move |identity: FederatedIdentity| {
                let recorded = recorded.clone();
                Box::pin(async move {
                    recorded.lock().unwrap().push(identity);
                    Ok(json!({ "ok": true }))
                })
            }),
            authenticate: None,
            trusted_origins: None,
            base_path: None,
        })?;
        Ok(Login {
            service,
            identities,
        })
    }

    /// Starts a sign-in; returns the authorization URL and the callback result.
    async fn run(&self, login: &Login) -> (url::Url, better_iam_core::IamResult<Value>) {
        let begin = login
            .service
            .begin("entra", None, None)
            .await
            .expect("begin");
        let url = url::Url::parse(&begin.url).unwrap();
        *self.nonce.lock().unwrap() = query_param(&begin.url, "nonce").unwrap();
        let result = login
            .service
            .callback(
                "entra",
                &format!("{}/callback?code=c&state={}", self.origin, begin.state),
                &begin.binding,
            )
            .await;
        (url, result)
    }
}

#[test]
fn signs_in_members_of_allowed_directories_with_the_concrete_tenant_issuer() {
    run(|| async {
        let e = entra().await;
        let login = e.login(|_| {}).unwrap();
        let (url, result) = e.run(&login).await;
        assert_eq!(
            format!("{}{}", url.origin().ascii_serialization(), url.path()),
            format!("{}/organizations/oauth2/v2.0/authorize", e.origin)
        );
        assert_eq!(
            query_param(url.as_str(), "scope").as_deref(),
            Some("openid email profile")
        );
        assert_eq!(result.expect("signed in"), json!({ "ok": true }));
        let first = login.identities.lock().unwrap()[0].to_value();
        assert_eq!(first["tenantId"], json!("a"));
        assert_eq!(first["providerId"], json!("entra"));
        assert_eq!(
            first["issuer"],
            json!(format!("{}/{CONTOSO}/v2.0", e.origin))
        );
        assert_eq!(first["subject"], json!(format!("pairwise-{CONTOSO}")));
        assert_eq!(first["email"], json!("ada@contoso.test"));
        assert_eq!(first["emailVerified"], json!(false));
        *e.issued.lock().unwrap() = Issued {
            tid: CONTOSO.into(),
            xms_edov: Some(true),
            ..Issued::default()
        };
        e.run(&login).await.1.expect("signed in");
        assert_eq!(
            login.identities.lock().unwrap()[1].to_value()["emailVerified"],
            json!(true)
        );
    });
}

#[test]
fn refuses_directories_outside_the_allowlist_and_mismatched_issuers() {
    run(|| async {
        let e = entra().await;
        let login = e.login(|_| {}).unwrap();
        *e.issued.lock().unwrap() = Issued {
            tid: FABRIKAM.into(),
            ..Issued::default()
        };
        let refused = e.run(&login).await.1.unwrap_err();
        assert_eq!(
            (refused.code.as_str(), refused.status),
            ("OAUTH_TENANT", 403)
        );
        *e.issued.lock().unwrap() = Issued {
            tid: CONTOSO.into(),
            iss: Some(format!("{}/{FABRIKAM}/v2.0", e.origin)),
            ..Issued::default()
        };
        assert!(e.run(&login).await.1.is_err());
        assert!(login.identities.lock().unwrap().is_empty());
    });
}

#[test]
fn forwards_validated_sign_in_hints_to_the_provider() {
    run(|| async {
        let e = entra().await;
        let login = e.login(|_| {}).unwrap();
        let begun = login
            .service
            .begin(
                "entra",
                None,
                Some(&LoginHints {
                    login_hint: Some(json!("ada@contoso.test")),
                    domain_hint: Some(json!("contoso.test")),
                    prompt: Some(json!("select_account")),
                }),
            )
            .await
            .unwrap();
        assert_eq!(
            query_param(&begun.url, "login_hint").as_deref(),
            Some("ada@contoso.test")
        );
        assert_eq!(
            query_param(&begun.url, "domain_hint").as_deref(),
            Some("contoso.test")
        );
        assert_eq!(
            query_param(&begun.url, "prompt").as_deref(),
            Some("select_account")
        );
        let get = |path: &str| {
            http::Request::builder()
                .uri(format!("{}{path}", e.origin))
                .body(Bytes::new())
                .unwrap()
        };
        let redirect = login
            .service
            .handler(&get(
                "/oauth/login/entra?login_hint=bob%40contoso.test&prompt=login",
            ))
            .await
            .expect("handled");
        assert_eq!(redirect.status(), 302);
        let location = redirect
            .headers()
            .get("location")
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        assert_eq!(
            query_param(&location, "login_hint").as_deref(),
            Some("bob@contoso.test")
        );
        assert_eq!(query_param(&location, "prompt").as_deref(), Some("login"));
        let script = login
            .service
            .begin(
                "entra",
                None,
                Some(&LoginHints {
                    login_hint: Some(json!("<script>")),
                    ..LoginHints::default()
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(script.code, "INVALID_INPUT");
        let always = login
            .service
            .begin(
                "entra",
                None,
                Some(&LoginHints {
                    prompt: Some(json!("always")),
                    ..LoginHints::default()
                }),
            )
            .await
            .unwrap_err();
        assert_eq!(always.code, "INVALID_INPUT");
        let invalid = login
            .service
            .handler(&get("/oauth/login/entra?domain_hint=not%20a%20domain"))
            .await
            .expect("handled");
        assert_eq!(invalid.status(), 400);
    });
}

#[test]
fn supports_single_tenant_connections_and_validates_configuration() {
    run(|| async {
        let e = entra().await;
        let login = e
            .login(|connection| {
                connection.microsoft_tenant = Some(CONTOSO.into());
                connection.allowed_microsoft_tenants = None;
            })
            .unwrap();
        let (url, result) = e.run(&login).await;
        assert_eq!(url.path(), format!("/{CONTOSO}/oauth2/v2.0/authorize"));
        assert_eq!(result.expect("signed in"), json!({ "ok": true }));
        let identities: Vec<Value> = login
            .identities
            .lock()
            .unwrap()
            .iter()
            .map(FederatedIdentity::to_value)
            .collect();
        assert_eq!(identities.len(), 1);
        assert_eq!(
            identities[0]["issuer"],
            json!(format!("{}/{CONTOSO}/v2.0", e.origin))
        );
        *e.issued.lock().unwrap() = Issued {
            tid: FABRIKAM.into(),
            ..Issued::default()
        };
        assert!(e.run(&login).await.1.is_err());
        assert_eq!(login.identities.lock().unwrap().len(), 1);
        let multi = e
            .login(|connection| connection.allowed_microsoft_tenants = None)
            .err()
            .expect("refused");
        assert!(multi.message.contains("allowedMicrosoftTenants"));
        let evil = e
            .login(|connection| connection.microsoft_tenant = Some("../evil".into()))
            .err()
            .expect("refused");
        assert!(evil.message.contains("microsoftTenant"));
    });
}
