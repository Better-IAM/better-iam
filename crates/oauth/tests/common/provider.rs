//! The provider fixture of the TypeScript provider suites: `admin` may do anything; `member` authenticates as
//! user-a but holds no IAM permissions.

#![allow(dead_code)]

use std::sync::{Arc, Mutex, OnceLock};

use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, IamError, IamStore, Identity, Session,
};
use better_iam_oauth::{
    DevicePageInput, OAuthProvider, OAuthProviderConfig, create_oauth_provider,
};
use serde_json::{Map, Value, json};

use super::*;

pub static ENCRYPTION_KEY: std::sync::LazyLock<String> = std::sync::LazyLock::new(random_key_b64);

pub fn credential(token: &str) -> CredentialInput {
    CredentialInput {
        headers: None,
        token: Some(token.to_owned()),
    }
}

pub fn admin() -> CredentialInput {
    credential("admin")
}

pub fn member() -> CredentialInput {
    credential("member")
}

pub fn identity_of(record: Map<String, Value>) -> Identity {
    serde_json::from_value(Value::Object(record)).expect("identity")
}

pub fn user_session(id: &str, tenant: &str, identity: &str, lifetime: f64) -> Session {
    serde_json::from_value(json!({
        "id": id, "tenantId": tenant, "identityId": identity, "kind": "user", "tokenHash": "irrelevant",
        "createdAt": now_ms(), "authenticatedAt": now_ms(), "lastSeenAt": now_ms(), "expiresAt": now_ms() + lifetime, "mfa": true,
    }))
    .expect("session")
}

pub async fn seed_tenants(store: &Arc<dyn IamStore>, ids: &[&str]) {
    for id in ids {
        insert(
            store,
            "tenants",
            json!({
                "id": id, "tenantId": id, "name": id,
                "type": if *id == "root" { "root" } else { "organization" },
                "parentId": if *id == "root" { Value::Null } else { json!("root") },
                "status": "active", "createdAt": now_ms(),
            }),
        )
        .await;
    }
}

pub async fn seed_identity(store: &Arc<dyn IamStore>, id: &str, tenant: &str, kind: &str) {
    let mut record = json!({
        "id": id, "tenantId": tenant, "name": id, "kind": kind, "emailVerified": kind == "user",
        "status": "active", "rootAdmin": false, "owner": false, "createdAt": now_ms(),
    });
    if kind == "user" {
        record["email"] = json!(format!("{id}@example.test"));
    }
    insert(store, "identities", record).await;
}

pub struct ProviderFixture {
    pub store: Arc<dyn IamStore>,
    pub provider: OAuthProvider,
    pub origin: String,
    pub denied: Arc<Mutex<Vec<String>>>,
    pub public_key: Value,
    pub config: OAuthProviderConfig,
}

/// Starts the provider behind a local server: `/interactions/*` completes interactions with the `admin` credential
/// (POST) or answers their details (GET); everything else reaches the provider mount.
pub async fn provider_fixture(
    store: &Arc<dyn IamStore>,
    configure: impl FnOnce(&mut OAuthProviderConfig, &str),
) -> ProviderFixture {
    let slot: Slot<OAuthProvider> = Arc::new(OnceLock::new());
    let handler_slot = slot.clone();
    let handler: Handler = Arc::new(move |request: HttpRequest| {
        let slot = handler_slot.clone();
        Box::pin(async move {
            let provider = slot.get().expect("provider").clone();
            if request.uri().path().starts_with("/interactions/") {
                let result = if request.method() == http::Method::POST {
                    provider
                        .complete_interaction(&request, &admin(), true)
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
        identity: identity_of(get(store, "identities", "user-a").await.expect("user-a")),
        session: user_session("session-a", "a", "user-a", 100_000.0),
        device_proof: None,
    };
    insert(
        store,
        "sessions",
        serde_json::to_value(&principal.session).unwrap(),
    )
    .await;
    let (signing, public_key) = rsa_key(0, "test-key");
    let denied: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    let interaction_origin = origin.clone();
    let recorded = denied.clone();
    let mut config = OAuthProviderConfig {
        store: store.clone(),
        issuer: format!("{origin}/oidc"),
        jwks: json!({ "keys": [signing] }),
        cookie_keys: vec!["test-key-with-at-least-32-characters-long".into()],
        encryption_key: ENCRYPTION_KEY.clone(),
        authenticate: Arc::new(move |credential: CredentialInput| {
            let principal = principal.clone();
            Box::pin(async move {
                match credential.token.as_deref() {
                    Some("admin" | "member") => Ok(principal),
                    _ => Err(IamError::with_status(
                        "UNAUTHENTICATED",
                        "Unauthenticated",
                        401,
                    )),
                }
            })
        }),
        validate_session: None,
        live_grants: None,
        client_allowed: None,
        authorize: Arc::new(move |(credential, action, _)| {
            let recorded = recorded.clone();
            Box::pin(async move {
                if credential.token.as_deref() != Some("admin") {
                    recorded.lock().unwrap().push(action);
                    return Err(IamError::with_status("ACCESS_DENIED", "Forbidden", 403));
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
        trusted_origins: vec![origin.clone()],
        scopes: None,
        resource_servers: Default::default(),
        require_pushed_authorization_requests: false,
        dpop_nonce_secret: None,
        authorize_token_exchange: None,
        registration: None,
        trust_proxy: false,
        allow_insecure_localhost: true,
    };
    configure(&mut config, &origin);
    let provider = create_oauth_provider(config.clone()).expect("provider");
    let _ = slot.set(provider.clone());
    ProviderFixture {
        store: store.clone(),
        provider,
        origin,
        denied,
        public_key,
        config,
    }
}

impl ProviderFixture {
    pub fn provider_config(&self) -> OAuthProviderConfig {
        self.config.clone()
    }

    pub async fn token(&self, body: &[(&str, &str)], headers: &[(&str, &str)]) -> Resp {
        let mut all = vec![("content-type", "application/x-www-form-urlencoded")];
        all.extend_from_slice(headers);
        fetch(
            "POST",
            &format!("{}/oidc/token", self.origin),
            &all,
            Some(&form(body)),
        )
        .await
    }

    pub fn denied(&self) -> Vec<String> {
        self.denied.lock().unwrap().clone()
    }

    /// The authorization code flow with consent, then the code exchange.
    pub async fn authorize(
        &self,
        browser: &mut Browser,
        client_id: &str,
        scope: &str,
        auth_extra: &[(&str, &str)],
        token_extra: &[(&str, &str)],
    ) -> (Value, Value) {
        let origin = self.origin.clone();
        let verifier = random_b64(32);
        let challenge = sha256_b64url(&verifier);
        let callback = format!("{origin}/callback");
        let mut params = vec![
            ("client_id", client_id),
            ("response_type", "code"),
            ("redirect_uri", callback.as_str()),
            ("scope", scope),
            ("prompt", "consent"),
            ("state", "state"),
            ("code_challenge", challenge.as_str()),
            ("code_challenge_method", "S256"),
        ];
        params.extend_from_slice(auth_extra);
        let mut result = browser
            .get(&format!("{origin}/oidc/auth?{}", form(&params)))
            .await;
        let mut redirect = result.location();
        assert!(
            redirect.contains("/interactions/"),
            "{} {}",
            result.status,
            result.body
        );
        let details = browser.get(&absolute(&redirect, &origin)).await.json();
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
            .unwrap_or_else(|| panic!("no code: {} {} {}", result.status, redirect, result.body));
        let mut body = vec![
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("code", code.as_str()),
            ("code_verifier", verifier.as_str()),
            ("redirect_uri", callback.as_str()),
        ];
        body.extend_from_slice(token_extra);
        let response = self.token(&body, &[]).await;
        assert_eq!(response.status, 200, "{}", response.body);
        (details, response.json())
    }
}

/// DPoP proofs (RFC 9449) signed with an ephemeral ES256 key.
pub struct DpopKey {
    private: Value,
    public: Value,
}

impl DpopKey {
    pub fn new() -> Self {
        let (private, public) = ec_key();
        Self { private, public }
    }

    pub fn proof(&self, htm: &str, htu: &str, access_token: Option<&str>) -> String {
        let mut payload = json!({
            "htm": htm, "htu": htu, "jti": uuid::Uuid::new_v4().to_string(),
            "iat": (now_ms() / 1000.0).floor(),
        });
        if let Some(token) = access_token {
            payload["ath"] = json!(sha256_b64url(token));
        }
        sign(
            &self.private,
            "ES256",
            json!({ "typ": "dpop+jwt", "jwk": self.public }),
            payload,
        )
    }
}
