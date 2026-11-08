//! OAuth/OIDC relying-party flows (client.ts, on the `oauth4webapi` checks): Google, GitHub, Microsoft Entra ID,
//! generic OIDC and configured OAuth2 providers. Login state is single-use, browser-bound and tenant-bound.

use std::collections::HashMap;
use std::sync::Arc;

use better_iam_auth::safe_fetch::{
    FetchBody, FetchRequest, FetchResponse, GuardedFetch, GuardedFetchOptions, RedirectMode,
    create_guarded_fetch,
};
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, IamError, IamResult, IamStore, IamStoreExt, js,
    tenant_tree_active,
};
use bytes::Bytes;
use futures::future::BoxFuture;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::adapter::{hash, truthy};
use crate::jose::{self, KeySet};
use crate::resource_server::{HttpRequest, HttpResponse, request_url_string, response};

/// `FederatedIdentity`: what a sign-in proved, handed to the host's `completeAuthentication`.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct FederatedIdentity {
    pub tenant_id: String,
    pub provider_id: String,
    pub issuer: String,
    pub subject: String,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
    pub linking_session_id: Option<String>,
    pub linking_identity_id: Option<String>,
    /// Identity attributes mapped from the provider's verified claims or profile; validated by the host.
    pub attributes: Option<Map<String, Value>>,
    /// The connection's `trustScimProvisioned` setting, applied by the host.
    pub trust_scim_provisioned: Option<Value>,
}

impl FederatedIdentity {
    /// The JSON object TypeScript builds (undefined members left out).
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("tenantId".into(), json!(self.tenant_id));
        out.insert("providerId".into(), json!(self.provider_id));
        out.insert("issuer".into(), json!(self.issuer));
        out.insert("subject".into(), json!(self.subject));
        if let Some(email) = &self.email {
            out.insert("email".into(), json!(email));
        }
        if let Some(verified) = self.email_verified {
            out.insert("emailVerified".into(), json!(verified));
        }
        if let Some(name) = &self.name {
            out.insert("name".into(), json!(name));
        }
        if let Some(attributes) = &self.attributes {
            out.insert("attributes".into(), Value::Object(attributes.clone()));
        }
        if let Some(trust) = &self.trust_scim_provisioned {
            out.insert("trustScimProvisioned".into(), trust.clone());
        }
        if let Some(identity) = &self.linking_identity_id {
            out.insert("linkingIdentityId".into(), json!(identity));
        }
        if let Some(session) = &self.linking_session_id {
            out.insert("linkingSessionId".into(), json!(session));
        }
        Value::Object(out)
    }
}

/// What a generic OAuth2 `mapProfile` returns.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MappedProfile {
    pub subject: Value,
    pub email: Option<String>,
    pub email_verified: Option<bool>,
    pub name: Option<String>,
}

/// `mapProfile(profile)`.
pub type MapProfile = Arc<dyn Fn(&Map<String, Value>) -> MappedProfile + Send + Sync>;
/// `mapAttributes(claims)`.
pub type MapAttributes =
    Arc<dyn Fn(&Map<String, Value>) -> Option<Map<String, Value>> + Send + Sync>;
/// `completeAuthentication(identity)`.
pub type CompleteAuthentication =
    Arc<dyn Fn(FederatedIdentity) -> BoxFuture<'static, IamResult<Value>> + Send + Sync>;
/// `authenticate(credential)`.
pub type Authenticate = Arc<
    dyn Fn(CredentialInput) -> BoxFuture<'static, IamResult<AuthenticatedPrincipal>> + Send + Sync,
>;

/// `OAuthLoginConnection.kind`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionKind {
    Oidc,
    Oauth2,
    Google,
    Github,
    Microsoft,
}

/// `OAuthLoginConnection`.
#[derive(Clone)]
pub struct OAuthLoginConnection {
    pub id: String,
    pub tenant_id: String,
    pub kind: ConnectionKind,
    pub client_id: String,
    pub client_secret: Option<String>,
    /// Fixed, registered callback URL. Never supplied by the browser.
    pub redirect_uri: String,
    pub issuer: Option<String>,
    pub scopes: Option<Vec<String>>,
    pub authorization_endpoint: Option<String>,
    pub token_endpoint: Option<String>,
    pub user_info_endpoint: Option<String>,
    pub microsoft_tenant: Option<String>,
    pub allowed_microsoft_tenants: Option<Vec<String>>,
    /// Email domains whose verified addresses may enroll (any JSON value; validated).
    pub allowed_email_domains: Option<Value>,
    /// `trustScimProvisioned`: a boolean or a list of SCIM connection IDs (any JSON value; validated).
    pub trust_scim_provisioned: Option<Value>,
    pub map_profile: Option<MapProfile>,
    pub map_attributes: Option<MapAttributes>,
}

impl Default for OAuthLoginConnection {
    fn default() -> Self {
        Self {
            id: String::new(),
            tenant_id: String::new(),
            kind: ConnectionKind::Oidc,
            client_id: String::new(),
            client_secret: None,
            redirect_uri: String::new(),
            issuer: None,
            scopes: None,
            authorization_endpoint: None,
            token_endpoint: None,
            user_info_endpoint: None,
            microsoft_tenant: None,
            allowed_microsoft_tenants: None,
            allowed_email_domains: None,
            trust_scim_provisioned: None,
            map_profile: None,
            map_attributes: None,
        }
    }
}

/// `OAuthLoginConfig`.
#[derive(Clone)]
pub struct OAuthLoginConfig {
    pub store: Arc<dyn IamStore>,
    pub connections: Vec<OAuthLoginConnection>,
    pub complete_authentication: CompleteAuthentication,
    pub authenticate: Option<Authenticate>,
    pub trusted_origins: Option<Vec<String>>,
    pub base_path: Option<String>,
    /// Test-only/local development; production requires HTTPS everywhere.
    pub allow_insecure_localhost: bool,
}

/// `LoginHints`.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LoginHints {
    pub login_hint: Option<Value>,
    pub domain_hint: Option<Value>,
    pub prompt: Option<Value>,
}

/// What `begin` returns.
#[derive(Debug, Clone, PartialEq)]
pub struct BeginResult {
    pub url: String,
    pub binding: String,
    pub state: String,
    pub expires_at: f64,
}

const MULTI_TENANT_DIRECTORIES: [&str; 3] = ["common", "organizations", "consumers"];
const MICROSOFT_AUTHORITY: &str = "https://login.microsoftonline.com";
const USER_AGENT: &str = "oauth4webapi/v3.8.8";

fn configuration(message: &str) -> IamError {
    IamError::new("configuration", message)
}

/// The failures `oauth4webapi` throws (not `IamError`s in TypeScript): answered as `OAUTH_FAILED` 401.
fn protocol_failure(message: impl Into<String>) -> IamError {
    IamError::with_status("OAUTH_FAILED", message, 401)
}

fn hostname(url: &url::Url) -> String {
    match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(host) => host.to_string(),
        None => String::new(),
    }
}

fn origin(url: &url::Url) -> String {
    url.origin().ascii_serialization()
}

/// `url(value, allowLocalhost)`: HTTPS (or explicitly enabled localhost HTTP), no credentials or fragment.
fn checked_url(value: &str, allow_localhost: bool) -> IamResult<url::Url> {
    let refused =
        || configuration("OAuth endpoints require HTTPS (or explicitly enabled localhost HTTP).");
    let parsed = url::Url::parse(value)
        .map_err(|_| IamError::with_status("OAUTH_FAILED", "Invalid URL", 401))?;
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed
            .fragment()
            .is_some_and(|fragment| !fragment.is_empty())
        || (parsed.scheme() != "https"
            && !(allow_localhost
                && parsed.scheme() == "http"
                && ["localhost", "127.0.0.1", "[::1]"].contains(&hostname(&parsed).as_str())))
    {
        return Err(refused());
    }
    Ok(parsed)
}

/// `new URL(value)` failures in TypeScript are `TypeError`s: configuration-time ones surface as is.
fn parse_url(value: &str) -> IamResult<url::Url> {
    url::Url::parse(value).map_err(|_| IamError::with_status("OAUTH_FAILED", "Invalid URL", 401))
}

async fn active_tenant(store: &dyn IamStore, id: &str) -> IamResult<()> {
    if !tenant_tree_active(store, id).await? {
        return Err(IamError::with_status(
            "TENANT_INACTIVE",
            "Tenant is unavailable.",
            403,
        ));
    }
    Ok(())
}

/// Authorization server metadata (`oauth.AuthorizationServer`).
type Metadata = Map<String, Value>;

fn meta_str<'a>(metadata: &'a Metadata, key: &str) -> Option<&'a str> {
    metadata.get(key).and_then(Value::as_str)
}

/// `createOAuthLogin(config)`.
pub struct OAuthLogin {
    config: OAuthLoginConfig,
    connections: Vec<OAuthLoginConnection>,
    pub base_path: String,
    fetch: GuardedFetch,
    jwks_cache: tokio::sync::Mutex<HashMap<String, (KeySet, f64)>>,
}

impl std::fmt::Debug for OAuthLogin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("OAuthLogin")
    }
}

/// `createOAuthLogin(config)`.
pub fn create_oauth_login(config: OAuthLoginConfig) -> IamResult<Arc<OAuthLogin>> {
    let raw_base = config
        .base_path
        .clone()
        .unwrap_or_else(|| "/oauth/login".to_owned());
    let base_path = raw_base.strip_suffix('/').unwrap_or(&raw_base).to_owned();
    let allow = config.allow_insecure_localhost;
    let domain_pattern =
        Regex::new(r"(?i)^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.[a-z]{2,}$").expect("valid regex");
    let directory_pattern = Regex::new(r"^[A-Za-z0-9.-]{1,128}$").expect("valid regex");
    let mut connections: Vec<OAuthLoginConnection> = Vec::new();
    for connection in &config.connections {
        if connection.id.is_empty()
            || connections
                .iter()
                .any(|existing| existing.id == connection.id)
            || connection.tenant_id.is_empty()
            || connection.client_id.is_empty()
        {
            return Err(configuration(
                "OAuth connection IDs must be unique and configuration complete.",
            ));
        }
        checked_url(&connection.redirect_uri, allow)?;
        if matches!(
            connection.kind,
            ConnectionKind::Oidc | ConnectionKind::Oauth2
        ) && connection.issuer.is_none()
        {
            return Err(configuration("The provider issuer is required."));
        }
        if let Some(domains) = &connection.allowed_email_domains {
            let valid = match domains {
                Value::Array(domains) => {
                    !domains.is_empty()
                        && domains.iter().all(|domain| {
                            domain
                                .as_str()
                                .is_some_and(|domain| domain_pattern.is_match(domain))
                        })
                }
                _ => false,
            };
            if !valid {
                return Err(configuration(
                    "allowedEmailDomains must list one or more exact domain names.",
                ));
            }
        }
        if let Some(issuer) = &connection.issuer {
            checked_url(issuer, allow)?;
        }
        if let Some(trust) = &connection.trust_scim_provisioned {
            let valid = match trust {
                Value::Bool(_) => true,
                Value::Array(ids) => {
                    ids.len() <= 20
                        && ids.iter().all(|id| {
                            id.as_str()
                                .is_some_and(|id| !id.is_empty() && js::utf16_len(id) <= 128)
                        })
                }
                _ => false,
            };
            if !valid {
                return Err(configuration(
                    "trustScimProvisioned is a boolean or a list of SCIM connection IDs.",
                ));
            }
        }
        if connection.kind == ConnectionKind::Microsoft {
            let directory = connection
                .microsoft_tenant
                .clone()
                .unwrap_or_else(|| "organizations".into());
            if !directory_pattern.is_match(&directory) {
                return Err(configuration(
                    "microsoftTenant must be a tenant ID, domain, or alias.",
                ));
            }
            if MULTI_TENANT_DIRECTORIES.contains(&directory.to_lowercase().as_str())
                && connection
                    .allowed_microsoft_tenants
                    .as_ref()
                    .is_none_or(Vec::is_empty)
            {
                return Err(configuration(
                    "Multi-tenant Microsoft connections need allowedMicrosoftTenants.",
                ));
            }
        }
        if connection.kind == ConnectionKind::Github
            && connection
                .client_secret
                .as_deref()
                .is_none_or(str::is_empty)
        {
            return Err(configuration("GitHub client secret is required."));
        }
        if connections
            .iter()
            .any(|value| value.redirect_uri == connection.redirect_uri)
        {
            return Err(configuration(
                "OAuth callback URLs must be unique per connection.",
            ));
        }
        if connection.kind == ConnectionKind::Oauth2 {
            let complete = connection
                .authorization_endpoint
                .as_deref()
                .is_some_and(|v| !v.is_empty())
                && connection
                    .token_endpoint
                    .as_deref()
                    .is_some_and(|v| !v.is_empty())
                && connection
                    .user_info_endpoint
                    .as_deref()
                    .is_some_and(|v| !v.is_empty())
                && connection.map_profile.is_some();
            if !complete {
                return Err(configuration(
                    "Generic OAuth2 requires authorization/token/profile endpoints and a trusted profile mapper.",
                ));
            }
            for endpoint in [
                &connection.authorization_endpoint,
                &connection.token_endpoint,
                &connection.user_info_endpoint,
            ]
            .into_iter()
            .flatten()
            {
                checked_url(endpoint, allow)?;
            }
        }
        connections.push(connection.clone());
    }
    let fetch = create_guarded_fetch(GuardedFetchOptions {
        allow_private_networks: true,
        allow_insecure_localhost: allow,
        any_port: true,
        max_bytes: None,
    });
    Ok(Arc::new(OAuthLogin {
        config,
        connections,
        base_path,
        fetch,
        jwks_cache: tokio::sync::Mutex::new(HashMap::new()),
    }))
}

fn get_param(url: &url::Url, name: &str) -> IamResult<Option<String>> {
    let values: Vec<String> = url
        .query_pairs()
        .filter(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .collect();
    if values.len() > 1 {
        return Err(protocol_failure(format!(
            "\"parameters\" properties must contain only one \"{name}\""
        )));
    }
    Ok(values.into_iter().next())
}

async fn read_json(response: &mut FetchResponse) -> IamResult<Value> {
    response
        .body
        .json()
        .await
        .map_err(|_| protocol_failure("failed to parse \"response\" body as JSON"))
}

impl OAuthLogin {
    fn connection(&self, id: &str) -> IamResult<&OAuthLoginConnection> {
        self.connections
            .iter()
            .find(|connection| connection.id == id)
            .ok_or_else(|| IamError::with_status("NOT_FOUND", "OAuth connection not found.", 404))
    }

    fn allow(&self) -> bool {
        self.config.allow_insecure_localhost
    }

    async fn send(&self, request: FetchRequest) -> IamResult<FetchResponse> {
        self.fetch
            .fetch(request)
            .await
            .map_err(|error| protocol_failure(error.to_string()))
    }

    /// Entra ID discovery: every endpoint must live on the configured authority.
    async fn microsoft_metadata(&self, item: &OAuthLoginConnection) -> IamResult<Metadata> {
        let authority = checked_url(
            item.issuer.as_deref().unwrap_or(MICROSOFT_AUTHORITY),
            self.allow(),
        )?;
        let path = authority.path();
        let root = format!(
            "{}{}",
            origin(&authority),
            path.strip_suffix('/').unwrap_or(path)
        );
        let directory = url::form_urlencoded::byte_serialize(
            item.microsoft_tenant
                .as_deref()
                .unwrap_or("organizations")
                .as_bytes(),
        )
        .collect::<String>()
        .replace('+', "%20");
        let discovery_failed =
            || IamError::with_status("OAUTH_DISCOVERY", "Microsoft discovery failed.", 502);
        let request = FetchRequest::get(format!(
            "{root}/{directory}/v2.0/.well-known/openid-configuration"
        ))
        .header("accept", "application/json")
        .redirect(RedirectMode::Error);
        let document = tokio::time::timeout(std::time::Duration::from_millis(10_000), async {
            let mut response = self
                .fetch
                .fetch(request)
                .await
                .map_err(|_| discovery_failed())?;
            if !response.ok() {
                return Err(discovery_failed());
            }
            response.body.json().await.map_err(|_| discovery_failed())
        })
        .await
        .map_err(|_| discovery_failed())??;
        let Value::Object(document) = document else {
            return Err(discovery_failed());
        };
        let issuer = meta_str(&document, "issuer").unwrap_or_default();
        if !issuer.starts_with(&format!("{root}/")) || !issuer.ends_with("/v2.0") {
            return Err(IamError::with_status(
                "OAUTH_DISCOVERY",
                "Unexpected Microsoft issuer.",
                502,
            ));
        }
        for key in ["authorization_endpoint", "token_endpoint", "jwks_uri"] {
            let endpoint = match document.get(key) {
                Some(value) if truthy(Some(value)) => value,
                _ => {
                    return Err(IamError::with_status(
                        "OAUTH_DISCOVERY",
                        "Microsoft metadata is incomplete.",
                        502,
                    ));
                }
            };
            let text = match endpoint {
                Value::String(text) => text.clone(),
                other => js::stringify(other),
            };
            if origin(&checked_url(&text, self.allow())?) != origin(&authority) {
                return Err(IamError::with_status(
                    "OAUTH_DISCOVERY",
                    "Microsoft endpoints must use the authority.",
                    502,
                ));
            }
        }
        Ok(document)
    }

    /// The concrete issuer of the directory that signed in, after checking it against `allowedMicrosoftTenants`.
    fn microsoft_issuer(
        &self,
        item: &OAuthLoginConnection,
        discovered: &Metadata,
        token_body: &Value,
    ) -> IamResult<Metadata> {
        let tid = token_body
            .get("id_token")
            .map(|token| match token {
                Value::String(text) => text.clone(),
                other => js::stringify(other),
            })
            .and_then(|token| token.split('.').nth(1).map(str::to_owned))
            .and_then(|payload| jose::b64url_decode(&payload))
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|claims| claims.get("tid").cloned());
        let pattern =
            Regex::new(r"(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
                .expect("valid regex");
        let Some(tid) = tid
            .and_then(|tid| tid.as_str().map(str::to_owned))
            .filter(|tid| pattern.is_match(tid))
        else {
            return Err(IamError::with_status(
                "OAUTH_PROFILE",
                "The Microsoft ID token names no directory.",
                401,
            ));
        };
        if let Some(allowed) = item
            .allowed_microsoft_tenants
            .as_ref()
            .filter(|allowed| !allowed.is_empty())
            && !allowed
                .iter()
                .any(|value| value.to_lowercase() == tid.to_lowercase())
        {
            return Err(IamError::with_status(
                "OAUTH_TENANT",
                "This Microsoft directory may not sign in here.",
                403,
            ));
        }
        let mut out = discovered.clone();
        let issuer = meta_str(discovered, "issuer").unwrap_or_default();
        if issuer.contains("{tenantid}") {
            out.insert(
                "issuer".into(),
                json!(issuer.replacen("{tenantid}", &tid, 1)),
            );
        }
        Ok(out)
    }

    async fn metadata(&self, item: &OAuthLoginConnection) -> IamResult<Metadata> {
        match item.kind {
            ConnectionKind::Github => {
                let value = json!({
                    "issuer": "https://github.com",
                    "authorization_endpoint": "https://github.com/login/oauth/authorize",
                    "token_endpoint": "https://github.com/login/oauth/access_token",
                });
                Ok(value.as_object().cloned().unwrap_or_default())
            }
            ConnectionKind::Oauth2 => {
                let value = json!({
                    "issuer": item.issuer,
                    "authorization_endpoint": item.authorization_endpoint,
                    "token_endpoint": item.token_endpoint,
                    "userinfo_endpoint": item.user_info_endpoint,
                });
                Ok(value.as_object().cloned().unwrap_or_default())
            }
            ConnectionKind::Microsoft => self.microsoft_metadata(item).await,
            ConnectionKind::Google | ConnectionKind::Oidc => {
                let issuer = checked_url(
                    if item.kind == ConnectionKind::Google {
                        "https://accounts.google.com"
                    } else {
                        item.issuer.as_deref().unwrap_or_default()
                    },
                    self.allow(),
                )?;
                let mut url = issuer.clone();
                let path = format!("{}/.well-known/openid-configuration", url.path());
                url.set_path(&path.replacen("//", "/", 1));
                let mut response = self
                    .send(
                        FetchRequest::get(url.to_string())
                            .header("user-agent", USER_AGENT)
                            .header("accept", "application/json")
                            .redirect(RedirectMode::Manual),
                    )
                    .await?;
                if response.status != 200 {
                    return Err(protocol_failure(
                        "\"response\" is not a conform Authorization Server Metadata response (unexpected HTTP status code)",
                    ));
                }
                let Value::Object(result) = read_json(&mut response).await? else {
                    return Err(protocol_failure(
                        "\"response\" body must be a top level object",
                    ));
                };
                let issuer_value = meta_str(&result, "issuer")
                    .filter(|value| !value.is_empty())
                    .ok_or_else(|| {
                        protocol_failure("\"response\" body \"issuer\" property must be a string")
                    })?;
                if parse_url(issuer_value)?.to_string() != issuer.to_string() {
                    return Err(protocol_failure(
                        "\"response\" body \"issuer\" property does not match the expected value",
                    ));
                }
                for key in [
                    "authorization_endpoint",
                    "token_endpoint",
                    "jwks_uri",
                    "userinfo_endpoint",
                ] {
                    if let Some(endpoint) = result.get(key).filter(|value| truthy(Some(value))) {
                        let text = match endpoint {
                            Value::String(text) => text.clone(),
                            other => js::stringify(other),
                        };
                        checked_url(&text, self.allow())?;
                    }
                }
                Ok(result)
            }
        }
    }

    /// Validated sign-in hints: never trusted for identity, only forwarded to the provider's login screen.
    fn hints(
        &self,
        input: &LoginHints,
    ) -> IamResult<(Option<String>, Option<String>, Option<String>)> {
        let invalid = |message: &str| IamError::with_status("INVALID_INPUT", message, 400);
        let mut login = None;
        let mut domain = None;
        let mut prompt = None;
        if let Some(hint) = &input.login_hint {
            let pattern = Regex::new(r"[\s<>]").expect("valid regex");
            match hint {
                Value::String(text)
                    if !text.is_empty()
                        && js::utf16_len(text) <= 320
                        && !pattern.is_match(text) =>
                {
                    login = Some(text.clone());
                }
                _ => {
                    return Err(invalid(
                        "login_hint must be a short identifier such as an email address.",
                    ));
                }
            }
        }
        if let Some(hint) = &input.domain_hint {
            let pattern =
                Regex::new(r"(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$").expect("valid regex");
            match hint {
                Value::String(text) if pattern.is_match(text) => domain = Some(text.clone()),
                _ => return Err(invalid("domain_hint must be a domain name.")),
            }
        }
        if let Some(value) = &input.prompt {
            match value.as_str() {
                Some(text @ ("login" | "select_account" | "consent" | "none")) => {
                    prompt = Some(text.to_owned())
                }
                _ => {
                    return Err(invalid(
                        "prompt must be login, select_account, consent, or none.",
                    ));
                }
            }
        }
        Ok((login, domain, prompt))
    }

    /// `begin(connectionId, linkingCredential?, loginHints?)`.
    pub async fn begin(
        &self,
        connection_id: &str,
        linking_credential: Option<&CredentialInput>,
        login_hints: Option<&LoginHints>,
    ) -> IamResult<BeginResult> {
        let (login_hint, domain_hint, prompt) =
            self.hints(login_hints.unwrap_or(&LoginHints::default()))?;
        let item = self.connection(connection_id)?;
        active_tenant(self.config.store.as_ref(), &item.tenant_id).await?;
        let mut linking_session_id = None;
        let mut linking_identity_id = None;
        if let Some(credential) = linking_credential {
            let Some(authenticate) = &self.config.authenticate else {
                return Err(configuration("Linking requires an authenticate callback."));
            };
            let principal = authenticate(credential.clone()).await?;
            let age = js::now_ms() - principal.session.authenticated_at;
            if principal.identity.tenant_id != item.tenant_id
                || principal.identity.root_admin
                || principal.session.kind != better_iam_core::SessionKind::User
                || age < 0.0
                || age > 300_000.0
            {
                return Err(IamError::with_status(
                    "RECENT_AUTH_REQUIRED",
                    "Linking requires recent authentication to a non-root identity in this tenant.",
                    403,
                ));
            }
            linking_session_id = Some(principal.session.id.clone());
            linking_identity_id = Some(principal.identity.id.clone());
        }
        let metadata = self.metadata(item).await?;
        let Some(authorization_endpoint) =
            meta_str(&metadata, "authorization_endpoint").filter(|v| !v.is_empty())
        else {
            return Err(configuration("Authorization endpoint is missing."));
        };
        let state = jose::b64url(&rand::random::<[u8; 32]>());
        let code_verifier = jose::b64url(&rand::random::<[u8; 32]>());
        let nonce = jose::b64url(&rand::random::<[u8; 32]>());
        let binding = jose::b64url(&rand::random::<[u8; 32]>());
        let mut authorization_url = parse_url(authorization_endpoint)?;
        let mut params: Vec<(String, String)> = authorization_url
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        let mut set = |name: &str, value: &str| {
            if let Some(index) = params.iter().position(|(key, _)| key == name) {
                params[index].1 = value.to_owned();
                let mut seen = false;
                params.retain(|(key, _)| {
                    if key != name {
                        return true;
                    }
                    let keep = !seen;
                    seen = true;
                    keep
                });
            } else {
                params.push((name.to_owned(), value.to_owned()));
            }
        };
        set("client_id", &item.client_id);
        set("redirect_uri", &item.redirect_uri);
        set("response_type", "code");
        let scopes = item.scopes.clone().unwrap_or_else(|| match item.kind {
            ConnectionKind::Github => vec!["read:user".into(), "user:email".into()],
            ConnectionKind::Oauth2 => Vec::new(),
            _ => vec!["openid".into(), "email".into(), "profile".into()],
        });
        if !scopes.is_empty() {
            set("scope", &scopes.join(" "));
        }
        if let Some(hint) = &login_hint {
            set(
                if item.kind == ConnectionKind::Github {
                    "login"
                } else {
                    "login_hint"
                },
                hint,
            );
        }
        if let Some(hint) = &domain_hint {
            if item.kind == ConnectionKind::Microsoft {
                set("domain_hint", hint);
            }
            if item.kind == ConnectionKind::Google {
                set("hd", hint);
            }
        }
        if let Some(prompt) = &prompt
            && item.kind != ConnectionKind::Github
        {
            set("prompt", prompt);
        }
        set("state", &state);
        set("code_challenge", &jose::sha256_b64url(&code_verifier));
        set("code_challenge_method", "S256");
        if matches!(
            item.kind,
            ConnectionKind::Oidc | ConnectionKind::Google | ConnectionKind::Microsoft
        ) {
            set("nonce", &nonce);
        }
        authorization_url
            .query_pairs_mut()
            .clear()
            .extend_pairs(params.iter());
        let tenant_id = item.tenant_id.clone();
        let record = {
            let mut record = Map::new();
            record.insert("id".into(), json!(hash(&state)));
            record.insert("tenantId".into(), json!(tenant_id));
            record.insert("connectionId".into(), json!(connection_id));
            record.insert("state".into(), json!(state));
            record.insert("codeVerifier".into(), json!(code_verifier));
            record.insert("nonce".into(), json!(nonce));
            record.insert("bindingHash".into(), json!(hash(&binding)));
            record.insert(
                "expiresAt".into(),
                js::number(js::now_ms() + 600_000.0).unwrap_or(Value::Null),
            );
            if let Some(identity) = &linking_identity_id {
                record.insert("linkingIdentityId".into(), json!(identity));
            }
            if let Some(session) = &linking_session_id {
                record.insert("linkingSessionId".into(), json!(session));
            }
            record
        };
        self.config
            .store
            .transaction(move |tx| async move {
                active_tenant(tx.as_ref(), &tenant_id).await?;
                tx.insert("oauthLoginStates", &record).await?;
                Ok(())
            })
            .await?;
        Ok(BeginResult {
            url: authorization_url.to_string(),
            binding,
            state,
            expires_at: js::now_ms() + 600_000.0,
        })
    }

    async fn issuer_keys(
        &self,
        jwks_uri: &str,
        kid_known: impl Fn(&KeySet) -> bool,
    ) -> IamResult<KeySet> {
        let mut cache = self.jwks_cache.lock().await;
        if let Some((keys, fetched)) = cache.get(jwks_uri)
            && js::now_ms() - fetched < 600_000.0
            && kid_known(keys)
        {
            return Ok(keys.clone());
        }
        let mut response = self
            .send(
                FetchRequest::get(jwks_uri)
                    .header("user-agent", USER_AGENT)
                    .header("accept", "application/json, application/jwk-set+json")
                    .redirect(RedirectMode::Manual),
            )
            .await?;
        if response.status != 200 {
            return Err(protocol_failure(
                "\"response\" is not a conform JSON Web Key Set response (unexpected HTTP status code)",
            ));
        }
        let body = read_json(&mut response).await?;
        let keys = KeySet::from_value(&body).map_err(|_| {
            protocol_failure("\"response\" body \"keys\" property must be an array")
        })?;
        cache.insert(jwks_uri.to_owned(), (keys.clone(), js::now_ms()));
        Ok(keys)
    }

    /// The ID token checks of `processAuthorizationCodeResponse` (OpenID) and the signature check of
    /// `validateApplicationLevelSignature`; returns the validated claims.
    async fn validate_id_token(
        &self,
        metadata: &Metadata,
        client_id: &str,
        id_token: &str,
        expected_nonce: &str,
    ) -> IamResult<Map<String, Value>> {
        let decoded =
            jose::decode(id_token).map_err(|error| protocol_failure(error.to_string()))?;
        let alg = decoded
            .header
            .get("alg")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let supported: Vec<String> = metadata
            .get("id_token_signing_alg_values_supported")
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_else(|| vec!["RS256".to_owned()]);
        if !supported.contains(&alg) {
            return Err(protocol_failure("unexpected JWT \"alg\" header parameter"));
        }
        if decoded.header.get("crit").is_some() {
            return Err(protocol_failure(
                "no JWT \"crit\" header parameter extensions are supported",
            ));
        }
        let claims = decoded.payload.clone();
        let now = (js::now_ms() / 1000.0).floor();
        let tolerance = 30.0;
        if let Some(exp) = claims.get("exp") {
            let exp = exp.as_f64().ok_or_else(|| {
                protocol_failure("unexpected JWT \"exp\" (expiration time) claim type")
            })?;
            if exp <= now - tolerance {
                return Err(protocol_failure(
                    "unexpected JWT \"exp\" (expiration time) claim value, expiration is past current timestamp",
                ));
            }
        }
        if claims.get("iat").is_some_and(|iat| !iat.is_number()) {
            return Err(protocol_failure(
                "unexpected JWT \"iat\" (issued at) claim type",
            ));
        }
        if claims.get("iss").is_some_and(|iss| !iss.is_string()) {
            return Err(protocol_failure(
                "unexpected JWT \"iss\" (issuer) claim type",
            ));
        }
        if let Some(nbf) = claims.get("nbf") {
            let nbf = nbf.as_f64().ok_or_else(|| {
                protocol_failure("unexpected JWT \"nbf\" (not before) claim type")
            })?;
            if nbf > now + tolerance {
                return Err(protocol_failure(
                    "unexpected JWT \"nbf\" (not before) claim value",
                ));
            }
        }
        if claims
            .get("aud")
            .is_some_and(|aud| !aud.is_string() && !aud.is_array())
        {
            return Err(protocol_failure(
                "unexpected JWT \"aud\" (audience) claim type",
            ));
        }
        for claim in ["aud", "exp", "iat", "iss", "sub", "nonce"] {
            if claims.get(claim).is_none() {
                return Err(protocol_failure(format!("JWT \"{claim}\" claim missing")));
            }
        }
        if claims.get("iss").and_then(Value::as_str) != meta_str(metadata, "issuer") {
            return Err(protocol_failure(
                "unexpected JWT \"iss\" (issuer) claim value",
            ));
        }
        let audiences: Vec<String> = match claims.get("aud") {
            Some(Value::Array(values)) => values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect(),
            Some(Value::String(aud)) => vec![aud.clone()],
            _ => Vec::new(),
        };
        let aud_ok = match claims.get("aud") {
            Some(Value::Array(values)) => {
                values.iter().any(|value| value.as_str() == Some(client_id))
            }
            Some(Value::String(aud)) => aud == client_id,
            _ => false,
        };
        if !aud_ok {
            return Err(protocol_failure(
                "unexpected JWT \"aud\" (audience) claim value",
            ));
        }
        if !claims.get("sub").is_some_and(Value::is_string) {
            return Err(protocol_failure(
                "unexpected JWT \"sub\" (subject) claim type",
            ));
        }
        // Authorized party: required with several audiences, and the client when present.
        if audiences.len() > 1 && claims.get("azp").is_none() {
            return Err(protocol_failure(
                "ID Token \"aud\" (audience) claim includes additional untrusted audiences",
            ));
        }
        if let Some(azp) = claims.get("azp")
            && azp.as_str() != Some(client_id)
        {
            return Err(protocol_failure(
                "unexpected ID Token \"azp\" (authorized party) claim value",
            ));
        }
        if let Some(auth_time) = claims.get("auth_time")
            && !auth_time
                .as_f64()
                .is_some_and(|value| value.is_finite() && value >= 0.0)
        {
            return Err(protocol_failure(
                "ID Token \"auth_time\" (authentication time) must be a number",
            ));
        }
        if claims.get("nonce").and_then(Value::as_str) != Some(expected_nonce) {
            return Err(protocol_failure(
                "unexpected ID Token \"nonce\" claim value",
            ));
        }
        // validateApplicationLevelSignature: the issuer's keys from its jwks_uri.
        if alg.starts_with("HS") {
            return Err(protocol_failure("unsupported JWS algorithm"));
        }
        let jwks_uri = meta_str(metadata, "jwks_uri")
            .filter(|uri| !uri.is_empty())
            .ok_or_else(|| protocol_failure("\"as.jwks_uri\" must be a string"))?;
        checked_url(jwks_uri, self.allow())?;
        let header = decoded.header.clone();
        let keys = self
            .issuer_keys(jwks_uri, |keys| !keys.candidates(&header).is_empty())
            .await?;
        let candidates = keys.candidates(&decoded.header);
        if candidates.is_empty() {
            return Err(protocol_failure(
                "error when selecting a JWT verification key, no applicable keys found",
            ));
        }
        if candidates.len() > 1 {
            return Err(protocol_failure(
                "error when selecting a JWT verification key, multiple applicable keys found, a \"kid\" JWT Header Parameter is required",
            ));
        }
        let key = jose::import_jwk(&jose::public_jwk(candidates[0]))
            .map_err(|error| protocol_failure(error.to_string()))?;
        if !jose::verify_bytes(
            &key,
            &alg,
            decoded.signing_input.as_bytes(),
            &decoded.signature,
        ) {
            return Err(protocol_failure("JWT signature verification failed"));
        }
        Ok(claims)
    }

    async fn protected_resource(
        &self,
        access_token: &str,
        url: &str,
        headers: &[(&str, &str)],
    ) -> IamResult<FetchResponse> {
        let mut request = FetchRequest::get(url).redirect(RedirectMode::Manual);
        for (name, value) in headers {
            request = request.header(*name, *value);
        }
        if !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("user-agent"))
        {
            request = request.header("user-agent", USER_AGENT);
        }
        request = request.header("authorization", format!("Bearer {access_token}"));
        let response = self.send(request).await?;
        if response.status == 401 && response.header("www-authenticate").is_some() {
            return Err(protocol_failure(
                "server responded with a challenge in the WWW-Authenticate HTTP Header",
            ));
        }
        Ok(response)
    }

    /// `callback(connectionId, callbackUrl, binding)`.
    pub async fn callback(
        &self,
        connection_id: &str,
        callback_url: &str,
        binding: &str,
    ) -> IamResult<Value> {
        let item = self.connection(connection_id)?.clone();
        let returned = parse_url(callback_url)?;
        let expected = parse_url(&item.redirect_uri)?;
        if origin(&returned) != origin(&expected) || returned.path() != expected.path() {
            return Err(IamError::with_status(
                "OAUTH_CALLBACK",
                "Unexpected callback URL.",
                400,
            ));
        }
        let state_value = returned
            .query_pairs()
            .find(|(key, _)| key == "state")
            .map(|(_, value)| value.into_owned())
            .unwrap_or_default();
        if state_value.is_empty() || js::utf16_len(&state_value) > 512 || binding.is_empty() {
            return Err(IamError::with_status(
                "OAUTH_STATE",
                "Missing login state.",
                400,
            ));
        }
        let tenant_id = item.tenant_id.clone();
        let binding_hash = hash(binding);
        let connection = connection_id.to_owned();
        let saved = self
            .config
            .store
            .transaction(move |tx| async move {
                let state = tx.get("oauthLoginStates", &hash(&state_value)).await?;
                let valid = state.as_ref().is_some_and(|state| {
                    state.get("connectionId").and_then(Value::as_str) == Some(connection.as_str())
                        && state.get("tenantId").and_then(Value::as_str) == Some(tenant_id.as_str())
                        && state
                            .get("expiresAt")
                            .and_then(Value::as_f64)
                            .is_some_and(|expires| expires > js::now_ms())
                        && jose::constant_equals(
                            &binding_hash,
                            state
                                .get("bindingHash")
                                .and_then(Value::as_str)
                                .unwrap_or_default(),
                        )
                });
                let Some(state) = state.filter(|_| valid) else {
                    return Err(IamError::with_status(
                        "OAUTH_STATE",
                        "Invalid, expired, or replayed login state.",
                        400,
                    ));
                };
                active_tenant(tx.as_ref(), &tenant_id).await?;
                tx.delete(
                    "oauthLoginStates",
                    state.get("id").and_then(Value::as_str).unwrap_or_default(),
                )
                .await?;
                Ok(state)
            })
            .await?;
        let saved_text = |key: &str| {
            saved
                .get(key)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned()
        };
        let discovered = self.metadata(&item).await?;
        // validateAuthResponse.
        let iss_supported = item.kind != ConnectionKind::Microsoft
            && discovered.get("authorization_response_iss_parameter_supported")
                == Some(&Value::Bool(true));
        if get_param(&returned, "response")?.is_some() {
            return Err(protocol_failure(
                "\"parameters\" contains a JARM response, use validateJwtAuthResponse() instead of validateAuthResponse()",
            ));
        }
        let iss = get_param(&returned, "iss")?;
        let state = get_param(&returned, "state")?;
        if iss.as_deref().is_none_or(str::is_empty) && iss_supported {
            return Err(protocol_failure(
                "response parameter \"iss\" (issuer) missing",
            ));
        }
        if let Some(iss) = iss.as_deref().filter(|iss| !iss.is_empty())
            && Some(iss) != meta_str(&discovered, "issuer")
        {
            return Err(protocol_failure(
                "unexpected \"iss\" (issuer) response parameter value",
            ));
        }
        if state.as_deref() != Some(saved_text("state").as_str()) {
            return Err(protocol_failure(if state.is_none() {
                "response parameter \"state\" missing"
            } else {
                "unexpected \"state\" response parameter value"
            }));
        }
        if get_param(&returned, "error")?.is_some_and(|error| !error.is_empty()) {
            return Err(protocol_failure(
                "authorization response from the server is an error",
            ));
        }
        if get_param(&returned, "id_token")?.is_some() || get_param(&returned, "token")?.is_some() {
            return Err(protocol_failure(
                "implicit and hybrid flows are not supported",
            ));
        }
        let code = get_param(&returned, "code")?
            .filter(|code| !code.is_empty())
            .ok_or_else(|| protocol_failure("no authorization code in \"callbackParameters\""))?;
        // authorizationCodeGrantRequest.
        let token_endpoint = meta_str(&discovered, "token_endpoint")
            .filter(|endpoint| !endpoint.is_empty())
            .ok_or_else(|| protocol_failure("\"as.token_endpoint\" must be a string"))?;
        let token_url = parse_url(token_endpoint)?;
        if token_url.scheme() != "https" && !self.allow() {
            return Err(protocol_failure("only requests to HTTPS are allowed"));
        }
        let mut form = url::form_urlencoded::Serializer::new(String::new());
        form.append_pair("redirect_uri", &item.redirect_uri);
        form.append_pair("code", &code);
        form.append_pair("code_verifier", &saved_text("codeVerifier"));
        form.append_pair("grant_type", "authorization_code");
        form.append_pair("client_id", &item.client_id);
        if let Some(secret) = item
            .client_secret
            .as_deref()
            .filter(|secret| !secret.is_empty())
        {
            form.append_pair("client_secret", secret);
        }
        let mut token_response = self
            .send(
                FetchRequest::new(
                    token_url.to_string(),
                    "POST",
                    Some(FetchBody::Text(form.finish())),
                )
                .header("accept", "application/json")
                .header("user-agent", USER_AGENT)
                .header(
                    "content-type",
                    "application/x-www-form-urlencoded;charset=UTF-8",
                )
                .redirect(RedirectMode::Manual),
            )
            .await?;
        if token_response.status != 200 {
            if token_response.status == 401 && token_response.header("www-authenticate").is_some() {
                return Err(protocol_failure(
                    "server responded with a challenge in the WWW-Authenticate HTTP Header",
                ));
            }
            return Err(protocol_failure(
                "\"response\" is not a conform Token Endpoint response (unexpected HTTP status code)",
            ));
        }
        let token_body = read_json(&mut token_response).await?;
        // Entra multi-tenant metadata names the issuer as a template; resolve it for the directory that signed in.
        let metadata = if item.kind == ConnectionKind::Microsoft {
            self.microsoft_issuer(&item, &discovered, &token_body)?
        } else {
            discovered.clone()
        };
        // processGenericAccessTokenResponse.
        let Value::Object(result) = &token_body else {
            return Err(protocol_failure(
                "\"response\" body must be a top level object",
            ));
        };
        let access_token = result
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                protocol_failure("\"response\" body \"access_token\" property must be a string")
            })?
            .to_owned();
        let token_type = result
            .get("token_type")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| {
                protocol_failure("\"response\" body \"token_type\" property must be a string")
            })?
            .to_lowercase();
        if let Some(expires_in) = result.get("expires_in") {
            let number = match expires_in {
                Value::Number(number) => number.as_f64().unwrap_or(f64::NAN),
                Value::String(text) => text.trim().parse::<f64>().unwrap_or(f64::NAN),
                _ => f64::NAN,
            };
            if !number.is_finite() || number < 0.0 {
                return Err(protocol_failure(
                    "\"response\" body \"expires_in\" property must be a non-negative number",
                ));
            }
        }
        if result
            .get("refresh_token")
            .is_some_and(|token| !token.as_str().is_some_and(|token| !token.is_empty()))
        {
            return Err(protocol_failure(
                "\"response\" body \"refresh_token\" property must be a string",
            ));
        }
        if result.get("scope").is_some_and(|scope| !scope.is_string()) {
            return Err(protocol_failure(
                "\"response\" body \"scope\" property must be a string",
            ));
        }
        let openid = !matches!(item.kind, ConnectionKind::Github | ConnectionKind::Oauth2);
        let id_token = match result.get("id_token") {
            Some(Value::String(token)) if !token.is_empty() => Some(token.clone()),
            Some(_) => {
                return Err(protocol_failure(
                    "\"response\" body \"id_token\" property must be a string",
                ));
            }
            None => None,
        };
        let mut claims: Option<Map<String, Value>> = None;
        if openid {
            let Some(id_token) = &id_token else {
                return Err(protocol_failure(
                    "\"response\" body \"id_token\" property must be a string",
                ));
            };
            claims = Some(
                self.validate_id_token(&metadata, &item.client_id, id_token, &saved_text("nonce"))
                    .await?,
            );
        } else if id_token.is_some() {
            return Err(protocol_failure(
                "unexpected ID Token in a plain OAuth 2.0 response",
            ));
        }
        if token_type != "bearer" && token_type != "dpop" {
            return Err(protocol_failure("unsupported `token_type` value"));
        }
        let mut identity = match item.kind {
            ConnectionKind::Github => {
                let headers = [
                    ("accept", "application/vnd.github+json"),
                    ("user-agent", "better-iam"),
                ];
                let mut profile_response = self
                    .protected_resource(&access_token, "https://api.github.com/user", &headers)
                    .await?;
                if !profile_response.ok() {
                    return Err(IamError::with_status(
                        "OAUTH_PROFILE",
                        "Provider profile request failed.",
                        401,
                    ));
                }
                let profile = read_json(&mut profile_response).await?;
                let profile = profile.as_object().cloned().unwrap_or_default();
                let subject = match profile.get("id") {
                    Some(Value::Number(number)) => {
                        js::number_to_string(number.as_f64().unwrap_or_default())
                    }
                    Some(Value::String(text)) => text.clone(),
                    _ => String::new(),
                };
                if subject.is_empty() {
                    return Err(IamError::with_status(
                        "OAUTH_PROFILE",
                        "Provider subject is missing.",
                        401,
                    ));
                }
                let name = profile
                    .get("name")
                    .and_then(Value::as_str)
                    .or_else(|| profile.get("login").and_then(Value::as_str))
                    .map(str::to_owned);
                let mut identity = FederatedIdentity {
                    tenant_id: item.tenant_id.clone(),
                    provider_id: item.id.clone(),
                    issuer: "https://github.com".into(),
                    subject,
                    name,
                    ..FederatedIdentity::default()
                };
                if let Some(map) = &item.map_attributes
                    && let Some(attributes) = map(&profile)
                {
                    identity.attributes = Some(attributes);
                }
                let mut email_response = self
                    .protected_resource(
                        &access_token,
                        "https://api.github.com/user/emails",
                        &headers,
                    )
                    .await?;
                if email_response.ok() {
                    let emails = read_json(&mut email_response).await?;
                    if let Value::Array(emails) = emails {
                        let primary = emails.iter().filter_map(Value::as_object).find(|value| {
                            value.get("primary") == Some(&Value::Bool(true))
                                && value.get("verified") == Some(&Value::Bool(true))
                        });
                        if let Some(email) = primary
                            .and_then(|primary| primary.get("email"))
                            .and_then(Value::as_str)
                        {
                            identity.email = Some(email.to_owned());
                            identity.email_verified = Some(true);
                        }
                    }
                }
                identity
            }
            ConnectionKind::Oauth2 => {
                let endpoint = item.user_info_endpoint.clone().unwrap_or_default();
                let mut profile_response = self
                    .protected_resource(&access_token, &endpoint, &[("accept", "application/json")])
                    .await?;
                if !profile_response.ok() {
                    return Err(IamError::with_status(
                        "OAUTH_PROFILE",
                        "Provider profile request failed.",
                        401,
                    ));
                }
                let profile = read_json(&mut profile_response).await?;
                let Value::Object(profile) = profile else {
                    return Err(IamError::with_status(
                        "OAUTH_PROFILE",
                        "Provider profile is invalid.",
                        401,
                    ));
                };
                let mapper = item
                    .map_profile
                    .clone()
                    .ok_or_else(|| configuration("mapProfile is required"))?;
                let mapped = mapper(&profile);
                let subject = match &mapped.subject {
                    Value::String(subject)
                        if !subject.is_empty() && js::utf16_len(subject) <= 512 =>
                    {
                        subject.clone()
                    }
                    _ => {
                        return Err(IamError::with_status(
                            "OAUTH_PROFILE",
                            "Provider subject is missing.",
                            401,
                        ));
                    }
                };
                let mut identity = FederatedIdentity {
                    tenant_id: item.tenant_id.clone(),
                    provider_id: item.id.clone(),
                    issuer: item.issuer.clone().unwrap_or_default(),
                    subject,
                    email: mapped.email.clone(),
                    email_verified: Some(mapped.email_verified == Some(true)),
                    name: mapped.name.clone(),
                    ..FederatedIdentity::default()
                };
                if let Some(map) = &item.map_attributes
                    && let Some(attributes) = map(&profile)
                {
                    identity.attributes = Some(attributes);
                }
                identity
            }
            _ => {
                let claims = claims.unwrap_or_default();
                let subject = claims
                    .get("sub")
                    .and_then(Value::as_str)
                    .filter(|sub| !sub.is_empty());
                let Some(subject) = subject else {
                    return Err(IamError::with_status(
                        "OAUTH_PROFILE",
                        "OIDC subject is missing.",
                        401,
                    ));
                };
                let mut identity = FederatedIdentity {
                    tenant_id: item.tenant_id.clone(),
                    provider_id: item.id.clone(),
                    issuer: claims
                        .get("iss")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    subject: subject.to_owned(),
                    email: claims
                        .get("email")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    // Entra lets directory administrators set any email; only its verified-domain claim counts.
                    email_verified: Some(if item.kind == ConnectionKind::Microsoft {
                        claims.get("xms_edov") == Some(&Value::Bool(true))
                    } else {
                        claims.get("email_verified") == Some(&Value::Bool(true))
                    }),
                    name: claims
                        .get("name")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    ..FederatedIdentity::default()
                };
                if let Some(map) = &item.map_attributes
                    && let Some(attributes) = map(&claims)
                {
                    identity.attributes = Some(attributes);
                }
                identity
            }
        };
        active_tenant(self.config.store.as_ref(), &item.tenant_id).await?;
        // Addresses outside the connection's enrollment domains never create an account.
        if let Some(Value::Array(domains)) = &item.allowed_email_domains
            && identity.email_verified == Some(true)
            && !domains.iter().filter_map(Value::as_str).any(|domain| {
                identity.email.as_ref().is_some_and(|email| {
                    email
                        .to_lowercase()
                        .ends_with(&format!("@{}", domain.to_lowercase()))
                })
            })
        {
            identity.email_verified = Some(false);
        }
        if let Some(trust) = &item.trust_scim_provisioned
            && truthy(Some(trust))
        {
            identity.trust_scim_provisioned = Some(trust.clone());
        }
        let linking_session = saved
            .get("linkingSessionId")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty());
        let linking_identity = saved
            .get("linkingIdentityId")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty());
        if let (Some(session), Some(identity_id)) = (linking_session, linking_identity) {
            identity.linking_identity_id = Some(identity_id.to_owned());
            identity.linking_session_id = Some(session.to_owned());
        }
        // Only protocol-verified claims reach this trusted server callback. It must apply local MFA.
        (self.config.complete_authentication)(identity).await
    }

    fn cookie_name(&self, item: &OAuthLoginConnection) -> String {
        let secure = url::Url::parse(&item.redirect_uri).is_ok_and(|url| url.scheme() == "https");
        format!(
            "{}better-iam-oauth-{}",
            if secure { "__Host-" } else { "" },
            &hash(&item.id)[..12]
        )
    }

    fn json_response(status: u16, body: &Value, headers: &[(&str, String)]) -> HttpResponse {
        let mut all = vec![("content-type", "application/json".to_owned())];
        all.extend(headers.iter().cloned());
        response(status, &all, js::stringify(body))
    }

    /// `handler(request)`: the callback URLs (GET), `{basePath}/{connectionId}` to start a sign-in (GET, 302) or a
    /// linking flow (POST, JSON); None for anything else.
    pub async fn handler(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let request_url = request_url_string(request, None);
        let parsed = url::Url::parse(&request_url).ok()?;
        let method = request.method().as_str();
        let header = |name: &str| -> Option<String> {
            let values: Vec<&str> = request
                .headers()
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            (!values.is_empty()).then(|| values.join(", "))
        };
        let callback_item = self.connections.iter().find(|value| {
            url::Url::parse(&value.redirect_uri).is_ok_and(|target| {
                origin(&target) == origin(&parsed) && target.path() == parsed.path()
            })
        });
        if method == "GET"
            && let Some(item) = callback_item
        {
            let secure =
                url::Url::parse(&item.redirect_uri).is_ok_and(|url| url.scheme() == "https");
            let cookie_name = self.cookie_name(item);
            let binding = header("cookie")
                .and_then(|cookies| {
                    cookies
                        .split(';')
                        .map(str::trim)
                        .find(|value| value.starts_with(&format!("{cookie_name}=")))
                        .map(|value| value[cookie_name.len() + 1..].to_owned())
                })
                .unwrap_or_default();
            return Some(
                match self.callback(&item.id, &request_url, &binding).await {
                    Ok(result) => Self::json_response(
                        200,
                        &result,
                        &[
                            ("cache-control", "no-store".to_owned()),
                            (
                                "set-cookie",
                                format!(
                                    "{cookie_name}=; Path=/; HttpOnly; {}SameSite=Lax; Max-Age=0",
                                    if secure { "Secure; " } else { "" }
                                ),
                            ),
                        ],
                    ),
                    Err(error) => Self::json_response(
                        error.status,
                        &json!({ "error": error.code }),
                        &[("cache-control", "no-store".to_owned())],
                    ),
                },
            );
        }
        if !parsed.path().starts_with(&format!("{}/", self.base_path)) {
            return None;
        }
        if method != "GET" && method != "POST" {
            return Some(Self::json_response(
                405,
                &json!({ "error": "METHOD_NOT_ALLOWED" }),
                &[],
            ));
        }
        let outcome: IamResult<HttpResponse> = async {
            let raw = &parsed.path()[self.base_path.len() + 1..];
            let id = percent_decode(raw).ok_or_else(|| protocol_failure("URI malformed"))?;
            if method == "POST" {
                let item = self.connection(&id)?;
                let trusted = self.config.trusted_origins.clone().unwrap_or_else(|| {
                    vec![
                        url::Url::parse(&item.redirect_uri)
                            .map(|url| origin(&url))
                            .unwrap_or_default(),
                    ]
                });
                let origin_header = header("origin");
                if origin_header
                    .as_ref()
                    .is_none_or(|origin| origin.is_empty() || !trusted.contains(origin))
                    || header("x-better-iam").as_deref() != Some("1")
                    || !header("content-type")
                        .is_some_and(|value| value.starts_with("application/json"))
                {
                    return Err(IamError::with_status(
                        "CSRF",
                        "Linking requires a trusted Origin and X-Better-IAM header.",
                        403,
                    ));
                }
            }
            let query = |name: &str| {
                parsed
                    .query_pairs()
                    .find(|(key, _)| key == name)
                    .map(|(_, value)| value.into_owned())
                    .filter(|value| !value.is_empty())
                    .map(Value::String)
            };
            let hints = LoginHints {
                login_hint: query("login_hint"),
                domain_hint: query("domain_hint"),
                prompt: query("prompt"),
            };
            let credential = (method == "POST").then(|| CredentialInput {
                headers: Some(
                    request
                        .headers()
                        .iter()
                        .filter_map(|(name, value)| {
                            value
                                .to_str()
                                .ok()
                                .map(|value| (name.as_str().to_owned(), value.to_owned()))
                        })
                        .collect(),
                ),
                token: None,
            });
            let result = self.begin(&id, credential.as_ref(), Some(&hints)).await?;
            let item = self.connection(&id)?;
            let secure =
                url::Url::parse(&item.redirect_uri).is_ok_and(|url| url.scheme() == "https");
            let cookie = format!(
                "{}better-iam-oauth-{}={}; Path=/; HttpOnly; {}SameSite=Lax; Max-Age=600",
                if secure { "__Host-" } else { "" },
                &hash(&id)[..12],
                result.binding,
                if secure { "Secure; " } else { "" }
            );
            let headers = vec![
                ("cache-control", "no-store".to_owned()),
                ("set-cookie", cookie),
            ];
            Ok(if method == "POST" {
                Self::json_response(200, &json!({ "url": result.url }), &headers)
            } else {
                let mut all = headers;
                all.push(("location", result.url));
                response(302, &all, Bytes::new())
            })
        }
        .await;
        Some(outcome.unwrap_or_else(|error| {
            Self::json_response(error.status, &json!({ "error": error.code }), &[])
        }))
    }
}

/// `decodeURIComponent`: None for malformed escapes.
pub(crate) fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let hex = value.get(index + 1..index + 3)?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            index += 3;
        } else {
            out.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(out).ok()
}
