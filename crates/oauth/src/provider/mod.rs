//! The OAuth 2.0 / OpenID Connect authorization server (provider.ts). TypeScript builds it on `oidc-provider`; this
//! port implements the provider natively, limited to the features the TypeScript configuration enables, with the
//! same routes, parameters, errors, cookies and encrypted artifacts (shared with TypeScript replicas).

pub mod core;
mod endpoints;
pub mod http;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use better_iam_auth::safe_fetch::{GuardedFetch, GuardedFetchOptions, create_guarded_fetch};
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore,
    IamStoreExt, Record, ResourceRef, SessionKind, append_audit_event, js, tenant_tree_active,
};
use futures::future::BoxFuture;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use self::core::{Core, ServerChallenge, grant as grant_ops, n, num, s};
use crate::adapter::{
    Cipher, ProviderAdapterFactory, cipher, create_provider_adapter, encryption_key, hash,
    iam_carrier_to_provider, provider_to_iam_carrier, truthy,
};
use crate::errors::{OidcError, ProviderError, ProviderResult};
use crate::resource_server::{HttpRequest, HttpResponse};

/// An asynchronous host callback.
pub type Callback<A, R> = Arc<dyn Fn(A) -> BoxFuture<'static, IamResult<R>> + Send + Sync>;

/// A protected API that clients address with an RFC 8707 `resource` indicator (`OAuthResourceServer`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OAuthResourceServer {
    /// Scopes this API understands.
    pub scopes: Vec<String>,
    /// Access token `aud`; defaults to the resource indicator.
    pub audience: Option<String>,
    /// Access token lifetime in seconds (default 900).
    pub access_token_ttl: Option<f64>,
    /// `jwt` (default) or `opaque`.
    pub access_token_format: Option<String>,
}

/// The groups and roles an identity holds right now (`liveGrants`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct LiveGrants {
    pub group_ids: Vec<String>,
    pub role_ids: Vec<String>,
}

/// What `renderDevicePage` renders.
#[derive(Debug, Clone, PartialEq)]
pub struct DevicePageInput {
    /// `input`, `confirm`, or `success`.
    pub kind: String,
    pub form: String,
    pub user_code: Option<String>,
    pub client_name: Option<String>,
}

/// What dynamically registered clients of one tenant may be (`RegistrationPolicy`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RegistrationPolicy {
    pub tenant_id: String,
    pub scopes: Option<Vec<String>>,
    pub resources: Option<Vec<String>>,
    pub allow_confidential: bool,
    pub max_clients: Option<f64>,
}

/// The request an anonymous registration hook judges.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AnonymousRegistrationRequest {
    pub headers: Vec<(String, String)>,
    pub ip: Option<String>,
}

/// `registration` options.
#[derive(Clone, Default)]
pub struct RegistrationConfig {
    pub anonymous: Option<Callback<AnonymousRegistrationRequest, Option<RegistrationPolicy>>>,
}

/// A token exchange the provider is about to perform (`TokenExchangeRequest`).
#[derive(Debug, Clone, PartialEq)]
pub struct TokenExchangeRequest {
    pub tenant_id: String,
    pub client_id: String,
    pub identity_id: String,
    pub subject_client_id: String,
    pub subject_scopes: Vec<String>,
    pub resource: String,
    pub scopes: Vec<String>,
}

/// `OAuthProviderConfig`.
#[derive(Clone)]
pub struct OAuthProviderConfig {
    pub store: Arc<dyn IamStore>,
    pub issuer: String,
    /// The private signing keys (`{ keys: [...] }`).
    pub jwks: Value,
    pub cookie_keys: Vec<String>,
    /// Base64-encoded 32-byte key, separate from signing keys. Encrypts provider artifacts at rest.
    pub encryption_key: String,
    pub authenticate: Callback<CredentialInput, AuthenticatedPrincipal>,
    pub validate_session: Option<Callback<String, ()>>,
    pub live_grants: Option<Callback<(String, String), LiveGrants>>,
    pub client_allowed: Option<Callback<(String, String, String), bool>>,
    pub authorize: Callback<(CredentialInput, String, ResourceRef), ()>,
    pub interaction_url: Arc<dyn Fn(&str) -> String + Send + Sync>,
    pub render_device_page: Callback<DevicePageInput, String>,
    pub render_logout_page: Callback<String, String>,
    pub trusted_origins: Vec<String>,
    pub scopes: Option<Vec<String>>,
    pub resource_servers: IndexMap<String, OAuthResourceServer>,
    pub require_pushed_authorization_requests: bool,
    pub dpop_nonce_secret: Option<String>,
    pub authorize_token_exchange: Option<Callback<TokenExchangeRequest, bool>>,
    pub registration: Option<RegistrationConfig>,
    pub trust_proxy: bool,
    pub allow_insecure_localhost: bool,
}

const GRANT_TYPES_SUPPORTED: [&str; 5] = [
    "authorization_code",
    "refresh_token",
    "client_credentials",
    "urn:ietf:params:oauth:grant-type:device_code",
    "urn:ietf:params:oauth:grant-type:token-exchange",
];
pub(crate) const TOKEN_EXCHANGE: &str = "urn:ietf:params:oauth:grant-type:token-exchange";
pub(crate) const ACCESS_TOKEN_TYPE: &str = "urn:ietf:params:oauth:token-type:access_token";
const LOOPBACK: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];
const DEFAULT_REGISTRATION_SCOPES: [&str; 4] = ["openid", "profile", "email", "offline_access"];

/// What the registration gate decided for one `POST /reg`.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistrationContext {
    pub tenant_id: String,
    pub scopes: Vec<String>,
    pub resources: Vec<String>,
    pub allow_confidential: bool,
    pub max_clients: f64,
    pub token_id: Option<String>,
    pub actor_id: String,
}

pub(crate) struct Inner {
    pub core: Core,
    pub config: OAuthProviderConfig,
    pub supported_scopes: Vec<String>,
    pub registration_scope: usize,
}

/// `createOAuthProvider(config)`.
#[derive(Clone)]
pub struct OAuthProvider {
    pub(crate) inner: Arc<Inner>,
    pub base_path: String,
}

impl std::fmt::Debug for OAuthProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "OAuthProvider({})", self.inner.config.issuer)
    }
}

fn scope_name_ok(scope: &str) -> bool {
    !scope.is_empty()
        && js::utf16_len(scope) <= 128
        && scope
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || ":_.-".contains(c))
}

fn configuration(message: &str) -> IamError {
    IamError::new("configuration", message)
}

/// The outbound transport (JWKS URIs, back-channel logout): special-use addresses refused, loopback allowed with
/// `allowInsecureLocalhost`.
pub(crate) fn outbound_fetch(core: &Core) -> GuardedFetch {
    create_guarded_fetch(GuardedFetchOptions {
        allow_private_networks: false,
        allow_insecure_localhost: core.allow_insecure_localhost,
        any_port: true,
        max_bytes: None,
    })
}

/// `createOAuthProvider(config)`.
pub fn create_oauth_provider(config: OAuthProviderConfig) -> IamResult<OAuthProvider> {
    let issuer = url::Url::parse(&config.issuer)
        .map_err(|_| configuration("OAuth issuer must use HTTPS."))?;
    let secure_or_local = |url: &url::Url| {
        url.scheme() == "https"
            || (config.allow_insecure_localhost
                && url.scheme() == "http"
                && LOOPBACK.contains(&self::core::hostname(url).as_str()))
    };
    if issuer.query().is_some()
        || issuer.fragment().is_some()
        || !issuer.username().is_empty()
        || issuer.password().is_some()
        || !secure_or_local(&issuer)
    {
        return Err(configuration("OAuth issuer must use HTTPS."));
    }
    let keys_ok = config
        .jwks
        .get("keys")
        .and_then(Value::as_array)
        .is_some_and(|keys| !keys.is_empty());
    if !keys_ok
        || config.cookie_keys.is_empty()
        || config.cookie_keys.iter().any(|key| js::utf16_len(key) < 32)
        || config.trusted_origins.is_empty()
    {
        return Err(configuration(
            "OAuth provider signing keys, cookie keys, interaction callbacks, and trusted origins are required.",
        ));
    }
    let crypt = cipher(encryption_key(&config.encryption_key)?);
    for (indicator, server) in &config.resource_servers {
        let parsed = url::Url::parse(indicator)
            .map_err(|_| configuration("Resource indicators must be absolute URIs."))?;
        if parsed.fragment().is_some() || parsed.query().is_some() {
            return Err(configuration(
                "Resource indicators cannot carry a query or fragment (RFC 8707).",
            ));
        }
        if server.scopes.is_empty()
            || server.scopes.iter().any(|scope| !scope_name_ok(scope))
            || server
                .access_token_ttl
                .is_some_and(|ttl| !js::is_safe_integer(ttl) || ttl <= 0.0)
            || server
                .access_token_format
                .as_deref()
                .is_some_and(|format| format != "jwt" && format != "opaque")
        {
            return Err(configuration(
                "Resource servers need scope identifiers, a positive integer TTL, and a jwt or opaque format.",
            ));
        }
    }
    let mut supported_scopes: Vec<String> = Vec::new();
    for scope in ["openid", "email", "profile", "offline_access", "iam"]
        .iter()
        .map(|scope| (*scope).to_owned())
        .chain(config.scopes.clone().unwrap_or_default())
        .chain(
            config
                .resource_servers
                .values()
                .flat_map(|server| server.scopes.clone()),
        )
    {
        if !supported_scopes.contains(&scope) {
            supported_scopes.push(scope);
        }
    }
    if supported_scopes.iter().any(|scope| !scope_name_ok(scope)) {
        return Err(configuration("OAuth scopes must be nonempty identifiers."));
    }
    let dpop_nonces = match &config.dpop_nonce_secret {
        Some(secret) => {
            let bytes: [u8; 32] = crate::jose::b64_decode_lenient(secret)
                .try_into()
                .map_err(|_| configuration("dpopNonceSecret must encode exactly 32 bytes."))?;
            Some(ServerChallenge::new(bytes, "DPoP"))
        }
        None => None,
    };
    let keystore =
        self::core::initialize_keystore(&config.jwks).map_err(|message| configuration(&message))?;
    let registration_scope = better_iam_core::task_scope::new_key();
    // The provider's scopes: the configured ones plus every claim-defined scope.
    let scopes = supported_scopes.clone();
    let claims = self::core::ClaimsConfig::new(&scopes);
    let mut grant_types = vec![
        "authorization_code".to_owned(),
        "refresh_token".to_owned(),
        "client_credentials".to_owned(),
    ];
    grant_types.push("urn:ietf:params:oauth:grant-type:device_code".into());
    grant_types.push(TOKEN_EXCHANGE.into());
    let validate_session: Option<crate::adapter::ValidateSession> = config.validate_session.clone();
    let base_path = issuer
        .path()
        .strip_suffix('/')
        .unwrap_or(issuer.path())
        .to_owned();
    let inner = Arc::new_cyclic(|weak: &std::sync::Weak<Inner>| {
        let register: Option<crate::adapter::RegisterClient> =
            config.registration.as_ref().map(|_| {
                let weak = weak.clone();
                let register: crate::adapter::RegisterClient =
                    Arc::new(move |client_id: String, payload: Map<String, Value>| {
                        let weak = weak.clone();
                        Box::pin(async move {
                            let Some(inner) = weak.upgrade() else {
                                return Err(IamError::with_status(
                                    "INTERNAL_ERROR",
                                    "Provider is gone",
                                    500,
                                )
                                .into());
                            };
                            inner.store_registered_client(&client_id, &payload).await
                        })
                    });
                register
            });
        let adapter = create_provider_adapter(
            config.store.clone(),
            &config.encryption_key,
            validate_session.clone(),
            register,
        )
        .expect("the encryption key was validated");
        Inner {
            core: Core {
                issuer: config.issuer.clone(),
                base_path: base_path.clone(),
                adapter,
                crypt,
                keystore,
                scopes,
                claims,
                grant_types,
                keygrip: self::http::Keygrip::new(config.cookie_keys.clone()),
                secure: issuer.scheme() == "https",
                dpop_nonces,
                resource_servers: config.resource_servers.clone(),
                client_keys: Mutex::new(HashMap::new()),
                allow_insecure_localhost: config.allow_insecure_localhost,
            },
            config: config.clone(),
            supported_scopes,
            registration_scope,
        }
    });
    Ok(OAuthProvider { inner, base_path })
}

pub(crate) fn text(value: Option<&Value>) -> String {
    match value {
        Some(Value::String(text)) => text.clone(),
        _ => String::new(),
    }
}

fn strings_of(value: Option<&Value>) -> Option<Vec<String>> {
    value.and_then(Value::as_array).map(|values| {
        values
            .iter()
            .map(|value| match value {
                Value::String(text) => text.clone(),
                other => js::stringify(other),
            })
            .collect()
    })
}

fn invalid_input(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn resource(tenant_id: &str, kind: &str, id: &str) -> ResourceRef {
    ResourceRef {
        tenant_id: tenant_id.to_owned(),
        kind: kind.to_owned(),
        id: id.to_owned(),
    }
}

/// One live consent: its row, its grant identifier, and the summary administrators see.
pub(crate) struct LiveGrant {
    pub row: Record,
    pub grant_id: String,
    pub summary: Value,
}

impl Inner {
    pub(crate) fn adapter(&self) -> &ProviderAdapterFactory {
        &self.core.adapter
    }

    fn crypt(&self) -> &Cipher {
        &self.core.crypt
    }

    async fn authorize(
        &self,
        credential: &CredentialInput,
        action: &str,
        target: ResourceRef,
    ) -> IamResult<()> {
        (self.config.authorize)((credential.clone(), action.to_owned(), target)).await
    }

    async fn authenticate(
        &self,
        credential: &CredentialInput,
    ) -> IamResult<AuthenticatedPrincipal> {
        (self.config.authenticate)(credential.clone()).await
    }

    pub(crate) async fn audit(
        tx: &dyn IamStore,
        tenant_id: &str,
        actor_id: &str,
        action: &str,
        resource_id: &str,
    ) -> IamResult<()> {
        let mut event = Map::new();
        event.insert("id".into(), json!(uuid::Uuid::new_v4().to_string()));
        event.insert("tenantId".into(), json!(tenant_id));
        event.insert("actorId".into(), json!(actor_id));
        event.insert("action".into(), json!(action));
        event.insert("resourceId".into(), json!(resource_id));
        event.insert("timestamp".into(), num(js::now_ms()));
        event.insert("outcome".into(), json!("allow"));
        append_audit_event(tx, &event).await?;
        Ok(())
    }

    /// `registrationLimits(policy)`: validates an anonymous-registration policy from the host.
    pub(crate) fn registration_limits(
        &self,
        policy: &RegistrationPolicy,
    ) -> IamResult<RegistrationContext> {
        let mut scopes: Vec<String> = Vec::new();
        for scope in policy.scopes.clone().unwrap_or_else(|| {
            DEFAULT_REGISTRATION_SCOPES
                .iter()
                .map(|s| (*s).to_owned())
                .collect()
        }) {
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        let mut resources: Vec<String> = Vec::new();
        for indicator in policy.resources.clone().unwrap_or_default() {
            if !resources.contains(&indicator) {
                resources.push(indicator);
            }
        }
        let max_clients = policy.max_clients.unwrap_or(100.0);
        if policy.tenant_id.is_empty()
            || scopes.is_empty()
            || scopes
                .iter()
                .any(|scope| !self.supported_scopes.contains(scope))
            || resources
                .iter()
                .any(|indicator| !self.core.resource_servers.contains_key(indicator))
            || !js::is_safe_integer(max_clients)
            || !(1.0..=100_000.0).contains(&max_clients)
        {
            return Err(configuration("Invalid dynamic registration policy."));
        }
        Ok(RegistrationContext {
            tenant_id: policy.tenant_id.clone(),
            scopes,
            resources,
            allow_confidential: policy.allow_confidential,
            max_clients,
            token_id: None,
            actor_id: String::new(),
        })
    }

    /// `usableRegistrationToken(record)`.
    pub(crate) fn usable_registration_token(record: &Record) -> bool {
        !truthy(record.get("revoked"))
            && n(record, "expiresAt").is_some_and(|expires| expires > js::now_ms())
            && n(record, "used").unwrap_or_default() < n(record, "maxClients").unwrap_or_default()
    }

    fn registration_token_summary(record: &Record) -> Value {
        let mut out = Map::new();
        for key in [
            "id",
            "tenantId",
            "name",
            "scopes",
            "resources",
            "allowConfidential",
            "maxClients",
            "used",
            "createdBy",
            "createdAt",
            "expiresAt",
            "revoked",
        ] {
            out.insert(key.into(), record.get(key).cloned().unwrap_or(Value::Null));
        }
        Value::Object(out)
    }

    /// The registration context of the current request (`registrationContext.getStore()`).
    pub(crate) fn registering(&self) -> Option<Arc<RegistrationContext>> {
        better_iam_core::task_scope::current::<RegistrationContext>(self.registration_scope)
    }

    /// `storeRegisteredClient(clientId, payload)`: persists a dynamically registered client inside the registration
    /// gate's tenant and limits.
    pub(crate) async fn store_registered_client(
        &self,
        client_id: &str,
        payload: &Map<String, Value>,
    ) -> ProviderResult<()> {
        let registering = self.registering();
        let Some(registering) = registering
            .filter(|context| s(payload, "tenant_id") == Some(context.tenant_id.as_str()))
        else {
            return Err(IamError::with_status(
                "PROTECTED_OPERATION",
                "Use authenticated registerClient().",
                403,
            )
            .into());
        };
        let crypt = self.crypt().clone();
        let client_id = client_id.to_owned();
        let payload = payload.clone();
        self.config
            .store
            .transaction(move |tx| async move {
                if !tenant_tree_active(tx.as_ref(), &registering.tenant_id).await? {
                    return Err(provider_to_iam_carrier(
                        OidcError::access_denied(Some("The tenant is unavailable.")).into(),
                    ));
                }
                if let Some(token_id) = &registering.token_id {
                    let token = tx.get("oauthRegistrationTokens", token_id).await?;
                    let Some(mut token) = token.filter(Inner::usable_registration_token) else {
                        return Err(provider_to_iam_carrier(
                            OidcError::invalid_token("The registration token is no longer usable.")
                                .into(),
                        ));
                    };
                    let used = n(&token, "used").unwrap_or_default() + 1.0;
                    token.insert("used".into(), num(used));
                    tx.put("oauthRegistrationTokens", &token).await?;
                } else {
                    let registered = tx
                        .find(
                            "oauthClients",
                            &Filter::new()
                                .eq("tenantId", registering.tenant_id.clone())
                                .eq("registeredVia", "anonymous"),
                            &FindOptions::default(),
                        )
                        .await?;
                    if registered.len() as f64 >= registering.max_clients {
                        return Err(provider_to_iam_carrier(
                            OidcError::access_denied(Some(
                                "The tenant has reached its registration limit.",
                            ))
                            .into(),
                        ));
                    }
                }
                if tx.get("oauthClients", &hash(&client_id)).await?.is_some() {
                    return Err(provider_to_iam_carrier(
                        OidcError::invalid_client_metadata("The client ID is taken.").into(),
                    ));
                }
                let now = js::now_ms();
                let mut row = Map::new();
                row.insert("id".into(), json!(hash(&client_id)));
                row.insert("tenantId".into(), json!(registering.tenant_id));
                row.insert("clientId".into(), json!(client_id));
                row.insert(
                    "encrypted".into(),
                    json!(crypt.seal(&Value::Object(payload))),
                );
                row.insert("revoked".into(), json!(false));
                row.insert("resources".into(), json!(registering.resources));
                row.insert(
                    "registeredVia".into(),
                    json!(
                        registering
                            .token_id
                            .clone()
                            .unwrap_or_else(|| "anonymous".into())
                    ),
                );
                row.insert("createdAt".into(), num(now));
                row.insert("updatedAt".into(), num(now));
                tx.insert("oauthClients", &row).await?;
                Inner::audit(
                    tx.as_ref(),
                    &registering.tenant_id,
                    &registering.actor_id,
                    "iam:oauth:RegisterClient",
                    &client_id,
                )
                .await
            })
            .await
            .map_err(iam_carrier_to_provider)
    }

    /// `clientRow(clientId)`: a live client row.
    async fn client_row(&self, client_id: &str) -> IamResult<Record> {
        let row = self
            .config
            .store
            .get("oauthClients", &hash(client_id))
            .await?;
        match row {
            Some(row)
                if !truthy(row.get("revoked"))
                    && tenant_tree_active(
                        self.config.store.as_ref(),
                        s(&row, "tenantId").unwrap_or_default(),
                    )
                    .await? =>
            {
                Ok(row)
            }
            _ => Err(IamError::with_status(
                "OAUTH_CLIENT",
                "Client is unavailable.",
                404,
            )),
        }
    }

    /// `tenantClient(tx, tenantId, clientId)`: a client of `tenantId`, including revoked ones.
    async fn tenant_client(
        tx: &dyn IamStore,
        tenant_id: &str,
        client_id: &str,
    ) -> IamResult<Record> {
        let row = if client_id.is_empty() {
            None
        } else {
            tx.get("oauthClients", &hash(client_id)).await?
        };
        row.filter(|row| s(row, "tenantId") == Some(tenant_id))
            .ok_or_else(|| IamError::with_status("NOT_FOUND", "Client not found.", 404))
    }

    /// `summary(row)`: a registered client as administrators see it.
    pub(crate) fn summary(&self, row: &Record) -> IamResult<Value> {
        let metadata = self
            .crypt()
            .open_object(s(row, "encrypted").unwrap_or_default())?;
        let client_id = s(row, "clientId").unwrap_or_default();
        let mut out = Map::new();
        out.insert("clientId".into(), json!(client_id));
        out.insert(
            "tenantId".into(),
            row.get("tenantId").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "name".into(),
            json!(match metadata.get("client_name") {
                Some(Value::String(name)) => name.clone(),
                Some(Value::Null) | None => client_id.to_owned(),
                Some(other) => js::stringify(other),
            }),
        );
        out.insert(
            "public".into(),
            json!(s(&metadata, "token_endpoint_auth_method") == Some("none")),
        );
        out.insert(
            "redirectUris".into(),
            metadata
                .get("redirect_uris")
                .cloned()
                .unwrap_or_else(|| json!([])),
        );
        out.insert(
            "postLogoutRedirectUris".into(),
            metadata
                .get("post_logout_redirect_uris")
                .cloned()
                .unwrap_or_else(|| json!([])),
        );
        out.insert(
            "grantTypes".into(),
            metadata
                .get("grant_types")
                .cloned()
                .unwrap_or_else(|| json!([])),
        );
        out.insert(
            "scopes".into(),
            json!(
                text(metadata.get("scope"))
                    .split(' ')
                    .filter(|s| !s.is_empty())
                    .collect::<Vec<_>>()
            ),
        );
        out.insert(
            "resources".into(),
            row.get("resources").cloned().unwrap_or_else(|| json!([])),
        );
        out.insert(
            "requireDpop".into(),
            json!(metadata.get("dpop_bound_access_tokens") == Some(&Value::Bool(true))),
        );
        out.insert(
            "requirePushedAuthorization".into(),
            json!(
                metadata.get("require_pushed_authorization_requests") == Some(&Value::Bool(true))
            ),
        );
        out.insert(
            "tokenEndpointAuthMethod".into(),
            metadata
                .get("token_endpoint_auth_method")
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| json!("client_secret_basic")),
        );
        if truthy(metadata.get("backchannel_logout_uri")) {
            out.insert(
                "backchannelLogoutUri".into(),
                metadata["backchannel_logout_uri"].clone(),
            );
        }
        if metadata
            .get("access_token_ttl")
            .is_some_and(Value::is_number)
        {
            out.insert(
                "accessTokenTtl".into(),
                metadata["access_token_ttl"].clone(),
            );
        }
        if metadata
            .get("refresh_token_ttl")
            .is_some_and(Value::is_number)
        {
            out.insert(
                "refreshTokenTtl".into(),
                metadata["refresh_token_ttl"].clone(),
            );
        }
        if truthy(metadata.get("jwks_uri")) {
            out.insert("jwksUri".into(), metadata["jwks_uri"].clone());
        }
        if truthy(metadata.get("jwks")) {
            let ids: Vec<Value> = metadata["jwks"]
                .get("keys")
                .and_then(Value::as_array)
                .map(|keys| {
                    keys.iter()
                        .map(|key| {
                            let value = key
                                .get("kid")
                                .filter(|v| !v.is_null())
                                .or_else(|| key.get("kty"));
                            json!(match value {
                                Some(Value::String(text)) => text.clone(),
                                Some(other) => js::stringify(other),
                                None => "undefined".to_owned(),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            out.insert("keyIds".into(), Value::Array(ids));
        }
        if truthy(row.get("serviceAccountId")) {
            out.insert("serviceAccountId".into(), row["serviceAccountId"].clone());
        }
        out.insert("revoked".into(), json!(truthy(row.get("revoked"))));
        for (key, name) in [
            ("logo_uri", "logoUri"),
            ("client_uri", "clientUri"),
            ("policy_uri", "policyUri"),
            ("tos_uri", "tosUri"),
        ] {
            if truthy(metadata.get(key)) {
                out.insert(name.into(), metadata[key].clone());
            }
        }
        out.insert(
            "firstParty".into(),
            json!(row.get("firstParty") == Some(&Value::Bool(true))),
        );
        for key in ["registeredVia", "createdAt", "updatedAt", "secretRotatedAt"] {
            if truthy(row.get(key)) {
                out.insert(key.into(), row[key].clone());
            }
        }
        Ok(Value::Object(out))
    }

    fn secure_or_local(&self, url: &url::Url) -> bool {
        url.scheme() == "https"
            || (self.config.allow_insecure_localhost
                && url.scheme() == "http"
                && LOOPBACK.contains(&self::core::hostname(url).as_str()))
    }

    /// `settings(input, authMethod, serviceAccountId?)`: validated client settings as protocol metadata.
    fn settings(
        &self,
        input: &Map<String, Value>,
        auth_method: &str,
        service_account_id: Option<&str>,
    ) -> IamResult<(Map<String, Value>, Vec<String>, bool)> {
        let is_public = auth_method == "none";
        let invalid_configuration = || invalid_input("Invalid client configuration.");
        let name_ok = input
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| !name.is_empty() && js::utf16_len(name) <= 200);
        let redirect_uris = match input.get("redirectUris") {
            Some(Value::Array(values)) if values.len() <= 20 => values.clone(),
            _ => return Err(invalid_configuration()),
        };
        let post_logout = match input.get("postLogoutRedirectUris") {
            None | Some(Value::Null) => None,
            Some(Value::Array(values)) if values.len() <= 20 => Some(values.clone()),
            _ => return Err(invalid_configuration()),
        };
        if !name_ok {
            return Err(invalid_configuration());
        }
        for uri in redirect_uris.iter().chain(post_logout.iter().flatten()) {
            let text = match uri {
                Value::String(text) => text.clone(),
                other => js::stringify(other),
            };
            let parsed = url::Url::parse(&text)
                .map_err(|_| invalid_input("Client redirect URIs must be absolute URLs."))?;
            if parsed.fragment().is_some()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || !self.secure_or_local(&parsed)
            {
                return Err(invalid_input("Client redirect URIs require HTTPS."));
            }
        }
        let grant_types: Vec<Value> = match input.get("grantTypes") {
            None | Some(Value::Null) => vec![json!("authorization_code"), json!("refresh_token")],
            Some(Value::Array(values)) => values.clone(),
            Some(_) => return Err(invalid_input("Unsupported client grant types.")),
        };
        let has_grant = |name: &str| grant_types.iter().any(|value| value.as_str() == Some(name));
        if grant_types.is_empty()
            || grant_types.iter().any(|value| {
                !value
                    .as_str()
                    .is_some_and(|value| GRANT_TYPES_SUPPORTED.contains(&value))
            })
            || (is_public && (has_grant("client_credentials") || has_grant(TOKEN_EXCHANGE)))
        {
            return Err(invalid_input("Unsupported client grant types."));
        }
        if has_grant("authorization_code") && redirect_uris.is_empty() {
            return Err(invalid_input(
                "Authorization code clients need a redirect URI.",
            ));
        }
        let scopes: Vec<Value> = match input.get("scopes") {
            None | Some(Value::Null) => ["openid", "email", "profile", "offline_access"]
                .iter()
                .map(|s| json!(s))
                .collect(),
            Some(Value::Array(values)) => values.clone(),
            Some(_) => return Err(invalid_input("Unsupported OAuth scope.")),
        };
        if scopes.iter().any(|scope| {
            !scope
                .as_str()
                .is_some_and(|scope| self.supported_scopes.iter().any(|s| s == scope))
        }) {
            return Err(invalid_input("Unsupported OAuth scope."));
        }
        let mut resources: Vec<String> = Vec::new();
        for indicator in strings_of(input.get("resources")).unwrap_or_default() {
            if !resources.contains(&indicator) {
                resources.push(indicator);
            }
        }
        if resources
            .iter()
            .any(|indicator| !self.core.resource_servers.contains_key(indicator))
        {
            return Err(invalid_input("Unknown resource indicator."));
        }
        if has_grant("client_credentials") && service_account_id.is_none_or(str::is_empty) {
            return Err(invalid_input(
                "Client credentials require a tenant service account.",
            ));
        }
        if input
            .get("requireDpop")
            .is_some_and(|value| !value.is_null() && !value.is_boolean())
            || input
                .get("requirePushedAuthorization")
                .is_some_and(|value| !value.is_null() && !value.is_boolean())
        {
            return Err(invalid_configuration());
        }
        let secure_url = |value: &Value, label: &str| -> IamResult<String> {
            let text = match value {
                Value::String(text) => text.clone(),
                other => js::stringify(other),
            };
            let parsed = url::Url::parse(&text)
                .map_err(|_| invalid_input(format!("{label} must be an absolute URL.")))?;
            if !value.is_string()
                || parsed.fragment().is_some()
                || !parsed.username().is_empty()
                || parsed.password().is_some()
                || !self.secure_or_local(&parsed)
            {
                return Err(invalid_input(format!("{label} requires HTTPS.")));
            }
            Ok(text)
        };
        let lifetime = |value: Option<&Value>, min: f64, max: f64| -> IamResult<()> {
            if let Some(value) = value.filter(|value| !value.is_null()) {
                let ok = value.as_f64().is_some_and(|value| {
                    js::is_safe_integer(value) && value >= min && value <= max
                });
                if !ok {
                    return Err(invalid_input(format!(
                        " must be an integer from {} to {} seconds.",
                        js::number_to_string(min),
                        js::number_to_string(max)
                    )));
                }
            }
            Ok(())
        };
        lifetime(input.get("accessTokenTtl"), 60.0, 86400.0)?;
        lifetime(input.get("refreshTokenTtl"), 300.0, 30.0 * 86400.0)?;
        let present = |key: &str| input.get(key).filter(|value| !value.is_null());
        if let Some(value) = present("backchannelLogoutUri") {
            secure_url(value, "The back-channel logout URI")?;
        }
        for (key, label) in [
            ("logoUri", "The logo URI"),
            ("clientUri", "The client URI"),
            ("policyUri", "The policy URI"),
            ("tosUri", "The terms of service URI"),
        ] {
            if let Some(value) = present(key) {
                secure_url(value, label)?;
            }
        }
        if present("firstParty").is_some_and(|value| !value.is_boolean()) {
            return Err(invalid_input("firstParty must be a boolean."));
        }
        if auth_method == "private_key_jwt" {
            if present("jwks").is_none() == present("jwksUri").is_none() {
                return Err(invalid_input(
                    "private_key_jwt clients need either jwks or jwksUri.",
                ));
            }
            if let Some(uri) = present("jwksUri") {
                secure_url(uri, "The JWKS URI")?;
            }
            if let Some(jwks) = present("jwks") {
                let ok = jwks
                    .get("keys")
                    .and_then(Value::as_array)
                    .is_some_and(|keys| {
                        !keys.is_empty()
                            && keys.len() <= 10
                            && keys.iter().all(|key| {
                                key.as_object().is_some_and(|key| {
                                    key.get("kty").is_some_and(Value::is_string)
                                        && !["d", "p", "q", "dp", "dq", "qi", "k"]
                                            .iter()
                                            .any(|member| key.contains_key(*member))
                                })
                            })
                    });
                if !ok {
                    return Err(invalid_input("jwks must hold one to ten public keys."));
                }
            }
        } else if present("jwks").is_some() || present("jwksUri").is_some() {
            return Err(invalid_input("Only private_key_jwt clients register keys."));
        }
        let mut unique_scopes: Vec<String> = Vec::new();
        for scope in scopes.iter().filter_map(Value::as_str) {
            if !unique_scopes.iter().any(|existing| existing == scope) {
                unique_scopes.push(scope.to_owned());
            }
        }
        let mut metadata = Map::new();
        metadata.insert("client_name".into(), input["name"].clone());
        metadata.insert("redirect_uris".into(), Value::Array(redirect_uris));
        metadata.insert("grant_types".into(), Value::Array(grant_types.clone()));
        metadata.insert(
            "response_types".into(),
            if has_grant("authorization_code") {
                json!(["code"])
            } else {
                json!([])
            },
        );
        metadata.insert("scope".into(), json!(unique_scopes.join(" ")));
        metadata.insert(
            "post_logout_redirect_uris".into(),
            post_logout.map(Value::Array).unwrap_or_else(|| json!([])),
        );
        if truthy(input.get("requireDpop")) {
            metadata.insert("dpop_bound_access_tokens".into(), json!(true));
        }
        if truthy(input.get("requirePushedAuthorization")) {
            metadata.insert("require_pushed_authorization_requests".into(), json!(true));
        }
        if truthy(input.get("backchannelLogoutUri")) {
            metadata.insert(
                "backchannel_logout_uri".into(),
                input["backchannelLogoutUri"].clone(),
            );
            metadata.insert("backchannel_logout_session_required".into(), json!(false));
        }
        for (key, name) in [
            ("logoUri", "logo_uri"),
            ("clientUri", "client_uri"),
            ("policyUri", "policy_uri"),
            ("tosUri", "tos_uri"),
        ] {
            if truthy(input.get(key)) {
                metadata.insert(name.into(), input[key].clone());
            }
        }
        if let Some(value) = present("accessTokenTtl") {
            metadata.insert("access_token_ttl".into(), value.clone());
        }
        if let Some(value) = present("refreshTokenTtl") {
            metadata.insert("refresh_token_ttl".into(), value.clone());
        }
        if auth_method == "private_key_jwt" {
            if let Some(jwks) = present("jwks").filter(|value| truthy(Some(value))) {
                metadata.insert("jwks".into(), jwks.clone());
            }
            if let Some(uri) = present("jwksUri").filter(|value| truthy(Some(value))) {
                metadata.insert("jwks_uri".into(), uri.clone());
            }
        }
        Ok((
            metadata,
            resources,
            input.get("firstParty") == Some(&Value::Bool(true)),
        ))
    }

    /// Deletes every artifact issued to a client (tokens, codes, grants).
    async fn purge_client_artifacts(tx: &dyn IamStore, client_id: &str) -> IamResult<()> {
        for record in tx
            .find(
                "oauthArtifacts",
                &Filter::new().eq("clientId", client_id),
                &FindOptions::default(),
            )
            .await?
        {
            tx.delete("oauthArtifacts", s(&record, "id").unwrap_or_default())
                .await?;
        }
        Ok(())
    }

    /// `grantOwner(credential, tenantId, identityId?, action)`.
    async fn grant_owner(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        identity_id: Option<&str>,
        action: &str,
    ) -> IamResult<(AuthenticatedPrincipal, String)> {
        let principal = self.authenticate(credential).await?;
        let target = identity_id
            .map(str::to_owned)
            .unwrap_or_else(|| principal.identity.id.clone());
        if target != principal.identity.id || tenant_id != principal.identity.tenant_id {
            self.authorize(credential, action, resource(tenant_id, "iam", &target))
                .await?;
            let identity = self.config.store.get("identities", &target).await?;
            if !identity.is_some_and(|identity| s(&identity, "tenantId") == Some(tenant_id)) {
                return Err(IamError::with_status(
                    "NOT_FOUND",
                    "Identity not found.",
                    404,
                ));
            }
        }
        Ok((principal, target))
    }

    /// `accountGrants(tenantId, identityId)`: live grants, newest first.
    pub(crate) async fn account_grants(
        &self,
        tenant_id: &str,
        identity_id: &str,
    ) -> ProviderResult<Vec<LiveGrant>> {
        let mut live: Vec<LiveGrant> = Vec::new();
        let mut names: HashMap<String, String> = HashMap::new();
        let rows = self
            .config
            .store
            .find(
                "oauthArtifacts",
                &Filter::new()
                    .eq("model", "Grant")
                    .eq("accountId", identity_id),
                &FindOptions::default(),
            )
            .await?;
        let grants = self.adapter().model("Grant");
        for row in rows {
            let client_id = s(&row, "clientId").unwrap_or_default().to_owned();
            if s(&row, "boundTenantId") != Some(tenant_id)
                || n(&row, "expiresAt").is_none_or(|expires| expires <= js::now_ms())
                || client_id.is_empty()
            {
                continue;
            }
            let sealed = self
                .crypt()
                .open_object(s(&row, "encrypted").unwrap_or_default())?;
            let Some(jti) = s(&sealed, "jti")
                .filter(|jti| !jti.is_empty())
                .map(str::to_owned)
            else {
                continue;
            };
            let Some(payload) = grants.find(&jti).await? else {
                continue;
            };
            if !names.contains_key(&client_id) {
                let client = self
                    .config
                    .store
                    .get("oauthClients", &hash(&client_id))
                    .await?;
                let Some(client) = client.filter(|client| !truthy(client.get("revoked"))) else {
                    continue;
                };
                let name = text(self.summary(&client)?.get("name"));
                names.insert(client_id.clone(), name);
            }
            let openid = payload
                .get("openid")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let resources = payload
                .get("resources")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            let mut resource_scopes = Map::new();
            for (indicator, scope) in resources {
                let scope = match scope {
                    Value::String(text) => text,
                    other => js::stringify(&other),
                };
                resource_scopes.insert(
                    indicator,
                    json!(
                        scope
                            .split(' ')
                            .filter(|s| !s.is_empty())
                            .collect::<Vec<_>>()
                    ),
                );
            }
            let created = match payload.get("iat") {
                Some(Value::Number(iat)) => iat.as_f64().unwrap_or_default() * 1000.0,
                _ => 0.0,
            };
            let mut summary = Map::new();
            summary.insert("id".into(), row.get("id").cloned().unwrap_or(Value::Null));
            summary.insert("tenantId".into(), json!(tenant_id));
            summary.insert("identityId".into(), json!(identity_id));
            summary.insert("clientId".into(), json!(client_id));
            summary.insert(
                "clientName".into(),
                json!(names.get(&client_id).cloned().unwrap_or_default()),
            );
            summary.insert(
                "scopes".into(),
                json!(
                    text(openid.get("scope"))
                        .split(' ')
                        .filter(|s| !s.is_empty())
                        .collect::<Vec<_>>()
                ),
            );
            summary.insert(
                "claims".into(),
                openid.get("claims").cloned().unwrap_or_else(|| json!([])),
            );
            summary.insert("resources".into(), Value::Object(resource_scopes));
            summary.insert("createdAt".into(), num(created));
            summary.insert(
                "expiresAt".into(),
                row.get("expiresAt").cloned().unwrap_or(Value::Null),
            );
            live.push(LiveGrant {
                row,
                grant_id: jti,
                summary: Value::Object(summary),
            });
        }
        live.sort_by(|a, b| {
            let created = |grant: &LiveGrant| {
                grant
                    .summary
                    .get("createdAt")
                    .and_then(Value::as_f64)
                    .unwrap_or_default()
            };
            created(b).total_cmp(&created(a)).then_with(|| {
                if text(a.summary.get("id")) < text(b.summary.get("id")) {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            })
        });
        Ok(live)
    }

    async fn revoke_grant_ids(
        &self,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        revoked: &[LiveGrant],
    ) -> IamResult<()> {
        let grants = self.adapter().model("Grant");
        for grant in revoked {
            grants
                .revoke_by_grant_id(&grant.grant_id)
                .await
                .map_err(ProviderError::into_iam)?;
        }
        if revoked.is_empty() {
            return Ok(());
        }
        let actor = principal.identity.id.clone();
        let tenant = tenant_id.to_owned();
        let clients: Vec<String> = revoked
            .iter()
            .map(|grant| text(grant.summary.get("clientId")))
            .collect();
        self.config
            .store
            .transaction(move |tx| async move {
                for client in &clients {
                    Inner::audit(
                        tx.as_ref(),
                        &tenant,
                        &actor,
                        "iam:oauth:RevokeGrant",
                        client,
                    )
                    .await?;
                }
                Ok(())
            })
            .await
    }
}

impl OAuthProvider {
    /// `nodeHandler(req, res)`: the complete provider mount. Requests under the issuer path are routed relative to it,
    /// `/.well-known/oauth-authorization-server{basePath}` to the RFC 8414 metadata, and anything else as is.
    pub async fn node_handler(&self, request: &HttpRequest) -> HttpResponse {
        endpoints::handle(&self.inner, request).await
    }

    /// Whether a request belongs to the provider mount (under the issuer path, or its RFC 8414 metadata path).
    pub fn owns(&self, request: &HttpRequest) -> bool {
        let path = request.uri().path();
        path == format!("/.well-known/oauth-authorization-server{}", self.base_path)
            || (self.base_path.is_empty() || path.starts_with(&format!("{}/", self.base_path)))
    }

    /// `registerClient(credential, input)`: registers a tenant-bound client; a confidential client receives its secret
    /// once.
    pub async fn register_client(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        let empty = Map::new();
        let input_map = input.as_object().unwrap_or(&empty);
        let client_id = match input_map.get("clientId") {
            Some(Value::String(id)) if !id.is_empty() && js::utf16_len(id) <= 128 => id.clone(),
            _ => return Err(invalid_input("Invalid client configuration.")),
        };
        if !truthy(input_map.get("name")) {
            return Err(invalid_input("Invalid client configuration."));
        }
        let is_public = truthy(input_map.get("public"));
        let requested_method = input_map
            .get("tokenEndpointAuthMethod")
            .filter(|value| !value.is_null());
        let auth_method = if is_public {
            "none".to_owned()
        } else {
            match requested_method {
                Some(Value::String(method)) => method.clone(),
                Some(other) => js::stringify(other),
                None => "client_secret_basic".to_owned(),
            }
        };
        if (is_public && requested_method.is_some())
            || ![
                "none",
                "client_secret_basic",
                "client_secret_post",
                "private_key_jwt",
            ]
            .contains(&auth_method.as_str())
        {
            return Err(invalid_input("Unsupported client authentication method."));
        }
        let service_account_id = input_map
            .get("serviceAccountId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .map(str::to_owned);
        let (base, resources, first_party) =
            inner.settings(input_map, &auth_method, service_account_id.as_deref())?;
        let secret = auth_method
            .starts_with("client_secret_")
            .then(|| crate::jose::b64url(&rand::random::<[u8; 32]>()));
        let tenant_id = text(input_map.get("tenantId"));
        let mut metadata = Map::new();
        metadata.insert("client_id".into(), json!(client_id));
        metadata.insert(
            "tenant_id".into(),
            input_map.get("tenantId").cloned().unwrap_or(Value::Null),
        );
        if let Some(secret) = &secret {
            metadata.insert("client_secret".into(), json!(secret));
        }
        metadata.insert("token_endpoint_auth_method".into(), json!(auth_method));
        for (key, value) in base {
            metadata.insert(key, value);
        }
        let this = self.clone();
        let credential = credential.clone();
        let store = inner.config.store.clone();
        let id = client_id.clone();
        let tenant = tenant_id.clone();
        store
            .transaction(move |tx| async move {
                let inner = &this.inner;
                inner
                    .authorize(
                        &credential,
                        "iam:oauth:clients:create",
                        resource(&tenant, "oauth-client", &id),
                    )
                    .await?;
                let principal = inner.authenticate(&credential).await?;
                if !tenant_tree_active(tx.as_ref(), &tenant).await? {
                    return Err(IamError::with_status(
                        "TENANT_INACTIVE",
                        "Tenant is unavailable.",
                        403,
                    ));
                }
                if let Some(service_id) = &service_account_id {
                    let service = tx.get("identities", service_id).await?;
                    let usable = service.is_some_and(|service| {
                        s(&service, "kind") == Some("service")
                            && s(&service, "status") == Some("active")
                            && s(&service, "tenantId") == Some(tenant.as_str())
                    });
                    if !usable {
                        return Err(invalid_input(
                            "An active service account in the client tenant is required.",
                        ));
                    }
                }
                if tx.get("oauthClients", &hash(&id)).await?.is_some() {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "Client ID already exists; tenant binding is immutable.",
                        409,
                    ));
                }
                let now = js::now_ms();
                let mut row = Map::new();
                row.insert("id".into(), json!(hash(&id)));
                row.insert("tenantId".into(), json!(tenant));
                row.insert("clientId".into(), json!(id));
                row.insert(
                    "encrypted".into(),
                    json!(inner.crypt().seal(&Value::Object(metadata))),
                );
                row.insert("revoked".into(), json!(false));
                if let Some(service_id) = &service_account_id {
                    row.insert("serviceAccountId".into(), json!(service_id));
                }
                row.insert("resources".into(), json!(resources));
                row.insert("firstParty".into(), json!(first_party));
                row.insert("createdAt".into(), num(now));
                row.insert("updatedAt".into(), num(now));
                tx.insert("oauthClients", &row).await?;
                // `provider.Client.find`: the stored metadata must pass the client schema.
                inner
                    .core
                    .find_client(&id)
                    .await
                    .map_err(provider_to_iam_carrier)?;
                Inner::audit(
                    tx.as_ref(),
                    &tenant,
                    &principal.identity.id,
                    "iam:oauth:RegisterClient",
                    &id,
                )
                .await
            })
            .await
            .map_err(|error| iam_carrier_to_provider(error).into_iam())?;
        let mut out = Map::new();
        out.insert("clientId".into(), json!(client_id));
        if let Some(secret) = secret {
            out.insert("clientSecret".into(), json!(secret));
        }
        out.insert(
            "tenantId".into(),
            input_map.get("tenantId").cloned().unwrap_or(Value::Null),
        );
        Ok(Value::Object(out))
    }

    /// `createRegistrationToken(credential, input)`: a tenant-scoped initial access token for dynamic registration.
    pub async fn create_registration_token(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        if inner.config.registration.is_none() {
            return Err(configuration("Dynamic registration is not enabled."));
        }
        let expires_in = input
            .get("expiresIn")
            .filter(|value| !value.is_null())
            .cloned()
            .unwrap_or(json!(7 * 86400));
        let name_ok = input
            .get("name")
            .and_then(Value::as_str)
            .is_some_and(|name| !js::trim(name).is_empty() && js::utf16_len(name) <= 200);
        let expires_ok = expires_in.as_f64().is_some_and(|value| {
            js::is_safe_integer(value) && (60.0..=365.0 * 86400.0).contains(&value)
        });
        if !name_ok || !expires_ok {
            return Err(invalid_input(
                "A name and a lifetime between one minute and one year are required.",
            ));
        }
        let tenant_id = text(input.get("tenantId"));
        let policy = RegistrationPolicy {
            tenant_id: tenant_id.clone(),
            scopes: strings_of(input.get("scopes")),
            resources: strings_of(input.get("resources")),
            allow_confidential: input.get("allowConfidential") == Some(&Value::Bool(true)),
            max_clients: Some(
                input
                    .get("maxClients")
                    .filter(|v| !v.is_null())
                    .map(js::to_number)
                    .unwrap_or(1.0),
            ),
        };
        let limits = inner
            .registration_limits(&policy)
            .map_err(|_| invalid_input("Unsupported scopes, resources, or client limit."))?;
        inner
            .authorize(
                credential,
                "iam:oauth:clients:create",
                resource(&tenant_id, "oauth-client", "*"),
            )
            .await?;
        let principal = inner.authenticate(credential).await?;
        let token = crate::jose::b64url(&rand::random::<[u8; 32]>());
        let now = js::now_ms();
        let mut record = Map::new();
        record.insert("id".into(), json!(hash(&token)));
        record.insert("tenantId".into(), json!(tenant_id));
        record.insert("name".into(), json!(js::trim(&text(input.get("name")))));
        record.insert("scopes".into(), json!(limits.scopes));
        record.insert("resources".into(), json!(limits.resources));
        record.insert("allowConfidential".into(), json!(limits.allow_confidential));
        record.insert("maxClients".into(), num(limits.max_clients));
        record.insert("used".into(), json!(0));
        record.insert("createdBy".into(), json!(principal.identity.id));
        record.insert("createdAt".into(), num(now));
        record.insert(
            "expiresAt".into(),
            num(now + expires_in.as_f64().unwrap_or_default() * 1000.0),
        );
        record.insert("revoked".into(), json!(false));
        let stored = record.clone();
        let actor = principal.identity.id.clone();
        inner
            .config
            .store
            .transaction(move |tx| async move {
                if !tenant_tree_active(tx.as_ref(), &tenant_id).await? {
                    return Err(IamError::with_status(
                        "TENANT_INACTIVE",
                        "Tenant is unavailable.",
                        403,
                    ));
                }
                tx.insert("oauthRegistrationTokens", &stored).await?;
                Inner::audit(
                    tx.as_ref(),
                    &tenant_id,
                    &actor,
                    "iam:oauth:CreateRegistrationToken",
                    s(&stored, "id").unwrap_or_default(),
                )
                .await
            })
            .await?;
        let mut out = Inner::registration_token_summary(&record)
            .as_object()
            .cloned()
            .unwrap_or_default();
        out.insert("token".into(), json!(token));
        Ok(Value::Object(out))
    }

    /// `listRegistrationTokens(credential, { tenantId })`.
    pub async fn list_registration_tokens(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Vec<Value>> {
        let tenant_id = text(input.get("tenantId"));
        self.inner
            .authorize(
                credential,
                "iam:oauth:clients:read",
                resource(&tenant_id, "oauth-client", "*"),
            )
            .await?;
        let mut records = self
            .inner
            .config
            .store
            .find(
                "oauthRegistrationTokens",
                &Filter::new().eq("tenantId", tenant_id),
                &FindOptions::default(),
            )
            .await?;
        records.sort_by(|a, b| {
            n(b, "createdAt")
                .unwrap_or_default()
                .total_cmp(&n(a, "createdAt").unwrap_or_default())
                .then_with(|| {
                    if s(a, "id") < s(b, "id") {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    }
                })
        });
        Ok(records
            .iter()
            .map(Inner::registration_token_summary)
            .collect())
    }

    /// `revokeRegistrationToken(credential, { tenantId, tokenId })`.
    pub async fn revoke_registration_token(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<()> {
        let tenant_id = text(input.get("tenantId"));
        self.inner
            .authorize(
                credential,
                "iam:oauth:clients:delete",
                resource(&tenant_id, "oauth-client", "*"),
            )
            .await?;
        let principal = self.inner.authenticate(credential).await?;
        let token_id = input
            .get("tokenId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        self.inner
            .config
            .store
            .transaction(move |tx| async move {
                let hex = regex::Regex::new("^[0-9a-f]{64}$").expect("valid regex");
                let record = match &token_id {
                    Some(id) if hex.is_match(id) => tx.get("oauthRegistrationTokens", id).await?,
                    _ => None,
                };
                let Some(mut record) =
                    record.filter(|record| s(record, "tenantId") == Some(tenant_id.as_str()))
                else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Registration token not found.",
                        404,
                    ));
                };
                record.insert("revoked".into(), json!(true));
                tx.put("oauthRegistrationTokens", &record).await?;
                Inner::audit(
                    tx.as_ref(),
                    &tenant_id,
                    &principal.identity.id,
                    "iam:oauth:RevokeRegistrationToken",
                    s(&record, "id").unwrap_or_default(),
                )
                .await
            })
            .await
    }

    /// `listClients(credential, { tenantId, includeRevoked })`: clients the caller may read.
    pub async fn list_clients(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Vec<Value>> {
        let inner = &self.inner;
        inner.authenticate(credential).await?;
        let tenant_id = text(input.get("tenantId"));
        let include_revoked = truthy(input.get("includeRevoked"));
        let mut visible = Vec::new();
        for row in inner
            .config
            .store
            .find(
                "oauthClients",
                &Filter::new().eq(
                    "tenantId",
                    input.get("tenantId").cloned().unwrap_or(Value::Null),
                ),
                &FindOptions::default(),
            )
            .await?
        {
            if truthy(row.get("revoked")) && !include_revoked {
                continue;
            }
            match inner
                .authorize(
                    credential,
                    "iam:oauth:clients:read",
                    resource(
                        &tenant_id,
                        "oauth-client",
                        s(&row, "clientId").unwrap_or_default(),
                    ),
                )
                .await
            {
                Ok(()) => {}
                Err(error) if error.status == 403 || error.status == 404 => continue,
                Err(error) => return Err(error),
            }
            visible.push(inner.summary(&row)?);
        }
        visible.sort_by(|a, b| {
            if text(a.get("clientId")) < text(b.get("clientId")) {
                std::cmp::Ordering::Less
            } else {
                std::cmp::Ordering::Greater
            }
        });
        Ok(visible)
    }

    /// `getClient(credential, { tenantId, clientId })`.
    pub async fn get_client(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let tenant_id = text(input.get("tenantId"));
        let client_id = text(input.get("clientId"));
        self.inner
            .authorize(
                credential,
                "iam:oauth:clients:read",
                resource(&tenant_id, "oauth-client", &client_id),
            )
            .await?;
        let row =
            Inner::tenant_client(self.inner.config.store.as_ref(), &tenant_id, &client_id).await?;
        self.inner.summary(&row)
    }

    /// `updateClient(credential, input)`: changes client settings; narrowing revokes every outstanding artifact.
    pub async fn update_client(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let this = self.clone();
        let credential = credential.clone();
        let input = input.as_object().cloned().unwrap_or_default();
        self.inner
            .config
            .store
            .transaction(move |tx| async move {
                let inner = &this.inner;
                let tenant_id = text(input.get("tenantId"));
                let client_id = text(input.get("clientId"));
                inner
                    .authorize(
                        &credential,
                        "iam:oauth:clients:update",
                        resource(&tenant_id, "oauth-client", &client_id),
                    )
                    .await?;
                let principal = inner.authenticate(&credential).await?;
                let row = Inner::tenant_client(tx.as_ref(), &tenant_id, &client_id).await?;
                if truthy(row.get("revoked")) {
                    return Err(IamError::with_status(
                        "OAUTH_CLIENT",
                        "Client is unavailable.",
                        404,
                    ));
                }
                let current = inner.summary(&row)?;
                let pick = |key: &str| -> Value {
                    match input.get(key) {
                        Some(value) if !value.is_null() => value.clone(),
                        _ => current.get(key).cloned().unwrap_or(Value::Null),
                    }
                };
                let nullable = |key: &str| -> Value {
                    match input.get(key) {
                        Some(Value::Null) => Value::Null,
                        Some(value) => value.clone(),
                        None => current.get(key).cloned().unwrap_or(Value::Null),
                    }
                };
                let mut next = Map::new();
                for key in [
                    "name",
                    "redirectUris",
                    "postLogoutRedirectUris",
                    "grantTypes",
                    "scopes",
                    "resources",
                    "requireDpop",
                    "requirePushedAuthorization",
                ] {
                    next.insert(key.into(), pick(key));
                }
                for key in [
                    "backchannelLogoutUri",
                    "accessTokenTtl",
                    "refreshTokenTtl",
                    "logoUri",
                    "clientUri",
                    "policyUri",
                    "tosUri",
                ] {
                    let value = nullable(key);
                    if !value.is_null() {
                        next.insert(key.into(), value);
                    }
                }
                next.insert("firstParty".into(), pick("firstParty"));
                let previous = inner
                    .crypt()
                    .open_object(s(&row, "encrypted").unwrap_or_default())?;
                // Signing keys: new inline keys or a new URL replace whichever the client had.
                if let Some(jwks) = input.get("jwks").filter(|v| !v.is_null()) {
                    next.insert("jwks".into(), jwks.clone());
                } else if let Some(uri) = input.get("jwksUri").filter(|v| !v.is_null()) {
                    next.insert("jwksUri".into(), uri.clone());
                } else if truthy(previous.get("jwks")) {
                    next.insert("jwks".into(), previous["jwks"].clone());
                } else if truthy(previous.get("jwks_uri")) {
                    next.insert("jwksUri".into(), previous["jwks_uri"].clone());
                }
                let method = text(current.get("tokenEndpointAuthMethod"));
                let (base, resources, first_party) =
                    inner.settings(&next, &method, s(&row, "serviceAccountId"))?;
                let mut metadata = Map::new();
                for key in [
                    "client_id",
                    "tenant_id",
                    "client_secret",
                    "token_endpoint_auth_method",
                ] {
                    if let Some(value) = previous.get(key) {
                        metadata.insert(key.into(), value.clone());
                    }
                }
                for (key, value) in base {
                    metadata.insert(key, value);
                }
                let narrowed = |before: Option<&Value>, after: &[String]| {
                    before.and_then(Value::as_array).is_some_and(|values| {
                        values.iter().any(|value| {
                            !value
                                .as_str()
                                .is_some_and(|value| after.iter().any(|a| a == value))
                        })
                    })
                };
                let next_grants = strings_of(next.get("grantTypes")).unwrap_or_default();
                let next_scopes = strings_of(next.get("scopes")).unwrap_or_default();
                let tokens_revoked = narrowed(current.get("grantTypes"), &next_grants)
                    || narrowed(current.get("scopes"), &next_scopes)
                    || narrowed(current.get("resources"), &resources)
                    || (current.get("requireDpop") != Some(&Value::Bool(true))
                        && next.get("requireDpop") == Some(&Value::Bool(true)));
                let mut updated = row.clone();
                updated.insert(
                    "encrypted".into(),
                    json!(inner.crypt().seal(&Value::Object(metadata))),
                );
                updated.insert("resources".into(), json!(resources));
                updated.insert("firstParty".into(), json!(first_party));
                updated.insert("updatedAt".into(), num(js::now_ms()));
                tx.put("oauthClients", &updated).await?;
                if tokens_revoked {
                    Inner::purge_client_artifacts(
                        tx.as_ref(),
                        s(&row, "clientId").unwrap_or_default(),
                    )
                    .await?;
                }
                Inner::audit(
                    tx.as_ref(),
                    &tenant_id,
                    &principal.identity.id,
                    "iam:oauth:UpdateClient",
                    &client_id,
                )
                .await?;
                let stored = tx
                    .get("oauthClients", s(&row, "id").unwrap_or_default())
                    .await?
                    .unwrap_or(updated);
                let mut out = inner
                    .summary(&stored)?
                    .as_object()
                    .cloned()
                    .unwrap_or_default();
                out.insert("tokensRevoked".into(), json!(tokens_revoked));
                Ok(Value::Object(out))
            })
            .await
    }

    /// `rotateClientSecret(credential, { tenantId, clientId, revokeTokens })`.
    pub async fn rotate_client_secret(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let secret = crate::jose::b64url(&rand::random::<[u8; 32]>());
        let tenant_id = text(input.get("tenantId"));
        let client_id = text(input.get("clientId"));
        let revoke_tokens = truthy(input.get("revokeTokens"));
        let this = self.clone();
        let credential = credential.clone();
        let new_secret = secret.clone();
        let (tenant, client) = (tenant_id.clone(), client_id.clone());
        self.inner
            .config
            .store
            .transaction(move |tx| async move {
                let inner = &this.inner;
                inner
                    .authorize(
                        &credential,
                        "iam:oauth:clients:update",
                        resource(&tenant, "oauth-client", &client),
                    )
                    .await?;
                let principal = inner.authenticate(&credential).await?;
                let row = Inner::tenant_client(tx.as_ref(), &tenant, &client).await?;
                if truthy(row.get("revoked")) {
                    return Err(IamError::with_status(
                        "OAUTH_CLIENT",
                        "Client is unavailable.",
                        404,
                    ));
                }
                let mut metadata = inner
                    .crypt()
                    .open_object(s(&row, "encrypted").unwrap_or_default())?;
                let method = match metadata.get("token_endpoint_auth_method") {
                    Some(Value::String(method)) => method.clone(),
                    Some(other) => js::stringify(other),
                    None => "undefined".to_owned(),
                };
                if !method.starts_with("client_secret_") {
                    return Err(invalid_input(
                        "Only secret-authenticated clients have a secret.",
                    ));
                }
                metadata.insert("client_secret".into(), json!(new_secret));
                let now = js::now_ms();
                let mut updated = row.clone();
                updated.insert(
                    "encrypted".into(),
                    json!(inner.crypt().seal(&Value::Object(metadata))),
                );
                updated.insert("updatedAt".into(), num(now));
                updated.insert("secretRotatedAt".into(), num(now));
                tx.put("oauthClients", &updated).await?;
                if revoke_tokens {
                    Inner::purge_client_artifacts(
                        tx.as_ref(),
                        s(&row, "clientId").unwrap_or_default(),
                    )
                    .await?;
                }
                Inner::audit(
                    tx.as_ref(),
                    &tenant,
                    &principal.identity.id,
                    "iam:oauth:RotateClientSecret",
                    &client,
                )
                .await
            })
            .await?;
        Ok(json!({ "clientId": client_id, "clientSecret": secret, "tenantId": tenant_id }))
    }

    /// `revokeClient(credential, { tenantId, clientId })`.
    pub async fn revoke_client(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<()> {
        let tenant_id = text(input.get("tenantId"));
        let client_id = text(input.get("clientId"));
        let this = self.clone();
        let credential = credential.clone();
        self.inner
            .config
            .store
            .transaction(move |tx| async move {
                let inner = &this.inner;
                inner
                    .authorize(
                        &credential,
                        "iam:oauth:clients:delete",
                        resource(&tenant_id, "oauth-client", &client_id),
                    )
                    .await?;
                let principal = inner.authenticate(&credential).await?;
                let mut row = inner.client_row(&client_id).await?;
                if s(&row, "tenantId") != Some(tenant_id.as_str()) {
                    return Err(IamError::with_status("NOT_FOUND", "Client not found.", 404));
                }
                row.insert("revoked".into(), json!(true));
                row.insert("updatedAt".into(), num(js::now_ms()));
                tx.put("oauthClients", &row).await?;
                Inner::purge_client_artifacts(tx.as_ref(), &client_id).await?;
                Inner::audit(
                    tx.as_ref(),
                    &tenant_id,
                    &principal.identity.id,
                    "iam:oauth:RevokeClient",
                    &client_id,
                )
                .await
            })
            .await
    }

    /// `listGrants(credential, { tenantId, identityId?, clientId? })`: connected apps.
    pub async fn list_grants(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Vec<Value>> {
        let tenant_id = text(input.get("tenantId"));
        let identity_id = input
            .get("identityId")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty());
        let (_, owner) = self
            .inner
            .grant_owner(credential, &tenant_id, identity_id, "iam:oauth:grants:read")
            .await?;
        let client_id = input
            .get("clientId")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty());
        Ok(self
            .inner
            .account_grants(&tenant_id, &owner)
            .await
            .map_err(ProviderError::into_iam)?
            .into_iter()
            .map(|grant| grant.summary)
            .filter(|summary| {
                client_id.is_none_or(|client| {
                    summary.get("clientId").and_then(Value::as_str) == Some(client)
                })
            })
            .collect())
    }

    /// `revokeGrant(credential, { tenantId, grantId })`: one consent by its summary ID.
    pub async fn revoke_grant(&self, credential: &CredentialInput, input: &Value) -> IamResult<()> {
        let inner = &self.inner;
        let tenant_id = text(input.get("tenantId"));
        let grant_id = input
            .get("grantId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let hex = regex::Regex::new("^[0-9a-f]{64}$").expect("valid regex");
        let row = match &grant_id {
            Some(id) if hex.is_match(id) => inner.config.store.get("oauthArtifacts", id).await?,
            _ => None,
        };
        let principal = inner.authenticate(credential).await?;
        let identity_id = row
            .as_ref()
            .filter(|row| {
                s(row, "model") == Some("Grant")
                    && s(row, "boundTenantId") == Some(tenant_id.as_str())
            })
            .and_then(|row| s(row, "accountId"))
            .map(str::to_owned);
        // Unknown references and foreign grants look the same; authorization runs before disclosure.
        let (owner_principal, owner) = inner
            .grant_owner(
                credential,
                &tenant_id,
                Some(identity_id.as_deref().unwrap_or(&principal.identity.id)),
                "iam:oauth:grants:revoke",
            )
            .await?;
        let grant = if identity_id.is_some() {
            inner
                .account_grants(&tenant_id, &owner)
                .await
                .map_err(ProviderError::into_iam)?
                .into_iter()
                .find(|candidate| s(&candidate.row, "id") == grant_id.as_deref())
        } else {
            None
        };
        let Some(grant) = grant else {
            return Err(IamError::with_status("NOT_FOUND", "Grant not found.", 404));
        };
        inner
            .revoke_grant_ids(&owner_principal, &tenant_id, &[grant])
            .await
    }

    /// `revokeGrants(credential, { tenantId, identityId?, clientId? })`: disconnects apps.
    pub async fn revoke_grants(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> IamResult<Value> {
        let inner = &self.inner;
        let tenant_id = text(input.get("tenantId"));
        let identity_id = input
            .get("identityId")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty());
        let (principal, owner) = inner
            .grant_owner(
                credential,
                &tenant_id,
                identity_id,
                "iam:oauth:grants:revoke",
            )
            .await?;
        let client_id = input
            .get("clientId")
            .and_then(Value::as_str)
            .filter(|v| !v.is_empty());
        let matching: Vec<LiveGrant> = inner
            .account_grants(&tenant_id, &owner)
            .await
            .map_err(ProviderError::into_iam)?
            .into_iter()
            .filter(|grant| {
                client_id.is_none_or(|client| {
                    grant.summary.get("clientId").and_then(Value::as_str) == Some(client)
                })
            })
            .collect();
        inner
            .revoke_grant_ids(&principal, &tenant_id, &matching)
            .await?;
        Ok(json!({ "revoked": matching.len() }))
    }

    /// `logoutEndedSessions({ identityId? })`: OpenID back-channel logout for ended IAM sessions.
    pub async fn logout_ended_sessions(&self, identity_id: Option<&str>) -> IamResult<Value> {
        let inner = &self.inner;
        let store = inner.config.store.as_ref();
        let filter = match identity_id {
            Some(id) => Filter::new().eq("identityId", id),
            None => Filter::new(),
        };
        let bindings = store
            .find("oauthGrantSessions", &filter, &FindOptions::default())
            .await?;
        let mut ended: IndexMap<String, Record> = IndexMap::new();
        let mut session_ended: HashMap<String, bool> = HashMap::new();
        for binding in bindings {
            let session_id = s(&binding, "sessionId").unwrap_or_default().to_owned();
            if !session_ended.contains_key(&session_id) {
                let session = store.get("sessions", &session_id).await?;
                let identity = store
                    .get("identities", s(&binding, "identityId").unwrap_or_default())
                    .await?;
                let mut live = match (&session, &identity) {
                    (Some(session), Some(identity)) => {
                        s(session, "identityId") == s(&binding, "identityId")
                            && s(session, "tenantId") == s(&binding, "tenantId")
                            && n(session, "expiresAt").is_some_and(|expires| expires > js::now_ms())
                            && s(identity, "status") == Some("active")
                            && tenant_tree_active(
                                store,
                                s(&binding, "tenantId").unwrap_or_default(),
                            )
                            .await?
                    }
                    _ => false,
                };
                if live && let Some(validate) = &inner.config.validate_session {
                    live = validate(session_id.clone()).await.is_ok();
                }
                session_ended.insert(session_id.clone(), !live);
            }
            if session_ended.get(&session_id).copied().unwrap_or(false) {
                ended.insert(s(&binding, "id").unwrap_or_default().to_owned(), binding);
            }
        }
        if ended.is_empty() {
            return Ok(json!({ "sessions": 0, "grants": 0, "notified": 0, "failures": [] }));
        }
        // Grant artifacts are keyed by their own hash; match them to bindings through the sealed grant ID.
        let mut revoked: Vec<(String, String, Record)> = Vec::new();
        let mut identities: Vec<String> = Vec::new();
        for binding in ended.values() {
            let id = s(binding, "identityId").unwrap_or_default().to_owned();
            if !identities.contains(&id) {
                identities.push(id);
            }
        }
        for identity in &identities {
            for row in store
                .find(
                    "oauthArtifacts",
                    &Filter::new()
                        .eq("model", "Grant")
                        .eq("accountId", identity.clone()),
                    &FindOptions::default(),
                )
                .await?
            {
                let sealed = inner
                    .crypt()
                    .open_object(s(&row, "encrypted").unwrap_or_default())?;
                let Some(jti) = s(&sealed, "jti").filter(|jti| !jti.is_empty()) else {
                    continue;
                };
                if let Some(binding) = ended.get(&hash(jti))
                    && let Some(client_id) = s(&row, "clientId").filter(|id| !id.is_empty())
                {
                    revoked.push((jti.to_owned(), client_id.to_owned(), binding.clone()));
                }
            }
        }
        let mut notified = 0;
        let mut failures: Vec<Value> = Vec::new();
        let mut informed: Vec<(String, String)> = Vec::new();
        for (_, client_id, binding) in &revoked {
            let identity = s(binding, "identityId").unwrap_or_default().to_owned();
            let key = (client_id.clone(), identity.clone());
            if informed.contains(&key) {
                continue;
            }
            informed.push(key);
            let client = inner.core.find_client(client_id).await.ok().flatten();
            let Some(client) = client.filter(|client| client.backchannel_logout_uri().is_some())
            else {
                continue;
            };
            match endpoints::backchannel_logout(inner, &client, &identity, "").await {
                Ok(()) => notified += 1,
                Err(_) => failures.push(json!({ "clientId": client_id, "identityId": identity })),
            }
        }
        let grants = inner.adapter().model("Grant");
        for (grant_id, _, _) in &revoked {
            grants
                .revoke_by_grant_id(grant_id)
                .await
                .map_err(ProviderError::into_iam)?;
        }
        let ended_bindings: Vec<Record> = ended.values().cloned().collect();
        let informed_pairs = informed.clone();
        inner
            .config
            .store
            .transaction(move |tx| async move {
                for binding in &ended_bindings {
                    tx.delete("oauthGrantSessions", s(binding, "id").unwrap_or_default())
                        .await?;
                }
                for (client_id, identity_id) in &informed_pairs {
                    let binding = ended_bindings
                        .iter()
                        .find(|binding| s(binding, "identityId") == Some(identity_id.as_str()))
                        .cloned()
                        .unwrap_or_default();
                    Inner::audit(
                        tx.as_ref(),
                        s(&binding, "tenantId").unwrap_or_default(),
                        identity_id,
                        "iam:oauth:SessionLogout",
                        client_id,
                    )
                    .await?;
                }
                Ok(())
            })
            .await?;
        let mut sessions: Vec<String> = Vec::new();
        for binding in ended.values() {
            let id = s(binding, "sessionId").unwrap_or_default().to_owned();
            if !sessions.contains(&id) {
                sessions.push(id);
            }
        }
        Ok(json!({
            "sessions": sessions.len(),
            "grants": revoked.len(),
            "notified": notified,
            "failures": failures,
        }))
    }

    /// `interactionDetails(req, res)`: the immutable tenant/client binding of a pending interaction.
    pub async fn interaction_details(&self, request: &HttpRequest) -> IamResult<Value> {
        let inner = &self.inner;
        let details = endpoints::get_interaction(inner, request)
            .await
            .map_err(ProviderError::into_iam)?;
        let params = details
            .get("params")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let client_id = match params.get("client_id") {
            Some(Value::String(id)) => id.clone(),
            Some(other) => js::stringify(other),
            None => "undefined".to_owned(),
        };
        let row = inner.client_row(&client_id).await?;
        let summary = inner.summary(&row)?;
        let mut client = Map::new();
        client.insert(
            "name".into(),
            summary.get("name").cloned().unwrap_or(Value::Null),
        );
        for key in ["logoUri", "clientUri", "policyUri", "tosUri"] {
            if truthy(summary.get(key)) {
                client.insert(key.into(), summary[key].clone());
            }
        }
        client.insert(
            "firstParty".into(),
            summary.get("firstParty").cloned().unwrap_or(json!(false)),
        );
        let resources: Vec<Value> = match params.get("resource") {
            Some(Value::Array(values)) => values
                .iter()
                .map(|value| {
                    json!(match value {
                        Value::String(text) => text.clone(),
                        other => js::stringify(other),
                    })
                })
                .collect(),
            Some(value) if truthy(Some(value)) => vec![json!(match value {
                Value::String(text) => text.clone(),
                other => js::stringify(other),
            })],
            _ => Vec::new(),
        };
        let prompt = details
            .get("prompt")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let mut out = Map::new();
        out.insert(
            "uid".into(),
            details.get("jti").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "prompt".into(),
            prompt.get("name").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "tenantId".into(),
            row.get("tenantId").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "clientId".into(),
            row.get("clientId").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "clientName".into(),
            summary.get("name").cloned().unwrap_or(Value::Null),
        );
        out.insert("client".into(), Value::Object(client));
        out.insert(
            "scopes".into(),
            match params.get("scope") {
                Some(Value::String(scope)) => json!(scope.split(' ').collect::<Vec<_>>()),
                _ => json!([]),
            },
        );
        out.insert("resources".into(), Value::Array(resources));
        out.insert(
            "details".into(),
            prompt.get("details").cloned().unwrap_or_else(|| json!({})),
        );
        Ok(Value::Object(out))
    }

    /// `completeInteraction(req, res, { credential, consent })`: finishes the pending interaction with the caller's
    /// IAM session; answers the 303 redirect back to the authorization flow.
    pub async fn complete_interaction(
        &self,
        request: &HttpRequest,
        credential: &CredentialInput,
        consent: bool,
    ) -> IamResult<HttpResponse> {
        let inner = &self.inner;
        let origin = request
            .headers()
            .get("origin")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if request.method() != ::http::Method::POST
            || origin.is_empty()
            || !inner
                .config
                .trusted_origins
                .iter()
                .any(|trusted| trusted == origin)
        {
            return Err(IamError::with_status(
                "CSRF",
                "A trusted Origin is required.",
                403,
            ));
        }
        let this = self.clone();
        let credential = credential.clone();
        let request = request.clone();
        inner
            .config
            .store
            .transaction(move |tx| async move {
                let inner = &this.inner;
                let principal = inner.authenticate(&credential).await?;
                if principal.session.kind != SessionKind::User {
                    return Err(IamError::with_status("INVALID_SESSION", "A user session is required.", 403));
                }
                if principal.session.impersonator_id.is_some() {
                    return Err(IamError::with_status(
                        "IMPERSONATION_RESTRICTED",
                        "Consent cannot be granted while impersonating a member.",
                        403,
                    ));
                }
                let mut interaction = endpoints::get_interaction(inner, &request).await.map_err(provider_to_iam_carrier)?;
                let params = interaction.get("params").and_then(Value::as_object).cloned().unwrap_or_default();
                let client_id = match params.get("client_id") {
                    Some(Value::String(id)) => id.clone(),
                    Some(other) => js::stringify(other),
                    None => "undefined".to_owned(),
                };
                let client = inner.client_row(&client_id).await?;
                if s(&client, "tenantId") != Some(principal.identity.tenant_id.as_str()) {
                    return Err(IamError::with_status(
                        "TENANT_MISMATCH",
                        "Sign in to the client tenant before continuing.",
                        403,
                    ));
                }
                if !consent {
                    let result = json!({ "error": "access_denied", "error_description": "Consent denied." });
                    return endpoints::interaction_finished(inner, &mut interaction, result)
                        .await
                        .map_err(provider_to_iam_carrier);
                }
                // `prompt=login` and `max_age` are judged here against the session's own sign-in time.
                let max_age = match params.get("max_age") {
                    Some(Value::String(text)) => Some(js::string_to_number(text)),
                    Some(Value::Number(number)) => number.as_f64(),
                    _ => None,
                };
                let started = match interaction.get("iat") {
                    Some(Value::Number(iat)) => (iat.as_f64().unwrap_or_default() + 1.0) * 1000.0,
                    _ => js::now_ms(),
                };
                let prompt_login = text(params.get("prompt")).split(' ').any(|value| value == "login");
                if max_age.is_some_and(|max_age| {
                    max_age.is_finite() && js::now_ms() - principal.session.authenticated_at > max_age * 1000.0
                }) || (prompt_login && principal.session.authenticated_at < started)
                {
                    return Err(IamError::with_status(
                        "LOGIN_REQUIRED",
                        "The application asked for a fresh sign-in: sign in again, then continue.",
                        401,
                    ));
                }
                // Extend the account's existing consent for this client instead of accumulating grants.
                let existing = match interaction.get("grantId").and_then(Value::as_str).filter(|id| !id.is_empty()) {
                    Some(id) => endpoints::find_grant(inner, id).await.map_err(provider_to_iam_carrier)?,
                    None => None,
                };
                let client_id = s(&client, "clientId").unwrap_or_default().to_owned();
                let mut grant = match existing {
                    Some(existing)
                        if s(&existing, "accountId") == Some(principal.identity.id.as_str())
                            && s(&existing, "clientId") == Some(client_id.as_str()) =>
                    {
                        existing
                    }
                    _ => {
                        let mut fresh = Map::new();
                        fresh.insert("accountId".into(), json!(principal.identity.id));
                        fresh.insert("clientId".into(), json!(client_id));
                        fresh
                    }
                };
                let scope = match params.get("scope") {
                    Some(Value::String(scope)) => scope.clone(),
                    Some(Value::Null) | None => "openid".to_owned(),
                    Some(other) => js::stringify(other),
                };
                grant_ops::add_oidc_scope(&mut grant, &scope);
                let prompt_details = interaction
                    .get("prompt")
                    .and_then(|prompt| prompt.get("details"))
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                if let Some(Value::Array(missing)) = prompt_details.get("missingOIDCClaims") {
                    let claims: Vec<String> = missing.iter().filter_map(Value::as_str).map(str::to_owned).collect();
                    grant_ops::add_oidc_claims(&mut grant, &claims);
                }
                // Requested resources receive the requested scopes their resource server defines.
                let requested_scopes: Vec<String> = text(params.get("scope")).split(' ').map(str::to_owned).collect();
                let requested_resources: Vec<String> = match params.get("resource") {
                    Some(Value::Array(values)) => values
                        .iter()
                        .map(|value| match value {
                            Value::String(text) => text.clone(),
                            other => js::stringify(other),
                        })
                        .collect(),
                    Some(value) if truthy(Some(value)) => vec![match value {
                        Value::String(text) => text.clone(),
                        other => js::stringify(other),
                    }],
                    _ => Vec::new(),
                };
                let client_resources: Vec<String> = strings_of(client.get("resources")).unwrap_or_default();
                for indicator in requested_resources {
                    let Some(server) = inner.core.resource_servers.get(&indicator) else {
                        continue;
                    };
                    let scopes: Vec<String> = server.scopes.iter().filter(|scope| requested_scopes.contains(scope)).cloned().collect();
                    if client_resources.contains(&indicator) && !scopes.is_empty() {
                        grant_ops::add_resource_scope(&mut grant, &indicator, &scopes);
                    }
                }
                if let Some(Value::Object(missing)) = prompt_details.get("missingResourceScopes") {
                    for (indicator, scopes) in missing {
                        if let Value::Array(scopes) = scopes {
                            let scopes: Vec<String> = scopes.iter().filter_map(Value::as_str).map(str::to_owned).collect();
                            grant_ops::add_resource_scope(&mut grant, indicator, &scopes);
                        }
                    }
                }
                let grant_id = endpoints::save_grant(inner, &mut grant).await.map_err(provider_to_iam_carrier)?;
                let mut binding = Map::new();
                binding.insert("id".into(), json!(hash(&grant_id)));
                binding.insert("tenantId".into(), json!(principal.identity.tenant_id));
                binding.insert("sessionId".into(), json!(principal.session.id));
                binding.insert("identityId".into(), json!(principal.identity.id));
                if tx.get("oauthGrantSessions", &hash(&grant_id)).await?.is_some() {
                    tx.put("oauthGrantSessions", &binding).await?;
                } else {
                    tx.insert("oauthGrantSessions", &binding).await?;
                }
                Inner::audit(tx.as_ref(), &principal.identity.tenant_id, &principal.identity.id, "iam:oauth:Consent", &client_id).await?;
                let result = json!({
                    "login": {
                        "accountId": principal.identity.id,
                        "ts": (principal.session.authenticated_at / 1000.0).floor() as i64,
                        "amr": if principal.session.mfa { json!(["pwd", "mfa"]) } else { json!(["pwd"]) },
                    },
                    "consent": { "grantId": grant_id },
                });
                endpoints::interaction_finished(inner, &mut interaction, result)
                    .await
                    .map_err(provider_to_iam_carrier)
            })
            .await
            .map_err(|error| iam_carrier_to_provider(error).into_iam())
    }
}
