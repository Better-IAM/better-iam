//! Port of `packages/saml/src/index.ts`: SAML 2.0 single sign-on with configured and tenant-managed
//! service-provider connections, the shared replay cache, the response envelope checks, and the HTTP handler (login
//! redirect, ACS, metadata).

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, LazyLock};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError, IamResult, IamStore,
    IamStoreExt, Record, ResourceRef, SessionKind, append_audit_event, js, tenant_tree_active,
};
use bytes::Bytes;
use indexmap::IndexMap;
use rand::RngCore;
use regex::Regex;
use serde_json::{Map, Value, json};

use crate::keys::{SamlError, SamlResult, base64_decode, sha256_hex, timing_safe_equal};
use crate::metadata::{certificate_info, normalize_certificate, parse_idp_metadata};
use crate::node_saml::{CacheProvider, Profile, Saml, SamlOptions, ValidateInResponseTo};
use crate::xml::Document;

/// A boxed future of the host callbacks.
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
/// `mapAttributes(profile)`: identity attributes from the validated assertion; None leaves them untouched.
pub type MapAttributes = Arc<dyn Fn(&Profile) -> Option<Map<String, Value>> + Send + Sync>;
/// `authorize(credential, action, resource)`.
pub type AuthorizeFn =
    Arc<dyn Fn(CredentialInput, String, ResourceRef) -> BoxFuture<IamResult<()>> + Send + Sync>;
/// `authenticate(credential)`.
pub type AuthenticateFn =
    Arc<dyn Fn(CredentialInput) -> BoxFuture<IamResult<AuthenticatedPrincipal>> + Send + Sync>;
/// `completeAuthentication(input)`: the federated sign-in (`{ tenantId, providerId, issuer, subject, ... }`).
pub type CompleteAuthenticationFn = Arc<dyn Fn(Value) -> BoxFuture<IamResult<Value>> + Send + Sync>;
/// `assertTrustChange(credential, { tenantId, providerId })`.
pub type AssertTrustChangeFn =
    Arc<dyn Fn(CredentialInput, String, String) -> BoxFuture<IamResult<()>> + Send + Sync>;
/// `revokeSession(credential)`.
pub type RevokeSessionFn =
    Arc<dyn Fn(CredentialInput) -> BoxFuture<IamResult<Value>> + Send + Sync>;

/// An HTTP request the handler reads.
pub type HttpRequest = http::Request<Bytes>;
/// An HTTP response the handler answers.
pub type HttpResponse = http::Response<Bytes>;

/// `SamlConnection`: a connection fixed in deployment configuration (or a tenant-managed one, as `connection(id)`
/// resolves it).
#[derive(Clone, Default)]
pub struct SamlConnection {
    pub id: String,
    /// The provider key accounts linked through this connection are stored under (default: `id`).
    pub provider_id: Option<String>,
    pub tenant_id: String,
    pub entry_point: String,
    pub idp_issuer: String,
    pub idp_certificates: Vec<String>,
    pub entity_id: String,
    pub callback_url: String,
    pub private_key: String,
    pub public_certificate: String,
    pub decryption_private_key: Option<String>,
    pub decryption_certificate: Option<String>,
    pub require_encrypted_assertions: bool,
    /// Domains whose email attributes this administrator-configured IdP is trusted to verify.
    pub trusted_email_domains: Option<Vec<String>>,
    /// Accept IdP-initiated (unsolicited) sign-in at the callback URL; each assertion is accepted once.
    pub allow_idp_initiated: bool,
    /// `true`, or a list of SCIM connection IDs (JSON, validated as TypeScript validates it).
    pub trust_scim_provisioned: Option<Value>,
    pub map_attributes: Option<MapAttributes>,
}

/// The deployment's own SAML service-provider identity, shared by every tenant-managed connection.
#[derive(Debug, Clone, Default)]
pub struct SamlServiceProvider {
    /// Public HTTPS origin (and optional path prefix) the SAML routes are served from.
    pub base_url: String,
    pub private_key: String,
    pub public_certificate: String,
    pub decryption_private_key: Option<String>,
    pub decryption_certificate: Option<String>,
}

/// `SamlConfigOptions`.
#[derive(Clone)]
pub struct SamlConfigOptions {
    pub store: Arc<dyn IamStore>,
    /// Connections fixed in deployment configuration. Tenant-managed connections live in the database.
    pub connections: Vec<SamlConnection>,
    /// Enables tenant-managed connections.
    pub service_provider: Option<SamlServiceProvider>,
    pub authorize: Option<AuthorizeFn>,
    pub base_path: Option<String>,
    pub complete_authentication: CompleteAuthenticationFn,
    pub authenticate: Option<AuthenticateFn>,
    pub assert_trust_change: Option<AssertTrustChangeFn>,
    pub trusted_origins: Option<Vec<String>>,
    pub after_sign_in: Option<String>,
    pub mfa_url: Option<String>,
    pub error_url: Option<String>,
    pub revoke_session: Option<RevokeSessionFn>,
}

impl SamlConfigOptions {
    /// Options with a store and the sign-in callback, everything else unset.
    pub fn new(
        store: Arc<dyn IamStore>,
        complete_authentication: CompleteAuthenticationFn,
    ) -> Self {
        Self {
            store,
            connections: Vec::new(),
            service_provider: None,
            authorize: None,
            base_path: None,
            complete_authentication,
            authenticate: None,
            assert_trust_change: None,
            trusted_origins: None,
            after_sign_in: None,
            mfa_url: None,
            error_url: None,
            revoke_session: None,
        }
    }
}

/// The result of `begin`: where to send the browser, the relay state, and the browser binding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BeginResult {
    pub url: String,
    pub relay_state: String,
    pub binding: String,
}

/// The input of `callback`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallbackInput {
    pub saml_response: String,
    pub relay_state: String,
    pub binding: String,
}

/// Response header a protocol sets to ask the host to answer with a 303 to this URL instead.
const REDIRECT_HEADER: &str = "x-better-iam-redirect";
const PROTOCOL_NS: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
const ASSERTION_NS: &str = "urn:oasis:names:tc:SAML:2.0:assertion";

/// Tenant-managed connection IDs appear in SAML URLs.
static CONNECTION_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9][a-z0-9-]{1,62}$").unwrap());
static DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}$").unwrap()
});
static ATTRIBUTE_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z][a-zA-Z0-9_]{0,63}$").unwrap());
static UNSAFE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)<!DOCTYPE|<!ENTITY").unwrap());
static ERROR_CODE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z_]{2,64}$").unwrap());

/// The code a plain error travels under through a store transaction (never leaves this module).
const PLAIN_ERROR: &str = "\u{0}saml-plain-error";

fn into_iam(error: SamlError) -> IamError {
    match error {
        SamlError::Iam(error) => error,
        SamlError::Plain(message) => IamError::new(PLAIN_ERROR, message),
    }
}

fn from_iam(error: IamError) -> SamlError {
    if error.code == PLAIN_ERROR {
        SamlError::Plain(error.message)
    } else {
        SamlError::Iam(error)
    }
}

fn invalid(message: &str) -> SamlError {
    SamlError::Iam(IamError::with_status("SAML_INVALID", message, 401))
}

fn configuration(message: &str) -> SamlError {
    SamlError::Iam(IamError::new("configuration", message))
}

/// `createHash('sha256').update(value).digest('hex')`.
fn hash(value: &str) -> String {
    sha256_hex(value)
}

fn random_url(length: usize) -> String {
    let mut bytes = vec![0u8; length];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn random_uuid() -> String {
    uuid::Uuid::new_v4().to_string()
}

fn number(value: f64) -> Value {
    js::number(value).unwrap_or(Value::Null)
}

fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(value)) => *value,
        Some(Value::Number(number)) => number
            .as_f64()
            .is_some_and(|value| value != 0.0 && !value.is_nan()),
        Some(Value::String(text)) => !text.is_empty(),
        Some(_) => true,
    }
}

/// `value ?? fallback` for JSON members (`null` and missing both fall back).
fn coalesce<'a>(value: Option<&'a Value>, fallback: Option<&'a Value>) -> Option<&'a Value> {
    match value {
        None | Some(Value::Null) => fallback,
        some => some,
    }
}

/// `String(value)`.
fn js_string(value: Option<&Value>) -> String {
    match value {
        None => "undefined".to_owned(),
        Some(Value::String(text)) => text.clone(),
        Some(Value::Null) => "null".to_owned(),
        Some(Value::Number(number)) => js::number_to_string(number.as_f64().unwrap_or(f64::NAN)),
        Some(Value::Bool(value)) => value.to_string(),
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                if item.is_null() {
                    String::new()
                } else {
                    js_string(Some(item))
                }
            })
            .collect::<Vec<_>>()
            .join(","),
        Some(Value::Object(_)) => "[object Object]".to_owned(),
    }
}

/// `new URL(value)`.
fn parse_url(value: &str) -> Option<url::Url> {
    url::Url::parse(value).ok()
}

/// The URL's `origin`.
fn origin(url: &url::Url) -> String {
    url.origin().ascii_serialization()
}

/// Whether a parsed URL has credentials or a non-empty fragment (`username || password || hash`).
fn has_credentials_or_hash(url: &url::Url) -> bool {
    !url.username().is_empty()
        || url.password().is_some_and(|p| !p.is_empty())
        || url.fragment().is_some_and(|f| !f.is_empty())
}

/// `encodeURIComponent`.
fn encode_uri_component(value: &str) -> String {
    let mut out = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || b"-_.!~*'()".contains(&byte) {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `decodeURIComponent`: fails on malformed escapes and invalid UTF-8.
fn decode_uri_component(value: &str) -> Option<String> {
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

/// The `/\s/`-free email shape (`/^[^\s@]+@[^\s@]+$/`).
fn email_shaped(value: &str) -> bool {
    let mut parts = value.split('@');
    let (Some(local), Some(domain), None) = (parts.next(), parts.next(), parts.next()) else {
        return false;
    };
    let clean = |part: &str| !part.is_empty() && !part.chars().any(crate::xml::is_js_space);
    clean(local) && clean(domain)
}

/// A same-site path to return to after sign-in: an absolute path, never scheme-relative, without control characters.
fn return_path(value: Option<&Value>) -> SamlResult<String> {
    let refuse = || {
        SamlError::Iam(IamError::new(
            "INVALID_INPUT",
            "returnTo must be a path on this site, such as /dashboard.",
        ))
    };
    let Some(Value::String(text)) = value else {
        return Err(refuse());
    };
    if js::utf16_len(text) > 1024
        || !text.starts_with('/')
        || text.starts_with("//")
        || text
            .chars()
            .any(|c| (c as u32) <= 0x1f || c == '\u{7f}' || c == '\\')
    {
        return Err(refuse());
    }
    Ok(text.clone())
}

/// Validates `trustScimProvisioned`: a boolean, or up to 20 distinct SCIM connection IDs (deduplicated).
fn scim_trust(value: Option<&Value>, code: &str) -> SamlResult<Value> {
    match value {
        None => return Ok(Value::Bool(false)),
        Some(Value::Bool(value)) => return Ok(Value::Bool(*value)),
        _ => {}
    }
    let refuse = || {
        SamlError::Iam(IamError::new(
            code,
            "trustScimProvisioned is a boolean or a list of SCIM connection IDs.",
        ))
    };
    let Some(Value::Array(items)) = value else {
        return Err(refuse());
    };
    if items.len() > 20
        || items.iter().any(|id| !matches!(id, Value::String(text) if !text.is_empty() && js::utf16_len(text) <= 128))
    {
        return Err(refuse());
    }
    if items.is_empty() {
        return Ok(Value::Bool(false));
    }
    let mut unique: Vec<Value> = Vec::new();
    for item in items {
        if !unique.contains(item) {
            unique.push(item.clone());
        }
    }
    Ok(Value::Array(unique))
}

/// Whether new settings make a connection trust more than before: another IdP issuer, an added signing certificate,
/// unsolicited sign-in, more trusted email domains, or SCIM-provisioned accounts it did not link before.
fn trust_widened(current: &Record, next: &Map<String, Value>) -> bool {
    let before = coalesce(current.get("trustScimProvisioned"), None)
        .cloned()
        .unwrap_or(Value::Bool(false));
    let after = coalesce(next.get("trustScimProvisioned"), None)
        .cloned()
        .unwrap_or(Value::Bool(false));
    let scim_widened = if after == Value::Bool(true) {
        before != Value::Bool(true)
    } else {
        match &after {
            Value::Array(ids) => {
                before != Value::Bool(true)
                    && ids
                        .iter()
                        .any(|id| !matches!(&before, Value::Array(listed) if listed.contains(id)))
            }
            _ => false,
        }
    };
    let strings = |value: Option<&Value>| -> Vec<Value> {
        value.and_then(Value::as_array).cloned().unwrap_or_default()
    };
    let current_certificates = strings(current.get("idpCertificates"));
    let current_domains = strings(current.get("trustedEmailDomains"));
    scim_widened
        || next.get("idpIssuer") != current.get("idpIssuer")
        || strings(next.get("idpCertificates"))
            .iter()
            .any(|cert| !current_certificates.contains(cert))
        || (next.get("allowIdpInitiated") == Some(&Value::Bool(true))
            && current.get("allowIdpInitiated") != Some(&Value::Bool(true)))
        || strings(next.get("trustedEmailDomains"))
            .iter()
            .any(|domain| !current_domains.contains(domain))
}

/// Shared replay cache (`createSamlCache`). Run response verification inside one store transaction.
pub struct SamlCache {
    store: Arc<dyn IamStore>,
    tenant_id: String,
    connection_id: String,
    expected_request_id: Option<String>,
}

/// `createSamlCache(store, tenantId, connectionId, expectedRequestId?)`.
pub fn create_saml_cache(
    store: Arc<dyn IamStore>,
    tenant_id: &str,
    connection_id: &str,
    expected_request_id: Option<&str>,
) -> SamlCache {
    SamlCache {
        store,
        tenant_id: tenant_id.to_owned(),
        connection_id: connection_id.to_owned(),
        expected_request_id: expected_request_id
            .filter(|id| !id.is_empty())
            .map(str::to_owned),
    }
}

impl SamlCache {
    fn id(&self, key: &str) -> String {
        hash(&format!("{}:{}:{key}", self.tenant_id, self.connection_id))
    }

    fn expected(&self, key: &str) -> bool {
        self.expected_request_id
            .as_deref()
            .is_none_or(|expected| expected == key)
    }
}

#[async_trait::async_trait]
impl CacheProvider for SamlCache {
    async fn save(&self, key: &str, value: &str) -> SamlResult<()> {
        let created_at = js::now_ms();
        let mut record = Map::new();
        record.insert("id".into(), Value::String(self.id(key)));
        record.insert("tenantId".into(), Value::String(self.tenant_id.clone()));
        record.insert("value".into(), Value::String(value.to_owned()));
        record.insert("createdAt".into(), number(created_at));
        record.insert("expiresAt".into(), number(created_at + 600_000.0));
        self.store
            .transaction(|tx| async move {
                tx.insert("samlRequests", &record).await?;
                Ok(())
            })
            .await
            .map_err(from_iam)
    }

    async fn get(&self, key: &str) -> SamlResult<Option<String>> {
        if !self.expected(key) {
            return Ok(None);
        }
        let item = self.store.get("samlRequests", &self.id(key)).await?;
        Ok(item.and_then(|item| {
            let valid = item.get("tenantId").and_then(Value::as_str)
                == Some(self.tenant_id.as_str())
                && item
                    .get("expiresAt")
                    .and_then(Value::as_f64)
                    .is_some_and(|at| at > js::now_ms());
            if valid {
                item.get("value").and_then(Value::as_str).map(str::to_owned)
            } else {
                None
            }
        }))
    }

    async fn remove(&self, key: Option<&str>) -> SamlResult<Option<String>> {
        let Some(key) = key.filter(|key| !key.is_empty()) else {
            return Ok(None);
        };
        if !self.expected(key) {
            return Ok(None);
        }
        let id = self.id(key);
        let tenant_id = self.tenant_id.clone();
        self.store
            .transaction(|tx| async move {
                let Some(item) = tx.get("samlRequests", &id).await? else {
                    return Ok(None);
                };
                if item.get("tenantId").and_then(Value::as_str) != Some(tenant_id.as_str()) {
                    return Ok(None);
                }
                tx.delete("samlRequests", &id).await?;
                Ok(item.get("value").and_then(Value::as_str).map(str::to_owned))
            })
            .await
            .map_err(from_iam)
    }
}

impl SamlCache {
    /// `saveAsync(key, value)`.
    pub async fn save_async(&self, key: &str, value: &str) -> SamlResult<()> {
        self.save(key, value).await
    }

    /// `getAsync(key)`.
    pub async fn get_async(&self, key: &str) -> SamlResult<Option<String>> {
        self.get(key).await
    }

    /// `removeAsync(key)`.
    pub async fn remove_async(&self, key: Option<&str>) -> SamlResult<Option<String>> {
        self.remove(key).await
    }
}

async fn active_tenant(store: &dyn IamStore, tenant_id: &str) -> SamlResult<()> {
    if !tenant_tree_active(store, tenant_id).await? {
        return Err(SamlError::Iam(IamError::with_status(
            "TENANT_INACTIVE",
            "Tenant unavailable.",
            403,
        )));
    }
    Ok(())
}

/// Supplements the cryptographic checks with exact response destination checks. `expected_request_id: None`
/// validates an IdP-initiated response, which must not answer any request.
pub fn validate_saml_envelope(
    xml: &str,
    callback_url: &str,
    expected_request_id: Option<&str>,
    encrypted_required: bool,
) -> SamlResult<()> {
    if js::utf16_len(xml) > 1024 * 1024 || UNSAFE.is_match(xml) {
        return Err(invalid("Unsafe SAML document."));
    }
    let binding_invalid = || invalid("SAML response binding is invalid.");
    let document = Document::parse(xml).map_err(|_| binding_invalid())?;
    let root = document.document_element().ok_or_else(binding_invalid)?;
    let in_response_to = document.attr(root, "InResponseTo");
    if document.namespace(root) != Some(PROTOCOL_NS)
        || document.local_name(root) != Some("Response")
        || document.attr(root, "Destination") != Some(callback_url)
        || match expected_request_id {
            None => in_response_to.is_some(),
            Some(expected) => in_response_to != Some(expected),
        }
    {
        return Err(binding_invalid());
    }
    // Judged where Node-SAML reads assertions: the Response's own children. Counting descendants would let an empty
    // <EncryptedAssertion> hidden elsewhere (inside the signature's <Object>) satisfy the rule while a plaintext
    // assertion is what gets validated.
    let children = |name: &str| document.find_children(root, Some(ASSERTION_NS), name).len();
    if encrypted_required && (children("EncryptedAssertion") != 1 || children("Assertion") != 0) {
        return Err(invalid("An encrypted assertion is required."));
    }
    for subject in document.find_descendants(root, Some(ASSERTION_NS), "SubjectConfirmationData") {
        if document.attr(subject, "Recipient") != Some(callback_url) {
            return Err(invalid("SAML subject recipient is invalid."));
        }
        if expected_request_id.is_none() && document.has_attr(subject, "InResponseTo") {
            return Err(invalid("An unsolicited response cannot answer a request."));
        }
    }
    Ok(())
}

/// A tenant-managed connection record (`ConnectionRecord`), as stored.
fn record_text<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn record_strings(record: &Record, key: &str) -> Vec<String> {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

struct Inner {
    config: SamlConfigOptions,
    base_path: String,
    connections: IndexMap<String, SamlConnection>,
    sp_base: String,
    after_sign_in: Option<String>,
    mfa_url: Option<String>,
    error_url: Option<String>,
}

/// The service `createSamlService` returns. Cheap to clone.
#[derive(Clone)]
pub struct SamlService {
    inner: Arc<Inner>,
}

/// `createSamlService(config)`.
pub fn create_saml_service(config: SamlConfigOptions) -> SamlResult<SamlService> {
    let base_path = config
        .base_path
        .clone()
        .unwrap_or_else(|| "/saml".to_owned());
    let base_path = base_path.strip_suffix('/').unwrap_or(&base_path).to_owned();
    let mut connections: IndexMap<String, SamlConnection> = IndexMap::new();
    for item in &config.connections {
        if item.id.is_empty()
            || connections.contains_key(&item.id)
            || item.tenant_id.is_empty()
            || item.idp_issuer.is_empty()
            || item.entity_id.is_empty()
            || item.private_key.is_empty()
            || item.public_certificate.is_empty()
            || item.idp_certificates.is_empty()
        {
            return Err(configuration(
                "SAML connection configuration is incomplete.",
            ));
        }
        for value in [&item.entry_point, &item.callback_url] {
            let parsed = parse_url(value).ok_or_else(|| SamlError::plain("Invalid URL"))?;
            if parsed.scheme() != "https" || has_credentials_or_hash(&parsed) {
                return Err(configuration("SAML endpoints require HTTPS."));
            }
        }
        if item.require_encrypted_assertions
            && (item
                .decryption_private_key
                .as_deref()
                .is_none_or(str::is_empty)
                || item
                    .decryption_certificate
                    .as_deref()
                    .is_none_or(str::is_empty))
        {
            return Err(configuration(
                "Encrypted SAML assertions require decryption key and certificate.",
            ));
        }
        if connections
            .values()
            .any(|value| value.callback_url == item.callback_url)
        {
            return Err(configuration(
                "SAML callback URLs must be unique per connection.",
            ));
        }
        if item
            .trusted_email_domains
            .as_ref()
            .is_some_and(|domains| domains.iter().any(|value| !DOMAIN.is_match(value)))
        {
            return Err(configuration(
                "Trusted SAML email domains must be exact domain names.",
            ));
        }
        scim_trust(item.trust_scim_provisioned.as_ref(), "configuration")?;
        connections.insert(item.id.clone(), item.clone());
    }
    let mut sp_base = String::new();
    if let Some(sp) = &config.service_provider {
        let parsed = parse_url(&sp.base_url).ok_or_else(|| SamlError::plain("Invalid URL"))?;
        if parsed.scheme() != "https"
            || has_credentials_or_hash(&parsed)
            || parsed.query().is_some_and(|query| !query.is_empty())
            || sp.private_key.is_empty()
            || sp.public_certificate.is_empty()
        {
            return Err(configuration(
                "The SAML service provider needs an HTTPS base URL, a private key, and a certificate.",
            ));
        }
        let path = parsed.path();
        sp_base = format!(
            "{}{}",
            origin(&parsed),
            path.strip_suffix('/').unwrap_or(path)
        );
    }
    // Redirect targets: a path on this site, or a URL on an origin this service already trusts.
    let mut redirect_origins: Vec<String> = config.trusted_origins.clone().unwrap_or_default();
    if !sp_base.is_empty()
        && let Some(parsed) = parse_url(&sp_base)
    {
        redirect_origins.push(origin(&parsed));
    }
    for item in connections.values() {
        if let Some(parsed) = parse_url(&item.callback_url) {
            redirect_origins.push(origin(&parsed));
        }
    }
    let redirect_target = |value: &Option<String>, name: &str| -> SamlResult<Option<String>> {
        let Some(value) = value else {
            return Ok(None);
        };
        let refuse = || {
            configuration(&format!(
                "SAML {name} must be a path or a trusted HTTPS URL."
            ))
        };
        if value.starts_with('/') {
            return return_path(Some(&Value::String(value.clone())))
                .map(Some)
                .map_err(|_| refuse());
        }
        let parsed = parse_url(value).ok_or_else(refuse)?;
        if !parsed.username().is_empty()
            || parsed.password().is_some_and(|p| !p.is_empty())
            || !redirect_origins.contains(&origin(&parsed))
        {
            return Err(refuse());
        }
        Ok(Some(parsed.to_string()))
    };
    let after_sign_in = redirect_target(&config.after_sign_in, "afterSignIn")?;
    let mfa_url = redirect_target(&config.mfa_url, "mfaUrl")?;
    let error_url = redirect_target(&config.error_url, "errorUrl")?;
    if (mfa_url.is_some() || error_url.is_some()) && after_sign_in.is_none() {
        return Err(configuration("SAML mfaUrl and errorUrl need afterSignIn."));
    }
    Ok(SamlService {
        inner: Arc::new(Inner {
            config,
            base_path,
            connections,
            sp_base,
            after_sign_in,
            mfa_url,
            error_url,
        }),
    })
}

/// The URLs of a tenant-managed connection.
struct ManagedUrls {
    entity_id: String,
    acs_url: String,
    metadata_url: String,
    login_url: String,
}

impl SamlService {
    fn config(&self) -> &SamlConfigOptions {
        &self.inner.config
    }

    /// The path the protocol is served under.
    pub fn base_path(&self) -> &str {
        &self.inner.base_path
    }

    fn managed_urls(&self, id: &str) -> ManagedUrls {
        let root = format!(
            "{}{}/{}",
            self.inner.sp_base,
            self.inner.base_path,
            encode_uri_component(id)
        );
        ManagedUrls {
            entity_id: format!("{root}/metadata"),
            acs_url: format!("{root}/acs"),
            metadata_url: format!("{root}/metadata"),
            login_url: format!("{root}/login"),
        }
    }

    fn from_record(&self, record: &Record) -> SamlConnection {
        let sp = self.config().service_provider.clone().unwrap_or_default();
        let id = record_text(record, "id").to_owned();
        let urls = self.managed_urls(&id);
        let mapping: Vec<(String, String)> = record
            .get("attributeMapping")
            .and_then(Value::as_object)
            .map(|map| {
                map.iter()
                    .map(|(key, value)| (key.clone(), js_string(Some(value))))
                    .collect()
            })
            .unwrap_or_default();
        let map_attributes: Option<MapAttributes> = if mapping.is_empty() {
            None
        } else {
            Some(Arc::new(move |profile: &Profile| {
                let mut attributes = Map::new();
                for (attribute, name) in &mapping {
                    let value = match profile.get(name) {
                        Some(Value::Array(items)) => items.first(),
                        other => other,
                    };
                    if let Some(Value::String(text)) = value {
                        attributes.insert(attribute.clone(), Value::String(text.clone()));
                    }
                }
                Some(attributes)
            }))
        };
        SamlConnection {
            id: id.clone(),
            provider_id: record
                .get("providerKey")
                .and_then(Value::as_str)
                .filter(|key| !key.is_empty())
                .map(str::to_owned),
            tenant_id: record_text(record, "tenantId").to_owned(),
            entry_point: record_text(record, "entryPoint").to_owned(),
            idp_issuer: record_text(record, "idpIssuer").to_owned(),
            idp_certificates: record_strings(record, "idpCertificates"),
            entity_id: urls.entity_id,
            callback_url: urls.acs_url,
            private_key: sp.private_key,
            public_certificate: sp.public_certificate,
            decryption_private_key: sp.decryption_private_key,
            decryption_certificate: sp.decryption_certificate,
            require_encrypted_assertions: record.get("requireEncryptedAssertions")
                == Some(&Value::Bool(true)),
            allow_idp_initiated: record.get("allowIdpInitiated") == Some(&Value::Bool(true)),
            trust_scim_provisioned: Some(
                coalesce(record.get("trustScimProvisioned"), None)
                    .cloned()
                    .unwrap_or(Value::Bool(false)),
            ),
            trusted_email_domains: Some(record_strings(record, "trustedEmailDomains")),
            map_attributes,
        }
    }

    fn static_connection(&self, id: &str) -> SamlResult<SamlConnection> {
        self.inner.connections.get(id).cloned().ok_or_else(|| {
            SamlError::Iam(IamError::with_status(
                "NOT_FOUND",
                "SAML connection unavailable.",
                404,
            ))
        })
    }

    /// A configured connection, or an enabled tenant-managed one.
    async fn connection(
        &self,
        id: &str,
        store: Option<&dyn IamStore>,
    ) -> SamlResult<SamlConnection> {
        if let Some(item) = self.inner.connections.get(id) {
            return Ok(item.clone());
        }
        if self.config().service_provider.is_some() && CONNECTION_NAME.is_match(id) {
            let store = store.unwrap_or(self.config().store.as_ref());
            if let Some(record) = store.get("samlConnections", id).await?
                && record
                    .get("enabled")
                    .is_some_and(|enabled| truthy(Some(enabled)))
            {
                return Ok(self.from_record(&record));
            }
        }
        Err(SamlError::Iam(IamError::with_status(
            "NOT_FOUND",
            "SAML connection unavailable.",
            404,
        )))
    }

    fn summary(&self, record: &Record) -> SamlResult<Value> {
        let id = record_text(record, "id").to_owned();
        let urls = self.managed_urls(&id);
        let certificates = record_strings(record, "idpCertificates")
            .iter()
            .map(|pem| {
                certificate_info(pem).map(|info| serde_json::to_value(info).unwrap_or(Value::Null))
            })
            .collect::<Result<Vec<_>, _>>()?;
        let mut out = Map::new();
        out.insert("id".into(), Value::String(id.clone()));
        out.insert(
            "tenantId".into(),
            record.get("tenantId").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "name".into(),
            record.get("name").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "enabled".into(),
            record.get("enabled").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "entryPoint".into(),
            record.get("entryPoint").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "idpIssuer".into(),
            record.get("idpIssuer").cloned().unwrap_or(Value::Null),
        );
        out.insert("certificates".into(), Value::Array(certificates));
        out.insert(
            "trustedEmailDomains".into(),
            record
                .get("trustedEmailDomains")
                .cloned()
                .unwrap_or(json!([])),
        );
        out.insert(
            "requireEncryptedAssertions".into(),
            record
                .get("requireEncryptedAssertions")
                .cloned()
                .unwrap_or(Value::Null),
        );
        out.insert(
            "attributeMapping".into(),
            record.get("attributeMapping").cloned().unwrap_or(json!({})),
        );
        out.insert(
            "allowIdpInitiated".into(),
            Value::Bool(record.get("allowIdpInitiated") == Some(&Value::Bool(true))),
        );
        out.insert(
            "trustScimProvisioned".into(),
            coalesce(record.get("trustScimProvisioned"), None)
                .cloned()
                .unwrap_or(Value::Bool(false)),
        );
        out.insert(
            "providerId".into(),
            coalesce(record.get("providerKey"), None)
                .cloned()
                .unwrap_or(Value::String(id)),
        );
        out.insert("entityId".into(), Value::String(urls.entity_id));
        out.insert("acsUrl".into(), Value::String(urls.acs_url));
        out.insert("metadataUrl".into(), Value::String(urls.metadata_url));
        out.insert("loginUrl".into(), Value::String(urls.login_url));
        out.insert(
            "createdAt".into(),
            record.get("createdAt").cloned().unwrap_or(Value::Null),
        );
        out.insert(
            "updatedAt".into(),
            record.get("updatedAt").cloned().unwrap_or(Value::Null),
        );
        Ok(Value::Object(out))
    }

    /// Validates administrator input, filling IdP details from metadata and unchanged values from `current`.
    fn settings(
        &self,
        input: &Map<String, Value>,
        current: Option<&Record>,
    ) -> SamlResult<Map<String, Value>> {
        let refuse = |message: &str| SamlError::Iam(IamError::new("INVALID_INPUT", message));
        let imported = match input.get("metadataXml") {
            None => None,
            Some(Value::String(xml)) => Some(parse_idp_metadata(xml)?),
            Some(_) => return Err(refuse("Unsafe or oversized SAML metadata.")),
        };
        let imported_entry = imported
            .as_ref()
            .map(|metadata| Value::String(metadata.entry_point.clone()));
        let imported_issuer = imported
            .as_ref()
            .map(|metadata| Value::String(metadata.entity_id.clone()));
        let imported_certificates = imported.as_ref().map(|metadata| {
            Value::Array(
                metadata
                    .certificates
                    .iter()
                    .cloned()
                    .map(Value::String)
                    .collect(),
            )
        });
        let from_current = |key: &str| current.and_then(|record| record.get(key));
        let name = coalesce(input.get("name"), from_current("name"));
        let entry_point = coalesce(
            input.get("entryPoint"),
            coalesce(imported_entry.as_ref(), from_current("entryPoint")),
        );
        let idp_issuer = coalesce(
            input.get("idpIssuer"),
            coalesce(imported_issuer.as_ref(), from_current("idpIssuer")),
        );
        let certificates = coalesce(
            input.get("idpCertificates"),
            coalesce(
                imported_certificates.as_ref(),
                from_current("idpCertificates"),
            ),
        );
        let empty_list = json!([]);
        let empty_object = json!({});
        let domains = coalesce(
            input.get("trustedEmailDomains"),
            coalesce(from_current("trustedEmailDomains"), Some(&empty_list)),
        );
        let mapping = coalesce(
            input.get("attributeMapping"),
            coalesce(from_current("attributeMapping"), Some(&empty_object)),
        );
        let falsy = Value::Bool(false);
        let yes = Value::Bool(true);
        let require_encrypted = coalesce(
            input.get("requireEncryptedAssertions"),
            coalesce(from_current("requireEncryptedAssertions"), Some(&falsy)),
        );
        let enabled = coalesce(
            input.get("enabled"),
            coalesce(from_current("enabled"), Some(&yes)),
        );
        let allow_idp_initiated = coalesce(
            input.get("allowIdpInitiated"),
            coalesce(from_current("allowIdpInitiated"), Some(&falsy)),
        );
        let trust_scim = scim_trust(
            coalesce(
                input.get("trustScimProvisioned"),
                coalesce(from_current("trustScimProvisioned"), Some(&falsy)),
            ),
            "INVALID_INPUT",
        )?;
        let name = match name {
            Some(Value::String(name))
                if !js::trim(name).is_empty() && js::utf16_len(name) <= 200 =>
            {
                name.clone()
            }
            _ => {
                return Err(refuse(
                    "A connection name of at most 200 characters is required.",
                ));
            }
        };
        let entry_message = "The IdP sign-on URL must be an absolute HTTPS URL.";
        let entry = parse_url(&js_string(entry_point)).ok_or_else(|| refuse(entry_message))?;
        if entry.scheme() != "https" || has_credentials_or_hash(&entry) {
            return Err(refuse(entry_message));
        }
        let idp_issuer = match idp_issuer {
            Some(Value::String(issuer)) if !issuer.is_empty() && js::utf16_len(issuer) <= 1024 => {
                issuer.clone()
            }
            _ => return Err(refuse("The IdP issuer (entity ID) is required.")),
        };
        let certificates = match certificates {
            Some(Value::Array(items)) if !items.is_empty() && items.len() <= 5 => items.clone(),
            _ => {
                return Err(refuse(
                    "Between one and five IdP signing certificates are required.",
                ));
            }
        };
        let domains = match domains {
            Some(Value::Array(items))
                if items.len() <= 20
                    && items
                        .iter()
                        .all(|item| item.as_str().is_some_and(|value| DOMAIN.is_match(value))) =>
            {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect::<Vec<_>>()
            }
            _ => return Err(refuse("Trusted email domains must be exact domain names.")),
        };
        let mapping = match mapping {
            Some(Value::Object(map))
                if map.len() <= 32
                    && map.iter().all(|(attribute, source)| {
                        ATTRIBUTE_NAME.is_match(attribute)
                            && matches!(source, Value::String(text) if !text.is_empty() && js::utf16_len(text) <= 256)
                    }) =>
            {
                map.clone()
            }
            _ => {
                return Err(refuse(
                    "attributeMapping maps up to 32 identity attribute names to SAML attribute names.",
                ));
            }
        };
        let (
            Some(Value::Bool(require_encrypted)),
            Some(Value::Bool(enabled)),
            Some(Value::Bool(allow_idp_initiated)),
        ) = (require_encrypted, enabled, allow_idp_initiated)
        else {
            return Err(refuse("Invalid SAML connection settings."));
        };
        let sp = self.config().service_provider.as_ref();
        if *require_encrypted
            && (sp
                .and_then(|sp| sp.decryption_private_key.as_deref())
                .is_none_or(str::is_empty)
                || sp
                    .and_then(|sp| sp.decryption_certificate.as_deref())
                    .is_none_or(str::is_empty))
        {
            return Err(refuse(
                "Encrypted assertions need a service-provider decryption key.",
            ));
        }
        let mut normalized: Vec<Value> = Vec::new();
        for certificate in &certificates {
            let pem = Value::String(normalize_certificate(&js_string(Some(certificate)))?);
            if !normalized.contains(&pem) {
                normalized.push(pem);
            }
        }
        let mut lowered: Vec<Value> = Vec::new();
        for domain in &domains {
            let domain = Value::String(js::to_lower(domain));
            if !lowered.contains(&domain) {
                lowered.push(domain);
            }
        }
        let mut out = Map::new();
        out.insert("name".into(), Value::String(js::trim(&name).to_owned()));
        out.insert("entryPoint".into(), Value::String(entry.to_string()));
        out.insert("idpIssuer".into(), Value::String(idp_issuer));
        out.insert("idpCertificates".into(), Value::Array(normalized));
        out.insert("trustedEmailDomains".into(), Value::Array(lowered));
        out.insert("attributeMapping".into(), Value::Object(mapping));
        out.insert(
            "requireEncryptedAssertions".into(),
            Value::Bool(*require_encrypted),
        );
        out.insert(
            "allowIdpInitiated".into(),
            Value::Bool(*allow_idp_initiated),
        );
        out.insert("trustScimProvisioned".into(), trust_scim);
        out.insert("enabled".into(), Value::Bool(*enabled));
        Ok(out)
    }

    /// Authorizes a management call on `saml/{id}` and returns the acting principal.
    async fn manager(
        &self,
        credential: &CredentialInput,
        action: &str,
        tenant_id: &str,
        id: &str,
    ) -> SamlResult<AuthenticatedPrincipal> {
        let config = self.config();
        let (Some(_), Some(authorize), Some(authenticate)) = (
            &config.service_provider,
            &config.authorize,
            &config.authenticate,
        ) else {
            return Err(configuration(
                "Managed SAML connections need serviceProvider, authorize, and authenticate.",
            ));
        };
        authorize(
            credential.clone(),
            action.to_owned(),
            ResourceRef {
                tenant_id: tenant_id.to_owned(),
                kind: "saml".into(),
                id: id.to_owned(),
            },
        )
        .await?;
        Ok(authenticate(credential.clone()).await?)
    }

    async fn managed(&self, tx: &dyn IamStore, tenant_id: &str, id: &str) -> SamlResult<Record> {
        let record = if CONNECTION_NAME.is_match(id) {
            tx.get("samlConnections", id).await?
        } else {
            None
        };
        match record {
            Some(record) if record.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => {
                Ok(record)
            }
            _ => Err(SamlError::Iam(IamError::with_status(
                "NOT_FOUND",
                "SAML connection not found.",
                404,
            ))),
        }
    }

    async fn audit(
        tx: &dyn IamStore,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        action: &str,
        resource_id: &str,
    ) -> IamResult<()> {
        let mut event = Map::new();
        event.insert("id".into(), Value::String(random_uuid()));
        event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        event.insert(
            "actorId".into(),
            Value::String(principal.identity.id.clone()),
        );
        event.insert("action".into(), Value::String(action.to_owned()));
        event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
        event.insert("timestamp".into(), number(js::now_ms()));
        event.insert("outcome".into(), Value::String("allow".into()));
        append_audit_event(tx, &event).await?;
        Ok(())
    }

    fn saml(
        &self,
        item: &SamlConnection,
        store: Arc<dyn IamStore>,
        request_id: Option<String>,
        expected_request_id: Option<&str>,
        unsolicited: bool,
    ) -> Saml {
        let generate: Arc<dyn Fn() -> String + Send + Sync> = match request_id {
            Some(id) => Arc::new(move || id.clone()),
            None => Arc::new(|| format!("_{}", random_uuid())),
        };
        Saml::new(SamlOptions {
            entry_point: item.entry_point.clone(),
            issuer: item.entity_id.clone(),
            idp_issuer: item.idp_issuer.clone(),
            callback_url: item.callback_url.clone(),
            audience: item.entity_id.clone(),
            idp_cert: item.idp_certificates.clone(),
            private_key: item.private_key.clone(),
            public_cert: item.public_certificate.clone(),
            decryption_pvk: item.decryption_private_key.clone(),
            validate_in_response_to: if unsolicited {
                ValidateInResponseTo::Never
            } else {
                ValidateInResponseTo::Always
            },
            request_id_expiration_period_ms: 600_000.0,
            max_assertion_age_ms: 300_000.0,
            accepted_clock_skew_ms: 30_000.0,
            cache_provider: Arc::new(create_saml_cache(
                store,
                &item.tenant_id,
                &item.id,
                expected_request_id,
            )),
            generate_unique_id: generate,
        })
    }

    /// Starts a sign-in (or, with `linking_credential`, links the IdP account to the signed-in identity): the IdP
    /// URL, the relay state, and the browser binding to set as a cookie. `return_to` replaces `afterSignIn` for
    /// this sign-in.
    pub async fn begin(
        &self,
        connection_id: &str,
        linking_credential: Option<&CredentialInput>,
        return_to: Option<&Value>,
    ) -> SamlResult<BeginResult> {
        let item = self.connection(connection_id, None).await?;
        let return_to = match return_to {
            None => None,
            some => Some(return_path(some)?),
        };
        let request_id = format!("_{}", random_uuid());
        let relay_state = random_url(32);
        let binding = random_url(32);
        let mut linking: Option<(String, String)> = None;
        if let Some(credential) = linking_credential {
            let Some(authenticate) = &self.config().authenticate else {
                return Err(configuration("Linking requires an authenticate callback."));
            };
            let principal = authenticate(credential.clone()).await?;
            let age = js::now_ms() - principal.session.authenticated_at;
            if principal.identity.tenant_id != item.tenant_id
                || principal.identity.root_admin
                || principal.session.kind != SessionKind::User
                || age < 0.0
                || age > 300_000.0
            {
                return Err(SamlError::Iam(IamError::with_status(
                    "RECENT_AUTH_REQUIRED",
                    "Linking requires recent authentication to a non-root identity in this tenant.",
                    403,
                )));
            }
            linking = Some((principal.session.id.clone(), principal.identity.id.clone()));
        }
        let (item_ref, request_ref, relay_ref, binding_ref, linking_ref, return_ref) = (
            &item,
            &request_id,
            &relay_state,
            &binding,
            &linking,
            &return_to,
        );
        let destination = self
            .config()
            .store
            .transaction(|tx| async move {
                active_tenant(tx.as_ref(), &item_ref.tenant_id)
                    .await
                    .map_err(into_iam)?;
                let destination = self
                    .saml(item_ref, tx.clone(), Some(request_ref.clone()), None, false)
                    .get_authorize_url(relay_ref)
                    .await
                    .map_err(into_iam)?;
                let mut relay = Map::new();
                relay.insert("id".into(), Value::String(hash(relay_ref)));
                relay.insert("tenantId".into(), Value::String(item_ref.tenant_id.clone()));
                relay.insert("connectionId".into(), Value::String(item_ref.id.clone()));
                relay.insert("requestId".into(), Value::String(request_ref.clone()));
                relay.insert("bindingHash".into(), Value::String(hash(binding_ref)));
                relay.insert("expiresAt".into(), number(js::now_ms() + 600_000.0));
                if let Some((session_id, identity_id)) = linking_ref {
                    relay.insert("linkingSessionId".into(), Value::String(session_id.clone()));
                    relay.insert(
                        "linkingIdentityId".into(),
                        Value::String(identity_id.clone()),
                    );
                }
                if let Some(path) = return_ref.as_ref().filter(|path| !path.is_empty()) {
                    relay.insert("returnTo".into(), Value::String(path.clone()));
                }
                tx.insert("samlRelays", &relay).await?;
                Ok(destination)
            })
            .await
            .map_err(from_iam)?;
        Ok(BeginResult {
            url: destination,
            relay_state,
            binding,
        })
    }

    /// Completes an SP-initiated sign-in from the IdP's POSTed response: the host's sign-in result.
    pub async fn callback(&self, connection_id: &str, input: &CallbackInput) -> SamlResult<Value> {
        Ok(self.consume(connection_id, input).await?.0)
    }

    /// `callback`, also returning the `returnTo` path the sign-in was started with.
    async fn consume(
        &self,
        connection_id: &str,
        input: &CallbackInput,
    ) -> SamlResult<(Value, Option<String>)> {
        let item = self.connection(connection_id, None).await?;
        if input.binding.is_empty()
            || input.relay_state.is_empty()
            || js::utf16_len(&input.relay_state) > 512
            || js::utf16_len(&input.saml_response) > 1_400_000
        {
            return Err(invalid("Invalid SAML response."));
        }
        let item = &item;
        self.config()
            .store
            .transaction(|tx| async move {
                async {
                    active_tenant(tx.as_ref(), &item.tenant_id).await?;
                    let relay = tx.get("samlRelays", &hash(&input.relay_state)).await?;
                    let replayed = || invalid("Invalid, expired, or replayed SAML login.");
                    let Some(relay) = relay else {
                        return Err(replayed());
                    };
                    if relay.get("tenantId").and_then(Value::as_str)
                        != Some(item.tenant_id.as_str())
                        || relay.get("connectionId").and_then(Value::as_str)
                            != Some(item.id.as_str())
                        || relay
                            .get("expiresAt")
                            .and_then(Value::as_f64)
                            .is_some_and(|at| at <= js::now_ms())
                        || !timing_safe_equal(
                            record_text(&relay, "bindingHash"),
                            &hash(&input.binding),
                        )?
                    {
                        return Err(replayed());
                    }
                    let request_id = record_text(&relay, "requestId").to_owned();
                    let xml =
                        String::from_utf8_lossy(&base64_decode(&input.saml_response)).into_owned();
                    validate_saml_envelope(
                        &xml,
                        &item.callback_url,
                        Some(&request_id),
                        item.require_encrypted_assertions,
                    )?;
                    let (profile, logged_out) = self
                        .saml(item, tx.clone(), None, Some(&request_id), false)
                        .validate_post_response(&input.saml_response)
                        .await?;
                    let profile = match profile {
                        Some(profile)
                            if !logged_out
                                && profile.text("issuer") == Some(item.idp_issuer.as_str())
                                && truthy(profile.get("nameID")) =>
                        {
                            profile
                        }
                        _ => return Err(invalid("Invalid SAML identity.")),
                    };
                    // Node-SAML decrypts and validates the assertion before exposing this XML.
                    let assertion = &profile.assertion;
                    for subject in assertion.document.find_descendants(
                        Document::ROOT,
                        Some(ASSERTION_NS),
                        "SubjectConfirmationData",
                    ) {
                        if assertion.document.attr(subject, "Recipient")
                            != Some(item.callback_url.as_str())
                        {
                            return Err(invalid("SAML assertion recipient is invalid."));
                        }
                    }
                    tx.delete("samlRelays", record_text(&relay, "id")).await?;
                    let result = self.finish(item, &profile, Some(&relay)).await?;
                    Ok((
                        result,
                        relay
                            .get("returnTo")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                    ))
                }
                .await
                .map_err(into_iam)
            })
            .await
            .map_err(from_iam)
    }

    /// Hands a validated SAML identity to the host, with a trusted-domain email and mapped attributes.
    async fn finish(
        &self,
        item: &SamlConnection,
        profile: &Profile,
        relay: Option<&Record>,
    ) -> SamlResult<Value> {
        let email = profile
            .get("email")
            .or_else(|| profile.get("mail"))
            .or_else(|| profile.get("urn:oid:0.9.2342.19200300.100.1.3"));
        let email = email.and_then(Value::as_str).map(str::to_owned);
        let verified = email.as_deref().is_some_and(|email| {
            email_shaped(email)
                && item.trusted_email_domains.as_ref().is_some_and(|domains| {
                    let domain = js::to_lower(email.split('@').nth(1).unwrap_or_default());
                    domains
                        .iter()
                        .any(|trusted| js::to_lower(trusted) == domain)
                })
        });
        let attributes = item.map_attributes.as_ref().and_then(|map| map(profile));
        let mut input = Map::new();
        input.insert("tenantId".into(), Value::String(item.tenant_id.clone()));
        input.insert(
            "providerId".into(),
            Value::String(item.provider_id.clone().unwrap_or_else(|| item.id.clone())),
        );
        input.insert("issuer".into(), Value::String(item.idp_issuer.clone()));
        input.insert(
            "subject".into(),
            profile.get("nameID").cloned().unwrap_or(Value::Null),
        );
        if let Some(email) = email {
            input.insert("email".into(), Value::String(email));
        }
        input.insert("emailVerified".into(), Value::Bool(verified));
        if let Some(name) = profile.text("displayName") {
            input.insert("name".into(), Value::String(name.to_owned()));
        }
        if let Some(relay) = relay
            && truthy(relay.get("linkingSessionId"))
        {
            input.insert(
                "linkingSessionId".into(),
                relay
                    .get("linkingSessionId")
                    .cloned()
                    .unwrap_or(Value::Null),
            );
            if let Some(identity) = relay.get("linkingIdentityId") {
                input.insert("linkingIdentityId".into(), identity.clone());
            }
        }
        if let Some(attributes) = attributes {
            input.insert("attributes".into(), Value::Object(attributes));
        }
        if truthy(item.trust_scim_provisioned.as_ref()) {
            input.insert(
                "trustScimProvisioned".into(),
                item.trust_scim_provisioned.clone().unwrap_or(Value::Null),
            );
        }
        Ok((self.config().complete_authentication)(Value::Object(input)).await?)
    }

    /// Whether a base64 SAML response carries `InResponseTo` (SP-initiated). Unparseable input counts as solicited.
    fn answers_request(saml_response: &str) -> bool {
        let xml = String::from_utf8_lossy(&base64_decode(saml_response)).into_owned();
        if js::utf16_len(&xml) > 1024 * 1024 || UNSAFE.is_match(&xml) {
            return true;
        }
        match Document::parse(&xml) {
            Ok(document) => document
                .document_element()
                .is_none_or(|root| document.has_attr(root, "InResponseTo")),
            Err(_) => true,
        }
    }

    /// Accepts an IdP-initiated response for a connection with `allowIdpInitiated` (the ACS route calls it): the same
    /// signature, issuer, audience, destination, recipient, and age checks as SP-initiated responses, no
    /// `InResponseTo`, and each assertion ID accepted only once.
    pub async fn idp_initiated(
        &self,
        connection_id: &str,
        saml_response: &str,
    ) -> SamlResult<Value> {
        let item = self.connection(connection_id, None).await?;
        if !item.allow_idp_initiated || js::utf16_len(saml_response) > 1_400_000 {
            return Err(invalid("Unsolicited SAML responses are not accepted."));
        }
        let item = &item;
        self.config()
            .store
            .transaction(|tx| async move {
                async {
                    active_tenant(tx.as_ref(), &item.tenant_id).await?;
                    let xml = String::from_utf8_lossy(&base64_decode(saml_response)).into_owned();
                    validate_saml_envelope(
                        &xml,
                        &item.callback_url,
                        None,
                        item.require_encrypted_assertions,
                    )?;
                    let (profile, logged_out) = self
                        .saml(item, tx.clone(), None, None, true)
                        .validate_post_response(saml_response)
                        .await?;
                    let profile = match profile {
                        Some(profile)
                            if !logged_out
                                && profile.text("issuer") == Some(item.idp_issuer.as_str())
                                && truthy(profile.get("nameID")) =>
                        {
                            profile
                        }
                        _ => return Err(invalid("Invalid SAML identity.")),
                    };
                    let assertion = &profile.assertion;
                    let root = assertion.document.document_element();
                    let assertion_id = root
                        .and_then(|root| assertion.document.attr(root, "ID"))
                        .filter(|id| !id.is_empty());
                    let (Some(root), Some(assertion_id)) = (root, assertion_id) else {
                        return Err(invalid("The assertion has no identifier."));
                    };
                    let assertion_id = assertion_id.to_owned();
                    // Node-SAML applies its age limit only when <Conditions> carries times, so an assertion without them
                    // would stay acceptable forever once its single-use record below lapses. Its own IssueInstant bounds
                    // it instead: accepted only within the maximum age (plus clock skew), which the single-use record
                    // outlives.
                    let issued = better_iam_auth::js_date::parse(
                        assertion
                            .document
                            .attr(root, "IssueInstant")
                            .unwrap_or_default(),
                    );
                    let now = js::now_ms();
                    if !issued.is_finite() || issued > now + 30_000.0 || now - issued > 330_000.0 {
                        return Err(invalid("The assertion is too old or not yet valid."));
                    }
                    for subject in assertion.document.find_descendants(
                        Document::ROOT,
                        Some(ASSERTION_NS),
                        "SubjectConfirmationData",
                    ) {
                        if assertion.document.attr(subject, "Recipient")
                            != Some(item.callback_url.as_str())
                            || assertion.document.has_attr(subject, "InResponseTo")
                        {
                            return Err(invalid("SAML assertion recipient is invalid."));
                        }
                    }
                    // One use per assertion for longer than an assertion can be accepted (maximum age plus clock skew).
                    let now = js::now_ms();
                    for seen in tx
                        .find(
                            "samlAssertions",
                            &Filter::new().eq("connectionId", item.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        if seen
                            .get("expiresAt")
                            .and_then(Value::as_f64)
                            .is_some_and(|at| at <= now)
                        {
                            tx.delete("samlAssertions", record_text(&seen, "id"))
                                .await?;
                        }
                    }
                    let key = hash(&format!("{}:{}:{assertion_id}", item.tenant_id, item.id));
                    if tx.get("samlAssertions", &key).await?.is_some() {
                        return Err(invalid("The assertion was already used."));
                    }
                    let mut record = Map::new();
                    record.insert("id".into(), Value::String(key));
                    record.insert("tenantId".into(), Value::String(item.tenant_id.clone()));
                    record.insert("connectionId".into(), Value::String(item.id.clone()));
                    record.insert("value".into(), Value::String(String::new()));
                    record.insert("createdAt".into(), number(now));
                    record.insert("expiresAt".into(), number(now + 600_000.0));
                    tx.insert("samlAssertions", &record).await?;
                    self.finish(item, &profile, None).await
                }
                .await
                .map_err(into_iam)
            })
            .await
            .map_err(from_iam)
    }

    /// Signed SP metadata of any available connection, configured or tenant-managed.
    pub async fn get_metadata(&self, connection_id: &str) -> SamlResult<String> {
        let item = self.connection(connection_id, None).await?;
        self.saml(&item, self.config().store.clone(), None, None, false)
            .generate_service_provider_metadata(
                item.decryption_certificate.as_deref(),
                &item.public_certificate,
            )
    }

    /// Signed SP metadata of a configured connection; `get_metadata` also serves tenant-managed ones.
    pub fn metadata(&self, connection_id: &str) -> SamlResult<String> {
        let item = self.static_connection(connection_id)?;
        self.saml(&item, self.config().store.clone(), None, None, false)
            .generate_service_provider_metadata(
                item.decryption_certificate.as_deref(),
                &item.public_certificate,
            )
    }

    /// Adds a tenant's identity provider (`iam:saml:connections:create` on `saml/{id}`). Give IdP metadata XML or the
    /// sign-on URL, issuer, and signing certificates; the result lists the SP values to enter at the IdP. `input`
    /// is the TypeScript input object (`tenantId`, `id?`, `name`, `metadataXml?`, ...).
    pub async fn create_connection(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> SamlResult<Value> {
        let empty = Map::new();
        let input = input.as_object().unwrap_or(&empty);
        let id = match coalesce(input.get("id"), None) {
            None => {
                let mut bytes = [0u8; 6];
                rand::thread_rng().fill_bytes(&mut bytes);
                Value::String(format!("saml-{}", hex::encode(bytes)))
            }
            Some(value) => value.clone(),
        };
        let id = match id {
            Value::String(id) if CONNECTION_NAME.is_match(&id) => id,
            _ => {
                return Err(SamlError::Iam(IamError::new(
                    "INVALID_INPUT",
                    "Connection IDs are 2-63 lowercase letters, digits, and hyphens.",
                )));
            }
        };
        let tenant_id = input
            .get("tenantId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let principal = self
            .manager(credential, "iam:saml:connections:create", &tenant_id, &id)
            .await?;
        let values = self.settings(input, None)?;
        // A fresh provider key links no account yet; the host still requires a recent sign-in to add a trust anchor.
        let provider_key = format!("saml:{id}:{}", random_url(12));
        if let Some(assert) = &self.config().assert_trust_change {
            assert(credential.clone(), tenant_id.clone(), provider_key.clone()).await?;
        }
        let (id_ref, tenant_ref, principal_ref, values_ref, key_ref) =
            (&id, &tenant_id, &principal, &values, &provider_key);
        let record = self
            .config()
            .store
            .transaction(|tx| async move {
                active_tenant(tx.as_ref(), tenant_ref)
                    .await
                    .map_err(into_iam)?;
                if self.inner.connections.contains_key(id_ref)
                    || tx.get("samlConnections", id_ref).await?.is_some()
                {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "A SAML connection with this ID already exists.",
                        409,
                    ));
                }
                let now = js::now_ms();
                let mut record = Map::new();
                record.insert("id".into(), Value::String(id_ref.clone()));
                record.insert("tenantId".into(), Value::String(tenant_ref.clone()));
                for (key, value) in values_ref {
                    record.insert(key.clone(), value.clone());
                }
                record.insert("providerKey".into(), Value::String(key_ref.clone()));
                record.insert("createdAt".into(), number(now));
                record.insert("updatedAt".into(), number(now));
                tx.insert("samlConnections", &record).await?;
                Self::audit(
                    tx.as_ref(),
                    principal_ref,
                    tenant_ref,
                    "iam:saml:CreateConnection",
                    id_ref,
                )
                .await?;
                Ok(record)
            })
            .await
            .map_err(from_iam)?;
        self.summary(&record)
    }

    /// The tenant's managed connections (`iam:saml:connections:read` on `saml/*`), by name then ID.
    pub async fn list_connections(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
    ) -> SamlResult<Vec<Value>> {
        self.manager(credential, "iam:saml:connections:read", tenant_id, "*")
            .await?;
        let records = self
            .config()
            .store
            .find(
                "samlConnections",
                &Filter::new().eq("tenantId", tenant_id.to_owned()),
                &FindOptions::default(),
            )
            .await?;
        let mut summaries = records
            .iter()
            .map(|record| self.summary(record))
            .collect::<SamlResult<Vec<_>>>()?;
        summaries.sort_by(|a, b| {
            let text = |value: &Value, key: &str| {
                value
                    .get(key)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let (name_a, name_b) = (text(a, "name"), text(b, "name"));
            match js::cmp_utf16(&name_a, &name_b) {
                std::cmp::Ordering::Equal => {
                    if js::cmp_utf16(&text(a, "id"), &text(b, "id")).is_lt() {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    }
                }
                other => other,
            }
        });
        Ok(summaries)
    }

    /// One managed connection (`iam:saml:connections:read` on `saml/{connectionId}`).
    pub async fn get_connection(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        connection_id: &str,
    ) -> SamlResult<Value> {
        self.manager(
            credential,
            "iam:saml:connections:read",
            tenant_id,
            connection_id,
        )
        .await?;
        let record = self
            .managed(self.config().store.as_ref(), tenant_id, connection_id)
            .await?;
        self.summary(&record)
    }

    /// Changes a managed connection, for example new IdP certificates during rollover (list old and new together
    /// until the IdP switches) or refreshed metadata. Disabling it stops new sign-ins at once. `input` carries
    /// `tenantId`, `connectionId` and the settings to change.
    pub async fn update_connection(
        &self,
        credential: &CredentialInput,
        input: &Value,
    ) -> SamlResult<Value> {
        let empty = Map::new();
        let input = input.as_object().unwrap_or(&empty);
        let tenant_id = input
            .get("tenantId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let connection_id = input
            .get("connectionId")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let principal = self
            .manager(
                credential,
                "iam:saml:connections:update",
                &tenant_id,
                &connection_id,
            )
            .await?;
        // Whoever changes what the connection trusts can sign in as every account linked through it.
        let before = self
            .managed(self.config().store.as_ref(), &tenant_id, &connection_id)
            .await?;
        let widened = trust_widened(&before, &self.settings(input, Some(&before))?);
        if widened && let Some(assert) = &self.config().assert_trust_change {
            let provider = coalesce(before.get("providerKey"), None)
                .and_then(Value::as_str)
                .unwrap_or(record_text(&before, "id"))
                .to_owned();
            assert(credential.clone(), tenant_id.clone(), provider).await?;
        }
        let (tenant_ref, connection_ref, principal_ref, before_ref) =
            (&tenant_id, &connection_id, &principal, &before);
        let record = self
            .config()
            .store
            .transaction(|tx| async move {
                async {
                    let current = self
                        .managed(tx.as_ref(), tenant_ref, connection_ref)
                        .await?;
                    let values = self.settings(input, Some(&current))?;
                    if trust_widened(&current, &values)
                        && (!widened || current.get("updatedAt") != before_ref.get("updatedAt"))
                    {
                        return Err(SamlError::Iam(IamError::with_status(
                            "CONFLICT",
                            "The connection changed while it was being updated; try again.",
                            409,
                        )));
                    }
                    let mut record = current.clone();
                    for (key, value) in values {
                        record.insert(key, value);
                    }
                    record.insert("updatedAt".into(), number(js::now_ms()));
                    tx.put("samlConnections", &record).await?;
                    Self::audit(
                        tx.as_ref(),
                        principal_ref,
                        tenant_ref,
                        "iam:saml:UpdateConnection",
                        record_text(&current, "id"),
                    )
                    .await?;
                    Ok(record)
                }
                .await
                .map_err(into_iam)
            })
            .await
            .map_err(from_iam)?;
        self.summary(&record)
    }

    /// Removes a managed connection, its pending sign-ins and the account links made through it (a connection created
    /// later, even with the same ID, never inherits them).
    pub async fn delete_connection(
        &self,
        credential: &CredentialInput,
        tenant_id: &str,
        connection_id: &str,
    ) -> SamlResult<()> {
        let principal = self
            .manager(
                credential,
                "iam:saml:connections:delete",
                tenant_id,
                connection_id,
            )
            .await?;
        let principal = &principal;
        self.config()
            .store
            .transaction(|tx| async move {
                async {
                    let current = self.managed(tx.as_ref(), tenant_id, connection_id).await?;
                    let id = record_text(&current, "id").to_owned();
                    tx.delete("samlConnections", &id).await?;
                    for relay in tx
                        .find(
                            "samlRelays",
                            &Filter::new().eq("connectionId", id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        tx.delete("samlRelays", record_text(&relay, "id")).await?;
                    }
                    // Connections from before provider keys share their ID with the links; only this IdP's own links go.
                    let provider_key = coalesce(current.get("providerKey"), None).cloned();
                    let provider = provider_key.clone().unwrap_or(Value::String(id.clone()));
                    for link in tx
                        .find(
                            "externalIdentities",
                            &Filter::new()
                                .eq(
                                    "tenantId",
                                    current.get("tenantId").cloned().unwrap_or(Value::Null),
                                )
                                .eq("providerId", provider),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        if truthy(provider_key.as_ref())
                            || link.get("issuer") == current.get("idpIssuer")
                        {
                            tx.delete("externalIdentities", record_text(&link, "id"))
                                .await?;
                        }
                    }
                    Self::audit(
                        tx.as_ref(),
                        principal,
                        tenant_id,
                        "iam:saml:DeleteConnection",
                        &id,
                    )
                    .await?;
                    Ok(())
                }
                .await
                .map_err(into_iam)
            })
            .await
            .map_err(from_iam)
    }

    /// Revokes the local IAM session; upstream SAML sessions are not modified.
    pub async fn logout(&self, credential: &CredentialInput) -> SamlResult<Value> {
        let Some(revoke) = &self.config().revoke_session else {
            return Err(configuration("Local logout callback is required."));
        };
        Ok(revoke(credential.clone()).await?)
    }

    // --- HTTP ---------------------------------------------------------------------------------------------------

    /// The assertion consumer service: HTTP-POST binding, browser-binding cookie, then `callback`.
    async fn acs(&self, item: &SamlConnection, request: &HttpRequest) -> HttpResponse {
        match self.acs_inner(item, request).await {
            Ok(response) => response,
            Err(error) => {
                let mut headers: Vec<(String, String)> =
                    vec![("cache-control".into(), "no-store".into())];
                // The specific code only goes to the configured error page; the JSON answer stays generic.
                if let Some(error_url) = &self.inner.error_url {
                    let code = match error.as_iam() {
                        Some(error) if ERROR_CODE.is_match(&error.code) => error.code.clone(),
                        _ => "SAML_INVALID".to_owned(),
                    };
                    if let Some(mut target) = url::Url::parse("https://placeholder.invalid")
                        .ok()
                        .and_then(|base| base.join(error_url).ok())
                    {
                        set_search_param(&mut target, "error", &code);
                        let value = if error_url.starts_with('/') {
                            let mut path = target.path().to_owned();
                            if let Some(query) = target.query().filter(|query| !query.is_empty()) {
                                path.push('?');
                                path.push_str(query);
                            }
                            if let Some(fragment) =
                                target.fragment().filter(|fragment| !fragment.is_empty())
                            {
                                path.push('#');
                                path.push_str(fragment);
                            }
                            path
                        } else {
                            target.to_string()
                        };
                        headers.push((REDIRECT_HEADER.into(), value));
                    }
                }
                json_response(401, &json!({ "error": "SAML_INVALID" }), &headers)
            }
        }
    }

    async fn acs_inner(
        &self,
        item: &SamlConnection,
        request: &HttpRequest,
    ) -> SamlResult<HttpResponse> {
        if !header(request, "content-type")
            .is_some_and(|value| value.starts_with("application/x-www-form-urlencoded"))
        {
            return Err(SamlError::Iam(IamError::with_status(
                "SAML_INVALID",
                "SAML POST binding is required.",
                415,
            )));
        }
        let body = String::from_utf8_lossy(request.body()).into_owned();
        if js::utf16_len(&body) > 2_000_000 {
            return Err(SamlError::Iam(IamError::with_status(
                "SAML_INVALID",
                "SAML response is too large.",
                413,
            )));
        }
        let form: Vec<(String, String)> = url::form_urlencoded::parse(body.as_bytes())
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        let all = |name: &str| -> Vec<&String> {
            form.iter()
                .filter(|(key, _)| key == name)
                .map(|(_, value)| value)
                .collect()
        };
        let bad_parameters = || {
            SamlError::Iam(IamError::with_status(
                "SAML_INVALID",
                "Invalid SAML POST parameters.",
                400,
            ))
        };
        if all("SAMLResponse").len() != 1 || all("RelayState").len() > 1 {
            return Err(bad_parameters());
        }
        let saml_response = all("SAMLResponse")[0].clone();
        // Responses that answer no request are IdP-initiated; only connections that opt in accept them.
        if item.allow_idp_initiated && !Self::answers_request(&saml_response) {
            let result = self.idp_initiated(&item.id, &saml_response).await?;
            return Ok(self.signed_in(
                item,
                &result,
                None,
                vec![("cache-control".into(), "no-store".into())],
            ));
        }
        if all("RelayState").len() != 1 {
            return Err(bad_parameters());
        }
        let cookie_name = format!("__Host-better-iam-saml-{}", &hash(&item.id)[..12]);
        let binding = header(request, "cookie")
            .and_then(|cookies| {
                cookies
                    .split(';')
                    .map(|value| js::trim(value).to_owned())
                    .find(|value| value.starts_with(&format!("{cookie_name}=")))
                    .map(|value| value[cookie_name.len() + 1..].to_owned())
            })
            .unwrap_or_default();
        let (result, return_to) = self
            .consume(
                &item.id,
                &CallbackInput {
                    saml_response,
                    relay_state: all("RelayState")[0].clone(),
                    binding,
                },
            )
            .await?;
        Ok(self.signed_in(
            item,
            &result,
            return_to.as_deref(),
            vec![
                ("cache-control".into(), "no-store".into()),
                (
                    "set-cookie".into(),
                    format!("{cookie_name}=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0"),
                ),
            ],
        ))
    }

    /// The ACS answer for a completed SAML exchange: the host's result as JSON and, with `afterSignIn`, the redirect
    /// hint the host's protocol mount turns into a 303. An MFA challenge goes to `mfaUrl` in the fragment, so it never
    /// reaches a server log or a Referer header.
    fn signed_in(
        &self,
        item: &SamlConnection,
        result: &Value,
        return_to: Option<&str>,
        mut headers: Vec<(String, String)>,
    ) -> HttpResponse {
        if let (Some(after_sign_in), Some(value)) = (&self.inner.after_sign_in, result.as_object())
        {
            if value.get("mfaRequired") == Some(&Value::Bool(true))
                && value.get("challenge").is_some_and(Value::is_string)
            {
                let mut fragment: Vec<(String, String)> =
                    vec![("tenantId".into(), item.tenant_id.clone())];
                let mut set = |key: &str, field: String| match fragment
                    .iter()
                    .position(|(existing, _)| existing == key)
                {
                    Some(position) => {
                        fragment[position].1 = field;
                        let mut index = 0;
                        fragment.retain(|(existing, _)| {
                            let keep = existing != key || index == position;
                            index += 1;
                            keep
                        });
                    }
                    None => fragment.push((key.to_owned(), field)),
                };
                for (key, field) in value {
                    match field {
                        Value::String(text) => set(key, text.clone()),
                        Value::Bool(flag) => set(key, flag.to_string()),
                        _ => {}
                    }
                }
                if let Some(path) = return_to.filter(|path| !path.is_empty()) {
                    set("returnTo", path.to_owned());
                }
                let serialized = url::form_urlencoded::Serializer::new(String::new())
                    .extend_pairs(fragment.iter())
                    .finish();
                let target = self
                    .inner
                    .mfa_url
                    .clone()
                    .unwrap_or_else(|| after_sign_in.clone());
                headers.push((REDIRECT_HEADER.into(), format!("{target}#{serialized}")));
            } else if value.get("token").is_some_and(Value::is_string) {
                let target = return_to
                    .map(str::to_owned)
                    .unwrap_or_else(|| after_sign_in.clone());
                headers.push((REDIRECT_HEADER.into(), target));
            }
        }
        json_response(200, result, &headers)
    }

    /// The protocol handler: the ACS of configured connections at their own callback URLs, and under the base path
    /// `{id}/acs`, `{id}/metadata` and `{id}/login`. None for requests it does not serve.
    pub async fn handler(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let request_url = request_url(request)?;
        let location = format!("{}{}", origin(&request_url), request_url.path());
        let callback_connection = self
            .inner
            .connections
            .values()
            .find(|item| item.callback_url == location);
        if let Some(item) = callback_connection
            && request.method() == http::Method::POST
        {
            return Some(self.acs(item, request).await);
        }
        let prefix = format!("{}/", self.inner.base_path);
        if !request_url.path().starts_with(&prefix) {
            return None;
        }
        Some(match self.route(request, &request_url).await {
            Ok(response) => response,
            Err(error) => match error.as_iam() {
                Some(error) => json_response(error.status, &json!({ "error": error.code }), &[]),
                None => json_response(401, &json!({ "error": "SAML_FAILED" }), &[]),
            },
        })
    }

    async fn route(
        &self,
        request: &HttpRequest,
        request_url: &url::Url,
    ) -> SamlResult<HttpResponse> {
        let rest = &request_url.path()[self.inner.base_path.len() + 1..];
        let parts: Vec<&str> = rest.split('/').collect();
        let id = decode_uri_component(parts[0]).ok_or_else(|| SamlError::plain("URI malformed"))?;
        let method = request.method();
        if method == http::Method::POST && parts.get(1) == Some(&"acs") && parts.len() == 2 {
            let item = if self.inner.connections.contains_key(&id) {
                None
            } else {
                self.connection(&id, None).await.ok()
            };
            let Some(item) = item else {
                return Ok(json_response(404, &json!({ "error": "NOT_FOUND" }), &[]));
            };
            return Ok(self.acs(&item, request).await);
        }
        if method == http::Method::GET && parts.get(1) == Some(&"metadata") && parts.len() == 2 {
            let item = self.connection(&id, None).await?;
            let metadata = self
                .saml(&item, self.config().store.clone(), None, None, false)
                .generate_service_provider_metadata(
                    item.decryption_certificate.as_deref(),
                    &item.public_certificate,
                )?;
            return Ok(response(
                200,
                &[("content-type".into(), "application/samlmetadata+xml".into())],
                metadata,
            ));
        }
        if !(method == http::Method::GET || method == http::Method::POST)
            || parts.len() != 2
            || parts[1] != "login"
        {
            return Ok(json_response(404, &json!({ "error": "NOT_FOUND" }), &[]));
        }
        if method == http::Method::POST {
            let item = self.connection(&id, None).await?;
            let origin_header = header(request, "origin");
            let trusted = match &self.config().trusted_origins {
                Some(origins) => origins.clone(),
                None => parse_url(&item.callback_url)
                    .map(|url| vec![origin(&url)])
                    .unwrap_or_default(),
            };
            if !origin_header
                .as_ref()
                .is_some_and(|origin| !origin.is_empty() && trusted.contains(origin))
                || header(request, "x-better-iam").as_deref() != Some("1")
                || !header(request, "content-type")
                    .is_some_and(|value| value.starts_with("application/json"))
            {
                return Err(SamlError::Iam(IamError::with_status(
                    "CSRF",
                    "Linking requires a trusted Origin and X-Better-IAM header.",
                    403,
                )));
            }
        }
        let return_to = request_url
            .query_pairs()
            .find(|(key, _)| key == "returnTo")
            .map(|(_, value)| Value::String(value.into_owned()));
        let linking = (method == http::Method::POST).then(|| CredentialInput {
            headers: Some(
                request
                    .headers()
                    .iter()
                    .map(|(name, value)| {
                        (
                            name.as_str().to_owned(),
                            String::from_utf8_lossy(value.as_bytes()).into_owned(),
                        )
                    })
                    .collect(),
            ),
            token: None,
        });
        let result = self
            .begin(&id, linking.as_ref(), return_to.as_ref())
            .await?;
        let headers: Vec<(String, String)> = vec![
            ("cache-control".into(), "no-store".into()),
            (
                "set-cookie".into(),
                format!(
                    "__Host-better-iam-saml-{}={}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=600",
                    &hash(&id)[..12],
                    result.binding
                ),
            ),
        ];
        if method == http::Method::POST {
            return Ok(json_response(200, &json!({ "url": result.url }), &headers));
        }
        let mut headers = headers;
        headers.push(("location".into(), result.url));
        Ok(response(302, &headers, String::new()))
    }
}

/// `URLSearchParams.set(name, value)` on a URL's query.
fn set_search_param(target: &mut url::Url, name: &str, value: &str) {
    let mut pairs: Vec<(String, String)> = target
        .query_pairs()
        .map(|(key, value)| (key.into_owned(), value.into_owned()))
        .collect();
    match pairs.iter().position(|(key, _)| key == name) {
        Some(position) => {
            pairs[position].1 = value.to_owned();
            let mut index = 0;
            pairs.retain(|(key, _)| {
                let keep = key != name || index == position;
                index += 1;
                keep
            });
        }
        None => pairs.push((name.to_owned(), value.to_owned())),
    }
    let query = url::form_urlencoded::Serializer::new(String::new())
        .extend_pairs(pairs.iter())
        .finish();
    target.set_query(if query.is_empty() { None } else { Some(&query) });
}

/// `request.headers.get(name)`: every value joined with ", ".
fn header(request: &HttpRequest, name: &str) -> Option<String> {
    let values: Vec<String> = request
        .headers()
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

/// `new URL(request.url)`: the absolute request target, or the path on the Host header's origin.
fn request_url(request: &HttpRequest) -> Option<url::Url> {
    let uri = request.uri();
    if uri.scheme().is_some() && uri.authority().is_some() {
        return url::Url::parse(&uri.to_string()).ok();
    }
    let host = header(request, "host").unwrap_or_else(|| "localhost".to_owned());
    url::Url::parse(&format!(
        "http://{host}{}",
        uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    ))
    .ok()
}

fn response(status: u16, headers: &[(String, String)], body: String) -> HttpResponse {
    let mut builder = http::Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name.as_str(), value.as_str());
    }
    builder.body(Bytes::from(body)).unwrap_or_else(|_| {
        let mut fallback = http::Response::new(Bytes::new());
        *fallback.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}

/// `Response.json(value, { status, headers })`.
fn json_response(status: u16, value: &Value, headers: &[(String, String)]) -> HttpResponse {
    let mut all: Vec<(String, String)> = vec![("content-type".into(), "application/json".into())];
    all.extend(headers.iter().cloned());
    response(status, &all, js::stringify(value))
}
