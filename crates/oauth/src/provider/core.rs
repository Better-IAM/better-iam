//! The provider state and the `oidc-provider` models the configuration enables: artifacts saved through the
//! persistent adapter (sessions, interactions, codes, tokens, grants, pushed requests, replay detection), clients
//! built from their metadata with the client schema rules, grants, claims, and the signing key store.

use std::collections::HashMap;
use std::sync::Mutex;

use better_iam_core::js;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::adapter::{Cipher, ProviderAdapterFactory, truthy};
use crate::errors::{OidcError, ProviderError, ProviderResult};
use crate::jose::{self, KeySet};

use super::OAuthResourceServer;

const URL_ALPHABET: &[u8] = b"useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict";

/// `nanoid(size = 21)`.
pub fn nanoid(size: usize) -> String {
    let bytes: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
    bytes
        .iter()
        .map(|byte| URL_ALPHABET[(byte & 63) as usize] as char)
        .collect()
}

/// `epochTime()`: whole seconds.
pub fn epoch() -> f64 {
    (js::now_ms() / 1000.0).floor()
}

pub fn num(value: f64) -> Value {
    js::number(value).unwrap_or(Value::Null)
}

pub fn s<'a>(map: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    map.get(key).and_then(Value::as_str)
}

pub fn n(map: &Map<String, Value>, key: &str) -> Option<f64> {
    map.get(key).and_then(Value::as_f64)
}

/// Splits a scope string into its set (`new Set(scope?.split(' '))`).
pub fn scope_set(scope: Option<&str>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    if let Some(scope) = scope {
        for part in scope.split(' ') {
            if !out.iter().any(|existing| existing == part) {
                out.push(part.to_owned());
            }
        }
    }
    out
}

/// The DPoP nonce challenges (`ServerChallenge`): HKDF-SHA256 over 60-second steps.
#[derive(Debug, Clone)]
pub struct ServerChallenge {
    secret: [u8; 32],
    info: String,
}

const STEP: f64 = 60.0;
pub const CHALLENGE_OK_WINDOW: f64 = STEP * 5.0;

fn hkdf_sha256(secret: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    use hmac::{Hmac, Mac};
    let mut extract = Hmac::<sha2::Sha256>::new_from_slice(salt).expect("any key length");
    extract.update(secret);
    let prk = extract.finalize().into_bytes();
    let mut out = Vec::new();
    let mut previous: Vec<u8> = Vec::new();
    let mut counter = 1u8;
    while out.len() < length {
        let mut expand = Hmac::<sha2::Sha256>::new_from_slice(&prk).expect("any key length");
        expand.update(&previous);
        expand.update(info);
        expand.update(&[counter]);
        previous = expand.finalize().into_bytes().to_vec();
        out.extend_from_slice(&previous);
        counter += 1;
    }
    out.truncate(length);
    out
}

impl ServerChallenge {
    pub fn new(secret: [u8; 32], info: &str) -> Self {
        Self {
            secret,
            info: info.to_owned(),
        }
    }

    fn compute(&self, step: i64) -> String {
        let salt = step.to_be_bytes();
        jose::b64url(&hkdf_sha256(&self.secret, &salt, self.info.as_bytes(), 32))
    }

    fn window(&self) -> Vec<String> {
        let step = (epoch() / STEP).floor() as i64;
        (step - 2..=step + 2)
            .map(|value| self.compute(value))
            .collect()
    }

    pub fn next_challenge(&self) -> String {
        self.window()[3].clone()
    }

    pub fn check_challenge(&self, challenge: &str) -> bool {
        self.window()
            .iter()
            .any(|server| jose::constant_equals(server, challenge))
    }
}

/// `ResourceServer`: the resolved settings of a resource indicator.
#[derive(Debug, Clone, PartialEq)]
pub struct ResourceServerInfo {
    pub identifier: String,
    pub scope: String,
    pub audience: String,
    pub access_token_ttl: f64,
    pub access_token_format: String,
}

impl ResourceServerInfo {
    pub fn scopes(&self) -> Vec<String> {
        scope_set(Some(&self.scope))
    }
}

/// A client loaded from its metadata (`Client`), validated with the client schema.
#[derive(Debug, Clone)]
pub struct Client {
    pub metadata: Map<String, Value>,
}

impl Client {
    pub fn client_id(&self) -> &str {
        s(&self.metadata, "client_id").unwrap_or_default()
    }
    pub fn strings(&self, key: &str) -> Vec<String> {
        self.metadata
            .get(key)
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
    pub fn grant_type_allowed(&self, grant: &str) -> bool {
        self.strings("grant_types")
            .iter()
            .any(|value| value == grant)
    }
    pub fn response_type_allowed(&self, response_type: &str) -> bool {
        self.strings("response_types")
            .iter()
            .any(|value| value == response_type)
    }
    pub fn auth_method(&self) -> &str {
        s(&self.metadata, "token_endpoint_auth_method").unwrap_or("client_secret_basic")
    }
    pub fn scope(&self) -> Option<&str> {
        s(&self.metadata, "scope").filter(|scope| !scope.is_empty())
    }
    pub fn application_type(&self) -> &str {
        s(&self.metadata, "application_type").unwrap_or("web")
    }
    pub fn dpop_bound(&self) -> bool {
        self.metadata.get("dpop_bound_access_tokens") == Some(&Value::Bool(true))
    }
    pub fn require_par(&self) -> bool {
        self.metadata.get("require_pushed_authorization_requests") == Some(&Value::Bool(true))
    }
    pub fn client_name(&self) -> Option<&str> {
        s(&self.metadata, "client_name")
    }
    pub fn backchannel_logout_uri(&self) -> Option<&str> {
        s(&self.metadata, "backchannel_logout_uri").filter(|uri| !uri.is_empty())
    }
    pub fn backchannel_session_required(&self) -> bool {
        self.metadata.get("backchannel_logout_session_required") == Some(&Value::Bool(true))
    }
    pub fn include_sid(&self) -> bool {
        self.backchannel_logout_uri().is_some() && self.backchannel_session_required()
    }
    pub fn id_token_alg(&self) -> &str {
        s(&self.metadata, "id_token_signed_response_alg").unwrap_or("RS256")
    }
    pub fn lifetime(&self, key: &str) -> Option<f64> {
        n(&self.metadata, key).filter(|value| *value > 0.0)
    }

    fn redirect_allowed(&self, value: &str, allowed: &[String]) -> bool {
        if allowed.iter().any(|uri| uri == value) {
            return true;
        }
        if self.application_type() != "native" {
            return false;
        }
        let Some(without) = strip_loopback_port(value) else {
            return false;
        };
        allowed
            .iter()
            .any(|uri| strip_loopback_port(uri).as_deref() == Some(without.as_str()))
    }
    pub fn redirect_uri_allowed(&self, value: &str) -> bool {
        self.redirect_allowed(value, &self.strings("redirect_uris"))
    }
    pub fn post_logout_redirect_uri_allowed(&self, value: &str) -> bool {
        self.redirect_allowed(value, &self.strings("post_logout_redirect_uris"))
    }
    /// `compareClientSecret(actual)`.
    pub fn compare_secret(&self, actual: &str) -> bool {
        jose::constant_equals(
            s(&self.metadata, "client_secret").unwrap_or_default(),
            actual,
        )
    }
    /// `checkClientSecretExpiration(message)`.
    pub fn check_secret_expiration(&self, message: &str) -> Result<(), OidcError> {
        let Some(expires) =
            n(&self.metadata, "client_secret_expires_at").filter(|value| *value != 0.0)
        else {
            return Ok(());
        };
        if epoch() - 15.0 >= expires {
            return Err(OidcError::invalid_client(Some(message)));
        }
        Ok(())
    }
}

const LOOPBACKS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// `stripLoopbackPort(uri)`.
fn strip_loopback_port(uri: &str) -> Option<String> {
    let parsed = url::Url::parse(uri).ok()?;
    if parsed.scheme() != "http" || !LOOPBACKS.contains(&hostname(&parsed).as_str()) {
        return None;
    }
    let scheme_end = uri.find("://")?;
    let authority_start = scheme_end + 3;
    let rest = &uri[authority_start..];
    let authority_end = rest
        .find(['/', '?', '#'])
        .map(|offset| authority_start + offset)
        .unwrap_or(uri.len());
    let authority = &uri[authority_start..authority_end];
    let host_start = authority.rfind('@').map(|index| index + 1).unwrap_or(0);
    let host_and_port = &authority[host_start..];
    let port_start = if host_and_port.starts_with('[') {
        let bracket = host_and_port.find(']')?;
        if host_and_port.as_bytes().get(bracket + 1) != Some(&b':') {
            return Some(uri.to_owned());
        }
        host_start + bracket + 1
    } else {
        match host_and_port.rfind(':') {
            Some(offset) => host_start + offset,
            None => return Some(uri.to_owned()),
        }
    };
    if !authority[port_start + 1..]
        .chars()
        .all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some(format!(
        "{}{}",
        &uri[..authority_start + port_start],
        &uri[authority_end..]
    ))
}

pub fn hostname(url: &url::Url) -> String {
    match url.host() {
        Some(url::Host::Ipv6(address)) => format!("[{address}]"),
        Some(host) => host.to_string(),
        None => String::new(),
    }
}

/// The client schema constants.
const RECOGNIZED_BASE: [&str; 26] = [
    "application_type",
    "client_id_issued_at",
    "client_id",
    "client_name",
    "client_secret_expires_at",
    "client_secret",
    "client_uri",
    "contacts",
    "default_acr_values",
    "default_max_age",
    "grant_types",
    "id_token_signed_response_alg",
    "initiate_login_uri",
    "jwks_uri",
    "jwks",
    "logo_uri",
    "policy_uri",
    "redirect_uris",
    "require_auth_time",
    "response_types",
    "response_modes",
    "scope",
    "sector_identifier_uri",
    "subject_type",
    "token_endpoint_auth_method",
    "tos_uri",
];
const RECOGNIZED_EXTRA: [&str; 6] = [
    "token_endpoint_auth_signing_alg",
    "post_logout_redirect_uris",
    "backchannel_logout_session_required",
    "backchannel_logout_uri",
    "require_pushed_authorization_requests",
    "dpop_bound_access_tokens",
];
pub const EXTRA_PROPERTIES: [&str; 3] = ["tenant_id", "access_token_ttl", "refresh_token_ttl"];
const BOOLS: [&str; 8] = [
    "backchannel_logout_session_required",
    "backchannel_user_code_parameter",
    "dpop_bound_access_tokens",
    "require_auth_time",
    "require_pushed_authorization_requests",
    "require_signed_request_object",
    "tls_client_certificate_bound_access_tokens",
    "use_mtls_endpoint_aliases",
];
const ARRAYS: [&str; 8] = [
    "contacts",
    "default_acr_values",
    "grant_types",
    "post_logout_redirect_uris",
    "redirect_uris",
    "response_types",
    "response_modes",
    "authorization_details_types",
];
const STRINGS: [&str; 46] = [
    "application_type",
    "authorization_encrypted_response_alg",
    "authorization_encrypted_response_enc",
    "authorization_signed_response_alg",
    "backchannel_authentication_request_signing_alg",
    "backchannel_client_notification_endpoint",
    "backchannel_logout_uri",
    "backchannel_token_delivery_mode",
    "client_id",
    "client_name",
    "client_secret",
    "client_uri",
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc",
    "id_token_signed_response_alg",
    "initiate_login_uri",
    "introspection_encrypted_response_alg",
    "introspection_encrypted_response_enc",
    "introspection_signed_response_alg",
    "jwks_uri",
    "logo_uri",
    "policy_uri",
    "request_object_encryption_alg",
    "request_object_encryption_enc",
    "request_object_signing_alg",
    "scope",
    "sector_identifier_uri",
    "subject_type",
    "tls_client_auth_san_dns",
    "tls_client_auth_san_email",
    "tls_client_auth_san_ip",
    "tls_client_auth_san_uri",
    "tls_client_auth_subject_dn",
    "token_endpoint_auth_method",
    "tos_uri",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc",
    "userinfo_signed_response_alg",
    "contacts",
    "default_acr_values",
    "grant_types",
    "post_logout_redirect_uris",
    "redirect_uris",
    "response_types",
    "response_modes",
    "authorization_details_types",
];
const WEB_URIS: [&str; 9] = [
    "backchannel_client_notification_endpoint",
    "backchannel_logout_uri",
    "client_uri",
    "initiate_login_uri",
    "jwks_uri",
    "logo_uri",
    "policy_uri",
    "sector_identifier_uri",
    "tos_uri",
];
const HTTPS_URIS: [&str; 3] = [
    "backchannel_client_notification_endpoint",
    "initiate_login_uri",
    "sector_identifier_uri",
];
const NON_SECRET_METHODS: [&str; 5] = [
    "private_key_jwt",
    "none",
    "tls_client_auth",
    "self_signed_tls_client_auth",
    "attest_jwt_client_auth",
];
pub const CLIENT_AUTH_METHODS: [&str; 5] = [
    "client_secret_basic",
    "client_secret_jwt",
    "client_secret_post",
    "private_key_jwt",
    "none",
];
pub const CLIENT_AUTH_SIGNING_ALGS: [&str; 6] =
    ["HS256", "RS256", "PS256", "ES256", "Ed25519", "EdDSA"];
pub const DPOP_SIGNING_ALGS: [&str; 3] = ["ES256", "Ed25519", "EdDSA"];

fn recognized(key: &str) -> bool {
    RECOGNIZED_BASE.contains(&key) || RECOGNIZED_EXTRA.contains(&key)
}

fn web_uri(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| url.scheme() == "https" || url.scheme() == "http")
}

fn https_uri(value: &str) -> bool {
    url::Url::parse(value).is_ok_and(|url| url.scheme() == "https")
}

/// `Client.needsSecret(metadata)`.
pub fn needs_secret(metadata: &Map<String, Value>) -> bool {
    let method = s(metadata, "token_endpoint_auth_method").unwrap_or("client_secret_basic");
    if !NON_SECRET_METHODS.contains(&method) {
        return true;
    }
    for key in [
        "id_token_signed_response_alg",
        "request_object_signing_alg",
        "token_endpoint_auth_signing_alg",
        "userinfo_signed_response_alg",
        "introspection_signed_response_alg",
        "authorization_signed_response_alg",
    ] {
        if s(metadata, key).is_some_and(|alg| alg.starts_with("HS")) {
            return true;
        }
    }
    false
}

/// The extra-metadata validator hook (`extraClientMetadata.validator`).
pub type ExtraValidator<'a> =
    &'a mut dyn FnMut(&str, &mut Map<String, Value>) -> Result<(), OidcError>;

/// What the schema needs from the provider configuration.
pub struct SchemaRules<'a> {
    pub grant_types: &'a [String],
    pub scopes: &'a [String],
    pub id_token_algs: &'a [String],
}

fn invalid(message: impl Into<String>) -> OidcError {
    OidcError::invalid_client_metadata(message)
}

/// `new Client.Schema(metadata, ctx)` with custom metadata processing: defaults, the validator hook, and every rule.
pub fn client_schema(
    input: &Map<String, Value>,
    rules: &SchemaRules<'_>,
    validator: ExtraValidator<'_>,
) -> Result<Map<String, Value>, OidcError> {
    let mut this = Map::new();
    let defaults = json!({
        "application_type": "web",
        "grant_types": ["authorization_code"],
        "id_token_signed_response_alg": "RS256",
        "post_logout_redirect_uris": [],
        "require_auth_time": false,
        "require_pushed_authorization_requests": false,
        "dpop_bound_access_tokens": false,
        "response_types": ["code"],
        "subject_type": "public",
        "token_endpoint_auth_method": "client_secret_basic",
        "backchannel_logout_session_required": false,
    });
    let order: Vec<&str> = RECOGNIZED_BASE
        .iter()
        .chain(RECOGNIZED_EXTRA.iter())
        .copied()
        .collect();
    for key in &order {
        if let Some(value) = defaults.get(*key) {
            this.insert((*key).to_owned(), value.clone());
        }
    }
    for key in order.iter().chain(EXTRA_PROPERTIES.iter()) {
        if let Some(value) = input.get(*key) {
            this.insert((*key).to_owned(), value.clone());
        }
    }
    // processCustomMetadata.
    for key in EXTRA_PROPERTIES {
        validator(key, &mut this)?;
    }
    initialize(&mut this, rules)?;
    this.retain(|key, _| recognized(key) || EXTRA_PROPERTIES.contains(&key.as_str()));
    Ok(this)
}

fn get_strings(this: &Map<String, Value>, key: &str) -> Vec<String> {
    this.get(key)
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

fn enum_check(this: &Map<String, Value>, key: &str, only: &[String]) -> Result<(), OidcError> {
    let Some(value) = this.get(key) else {
        return Ok(());
    };
    let is_array = ARRAYS.contains(&key);
    if is_array {
        let values = value.as_array().cloned().unwrap_or_default();
        if !values.iter().all(|value| {
            value
                .as_str()
                .is_some_and(|value| only.iter().any(|o| o == value))
        }) {
            return Err(invalid(if only.is_empty() {
                format!("{key} must be empty (no values are allowed)")
            } else {
                format!(
                    "{key} can only contain {}",
                    super::http::format_list(only, true)
                )
            }));
        }
    } else if !value
        .as_str()
        .is_some_and(|value| only.iter().any(|o| o == value))
    {
        return Err(invalid(if only.is_empty() {
            format!("{key} must not be provided (no values are allowed)")
        } else {
            format!("{key} must be {}", super::http::format_list(only, true))
        }));
    }
    Ok(())
}

fn redirect_uris_check(this: &Map<String, Value>, key: &str) -> Result<(), OidcError> {
    let application_type = s(this, "application_type").unwrap_or("web").to_owned();
    let implicit = get_strings(this, "grant_types")
        .iter()
        .any(|grant| grant == "implicit");
    for uri in get_strings(this, key) {
        let Ok(parsed) = url::Url::parse(&uri) else {
            return Err(invalid(format!("{key} must only contain valid uris")));
        };
        if parsed.as_str().contains('#') {
            return Err(invalid(format!("{key} must not contain fragments")));
        }
        let host = hostname(&parsed);
        let protocol = format!("{}:", parsed.scheme());
        match application_type.as_str() {
            "web" => {
                if protocol != "https:" && protocol != "http:" {
                    return Err(invalid(format!("{key} must only contain web uris")));
                }
                if implicit {
                    if protocol == "http:" {
                        return Err(invalid(format!(
                            "{key} for web clients using implicit flow MUST only register URLs using the https scheme"
                        )));
                    }
                    if host == "localhost" {
                        return Err(invalid(format!(
                            "{key} for web clients using implicit flow must not be using localhost"
                        )));
                    }
                }
            }
            "native" => match protocol.as_str() {
                "http:" => {
                    if !LOOPBACKS.contains(&host.as_str()) {
                        return Err(invalid(format!(
                            "{key} for native clients using http as a protocol can only use loopback addresses as hostnames"
                        )));
                    }
                }
                "https:" => {
                    if LOOPBACKS.contains(&host.as_str()) {
                        return Err(invalid(format!(
                            "{key} for native clients using claimed HTTPS URIs must not be using {host} as hostname"
                        )));
                    }
                }
                other => {
                    if [
                        "javascript:",
                        "vbscript:",
                        "data:",
                        "blob:",
                        "file:",
                        "about:",
                    ]
                    .contains(&other)
                    {
                        return Err(invalid(format!(
                            "{key} must not use the {} URI scheme",
                            &other[..other.len() - 1]
                        )));
                    }
                }
            },
            _ => {}
        }
    }
    Ok(())
}

fn initialize(this: &mut Map<String, Value>, rules: &SchemaRules<'_>) -> Result<(), OidcError> {
    // required
    let mut checked = vec!["client_id"];
    if needs_secret(this) {
        checked.push("client_secret");
    }
    let response_types_nonempty = this
        .get("response_types")
        .and_then(Value::as_array)
        .is_some_and(|values| !values.is_empty());
    if response_types_nonempty {
        checked.push("redirect_uris");
    } else if this.get("redirect_uris").is_none() {
        this.insert("redirect_uris".into(), json!([]));
    }
    for prop in checked {
        if !truthy(this.get(prop)) {
            return Err(invalid(format!("{prop} is mandatory property")));
        }
    }
    let method = s(this, "token_endpoint_auth_method").unwrap_or("client_secret_basic");
    if ["private_key_jwt", "self_signed_tls_client_auth"].contains(&method)
        && this.get("jwks").is_none()
        && this.get("jwks_uri").is_none()
    {
        return Err(invalid("jwks or jwks_uri is mandatory for this client"));
    }
    // booleans
    for prop in BOOLS {
        if let Some(value) = this.get(prop)
            && !value.is_boolean()
        {
            return Err(invalid(format!("{prop} must be a boolean")));
        }
    }
    // arrays
    for prop in ARRAYS {
        if let Some(value) = this.get(prop).cloned() {
            let Value::Array(values) = value else {
                return Err(invalid(format!("{prop} must be an array")));
            };
            let mut unique: Vec<Value> = Vec::new();
            for value in values {
                if !unique.contains(&value) {
                    unique.push(value);
                }
            }
            this.insert(prop.to_owned(), Value::Array(unique));
        }
    }
    // strings
    for prop in STRINGS {
        if let Some(value) = this.get(prop) {
            let is_array = ARRAYS.contains(&prop);
            let values: Vec<Value> = if is_array {
                value.as_array().cloned().unwrap_or_default()
            } else {
                vec![value.clone()]
            };
            for value in values {
                if !value.as_str().is_some_and(|text| !text.is_empty()) {
                    return Err(invalid(if is_array {
                        format!("{prop} must only contain strings")
                    } else {
                        format!("{prop} must be a non-empty string if provided")
                    }));
                }
            }
        }
    }
    // syntax
    for prop in ["client_id", "client_secret"] {
        if let Some(value) = s(this, prop)
            && value.chars().any(|c| !(' '..='~').contains(&c))
        {
            return Err(invalid(format!("invalid {prop} value")));
        }
    }
    // normalizeResponseTypes
    let response_types: Vec<Value> = get_strings(this, "response_types")
        .iter()
        .map(|value| {
            let mut parts: Vec<&str> = Vec::new();
            for part in value.split(' ') {
                if !parts.contains(&part) {
                    parts.push(part);
                }
            }
            parts.sort_unstable();
            Value::String(parts.join(" "))
        })
        .collect();
    this.insert("response_types".into(), Value::Array(response_types));
    // enums
    enum_check(
        this,
        "application_type",
        &["native".to_owned(), "web".to_owned()],
    )?;
    enum_check(this, "default_acr_values", &[])?;
    enum_check(this, "grant_types", rules.grant_types)?;
    enum_check(this, "id_token_signed_response_alg", rules.id_token_algs)?;
    enum_check(this, "response_types", &["code".to_owned()])?;
    enum_check(
        this,
        "response_modes",
        &[
            "query".to_owned(),
            "fragment".to_owned(),
            "form_post".to_owned(),
        ],
    )?;
    enum_check(this, "subject_type", &["public".to_owned()])?;
    let methods: Vec<String> = CLIENT_AUTH_METHODS
        .iter()
        .map(|m| (*m).to_owned())
        .collect();
    enum_check(this, "token_endpoint_auth_method", &methods)?;
    let signing: Vec<String> = match s(this, "token_endpoint_auth_method") {
        Some("private_key_jwt") => CLIENT_AUTH_SIGNING_ALGS
            .iter()
            .filter(|alg| !alg.starts_with("HS"))
            .map(|a| (*a).to_owned())
            .collect(),
        Some("client_secret_jwt") => CLIENT_AUTH_SIGNING_ALGS
            .iter()
            .filter(|alg| alg.starts_with("HS"))
            .map(|a| (*a).to_owned())
            .collect(),
        _ => Vec::new(),
    };
    enum_check(this, "token_endpoint_auth_signing_alg", &signing)?;
    // webUris
    for prop in WEB_URIS {
        if let Some(value) = this.get(prop) {
            let https = HTTPS_URIS.contains(&prop);
            let ok = value.as_str().is_some_and(|value| {
                if https {
                    https_uri(value)
                } else {
                    web_uri(value)
                }
            });
            if !ok {
                return Err(invalid(format!(
                    "{prop} must be a {} uri",
                    if https { "https" } else { "web" }
                )));
            }
        }
    }
    // scopes
    if let Some(scope) = s(this, "scope")
        .filter(|scope| !scope.is_empty())
        .map(str::to_owned)
    {
        let parsed = scope_set(Some(&scope));
        if parsed.iter().any(|value| !rules.scopes.contains(value)) {
            return Err(invalid(
                "scope must only contain Authorization Server supported scope values",
            ));
        }
        this.insert("scope".into(), json!(parsed.join(" ")));
    }
    if this.get("post_logout_redirect_uris").is_some() {
        redirect_uris_check(this, "post_logout_redirect_uris")?;
    }
    redirect_uris_check(this, "redirect_uris")?;
    // checkContacts
    let email =
        regex::Regex::new(r"^[a-zA-Z0-9.!#$%&’*+/=?^_`{|}~-]+@[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*$")
            .expect("valid regex");
    for contact in get_strings(this, "contacts") {
        if !email.is_match(&contact) {
            return Err(invalid("contacts can only contain email addresses"));
        }
    }
    for prop in ["default_max_age", "client_secret_expires_at"] {
        if let Some(value) = this.get(prop) {
            let ok = value
                .as_f64()
                .is_some_and(|value| js::is_safe_integer(value) && value >= 0.0);
            if !ok {
                return Err(invalid(format!("{prop} must be a non-negative integer")));
            }
        }
    }
    let mut response_set: Vec<String> = Vec::new();
    for value in get_strings(this, "response_types") {
        for part in value.split(' ') {
            if !response_set.iter().any(|existing| existing == part) {
                response_set.push(part.to_owned());
            }
        }
    }
    if !response_set.is_empty() && get_strings(this, "redirect_uris").is_empty() {
        return Err(invalid("redirect_uris must contain members"));
    }
    if !response_set.is_empty()
        && this
            .get("response_modes")
            .and_then(Value::as_array)
            .is_some_and(Vec::is_empty)
    {
        return Err(invalid("response_modes must contain members"));
    }
    let mut grants = get_strings(this, "grant_types");
    let has = |name: &str| response_set.iter().any(|value| value == name);
    if has("code") && !grants.iter().any(|grant| grant == "authorization_code") {
        grants.push("authorization_code".into());
    }
    if (has("token") || has("id_token")) && !grants.iter().any(|grant| grant == "implicit") {
        grants.push("implicit".into());
    }
    if grants.iter().any(|grant| grant == "implicit") && !has("id_token") && !has("token") {
        grants.retain(|grant| grant != "implicit");
    }
    if grants.iter().any(|grant| grant == "authorization_code") && !has("code") {
        grants.retain(|grant| grant != "authorization_code");
    }
    this.insert("grant_types".into(), json!(grants));
    if this.get("jwks").is_some() && this.get("jwks_uri").is_some() {
        return Err(invalid(
            "jwks and jwks_uri must not be used at the same time",
        ));
    }
    if let Some(jwks) = this.get("jwks") {
        validate_client_jwks(jwks)?;
    }
    Ok(())
}

type JwkRule<'a> = (
    &'a [&'a str],
    &'a [&'a str],
    Option<(&'a str, &'a [&'a str])>,
);

/// `validateJWKS` + `checkJWK` for the inline keys of a client: the usable public keys.
pub fn validate_client_jwks(jwks: &Value) -> Result<Vec<Map<String, Value>>, OidcError> {
    let invalid_set = || OidcError::invalid_client_metadata("client JSON Web Key Set is invalid");
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(invalid_set)?;
    if !keys.iter().all(Value::is_object) {
        return Err(invalid_set());
    }
    let mut out = Vec::new();
    for key in keys {
        let jwk = key.as_object().cloned().unwrap_or_default();
        let kty = s(&jwk, "kty")
            .filter(|kty| !kty.is_empty())
            .ok_or_else(invalid_set)?
            .to_owned();
        let (required, private, subtype): JwkRule<'_> = match kty.as_str() {
            "EC" => (
                &["x", "y"],
                &["d"],
                Some(("crv", &["P-256", "P-384", "P-521"])),
            ),
            "OKP" => (&["x"], &["d"], Some(("crv", &["Ed25519", "X25519"]))),
            "AKP" => (&["alg", "pub"], &["priv"], None),
            "RSA" => (&["e", "n"], &["d", "p", "q", "dp", "dq", "qi", "oth"], None),
            "oct" => return Err(invalid_set()),
            _ => continue,
        };
        if let Some((parameter, values)) = subtype {
            let value = s(&jwk, parameter)
                .filter(|v| !v.is_empty())
                .ok_or_else(invalid_set)?;
            if !values.contains(&value) {
                continue;
            }
        }
        for parameter in required {
            if !s(&jwk, parameter).is_some_and(|v| !v.is_empty()) {
                return Err(invalid_set());
            }
        }
        for parameter in private {
            if jwk.get(*parameter).is_some() {
                return Err(invalid_set());
            }
        }
        for parameter in ["alg", "kid", "use"] {
            if let Some(value) = jwk.get(parameter)
                && !value.as_str().is_some_and(|v| !v.is_empty())
            {
                return Err(invalid_set());
            }
        }
        if let Some(x5c) = jwk.get("x5c")
            && !x5c.as_array().is_some_and(|items| {
                items
                    .iter()
                    .all(|item| item.as_str().is_some_and(|v| !v.is_empty()))
            })
        {
            return Err(invalid_set());
        }
        out.push(jwk);
    }
    Ok(out)
}

/// The provider signing key store (`instance(provider).keystore`) and its public set.
#[derive(Debug, Clone)]
pub struct KeyStore {
    pub keys: Vec<jose::SigningKey>,
    pub public: Value,
    pub id_token_algs: Vec<String>,
}

/// `initializeKeystore(jwks)`.
pub fn initialize_keystore(jwks: &Value) -> Result<KeyStore, String> {
    let keys = jwks
        .get("keys")
        .and_then(Value::as_array)
        .ok_or_else(|| "keystore must be a JSON Web Key Set formatted object".to_owned())?;
    let mut out = Vec::new();
    let mut kids: Vec<String> = Vec::new();
    let enabled = ["RS256", "PS256", "ES256", "Ed25519", "EdDSA"];
    let mut id_token_algs: Vec<String> = Vec::new();
    for (index, key) in keys.iter().enumerate() {
        let mut jwk = key
            .as_object()
            .cloned()
            .ok_or_else(|| format!("jwks.keys[{index}] is invalid"))?;
        let kty = s(&jwk, "kty").unwrap_or_default().to_owned();
        if !["RSA", "EC", "OKP"].contains(&kty.as_str()) {
            return Err(format!(
                "only RSA, EC, OKP, or AKP keys should be part of jwks configuration (index {index})"
            ));
        }
        if jwk.get("kid").is_none()
            && let Some(kid) = jose::calculate_kid(&jwk)
        {
            jwk.insert("kid".into(), json!(kid));
        }
        let kid = s(&jwk, "kid")
            .filter(|kid| !kid.is_empty())
            .ok_or_else(|| {
                format!("jwks.keys[{index}].kid configuration must be a non-empty string")
            })?
            .to_owned();
        if kids.contains(&kid) {
            return Err("jwks.keys configuration must not contain duplicate \"kid\" values".into());
        }
        kids.push(kid.clone());
        let required: &[&str] = match kty.as_str() {
            "OKP" => &["crv", "x", "d"],
            "EC" => &["crv", "x", "y", "d"],
            _ => &["e", "n", "d", "p", "q", "dp", "dq", "qi"],
        };
        for parameter in required {
            if !s(&jwk, parameter).is_some_and(|v| !v.is_empty()) {
                return Err(format!(
                    "jwks.keys[{index}].{parameter} configuration must be a non-empty string"
                ));
            }
        }
        let use_value = s(&jwk, "use").map(str::to_owned);
        let algorithms: Vec<&'static str> = if use_value.as_deref().is_some_and(|u| u != "sig") {
            Vec::new()
        } else {
            jose::key_algorithms(&jwk)
        };
        for alg in &algorithms {
            if enabled.contains(alg) && !id_token_algs.iter().any(|existing| existing == alg) {
                id_token_algs.push((*alg).to_owned());
            }
        }
        if algorithms.len() == 1 && s(&jwk, "alg") != Some(algorithms[0]) {
            jwk.insert("alg".into(), json!(algorithms[0]));
        }
        if !algorithms.is_empty() && use_value.as_deref() != Some("sig") {
            jwk.insert("use".into(), json!("sig"));
        }
        if algorithms.is_empty() {
            return Err(format!(
                "jwks.keys[{index}] is of no use given the other configuration, remove it"
            ));
        }
        let key = jose::import_jwk(&jwk).map_err(|error| error.to_string())?;
        out.push(jose::SigningKey {
            jwk,
            kid: Some(kid),
            algorithms,
            key,
        });
    }
    // idTokenSigningAlgValues keep the configured order of the allow list.
    let id_token_algs: Vec<String> = enabled
        .iter()
        .filter(|alg| id_token_algs.iter().any(|existing| existing == *alg))
        .map(|alg| (*alg).to_owned())
        .collect();
    let public: Vec<Value> = out
        .iter()
        .map(|key| {
            let mut public = Map::new();
            for member in [
                "kty", "use", "key_ops", "kid", "alg", "crv", "e", "n", "x", "x5c", "y", "pub",
            ] {
                if let Some(value) = key.jwk.get(member) {
                    public.insert(member.to_owned(), value.clone());
                }
            }
            Value::Object(public)
        })
        .collect();
    Ok(KeyStore {
        keys: out,
        public: json!({ "keys": public }),
        id_token_algs,
    })
}

impl KeyStore {
    /// `keystore.selectForSign({ alg, use: 'sig' })`: the first key serving `alg`.
    pub fn select(&self, alg: &str) -> Option<&jose::SigningKey> {
        self.keys.iter().find(|key| key.algorithms.contains(&alg))
    }
}

/// The grant model operations (`Grant`) on its payload.
pub mod grant {
    use super::*;

    const NON_REJECTABLE: [&str; 6] = ["sub", "sid", "auth_time", "acr", "amr", "iss"];

    fn openid_scope(container: Option<&Map<String, Value>>) -> String {
        container
            .and_then(|container| container.get("openid"))
            .and_then(|openid| openid.get("scope"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    fn rejected(grant: &Map<String, Value>) -> Option<&Map<String, Value>> {
        grant.get("rejected").and_then(Value::as_object)
    }

    pub fn oidc_scope(grant: &Map<String, Value>) -> String {
        let scope = openid_scope(Some(grant));
        if scope.is_empty() {
            return String::new();
        }
        match rejected(grant) {
            Some(rejected) => {
                let rejected = openid_scope(Some(rejected));
                let mut granted = scope_set(Some(&scope));
                for value in rejected.split(' ') {
                    if value != "openid" {
                        granted.retain(|existing| existing != value);
                    }
                }
                granted.join(" ")
            }
            None => scope,
        }
    }

    pub fn oidc_scope_filtered(grant: &Map<String, Value>, filter: &[String]) -> String {
        oidc_scope(grant)
            .split(' ')
            .filter(|scope| filter.iter().any(|wanted| wanted == scope))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn resource_scope_of(container: &Map<String, Value>, resource: &str) -> String {
        container
            .get("resources")
            .and_then(|resources| resources.get(resource))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    pub fn resource_scope(grant: &Map<String, Value>, resource: &str) -> String {
        let scope = resource_scope_of(grant, resource);
        if scope.is_empty() {
            return String::new();
        }
        match rejected(grant) {
            Some(rejected) => {
                let rejected = resource_scope_of(rejected, resource);
                let mut granted = scope_set(Some(&scope));
                for value in rejected.split(' ') {
                    granted.retain(|existing| existing != value);
                }
                granted.join(" ")
            }
            None => scope,
        }
    }

    pub fn resource_scope_filtered(
        grant: &Map<String, Value>,
        resource: &str,
        filter: &[String],
    ) -> String {
        resource_scope(grant, resource)
            .split(' ')
            .filter(|scope| filter.iter().any(|wanted| wanted == scope))
            .collect::<Vec<_>>()
            .join(" ")
    }

    pub fn oidc_scope_encountered(grant: &Map<String, Value>) -> Vec<String> {
        let mut out: Vec<String> = oidc_scope(grant).split(' ').map(str::to_owned).collect();
        out.extend(openid_scope(rejected(grant)).split(' ').map(str::to_owned));
        out
    }

    pub fn resource_scope_encountered(grant: &Map<String, Value>, resource: &str) -> Vec<String> {
        let mut out: Vec<String> = resource_scope(grant, resource)
            .split(' ')
            .map(str::to_owned)
            .collect();
        out.extend(
            rejected(grant)
                .map(|rejected| resource_scope_of(rejected, resource))
                .unwrap_or_default()
                .split(' ')
                .map(str::to_owned),
        );
        out
    }

    fn claims_of(container: Option<&Map<String, Value>>) -> Vec<String> {
        container
            .and_then(|container| container.get("openid"))
            .and_then(|openid| openid.get("claims"))
            .and_then(Value::as_array)
            .map(|values| {
                values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn oidc_claims(grant: &Map<String, Value>) -> Vec<String> {
        let claims = claims_of(Some(grant));
        match rejected(grant) {
            Some(rejected) if !claims.is_empty() => {
                let rejected = claims_of(Some(rejected));
                claims
                    .into_iter()
                    .filter(|claim| {
                        NON_REJECTABLE.contains(&claim.as_str()) || !rejected.contains(claim)
                    })
                    .collect()
            }
            _ => claims,
        }
    }

    pub fn rejected_oidc_claims(grant: &Map<String, Value>) -> Vec<String> {
        claims_of(rejected(grant))
    }

    pub fn oidc_claims_encountered(grant: &Map<String, Value>) -> Vec<String> {
        let mut out = oidc_claims(grant);
        out.extend(rejected_oidc_claims(grant));
        out
    }

    pub fn add_oidc_scope(grant: &mut Map<String, Value>, scope: &str) {
        let openid = grant.entry("openid").or_insert_with(|| json!({}));
        if let Value::Object(openid) = openid {
            let existing = openid
                .get("scope")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if existing.is_empty() {
                openid.insert("scope".into(), json!(scope));
            } else {
                let mut merged = scope_set(Some(&existing));
                for value in scope.split(' ') {
                    if !merged.iter().any(|existing| existing == value) {
                        merged.push(value.to_owned());
                    }
                }
                openid.insert("scope".into(), json!(merged.join(" ")));
            }
        }
    }

    pub fn add_oidc_claims(grant: &mut Map<String, Value>, claims: &[String]) {
        let openid = grant.entry("openid").or_insert_with(|| json!({}));
        if let Value::Object(openid) = openid {
            let mut existing: Vec<String> = openid
                .get("claims")
                .and_then(Value::as_array)
                .map(|values| {
                    values
                        .iter()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default();
            if openid.get("claims").is_some() {
                for claim in claims {
                    if !existing.contains(claim) {
                        existing.push(claim.clone());
                    }
                }
            } else {
                existing = claims.to_vec();
            }
            openid.insert("claims".into(), json!(existing));
        }
    }

    pub fn add_resource_scope(grant: &mut Map<String, Value>, resource: &str, scopes: &[String]) {
        let scope = scopes.join(" ");
        let resources = grant.entry("resources").or_insert_with(|| json!({}));
        if let Value::Object(resources) = resources {
            let existing = resources
                .get(resource)
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            if existing.is_empty() {
                resources.insert(resource.to_owned(), json!(scope));
            } else {
                let mut merged = scope_set(Some(&existing));
                for value in scope.split(' ') {
                    if !merged.iter().any(|existing| existing == value) {
                        merged.push(value.to_owned());
                    }
                }
                resources.insert(resource.to_owned(), json!(merged.join(" ")));
            }
        }
    }

    /// `clean()`.
    pub fn clean(grant: &mut Map<String, Value>) {
        let drop_openid = grant
            .get("openid")
            .and_then(Value::as_object)
            .is_some_and(|openid| {
                !truthy(openid.get("scope"))
                    && openid
                        .get("claims")
                        .and_then(Value::as_array)
                        .is_none_or(Vec::is_empty)
            });
        if drop_openid {
            grant.shift_remove("openid");
        }
        let mut drop_resources = false;
        if let Some(Value::Object(resources)) = grant.get_mut("resources") {
            resources.retain(|_, value| truthy(Some(value)));
            drop_resources = resources.is_empty();
        }
        if drop_resources {
            grant.shift_remove("resources");
        }
    }
}

/// The claims configuration: each scope's claims, in configuration order.
#[derive(Debug, Clone)]
pub struct ClaimsConfig {
    pub scopes: IndexMap<String, Vec<String>>,
    /// Claims requestable outside scopes (`sid`, `auth_time`, `iss`).
    pub standalone: Vec<String>,
    pub supported: Vec<String>,
}

impl ClaimsConfig {
    pub fn new(configured_scopes: &[String]) -> Self {
        let mut scopes = IndexMap::new();
        scopes.insert(
            "openid".to_owned(),
            vec!["sub".to_owned(), "tenant_id".to_owned()],
        );
        scopes.insert(
            "email".to_owned(),
            vec!["email".to_owned(), "email_verified".to_owned()],
        );
        scopes.insert("profile".to_owned(), vec!["name".to_owned()]);
        scopes.insert(
            "iam".to_owned(),
            vec![
                "roles".to_owned(),
                "groups".to_owned(),
                "attributes".to_owned(),
            ],
        );
        let standalone = vec!["sid".to_owned(), "auth_time".to_owned(), "iss".to_owned()];
        let mut supported: Vec<String> = Vec::new();
        for scope in configured_scopes {
            if let Some(claims) = scopes.get(scope) {
                for claim in claims {
                    if !supported.contains(claim) {
                        supported.push(claim.clone());
                    }
                }
            }
        }
        for claim in &standalone {
            if !supported.contains(claim) {
                supported.push(claim.clone());
            }
        }
        Self {
            scopes,
            standalone,
            supported,
        }
    }

    /// `new Claims(available).scope(scope).mask(mask).rejected(rejected).result()`.
    pub fn result(
        &self,
        available: &Map<String, Value>,
        scope: &str,
        mask: &Map<String, Value>,
        rejected: &[String],
    ) -> Map<String, Value> {
        let mut filter: IndexMap<String, Value> = IndexMap::new();
        for scope in scope.split(' ') {
            if let Some(claims) = self.scopes.get(scope) {
                for claim in claims {
                    filter.entry(claim.clone()).or_insert(Value::Null);
                }
            } else if self.standalone.iter().any(|claim| claim == scope) {
                // A null claim config entry used as a scope name masks nothing (it is not a plain object).
            }
        }
        for (key, value) in mask {
            filter.insert(key.clone(), value.clone());
        }
        for claim in rejected {
            filter.shift_remove(claim);
        }
        let mut out = Map::new();
        for (key, value) in &filter {
            if !(value.is_null() || value.is_object()) || !self.supported.contains(key) {
                continue;
            }
            if let Some(found) = available.get(key) {
                out.insert(key.clone(), found.clone());
            }
        }
        out
    }
}

/// `filterClaims(source, target, grant)`: requested claims of `target` the grant allows.
pub fn filter_claims(
    source: Option<&Value>,
    target: &str,
    grant_payload: &Map<String, Value>,
) -> Map<String, Value> {
    let mut claims = source
        .and_then(|source| source.get(target))
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let requested: Vec<String> = claims.keys().cloned().collect();
    let granted: Vec<String> = grant::oidc_claims(grant_payload)
        .into_iter()
        .filter(|claim| requested.contains(claim))
        .collect();
    for claim in requested {
        if ["sub", "sid", "auth_time", "acr", "amr", "iss"].contains(&claim.as_str()) {
            continue;
        }
        if !granted.contains(&claim) {
            claims.shift_remove(&claim);
        }
    }
    claims
}

/// A key set fetched from a client's `jwks_uri` with its freshness.
#[derive(Debug, Clone)]
pub struct CachedKeys {
    pub keys: KeySet,
    pub fresh_until: f64,
}

/// State shared by every request of one provider.
pub struct Core {
    pub issuer: String,
    pub base_path: String,
    pub adapter: ProviderAdapterFactory,
    pub crypt: Cipher,
    pub keystore: KeyStore,
    pub scopes: Vec<String>,
    pub claims: ClaimsConfig,
    pub grant_types: Vec<String>,
    pub keygrip: super::http::Keygrip,
    pub secure: bool,
    pub dpop_nonces: Option<ServerChallenge>,
    pub resource_servers: IndexMap<String, OAuthResourceServer>,
    pub client_keys: Mutex<HashMap<String, CachedKeys>>,
    pub allow_insecure_localhost: bool,
}

impl std::fmt::Debug for Core {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Core")
    }
}

/// Builds a [`Client`] from stored metadata (`addClient` → `new Client(metadata)`), with the validator of the
/// provider's extra metadata.
pub fn build_client(
    core: &Core,
    metadata: &Map<String, Value>,
    validator: ExtraValidator<'_>,
) -> Result<Client, OidcError> {
    let rules = SchemaRules {
        grant_types: &core.grant_types,
        scopes: &core.scopes,
        id_token_algs: &core.keystore.id_token_algs,
    };
    let metadata = client_schema(metadata, &rules, validator)?;
    Ok(Client { metadata })
}

/// The extra metadata validator outside dynamic registration.
pub fn plain_validator(key: &str, client: &mut Map<String, Value>) -> Result<(), OidcError> {
    let value = client.get(key);
    if key == "tenant_id"
        && !value.is_some_and(|value| value.as_str().is_some_and(|v| !v.is_empty()))
    {
        return Err(OidcError::invalid_client_metadata("tenant_id is required."));
    }
    if key != "tenant_id"
        && let Some(value) = value
        && !value.as_f64().is_some_and(js::is_safe_integer)
    {
        return Err(OidcError::invalid_client_metadata(format!(
            "{key} must be an integer."
        )));
    }
    Ok(())
}

impl Core {
    /// `provider.Client.find(id)`.
    pub async fn find_client(&self, id: &str) -> ProviderResult<Option<Client>> {
        if id.is_empty() {
            return Ok(None);
        }
        let Some(metadata) = self.adapter.model("Client").find(id).await? else {
            return Ok(None);
        };
        let mut validator = plain_validator;
        Ok(Some(build_client(self, &metadata, &mut validator)?))
    }

    /// The usable verification keys of a client (`asymmetricKeyStore`), fetching `jwks_uri` when stale.
    pub async fn client_keys(&self, client: &Client, force: bool) -> ProviderResult<KeySet> {
        if let Some(jwks) = client.metadata.get("jwks") {
            return Ok(KeySet::new(validate_client_jwks(jwks)?));
        }
        let Some(uri) = s(&client.metadata, "jwks_uri").map(str::to_owned) else {
            return Ok(KeySet::default());
        };
        let cache_key = format!("{}\n{uri}", client.client_id());
        if !force
            && let Some(cached) = self
                .client_keys
                .lock()
                .unwrap_or_else(|p| p.into_inner())
                .get(&cache_key)
            && cached.fresh_until > epoch()
        {
            return Ok(cached.keys.clone());
        }
        let refresh_failed = || {
            ProviderError::Oidc(OidcError::invalid_client_metadata(
                "client JSON Web Key Set failed to be refreshed",
            ))
        };
        let fetch = super::outbound_fetch(self);
        let mut response = fetch
            .fetch(
                better_iam_auth::safe_fetch::FetchRequest::get(uri.clone())
                    .header("accept", "application/json")
                    .redirect(better_iam_auth::safe_fetch::RedirectMode::Manual),
            )
            .await
            .map_err(|_| refresh_failed())?;
        let mut fresh = vec![epoch() + 60.0];
        if let Some(cache) = response.header("cache-control")
            && let Some(captures) = regex::Regex::new(r"max-age=(\d+)")
                .expect("valid regex")
                .captures(&cache)
            && let Ok(age) = captures[1].parse::<f64>()
        {
            fresh.push(epoch() + age);
        }
        let body = response.body.json().await.map_err(|_| refresh_failed())?;
        if response.status != 200 {
            return Err(refresh_failed());
        }
        let keys = validate_client_jwks(&body).map_err(|_| refresh_failed())?;
        let set = KeySet::new(keys);
        self.client_keys
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                cache_key,
                CachedKeys {
                    keys: set.clone(),
                    fresh_until: fresh.into_iter().fold(f64::MIN, f64::max),
                },
            );
        Ok(set)
    }

    /// The resource server settings of an indicator for a client (`getResourceServerInfo`).
    pub async fn resource_server_info(
        &self,
        indicator: &str,
        client: &Client,
    ) -> ProviderResult<ResourceServerInfo> {
        let server = self.resource_servers.get(indicator);
        let row = self
            .adapter
            .store()
            .get("oauthClients", &crate::adapter::hash(client.client_id()))
            .await?;
        let allowed = row
            .as_ref()
            .and_then(|row| row.get("resources"))
            .and_then(Value::as_array)
            .is_some_and(|resources| {
                resources
                    .iter()
                    .any(|value| value.as_str() == Some(indicator))
            });
        let Some(server) = server.filter(|_| allowed) else {
            return Err(OidcError::invalid_target(Some(
                "The client may not request this resource.",
            ))
            .into());
        };
        Ok(ResourceServerInfo {
            identifier: indicator.to_owned(),
            scope: server.scopes.join(" "),
            audience: server
                .audience
                .clone()
                .unwrap_or_else(|| indicator.to_owned()),
            access_token_ttl: server.access_token_ttl.unwrap_or(900.0),
            access_token_format: server
                .access_token_format
                .clone()
                .unwrap_or_else(|| "jwt".to_owned()),
        })
    }

    /// Saves a plain model (`BaseModel.save(ttl)`: Session, Interaction, PushedAuthorizationRequest,
    /// ReplayDetection). Returns the stored payload's `jti`.
    pub async fn save_model(
        &self,
        model: &str,
        payload: &mut Map<String, Value>,
        ttl: f64,
    ) -> ProviderResult<String> {
        if !truthy(payload.get("jti")) {
            let size = if model == "PushedAuthorizationRequest" {
                21
            } else {
                43
            };
            payload.insert("jti".into(), json!(nanoid(size)));
        }
        payload.insert("kind".into(), json!(model));
        let now = epoch();
        payload.insert("exp".into(), num(now + ttl));
        if !truthy(payload.get("iat")) {
            payload.insert("iat".into(), num(now));
        }
        let jti = s(payload, "jti").unwrap_or_default().to_owned();
        let stored = stored_payload(payload);
        self.adapter
            .model(model)
            .upsert(&jti, &stored, Some(ttl))
            .await?;
        Ok(jti)
    }

    /// `Model.find(value, { ignoreExpiration })` without session binding: the payload when it verifies.
    pub async fn find_model(
        &self,
        model: &str,
        value: &str,
        ignore_expiration: bool,
    ) -> ProviderResult<Option<Map<String, Value>>> {
        if value.is_empty() {
            return Ok(None);
        }
        let Some(stored) = self.adapter.model(model).find(value).await? else {
            return Ok(None);
        };
        Ok(verify_stored(model, stored, ignore_expiration))
    }

    /// The payload's `exp` passed (`isExpired`).
    pub fn is_expired(payload: &Map<String, Value>) -> bool {
        n(payload, "exp").is_none_or(|exp| exp <= epoch())
    }
}

/// The payload a model stores: `iat`, `exp`, then its defined members (`getValueAndPayload`).
pub fn stored_payload(payload: &Map<String, Value>) -> Map<String, Value> {
    let mut out = Map::new();
    if let Some(iat) = payload.get("iat") {
        out.insert("iat".into(), iat.clone());
    }
    if let Some(exp) = payload.get("exp").filter(|value| truthy(Some(value))) {
        out.insert("exp".into(), exp.clone());
    }
    for (key, value) in payload {
        if key != "iat" && key != "exp" && !value.is_null() {
            out.insert(key.clone(), value.clone());
        }
    }
    out
}

/// `opaque.verify(stored)` + `instantiate`: refuses structured formats, an expired payload (unless ignored), and a
/// kind mismatch.
pub fn verify_stored(
    model: &str,
    stored: Map<String, Value>,
    ignore_expiration: bool,
) -> Option<Map<String, Value>> {
    if stored.contains_key("jwt")
        || stored.contains_key("jwt-ietf")
        || stored.contains_key("paseto")
    {
        return None;
    }
    if let Some(format) = stored.get("format")
        && format.as_str() != Some("opaque")
    {
        return None;
    }
    let now = epoch();
    if let Some(nbf) = stored.get("nbf") {
        let nbf = nbf.as_f64()?;
        if nbf > now + 15.0 {
            return None;
        }
    }
    if let Some(iat) = stored.get("iat") {
        let iat = iat.as_f64()?;
        if stored.get("exp").is_none() && iat > now + 15.0 {
            return None;
        }
    }
    if let Some(exp) = stored.get("exp")
        && !ignore_expiration
    {
        let exp = exp.as_f64()?;
        if now - 15.0 >= exp {
            return None;
        }
    }
    if stored.get("jti").is_some_and(|jti| !jti.is_string()) {
        return None;
    }
    if let Some(kind) = s(&stored, "kind").filter(|kind| !kind.is_empty())
        && kind != model
    {
        return None;
    }
    Some(stored)
}
