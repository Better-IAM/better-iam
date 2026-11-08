//! Resource servers (resource-server.ts): offline verification of JWT access tokens (RFC 9068) with DPoP proof of
//! possession (RFC 9449), RFC 9728 protected resource metadata, and a guard that answers failures with a
//! `WWW-Authenticate` challenge naming the metadata URL.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};

use better_iam_auth::safe_fetch::{
    FetchRequest, GuardedFetchOptions, RedirectMode, create_guarded_fetch,
};
use better_iam_core::{IamError, IamResult, js};
use bytes::Bytes;
use serde_json::{Map, Value, json};

use crate::jose::{self, KeySet, VerifyKey, VerifyOptions};

/// The asymmetric algorithms accepted for access tokens and DPoP proofs.
pub const ASYMMETRIC: [&str; 11] = jose::ASYMMETRIC;

fn invalid(message: &str) -> IamError {
    IamError::with_status("INVALID_TOKEN", message, 401)
}

fn base64url_sha256(value: &str) -> String {
    jose::sha256_b64url(value)
}

/// The URL without query and fragment (`targetUri`).
fn target_uri(value: &str) -> Option<String> {
    let mut url = url::Url::parse(value).ok()?;
    url.set_query(None);
    url.set_fragment(None);
    Some(url.to_string())
}

/// `AccessTokenVerifierOptions`.
#[derive(Debug, Clone, Default)]
pub struct AccessTokenVerifierOptions {
    /// The authorization server issuer, exactly as in its discovery document.
    pub issuer: String,
    /// The `aud` values this API accepts.
    pub audience: Vec<String>,
    /// Public signing keys; defaults to fetching `{issuer}/jwks`.
    pub jwks: Option<Value>,
    pub jwks_uri: Option<String>,
    /// Seconds of clock skew tolerated (default 30).
    pub clock_tolerance: Option<f64>,
    /// Maximum age of a DPoP proof in seconds (default 300).
    pub dpop_max_age: Option<f64>,
    /// Signature algorithms accepted for access tokens.
    pub algorithms: Option<Vec<String>>,
    /// The organization this API serves.
    pub tenant_id: Option<String>,
}

/// `ProtectedRequest`.
#[derive(Debug, Clone, Default)]
pub struct ProtectedRequest {
    pub authorization: Option<String>,
    pub dpop: Option<String>,
    pub method: String,
    pub url: String,
}

/// `VerifiedAccessToken`.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedAccessToken {
    pub subject: Option<String>,
    pub client_id: String,
    pub tenant_id: Option<String>,
    pub identity_id: Option<String>,
    pub scopes: Vec<String>,
    pub audience: Vec<String>,
    pub issued_at: Option<f64>,
    pub expires_at: f64,
    pub token_id: Option<String>,
    pub bound_key: Option<String>,
    pub actor: Option<Value>,
    pub claims: Map<String, Value>,
}

impl VerifiedAccessToken {
    /// The JSON form TypeScript returns.
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        if let Some(subject) = &self.subject {
            out.insert("subject".into(), json!(subject));
        }
        out.insert("clientId".into(), json!(self.client_id));
        if let Some(tenant) = &self.tenant_id {
            out.insert("tenantId".into(), json!(tenant));
        }
        if let Some(identity) = &self.identity_id {
            out.insert("identityId".into(), json!(identity));
        }
        out.insert("scopes".into(), json!(self.scopes));
        out.insert("audience".into(), json!(self.audience));
        if let Some(iat) = self.issued_at {
            out.insert("issuedAt".into(), js::number(iat).unwrap_or(Value::Null));
        }
        out.insert(
            "expiresAt".into(),
            js::number(self.expires_at).unwrap_or(Value::Null),
        );
        if let Some(jti) = &self.token_id {
            out.insert("tokenId".into(), json!(jti));
        }
        if let Some(bound) = &self.bound_key {
            out.insert("boundKey".into(), json!(bound));
        }
        if let Some(actor) = &self.actor {
            out.insert("actor".into(), actor.clone());
        }
        out.insert("claims".into(), Value::Object(self.claims.clone()));
        Value::Object(out)
    }
}

/// A key set fetched from a URL (`createRemoteJWKSet`): cached for ten minutes, refetched (at most every 30 seconds)
/// when no key matches a token.
pub(crate) struct RemoteKeySet {
    url: String,
    state: tokio::sync::Mutex<RemoteState>,
}

#[derive(Default)]
struct RemoteState {
    keys: Option<KeySet>,
    fetched_at: f64,
}

impl RemoteKeySet {
    pub(crate) fn new(url: String) -> Self {
        Self {
            url,
            state: tokio::sync::Mutex::new(RemoteState::default()),
        }
    }

    async fn reload(&self, state: &mut RemoteState) -> Result<(), jose::JoseError> {
        let fetch = create_guarded_fetch(GuardedFetchOptions {
            allow_private_networks: true,
            allow_insecure_localhost: true,
            any_port: true,
            max_bytes: None,
        });
        let request = FetchRequest::get(self.url.clone())
            .header("accept", "application/json")
            .redirect(RedirectMode::Manual);
        let work = async {
            let mut response = fetch
                .fetch(request)
                .await
                .map_err(|error| jose::JoseError::Invalid(error.to_string()))?;
            if response.status != 200 {
                return Err(jose::JoseError::Invalid(
                    "Expected 200 OK from the JSON Web Key Set HTTP response".into(),
                ));
            }
            let body = response
                .body
                .json()
                .await
                .map_err(|error| jose::JoseError::Invalid(error.to_string()))?;
            KeySet::from_value(&body)
        };
        let keys = tokio::time::timeout(std::time::Duration::from_millis(5000), work)
            .await
            .map_err(|_| jose::JoseError::Invalid("request timed out".into()))??;
        state.keys = Some(keys);
        state.fetched_at = js::now_ms();
        Ok(())
    }

    /// Verifies a decoded token with the remote keys.
    pub(crate) async fn verify(&self, decoded: &jose::Decoded) -> Result<(), jose::JoseError> {
        let mut state = self.state.lock().await;
        let now = js::now_ms();
        if state.keys.is_none() || now - state.fetched_at > 600_000.0 {
            self.reload(&mut state).await?;
        }
        let keys = state.keys.clone().unwrap_or_default();
        match keys.verify(decoded) {
            Err(jose::JoseError::NoMatchingKey) if js::now_ms() - state.fetched_at > 30_000.0 => {
                self.reload(&mut state).await?;
                state.keys.clone().unwrap_or_default().verify(decoded)
            }
            result => result,
        }
    }
}

enum Keys {
    Local(KeySet),
    Remote(Arc<RemoteKeySet>),
}

/// `createAccessTokenVerifier(options)`.
pub struct AccessTokenVerifier {
    issuers: Vec<String>,
    audience: Vec<String>,
    keys: Keys,
    clock_tolerance: f64,
    dpop_max_age: f64,
    algorithms: Vec<String>,
    tenant_id: Option<String>,
    seen_proofs: Mutex<VecDeque<(String, f64)>>,
}

impl std::fmt::Debug for AccessTokenVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AccessTokenVerifier")
    }
}

/// Offline verification of JWT access tokens issued for a resource server (RFC 9068), including DPoP proof of
/// possession (RFC 9449) with in-memory proof replay detection. Opaque tokens need the provider's introspection.
pub fn create_access_token_verifier(
    options: AccessTokenVerifierOptions,
) -> IamResult<AccessTokenVerifier> {
    let issuer = options
        .issuer
        .strip_suffix('/')
        .unwrap_or(&options.issuer)
        .to_owned();
    let mut issuers = vec![options.issuer.clone()];
    if issuer != options.issuer {
        issuers.push(issuer.clone());
    }
    let keys = match &options.jwks {
        Some(jwks) => Keys::Local(
            KeySet::from_value(jwks)
                .map_err(|error| IamError::new("configuration", error.to_string()))?,
        ),
        None => Keys::Remote(Arc::new(RemoteKeySet::new(
            options
                .jwks_uri
                .clone()
                .unwrap_or_else(|| format!("{issuer}/jwks")),
        ))),
    };
    Ok(AccessTokenVerifier {
        issuers,
        audience: options.audience.clone(),
        keys,
        clock_tolerance: options.clock_tolerance.unwrap_or(30.0),
        dpop_max_age: options.dpop_max_age.unwrap_or(300.0),
        algorithms: options
            .algorithms
            .clone()
            .unwrap_or_else(|| ASYMMETRIC.iter().map(|alg| (*alg).to_owned()).collect()),
        tenant_id: options.tenant_id.clone(),
        seen_proofs: Mutex::new(VecDeque::new()),
    })
}

impl AccessTokenVerifier {
    /// Refuses a proof seen before, remembering each one until it can no longer be accepted.
    fn remember_proof(&self, jti: &str, thumbprint: &str, issued_at: f64) -> IamResult<()> {
        let now = js::now_ms();
        let mut seen = self
            .seen_proofs
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        while let Some((_, expires)) = seen.front() {
            if *expires > now {
                break;
            }
            seen.pop_front();
        }
        let key = format!("{thumbprint}:{jti}");
        if let Some((_, expires)) = seen.iter().find(|(entry, _)| *entry == key)
            && *expires > now
        {
            return Err(invalid("DPoP proof was already used."));
        }
        let until =
            now.max(issued_at * 1000.0) + (self.dpop_max_age + self.clock_tolerance) * 1000.0;
        seen.retain(|(entry, _)| *entry != key);
        seen.push_back((key, until));
        Ok(())
    }

    async fn verify_token(&self, token: &str) -> IamResult<VerifiedAccessToken> {
        let options = VerifyOptions {
            issuer: Some(self.issuers.clone()),
            audience: Some(self.audience.clone()),
            typ: Some("at+jwt".into()),
            algorithms: Some(self.algorithms.clone()),
            clock_tolerance: self.clock_tolerance,
            required_claims: vec!["exp".into(), "client_id".into()],
            ..VerifyOptions::default()
        };
        let verified = match &self.keys {
            Keys::Local(keys) => jose::verify_jwt(token, VerifyKey::Set(keys), &options),
            Keys::Remote(remote) => match jose::decode(token) {
                Err(error) => Err(error),
                Ok(decoded) => {
                    let alg = decoded
                        .header
                        .get("alg")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    if !self.algorithms.iter().any(|allowed| allowed == alg) {
                        Err(jose::JoseError::AlgorithmNotAllowed)
                    } else {
                        match remote.verify(&decoded).await {
                            Ok(()) => jose::check_claims(&decoded, &options).map(|()| decoded),
                            Err(error) => Err(error),
                        }
                    }
                }
            },
        };
        let payload = verified
            .map_err(|_| invalid("The access token is invalid or expired."))?
            .payload;
        if let Some(tenant) = &self.tenant_id
            && payload.get("tenant_id").and_then(Value::as_str) != Some(tenant.as_str())
        {
            return Err(invalid(
                "The access token was issued for another organization.",
            ));
        }
        let text = |name: &str| payload.get(name).and_then(Value::as_str).map(str::to_owned);
        let actor = payload
            .get("act")
            .filter(|act| act.get("sub").is_some_and(Value::is_string) && adapter_truthy(act))
            .cloned();
        Ok(VerifiedAccessToken {
            subject: text("sub"),
            client_id: match payload.get("client_id") {
                Some(Value::String(value)) => value.clone(),
                Some(other) => js::stringify(other),
                None => String::new(),
            },
            tenant_id: text("tenant_id"),
            identity_id: text("identity_id"),
            scopes: text("scope")
                .map(|scope| {
                    scope
                        .split(' ')
                        .filter(|s| !s.is_empty())
                        .map(str::to_owned)
                        .collect()
                })
                .unwrap_or_default(),
            audience: match payload.get("aud") {
                Some(Value::Array(values)) => values
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_owned)
                    .collect(),
                Some(Value::String(aud)) if !aud.is_empty() => vec![aud.clone()],
                _ => Vec::new(),
            },
            issued_at: payload.get("iat").and_then(Value::as_f64),
            expires_at: payload
                .get("exp")
                .and_then(Value::as_f64)
                .unwrap_or_default(),
            token_id: text("jti"),
            bound_key: payload
                .get("cnf")
                .and_then(|cnf| cnf.get("jkt"))
                .and_then(Value::as_str)
                .map(str::to_owned),
            actor,
            claims: payload,
        })
    }

    fn verify_proof(
        &self,
        proof: &str,
        token: &str,
        request: &ProtectedRequest,
        bound_key: &str,
    ) -> IamResult<()> {
        let options = VerifyOptions {
            typ: Some("dpop+jwt".into()),
            algorithms: Some(ASYMMETRIC.iter().map(|alg| (*alg).to_owned()).collect()),
            max_token_age: Some(self.dpop_max_age),
            clock_tolerance: self.clock_tolerance,
            required_claims: ["iat", "jti", "htm", "htu", "ath"]
                .iter()
                .map(|c| (*c).to_owned())
                .collect(),
            ..VerifyOptions::default()
        };
        let jwk = jose::decode_protected_header(proof)
            .and_then(|header| header.get("jwk").and_then(Value::as_object).cloned());
        let payload = jose::verify_jwt(proof, VerifyKey::Embedded, &options)
            .map_err(|_| invalid("The DPoP proof is invalid."))?
            .payload;
        let thumbprint = jwk.as_ref().and_then(|jwk| jose::jwk_thumbprint(jwk).ok());
        if thumbprint.as_deref() != Some(bound_key) {
            return Err(invalid(
                "The DPoP proof key does not match the token binding.",
            ));
        }
        let htu_value = match payload.get("htu") {
            Some(Value::String(value)) => value.clone(),
            Some(other) => js::stringify(other),
            None => "undefined".into(),
        };
        let htu =
            target_uri(&htu_value).ok_or_else(|| invalid("The DPoP proof target is invalid."))?;
        let request_target = target_uri(&request.url);
        if payload.get("htm").and_then(Value::as_str)
            != Some(request.method.to_uppercase().as_str())
            || request_target.as_deref() != Some(htu.as_str())
            || payload.get("ath").and_then(Value::as_str) != Some(base64url_sha256(token).as_str())
        {
            return Err(invalid("The DPoP proof does not match this request."));
        }
        let jti = match payload.get("jti") {
            Some(Value::String(value)) => value.clone(),
            Some(other) => js::stringify(other),
            None => String::new(),
        };
        self.remember_proof(
            &jti,
            bound_key,
            payload.get("iat").map(js::to_number).unwrap_or(f64::NAN),
        )
    }

    fn require_scopes(verified: &VerifiedAccessToken, scopes: &[String]) -> IamResult<()> {
        let missing: Vec<&String> = scopes
            .iter()
            .filter(|scope| !verified.scopes.contains(scope))
            .collect();
        if !missing.is_empty() {
            return Err(IamError::with_status(
                "INSUFFICIENT_SCOPE",
                format!(
                    "Missing scope: {}.",
                    missing
                        .iter()
                        .map(|scope| scope.as_str())
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                403,
            ));
        }
        Ok(())
    }

    /// `verify(token, { scopes })`: a bearer access token string. DPoP-bound tokens are refused here.
    pub async fn verify(&self, token: &str, scopes: &[String]) -> IamResult<VerifiedAccessToken> {
        let verified = self.verify_token(token).await?;
        if verified.bound_key.is_some() {
            return Err(invalid("A DPoP-bound token requires a DPoP proof."));
        }
        Self::require_scopes(&verified, scopes)?;
        Ok(verified)
    }

    /// `verifyRequest(request, { scopes })`: the `Authorization` header, checking the DPoP proof when bound.
    pub async fn verify_request(
        &self,
        request: &ProtectedRequest,
        scopes: &[String],
    ) -> IamResult<VerifiedAccessToken> {
        let header = request.authorization.clone().unwrap_or_default();
        let pattern =
            regex::Regex::new(r"(?i)^(Bearer|DPoP) ([A-Za-z0-9._~+/-]+=*)$").expect("valid regex");
        let Some(captures) = pattern.captures(&header) else {
            return Err(invalid("An access token is required."));
        };
        let scheme = captures[1].to_lowercase();
        let token = captures[2].to_owned();
        let verified = self.verify_token(&token).await?;
        if let Some(bound) = &verified.bound_key {
            let Some(proof) = request
                .dpop
                .as_deref()
                .filter(|proof| !proof.is_empty())
                .filter(|_| scheme == "dpop")
            else {
                return Err(invalid(
                    "A DPoP-bound token requires the DPoP scheme and proof.",
                ));
            };
            self.verify_proof(proof, &token, request, bound)?;
        } else if scheme == "dpop" {
            return Err(invalid("The access token is not DPoP-bound."));
        }
        Self::require_scopes(&verified, scopes)?;
        Ok(verified)
    }

    /// `challenge(error, realm?, { resourceMetadata, scopes })`: a `WWW-Authenticate` value for a failure.
    pub fn challenge(
        &self,
        error: &IamError,
        realm: Option<&str>,
        resource_metadata: Option<&str>,
        scopes: &[String],
    ) -> String {
        challenge(error, realm, resource_metadata, scopes)
    }
}

fn adapter_truthy(value: &Value) -> bool {
    crate::adapter::truthy(Some(value))
}

fn quoted(value: &str) -> String {
    value.replace(['"', '\\'], "")
}

fn challenge(
    error: &IamError,
    realm: Option<&str>,
    resource_metadata: Option<&str>,
    scopes: &[String],
) -> String {
    let code = if error.code == "INSUFFICIENT_SCOPE" {
        "insufficient_scope"
    } else {
        "invalid_token"
    };
    let mut shared = Vec::new();
    if let Some(realm) = realm.filter(|realm| !realm.is_empty()) {
        shared.push(format!("realm=\"{}\"", quoted(realm)));
    }
    shared.push(format!("error=\"{code}\""));
    if let Some(metadata) = resource_metadata.filter(|value| !value.is_empty()) {
        shared.push(format!("resource_metadata=\"{}\"", quoted(metadata)));
    }
    if code == "insufficient_scope" && !scopes.is_empty() {
        shared.push(format!("scope=\"{}\"", quoted(&scopes.join(" "))));
    }
    let algs = format!(
        "algs=\"{}\"",
        ASYMMETRIC
            .iter()
            .filter(|alg| **alg != "Ed25519")
            .copied()
            .collect::<Vec<_>>()
            .join(" ")
    );
    let mut dpop = shared.clone();
    dpop.push(algs);
    format!("DPoP {}, Bearer {}", dpop.join(", "), shared.join(", "))
}

/// `ProtectedResourceMetadataOptions`.
#[derive(Debug, Clone, Default)]
pub struct ProtectedResourceMetadataOptions {
    pub resource: String,
    pub authorization_servers: Vec<String>,
    pub scopes: Option<Vec<String>>,
    pub resource_name: Option<String>,
    pub documentation: Option<String>,
    pub require_dpop: bool,
}

fn absolute(value: &str, label: &str) -> IamResult<url::Url> {
    let parsed = url::Url::parse(value)
        .map_err(|_| IamError::new("configuration", format!("{label} must be an absolute URL.")))?;
    if parsed.fragment().is_some() || !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(IamError::new(
            "configuration",
            format!("{label} cannot carry a fragment or credentials."),
        ));
    }
    Ok(parsed)
}

/// `protectedResourceMetadata(options)`: the RFC 9728 §2 document.
pub fn protected_resource_metadata(options: &ProtectedResourceMetadataOptions) -> IamResult<Value> {
    absolute(&options.resource, "The resource")?;
    if options.authorization_servers.is_empty() {
        return Err(IamError::new(
            "configuration",
            "At least one authorization server is required.",
        ));
    }
    for server in &options.authorization_servers {
        absolute(server, "An authorization server")?;
    }
    let mut out = Map::new();
    out.insert("resource".into(), json!(options.resource));
    out.insert(
        "authorization_servers".into(),
        json!(options.authorization_servers),
    );
    if let Some(scopes) = options.scopes.as_ref().filter(|scopes| !scopes.is_empty()) {
        out.insert("scopes_supported".into(), json!(scopes));
    }
    out.insert("bearer_methods_supported".into(), json!(["header"]));
    if let Some(name) = options
        .resource_name
        .as_ref()
        .filter(|name| !name.is_empty())
    {
        out.insert("resource_name".into(), json!(name));
    }
    if let Some(docs) = options
        .documentation
        .as_ref()
        .filter(|docs| !docs.is_empty())
    {
        out.insert("resource_documentation".into(), json!(docs));
    }
    out.insert(
        "dpop_signing_alg_values_supported".into(),
        json!(
            ASYMMETRIC
                .iter()
                .filter(|alg| **alg != "Ed25519")
                .collect::<Vec<_>>()
        ),
    );
    if options.require_dpop {
        out.insert("dpop_bound_access_tokens_required".into(), json!(true));
    }
    Ok(Value::Object(out))
}

/// `protectedResourceMetadataUrl(resource)`: `/.well-known/oauth-protected-resource` inserted before the path.
pub fn protected_resource_metadata_url(resource: &str) -> IamResult<String> {
    let parsed = absolute(resource, "The resource")?;
    let path = if parsed.path() == "/" {
        String::new()
    } else {
        parsed
            .path()
            .strip_suffix('/')
            .unwrap_or(parsed.path())
            .to_owned()
    };
    Ok(format!(
        "{}/.well-known/oauth-protected-resource{path}",
        parsed.origin().ascii_serialization()
    ))
}

/// An HTTP request a handler reads.
pub type HttpRequest = http::Request<Bytes>;
/// An HTTP response a handler answers.
pub type HttpResponse = http::Response<Bytes>;

pub(crate) fn request_url_string(request: &HttpRequest, fallback_origin: Option<&str>) -> String {
    let uri = request.uri();
    if uri.scheme().is_some() && uri.authority().is_some() {
        return uri.to_string();
    }
    let host = request
        .headers()
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(|host| format!("http://{host}"))
        .or_else(|| fallback_origin.map(str::to_owned))
        .unwrap_or_else(|| "http://localhost".to_owned());
    format!(
        "{host}{}",
        uri.path_and_query().map(|p| p.as_str()).unwrap_or("/")
    )
}

pub(crate) fn response(
    status: u16,
    headers: &[(&str, String)],
    body: impl Into<Bytes>,
) -> HttpResponse {
    let mut builder = http::Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    builder.body(body.into()).unwrap_or_else(|_| {
        let mut fallback = http::Response::new(Bytes::new());
        *fallback.status_mut() = http::StatusCode::INTERNAL_SERVER_ERROR;
        fallback
    })
}

/// `createProtectedResourceHandler(options)`: serves the metadata document at its well-known path (GET, HEAD, and
/// CORS preflight); None for every other request.
pub struct ProtectedResourceHandler {
    document: String,
    path: String,
}

impl std::fmt::Debug for ProtectedResourceHandler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ProtectedResourceHandler")
    }
}

pub fn create_protected_resource_handler(
    options: &ProtectedResourceMetadataOptions,
) -> IamResult<ProtectedResourceHandler> {
    let document = js::stringify(&protected_resource_metadata(options)?);
    let path = url::Url::parse(&protected_resource_metadata_url(&options.resource)?)
        .map(|url| url.path().to_owned())
        .unwrap_or_default();
    Ok(ProtectedResourceHandler { document, path })
}

impl ProtectedResourceHandler {
    pub fn handle(&self, request: &HttpRequest) -> Option<HttpResponse> {
        let url = request_url_string(request, None);
        let path = url::Url::parse(&url)
            .map(|url| url.path().to_owned())
            .unwrap_or_default();
        if path != self.path {
            return None;
        }
        let cors = [
            ("access-control-allow-origin", "*".to_owned()),
            (
                "access-control-allow-methods",
                "GET, HEAD, OPTIONS".to_owned(),
            ),
        ];
        let method = request.method().as_str();
        if method == "OPTIONS" {
            return Some(response(204, &cors, Bytes::new()));
        }
        if method != "GET" && method != "HEAD" {
            let mut headers = cors.to_vec();
            headers.push(("allow", "GET, HEAD, OPTIONS".to_owned()));
            return Some(response(405, &headers, Bytes::new()));
        }
        let mut headers = cors.to_vec();
        headers.push(("content-type", "application/json".to_owned()));
        headers.push(("cache-control", "public, max-age=3600".to_owned()));
        let body = if method == "HEAD" {
            Bytes::new()
        } else {
            Bytes::from(self.document.clone())
        };
        Some(response(200, &headers, body))
    }
}

/// `ResourceGuardOptions`.
#[derive(Debug, Clone, Default)]
pub struct ResourceGuardOptions {
    pub metadata: ProtectedResourceMetadataOptions,
    pub issuer: Option<String>,
    pub audience: Option<Vec<String>>,
    pub jwks: Option<Value>,
    pub jwks_uri: Option<String>,
    pub clock_tolerance: Option<f64>,
    pub required_scopes: Vec<String>,
    pub realm: Option<String>,
    pub tenant_id: Option<String>,
}

/// What [`ResourceGuard::check`] decided.
#[derive(Debug)]
pub enum GuardOutcome {
    /// The metadata document or a refusal: return it as is.
    Response(HttpResponse),
    /// An authorized request.
    Token(Box<VerifiedAccessToken>),
}

/// `createResourceGuard(options)`.
#[derive(Debug)]
pub struct ResourceGuard {
    pub metadata_url: String,
    pub verifier: AccessTokenVerifier,
    metadata: ProtectedResourceHandler,
    options: ResourceGuardOptions,
}

pub fn create_resource_guard(options: ResourceGuardOptions) -> IamResult<ResourceGuard> {
    let metadata = create_protected_resource_handler(&options.metadata)?;
    let metadata_url = protected_resource_metadata_url(&options.metadata.resource)?;
    let verifier = create_access_token_verifier(AccessTokenVerifierOptions {
        issuer: options
            .issuer
            .clone()
            .or_else(|| options.metadata.authorization_servers.first().cloned())
            .unwrap_or_default(),
        audience: options
            .audience
            .clone()
            .unwrap_or_else(|| vec![options.metadata.resource.clone()]),
        jwks: options.jwks.clone(),
        jwks_uri: options.jwks_uri.clone(),
        clock_tolerance: options.clock_tolerance,
        tenant_id: options.tenant_id.clone(),
        ..AccessTokenVerifierOptions::default()
    })?;
    Ok(ResourceGuard {
        metadata_url,
        verifier,
        metadata,
        options,
    })
}

impl ResourceGuard {
    /// Serves the metadata document, or verifies the request's access token (with `scopes` added to the required
    /// ones) and answers refusals with 401/403 and a challenge.
    pub async fn check(&self, request: &HttpRequest, scopes: &[String]) -> GuardOutcome {
        if let Some(served) = self.metadata.handle(request) {
            return GuardOutcome::Response(served);
        }
        let mut required: Vec<String> = Vec::new();
        for scope in self.options.required_scopes.iter().chain(scopes) {
            if !required.contains(scope) {
                required.push(scope.clone());
            }
        }
        let header = |name: &str| {
            let values: Vec<&str> = request
                .headers()
                .get_all(name)
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect();
            (!values.is_empty()).then(|| values.join(", "))
        };
        let Some(authorization) = header("authorization") else {
            let mut parts = Vec::new();
            if let Some(realm) = self
                .options
                .realm
                .as_ref()
                .filter(|realm| !realm.is_empty())
            {
                parts.push(format!("realm=\"{}\"", quoted(realm)));
            }
            parts.push(format!(
                "resource_metadata=\"{}\"",
                quoted(&self.metadata_url)
            ));
            if !required.is_empty() {
                parts.push(format!("scope=\"{}\"", quoted(&required.join(" "))));
            }
            return GuardOutcome::Response(response(
                401,
                &[
                    ("cache-control", "no-store".to_owned()),
                    ("www-authenticate", format!("Bearer {}", parts.join(", "))),
                ],
                Bytes::new(),
            ));
        };
        let protected = ProtectedRequest {
            authorization: Some(authorization),
            dpop: header("dpop"),
            method: request.method().as_str().to_owned(),
            url: request_url_string(request, None),
        };
        match self.verifier.verify_request(&protected, &required).await {
            Ok(token) => GuardOutcome::Token(Box::new(token)),
            Err(error) => {
                let insufficient = error.code == "INSUFFICIENT_SCOPE";
                let body = json!({
                    "error": if insufficient { "insufficient_scope" } else { "invalid_token" },
                    "error_description": error.message,
                });
                GuardOutcome::Response(response(
                    if insufficient { 403 } else { 401 },
                    &[
                        ("content-type", "application/json".to_owned()),
                        ("cache-control", "no-store".to_owned()),
                        (
                            "www-authenticate",
                            challenge(
                                &error,
                                self.options.realm.as_deref(),
                                Some(&self.metadata_url),
                                &required,
                            ),
                        ),
                    ],
                    js::stringify(&body),
                ))
            }
        }
    }
}
