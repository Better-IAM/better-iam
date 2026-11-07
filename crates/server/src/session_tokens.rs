//! Port of `packages/server/src/session-tokens.ts`: verification of IAM-signed session JWTs (`format: 'jwt'` role
//! sessions and session tokens) for downstream services.
//!
//! IAM itself verifies with the same code path before it checks the stored row. Offline verification learns of
//! revocation only at `exp`; use short lifetimes for high-risk services, or an online check
//! (`sts.getCallerIdentity`, or `iam.sessionTokens.verify` in process).
//!
//! The TypeScript module sits on `jose`; [`jose`] below ports the parts of `jose` 6 it and the web-identity verifier
//! use (`jwtVerify`, `decodeProtectedHeader`, `createLocalJWKSet`, `createRemoteJWKSet`, compact signing), with the
//! same check order, so every refusal maps to the same failure reason.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex};

use better_iam_core::{IamError, IamResult};
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::context::NowFn;
use crate::js::{ThrownError, utf16_len};

/// Longest accepted compact serialization, in characters.
pub const MAX_SESSION_TOKEN_LENGTH: f64 = 4096.0;

/// A public signing key as published at `{basePath}/.well-known/jwks.json`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicSessionJwk {
    #[serde(rename = "kty")]
    pub kty: String,
    #[serde(rename = "crv")]
    pub crv: String,
    #[serde(rename = "x")]
    pub x: String,
    #[serde(rename = "y", default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(rename = "kid")]
    pub kid: String,
    #[serde(rename = "alg")]
    pub alg: String,
    #[serde(rename = "use")]
    pub r#use: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The `typ` header of every IAM session JWT; other token classes (assertions, OAuth `at+jwt`) never carry it.
pub const SESSION_TOKEN_TYPE: &str = "biam-session+jwt";
/// The only signature algorithms IAM issues or accepts for session JWTs.
pub const SESSION_TOKEN_ALGORITHMS: [&str; 2] = ["EdDSA", "ES256"];

/// `'EdDSA' | 'ES256'`.
pub type SessionTokenAlgorithm = String;

/// The session kinds that may be issued as JWTs. User sessions and API keys are never JWTs.
const TOKEN_KINDS: [&str; 2] = ["role", "session-token"];

/// The claims of an IAM session JWT. Tags, policies, authority ids and hashes are never included.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionTokenClaims {
    #[serde(rename = "iss")]
    pub iss: String,
    /// One audience as a string, several as an array; always includes the IAM issuer for tokens IAM accepts.
    #[serde(rename = "aud")]
    pub aud: Value,
    /// The identity the session acts as.
    #[serde(rename = "sub")]
    pub sub: String,
    /// The tenant the session belongs to.
    #[serde(rename = "tid")]
    pub tid: String,
    /// The session id; equal to `jti`.
    #[serde(rename = "sid")]
    pub sid: String,
    #[serde(rename = "jti")]
    pub jti: String,
    #[serde(rename = "iat")]
    pub iat: f64,
    #[serde(rename = "nbf")]
    pub nbf: f64,
    #[serde(rename = "exp")]
    pub exp: f64,
    /// When the credential behind the session was authenticated (epoch seconds).
    #[serde(rename = "auth_time")]
    pub auth_time: f64,
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "mfa")]
    pub mfa: bool,
    #[serde(rename = "role", default, skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    #[serde(rename = "trust", default, skip_serializing_if = "Option::is_none")]
    pub trust: Option<String>,
    #[serde(rename = "src_tid", default, skip_serializing_if = "Option::is_none")]
    pub src_tid: Option<String>,
    #[serde(
        rename = "session_name",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_name: Option<String>,
    #[serde(
        rename = "source_identity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_identity: Option<String>,
    /// The OIDC provider id of a web-identity role session.
    #[serde(rename = "idp", default, skip_serializing_if = "Option::is_none")]
    pub idp: Option<String>,
    /// The verified external subject of a web-identity role session.
    #[serde(rename = "idp_sub", default, skip_serializing_if = "Option::is_none")]
    pub idp_sub: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SessionTokenClaims {
    /// The claims as the JSON object `SignJWT` serializes (numbers as JavaScript numbers, members in order).
    pub fn to_json(&self) -> Map<String, Value> {
        let mut map = Map::new();
        map.insert("iss".into(), Value::String(self.iss.clone()));
        map.insert("aud".into(), self.aud.clone());
        map.insert("sub".into(), Value::String(self.sub.clone()));
        map.insert("tid".into(), Value::String(self.tid.clone()));
        map.insert("sid".into(), Value::String(self.sid.clone()));
        map.insert("jti".into(), Value::String(self.jti.clone()));
        map.insert("iat".into(), crate::js::number(self.iat));
        map.insert("nbf".into(), crate::js::number(self.nbf));
        map.insert("exp".into(), crate::js::number(self.exp));
        map.insert("auth_time".into(), crate::js::number(self.auth_time));
        map.insert("kind".into(), Value::String(self.kind.clone()));
        map.insert("mfa".into(), Value::Bool(self.mfa));
        let optional = [
            ("role", &self.role),
            ("trust", &self.trust),
            ("src_tid", &self.src_tid),
            ("session_name", &self.session_name),
            ("source_identity", &self.source_identity),
            ("idp", &self.idp),
            ("idp_sub", &self.idp_sub),
        ];
        for (name, value) in optional {
            if let Some(value) = value {
                map.insert(name.into(), Value::String(value.clone()));
            }
        }
        for (name, value) in &self.extra {
            map.insert(name.clone(), value.clone());
        }
        map
    }
}

/// Every verification failure. `reason` is for logs and metrics; clients should only see the 401.
#[derive(Debug, Clone, PartialEq)]
pub struct SessionTokenError {
    /// `SessionTokenErrorReason`: `malformed`, `too-large`, `type`, `algorithm`, `unknown-key`, `signature`, `expired`,
    /// `not-yet-valid`, `issuer`, `audience`, `claims`, `lifetime`, `kind`, `jwks` or `revoked`.
    pub reason: String,
    pub message: String,
}

impl SessionTokenError {
    /// `INVALID_SESSION_TOKEN`.
    pub const CODE: &'static str = "INVALID_SESSION_TOKEN";
    /// 401.
    pub const STATUS: u16 = 401;

    /// `new SessionTokenError(reason, message = 'The session token is invalid or expired')`.
    pub fn new(reason: &str, message: Option<&str>) -> Self {
        Self {
            reason: reason.to_owned(),
            message: message
                .unwrap_or("The session token is invalid or expired")
                .to_owned(),
        }
    }
}

impl std::fmt::Display for SessionTokenError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for SessionTokenError {}

/// A `SessionTokenError` as the server reports it: code `INVALID_SESSION_TOKEN`, status 401.
impl From<SessionTokenError> for IamError {
    fn from(error: SessionTokenError) -> Self {
        IamError::with_status(
            SessionTokenError::CODE,
            error.message,
            SessionTokenError::STATUS,
        )
    }
}

static SEGMENTS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}$").expect("valid regex")
});
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^Bearer (\S+)$").expect("valid regex"));
/// `/^[A-Za-z0-9._-]{1,64}$/`: key ids.
pub(crate) static KID_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._-]{1,64}$").expect("valid regex"));
const OPTIONAL_STRING_CLAIMS: [&str; 7] = [
    "role",
    "trust",
    "src_tid",
    "session_name",
    "source_identity",
    "idp",
    "idp_sub",
];

/// True for a compact JWS shape (three base64url segments); says nothing about validity.
pub fn looks_like_jwt(value: &str) -> bool {
    SEGMENTS.is_match(value)
}

/// `looksLikeJwt(value)` for an untrusted value.
pub fn looks_like_jwt_value(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(text)) if looks_like_jwt(text))
}

fn invalid_option(name: &str) -> ThrownError {
    ThrownError::type_error(format!("Invalid session token verifier option: {name}"))
}

/// `nonEmpty(value, max)`: a string of 1 to `max` UTF-16 code units.
fn non_empty(value: Option<&Value>, max: usize) -> bool {
    matches!(value, Some(Value::String(text)) if !text.is_empty() && utf16_len(text) <= max)
}

/// `numeric(value)`: a finite number.
fn numeric(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(crate::js::as_number)
        .filter(|number| number.is_finite())
}

/// `seconds(value, fallback, name, min, max)`.
fn seconds(
    value: Option<&Value>,
    fallback: f64,
    name: &str,
    min: f64,
    max: f64,
) -> Result<f64, ThrownError> {
    let result = match value {
        None | Some(Value::Null) => fallback,
        Some(Value::Number(number)) => better_iam_core::js::number_value(number),
        Some(_) => return Err(invalid_option(name)),
    };
    if !result.is_finite() || result < min || result > max {
        return Err(invalid_option(name));
    }
    Ok(result)
}

/// `remoteUrl(value)`: https, or http on localhost; no credentials or fragment.
fn remote_url(value: &str) -> Result<url::Url, ThrownError> {
    let url = url::Url::parse(value).map_err(|_| invalid_option("jwks"))?;
    let hostname = crate::hosts::url_hostname(&url);
    let local = ["localhost", "127.0.0.1", "[::1]"].contains(&hostname.as_str());
    if url.scheme() != "https" && !(local && url.scheme() == "http") {
        return Err(invalid_option("jwks"));
    }
    if !url.username().is_empty()
        || url.password().is_some_and(|password| !password.is_empty())
        || url.fragment().is_some_and(|fragment| !fragment.is_empty())
    {
        return Err(invalid_option("jwks"));
    }
    Ok(url)
}

/// `reasonFor(error)`: maps jose errors to failure reasons; anything unrecognised is `malformed`.
fn reason_for(error: &jose::JoseError) -> &'static str {
    use jose::JoseError as E;
    match error {
        E::KeySetUnavailable => "jwks",
        E::Expired { .. } => "expired",
        E::ClaimValidation { claim, reason } => {
            if claim == "typ" {
                "type"
            } else if reason == "missing" || reason == "invalid" {
                "claims"
            } else if claim == "iss" {
                "issuer"
            } else if claim == "aud" {
                "audience"
            } else if claim == "nbf" || claim == "iat" {
                "not-yet-valid"
            } else {
                "claims"
            }
        }
        E::AlgNotAllowed => "algorithm",
        E::NoMatchingKey | E::MultipleMatchingKeys => "unknown-key",
        E::SignatureFailed => "signature",
        E::Timeout | E::JwksInvalid => "jwks",
        _ => "malformed",
    }
}

/// `claimsOf(payload)`: checks claim types and returns an allowlisted copy; unknown claims are dropped.
fn claims_of(payload: &Map<String, Value>) -> Result<SessionTokenClaims, SessionTokenError> {
    let claims_error = || SessionTokenError::new("claims", None);
    let aud = payload.get("aud");
    let audience_valid = non_empty(aud, 2048)
        || matches!(aud, Some(Value::Array(items))
            if !items.is_empty() && items.iter().all(|item| non_empty(Some(item), 2048)));
    let number = |name: &str| numeric(payload.get(name));
    let string = |name: &str| match payload.get(name) {
        Some(Value::String(text)) => text.clone(),
        _ => String::new(),
    };
    let same_jti = match (payload.get("jti"), payload.get("sid")) {
        (Some(jti), Some(sid)) => better_iam_core::js::strict_equal(jti, sid),
        (None, None) => true,
        _ => false,
    };
    if !non_empty(payload.get("iss"), 2048)
        || !audience_valid
        || !non_empty(payload.get("sub"), 256)
        || !non_empty(payload.get("tid"), 256)
        || !non_empty(payload.get("sid"), 256)
        || !same_jti
        || number("iat").is_none()
        || number("nbf").is_none()
        || number("exp").is_none()
        || number("auth_time").is_none()
        || !matches!(payload.get("mfa"), Some(Value::Bool(_)))
    {
        return Err(claims_error());
    }
    let mut claims = SessionTokenClaims {
        iss: string("iss"),
        aud: aud.cloned().unwrap_or(Value::Null),
        sub: string("sub"),
        tid: string("tid"),
        sid: string("sid"),
        jti: string("sid"),
        iat: number("iat").unwrap_or_default(),
        nbf: number("nbf").unwrap_or_default(),
        exp: number("exp").unwrap_or_default(),
        auth_time: number("auth_time").unwrap_or_default(),
        kind: string("kind"),
        mfa: matches!(payload.get("mfa"), Some(Value::Bool(true))),
        role: None,
        trust: None,
        src_tid: None,
        session_name: None,
        source_identity: None,
        idp: None,
        idp_sub: None,
        extra: Map::new(),
    };
    for name in OPTIONAL_STRING_CLAIMS {
        let Some(value) = payload.get(name) else {
            continue;
        };
        if !non_empty(Some(value), 1024) {
            return Err(claims_error());
        }
        let value = value.as_str().map(str::to_owned);
        match name {
            "role" => claims.role = value,
            "trust" => claims.trust = value,
            "src_tid" => claims.src_tid = value,
            "session_name" => claims.session_name = value,
            "source_identity" => claims.source_identity = value,
            "idp" => claims.idp = value,
            _ => claims.idp_sub = value,
        }
    }
    Ok(claims)
}

/// Where a verifier finds its public keys.
enum KeySource {
    Local(jose::JwkSet),
    Remote(Arc<jose::RemoteJwkSet>),
}

/// An offline verifier for IAM session JWTs (`createSessionTokenVerifier`). It enforces the `biam-session+jwt` type,
/// the EdDSA/ES256 allowlist (pinned to each key's `alg` for a local key set), the exact issuer, one of the configured
/// audiences, `exp`/`nbf` with clock tolerance, the lifetime cap, the accepted kinds and the claim types.
pub struct SessionTokenVerifier {
    issuer: String,
    audience: Vec<String>,
    algorithms: Vec<String>,
    kinds: Vec<String>,
    clock_tolerance: f64,
    max_lifetime: f64,
    now: NowFn,
    keys: KeySource,
    /// For a local set the algorithm is pinned per kid before any cryptography runs.
    pinned: Option<HashMap<String, String>>,
}

/// `createSessionTokenVerifier(options)` with options as JSON (`issuer`, `audience`, `jwks` as a key set or the URL
/// of a JWKS route, `algorithms`, `kinds`, `clockToleranceSeconds`, `maxLifetimeSeconds`, `cacheMaxAgeSeconds`,
/// `cooldownSeconds`, `timeoutMs`), on the `Date.now` clock. An invalid option is the TypeError TypeScript throws.
pub fn create_session_token_verifier(options: &Value) -> IamResult<SessionTokenVerifier> {
    create_session_token_verifier_with(options, None).map_err(ThrownError::into_iam)
}

/// `createSessionTokenVerifier(options)` with an injected clock (`now`, epoch milliseconds; `Date.now` when None).
pub fn create_session_token_verifier_with(
    options: &Value,
    now: Option<NowFn>,
) -> Result<SessionTokenVerifier, ThrownError> {
    let Value::Object(options) = options else {
        return Err(invalid_option("issuer"));
    };
    if !non_empty(options.get("issuer"), 2048) {
        return Err(invalid_option("issuer"));
    }
    let issuer = options
        .get("issuer")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let audience: Vec<Value> = match options.get("audience") {
        Some(Value::Array(items)) => items.clone(),
        Some(other) => vec![other.clone()],
        None => vec![Value::Null],
    };
    if audience.is_empty() || !audience.iter().all(|item| non_empty(Some(item), 2048)) {
        return Err(invalid_option("audience"));
    }
    let audience: Vec<String> = audience
        .iter()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect();
    let list = |name: &str,
                fallback: &[&str],
                allowed: &[&str]|
     -> Result<Vec<String>, ThrownError> {
        let items: Vec<Value> = match options.get(name) {
            None | Some(Value::Null) => fallback.iter().map(|item| Value::from(*item)).collect(),
            Some(Value::Array(items)) => items.clone(),
            // `[...text]` spreads a string into its characters.
            Some(Value::String(text)) => {
                text.chars().map(|c| Value::String(c.to_string())).collect()
            }
            Some(_) => return Err(invalid_option(name)),
        };
        if items.is_empty()
            || !items
                .iter()
                .all(|item| item.as_str().is_some_and(|text| allowed.contains(&text)))
        {
            return Err(invalid_option(name));
        }
        Ok(items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect())
    };
    let algorithms = list(
        "algorithms",
        &SESSION_TOKEN_ALGORITHMS,
        &SESSION_TOKEN_ALGORITHMS,
    )?;
    let kinds = list("kinds", &TOKEN_KINDS, &TOKEN_KINDS)?;
    let clock_tolerance = seconds(
        options.get("clockToleranceSeconds"),
        5.0,
        "clockToleranceSeconds",
        0.0,
        60.0,
    )?;
    let max_lifetime = seconds(
        options.get("maxLifetimeSeconds"),
        43200.0,
        "maxLifetimeSeconds",
        1.0,
        10.0 * 365.0 * 86400.0,
    )?;
    let now: NowFn = now.unwrap_or_else(|| Arc::new(crate::utils::date_now));

    let mut pinned = None;
    let keys = match options.get("jwks") {
        Some(Value::String(url)) => {
            let url = remote_url(url)?;
            let timeout = seconds(options.get("timeoutMs"), 5000.0, "timeoutMs", 1.0, 60_000.0)?;
            let cooldown = seconds(
                options.get("cooldownSeconds"),
                30.0,
                "cooldownSeconds",
                0.0,
                86400.0,
            )? * 1000.0;
            let cache_max_age = seconds(
                options.get("cacheMaxAgeSeconds"),
                600.0,
                "cacheMaxAgeSeconds",
                1.0,
                86400.0,
            )? * 1000.0;
            KeySource::Remote(jose::RemoteJwkSet::new(
                url,
                timeout,
                cooldown,
                cache_max_age,
            )?)
        }
        jwks => {
            let Some(Value::Array(keys)) = jwks.and_then(|jwks| jwks.get("keys")) else {
                return Err(invalid_option("jwks"));
            };
            let mut pins = HashMap::new();
            for key in keys {
                match key {
                    Value::Object(key) => {
                        if let (Some(Value::String(kid)), Some(Value::String(alg))) =
                            (key.get("kid"), key.get("alg"))
                        {
                            pins.insert(kid.clone(), alg.clone());
                        }
                    }
                    // `typeof [] === 'object'`: an array passes here and is refused by the key set below.
                    Value::Array(_) => {}
                    _ => return Err(invalid_option("jwks")),
                }
            }
            pinned = Some(pins);
            let set = jose::JwkSet::new(&serde_json::json!({ "keys": keys }))
                .map_err(|_| invalid_option("jwks"))?;
            KeySource::Local(set)
        }
    };
    Ok(SessionTokenVerifier {
        issuer,
        audience,
        algorithms,
        kinds,
        clock_tolerance,
        max_lifetime,
        now,
        keys,
        pinned,
    })
}

enum Failure {
    Token(SessionTokenError),
    Jose(jose::JoseError),
}

impl SessionTokenVerifier {
    /// Verifies a compact session JWT and returns its claims, or a `SessionTokenError` (code INVALID_SESSION_TOKEN).
    pub async fn verify(
        &self,
        token: &str,
    ) -> IamResult<crate::session_tokens::SessionTokenClaims> {
        self.verify_detailed(token).await.map_err(IamError::from)
    }

    /// [`SessionTokenVerifier::verify`] keeping the failure reason.
    pub async fn verify_detailed(
        &self,
        token: &str,
    ) -> Result<SessionTokenClaims, SessionTokenError> {
        match self.check(token).await {
            Ok(claims) => Ok(claims),
            Err(Failure::Token(error)) => Err(error),
            Err(Failure::Jose(error)) => Err(SessionTokenError::new(reason_for(&error), None)),
        }
    }

    /// `verify(token)` for an untrusted value: anything but a string is `malformed`.
    pub async fn verify_value(
        &self,
        token: Option<&Value>,
    ) -> Result<SessionTokenClaims, SessionTokenError> {
        match token {
            Some(Value::String(token)) => self.verify_detailed(token).await,
            _ => Err(SessionTokenError::new("malformed", None)),
        }
    }

    async fn check(&self, token: &str) -> Result<SessionTokenClaims, Failure> {
        let fail = |reason: &str| Failure::Token(SessionTokenError::new(reason, None));
        if utf16_len(token) as f64 > MAX_SESSION_TOKEN_LENGTH {
            return Err(fail("too-large"));
        }
        if !looks_like_jwt(token) {
            return Err(fail("malformed"));
        }
        let header = jose::decode_protected_header(token).map_err(|_| fail("malformed"))?;
        let kid = match header.get("kid") {
            Some(Value::String(kid)) if KID_PATTERN.is_match(kid) => kid.clone(),
            _ => return Err(fail("unknown-key")),
        };
        let alg = match header.get("alg") {
            Some(Value::String(alg)) if self.algorithms.contains(alg) => alg.clone(),
            _ => return Err(fail("algorithm")),
        };
        if let Some(pinned) = &self.pinned {
            match pinned.get(&kid) {
                None => return Err(fail("unknown-key")),
                Some(pinned) if *pinned != alg => return Err(fail("algorithm")),
                Some(_) => {}
            }
        }
        let issuer = Value::String(self.issuer.clone());
        let tolerance = crate::js::number(self.clock_tolerance);
        let options = jose::VerifyOptions {
            algorithms: &self.algorithms,
            issuer: Some(&issuer),
            audience: Some(&self.audience),
            typ: Some(SESSION_TOKEN_TYPE),
            required_claims: &["iss", "sub", "aud", "exp", "iat", "sid", "tid", "kind"],
            clock_tolerance: Some(&tolerance),
            current_ms: (self.now)(),
            max_token_age: None,
        };
        let payload = match &self.keys {
            KeySource::Local(set) => {
                jose::jwt_verify(
                    token,
                    |header| async move { set.get_key(&header) },
                    &options,
                )
                .await
            }
            KeySource::Remote(remote) => {
                let remote = remote.clone();
                jose::jwt_verify(
                    token,
                    |header| async move {
                        remote.get_key(&header).await.map_err(|error| match error {
                            jose::JoseError::NoMatchingKey
                            | jose::JoseError::MultipleMatchingKeys => error,
                            _ => jose::JoseError::KeySetUnavailable,
                        })
                    },
                    &options,
                )
                .await
            }
        }
        .map_err(Failure::Jose)?;
        if !matches!(payload.get("kind"), Some(Value::String(kind)) if self.kinds.contains(kind)) {
            return Err(fail("kind"));
        }
        match (numeric(payload.get("exp")), numeric(payload.get("iat"))) {
            (Some(exp), Some(iat)) if exp - iat <= self.max_lifetime => {}
            _ => return Err(fail("lifetime")),
        }
        claims_of(&payload).map_err(Failure::Token)
    }

    /// Verifies the `Authorization: Bearer <jwt>` header of a request (the scheme is case-insensitive).
    pub async fn verify_request(
        &self,
        request: &Value,
    ) -> IamResult<crate::session_tokens::SessionTokenClaims> {
        self.verify_request_detailed(request)
            .await
            .map_err(IamError::from)
    }

    /// [`SessionTokenVerifier::verify_request`] keeping the failure reason. `request.headers` is a record of header
    /// values or a list of `[name, value]` pairs, as `new Headers(init)` reads them.
    pub async fn verify_request_detailed(
        &self,
        request: &Value,
    ) -> Result<SessionTokenClaims, SessionTokenError> {
        let authorization = authorization_header(request.get("headers"));
        self.verify_authorization(authorization.as_deref()).await
    }

    /// The bearer check of `verifyRequest` for an already-read `Authorization` header.
    pub async fn verify_authorization(
        &self,
        authorization: Option<&str>,
    ) -> Result<SessionTokenClaims, SessionTokenError> {
        let Some(token) = BEARER
            .captures(authorization.unwrap_or_default())
            .and_then(|captures| captures.get(1))
            .map(|token| token.as_str().to_owned())
        else {
            return Err(SessionTokenError::new(
                "malformed",
                Some("A bearer session token is required"),
            ));
        };
        self.verify_detailed(&token).await
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let first = args.first();
        let result = match method {
            "verify" => self.verify_value(first).await,
            "verifyRequest" => {
                self.verify_request_detailed(first.unwrap_or(&Value::Null))
                    .await
            }
            _ => return None,
        };
        Some(
            result
                .map(|claims| Value::Object(claims.to_json()))
                .map_err(IamError::from),
        )
    }
}

/// `new Headers(init).get('authorization')`: values of every member named `authorization` (any case), joined with
/// `, ` and trimmed of HTTP whitespace; None when absent or when `init` is not a header list.
fn authorization_header(headers: Option<&Value>) -> Option<String> {
    let trim = |value: &str| {
        value
            .trim_matches(|c| matches!(c, ' ' | '\t' | '\n' | '\r'))
            .to_owned()
    };
    let mut found: Vec<String> = Vec::new();
    match headers {
        Some(Value::Object(map)) => {
            for (name, value) in map {
                if name.eq_ignore_ascii_case("authorization") {
                    found.push(trim(&crate::js::js_string(Some(value))));
                }
            }
        }
        Some(Value::Array(pairs)) => {
            for pair in pairs {
                let Value::Array(pair) = pair else {
                    return None;
                };
                if pair.len() != 2 {
                    return None;
                }
                let name = crate::js::js_string(Some(&pair[0]));
                if name.eq_ignore_ascii_case("authorization") {
                    found.push(trim(&crate::js::js_string(Some(&pair[1]))));
                }
            }
        }
        _ => return None,
    }
    if found.is_empty() {
        None
    } else {
        Some(found.join(", "))
    }
}

/// The JOSE operations of `jose` 6 that session JWTs and web-identity tokens rely on, with jose's check order and
/// error classes (each failure reason in TypeScript is derived from the class jose throws).
pub(crate) mod jose {
    use super::*;
    use base64::Engine;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use std::future::Future;

    /// The jose error classes (and the plain TypeErrors jose lets through) the reason mappings distinguish.
    #[derive(Debug, Clone, PartialEq)]
    pub enum JoseError {
        /// `JWSInvalid`.
        JwsInvalid,
        /// `JWTInvalid`.
        JwtInvalid,
        /// `JOSEAlgNotAllowed`.
        AlgNotAllowed,
        /// `JOSENotSupported`.
        NotSupported,
        /// `JWKSInvalid`.
        JwksInvalid,
        /// `JWKSNoMatchingKey`.
        NoMatchingKey,
        /// `JWKSMultipleMatchingKeys`.
        MultipleMatchingKeys,
        /// `JWSSignatureVerificationFailed`.
        SignatureFailed,
        /// `JWTClaimValidationFailed` (`reason`: `missing`, `invalid` or `check_failed`).
        ClaimValidation { claim: String, reason: String },
        /// `JWTExpired`.
        Expired { claim: String },
        /// `JWKSTimeout`.
        Timeout,
        /// A TypeError (or DOMException) from key import or option checks.
        TypeError,
        /// Another error from a remote key set (a failed fetch, a non-200 answer, unparseable JSON).
        Fetch,
        /// A key resolver's own refusal (`KeySetUnavailable` of session-tokens.ts, `KeysUnavailable` of
        /// web-identity.ts).
        KeySetUnavailable,
    }

    fn claim_failed(claim: &str, reason: &str) -> JoseError {
        JoseError::ClaimValidation {
            claim: claim.to_owned(),
            reason: reason.to_owned(),
        }
    }

    /// `decode(input)` of jose's base64url helper: `atob` after mapping the URL alphabet (forgiving: ASCII whitespace
    /// ignored, up to two trailing `=` accepted when the length is a multiple of four, unused trailing bits ignored,
    /// a length of 1 modulo 4 refused). `+` and `/` are refused.
    pub fn decode_base64url(input: &str) -> Option<Vec<u8>> {
        if input.contains(['+', '/']) {
            return None;
        }
        let mut text: Vec<u8> = input
            .bytes()
            .filter(|byte| !matches!(byte, b' ' | b'\t' | b'\n' | b'\x0c' | b'\r'))
            .collect();
        if text.len().is_multiple_of(4) {
            if text.ends_with(b"==") {
                text.truncate(text.len() - 2);
            } else if text.ends_with(b"=") {
                text.truncate(text.len() - 1);
            }
        }
        if text.len() % 4 == 1 {
            return None;
        }
        let mut out = Vec::with_capacity(text.len() * 3 / 4);
        let mut buffer: u32 = 0;
        let mut bits = 0u32;
        for byte in text {
            let value = match byte {
                b'A'..=b'Z' => byte - b'A',
                b'a'..=b'z' => byte - b'a' + 26,
                b'0'..=b'9' => byte - b'0' + 52,
                b'-' => 62,
                b'_' => 63,
                _ => return None,
            };
            buffer = (buffer << 6) | u32::from(value);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                out.push(((buffer >> bits) & 0xff) as u8);
            }
        }
        Some(out)
    }

    /// `encode(bytes)`: base64url without padding.
    pub fn encode_base64url(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    /// `JSON.parse(strictDecoder.decode(bytes))` (a leading BOM is dropped, invalid UTF-8 refused), as an object
    /// (`isObject`).
    fn parse_object(bytes: &[u8]) -> Option<Map<String, Value>> {
        let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(bytes);
        let text = std::str::from_utf8(bytes).ok()?;
        match better_iam_core::js::parse(text).ok()? {
            Value::Object(map) => Some(map),
            _ => None,
        }
    }

    /// `parseJoseHeader(b64)`.
    fn parse_jose_header(encoded: &str) -> Option<Map<String, Value>> {
        parse_object(&decode_base64url(encoded)?)
    }

    /// `decodeProtectedHeader(token)` for a compact token (three or five segments).
    pub fn decode_protected_header(token: &str) -> Result<Map<String, Value>, JoseError> {
        let parts: Vec<&str> = token.split('.').collect();
        let protected = if parts.len() == 3 || parts.len() == 5 {
            parts[0]
        } else {
            ""
        };
        if protected.is_empty() {
            return Err(JoseError::TypeError);
        }
        parse_jose_header(protected).ok_or(JoseError::TypeError)
    }

    /// One row of jose's JWS algorithm table.
    #[derive(Debug, Clone, Copy)]
    struct Entry {
        alg: &'static str,
        kty: &'static str,
        crv: Option<&'static str>,
        secret: bool,
    }

    fn entry(alg: &str) -> Option<Entry> {
        let (alg, kty, crv, secret) = match alg {
            "HS256" => ("HS256", "oct", None, true),
            "HS384" => ("HS384", "oct", None, true),
            "HS512" => ("HS512", "oct", None, true),
            "RS256" => ("RS256", "RSA", None, false),
            "RS384" => ("RS384", "RSA", None, false),
            "RS512" => ("RS512", "RSA", None, false),
            "PS256" => ("PS256", "RSA", None, false),
            "PS384" => ("PS384", "RSA", None, false),
            "PS512" => ("PS512", "RSA", None, false),
            "ES256" => ("ES256", "EC", Some("P-256"), false),
            "ES384" => ("ES384", "EC", Some("P-384"), false),
            "ES512" => ("ES512", "EC", Some("P-521"), false),
            "EdDSA" => ("EdDSA", "OKP", Some("Ed25519"), false),
            "Ed25519" => ("Ed25519", "OKP", Some("Ed25519"), false),
            "ML-DSA-44" => ("ML-DSA-44", "AKP", None, false),
            "ML-DSA-65" => ("ML-DSA-65", "AKP", None, false),
            "ML-DSA-87" => ("ML-DSA-87", "AKP", None, false),
            _ => return None,
        };
        Some(Entry {
            alg,
            kty,
            crv,
            secret,
        })
    }

    /// An imported public verification key.
    #[derive(Clone)]
    pub enum VerifyKey {
        Rsa(Box<rsa::RsaPublicKey>),
        P256(p256::ecdsa::VerifyingKey),
        P384(p384::ecdsa::VerifyingKey),
        /// None for 32 bytes that are not a curve point: imported (as OpenSSL does), but never verifies.
        Ed25519(Option<ed25519_dalek::VerifyingKey>),
    }

    fn str_member<'a>(jwk: &'a Map<String, Value>, name: &str) -> Option<&'a str> {
        jwk.get(name).and_then(Value::as_str)
    }

    /// `jwkToKey(entry, jwk)` + WebCrypto `importKey('jwk', ...)` + the public-key check of `importWithAlgCache`.
    fn import(jwk: &Map<String, Value>, entry: Entry) -> Result<VerifyKey, JoseError> {
        if str_member(jwk, "kty") != Some(entry.kty) {
            return Err(JoseError::NotSupported);
        }
        let private = crate::js::truthy(jwk.get("d")) || crate::js::truthy(jwk.get("priv"));
        if private {
            // Imported as a private key, which a key set refuses.
            return if jwk.get("d").is_some_and(Value::is_string) {
                Err(JoseError::JwksInvalid)
            } else {
                Err(JoseError::TypeError)
            };
        }
        // WebCrypto: a public key may only be used to verify.
        if let Some(ops) = jwk.get("key_ops") {
            let Value::Array(ops) = ops else {
                return Err(JoseError::TypeError);
            };
            if ops.iter().any(|op| op.as_str() != Some("verify")) {
                return Err(JoseError::TypeError);
            }
        }
        let bytes = |name: &str| -> Result<Vec<u8>, JoseError> {
            str_member(jwk, name)
                .and_then(decode_base64url)
                .ok_or(JoseError::TypeError)
        };
        match entry.kty {
            "RSA" => {
                let n = rsa::BigUint::from_bytes_be(&bytes("n")?);
                let e = rsa::BigUint::from_bytes_be(&bytes("e")?);
                let key = rsa::RsaPublicKey::new_with_max_size(n, e, 16384)
                    .map_err(|_| JoseError::TypeError)?;
                Ok(VerifyKey::Rsa(Box::new(key)))
            }
            "EC" => {
                if str_member(jwk, "crv") != entry.crv {
                    return Err(JoseError::TypeError);
                }
                let (x, y) = (bytes("x")?, bytes("y")?);
                match entry.crv {
                    Some("P-256") => {
                        if x.len() != 32 || y.len() != 32 {
                            return Err(JoseError::TypeError);
                        }
                        let point = p256::EncodedPoint::from_affine_coordinates(
                            x.as_slice().into(),
                            y.as_slice().into(),
                            false,
                        );
                        p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                            .map(VerifyKey::P256)
                            .map_err(|_| JoseError::TypeError)
                    }
                    Some("P-384") => {
                        if x.len() != 48 || y.len() != 48 {
                            return Err(JoseError::TypeError);
                        }
                        let point = p384::EncodedPoint::from_affine_coordinates(
                            x.as_slice().into(),
                            y.as_slice().into(),
                            false,
                        );
                        p384::ecdsa::VerifyingKey::from_encoded_point(&point)
                            .map(VerifyKey::P384)
                            .map_err(|_| JoseError::TypeError)
                    }
                    // P-521 (ES512) is in jose's table but neither verifier allows it.
                    _ => Err(JoseError::NotSupported),
                }
            }
            "OKP" => {
                if str_member(jwk, "crv") != Some("Ed25519") {
                    return Err(JoseError::TypeError);
                }
                let x: [u8; 32] = bytes("x")?.try_into().map_err(|_| JoseError::TypeError)?;
                Ok(VerifyKey::Ed25519(
                    ed25519_dalek::VerifyingKey::from_bytes(&x).ok(),
                ))
            }
            _ => Err(JoseError::NotSupported),
        }
    }

    /// `crypto.subtle.verify(...)` for the algorithm; false for any malformed signature.
    fn verify_signature(key: &VerifyKey, alg: &str, data: &[u8], signature: &[u8]) -> bool {
        use p256::ecdsa::signature::Verifier;
        macro_rules! rsa_verify {
            ($scheme:ident, $digest:ty, $key:expr) => {
                rsa::$scheme::Signature::try_from(signature).is_ok_and(|signature| {
                    rsa::$scheme::VerifyingKey::<$digest>::new($key.clone())
                        .verify(data, &signature)
                        .is_ok()
                })
            };
        }
        match key {
            VerifyKey::Rsa(key) => {
                let key: &rsa::RsaPublicKey = key;
                match alg {
                    "RS256" => rsa_verify!(pkcs1v15, sha2::Sha256, key),
                    "RS384" => rsa_verify!(pkcs1v15, sha2::Sha384, key),
                    "RS512" => rsa_verify!(pkcs1v15, sha2::Sha512, key),
                    "PS256" => rsa_verify!(pss, sha2::Sha256, key),
                    "PS384" => rsa_verify!(pss, sha2::Sha384, key),
                    "PS512" => rsa_verify!(pss, sha2::Sha512, key),
                    _ => false,
                }
            }
            VerifyKey::P256(key) => p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
            VerifyKey::P384(key) => p384::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
            VerifyKey::Ed25519(key) => {
                let Some(key) = key else {
                    return false;
                };
                ed25519_dalek::Signature::from_slice(signature)
                    .is_ok_and(|signature| key.verify(data, &signature).is_ok())
            }
        }
    }

    /// The checks `prepareKey` / `checkCryptoKey` / `checkModulusLength` make before the signature is verified.
    fn check_key(key: &VerifyKey, entry: Entry) -> Result<(), JoseError> {
        use rsa::traits::PublicKeyParts;
        let fits = match (key, entry.kty, entry.crv) {
            (VerifyKey::Rsa(key), "RSA", _) => {
                if key.n().bits() < 2048 {
                    return Err(JoseError::TypeError);
                }
                true
            }
            (VerifyKey::P256(_), "EC", Some("P-256")) => true,
            (VerifyKey::P384(_), "EC", Some("P-384")) => true,
            (VerifyKey::Ed25519(_), "OKP", _) => true,
            _ => false,
        };
        if fits {
            Ok(())
        } else {
            Err(JoseError::TypeError)
        }
    }

    /// `createLocalJWKSet(jwks)`: a snapshot of a key set.
    #[derive(Debug, Clone)]
    pub struct JwkSet {
        keys: Vec<Map<String, Value>>,
    }

    impl JwkSet {
        /// `createLocalJWKSet(jwks)`: JWKSInvalid unless `jwks` is an object whose `keys` are all objects.
        pub fn new(jwks: &Value) -> Result<Self, JoseError> {
            let Some(Value::Array(keys)) = jwks.as_object().and_then(|jwks| jwks.get("keys"))
            else {
                return Err(JoseError::JwksInvalid);
            };
            let mut snapshot = Vec::with_capacity(keys.len());
            for key in keys {
                let Value::Object(key) = key else {
                    return Err(JoseError::JwksInvalid);
                };
                snapshot.push(key.clone());
            }
            Ok(Self { keys: snapshot })
        }

        /// A set of already-checked keys.
        pub fn from_keys(keys: Vec<Map<String, Value>>) -> Self {
            Self { keys }
        }

        /// The key resolver: the one usable key for the header's `alg` and `kid`, imported.
        pub fn get_key(&self, header: &Map<String, Value>) -> Result<VerifyKey, JoseError> {
            let alg = header.get("alg");
            let Some(entry) = alg.and_then(Value::as_str).and_then(entry) else {
                return Err(JoseError::NotSupported);
            };
            if entry.secret {
                return Err(JoseError::NotSupported);
            }
            let kid = header.get("kid");
            let candidates: Vec<&Map<String, Value>> = self
                .keys
                .iter()
                .filter(|jwk| usable(jwk, entry, kid))
                .collect();
            match candidates.as_slice() {
                [] => Err(JoseError::NoMatchingKey),
                [jwk] => import(jwk, entry),
                _ => Err(JoseError::MultipleMatchingKeys),
            }
        }
    }

    /// `isUsableJWK(jwk, entry, alg, kid)`.
    fn usable(jwk: &Map<String, Value>, entry: Entry, kid: Option<&Value>) -> bool {
        if !matches!(jwk.get("ext"), None | Some(Value::Bool(_))) {
            return false;
        }
        if let Some(ops) = jwk.get("key_ops") {
            let Value::Array(ops) = ops else {
                return false;
            };
            let mut seen: Vec<&str> = Vec::new();
            for op in ops {
                let Some(op) = op.as_str() else {
                    return false;
                };
                if seen.contains(&op) {
                    return false;
                }
                seen.push(op);
            }
            if !seen.contains(&"verify") {
                return false;
            }
        }
        if str_member(jwk, "kty") != Some(entry.kty) {
            return false;
        }
        if let Some(kid) = kid {
            match (kid, jwk.get("kid")) {
                (Value::String(kid), Some(Value::String(own))) if kid == own => {}
                _ => return false,
            }
        }
        match jwk.get("alg") {
            None => {
                if entry.kty == "AKP" {
                    return false;
                }
            }
            Some(Value::String(own)) if own == entry.alg => {}
            Some(_) => return false,
        }
        if jwk.get("use").is_some() && str_member(jwk, "use") != Some("sig") {
            return false;
        }
        if let Some(crv) = entry.crv
            && str_member(jwk, "crv") != Some(crv)
        {
            return false;
        }
        true
    }

    /// The options of `jwtVerify` both verifiers use.
    pub struct VerifyOptions<'a> {
        pub algorithms: &'a [String],
        /// `issuer` (compared with `payload.iss` by identity).
        pub issuer: Option<&'a Value>,
        pub audience: Option<&'a [String]>,
        pub typ: Option<&'a str>,
        pub required_claims: &'a [&'a str],
        /// `clockTolerance`: a number, a duration string, or absent (0).
        pub clock_tolerance: Option<&'a Value>,
        /// `currentDate` in epoch milliseconds.
        pub current_ms: f64,
        /// `maxTokenAge`: a number of seconds, a duration string, or absent.
        pub max_token_age: Option<&'a Value>,
    }

    /// jose's `secs(str)`: a duration such as `5s`, `2 minutes`, `1h ago`.
    fn secs(value: &Value) -> Result<f64, JoseError> {
        static DURATION: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(
                r"(?i)^(\+|\-)? ?(\d+|\d+\.\d+) ?(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h|days?|d|weeks?|w|years?|yrs?|y)(?: (ago|from now))?$",
            )
            .expect("valid regex")
        });
        let Value::String(text) = value else {
            return Err(JoseError::TypeError);
        };
        let Some(matched) = DURATION.captures(text) else {
            return Err(JoseError::TypeError);
        };
        if matched.get(4).is_some() && matched.get(1).is_some() {
            return Err(JoseError::TypeError);
        }
        let number: f64 = matched[2].parse().map_err(|_| JoseError::TypeError)?;
        let multiplier = match matched[3].chars().next().map(|c| c.to_ascii_lowercase()) {
            Some('s') => 1.0,
            Some('m') => 60.0,
            Some('h') => 3600.0,
            Some('d') => 86400.0,
            Some('w') => 604800.0,
            _ => 31557600.0,
        };
        let numeric = (number * multiplier + 0.5).floor();
        if !numeric.is_finite() {
            return Err(JoseError::TypeError);
        }
        let negative = matched.get(1).is_some_and(|sign| sign.as_str() == "-")
            || matched
                .get(4)
                .is_some_and(|tail| tail.as_str().eq_ignore_ascii_case("ago"));
        Ok(if negative { -numeric } else { numeric })
    }

    fn finite(value: f64) -> Result<f64, JoseError> {
        if value.is_finite() {
            Ok(value)
        } else {
            Err(JoseError::TypeError)
        }
    }

    /// `normalizeTyp(value)`.
    fn normalize_typ(value: &str) -> String {
        let normalized = value.to_lowercase();
        if value.contains('/') {
            normalized
        } else {
            format!("application/{normalized}")
        }
    }

    /// `validateNumericDate(payload, claim, required)`.
    fn numeric_date(
        payload: &Map<String, Value>,
        claim: &str,
        required: bool,
    ) -> Result<Option<f64>, JoseError> {
        match payload.get(claim) {
            None if !required => Ok(None),
            Some(Value::Number(number)) => Ok(Some(better_iam_core::js::number_value(number))),
            _ => Err(claim_failed(claim, "invalid")),
        }
    }

    /// `validateClaimsSet(protectedHeader, encodedPayload, options)`.
    fn validate_claims_set(
        header: &Map<String, Value>,
        payload: &[u8],
        options: &VerifyOptions<'_>,
    ) -> Result<Map<String, Value>, JoseError> {
        let payload = parse_object(payload).ok_or(JoseError::JwtInvalid)?;
        if let Some(typ) = options.typ {
            match header.get("typ") {
                Some(Value::String(own)) if normalize_typ(own) == normalize_typ(typ) => {}
                _ => return Err(claim_failed("typ", "check_failed")),
            }
        }
        let mut presence: Vec<&str> = options.required_claims.to_vec();
        if options.max_token_age.is_some() {
            presence.push("iat");
        }
        if options.audience.is_some() {
            presence.push("aud");
        }
        if options.issuer.is_some() {
            presence.push("iss");
        }
        presence.reverse();
        let mut checked: Vec<&str> = Vec::new();
        for claim in presence {
            if checked.contains(&claim) {
                continue;
            }
            checked.push(claim);
            if !payload.contains_key(claim) {
                return Err(claim_failed(claim, "missing"));
            }
        }
        if let Some(issuer) = options.issuer {
            let same = payload
                .get("iss")
                .is_some_and(|iss| better_iam_core::js::strict_equal(iss, issuer));
            if !same {
                return Err(claim_failed("iss", "check_failed"));
            }
        }
        if let Some(audience) = options.audience {
            let present = match payload.get("aud") {
                Some(Value::String(aud)) => audience.contains(aud),
                Some(Value::Array(items)) => audience
                    .iter()
                    .any(|wanted| items.iter().any(|item| item.as_str() == Some(wanted))),
                _ => false,
            };
            if !present {
                return Err(claim_failed("aud", "check_failed"));
            }
        }
        let tolerance = match options.clock_tolerance {
            None => 0.0,
            Some(value @ Value::String(_)) => secs(value)?,
            Some(Value::Number(number)) => better_iam_core::js::number_value(number),
            Some(_) => return Err(JoseError::TypeError),
        };
        let tolerance = finite(tolerance)?;
        // `new Date(now())` keeps whole milliseconds (TimeClip); `epoch(date)` floors to seconds.
        let current = if options.current_ms.is_finite() && options.current_ms.abs() <= 8.64e15 {
            options.current_ms.trunc()
        } else {
            f64::NAN
        };
        let now = finite((current / 1000.0).floor())?;
        let iat = numeric_date(&payload, "iat", options.max_token_age.is_some())?;
        let nbf = numeric_date(&payload, "nbf", false)?;
        if let Some(nbf) = nbf
            && nbf > now + tolerance
        {
            return Err(claim_failed("nbf", "check_failed"));
        }
        let exp = numeric_date(&payload, "exp", false)?;
        if let Some(exp) = exp
            && exp <= now - tolerance
        {
            return Err(JoseError::Expired {
                claim: "exp".to_owned(),
            });
        }
        if let Some(max_token_age) = options.max_token_age {
            let age = now - iat.unwrap_or(f64::NAN);
            let max = match max_token_age {
                Value::Number(number) => better_iam_core::js::number_value(number),
                other => secs(other)?,
            };
            let max = finite(max)?;
            if age - tolerance > max {
                return Err(JoseError::Expired {
                    claim: "iat".to_owned(),
                });
            }
            if age < -tolerance {
                return Err(claim_failed("iat", "check_failed"));
            }
        }
        Ok(payload)
    }

    /// `validateCrit(JWSInvalid, { b64: true }, undefined, protectedHeader, joseHeader)` + `validateB64`: whether the
    /// payload is base64url-encoded.
    fn validate_crit_b64(header: &Map<String, Value>) -> Result<bool, JoseError> {
        let Some(crit) = header.get("crit") else {
            return Ok(true);
        };
        let Value::Array(crit) = crit else {
            return Err(JoseError::JwsInvalid);
        };
        if crit.is_empty()
            || crit
                .iter()
                .any(|item| !matches!(item, Value::String(text) if !text.is_empty()))
        {
            return Err(JoseError::JwsInvalid);
        }
        for parameter in crit {
            let parameter = parameter.as_str().unwrap_or_default();
            if parameter != "b64" {
                return Err(JoseError::NotSupported);
            }
            if !header.contains_key(parameter) {
                return Err(JoseError::JwsInvalid);
            }
        }
        match header.get("b64") {
            Some(Value::Bool(b64)) => Ok(*b64),
            _ => Err(JoseError::JwsInvalid),
        }
    }

    /// `jwtVerify(jwt, getKey, options)` for a compact token: the payload of a verified token, or the jose error, in
    /// jose's order (header, `crit`, `alg`, the allowlist, key resolution, signature, payload, claims).
    pub async fn jwt_verify<R, F>(
        token: &str,
        resolve: R,
        options: &VerifyOptions<'_>,
    ) -> Result<Map<String, Value>, JoseError>
    where
        R: FnOnce(Map<String, Value>) -> F,
        F: Future<Output = Result<VerifyKey, JoseError>>,
    {
        let parts: Vec<&str> = token.split('.').collect();
        let [protected, payload, signature] = parts.as_slice() else {
            return Err(JoseError::JwsInvalid);
        };
        let header = parse_jose_header(protected).ok_or(JoseError::JwsInvalid)?;
        let b64 = validate_crit_b64(&header)?;
        let alg = match header.get("alg") {
            Some(Value::String(alg)) if !alg.is_empty() => alg.clone(),
            _ => return Err(JoseError::JwsInvalid),
        };
        if !options.algorithms.contains(&alg) {
            return Err(JoseError::AlgNotAllowed);
        }
        // An unencoded payload is encoded before the key is resolved; an encoded one after.
        if !b64 && !payload.is_ascii() {
            return Err(JoseError::JwsInvalid);
        }
        let key = resolve(header.clone()).await?;
        let entry = entry(&alg).ok_or(JoseError::NotSupported)?;
        if b64 && !payload.is_ascii() {
            return Err(JoseError::JwsInvalid);
        }
        let mut data = Vec::with_capacity(protected.len() + payload.len() + 1);
        data.extend_from_slice(protected.as_bytes());
        data.push(b'.');
        data.extend_from_slice(payload.as_bytes());
        let signature = decode_base64url(signature).ok_or(JoseError::JwsInvalid)?;
        check_key(&key, entry)?;
        if !verify_signature(&key, &alg, &data, &signature) {
            return Err(JoseError::SignatureFailed);
        }
        if !b64 {
            return Err(JoseError::JwtInvalid);
        }
        let payload = decode_base64url(payload).ok_or(JoseError::JwsInvalid)?;
        validate_claims_set(&header, &payload, options)
    }

    /// The private half of a session signing key.
    #[derive(Clone)]
    pub enum SigningKey {
        Ed25519(Box<ed25519_dalek::SigningKey>),
        P256(Box<p256::ecdsa::SigningKey>),
    }

    /// `new SignJWT(payload).setProtectedHeader(header).sign(key)`: the compact JWS.
    pub fn sign_compact(header: &Value, payload: &Value, key: &SigningKey) -> String {
        use p256::ecdsa::signature::Signer;
        let mut input = encode_base64url(better_iam_core::js::stringify(header).as_bytes());
        input.push('.');
        input.push_str(&encode_base64url(
            better_iam_core::js::stringify(payload).as_bytes(),
        ));
        let signature: Vec<u8> = match key {
            SigningKey::Ed25519(key) => key.sign(input.as_bytes()).to_bytes().to_vec(),
            SigningKey::P256(key) => {
                let signature: p256::ecdsa::Signature = key.sign(input.as_bytes());
                signature.to_bytes().to_vec()
            }
        };
        input.push('.');
        input.push_str(&encode_base64url(&signature));
        input
    }

    type Reload = Shared<BoxFuture<'static, Result<(), JoseError>>>;

    struct RemoteState {
        local: Option<Arc<JwkSet>>,
        timestamp: Option<f64>,
        pending: Option<(u64, Reload)>,
        reload_sequence: u64,
        applied_sequence: u64,
    }

    /// `createRemoteJWKSet(url, { timeoutDuration, cooldownDuration, cacheMaxAge })`: a key set fetched from a JWKS
    /// route, cached for `cacheMaxAge` and refetched on an unknown `kid` once the cooldown has passed. Times are
    /// `Date.now()`.
    pub struct RemoteJwkSet {
        url: url::Url,
        timeout_ms: u64,
        cooldown_ms: f64,
        cache_max_age_ms: f64,
        fetch: crate::safe_fetch::GuardedFetch,
        state: Mutex<RemoteState>,
    }

    fn fresh_for(timestamp: Option<f64>, duration: f64) -> bool {
        timestamp.is_some_and(|timestamp| {
            timestamp.is_finite() && crate::utils::date_now() < timestamp + duration
        })
    }

    impl RemoteJwkSet {
        /// `createRemoteJWKSet`: TypeError for a timeout that is not a non-negative integer.
        pub fn new(
            url: url::Url,
            timeout_ms: f64,
            cooldown_ms: f64,
            cache_max_age_ms: f64,
        ) -> Result<Arc<Self>, ThrownError> {
            if timeout_ms.fract() != 0.0 || timeout_ms < 0.0 {
                return Err(ThrownError::type_error(
                    "\"timeoutDuration\" option must be a non-negative integer",
                ));
            }
            // jose fetches without an address guard; the URL rules above are the only ones.
            let fetch =
                crate::safe_fetch::create_guarded_fetch(crate::safe_fetch::GuardedFetchOptions {
                    allow_private_networks: true,
                    allow_insecure_localhost: true,
                    any_port: true,
                    max_bytes: None,
                });
            Ok(Arc::new(Self {
                url,
                timeout_ms: timeout_ms as u64,
                cooldown_ms,
                cache_max_age_ms,
                fetch,
                state: Mutex::new(RemoteState {
                    local: None,
                    timestamp: None,
                    pending: None,
                    reload_sequence: 0,
                    applied_sequence: 0,
                }),
            }))
        }

        fn state(&self) -> std::sync::MutexGuard<'_, RemoteState> {
            self.state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
        }

        /// `fetchJwks(url, headers, signal)`.
        async fn fetch_jwks(&self) -> Result<Value, JoseError> {
            let request = crate::safe_fetch::FetchRequest::get(self.url.as_str())
                .header("user-agent", "jose/v6.2.12")
                .header("accept", "application/json, application/jwk-set+json")
                .redirect(crate::safe_fetch::RedirectMode::Manual);
            let work = async {
                let mut response = self
                    .fetch
                    .fetch(request)
                    .await
                    .map_err(|_| JoseError::Fetch)?;
                if response.status != 200 {
                    return Err(JoseError::Fetch);
                }
                response.body.json().await.map_err(|_| JoseError::Fetch)
            };
            match tokio::time::timeout(std::time::Duration::from_millis(self.timeout_ms), work)
                .await
            {
                Ok(result) => result,
                Err(_) => Err(JoseError::Timeout),
            }
        }

        /// `reload()`: one fetch for all concurrent callers; a later fetch's keys are never replaced by an earlier
        /// one's.
        pub async fn reload(self: &Arc<Self>) -> Result<(), JoseError> {
            let pending = {
                let mut state = self.state();
                match &state.pending {
                    Some((_, pending)) => pending.clone(),
                    None => {
                        state.reload_sequence += 1;
                        let sequence = state.reload_sequence;
                        let this = self.clone();
                        let future: BoxFuture<'static, Result<(), JoseError>> =
                            Box::pin(async move {
                                let outcome = match this.fetch_jwks().await {
                                    Ok(json) => JwkSet::new(&json).map(|next| {
                                        let mut state = this.state();
                                        if sequence > state.applied_sequence {
                                            state.local = Some(Arc::new(next));
                                            state.timestamp = Some(crate::utils::date_now());
                                            state.applied_sequence = sequence;
                                        }
                                    }),
                                    Err(error) => Err(error),
                                };
                                let mut state = this.state();
                                if state
                                    .pending
                                    .as_ref()
                                    .is_some_and(|(current, _)| *current == sequence)
                                {
                                    state.pending = None;
                                }
                                outcome
                            });
                        let shared = future.shared();
                        state.pending = Some((sequence, shared.clone()));
                        shared
                    }
                }
            };
            pending.await
        }

        /// The key resolver of a remote set.
        pub async fn get_key(
            self: &Arc<Self>,
            header: &Map<String, Value>,
        ) -> Result<VerifyKey, JoseError> {
            let stale = {
                let state = self.state();
                state.local.is_none() || !fresh_for(state.timestamp, self.cache_max_age_ms)
            };
            if stale {
                self.reload().await?;
            }
            let local = self.state().local.clone().ok_or(JoseError::JwksInvalid)?;
            let cooling = fresh_for(self.state().timestamp, self.cooldown_ms);
            match local.get_key(header) {
                Err(JoseError::NoMatchingKey) if !cooling => {
                    self.reload().await?;
                    let local = self.state().local.clone().ok_or(JoseError::JwksInvalid)?;
                    local.get_key(header)
                }
                other => other,
            }
        }
    }
}
