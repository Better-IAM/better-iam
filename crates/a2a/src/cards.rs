//! Agent2Agent (A2A) agent cards: the types the helpers read, verification of cards Better IAM attested
//! (`agents.signCard`), discovery of a remote agent's card, and an attestor that keeps an agent's own card signed
//! (cards.ts).

use std::collections::HashMap;
use std::sync::{Arc, LazyLock, Mutex, Weak};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_core::{canonicalize_json, js};
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use url::Url;

use crate::error::A2aError;
use crate::transport::{
    self, Body, DEFAULT_FETCH, Fetch, RedirectPolicy, ResponseUrl, decode_utf8, read_bounded,
};

/// An A2A agent card (`/.well-known/agent-card.json`): a JSON object whose members (`name`, `url`, `skills`,
/// `capabilities`, `signatures`, ...) are read as the A2A specification defines them. Members the helpers do not
/// know are kept: a card's signature covers all of them.
pub type AgentCard = Map<String, Value>;

/// One skill of a card (`AgentSkill`), for building cards; [`AgentCard`] holds skills as JSON.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub examples: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input_modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_modes: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub security: Option<Vec<IndexMap<String, Vec<String>>>>,
    /// Other members (`[key: string]: unknown`).
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A card extension (`AgentExtension`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentExtension {
    pub uri: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<Map<String, Value>>,
}

/// One JWS signature of a card (RFC 7515 JSON serialization, detached payload) (`AgentCardSignature`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AgentCardSignature {
    pub protected: String,
    pub signature: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub header: Option<Map<String, Value>>,
}

/// The URI of the attestation extension Better IAM adds to every card it signs (`agentAttestationUri`).
pub const AGENT_ATTESTATION_URI: &str = "urn:better-iam:a2a:attestation:v1";

/// What Better IAM attests about an agent: the params of the attestation extension (`AgentAttestation`). The string
/// members a verified attestation always has are fields; `params` is the whole object as the card carries it.
#[derive(Debug, Clone, PartialEq)]
pub struct AgentAttestation {
    pub issuer: String,
    pub tenant_id: String,
    pub organization: String,
    pub agent_id: String,
    pub agent_name: String,
    pub issued_at: String,
    pub expires_at: String,
    /// The attestation as the card carries it (`sponsored`, `delegable`, `model`, `provider`, `protocols`, ...).
    pub params: Map<String, Value>,
}

impl AgentAttestation {
    /// `delegable`.
    pub fn delegable(&self) -> bool {
        self.params.get("delegable") == Some(&Value::Bool(true))
    }

    /// `model`.
    pub fn model(&self) -> Option<&str> {
        self.params.get("model").and_then(Value::as_str)
    }

    /// `provider`.
    pub fn provider(&self) -> Option<&str> {
        self.params.get("provider").and_then(Value::as_str)
    }

    /// `protocols`.
    pub fn protocols(&self) -> Option<Vec<&str>> {
        self.params
            .get("protocols")
            .and_then(Value::as_array)
            .map(|items| items.iter().filter_map(Value::as_str).collect())
    }

    /// The attestation as JSON.
    pub fn to_value(&self) -> Value {
        Value::Object(self.params.clone())
    }
}

impl Serialize for AgentAttestation {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.params.serialize(serializer)
    }
}

/// A public card key (`CardJwk`), for building key sets; [`CardJwks`] holds keys as JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CardJwk {
    pub kty: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub crv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub x: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub y: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alg: Option<String>,
    #[serde(rename = "use", default, skip_serializing_if = "Option::is_none")]
    pub use_: Option<String>,
}

/// A key set (`iam.a2a.jwks()`) (`CardJwks`). Keys are kept as JSON, as a fetched set gives them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
pub struct CardJwks {
    pub keys: Vec<Value>,
}

impl CardJwks {
    /// A key set from a JSON value (`{ keys: [...] }`); None when it is not one.
    pub fn from_value(value: &Value) -> Option<Self> {
        let keys = value.as_object()?.get("keys")?.as_array()?;
        Some(CardJwks { keys: keys.clone() })
    }

    /// A key set of typed keys.
    pub fn from_keys(keys: &[CardJwk]) -> Self {
        CardJwks {
            keys: keys
                .iter()
                .map(|key| serde_json::to_value(key).unwrap_or(Value::Null))
                .collect(),
        }
    }
}

/// Why an agent card was refused (`AgentCardErrorReason`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AgentCardErrorReason {
    Malformed,
    Unsigned,
    UntrustedKey,
    Signature,
    Attestation,
    Expired,
    Issuer,
    Tenant,
    Endpoint,
    Fetch,
}

impl AgentCardErrorReason {
    /// The TypeScript string (`untrusted-key`, ...).
    pub fn as_str(self) -> &'static str {
        match self {
            AgentCardErrorReason::Malformed => "malformed",
            AgentCardErrorReason::Unsigned => "unsigned",
            AgentCardErrorReason::UntrustedKey => "untrusted-key",
            AgentCardErrorReason::Signature => "signature",
            AgentCardErrorReason::Attestation => "attestation",
            AgentCardErrorReason::Expired => "expired",
            AgentCardErrorReason::Issuer => "issuer",
            AgentCardErrorReason::Tenant => "tenant",
            AgentCardErrorReason::Endpoint => "endpoint",
            AgentCardErrorReason::Fetch => "fetch",
        }
    }
}

/// Why an agent card was refused by [`verify_agent_card`] or [`discover_agent`] (`AgentCardError`): `reason` is
/// `unsigned`, `untrusted-key`, `signature`, `attestation`, `expired`, `issuer`, `tenant`, `endpoint`, `malformed` or
/// `fetch`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{message}")]
pub struct AgentCardError {
    pub reason: AgentCardErrorReason,
    pub message: String,
}

impl AgentCardError {
    pub fn new(reason: AgentCardErrorReason, message: impl Into<String>) -> Self {
        AgentCardError {
            reason,
            message: message.into(),
        }
    }

    /// `error.name`.
    pub fn name(&self) -> &'static str {
        "AgentCardError"
    }
}

fn card_error(reason: AgentCardErrorReason, message: impl Into<String>) -> A2aError {
    A2aError::Card(AgentCardError::new(reason, message))
}

/// The current time in epoch milliseconds (`now`).
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// Where a trusted deployment's keys come from: its JWKS URL (`a2a.jwksUrl`) or its JWKS.
#[derive(Debug, Clone, PartialEq)]
pub enum TrustedKeys {
    Url(String),
    Jwks(CardJwks),
}

impl From<CardJwks> for TrustedKeys {
    fn from(jwks: CardJwks) -> Self {
        TrustedKeys::Jwks(jwks)
    }
}

impl From<String> for TrustedKeys {
    fn from(url: String) -> Self {
        TrustedKeys::Url(url)
    }
}

impl From<&str> for TrustedKeys {
    fn from(url: &str) -> Self {
        TrustedKeys::Url(url.to_owned())
    }
}

/// The key set for a signature's `kid` and `jku` (`keys` as a function).
pub type CardKeyResolver = Arc<
    dyn Fn(String, Option<String>) -> BoxFuture<'static, Result<CardJwks, A2aError>> + Send + Sync,
>;

/// The card keys of a Better IAM deployment you trust: a JWKS (`iam.a2a.jwks()`), or a function returning the JWKS
/// for a signature's `kid` and `jku`.
#[derive(Clone)]
pub enum CardKeys {
    Jwks(CardJwks),
    Resolve(CardKeyResolver),
}

impl From<CardJwks> for CardKeys {
    fn from(jwks: CardJwks) -> Self {
        CardKeys::Jwks(jwks)
    }
}

/// `VerifyAgentCardOptions`.
#[derive(Clone, Default)]
pub struct VerifyAgentCardOptions {
    /// The Better IAM deployments you trust, by attestation issuer: each issuer's JWKS URL (`a2a.jwksUrl`) or its
    /// JWKS. The card is checked only with the keys of the issuer it names, so one trusted deployment cannot vouch in
    /// another's name. The safest choice when you trust more than one deployment; otherwise give `keys` or
    /// `trusted_jwks_urls`.
    pub trusted_issuers: Option<IndexMap<String, TrustedKeys>>,
    /// The card keys of a Better IAM deployment you trust.
    pub keys: Option<CardKeys>,
    /// JWKS URLs you trust (`a2a.jwksUrl` of those deployments). A signature is checked only when its `jku` is
    /// exactly one of them; the key set is fetched with `fetch` and cached for `jwks_cache_seconds` (fetched again,
    /// at most every 30 seconds, when a signature names a key it does not have).
    pub trusted_jwks_urls: Option<Vec<String>>,
    /// Attestation issuers you accept; default: any whose key verifies.
    pub issuers: Option<Vec<String>>,
    /// Accept only agents attested for this tenant (organization).
    pub tenant_id: Option<String>,
    /// Require the card's `url` to be on this origin (discovery passes the origin it fetched from).
    pub origin: Option<String>,
    /// Allowed clock difference in seconds (default 60).
    pub clock_tolerance_seconds: Option<f64>,
    /// How long fetched key sets are kept, in seconds (default 300).
    pub jwks_cache_seconds: Option<f64>,
    pub now: Option<Clock>,
    pub fetch: Option<Arc<dyn Fetch>>,
}

/// `VerifiedAgentCard`.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedAgentCard {
    pub card: AgentCard,
    pub attestation: AgentAttestation,
    /// The `kid` of the key that verified the card.
    pub kid: String,
}

/// Why base64url text could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Base64Error {
    /// Characters outside the base64url alphabet (`AgentCardError('malformed')`).
    Malformed(AgentCardError),
    /// A length `atob` refuses (`InvalidCharacterError`).
    Invalid,
}

/// `fromBase64Url(value)` (shared with delegation_tokens.rs; not exported from the package).
pub(crate) fn from_base64_url(value: &str) -> Result<Vec<u8>, Base64Error> {
    if !value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_')
    {
        return Err(Base64Error::Malformed(AgentCardError::new(
            AgentCardErrorReason::Malformed,
            "Invalid base64url",
        )));
    }
    if value.len() % 4 == 1 {
        return Err(Base64Error::Invalid);
    }
    // `atob` ignores bits past the last whole byte.
    let mut bytes = Vec::with_capacity(value.len() * 3 / 4);
    let mut buffer: u32 = 0;
    let mut bits = 0;
    for byte in value.bytes() {
        let sextet = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'-' => 62,
            _ => 63,
        };
        buffer = (buffer << 6) | u32::from(sextet);
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            bytes.push((buffer >> bits) as u8);
            buffer &= (1 << bits) - 1;
        }
    }
    Ok(bytes)
}

fn to_base64_url(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// `plain(value)`: a JSON object (not an array).
pub(crate) fn plain(value: Option<&Value>) -> Option<&Map<String, Value>> {
    value.and_then(Value::as_object)
}

fn base64url_member(material: &Map<String, Value>, name: &str) -> Option<Vec<u8>> {
    let text = material.get(name)?.as_str()?;
    URL_SAFE_NO_PAD
        .decode(text.trim_end_matches('='))
        .ok()
        .or_else(|| from_base64_url(text).ok())
}

/// `verifySignature(jwk, alg, signingInput, signature)`: WebCrypto verification with the key's public material
/// (`{ kty, crv, x, y? }`); false for a key that does not import or a signature that does not verify.
pub(crate) fn verify_signature(
    jwk: &Value,
    alg: &str,
    signing_input: &[u8],
    signature: &[u8],
) -> bool {
    use p256::ecdsa::signature::Verifier;
    let Some(material) = jwk.as_object() else {
        return false;
    };
    let member = |name: &str| material.get(name).and_then(Value::as_str);
    if alg == "EdDSA" && member("kty") == Some("OKP") && member("crv") == Some("Ed25519") {
        let Some(x) = base64url_member(material, "x").and_then(|x| <[u8; 32]>::try_from(x).ok())
        else {
            return false;
        };
        let Ok(key) = ed25519_dalek::VerifyingKey::from_bytes(&x) else {
            return false;
        };
        return ed25519_dalek::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verify(signing_input, &signature).is_ok());
    }
    if alg == "ES256" && member("kty") == Some("EC") && member("crv") == Some("P-256") {
        let (Some(x), Some(y)) = (
            base64url_member(material, "x"),
            base64url_member(material, "y"),
        ) else {
            return false;
        };
        if x.len() != 32 || y.len() != 32 {
            return false;
        }
        let point = p256::EncodedPoint::from_affine_coordinates(
            x.as_slice().into(),
            y.as_slice().into(),
            false,
        );
        let Ok(key) = p256::ecdsa::VerifyingKey::from_encoded_point(&point) else {
            return false;
        };
        return p256::ecdsa::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verify(signing_input, &signature).is_ok());
    }
    false
}

/// `attestationOf(card)`.
fn attestation_of(card: &AgentCard) -> Result<AgentAttestation, A2aError> {
    // `card.capabilities?.extensions ?? []`: a capabilities value that is not an object has no extensions.
    let extensions = match card.get("capabilities") {
        Some(Value::Object(capabilities)) => capabilities.get("extensions"),
        _ => None,
    };
    let items: &[Value] = match extensions {
        None | Some(Value::Null) => &[],
        Some(Value::Array(items)) => items,
        Some(_) => {
            return Err(A2aError::type_error(
                "(card.capabilities?.extensions ?? []).filter is not a function",
            ));
        }
    };
    let found: Vec<&Map<String, Value>> = items
        .iter()
        .filter_map(Value::as_object)
        .filter(|item| item.get("uri").and_then(Value::as_str) == Some(AGENT_ATTESTATION_URI))
        .collect();
    let params = match found.as_slice() {
        [only] => plain(only.get("params")),
        _ => None,
    };
    let Some(params) = params else {
        return Err(card_error(
            AgentCardErrorReason::Attestation,
            "The card carries no Better IAM attestation",
        ));
    };
    let mut fields = Vec::with_capacity(7);
    for field in [
        "issuer",
        "tenantId",
        "organization",
        "agentId",
        "agentName",
        "issuedAt",
        "expiresAt",
    ] {
        match params.get(field) {
            Some(Value::String(text)) => fields.push(text.clone()),
            _ => {
                return Err(card_error(
                    AgentCardErrorReason::Attestation,
                    format!("The attestation has no {field}"),
                ));
            }
        }
    }
    if params.get("sponsored") != Some(&Value::Bool(true)) {
        return Err(card_error(
            AgentCardErrorReason::Attestation,
            "The attestation does not state a sponsor",
        ));
    }
    let mut fields = fields.into_iter();
    let mut next = || fields.next().unwrap_or_default();
    Ok(AgentAttestation {
        issuer: next(),
        tenant_id: next(),
        organization: next(),
        agent_id: next(),
        agent_name: next(),
        issued_at: next(),
        expires_at: next(),
        params: params.clone(),
    })
}

struct CachedJwks {
    jwks: CardJwks,
    until: f64,
    fetched_at: f64,
}

type JwksCacheEntry = (Weak<dyn Fetch>, HashMap<String, CachedJwks>);

/// Fetched key sets by URL, shared by every verification that fetches keys with the same fetch (a `WeakMap` keyed
/// by the fetch).
static JWKS_CACHE: LazyLock<Mutex<Vec<JwksCacheEntry>>> = LazyLock::new(|| Mutex::new(Vec::new()));

fn same_fetch(weak: &Weak<dyn Fetch>, fetcher: &Arc<dyn Fetch>) -> bool {
    std::ptr::addr_eq(weak.as_ptr(), Arc::as_ptr(fetcher))
}

fn cached_jwks(fetcher: &Arc<dyn Fetch>, url: &str, now: f64, fresh: bool) -> Option<CardJwks> {
    let mut cache = JWKS_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.retain(|(weak, _)| weak.strong_count() > 0);
    let (_, entries) = cache.iter().find(|(weak, _)| same_fetch(weak, fetcher))?;
    let cached = entries.get(url)?;
    (cached.until > now && !(fresh && now - cached.fetched_at > 30_000.0))
        .then(|| cached.jwks.clone())
}

fn store_jwks(fetcher: &Arc<dyn Fetch>, url: &str, jwks: CardJwks, now: f64, cache_seconds: f64) {
    let mut cache = JWKS_CACHE
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    cache.retain(|(weak, _)| weak.strong_count() > 0);
    let index = match cache.iter().position(|(weak, _)| same_fetch(weak, fetcher)) {
        Some(index) => index,
        None => {
            cache.push((Arc::downgrade(fetcher), HashMap::new()));
            cache.len() - 1
        }
    };
    let entries = &mut cache[index].1;
    if entries.len() > 64 {
        entries.clear();
    }
    entries.insert(
        url.to_owned(),
        CachedJwks {
            jwks,
            until: now + cache_seconds * 1000.0,
            fetched_at: now,
        },
    );
}

/// A GET request with headers, as `fetch(url, { headers, redirect: 'error' })` sends it.
pub(crate) fn get_request(url: &str, accept: &str) -> Result<http::Request<Body>, A2aError> {
    let uri: http::Uri = url
        .parse()
        .map_err(|_| A2aError::message(format!("Failed to parse URL from {url}")))?;
    let mut request = http::Request::builder()
        .method(http::Method::GET)
        .uri(uri)
        .header(http::header::ACCEPT, accept)
        .body(transport::empty())
        .map_err(|error| A2aError::message(error.to_string()))?;
    request.extensions_mut().insert(RedirectPolicy::Error);
    Ok(request)
}

/// A JWKS from `url`, cached for `cache_seconds`. With `fresh` (a signature named a key the cached set lacks), a set
/// older than 30 seconds is fetched again, so a newly activated key verifies without waiting out the cache
/// (`fetchJwks`).
pub(crate) async fn fetch_jwks(
    url: &str,
    fetcher: &Arc<dyn Fetch>,
    now: f64,
    cache_seconds: f64,
    fresh: bool,
) -> Result<CardJwks, A2aError> {
    if let Some(jwks) = cached_jwks(fetcher, url, now, fresh) {
        return Ok(jwks);
    }
    let text = transport::with_timeout(5000, async {
        let request = get_request(url, "application/jwk-set+json, application/json")?;
        let response = fetcher.fetch(request).await?;
        bounded_text(response, 256 * 1024).await
    })
    .await?;
    let parsed = js::parse(&text).map_err(|error| A2aError::message(error.to_string()))?;
    let Some(keys) = parsed
        .as_object()
        .and_then(|parsed| parsed.get("keys"))
        .and_then(Value::as_array)
    else {
        return Err(card_error(
            AgentCardErrorReason::UntrustedKey,
            format!("{url} is not a JWKS"),
        ));
    };
    let jwks = CardJwks { keys: keys.clone() };
    store_jwks(fetcher, url, jwks.clone(), now, cache_seconds);
    Ok(jwks)
}

/// `boundedText(response, maxBytes)`: the body as text, refusing an error status or a body over `max_bytes`.
pub(crate) async fn bounded_text(
    response: http::Response<Body>,
    max_bytes: usize,
) -> Result<String, A2aError> {
    let status = response.status();
    if !status.is_success() {
        let url = response
            .extensions()
            .get::<ResponseUrl>()
            .map(|url| url.0.clone())
            .filter(|url| !url.is_empty())
            .unwrap_or_else(|| "The server".to_owned());
        return Err(card_error(
            AgentCardErrorReason::Fetch,
            format!("{url} answered {}", status.as_u16()),
        ));
    }
    match read_bounded(response.into_body(), max_bytes).await? {
        Some(bytes) => Ok(decode_utf8(&bytes)),
        None => Err(card_error(
            AgentCardErrorReason::Fetch,
            format!("The response is larger than {max_bytes} bytes"),
        )),
    }
}

/// `jwks?.keys.find(key => key.kid === kid && (key.alg === undefined || key.alg === alg) && key.use !== 'enc')`;
/// Err where reading a member of a `null` key throws.
pub(crate) fn pick_key<'a>(
    jwks: &'a CardJwks,
    kid: &str,
    alg: &str,
) -> Result<Option<&'a Value>, ()> {
    for key in &jwks.keys {
        let Some(map) = key.as_object() else {
            if key.is_null() {
                return Err(());
            }
            continue;
        };
        let alg_ok = match map.get("alg") {
            None => true,
            Some(value) => value.as_str() == Some(alg),
        };
        if map.get("kid").and_then(Value::as_str) == Some(kid)
            && alg_ok
            && map.get("use").and_then(Value::as_str) != Some("enc")
        {
            return Ok(Some(key));
        }
    }
    Ok(None)
}

/// `new URL(value).origin`; None for text that is not a URL.
pub(crate) fn origin_of(value: &str) -> Option<String> {
    Url::parse(value)
        .ok()
        .map(|url| url.origin().ascii_serialization())
}

/// Verifies that `card` was signed by a trusted Better IAM deployment and that its attestation is current: one of
/// the card's signatures verifies over the canonical card (RFC 8785, without `signatures`) with a trusted key, the
/// card carries exactly one attestation, it is neither expired nor from the future, and it matches `issuers`,
/// `tenant_id` and `origin` when given. Fails with an `AgentCardError` otherwise (`verifyAgentCard`).
pub async fn verify_agent_card(
    card: &Value,
    options: &VerifyAgentCardOptions,
) -> Result<VerifiedAgentCard, A2aError> {
    if options.trusted_issuers.is_none()
        && options.keys.is_none()
        && options.trusted_jwks_urls.as_ref().is_none_or(Vec::is_empty)
    {
        return Err(A2aError::type_error(
            "verifyAgentCard needs trustedIssuers, keys or trustedJwksUrls",
        ));
    }
    let card = match card {
        Value::Object(map)
            if map.get("url").is_some_and(Value::is_string)
                && map.get("name").is_some_and(Value::is_string) =>
        {
            map
        }
        _ => {
            return Err(card_error(
                AgentCardErrorReason::Malformed,
                "Not an agent card",
            ));
        }
    };
    let signatures = match card.get("signatures") {
        Some(Value::Array(items)) if !items.is_empty() => items,
        _ => {
            return Err(card_error(
                AgentCardErrorReason::Unsigned,
                "The card is not signed",
            ));
        }
    };
    let now = match &options.now {
        Some(now) => now(),
        None => js::now_ms(),
    };
    let fetcher = options
        .fetch
        .clone()
        .unwrap_or_else(|| DEFAULT_FETCH.clone());
    let cache_seconds = options.jwks_cache_seconds.unwrap_or(300.0);
    // With trusted_issuers the keys are the named issuer's: read the (not yet verified) issuer first; the signature
    // check below then binds the card to that issuer's keys.
    let mut issuer_keys: Option<&TrustedKeys> = None;
    if let Some(trusted) = &options.trusted_issuers {
        let claimed = attestation_of(card)?.issuer;
        match trusted.get(&claimed) {
            Some(keys) => issuer_keys = Some(keys),
            None => {
                return Err(card_error(
                    AgentCardErrorReason::Issuer,
                    format!("The card was attested by {claimed}, which is not trusted"),
                ));
            }
        }
    }
    let keys_for = |kid: String, jku: Option<String>, fresh: bool| {
        let fetcher = fetcher.clone();
        async move {
            if let Some(keys) = issuer_keys {
                return match keys {
                    TrustedKeys::Url(url) => fetch_jwks(url, &fetcher, now, cache_seconds, fresh)
                        .await
                        .map(Some),
                    TrustedKeys::Jwks(jwks) => Ok(Some(jwks.clone())),
                };
            }
            if let Some(keys) = &options.keys {
                return match keys {
                    CardKeys::Resolve(resolve) => resolve(kid, jku).await.map(Some),
                    CardKeys::Jwks(jwks) => Ok(Some(jwks.clone())),
                };
            }
            if let Some(jku) = jku
                && options
                    .trusted_jwks_urls
                    .as_ref()
                    .is_some_and(|urls| urls.contains(&jku))
            {
                return fetch_jwks(&jku, &fetcher, now, cache_seconds, fresh)
                    .await
                    .map(Some);
            }
            Ok(None)
        }
    };
    let mut unsigned = card.clone();
    unsigned.shift_remove("signatures");
    let payload = to_base64_url(canonicalize_json(&Value::Object(unsigned)).as_bytes());
    let mut verified_kid: Option<String> = None;
    let mut saw_trusted_key = false;
    for entry in signatures.iter().take(8) {
        let Some(entry) = entry.as_object() else {
            continue;
        };
        let (Some(Value::String(protected)), Some(Value::String(signature_text))) =
            (entry.get("protected"), entry.get("signature"))
        else {
            continue;
        };
        let header = match from_base64_url(protected) {
            Ok(bytes) => match js::parse(&decode_utf8(&bytes)) {
                Ok(header) => header,
                Err(_) => continue,
            },
            Err(_) => continue,
        };
        // Only plain detached card signatures (`typ` JOSE, never another JWT type signed with the same keys): no
        // critical extensions, no unencoded payloads.
        let Some(header) = header.as_object() else {
            continue;
        };
        if header.get("typ").and_then(Value::as_str) != Some("JOSE")
            || header.contains_key("crit")
            || header.contains_key("b64")
        {
            continue;
        }
        let alg = match header.get("alg").and_then(Value::as_str) {
            Some(alg @ ("EdDSA" | "ES256")) => alg,
            _ => continue,
        };
        let Some(kid) = header.get("kid").and_then(Value::as_str) else {
            continue;
        };
        let jku = header.get("jku").and_then(Value::as_str).map(str::to_owned);
        // A key the (cached) set lacks may have been activated since: look once more with a fresh set.
        let looked_up = async {
            let first = keys_for(kid.to_owned(), jku.clone(), false)
                .await
                .map_err(Some)?;
            let found = match &first {
                Some(jwks) => pick_key(jwks, kid, alg).map_err(|()| None)?.cloned(),
                None => None,
            };
            if found.is_some() {
                return Ok(found);
            }
            let second = keys_for(kid.to_owned(), jku.clone(), true)
                .await
                .map_err(Some)?;
            match &second {
                Some(jwks) => Ok(pick_key(jwks, kid, alg).map_err(|()| None)?.cloned()),
                None => Ok(None),
            }
        };
        let jwk: Option<Value> = match looked_up.await {
            Ok(jwk) => jwk,
            Err(Some(A2aError::Card(error))) if error.reason == AgentCardErrorReason::Fetch => {
                return Err(A2aError::Card(error));
            }
            Err(_) => None,
        };
        let Some(jwk) = jwk else {
            continue;
        };
        saw_trusted_key = true;
        let Ok(signature) = from_base64_url(signature_text) else {
            continue;
        };
        let signing_input = format!("{protected}.{payload}");
        if verify_signature(&jwk, alg, signing_input.as_bytes(), &signature) {
            verified_kid = Some(kid.to_owned());
            break;
        }
    }
    let Some(verified_kid) = verified_kid else {
        return Err(if saw_trusted_key {
            card_error(
                AgentCardErrorReason::Signature,
                "The card signature does not verify",
            )
        } else {
            card_error(
                AgentCardErrorReason::UntrustedKey,
                "The card is not signed with a trusted key",
            )
        });
    };
    let attestation = attestation_of(card)?;
    // A NaN or infinite tolerance (or clock) would make both time checks below false and accept any attestation.
    let tolerance_seconds = options.clock_tolerance_seconds.unwrap_or(60.0);
    if !tolerance_seconds.is_finite()
        || tolerance_seconds < 0.0
        || tolerance_seconds > 300.0
        || !now.is_finite()
    {
        return Err(A2aError::type_error(
            "clockToleranceSeconds must be 0 to 300 seconds and now a finite time",
        ));
    }
    let tolerance = tolerance_seconds * 1000.0;
    let issued_at = better_iam_auth::js_date::parse(&attestation.issued_at);
    let expires_at = better_iam_auth::js_date::parse(&attestation.expires_at);
    if !issued_at.is_finite() || !expires_at.is_finite() {
        return Err(card_error(
            AgentCardErrorReason::Attestation,
            "The attestation times are invalid",
        ));
    }
    if issued_at > now + tolerance {
        return Err(card_error(
            AgentCardErrorReason::Attestation,
            "The attestation is not valid yet",
        ));
    }
    if expires_at <= now - tolerance {
        return Err(card_error(
            AgentCardErrorReason::Expired,
            "The attestation has expired",
        ));
    }
    if let Some(issuers) = &options.issuers
        && !issuers.contains(&attestation.issuer)
    {
        return Err(card_error(
            AgentCardErrorReason::Issuer,
            format!("The card was attested by {}", attestation.issuer),
        ));
    }
    if let Some(tenant_id) = &options.tenant_id
        && &attestation.tenant_id != tenant_id
    {
        return Err(card_error(
            AgentCardErrorReason::Tenant,
            "The agent belongs to another organization",
        ));
    }
    if let Some(expected) = &options.origin {
        let origin = card.get("url").and_then(Value::as_str).and_then(origin_of);
        let Some(expected) = origin_of(expected) else {
            return Err(A2aError::type_error("Invalid URL"));
        };
        if origin.as_deref() != Some(expected.as_str()) {
            return Err(card_error(
                AgentCardErrorReason::Endpoint,
                "The card describes an agent on another origin",
            ));
        }
    }
    Ok(VerifiedAgentCard {
        card: card.clone(),
        attestation,
        kid: verified_kid,
    })
}

/// `DiscoverAgentOptions`: the verification options, plus the limits of the card request.
#[derive(Clone, Default)]
pub struct DiscoverAgentOptions {
    pub verify: VerifyAgentCardOptions,
    /// Largest accepted card in bytes (default 256 KiB).
    pub max_bytes: Option<usize>,
    /// Timeout of the card request in milliseconds (default 5000).
    pub timeout_ms: Option<u64>,
}

impl From<VerifyAgentCardOptions> for DiscoverAgentOptions {
    fn from(verify: VerifyAgentCardOptions) -> Self {
        DiscoverAgentOptions {
            verify,
            ..DiscoverAgentOptions::default()
        }
    }
}

/// Fetches a remote agent's card (`url` itself when it ends in `.json`, otherwise `/.well-known/agent-card.json` on
/// its origin) and verifies it with [`verify_agent_card`], requiring the card's `url` to be on the origin it was
/// fetched from. Call it only with agent addresses you chose: it makes an outbound request (`discoverAgent`).
pub async fn discover_agent(
    url: &str,
    options: &DiscoverAgentOptions,
) -> Result<VerifiedAgentCard, A2aError> {
    let target = Url::parse(url).map_err(|_| A2aError::type_error("Invalid URL"))?;
    if target.scheme() != "https" && target.scheme() != "http" {
        return Err(card_error(
            AgentCardErrorReason::Fetch,
            "Agent cards are fetched over http(s)",
        ));
    }
    let location = if target.path().ends_with(".json") {
        target.clone()
    } else {
        // `new URL('/.well-known/agent-card.json', target.origin)`: no credentials, query or fragment.
        Url::parse(&format!(
            "{}/.well-known/agent-card.json",
            target.origin().ascii_serialization()
        ))
        .map_err(|_| A2aError::type_error("Invalid URL"))?
    };
    let fetcher = options
        .verify
        .fetch
        .clone()
        .unwrap_or_else(|| DEFAULT_FETCH.clone());
    let href = location.as_str().to_owned();
    let max_bytes = options.max_bytes.unwrap_or(256 * 1024);
    let fetched = transport::with_timeout(options.timeout_ms.unwrap_or(5000), async {
        let request = get_request(&href, "application/json")?;
        let response = fetcher.fetch(request).await?;
        bounded_text(response, max_bytes).await
    })
    .await;
    let text = match fetched {
        Ok(text) => text,
        Err(A2aError::Card(error)) => return Err(A2aError::Card(error)),
        Err(_) => {
            return Err(card_error(
                AgentCardErrorReason::Fetch,
                format!("Could not fetch {href}"),
            ));
        }
    };
    let Ok(card) = js::parse(&text) else {
        return Err(card_error(
            AgentCardErrorReason::Malformed,
            format!("{href} is not JSON"),
        ));
    };
    let mut verify = options.verify.clone();
    if verify.origin.is_none() {
        verify.origin = Some(location.origin().ascii_serialization());
    }
    verify_agent_card(&card, &verify).await
}

/// The card to have attested: an object, or a function building it.
#[derive(Clone)]
pub enum CardSource {
    Card(AgentCard),
    Build(Arc<dyn Fn() -> BoxFuture<'static, Result<AgentCard, A2aError>> + Send + Sync>),
}

impl CardSource {
    /// A card built by a function on every use.
    pub fn build<F, Fut>(function: F) -> Self
    where
        F: Fn() -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = Result<AgentCard, A2aError>> + Send + 'static,
    {
        CardSource::Build(Arc::new(move || function().boxed()))
    }

    /// The card (`typeof source === 'function' ? await source() : source`).
    pub async fn card(&self) -> Result<AgentCard, A2aError> {
        match self {
            CardSource::Card(card) => Ok(card.clone()),
            CardSource::Build(build) => build().await,
        }
    }
}

impl From<AgentCard> for CardSource {
    fn from(card: AgentCard) -> Self {
        CardSource::Card(card)
    }
}

/// A card Better IAM signed: `{ card, expiresAt }` of `agents.signCard`.
#[derive(Debug, Clone, PartialEq)]
pub struct SignedCard {
    pub card: Map<String, Value>,
    pub expires_at: f64,
}

/// Signs a card through Better IAM, for example with `iam.api.agents.sign_card`.
pub type CardSigner =
    Arc<dyn Fn(AgentCard) -> BoxFuture<'static, Result<SignedCard, A2aError>> + Send + Sync>;

/// `CardAttestorOptions`.
#[derive(Clone)]
pub struct CardAttestorOptions {
    /// The card to have attested (without signatures).
    pub card: CardSource,
    /// Signs a card through Better IAM.
    pub sign: CardSigner,
    /// Re-sign once less than this share of the attestation's lifetime is left (default 0.2).
    pub refresh_share: Option<f64>,
    pub now: Option<Clock>,
}

struct AttestedCard {
    card: AgentCard,
    signed_at: f64,
    expires_at: f64,
}

type SharedCard = Shared<BoxFuture<'static, Result<AgentCard, A2aError>>>;

struct AttestorState {
    options: CardAttestorOptions,
    current: Mutex<Option<AttestedCard>>,
    pending: Mutex<Option<(u64, SharedCard)>>,
    runs: std::sync::atomic::AtomicU64,
}

impl AttestorState {
    fn now(&self) -> f64 {
        match &self.options.now {
            Some(now) => now(),
            None => js::now_ms(),
        }
    }
}

/// Keeps an agent's own card attested ([`create_card_attestor`]): [`CardAttestor::card`] yields the signed card,
/// signing on first use and again when the attestation nears its end. Concurrent calls share one signing request;
/// when re-signing fails while the previous card is still valid, that card is returned.
#[derive(Clone)]
pub struct CardAttestor {
    state: Arc<AttestorState>,
}

/// `createCardAttestor(options)`.
pub fn create_card_attestor(options: CardAttestorOptions) -> CardAttestor {
    CardAttestor {
        state: Arc::new(AttestorState {
            options,
            current: Mutex::new(None),
            pending: Mutex::new(None),
            runs: std::sync::atomic::AtomicU64::new(0),
        }),
    }
}

async fn attest(state: Arc<AttestorState>, run: u64) -> Result<AgentCard, A2aError> {
    let result = async {
        let base = state.options.card.card().await?;
        let signed_at = state.now();
        let signed = (state.options.sign)(base).await?;
        let card = signed.card.clone();
        *state
            .current
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(AttestedCard {
            card: signed.card,
            signed_at,
            expires_at: signed.expires_at,
        });
        Ok::<_, A2aError>(card)
    }
    .await;
    let result = match result {
        Ok(card) => Ok(card),
        Err(error) => {
            let now = state.now();
            let current = state
                .current
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match current.as_ref() {
                Some(current) if current.expires_at > now => Ok(current.card.clone()),
                _ => Err(error),
            }
        }
    };
    let mut pending = state
        .pending
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if pending.as_ref().is_some_and(|(id, _)| *id == run) {
        *pending = None;
    }
    result
}

impl CardAttestor {
    fn refresh(&self) -> SharedCard {
        let mut pending = self
            .state
            .pending
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, run)) = pending.as_ref() {
            return run.clone();
        }
        let id = self
            .state
            .runs
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let run = attest(self.state.clone(), id).boxed().shared();
        *pending = Some((id, run.clone()));
        run
    }

    /// The signed card.
    pub async fn card(&self) -> Result<AgentCard, A2aError> {
        let share = self.state.options.refresh_share.unwrap_or(0.2);
        let decision = {
            let current = self
                .state
                .current
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match current.as_ref() {
                None => None,
                Some(current) => {
                    let left = current.expires_at - self.state.now();
                    if left <= (current.expires_at - current.signed_at) * share {
                        None
                    } else {
                        Some(current.card.clone())
                    }
                }
            }
        };
        match decision {
            Some(card) => Ok(card),
            None => self.refresh().await,
        }
    }
}

impl From<CardAttestor> for CardSource {
    fn from(attestor: CardAttestor) -> Self {
        CardSource::Build(Arc::new(move || {
            let attestor = attestor.clone();
            async move { attestor.card().await }.boxed()
        }))
    }
}
