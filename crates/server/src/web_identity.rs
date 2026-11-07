//! Port of `packages/server/src/web-identity.ts`: verification of external OIDC tokens for
//! AssumeRoleWithWebIdentity (GitHub Actions, GitLab, Kubernetes, cloud workload identity), plus the validators for
//! OIDC provider and web-identity trust settings.
//!
//! This is a separate verifier from IAM's own session JWTs: algorithms come from each provider's allowlist, the `typ`
//! must be absent, `JWT` or `application/jwt` (never `biam-session+jwt` or `at+jwt`), and IAM's own issuer is refused.

use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use better_iam_core::{IamError, IamResult};
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use url::Url;

use crate::hosts::url_hostname;
use crate::js::{invalid_input, utf16_len};
use crate::session_tokens::jose::{self, JoseError, JwkSet};

/// Signature algorithms a provider may allow. Symmetric algorithms and `none` are never accepted.
pub const WEB_IDENTITY_ALGORITHMS: &[&str] = &[
    "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA",
];
/// Used when a provider does not name its algorithms.
pub const DEFAULT_WEB_IDENTITY_ALGORITHMS: &[&str] = &["RS256", "ES256"];

/// A verified external token. `context` holds the flattened claims as `token.<claim>` condition keys.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifiedWebIdentity {
    #[serde(rename = "issuer")]
    pub issuer: String,
    #[serde(rename = "subject")]
    pub subject: String,
    /// The provider audience the token was accepted for.
    #[serde(rename = "audience")]
    pub audience: String,
    #[serde(rename = "jti", default, skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Epoch seconds.
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    /// Epoch seconds.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(rename = "context")]
    pub context: Map<String, Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl VerifiedWebIdentity {
    /// The verified identity as JSON (numbers as JavaScript numbers).
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        map.insert("issuer".into(), Value::String(self.issuer.clone()));
        map.insert("subject".into(), Value::String(self.subject.clone()));
        map.insert("audience".into(), Value::String(self.audience.clone()));
        if let Some(jti) = &self.jti {
            map.insert("jti".into(), Value::String(jti.clone()));
        }
        map.insert("issuedAt".into(), crate::js::number(self.issued_at));
        map.insert("expiresAt".into(), crate::js::number(self.expires_at));
        map.insert("context".into(), Value::Object(self.context.clone()));
        Value::Object(map)
    }
}

/// `WebIdentityFailureReason`: `malformed`, `type`, `algorithm`, `unknown-key`, `signature`, `issuer`, `audience`,
/// `expired`, `not-yet-valid`, `too-old`, `lifetime`, `claims` or `jwks-unavailable`.
pub type WebIdentityFailureReason = String;

/// A refused external token. Callers turn every reason into the same public error; `reason` is for audits.
#[derive(Debug, Clone, PartialEq)]
pub struct WebIdentityFailure {
    pub reason: WebIdentityFailureReason,
}

/// The code a [`WebIdentityFailure`] travels under inside an `IamError` (it is not an `IamError` in TypeScript, so
/// callers always catch it).
const FAILURE_CODE: &str = "WEB_IDENTITY_FAILURE";
const FAILURE_PREFIX: &str = "The web identity token was not accepted (";

impl WebIdentityFailure {
    /// `new WebIdentityFailure(reason)`.
    pub fn new(reason: &str) -> Self {
        Self {
            reason: reason.to_owned(),
        }
    }

    /// `The web identity token was not accepted (${reason})`.
    pub fn message(&self) -> String {
        format!("{FAILURE_PREFIX}{})", self.reason)
    }

    /// The failure an error carries, when it is one (`error instanceof WebIdentityFailure`).
    pub fn from_error(error: &IamError) -> Option<Self> {
        if error.code != FAILURE_CODE {
            return None;
        }
        let reason = error
            .message
            .strip_prefix(FAILURE_PREFIX)?
            .strip_suffix(')')?;
        Some(Self::new(reason))
    }
}

impl std::fmt::Display for WebIdentityFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message())
    }
}

impl From<WebIdentityFailure> for IamError {
    fn from(error: WebIdentityFailure) -> Self {
        IamError::with_status(FAILURE_CODE, error.message(), 500)
    }
}

/// The verifier contract (`WebIdentityVerifier` of web-identity.ts).
pub use crate::contracts::WebIdentityVerifier;

const MAX_TOKEN_LENGTH: usize = 8192;
const MAX_FETCHED_KEYS: usize = 32;
const NEGATIVE_CACHE_MS: f64 = 30_000.0;
const REFETCH_COOLDOWN_MS: f64 = 30_000.0;
const MAX_CACHED_PROVIDERS: usize = 1000;
static TOKEN_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$").expect("valid regex")
});
static BASE64URL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_-]+$").expect("valid regex"));

/// `reasonFor(error)` of web-identity.ts.
fn reason_for(error: &JoseError) -> &'static str {
    match error {
        JoseError::KeySetUnavailable => "jwks-unavailable",
        JoseError::Expired { claim } => {
            if claim == "iat" {
                "too-old"
            } else {
                "expired"
            }
        }
        JoseError::ClaimValidation { claim, reason } => {
            if reason == "missing" || reason == "invalid" {
                "claims"
            } else if claim == "iss" {
                "issuer"
            } else if claim == "aud" {
                "audience"
            } else if claim == "nbf" || claim == "iat" {
                "not-yet-valid"
            } else if claim == "typ" {
                "type"
            } else {
                "claims"
            }
        }
        JoseError::AlgNotAllowed | JoseError::NotSupported => "algorithm",
        JoseError::NoMatchingKey | JoseError::MultipleMatchingKeys => "unknown-key",
        JoseError::SignatureFailed => "signature",
        _ => "malformed",
    }
}

/// `base64urlBytes(value)`: the decoded length of a base64url string, 0 for anything else.
fn base64url_bytes(value: Option<&Value>) -> usize {
    match value {
        Some(Value::String(text)) if BASE64URL.is_match(text) => text.len() * 6 / 8,
        _ => 0,
    }
}

/// `modulusBits(value)`: the bit length of a base64url big-endian integer (leading zero bits excluded).
fn modulus_bits(value: Option<&Value>) -> usize {
    if base64url_bytes(value) == 0 {
        return 0;
    }
    let bytes = better_iam_auth::util::node_base64_decode(
        value.and_then(Value::as_str).unwrap_or_default(),
    );
    let Some(index) = bytes.iter().position(|byte| *byte != 0) else {
        return 0;
    };
    (bytes.len() - index) * 8 - bytes[index].leading_zeros() as usize
}

/// `usableKey(value)`: the allowlisted public members of an acceptable verification key, or None when the key is
/// unusable.
fn usable_key(value: &Value) -> Option<Map<String, Value>> {
    let Value::Object(key) = value else {
        return None;
    };
    if ["d", "p", "q", "dp", "dq", "qi", "k", "oth"]
        .iter()
        .any(|member| key.get(*member).is_some())
    {
        return None;
    }
    if key.get("use").is_some() && key.get("use").and_then(Value::as_str) != Some("sig") {
        return None;
    }
    if let Some(ops) = key.get("key_ops")
        && !matches!(ops, Value::Array(items) if items.iter().any(|item| item.as_str() == Some("verify")))
    {
        return None;
    }
    if let Some(kid) = key.get("kid")
        && !matches!(kid, Value::String(kid) if utf16_len(kid) <= 256)
    {
        return None;
    }
    if let Some(alg) = key.get("alg")
        && !alg
            .as_str()
            .is_some_and(|alg| WEB_IDENTITY_ALGORITHMS.contains(&alg))
    {
        return None;
    }
    let text = |name: &str| key.get(name).cloned().unwrap_or(Value::Null);
    let mut common = Map::new();
    common.insert("kty".into(), text("kty"));
    if key.get("kid").is_some() {
        common.insert("kid".into(), text("kid"));
    }
    if key.get("alg").is_some() {
        common.insert("alg".into(), text("alg"));
    }
    if key.get("use").is_some() {
        common.insert("use".into(), Value::from("sig"));
    }
    match key.get("kty").and_then(Value::as_str) {
        Some("RSA") => {
            // RSA keys under 2048 bits are refused; e must be present.
            if modulus_bits(key.get("n")) < 2048 || base64url_bytes(key.get("e")) == 0 {
                return None;
            }
            common.insert("n".into(), text("n"));
            common.insert("e".into(), text("e"));
            Some(common)
        }
        Some("EC") => {
            if !matches!(
                key.get("crv").and_then(Value::as_str),
                Some("P-256" | "P-384" | "P-521")
            ) {
                return None;
            }
            if base64url_bytes(key.get("x")) == 0 || base64url_bytes(key.get("y")) == 0 {
                return None;
            }
            common.insert("crv".into(), text("crv"));
            common.insert("x".into(), text("x"));
            common.insert("y".into(), text("y"));
            Some(common)
        }
        Some("OKP") => {
            if key.get("crv").and_then(Value::as_str) != Some("Ed25519")
                || base64url_bytes(key.get("x")) == 0
            {
                return None;
            }
            common.insert("crv".into(), Value::from("Ed25519"));
            common.insert("x".into(), text("x"));
            Some(common)
        }
        _ => None,
    }
}

const LOOPBACK_HOSTS: [&str; 3] = ["localhost", "127.0.0.1", "[::1]"];

/// `/[\u0000-\u001f\u007f]/`.
fn has_control_or_delete(value: &str) -> bool {
    value.chars().any(|c| (c as u32) < 0x20 || c == '\u{7f}')
}

/// What [`web_identity_issuer`] checks besides the URL shape.
#[derive(Debug, Clone, Copy, Default)]
pub struct IssuerRules<'a> {
    pub allow_insecure_localhost: bool,
    pub self_issuer: Option<&'a str>,
    pub allowed_issuers: Option<&'a [String]>,
}

/// `webIdentityIssuer(value, options)`: an absolute https URL without credentials, query or fragment, at most 512
/// characters (http only for loopback hosts with `allowInsecureLocalhost`). IAM's own issuer is refused, and with
/// `allowedIssuers` the issuer must be on it. Returns the value unchanged; comparisons are exact.
pub fn web_identity_issuer(value: Option<&Value>, rules: &IssuerRules<'_>) -> IamResult<String> {
    let value = match value {
        Some(Value::String(text))
            if !text.is_empty() && utf16_len(text) <= 512 && !has_control_or_delete(text) =>
        {
            text.clone()
        }
        _ => return Err(invalid_input("Invalid issuer")),
    };
    let Ok(url) = Url::parse(&value) else {
        return Err(invalid_input("The issuer must be an absolute URL"));
    };
    let insecure_local =
        rules.allow_insecure_localhost && LOOPBACK_HOSTS.contains(&url_hostname(&url).as_str());
    if url.scheme() != "https" && !(insecure_local && url.scheme() == "http") {
        return Err(invalid_input("The issuer must use https"));
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some_and(|query| !query.is_empty())
        || url.fragment().is_some_and(|fragment| !fragment.is_empty())
        || value.contains(['?', '#'])
    {
        return Err(invalid_input(
            "The issuer cannot carry credentials, a query or a fragment",
        ));
    }
    let trimmed = |issuer: &str| issuer.trim_end_matches('/').to_owned();
    if let Some(self_issuer) = rules.self_issuer
        && trimmed(&value) == trimmed(self_issuer)
    {
        return Err(invalid_input(
            "IAM cannot trust its own issuer as a web identity provider",
        ));
    }
    if let Some(allowed) = rules.allowed_issuers
        && !allowed.contains(&value)
    {
        return Err(invalid_input(
            "The issuer is not in sts.webIdentity.allowedIssuers",
        ));
    }
    Ok(value)
}

/// `webIdentityJwksUri(value, { allowInsecureLocalhost, allowPrivateNetworks })`: https on port 443 without
/// credentials or a fragment (loopback http with the dev option).
pub fn web_identity_jwks_uri(value: Option<&Value>, options: &Value) -> IamResult<String> {
    jwks_uri(
        value,
        crate::js::truthy(options.get("allowInsecureLocalhost")),
        options.get("allowPrivateNetworks") == Some(&Value::Bool(true)),
    )
}

fn jwks_uri(
    value: Option<&Value>,
    allow_insecure_localhost: bool,
    allow_private_networks: bool,
) -> IamResult<String> {
    let value = match value {
        Some(Value::String(text))
            if !text.is_empty() && utf16_len(text) <= 2048 && !has_control_or_delete(text) =>
        {
            text.clone()
        }
        _ => return Err(invalid_input("Invalid jwksUri")),
    };
    let checked = crate::safe_fetch::check_fetch_url(
        &value,
        &crate::safe_fetch::SafeFetchAddressOptions {
            allow_private_networks,
            allow_insecure_localhost,
            any_port: false,
        },
    );
    if let Err(error) = checked {
        if error.reason == crate::safe_fetch::SafeFetchFailureReason::Address {
            return Err(invalid_input(
                "The jwksUri must not point at a private address",
            ));
        }
        return Err(invalid_input(
            "The jwksUri must be an https URL on port 443 without credentials or a fragment",
        ));
    }
    Ok(value)
}

/// `webIdentityKeys(value)`: 1 to 20 public keys (RSA of at least 2048 bits, EC P-256/P-384/P-521, OKP Ed25519),
/// `use` absent or `sig`. Returns an allowlisted copy (`{ keys }`).
pub fn web_identity_keys(value: Option<&Value>) -> IamResult<Value> {
    let Some(Value::Object(set)) = value else {
        return Err(invalid_input("jwks must be an object with keys"));
    };
    let keys = match set.get("keys") {
        Some(Value::Array(keys)) if !keys.is_empty() && keys.len() <= 20 => keys,
        _ => return Err(invalid_input("jwks must contain 1 to 20 keys")),
    };
    let mut usable = Vec::with_capacity(keys.len());
    for key in keys {
        let Some(key) = usable_key(key) else {
            return Err(invalid_input(
                "jwks keys must be public RSA (at least 2048 bits), EC (P-256, P-384, P-521) or Ed25519 signature keys",
            ));
        };
        usable.push(Value::Object(key));
    }
    Ok(json!({ "keys": usable }))
}

/// `webIdentityAlgorithms(value)`: a non-empty subset of `WEB_IDENTITY_ALGORITHMS` (default RS256 and ES256).
pub fn web_identity_algorithms(value: Option<&Value>) -> IamResult<Vec<String>> {
    let Some(value) = value else {
        return Ok(DEFAULT_WEB_IDENTITY_ALGORITHMS
            .iter()
            .map(|alg| (*alg).to_owned())
            .collect());
    };
    let items = match value {
        Value::Array(items)
            if !items.is_empty()
                && items.iter().all(|alg| {
                    alg.as_str()
                        .is_some_and(|alg| WEB_IDENTITY_ALGORITHMS.contains(&alg))
                }) =>
        {
            items
        }
        _ => {
            return Err(invalid_input(format!(
                "algorithms must be a non-empty subset of {}",
                WEB_IDENTITY_ALGORITHMS.join(", ")
            )));
        }
    };
    Ok(crate::js::unique(
        items
            .iter()
            .filter_map(|alg| alg.as_str().map(str::to_owned)),
    ))
}

/// `webIdentityAudiences(value)`: 1 to 10 strings of 1 to 256 characters.
pub fn web_identity_audiences(value: Option<&Value>) -> IamResult<Vec<String>> {
    let items = match value {
        Some(Value::Array(items))
            if !items.is_empty()
                && items.len() <= 10
                && items.iter().all(|item| {
                    matches!(item, Value::String(text)
                        if !text.is_empty() && utf16_len(text) <= 256 && !has_control_or_delete(text))
                }) =>
        {
            items
        }
        _ => {
            return Err(invalid_input(
                "audiences must contain 1 to 10 strings of at most 256 characters",
            ));
        }
    };
    Ok(crate::js::unique(
        items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned)),
    ))
}

static CLAIM_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^token\.[A-Za-z0-9_:.-]{1,122}$").expect("valid regex"));
const MAX_CONDITION_ENTRIES: usize = 20;
const CONDITION_ACTION: &str = "sts:AssumeRoleWithWebIdentity";

/// `webIdentityClaimName(value)`: a flattened claim name as used in conditions, `tagClaims` and
/// `sourceIdentityClaim`: `token.<claim>`.
pub fn web_identity_claim_name(value: Option<&Value>) -> IamResult<String> {
    match value {
        Some(Value::String(name)) if CLAIM_KEY.is_match(name) => Ok(name.clone()),
        _ => Err(invalid_input(
            "Claim names must look like token.<claim> (letters, digits, _ : . -)",
        )),
    }
}

/// `pinsSubject(value)`: whether a `StringLike` value on `token.sub` names a workload rather than a whole platform:
/// any wildcard (`*`, `?`) comes after at least two complete segments (each ended by `:` or `/`).
fn pins_subject(value: &str) -> bool {
    let Some(first) = value.find(['*', '?']) else {
        return true;
    };
    let segments: Vec<&str> = value[..first].split([':', '/']).collect();
    let complete = segments[..segments.len().saturating_sub(1)]
        .iter()
        .filter(|segment| !segment.is_empty())
        .count();
    complete >= 2
}

/// `webIdentityConditions(value)`: the core condition grammar over `token.<claim>` keys, at most 20 operator/key
/// entries, no policy variables, and a mandatory subject pin: a `StringEquals` or `StringLike` entry on `token.sub`
/// whose values are non-empty and, for `StringLike`, put any wildcard only after two complete segments (else
/// WEAK_TRUST_CONDITIONS). Returns a copy.
pub fn web_identity_conditions(value: Option<&Value>) -> IamResult<Value> {
    let Some(Value::Object(conditions)) = value else {
        return Err(invalid_input("conditions must be an operator map"));
    };
    let mut entries = 0usize;
    for (_, attributes) in better_iam_core::js::entries(conditions) {
        let Value::Object(attributes) = attributes else {
            return Err(invalid_input("conditions must map operators to claim keys"));
        };
        for (key, expected) in better_iam_core::js::entries(attributes) {
            entries += 1;
            if !CLAIM_KEY.is_match(key) {
                return Err(invalid_input(format!(
                    "Condition key {key} must look like token.<claim>"
                )));
            }
            let values: Vec<&Value> = match expected {
                Value::Array(items) => items.iter().collect(),
                other => vec![other],
            };
            if values
                .iter()
                .any(|item| item.as_str().is_some_and(|text| text.contains("${")))
            {
                return Err(invalid_input(
                    "Policy variables are not allowed in web identity conditions",
                ));
            }
        }
    }
    if entries > MAX_CONDITION_ENTRIES {
        return Err(invalid_input(format!(
            "conditions may contain at most {MAX_CONDITION_ENTRIES} entries"
        )));
    }
    better_iam_core::validate_policy(&json!({
        "version": 1,
        "statements": [{
            "effect": "allow",
            "actions": [CONDITION_ACTION],
            "resources": ["trust/*"],
            "conditions": Value::Object(conditions.clone()),
        }],
    }))?;
    let pinned = ["StringEquals", "StringLike"].iter().any(|operator| {
        let Some(expected) = conditions
            .get(*operator)
            .and_then(|attributes| attributes.get("token.sub"))
        else {
            return false;
        };
        let values: Vec<&Value> = match expected {
            Value::Array(items) => items.iter().collect(),
            other => vec![other],
        };
        values.iter().all(|item| {
            matches!(item, Value::String(text)
                if !text.is_empty() && (*operator == "StringEquals" || pins_subject(text)))
        })
    });
    if !pinned {
        return Err(IamError::new(
            "WEAK_TRUST_CONDITIONS",
            "Web identity trusts must pin token.sub with StringEquals or StringLike (a wildcard only after two complete segments, such as repo:acme/*)",
        ));
    }
    Ok(Value::Object(conditions.clone()))
}

static SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_:.-]{1,64}$").expect("valid regex"));
const UNSAFE_SEGMENTS: [&str; 3] = ["__proto__", "prototype", "constructor"];
const MAX_CLAIM_KEYS: usize = 128;
const MAX_CLAIM_DEPTH: usize = 3;
const MAX_CLAIM_STRING: usize = 1024;
const MAX_CLAIM_ARRAY: usize = 64;

/// `scalar(value)`: a string of at most 1024 characters, a finite number or a boolean.
fn scalar(value: &Value) -> bool {
    match value {
        Value::String(text) => utf16_len(text) <= MAX_CLAIM_STRING,
        Value::Number(number) => better_iam_core::js::number_value(number).is_finite(),
        Value::Bool(_) => true,
        _ => false,
    }
}

/// `flattenClaims(payload)`: a verified payload as `token.<path>` condition keys: nested objects to depth 3 joined
/// with '.', segments matching /^[A-Za-z0-9_:.-]{1,64}$/, strings up to 1024 characters, finite numbers, booleans,
/// and arrays of up to 64 such scalars; at most 128 keys. Anything else is left out.
pub fn flatten_claims(payload: &Map<String, Value>) -> Map<String, Value> {
    fn walk(
        value: &Map<String, Value>,
        prefix: &str,
        depth: usize,
        result: &mut Map<String, Value>,
        count: &mut usize,
    ) {
        for (name, item) in better_iam_core::js::entries(value) {
            if *count >= MAX_CLAIM_KEYS {
                return;
            }
            if !SEGMENT.is_match(name) || UNSAFE_SEGMENTS.contains(&name.as_str()) {
                continue;
            }
            let key = format!("{prefix}.{name}");
            if !CLAIM_KEY.is_match(&key) {
                continue;
            }
            if scalar(item) {
                result.insert(key, item.clone());
                *count += 1;
            } else if let Value::Array(items) = item {
                if items.len() <= MAX_CLAIM_ARRAY && items.iter().all(scalar) {
                    result.insert(key, item.clone());
                    *count += 1;
                }
            } else if let Value::Object(nested) = item
                && depth < MAX_CLAIM_DEPTH
            {
                walk(nested, &key, depth + 1, result, count);
            }
        }
    }
    let mut result = Map::new();
    let mut count = 0;
    walk(payload, "token", 1, &mut result, &mut count);
    result
}

/// `matchWebIdentityConditions(conditions, context, trustId)`: evaluates trust conditions against flattened claims
/// with the core policy engine (an allow statement for `sts:AssumeRoleWithWebIdentity` on `trust/{trustId}`).
/// Returns `{ matched, failed }`; `failed` lists each unmet entry as `Operator:key`.
pub fn match_web_identity_conditions(
    conditions: &Value,
    context: &Map<String, Value>,
    trust_id: &str,
) -> IamResult<Value> {
    let resource = format!("trust/{trust_id}");
    let evaluate = |entries: Value| -> IamResult<bool> {
        let decision = better_iam_core::evaluate_policy_json(&json!({
            "grants": [{
                "version": 1,
                "statements": [{
                    "effect": "allow",
                    "actions": [CONDITION_ACTION],
                    "resources": [resource],
                    "conditions": entries,
                }],
            }],
            "action": CONDITION_ACTION,
            "resource": resource,
            "context": Value::Object(context.clone()),
        }))?;
        Ok(decision.allowed)
    };
    let mut failed: Vec<Value> = Vec::new();
    if let Value::Object(operators) = conditions {
        for (operator, attributes) in better_iam_core::js::entries(operators) {
            let Value::Object(attributes) = attributes else {
                continue;
            };
            for (key, expected) in better_iam_core::js::entries(attributes) {
                let mut entry = Map::new();
                let mut inner = Map::new();
                inner.insert(key.clone(), expected.clone());
                entry.insert(operator.clone(), Value::Object(inner));
                if !evaluate(Value::Object(entry))? {
                    failed.push(Value::String(format!("{operator}:{key}")));
                }
            }
        }
    }
    let matched = failed.is_empty() && evaluate(conditions.clone())?;
    Ok(json!({ "matched": matched, "failed": failed }))
}

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// `webIdentityReplayId(providerId, jti, token)`: the replay-cache key of a token at a provider (hex): by `jti` when
/// present, else by the hash of the token's signed content (`header.payload`). The signature segment is left out on
/// purpose: it is malleable without the key, so hashing the whole token would let one token be redeemed several
/// times under different spellings.
pub fn web_identity_replay_id(
    provider_id: &str,
    jti: Option<&str>,
    token: &str,
) -> IamResult<String> {
    let signed = &token[..token.rfind('.').unwrap_or(0)];
    let id = match jti.filter(|jti| !jti.is_empty()) {
        Some(jti) => format!("jti:{jti}"),
        None => format!("tok:{}", sha256_hex(signed)),
    };
    Ok(sha256_hex(&format!("wi\n{provider_id}\n{id}")))
}

/// The settings the verifier runs with (`WebIdentityVerifierOptions`).
#[derive(Clone)]
struct VerifierOptions {
    jwks_cache_seconds: f64,
    fetch_timeout_ms: f64,
    max_jwks_bytes: f64,
    allow_private_networks: bool,
    allow_insecure_localhost: bool,
    fetch_json: Option<crate::options::FetchJsonFn>,
    now: crate::context::NowFn,
    self_issuer: Option<String>,
}

type Refresh = Shared<BoxFuture<'static, Result<Arc<JwkSet>, ()>>>;

/// `CachedKeys`: a provider's keys.
#[derive(Default)]
struct CachedKeys {
    updated_at: Option<Value>,
    /// When the current keys were fetched (ms); None before the first success.
    fetched_at: Option<f64>,
    keys: Option<Arc<JwkSet>>,
    /// When the last fetch failed (ms), for the negative cache.
    failed_at: Option<f64>,
    pending: Option<Refresh>,
    /// The static keys of a provider configured with `jwks`.
    local: Option<Arc<JwkSet>>,
}

type Entry = Arc<Mutex<CachedKeys>>;

fn lock(entry: &Entry) -> std::sync::MutexGuard<'_, CachedKeys> {
    entry
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct VerifierInner {
    options: VerifierOptions,
    cache: Mutex<IndexMap<String, Entry>>,
}

/// The web-identity verifier (`createWebIdentityVerifier`'s result).
pub struct WebIdentityTokenVerifier {
    inner: Arc<VerifierInner>,
}

/// `createWebIdentityVerifier({ ...config.sts.webIdentity, fetchJson, now, selfIssuer })`: creates the web-identity
/// verifier. Fetched keys are cached per provider id (dropped when `updatedAt` changes) for `jwksCacheSeconds`,
/// fetched single-flight, remembered as unavailable for 30 s after a failure, and refetched on an unknown `kid` at
/// most once per 30 s. Nothing is fetched until a token needs it.
pub fn create_web_identity_verifier(
    options: &crate::options::ResolvedWebIdentityConfig,
    fetch_json: Option<crate::options::FetchJsonFn>,
    now: crate::context::NowFn,
    self_issuer: &str,
) -> IamResult<Arc<dyn WebIdentityVerifier>> {
    Ok(Arc::new(web_identity_verifier(
        options,
        fetch_json,
        now,
        Some(self_issuer),
    )))
}

/// [`create_web_identity_verifier`] as its concrete type (`selfIssuer` optional).
pub fn web_identity_verifier(
    options: &crate::options::ResolvedWebIdentityConfig,
    fetch_json: Option<crate::options::FetchJsonFn>,
    now: crate::context::NowFn,
    self_issuer: Option<&str>,
) -> WebIdentityTokenVerifier {
    WebIdentityTokenVerifier {
        inner: Arc::new(VerifierInner {
            options: VerifierOptions {
                jwks_cache_seconds: options.jwks_cache_seconds,
                fetch_timeout_ms: options.fetch_timeout_ms,
                max_jwks_bytes: options.max_jwks_bytes,
                allow_private_networks: options.allow_private_networks,
                allow_insecure_localhost: options.allow_insecure_localhost,
                fetch_json,
                now,
                self_issuer: self_issuer.map(str::to_owned),
            },
            cache: Mutex::new(IndexMap::new()),
        }),
    }
}

/// A thrown error that is not a `WebIdentityFailure` (a malformed stored provider read as TypeScript would read it).
fn thrown() -> IamError {
    crate::js::internal_error()
}

/// The cache key of a provider id (`Map` keys compare by value and type).
fn provider_key(id: Option<&Value>) -> String {
    match id {
        Some(Value::String(id)) => id.clone(),
        Some(other) => format!("\u{0}{}", better_iam_core::js::stringify(other)),
        None => "\u{0}undefined".to_owned(),
    }
}

fn same_updated_at(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => better_iam_core::js::strict_equal(left, right),
        _ => false,
    }
}

impl VerifierInner {
    fn now(&self) -> f64 {
        (self.options.now)()
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, IndexMap<String, Entry>> {
        self.cache
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    async fn fetch_json(&self, url: Url) -> Result<Value, ()> {
        if let Some(fetch_json) = &self.options.fetch_json {
            return fetch_json(url).await.map_err(|_| ());
        }
        crate::safe_fetch::fetch_json_safely(
            url.as_str(),
            &crate::safe_fetch::SafeFetchOptions {
                timeout_ms: self.options.fetch_timeout_ms.max(0.0) as u64,
                max_bytes: self.options.max_jwks_bytes.max(0.0) as u64,
                allow_private_networks: self.options.allow_private_networks,
                allow_insecure_localhost: self.options.allow_insecure_localhost,
            },
        )
        .await
        .map_err(|_| ())
    }

    /// `checkedUrl(value)`.
    fn checked_url(&self, value: Option<&Value>) -> Result<Url, ()> {
        let checked = jwks_uri(
            value,
            self.options.allow_insecure_localhost,
            self.options.allow_private_networks,
        )
        .map_err(|_| ())?;
        Url::parse(&checked).map_err(|_| ())
    }

    /// `download(provider)`: discovery (when there is no `jwksUri`), then the key set.
    async fn download(&self, provider: &Map<String, Value>) -> Result<Arc<JwkSet>, ()> {
        let mut jwks_uri = provider.get("jwksUri").cloned();
        if jwks_uri.is_none() {
            let Some(Value::String(issuer)) = provider.get("issuer") else {
                return Err(());
            };
            let discovery = Url::parse(&format!(
                "{}/.well-known/openid-configuration",
                issuer.trim_end_matches('/')
            ))
            .map_err(|_| ())?;
            let url = self.checked_url(Some(&Value::String(discovery.as_str().to_owned())))?;
            let document = self.fetch_json(url).await?;
            let issuer_matches = match (&document, provider.get("issuer")) {
                (Value::Object(document), Some(issuer)) => document
                    .get("issuer")
                    .is_some_and(|own| better_iam_core::js::strict_equal(own, issuer)),
                _ => false,
            };
            if !issuer_matches {
                return Err(());
            }
            jwks_uri = document.get("jwks_uri").cloned();
        }
        let url = self.checked_url(jwks_uri.as_ref())?;
        let body = self.fetch_json(url).await?;
        let Some(Value::Array(keys)) = body.as_object().and_then(|body| body.get("keys")) else {
            return Err(());
        };
        let keys: Vec<Map<String, Value>> = keys
            .iter()
            .filter_map(usable_key)
            .take(MAX_FETCHED_KEYS)
            .collect();
        if keys.is_empty() {
            return Err(());
        }
        Ok(Arc::new(JwkSet::from_keys(keys)))
    }

    /// `entryFor(provider)`.
    fn entry_for(&self, provider: &Map<String, Value>) -> Entry {
        let key = provider_key(provider.get("id"));
        let updated_at = provider.get("updatedAt");
        let mut cache = self.cache();
        if let Some(entry) = cache.get(&key)
            && same_updated_at(lock(entry).updated_at.as_ref(), updated_at)
        {
            return entry.clone();
        }
        if !cache.contains_key(&key) && cache.len() >= MAX_CACHED_PROVIDERS {
            cache.shift_remove_index(0);
        }
        let entry: Entry = Arc::new(Mutex::new(CachedKeys {
            updated_at: updated_at.cloned(),
            ..CachedKeys::default()
        }));
        cache.insert(key, entry.clone());
        entry
    }

    /// `refresh(provider, entry)`: fetches the provider's keys once for all concurrent callers and records the
    /// outcome.
    fn refresh(self: &Arc<Self>, provider: &Map<String, Value>, entry: &Entry) -> Refresh {
        let mut state = lock(entry);
        if let Some(pending) = &state.pending {
            return pending.clone();
        }
        let inner = self.clone();
        let owned_entry = entry.clone();
        let provider = provider.clone();
        let future: BoxFuture<'static, Result<Arc<JwkSet>, ()>> = Box::pin(async move {
            let outcome = inner.download(&provider).await;
            let now = inner.now();
            let mut state = lock(&owned_entry);
            let result = match outcome {
                Ok(keys) => {
                    state.keys = Some(keys.clone());
                    state.fetched_at = Some(now);
                    state.failed_at = None;
                    Ok(keys)
                }
                Err(()) => {
                    state.failed_at = Some(now);
                    Err(())
                }
            };
            state.pending = None;
            result
        });
        let shared = future.shared();
        state.pending = Some(shared.clone());
        shared
    }

    /// `fetchedKeys(provider)`.
    async fn fetched_keys(
        self: &Arc<Self>,
        provider: &Map<String, Value>,
    ) -> Result<Arc<JwkSet>, JoseError> {
        let entry = self.entry_for(provider);
        let now = self.now();
        let cache_ms = self.options.jwks_cache_seconds * 1000.0;
        {
            let state = lock(&entry);
            if let (Some(keys), Some(fetched_at)) = (&state.keys, state.fetched_at)
                && now - fetched_at < cache_ms
            {
                return Ok(keys.clone());
            }
            if let Some(failed_at) = state.failed_at
                && now - failed_at < NEGATIVE_CACHE_MS
                && state.pending.is_none()
            {
                return Err(JoseError::KeySetUnavailable);
            }
        }
        self.refresh(provider, &entry)
            .await
            .map_err(|()| JoseError::KeySetUnavailable)
    }

    /// `refetchForUnknownKid(provider)`: refetches after an unknown kid, unless the cooldown since the last fetch
    /// attempt is still running. A failed attempt starts the cooldown too.
    async fn refetch_for_unknown_kid(
        self: &Arc<Self>,
        provider: &Map<String, Value>,
    ) -> Option<Result<Arc<JwkSet>, JoseError>> {
        let entry = self.entry_for(provider);
        let pending = lock(&entry).pending.clone();
        if let Some(pending) = pending {
            return Some(pending.await.map_err(|()| JoseError::KeySetUnavailable));
        }
        let last_attempt = {
            let state = lock(&entry);
            state
                .fetched_at
                .unwrap_or(f64::NEG_INFINITY)
                .max(state.failed_at.unwrap_or(f64::NEG_INFINITY))
        };
        if self.now() - last_attempt < REFETCH_COOLDOWN_MS.max(NEGATIVE_CACHE_MS) {
            return None;
        }
        Some(
            self.refresh(provider, &entry)
                .await
                .map_err(|()| JoseError::KeySetUnavailable),
        )
    }

    /// `localKeys(provider)`: static keys are imported once per provider version.
    fn local_keys(&self, provider: &Map<String, Value>) -> Arc<JwkSet> {
        let entry = self.entry_for(provider);
        let mut state = lock(&entry);
        if let Some(local) = &state.local {
            return local.clone();
        }
        let usable = match provider.get("jwks").and_then(|jwks| jwks.get("keys")) {
            Some(Value::Array(keys)) => keys.iter().filter_map(usable_key).collect(),
            _ => Vec::new(),
        };
        let local = Arc::new(JwkSet::from_keys(usable));
        state.local = Some(local.clone());
        local
    }

    /// `check(provider, token, keys)`: `jwtVerify` with the provider's settings.
    async fn check(
        &self,
        provider: &Map<String, Value>,
        token: &str,
        keys: &JwkSet,
    ) -> Result<Map<String, Value>, JoseError> {
        let algorithms = match provider.get("algorithms") {
            Some(Value::Array(items)) if items.iter().all(Value::is_string) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect::<Vec<_>>(),
            _ => return Err(JoseError::TypeError),
        };
        let audiences = match provider.get("audiences") {
            Some(Value::Array(items)) => items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect::<Vec<_>>(),
            Some(Value::String(text)) => text.chars().map(|c| c.to_string()).collect(),
            _ => return Err(JoseError::TypeError),
        };
        let options = jose::VerifyOptions {
            algorithms: &algorithms,
            issuer: Some(provider.get("issuer").unwrap_or(&Value::Null)),
            audience: Some(&audiences),
            typ: None,
            required_claims: &["iss", "sub", "aud", "exp", "iat"],
            clock_tolerance: provider.get("clockToleranceSeconds"),
            current_ms: self.now(),
            max_token_age: provider.get("maxTokenLifetimeSeconds"),
        };
        jose::jwt_verify(
            token,
            |header| async move { keys.get_key(&header) },
            &options,
        )
        .await
    }

    /// `verify(provider, token)`.
    async fn verify(
        self: &Arc<Self>,
        provider: &Value,
        token: &str,
    ) -> IamResult<VerifiedWebIdentity> {
        let fail = |reason: &str| IamError::from(WebIdentityFailure::new(reason));
        if utf16_len(token) > MAX_TOKEN_LENGTH || !TOKEN_SHAPE.is_match(token) {
            return Err(fail("malformed"));
        }
        let header = jose::decode_protected_header(token).map_err(|_| fail("malformed"))?;
        if let Some(typ) = header.get("typ") {
            let typ = typ.as_str().map(str::to_lowercase).unwrap_or_default();
            let normalized = if typ.contains('/') {
                typ
            } else {
                format!("application/{typ}")
            };
            if normalized != "application/jwt" {
                return Err(fail("type"));
            }
        }
        let Some(Value::String(alg)) = header.get("alg") else {
            return Err(fail("algorithm"));
        };
        let Value::Object(provider) = provider else {
            return Err(thrown());
        };
        let allowed = match provider.get("algorithms") {
            Some(Value::Array(items)) => items.iter().any(|item| item.as_str() == Some(alg)),
            Some(Value::String(text)) => text.contains(alg.as_str()),
            _ => return Err(thrown()),
        };
        if !allowed || !WEB_IDENTITY_ALGORITHMS.contains(&alg.as_str()) {
            return Err(fail("algorithm"));
        }
        if header.get("kid").is_some_and(|kid| !kid.is_string()) {
            return Err(fail("malformed"));
        }
        let Some(Value::String(issuer)) = provider.get("issuer") else {
            return Err(thrown());
        };
        if let Some(self_issuer) = &self.options.self_issuer
            && issuer.trim_end_matches('/') == self_issuer.trim_end_matches('/')
        {
            return Err(fail("issuer"));
        }

        let verified = async {
            if crate::js::truthy(provider.get("jwks")) {
                let keys = self.local_keys(provider);
                return self.check(provider, token, &keys).await;
            }
            let keys = self.fetched_keys(provider).await?;
            match self.check(provider, token, &keys).await {
                Err(JoseError::NoMatchingKey) => {
                    match self.refetch_for_unknown_kid(provider).await {
                        None => Err(JoseError::NoMatchingKey),
                        Some(refreshed) => {
                            let refreshed: Arc<JwkSet> = refreshed?;
                            self.check(provider, token, &refreshed).await
                        }
                    }
                }
                other => other,
            }
        };
        let payload = verified.await.map_err(|error| fail(reason_for(&error)))?;

        let number = |name: &str| payload.get(name).and_then(crate::js::as_number);
        let (Some(iat), Some(exp)) = (number("iat"), number("exp")) else {
            return Err(fail("claims"));
        };
        // `exp - iat > provider.maxTokenLifetimeSeconds`, with JavaScript's coercion of the stored value.
        if let Some(max) = provider
            .get("maxTokenLifetimeSeconds")
            .map(crate::js::to_number)
            && exp - iat > max
        {
            return Err(fail("lifetime"));
        }
        let subject = match payload.get("sub") {
            Some(Value::String(sub)) if !sub.is_empty() && utf16_len(sub) <= 512 => sub.clone(),
            _ => return Err(fail("claims")),
        };
        let jti = match payload.get("jti") {
            None => None,
            Some(Value::String(jti)) if !jti.is_empty() && utf16_len(jti) <= 256 => {
                Some(jti.clone())
            }
            Some(_) => return Err(fail("claims")),
        };
        let token_audiences: Vec<&Value> = match payload.get("aud") {
            Some(Value::Array(items)) => items.iter().collect(),
            Some(other) => vec![other],
            None => Vec::new(),
        };
        let audience = match provider.get("audiences") {
            Some(Value::Array(items)) => items.iter().find(|item| {
                token_audiences
                    .iter()
                    .any(|aud| better_iam_core::js::strict_equal(aud, item))
            }),
            _ => return Err(thrown()),
        };
        let Some(Value::String(audience)) = audience else {
            return Err(fail("audience"));
        };
        Ok(VerifiedWebIdentity {
            issuer: issuer.clone(),
            subject,
            audience: audience.clone(),
            jti,
            issued_at: iat,
            expires_at: exp,
            context: flatten_claims(&payload),
            extra: Map::new(),
        })
    }
}

impl WebIdentityTokenVerifier {
    /// Verifies an external token against a provider (the stored OIDC provider record), or fails with a
    /// [`WebIdentityFailure`] (see [`WebIdentityFailure::from_error`]).
    pub async fn verify_token(
        &self,
        provider: &Value,
        token: &str,
    ) -> IamResult<VerifiedWebIdentity> {
        self.inner.verify(provider, token).await
    }

    /// Drops the cached keys of a provider.
    pub fn forget_provider(&self, provider_id: &str) {
        self.inner
            .cache()
            .shift_remove(&provider_key(Some(&Value::String(provider_id.to_owned()))));
    }
}

#[async_trait]
impl WebIdentityVerifier for WebIdentityTokenVerifier {
    async fn verify(&self, provider: &Value, token: &str) -> IamResult<Value> {
        self.verify_token(provider, token)
            .await
            .map(|verified| verified.to_value())
    }

    fn forget(&self, provider_id: &str) {
        self.forget_provider(provider_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn check(value: Value, rules: &IssuerRules<'_>) -> Result<String, String> {
        web_identity_issuer(Some(&value), rules).map_err(|error| error.message)
    }

    #[test]
    fn issuers() {
        let rules = IssuerRules {
            self_issuer: Some("https://iam.example.com/api/iam"),
            ..IssuerRules::default()
        };
        assert_eq!(
            check(json!("https://token.actions.githubusercontent.com"), &rules).unwrap(),
            "https://token.actions.githubusercontent.com"
        );
        assert_eq!(check(json!(""), &rules).unwrap_err(), "Invalid issuer");
        assert_eq!(
            check(json!("not a url"), &rules).unwrap_err(),
            "The issuer must be an absolute URL"
        );
        assert_eq!(
            check(json!("http://localhost:8080"), &rules).unwrap_err(),
            "The issuer must use https"
        );
        assert!(
            check(
                json!("http://localhost:8080"),
                &IssuerRules {
                    allow_insecure_localhost: true,
                    ..rules
                }
            )
            .is_ok()
        );
        assert_eq!(
            check(json!("https://a.example.com/?"), &rules).unwrap_err(),
            "The issuer cannot carry credentials, a query or a fragment"
        );
        assert_eq!(
            check(json!("https://iam.example.com/api/iam/"), &rules).unwrap_err(),
            "IAM cannot trust its own issuer as a web identity provider"
        );
        let allowed = vec!["https://a.example.com".to_owned()];
        assert_eq!(
            check(
                json!("https://b.example.com"),
                &IssuerRules {
                    allowed_issuers: Some(&allowed),
                    ..rules
                }
            )
            .unwrap_err(),
            "The issuer is not in sts.webIdentity.allowedIssuers"
        );
    }

    #[test]
    fn subject_pins() {
        assert!(pins_subject("repo:acme/api:ref:refs/heads/main"));
        assert!(pins_subject("repo:acme/*"));
        assert!(pins_subject("repo:acme/api:*"));
        assert!(!pins_subject("*"));
        assert!(!pins_subject("repo:*"));
        assert!(!pins_subject("repo:acme*"));
    }

    #[test]
    fn replay_ids_ignore_the_signature() {
        let a = web_identity_replay_id("p1", None, "aaa.bbb.ccc").unwrap();
        let b = web_identity_replay_id("p1", None, "aaa.bbb.ccd").unwrap();
        assert_eq!(a, b);
        assert_ne!(
            a,
            web_identity_replay_id("p1", Some("jti-1"), "aaa.bbb.ccc").unwrap()
        );
        assert_ne!(
            a,
            web_identity_replay_id("p2", None, "aaa.bbb.ccc").unwrap()
        );
    }
}
