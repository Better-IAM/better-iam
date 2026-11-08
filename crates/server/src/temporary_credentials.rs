//! Port of `packages/server/src/temporary-credentials.ts`: the issuance core of temporary credentials (STS).
//!
//! Role sessions (`roles.assume`, web identity) and session tokens (`sts.getSessionToken`) validate their inputs with
//! the helpers below, build a draft session row, and hand it to [`mint_credential`], which issues either a typed opaque
//! token (`biam_rol_…`, `biam_sts_…`) or an IAM-signed session JWT and stores the row. The projections at the end
//! ([`temporary_credential`], [`caller_identity`], [`role_session_summary`], [`audit_session_context`]) are allowlists:
//! they never carry hashes, policies, authority ids or the source session id.

use std::sync::{Arc, LazyLock};

use better_iam_auth::{CredentialTokenType, new_credential_token};
use better_iam_core::{
    AuditSessionContext, AuthenticatedPrincipal, IamError, IamResult, Identity, Record, Session,
    js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::context_keys::is_tag_key;
use crate::js::{ThrownError, defined, invalid_input, js_string, number, number_to_string};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::session_tokens::{MAX_SESSION_TOKEN_LENGTH, SessionTokenClaims};
use crate::utils::hash;

/// How a temporary credential is delivered: the JSON string `"opaque"` (a typed opaque token, the default) or
/// `"jwt"` (an IAM-signed session JWT). Kept as a JSON value so callers compare it with string literals
/// (`format == "jwt"`) and pass it on to the record and audit metadata unchanged.
pub type CredentialFormat = Value;

/// `roles.assume` input (AWS AssumeRole).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssumeRoleInput {
    /// The tenant of the role (the trust's tenant).
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "trustId")]
    pub trust_id: String,
    /// Required when the trust was created with an external ID.
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    /// 60 up to the trust's maximum (default 900, or less when the maximum is lower).
    #[serde(
        rename = "durationSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub duration_seconds: Option<f64>,
    /// A scope-down policy: the session may do only what both the role and this policy allow.
    #[serde(rename = "policy", default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<better_iam_core::PolicyDocument>,
    /// A label for the session (/^[\w+=,.@-]{2,64}$/), exposed as principal.sessionName and in audit events.
    #[serde(
        rename = "sessionName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_name: Option<String>,
    /// The person or workload behind the call, when the trust's sourceIdentityMode permits or requires it.
    #[serde(
        rename = "sourceIdentity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_identity: Option<String>,
    /// Session tags (principal.sessionTags.{key}); every key must be admitted by the trust's allowedTagKeys.
    #[serde(rename = "tags", default, skip_serializing_if = "Option::is_none")]
    pub tags: Option<IndexMap<String, String>>,
    #[serde(rename = "format", default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    /// Session JWTs only: 1 to 5 audiences from `sts.jwt.audiences` (default: the IAM issuer).
    #[serde(rename = "audience", default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `sts.getSessionToken` input (AWS GetSessionToken).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GetSessionTokenInput {
    #[serde(
        rename = "durationSeconds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub duration_seconds: Option<f64>,
    #[serde(rename = "policy", default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<better_iam_core::PolicyDocument>,
    #[serde(
        rename = "sessionName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_name: Option<String>,
    /// A current TOTP code: the token then carries a fresh MFA time (user sources with TOTP only).
    #[serde(rename = "mfaCode", default, skip_serializing_if = "Option::is_none")]
    pub mfa_code: Option<String>,
    #[serde(rename = "format", default, skip_serializing_if = "Option::is_none")]
    pub format: Option<String>,
    #[serde(rename = "audience", default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What every temporary-credential issuer returns. The token appears once, in the response body only. Members in the
/// order `temporaryCredential` writes them (`audience` last).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TemporaryCredential {
    #[serde(rename = "token")]
    pub token: String,
    #[serde(rename = "tokenType")]
    pub token_type: String,
    #[serde(rename = "format")]
    pub format: CredentialFormat,
    /// Epoch milliseconds; never later than the source credential's expiry.
    #[serde(rename = "expiresAt", serialize_with = "crate::js::serialize_number")]
    pub expires_at: f64,
    /// Seconds from issuance to `expiresAt`.
    #[serde(rename = "expiresIn", serialize_with = "crate::js::serialize_number")]
    pub expires_in: f64,
    /// The session the credential opens (`TemporaryCredentialSession`).
    #[serde(rename = "session")]
    pub session: Value,
    /// Session JWTs: the audiences the token names.
    #[serde(rename = "audience", default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `roles.assume`: a temporary credential whose session always names the role and the trust.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleCredential {
    #[serde(rename = "token")]
    pub token: String,
    #[serde(rename = "tokenType")]
    pub token_type: String,
    #[serde(rename = "format")]
    pub format: CredentialFormat,
    /// Epoch milliseconds; never later than the source credential's expiry.
    #[serde(rename = "expiresAt", serialize_with = "crate::js::serialize_number")]
    pub expires_at: f64,
    /// Seconds from issuance to `expiresAt`.
    #[serde(rename = "expiresIn", serialize_with = "crate::js::serialize_number")]
    pub expires_in: f64,
    #[serde(rename = "session")]
    pub session: Value,
    /// Session JWTs: the audiences the token names.
    #[serde(rename = "audience", default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl From<TemporaryCredential> for RoleCredential {
    fn from(credential: TemporaryCredential) -> Self {
        Self {
            token: credential.token,
            token_type: credential.token_type,
            format: credential.format,
            expires_at: credential.expires_at,
            expires_in: credential.expires_in,
            session: credential.session,
            audience: credential.audience,
            extra: credential.extra,
        }
    }
}

/// `sts.getCallerIdentity`: who the presented credential acts as, for every session kind.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallerIdentity {
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "identityTenantId")]
    pub identity_tenant_id: String,
    #[serde(rename = "identityKind")]
    pub identity_kind: String,
    /// The tenant the session acts in (the role's tenant for role sessions).
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "sessionId")]
    pub session_id: String,
    #[serde(rename = "sessionKind")]
    pub session_kind: String,
    #[serde(rename = "format")]
    pub format: CredentialFormat,
    #[serde(rename = "mfa")]
    pub mfa: bool,
    #[serde(
        rename = "authenticatedAt",
        serialize_with = "crate::js::serialize_number"
    )]
    pub authenticated_at: f64,
    #[serde(rename = "issuedAt", serialize_with = "crate::js::serialize_number")]
    pub issued_at: f64,
    #[serde(rename = "expiresAt", serialize_with = "crate::js::serialize_number")]
    pub expires_at: f64,
    #[serde(rename = "method", default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(rename = "roleId", default, skip_serializing_if = "Option::is_none")]
    pub role_id: Option<String>,
    #[serde(rename = "trustId", default, skip_serializing_if = "Option::is_none")]
    pub trust_id: Option<String>,
    #[serde(
        rename = "sourceTenantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_tenant_id: Option<String>,
    #[serde(
        rename = "sessionName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_name: Option<String>,
    #[serde(
        rename = "sourceIdentity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_identity: Option<String>,
    #[serde(
        rename = "sessionTags",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_tags: Option<IndexMap<String, String>>,
    #[serde(rename = "audience", default, skip_serializing_if = "Option::is_none")]
    pub audience: Option<Vec<String>>,
    /// `{ providerId, issuer, subject }`.
    #[serde(
        rename = "webIdentity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub web_identity: Option<Value>,
    #[serde(
        rename = "impersonatorId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub impersonator_id: Option<String>,
    /// Delegated sessions: the agent acting for the identity, and the delegation it acts under.
    #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(
        rename = "delegationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub delegation_id: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A live role session as `roles.listSessions` shows it to the target tenant. Members in the order
/// `roleSessionSummary` writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RoleSessionSummary {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "roleId")]
    pub role_id: String,
    #[serde(rename = "trustId")]
    pub trust_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "mfa")]
    pub mfa: bool,
    #[serde(rename = "format")]
    pub format: CredentialFormat,
    #[serde(rename = "createdAt", serialize_with = "crate::js::serialize_number")]
    pub created_at: f64,
    #[serde(rename = "expiresAt", serialize_with = "crate::js::serialize_number")]
    pub expires_at: f64,
    #[serde(
        rename = "sourceTenantId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_tenant_id: Option<String>,
    #[serde(
        rename = "sessionName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_name: Option<String>,
    #[serde(
        rename = "sourceIdentity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub source_identity: Option<String>,
    /// `{ providerId, subject }`.
    #[serde(
        rename = "webIdentity",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub web_identity: Option<Value>,
    #[serde(rename = "clientIp", default, skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Session names and source identities: 2 to 64 characters of letters, digits and `+=,.@_-` (as in AWS STS). `\w`
/// is ASCII-only, as in a JavaScript regular expression without the `u` flag.
pub const SESSION_NAME_PATTERN: &str = r"^[\w+=,.@-]{2,64}$";

/// `sessionNamePattern`: the pattern's source (`/^[\w+=,.@-]{2,64}$/`). Test values with [`is_session_name`].
pub fn session_name_pattern() -> IamResult<Value> {
    Ok(Value::String(SESSION_NAME_PATTERN.to_owned()))
}

/// `sessionNamePattern.test(value)`.
pub fn is_session_name(value: &str) -> bool {
    let length = value.chars().count();
    (2..=64).contains(&length)
        && value.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '_' | '+' | '=' | ',' | '.' | '@' | '-')
        })
}

/// Session tag values: at most 256 letters, digits, whitespace and `_.:/=+-@` (`/^[\p{L}\p{N}\s_.:/=+\-@]*$/u`).
static LETTER_OR_NUMBER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[\p{L}\p{N}]$").expect("valid pattern"));

fn tag_value_shape(value: &str) -> bool {
    let mut buffer = [0u8; 4];
    value.chars().all(|c| {
        core_js::is_js_whitespace(c)
            || matches!(c, '_' | '.' | ':' | '/' | '=' | '+' | '-' | '@')
            || LETTER_OR_NUMBER.is_match(c.encode_utf8(&mut buffer))
    })
}

/// Session JWT audiences, as for assertions: URL-safe identifiers of at most 256 characters
/// (`/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/`).
fn audience_shape(value: &str) -> bool {
    let mut chars = value.chars();
    matches!(chars.next(), Some(first) if first.is_ascii_alphanumeric())
        && value.chars().count() <= 256
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
}

const MAX_TAGS: usize = 50;
const MAX_PACKED_TAG_BYTES: usize = 2048;
const MAX_AUDIENCES: usize = 5;

/// A trust's default maximum role session, used when it stores none (or none that is usable).
const DEFAULT_TRUST_MAX_SESSION_SECONDS: f64 = 3600.0;

/// A session name, or None when none was given.
pub fn session_name_value(value: Option<&Value>) -> IamResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::String(text) if is_session_name(text) => Ok(Some(text.clone())),
        _ => Err(invalid_input(
            "sessionName must be 2-64 letters, digits or +=,.@_- characters",
        )),
    }
}

/// A caller-stated source identity, or None when none was given.
pub fn source_identity_value(value: Option<&Value>) -> IamResult<Option<String>> {
    let Some(value) = value else {
        return Ok(None);
    };
    match value {
        Value::String(text) if is_session_name(text) => Ok(Some(text.clone())),
        _ => Err(invalid_input(
            "sourceIdentity must be 2-64 letters, digits or +=,.@_- characters",
        )),
    }
}

/// Session tags: at most 50, keys matching /^[A-Za-z][A-Za-z0-9_]{0,63}$/ and unique case-insensitively, values of at
/// most 256 characters from the tag value charset, and at most 2048 bytes as packed JSON. None (or no tags) gives
/// None.
pub fn session_tags_value(value: Option<&Value>) -> IamResult<Option<IndexMap<String, String>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let map = match value {
        Value::Object(map) if !crate::js::is_function(Some(value)) => map,
        _ => {
            return Err(invalid_input(
                "tags must be an object of tag keys to string values",
            ));
        }
    };
    let entries = core_js::entries(map);
    if entries.len() > MAX_TAGS {
        return Err(invalid_input(format!(
            "tags may contain at most {MAX_TAGS} entries"
        )));
    }
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut tags: IndexMap<String, String> = IndexMap::new();
    for (key, tag) in &entries {
        if !is_tag_key(key) {
            return Err(invalid_input(
                "Tag keys must start with a letter and use at most 64 letters, digits or underscores",
            ));
        }
        let folded = core_js::to_lower(key);
        if seen.contains(&folded) {
            return Err(invalid_input(format!(
                "Tag key {key} is repeated (tag keys are case-insensitive)"
            )));
        }
        seen.insert(folded);
        match tag {
            Value::String(text) if crate::js::utf16_len(text) <= 256 && tag_value_shape(text) => {
                tags.insert((*key).clone(), text.clone());
            }
            _ => {
                return Err(invalid_input(format!(
                    "Tag {key} must be a string of at most 256 letters, digits, spaces or _.:/=+-@"
                )));
            }
        }
    }
    if entries.is_empty() {
        return Ok(None);
    }
    let packed: Map<String, Value> = tags
        .iter()
        .map(|(key, tag)| (key.clone(), Value::String(tag.clone())))
        .collect();
    if core_js::stringify(&Value::Object(packed)).len() > MAX_PACKED_TAG_BYTES {
        return Err(invalid_input(format!(
            "tags must pack into at most {MAX_PACKED_TAG_BYTES} bytes"
        )));
    }
    Ok(Some(tags))
}

/// A trust's admitted session tag keys: at most 50 distinct tag keys, or exactly ['*'] for any key.
pub fn allowed_tag_keys_value(value: Option<&Value>) -> IamResult<Vec<String>> {
    let refused = || {
        invalid_input(format!(
            "allowedTagKeys must be a list of at most {MAX_TAGS} tag keys, or ['*']"
        ))
    };
    let Some(Value::Array(items)) = value else {
        return Err(refused());
    };
    if items.len() > MAX_TAGS {
        return Err(refused());
    }
    if items.len() == 1 && items[0] == Value::String("*".into()) {
        return Ok(vec!["*".into()]);
    }
    let mut seen: IndexSet<String> = IndexSet::new();
    let mut keys = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(key) = item else {
            return Err(refused());
        };
        if !is_tag_key(key) {
            return Err(refused());
        }
        let folded = core_js::to_lower(key);
        if seen.contains(&folded) {
            return Err(invalid_input(format!(
                "Tag key {key} is repeated (tag keys are case-insensitive)"
            )));
        }
        seen.insert(folded);
        keys.push(key.clone());
    }
    Ok(keys)
}

/// The requested credential format; `"opaque"` by default.
pub fn credential_format(value: Option<&Value>) -> IamResult<CredentialFormat> {
    match value {
        None => Ok(Value::String("opaque".into())),
        Some(Value::String(format)) if format == "opaque" || format == "jwt" => {
            Ok(Value::String(format.clone()))
        }
        Some(_) => Err(invalid_input("format must be 'opaque' or 'jwt'")),
    }
}

fn is_jwt(format: &CredentialFormat) -> bool {
    format.as_str() == Some("jwt")
}

/// Requested JWT audiences: 1 to 5 URL-safe identifiers, deduplicated, and only with `format: 'jwt'`. Whether each
/// is on the deployment's allowlist and permitted to the caller is checked at issuance ([`mint_credential`]).
pub fn audience_value(
    value: Option<&Value>,
    format: &CredentialFormat,
) -> IamResult<Option<Vec<String>>> {
    let Some(value) = value else {
        return Ok(None);
    };
    if !is_jwt(format) {
        return Err(invalid_input("audience requires format 'jwt'"));
    }
    let items = match value {
        Value::Array(items) if !items.is_empty() && items.len() <= MAX_AUDIENCES => items,
        _ => {
            return Err(invalid_input(format!(
                "audience must list 1 to {MAX_AUDIENCES} audiences"
            )));
        }
    };
    let mut audiences: IndexSet<String> = IndexSet::new();
    for item in items {
        match item {
            Value::String(audience) if audience_shape(audience) => {
                audiences.insert(audience.clone());
            }
            _ => {
                return Err(invalid_input(
                    "audience entries must be URL-safe identifiers of at most 256 characters",
                ));
            }
        }
    }
    Ok(Some(audiences.into_iter().collect()))
}

/// `secondsOr(value, fallback)`: a stored or configured duration limit in seconds, or `fallback` when it is not a
/// positive safe integer. Limits read from storage may be malformed (a string, NaN, a negative number); this fails
/// closed to the default instead, which the other levels then clamp.
fn seconds_or(value: Option<f64>, fallback: f64) -> f64 {
    match value {
        Some(seconds) if core_js::is_safe_integer(seconds) && seconds > 0.0 => seconds,
        _ => fallback,
    }
}

/// `Math.min` of JavaScript numbers (NaN wins).
fn js_min(values: &[f64]) -> f64 {
    let mut result = f64::INFINITY;
    for value in values {
        if value.is_nan() {
            return f64::NAN;
        }
        if *value < result {
            result = *value;
        }
    }
    result
}

/// The JWT lifetime cap, or no cap for opaque tokens (and deployments without `sts.jwt`, which refuse JWTs anyway).
fn format_cap(ctx: &ServerContext, format: &CredentialFormat) -> f64 {
    match ctx.session_tokens() {
        Some(signer) if is_jwt(format) => seconds_or(
            Some(signer.max_lifetime_seconds()),
            DEFAULT_TRUST_MAX_SESSION_SECONDS,
        ),
        _ => f64::INFINITY,
    }
}

fn bounds_value(min: f64, max: f64, fallback: f64) -> Value {
    json!({ "min": number(min), "max": number(max), "fallback": number(fallback) })
}

/// Role session durations: the least of the deployment ceiling (`sts.maxRoleSessionSeconds`), the trust's
/// `maxSessionSeconds` (3600 when absent or not a positive integer) and, for JWTs, `sts.jwt.maxLifetimeSeconds`;
/// 900 by default or the maximum when that is lower. A lower level can only reduce the level above it. The bounds are
/// `{ min, max, fallback }` (`DurationBounds`).
pub fn role_duration_bounds(
    ctx: &Arc<ServerContext>,
    trust: &Value,
    format: &CredentialFormat,
) -> IamResult<Value> {
    let max = js_min(&[
        seconds_or(
            Some(ctx.config.sts.max_role_session_seconds),
            DEFAULT_TRUST_MAX_SESSION_SECONDS,
        ),
        seconds_or(
            trust.get("maxSessionSeconds").and_then(core_js::as_number),
            DEFAULT_TRUST_MAX_SESSION_SECONDS,
        ),
        format_cap(ctx, format),
    ]);
    Ok(bounds_value(60.0, max, js_min(&[900.0, max])))
}

/// Session token durations: the least of `sts.maxSessionTokenSeconds` and, for JWTs, `sts.jwt.maxLifetimeSeconds`;
/// 3600 by default or the maximum when that is lower. A limit that is not a positive integer counts as 3600.
pub fn session_token_duration_bounds(
    ctx: &Arc<ServerContext>,
    format: &CredentialFormat,
) -> IamResult<Value> {
    let max = js_min(&[
        seconds_or(
            Some(ctx.config.sts.max_session_token_seconds),
            DEFAULT_TRUST_MAX_SESSION_SECONDS,
        ),
        format_cap(ctx, format),
    ]);
    Ok(bounds_value(60.0, max, js_min(&[3600.0, max])))
}

/// A bound of a `DurationBounds` value (`bounds.min`, `bounds.max`, `bounds.fallback`): `undefined` reads as NaN in
/// every comparison and as "undefined" in messages.
fn bound<'a>(bounds: &'a Value, key: &str) -> Option<&'a Value> {
    crate::js::member(Some(bounds), key)
}

/// A requested duration within the bounds (the fallback when absent); anything outside is INVALID_INPUT, never
/// clamped.
pub fn duration_within(value: Option<&Value>, bounds: &Value) -> IamResult<f64> {
    let seconds = defined(value).or_else(|| bound(bounds, "fallback"));
    let min = bound(bounds, "min")
        .and_then(core_js::as_number)
        .unwrap_or(f64::NAN);
    let max = bound(bounds, "max")
        .and_then(core_js::as_number)
        .unwrap_or(f64::NAN);
    match seconds.and_then(core_js::as_number) {
        Some(seconds) if core_js::is_safe_integer(seconds) && seconds >= min && seconds <= max => {
            Ok(seconds)
        }
        _ => Err(invalid_input(format!(
            "durationSeconds must be an integer from {} to {}",
            bound_text(bound(bounds, "min")),
            bound_text(bound(bounds, "max"))
        ))),
    }
}

/// `${bounds.max}`: a JSON `null` stands for a non-finite number (`Infinity` has no JSON form).
fn bound_text(value: Option<&Value>) -> String {
    match value {
        Some(Value::Null) => "Infinity".to_owned(),
        other => js_string(other),
    }
}

/// A member of a draft session read as a string (`typeof draft.x === 'string'`).
fn string_of<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// Issues a temporary credential for a draft session row and stores the row. The draft carries every field except
/// the token material (`tokenHash` and `uniqueKey` are replaced; `format` and `audience` are set here).
///
/// `input` is `{ identity, draft, format, audience? }` (an absent or `null` audience is `undefined`); the result is
/// `{ token, session }` with the stored row. Opaque tokens are typed and checksummed (`biam_rol_…` for role sessions,
/// `biam_sts_…` for session tokens). Session JWTs need `sts.jwt` (FEATURE_DISABLED otherwise): every audience must be
/// on the deployment's allowlist (INVALID_INPUT), and each one other than the IAM issuer must be allowed as
/// `iam:assertions:create` on `iam/{aud}` for the drafted session (ACCESS_DENIED). The token is signed, bounded to
/// 4096 characters, and its SHA-256 stored like an opaque token's, so IAM re-validates the row on every use.
pub async fn mint_credential(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    input: &Value,
) -> IamResult<Value> {
    let draft: &Map<String, Value> = match input.get("draft") {
        Some(Value::Object(draft)) => draft,
        _ => return Err(ThrownError::type_error("draft is not an object").into()),
    };
    let format = input.get("format").cloned().unwrap_or(Value::Null);
    let audience_input = defined(input.get("audience"));
    let kind = string_of(draft, "kind");
    if kind != Some("role") && kind != Some("session-token") {
        return Err(ThrownError::error(
            "mintCredential issues role sessions and session tokens only",
        )
        .into());
    }
    let mut row: Record = draft.clone();
    row.shift_remove("format");
    row.shift_remove("audience");
    if format.as_str() == Some("opaque") {
        if audience_input.is_some() {
            return Err(invalid_input("audience requires format 'jwt'"));
        }
        let token = new_credential_token(if kind == Some("role") {
            CredentialTokenType::Rol
        } else {
            CredentialTokenType::Sts
        });
        let token_hash = hash(&token);
        row.insert("tokenHash".into(), Value::String(token_hash.clone()));
        row.insert("uniqueKey".into(), Value::String(token_hash));
        let session = tx.insert("sessions", &row).await?;
        return Ok(json!({ "token": token, "session": Value::Object(session) }));
    }
    if !is_jwt(&format) {
        return Err(invalid_input("format must be 'opaque' or 'jwt'"));
    }
    let Some(signer) = ctx.session_tokens() else {
        return Err(IamError::with_status(
            "FEATURE_DISABLED",
            "Session JWTs are not enabled on this deployment (sts.jwt)",
            403,
        ));
    };
    let audience: Vec<String> = match audience_input {
        None => vec![signer.issuer().to_owned()],
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| {
                item.as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| js_string(Some(item)))
            })
            .collect(),
        Some(_) => return Err(ThrownError::type_error("audience is not iterable").into()),
    };
    if audience.is_empty() || audience.len() > MAX_AUDIENCES {
        return Err(invalid_input(format!(
            "audience must list 1 to {MAX_AUDIENCES} audiences"
        )));
    }
    for entry in &audience {
        if !signer.audiences().iter().any(|allowed| allowed == entry) {
            return Err(invalid_input(format!(
                "audience {entry} is not an allowed session token audience"
            )));
        }
    }
    let identity: Identity = crate::port::decode(match input.get("identity") {
        Some(Value::Object(identity)) => identity.clone(),
        _ => Record::new(),
    })?;
    let session: Session = crate::port::decode(draft.clone())?;
    let principal = AuthenticatedPrincipal {
        identity,
        session: session.clone(),
        device_proof: None,
    };
    for entry in &audience {
        if entry == signer.issuer() {
            continue;
        }
        let decision = ctx
            .decisions()?
            .decide(
                tx,
                &principal,
                &AuthorizationRequest {
                    credential: better_iam_core::CredentialInput::default(),
                    tenant_id: session.tenant_id.clone(),
                    action: "iam:assertions:create".into(),
                    resource: ResourceTarget {
                        kind: "iam".into(),
                        id: entry.clone(),
                    },
                },
                true,
            )
            .await?;
        if !decision.allowed {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                format!("This credential may not obtain tokens for audience {entry}"),
                403,
            ));
        }
    }
    let issued_at = (session.created_at / 1000.0).floor();
    let expires_at = (session.expires_at / 1000.0).floor();
    if expires_at - issued_at > signer.max_lifetime_seconds() {
        return Err(invalid_input(format!(
            "durationSeconds exceeds the session JWT lifetime of {}",
            number_to_string(signer.max_lifetime_seconds())
        )));
    }
    let mut claims = SessionTokenClaims {
        iss: signer.issuer().to_owned(),
        aud: if audience.len() == 1 {
            Value::String(audience[0].clone())
        } else {
            Value::Array(audience.iter().cloned().map(Value::String).collect())
        },
        sub: session.identity_id.clone(),
        tid: session.tenant_id.clone(),
        sid: session.id.clone(),
        jti: session.id.clone(),
        iat: issued_at,
        nbf: issued_at,
        exp: expires_at,
        auth_time: (session.authenticated_at / 1000.0).floor(),
        kind: session.kind.as_str().to_owned(),
        mfa: session.mfa,
        role: None,
        trust: None,
        src_tid: None,
        session_name: None,
        source_identity: None,
        idp: None,
        idp_sub: None,
        extra: Map::new(),
    };
    claims.role = string_of(draft, "roleId").map(str::to_owned);
    claims.trust = string_of(draft, "trustId").map(str::to_owned);
    claims.src_tid = string_of(draft, "sourceTenantId").map(str::to_owned);
    claims.session_name = string_of(draft, "sessionName").map(str::to_owned);
    claims.source_identity = string_of(draft, "sourceIdentity").map(str::to_owned);
    if let Some(web) = &session.web_identity {
        claims.idp = Some(web.provider_id.clone());
        claims.idp_sub = Some(web.subject.clone());
    }
    let token = signer.sign(&claims).await?;
    if crate::js::utf16_len(&token) as f64 > MAX_SESSION_TOKEN_LENGTH {
        return Err(invalid_input(format!(
            "The session token would exceed {} characters",
            number_to_string(MAX_SESSION_TOKEN_LENGTH)
        )));
    }
    let token_hash = hash(&token);
    row.insert("tokenHash".into(), Value::String(token_hash.clone()));
    row.insert("uniqueKey".into(), Value::String(token_hash));
    row.insert("format".into(), Value::String("jwt".into()));
    row.insert(
        "audience".into(),
        Value::Array(audience.into_iter().map(Value::String).collect()),
    );
    let session = tx.insert("sessions", &row).await?;
    Ok(json!({ "token": token, "session": Value::Object(session) }))
}

fn credential_format_of(session: &Session) -> CredentialFormat {
    Value::String(
        if session.format.as_deref() == Some("jwt") {
            "jwt"
        } else {
            "opaque"
        }
        .into(),
    )
}

/// The issuer response for a stored temporary session (an allowlist projection; the token is the only secret).
pub fn temporary_credential(
    token: &str,
    session: &Session,
    now: f64,
) -> IamResult<TemporaryCredential> {
    let mut summary = Map::new();
    summary.insert("id".into(), Value::String(session.id.clone()));
    summary.insert("tenantId".into(), Value::String(session.tenant_id.clone()));
    summary.insert("kind".into(), Value::String(session.kind.as_str().into()));
    summary.insert(
        "identityId".into(),
        Value::String(session.identity_id.clone()),
    );
    summary.insert("expiresAt".into(), number(session.expires_at));
    summary.insert("mfa".into(), Value::Bool(session.mfa));
    if let Some(role_id) = &session.role_id {
        summary.insert("roleId".into(), Value::String(role_id.clone()));
    }
    if let Some(trust_id) = &session.trust_id {
        summary.insert("trustId".into(), Value::String(trust_id.clone()));
    }
    if let Some(session_name) = &session.session_name {
        summary.insert("sessionName".into(), Value::String(session_name.clone()));
    }
    if let Some(source_identity) = &session.source_identity {
        summary.insert(
            "sourceIdentity".into(),
            Value::String(source_identity.clone()),
        );
    }
    Ok(TemporaryCredential {
        token: token.to_owned(),
        token_type: "Bearer".into(),
        format: credential_format_of(session),
        expires_at: session.expires_at,
        expires_in: js_max0(((session.expires_at - now) / 1000.0).floor()),
        session: Value::Object(summary),
        audience: session.audience.clone(),
        extra: Map::new(),
    })
}

/// `Math.max(0, value)` (NaN wins).
fn js_max0(value: f64) -> f64 {
    if value.is_nan() {
        f64::NAN
    } else {
        value.max(0.0)
    }
}

/// `sts.getCallerIdentity`: an allowlist projection of a verified principal.
pub fn caller_identity(principal: &AuthenticatedPrincipal) -> IamResult<CallerIdentity> {
    let AuthenticatedPrincipal {
        identity, session, ..
    } = principal;
    let identity_kind = match serde_json::to_value(identity.kind) {
        Ok(Value::String(kind)) => kind,
        _ => String::new(),
    };
    let method = session
        .method
        .as_ref()
        .and_then(|method| match serde_json::to_value(method) {
            Ok(Value::String(method)) => Some(method),
            _ => None,
        });
    let session_tags = session
        .session_tags
        .as_ref()
        .filter(|tags| !tags.is_empty())
        .map(|tags| {
            tags.iter()
                .map(|(key, value)| {
                    (
                        key.clone(),
                        value
                            .as_str()
                            .map(str::to_owned)
                            .unwrap_or_else(|| js_string(Some(value))),
                    )
                })
                .collect()
        });
    Ok(CallerIdentity {
        identity_id: identity.id.clone(),
        identity_tenant_id: identity.tenant_id.clone(),
        identity_kind,
        tenant_id: session.tenant_id.clone(),
        session_id: session.id.clone(),
        session_kind: session.kind.as_str().to_owned(),
        format: credential_format_of(session),
        mfa: session.mfa,
        authenticated_at: session.authenticated_at,
        issued_at: session.created_at,
        expires_at: session.expires_at,
        method,
        role_id: session.role_id.clone(),
        trust_id: session.trust_id.clone(),
        source_tenant_id: session.source_tenant_id.clone(),
        session_name: session.session_name.clone(),
        source_identity: session.source_identity.clone(),
        session_tags,
        audience: session.audience.clone(),
        web_identity: session.web_identity.as_ref().map(|web| {
            json!({ "providerId": web.provider_id, "issuer": web.issuer, "subject": web.subject })
        }),
        impersonator_id: session.impersonator_id.clone(),
        agent_id: session.agent_id.clone(),
        delegation_id: session.delegation_id.clone(),
        extra: Map::new(),
    })
}

/// `roles.listSessions`: an allowlist projection of a role session row.
pub fn role_session_summary(session: &Session) -> IamResult<RoleSessionSummary> {
    // A cross-tenant role session was issued to a person of another tenant: their address is not the target tenant's
    // to see (its readers hold iam:trust:read, not access to the source tenant's sign-in records).
    let cross_tenant = session
        .source_tenant_id
        .as_ref()
        .is_some_and(|source| *source != session.tenant_id);
    Ok(RoleSessionSummary {
        id: session.id.clone(),
        role_id: session.role_id.clone().unwrap_or_default(),
        trust_id: session.trust_id.clone().unwrap_or_default(),
        identity_id: session.identity_id.clone(),
        mfa: session.mfa,
        format: credential_format_of(session),
        created_at: session.created_at,
        expires_at: session.expires_at,
        source_tenant_id: session.source_tenant_id.clone(),
        session_name: session.session_name.clone(),
        source_identity: session.source_identity.clone(),
        web_identity: session
            .web_identity
            .as_ref()
            .map(|web| json!({ "providerId": web.provider_id, "subject": web.subject })),
        client_ip: if cross_tenant {
            None
        } else {
            session.client.as_ref().and_then(|client| client.ip.clone())
        },
        extra: Map::new(),
    })
}

/// `auditSessionContext(session)`: the session an audited action ran under (an allowlist projection), None for
/// events recorded without a principal and for simulated principals (session id `simulation`). Session ids are
/// identifiers, not credentials; hashes, policies, tag values and authority ids are never included.
pub fn audit_session_context(session: Option<&Session>) -> Option<AuditSessionContext> {
    let session = session?;
    if session.id == "simulation" {
        return None;
    }
    let mut context = AuditSessionContext {
        session_id: session.id.clone(),
        kind: session.kind,
        role_id: session.role_id.clone(),
        trust_id: session.trust_id.clone(),
        source_tenant_id: session.source_tenant_id.clone(),
        session_name: session.session_name.clone(),
        source_identity: session.source_identity.clone(),
        web_identity_provider_id: None,
        web_identity_subject: None,
        format: None,
        agent_id: None,
        delegation_id: None,
    };
    if let Some(web) = &session.web_identity {
        context.web_identity_provider_id = Some(web.provider_id.clone());
        // `subject.slice(0, 256)`: the first 256 UTF-16 code units.
        let units: Vec<u16> = web.subject.encode_utf16().take(256).collect();
        context.web_identity_subject = Some(String::from_utf16_lossy(&units));
    }
    if session.format.as_deref() == Some("jwt") {
        context.format = Some("jwt".into());
    }
    // Delegated sessions: the agent that acted for the person, under which delegation.
    context.agent_id = session.agent_id.clone();
    context.delegation_id = session.delegation_id.clone();
    Some(context)
}

/// Deletes live role sessions of a role in a tenant created before `createdBefore` (eager revocation alongside a
/// watermark), optionally only those of one trust or one OIDC provider. `filter` is `{ tenantId, roleId, trustId?,
/// providerId?, createdBefore }`. Reads through the indexed roleId and returns the number of rows deleted.
pub async fn delete_temporary_sessions(tx: &Store, filter: &Value) -> IamResult<f64> {
    let role_id = filter.get("roleId").cloned().unwrap_or(Value::Null);
    let tenant_id = filter.get("tenantId");
    let trust_id = filter.get("trustId");
    let provider_id = filter.get("providerId");
    let created_before = filter
        .get("createdBefore")
        .map_or(f64::NAN, core_js::to_number);
    let sessions = tx
        .find(
            "sessions",
            &better_iam_core::Filter::new().eq("roleId", role_id),
            &better_iam_core::FindOptions::default(),
        )
        .await?;
    let mut deleted = 0.0;
    for session in sessions {
        let created_at = session
            .get("createdAt")
            .map_or(f64::NAN, core_js::to_number);
        let session_provider = session
            .get("webIdentity")
            .and_then(|web| web.get("providerId"));
        if session.get("kind").and_then(Value::as_str) != Some("role")
            || session.get("tenantId") != tenant_id
            || (trust_id.is_some() && session.get("trustId") != trust_id)
            || (provider_id.is_some() && session_provider != provider_id)
            || created_at.partial_cmp(&created_before) != Some(std::cmp::Ordering::Less)
        {
            continue;
        }
        tx.delete("sessions", better_iam_core::record_id(&session))
            .await?;
        deleted += 1.0;
    }
    Ok(deleted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message<T: std::fmt::Debug>(result: IamResult<T>) -> String {
        result.unwrap_err().message
    }

    #[test]
    fn session_names() {
        assert_eq!(session_name_value(None).unwrap(), None);
        assert_eq!(
            session_name_value(Some(&json!("ci-run_42@build.example"))).unwrap(),
            Some("ci-run_42@build.example".into())
        );
        for bad in [
            json!("x"),
            json!("has space"),
            json!(5),
            json!("é-accent"),
            json!("a".repeat(65)),
        ] {
            assert_eq!(
                message(session_name_value(Some(&bad))),
                "sessionName must be 2-64 letters, digits or +=,.@_- characters"
            );
        }
        assert_eq!(
            message(source_identity_value(Some(&json!("!")))),
            "sourceIdentity must be 2-64 letters, digits or +=,.@_- characters"
        );
        assert!(is_session_name(&"a".repeat(64)));
    }

    #[test]
    fn session_tags() {
        assert_eq!(session_tags_value(None).unwrap(), None);
        assert_eq!(session_tags_value(Some(&json!({}))).unwrap(), None);
        let tags = session_tags_value(Some(&json!({ "team": "Platform Ops", "cost": "ünï 42" })))
            .unwrap()
            .unwrap();
        assert_eq!(tags.get("cost").map(String::as_str), Some("ünï 42"));
        assert_eq!(
            message(session_tags_value(Some(&json!(["a"])))),
            "tags must be an object of tag keys to string values"
        );
        assert_eq!(
            message(session_tags_value(Some(&json!({ "1a": "x" })))),
            "Tag keys must start with a letter and use at most 64 letters, digits or underscores"
        );
        assert_eq!(
            message(session_tags_value(Some(
                &json!({ "Team": "a", "team": "b" })
            ))),
            "Tag key team is repeated (tag keys are case-insensitive)"
        );
        assert_eq!(
            message(session_tags_value(Some(&json!({ "team": "a;b" })))),
            "Tag team must be a string of at most 256 letters, digits, spaces or _.:/=+-@"
        );
        let many: Map<String, Value> = (0..51)
            .map(|index| (format!("k{index}"), json!("v")))
            .collect();
        assert_eq!(
            message(session_tags_value(Some(&Value::Object(many)))),
            "tags may contain at most 50 entries"
        );
        let large: Map<String, Value> = (0..10)
            .map(|index| (format!("k{index}"), json!("v".repeat(250))))
            .collect();
        assert_eq!(
            message(session_tags_value(Some(&Value::Object(large)))),
            "tags must pack into at most 2048 bytes"
        );
    }

    #[test]
    fn allowed_tag_keys() {
        assert_eq!(
            allowed_tag_keys_value(Some(&json!(["*"]))).unwrap(),
            vec!["*"]
        );
        assert_eq!(
            allowed_tag_keys_value(Some(&json!(["team", "cost"]))).unwrap(),
            vec!["team", "cost"]
        );
        let refused = "allowedTagKeys must be a list of at most 50 tag keys, or ['*']";
        assert_eq!(message(allowed_tag_keys_value(None)), refused);
        assert_eq!(
            message(allowed_tag_keys_value(Some(&json!(["*", "a"])))),
            refused
        );
        assert_eq!(
            message(allowed_tag_keys_value(Some(&json!(["Team", "TEAM"])))),
            "Tag key TEAM is repeated (tag keys are case-insensitive)"
        );
    }

    #[test]
    fn formats_and_audiences() {
        assert_eq!(credential_format(None).unwrap(), json!("opaque"));
        assert_eq!(
            credential_format(Some(&json!("jwt"))).unwrap(),
            json!("jwt")
        );
        assert_eq!(
            message(credential_format(Some(&json!("JWT")))),
            "format must be 'opaque' or 'jwt'"
        );
        let jwt = json!("jwt");
        assert_eq!(audience_value(None, &jwt).unwrap(), None);
        assert_eq!(
            audience_value(Some(&json!(["a", "b", "a"])), &jwt).unwrap(),
            Some(vec!["a".into(), "b".into()])
        );
        assert_eq!(
            message(audience_value(Some(&json!(["a"])), &json!("opaque"))),
            "audience requires format 'jwt'"
        );
        assert_eq!(
            message(audience_value(Some(&json!([])), &jwt)),
            "audience must list 1 to 5 audiences"
        );
        assert_eq!(
            message(audience_value(Some(&json!(["-x"])), &jwt)),
            "audience entries must be URL-safe identifiers of at most 256 characters"
        );
    }

    #[test]
    fn durations() {
        let bounds = json!({ "min": 60, "max": 900, "fallback": 900 });
        assert_eq!(duration_within(None, &bounds).unwrap(), 900.0);
        assert_eq!(duration_within(Some(&json!(120)), &bounds).unwrap(), 120.0);
        for bad in [json!(59), json!(901), json!(60.5), json!("120")] {
            assert_eq!(
                message(duration_within(Some(&bad), &bounds)),
                "durationSeconds must be an integer from 60 to 900"
            );
        }
        assert_eq!(seconds_or(Some(-1.0), 3600.0), 3600.0);
        assert_eq!(seconds_or(Some(f64::NAN), 3600.0), 3600.0);
        assert_eq!(seconds_or(Some(120.0), 3600.0), 120.0);
    }

    #[test]
    fn credentials_serialize_times_as_javascript_numbers() {
        let credential = TemporaryCredential {
            token: "t".into(),
            token_type: "Bearer".into(),
            format: json!("opaque"),
            expires_at: 1_794_113_725_504.0,
            expires_in: 600.0,
            session: json!({}),
            audience: None,
            extra: Map::new(),
        };
        let value = serde_json::to_value(&credential).unwrap();
        // Integral doubles are JSON integers, as `JSON.stringify` writes them.
        assert_eq!(value["expiresIn"], json!(600));
        assert_eq!(value["expiresAt"], json!(1_794_113_725_504_i64));
        let role = serde_json::to_value(RoleCredential::from(TemporaryCredential {
            expires_in: 1.5,
            ..credential
        }))
        .unwrap();
        assert_eq!(role["expiresIn"], json!(1.5));
        assert_eq!(role["expiresAt"], json!(1_794_113_725_504_i64));
    }
}
