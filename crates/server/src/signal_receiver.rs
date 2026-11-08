//! Port of `packages/server/src/signal-receiver.ts`.
//!
//! The Shared Signals receiver (OpenID SSF 1.0 with CAEP and RISC): security events an upstream identity provider sends
//! about the tenant's people. Each tenant registers its transmitters as signal sources (`signals` API group); events
//! arrive by push (RFC 8935, the `{signals.pushPath}/{sourceId}` protocol mount) or by poll (RFC 8936,
//! `iam.signals.poll()`), are verified against the source's keys, deduplicated on issuer and `jti`, mapped to an
//! identity of the source's tenant, recorded (`signalEvents`), and audited as `signal:received`, which threat detection
//! reads. The only action taken directly is ending sessions, and only for event types a source configures that way;
//! containment is left to threat-detection playbooks.

use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::Duration;

use better_iam_auth::service::base::LimitAttemptOptions;
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStoreExt, Record, SecurityEventClaims,
    SignalFormatError, SubjectIdentifier, js as core_js, read_security_event, record_id,
    user_subjects,
};
use bytes::Bytes;
use futures::FutureExt;
use futures::future::{BoxFuture, Shared};
use indexmap::IndexMap;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use url::Url;

use crate::context::{ServerContext, Store};
use crate::js::number;
use crate::options::{HttpRequest, HttpResponse};
use crate::safe_fetch::{
    FetchBody, FetchRequest, GuardedFetch, GuardedFetchOptions, RedirectMode,
    SafeFetchAddressOptions, check_fetch_url, create_guarded_fetch,
};
use crate::session_tokens::jose::{self, JoseError, JwkSet, VerifyKey};
use crate::utils::{by_id, date_now, hash, id, same_hash};

/// Used when a source does not name its algorithms.
pub const DEFAULT_SIGNAL_ALGORITHMS: &[&str] = &["RS256", "ES256", "PS256", "EdDSA"];

/// A received security event (`signalEvents`, natural key `jti:{sha256(issuer|jti)}`), kept for 90 days.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReceivedSignal {
    #[serde(rename = "sourceId")]
    pub source_id: String,
    /// The source id again, under the indexed lookup field `streamId`.
    #[serde(rename = "streamId")]
    pub stream_id: String,
    #[serde(rename = "jti")]
    pub jti: String,
    #[serde(rename = "eventType")]
    pub event_type: String,
    #[serde(rename = "eventUri")]
    pub event_uri: String,
    /// The SET's `iat`, in epoch milliseconds.
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    /// When the event happened, per the transmitter (epoch milliseconds).
    #[serde(
        rename = "eventTimestamp",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub event_timestamp: Option<f64>,
    #[serde(rename = "txn", default, skip_serializing_if = "Option::is_none")]
    pub txn: Option<String>,
    /// The subject as parsed (RFC 9493 form), when the SET named one.
    #[serde(rename = "subject", default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<IndexMap<String, better_iam_core::Json>>,
    /// The identity of the source's tenant the subject matched.
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "status")]
    pub status: crate::signal_receiver::SignalStatus,
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The event's own claims (at most 4 KiB; larger ones keep their shorter members and `_truncated`).
    #[serde(rename = "claims")]
    pub claims: IndexMap<String, better_iam_core::Json>,
    #[serde(rename = "receivedAt")]
    pub received_at: f64,
    /// `receivedAt` again: the ordered field the event list pages by.
    #[serde(rename = "timestamp")]
    pub timestamp: f64,
    /// When the retention sweep deletes the record.
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(
        rename = "reprocessedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reprocessed_at: Option<f64>,
    #[serde(
        rename = "reprocessedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub reprocessed_by: Option<String>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What the receiver does with a matched event: `record` (the default), or also end the person's sessions
/// (`revoke-sessions`).
pub type SignalAction = String;

/// Event types a source may configure an action for: every known type except the SSF control events.
pub type SignalActionableEvent = String;

/// Signature algorithms a source may allow. Symmetric algorithms and `none` are never accepted.
pub type SignalAlgorithm = String;

/// How a source's events arrive: pushed to the receiver (`push`, RFC 8935) or polled from the transmitter (`poll`,
/// RFC 8936).
pub type SignalDelivery = String;

/// What one poll run did.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalPollResult {
    /// Poll sources polled.
    #[serde(rename = "sources")]
    pub sources: f64,
    /// New events recorded (duplicates excluded).
    #[serde(rename = "received")]
    pub received: f64,
    /// Events acknowledged to transmitters.
    #[serde(rename = "acknowledged")]
    pub acknowledged: f64,
    /// Failed poll requests and events left unacknowledged for redelivery.
    #[serde(rename = "errors")]
    pub errors: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl SignalPollResult {
    /// The result as the TypeScript object (`{ sources, received, acknowledged, errors }`).
    pub fn to_value(&self) -> Value {
        json!({
            "sources": number(self.sources),
            "received": number(self.received),
            "acknowledged": number(self.acknowledged),
            "errors": number(self.errors),
        })
    }
}

/// A poll source's transmitter endpoint and the receiver's place in its queue.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalPollState {
    /// The transmitter's RFC 8936 poll endpoint.
    #[serde(rename = "endpoint")]
    pub endpoint: String,
    /// The bearer token for the endpoint, sealed with the deployment secret (`rotateSecrets` re-seals it).
    #[serde(rename = "tokenSealed")]
    pub token_sealed: String,
    /// Events asked for per request.
    #[serde(rename = "maxEvents")]
    pub max_events: f64,
    /// `jti`s committed since the last successful request, acknowledged with the next one.
    #[serde(rename = "pendingAcks")]
    pub pending_acks: Vec<String>,
    /// Events refused since the last successful request (`setErrs` of the next one), by `jti`.
    #[serde(
        rename = "pendingErrors",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub pending_errors: Option<Map<String, Value>>,
    #[serde(
        rename = "lastPolledAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_polled_at: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A registered transmitter (`signalSources`, natural key `issuer:{issuer}` per tenant). `updatedAt` versions the
/// settings verification depends on and moves only when an administrator changes the source; the receiver's own
/// bookkeeping (`lastEventAt`, `lastError`, poll state) leaves it alone.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalSource {
    #[serde(rename = "name")]
    pub name: String,
    /// The transmitter's `iss`, without a trailing slash (both spellings are accepted on SETs).
    #[serde(rename = "issuer")]
    pub issuer: String,
    /// Other spellings of the issuer its SETs or federation links use (at most 5, without trailing slashes).
    #[serde(rename = "issuerAliases")]
    pub issuer_aliases: Vec<String>,
    /// Accepted `aud` values (1 to 10); a SET must name one of them.
    #[serde(rename = "audiences")]
    pub audiences: Vec<String>,
    /// Where the transmitter's keys live; without it and without `jwks`, SSF discovery on the issuer.
    #[serde(rename = "jwksUri", default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
    /// Static public keys, used instead of fetching.
    #[serde(rename = "jwks", default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<Value>,
    #[serde(rename = "algorithms")]
    pub algorithms: Vec<String>,
    #[serde(rename = "delivery")]
    pub delivery: crate::signal_receiver::SignalDelivery,
    /// SHA-256 of the bearer token the transmitter presents on pushes, when the source has one.
    #[serde(
        rename = "pushTokenHash",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub push_token_hash: Option<String>,
    #[serde(rename = "poll", default, skip_serializing_if = "Option::is_none")]
    pub poll: Option<crate::signal_receiver::SignalPollState>,
    #[serde(rename = "subjects")]
    pub subjects: crate::signal_receiver::SignalSubjectMapping,
    /// The action per event type; unlisted types are recorded only.
    #[serde(rename = "actions")]
    pub actions: Value,
    /// Require the `secevent+jwt` token type (default); false tolerates legacy RISC transmitters.
    #[serde(rename = "requireTyp")]
    pub require_typ: bool,
    /// When set, a SET must carry a `tenant_id` claim equal to it. A Better IAM transmitter signs every organization's
    /// events with one issuer and key, so without this another organization of that deployment could point its own
    /// stream at this source (with this source's audience) and have its events accepted here.
    #[serde(
        rename = "tenantClaim",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tenant_claim: Option<String>,
    #[serde(rename = "status")]
    pub status: crate::signal_receiver::SignalSourceStatus,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    #[serde(
        rename = "lastEventAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_event_at: Option<f64>,
    /// The last refusal or transport failure, or a transmitter that paused or disabled the stream.
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<Value>,
    /// When the transmitter last sent a verification event.
    #[serde(
        rename = "lastVerifiedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_verified_at: Option<f64>,
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `active` or `disabled`.
pub type SignalSourceStatus = String;

/// A received event's outcome: `applied` (its configured action ran), `recorded` (kept, nothing to do or only
/// record), `unmatched` (no identity of the tenant matched its subject), `ignored` (an unsupported event type, or
/// an action refused for a protected identity) or `failed` (processing failed; an administrator may reprocess it).
pub type SignalStatus = String;

/// How a source's subjects are matched to the tenant's identities.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignalSubjectMapping {
    /// Sign-in connections (OAuth/OIDC login connection or SAML connection ids) whose federation links map `iss_sub`
    /// subjects: a subject of the source's issuer (or an alias) matches the identity linked to that subject.
    #[serde(rename = "connectionIds")]
    pub connection_ids: Vec<String>,
    /// Match `email` and `acct:` subjects to identities by email, only for domains the tenant verified.
    #[serde(rename = "matchEmail")]
    pub match_email: bool,
    /// SCIM connections whose provisioned users' `externalId` maps `iss_sub` and `opaque` subjects.
    #[serde(rename = "scimConnectionIds")]
    pub scim_connection_ids: Vec<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Signal sources one tenant may register.
pub const MAX_SIGNAL_SOURCES_PER_TENANT: f64 = 20.0;

/// Where the receiver keeps its records; both are tenant-scoped and purged with the tenant (lifecycle.ts).
pub static SIGNAL_COLLECTIONS: LazyLock<Value> =
    LazyLock::new(|| json!({"sources":"signalSources","events":"signalEvents"}));

/// `signalCollections.sources`.
pub const SOURCES_COLLECTION: &str = "signalSources";
/// `signalCollections.events`.
pub const EVENTS_COLLECTION: &str = "signalEvents";

/// RFC 8935 / RFC 8936 error codes the receiver answers a refused SET with: `invalid_request`, `invalid_key`,
/// `invalid_issuer` or `invalid_audience`.
pub type SignalErrorCode = &'static str;

/// A refused security event token. `err` is the RFC 8935 error code, `description` its description (the error
/// message). `temporary` marks a refusal that may pass later (the source's keys could not be fetched): pushes answer
/// 503 and polls leave the event unacknowledged, so the transmitter delivers it again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignalRejectedError {
    pub err: SignalErrorCode,
    pub description: String,
    pub temporary: bool,
}

impl SignalRejectedError {
    pub fn new(err: SignalErrorCode, description: impl Into<String>) -> Self {
        Self {
            err,
            description: description.into(),
            temporary: false,
        }
    }

    fn temporary(err: SignalErrorCode, description: impl Into<String>, temporary: bool) -> Self {
        Self {
            err,
            description: description.into(),
            temporary,
        }
    }
}

impl From<SignalRejectedError> for IamError {
    fn from(error: SignalRejectedError) -> Self {
        IamError::with_status("SIGNAL_REJECTED", error.description, 400)
    }
}

/// The outcome of accepting one security event.
#[derive(Debug, Clone, PartialEq)]
pub struct SignalReceipt {
    /// The received event's id (`signals.getEvent`).
    pub event_id: String,
    pub status: String,
    /// The event had been received before (same issuer and `jti`); nothing was done again.
    pub duplicate: bool,
    pub identity_id: Option<String>,
}

impl SignalReceipt {
    /// The receipt as the TypeScript object.
    pub fn to_value(&self) -> Value {
        let mut out = Map::new();
        out.insert("eventId".into(), Value::String(self.event_id.clone()));
        out.insert("status".into(), Value::String(self.status.clone()));
        out.insert("duplicate".into(), Value::Bool(self.duplicate));
        if let Some(identity_id) = &self.identity_id {
            out.insert("identityId".into(), Value::String(identity_id.clone()));
        }
        Value::Object(out)
    }
}

const DAY: f64 = 86_400_000.0;
const SIGNAL_RETENTION_MS: f64 = 90.0 * DAY;
const MAX_SET_BYTES: usize = 16_384;
const MAX_PUSH_BYTES: usize = 65_536;
const MAX_CLAIMS_CHARS: usize = 4096;
const MAX_SUBJECT_CHARS: usize = 8192;
const CLOCK_TOLERANCE_SECONDS: f64 = 300.0;
const MAX_SET_AGE_SECONDS: f64 = 7.0 * 86_400.0;
/// Pushes per source per rate-limit window.
const PUSHES_PER_WINDOW: f64 = 3000.0;
const POLL_REQUESTS_PER_RUN: usize = 5;
const POLL_TIMEOUT_MS: u64 = 10_000;
const POLL_MAX_BYTES: u64 = 1_048_576;
const JWKS_MAX_BYTES: u64 = 262_144;
const DISCOVERY_MAX_BYTES: u64 = 65_536;
const FETCH_TIMEOUT_MS: u64 = 5000;
const NEGATIVE_CACHE_MS: f64 = 30_000.0;
const REDISCOVER_MS: f64 = DAY;
const MAX_CACHED_SOURCES: usize = 1000;
/// Keys tried when several of a source's keys match a token.
const MAX_CANDIDATE_KEYS: usize = 20;
/// `createRemoteJWKSet` settings of the receiver.
const JWKS_COOLDOWN_MS: f64 = 30_000.0;
const JWKS_CACHE_MAX_AGE_MS: f64 = 600_000.0;
static COMPACT_JWS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$").expect("valid regex")
});
static SOURCE_ID_SHAPE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
        .expect("valid regex")
});
static BEARER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)^Bearer[ ]+([^\s]+)$").expect("valid regex"));
const FORBIDDEN_HEADERS: [&str; 4] = ["jwk", "jku", "x5u", "x5c"];
/// Token types a source that does not require `secevent+jwt` still accepts (as well as none at all).
const LENIENT_TYPES: [&str; 2] = ["secevent+jwt", "jwt"];
const UNSAFE_KEYS: [&str; 3] = ["__proto__", "constructor", "prototype"];

/// `/^[0-9a-f]{8}-...$/.test(value)`.
pub fn source_id_shaped(value: &str) -> bool {
    SOURCE_ID_SHAPE.is_match(value)
}

fn trim_slashes(value: &str) -> &str {
    value.trim_end_matches('/')
}

/// `value.slice(0, max)` (UTF-16 code units; half of a split surrogate pair reads back as U+FFFD, as a lone surrogate
/// does through JSON).
fn clip(value: &str, max: usize) -> String {
    if core_js::utf16_len(value) <= max {
        return value.to_owned();
    }
    let mut units = 0;
    let mut out = String::new();
    for c in value.chars() {
        let width = c.len_utf16();
        if units + width > max {
            if units < max {
                out.push('\u{FFFD}');
            }
            break;
        }
        units += width;
        out.push(c);
    }
    out
}

/// `plain(value)`: a non-array object.
fn plain(value: Option<&Value>) -> Option<&Map<String, Value>> {
    match value {
        Some(Value::Object(map)) => Some(map),
        _ => None,
    }
}

fn normalized_typ(value: &str) -> String {
    let lower = value.to_lowercase();
    match lower.strip_prefix("application/") {
        Some(rest) => rest.to_owned(),
        None => lower,
    }
}

fn str_member<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn strings_of(value: Option<&Value>) -> Vec<String> {
    match value {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
        _ => Vec::new(),
    }
}

/// The system actor of the receiver's own audit events: `signal:{sourceId}`.
pub fn signal_actor(source_id: &str) -> String {
    format!("signal:{source_id}")
}

/// The encryption context of a poll source's bearer token: binds the ciphertext to its source.
pub fn poll_token_context(source_id: &str) -> String {
    format!("signal-poll:{source_id}")
}

/// Seals a poll source's bearer token with the current deployment secret.
pub fn seal_poll_token(
    ctx: &Arc<ServerContext>,
    source_id: &str,
    token: &str,
) -> IamResult<String> {
    Ok(better_iam_auth::crypto::encrypt_secret(
        token,
        &ctx.options.secret,
        &poll_token_context(source_id),
    ))
}

/// Opens a poll source's bearer token with the current secret or a previous one.
fn open_poll_token(ctx: &ServerContext, source: &Record) -> IamResult<String> {
    let sealed = source
        .get("poll")
        .and_then(|poll| poll.get("tokenSealed"))
        .and_then(Value::as_str)
        .ok_or_else(crate::js::internal_error)?;
    let mut secrets = vec![ctx.options.secret.clone()];
    secrets.extend(ctx.options.previous_secrets.clone().unwrap_or_default());
    better_iam_auth::crypto::decrypt_secret(
        sealed,
        &secrets,
        &poll_token_context(record_id(source)),
    )
}

/// The issuer and its aliases, without trailing slashes.
fn issuer_forms(source: &Record) -> Vec<String> {
    let mut forms: Vec<String> = Vec::new();
    let issuer = str_member(source, "issuer").unwrap_or_default().to_owned();
    for form in std::iter::once(issuer).chain(strings_of(source.get("issuerAliases"))) {
        let trimmed = trim_slashes(&form).to_owned();
        if !forms.contains(&trimmed) {
            forms.push(trimmed);
        }
    }
    forms
}

/// Whether an issuer names the source (its issuer or an alias, with or without a trailing slash).
pub fn names_signal_source(source: &Record, issuer: &str) -> bool {
    issuer_forms(source)
        .iter()
        .any(|form| form == trim_slashes(issuer))
}

/// The received event's natural key: the SHA-256 of the source's issuer and the `jti`.
pub fn signal_event_key(issuer: &str, jti: &str) -> String {
    format!("jti:{}", hash(&format!("{}|{jti}", trim_slashes(issuer))))
}

/// A plain JSON copy without prototype-polluting keys (storage refuses them), non-finite numbers or deep nesting.
fn json_copy(value: &Value, depth: usize) -> Option<Value> {
    match value {
        Value::Null | Value::String(_) | Value::Bool(_) | Value::Number(_) => Some(value.clone()),
        _ if depth >= 16 => None,
        Value::Array(items) => Some(Value::Array(
            items
                .iter()
                .map(|entry| json_copy(entry, depth + 1).unwrap_or(Value::Null))
                .collect(),
        )),
        Value::Object(map) => {
            let mut result = Map::new();
            for (key, entry) in core_js::entries(map) {
                if UNSAFE_KEYS.contains(&key.as_str()) {
                    continue;
                }
                if let Some(copied) = json_copy(entry, depth + 1) {
                    result.insert(key.clone(), copied);
                }
            }
            Some(Value::Object(result))
        }
    }
}

fn stringified_len(value: &Value) -> usize {
    core_js::utf16_len(&core_js::stringify(value))
}

/// The event claims as stored: all of them up to 4 KiB, else the members that fit (long strings shortened).
fn stored_claims(event: &Map<String, Value>) -> Map<String, Value> {
    let copy = match json_copy(&Value::Object(event.clone()), 0) {
        Some(Value::Object(copy)) => copy,
        _ => Map::new(),
    };
    if stringified_len(&Value::Object(copy.clone())) <= MAX_CLAIMS_CHARS {
        return copy;
    }
    let mut kept = Map::new();
    kept.insert("_truncated".into(), Value::Bool(true));
    let mut size = stringified_len(&Value::Object(kept.clone()));
    for (key, value) in core_js::entries(&copy) {
        let entry = match value {
            Value::String(text) => Value::String(clip(text, 256)),
            other => other.clone(),
        };
        let mut single = Map::new();
        single.insert(key.clone(), entry.clone());
        let cost = stringified_len(&Value::Object(single));
        if size + cost > MAX_CLAIMS_CHARS {
            continue;
        }
        kept.insert(key.clone(), entry);
        size += cost;
    }
    kept
}

fn stored_subject(subject: Option<&SubjectIdentifier>) -> Option<Value> {
    let subject = subject?;
    let copy = json_copy(&subject.to_value(), 0).unwrap_or(Value::Null);
    if stringified_len(&copy) <= MAX_SUBJECT_CHARS {
        Some(copy)
    } else {
        Some(json!({ "format": subject.format(), "_truncated": true }))
    }
}

/// A localized claim (CAEP `reason_admin` is a language map; some transmitters send a plain string).
fn localized(value: Option<&Value>) -> Option<String> {
    if let Some(Value::String(text)) = value {
        return Some(text.clone());
    }
    let map = plain(value)?;
    if let Some(Value::String(english)) = map.get("en") {
        return Some(english.clone());
    }
    core_js::entries(map)
        .into_iter()
        .find_map(|(_, entry)| entry.as_str().map(str::to_owned))
}

/// A person of the source's tenant (not a service account or agent, not deleted), or None.
async fn person(
    tx: &Store,
    source: &Record,
    identity_id: Option<&Value>,
) -> IamResult<Option<Record>> {
    let Some(Value::String(identity_id)) = identity_id else {
        return Ok(None);
    };
    if identity_id.is_empty() {
        return Ok(None);
    }
    let Some(identity) = tx.get("identities", identity_id).await? else {
        return Ok(None);
    };
    if identity.get("tenantId") != source.get("tenantId")
        || str_member(&identity, "status") == Some("deleted")
        || matches!(str_member(&identity, "kind"), Some("service" | "agent"))
    {
        return Ok(None);
    }
    Ok(Some(identity))
}

/// Federation links store the connection's issuer spelled as its tokens did: try every spelling the source accepts.
fn link_issuers(source: &Record, iss: &str) -> Vec<String> {
    let mut spellings = vec![
        iss.to_owned(),
        trim_slashes(iss).to_owned(),
        format!("{}/", trim_slashes(iss)),
    ];
    for form in issuer_forms(source) {
        spellings.push(form.clone());
        spellings.push(format!("{form}/"));
    }
    core_js_unique(spellings)
}

fn core_js_unique(items: Vec<String>) -> Vec<String> {
    crate::js::unique(items)
}

fn tenant_of(source: &Record) -> Value {
    source.get("tenantId").cloned().unwrap_or(Value::Null)
}

fn subjects_list(source: &Record, key: &str) -> Vec<String> {
    strings_of(
        source
            .get("subjects")
            .and_then(|subjects| subjects.get(key)),
    )
}

async fn by_federation_link(
    tx: &Store,
    source: &Record,
    iss: &str,
    sub: &str,
) -> IamResult<Option<String>> {
    for connection_id in subjects_list(source, "connectionIds") {
        for issuer in link_issuers(source, iss) {
            let unique_key = core_js::stringify(&json!([connection_id, issuer, sub]));
            let link = tx
                .find(
                    "externalIdentities",
                    &Filter::new()
                        .eq("tenantId", tenant_of(source))
                        .eq("uniqueKey", unique_key),
                    &FindOptions::default(),
                )
                .await?
                .into_iter()
                .next();
            let identity = match &link {
                Some(link) => person(tx, source, link.get("identityId")).await?,
                None => None,
            };
            if let Some(identity) = identity {
                return Ok(Some(record_id(&identity).to_owned()));
            }
        }
    }
    Ok(None)
}

async fn by_scim_external_id(
    tx: &Store,
    source: &Record,
    external_id: &str,
) -> IamResult<Option<String>> {
    for connection_id in subjects_list(source, "scimConnectionIds") {
        for link in tx
            .find(
                "scimUsers",
                &Filter::new()
                    .eq("tenantId", tenant_of(source))
                    .eq("connectionId", connection_id)
                    .eq("externalId", external_id),
                &FindOptions::default(),
            )
            .await?
        {
            if let Some(identity) = person(tx, source, link.get("identityId")).await? {
                return Ok(Some(record_id(&identity).to_owned()));
            }
        }
    }
    Ok(None)
}

async fn by_verified_email(
    tx: &Store,
    source: &Record,
    address: &str,
) -> IamResult<Option<String>> {
    let match_email = source
        .get("subjects")
        .and_then(|subjects| subjects.get("matchEmail"));
    if !crate::js::truthy(match_email) {
        return Ok(None);
    }
    let Ok(normalized) = crate::validation::email(Some(&Value::String(address.to_owned()))) else {
        return Ok(None);
    };
    // Only a domain the tenant proved it controls: anyone can hold an address at a domain the tenant does not own.
    let domain = match normalized.rfind('@') {
        Some(at) => normalized[at + 1..].to_owned(),
        None => normalized.clone(),
    };
    let claim = tx
        .find(
            "tenantDomains",
            &Filter::new()
                .eq("tenantId", tenant_of(source))
                .eq("uniqueKey", domain.clone()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    let Some(claim) = claim else {
        return Ok(None);
    };
    if str_member(&claim, "status") != Some("verified")
        || str_member(&claim, "domain") != Some(&domain)
    {
        return Ok(None);
    }
    for identity in tx
        .find(
            "identities",
            &Filter::new()
                .eq("tenantId", tenant_of(source))
                .eq("email", normalized.clone()),
            &FindOptions::default(),
        )
        .await?
    {
        if let Some(found) = person(tx, source, identity.get("id")).await? {
            return Ok(Some(record_id(&found).to_owned()));
        }
    }
    Ok(None)
}

/// The identity of the source's tenant an event's subject names, or None. Every identifier that may name a person
/// (the subject itself, a complex subject's `user`, each alias) is tried in order: `iss_sub` of the source's issuer
/// (or an alias) through the federation links of `subjects.connectionIds`, then the `externalId` of users provisioned
/// through `subjects.scimConnectionIds`; `opaque` through the SCIM `externalId`; `email` and `acct:` by email when
/// `subjects.matchEmail` is on and the tenant verified the domain. Deleted identities, service accounts and agents
/// never match, nor does anyone in another tenant.
pub async fn resolve_subject(
    tx: &Store,
    source: &Record,
    subject: Option<&SubjectIdentifier>,
) -> IamResult<Option<String>> {
    for identifier in user_subjects(subject) {
        let identity_id = match &identifier {
            SubjectIdentifier::IssSub { iss, sub } => {
                if !names_signal_source(source, iss) {
                    None
                } else {
                    match by_federation_link(tx, source, iss, sub).await? {
                        Some(found) => Some(found),
                        None => by_scim_external_id(tx, source, sub).await?,
                    }
                }
            }
            SubjectIdentifier::Opaque { id } => by_scim_external_id(tx, source, id).await?,
            SubjectIdentifier::Email { email } => by_verified_email(tx, source, email).await?,
            SubjectIdentifier::Account { uri } => {
                let address = uri.get("acct:".len()..).unwrap_or_default();
                match crate::http::decode_uri_component(address) {
                    Some(address) => by_verified_email(tx, source, &address).await?,
                    None => None,
                }
            }
            _ => None,
        };
        if let Some(identity_id) = identity_id
            && !identity_id.is_empty()
        {
            return Ok(Some(identity_id));
        }
    }
    Ok(None)
}

/// Ends an identity's sessions except its API keys: user, role and session-token sessions (with the impersonations
/// opened through them), role sessions it assumed elsewhere, and its pending sign-in challenges. Remembered devices
/// stay, so the person's next sign-in is as usual. Returns the number of sessions ended.
async fn end_sessions(ctx: &ServerContext, tx: &Store, identity_id: &str) -> IamResult<f64> {
    let mut revoked = 0.0;
    for session in tx
        .find(
            "sessions",
            &Filter::new().eq("identityId", identity_id),
            &FindOptions::default(),
        )
        .await?
    {
        if str_member(&session, "kind") == Some("api-key") {
            continue;
        }
        ctx.auth.end_session(tx, record_id(&session)).await?;
        revoked += 1.0;
    }
    for session in tx
        .find(
            "sessions",
            &Filter::new().eq("originalIdentityId", identity_id),
            &FindOptions::default(),
        )
        .await?
    {
        if str_member(&session, "kind") == Some("api-key") {
            continue;
        }
        tx.delete("sessions", record_id(&session)).await?;
        revoked += 1.0;
    }
    for challenge in tx
        .find(
            "authChallenges",
            &Filter::new().eq("identityId", identity_id),
            &FindOptions::default(),
        )
        .await?
    {
        tx.delete("authChallenges", record_id(&challenge)).await?;
    }
    Ok(revoked)
}

async fn signal_audit(
    ctx: &ServerContext,
    tx: &Store,
    source: &Record,
    action: &str,
    resource_id: &str,
    metadata: Map<String, Value>,
) -> IamResult<()> {
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), tenant_of(source));
    event.insert(
        "actorId".into(),
        Value::String(signal_actor(record_id(source))),
    );
    event.insert("action".into(), Value::String(action.to_owned()));
    event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    event.insert("timestamp".into(), number(ctx.now()));
    event.insert("outcome".into(), Value::String("allow".into()));
    event.insert("metadata".into(), Value::Object(metadata));
    ctx.events()?.record_audit(tx, &event).await
}

/// What processing needs from a security event.
#[derive(Debug, Clone)]
pub struct SignalInput {
    pub event_type: String,
    pub subject: Option<SubjectIdentifier>,
    /// The event's own claims.
    pub event: Map<String, Value>,
    pub jti: String,
}

/// The result of `applySignal`; `source` carries the bookkeeping a control event changed (`source_changed` when it
/// is not the source passed in).
#[derive(Debug, Clone)]
pub struct SignalOutcome {
    pub status: &'static str,
    pub identity_id: Option<String>,
    pub reason: Option<&'static str>,
    pub source: Record,
    pub source_changed: bool,
}

fn outcome(
    status: &'static str,
    identity_id: Option<String>,
    reason: Option<&'static str>,
    source: &Record,
) -> SignalOutcome {
    SignalOutcome {
        status,
        identity_id,
        reason,
        source: source.clone(),
        source_changed: false,
    }
}

/// Handles one event inside the caller's transaction. Control events touch only the source: `verification` records
/// `lastVerifiedAt`; `stream-updated` to paused or disabled records the transmitter's status in `lastError`.
/// Unknown event types are ignored. Otherwise the subject is mapped (`resolveSubject`); for a match with the action
/// `revoke-sessions` configured for the event type, the person's sessions end (`signal:revoke-sessions`), except
/// for a root administrator unless the source belongs to the root tenant (ignored, reason `protected`).
pub async fn apply_signal(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    source: &Record,
    signal: &SignalInput,
) -> IamResult<SignalOutcome> {
    let now = ctx.now();
    if signal.event_type == "verification" {
        let mut next = source.clone();
        next.insert("lastVerifiedAt".into(), number(now));
        return Ok(SignalOutcome {
            status: "recorded",
            identity_id: None,
            reason: None,
            source: next,
            source_changed: true,
        });
    }
    if signal.event_type == "stream-updated" {
        let status = signal.event.get("status").and_then(Value::as_str);
        if let Some(status @ ("paused" | "disabled")) = status {
            let reason = localized(signal.event.get("reason")).filter(|reason| !reason.is_empty());
            let message = format!(
                "The transmitter {} the stream{}",
                if status == "paused" {
                    "paused"
                } else {
                    "disabled"
                },
                match reason {
                    Some(reason) => format!(": {}", clip(&reason, 200)),
                    None => String::new(),
                }
            );
            let mut next = source.clone();
            next.insert(
                "lastError".into(),
                json!({ "at": number(now), "message": message }),
            );
            return Ok(SignalOutcome {
                status: "recorded",
                identity_id: None,
                reason: None,
                source: next,
                source_changed: true,
            });
        }
        return Ok(outcome("recorded", None, None, source));
    }
    if signal.event_type == "unknown" {
        return Ok(outcome("ignored", None, Some("unsupported-event"), source));
    }
    let Some(identity_id) = resolve_subject(tx, source, signal.subject.as_ref()).await? else {
        let reason = if signal.subject.is_some() {
            "no-match"
        } else {
            "no-subject"
        };
        return Ok(outcome("unmatched", None, Some(reason), source));
    };
    let action = source
        .get("actions")
        .and_then(|actions| actions.get(&signal.event_type))
        .and_then(Value::as_str);
    if action != Some("revoke-sessions") {
        return Ok(outcome("recorded", Some(identity_id), None, source));
    }
    let identity = tx
        .get("identities", &identity_id)
        .await?
        .ok_or_else(crate::js::internal_error)?;
    if crate::js::truthy(identity.get("rootAdmin")) {
        let tenant = match source.get("tenantId").and_then(Value::as_str) {
            Some(tenant_id) => tx.get("tenants", tenant_id).await?,
            None => None,
        };
        let root = tenant.as_ref().is_some_and(|tenant| {
            str_member(tenant, "type") == Some("root")
                && tenant.get("parentId") == Some(&Value::Null)
        });
        if !root {
            return Ok(outcome(
                "ignored",
                Some(identity_id),
                Some("protected"),
                source,
            ));
        }
    }
    let identity_key = record_id(&identity).to_owned();
    let revoked = end_sessions(ctx, tx, &identity_key).await?;
    // A name of its own: the transmitter maps `identity:revoke-sessions` and would echo the revocation upstream.
    let mut metadata = Map::new();
    metadata.insert(
        "sourceId".into(),
        Value::String(record_id(source).to_owned()),
    );
    metadata.insert("eventType".into(), Value::String(signal.event_type.clone()));
    metadata.insert("jti".into(), Value::String(signal.jti.clone()));
    metadata.insert("revoked".into(), number(revoked));
    signal_audit(
        ctx,
        tx,
        source,
        "signal:revoke-sessions",
        &identity_key,
        metadata,
    )
    .await?;
    Ok(outcome("applied", Some(identity_id), None, source))
}

/// Audits a received (or reprocessed) event as `signal:received` for threat detection: actor `signal:{sourceId}`,
/// the matched identity (else the source) as resource, and `{ sourceId, eventType, jti, status, identityId?,
/// reasonAdmin?, currentLevel?, credentialType? }` (`currentLevel` upper-cased, for `risk-level-change`). `record`
/// carries the received event's `eventType`, `jti`, `status` and `identityId`.
pub async fn record_signal_received(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    source: &Record,
    record: &Record,
    event: &Map<String, Value>,
) -> IamResult<()> {
    let mut metadata = Map::new();
    metadata.insert(
        "sourceId".into(),
        Value::String(record_id(source).to_owned()),
    );
    for key in ["eventType", "jti", "status"] {
        metadata.insert(key.into(), record.get(key).cloned().unwrap_or(Value::Null));
    }
    let identity_id = record
        .get("identityId")
        .and_then(Value::as_str)
        .filter(|identity_id| !identity_id.is_empty());
    if let Some(identity_id) = identity_id {
        metadata.insert("identityId".into(), Value::String(identity_id.to_owned()));
    }
    if let Some(reason_admin) =
        localized(event.get("reason_admin")).filter(|reason| !reason.is_empty())
    {
        metadata.insert(
            "reasonAdmin".into(),
            Value::String(clip(&reason_admin, 256)),
        );
    }
    if str_member(record, "eventType") == Some("risk-level-change")
        && let Some(Value::String(level)) = event.get("current_level")
        && !level.is_empty()
    {
        metadata.insert(
            "currentLevel".into(),
            Value::String(clip(&level.to_uppercase(), 32)),
        );
    }
    if let Some(Value::String(credential_type)) = event.get("credential_type")
        && !credential_type.is_empty()
    {
        metadata.insert(
            "credentialType".into(),
            Value::String(clip(credential_type, 64)),
        );
    }
    let resource = match record.get("identityId") {
        Some(Value::String(identity_id)) => identity_id.clone(),
        _ => format!("signals/sources/{}", record_id(source)),
    };
    signal_audit(ctx, tx, source, "signal:received", &resource, metadata).await
}

fn receipt_of(record: &Record, duplicate: bool) -> SignalReceipt {
    SignalReceipt {
        event_id: record_id(record).to_owned(),
        status: str_member(record, "status").unwrap_or_default().to_owned(),
        duplicate,
        identity_id: str_member(record, "identityId")
            .filter(|identity_id| !identity_id.is_empty())
            .map(str::to_owned),
    }
}

fn source_gone() -> IamError {
    IamError::with_status("NOT_FOUND", "Signal source not found", 404)
}

/// The source inside a transaction, when it is active and its tenant (and every ancestor) is too; else NOT_FOUND.
async fn live_source(ctx: &ServerContext, tx: &Store, source_id: &str) -> IamResult<Record> {
    let Some(source) = tx.get(SOURCES_COLLECTION, source_id).await? else {
        return Err(source_gone());
    };
    if str_member(&source, "status") != Some("active") {
        return Err(source_gone());
    }
    let tenant_id = str_member(&source, "tenantId")
        .unwrap_or_default()
        .to_owned();
    match ctx.auth.assert_tenant_active(tx, &tenant_id).await {
        Ok(()) => Ok(source),
        Err(error) if error.status == 403 => Err(source_gone()),
        Err(error) => Err(error),
    }
}

async fn received_by_key(
    tx: &Store,
    tenant_id: &Value,
    unique_key: &str,
) -> IamResult<Option<Record>> {
    Ok(tx
        .find(
            EVENTS_COLLECTION,
            &Filter::new()
                .eq("tenantId", tenant_id.clone())
                .eq("uniqueKey", unique_key),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next())
}

fn received_record(
    source: &Record,
    claims: &SecurityEventClaims,
    unique_key: &str,
    now: f64,
    status: &str,
    identity_id: Option<&str>,
    reason: Option<&str>,
) -> Record {
    let subject = stored_subject(claims.subject.as_ref());
    let mut record = Record::new();
    record.insert("id".into(), Value::String(id()));
    record.insert("tenantId".into(), tenant_of(source));
    record.insert("uniqueKey".into(), Value::String(unique_key.to_owned()));
    record.insert(
        "sourceId".into(),
        Value::String(record_id(source).to_owned()),
    );
    record.insert(
        "streamId".into(),
        Value::String(record_id(source).to_owned()),
    );
    record.insert("jti".into(), Value::String(claims.jti.clone()));
    record.insert(
        "eventType".into(),
        Value::String(claims.event_type.to_owned()),
    );
    record.insert("eventUri".into(), Value::String(claims.event_uri.clone()));
    record.insert(
        "issuedAt".into(),
        number((claims.iat * 1000.0 + 0.5).floor()),
    );
    if let Some(timestamp) = claims.event_timestamp {
        record.insert("eventTimestamp".into(), number(timestamp));
    }
    if let Some(txn) = &claims.txn {
        record.insert("txn".into(), Value::String(txn.clone()));
    }
    if let Some(subject) = subject {
        record.insert("subject".into(), subject);
    }
    if let Some(identity_id) = identity_id.filter(|identity_id| !identity_id.is_empty()) {
        record.insert("identityId".into(), Value::String(identity_id.to_owned()));
    }
    record.insert("status".into(), Value::String(status.to_owned()));
    if let Some(reason) = reason.filter(|reason| !reason.is_empty()) {
        record.insert("reason".into(), Value::String(reason.to_owned()));
    }
    record.insert("claims".into(), Value::Object(stored_claims(&claims.event)));
    record.insert("receivedAt".into(), number(now));
    record.insert("timestamp".into(), number(now));
    record.insert("expiresAt".into(), number(now + SIGNAL_RETENTION_MS));
    record
}

/// Records a verified event for a source in one transaction: deduplicates on issuer and `jti` (a repeat returns the
/// first receipt with `duplicate: true`), applies it (`applySignal`), stores it, audits `signal:received` and notes
/// `lastEventAt`. When applying fails, the event is stored as `failed` in a transaction of its own instead, so an
/// administrator can reprocess it and the transmitter is not asked for it again. Fails with NOT_FOUND when the source
/// is gone or disabled, and storage contention (503) as is, so the caller can have the event delivered again.
pub async fn process_signal(
    ctx: &Arc<ServerContext>,
    source_id: &str,
    claims: &SecurityEventClaims,
) -> IamResult<SignalReceipt> {
    let first = ctx
        .store
        .transaction(|tx| async move {
            let source = live_source(ctx, &tx, source_id).await?;
            let unique_key = signal_event_key(
                str_member(&source, "issuer").unwrap_or_default(),
                &claims.jti,
            );
            if let Some(existing) = received_by_key(&tx, &tenant_of(&source), &unique_key).await? {
                return Ok(receipt_of(&existing, true));
            }
            let now = ctx.now();
            let outcome = apply_signal(
                ctx,
                &tx,
                &source,
                &SignalInput {
                    event_type: claims.event_type.to_owned(),
                    subject: claims.subject.clone(),
                    event: claims.event.clone(),
                    jti: claims.jti.clone(),
                },
            )
            .await?;
            let record = tx
                .insert(
                    EVENTS_COLLECTION,
                    &received_record(
                        &source,
                        claims,
                        &unique_key,
                        now,
                        outcome.status,
                        outcome.identity_id.as_deref(),
                        outcome.reason,
                    ),
                )
                .await?;
            record_signal_received(ctx, &tx, &source, &record, &claims.event).await?;
            let mut next = outcome.source.clone();
            next.insert("lastEventAt".into(), number(now));
            tx.put(SOURCES_COLLECTION, &next).await?;
            Ok(receipt_of(&record, false))
        })
        .await;
    let error = match first {
        Ok(receipt) => return Ok(receipt),
        Err(error) => error,
    };
    if error.status == 404 || error.status >= 500 {
        return Err(error);
    }
    // The same event committed concurrently (the natural key collided), or applying it failed.
    let failure_code = error.code.clone();
    ctx.store
        .transaction(|tx| async move {
            let source = live_source(ctx, &tx, source_id).await?;
            let unique_key = signal_event_key(
                str_member(&source, "issuer").unwrap_or_default(),
                &claims.jti,
            );
            if let Some(existing) = received_by_key(&tx, &tenant_of(&source), &unique_key).await? {
                return Ok(receipt_of(&existing, true));
            }
            let now = ctx.now();
            let record = tx
                .insert(
                    EVENTS_COLLECTION,
                    &received_record(
                        &source,
                        claims,
                        &unique_key,
                        now,
                        "failed",
                        None,
                        Some(&failure_code),
                    ),
                )
                .await?;
            record_signal_received(ctx, &tx, &source, &record, &claims.event).await?;
            let mut next = source.clone();
            next.insert("lastEventAt".into(), number(now));
            tx.put(SOURCES_COLLECTION, &next).await?;
            Ok(receipt_of(&record, false))
        })
        .await
}

/// Why verification stopped before it became a [`SignalRejectedError`].
#[derive(Debug, Clone)]
enum Failure {
    Rejected(SignalRejectedError),
    /// The key resolver could not obtain the source's keys right now (`KeysUnavailable`).
    KeysUnavailable,
    Jose(JoseError),
    Format(SignalFormatError),
}

impl From<SignalRejectedError> for Failure {
    fn from(error: SignalRejectedError) -> Self {
        Failure::Rejected(error)
    }
}

impl From<JoseError> for Failure {
    fn from(error: JoseError) -> Self {
        match error {
            JoseError::KeySetUnavailable => Failure::KeysUnavailable,
            other => Failure::Jose(other),
        }
    }
}

fn rejection_for(error: Failure, remote_keys: bool) -> SignalRejectedError {
    let rejected =
        |err: SignalErrorCode, description: &str| SignalRejectedError::new(err, description);
    match error {
        Failure::Rejected(error) => error,
        Failure::KeysUnavailable | Failure::Jose(JoseError::Timeout) => {
            SignalRejectedError::temporary(
                "invalid_key",
                "The source's signing keys could not be obtained",
                true,
            )
        }
        Failure::Jose(JoseError::JwksInvalid) => {
            SignalRejectedError::temporary("invalid_key", "The source's key set is invalid", true)
        }
        // A transmitter that rotated its keys moments ago is retried once the key set may be fetched again.
        Failure::Jose(JoseError::NoMatchingKey) => SignalRejectedError::temporary(
            "invalid_key",
            "No key of the source matches the token",
            remote_keys,
        ),
        Failure::Jose(JoseError::MultipleMatchingKeys) => {
            rejected("invalid_key", "Several keys of the source match the token")
        }
        Failure::Jose(JoseError::SignatureFailed) => {
            rejected("invalid_key", "The token signature is invalid")
        }
        Failure::Jose(JoseError::AlgNotAllowed | JoseError::NotSupported) => {
            rejected("invalid_key", "The token algorithm or key is not accepted")
        }
        Failure::Jose(JoseError::Expired { .. }) => {
            rejected("invalid_request", "The token has expired")
        }
        Failure::Jose(JoseError::ClaimValidation { claim, .. }) => match claim.as_str() {
            "iss" => rejected(
                "invalid_issuer",
                "The token's issuer is not the source's issuer",
            ),
            "aud" => rejected(
                "invalid_audience",
                "The token is not addressed to this receiver",
            ),
            "typ" => rejected("invalid_request", "The token type must be secevent+jwt"),
            other => rejected(
                "invalid_request",
                &format!("The token's {other} claim is missing or invalid"),
            ),
        },
        Failure::Format(error) => rejected("invalid_request", &error.message),
        Failure::Jose(_) => rejected("invalid_request", "The security event token is malformed"),
    }
}

/// A key set snapshot (`createLocalJWKSet`), with the raw keys for trying several candidates.
#[derive(Clone)]
struct LocalKeys {
    set: Arc<JwkSet>,
    keys: Arc<Vec<Map<String, Value>>>,
}

impl LocalKeys {
    /// `createLocalJWKSet(jwks)`: JWKSInvalid unless `jwks` is an object whose `keys` are all objects.
    fn new(jwks: &Value) -> Result<Self, JoseError> {
        let set = JwkSet::new(jwks)?;
        let keys = match jwks.get("keys") {
            Some(Value::Array(keys)) => keys
                .iter()
                .filter_map(|key| key.as_object().cloned())
                .collect(),
            _ => Vec::new(),
        };
        Ok(Self {
            set: Arc::new(set),
            keys: Arc::new(keys),
        })
    }

    /// The key resolver; on several matching keys, the candidates (jose's async iterator) go into `stash`.
    fn lookup(
        &self,
        header: &Map<String, Value>,
        stash: &Mutex<Option<Vec<VerifyKey>>>,
    ) -> Result<VerifyKey, JoseError> {
        match self.set.get_key(header) {
            Err(JoseError::MultipleMatchingKeys) => {
                // Each candidate imported on its own; keys that do not import are skipped.
                let candidates: Vec<VerifyKey> = self
                    .keys
                    .iter()
                    .filter_map(|key| JwkSet::from_keys(vec![key.clone()]).get_key(header).ok())
                    .collect();
                *lock(stash) = Some(candidates);
                Err(JoseError::MultipleMatchingKeys)
            }
            other => other,
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

type Reload = Shared<BoxFuture<'static, Result<(), JoseError>>>;

struct RemoteState {
    local: Option<LocalKeys>,
    timestamp: Option<f64>,
    pending: Option<Reload>,
}

/// `createRemoteJWKSet(url, { [customFetch]: jwksFetch, timeoutDuration: 5000, cooldownDuration: 30000,
/// cacheMaxAge: 600000 })`: a key set fetched through the receiver's guarded transport, cached for ten minutes and
/// refetched on an unknown `kid` once the cooldown has passed. Times are `Date.now()`.
struct RemoteKeys {
    url: Url,
    fetch: GuardedFetch,
    state: Mutex<RemoteState>,
}

fn fresh_for(timestamp: Option<f64>, duration: f64) -> bool {
    timestamp.is_some_and(|timestamp| timestamp.is_finite() && date_now() < timestamp + duration)
}

impl RemoteKeys {
    fn new(url: Url, fetch: GuardedFetch) -> Arc<Self> {
        Arc::new(Self {
            url,
            fetch,
            state: Mutex::new(RemoteState {
                local: None,
                timestamp: None,
                pending: None,
            }),
        })
    }

    /// `fetchJwks(url, headers, signal, fetchImpl)`.
    async fn fetch_jwks(&self) -> Result<Value, JoseError> {
        let request = FetchRequest::get(self.url.as_str())
            .header("user-agent", "jose/v6.2.12")
            .header("accept", "application/json, application/jwk-set+json")
            .redirect(RedirectMode::Manual);
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
        match tokio::time::timeout(Duration::from_millis(FETCH_TIMEOUT_MS), work).await {
            Ok(result) => result,
            Err(_) => Err(JoseError::Timeout),
        }
    }

    /// `reload()`: one fetch for all concurrent callers.
    async fn reload(self: &Arc<Self>) -> Result<(), JoseError> {
        let pending = {
            let mut state = lock(&self.state);
            match &state.pending {
                Some(pending) => pending.clone(),
                None => {
                    let this = self.clone();
                    let future: BoxFuture<'static, Result<(), JoseError>> = Box::pin(async move {
                        let outcome = match this.fetch_jwks().await {
                            Ok(json) => LocalKeys::new(&json).map(|next| {
                                let mut state = lock(&this.state);
                                state.local = Some(next);
                                state.timestamp = Some(date_now());
                            }),
                            Err(error) => Err(error),
                        };
                        lock(&this.state).pending = None;
                        outcome
                    });
                    let shared = future.shared();
                    state.pending = Some(shared.clone());
                    shared
                }
            }
        };
        pending.await
    }

    /// `getKey(protectedHeader)` of the remote set.
    async fn get_key(
        self: &Arc<Self>,
        header: &Map<String, Value>,
        stash: &Mutex<Option<Vec<VerifyKey>>>,
    ) -> Result<VerifyKey, JoseError> {
        let stale = {
            let state = lock(&self.state);
            state.local.is_none() || !fresh_for(state.timestamp, JWKS_CACHE_MAX_AGE_MS)
        };
        if stale {
            self.reload().await?;
        }
        let local = lock(&self.state)
            .local
            .clone()
            .ok_or(JoseError::JwksInvalid)?;
        let cooling = fresh_for(lock(&self.state).timestamp, JWKS_COOLDOWN_MS);
        match local.lookup(header, stash) {
            Err(JoseError::NoMatchingKey) if !cooling => {
                self.reload().await?;
                let local = lock(&self.state)
                    .local
                    .clone()
                    .ok_or(JoseError::JwksInvalid)?;
                local.lookup(header, stash)
            }
            other => other,
        }
    }
}

/// A source's key resolver: static keys, or a remote key set whose transport failures read as unavailable keys.
#[derive(Clone)]
enum KeySet {
    Local(LocalKeys),
    Remote(Arc<RemoteKeys>),
}

impl KeySet {
    async fn resolve(
        &self,
        header: &Map<String, Value>,
        stash: &Mutex<Option<Vec<VerifyKey>>>,
    ) -> Result<VerifyKey, JoseError> {
        match self {
            KeySet::Local(local) => local.lookup(header, stash),
            KeySet::Remote(remote) => match remote.get_key(header, stash).await {
                // Which key signed the token is the token's matter. A key set that could not be fetched or read (a
                // timeout, a status other than 200, a body that is not a public key set) is the transmitter's, and
                // may pass later.
                Ok(key) => Ok(key),
                Err(
                    error @ (JoseError::NoMatchingKey
                    | JoseError::MultipleMatchingKeys
                    | JoseError::NotSupported),
                ) => Err(error),
                Err(_) => Err(JoseError::KeySetUnavailable),
            },
        }
    }
}

/// The `jwtVerify` options of the receiver; the issuer (one of several spellings) and the audience are checked here,
/// in jose's order, around the shared verifier.
struct ClaimRules {
    issuers: Vec<String>,
    audiences: Vec<String>,
    typ: Option<&'static str>,
    algorithms: Vec<String>,
    current_ms: f64,
}

fn claim_failed(claim: &str) -> JoseError {
    JoseError::ClaimValidation {
        claim: claim.to_owned(),
        reason: "check_failed".to_owned(),
    }
}

/// jose's issuer (`issuer` as an array) and audience checks.
fn check_issuer_audience(
    payload: &Map<String, Value>,
    rules: &ClaimRules,
) -> Result<(), JoseError> {
    let issuer_ok =
        matches!(payload.get("iss"), Some(Value::String(iss)) if rules.issuers.contains(iss));
    if !issuer_ok {
        return Err(claim_failed("iss"));
    }
    let audience_ok = match payload.get("aud") {
        Some(Value::String(aud)) => rules.audiences.contains(aud),
        Some(Value::Array(items)) => rules.audiences.iter().any(|wanted| {
            items
                .iter()
                .any(|item| item.as_str() == Some(wanted.as_str()))
        }),
        _ => false,
    };
    if !audience_ok {
        return Err(claim_failed("aud"));
    }
    Ok(())
}

/// The payload of a token whose signature verified, decoded as jose does.
fn decoded_payload(token: &str) -> Option<Map<String, Value>> {
    let encoded = token.split('.').nth(1)?;
    let bytes = jose::decode_base64url(encoded)?;
    let bytes = bytes.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(&bytes);
    match core_js::parse(std::str::from_utf8(bytes).ok()?).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// One `jwtVerify(token, getKey, options)` with the receiver's options.
async fn jwt_verify_with<R, F>(
    token: &str,
    resolve: R,
    rules: &ClaimRules,
) -> Result<Map<String, Value>, JoseError>
where
    R: FnOnce(Map<String, Value>) -> F,
    F: std::future::Future<Output = Result<VerifyKey, JoseError>>,
{
    let tolerance = number(CLOCK_TOLERANCE_SECONDS);
    // jose checks the presence of `requiredClaims` plus `aud` and `iss` (given as options) in reverse order: `iss`,
    // `aud`, `events`, `jti`, `iat`.
    let options = jose::VerifyOptions {
        algorithms: &rules.algorithms,
        issuer: None,
        audience: None,
        typ: rules.typ,
        required_claims: &["iat", "jti", "events", "aud", "iss"],
        clock_tolerance: Some(&tolerance),
        current_ms: rules.current_ms,
        max_token_age: None,
    };
    match jose::jwt_verify(token, resolve, &options).await {
        Ok(payload) => {
            check_issuer_audience(&payload, rules)?;
            Ok(payload)
        }
        // jose checks the issuer and the audience before the times.
        Err(error @ (JoseError::Expired { .. } | JoseError::ClaimValidation { .. })) if !matches!(&error, JoseError::ClaimValidation { claim, reason } if reason == "missing" || claim == "typ") =>
        {
            if let Some(payload) = decoded_payload(token) {
                check_issuer_audience(&payload, rules)?;
            }
            Err(error)
        }
        Err(error) => Err(error),
    }
}

/// jose's `jwtVerify`, trying each candidate when several keys of the set could have signed the token (keys without
/// a `kid`, or a token without one): the first that verifies wins, and none verifying is a bad signature.
async fn verified_payload(
    token: &str,
    keys: &KeySet,
    rules: &ClaimRules,
) -> Result<Map<String, Value>, JoseError> {
    let stash: Mutex<Option<Vec<VerifyKey>>> = Mutex::new(None);
    let stash = &stash;
    let first = jwt_verify_with(
        token,
        |header| async move { keys.resolve(&header, stash).await },
        rules,
    )
    .await;
    match first {
        Err(JoseError::MultipleMatchingKeys) => {}
        other => return other,
    }
    let candidates = lock(stash).take().unwrap_or_default();
    for key in candidates.into_iter().take(MAX_CANDIDATE_KEYS) {
        match jwt_verify_with(token, |_| async move { Ok(key) }, rules).await {
            Ok(payload) => return Ok(payload),
            Err(JoseError::SignatureFailed) => {}
            Err(other) => return Err(other),
        }
    }
    Err(JoseError::SignatureFailed)
}

/// What the key cache keeps per source.
#[derive(Default)]
struct CachedKeys {
    updated_at: Option<Value>,
    keys: Option<KeySet>,
    discovered_at: Option<f64>,
    pending: Option<Shared<BoxFuture<'static, Result<KeySet, ()>>>>,
    failed_at: Option<f64>,
}

type Entry = Arc<Mutex<CachedKeys>>;

fn same_updated_at(left: Option<&Value>, right: Option<&Value>) -> bool {
    match (left, right) {
        (None, None) => true,
        (Some(left), Some(right)) => core_js::strict_equal(left, right),
        _ => false,
    }
}

fn header_value(headers: &http::HeaderMap, name: &str) -> Option<String> {
    let values: Vec<String> = headers
        .get_all(name)
        .iter()
        .map(|value| String::from_utf8_lossy(value.as_bytes()).into_owned())
        .collect();
    (!values.is_empty()).then(|| values.join(", "))
}

fn push_error(
    status: u16,
    err: &str,
    description: &str,
    headers: &[(&str, String)],
) -> HttpResponse {
    let body = core_js::stringify(&json!({ "err": err, "description": description }));
    let mut builder = http::Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .header("cache-control", "no-store");
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    builder
        .body(Bytes::from(body))
        .unwrap_or_else(|_| HttpResponse::new(Bytes::new()))
}

/// A failed poll request; the message is safe to store as the source's `lastError`.
struct PollFailure(String);

/// One poll answer: `[jti, set]` pairs and `moreAvailable`.
struct PollAnswer {
    sets: Vec<(String, Value)>,
    more_available: bool,
}

/// The receiver's per-deployment state: key caches, guarded transports, and the push endpoint.
pub struct SignalReceiver {
    address_rules: SafeFetchAddressOptions,
    jwks_fetch: GuardedFetch,
    discovery_fetch: GuardedFetch,
    poll_fetch: GuardedFetch,
    cache: Mutex<IndexMap<String, Entry>>,
    prefix: String,
}

fn create_signal_receiver(ctx: &ServerContext) -> SignalReceiver {
    let settings = &ctx.config.signals;
    let address_rules = SafeFetchAddressOptions {
        any_port: true,
        allow_private_networks: settings.allow_private_networks,
        allow_insecure_localhost: settings.allow_insecure_localhost,
    };
    let guarded = |max_bytes: u64| {
        create_guarded_fetch(GuardedFetchOptions {
            allow_private_networks: settings.allow_private_networks,
            allow_insecure_localhost: settings.allow_insecure_localhost,
            any_port: true,
            max_bytes: Some(max_bytes),
        })
    };
    SignalReceiver {
        address_rules,
        jwks_fetch: guarded(JWKS_MAX_BYTES),
        discovery_fetch: guarded(DISCOVERY_MAX_BYTES),
        poll_fetch: guarded(POLL_MAX_BYTES),
        cache: Mutex::new(IndexMap::new()),
        prefix: format!("{}/", settings.push_path),
    }
}

impl SignalReceiver {
    fn entry_for(&self, source: &Record) -> Entry {
        let key = record_id(source).to_owned();
        let updated_at = source.get("updatedAt");
        let mut cache = lock(&self.cache);
        if let Some(entry) = cache.get(&key)
            && same_updated_at(lock(entry).updated_at.as_ref(), updated_at)
        {
            return entry.clone();
        }
        if !cache.contains_key(&key) && cache.len() >= MAX_CACHED_SOURCES {
            cache.shift_remove_index(0);
        }
        let entry: Entry = Arc::new(Mutex::new(CachedKeys {
            updated_at: updated_at.cloned(),
            ..CachedKeys::default()
        }));
        cache.insert(key, entry.clone());
        entry
    }

    /// A remote key set fetched through the guarded transport.
    fn remote_keys(&self, url: Url) -> KeySet {
        KeySet::Remote(RemoteKeys::new(url, self.jwks_fetch))
    }

    async fn get_json(&self, url: &str) -> Result<Value, ()> {
        let request = FetchRequest::get(url)
            .header("accept", "application/json")
            .redirect(RedirectMode::Error);
        let work = async {
            let mut response = self.discovery_fetch.fetch(request).await.map_err(|_| ())?;
            let content_type = response.header("content-type").unwrap_or_default();
            if response.status != 200 || !content_type.to_lowercase().contains("json") {
                response.body.cancel();
                return Err(());
            }
            let text = response.body.text().await.map_err(|_| ())?;
            core_js::parse(&text).map_err(|_| ())
        };
        match tokio::time::timeout(Duration::from_millis(FETCH_TIMEOUT_MS), work).await {
            Ok(result) => result,
            Err(_) => Err(()),
        }
    }

    /// SSF discovery (`/.well-known/ssf-configuration{path}`, then the legacy RISC document): the `jwks_uri`.
    async fn discover(&self, source: &Record) -> Result<Url, ()> {
        let issuer =
            Url::parse(str_member(source, "issuer").unwrap_or_default()).map_err(|_| ())?;
        let path = trim_slashes(issuer.path()).to_owned();
        let origin = crate::hosts::url_origin(&issuer);
        for name in ["ssf-configuration", "risc-configuration"] {
            let Ok(url) = Url::parse(&format!("{origin}/.well-known/{name}{path}")) else {
                continue;
            };
            let Ok(document) = self.get_json(url.as_str()).await else {
                continue;
            };
            let Some(document) = plain(Some(&document)) else {
                continue;
            };
            let document_issuer = document.get("issuer");
            match document_issuer {
                Some(Value::String(document_issuer))
                    if names_signal_source(source, document_issuer) => {}
                _ => continue,
            }
            let Some(Value::String(jwks_uri)) = document.get("jwks_uri") else {
                continue;
            };
            if let Ok(url) = check_fetch_url(jwks_uri, &self.address_rules) {
                return Ok(url);
            }
        }
        Err(())
    }

    /// The source's keys: static ones, its key URL, or discovered (single-flight, 30 s negative cache, daily
    /// refresh).
    async fn keys_for(self: &Arc<Self>, source: &Record) -> Result<KeySet, Failure> {
        let entry = self.entry_for(source);
        let now = date_now();
        {
            let state = lock(&entry);
            if let Some(keys) = &state.keys
                && state
                    .discovered_at
                    .is_none_or(|discovered_at| now - discovered_at < REDISCOVER_MS)
            {
                return Ok(keys.clone());
            }
        }
        if crate::js::truthy(source.get("jwks")) {
            let jwks = source.get("jwks").and_then(|jwks| jwks.get("keys"));
            let set = json!({ "keys": jwks.cloned().unwrap_or(Value::Null) });
            let keys = KeySet::Local(LocalKeys::new(&set)?);
            lock(&entry).keys = Some(keys.clone());
            return Ok(keys);
        }
        if crate::js::truthy(source.get("jwksUri")) {
            let jwks_uri = source
                .get("jwksUri")
                .and_then(Value::as_str)
                .unwrap_or_default();
            let Ok(url) = check_fetch_url(jwks_uri, &self.address_rules) else {
                // Stored under looser deployment settings than the current ones: it stays refused until an update
                // fixes it.
                return Err(SignalRejectedError::new(
                    "invalid_key",
                    "The source's key URL is not allowed",
                )
                .into());
            };
            let keys = self.remote_keys(url);
            lock(&entry).keys = Some(keys.clone());
            return Ok(keys);
        }
        // A daily rediscovery that fails keeps the keys found before, so a brief outage of the discovery document
        // does not refuse events the known keys still verify.
        let pending = {
            let mut state = lock(&entry);
            let stale = state.keys.clone();
            if let Some(failed_at) = state.failed_at
                && now - failed_at < NEGATIVE_CACHE_MS
                && state.pending.is_none()
            {
                return match stale {
                    Some(stale) => Ok(stale),
                    None => Err(Failure::KeysUnavailable),
                };
            }
            match &state.pending {
                Some(pending) => pending.clone(),
                None => {
                    let receiver = self.clone();
                    let owned_entry = entry.clone();
                    let source = source.clone();
                    let future: BoxFuture<'static, Result<KeySet, ()>> = Box::pin(async move {
                        let outcome = receiver.discover(&source).await;
                        let mut state = lock(&owned_entry);
                        let result = match outcome {
                            Ok(url) => {
                                let keys = receiver.remote_keys(url);
                                state.keys = Some(keys.clone());
                                state.discovered_at = Some(date_now());
                                state.failed_at = None;
                                Ok(keys)
                            }
                            Err(()) => {
                                state.failed_at = Some(date_now());
                                state.keys.clone().ok_or(())
                            }
                        };
                        state.pending = None;
                        result
                    });
                    let shared = future.shared();
                    state.pending = Some(shared.clone());
                    shared
                }
            }
        };
        pending.await.map_err(|()| Failure::KeysUnavailable)
    }

    async fn verify_inner(
        self: &Arc<Self>,
        ctx: &ServerContext,
        source: &Record,
        set: &Value,
    ) -> Result<SecurityEventClaims, Failure> {
        let Value::String(set) = set else {
            return Err(SignalRejectedError::new(
                "invalid_request",
                "Expected a compact security event token",
            )
            .into());
        };
        let token = core_js::trim(set);
        if token.len() > MAX_SET_BYTES {
            return Err(SignalRejectedError::new(
                "invalid_request",
                "The security event token is larger than 16 KiB",
            )
            .into());
        }
        if !COMPACT_JWS.is_match(token) {
            return Err(SignalRejectedError::new(
                "invalid_request",
                "Expected a compact signed JWT",
            )
            .into());
        }
        let header = jose::decode_protected_header(token).map_err(|_| {
            SignalRejectedError::new("invalid_request", "The token header is malformed")
        })?;
        // Keys come from the source's configuration only, never from the token itself.
        for member in FORBIDDEN_HEADERS {
            if header.contains_key(member) {
                return Err(SignalRejectedError::new(
                    "invalid_request",
                    format!("The token header must not carry {member}"),
                )
                .into());
            }
        }
        if header.contains_key("crit") {
            return Err(SignalRejectedError::new(
                "invalid_request",
                "The token names critical header parameters",
            )
            .into());
        }
        let algorithms = strings_of(source.get("algorithms"));
        match header.get("alg") {
            Some(Value::String(alg)) if algorithms.contains(alg) => {}
            _ => {
                return Err(SignalRejectedError::new(
                    "invalid_key",
                    "The token algorithm is not allowed for this source",
                )
                .into());
            }
        }
        if header.get("kid").is_some_and(|kid| !kid.is_string()) {
            return Err(SignalRejectedError::new(
                "invalid_request",
                "The token header is malformed",
            )
            .into());
        }
        let require_typ = crate::js::truthy(source.get("requireTyp"));
        if require_typ {
            match header.get("typ") {
                Some(Value::String(typ)) if normalized_typ(typ) == "secevent+jwt" => {}
                _ => {
                    return Err(SignalRejectedError::new(
                        "invalid_request",
                        "The token type must be secevent+jwt",
                    )
                    .into());
                }
            }
        } else if let Some(typ) = header.get("typ") {
            let lenient = typ
                .as_str()
                .is_some_and(|typ| LENIENT_TYPES.contains(&normalized_typ(typ).as_str()));
            if !lenient {
                return Err(SignalRejectedError::new(
                    "invalid_request",
                    "The token type is not a security event token",
                )
                .into());
            }
        }
        let now = ctx.now();
        let keys = self.keys_for(source).await?;
        let rules = ClaimRules {
            issuers: issuer_forms(source)
                .into_iter()
                .flat_map(|form| [form.clone(), format!("{form}/")])
                .collect(),
            audiences: strings_of(source.get("audiences")),
            typ: require_typ.then_some("secevent+jwt"),
            algorithms,
            current_ms: now,
        };
        let payload = verified_payload(token, &keys, &rules).await?;
        let claims =
            read_security_event(&Value::Object(payload.clone())).map_err(Failure::Format)?;
        if let Some(tenant_claim) = source.get("tenantClaim") {
            let matches = payload
                .get("tenant_id")
                .is_some_and(|claim| core_js::strict_equal(claim, tenant_claim));
            if !matches {
                return Err(SignalRejectedError::new(
                    "invalid_audience",
                    "The token is for another organization of its issuer",
                )
                .into());
            }
        }
        // No maxTokenAge (a polled event can wait in the transmitter's queue), but nothing older than a week.
        let seconds = now / 1000.0;
        if claims.iat > seconds + CLOCK_TOLERANCE_SECONDS {
            return Err(SignalRejectedError::new(
                "invalid_request",
                "The token was issued in the future",
            )
            .into());
        }
        if claims.iat < seconds - MAX_SET_AGE_SECONDS {
            return Err(SignalRejectedError::new(
                "invalid_request",
                "The token is older than seven days",
            )
            .into());
        }
        Ok(claims)
    }

    /// Verifies a compact SET for a source (signature, issuer, audience, type, age, claims) or fails with
    /// [`SignalRejectedError`].
    pub async fn verify(
        self: &Arc<Self>,
        ctx: &ServerContext,
        source: &Record,
        set: &Value,
    ) -> Result<SecurityEventClaims, SignalRejectedError> {
        let remote = !source.contains_key("jwks");
        self.verify_inner(ctx, source, set)
            .await
            .map_err(|error| rejection_for(error, remote))
    }

    /// Notes a refusal or transport failure on the source, at most once a minute per message.
    async fn note_error(&self, ctx: &Arc<ServerContext>, source_id: &str, message: &str) {
        let _ = ctx
            .store
            .transaction(|tx| async move {
                let Some(mut current) = tx.get(SOURCES_COLLECTION, source_id).await? else {
                    return Ok(());
                };
                let now = ctx.now();
                if let Some(last) = current.get("lastError")
                    && last.get("message").and_then(Value::as_str) == Some(message)
                    && last
                        .get("at")
                        .and_then(core_js::as_number)
                        .is_some_and(|at| now - at < 60_000.0)
                {
                    return Ok(());
                }
                current.insert(
                    "lastError".into(),
                    json!({ "at": number(now), "message": clip(message, 512) }),
                );
                tx.put(SOURCES_COLLECTION, &current).await?;
                Ok(())
            })
            .await;
        // Bookkeeping never hides the refusal itself.
    }

    /// Verifies and processes a SET; a refusal is noted on the source as `lastError`.
    pub async fn accept(
        self: &Arc<Self>,
        ctx: &Arc<ServerContext>,
        source: &Record,
        set: &Value,
    ) -> Result<SignalReceipt, AcceptError> {
        let claims = match self.verify(ctx, source, set).await {
            Ok(claims) => claims,
            Err(rejection) => {
                self.note_error(
                    ctx,
                    record_id(source),
                    &format!("Refused an event: {}", rejection.description),
                )
                .await;
                return Err(AcceptError::Rejected(rejection));
            }
        };
        process_signal(ctx, record_id(source), &claims)
            .await
            .map_err(AcceptError::Failed)
    }

    /// The source when it is active and its tenant is, read in a short transaction; None otherwise.
    async fn active_source(
        &self,
        ctx: &ServerContext,
        source_id: &str,
    ) -> IamResult<Option<Record>> {
        match ctx
            .store
            .transaction(|tx| async move { live_source(ctx, &tx, source_id).await })
            .await
        {
            Ok(source) => Ok(Some(source)),
            Err(error) if error.status == 404 => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// The RFC 8935 push endpoint.
    pub async fn handle(
        self: &Arc<Self>,
        ctx: &Arc<ServerContext>,
        request: &HttpRequest,
    ) -> Option<HttpResponse> {
        let url = crate::http::request_url(request, &ctx.config.base_url)?;
        let source_id = url.path().strip_prefix(self.prefix.as_str())?.to_owned();
        if !source_id_shaped(&source_id) {
            return None;
        }
        Some(match self.push(ctx, request, &source_id).await {
            Ok(response) => response,
            Err(error) if error.status == 404 => {
                push_error(404, "invalid_request", "Unknown stream", &[])
            }
            Err(error) if error.status == 503 => push_error(
                503,
                "invalid_request",
                "The receiver is busy; try again later",
                &[("retry-after", "1".to_owned())],
            ),
            Err(_) => push_error(
                500,
                "invalid_request",
                "The event could not be processed",
                &[],
            ),
        })
    }

    async fn push(
        self: &Arc<Self>,
        ctx: &Arc<ServerContext>,
        request: &HttpRequest,
        source_id: &str,
    ) -> IamResult<HttpResponse> {
        if request.method() != http::Method::POST {
            return Ok(push_error(
                405,
                "invalid_request",
                "Use POST",
                &[("allow", "POST".to_owned())],
            ));
        }
        let content_type = header_value(request.headers(), "content-type").unwrap_or_default();
        let kind = core_js::trim(content_type.split(';').next().unwrap_or_default()).to_lowercase();
        if kind != "application/secevent+jwt" {
            return Ok(push_error(
                415,
                "invalid_request",
                "The content type must be application/secevent+jwt",
                &[],
            ));
        }
        let declared = match header_value(request.headers(), "content-length") {
            Some(length) => core_js::string_to_number(&length),
            None => 0.0,
        };
        if declared.is_finite() && declared > MAX_PUSH_BYTES as f64 {
            return Ok(push_error(
                413,
                "invalid_request",
                "The request body is too large",
                &[],
            ));
        }
        let source = self.active_source(ctx, source_id).await?;
        let Some(source) = source.filter(|source| str_member(source, "delivery") == Some("push"))
        else {
            return Ok(push_error(404, "invalid_request", "Unknown stream", &[]));
        };
        let tenant_id = str_member(&source, "tenantId")
            .unwrap_or_default()
            .to_owned();
        if let Err(error) = ctx
            .auth
            .limit_attempt(
                &tenant_id,
                &format!("signals:{}", record_id(&source)),
                LimitAttemptOptions {
                    tier: None,
                    limit: Some(PUSHES_PER_WINDOW),
                    count_client: None,
                },
            )
            .await
        {
            if error.status == 429 {
                let retry_after = crate::port::details_of(&error)
                    .and_then(|details| details.retry_after_ms)
                    .map(|ms| core_js::number_to_string((ms / 1000.0).ceil()));
                let headers: Vec<(&str, String)> = retry_after
                    .map(|value| vec![("retry-after", value)])
                    .unwrap_or_default();
                return Ok(push_error(
                    429,
                    "invalid_request",
                    "Too many events; try again later",
                    &headers,
                ));
            }
            if error.status == 403 {
                return Ok(push_error(
                    403,
                    "access_denied",
                    "The sender is not allowed",
                    &[],
                ));
            }
            return Err(error);
        }
        if let Some(stored) = source.get("pushTokenHash") {
            let authorization =
                header_value(request.headers(), "authorization").unwrap_or_default();
            let presented = BEARER
                .captures(&authorization)
                .and_then(|captures| captures.get(1).map(|token| token.as_str().to_owned()));
            let valid = match (presented, stored.as_str()) {
                (Some(presented), Some(stored)) => same_hash(&hash(&presented), stored),
                _ => false,
            };
            if !valid {
                return Ok(push_error(
                    401,
                    "authentication_failed",
                    "The bearer token is missing or invalid",
                    &[("www-authenticate", "Bearer".to_owned())],
                ));
            }
        }
        let body = request.body();
        if body.len() > MAX_PUSH_BYTES {
            return Ok(push_error(
                413,
                "invalid_request",
                "The request body is too large",
                &[],
            ));
        }
        let body = String::from_utf8_lossy(body).into_owned();
        match self.accept(ctx, &source, &Value::String(body)).await {
            Ok(_) => {}
            Err(AcceptError::Rejected(error)) => {
                if error.temporary {
                    return Ok(push_error(
                        503,
                        error.err,
                        &error.description,
                        &[("retry-after", "30".to_owned())],
                    ));
                }
                return Ok(push_error(400, error.err, &error.description, &[]));
            }
            Err(AcceptError::Failed(error)) => return Err(error),
        }
        Ok(http::Response::builder()
            .status(202)
            .header("cache-control", "no-store")
            .body(Bytes::new())
            .unwrap_or_else(|_| HttpResponse::new(Bytes::new())))
    }

    /// One RFC 8936 poll request: acknowledgements and errors out, `{ sets, moreAvailable }` back.
    async fn poll_request(
        &self,
        source: &Record,
        token: &str,
        body: &Value,
    ) -> Result<PollAnswer, PollFailure> {
        let endpoint = source
            .get("poll")
            .and_then(|poll| poll.get("endpoint"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        let request = FetchRequest::new(
            endpoint,
            "POST",
            Some(FetchBody::Text(core_js::stringify(body))),
        )
        .redirect(RedirectMode::Error)
        .header("content-type", "application/json")
        .header("accept", "application/json")
        .header("authorization", format!("Bearer {token}"))
        .header("user-agent", "better-iam-signals/1");
        let deadline = tokio::time::Instant::now() + Duration::from_millis(POLL_TIMEOUT_MS);
        let response = tokio::time::timeout_at(deadline, self.poll_fetch.fetch(request)).await;
        let mut response = match response {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => {
                return Err(PollFailure(match error.refusal() {
                    Some(refusal) => format!(
                        "The poll endpoint was refused ({})",
                        refusal.reason.as_str()
                    ),
                    None => "The poll endpoint could not be reached".to_owned(),
                }));
            }
            Err(_) => {
                return Err(PollFailure(
                    "The poll endpoint could not be reached".to_owned(),
                ));
            }
        };
        if response.status != 200 {
            response.body.cancel();
            return Err(PollFailure(format!(
                "The poll endpoint answered {}",
                response.status
            )));
        }
        let parsed = match tokio::time::timeout_at(deadline, response.body.text()).await {
            Ok(Ok(text)) => core_js::parse(&text).ok(),
            _ => None,
        };
        let unreadable = || PollFailure("The poll endpoint sent an unreadable response".to_owned());
        let Some(Value::Object(parsed)) = parsed else {
            return Err(unreadable());
        };
        let sets = parsed.get("sets");
        let more = parsed.get("moreAvailable");
        if (sets.is_some() && plain(sets).is_none()) || more.is_some_and(|more| !more.is_boolean())
        {
            return Err(unreadable());
        }
        let sets = plain(sets)
            .map(|sets| {
                core_js::entries(sets)
                    .into_iter()
                    .map(|(jti, set)| (jti.clone(), set.clone()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(PollAnswer {
            sets,
            more_available: more == Some(&Value::Bool(true)),
        })
    }

    /// Stores the acknowledgements and errors the next request carries, and the poll outcome.
    async fn poll_bookkeeping(
        &self,
        ctx: &Arc<ServerContext>,
        source_id: &str,
        endpoint: &str,
        acks: &[String],
        set_errs: &Map<String, Value>,
        failure: Option<&str>,
    ) -> IamResult<()> {
        ctx.store
            .transaction(|tx| async move {
                let Some(mut current) = tx.get(SOURCES_COLLECTION, source_id).await? else {
                    return Ok(());
                };
                // A source deleted, switched to another endpoint or turned into a push source meanwhile keeps its
                // own state.
                let Some(Value::Object(mut state)) = current.get("poll").cloned() else {
                    return Ok(());
                };
                if state.get("endpoint").and_then(Value::as_str) != Some(endpoint) {
                    return Ok(());
                }
                let now = ctx.now();
                state.shift_remove("pendingErrors");
                state.insert(
                    "pendingAcks".into(),
                    Value::Array(acks.iter().cloned().map(Value::String).collect()),
                );
                if !set_errs.is_empty() {
                    state.insert("pendingErrors".into(), Value::Object(set_errs.clone()));
                }
                state.insert("lastPolledAt".into(), number(now));
                current.insert("poll".into(), Value::Object(state));
                if let Some(failure) = failure.filter(|failure| !failure.is_empty()) {
                    current.insert(
                        "lastError".into(),
                        json!({ "at": number(now), "message": failure }),
                    );
                }
                tx.put(SOURCES_COLLECTION, &current).await?;
                Ok(())
            })
            .await
    }

    async fn poll_source(
        self: &Arc<Self>,
        ctx: &Arc<ServerContext>,
        source: &Record,
        result: &mut SignalPollResult,
    ) -> IamResult<()> {
        let source_id = record_id(source).to_owned();
        let state = source.get("poll").cloned().unwrap_or(Value::Null);
        let Ok(token) = open_poll_token(ctx, source) else {
            result.errors += 1.0;
            self.note_error(
                ctx,
                &source_id,
                "The poll token cannot be opened: it was sealed with a secret that is gone",
            )
            .await;
            return Ok(());
        };
        let endpoint = state
            .get("endpoint")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let max_events = state.get("maxEvents").cloned().unwrap_or(Value::Null);
        let mut acks: Vec<String> = strings_of(state.get("pendingAcks"));
        let mut set_errs: Map<String, Value> = plain(state.get("pendingErrors"))
            .cloned()
            .unwrap_or_default();
        for _ in 0..POLL_REQUESTS_PER_RUN {
            let mut body = Map::new();
            body.insert("maxEvents".into(), max_events.clone());
            body.insert("returnImmediately".into(), Value::Bool(true));
            body.insert(
                "ack".into(),
                Value::Array(acks.iter().cloned().map(Value::String).collect()),
            );
            if !set_errs.is_empty() {
                body.insert("setErrs".into(), Value::Object(set_errs.clone()));
            }
            let answer = match self
                .poll_request(source, &token, &Value::Object(body))
                .await
            {
                Ok(answer) => answer,
                Err(PollFailure(message)) => {
                    result.errors += 1.0;
                    self.poll_bookkeeping(
                        ctx,
                        &source_id,
                        &endpoint,
                        &acks,
                        &set_errs,
                        Some(&message),
                    )
                    .await?;
                    return Ok(());
                }
            };
            // The transmitter answered, so it has the acknowledgements and errors this request carried.
            result.acknowledged += acks.len() as f64;
            acks.clear();
            set_errs = Map::new();
            let end = slice_end(core_js::as_number(&max_events), answer.sets.len());
            for (jti, set) in answer.sets.into_iter().take(end) {
                if jti.is_empty() || core_js::utf16_len(&jti) > 512 {
                    continue;
                }
                let step = async {
                    let claims = self
                        .verify(ctx, source, &set)
                        .await
                        .map_err(AcceptError::Rejected)?;
                    if claims.jti != jti {
                        return Err(AcceptError::Rejected(SignalRejectedError::new(
                            "invalid_request",
                            "The token jti does not match its key in sets",
                        )));
                    }
                    process_signal(ctx, &source_id, &claims)
                        .await
                        .map_err(AcceptError::Failed)
                };
                match step.await {
                    Ok(receipt) => {
                        // Acknowledged with the next request, now that the event is committed.
                        acks.push(jti);
                        if !receipt.duplicate {
                            result.received += 1.0;
                        }
                    }
                    Err(AcceptError::Rejected(error)) if !error.temporary => {
                        set_errs.insert(
                            jti,
                            json!({ "err": error.err, "description": error.description }),
                        );
                        self.note_error(
                            ctx,
                            &source_id,
                            &format!("Refused an event: {}", error.description),
                        )
                        .await;
                    }
                    Err(AcceptError::Failed(error)) if error.status == 404 => {
                        // The source was deleted or disabled while polling: stop without touching its state.
                        return Ok(());
                    }
                    Err(_) => result.errors += 1.0,
                }
            }
            self.poll_bookkeeping(ctx, &source_id, &endpoint, &acks, &set_errs, None)
                .await?;
            if !answer.more_available {
                break;
            }
        }
        Ok(())
    }

    /// Polls every active poll source (or one).
    pub async fn poll(
        self: &Arc<Self>,
        ctx: &Arc<ServerContext>,
        source_id: Option<&Value>,
    ) -> IamResult<SignalPollResult> {
        let mut result = SignalPollResult {
            sources: 0.0,
            received: 0.0,
            acknowledged: 0.0,
            errors: 0.0,
            extra: Map::new(),
        };
        let mut candidates: Vec<Record> = match source_id {
            Some(source_id) => {
                let Some(source_id) = source_id.as_str().filter(|id| source_id_shaped(id)) else {
                    return Err(IamError::new("INVALID_INPUT", "Invalid sourceId"));
                };
                self.active_source(ctx, source_id)
                    .await?
                    .into_iter()
                    .collect()
            }
            None => {
                ctx.store
                    .find(
                        SOURCES_COLLECTION,
                        &Filter::new().eq("delivery", "poll").eq("status", "active"),
                        &FindOptions::default(),
                    )
                    .await?
            }
        };
        candidates.sort_by(|a, b| by_id(record_id(a), record_id(b)));
        for candidate in candidates {
            if str_member(&candidate, "delivery") != Some("poll")
                || str_member(&candidate, "status") != Some("active")
                || !crate::js::truthy(candidate.get("poll"))
            {
                continue;
            }
            // Re-read under the tenant checks: a whole-collection scan also lists sources of suspended tenants.
            let source = if source_id.is_none() {
                self.active_source(ctx, record_id(&candidate)).await?
            } else {
                Some(candidate)
            };
            let Some(source) = source else {
                continue;
            };
            if !crate::js::truthy(source.get("poll"))
                || str_member(&source, "delivery") != Some("poll")
            {
                continue;
            }
            result.sources += 1.0;
            self.poll_source(ctx, &source, &mut result).await?;
        }
        Ok(result)
    }

    /// Drops the cached keys of a source (after an update or deletion).
    pub fn forget(&self, source_id: &str) {
        lock(&self.cache).shift_remove(source_id);
    }
}

/// `array.slice(0, end).length` for a JavaScript number `end`.
fn slice_end(end: Option<f64>, length: usize) -> usize {
    let end = match end {
        Some(end) if !end.is_nan() => end.trunc(),
        _ => 0.0,
    };
    if end < 0.0 {
        (length as f64 + end).max(0.0) as usize
    } else {
        end.min(length as f64) as usize
    }
}

/// Why accepting a SET failed: a refused token, or processing that failed (NOT_FOUND, storage contention).
#[derive(Debug, Clone)]
pub enum AcceptError {
    Rejected(SignalRejectedError),
    Failed(IamError),
}

impl From<AcceptError> for IamError {
    fn from(error: AcceptError) -> Self {
        match error {
            AcceptError::Rejected(error) => error.into(),
            AcceptError::Failed(error) => error,
        }
    }
}

/// Receivers already created, per context (the TypeScript WeakMap): an entry ends with its context.
type ReceiverEntry = (Weak<ServerContext>, Arc<SignalReceiver>);
static RECEIVERS: Mutex<Vec<ReceiverEntry>> = Mutex::new(Vec::new());

/// The deployment's signal receiver (one per server context, created on first use).
pub fn signal_receiver_of(ctx: &Arc<ServerContext>) -> IamResult<Arc<SignalReceiver>> {
    let mut entries = lock(&RECEIVERS);
    entries.retain(|(weak, _)| weak.strong_count() > 0);
    if let Some((_, receiver)) = entries
        .iter()
        .find(|(weak, _)| weak.upgrade().is_some_and(|live| Arc::ptr_eq(&live, ctx)))
    {
        return Ok(receiver.clone());
    }
    let receiver = Arc::new(create_signal_receiver(ctx));
    entries.push((Arc::downgrade(ctx), receiver.clone()));
    Ok(receiver)
}

/// Verifies a compact SET for a source (see [`SignalReceiver::verify`]).
pub async fn verify_signal(
    ctx: &Arc<ServerContext>,
    source: &Record,
    set: &Value,
) -> IamResult<SecurityEventClaims> {
    signal_receiver_of(ctx)?
        .verify(ctx, source, set)
        .await
        .map_err(IamError::from)
}

/// The RFC 8935 push endpoint, `POST {signals.pushPath}/{sourceId}` (default `{basePath}/signals/push/{sourceId}`),
/// mounted beside the HTTP API: `application/secevent+jwt` bodies of at most 64 KiB, rate limited per source, the
/// source's bearer token when it has one, then verification and processing. Answers 202 with no body, or `{ err,
/// description }`: 400 for a refused SET, 401 for a bad bearer token, 404 for an unknown, disabled or poll source,
/// 405, 413, 415, 429, and 503 while the source's keys cannot be fetched. Other paths pass through.
pub fn create_signals_protocol(
    ctx: &Arc<ServerContext>,
) -> IamResult<Arc<dyn crate::options::ProtocolMount>> {
    Ok(Arc::new(SignalsProtocol {
        ctx: Arc::downgrade(ctx),
    }))
}

/// The push endpoint's protocol mount (it holds its context weakly: the context keeps its mounts).
struct SignalsProtocol {
    ctx: Weak<ServerContext>,
}

#[async_trait::async_trait]
impl crate::options::ProtocolMount for SignalsProtocol {
    async fn handle(&self, request: &HttpRequest) -> IamResult<Option<HttpResponse>> {
        let Some(ctx) = self.ctx.upgrade() else {
            return Ok(None);
        };
        Ok(signal_receiver_of(&ctx)?.handle(&ctx, request).await)
    }
}

/// `iam.signals`: the poll job and in-process delivery.
pub struct SignalsRuntime {
    ctx: Arc<ServerContext>,
}

/// `createSignalsRuntime(ctx)`.
pub fn create_signals_runtime(ctx: &Arc<ServerContext>) -> IamResult<SignalsRuntime> {
    Ok(SignalsRuntime { ctx: ctx.clone() })
}

impl SignalsRuntime {
    /// Polls every active poll source (or one): acknowledges what earlier runs committed, then fetches, verifies and
    /// records events, following `moreAvailable` for at most five requests per source. A scheduler job; run it every
    /// minute or so. `input` is `{ sourceId? }`.
    pub async fn poll(
        &self,
        input: Option<&Value>,
    ) -> IamResult<crate::signal_receiver::SignalPollResult> {
        let source_id = match input {
            Some(Value::Null) => return Err(crate::js::internal_error()),
            Some(Value::Object(input)) => input.get("sourceId"),
            _ => None,
        };
        signal_receiver_of(&self.ctx)?
            .poll(&self.ctx, source_id)
            .await
    }

    /// Verifies and records one compact security event token for a source, as the push endpoint does: for custom
    /// transports and tests. Fails with `SIGNAL_REJECTED` for a refused token and NOT_FOUND for an unknown or disabled
    /// source. Answers the receipt (`{ eventId, status, duplicate, identityId? }`).
    pub async fn receive(&self, source_id: &str, set: &str) -> IamResult<Value> {
        self.receive_value(
            Some(&Value::String(source_id.to_owned())),
            Some(&Value::String(set.to_owned())),
        )
        .await
    }

    async fn receive_value(
        &self,
        source_id: Option<&Value>,
        set: Option<&Value>,
    ) -> IamResult<Value> {
        let Some(source_id) = source_id
            .and_then(Value::as_str)
            .filter(|source_id| source_id_shaped(source_id))
        else {
            return Err(source_gone());
        };
        let ctx = &self.ctx;
        let receiver = signal_receiver_of(ctx)?;
        let source = ctx
            .store
            .transaction(|tx| async move { live_source(ctx, &tx, source_id).await })
            .await?;
        let set = set.cloned().unwrap_or(Value::Null);
        let receipt = receiver.accept(ctx, &source, &set).await?;
        Ok(receipt.to_value())
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "poll" => Some(
                self.poll(args.first())
                    .await
                    .map(|result| result.to_value()),
            ),
            "receive" => Some(self.receive_value(args.first(), args.get(1)).await),
            _ => None,
        }
    }
}
