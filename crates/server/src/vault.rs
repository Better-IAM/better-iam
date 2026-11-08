//! Port of `packages/server/src/vault.ts`.
//!
//! The secrets vault: tenant-scoped secrets with versions, stage labels, rotation, check-out leases for shared
//! privileged credentials, and dynamic secrets minted per caller by an engine. Values are sealed at rest with the
//! deployment secret (AES-256-GCM, bound to tenant, secret, and version) and leave storage only through `reveal`, a
//! check-out, a lease, or the trusted `iam.vault` runtime. Access is decided like every administrative action:
//! `iam:vault:*` on `iam/vault/secrets/{name}`, where the secret's tags and settings are resource attributes. The
//! API lives in api/vault.rs.

use std::future::Future;
use std::sync::{Arc, LazyLock};

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use better_iam_core::{
    AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, Record, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::{
    MAX_SAFE_INTEGER, cmp_utf16, internal_error, invalid_config, invalid_input, is_function,
    is_safe_integer, js_string, number_to_string, utf16_len,
};
use crate::options::{VaultEngine, VaultRotator};
use crate::port::{decode, encode};
use crate::utils::id;
use crate::validation::{integer, object, text};

/// The resource ID prefix of secrets: `iam/vault/secrets/{name}` in policies.
pub const SECRET_RESOURCE_PREFIX: &str = "vault/secrets/";

pub const MINUTE: f64 = 60_000.0;
pub const HOUR: f64 = 60.0 * MINUTE;
pub const DAY: f64 = 24.0 * HOUR;

/// `'text' | 'json'`.
pub type SecretFormat = String;

/// `'static' | 'dynamic'`.
pub type SecretKind = String;

/// Who a value is encrypted or opened for: recorded on the customer-managed key's `iam:kms:*` audit events. An
/// absent use (`undefined` in TypeScript) is `None` where a function takes one.
pub type ValueUse = AuthenticatedPrincipal;

/// `'reveal' | 'checkout' | 'checkin' | 'lease' | 'renew' | 'revoke' | 'put' | 'rotate' | 'share'`.
pub type VaultAccessAction = String;

/// How generated values look: rotation and `create({ generate })` draw them from the system's CSPRNG.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasswordGenerator {
    /// 8-256 characters.
    #[serde(rename = "length")]
    pub length: f64,
    #[serde(rename = "charset")]
    pub charset: String,
    /// Characters never used (a target system that rejects some symbols, say).
    #[serde(rename = "exclude", default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<String>,
    /// At least one character of each class the charset keeps (lowercase, uppercase, digits, symbols).
    #[serde(rename = "eachClass")]
    pub each_class: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The last failed rotation attempt (`SecretRotation.lastFailure`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RotationFailure {
    #[serde(rename = "at")]
    pub at: f64,
    #[serde(rename = "message")]
    pub message: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `SecretRotation`, with members in the order the vault writes them.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecretRotation {
    /// Rotate automatically this many days after the last rotation (`iam.vault.rotateDue`); absent: on demand only.
    #[serde(
        rename = "intervalDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub interval_days: Option<f64>,
    /// The name of a rotator in the `vault.rotators` option that applies new values to the system they unlock.
    #[serde(rename = "rotator", default, skip_serializing_if = "Option::is_none")]
    pub rotator: Option<String>,
    /// Generates the next value; absent with a rotator means the default generator.
    #[serde(rename = "generator", default, skip_serializing_if = "Option::is_none")]
    pub generator: Option<PasswordGenerator>,
    /// For `json` secrets: the field the generated value replaces (the rest is carried over).
    #[serde(rename = "field", default, skip_serializing_if = "Option::is_none")]
    pub field: Option<String>,
    #[serde(
        rename = "lastRotatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_rotated_at: Option<f64>,
    #[serde(
        rename = "nextRotationAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_rotation_at: Option<f64>,
    /// The last attempt failed; the pending version stays staged and the next attempt retries it.
    #[serde(
        rename = "lastFailure",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_failure: Option<RotationFailure>,
    #[serde(rename = "failures", default, skip_serializing_if = "Option::is_none")]
    pub failures: Option<f64>,
    /// When the manual-rotation reminder for the current due date was recorded (no generator and no rotator).
    #[serde(
        rename = "dueNotifiedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub due_notified_at: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Check-out rules for shared privileged credentials (the "password vault" of privileged access management).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckoutPolicy {
    /// The value is handed out only through a check-out (reveal is refused with CHECKOUT_REQUIRED).
    #[serde(rename = "required")]
    pub required: bool,
    /// One holder at a time; others get SECRET_CHECKED_OUT until it is checked in or expires.
    #[serde(rename = "exclusive")]
    pub exclusive: bool,
    /// Longest check-out (1 minute to 24 hours).
    #[serde(rename = "maxDurationMs")]
    pub max_duration_ms: f64,
    /// Rotate the value when a check-out ends, so a returned password stops working.
    #[serde(rename = "rotateOnCheckin")]
    pub rotate_on_checkin: bool,
    /// A check-out must say why (kept with the lease and in the audit log).
    #[serde(rename = "requireReason")]
    pub require_reason: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Lease lengths of a dynamic secret.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LeaseSettings {
    #[serde(rename = "defaultTtlMs")]
    pub default_ttl_ms: f64,
    #[serde(rename = "maxTtlMs")]
    pub max_ttl_ms: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultSecret {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    /// The name: unique per tenant.
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "kind")]
    pub kind: crate::vault::SecretKind,
    #[serde(rename = "format")]
    pub format: crate::vault::SecretFormat,
    #[serde(rename = "tags")]
    pub tags: IndexMap<String, String>,
    #[serde(rename = "status")]
    pub status: String,
    /// Stage labels and the version each points at; `current` is what callers get by default.
    #[serde(rename = "stages")]
    pub stages: IndexMap<String, f64>,
    #[serde(rename = "latestVersion")]
    pub latest_version: f64,
    #[serde(rename = "maxVersions")]
    pub max_versions: f64,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Dynamic secrets: the engine (from the `vault.engines` option) and its configuration.
    #[serde(rename = "engine", default, skip_serializing_if = "Option::is_none")]
    pub engine: Option<String>,
    #[serde(
        rename = "engineConfig",
        default,
        deserialize_with = "present_json",
        skip_serializing_if = "Option::is_none"
    )]
    pub engine_config: Option<Value>,
    #[serde(rename = "lease", default, skip_serializing_if = "Option::is_none")]
    pub lease: Option<crate::vault::LeaseSettings>,
    #[serde(rename = "rotation", default, skip_serializing_if = "Option::is_none")]
    pub rotation: Option<crate::vault::SecretRotation>,
    #[serde(rename = "checkout", default, skip_serializing_if = "Option::is_none")]
    pub checkout: Option<crate::vault::CheckoutPolicy>,
    /// A customer-managed key (a tenant KMS encryption key's id): new versions are encrypted under it instead of the
    /// deployment secret, and disabling the key makes every such version unreadable.
    #[serde(rename = "kmsKeyId", default, skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
    /// When a pending deletion becomes final (`iam.vault.purgeDeleted`).
    #[serde(
        rename = "deletionAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deletion_at: Option<f64>,
    #[serde(
        rename = "deletionRequestedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deletion_requested_by: Option<String>,
    /// The pending version a rotation staged and has not completed. Only this version is handed to the rotator again on
    /// a retry; a `pending` label set by `put` or `setStage` is never applied to the target system.
    #[serde(
        rename = "rotationPending",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rotation_pending: Option<f64>,
    #[serde(
        rename = "lastAccessedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_accessed_at: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A member that may hold any JSON value, `null` included: present (even as `null`) is `Some`, absent is `None`.
fn present_json<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

/// A version of a secret, with members in the order `addVersion` writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultVersion {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "uniqueKey")]
    pub unique_key: String,
    #[serde(rename = "secretId")]
    pub secret_id: String,
    #[serde(rename = "version")]
    pub version: f64,
    #[serde(rename = "state")]
    pub state: String,
    #[serde(rename = "source")]
    pub source: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    /// Absent once destroyed: sealed with the deployment secret, or a KMS ciphertext when `kmsKeyId` is set.
    #[serde(rename = "sealed", default, skip_serializing_if = "Option::is_none")]
    pub sealed: Option<String>,
    /// The customer-managed key the value is encrypted under.
    #[serde(rename = "kmsKeyId", default, skip_serializing_if = "Option::is_none")]
    pub kms_key_id: Option<String>,
    #[serde(
        rename = "disabledAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub disabled_at: Option<f64>,
    #[serde(
        rename = "destroyedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub destroyed_at: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultLease {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "secretId")]
    pub secret_id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "holderId")]
    pub holder_id: String,
    #[serde(rename = "sessionId", default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// A lease an agent took for a person in a delegated session: the agent and the delegation. The lease ends when the
    /// delegation does or the agent may no longer act (`iam.vault.expireLeases`).
    #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(
        rename = "delegationId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub delegation_id: Option<String>,
    /// The version a check-out handed out.
    #[serde(rename = "version", default, skip_serializing_if = "Option::is_none")]
    pub version: Option<f64>,
    #[serde(rename = "reason", default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(rename = "state")]
    pub state: String,
    #[serde(rename = "issuedAt")]
    pub issued_at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    /// Renewals never extend a lease past this.
    #[serde(rename = "maxExpiresAt")]
    pub max_expires_at: f64,
    /// The length the lease was issued for; a renewal without `ttlMs` extends by this much.
    #[serde(rename = "ttlMs", default, skip_serializing_if = "Option::is_none")]
    pub ttl_ms: Option<f64>,
    #[serde(rename = "endedAt", default, skip_serializing_if = "Option::is_none")]
    pub ended_at: Option<f64>,
    #[serde(rename = "endedBy", default, skip_serializing_if = "Option::is_none")]
    pub ended_by: Option<String>,
    /// The engine's revocation handle, sealed.
    #[serde(
        rename = "handleSealed",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub handle_sealed: Option<String>,
    #[serde(
        rename = "revokeAttempts",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revoke_attempts: Option<f64>,
    /// When the first revocation attempt failed; revocations are retried with backoff for seven days from then.
    #[serde(
        rename = "revokeStartedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub revoke_started_at: Option<f64>,
    /// The next revocation retry is not before this.
    #[serde(rename = "retryAt", default, skip_serializing_if = "Option::is_none")]
    pub retry_at: Option<f64>,
    /// The state a revocation in progress (`revoking`) ends the lease in.
    #[serde(rename = "endState", default, skip_serializing_if = "Option::is_none")]
    pub end_state: Option<String>,
    #[serde(rename = "lastError", default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One use of a secret, kept `accessRetentionDays` (default 90) for the per-secret access log. Members are in the
/// order `recordAccess` writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VaultAccessRecord {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "secretId")]
    pub secret_id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "action")]
    pub action: crate::vault::VaultAccessAction,
    #[serde(rename = "version", default, skip_serializing_if = "Option::is_none")]
    pub version: Option<f64>,
    #[serde(rename = "leaseId", default, skip_serializing_if = "Option::is_none")]
    pub lease_id: Option<String>,
    #[serde(
        rename = "sessionKind",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub session_kind: Option<String>,
    #[serde(rename = "agentId", default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<String>,
    #[serde(rename = "at")]
    pub at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    /// Optional database-enforced natural key, unique within collection and tenant.
    #[serde(rename = "uniqueKey", default, skip_serializing_if = "Option::is_none")]
    pub unique_key: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What an engine's `issue` returns (`EngineIssued`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EngineIssued {
    /// The credential, for `text` secrets.
    #[serde(rename = "value", default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// The credential's fields (`username`, `password`, ...), for `json` secrets.
    #[serde(rename = "fields", default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<IndexMap<String, better_iam_core::Json>>,
    /// Opaque data `revoke` and `renew` receive back (at most 4096 characters); sealed at rest.
    #[serde(rename = "handle", default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What `addVersion` returns: the secret with its new `latestVersion` (not stored yet) and the stored version.
#[derive(Debug, Clone, PartialEq)]
pub struct AddedVersion {
    pub secret: VaultSecret,
    pub version: VaultVersion,
}

/// One entry of the per-secret access log, as `recordAccess` takes it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct AccessEntry {
    pub identity_id: String,
    pub action: VaultAccessAction,
    pub version: Option<f64>,
    pub lease_id: Option<String>,
    pub session_kind: Option<String>,
    pub agent_id: Option<String>,
}

/// The secrets vault's collections.
pub static VAULT_COLLECTIONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"secrets":"vaultSecrets","versions":"vaultVersions","leases":"vaultLeases","access":"vaultAccess"}),
);

const SECRETS: &str = "vaultSecrets";
const VERSIONS: &str = "vaultVersions";
const LEASES: &str = "vaultLeases";
const ACCESS: &str = "vaultAccess";

pub fn secret_resource(name: &str) -> IamResult<String> {
    Ok(format!("{SECRET_RESOURCE_PREFIX}{name}"))
}

/// The audit actor of the scheduler jobs, as elsewhere.
pub const VAULT_OPERATOR: &str = "deployment-operator";

// --- options -------------------------------------------------------------------------------------

/// The validated `vault` option.
#[derive(Clone)]
pub struct VaultSettings {
    pub rotators: IndexMap<String, Arc<dyn VaultRotator>>,
    pub engines: IndexMap<String, Arc<dyn VaultEngine>>,
    pub max_value_bytes: f64,
    pub max_secrets_per_tenant: f64,
    pub access_retention_ms: f64,
    pub call_timeout_ms: f64,
}

static PLUGIN_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9-]{0,63}$").expect("plugin name pattern"));

/// The validated `vault` option (INVALID_CONFIG on a bad value). The option is read as the TypeScript validator sees
/// it (the options model, where callbacks are function markers); the rotators and engines themselves come from the
/// typed options. TypeScript caches the result per options object; validating again gives the same answer.
pub fn vault_settings(ctx: &ServerContext) -> IamResult<VaultSettings> {
    let model = crate::options_value::options_value(&ctx.options);
    let empty = Value::Object(Map::new());
    // `options.vault ?? {}`.
    let raw = match model.get("vault") {
        None | Some(Value::Null) => &empty,
        Some(value) => value,
    };
    let input = match raw {
        Value::Object(map) if !is_function(Some(raw)) => map,
        _ => return Err(invalid_config("vault must be an options object")),
    };
    let bounded = |value: Option<&Value>, fallback: f64, min: f64, max: f64, name: &str| {
        let Some(value) = value else {
            return Ok(fallback);
        };
        match core_js::as_number(value) {
            Some(number) if is_safe_integer(number) && number >= min && number <= max => Ok(number),
            _ => Err(invalid_config(format!(
                "vault.{name} must be an integer from {} to {}",
                number_to_string(min),
                number_to_string(max)
            ))),
        }
    };
    let named = |value: Option<&Value>, name: &str, method: &str| -> IamResult<Vec<String>> {
        let Some(value) = value else {
            return Ok(Vec::new());
        };
        let map = match value {
            Value::Object(map) if !is_function(Some(value)) => map,
            _ => return Err(invalid_config(format!("vault.{name} must be an object"))),
        };
        let mut names = Vec::new();
        for (key, item) in core_js::entries(map) {
            if !PLUGIN_NAME.is_match(key) {
                return Err(invalid_config(format!(
                    "vault.{name} keys must be lowercase identifiers"
                )));
            }
            if !crate::js::truthy(Some(item)) || !is_function(crate::js::member(Some(item), method))
            {
                return Err(invalid_config(format!(
                    "vault.{name}.{key} must have a {method} function"
                )));
            }
            names.push(key.clone());
        }
        Ok(names)
    };
    let rotator_names = named(input.get("rotators"), "rotators", "rotate")?;
    let engine_names = named(input.get("engines"), "engines", "issue")?;
    let typed = ctx.options.vault.as_ref();
    let mut rotators = IndexMap::new();
    for name in rotator_names {
        if let Some(rotator) = typed
            .and_then(|vault| vault.rotators.as_ref())
            .and_then(|rotators| rotators.get(&name))
        {
            rotators.insert(name, rotator.clone());
        }
    }
    let mut engines = IndexMap::new();
    for name in engine_names {
        if let Some(engine) = typed
            .and_then(|vault| vault.engines.as_ref())
            .and_then(|engines| engines.get(&name))
        {
            engines.insert(name, engine.clone());
        }
    }
    Ok(VaultSettings {
        rotators,
        engines,
        max_value_bytes: bounded(
            input.get("maxValueBytes"),
            65536.0,
            16.0,
            1048576.0,
            "maxValueBytes",
        )?,
        max_secrets_per_tenant: bounded(
            input.get("maxSecretsPerTenant"),
            1000.0,
            1.0,
            100000.0,
            "maxSecretsPerTenant",
        )?,
        access_retention_ms: bounded(
            input.get("accessRetentionDays"),
            90.0,
            1.0,
            3650.0,
            "accessRetentionDays",
        )? * DAY,
        call_timeout_ms: bounded(
            input.get("callTimeoutMs"),
            30_000.0,
            1000.0,
            300_000.0,
            "callTimeoutMs",
        )?,
    })
}

// --- validation ----------------------------------------------------------------------------------

static SEGMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$").expect("segment pattern"));

/// A secret name: 1-16 `/`-separated segments of letters, digits and `_.-` (not starting with `.` or `-`).
pub fn secret_name(value: Option<&Value>) -> IamResult<String> {
    let name = text(value, "name", 256)?;
    let parts: Vec<&str> = name.split('/').collect();
    if parts.len() > 16 || !parts.iter().all(|part| SEGMENT.is_match(part)) {
        return Err(invalid_input(
            "Secret names are 1-16 segments of letters, digits and _.- (not starting with . or -) separated by /",
        ));
    }
    Ok(name)
}

/// A listing prefix: a name prefix, optionally ending in `/`; the empty string lists everything.
pub fn secret_prefix(value: Option<&Value>) -> IamResult<String> {
    match value {
        None => return Ok(String::new()),
        Some(Value::String(text)) if text.is_empty() => return Ok(String::new()),
        _ => {}
    }
    let prefix = text(value, "prefix", 256)?;
    let trimmed = prefix.strip_suffix('/').unwrap_or(&prefix);
    if !trimmed.is_empty() {
        secret_name(Some(&Value::String(trimmed.to_owned())))?;
    }
    Ok(prefix)
}

static TAG_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z][a-zA-Z0-9_-]{0,63}$").expect("tag key pattern"));

/// Up to 20 tags; keys are identifiers, values 1-256 printable characters.
pub fn secret_tags(value: Option<&Value>) -> IamResult<IndexMap<String, String>> {
    if value.is_none() {
        return Ok(IndexMap::new());
    }
    let input = object(value)?;
    let mut entries = core_js::entries(input);
    if entries.len() > 20 {
        return Err(invalid_input("A secret has at most 20 tags"));
    }
    entries.sort_by(|(a, _), (b, _)| cmp_utf16(a, b));
    let mut tags = IndexMap::new();
    for (key, item) in entries {
        if !TAG_KEY.is_match(key) {
            return Err(invalid_input(format!("Invalid tag name {key}")));
        }
        tags.insert(key.clone(), text(Some(item), &format!("tag {key}"), 256)?);
    }
    Ok(tags)
}

static STAGE_LABEL: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9-]{0,31}$").expect("stage label pattern"));

/// Stage labels the vault moves itself.
/// A `Set` in TypeScript.
pub const SYSTEM_STAGES: &[&str] = &["current", "previous", "pending"];

pub fn stage_name(value: Option<&Value>) -> IamResult<String> {
    let label = text(value, "stage", 32)?;
    if !STAGE_LABEL.is_match(&label) {
        return Err(invalid_input(
            "Stage labels are 1-32 lowercase letters, digits or hyphens, starting with a letter",
        ));
    }
    Ok(label)
}

pub fn secret_format(value: Option<&Value>) -> IamResult<crate::vault::SecretFormat> {
    match value {
        None => Ok("text".to_owned()),
        Some(Value::String(format)) if format == "text" || format == "json" => Ok(format.clone()),
        _ => Err(invalid_input("format must be text or json")),
    }
}

/// The stored form of a value: the text itself, or for `json` secrets the object serialized (callers may pass it as
/// a JSON string or as `fields`). Refuses empty values and values over the size limit. `input` is the object holding
/// `value` and `fields`.
pub fn secret_value(settings: &VaultSettings, format: &str, input: &Value) -> IamResult<String> {
    let value = if let Some(fields) = input.get("fields") {
        if format != "json" {
            return Err(invalid_input(
                "fields are for json secrets; pass value instead",
            ));
        }
        core_js::stringify_object(object(Some(fields))?)
    } else {
        match input.get("value") {
            Some(Value::String(value)) if !value.is_empty() => value.clone(),
            _ => return Err(invalid_input("value must be a nonempty string")),
        }
    };
    if value.len() as f64 > settings.max_value_bytes {
        return Err(invalid_input(format!(
            "Secret values are at most {} bytes",
            number_to_string(settings.max_value_bytes)
        )));
    }
    if format == "json" {
        parse_fields(&value)?;
    }
    Ok(value)
}

static FIELD_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$").expect("field pattern"));
const RESERVED_FIELD_NAMES: &[&str] = &["__proto__", "constructor", "prototype"];

/// A json secret's field name: 1-64 letters, digits and `_.-`, never one that names an object's prototype.
pub fn field_name(value: Option<&Value>, name: &str) -> IamResult<String> {
    let field = text(value, name, 64)?;
    if !FIELD_NAME.is_match(&field) || RESERVED_FIELD_NAMES.contains(&field.as_str()) {
        return Err(invalid_input(format!(
            "{name} must be a field name of letters, digits and _.-"
        )));
    }
    Ok(field)
}

/// One field of a json secret's parsed value, own properties only.
pub fn own_field(
    fields: Option<&IndexMap<String, better_iam_core::Json>>,
    field: &str,
) -> IamResult<Option<Value>> {
    Ok(fields.and_then(|fields| fields.get(field)).cloned())
}

/// A json secret's fields; INVALID_INPUT when the value is not a JSON object.
pub fn parse_fields(value: &str) -> IamResult<IndexMap<String, better_iam_core::Json>> {
    let refuse = || invalid_input("json secrets hold a JSON object");
    match core_js::parse(value) {
        Ok(Value::Object(map)) => Ok(map.into_iter().collect()),
        _ => Err(refuse()),
    }
}

fn charset(name: &str) -> Option<&'static str> {
    match name {
        "alphanumeric" => Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        // Printable ASCII without space, quotes, backslash and backtick, which break shells and connection strings.
        "ascii" => Some(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~",
        ),
        "hex" => Some("0123456789abcdef"),
        "base64url" => Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"),
        "numeric" => Some("0123456789"),
        _ => None,
    }
}

/// `[/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/]`.
const CLASSES: [fn(char) -> bool; 4] = [
    |c| c.is_ascii_lowercase(),
    |c| c.is_ascii_uppercase(),
    |c| c.is_ascii_digit(),
    |c| !c.is_ascii_alphanumeric(),
];

pub static DEFAULT_GENERATOR: std::sync::LazyLock<PasswordGenerator> =
    std::sync::LazyLock::new(|| PasswordGenerator {
        length: 32.0,
        charset: "alphanumeric".to_owned(),
        exclude: None,
        each_class: true,
        extra: Map::new(),
    });

pub fn password_generator(value: Option<&Value>) -> IamResult<crate::vault::PasswordGenerator> {
    if value.is_none() || value == Some(&Value::Bool(true)) {
        return Ok(DEFAULT_GENERATOR.clone());
    }
    let input = object(value)?;
    let length = match input.get("length") {
        None => 32.0,
        Some(length) => integer(Some(length), "generator.length", 8.0, 256.0)?,
    };
    // `input.charset ?? 'alphanumeric'`, looked up as a property key.
    let charset_name = match input.get("charset") {
        None | Some(Value::Null) => "alphanumeric".to_owned(),
        Some(value) => js_string(Some(value)),
    };
    let each_class = match input.get("eachClass") {
        None => true,
        Some(value) => value == &Value::Bool(true),
    };
    if charset(&charset_name).is_none() {
        return Err(invalid_input(
            "generator.charset must be alphanumeric, ascii, hex, base64url or numeric",
        ));
    }
    if let Some(value) = input.get("eachClass")
        && !value.is_boolean()
    {
        return Err(invalid_input("generator.eachClass must be a boolean"));
    }
    let mut generator = PasswordGenerator {
        length,
        charset: charset_name,
        exclude: None,
        each_class,
        extra: Map::new(),
    };
    match input.get("exclude") {
        None => {}
        Some(Value::String(exclude)) if exclude.is_empty() => {}
        Some(exclude) => {
            generator.exclude = Some(text(Some(exclude), "generator.exclude", 64)?);
        }
    }
    if pool(&generator).len() < 10 {
        return Err(invalid_input(
            "The generator must keep at least 10 characters",
        ));
    }
    Ok(generator)
}

fn pool(generator: &PasswordGenerator) -> Vec<char> {
    let excluded: IndexSet<char> = generator
        .exclude
        .as_deref()
        .unwrap_or_default()
        .chars()
        .collect();
    charset(&generator.charset)
        .unwrap_or_default()
        .chars()
        .filter(|char| !excluded.contains(char))
        .collect()
}

/// `randomInt(max)`: a uniform integer in `[0, max)` from the system's CSPRNG.
fn random_int(max: usize) -> usize {
    let max = max as u64;
    // Rejection sampling over 64 bits, as Node's randomInt does over 48: no modulo bias.
    let limit = u64::MAX - (u64::MAX % max);
    loop {
        let bytes = better_iam_auth::crypto::random_bytes(8);
        let draw = u64::from_le_bytes(bytes.try_into().expect("8 random bytes"));
        if draw < limit {
            return (draw % max) as usize;
        }
    }
}

/// A random value from the generator: uniform draws, with one character of each kept class placed at random.
pub fn generate_value(generator: &crate::vault::PasswordGenerator) -> IamResult<String> {
    let characters = pool(generator);
    if characters.is_empty() {
        // `from[randomInt(0)]`: randomInt refuses an empty range.
        return Err(internal_error());
    }
    let draw = |from: &[char]| from[random_int(from.len())];
    let required: Vec<Vec<char>> = if generator.each_class {
        CLASSES
            .iter()
            .map(|class| characters.iter().copied().filter(|c| class(*c)).collect())
            .filter(|set: &Vec<char>| !set.is_empty())
            .collect()
    } else {
        Vec::new()
    };
    let mut result: Vec<char> = required.iter().map(|set| draw(set)).collect();
    while (result.len() as f64) < generator.length {
        result.push(draw(&characters));
    }
    // Fisher-Yates, so the required characters land anywhere.
    for index in (1..result.len()).rev() {
        let other = random_int(index + 1);
        result.swap(index, other);
    }
    Ok(result.into_iter().collect())
}

pub fn rotation_settings(
    settings: &VaultSettings,
    format: &str,
    value: Option<&Value>,
    previous: Option<&crate::vault::SecretRotation>,
) -> IamResult<Option<crate::vault::SecretRotation>> {
    let Some(value) = value else {
        return Ok(previous.cloned());
    };
    if value.is_null() {
        return Ok(None);
    }
    let input = object(Some(value))?;
    let defined = |key: &str| input.get(key).filter(|value| !value.is_null());
    let mut rotation = SecretRotation::default();
    if let Some(days) = defined("intervalDays") {
        rotation.interval_days = Some(integer(Some(days), "rotation.intervalDays", 1.0, 365.0)?);
    }
    if let Some(rotator) = defined("rotator") {
        let rotator = text(Some(rotator), "rotation.rotator", 64)?;
        if !settings.rotators.contains_key(&rotator) {
            return Err(invalid_input(format!("Unknown rotator {rotator}")));
        }
        rotation.rotator = Some(rotator);
    }
    if let Some(generator) = defined("generator").filter(|value| **value != Value::Bool(false)) {
        rotation.generator = Some(password_generator(Some(generator))?);
    }
    if let Some(field) = defined("field") {
        if format != "json" {
            return Err(invalid_input("rotation.field is for json secrets"));
        }
        rotation.field = Some(field_name(Some(field), "rotation.field")?);
    }
    if format == "json"
        && (rotation.generator.is_some() || rotation.rotator.is_some())
        && rotation.field.is_none()
    {
        return Err(invalid_input(
            "json secrets name the field rotation replaces (rotation.field)",
        ));
    }
    // History carries over; a new interval counts from the last rotation.
    if let Some(last) = previous.and_then(|previous| previous.last_rotated_at) {
        rotation.last_rotated_at = Some(last);
    }
    Ok(Some(rotation))
}

pub fn checkout_policy(
    value: Option<&Value>,
    previous: Option<&crate::vault::CheckoutPolicy>,
) -> IamResult<Option<crate::vault::CheckoutPolicy>> {
    let Some(value) = value else {
        return Ok(previous.cloned());
    };
    if value.is_null() {
        return Ok(None);
    }
    let input = object(Some(value))?;
    let flag = |key: &str, fallback: bool| match input.get(key) {
        None => Ok(fallback),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(invalid_input(format!("checkout.{key} must be a boolean"))),
    };
    Ok(Some(CheckoutPolicy {
        required: flag("required", true)?,
        exclusive: flag("exclusive", false)?,
        max_duration_ms: match input.get("maxDurationMs") {
            None => HOUR,
            Some(duration) => integer(Some(duration), "checkout.maxDurationMs", MINUTE, DAY)?,
        },
        rotate_on_checkin: flag("rotateOnCheckin", false)?,
        require_reason: flag("requireReason", false)?,
        extra: Map::new(),
    }))
}

pub fn lease_settings(
    value: Option<&Value>,
    previous: Option<&crate::vault::LeaseSettings>,
) -> IamResult<crate::vault::LeaseSettings> {
    if value.is_none()
        && let Some(previous) = previous
    {
        return Ok(previous.clone());
    }
    let empty = Map::new();
    let input = match value {
        None => &empty,
        Some(_) => object(value)?,
    };
    let default_ttl_ms = match input.get("defaultTtlMs") {
        None => HOUR,
        Some(ttl) => integer(Some(ttl), "lease.defaultTtlMs", MINUTE, 30.0 * DAY)?,
    };
    let max_ttl_ms = match input.get("maxTtlMs") {
        None => DAY.max(default_ttl_ms),
        Some(ttl) => integer(Some(ttl), "lease.maxTtlMs", MINUTE, 30.0 * DAY)?,
    };
    if default_ttl_ms > max_ttl_ms {
        return Err(invalid_input(
            "lease.defaultTtlMs must not exceed lease.maxTtlMs",
        ));
    }
    Ok(LeaseSettings {
        default_ttl_ms,
        max_ttl_ms,
        extra: Map::new(),
    })
}

/// Engine configuration: any JSON value up to 8 KiB.
pub fn engine_config(value: Option<&Value>) -> IamResult<better_iam_core::Json> {
    let Some(value) = value else {
        return Ok(Value::Object(Map::new()));
    };
    // `JSON.stringify` of a function is undefined.
    if is_function(Some(value)) {
        return Err(invalid_input("engineConfig must be JSON of at most 8 KiB"));
    }
    let serialized = core_js::stringify(value);
    if utf16_len(&serialized) > 8192 {
        return Err(invalid_input("engineConfig must be JSON of at most 8 KiB"));
    }
    core_js::parse(&serialized).map_err(|_| invalid_input("engineConfig must be JSON"))
}

// --- sealing -------------------------------------------------------------------------------------

/// The encryption context of a version: a sealed value opens only as that version of that secret.
pub fn version_context(tenant_id: &str, secret_id: &str, version: f64) -> String {
    format!(
        "vault:{tenant_id}:{secret_id}:{}",
        number_to_string(version)
    )
}

fn context_of(version: &VaultVersion) -> String {
    version_context(&version.tenant_id, &version.secret_id, version.version)
}

pub fn lease_handle_context(lease_id: &str) -> IamResult<String> {
    Ok(format!("vault-lease:{lease_id}"))
}

pub fn seal_value(ctx: &Arc<ServerContext>, value: &str, context: &str) -> IamResult<String> {
    Ok(better_iam_auth::encrypt_secret(
        value,
        &ctx.options.secret,
        context,
    ))
}

/// Opens a sealed value with the current secret or a previous one (`rotateSecrets` re-seals).
pub fn open_value(ctx: &Arc<ServerContext>, sealed: &str, context: &str) -> IamResult<String> {
    let mut secrets = vec![ctx.options.secret.clone()];
    secrets.extend(ctx.options.previous_secrets.iter().flatten().cloned());
    match better_iam_auth::open_secret(sealed, &secrets, context) {
        Some((value, _)) => Ok(value),
        None => Err(IamError::with_status(
            "INVALID_SEALED_VALUE",
            "The secret value cannot be opened",
            500,
        )),
    }
}

// --- records -------------------------------------------------------------------------------------

async fn find_records(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

pub async fn find_secret(
    tx: &Store,
    tenant_id: &str,
    name: &str,
) -> IamResult<Option<crate::vault::VaultSecret>> {
    let found = find_records(
        tx,
        SECRETS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("uniqueKey", name),
    )
    .await?;
    found.into_iter().next().map(decode).transpose()
}

pub async fn secret_versions(
    tx: &Store,
    secret: &crate::vault::VaultSecret,
) -> IamResult<Vec<crate::vault::VaultVersion>> {
    let mut versions = find_records(
        tx,
        VERSIONS,
        Filter::new()
            .eq("tenantId", secret.tenant_id.as_str())
            .eq("secretId", secret.id.as_str()),
    )
    .await?
    .into_iter()
    .map(decode::<VaultVersion>)
    .collect::<IamResult<Vec<_>>>()?;
    versions.sort_by(|a, b| b.version.total_cmp(&a.version));
    Ok(versions)
}

pub async fn version_of(
    tx: &Store,
    secret: &crate::vault::VaultSecret,
    version: f64,
) -> IamResult<Option<crate::vault::VaultVersion>> {
    version_by_key(
        tx,
        &secret.tenant_id,
        &format!("{}:{}", secret.id, number_to_string(version)),
    )
    .await
}

async fn version_by_key(
    tx: &Store,
    tenant_id: &str,
    unique_key: &str,
) -> IamResult<Option<VaultVersion>> {
    let found = find_records(
        tx,
        VERSIONS,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("uniqueKey", unique_key),
    )
    .await?;
    found.into_iter().next().map(decode).transpose()
}

/// `{ via: 'vault', principal? }`: how the vault uses a customer-managed key.
fn kms_use(r#use: Option<&ValueUse>) -> Value {
    let mut map = Map::new();
    map.insert("via".into(), Value::String("vault".into()));
    if let Some(principal) = r#use {
        map.insert(
            "principal".into(),
            crate::conformance::principal_json(principal),
        );
    }
    Value::Object(map)
}

/// Encrypts a version's value: under the secret's customer-managed key (`kms_key_id`, the secret's `kmsKeyId`) when
/// it has one, else the deployment secret.
pub async fn encrypt_version(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    kms_key_id: Option<&str>,
    record: &crate::vault::VaultVersion,
    value: &str,
    r#use: Option<&crate::vault::ValueUse>,
) -> IamResult<crate::vault::VaultVersion> {
    let mut rest = record.clone();
    rest.sealed = None;
    rest.kms_key_id = None;
    let Some(key) = kms_key_id else {
        rest.sealed = Some(seal_value(ctx, value, &context_of(record))?);
        return Ok(rest);
    };
    let encrypted = crate::kms::kms_encrypt_for(
        ctx,
        tx,
        &record.tenant_id,
        key,
        value,
        &Value::String(context_of(record)),
        Some(&kms_use(r#use)),
    )
    .await?;
    rest.sealed = Some(js_string(encrypted.get("ciphertext")));
    rest.kms_key_id = Some(js_string(encrypted.get("keyId")));
    Ok(rest)
}

/// Adds a version (encrypted) and returns it; the caller moves stages.
pub async fn add_version(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    secret: &crate::vault::VaultSecret,
    value: &str,
    source: &str,
    actor_id: &str,
    r#use: Option<&crate::vault::ValueUse>,
) -> IamResult<AddedVersion> {
    let number = secret.latest_version + 1.0;
    let record = encrypt_version(
        ctx,
        tx,
        secret.kms_key_id.as_deref(),
        &VaultVersion {
            id: id(),
            tenant_id: secret.tenant_id.clone(),
            unique_key: format!("{}:{}", secret.id, number_to_string(number)),
            secret_id: secret.id.clone(),
            version: number,
            state: "enabled".into(),
            source: source.to_owned(),
            created_at: ctx.now(),
            created_by: actor_id.to_owned(),
            sealed: None,
            kms_key_id: None,
            disabled_at: None,
            destroyed_at: None,
            extra: Map::new(),
        },
        value,
        r#use,
    )
    .await?;
    tx.insert(VERSIONS, &encode(&record)).await?;
    let mut next = secret.clone();
    next.latest_version = number;
    Ok(AddedVersion {
        secret: next,
        version: record,
    })
}

/// Makes a version current: the old current becomes `previous`, a `pending` label on it is dropped, and versions
/// past `maxVersions` that no stage names are deleted. Returns the stored secret.
pub async fn promote_version(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    secret: &crate::vault::VaultSecret,
    version: f64,
    actor_id: &str,
    rotated: Option<bool>,
) -> IamResult<crate::vault::VaultSecret> {
    let rotated = rotated.unwrap_or(false);
    let mut stages = secret.stages.clone();
    let current = stages.get("current").copied();
    // A newer value restarts the rotation clock; rolling back to an older version does not.
    let fresher = current.is_none_or(|current| version > current);
    if current != Some(version) {
        if let Some(current) = current {
            stages.insert("previous".into(), current);
        }
        stages.insert("current".into(), version);
    }
    if stages.get("pending") == Some(&version) {
        stages.shift_remove("pending");
    }
    if stages.get("previous") == Some(&version) {
        stages.shift_remove("previous");
    }
    let now = ctx.now();
    let mut next = secret.clone();
    // A rotation's staged version stays marked until it becomes current (or another version does).
    next.rotation_pending = secret
        .rotation_pending
        .filter(|pending| *pending != version && stages.get("pending").copied() == Some(*pending));
    next.stages = stages;
    next.updated_at = now;
    next.updated_by = actor_id.to_owned();
    if rotated || (next.rotation.is_some() && fresher) {
        next.rotation = rotation_after(next.rotation.as_ref(), now, rotated);
    }
    let stored: VaultSecret = decode(tx.put(SECRETS, &encode(&next)).await?)?;
    prune_versions(tx, &stored).await?;
    Ok(stored)
}

/// Rotation bookkeeping after a new current version: the next due date counts from now.
fn rotation_after(
    rotation: Option<&SecretRotation>,
    now: f64,
    rotated: bool,
) -> Option<SecretRotation> {
    let Some(rotation) = rotation else {
        return rotated.then(|| SecretRotation {
            last_rotated_at: Some(now),
            ..SecretRotation::default()
        });
    };
    let mut next = rotation.clone();
    next.last_failure = None;
    next.failures = None;
    next.due_notified_at = None;
    next.next_rotation_at = None;
    next.last_rotated_at = Some(now);
    if let Some(days) = next.interval_days {
        next.next_rotation_at = Some(now + days * DAY);
    }
    Some(next)
}

/// Recomputes the next due date after settings change (the interval counts from the last rotation or creation).
pub fn schedule_rotation(
    rotation: Option<&crate::vault::SecretRotation>,
    created_at: f64,
    now: f64,
) -> IamResult<Option<crate::vault::SecretRotation>> {
    let Some(rotation) = rotation else {
        return Ok(None);
    };
    let mut rest = rotation.clone();
    rest.next_rotation_at = None;
    let Some(days) = rest.interval_days else {
        return Ok(Some(rest));
    };
    let from = rest.last_rotated_at.unwrap_or(created_at);
    rest.next_rotation_at = Some((from + days * DAY).max(now));
    Ok(Some(rest))
}

pub async fn prune_versions(tx: &Store, secret: &crate::vault::VaultSecret) -> IamResult<f64> {
    let staged: Vec<f64> = secret.stages.values().copied().collect();
    let versions = secret_versions(tx, secret).await?;
    let mut removed = 0.0;
    for (index, version) in versions.iter().enumerate() {
        if index as f64 >= secret.max_versions && !staged.contains(&version.version) {
            tx.delete(VERSIONS, &version.id).await?;
            removed += 1.0;
        }
    }
    Ok(removed)
}

/// The value of one version; refuses disabled and destroyed versions. A version under a customer-managed key opens
/// only while that key is enabled (KEY_STATE_INVALID otherwise); the key's audit log records the use.
pub async fn open_version(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    version: &crate::vault::VaultVersion,
    r#use: Option<&crate::vault::ValueUse>,
) -> IamResult<String> {
    if version.state == "disabled" {
        return Err(IamError::with_status(
            "VERSION_DISABLED",
            "This version is disabled",
            409,
        ));
    }
    open_stored(ctx, tx, version, r#use).await
}

/// A version's value whatever its state (re-encryption under another key); destroyed versions have none.
pub async fn open_stored(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    version: &crate::vault::VaultVersion,
    r#use: Option<&crate::vault::ValueUse>,
) -> IamResult<String> {
    let sealed = match &version.sealed {
        Some(sealed) if version.state != "destroyed" => sealed,
        _ => {
            return Err(IamError::with_status(
                "VERSION_DESTROYED",
                "This version was destroyed",
                410,
            ));
        }
    };
    let Some(key_id) = &version.kms_key_id else {
        return open_value(ctx, sealed, &context_of(version));
    };
    crate::kms::kms_decrypt_for(
        ctx,
        tx,
        &version.tenant_id,
        &json!({ "ciphertext": sealed, "keyId": key_id }),
        &Value::String(context_of(version)),
        Some(&kms_use(r#use)),
    )
    .await
}

/// Resolves `version` / `stage` (default `current`) to a version record of the secret. `input` is the object holding
/// `version` and `stage`.
pub async fn select_version(
    tx: &Store,
    secret: &crate::vault::VaultSecret,
    input: &Value,
) -> IamResult<crate::vault::VaultVersion> {
    let version = input.get("version");
    let stage = input.get("stage");
    if version.is_some() && stage.is_some() {
        return Err(invalid_input("Pass version or stage, not both"));
    }
    let not_found = |message: &str| IamError::with_status("NOT_FOUND", message, 404);
    let key = if let Some(version) = version {
        let number = integer(Some(version), "version", 1.0, MAX_SAFE_INTEGER)?;
        format!("{}:{}", secret.id, number_to_string(number))
    } else {
        let label = match stage {
            None => "current".to_owned(),
            Some(stage) => stage_name(Some(stage))?,
        };
        match secret.stages.get(&label) {
            Some(number) => format!("{}:{}", secret.id, number_to_string(*number)),
            // `secret.stages.constructor` is `Object`, which names no version.
            None if label == "constructor" => {
                format!("{}:function Object() {{ [native code] }}", secret.id)
            }
            None => {
                return Err(not_found(if stage.is_none() {
                    "This secret has no current version"
                } else {
                    "No version has this stage"
                }));
            }
        }
    };
    version_by_key(tx, &secret.tenant_id, &key)
        .await?
        .ok_or_else(|| not_found("Version not found"))
}

pub async fn record_access(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    secret: &crate::vault::VaultSecret,
    entry: &AccessEntry,
) -> IamResult<()> {
    let at = ctx.now();
    let retention = vault_settings(ctx)?.access_retention_ms;
    let mut record = Map::new();
    record.insert("id".into(), Value::String(id()));
    record.insert("tenantId".into(), Value::String(secret.tenant_id.clone()));
    record.insert("secretId".into(), Value::String(secret.id.clone()));
    record.insert("name".into(), Value::String(secret.name.clone()));
    record.insert(
        "identityId".into(),
        Value::String(entry.identity_id.clone()),
    );
    record.insert("action".into(), Value::String(entry.action.clone()));
    if let Some(version) = entry.version {
        record.insert("version".into(), crate::js::number(version));
    }
    if let Some(lease_id) = &entry.lease_id {
        record.insert("leaseId".into(), Value::String(lease_id.clone()));
    }
    if let Some(kind) = &entry.session_kind {
        record.insert("sessionKind".into(), Value::String(kind.clone()));
    }
    if let Some(agent_id) = &entry.agent_id {
        record.insert("agentId".into(), Value::String(agent_id.clone()));
    }
    record.insert("at".into(), crate::js::number(at));
    record.insert("expiresAt".into(), crate::js::number(at + retention));
    tx.insert(ACCESS, &record).await?;
    if matches!(entry.action.as_str(), "reveal" | "checkout" | "lease")
        && let Some(mut current) = tx.get(SECRETS, &secret.id).await?
    {
        current.insert("lastAccessedAt".into(), crate::js::number(at));
        tx.put(SECRETS, &current).await?;
    }
    Ok(())
}

/// Active check-outs and leases of a secret, in issue order.
pub async fn live_leases(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    secret: &crate::vault::VaultSecret,
) -> IamResult<Vec<crate::vault::VaultLease>> {
    let now = ctx.now();
    let mut leases = find_records(
        tx,
        LEASES,
        Filter::new()
            .eq("tenantId", secret.tenant_id.as_str())
            .eq("secretId", secret.id.as_str())
            .eq("state", "active"),
    )
    .await?
    .into_iter()
    .map(decode::<VaultLease>)
    .collect::<IamResult<Vec<_>>>()?;
    leases.retain(|lease| lease.expires_at > now);
    leases.sort_by(|a, b| a.issued_at.total_cmp(&b.issued_at));
    Ok(leases)
}

/// The policy attributes of a secret: `resource.name`, `resource.tag.{key}`, and its settings.
pub fn secret_attributes(
    secret: &crate::vault::VaultSecret,
) -> IamResult<IndexMap<String, better_iam_core::Json>> {
    let mut attributes: IndexMap<String, Value> = IndexMap::new();
    attributes.insert("name".into(), Value::String(secret.name.clone()));
    attributes.insert("kind".into(), Value::String(secret.kind.clone()));
    attributes.insert("format".into(), Value::String(secret.format.clone()));
    attributes.insert("status".into(), Value::String(secret.status.clone()));
    attributes.insert("createdBy".into(), Value::String(secret.created_by.clone()));
    attributes.insert(
        "checkoutRequired".into(),
        Value::Bool(
            secret
                .checkout
                .as_ref()
                .is_some_and(|policy| policy.required),
        ),
    );
    attributes.insert(
        "rotationEnabled".into(),
        Value::Bool(
            secret
                .rotation
                .as_ref()
                .is_some_and(|rotation| rotation.interval_days.is_some()),
        ),
    );
    attributes.insert(
        "customerManagedKey".into(),
        Value::Bool(secret.kms_key_id.is_some()),
    );
    if let Some(engine) = &secret.engine {
        attributes.insert("engine".into(), Value::String(engine.clone()));
    }
    for (key, value) in &secret.tags {
        attributes.insert(format!("tag.{key}"), Value::String(value.clone()));
    }
    Ok(attributes)
}

/// The decision engine's resolver for `iam/vault/secrets/{name}`: an existing secret carries its attributes; a name
/// nobody uses yet resolves without any (conditions on them then fail closed), never falling through to a managed
/// resource that could plant attributes. Undefined for other resources.
pub async fn resolve_secret_resource(
    tx: &Store,
    reference: &better_iam_core::ResourceRef,
) -> IamResult<Option<crate::options::ResolvedResource>> {
    if reference.kind != "iam" || !reference.id.starts_with(SECRET_RESOURCE_PREFIX) {
        return Ok(None);
    }
    let name = &reference.id[SECRET_RESOURCE_PREFIX.len()..];
    let secret = if !name.is_empty() && utf16_len(name) <= 256 {
        find_secret(tx, &reference.tenant_id, name).await?
    } else {
        None
    };
    let mut resolved = crate::options::ResolvedResource::of(reference);
    if let Some(secret) = secret {
        resolved.attributes = Some(secret_attributes(&secret)?.into_iter().collect());
    }
    Ok(Some(resolved))
}

// --- external calls ------------------------------------------------------------------------------

/// Runs a rotator or engine call with the configured timeout. As in TypeScript, a call that times out is not
/// cancelled: it keeps running on its own task, and only its answer is dropped. The timeout is a plain `Error`
/// (INTERNAL_ERROR) whose message the callers record, redacted.
pub async fn with_timeout<T, F>(ctx: &ServerContext, what: &str, call: F) -> IamResult<T>
where
    T: Send + 'static,
    F: Future<Output = IamResult<T>> + Send + 'static,
{
    let timeout = vault_settings(ctx)?.call_timeout_ms;
    let task = tokio::spawn(call);
    match tokio::time::timeout(std::time::Duration::from_millis(timeout as u64), task).await {
        Ok(Ok(result)) => result,
        Ok(Err(_)) => Err(internal_error()),
        Err(_) => Err(IamError::with_status(
            "INTERNAL_ERROR",
            format!(
                "{what} did not finish within {} ms",
                number_to_string(timeout)
            ),
            500,
        )),
    }
}

/// Every form a secret value might take inside an error message: the value itself and, for a JSON object, each string
/// (and number) field, each with its JSON-escaped, URL-encoded and base64 spellings. Longest first, so a field inside a
/// longer match is not left half-redacted.
fn sensitive_forms(values: &[Option<String>]) -> Vec<String> {
    let mut plain: IndexSet<String> = IndexSet::new();
    for value in values.iter().flatten() {
        if value.is_empty() {
            continue;
        }
        plain.insert(value.clone());
        if value.starts_with('{')
            && let Ok(parsed) = core_js::parse(value)
        {
            let fields: Vec<&Value> = match &parsed {
                Value::Object(map) => core_js::entries(map)
                    .into_iter()
                    .map(|(_, item)| item)
                    .collect(),
                Value::Array(items) => items.iter().collect(),
                _ => Vec::new(),
            };
            for field in fields {
                match field {
                    Value::String(text) => {
                        plain.insert(text.clone());
                    }
                    Value::Number(_) => {
                        plain.insert(js_string(Some(field)));
                    }
                    _ => {}
                }
            }
        }
    }
    let mut forms: IndexSet<String> = IndexSet::new();
    for value in plain {
        if utf16_len(&value) < 4 {
            continue;
        }
        let quoted = core_js::quote(&value);
        forms.insert(value.clone());
        forms.insert(quoted[1..quoted.len() - 1].to_owned());
        forms.insert(better_iam_auth::util::encode_uri_component(&value));
        forms.insert(STANDARD_NO_PAD.encode(value.as_bytes()));
    }
    let mut forms: Vec<String> = forms
        .into_iter()
        .filter(|form| utf16_len(form) >= 4)
        .collect();
    forms.sort_by_key(|form| std::cmp::Reverse(utf16_len(form)));
    forms
}

/// An error message safe to store: at most 512 characters, with any secret value (or field of one) it quotes
/// redacted. `error.message` is the message (`error instanceof Error ? error.message : String(error)`).
pub fn redacted_message(error: &IamError, values: &[Option<String>]) -> IamResult<String> {
    let mut message = error.message.clone();
    for form in sensitive_forms(values) {
        message = message.replace(&form, "[redacted]");
    }
    let cleaned: String = message
        .chars()
        .map(|c| if (c as u32) < 0x20 { ' ' } else { c })
        .collect();
    // `.slice(0, 512)` in UTF-16 code units, never splitting a character.
    let mut units = 0;
    let mut sliced = String::new();
    for c in cleaned.chars() {
        units += c.len_utf16();
        if units > 512 {
            break;
        }
        sliced.push(c);
    }
    Ok(if sliced.is_empty() {
        "Unknown error".to_owned()
    } else {
        sliced
    })
}

/// `vaultTime`: `{ MINUTE, HOUR, DAY }` in milliseconds.
pub fn vault_time() -> IamResult<Value> {
    Ok(json!({
        "MINUTE": crate::js::number(MINUTE),
        "HOUR": crate::js::number(HOUR),
        "DAY": crate::js::number(DAY),
    }))
}
