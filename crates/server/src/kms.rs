//! Port of `packages/server/src/kms.ts`.
//!
//! Key management (KMS): tenant keys whose material never leaves the server. Symmetric keys encrypt and decrypt
//! (AES-256-GCM, bound to an encryption context), asymmetric keys sign and verify (ECDSA, Ed25519, RSA) or encrypt
//! (RSA-OAEP), and HMAC keys compute and check message authentication codes. Every key keeps its old versions, so
//! rotation never breaks existing ciphertexts or signatures. Material is sealed under the deployment secret (and
//! re-sealed by `iam.rotateSecrets()`); the API lives in api/keys.rs.
//!
//! Key material is stored exactly as the TypeScript implementation stores it (a mixed fleet shares the database):
//! raw bytes in base64url for AES and HMAC keys, a PKCS#8 PEM private key and an SPKI PEM public key otherwise.

use std::sync::Arc;

use aes_gcm::aead::{Aead, KeyInit, Payload as AeadPayload};
use aes_gcm::{Aes256Gcm, Nonce};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use better_iam_auth::crypto::{encrypt_secret, open_secret, random_bytes};
use better_iam_auth::util::{base64_padded, base64url, node_base64_decode};
use better_iam_core::js::{cmp_utf16, number_to_string};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, Identity,
    Record, SessionKind, canonicalize_json,
};
use hmac::{Hmac, Mac};
use indexmap::IndexMap;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256, Sha384, Sha512};

use crate::context::{ServerContext, Store};
use crate::js::{internal_error, js_string, keys as js_keys, number, utf16_len};
use crate::port::decode;
use crate::utils::id;
use crate::validation::{object, text};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EncryptionContext {
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `KmsServiceUse`: how another module uses a tenant key on behalf of a caller.
#[derive(Debug, Clone)]
pub struct KmsServiceUse {
    /// The module using the key, recorded as `metadata.via` (for example `vault`).
    pub via: String,
    /// The caller the module acts for, recorded as the event's actor; otherwise `deployment-operator`.
    pub principal: Option<better_iam_core::AuthenticatedPrincipal>,
}

/// What `kmsDataKeyFor` returns: a fresh data key (wipe it after use) and its wrapped form.
#[derive(Debug, Clone)]
pub struct ServiceDataKey {
    pub data_key: Vec<u8>,
    pub wrapped: String,
    pub key_id: String,
    pub key_version: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantConstraints {
    /// The request's encryption context must equal this one exactly.
    #[serde(
        rename = "encryptionContextEquals",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub encryption_context_equals: Option<IndexMap<String, String>>,
    /// The request's encryption context must contain every one of these pairs.
    #[serde(
        rename = "encryptionContextSubset",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub encryption_context_subset: Option<IndexMap<String, String>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The operations a key grant can allow (`read`, `encrypt`, `decrypt`, `generate-data-key`, `sign`, `verify`,
/// `generate-mac`, `verify-mac`); each maps to one `iam:kms:*` action. A JSON string.
pub type GrantOperation = Value;

/// The public view of a grant. Members are declared in the order the TypeScript summary writes them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GrantSummary {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    /// Grants name one identity (a person, service account or agent); groups are not grantees.
    #[serde(rename = "granteeType")]
    pub grantee_type: String,
    #[serde(rename = "granteeId")]
    pub grantee_id: String,
    #[serde(rename = "operations")]
    pub operations: Vec<crate::kms::GrantOperation>,
    #[serde(rename = "active")]
    pub active: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(
        rename = "constraints",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub constraints: Option<crate::kms::GrantConstraints>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A key spec (`aes-256-gcm`, `hmac-sha256|384|512`, `ecc-p256|p384`, `ed25519`, `rsa-2048|3072|4096`). A JSON string.
pub type KeySpec = Value;

/// `enabled`, `disabled` or `pending-deletion`. A JSON string.
pub type KeyState = Value;

/// The public view of a key: never its material. Members are declared in the order the TypeScript summary writes
/// them.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeySummary {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "keySpec")]
    pub key_spec: crate::kms::KeySpec,
    #[serde(rename = "keyUsage")]
    pub key_usage: crate::kms::KeyUsage,
    #[serde(rename = "state")]
    pub state: crate::kms::KeyState,
    #[serde(rename = "currentVersion")]
    pub current_version: f64,
    #[serde(rename = "tags")]
    pub tags: IndexMap<String, String>,
    #[serde(rename = "aliases")]
    pub aliases: Vec<String>,
    /// Signing or MAC algorithms the key supports (none for encryption keys).
    #[serde(rename = "algorithms")]
    pub algorithms: Vec<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(
        rename = "rotationPeriodDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rotation_period_days: Option<f64>,
    #[serde(
        rename = "nextRotationAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_rotation_at: Option<f64>,
    #[serde(
        rename = "lastRotatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_rotated_at: Option<f64>,
    #[serde(
        rename = "deletionDate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deletion_date: Option<f64>,
    /// The module the key belongs to; the KMS API does not use it directly.
    #[serde(rename = "managedBy", default, skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<String>,
    #[serde(rename = "managedId", default, skip_serializing_if = "Option::is_none")]
    pub managed_id: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `encrypt`, `sign` or `mac`. A JSON string.
pub type KeyUsage = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KmsAlias {
    /// `alias/{name}`; also the uniqueKey, so an alias names one key per tenant.
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KmsGrant {
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "name", default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Grants name one identity (a person, service account or agent); groups are not grantees.
    #[serde(rename = "granteeType")]
    pub grantee_type: String,
    #[serde(rename = "granteeId")]
    pub grantee_id: String,
    #[serde(rename = "operations")]
    pub operations: Vec<crate::kms::GrantOperation>,
    #[serde(
        rename = "constraints",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub constraints: Option<crate::kms::GrantConstraints>,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KmsKey {
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "keySpec")]
    pub key_spec: crate::kms::KeySpec,
    #[serde(rename = "keyUsage")]
    pub key_usage: crate::kms::KeyUsage,
    #[serde(rename = "state")]
    pub state: crate::kms::KeyState,
    /// The version encrypt, sign and MAC calls use; older versions still decrypt and verify.
    #[serde(rename = "currentVersion")]
    pub current_version: f64,
    #[serde(rename = "tags")]
    pub tags: IndexMap<String, String>,
    /// Automatic rotation period; absent when the key rotates only on demand.
    #[serde(
        rename = "rotationPeriodDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rotation_period_days: Option<f64>,
    #[serde(
        rename = "nextRotationAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub next_rotation_at: Option<f64>,
    #[serde(
        rename = "lastRotatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_rotated_at: Option<f64>,
    /// When a key pending deletion is destroyed, with every version, alias and grant.
    #[serde(
        rename = "deletionDate",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub deletion_date: Option<f64>,
    /// A key that belongs to another module (a certificate authority's signing key, a protection profile's key): the
    /// KMS API refuses to encrypt, decrypt, sign or grant with it directly, so nobody can use it around that module's
    /// own checks. It can still be read, tagged, disabled and deleted.
    #[serde(rename = "managedBy", default, skip_serializing_if = "Option::is_none")]
    pub managed_by: Option<String>,
    #[serde(rename = "managedId", default, skip_serializing_if = "Option::is_none")]
    pub managed_id: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
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

impl KmsKey {
    /// `key.keySpec` as a string ("" for a malformed record).
    pub fn spec(&self) -> &str {
        self.key_spec.as_str().unwrap_or_default()
    }
    /// `key.keyUsage` as a string.
    pub fn usage(&self) -> &str {
        self.key_usage.as_str().unwrap_or_default()
    }
    /// `key.state` as a string.
    pub fn state_name(&self) -> &str {
        self.state.as_str().unwrap_or_default()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KmsKeyVersion {
    #[serde(rename = "keyId")]
    pub key_id: String,
    #[serde(rename = "version")]
    pub version: f64,
    /// How the material is sealed: `secret` = under the deployment secret (re-sealed by `iam.rotateSecrets()`).
    #[serde(rename = "wrapper")]
    pub wrapper: String,
    #[serde(rename = "materialSealed")]
    pub material_sealed: String,
    /// SPKI PEM of an asymmetric key version.
    #[serde(
        rename = "publicKeyPem",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub public_key_pem: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    /// `create`, `rotate` (on demand) or `automatic`.
    #[serde(rename = "origin")]
    pub origin: String,
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

pub const MAX_ALIASES_PER_KEY: f64 = 50.0;

pub const MAX_GRANTS_PER_KEY: f64 = 50.0;

pub const MAX_KEYS_PER_TENANT: f64 = 1000.0;

/// Messages accepted by `sign`, `verify` and the MAC calls.
pub const MAX_MESSAGE_BYTES: f64 = 65536.0;

/// Plaintext accepted by `encrypt` (AES-GCM); RSA-OAEP accepts what the modulus allows.
pub const MAX_PLAINTEXT_BYTES: f64 = 4096.0;

pub const MAX_VERSIONS: f64 = 1000.0;

const MAX_CIPHERTEXT_CHARS: usize = 16384;

const CIPHERTEXT_PREFIX: &str = "kms1";

/// `der` (default) or `jose` (raw r||s for ECDSA, as in JWS). A JSON string.
pub type SignatureFormat = Value;

// ---------------------------------------------------------------------------------------------------------------
// Specs

/// `SpecInfo`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SpecInfo {
    pub usages: &'static [&'static str],
    /// `aes`, `hmac`, `ec`, `ed25519` or `rsa`.
    pub family: &'static str,
    /// HMAC key length in bytes, or the RSA modulus length in bits.
    pub size: Option<usize>,
    pub hash: Option<&'static str>,
    pub curve: Option<&'static str>,
}

const SPEC_NAMES: [&str; 10] = [
    "aes-256-gcm",
    "hmac-sha256",
    "hmac-sha384",
    "hmac-sha512",
    "ecc-p256",
    "ecc-p384",
    "ed25519",
    "rsa-2048",
    "rsa-3072",
    "rsa-4096",
];

/// `keySpecs[spec]`.
pub(crate) fn spec_info(spec: &str) -> Option<SpecInfo> {
    let info = |usages, family, size, hash, curve| SpecInfo {
        usages,
        family,
        size,
        hash,
        curve,
    };
    Some(match spec {
        "aes-256-gcm" => info(&["encrypt"], "aes", None, None, None),
        "hmac-sha256" => info(&["mac"], "hmac", Some(32), Some("sha256"), None),
        "hmac-sha384" => info(&["mac"], "hmac", Some(48), Some("sha384"), None),
        "hmac-sha512" => info(&["mac"], "hmac", Some(64), Some("sha512"), None),
        "ecc-p256" => info(&["sign"], "ec", None, Some("sha256"), Some("P-256")),
        "ecc-p384" => info(&["sign"], "ec", None, Some("sha384"), Some("P-384")),
        "ed25519" => info(&["sign"], "ed25519", None, None, None),
        "rsa-2048" => info(&["encrypt", "sign"], "rsa", Some(2048), None, None),
        "rsa-3072" => info(&["encrypt", "sign"], "rsa", Some(3072), None, None),
        "rsa-4096" => info(&["encrypt", "sign"], "rsa", Some(4096), None, None),
        _ => return None,
    })
}

/// `keySpecs[spec]` for a spec read from a record: a spec the table does not know is a TypeError in TypeScript.
fn known_spec(spec: &str) -> IamResult<SpecInfo> {
    spec_info(spec).ok_or_else(internal_error)
}

/// `keySpecs[spec].family` ("" for an unknown spec).
pub(crate) fn spec_family(spec: &str) -> &'static str {
    spec_info(spec).map(|info| info.family).unwrap_or_default()
}

/// The table `keySpecs` as JSON.
pub fn key_specs() -> IamResult<Value> {
    let mut table = Map::new();
    for name in SPEC_NAMES {
        let info = known_spec(name)?;
        let mut entry = Map::new();
        entry.insert("usages".into(), json!(info.usages));
        entry.insert("family".into(), Value::String(info.family.into()));
        if let Some(size) = info.size {
            entry.insert("size".into(), json!(size));
        }
        if let Some(hash) = info.hash {
            entry.insert("hash".into(), Value::String(hash.into()));
        }
        if let Some(curve) = info.curve {
            entry.insert("curve".into(), Value::String(curve.into()));
        }
        table.insert(name.into(), Value::Object(entry));
    }
    Ok(Value::Object(table))
}

/// The KMS actions in declaration order (`Object.values(kmsActions)`), with the operation each one names.
pub(crate) const KMS_ACTIONS: [(&str, &str); 12] = [
    ("create", "iam:kms:create"),
    ("read", "iam:kms:read"),
    ("update", "iam:kms:update"),
    ("delete", "iam:kms:delete"),
    ("grant", "iam:kms:grant"),
    ("encrypt", "iam:kms:encrypt"),
    ("decrypt", "iam:kms:decrypt"),
    ("generate-data-key", "iam:kms:generate-data-key"),
    ("sign", "iam:kms:sign"),
    ("verify", "iam:kms:verify"),
    ("generate-mac", "iam:kms:generate-mac"),
    ("verify-mac", "iam:kms:verify-mac"),
];

/// `kmsActions[name]`.
pub(crate) fn kms_action(name: &str) -> &'static str {
    KMS_ACTIONS
        .iter()
        .find(|(operation, _)| *operation == name)
        .map(|(_, action)| *action)
        .unwrap_or_default()
}

/// The actions KMS authorizes, by operation. Management actions are `create/read/update/delete/grant`.
pub fn kms_actions() -> IamResult<Value> {
    let mut table = Map::new();
    for (operation, action) in KMS_ACTIONS {
        table.insert(operation.into(), Value::String(action.into()));
    }
    Ok(Value::Object(table))
}

/// The grant operations (every action but the management ones `create`, `update`, `delete` and `grant`).
const GRANT_OPERATIONS: [&str; 8] = [
    "read",
    "encrypt",
    "decrypt",
    "generate-data-key",
    "sign",
    "verify",
    "generate-mac",
    "verify-mac",
];

/// `grantOperationOf[action]`.
pub(crate) fn grant_operation_for(action: &str) -> Option<&'static str> {
    GRANT_OPERATIONS
        .iter()
        .copied()
        .find(|operation| kms_action(operation) == action)
}

/// Grant operations, keyed by the action they allow.
pub fn grant_operation_of() -> IamResult<IndexMap<String, crate::kms::GrantOperation>> {
    Ok(GRANT_OPERATIONS
        .iter()
        .map(|operation| {
            (
                kms_action(operation).to_owned(),
                Value::String((*operation).to_owned()),
            )
        })
        .collect())
}

/// `operationsByUsage[usage]`.
fn operations_by_usage(usage: &str) -> &'static [&'static str] {
    match usage {
        "encrypt" => &["read", "encrypt", "decrypt", "generate-data-key"],
        "sign" => &["read", "sign", "verify"],
        "mac" => &["read", "generate-mac", "verify-mac"],
        _ => &[],
    }
}

/// Operations that carry an encryption context, the only ones a context-constrained grant may allow.
fn context_operation(operation: &str) -> bool {
    matches!(operation, "encrypt" | "decrypt" | "generate-data-key")
}

// ---------------------------------------------------------------------------------------------------------------
// Validation

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// `/^[A-Za-z0-9_.:/=+@-]{1,128}$/` (tag and encryption context keys).
fn identifier_key(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.:/=+@-".contains(&byte))
}

fn unsafe_key(value: &str) -> bool {
    matches!(value, "__proto__" | "prototype" | "constructor")
}

/// `/[\u0000-\u001f]/`.
fn has_c0(value: &str) -> bool {
    value.chars().any(|c| (c as u32) <= 0x1f)
}

/// `aliasPattern`: `/^alias\/[A-Za-z0-9/_-]{1,250}$/`.
pub(crate) fn is_alias(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("alias/") else {
        return false;
    };
    !rest.is_empty()
        && rest.len() <= 250
        && rest
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/_-".contains(&byte))
}

/// The source of `aliasPattern` (`/^alias\/[A-Za-z0-9/_-]{1,250}$/`).
pub fn alias_pattern() -> IamResult<Value> {
    Ok(Value::String("^alias\\/[A-Za-z0-9/_-]{1,250}$".into()))
}

/// `/^[A-Za-z0-9-]{1,64}$/`.
fn key_id_like(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
}

/// `/^[A-Za-z0-9_-]*$/` (a base64url alphabet, possibly empty).
pub(crate) fn base64url_chars(value: &str) -> bool {
    value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
}

/// `/^[1-9]\d{0,5}$/`.
fn version_digits(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 6
        && (b'1'..=b'9').contains(&bytes[0])
        && bytes.iter().all(u8::is_ascii_digit)
}

pub fn key_spec(value: Option<&Value>) -> IamResult<crate::kms::KeySpec> {
    match value {
        Some(Value::String(spec)) if spec_info(spec).is_some() => Ok(Value::String(spec.clone())),
        _ => Err(invalid(format!(
            "keySpec must be one of {}",
            SPEC_NAMES.join(", ")
        ))),
    }
}

/// The usage a new key gets: the one its spec allows, or (for RSA) the one asked for.
pub fn key_usage_for(
    spec: &crate::kms::KeySpec,
    value: Option<&Value>,
) -> IamResult<crate::kms::KeyUsage> {
    let name = js_string(Some(spec));
    let usages = known_spec(&name)?.usages;
    let Some(value) = value else {
        if usages.len() == 1 {
            return Ok(Value::String(usages[0].into()));
        }
        return Err(invalid(format!(
            "keyUsage is required for {name} (encrypt or sign)"
        )));
    };
    match value {
        Value::String(usage) if usages.contains(&usage.as_str()) => Ok(value.clone()),
        _ => Err(invalid(format!(
            "{name} keys support keyUsage {}",
            usages.join(" or ")
        ))),
    }
}

/// Up to 50 tags; keys are identifiers, values short strings (they become `resource.tags.{key}`).
pub fn key_tags(value: Option<&Value>) -> IamResult<IndexMap<String, String>> {
    let Some(value) = value else {
        return Ok(IndexMap::new());
    };
    let input = object(Some(value))?;
    let entries = js_keys(input);
    if entries.len() > 50 {
        return Err(invalid("At most 50 tags"));
    }
    let mut tags = IndexMap::new();
    for key in entries {
        if !identifier_key(key) || unsafe_key(key) {
            return Err(invalid(format!("Invalid tag key {key}")));
        }
        match input.get(key) {
            Some(Value::String(item)) if utf16_len(item) <= 256 && !has_c0(item) => {
                tags.insert(key.clone(), item.clone());
            }
            _ => {
                return Err(invalid(format!(
                    "Tag {key} must be a string of at most 256 characters"
                )));
            }
        }
    }
    Ok(tags)
}

/// An encryption context: up to 16 non-secret key/value pairs bound to a ciphertext as additional authenticated
/// data. Decryption must present the same pairs. They are recorded in the audit trail and exposed to policies as
/// `resource.encryptionContext.{key}`, so never put secrets in them.
pub fn encryption_context(
    value: Option<&Value>,
    name: Option<&str>,
) -> IamResult<crate::kms::EncryptionContext> {
    let name = name.unwrap_or("encryptionContext");
    let Some(value) = value else {
        return Ok(EncryptionContext { extra: Map::new() });
    };
    let input = object(Some(value))?;
    let entries = js_keys(input);
    if entries.len() > 16 {
        return Err(invalid(format!("{name} has more than 16 pairs")));
    }
    let mut result = Map::new();
    for key in entries {
        if !identifier_key(key) || unsafe_key(key) {
            return Err(invalid(format!("Invalid {name} key {key}")));
        }
        match input.get(key) {
            Some(Value::String(item))
                if !item.is_empty() && utf16_len(item) <= 1024 && !has_c0(item) =>
            {
                result.insert(key.clone(), Value::String(item.clone()));
            }
            _ => {
                return Err(invalid(format!(
                    "{name} values must be non-empty strings of at most 1024 characters"
                )));
            }
        }
    }
    Ok(EncryptionContext { extra: result })
}

/// Decodes canonical standard or URL-safe base64 (padding optional), refusing anything else and anything longer
/// than `max` bytes. Canonical only: one byte string has one accepted spelling, so string-keyed replay caches hold.
pub fn base64_bytes(value: Option<&Value>, name: &str, max: f64) -> IamResult<Vec<u8>> {
    let refused = || invalid(format!("{name} must be base64"));
    let Some(Value::String(value)) = value else {
        return Err(refused());
    };
    let url_safe = base64url_chars(value);
    let standard = || {
        let body = value.trim_end_matches('=');
        value.len() - body.len() <= 2
            && body
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/')
    };
    if utf16_len(value) as f64 > (max * 4.0 / 3.0).ceil() + 4.0 || !(url_safe || standard()) {
        return Err(refused());
    }
    let bytes = node_base64_decode(value);
    let again = if url_safe {
        base64url(&bytes)
    } else {
        base64_padded(&bytes)
    };
    if again.trim_end_matches('=') != value.trim_end_matches('=') {
        return Err(invalid(format!("{name} must be canonical base64")));
    }
    if bytes.len() as f64 > max {
        return Err(invalid(format!(
            "{name} is longer than {} bytes",
            number_to_string(max)
        )));
    }
    Ok(bytes)
}

/// What [`payload`] reads: the bytes, and whether they were given as text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Payload {
    pub bytes: Vec<u8>,
    pub text: bool,
}

/// Reads a payload given as text (`{name}`, UTF-8) or bytes (`{name}Base64`): exactly one of the two. Says which,
/// so decryption can return the same form.
pub fn payload(input: &Map<String, Value>, name: &str, max: f64) -> IamResult<Payload> {
    let plain = input.get(name);
    let encoded = input.get(&format!("{name}Base64"));
    if plain.is_none() == encoded.is_none() {
        return Err(invalid(format!("Provide either {name} or {name}Base64")));
    }
    if let Some(plain) = plain {
        let Value::String(plain) = plain else {
            return Err(invalid(format!("{name} must be a string")));
        };
        let bytes = plain.as_bytes().to_vec();
        if bytes.len() as f64 > max {
            return Err(invalid(format!(
                "{name} is longer than {} bytes",
                number_to_string(max)
            )));
        }
        return Ok(Payload { bytes, text: true });
    }
    Ok(Payload {
        bytes: base64_bytes(encoded, &format!("{name}Base64"), max)?,
        text: false,
    })
}

/// The algorithms a key of this spec and usage signs or computes MACs with (encryption keys: none).
pub(crate) fn algorithms_for(spec: &str, usage: &str) -> IamResult<Vec<String>> {
    let info = known_spec(spec)?;
    if usage == "mac" {
        let hash = info.hash.ok_or_else(internal_error)?;
        return Ok(vec![format!("HS{}", &hash[3..])]);
    }
    if usage != "sign" {
        return Ok(Vec::new());
    }
    Ok(match info.family {
        "ec" => vec![if info.curve == Some("P-256") {
            "ES256".into()
        } else {
            "ES384".into()
        }],
        "ed25519" => vec!["EdDSA".into()],
        _ => ["PS256", "PS384", "PS512", "RS256", "RS384", "RS512"]
            .map(String::from)
            .to_vec(),
    })
}

/// The algorithms a key signs or computes MACs with (encryption keys: none).
pub fn key_algorithms(key: &Value) -> IamResult<Vec<String>> {
    algorithms_for(
        &js_string(key.get("keySpec")),
        &js_string(key.get("keyUsage")),
    )
}

pub fn signing_algorithm(key: &Value, value: Option<&Value>) -> IamResult<String> {
    let supported = key_algorithms(key)?;
    let Some(value) = value else {
        return Ok(supported.first().cloned().unwrap_or_default());
    };
    match value {
        Value::String(algorithm) if supported.contains(algorithm) => Ok(algorithm.clone()),
        _ => Err(invalid(format!(
            "This key supports the algorithms {}",
            supported.join(", ")
        ))),
    }
}

/// Sorted copy of a list of names (`[...names].sort()`).
fn sorted(names: &[String]) -> Vec<String> {
    let mut names = names.to_vec();
    names.sort_by(|a, b| cmp_utf16(a, b));
    names
}

pub fn summarize_key(
    key: &crate::kms::KmsKey,
    aliases: &[String],
) -> IamResult<crate::kms::KeySummary> {
    Ok(KeySummary {
        id: key.id.clone(),
        tenant_id: key.tenant_id.clone(),
        key_spec: key.key_spec.clone(),
        key_usage: key.key_usage.clone(),
        state: key.state.clone(),
        current_version: key.current_version,
        tags: key.tags.clone(),
        aliases: sorted(aliases),
        algorithms: algorithms_for(key.spec(), key.usage())?,
        created_at: key.created_at,
        created_by: key.created_by.clone(),
        updated_at: key.updated_at,
        description: key.description.clone(),
        rotation_period_days: key.rotation_period_days,
        next_rotation_at: key.next_rotation_at,
        last_rotated_at: key.last_rotated_at,
        deletion_date: key.deletion_date,
        managed_by: key.managed_by.clone(),
        managed_id: key.managed_id.clone(),
        extra: Map::new(),
    })
}

/// Refuses direct cryptographic use of a key another module owns (`KEY_MANAGED`).
pub fn assert_unmanaged(key: &Value) -> IamResult<()> {
    let managed_by = key.get("managedBy");
    if crate::js::truthy(managed_by) {
        return Err(IamError::with_status(
            "KEY_MANAGED",
            if managed_by.and_then(Value::as_str) == Some("pki") {
                "This key signs for a certificate authority; issue certificates through the pki API"
            } else {
                "This key protects a data protection profile; use the protection API"
            },
            409,
        ));
    }
    Ok(())
}

/// A typed key as the JSON object the TypeScript helpers receive.
pub(crate) fn key_json(key: &KmsKey) -> Value {
    serde_json::to_value(key).unwrap_or(Value::Null)
}

pub fn summarize_grant(
    grant: &crate::kms::KmsGrant,
    now: f64,
) -> IamResult<crate::kms::GrantSummary> {
    Ok(GrantSummary {
        id: grant.id.clone(),
        tenant_id: grant.tenant_id.clone(),
        key_id: grant.key_id.clone(),
        grantee_type: grant.grantee_type.clone(),
        grantee_id: grant.grantee_id.clone(),
        operations: grant.operations.clone(),
        active: grant.expires_at.is_none_or(|expires| expires > now),
        created_at: grant.created_at,
        created_by: grant.created_by.clone(),
        name: grant.name.clone(),
        constraints: grant.constraints.clone(),
        expires_at: grant.expires_at,
        extra: Map::new(),
    })
}

/// The attributes a key presents to policies (`resource.{name}`): identity, spec, usage, state, aliases, tags as
/// `resource.tags.{key}`, and for calls with one the encryption context as `resource.encryptionContext.{key}` plus
/// `resource.encryptionContextKeys`, and a signing call's `resource.algorithm`.
///
/// `extra` is `{ context?, algorithm? }`.
pub fn key_attributes(
    key: &Value,
    aliases: &[String],
    extra: Option<&Value>,
) -> IamResult<Map<String, Value>> {
    let mut attributes = Map::new();
    for (name, member) in [
        ("keyId", "id"),
        ("keySpec", "keySpec"),
        ("keyUsage", "keyUsage"),
        ("keyState", "state"),
    ] {
        attributes.insert(name.into(), key.get(member).cloned().unwrap_or(Value::Null));
    }
    attributes.insert("aliases".into(), json!(sorted(aliases)));
    attributes.insert(
        "createdBy".into(),
        key.get("createdBy").cloned().unwrap_or(Value::Null),
    );
    if crate::js::truthy(key.get("managedBy")) {
        attributes.insert(
            "managedBy".into(),
            key.get("managedBy").cloned().unwrap_or(Value::Null),
        );
    }
    if let Some(Value::Object(tags)) = key.get("tags") {
        for name in js_keys(tags) {
            attributes.insert(
                format!("tags.{name}"),
                tags.get(name).cloned().unwrap_or(Value::Null),
            );
        }
    }
    let extra = extra.and_then(Value::as_object);
    if let Some(Value::Object(context)) = extra.and_then(|extra| extra.get("context")) {
        let mut keys: Vec<String> = context.keys().cloned().collect();
        keys.sort_by(|a, b| cmp_utf16(a, b));
        attributes.insert("encryptionContextKeys".into(), json!(keys));
        for name in &keys {
            attributes.insert(
                format!("encryptionContext.{name}"),
                context.get(name).cloned().unwrap_or(Value::Null),
            );
        }
    }
    if let Some(algorithm) = extra.and_then(|extra| extra.get("algorithm")) {
        attributes.insert("algorithm".into(), algorithm.clone());
    }
    Ok(attributes)
}

/// Attributes for creating a key: what it would be, so policies can require tags or specs (`resource.tags.team`).
pub fn request_attributes(
    spec: &crate::kms::KeySpec,
    usage: &crate::kms::KeyUsage,
    tags: &IndexMap<String, String>,
) -> IamResult<Map<String, Value>> {
    let mut attributes = Map::new();
    attributes.insert("keySpec".into(), spec.clone());
    attributes.insert("keyUsage".into(), usage.clone());
    for (name, value) in tags {
        attributes.insert(format!("tags.{name}"), Value::String(value.clone()));
    }
    Ok(attributes)
}

// ---------------------------------------------------------------------------------------------------------------
// Key material

fn version_context(key_id: &str, version: f64) -> String {
    format!("kms-key:{key_id}:{}", number_to_string(version))
}

/// Where sealed key material lives, for `iam.rotateSecrets()` (secrets.rs keeps the executable form).
pub fn kms_sealed_field() -> IamResult<Value> {
    Ok(json!({
        "collection": "kmsKeyVersions",
        "filter": { "wrapper": "secret" },
        "field": "materialSealed",
        "context": "kms-key:{keyId}:{version}",
    }))
}

/// PEM armor with 64-character lines, as Node's `KeyObject.export({ format: 'pem' })` writes it.
fn pem_encode(label: &str, der: &[u8]) -> String {
    let body = STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for chunk in body.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// The label and DER of the first PEM block.
fn pem_decode(pem: &str) -> Option<(String, Vec<u8>)> {
    let begin = pem.find("-----BEGIN ")?;
    let rest = &pem[begin + 11..];
    let label_end = rest.find("-----")?;
    let label = rest[..label_end].to_owned();
    let body_start = &rest[label_end + 5..];
    let end = body_start.find(&format!("-----END {label}-----"))?;
    let body: String = body_start[..end]
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let der = STANDARD.decode(body.as_bytes()).ok()?;
    Some((label, der))
}

/// The PKCS#8 v1 prefix of an Ed25519 private key (RFC 8410), followed by the 32-byte seed.
const ED25519_PKCS8_PREFIX: [u8; 16] = [
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
];
/// The SPKI prefix of an Ed25519 public key, followed by the 32-byte key.
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];

/// A private key opened from its PKCS#8 PEM (`createPrivateKey(pem)`).
enum PrivateKey {
    P256(p256::SecretKey),
    P384(p384::SecretKey),
    Ed25519(Box<ed25519_dalek::SigningKey>),
    Rsa(Box<rsa::RsaPrivateKey>),
}

/// A public key opened from its SPKI PEM (`createPublicKey(pem)`).
enum PublicKey {
    P256(p256::PublicKey),
    P384(p384::PublicKey),
    Ed25519(ed25519_dalek::VerifyingKey),
    Rsa(Box<rsa::RsaPublicKey>),
}

fn parse_private_key(pem: &str) -> Option<PrivateKey> {
    use p256::pkcs8::DecodePrivateKey;
    let (label, der) = pem_decode(pem)?;
    match label.as_str() {
        "PRIVATE KEY" => {}
        "RSA PRIVATE KEY" => {
            use rsa::pkcs1::DecodeRsaPrivateKey;
            return rsa::RsaPrivateKey::from_pkcs1_der(&der)
                .ok()
                .map(|key| PrivateKey::Rsa(Box::new(key)));
        }
        _ => return None,
    }
    if der.len() == 48 && der[..16] == ED25519_PKCS8_PREFIX {
        let seed: [u8; 32] = der[16..].try_into().ok()?;
        return Some(PrivateKey::Ed25519(Box::new(
            ed25519_dalek::SigningKey::from_bytes(&seed),
        )));
    }
    if let Ok(key) = p256::SecretKey::from_pkcs8_der(&der) {
        return Some(PrivateKey::P256(key));
    }
    if let Ok(key) = p384::SecretKey::from_pkcs8_der(&der) {
        return Some(PrivateKey::P384(key));
    }
    if let Ok(key) = ed25519_dalek::SigningKey::from_pkcs8_der(&der) {
        return Some(PrivateKey::Ed25519(Box::new(key)));
    }
    rsa::RsaPrivateKey::from_pkcs8_der(&der)
        .ok()
        .map(|key| PrivateKey::Rsa(Box::new(key)))
}

fn parse_public_key(pem: &str) -> Option<PublicKey> {
    use p256::pkcs8::DecodePublicKey;
    let (label, der) = pem_decode(pem)?;
    if label != "PUBLIC KEY" {
        return None;
    }
    if der.len() == 44 && der[..12] == ED25519_SPKI_PREFIX {
        let bytes: [u8; 32] = der[12..].try_into().ok()?;
        return ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .ok()
            .map(PublicKey::Ed25519);
    }
    if let Ok(key) = p256::PublicKey::from_public_key_der(&der) {
        return Some(PublicKey::P256(key));
    }
    if let Ok(key) = p384::PublicKey::from_public_key_der(&der) {
        return Some(PublicKey::P384(key));
    }
    rsa::RsaPublicKey::from_public_key_der(&der)
        .ok()
        .map(|key| PublicKey::Rsa(Box::new(key)))
}

/// New key material: raw bytes (base64url) for AES and HMAC keys, a PKCS#8 PEM private key otherwise (with the
/// SPKI PEM public key). Runs on a blocking thread: RSA-4096 generation is slow.
fn generate_material_now(info: SpecInfo) -> IamResult<(String, Option<String>)> {
    use p256::pkcs8::{EncodePrivateKey, EncodePublicKey};
    let mut rng = rand::rngs::OsRng;
    fn encoded<T, E>(result: Result<T, E>) -> IamResult<T> {
        result.map_err(|_| internal_error())
    }
    match info.family {
        "aes" => Ok((base64url(random_bytes(32)), None)),
        "hmac" => Ok((base64url(random_bytes(info.size.unwrap_or(32))), None)),
        "ec" if info.curve == Some("P-256") => {
            let secret = p256::SecretKey::random(&mut rng);
            let private = encoded(secret.to_pkcs8_der())?;
            let public = encoded(secret.public_key().to_public_key_der())?;
            Ok((
                pem_encode("PRIVATE KEY", private.as_bytes()),
                Some(pem_encode("PUBLIC KEY", public.as_bytes())),
            ))
        }
        "ec" => {
            let secret = p384::SecretKey::random(&mut rng);
            let private = encoded(secret.to_pkcs8_der())?;
            let public = encoded(secret.public_key().to_public_key_der())?;
            Ok((
                pem_encode("PRIVATE KEY", private.as_bytes()),
                Some(pem_encode("PUBLIC KEY", public.as_bytes())),
            ))
        }
        "ed25519" => {
            let seed: [u8; 32] = random_bytes(32).try_into().map_err(|_| internal_error())?;
            let signing = ed25519_dalek::SigningKey::from_bytes(&seed);
            let mut private = ED25519_PKCS8_PREFIX.to_vec();
            private.extend_from_slice(&seed);
            let mut public = ED25519_SPKI_PREFIX.to_vec();
            public.extend_from_slice(signing.verifying_key().as_bytes());
            Ok((
                pem_encode("PRIVATE KEY", &private),
                Some(pem_encode("PUBLIC KEY", &public)),
            ))
        }
        _ => {
            let bits = info.size.ok_or_else(internal_error)?;
            let key =
                rsa::RsaPrivateKey::new_with_exp(&mut rng, bits, &rsa::BigUint::from(65_537u32))
                    .map_err(|_| internal_error())?;
            let private = encoded(key.to_pkcs8_der())?;
            let public = encoded(key.to_public_key().to_public_key_der())?;
            Ok((
                pem_encode("PRIVATE KEY", private.as_bytes()),
                Some(pem_encode("PUBLIC KEY", public.as_bytes())),
            ))
        }
    }
}

async fn generate_material(spec: &str) -> IamResult<(String, Option<String>)> {
    let info = known_spec(spec)?;
    if matches!(info.family, "aes" | "hmac") {
        return generate_material_now(info);
    }
    match tokio::runtime::Handle::try_current() {
        Ok(handle) => handle
            .spawn_blocking(move || generate_material_now(info))
            .await
            .map_err(|_| internal_error())?,
        Err(_) => generate_material_now(info),
    }
}

/// Generates, seals and stores a new version of a key.
pub async fn add_key_version(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    key: &Value,
    version: f64,
    origin: &str,
) -> IamResult<crate::kms::KmsKeyVersion> {
    let key_id = js_string(key.get("id"));
    let (material, public_key_pem) = generate_material(&js_string(key.get("keySpec"))).await?;
    let mut record = Record::new();
    record.insert("id".into(), Value::String(id()));
    record.insert(
        "tenantId".into(),
        key.get("tenantId").cloned().unwrap_or(Value::Null),
    );
    record.insert(
        "uniqueKey".into(),
        Value::String(format!("{key_id}:{}", number_to_string(version))),
    );
    record.insert("keyId".into(), Value::String(key_id.clone()));
    record.insert("version".into(), number(version));
    record.insert("wrapper".into(), Value::String("secret".into()));
    record.insert(
        "materialSealed".into(),
        Value::String(encrypt_secret(
            &material,
            &ctx.options.secret,
            &version_context(&key_id, version),
        )),
    );
    record.insert("createdAt".into(), number(ctx.now()));
    record.insert("origin".into(), Value::String(origin.into()));
    if let Some(pem) = public_key_pem {
        record.insert("publicKeyPem".into(), Value::String(pem));
    }
    decode(tx.insert("kmsKeyVersions", &record).await?)
}

pub async fn key_version(
    tx: &Store,
    key: &Value,
    version: f64,
) -> IamResult<crate::kms::KmsKeyVersion> {
    let filter = Filter::new()
        .eq(
            "tenantId",
            key.get("tenantId").cloned().unwrap_or(Value::Null),
        )
        .eq(
            "uniqueKey",
            format!("{}:{}", js_string(key.get("id")), number_to_string(version)),
        );
    match tx
        .find("kmsKeyVersions", &filter, &FindOptions::default())
        .await?
        .into_iter()
        .next()
    {
        Some(found) => decode(found),
        None => Err(IamError::with_status(
            "NOT_FOUND",
            "Key version not found",
            404,
        )),
    }
}

/// Opens a version's sealed material with the deployment secret (or a previous one during a rotation).
fn open_material(ctx: &ServerContext, version: &KmsKeyVersion) -> IamResult<String> {
    let mut secrets = vec![ctx.options.secret.clone()];
    secrets.extend(ctx.options.previous_secrets.clone().unwrap_or_default());
    open_secret(
        &version.material_sealed,
        &secrets,
        &version_context(&version.key_id, version.version),
    )
    .map(|(value, _)| value)
    .ok_or_else(|| {
        IamError::with_status(
            "KEY_MATERIAL_UNAVAILABLE",
            "The key material cannot be opened with the configured secrets",
            500,
        )
    })
}

fn symmetric_key(ctx: &ServerContext, version: &KmsKeyVersion) -> IamResult<Vec<u8>> {
    Ok(node_base64_decode(&open_material(ctx, version)?))
}

fn private_key(ctx: &ServerContext, version: &KmsKeyVersion) -> IamResult<PrivateKey> {
    parse_private_key(&open_material(ctx, version)?).ok_or_else(internal_error)
}

fn public_key(version: &KmsKeyVersion) -> IamResult<PublicKey> {
    match version.public_key_pem.as_deref() {
        Some(pem) if !pem.is_empty() => parse_public_key(pem).ok_or_else(internal_error),
        _ => Err(invalid("This key has no public key")),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Ciphertexts: `kms1.{keyId}.{version}.{t|b}.{payload}`. The header (with the plaintext form `t` text / `b` bytes)
// and the canonical encryption context are authenticated; the payload is iv|tag|ciphertext (AES-GCM) or the
// RSA-OAEP (SHA-256) ciphertext, whose label carries the same associated data.

/// `CiphertextHeader`.
#[derive(Debug, Clone, PartialEq)]
pub struct CiphertextHeader {
    pub key_id: String,
    pub version: f64,
    pub text: bool,
    pub payload: Vec<u8>,
    pub header: String,
}

pub fn parse_ciphertext(value: Option<&Value>) -> IamResult<CiphertextHeader> {
    let invalid =
        || IamError::with_status("INVALID_CIPHERTEXT", "The ciphertext is not valid", 400);
    let Some(Value::String(value)) = value else {
        return Err(invalid());
    };
    if utf16_len(value) > MAX_CIPHERTEXT_CHARS {
        return Err(invalid());
    }
    let parts: Vec<&str> = value.split('.').collect();
    if parts.len() != 5 || parts[0] != CIPHERTEXT_PREFIX {
        return Err(invalid());
    }
    let (key_id, version_text, form, encoded) = (parts[1], parts[2], parts[3], parts[4]);
    if !key_id_like(key_id) || !version_digits(version_text) {
        return Err(invalid());
    }
    if form != "t" && form != "b" {
        return Err(invalid());
    }
    if encoded.is_empty() || !base64url_chars(encoded) {
        return Err(invalid());
    }
    let payload = node_base64_decode(encoded);
    // One spelling per ciphertext: non-canonical trailing bits would give the same bytes several string forms.
    if base64url(&payload) != encoded {
        return Err(invalid());
    }
    Ok(CiphertextHeader {
        key_id: key_id.to_owned(),
        version: version_text.parse::<f64>().map_err(|_| invalid())?,
        text: form == "t",
        payload,
        header: format!("{CIPHERTEXT_PREFIX}.{key_id}.{version_text}.{form}"),
    })
}

fn associated_data(header: &str, context: &EncryptionContext) -> String {
    format!(
        "{header}\n{}",
        canonicalize_json(&Value::Object(context.extra.clone()))
    )
}

fn oaep_capacity(spec: &str) -> IamResult<usize> {
    let bits = known_spec(spec)?.size.ok_or_else(internal_error)?;
    Ok(bits / 8 - 2 * 32 - 2)
}

/// AES-256-GCM: `iv|tag|ciphertext`.
fn aes_seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> IamResult<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| internal_error())?;
    let iv = random_bytes(12);
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&iv),
            AeadPayload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| internal_error())?;
    let (encrypted, tag) = sealed.split_at(sealed.len() - 16);
    let mut out = iv;
    out.extend_from_slice(tag);
    out.extend_from_slice(encrypted);
    Ok(out)
}

/// Opens `iv|tag|ciphertext`; None when the key, the data or the associated data do not authenticate.
fn aes_open(key: &[u8], payload: &[u8], aad: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 28 {
        return None;
    }
    let cipher = Aes256Gcm::new_from_slice(key).ok()?;
    let mut sealed = payload[28..].to_vec();
    sealed.extend_from_slice(&payload[12..28]);
    cipher
        .decrypt(
            Nonce::from_slice(&payload[..12]),
            AeadPayload { msg: &sealed, aad },
        )
        .ok()
}

pub fn encrypt_with(
    ctx: &Arc<ServerContext>,
    key: &crate::kms::KmsKey,
    version: &crate::kms::KmsKeyVersion,
    plaintext: &[u8],
    is_text: bool,
    context: &crate::kms::EncryptionContext,
) -> IamResult<String> {
    let header = format!(
        "{CIPHERTEXT_PREFIX}.{}.{}.{}",
        key.id,
        number_to_string(version.version),
        if is_text { "t" } else { "b" }
    );
    let aad = associated_data(&header, context);
    if spec_family(key.spec()) == "rsa" {
        let capacity = oaep_capacity(key.spec())?;
        if plaintext.len() > capacity {
            return Err(invalid(format!(
                "{} keys encrypt at most {capacity} bytes; encrypt a data key instead",
                key.spec()
            )));
        }
        let PublicKey::Rsa(public) = public_key(version)? else {
            return Err(internal_error());
        };
        let encrypted = public
            .encrypt(
                &mut rand::rngs::OsRng,
                rsa::Oaep::new_with_label::<Sha256, _>(aad),
                plaintext,
            )
            .map_err(|_| internal_error())?;
        return Ok(format!("{header}.{}", base64url(encrypted)));
    }
    if plaintext.len() as f64 > MAX_PLAINTEXT_BYTES {
        return Err(invalid(format!(
            "Encrypt at most {} bytes directly; use generateDataKey for more",
            number_to_string(MAX_PLAINTEXT_BYTES)
        )));
    }
    let sealed = aes_seal(&symmetric_key(ctx, version)?, plaintext, aad.as_bytes())?;
    Ok(format!("{header}.{}", base64url(sealed)))
}

/// Decrypts; any tampering, wrong key version or different encryption context fails the same way.
pub fn decrypt_with(
    ctx: &Arc<ServerContext>,
    key: &crate::kms::KmsKey,
    version: &crate::kms::KmsKeyVersion,
    parsed: &CiphertextHeader,
    context: &crate::kms::EncryptionContext,
) -> IamResult<Vec<u8>> {
    let aad = associated_data(&parsed.header, context);
    let attempt = || -> IamResult<Option<Vec<u8>>> {
        if spec_family(key.spec()) == "rsa" {
            let PrivateKey::Rsa(private) = private_key(ctx, version)? else {
                return Ok(None);
            };
            return Ok(private
                .decrypt_blinded(
                    &mut rand::rngs::OsRng,
                    rsa::Oaep::new_with_label::<Sha256, _>(aad.clone()),
                    &parsed.payload,
                )
                .ok());
        }
        if parsed.payload.len() < 28 {
            return Ok(None);
        }
        Ok(aes_open(
            &symmetric_key(ctx, version)?,
            &parsed.payload,
            aad.as_bytes(),
        ))
    };
    match attempt() {
        Ok(Some(plaintext)) => Ok(plaintext),
        Err(error) if error.code == "KEY_MATERIAL_UNAVAILABLE" => Err(error),
        _ => Err(IamError::with_status(
            "INVALID_CIPHERTEXT",
            "The ciphertext could not be decrypted with this key and encryption context",
            400,
        )),
    }
}

// ---------------------------------------------------------------------------------------------------------------
// Signatures and MACs

/// `hashOf(algorithm)`.
fn hash_of(algorithm: &str) -> &'static str {
    if algorithm.ends_with("384") {
        "sha384"
    } else if algorithm.ends_with("512") {
        "sha512"
    } else {
        "sha256"
    }
}

fn jose_format(format: Option<&Value>) -> bool {
    format.and_then(Value::as_str) == Some("jose")
}

pub fn sign_with(
    ctx: &Arc<ServerContext>,
    version: &crate::kms::KmsKeyVersion,
    algorithm: &str,
    message: &[u8],
    format: Option<&crate::kms::SignatureFormat>,
) -> IamResult<Vec<u8>> {
    use rsa::signature::{RandomizedSigner, SignatureEncoding, Signer};
    let key = private_key(ctx, version)?;
    let jose = jose_format(format);
    let mismatch = internal_error;
    if algorithm == "EdDSA" {
        let PrivateKey::Ed25519(key) = key else {
            return Err(mismatch());
        };
        return Ok(key.sign(message).to_bytes().to_vec());
    }
    if algorithm.starts_with("ES") {
        return match (key, hash_of(algorithm)) {
            (PrivateKey::P256(key), "sha256") => {
                let signature: p256::ecdsa::Signature =
                    p256::ecdsa::SigningKey::from(key).sign(message);
                Ok(if jose {
                    signature.to_bytes().to_vec()
                } else {
                    signature.to_der().as_bytes().to_vec()
                })
            }
            (PrivateKey::P384(key), "sha384") => {
                let signature: p384::ecdsa::Signature =
                    p384::ecdsa::SigningKey::from(key).sign(message);
                Ok(if jose {
                    signature.to_bytes().to_vec()
                } else {
                    signature.to_der().as_bytes().to_vec()
                })
            }
            _ => Err(mismatch()),
        };
    }
    let PrivateKey::Rsa(key) = key else {
        return Err(mismatch());
    };
    let key = *key;
    let mut rng = rand::rngs::OsRng;
    let signature = if algorithm.starts_with("PS") {
        match hash_of(algorithm) {
            "sha384" => rsa::pss::SigningKey::<Sha384>::new(key)
                .try_sign_with_rng(&mut rng, message)
                .map(|signature| signature.to_vec()),
            "sha512" => rsa::pss::SigningKey::<Sha512>::new(key)
                .try_sign_with_rng(&mut rng, message)
                .map(|signature| signature.to_vec()),
            _ => rsa::pss::SigningKey::<Sha256>::new(key)
                .try_sign_with_rng(&mut rng, message)
                .map(|signature| signature.to_vec()),
        }
    } else {
        match hash_of(algorithm) {
            "sha384" => rsa::pkcs1v15::SigningKey::<Sha384>::new(key)
                .try_sign(message)
                .map(|signature| signature.to_vec()),
            "sha512" => rsa::pkcs1v15::SigningKey::<Sha512>::new(key)
                .try_sign(message)
                .map(|signature| signature.to_vec()),
            _ => rsa::pkcs1v15::SigningKey::<Sha256>::new(key)
                .try_sign(message)
                .map(|signature| signature.to_vec()),
        }
    };
    signature.map_err(|_| internal_error())
}

pub fn verify_with(
    version: &crate::kms::KmsKeyVersion,
    algorithm: &str,
    message: &[u8],
    signature: &[u8],
    format: Option<&crate::kms::SignatureFormat>,
) -> IamResult<bool> {
    use rsa::signature::Verifier;
    let key = public_key(version)?;
    let jose = jose_format(format);
    let valid = if algorithm == "EdDSA" {
        match (&key, ed25519_dalek::Signature::from_slice(signature)) {
            (PublicKey::Ed25519(key), Ok(signature)) => key.verify(message, &signature).is_ok(),
            _ => false,
        }
    } else if algorithm.starts_with("ES") {
        match (&key, hash_of(algorithm)) {
            (PublicKey::P256(key), "sha256") => {
                let parsed = if jose {
                    p256::ecdsa::Signature::from_slice(signature)
                } else {
                    p256::ecdsa::Signature::from_der(signature)
                };
                parsed.is_ok_and(|signature| {
                    p256::ecdsa::VerifyingKey::from(key)
                        .verify(message, &signature)
                        .is_ok()
                })
            }
            (PublicKey::P384(key), "sha384") => {
                let parsed = if jose {
                    p384::ecdsa::Signature::from_slice(signature)
                } else {
                    p384::ecdsa::Signature::from_der(signature)
                };
                parsed.is_ok_and(|signature| {
                    p384::ecdsa::VerifyingKey::from(key)
                        .verify(message, &signature)
                        .is_ok()
                })
            }
            _ => false,
        }
    } else if let PublicKey::Rsa(key) = &key {
        let key = (**key).clone();
        let Ok(parsed) = rsa::pkcs1v15::Signature::try_from(signature) else {
            return Ok(false);
        };
        let pss = || rsa::pss::Signature::try_from(signature);
        match (algorithm.starts_with("PS"), hash_of(algorithm)) {
            (true, hash) => match pss() {
                Ok(signature) => match hash {
                    "sha384" => rsa::pss::VerifyingKey::<Sha384>::new(key)
                        .verify(message, &signature)
                        .is_ok(),
                    "sha512" => rsa::pss::VerifyingKey::<Sha512>::new(key)
                        .verify(message, &signature)
                        .is_ok(),
                    _ => rsa::pss::VerifyingKey::<Sha256>::new(key)
                        .verify(message, &signature)
                        .is_ok(),
                },
                Err(_) => false,
            },
            (false, "sha384") => rsa::pkcs1v15::VerifyingKey::<Sha384>::new(key)
                .verify(message, &parsed)
                .is_ok(),
            (false, "sha512") => rsa::pkcs1v15::VerifyingKey::<Sha512>::new(key)
                .verify(message, &parsed)
                .is_ok(),
            (false, _) => rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key)
                .verify(message, &parsed)
                .is_ok(),
        }
    } else {
        false
    };
    Ok(valid)
}

fn hmac_digest(hash: &str, key: &[u8], message: &[u8]) -> IamResult<Vec<u8>> {
    macro_rules! digest {
        ($hash:ty) => {{
            let mut mac =
                <Hmac<$hash> as Mac>::new_from_slice(key).map_err(|_| internal_error())?;
            mac.update(message);
            mac.finalize().into_bytes().to_vec()
        }};
    }
    Ok(match hash {
        "sha384" => digest!(Sha384),
        "sha512" => digest!(Sha512),
        _ => digest!(Sha256),
    })
}

pub fn mac_with(
    ctx: &Arc<ServerContext>,
    key: &Value,
    version: &crate::kms::KmsKeyVersion,
    message: &[u8],
) -> IamResult<Vec<u8>> {
    let hash = known_spec(&js_string(key.get("keySpec")))?
        .hash
        .ok_or_else(internal_error)?;
    hmac_digest(hash, &symmetric_key(ctx, version)?, message)
}

pub fn same_bytes(left: &[u8], right: &[u8]) -> IamResult<bool> {
    use subtle::ConstantTimeEq;
    Ok(left.len() == right.len() && bool::from(left.ct_eq(right)))
}

/// The public key of an asymmetric version as a JWK, `kid` = `{keyId}.{version}`.
pub fn public_jwk(
    key: &crate::kms::KmsKey,
    version: &crate::kms::KmsKeyVersion,
) -> IamResult<Value> {
    use rsa::traits::PublicKeyParts;
    let mut jwk = Map::new();
    match public_key(version)? {
        PublicKey::P256(public) => {
            let point =
                p256::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&public, false);
            jwk.insert("kty".into(), json!("EC"));
            jwk.insert(
                "x".into(),
                json!(base64url(point.x().ok_or_else(internal_error)?)),
            );
            jwk.insert(
                "y".into(),
                json!(base64url(point.y().ok_or_else(internal_error)?)),
            );
            jwk.insert("crv".into(), json!("P-256"));
        }
        PublicKey::P384(public) => {
            let point =
                p384::elliptic_curve::sec1::ToEncodedPoint::to_encoded_point(&public, false);
            jwk.insert("kty".into(), json!("EC"));
            jwk.insert(
                "x".into(),
                json!(base64url(point.x().ok_or_else(internal_error)?)),
            );
            jwk.insert(
                "y".into(),
                json!(base64url(point.y().ok_or_else(internal_error)?)),
            );
            jwk.insert("crv".into(), json!("P-384"));
        }
        PublicKey::Ed25519(public) => {
            jwk.insert("crv".into(), json!("Ed25519"));
            jwk.insert("x".into(), json!(base64url(public.as_bytes())));
            jwk.insert("kty".into(), json!("OKP"));
        }
        PublicKey::Rsa(public) => {
            jwk.insert("kty".into(), json!("RSA"));
            jwk.insert("n".into(), json!(base64url(public.n().to_bytes_be())));
            jwk.insert("e".into(), json!(base64url(public.e().to_bytes_be())));
        }
    }
    jwk.insert(
        "kid".into(),
        Value::String(format!("{}.{}", key.id, number_to_string(version.version))),
    );
    jwk.insert(
        "use".into(),
        json!(if key.usage() == "sign" { "sig" } else { "enc" }),
    );
    let algorithms = algorithms_for(key.spec(), key.usage())?;
    if key.usage() == "sign" && algorithms.len() == 1 {
        jwk.insert("alg".into(), Value::String(algorithms[0].clone()));
    }
    // No `alg` for RSA encryption keys: KMS binds its header and encryption context as the OAEP label, so what a
    // plain RSA-OAEP-256 encrypter produces offline is not a KMS ciphertext.
    Ok(Value::Object(jwk))
}

/// A parsed `kid`.
#[derive(Debug, Clone, PartialEq)]
pub struct Kid {
    pub key_id: String,
    pub version: f64,
}

/// [`parse_kid`], typed.
pub(crate) fn parse_kid_typed(value: Option<&Value>) -> Option<Kid> {
    let Some(Value::String(value)) = value else {
        return None;
    };
    let (key_id, version) = value.split_once('.')?;
    if !key_id_like(key_id) || !version_digits(version) {
        return None;
    }
    Some(Kid {
        key_id: key_id.to_owned(),
        version: version.parse().ok()?,
    })
}

/// A JWT `kid` of the form `{keyId}.{version}`: `{ keyId, version }`.
pub fn parse_kid(value: Option<&Value>) -> IamResult<Option<Value>> {
    Ok(parse_kid_typed(value)
        .map(|kid| json!({ "keyId": kid.key_id, "version": number(kid.version) })))
}

// ---------------------------------------------------------------------------------------------------------------
// Grants

pub fn grant_operations(
    value: Option<&Value>,
    usage: &crate::kms::KeyUsage,
) -> IamResult<Vec<crate::kms::GrantOperation>> {
    let items = match value {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= 8 => items,
        _ => return Err(invalid("operations must list 1-8 grant operations")),
    };
    let usage = js_string(Some(usage));
    let allowed = operations_by_usage(&usage);
    let mut operations: Vec<Value> = Vec::new();
    for item in items {
        if !operations.contains(item) {
            operations.push(item.clone());
        }
    }
    for operation in &operations {
        match operation {
            Value::String(name) if allowed.contains(&name.as_str()) => {}
            _ => {
                return Err(invalid(format!(
                    "A {usage} key's grants may allow {}",
                    allowed.join(", ")
                )));
            }
        }
    }
    operations.sort_by(|a, b| cmp_utf16(&js_string(Some(a)), &js_string(Some(b))));
    Ok(operations)
}

fn string_pairs(context: EncryptionContext) -> IndexMap<String, String> {
    context
        .extra
        .into_iter()
        .map(|(key, value)| (key, js_string(Some(&value))))
        .collect()
}

pub fn grant_constraints(
    value: Option<&Value>,
    operations: &[crate::kms::GrantOperation],
) -> IamResult<Option<crate::kms::GrantConstraints>> {
    let Some(value) = value else {
        return Ok(None);
    };
    let input = object(Some(value))?;
    for name in js_keys(input) {
        if name != "encryptionContextEquals" && name != "encryptionContextSubset" {
            return Err(invalid(format!("Unknown grant constraint {name}")));
        }
    }
    let mut constraints = GrantConstraints {
        encryption_context_equals: None,
        encryption_context_subset: None,
        extra: Map::new(),
    };
    if let Some(equals) = input.get("encryptionContextEquals") {
        constraints.encryption_context_equals = Some(string_pairs(encryption_context(
            Some(equals),
            Some("encryptionContextEquals"),
        )?));
    }
    if let Some(subset) = input.get("encryptionContextSubset") {
        constraints.encryption_context_subset = Some(string_pairs(encryption_context(
            Some(subset),
            Some("encryptionContextSubset"),
        )?));
    }
    if constraints.encryption_context_equals.is_none()
        && constraints.encryption_context_subset.is_none()
    {
        return Err(invalid("constraints must name an encryption context"));
    }
    if operations
        .iter()
        .any(|operation| !context_operation(&js_string(Some(operation))))
    {
        return Err(invalid(
            "Encryption context constraints apply only to encrypt, decrypt and generate-data-key grants",
        ));
    }
    Ok(Some(constraints))
}

fn context_satisfies(
    constraints: Option<&GrantConstraints>,
    context: Option<&EncryptionContext>,
) -> bool {
    let Some(constraints) = constraints else {
        return true;
    };
    let empty = Map::new();
    let actual = context.map_or(&empty, |context| &context.extra);
    if let Some(wanted) = &constraints.encryption_context_equals {
        if wanted.len() != actual.len() {
            return false;
        }
        if wanted
            .iter()
            .any(|(key, value)| actual.get(key).and_then(Value::as_str) != Some(value.as_str()))
        {
            return false;
        }
    }
    if let Some(subset) = &constraints.encryption_context_subset {
        for (key, value) in subset {
            if actual.get(key).and_then(Value::as_str) != Some(value.as_str()) {
                return false;
            }
        }
    }
    true
}

/// A session that acts in its own right: a user session or an API key, not derived, not "view as".
pub fn acts_in_own_right(principal: &better_iam_core::AuthenticatedPrincipal) -> IamResult<bool> {
    let session = &principal.session;
    Ok(
        matches!(session.kind, SessionKind::User | SessionKind::ApiKey)
            && !session
                .impersonator_id
                .as_deref()
                .is_some_and(|impersonator| !impersonator.is_empty())
            && session.source_session_id.is_none(),
    )
}

/// The live grants on the key that allow `operation` to the principal's own identity, satisfying their constraints,
/// oldest first. Grants serve people and machine accounts acting in their own right (user sessions and API keys):
/// assumed roles, session tokens, delegated agent sessions and impersonation never use them. The caller still
/// checks that each grant's creator could make the call now (api/keys.rs), so a grant never outlives its creator's
/// access.
pub async fn candidate_grants(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    key: &crate::kms::KmsKey,
    principal: &better_iam_core::AuthenticatedPrincipal,
    operation: &crate::kms::GrantOperation,
    context: Option<&crate::kms::EncryptionContext>,
) -> IamResult<Vec<crate::kms::KmsGrant>> {
    if !acts_in_own_right(principal)?
        || principal.session.tenant_id != key.tenant_id
        || principal.identity.tenant_id != key.tenant_id
    {
        return Ok(Vec::new());
    }
    let now = ctx.now();
    let records = tx
        .find(
            "kmsGrants",
            &Filter::new()
                .eq("tenantId", key.tenant_id.clone())
                .eq("keyId", key.id.clone())
                .eq("granteeId", principal.identity.id.clone()),
            &FindOptions::default(),
        )
        .await?;
    let mut grants = Vec::new();
    for record in records {
        let grant: KmsGrant = decode(record)?;
        if grant.grantee_type == "identity"
            && grant.expires_at.is_none_or(|expires| expires > now)
            && grant.operations.contains(operation)
            && context_satisfies(grant.constraints.as_ref(), context)
        {
            grants.push(grant);
        }
    }
    grants.sort_by(|a, b| {
        a.created_at
            .partial_cmp(&b.created_at)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                if cmp_utf16(&a.id, &b.id) == std::cmp::Ordering::Less {
                    std::cmp::Ordering::Less
                } else {
                    std::cmp::Ordering::Greater
                }
            })
    });
    Ok(grants)
}

// ---------------------------------------------------------------------------------------------------------------
// Lookups

/// [`find_key`] as the stored record (kept raw for read-modify-write).
pub(crate) async fn find_key_record(
    tx: &Store,
    tenant_id: &str,
    reference: Option<&Value>,
) -> IamResult<Record> {
    let not_found = || IamError::with_status("NOT_FOUND", "Key not found", 404);
    let value = text(reference, "keyId", 256)?;
    let key = if value.starts_with("alias/") {
        let alias = tx
            .find(
                "kmsAliases",
                &Filter::new()
                    .eq("tenantId", tenant_id.to_owned())
                    .eq("uniqueKey", value.clone()),
                &FindOptions::default(),
            )
            .await?
            .into_iter()
            .next();
        match alias {
            Some(alias) => tx.get("kmsKeys", &js_string(alias.get("keyId"))).await?,
            None => None,
        }
    } else if key_id_like(&value) {
        tx.get("kmsKeys", &value).await?
    } else {
        None
    };
    match key {
        Some(key) if key.get("tenantId").and_then(Value::as_str) == Some(tenant_id) => Ok(key),
        _ => Err(not_found()),
    }
}

/// A key by id or `alias/{name}` within a tenant.
pub async fn find_key(
    tx: &Store,
    tenant_id: &str,
    reference: Option<&Value>,
) -> IamResult<crate::kms::KmsKey> {
    decode(find_key_record(tx, tenant_id, reference).await?)
}

pub async fn alias_names(tx: &Store, key: &Value) -> IamResult<Vec<String>> {
    let records = tx
        .find(
            "kmsAliases",
            &Filter::new()
                .eq(
                    "tenantId",
                    key.get("tenantId").cloned().unwrap_or(Value::Null),
                )
                .eq("keyId", key.get("id").cloned().unwrap_or(Value::Null)),
            &FindOptions::default(),
        )
        .await?;
    let names: Vec<String> = records
        .iter()
        .map(|alias| js_string(alias.get("name")))
        .collect();
    Ok(sorted(&names))
}

pub fn assert_usable(key: &crate::kms::KmsKey, usage: &crate::kms::KeyUsage) -> IamResult<()> {
    if key.state_name() != "enabled" {
        return Err(IamError::with_status(
            "KEY_STATE_INVALID",
            if key.state_name() == "disabled" {
                "The key is disabled"
            } else {
                "The key is pending deletion"
            },
            409,
        ));
    }
    if key.key_usage != *usage {
        return Err(invalid(format!(
            "This key is for {}, not {}",
            key.usage(),
            js_string(Some(usage))
        )));
    }
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------
// Service helpers for other modules (the secrets vault): encryption under a tenant key without a caller permission
// check. The calling module authorizes its own caller; the key's state is still enforced and the use is audited.

/// `{ via, principal? }` as JSON (`principal` in the form `crate::conformance::principal_json` writes) to its typed
/// form; absent, `{ via: 'service' }`.
fn service_use_of(value: Option<&Value>) -> IamResult<KmsServiceUse> {
    let Some(value) = value else {
        return Ok(KmsServiceUse {
            via: "service".into(),
            principal: None,
        });
    };
    let principal = match value.get("principal") {
        None | Some(Value::Null) => None,
        Some(principal) => Some(principal_from_json(principal)?),
    };
    Ok(KmsServiceUse {
        // A `via` that is not a string fails `text(use.via, 'via', 64)` when the use is audited, as in TypeScript:
        // the control character stands in for the non-string value.
        via: match value.get("via") {
            Some(Value::String(via)) => via.clone(),
            _ => "\u{0}".into(),
        },
        principal,
    })
}

/// An `AuthenticatedPrincipal` from `{ identity, session, deviceProof? }`.
pub(crate) fn principal_from_json(value: &Value) -> IamResult<AuthenticatedPrincipal> {
    let identity: Identity =
        serde_json::from_value(value.get("identity").cloned().unwrap_or(Value::Null))
            .map_err(|_| internal_error())?;
    let session = serde_json::from_value(value.get("session").cloned().unwrap_or(Value::Null))
        .map_err(|_| internal_error())?;
    Ok(AuthenticatedPrincipal {
        identity,
        session,
        device_proof: value
            .get("deviceProof")
            .and_then(Value::as_str)
            .map(str::to_owned),
    })
}

async fn service_audit(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    r#use: &KmsServiceUse,
    action: &str,
    key: &KmsKey,
    metadata: Map<String, Value>,
) -> IamResult<()> {
    let mut details = metadata;
    details.insert(
        "via".into(),
        Value::String(text(Some(&Value::String(r#use.via.clone())), "via", 64)?),
    );
    let events = ctx.events()?;
    let resource_id = format!("kms/{}", key.id);
    match &r#use.principal {
        Some(principal) => {
            events
                .audit(
                    tx,
                    principal,
                    action,
                    &key.tenant_id,
                    &resource_id,
                    AuditOutcome::Allow,
                    false,
                    Some(details),
                )
                .await
        }
        None => {
            let mut event = Record::new();
            event.insert("id".into(), Value::String(id()));
            event.insert("tenantId".into(), Value::String(key.tenant_id.clone()));
            event.insert(
                "actorId".into(),
                Value::String("deployment-operator".into()),
            );
            event.insert("action".into(), Value::String(action.into()));
            event.insert("resourceId".into(), Value::String(resource_id));
            event.insert("timestamp".into(), number(ctx.now()));
            event.insert("outcome".into(), Value::String("allow".into()));
            event.insert("metadata".into(), Value::Object(details));
            events.record_audit(tx, &event).await
        }
    }
}

/// `serviceContext(context)`: a string context is bound as `{ context }`.
fn service_context(context: &Value) -> IamResult<EncryptionContext> {
    match context {
        Value::String(_) => {
            let mut extra = Map::new();
            extra.insert(
                "context".into(),
                Value::String(text(Some(context), "context", 1024)?),
            );
            Ok(EncryptionContext { extra })
        }
        other => encryption_context(Some(other), None),
    }
}

/// A key the service helpers accept: AES only, since they wrap data keys of any payload size.
fn service_key(key: &KmsKey) -> IamResult<()> {
    assert_usable(key, &Value::String("encrypt".into()))?;
    if key.spec() != "aes-256-gcm" {
        return Err(invalid("Only aes-256-gcm keys can protect stored values"));
    }
    Ok(())
}

/// At most 16 MiB through the service helpers.
const MAX_SERVICE_PLAINTEXT: usize = 16 * 1024 * 1024;

fn service_metadata(version: f64, context: &EncryptionContext) -> Map<String, Value> {
    let mut keys: Vec<String> = context.extra.keys().cloned().collect();
    keys.sort_by(|a, b| cmp_utf16(a, b));
    let mut metadata = Map::new();
    metadata.insert("keyVersion".into(), number(version));
    metadata.insert("encryptionContextKeys".into(), json!(keys));
    metadata
}

/// Encrypts a UTF-8 string of any size (up to 16 MiB) under a tenant's AES key (id or alias) by envelope
/// encryption: a fresh data key encrypts the value locally and the key's current version wraps the data key. The
/// result is `{wrapped data key}~{iv|tag|ciphertext}`, both bound to the encryption context (a string `context` is
/// bound as `{ context }`). Refuses disabled keys, keys pending deletion and non-AES keys.
///
/// `use` is `{ via, principal? }` (default `{ via: 'service' }`); the result is `{ ciphertext, keyId, keyVersion }`.
pub async fn kms_encrypt_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    key_ref: &str,
    plaintext: &str,
    context: &Value,
    r#use: Option<&Value>,
) -> IamResult<Value> {
    let service = service_use_of(r#use)?;
    let key = find_key(tx, tenant_id, Some(&Value::String(key_ref.to_owned()))).await?;
    service_key(&key)?;
    let value = plaintext.as_bytes();
    if value.len() > MAX_SERVICE_PLAINTEXT {
        return Err(invalid("The value is larger than 16 MiB"));
    }
    let version = key_version(tx, &key_json(&key), key.current_version).await?;
    let bound = service_context(context)?;
    let mut data_key = random_bytes(32);
    let result = async {
        let wrapped = encrypt_with(ctx, &key, &version, &data_key, false, &bound)?;
        // The wrapped key is associated data too, so a payload cannot be paired with another wrapped key.
        let sealed = aes_seal(
            &data_key,
            value,
            associated_data(&wrapped, &bound).as_bytes(),
        )?;
        service_audit(
            ctx,
            tx,
            &service,
            kms_action("encrypt"),
            &key,
            service_metadata(version.version, &bound),
        )
        .await?;
        Ok(json!({
            "ciphertext": format!("{wrapped}~{}", base64url(sealed)),
            "keyId": key.id,
            "keyVersion": number(version.version),
        }))
    }
    .await;
    data_key.fill(0);
    result
}

/// Decrypts what `kmsEncryptFor` returned; the key must still be enabled and the context the same.
///
/// `sealed` is `{ ciphertext, keyId?, keyVersion? }`, `use` `{ via, principal? }` (default `{ via: 'service' }`).
pub async fn kms_decrypt_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    sealed: &Value,
    context: &Value,
    r#use: Option<&Value>,
) -> IamResult<String> {
    let service = service_use_of(r#use)?;
    let invalid =
        || IamError::with_status("INVALID_CIPHERTEXT", "The ciphertext is not valid", 400);
    let ciphertext = match sealed.get("ciphertext") {
        Some(Value::String(ciphertext)) if utf16_len(ciphertext) <= 23_000_000 => ciphertext,
        _ => return Err(invalid()),
    };
    let mut pieces = ciphertext.split('~');
    let wrapped = pieces.next().unwrap_or_default();
    let payload = pieces.next().unwrap_or_default();
    if pieces.next().is_some() || payload.is_empty() || !base64url_chars(payload) {
        return Err(invalid());
    }
    let parsed = parse_ciphertext(Some(&Value::String(wrapped.to_owned())))?;
    if sealed
        .get("keyId")
        .is_some_and(|key_id| key_id.as_str() != Some(parsed.key_id.as_str()))
        || sealed
            .get("keyVersion")
            .is_some_and(|version| better_iam_core::js::as_number(version) != Some(parsed.version))
    {
        return Err(invalid());
    }
    let key = find_key(tx, tenant_id, Some(&Value::String(parsed.key_id.clone()))).await?;
    service_key(&key)?;
    let version = key_version(tx, &key_json(&key), parsed.version).await?;
    let bound = service_context(context)?;
    let mut data_key = decrypt_with(ctx, &key, &version, &parsed, &bound)?;
    let result = async {
        let bytes = node_base64_decode(payload);
        if bytes.len() < 28 || data_key.len() != 32 {
            return Err(invalid());
        }
        let Some(plaintext) = aes_open(
            &data_key,
            &bytes,
            associated_data(wrapped, &bound).as_bytes(),
        ) else {
            return Err(invalid());
        };
        service_audit(
            ctx,
            tx,
            &service,
            kms_action("decrypt"),
            &key,
            service_metadata(version.version, &bound),
        )
        .await?;
        Ok(String::from_utf8_lossy(&plaintext).into_owned())
    }
    .await;
    data_key.fill(0);
    result
}

/// A fresh 32-byte data key wrapped under a tenant AES key, for a module that protects many values in one call
/// (tokenization): the caller encrypts locally, stores `wrapped` beside the data, and must wipe `dataKey` after
/// use. Audited once as `iam:kms:generate-data-key` with `metadata.via`.
pub async fn kms_data_key_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    key_ref: &str,
    context: &crate::kms::EncryptionContext,
    r#use: &crate::kms::KmsServiceUse,
) -> IamResult<crate::kms::ServiceDataKey> {
    let key = find_key(tx, tenant_id, Some(&Value::String(key_ref.to_owned()))).await?;
    service_key(&key)?;
    let version = key_version(tx, &key_json(&key), key.current_version).await?;
    let bound = encryption_context(Some(&Value::Object(context.extra.clone())), None)?;
    let data_key = random_bytes(32);
    let wrapped = encrypt_with(ctx, &key, &version, &data_key, false, &bound)?;
    service_audit(
        ctx,
        tx,
        r#use,
        kms_action("generate-data-key"),
        &key,
        service_metadata(version.version, &bound),
    )
    .await?;
    Ok(ServiceDataKey {
        data_key,
        wrapped,
        key_id: key.id.clone(),
        key_version: version.version,
    })
}

/// Unwraps a data key from `kmsDataKeyFor`; the key must still be enabled and the context the same.
pub async fn kms_open_data_key_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    wrapped: &str,
    context: &crate::kms::EncryptionContext,
    r#use: &crate::kms::KmsServiceUse,
) -> IamResult<Vec<u8>> {
    let parsed = parse_ciphertext(Some(&Value::String(wrapped.to_owned())))?;
    let key = find_key(tx, tenant_id, Some(&Value::String(parsed.key_id.clone()))).await?;
    service_key(&key)?;
    let version = key_version(tx, &key_json(&key), parsed.version).await?;
    let bound = encryption_context(Some(&Value::Object(context.extra.clone())), None)?;
    let data_key = decrypt_with(ctx, &key, &version, &parsed, &bound)?;
    if data_key.len() != 32 {
        return Err(IamError::with_status(
            "INVALID_CIPHERTEXT",
            "The ciphertext is not valid",
            400,
        ));
    }
    service_audit(
        ctx,
        tx,
        r#use,
        kms_action("decrypt"),
        &key,
        service_metadata(version.version, &bound),
    )
    .await?;
    Ok(data_key)
}

/// Creates a key for another module's own use, such as a certificate authority's signing key, without a caller
/// permission check (the calling module authorizes its caller). The key is an ordinary KMS key: visible, taggable,
/// and disabled or deleted like any other.
///
/// `input` is `{ tenantId, keySpec, keyUsage, description, tags, createdBy, managedBy, managedId }`.
pub async fn create_service_key(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    input: &Value,
) -> IamResult<crate::kms::KmsKey> {
    let tenant_id = js_string(input.get("tenantId"));
    let existing = tx
        .find(
            "kmsKeys",
            &Filter::new().eq("tenantId", tenant_id.clone()),
            &FindOptions::default(),
        )
        .await?;
    if existing.len() as f64 >= MAX_KEYS_PER_TENANT {
        return Err(IamError::with_status(
            "LIMIT_EXCEEDED",
            format!(
                "A tenant keeps at most {} keys",
                number_to_string(MAX_KEYS_PER_TENANT)
            ),
            409,
        ));
    }
    let now = ctx.now();
    let spec = input.get("keySpec").cloned().unwrap_or(Value::Null);
    let description = text(input.get("description"), "description", 512)?;
    let usage = key_usage_for(&spec, input.get("keyUsage"))?;
    let tags = key_tags(input.get("tags"))?;
    let mut key = Record::new();
    key.insert("id".into(), Value::String(id()));
    key.insert("tenantId".into(), Value::String(tenant_id));
    key.insert("description".into(), Value::String(description));
    key.insert("keySpec".into(), spec);
    key.insert("keyUsage".into(), usage);
    key.insert("state".into(), Value::String("enabled".into()));
    key.insert("currentVersion".into(), number(1.0));
    key.insert("tags".into(), json!(tags));
    key.insert(
        "managedBy".into(),
        input.get("managedBy").cloned().unwrap_or(Value::Null),
    );
    key.insert(
        "managedId".into(),
        input.get("managedId").cloned().unwrap_or(Value::Null),
    );
    key.insert("createdAt".into(), number(now));
    key.insert(
        "createdBy".into(),
        input.get("createdBy").cloned().unwrap_or(Value::Null),
    );
    key.insert("updatedAt".into(), number(now));
    tx.insert("kmsKeys", &key).await?;
    let key_value = Value::Object(key.clone());
    add_key_version(ctx, tx, &key_value, 1.0, "create").await?;
    decode(key)
}

/// Schedules deletion of a key a module created for its own use once the module is done with it (a deleted data
/// protection profile), after the shortest waiting period. Keys the module does not manage are left alone. Returns
/// the deletion date, or undefined when nothing was scheduled.
pub async fn retire_service_key(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    key_id: &str,
    managed_by: &str,
    managed_id: &str,
) -> IamResult<Option<f64>> {
    let Some(mut key) = tx.get("kmsKeys", key_id).await? else {
        return Ok(None);
    };
    let member = |name: &str| key.get(name).and_then(Value::as_str).map(str::to_owned);
    if member("tenantId").as_deref() != Some(tenant_id)
        || member("managedBy").as_deref() != Some(managed_by)
        || member("managedId").as_deref() != Some(managed_id)
        || member("state").as_deref() == Some("pending-deletion")
    {
        return Ok(None);
    }
    let now = ctx.now();
    let deletion_date = now + 7.0 * 86_400_000.0;
    key.insert("state".into(), Value::String("pending-deletion".into()));
    key.insert("deletionDate".into(), number(deletion_date));
    key.insert("updatedAt".into(), number(now));
    tx.put("kmsKeys", &key).await?;
    Ok(Some(deletion_date))
}

/// Signs `data` with one pinned version of a signing key for another module (a certificate authority signing
/// certificates and CRLs). The key must be enabled; the use is audited as `iam:kms:sign` with `metadata.via`.
///
/// `use` is `{ via, principal? }`.
#[allow(clippy::too_many_arguments)]
pub async fn kms_sign_for(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    key_id: &str,
    version: f64,
    algorithm: &str,
    data: &[u8],
    r#use: &KmsServiceUse,
) -> IamResult<Vec<u8>> {
    let service = r#use;
    let key = find_key(tx, tenant_id, Some(&Value::String(key_id.to_owned()))).await?;
    assert_usable(&key, &Value::String("sign".into()))?;
    if !algorithms_for(key.spec(), key.usage())?.contains(&algorithm.to_owned()) {
        return Err(invalid(format!("This key does not sign with {algorithm}")));
    }
    let pinned = key_version(tx, &key_json(&key), version).await?;
    let signature = sign_with(ctx, &pinned, algorithm, data, None)?;
    let mut metadata = Map::new();
    metadata.insert("keyVersion".into(), number(version));
    metadata.insert("algorithm".into(), Value::String(algorithm.into()));
    service_audit(ctx, tx, service, kms_action("sign"), &key, metadata).await?;
    Ok(signature)
}

/// A short fingerprint of public material, for listings (never of secret material).
pub fn fingerprint(pem: &str) -> IamResult<String> {
    let digest = base64url(Sha256::digest(pem.as_bytes()));
    Ok(digest.chars().take(16).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_bytes_accepts_canonical_spellings_only() {
        let value = |text: &str| Value::String(text.into());
        assert_eq!(base64_bytes(Some(&value("aGk")), "x", 10.0).unwrap(), b"hi");
        assert_eq!(
            base64_bytes(Some(&value("aGk=")), "x", 10.0).unwrap(),
            b"hi"
        );
        assert_eq!(
            base64_bytes(Some(&value("aGl")), "x", 10.0)
                .unwrap_err()
                .message,
            "x must be canonical base64"
        );
        assert_eq!(
            base64_bytes(Some(&value("a b")), "x", 10.0)
                .unwrap_err()
                .message,
            "x must be base64"
        );
        assert_eq!(
            base64_bytes(Some(&value("aGVsbG8gd29ybGQ")), "x", 4.0)
                .unwrap_err()
                .message,
            "x must be base64"
        );
    }

    #[test]
    fn parses_ciphertexts_and_kids() {
        let parsed = parse_ciphertext(Some(&Value::String("kms1.abc-1.12.t.AAAA".into()))).unwrap();
        assert_eq!(parsed.key_id, "abc-1");
        assert_eq!(parsed.version, 12.0);
        assert!(parsed.text);
        assert_eq!(parsed.header, "kms1.abc-1.12.t");
        for bad in [
            "kms2.a.1.t.AAAA",
            "kms1.a.0.t.AAAA",
            "kms1.a.1.x.AAAA",
            "kms1.a.1.t.",
            "kms1.a.1.t.AAB",
        ] {
            assert_eq!(
                parse_ciphertext(Some(&Value::String(bad.into())))
                    .unwrap_err()
                    .code,
                "INVALID_CIPHERTEXT"
            );
        }
        assert_eq!(
            parse_kid_typed(Some(&Value::String("key-1.3".into()))),
            Some(Kid {
                key_id: "key-1".into(),
                version: 3.0
            })
        );
        assert_eq!(parse_kid_typed(Some(&Value::String("key.03".into()))), None);
    }

    #[test]
    fn generates_material_node_can_open() {
        for spec in ["ecc-p256", "ecc-p384", "ed25519"] {
            let (private, public) = generate_material_now(spec_info(spec).unwrap()).unwrap();
            assert!(private.starts_with("-----BEGIN PRIVATE KEY-----\n"));
            assert!(parse_private_key(&private).is_some());
            assert!(parse_public_key(&public.unwrap()).is_some());
        }
    }
}
