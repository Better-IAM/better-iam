//! Port of `packages/server/src/devices.ts`.
//!
//! Device posture: registered devices, the keys that prove a request comes from one, and the compliance of the
//! devices an MDM or EDR integration manages. A browser or agent enrols a public key (`devices.enroll`); every
//! request can then carry a short-lived signed proof (`x-better-iam-device`) bound to the presenting session.
//! Decisions verify that proof against the stored key only (never a key the proof carries) and expose the device's
//! assurance to policies as `request.deviceAssurance`, `request.deviceManaged`, `request.deviceCompliant`,
//! `request.deviceId` and `request.devicePlatform`, read only when a document names them.
//!
//! Not to be confused with remembered browsers (`authDevices`, `TrustedDevice`), which skip a second factor: a
//! registered device never satisfies MFA and remembered browsers never count as registered devices.
//!
//! Stored records are read and written as raw JSON records (a mixed fleet shares the database with TypeScript), and
//! malformed stored values are judged as TypeScript judges them. The typed record structs below document the shapes.

use better_iam_core::js::{as_number, is_safe_integer, strict_equal, to_number, utf16_len};
use better_iam_core::{
    AuthenticatedPrincipal, Filter, FindOptions, IamResult, Identity, PolicyDocument, Record,
};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::context::Store;
use crate::session_tokens::jose::{decode_base64url, decode_protected_header, encode_base64url};

/// Why a device is not compliant (`not-managed`, `integration-disabled`, `stale`, `vendor-noncompliant`,
/// `not-encrypted`, `no-screen-lock`, `no-firewall`, `edr-unhealthy`, `jailbroken`, `os-too-old`, `os-unknown`,
/// `lost`, `retired`).
pub type ComplianceReason = String;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ComplianceResult {
    pub compliant: bool,
    pub managed: bool,
    /// Empty exactly when the device is compliant.
    pub reasons: Vec<ComplianceReason>,
}

impl ComplianceResult {
    /// The result as TypeScript encodes it: `{ compliant, managed, reasons }`.
    pub fn to_json(&self) -> Value {
        json!({ "compliant": self.compliant, "managed": self.managed, "reasons": self.reasons })
    }
}

/// What a request's device proves, weakest first: `none` (no valid proof), `registered` (a proof from an active
/// registered device), `managed` (an active integration manages that device) and `compliant` (it also meets the
/// tenant's requirements).
pub type DeviceAssurance = &'static str;

/// `DeviceIntegrationVendor` (one of [`DEVICE_INTEGRATION_VENDORS`]) as records hold it.
pub type DeviceIntegrationVendor = Value;

/// `DevicePlatform` (`windows`, `macos`, `linux`, `ios`, `android`, `chromeos`, `other`) as records hold it.
pub type DevicePlatform = Value;

/// A device's public key as stored: EC P-256 (ES256) or Ed25519 (EdDSA), public members only.
pub type DevicePublicJwk = Value;

/// `DeviceStatus` (`active`, `lost`, `retired`) as records hold it.
pub type DeviceStatus = Value;
/// A one-time code for binding a key to a device; only its hash is stored (uniqueKey = codeHash).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceEnrollment {
    #[serde(rename = "codeHash")]
    pub code_hash: String,
    /// Bind the key to this existing (usually managed) device; unset creates a new device on enrolment.
    #[serde(rename = "deviceId", default, skip_serializing_if = "Option::is_none")]
    pub device_id: Option<String>,
    /// Only this person may use the code; unset lets any person of the tenant use it (a shared device).
    #[serde(
        rename = "ownerIdentityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_identity_id: Option<String>,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "usedAt", default, skip_serializing_if = "Option::is_none")]
    pub used_at: Option<f64>,
    #[serde(rename = "usedBy", default, skip_serializing_if = "Option::is_none")]
    pub used_by: Option<String>,
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

/// An MDM or EDR system that reports devices and their posture (`devices.report`, with `iam:devices:report`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceIntegration {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "vendor")]
    pub vendor: crate::devices::DeviceIntegrationVendor,
    #[serde(rename = "status")]
    pub status: String,
    /// Accept the vendor's `compliant` verdict (still combined with the tenant's own requirements). Default true.
    #[serde(rename = "trustVendorCompliance")]
    pub trust_vendor_compliance: bool,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(
        rename = "lastReportAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_report_at: Option<f64>,
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

/// A key that proves requests come from a device. The id is the key's RFC 7638 thumbprint (base64url SHA-256).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceKey {
    #[serde(rename = "deviceId")]
    pub device_id: String,
    #[serde(rename = "jwk")]
    pub jwk: crate::devices::DevicePublicJwk,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    /// The last verified proof seen by `devices.check` (written at most once a minute).
    #[serde(
        rename = "lastUsedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_used_at: Option<f64>,
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

/// The last posture report from the integration that manages a device. Absent booleans are unknown.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DevicePosture {
    /// The vendor's own verdict; counts only while the integration has `trustVendorCompliance`.
    #[serde(rename = "compliant", default, skip_serializing_if = "Option::is_none")]
    pub compliant: Option<bool>,
    #[serde(rename = "encrypted", default, skip_serializing_if = "Option::is_none")]
    pub encrypted: Option<bool>,
    #[serde(rename = "firewall", default, skip_serializing_if = "Option::is_none")]
    pub firewall: Option<bool>,
    #[serde(
        rename = "screenLock",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub screen_lock: Option<bool>,
    #[serde(
        rename = "edrHealthy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub edr_healthy: Option<bool>,
    #[serde(
        rename = "jailbroken",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub jailbroken: Option<bool>,
    /// Dotted numeric version (`14.5.1`), at most 32 characters.
    #[serde(rename = "osVersion", default, skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,
    /// When the device checked in with the integration (epoch milliseconds).
    #[serde(rename = "reportedAt")]
    pub reported_at: f64,
    #[serde(rename = "integrationId")]
    pub integration_id: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The tenant's compliance requirements for managed devices; the id is the tenant id.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DeviceSettings {
    #[serde(rename = "requireEncrypted")]
    pub require_encrypted: bool,
    #[serde(rename = "requireScreenLock")]
    pub require_screen_lock: bool,
    #[serde(rename = "requireFirewall")]
    pub require_firewall: bool,
    #[serde(rename = "requireEdr")]
    pub require_edr: bool,
    /// Default true.
    #[serde(rename = "blockJailbroken")]
    pub block_jailbroken: bool,
    #[serde(rename = "minOsVersions")]
    pub min_os_versions: Value,
    /// 1 to 720 (default 24): a device that has not checked in for longer is not compliant.
    #[serde(rename = "maxCheckInAgeHours")]
    pub max_check_in_age_hours: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    #[serde(rename = "updatedBy")]
    pub updated_by: String,
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

/// A registered device: self-enrolled (unmanaged) or reported by an integration (managed).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RegisteredDevice {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "platform")]
    pub platform: crate::devices::DevicePlatform,
    #[serde(rename = "status")]
    pub status: crate::devices::DeviceStatus,
    /// The person the device belongs to; unset means a shared device any member of the tenant may present.
    #[serde(
        rename = "ownerIdentityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub owner_identity_id: Option<String>,
    /// Set when an integration manages the device; the uniqueKey is then `src:{integrationId}:{externalId}`.
    #[serde(rename = "source", default, skip_serializing_if = "Option::is_none")]
    pub source: Option<Value>,
    #[serde(
        rename = "serialNumber",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub serial_number: Option<String>,
    #[serde(rename = "model", default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(rename = "posture", default, skip_serializing_if = "Option::is_none")]
    pub posture: Option<crate::devices::DevicePosture>,
    /// The last integration check-in (written at most once a minute unless the posture changed).
    #[serde(
        rename = "lastCheckInAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_check_in_at: Option<f64>,
    /// The last verified proof seen by `devices.check` (written at most once a minute).
    #[serde(
        rename = "lastSeenAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_seen_at: Option<f64>,
    /// The identity that last bound a key to the device (self-enrolment).
    #[serde(
        rename = "enrolledBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub enrolled_by: Option<String>,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
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

/// The requirements that apply to a tenant: its settings, or the defaults where it has none.
#[derive(Debug, Clone, PartialEq)]
pub struct ResolvedDeviceSettings {
    pub require_encrypted: bool,
    pub require_screen_lock: bool,
    pub require_firewall: bool,
    pub require_edr: bool,
    pub block_jailbroken: bool,
    /// Platform to dotted version (`Partial<Record<DevicePlatform, string>>`), in platform order.
    pub min_os_versions: Map<String, Value>,
    pub max_check_in_age_hours: f64,
}

impl ResolvedDeviceSettings {
    /// The settings as TypeScript encodes them, in member order.
    pub fn to_json(&self) -> Map<String, Value> {
        let mut out = Map::new();
        out.insert(
            "requireEncrypted".into(),
            Value::Bool(self.require_encrypted),
        );
        out.insert(
            "requireScreenLock".into(),
            Value::Bool(self.require_screen_lock),
        );
        out.insert("requireFirewall".into(), Value::Bool(self.require_firewall));
        out.insert("requireEdr".into(), Value::Bool(self.require_edr));
        out.insert("blockJailbroken".into(), Value::Bool(self.block_jailbroken));
        out.insert(
            "minOsVersions".into(),
            Value::Object(self.min_os_versions.clone()),
        );
        out.insert(
            "maxCheckInAgeHours".into(),
            crate::js::number(self.max_check_in_age_hours),
        );
        out
    }
}

/// `deviceCollections`: the collections device posture keeps.
pub static DEVICE_COLLECTIONS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"devices":"registeredDevices","keys":"deviceKeys","enrollments":"deviceEnrollments","integrations":"deviceIntegrations","settings":"deviceSettings"}),
);

/// The members of `deviceCollections`.
pub mod collections {
    /// `RegisteredDevice`: one row per device, in the owner's (home) tenant.
    pub const DEVICES: &str = "registeredDevices";
    /// `DeviceKey`: the id is the key's RFC 7638 thumbprint, unique across tenants; rows carry their tenant.
    pub const KEYS: &str = "deviceKeys";
    /// `DeviceEnrollment`: one-time codes that bind a key to a (usually managed) device; stored hashed.
    pub const ENROLLMENTS: &str = "deviceEnrollments";
    /// `DeviceIntegration`: the MDM/EDR systems that report posture.
    pub const INTEGRATIONS: &str = "deviceIntegrations";
    /// `DeviceSettings`: the tenant's compliance requirements; the id is the tenant id.
    pub const SETTINGS: &str = "deviceSettings";
}

use collections::{DEVICES, ENROLLMENTS, INTEGRATIONS, KEYS, SETTINGS};

/// The request header carrying a device proof (`deviceProofHeader`, a compact JWS).
pub const DEVICE_PROOF_HEADER: &str = "x-better-iam-device";
/// The `typ` every device proof's protected header must carry, exactly.
pub const DEVICE_PROOF_TYPE: &str = "device-proof+jwt";
/// Proofs longer than this are ignored (never an error).
pub const MAX_DEVICE_PROOF_LENGTH: usize = 2048;
/// How far a proof's `iat` may lie from the server clock, either way.
pub const DEVICE_PROOF_SKEW_SECONDS: f64 = 300.0;
/// Devices one person may own (not counting retired ones), for self-enrolment.
pub const MAX_DEVICES_PER_PERSON: f64 = 20.0;
/// Keys one device may hold (one per browser profile or agent).
pub const MAX_KEYS_PER_DEVICE: f64 = 20.0;
/// Device integrations per tenant.
pub const MAX_DEVICE_INTEGRATIONS: f64 = 20.0;

pub const DEVICE_PLATFORMS: &[&str] = &[
    "windows", "macos", "linux", "ios", "android", "chromeos", "other",
];

pub const DEVICE_INTEGRATION_VENDORS: &[&str] = &[
    "intune",
    "jamf",
    "kandji",
    "workspace-one",
    "google-endpoint",
    "crowdstrike",
    "sentinelone",
    "custom",
];

/// `defaultDeviceSettings`.
pub fn default_device_settings() -> ResolvedDeviceSettings {
    ResolvedDeviceSettings {
        require_encrypted: false,
        require_screen_lock: false,
        require_firewall: false,
        require_edr: false,
        block_jailbroken: true,
        min_os_versions: Map::new(),
        max_check_in_age_hours: 24.0,
    }
}

/// The only protected header members a device proof may carry; `jwk`, `jku`, `x5u`, `x5c`, `crit` and all others
/// are refused.
const PROOF_HEADER_MEMBERS: [&str; 3] = ["alg", "typ", "kid"];

/// Where [`with_device_key`] pins a key: a value the proof header can never carry (`:` is not base64url), so a
/// pinned principal never verifies a request proof and every proof check refuses it.
const PINNED_KEY_PREFIX: &str = "pinned-device-key:";

fn base64url_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
}

/// `/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/`: a compact JWS, three base64url segments.
fn is_compact_jws(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 3
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(base64url_byte))
}

/// `deviceKeyIdPattern` (`/^[A-Za-z0-9_-]{43}$/`): an RFC 7638 SHA-256 thumbprint in base64url.
pub fn is_device_key_id(value: &str) -> bool {
    value.len() == 43 && value.bytes().all(base64url_byte)
}

/// `dottedVersion` (`/^\d{1,9}(?:\.\d{1,9}){0,7}$/`): 1 to 8 parts of at most 9 digits.
fn dotted_version(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() <= 8
        && parts.iter().all(|part| {
            (1..=9).contains(&part.len()) && part.bytes().all(|byte| byte.is_ascii_digit())
        })
}

/// Whether a value is a dotted numeric version of at most 32 characters.
pub fn is_os_version(value: Option<&Value>) -> bool {
    matches!(value, Some(Value::String(text)) if is_os_version_str(text))
}

/// [`is_os_version`] for a string.
pub fn is_os_version_str(value: &str) -> bool {
    utf16_len(value) <= 32 && dotted_version(value)
}

/// Compares two dotted numeric versions part by part (missing parts count as 0): negative, 0 or positive.
pub fn compare_os_versions(left: &str, right: &str) -> i32 {
    let parse = |value: &str| -> Vec<f64> {
        value
            .split('.')
            .map(better_iam_core::js::string_to_number)
            .collect()
    };
    let (a, b) = (parse(left), parse(right));
    for index in 0..a.len().max(b.len()) {
        let difference =
            a.get(index).copied().unwrap_or(0.0) - b.get(index).copied().unwrap_or(0.0);
        if difference != 0.0 {
            return if difference < 0.0 { -1 } else { 1 };
        }
    }
    0
}

/// `a === b` for two possibly absent members (absent is `undefined`).
fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => strict_equal(a, b),
        _ => false,
    }
}

/// `value?.[name]`: a member of an object; absent for anything else.
fn member<'a>(value: Option<&'a Value>, name: &str) -> Option<&'a Value> {
    match value {
        Some(Value::Object(map)) => map.get(name),
        _ => None,
    }
}

fn is_str(value: Option<&Value>, wanted: &str) -> bool {
    matches!(value, Some(Value::String(text)) if text == wanted)
}

/// An equality filter whose absent values match records that lack the member (`{ key: undefined }`).
fn filter_of(entries: &[(&str, Option<&Value>)]) -> Filter {
    let mut filter = Filter::new();
    for (key, value) in entries {
        filter.set(*key, value.cloned());
    }
    filter
}

/// The requirements for a tenant: the stored settings over the defaults (stored values were validated on write).
pub fn resolve_device_settings(stored: Option<&Record>) -> ResolvedDeviceSettings {
    let defaults = default_device_settings();
    let flag = |name: &str, fallback: bool| match stored.and_then(|stored| stored.get(name)) {
        Some(Value::Bool(value)) => *value,
        _ => fallback,
    };
    let mut minimums = Map::new();
    if let Some(Value::Object(stored)) = stored.and_then(|stored| stored.get("minOsVersions")) {
        for platform in DEVICE_PLATFORMS {
            let minimum = stored.get(*platform);
            if let Some(minimum) = minimum.filter(|minimum| is_os_version(Some(minimum))) {
                minimums.insert((*platform).to_owned(), minimum.clone());
            }
        }
    }
    let hours = match stored.and_then(|stored| stored.get("maxCheckInAgeHours")) {
        Some(value @ Value::Number(_)) => as_number(value),
        _ => None,
    };
    ResolvedDeviceSettings {
        require_encrypted: flag("requireEncrypted", defaults.require_encrypted),
        require_screen_lock: flag("requireScreenLock", defaults.require_screen_lock),
        require_firewall: flag("requireFirewall", defaults.require_firewall),
        require_edr: flag("requireEdr", defaults.require_edr),
        block_jailbroken: flag("blockJailbroken", defaults.block_jailbroken),
        min_os_versions: minimums,
        max_check_in_age_hours: match hours {
            Some(hours) if is_safe_integer(hours) && (1.0..=720.0).contains(&hours) => hours,
            _ => defaults.max_check_in_age_hours,
        },
    }
}

/// The stored settings record of a tenant, when it is the tenant's.
pub async fn stored_device_settings(tx: &Store, tenant_id: &str) -> IamResult<Option<Record>> {
    let stored = tx.get(SETTINGS, tenant_id).await?;
    Ok(stored.filter(|stored| is_str(stored.get("tenantId"), tenant_id)))
}

/// The tenant's resolved requirements, read from storage.
pub async fn device_settings_of(tx: &Store, tenant_id: &str) -> IamResult<ResolvedDeviceSettings> {
    let stored = stored_device_settings(tx, tenant_id).await?;
    Ok(resolve_device_settings(stored.as_ref()))
}

/// Judges a device against the tenant's requirements. Only an active device an active integration manages can be
/// compliant: its last check-in must be recent, the vendor's verdict (when trusted) must not be `false`, every
/// required posture field must be reported `true` (unknown fails), a jailbroken device fails while
/// `blockJailbroken` is on, and a minimum OS version for the platform needs a reported version at least that high.
pub fn evaluate_compliance(
    device: &Record,
    integration: Option<&Record>,
    settings: &ResolvedDeviceSettings,
    now: f64,
) -> ComplianceResult {
    let mut reasons: Vec<ComplianceReason> = Vec::new();
    let status = device.get("status");
    if is_str(status, "lost") {
        reasons.push("lost".into());
    } else if !is_str(status, "active") {
        reasons.push("retired".into());
    }
    let source = device.get("source");
    let linked = match (source, integration) {
        (Some(source), Some(integration)) => {
            same(integration.get("id"), member(Some(source), "integrationId"))
                && same(integration.get("tenantId"), device.get("tenantId"))
        }
        _ => false,
    };
    let integration = integration.filter(|_| linked);
    let managed =
        integration.is_some_and(|integration| is_str(integration.get("status"), "active"));
    if !linked {
        reasons.push("not-managed".into());
    } else if !managed {
        reasons.push("integration-disabled".into());
    }
    let Some(integration) = integration.filter(|_| managed) else {
        return ComplianceResult {
            compliant: false,
            managed,
            reasons,
        };
    };
    // Posture reported under another integration (before the device moved) says nothing about this one.
    let reported = device.get("posture").filter(|posture| !posture.is_null());
    let posture = reported.filter(|posture| {
        same(
            member(Some(posture), "integrationId"),
            integration.get("id"),
        )
    });
    let Some(posture) = posture.filter(|posture| crate::js::truthy(Some(posture))) else {
        reasons.push("stale".into());
        return ComplianceResult {
            compliant: false,
            managed,
            reasons,
        };
    };
    let posture = Some(posture);
    let checked_at = match device.get("lastCheckInAt").filter(|value| !value.is_null()) {
        Some(value) => to_number(value),
        None => member(posture, "reportedAt").map_or(f64::NAN, to_number),
    };
    let fresh = now - checked_at <= settings.max_check_in_age_hours * 3_600_000.0;
    if !fresh {
        reasons.push("stale".into());
    }
    let flag_is = |name: &str, wanted: bool| matches!(member(posture, name), Some(Value::Bool(value)) if *value == wanted);
    if crate::js::truthy(integration.get("trustVendorCompliance")) && flag_is("compliant", false) {
        reasons.push("vendor-noncompliant".into());
    }
    if settings.require_encrypted && !flag_is("encrypted", true) {
        reasons.push("not-encrypted".into());
    }
    if settings.require_screen_lock && !flag_is("screenLock", true) {
        reasons.push("no-screen-lock".into());
    }
    if settings.require_firewall && !flag_is("firewall", true) {
        reasons.push("no-firewall".into());
    }
    if settings.require_edr && !flag_is("edrHealthy", true) {
        reasons.push("edr-unhealthy".into());
    }
    if settings.block_jailbroken && flag_is("jailbroken", true) {
        reasons.push("jailbroken".into());
    }
    let platform = crate::js::js_string(device.get("platform"));
    if let Some(minimum) = settings.min_os_versions.get(&platform) {
        let os_version = member(posture, "osVersion");
        match os_version {
            Some(Value::String(version)) if is_os_version_str(version) => {
                if compare_os_versions(version, minimum.as_str().unwrap_or_default()) < 0 {
                    reasons.push("os-too-old".into());
                }
            }
            _ => reasons.push("os-unknown".into()),
        }
    }
    ComplianceResult {
        compliant: reasons.is_empty(),
        managed,
        reasons,
    }
}

/// The assurance a request gets from a device: `none` unless `registered` (a verified, active device).
pub fn assurance_of(result: &ComplianceResult, registered: bool) -> DeviceAssurance {
    if !registered {
        return "none";
    }
    if result.compliant {
        "compliant"
    } else if result.managed {
        "managed"
    } else {
        "registered"
    }
}

/// A device's compliance, reading its integration and the tenant's settings.
pub async fn compliance_of(tx: &Store, device: &Record, now: f64) -> IamResult<ComplianceResult> {
    let integration = if crate::js::truthy(device.get("source")) {
        match member(device.get("source"), "integrationId").and_then(Value::as_str) {
            Some(integration_id) => tx.get(INTEGRATIONS, integration_id).await?,
            None => None,
        }
    } else {
        None
    };
    let tenant_id = device
        .get("tenantId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let settings = device_settings_of(tx, tenant_id).await?;
    Ok(evaluate_compliance(
        device,
        integration.as_ref(),
        &settings,
        now,
    ))
}

/// The JWS algorithm a stored key admits: ES256 for EC P-256, EdDSA for Ed25519, nothing else.
pub fn device_key_algorithm(jwk: &DevicePublicJwk) -> Option<&'static str> {
    let kty = member(Some(jwk), "kty");
    let crv = member(Some(jwk), "crv");
    if is_str(kty, "EC") && is_str(crv, "P-256") {
        return Some("ES256");
    }
    if is_str(kty, "OKP") && is_str(crv, "Ed25519") {
        return Some("EdDSA");
    }
    None
}

/// The RFC 7638 SHA-256 thumbprint (base64url) of a public EC P-256 or Ed25519 JWK: the required members in
/// lexicographic order (`calculateJwkThumbprint(jwk, 'sha256')`). None when a required member is not a string.
pub fn jwk_thumbprint(jwk: &DevicePublicJwk) -> Option<String> {
    let text = |name: &str| member(Some(jwk), name).and_then(Value::as_str);
    let mut components = Map::new();
    match text("kty")? {
        "EC" => {
            components.insert("crv".into(), Value::String(text("crv")?.to_owned()));
            components.insert("kty".into(), Value::String("EC".into()));
            components.insert("x".into(), Value::String(text("x")?.to_owned()));
            components.insert("y".into(), Value::String(text("y")?.to_owned()));
        }
        "OKP" => {
            components.insert("crv".into(), Value::String(text("crv")?.to_owned()));
            components.insert("kty".into(), Value::String("OKP".into()));
            components.insert("x".into(), Value::String(text("x")?.to_owned()));
        }
        _ => return None,
    }
    let serialized = better_iam_core::js::stringify_object(&components);
    Some(encode_base64url(&Sha256::digest(serialized.as_bytes())))
}

/// A verification key rebuilt from a stored key's public members only (`importJWK`), or None when the members do
/// not import (an EC point must lie on the curve). Ed25519 keys whose 32 bytes are no curve point import (as
/// OpenSSL does) but never verify.
enum ProofKey {
    P256(p256::ecdsa::VerifyingKey),
    Ed25519(Option<ed25519_dalek::VerifyingKey>),
}

fn import_device_key(jwk: &DevicePublicJwk) -> Option<ProofKey> {
    let bytes = |name: &str| {
        member(Some(jwk), name)
            .and_then(Value::as_str)
            .and_then(decode_base64url)
    };
    match device_key_algorithm(jwk)? {
        "ES256" => {
            let (x, y) = (bytes("x")?, bytes("y")?);
            if x.len() != 32 || y.len() != 32 {
                return None;
            }
            let point = p256::EncodedPoint::from_affine_coordinates(
                x.as_slice().into(),
                y.as_slice().into(),
                false,
            );
            p256::ecdsa::VerifyingKey::from_encoded_point(&point)
                .ok()
                .map(ProofKey::P256)
        }
        _ => {
            let x: [u8; 32] = bytes("x")?.try_into().ok()?;
            Some(ProofKey::Ed25519(
                ed25519_dalek::VerifyingKey::from_bytes(&x).ok(),
            ))
        }
    }
}

/// Whether a stored key's public members import as a key of its type (`importJWK({ ...jwk }, alg)`).
pub fn device_key_imports(jwk: &DevicePublicJwk) -> bool {
    import_device_key(jwk).is_some()
}

fn verify_signature(key: &ProofKey, data: &[u8], signature: &[u8]) -> bool {
    use p256::ecdsa::signature::Verifier;
    match key {
        ProofKey::P256(key) => p256::ecdsa::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
        ProofKey::Ed25519(Some(key)) => ed25519_dalek::Signature::from_slice(signature)
            .is_ok_and(|signature| key.verify(data, &signature).is_ok()),
        ProofKey::Ed25519(None) => false,
    }
}

/// The device proof a credential's headers carry (`x-better-iam-device`), or None when there is none or it is not
/// shaped like a compact JWS of at most 2048 characters. Every value of the header counts, joined with `, ` (as
/// `new Headers(init).get(name)` reads them).
pub fn device_proof_of(headers: Option<&[(String, String)]>) -> Option<String> {
    let headers = headers?;
    let values: Vec<&str> = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(DEVICE_PROOF_HEADER))
        .map(|(_, value)| value.as_str())
        .collect();
    if values.is_empty() {
        return None;
    }
    let value = values.join(", ");
    (!value.is_empty() && utf16_len(&value) <= MAX_DEVICE_PROOF_LENGTH && is_compact_jws(&value))
        .then_some(value)
}

/// A device a proof verified for, with the key that signed it (`VerifiedDevice`), as raw records.
#[derive(Debug, Clone, PartialEq)]
pub struct VerifiedDevice {
    pub device: Record,
    pub key: Record,
}

/// The session (and its tenant) a device proof must be bound to (`ProofBinding`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofBinding {
    pub session_id: String,
    pub tenant_id: String,
}

/// Principals whose proof is bound to another session (the request's), the ones `withRequestDevice` makes: a
/// WeakMap keyed by the principal object in TypeScript, keyed here by the carried proof and the principal's session.
static PROOF_BINDINGS: std::sync::Mutex<Vec<((String, String), ProofBinding)>> =
    std::sync::Mutex::new(Vec::new());

fn remember_binding(principal: &AuthenticatedPrincipal, binding: ProofBinding) {
    let Some(proof) = &principal.device_proof else {
        return;
    };
    let key = (proof.clone(), principal.session.id.clone());
    let mut list = PROOF_BINDINGS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    list.retain(|(known, _)| known != &key);
    list.push((key, binding));
    if list.len() > 4096 {
        list.remove(0);
    }
}

/// `bindingOf(principal)`: the binding `withRequestDevice` recorded, else the principal's own session and tenant.
pub fn proof_binding(principal: &AuthenticatedPrincipal) -> ProofBinding {
    if let Some(proof) = &principal.device_proof {
        let list = PROOF_BINDINGS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some((_, binding)) = list
            .iter()
            .rev()
            .find(|((known, session), _)| known == proof && session == &principal.session.id)
        {
            return binding.clone();
        }
    }
    ProofBinding {
        session_id: principal.session.id.clone(),
        tenant_id: principal.session.tenant_id.clone(),
    }
}

/// Another principal a request is decided for besides its own (the source identity of a role session, whose right
/// to the role is decided again on every use; the administrator behind a "view as" session), carrying the request's
/// device proof. The proof stays bound to the request's session and tenant, and the device must still live in this
/// principal's home tenant and be shared or theirs. Without a proof on the request, `derived` is returned as it is.
pub fn with_request_device(
    derived: AuthenticatedPrincipal,
    request: &AuthenticatedPrincipal,
) -> AuthenticatedPrincipal {
    let Some(proof) = &request.device_proof else {
        return derived;
    };
    let binding = proof_binding(request);
    let carried = AuthenticatedPrincipal {
        device_proof: Some(proof.clone()),
        ..derived
    };
    remember_binding(&carried, binding);
    carried
}

/// A principal a job without a request decides for again (the SSH certificate sweep), with the device key its
/// original request proved: device conditions then judge that device as it stands now (still active, still the
/// identity's or shared, and its current compliance), where they would otherwise always see no device. The pin
/// travels with the principal value (TypeScript keeps it in a WeakMap keyed by the copied principal object).
pub fn with_device_key(
    principal: &AuthenticatedPrincipal,
    key_id: &str,
) -> IamResult<AuthenticatedPrincipal> {
    Ok(AuthenticatedPrincipal {
        device_proof: Some(format!("{PINNED_KEY_PREFIX}{key_id}")),
        ..principal.clone()
    })
}

/// The key [`with_device_key`] pinned on a principal.
fn pinned_key(principal: &AuthenticatedPrincipal) -> Option<&str> {
    principal
        .device_proof
        .as_deref()?
        .strip_prefix(PINNED_KEY_PREFIX)
}

/// A well-formed proof's protected header: only `alg`, `typ` (exactly `device-proof+jwt`) and a thumbprint `kid`.
/// Returns the `alg` member (absent stays absent) and the `kid`.
fn proof_header_of(proof: Option<&str>) -> Option<(Option<Value>, String)> {
    let proof = proof?;
    if utf16_len(proof) > MAX_DEVICE_PROOF_LENGTH || !is_compact_jws(proof) {
        return None;
    }
    let header = decode_protected_header(proof).ok()?;
    if header
        .keys()
        .any(|member| !PROOF_HEADER_MEMBERS.contains(&member.as_str()))
        || !is_str(header.get("typ"), DEVICE_PROOF_TYPE)
    {
        return None;
    }
    let kid = match header.get("kid") {
        Some(Value::String(kid)) if is_device_key_id(kid) => kid.clone(),
        _ => return None,
    };
    Some((header.get("alg").cloned(), kid))
}

/// Whether a proof is signed with `jwk` under the algorithm the key's type pins, and its claims hold: `iat` within
/// 300 seconds of `now` either way, `sid` the bound session and `tid`, when present, that session's tenant. Malformed
/// input is no proof (TypeScript throws and its callers treat that as no proof).
fn proof_signed(
    proof: &str,
    alg: Option<&Value>,
    jwk: &DevicePublicJwk,
    binding: &ProofBinding,
    now: f64,
) -> bool {
    let Some(algorithm) = device_key_algorithm(jwk) else {
        return false;
    };
    if !is_str(alg, algorithm) {
        return false;
    }
    // Key material comes only from the given key, rebuilt from its public members.
    let Some(key) = import_device_key(jwk) else {
        return false;
    };
    // `compactVerify(proof, key, { algorithms: [algorithm] })`.
    let parts: Vec<&str> = proof.split('.').collect();
    let [protected, payload, signature] = parts.as_slice() else {
        return false;
    };
    let Some(signature) = decode_base64url(signature) else {
        return false;
    };
    let data = format!("{protected}.{payload}");
    if !verify_signature(&key, data.as_bytes(), &signature) {
        return false;
    }
    let Some(payload) = decode_base64url(payload) else {
        return false;
    };
    // `JSON.parse(new TextDecoder().decode(payload))`: a leading BOM dropped, invalid UTF-8 replaced.
    let payload = payload
        .strip_prefix(&[0xEF, 0xBB, 0xBF])
        .unwrap_or(&payload);
    let text = String::from_utf8_lossy(payload);
    let Ok(Value::Object(claims)) = better_iam_core::js::parse(&text) else {
        return false;
    };
    let iat = match claims.get("iat") {
        Some(value @ Value::Number(_)) => as_number(value).filter(|iat| iat.is_finite()),
        _ => None,
    };
    let Some(iat) = iat else {
        return false;
    };
    (now / 1000.0 - iat).abs() <= DEVICE_PROOF_SKEW_SECONDS
        && is_str(claims.get("sid"), &binding.session_id)
        && match claims.get("tid") {
            None => true,
            Some(tid) => is_str(Some(tid), &binding.tenant_id),
        }
}

/// The device a stored key stands for, when it may vouch for the principal: active, and shared or the identity's.
async fn device_of_key(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    key: Option<Record>,
) -> IamResult<Option<VerifiedDevice>> {
    let Some(key) = key else {
        return Ok(None);
    };
    if !is_str(key.get("tenantId"), &principal.identity.tenant_id) {
        return Ok(None);
    }
    let device = match key.get("deviceId").and_then(Value::as_str) {
        Some(device_id) => tx.get(DEVICES, device_id).await?,
        None => None,
    };
    let Some(device) = device else {
        return Ok(None);
    };
    let foreign_owner = device
        .get("ownerIdentityId")
        .is_some_and(|owner| !is_str(Some(owner), &principal.identity.id));
    if !same(device.get("tenantId"), key.get("tenantId"))
        || !is_str(device.get("status"), "active")
        || foreign_owner
    {
        return Ok(None);
    }
    Ok(Some(VerifiedDevice { device, key }))
}

/// Verifies a device proof for a principal; None for anything short of a valid proof (never fails). The protected
/// header may hold only `alg`, `typ` (exactly `device-proof+jwt`) and `kid` (a stored key's thumbprint); the
/// algorithm is pinned by the stored key's type and the signature checked with the stored key only. The payload's
/// `iat` must lie within 300 seconds of `now` either way, its `sid` must be the session that authenticated the
/// request and its `tid`, when present, that session's tenant. The device must be active, live in the identity's
/// home tenant, and be shared or owned by the identity. Simulated principals never verify. Reads only.
pub async fn verify_device_proof(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    proof: Option<&str>,
    now: f64,
) -> Option<VerifiedDevice> {
    if principal.session.id == "simulation" {
        return None;
    }
    let (alg, kid) = proof_header_of(proof)?;
    let key = tx.get(KEYS, &kid).await.ok()??;
    if !is_str(key.get("id"), &kid) || !is_str(key.get("tenantId"), &principal.identity.tenant_id) {
        return None;
    }
    let jwk = key.get("jwk").cloned().unwrap_or(Value::Null);
    if !proof_signed(proof?, alg.as_ref(), &jwk, &proof_binding(principal), now) {
        return None;
    }
    device_of_key(tx, principal, Some(key)).await.ok().flatten()
}

/// Proof of possession for enrolment: the request's device proof must be signed with the key being enrolled (its
/// `kid` that key's thumbprint) and bound to the enrolling session, with the checks every proof gets. Without it,
/// anyone who saw a public key (one proof is enough to recover it) could enrol it first and lock its holder out.
/// Never fails.
pub async fn proves_possession(
    principal: &AuthenticatedPrincipal,
    jwk: &DevicePublicJwk,
    key_id: &str,
    now: f64,
) -> bool {
    let proof = principal.device_proof.as_deref();
    match proof_header_of(proof) {
        Some((alg, kid)) if kid == key_id => proof_signed(
            proof.unwrap_or_default(),
            alg.as_ref(),
            jwk,
            &proof_binding(principal),
            now,
        ),
        _ => false,
    }
}

/// A verified device with its compliance and the assurance it gives the request (`PresentedDevice`).
#[derive(Debug, Clone, PartialEq)]
pub struct PresentedDevice {
    pub device: Record,
    pub key: Record,
    pub compliance: ComplianceResult,
    pub assurance: DeviceAssurance,
}

impl PresentedDevice {
    /// `{ device, key, compliance, assurance }` as TypeScript returns it.
    pub fn to_json(&self) -> Value {
        json!({
            "device": self.device,
            "key": self.key,
            "compliance": self.compliance.to_json(),
            "assurance": self.assurance,
        })
    }
}

/// The device the principal's request presents (its `deviceProof`, or the key `withDeviceKey` pinned), verified and
/// judged, or None. A session acting in another tenant than the device's (a cross-tenant role session) is decided
/// there, and that tenant neither manages the device nor set the requirements it was judged by, so the device counts
/// as registered only: never managed or compliant. Never fails. (TypeScript caches the answer per principal object
/// within a transaction; it is recomputed here from the same reads.)
pub async fn presented(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    now: f64,
) -> Option<PresentedDevice> {
    let verified = match pinned_key(principal) {
        None => verify_device_proof(tx, principal, principal.device_proof.as_deref(), now).await,
        Some(_) if principal.session.id == "simulation" => None,
        Some(key_id) => match tx.get(KEYS, key_id).await {
            Ok(key) => device_of_key(tx, principal, key).await.ok().flatten(),
            Err(_) => None,
        },
    }?;
    let compliance = if is_str(
        verified.device.get("tenantId"),
        &principal.session.tenant_id,
    ) {
        compliance_of(tx, &verified.device, now).await.ok()?
    } else {
        ComplianceResult {
            compliant: false,
            managed: false,
            reasons: vec!["not-managed".into()],
        }
    };
    Some(PresentedDevice {
        assurance: assurance_of(&compliance, true),
        device: verified.device,
        key: verified.key,
        compliance,
    })
}

/// [`presented`] as the JSON TypeScript returns (`{ device, key, compliance, assurance }`).
pub async fn presented_device(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    now: f64,
) -> IamResult<Option<Value>> {
    Ok(presented(tx, principal, now)
        .await
        .map(|device| device.to_json()))
}

/// The device keys for a decision: the assurance, managed and compliant flags always, the device id and platform
/// when a proof verified. Simulated principals and requests without a valid proof get `none`/false. Never fails.
pub async fn device_context(
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    now: f64,
) -> IamResult<Map<String, Value>> {
    let mut keys = Map::new();
    let Some(device) = presented(tx, principal, now).await else {
        keys.insert(
            "request.deviceAssurance".into(),
            Value::String("none".into()),
        );
        keys.insert("request.deviceManaged".into(), Value::Bool(false));
        keys.insert("request.deviceCompliant".into(), Value::Bool(false));
        return Ok(keys);
    };
    keys.insert(
        "request.deviceAssurance".into(),
        Value::String(device.assurance.into()),
    );
    keys.insert(
        "request.deviceManaged".into(),
        Value::Bool(device.compliance.managed),
    );
    keys.insert(
        "request.deviceCompliant".into(),
        Value::Bool(device.compliance.compliant),
    );
    if let Some(id) = device.device.get("id") {
        keys.insert("request.deviceId".into(), id.clone());
    }
    if let Some(platform) = device.device.get("platform") {
        keys.insert("request.devicePlatform".into(), platform.clone());
    }
    Ok(keys)
}

/// Whether any document names a device key (`request.device…`), in conditions or `${…}` variables.
pub fn mentions_device(documents: &[&PolicyDocument]) -> bool {
    documents.iter().any(|document| {
        let serialized = better_iam_core::js::stringify(
            &serde_json::to_value(&document.statements).unwrap_or(Value::Null),
        );
        serialized.contains("request.device")
    })
}

/// Retires a device: status `retired`, every key and pending enrollment code for it deleted. Returns the retired
/// record and the number of keys removed.
pub async fn retire_device(tx: &Store, device: &Record, now: f64) -> IamResult<(Record, usize)> {
    let scope = filter_of(&[
        ("tenantId", device.get("tenantId")),
        ("deviceId", device.get("id")),
    ]);
    let keys = tx.find(KEYS, &scope, &FindOptions::default()).await?;
    for key in &keys {
        tx.delete(
            KEYS,
            key.get("id").and_then(Value::as_str).unwrap_or_default(),
        )
        .await?;
    }
    for enrollment in tx
        .find(ENROLLMENTS, &scope, &FindOptions::default())
        .await?
    {
        tx.delete(
            ENROLLMENTS,
            enrollment
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .await?;
    }
    let mut next = device.clone();
    next.insert("status".into(), Value::String("retired".into()));
    next.insert("updatedAt".into(), crate::js::number(now));
    let retired = tx.put(DEVICES, &next).await?;
    Ok((retired, keys.len()))
}

/// Devices of a deleted identity: its self-enrolled (unmanaged) devices are retired with their keys, managed ones
/// lose their owner (the integration may assign someone else) and the keys the person bound to them, and enrollment
/// codes issued for the person are withdrawn. Shared devices keep the keys the person enrolled on them.
pub async fn release_devices_of(tx: &Store, identity: &Identity, now: f64) -> IamResult<()> {
    let tenant_id = Value::String(identity.tenant_id.clone());
    let identity_id = Value::String(identity.id.clone());
    let owned = filter_of(&[
        ("tenantId", Some(&tenant_id)),
        ("ownerIdentityId", Some(&identity_id)),
    ]);
    for device in tx.find(DEVICES, &owned, &FindOptions::default()).await? {
        if !crate::js::truthy(device.get("source")) {
            if !is_str(device.get("status"), "retired") {
                retire_device(tx, &device, now).await?;
            }
            continue;
        }
        let bound = filter_of(&[
            ("tenantId", Some(&tenant_id)),
            ("deviceId", device.get("id")),
            ("createdBy", Some(&identity_id)),
        ]);
        for key in tx.find(KEYS, &bound, &FindOptions::default()).await? {
            tx.delete(
                KEYS,
                key.get("id").and_then(Value::as_str).unwrap_or_default(),
            )
            .await?;
        }
        let mut rest = device.clone();
        rest.shift_remove("ownerIdentityId");
        rest.insert("updatedAt".into(), crate::js::number(now));
        tx.put(DEVICES, &rest).await?;
    }
    for enrollment in tx
        .find(ENROLLMENTS, &owned, &FindOptions::default())
        .await?
    {
        tx.delete(
            ENROLLMENTS,
            enrollment
                .get("id")
                .and_then(Value::as_str)
                .unwrap_or_default(),
        )
        .await?;
    }
    Ok(())
}
