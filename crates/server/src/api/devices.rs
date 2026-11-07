//! Port of `packages/server/src/api/devices.ts`: the `devices` API group.
//!
//! Device posture: registered devices, the keys that prove a request comes from one, the integrations (MDM, EDR)
//! that manage devices and report their posture, and the tenant's compliance requirements. People enrol their own
//! devices and list or retire them without a permission; administrators hold `iam:devices:read` /
//! `iam:devices:manage` on `iam/devices…`; integrations report with `iam:devices:report` on
//! `iam/devices/integrations/{id}` (an API key of a service account). Policies see the presenting device as
//! `request.deviceAssurance`, `request.deviceManaged`, `request.deviceCompliant`, `request.deviceId` and
//! `request.devicePlatform`.
//!
//! Records are read and written as raw JSON records, so member order and members this port does not know survive a
//! round trip (a mixed fleet shares the database with TypeScript).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use better_iam_auth::service::base::LimitAttemptOptions;
use better_iam_core::js::{
    entries, keys as js_keys, strict_equal, to_lower, to_number, trim as js_trim, utf16_len,
};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, IdentityKind, Record,
};
use better_iam_types::api::devices;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationDenied};
use crate::devices::collections::{DEVICES, ENROLLMENTS, INTEGRATIONS, KEYS, SETTINGS};
use crate::devices::{
    ComplianceResult, DEVICE_INTEGRATION_VENDORS, DEVICE_PLATFORMS, MAX_DEVICE_INTEGRATIONS,
    MAX_DEVICES_PER_PERSON, MAX_KEYS_PER_DEVICE, assurance_of, device_key_algorithm,
    device_key_imports, device_settings_of, evaluate_compliance, is_device_key_id, is_os_version,
    is_os_version_str, jwk_thumbprint, presented, proves_possession, resolve_device_settings,
    retire_device, stored_device_settings,
};
use crate::js::truthy;
use crate::metrics::locale_compare;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::session_kinds::acts_in_own_right;
use crate::utils::{by_newest_records, hash, id, same_hash_value, token};
use crate::validation::{integer, object, text};

const DAY: f64 = 86_400_000.0;
const MIN_ENROLLMENT_MS: f64 = 10.0 * 60_000.0;
const MAX_ENROLLMENT_MS: f64 = 30.0 * DAY;
const DEFAULT_ENROLLMENT_MS: f64 = 7.0 * DAY;
/// Pending (unused, unexpired) enrollment codes per tenant.
const MAX_PENDING_ENROLLMENTS: usize = 1000;
/// Devices per `devices.report` call.
const MAX_REPORTED_DEVICES: usize = 500;
/// Self-enrolments one person may attempt per rate-limit window.
const ENROLL_ATTEMPTS: f64 = 30.0;
/// `lastCheckInAt`, `lastSeenAt` and `lastUsedAt` are written at most this often unless something else changed.
const TOUCH_MS: f64 = 60_000.0;

const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "k", "oth"];
const POSTURE_FIELDS: [&str; 6] = [
    "compliant",
    "encrypted",
    "firewall",
    "screenLock",
    "edrHealthy",
    "jailbroken",
];
const REPORT_FIELDS: [&str; 11] = [
    "externalId",
    "name",
    "platform",
    "serialNumber",
    "model",
    "osVersion",
    "ownerEmail",
    "ownerIdentityId",
    "keyThumbprint",
    "posture",
    "checkedInAt",
];
const SETTINGS_FLAGS: [&str; 5] = [
    "requireEncrypted",
    "requireScreenLock",
    "requireFirewall",
    "requireEdr",
    "blockJailbroken",
];

fn device_resource(device_id: &str) -> String {
    format!("devices/{device_id}")
}

fn integration_resource(integration_id: &str) -> String {
    format!("devices/integrations/{integration_id}")
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn str_of<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

fn is_str(value: Option<&Value>, wanted: &str) -> bool {
    matches!(value, Some(Value::String(text)) if text == wanted)
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

/// `value ?? fallback`: a member that is neither absent nor null.
fn given_member<'a>(record: &'a Record, key: &str) -> Option<&'a Value> {
    record.get(key).filter(|value| !value.is_null())
}

/// `...(record.key !== undefined ? { key: record.key } : {})`.
fn copy(out: &mut Map<String, Value>, record: &Record, key: &str) {
    if let Some(value) = record.get(key) {
        out.insert(key.to_owned(), value.clone());
    }
}

/// `value ?? null`.
fn or_null(value: Option<&Value>) -> Value {
    value
        .filter(|value| !value.is_null())
        .cloned()
        .unwrap_or(Value::Null)
}

/// An equality filter whose absent values match records that lack the member (`{ key: undefined }`).
fn filter_of(entries: &[(&str, Option<&Value>)]) -> Filter {
    let mut filter = Filter::new();
    for (key, value) in entries {
        filter.set(*key, value.cloned());
    }
    filter
}

async fn find(tx: &Store, collection: &str, filter: &Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, filter, &FindOptions::default()).await
}

/// `value.slice(0, length)` in UTF-16 code units (a pair cut in half is dropped).
fn slice_utf16(value: &str, length: usize) -> String {
    let mut out = String::new();
    let mut units = 0;
    for c in value.chars() {
        units += c.len_utf16();
        if units > length {
            break;
        }
        out.push(c);
    }
    out
}

fn platform_of(value: Option<&Value>, name: &str) -> IamResult<String> {
    match value {
        Some(Value::String(platform)) if DEVICE_PLATFORMS.contains(&platform.as_str()) => {
            Ok(platform.clone())
        }
        _ => Err(invalid(format!(
            "{name} must be one of {}",
            DEVICE_PLATFORMS.join(", ")
        ))),
    }
}

fn flag(value: Option<&Value>, name: &str) -> IamResult<bool> {
    match value {
        Some(Value::Bool(value)) => Ok(*value),
        _ => Err(invalid(format!("{name} must be a boolean"))),
    }
}

/// The input object, refusing fields the call does not know (a misspelt setting must not pass silently).
fn fields_of<'a>(value: Option<&'a Value>, allowed: &[&str]) -> IamResult<&'a Map<String, Value>> {
    let input = object(value)?;
    check_fields(input, allowed)?;
    Ok(input)
}

fn check_fields(input: &Map<String, Value>, allowed: &[&str]) -> IamResult<()> {
    for key in js_keys(input) {
        if !allowed.contains(&key.as_str()) {
            return Err(invalid(format!("Unknown field {key}")));
        }
    }
    Ok(())
}

fn device_name(value: Option<&Value>) -> IamResult<String> {
    Ok(js_trim(&text(value, "name", 128)?).to_owned())
}

fn invalid_key() -> IamError {
    invalid("publicKey must be a public EC P-256 or Ed25519 JWK")
}

/// `/^[A-Za-z0-9_-]{43}$/`.
fn coordinate(value: Option<&Value>) -> Option<&str> {
    match value {
        Some(Value::String(text)) if is_device_key_id(text) => Some(text.as_str()),
        _ => None,
    }
}

/// A public EC P-256 or Ed25519 JWK reduced to its public members; private material is refused outright.
fn public_key_of(value: Option<&Value>) -> IamResult<Value> {
    let jwk = match value {
        Some(Value::Object(jwk)) if !crate::js::is_function(value) => jwk,
        _ => return Err(invalid_key()),
    };
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| jwk.contains_key(*member))
    {
        return Err(invalid("publicKey must not contain private key material"));
    }
    if jwk
        .get("use")
        .is_some_and(|value| !is_str(Some(value), "sig"))
    {
        return Err(invalid_key());
    }
    let x = coordinate(jwk.get("x"));
    let alg = jwk.get("alg");
    if is_str(jwk.get("kty"), "EC")
        && is_str(jwk.get("crv"), "P-256")
        && let Some(x) = x
        && let Some(y) = coordinate(jwk.get("y"))
        && (alg.is_none() || is_str(alg, "ES256"))
    {
        return Ok(json!({ "kty": "EC", "crv": "P-256", "x": x, "y": y }));
    }
    if is_str(jwk.get("kty"), "OKP")
        && is_str(jwk.get("crv"), "Ed25519")
        && let Some(x) = x
        && !jwk.contains_key("y")
        && (alg.is_none() || is_str(alg, "EdDSA") || is_str(alg, "Ed25519"))
    {
        return Ok(json!({ "kty": "OKP", "crv": "Ed25519", "x": x }));
    }
    Err(invalid_key())
}

/// The key's thumbprint (its id), after checking the key imports (an EC point must lie on the curve).
fn key_id_of(jwk: &Value) -> IamResult<String> {
    if !device_key_imports(jwk) {
        return Err(invalid_key());
    }
    jwk_thumbprint(jwk).ok_or_else(invalid_key)
}

/// Self-service calls act for the caller in their own tenant, from a session in their own right.
fn own_session(
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    message: &str,
) -> IamResult<()> {
    if !acts_in_own_right(principal.session.kind)
        || principal.session.tenant_id != tenant_id
        || principal.identity.tenant_id != tenant_id
    {
        return Err(IamError::with_status("ACCESS_DENIED", message, 403));
    }
    Ok(())
}

fn not_impersonating(principal: &AuthenticatedPrincipal) -> IamResult<()> {
    if principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
    {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Devices cannot be enrolled or retired while impersonating",
            403,
        ));
    }
    Ok(())
}

fn invalid_code() -> IamError {
    invalid("Invalid or expired enrollment code")
}

/// `/^biam_denr_[A-Za-z0-9_-]{43}$/`.
fn is_enrollment_code(value: &str) -> bool {
    value
        .strip_prefix("biam_denr_")
        .is_some_and(is_device_key_id)
}

/// A registered device as administrators see it (`DeviceView`).
fn device_view(
    device: &Record,
    compliance: &ComplianceResult,
    keys: usize,
    owner: Option<&Record>,
) -> Record {
    let mut view = Map::new();
    copy(&mut view, device, "id");
    copy(&mut view, device, "tenantId");
    copy(&mut view, device, "name");
    copy(&mut view, device, "platform");
    copy(&mut view, device, "status");
    copy(&mut view, device, "ownerIdentityId");
    if let Some(owner) = owner {
        let mut summary = Map::new();
        copy(&mut summary, owner, "id");
        copy(&mut summary, owner, "name");
        copy(&mut summary, owner, "email");
        view.insert("owner".into(), Value::Object(summary));
    }
    if truthy(device.get("source")) {
        let source = device.get("source");
        let mut summary = Map::new();
        if let Some(value) = member(source, "integrationId") {
            summary.insert("integrationId".into(), value.clone());
        }
        if let Some(value) = member(source, "externalId") {
            summary.insert("externalId".into(), value.clone());
        }
        view.insert("source".into(), Value::Object(summary));
    }
    copy(&mut view, device, "serialNumber");
    copy(&mut view, device, "model");
    if truthy(device.get("posture")) {
        let posture = match device.get("posture") {
            Some(Value::Object(posture)) => posture.clone(),
            _ => Map::new(),
        };
        view.insert("posture".into(), Value::Object(posture));
    }
    copy(&mut view, device, "lastCheckInAt");
    copy(&mut view, device, "lastSeenAt");
    copy(&mut view, device, "enrolledBy");
    copy(&mut view, device, "createdAt");
    copy(&mut view, device, "updatedAt");
    view.insert("compliance".into(), compliance.to_json());
    view.insert(
        "assurance".into(),
        Value::String(
            assurance_of(
                compliance,
                is_str(device.get("status"), "active") && keys > 0,
            )
            .into(),
        ),
    );
    view.insert("keys".into(), crate::js::number(keys as f64));
    view
}

/// Views of devices of one tenant, reading the settings, integrations, key counts and owners once.
async fn describe(
    tx: &Store,
    tenant_id: &str,
    devices: &[Record],
    now: f64,
) -> IamResult<Vec<Record>> {
    if devices.is_empty() {
        return Ok(Vec::new());
    }
    let tenant = Value::String(tenant_id.to_owned());
    let settings = device_settings_of(tx, tenant_id).await?;
    let mut integrations: HashMap<String, Record> = HashMap::new();
    for integration in find(tx, INTEGRATIONS, &filter_of(&[("tenantId", Some(&tenant))])).await? {
        if let Some(id) = integration.get("id").and_then(Value::as_str) {
            integrations.insert(id.to_owned(), integration);
        }
    }
    let mut key_counts: HashMap<String, usize> = HashMap::new();
    if devices.len() > 20 {
        for key in find(tx, KEYS, &filter_of(&[("tenantId", Some(&tenant))])).await? {
            if let Some(device_id) = key.get("deviceId").and_then(Value::as_str) {
                *key_counts.entry(device_id.to_owned()).or_default() += 1;
            }
        }
    } else {
        for device in devices {
            let count = find(
                tx,
                KEYS,
                &filter_of(&[("tenantId", Some(&tenant)), ("deviceId", device.get("id"))]),
            )
            .await?
            .len();
            if let Some(device_id) = device.get("id").and_then(Value::as_str) {
                key_counts.insert(device_id.to_owned(), count);
            }
        }
    }
    let mut owners: HashMap<String, Option<Record>> = HashMap::new();
    let mut views = Vec::with_capacity(devices.len());
    for device in devices {
        let owner_id = device.get("ownerIdentityId").and_then(Value::as_str);
        if let Some(owner_id) = owner_id
            && !owners.contains_key(owner_id)
        {
            let identity = tx.get("identities", owner_id).await?;
            owners.insert(
                owner_id.to_owned(),
                identity.filter(|identity| is_str(identity.get("tenantId"), tenant_id)),
            );
        }
        let integration = if truthy(device.get("source")) {
            member(device.get("source"), "integrationId")
                .and_then(Value::as_str)
                .and_then(|id| integrations.get(id))
        } else {
            None
        };
        let keys = device
            .get("id")
            .and_then(Value::as_str)
            .and_then(|id| key_counts.get(id))
            .copied()
            .unwrap_or(0);
        views.push(device_view(
            device,
            &evaluate_compliance(device, integration, &settings, now),
            keys,
            owner_id
                .and_then(|id| owners.get(id))
                .and_then(Option::as_ref),
        ));
    }
    Ok(views)
}

/// An enrollment code as administrators see it (`DeviceEnrollmentView`); the code itself is shown once.
fn enrollment_view(enrollment: &Record, now: f64) -> Record {
    let mut view = Map::new();
    copy(&mut view, enrollment, "id");
    copy(&mut view, enrollment, "tenantId");
    copy(&mut view, enrollment, "deviceId");
    copy(&mut view, enrollment, "ownerIdentityId");
    let status = if enrollment.contains_key("usedAt") {
        "used"
    } else if enrollment.get("expiresAt").map_or(f64::NAN, to_number) <= now {
        "expired"
    } else {
        "pending"
    };
    view.insert("status".into(), Value::String(status.into()));
    copy(&mut view, enrollment, "expiresAt");
    copy(&mut view, enrollment, "createdAt");
    copy(&mut view, enrollment, "createdBy");
    copy(&mut view, enrollment, "usedAt");
    copy(&mut view, enrollment, "usedBy");
    view
}

/// A device integration with the number of devices it manages (`DeviceIntegrationView`).
fn integration_view(integration: &Record, devices: usize) -> Record {
    let mut view = Map::new();
    for key in [
        "id",
        "tenantId",
        "name",
        "vendor",
        "status",
        "trustVendorCompliance",
        "createdAt",
        "createdBy",
        "updatedAt",
        "lastReportAt",
    ] {
        copy(&mut view, integration, key);
    }
    view.insert("devices".into(), crate::js::number(devices as f64));
    view
}

fn integration_metadata(integration: &Record) -> Map<String, Value> {
    let mut metadata = Map::new();
    for key in ["name", "vendor", "status", "trustVendorCompliance"] {
        copy(&mut metadata, integration, key);
    }
    metadata
}

/// The tenant's compliance requirements (`DeviceSettingsView`).
fn settings_view(tenant_id: &str, stored: Option<&Record>) -> Record {
    let mut view = resolve_device_settings(stored).to_json();
    view.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    view.insert("configured".into(), Value::Bool(stored.is_some()));
    if let Some(stored) = stored {
        copy(&mut view, stored, "updatedAt");
        copy(&mut view, stored, "updatedBy");
    }
    view
}

/// A person of the tenant who can own a device (a user identity that is not deleted).
fn person(identity: Option<&Record>, tenant_id: &str) -> bool {
    identity.is_some_and(|identity| {
        is_str(identity.get("tenantId"), tenant_id)
            && is_str(identity.get("kind"), "user")
            && !is_str(identity.get("status"), "deleted")
    })
}

/// A report item after validation (`ReportItem`).
struct ReportItem {
    external_id: String,
    name: Option<String>,
    platform: String,
    serial_number: Option<String>,
    model: Option<String>,
    os_version: Option<String>,
    /// Whether the report names an owner at all (then an unknown one clears it).
    owner_named: bool,
    owner_identity_id: Option<String>,
    owner_email: Option<String>,
    key_thumbprint: Option<String>,
    posture: Map<String, Value>,
    checked_in_at: f64,
}

/// `/^[!-~](?:[ -~]{0,198}[!-~])?$/`: printable ASCII without leading or trailing spaces, at most 200 characters.
fn is_external_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    let printable = |byte: &u8| (0x20..=0x7e).contains(byte);
    let visible = |byte: &u8| (0x21..=0x7e).contains(byte);
    !bytes.is_empty()
        && bytes.len() <= 200
        && bytes.iter().all(printable)
        && visible(&bytes[0])
        && visible(&bytes[bytes.len() - 1])
}

/// `/^v?(\d{1,9}(?:\.\d{1,9}){0,7})/i`: the leading dotted number of a version string.
fn leading_version(value: &str) -> Option<&str> {
    let bytes = value.as_bytes();
    let digits = |from: usize| {
        bytes[from..]
            .iter()
            .take(9)
            .take_while(|byte| byte.is_ascii_digit())
            .count()
    };
    let start = usize::from(matches!(bytes.first(), Some(b'v' | b'V')));
    let first = digits(start);
    if first == 0 {
        return None;
    }
    let mut end = start + first;
    for _ in 0..7 {
        if bytes.get(end) != Some(&b'.') {
            break;
        }
        let more = digits(end + 1);
        if more == 0 {
            break;
        }
        end += 1 + more;
    }
    Some(&value[start..end])
}

fn report_items(value: Option<&Value>, now: f64) -> IamResult<Vec<ReportItem>> {
    let reports = match value {
        Some(Value::Array(reports))
            if !reports.is_empty() && reports.len() <= MAX_REPORTED_DEVICES =>
        {
            reports
        }
        _ => {
            return Err(invalid(format!(
                "devices must list 1-{MAX_REPORTED_DEVICES} device reports"
            )));
        }
    };
    let mut seen: HashSet<String> = HashSet::new();
    let mut items = Vec::with_capacity(reports.len());
    for (index, raw) in reports.iter().enumerate() {
        let at = format!("devices[{index}]");
        let input = fields_of(Some(raw), &REPORT_FIELDS)?;
        let external_id = match input.get("externalId") {
            Some(Value::String(external_id)) if is_external_id(external_id) => external_id.clone(),
            _ => return Err(invalid(format!("{at}.externalId is invalid"))),
        };
        if !seen.insert(external_id.clone()) {
            return Err(invalid(format!(
                "{at}.externalId repeats an earlier device"
            )));
        }
        // Connectors often send null or an empty string for a field the vendor does not know: both read as absent.
        let given = |name: &str| -> Option<&Value> {
            match input.get(name) {
                None | Some(Value::Null) => None,
                Some(Value::String(text)) if js_trim(text).is_empty() => None,
                Some(value) => Some(value),
            }
        };
        let optional = |name: &str, max: usize| -> IamResult<Option<String>> {
            match given(name) {
                None => Ok(None),
                Some(value) => Ok(Some(
                    js_trim(&text(Some(value), &format!("{at}.{name}"), max)?).to_owned(),
                )),
            }
        };
        let empty = Value::Object(Map::new());
        let posture = fields_of(Some(given("posture").unwrap_or(&empty)), &POSTURE_FIELDS)?;
        let mut reported = Map::new();
        for field in POSTURE_FIELDS {
            if let Some(value) = posture.get(field).filter(|value| !value.is_null()) {
                reported.insert(
                    field.to_owned(),
                    Value::Bool(flag(Some(value), &format!("{at}.posture.{field}"))?),
                );
            }
        }
        let mut os_version = None;
        if let Some(os) = given("osVersion") {
            let os = match os {
                Value::String(os) if utf16_len(os) <= 64 => os,
                _ => {
                    return Err(invalid(format!(
                        "{at}.osVersion must be a string of at most 64 characters"
                    )));
                }
            };
            os_version = leading_version(js_trim(os))
                .filter(|version| is_os_version_str(version))
                .map(str::to_owned);
        }
        let owner_identity_id = optional("ownerIdentityId", 256)?;
        let owner_email = optional("ownerEmail", 254)?.map(|email| to_lower(&email));
        let key_thumbprint = match given("keyThumbprint") {
            None => None,
            Some(Value::String(thumbprint)) if is_device_key_id(thumbprint) => {
                Some(thumbprint.clone())
            }
            Some(_) => {
                return Err(invalid(format!(
                    "{at}.keyThumbprint must be a JWK thumbprint"
                )));
            }
        };
        let checked_in_at = match given("checkedInAt") {
            None => now,
            Some(reported_at) => integer(
                Some(reported_at),
                &format!("{at}.checkedInAt"),
                0.0,
                now + 5.0 * 60_000.0,
            )?
            .min(now),
        };
        let name = optional("name", 128)?;
        let serial_number = optional("serialNumber", 128)?;
        let model = optional("model", 128)?;
        let platform = platform_of(input.get("platform"), &format!("{at}.platform"))?;
        items.push(ReportItem {
            external_id,
            name: name.filter(|name| !name.is_empty()),
            platform,
            serial_number: serial_number.filter(|serial| !serial.is_empty()),
            model: model.filter(|model| !model.is_empty()),
            os_version: os_version.filter(|version| !version.is_empty()),
            owner_named: owner_identity_id.is_some() || owner_email.is_some(),
            owner_identity_id: owner_identity_id.filter(|id| !id.is_empty()),
            owner_email: owner_email.filter(|email| !email.is_empty()),
            key_thumbprint,
            posture: reported,
            checked_in_at,
        });
    }
    Ok(items)
}

/// What a report can change on a device, for telling a real change from a repeated check-in.
fn reported_state(device: &Record) -> String {
    let posture = device.get("posture");
    let mut state = vec![
        or_null(device.get("name")),
        or_null(device.get("platform")),
        or_null(device.get("ownerIdentityId")),
        or_null(device.get("serialNumber")),
        or_null(device.get("model")),
        or_null(member(posture, "integrationId")),
    ];
    for field in POSTURE_FIELDS {
        state.push(or_null(member(posture, field)));
    }
    state.push(or_null(member(posture, "osVersion")));
    better_iam_core::js::stringify(&Value::Array(state))
}

async fn audit(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    action: &str,
    tenant_id: &str,
    resource_id: &str,
    metadata: Map<String, Value>,
) -> IamResult<()> {
    ctx.events()?
        .audit(
            tx,
            principal,
            action,
            tenant_id,
            resource_id,
            AuditOutcome::Allow,
            false,
            Some(metadata),
        )
        .await
}

/// The id of the device this request's proof verifies for, if any.
async fn current_device_id(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
) -> Option<Value> {
    presented(tx, principal, ctx.now())
        .await
        .and_then(|device| device.device.get("id").cloned())
}

/// A pending, unexpired enrollment code of the tenant, or INVALID_INPUT.
async fn usable_enrollment(tx: &Store, tenant_id: &str, code: &str, now: f64) -> IamResult<Record> {
    let code_hash = Value::String(hash(code));
    let enrollment = find(
        tx,
        ENROLLMENTS,
        &filter_of(&[
            ("tenantId", Some(&Value::String(tenant_id.to_owned()))),
            ("uniqueKey", Some(&code_hash)),
        ]),
    )
    .await?
    .into_iter()
    .next();
    let expired =
        |enrollment: &Record| enrollment.get("expiresAt").map_or(f64::NAN, to_number) <= now;
    match enrollment {
        Some(enrollment)
            if same_hash_value(enrollment.get("codeHash"), Some(&code_hash))
                && !enrollment.contains_key("usedAt")
                && !expired(&enrollment) =>
        {
            Ok(enrollment)
        }
        _ => Err(invalid_code()),
    }
}

/// A person of the tenant, for owner fields; INVALID_INPUT for anyone else. Returns the identity's id.
async fn owner_of(tx: &Store, tenant_id: &str, value: Option<&Value>) -> IamResult<Value> {
    let identity = tx
        .get("identities", &text(value, "ownerIdentityId", 256)?)
        .await?;
    if !person(identity.as_ref(), tenant_id) {
        return Err(invalid("ownerIdentityId must name a person of the tenant"));
    }
    Ok(identity
        .and_then(|identity| identity.get("id").cloned())
        .unwrap_or(Value::Null))
}

/// Moves a key an integration's agent enrolled onto the device the integration reports it on. Only the key's own
/// record of this machine gives it up: the same person's self-enrolled device, or another record of this integration
/// with the same owner, and only while that device is active. So a report never revives a key on a device an
/// administrator marked lost, never takes one off a shared device, another person's device, or a device another
/// integration manages, and never hands a key to a device without the key's owner.
async fn claim_key(tx: &Store, thumbprint: &str, device: &Record, now: f64) -> IamResult<bool> {
    let Some(key) = tx.get(KEYS, thumbprint).await? else {
        return Ok(false);
    };
    if !same(key.get("tenantId"), device.get("tenantId"))
        || same(key.get("deviceId"), device.get("id"))
    {
        return Ok(false);
    }
    let previous = match key.get("deviceId").and_then(Value::as_str) {
        Some(device_id) => tx.get(DEVICES, device_id).await?,
        None => None,
    };
    let Some(previous) = previous else {
        return Ok(false);
    };
    let other_integration = previous.get("source").is_some_and(|source| {
        !same(
            member(Some(source), "integrationId"),
            member(device.get("source"), "integrationId"),
        )
    });
    if !same(previous.get("tenantId"), device.get("tenantId"))
        || !is_str(previous.get("status"), "active")
        || !previous.contains_key("ownerIdentityId")
        || !same(
            previous.get("ownerIdentityId"),
            device.get("ownerIdentityId"),
        )
        || other_integration
    {
        return Ok(false);
    }
    let mut moved = key.clone();
    moved.insert(
        "deviceId".into(),
        device.get("id").cloned().unwrap_or(Value::Null),
    );
    tx.put(KEYS, &moved).await?;
    // The same person's self-enrolled record of this machine is superseded by the managed one.
    if !truthy(previous.get("source"))
        && find(
            tx,
            KEYS,
            &filter_of(&[
                ("tenantId", previous.get("tenantId")),
                ("deviceId", previous.get("id")),
            ]),
        )
        .await?
        .is_empty()
    {
        retire_device(tx, &previous, now).await?;
    }
    Ok(true)
}

/// The `devices` API group (`createDevicesApi(ctx)`): one method per route `devices/{method}`.
pub struct DevicesApi {
    ctx: Arc<ServerContext>,
}

/// `createDevicesApi(ctx)`.
pub fn create_devices_api(ctx: &Arc<ServerContext>) -> IamResult<DevicesApi> {
    Ok(DevicesApi { ctx: ctx.clone() })
}

impl DevicesApi {
    // -------------------------------------------------------------------------------------------------------------
    // Self-service

    /// `devices/enroll`: enrols a key for the caller's device (people only, from an ordinary session of their tenant;
    /// never while impersonating). Without `enrollmentCode` it registers a new unmanaged device the caller owns (at
    /// most 20 per person). With a code from `devices.createEnrollment` it binds the key to the code's device (which
    /// must be active and shared or the caller's) or, when the code names none, creates one owned by the code's
    /// person (unset: a shared device); the code is then used up. The request must carry a device proof signed with
    /// that key for this session, and the session needs a recent sign-in. Rate limited per person; audited as
    /// `device:enroll`.
    pub async fn enroll(
        &self,
        credential: &CredentialInput,
        input: Body<devices::EnrollInput>,
    ) -> IamResult<Reply<devices::EnrollOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let name = device_name(input.get("name"))?;
        let platform = platform_of(input.get("platform"), "platform")?;
        let jwk = public_key_of(input.get("publicKey"))?;
        let code = match input.get("enrollmentCode") {
            None => None,
            Some(Value::String(code)) if is_enrollment_code(code) => Some(code.clone()),
            Some(_) => return Err(invalid_code()),
        };
        let key_id = key_id_of(&jwk)?;
        let ctx = self.ctx.clone();
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        if authenticated.session.tenant_id != tenant_id {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                "Devices are enrolled from an ordinary session of their tenant",
                403,
            ));
        }
        // Outside the transaction, so a refusal inside it cannot roll the counter back.
        ctx.auth
            .limit_attempt(
                &tenant_id,
                &format!("device-enroll:{}", authenticated.identity.id),
                LimitAttemptOptions {
                    limit: Some(ENROLL_ATTEMPTS),
                    ..LimitAttemptOptions::default()
                },
            )
            .await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                own_session(
                    &principal,
                    &tenant_id,
                    "Devices are enrolled from an ordinary session of their tenant",
                )?;
                not_impersonating(&principal)?;
                if principal.identity.kind != IdentityKind::User {
                    return Err(invalid("Only people enrol devices"));
                }
                // A stolen session must not bring a key of its own (passkey registration asks for a recent sign-in
                // too), and the caller must hold the key: the request carries a proof signed with it for this session.
                ctx.auth.require_recent(&principal)?;
                if !proves_possession(&principal, &jwk, &key_id, ctx.now()).await {
                    return Err(invalid(
                        "Send a device proof (x-better-iam-device) signed with the key being enrolled",
                    ));
                }
                let caller_id = Value::String(principal.identity.id.clone());
                if tx.get(KEYS, &key_id).await?.is_some() {
                    return Err(IamError::with_status(
                        "CONFLICT",
                        "This key is already enrolled",
                        409,
                    ));
                }
                let now = ctx.now();
                let enrollment = match &code {
                    Some(code) => Some(usable_enrollment(&tx, &tenant_id, code, now).await?),
                    None => None,
                };
                let enrollment_owner = enrollment
                    .as_ref()
                    .and_then(|enrollment| enrollment.get("ownerIdentityId"));
                if enrollment_owner.is_some_and(|owner| !strict_equal(owner, &caller_id)) {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "This enrollment code is for someone else",
                        403,
                    ));
                }
                let tenant = Value::String(tenant_id.clone());
                let device: Record;
                let mut created = false;
                let enrollment_device = enrollment
                    .as_ref()
                    .and_then(|enrollment| enrollment.get("deviceId"));
                if let Some(target_id) = enrollment_device {
                    let target = match target_id.as_str() {
                        Some(target_id) => tx.get(DEVICES, target_id).await?,
                        None => None,
                    };
                    let target = match target {
                        Some(target) if is_str(target.get("tenantId"), &tenant_id) => target,
                        _ => return Err(invalid_code()),
                    };
                    if !is_str(target.get("status"), "active") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The device is not active",
                            409,
                        ));
                    }
                    if target
                        .get("ownerIdentityId")
                        .is_some_and(|owner| !strict_equal(owner, &caller_id))
                    {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "The device belongs to someone else",
                            403,
                        ));
                    }
                    let keys = find(
                        &tx,
                        KEYS,
                        &filter_of(&[("tenantId", Some(&tenant)), ("deviceId", target.get("id"))]),
                    )
                    .await?;
                    if keys.len() as f64 >= MAX_KEYS_PER_DEVICE {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A device can hold at most {} keys",
                                crate::js::number(MAX_KEYS_PER_DEVICE)
                            ),
                            409,
                        ));
                    }
                    let mut next = target.clone();
                    if let Some(owner) = enrollment_owner {
                        next.insert("ownerIdentityId".into(), owner.clone());
                    }
                    next.insert("enrolledBy".into(), caller_id.clone());
                    next.insert("updatedAt".into(), crate::js::number(now));
                    device = tx.put(DEVICES, &next).await?;
                } else {
                    // Without a code the caller owns the device; a code without a device names its owner (or none:
                    // shared).
                    let owner = match &enrollment {
                        Some(_) => enrollment_owner.cloned(),
                        None => Some(caller_id.clone()),
                    };
                    if let Some(owner) = &owner {
                        let owned = find(
                            &tx,
                            DEVICES,
                            &filter_of(&[("tenantId", Some(&tenant)), ("ownerIdentityId", Some(owner))]),
                        )
                        .await?
                        .into_iter()
                        .filter(|record| !is_str(record.get("status"), "retired"))
                        .count();
                        if owned as f64 >= MAX_DEVICES_PER_PERSON {
                            return Err(IamError::with_status(
                                "LIMIT_EXCEEDED",
                                format!(
                                    "A person can register at most {} devices",
                                    crate::js::number(MAX_DEVICES_PER_PERSON)
                                ),
                                409,
                            ));
                        }
                    }
                    let mut record = Map::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), tenant.clone());
                    record.insert("name".into(), Value::String(name.clone()));
                    record.insert("platform".into(), Value::String(platform.clone()));
                    record.insert("status".into(), Value::String("active".into()));
                    if let Some(owner) = owner {
                        record.insert("ownerIdentityId".into(), owner);
                    }
                    record.insert("enrolledBy".into(), caller_id.clone());
                    record.insert("createdAt".into(), crate::js::number(now));
                    record.insert("updatedAt".into(), crate::js::number(now));
                    device = tx.insert(DEVICES, &record).await?;
                    created = true;
                }
                let mut key = Map::new();
                key.insert("id".into(), Value::String(key_id.clone()));
                key.insert("tenantId".into(), tenant.clone());
                key.insert(
                    "deviceId".into(),
                    device.get("id").cloned().unwrap_or(Value::Null),
                );
                key.insert("jwk".into(), jwk.clone());
                key.insert("createdAt".into(), crate::js::number(now));
                key.insert("createdBy".into(), caller_id.clone());
                tx.insert(KEYS, &key).await?;
                if let Some(enrollment) = &enrollment {
                    let mut used = enrollment.clone();
                    used.insert("usedAt".into(), crate::js::number(now));
                    used.insert("usedBy".into(), caller_id.clone());
                    tx.put(ENROLLMENTS, &used).await?;
                }
                let device_id = str_of(&device, "id").to_owned();
                let mut metadata = Map::new();
                copy_as(&mut metadata, "deviceId", device.get("id"));
                metadata.insert("keyId".into(), Value::String(key_id.clone()));
                copy_as(&mut metadata, "platform", device.get("platform"));
                metadata.insert("created".into(), Value::Bool(created));
                metadata.insert(
                    "managed".into(),
                    Value::Bool(device.contains_key("source")),
                );
                if let Some(enrollment) = &enrollment {
                    copy_as(&mut metadata, "enrollmentId", enrollment.get("id"));
                }
                audit(
                    &ctx,
                    &tx,
                    &principal,
                    "device:enroll",
                    &tenant_id,
                    &device_resource(&device_id),
                    metadata,
                )
                .await?;
                let mut view = describe(&tx, &tenant_id, std::slice::from_ref(&device), now)
                    .await?
                    .into_iter()
                    .next()
                    .unwrap_or_default();
                let current = current_device_id(&ctx, &tx, &principal).await;
                view.insert(
                    "current".into(),
                    Value::Bool(same(current.as_ref(), device.get("id"))),
                );
                Ok(json!({ "device": view, "keyId": key_id }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/mine`: the caller's devices that are not retired, the one this request presents first (`current`),
    /// each with its compliance and assurance. Needs only an ordinary session of the tenant; readable while
    /// impersonating.
    pub async fn mine(
        &self,
        credential: &CredentialInput,
        input: Body<devices::MineInput>,
    ) -> IamResult<Reply<devices::MineOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let ctx = self.ctx.clone();
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                own_session(
                    &principal,
                    &tenant_id,
                    "Devices are listed from an ordinary session of their tenant",
                )?;
                let devices: Vec<Record> = find(
                    &tx,
                    DEVICES,
                    &filter_of(&[
                        ("tenantId", Some(&Value::String(tenant_id.clone()))),
                        (
                            "ownerIdentityId",
                            Some(&Value::String(principal.identity.id.clone())),
                        ),
                    ]),
                )
                .await?
                .into_iter()
                .filter(|device| !is_str(device.get("status"), "retired"))
                .collect();
                let current = current_device_id(&ctx, &tx, &principal).await;
                let mut views: Vec<(bool, Record)> = describe(&tx, &tenant_id, &devices, ctx.now())
                    .await?
                    .into_iter()
                    .map(|mut view| {
                        let is_current = same(view.get("id"), current.as_ref());
                        view.insert("current".into(), Value::Bool(is_current));
                        (is_current, view)
                    })
                    .collect();
                views.sort_by(|(a_current, a), (b_current, b)| {
                    b_current
                        .cmp(a_current)
                        .then_with(|| by_newest_records(a, b))
                });
                Ok(Value::Array(
                    views
                        .into_iter()
                        .map(|(_, view)| Value::Object(view))
                        .collect(),
                ))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/retireMine`: retires one of the caller's own unmanaged devices: it stops proving anything and its keys
    /// are deleted. Managed devices are retired by administrators. Needs a recent sign-in, never while impersonating;
    /// audited as `device:retire`.
    pub async fn retire_mine(
        &self,
        credential: &CredentialInput,
        input: Body<devices::RetireMineInput>,
    ) -> IamResult<Reply<devices::RetireMineOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let device_id = text(input.get("deviceId"), "deviceId", 256)?;
        let ctx = self.ctx.clone();
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                own_session(
                    &principal,
                    &tenant_id,
                    "Devices are retired from an ordinary session of their tenant",
                )?;
                not_impersonating(&principal)?;
                // A stolen session must not take the person's own devices away either.
                ctx.auth.require_recent(&principal)?;
                let device = ctx
                    .scoped(&tx, DEVICES, Some(&Value::String(device_id)), &tenant_id)
                    .await?;
                if !is_str(device.get("ownerIdentityId"), &principal.identity.id) {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "Resource not found",
                        404,
                    ));
                }
                if truthy(device.get("source")) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Managed devices are retired by administrators",
                        409,
                    ));
                }
                if is_str(device.get("status"), "retired") {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "The device is already retired",
                        409,
                    ));
                }
                let (_, keys_removed) = retire_device(&tx, &device, ctx.now()).await?;
                let mut metadata = Map::new();
                copy_as(&mut metadata, "deviceId", device.get("id"));
                metadata.insert("keysRemoved".into(), crate::js::number(keys_removed as f64));
                metadata.insert("self".into(), Value::Bool(true));
                audit(
                    &ctx,
                    &tx,
                    &principal,
                    "device:retire",
                    &tenant_id,
                    &device_resource(str_of(&device, "id")),
                    metadata,
                )
                .await?;
                Ok(json!({
                    "success": true,
                    "keysRemoved": crate::js::number(keys_removed as f64),
                }))
            })
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/check`: what the device presenting this request proves: its assurance, id, platform and compliance,
    /// or `none` when the request carries no valid proof (`proof` says which). Records when the device and key were
    /// last seen (at most once a minute). Needs only a session of the tenant.
    pub async fn check(
        &self,
        credential: &CredentialInput,
        input: Body<devices::CheckInput>,
    ) -> IamResult<Reply<devices::CheckOutput>> {
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let ctx = self.ctx.clone();
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let store = ctx.store.clone();
        let result = store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, &authenticated)
                    .await?;
                if principal.session.tenant_id != tenant_id {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Devices are checked from a session of their tenant",
                        403,
                    ));
                }
                let now = ctx.now();
                let Some(presented) = presented(&tx, &principal, now).await else {
                    let proof = if principal.device_proof.is_none() {
                        "absent"
                    } else {
                        "invalid"
                    };
                    return Ok(json!({
                        "assurance": "none",
                        "managed": false,
                        "compliant": false,
                        "reasons": [],
                        "proof": proof,
                    }));
                };
                let (device, key, compliance) =
                    (&presented.device, &presented.key, &presented.compliance);
                if now - given_member(device, "lastSeenAt").map_or(0.0, to_number) >= TOUCH_MS {
                    let mut touched = device.clone();
                    touched.insert("lastSeenAt".into(), crate::js::number(now));
                    tx.put(DEVICES, &touched).await?;
                }
                if now - given_member(key, "lastUsedAt").map_or(0.0, to_number) >= TOUCH_MS {
                    let mut touched = key.clone();
                    touched.insert("lastUsedAt".into(), crate::js::number(now));
                    tx.put(KEYS, &touched).await?;
                }
                let mut out = Map::new();
                out.insert(
                    "assurance".into(),
                    Value::String(presented.assurance.into()),
                );
                copy_as(&mut out, "deviceId", device.get("id"));
                copy_as(&mut out, "platform", device.get("platform"));
                out.insert("managed".into(), Value::Bool(compliance.managed));
                out.insert("compliant".into(), Value::Bool(compliance.compliant));
                out.insert("reasons".into(), json!(compliance.reasons));
                out.insert("proof".into(), Value::String("verified".into()));
                Ok(Value::Object(out))
            })
            .await?;
        Ok(Reply::json(result))
    }

    // -------------------------------------------------------------------------------------------------------------
    // Administration

    /// `devices/list`: the tenant's devices, newest first, each with compliance, assurance, key count and owner.
    /// Filters: owner, status, platform, `managed`, `compliant`, and `query` (name, serial number, model, external id
    /// or owner, case insensitive). Requires iam:devices:read on `iam/devices`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<devices::ListInput>,
    ) -> IamResult<Reply<devices::ListOutput>> {
        let defaulted = |name: &str, fallback: f64| {
            input
                .get(name)
                .filter(|value| !value.is_null())
                .cloned()
                .unwrap_or_else(|| crate::js::number(fallback))
        };
        let limit = integer(Some(&defaulted("limit", 100.0)), "limit", 1.0, 1000.0)?;
        let offset = integer(Some(&defaulted("offset", 0.0)), "offset", 0.0, 1_000_000.0)?;
        let owner_identity_id = match input.get("ownerIdentityId") {
            None => None,
            Some(value) => Some(text(Some(value), "ownerIdentityId", 256)?),
        };
        let status = input.get("status").cloned();
        if let Some(status) = &status
            && !["active", "lost", "retired"]
                .iter()
                .any(|wanted| is_str(Some(status), wanted))
        {
            return Err(invalid("status must be active, lost or retired"));
        }
        let platform = match input.get("platform") {
            None => None,
            Some(value) => Some(platform_of(Some(value), "platform")?),
        };
        let managed = match input.get("managed") {
            None => None,
            Some(value) => Some(flag(Some(value), "managed")?),
        };
        let compliant = match input.get("compliant") {
            None => None,
            Some(value) => Some(flag(Some(value), "compliant")?),
        };
        let query = match input.get("query") {
            None => None,
            Some(value) => Some(to_lower(js_trim(&text(Some(value), "query", 200)?))),
        };
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let tenant_value = Value::String(tenant.id.clone());
                let mut filter = filter_of(&[("tenantId", Some(&tenant_value))]);
                if let Some(owner) = &owner_identity_id {
                    filter.set("ownerIdentityId", Some(Value::String(owner.clone())));
                }
                if let Some(status) = &status {
                    filter.set("status", Some(status.clone()));
                }
                if let Some(platform) = &platform {
                    filter.set("platform", Some(Value::String(platform.clone())));
                }
                let devices = find(&tx, DEVICES, &filter).await?;
                let mut views: Vec<Record> = describe(&tx, &tenant.id, &devices, ctx.now())
                    .await?
                    .into_iter()
                    .filter(|view| {
                        let compliance = view.get("compliance");
                        let flag_is = |name: &str, wanted: Option<bool>| {
                            wanted.is_none_or(|wanted| {
                                member(compliance, name) == Some(&Value::Bool(wanted))
                            })
                        };
                        flag_is("managed", managed)
                            && flag_is("compliant", compliant)
                            && query.as_deref().is_none_or(|query| {
                                query.is_empty()
                                    || [
                                        view.get("id"),
                                        view.get("name"),
                                        view.get("serialNumber"),
                                        view.get("model"),
                                        member(view.get("source"), "externalId"),
                                        member(view.get("owner"), "name"),
                                        member(view.get("owner"), "email"),
                                    ]
                                    .into_iter()
                                    .any(|value| {
                                        value
                                            .and_then(Value::as_str)
                                            .is_some_and(|value| to_lower(value).contains(query))
                                    })
                            })
                    })
                    .collect();
                views.sort_by(by_newest_records);
                let total = views.len();
                let page: Vec<Value> = views
                    .into_iter()
                    .skip(offset as usize)
                    .take(limit as usize)
                    .map(Value::Object)
                    .collect();
                Ok(json!({ "devices": page, "total": crate::js::number(total as f64) }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:read",
                "devices",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/get`: one device with its keys. Requires iam:devices:read on `iam/devices/{id}`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<devices::GetInput>,
    ) -> IamResult<Reply<devices::GetOutput>> {
        let device_id = text(input.get("deviceId"), "deviceId", 256)?;
        let resource = device_resource(&device_id);
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let device = ctx
                    .scoped(&tx, DEVICES, Some(&Value::String(device_id)), &tenant.id)
                    .await?;
                let mut view = describe(&tx, &tenant.id, std::slice::from_ref(&device), ctx.now())
                    .await?
                    .into_iter()
                    .next()
                    .unwrap_or_default();
                let mut keys = find(
                    &tx,
                    KEYS,
                    &filter_of(&[
                        ("tenantId", Some(&Value::String(tenant.id.clone()))),
                        ("deviceId", device.get("id")),
                    ]),
                )
                .await?;
                keys.sort_by(by_newest_records);
                let public_keys: Vec<Value> = keys
                    .iter()
                    .map(|key| {
                        let mut out = Map::new();
                        copy(&mut out, key, "id");
                        let algorithm = key
                            .get("jwk")
                            .and_then(device_key_algorithm)
                            .unwrap_or("ES256");
                        out.insert("algorithm".into(), Value::String(algorithm.into()));
                        copy(&mut out, key, "createdAt");
                        copy(&mut out, key, "createdBy");
                        copy(&mut out, key, "lastUsedAt");
                        Value::Object(out)
                    })
                    .collect();
                view.insert("publicKeys".into(), Value::Array(public_keys));
                Ok(Value::Object(view))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/update`: renames a device, reassigns it (`ownerIdentityId`, a person of the tenant, or `null` for a
    /// shared device) or marks it `lost` (it stops proving anything) or `active` again. A new owner drops the keys the
    /// previous owner enrolled. Retired devices cannot change. Requires iam:devices:manage on `iam/devices/{id}` and
    /// recent authentication; audited as `device:update`.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<devices::UpdateInput>,
    ) -> IamResult<Reply<devices::UpdateOutput>> {
        check_fields(
            &input,
            &["tenantId", "deviceId", "name", "ownerIdentityId", "status"],
        )?;
        let device_id = text(input.get("deviceId"), "deviceId", 256)?;
        let name = match input.get("name") {
            None => None,
            Some(value) => Some(device_name(Some(value))?),
        };
        let status = input.get("status").cloned();
        if let Some(status) = &status
            && !is_str(Some(status), "active")
            && !is_str(Some(status), "lost")
        {
            return Err(invalid("status must be active or lost"));
        }
        let owner_input = input.get("ownerIdentityId").cloned();
        if name.is_none() && status.is_none() && owner_input.is_none() {
            return Err(invalid("Nothing to update"));
        }
        let resource = device_resource(&device_id);
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let device = ctx
                        .scoped(&tx, DEVICES, Some(&Value::String(device_id)), &tenant.id)
                        .await?;
                    if is_str(device.get("status"), "retired") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Retired devices cannot change",
                            409,
                        )
                        .into());
                    }
                    let previous_owner = device.get("ownerIdentityId").cloned();
                    let owner = match &owner_input {
                        None => previous_owner.clone(),
                        Some(Value::Null) => None,
                        Some(value) => Some(owner_of(&tx, &tenant.id, Some(value)).await?),
                    };
                    let next_status = status.clone().or_else(|| device.get("status").cloned());
                    let now = ctx.now();
                    let mut keys_removed = 0usize;
                    if !same(owner.as_ref(), previous_owner.as_ref())
                        && let Some(previous) = &previous_owner
                    {
                        for key in find(
                            &tx,
                            KEYS,
                            &filter_of(&[
                                ("tenantId", Some(&Value::String(tenant.id.clone()))),
                                ("deviceId", device.get("id")),
                                ("createdBy", Some(previous)),
                            ]),
                        )
                        .await?
                        {
                            tx.delete(KEYS, str_of(&key, "id")).await?;
                            keys_removed += 1;
                        }
                    }
                    let mut next = device.clone();
                    next.shift_remove("ownerIdentityId");
                    match &name {
                        Some(name) => {
                            next.insert("name".into(), Value::String(name.clone()));
                        }
                        None => set_or_remove(&mut next, "name", device.get("name")),
                    }
                    match &next_status {
                        Some(status) => {
                            next.insert("status".into(), status.clone());
                        }
                        None => {
                            next.shift_remove("status");
                        }
                    }
                    if let Some(owner) = &owner {
                        next.insert("ownerIdentityId".into(), owner.clone());
                    }
                    next.insert("updatedAt".into(), crate::js::number(now));
                    let next = tx.put(DEVICES, &next).await?;
                    let mut before = Map::new();
                    copy_as(&mut before, "name", device.get("name"));
                    copy_as(&mut before, "status", device.get("status"));
                    before.insert("ownerIdentityId".into(), or_null(previous_owner.as_ref()));
                    let mut after = Map::new();
                    copy_as(&mut after, "name", next.get("name"));
                    copy_as(&mut after, "status", next.get("status"));
                    after.insert("ownerIdentityId".into(), or_null(owner.as_ref()));
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "deviceId", device.get("id"));
                    metadata.insert("before".into(), Value::Object(before));
                    metadata.insert("after".into(), Value::Object(after));
                    metadata.insert("keysRemoved".into(), crate::js::number(keys_removed as f64));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:update",
                        &tenant.id,
                        &device_resource(str_of(&device, "id")),
                        metadata,
                    )
                    .await?;
                    let view = describe(&tx, &tenant.id, std::slice::from_ref(&next), now)
                        .await?
                        .into_iter()
                        .next()
                        .unwrap_or_default();
                    Ok(Value::Object(view))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/retire`: retires a device for good: it stops proving anything, its keys and pending enrollment codes
    /// are deleted, and an integration's later reports keep it retired. Requires iam:devices:manage on
    /// `iam/devices/{id}` and recent authentication; audited as `device:retire`.
    pub async fn retire(
        &self,
        credential: &CredentialInput,
        input: Body<devices::RetireInput>,
    ) -> IamResult<Reply<devices::RetireOutput>> {
        let device_id = text(input.get("deviceId"), "deviceId", 256)?;
        let resource = device_resource(&device_id);
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let device = ctx
                        .scoped(&tx, DEVICES, Some(&Value::String(device_id)), &tenant.id)
                        .await?;
                    if is_str(device.get("status"), "retired") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The device is already retired",
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let (retired, keys_removed) = retire_device(&tx, &device, now).await?;
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "deviceId", device.get("id"));
                    metadata.insert("keysRemoved".into(), crate::js::number(keys_removed as f64));
                    metadata.insert("self".into(), Value::Bool(false));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:retire",
                        &tenant.id,
                        &device_resource(str_of(&device, "id")),
                        metadata,
                    )
                    .await?;
                    let view = describe(&tx, &tenant.id, std::slice::from_ref(&retired), now)
                        .await?
                        .into_iter()
                        .next()
                        .unwrap_or_default();
                    Ok(Value::Object(view))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/delete`: deletes a device with its keys and enrollment codes (a managed device reappears with the
    /// integration's next report). Requires iam:devices:manage on `iam/devices/{id}` and recent authentication; audited
    /// as `device:delete`.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<devices::DeleteInput>,
    ) -> IamResult<Reply<devices::DeleteOutput>> {
        let device_id = text(input.get("deviceId"), "deviceId", 256)?;
        let resource = device_resource(&device_id);
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let device = ctx
                        .scoped(&tx, DEVICES, Some(&Value::String(device_id)), &tenant.id)
                        .await?;
                    let scope = filter_of(&[
                        ("tenantId", Some(&Value::String(tenant.id.clone()))),
                        ("deviceId", device.get("id")),
                    ]);
                    let keys = find(&tx, KEYS, &scope).await?;
                    for key in &keys {
                        tx.delete(KEYS, str_of(key, "id")).await?;
                    }
                    let enrollments = find(&tx, ENROLLMENTS, &scope).await?;
                    for enrollment in &enrollments {
                        tx.delete(ENROLLMENTS, str_of(enrollment, "id")).await?;
                    }
                    tx.delete(DEVICES, str_of(&device, "id")).await?;
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "deviceId", device.get("id"));
                    copy_as(&mut metadata, "name", device.get("name"));
                    metadata.insert("managed".into(), Value::Bool(device.contains_key("source")));
                    metadata.insert("keysRemoved".into(), crate::js::number(keys.len() as f64));
                    metadata.insert(
                        "enrollmentsRemoved".into(),
                        crate::js::number(enrollments.len() as f64),
                    );
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:delete",
                        &tenant.id,
                        &device_resource(str_of(&device, "id")),
                        metadata,
                    )
                    .await?;
                    Ok(json!({
                        "success": true,
                        "keysRemoved": crate::js::number(keys.len() as f64),
                        "enrollmentsRemoved": crate::js::number(enrollments.len() as f64),
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/removeKey`: removes one key from a device (a lost browser profile, a replaced agent). Requires
    /// iam:devices:manage on `iam/devices/{id}` and recent authentication; audited as `device:key-remove`.
    pub async fn remove_key(
        &self,
        credential: &CredentialInput,
        input: Body<devices::RemoveKeyInput>,
    ) -> IamResult<Reply<devices::RemoveKeyOutput>> {
        let device_id = text(input.get("deviceId"), "deviceId", 256)?;
        let key_id = text(input.get("keyId"), "keyId", 256)?;
        let resource = device_resource(&device_id);
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let device = ctx
                        .scoped(&tx, DEVICES, Some(&Value::String(device_id)), &tenant.id)
                        .await?;
                    let key = tx.get(KEYS, &key_id).await?;
                    let key = match key {
                        Some(key)
                            if is_str(key.get("tenantId"), &tenant.id)
                                && same(key.get("deviceId"), device.get("id")) =>
                        {
                            key
                        }
                        _ => {
                            return Err(IamError::with_status(
                                "NOT_FOUND",
                                "Resource not found",
                                404,
                            )
                            .into());
                        }
                    };
                    tx.delete(KEYS, str_of(&key, "id")).await?;
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "deviceId", device.get("id"));
                    copy_as(&mut metadata, "keyId", key.get("id"));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:key-remove",
                        &tenant.id,
                        &device_resource(str_of(&device, "id")),
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "success": true }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/createEnrollment`: creates a one-time enrollment code (`biam_denr_…`, shown only in this answer) valid
    /// for `expiresInMs` (10 minutes to 30 days, default 7 days). With `deviceId` the code binds a key to that device;
    /// without it, enrolment creates a new device. `ownerIdentityId` limits the code to that person (a device with an
    /// owner implies it). Requires iam:devices:manage on `iam/devices/enrollments` (and, with `deviceId`, on
    /// `iam/devices/{id}`) and recent authentication; audited as `device:enrollment-create`.
    pub async fn create_enrollment(
        &self,
        credential: &CredentialInput,
        input: Body<devices::CreateEnrollmentInput>,
    ) -> IamResult<Reply<devices::CreateEnrollmentOutput>> {
        let device_id = match input.get("deviceId") {
            None => None,
            Some(value) => Some(text(Some(value), "deviceId", 256)?),
        };
        let lifetime = integer(
            Some(
                &input
                    .get("expiresInMs")
                    .filter(|value| !value.is_null())
                    .cloned()
                    .unwrap_or_else(|| crate::js::number(DEFAULT_ENROLLMENT_MS)),
            ),
            "expiresInMs",
            MIN_ENROLLMENT_MS,
            MAX_ENROLLMENT_MS,
        )?;
        let owner_input = input.get("ownerIdentityId").cloned();
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let now = ctx.now();
                    let mut owner = match &owner_input {
                        None => None,
                        Some(value) => Some(owner_of(&tx, &tenant.id, Some(value)).await?),
                    };
                    if let Some(device_id) = &device_id {
                        let device = ctx
                            .scoped(
                                &tx,
                                DEVICES,
                                Some(&Value::String(device_id.clone())),
                                &tenant.id,
                            )
                            .await?;
                        // Using the code adds a key to the device (and may give a shared one an owner), which
                        // devices.update and removeKey allow only with iam:devices:manage on the device itself.
                        let on_device = ctx
                            .decisions()?
                            .decide(
                                &tx,
                                &principal,
                                &AuthorizationRequest {
                                    credential: CredentialInput::default(),
                                    tenant_id: tenant.id.clone(),
                                    action: "iam:devices:manage".into(),
                                    resource: ResourceTarget {
                                        kind: "iam".into(),
                                        id: device_resource(str_of(&device, "id")),
                                    },
                                },
                                true,
                            )
                            .await?;
                        if !on_device.allowed {
                            return Err(OperationDenied::new(Some(
                                "A code for an existing device requires iam:devices:manage on that device",
                            )));
                        }
                        if !is_str(device.get("status"), "active") {
                            return Err(IamError::with_status(
                                "INVALID_TRANSITION",
                                "The device is not active",
                                409,
                            )
                            .into());
                        }
                        if let Some(device_owner) = device.get("ownerIdentityId") {
                            if owner
                                .as_ref()
                                .is_some_and(|owner| !strict_equal(owner, device_owner))
                            {
                                return Err(invalid("The device belongs to someone else").into());
                            }
                            owner = Some(device_owner.clone());
                        }
                    }
                    let tenant_value = Value::String(tenant.id.clone());
                    let pending = find(
                        &tx,
                        ENROLLMENTS,
                        &filter_of(&[("tenantId", Some(&tenant_value))]),
                    )
                    .await?
                    .into_iter()
                    .filter(|enrollment| {
                        !enrollment.contains_key("usedAt")
                            && enrollment.get("expiresAt").map_or(f64::NAN, to_number) > now
                    })
                    .count();
                    if pending >= MAX_PENDING_ENROLLMENTS {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A tenant can hold at most {MAX_PENDING_ENROLLMENTS} pending enrollment codes"
                            ),
                            409,
                        )
                        .into());
                    }
                    let code = format!("biam_denr_{}", token());
                    let code_hash = hash(&code);
                    let mut record = Map::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), tenant_value.clone());
                    record.insert("uniqueKey".into(), Value::String(code_hash.clone()));
                    record.insert("codeHash".into(), Value::String(code_hash));
                    if let Some(device_id) = &device_id {
                        record.insert("deviceId".into(), Value::String(device_id.clone()));
                    }
                    if let Some(owner) = &owner {
                        record.insert("ownerIdentityId".into(), owner.clone());
                    }
                    record.insert("expiresAt".into(), crate::js::number(now + lifetime));
                    record.insert("createdAt".into(), crate::js::number(now));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let enrollment = tx.insert(ENROLLMENTS, &record).await?;
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "enrollmentId", enrollment.get("id"));
                    metadata.insert(
                        "deviceId".into(),
                        device_id.clone().map_or(Value::Null, Value::String),
                    );
                    metadata.insert("ownerIdentityId".into(), or_null(owner.as_ref()));
                    copy_as(&mut metadata, "expiresAt", enrollment.get("expiresAt"));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:enrollment-create",
                        &tenant.id,
                        "devices/enrollments",
                        metadata,
                    )
                    .await?;
                    let mut out = Map::new();
                    out.insert("code".into(), Value::String(code));
                    copy_as(&mut out, "expiresAt", enrollment.get("expiresAt"));
                    copy_as(&mut out, "enrollmentId", enrollment.get("id"));
                    Ok(Value::Object(out))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                "devices/enrollments",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/listEnrollments`: the tenant's enrollment codes (without the codes), newest first. Requires
    /// iam:devices:manage.
    pub async fn list_enrollments(
        &self,
        credential: &CredentialInput,
        input: Body<devices::ListEnrollmentsInput>,
    ) -> IamResult<Reply<devices::ListEnrollmentsOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let now = ctx.now();
                let mut enrollments = find(
                    &tx,
                    ENROLLMENTS,
                    &filter_of(&[("tenantId", Some(&Value::String(tenant.id.clone())))]),
                )
                .await?;
                enrollments.sort_by(by_newest_records);
                Ok(Value::Array(
                    enrollments
                        .iter()
                        .map(|enrollment| Value::Object(enrollment_view(enrollment, now)))
                        .collect(),
                ))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                "devices/enrollments",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/revokeEnrollment`: withdraws an enrollment code. Requires iam:devices:manage; audited as
    /// `device:enrollment-revoke`.
    pub async fn revoke_enrollment(
        &self,
        credential: &CredentialInput,
        input: Body<devices::RevokeEnrollmentInput>,
    ) -> IamResult<Reply<devices::RevokeEnrollmentOutput>> {
        let enrollment_id = text(input.get("enrollmentId"), "enrollmentId", 256)?;
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let enrollment = ctx
                        .scoped(
                            &tx,
                            ENROLLMENTS,
                            Some(&Value::String(enrollment_id)),
                            &tenant.id,
                        )
                        .await?;
                    tx.delete(ENROLLMENTS, str_of(&enrollment, "id")).await?;
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "enrollmentId", enrollment.get("id"));
                    metadata.insert("deviceId".into(), or_null(enrollment.get("deviceId")));
                    metadata.insert(
                        "used".into(),
                        Value::Bool(enrollment.contains_key("usedAt")),
                    );
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:enrollment-revoke",
                        &tenant.id,
                        "devices/enrollments",
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "success": true }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                "devices/enrollments",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/getSettings`: the tenant's compliance requirements (defaults until configured). Requires
    /// iam:devices:read on `iam/devices/settings`.
    pub async fn get_settings(
        &self,
        credential: &CredentialInput,
        input: Body<devices::GetSettingsInput>,
    ) -> IamResult<Reply<devices::GetSettingsOutput>> {
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let stored = stored_device_settings(&tx, &tenant.id).await?;
                Ok(Value::Object(settings_view(&tenant.id, stored.as_ref())))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:read",
                "devices/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/configure`: sets the compliance requirements managed devices must meet; fields left out keep their
    /// value, and `minOsVersions` (platform to dotted version) replaces the whole map. `maxCheckInAgeHours` is 1 to
    /// 720. Requires iam:devices:manage on `iam/devices/settings` and recent authentication; audited as
    /// `device:settings`.
    pub async fn configure(
        &self,
        credential: &CredentialInput,
        input: Body<devices::ConfigureInput>,
    ) -> IamResult<Reply<devices::ConfigureOutput>> {
        let mut allowed = vec!["tenantId"];
        allowed.extend(SETTINGS_FLAGS);
        allowed.extend(["minOsVersions", "maxCheckInAgeHours"]);
        check_fields(&input, &allowed)?;
        let mut changes = Map::new();
        for name in SETTINGS_FLAGS {
            if let Some(value) = input.get(name) {
                changes.insert(name.to_owned(), Value::Bool(flag(Some(value), name)?));
            }
        }
        if let Some(value) = input.get("minOsVersions") {
            let mut minimums = Map::new();
            for (platform, version) in entries(object(Some(value))?) {
                let key = platform_of(
                    Some(&Value::String(platform.clone())),
                    "minOsVersions platform",
                )?;
                if !is_os_version(Some(version)) {
                    return Err(invalid(format!(
                        "minOsVersions.{key} must be a dotted version such as 14.5"
                    )));
                }
                minimums.insert(key, version.clone());
            }
            changes.insert("minOsVersions".into(), Value::Object(minimums));
        }
        if let Some(value) = input.get("maxCheckInAgeHours") {
            changes.insert(
                "maxCheckInAgeHours".into(),
                crate::js::number(integer(Some(value), "maxCheckInAgeHours", 1.0, 720.0)?),
            );
        }
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let previous = stored_device_settings(&tx, &tenant.id).await?;
                    let before = resolve_device_settings(previous.as_ref());
                    let mut record = Map::new();
                    record.insert("id".into(), Value::String(tenant.id.clone()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.extend(before.to_json());
                    for (key, value) in changes {
                        record.insert(key, value);
                    }
                    record.insert("updatedAt".into(), crate::js::number(ctx.now()));
                    record.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    let saved = if previous.is_some() {
                        tx.put(SETTINGS, &record).await?
                    } else {
                        tx.insert(SETTINGS, &record).await?
                    };
                    let mut metadata = Map::new();
                    metadata.insert("before".into(), Value::Object(before.to_json()));
                    metadata.insert(
                        "after".into(),
                        Value::Object(resolve_device_settings(Some(&saved)).to_json()),
                    );
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:settings",
                        &tenant.id,
                        "devices/settings",
                        metadata,
                    )
                    .await?;
                    Ok(Value::Object(settings_view(&tenant.id, Some(&saved))))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                "devices/settings",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/listIntegrations`: the tenant's device integrations with the number of devices each manages. Requires
    /// iam:devices:read.
    pub async fn list_integrations(
        &self,
        credential: &CredentialInput,
        input: Body<devices::ListIntegrationsInput>,
    ) -> IamResult<Reply<devices::ListIntegrationsOutput>> {
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let tenant_value = Value::String(tenant.id.clone());
                let scope = filter_of(&[("tenantId", Some(&tenant_value))]);
                let mut counts: HashMap<String, usize> = HashMap::new();
                for device in find(&tx, DEVICES, &scope).await? {
                    if truthy(device.get("source"))
                        && let Some(integration_id) =
                            member(device.get("source"), "integrationId").and_then(Value::as_str)
                    {
                        *counts.entry(integration_id.to_owned()).or_default() += 1;
                    }
                }
                let mut integrations = find(&tx, INTEGRATIONS, &scope).await?;
                integrations.sort_by(|a, b| locale_compare(str_of(a, "name"), str_of(b, "name")));
                Ok(Value::Array(
                    integrations
                        .iter()
                        .map(|integration| {
                            let count = counts.get(str_of(integration, "id")).copied().unwrap_or(0);
                            Value::Object(integration_view(integration, count))
                        })
                        .collect(),
                ))
            })
        });
        let result = self
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:read",
                "devices/integrations",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/createIntegration`: adds an MDM or EDR integration (at most 20 per tenant, names unique). Its reporter
    /// needs `iam:devices:report` on `iam/devices/integrations/{id}`. `trustVendorCompliance` (default true) accepts the
    /// vendor's own verdict next to the tenant's requirements. Requires iam:devices:manage and recent authentication;
    /// audited as `device:integration-create`.
    pub async fn create_integration(
        &self,
        credential: &CredentialInput,
        input: Body<devices::CreateIntegrationInput>,
    ) -> IamResult<Reply<devices::CreateIntegrationOutput>> {
        check_fields(
            &input,
            &["tenantId", "name", "vendor", "trustVendorCompliance"],
        )?;
        let name = js_trim(&text(input.get("name"), "name", 100)?).to_owned();
        let vendor = match input.get("vendor") {
            Some(Value::String(vendor))
                if DEVICE_INTEGRATION_VENDORS.contains(&vendor.as_str()) =>
            {
                vendor.clone()
            }
            _ => {
                return Err(invalid(format!(
                    "vendor must be one of {}",
                    DEVICE_INTEGRATION_VENDORS.join(", ")
                )));
            }
        };
        let trust = match input.get("trustVendorCompliance") {
            None => true,
            Some(value) => flag(Some(value), "trustVendorCompliance")?,
        };
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let tenant_value = Value::String(tenant.id.clone());
                    let existing = find(
                        &tx,
                        INTEGRATIONS,
                        &filter_of(&[("tenantId", Some(&tenant_value))]),
                    )
                    .await?;
                    let unique_key = format!("name:{}", to_lower(&name));
                    if existing
                        .iter()
                        .any(|integration| is_str(integration.get("uniqueKey"), &unique_key))
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "An integration with this name exists",
                            409,
                        )
                        .into());
                    }
                    if existing.len() as f64 >= MAX_DEVICE_INTEGRATIONS {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!(
                                "A tenant can have at most {} device integrations",
                                crate::js::number(MAX_DEVICE_INTEGRATIONS)
                            ),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let mut record = Map::new();
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), tenant_value.clone());
                    record.insert("uniqueKey".into(), Value::String(unique_key));
                    record.insert("name".into(), Value::String(name));
                    record.insert("vendor".into(), Value::String(vendor));
                    record.insert("status".into(), Value::String("active".into()));
                    record.insert("trustVendorCompliance".into(), Value::Bool(trust));
                    record.insert("createdAt".into(), crate::js::number(now));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("updatedAt".into(), crate::js::number(now));
                    let integration = tx.insert(INTEGRATIONS, &record).await?;
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "integrationId", integration.get("id"));
                    metadata.extend(integration_metadata(&integration));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:integration-create",
                        &tenant.id,
                        &integration_resource(str_of(&integration, "id")),
                        metadata,
                    )
                    .await?;
                    Ok(Value::Object(integration_view(&integration, 0)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                "devices/integrations",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/updateIntegration`: renames an integration, disables it (its devices stop counting as managed) or
    /// enables it, or changes whether its vendor verdict counts. Requires iam:devices:manage on
    /// `iam/devices/integrations/{id}` and recent authentication; audited as `device:integration-update`.
    pub async fn update_integration(
        &self,
        credential: &CredentialInput,
        input: Body<devices::UpdateIntegrationInput>,
    ) -> IamResult<Reply<devices::UpdateIntegrationOutput>> {
        check_fields(
            &input,
            &[
                "tenantId",
                "integrationId",
                "name",
                "status",
                "trustVendorCompliance",
            ],
        )?;
        let integration_id = text(input.get("integrationId"), "integrationId", 256)?;
        let name = match input.get("name") {
            None => None,
            Some(value) => Some(js_trim(&text(Some(value), "name", 100)?).to_owned()),
        };
        let status = input.get("status").cloned();
        if let Some(status) = &status
            && !is_str(Some(status), "active")
            && !is_str(Some(status), "disabled")
        {
            return Err(invalid("status must be active or disabled"));
        }
        let trust = match input.get("trustVendorCompliance") {
            None => None,
            Some(value) => Some(flag(Some(value), "trustVendorCompliance")?),
        };
        let resource = integration_resource(&integration_id);
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let integration = ctx
                        .scoped(
                            &tx,
                            INTEGRATIONS,
                            Some(&Value::String(integration_id)),
                            &tenant.id,
                        )
                        .await?;
                    let tenant_value = Value::String(tenant.id.clone());
                    let unique_key = match &name {
                        None => integration.get("uniqueKey").cloned(),
                        Some(name) => Some(Value::String(format!("name:{}", to_lower(name)))),
                    };
                    if name.is_some()
                        && find(
                            &tx,
                            INTEGRATIONS,
                            &filter_of(&[
                                ("tenantId", Some(&tenant_value)),
                                ("uniqueKey", unique_key.as_ref()),
                            ]),
                        )
                        .await?
                        .iter()
                        .any(|other| !same(other.get("id"), integration.get("id")))
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "An integration with this name exists",
                            409,
                        )
                        .into());
                    }
                    let mut next = integration.clone();
                    if let Some(unique_key) = &unique_key {
                        next.insert("uniqueKey".into(), unique_key.clone());
                    }
                    if let Some(name) = &name {
                        next.insert("name".into(), Value::String(name.clone()));
                    } else {
                        set_or_remove(&mut next, "name", integration.get("name"));
                    }
                    match status.as_ref().filter(|status| !status.is_null()) {
                        Some(status) => {
                            next.insert("status".into(), status.clone());
                        }
                        None => set_or_remove(&mut next, "status", integration.get("status")),
                    }
                    match trust {
                        Some(trust) => {
                            next.insert("trustVendorCompliance".into(), Value::Bool(trust));
                        }
                        None => set_or_remove(
                            &mut next,
                            "trustVendorCompliance",
                            integration.get("trustVendorCompliance"),
                        ),
                    }
                    next.insert("updatedAt".into(), crate::js::number(ctx.now()));
                    let next = tx.put(INTEGRATIONS, &next).await?;
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "integrationId", integration.get("id"));
                    metadata.insert(
                        "before".into(),
                        Value::Object(integration_metadata(&integration)),
                    );
                    metadata.insert("after".into(), Value::Object(integration_metadata(&next)));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:integration-update",
                        &tenant.id,
                        &integration_resource(str_of(&integration, "id")),
                        metadata,
                    )
                    .await?;
                    let managed = find(
                        &tx,
                        DEVICES,
                        &filter_of(&[("tenantId", Some(&tenant_value))]),
                    )
                    .await?
                    .iter()
                    .filter(|device| {
                        let source = device.get("source").filter(|source| !source.is_null());
                        source.is_some()
                            && same(member(source, "integrationId"), integration.get("id"))
                    })
                    .count();
                    Ok(Value::Object(integration_view(&next, managed)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `devices/deleteIntegration`: deletes an integration. While it manages devices the call is refused
    /// (RESOURCE_IN_USE) unless `detach` is true: its devices then become unmanaged (they keep their keys and last
    /// posture, but no longer count as managed). Requires iam:devices:manage on `iam/devices/integrations/{id}` and
    /// recent authentication; audited as `device:integration-delete`.
    pub async fn delete_integration(
        &self,
        credential: &CredentialInput,
        input: Body<devices::DeleteIntegrationInput>,
    ) -> IamResult<Reply<devices::DeleteIntegrationOutput>> {
        let integration_id = text(input.get("integrationId"), "integrationId", 256)?;
        let detach = match input.get("detach") {
            None => false,
            Some(value) => flag(Some(value), "detach")?,
        };
        let resource = integration_resource(&integration_id);
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let integration = ctx
                        .scoped(
                            &tx,
                            INTEGRATIONS,
                            Some(&Value::String(integration_id)),
                            &tenant.id,
                        )
                        .await?;
                    let managed: Vec<Record> = find(
                        &tx,
                        DEVICES,
                        &filter_of(&[("tenantId", Some(&Value::String(tenant.id.clone())))]),
                    )
                    .await?
                    .into_iter()
                    .filter(|device| {
                        let source = device.get("source").filter(|source| !source.is_null());
                        source.is_some()
                            && same(member(source, "integrationId"), integration.get("id"))
                    })
                    .collect();
                    if !managed.is_empty() && !detach {
                        return Err(IamError::with_status(
                            "RESOURCE_IN_USE",
                            format!(
                                "The integration manages {} devices; pass detach to make them unmanaged",
                                managed.len()
                            ),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    for device in &managed {
                        let mut rest = device.clone();
                        rest.shift_remove("source");
                        rest.shift_remove("uniqueKey");
                        rest.insert("updatedAt".into(), crate::js::number(now));
                        tx.put(DEVICES, &rest).await?;
                    }
                    tx.delete(INTEGRATIONS, str_of(&integration, "id")).await?;
                    let mut metadata = Map::new();
                    copy_as(&mut metadata, "integrationId", integration.get("id"));
                    copy_as(&mut metadata, "name", integration.get("name"));
                    metadata.insert("detached".into(), crate::js::number(managed.len() as f64));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:integration-delete",
                        &tenant.id,
                        &integration_resource(str_of(&integration, "id")),
                        metadata,
                    )
                    .await?;
                    Ok(json!({
                        "success": true,
                        "detached": crate::js::number(managed.len() as f64),
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    // -------------------------------------------------------------------------------------------------------------
    // Integration reports

    /// `devices/report`: an integration reports up to 500 devices with their posture, all or nothing. Devices are
    /// matched by the integration's `externalId` and created on first sight; a report that names an owner (identity id
    /// or email of a person of the tenant) sets it, and an unknown one clears it. `keyThumbprint` moves a key the
    /// integration's agent enrolled onto the reported device. Repeated check-ins within a minute that change nothing
    /// (not even compliance) are not written, and reports older than the device's last check-in are ignored. Retired
    /// devices stay retired. The integration must be active. Requires iam:devices:report on
    /// `iam/devices/integrations/{id}`; audited once per call as `device:report`, plus `device:compliance-change` for
    /// each existing device whose compliance flipped.
    pub async fn report(
        &self,
        credential: &CredentialInput,
        input: Body<devices::ReportInput>,
    ) -> IamResult<Reply<devices::ReportOutput>> {
        let integration_id = text(input.get("integrationId"), "integrationId", 256)?;
        let ctx = &self.ctx;
        let items = report_items(input.get("devices"), ctx.now())?;
        let resource = integration_resource(&integration_id);
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let integration = ctx
                        .scoped(
                            &tx,
                            INTEGRATIONS,
                            Some(&Value::String(integration_id)),
                            &tenant.id,
                        )
                        .await?;
                    if !is_str(integration.get("status"), "active") {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The integration is disabled",
                            409,
                        )
                        .into());
                    }
                    let settings = device_settings_of(&tx, &tenant.id).await?;
                    let now = ctx.now();
                    let tenant_value = Value::String(tenant.id.clone());
                    let integration_key = integration.get("id").cloned().unwrap_or(Value::Null);
                    let integration_text = crate::js::js_string(integration.get("id"));
                    let mut owners: HashMap<String, Option<String>> = HashMap::new();
                    let (mut created, mut updated, mut unchanged, mut compliance_changed) =
                        (0usize, 0usize, 0usize, 0usize);
                    for item in &items {
                        let unique_key =
                            Value::String(format!("src:{integration_text}:{}", item.external_id));
                        let existing = find(
                            &tx,
                            DEVICES,
                            &filter_of(&[
                                ("tenantId", Some(&tenant_value)),
                                ("uniqueKey", Some(&unique_key)),
                            ]),
                        )
                        .await?
                        .into_iter()
                        .next();
                        if let Some(existing) = &existing
                            && let Some(last) = existing.get("lastCheckInAt")
                            && item.checked_in_at < to_number(last)
                        {
                            unchanged += 1;
                            continue;
                        }
                        let owner: Option<Value> = if item.owner_named {
                            resolve_owner(&tx, &tenant.id, item, &mut owners)
                                .await?
                                .map(Value::String)
                        } else {
                            existing
                                .as_ref()
                                .and_then(|existing| existing.get("ownerIdentityId").cloned())
                        };
                        let mut posture = item.posture.clone();
                        if let Some(os_version) = &item.os_version {
                            posture.insert("osVersion".into(), Value::String(os_version.clone()));
                        }
                        posture.insert("reportedAt".into(), crate::js::number(item.checked_in_at));
                        posture.insert("integrationId".into(), integration_key.clone());
                        let existing_member = |key: &str| {
                            existing
                                .as_ref()
                                .and_then(|existing| given_member(existing, key))
                                .cloned()
                        };
                        let serial_number =
                            item.serial_number.clone().map(Value::String).or_else(|| {
                                existing
                                    .as_ref()
                                    .and_then(|existing| existing.get("serialNumber"))
                                    .cloned()
                            });
                        let model = item.model.clone().map(Value::String).or_else(|| {
                            existing
                                .as_ref()
                                .and_then(|existing| existing.get("model"))
                                .cloned()
                        });
                        let name = item
                            .name
                            .clone()
                            .map(Value::String)
                            .or_else(|| existing_member("name"))
                            .or_else(|| item.model.clone().map(Value::String))
                            .or_else(|| item.serial_number.clone().map(Value::String))
                            .unwrap_or_else(|| Value::String(item.external_id.clone()));
                        let name =
                            Value::String(slice_utf16(&crate::js::js_string(Some(&name)), 128));
                        let mut described = Map::new();
                        described.insert("name".into(), name);
                        described.insert("platform".into(), Value::String(item.platform.clone()));
                        if let Some(owner) = &owner {
                            described.insert("ownerIdentityId".into(), owner.clone());
                        }
                        if let Some(serial_number) = &serial_number {
                            described.insert("serialNumber".into(), serial_number.clone());
                        }
                        if let Some(model) = &model {
                            described.insert("model".into(), model.clone());
                        }
                        described.insert("posture".into(), Value::Object(posture.clone()));
                        described.insert(
                            "lastCheckInAt".into(),
                            crate::js::number(item.checked_in_at),
                        );
                        let Some(existing) = existing else {
                            let mut record = Map::new();
                            record.insert("id".into(), Value::String(id()));
                            record.insert("tenantId".into(), tenant_value.clone());
                            record.insert("uniqueKey".into(), unique_key.clone());
                            record.extend(described);
                            record.insert("status".into(), Value::String("active".into()));
                            record.insert(
                                "source".into(),
                                json!({
                                    "integrationId": integration_key,
                                    "externalId": item.external_id,
                                }),
                            );
                            record.insert("createdAt".into(), crate::js::number(now));
                            record.insert("updatedAt".into(), crate::js::number(now));
                            let device = tx.insert(DEVICES, &record).await?;
                            if let Some(thumbprint) = &item.key_thumbprint {
                                claim_key(&tx, thumbprint, &device, now).await?;
                            }
                            created += 1;
                            continue;
                        };
                        let mut next = existing.clone();
                        next.shift_remove("ownerIdentityId");
                        next.shift_remove("serialNumber");
                        next.shift_remove("model");
                        next.extend(described);
                        next.insert("updatedAt".into(), crate::js::number(now));
                        let changed = reported_state(&existing) != reported_state(&next);
                        let moved = match &item.key_thumbprint {
                            Some(thumbprint) => claim_key(&tx, thumbprint, &next, now).await?,
                            None => false,
                        };
                        let before =
                            evaluate_compliance(&existing, Some(&integration), &settings, now);
                        let after = evaluate_compliance(&next, Some(&integration), &settings, now);
                        let flipped = before.compliant != after.compliant;
                        // A check-in that flips compliance (the stored one had just gone stale) is written however
                        // soon it comes, so the verdict audited below is the one decisions see.
                        let due = flipped
                            || match existing.get("lastCheckInAt") {
                                None => true,
                                Some(last) => item.checked_in_at - to_number(last) >= TOUCH_MS,
                            };
                        if changed || moved {
                            tx.put(DEVICES, &next).await?;
                            updated += 1;
                        } else {
                            if due {
                                let mut touched = existing.clone();
                                touched.insert(
                                    "lastCheckInAt".into(),
                                    crate::js::number(item.checked_in_at),
                                );
                                touched.insert("posture".into(), Value::Object(posture.clone()));
                                tx.put(DEVICES, &touched).await?;
                            }
                            unchanged += 1;
                        }
                        if flipped {
                            compliance_changed += 1;
                            let mut metadata = Map::new();
                            copy_as(&mut metadata, "deviceId", existing.get("id"));
                            metadata.insert("integrationId".into(), integration_key.clone());
                            metadata.insert("from".into(), Value::Bool(before.compliant));
                            metadata.insert("to".into(), Value::Bool(after.compliant));
                            metadata.insert("reasons".into(), json!(after.reasons));
                            audit(
                                ctx,
                                &tx,
                                &principal,
                                "device:compliance-change",
                                &tenant.id,
                                &device_resource(str_of(&existing, "id")),
                                metadata,
                            )
                            .await?;
                        }
                    }
                    let mut reported = integration.clone();
                    reported.insert("lastReportAt".into(), crate::js::number(now));
                    tx.put(INTEGRATIONS, &reported).await?;
                    let count = |value: usize| crate::js::number(value as f64);
                    let mut metadata = Map::new();
                    metadata.insert("integrationId".into(), integration_key.clone());
                    metadata.insert("received".into(), count(items.len()));
                    metadata.insert("created".into(), count(created));
                    metadata.insert("updated".into(), count(updated));
                    metadata.insert("unchanged".into(), count(unchanged));
                    metadata.insert("complianceChanged".into(), count(compliance_changed));
                    audit(
                        ctx,
                        &tx,
                        &principal,
                        "device:report",
                        &tenant.id,
                        &integration_resource(&integration_text),
                        metadata,
                    )
                    .await?;
                    Ok(json!({
                        "created": count(created),
                        "updated": count(updated),
                        "unchanged": count(unchanged),
                        "complianceChanged": count(compliance_changed),
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:devices:report",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// `...(value !== undefined ? { key: value } : {})` for a member read from elsewhere.
fn copy_as(out: &mut Map<String, Value>, key: &str, value: Option<&Value>) {
    if let Some(value) = value {
        out.insert(key.to_owned(), value.clone());
    }
}

/// `{ ...record, key: value }` where `value` may be undefined (which JSON drops).
fn set_or_remove(record: &mut Record, key: &str, value: Option<&Value>) {
    match value {
        Some(value) => {
            record.insert(key.to_owned(), value.clone());
        }
        None => {
            record.shift_remove(key);
        }
    }
}

/// The owner a report names: a person of the tenant by identity id, else by email; None when neither is one
/// (`resolveOwner`, cached per call).
async fn resolve_owner(
    tx: &Store,
    tenant_id: &str,
    item: &ReportItem,
    owners: &mut HashMap<String, Option<String>>,
) -> IamResult<Option<String>> {
    if let Some(owner_identity_id) = &item.owner_identity_id {
        let key = format!("id:{owner_identity_id}");
        if !owners.contains_key(&key) {
            let identity = tx.get("identities", owner_identity_id).await?;
            let found = if person(identity.as_ref(), tenant_id) {
                identity
                    .as_ref()
                    .and_then(|identity| identity.get("id"))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            } else {
                None
            };
            owners.insert(key.clone(), found);
        }
        if let Some(Some(found)) = owners.get(&key) {
            return Ok(Some(found.clone()));
        }
    }
    let Some(owner_email) = &item.owner_email else {
        return Ok(None);
    };
    let key = format!("email:{owner_email}");
    if !owners.contains_key(&key) {
        let found = find(
            tx,
            "identities",
            &filter_of(&[
                ("tenantId", Some(&Value::String(tenant_id.to_owned()))),
                ("email", Some(&Value::String(owner_email.clone()))),
            ]),
        )
        .await?
        .into_iter()
        .find(|identity| person(Some(identity), tenant_id))
        .and_then(|identity| {
            identity
                .get("id")
                .and_then(Value::as_str)
                .map(str::to_owned)
        });
        owners.insert(key.clone(), found);
    }
    Ok(owners.get(&key).cloned().flatten())
}
