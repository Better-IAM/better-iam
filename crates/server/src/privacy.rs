//! Port of `packages/server/src/privacy.ts`.
//!
//! Privacy and consent management (GDPR, UK GDPR, CCPA/CPRA, LGPD, PIPEDA): the purposes a tenant processes personal
//! data for, each person's consent to them with a signed receipt and an append-only history, data-subject requests
//! with statutory deadlines, legal holds that stop erasure, and restriction of processing.

use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IdentityKind, IdentityStatus, Record,
};
use hmac::{Hmac, Mac};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::context::Store;
use crate::js::{invalid_input, utf16_len};
use crate::validation::{integer, text};

type HmacSha256 = Hmac<Sha256>;

/// `opt-in` needs a recorded grant; `opt-out` is allowed until the person withdraws (CCPA "do not sell or share").
/// A string union in TypeScript, kept as its JSON value so records written by any server round-trip unchanged.
pub type ConsentMode = Value;

/// A consent receipt the subject can keep: the decision, signed by the deployment (HMAC-SHA256 over canonical
/// JSON).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsentReceipt {
    #[serde(rename = "version")]
    pub version: f64,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(rename = "purpose")]
    pub purpose: Value,
    #[serde(rename = "granted")]
    pub granted: bool,
    #[serde(rename = "recordedAt")]
    pub recorded_at: f64,
    #[serde(rename = "source")]
    pub source: crate::privacy::ConsentSource,
    #[serde(rename = "method", default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(rename = "signature")]
    pub signature: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Where a consent record came from. `request` records were written while fulfilling a data-subject request.
/// A string union in TypeScript, kept as its JSON value so records written by any server round-trip unchanged.
pub type ConsentSource = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConsentState {
    #[serde(rename = "allowed")]
    pub allowed: bool,
    #[serde(rename = "reason")]
    pub reason: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// The lawful basis a purpose relies on (GDPR Art. 6). Only `consent` and `legitimate-interests` give people a say.
/// A string union in TypeScript, kept as its JSON value so records written by any server round-trip unchanged.
pub type LegalBasis = Value;

/// The current decision of one subject on one purpose (uniqueKey `{purposeId}:{subject}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyConsent {
    #[serde(rename = "purposeId")]
    pub purpose_id: String,
    #[serde(rename = "purposeKey")]
    pub purpose_key: String,
    /// `identity:{id}` for people with an account here, `external:{id}` for subjects the application names.
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    #[serde(rename = "granted")]
    pub granted: bool,
    /// The purpose version the decision was made on.
    #[serde(rename = "purposeVersion")]
    pub purpose_version: f64,
    #[serde(rename = "source")]
    pub source: crate::privacy::ConsentSource,
    #[serde(rename = "method", default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(rename = "recordedAt")]
    pub recorded_at: f64,
    #[serde(rename = "recordedBy")]
    pub recorded_by: String,
    /// Grants only: when the grant lapses (`consentLifetimeDays`).
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
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

/// One entry of the append-only consent history; erasure redacts `evidence`, `ip` and `userAgent`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyConsentEvent {
    #[serde(rename = "receiptId")]
    pub receipt_id: String,
    #[serde(rename = "purposeId")]
    pub purpose_id: String,
    #[serde(rename = "purposeKey")]
    pub purpose_key: String,
    /// The purpose's name and basis when the decision was made, so the receipt can be rebuilt exactly later.
    #[serde(rename = "purposeName")]
    pub purpose_name: String,
    #[serde(rename = "legalBasis")]
    pub legal_basis: crate::privacy::LegalBasis,
    #[serde(rename = "purposeVersion")]
    pub purpose_version: f64,
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    #[serde(rename = "granted")]
    pub granted: bool,
    #[serde(rename = "source")]
    pub source: crate::privacy::ConsentSource,
    #[serde(rename = "method", default, skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    /// What the person saw or where the decision was captured (a form version, a banner text hash).
    #[serde(rename = "evidence", default, skip_serializing_if = "Option::is_none")]
    pub evidence: Option<String>,
    #[serde(rename = "ip", default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(rename = "userAgent", default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(rename = "recordedAt")]
    pub recorded_at: f64,
    #[serde(rename = "recordedBy")]
    pub recorded_by: String,
    #[serde(rename = "redacted", default, skip_serializing_if = "Option::is_none")]
    pub redacted: Option<bool>,
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

/// A generated access or portability export, downloadable until `expiresAt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyExport {
    #[serde(rename = "requestId")]
    pub request_id: String,
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(rename = "scope")]
    pub scope: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    /// SHA-256 of the canonical JSON of `data`, so a copy handed over can be checked later.
    #[serde(rename = "sha256")]
    pub sha256: String,
    #[serde(rename = "data")]
    pub data: better_iam_core::Json,
    #[serde(rename = "downloads")]
    pub downloads: f64,
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

/// A legal hold: erasure of the subject is refused until it is released or lapses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyHold {
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    #[serde(rename = "reason")]
    pub reason: String,
    #[serde(rename = "placedBy")]
    pub placed_by: String,
    #[serde(rename = "placedAt")]
    pub placed_at: f64,
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
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

/// A processing purpose, such as `marketing-email` or `product-analytics`. Keys are unique per tenant.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyPurpose {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "name")]
    pub name: String,
    /// What is processed and why, as shown to people when they decide (plain text, at most 5 000 characters).
    #[serde(rename = "description")]
    pub description: String,
    #[serde(rename = "legalBasis")]
    pub legal_basis: crate::privacy::LegalBasis,
    #[serde(rename = "mode")]
    pub mode: crate::privacy::ConsentMode,
    /// Bumped when the purpose changes materially; see `reconsentOnVersion`.
    #[serde(rename = "version")]
    pub version: f64,
    /// Categories of personal data the purpose uses (`contact`, `usage`, `location`, ...).
    #[serde(rename = "dataCategories")]
    pub data_categories: Vec<String>,
    /// How long data for this purpose is kept, for records of processing and people's information.
    #[serde(
        rename = "retentionDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub retention_days: Option<f64>,
    /// A grant lapses this many days after it was given (cookie consent is often 365).
    #[serde(
        rename = "consentLifetimeDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub consent_lifetime_days: Option<f64>,
    /// Opt-in grants given to an older version stop counting when a new version is published (default true).
    #[serde(rename = "reconsentOnVersion")]
    pub reconsent_on_version: bool,
    /// Archived purposes are no longer processed: every check refuses them and people no longer see them.
    #[serde(rename = "archived")]
    pub archived: bool,
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

/// Processing of a subject is restricted (GDPR Art. 18): only legal-obligation and vital-interests purposes pass.
/// An erasure of an application subject leaves one with `erased: true` as a suppression marker, so an opt-out or
/// objection the erased records held cannot turn back into "allowed" when the application asks about the same
/// identifier again.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyRestriction {
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    #[serde(rename = "requestId", default, skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(rename = "erased", default, skip_serializing_if = "Option::is_none")]
    pub erased: Option<bool>,
    #[serde(rename = "restrictedAt")]
    pub restricted_at: f64,
    #[serde(rename = "restrictedBy")]
    pub restricted_by: String,
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

/// Per-tenant privacy settings (one record per tenant, id `privacy:{tenantId}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacySettings {
    /// The privacy contact (data protection officer): emailed about new requests and approaching deadlines.
    #[serde(
        rename = "contactEmail",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub contact_email: Option<String>,
    #[serde(
        rename = "contactName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub contact_name: Option<String>,
    #[serde(rename = "defaultRegulation")]
    pub default_regulation: crate::privacy::Regulation,
    /// Shorter internal response windows per regulation (days, never longer than the statutory one).
    #[serde(
        rename = "responseDays",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub response_days: Option<Value>,
    /// Accept requests from people without an account through `privacy.submitPublic` (email confirmation).
    #[serde(rename = "publicIntake")]
    pub public_intake: bool,
    /// How long a generated export stays downloadable (default 14 days).
    #[serde(rename = "exportLifetimeDays")]
    pub export_lifetime_days: f64,
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

/// The regulations data-subject requests are answered under, with their statutory response windows.
/// A string union in TypeScript, kept as its JSON value so records written by any server round-trip unchanged.
pub type Regulation = Value;

/// A string union in TypeScript, kept as its JSON value so records written by any server round-trip unchanged.
pub type RejectionReason = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedSubject {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    #[serde(rename = "identity", default, skip_serializing_if = "Option::is_none")]
    pub identity: Option<better_iam_core::Identity>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A subject as callers name it: a person with an account in the tenant, or an application-side identifier.
/// `{ identityId } | { externalId }` in TypeScript, kept as JSON: [`resolve_subject`] validates it.
pub type SubjectInput = Value;

/// A data-subject request (DSR / DSAR); uniqueKey `number:{number}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SubjectRequest {
    /// Human reference such as `DSR-7K2M9QX4`.
    #[serde(rename = "number")]
    pub number: String,
    #[serde(rename = "type")]
    pub r#type: crate::privacy::SubjectRequestType,
    #[serde(rename = "regulation")]
    pub regulation: crate::privacy::Regulation,
    #[serde(rename = "status")]
    pub status: String,
    /// `identity:{id}` or `external:{id}`; public requests from an unknown address use `email:{sha256}`.
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(
        rename = "identityId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub identity_id: Option<String>,
    #[serde(
        rename = "externalId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub external_id: Option<String>,
    #[serde(
        rename = "requesterEmail",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub requester_email: Option<String>,
    #[serde(
        rename = "requesterName",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub requester_name: Option<String>,
    #[serde(rename = "details", default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    /// Objection, opt-out and restriction scope; empty means every purpose the person has a say in.
    #[serde(
        rename = "purposeKeys",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub purpose_keys: Option<Vec<String>>,
    #[serde(rename = "channel")]
    pub channel: String,
    #[serde(rename = "verification")]
    pub verification: Value,
    /// Public intake: the emailed confirmation token's hash and when it lapses.
    #[serde(rename = "tokenHash", default, skip_serializing_if = "Option::is_none")]
    pub token_hash: Option<String>,
    #[serde(
        rename = "tokenExpiresAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub token_expires_at: Option<f64>,
    /// Public intake: when the requester confirmed their address (requests naming an `externalId` still need a
    /// handler).
    #[serde(
        rename = "emailConfirmedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub email_confirmed_at: Option<f64>,
    #[serde(rename = "submittedAt")]
    pub submitted_at: f64,
    /// When the response window started (verification) and when it ends; absent while unverified.
    #[serde(
        rename = "receivedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub received_at: Option<f64>,
    #[serde(rename = "dueAt", default, skip_serializing_if = "Option::is_none")]
    pub due_at: Option<f64>,
    #[serde(
        rename = "extendedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub extended_at: Option<f64>,
    #[serde(
        rename = "extensionReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub extension_reason: Option<String>,
    #[serde(
        rename = "assigneeId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub assignee_id: Option<String>,
    #[serde(rename = "closedAt", default, skip_serializing_if = "Option::is_none")]
    pub closed_at: Option<f64>,
    #[serde(rename = "closedBy", default, skip_serializing_if = "Option::is_none")]
    pub closed_by: Option<String>,
    #[serde(
        rename = "rejectionReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rejection_reason: Option<String>,
    /// What fulfilling it did (`export`, `erased`, `consents-withdrawn:3`, `restricted`, ...).
    #[serde(rename = "actions", default, skip_serializing_if = "Option::is_none")]
    pub actions: Option<Vec<String>>,
    #[serde(rename = "exportId", default, skip_serializing_if = "Option::is_none")]
    pub export_id: Option<String>,
    /// Deadline reminders already sent (`due-soon`, `overdue`).
    #[serde(rename = "reminded", default, skip_serializing_if = "Option::is_none")]
    pub reminded: Option<Vec<String>>,
    /// Erasure removed the requester's contact details and free text from this record.
    #[serde(rename = "redacted", default, skip_serializing_if = "Option::is_none")]
    pub redacted: Option<bool>,
    #[serde(rename = "events")]
    pub events: Vec<crate::privacy::SubjectRequestEvent>,
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
pub struct SubjectRequestEvent {
    #[serde(rename = "at")]
    pub at: f64,
    /// Identity ID of whoever acted; `requester` for public intake steps, `deployment-operator` for jobs.
    #[serde(rename = "by")]
    pub by: String,
    #[serde(rename = "what")]
    pub what: String,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a data subject asks for.
/// A string union in TypeScript, kept as its JSON value so records written by any server round-trip unchanged.
pub type SubjectRequestType = Value;

pub const LEGAL_BASES: &[&str] = &[
    "consent",
    "contract",
    "legal-obligation",
    "vital-interests",
    "public-task",
    "legitimate-interests",
];

/// The statutory response windows per regulation (`regulationDeadlines`): GDPR and UK GDPR one month, extendable by
/// two further months (Art. 12(3)); CCPA 45 days, extendable once by 45 (Cal. Civ. Code 1798.130); LGPD 15 days for a
/// complete answer (Art. 19), no extension; PIPEDA 30 days, extendable by 30 (s. 8(3)).
pub static REGULATION_DEADLINES: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!({"gdpr":{"responseDays":30,"extensionDays":60},"uk-gdpr":{"responseDays":30,"extensionDays":60},"ccpa":{"responseDays":45,"extensionDays":45},"lgpd":{"responseDays":15,"extensionDays":0},"pipeda":{"responseDays":30,"extensionDays":30},"other":{"responseDays":30,"extensionDays":30}}),
);

/// `regulations`: `Object.keys(regulationDeadlines)`.
pub fn regulations() -> IamResult<Vec<crate::privacy::Regulation>> {
    Ok(REGULATION_DEADLINES
        .as_object()
        .map(|deadlines| {
            deadlines
                .keys()
                .map(|key| Value::String(key.clone()))
                .collect()
        })
        .unwrap_or_default())
}

pub const SUBJECT_REQUEST_TYPES: &[&str] = &[
    "access",
    "portability",
    "erasure",
    "rectification",
    "restriction",
    "objection",
    "opt-out",
];

pub const REJECTION_REASONS: &[&str] = &[
    "unverified",
    "unfounded",
    "excessive",
    "exempt",
    "duplicate",
    "no-data",
    "other",
];

/// `defaultPrivacySettings(tenantId)`: the settings of a tenant that never saved any.
pub fn default_privacy_settings(tenant_id: &str) -> PrivacySettings {
    PrivacySettings {
        contact_email: None,
        contact_name: None,
        default_regulation: Value::String("gdpr".into()),
        response_days: None,
        public_intake: false,
        export_lifetime_days: 14.0,
        updated_at: 0.0,
        id: format!("privacy:{tenant_id}"),
        tenant_id: tenant_id.to_owned(),
        unique_key: None,
        extra: Map::new(),
    }
}

/// [`default_privacy_settings`] as the record TypeScript builds, in its member order.
pub fn default_privacy_settings_record(tenant_id: &str) -> Record {
    let mut record = Record::new();
    record.insert("id".into(), Value::String(format!("privacy:{tenant_id}")));
    record.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    record.insert("defaultRegulation".into(), Value::String("gdpr".into()));
    record.insert("publicIntake".into(), Value::Bool(false));
    record.insert("exportLifetimeDays".into(), crate::js::number(14.0));
    record.insert("updatedAt".into(), crate::js::number(0.0));
    record
}

pub async fn privacy_settings(
    tx: &Store,
    tenant_id: &str,
) -> IamResult<crate::privacy::PrivacySettings> {
    match tx
        .get("privacySettings", &format!("privacy:{tenant_id}"))
        .await?
    {
        Some(record) => crate::port::decode(record),
        None => Ok(default_privacy_settings(tenant_id)),
    }
}

/// Application-side subject identifiers: 1-256 visible characters (a customer number, a visitor ID, an email hash).
pub fn external_subject_id(value: Option<&Value>) -> IamResult<String> {
    let result = text(value, "externalId", 256)?;
    if better_iam_core::js::trim(&result) != result {
        return Err(invalid_input("Invalid externalId"));
    }
    Ok(result)
}

/// Resolves a subject reference inside a tenant. Identities must be people (service accounts and agents have no
/// privacy rights of their own) and, unless `allowDeleted`, not tombstones.
pub async fn resolve_subject(
    tx: &Store,
    tenant_id: &str,
    value: Option<&Value>,
    allow_deleted: Option<bool>,
) -> IamResult<crate::privacy::ResolvedSubject> {
    let allow_deleted = allow_deleted.unwrap_or(false);
    let Some(Value::Object(input)) = value else {
        return Err(invalid_input(
            "subject must name an identityId or an externalId",
        ));
    };
    let has_identity = input.contains_key("identityId");
    let has_external = input.contains_key("externalId");
    if has_identity == has_external {
        return Err(invalid_input(
            "subject must name exactly one of identityId or externalId",
        ));
    }
    if has_external {
        let external_id = external_subject_id(input.get("externalId"))?;
        return Ok(ResolvedSubject {
            key: format!("external:{external_id}"),
            identity_id: None,
            external_id: Some(external_id),
            identity: None,
            extra: Map::new(),
        });
    }
    let identity_id = text(input.get("identityId"), "identityId", 256)?;
    let identity: Option<better_iam_core::Identity> =
        match tx.get("identities", &identity_id).await? {
            Some(record) => Some(crate::port::decode(record)?),
            None => None,
        };
    let Some(identity) = identity.filter(|identity| {
        identity.tenant_id == tenant_id
            && (allow_deleted || identity.status != IdentityStatus::Deleted)
    }) else {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Identity not found",
            404,
        ));
    };
    if identity.kind != IdentityKind::User {
        return Err(invalid_input("Only people are data subjects"));
    }
    Ok(ResolvedSubject {
        key: format!("identity:{}", identity.id),
        identity_id: Some(identity.id.clone()),
        external_id: None,
        identity: Some(identity),
        extra: Map::new(),
    })
}

pub fn identity_subject(identity_id: &str) -> IamResult<String> {
    Ok(format!("identity:{identity_id}"))
}

/// The subject of a request from someone without an account: a keyed hash of their address, so a redacted request
/// cannot be matched back to an email by hashing guesses.
pub fn email_subject(secret: &str, address: &str) -> IamResult<String> {
    let key = Sha256::digest(format!("better-iam:privacy-subject:{secret}").as_bytes());
    let mut mac = HmacSha256::new_from_slice(&key).expect("HMAC accepts any key length");
    mac.update(better_iam_core::js::to_lower(address).as_bytes());
    Ok(format!(
        "email:{}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

/// Purposes a person decides on: consent (opt-in or opt-out) and legitimate interests (objection).
pub fn decidable(purpose: &Value) -> IamResult<bool> {
    Ok(decidable_basis(crate::js::member(
        Some(purpose),
        "legalBasis",
    )))
}

/// `decidable` on a purpose's `legalBasis`.
fn decidable_basis(legal_basis: Option<&Value>) -> bool {
    matches!(legal_basis, Some(Value::String(basis)) if basis == "consent" || basis == "legitimate-interests")
}

fn state(allowed: bool, reason: &str) -> ConsentState {
    ConsentState {
        allowed,
        reason: reason.to_owned(),
        extra: Map::new(),
    }
}

/// The processing decision for one purpose and subject. Restriction holds back everything except legal obligations
/// and vital interests; bases other than consent and legitimate interests are allowed without a record. Opt-out
/// purposes and legitimate interests are allowed until the person withdraws or objects; opt-in consent needs a live
/// grant for the current version (unless the purpose keeps older grants valid).
///
/// `restricted` is `false`, `true` or `"erased"` ([`restriction_state`]).
pub fn consent_state(
    purpose: &crate::privacy::PrivacyPurpose,
    consent: Option<&crate::privacy::PrivacyConsent>,
    restricted: &Value,
    now: f64,
) -> IamResult<crate::privacy::ConsentState> {
    if purpose.archived {
        return Ok(state(false, "PURPOSE_ARCHIVED"));
    }
    if crate::js::truthy(Some(restricted))
        && purpose.legal_basis != "legal-obligation"
        && purpose.legal_basis != "vital-interests"
    {
        return Ok(state(
            false,
            if *restricted == "erased" {
                "ERASED"
            } else {
                "RESTRICTED"
            },
        ));
    }
    if purpose.legal_basis == "legitimate-interests" {
        return Ok(if consent.is_some_and(|consent| !consent.granted) {
            state(false, "OBJECTED")
        } else {
            state(true, "LEGITIMATE_INTERESTS")
        });
    }
    if purpose.legal_basis != "consent" {
        return Ok(state(true, "LEGAL_BASIS"));
    }
    if consent.is_some_and(|consent| !consent.granted) {
        return Ok(state(false, "CONSENT_WITHDRAWN"));
    }
    if purpose.mode == "opt-out" {
        return Ok(state(true, "NOT_OPTED_OUT"));
    }
    let Some(consent) = consent else {
        return Ok(state(false, "NO_CONSENT"));
    };
    if consent
        .expires_at
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Ok(state(false, "CONSENT_EXPIRED"));
    }
    if purpose.reconsent_on_version && consent.purpose_version < purpose.version {
        return Ok(state(false, "CONSENT_OUTDATED"));
    }
    Ok(state(true, "CONSENT_GIVEN"))
}

pub async fn restriction_of(
    tx: &Store,
    tenant_id: &str,
    subject: &str,
) -> IamResult<Option<crate::privacy::PrivacyRestriction>> {
    match tx
        .find(
            "privacyRestrictions",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subject", subject),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next()
    {
        Some(record) => Ok(Some(crate::port::decode(record)?)),
        None => Ok(None),
    }
}

/// How a restriction record feeds `consentState`: none, an ordinary restriction, or an erasure's suppression
/// marker.
pub fn restriction_state(
    restriction: Option<&crate::privacy::PrivacyRestriction>,
) -> IamResult<Value> {
    Ok(match restriction {
        Some(restriction) if restriction.erased == Some(true) => Value::String("erased".into()),
        Some(_) => Value::Bool(true),
        None => Value::Bool(false),
    })
}

/// The subject's current decision on every purpose, keyed by purpose ID.
pub async fn consents_of(
    tx: &Store,
    tenant_id: &str,
    subject: &str,
) -> IamResult<IndexMap<String, crate::privacy::PrivacyConsent>> {
    let mut consents = IndexMap::new();
    for record in tx
        .find(
            "privacyConsents",
            &Filter::new()
                .eq("tenantId", tenant_id)
                .eq("subject", subject),
            &FindOptions::default(),
        )
        .await?
    {
        let consent: PrivacyConsent = crate::port::decode(record)?;
        consents.insert(consent.purpose_id.clone(), consent);
    }
    Ok(consents)
}

pub const CONSENT_CONTEXT_KEY: &str = "principal.consents";

/// Whether any statement of the documents names `principal.consents` in a condition.
pub fn mentions_consents(documents: &[&better_iam_core::PolicyDocument]) -> bool {
    documents.iter().any(|document| {
        document.statements.iter().any(|statement| {
            statement.conditions.as_ref().is_some_and(|conditions| {
                conditions
                    .values()
                    .any(|block| block.contains_key(CONSENT_CONTEXT_KEY))
            })
        })
    })
}

/// Policy context for a person in their own tenant: `principal.consents` lists the keys of the consent and
/// legitimate-interest purposes that may be processed for them right now (granted, not opted out, not objected to,
/// not restricted). Service accounts and agents are not data subjects, so theirs is empty.
pub async fn consent_context(
    tx: &Store,
    tenant_id: &str,
    identity: &better_iam_core::Identity,
    now: f64,
) -> IamResult<Map<String, Value>> {
    let context = |keys: Vec<String>| {
        let mut context = Map::new();
        context.insert(
            CONSENT_CONTEXT_KEY.into(),
            Value::Array(keys.into_iter().map(Value::String).collect()),
        );
        context
    };
    if identity.kind != IdentityKind::User || identity.tenant_id != tenant_id {
        return Ok(context(Vec::new()));
    }
    let mut purposes: Vec<PrivacyPurpose> = Vec::new();
    for record in tx
        .find(
            "privacyPurposes",
            &Filter::new().eq("tenantId", tenant_id),
            &FindOptions::default(),
        )
        .await?
    {
        let purpose: PrivacyPurpose = crate::port::decode(record)?;
        if decidable_basis(Some(&purpose.legal_basis)) && !purpose.archived {
            purposes.push(purpose);
        }
    }
    if purposes.is_empty() {
        return Ok(context(Vec::new()));
    }
    let subject = identity_subject(&identity.id)?;
    let consents = consents_of(tx, tenant_id, &subject).await?;
    let restricted = Value::Bool(restriction_of(tx, tenant_id, &subject).await?.is_some());
    let mut keys = Vec::new();
    for purpose in &purposes {
        if consent_state(purpose, consents.get(&purpose.id), &restricted, now)?.allowed {
            keys.push(purpose.key.clone());
        }
    }
    crate::js::sort_strings(&mut keys);
    Ok(context(keys))
}

/// `receiptKey(secret)`: SHA-256 of `better-iam:privacy-receipt:{secret}`.
fn receipt_key(secret: &str) -> Vec<u8> {
    Sha256::digest(format!("better-iam:privacy-receipt:{secret}").as_bytes()).to_vec()
}

/// The receipt signature over a body (HMAC-SHA256 over its canonical JSON, base64url without padding).
fn receipt_signature(secret: &str, body: &Value) -> String {
    use base64::Engine;
    let mut mac =
        HmacSha256::new_from_slice(&receipt_key(secret)).expect("HMAC accepts any key length");
    mac.update(better_iam_core::canonical_json(body).as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
}

/// The receipt of a recorded decision; receipts are deterministic, so they are rebuilt rather than stored.
pub fn receipt_from_event(
    secret: &str,
    event: &crate::privacy::PrivacyConsentEvent,
) -> IamResult<crate::privacy::ConsentReceipt> {
    let mut purpose = Map::new();
    purpose.insert("key".into(), Value::String(event.purpose_key.clone()));
    purpose.insert("name".into(), Value::String(event.purpose_name.clone()));
    purpose.insert("version".into(), crate::js::number(event.purpose_version));
    purpose.insert("legalBasis".into(), event.legal_basis.clone());
    let mut body = Map::new();
    body.insert("version".into(), crate::js::number(1.0));
    body.insert("receiptId".into(), Value::String(event.receipt_id.clone()));
    body.insert("tenantId".into(), Value::String(event.tenant_id.clone()));
    body.insert("subject".into(), Value::String(event.subject.clone()));
    body.insert("purpose".into(), Value::Object(purpose));
    body.insert("granted".into(), Value::Bool(event.granted));
    body.insert("recordedAt".into(), crate::js::number(event.recorded_at));
    body.insert("source".into(), event.source.clone());
    if let Some(method) = event.method.as_deref().filter(|method| !method.is_empty()) {
        body.insert("method".into(), Value::String(method.to_owned()));
    }
    sign_receipt(secret, body)
}

/// `signReceipt(secret, body)`: the body with its `signature` appended.
pub fn sign_receipt(
    secret: &str,
    body: Map<String, Value>,
) -> IamResult<crate::privacy::ConsentReceipt> {
    let receipt = sign_receipt_value(secret, body);
    crate::port::decode(receipt)
}

/// [`sign_receipt`] as the JSON object TypeScript returns (`{ ...body, signature }`), member order kept.
pub fn sign_receipt_value(secret: &str, body: Map<String, Value>) -> Map<String, Value> {
    let mut receipt = body;
    receipt.shift_remove("signature");
    let signature = receipt_signature(secret, &Value::Object(receipt.clone()));
    receipt.insert("signature".into(), Value::String(signature));
    receipt
}

/// Whether a receipt was signed with one of the deployment's secrets (the current one or a previous one).
pub fn receipt_signature_valid(
    secrets: &[String],
    receipt: &crate::privacy::ConsentReceipt,
) -> IamResult<bool> {
    let receipt = serde_json::to_value(receipt)
        .map_err(|error| IamError::with_status("INTERNAL_ERROR", error.to_string(), 500))?;
    Ok(receipt_value_signature_valid(secrets, &receipt))
}

/// [`receipt_signature_valid`] on a receipt as JSON, exactly as TypeScript reads an untrusted one: every member but
/// `signature` is signed as given, and a missing or non-string signature never matches.
pub fn receipt_value_signature_valid(secrets: &[String], receipt: &Value) -> bool {
    let Some(receipt) = receipt.as_object() else {
        return false;
    };
    let Some(Value::String(signature)) = receipt.get("signature") else {
        return false;
    };
    let mut body = receipt.clone();
    body.shift_remove("signature");
    let body = Value::Object(body);
    secrets
        .iter()
        .any(|secret| crate::utils::same_hash(&receipt_signature(secret, &body), signature))
}

/// A request reference: `DSR-` and eight characters of Crockford base32.
pub fn request_number() -> IamResult<String> {
    const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut result = String::from("DSR-");
    for byte in better_iam_auth::crypto::random_bytes(8) {
        result.push(char::from(ALPHABET[usize::from(byte & 31)]));
    }
    Ok(result)
}

/// `Math.min(own, statutory)` for a stored `responseDays` member (JavaScript number coercion of the stored value).
fn js_min(own: &Value, statutory: f64) -> f64 {
    let own = match own {
        Value::Number(number) => better_iam_core::js::number_value(number),
        Value::Null => 0.0,
        Value::Bool(flag) => f64::from(u8::from(*flag)),
        _ => f64::NAN,
    };
    if own.is_nan() {
        f64::NAN
    } else {
        own.min(statutory)
    }
}

/// The response window for a regulation, shortened by the tenant's own `responseDays` when set.
pub fn response_window(
    regulation: &crate::privacy::Regulation,
    settings: &Value,
) -> IamResult<Value> {
    let Some(statutory) = regulation
        .as_str()
        .and_then(|regulation| REGULATION_DEADLINES.get(regulation))
    else {
        // `regulationDeadlines[regulation].responseDays` on an unknown regulation is a TypeError.
        return Err(crate::js::internal_error());
    };
    let statutory_response = statutory["responseDays"].as_f64().unwrap_or(f64::NAN);
    let statutory_extension = statutory["extensionDays"].as_f64().unwrap_or(f64::NAN);
    let own = match (
        crate::js::member(Some(settings), "responseDays"),
        regulation.as_str(),
    ) {
        (Some(Value::Object(days)), Some(regulation)) => days.get(regulation),
        _ => None,
    };
    let response_days = match own {
        Some(own) => js_min(own, statutory_response),
        None => statutory_response,
    };
    let mut window = Map::new();
    window.insert("responseDays".into(), crate::js::number(response_days));
    window.insert(
        "extensionDays".into(),
        crate::js::number(statutory_extension),
    );
    Ok(Value::Object(window))
}

pub const DAY_MS: f64 = 86400000.0;

/// A request is overdue once its deadline passed while it is still being handled.
pub fn request_overdue(request: &crate::privacy::SubjectRequest, now: f64) -> IamResult<bool> {
    Ok(request.status == "open" && request.due_at.is_some_and(|due_at| due_at <= now))
}

/// `hold.expiresAt === undefined || hold.expiresAt > now` on a stored hold.
fn hold_live(hold: &Record, now: f64) -> bool {
    match hold.get("expiresAt") {
        None => true,
        Some(Value::Number(expires_at)) => better_iam_core::js::number_value(expires_at) > now,
        // `null > now` compares 0 with the clock.
        Some(Value::Null) => 0.0 > now,
        Some(_) => false,
    }
}

async fn holds_of(tx: &Store, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find("privacyHolds", &filter, &FindOptions::default())
        .await
}

/// The live legal hold on a subject, if any.
pub async fn active_hold(
    tx: &Store,
    tenant_id: &str,
    subject: &str,
    now: f64,
) -> IamResult<Option<crate::privacy::PrivacyHold>> {
    let holds = holds_of(
        tx,
        Filter::new()
            .eq("tenantId", tenant_id)
            .eq("subject", subject),
    )
    .await?;
    match holds.into_iter().find(|hold| hold_live(hold, now)) {
        Some(hold) => Ok(Some(crate::port::decode(hold)?)),
        None => Ok(None),
    }
}

/// Refuses to delete a person under a legal hold (`LEGAL_HOLD`, 409). Called from identity deletion, so every path
/// that deletes (an administrator, an erasure request, a workflow, agent removal) is refused; offboarding and SCIM
/// deprovisioning only disable the account, so its data stays anyway.
pub async fn assert_no_legal_hold(
    tx: &Store,
    identity: &better_iam_core::Identity,
    now: f64,
) -> IamResult<()> {
    if identity.kind != IdentityKind::User {
        return Ok(());
    }
    let hold = active_hold(
        tx,
        &identity.tenant_id,
        &identity_subject(&identity.id)?,
        now,
    )
    .await?;
    if hold.is_some() {
        return Err(IamError::with_status(
            "LEGAL_HOLD",
            "This person is under a legal hold; release the hold before deleting them",
            409,
        ));
    }
    Ok(())
}

/// Refuses to delete an organization (or the one above it) while a legal hold on anyone in it, or in a tenant below
/// it, is active (`LEGAL_HOLD`, 409): deleting the tenant would purge the held people with it.
pub async fn assert_no_tenant_legal_hold(
    tx: &Store,
    tenant_id: &str,
    now: f64,
    max_depth: f64,
) -> IamResult<()> {
    let realms = tx
        .find("tenants", &Filter::new(), &FindOptions::default())
        .await?;
    let mut subtree: IndexSet<String> = IndexSet::new();
    subtree.insert(tenant_id.to_owned());
    let mut depth = 0.0;
    while depth < max_depth {
        for realm in &realms {
            if let (Some(Value::String(parent_id)), Some(Value::String(id))) =
                (realm.get("parentId"), realm.get("id"))
                && !parent_id.is_empty()
                && subtree.contains(parent_id)
            {
                subtree.insert(id.clone());
            }
        }
        depth += 1.0;
    }
    for id in &subtree {
        let holds = holds_of(tx, Filter::new().eq("tenantId", id.as_str())).await?;
        if holds.iter().any(|hold| hold_live(hold, now)) {
            return Err(IamError::with_status(
                "LEGAL_HOLD",
                "People in this organization are under a legal hold; release the holds before deleting it",
                409,
            ));
        }
    }
    Ok(())
}

/// Removes a deleted person's current consent decisions and restriction. The consent history stays as proof of what
/// was recorded (erasure redacts it separately), and data-subject requests stay as the record of their handling.
pub async fn release_privacy_records(
    tx: &Store,
    identity: &better_iam_core::Identity,
) -> IamResult<()> {
    let subject = identity_subject(&identity.id)?;
    for collection in ["privacyConsents", "privacyRestrictions"] {
        for record in tx
            .find(
                collection,
                &Filter::new()
                    .eq("tenantId", identity.tenant_id.as_str())
                    .eq("subject", subject.as_str()),
                &FindOptions::default(),
            )
            .await?
        {
            if let Some(Value::String(id)) = record.get("id") {
                tx.delete(collection, id).await?;
            }
        }
    }
    Ok(())
}

/// `/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/`: control characters other than tab, line feed and carriage
/// return.
fn has_prose_control(value: &str) -> bool {
    value.chars().any(|c| {
        let code = c as u32;
        code <= 0x08
            || code == 0x0b
            || code == 0x0c
            || (0x0e..=0x1f).contains(&code)
            || code == 0x7f
    })
}

/// Free text up to `max` characters over several lines (tabs and line breaks allowed, other controls not).
pub fn prose(value: Option<&Value>, name: &str, max: f64) -> IamResult<String> {
    match value {
        Some(Value::String(value))
            if !better_iam_core::js::trim(value).is_empty()
                && (utf16_len(value) as f64) <= max
                && !has_prose_control(value) =>
        {
            Ok(value.clone())
        }
        _ => Err(invalid_input(format!("Invalid {name}"))),
    }
}

/// A purpose key: 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter.
pub fn purpose_key(value: Option<&Value>) -> IamResult<String> {
    let key = text(value, "purposeKey", 64)?;
    // `/^[a-z][a-z0-9._-]{0,63}$/`
    let mut chars = key.chars();
    let shaped = chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && key.len() <= 64
        && chars
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '-'));
    if !shaped {
        return Err(invalid_input(
            "Purpose keys use lowercase letters, digits, dots, underscores or hyphens",
        ));
    }
    Ok(key)
}

/// `oneOf(value, allowed, name)`: one of the allowed strings.
pub fn one_of(value: Option<&Value>, allowed: &[Value], name: &str) -> IamResult<Value> {
    match value {
        Some(Value::String(text)) if allowed.iter().any(|item| item == text.as_str()) => {
            Ok(Value::String(text.clone()))
        }
        _ => Err(invalid_input(format!(
            "{name} must be one of {}",
            allowed
                .iter()
                .map(|item| crate::js::js_string(Some(item)))
                .collect::<Vec<_>>()
                .join(", ")
        ))),
    }
}

/// [`one_of`] over a list of string constants ([`LEGAL_BASES`], [`SUBJECT_REQUEST_TYPES`], ...).
pub fn one_of_str(value: Option<&Value>, allowed: &[&str], name: &str) -> IamResult<String> {
    match value {
        Some(Value::String(text)) if allowed.contains(&text.as_str()) => Ok(text.clone()),
        _ => Err(invalid_input(format!(
            "{name} must be one of {}",
            allowed.join(", ")
        ))),
    }
}

pub fn days(value: Option<&Value>, name: &str, max: Option<f64>) -> IamResult<f64> {
    integer(value, name, 1.0, max.unwrap_or(3650.0))
}
