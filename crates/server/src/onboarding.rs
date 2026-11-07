//! Port of `packages/server/src/onboarding.ts`.
//!
//! Customizable onboarding. A flow is an ordered checklist a newcomer completes: people joining a tenant (`member`
//! flows) or a new tenant's administrators setting it up (`tenant` flows). Flows are defined at any level of the
//! tenant hierarchy (the platform root, an organization, a project) and inherited downward, so the platform sets
//! defaults for every organization, an organization adds its own steps and switches off the platform's optional
//! flows, and a project does the same again. This module holds the records, the validators, the resolution of which
//! flows apply to whom, and the evaluation of step state; the `onboarding` API group builds on it.
//!
//! Flows, progress and settings are handled as the JSON records the store keeps (a mixed fleet shares them with
//! TypeScript), built in the TypeScript member order; the structs below document their shapes.

use std::collections::HashMap;
use std::sync::Mutex;

use better_iam_core::{
    AttributeType, Filter, FindOptions, IamError, IamResult, Identity, IdentityKind,
    IdentityStatus, Record, Tenant, TenantStatus, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::agreements::{Agreement, AgreementAcceptance, acceptance_current};
use crate::context::Store;
use crate::js::{is_object, number, truthy, utf16_len};
use crate::package_rules::{
    RuleEnvironment, parse_auto_assign, rule_context, rule_document, rule_match,
};
use crate::port::decode;
use crate::validation::{email as email_address, integer, text};

/// A candidate flow: the stored flow record, the tenant that defines it, and how it reaches the target.
#[derive(Debug, Clone, PartialEq)]
pub struct CandidateFlow {
    /// The `onboardingFlows` record as stored.
    pub flow: Record,
    pub source: Tenant,
    pub inherited: bool,
    /// Depth of the defining tenant above the target (0 = the target itself).
    pub depth: usize,
    /// The tenant (the target or one between it and the source) that switched this inherited flow off.
    pub disabled_by: Option<Tenant>,
}

/// `'member' | 'tenant'`.
pub type OnboardingAudience = String;

/// One field of a form step (`OnboardingField`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingField {
    /// Answer key: a letter, then letters, digits or underscores (at most 40).
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "label")]
    pub label: String,
    #[serde(rename = "type")]
    pub r#type: String,
    /// A required boolean must be checked (a confirmation).
    #[serde(rename = "required", default, skip_serializing_if = "Option::is_none")]
    pub required: Option<bool>,
    #[serde(rename = "help", default, skip_serializing_if = "Option::is_none")]
    pub help: Option<String>,
    #[serde(
        rename = "placeholder",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub placeholder: Option<String>,
    /// `select` choices (1-50).
    #[serde(rename = "options", default, skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,
    /// Text length cap (text/textarea).
    #[serde(rename = "maxLength", default, skip_serializing_if = "Option::is_none")]
    pub max_length: Option<f64>,
    /// Number bounds.
    #[serde(rename = "min", default, skip_serializing_if = "Option::is_none")]
    pub min: Option<f64>,
    #[serde(rename = "max", default, skip_serializing_if = "Option::is_none")]
    pub max: Option<f64>,
    /// Member flows: the declared identity attribute this answer fills (only when empty).
    #[serde(rename = "attribute", default, skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingFlow {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "audience")]
    pub audience: crate::onboarding::OnboardingAudience,
    #[serde(rename = "appliesTo")]
    pub applies_to: crate::onboarding::OnboardingScope,
    /// Descendant tenants of these types only (all types when absent).
    #[serde(
        rename = "tenantTypes",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub tenant_types: Option<Vec<String>>,
    /// Member flows: only people this rule matches.
    #[serde(rename = "rule", default, skip_serializing_if = "Option::is_none")]
    pub rule: Option<crate::onboarding::OnboardingRule>,
    /// Required flows count toward `principal.pendingOnboarding` until complete.
    #[serde(rename = "required")]
    pub required: bool,
    /// Inherited flows a descendant tenant may not switch off. Tenant flows are always binding.
    #[serde(rename = "locked")]
    pub locked: bool,
    /// Also applies to people and tenants that existed before the flow took effect.
    #[serde(rename = "includeExisting")]
    pub include_existing: bool,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    /// When the flow first took effect; without `includeExisting` only newcomers from then on are asked.
    #[serde(
        rename = "effectiveFrom",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub effective_from: Option<f64>,
    #[serde(rename = "steps")]
    pub steps: Vec<crate::onboarding::OnboardingStep>,
    /// Member flows of the defining tenant: groups a person joins when they complete the flow.
    #[serde(
        rename = "completionGroupIds",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completion_group_ids: Option<Vec<String>>,
    /// Whose authority the completion groups stand on: the last editor checked for every group (any change to who
    /// completes the flow, or when, checks again). Groups this person can no longer add people to are skipped.
    #[serde(
        rename = "groupsOwnerId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub groups_owner_id: Option<String>,
    /// Bumped whenever the steps change.
    #[serde(rename = "version")]
    pub version: f64,
    /// Who last saved the flow (left out where descendants see an inherited flow).
    #[serde(rename = "authorId", default, skip_serializing_if = "Option::is_none")]
    pub author_id: Option<String>,
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingFlowStatus {
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "audience")]
    pub audience: crate::onboarding::OnboardingAudience,
    #[serde(rename = "required")]
    pub required: bool,
    #[serde(rename = "locked")]
    pub locked: bool,
    #[serde(rename = "version")]
    pub version: f64,
    #[serde(rename = "source")]
    pub source: crate::onboarding::OnboardingSource,
    #[serde(rename = "inherited")]
    pub inherited: bool,
    #[serde(rename = "steps")]
    pub steps: Vec<Value>,
    #[serde(rename = "complete")]
    pub complete: bool,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<f64>,
    #[serde(rename = "done")]
    pub done: f64,
    #[serde(rename = "total")]
    pub total: f64,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// One subject's progress through one flow; the ID is `{flowId}:{subjectId}` and the tenant is the subject's own
/// (the person's tenant, or the tenant being set up).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingProgress {
    #[serde(rename = "flowId")]
    pub flow_id: String,
    #[serde(rename = "flowTenantId")]
    pub flow_tenant_id: String,
    #[serde(rename = "subjectType")]
    pub subject_type: String,
    #[serde(rename = "subjectId")]
    pub subject_id: String,
    #[serde(rename = "steps")]
    pub steps: Vec<crate::onboarding::OnboardingStepRecord>,
    #[serde(rename = "startedAt")]
    pub started_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    /// When the flow was last seen complete, and in which version.
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<f64>,
    #[serde(
        rename = "completedVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_version: Option<f64>,
    /// Member flows: the version whose completion groups were applied.
    #[serde(
        rename = "groupsAppliedVersion",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub groups_applied_version: Option<f64>,
    /// Why applying completion groups failed (a separation-of-duties rule, for example); retried later.
    #[serde(
        rename = "completionError",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completion_error: Option<String>,
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

/// A targeting rule in the access-package rule language: include clauses (any matches) and exclude clauses.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingRule {
    #[serde(rename = "include")]
    pub include: Vec<Value>,
    #[serde(rename = "exclude", default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<Value>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Which members or tenants a flow reaches: its own tenant, the tenants below it, or both
/// (`'tenant' | 'descendants' | 'subtree'`).
pub type OnboardingScope = String;

/// A tenant's onboarding customization: welcome copy, support contacts, and inherited flows switched off here.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingSettings {
    #[serde(
        rename = "welcomeTitle",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub welcome_title: Option<String>,
    #[serde(
        rename = "welcomeMessage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub welcome_message: Option<String>,
    #[serde(
        rename = "supportEmail",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub support_email: Option<String>,
    #[serde(
        rename = "supportUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub support_url: Option<String>,
    /// Inherited, unlocked member flows switched off for this tenant and every tenant below it.
    #[serde(rename = "disabledFlowIds")]
    pub disabled_flow_ids: Vec<String>,
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
pub struct OnboardingSource {
    #[serde(rename = "tenantId")]
    pub tenant_id: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(rename = "type")]
    pub r#type: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingStep {
    /// Stable within the flow: lowercase letters, digits and dashes (at most 40). Progress is recorded per step ID.
    #[serde(rename = "id")]
    pub id: String,
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "title")]
    pub title: String,
    /// Plain text or Markdown shown with the step.
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    /// Optional steps never hold a flow back.
    #[serde(rename = "optional", default, skip_serializing_if = "Option::is_none")]
    pub optional: Option<bool>,
    #[serde(rename = "fields", default, skip_serializing_if = "Option::is_none")]
    pub fields: Option<Vec<OnboardingField>>,
    /// `acknowledge`: the text the reader confirms.
    #[serde(rename = "content", default, skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    /// `task`: where the work happens.
    #[serde(rename = "url", default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// `task`: `self` (the default) completes when marked done; `admin` waits for an administrator to verify it.
    #[serde(
        rename = "verification",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verification: Option<String>,
    /// `agreement`: the name of a terms-of-use agreement in the member's own tenant.
    #[serde(rename = "agreement", default, skip_serializing_if = "Option::is_none")]
    pub agreement: Option<String>,
    #[serde(rename = "check", default, skip_serializing_if = "Option::is_none")]
    pub check: Option<String>,
    /// `check` members/owners: how many are needed (default 2).
    #[serde(rename = "minimum", default, skip_serializing_if = "Option::is_none")]
    pub minimum: Option<f64>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnboardingStepRecord {
    #[serde(rename = "stepId")]
    pub step_id: String,
    #[serde(
        rename = "completedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_at: Option<f64>,
    #[serde(
        rename = "completedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub completed_by: Option<String>,
    /// Admin-verified tasks: marked done by the subject and waiting for an administrator.
    #[serde(
        rename = "submittedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub submitted_at: Option<f64>,
    #[serde(
        rename = "verifiedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub verified_by: Option<String>,
    /// Sent back by an administrator, with an optional note for the subject.
    #[serde(
        rename = "rejectedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub rejected_at: Option<f64>,
    #[serde(rename = "note", default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
    #[serde(rename = "answers", default, skip_serializing_if = "Option::is_none")]
    pub answers: Option<IndexMap<String, better_iam_core::Json>>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ResolvedOnboardingSettings {
    #[serde(
        rename = "welcomeTitle",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub welcome_title: Option<String>,
    #[serde(
        rename = "welcomeMessage",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub welcome_message: Option<String>,
    #[serde(
        rename = "supportEmail",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub support_email: Option<String>,
    #[serde(
        rename = "supportUrl",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub support_url: Option<String>,
    /// The tenant each value came from (the nearest one that set it).
    #[serde(rename = "sources")]
    pub sources: Value,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// Reads each tenant's settings record at most once.
pub struct SettingsReader {
    tx: Store,
    cache: Mutex<HashMap<String, Option<Record>>>,
}

impl std::fmt::Debug for SettingsReader {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SettingsReader").finish_non_exhaustive()
    }
}

impl SettingsReader {
    /// `new SettingsReader(tx)`.
    pub fn new(tx: &Store) -> Self {
        Self {
            tx: tx.clone(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// `settings.get(tenantId)`: the tenant's `onboardingSettings` record, read once.
    pub async fn get(&self, tenant_id: &str) -> IamResult<Option<Record>> {
        if let Some(found) = self
            .cache
            .lock()
            .expect("settings cache")
            .get(tenant_id)
            .cloned()
        {
            return Ok(found);
        }
        let found = self
            .tx
            .get("onboardingSettings", &settings_id(tenant_id))
            .await?;
        self.cache
            .lock()
            .expect("settings cache")
            .insert(tenant_id.to_owned(), found.clone());
        Ok(found)
    }
}

pub const MAX_FLOWS_PER_TENANT: f64 = 50.0;
pub const MAX_STEPS: usize = 25;
pub const MAX_FIELDS: usize = 20;
pub const MAX_COMPLETION_GROUPS: f64 = 10.0;

const MEMBER_STEP_KINDS: &[&str] = &[
    "form",
    "acknowledge",
    "task",
    "agreement",
    "verify-email",
    "mfa",
    "passkey",
];
const TENANT_STEP_KINDS: &[&str] = &["form", "acknowledge", "task", "check"];

/// What a tenant `check` step watches.
pub const ONBOARDING_CHECKS: &[&str] = &[
    "verified-domain",
    "members",
    "owners",
    "mfa-policy",
    "agreement",
    "slug",
    "sso",
    "directory-sync",
    "member-onboarding",
];
const FIELD_TYPES: &[&str] = &[
    "text", "textarea", "email", "url", "number", "boolean", "select", "date",
];

/// Steps that complete on their own and cannot be marked done.
/// A `Set` in TypeScript.
pub const AUTOMATIC_STEPS: &[&str] = &["agreement", "verify-email", "mfa", "passkey", "check"];

/// The context keys onboarding supplies to policies.
pub const ONBOARDING_CONTEXT_KEYS: &[&str] =
    &["principal.onboarding", "principal.pendingOnboarding"];

// ----- record accessors -----

/// `record[key]` as a string (`undefined` for anything else).
pub(crate) fn str_of<'a>(record: &'a Map<String, Value>, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// `record[key]` as a number.
pub(crate) fn num_of(record: &Map<String, Value>, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

/// JavaScript truthiness of `record[key]`.
pub(crate) fn flag_of(record: &Map<String, Value>, key: &str) -> bool {
    truthy(record.get(key))
}

/// `record[key]` as an array (empty for anything else).
pub(crate) fn array_of<'a>(record: &'a Map<String, Value>, key: &str) -> &'a [Value] {
    record
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}

/// The steps of a flow record, as objects.
pub(crate) fn steps_of(flow: &Map<String, Value>) -> impl Iterator<Item = &Map<String, Value>> {
    array_of(flow, "steps").iter().filter_map(Value::as_object)
}

/// `Number(record[key])` with `NaN` for a missing value (TypeScript arithmetic on an absent number).
fn number_or_nan(record: &Map<String, Value>, key: &str) -> f64 {
    num_of(record, key).unwrap_or(f64::NAN)
}

/// `tenant.status` as TypeScript writes it.
pub(crate) fn tenant_status(status: TenantStatus) -> &'static str {
    match status {
        TenantStatus::Pending => "pending",
        TenantStatus::Active => "active",
        TenantStatus::Suspended => "suspended",
        TenantStatus::Deleted => "deleted",
    }
}

/// `typeof value === 'string' && /^[a-z0-9][a-z0-9-]{0,39}$/.test(value)`.
fn step_id_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 40
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// `/^[a-zA-Z][a-zA-Z0-9_]{0,39}$/`.
fn field_name_shape(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 40
        && bytes[0].is_ascii_alphabetic()
        && bytes
            .iter()
            .all(|c| c.is_ascii_alphanumeric() || *c == b'_')
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

/// Multi-line text: tabs and line breaks allowed, other control characters not.
pub fn long_text(value: Option<&Value>, name: &str, max: f64) -> IamResult<String> {
    match value {
        Some(Value::String(text))
            if !core_js::trim(text).is_empty()
                && (utf16_len(text) as f64) <= max
                && !text.chars().any(
                    |c| matches!(c as u32, 0x00..=0x08 | 0x0b | 0x0c | 0x0e..=0x1f | 0x7f),
                ) =>
        {
            Ok(text.clone())
        }
        _ => Err(invalid(format!("Invalid {name}"))),
    }
}

/// `httpUrl(value, name)`: a trimmed http(s) URL of at most 2048 characters.
pub fn http_url(value: Option<&Value>, name: &str) -> IamResult<String> {
    let url = core_js::trim(&text(value, name, 2048)?).to_owned();
    let parsed =
        url::Url::parse(&url).map_err(|_| invalid(format!("{name} must be an http(s) URL")))?;
    if parsed.scheme() != "https" && parsed.scheme() != "http" {
        return Err(invalid(format!("{name} must be an http(s) URL")));
    }
    Ok(url)
}

fn flag(value: Option<&Value>, name: &str, fallback: bool) -> IamResult<bool> {
    match value {
        None => Ok(fallback),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(invalid(format!("{name} must be a boolean"))),
    }
}

fn only(value: &Map<String, Value>, keys: &[&str], path: &str) -> IamResult<()> {
    for key in core_js::keys(value) {
        if !keys.contains(&key.as_str()) {
            return Err(invalid(format!("{path}: unknown field {key}")));
        }
    }
    Ok(())
}

/// `[...new Set(items)].length !== items.length`.
fn has_duplicates<'a>(items: impl IntoIterator<Item = &'a str>) -> bool {
    let mut seen = IndexSet::new();
    items.into_iter().any(|item| !seen.insert(item))
}

/// The identity attribute type an answer of this field type fills.
pub fn attribute_type_of(r#type: &str) -> AttributeType {
    match r#type {
        "number" => AttributeType::Number,
        "boolean" => AttributeType::Boolean,
        _ => AttributeType::String,
    }
}

fn attribute_type_name(r#type: AttributeType) -> &'static str {
    match r#type {
        AttributeType::String => "string",
        AttributeType::Number => "number",
        AttributeType::Boolean => "boolean",
    }
}

fn parse_field(
    value: &Value,
    path: &str,
    audience: &str,
    identity_attributes: &IndexMap<String, AttributeType>,
) -> IamResult<Map<String, Value>> {
    let value = match value {
        Value::Object(map) if is_object(Some(value)) => map,
        _ => return Err(invalid(format!("{path} must be an object"))),
    };
    only(
        value,
        &[
            "name",
            "label",
            "type",
            "required",
            "help",
            "placeholder",
            "options",
            "maxLength",
            "min",
            "max",
            "attribute",
        ],
        path,
    )?;
    let name = match str_of(value, "name") {
        Some(name) if field_name_shape(name) => name.to_owned(),
        _ => {
            return Err(invalid(format!(
                "{path}.name must start with a letter and use letters, digits or underscores (at most 40)"
            )));
        }
    };
    let r#type = match crate::js::defined(value.get("type")) {
        None => "text".to_owned(),
        Some(Value::String(kind)) if FIELD_TYPES.contains(&kind.as_str()) => kind.clone(),
        Some(_) => {
            return Err(invalid(format!(
                "{path}.type must be one of {}",
                FIELD_TYPES.join(", ")
            )));
        }
    };
    let mut field = Map::new();
    field.insert("name".into(), Value::String(name));
    field.insert(
        "label".into(),
        Value::String(
            core_js::trim(&text(value.get("label"), &format!("{path}.label"), 100)?).to_owned(),
        ),
    );
    field.insert("type".into(), Value::String(r#type.clone()));
    if flag(value.get("required"), &format!("{path}.required"), false)? {
        field.insert("required".into(), Value::Bool(true));
    }
    if value.get("help").is_some() {
        field.insert(
            "help".into(),
            Value::String(
                core_js::trim(&text(value.get("help"), &format!("{path}.help"), 300)?).to_owned(),
            ),
        );
    }
    if value.get("placeholder").is_some() {
        field.insert(
            "placeholder".into(),
            Value::String(text(
                value.get("placeholder"),
                &format!("{path}.placeholder"),
                100,
            )?),
        );
    }
    if r#type == "select" {
        let options = match value.get("options") {
            Some(Value::Array(options)) if !options.is_empty() && options.len() <= 50 => options,
            _ => return Err(invalid(format!("{path}.options must list 1-50 choices"))),
        };
        let mut parsed = Vec::with_capacity(options.len());
        for (index, option) in options.iter().enumerate() {
            parsed.push(
                core_js::trim(&text(
                    Some(option),
                    &format!("{path}.options[{index}]"),
                    100,
                )?)
                .to_owned(),
            );
        }
        if has_duplicates(parsed.iter().map(String::as_str)) {
            return Err(invalid(format!("{path}.options must be distinct")));
        }
        field.insert(
            "options".into(),
            Value::Array(parsed.into_iter().map(Value::String).collect()),
        );
    } else if value.get("options").is_some() {
        return Err(invalid(format!(
            "{path}.options apply to select fields only"
        )));
    }
    if value.get("maxLength").is_some() {
        if r#type != "text" && r#type != "textarea" {
            return Err(invalid(format!(
                "{path}.maxLength applies to text fields only"
            )));
        }
        let max = if r#type == "textarea" {
            10_000.0
        } else {
            2_000.0
        };
        field.insert(
            "maxLength".into(),
            number(integer(
                value.get("maxLength"),
                &format!("{path}.maxLength"),
                1.0,
                max,
            )?),
        );
    }
    for bound in ["min", "max"] {
        if let Some(raw) = value.get(bound) {
            if r#type != "number" {
                return Err(invalid(format!(
                    "{path}.{bound} applies to number fields only"
                )));
            }
            if core_js::as_number(raw).is_none_or(|n| !n.is_finite()) {
                return Err(invalid(format!("{path}.{bound} must be a number")));
            }
            field.insert(bound.into(), raw.clone());
        }
    }
    if let (Some(min), Some(max)) = (num_of(&field, "min"), num_of(&field, "max"))
        && min > max
    {
        return Err(invalid(format!("{path}.min must not exceed max")));
    }
    if value.get("attribute").is_some() {
        if audience != "member" {
            return Err(invalid(format!(
                "{path}.attribute applies to member flows only"
            )));
        }
        // Attribute values are single lines without control characters; a textarea answer is neither.
        if r#type == "textarea" {
            return Err(invalid(format!(
                "{path}.attribute: a textarea answer cannot fill an attribute"
            )));
        }
        let attribute = text(value.get("attribute"), &format!("{path}.attribute"), 64)?;
        let Some(declared) = identity_attributes.get(&attribute).copied() else {
            return Err(invalid(format!(
                "{path}.attribute {attribute} is not a declared identity attribute"
            )));
        };
        if declared != attribute_type_of(&r#type) {
            return Err(invalid(format!(
                "{path}.attribute {attribute} holds a {}; a {} field cannot fill it",
                attribute_type_name(declared),
                r#type
            )));
        }
        field.insert("attribute".into(), Value::String(attribute));
    }
    Ok(field)
}

/// The members each step kind may carry.
fn allowed_members(kind: &str) -> &'static [&'static str] {
    match kind {
        "form" => &["fields"],
        "acknowledge" => &["content"],
        "task" => &["url", "verification"],
        "agreement" => &["agreement"],
        "check" => &["check", "minimum"],
        _ => &[],
    }
}

fn parse_step(
    value: &Value,
    path: &str,
    audience: &str,
    identity_attributes: &IndexMap<String, AttributeType>,
) -> IamResult<Map<String, Value>> {
    let value = match value {
        Value::Object(map) if is_object(Some(value)) => map,
        _ => return Err(invalid(format!("{path} must be an object"))),
    };
    only(
        value,
        &[
            "id",
            "kind",
            "title",
            "description",
            "optional",
            "fields",
            "content",
            "url",
            "verification",
            "agreement",
            "check",
            "minimum",
        ],
        path,
    )?;
    let id = match str_of(value, "id") {
        Some(id) if step_id_shape(id) => id.to_owned(),
        _ => {
            return Err(invalid(format!(
                "{path}.id must use lowercase letters, digits and dashes (at most 40)"
            )));
        }
    };
    let kinds = if audience == "member" {
        MEMBER_STEP_KINDS
    } else {
        TENANT_STEP_KINDS
    };
    let kind = match str_of(value, "kind") {
        Some(kind) if kinds.contains(&kind) => kind.to_owned(),
        _ => {
            return Err(invalid(format!(
                "{path}.kind must be one of {} in a {audience} flow",
                kinds.join(", ")
            )));
        }
    };
    let mut step = Map::new();
    step.insert("id".into(), Value::String(id));
    step.insert("kind".into(), Value::String(kind.clone()));
    step.insert(
        "title".into(),
        Value::String(
            core_js::trim(&text(value.get("title"), &format!("{path}.title"), 120)?).to_owned(),
        ),
    );
    if value.get("description").is_some() {
        step.insert(
            "description".into(),
            Value::String(long_text(
                value.get("description"),
                &format!("{path}.description"),
                2_000.0,
            )?),
        );
    }
    if flag(value.get("optional"), &format!("{path}.optional"), false)? {
        step.insert("optional".into(), Value::Bool(true));
    }
    let allowed = allowed_members(&kind);
    for key in [
        "fields",
        "content",
        "url",
        "verification",
        "agreement",
        "check",
        "minimum",
    ] {
        if value.get(key).is_some() && !allowed.contains(&key) {
            return Err(invalid(format!(
                "{path}.{key} does not apply to {kind} steps"
            )));
        }
    }
    if kind == "form" {
        let fields = match value.get("fields") {
            Some(Value::Array(fields)) if !fields.is_empty() && fields.len() <= MAX_FIELDS => {
                fields
            }
            _ => {
                return Err(invalid(format!(
                    "{path}.fields must list 1-{MAX_FIELDS} fields"
                )));
            }
        };
        let mut parsed = Vec::with_capacity(fields.len());
        for (index, field) in fields.iter().enumerate() {
            parsed.push(parse_field(
                field,
                &format!("{path}.fields[{index}]"),
                audience,
                identity_attributes,
            )?);
        }
        let names: Vec<String> = parsed
            .iter()
            .map(|field| core_js::to_lower(str_of(field, "name").unwrap_or("")))
            .collect();
        if has_duplicates(names.iter().map(String::as_str)) {
            return Err(invalid(format!("{path}.fields must have distinct names")));
        }
        let attributes: Vec<&str> = parsed
            .iter()
            .filter_map(|field| str_of(field, "attribute").filter(|name| !name.is_empty()))
            .collect();
        if has_duplicates(attributes) {
            return Err(invalid(format!(
                "{path}: two fields fill the same attribute"
            )));
        }
        step.insert(
            "fields".into(),
            Value::Array(parsed.into_iter().map(Value::Object).collect()),
        );
    }
    if kind == "acknowledge" {
        step.insert(
            "content".into(),
            Value::String(long_text(
                value.get("content"),
                &format!("{path}.content"),
                20_000.0,
            )?),
        );
    }
    if kind == "task" {
        if value.get("url").is_some() {
            step.insert(
                "url".into(),
                Value::String(http_url(value.get("url"), &format!("{path}.url"))?),
            );
        }
        let verification = match crate::js::defined(value.get("verification")) {
            None => "self",
            Some(Value::String(mode)) if mode == "self" => "self",
            Some(Value::String(mode)) if mode == "admin" => "admin",
            Some(_) => {
                return Err(invalid(format!(
                    "{path}.verification must be self or admin"
                )));
            }
        };
        step.insert(
            "verification".into(),
            Value::String(verification.to_owned()),
        );
    }
    if kind == "agreement" {
        step.insert(
            "agreement".into(),
            Value::String(
                core_js::trim(&text(
                    value.get("agreement"),
                    &format!("{path}.agreement"),
                    100,
                )?)
                .to_owned(),
            ),
        );
    }
    if kind == "check" {
        let check = match str_of(value, "check") {
            Some(check) if ONBOARDING_CHECKS.contains(&check) => check.to_owned(),
            _ => {
                return Err(invalid(format!(
                    "{path}.check must be one of {}",
                    ONBOARDING_CHECKS.join(", ")
                )));
            }
        };
        step.insert("check".into(), Value::String(check.clone()));
        if value.get("minimum").is_some() {
            if check != "members" && check != "owners" {
                return Err(invalid(format!(
                    "{path}.minimum applies to members and owners checks"
                )));
            }
            step.insert(
                "minimum".into(),
                number(integer(
                    value.get("minimum"),
                    &format!("{path}.minimum"),
                    1.0,
                    10_000.0,
                )?),
            );
        }
    }
    Ok(step)
}

/// Validates a flow's steps (1-25, distinct IDs, kinds allowed for the audience).
pub fn parse_steps(
    value: Option<&Value>,
    audience: &str,
    identity_attributes: &IndexMap<String, AttributeType>,
) -> IamResult<Vec<Value>> {
    let items = match value {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_STEPS => items,
        _ => {
            return Err(invalid(format!("steps must list 1-{MAX_STEPS} steps")));
        }
    };
    let mut steps = Vec::with_capacity(items.len());
    for (index, step) in items.iter().enumerate() {
        steps.push(parse_step(
            step,
            &format!("steps[{index}]"),
            audience,
            identity_attributes,
        )?);
    }
    if has_duplicates(steps.iter().map(|step| str_of(step, "id").unwrap_or(""))) {
        return Err(invalid("steps must have distinct IDs"));
    }
    let steps: Vec<Value> = steps.into_iter().map(Value::Object).collect();
    if utf16_len(&core_js::stringify(&Value::Array(steps.clone()))) > 200_000 {
        return Err(invalid("steps are larger than 200 000 characters"));
    }
    Ok(steps)
}

/// Validates a member flow's targeting rule. Group tests (`identity.groups`) name groups of the defining tenant, so
/// they are refused on flows that reach only descendant tenants, whose people are never members of those groups.
pub fn parse_rule(
    value: Option<&Value>,
    identity_attributes: &IndexMap<String, AttributeType>,
    groups: &IndexSet<String>,
) -> IamResult<Map<String, Value>> {
    let object = match value {
        Some(Value::Object(map)) if is_object(value) => map,
        _ => return Err(invalid("rule must be an object")),
    };
    only(object, &["include", "exclude"], "rule")?;
    let parsed = parse_auto_assign(
        value,
        &RuleEnvironment {
            identity_attributes: identity_attributes.clone(),
            groups: Some(groups.clone()),
            packaged_groups: None,
            org: None,
            extra: Map::new(),
        },
        Some("rule"),
    )?;
    let mut rule = Map::new();
    rule.insert("include".into(), Value::Array(parsed.include));
    if let Some(exclude) = parsed.exclude {
        rule.insert("exclude".into(), Value::Array(exclude));
    }
    Ok(rule)
}

/// Whether a flow at `source` reaches `target` under its scope and tenant types.
fn reaches_tenant(flow: &Record, source: &Tenant, target: &Tenant) -> bool {
    let applies_to = str_of(flow, "appliesTo");
    if source.id == target.id {
        return applies_to != Some("descendants");
    }
    if applies_to == Some("tenant") {
        return false;
    }
    match flow.get("tenantTypes") {
        None | Some(Value::Null) => true,
        Some(Value::Array(types)) => types
            .iter()
            .any(|kind| kind.as_str() == Some(target.kind.as_str())),
        Some(_) => false,
    }
}

/// `bySourceThenCreated`: platform first, then oldest, then by ID.
fn by_source_then_created(a: &CandidateFlow, b: &CandidateFlow) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let ordering = |difference: f64| {
        if difference < 0.0 {
            Ordering::Less
        } else if difference > 0.0 {
            Ordering::Greater
        } else {
            Ordering::Equal
        }
    };
    ordering(b.depth as f64 - a.depth as f64)
        .then_with(|| {
            ordering(number_or_nan(&a.flow, "createdAt") - number_or_nan(&b.flow, "createdAt"))
        })
        .then_with(|| {
            core_js::cmp_utf16(
                str_of(&a.flow, "id").unwrap_or(""),
                str_of(&b.flow, "id").unwrap_or(""),
            )
        })
}

pub fn settings_id(tenant_id: &str) -> String {
    format!("settings:{tenant_id}")
}

pub fn progress_id(flow_id: &str, subject_id: &str) -> String {
    format!("{flow_id}:{subject_id}")
}

/// `settings.disabledFlowIds.includes(flowId)` for a stored settings record.
fn disables(settings: &Record, flow_id: &str) -> bool {
    array_of(settings, "disabledFlowIds")
        .iter()
        .any(|id| id.as_str() == Some(flow_id))
}

/// The flows of one audience that reach a tenant, before anything about a particular person is known: the tenant's
/// own flows for its members, and its ancestors' flows that reach down to it. `chain` is the tenant's ancestry
/// (`ctx.ancestry`: the tenant first, the root last). Disabled flows are included with `disabledBy` so
/// administrators can see them; locked flows ignore the switch.
pub async fn candidate_flows(
    tx: &Store,
    chain: &[Tenant],
    audience: &str,
    settings: Option<&SettingsReader>,
) -> IamResult<Vec<CandidateFlow>> {
    let own_reader;
    let settings = match settings {
        Some(settings) => settings,
        None => {
            own_reader = SettingsReader::new(tx);
            &own_reader
        }
    };
    let Some(target) = chain.first() else {
        return Err(crate::js::internal_error());
    };
    let mut found: Vec<CandidateFlow> = Vec::new();
    for (depth, source) in chain.iter().enumerate() {
        // A tenant is never onboarded by its own tenant flows; they describe how its descendants set up.
        if audience == "tenant" && depth == 0 {
            continue;
        }
        for flow in tx
            .find(
                "onboardingFlows",
                &Filter::new().eq("tenantId", source.id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            if str_of(&flow, "audience") != Some(audience)
                || !flag_of(&flow, "enabled")
                || !reaches_tenant(&flow, source, target)
            {
                continue;
            }
            let mut disabled_by = None;
            if audience == "member" && depth > 0 && !flag_of(&flow, "locked") {
                let flow_id = str_of(&flow, "id").unwrap_or("");
                for between in &chain[..depth] {
                    if settings
                        .get(&between.id)
                        .await?
                        .is_some_and(|record| disables(&record, flow_id))
                    {
                        disabled_by = Some(between.clone());
                        break;
                    }
                }
            }
            found.push(CandidateFlow {
                flow,
                source: source.clone(),
                inherited: depth > 0,
                depth,
                disabled_by,
            });
        }
    }
    found.sort_by(by_source_then_created);
    Ok(found)
}

/// The group IDs an identity is a live member of in its tenant (targeting rules test these).
pub async fn live_group_ids(tx: &Store, identity: &Identity, now: f64) -> IamResult<Vec<String>> {
    Ok(tx
        .find(
            "groupMembers",
            &Filter::new()
                .eq("tenantId", identity.tenant_id.clone())
                .eq("identityId", identity.id.clone()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .filter(|member| match member.get("expiresAt") {
            None => true,
            Some(expires) => core_js::as_number(expires).is_some_and(|expires| expires > now),
        })
        .map(|member| str_of(&member, "groupId").unwrap_or("").to_owned())
        .collect())
}

/// Whether a member flow applies to this person: people only, newcomers unless `includeExisting`, and the rule.
pub fn flow_applies_to(
    flow: &Record,
    identity: &Identity,
    group_ids: Option<&[String]>,
) -> IamResult<bool> {
    if identity.kind != IdentityKind::User || identity.status == IdentityStatus::Deleted {
        return Ok(false);
    }
    if !flag_of(flow, "includeExisting") {
        let effective = match flow.get("effectiveFrom") {
            Some(value) if !value.is_null() => core_js::as_number(value).unwrap_or(f64::NAN),
            _ => number_or_nan(flow, "createdAt"),
        };
        if identity.created_at < effective {
            return Ok(false);
        }
    }
    let Some(rule) = flow.get("rule").filter(|rule| truthy(Some(rule))) else {
        return Ok(true);
    };
    let group_ids = Value::Array(
        group_ids
            .unwrap_or(&[])
            .iter()
            .cloned()
            .map(Value::String)
            .collect(),
    );
    Ok(rule_match(
        &rule_document(rule)?,
        identity,
        &rule_context(identity, &group_ids, None)?,
    )?
    .matched)
}

/// Whether a tenant flow applies to this tenant: newcomers unless `includeExisting`.
pub fn tenant_flow_applies(flow: &Record, tenant: &Tenant) -> bool {
    if tenant.status == TenantStatus::Deleted {
        return false;
    }
    if flag_of(flow, "includeExisting") {
        return true;
    }
    let effective = match flow.get("effectiveFrom") {
        Some(value) if !value.is_null() => core_js::as_number(value).unwrap_or(f64::NAN),
        _ => number_or_nan(flow, "createdAt"),
    };
    tenant.created_at >= effective
}

/// The member flows a person is asked to complete (switched-off flows removed), in platform-first order.
pub async fn flows_for_identity(
    tx: &Store,
    chain: &[Tenant],
    identity: &Identity,
    now: f64,
    candidates: Option<Vec<CandidateFlow>>,
) -> IamResult<Vec<CandidateFlow>> {
    if identity.kind != IdentityKind::User {
        return Ok(Vec::new());
    }
    let candidates = match candidates {
        Some(candidates) => candidates,
        None => candidate_flows(tx, chain, "member", None).await?,
    };
    let flows: Vec<CandidateFlow> = candidates
        .into_iter()
        .filter(|candidate| candidate.disabled_by.is_none())
        .collect();
    if flows.is_empty() {
        return Ok(Vec::new());
    }
    let group_ids = if flows
        .iter()
        .any(|candidate| flag_of(&candidate.flow, "rule"))
    {
        Some(live_group_ids(tx, identity, now).await?)
    } else {
        None
    };
    let mut applying = Vec::new();
    for candidate in flows {
        if flow_applies_to(&candidate.flow, identity, group_ids.as_deref())? {
            applying.push(candidate);
        }
    }
    Ok(applying)
}

/// An agreement a member flow names, and whether the person accepted its current version.
#[derive(Debug, Clone, PartialEq)]
pub struct AgreementFact {
    pub agreement: Agreement,
    pub accepted: bool,
}

/// Facts a member flow's self-completing steps read, loaded only when a step needs them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct MemberFacts {
    pub mfa: Option<bool>,
    pub passkeys: Option<f64>,
    /// By lowercased agreement name.
    pub agreements: Option<IndexMap<String, AgreementFact>>,
}

pub async fn member_facts(
    tx: &Store,
    identity: &Identity,
    flows: &[&Record],
    now: f64,
) -> IamResult<MemberFacts> {
    let kinds: IndexSet<&str> = flows
        .iter()
        .flat_map(|flow| steps_of(flow).filter_map(|step| str_of(step, "kind")))
        .collect();
    let mut facts = MemberFacts::default();
    if kinds.contains("mfa") || kinds.contains("passkey") {
        let passkeys = tx
            .find(
                "authPasskeys",
                &Filter::new()
                    .eq("tenantId", identity.tenant_id.clone())
                    .eq("identityId", identity.id.clone()),
                &FindOptions::default(),
            )
            .await?
            .len() as f64;
        facts.passkeys = Some(passkeys);
        facts.mfa = Some(
            passkeys > 0.0
                || tx
                    .get("authMfa", &identity.id)
                    .await?
                    .is_some_and(|record| flag_of(&record, "enabled")),
        );
    }
    if kinds.contains("agreement") {
        let mut acceptances: HashMap<String, AgreementAcceptance> = HashMap::new();
        for record in tx
            .find(
                "agreementAcceptances",
                &Filter::new()
                    .eq("tenantId", identity.tenant_id.clone())
                    .eq("identityId", identity.id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            let acceptance: AgreementAcceptance = decode(record)?;
            acceptances.insert(acceptance.agreement_id.clone(), acceptance);
        }
        let mut agreements = IndexMap::new();
        for record in tx
            .find(
                "agreements",
                &Filter::new().eq("tenantId", identity.tenant_id.clone()),
                &FindOptions::default(),
            )
            .await?
        {
            let agreement: Agreement = decode(record)?;
            let accepted = acceptance_current(&agreement, acceptances.get(&agreement.id), now);
            agreements.insert(
                core_js::to_lower(&agreement.name),
                AgreementFact {
                    agreement,
                    accepted,
                },
            );
        }
        facts.agreements = Some(agreements);
    }
    Ok(facts)
}

/// A fact a tenant `check` step reads: a count, or a yes/no.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CheckFact {
    Count(f64),
    Flag(bool),
}

/// Facts a tenant flow's check steps read, loaded only when a step needs them (by check name).
pub type TenantFacts = IndexMap<String, CheckFact>;

pub async fn tenant_facts(
    tx: &Store,
    tenant: &Tenant,
    flows: &[&Record],
) -> IamResult<TenantFacts> {
    let checks: IndexSet<String> = flows
        .iter()
        .flat_map(|flow| {
            steps_of(flow).filter_map(|step| {
                step.get("check")
                    .filter(|check| truthy(Some(check)))
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
        })
        .collect();
    let mut facts = TenantFacts::new();
    let find = |collection: &'static str| {
        let tenant_id = tenant.id.clone();
        async move {
            tx.find(
                collection,
                &Filter::new().eq("tenantId", tenant_id),
                &FindOptions::default(),
            )
            .await
        }
    };
    let people = || async {
        let mut people = Vec::new();
        for record in find("identities").await? {
            let identity: Identity = decode(record)?;
            if identity.kind == IdentityKind::User && identity.status == IdentityStatus::Active {
                people.push(identity);
            }
        }
        Ok::<_, IamError>(people)
    };
    for check in checks {
        let fact = match check.as_str() {
            "verified-domain" => CheckFact::Count(
                find("tenantDomains")
                    .await?
                    .iter()
                    .filter(|domain| str_of(domain, "status") == Some("verified"))
                    .count() as f64,
            ),
            "members" => CheckFact::Count(people().await?.len() as f64),
            "owners" => CheckFact::Count(
                people()
                    .await?
                    .iter()
                    .filter(|identity| identity.owner)
                    .count() as f64,
            ),
            "mfa-policy" => CheckFact::Flag(
                tenant
                    .auth_policy
                    .as_ref()
                    .and_then(|policy| policy.require_mfa)
                    == Some(true),
            ),
            "agreement" => CheckFact::Count(find("agreements").await?.len() as f64),
            "slug" => CheckFact::Flag(tenant.slug.is_some()),
            "sso" => CheckFact::Count(
                find("samlConnections")
                    .await?
                    .iter()
                    .filter(|connection| connection.get("enabled") != Some(&Value::Bool(false)))
                    .count() as f64,
            ),
            "directory-sync" => CheckFact::Count(
                find("scimConnections")
                    .await?
                    .iter()
                    .filter(|connection| !flag_of(connection, "revoked"))
                    .count() as f64,
            ),
            "member-onboarding" => CheckFact::Count(
                find("onboardingFlows")
                    .await?
                    .iter()
                    .filter(|flow| {
                        str_of(flow, "audience") == Some("member")
                            && flag_of(flow, "enabled")
                            && str_of(flow, "appliesTo") != Some("descendants")
                    })
                    .count() as f64,
            ),
            _ => continue,
        };
        facts.insert(check, fact);
    }
    Ok(facts)
}

fn check_label(check: &str) -> &'static str {
    match check {
        "verified-domain" => "verified domain",
        "members" => "member",
        "owners" => "owner",
        "mfa-policy" | "slug" => "",
        "agreement" => "agreement",
        "sso" => "SSO connection",
        "directory-sync" => "directory connection",
        "member-onboarding" => "member onboarding flow",
        _ => "undefined",
    }
}

fn check_state(step: &Map<String, Value>, facts: &TenantFacts) -> (bool, String) {
    let check = str_of(step, "check").unwrap_or("");
    let value = facts.get(check).copied();
    if let Some(CheckFact::Flag(value)) = value {
        let detail = if check == "mfa-policy" {
            if value {
                "MFA is required"
            } else {
                "MFA is not required yet"
            }
        } else if value {
            "Sign-in alias set"
        } else {
            "No sign-in alias yet"
        };
        return (value, detail.to_owned());
    }
    let count = match value {
        Some(CheckFact::Count(count)) => count,
        _ => 0.0,
    };
    let needed = if check == "members" || check == "owners" {
        match step.get("minimum") {
            None | Some(Value::Null) => 2.0,
            Some(minimum) => core_js::as_number(minimum).unwrap_or(f64::NAN),
        }
    } else {
        1.0
    };
    let label = check_label(check);
    (
        count >= needed,
        format!(
            "{} of {} {label}{}",
            core_js::number_to_string(count.min(needed)),
            core_js::number_to_string(needed),
            if needed == 1.0 { "" } else { "s" }
        ),
    )
}

/// What `evaluateFlow` knows about the subject: a person with their member facts, or a tenant's check facts.
#[derive(Debug, Clone, Copy, Default)]
pub struct FlowFacts<'a> {
    pub member: Option<(&'a Identity, &'a MemberFacts)>,
    pub tenant: Option<&'a TenantFacts>,
}

/// The state of each step and of the whole flow for one subject (an `OnboardingFlowStatus` object).
pub fn evaluate_flow(
    candidate: &CandidateFlow,
    progress: Option<&Record>,
    facts: FlowFacts<'_>,
    answers: bool,
) -> Map<String, Value> {
    let flow = &candidate.flow;
    let mut records: HashMap<String, &Map<String, Value>> = HashMap::new();
    if let Some(progress) = progress {
        for record in array_of(progress, "steps")
            .iter()
            .filter_map(Value::as_object)
        {
            records.insert(str_of(record, "stepId").unwrap_or("").to_owned(), record);
        }
    }
    let empty_facts = TenantFacts::new();
    let mut steps: Vec<Map<String, Value>> = Vec::new();
    for step in steps_of(flow) {
        let record = str_of(step, "id").and_then(|id| records.get(id).copied());
        let mut status = step.clone();
        status.insert(
            "optional".into(),
            Value::Bool(step.get("optional") == Some(&Value::Bool(true))),
        );
        status.insert("state".into(), Value::String("pending".into()));
        let member = |key: &str| record.and_then(|record| record.get(key));
        if let Some(completed_at) = member("completedAt") {
            status.insert("completedAt".into(), completed_at.clone());
        }
        if answers && let Some(recorded) = member("answers").filter(|value| truthy(Some(value))) {
            status.insert("answers".into(), recorded.clone());
        }
        let mut state = "pending";
        match str_of(step, "kind").unwrap_or("") {
            "form" | "acknowledge" => {
                if member("completedAt").is_some() {
                    state = "complete";
                }
            }
            "task" => {
                if member("completedAt").is_some() {
                    state = "complete";
                } else if let Some(submitted_at) = member("submittedAt") {
                    state = "submitted";
                    status.insert("submittedAt".into(), submitted_at.clone());
                } else if let Some(rejected_at) = member("rejectedAt") {
                    state = "rejected";
                    status.insert("rejectedAt".into(), rejected_at.clone());
                    if let Some(note) = member("note").filter(|note| truthy(Some(note))) {
                        status.insert("note".into(), note.clone());
                    }
                }
            }
            "verify-email" => {
                if facts
                    .member
                    .is_some_and(|(identity, _)| identity.email_verified)
                {
                    state = "complete";
                }
            }
            "mfa" => {
                if facts
                    .member
                    .is_some_and(|(_, facts)| facts.mfa == Some(true))
                {
                    state = "complete";
                }
            }
            "passkey" => {
                if facts
                    .member
                    .and_then(|(_, facts)| facts.passkeys)
                    .unwrap_or(0.0)
                    > 0.0
                {
                    state = "complete";
                }
            }
            "agreement" => {
                let name = core_js::to_lower(str_of(step, "agreement").unwrap_or(""));
                let found = facts
                    .member
                    .and_then(|(_, facts)| facts.agreements.as_ref())
                    .and_then(|agreements| agreements.get(&name));
                state = match found {
                    None => "unavailable",
                    Some(found) if found.accepted => "complete",
                    Some(_) => "pending",
                };
                if found.is_none() {
                    status.insert(
                        "detail".into(),
                        Value::String("Your organization has not published this agreement".into()),
                    );
                }
            }
            "check" => {
                let (done, detail) = check_state(step, facts.tenant.unwrap_or(&empty_facts));
                state = if done { "complete" } else { "pending" };
                status.insert("detail".into(), Value::String(detail));
            }
            _ => {}
        }
        status.insert("state".into(), Value::String(state.into()));
        steps.push(status);
    }
    let counted: Vec<&Map<String, Value>> = steps
        .iter()
        .filter(|step| {
            step.get("optional") != Some(&Value::Bool(true))
                && str_of(step, "state") != Some("unavailable")
        })
        .collect();
    let done = counted
        .iter()
        .filter(|step| str_of(step, "state") == Some("complete"))
        .count();
    let total = counted.len();
    let complete = done == total;
    let mut result = Map::new();
    let member = |key: &str| flow.get(key).cloned().unwrap_or(Value::Null);
    result.insert("id".into(), member("id"));
    result.insert("name".into(), member("name"));
    if let Some(description) = flow.get("description").filter(|value| truthy(Some(value))) {
        result.insert("description".into(), description.clone());
    }
    result.insert("audience".into(), member("audience"));
    result.insert("required".into(), member("required"));
    result.insert("locked".into(), member("locked"));
    result.insert("version".into(), member("version"));
    result.insert("source".into(), source_of(&candidate.source));
    result.insert("inherited".into(), Value::Bool(candidate.inherited));
    result.insert(
        "steps".into(),
        Value::Array(steps.into_iter().map(Value::Object).collect()),
    );
    result.insert("complete".into(), Value::Bool(complete));
    result.insert("done".into(), number(done as f64));
    result.insert("total".into(), number(total as f64));
    if complete
        && let Some(completed_at) = progress.and_then(|progress| progress.get("completedAt"))
    {
        result.insert("completedAt".into(), completed_at.clone());
    }
    result
}

/// `{ tenantId, name, type }` of a tenant (an `OnboardingSource`).
pub fn source_of(tenant: &Tenant) -> Value {
    let mut source = Map::new();
    source.insert("tenantId".into(), Value::String(tenant.id.clone()));
    source.insert("name".into(), Value::String(tenant.name.clone()));
    source.insert("type".into(), Value::String(tenant.kind.clone()));
    Value::Object(source)
}

/// Whether any statement of the documents names an onboarding context key in a condition.
pub fn mentions_onboarding(documents: &[&better_iam_core::PolicyDocument]) -> bool {
    documents.iter().any(|document| {
        document.statements.iter().any(|statement| {
            statement.conditions.as_ref().is_some_and(|conditions| {
                conditions.values().any(|block| {
                    ONBOARDING_CONTEXT_KEYS
                        .iter()
                        .any(|key| block.contains_key(*key))
                })
            })
        })
    })
}

/// Policy context for a person in their own tenant: `principal.onboarding` names the member flows they have
/// completed, and `principal.pendingOnboarding` counts required ones still open. Service accounts are never
/// onboarded.
pub async fn onboarding_context(
    tx: &Store,
    chain: &[Tenant],
    identity: &Identity,
    now: f64,
) -> IamResult<Map<String, Value>> {
    let context = |completed: Vec<String>, pending: usize| {
        let mut context = Map::new();
        context.insert(
            "principal.onboarding".into(),
            Value::Array(completed.into_iter().map(Value::String).collect()),
        );
        context.insert("principal.pendingOnboarding".into(), number(pending as f64));
        context
    };
    if identity.kind != IdentityKind::User
        || chain.first().map(|tenant| tenant.id.as_str()) != Some(identity.tenant_id.as_str())
    {
        return Ok(context(Vec::new(), 0));
    }
    let flows = flows_for_identity(tx, chain, identity, now, None).await?;
    if flows.is_empty() {
        return Ok(context(Vec::new(), 0));
    }
    let mut progress: HashMap<String, Record> = HashMap::new();
    for record in tx
        .find(
            "onboardingProgress",
            &Filter::new()
                .eq("tenantId", identity.tenant_id.clone())
                .eq("subjectId", identity.id.clone()),
            &FindOptions::default(),
        )
        .await?
    {
        progress.insert(str_of(&record, "flowId").unwrap_or("").to_owned(), record);
    }
    let records: Vec<&Record> = flows.iter().map(|candidate| &candidate.flow).collect();
    let facts = member_facts(tx, identity, &records, now).await?;
    let mut completed: Vec<String> = Vec::new();
    let mut pending = 0;
    for candidate in &flows {
        let status = evaluate_flow(
            candidate,
            progress.get(str_of(&candidate.flow, "id").unwrap_or("")),
            FlowFacts {
                member: Some((identity, &facts)),
                tenant: None,
            },
            false,
        );
        if status.get("complete") == Some(&Value::Bool(true)) {
            completed.push(str_of(&candidate.flow, "name").unwrap_or("").to_owned());
        } else if flag_of(&candidate.flow, "required") {
            pending += 1;
        }
    }
    let mut completed = crate::js::unique(completed);
    completed.sort_by(|a, b| core_js::cmp_utf16(a, b));
    Ok(context(completed, pending))
}

const SETTINGS_KEYS: [&str; 4] = [
    "welcomeTitle",
    "welcomeMessage",
    "supportEmail",
    "supportUrl",
];

/// Welcome copy and support contacts: for each value, the nearest tenant in the chain that set it wins (a
/// `ResolvedOnboardingSettings` object).
pub async fn resolve_settings(
    chain: &[Tenant],
    settings: &SettingsReader,
) -> IamResult<Map<String, Value>> {
    let mut resolved = Map::new();
    let mut sources = Map::new();
    resolved.insert("sources".into(), Value::Object(Map::new()));
    for tenant in chain {
        let Some(record) = settings.get(&tenant.id).await? else {
            continue;
        };
        for key in SETTINGS_KEYS {
            if !resolved.contains_key(key)
                && let Some(value) = record.get(key)
            {
                resolved.insert(key.into(), value.clone());
                sources.insert(key.into(), source_of(tenant));
            }
        }
    }
    resolved.insert("sources".into(), Value::Object(sources));
    Ok(resolved)
}

/// Validates settings input (replace semantics); `disabledFlowIds` is checked against the inherited flows by the
/// caller. Returns the `OnboardingSettingsValues` object.
pub fn parse_settings(input: &Map<String, Value>) -> IamResult<Map<String, Value>> {
    only(
        input,
        &[
            "tenantId",
            "welcomeTitle",
            "welcomeMessage",
            "supportEmail",
            "supportUrl",
            "disabledFlowIds",
        ],
        "settings",
    )?;
    let present = |key: &str| match input.get(key) {
        None | Some(Value::Null) => None,
        Some(Value::String(text)) if text.is_empty() => None,
        Some(value) => Some(value),
    };
    let welcome_title = present("welcomeTitle")
        .map(|value| text(Some(value), "welcomeTitle", 120).map(|t| core_js::trim(&t).to_owned()))
        .transpose()?;
    let welcome_message = present("welcomeMessage")
        .map(|value| long_text(Some(value), "welcomeMessage", 5_000.0))
        .transpose()?;
    let support_email = present("supportEmail")
        .map(|value| email_address(Some(value)))
        .transpose()?;
    let support_url = present("supportUrl")
        .map(|value| http_url(Some(value), "supportUrl"))
        .transpose()?;
    let disabled = match input.get("disabledFlowIds") {
        None | Some(Value::Null) => Vec::new(),
        Some(Value::Array(items)) if items.len() <= 100 => items.clone(),
        Some(_) => {
            return Err(invalid("disabledFlowIds must list at most 100 flows"));
        }
    };
    let mut disabled_ids = Vec::with_capacity(disabled.len());
    for flow_id in &disabled {
        disabled_ids.push(text(Some(flow_id), "disabledFlowIds", 128)?);
    }
    let mut disabled_ids = crate::js::unique(disabled_ids);
    disabled_ids.sort_by(|a, b| core_js::cmp_utf16(a, b));
    let mut values = Map::new();
    for (key, value) in [
        ("welcomeTitle", welcome_title),
        ("welcomeMessage", welcome_message),
        ("supportEmail", support_email),
        ("supportUrl", support_url),
    ] {
        if let Some(value) = value {
            values.insert(key.into(), Value::String(value));
        }
    }
    values.insert(
        "disabledFlowIds".into(),
        Value::Array(disabled_ids.into_iter().map(Value::String).collect()),
    );
    Ok(values)
}

/// `/^\d{4}-\d{2}-\d{2}$/` and a real calendar date (`new Date(`${raw}T00:00:00Z`)` round-trips).
fn calendar_date(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || !bytes
            .iter()
            .enumerate()
            .all(|(index, c)| index == 4 || index == 7 || c.is_ascii_digit())
    {
        return false;
    }
    let year: i64 = raw[0..4].parse().unwrap_or(-1);
    let month: i64 = raw[5..7].parse().unwrap_or(0);
    let day: i64 = raw[8..10].parse().unwrap_or(0);
    (1..=12).contains(&month) && day >= 1 && day <= core_js::days_in_month(year, month)
}

/// Validates a form step's answers: every required field present, values of the declared type and within bounds.
/// Unknown answer keys are refused. Returns the answers to record (empty optional fields left out).
pub fn parse_answers(
    step: &Map<String, Value>,
    value: Option<&Value>,
) -> IamResult<Map<String, Value>> {
    let empty_answers = Value::Object(Map::new());
    let value = value.unwrap_or(&empty_answers);
    let value = match value {
        Value::Object(map) if is_object(Some(value)) => map,
        _ => return Err(invalid("answers must be an object")),
    };
    let fields: Vec<&Map<String, Value>> = array_of(step, "fields")
        .iter()
        .filter_map(Value::as_object)
        .collect();
    for key in core_js::keys(value) {
        if !fields
            .iter()
            .any(|field| str_of(field, "name") == Some(key.as_str()))
        {
            return Err(invalid(format!("Unknown answer {key}")));
        }
    }
    let mut answers = Map::new();
    for field in fields {
        let name = str_of(field, "name").unwrap_or("");
        let label = crate::js::js_string(field.get("label"));
        let kind = str_of(field, "type").unwrap_or("");
        let raw = value.get(name);
        let empty = match raw {
            None | Some(Value::Null) => true,
            Some(Value::String(text)) => core_js::trim(text).is_empty(),
            Some(Value::Bool(false)) => kind == "boolean",
            _ => false,
        };
        if empty {
            if flag_of(field, "required") {
                return Err(invalid(if kind == "boolean" {
                    format!("{label} must be confirmed")
                } else {
                    format!("{label} is required")
                }));
            }
            if kind == "boolean" && raw == Some(&Value::Bool(false)) {
                answers.insert(name.into(), Value::Bool(false));
            }
            continue;
        }
        let raw = raw.expect("present");
        let not_valid = || invalid(format!("{label} is not valid"));
        let max_length = |fallback: f64| match field.get("maxLength") {
            None | Some(Value::Null) => fallback,
            Some(max) => core_js::as_number(max).unwrap_or(f64::NAN),
        };
        match kind {
            "text" => {
                let Value::String(text) = raw else {
                    return Err(not_valid());
                };
                let trimmed = core_js::trim(text);
                if utf16_len(trimmed) as f64 > max_length(200.0)
                    || trimmed
                        .chars()
                        .any(|c| (c as u32) < 0x20 || c as u32 == 0x7f)
                {
                    return Err(not_valid());
                }
                answers.insert(name.into(), Value::String(trimmed.to_owned()));
            }
            "textarea" => {
                let Value::String(text) = raw else {
                    return Err(not_valid());
                };
                let max = max_length(2_000.0);
                if utf16_len(text) as f64 > max {
                    return Err(not_valid());
                }
                answers.insert(
                    name.into(),
                    Value::String(long_text(Some(raw), &label, max)?),
                );
            }
            "email" => {
                let address = email_address(Some(raw)).map_err(|_| not_valid())?;
                answers.insert(name.into(), Value::String(address));
            }
            "url" => {
                let url = http_url(Some(raw), &label).map_err(|_| not_valid())?;
                answers.insert(name.into(), Value::String(url));
            }
            "number" => {
                let Some(number) = raw.as_number().map(core_js::number_value) else {
                    return Err(not_valid());
                };
                let below = num_of(field, "min").is_some_and(|min| number < min);
                let above = num_of(field, "max").is_some_and(|max| number > max);
                if !number.is_finite() || below || above {
                    return Err(not_valid());
                }
                answers.insert(name.into(), raw.clone());
            }
            "boolean" => {
                if !raw.is_boolean() {
                    return Err(not_valid());
                }
                answers.insert(name.into(), raw.clone());
            }
            "select" => {
                let allowed = match raw {
                    Value::String(choice) => array_of(field, "options")
                        .iter()
                        .any(|option| option.as_str() == Some(choice.as_str())),
                    _ => false,
                };
                if !allowed {
                    return Err(not_valid());
                }
                answers.insert(name.into(), raw.clone());
            }
            "date" => {
                let valid = matches!(raw, Value::String(date) if calendar_date(date));
                if !valid {
                    return Err(not_valid());
                }
                answers.insert(name.into(), raw.clone());
            }
            _ => {}
        }
    }
    Ok(answers)
}

/// A flow record without the fields only the defining tenant needs; what descendants and members see.
pub fn public_flow(flow: &Record) -> Record {
    let mut rest = flow.clone();
    rest.shift_remove("completionGroupIds");
    rest.shift_remove("groupsOwnerId");
    rest.shift_remove("authorId");
    rest
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn calendar_dates() {
        assert!(calendar_date("2024-02-29"));
        assert!(!calendar_date("2023-02-29"));
        assert!(!calendar_date("2023-13-01"));
        assert!(!calendar_date("2023-00-10"));
        assert!(!calendar_date("2023-1-10"));
        assert!(calendar_date("0000-01-01"));
    }

    #[test]
    fn long_text_rules() {
        assert_eq!(
            long_text(Some(&json!("a\n\tb")), "content", 10.0).unwrap(),
            "a\n\tb"
        );
        assert_eq!(
            long_text(Some(&json!("a\u{0001}")), "content", 10.0)
                .unwrap_err()
                .message,
            "Invalid content"
        );
        assert!(long_text(Some(&json!("   ")), "content", 10.0).is_err());
        assert!(long_text(Some(&json!("abcdef")), "content", 5.0).is_err());
    }

    #[test]
    fn steps_validate_in_order() {
        let attributes = IndexMap::new();
        let error = parse_steps(
            Some(&json!([{ "id": "a", "kind": "check", "title": "x", "check": "slug" }])),
            "member",
            &attributes,
        )
        .unwrap_err();
        assert_eq!(
            error.message,
            "steps[0].kind must be one of form, acknowledge, task, agreement, verify-email, mfa, passkey in a member flow"
        );
        let steps = parse_steps(
            Some(&json!([{ "id": "t", "kind": "task", "title": " Task " }])),
            "member",
            &attributes,
        )
        .unwrap();
        assert_eq!(
            steps,
            vec![json!({ "id": "t", "kind": "task", "title": "Task", "verification": "self" })]
        );
    }

    #[test]
    fn answers() {
        let step = json!({
            "id": "f",
            "kind": "form",
            "title": "F",
            "fields": [
                { "name": "size", "label": "Size", "type": "select", "options": ["a", "b"], "required": true },
                { "name": "ok", "label": "OK", "type": "boolean" },
                { "name": "phone", "label": "Phone", "type": "text" }
            ]
        });
        let step = step.as_object().unwrap();
        assert_eq!(
            parse_answers(
                step,
                Some(&json!({ "size": "a", "ok": false, "phone": " 1 " }))
            )
            .unwrap(),
            *json!({ "size": "a", "ok": false, "phone": "1" })
                .as_object()
                .unwrap()
        );
        assert_eq!(
            parse_answers(step, None).unwrap_err().message,
            "Size is required"
        );
        assert_eq!(
            parse_answers(step, Some(&json!({ "nope": 1 })))
                .unwrap_err()
                .message,
            "Unknown answer nope"
        );
    }
}
