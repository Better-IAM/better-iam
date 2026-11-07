//! Port of `packages/server/src/workflows.ts`.
//!
//! Identity lifecycle workflows (joiner, mover, leaver): a trigger, a scope in the access-package rule language, and
//! a list of steps that run for each person the trigger fires for, under the authority of the administrator who saved
//! the workflow (re-checked when each step runs). Pure: validation and trigger computation, no store access.
//!
//! Triggers and steps stay JSON (`Value`) with the members TypeScript writes, in its member order, so the records a
//! Rust replica stores are the ones a TypeScript replica stores.

use std::sync::LazyLock;

use better_iam_core::js::{self as core_js, to_lower, trim};
use better_iam_core::{AttributeType, IamResult, Identity, IdentityStatus, canonical_json};
use indexmap::{IndexMap, IndexSet};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::js::{invalid_input, is_object, number, utf16_len};
use crate::package_rules::{AutoAssignInput, RuleEnvironment, parse_auto_assign};
use crate::validation::{integer, object, text};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Workflow {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    #[serde(rename = "trigger")]
    pub trigger: crate::workflows::WorkflowTrigger,
    /// Which people the workflow applies to; absent = every active person (service accounts and agents excluded).
    #[serde(rename = "scope", default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<crate::package_rules::AutoAssignInput>,
    #[serde(rename = "steps")]
    pub steps: Vec<crate::workflows::WorkflowStep>,
    /// Joiner workflows: also run for people who were already active when the workflow was enabled.
    #[serde(rename = "includeExisting")]
    pub include_existing: bool,
    /// At most this many runs start per day; more stops the workflow for the day (`workflow:brake`).
    #[serde(rename = "maxRunsPerDay")]
    pub max_runs_per_day: f64,
    /// The administrator whose rights the steps use (whoever last saved the workflow).
    #[serde(rename = "ownerId")]
    pub owner_id: String,
    /// Whether the owner saved it from a session with a second factor; runs carry it into their decisions.
    #[serde(rename = "ownerMfa")]
    pub owner_mfa: bool,
    #[serde(rename = "version")]
    pub version: f64,
    /// The daily brake's counter: the UTC day and how many automatic runs started on it.
    #[serde(rename = "startedOn", default, skip_serializing_if = "Option::is_none")]
    pub started_on: Option<String>,
    #[serde(
        rename = "startedToday",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub started_today: Option<f64>,
    /// When the workflow was (last) enabled: joiners and dates before it do not fire.
    #[serde(rename = "activeSince")]
    pub active_since: f64,
    /// The day (`YYYY-MM-DD`, UTC) the brake last stopped the workflow, so it is reported once.
    #[serde(rename = "brakedOn", default, skip_serializing_if = "Option::is_none")]
    pub braked_on: Option<String>,
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

/// One run of a workflow for one person (uniqueKey `{workflowId}:{identityId}:{occurrence}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowRun {
    #[serde(rename = "workflowId")]
    pub workflow_id: String,
    #[serde(rename = "workflowName")]
    pub workflow_name: String,
    #[serde(rename = "workflowVersion")]
    pub workflow_version: f64,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    /// What fired: `joiner`, `mover:{n}`, `leaver:{n}`, `date:{target}`, or `manual:{id}`.
    #[serde(rename = "occurrence")]
    pub occurrence: String,
    #[serde(rename = "trigger")]
    pub trigger: String,
    /// The steps as they were when the run started; later edits apply to new runs only.
    #[serde(rename = "steps")]
    pub steps: Vec<crate::workflows::WorkflowStep>,
    /// Whose rights the steps use: the owner who approved these steps (when the run started), not a later editor.
    #[serde(rename = "ownerId")]
    pub owner_id: String,
    #[serde(rename = "ownerMfa")]
    pub owner_mfa: bool,
    /// Finished runs are kept 180 days, then the retention sweep removes them.
    #[serde(rename = "expiresAt", default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<f64>,
    #[serde(rename = "status")]
    pub status: crate::workflows::WorkflowRunStatus,
    #[serde(rename = "stepIndex")]
    pub step_index: f64,
    #[serde(rename = "nextAt")]
    pub next_at: f64,
    #[serde(rename = "results")]
    pub results: Vec<crate::workflows::WorkflowStepResult>,
    #[serde(rename = "startedAt")]
    pub started_at: f64,
    #[serde(
        rename = "finishedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub finished_at: Option<f64>,
    #[serde(rename = "startedBy", default, skip_serializing_if = "Option::is_none")]
    pub started_by: Option<String>,
    #[serde(rename = "error", default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    #[serde(
        rename = "leaseToken",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_token: Option<String>,
    #[serde(
        rename = "leaseUntil",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub lease_until: Option<f64>,
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

/// `'pending' | 'running' | 'waiting' | 'completed' | 'failed' | 'cancelled'`.
pub type WorkflowRunStatus = String;

/// One step (`{ kind: 'add-to-group', groupId, days? }`, `{ kind: 'wait', hours }`, ...; see [`parse_steps`]). Steps
/// run in order; `wait` pauses the run.
pub type WorkflowStep = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowStepResult {
    #[serde(rename = "index")]
    pub index: f64,
    #[serde(rename = "kind")]
    pub kind: String,
    #[serde(rename = "outcome")]
    pub outcome: String,
    #[serde(rename = "at")]
    pub at: f64,
    #[serde(rename = "detail", default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(rename = "code", default, skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What mover and leaver triggers compare against (uniqueKey `{workflowId}:{identityId}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowSubject {
    #[serde(rename = "workflowId")]
    pub workflow_id: String,
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "values")]
    pub values: IndexMap<String, better_iam_core::Json>,
    #[serde(rename = "status")]
    pub status: String,
    /// How many times the trigger fired for this person, so the same change twice fires twice.
    #[serde(rename = "fired")]
    pub fired: f64,
    /// The latest occurrences that started a run (joiner, dates), so each fires once even after its run expired.
    #[serde(
        rename = "occurrences",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub occurrences: Option<Vec<String>>,
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

/// What starts a run for a person: - `joiner`: the person is active and joined after the workflow was enabled (or
/// already existed, with `includeExisting`); - `mover`: one of the watched attributes (declared identity
/// attributes, or `managerId`) changed; - `leaver`: the person was disabled (by an administrator, offboarding, or
/// account expiry); - `date`: `offsetDays` after (or before, when negative) a date the person carries: a declared
/// string attribute holding an ISO date such as `startDate`, or `createdAt` / `expiresAt`; - `manual`: only
/// `workflows.run`. As JSON: `{ kind: 'joiner' }`, `{ kind: 'mover', attributes }`, `{ kind: 'leaver' }`,
/// `{ kind: 'date', attribute, offsetDays }` or `{ kind: 'manual' }`.
pub type WorkflowTrigger = Value;

/// `workflowStepKinds`.
pub const WORKFLOW_STEP_KINDS: &[&str] = &[
    "add-to-group",
    "remove-from-group",
    "remove-from-all-groups",
    "assign-package",
    "revoke-packages",
    "send-email",
    "revoke-sessions",
    "disable",
    "enable",
    "set-attributes",
    "set-expiry",
    "delete",
    "emit-event",
    "wait",
];

/// Steps that take something away; workflows with any of them default to a lower daily brake.
/// A `Set` in TypeScript.
pub const DESTRUCTIVE_STEPS: &[&str] = &[
    "remove-from-all-groups",
    "revoke-packages",
    "revoke-sessions",
    "disable",
    "delete",
];

pub const MAX_STEPS: usize = 20;
pub const MAX_WAITS: usize = 5;
const MAX_WAIT_HOURS: f64 = 365.0 * 24.0;
pub const DAY_MS: f64 = 86400000.0;

/// `step.kind` ("" when a stored step has none).
pub fn step_kind(step: &Value) -> &str {
    step.get("kind").and_then(Value::as_str).unwrap_or_default()
}

/// `trigger.kind` ("" when a stored trigger has none).
pub fn trigger_kind(trigger: &Value) -> &str {
    trigger
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or_default()
}

/// Whether a step kind is one of [`DESTRUCTIVE_STEPS`].
pub fn is_destructive(kind: &str) -> bool {
    DESTRUCTIVE_STEPS.contains(&kind)
}

/// `plain(value)`: a non-null, non-array object.
fn plain(value: Option<&Value>) -> bool {
    is_object(value)
}

fn days(value: Option<&Value>, name: &str) -> IamResult<f64> {
    integer(value, name, 1.0, 3650.0)
}

fn attribute_type_name(kind: AttributeType) -> &'static str {
    match kind {
        AttributeType::String => "string",
        AttributeType::Number => "number",
        AttributeType::Boolean => "boolean",
    }
}

/// Validates a trigger against the deployment's declared identity attributes.
pub fn parse_trigger(
    value: Option<&Value>,
    attributes: &IndexMap<String, AttributeType>,
) -> IamResult<crate::workflows::WorkflowTrigger> {
    let input = object(value)?;
    match input.get("kind").and_then(Value::as_str) {
        Some(kind @ ("joiner" | "leaver" | "manual")) => Ok(json!({ "kind": kind })),
        Some("mover") => {
            let names = match input.get("attributes") {
                Some(Value::Array(items)) if !items.is_empty() && items.len() <= 20 => items,
                _ => {
                    return Err(invalid_input(
                        "trigger.attributes must name 1-20 attributes to watch",
                    ));
                }
            };
            let mut watched: IndexSet<String> = IndexSet::new();
            let checked = names
                .iter()
                .map(|name| text(Some(name), "trigger.attributes", 64))
                .collect::<IamResult<Vec<_>>>()?;
            watched.extend(checked);
            for name in &watched {
                if name != "managerId" && !attributes.contains_key(name) {
                    return Err(invalid_input(format!(
                        "trigger.attributes: {name} is not a declared identity attribute (or managerId)"
                    )));
                }
            }
            let mut sorted: Vec<String> = watched.into_iter().collect();
            crate::js::sort_strings(&mut sorted);
            Ok(json!({ "kind": "mover", "attributes": sorted }))
        }
        Some("date") => {
            let attribute = text(input.get("attribute"), "trigger.attribute", 64)?;
            if attribute != "createdAt"
                && attribute != "expiresAt"
                && attributes.get(&attribute) != Some(&AttributeType::String)
            {
                return Err(invalid_input(
                    "trigger.attribute must be createdAt, expiresAt, or a declared string attribute holding an ISO date",
                ));
            }
            let zero = json!(0);
            let offset = input
                .get("offsetDays")
                .filter(|value| !value.is_null())
                .unwrap_or(&zero);
            let offset_days = integer(Some(offset), "trigger.offsetDays", -365.0, 3650.0)?;
            Ok(json!({ "kind": "date", "attribute": attribute, "offsetDays": number(offset_days) }))
        }
        _ => Err(invalid_input(
            "trigger.kind must be joiner, mover, leaver, date or manual",
        )),
    }
}

/// `/^[^\s@]+@[^\s@]+\.[^\s@]+$/`.
fn email_recipient(value: &str) -> bool {
    let ok = |c: char| c != '@' && !core_js::is_js_whitespace(c);
    let Some((local, domain)) = value.split_once('@') else {
        return false;
    };
    if local.is_empty() || !local.chars().all(ok) || !domain.chars().all(ok) {
        return false;
    }
    domain
        .char_indices()
        .any(|(index, c)| c == '.' && index > 0 && index + 1 < domain.len())
}

/// `/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/`: control characters other than tab, line feed and carriage
/// return.
fn has_body_control(value: &str) -> bool {
    value.chars().any(|c| {
        let code = c as u32;
        code <= 0x08
            || code == 0x0b
            || code == 0x0c
            || (0x0e..=0x1f).contains(&code)
            || code == 0x7f
    })
}

static EVENT_NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z][a-z0-9._-]{0,63}$").expect("valid pattern"));

/// One step of [`parse_steps`].
fn parse_step(
    raw: Option<&Value>,
    index: usize,
    attributes: &IndexMap<String, AttributeType>,
    waits: &mut usize,
) -> IamResult<Value> {
    let path = format!("steps[{index}]");
    if !plain(raw) {
        return Err(invalid_input(format!("{path} must be an object")));
    }
    let Some(Value::Object(raw)) = raw else {
        return Err(invalid_input(format!("{path} must be an object")));
    };
    let only = |keys: &[&str]| -> IamResult<()> {
        for key in core_js::keys(raw) {
            if key != "kind" && !keys.contains(&key.as_str()) {
                return Err(invalid_input(format!("{path}: unknown field {key}")));
            }
        }
        Ok(())
    };
    let kind = raw.get("kind").and_then(Value::as_str).unwrap_or_default();
    let known = raw.get("kind").is_some_and(Value::is_string);
    let mut step = Map::new();
    match (known, kind) {
        (true, "add-to-group") => {
            only(&["groupId", "days"])?;
            step.insert("kind".into(), json!(kind));
            step.insert(
                "groupId".into(),
                json!(text(raw.get("groupId"), &format!("{path}.groupId"), 256)?),
            );
            if raw.get("days").is_some() {
                step.insert(
                    "days".into(),
                    number(days(raw.get("days"), &format!("{path}.days"))?),
                );
            }
        }
        (true, "remove-from-group") => {
            only(&["groupId"])?;
            step.insert("kind".into(), json!(kind));
            step.insert(
                "groupId".into(),
                json!(text(raw.get("groupId"), &format!("{path}.groupId"), 256)?),
            );
        }
        (true, "assign-package") => {
            only(&["packageId", "days"])?;
            step.insert("kind".into(), json!(kind));
            step.insert(
                "packageId".into(),
                json!(text(
                    raw.get("packageId"),
                    &format!("{path}.packageId"),
                    256
                )?),
            );
            if raw.get("days").is_some() {
                step.insert(
                    "days".into(),
                    number(days(raw.get("days"), &format!("{path}.days"))?),
                );
            }
        }
        (true, "revoke-packages") => {
            only(&["packageId"])?;
            step.insert("kind".into(), json!(kind));
            if raw.get("packageId").is_some() {
                step.insert(
                    "packageId".into(),
                    json!(text(
                        raw.get("packageId"),
                        &format!("{path}.packageId"),
                        256
                    )?),
                );
            }
        }
        (true, "send-email") => {
            only(&["to", "subject", "body"])?;
            let to = to_lower(trim(&text(raw.get("to"), &format!("{path}.to"), 254)?));
            if to != "subject" && to != "manager" && !email_recipient(&to) {
                return Err(invalid_input(format!(
                    "{path}.to must be subject, manager, or an email address"
                )));
            }
            let subject = text(raw.get("subject"), &format!("{path}.subject"), 200)?;
            let body = match raw.get("body") {
                Some(Value::String(body))
                    if !trim(body).is_empty()
                        && utf16_len(body) <= 5000
                        && !has_body_control(body) =>
                {
                    body.clone()
                }
                _ => {
                    return Err(invalid_input(format!(
                        "{path}.body must be text of at most 5000 characters"
                    )));
                }
            };
            step.insert("kind".into(), json!(kind));
            step.insert("to".into(), json!(to));
            step.insert("subject".into(), json!(subject));
            step.insert("body".into(), json!(body));
        }
        (true, "remove-from-all-groups" | "revoke-sessions" | "disable" | "enable" | "delete") => {
            only(&[])?;
            step.insert("kind".into(), json!(kind));
        }
        (true, "set-attributes") => {
            only(&["attributes"])?;
            let entries = match raw.get("attributes") {
                Some(Value::Object(map)) if plain(raw.get("attributes")) && !map.is_empty() => map,
                _ => {
                    return Err(invalid_input(format!(
                        "{path}.attributes must set at least one attribute"
                    )));
                }
            };
            let mut result = Map::new();
            for (name, entry) in core_js::entries(entries) {
                let Some(kind) = attributes.get(name).copied() else {
                    return Err(invalid_input(format!(
                        "{path}.attributes: {name} is not a declared identity attribute"
                    )));
                };
                let type_name = attribute_type_name(kind);
                let wrong = !entry.is_null()
                    && (core_js::type_of(entry) != type_name
                        || (kind == AttributeType::String
                            && entry.as_str().is_some_and(|text| {
                                utf16_len(text) > 2048 || crate::js::has_control(text)
                            }))
                        || (kind == AttributeType::Number
                            && !entry.as_f64().is_some_and(f64::is_finite)));
                if wrong {
                    return Err(invalid_input(format!(
                        "{path}.attributes: {name} must be a {type_name} (or null to clear it)"
                    )));
                }
                result.insert(name.clone(), entry.clone());
            }
            step.insert("kind".into(), json!(kind));
            step.insert("attributes".into(), Value::Object(result));
        }
        (true, "set-expiry") => {
            only(&["days"])?;
            let value = match raw.get("days") {
                Some(Value::Null) => Value::Null,
                other => number(days(other, &format!("{path}.days"))?),
            };
            step.insert("kind".into(), json!(kind));
            step.insert("days".into(), value);
        }
        (true, "emit-event") => {
            only(&["name"])?;
            let name = text(raw.get("name"), &format!("{path}.name"), 64)?;
            if !EVENT_NAME.is_match(&name) {
                return Err(invalid_input(format!(
                    "{path}.name uses lowercase letters, digits, dots, underscores or hyphens"
                )));
            }
            step.insert("kind".into(), json!(kind));
            step.insert("name".into(), json!(name));
        }
        (true, "wait") => {
            only(&["hours"])?;
            *waits += 1;
            let hours = integer(
                raw.get("hours"),
                &format!("{path}.hours"),
                1.0,
                MAX_WAIT_HOURS,
            )?;
            step.insert("kind".into(), json!(kind));
            step.insert("hours".into(), number(hours));
        }
        _ => {
            return Err(invalid_input(format!(
                "{path}.kind must be one of {}",
                WORKFLOW_STEP_KINDS.join(", ")
            )));
        }
    }
    Ok(Value::Object(step))
}

/// Validates the steps (references to groups and packages are checked against the store by the caller).
pub fn parse_steps(
    value: Option<&Value>,
    attributes: &IndexMap<String, AttributeType>,
) -> IamResult<Vec<crate::workflows::WorkflowStep>> {
    let items = match value {
        Some(Value::Array(items)) if !items.is_empty() && items.len() <= MAX_STEPS => items,
        _ => {
            return Err(invalid_input(format!(
                "steps must list 1-{MAX_STEPS} steps"
            )));
        }
    };
    let mut waits = 0;
    let steps = items
        .iter()
        .enumerate()
        .map(|(index, raw)| parse_step(Some(raw), index, attributes, &mut waits))
        .collect::<IamResult<Vec<_>>>()?;
    if waits > MAX_WAITS {
        return Err(invalid_input(format!(
            "A workflow may wait at most {MAX_WAITS} times"
        )));
    }
    if steps.iter().all(|step| step_kind(step) == "wait") {
        return Err(invalid_input(
            "A workflow needs at least one step that does something",
        ));
    }
    if steps.last().is_some_and(|step| step_kind(step) == "wait") {
        return Err(invalid_input("A workflow cannot end with a wait"));
    }
    if let Some(delete_at) = steps.iter().position(|step| step_kind(step) == "delete")
        && delete_at != steps.len() - 1
    {
        return Err(invalid_input("delete must be the last step"));
    }
    Ok(steps)
}

/// Validates a scope in the access-package rule language (`include` / `exclude` condition sets).
pub fn parse_scope(
    value: Option<&Value>,
    env: &crate::package_rules::RuleEnvironment,
) -> IamResult<Option<crate::package_rules::AutoAssignInput>> {
    let Some(value) = value.filter(|value| !value.is_null()) else {
        return Ok(None);
    };
    let Value::Object(map) = value else {
        return Err(invalid_input("scope must be an object"));
    };
    if !plain(Some(value)) {
        return Err(invalid_input("scope must be an object"));
    }
    for key in core_js::keys(map) {
        if key != "include" && key != "exclude" {
            return Err(invalid_input(format!(
                "scope: unknown field {key} (use include and exclude)"
            )));
        }
    }
    let parsed = parse_auto_assign(Some(value), env, Some("scope"))?;
    Ok(Some(AutoAssignInput {
        include: parsed.include,
        exclude: parsed.exclude.filter(|exclude| !exclude.is_empty()),
        grace_ms: None,
        max_grants: None,
        max_removals: None,
        extra: Map::new(),
    }))
}

/// The environment `parseScope` validates against: the declared attributes, the tenant's group IDs, and its org
/// structure (`orgRuleEnvironment`).
pub fn scope_environment(
    attributes: &IndexMap<String, AttributeType>,
    groups: IndexSet<String>,
    org: Value,
) -> RuleEnvironment {
    RuleEnvironment {
        identity_attributes: attributes.clone(),
        groups: Some(groups),
        packaged_groups: None,
        org: Some(org),
        extra: Map::new(),
    }
}

/// The daily run brake: lower when a workflow takes access away.
pub fn default_brake(steps: &[crate::workflows::WorkflowStep]) -> f64 {
    if steps.iter().any(|step| is_destructive(step_kind(step))) {
        25.0
    } else {
        200.0
    }
}

/// `new Date(at).toISOString().slice(0, 10)`.
pub fn utc_day(at: f64) -> IamResult<String> {
    core_js::iso_string(at)
        .map(|iso| iso.chars().take(10).collect())
        .ok_or_else(|| crate::js::ThrownError::new("RangeError", "Invalid time value").into())
}

/// `identity.status` as TypeScript stores it.
pub fn status_name(status: IdentityStatus) -> &'static str {
    match status {
        IdentityStatus::Active => "active",
        IdentityStatus::Disabled => "disabled",
        IdentityStatus::Deleted => "deleted",
    }
}

/// The values a mover trigger watches, as the snapshot stores them.
pub fn watched_values(trigger: &Value, identity: &Identity) -> Map<String, Value> {
    let mut values = Map::new();
    let names = trigger
        .get("attributes")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    for name in names {
        let name = crate::js::js_string(Some(&name));
        let value = if name == "managerId" {
            identity.manager_id.clone().map(Value::String)
        } else {
            identity
                .attributes
                .as_ref()
                .and_then(|attributes| attributes.get(&name).cloned())
        };
        values.insert(name, value.unwrap_or(Value::Null));
    }
    values
}

fn digest(value: &Value) -> String {
    let hex = hex::encode(Sha256::digest(canonical_json(value).as_bytes()));
    hex[..16].to_owned()
}

static ISO_DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[0-9]{4}-[0-9]{2}-[0-9]{2}(?:T[0-9]{2}:[0-9]{2}(?::[0-9]{2}(?:\.[0-9]{1,9})?)?(?:Z|[+-][0-9]{2}:[0-9]{2}))?$",
    )
    .expect("valid pattern")
});

/// The instant a date trigger fires for an identity, or undefined when the identity carries no usable date.
pub fn date_target(trigger: &Value, identity: &better_iam_core::Identity) -> Option<f64> {
    let attribute = trigger
        .get("attribute")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let base = match attribute {
        "createdAt" => Some(identity.created_at),
        "expiresAt" => identity.expires_at,
        _ => {
            let raw = identity
                .attributes
                .as_ref()
                .and_then(|attributes| attributes.get(attribute));
            // A date (read as UTC midnight) or a full timestamp with its offset; a local time without one is
            // ambiguous.
            match raw {
                Some(Value::String(raw)) if ISO_DATE.is_match(raw) => {
                    let parsed = if raw.len() == 10 {
                        better_iam_auth::js_date::parse(&format!("{raw}T00:00:00Z"))
                    } else {
                        better_iam_auth::js_date::parse(raw)
                    };
                    parsed.is_finite().then_some(parsed)
                }
                _ => None,
            }
        }
    };
    let offset = trigger
        .get("offsetDays")
        .map(core_js::to_number)
        .unwrap_or(f64::NAN);
    base.map(|base| base + offset * DAY_MS)
}

/// The part of a [`WorkflowSubject`] a trigger compares against: `Pick<WorkflowSubject, 'values' | 'status' | 'fired'>`.
#[derive(Debug, Clone, PartialEq)]
pub struct SubjectSnapshot {
    pub values: Map<String, Value>,
    pub status: String,
    pub fired: f64,
}

impl SubjectSnapshot {
    /// The snapshot members of a stored `workflowSubjects` record.
    pub fn of_record(record: &Map<String, Value>) -> Self {
        Self {
            values: record
                .get("values")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default(),
            status: record
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned(),
            fired: record
                .get("fired")
                .map(core_js::to_number)
                .unwrap_or(f64::NAN),
        }
    }
}

/// The answer of [`trigger_occurrence`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TriggerOccurrence {
    pub occurrence: Option<String>,
    pub snapshot: Option<SubjectSnapshot>,
}

/// What [`trigger_occurrence`] reads of a workflow: `Pick<Workflow, 'trigger' | 'activeSince' | 'includeExisting'>`.
pub struct TriggerWorkflow<'a> {
    pub trigger: &'a Value,
    pub active_since: f64,
    pub include_existing: bool,
}

impl<'a> TriggerWorkflow<'a> {
    /// The members of a stored workflow record.
    pub fn of_record(record: &'a Map<String, Value>) -> Self {
        static NONE: Value = Value::Null;
        Self {
            trigger: record.get("trigger").unwrap_or(&NONE),
            active_since: record
                .get("activeSince")
                .map(core_js::to_number)
                .unwrap_or(f64::NAN),
            include_existing: crate::js::truthy(record.get("includeExisting")),
        }
    }
}

/// Whether the trigger fires for an identity now, and the snapshot to keep for mover and leaver triggers.
/// `occurrence` names the firing so each change runs once; the caller skips occurrences that already have a run.
pub fn trigger_occurrence(
    workflow: &TriggerWorkflow<'_>,
    identity: &better_iam_core::Identity,
    snapshot: Option<&SubjectSnapshot>,
    now: f64,
) -> IamResult<TriggerOccurrence> {
    let trigger = workflow.trigger;
    let status = status_name(identity.status);
    Ok(match trigger_kind(trigger) {
        "joiner" => {
            if identity.status == IdentityStatus::Active
                && (workflow.include_existing || identity.created_at >= workflow.active_since)
            {
                TriggerOccurrence {
                    occurrence: Some("joiner".into()),
                    snapshot: None,
                }
            } else {
                TriggerOccurrence::default()
            }
        }
        "mover" => {
            let values = watched_values(trigger, identity);
            let Some(snapshot) = snapshot else {
                return Ok(TriggerOccurrence {
                    occurrence: None,
                    snapshot: Some(SubjectSnapshot {
                        values,
                        status: status.into(),
                        fired: 0.0,
                    }),
                });
            };
            let current = digest(&Value::Object(values.clone()));
            if current == digest(&Value::Object(snapshot.values.clone())) {
                return Ok(TriggerOccurrence::default());
            }
            let fired = snapshot.fired + 1.0;
            TriggerOccurrence {
                occurrence: (identity.status == IdentityStatus::Active)
                    .then(|| format!("mover:{}:{current}", core_js::number_to_string(fired))),
                snapshot: Some(SubjectSnapshot {
                    values,
                    status: status.into(),
                    fired,
                }),
            }
        }
        "leaver" => {
            let Some(snapshot) = snapshot else {
                return Ok(TriggerOccurrence {
                    occurrence: None,
                    snapshot: Some(SubjectSnapshot {
                        values: Map::new(),
                        status: status.into(),
                        fired: 0.0,
                    }),
                });
            };
            if snapshot.status == status {
                return Ok(TriggerOccurrence::default());
            }
            let leaving =
                snapshot.status == "active" && identity.status == IdentityStatus::Disabled;
            let fired = snapshot.fired + if leaving { 1.0 } else { 0.0 };
            TriggerOccurrence {
                occurrence: leaving.then(|| format!("leaver:{}", core_js::number_to_string(fired))),
                snapshot: Some(SubjectSnapshot {
                    values: Map::new(),
                    status: status.into(),
                    fired,
                }),
            }
        }
        "date" => {
            if identity.status != IdentityStatus::Active {
                return Ok(TriggerOccurrence::default());
            }
            // Dates well before the workflow existed never fire; a date that moves fires again.
            match date_target(trigger, identity) {
                Some(target) if !(target > now || target < workflow.active_since - DAY_MS) => {
                    TriggerOccurrence {
                        occurrence: Some(format!("date:{}", utc_day(target)?)),
                        snapshot: None,
                    }
                }
                _ => TriggerOccurrence::default(),
            }
        }
        "manual" => TriggerOccurrence::default(),
        // A stored trigger of no known kind: TypeScript's switch falls through and destructuring its `undefined`
        // answer throws a TypeError.
        _ => return Err(crate::js::internal_error()),
    })
}

/// What [`fill_template`] fills in.
pub struct TemplateValues<'a> {
    pub identity: &'a Identity,
    pub organization: &'a str,
    pub workflow: &'a str,
}

static PLACEHOLDER: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{([a-zA-Z][A-Za-z0-9_.]{0,80})\}").expect("valid pattern"));

/// Fills `{name}`, `{email}`, `{organization}`, `{workflow}` and `{attribute.<name>}` in an email template.
pub fn fill_template(template: &str, values: &TemplateValues<'_>) -> String {
    PLACEHOLDER
        .replace_all(template, |captures: &regex::Captures<'_>| {
            let key = &captures[1];
            match key {
                "name" => values.identity.name.clone(),
                "email" => values.identity.email.clone().unwrap_or_default(),
                "organization" => values.organization.to_owned(),
                "workflow" => values.workflow.to_owned(),
                _ => match key.strip_prefix("attribute.") {
                    Some(name) => {
                        let value = values
                            .identity
                            .attributes
                            .as_ref()
                            .and_then(|attributes| attributes.get(name));
                        match value {
                            None | Some(Value::Null) => String::new(),
                            other => crate::js::js_string(other),
                        }
                    }
                    None => captures[0].to_owned(),
                },
            }
        })
        .into_owned()
}
