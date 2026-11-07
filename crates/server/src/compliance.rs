//! Port of `packages/server/src/compliance.ts`.
//!
//! The compliance center: automated checks over the IAM state (who has MFA, stale access, reviews, leavers,
//! privileged access, audit integrity, ...), mapped to the requirements of common frameworks. Tenants turn checks into
//! controls, evaluate them on a schedule, record exceptions with an expiry, and export signed evidence.
//!
//! Checks only read, and they read outside any transaction (`ctx.store`), so an evaluation never holds the store's
//! write lock while it walks a large tenant; only the results are written, in one short transaction. Findings name
//! their subject by ID (`identity:{id}`); names are looked up when results are read, so stored results carry no
//! personal data beyond pseudonymous IDs.

use std::sync::{Arc, LazyLock};

use better_iam_core::js as core_js;
use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, OrderOptions, Record, Tenant,
    VerifyAuditChainOptions, find_ordered, match_pattern, verify_audit_chain,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::js::{cmp_utf16, number_to_string};
use crate::privacy::{SubjectRequest, request_overdue};
use crate::sod::sod_violations;
use crate::validation::integer;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CheckFinding {
    /// What the finding is about, specific enough that an exception covers only this finding: `identity:{id}`,
    /// `identity:{id}:rule:{ruleId}`, `session:{id}`, `trust:{id}`, `role:{id}`, `campaign:{id}`, `request:{id}`, or
    /// `tenant:{id}:{condition}` for organization-wide settings.
    #[serde(rename = "subject")]
    pub subject: String,
    /// Plain text without names; readers with directory access see the subject's name next to it.
    #[serde(rename = "detail")]
    pub detail: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `pass`, `fail`, `warn` or `not-applicable`.
pub type CheckStatus = String;

/// How far the audit-integrity check has verified a tenant's chain (`complianceCheckpoints`, ID
/// `audit:{tenantId}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceCheckpoint {
    #[serde(rename = "sequence")]
    pub sequence: f64,
    #[serde(rename = "hash")]
    pub hash: String,
    #[serde(rename = "verifiedAt")]
    pub verified_at: f64,
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

/// Tenant state: one control per check (or a custom one), with its framework mappings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceControl {
    #[serde(rename = "key")]
    pub key: String,
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "checkId")]
    pub check_id: String,
    #[serde(rename = "params")]
    pub params: IndexMap<String, f64>,
    /// Framework requirements this control evidences, as `framework:requirement` (or free-form references).
    #[serde(rename = "mappings")]
    pub mappings: Vec<String>,
    #[serde(rename = "enabled")]
    pub enabled: bool,
    #[serde(
        rename = "lastStatus",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_status: Option<String>,
    #[serde(
        rename = "lastEvaluatedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_evaluated_at: Option<f64>,
    /// The newest result, so reads never scan the result history.
    #[serde(
        rename = "lastResultId",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub last_result_id: Option<String>,
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
pub struct ComplianceException {
    #[serde(rename = "controlKey")]
    pub control_key: String,
    #[serde(rename = "subject")]
    pub subject: String,
    #[serde(rename = "reason")]
    pub reason: String,
    #[serde(rename = "expiresAt")]
    pub expires_at: f64,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    /// `pending` until a second person with `iam:compliance:manage` approves it; only `approved` exceptions cover
    /// findings. Absent on exceptions created before approvals, which count as approved. Revoked ones stay as history.
    #[serde(rename = "status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,
    #[serde(
        rename = "approvedBy",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub approved_by: Option<String>,
    #[serde(
        rename = "approvedAt",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub approved_at: Option<f64>,
    #[serde(rename = "revokedBy", default, skip_serializing_if = "Option::is_none")]
    pub revoked_by: Option<String>,
    #[serde(rename = "revokedAt", default, skip_serializing_if = "Option::is_none")]
    pub revoked_at: Option<f64>,
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
pub struct ComplianceResult {
    #[serde(rename = "runId")]
    pub run_id: String,
    #[serde(rename = "controlId")]
    pub control_id: String,
    #[serde(rename = "controlKey")]
    pub control_key: String,
    #[serde(rename = "checkId")]
    pub check_id: String,
    #[serde(rename = "status")]
    pub status: crate::compliance::CheckStatus,
    /// The status before exceptions were applied.
    #[serde(rename = "rawStatus")]
    pub raw_status: crate::compliance::CheckStatus,
    #[serde(rename = "summary")]
    pub summary: String,
    #[serde(rename = "metrics")]
    pub metrics: IndexMap<String, f64>,
    /// At most 200 findings, the excepted ones marked.
    #[serde(rename = "findings")]
    pub findings: Vec<Value>,
    #[serde(rename = "findingsTotal")]
    pub findings_total: f64,
    #[serde(rename = "excepted")]
    pub excepted: f64,
    #[serde(rename = "evaluatedAt")]
    pub evaluated_at: f64,
    /// Results are kept 400 days (a year of history for an audit period), then the retention sweep removes them.
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

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComplianceRun {
    #[serde(rename = "evaluatedAt")]
    pub evaluated_at: f64,
    #[serde(rename = "counts")]
    pub counts: Value,
    /// SHA-256 of the run's results (canonical JSON), also recorded in the audit chain.
    #[serde(rename = "digest")]
    pub digest: String,
    #[serde(rename = "triggeredBy")]
    pub triggered_by: String,
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

/// Built-in mappings. They are evidence for these requirements, not the whole of them.
pub static COMPLIANCE_FRAMEWORKS: std::sync::LazyLock<Value> = std::sync::LazyLock::new(
    || json!([{"id":"soc2","name":"SOC 2 (Trust Services Criteria)","requirements":[{"id":"CC6.1","title":"Logical access security","checks":["mfa-enforced","mfa-coverage","password-length","session-lifetime","api-key-lifetime"]},{"id":"CC6.2","title":"Registration and deregistration of users","checks":["leaver-access","inactive-accounts"]},{"id":"CC6.3","title":"Role-based access, least privilege, and access review","checks":["access-reviews","privileged-access","separation-of-duties","stale-api-keys"]},{"id":"CC7.2","title":"Monitoring of system components","checks":["audit-integrity"]}]},{"id":"iso27001","name":"ISO/IEC 27001:2022 Annex A","requirements":[{"id":"5.3","title":"Segregation of duties","checks":["separation-of-duties"]},{"id":"5.16","title":"Identity management","checks":["leaver-access","inactive-accounts"]},{"id":"5.17","title":"Authentication information","checks":["password-length","api-key-lifetime"]},{"id":"5.18","title":"Access rights","checks":["access-reviews","stale-api-keys"]},{"id":"5.34","title":"Privacy and protection of PII","checks":["privacy-deadlines"]},{"id":"8.2","title":"Privileged access rights","checks":["privileged-access","owner-redundancy"]},{"id":"8.5","title":"Secure authentication","checks":["mfa-enforced","mfa-coverage","session-lifetime"]},{"id":"8.15","title":"Logging","checks":["audit-integrity"]}]},{"id":"nist-800-53","name":"NIST SP 800-53 Rev. 5","requirements":[{"id":"AC-2","title":"Account management","checks":["leaver-access","inactive-accounts"]},{"id":"AC-5","title":"Separation of duties","checks":["separation-of-duties"]},{"id":"AC-6","title":"Least privilege","checks":["privileged-access"]},{"id":"AC-6(7)","title":"Review of user privileges","checks":["access-reviews"]},{"id":"AC-12","title":"Session termination","checks":["session-lifetime"]},{"id":"IA-2(1)","title":"Multi-factor authentication","checks":["mfa-enforced","mfa-coverage"]},{"id":"IA-5","title":"Authenticator management","checks":["password-length","api-key-lifetime","stale-api-keys"]},{"id":"AU-9","title":"Protection of audit information","checks":["audit-integrity"]}]},{"id":"gdpr","name":"GDPR (selected articles)","requirements":[{"id":"Art. 12","title":"Responding to data subjects in time","checks":["privacy-deadlines"]},{"id":"Art. 32","title":"Security of processing","checks":["mfa-coverage","audit-integrity","leaver-access"]}]}]),
);

impl CheckFinding {
    /// A finding with its subject and detail.
    pub fn new(subject: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            subject: subject.into(),
            detail: detail.into(),
            extra: Map::new(),
        }
    }
}

/// The status and summary a check's judge gives (`{ status, summary }`).
#[derive(Debug, Clone, PartialEq)]
pub struct Judgement {
    pub status: &'static str,
    pub summary: String,
}

impl Judgement {
    fn new(status: &'static str, summary: impl Into<String>) -> Self {
        Self {
            status,
            summary: summary.into(),
        }
    }
}

/// `judge(remaining)`: the status given the findings that no exception covers.
pub type Judge = Box<dyn Fn(&[CheckFinding]) -> Judgement + Send + Sync>;

/// What a check found (`CheckOutcome`).
pub struct CheckOutcome {
    pub findings: Vec<CheckFinding>,
    /// `metrics`, in the TypeScript member order.
    pub metrics: Vec<(&'static str, f64)>,
    /// The status given the findings that no exception covers.
    pub judge: Judge,
    /// Audit verification progress to store (audit-integrity only): `{ sequence, hash }`.
    pub checkpoint: Option<(f64, String)>,
}

impl CheckOutcome {
    /// `metrics` as the JSON object TypeScript stores.
    pub fn metrics_json(&self) -> Map<String, Value> {
        metrics_json(&self.metrics)
    }
}

/// A list of metrics as a JSON object of JavaScript numbers.
pub fn metrics_json(metrics: &[(&'static str, f64)]) -> Map<String, Value> {
    metrics
        .iter()
        .map(|(name, value)| ((*name).to_owned(), crate::js::number(*value)))
        .collect()
}

/// A check parameter (`CheckParam`).
#[derive(Debug, Clone, PartialEq)]
pub struct CheckParam {
    pub name: &'static str,
    pub description: &'static str,
    pub default: f64,
    pub min: f64,
    pub max: f64,
}

impl CheckParam {
    /// The parameter as the catalog lists it.
    pub fn to_json(&self) -> Value {
        json!({
            "name": self.name,
            "description": self.description,
            "default": crate::js::number(self.default),
            "min": crate::js::number(self.min),
            "max": crate::js::number(self.max),
        })
    }
}

/// A built-in check (`ComplianceCheck`); [`evaluate_check`] runs it.
#[derive(Debug, Clone, PartialEq)]
pub struct ComplianceCheck {
    pub id: &'static str,
    pub title: &'static str,
    pub description: &'static str,
    pub params: &'static [CheckParam],
    /// Exceptions may not cover this check's findings (a broken audit chain cannot be accepted).
    pub no_exceptions: bool,
}

const DAY_MS: f64 = 86_400_000.0;
const HOUR_MS: f64 = 3_600_000.0;
/// Audit events verified per evaluation (the rest continue from the checkpoint on the next run).
const AUDIT_PAGE_SIZE: f64 = 2_000.0;
const AUDIT_PAGES: f64 = 50.0;

fn plural(count: usize, word: &str) -> String {
    format!("{count} {word}{}", if count == 1 { "" } else { "s" })
}

/// `${number}` of a JavaScript number.
fn n(value: f64) -> String {
    number_to_string(value)
}

/// `Math.floor(value)` as text.
fn floor(value: f64) -> String {
    n(value.floor())
}

/// `Math.round(value)`: halves round up.
fn js_round(value: f64) -> f64 {
    let floor = value.floor();
    if value - floor >= 0.5 {
        floor + 1.0
    } else {
        floor
    }
}

fn num(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

fn text_of<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn truthy(record: &Record, key: &str) -> bool {
    crate::js::truthy(record.get(key))
}

/// `value === undefined || value > now`: not ended.
fn live(record: &Record, key: &str, now: f64) -> bool {
    match record.get(key) {
        None => true,
        Some(value) => core_js::as_number(value).is_some_and(|at| at > now),
    }
}

fn param(params: &IndexMap<String, f64>, name: &str) -> f64 {
    params.get(name).copied().unwrap_or(f64::NAN)
}

async fn find(store: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    store
        .find(collection, &filter, &FindOptions::default())
        .await
}

fn by_tenant(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id)
}

/// `ctx.identityExpired(identity)`.
fn identity_expired(ctx: &ServerContext, identity: &Record) -> bool {
    num(identity, "expiresAt").is_some_and(|expires| expires <= ctx.now())
}

/// Active, unexpired people.
async fn people(ctx: &ServerContext, store: &Store, tenant_id: &str) -> IamResult<Vec<Record>> {
    Ok(find(store, "identities", by_tenant(tenant_id))
        .await?
        .into_iter()
        .filter(|identity| {
            text_of(identity, "kind") == Some("user")
                && text_of(identity, "status") == Some("active")
                && !identity_expired(ctx, identity)
        })
        .collect())
}

fn count_judge(what: &'static str, fine: String) -> Judge {
    Box::new(move |remaining| {
        if remaining.is_empty() {
            Judgement::new("pass", fine.clone())
        } else {
            Judgement::new(
                "fail",
                format!(
                    "{} need{} attention",
                    plural(remaining.len(), what),
                    if remaining.len() == 1 { "s" } else { "" }
                ),
            )
        }
    })
}

/// Actions that together amount to administering a tenant: whoever may do all of them can grant themselves anything.
const ADMIN_PROBES: [&str; 3] = [
    "iam:bindings:create",
    "iam:roles:update",
    "iam:policies:update",
];

fn safe_match(pattern: &Value, value: &str) -> bool {
    pattern
        .as_str()
        .is_some_and(|pattern| match_pattern(pattern, value, None))
}

fn list(value: Option<&Value>) -> &[Value] {
    match value {
        Some(Value::Array(items)) => items,
        _ => &[],
    }
}

/// Whether documents allow administering the tenant: one allow statement covering every admin probe action on the
/// tenant's resource. Conditions are ignored on purpose: a condition (MFA, network, time) changes when someone may act,
/// not who holds the power.
pub fn administers(documents: &[Option<&Value>], tenant_id: &str) -> bool {
    let resource = format!("iam/{tenant_id}");
    documents.iter().any(|document| {
        list(document.and_then(|document| document.get("statements")))
            .iter()
            .any(|statement| {
                statement.get("effect").and_then(Value::as_str) == Some("allow")
                    && ADMIN_PROBES.iter().all(|probe| {
                        list(statement.get("actions"))
                            .iter()
                            .any(|action| safe_match(action, probe))
                    })
                    && list(statement.get("resources"))
                        .iter()
                        .any(|pattern| safe_match(pattern, &resource))
            })
    })
}

/// Who holds full administration, by any path: owners and root administrators; live bindings (direct or through a
/// group) to a role that administers the tenant itself or through the roles it inherits; eligible bindings to such a
/// role while activated or when activation needs no approval; and trusts that let an identity or workload assume one.
async fn privileged_holders(
    ctx: &ServerContext,
    store: &Store,
    tenant_id: &str,
    now: f64,
) -> IamResult<(IndexMap<String, String>, usize)> {
    let mut holders: IndexMap<String, String> = IndexMap::new();
    let everyone: Vec<Record> = find(store, "identities", by_tenant(tenant_id))
        .await?
        .into_iter()
        .filter(|identity| {
            text_of(identity, "status") == Some("active") && !identity_expired(ctx, identity)
        })
        .collect();
    for identity in &everyone {
        if truthy(identity, "owner") || truthy(identity, "rootAdmin") {
            holders.insert(
                format!("identity:{}", text_of(identity, "id").unwrap_or_default()),
                if truthy(identity, "rootAdmin") {
                    "root administrator".to_owned()
                } else {
                    "owner".to_owned()
                },
            );
        }
    }
    let policies: IndexMap<String, Record> = find(store, "policies", by_tenant(tenant_id))
        .await?
        .into_iter()
        .map(|policy| {
            (
                text_of(&policy, "id").unwrap_or_default().to_owned(),
                policy,
            )
        })
        .collect();
    let roles: IndexMap<String, Record> = find(store, "roles", by_tenant(tenant_id))
        .await?
        .into_iter()
        .map(|role| (text_of(&role, "id").unwrap_or_default().to_owned(), role))
        .collect();
    let own = |role: &Record| -> Vec<Option<Value>> {
        let mut documents = vec![role.get("document").cloned()];
        for policy_id in list(role.get("policyIds")) {
            documents.push(
                policy_id
                    .as_str()
                    .and_then(|policy_id| policies.get(policy_id))
                    .and_then(|policy| policy.get("document").cloned()),
            );
        }
        documents
    };
    // A role administers if it or any role it inherits (as decisions.ts follows them) does.
    let mut admin_roles: IndexMap<String, String> = IndexMap::new();
    for role in roles.values() {
        let role_id = text_of(role, "id").unwrap_or_default();
        let role_name = crate::js::js_string(role.get("name"));
        let mut seen: IndexSet<String> = IndexSet::from([role_id.to_owned()]);
        let mut queue: std::collections::VecDeque<&Record> =
            std::collections::VecDeque::from([role]);
        while !queue.is_empty() && seen.len() <= 256 {
            let current = queue.pop_front().expect("queue is not empty");
            let documents = own(current);
            let documents: Vec<Option<&Value>> = documents.iter().map(Option::as_ref).collect();
            if administers(&documents, tenant_id) {
                let current_id = text_of(current, "id").unwrap_or_default();
                admin_roles.insert(
                    role_id.to_owned(),
                    if current_id == role_id {
                        role_name.clone()
                    } else {
                        format!(
                            "{role_name}, through {}",
                            crate::js::js_string(current.get("name"))
                        )
                    },
                );
                break;
            }
            for inherited_id in list(current.get("inherits")) {
                let Some(inherited_id) = inherited_id.as_str() else {
                    continue;
                };
                let Some(inherited) = roles.get(inherited_id) else {
                    continue;
                };
                if truthy(inherited, "protected") || seen.contains(inherited_id) {
                    continue;
                }
                seen.insert(inherited_id.to_owned());
                queue.push_back(inherited);
            }
        }
    }
    let mut eligible_with_approval = 0;
    if admin_roles.is_empty() {
        return Ok((holders, eligible_with_approval));
    }
    let mut members: IndexMap<String, Vec<String>> = IndexMap::new();
    for member in find(store, "groupMembers", by_tenant(tenant_id)).await? {
        if live(&member, "expiresAt", now) {
            members
                .entry(text_of(&member, "groupId").unwrap_or_default().to_owned())
                .or_default()
                .push(
                    text_of(&member, "identityId")
                        .unwrap_or_default()
                        .to_owned(),
                );
        }
    }
    let activations: Vec<Record> = find(store, "bindingActivations", by_tenant(tenant_id))
        .await?
        .into_iter()
        .filter(|activation| {
            text_of(activation, "status") != Some("pending")
                && text_of(activation, "status") != Some("denied")
                && num(activation, "expiresAt").is_some_and(|expires| expires > now)
        })
        .collect();
    let active: IndexSet<&str> = everyone
        .iter()
        .map(|identity| text_of(identity, "id").unwrap_or_default())
        .collect();
    for binding in find(store, "bindings", by_tenant(tenant_id)).await? {
        let Some(role) = text_of(&binding, "roleId").and_then(|role_id| admin_roles.get(role_id))
        else {
            continue;
        };
        if num(&binding, "startsAt").is_some_and(|starts| starts > now) {
            continue;
        }
        if num(&binding, "expiresAt").is_some_and(|expires| expires <= now) {
            continue;
        }
        let subject_id = text_of(&binding, "subjectId").unwrap_or_default();
        let subjects: Vec<String> = if text_of(&binding, "subjectType") == Some("identity") {
            vec![subject_id.to_owned()]
        } else {
            members.get(subject_id).cloned().unwrap_or_default()
        };
        let binding_id = text_of(&binding, "id").unwrap_or_default();
        for subject in subjects {
            let key = format!("identity:{subject}");
            if !active.contains(subject.as_str()) || holders.contains_key(&key) {
                continue;
            }
            if !truthy(&binding, "eligible") {
                holders.insert(key, format!("role {role}"));
            } else if activations.iter().any(|item| {
                text_of(item, "bindingId") == Some(binding_id)
                    && text_of(item, "identityId") == Some(subject.as_str())
            }) {
                holders.insert(key, format!("role {role}, activated"));
            } else if !truthy(&binding, "requireApproval") {
                holders.insert(key, format!("role {role}, eligible without approval"));
            } else {
                eligible_with_approval += 1;
            }
        }
    }
    for trust in find(store, "trusts", by_tenant(tenant_id)).await? {
        let Some(role) = text_of(&trust, "roleId").and_then(|role_id| admin_roles.get(role_id))
        else {
            continue;
        };
        if truthy(&trust, "revoked") {
            continue;
        }
        let source_identity = crate::js::js_string(trust.get("sourceIdentityId"));
        holders.insert(
            format!("trust:{}", text_of(&trust, "id").unwrap_or_default()),
            if text_of(&trust, "kind") == Some("web-identity") {
                format!("a workload federation trust assumes role {role}")
            } else if text_of(&trust, "sourceTenantId") == Some(tenant_id) {
                format!("a trust lets identity {source_identity} assume role {role}")
            } else {
                format!(
                    "a trust lets identity {source_identity} of tenant {} assume role {role}",
                    crate::js::js_string(trust.get("sourceTenantId"))
                )
            },
        );
    }
    Ok((holders, eligible_with_approval))
}

const fn p(
    name: &'static str,
    description: &'static str,
    default: f64,
    min: f64,
    max: f64,
) -> CheckParam {
    CheckParam {
        name,
        description,
        default,
        min,
        max,
    }
}

/// The built-in checks.
pub static COMPLIANCE_CHECKS: [ComplianceCheck; 14] = [
    ComplianceCheck {
        id: "mfa-enforced",
        title: "Multi-factor authentication is required",
        description: "The organization\u{2019}s sign-in policy requires a second factor for everyone (requireMfa).",
        params: &[],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "mfa-coverage",
        title: "People have a second factor",
        description: "The share of active people with an authenticator app, or a passkey where the deployment accepts passkeys as a second factor.",
        params: &[p(
            "minimumPercent",
            "Share of people that must be enrolled",
            100.0,
            50.0,
            100.0,
        )],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "password-length",
        title: "Passwords are long enough",
        description: "The minimum password length the organization enforces (never below 12, the deployment\u{2019}s floor), or passwords are not allowed at all.",
        params: &[p("minimum", "Required minimum length", 12.0, 8.0, 64.0)],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "session-lifetime",
        title: "Sessions end",
        description: "Sessions end within a maximum lifetime and after a period of inactivity.",
        params: &[
            p("maxHours", "Longest session", 24.0 * 7.0, 1.0, 24.0 * 30.0),
            p(
                "idleMinutes",
                "Longest inactivity before sign-out",
                24.0 * 60.0,
                5.0,
                24.0 * 60.0 * 7.0,
            ),
        ],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "inactive-accounts",
        title: "Inactive accounts are removed",
        description: "Active people who have not signed in for a while (their access should be reviewed or removed).",
        params: &[p("days", "Days without a sign-in", 90.0, 7.0, 730.0)],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "leaver-access",
        title: "Leavers lose access",
        description: "Disabled or expired accounts hold no live sessions, API keys, role bindings or group memberships.",
        params: &[],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "stale-api-keys",
        title: "Unused API keys are revoked",
        description: "Live API keys (service accounts and agents) that have not been used for a while.",
        params: &[p("days", "Days without use", 90.0, 7.0, 730.0)],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "api-key-lifetime",
        title: "API keys expire",
        description: "Live API keys whose lifetime exceeds the maximum.",
        params: &[p("maxDays", "Longest API key lifetime", 365.0, 1.0, 3650.0)],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "access-reviews",
        title: "Access is reviewed periodically",
        description: "Within the interval, closed certification campaigns in which reviewers decided most items covered the roles people hold; no campaign is overdue. Campaigns closed with few human decisions do not count.",
        params: &[
            p(
                "intervalDays",
                "Longest time between completed reviews",
                90.0,
                7.0,
                730.0,
            ),
            p(
                "minDecidedPercent",
                "Share of a campaign\u{2019}s items a reviewer must decide for it to count",
                80.0,
                50.0,
                100.0,
            ),
            p(
                "minCoveragePercent",
                "Share of the roles held today that counted reviews must have covered",
                100.0,
                50.0,
                100.0,
            ),
        ],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "privileged-access",
        title: "Few people hold full administration",
        description: "Everyone who can administer the organization \u{2014} owners, root administrators, holders of admin roles (also through inherited roles, activated or approval-free eligible bindings) and trusts that assume them \u{2014} against a maximum.",
        params: &[p(
            "maxHolders",
            "Most people with full administration",
            5.0,
            1.0,
            1000.0,
        )],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "owner-redundancy",
        title: "More than one owner",
        description: "At least two active owners, so losing one account does not lock the organization out.",
        params: &[],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "separation-of-duties",
        title: "Separation of duties holds",
        description: "Nobody holds two roles a separation-of-duties rule keeps apart. Without any rule the check warns.",
        params: &[],
        no_exceptions: false,
    },
    ComplianceCheck {
        id: "audit-integrity",
        title: "The audit log is intact",
        description: "The audit hash chain verifies: no event was changed, removed or inserted. Each evaluation continues from where the last one stopped (up to 100,000 events per run) and checks the newest event against the chain head; pruned prefixes must match their audit:prune record.",
        params: &[],
        no_exceptions: true,
    },
    ComplianceCheck {
        id: "privacy-deadlines",
        title: "Data-subject requests are answered on time",
        description: "No privacy request (access, erasure, ...) is past its statutory deadline.",
        params: &[],
        no_exceptions: false,
    },
];

/// The built-in checks (`complianceChecks`).
pub fn compliance_checks() -> &'static [ComplianceCheck] {
    &COMPLIANCE_CHECKS
}

/// `checkById.get(id)`.
pub fn check_by_id(id: &str) -> Option<&'static ComplianceCheck> {
    COMPLIANCE_CHECKS.iter().find(|check| check.id == id)
}

/// `check.evaluate(ctx, store, tenant, params, now)`: `store` is read outside any transaction.
pub async fn evaluate_check(
    check: &ComplianceCheck,
    ctx: &Arc<ServerContext>,
    store: &Store,
    tenant: &Tenant,
    params: &IndexMap<String, f64>,
    now: f64,
) -> IamResult<CheckOutcome> {
    match check.id {
        "mfa-enforced" => Ok(mfa_enforced(tenant)),
        "mfa-coverage" => mfa_coverage(ctx, store, tenant, params).await,
        "password-length" => Ok(password_length(tenant, params)),
        "session-lifetime" => Ok(session_lifetime(ctx, tenant, params)),
        "inactive-accounts" => inactive_accounts(ctx, store, tenant, params, now).await,
        "leaver-access" => leaver_access(ctx, store, tenant, now).await,
        "stale-api-keys" => stale_api_keys(store, tenant, params, now).await,
        "api-key-lifetime" => api_key_lifetime(store, tenant, params, now).await,
        "access-reviews" => access_reviews(store, tenant, params, now).await,
        "privileged-access" => privileged_access(ctx, store, tenant, params, now).await,
        "owner-redundancy" => owner_redundancy(ctx, store, tenant).await,
        "separation-of-duties" => separation_of_duties(ctx, store, tenant).await,
        "audit-integrity" => audit_integrity(store, tenant).await,
        "privacy-deadlines" => privacy_deadlines(store, tenant, now).await,
        other => Err(IamError::new(
            "INVALID_INPUT",
            format!("Unknown check {other}"),
        )),
    }
}

fn mfa_enforced(tenant: &Tenant) -> CheckOutcome {
    let policy = tenant.auth_policy.as_ref();
    let require_mfa = policy
        .and_then(|policy| policy.require_mfa)
        .unwrap_or(false);
    let owners_only = policy
        .and_then(|policy| policy.require_mfa_for_owners)
        .unwrap_or(false);
    let findings = if require_mfa {
        vec![]
    } else if owners_only {
        vec![CheckFinding::new(
            format!("tenant:{}:mfa-owners-only", tenant.id),
            "Only owners must use a second factor",
        )]
    } else {
        vec![CheckFinding::new(
            format!("tenant:{}:mfa-optional", tenant.id),
            "The sign-in policy does not require a second factor",
        )]
    };
    CheckOutcome {
        findings,
        metrics: vec![("required", if require_mfa { 1.0 } else { 0.0 })],
        judge: Box::new(move |remaining| {
            if remaining.is_empty() {
                Judgement::new(
                    "pass",
                    if require_mfa {
                        "Everyone must use a second factor"
                    } else {
                        "Accepted by exception"
                    },
                )
            } else if owners_only {
                Judgement::new("warn", "Only owners must use a second factor")
            } else {
                Judgement::new("fail", "A second factor is optional")
            }
        }),
        checkpoint: None,
    }
}

async fn mfa_coverage(
    ctx: &ServerContext,
    store: &Store,
    tenant: &Tenant,
    params: &IndexMap<String, f64>,
) -> IamResult<CheckOutcome> {
    let list = people(ctx, store, &tenant.id).await?;
    // Passkeys satisfy MFA only when the deployment enables them (auth base.ts passkeyFactor).
    let passkeys_enabled = ctx
        .options
        .authentication
        .as_ref()
        .is_some_and(|auth| auth.passkeys.is_some());
    let with_passkeys: IndexSet<String> = if passkeys_enabled {
        find(store, "authPasskeys", by_tenant(&tenant.id))
            .await?
            .iter()
            .map(|passkey| crate::js::js_string(passkey.get("identityId")))
            .collect()
    } else {
        IndexSet::new()
    };
    let mut findings = Vec::new();
    for person in &list {
        let person_id = text_of(person, "id").unwrap_or_default();
        let mfa = store.get("authMfa", person_id).await?;
        let enabled = mfa.as_ref().is_some_and(|mfa| truthy(mfa, "enabled"));
        if !enabled && !with_passkeys.contains(person_id) {
            findings.push(CheckFinding::new(
                format!("identity:{person_id}"),
                "Has no second factor",
            ));
        }
    }
    let total = list.len();
    let minimum = param(params, "minimumPercent");
    Ok(CheckOutcome {
        metrics: vec![
            ("people", total as f64),
            ("enrolled", (total - findings.len()) as f64),
        ],
        findings,
        judge: Box::new(move |remaining| {
            let percent = if total > 0 {
                (((total - remaining.len()) as f64 / total as f64) * 100.0).floor()
            } else {
                100.0
            };
            if percent >= minimum {
                Judgement::new(
                    "pass",
                    format!("{}% of people have a second factor", n(percent)),
                )
            } else {
                Judgement::new(
                    "fail",
                    format!(
                        "{}% of people have a second factor (at least {}% required)",
                        n(percent),
                        n(minimum)
                    ),
                )
            }
        }),
        checkpoint: None,
    })
}

fn password_length(tenant: &Tenant, params: &IndexMap<String, f64>) -> CheckOutcome {
    let policy = tenant.auth_policy.as_ref();
    let passwordless = policy
        .and_then(|policy| policy.allowed_methods.as_ref())
        .is_some_and(|methods| {
            !methods.iter().any(|method| {
                serde_json::to_value(method)
                    .ok()
                    .as_ref()
                    .and_then(Value::as_str)
                    == Some("password")
            })
        });
    let length = policy
        .and_then(|policy| policy.min_password_length)
        .unwrap_or(12.0)
        .max(12.0);
    let minimum = param(params, "minimum");
    let ok = passwordless || length >= minimum;
    CheckOutcome {
        findings: if ok {
            vec![]
        } else {
            vec![CheckFinding::new(
                format!("tenant:{}:password-length-{}", tenant.id, n(length)),
                format!("Passwords may be {} characters long", n(length)),
            )]
        },
        metrics: vec![
            ("minimumLength", length),
            ("passwordless", if passwordless { 1.0 } else { 0.0 }),
        ],
        judge: Box::new(move |remaining| {
            if remaining.is_empty() {
                Judgement::new(
                    "pass",
                    if passwordless {
                        "Passwords are not used".to_owned()
                    } else if ok {
                        format!("Passwords need {} characters", n(length))
                    } else {
                        "Accepted by exception".to_owned()
                    },
                )
            } else {
                Judgement::new(
                    "fail",
                    format!(
                        "Passwords need only {} characters ({} required)",
                        n(length),
                        n(minimum)
                    ),
                )
            }
        }),
        checkpoint: None,
    }
}

fn session_lifetime(
    ctx: &ServerContext,
    tenant: &Tenant,
    params: &IndexMap<String, f64>,
) -> CheckOutcome {
    let auth = ctx.options.authentication.as_ref();
    let policy = tenant.auth_policy.as_ref();
    let lifetime = auth
        .and_then(|auth| auth.session_lifetime_ms)
        .unwrap_or(7.0 * 24.0 * HOUR_MS)
        .min(
            policy
                .and_then(|policy| policy.session_lifetime_ms)
                .unwrap_or(f64::INFINITY),
        );
    let idle = auth
        .and_then(|auth| auth.session_idle_timeout_ms)
        .unwrap_or_else(|| lifetime.min(24.0 * HOUR_MS))
        .min(
            policy
                .and_then(|policy| policy.session_idle_timeout_ms)
                .unwrap_or(f64::INFINITY),
        );
    let hours = js_round(lifetime / HOUR_MS);
    let minutes = js_round(idle / 60_000.0);
    let mut findings = Vec::new();
    if lifetime > param(params, "maxHours") * HOUR_MS {
        findings.push(CheckFinding::new(
            format!("tenant:{}:lifetime-{}h", tenant.id, n(hours)),
            format!("Sessions last {} hours", n(hours)),
        ));
    }
    if idle > param(params, "idleMinutes") * 60_000.0 {
        findings.push(CheckFinding::new(
            format!("tenant:{}:idle-{}m", tenant.id, n(minutes)),
            format!("Idle sessions last {} minutes", n(minutes)),
        ));
    }
    CheckOutcome {
        findings,
        metrics: vec![("lifetimeHours", hours), ("idleMinutes", minutes)],
        judge: count_judge("session limit", "Sessions end on time".to_owned()),
        checkpoint: None,
    }
}

async fn inactive_accounts(
    ctx: &ServerContext,
    store: &Store,
    tenant: &Tenant,
    params: &IndexMap<String, f64>,
    now: f64,
) -> IamResult<CheckOutcome> {
    let days = param(params, "days");
    let cutoff = now - days * DAY_MS;
    let mut findings = Vec::new();
    for person in people(ctx, store, &tenant.id).await? {
        if num(&person, "createdAt").is_some_and(|created| created > cutoff) {
            continue;
        }
        let person_id = text_of(&person, "id").unwrap_or_default();
        let record = store.get("authSignIns", person_id).await?;
        let last = record.as_ref().and_then(|record| num(record, "lastAt"));
        if last.is_none_or(|last| last < cutoff) {
            findings.push(CheckFinding::new(
                format!("identity:{person_id}"),
                match last {
                    Some(last) if last != 0.0 => {
                        format!("Last signed in {} days ago", floor((now - last) / DAY_MS))
                    }
                    _ => "Has never signed in".to_owned(),
                },
            ));
        }
    }
    Ok(CheckOutcome {
        metrics: vec![("inactive", findings.len() as f64)],
        findings,
        judge: count_judge(
            "inactive account",
            format!("Everyone signed in within {} days", n(days)),
        ),
        checkpoint: None,
    })
}

async fn leaver_access(
    ctx: &ServerContext,
    store: &Store,
    tenant: &Tenant,
    now: f64,
) -> IamResult<CheckOutcome> {
    let mut findings = Vec::new();
    for identity in find(store, "identities", by_tenant(&tenant.id)).await? {
        let status = text_of(&identity, "status");
        let leaving = status == Some("disabled")
            || (status == Some("active") && identity_expired(ctx, &identity));
        if !leaving {
            continue;
        }
        let identity_id = text_of(&identity, "id").unwrap_or_default();
        let sessions = find(
            store,
            "sessions",
            by_tenant(&tenant.id).eq("identityId", identity_id),
        )
        .await?
        .iter()
        .filter(|session| num(session, "expiresAt").is_some_and(|expires| expires > now))
        .count();
        let bindings = find(
            store,
            "bindings",
            by_tenant(&tenant.id)
                .eq("subjectType", "identity")
                .eq("subjectId", identity_id),
        )
        .await?
        .iter()
        .filter(|binding| live(binding, "expiresAt", now))
        .count();
        let groups = find(
            store,
            "groupMembers",
            by_tenant(&tenant.id).eq("identityId", identity_id),
        )
        .await?
        .iter()
        .filter(|member| live(member, "expiresAt", now))
        .count();
        if sessions > 0 || bindings > 0 || groups > 0 {
            let held: Vec<String> = [
                (sessions, "session"),
                (bindings, "role binding"),
                (groups, "group membership"),
            ]
            .into_iter()
            .filter(|(count, _)| *count > 0)
            .map(|(count, word)| plural(count, word))
            .collect();
            findings.push(CheckFinding::new(
                format!("identity:{identity_id}"),
                format!(
                    "{} but still holds {}",
                    if status == Some("disabled") {
                        "Disabled"
                    } else {
                        "Expired"
                    },
                    held.join(", ")
                ),
            ));
        }
    }
    Ok(CheckOutcome {
        metrics: vec![("leaversWithAccess", findings.len() as f64)],
        findings,
        judge: count_judge(
            "leaver with access",
            "Disabled and expired accounts hold no access".to_owned(),
        ),
        checkpoint: None,
    })
}

/// `session.name ? `Key "${session.name}"` : 'An API key'`.
fn key_label(session: &Record) -> String {
    if truthy(session, "name") {
        format!("Key \"{}\"", crate::js::js_string(session.get("name")))
    } else {
        "An API key".to_owned()
    }
}

async fn api_keys(store: &Store, tenant: &Tenant) -> IamResult<Vec<Record>> {
    find(
        store,
        "sessions",
        by_tenant(&tenant.id).eq("kind", "api-key"),
    )
    .await
}

async fn stale_api_keys(
    store: &Store,
    tenant: &Tenant,
    params: &IndexMap<String, f64>,
    now: f64,
) -> IamResult<CheckOutcome> {
    let days = param(params, "days");
    let cutoff = now - days * DAY_MS;
    let mut findings = Vec::new();
    for session in api_keys(store, tenant).await? {
        if num(&session, "expiresAt").is_some_and(|expires| expires <= now) {
            continue;
        }
        let last = match session.get("lastSeenAt") {
            Some(value) if !value.is_null() => core_js::as_number(value),
            _ => num(&session, "createdAt"),
        };
        if let Some(last) = last
            && last < cutoff
        {
            findings.push(CheckFinding::new(
                format!("session:{}", text_of(&session, "id").unwrap_or_default()),
                format!(
                    "{} unused for {} days",
                    key_label(&session),
                    floor((now - last) / DAY_MS)
                ),
            ));
        }
    }
    Ok(CheckOutcome {
        metrics: vec![("staleKeys", findings.len() as f64)],
        findings,
        judge: count_judge(
            "unused API key",
            format!("Every API key was used within {} days", n(days)),
        ),
        checkpoint: None,
    })
}

async fn api_key_lifetime(
    store: &Store,
    tenant: &Tenant,
    params: &IndexMap<String, f64>,
    now: f64,
) -> IamResult<CheckOutcome> {
    let max_days = param(params, "maxDays");
    let mut findings = Vec::new();
    for session in api_keys(store, tenant).await? {
        if num(&session, "expiresAt").is_some_and(|expires| expires <= now) {
            continue;
        }
        let days = ((num(&session, "expiresAt").unwrap_or(f64::NAN)
            - num(&session, "createdAt").unwrap_or(f64::NAN))
            / DAY_MS)
            .floor();
        if days > max_days {
            findings.push(CheckFinding::new(
                format!("session:{}", text_of(&session, "id").unwrap_or_default()),
                format!("{} lives {} days", key_label(&session), n(days)),
            ));
        }
    }
    Ok(CheckOutcome {
        metrics: vec![("longLivedKeys", findings.len() as f64)],
        findings,
        judge: count_judge(
            "long-lived API key",
            format!("Every API key expires within {} days", n(max_days)),
        ),
        checkpoint: None,
    })
}

async fn access_reviews(
    store: &Store,
    tenant: &Tenant,
    params: &IndexMap<String, f64>,
    now: f64,
) -> IamResult<CheckOutcome> {
    let interval_days = param(params, "intervalDays");
    let min_decided = param(params, "minDecidedPercent");
    let min_coverage = param(params, "minCoveragePercent");
    let since = now - interval_days * DAY_MS;
    let campaigns = find(store, "certificationCampaigns", by_tenant(&tenant.id)).await?;
    let mut findings = Vec::new();
    // Roles covered by campaigns that count: closed within the interval, not empty, mostly decided by people.
    let mut covered: IndexSet<String> = IndexSet::new();
    let mut qualifying = 0usize;
    let mut latest_qualifying = 0.0f64;
    let mut latest_closed = 0.0f64;
    let mut last_decided_percent = -1.0f64;
    for campaign in &campaigns {
        let closed_at = num(campaign, "closedAt");
        let Some(closed_at) = closed_at.filter(|_| text_of(campaign, "status") == Some("closed"))
        else {
            continue;
        };
        if closed_at < since {
            continue;
        }
        let items = find(
            store,
            "certificationItems",
            by_tenant(&tenant.id).eq("campaignId", text_of(campaign, "id").unwrap_or_default()),
        )
        .await?;
        let decided = items
            .iter()
            .filter(|item| item.get("decidedBy").is_some())
            .count();
        let percent = if items.is_empty() {
            0.0
        } else {
            ((decided as f64 / items.len() as f64) * 100.0).floor()
        };
        if closed_at >= latest_closed {
            latest_closed = closed_at;
            last_decided_percent = percent;
        }
        if items.is_empty() || percent < min_decided {
            continue;
        }
        qualifying += 1;
        latest_qualifying = latest_qualifying.max(closed_at);
        for item in &items {
            covered.insert(crate::js::js_string(item.get("roleId")));
        }
    }
    if qualifying == 0 {
        findings.push(CheckFinding::new(
            format!("tenant:{}:no-review", tenant.id),
            format!(
                "No review closed in the last {} days with at least {}% of its items decided by a reviewer",
                n(interval_days),
                n(min_decided)
            ),
        ));
    }
    // Roles held today (live bindings to unprotected roles); owners are the owner-redundancy and privileged checks'.
    let roles: IndexMap<String, Record> = find(store, "roles", by_tenant(&tenant.id))
        .await?
        .into_iter()
        .filter(|role| !truthy(role, "protected"))
        .map(|role| (text_of(&role, "id").unwrap_or_default().to_owned(), role))
        .collect();
    let mut held: IndexSet<String> = IndexSet::new();
    for binding in find(store, "bindings", by_tenant(&tenant.id)).await? {
        if let Some(role_id) = text_of(&binding, "roleId")
            && roles.contains_key(role_id)
            && live(&binding, "expiresAt", now)
        {
            held.insert(role_id.to_owned());
        }
    }
    let mut uncovered: Vec<String> = held
        .iter()
        .filter(|role_id| !covered.contains(*role_id))
        .cloned()
        .collect();
    uncovered.sort_by(|a, b| cmp_utf16(a, b));
    if qualifying > 0 {
        for role_id in &uncovered {
            findings.push(CheckFinding::new(
                format!("role:{role_id}"),
                format!(
                    "Role \"{}\" is held but no counted review covered it",
                    crate::js::js_string(roles.get(role_id).and_then(|role| role.get("name")))
                ),
            ));
        }
    }
    for campaign in &campaigns {
        if text_of(campaign, "status") == Some("open")
            && let Some(due_at) = num(campaign, "dueAt")
            && due_at < now
        {
            findings.push(CheckFinding::new(
                format!("campaign:{}", text_of(campaign, "id").unwrap_or_default()),
                format!(
                    "Review \"{}\" is {} days overdue",
                    crate::js::js_string(campaign.get("name")),
                    floor((now - due_at) / DAY_MS)
                ),
            ));
        }
    }
    let held_count = held.len();
    let coverage = if held_count > 0 {
        (((held_count - uncovered.len()) as f64 / held_count as f64) * 100.0).floor()
    } else {
        100.0
    };
    Ok(CheckOutcome {
        findings,
        metrics: vec![
            ("campaigns", campaigns.len() as f64),
            ("qualifying", qualifying as f64),
            ("rolesHeld", held_count as f64),
            ("coveragePercent", coverage),
            ("lastDecidedPercent", last_decided_percent),
            (
                "lastClosedDaysAgo",
                if latest_qualifying != 0.0 {
                    ((now - latest_qualifying) / DAY_MS).floor()
                } else {
                    -1.0
                },
            ),
        ],
        judge: Box::new(move |remaining| {
            let no_review = remaining
                .iter()
                .any(|finding| finding.subject.ends_with(":no-review"));
            let overdue = remaining
                .iter()
                .filter(|finding| finding.subject.starts_with("campaign:"))
                .count();
            let missing = remaining
                .iter()
                .filter(|finding| finding.subject.starts_with("role:"))
                .count();
            let percent = if held_count > 0 {
                ((held_count as f64 - missing as f64) / held_count as f64 * 100.0).floor()
            } else {
                100.0
            };
            if no_review {
                return Judgement::new("fail", "No counted review within the interval");
            }
            if percent < min_coverage {
                return Judgement::new(
                    "fail",
                    format!(
                        "Reviews covered {}% of the roles held ({}% required)",
                        n(percent),
                        n(min_coverage)
                    ),
                );
            }
            if overdue > 0 {
                return Judgement::new("fail", format!("{} overdue", plural(overdue, "review")));
            }
            Judgement::new(
                "pass",
                format!(
                    "Access was reviewed within {} days ({}% of roles)",
                    n(interval_days),
                    n(percent)
                ),
            )
        }),
        checkpoint: None,
    })
}

async fn privileged_access(
    ctx: &ServerContext,
    store: &Store,
    tenant: &Tenant,
    params: &IndexMap<String, f64>,
    now: f64,
) -> IamResult<CheckOutcome> {
    let (holders, eligible_with_approval) = privileged_holders(ctx, store, &tenant.id, now).await?;
    let max_holders = param(params, "maxHolders");
    let findings: Vec<CheckFinding> = holders
        .iter()
        .map(|(subject, via)| {
            CheckFinding::new(
                subject.clone(),
                format!("Holds full administration ({via})"),
            )
        })
        .collect();
    Ok(CheckOutcome {
        findings,
        metrics: vec![
            ("holders", holders.len() as f64),
            ("eligibleWithApproval", eligible_with_approval as f64),
        ],
        judge: Box::new(move |remaining| {
            if remaining.len() as f64 <= max_holders {
                Judgement::new(
                    "pass",
                    format!(
                        "{} of full administration",
                        plural(remaining.len(), "holder")
                    ),
                )
            } else {
                Judgement::new(
                    "fail",
                    format!(
                        "{} of full administration (at most {})",
                        plural(remaining.len(), "holder"),
                        n(max_holders)
                    ),
                )
            }
        }),
        checkpoint: None,
    })
}

async fn owner_redundancy(
    ctx: &ServerContext,
    store: &Store,
    tenant: &Tenant,
) -> IamResult<CheckOutcome> {
    let owners = people(ctx, store, &tenant.id)
        .await?
        .iter()
        .filter(|identity| truthy(identity, "owner"))
        .count();
    Ok(CheckOutcome {
        findings: if owners >= 2 {
            vec![]
        } else {
            vec![CheckFinding::new(
                format!("tenant:{}:owners-{owners}", tenant.id),
                plural(owners, "active owner"),
            )]
        },
        metrics: vec![("owners", owners as f64)],
        judge: Box::new(move |remaining| {
            if remaining.is_empty() {
                Judgement::new(
                    "pass",
                    if owners >= 2 {
                        format!("{owners} owners")
                    } else {
                        "Accepted by exception".to_owned()
                    },
                )
            } else {
                Judgement::new(
                    if owners > 0 { "warn" } else { "fail" },
                    if owners > 0 {
                        "Only one owner"
                    } else {
                        "No active owner"
                    },
                )
            }
        }),
        checkpoint: None,
    })
}

async fn separation_of_duties(
    ctx: &Arc<ServerContext>,
    store: &Store,
    tenant: &Tenant,
) -> IamResult<CheckOutcome> {
    let rules = find(store, "sodRules", by_tenant(&tenant.id)).await?;
    if rules.is_empty() {
        return Ok(CheckOutcome {
            findings: vec![],
            metrics: vec![("rules", 0.0)],
            // Frameworks that map here (ISO 5.3, NIST AC-5) expect duties to be separated: no rule is not a pass.
            judge: Box::new(|_| {
                Judgement::new("warn", "No separation-of-duties rules are defined")
            }),
            checkpoint: None,
        });
    }
    let violations = sod_violations(ctx, store, &tenant.id, None, None).await?;
    Ok(CheckOutcome {
        findings: violations
            .iter()
            .map(|violation| {
                CheckFinding::new(
                    format!(
                        "identity:{}:rule:{}",
                        crate::js::js_string(violation.get("identityId")),
                        crate::js::js_string(violation.get("ruleId"))
                    ),
                    format!(
                        "Breaks rule \"{}\"",
                        crate::js::js_string(violation.get("ruleName"))
                    ),
                )
            })
            .collect(),
        metrics: vec![
            ("rules", rules.len() as f64),
            ("violations", violations.len() as f64),
        ],
        judge: count_judge(
            "separation-of-duties violation",
            "No separation-of-duties violations".to_owned(),
        ),
        checkpoint: None,
    })
}

/// `a === b` of two optional JSON values (`undefined === undefined`).
fn same(a: Option<&Value>, b: Option<&Value>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => core_js::strict_equal(a, b),
        _ => false,
    }
}

async fn audit_integrity(store: &Store, tenant: &Tenant) -> IamResult<CheckOutcome> {
    let head = store.get("auditChains", &tenant.id).await?;
    let saved = store
        .get("complianceCheckpoints", &checkpoint_id(&tenant.id))
        .await?;
    let mut sequence = saved
        .as_ref()
        .and_then(|saved| num(saved, "sequence"))
        .unwrap_or(0.0);
    let mut hash: Option<String> = saved
        .as_ref()
        .and_then(|saved| text_of(saved, "hash"))
        .map(str::to_owned);
    let mut checked = 0.0f64;
    let mut failure: Option<String> = None;
    let mut partial = false;
    let head_sequence = head.as_ref().and_then(|head| num(head, "sequence"));
    let target = head_sequence.unwrap_or(0.0);
    while failure.is_none() && sequence < target {
        if checked >= AUDIT_PAGE_SIZE * AUDIT_PAGES {
            partial = true;
            break;
        }
        let events = find_ordered(
            store.as_ref(),
            "audit",
            &by_tenant(&tenant.id),
            &OrderOptions {
                from: Some(sequence + 1.0),
                to: Some(target),
                limit: Some(AUDIT_PAGE_SIZE as i64),
                ..OrderOptions::by("sequence")
            },
            None,
        )
        .await?;
        let Some(first) = events.first() else {
            failure = Some(format!(
                "Events {} to {} are missing",
                n(sequence + 1.0),
                n(target)
            ));
            break;
        };
        let first_sequence = num(first, "sequence");
        let mut previous_hash = hash.clone();
        if first_sequence != Some(sequence + 1.0) {
            // A gap is only acceptable as a pruned prefix, which audit:prune recorded with the hash it ended on.
            let through = first_sequence.unwrap_or(f64::NAN) - 1.0;
            let pruned = find(
                store,
                "audit",
                by_tenant(&tenant.id).eq("action", "audit:prune"),
            )
            .await?
            .iter()
            .any(|event| {
                let metadata = event.get("metadata");
                metadata
                    .and_then(|metadata| metadata.get("prunedThroughSequence"))
                    .and_then(core_js::as_number)
                    == Some(through)
                    && same(
                        metadata.and_then(|metadata| metadata.get("prunedThroughHash")),
                        first.get("previousHash"),
                    )
            });
            if !pruned {
                failure = Some(format!(
                    "Events {} to {} are missing",
                    n(sequence + 1.0),
                    n(through)
                ));
                break;
            }
            previous_hash = first
                .get("previousHash")
                .and_then(Value::as_str)
                .map(str::to_owned);
        }
        let verification = verify_audit_chain(
            &events,
            &VerifyAuditChainOptions {
                previous_hash,
                head: None,
            },
        );
        if !verification.valid {
            let (at, reason) = match &verification.failure {
                Some(detail) => (
                    n(detail.sequence),
                    serde_json::to_value(detail.reason)
                        .ok()
                        .and_then(|value| value.as_str().map(str::to_owned))
                        .unwrap_or_else(|| "unknown".to_owned()),
                ),
                None => ("?".to_owned(), "unknown".to_owned()),
            };
            failure = Some(format!("The chain breaks at sequence {at} ({reason})"));
            break;
        }
        checked += verification.checked as f64;
        sequence = verification.last.unwrap_or(f64::NAN);
        hash = verification.last_hash.clone();
    }
    if failure.is_none()
        && !partial
        && let Some(head) = &head
        && (Some(sequence) != head_sequence || hash.as_deref() != text_of(head, "hash"))
    {
        failure = Some("The newest event does not match the chain head".to_owned());
    }
    let checkpoint = match (&failure, &hash) {
        (None, Some(hash)) if sequence > 0.0 => Some((sequence, hash.clone())),
        _ => None,
    };
    let findings = match &failure {
        Some(detail) => vec![CheckFinding::new(
            format!("tenant:{}:audit-chain", tenant.id),
            detail.clone(),
        )],
        None => vec![],
    };
    Ok(CheckOutcome {
        findings,
        metrics: vec![
            ("checked", checked),
            ("verifiedThrough", sequence),
            ("head", target),
        ],
        checkpoint,
        judge: Box::new(move |remaining| {
            if !remaining.is_empty() {
                Judgement::new("fail", failure.clone().unwrap_or_default())
            } else if partial {
                Judgement::new(
                    "warn",
                    format!(
                        "Verified through event {} of {}; the next run continues",
                        n(sequence),
                        n(target)
                    ),
                )
            } else {
                Judgement::new(
                    "pass",
                    format!("The audit chain verifies through event {}", n(sequence)),
                )
            }
        }),
    })
}

async fn privacy_deadlines(store: &Store, tenant: &Tenant, now: f64) -> IamResult<CheckOutcome> {
    let requests = find(store, "privacyRequests", by_tenant(&tenant.id)).await?;
    let mut overdue = Vec::new();
    for request in &requests {
        let typed: SubjectRequest = crate::port::decode(request.clone())?;
        if request_overdue(&typed, now)? {
            overdue.push(request);
        }
    }
    Ok(CheckOutcome {
        findings: overdue
            .iter()
            .map(|request| {
                CheckFinding::new(
                    format!("request:{}", text_of(request, "id").unwrap_or_default()),
                    format!(
                        "{} ({}) was due {} days ago",
                        crate::js::js_string(request.get("number")),
                        crate::js::js_string(request.get("type")),
                        floor((now - num(request, "dueAt").unwrap_or(f64::NAN)) / DAY_MS)
                    ),
                )
            })
            .collect(),
        metrics: vec![
            ("requests", requests.len() as f64),
            ("overdue", overdue.len() as f64),
        ],
        judge: count_judge(
            "overdue request",
            "No data-subject request is overdue".to_owned(),
        ),
        checkpoint: None,
    })
}

/// `frameworkById.get(id)`: a framework of [`COMPLIANCE_FRAMEWORKS`].
pub fn framework_by_id(id: &str) -> Option<&'static Value> {
    COMPLIANCE_FRAMEWORKS
        .as_array()
        .expect("the frameworks are a list")
        .iter()
        .find(|framework| framework.get("id").and_then(Value::as_str) == Some(id))
}

/// Validates check parameters, filling defaults.
pub fn check_params(
    check: &ComplianceCheck,
    value: Option<&Value>,
) -> IamResult<IndexMap<String, f64>> {
    let empty = Map::new();
    let input = match value {
        None | Some(Value::Null) => &empty,
        Some(Value::Object(map)) => map,
        Some(_) => {
            return Err(IamError::new("INVALID_INPUT", "params must be an object"));
        }
    };
    for key in crate::js::keys(input) {
        if !check.params.iter().any(|param| param.name == key) {
            return Err(IamError::new(
                "INVALID_INPUT",
                format!("{} has no parameter {key}", check.id),
            ));
        }
    }
    let mut result = IndexMap::new();
    for param in check.params {
        let value = input.get(param.name);
        result.insert(
            param.name.to_owned(),
            match value {
                None => param.default,
                Some(value) => integer(
                    Some(value),
                    &format!("params.{}", param.name),
                    param.min,
                    param.max,
                )?,
            },
        );
    }
    Ok(result)
}

/// [`check_params`] as the JSON object stored on a control.
pub fn params_json(params: &IndexMap<String, f64>) -> Map<String, Value> {
    params
        .iter()
        .map(|(name, value)| (name.clone(), crate::js::number(*value)))
        .collect()
}

/// Stored parameters brought within the check's current bounds (bounds tighten over releases). `stored` is the raw
/// `params` member of the control; reading a member of `undefined` or `null` throws as in JavaScript.
pub fn effective_params(
    check: &ComplianceCheck,
    stored: Option<&Value>,
) -> IamResult<IndexMap<String, f64>> {
    let mut result = IndexMap::new();
    for param in check.params {
        let value = match stored {
            None | Some(Value::Null) => {
                return Err(IamError::with_status(
                    "INTERNAL_ERROR",
                    format!(
                        "Cannot read properties of {} (reading '{}')",
                        if stored.is_none() {
                            "undefined"
                        } else {
                            "null"
                        },
                        param.name
                    ),
                    500,
                ));
            }
            Some(Value::Object(map)) => map.get(param.name).and_then(|value| match value {
                Value::Number(number) => Some(core_js::number_value(number)),
                _ => None,
            }),
            Some(_) => None,
        };
        result.insert(
            param.name.to_owned(),
            match value {
                Some(value) if value.is_finite() => param.min.max(value.trunc()).min(param.max),
                _ => param.default,
            },
        );
    }
    Ok(result)
}

/// Whether an exception covers findings now.
pub fn exception_active(exception: &Record, now: f64) -> bool {
    let status = exception.get("status");
    (status.is_none() || status.and_then(Value::as_str) == Some("approved"))
        && num(exception, "expiresAt").is_some_and(|expires| expires > now)
}

/// `checkpointId(tenantId)`: the `complianceCheckpoints` ID of a tenant.
pub fn checkpoint_id(tenant_id: &str) -> String {
    format!("audit:{tenant_id}")
}

/// Shared with the API: the frameworks as a lazily built list.
pub fn compliance_frameworks() -> &'static [Value] {
    static LIST: LazyLock<Vec<Value>> = LazyLock::new(|| {
        COMPLIANCE_FRAMEWORKS
            .as_array()
            .cloned()
            .unwrap_or_default()
    });
    &LIST
}
