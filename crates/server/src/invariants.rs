//! Port of `packages/server/src/invariants.ts`: access invariants (guardrails), their evaluation, the scheduled
//! check, and the enforcement around access-changing operations.

use std::sync::Arc;

use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStoreExt, Identity, IdentityStatus, Record,
    ResourceRef, Tenant, TenantStatus, js as core_js,
};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::contracts::decide_on;
use crate::metrics::locale_compare;
use crate::models::GroupMember;
use crate::options::ResolvedResource;
use crate::port::decode;
use crate::utils::id;
use crate::validation::text;

/// An access invariant: a statement about who may (or must never) perform an action on a resource, such as "no
/// contractor may delete the payroll workspace" or "on-call engineers can always restart production". `monitor`
/// invariants are reported by `invariants.run`; `enforce` invariants also refuse any access change that would newly
/// break them. Names are unique per tenant (uniqueKey `name:{lowercase}`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessInvariant {
    #[serde(rename = "name")]
    pub name: String,
    #[serde(
        rename = "description",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub description: Option<String>,
    #[serde(rename = "subject")]
    pub subject: crate::invariants::InvariantSubject,
    #[serde(rename = "action")]
    pub action: String,
    /// `{ type, id }`.
    #[serde(rename = "resource")]
    pub resource: Value,
    /// `'allow' | 'deny'`.
    #[serde(rename = "expect")]
    pub expect: String,
    /// `'enforce' | 'monitor'`.
    #[serde(rename = "mode")]
    pub mode: String,
    /// Evaluate subjects as MFA-verified sessions (default true: the most a person can reach).
    #[serde(rename = "assumeMfa")]
    pub assume_mfa: bool,
    #[serde(rename = "createdBy")]
    pub created_by: String,
    #[serde(rename = "createdAt")]
    pub created_at: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    /// The last scheduled check (`iam.checkInvariants`): whether it passed and who violated it.
    #[serde(rename = "lastCheck", default, skip_serializing_if = "Option::is_none")]
    pub last_check: Option<Value>,
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

/// One invariant's evaluation (`InvariantResult`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvariantResult {
    /// `Pick<AccessInvariant, 'id' | 'name' | 'mode' | 'expect' | 'action' | 'resource'>`.
    #[serde(rename = "invariant")]
    pub invariant: Value,
    #[serde(rename = "passed")]
    pub passed: bool,
    #[serde(rename = "evaluated")]
    pub evaluated: f64,
    /// Subjects beyond the evaluation cap (500) were not checked.
    #[serde(rename = "truncated")]
    pub truncated: bool,
    #[serde(rename = "violations")]
    pub violations: Vec<crate::invariants::InvariantViolation>,
    /// Set when the invariant could not be evaluated (its resource or group no longer exists, for example):
    /// `{ code, message }`.
    #[serde(rename = "error", default, skip_serializing_if = "Option::is_none")]
    pub error: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

impl InvariantResult {
    /// The result as the TypeScript object (numbers in JavaScript form).
    pub fn to_json(&self) -> Value {
        let mut out = Map::new();
        out.insert("invariant".into(), self.invariant.clone());
        out.insert("passed".into(), Value::Bool(self.passed));
        out.insert("evaluated".into(), crate::js::number(self.evaluated));
        out.insert("truncated".into(), Value::Bool(self.truncated));
        out.insert(
            "violations".into(),
            Value::Array(
                self.violations
                    .iter()
                    .map(|violation| {
                        json!({ "identity": violation.identity, "reason": violation.reason })
                    })
                    .collect(),
            ),
        );
        if let Some(error) = &self.error {
            out.insert("error".into(), error.clone());
        }
        Value::Object(out)
    }

    fn invariant_member(&self, key: &str) -> Option<&Value> {
        self.invariant.get(key)
    }

    fn error_member(&self, key: &str) -> String {
        self.error
            .as_ref()
            .and_then(|error| error.get(key))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }
}

/// Who an invariant is about: `{ identityId }`, `{ groupId }`, `{ attribute: { name, value } }` or
/// `{ everyone: true }`, as stored.
pub type InvariantSubject = Value;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InvariantViolation {
    /// `{ id, name }`.
    #[serde(rename = "identity")]
    pub identity: Value,
    /// The decision reason: why the action was allowed, or why it was denied.
    #[serde(rename = "reason")]
    pub reason: String,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

const MAX_SUBJECTS: usize = 500;

/// How evaluating one invariant failed: an `IamError` (reported on the result) or any other exception (thrown).
enum Failure {
    Reported(IamError),
    Thrown(IamError),
}

impl From<IamError> for Failure {
    fn from(error: IamError) -> Self {
        Failure::Reported(error)
    }
}

fn find_all() -> FindOptions {
    FindOptions::default()
}

fn live(ctx: &ServerContext, tenant_id: &str, identity: &Identity) -> bool {
    identity.tenant_id == tenant_id
        && identity.status == IdentityStatus::Active
        && !ctx.identity_expired(identity)
}

async fn get_identity(tx: &Store, identity_id: &str) -> IamResult<Option<Identity>> {
    match tx.get("identities", identity_id).await? {
        Some(record) => Ok(Some(decode(record)?)),
        None => Ok(None),
    }
}

async fn subjects(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    subject: &InvariantSubject,
) -> Result<Vec<Identity>, Failure> {
    // `'identityId' in subject` on something that is not an object throws a TypeError.
    let Value::Object(subject) = subject else {
        return Err(Failure::Thrown(crate::js::internal_error()));
    };
    if subject.contains_key("identityId") {
        let identity = match subject.get("identityId").and_then(Value::as_str) {
            Some(identity_id) => get_identity(tx, identity_id).await?,
            None => None,
        };
        let Some(identity) = identity.filter(|identity| identity.tenant_id == tenant_id) else {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "The invariant names an identity that no longer exists",
                404,
            )
            .into());
        };
        return Ok(if live(ctx, tenant_id, &identity) {
            vec![identity]
        } else {
            Vec::new()
        });
    }
    if subject.contains_key("groupId") {
        let group_id = subject.get("groupId").and_then(Value::as_str);
        let group = match group_id {
            Some(group_id) => tx.get("groups", group_id).await?,
            None => None,
        };
        let (Some(group_id), Some(_)) = (
            group_id,
            group.filter(|group| group.get("tenantId").and_then(Value::as_str) == Some(tenant_id)),
        ) else {
            return Err(IamError::with_status(
                "NOT_FOUND",
                "The invariant names a group that no longer exists",
                404,
            )
            .into());
        };
        let mut people = Vec::new();
        for member in tx
            .find(
                "groupMembers",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("groupId", group_id),
                &find_all(),
            )
            .await?
        {
            let member: GroupMember = decode(member)?;
            if !ctx.live_membership(&member) {
                continue;
            }
            if let Some(identity) = get_identity(tx, &member.identity_id).await?
                && live(ctx, tenant_id, &identity)
            {
                people.push(identity);
            }
        }
        return Ok(people);
    }
    let mut everyone = Vec::new();
    for record in tx
        .find(
            "identities",
            &Filter::new().eq("tenantId", tenant_id),
            &find_all(),
        )
        .await?
    {
        let identity: Identity = decode(record)?;
        if live(ctx, tenant_id, &identity) {
            everyone.push(identity);
        }
    }
    if subject.contains_key("everyone") {
        return Ok(everyone);
    }
    // `const { name, value } = subject.attribute` throws a TypeError when the attribute is missing.
    let attribute = match subject.get("attribute") {
        None | Some(Value::Null) => return Err(Failure::Thrown(crate::js::internal_error())),
        Some(attribute) => attribute,
    };
    let name = crate::js::js_string(attribute.get("name"));
    let value = attribute.get("value");
    Ok(everyone
        .into_iter()
        .filter(|identity| {
            match (
                identity
                    .attributes
                    .as_ref()
                    .and_then(|attributes| attributes.get(&name)),
                value,
            ) {
                (Some(held), Some(value)) => core_js::strict_equal(held, value),
                (None, None) => true,
                _ => false,
            }
        })
        .collect())
}

/// The summary of an invariant a result carries.
fn summary(invariant: &AccessInvariant) -> Value {
    json!({
        "id": invariant.id,
        "name": invariant.name,
        "mode": invariant.mode,
        "expect": invariant.expect,
        "action": invariant.action,
        "resource": invariant.resource,
    })
}

async fn evaluate_one(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &Tenant,
    invariant: &AccessInvariant,
    resources: &mut IndexMap<String, ResolvedResource>,
    unlimited: bool,
) -> Result<(Vec<InvariantViolation>, usize, bool), Failure> {
    let resource_type = crate::js::js_string(invariant.resource.get("type"));
    let resource_id = crate::js::js_string(invariant.resource.get("id"));
    let key = format!("{resource_type}/{resource_id}");
    let resource = match resources.get(&key) {
        Some(resource) => resource.clone(),
        None => {
            let reference = ResourceRef {
                tenant_id: tenant.id.clone(),
                kind: text(invariant.resource.get("type"), "resource type", 256)?,
                id: text(invariant.resource.get("id"), "resource id", 256)?,
            };
            let resolved = ctx
                .decisions()?
                .resolve(tx, &reference, true, None, None)
                .await?;
            resources.insert(key, resolved.clone());
            resolved
        }
    };
    let mut people = subjects(ctx, tx, &tenant.id, &invariant.subject).await?;
    people.sort_by(|a, b| locale_compare(&a.id, &b.id));
    let total = people.len();
    let checked: Vec<Identity> = if unlimited {
        people
    } else {
        people.into_iter().take(MAX_SUBJECTS).collect()
    };
    let decisions = ctx.decisions()?;
    let mut violations = Vec::new();
    for identity in &checked {
        let principal = decisions.simulated_principal(identity, invariant.assume_mfa);
        let prepared = decisions
            .prepare_decision(tx, &principal, tenant, &invariant.action)
            .await?;
        let decision = decide_on(&prepared, &resource, Some(&invariant.action))?;
        if decision.allowed != (invariant.expect == "allow") {
            violations.push(InvariantViolation {
                identity: json!({
                    "id": identity.id,
                    "name": identity.email.clone().unwrap_or_else(|| identity.name.clone()),
                }),
                reason: decision.reason,
                extra: Map::new(),
            });
        }
    }
    Ok((violations, checked.len(), total > checked.len()))
}

/// Evaluates invariants against the current state of the transaction. Enforcement (`unlimited`) evaluates every
/// subject; reports stop at 500 subjects per invariant.
pub async fn evaluate_invariants(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant: &Tenant,
    invariants: &[AccessInvariant],
    unlimited: bool,
) -> IamResult<Vec<InvariantResult>> {
    let mut resources: IndexMap<String, ResolvedResource> = IndexMap::new();
    let mut results = Vec::new();
    for invariant in invariants {
        let summary = summary(invariant);
        match evaluate_one(ctx, tx, tenant, invariant, &mut resources, unlimited).await {
            Ok((violations, evaluated, truncated)) => results.push(InvariantResult {
                invariant: summary,
                passed: violations.is_empty(),
                evaluated: evaluated as f64,
                truncated,
                violations,
                error: None,
                extra: Map::new(),
            }),
            Err(Failure::Thrown(error)) => return Err(error),
            Err(Failure::Reported(error)) => results.push(InvariantResult {
                invariant: summary,
                passed: false,
                evaluated: 0.0,
                truncated: false,
                violations: Vec::new(),
                error: Some(json!({ "code": error.code, "message": error.message })),
                extra: Map::new(),
            }),
        }
    }
    Ok(results)
}

/// A system audit event of the invariant check.
fn check_event(
    tenant_id: &str,
    action: &str,
    resource_id: &str,
    now: f64,
    outcome: &str,
    metadata: Value,
) -> Record {
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
    event.insert(
        "actorId".into(),
        Value::String("deployment-operator".into()),
    );
    event.insert("action".into(), Value::String(action.to_owned()));
    event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
    event.insert("timestamp".into(), crate::js::number(now));
    event.insert("outcome".into(), Value::String(outcome.to_owned()));
    event.insert("metadata".into(), metadata);
    event
}

/// The scheduled invariant check: evaluates every invariant of every active tenant (or one `tenantId`), remembers
/// the outcome on the invariant, and records `invariant:broken` when an invariant starts failing or gains violators
/// and `invariant:restored` when it passes again, so monitored invariants reach webhooks and audit exports. A
/// deployment operation: no credential, one transaction per tenant.
pub async fn check_invariants(ctx: &Arc<ServerContext>, input: Option<&Value>) -> IamResult<Value> {
    let empty = Map::new();
    let input = match input {
        None => &empty,
        Some(Value::Object(input)) => input,
        // Reading a member of null throws a TypeError in TypeScript.
        Some(Value::Null) => return Err(crate::js::internal_error()),
        Some(_) => &empty,
    };
    let filter_tenant = input
        .get("tenantId")
        .filter(|tenant| crate::js::truthy(Some(tenant)))
        .cloned();
    let tenant_ids: Vec<String> = ctx
        .store
        .transaction(|tx| async move {
            let filter = match filter_tenant {
                Some(tenant) => Filter::new().eq("tenantId", tenant),
                None => Filter::new(),
            };
            let mut ids: Vec<String> = crate::js::unique(
                tx.find("accessInvariants", &filter, &find_all())
                    .await?
                    .iter()
                    .map(|invariant| {
                        invariant
                            .get("tenantId")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned()
                    }),
            );
            crate::js::sort_strings(&mut ids);
            Ok(ids)
        })
        .await?;
    let mut checked = 0.0;
    let mut broken: Vec<Value> = Vec::new();
    let mut restored: Vec<Value> = Vec::new();
    for tenant_id in tenant_ids {
        let tenant_id = &tenant_id;
        let (count, newly_broken, newly_restored) = ctx
            .store
            .transaction(|tx| async move {
                let mut count = 0.0;
                let mut newly_broken: Vec<Value> = Vec::new();
                let mut newly_restored: Vec<Value> = Vec::new();
                let tenant: Option<Tenant> = match tx.get("tenants", tenant_id).await? {
                    Some(record) => Some(decode(record)?),
                    None => None,
                };
                let Some(tenant) = tenant.filter(|tenant| tenant.status == TenantStatus::Active)
                else {
                    return Ok((count, newly_broken, newly_restored));
                };
                let mut raw = tx
                    .find(
                        "accessInvariants",
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &find_all(),
                    )
                    .await?;
                raw.sort_by(|a, b| {
                    locale_compare(better_iam_core::record_id(a), better_iam_core::record_id(b))
                });
                let invariants = raw
                    .iter()
                    .map(|record| decode::<AccessInvariant>(record.clone()))
                    .collect::<IamResult<Vec<_>>>()?;
                let outcomes = evaluate_invariants(ctx, &tx, &tenant, &invariants, false).await?;
                let now = ctx.now();
                for ((invariant, record), outcome) in invariants.iter().zip(raw).zip(outcomes) {
                    count += 1.0;
                    let mut violations: Vec<String> = outcome
                        .violations
                        .iter()
                        .map(|violation| crate::js::js_string(violation.identity.get("id")))
                        .collect();
                    crate::js::sort_strings(&mut violations);
                    let previous = invariant
                        .last_check
                        .as_ref()
                        .filter(|previous| !previous.is_null());
                    let known: IndexSet<String> = previous
                        .and_then(|previous| previous.get("violations"))
                        .and_then(Value::as_array)
                        .map(|known| {
                            known
                                .iter()
                                .map(|item| crate::js::js_string(Some(item)))
                                .collect()
                        })
                        .unwrap_or_default();
                    let fresh: Vec<String> = violations
                        .iter()
                        .filter(|identity_id| !known.contains(*identity_id))
                        .cloned()
                        .collect();
                    let failed_now = !outcome.passed;
                    let previous_passed =
                        previous.is_some_and(|previous| crate::js::truthy(previous.get("passed")));
                    // Reported once per change: a failure after a pass (or the first check), or new people violating it.
                    let is_newly_broken =
                        failed_now && (previous.is_none() || previous_passed || !fresh.is_empty());
                    let is_restored = !failed_now && previous.is_some() && !previous_passed;
                    if is_newly_broken {
                        let mut metadata = Map::new();
                        metadata.insert("name".into(), Value::String(invariant.name.clone()));
                        metadata.insert("mode".into(), Value::String(invariant.mode.clone()));
                        metadata.insert(
                            "violations".into(),
                            json!(if fresh.is_empty() {
                                &violations
                            } else {
                                &fresh
                            }),
                        );
                        if outcome.error.is_some() {
                            metadata.insert(
                                "error".into(),
                                Value::String(outcome.error_member("code")),
                            );
                        }
                        ctx.events()?
                            .record_audit(
                                &tx,
                                &check_event(
                                    tenant_id,
                                    "invariant:broken",
                                    &invariant.id,
                                    now,
                                    "deny",
                                    Value::Object(metadata),
                                ),
                            )
                            .await?;
                        newly_broken.push(json!({
                            "tenantId": tenant_id,
                            "invariantId": invariant.id,
                            "name": invariant.name,
                            "violations": violations,
                        }));
                    } else if is_restored {
                        ctx.events()?
                            .record_audit(
                                &tx,
                                &check_event(
                                    tenant_id,
                                    "invariant:restored",
                                    &invariant.id,
                                    now,
                                    "allow",
                                    json!({ "name": invariant.name, "mode": invariant.mode }),
                                ),
                            )
                            .await?;
                        newly_restored.push(json!({
                            "tenantId": tenant_id,
                            "invariantId": invariant.id,
                            "name": invariant.name,
                        }));
                    }
                    let mut last_check = Map::new();
                    last_check.insert("at".into(), crate::js::number(now));
                    last_check.insert("passed".into(), Value::Bool(outcome.passed));
                    last_check.insert("violations".into(), json!(violations));
                    if outcome.error.is_some() {
                        last_check.insert(
                            "error".into(),
                            Value::String(outcome.error_member("message")),
                        );
                    }
                    let mut record = record;
                    record.insert("lastCheck".into(), Value::Object(last_check));
                    tx.put("accessInvariants", &record).await?;
                }
                Ok((count, newly_broken, newly_restored))
            })
            .await?;
        checked += count;
        broken.extend(newly_broken);
        restored.extend(newly_restored);
    }
    Ok(json!({
        "checked": crate::js::number(checked),
        "broken": broken,
        "restored": restored,
    }))
}

/// `violationKeys(results)`: `{invariantId}:{identityId}` of every violation.
fn violation_keys(results: &[InvariantResult]) -> IndexSet<String> {
    results
        .iter()
        .flat_map(|result| {
            let invariant_id = crate::js::js_string(result.invariant_member("id"));
            result.violations.iter().map(move |violation| {
                format!(
                    "{invariant_id}:{}",
                    crate::js::js_string(violation.identity.get("id"))
                )
            })
        })
        .collect()
}

/// Before an access-changing operation: the enforced invariants and the violations that already exist.
pub async fn invariant_snapshot(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    action: &str,
) -> IamResult<Option<InvariantSnapshot>> {
    narrowing_only(tx, false);
    if !ACCESS_CHANGING_ACTIONS.contains(&action) {
        return Ok(None);
    }
    let mut invariants = Vec::new();
    for record in tx
        .find(
            "accessInvariants",
            &Filter::new().eq("tenantId", tenant_id),
            &find_all(),
        )
        .await?
    {
        if record.get("mode").and_then(Value::as_str) == Some("enforce") {
            invariants.push(decode::<AccessInvariant>(record)?);
        }
    }
    if invariants.is_empty() {
        return Ok(None);
    }
    let tenant = ctx.tenant(tx, tenant_id).await?;
    let results = evaluate_invariants(ctx, tx, &tenant, &invariants, true).await?;
    let existing = violation_keys(&results);
    let unevaluable = results
        .iter()
        .filter(|result| result.error.is_some())
        .map(|result| crate::js::js_string(result.invariant_member("id")))
        .collect();
    Ok(Some(InvariantSnapshot {
        invariants,
        existing,
        unevaluable,
    }))
}

/// What `invariantSnapshot` returns: the enforced invariants, the violations that already existed and the
/// invariants that already could not be evaluated.
#[derive(Debug, Clone)]
pub struct InvariantSnapshot {
    pub invariants: Vec<AccessInvariant>,
    pub existing: IndexSet<String>,
    pub unevaluable: IndexSet<String>,
}

/// Operations that can change who may do what (`accessChangingActions`): enforced invariants are re-checked around
/// them.
pub const ACCESS_CHANGING_ACTIONS: &[&str] = &[
    "iam:roles:update",
    "iam:roles:delete",
    "iam:policies:update",
    "iam:policies:delete",
    "iam:bindings:create",
    "iam:bindings:delete",
    "iam:bindings:activate",
    "iam:bindings:approve",
    "iam:groups:update",
    "iam:groups:delete",
    "iam:identities:create",
    "iam:identities:update",
    "iam:packages:update",
    "iam:packages:assign",
    "iam:packages:approve",
    "iam:config:apply",
    "iam:access-requests:review",
    "iam:relationships:create",
    "iam:relationships:delete",
    "iam:resources:update",
    "iam:boundaries:update",
    "iam:authorities:revoke",
    "iam:resources:delete",
    "iam:root:grant",
    "iam:certifications:manage",
    "iam:agreements:manage",
    "iam:onboarding:manage",
    "iam:analysis:update",
    "iam:roles:assume",
    "iam:trust:create",
    "iam:trust:update",
    "iam:session-tokens:create",
    "iam:oidc-providers:create",
    "iam:oidc-providers:update",
    "iam:teams:create",
    "iam:teams:update",
    "iam:teams:delete",
    "iam:departments:manage",
    "iam:packages:create",
    "iam:features:manage",
    "iam:features:override",
    "iam:billing:manage",
    "iam:licenses:assign",
    "iam:licenses:manage",
    "iam:guests:manage",
    "iam:guests:settings",
    "iam:clearances:adjudicate",
    "iam:classifications:manage",
    "iam:classifications:declassify",
];

/// The transactions whose running operation only narrows access (`narrowingOnly`, a WeakSet keyed by the
/// transaction): `mark` true adds `tx`; false removes it and reports whether it was there.
fn narrowing_only(tx: &Store, mark: bool) -> bool {
    static MARKED: std::sync::Mutex<Vec<std::sync::Weak<dyn better_iam_core::IamStore>>> =
        std::sync::Mutex::new(Vec::new());
    let mut marked = MARKED
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    marked.retain(|weak| weak.strong_count() > 0);
    let position = marked.iter().position(|weak| {
        weak.upgrade()
            .is_some_and(|live| std::ptr::addr_eq(Arc::as_ptr(&live), Arc::as_ptr(tx)))
    });
    if mark {
        if position.is_none() {
            marked.push(Arc::downgrade(tx));
        }
        true
    } else if let Some(index) = position {
        marked.remove(index);
        true
    } else {
        false
    }
}

/// After the operation: refuses (rolling the transaction back) when it newly broke an enforced invariant.
pub async fn invariant_verify(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    snapshot: Option<&InvariantSnapshot>,
) -> IamResult<()> {
    let narrowing = narrowing_only(tx, false);
    let Some(snapshot) = snapshot else {
        return Ok(());
    };
    let tenant = ctx.tenant(tx, tenant_id).await?;
    for result in evaluate_invariants(ctx, tx, &tenant, &snapshot.invariants, true).await? {
        let member = |key: &str| crate::js::js_string(result.invariant_member(key));
        // Taking access away for cause is never blocked by an invariant that expects it to remain.
        if narrowing && member("expect") == "allow" {
            continue;
        }
        // Deleting an invariant's group or resource would otherwise switch enforcement off silently.
        if result.error.is_some() && !snapshot.unevaluable.contains(&member("id")) {
            return Err(IamError::with_status(
                "INVARIANT_VIOLATION",
                format!(
                    "Access invariant \"{}\" could no longer be evaluated ({}); change or delete the invariant first",
                    member("name"),
                    result.error_member("message")
                ),
                409,
            ));
        }
        let invariant_id = member("id");
        let Some(broken) = result.violations.iter().find(|violation| {
            !snapshot.existing.contains(&format!(
                "{invariant_id}:{}",
                crate::js::js_string(violation.identity.get("id"))
            ))
        }) else {
            continue;
        };
        let resource = result.invariant_member("resource");
        return Err(IamError::with_status(
            "INVARIANT_VIOLATION",
            format!(
                "Access invariant \"{}\": {} would {} {} on {}/{}",
                member("name"),
                crate::js::js_string(broken.identity.get("name")),
                if member("expect") == "deny" {
                    "be allowed"
                } else {
                    "no longer be allowed"
                },
                member("action"),
                crate::js::js_string(resource.and_then(|resource| resource.get("type"))),
                crate::js::js_string(resource.and_then(|resource| resource.get("id"))),
            ),
            409,
        ));
    }
    Ok(())
}

/// Marks the running operation (inside `operation()`) as one that only narrows access; see `narrowingOnly`.
pub fn narrows_access_only(tx: &Store) {
    narrowing_only(tx, true);
}
