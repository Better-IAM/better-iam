//! Port of `packages/server/src/api/quotas.ts`: the `quotas` API group (usage plans, assignments, usage, resets and
//! the caller's own consumption) and the trusted runtime behind `iam.quotas`.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Record, Tenant, TenantStatus,
};
use better_iam_types::api::quotas;
use futures::future::BoxFuture;
use indexmap::IndexMap;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::js::{cmp_utf16, invalid_input, js_string, number, number_to_string, truthy};
use crate::port::decode;
use crate::quotas::{
    QUOTA_ASSIGNMENTS, QUOTA_COUNTERS, QUOTA_PLANS, QuotaAssignment, QuotaCounter, QuotaDecision,
    QuotaExceededError, QuotaLimit, QuotaPlan, QuotaSubject, QuotaWindow, alert_thresholds,
    consume_quota, quota_limits, quota_name, quota_throttle, quota_window, subject_of, time_zone,
};
use crate::utils::id;
use crate::validation::{integer, text};

/// `quotas/{name}`: the resource of a plan.
fn plan_resource(name: &str) -> String {
    format!("quotas/{name}")
}

/// `planView(plan, assignments)`: a plan as its managers see it.
fn plan_view(plan: &Record, assignments: usize) -> Value {
    let member = |name: &str| plan.get(name).cloned().unwrap_or(Value::Null);
    let mut out = Map::new();
    out.insert("name".into(), member("name"));
    if let Some(description) = plan.get("description") {
        out.insert("description".into(), description.clone());
    }
    out.insert("meter".into(), member("meter"));
    if truthy(plan.get("throttle")) {
        out.insert("throttle".into(), member("throttle"));
    }
    out.insert("limits".into(), member("limits"));
    out.insert("scope".into(), member("scope"));
    out.insert("default".into(), member("default"));
    out.insert("priority".into(), member("priority"));
    out.insert("timeZone".into(), member("timeZone"));
    out.insert("alertThresholds".into(), member("alertThresholds"));
    out.insert("assignments".into(), number(assignments as f64));
    out.insert("createdAt".into(), member("createdAt"));
    out.insert("createdBy".into(), member("createdBy"));
    out.insert("updatedAt".into(), member("updatedAt"));
    out.insert("updatedBy".into(), member("updatedBy"));
    Value::Object(out)
}

/// `cost(value)`: 1 by default, else a whole number of units.
fn cost(value: Option<&Value>) -> IamResult<f64> {
    match value {
        None => Ok(1.0),
        Some(value) => integer(Some(value), "cost", 1.0, 1_000_000_000.0),
    }
}

/// `findPlan(tx, tenantId, name)`: the stored record and the plan.
async fn find_plan(tx: &Store, tenant_id: &str, name: &str) -> IamResult<(Record, QuotaPlan)> {
    let found = tx
        .find(
            QUOTA_PLANS,
            &Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("uniqueKey", name.to_owned()),
            &FindOptions::default(),
        )
        .await?
        .into_iter()
        .next();
    let Some(record) = found else {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Quota plan not found",
            404,
        ));
    };
    let plan = decode(record.clone())?;
    Ok((record, plan))
}

/// `writable(realm)`: deleted tenants cannot be updated.
fn writable(realm: &Tenant) -> IamResult<()> {
    if realm.status == TenantStatus::Deleted {
        return Err(IamError::new(
            "INVALID_TRANSITION",
            "Deleted tenants cannot be updated",
        ));
    }
    Ok(())
}

/// `${limit}/${period}` for each limit of a plan record.
fn limit_labels(plan: &QuotaPlan) -> Value {
    Value::Array(
        plan.limits
            .iter()
            .map(|limit| {
                Value::String(format!(
                    "{}/{}",
                    number_to_string(limit.limit),
                    limit.period
                ))
            })
            .collect(),
    )
}

/// `${ratePerSecond}/s burst ${burst}`, or null without a throttle.
fn throttle_label(plan: &QuotaPlan) -> Value {
    plan.throttle
        .as_ref()
        .map(|throttle| {
            Value::String(format!(
                "{}/s burst {}",
                number_to_string(throttle.rate_per_second),
                number_to_string(throttle.burst)
            ))
        })
        .unwrap_or(Value::Null)
}

/// `scope` must be `subject` or `tenant` when given.
fn valid_scope(value: Option<&Value>) -> IamResult<()> {
    match value {
        None => Ok(()),
        Some(Value::String(scope)) if scope == "subject" || scope == "tenant" => Ok(()),
        Some(_) => Err(invalid_input("scope must be subject or tenant")),
    }
}

/// The plans of a tenant that are its default for a meter.
async fn default_plans(tx: &Store, tenant_id: &str, meter: &str) -> IamResult<usize> {
    Ok(tx
        .find(
            QUOTA_PLANS,
            &Filter::new()
                .eq("tenantId", tenant_id.to_owned())
                .eq("meter", meter.to_owned())
                .eq("default", true),
            &FindOptions::default(),
        )
        .await?
        .len())
}

/// `assignmentCount(tx, plan)`.
async fn assignment_count(tx: &Store, plan: &QuotaPlan) -> IamResult<usize> {
    Ok(tx
        .find(
            QUOTA_ASSIGNMENTS,
            &Filter::new()
                .eq("tenantId", plan.tenant_id.clone())
                .eq("planId", plan.id.clone()),
            &FindOptions::default(),
        )
        .await?
        .len())
}

/// `subjectName(tx, tenantId, type, subjectId)`: the label of an assignment's subject.
async fn subject_name(
    tx: &Store,
    tenant_id: &str,
    kind: &str,
    subject_id: &str,
) -> IamResult<Option<String>> {
    let same_tenant =
        |record: &Record| record.get("tenantId").and_then(Value::as_str) == Some(tenant_id);
    let label = |record: &Record| {
        record
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_owned)
    };
    if kind == "group" {
        let group = tx.get("groups", subject_id).await?;
        return Ok(group.filter(same_tenant).and_then(|group| label(&group)));
    }
    if kind == "identity" {
        let identity = tx.get("identities", subject_id).await?;
        return Ok(identity
            .filter(same_tenant)
            .and_then(|identity| label(&identity)));
    }
    let session = tx.get("sessions", subject_id).await?;
    Ok(session
        .filter(same_tenant)
        .and_then(|session| label(&session)))
}

/// The consumption of the caller's own session, which must belong to the tenant.
async fn caller_decision(
    ctx: &Arc<ServerContext>,
    credential: &CredentialInput,
    input: &Map<String, Value>,
    dry_run: bool,
) -> IamResult<QuotaDecision> {
    let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
    let meter = quota_name(input.get("meter"), Some("meter"))?;
    let units = if dry_run {
        0.0
    } else {
        cost(input.get("cost"))?
    };
    let authenticated = ctx.principals()?.authenticate(credential).await?;
    let ctx = ctx.clone();
    ctx.store
        .clone()
        .transaction(|tx| async move {
            let principal = ctx
                .principals()?
                .current_principal(&tx, &authenticated)
                .await?;
            let realm = ctx.tenant(&tx, &tenant_id).await?;
            if principal.session.tenant_id != realm.id {
                return Err(IamError::with_status(
                    "ACCESS_DENIED",
                    "Quotas count in the session\u{2019}s own tenant",
                    403,
                ));
            }
            let recorder = {
                let ctx = ctx.clone();
                let principal = principal.clone();
                let realm_id = realm.id.clone();
                move |store: Store,
                      action: &'static str,
                      metadata: Map<String, Value>|
                      -> BoxFuture<'static, IamResult<()>> {
                    let ctx = ctx.clone();
                    let principal = principal.clone();
                    let realm_id = realm_id.clone();
                    Box::pin(async move {
                        let resource = plan_resource(&js_string(metadata.get("plan")));
                        ctx.events()?
                            .audit(
                                &store,
                                &principal,
                                action,
                                &realm_id,
                                &resource,
                                if action == "quota:exceeded" {
                                    AuditOutcome::Deny
                                } else {
                                    AuditOutcome::Allow
                                },
                                false,
                                Some(metadata),
                            )
                            .await
                    })
                }
            };
            consume_quota(
                &ctx,
                &tx,
                &subject_of(&principal),
                &meter,
                units,
                &recorder,
                dry_run,
            )
            .await
        })
        .await
}

/// The `quotas` API group (`createQuotasApi(ctx)`): one method per route `quotas/{method}`.
///
/// API usage plans and quotas. Managers define plans (`iam:quotas:manage` on `iam/quotas/{plan}`) and assign them to
/// API keys, agents, people or groups, or make one the tenant's default for its meter; applications count use with
/// `iam.quotas.consume` (or `quotas.consume` over HTTP with the caller's own credential) and show callers their
/// remaining quota with `quotas.status`.
pub struct QuotasApi {
    ctx: Arc<ServerContext>,
}

/// `createQuotasApi(ctx)`.
pub fn create_quotas_api(ctx: &Arc<ServerContext>) -> IamResult<QuotasApi> {
    Ok(QuotasApi { ctx: ctx.clone() })
}

impl QuotasApi {
    async fn audit(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        action: &str,
        tenant_id: &str,
        name: &str,
        metadata: Map<String, Value>,
    ) -> IamResult<()> {
        self.ctx
            .events()?
            .audit(
                tx,
                principal,
                action,
                tenant_id,
                &plan_resource(name),
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await
    }

    /// `validSubject(tx, tenantId, type, subjectId)`: refuses subjects outside the tenant, deleted identities, and
    /// sessions that are not API keys.
    async fn valid_subject(
        &self,
        tx: &Store,
        tenant_id: &str,
        kind: Option<&Value>,
        subject_id: Option<&Value>,
    ) -> IamResult<(String, String)> {
        let subject = text(subject_id, "subjectId", 256)?;
        match kind.and_then(Value::as_str) {
            Some("identity") => {
                self.ctx.active_identity(tx, &subject, tenant_id).await?;
                Ok(("identity".into(), subject))
            }
            Some("group") => {
                self.ctx
                    .scoped(
                        tx,
                        "groups",
                        Some(&Value::String(subject.clone())),
                        tenant_id,
                    )
                    .await?;
                Ok(("group".into(), subject))
            }
            Some("apiKey") => {
                let session = tx.get("sessions", &subject).await?;
                let valid = session.as_ref().is_some_and(|session| {
                    session.get("tenantId").and_then(Value::as_str) == Some(tenant_id)
                        && session.get("kind").and_then(Value::as_str) == Some("api-key")
                });
                if !valid {
                    return Err(IamError::with_status("NOT_FOUND", "API key not found", 404));
                }
                Ok(("apiKey".into(), subject))
            }
            _ => Err(invalid_input(
                "subjectType must be apiKey, identity or group",
            )),
        }
    }

    /// `quotas/assign`: assigns a plan to an API key (a session id of kind `api-key`), an identity (a person,
    /// service account or agent) or a group, replacing the subject's plan for the same meter. Requires
    /// iam:quotas:manage on the plan; audited as `quota:assign`.
    pub async fn assign(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::AssignInput>,
    ) -> IamResult<Reply<quotas::AssignOutput>> {
        let name = quota_name(input.get("plan"), Some("plan"))?;
        let ctx = &self.ctx;
        let body = &input;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let name = name_ref.clone();
                    writable(&realm)?;
                    let (_, plan) = find_plan(&tx, &realm.id, &name).await?;
                    let (subject_type, subject_id) = self
                        .valid_subject(
                            &tx,
                            &realm.id,
                            body.get("subjectType"),
                            body.get("subjectId"),
                        )
                        .await?;
                    let unique_key = format!("{}:{subject_type}:{subject_id}", plan.meter);
                    let existing = tx
                        .find(
                            QUOTA_ASSIGNMENTS,
                            &Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("uniqueKey", unique_key.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                        .into_iter()
                        .next();
                    let created_at = ctx.now();
                    let mut record = Record::new();
                    record.insert(
                        "id".into(),
                        existing
                            .as_ref()
                            .and_then(|existing| existing.get("id").cloned())
                            .unwrap_or_else(|| Value::String(id())),
                    );
                    record.insert("tenantId".into(), Value::String(realm.id.clone()));
                    record.insert("uniqueKey".into(), Value::String(unique_key));
                    record.insert("planId".into(), Value::String(plan.id.clone()));
                    record.insert("meter".into(), Value::String(plan.meter.clone()));
                    record.insert("subjectType".into(), Value::String(subject_type.clone()));
                    record.insert("subjectId".into(), Value::String(subject_id.clone()));
                    record.insert("createdAt".into(), number(created_at));
                    record.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    if existing.is_some() {
                        tx.put(QUOTA_ASSIGNMENTS, &record).await?;
                    } else {
                        tx.insert(QUOTA_ASSIGNMENTS, &record).await?;
                    }
                    let mut metadata = Map::new();
                    metadata.insert("plan".into(), Value::String(name.clone()));
                    metadata.insert("meter".into(), Value::String(plan.meter.clone()));
                    metadata.insert("subjectType".into(), Value::String(subject_type.clone()));
                    metadata.insert("subjectId".into(), Value::String(subject_id.clone()));
                    self.audit(&tx, &principal, "quota:assign", &realm.id, &name, metadata)
                        .await?;
                    let label = subject_name(&tx, &realm.id, &subject_type, &subject_id).await?;
                    let mut out = Map::new();
                    out.insert("plan".into(), Value::String(name.clone()));
                    out.insert("meter".into(), Value::String(plan.meter.clone()));
                    out.insert("subjectType".into(), Value::String(subject_type));
                    out.insert("subjectId".into(), Value::String(subject_id));
                    if let Some(label) = label {
                        out.insert("subjectName".into(), Value::String(label));
                    }
                    out.insert("createdAt".into(), number(created_at));
                    out.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    Ok(Value::Object(out))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:manage",
                &plan_resource(&name),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/consume`: counts `cost` (default 1) units of a meter for the caller's own session, or refuses without
    /// counting when the plan's throttle or a period limit would be exceeded (`allowed: false`, with `reason` and
    /// `retryAfterMs`). Needs only a session of the tenant. Thresholds crossed are audited as `quota:threshold`, and
    /// a window's first refusal as `quota:exceeded`.
    pub async fn consume(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::ConsumeInput>,
    ) -> IamResult<Reply<quotas::ConsumeOutput>> {
        let decision = caller_decision(&self.ctx, credential, &input, false).await?;
        Ok(Reply::json(decision.to_json()))
    }

    /// `quotas/createPlan`: defines a plan for a meter: a `throttle` (`ratePerSecond`, `burst`), period `limits`
    /// (minute to month), or both. `default: true` makes it the plan for everyone in the tenant without one of their
    /// own (one per meter); `scope: 'tenant'` makes everyone it covers share one set of counters. Requires
    /// iam:quotas:manage; audited as `quota:plan-create`.
    pub async fn create_plan(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::CreatePlanInput>,
    ) -> IamResult<Reply<quotas::CreatePlanOutput>> {
        let name = quota_name(input.get("name"), None)?;
        let ctx = &self.ctx;
        let body = &input;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let name = name_ref.clone();
                    writable(&realm)?;
                    let taken = tx
                        .find(
                            QUOTA_PLANS,
                            &Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("uniqueKey", name.clone()),
                            &FindOptions::default(),
                        )
                        .await?;
                    if !taken.is_empty() {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A plan with this name already exists",
                            409,
                        )
                        .into());
                    }
                    let meter = quota_name(body.get("meter"), Some("meter"))?;
                    let throttle = quota_throttle(body.get("throttle"))?;
                    let limits = quota_limits(body.get("limits"))?;
                    if throttle.is_none() && limits.is_empty() {
                        return Err(
                            invalid_input("A plan needs a throttle, limits, or both").into()
                        );
                    }
                    valid_scope(body.get("scope"))?;
                    let default = match body.get("default") {
                        None => false,
                        Some(Value::Bool(default)) => *default,
                        Some(_) => return Err(invalid_input("default must be a boolean").into()),
                    };
                    if default && default_plans(&tx, &realm.id, &meter).await? > 0 {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            format!("The tenant already has a default plan for {meter}"),
                            409,
                        )
                        .into());
                    }
                    let now = ctx.now();
                    let mut plan = Record::new();
                    plan.insert("id".into(), Value::String(id()));
                    plan.insert("tenantId".into(), Value::String(realm.id.clone()));
                    plan.insert("uniqueKey".into(), Value::String(name.clone()));
                    plan.insert("name".into(), Value::String(name.clone()));
                    plan.insert("meter".into(), Value::String(meter.clone()));
                    if let Some(throttle) = &throttle {
                        plan.insert("throttle".into(), Value::Object(throttle.to_json()));
                    }
                    plan.insert(
                        "limits".into(),
                        Value::Array(limits.iter().map(QuotaLimit::to_json).collect()),
                    );
                    plan.insert(
                        "scope".into(),
                        body.get("scope")
                            .cloned()
                            .unwrap_or_else(|| Value::String("subject".into())),
                    );
                    plan.insert("default".into(), Value::Bool(default));
                    let priority = match body.get("priority") {
                        None => 0.0,
                        Some(priority) => integer(Some(priority), "priority", -1000.0, 1000.0)?,
                    };
                    plan.insert("priority".into(), number(priority));
                    plan.insert(
                        "timeZone".into(),
                        Value::String(time_zone(body.get("timeZone"))?),
                    );
                    plan.insert(
                        "alertThresholds".into(),
                        Value::Array(
                            alert_thresholds(body.get("alertThresholds"))?
                                .into_iter()
                                .map(number)
                                .collect(),
                        ),
                    );
                    plan.insert("createdAt".into(), number(now));
                    plan.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    plan.insert("updatedAt".into(), number(now));
                    plan.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    if body.contains_key("description") {
                        let description = text(body.get("description"), "description", 512)?;
                        plan.insert(
                            "description".into(),
                            Value::String(better_iam_core::js::trim(&description).to_owned()),
                        );
                    }
                    tx.insert(QUOTA_PLANS, &plan).await?;
                    let typed: QuotaPlan = decode(plan.clone())?;
                    let mut metadata = Map::new();
                    metadata.insert("name".into(), Value::String(name.clone()));
                    metadata.insert("meter".into(), Value::String(meter.clone()));
                    metadata.insert("limits".into(), limit_labels(&typed));
                    metadata.insert("throttle".into(), throttle_label(&typed));
                    metadata.insert("default".into(), Value::Bool(typed.default));
                    self.audit(
                        &tx,
                        &principal,
                        "quota:plan-create",
                        &realm.id,
                        &name,
                        metadata,
                    )
                    .await?;
                    Ok(plan_view(&plan, 0))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:manage",
                &plan_resource(&name),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/deletePlan`: deletes a plan with its assignments and counters. Requires iam:quotas:manage; audited as
    /// `quota:plan-delete`.
    pub async fn delete_plan(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::DeletePlanInput>,
    ) -> IamResult<Reply<quotas::DeletePlanOutput>> {
        let name = quota_name(input.get("name"), None)?;
        let ctx = &self.ctx;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let name = name_ref.clone();
                    let (_, plan) = find_plan(&tx, &realm.id, &name).await?;
                    let mut removed = 0usize;
                    for collection in [QUOTA_ASSIGNMENTS, QUOTA_COUNTERS] {
                        for record in tx
                            .find(
                                collection,
                                &Filter::new()
                                    .eq("tenantId", realm.id.clone())
                                    .eq("planId", plan.id.clone()),
                                &FindOptions::default(),
                            )
                            .await?
                        {
                            let record_id = record.get("id").and_then(Value::as_str).unwrap_or("");
                            tx.delete(collection, record_id).await?;
                            if collection == QUOTA_ASSIGNMENTS {
                                removed += 1;
                            }
                        }
                    }
                    tx.delete(QUOTA_PLANS, &plan.id).await?;
                    let mut metadata = Map::new();
                    metadata.insert("name".into(), Value::String(name.clone()));
                    metadata.insert("assignments".into(), number(removed as f64));
                    self.audit(
                        &tx,
                        &principal,
                        "quota:plan-delete",
                        &realm.id,
                        &name,
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "deleted": true, "assignments": removed }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:manage",
                &plan_resource(&name),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/getPlan`: one plan. Requires iam:quotas:read.
    pub async fn get_plan(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::GetPlanInput>,
    ) -> IamResult<Reply<quotas::GetPlanOutput>> {
        let name = quota_name(input.get("name"), None)?;
        let ctx = &self.ctx;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let (record, plan) = find_plan(&tx, &realm.id, name_ref).await?;
                    Ok(plan_view(&record, assignment_count(&tx, &plan).await?))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:read",
                &plan_resource(&name),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/listAssignments`: assignments, optionally of one plan, with their subjects' names. Requires
    /// iam:quotas:read on `iam/quotas`.
    pub async fn list_assignments(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::ListAssignmentsInput>,
    ) -> IamResult<Reply<quotas::ListAssignmentsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let mut plans: IndexMap<String, QuotaPlan> = IndexMap::new();
                    for record in tx
                        .find(
                            QUOTA_PLANS,
                            &Filter::new().eq("tenantId", realm.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        let plan: QuotaPlan = decode(record)?;
                        plans.insert(plan.id.clone(), plan);
                    }
                    let only = match body.get("plan") {
                        None => None,
                        Some(plan) => Some(quota_name(Some(plan), Some("plan"))?),
                    };
                    let mut views: Vec<(String, String, Value)> = Vec::new();
                    for record in tx
                        .find(
                            QUOTA_ASSIGNMENTS,
                            &Filter::new().eq("tenantId", realm.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        let assignment: QuotaAssignment = decode(record)?;
                        let Some(plan) = plans.get(&assignment.plan_id) else {
                            continue;
                        };
                        if only.as_ref().is_some_and(|only| *only != plan.name) {
                            continue;
                        }
                        let label = subject_name(
                            &tx,
                            &realm.id,
                            &assignment.subject_type,
                            &assignment.subject_id,
                        )
                        .await?;
                        let mut out = Map::new();
                        out.insert("plan".into(), Value::String(plan.name.clone()));
                        out.insert("meter".into(), Value::String(assignment.meter.clone()));
                        out.insert(
                            "subjectType".into(),
                            Value::String(assignment.subject_type.clone()),
                        );
                        out.insert(
                            "subjectId".into(),
                            Value::String(assignment.subject_id.clone()),
                        );
                        if let Some(label) = label {
                            out.insert("subjectName".into(), Value::String(label));
                        }
                        out.insert("createdAt".into(), number(assignment.created_at));
                        out.insert(
                            "createdBy".into(),
                            Value::String(assignment.created_by.clone()),
                        );
                        views.push((
                            plan.name.clone(),
                            assignment.subject_id.clone(),
                            Value::Object(out),
                        ));
                    }
                    // `a.plan < b.plan ? -1 : a.plan > b.plan ? 1 : a.subjectId < b.subjectId ? -1 : 1`.
                    views.sort_by(|a, b| match cmp_utf16(&a.0, &b.0) {
                        std::cmp::Ordering::Equal => {
                            if cmp_utf16(&a.1, &b.1) == std::cmp::Ordering::Less {
                                std::cmp::Ordering::Less
                            } else {
                                std::cmp::Ordering::Greater
                            }
                        }
                        other => other,
                    });
                    Ok(Value::Array(
                        views.into_iter().map(|(_, _, view)| view).collect(),
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:read",
                "quotas",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/listPlans`: every plan of the tenant, by name. Requires iam:quotas:read on `iam/quotas`.
    pub async fn list_plans(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::ListPlansInput>,
    ) -> IamResult<Reply<quotas::ListPlansOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let mut plans: Vec<(Record, QuotaPlan)> = Vec::new();
                    for record in tx
                        .find(
                            QUOTA_PLANS,
                            &Filter::new().eq("tenantId", realm.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        let plan: QuotaPlan = decode(record.clone())?;
                        plans.push((record, plan));
                    }
                    // `(a, b) => (a.name < b.name ? -1 : 1)`.
                    plans.sort_by(|a, b| {
                        if cmp_utf16(&a.1.name, &b.1.name) == std::cmp::Ordering::Less {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Greater
                        }
                    });
                    let mut views = Vec::new();
                    for (record, plan) in &plans {
                        views.push(plan_view(record, assignment_count(&tx, plan).await?));
                    }
                    Ok(Value::Array(views))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:read",
                "quotas",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/reset`: starts a subject's counters (and throttle) over, or every subject's with no subject given.
    /// Requires iam:quotas:manage; audited as `quota:reset`.
    pub async fn reset(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::ResetInput>,
    ) -> IamResult<Reply<quotas::ResetOutput>> {
        let name = quota_name(input.get("plan"), Some("plan"))?;
        let ctx = &self.ctx;
        let body = &input;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let name = name_ref.clone();
                    let (_, plan) = find_plan(&tx, &realm.id, &name).await?;
                    let subject = match body.get("subject") {
                        None => None,
                        Some(subject) => Some(text(Some(subject), "subject", 256)?),
                    };
                    let mut removed = 0usize;
                    for record in tx
                        .find(
                            QUOTA_COUNTERS,
                            &Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("planId", plan.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        let counter: QuotaCounter = decode(record)?;
                        if subject
                            .as_ref()
                            .is_none_or(|subject| counter.subject_key == *subject)
                        {
                            tx.delete(QUOTA_COUNTERS, &counter.id).await?;
                            removed += 1;
                        }
                    }
                    let mut metadata = Map::new();
                    metadata.insert("plan".into(), Value::String(name.clone()));
                    metadata.insert(
                        "subject".into(),
                        subject.map(Value::String).unwrap_or(Value::Null),
                    );
                    metadata.insert("counters".into(), number(removed as f64));
                    self.audit(&tx, &principal, "quota:reset", &realm.id, &name, metadata)
                        .await?;
                    Ok(json!({ "reset": removed }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:manage",
                &plan_resource(&name),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/status`: the caller's own quota for a meter without counting anything: the plan that applies, what is
    /// left in each window, and the throttle's tokens. Needs only a session of the tenant; not audited.
    pub async fn status(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::StatusInput>,
    ) -> IamResult<Reply<quotas::StatusOutput>> {
        let decision = caller_decision(&self.ctx, credential, &input, true).await?;
        Ok(Reply::json(decision.to_json()))
    }

    /// `quotas/unassign`: removes a subject's plan for a meter. Requires iam:quotas:manage on `iam/quotas`; audited
    /// as `quota:unassign`.
    pub async fn unassign(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::UnassignInput>,
    ) -> IamResult<Reply<quotas::UnassignOutput>> {
        let meter = quota_name(input.get("meter"), Some("meter"))?;
        let ctx = &self.ctx;
        let body = &input;
        let meter_ref = &meter;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let meter = meter_ref.clone();
                    let subject_type = js_string(body.get("subjectType"));
                    let subject_id = text(body.get("subjectId"), "subjectId", 256)?;
                    let unique_key = format!("{meter}:{subject_type}:{subject_id}");
                    let existing = tx
                        .find(
                            QUOTA_ASSIGNMENTS,
                            &Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("uniqueKey", unique_key),
                            &FindOptions::default(),
                        )
                        .await?
                        .into_iter()
                        .next();
                    let Some(existing) = existing else {
                        return Ok(json!({ "removed": false }));
                    };
                    let existing: QuotaAssignment = decode(existing)?;
                    tx.delete(QUOTA_ASSIGNMENTS, &existing.id).await?;
                    let plan = match tx.get(QUOTA_PLANS, &existing.plan_id).await? {
                        Some(record) => Some(decode::<QuotaPlan>(record)?),
                        None => None,
                    };
                    let plan_name = plan.map(|plan| plan.name);
                    let mut metadata = Map::new();
                    metadata.insert(
                        "plan".into(),
                        plan_name.clone().map(Value::String).unwrap_or(Value::Null),
                    );
                    metadata.insert("meter".into(), Value::String(meter.clone()));
                    metadata.insert(
                        "subjectType".into(),
                        Value::String(existing.subject_type.clone()),
                    );
                    metadata.insert(
                        "subjectId".into(),
                        Value::String(existing.subject_id.clone()),
                    );
                    self.audit(
                        &tx,
                        &principal,
                        "quota:unassign",
                        &realm.id,
                        plan_name.as_deref().unwrap_or(&meter),
                        metadata,
                    )
                    .await?;
                    Ok(json!({ "removed": true }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:manage",
                "quotas",
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/updatePlan`: changes a plan: fields left out keep their value; `throttle: null` and
    /// `description: null` clear them; `limits` replaces the whole list. The meter cannot change. Counters in
    /// progress keep counting under the new limits. Requires iam:quotas:manage; audited as `quota:plan-update`.
    pub async fn update_plan(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::UpdatePlanInput>,
    ) -> IamResult<Reply<quotas::UpdatePlanOutput>> {
        let name = quota_name(input.get("name"), None)?;
        let ctx = &self.ctx;
        let body = &input;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant: realm,
                  }| {
                Box::pin(async move {
                    let name = name_ref.clone();
                    writable(&realm)?;
                    let (record, plan) = find_plan(&tx, &realm.id, &name).await?;
                    // `{ ...rest, updatedAt, updatedBy }` without description and throttle.
                    let mut next = record.clone();
                    next.shift_remove("description");
                    next.shift_remove("throttle");
                    next.insert("updatedAt".into(), number(ctx.now()));
                    next.insert(
                        "updatedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    match body.get("description") {
                        None => {
                            if let Some(description) = record.get("description") {
                                next.insert("description".into(), description.clone());
                            }
                        }
                        Some(Value::Null) => {}
                        Some(description) => {
                            let description = text(Some(description), "description", 512)?;
                            next.insert(
                                "description".into(),
                                Value::String(better_iam_core::js::trim(&description).to_owned()),
                            );
                        }
                    }
                    let throttle = match body.get("throttle") {
                        None => record
                            .get("throttle")
                            .filter(|throttle| truthy(Some(throttle)))
                            .cloned(),
                        Some(throttle) => quota_throttle(Some(throttle))?
                            .map(|throttle| Value::Object(throttle.to_json())),
                    };
                    if let Some(throttle) = throttle {
                        next.insert("throttle".into(), throttle);
                    }
                    if body.contains_key("limits") {
                        next.insert(
                            "limits".into(),
                            Value::Array(
                                quota_limits(body.get("limits"))?
                                    .iter()
                                    .map(QuotaLimit::to_json)
                                    .collect(),
                            ),
                        );
                    }
                    let limit_count = next
                        .get("limits")
                        .and_then(Value::as_array)
                        .map(Vec::len)
                        .unwrap_or(0);
                    if !truthy(next.get("throttle")) && limit_count == 0 {
                        return Err(
                            invalid_input("A plan needs a throttle, limits, or both").into()
                        );
                    }
                    if body.contains_key("scope") {
                        valid_scope(body.get("scope"))?;
                        next.insert(
                            "scope".into(),
                            body.get("scope").cloned().unwrap_or(Value::Null),
                        );
                    }
                    if let Some(default) = body.get("default") {
                        let Value::Bool(default) = default else {
                            return Err(invalid_input("default must be a boolean").into());
                        };
                        if *default
                            && !plan.default
                            && default_plans(&tx, &realm.id, &plan.meter).await? > 0
                        {
                            return Err(IamError::with_status(
                                "CONFLICT",
                                format!("The tenant already has a default plan for {}", plan.meter),
                                409,
                            )
                            .into());
                        }
                        next.insert("default".into(), Value::Bool(*default));
                    }
                    if let Some(priority) = body.get("priority") {
                        next.insert(
                            "priority".into(),
                            number(integer(Some(priority), "priority", -1000.0, 1000.0)?),
                        );
                    }
                    if body.contains_key("timeZone") {
                        next.insert(
                            "timeZone".into(),
                            Value::String(time_zone(body.get("timeZone"))?),
                        );
                    }
                    if body.contains_key("alertThresholds") {
                        next.insert(
                            "alertThresholds".into(),
                            Value::Array(
                                alert_thresholds(body.get("alertThresholds"))?
                                    .into_iter()
                                    .map(number)
                                    .collect(),
                            ),
                        );
                    }
                    let stored_record = tx.put(QUOTA_PLANS, &next).await?;
                    let stored: QuotaPlan = decode(stored_record.clone())?;
                    let mut metadata = Map::new();
                    metadata.insert("name".into(), Value::String(name.clone()));
                    metadata.insert("limits".into(), limit_labels(&stored));
                    metadata.insert("throttle".into(), throttle_label(&stored));
                    metadata.insert("default".into(), Value::Bool(stored.default));
                    metadata.insert("scope".into(), Value::String(stored.scope.clone()));
                    self.audit(
                        &tx,
                        &principal,
                        "quota:plan-update",
                        &realm.id,
                        &name,
                        metadata,
                    )
                    .await?;
                    Ok(plan_view(
                        &stored_record,
                        assignment_count(&tx, &stored).await?,
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:manage",
                &plan_resource(&name),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `quotas/usage`: every subject's use of a plan in the current windows, most used first. Requires
    /// iam:quotas:read.
    pub async fn usage(
        &self,
        credential: &CredentialInput,
        input: Body<quotas::UsageInput>,
    ) -> IamResult<Reply<quotas::UsageOutput>> {
        let name = quota_name(input.get("plan"), Some("plan"))?;
        let ctx = &self.ctx;
        let name_ref = &name;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx, tenant: realm, ..
                  }| {
                Box::pin(async move {
                    let (_, plan) = find_plan(&tx, &realm.id, name_ref).await?;
                    let now = ctx.now();
                    let mut current: IndexMap<String, QuotaWindow> = IndexMap::new();
                    for limit in &plan.limits {
                        current.insert(
                            limit.period.clone(),
                            quota_window(&limit.period, now, &plan.time_zone)?,
                        );
                    }
                    let mut by_subject: IndexMap<String, Vec<QuotaCounter>> = IndexMap::new();
                    for record in tx
                        .find(
                            QUOTA_COUNTERS,
                            &Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("planId", plan.id.clone())
                                .eq("kind", "window"),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        let counter: QuotaCounter = decode(record)?;
                        let in_window = counter
                            .period
                            .as_ref()
                            .filter(|period| !period.is_empty())
                            .and_then(|period| current.get(period))
                            .is_some_and(|window| Some(window.start) == counter.window_start);
                        if in_window {
                            by_subject
                                .entry(counter.subject_key.clone())
                                .or_default()
                                .push(counter);
                        }
                    }
                    let mut views: Vec<(String, f64, Value)> = Vec::new();
                    for (subject, counters) in &by_subject {
                        let (kind, subject_id) = match subject.find(':') {
                            Some(index) => (&subject[..index], &subject[index + 1..]),
                            // `slice(0, -1)` and `slice(0)` when there is no colon.
                            None => {
                                let end = subject
                                    .char_indices()
                                    .last()
                                    .map(|(index, _)| index)
                                    .unwrap_or(0);
                                (&subject[..end], subject.as_str())
                            }
                        };
                        let label = match kind {
                            "identity" => {
                                subject_name(&tx, &realm.id, "identity", subject_id).await?
                            }
                            "key" => subject_name(&tx, &realm.id, "apiKey", subject_id).await?,
                            _ => None,
                        };
                        let exceeded: Vec<f64> = counters
                            .iter()
                            .filter_map(|counter| counter.exceeded_at)
                            .collect();
                        let mut share = 0.0f64;
                        let mut limits = Vec::new();
                        for limit in &plan.limits {
                            let counter = counters
                                .iter()
                                .find(|item| item.period.as_deref() == Some(limit.period.as_str()));
                            let used = counter.and_then(|counter| counter.used).unwrap_or(0.0);
                            share = share.max(used / limit.limit);
                            let reset_at = current
                                .get(&limit.period)
                                .map(|window| window.end)
                                .ok_or_else(crate::js::internal_error)?;
                            limits.push(json!({
                                "period": limit.period,
                                "limit": number(limit.limit),
                                "used": number(used),
                                "remaining": number((limit.limit - used).max(0.0)),
                                "resetAt": number(reset_at),
                            }));
                        }
                        let mut out = Map::new();
                        out.insert("subject".into(), Value::String(subject.clone()));
                        if let Some(label) = label {
                            out.insert("subjectName".into(), Value::String(label));
                        }
                        out.insert("limits".into(), Value::Array(limits));
                        if !exceeded.is_empty() {
                            let first = exceeded.iter().copied().fold(f64::INFINITY, f64::min);
                            out.insert("exceededAt".into(), number(first));
                        }
                        views.push((subject.clone(), share, Value::Object(out)));
                    }
                    // `share(b) - share(a) || (a.subject < b.subject ? -1 : 1)`.
                    views.sort_by(|a, b| {
                        let by_share = b.1 - a.1;
                        if by_share != 0.0 && !by_share.is_nan() {
                            return by_share.total_cmp(&0.0);
                        }
                        if cmp_utf16(&a.0, &b.0) == std::cmp::Ordering::Less {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Greater
                        }
                    });
                    Ok(Value::Array(
                        views.into_iter().map(|(_, _, view)| view).collect(),
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:quotas:read",
                &plan_resource(&name),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// Trusted quota checks for the deployment's own request handlers (`iam.quotas`).
pub struct QuotasRuntime {
    ctx: Arc<ServerContext>,
}

/// `createQuotasRuntime(ctx)`.
pub fn create_quotas_runtime(ctx: &Arc<ServerContext>) -> IamResult<QuotasRuntime> {
    Ok(QuotasRuntime { ctx: ctx.clone() })
}

/// `split(request)`: the credential members and the `{ tenantId, meter, cost? }` input of a request.
fn split(request: &Value, with_cost: bool) -> (CredentialInput, Map<String, Value>) {
    let mut rest = request.as_object().cloned().unwrap_or_default();
    let mut input = Map::new();
    if let Some(tenant_id) = rest.shift_remove("tenantId") {
        input.insert("tenantId".into(), tenant_id);
    }
    if let Some(meter) = rest.shift_remove("meter") {
        input.insert("meter".into(), meter);
    }
    if with_cost && let Some(units) = rest.shift_remove("cost") {
        input.insert("cost".into(), units);
    }
    (
        crate::api::credential_from_json(Some(&Value::Object(rest))),
        input,
    )
}

impl QuotasRuntime {
    /// Counts use for the request's credential (as `quotas.consume`) and returns the decision.
    pub async fn consume(&self, request: &Value) -> IamResult<crate::quotas::QuotaDecision> {
        let (credential, input) = split(request, true);
        caller_decision(&self.ctx, &credential, &input, false).await
    }
    /// As `consume`, but throws QUOTA_EXCEEDED (429, with `retryAfterMs` for the Retry-After header) when refused.
    pub async fn enforce(&self, request: &Value) -> IamResult<crate::quotas::QuotaDecision> {
        let (credential, input) = split(request, true);
        let decision = caller_decision(&self.ctx, &credential, &input, false).await?;
        if !decision.allowed {
            return Err(QuotaExceededError::new(&decision, decision.retry_after_ms).into());
        }
        Ok(decision)
    }
    /// The request credential's quota for a meter without counting.
    pub async fn status(&self, request: &Value) -> IamResult<crate::quotas::QuotaDecision> {
        let (credential, input) = split(request, false);
        caller_decision(&self.ctx, &credential, &input, true).await
    }
    /// Counts use for a subject your code identified itself (a background job, a webhook sender): an identity of the
    /// tenant, optionally through one of its API keys. No credential; events are recorded as `deployment-operator`.
    pub async fn consume_for(&self, input: &Value) -> IamResult<crate::quotas::QuotaDecision> {
        let member = |key: &str| crate::js::member(Some(input), key).cloned();
        let tenant_id = text(member("tenantId").as_ref(), "tenantId", 256)?;
        let meter = quota_name(member("meter").as_ref(), Some("meter"))?;
        let units = cost(member("cost").as_ref())?;
        let identity_id = member("identityId");
        let api_key_id = member("apiKeyId");
        let ctx = self.ctx.clone();
        ctx.store
            .clone()
            .transaction(|tx| async move {
                let realm = ctx.tenant(&tx, &tenant_id).await?;
                let identity = ctx
                    .active_identity(
                        &tx,
                        &text(identity_id.as_ref(), "identityId", 256)?,
                        &realm.id,
                    )
                    .await?;
                let mut key_id: Option<String> = None;
                if let Some(api_key_id) = &api_key_id {
                    let session_id = text(Some(api_key_id), "apiKeyId", 256)?;
                    let session = tx.get("sessions", &session_id).await?;
                    let valid = session.as_ref().is_some_and(|session| {
                        session.get("kind").and_then(Value::as_str) == Some("api-key")
                            && session.get("identityId").and_then(Value::as_str)
                                == Some(identity.id.as_str())
                    });
                    let Some(session) = session.filter(|_| valid) else {
                        return Err(IamError::with_status("NOT_FOUND", "API key not found", 404));
                    };
                    key_id = session.get("id").and_then(Value::as_str).map(str::to_owned);
                }
                let subject = QuotaSubject {
                    tenant_id: realm.id.clone(),
                    identity_id: identity.id.clone(),
                    api_key_id: key_id.filter(|key| !key.is_empty()),
                    agent_id: None,
                };
                let recorder = {
                    let ctx = ctx.clone();
                    let realm_id = realm.id.clone();
                    move |store: Store,
                          action: &'static str,
                          metadata: Map<String, Value>|
                          -> BoxFuture<'static, IamResult<()>> {
                        let ctx = ctx.clone();
                        let realm_id = realm_id.clone();
                        Box::pin(async move {
                            let mut event = Record::new();
                            event.insert("id".into(), Value::String(id()));
                            event.insert("tenantId".into(), Value::String(realm_id));
                            event.insert(
                                "actorId".into(),
                                Value::String("deployment-operator".into()),
                            );
                            event.insert("action".into(), Value::String(action.to_owned()));
                            event.insert(
                                "resourceId".into(),
                                Value::String(plan_resource(&js_string(metadata.get("plan")))),
                            );
                            event.insert("timestamp".into(), number(ctx.now()));
                            event.insert(
                                "outcome".into(),
                                Value::String(
                                    if action == "quota:exceeded" {
                                        "deny"
                                    } else {
                                        "allow"
                                    }
                                    .into(),
                                ),
                            );
                            event.insert("metadata".into(), Value::Object(metadata));
                            ctx.events()?.record_audit(&store, &event).await
                        })
                    }
                };
                consume_quota(&ctx, &tx, &subject, &meter, units, &recorder, false).await
            })
            .await
    }
    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        let request = args.first().cloned().unwrap_or(Value::Null);
        let decision = match method {
            "consume" => self.consume(&request).await,
            "enforce" => self.enforce(&request).await,
            "status" => self.status(&request).await,
            "consumeFor" => self.consume_for(&request).await,
            _ => return None,
        };
        Some(decision.map(|decision| decision.to_json()))
    }
}
