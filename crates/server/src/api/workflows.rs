//! Port of `packages/server/src/api/workflows.ts`.
//!
//! Identity lifecycle workflows: joiner, mover and leaver automation. A workflow has a trigger, a scope (the
//! access-package rule language over the person's attributes, groups, teams and departments) and steps (group and
//! package changes, emails, sign-outs, disabling, attribute and expiry changes, deletion, events for webhooks, and
//! waits). Steps run under the rights of whoever saved the workflow, re-checked at every step. Managing needs
//! `iam:workflows:manage`, reading `iam:workflows:read`, starting and retrying runs `iam:workflows:run`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::js::{self as core_js, to_lower};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, Identity, IdentityKind, IdentityStatus, OutboxKind, Record, Tenant,
    TenantStatus,
};
use better_iam_types::api::workflows;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::groups::{add_group_member, remove_group_member};
use crate::api::identities::{delete_identity, revoke_invitations_by};
use crate::api::package_automation::after_identity_change;
use crate::api::packages::{allow, assign_package, authorize_package, revoke_assignment};
use crate::api::{Body, Reply, string_member};
use crate::catalog::attribute_values;
use crate::context::{ServerContext, Store, SubscriberFn};
use crate::contracts::{Mutation, MutationContext, OperationDenied, OperationResult};
use crate::js::{invalid_input, js_string, number, truthy, utf16_len};
use crate::models::{AccessPackage, Group, GroupMember, PackageAssignment};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::org_rules::{TenantOrgFacts, load_org_facts, org_rule_environment};
use crate::package_rules::{rule_context, rule_document, rule_match};
use crate::port::{Callback, decode, undefined};
use crate::session_kinds::acts_in_own_right;
use crate::threats::end_containment;
use crate::utils::id;
use crate::validation::{integer, strings, text};
use crate::workflows::{
    DAY_MS, SubjectSnapshot, TemplateValues, TriggerWorkflow, date_target, default_brake,
    fill_template, is_destructive, parse_scope, parse_steps, parse_trigger, scope_environment,
    status_name, step_kind, trigger_kind, trigger_occurrence, utc_day,
};

const MAX_WORKFLOWS: usize = 100;
const LEASE_MS: f64 = 5.0 * 60_000.0;
/// Finished runs stay this long for review, then the retention sweep removes them.
const RUN_RETENTION_MS: f64 = 180.0 * 86_400_000.0;

/// Steps that change a person's own record: nobody may point them at themself through a workflow.
const SELF_CHANGING: &[&str] = &["set-attributes", "set-expiry", "enable"];

fn self_changing(step: &Value) -> bool {
    SELF_CHANGING.contains(&step_kind(step))
}

// --- small record helpers ----------------------------------------------------------------------------------------

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &FindOptions::default()).await
}

fn by_tenant(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id)
}

/// A string member of a record ("" when absent or not a string).
fn member_str<'a>(record: &'a Map<String, Value>, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// A numeric member of a record as JavaScript reads it (`undefined` → NaN).
fn member_num(record: &Map<String, Value>, key: &str) -> f64 {
    record.get(key).map(core_js::to_number).unwrap_or(f64::NAN)
}

/// `record.key ?? fallback` for a numeric member.
fn member_num_or(record: &Map<String, Value>, key: &str, fallback: f64) -> f64 {
    match record.get(key) {
        None | Some(Value::Null) => fallback,
        Some(value) => core_js::to_number(value),
    }
}

fn str_value(value: &str) -> Value {
    Value::String(value.to_owned())
}

/// The steps of a stored workflow or run.
fn steps_of(record: &Map<String, Value>) -> Vec<Value> {
    record
        .get("steps")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default()
}

/// `value.slice(0, max)` in UTF-16 code units (a surrogate pair is never split).
fn slice_utf16(value: &str, max: usize) -> String {
    if utf16_len(value) <= max {
        return value.to_owned();
    }
    let mut out = String::new();
    let mut units = 0;
    for c in value.chars() {
        let width = c.len_utf16();
        if units + width > max {
            break;
        }
        units += width;
        out.push(c);
    }
    out
}

/// Copies a member when the record has it (`key: record.key`, which JSON leaves out when undefined).
fn copy(out: &mut Map<String, Value>, record: &Map<String, Value>, key: &str) {
    if let Some(value) = record.get(key) {
        out.insert(key.to_owned(), value.clone());
    }
}

/// Copies a member when it is truthy (`...(record.key ? { key: record.key } : {})`).
fn copy_truthy(out: &mut Map<String, Value>, record: &Map<String, Value>, key: &str) {
    if truthy(record.get(key)) {
        copy(out, record, key);
    }
}

/// `{ leaseToken, leaseUntil, ...rest } = run`.
fn clear_lease(run: &mut Record) {
    run.shift_remove("leaseToken");
    run.shift_remove("leaseUntil");
}

/// A system audit event (`actorId: 'deployment-operator'`).
fn system_event(
    tenant_id: &str,
    action: &str,
    resource_id: &str,
    now: f64,
    outcome: &str,
    metadata: Map<String, Value>,
) -> Record {
    let mut event = Record::new();
    event.insert("id".into(), Value::String(id()));
    event.insert("tenantId".into(), str_value(tenant_id));
    event.insert("actorId".into(), str_value("deployment-operator"));
    event.insert("action".into(), str_value(action));
    event.insert("resourceId".into(), str_value(resource_id));
    event.insert("timestamp".into(), number(now));
    event.insert("outcome".into(), str_value(outcome));
    event.insert("metadata".into(), Value::Object(metadata));
    event
}

fn object_of(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `ctx.decisions.decide(tx, principal, { tenantId, action, resource: { type: 'iam', id } }, true).allowed`.
async fn decide_iam(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    action: &str,
    resource: &str,
) -> IamResult<bool> {
    Ok(ctx
        .decisions()?
        .decide(
            tx,
            principal,
            &AuthorizationRequest {
                credential: CredentialInput::default(),
                tenant_id: tenant_id.to_owned(),
                action: action.to_owned(),
                resource: ResourceTarget {
                    kind: "iam".into(),
                    id: resource.to_owned(),
                },
            },
            true,
        )
        .await?
        .allowed)
}

/// `ctx.activeIdentity(tx, identityId, tenantId)`, keeping the stored record for read-modify-write.
async fn active_identity_record(
    ctx: &ServerContext,
    tx: &Store,
    identity_id: &str,
    tenant_id: &str,
) -> IamResult<(Record, Identity)> {
    let record = ctx
        .scoped(tx, "identities", Some(&str_value(identity_id)), tenant_id)
        .await?;
    let identity: Identity = decode(record.clone())?;
    if identity.status == IdentityStatus::Deleted {
        return Err(IamError::with_status(
            "NOT_FOUND",
            "Identity has been deleted",
            404,
        ));
    }
    Ok((record, identity))
}

// --- module helpers -----------------------------------------------------------------------------------------------

/// The rights a step needs, as the owner would need them by hand: [action, resource] pairs.
fn requirements(step: &Value, tenant_id: &str, identity_id: Option<&str>) -> Vec<(String, String)> {
    let person = identity_id.unwrap_or(tenant_id).to_owned();
    let member = |key: &str| js_string(step.get(key));
    match step_kind(step) {
        "add-to-group" | "remove-from-group" => {
            vec![("iam:groups:update".into(), member("groupId"))]
        }
        "assign-package" => vec![("iam:packages:assign".into(), member("packageId"))],
        "revoke-packages" => {
            if truthy(step.get("packageId")) {
                vec![("iam:packages:assign".into(), member("packageId"))]
            } else {
                Vec::new()
            }
        }
        "revoke-sessions" | "disable" | "enable" | "set-attributes" | "set-expiry" => {
            vec![("iam:identities:update".into(), person)]
        }
        "delete" => vec![("iam:identities:delete".into(), person)],
        // An email carries the person's name, address and attributes: whoever automates it must be able to read them.
        "send-email" => vec![("iam:identities:read".into(), person)],
        _ => Vec::new(),
    }
}

/// Where a literal `send-email` address may point: an address of an active member of the organization, or one at a
/// domain the organization verified, so a workflow cannot mail people's details (or phishing) to arbitrary outsiders.
async fn assert_recipients(tx: &Store, tenant_id: &str, steps: &[Value]) -> IamResult<()> {
    let literal: Vec<String> = steps
        .iter()
        .filter(|step| step_kind(step) == "send-email")
        .map(|step| js_string(step.get("to")))
        .filter(|to| to != "subject" && to != "manager")
        .collect();
    if literal.is_empty() {
        return Ok(());
    }
    let domains: IndexSet<String> = find(tx, "tenantDomains", by_tenant(tenant_id))
        .await?
        .iter()
        .filter(|record| record.get("status").and_then(Value::as_str) == Some("verified"))
        .map(|record| to_lower(&js_string(record.get("domain"))))
        .collect();
    for address in literal {
        let domain = match address.rfind('@') {
            Some(at) => &address[at + 1..],
            None => address.as_str(),
        };
        if domains.contains(domain) {
            continue;
        }
        let member = find(
            tx,
            "identities",
            by_tenant(tenant_id).eq("email", address.clone()),
        )
        .await?
        .iter()
        .any(|identity| identity.get("status").and_then(Value::as_str) == Some("active"));
        if !member {
            return Err(invalid_input(format!(
                "send-email may address subject, manager, a member of the organization, or a verified domain (not {address})"
            )));
        }
    }
    Ok(())
}

fn workflow_view(
    workflow: &Map<String, Value>,
    owner_name: Option<&str>,
    runs: Option<Value>,
) -> Value {
    let mut view = Map::new();
    copy(&mut view, workflow, "id");
    copy(&mut view, workflow, "tenantId");
    copy(&mut view, workflow, "name");
    copy_truthy(&mut view, workflow, "description");
    copy(&mut view, workflow, "enabled");
    copy(&mut view, workflow, "trigger");
    copy_truthy(&mut view, workflow, "scope");
    copy(&mut view, workflow, "steps");
    copy(&mut view, workflow, "includeExisting");
    copy(&mut view, workflow, "maxRunsPerDay");
    copy(&mut view, workflow, "ownerId");
    if let Some(name) = owner_name.filter(|name| !name.is_empty()) {
        view.insert("ownerName".into(), str_value(name));
    }
    copy(&mut view, workflow, "version");
    copy(&mut view, workflow, "activeSince");
    copy_truthy(&mut view, workflow, "brakedOn");
    copy(&mut view, workflow, "createdAt");
    copy(&mut view, workflow, "updatedAt");
    if let Some(runs) = runs {
        view.insert("runs".into(), runs);
    }
    Value::Object(view)
}

fn run_view(run: &Map<String, Value>, identity_name: Option<&str>) -> Value {
    let mut view = Map::new();
    copy(&mut view, run, "id");
    copy(&mut view, run, "workflowId");
    copy(&mut view, run, "workflowName");
    copy(&mut view, run, "workflowVersion");
    copy(&mut view, run, "identityId");
    if let Some(name) = identity_name.filter(|name| !name.is_empty()) {
        view.insert("identityName".into(), str_value(name));
    }
    copy(&mut view, run, "occurrence");
    copy(&mut view, run, "trigger");
    copy(&mut view, run, "steps");
    copy(&mut view, run, "status");
    copy(&mut view, run, "stepIndex");
    copy(&mut view, run, "nextAt");
    copy(&mut view, run, "results");
    copy(&mut view, run, "startedAt");
    copy(&mut view, run, "finishedAt");
    copy_truthy(&mut view, run, "startedBy");
    copy_truthy(&mut view, run, "error");
    Value::Object(view)
}

/// `input.key ?? fallback`: a member that is absent or null is replaced.
fn present(value: Option<&Value>) -> Option<&Value> {
    value.filter(|value| !value.is_null())
}

/// Validates a workflow's parts and the groups and packages its steps name. Answers the members TypeScript spreads
/// into the record, in its order.
async fn workflow_fields(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    input: &Map<String, Value>,
    previous: Option<&Record>,
) -> IamResult<Map<String, Value>> {
    let attributes = &ctx.catalog.identity_attributes;
    let name = text(
        present(input.get("name")).or_else(|| previous.and_then(|previous| previous.get("name"))),
        "name",
        120,
    )?;
    let name = core_js::trim(&name).to_owned();
    if name.is_empty() {
        return Err(invalid_input("name is required"));
    }
    let description = match input.get("description") {
        None => previous.and_then(|previous| previous.get("description").cloned()),
        Some(Value::Null) => None,
        Some(Value::String(value)) if value.is_empty() => None,
        Some(value) => Some(Value::String(text(Some(value), "description", 1000)?)),
    };
    if previous.is_none() && (input.get("trigger").is_none() || input.get("steps").is_none()) {
        return Err(invalid_input("A workflow needs a trigger and steps"));
    }
    let trigger = match (input.get("trigger"), previous) {
        (None, Some(previous)) => previous.get("trigger").cloned().unwrap_or(Value::Null),
        (value, _) => parse_trigger(value, attributes)?,
    };
    let steps = match (input.get("steps"), previous) {
        (None, Some(previous)) => steps_of(previous),
        (value, _) => parse_steps(value, attributes)?,
    };
    let groups = find(tx, "groups", by_tenant(tenant_id)).await?;
    let group_ids: IndexSet<String> = groups
        .iter()
        .map(|group| member_str(group, "id").to_owned())
        .collect();
    let scope = match input.get("scope") {
        None => previous.and_then(|previous| previous.get("scope").cloned()),
        Some(value) => {
            let env = scope_environment(
                attributes,
                group_ids,
                org_rule_environment(tx, tenant_id).await?,
            );
            parse_scope(Some(value), &env)?
                .map(|scope| serde_json::to_value(scope).map_err(|_| crate::js::internal_error()))
                .transpose()?
        }
    };
    for step in &steps {
        let kind = step_kind(step);
        if kind == "add-to-group" || kind == "remove-from-group" {
            let group_id = js_string(step.get("groupId"));
            let Some(group) = groups
                .iter()
                .find(|item| member_str(item, "id") == group_id)
            else {
                return Err(invalid_input(format!("Unknown group {group_id}")));
            };
            if truthy(group.get("teamId")) {
                return Err(IamError::with_status(
                    "TEAM_MANAGED",
                    format!(
                        "{} belongs to a team; add people to the team instead",
                        js_string(group.get("name"))
                    ),
                    409,
                ));
            }
        }
        if kind == "assign-package" || (kind == "revoke-packages" && truthy(step.get("packageId")))
        {
            ctx.scoped(tx, "accessPackages", step.get("packageId"), tenant_id)
                .await?;
        }
    }
    assert_recipients(tx, tenant_id, &steps).await?;
    let include_existing = present(input.get("includeExisting"))
        .or_else(|| present(previous.and_then(|previous| previous.get("includeExisting"))))
        .cloned()
        .unwrap_or(Value::Bool(false));
    if !include_existing.is_boolean() {
        return Err(invalid_input("includeExisting must be a boolean"));
    }
    let max_runs_per_day = match input.get("maxRunsPerDay") {
        None => present(previous.and_then(|previous| previous.get("maxRunsPerDay")))
            .cloned()
            .unwrap_or_else(|| number(default_brake(&steps))),
        Some(value) => number(integer(Some(value), "maxRunsPerDay", 1.0, 10_000.0)?),
    };
    let enabled = present(input.get("enabled"))
        .or_else(|| present(previous.and_then(|previous| previous.get("enabled"))))
        .cloned()
        .unwrap_or(Value::Bool(true));
    if !enabled.is_boolean() {
        return Err(invalid_input("enabled must be a boolean"));
    }
    let mut values = Map::new();
    values.insert(
        "uniqueKey".into(),
        Value::String(format!("name:{}", to_lower(&name))),
    );
    values.insert("name".into(), Value::String(name));
    if let Some(description) = description.filter(|value| truthy(Some(value))) {
        values.insert("description".into(), description);
    }
    values.insert("enabled".into(), enabled);
    values.insert("trigger".into(), trigger);
    if let Some(scope) = scope.filter(|value| truthy(Some(value))) {
        values.insert("scope".into(), scope);
    }
    values.insert("steps".into(), Value::Array(steps));
    values.insert("includeExisting".into(), include_existing);
    values.insert("maxRunsPerDay".into(), max_runs_per_day);
    Ok(values)
}

/// The saver becomes the workflow's owner: they must be a person or service account acting in their own right, and
/// hold every right the steps use, so nobody automates what they could not do by hand.
async fn assert_owner_rights(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    steps: &[Value],
    identity_ids: &[Option<String>],
) -> OperationResult<()> {
    if !acts_in_own_right(principal.session.kind)
        || principal
            .session
            .impersonator_id
            .as_deref()
            .is_some_and(|value| !value.is_empty())
    {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Workflows are saved and run from a signed-in session or an API key of their own",
            403,
        )
        .into());
    }
    if principal.identity.tenant_id != tenant_id && !ctx.root_principal(tx, principal).await? {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            "Workflows are managed from their own organization",
            403,
        )
        .into());
    }
    for identity_id in identity_ids {
        for step in steps {
            for (action, resource) in requirements(step, tenant_id, identity_id.as_deref()) {
                if !decide_iam(ctx, tx, principal, tenant_id, &action, &resource).await? {
                    return Err(OperationDenied::new(Some(&format!(
                        "The {} step needs {action} on {resource}, which you do not have",
                        step_kind(step)
                    ))));
                }
            }
        }
    }
    if steps.iter().any(|step| step_kind(step) == "assign-package") {
        for step in steps {
            if step_kind(step) == "assign-package" {
                let pkg: AccessPackage = decode(
                    ctx.scoped(tx, "accessPackages", step.get("packageId"), tenant_id)
                        .await?,
                )?;
                authorize_package(ctx, tx, principal, &pkg, None).await?;
            }
        }
    }
    Ok(())
}

/// Baselines for mover and leaver triggers, so only changes after this moment fire.
async fn rebuild_snapshots(tx: &Store, workflow: &Record, now: f64) -> IamResult<()> {
    let tenant_id = member_str(workflow, "tenantId");
    let workflow_id = member_str(workflow, "id");
    for subject in find(
        tx,
        "workflowSubjects",
        by_tenant(tenant_id).eq("workflowId", workflow_id),
    )
    .await?
    {
        tx.delete("workflowSubjects", member_str(&subject, "id"))
            .await?;
    }
    let kind = trigger_kind(workflow.get("trigger").unwrap_or(&Value::Null));
    if kind != "mover" && kind != "leaver" {
        return Ok(());
    }
    let shape = TriggerWorkflow::of_record(workflow);
    for record in find(tx, "identities", by_tenant(tenant_id)).await? {
        let identity: Identity = decode(record)?;
        if identity.kind != IdentityKind::User || identity.status == IdentityStatus::Deleted {
            continue;
        }
        let outcome = trigger_occurrence(&shape, &identity, None, now)?;
        if let Some(snapshot) = outcome.snapshot {
            let mut subject = Record::new();
            subject.insert("id".into(), Value::String(id()));
            subject.insert("tenantId".into(), str_value(tenant_id));
            subject.insert(
                "uniqueKey".into(),
                Value::String(format!("{workflow_id}:{}", identity.id)),
            );
            subject.insert("workflowId".into(), str_value(workflow_id));
            subject.insert("identityId".into(), Value::String(identity.id.clone()));
            subject.insert("values".into(), Value::Object(snapshot.values));
            subject.insert("status".into(), Value::String(snapshot.status));
            subject.insert("fired".into(), number(snapshot.fired));
            tx.insert("workflowSubjects", &subject).await?;
        }
    }
    Ok(())
}

// --- the run engine -----------------------------------------------------------------------------------------------

/// What a step did.
struct StepOutcome {
    outcome: &'static str,
    detail: Option<String>,
    changed: bool,
}

impl StepOutcome {
    fn done(detail: Option<String>, changed: bool) -> Self {
        Self {
            outcome: "done",
            detail,
            changed,
        }
    }

    fn skipped(detail: impl Into<String>) -> Self {
        Self {
            outcome: "skipped",
            detail: Some(detail.into()),
            changed: false,
        }
    }
}

/// `WorkflowJobResult`.
#[derive(Debug, Default, Clone, Copy)]
struct JobResult {
    started: f64,
    executed: f64,
    completed: f64,
    failed: f64,
    waiting: f64,
}

impl JobResult {
    fn to_json(self) -> Value {
        json!({
            "started": number(self.started),
            "executed": number(self.executed),
            "completed": number(self.completed),
            "failed": number(self.failed),
            "waiting": number(self.waiting),
        })
    }
}

/// How a step transaction ended.
enum Next {
    Stop,
    Continue,
}

/// A person a run would start for (`candidates` of `evaluateWorkflow`).
struct Candidate {
    identity: Identity,
    occurrence: String,
    snapshot: Option<SubjectSnapshot>,
}

/// The run engine, shared by the API and the scheduler runtime.
#[derive(Clone)]
struct Engine {
    ctx: Arc<ServerContext>,
}

impl Engine {
    fn can_email(&self) -> bool {
        self.ctx
            .options
            .authentication
            .as_ref()
            .is_some_and(|authentication| authentication.send_email.is_some())
    }

    /// A step that takes something away (or rewrites the record) never reaches owners, root administrators, or the
    /// workflow's owner; nobody changes their own record through a workflow they own or started (identities.update
    /// refuses that to non-owners by hand); re-enabling a root administrator needs a root owner, as setStatus does.
    async fn protect(
        &self,
        tx: &Store,
        step: &Value,
        target: &Identity,
        owner: &AuthenticatedPrincipal,
        run: &Record,
    ) -> IamResult<()> {
        let kind = step_kind(step);
        let guarded = is_destructive(kind) || kind == "set-expiry" || kind == "set-attributes";
        if guarded && (target.owner || target.root_admin) {
            return Err(IamError::with_status(
                "PROTECTED_RESOURCE",
                "Workflows never disable, delete, sign out, strip access from, or edit owners or root administrators",
                403,
            ));
        }
        if guarded && target.id == owner.identity.id {
            return Err(invalid_input(
                "A workflow does not act against its own owner",
            ));
        }
        if self_changing(step)
            && (target.id == owner.identity.id
                || run.get("startedBy").and_then(Value::as_str) == Some(target.id.as_str()))
        {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                "Nobody changes their own account through a workflow they own or started",
                403,
            ));
        }
        if kind == "enable" && target.root_admin && !self.ctx.root_principal(tx, owner).await? {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                "Root capability is protected",
                403,
            ));
        }
        Ok(())
    }

    /// The audit event of a step's change: `{ ...metadata, via: 'workflow', workflowId, runId }`.
    #[allow(clippy::too_many_arguments)]
    async fn step_audit(
        &self,
        tx: &Store,
        owner: &AuthenticatedPrincipal,
        tenant_id: &str,
        run: &Record,
        action: &str,
        resource_id: &str,
        mut metadata: Map<String, Value>,
    ) -> IamResult<()> {
        metadata.insert("via".into(), str_value("workflow"));
        metadata.insert(
            "workflowId".into(),
            run.get("workflowId").cloned().unwrap_or(Value::Null),
        );
        metadata.insert(
            "runId".into(),
            run.get("id").cloned().unwrap_or(Value::Null),
        );
        self.ctx
            .events()?
            .audit(
                tx,
                owner,
                action,
                tenant_id,
                resource_id,
                AuditOutcome::Allow,
                false,
                Some(metadata),
            )
            .await
    }

    async fn perform(
        &self,
        tx: &Store,
        owner: &AuthenticatedPrincipal,
        tenant: &Tenant,
        run: &Record,
        step: &Value,
    ) -> OperationResult<StepOutcome> {
        let ctx = &self.ctx;
        let tenant_id = tenant.id.as_str();
        let (mut target_record, target) =
            active_identity_record(ctx, tx, member_str(run, "identityId"), tenant_id).await?;
        self.protect(tx, step, &target, owner, run).await?;
        let kind = step_kind(step);
        if kind == "send-email" {
            assert_recipients(tx, tenant_id, std::slice::from_ref(step)).await?;
        }
        for (action, resource) in requirements(step, tenant_id, Some(&target.id)) {
            allow(
                ctx,
                tx,
                owner,
                tenant_id,
                &action,
                &resource,
                &format!("run the {kind} step"),
            )
            .await?;
        }
        let now = ctx.now();
        let identity_meta = |extra: Value| {
            let mut metadata = Map::new();
            metadata.insert("identityId".into(), Value::String(target.id.clone()));
            metadata.extend(object_of(extra));
            metadata
        };
        let days_ms = |key: &str| -> Option<f64> {
            truthy(step.get(key))
                .then(|| now + step.get(key).map(core_js::to_number).unwrap_or(f64::NAN) * DAY_MS)
        };
        match kind {
            "add-to-group" => {
                let group_record = ctx
                    .scoped(tx, "groups", step.get("groupId"), tenant_id)
                    .await?;
                let group: Group = decode(group_record)?;
                // Already a member (a joiner run for someone who was added by hand, say): nothing to do.
                let mut already = false;
                for record in find(
                    tx,
                    "groupMembers",
                    by_tenant(tenant_id)
                        .eq("groupId", group.id.clone())
                        .eq("identityId", target.id.clone()),
                )
                .await?
                {
                    let member: GroupMember = decode(record)?;
                    if ctx.live_membership(&member) {
                        already = true;
                        break;
                    }
                }
                if already {
                    return Ok(StepOutcome::skipped(format!("already in {}", group.name)));
                }
                let mut input = Map::new();
                input.insert("tenantId".into(), str_value(tenant_id));
                input.insert("groupId".into(), Value::String(group.id.clone()));
                input.insert("identityId".into(), Value::String(target.id.clone()));
                if let Some(expires_at) = days_ms("days") {
                    input.insert("expiresAt".into(), number(expires_at));
                }
                add_group_member(ctx, tx, owner, &Value::Object(input)).await?;
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "iam:groups:update",
                    &group.id,
                    identity_meta(json!({ "added": true })),
                )
                .await?;
                Ok(StepOutcome::done(Some(group.name), true))
            }
            "remove-from-group" => {
                let group_record = ctx
                    .scoped(tx, "groups", step.get("groupId"), tenant_id)
                    .await?;
                let group: Group = decode(group_record)?;
                let members = find(
                    tx,
                    "groupMembers",
                    by_tenant(tenant_id)
                        .eq("groupId", group.id.clone())
                        .eq("identityId", target.id.clone()),
                )
                .await?;
                if members.is_empty() {
                    return Ok(StepOutcome::skipped(format!("not in {}", group.name)));
                }
                remove_group_member(
                    ctx,
                    tx,
                    owner,
                    &json!({ "tenantId": tenant_id, "groupId": group.id, "identityId": target.id }),
                )
                .await?;
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "iam:groups:update",
                    &group.id,
                    identity_meta(json!({ "removed": true })),
                )
                .await?;
                Ok(StepOutcome::done(Some(group.name), true))
            }
            "remove-from-all-groups" => {
                // Memberships a team or an access package manages are left to them.
                let memberships: Vec<Record> = find(
                    tx,
                    "groupMembers",
                    by_tenant(tenant_id).eq("identityId", target.id.clone()),
                )
                .await?
                .into_iter()
                .filter(|member| {
                    !truthy(member.get("teamId")) && !truthy(member.get("packageAssignmentId"))
                })
                .collect();
                let mut groups = crate::js::unique(
                    memberships
                        .iter()
                        .map(|member| js_string(member.get("groupId"))),
                );
                crate::js::sort_strings(&mut groups);
                for group_id in &groups {
                    allow(
                        ctx,
                        tx,
                        owner,
                        tenant_id,
                        "iam:groups:update",
                        group_id,
                        "remove from a group",
                    )
                    .await?;
                    remove_group_member(
                        ctx,
                        tx,
                        owner,
                        &json!({ "tenantId": tenant_id, "groupId": group_id, "identityId": target.id }),
                    )
                    .await?;
                    self.step_audit(
                        tx,
                        owner,
                        tenant_id,
                        run,
                        "iam:groups:update",
                        group_id,
                        identity_meta(json!({ "removed": true })),
                    )
                    .await?;
                }
                Ok(if groups.is_empty() {
                    StepOutcome::skipped("in no groups")
                } else {
                    StepOutcome::done(Some(format!("{} groups", groups.len())), true)
                })
            }
            "assign-package" => {
                let pkg: AccessPackage = decode(
                    ctx.scoped(tx, "accessPackages", step.get("packageId"), tenant_id)
                        .await?,
                )?;
                let mut input = Map::new();
                input.insert("identityId".into(), Value::String(target.id.clone()));
                if let Some(expires_at) = days_ms("days") {
                    input.insert("expiresAt".into(), number(expires_at));
                }
                input.insert(
                    "justification".into(),
                    Value::String(format!("Workflow: {}", member_str(run, "workflowName"))),
                );
                let assigned =
                    assign_package(ctx, tx, owner, &pkg, &Value::Object(input), None).await?;
                let assignment = assigned.get("assignment");
                let count = |key: &str| {
                    assignment
                        .and_then(|assignment| assignment.get(key))
                        .and_then(Value::as_array)
                        .map_or(0, Vec::len)
                };
                let mut metadata = Map::new();
                metadata.insert("packageId".into(), Value::String(pkg.id.clone()));
                metadata.insert("packageName".into(), Value::String(pkg.name.clone()));
                metadata.insert("identityId".into(), Value::String(target.id.clone()));
                metadata.insert("bindings".into(), json!(count("bindingIds")));
                metadata.insert("memberships".into(), json!(count("membershipIds")));
                if let Some(skipped) = assigned.get("skipped") {
                    metadata.insert("skipped".into(), skipped.clone());
                }
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "package:assign",
                    &pkg.id,
                    metadata,
                )
                .await?;
                Ok(StepOutcome::done(Some(pkg.name), true))
            }
            "revoke-packages" => {
                // Assignments a package rule made belong to the rule (packages.revoke refuses them too): it removes
                // them itself once the person no longer matches.
                let package_id = step.get("packageId").filter(|value| truthy(Some(value)));
                let assignments: Vec<Record> = find(
                    tx,
                    "packageAssignments",
                    by_tenant(tenant_id).eq("identityId", target.id.clone()),
                )
                .await?
                .into_iter()
                .filter(|assignment| {
                    package_id.is_none_or(|wanted| assignment.get("packageId") == Some(wanted))
                        && assignment.get("ruleRevision").is_none()
                })
                .collect();
                for record in &assignments {
                    let package = js_string(record.get("packageId"));
                    allow(
                        ctx,
                        tx,
                        owner,
                        tenant_id,
                        "iam:packages:assign",
                        &package,
                        "revoke a package",
                    )
                    .await?;
                    let assignment: PackageAssignment = decode(record.clone())?;
                    revoke_assignment(ctx, tx, &assignment).await?;
                    self.step_audit(
                        tx,
                        owner,
                        tenant_id,
                        run,
                        "package:revoke",
                        &package,
                        json!({ "packageId": package, "identityId": target.id })
                            .as_object()
                            .cloned()
                            .unwrap_or_default(),
                    )
                    .await?;
                }
                Ok(if assignments.is_empty() {
                    StepOutcome::skipped("no packages")
                } else {
                    StepOutcome::done(Some(format!("{} packages", assignments.len())), true)
                })
            }
            "send-email" => {
                if !self.can_email() {
                    return Ok(StepOutcome::skipped("no email delivery configured"));
                }
                let recipient = js_string(step.get("to"));
                let to = match recipient.as_str() {
                    "subject" => target.email.clone(),
                    "manager" => {
                        let manager = match target.manager_id.as_deref().filter(|id| !id.is_empty())
                        {
                            Some(manager_id) => tx.get("identities", manager_id).await?,
                            None => None,
                        };
                        match manager {
                            Some(manager)
                                if manager.get("status").and_then(Value::as_str)
                                    == Some("active") =>
                            {
                                manager
                                    .get("email")
                                    .and_then(Value::as_str)
                                    .map(str::to_owned)
                            }
                            _ => None,
                        }
                    }
                    _ => Some(recipient.clone()),
                };
                let Some(to) = to.filter(|to| !to.is_empty()) else {
                    return Ok(StepOutcome::skipped(format!("no address for {recipient}")));
                };
                let workflow_name = member_str(run, "workflowName");
                let values = TemplateValues {
                    identity: &target,
                    organization: &tenant.name,
                    workflow: workflow_name,
                };
                let mut payload = Map::new();
                payload.insert("tenantId".into(), str_value(tenant_id));
                payload.insert("tenantName".into(), Value::String(tenant.name.clone()));
                payload.insert("workflowName".into(), str_value(workflow_name));
                payload.insert(
                    "subject".into(),
                    Value::String(slice_utf16(
                        &fill_template(&js_string(step.get("subject")), &values),
                        300,
                    )),
                );
                payload.insert(
                    "body".into(),
                    Value::String(slice_utf16(
                        &fill_template(&js_string(step.get("body")), &values),
                        10_000,
                    )),
                );
                ctx.auth
                    .enqueue_delivery(
                        tx,
                        EnqueueInput {
                            tenant_id: tenant_id.to_owned(),
                            kind: OutboxKind::Email,
                            to: to.clone(),
                            template: "workflow-message".into(),
                            payload,
                            reference: None,
                        },
                    )
                    .await?;
                Ok(StepOutcome::done(
                    Some(if recipient == to {
                        "sent".to_owned()
                    } else {
                        format!("sent to {recipient}")
                    }),
                    false,
                ))
            }
            "revoke-sessions" => {
                ctx.revoke_all(tx, &target.id).await?;
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "identity:revoke-sessions",
                    &target.id,
                    Map::new(),
                )
                .await?;
                Ok(StepOutcome::done(None, false))
            }
            "disable" => {
                if target.status == IdentityStatus::Disabled {
                    return Ok(StepOutcome::skipped("already disabled"));
                }
                ctx.protect_last_owner(tx, &target).await?;
                target_record.insert("status".into(), str_value("disabled"));
                tx.put("identities", &target_record).await?;
                end_containment(tx, &target.id, ctx.now()).await?;
                ctx.revoke_all(tx, &target.id).await?;
                // As setStatus does: invitations the person sent (or, for guests, sponsors) and nobody redeemed yet
                // are revoked, so re-enabling them later does not bring the tokens back.
                revoke_invitations_by(tx, &target.id).await?;
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "iam:identities:update",
                    &target.id,
                    json!({ "status": "disabled" })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                )
                .await?;
                Ok(StepOutcome::done(None, true))
            }
            "enable" => {
                if target.status == IdentityStatus::Active {
                    return Ok(StepOutcome::skipped("already active"));
                }
                if ctx.identity_expired(&target) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "The account has expired; extend or clear expiresAt first",
                        409,
                    )
                    .into());
                }
                target_record.insert("status".into(), str_value("active"));
                tx.put("identities", &target_record).await?;
                // As setStatus does: re-enabling ends a threats containment.
                end_containment(tx, &target.id, ctx.now()).await?;
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "iam:identities:update",
                    &target.id,
                    json!({ "status": "active" })
                        .as_object()
                        .cloned()
                        .unwrap_or_default(),
                )
                .await?;
                Ok(StepOutcome::done(None, true))
            }
            "set-attributes" => {
                let mut next = target.attributes.clone().unwrap_or_default();
                let mut setting = Map::new();
                let attributes = step
                    .get("attributes")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default();
                for (name, value) in core_js::entries(&attributes) {
                    if value.is_null() {
                        next.shift_remove(name);
                    } else {
                        setting.insert(name.clone(), value.clone());
                    }
                }
                for (name, value) in attribute_values(
                    &ctx.catalog.identity_attributes,
                    Some(&Value::Object(setting)),
                )? {
                    next.insert(name, value);
                }
                target_record.shift_remove("attributes");
                if !next.is_empty() {
                    target_record.insert("attributes".into(), Value::Object(next));
                }
                tx.put("identities", &target_record).await?;
                let mut names: Vec<String> =
                    core_js::keys(&attributes).into_iter().cloned().collect();
                crate::js::sort_strings(&mut names);
                let mut metadata = Map::new();
                metadata.insert("attributes".into(), json!(names));
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "iam:identities:update",
                    &target.id,
                    metadata,
                )
                .await?;
                Ok(StepOutcome::done(None, true))
            }
            "set-expiry" => {
                let expires_at = match step.get("days") {
                    None | Some(Value::Null) => None,
                    Some(days) => Some(now + core_js::to_number(days) * DAY_MS),
                };
                target_record.shift_remove("expiresAt");
                if let Some(expires_at) = expires_at {
                    target_record.insert("expiresAt".into(), number(expires_at));
                }
                tx.put("identities", &target_record).await?;
                let mut metadata = Map::new();
                metadata.insert("expiresAt".into(), expires_at.map_or(Value::Null, number));
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "iam:identities:update",
                    &target.id,
                    metadata,
                )
                .await?;
                Ok(StepOutcome::done(None, true))
            }
            "delete" => {
                delete_identity(ctx, tx, owner, &target).await?;
                let mut metadata = Map::new();
                metadata.insert(
                    "kind".into(),
                    serde_json::to_value(target.kind).unwrap_or(Value::Null),
                );
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "identity:delete",
                    &target.id,
                    metadata,
                )
                .await?;
                Ok(StepOutcome::done(None, true))
            }
            "emit-event" => {
                let name = js_string(step.get("name"));
                let mut metadata = Map::new();
                metadata.insert("name".into(), Value::String(name.clone()));
                self.step_audit(
                    tx,
                    owner,
                    tenant_id,
                    run,
                    "workflow:event",
                    &target.id,
                    metadata,
                )
                .await?;
                Ok(StepOutcome::done(Some(name), false))
            }
            "wait" => Ok(StepOutcome::done(None, false)),
            // A stored step of no known kind: TypeScript's switch answers undefined and reading its outcome throws.
            _ => Err(crate::js::internal_error().into()),
        }
    }

    /// One step of a claimed run, in its own transaction.
    async fn step(&self, run_id: &str, token: &str) -> IamResult<(Next, bool, String, String)> {
        let ctx = &self.ctx;
        ctx.store
            .transaction(|tx| async move {
                let Some(mut run) = tx.get("workflowRuns", run_id).await? else {
                    return Ok((Next::Stop, false, String::new(), String::new()));
                };
                if run.get("leaseToken").and_then(Value::as_str) != Some(token)
                    || member_str(&run, "status") != "running"
                {
                    return Ok((Next::Stop, false, String::new(), String::new()));
                }
                let tenant_id = member_str(&run, "tenantId").to_owned();
                let identity_id = member_str(&run, "identityId").to_owned();
                let now = ctx.now();
                let steps = steps_of(&run);
                let step_index = member_num(&run, "stepIndex");
                if step_index >= steps.len() as f64 {
                    clear_lease(&mut run);
                    run.insert("status".into(), str_value("completed"));
                    run.insert("finishedAt".into(), number(now));
                    run.insert("expiresAt".into(), number(now + RUN_RETENTION_MS));
                    tx.put("workflowRuns", &run).await?;
                    let mut metadata = Map::new();
                    copy(&mut metadata, &run, "workflowId");
                    copy(&mut metadata, &run, "identityId");
                    ctx.events()?
                        .record_audit(
                            &tx,
                            &system_event(
                                &tenant_id,
                                "workflow:run:complete",
                                member_str(&run, "id"),
                                now,
                                "allow",
                                metadata,
                            ),
                        )
                        .await?;
                    return Ok((Next::Stop, false, tenant_id, identity_id));
                }
                if tx
                    .get("workflows", member_str(&run, "workflowId"))
                    .await?
                    .is_none()
                {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "The workflow was deleted",
                        404,
                    ));
                }
                // The rights of the owner who approved these steps: a later editor never lends theirs to old step
                // lists.
                let owner = match tx.get("identities", member_str(&run, "ownerId")).await? {
                    Some(record) => Some(decode::<Identity>(record)?),
                    None => None,
                };
                let owner = match owner {
                    Some(owner)
                        if owner.status == IdentityStatus::Active
                            && !ctx.identity_expired(&owner) =>
                    {
                        owner
                    }
                    _ => {
                        return Err(IamError::with_status(
                            "OWNER_INACTIVE",
                            "The owner of these steps is no longer active; cancel the run, or save the workflow again and start a new one",
                            409,
                        ));
                    }
                };
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                if tenant.status != TenantStatus::Active {
                    return Err(IamError::with_status(
                        "TENANT_INACTIVE",
                        "Tenant inactive",
                        403,
                    ));
                }
                let step = steps
                    .get(step_index as usize)
                    .cloned()
                    .unwrap_or(Value::Null);
                let mut results = run
                    .get("results")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if step_kind(&step) == "wait" {
                    let until = now + member_num(step.as_object().unwrap_or(&Map::new()), "hours") * 3_600_000.0;
                    let iso = core_js::iso_string(until).ok_or_else(|| {
                        IamError::from(crate::js::ThrownError::new(
                            "RangeError",
                            "Invalid time value",
                        ))
                    })?;
                    clear_lease(&mut run);
                    run.insert("status".into(), str_value("waiting"));
                    run.insert("nextAt".into(), number(until));
                    run.insert("stepIndex".into(), number(step_index + 1.0));
                    results.push(json!({
                        "index": number(step_index),
                        "kind": "wait",
                        "outcome": "done",
                        "at": number(now),
                        "detail": format!("until {iso}"),
                    }));
                    run.insert("results".into(), Value::Array(results));
                    tx.put("workflowRuns", &run).await?;
                    return Ok((Next::Stop, false, tenant_id, identity_id));
                }
                let principal = ctx.decisions()?.simulated_principal(
                    &owner,
                    run.get("ownerMfa") == Some(&Value::Bool(true)),
                );
                let result = self
                    .perform(&tx, &principal, &tenant, &run, &step)
                    .await
                    .map_err(IamError::from)?;
                let kind = step_kind(&step).to_owned();
                let mut entry = Map::new();
                entry.insert("index".into(), number(step_index));
                entry.insert("kind".into(), Value::String(kind.clone()));
                entry.insert("outcome".into(), str_value(result.outcome));
                entry.insert("at".into(), number(now));
                if let Some(detail) = result.detail.as_deref().filter(|detail| !detail.is_empty()) {
                    entry.insert("detail".into(), Value::String(slice_utf16(detail, 300)));
                }
                results.push(Value::Object(entry));
                run.insert("stepIndex".into(), number(step_index + 1.0));
                run.insert("leaseUntil".into(), number(now + LEASE_MS));
                run.insert("results".into(), Value::Array(results));
                tx.put("workflowRuns", &run).await?;
                let mut metadata = Map::new();
                copy(&mut metadata, &run, "workflowId");
                copy(&mut metadata, &run, "identityId");
                metadata.insert("index".into(), number(step_index));
                metadata.insert("kind".into(), Value::String(kind));
                metadata.insert("outcome".into(), str_value(result.outcome));
                ctx.events()?
                    .record_audit(
                        &tx,
                        &system_event(
                            &tenant_id,
                            "workflow:step",
                            member_str(&run, "id"),
                            now,
                            "allow",
                            metadata,
                        ),
                    )
                    .await?;
                Ok((Next::Continue, result.changed, tenant_id, identity_id))
            })
            .await
    }

    /// Records a run's failure (the `catch` of `execute`).
    async fn fail(&self, run_id: &str, token: &str, error: &IamError) -> IamResult<()> {
        let ctx = &self.ctx;
        let code = error.code.clone();
        let message = slice_utf16(&error.message, 500);
        ctx.store
            .transaction(|tx| async move {
                let Some(mut run) = tx.get("workflowRuns", run_id).await? else {
                    return Ok(());
                };
                if run.get("leaseToken").and_then(Value::as_str) != Some(token) {
                    return Ok(());
                }
                let now = ctx.now();
                let step_index = member_num(&run, "stepIndex");
                let steps = steps_of(&run);
                let step = if step_index >= 0.0 && step_index.fract() == 0.0 {
                    steps.get(step_index as usize).cloned()
                } else {
                    None
                };
                let mut results = run
                    .get("results")
                    .and_then(Value::as_array)
                    .cloned()
                    .unwrap_or_default();
                if let Some(step) = &step {
                    results.push(json!({
                        "index": number(step_index),
                        "kind": step_kind(step),
                        "outcome": "failed",
                        "at": number(now),
                        "code": code,
                        "detail": message,
                    }));
                }
                clear_lease(&mut run);
                run.insert("status".into(), str_value("failed"));
                run.insert("finishedAt".into(), number(now));
                run.insert("expiresAt".into(), number(now + RUN_RETENTION_MS));
                run.insert("error".into(), json!({ "code": code, "message": message }));
                if step.is_some() {
                    run.insert("results".into(), Value::Array(results));
                } else if let Some(previous) = run.get("results").cloned() {
                    run.insert("results".into(), previous);
                }
                tx.put("workflowRuns", &run).await?;
                let mut metadata = Map::new();
                copy(&mut metadata, &run, "workflowId");
                copy(&mut metadata, &run, "identityId");
                metadata.insert("index".into(), number(step_index));
                metadata.insert("code".into(), Value::String(code.clone()));
                let tenant_id = member_str(&run, "tenantId").to_owned();
                ctx.events()?
                    .record_audit(
                        &tx,
                        &system_event(
                            &tenant_id,
                            "workflow:run:fail",
                            member_str(&run, "id"),
                            now,
                            "deny",
                            metadata,
                        ),
                    )
                    .await
            })
            .await
    }

    /// Runs one run's steps until it waits, finishes or fails. Returns its final status.
    async fn execute(&self, run_id: &str) -> IamResult<Option<String>> {
        let ctx = &self.ctx;
        let token = URL_SAFE_NO_PAD.encode(better_iam_auth::crypto::random_bytes(12));
        let claimed = ctx
            .store
            .transaction(|tx| {
                let token = token.clone();
                async move {
                    let run = tx.get("workflowRuns", run_id).await?;
                    let now = ctx.now();
                    let Some(mut run) = run else {
                        return Ok(false);
                    };
                    let status = member_str(&run, "status").to_owned();
                    if status == "running" && member_num_or(&run, "leaseUntil", 0.0) > now {
                        return Ok(false);
                    }
                    if !["pending", "waiting", "running"].contains(&status.as_str())
                        || member_num(&run, "nextAt") > now
                    {
                        return Ok(false);
                    }
                    run.insert("status".into(), str_value("running"));
                    run.insert("leaseToken".into(), Value::String(token));
                    run.insert("leaseUntil".into(), number(now + LEASE_MS));
                    tx.put("workflowRuns", &run).await?;
                    Ok(true)
                }
            })
            .await?;
        if !claimed {
            return Ok(None);
        }
        for _guard in 0..=25 {
            let outcome = match Box::pin(self.step(run_id, &token)).await {
                Ok((next, changed, tenant_id, identity_id)) => {
                    if changed {
                        after_identity_change(ctx, &tenant_id, &[identity_id], &Value::Null)
                            .await
                            .map(|_| next)
                    } else {
                        Ok(next)
                    }
                }
                Err(error) => Err(error),
            };
            match outcome {
                Ok(Next::Stop) => break,
                Ok(Next::Continue) => {}
                Err(error) => {
                    self.fail(run_id, &token, &error).await?;
                    break;
                }
            }
        }
        let run = ctx
            .store
            .transaction(|tx| async move { tx.get("workflowRuns", run_id).await })
            .await?;
        Ok(run.map(|run| member_str(&run, "status").to_owned()))
    }

    /// Writes a person's workflowSubjects record (`writeSnapshot`).
    #[allow(clippy::too_many_arguments)]
    async fn write_snapshot(
        tx: &Store,
        snapshots: &mut IndexMap<String, Record>,
        tenant_id: &str,
        workflow_id: &str,
        identity: &Identity,
        snapshot: SubjectSnapshot,
        occurrence: Option<&str>,
    ) -> IamResult<()> {
        let previous = snapshots.get(&identity.id).cloned();
        let previous_occurrences: Vec<Value> = previous
            .as_ref()
            .and_then(|previous| previous.get("occurrences"))
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let mut record = Record::new();
        record.insert(
            "id".into(),
            previous
                .as_ref()
                .and_then(|previous| previous.get("id").cloned())
                .unwrap_or_else(|| Value::String(id())),
        );
        record.insert("tenantId".into(), str_value(tenant_id));
        record.insert(
            "uniqueKey".into(),
            Value::String(format!("{workflow_id}:{}", identity.id)),
        );
        record.insert("workflowId".into(), str_value(workflow_id));
        record.insert("identityId".into(), Value::String(identity.id.clone()));
        record.insert("values".into(), Value::Object(snapshot.values));
        record.insert("status".into(), Value::String(snapshot.status));
        record.insert("fired".into(), number(snapshot.fired));
        if occurrence.is_some_and(|occurrence| !occurrence.is_empty())
            || !previous_occurrences.is_empty()
        {
            let mut occurrences = previous_occurrences;
            if let Some(occurrence) = occurrence.filter(|occurrence| !occurrence.is_empty()) {
                occurrences.push(str_value(occurrence));
            }
            let start = occurrences.len().saturating_sub(20);
            record.insert(
                "occurrences".into(),
                Value::Array(occurrences[start..].to_vec()),
            );
        }
        if previous.is_some() {
            tx.put("workflowSubjects", &record).await?;
        } else {
            tx.insert("workflowSubjects", &record).await?;
        }
        snapshots.insert(identity.id.clone(), record);
        Ok(())
    }

    /// Starts the runs a workflow's trigger calls for now. Returns how many started.
    async fn evaluate_workflow(&self, workflow_id: &str) -> IamResult<usize> {
        let ctx = &self.ctx;
        ctx.store
            .transaction(|tx| async move {
                let Some(workflow) = tx.get("workflows", workflow_id).await? else {
                    return Ok(0);
                };
                let trigger = workflow.get("trigger").cloned().unwrap_or(Value::Null);
                if !truthy(workflow.get("enabled")) || trigger_kind(&trigger) == "manual" {
                    return Ok(0);
                }
                let tenant_id = member_str(&workflow, "tenantId").to_owned();
                match tx.get("tenants", &tenant_id).await? {
                    Some(tenant) if member_str(&tenant, "status") == "active" => {}
                    _ => return Ok(0),
                }
                let now = ctx.now();
                let workflow_id = member_str(&workflow, "id").to_owned();
                let mut people = Vec::new();
                for record in find(&tx, "identities", by_tenant(&tenant_id)).await? {
                    let identity: Identity = decode(record)?;
                    if identity.kind == IdentityKind::User
                        && identity.status != IdentityStatus::Deleted
                    {
                        people.push(identity);
                    }
                }
                let kind = trigger_kind(&trigger);
                let tracked = kind == "mover" || kind == "leaver";
                // Per person: the mover/leaver baseline, and which occurrences already fired (runs themselves expire).
                let mut snapshots: IndexMap<String, Record> = IndexMap::new();
                for subject in find(
                    &tx,
                    "workflowSubjects",
                    by_tenant(&tenant_id).eq("workflowId", workflow_id.clone()),
                )
                .await?
                {
                    snapshots.insert(member_str(&subject, "identityId").to_owned(), subject);
                }
                let mut facts: Option<(HashMap<String, Vec<String>>, TenantOrgFacts)> = None;
                let scope_document = match workflow.get("scope") {
                    Some(scope) if truthy(Some(scope)) => Some(rule_document(scope)?),
                    _ => None,
                };
                let shape = TriggerWorkflow::of_record(&workflow);
                let mut candidates: Vec<Candidate> = Vec::new();
                for identity in people {
                    let previous = snapshots.get(&identity.id).cloned();
                    let previous_snapshot = previous.as_ref().map(SubjectSnapshot::of_record);
                    let outcome = trigger_occurrence(
                        &shape,
                        &identity,
                        if tracked {
                            previous_snapshot.as_ref()
                        } else {
                            None
                        },
                        now,
                    )?;
                    let mut start = false;
                    if let Some(occurrence) = &outcome.occurrence {
                        let fired = previous
                            .as_ref()
                            .and_then(|previous| previous.get("occurrences"))
                            .and_then(Value::as_array)
                            .is_some_and(|items| {
                                items.iter().any(|item| item.as_str() == Some(occurrence))
                            });
                        if !fired {
                            start = match &scope_document {
                                None => true,
                                Some(document) => {
                                    if facts.is_none() {
                                        let mut members: HashMap<String, Vec<String>> =
                                            HashMap::new();
                                        for record in
                                            find(&tx, "groupMembers", by_tenant(&tenant_id)).await?
                                        {
                                            let member: GroupMember = decode(record)?;
                                            if member.package_assignment_id.is_none()
                                                && ctx.live_membership(&member)
                                            {
                                                members
                                                    .entry(member.identity_id.clone())
                                                    .or_default()
                                                    .push(member.group_id.clone());
                                            }
                                        }
                                        facts = Some((
                                            members,
                                            load_org_facts(&tx, &tenant_id, now).await?,
                                        ));
                                    }
                                    let (members, org) =
                                        facts.as_ref().expect("facts were just loaded");
                                    let direct =
                                        members.get(&identity.id).cloned().unwrap_or_default();
                                    let context = rule_context(
                                        &identity,
                                        &json!(direct),
                                        Some(&org.of(&identity.id, &direct)),
                                    )?;
                                    rule_match(document, &identity, &context)?.matched
                                }
                            };
                        }
                    }
                    if start {
                        candidates.push(Candidate {
                            occurrence: outcome.occurrence.clone().unwrap_or_default(),
                            snapshot: outcome.snapshot,
                            identity,
                        });
                    } else if let Some(snapshot) = outcome.snapshot.filter(|_| tracked) {
                        // A change outside the scope (or already run) is taken as the new baseline right away.
                        Self::write_snapshot(
                            &tx,
                            &mut snapshots,
                            &tenant_id,
                            &workflow_id,
                            &identity,
                            snapshot,
                            None,
                        )
                        .await?;
                    }
                }
                if candidates.is_empty() {
                    return Ok(0);
                }
                let today = utc_day(now)?;
                let started_today =
                    if workflow.get("startedOn").and_then(Value::as_str) == Some(today.as_str()) {
                        member_num_or(&workflow, "startedToday", 0.0)
                    } else {
                        0.0
                    };
                let max_runs = member_num(&workflow, "maxRunsPerDay");
                // The brake admits runs up to the day's allowance and holds the rest (their baselines stay
                // unchanged, so they start on a later day or after someone raises the limit).
                let allowance = (max_runs - started_today).max(0.0);
                let admitted_count = if allowance.is_nan() {
                    0
                } else {
                    (allowance.trunc() as usize).min(candidates.len())
                };
                let held = candidates.len() - admitted_count;
                let braked = held > 0
                    && workflow.get("brakedOn").and_then(Value::as_str) != Some(today.as_str());
                let mut updated = workflow.clone();
                updated.insert("startedOn".into(), Value::String(today.clone()));
                updated.insert(
                    "startedToday".into(),
                    number(started_today + admitted_count as f64),
                );
                if braked {
                    updated.insert("brakedOn".into(), Value::String(today.clone()));
                }
                tx.put("workflows", &updated).await?;
                if braked {
                    let mut metadata = Map::new();
                    metadata.insert("held".into(), json!(held));
                    metadata.insert(
                        "startedToday".into(),
                        number(started_today + admitted_count as f64),
                    );
                    metadata.insert(
                        "maxRunsPerDay".into(),
                        workflow
                            .get("maxRunsPerDay")
                            .cloned()
                            .unwrap_or(Value::Null),
                    );
                    ctx.events()?
                        .record_audit(
                            &tx,
                            &system_event(
                                &tenant_id,
                                "workflow:brake",
                                &workflow_id,
                                now,
                                "deny",
                                metadata,
                            ),
                        )
                        .await?;
                }
                candidates.truncate(admitted_count);
                for candidate in candidates {
                    let snapshot = match candidate.snapshot {
                        Some(snapshot) => snapshot,
                        None => match snapshots.get(&candidate.identity.id) {
                            Some(base) => SubjectSnapshot::of_record(base),
                            None => SubjectSnapshot {
                                values: Map::new(),
                                status: status_name(candidate.identity.status).into(),
                                fired: 0.0,
                            },
                        },
                    };
                    Self::write_snapshot(
                        &tx,
                        &mut snapshots,
                        &tenant_id,
                        &workflow_id,
                        &candidate.identity,
                        snapshot,
                        Some(&candidate.occurrence),
                    )
                    .await?;
                    // No uniqueKey: which occurrences already ran is kept on the person's workflowSubjects record,
                    // which a restart resets, while older runs of the same occurrence may still exist.
                    let mut run = Record::new();
                    let run_id = id();
                    run.insert("id".into(), Value::String(run_id.clone()));
                    run.insert("tenantId".into(), str_value(&tenant_id));
                    run.insert("workflowId".into(), str_value(&workflow_id));
                    copy_as(&mut run, &workflow, "name", "workflowName");
                    copy_as(&mut run, &workflow, "version", "workflowVersion");
                    run.insert(
                        "identityId".into(),
                        Value::String(candidate.identity.id.clone()),
                    );
                    run.insert(
                        "occurrence".into(),
                        Value::String(candidate.occurrence.clone()),
                    );
                    run.insert("trigger".into(), str_value(trigger_kind(&trigger)));
                    copy(&mut run, &workflow, "steps");
                    copy(&mut run, &workflow, "ownerId");
                    run.insert(
                        "ownerMfa".into(),
                        Value::Bool(workflow.get("ownerMfa") == Some(&Value::Bool(true))),
                    );
                    run.insert("status".into(), str_value("pending"));
                    run.insert("stepIndex".into(), json!(0));
                    run.insert("nextAt".into(), number(now));
                    run.insert("results".into(), json!([]));
                    run.insert("startedAt".into(), number(now));
                    tx.insert("workflowRuns", &run).await?;
                    let mut metadata = Map::new();
                    metadata.insert("workflowId".into(), str_value(&workflow_id));
                    metadata.insert(
                        "identityId".into(),
                        Value::String(candidate.identity.id.clone()),
                    );
                    metadata.insert("occurrence".into(), Value::String(candidate.occurrence));
                    ctx.events()?
                        .record_audit(
                            &tx,
                            &system_event(
                                &tenant_id,
                                "workflow:run:start",
                                &run_id,
                                now,
                                "allow",
                                metadata,
                            ),
                        )
                        .await?;
                }
                Ok(admitted_count)
            })
            .await
    }

    /// Evaluates every enabled workflow (of one tenant) and runs what is due.
    async fn run_due(&self, input: Option<&Value>) -> IamResult<Value> {
        let ctx = &self.ctx;
        let empty = Map::new();
        let input = match input {
            None => &empty,
            // `input.limit` of null throws a TypeError.
            Some(Value::Null) => return Err(crate::js::internal_error()),
            Some(Value::Object(map)) => map,
            Some(_) => &empty,
        };
        let limit_value = present(input.get("limit")).cloned().unwrap_or(json!(500));
        let limit = integer(Some(&limit_value), "limit", 1.0, 10_000.0)? as usize;
        let tenant_filter = match input.get("tenantId") {
            None => None,
            Some(value) => Some(text(Some(value), "tenantId", 256)?),
        };
        let filter = || match &tenant_filter {
            Some(tenant_id) => by_tenant(tenant_id),
            None => Filter::new(),
        };
        let mut result = JobResult::default();
        let workflows = ctx
            .store
            .transaction(|tx| {
                let filter = filter();
                async move { find(&tx, "workflows", filter).await }
            })
            .await?;
        for workflow in &workflows {
            let trigger = workflow.get("trigger").cloned().unwrap_or(Value::Null);
            if truthy(workflow.get("enabled")) && trigger_kind(&trigger) != "manual" {
                // One workflow's failure (a lock timeout, a record another process changed) never stops the others.
                if let Ok(started) =
                    Box::pin(self.evaluate_workflow(member_str(workflow, "id"))).await
                {
                    result.started += started as f64;
                }
            }
        }
        let now = ctx.now();
        let due = ctx
            .store
            .transaction(|tx| {
                let (pending, waiting, running) = (
                    filter().eq("status", "pending"),
                    filter().eq("status", "waiting"),
                    filter().eq("status", "running"),
                );
                async move {
                    let mut runs = find(&tx, "workflowRuns", pending).await?;
                    runs.extend(find(&tx, "workflowRuns", waiting).await?);
                    runs.extend(
                        find(&tx, "workflowRuns", running)
                            .await?
                            .into_iter()
                            .filter(|run| member_num_or(run, "leaseUntil", 0.0) <= now),
                    );
                    let mut runs: Vec<Record> = runs
                        .into_iter()
                        .filter(|run| member_num(run, "nextAt") <= now)
                        .collect();
                    runs.sort_by(|a, b| {
                        let difference = member_num(a, "nextAt") - member_num(b, "nextAt");
                        if difference != 0.0 && !difference.is_nan() {
                            difference
                                .partial_cmp(&0.0)
                                .unwrap_or(std::cmp::Ordering::Equal)
                        } else if member_str(a, "id") < member_str(b, "id") {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Greater
                        }
                    });
                    runs.truncate(limit);
                    Ok(runs)
                }
            })
            .await?;
        for run in &due {
            let Some(status) = Box::pin(self.execute(member_str(run, "id"))).await? else {
                continue;
            };
            result.executed += 1.0;
            match status.as_str() {
                "completed" => result.completed += 1.0,
                "failed" => result.failed += 1.0,
                "waiting" => result.waiting += 1.0,
                _ => {}
            }
        }
        Ok(result.to_json())
    }
}

/// Copies a member under another name when the record has it.
fn copy_as(out: &mut Map<String, Value>, record: &Map<String, Value>, key: &str, name: &str) {
    if let Some(value) = record.get(key) {
        out.insert(name.to_owned(), value.clone());
    }
}

/// `principal.identity.email ?? principal.identity.name`.
fn display_name(identity: &Identity) -> String {
    identity
        .email
        .clone()
        .unwrap_or_else(|| identity.name.clone())
}

/// Sorts runs newest first (`b.startedAt - a.startedAt || (a.id < b.id ? -1 : 1)`).
fn sort_newest(runs: &mut [Record]) {
    runs.sort_by(|a, b| {
        let difference = member_num(b, "startedAt") - member_num(a, "startedAt");
        if difference != 0.0 && !difference.is_nan() {
            difference
                .partial_cmp(&0.0)
                .unwrap_or(std::cmp::Ordering::Equal)
        } else if member_str(a, "id") < member_str(b, "id") {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
}

/// The `workflows` API group (`createWorkflowsApi(ctx)`): one method per route `workflows/{method}`.
pub struct WorkflowsApi {
    ctx: Arc<ServerContext>,
    engine: Engine,
}

/// `createWorkflowsApi(ctx)`.
pub fn create_workflows_api(ctx: &Arc<ServerContext>) -> IamResult<WorkflowsApi> {
    Ok(WorkflowsApi {
        ctx: ctx.clone(),
        engine: Engine { ctx: ctx.clone() },
    })
}

impl WorkflowsApi {
    /// May the caller see people's names and addresses (`iam:identities:read`)? Otherwise views carry IDs only.
    async fn directory(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
    ) -> IamResult<bool> {
        decide_iam(
            &self.ctx,
            tx,
            principal,
            tenant_id,
            "iam:identities:read",
            tenant_id,
        )
        .await
    }

    async fn names(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        identity_ids: Vec<String>,
    ) -> IamResult<HashMap<String, String>> {
        let mut result = HashMap::new();
        if !self.directory(tx, principal, tenant_id).await? {
            return Ok(result);
        }
        for identity_id in crate::js::unique(identity_ids) {
            if let Some(identity) = tx.get("identities", &identity_id).await? {
                let name = match identity.get("email") {
                    None | Some(Value::Null) => identity.get("name"),
                    email => email,
                };
                result.insert(identity_id, js_string(name));
            }
        }
        Ok(result)
    }

    fn run_stats(runs: &[&Record], now: f64) -> Value {
        let last = runs.iter().fold(0.0_f64, |latest, item| {
            latest.max(member_num(item, "startedAt"))
        });
        let mut stats = Map::new();
        stats.insert(
            "last30Days".into(),
            json!(
                runs.iter()
                    .filter(|item| member_num(item, "startedAt") > now - 30.0 * DAY_MS)
                    .count()
            ),
        );
        stats.insert(
            "active".into(),
            json!(
                runs.iter()
                    .filter(|item| {
                        ["pending", "running", "waiting"].contains(&member_str(item, "status"))
                    })
                    .count()
            ),
        );
        stats.insert(
            "failed".into(),
            json!(
                runs.iter()
                    .filter(|item| member_str(item, "status") == "failed")
                    .count()
            ),
        );
        if last != 0.0 && !last.is_nan() {
            stats.insert("lastRunAt".into(), number(last));
        }
        Value::Object(stats)
    }

    /// Starts manual runs for people (the caller needs the steps' rights over each of them).
    async fn start_manual(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        workflow: &Record,
        identity_ids: &[String],
    ) -> OperationResult<Vec<String>> {
        let ctx = &self.ctx;
        let tenant_id = member_str(workflow, "tenantId");
        let steps = steps_of(workflow);
        let targets: Vec<Option<String>> = identity_ids.iter().cloned().map(Some).collect();
        assert_owner_rights(ctx, tx, principal, tenant_id, &steps, &targets).await?;
        if identity_ids.contains(&principal.identity.id) && steps.iter().any(self_changing) {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                "Nobody changes their own account through a workflow they start",
                403,
            )
            .into());
        }
        let now = ctx.now();
        let trigger = workflow.get("trigger").cloned().unwrap_or(Value::Null);
        let mut created = Vec::new();
        for identity_id in identity_ids {
            let identity = ctx.active_identity(tx, identity_id, tenant_id).await?;
            if identity.kind != IdentityKind::User {
                return Err(invalid_input("Workflows run for people").into());
            }
            let occurrence = format!("manual:{}", id());
            let run_id = id();
            let mut record = Record::new();
            record.insert("id".into(), Value::String(run_id.clone()));
            record.insert("tenantId".into(), str_value(tenant_id));
            copy_as(&mut record, workflow, "id", "workflowId");
            copy_as(&mut record, workflow, "name", "workflowName");
            copy_as(&mut record, workflow, "version", "workflowVersion");
            record.insert("identityId".into(), Value::String(identity.id.clone()));
            record.insert("occurrence".into(), Value::String(occurrence.clone()));
            record.insert("trigger".into(), str_value(trigger_kind(&trigger)));
            copy(&mut record, workflow, "steps");
            copy(&mut record, workflow, "ownerId");
            record.insert(
                "ownerMfa".into(),
                Value::Bool(workflow.get("ownerMfa") == Some(&Value::Bool(true))),
            );
            record.insert("status".into(), str_value("pending"));
            record.insert("stepIndex".into(), json!(0));
            record.insert("nextAt".into(), number(now));
            record.insert("results".into(), json!([]));
            record.insert("startedAt".into(), number(now));
            record.insert(
                "startedBy".into(),
                Value::String(principal.identity.id.clone()),
            );
            tx.insert("workflowRuns", &record).await?;
            let mut metadata = Map::new();
            copy_as(&mut metadata, workflow, "id", "workflowId");
            metadata.insert("identityId".into(), Value::String(identity.id.clone()));
            metadata.insert("occurrence".into(), Value::String(occurrence));
            ctx.events()?
                .audit(
                    tx,
                    principal,
                    "workflow:run:start",
                    tenant_id,
                    &run_id,
                    AuditOutcome::Allow,
                    false,
                    Some(metadata),
                )
                .await?;
            created.push(run_id);
        }
        Ok(created)
    }

    async fn settle(&self, tenant_id: &str, run_ids: &[String]) -> IamResult<Vec<Value>> {
        for run_id in run_ids {
            Box::pin(self.engine.execute(run_id)).await?;
        }
        self.ctx
            .store
            .transaction(|tx| async move {
                let mut views = Vec::new();
                for run_id in run_ids {
                    // Listed by ID: the caller may run steps without being allowed to read the directory.
                    if let Some(run) = tx.get("workflowRuns", run_id).await?
                        && member_str(&run, "tenantId") == tenant_id
                    {
                        views.push(run_view(&run, None));
                    }
                }
                Ok(views)
            })
            .await
    }

    /// `workflows/cancelRun`: stops a pending, waiting or failed run; steps already done stay done.
    pub async fn cancel_run(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::CancelRunInput>,
    ) -> IamResult<Reply<workflows::CancelRunOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("runId"), "runId", 256)?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let mut item = ctx
                    .scoped(&tx, "workflowRuns", body.get("runId"), &tenant.id)
                    .await?;
                if !["pending", "waiting", "failed", "running"]
                    .contains(&member_str(&item, "status"))
                {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "This run already finished",
                        409,
                    )
                    .into());
                }
                clear_lease(&mut item);
                item.insert("status".into(), str_value("cancelled"));
                item.insert("finishedAt".into(), number(ctx.now()));
                item.insert("expiresAt".into(), number(ctx.now() + RUN_RETENTION_MS));
                let cancelled = tx.put("workflowRuns", &item).await?;
                Ok(run_view(&cancelled, None))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:run",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `workflows/create`: creates a workflow owned by the caller, who must hold every right its steps use. Mover
    /// and leaver workflows take everyone's current values as their baseline, so only later changes fire.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::CreateInput>,
    ) -> IamResult<Reply<workflows::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let values = workflow_fields(ctx, &tx, &tenant.id, body, None).await?;
                    let existing = find(&tx, "workflows", by_tenant(&tenant.id)).await?;
                    if existing
                        .iter()
                        .any(|workflow| workflow.get("uniqueKey") == values.get("uniqueKey"))
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A workflow with this name exists",
                            409,
                        )
                        .into());
                    }
                    if existing.len() >= MAX_WORKFLOWS {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            format!("At most {MAX_WORKFLOWS} workflows"),
                            409,
                        )
                        .into());
                    }
                    let steps = steps_of(&values);
                    assert_owner_rights(ctx, &tx, &principal, &tenant.id, &steps, &[None]).await?;
                    if steps.iter().any(|step| is_destructive(step_kind(step))) {
                        ctx.auth.require_recent(&principal)?;
                    }
                    let now = ctx.now();
                    let mut record = values;
                    record.insert("id".into(), Value::String(id()));
                    record.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    record.insert(
                        "ownerId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("ownerMfa".into(), Value::Bool(principal.session.mfa));
                    record.insert("version".into(), json!(1));
                    record.insert("activeSince".into(), number(now));
                    record.insert("createdAt".into(), number(now));
                    record.insert("updatedAt".into(), number(now));
                    let workflow = tx.insert("workflows", &record).await?;
                    rebuild_snapshots(&tx, &workflow, now).await?;
                    Ok(workflow_view(
                        &workflow,
                        Some(&display_name(&principal.identity)),
                        None,
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:manage",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `workflows/delete`: deletes a workflow and cancels its pending and waiting runs; finished runs stay as
    /// history.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::DeleteInput>,
    ) -> IamResult<Reply<workflows::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("workflowId"), "workflowId", 256)?;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let workflow = ctx
                    .scoped(&tx, "workflows", body.get("workflowId"), &tenant.id)
                    .await?;
                let workflow_id = member_str(&workflow, "id").to_owned();
                let now = ctx.now();
                let mut cancelled = 0;
                for mut item in find(
                    &tx,
                    "workflowRuns",
                    by_tenant(&tenant.id).eq("workflowId", workflow_id.clone()),
                )
                .await?
                {
                    if ["pending", "waiting", "running"].contains(&member_str(&item, "status")) {
                        clear_lease(&mut item);
                        item.insert("status".into(), str_value("cancelled"));
                        item.insert("finishedAt".into(), number(now));
                        item.insert("expiresAt".into(), number(now + RUN_RETENTION_MS));
                        tx.put("workflowRuns", &item).await?;
                        cancelled += 1;
                    }
                }
                for subject in find(
                    &tx,
                    "workflowSubjects",
                    by_tenant(&tenant.id).eq("workflowId", workflow_id.clone()),
                )
                .await?
                {
                    tx.delete("workflowSubjects", member_str(&subject, "id"))
                        .await?;
                }
                tx.delete("workflows", &workflow_id).await?;
                Ok(json!({ "deleted": true, "runsCancelled": cancelled }))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `workflows/evaluate`: evaluates this organization's workflows and runs what is due now, instead of waiting
    /// for the scheduler.
    pub async fn evaluate(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::EvaluateInput>,
    ) -> IamResult<Reply<workflows::EvaluateOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> =
            Box::new(|_: MutationContext| Box::pin(async move { Ok(Value::Bool(true)) }));
        ctx.operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:run",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        let mut job = Map::new();
        if let Some(tenant_id) = input.get("tenantId") {
            job.insert("tenantId".into(), tenant_id.clone());
        }
        Ok(Reply::json(
            Box::pin(self.engine.run_due(Some(&Value::Object(job)))).await?,
        ))
    }

    /// `workflows/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::GetInput>,
    ) -> IamResult<Reply<workflows::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("workflowId"), "workflowId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let workflow = ctx
                        .scoped(&tx, "workflows", body.get("workflowId"), &tenant.id)
                        .await?;
                    let mut runs = find(
                        &tx,
                        "workflowRuns",
                        by_tenant(&tenant.id).eq("workflowId", member_str(&workflow, "id")),
                    )
                    .await?;
                    sort_newest(&mut runs);
                    let owner_id = member_str(&workflow, "ownerId").to_owned();
                    let mut ids = vec![owner_id.clone()];
                    ids.extend(
                        runs.iter()
                            .take(50)
                            .map(|item| member_str(item, "identityId").to_owned()),
                    );
                    let known = self.names(&tx, &principal, &tenant.id, ids).await?;
                    let all: Vec<&Record> = runs.iter().collect();
                    let mut view = object_of(workflow_view(
                        &workflow,
                        known.get(&owner_id).map(String::as_str),
                        Some(Self::run_stats(&all, ctx.now())),
                    ));
                    view.insert(
                        "recentRuns".into(),
                        Value::Array(
                            runs.iter()
                                .take(50)
                                .map(|item| {
                                    run_view(
                                        item,
                                        known
                                            .get(member_str(item, "identityId"))
                                            .map(String::as_str),
                                    )
                                })
                                .collect(),
                        ),
                    );
                    Ok(Value::Object(view))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `workflows/getRun`.
    pub async fn get_run(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::GetRunInput>,
    ) -> IamResult<Reply<workflows::GetRunOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("runId"), "runId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let item = ctx
                        .scoped(&tx, "workflowRuns", body.get("runId"), &tenant.id)
                        .await?;
                    let identity_id = member_str(&item, "identityId").to_owned();
                    let known = self
                        .names(&tx, &principal, &tenant.id, vec![identity_id.clone()])
                        .await?;
                    Ok(run_view(&item, known.get(&identity_id).map(String::as_str)))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `workflows/list`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::ListInput>,
    ) -> IamResult<Reply<workflows::ListOutput>> {
        let ctx = &self.ctx;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let mut workflows = find(&tx, "workflows", by_tenant(&tenant.id)).await?;
                    let runs = find(&tx, "workflowRuns", by_tenant(&tenant.id)).await?;
                    let owners = self
                        .names(
                            &tx,
                            &principal,
                            &tenant.id,
                            workflows
                                .iter()
                                .map(|workflow| member_str(workflow, "ownerId").to_owned())
                                .collect(),
                        )
                        .await?;
                    let now = ctx.now();
                    workflows.sort_by(|a, b| {
                        crate::metrics::locale_compare(member_str(a, "name"), member_str(b, "name"))
                    });
                    Ok(Value::Array(
                        workflows
                            .iter()
                            .map(|workflow| {
                                let own: Vec<&Record> = runs
                                    .iter()
                                    .filter(|item| {
                                        member_str(item, "workflowId") == member_str(workflow, "id")
                                    })
                                    .collect();
                                workflow_view(
                                    workflow,
                                    owners
                                        .get(member_str(workflow, "ownerId"))
                                        .map(String::as_str),
                                    Some(Self::run_stats(&own, now)),
                                )
                            })
                            .collect(),
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `workflows/listRuns`.
    pub async fn list_runs(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::ListRunsInput>,
    ) -> IamResult<Reply<workflows::ListRunsOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let limit_value = present(body.get("limit")).cloned().unwrap_or(json!(100));
                    let limit = integer(Some(&limit_value), "limit", 1.0, 500.0)? as usize;
                    let offset_value = present(body.get("offset")).cloned().unwrap_or(json!(0));
                    let offset =
                        integer(Some(&offset_value), "offset", 0.0, 10_000_000.0)? as usize;
                    let mut filter = by_tenant(&tenant.id);
                    if let Some(value) = body.get("workflowId") {
                        filter = filter.eq("workflowId", text(Some(value), "workflowId", 256)?);
                    }
                    if let Some(value) = body.get("identityId") {
                        filter = filter.eq("identityId", text(Some(value), "identityId", 256)?);
                    }
                    if let Some(value) = body.get("status") {
                        filter = filter.eq("status", text(Some(value), "status", 32)?);
                    }
                    let mut rows = find(&tx, "workflowRuns", filter).await?;
                    sort_newest(&mut rows);
                    let page: Vec<&Record> = rows.iter().skip(offset).take(limit).collect();
                    let known = self
                        .names(
                            &tx,
                            &principal,
                            &tenant.id,
                            page.iter()
                                .map(|item| member_str(item, "identityId").to_owned())
                                .collect(),
                        )
                        .await?;
                    Ok(json!({
                        "total": rows.len(),
                        "runs": page
                            .iter()
                            .map(|item| run_view(item, known.get(member_str(item, "identityId")).map(String::as_str)))
                            .collect::<Vec<_>>(),
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `workflows/preview`: what the workflow would do right now: who its scope matches, who a run would start for
    /// at the next evaluation, upcoming dates (30 days), and whether the owner still holds each step's rights.
    /// Changes nothing.
    pub async fn preview(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::PreviewInput>,
    ) -> IamResult<Reply<workflows::PreviewOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("workflowId"), "workflowId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let workflow = ctx
                        .scoped(&tx, "workflows", body.get("workflowId"), &tenant.id)
                        .await?;
                    let now = ctx.now();
                    let visible = self.directory(&tx, &principal, &tenant.id).await?;
                    let mut people = Vec::new();
                    for record in find(&tx, "identities", by_tenant(&tenant.id)).await? {
                        let identity: Identity = decode(record)?;
                        if identity.kind == IdentityKind::User
                            && identity.status == IdentityStatus::Active
                        {
                            people.push(identity);
                        }
                    }
                    let mut members: HashMap<String, Vec<String>> = HashMap::new();
                    for record in find(&tx, "groupMembers", by_tenant(&tenant.id)).await? {
                        let member: GroupMember = decode(record)?;
                        if member.package_assignment_id.is_none() && ctx.live_membership(&member) {
                            members
                                .entry(member.identity_id.clone())
                                .or_default()
                                .push(member.group_id.clone());
                        }
                    }
                    let org = load_org_facts(&tx, &tenant.id, now).await?;
                    let document = match workflow.get("scope") {
                        Some(scope) if truthy(Some(scope)) => Some(rule_document(scope)?),
                        _ => None,
                    };
                    let mut snapshots: HashMap<String, Record> = HashMap::new();
                    for subject in find(
                        &tx,
                        "workflowSubjects",
                        by_tenant(&tenant.id).eq("workflowId", member_str(&workflow, "id")),
                    )
                    .await?
                    {
                        snapshots.insert(member_str(&subject, "identityId").to_owned(), subject);
                    }
                    let trigger = workflow.get("trigger").cloned().unwrap_or(Value::Null);
                    let kind = trigger_kind(&trigger);
                    let tracked = kind == "mover" || kind == "leaver";
                    let shape = TriggerWorkflow::of_record(&workflow);
                    let mut in_scope = Vec::new();
                    let mut would_start = Vec::new();
                    let mut upcoming: Vec<(f64, Value)> = Vec::new();
                    for identity in &people {
                        let direct = members.get(&identity.id).cloned().unwrap_or_default();
                        if let Some(document) = &document {
                            let context = rule_context(
                                identity,
                                &json!(direct),
                                Some(&org.of(&identity.id, &direct)),
                            )?;
                            if !rule_match(document, identity, &context)?.matched {
                                continue;
                            }
                        }
                        // Names and addresses only for callers who may read the directory; IDs otherwise.
                        let name = if visible {
                            identity.name.clone()
                        } else {
                            identity.id.clone()
                        };
                        let mut person = Map::new();
                        person.insert("id".into(), Value::String(identity.id.clone()));
                        person.insert("name".into(), Value::String(name.clone()));
                        if visible
                            && let Some(email) =
                                identity.email.as_deref().filter(|email| !email.is_empty())
                        {
                            person.insert("email".into(), str_value(email));
                        }
                        in_scope.push(Value::Object(person));
                        let subject = snapshots.get(&identity.id);
                        let snapshot = subject.map(SubjectSnapshot::of_record);
                        let outcome = trigger_occurrence(
                            &shape,
                            identity,
                            if tracked { snapshot.as_ref() } else { None },
                            now,
                        )?;
                        if let Some(occurrence) = outcome.occurrence
                            && truthy(workflow.get("enabled"))
                            && !subject
                                .and_then(|subject| subject.get("occurrences"))
                                .and_then(Value::as_array)
                                .is_some_and(|items| {
                                    items.iter().any(|item| item.as_str() == Some(&occurrence))
                                })
                        {
                            would_start.push(json!({
                                "id": identity.id,
                                "name": name,
                                "occurrence": occurrence,
                            }));
                        }
                        if kind == "date"
                            && let Some(at) = date_target(&trigger, identity)
                            && at > now
                            && at <= now + 30.0 * DAY_MS
                        {
                            upcoming.push((
                                at,
                                json!({ "id": identity.id, "name": name, "at": number(at) }),
                            ));
                        }
                    }
                    upcoming
                        .sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
                    let owner = match tx
                        .get("identities", member_str(&workflow, "ownerId"))
                        .await?
                    {
                        Some(record) => Some(decode::<Identity>(record)?),
                        None => None,
                    };
                    let owner_principal = match owner {
                        Some(owner) if owner.status == IdentityStatus::Active => {
                            Some(ctx.decisions()?.simulated_principal(
                                &owner,
                                workflow.get("ownerMfa") == Some(&Value::Bool(true)),
                            ))
                        }
                        _ => None,
                    };
                    let mut step_checks = Vec::new();
                    for (index, step) in steps_of(&workflow).iter().enumerate() {
                        let mut allowed = owner_principal.is_some();
                        let mut reason = if owner_principal.is_some() {
                            None
                        } else {
                            Some("The owner is no longer active".to_owned())
                        };
                        if let Some(owner_principal) = &owner_principal {
                            for (action, resource) in requirements(step, &tenant.id, None) {
                                if !decide_iam(
                                    ctx,
                                    &tx,
                                    owner_principal,
                                    &tenant.id,
                                    &action,
                                    &resource,
                                )
                                .await?
                                {
                                    allowed = false;
                                    reason =
                                        Some(format!("The owner lacks {action} on {resource}"));
                                    break;
                                }
                            }
                        }
                        let mut check = Map::new();
                        check.insert("index".into(), json!(index));
                        check.insert("kind".into(), str_value(step_kind(step)));
                        check.insert("allowed".into(), Value::Bool(allowed));
                        if let Some(reason) = reason {
                            check.insert("reason".into(), Value::String(reason));
                        }
                        step_checks.push(Value::Object(check));
                    }
                    Ok(json!({
                        "inScope": in_scope,
                        "wouldStart": would_start,
                        "upcoming": upcoming.into_iter().map(|(_, item)| item).collect::<Vec<_>>(),
                        "steps": step_checks,
                    }))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `workflows/retryRun`: resumes a failed run at the step that failed (after fixing the cause: a deleted group,
    /// an owner who left). The caller needs the remaining steps' rights over the person, and the remaining steps
    /// then run with the caller's rights: retrying is approving them.
    pub async fn retry_run(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::RetryRunInput>,
    ) -> IamResult<Reply<workflows::RetryRunOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("runId"), "runId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let mut item = ctx
                        .scoped(&tx, "workflowRuns", body.get("runId"), &tenant.id)
                        .await?;
                    if member_str(&item, "status") != "failed" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "Only failed runs can be retried",
                            409,
                        )
                        .into());
                    }
                    let steps = steps_of(&item);
                    let step_index = member_num(&item, "stepIndex");
                    let start = if step_index.is_nan() {
                        0
                    } else {
                        (step_index.max(0.0) as usize).min(steps.len())
                    };
                    let remaining = steps[start..].to_vec();
                    let identity_id = member_str(&item, "identityId").to_owned();
                    assert_owner_rights(
                        ctx,
                        &tx,
                        &principal,
                        &tenant.id,
                        &remaining,
                        &[Some(identity_id.clone())],
                    )
                    .await?;
                    if remaining.iter().any(|step| is_destructive(step_kind(step))) {
                        ctx.auth.require_recent(&principal)?;
                    }
                    if identity_id == principal.identity.id && remaining.iter().any(self_changing) {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Nobody changes their own account through a workflow they retry",
                            403,
                        )
                        .into());
                    }
                    item.shift_remove("error");
                    item.shift_remove("finishedAt");
                    item.shift_remove("expiresAt");
                    item.insert("status".into(), str_value("pending"));
                    item.insert("nextAt".into(), number(ctx.now()));
                    item.insert(
                        "ownerId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    item.insert("ownerMfa".into(), Value::Bool(principal.session.mfa));
                    item.insert(
                        "startedBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    tx.put("workflowRuns", &item).await?;
                    Ok(item.get("id").cloned().unwrap_or(Value::Null))
                })
            },
        );
        let retried = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:run",
                &resource,
                mutation,
                false,
            )
            .await?;
        let views = self
            .settle(
                &string_member(&input, "tenantId"),
                &[js_string(Some(&retried))],
            )
            .await?;
        // `(await settle(...))[0]!`: undefined when the run is gone.
        Ok(Reply::json(views.into_iter().next().unwrap_or(Value::Null)))
    }

    /// `workflows/run`: runs a workflow now for up to 100 people, whatever its trigger (the scope is not applied:
    /// you choose the people). The caller needs the steps' rights over each of them. Steps run until the first wait
    /// before this returns.
    pub async fn run(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::RunInput>,
    ) -> IamResult<Reply<workflows::RunOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let identity_ids = crate::js::unique(strings(input.get("identityIds"), "identityIds")?);
        if identity_ids.is_empty() {
            return Err(invalid_input("Provide 1-100 identityIds"));
        }
        let resource = text(input.get("workflowId"), "workflowId", 256)?;
        let targets = &identity_ids;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let workflow = ctx
                        .scoped(&tx, "workflows", body.get("workflowId"), &tenant.id)
                        .await?;
                    if steps_of(&workflow)
                        .iter()
                        .any(|step| is_destructive(step_kind(step)))
                    {
                        ctx.auth.require_recent(&principal)?;
                    }
                    let created = self
                        .start_manual(&tx, &principal, &workflow, targets)
                        .await?;
                    Ok(json!(created))
                })
            },
        );
        let created = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:run",
                &resource,
                mutation,
                false,
            )
            .await?;
        let run_ids: Vec<String> = created
            .as_array()
            .map(|items| items.iter().map(|item| js_string(Some(item))).collect())
            .unwrap_or_default();
        let views = self
            .settle(&string_member(&input, "tenantId"), &run_ids)
            .await?;
        Ok(Reply::json(Value::Array(views)))
    }

    /// `workflows/update`: edits a workflow; the caller becomes its owner (and must hold the steps' rights).
    /// Changing the trigger or enabling it again starts it afresh: joiners and dates count from now, and mover and
    /// leaver baselines are retaken. Runs already started keep the steps they started with, and the rights of the
    /// owner who approved them, unless `activeRuns: 'cancel'` stops them.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<workflows::UpdateInput>,
    ) -> IamResult<Reply<workflows::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let resource = text(input.get("workflowId"), "workflowId", 256)?;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let previous = ctx
                        .scoped(&tx, "workflows", body.get("workflowId"), &tenant.id)
                        .await?;
                    let values =
                        workflow_fields(ctx, &tx, &tenant.id, body, Some(&previous)).await?;
                    if find(&tx, "workflows", by_tenant(&tenant.id))
                        .await?
                        .iter()
                        .any(|workflow| {
                            member_str(workflow, "id") != member_str(&previous, "id")
                                && workflow.get("uniqueKey") == values.get("uniqueKey")
                        })
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A workflow with this name exists",
                            409,
                        )
                        .into());
                    }
                    let steps = steps_of(&values);
                    assert_owner_rights(ctx, &tx, &principal, &tenant.id, &steps, &[None]).await?;
                    if steps.iter().any(|step| is_destructive(step_kind(step))) {
                        ctx.auth.require_recent(&principal)?;
                    }
                    let now = ctx.now();
                    let restart = core_js::stringify(values.get("trigger").unwrap_or(&Value::Null))
                        != core_js::stringify(previous.get("trigger").unwrap_or(&Value::Null))
                        || (values.get("enabled") == Some(&Value::Bool(true))
                            && !truthy(previous.get("enabled")));
                    let mut kept = previous.clone();
                    kept.shift_remove("description");
                    kept.shift_remove("scope");
                    kept.shift_remove("brakedOn");
                    let active_runs = body.get("activeRuns");
                    if let Some(value) = active_runs
                        && value.as_str() != Some("keep")
                        && value.as_str() != Some("cancel")
                    {
                        return Err(invalid_input("activeRuns must be 'keep' or 'cancel'").into());
                    }
                    let mut record = kept;
                    for (key, value) in values {
                        record.insert(key, value);
                    }
                    record.insert(
                        "ownerId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    record.insert("ownerMfa".into(), Value::Bool(principal.session.mfa));
                    record.insert(
                        "version".into(),
                        number(member_num(&previous, "version") + 1.0),
                    );
                    record.insert(
                        "activeSince".into(),
                        if restart {
                            number(now)
                        } else {
                            previous.get("activeSince").cloned().unwrap_or(Value::Null)
                        },
                    );
                    record.insert("updatedAt".into(), number(now));
                    if truthy(previous.get("brakedOn")) && body.get("maxRunsPerDay").is_none() {
                        record.insert(
                            "brakedOn".into(),
                            previous.get("brakedOn").cloned().unwrap_or(Value::Null),
                        );
                    }
                    let workflow = tx.put("workflows", &record).await?;
                    if restart {
                        rebuild_snapshots(&tx, &workflow, now).await?;
                    }
                    if active_runs.and_then(Value::as_str) == Some("cancel") {
                        for mut item in find(
                            &tx,
                            "workflowRuns",
                            by_tenant(&tenant.id).eq("workflowId", member_str(&workflow, "id")),
                        )
                        .await?
                        {
                            if ["pending", "waiting", "running", "failed"]
                                .contains(&member_str(&item, "status"))
                            {
                                clear_lease(&mut item);
                                item.insert("status".into(), str_value("cancelled"));
                                item.insert("finishedAt".into(), number(now));
                                item.insert("expiresAt".into(), number(now + RUN_RETENTION_MS));
                                tx.put("workflowRuns", &item).await?;
                            }
                        }
                    }
                    Ok(workflow_view(
                        &workflow,
                        Some(&display_name(&principal.identity)),
                        None,
                    ))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:workflows:manage",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// Audit actions that can change who a workflow fires for: people, their groups, teams and departments, and
/// workflows.
const REACTING_PREFIXES: &[&str] = &[
    "iam:identities:",
    "identity:",
    "iam:groups:",
    "iam:teams:",
    "iam:departments:",
    "iam:workflows:",
    "iam:scim",
    "scim:",
];

/// The background state of `subscribe()`: tenants being evaluated, changed meanwhile, or scheduled.
#[derive(Default)]
struct ReactorState {
    busy: Mutex<IndexSet<String>>,
    dirty: Mutex<IndexSet<String>>,
    pending: Mutex<IndexSet<String>>,
    enabled_cache: Mutex<HashMap<String, (f64, bool)>>,
    settled: tokio::sync::Notify,
}

fn locked<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl ReactorState {
    async fn has_workflows(&self, ctx: &ServerContext, tenant_id: &str) -> IamResult<bool> {
        let now = crate::utils::date_now();
        if let Some((at, value)) = locked(&self.enabled_cache).get(tenant_id).copied()
            && at > now - 15_000.0
        {
            return Ok(value);
        }
        let workflows = ctx
            .store
            .transaction(|tx| async move { find(&tx, "workflows", by_tenant(tenant_id)).await })
            .await?;
        let value = workflows.iter().any(|workflow| {
            truthy(workflow.get("enabled"))
                && trigger_kind(workflow.get("trigger").unwrap_or(&Value::Null)) != "manual"
        });
        let mut cache = locked(&self.enabled_cache);
        cache.insert(tenant_id.to_owned(), (crate::utils::date_now(), value));
        if cache.len() > 10_000 {
            cache.clear();
        }
        Ok(value)
    }

    async fn evaluate(&self, ctx: &Arc<ServerContext>, tenant_id: &str) {
        locked(&self.busy).insert(tenant_id.to_owned());
        let engine = Engine { ctx: ctx.clone() };
        // The scheduler catches up; a background evaluation never surfaces.
        loop {
            locked(&self.dirty).shift_remove(tenant_id);
            match self.has_workflows(ctx, tenant_id).await {
                Ok(true) => {}
                _ => break,
            }
            let mut job = Map::new();
            job.insert("tenantId".into(), str_value(tenant_id));
            if Box::pin(engine.run_due(Some(&Value::Object(job))))
                .await
                .is_err()
            {
                break;
            }
            if !locked(&self.dirty).contains(tenant_id) {
                break;
            }
        }
        locked(&self.busy).shift_remove(tenant_id);
        locked(&self.pending).shift_remove(tenant_id);
        self.settled.notify_waiters();
    }

    fn react(self: &Arc<Self>, ctx: &Weak<ServerContext>, event: &Record) {
        // A workflow's own steps (and the run events) never retrigger evaluation; other workflows see them on
        // schedule.
        if event
            .get("metadata")
            .and_then(|metadata| metadata.get("via"))
            .and_then(Value::as_str)
            == Some("workflow")
        {
            return;
        }
        let action = member_str(event, "action");
        if !REACTING_PREFIXES
            .iter()
            .any(|prefix| action.starts_with(prefix))
        {
            return;
        }
        let tenant_id = member_str(event, "tenantId").to_owned();
        if action.starts_with("iam:workflows:") {
            locked(&self.enabled_cache).remove(&tenant_id);
        }
        if locked(&self.busy).contains(&tenant_id) || locked(&self.pending).contains(&tenant_id) {
            locked(&self.dirty).insert(tenant_id);
            return;
        }
        locked(&self.pending).insert(tenant_id.clone());
        let state = self.clone();
        let ctx = ctx.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(200)).await;
            match ctx.upgrade() {
                Some(ctx) => Box::pin(state.evaluate(&ctx, &tenant_id)).await,
                None => {
                    locked(&state.pending).shift_remove(&tenant_id);
                    state.settled.notify_waiters();
                }
            }
        });
    }
}

/// Workflows for the deployment's own code (`iam.workflows`): the scheduler job `runDue` (every few minutes), and
/// `subscribe()`, which evaluates an organization's workflows shortly after a change to its people is recorded in
/// the audit log (it needs `iam.dispatchAuditHooks()` to be running, as the console does). Returns the unsubscribe
/// function. Evaluations run in the background, debounced per organization, so audit dispatch never waits for them;
/// `idle()` resolves once the scheduled ones have finished.
pub struct WorkflowsRuntime {
    ctx: Arc<ServerContext>,
    engine: Engine,
    state: Arc<ReactorState>,
}

/// `createWorkflowsRuntime(ctx)`.
pub fn create_workflows_runtime(ctx: &Arc<ServerContext>) -> IamResult<WorkflowsRuntime> {
    Ok(WorkflowsRuntime {
        ctx: ctx.clone(),
        engine: Engine { ctx: ctx.clone() },
        state: Arc::new(ReactorState::default()),
    })
}

impl WorkflowsRuntime {
    /// Evaluates every enabled workflow and runs the steps that are due (a scheduler job, every few minutes).
    /// `input` is `{ tenantId?, limit? }`.
    pub async fn run_due(&self, input: Option<&Value>) -> IamResult<Value> {
        Box::pin(self.engine.run_due(input)).await
    }

    /// Reacts to changes to each organization's people (see above); returns the unsubscribe function.
    pub fn subscribe(&self) -> IamResult<Callback> {
        let state = self.state.clone();
        let weak = Arc::downgrade(&self.ctx);
        let handler: SubscriberFn = Arc::new(move |event: Record| {
            state.react(&weak, &event);
            Box::pin(async { Ok(()) })
        });
        let subscription = Arc::new(self.ctx.events()?.subscribe(&["*"], handler)?);
        Ok(Arc::new(move |_args: Vec<Value>| {
            subscription.unsubscribe();
            Box::pin(async { Ok(undefined()) })
        }))
    }

    /// Resolves once every evaluation `subscribe()` scheduled has finished (for tests and graceful shutdown).
    pub async fn idle(&self) -> IamResult<()> {
        loop {
            let settled = self.state.settled.notified();
            tokio::pin!(settled);
            settled.as_mut().enable();
            if locked(&self.state.pending).is_empty() {
                return Ok(());
            }
            settled.await;
        }
    }

    /// The conformance server's `call` for a member of this object: JSON arguments in, the JSON result out;
    /// None for a name it does not have.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        match method {
            "runDue" => Some(self.run_due(args.first()).await),
            // The unsubscribe function has no JSON form; the subscription stays until the instance is reset.
            "subscribe" => Some(
                self.subscribe()
                    .map(|_unsubscribe| json!({ "$function": "anonymous" })),
            ),
            "idle" => Some(self.idle().await.map(|()| undefined())),
            _ => None,
        }
    }
}
