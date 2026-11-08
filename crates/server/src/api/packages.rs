//! Port of `packages/server/src/api/packages.ts`: access packages (bundles of roles and groups granted together),
//! their assignments, the self-service requests and approvals, and the shared helpers other writers use
//! (configuration sync, guests, workflows, the package rule reconciler).
//!
//! Records are handled raw (`Record`) so member order and members this version does not know survive a
//! read-modify-write in a mixed fleet; the typed entry points other modules call convert at the boundary.

use std::cmp::Ordering;
use std::sync::{Arc, Mutex};

use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, IamError, IamResult, Record,
    js as core_js,
};
use better_iam_types::api::packages;
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::access_policy::DEFAULT_APPROVAL_LIFETIME_MS;
use crate::api::bindings::create_binding_record;
use crate::api::groups::{
    add_group_member_record, assert_may_claim_licenses, update_group_member_record,
};
use crate::api::package_automation::{
    approve_rule, auto_assign_view, preview_rule, reconcile_package_rules,
};
use crate::api::roles::{find_all, member_str, same_member, string_list};
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationResult};
use crate::js::{internal_error, js_string, number, truthy, unique};
use crate::metrics::locale_compare;
use crate::models::{AccessPackage, GrantAuthority, PACKAGE_REQUEST_STATUSES};
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::org_rules::org_rule_environment;
use crate::package_rules::{
    AUTOMATIC_JUSTIFICATION, RuleEnvironment, parse_auto_assign, rule_input, rule_problem,
};
use crate::port::{decode, encode};
use crate::session_kinds::acts_in_own_right;
use crate::teams::{assert_not_team_group, sync_teams_from_groups};
use crate::utils::id;
use crate::validation::{integer, strings, text};

const MAX_CONTENTS: usize = 50;
const TEN_YEARS: f64 = 315_360_000_000.0;

// --- small helpers -----------------------------------------------------------------------------------------------

fn name_key(name: &str) -> String {
    format!("name:{}", core_js::to_lower(core_js::trim(name)))
}

/// `byName`: `a.name.localeCompare(b.name, 'en')`.
fn by_name(a: &Record, b: &Record) -> Ordering {
    locale_compare(member_str(a, "name"), member_str(b, "name"))
}

/// `sameIds(a, b)`: the same IDs, ignoring order.
fn same_ids(a: &[String], b: &[String]) -> bool {
    let left: IndexSet<&String> = a.iter().collect();
    let both: IndexSet<&String> = a.iter().chain(b.iter()).collect();
    a.len() == b.len() && both.len() == left.len()
}

fn boolean(value: Option<&Value>, name: &str) -> IamResult<bool> {
    match value {
        Some(Value::Bool(flag)) => Ok(*flag),
        _ => Err(IamError::new(
            "INVALID_INPUT",
            format!("{name} must be boolean"),
        )),
    }
}

fn invalid(message: impl Into<String>) -> IamError {
    IamError::new("INVALID_INPUT", message)
}

fn num(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(core_js::as_number)
}

fn string(value: impl Into<String>) -> Value {
    Value::String(value.into())
}

/// `endOf(expiresAt)`: "no end" compares last.
fn end(expires_at: Option<f64>) -> f64 {
    expires_at.unwrap_or(f64::INFINITY)
}

/// `String(n)` for a JavaScript number.
fn number_text(value: f64) -> String {
    js_string(Some(&number(value)))
}

/// A record with an `expiresAt` member: absent means no end; otherwise it must lie ahead (`liveAssignment`,
/// `liveMembership`).
fn live(ctx: &ServerContext, record: &Record) -> bool {
    match record.get("expiresAt") {
        None => true,
        Some(value) => core_js::as_number(value).is_some_and(|expires| expires > ctx.now()),
    }
}

/// `ctx.expiredBinding(binding)`: a temporary binding past its end.
fn expired_binding(ctx: &ServerContext, binding: &Record) -> bool {
    num(binding, "expiresAt").is_some_and(|expires| expires <= ctx.now())
}

/// `pendingRequest(request, now)`: a request that still waits for a decision.
pub fn pending_request(request: &Record, now: f64) -> bool {
    member_str(request, "status") == "pending"
        && num(request, "expiresAt").is_some_and(|expires| expires > now)
}

fn set_list(record: &mut Record, key: &str, items: &[String]) {
    record.insert(
        key.to_owned(),
        Value::Array(items.iter().cloned().map(Value::String).collect()),
    );
}

/// Copies a member when it is present (`...(x.k !== undefined ? { k: x.k } : {})`).
fn copy(target: &mut Map<String, Value>, source: &Record, key: &str) {
    if let Some(value) = source.get(key) {
        target.insert(key.to_owned(), value.clone());
    }
}

async fn find(tx: &Store, collection: &str, filter: Filter) -> IamResult<Vec<Record>> {
    tx.find(collection, &filter, &find_all()).await
}

fn tenant_filter(tenant_id: &str) -> Filter {
    Filter::new().eq("tenantId", tenant_id.to_owned())
}

fn id_value(value: &str) -> Value {
    Value::String(value.to_owned())
}

// --- the API group -----------------------------------------------------------------------------------------------

/// The `packages` API group (`createPackagesApi(ctx)`): one method per route `packages/{method}`.
pub struct PackagesApi {
    ctx: Arc<ServerContext>,
}

/// `createPackagesApi(ctx)`.
pub fn create_packages_api(ctx: &Arc<ServerContext>) -> IamResult<PackagesApi> {
    Ok(PackagesApi { ctx: ctx.clone() })
}

/// A package whose rule changed inside the operation, reconciled after the commit.
type Ruled = Mutex<Option<(Record, String)>>;

impl PackagesApi {
    /// Runs the post-commit reconcile of a rule change; a failure never fails the call (the scheduler catches up).
    async fn after_rule_change(&self, pkg: &Record, requested_by: &str) -> IamResult<Value> {
        let ctx = &self.ctx;
        let mut options = Map::new();
        options.insert("tenantId".into(), string(member_str(pkg, "tenantId")));
        options.insert("packageId".into(), string(member_str(pkg, "id")));
        options.insert("limit".into(), number(200.0));
        options.insert("trigger".into(), string("rule-change"));
        options.insert("requestedBy".into(), string(requested_by));
        let reconcile = reconcile_package_rules(ctx, &Value::Object(options))
            .await
            .ok()
            .map(|result| Value::Object(encode(&result)));
        let fresh = ctx
            .store
            .get("accessPackages", member_str(pkg, "id"))
            .await?
            .unwrap_or_else(|| pkg.clone());
        let mut view = public_view(ctx, &ctx.store, &fresh, None).await?;
        if let Some(reconcile) = reconcile {
            view.insert("reconcile".into(), reconcile);
        }
        Ok(Value::Object(view))
    }

    /// `decideRequest(credential, input, decision)`: approves or denies a pending request.
    async fn decide_request(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        decision: &'static str,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let existing = ctx
            .scoped(
                &ctx.store,
                "packageRequests",
                input.get("requestId"),
                &text(input.get("tenantId"), "tenantId", 256)?,
            )
            .await?;
        let tenant_id = string_member(input, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let request = ctx
                    .scoped(&tx, "packageRequests", input.get("requestId"), tenant_id)
                    .await?;
                let now = ctx.now();
                if !pending_request(&request, now) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "This request is not awaiting a decision",
                        409,
                    )
                    .into());
                }
                let requester_id = member_str(&request, "identityId").to_owned();
                if requester_id == principal.identity.id {
                    return Err(invalid("You cannot decide on your own request").into());
                }
                // Two-person control: an administrator viewing as an approver must not decide in their name.
                if principal.session.impersonator_id.is_some() {
                    return Err(IamError::with_status(
                        "IMPERSONATION_RESTRICTED",
                        "Requests cannot be decided while impersonating",
                        403,
                    )
                    .into());
                }
                let Some(pkg) = tx
                    .get("accessPackages", member_str(&request, "packageId"))
                    .await?
                else {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "The package no longer exists",
                        409,
                    )
                    .into());
                };
                if decision == "approved" && !truthy(pkg.get("requestable")) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "The package is no longer requestable",
                        409,
                    )
                    .into());
                }
                if !may_approve(ctx, &tx, &pkg, &principal, &requester_id).await? {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Only the designated approvers may decide",
                        403,
                    )
                    .into());
                }
                let note = match input.get("note") {
                    Some(value) => Some(text(Some(value), "note", 2048)?),
                    None => None,
                };
                let mut decided = request.clone();
                decided.insert("status".into(), string(decision));
                decided.insert("decidedBy".into(), string(principal.identity.id.clone()));
                decided.insert("decidedAt".into(), number(now));
                if let Some(note) = &note {
                    decided.insert("note".into(), string(note.clone()));
                }
                let pkg_id = member_str(&pkg, "id").to_owned();
                let pkg_name = member_str(&pkg, "name").to_owned();
                let mut metadata = Map::new();
                metadata.insert("requestId".into(), string(member_str(&request, "id")));
                metadata.insert("packageId".into(), string(pkg_id.clone()));
                metadata.insert("packageName".into(), string(pkg_name.clone()));
                metadata.insert("identityId".into(), string(requester_id.clone()));
                if let Some(note) = &note {
                    metadata.insert("note".into(), string(note.clone()));
                }
                let mut assigned_expires_at = None;
                if decision == "approved" {
                    let mut assign_input = Map::new();
                    assign_input.insert("identityId".into(), string(requester_id.clone()));
                    // `input.expiresAt ?? request.desiredExpiresAt`
                    match input.get("expiresAt") {
                        Some(value) if !value.is_null() => {
                            assign_input.insert("expiresAt".into(), value.clone());
                        }
                        _ => {
                            if let Some(desired) = request.get("desiredExpiresAt") {
                                assign_input.insert("expiresAt".into(), desired.clone());
                            }
                        }
                    }
                    if let Some(justification) = request.get("justification") {
                        assign_input.insert("justification".into(), justification.clone());
                    }
                    let assigned =
                        assign_package_record(ctx, &tx, &principal, &pkg, &assign_input, None)
                            .await?;
                    let assignment_id = member_str(&assigned.assignment, "id").to_owned();
                    decided.insert("assignmentId".into(), string(assignment_id.clone()));
                    metadata.insert("assignmentId".into(), string(assignment_id));
                    metadata.insert(
                        "bindings".into(),
                        number(string_list(&assigned.assignment, "bindingIds").len() as f64),
                    );
                    metadata.insert(
                        "memberships".into(),
                        number(string_list(&assigned.assignment, "membershipIds").len() as f64),
                    );
                    metadata.insert(
                        "skipped".into(),
                        Value::Array(
                            assigned
                                .skipped
                                .iter()
                                .cloned()
                                .map(Value::String)
                                .collect(),
                        ),
                    );
                    if assigned.replaced_automatic {
                        metadata.insert("replacedAutomatic".into(), Value::Bool(true));
                    }
                    if let Some(expires_at) = assigned.assignment.get("expiresAt") {
                        metadata.insert("expiresAt".into(), expires_at.clone());
                        assigned_expires_at = core_js::as_number(expires_at);
                    }
                }
                tx.put("packageRequests", &decided).await?;
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        &format!("package:request-{decision}"),
                        tenant_id,
                        &pkg_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let requester = tx.get("identities", &requester_id).await?;
                let mut payload = Map::new();
                payload.insert("requestId".into(), string(member_str(&request, "id")));
                payload.insert("packageId".into(), string(pkg_id.clone()));
                payload.insert("packageName".into(), string(pkg_name.clone()));
                payload.insert("decision".into(), string(decision));
                payload.insert(
                    "deciderName".into(),
                    string(principal.identity.name.clone()),
                );
                if let Some(note) = &note {
                    payload.insert("note".into(), string(note.clone()));
                }
                if let Some(expires_at) = assigned_expires_at {
                    payload.insert("expiresAt".into(), string(number_text(expires_at)));
                }
                notify(
                    ctx,
                    &tx,
                    tenant_id,
                    requester
                        .as_ref()
                        .and_then(|requester| requester.get("email"))
                        .and_then(Value::as_str),
                    "package-decided",
                    payload,
                )
                .await?;
                let summary = summarize_requests(&tx, vec![decided], now).await?;
                Ok(summary.into_iter().next().unwrap_or(Value::Null))
            })
        });
        ctx.operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:approve",
                member_str(&existing, "packageId"),
                mutation,
                false,
            )
            .await
    }

    /// `packages/approveRequest`: grants a pending request: the package is assigned to the requester under the
    /// approver's authority (so the approver needs the same rights as `assign`), ending at `expiresAt` or the end the
    /// requester asked for. Requires iam:packages:approve on the package and, when the package names approvers,
    /// membership of the approver group or being the requester's manager (or root); nobody decides on their own
    /// request, and never while impersonating. The requester is emailed (`package-decided`). Audited as
    /// `package:request-approved`.
    pub async fn approve_request(
        &self,
        credential: &CredentialInput,
        input: Body<packages::ApproveRequestInput>,
    ) -> IamResult<Reply<packages::ApproveRequestOutput>> {
        let result = self
            .decide_request(credential, input.raw(), "approved")
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/assign`: grants a package: every role becomes an identity binding of the assignment's own and every
    /// group a membership, all ending at `expiresAt`, in one transaction under the caller's grant authority. Besides
    /// iam:packages:assign on the package the caller needs iam:bindings:create on each role and iam:groups:update on
    /// each group, exactly as for the direct calls. A membership the identity already holds for as long is left
    /// alone and listed in `skipped`. An automatic assignment is taken over (`replacedAutomatic`). Audited as
    /// `package:assign`.
    pub async fn assign(
        &self,
        credential: &CredentialInput,
        input: Body<packages::AssignInput>,
    ) -> IamResult<Reply<packages::AssignOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let pkg = ctx
                    .scoped(&tx, "accessPackages", body.get("packageId"), tenant_id)
                    .await?;
                let assigned =
                    assign_package_record(ctx, &tx, &principal, &pkg, body, None).await?;
                let assignment = &assigned.assignment;
                let bindings = string_list(assignment, "bindingIds").len() as f64;
                let memberships = string_list(assignment, "membershipIds").len() as f64;
                let skipped = Value::Array(
                    assigned
                        .skipped
                        .iter()
                        .cloned()
                        .map(Value::String)
                        .collect(),
                );
                let mut metadata = Map::new();
                metadata.insert("packageId".into(), string(member_str(&pkg, "id")));
                metadata.insert("packageName".into(), string(member_str(&pkg, "name")));
                metadata.insert(
                    "identityId".into(),
                    string(member_str(assignment, "identityId")),
                );
                metadata.insert("bindings".into(), number(bindings));
                metadata.insert("memberships".into(), number(memberships));
                metadata.insert("skipped".into(), skipped.clone());
                if assigned.replaced_automatic {
                    metadata.insert("replacedAutomatic".into(), Value::Bool(true));
                }
                copy(&mut metadata, assignment, "expiresAt");
                copy(&mut metadata, assignment, "justification");
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "package:assign",
                        tenant_id,
                        member_str(&pkg, "id"),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let mut result = summarize(ctx, &tx, vec![assignment.clone()])
                    .await?
                    .into_iter()
                    .next()
                    .and_then(|summary| summary.as_object().cloned())
                    .unwrap_or_default();
                let mut created = Map::new();
                created.insert("bindings".into(), number(bindings));
                created.insert("memberships".into(), number(memberships));
                result.insert("created".into(), Value::Object(created));
                result.insert("skipped".into(), skipped);
                result.insert(
                    "replacedAutomatic".into(),
                    Value::Bool(assigned.replaced_automatic),
                );
                Ok(Value::Object(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:assign",
                &string_member(&input, "packageId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/cancelRequest`: withdraws one's own pending request, from an ordinary session or API key of the
    /// tenant (never a role session or session token). Audited as `package:request-cancelled`.
    pub async fn cancel_request(
        &self,
        credential: &CredentialInput,
        input: Body<packages::CancelRequestInput>,
    ) -> IamResult<Reply<packages::CancelRequestOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let existing = ctx
            .scoped(
                &ctx.store,
                "packageRequests",
                body.get("requestId"),
                &text(body.get("tenantId"), "tenantId", 256)?,
            )
            .await?;
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let request = ctx
                    .scoped(&tx, "packageRequests", body.get("requestId"), tenant_id)
                    .await?;
                // Withdrawing acts in the requester's own right, like making the request: never through a role
                // session or session token.
                if !acts_in_own_right(principal.session.kind)
                    || principal.session.tenant_id != *tenant_id
                {
                    return Err(invalid(
                        "Requests are made from an ordinary session of the target tenant",
                    )
                    .into());
                }
                if member_str(&request, "identityId") != principal.identity.id {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Only the requester may cancel a request",
                        403,
                    )
                    .into());
                }
                let now = ctx.now();
                if !pending_request(&request, now) {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "This request is not awaiting a decision",
                        409,
                    )
                    .into());
                }
                let mut cancelled = request.clone();
                cancelled.insert("status".into(), string("cancelled"));
                cancelled.insert("decidedAt".into(), number(now));
                tx.put("packageRequests", &cancelled).await?;
                let mut metadata = Map::new();
                metadata.insert("requestId".into(), string(member_str(&request, "id")));
                metadata.insert(
                    "packageId".into(),
                    string(member_str(&request, "packageId")),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "package:request-cancelled",
                        tenant_id,
                        member_str(&request, "packageId"),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let summary = summarize_requests(&tx, vec![cancelled], now).await?;
                Ok(summary.into_iter().next().unwrap_or(Value::Null))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:request",
                member_str(&existing, "packageId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/create`: defines a bundle of roles and groups granted together by `assign`. Names are unique per
    /// tenant; protected roles cannot be packaged. `maxDurationMs` forces assignments to state an end within it,
    /// `requireJustification` makes the justification mandatory, `requestable` lets members ask for it, and
    /// `approverGroupId` / `managerApproval` name who decides. `autoAssign` makes it a birthright package: every
    /// active identity matching the rule receives it automatically, under the caller's grant authority (the caller
    /// then needs iam:packages:assign on the package and the rights to grant each part by hand); the response
    /// carries the first `reconcile`. Requires iam:packages:create. Audited as `package:auto-rule` for a rule.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<packages::CreateInput>,
    ) -> IamResult<Reply<packages::CreateOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let ruled: Ruled = Mutex::new(None);
        let ruled_ref = &ruled;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let mut pkg = create_package_record(ctx, &tx, body, Some(&principal)).await?;
                if pkg.get("autoAssign").is_some_and(|rule| truthy(Some(rule))) {
                    pkg = approved_package(ctx, &tx, &pkg).await?;
                    *ruled_ref.lock().map_err(|_| internal_error())? =
                        Some((pkg.clone(), principal.identity.id.clone()));
                }
                Ok(Value::Object(public_view(ctx, &tx, &pkg, None).await?))
            })
        });
        let view = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:create",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        let ruled = ruled.lock().map_err(|_| internal_error())?.take();
        match ruled {
            None => Ok(Reply::json(view)),
            Some((pkg, requested_by)) => Ok(Reply::json(
                self.after_rule_change(&pkg, &requested_by).await?,
            )),
        }
    }

    /// `packages/delete`: deletes a package nobody holds (RESOURCE_IN_USE otherwise) together with its request
    /// history. Requires iam:packages:delete.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<packages::DeleteInput>,
    ) -> IamResult<Reply<packages::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let pkg = ctx
                    .scoped(&tx, "accessPackages", body.get("packageId"), tenant_id)
                    .await?;
                delete_package_record(ctx, &tx, &pkg).await?;
                let mut result = Map::new();
                result.insert("deleted".into(), Value::Bool(true));
                Ok(Value::Object(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:delete",
                &string_member(&input, "packageId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/denyRequest`: refuses a pending request with an optional note; same rights as `approveRequest`.
    /// Audited as `package:request-denied`.
    pub async fn deny_request(
        &self,
        credential: &CredentialInput,
        input: Body<packages::DenyRequestInput>,
    ) -> IamResult<Reply<packages::DenyRequestOutput>> {
        // `{ ...input, expiresAt: undefined }`: a denial never reads an end.
        let mut body = input.raw().clone();
        body.shift_remove("expiresAt");
        let result = self.decide_request(credential, &body, "denied").await?;
        Ok(Reply::json(result))
    }

    /// `packages/extend`: moves the end of an assignment: the assignment and every binding and membership it
    /// created get the new end together (null makes them permanent, unless the package caps durations). Shortening
    /// requires iam:packages:assign on the package; lengthening (or null) is granting, so it also needs the rights
    /// `assign` needs and a grant authority, and the package's bindings move to the extender's authority.
    /// Lengthening reaches only the roles and groups the package bundles now: records of ones taken out of the
    /// package since the assignment keep their end. Automatic assignments cannot be extended (INVALID_TRANSITION).
    /// Audited as `package:extend`.
    pub async fn extend(
        &self,
        credential: &CredentialInput,
        input: Body<packages::ExtendInput>,
    ) -> IamResult<Reply<packages::ExtendOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let pkg = ctx
                    .scoped(&tx, "accessPackages", body.get("packageId"), tenant_id)
                    .await?;
                let pkg_id = member_str(&pkg, "id").to_owned();
                let identity_id = text(body.get("identityId"), "identityId", 256)?;
                let assignment = find(
                    &tx,
                    "packageAssignments",
                    tenant_filter(tenant_id).eq("uniqueKey", format!("{pkg_id}:{identity_id}")),
                )
                .await?
                .into_iter()
                .next();
                let assignment = match assignment {
                    Some(assignment) if live(ctx, &assignment) => assignment,
                    _ => {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "The package is not assigned to this identity",
                            404,
                        )
                        .into());
                    }
                };
                if assignment.contains_key("ruleRevision") {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Automatic assignments end when the person stops matching the rule; assign the package manually to set an end",
                        409,
                    )
                    .into());
                }
                let requested = match body.get("expiresAt") {
                    None => {
                        return Err(invalid("expiresAt is required (null for no end)").into());
                    }
                    Some(Value::Null) => None,
                    Some(value) => Some(value),
                };
                let expires_at = assignment_end(ctx, &pkg, requested)?;
                // Lengthening is granting: it needs the rights `assign` needs, and the bindings move to the
                // extender's authority so the longer grant is bounded by what the extender may give. Those rights
                // are checked for the package's current contents, so only records of those roles and groups are
                // lengthened (and moved); the rest keep their end and authority (retimeAssignment). Shortening needs
                // no more than iam:packages:assign, like revoking.
                if end(expires_at) > end(num(&assignment, "expiresAt")) {
                    let authority = authorize_package_record(
                        ctx,
                        &tx,
                        &principal,
                        &pkg,
                        &AuthorizeOptions {
                            group_authorities: true,
                            ..AuthorizeOptions::default()
                        },
                    )
                    .await?;
                    if let Some(authority) = authority {
                        let role_ids = string_list(&pkg, "roleIds");
                        let assignment_id = member_str(&assignment, "id");
                        for binding_id in string_list(&assignment, "bindingIds") {
                            let Some(binding) = tx.get("bindings", &binding_id).await? else {
                                continue;
                            };
                            if binding.get("packageAssignmentId").and_then(Value::as_str)
                                != Some(assignment_id)
                                || member_str(&binding, "authorityId") == authority.id
                                || !role_ids
                                    .iter()
                                    .any(|role| role == member_str(&binding, "roleId"))
                            {
                                continue;
                            }
                            let unique_key = format!(
                                "{}:{}:{}:{}:package:{}",
                                js_string(binding.get("subjectType")),
                                js_string(binding.get("subjectId")),
                                js_string(binding.get("roleId")),
                                authority.id,
                                assignment_id
                            );
                            let mut moved = binding.clone();
                            moved.insert("authorityId".into(), string(authority.id.clone()));
                            moved.insert("uniqueKey".into(), string(unique_key));
                            tx.put("bindings", &moved).await?;
                        }
                    }
                }
                let updated =
                    retime_assignment_record(ctx, &tx, &pkg, &assignment, expires_at, None).await?;
                let mut metadata = Map::new();
                metadata.insert("packageId".into(), string(pkg_id.clone()));
                metadata.insert("packageName".into(), string(member_str(&pkg, "name")));
                metadata.insert(
                    "identityId".into(),
                    string(member_str(&assignment, "identityId")),
                );
                if let Some(previous) = assignment.get("expiresAt") {
                    metadata.insert("previousExpiresAt".into(), previous.clone());
                }
                if let Some(expires_at) = expires_at {
                    metadata.insert("expiresAt".into(), number(expires_at));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "package:extend",
                        tenant_id,
                        &pkg_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let summary = summarize(ctx, &tx, vec![updated]).await?;
                Ok(summary.into_iter().next().unwrap_or(Value::Null))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:assign",
                &string_member(&input, "packageId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/get`: a package with its live holder counts and, for a rule package, the rule's status. Requires
    /// iam:packages:read.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<packages::GetInput>,
    ) -> IamResult<Reply<packages::GetOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let pkg = ctx
                    .scoped(&tx, "accessPackages", body.get("packageId"), tenant_id)
                    .await?;
                Ok(Value::Object(public_view(ctx, &tx, &pkg, None).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:read",
                &string_member(&input, "packageId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/list`: the tenant's packages by name, each with its live holder counts. Requires
    /// iam:packages:read.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<packages::ListInput>,
    ) -> IamResult<Reply<packages::ListOutput>> {
        let ctx = &self.ctx;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut packages = find(&tx, "accessPackages", tenant_filter(tenant_id)).await?;
                packages.sort_by(by_name);
                let mut listed = Vec::new();
                let mut env: Option<RuleEnvironment> = None;
                for pkg in &packages {
                    let ruled = truthy(pkg.get("autoAssign"));
                    if ruled && env.is_none() {
                        env = Some(rule_env(ctx, &tx, pkg).await?);
                    }
                    let own = match (&env, ruled) {
                        (Some(env), true) => {
                            let mut own = env.clone();
                            own.packaged_groups =
                                Some(string_list(pkg, "groupIds").into_iter().collect());
                            Some(own)
                        }
                        _ => None,
                    };
                    listed.push(Value::Object(public_view(ctx, &tx, pkg, own).await?));
                }
                Ok(Value::Array(listed))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:read",
                tenant_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/listApprovals`: the pending requests the caller may decide on: iam:packages:approve on each
    /// package, the package's approver rules, never their own. Requires iam:packages:approve on the tenant.
    pub async fn list_approvals(
        &self,
        credential: &CredentialInput,
        input: Body<packages::ListApprovalsInput>,
    ) -> IamResult<Reply<packages::ListApprovalsOutput>> {
        let ctx = &self.ctx;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let now = ctx.now();
                let mut packages: IndexMap<String, Option<Record>> = IndexMap::new();
                let mut pending = Vec::new();
                for request in find(
                    &tx,
                    "packageRequests",
                    tenant_filter(tenant_id).eq("status", "pending"),
                )
                .await?
                {
                    if !pending_request(&request, now)
                        || member_str(&request, "identityId") == principal.identity.id
                    {
                        continue;
                    }
                    let package_id = member_str(&request, "packageId").to_owned();
                    if !packages.contains_key(&package_id) {
                        let pkg = tx.get("accessPackages", &package_id).await?;
                        let decidable = match &pkg {
                            Some(pkg) if truthy(pkg.get("requestable")) => {
                                ctx.decisions()?
                                    .decide(
                                        &tx,
                                        &principal,
                                        &AuthorizationRequest {
                                            credential: CredentialInput::default(),
                                            tenant_id: tenant_id.clone(),
                                            action: "iam:packages:approve".into(),
                                            resource: ResourceTarget {
                                                kind: "iam".into(),
                                                id: member_str(pkg, "id").to_owned(),
                                            },
                                        },
                                        true,
                                    )
                                    .await?
                                    .allowed
                            }
                            _ => false,
                        };
                        packages.insert(package_id.clone(), if decidable { pkg } else { None });
                    }
                    if let Some(Some(pkg)) = packages.get(&package_id)
                        && may_approve(
                            ctx,
                            &tx,
                            pkg,
                            &principal,
                            member_str(&request, "identityId"),
                        )
                        .await?
                    {
                        pending.push(request);
                    }
                }
                Ok(Value::Array(summarize_requests(&tx, pending, now).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:approve",
                tenant_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/listAssignments`: holders of a package, or the packages of an identity, newest first; ended
    /// assignments only with `includeExpired`; `source` keeps only automatic or manual ones. Requires
    /// iam:packages:read.
    pub async fn list_assignments(
        &self,
        credential: &CredentialInput,
        input: Body<packages::ListAssignmentsInput>,
    ) -> IamResult<Reply<packages::ListAssignmentsOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let source = body.get("source");
                if let Some(source) = source
                    && source.as_str() != Some("automatic")
                    && source.as_str() != Some("manual")
                {
                    return Err(invalid("source must be automatic or manual").into());
                }
                let mut filter = tenant_filter(tenant_id);
                if let Some(package_id) = body.get("packageId") {
                    ctx.scoped(&tx, "accessPackages", Some(package_id), tenant_id)
                        .await?;
                    filter = filter.eq("packageId", package_id.clone());
                }
                if let Some(identity_id) = body.get("identityId") {
                    filter = filter.eq("identityId", text(Some(identity_id), "identityId", 256)?);
                }
                let include_expired = body.get("includeExpired") == Some(&Value::Bool(true));
                let automatic_only = source.map(|source| source.as_str() == Some("automatic"));
                let assignments: Vec<Record> = find(&tx, "packageAssignments", filter)
                    .await?
                    .into_iter()
                    .filter(|assignment| {
                        (include_expired || live(ctx, assignment))
                            && automatic_only.is_none_or(|automatic| {
                                automatic == assignment.contains_key("ruleRevision")
                            })
                    })
                    .collect();
                Ok(Value::Array(summarize(ctx, &tx, assignments).await?))
            })
        });
        let resource = package_or_tenant(body);
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/listMine`: self-service view: the requestable packages (with their contents named, and the
    /// caller's live assignment or pending request on each), the caller's live assignments, and their recent
    /// requests. A package's rule is never shown here. Requires iam:packages:request on the tenant.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<packages::ListMineInput>,
    ) -> IamResult<Reply<packages::ListMineOutput>> {
        let ctx = &self.ctx;
        let tenant_id = string_member(&input, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let identity_id = principal.identity.id.clone();
                let now = ctx.now();
                let role_names: IndexMap<String, String> =
                    find(&tx, "roles", tenant_filter(tenant_id))
                        .await?
                        .iter()
                        .map(|role| {
                            (
                                member_str(role, "id").to_owned(),
                                member_str(role, "name").to_owned(),
                            )
                        })
                        .collect();
                let group_names: IndexMap<String, String> =
                    find(&tx, "groups", tenant_filter(tenant_id))
                        .await?
                        .iter()
                        .map(|group| {
                            (
                                member_str(group, "id").to_owned(),
                                member_str(group, "name").to_owned(),
                            )
                        })
                        .collect();
                let held: Vec<Record> = find(
                    &tx,
                    "packageAssignments",
                    tenant_filter(tenant_id).eq("identityId", identity_id.clone()),
                )
                .await?
                .into_iter()
                .filter(|assignment| live(ctx, assignment))
                .collect();
                let assignments = summarize(ctx, &tx, held).await?;
                let mut requests = summarize_requests(
                    &tx,
                    find(
                        &tx,
                        "packageRequests",
                        tenant_filter(tenant_id).eq("identityId", identity_id.clone()),
                    )
                    .await?,
                    now,
                )
                .await?;
                requests.truncate(50);
                let mut requestable: Vec<Record> =
                    find(&tx, "accessPackages", tenant_filter(tenant_id))
                        .await?
                        .into_iter()
                        .filter(|pkg| truthy(pkg.get("requestable")))
                        .collect();
                requestable.sort_by(by_name);
                let packages: Vec<Value> = requestable
                    .iter()
                    .map(|pkg| {
                        let pkg_id = member_str(pkg, "id");
                        let mut rest = pkg.clone();
                        rest.shift_remove("uniqueKey");
                        rest.shift_remove("autoAssign");
                        rest.shift_remove("roleIds");
                        rest.shift_remove("groupIds");
                        let named = |id: String, names: &IndexMap<String, String>| {
                            let name = names.get(&id).cloned().unwrap_or_else(|| id.clone());
                            let mut entry = Map::new();
                            entry.insert("id".into(), string(id));
                            entry.insert("name".into(), string(name));
                            Value::Object(entry)
                        };
                        rest.insert(
                            "roles".into(),
                            Value::Array(
                                string_list(pkg, "roleIds")
                                    .into_iter()
                                    .map(|id| named(id, &role_names))
                                    .collect(),
                            ),
                        );
                        rest.insert(
                            "groups".into(),
                            Value::Array(
                                string_list(pkg, "groupIds")
                                    .into_iter()
                                    .map(|id| named(id, &group_names))
                                    .collect(),
                            ),
                        );
                        if let Some(approver) = pkg.get("approverGroupId") {
                            let approver_id = js_string(Some(approver));
                            rest.insert(
                                "approverGroupName".into(),
                                string(
                                    group_names
                                        .get(&approver_id)
                                        .cloned()
                                        .unwrap_or(approver_id),
                                ),
                            );
                        }
                        if let Some(assignment) = assignments.iter().find(|assignment| {
                            assignment.get("packageId").and_then(Value::as_str) == Some(pkg_id)
                        }) {
                            rest.insert("assignment".into(), assignment.clone());
                        }
                        if let Some(request) = requests.iter().find(|request| {
                            request.get("packageId").and_then(Value::as_str) == Some(pkg_id)
                                && request
                                    .as_object()
                                    .is_some_and(|request| pending_request(request, now))
                        }) {
                            rest.insert("pending".into(), request.clone());
                        }
                        Value::Object(rest)
                    })
                    .collect();
                let mut result = Map::new();
                result.insert("packages".into(), Value::Array(packages));
                result.insert("assignments".into(), Value::Array(assignments));
                result.insert("requests".into(), Value::Array(requests));
                Ok(Value::Object(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:request",
                tenant_id,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/listRequests`: requests of a package or an identity, newest first, optionally by `status`.
    /// Requires iam:packages:read.
    pub async fn list_requests(
        &self,
        credential: &CredentialInput,
        input: Body<packages::ListRequestsInput>,
    ) -> IamResult<Reply<packages::ListRequestsOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut filter = tenant_filter(tenant_id);
                if let Some(package_id) = body.get("packageId") {
                    ctx.scoped(&tx, "accessPackages", Some(package_id), tenant_id)
                        .await?;
                    filter = filter.eq("packageId", package_id.clone());
                }
                if let Some(identity_id) = body.get("identityId") {
                    filter = filter.eq("identityId", text(Some(identity_id), "identityId", 256)?);
                }
                let status = body.get("status");
                if let Some(status) = status
                    && !status
                        .as_str()
                        .is_some_and(|status| PACKAGE_REQUEST_STATUSES.contains(&status))
                {
                    return Err(invalid("Invalid status").into());
                }
                // Filtered on the reported status, so a lapsed request counts as expired before the worker marks it.
                let requests =
                    summarize_requests(&tx, find(&tx, "packageRequests", filter).await?, ctx.now())
                        .await?;
                Ok(Value::Array(
                    requests
                        .into_iter()
                        .filter(|request| {
                            status.is_none_or(|status| request.get("status") == Some(status))
                        })
                        .collect(),
                ))
            })
        });
        let resource = package_or_tenant(body);
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/previewAutoAssign`: what a rule matches: the stored rule of `packageId`, a candidate
    /// `autoAssign`, or neither (the valid keys only). With `packageId` it also shows what a run would change and
    /// whether the brakes would hold it back. Writes nothing. Requires iam:packages:read, and iam:identities:read to
    /// evaluate a rule.
    pub async fn preview_auto_assign(
        &self,
        credential: &CredentialInput,
        input: Body<packages::PreviewAutoAssignInput>,
    ) -> IamResult<Reply<packages::PreviewAutoAssignOutput>> {
        let ctx = &self.ctx;
        let body = input.value();
        let body = &body;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let preview = preview_rule(ctx, &tx, &principal, body).await?;
                Ok(Value::Object(encode(&preview)))
            })
        });
        let resource = package_or_tenant(input.raw());
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:read",
                &resource,
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/reconcile`: runs the rule reconciler now for the tenant or one package (at most `limit` changes).
    /// Unusually large changes are held back unless `confirm` (with `packageId`), which approves the planned counts
    /// for a day and needs the rights to assign the package by hand. Requires iam:packages:assign. Audited per
    /// change as `package:auto-*`.
    pub async fn reconcile(
        &self,
        credential: &CredentialInput,
        input: Body<packages::ReconcileInput>,
    ) -> IamResult<Reply<packages::ReconcileOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let prepared: Mutex<Option<(f64, AuthenticatedPrincipal)>> = Mutex::new(None);
        let prepared_ref = &prepared;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                if let Some(package_id) = body.get("packageId") {
                    ctx.scoped(&tx, "accessPackages", Some(package_id), tenant_id)
                        .await?;
                }
                let fallback = number(1000.0);
                let limit = integer(
                    Some(match body.get("limit") {
                        None | Some(Value::Null) => &fallback,
                        Some(value) => value,
                    }),
                    "limit",
                    1.0,
                    10000.0,
                )?;
                if let Some(confirm) = body.get("confirm") {
                    boolean(Some(confirm), "confirm")?;
                }
                if truthy(body.get("confirm")) {
                    let Some(package_id) = body.get("packageId") else {
                        return Err(invalid("confirm needs packageId").into());
                    };
                    let pkg = tx
                        .get("accessPackages", &js_string(Some(package_id)))
                        .await?
                        .ok_or_else(internal_error)?;
                    if !truthy(pkg.get("autoAssign")) {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "This package has no rule",
                            409,
                        )
                        .into());
                    }
                    // A confirmer must be able to grant the package by hand.
                    authorize_package_record(
                        ctx,
                        &tx,
                        &principal,
                        &pkg,
                        &AuthorizeOptions {
                            group_authorities: true,
                            ..AuthorizeOptions::default()
                        },
                    )
                    .await?;
                }
                *prepared_ref.lock().map_err(|_| internal_error())? =
                    Some((limit, principal.clone()));
                let mut result = Map::new();
                result.insert("limit".into(), number(limit));
                Ok(Value::Object(result))
            })
        });
        let resource = package_or_tenant(body);
        ctx.operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:assign",
                &resource,
                mutation,
                false,
            )
            .await?;
        let (limit, principal) = prepared
            .lock()
            .map_err(|_| internal_error())?
            .take()
            .ok_or_else(internal_error)?;
        let mut options = Map::new();
        options.insert("tenantId".into(), string(tenant_id.clone()));
        copy(&mut options, body, "packageId");
        options.insert("limit".into(), number(limit));
        options.insert("trigger".into(), string("manual"));
        options.insert("requestedBy".into(), string(principal.identity.id.clone()));
        if truthy(body.get("confirm")) {
            options.insert("confirmedBy".into(), principal_value(&principal)?);
        }
        let result = reconcile_package_rules(ctx, &Value::Object(options)).await?;
        Ok(Reply::json(Value::Object(encode(&result))))
    }

    /// `packages/request`: self-service: asks for a requestable package for oneself, with the end and
    /// justification the package requires, from an ordinary session of the tenant. The request waits for the
    /// tenant's `approvalLifetimeMs` (one day by default) but never beyond the end it asks for; the designated
    /// approvers are emailed (`package-request`), and a request no approver could act on is refused. Requires
    /// iam:packages:request on the package. Audited as `package:request`.
    pub async fn request(
        &self,
        credential: &CredentialInput,
        input: Body<packages::RequestInput>,
    ) -> IamResult<Reply<packages::RequestOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| {
                Box::pin(async move {
                    let pkg = ctx
                        .scoped(&tx, "accessPackages", body.get("packageId"), tenant_id)
                        .await?;
                    if !truthy(pkg.get("requestable")) {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "This package cannot be requested",
                            409,
                        )
                        .into());
                    }
                    if !acts_in_own_right(principal.session.kind)
                        || principal.session.tenant_id != *tenant_id
                    {
                        return Err(invalid(
                            "Requests are made from an ordinary session of the target tenant",
                        )
                        .into());
                    }
                    if principal.session.impersonator_id.is_some() {
                        return Err(IamError::with_status(
                            "IMPERSONATION_RESTRICTED",
                            "Packages cannot be requested while impersonating",
                            403,
                        )
                        .into());
                    }
                    let pkg_id = member_str(&pkg, "id").to_owned();
                    let pkg_name = member_str(&pkg, "name").to_owned();
                    let identity_id = principal.identity.id.clone();
                    let now = ctx.now();
                    let held = find(
                        &tx,
                        "packageAssignments",
                        tenant_filter(tenant_id).eq("uniqueKey", format!("{pkg_id}:{identity_id}")),
                    )
                    .await?
                    .into_iter()
                    .next();
                    if let Some(held) = held
                        && live(ctx, &held)
                        && !assignment_broken(ctx, &tx, &held).await?
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "You already hold this package",
                            409,
                        )
                        .into());
                    }
                    let open = find(
                        &tx,
                        "packageRequests",
                        tenant_filter(tenant_id)
                            .eq("packageId", pkg_id.clone())
                            .eq("identityId", identity_id.clone())
                            .eq("status", "pending"),
                    )
                    .await?
                    .iter()
                    .any(|request| pending_request(request, now));
                    if open {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "Your request is still awaiting a decision",
                            409,
                        )
                        .into());
                    }
                    let desired_expires_at = assignment_end(ctx, &pkg, body.get("expiresAt"))?;
                    let justification = justification_for(&pkg, body.get("justification"))?;
                    // A request that names its approvers must reach at least one who can act on it.
                    let mut approvers: Vec<Record> = Vec::new();
                    for approver_id in approver_ids(ctx, &tx, &pkg, &identity_id).await? {
                        if let Some(approver) = tx.get("identities", &approver_id).await?
                            && approver.get("status").and_then(Value::as_str) == Some("active")
                        {
                            approvers.push(approver);
                        }
                    }
                    if (truthy(pkg.get("approverGroupId")) || truthy(pkg.get("managerApproval")))
                        && approvers.is_empty()
                    {
                        return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        "Nobody can approve this request: the approver group is empty and you have no active manager",
                        409,
                    )
                    .into());
                    }
                    let lifetime = tenant
                        .access_policy
                        .as_ref()
                        .and_then(|policy| policy.approval_lifetime_ms)
                        .unwrap_or(DEFAULT_APPROVAL_LIFETIME_MS);
                    // A request cannot outlive the access it asks for.
                    let lapses_at = (now + lifetime).min(end(desired_expires_at));
                    let request_id = id();
                    let mut request = Record::new();
                    request.insert("id".into(), string(request_id.clone()));
                    request.insert("tenantId".into(), string(tenant_id.clone()));
                    request.insert("packageId".into(), string(pkg_id.clone()));
                    request.insert("identityId".into(), string(identity_id.clone()));
                    request.insert("status".into(), string("pending"));
                    request.insert("requestedAt".into(), number(now));
                    request.insert("expiresAt".into(), number(lapses_at));
                    if let Some(desired) = desired_expires_at {
                        request.insert("desiredExpiresAt".into(), number(desired));
                    }
                    if let Some(justification) = &justification {
                        request.insert("justification".into(), string(justification.clone()));
                    }
                    tx.insert("packageRequests", &request).await?;
                    let mut metadata = Map::new();
                    metadata.insert("requestId".into(), string(request_id.clone()));
                    metadata.insert("packageId".into(), string(pkg_id.clone()));
                    metadata.insert("packageName".into(), string(pkg_name.clone()));
                    metadata.insert("lapsesAt".into(), number(lapses_at));
                    if let Some(desired) = desired_expires_at {
                        metadata.insert("desiredExpiresAt".into(), number(desired));
                    }
                    if let Some(justification) = &justification {
                        metadata.insert("justification".into(), string(justification.clone()));
                    }
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            "package:request",
                            tenant_id,
                            &pkg_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    for approver in &approvers {
                        let mut payload = Map::new();
                        payload.insert("requestId".into(), string(request_id.clone()));
                        payload.insert("packageId".into(), string(pkg_id.clone()));
                        payload.insert("packageName".into(), string(pkg_name.clone()));
                        payload.insert(
                            "requesterName".into(),
                            string(principal.identity.name.clone()),
                        );
                        if let Some(email) = principal
                            .identity
                            .email
                            .as_ref()
                            .filter(|email| !email.is_empty())
                        {
                            payload.insert("requesterEmail".into(), string(email.clone()));
                        }
                        payload.insert("lapsesAt".into(), string(number_text(lapses_at)));
                        if let Some(desired) = desired_expires_at {
                            payload.insert("expiresAt".into(), string(number_text(desired)));
                        }
                        if let Some(justification) = &justification {
                            payload.insert("justification".into(), string(justification.clone()));
                        }
                        notify(
                            ctx,
                            &tx,
                            tenant_id,
                            approver.get("email").and_then(Value::as_str),
                            "package-request",
                            payload,
                        )
                        .await?;
                    }
                    let summary = summarize_requests(&tx, vec![request], now).await?;
                    Ok(summary.into_iter().next().unwrap_or(Value::Null))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:request",
                &string_member(&input, "packageId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/revoke`: removes exactly what the assignment added and the assignment itself. The assignment owns
    /// its records whichever authority issued them, so iam:packages:assign on the package is all it takes. An
    /// automatic assignment of a package that still has its rule cannot be revoked (INVALID_TRANSITION): exclude
    /// the person in the rule. Audited as `package:revoke`.
    pub async fn revoke(
        &self,
        credential: &CredentialInput,
        input: Body<packages::RevokeInput>,
    ) -> IamResult<Reply<packages::RevokeOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let pkg = ctx
                    .scoped(&tx, "accessPackages", body.get("packageId"), tenant_id)
                    .await?;
                let pkg_id = member_str(&pkg, "id").to_owned();
                let identity_id = text(body.get("identityId"), "identityId", 256)?;
                let Some(assignment) = find(
                    &tx,
                    "packageAssignments",
                    tenant_filter(tenant_id).eq("uniqueKey", format!("{pkg_id}:{identity_id}")),
                )
                .await?
                .into_iter()
                .next() else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "The package is not assigned to this identity",
                        404,
                    )
                    .into());
                };
                if assignment.contains_key("ruleRevision")
                    && truthy(pkg.get("autoAssign"))
                    && live(ctx, &assignment)
                {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        format!(
                            "Assigned by the package rule: exclude the person in the rule (exclude: [{{ StringEquals: {{ \"principal.id\": \"{}\" }} }}]), change their attributes, or assign the package manually to take it over",
                            js_string(assignment.get("identityId"))
                        ),
                        409,
                    )
                    .into());
                }
                let (bindings, memberships) =
                    revoke_assignment_record(ctx, &tx, &assignment).await?;
                let mut metadata = Map::new();
                metadata.insert("packageId".into(), string(pkg_id.clone()));
                metadata.insert("packageName".into(), string(member_str(&pkg, "name")));
                metadata.insert(
                    "identityId".into(),
                    string(member_str(&assignment, "identityId")),
                );
                metadata.insert("bindings".into(), number(bindings));
                metadata.insert("memberships".into(), number(memberships));
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "package:revoke",
                        tenant_id,
                        &pkg_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                let mut result = Map::new();
                result.insert("revoked".into(), Value::Bool(true));
                result.insert("bindings".into(), number(bindings));
                result.insert("memberships".into(), number(memberships));
                Ok(Value::Object(result))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:assign",
                &string_member(&input, "packageId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `packages/update`: changes name, description, contents, or rules; existing manual assignments keep what
    /// they were given, automatic ones follow the package. `autoAssign` sets, changes, or takes over the rule (the
    /// caller becomes its owner, with the checks of `create`); null clears it (automatic holders lose the package at
    /// the next reconcile, or keep it as manual assignments with `keepAutomaticAssignments`). Changing a rule
    /// package's roles or groups makes the caller its owner. Requires iam:packages:update. Audited as
    /// `package:auto-rule` when the rule changes.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<packages::UpdateInput>,
    ) -> IamResult<Reply<packages::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = input.raw();
        let tenant_id = string_member(body, "tenantId");
        let tenant_id = &tenant_id;
        let ruled: Ruled = Mutex::new(None);
        let ruled_ref = &ruled;
        let mutation: Mutation<'_> = Box::new(move |MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let before = ctx
                    .scoped(&tx, "accessPackages", body.get("packageId"), tenant_id)
                    .await?;
                let mut pkg =
                    update_package_record(ctx, &tx, &before, body, Some(&principal)).await?;
                let before_rule = before.get("autoAssign");
                let after_rule = pkg.get("autoAssign");
                let touched = !same_member(
                    before_rule.and_then(|rule| rule.get("updatedAt")),
                    after_rule.and_then(|rule| rule.get("updatedAt")),
                ) || truthy(before_rule) != truthy(after_rule);
                if touched {
                    if truthy(pkg.get("autoAssign")) {
                        pkg = approved_package(ctx, &tx, &pkg).await?;
                    }
                    *ruled_ref.lock().map_err(|_| internal_error())? =
                        Some((pkg.clone(), principal.identity.id.clone()));
                }
                Ok(Value::Object(public_view(ctx, &tx, &pkg, None).await?))
            })
        });
        let view = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:packages:update",
                &string_member(&input, "packageId"),
                mutation,
                false,
            )
            .await?;
        let ruled = ruled.lock().map_err(|_| internal_error())?.take();
        match ruled {
            None => Ok(Reply::json(view)),
            Some((pkg, requested_by)) => Ok(Reply::json(
                self.after_rule_change(&pkg, &requested_by).await?,
            )),
        }
    }
}

/// `input.packageId ?? input.tenantId`, the resource an operation authorizes on.
fn package_or_tenant(input: &Map<String, Value>) -> String {
    match input.get("packageId") {
        None | Some(Value::Null) => string_member(input, "tenantId"),
        Some(_) => string_member(input, "packageId"),
    }
}

/// The principal a confirmed reconcile runs for (`confirmedBy`), in the JSON shape the reconciler reads.
fn principal_value(principal: &AuthenticatedPrincipal) -> IamResult<Value> {
    let mut value = Map::new();
    value.insert(
        "identity".into(),
        serde_json::to_value(&principal.identity).map_err(|_| internal_error())?,
    );
    value.insert(
        "session".into(),
        serde_json::to_value(&principal.session).map_err(|_| internal_error())?,
    );
    if let Some(proof) = &principal.device_proof {
        value.insert("deviceProof".into(), string(proof.clone()));
    }
    Ok(Value::Object(value))
}

/// `(await approveRule(ctx, tx, pkg)).pkg`.
async fn approved_package(ctx: &Arc<ServerContext>, tx: &Store, pkg: &Record) -> IamResult<Record> {
    let typed: AccessPackage = decode(pkg.clone())?;
    let approved = approve_rule(ctx, tx, &typed).await?;
    approved
        .get("pkg")
        .and_then(Value::as_object)
        .cloned()
        .ok_or_else(internal_error)
}

/// What a rule matches and, for a package, what a run would change.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AutoAssignPreview {
    #[serde(rename = "rule")]
    pub rule: String,
    #[serde(rename = "keys")]
    pub keys: Vec<crate::package_rules::RuleKey>,
    #[serde(rename = "warnings")]
    pub warnings: Vec<String>,
    #[serde(rename = "matching")]
    pub matching: f64,
    #[serde(rename = "excluded")]
    pub excluded: f64,
    #[serde(rename = "frozen")]
    pub frozen: f64,
    #[serde(rename = "sample")]
    pub sample: Vec<Value>,
    /// Only with packageId.
    #[serde(rename = "plan", default, skip_serializing_if = "Option::is_none")]
    pub plan: Option<Value>,
    #[serde(rename = "changes", default, skip_serializing_if = "Option::is_none")]
    pub changes: Option<Vec<Value>>,
    #[serde(rename = "brake", default, skip_serializing_if = "Option::is_none")]
    pub brake: Option<Value>,
    #[serde(rename = "status", default, skip_serializing_if = "Option::is_none")]
    pub status: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// What a reconcile run did, and what needs attention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PackageReconcileResult {
    #[serde(rename = "trigger")]
    pub trigger: crate::api::packages::ReconcileTrigger,
    #[serde(rename = "assigned")]
    pub assigned: f64,
    #[serde(rename = "refreshed")]
    pub refreshed: f64,
    #[serde(rename = "restored")]
    pub restored: f64,
    #[serde(rename = "ending")]
    pub ending: f64,
    #[serde(rename = "revoked")]
    pub revoked: f64,
    /// Planned changes skipped because the state moved between planning and applying; retried next run.
    #[serde(rename = "stale")]
    pub stale: f64,
    #[serde(rename = "failed")]
    pub failed: Vec<Value>,
    #[serde(rename = "suspended")]
    pub suspended: Vec<Value>,
    #[serde(rename = "braked")]
    pub braked: Vec<Value>,
    #[serde(rename = "skipped")]
    pub skipped: Value,
    /// The change budget ran out; run again.
    #[serde(rename = "truncated")]
    pub truncated: bool,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// A package's rule as administrators see it: the rule, who it runs as, whether it runs, and what went wrong.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PublicAutoAssign {
    #[serde(rename = "ownerName")]
    pub owner_name: String,
    #[serde(rename = "status")]
    pub status: String,
    #[serde(
        rename = "suspendedReason",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub suspended_reason: Option<String>,
    #[serde(
        rename = "suspendedDetail",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub suspended_detail: Option<String>,
    #[serde(rename = "warnings")]
    pub warnings: Vec<String>,
    #[serde(rename = "issueCount")]
    pub issue_count: f64,
    /// Newest first, at most 20.
    #[serde(rename = "issues")]
    pub issues: Vec<Value>,
    /// 1-10 clauses; an identity matches when any clause holds.
    #[serde(rename = "include")]
    pub include: Vec<Value>,
    /// 0-10 clauses; an identity matching any of them never matches (deny wins).
    #[serde(rename = "exclude", default, skip_serializing_if = "Option::is_none")]
    pub exclude: Option<Vec<Value>>,
    /// Automatic holders keep the package this long after they stop matching (at most 90 days); absent: removed at the
    /// next reconcile.
    #[serde(rename = "graceMs", default, skip_serializing_if = "Option::is_none")]
    pub grace_ms: Option<f64>,
    /// Unattended runs hold back this package's new grants (assign and refresh) above this count (default 100).
    #[serde(rename = "maxGrants", default, skip_serializing_if = "Option::is_none")]
    pub max_grants: Option<f64>,
    /// Unattended runs hold back this package's removals (revoke and grace starts) above this count (default 25).
    #[serde(
        rename = "maxRemovals",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub max_removals: Option<f64>,
    /// The identity whose grant authority and rights the rule runs under.
    #[serde(rename = "ownerId")]
    pub owner_id: String,
    /// The owner's grant authority; every automatic binding is issued under it.
    #[serde(rename = "authorityId")]
    pub authority_id: String,
    /// Starts at 1; increments when the owner, the authority, or the package's roles or groups change.
    #[serde(rename = "revision")]
    pub revision: f64,
    #[serde(rename = "updatedAt")]
    pub updated_at: f64,
    /// Planned change counts a person approved (an API save or a confirmed reconcile); unattended runs may apply up to
    /// these until `until`.
    #[serde(rename = "approved", default, skip_serializing_if = "Option::is_none")]
    pub approved: Option<Value>,
    /// Members this type does not declare.
    #[serde(flatten)]
    pub extra: Map<String, Value>,
}

/// `'schedule' | 'identity-change' | 'rule-change' | 'manual'`.
pub type ReconcileTrigger = Value;

/// `'assign' | 'refresh' | 'restore' | 'ending' | 'revoke'`.
pub type RuleChange = Value;

/// `'invalid-rule' | 'owner-inactive' | 'authority-revoked' | 'owner-lacks-rights'`.
pub type RuleSuspension = Value;

// --- shared helpers ----------------------------------------------------------------------------------------------

/// The roles and groups a package bundles must exist in the tenant, and protected roles are never packaged.
async fn contents(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    role_ids: &[String],
    group_ids: &[String],
) -> IamResult<()> {
    if role_ids.len() > MAX_CONTENTS || group_ids.len() > MAX_CONTENTS {
        return Err(invalid(format!(
            "A package holds at most {MAX_CONTENTS} roles and {MAX_CONTENTS} groups"
        )));
    }
    if role_ids.is_empty() && group_ids.is_empty() {
        return Err(invalid("A package needs at least one role or group"));
    }
    for role_id in role_ids {
        let role = ctx
            .scoped(tx, "roles", Some(&id_value(role_id)), tenant_id)
            .await?;
        if truthy(role.get("protected")) {
            return Err(IamError::with_status(
                "PROTECTED_RESOURCE",
                "Protected roles cannot be packaged",
                403,
            ));
        }
    }
    // A team's backing group takes its members from the team only (teams.ts).
    for group_id in group_ids {
        let group = ctx
            .scoped(tx, "groups", Some(&id_value(group_id)), tenant_id)
            .await?;
        assert_not_team_group(Some(&Value::Object(group)))?;
    }
    Ok(())
}

async fn package_by_name(tx: &Store, tenant_id: &str, name: &str) -> IamResult<Option<Record>> {
    Ok(find(
        tx,
        "accessPackages",
        tenant_filter(tenant_id).eq("uniqueKey", name_key(name)),
    )
    .await?
    .into_iter()
    .next())
}

/// Every part of an assignment is authorized like the direct call, so a package never widens what its assigner may
/// grant.
pub async fn allow(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    tenant_id: &str,
    action: &str,
    resource_id: &str,
    what: &str,
) -> IamResult<()> {
    let decision = ctx
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
                    id: resource_id.to_owned(),
                },
            },
            true,
        )
        .await?;
    if !decision.allowed {
        return Err(IamError::with_status(
            "ACCESS_DENIED",
            format!("Not allowed to {what} ({action})"),
            403,
        ));
    }
    Ok(())
}

/// The options of `authorizePackage`.
#[derive(Debug, Clone, Default)]
struct AuthorizeOptions {
    group_authorities: bool,
    authority_id: Option<String>,
    require_authority: bool,
}

/// [`authorize_package`] on a raw package record.
async fn authorize_package_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    pkg: &Record,
    options: &AuthorizeOptions,
) -> OperationResult<Option<GrantAuthority>> {
    let tenant_id = member_str(pkg, "tenantId");
    let role_ids = string_list(pkg, "roleIds");
    let group_ids = string_list(pkg, "groupIds");
    for role_id in &role_ids {
        allow(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:bindings:create",
            role_id,
            "grant a packaged role",
        )
        .await?;
    }
    for group_id in &group_ids {
        allow(
            ctx,
            tx,
            principal,
            tenant_id,
            "iam:groups:update",
            group_id,
            "add to a packaged group",
        )
        .await?;
        if options.group_authorities {
            for binding in find(
                tx,
                "bindings",
                tenant_filter(tenant_id)
                    .eq("subjectType", "group")
                    .eq("subjectId", group_id.clone()),
            )
            .await?
            {
                ctx.granting_authority(
                    tx,
                    principal,
                    tenant_id,
                    Some(member_str(&binding, "authorityId")),
                )
                .await?;
            }
        }
    }
    assert_may_claim_licenses(
        ctx,
        tx,
        principal,
        tenant_id,
        &Value::Array(group_ids.iter().cloned().map(Value::String).collect()),
        Some(
            "A group this package includes carries license seats; granting it needs iam:licenses:assign",
        ),
    )
    .await?;
    let authority_id = options
        .authority_id
        .as_deref()
        .filter(|authority| !authority.is_empty());
    if role_ids.is_empty() && !options.require_authority && authority_id.is_none() {
        return Ok(None);
    }
    Ok(Some(
        ctx.granting_authority(tx, principal, tenant_id, authority_id)
            .await?,
    ))
}

/// The rights assigning a package by hand needs: iam:bindings:create on each role and iam:groups:update on each
/// group, and (with `groupAuthorities`) the use of every grant authority behind the groups' own bindings, which
/// membership confers. A packaged group that carries license seats (a product is assigned to it, or to a team it
/// syncs into) needs iam:licenses:assign too, refused with `OperationDenied` (api/groups.ts): so assigning or
/// approving the package, lengthening an assignment, confirming a rule's held-back changes, and saving or running a
/// rule (its owner; `ruleHealth` suspends the rule's additions in advance) all need it. Returns the caller's grant
/// authority when the package has roles (or `requireAuthority`). Callers outside a transaction must pass
/// `authorityId`: the root path of grantingAuthority writes a record.
///
/// `options`: `{ groupAuthorities?: boolean, authorityId?: string, requireAuthority?: boolean }`.
pub async fn authorize_package(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    pkg: &crate::models::AccessPackage,
    options: Option<&Value>,
) -> OperationResult<Option<crate::models::GrantAuthority>> {
    let option = |key: &str| options.and_then(|options| options.get(key));
    let options = AuthorizeOptions {
        group_authorities: truthy(option("groupAuthorities")),
        authority_id: option("authorityId")
            .and_then(Value::as_str)
            .map(str::to_owned),
        require_authority: truthy(option("requireAuthority")),
    };
    authorize_package_record(ctx, tx, principal, &encode(pkg), &options).await
}

/// What a rule of this package may name: the deployment's declared attributes and the tenant's groups, teams, and
/// departments.
pub async fn rule_environment(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    pkg: &Value,
) -> IamResult<crate::package_rules::RuleEnvironment> {
    let tenant_id = pkg
        .get("tenantId")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let groups: IndexSet<String> = find(reader, "groups", tenant_filter(tenant_id))
        .await?
        .iter()
        .map(|group| member_str(group, "id").to_owned())
        .collect();
    let packaged: IndexSet<String> = pkg
        .get("groupIds")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default();
    Ok(RuleEnvironment {
        identity_attributes: ctx.catalog.identity_attributes.clone(),
        groups: Some(groups),
        packaged_groups: Some(packaged),
        org: Some(org_rule_environment(reader, tenant_id).await?),
        extra: Map::new(),
    })
}

async fn rule_env(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    pkg: &Record,
) -> IamResult<RuleEnvironment> {
    rule_environment(ctx, reader, &Value::Object(pkg.clone())).await
}

/// The owner checks of a rule: an ordinary session or API key (never a role session, session token or
/// impersonation), iam:packages:assign on the package, the rights assigning by hand needs including the groups'
/// authorities, and a grant authority. The same owner re-saving keeps their authority when it is still usable, to
/// avoid re-issuing every binding. Answers `(ownerId, authorityId)`.
async fn author_rule(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    pkg: &Record,
    previous: Option<&Record>,
) -> OperationResult<(String, String)> {
    if !acts_in_own_right(principal.session.kind) {
        return Err(invalid(
            "Package rules are set from an ordinary session or API key of the tenant",
        )
        .into());
    }
    if principal.session.impersonator_id.is_some() {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Package rules cannot be set while impersonating",
            403,
        )
        .into());
    }
    let tenant_id = member_str(pkg, "tenantId");
    allow(
        ctx,
        tx,
        principal,
        tenant_id,
        "iam:packages:assign",
        member_str(pkg, "id"),
        "assign this package automatically",
    )
    .await?;
    let mut keep = previous
        .filter(|previous| {
            previous.get("ownerId").and_then(Value::as_str) == Some(principal.identity.id.as_str())
        })
        .and_then(|previous| previous.get("authorityId"))
        .and_then(Value::as_str)
        .filter(|authority| !authority.is_empty())
        .map(str::to_owned);
    if let Some(authority) = &keep
        && ctx
            .granting_authority(tx, principal, tenant_id, Some(authority))
            .await
            .is_err()
    {
        keep = None;
    }
    let authority = authorize_package_record(
        ctx,
        tx,
        principal,
        pkg,
        &AuthorizeOptions {
            group_authorities: true,
            require_authority: true,
            authority_id: keep,
        },
    )
    .await?
    .ok_or_else(internal_error)?;
    Ok((principal.identity.id.clone(), authority.id))
}

/// `autoAssign` in a create or update input: absent, null (clear), or a rule.
#[derive(Clone, Copy)]
enum RuleInput<'a> {
    Absent,
    Null,
    Set(&'a Value),
}

impl<'a> RuleInput<'a> {
    fn of(value: Option<&'a Value>) -> Self {
        match value {
            None => RuleInput::Absent,
            Some(Value::Null) => RuleInput::Null,
            Some(value) => RuleInput::Set(value),
        }
    }
}

/// The audit metadata of a rule.
fn rule_metadata(rule: &Record) -> Map<String, Value> {
    let mut metadata = Map::new();
    copy(&mut metadata, rule, "revision");
    copy(&mut metadata, rule, "ownerId");
    copy(&mut metadata, rule, "authorityId");
    copy(&mut metadata, rule, "include");
    if truthy(rule.get("exclude")) {
        copy(&mut metadata, rule, "exclude");
    }
    copy(&mut metadata, rule, "graceMs");
    copy(&mut metadata, rule, "maxGrants");
    copy(&mut metadata, rule, "maxRemovals");
    metadata
}

/// `package:auto-rule`, with the package named first.
async fn rule_audit(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    next: &Record,
    change: &str,
    metadata: Map<String, Value>,
) -> IamResult<()> {
    let mut full = Map::new();
    full.insert("packageId".into(), string(member_str(next, "id")));
    full.insert("packageName".into(), string(member_str(next, "name")));
    full.insert("change".into(), string(change));
    for (key, value) in metadata {
        full.insert(key, value);
    }
    ctx.events()?
        .audit(
            tx,
            principal,
            "package:auto-rule",
            member_str(next, "tenantId"),
            member_str(next, "id"),
            AuditOutcome::Allow,
            false,
            Some(full),
        )
        .await
}

/// A stored rule (`AutoAssignRule`) from an administrator's part and its runtime state.
fn stored_rule(
    written: &crate::package_rules::AutoAssignInput,
    owner_id: &str,
    authority_id: &str,
    revision: f64,
    updated_at: f64,
) -> Record {
    let mut rule = encode(written);
    rule.insert("ownerId".into(), string(owner_id));
    rule.insert("authorityId".into(), string(authority_id));
    rule.insert("revision".into(), number(revision));
    rule.insert("updatedAt".into(), number(updated_at));
    rule
}

/// Sets, changes, takes over, or clears a package's rule while the package is created or updated. Changing a rule
/// package's roles or groups re-authorizes the editor, who becomes the owner: someone holding only
/// iam:packages:update cannot add a role that is then granted under another administrator's authority.
#[allow(clippy::too_many_arguments)]
async fn apply_rule_change(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: Option<&AuthenticatedPrincipal>,
    previous: Option<&Record>,
    next: &mut Record,
    input: RuleInput<'_>,
    keep: bool,
) -> OperationResult<()> {
    let old: Option<Record> = previous
        .and_then(|previous| previous.get("autoAssign"))
        .filter(|rule| truthy(Some(rule)))
        .and_then(Value::as_object)
        .cloned();
    let contents_changed = previous.is_some_and(|previous| {
        !same_ids(
            &string_list(previous, "roleIds"),
            &string_list(next, "roleIds"),
        ) || !same_ids(
            &string_list(previous, "groupIds"),
            &string_list(next, "groupIds"),
        )
    });
    let require_principal =
        || principal.ok_or_else(|| invalid("A principal is required to change a package rule"));
    match input {
        RuleInput::Null => match &old {
            None => {
                if keep {
                    return Err(invalid("keepAutomaticAssignments needs a rule to clear").into());
                }
            }
            Some(old) => {
                let caller = require_principal()?;
                allow(
                    ctx,
                    tx,
                    caller,
                    member_str(next, "tenantId"),
                    "iam:packages:assign",
                    member_str(next, "id"),
                    "stop assigning this package automatically",
                )
                .await?;
                next.shift_remove("autoAssign");
                let mut kept = 0.0;
                if keep {
                    let automatic: Vec<Record> = package_assignments(ctx, tx, next, false)
                        .await?
                        .into_iter()
                        .filter(|assignment| assignment.contains_key("ruleRevision"))
                        .collect();
                    if automatic.len() > 5000 {
                        return Err(invalid(
                            "More than 5000 automatic holders; clear the rule without keepAutomaticAssignments",
                        )
                        .into());
                    }
                    for mut assignment in automatic {
                        assignment.shift_remove("ruleRevision");
                        tx.put("packageAssignments", &assignment).await?;
                        kept += 1.0;
                    }
                }
                for issue in find(
                    tx,
                    "packageRuleIssues",
                    tenant_filter(member_str(next, "tenantId"))
                        .eq("packageId", member_str(next, "id").to_owned()),
                )
                .await?
                {
                    tx.delete("packageRuleIssues", member_str(&issue, "id"))
                        .await?;
                }
                let mut metadata = Map::new();
                copy(&mut metadata, old, "revision");
                copy(&mut metadata, old, "ownerId");
                if keep {
                    metadata.insert("kept".into(), number(kept));
                }
                rule_audit(ctx, tx, require_principal()?, next, "clear", metadata).await?;
            }
        },
        _ if keep => {
            return Err(
                invalid("keepAutomaticAssignments applies only with autoAssign: null").into(),
            );
        }
        RuleInput::Set(value) => {
            let env = rule_env(ctx, tx, next).await?;
            let parsed = parse_auto_assign(Some(value), &env, None)?;
            let (owner_id, authority_id) =
                author_rule(ctx, tx, require_principal()?, next, old.as_ref()).await?;
            let moved = old.as_ref().is_some_and(|old| {
                old.get("ownerId").and_then(Value::as_str) != Some(owner_id.as_str())
                    || old.get("authorityId").and_then(Value::as_str) != Some(authority_id.as_str())
            });
            let revision = match &old {
                Some(old) => {
                    num(old, "revision").unwrap_or(f64::NAN)
                        + if moved || contents_changed { 1.0 } else { 0.0 }
                }
                None => 1.0,
            };
            let rule = stored_rule(&parsed, &owner_id, &authority_id, revision, ctx.now());
            next.insert("autoAssign".into(), Value::Object(rule.clone()));
            let change = match (&old, moved) {
                (None, _) => "set",
                (Some(_), true) => "owner",
                (Some(_), false) => "change",
            };
            let mut metadata = rule_metadata(&rule);
            if moved && let Some(old) = &old {
                copy_as(&mut metadata, old, "ownerId", "previousOwnerId");
            }
            rule_audit(ctx, tx, require_principal()?, next, change, metadata).await?;
        }
        RuleInput::Absent => {
            if let Some(old) = &old
                && contents_changed
            {
                let env = rule_env(ctx, tx, next).await?;
                if let Some(problem) = rule_problem(&Value::Object(old.clone()), &env)? {
                    return Err(invalid(format!(
                        "The package rule no longer fits the new contents: {problem}"
                    ))
                    .into());
                }
                let (owner_id, authority_id) =
                    author_rule(ctx, tx, require_principal()?, next, Some(old)).await?;
                let written = rule_input(&Value::Object(old.clone()))?;
                let revision = num(old, "revision").unwrap_or(f64::NAN) + 1.0;
                let rule = stored_rule(&written, &owner_id, &authority_id, revision, ctx.now());
                next.insert("autoAssign".into(), Value::Object(rule.clone()));
                let mut metadata = rule_metadata(&rule);
                if old.get("ownerId").and_then(Value::as_str) != Some(owner_id.as_str()) {
                    copy_as(&mut metadata, old, "ownerId", "previousOwnerId");
                }
                rule_audit(ctx, tx, require_principal()?, next, "contents", metadata).await?;
            }
        }
    }
    if truthy(next.get("autoAssign")) && next.contains_key("maxDurationMs") {
        return Err(invalid(
            "A package with an automatic-assignment rule cannot have a maximum duration; use graceMs for a delayed end",
        )
        .into());
    }
    Ok(())
}

/// `{ [as]: source[key] }` when the member is present.
fn copy_as(target: &mut Map<String, Value>, source: &Record, key: &str, name: &str) {
    if let Some(value) = source.get(key) {
        target.insert(name.to_owned(), value.clone());
    }
}

/// [`create_package`] on a raw input, answering the stored record.
pub async fn create_package_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    input: &Map<String, Value>,
    principal: Option<&AuthenticatedPrincipal>,
) -> OperationResult<Record> {
    let tenant_id = string_member(input, "tenantId");
    let name = text(input.get("name"), "name", 128)?;
    if package_by_name(tx, &tenant_id, &name).await?.is_some() {
        return Err(
            IamError::with_status("CONFLICT", "A package with this name exists", 409).into(),
        );
    }
    let role_ids = match input.get("roleIds") {
        None => Vec::new(),
        Some(value) => unique(strings(Some(value), "roleIds")?),
    };
    let group_ids = match input.get("groupIds") {
        None => Vec::new(),
        Some(value) => unique(strings(Some(value), "groupIds")?),
    };
    contents(ctx, tx, &tenant_id, &role_ids, &group_ids).await?;
    let now = ctx.now();
    let mut record = Record::new();
    record.insert("id".into(), string(id()));
    record.insert("tenantId".into(), string(tenant_id.clone()));
    record.insert("uniqueKey".into(), string(name_key(&name)));
    record.insert("name".into(), string(name));
    set_list(&mut record, "roleIds", &role_ids);
    set_list(&mut record, "groupIds", &group_ids);
    record.insert("createdAt".into(), number(now));
    record.insert("updatedAt".into(), number(now));
    if let Some(description) = input.get("description") {
        record.insert(
            "description".into(),
            string(text(Some(description), "description", 512)?),
        );
    }
    if let Some(max) = input.get("maxDurationMs") {
        record.insert(
            "maxDurationMs".into(),
            number(integer(Some(max), "maxDurationMs", 60_000.0, TEN_YEARS)?),
        );
    }
    if let Some(value) = input.get("requireJustification")
        && boolean(Some(value), "requireJustification")?
    {
        record.insert("requireJustification".into(), Value::Bool(true));
    }
    if let Some(value) = input.get("requestable")
        && boolean(Some(value), "requestable")?
    {
        record.insert("requestable".into(), Value::Bool(true));
    }
    if let Some(approver) = input
        .get("approverGroupId")
        .filter(|value| !value.is_null())
    {
        ctx.scoped(tx, "groups", Some(approver), &tenant_id).await?;
        record.insert("approverGroupId".into(), approver.clone());
    }
    if let Some(value) = input.get("managerApproval")
        && boolean(Some(value), "managerApproval")?
    {
        record.insert("managerApproval".into(), Value::Bool(true));
    }
    if input.contains_key("autoAssign") {
        apply_rule_change(
            ctx,
            tx,
            principal,
            None,
            &mut record,
            RuleInput::of(input.get("autoAssign")),
            false,
        )
        .await?;
    }
    Ok(tx.insert("accessPackages", &record).await?)
}

/// Creates a package; shared by `packages.create` and configuration sync.
pub async fn create_package(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    input: &Value,
    principal: Option<&better_iam_core::AuthenticatedPrincipal>,
) -> OperationResult<crate::models::AccessPackage> {
    let input = input.as_object().cloned().unwrap_or_default();
    Ok(decode(
        create_package_record(ctx, tx, &input, principal).await?,
    )?)
}

/// [`update_package`] on a raw package record and input, answering the stored record.
pub async fn update_package_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    existing: &Record,
    input: &Map<String, Value>,
    principal: Option<&AuthenticatedPrincipal>,
) -> OperationResult<Record> {
    let tenant_id = member_str(existing, "tenantId").to_owned();
    let existing_id = member_str(existing, "id").to_owned();
    let mut updated = existing.clone();
    updated.insert("updatedAt".into(), number(ctx.now()));
    if let Some(value) = input.get("name") {
        let name = text(Some(value), "name", 128)?;
        if let Some(other) = package_by_name(tx, &tenant_id, &name).await?
            && member_str(&other, "id") != existing_id
        {
            return Err(
                IamError::with_status("CONFLICT", "A package with this name exists", 409).into(),
            );
        }
        updated.insert("name".into(), string(name.clone()));
        updated.insert("uniqueKey".into(), string(name_key(&name)));
    }
    match input.get("description") {
        Some(Value::Null) => {
            updated.shift_remove("description");
        }
        Some(value) => {
            updated.insert(
                "description".into(),
                string(text(Some(value), "description", 512)?),
            );
        }
        None => {}
    }
    if let Some(value) = input.get("roleIds") {
        set_list(
            &mut updated,
            "roleIds",
            &unique(strings(Some(value), "roleIds")?),
        );
    }
    if let Some(value) = input.get("groupIds") {
        set_list(
            &mut updated,
            "groupIds",
            &unique(strings(Some(value), "groupIds")?),
        );
    }
    if input.contains_key("roleIds") || input.contains_key("groupIds") {
        contents(
            ctx,
            tx,
            &tenant_id,
            &string_list(&updated, "roleIds"),
            &string_list(&updated, "groupIds"),
        )
        .await?;
    }
    match input.get("maxDurationMs") {
        Some(Value::Null) => {
            updated.shift_remove("maxDurationMs");
        }
        Some(value) => {
            updated.insert(
                "maxDurationMs".into(),
                number(integer(Some(value), "maxDurationMs", 60_000.0, TEN_YEARS)?),
            );
        }
        None => {}
    }
    for flag in ["requireJustification", "requestable"] {
        if let Some(value) = input.get(flag) {
            if boolean(Some(value), flag)? {
                updated.insert(flag.into(), Value::Bool(true));
            } else {
                updated.shift_remove(flag);
            }
        }
    }
    match input.get("approverGroupId") {
        Some(Value::Null) => {
            updated.shift_remove("approverGroupId");
        }
        Some(value) => {
            ctx.scoped(tx, "groups", Some(value), &tenant_id).await?;
            updated.insert("approverGroupId".into(), value.clone());
        }
        None => {}
    }
    if let Some(value) = input.get("managerApproval") {
        if boolean(Some(value), "managerApproval")? {
            updated.insert("managerApproval".into(), Value::Bool(true));
        } else {
            updated.shift_remove("managerApproval");
        }
    }
    if let Some(value) = input.get("keepAutomaticAssignments") {
        boolean(Some(value), "keepAutomaticAssignments")?;
    }
    apply_rule_change(
        ctx,
        tx,
        principal,
        Some(existing),
        &mut updated,
        RuleInput::of(input.get("autoAssign")),
        input.get("keepAutomaticAssignments") == Some(&Value::Bool(true)),
    )
    .await?;
    // Pending requests the tightened rules no longer allow could never be approved; they are cancelled with the
    // reason.
    let now = ctx.now();
    for request in find(
        tx,
        "packageRequests",
        tenant_filter(&tenant_id)
            .eq("packageId", existing_id.clone())
            .eq("status", "pending"),
    )
    .await?
    {
        // A request that already lapsed keeps its history; the purge worker marks it expired.
        if !pending_request(&request, now) {
            continue;
        }
        let max_duration = updated
            .contains_key("maxDurationMs")
            .then(|| num(&updated, "maxDurationMs").unwrap_or(f64::NAN));
        let reason = if !truthy(updated.get("requestable")) {
            Some("The package can no longer be requested")
        } else if truthy(updated.get("requireJustification"))
            && !request.contains_key("justification")
        {
            Some("The package now requires a justification")
        } else if let Some(max) = max_duration
            && num(&request, "desiredExpiresAt").is_none_or(|desired| desired > now + max)
        {
            Some("The requested end no longer fits the package")
        } else {
            None
        };
        if let Some(reason) = reason {
            let mut cancelled = request.clone();
            cancelled.insert("status".into(), string("cancelled"));
            cancelled.insert("decidedAt".into(), number(now));
            cancelled.insert("note".into(), string(reason));
            tx.put("packageRequests", &cancelled).await?;
        }
    }
    Ok(tx.put("accessPackages", &updated).await?)
}

/// Changes a package's contents and rules; existing manual assignments keep what they were given. Changing the
/// contents of a package without a rule needs no rights over what is added or removed because it grants nothing:
/// extending an assignment lengthens only what the package still bundles (and the extender is authorized for), and
/// handing a shared membership over never lengthens it.
pub async fn update_package(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    existing: &crate::models::AccessPackage,
    input: &Value,
    principal: Option<&better_iam_core::AuthenticatedPrincipal>,
) -> OperationResult<crate::models::AccessPackage> {
    let input = input.as_object().cloned().unwrap_or_default();
    Ok(decode(
        update_package_record(ctx, tx, &encode(existing), &input, principal).await?,
    )?)
}

/// `packageAssignments(ctx, tx, pkg, includeExpired)`: the assignments of a package, live ones only unless
/// `include_expired`.
pub async fn package_assignments(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    pkg: &Record,
    include_expired: bool,
) -> IamResult<Vec<Record>> {
    Ok(find(
        tx,
        "packageAssignments",
        tenant_filter(member_str(pkg, "tenantId"))
            .eq("packageId", member_str(pkg, "id").to_owned()),
    )
    .await?
    .into_iter()
    .filter(|assignment| include_expired || live(ctx, assignment))
    .collect())
}

/// [`delete_package`] on a raw package record.
pub async fn delete_package_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    pkg: &Record,
) -> IamResult<()> {
    let held = package_assignments(ctx, tx, pkg, false).await?.len();
    if held > 0 {
        let noun = if held == 1 { "y" } else { "ies" };
        let message = if truthy(pkg.get("autoAssign")) {
            format!(
                "Still assigned to {held} identit{noun}; set autoAssign to null so reconciliation removes the automatic assignments, and revoke the manual ones"
            )
        } else {
            format!("Still assigned to {held} identit{noun}; revoke first")
        };
        return Err(IamError::with_status("RESOURCE_IN_USE", message, 409));
    }
    for ended in package_assignments(ctx, tx, pkg, true).await? {
        tx.delete("packageAssignments", member_str(&ended, "id"))
            .await?;
    }
    let tenant_id = member_str(pkg, "tenantId");
    let pkg_id = member_str(pkg, "id");
    for request in find(
        tx,
        "packageRequests",
        tenant_filter(tenant_id).eq("packageId", pkg_id.to_owned()),
    )
    .await?
    {
        tx.delete("packageRequests", member_str(&request, "id"))
            .await?;
    }
    for issue in find(
        tx,
        "packageRuleIssues",
        tenant_filter(tenant_id).eq("packageId", pkg_id.to_owned()),
    )
    .await?
    {
        tx.delete("packageRuleIssues", member_str(&issue, "id"))
            .await?;
    }
    tx.delete("accessPackages", pkg_id).await
}

/// Deletes a package nobody holds, with its request history; shared by `packages.delete` and configuration sync.
pub async fn delete_package(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    pkg: &crate::models::AccessPackage,
) -> IamResult<()> {
    delete_package_record(ctx, tx, &encode(pkg)).await
}

/// The end an assignment or request asks for, validated against the package's cap.
fn assignment_end(
    ctx: &ServerContext,
    pkg: &Record,
    value: Option<&Value>,
) -> IamResult<Option<f64>> {
    let expires_at = match value {
        Some(value) => Some(ctx.binding_expiry(Some(value))?),
        None => None,
    };
    if pkg.contains_key("maxDurationMs") {
        let max = num(pkg, "maxDurationMs").unwrap_or(f64::NAN);
        let Some(expires_at) = expires_at else {
            return Err(invalid("This package requires an end date (expiresAt)"));
        };
        if expires_at > ctx.now() + max {
            return Err(invalid(
                "expiresAt exceeds the maximum duration of this package",
            ));
        }
    }
    Ok(expires_at)
}

fn justification_for(pkg: &Record, value: Option<&Value>) -> IamResult<Option<String>> {
    let justification = match value {
        Some(value) => Some(text(Some(value), "justification", 2048)?),
        None => None,
    };
    if truthy(pkg.get("requireJustification")) && justification.is_none() {
        return Err(invalid("This package requires a justification"));
    }
    Ok(justification)
}

/// Ends compare with "no end" last.
pub fn end_of(expires_at: Option<f64>) -> IamResult<f64> {
    Ok(end(expires_at))
}

/// Whether an assignment still applies; an ended one grants nothing and waits for the purge worker.
pub fn live_assignment(
    ctx: &Arc<ServerContext>,
    assignment: &crate::models::PackageAssignment,
) -> IamResult<bool> {
    Ok(assignment
        .expires_at
        .is_none_or(|expires| expires > ctx.now()))
}

/// `assignmentBroken(ctx, tx, assignment)`: an assignment whose bindings no longer grant (the issuing authority was
/// revoked, for example when the assigner was offboarded, or a binding was removed or taken over by hand) is broken:
/// it may be replaced by a new one.
pub async fn assignment_broken(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    assignment: &Record,
) -> IamResult<bool> {
    let assignment_id = member_str(assignment, "id");
    for binding_id in string_list(assignment, "bindingIds") {
        let Some(binding) = tx.get("bindings", &binding_id).await? else {
            return Ok(true);
        };
        if binding.get("packageAssignmentId").and_then(Value::as_str) != Some(assignment_id) {
            return Ok(true);
        }
        if ctx
            .authority_chain(tx, member_str(&binding, "authorityId"))
            .await?
            .is_none()
        {
            return Ok(true);
        }
    }
    Ok(false)
}

/// The longest-lived other live assignment of the identity whose package includes the group.
async fn next_owner(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    tenant_id: &str,
    identity_id: &str,
    group_id: &str,
    exclude_id: &str,
) -> IamResult<Option<Record>> {
    let mut best: Option<Record> = None;
    for other in find(
        tx,
        "packageAssignments",
        tenant_filter(tenant_id).eq("identityId", identity_id.to_owned()),
    )
    .await?
    {
        if member_str(&other, "id") == exclude_id || !live(ctx, &other) {
            continue;
        }
        let pkg = tx
            .get("accessPackages", member_str(&other, "packageId"))
            .await?;
        if !pkg.is_some_and(|pkg| {
            string_list(&pkg, "groupIds")
                .iter()
                .any(|id| id == group_id)
        }) {
            continue;
        }
        if best
            .as_ref()
            .is_none_or(|best| end(num(&other, "expiresAt")) > end(num(best, "expiresAt")))
        {
            best = Some(other);
        }
    }
    Ok(best)
}

/// A group has one membership record per person, so packages that share a group share it: the record belongs to
/// the assignment that needs it longest. Handing it over moves its tag and end to the new owner, but never
/// lengthens it: the new owner's package may have gained the group after that assignment was made (packages.update
/// grants nothing), so the owner's end was never authorized for this group. Every assignment that did receive the
/// group already ends no later than the record (materialize and retimeAssignment keep the longest end on it).
async fn hand_over(tx: &Store, member: &Record, owner_id: &str) -> IamResult<()> {
    let Some(owner) = tx.get("packageAssignments", owner_id).await? else {
        return Ok(());
    };
    let mut handed = member.clone();
    handed.shift_remove("expiresAt");
    let until = end(num(member, "expiresAt")).min(end(num(&owner, "expiresAt")));
    if until != f64::INFINITY {
        handed.insert("expiresAt".into(), number(until));
    }
    handed.insert(
        "packageAssignmentId".into(),
        string(member_str(&owner, "id")),
    );
    tx.put("groupMembers", &handed).await?;
    let member_id = member_str(member, "id").to_owned();
    let mut membership_ids = string_list(&owner, "membershipIds");
    if !membership_ids.contains(&member_id) {
        membership_ids.push(member_id);
        let mut updated = owner.clone();
        set_list(&mut updated, "membershipIds", &membership_ids);
        tx.put("packageAssignments", &updated).await?;
    }
    Ok(())
}

/// Creates what an assignment is missing: a binding of its own for each role (under `authority`, never depending
/// on or replacing a binding granted another way) and a membership for each group. A membership the person already
/// holds for at least as long is left alone and reported in the returned `skipped`; a shorter one is extended and
/// becomes the assignment's. Idempotent: what the assignment already holds is kept.
#[allow(clippy::too_many_arguments)]
async fn materialize(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    pkg: &Record,
    identity_id: &str,
    assignment: &mut Record,
    authority: Option<&GrantAuthority>,
    expires_at: Option<f64>,
) -> OperationResult<Vec<String>> {
    let tenant_id = member_str(pkg, "tenantId").to_owned();
    let assignment_id = member_str(assignment, "id").to_owned();
    let mut skipped = Vec::new();
    let mut binding_ids = string_list(assignment, "bindingIds");
    let mut membership_ids = string_list(assignment, "membershipIds");
    let role_ids = string_list(pkg, "roleIds");
    if !role_ids.is_empty() {
        let authority = authority.ok_or_else(internal_error)?;
        let own: Vec<Record> = find(
            tx,
            "bindings",
            tenant_filter(&tenant_id)
                .eq("subjectType", "identity")
                .eq("subjectId", identity_id.to_owned()),
        )
        .await?
        .into_iter()
        .filter(|binding| {
            binding.get("packageAssignmentId").and_then(Value::as_str)
                == Some(assignment_id.as_str())
        })
        .collect();
        for role_id in &role_ids {
            let held: Vec<&Record> = own
                .iter()
                .filter(|binding| {
                    member_str(binding, "roleId") == role_id
                        && member_str(binding, "authorityId") == authority.id
                })
                .collect();
            if held.iter().any(|binding| !expired_binding(ctx, binding)) {
                for binding in &held {
                    let binding_id = member_str(binding, "id").to_owned();
                    if !binding_ids.contains(&binding_id) {
                        binding_ids.push(binding_id);
                    }
                }
                continue;
            }
            // A dead binding of the same key (the assignment's own, expired) is replaced.
            for binding in &held {
                remove_tagged_binding(tx, binding).await?;
            }
            let mut input = Map::new();
            input.insert("tenantId".into(), string(tenant_id.clone()));
            input.insert("roleId".into(), string(role_id.clone()));
            input.insert("subjectType".into(), string("identity"));
            input.insert("subjectId".into(), string(identity_id));
            input.insert("authorityId".into(), string(authority.id.clone()));
            if let Some(expires_at) = expires_at {
                input.insert("expiresAt".into(), number(expires_at));
            }
            let binding =
                create_binding_record(ctx, tx, principal, &input, Some(&assignment_id)).await?;
            binding_ids.retain(|existing| {
                !held
                    .iter()
                    .any(|dead| member_str(dead, "id") == existing.as_str())
            });
            binding_ids.push(member_str(&binding, "id").to_owned());
        }
    }
    for group_id in string_list(pkg, "groupIds") {
        let existing = find(
            tx,
            "groupMembers",
            tenant_filter(&tenant_id).eq("uniqueKey", format!("{group_id}:{identity_id}")),
        )
        .await?
        .into_iter()
        .next();
        let member = match existing {
            Some(existing) if live(ctx, &existing) => {
                if existing.get("packageAssignmentId").and_then(Value::as_str)
                    == Some(assignment_id.as_str())
                {
                    let member_id = member_str(&existing, "id").to_owned();
                    if !membership_ids.contains(&member_id) {
                        membership_ids.push(member_id);
                    }
                    continue;
                }
                if end(num(&existing, "expiresAt")) >= end(expires_at) {
                    let label = tx
                        .get("groups", &group_id)
                        .await?
                        .and_then(|group| {
                            group.get("name").and_then(Value::as_str).map(str::to_owned)
                        })
                        .unwrap_or_else(|| group_id.clone());
                    let owner = match existing.get("packageAssignmentId").and_then(Value::as_str) {
                        Some(owner_id) if !owner_id.is_empty() => {
                            tx.get("packageAssignments", owner_id).await?
                        }
                        _ => None,
                    };
                    let through = match &owner {
                        Some(owner) => tx
                            .get("accessPackages", member_str(owner, "packageId"))
                            .await?
                            .and_then(|pkg| {
                                pkg.get("name").and_then(Value::as_str).map(str::to_owned)
                            }),
                        None => None,
                    };
                    skipped.push(match through.filter(|name| !name.is_empty()) {
                        Some(through) => {
                            format!("already a member of group {label} (through package {through})")
                        }
                        None => format!("already a member of group {label}"),
                    });
                    continue;
                }
                // A shorter membership is extended to the assignment's end and becomes the assignment's.
                let mut input = Map::new();
                input.insert("tenantId".into(), string(tenant_id.clone()));
                input.insert("groupId".into(), string(group_id.clone()));
                input.insert("identityId".into(), string(identity_id));
                input.insert("expiresAt".into(), expires_at.map_or(Value::Null, number));
                update_group_member_record(ctx, tx, principal, &input).await?
            }
            _ => {
                let mut input = Map::new();
                input.insert("tenantId".into(), string(tenant_id.clone()));
                input.insert("groupId".into(), string(group_id.clone()));
                input.insert("identityId".into(), string(identity_id));
                if let Some(expires_at) = expires_at {
                    input.insert("expiresAt".into(), number(expires_at));
                }
                add_group_member_record(ctx, tx, principal, &input).await?
            }
        };
        let mut tagged = member.clone();
        tagged.insert("packageAssignmentId".into(), string(assignment_id.clone()));
        tx.put("groupMembers", &tagged).await?;
        let member_id = member_str(&member, "id").to_owned();
        if !membership_ids.contains(&member_id) {
            membership_ids.push(member_id);
        }
    }
    set_list(assignment, "bindingIds", &binding_ids);
    set_list(assignment, "membershipIds", &membership_ids);
    Ok(skipped)
}

/// The rule engine's assignment: under the rule owner's authority, at the rule's revision.
struct Automatic {
    authority: GrantAuthority,
    rule_revision: f64,
}

/// What `assignPackage` answers.
struct Assigned {
    assignment: Record,
    skipped: Vec<String>,
    replaced_automatic: bool,
}

/// [`assign_package`] on raw records.
async fn assign_package_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    pkg: &Record,
    input: &Map<String, Value>,
    automatic: Option<&Automatic>,
) -> OperationResult<Assigned> {
    let tenant_id = member_str(pkg, "tenantId").to_owned();
    let pkg_id = member_str(pkg, "id").to_owned();
    let identity = ctx
        .scoped(tx, "identities", input.get("identityId"), &tenant_id)
        .await?;
    if identity.get("status").and_then(Value::as_str) == Some("deleted") {
        return Err(IamError::with_status("NOT_FOUND", "Identity has been deleted", 404).into());
    }
    let identity_id = member_str(&identity, "id").to_owned();
    let now = ctx.now();
    let mut replaced_automatic = false;
    let unique_key = format!("{pkg_id}:{identity_id}");
    let previous = find(
        tx,
        "packageAssignments",
        tenant_filter(&tenant_id).eq("uniqueKey", unique_key.clone()),
    )
    .await?
    .into_iter()
    .next();
    if let Some(previous) = previous {
        if live(ctx, &previous) {
            if previous.contains_key("ruleRevision") && automatic.is_none() {
                // An administrator takes an automatic assignment over; it becomes manual under their authority.
                revoke_assignment_record(ctx, tx, &previous).await?;
                replaced_automatic = true;
            } else if !assignment_broken(ctx, tx, &previous).await? {
                return Err(IamError::with_status(
                    "CONFLICT",
                    "This package is already assigned to the identity",
                    409,
                )
                .into());
            } else {
                // A broken assignment grants nothing any more: clear what is left of it and start over.
                revoke_assignment_record(ctx, tx, &previous).await?;
            }
        } else {
            tx.delete("packageAssignments", member_str(&previous, "id"))
                .await?;
        }
    }
    let expires_at = match automatic {
        Some(_) => None,
        None => assignment_end(ctx, pkg, input.get("expiresAt"))?,
    };
    let automatic_justification = string(AUTOMATIC_JUSTIFICATION);
    let justification = justification_for(
        pkg,
        match automatic {
            Some(_) => Some(&automatic_justification),
            None => input.get("justification"),
        },
    )?;
    let authority = match automatic {
        Some(automatic) => Some(automatic.authority.clone()),
        None => {
            authorize_package_record(ctx, tx, principal, pkg, &AuthorizeOptions::default()).await?
        }
    };
    let mut assignment = Record::new();
    assignment.insert("id".into(), string(id()));
    assignment.insert("tenantId".into(), string(tenant_id.clone()));
    assignment.insert("uniqueKey".into(), string(unique_key));
    assignment.insert("packageId".into(), string(pkg_id.clone()));
    assignment.insert("identityId".into(), string(identity_id.clone()));
    assignment.insert("assignedBy".into(), string(principal.identity.id.clone()));
    assignment.insert("assignedAt".into(), number(now));
    if let Some(expires_at) = expires_at {
        assignment.insert("expiresAt".into(), number(expires_at));
    }
    if let Some(justification) = &justification {
        assignment.insert("justification".into(), string(justification.clone()));
    }
    if let Some(automatic) = automatic {
        assignment.insert("ruleRevision".into(), number(automatic.rule_revision));
    }
    assignment.insert("bindingIds".into(), Value::Array(Vec::new()));
    assignment.insert("membershipIds".into(), Value::Array(Vec::new()));
    let skipped = materialize(
        ctx,
        tx,
        principal,
        pkg,
        &identity_id,
        &mut assignment,
        authority.as_ref(),
        expires_at,
    )
    .await?;
    let inserted = tx.insert("packageAssignments", &assignment).await?;
    // A request for the same package is fulfilled by the assignment.
    for request in find(
        tx,
        "packageRequests",
        tenant_filter(&tenant_id)
            .eq("packageId", pkg_id.clone())
            .eq("identityId", identity_id.clone())
            .eq("status", "pending"),
    )
    .await?
    {
        let mut fulfilled = request.clone();
        if automatic.is_some() {
            fulfilled.insert("status".into(), string("cancelled"));
            fulfilled.insert("decidedAt".into(), number(now));
            fulfilled.insert(
                "note".into(),
                string("Assigned automatically by the package rule"),
            );
        } else {
            fulfilled.insert("status".into(), string("approved"));
            fulfilled.insert("decidedBy".into(), string(principal.identity.id.clone()));
            fulfilled.insert("decidedAt".into(), number(now));
            fulfilled.insert("assignmentId".into(), string(member_str(&inserted, "id")));
        }
        tx.put("packageRequests", &fulfilled).await?;
    }
    Ok(Assigned {
        assignment: inserted,
        skipped,
        replaced_automatic,
    })
}

/// Grants a package to an identity: every role becomes an identity binding of the assignment's own and every group
/// a membership, all ending at `expiresAt`, created under the caller's grant authority and tagged with the
/// assignment (see materialize). A live automatic assignment is taken over (revoked and replaced by this manual
/// one); a broken one is replaced. The identity's pending request for the package is marked approved (cancelled,
/// for an automatic assignment). With `automatic`, the rule engine assigns under the rule owner's authority.
///
/// `input`: `{ identityId, expiresAt?, justification? }`; `automatic`: `{ authority: GrantAuthority, ruleRevision }`.
/// Answers `{ assignment, skipped, replacedAutomatic }`.
pub async fn assign_package(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    pkg: &crate::models::AccessPackage,
    input: &Value,
    automatic: Option<&Value>,
) -> OperationResult<Value> {
    let automatic = match automatic {
        Some(automatic) => Some(Automatic {
            authority: decode(
                automatic
                    .get("authority")
                    .and_then(Value::as_object)
                    .cloned()
                    .unwrap_or_default(),
            )?,
            rule_revision: automatic
                .get("ruleRevision")
                .and_then(core_js::as_number)
                .unwrap_or(f64::NAN),
        }),
        None => None,
    };
    let input = input.as_object().cloned().unwrap_or_default();
    let assigned =
        assign_package_record(ctx, tx, principal, &encode(pkg), &input, automatic.as_ref()).await?;
    let mut result = Map::new();
    result.insert("assignment".into(), Value::Object(assigned.assignment));
    result.insert(
        "skipped".into(),
        Value::Array(assigned.skipped.into_iter().map(Value::String).collect()),
    );
    result.insert(
        "replacedAutomatic".into(),
        Value::Bool(assigned.replaced_automatic),
    );
    Ok(Value::Object(result))
}

/// Removes one of an assignment's bindings with its activations.
async fn remove_tagged_binding(tx: &Store, binding: &Record) -> IamResult<()> {
    for activation in find(
        tx,
        "bindingActivations",
        tenant_filter(member_str(binding, "tenantId"))
            .eq("bindingId", member_str(binding, "id").to_owned()),
    )
    .await?
    {
        tx.delete("bindingActivations", member_str(&activation, "id"))
            .await?;
    }
    tx.delete("bindings", member_str(binding, "id")).await
}

/// Removes one of an assignment's memberships, unless another live package of the person includes the group: then
/// that assignment takes it over. Removing ends the person's activations of the group's eligible bindings, as
/// groups.removeMember does. Returns whether the membership was removed.
async fn remove_tagged_membership(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    member: &Record,
    assignment_id: &str,
) -> IamResult<bool> {
    let tenant_id = member_str(member, "tenantId");
    let identity_id = member_str(member, "identityId");
    let group_id = member_str(member, "groupId");
    if let Some(owner) =
        next_owner(ctx, tx, tenant_id, identity_id, group_id, assignment_id).await?
    {
        hand_over(tx, member, member_str(&owner, "id")).await?;
        return Ok(false);
    }
    for group_binding in find(
        tx,
        "bindings",
        tenant_filter(tenant_id)
            .eq("subjectType", "group")
            .eq("subjectId", group_id.to_owned()),
    )
    .await?
    {
        for activation in find(
            tx,
            "bindingActivations",
            tenant_filter(tenant_id)
                .eq("bindingId", member_str(&group_binding, "id").to_owned())
                .eq("identityId", identity_id.to_owned()),
        )
        .await?
        {
            tx.delete("bindingActivations", member_str(&activation, "id"))
                .await?;
        }
    }
    tx.delete("groupMembers", member_str(member, "id")).await?;
    Ok(true)
}

/// [`revoke_assignment`] on a raw record, answering `(bindings, memberships)`.
async fn revoke_assignment_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    assignment: &Record,
) -> IamResult<(f64, f64)> {
    let assignment_id = member_str(assignment, "id").to_owned();
    let mut bindings = 0.0;
    let mut memberships = 0.0;
    for binding_id in string_list(assignment, "bindingIds") {
        let Some(binding) = tx.get("bindings", &binding_id).await? else {
            continue;
        };
        if binding.get("packageAssignmentId").and_then(Value::as_str)
            != Some(assignment_id.as_str())
        {
            continue;
        }
        remove_tagged_binding(tx, &binding).await?;
        bindings += 1.0;
    }
    let mut groups: IndexSet<String> = IndexSet::new();
    for membership_id in string_list(assignment, "membershipIds") {
        let Some(member) = tx.get("groupMembers", &membership_id).await? else {
            continue;
        };
        if member.get("packageAssignmentId").and_then(Value::as_str) != Some(assignment_id.as_str())
        {
            continue;
        }
        groups.insert(member_str(&member, "groupId").to_owned());
        if remove_tagged_membership(ctx, tx, &member, &assignment_id).await? {
            memberships += 1.0;
        }
    }
    tx.delete("packageAssignments", &assignment_id).await?;
    // Teams that sync their members from these groups follow (teams.ts).
    let tenant_id = member_str(assignment, "tenantId");
    for group_id in groups {
        sync_teams_from_groups(ctx, tx, tenant_id, &team_sync(&group_id)).await?;
    }
    Ok((bindings, memberships))
}

/// `{ groupId, actorId: 'access-package' }`.
fn team_sync(group_id: &str) -> Value {
    let mut options = Map::new();
    options.insert("groupId".into(), string(group_id));
    options.insert("actorId".into(), string("access-package"));
    Value::Object(options)
}

/// Removes exactly the bindings and memberships an assignment created, then the assignment. The assignment owns
/// those records whichever authority issued them, so revoking needs only the right to manage the package. Answers
/// `{ bindings, memberships }`.
pub async fn revoke_assignment(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    assignment: &crate::models::PackageAssignment,
) -> IamResult<Value> {
    let (bindings, memberships) = revoke_assignment_record(ctx, tx, &encode(assignment)).await?;
    let mut counts = Map::new();
    counts.insert("bindings".into(), number(bindings));
    counts.insert("memberships".into(), number(memberships));
    Ok(Value::Object(counts))
}

/// `retime(record)`: the record with the new end (none: no end), the end moved last as the spread writes it.
fn retimed(record: &Record, expires_at: Option<f64>) -> Record {
    let mut record = record.clone();
    record.shift_remove("expiresAt");
    if let Some(expires_at) = expires_at {
        record.insert("expiresAt".into(), number(expires_at));
    }
    record
}

/// [`retime_assignment`] on raw records.
async fn retime_assignment_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    pkg: &Record,
    assignment: &Record,
    expires_at: Option<f64>,
    lengthen_only: Option<&IndexSet<String>>,
) -> IamResult<Record> {
    let tenant_id = member_str(assignment, "tenantId").to_owned();
    let assignment_id = member_str(assignment, "id").to_owned();
    let identity_id = member_str(assignment, "identityId").to_owned();
    let role_ids = string_list(pkg, "roleIds");
    let group_ids = string_list(pkg, "groupIds");
    let lengthening = end(expires_at) > end(num(assignment, "expiresAt"));
    for binding_id in string_list(assignment, "bindingIds") {
        let Some(binding) = tx.get("bindings", &binding_id).await? else {
            continue;
        };
        if binding.get("packageAssignmentId").and_then(Value::as_str)
            != Some(assignment_id.as_str())
        {
            continue;
        }
        if lengthening
            && !role_ids
                .iter()
                .any(|role| role == member_str(&binding, "roleId"))
        {
            continue;
        }
        tx.put("bindings", &retimed(&binding, expires_at)).await?;
    }
    let mut current = assignment.clone();
    // The memberships the assignment holds, plus the person's memberships of the package's current groups.
    let mut members: IndexMap<String, Record> = IndexMap::new();
    for membership_id in string_list(assignment, "membershipIds") {
        if let Some(member) = tx.get("groupMembers", &membership_id).await?
            && member.get("packageAssignmentId").and_then(Value::as_str)
                == Some(assignment_id.as_str())
        {
            members.insert(member_str(&member, "id").to_owned(), member);
        }
    }
    if lengthen_only.is_none() {
        for group_id in &group_ids {
            if let Some(member) = find(
                tx,
                "groupMembers",
                tenant_filter(&tenant_id).eq("uniqueKey", format!("{group_id}:{identity_id}")),
            )
            .await?
            .into_iter()
            .next()
            {
                members.insert(member_str(&member, "id").to_owned(), member);
            }
        }
    }
    for member in members.values() {
        if !live(ctx, member) {
            continue;
        }
        let member_id = member_str(member, "id").to_owned();
        let group_id = member_str(member, "groupId").to_owned();
        let packaged = group_ids.contains(&group_id);
        if member.get("packageAssignmentId").and_then(Value::as_str) == Some(assignment_id.as_str())
        {
            if lengthening {
                if !packaged {
                    continue;
                }
                if lengthen_only.is_some_and(|only| !only.contains(&member_id)) {
                    continue;
                }
            } else {
                let owner =
                    next_owner(ctx, tx, &tenant_id, &identity_id, &group_id, &assignment_id)
                        .await?;
                if let Some(owner) = owner
                    && end(num(&owner, "expiresAt")) > end(expires_at)
                {
                    hand_over(tx, member, member_str(&owner, "id")).await?;
                    continue;
                }
            }
            tx.put("groupMembers", &retimed(member, expires_at)).await?;
        } else if lengthening && packaged && end(num(member, "expiresAt")) < end(expires_at) {
            let mut rest = member.clone();
            rest.shift_remove("packageAssignmentId");
            let mut taken = retimed(&rest, expires_at);
            taken.insert("packageAssignmentId".into(), string(assignment_id.clone()));
            tx.put("groupMembers", &taken).await?;
            let mut membership_ids = string_list(&current, "membershipIds");
            if !membership_ids.contains(&member_id) {
                membership_ids.push(member_id);
                set_list(&mut current, "membershipIds", &membership_ids);
            }
        }
    }
    // Synced team memberships follow the new end of their source memberships (teams.ts).
    let groups: IndexSet<String> = members
        .values()
        .map(|member| member_str(member, "groupId").to_owned())
        .collect();
    for group_id in groups {
        sync_teams_from_groups(ctx, tx, &tenant_id, &team_sync(&group_id)).await?;
    }
    tx.put("packageAssignments", &retimed(&current, expires_at))
        .await
}

/// Moves the end of an assignment and of exactly its records (undefined: no end). Shortening a shared membership
/// hands it to the package that still needs it longer; lengthening extends a shorter membership of the package's
/// groups (held by hand or through another package) and makes it the assignment's. Authorization is the caller's,
/// for the package's current contents: lengthening therefore reaches only records of roles and groups the package
/// still bundles, and those it no longer bundles (removed by packages.update since) keep their end. A caller nobody
/// authorized for the current contents (a guest's renewal, api/guests.ts) passes `lengthenOnly`: lengthening then
/// reaches only those memberships of the assignment, takes no other membership over, and leaves the rest as they
/// are.
pub async fn retime_assignment(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    pkg: &crate::models::AccessPackage,
    assignment: &crate::models::PackageAssignment,
    expires_at: Option<f64>,
    lengthen_only: Option<&IndexSet<String>>,
) -> IamResult<crate::models::PackageAssignment> {
    decode(
        retime_assignment_record(
            ctx,
            tx,
            &encode(pkg),
            &encode(assignment),
            expires_at,
            lengthen_only,
        )
        .await?,
    )
}

/// [`refresh_assignment`] on raw records.
async fn refresh_assignment_record(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    pkg: &Record,
    assignment: &Record,
    authority: &GrantAuthority,
) -> OperationResult<Value> {
    let assignment_id = member_str(assignment, "id").to_owned();
    let role_ids = string_list(pkg, "roleIds");
    let group_ids = string_list(pkg, "groupIds");
    let mut kept_bindings: Vec<String> = Vec::new();
    let mut kept_memberships: Vec<String> = Vec::new();
    let mut removed_bindings = 0.0;
    let mut removed_memberships = 0.0;
    for binding_id in string_list(assignment, "bindingIds") {
        let Some(binding) = tx.get("bindings", &binding_id).await? else {
            continue;
        };
        if binding.get("packageAssignmentId").and_then(Value::as_str)
            != Some(assignment_id.as_str())
        {
            continue;
        }
        if !role_ids
            .iter()
            .any(|role| role == member_str(&binding, "roleId"))
            || member_str(&binding, "authorityId") != authority.id
        {
            remove_tagged_binding(tx, &binding).await?;
            removed_bindings += 1.0;
        } else {
            kept_bindings.push(member_str(&binding, "id").to_owned());
        }
    }
    for membership_id in string_list(assignment, "membershipIds") {
        let Some(member) = tx.get("groupMembers", &membership_id).await? else {
            continue;
        };
        if member.get("packageAssignmentId").and_then(Value::as_str) != Some(assignment_id.as_str())
        {
            continue;
        }
        if !group_ids
            .iter()
            .any(|group| group == member_str(&member, "groupId"))
        {
            if remove_tagged_membership(ctx, tx, &member, &assignment_id).await? {
                removed_memberships += 1.0;
            }
        } else {
            kept_memberships.push(member_str(&member, "id").to_owned());
        }
    }
    let mut working = assignment.clone();
    set_list(&mut working, "bindingIds", &kept_bindings);
    set_list(&mut working, "membershipIds", &kept_memberships);
    let identity_id = member_str(&working, "identityId").to_owned();
    let expires_at = num(&working, "expiresAt");
    let skipped = materialize(
        ctx,
        tx,
        principal,
        pkg,
        &identity_id,
        &mut working,
        Some(authority),
        expires_at,
    )
    .await?;
    let revision = pkg
        .get("autoAssign")
        .and_then(|rule| rule.get("revision"))
        .cloned()
        .ok_or_else(internal_error)?;
    working.insert("ruleRevision".into(), revision);
    let saved = tx.put("packageAssignments", &working).await?;
    let added_bindings = string_list(&saved, "bindingIds")
        .iter()
        .filter(|binding| !kept_bindings.contains(binding))
        .count();
    let added_memberships = string_list(&saved, "membershipIds")
        .iter()
        .filter(|member| !kept_memberships.contains(member))
        .count();
    let mut result = Map::new();
    result.insert("assignment".into(), Value::Object(saved));
    result.insert("bindings".into(), number(added_bindings as f64));
    result.insert("memberships".into(), number(added_memberships as f64));
    result.insert("removedBindings".into(), number(removed_bindings));
    result.insert("removedMemberships".into(), number(removed_memberships));
    result.insert(
        "skipped".into(),
        Value::Array(skipped.into_iter().map(Value::String).collect()),
    );
    Ok(Value::Object(result))
}

/// Brings an automatic assignment up to its package and rule: bindings of roles no longer packaged, or issued under
/// another authority than the rule's, are removed; memberships of groups no longer packaged are removed (or handed
/// over); what is missing is materialized. Memberships that stay are untouched, so live activations survive.
///
/// Answers `{ assignment, bindings, memberships, removedBindings, removedMemberships, skipped }`.
pub async fn refresh_assignment(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    principal: &better_iam_core::AuthenticatedPrincipal,
    pkg: &crate::models::AccessPackage,
    assignment: &crate::models::PackageAssignment,
    authority: &crate::models::GrantAuthority,
) -> OperationResult<Value> {
    refresh_assignment_record(
        ctx,
        tx,
        principal,
        &encode(pkg),
        &encode(assignment),
        authority,
    )
    .await
}

/// Assignments as the API returns them (`PackageAssignmentSummary`), newest first.
async fn summarize(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    assignments: Vec<Record>,
) -> IamResult<Vec<Value>> {
    let mut packages: IndexMap<String, Option<Record>> = IndexMap::new();
    let mut identities: IndexMap<String, Option<Record>> = IndexMap::new();
    let mut summaries: Vec<(f64, Value)> = Vec::new();
    for assignment in assignments {
        let package_id = member_str(&assignment, "packageId").to_owned();
        let identity_id = member_str(&assignment, "identityId").to_owned();
        if !packages.contains_key(&package_id) {
            let pkg = tx.get("accessPackages", &package_id).await?;
            packages.insert(package_id.clone(), pkg);
        }
        if !identities.contains_key(&identity_id) {
            let identity = tx.get("identities", &identity_id).await?;
            identities.insert(identity_id.clone(), identity);
        }
        let identity = identities.get(&identity_id).cloned().flatten();
        let automatic = assignment.contains_key("ruleRevision");
        let mut summary = assignment.clone();
        summary.shift_remove("uniqueKey");
        summary.shift_remove("ruleRevision");
        let expired = !live(ctx, &assignment);
        summary.insert(
            "packageName".into(),
            string(
                packages
                    .get(&package_id)
                    .cloned()
                    .flatten()
                    .and_then(|pkg| pkg.get("name").and_then(Value::as_str).map(str::to_owned))
                    .unwrap_or_else(|| package_id.clone()),
            ),
        );
        summary.insert(
            "identityName".into(),
            string(
                identity
                    .as_ref()
                    .and_then(|identity| identity.get("name").and_then(Value::as_str))
                    .map(str::to_owned)
                    .unwrap_or_else(|| identity_id.clone()),
            ),
        );
        if let Some(email) = identity
            .as_ref()
            .and_then(|identity| identity.get("email"))
            .filter(|email| truthy(Some(email)))
        {
            summary.insert("identityEmail".into(), email.clone());
        }
        summary.insert("expired".into(), Value::Bool(expired));
        let broken = !expired && assignment_broken(ctx, tx, &assignment).await?;
        summary.insert("broken".into(), Value::Bool(broken));
        summary.insert("automatic".into(), Value::Bool(automatic));
        summaries.push((
            num(&assignment, "assignedAt").unwrap_or(f64::NAN),
            Value::Object(summary),
        ));
    }
    summaries.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal));
    Ok(summaries.into_iter().map(|(_, summary)| summary).collect())
}

/// Requests as the API returns them (`PackageRequestSummary`), newest first. A pending request past its lapse time
/// is reported as expired even before the purge worker marks it.
async fn summarize_requests(tx: &Store, requests: Vec<Record>, now: f64) -> IamResult<Vec<Value>> {
    let mut packages: IndexMap<String, Option<Record>> = IndexMap::new();
    let mut identities: IndexMap<String, Option<Record>> = IndexMap::new();
    let mut summaries: Vec<(f64, Value)> = Vec::new();
    for request in requests {
        let package_id = member_str(&request, "packageId").to_owned();
        let identity_id = member_str(&request, "identityId").to_owned();
        if !packages.contains_key(&package_id) {
            let pkg = tx.get("accessPackages", &package_id).await?;
            packages.insert(package_id.clone(), pkg);
        }
        if !identities.contains_key(&identity_id) {
            let identity = tx.get("identities", &identity_id).await?;
            identities.insert(identity_id.clone(), identity);
        }
        let identity = identities.get(&identity_id).cloned().flatten();
        let mut summary = request.clone();
        summary.shift_remove("uniqueKey");
        let lapsed = member_str(&request, "status") == "pending"
            && num(&request, "expiresAt").is_some_and(|expires| expires <= now);
        if lapsed {
            summary.insert("status".into(), string("expired"));
        }
        summary.insert(
            "packageName".into(),
            string(
                packages
                    .get(&package_id)
                    .cloned()
                    .flatten()
                    .and_then(|pkg| pkg.get("name").and_then(Value::as_str).map(str::to_owned))
                    .unwrap_or_else(|| package_id.clone()),
            ),
        );
        summary.insert(
            "identityName".into(),
            string(
                identity
                    .as_ref()
                    .and_then(|identity| identity.get("name").and_then(Value::as_str))
                    .map(str::to_owned)
                    .unwrap_or_else(|| identity_id.clone()),
            ),
        );
        if let Some(email) = identity
            .as_ref()
            .and_then(|identity| identity.get("email"))
            .filter(|email| truthy(Some(email)))
        {
            summary.insert("identityEmail".into(), email.clone());
        }
        summaries.push((
            num(&request, "requestedAt").unwrap_or(f64::NAN),
            Value::Object(summary),
        ));
    }
    summaries.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(Ordering::Equal));
    Ok(summaries.into_iter().map(|(_, summary)| summary).collect())
}

/// Whether the caller may decide on a request for this package: anyone holding the permission when the package
/// names no approvers; otherwise root, the requester's manager (`managerApproval`), or a member of the approver
/// group.
async fn may_approve(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    pkg: &Record,
    principal: &AuthenticatedPrincipal,
    requester_id: &str,
) -> IamResult<bool> {
    let approver_group = pkg
        .get("approverGroupId")
        .filter(|group| truthy(Some(group)));
    let manager_approval = truthy(pkg.get("managerApproval"));
    if approver_group.is_none() && !manager_approval {
        return Ok(true);
    }
    if ctx.root_principal(tx, principal).await? {
        return Ok(true);
    }
    if manager_approval {
        let requester = tx.get("identities", requester_id).await?;
        if requester
            .as_ref()
            .and_then(|requester| requester.get("managerId"))
            .and_then(Value::as_str)
            == Some(principal.identity.id.as_str())
        {
            return Ok(true);
        }
    }
    let Some(group) = approver_group else {
        return Ok(false);
    };
    Ok(find(
        tx,
        "groupMembers",
        tenant_filter(member_str(pkg, "tenantId"))
            .eq("groupId", group.clone())
            .eq("identityId", principal.identity.id.clone()),
    )
    .await?
    .iter()
    .any(|member| live(ctx, member)))
}

/// Who is emailed a request: live approver-group members and, with `managerApproval`, the requester's manager.
async fn approver_ids(
    ctx: &Arc<ServerContext>,
    tx: &Store,
    pkg: &Record,
    requester_id: &str,
) -> IamResult<IndexSet<String>> {
    let mut recipients: IndexSet<String> = IndexSet::new();
    if let Some(group) = pkg
        .get("approverGroupId")
        .filter(|group| truthy(Some(group)))
    {
        for member in find(
            tx,
            "groupMembers",
            tenant_filter(member_str(pkg, "tenantId")).eq("groupId", group.clone()),
        )
        .await?
        {
            if live(ctx, &member) {
                recipients.insert(member_str(&member, "identityId").to_owned());
            }
        }
    }
    if truthy(pkg.get("managerApproval"))
        && let Some(manager) = tx
            .get("identities", requester_id)
            .await?
            .and_then(|requester| requester.get("managerId").cloned())
            .filter(|manager| truthy(Some(manager)))
    {
        recipients.insert(js_string(Some(&manager)));
    }
    recipients.shift_remove(requester_id);
    Ok(recipients)
}

/// Queues an email through the host outbox when the deployment delivers email at all.
async fn notify(
    ctx: &ServerContext,
    tx: &Store,
    tenant_id: &str,
    to: Option<&str>,
    template: &str,
    payload: Map<String, Value>,
) -> IamResult<()> {
    let Some(to) = to.filter(|to| !to.is_empty()) else {
        return Ok(());
    };
    let sends_email = ctx
        .options
        .authentication
        .as_ref()
        .is_some_and(|authentication| authentication.send_email.is_some());
    if !sends_email {
        return Ok(());
    }
    ctx.auth
        .enqueue_delivery(
            tx,
            better_iam_auth::outbox::EnqueueInput {
                tenant_id: tenant_id.to_owned(),
                kind: better_iam_core::OutboxKind::Email,
                to: to.to_owned(),
                template: template.to_owned(),
                payload,
                reference: None,
            },
        )
        .await?;
    Ok(())
}

/// `publicView(ctx, reader, pkg, env)`: a package as the API returns it: holder counts and, for a rule package,
/// the rule's view.
pub async fn public_view(
    ctx: &Arc<ServerContext>,
    reader: &Store,
    pkg: &Record,
    env: Option<RuleEnvironment>,
) -> IamResult<Map<String, Value>> {
    let mut view = pkg.clone();
    view.shift_remove("uniqueKey");
    let rule = view.shift_remove("autoAssign");
    let live_holders = package_assignments(ctx, reader, pkg, false).await?;
    let automatic = live_holders
        .iter()
        .filter(|assignment| assignment.contains_key("ruleRevision"))
        .count();
    view.insert("assignments".into(), number(live_holders.len() as f64));
    view.insert("automaticAssignments".into(), number(automatic as f64));
    if truthy(rule.as_ref()) {
        let env = match env {
            Some(env) => env,
            None => rule_env(ctx, reader, pkg).await?,
        };
        let typed: AccessPackage = decode(pkg.clone())?;
        let rule_view = auto_assign_view(ctx, reader, &typed, &env).await?;
        view.insert("autoAssign".into(), Value::Object(encode(&rule_view)));
    }
    Ok(view)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_ids_ignores_order_and_duplicates_count() {
        let a = vec!["x".to_owned(), "y".to_owned()];
        let b = vec!["y".to_owned(), "x".to_owned()];
        assert!(same_ids(&a, &b));
        assert!(!same_ids(&a, &["x".to_owned()]));
        assert!(!same_ids(&a, &["x".to_owned(), "z".to_owned()]));
    }

    #[test]
    fn name_keys_fold_case_and_trim() {
        assert_eq!(name_key("  Engineer KIT "), "name:engineer kit");
    }

    #[test]
    fn ends_compare_with_no_end_last() {
        assert_eq!(end_of(None).unwrap(), f64::INFINITY);
        assert_eq!(end_of(Some(5.0)).unwrap(), 5.0);
    }
}
