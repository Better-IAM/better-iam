//! Port of `packages/server/src/api/access-requests.ts`: members ask for roles, reviewers approve under their own grant
//! authority (exactly as `bindings.create` would) or deny, requesters cancel.

use std::sync::Arc;

use better_iam_core::{
    AuditOutcome, CredentialInput, Filter, FindOptions, IamError, IamResult, Record, TenantStatus,
    js as core_js,
};
use better_iam_types::api::access_requests;
use serde_json::{Map, Value};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::models::Role;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::session_kinds::acts_in_own_right;
use crate::utils::{by_newest_records, id};
use crate::validation::{integer, strings, text};

const ACCESS_REQUEST_STATUSES: [&str; 5] =
    ["pending", "approved", "denied", "cancelled", "expired"];

fn str_of<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

fn number_of(record: &Record, key: &str) -> f64 {
    record
        .get(key)
        .and_then(core_js::as_number)
        .unwrap_or(f64::NAN)
}

/// `request.roleIds` as strings.
fn role_ids_of(record: &Record) -> Vec<String> {
    match record.get("roleIds") {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| item.as_str().unwrap_or("").to_owned())
            .collect(),
        _ => Vec::new(),
    }
}

/// A pending request past its lifetime reads as expired even before the purge worker marks it.
fn effective(ctx: &ServerContext, mut request: Record) -> Record {
    if str_of(&request, "status") == Some("pending")
        && number_of(&request, "expiresAt") <= ctx.now()
    {
        request.insert("status".into(), Value::String("expired".into()));
    }
    request
}

/// The request, refused unless it is (effectively) pending.
async fn pending(
    ctx: &ServerContext,
    tx: &Store,
    request_id: Option<&Value>,
    tenant_id: &str,
) -> IamResult<Record> {
    let request = effective(
        ctx,
        ctx.scoped(tx, "accessRequests", request_id, tenant_id)
            .await?,
    );
    let status = str_of(&request, "status").unwrap_or("");
    if status != "pending" {
        return Err(IamError::with_status(
            "INVALID_TRANSITION",
            format!("Request is {status}"),
            409,
        ));
    }
    Ok(request)
}

/// Adds the `status` member to a filter after validating it.
fn status_filter(status: Option<&Value>, filter: Filter) -> IamResult<Filter> {
    let Some(status) = status else {
        return Ok(filter);
    };
    match status.as_str() {
        Some(status) if ACCESS_REQUEST_STATUSES.contains(&status) => {
            Ok(filter.eq("status", status))
        }
        _ => Err(IamError::new("INVALID_INPUT", "Invalid status")),
    }
}

/// `principal.session.impersonatorId` is set (truthy).
fn impersonating(principal: &better_iam_core::AuthenticatedPrincipal) -> bool {
    principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
}

fn impersonation_restricted() -> IamError {
    IamError::with_status(
        "IMPERSONATION_RESTRICTED",
        "Requests cannot be decided while impersonating",
        403,
    )
}

/// Requests sorted newest first, each as it effectively stands.
fn listing(ctx: &ServerContext, records: Vec<Record>) -> Value {
    let mut list: Vec<Record> = records
        .into_iter()
        .map(|record| effective(ctx, record))
        .collect();
    list.sort_by(by_newest_records);
    Value::Array(list.into_iter().map(Value::Object).collect())
}

/// The `accessRequests` API group (`createAccessRequestsApi(ctx)`): one method per route `accessRequests/{method}`.
pub struct AccessRequestsApi {
    ctx: Arc<ServerContext>,
}

/// `createAccessRequestsApi(ctx)`.
pub fn create_access_requests_api(ctx: &Arc<ServerContext>) -> IamResult<AccessRequestsApi> {
    Ok(AccessRequestsApi { ctx: ctx.clone() })
}

impl AccessRequestsApi {
    /// `accessRequests/approve`: approval binds the requested roles under the reviewer's grant authority, exactly as
    /// bindings.create would, so a reviewer can never grant more than they could bind directly. durationSeconds
    /// overrides the requested duration; the grant expires accordingly.
    pub async fn approve(
        &self,
        credential: &CredentialInput,
        input: Body<access_requests::ApproveInput>,
    ) -> IamResult<Reply<access_requests::ApproveOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let config = &ctx.config;
                let request = pending(ctx, &tx, body.get("requestId"), &tenant_id).await?;
                let requester_id = str_of(&request, "requesterId").unwrap_or("").to_owned();
                if requester_id == principal.identity.id {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "A request cannot be approved by its requester",
                        403,
                    )
                    .into());
                }
                // Two-person control: an administrator viewing as a reviewer must not decide in their name.
                if impersonating(&principal) {
                    return Err(impersonation_restricted().into());
                }
                let requester = ctx.active_identity(&tx, &requester_id, &tenant_id).await?;
                if requester.status != better_iam_core::IdentityStatus::Active {
                    return Err(IamError::new("INVALID_IDENTITY", "Requester is not active").into());
                }
                let duration = match body.get("durationSeconds") {
                    Some(value) => Some(integer(
                        Some(value),
                        "durationSeconds",
                        60.0,
                        config.access_request_max_duration_seconds,
                    )?),
                    None => request.get("durationSeconds").and_then(core_js::as_number),
                };
                let grant_expires_at = duration.map(|duration| ctx.now() + duration * 1000.0);
                let authority = ctx
                    .granting_authority(&tx, &principal, &tenant_id, None)
                    .await?;
                let request_id = str_of(&request, "id").unwrap_or("").to_owned();
                let mut binding_ids: Vec<String> = Vec::new();
                for role_id in role_ids_of(&request) {
                    let role: Role = ctx.scoped_as(&tx, "roles", &role_id, &tenant_id).await?;
                    if role.protected {
                        return Err(IamError::with_status(
                            "PROTECTED_RESOURCE",
                            "Owner roles cannot be granted this way",
                            403,
                        )
                        .into());
                    }
                    let decision = ctx
                        .decisions()?
                        .decide(
                            &tx,
                            &principal,
                            &AuthorizationRequest {
                                credential: CredentialInput::default(),
                                tenant_id: tenant_id.clone(),
                                action: "iam:bindings:create".into(),
                                resource: ResourceTarget {
                                    kind: "iam".into(),
                                    id: role.id.clone(),
                                },
                            },
                            true,
                        )
                        .await?;
                    if !decision.allowed {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            format!("Cannot grant role {}", role.name),
                            403,
                        )
                        .into());
                    }
                    let unique_key =
                        format!("identity:{}:{}:{}", requester.id, role.id, authority.id);
                    let existing = tx
                        .find(
                            "bindings",
                            &Filter::new()
                                .eq("tenantId", tenant_id.clone())
                                .eq("uniqueKey", unique_key.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                        .into_iter()
                        .next();
                    let mut binding = match &existing {
                        Some(existing) => {
                            let mut base = existing.clone();
                            base.shift_remove("expiresAt");
                            base
                        }
                        None => {
                            let mut base = Map::new();
                            base.insert("id".into(), Value::String(id()));
                            base.insert("tenantId".into(), Value::String(tenant_id.clone()));
                            base.insert("uniqueKey".into(), Value::String(unique_key));
                            base.insert("subjectType".into(), Value::String("identity".into()));
                            base.insert("subjectId".into(), Value::String(requester.id.clone()));
                            base.insert("roleId".into(), Value::String(role.id.clone()));
                            base.insert("authorityId".into(), Value::String(authority.id.clone()));
                            base
                        }
                    };
                    binding.insert("accessRequestId".into(), Value::String(request_id.clone()));
                    if let Some(expires_at) = grant_expires_at {
                        binding.insert("expiresAt".into(), crate::js::number(expires_at));
                    }
                    let saved = if existing.is_some() {
                        tx.put("bindings", &binding).await?
                    } else {
                        tx.insert("bindings", &binding).await?
                    };
                    binding_ids.push(str_of(&saved, "id").unwrap_or("").to_owned());
                }
                let binding_values: Vec<Value> =
                    binding_ids.iter().cloned().map(Value::String).collect();
                let mut decided = request.clone();
                decided.insert("status".into(), Value::String("approved".into()));
                decided.insert(
                    "reviewerId".into(),
                    Value::String(principal.identity.id.clone()),
                );
                decided.insert("reviewedAt".into(), crate::js::number(ctx.now()));
                decided.insert("bindingIds".into(), Value::Array(binding_values.clone()));
                if let Some(expires_at) = grant_expires_at {
                    decided.insert("grantExpiresAt".into(), crate::js::number(expires_at));
                }
                if let Some(note) = body.get("note") {
                    decided.insert(
                        "note".into(),
                        Value::String(text(Some(note), "note", 2048)?),
                    );
                }
                let mut metadata = Map::new();
                metadata.insert("requesterId".into(), Value::String(requester_id.clone()));
                metadata.insert(
                    "roleIds".into(),
                    request.get("roleIds").cloned().unwrap_or(Value::Null),
                );
                metadata.insert("bindingIds".into(), Value::Array(binding_values));
                if let Some(expires_at) = grant_expires_at {
                    metadata.insert("grantExpiresAt".into(), crate::js::number(expires_at));
                }
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "access-request:approve",
                        &tenant_id,
                        &request_id,
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(Value::Object(tx.put("accessRequests", &decided).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:access-requests:review",
                &string_member(&input, "requestId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `accessRequests/cancel`: the requester withdraws a pending request.
    pub async fn cancel(
        &self,
        credential: &CredentialInput,
        input: Body<access_requests::CancelInput>,
    ) -> IamResult<Reply<access_requests::CancelOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let mut request = pending(ctx, &tx, body.get("requestId"), &tenant_id).await?;
                if str_of(&request, "requesterId") != Some(principal.identity.id.as_str()) {
                    return Err(IamError::with_status(
                        "ACCESS_DENIED",
                        "Only the requester can cancel a request",
                        403,
                    )
                    .into());
                }
                request.insert("status".into(), Value::String("cancelled".into()));
                request.insert("reviewedAt".into(), crate::js::number(ctx.now()));
                Ok(Value::Object(tx.put("accessRequests", &request).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:access-requests:create",
                &string_member(&input, "requestId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `accessRequests/create`: a member asks for roles, optionally for a limited time. Nothing is granted until a
    /// reviewer approves under their own grant authority.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<access_requests::CreateInput>,
    ) -> IamResult<Reply<access_requests::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant: realm,
             }| {
                Box::pin(async move {
                    let config = &ctx.config;
                    if realm.status != TenantStatus::Active {
                        return Err(
                            IamError::new("TENANT_INACTIVE", "Tenant must be active").into()
                        );
                    }
                    if principal.session.tenant_id != realm.id
                        || !acts_in_own_right(principal.session.kind)
                    {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "Requests are made from an ordinary session of the target tenant",
                        )
                        .into());
                    }
                    let role_ids = crate::js::unique(strings(body.get("roleIds"), "roleIds")?);
                    if role_ids.is_empty() || role_ids.len() > 20 {
                        return Err(IamError::new("INVALID_INPUT", "Request 1-20 roles").into());
                    }
                    for role_id in &role_ids {
                        let role: Role = ctx.scoped_as(&tx, "roles", role_id, &realm.id).await?;
                        if role.protected {
                            return Err(IamError::with_status(
                                "PROTECTED_RESOURCE",
                                "Owner roles cannot be requested",
                                403,
                            )
                            .into());
                        }
                    }
                    let open = tx
                        .find(
                            "accessRequests",
                            &Filter::new()
                                .eq("tenantId", realm.id.clone())
                                .eq("requesterId", principal.identity.id.clone())
                                .eq("status", "pending"),
                            &FindOptions::default(),
                        )
                        .await?;
                    if open.len() >= 20 {
                        return Err(IamError::with_status(
                            "TOO_MANY_REQUESTS",
                            "Resolve pending requests before opening more",
                            429,
                        )
                        .into());
                    }
                    if open.iter().any(|existing| {
                        let existing_roles = role_ids_of(existing);
                        number_of(existing, "expiresAt") > ctx.now()
                            && existing_roles.len() == role_ids.len()
                            && existing_roles
                                .iter()
                                .all(|role_id| role_ids.contains(role_id))
                    }) {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "An identical request is already pending",
                            409,
                        )
                        .into());
                    }
                    let mut request = Map::new();
                    request.insert("id".into(), Value::String(id()));
                    request.insert("tenantId".into(), Value::String(realm.id.clone()));
                    request.insert(
                        "requesterId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    request.insert(
                        "roleIds".into(),
                        Value::Array(role_ids.into_iter().map(Value::String).collect()),
                    );
                    request.insert("status".into(), Value::String("pending".into()));
                    request.insert("createdAt".into(), crate::js::number(ctx.now()));
                    request.insert(
                        "expiresAt".into(),
                        crate::js::number(ctx.now() + config.access_request_lifetime_ms),
                    );
                    if let Some(justification) = body.get("justification") {
                        request.insert(
                            "justification".into(),
                            Value::String(text(Some(justification), "justification", 2048)?),
                        );
                    }
                    if let Some(duration) = body.get("durationSeconds") {
                        request.insert(
                            "durationSeconds".into(),
                            crate::js::number(integer(
                                Some(duration),
                                "durationSeconds",
                                60.0,
                                config.access_request_max_duration_seconds,
                            )?),
                        );
                    }
                    Ok(Value::Object(tx.insert("accessRequests", &request).await?))
                })
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:access-requests:create",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `accessRequests/deny`.
    pub async fn deny(
        &self,
        credential: &CredentialInput,
        input: Body<access_requests::DenyInput>,
    ) -> IamResult<Reply<access_requests::DenyOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let request = pending(ctx, &tx, body.get("requestId"), &tenant_id).await?;
                if impersonating(&principal) {
                    return Err(impersonation_restricted().into());
                }
                let mut decided = request.clone();
                decided.insert("status".into(), Value::String("denied".into()));
                decided.insert(
                    "reviewerId".into(),
                    Value::String(principal.identity.id.clone()),
                );
                decided.insert("reviewedAt".into(), crate::js::number(ctx.now()));
                if let Some(note) = body.get("note") {
                    decided.insert(
                        "note".into(),
                        Value::String(text(Some(note), "note", 2048)?),
                    );
                }
                let mut metadata = Map::new();
                metadata.insert(
                    "requesterId".into(),
                    request.get("requesterId").cloned().unwrap_or(Value::Null),
                );
                metadata.insert(
                    "roleIds".into(),
                    request.get("roleIds").cloned().unwrap_or(Value::Null),
                );
                ctx.events()?
                    .audit(
                        &tx,
                        &principal,
                        "access-request:deny",
                        &tenant_id,
                        str_of(&request, "id").unwrap_or(""),
                        AuditOutcome::Allow,
                        false,
                        Some(metadata),
                    )
                    .await?;
                Ok(Value::Object(tx.put("accessRequests", &decided).await?))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:access-requests:review",
                &string_member(&input, "requestId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `accessRequests/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<access_requests::GetInput>,
    ) -> IamResult<Reply<access_requests::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let request = ctx
                    .scoped(&tx, "accessRequests", body.get("requestId"), &tenant_id)
                    .await?;
                Ok(Value::Object(effective(ctx, request)))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:access-requests:read",
                &string_member(&input, "requestId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `accessRequests/list`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<access_requests::ListInput>,
    ) -> IamResult<Reply<access_requests::ListOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let mut filter =
                    status_filter(body.get("status"), Filter::new().eq("tenantId", tenant_id))?;
                if let Some(requester_id) = body.get("requesterId") {
                    filter =
                        filter.eq("requesterId", text(Some(requester_id), "requesterId", 256)?);
                }
                let records = tx
                    .find("accessRequests", &filter, &FindOptions::default())
                    .await?;
                Ok(listing(ctx, records))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:access-requests:read",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `accessRequests/listMine`: the caller's own requests; needs only the permission to create requests.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<access_requests::ListMineInput>,
    ) -> IamResult<Reply<access_requests::ListMineOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let tenant_id = string_member(&input, "tenantId");
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, principal, .. }| {
            Box::pin(async move {
                let filter = status_filter(
                    body.get("status"),
                    Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("requesterId", principal.identity.id.clone()),
                )?;
                let records = tx
                    .find("accessRequests", &filter, &FindOptions::default())
                    .await?;
                Ok(listing(ctx, records))
            })
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:access-requests:create",
                &string_member(&input, "tenantId"),
                mutation,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }
}
