//! Port of `packages/server/src/operations.ts`: the transactional authorization envelope of every provisioning call
//! (`operation`), the recorded decisions behind `authorize`, `authorizeMany` and `listAccessible`, and plugin endpoint
//! dispatch.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};

use async_trait::async_trait;
use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::boxed;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Decision, Filter, FindOptions, IamError,
    IamResult, IamStoreExt, OperationHookInput, OutboxKind, PluginDeliveryKind,
    PluginEndpointContext, Tenant,
};
use serde_json::{Map, Value};

use crate::catalog::resolved_managed;
use crate::clearances::labels_for_type;
use crate::context::{ServerContext, Store};
use crate::contracts::{
    AccessibleResources, BatchResult, Mutation, MutationContext, OperationService, PluginCall,
    decide_on, is_root_override,
};
use crate::decisions::{impersonating_actor, shadows_application_type};
use crate::delegations::use_confirmation;
use crate::invariants::{invariant_snapshot, invariant_verify};
use crate::models::ResourceRecord;
use crate::observe::{SpanKind, SpanOutcome, SpanOverride};
use crate::options::{
    AccessibleResourcesRequest, AuthorizationCheck, AuthorizationRequest,
    BatchAuthorizationRequest, ResolvedResource, ResourceTarget,
};
use crate::port::decode;
use crate::sod::{sod_snapshot, sod_verify};
use crate::validation::{integer, object, text, text_str};

pub use crate::contracts::{OperationDenied, OperationFailure, OperationResult};

fn access_denied() -> IamError {
    IamError::with_status("ACCESS_DENIED", "Access denied", 403)
}

/// `request.checks.map(...)` of `evaluateMany`: 1 to 50 checks, each `{ action, resource: { type, id } }`, validated
/// in the TypeScript order. The HTTP router passes the request body's `checks` through it.
pub fn parse_checks(checks: Option<&Value>) -> IamResult<Vec<AuthorizationCheck>> {
    let Some(Value::Array(items)) = checks else {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Provide 1-50 authorization checks",
        ));
    };
    if items.is_empty() || items.len() > 50 {
        return Err(IamError::new(
            "INVALID_INPUT",
            "Provide 1-50 authorization checks",
        ));
    }
    items
        .iter()
        .map(|check| {
            let item = object(Some(check))?;
            let resource = object(item.get("resource"))?;
            Ok(AuthorizationCheck {
                action: text(item.get("action"), "action", 256)?,
                resource: ResourceTarget {
                    kind: text(resource.get("type"), "resource type", 256)?,
                    id: text(resource.get("id"), "resource id", 256)?,
                },
            })
        })
        .collect()
}

/// `byResourceKey`: registrations in `uniqueKey` order.
fn by_resource_key(a: &ResourceRecord, b: &ResourceRecord) -> std::cmp::Ordering {
    let left = a.unique_key.as_deref().unwrap_or("");
    let right = b.unique_key.as_deref().unwrap_or("");
    better_iam_core::js::cmp_utf16(left, right)
}

/// `createOperations(ctx)`: the operation service ([`OperationService`]).
pub fn create_operations(ctx: &Arc<ServerContext>) -> Arc<Operations> {
    Arc::new(Operations {
        ctx: Arc::downgrade(ctx),
    })
}

/// The operation service of one server context.
pub struct Operations {
    ctx: Weak<ServerContext>,
}

enum Outcome {
    Denied,
    Allowed { value: Value, root_override: bool },
}

impl Operations {
    fn context(&self) -> IamResult<Arc<ServerContext>> {
        self.ctx.upgrade().ok_or_else(crate::js::internal_error)
    }

    /// `auditRefusal(tx, principal, action, tenantId, resourceId, decision)`: records a refused decision. A principal
    /// of another tenant is refused before anything of the target is read, and so is its record: it goes to the
    /// caller's own tenant, naming the target. A clearance refusal is marked `{ mandatory: 'clearance' }`.
    async fn audit_refusal(
        ctx: &ServerContext,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        action: &str,
        tenant_id: &str,
        resource_id: &str,
        decision: &Decision,
    ) -> IamResult<()> {
        let events = ctx.events()?;
        if decision.reason == "TENANT_MISMATCH" {
            let mut metadata = Map::new();
            metadata.insert("targetTenantId".into(), Value::String(tenant_id.to_owned()));
            return boxed(|| {
                events.audit(
                    tx,
                    principal,
                    action,
                    &principal.session.tenant_id,
                    resource_id,
                    AuditOutcome::Deny,
                    false,
                    Some(metadata),
                )
            })
            .await;
        }
        if decision.reason == "CLEARANCE_REQUIRED" {
            let mut metadata = Map::new();
            metadata.insert("mandatory".into(), Value::String("clearance".into()));
            return boxed(|| {
                events.audit(
                    tx,
                    principal,
                    action,
                    tenant_id,
                    resource_id,
                    AuditOutcome::Deny,
                    false,
                    Some(metadata),
                )
            })
            .await;
        }
        boxed(|| {
            events.audit(
                tx,
                principal,
                action,
                tenant_id,
                resource_id,
                AuditOutcome::Deny,
                false,
                None,
            )
        })
        .await
    }

    /// The body of `operation` inside its span.
    #[allow(clippy::too_many_arguments)]
    async fn run_operation<'a>(
        &self,
        ctx: &Arc<ServerContext>,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'a>,
        root_only: bool,
    ) -> IamResult<Value> {
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let denied = AtomicBool::new(false);
        let mutation = Mutex::new(Some(mutation));
        // `refusable`: a mutation that refuses with OperationDenied is rolled back like any failure; the refusal is
        // then recorded in its own transaction as a deny event, like an authorization denial.
        let tenant_text = tenant_id
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned();
        let result = ctx
            .store
            .transaction(|tx| {
                let authenticated = &authenticated;
                let denied = &denied;
                let mutation = &mutation;
                async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let target: Tenant = boxed(|| ctx.tenant_of(&tx, tenant_id)).await?;
                    let decision = ctx
                        .decisions()?
                        .decide(
                            &tx,
                            &principal,
                            &AuthorizationRequest {
                                credential: CredentialInput::default(),
                                tenant_id: target.id.clone(),
                                action: action.to_owned(),
                                resource: ResourceTarget {
                                    kind: "iam".into(),
                                    id: resource_id.to_owned(),
                                },
                            },
                            true,
                        )
                        .await?;
                    if !decision.allowed
                        || (root_only && !boxed(|| ctx.root_principal(&tx, &principal)).await?)
                    {
                        boxed(|| {
                            Self::audit_refusal(
                                ctx,
                                &tx,
                                &principal,
                                action,
                                &target.id,
                                resource_id,
                                &decision,
                            )
                        })
                        .await?;
                        return Ok(Outcome::Denied);
                    }
                    // An operation a delegation holds back uses up the person's confirmation (rolled back if it fails).
                    use_confirmation(&tx, &principal, action, "iam", resource_id, ctx.now())
                        .await?;
                    let hook = OperationHookInput {
                        store: tx.clone(),
                        principal: principal.clone(),
                        tenant_id: target.id.clone(),
                        action: action.to_owned(),
                        resource_id: resource_id.to_owned(),
                    };
                    for plugin in &ctx.plugins {
                        if let Some(hooks) = plugin.hooks() {
                            boxed(|| hooks.before_operation(&hook)).await?;
                        }
                    }
                    let separation = boxed(|| sod_snapshot(ctx, &tx, &target.id, action)).await?;
                    let guardrails =
                        boxed(|| invariant_snapshot(ctx, &tx, &target.id, action)).await?;
                    let run = mutation
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .take()
                        .ok_or_else(crate::js::internal_error)?;
                    let value = match boxed(|| {
                        run(MutationContext {
                            tx: tx.clone(),
                            principal: principal.clone(),
                            tenant: target.clone(),
                        })
                    })
                    .await
                    {
                        Ok(value) => value,
                        Err(failure) => {
                            denied.store(failure.denied, Ordering::SeqCst);
                            return Err(failure.error);
                        }
                    };
                    boxed(|| sod_verify(ctx, &tx, &target.id, separation.as_ref(), None)).await?;
                    boxed(|| invariant_verify(ctx, &tx, &target.id, guardrails.as_ref())).await?;
                    for plugin in &ctx.plugins {
                        if let Some(hooks) = plugin.hooks() {
                            boxed(|| hooks.after_operation(&hook, &value)).await?;
                        }
                    }
                    let root_override = decision.reason == "ROOT_OVERRIDE";
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            action,
                            &target.id,
                            resource_id,
                            AuditOutcome::Allow,
                            root_override,
                            None,
                        )
                        .await?;
                    Ok(Outcome::Allowed {
                        value,
                        root_override,
                    })
                }
            })
            .await;
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(error) => {
                if denied.load(Ordering::SeqCst) {
                    let recorded = ctx
                        .store
                        .transaction(|tx| {
                            let authenticated = &authenticated;
                            let tenant_text = &tenant_text;
                            async move {
                                ctx.events()?
                                    .audit(
                                        &tx,
                                        authenticated,
                                        action,
                                        tenant_text,
                                        resource_id,
                                        AuditOutcome::Deny,
                                        false,
                                        None,
                                    )
                                    .await
                            }
                        })
                        .await;
                    // Bookkeeping never masks the refusal.
                    let _ = recorded;
                }
                return Err(error);
            }
        };
        let Outcome::Allowed {
            value,
            root_override,
        } = outcome
        else {
            return Err(access_denied());
        };
        // Access usage: what the person used through their grants, not a root override or what an impersonating
        // administrator did as them. Recorded after the commit.
        let impersonated = authenticated
            .session
            .impersonator_id
            .as_deref()
            .is_some_and(|id| !id.is_empty());
        if !impersonated && !root_override {
            ctx.usage()?
                .record(&tenant_text, &authenticated.identity.id, action);
        }
        Ok(value)
    }
}

#[async_trait]
impl OperationService for Operations {
    async fn operation<'m>(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'m>,
        root_only: bool,
    ) -> IamResult<Value> {
        let ctx = self.context()?;
        let span_tenant = tenant_id.and_then(Value::as_str);
        boxed(|| {
            ctx.observe.span(
                SpanKind::Operation,
                action,
                span_tenant,
                boxed(|| {
                    self.run_operation(
                        &ctx,
                        credential,
                        tenant_id,
                        action,
                        resource_id,
                        mutation,
                        root_only,
                    )
                }),
                None,
                None,
            )
        })
        .await
    }

    async fn recorded_decision(
        &self,
        tx: &Store,
        current: &AuthenticatedPrincipal,
        request: &AuthorizationRequest,
    ) -> IamResult<Decision> {
        let ctx = self.context()?;
        let decision = ctx.decisions()?.decide(tx, current, request, false).await?;
        let impersonated = current
            .session
            .impersonator_id
            .as_deref()
            .is_some_and(|id| !id.is_empty());
        if decision.allowed && decision.reason != "ROOT_OVERRIDE" && !impersonated {
            ctx.usage()?
                .record(&request.tenant_id, &current.identity.id, &request.action);
        }
        if !decision.allowed {
            boxed(|| {
                Self::audit_refusal(
                    &ctx,
                    tx,
                    current,
                    &request.action,
                    &request.tenant_id,
                    &request.resource.id,
                    &decision,
                )
            })
            .await?;
        } else if decision.reason == "ROOT_OVERRIDE" {
            ctx.events()?
                .audit(
                    tx,
                    current,
                    &request.action,
                    &request.tenant_id,
                    &request.resource.id,
                    AuditOutcome::Allow,
                    true,
                    None,
                )
                .await?;
        }
        Ok(Decision {
            allowed: decision.allowed,
            reason: if decision.allowed {
                decision.reason
            } else {
                "ACCESS_DENIED".into()
            },
            matched: Vec::new(),
        })
    }

    async fn authorize(&self, request: &AuthorizationRequest) -> IamResult<Decision> {
        let ctx = self.context()?;
        let classify = |decision: &Decision| SpanOverride {
            outcome: Some(if decision.allowed {
                SpanOutcome::Ok
            } else {
                SpanOutcome::Denied
            }),
            status: None,
            code: Some(decision.reason.clone()),
        };
        ctx.observe
            .span(
                SpanKind::Authorize,
                &request.action,
                Some(&request.tenant_id),
                async {
                    let principal = ctx.principals()?.authenticate(&request.credential).await?;
                    ctx.store
                        .transaction(|tx| {
                            let principal = &principal;
                            let ctx = &ctx;
                            async move {
                                let current =
                                    ctx.principals()?.current_principal(&tx, principal).await?;
                                let decision =
                                    self.recorded_decision(&tx, &current, request).await?;
                                // A person's confirmation of an agent's held-back action opens one call
                                // (delegations.ts): this check is that call and uses it up.
                                if decision.allowed {
                                    use_confirmation(
                                        &tx,
                                        &current,
                                        &request.action,
                                        &request.resource.kind,
                                        &request.resource.id,
                                        ctx.now(),
                                    )
                                    .await?;
                                }
                                Ok(decision)
                            }
                        })
                        .await
                },
                Some(&classify),
                None,
            )
            .await
    }

    async fn authorize_many(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> IamResult<Vec<BatchResult>> {
        let ctx = self.context()?;
        ctx.observe
            .span(
                SpanKind::AuthorizeMany,
                "authorizeMany",
                Some(&request.tenant_id),
                self.evaluate_many(request),
                None,
                None,
            )
            .await
    }

    async fn evaluate_many(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> IamResult<Vec<BatchResult>> {
        let ctx = self.context()?;
        let tenant_id = text_str(&request.tenant_id, "tenantId", 256)?;
        let raw: Vec<Value> = request
            .checks
            .iter()
            .map(|check| serde_json::to_value(check).unwrap_or(Value::Null))
            .collect();
        let checks = parse_checks(Some(&Value::Array(raw)))?;
        let principal = ctx.principals()?.authenticate(&request.credential).await?;
        ctx.store
            .transaction(|tx| {
                let principal = &principal;
                let ctx = &ctx;
                let checks = &checks;
                let tenant_id = &tenant_id;
                async move {
                    let current = ctx.principals()?.current_principal(&tx, principal).await?;
                    let mut results = Vec::new();
                    for check in checks {
                        let decision = self
                            .recorded_decision(
                                &tx,
                                &current,
                                &AuthorizationRequest {
                                    credential: CredentialInput::default(),
                                    tenant_id: tenant_id.clone(),
                                    action: check.action.clone(),
                                    resource: check.resource.clone(),
                                },
                            )
                            .await?;
                        results.push(BatchResult {
                            check: check.clone(),
                            allowed: decision.allowed,
                            reason: decision.reason,
                        });
                    }
                    Ok(results)
                }
            })
            .await
    }

    async fn list_accessible(
        &self,
        request: &AccessibleResourcesRequest,
    ) -> IamResult<AccessibleResources> {
        let ctx = self.context()?;
        ctx.observe
            .span(
                SpanKind::ListAccessible,
                &request.action,
                Some(&request.tenant_id),
                self.query_accessible(request),
                None,
                None,
            )
            .await
    }

    async fn query_accessible(
        &self,
        request: &AccessibleResourcesRequest,
    ) -> IamResult<AccessibleResources> {
        let ctx = self.context()?;
        let tenant_id = text_str(&request.tenant_id, "tenantId", 256)?;
        let action = text_str(&request.action, "action", 256)?;
        let kind = text_str(&request.kind, "resource type", 64)?;
        let limit = integer(
            Some(&crate::js::number(request.limit.unwrap_or(100.0))),
            "limit",
            1.0,
            1000.0,
        )?;
        let offset = integer(
            Some(&crate::js::number(request.offset.unwrap_or(0.0))),
            "offset",
            0.0,
            1_000_000.0,
        )?;
        let principal = ctx.principals()?.authenticate(&request.credential).await?;
        ctx.store
            .transaction(|tx| {
                let principal = &principal;
                let ctx = &ctx;
                let (tenant_id, action, kind) = (&tenant_id, &action, &kind);
                async move {
                    let current = ctx.principals()?.current_principal(&tx, principal).await?;
                    let target = ctx.tenant(&tx, tenant_id).await?;
                    if !ctx.catalog.known_action(tx.as_ref(), &target.id, action).await? {
                        return Err(IamError::new(
                            "INVALID_ACTION",
                            format!("Unknown action {action}"),
                        ));
                    }
                    let definition = ctx
                        .catalog
                        .managed_definition(tx.as_ref(), &target.id, Some(&Value::String(kind.clone())))
                        .await?;
                    if shadows_application_type(
                        Some(&definition.source),
                        kind,
                        Some(action),
                        ctx.options.resolve_resource.is_some(),
                    ) {
                        return Err(IamError::new(
                            "INVALID_RESOURCE_TYPE",
                            "This resource type is resolved by the application, not registered with IAM",
                        ));
                    }
                    let decisions = ctx.decisions()?;
                    let prepared = decisions
                        .prepare_decision(&tx, &current, &target, action)
                        .await?;
                    // An impersonation session lists only what the administrator behind it could reach too.
                    let own = match impersonating_actor(&tx, &current).await? {
                        Some(actor) => Some(decisions.prepare_decision(&tx, &actor, &target, action).await?),
                        None => None,
                    };
                    // Security clearances: every registration's effective label, read once for the type.
                    let labels = if ctx.config.clearances.is_some() {
                        Some(labels_for_type(&tx, &target.id, &definition.name).await?)
                    } else {
                        None
                    };
                    let resolved = |item: &ResourceRecord| -> ResolvedResource {
                        let mut resource = resolved_managed(item);
                        if let Some(labels) = &labels {
                            resource.classification = Some(
                                labels
                                    .get(&item.resource_id)
                                    .and_then(|label| serde_json::to_value(label).ok())
                                    .unwrap_or(Value::Null),
                            );
                        }
                        resource
                    };
                    let mut records: Vec<ResourceRecord> = tx
                        .find(
                            "resources",
                            &Filter::new()
                                .eq("tenantId", target.id.clone())
                                .eq("type", definition.name.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                        .into_iter()
                        .map(decode)
                        .collect::<IamResult<_>>()?;
                    records.sort_by(by_resource_key);
                    let mut accessible = Vec::new();
                    for item in records {
                        let resource = resolved(&item);
                        if decide_on(&prepared, &resource, None)?.allowed
                            && match &own {
                                Some(own) => decide_on(own, &resource, None)?.allowed,
                                None => true,
                            }
                        {
                            accessible.push(item);
                        }
                    }
                    // Listing what one may act on is using the action (not for root overrides or impersonation).
                    let impersonated = current
                        .session
                        .impersonator_id
                        .as_deref()
                        .is_some_and(|id| !id.is_empty());
                    if !accessible.is_empty() && !impersonated && !is_root_override(&prepared) {
                        ctx.usage()?.record(&target.id, &current.identity.id, action);
                    }
                    let total = accessible.len() as f64;
                    let resources = accessible
                        .into_iter()
                        .skip(offset as usize)
                        .take(limit as usize)
                        .map(|item| Value::Object(crate::port::encode(&item)))
                        .collect();
                    Ok(AccessibleResources { resources, total })
                }
            })
            .await
    }

    async fn require_access(&self, request: &AuthorizationRequest) -> IamResult<()> {
        if !self.authorize(request).await?.allowed {
            return Err(access_denied());
        }
        Ok(())
    }

    async fn call_plugin(
        &self,
        credential: &CredentialInput,
        input: PluginCall,
    ) -> IamResult<Value> {
        let ctx = self.context()?;
        let plugin_id = text(input.plugin_id.as_ref(), "pluginId", 256)?;
        let path = text(input.path.as_ref(), "path", 256)?;
        let path = path.strip_prefix('/').unwrap_or(&path).to_owned();
        let tenant_id = text(input.tenant_id.as_ref(), "tenantId", 256)?;
        let endpoint = ctx
            .plugins
            .iter()
            .find(|plugin| plugin.id() == plugin_id)
            .and_then(|plugin| {
                plugin.endpoints().into_iter().find(|candidate| {
                    candidate
                        .path()
                        .strip_prefix('/')
                        .unwrap_or(candidate.path())
                        == path
                })
            })
            .ok_or_else(|| IamError::with_status("NOT_FOUND", "Endpoint not found", 404))?;
        let empty = Value::Object(Map::new());
        let raw = object(Some(
            input
                .input
                .as_ref()
                .filter(|value| !value.is_null())
                .unwrap_or(&empty),
        ))?;
        if raw.contains_key("tenantId")
            && raw.get("tenantId") != Some(&Value::String(tenant_id.clone()))
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Plugin input tenant does not match request scope",
            ));
        }
        let mut scoped = raw.clone();
        scoped.insert("tenantId".into(), Value::String(tenant_id.clone()));
        let validated = endpoint.validate(&Value::Object(scoped))?;
        if validated.contains_key("tenantId")
            && validated.get("tenantId") != Some(&Value::String(tenant_id.clone()))
        {
            return Err(IamError::new(
                "INVALID_INPUT",
                "Plugin validation changed tenant scope",
            ));
        }
        // Per-record endpoints are authorized on the record they name, tenant-wide ones on the tenant.
        let resource_id = match endpoint.resource(&validated) {
            Some(resource) => text_str(&resource, "plugin resource", 512)?,
            None => tenant_id.clone(),
        };
        let action = endpoint.action().to_owned();
        let tenant_value = Value::String(tenant_id.clone());
        let auth = ctx.auth.clone();
        let mutation: Mutation<'_> = Box::new(move |call: MutationContext| {
            Box::pin(async move {
                let tx = call.tx.clone();
                let delivery_tenant = tenant_id.clone();
                let deliver: better_iam_core::DeliverFn = Arc::new(move |delivery| {
                    let auth = auth.clone();
                    let tx = tx.clone();
                    let tenant_id = delivery_tenant.clone();
                    Box::pin(async move {
                        auth.enqueue_delivery(
                            &tx,
                            EnqueueInput {
                                tenant_id,
                                kind: match delivery.kind {
                                    PluginDeliveryKind::Email => OutboxKind::Email,
                                    PluginDeliveryKind::Sms => OutboxKind::Sms,
                                },
                                to: delivery.to,
                                template: delivery.template,
                                payload: delivery
                                    .payload
                                    .into_iter()
                                    .map(|(key, value)| (key, Value::String(value)))
                                    .collect(),
                                reference: None,
                            },
                        )
                        .await
                    })
                });
                let value = endpoint
                    .handler(
                        PluginEndpointContext {
                            store: call.tx,
                            principal: call.principal,
                            tenant_id,
                            deliver,
                        },
                        validated,
                    )
                    .await?;
                Ok(value)
            })
        });
        self.operation(
            credential,
            Some(&tenant_value),
            &action,
            &resource_id,
            mutation,
            false,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn checks_are_validated_in_order() {
        let error = parse_checks(None).unwrap_err();
        assert_eq!(error.message, "Provide 1-50 authorization checks");
        assert!(parse_checks(Some(&json!([]))).is_err());
        let too_many: Vec<Value> = (0..51)
            .map(|_| json!({ "action": "a", "resource": { "type": "t", "id": "i" } }))
            .collect();
        assert!(parse_checks(Some(&Value::Array(too_many))).is_err());
        let error =
            parse_checks(Some(&json!([{ "resource": { "type": "t", "id": "i" } }]))).unwrap_err();
        assert_eq!(error.message, "Invalid action");
        let error = parse_checks(Some(&json!([{ "action": "a" }]))).unwrap_err();
        assert_eq!(error.code, "INVALID_INPUT");
        let parsed = parse_checks(Some(
            &json!([{ "action": "a", "resource": { "type": "t", "id": "i" } }]),
        ))
        .unwrap();
        assert_eq!(parsed[0].resource.kind, "t");
    }
}
