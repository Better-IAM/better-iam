//! Port of `packages/server/src/api/webhooks.ts`: the `webhooks` API group (signed HTTPS subscriptions to audit
//! events, their secrets, deliveries, and redelivery) and the `audit` API group (listing, exporting, and verifying
//! the chained audit log).

use std::sync::Arc;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::{
    AuthenticatedPrincipal, ChainHead, CredentialInput, Direction, Filter, FindOptions, IamError,
    IamResult, OrderOptions, OutboxKind, Record, VerifyAuditChainOptions, find_ordered,
    js as core_js, verify_audit_chain,
};
use better_iam_types::api::{audit, webhooks};
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext};
use crate::events::{public_webhook, webhook_body};
use crate::js::truthy;
use crate::models::Webhook;
use crate::port::decode;
use crate::utils::id;
use crate::validation::{integer, strings, text};

/// `outcomes(value)`: `allow`, `deny`, or both, without duplicates.
fn outcomes(value: Option<&Value>) -> IamResult<Vec<String>> {
    let items: IndexSet<String> = strings(value, "outcomes")?.into_iter().collect();
    if items.is_empty() || items.iter().any(|item| item != "allow" && item != "deny") {
        return Err(IamError::new(
            "INVALID_INPUT",
            "outcomes must list allow, deny, or both",
        ));
    }
    Ok(items.into_iter().collect())
}

/// `resourcePatterns(value)`: 1-20 distinct resource patterns.
fn resource_patterns(value: Option<&Value>) -> IamResult<Vec<String>> {
    let items: IndexSet<String> = strings(value, "resources")?.into_iter().collect();
    if items.is_empty()
        || items.len() > 20
        || items.iter().any(|item| core_js::utf16_len(item) > 256)
    {
        return Err(IamError::new(
            "INVALID_INPUT",
            "resources must contain 1-20 patterns",
        ));
    }
    Ok(items.into_iter().collect())
}

/// The webhook as callers see it (`publicWebhook`), as JSON.
fn public(hook: &Record) -> Value {
    Value::Object(public_webhook(hook))
}

/// `INVALID_TRANSITION`: the subscription is paused.
fn paused() -> IamError {
    IamError::new("INVALID_TRANSITION", "Webhook is paused")
}

/// The `webhooks` API group (`createWebhooksApi(ctx)`): one method per route `webhooks/{method}`.
pub struct WebhooksApi {
    ctx: Arc<ServerContext>,
}

/// `createWebhooksApi(ctx)`.
pub fn create_webhooks_api(ctx: &Arc<ServerContext>) -> IamResult<WebhooksApi> {
    Ok(WebhooksApi { ctx: ctx.clone() })
}

impl WebhooksApi {
    /// A subtree subscription receives every descendant organization's events, so it stays root's after creation
    /// too: retargeting it, taking its secret, removing it, or making it deliver needs a root principal, not just
    /// iam:webhooks:update or iam:webhooks:delete in the tenant that holds it. Answers the stored record and its
    /// typed form.
    async fn subscription(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        webhook_id: Option<&Value>,
    ) -> IamResult<(Record, Webhook)> {
        let raw = self
            .ctx
            .scoped(tx, "webhooks", webhook_id, tenant_id)
            .await?;
        let hook: Webhook = decode(raw.clone())?;
        if hook.scope == "subtree" && !self.ctx.root_principal(tx, principal).await? {
            return Err(IamError::with_status(
                "ACCESS_DENIED",
                "Subtree subscriptions are platform controlled",
                403,
            ));
        }
        Ok((raw, hook))
    }

    /// `operation(credential, input.tenantId, action, resourceId, mutation)`.
    async fn run(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                action,
                resource_id,
                mutation,
                false,
            )
            .await
    }

    /// `webhooks/create`: subscribes an HTTPS endpoint to audit events matching the given patterns. The signing
    /// secret is returned once.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::CreateInput>,
    ) -> IamResult<Reply<webhooks::CreateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let scope = match body.get("scope") {
                        None | Some(Value::Null) => Value::String("tenant".into()),
                        Some(scope) => scope.clone(),
                    };
                    let scope = match scope.as_str() {
                        Some(scope @ ("tenant" | "subtree")) => scope.to_owned(),
                        _ => {
                            return Err(IamError::new(
                                "INVALID_INPUT",
                                "scope must be tenant or subtree",
                            )
                            .into());
                        }
                    };
                    if scope == "subtree" && !ctx.root_principal(&tx, &principal).await? {
                        return Err(IamError::with_status(
                            "ACCESS_DENIED",
                            "Subtree subscriptions are platform controlled",
                            403,
                        )
                        .into());
                    }
                    let existing = tx
                        .find(
                            "webhooks",
                            &Filter::new().eq("tenantId", tenant.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                        .len() as f64;
                    if existing >= 50.0 {
                        return Err(IamError::with_status(
                            "LIMIT_EXCEEDED",
                            "At most 50 webhooks per tenant",
                            409,
                        )
                        .into());
                    }
                    ctx.enforce_limit(&tenant, "webhooks", || async { Ok(existing) }, None)
                        .await?;
                    let events = ctx.events()?;
                    let hook_id = id();
                    let sealed = events.sealed_webhook_secret(&hook_id)?;
                    let mut hook = Record::new();
                    hook.insert("id".into(), Value::String(hook_id));
                    hook.insert("tenantId".into(), Value::String(tenant.id.clone()));
                    hook.insert(
                        "url".into(),
                        Value::String(events.webhook_url(body.get("url"))?),
                    );
                    hook.insert(
                        "events".into(),
                        json!(events.webhook_events(body.get("events"))?),
                    );
                    hook.insert("active".into(), Value::Bool(true));
                    hook.insert("scope".into(), Value::String(scope));
                    hook.insert("secretSealed".into(), Value::String(sealed.sealed));
                    hook.insert("createdAt".into(), crate::js::number(ctx.now()));
                    hook.insert("updatedAt".into(), crate::js::number(ctx.now()));
                    hook.insert(
                        "createdBy".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    if let Some(description) = body.get("description") {
                        hook.insert(
                            "description".into(),
                            Value::String(text(Some(description), "description", 512)?),
                        );
                    }
                    if let Some(value) = body.get("outcomes") {
                        hook.insert("outcomes".into(), json!(outcomes(Some(value))?));
                    }
                    if let Some(value) = body.get("resources") {
                        hook.insert("resources".into(), json!(resource_patterns(Some(value))?));
                    }
                    let stored = tx.insert("webhooks", &hook).await?;
                    Ok(json!({ "webhook": public(&stored), "secret": sealed.secret }))
                })
            },
        );
        let resource_id = string_member(&input, "tenantId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:create",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `webhooks/list`.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::ListInput>,
    ) -> IamResult<Reply<webhooks::ListOutput>> {
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let hooks = tx
                    .find(
                        "webhooks",
                        &Filter::new().eq("tenantId", tenant.id.clone()),
                        &FindOptions::default(),
                    )
                    .await?;
                Ok(Value::Array(hooks.iter().map(public).collect()))
            })
        });
        let resource_id = string_member(&input, "tenantId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:read",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `webhooks/get`.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::GetInput>,
    ) -> IamResult<Reply<webhooks::GetOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                let hook = ctx
                    .scoped(&tx, "webhooks", body.get("webhookId"), &tenant.id)
                    .await?;
                Ok(public(&hook))
            })
        });
        let resource_id = string_member(&input, "webhookId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:read",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `webhooks/update`: a new URL, event patterns, description, filters, or active flag; `null` clears the
    /// description and the filters.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::UpdateInput>,
    ) -> IamResult<Reply<webhooks::UpdateOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let (raw, _) = self
                        .subscription(&tx, &principal, &tenant.id, body.get("webhookId"))
                        .await?;
                    if [
                        "url",
                        "events",
                        "description",
                        "active",
                        "outcomes",
                        "resources",
                    ]
                    .iter()
                    .all(|key| body.get(*key).is_none())
                    {
                        return Err(IamError::new("INVALID_INPUT", "Nothing to update").into());
                    }
                    let events = ctx.events()?;
                    let mut next = raw;
                    next.insert("updatedAt".into(), crate::js::number(ctx.now()));
                    if let Some(url) = body.get("url") {
                        next.insert("url".into(), Value::String(events.webhook_url(Some(url))?));
                    }
                    if let Some(patterns) = body.get("events") {
                        next.insert(
                            "events".into(),
                            json!(events.webhook_events(Some(patterns))?),
                        );
                    }
                    match body.get("description") {
                        Some(Value::Null) => {
                            next.shift_remove("description");
                        }
                        Some(description) => {
                            next.insert(
                                "description".into(),
                                Value::String(text(Some(description), "description", 512)?),
                            );
                        }
                        None => {}
                    }
                    match body.get("outcomes") {
                        Some(Value::Null) => {
                            next.shift_remove("outcomes");
                        }
                        Some(value) => {
                            next.insert("outcomes".into(), json!(outcomes(Some(value))?));
                        }
                        None => {}
                    }
                    match body.get("resources") {
                        Some(Value::Null) => {
                            next.shift_remove("resources");
                        }
                        Some(value) => {
                            next.insert("resources".into(), json!(resource_patterns(Some(value))?));
                        }
                        None => {}
                    }
                    if let Some(active) = body.get("active") {
                        let Value::Bool(active) = active else {
                            return Err(
                                IamError::new("INVALID_INPUT", "active must be boolean").into()
                            );
                        };
                        next.insert("active".into(), Value::Bool(*active));
                    }
                    Ok(public(&tx.put("webhooks", &next).await?))
                })
            },
        );
        let resource_id = string_member(&input, "webhookId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:update",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `webhooks/rotateSecret`: issues a new signing secret; deliveries claimed after this point are signed with it.
    pub async fn rotate_secret(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::RotateSecretInput>,
    ) -> IamResult<Reply<webhooks::RotateSecretOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let (mut raw, hook) = self
                        .subscription(&tx, &principal, &tenant.id, body.get("webhookId"))
                        .await?;
                    let sealed = ctx.events()?.sealed_webhook_secret(&hook.id)?;
                    raw.insert("secretSealed".into(), Value::String(sealed.sealed));
                    raw.insert("updatedAt".into(), crate::js::number(ctx.now()));
                    let stored = tx.put("webhooks", &raw).await?;
                    Ok(json!({ "webhook": public(&stored), "secret": sealed.secret }))
                })
            },
        );
        let resource_id = string_member(&input, "webhookId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:update",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `webhooks/delete`: removes the subscription and its undelivered messages.
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::DeleteInput>,
    ) -> IamResult<Reply<webhooks::DeleteOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    ctx.auth.require_recent(&principal)?;
                    let (_, hook) = self
                        .subscription(&tx, &principal, &tenant.id, body.get("webhookId"))
                        .await?;
                    tx.delete("webhooks", &hook.id).await?;
                    for message in tx
                        .find(
                            "outbox",
                            &Filter::new()
                                .eq("tenantId", tenant.id.clone())
                                .eq("kind", "webhook")
                                .eq("to", hook.id.clone()),
                            &FindOptions::default(),
                        )
                        .await?
                    {
                        if !truthy(message.get("deliveredAt")) && !truthy(message.get("failedAt")) {
                            tx.delete("outbox", &string_member(&message, "id")).await?;
                        }
                    }
                    Ok(json!({ "deleted": true }))
                })
            },
        );
        let resource_id = string_member(&input, "webhookId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:delete",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `webhooks/ping`: queues a synthetic `webhook:ping` delivery so an endpoint can be verified end to end.
    pub async fn ping(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::PingInput>,
    ) -> IamResult<Reply<webhooks::PingOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let (_, hook) = self
                        .subscription(&tx, &principal, &tenant.id, body.get("webhookId"))
                        .await?;
                    if !hook.active {
                        return Err(paused().into());
                    }
                    let mut event = Map::new();
                    event.insert("id".into(), Value::String(id()));
                    event.insert("type".into(), Value::String("webhook:ping".into()));
                    event.insert("tenantId".into(), Value::String(hook.tenant_id.clone()));
                    event.insert(
                        "actorId".into(),
                        Value::String(principal.identity.id.clone()),
                    );
                    event.insert("resourceId".into(), Value::String(hook.id.clone()));
                    event.insert("outcome".into(), Value::String("allow".into()));
                    event.insert("timestamp".into(), crate::js::number(ctx.now()));
                    let mut payload = Map::new();
                    payload.insert("url".into(), Value::String(hook.url.clone()));
                    payload.insert(
                        "body".into(),
                        Value::String(core_js::stringify_object(&event)),
                    );
                    let delivery_id = ctx
                        .auth
                        .enqueue_delivery(
                            &tx,
                            EnqueueInput {
                                tenant_id: hook.tenant_id.clone(),
                                kind: OutboxKind::Webhook,
                                to: hook.id.clone(),
                                template: "webhook:ping".into(),
                                payload,
                                reference: None,
                            },
                        )
                        .await?;
                    Ok(json!({ "deliveryId": delivery_id }))
                })
            },
        );
        let resource_id = string_member(&input, "webhookId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:update",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `webhooks/listDeliveries`: delivery history of one webhook, newest first. Payloads are never returned.
    pub async fn list_deliveries(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::ListDeliveriesInput>,
    ) -> IamResult<Reply<webhooks::ListDeliveriesOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, tenant, .. }| {
            Box::pin(async move {
                ctx.scoped(&tx, "webhooks", body.get("webhookId"), &tenant.id)
                    .await?;
                let limit_value = match body.get("limit") {
                    None | Some(Value::Null) => crate::js::number(100.0),
                    Some(value) => value.clone(),
                };
                let limit = integer(Some(&limit_value), "limit", 1.0, 1000.0)?;
                let mut messages = tx
                    .find(
                        "outbox",
                        &Filter::new()
                            .eq("tenantId", tenant.id.clone())
                            .eq("kind", "webhook")
                            .eq("to", string_member(body, "webhookId")),
                        &FindOptions::default(),
                    )
                    .await?;
                let created = |message: &Record| {
                    message
                        .get("createdAt")
                        .and_then(core_js::as_number)
                        .unwrap_or(f64::NAN)
                };
                messages.sort_by(|a, b| {
                    let difference = created(b) - created(a);
                    if difference != 0.0 && !difference.is_nan() {
                        return if difference < 0.0 {
                            std::cmp::Ordering::Less
                        } else {
                            std::cmp::Ordering::Greater
                        };
                    }
                    if core_js::cmp_utf16(&string_member(a, "id"), &string_member(b, "id"))
                        == std::cmp::Ordering::Less
                    {
                        std::cmp::Ordering::Less
                    } else {
                        std::cmp::Ordering::Greater
                    }
                });
                Ok(Value::Array(
                    messages
                        .iter()
                        .take(limit as usize)
                        .map(|message| {
                            let mut out = Map::new();
                            let mut copy = |from: &str, to: &str| {
                                if let Some(value) = message.get(from) {
                                    out.insert(to.to_owned(), value.clone());
                                }
                            };
                            copy("id", "id");
                            copy("template", "event");
                            copy("reference", "eventId");
                            copy("createdAt", "createdAt");
                            copy("attempts", "attempts");
                            copy("deliveredAt", "deliveredAt");
                            copy("failedAt", "failedAt");
                            copy("lastError", "lastError");
                            let status = if truthy(message.get("deliveredAt")) {
                                "delivered"
                            } else if truthy(message.get("failedAt")) {
                                "failed"
                            } else {
                                "pending"
                            };
                            out.insert("status".into(), Value::String(status.into()));
                            Value::Object(out)
                        })
                        .collect(),
                ))
            })
        });
        let resource_id = string_member(&input, "webhookId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:read",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `webhooks/redeliver`: queues the event behind an earlier delivery again (after an outage, or to replay a
    /// delivered event). The body is rebuilt from the audit record and signed with the subscription's current secret
    /// at delivery time.
    pub async fn redeliver(
        &self,
        credential: &CredentialInput,
        input: Body<webhooks::RedeliverInput>,
    ) -> IamResult<Reply<webhooks::RedeliverOutput>> {
        let ctx = &self.ctx;
        let body = &input;
        let mutation: Mutation<'_> = Box::new(
            |MutationContext {
                 tx,
                 principal,
                 tenant,
             }| {
                Box::pin(async move {
                    let (_, hook) = self
                        .subscription(&tx, &principal, &tenant.id, body.get("webhookId"))
                        .await?;
                    if !hook.active {
                        return Err(paused().into());
                    }
                    let delivery_id = text(body.get("deliveryId"), "deliveryId", 256)?;
                    let message = tx.get("outbox", &delivery_id).await?;
                    let message = match message {
                        Some(message)
                            if message.get("tenantId").and_then(Value::as_str)
                                == Some(tenant.id.as_str())
                                && message.get("kind").and_then(Value::as_str)
                                    == Some("webhook")
                                && message.get("to").and_then(Value::as_str)
                                    == Some(hook.id.as_str()) =>
                        {
                            message
                        }
                        _ => {
                            return Err(IamError::with_status(
                                "NOT_FOUND",
                                "Delivery not found",
                                404,
                            )
                            .into());
                        }
                    };
                    if !truthy(message.get("reference")) {
                        return Err(IamError::new(
                            "INVALID_TRANSITION",
                            "This delivery cannot be rebuilt",
                        )
                        .into());
                    }
                    let reference = string_member(&message, "reference");
                    let Some(event) = tx.get("audit", &reference).await? else {
                        return Err(IamError::with_status(
                            "NOT_FOUND",
                            "The delivered event no longer exists",
                            404,
                        )
                        .into());
                    };
                    let event_id = string_member(&event, "id");
                    let mut payload = Map::new();
                    payload.insert("url".into(), Value::String(hook.url.clone()));
                    payload.insert(
                        "body".into(),
                        Value::String(core_js::stringify_object(&webhook_body(&event))),
                    );
                    let delivery_id = ctx
                        .auth
                        .enqueue_delivery(
                            &tx,
                            EnqueueInput {
                                tenant_id: hook.tenant_id.clone(),
                                kind: OutboxKind::Webhook,
                                to: hook.id.clone(),
                                template: string_member(&event, "action"),
                                payload,
                                reference: Some(event_id.clone()),
                            },
                        )
                        .await?;
                    Ok(json!({ "deliveryId": delivery_id, "eventId": event_id }))
                })
            },
        );
        let resource_id = string_member(&input, "webhookId");
        let result = self
            .run(
                credential,
                &input,
                "iam:webhooks:update",
                &resource_id,
                mutation,
            )
            .await?;
        Ok(Reply::json(result))
    }
}

/// The `audit` API group (`createAuditApi(ctx)`): one method per route `audit/{method}`.
pub struct AuditApi {
    ctx: Arc<ServerContext>,
}

/// `createAuditApi(ctx)`.
pub fn create_audit_api(ctx: &Arc<ServerContext>) -> IamResult<AuditApi> {
    Ok(AuditApi { ctx: ctx.clone() })
}

impl AuditApi {
    /// `audit/export`: chained events in sequence order as JSON Lines, including `sequence`, `previousHash` and
    /// `hash`, so an archive can be verified later (the last line's hash links the next export).
    pub async fn export(
        &self,
        credential: &CredentialInput,
        input: Body<audit::ExportInput>,
    ) -> IamResult<Reply<audit::ExportOutput>> {
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                let from = match body.get("fromSequence") {
                    Some(value) => integer(Some(value), "fromSequence", 1.0, MAX_SAFE)?,
                    None => 1.0,
                };
                let limit = integer(
                    Some(&or_default(body.get("limit"), 1000.0)),
                    "limit",
                    1.0,
                    10_000.0,
                )?;
                // One event past the page tells whether more follow.
                let events = find_ordered(
                    tx.as_ref(),
                    "audit",
                    &Filter::new().eq("tenantId", tenant_id.clone()),
                    &OrderOptions {
                        from: Some(from),
                        limit: Some(limit as i64 + 1),
                        ..OrderOptions::by("sequence")
                    },
                    None,
                )
                .await?;
                let page: Vec<&Record> = events.iter().take(limit as usize).collect();
                let head = tx.get("auditChains", &tenant_id).await?;
                let sequence = |event: Option<&&Record>| {
                    event.and_then(|event| event.get("sequence")).cloned()
                };
                let mut out = Map::new();
                out.insert("format".into(), json!("jsonl"));
                out.insert("count".into(), json!(page.len()));
                out.insert(
                    "body".into(),
                    Value::String(
                        page.iter()
                            .map(|event| better_iam_core::js::stringify_object(event))
                            .collect::<Vec<_>>()
                            .join("\n"),
                    ),
                );
                if let Some(first) = sequence(page.first()) {
                    out.insert("firstSequence".into(), first);
                }
                if let Some(last) = sequence(page.last()) {
                    out.insert("lastSequence".into(), last.clone());
                    if events.len() as f64 > limit {
                        let next = last.as_f64().unwrap_or(f64::NAN) + 1.0;
                        out.insert("nextSequence".into(), crate::js::number(next));
                    }
                }
                out.insert(
                    "head".into(),
                    match head {
                        Some(head) => json!({
                            "sequence": head.get("sequence").cloned().unwrap_or(Value::Null),
                            "hash": head.get("hash").cloned().unwrap_or(Value::Null),
                        }),
                        None => Value::Null,
                    },
                );
                Ok(Value::Object(out))
            })
        });
        Ok(Reply::json(self.run(credential, &input, mutation).await?))
    }

    /// `audit/list`: newest first. `action` accepts a glob pattern; `from`/`to` bound the timestamp; `actorId`,
    /// `resourceId` and `outcome` match exactly.
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<audit::ListInput>,
    ) -> IamResult<Reply<audit::ListOutput>> {
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                let limit = integer(
                    Some(&or_default(body.get("limit"), 100.0)),
                    "limit",
                    1.0,
                    1000.0,
                )?;
                let offset = integer(
                    Some(&or_default(body.get("offset"), 0.0)),
                    "offset",
                    0.0,
                    1_000_000.0,
                )?;
                let mut filter = Filter::new().eq("tenantId", tenant_id);
                if let Some(value) = body.get("actorId") {
                    filter = filter.eq("actorId", text(Some(value), "actorId", 256)?);
                }
                if let Some(value) = body.get("resourceId") {
                    filter = filter.eq("resourceId", text(Some(value), "resourceId", 2048)?);
                }
                if let Some(value) = body.get("outcome") {
                    if value != &json!("allow") && value != &json!("deny") {
                        return Err(IamError::new(
                            "INVALID_INPUT",
                            "outcome must be allow or deny",
                        )
                        .into());
                    }
                    filter = filter.eq("outcome", value.clone());
                }
                let from = match body.get("from") {
                    Some(value) => Some(integer(Some(value), "from", 0.0, MAX_SAFE)?),
                    None => None,
                };
                let to = match body.get("to") {
                    Some(value) => Some(integer(Some(value), "to", 0.0, MAX_SAFE)?),
                    None => None,
                };
                let action = match body.get("action") {
                    Some(value) => Some(text(Some(value), "action", 128)?),
                    None => None,
                };
                // An action without wildcards is an exact filter the database can use; a glob is applied while reading
                // the log newest first in pages, so the whole log is never loaded.
                let glob = action
                    .as_deref()
                    .is_some_and(|action| action.contains('*') || action.contains('?'));
                if let (Some(action), false) = (&action, glob) {
                    filter = filter.eq("action", action.clone());
                }
                let pattern = action.clone().unwrap_or_default();
                let matches = move |event: &Record| {
                    better_iam_core::match_pattern(
                        &pattern,
                        event.get("action").and_then(Value::as_str).unwrap_or(""),
                        None,
                    )
                };
                let events = find_ordered(
                    tx.as_ref(),
                    "audit",
                    &filter,
                    &OrderOptions {
                        direction: Direction::Desc,
                        from,
                        to,
                        offset: Some(offset as i64),
                        limit: Some(limit as i64),
                        ..OrderOptions::by("timestamp")
                    },
                    if glob { Some(&matches) } else { None },
                )
                .await?;
                Ok(Value::Array(
                    events.into_iter().map(Value::Object).collect(),
                ))
            })
        });
        Ok(Reply::json(self.run(credential, &input, mutation).await?))
    }

    /// `audit/verify`: verifies the tenant's audit hash chain: contiguous sequences, linked hashes, recomputable event
    /// hashes, and a chain head that matches the last event. `fromSequence`/`toSequence` verify a window against its own
    /// links.
    pub async fn verify(
        &self,
        credential: &CredentialInput,
        input: Body<audit::VerifyInput>,
    ) -> IamResult<Reply<audit::VerifyOutput>> {
        let body = &input;
        let mutation: Mutation<'_> = Box::new(|MutationContext { tx, .. }| {
            Box::pin(async move {
                let tenant_id = crate::api::string_member(body, "tenantId");
                let from = match body.get("fromSequence") {
                    Some(value) => Some(integer(Some(value), "fromSequence", 1.0, MAX_SAFE)?),
                    None => None,
                };
                let to = match body.get("toSequence") {
                    Some(value) => Some(integer(Some(value), "toSequence", 1.0, MAX_SAFE)?),
                    None => None,
                };
                let head = tx.get("auditChains", &tenant_id).await?;
                let events: Vec<Record> = tx
                    .find(
                        "audit",
                        &Filter::new().eq("tenantId", tenant_id.clone()),
                        &FindOptions::default(),
                    )
                    .await?
                    .into_iter()
                    .filter(
                        |event| match event.get("sequence").and_then(Value::as_f64) {
                            None => true,
                            Some(sequence) => {
                                from.is_none_or(|from| sequence >= from)
                                    && to.is_none_or(|to| sequence <= to)
                            }
                        },
                    )
                    .collect();
                let partial = from.is_some() || to.is_some();
                let chain_head = match (&head, partial) {
                    (Some(head), false) => Some(ChainHead {
                        sequence: head
                            .get("sequence")
                            .and_then(Value::as_f64)
                            .unwrap_or(f64::NAN),
                        hash: head
                            .get("hash")
                            .and_then(Value::as_str)
                            .unwrap_or_default()
                            .to_owned(),
                    }),
                    _ => None,
                };
                let verification = verify_audit_chain(
                    &events,
                    &VerifyAuditChainOptions {
                        previous_hash: None,
                        head: chain_head,
                    },
                );
                let mut out = match serde_json::to_value(&verification) {
                    Ok(Value::Object(map)) => map,
                    _ => Map::new(),
                };
                out.insert(
                    "head".into(),
                    match head {
                        Some(head) => json!({
                            "sequence": head.get("sequence").cloned().unwrap_or(Value::Null),
                            "hash": head.get("hash").cloned().unwrap_or(Value::Null),
                            "updatedAt": head.get("updatedAt").cloned().unwrap_or(Value::Null),
                        }),
                        None => Value::Null,
                    },
                );
                Ok(Value::Object(out))
            })
        });
        Ok(Reply::json(self.run(credential, &input, mutation).await?))
    }

    /// `operation(credential, input.tenantId, 'iam:audit:read', input.tenantId, mutation)`.
    async fn run(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        mutation: Mutation<'_>,
    ) -> IamResult<Value> {
        let resource_id = crate::api::string_member(input, "tenantId");
        self.ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:audit:read",
                &resource_id,
                mutation,
                false,
            )
            .await
    }
}

/// `Number.MAX_SAFE_INTEGER`.
const MAX_SAFE: f64 = 9_007_199_254_740_991.0;

/// `value ?? fallback` for a numeric option: an absent or null member takes the fallback.
fn or_default(value: Option<&Value>, fallback: f64) -> Value {
    match value {
        None | Some(Value::Null) => crate::js::number(fallback),
        Some(value) => value.clone(),
    }
}
