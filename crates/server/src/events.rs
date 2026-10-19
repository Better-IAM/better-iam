//! Port of `packages/server/src/events.ts`: chained audit recording, in-transaction fan-out to webhooks and the
//! post-commit dispatcher, webhook signing and the built-in HTTPS transport, and post-commit dispatch.

use std::sync::{Arc, LazyLock, Weak};
use std::time::Duration;

use better_iam_auth::outbox::EnqueueInput;
use better_iam_auth::{DeliveryError, DeliveryMessage, decrypt_secret, encrypt_secret};
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, Filter, FindOptions, IamError, IamResult, IamStoreExt,
    OutboxKind, Record, append_audit_event, match_pattern,
};
use hmac::{Hmac, Mac};
use indexmap::IndexMap;
use regex::Regex;
use serde_json::{Map, Value};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use url::Url;

use crate::context::{EventSubscriber, ServerContext, Store, SubscriberFn};
use crate::hosts::url_hostname;
use crate::js::{self, invalid_input, member, number_to_string, truthy};
use crate::options::WebhookDelivery;
use crate::options_value::options_value;
use crate::safe_fetch::{
    FetchBody, FetchRequest, GuardedFetch, GuardedFetchOptions, RedirectMode,
    SafeFetchAddressOptions, check_fetch_url, create_guarded_fetch,
};
use crate::temporary_credentials::audit_session_context;
use crate::utils::{date_now, id, token};
use crate::validation::{strings, text, text_str};

static WEBHOOK_EVENT_PATTERN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[a-zA-Z0-9:*?_.-]{1,128}$").expect("regex"));

type HmacSha256 = Hmac<Sha256>;

fn hmac(secret: &[u8], message: &str) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(message.as_bytes());
    mac.finalize().into_bytes().to_vec()
}

/// The input of [`verify_webhook_signature`].
#[derive(Debug, Clone, PartialEq)]
pub struct VerifyWebhookInput<'a> {
    pub secret: &'a str,
    /// The X-Better-IAM-Timestamp header value (a string or a number).
    pub timestamp: &'a Value,
    pub body: &'a str,
    /// The X-Better-IAM-Signature header value.
    pub signature: &'a str,
    pub tolerance_seconds: Option<f64>,
    pub now: Option<f64>,
}

/// `verifyWebhookSignature(input)`: verifies a webhook signature produced by Better IAM.
pub fn verify_webhook_signature(input: &VerifyWebhookInput<'_>) -> bool {
    let timestamp = js::to_number(input.timestamp);
    if !timestamp.is_finite() {
        return false;
    }
    let tolerance = input.tolerance_seconds.unwrap_or(300.0);
    let now = input.now.unwrap_or_else(date_now);
    if ((now / 1000.0).floor() - timestamp).abs() > tolerance {
        return false;
    }
    let expected = hmac(
        input.secret.as_bytes(),
        &format!("{}.{}", number_to_string(timestamp), input.body),
    );
    let provided = input
        .signature
        .split(',')
        .map(js::trim)
        .find(|part| part.starts_with("v1="))
        .map(|part| &part[3..]);
    let Some(provided) = provided else {
        return false;
    };
    if provided.len() != 64
        || !provided
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return false;
    }
    let Ok(provided) = hex::decode(provided) else {
        return false;
    };
    bool::from(expected.as_slice().ct_eq(&provided))
}

/// `webhookBody(event)`: the JSON body delivered to a webhook endpoint, in its fixed member order.
pub fn webhook_body(event: &Record) -> Record {
    let mut body = Record::new();
    // A member the event lacks is undefined in the body, which JSON.stringify leaves out.
    let copy = |body: &mut Record, from: &str, to: &str| {
        if let Some(value) = event.get(from) {
            body.insert(to.to_owned(), value.clone());
        }
    };
    copy(&mut body, "id", "id");
    copy(&mut body, "action", "type");
    copy(&mut body, "tenantId", "tenantId");
    copy(&mut body, "actorId", "actorId");
    copy(&mut body, "resourceId", "resourceId");
    copy(&mut body, "outcome", "outcome");
    copy(&mut body, "timestamp", "timestamp");
    if truthy(event.get("originalActorId")) {
        copy(&mut body, "originalActorId", "originalActorId");
    }
    if truthy(event.get("impersonatorId")) {
        copy(&mut body, "impersonatorId", "impersonatorId");
    }
    if truthy(event.get("rootOverride")) {
        body.insert("rootOverride".into(), Value::Bool(true));
    }
    if truthy(event.get("metadata")) {
        copy(&mut body, "metadata", "metadata");
    }
    if let Some(context) = event.get("sessionContext")
        && truthy(Some(context))
    {
        // `{ ...event.sessionContext }`: a shallow copy of an object (nothing for primitives).
        let copied = match context {
            Value::Object(map) => Value::Object(map.clone()),
            Value::String(text) => Value::Object(
                text.chars()
                    .enumerate()
                    .map(|(index, c)| (index.to_string(), Value::String(c.into())))
                    .collect(),
            ),
            Value::Array(items) => Value::Object(
                items
                    .iter()
                    .enumerate()
                    .map(|(index, item)| (index.to_string(), item.clone()))
                    .collect(),
            ),
            _ => Value::Object(Map::new()),
        };
        body.insert("sessionContext".into(), copied);
    }
    if let Some(sequence @ Value::Number(_)) = event.get("sequence") {
        body.insert("sequence".into(), sequence.clone());
    }
    if let Some(hash @ Value::String(_)) = event.get("hash") {
        body.insert("hash".into(), hash.clone());
    }
    body
}

/// `publicWebhook(hook)`: a webhook without its sealed secret.
pub fn public_webhook(hook: &Record) -> Record {
    let mut safe = hook.clone();
    safe.shift_remove("secretSealed");
    safe
}

/// `sealedWebhookSecret(hookId)`: a new signing secret and its sealed form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealedWebhookSecret {
    pub secret: String,
    pub sealed: String,
}

/// What `dispatch()` reports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub struct Dispatched {
    pub dispatched: u64,
}

/// The handle `subscribe` returns; [`Subscription::unsubscribe`] removes the handler.
pub struct Subscription {
    ctx: Weak<ServerContext>,
    subscriber: Arc<EventSubscriber>,
}

impl Subscription {
    /// The unsubscribe function `subscribe` returns.
    pub fn unsubscribe(&self) {
        if let Some(ctx) = self.ctx.upgrade() {
            ctx.subscribers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .retain(|item| !Arc::ptr_eq(item, &self.subscriber));
        }
    }
}

/// `EventService`.
pub struct EventService {
    ctx: Weak<ServerContext>,
    /// Where webhook endpoints may point: public addresses on any https port; loopback over http in development.
    rules: SafeFetchAddressOptions,
    fetch: GuardedFetch,
}

/// `createEvents(ctx)`.
pub fn create_events(ctx: &Arc<ServerContext>) -> Arc<EventService> {
    let model = options_value(&ctx.options);
    let rules = SafeFetchAddressOptions {
        any_port: true,
        allow_private_networks: member(member(Some(&model), "events"), "allowPrivateNetworks")
            == Some(&Value::Bool(true)),
        allow_insecure_localhost: !ctx.config.https(),
    };
    Arc::new(EventService {
        ctx: Arc::downgrade(ctx),
        rules,
        fetch: create_guarded_fetch(GuardedFetchOptions {
            allow_private_networks: rules.allow_private_networks,
            allow_insecure_localhost: rules.allow_insecure_localhost,
            any_port: true,
            max_bytes: None,
        }),
    })
}

fn string_of<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or("")
}

fn patterns_match(patterns: Option<&Value>, value: &str) -> IamResult<bool> {
    match patterns {
        Some(Value::Array(items)) => Ok(items
            .iter()
            .any(|pattern| match_pattern(&js::js_string(Some(pattern)), value, None))),
        // `hook.events.some(...)` of a malformed record throws a TypeError.
        _ => Err(js::internal_error()),
    }
}

impl EventService {
    fn ctx(&self) -> IamResult<Arc<ServerContext>> {
        self.ctx
            .upgrade()
            .ok_or_else(|| IamError::with_status("INTERNAL_ERROR", "Internal server error", 500))
    }

    /// `fanOut(tx, event)`: queues post-commit dispatch and webhook deliveries inside the recording transaction.
    pub async fn fan_out(&self, tx: &Store, event: &Record) -> IamResult<()> {
        let ctx = self.ctx()?;
        let has_on_event = ctx
            .options
            .events
            .as_ref()
            .is_some_and(|events| events.on_event.is_some())
            || js::is_function(member(
                member(Some(&options_value(&ctx.options)), "events"),
                "onEvent",
            ));
        let subscribers = !ctx
            .subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .is_empty();
        let has_after_audit = ctx
            .plugins
            .iter()
            .any(|plugin| plugin.after_audit().is_some());
        if has_after_audit || has_on_event || subscribers {
            let mut hook = Record::new();
            hook.insert("id".into(), event.get("id").cloned().unwrap_or(Value::Null));
            hook.insert(
                "tenantId".into(),
                event.get("tenantId").cloned().unwrap_or(Value::Null),
            );
            hook.insert("event".into(), Value::Object(event.clone()));
            hook.insert("delivered".into(), Value::Bool(false));
            tx.insert("auditHooks", &hook).await?;
        }
        let hooks = tx
            .find(
                "webhooks",
                &Filter::new().eq("active", true),
                &FindOptions::default(),
            )
            .await?;
        if hooks.is_empty() {
            return Ok(());
        }
        let mut ancestors: Option<Vec<String>> = None;
        let body = js::stringify(&Value::Object(webhook_body(event)));
        let action = string_of(event, "action");
        let outcome = event.get("outcome").cloned().unwrap_or(Value::Null);
        let resource_id = string_of(event, "resourceId");
        let tenant_id = string_of(event, "tenantId");
        for hook in &hooks {
            if !patterns_match(hook.get("events"), action)? {
                continue;
            }
            if let Some(outcomes) = js::defined(hook.get("outcomes")).filter(|v| truthy(Some(v))) {
                let Value::Array(outcomes) = outcomes else {
                    return Err(js::internal_error());
                };
                if !js::includes(outcomes, &outcome) {
                    continue;
                }
            }
            if let Some(resources) = js::defined(hook.get("resources")).filter(|v| truthy(Some(v)))
                && !patterns_match(Some(resources), resource_id)?
            {
                continue;
            }
            let hook_tenant = string_of(hook, "tenantId");
            if hook_tenant != tenant_id {
                if hook.get("scope").and_then(Value::as_str) != Some("subtree") {
                    continue;
                }
                if ancestors.is_none() {
                    ancestors = Some(ctx.ancestor_ids(tx, tenant_id).await?);
                }
                if !ancestors
                    .as_ref()
                    .is_some_and(|ids| ids.iter().any(|id| id == hook_tenant))
                {
                    continue;
                }
            }
            let mut payload = Map::new();
            payload.insert(
                "url".into(),
                hook.get("url").cloned().unwrap_or(Value::Null),
            );
            payload.insert("body".into(), Value::String(body.clone()));
            ctx.auth
                .enqueue_delivery(
                    tx,
                    EnqueueInput {
                        tenant_id: hook_tenant.to_owned(),
                        kind: OutboxKind::Webhook,
                        to: string_of(hook, "id").to_owned(),
                        template: action.to_owned(),
                        payload,
                        reference: event.get("id").and_then(Value::as_str).map(str::to_owned),
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// `recordAudit(tx, event)`: records an audit event and fans it out. Every audit insert in the server goes
    /// through here.
    pub async fn record_audit(&self, tx: &Store, event: &Record) -> IamResult<()> {
        let chained = append_audit_event(tx.as_ref(), event).await?;
        self.fan_out(tx, &chained).await
    }

    /// `audit(tx, principal, action, tenantId, resourceId, outcome, rootOverride = false, metadata?)`: an audit
    /// event attributed to the acting principal, with the session context of its credential.
    #[allow(clippy::too_many_arguments)]
    pub async fn audit(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        action: &str,
        tenant_id: &str,
        resource_id: &str,
        outcome: AuditOutcome,
        root_override: bool,
        metadata: Option<Map<String, Value>>,
    ) -> IamResult<()> {
        let mut event = Record::new();
        event.insert("id".into(), Value::String(id()));
        event.insert("tenantId".into(), Value::String(tenant_id.to_owned()));
        event.insert(
            "actorId".into(),
            Value::String(principal.identity.id.clone()),
        );
        if let Some(original) = &principal.session.original_identity_id {
            event.insert("originalActorId".into(), Value::String(original.clone()));
        }
        event.insert("action".into(), Value::String(action.to_owned()));
        event.insert("resourceId".into(), Value::String(resource_id.to_owned()));
        event.insert(
            "outcome".into(),
            Value::String(
                match outcome {
                    AuditOutcome::Allow => "allow",
                    AuditOutcome::Deny => "deny",
                }
                .into(),
            ),
        );
        event.insert("rootOverride".into(), Value::Bool(root_override));
        event.insert("timestamp".into(), js::number(date_now()));
        if let Some(metadata) = metadata {
            event.insert("metadata".into(), Value::Object(metadata));
        }
        if let Some(impersonator) = &principal.session.impersonator_id
            && !impersonator.is_empty()
        {
            event.insert("impersonatorId".into(), Value::String(impersonator.clone()));
        }
        // Which credential acted (and the role, trust and names behind a temporary one); covered by the hash chain.
        if let Some(context) = audit_session_context(Some(&principal.session)) {
            event.insert(
                "sessionContext".into(),
                serde_json::to_value(context).unwrap_or(Value::Null),
            );
        }
        // Hooks are dispatched separately so external code cannot interrupt a committed mutation.
        self.record_audit(tx, &event).await
    }

    /// `deliverWebhookMessage(message)`: the built-in webhook transport. Signs the stored body with the
    /// subscription's current secret and POSTs it (or hands it to `events.deliverWebhook`).
    pub async fn deliver_webhook_message(
        &self,
        message: DeliveryMessage,
    ) -> Result<(), DeliveryError> {
        let ctx = self.ctx()?;
        let Some(hook) = ctx.store.get("webhooks", &message.to).await? else {
            return Ok(());
        };
        // A removed or paused subscription drops its pending deliveries instead of failing forever.
        if !truthy(hook.get("active")) {
            return Ok(());
        }
        let Some(Value::String(body)) = message.payload.get("body") else {
            return Err(
                IamError::new("INVALID_SEALED_VALUE", "Webhook payload is incomplete").into(),
            );
        };
        let hook_id = string_of(&hook, "id").to_owned();
        let Some(Value::String(sealed)) = hook.get("secretSealed") else {
            return Err(js::internal_error().into());
        };
        let mut secrets = vec![ctx.options.secret.clone()];
        secrets.extend(ctx.options.previous_secrets.clone().unwrap_or_default());
        let secret = decrypt_secret(sealed, &secrets, &format!("webhook:{hook_id}"))?;
        let timestamp = (ctx.now() / 1000.0).floor();
        let timestamp_text = number_to_string(timestamp);
        let signature = hex::encode(hmac(secret.as_bytes(), &format!("{timestamp_text}.{body}")));
        let mut headers = IndexMap::new();
        headers.insert("content-type".to_owned(), "application/json".to_owned());
        headers.insert("user-agent".to_owned(), "better-iam-webhooks/1".to_owned());
        headers.insert("x-better-iam-event".to_owned(), message.template.clone());
        headers.insert("x-better-iam-delivery".to_owned(), message.id.clone());
        headers.insert("x-better-iam-webhook".to_owned(), hook_id.clone());
        headers.insert("x-better-iam-timestamp".to_owned(), timestamp_text);
        headers.insert(
            "x-better-iam-signature".to_owned(),
            format!("v1={signature}"),
        );
        let delivery = WebhookDelivery {
            id: message.id.clone(),
            tenant_id: message.tenant_id.clone(),
            webhook_id: hook_id,
            url: js::js_string(hook.get("url")),
            event: message.template.clone(),
            body: body.clone(),
            headers,
        };
        if let Some(deliver) = ctx
            .options
            .events
            .as_ref()
            .and_then(|events| events.deliver_webhook.clone())
        {
            return deliver(delivery).await;
        }
        let mut request = FetchRequest::new(
            delivery.url.clone(),
            "POST",
            Some(FetchBody::Text(body.clone())),
        )
        .redirect(RedirectMode::Error);
        for (name, value) in &delivery.headers {
            request = request.header(name.clone(), value.clone());
        }
        let timeout = Duration::from_millis(ctx.config.webhook_timeout_ms.max(0.0) as u64);
        // Tenant administrators choose the URL: the guarded transport refuses private and reserved addresses at
        // connect time and never follows redirects. One message for every connection failure, so delivery history
        // cannot map networks or ports.
        let mut response = match tokio::time::timeout(timeout, self.fetch.fetch(request)).await {
            Err(_) => {
                return Err(IamError::with_status(
                    "WEBHOOK_UNREACHABLE",
                    "Webhook endpoint did not answer in time",
                    502,
                )
                .into());
            }
            Ok(Err(_)) => {
                return Err(IamError::with_status(
                    "WEBHOOK_UNREACHABLE",
                    "Webhook endpoint could not be reached",
                    502,
                )
                .into());
            }
            Ok(Ok(response)) => response,
        };
        // The response body is never read; release the connection.
        response.body.cancel();
        if !response.ok() {
            return Err(IamError::with_status(
                "WEBHOOK_REJECTED",
                format!("Webhook endpoint responded with status {}", response.status),
                502,
            )
            .into());
        }
        Ok(())
    }

    /// `dispatch()`: post-commit dispatch of queued events to plugins, the configured callback, and in-process
    /// subscribers.
    pub async fn dispatch(&self) -> IamResult<Dispatched> {
        let ctx = self.ctx()?;
        let mut dispatched = 0;
        let rows = ctx
            .store
            .find(
                "auditHooks",
                &Filter::new().eq("delivered", false),
                &FindOptions::default(),
            )
            .await?;
        for row in rows {
            let event = match row.get("event") {
                Some(Value::Object(event)) => event.clone(),
                _ => Record::new(),
            };
            for plugin in &ctx.plugins {
                if let Some(hook) = plugin.after_audit() {
                    hook.after_audit(&event).await?;
                }
            }
            if let Some(on_event) = ctx
                .options
                .events
                .as_ref()
                .and_then(|events| events.on_event.clone())
            {
                on_event(event.clone()).await?;
            }
            let subscribers: Vec<Arc<EventSubscriber>> = ctx
                .subscribers
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .clone();
            let action = string_of(&event, "action").to_owned();
            for subscriber in subscribers {
                if subscriber
                    .patterns
                    .iter()
                    .any(|pattern| match_pattern(pattern, &action, None))
                {
                    (subscriber.handler)(event.clone()).await?;
                }
            }
            // Re-read: another dispatcher may have delivered the row and a retention sweep deleted it.
            let row_id = string_of(&row, "id").to_owned();
            let now = ctx.now();
            ctx.store
                .transaction(move |tx| async move {
                    if let Some(mut current) = tx.get("auditHooks", &row_id).await?
                        && !truthy(current.get("delivered"))
                    {
                        current.insert("delivered".into(), Value::Bool(true));
                        current.insert("deliveredAt".into(), js::number(now));
                        tx.put("auditHooks", &current).await?;
                    }
                    Ok(())
                })
                .await?;
            dispatched += 1;
        }
        Ok(Dispatched { dispatched })
    }

    /// `subscribe(pattern, handler)`: an in-process handler for audit events whose action matches any pattern.
    pub fn subscribe(&self, patterns: &[&str], handler: SubscriberFn) -> IamResult<Subscription> {
        let ctx = self.ctx()?;
        let patterns = patterns
            .iter()
            .map(|pattern| text_str(pattern, "event pattern", 128))
            .collect::<IamResult<Vec<_>>>()?;
        let subscriber = Arc::new(EventSubscriber { patterns, handler });
        ctx.subscribers
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .push(subscriber.clone());
        Ok(Subscription {
            ctx: self.ctx.clone(),
            subscriber,
        })
    }

    /// `webhookUrl(value)`: an absolute https URL without credentials or a fragment, pointing at a public address.
    pub fn webhook_url(&self, value: Option<&Value>) -> IamResult<String> {
        let ctx = self.ctx()?;
        let raw = text(value, "url", 2048)?;
        let Ok(url) = Url::parse(&raw) else {
            return Err(invalid_input("Webhook URL must be absolute"));
        };
        if !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some_and(|fragment| !fragment.is_empty())
        {
            return Err(invalid_input(
                "Webhook URLs cannot carry credentials or fragments",
            ));
        }
        let loopback = ["localhost", "127.0.0.1", "[::1]"].contains(&url_hostname(&url).as_str());
        if url.scheme() != "https" && !(url.scheme() == "http" && loopback && !ctx.config.https()) {
            return Err(invalid_input("Webhook URLs must use HTTPS"));
        }
        // IP literals are judged now; hostnames are judged again by the transport each time it connects.
        if check_fetch_url(url.as_str(), &self.rules).is_err() {
            return Err(invalid_input(
                "Webhook URLs must point at a public address (see events.allowPrivateNetworks)",
            ));
        }
        Ok(url.to_string())
    }

    /// `webhookEvents(value)`: 1-50 event name patterns, deduplicated.
    pub fn webhook_events(&self, value: Option<&Value>) -> IamResult<Vec<String>> {
        let patterns = strings(value, "events")?;
        if patterns.is_empty()
            || patterns.len() > 50
            || patterns
                .iter()
                .any(|pattern| !WEBHOOK_EVENT_PATTERN.is_match(pattern))
        {
            return Err(invalid_input(
                "events must contain 1-50 event name patterns",
            ));
        }
        Ok(js::unique(patterns))
    }

    /// `sealedWebhookSecret(hookId)`.
    pub fn sealed_webhook_secret(&self, hook_id: &str) -> IamResult<SealedWebhookSecret> {
        let ctx = self.ctx()?;
        let secret = format!("whsec_{}", token());
        let sealed = encrypt_secret(&secret, &ctx.options.secret, &format!("webhook:{hook_id}"));
        Ok(SealedWebhookSecret { secret, sealed })
    }
}

/// The signed delivery `deliverWebhookMessage` builds for a stored body (vectors and tests): the headers and the
/// `v1=` HMAC-SHA256 signature of `{timestamp}.{body}` with the webhook secret at `now`.
pub fn sign_webhook(secret: &str, body: &str, now: f64) -> (String, String) {
    let timestamp = number_to_string((now / 1000.0).floor());
    let signature = hex::encode(hmac(secret.as_bytes(), &format!("{timestamp}.{body}")));
    (timestamp, format!("v1={signature}"))
}
