//! The transactional outbox: sealed deliveries enqueued with the change that caused them and delivered at least
//! once with backoff (`outbox.ts`).

use std::sync::Arc;

use better_iam_core::{
    Filter, FindOptions, IamError, IamResult, IamStore, IamStoreExt, OutboxKind, Record, js,
};
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::crypto::{decrypt_secret, encrypt_secret, new_id};
use crate::types::{DeliveryError, DeliveryFn, DeliveryMessage, NowFn};
use crate::util::{js_less, num, truthy};

/// The outbox's view of the service (`OutboxContext`).
#[derive(Clone)]
pub struct OutboxContext {
    pub store: Arc<dyn IamStore>,
    /// Seals new payloads.
    pub secret: String,
    /// Opens payloads: the current secret, then previous ones during a rotation (defaults to `secret`).
    pub secrets: Option<Vec<String>>,
    pub now: NowFn,
    pub max_attempts: f64,
    /// The callback for a message kind, or None when that kind is not configured.
    pub deliverer: Arc<dyn Fn(OutboxKind) -> Option<DeliveryFn> + Send + Sync>,
}

/// What one dispatch pass did (`DispatchResult`).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct DispatchResult {
    pub delivered: u32,
    pub failed: u32,
    pub abandoned: u32,
}

/// What `enqueueDelivery` queues.
#[derive(Debug, Clone, PartialEq)]
pub struct EnqueueInput {
    pub tenant_id: String,
    pub kind: OutboxKind,
    pub to: String,
    pub template: String,
    pub payload: Map<String, Value>,
    pub reference: Option<String>,
}

fn kind_name(kind: OutboxKind) -> &'static str {
    match kind {
        OutboxKind::Email => "email",
        OutboxKind::Sms => "sms",
        OutboxKind::Webhook => "webhook",
    }
}

fn kind_of(value: Option<&Value>) -> Option<OutboxKind> {
    match value.and_then(Value::as_str) {
        Some("email") => Some(OutboxKind::Email),
        Some("sms") => Some(OutboxKind::Sms),
        Some("webhook") => Some(OutboxKind::Webhook),
        _ => None,
    }
}

/// `enqueueDelivery(ctx, tx, input)`: enqueues a sealed delivery in the caller's transaction and returns the
/// message ID.
pub async fn enqueue_delivery(
    ctx: &OutboxContext,
    tx: &dyn IamStore,
    input: EnqueueInput,
) -> IamResult<String> {
    if (ctx.deliverer)(input.kind).is_none() {
        return Err(IamError::new(
            "FEATURE_DISABLED",
            format!("{} delivery is not configured", kind_name(input.kind)),
        ));
    }
    let id = new_id("out");
    let sealed = encrypt_secret(
        &js::stringify(&Value::Object(input.payload)),
        &ctx.secret,
        &format!("outbox:{id}"),
    );
    let mut message = better_iam_core::record(json!({
        "id": id,
        "tenantId": input.tenant_id,
        "kind": kind_name(input.kind),
        "to": input.to,
        "template": input.template,
        "payload": { "sealed": sealed },
        "createdAt": num((ctx.now)()),
        "attempts": 0,
    }));
    if let Some(reference) = input.reference {
        message.insert("reference".to_owned(), Value::String(reference));
    }
    tx.insert("outbox", &message).await?;
    Ok(id)
}

fn number_of(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(js::as_number)
}

/// `typeof message.leaseUntil === 'number' && message.leaseUntil > now`.
fn leased(record: &Record, now: f64) -> bool {
    number_of(record, "leaseUntil").is_some_and(|until| until > now)
}

fn pending(record: &Record, now: f64) -> bool {
    !truthy(record.get("deliveredAt")) && !truthy(record.get("failedAt")) && !leased(record, now)
}

/// `a - b` of two JavaScript numbers read from records (`undefined - x` is NaN).
fn created_at(record: &Record) -> f64 {
    number_of(record, "createdAt").unwrap_or(f64::NAN)
}

fn id_of(record: &Record) -> &str {
    record.get("id").and_then(Value::as_str).unwrap_or("")
}

/// `{ ...message, ...changes }`: replaces members in place and appends new ones; `None` values are dropped
/// (`undefined` disappears from JSON).
fn merged(message: &Record, changes: Vec<(&str, Option<Value>)>) -> Record {
    let mut next = message.clone();
    for (key, value) in changes {
        match value {
            Some(value) => {
                next.insert(key.to_owned(), value);
            }
            None => {
                next.shift_remove(key);
            }
        }
    }
    next
}

/// `dispatchOutbox(ctx, limit)`: at-least-once delivery. Callbacks must deduplicate by `message.id`. A failed
/// attempt is retried with exponential backoff (30 seconds doubling to one hour) until `maxAttempts`, then abandoned
/// with `failedAt` set.
pub async fn dispatch_outbox(ctx: &OutboxContext, limit: f64) -> IamResult<DispatchResult> {
    if !js::is_safe_integer(limit) || !(1.0..=1000.0).contains(&limit) {
        return Err(IamError::new(
            "INVALID_INPUT",
            "limit must be between 1 and 1000",
        ));
    }
    let mut result = DispatchResult::default();
    let now = (ctx.now)();
    let mut candidates: Vec<Record> = ctx
        .store
        .find("outbox", &Filter::new(), &FindOptions::default())
        .await?
        .into_iter()
        .filter(|message| pending(message, now))
        .collect();
    candidates.sort_by(|a, b| {
        let delta = created_at(a) - created_at(b);
        if delta != 0.0 && !delta.is_nan() {
            return delta.partial_cmp(&0.0).unwrap_or(std::cmp::Ordering::Equal);
        }
        if js_less(id_of(a), id_of(b)) {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        }
    });
    candidates.truncate(limit as usize);
    for candidate in candidates {
        let lease = new_id("lease");
        let candidate_id = id_of(&candidate).to_owned();
        // Claiming is its own transaction so two workers never deliver the same message.
        let claimed = {
            let lease = lease.clone();
            let candidate_id = candidate_id.clone();
            let now = ctx.now.clone();
            ctx.store
                .transaction(|tx| async move {
                    let Some(mut message) = tx.get("outbox", &candidate_id).await? else {
                        return Ok(None);
                    };
                    if !pending(&message, now()) {
                        return Ok(None);
                    }
                    message.insert("lease".to_owned(), Value::String(lease));
                    message.insert("leaseUntil".to_owned(), num(now() + 60_000.0));
                    let attempts = number_of(&message, "attempts").unwrap_or(f64::NAN) + 1.0;
                    message.insert("attempts".to_owned(), num(attempts));
                    tx.put("outbox", &message).await?;
                    Ok(Some(message))
                })
                .await?
        };
        let Some(claimed) = claimed else {
            continue;
        };
        match deliver(ctx, &claimed).await {
            Ok(()) => {
                let lease = lease.clone();
                let id = candidate_id.clone();
                let now = ctx.now.clone();
                ctx.store
                    .transaction(|tx| async move {
                        if let Some(message) = tx.get("outbox", &id).await?
                            && message.get("lease").and_then(Value::as_str) == Some(lease.as_str())
                        {
                            let next = merged(
                                &message,
                                vec![
                                    ("payload", Some(json!({}))),
                                    ("deliveredAt", Some(num(now()))),
                                    ("leaseUntil", Some(json!(0))),
                                    ("lastError", None),
                                ],
                            );
                            tx.put("outbox", &next).await?;
                        }
                        Ok(())
                    })
                    .await?;
                result.delivered += 1;
            }
            Err(error) => {
                result.failed += 1;
                let last_error = truncate_utf16(&error.recorded(), 256);
                let attempts = number_of(&claimed, "attempts").unwrap_or(f64::NAN);
                let exhausted = attempts >= ctx.max_attempts;
                if exhausted {
                    result.abandoned += 1;
                }
                let backoff =
                    (30_000.0 * 2f64.powf((attempts - 1.0).max(0.0))).min(60.0 * 60_000.0);
                let lease = lease.clone();
                let id = candidate_id.clone();
                let now = ctx.now.clone();
                ctx.store
                    .transaction(|tx| async move {
                        let Some(message) = tx.get("outbox", &id).await? else {
                            return Ok(());
                        };
                        if message.get("lease").and_then(Value::as_str) != Some(lease.as_str()) {
                            return Ok(());
                        }
                        let next = if exhausted {
                            merged(
                                &message,
                                vec![
                                    ("payload", Some(json!({}))),
                                    ("failedAt", Some(num(now()))),
                                    ("leaseUntil", Some(json!(0))),
                                    ("lastError", Some(Value::String(last_error))),
                                ],
                            )
                        } else {
                            merged(
                                &message,
                                vec![
                                    ("leaseUntil", Some(num(now() + backoff))),
                                    ("lastError", Some(Value::String(last_error))),
                                ],
                            )
                        };
                        tx.put("outbox", &next).await?;
                        Ok(())
                    })
                    .await?;
            }
        }
    }
    Ok(result)
}

/// `value.slice(0, max)` by UTF-16 code units.
pub(crate) fn truncate_utf16(value: &str, max: usize) -> String {
    if js::utf16_len(value) <= max {
        return value.to_owned();
    }
    let units: Vec<u16> = value.encode_utf16().take(max).collect();
    String::from_utf16_lossy(&units)
}

async fn deliver(ctx: &OutboxContext, claimed: &Record) -> Result<(), DeliveryError> {
    let kind = kind_of(claimed.get("kind"));
    let callback = kind.and_then(|kind| (ctx.deliverer)(kind)).ok_or_else(|| {
        DeliveryError::from(IamError::new(
            "FEATURE_DISABLED",
            "Delivery callback unavailable",
        ))
    })?;
    let sealed = claimed
        .get("payload")
        .and_then(|payload| payload.get("sealed"))
        .filter(|sealed| truthy(Some(sealed)))
        .ok_or_else(|| {
            DeliveryError::from(IamError::new(
                "INVALID_SEALED_VALUE",
                "Outbox payload is not sealed",
            ))
        })?;
    let id = id_of(claimed);
    let secrets: Vec<String> = ctx
        .secrets
        .clone()
        .unwrap_or_else(|| vec![ctx.secret.clone()]);
    let opened = match sealed {
        Value::String(sealed) => decrypt_secret(sealed, &secrets, &format!("outbox:{id}"))?,
        _ => {
            return Err(DeliveryError::from(IamError::new(
                "INVALID_SEALED_VALUE",
                "Invalid sealed value",
            )));
        }
    };
    let payload = match js::parse(&opened) {
        Ok(Value::Object(payload)) => payload,
        Ok(_) => Map::new(),
        Err(error) => return Err(DeliveryError::new("SyntaxError", error.to_string())),
    };
    let text = |key: &str| {
        claimed
            .get(key)
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned()
    };
    callback(DeliveryMessage {
        id: id.to_owned(),
        tenant_id: text("tenantId"),
        to: text("to"),
        template: text("template"),
        payload,
        sign_in_url: None,
    })
    .await
}
