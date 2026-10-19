//! Port of `packages/server/src/usage.ts`.
//!
//! Ported in full (kernel B: every operation records its use here).
#![allow(
    unused_variables,
    unused_imports,
    dead_code,
    clippy::too_many_arguments,
    clippy::module_inception
)]

use std::sync::{Arc, Weak};

use better_iam_core::{IamError, IamResult};
use indexmap::{IndexMap, IndexSet};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::context::{ServerContext, Store};
use crate::options::{HttpRequest, HttpResponse};
use crate::port::{Callback, not_ported};

/// One identity's use of one action in a tenant; the ID is `{tenantId}:{identityId}:{action}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessUsageRecord {
    #[serde(rename = "identityId")]
    pub identity_id: String,
    #[serde(rename = "action")]
    pub action: String,
    #[serde(rename = "firstUsedAt")]
    pub first_used_at: f64,
    #[serde(rename = "lastUsedAt")]
    pub last_used_at: f64,
    /// Allowed checks counted since tracking began (approximate across concurrent instances).
    #[serde(rename = "count")]
    pub count: f64,
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

/// When a tenant's usage was first recorded; the ID is the tenant ID.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AccessUsageTracking {
    #[serde(rename = "startedAt")]
    pub started_at: f64,
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

/// `usageRecordId(tenantId, identityId, action)`.
pub fn usage_record_id(tenant_id: &str, identity_id: &str, action: &str) -> String {
    format!("{tenant_id}:{identity_id}:{action}")
}

/// One buffered use count (`Pending`).
#[derive(Debug, Clone)]
struct Pending {
    tenant_id: String,
    identity_id: String,
    action: String,
    first: f64,
    last: f64,
    count: f64,
}

struct State {
    /// Keys are JSON arrays: identity and action strings may contain any separator.
    buffer: IndexMap<String, Pending>,
    scheduled: bool,
    writing: bool,
    last_failure: f64,
}

/// `createUsageRecorder(ctx)`: buffered access usage tracking (`accessUsage` option).
pub struct UsageRecorder {
    ctx: Weak<ServerContext>,
    enabled: bool,
    interval: f64,
    max_buffered: f64,
    state: std::sync::Mutex<State>,
    /// One write at a time (`writing`): a caller arriving mid-write waits and then writes what arrived since.
    write_lock: tokio::sync::Mutex<()>,
    timer: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    this: std::sync::OnceLock<Weak<UsageRecorder>>,
}

/// `createUsageRecorder(ctx)`. With tracking on, a periodic writer runs every `flushIntervalMs` (default 60 s, at
/// least 1 s) on the tokio runtime the recorder is created on.
pub fn create_usage_recorder(ctx: &Arc<ServerContext>) -> IamResult<Arc<UsageRecorder>> {
    let setting = ctx.options.access_usage.as_ref();
    let enabled = setting.is_some_and(|toggle| toggle.enabled());
    let options = setting.and_then(|toggle| toggle.options());
    let interval = options
        .and_then(|options| options.flush_interval_ms)
        .unwrap_or(60_000.0)
        .max(1000.0);
    let max_buffered = options
        .and_then(|options| options.max_buffered)
        .unwrap_or(10_000.0)
        .max(1.0);
    let recorder = Arc::new(UsageRecorder {
        ctx: Arc::downgrade(ctx),
        enabled,
        interval,
        max_buffered,
        state: std::sync::Mutex::new(State {
            buffer: IndexMap::new(),
            scheduled: false,
            writing: false,
            last_failure: 0.0,
        }),
        write_lock: tokio::sync::Mutex::new(()),
        timer: std::sync::Mutex::new(None),
        this: std::sync::OnceLock::new(),
    });
    let _ = recorder.this.set(Arc::downgrade(&recorder));
    if enabled && let Ok(runtime) = tokio::runtime::Handle::try_current() {
        let weak = Arc::downgrade(&recorder);
        let period = std::time::Duration::from_millis(interval as u64);
        let handle = runtime.spawn(async move {
            let mut ticker = tokio::time::interval_at(tokio::time::Instant::now() + period, period);
            loop {
                ticker.tick().await;
                let Some(recorder) = weak.upgrade() else {
                    return;
                };
                if recorder.buffered() > 0 && recorder.flush_written().await.is_err() {
                    recorder.lock().last_failure = crate::utils::date_now();
                }
            }
        });
        *recorder
            .timer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(handle);
    }
    Ok(recorder)
}

impl UsageRecorder {
    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn buffered(&self) -> usize {
        self.lock().buffer.len()
    }

    /// Writes one batch in its own transaction; the number of rows written.
    async fn write(&self, batch: &IndexMap<String, Pending>) -> IamResult<f64> {
        if batch.is_empty() {
            return Ok(0.0);
        }
        let Some(ctx) = self.ctx.upgrade() else {
            return Ok(0.0);
        };
        use better_iam_core::IamStoreExt;
        ctx.store
            .transaction(|tx| async move {
                let mut tenants: IndexMap<String, f64> = IndexMap::new();
                for entry in batch.values() {
                    let first = tenants
                        .get(&entry.tenant_id)
                        .copied()
                        .unwrap_or(f64::INFINITY)
                        .min(entry.first);
                    tenants.insert(entry.tenant_id.clone(), first);
                    let id = usage_record_id(&entry.tenant_id, &entry.identity_id, &entry.action);
                    match tx.get("accessUsage", &id).await? {
                        Some(mut existing) => {
                            let number = |record: &Map<String, Value>, key: &str| {
                                record
                                    .get(key)
                                    .and_then(better_iam_core::js::as_number)
                                    .unwrap_or(f64::NAN)
                            };
                            let first_used = number(&existing, "firstUsedAt").min(entry.first);
                            let last_used = number(&existing, "lastUsedAt").max(entry.last);
                            let count = number(&existing, "count") + entry.count;
                            existing.insert("firstUsedAt".into(), crate::js::number(first_used));
                            existing.insert("lastUsedAt".into(), crate::js::number(last_used));
                            existing.insert("count".into(), crate::js::number(count));
                            tx.put("accessUsage", &existing).await?;
                        }
                        None => {
                            let mut record = Map::new();
                            record.insert("id".into(), Value::String(id));
                            record
                                .insert("tenantId".into(), Value::String(entry.tenant_id.clone()));
                            record.insert(
                                "identityId".into(),
                                Value::String(entry.identity_id.clone()),
                            );
                            record.insert("action".into(), Value::String(entry.action.clone()));
                            record.insert("firstUsedAt".into(), crate::js::number(entry.first));
                            record.insert("lastUsedAt".into(), crate::js::number(entry.last));
                            record.insert("count".into(), crate::js::number(entry.count));
                            tx.insert("accessUsage", &record).await?;
                        }
                    }
                }
                for (tenant_id, started_at) in tenants {
                    if tx.get("accessUsageTracking", &tenant_id).await?.is_none() {
                        let mut record = Map::new();
                        record.insert("id".into(), Value::String(tenant_id.clone()));
                        record.insert("tenantId".into(), Value::String(tenant_id));
                        record.insert("startedAt".into(), crate::js::number(started_at));
                        tx.insert("accessUsageTracking", &record).await?;
                    }
                }
                Ok(())
            })
            .await?;
        Ok(batch.len() as f64)
    }

    /// `flush()`: writes everything buffered (concurrent calls write one after the other); the rows written
    /// (`{ written }`). A failed write keeps its batch for the next attempt, merged with anything recorded meanwhile.
    pub async fn flush_written(&self) -> IamResult<f64> {
        let _writing = self.write_lock.lock().await;
        let batch = {
            let mut state = self.lock();
            state.writing = true;
            std::mem::take(&mut state.buffer)
        };
        let result = self.write(&batch).await;
        let mut state = self.lock();
        state.writing = false;
        if result.is_err() {
            for (key, entry) in batch {
                match state.buffer.get_mut(&key) {
                    None => {
                        state.buffer.insert(key, entry);
                    }
                    Some(current) => {
                        current.first = current.first.min(entry.first);
                        current.last = current.last.max(entry.last);
                        current.count += entry.count;
                    }
                }
            }
        }
        result
    }

    /// The conformance server's `call` for a member of this object.
    pub async fn call(&self, method: &str, args: Vec<Value>) -> Option<IamResult<Value>> {
        use crate::contracts::UsageRecorder as _;
        match method {
            "flush" => Some(
                self.flush_written()
                    .await
                    .map(|written| json!({ "written": crate::js::number(written) })),
            ),
            "stop" => {
                self.stop();
                Some(Ok(Value::Null))
            }
            "record" => {
                let text = |index: usize| {
                    args.get(index)
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned()
                };
                self.record(&text(0), &text(1), &text(2));
                Some(Ok(Value::Null))
            }
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl crate::contracts::UsageRecorder for UsageRecorder {
    fn enabled(&self) -> bool {
        self.enabled
    }

    fn record(&self, tenant_id: &str, identity_id: &str, action: &str) {
        if !self.enabled {
            return;
        }
        let Some(ctx) = self.ctx.upgrade() else {
            return;
        };
        let now = ctx.now();
        let key = better_iam_core::js::stringify(&json!([tenant_id, identity_id, action]));
        let mut state = self.lock();
        match state.buffer.get_mut(&key) {
            Some(entry) => {
                entry.last = entry.last.max(now);
                entry.count += 1.0;
            }
            None => {
                state.buffer.insert(
                    key,
                    Pending {
                        tenant_id: tenant_id.to_owned(),
                        identity_id: identity_id.to_owned(),
                        action: action.to_owned(),
                        first: now,
                        last: now,
                        count: 1.0,
                    },
                );
            }
        }
        // One early write at a time, and none while storage keeps failing (the interval retries). It runs on its own
        // task, outside the caller's transaction (TypeScript binds it to the construction context for that reason).
        if state.buffer.len() as f64 >= self.max_buffered
            && !state.scheduled
            && !state.writing
            && crate::utils::date_now() - state.last_failure >= self.interval
            && let (Ok(runtime), Some(this)) = (
                tokio::runtime::Handle::try_current(),
                self.this.get().and_then(Weak::upgrade),
            )
        {
            state.scheduled = true;
            drop(state);
            runtime.spawn(async move {
                this.lock().scheduled = false;
                if this.flush_written().await.is_err() {
                    this.lock().last_failure = crate::utils::date_now();
                }
            });
        }
    }

    async fn flush(&self) -> IamResult<f64> {
        self.flush_written().await
    }

    fn stop(&self) {
        if let Some(handle) = self
            .timer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            handle.abort();
        }
    }
}

impl Drop for UsageRecorder {
    fn drop(&mut self) {
        if let Some(handle) = self
            .timer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            handle.abort();
        }
    }
}
