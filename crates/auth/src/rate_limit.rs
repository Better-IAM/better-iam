//! Attempt counters: the in-memory limiter, the default store limiter, and option resolution (`rate-limit.ts`).

use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use better_iam_core::{Filter, IamError, IamResult, IamStore, IamStoreExt, js};

use crate::types::{ConsumeInput, RateLimitOptions, RateLimiter, RateRecord, ResetInput};
use crate::util::{find, get, insert, put};

/// The limits in force (`ResolvedRateLimits`).
#[derive(Clone)]
pub struct ResolvedRateLimits {
    pub attempts: f64,
    pub sensitive_attempts: f64,
    pub window_ms: f64,
    /// Per-client-IP attempts per window across flows; 0 disables the check.
    pub ip_attempts: f64,
    pub limiter: Arc<dyn RateLimiter>,
}

/// `MemoryRateLimiterOptions`.
#[derive(Debug, Clone, Default)]
pub struct MemoryRateLimiterOptions {
    /// Counters kept at most (default 100,000). Expired counters are dropped first; at the cap with none expired,
    /// the oldest window is dropped (its counter starts over).
    pub max_keys: Option<f64>,
}

struct Counter {
    count: f64,
    reset_at: f64,
    order: u64,
}

#[derive(Default)]
struct Counters {
    /// Insertion order (a JavaScript `Map` iterates oldest insertion first).
    order: BTreeMap<u64, String>,
    entries: HashMap<String, Counter>,
    next: u64,
}

impl Counters {
    fn remove(&mut self, key: &str) {
        if let Some(entry) = self.entries.remove(key) {
            self.order.remove(&entry.order);
        }
    }
}

/// The in-process limiter (`createMemoryRateLimiter`) for single-instance deployments and tests.
pub struct MemoryRateLimiter {
    max_keys: usize,
    counters: Mutex<Counters>,
}

/// `createMemoryRateLimiter(options)`: counters are not shared between processes, and the map is bounded by
/// `maxKeys`.
pub fn create_memory_rate_limiter(
    options: MemoryRateLimiterOptions,
) -> IamResult<Arc<dyn RateLimiter>> {
    let max_keys = options.max_keys.unwrap_or(100_000.0);
    if !js::is_safe_integer(max_keys) || max_keys < 1.0 {
        return Err(IamError::new(
            "INVALID_CONFIG",
            "maxKeys must be a positive integer",
        ));
    }
    Ok(Arc::new(MemoryRateLimiter {
        max_keys: max_keys as usize,
        counters: Mutex::new(Counters::default()),
    }))
}

#[async_trait]
impl RateLimiter for MemoryRateLimiter {
    async fn consume(&self, input: ConsumeInput) -> IamResult<bool> {
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let now = input.now;
        // Prune from the oldest window, stopping at the first live counter.
        while let Some((&order, key)) = counters.order.iter().next() {
            let live = counters
                .entries
                .get(key)
                .is_some_and(|entry| entry.reset_at > now);
            if live {
                break;
            }
            let key = key.clone();
            counters.order.remove(&order);
            counters.entries.remove(&key);
        }
        let fresh = counters
            .entries
            .get(&input.key)
            .is_none_or(|entry| entry.reset_at <= now);
        if fresh {
            counters.remove(&input.key);
            while counters.entries.len() >= self.max_keys {
                let Some((&order, key)) = counters.order.iter().next() else {
                    break;
                };
                let key = key.clone();
                counters.order.remove(&order);
                counters.entries.remove(&key);
            }
            let order = counters.next;
            counters.next += 1;
            counters.order.insert(order, input.key.clone());
            counters.entries.insert(
                input.key.clone(),
                Counter {
                    count: 0.0,
                    reset_at: now + input.window_ms,
                    order,
                },
            );
        }
        let entry = counters
            .entries
            .get_mut(&input.key)
            .expect("the counter just ensured");
        if entry.count >= input.limit {
            return Ok(false);
        }
        entry.count += 1.0;
        Ok(true)
    }

    fn supports_reset(&self) -> bool {
        true
    }

    async fn reset(&self, input: ResetInput) -> IamResult<()> {
        let mut counters = self
            .counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        counters.remove(&input.key);
        Ok(())
    }
}

/// A store limiter sweeps expired counters at most this often, in transactions of at most `SWEEP_BATCH` deletions.
const SWEEP_INTERVAL_MS: f64 = 60_000.0;
const SWEEP_BATCH: usize = 200;

/// The default limiter (`createStoreRateLimiter`): durable counters in the IAM database, committed independently so
/// rejected credentials cannot roll back their attempt.
pub struct StoreRateLimiter {
    store: Arc<dyn IamStore>,
    next_sweep: Mutex<f64>,
    sweeping: Arc<AtomicBool>,
}

/// `createStoreRateLimiter(store)`.
pub fn create_store_rate_limiter(store: Arc<dyn IamStore>) -> Arc<dyn RateLimiter> {
    Arc::new(StoreRateLimiter {
        store,
        next_sweep: Mutex::new(f64::NEG_INFINITY),
        sweeping: Arc::new(AtomicBool::new(false)),
    })
}

async fn sweep(store: Arc<dyn IamStore>, now: f64) -> IamResult<()> {
    let expired: Vec<RateRecord> =
        find::<RateRecord>(store.as_ref(), "authRateLimits", &Filter::new())
            .await?
            .into_iter()
            .filter(|record| record.reset_at <= now)
            .collect();
    for batch in expired.chunks(SWEEP_BATCH) {
        let ids: Vec<String> = batch.iter().map(|record| record.id.clone()).collect();
        store
            .transaction(|tx| async move {
                for id in ids {
                    let current: Option<RateRecord> =
                        get(tx.as_ref(), "authRateLimits", &id).await?;
                    if current.is_some_and(|current| current.reset_at <= now) {
                        tx.delete("authRateLimits", &id).await?;
                    }
                }
                Ok(())
            })
            .await?;
    }
    Ok(())
}

#[async_trait]
impl RateLimiter for StoreRateLimiter {
    async fn consume(&self, input: ConsumeInput) -> IamResult<bool> {
        let ConsumeInput {
            key,
            tenant_id,
            limit,
            window_ms,
            now,
        } = input;
        let permitted = self
            .store
            .transaction(|tx| async move {
                let existing: Option<RateRecord> = get(tx.as_ref(), "authRateLimits", &key).await?;
                let mut record = match &existing {
                    Some(existing) if existing.reset_at > now => existing.clone(),
                    _ => RateRecord {
                        id: key.clone(),
                        tenant_id: tenant_id.clone(),
                        unique_key: None,
                        count: 0.0,
                        reset_at: now + window_ms,
                        extra: Default::default(),
                    },
                };
                if record.count >= limit {
                    return Ok(false);
                }
                record.count += 1.0;
                if existing.is_some() {
                    put(tx.as_ref(), "authRateLimits", &record).await?;
                } else {
                    insert(tx.as_ref(), "authRateLimits", &record).await?;
                }
                Ok(true)
            })
            .await?;
        let due = {
            let mut next = self
                .next_sweep
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if !self.sweeping.load(Ordering::SeqCst) && now >= *next {
                self.sweeping.store(true, Ordering::SeqCst);
                *next = now + SWEEP_INTERVAL_MS;
                true
            } else {
                false
            }
        };
        if due {
            let store = self.store.clone();
            let sweeping = self.sweeping.clone();
            let task = async move {
                // Housekeeping only: the next sweep (or the purge worker) retries.
                let _ = sweep(store, now).await;
                sweeping.store(false, Ordering::SeqCst);
            };
            match tokio::runtime::Handle::try_current() {
                Ok(handle) => {
                    handle.spawn(task);
                }
                Err(_) => self.sweeping.store(false, Ordering::SeqCst),
            }
        }
        Ok(permitted)
    }

    fn supports_reset(&self) -> bool {
        true
    }

    async fn reset(&self, input: ResetInput) -> IamResult<()> {
        let key = input.key;
        self.store
            .transaction(|tx| async move {
                if tx.get("authRateLimits", &key).await?.is_some() {
                    tx.delete("authRateLimits", &key).await?;
                }
                Ok(())
            })
            .await
    }
}

/// `resolveRateLimits(options, store)`: defaults and bounds.
pub fn resolve_rate_limits(
    options: Option<&RateLimitOptions>,
    store: Arc<dyn IamStore>,
) -> IamResult<ResolvedRateLimits> {
    let limits = options.cloned().unwrap_or_default();
    let resolved = ResolvedRateLimits {
        attempts: limits.attempts.unwrap_or(10.0),
        sensitive_attempts: limits.sensitive_attempts.unwrap_or(5.0),
        window_ms: limits.window_ms.unwrap_or(15.0 * 60_000.0),
        ip_attempts: limits.ip_attempts.unwrap_or(0.0),
        limiter: limits
            .limiter
            .unwrap_or_else(|| create_store_rate_limiter(store)),
    };
    let bounds: [(&str, f64, f64, f64); 4] = [
        ("attempts", resolved.attempts, 1.0, 100_000.0),
        (
            "sensitiveAttempts",
            resolved.sensitive_attempts,
            1.0,
            100_000.0,
        ),
        (
            "windowMs",
            resolved.window_ms,
            1_000.0,
            24.0 * 60.0 * 60_000.0,
        ),
        ("ipAttempts", resolved.ip_attempts, 0.0, 1_000_000.0),
    ];
    for (name, value, min, max) in bounds {
        if !js::is_safe_integer(value) || value < min || value > max {
            return Err(IamError::new(
                "INVALID_CONFIG",
                format!(
                    "rateLimits.{name} must be an integer between {} and {}",
                    js::number_to_string(min),
                    js::number_to_string(max)
                ),
            ));
        }
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input(key: &str, limit: f64, now: f64) -> ConsumeInput {
        ConsumeInput {
            key: key.to_owned(),
            tenant_id: "t".to_owned(),
            limit,
            window_ms: 1_000.0,
            now,
        }
    }

    #[tokio::test]
    async fn memory_limiter_counts_windows_and_bounds_keys() {
        let limiter = create_memory_rate_limiter(MemoryRateLimiterOptions {
            max_keys: Some(2.0),
        })
        .unwrap();
        assert!(limiter.consume(input("a", 2.0, 0.0)).await.unwrap());
        assert!(limiter.consume(input("a", 2.0, 1.0)).await.unwrap());
        assert!(!limiter.consume(input("a", 2.0, 2.0)).await.unwrap());
        assert!(limiter.consume(input("a", 2.0, 1_000.0)).await.unwrap());
        // At the cap the oldest window is dropped.
        assert!(limiter.consume(input("b", 1.0, 1_001.0)).await.unwrap());
        assert!(limiter.consume(input("c", 1.0, 1_002.0)).await.unwrap());
        assert!(limiter.consume(input("a", 1.0, 1_003.0)).await.unwrap());
        assert!(
            create_memory_rate_limiter(MemoryRateLimiterOptions {
                max_keys: Some(0.0)
            })
            .is_err()
        );
    }
}
