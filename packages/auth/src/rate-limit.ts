import { IamError, type IamStore } from '@better-iam/core';
import type { RateLimitOptions, RateLimiter, RateRecord } from './types.js';

export interface ResolvedRateLimits {
  attempts: number;
  sensitiveAttempts: number;
  windowMs: number;
  /** Per-client-IP attempts per window across flows; 0 disables the check. */
  ipAttempts: number;
  limiter: RateLimiter;
}

export interface MemoryRateLimiterOptions {
  /**
   * Counters kept at most (default 100,000). Expired counters are dropped first; at the cap with none expired, the
   * oldest window is dropped (its counter starts over), so a flood of fresh keys costs bounded memory and work.
   */
  maxKeys?: number;
}

/**
 * In-process limiter for single-instance deployments and tests. Counters are not shared between processes, and the
 * map is bounded by `maxKeys`.
 */
export function createMemoryRateLimiter(options: MemoryRateLimiterOptions = {}): RateLimiter {
  const maxKeys = options.maxKeys ?? 100_000;
  if (!Number.isSafeInteger(maxKeys) || maxKeys < 1)
    throw new IamError('INVALID_CONFIG', 'maxKeys must be a positive integer');
  // Keys are attacker-chosen (emails, addresses, challenge tokens). A counter is (re)inserted whenever its window
  // starts, so with one window length the map runs oldest window first: pruning walks from the front and stops at
  // the first live counter, doing work only for what it frees instead of scanning the whole map on every call.
  const counters = new Map<string, { count: number; resetAt: number }>();
  return {
    async consume({ key, limit, windowMs, now }) {
      for (const [id, entry] of counters) {
        if (entry.resetAt > now) break;
        counters.delete(id);
      }
      let entry = counters.get(key);
      if (!entry || entry.resetAt <= now) {
        counters.delete(key);
        while (counters.size >= maxKeys) counters.delete(counters.keys().next().value!);
        entry = { count: 0, resetAt: now + windowMs };
        counters.set(key, entry);
      }
      if (entry.count >= limit) return false;
      entry.count++;
      return true;
    },
    async reset({ key }) {
      counters.delete(key);
    },
  };
}

/** A store limiter sweeps expired counters at most this often, in transactions of at most `SWEEP_BATCH` deletions. */
const SWEEP_INTERVAL_MS = 60_000;
const SWEEP_BATCH = 200;

/** The default limiter: durable counters in the IAM database, committed independently so rejected credentials cannot roll back their attempt. */
export function createStoreRateLimiter(store: IamStore): RateLimiter {
  // Every distinct key (an email, an address, a made-up tenant, a challenge token) leaves a row, so expired rows
  // are deleted opportunistically: at most once a minute per limiter, after the triggering attempt was counted and
  // without delaying it, in short transactions of their own. A counter restarted meanwhile is re-read and kept.
  let nextSweep = -Infinity;
  let sweeping = false;
  const sweep = async (now: number) => {
    const expired = (await store.find<RateRecord>('authRateLimits')).filter(
      (record) => record.resetAt <= now,
    );
    for (let start = 0; start < expired.length; start += SWEEP_BATCH)
      await store.transaction(async (tx) => {
        for (const stale of expired.slice(start, start + SWEEP_BATCH)) {
          const current = await tx.get<RateRecord>('authRateLimits', stale.id);
          if (current && current.resetAt <= now) await tx.delete('authRateLimits', stale.id);
        }
      });
  };
  return {
    async consume({ key, tenantId, limit, windowMs, now }) {
      const permitted = await store.transaction(async (tx) => {
        const existing = await tx.get<RateRecord>('authRateLimits', key);
        const record: RateRecord =
          existing && existing.resetAt > now
            ? existing
            : { id: key, tenantId, count: 0, resetAt: now + windowMs };
        if (record.count >= limit) return false;
        record.count++;
        if (existing) await tx.put('authRateLimits', record);
        else await tx.insert('authRateLimits', record);
        return true;
      });
      if (!sweeping && now >= nextSweep) {
        sweeping = true;
        nextSweep = now + SWEEP_INTERVAL_MS;
        void sweep(now)
          .catch(() => {
            /* Housekeeping only: the next sweep (or the purge worker) retries. */
          })
          .finally(() => {
            sweeping = false;
          });
      }
      return permitted;
    },
    reset: ({ key }) =>
      store.transaction(async (tx) => {
        if (await tx.get('authRateLimits', key)) await tx.delete('authRateLimits', key);
      }),
  };
}

export function resolveRateLimits(
  options: RateLimitOptions | undefined,
  store: IamStore,
): ResolvedRateLimits {
  const limits = options ?? {};
  const resolved: ResolvedRateLimits = {
    attempts: limits.attempts ?? 10,
    sensitiveAttempts: limits.sensitiveAttempts ?? 5,
    windowMs: limits.windowMs ?? 15 * 60_000,
    ipAttempts: limits.ipAttempts ?? 0,
    limiter: limits.limiter ?? createStoreRateLimiter(store),
  };
  const bounds = [
    ['attempts', resolved.attempts, 1, 100_000],
    ['sensitiveAttempts', resolved.sensitiveAttempts, 1, 100_000],
    ['windowMs', resolved.windowMs, 1_000, 24 * 60 * 60_000],
    ['ipAttempts', resolved.ipAttempts, 0, 1_000_000],
  ] as const;
  for (const [name, value, min, max] of bounds) {
    if (!Number.isSafeInteger(value) || value < min || value > max)
      throw new IamError(
        'INVALID_CONFIG',
        `rateLimits.${name} must be an integer between ${min} and ${max}`,
      );
  }
  if (typeof resolved.limiter.consume !== 'function')
    throw new IamError('INVALID_CONFIG', 'rateLimits.limiter must implement consume()');
  return resolved;
}
