import { AsyncResource } from 'node:async_hooks';
import type { StoredRecord } from '@better-iam/core';
import type { ServerContext } from './context.js';

/**
 * Access usage tracking: which actions each identity was actually allowed to perform, and when last. Allowed
 * `authorize`/`authorizeMany` checks and allowed provisioning operations are counted in memory and written in
 * batches, so the hot path never touches storage.
 */
export interface AccessUsageOptions {
  /** How often buffered usage is written (default one minute, at least one second). */
  flushIntervalMs?: number;
  /** Buffered (identity, action) pairs that trigger an early write (default 10 000). */
  maxBuffered?: number;
}
/** One identity's use of one action in a tenant; the ID is `{tenantId}:{identityId}:{action}`. */
export interface AccessUsageRecord extends StoredRecord {
  identityId: string;
  action: string;
  firstUsedAt: number;
  lastUsedAt: number;
  /** Allowed checks counted since tracking began (approximate across concurrent instances). */
  count: number;
}
/** When a tenant's usage was first recorded; the ID is the tenant ID. */
export interface AccessUsageTracking extends StoredRecord {
  startedAt: number;
}
export interface UsageRecorder {
  readonly enabled: boolean;
  /** Counts one allowed use; a no-op when tracking is off. */
  record(tenantId: string, identityId: string, action: string): void;
  /** Writes everything buffered; concurrent calls share one write. */
  flush(): Promise<{ written: number }>;
  /** Stops the periodic writer (buffered usage stays until the next `flush`). */
  stop(): void;
}

interface Pending {
  tenantId: string;
  identityId: string;
  action: string;
  first: number;
  last: number;
  count: number;
}

export const usageRecordId = (tenantId: string, identityId: string, action: string) =>
  `${tenantId}:${identityId}:${action}`;

export function createUsageRecorder(ctx: ServerContext): UsageRecorder {
  const setting = ctx.options.accessUsage;
  const enabled = Boolean(setting);
  const options: AccessUsageOptions = typeof setting === 'object' ? setting : {};
  const interval = Math.max(1000, options.flushIntervalMs ?? 60_000);
  const maxBuffered = Math.max(1, options.maxBuffered ?? 10_000);
  // Keys are JSON arrays: identity and action strings may contain any separator.
  let buffer = new Map<string, Pending>();
  let timer: ReturnType<typeof setInterval> | undefined;
  let writing: Promise<{ written: number }> | undefined;

  async function write(batch: Map<string, Pending>): Promise<number> {
    if (!batch.size) return 0;
    await ctx.store.transaction(async (tx) => {
      const tenants = new Map<string, number>();
      for (const entry of batch.values()) {
        tenants.set(entry.tenantId, Math.min(tenants.get(entry.tenantId) ?? Infinity, entry.first));
        const id = usageRecordId(entry.tenantId, entry.identityId, entry.action);
        const existing = await tx.get<AccessUsageRecord>('accessUsage', id);
        if (existing)
          await tx.put<AccessUsageRecord>('accessUsage', {
            ...existing,
            firstUsedAt: Math.min(existing.firstUsedAt, entry.first),
            lastUsedAt: Math.max(existing.lastUsedAt, entry.last),
            count: existing.count + entry.count,
          });
        else
          await tx.insert<AccessUsageRecord>('accessUsage', {
            id,
            tenantId: entry.tenantId,
            identityId: entry.identityId,
            action: entry.action,
            firstUsedAt: entry.first,
            lastUsedAt: entry.last,
            count: entry.count,
          });
      }
      for (const [tenantId, startedAt] of tenants)
        if (!(await tx.get('accessUsageTracking', tenantId)))
          await tx.insert<AccessUsageTracking>('accessUsageTracking', {
            id: tenantId,
            tenantId,
            startedAt,
          });
    });
    return batch.size;
  }

  // `record` runs inside callers' transactions, and adapters find their transaction through async context. Timers
  // and early flushes are therefore created from the context captured here, at construction, never from `record`:
  // otherwise they would join (or find closed) the transaction that happened to record first.
  let scheduled = false;
  let lastFailure = 0;
  const background = AsyncResource.bind((delay: number) => {
    setTimeout(() => {
      scheduled = false;
      void recorder.flush().catch(() => {
        lastFailure = Date.now();
      });
    }, delay).unref?.();
  });
  if (enabled) {
    timer = setInterval(
      AsyncResource.bind(() => {
        if (buffer.size) void recorder.flush().catch(() => (lastFailure = Date.now()));
      }),
      interval,
    );
    timer.unref?.();
  }

  const recorder: UsageRecorder = {
    enabled,
    record(tenantId, identityId, action) {
      if (!enabled) return;
      const now = ctx.now();
      const key = JSON.stringify([tenantId, identityId, action]);
      const entry = buffer.get(key);
      if (entry) {
        entry.last = Math.max(entry.last, now);
        entry.count++;
      } else buffer.set(key, { tenantId, identityId, action, first: now, last: now, count: 1 });
      // One early write at a time, and none while storage keeps failing (the interval retries).
      if (
        buffer.size >= maxBuffered &&
        !scheduled &&
        !writing &&
        Date.now() - lastFailure >= interval
      ) {
        scheduled = true;
        background(0);
      }
    },
    async flush() {
      // One write at a time; a caller arriving mid-write waits and then writes what arrived since.
      while (writing) await writing.catch(() => undefined);
      const batch = buffer;
      buffer = new Map();
      writing = write(batch)
        .then((written) => ({ written }))
        .catch((error: unknown) => {
          // Keep the batch for the next attempt, merged with anything recorded meanwhile.
          for (const [key, entry] of batch) {
            const current = buffer.get(key);
            if (!current) buffer.set(key, entry);
            else {
              current.first = Math.min(current.first, entry.first);
              current.last = Math.max(current.last, entry.last);
              current.count += entry.count;
            }
          }
          throw error;
        })
        .finally(() => {
          writing = undefined;
        });
      return writing;
    },
    stop() {
      if (timer) clearInterval(timer);
      timer = undefined;
    },
  };
  return recorder;
}
