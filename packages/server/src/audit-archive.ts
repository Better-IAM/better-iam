import { randomUUID } from 'node:crypto';
import { link, mkdir, open, readFile, rm } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import {
  IamError,
  auditGenesis,
  findOrdered,
  verifyAuditChain,
  type AuditChainHead,
  type AuditEvent,
  type StoredRecord,
} from '@better-iam/core';
import type { ServerContext } from './context.js';

/** A contiguous, verified run of one tenant's audit chain, handed to the archive in order. */
export interface AuditArchiveBatch {
  tenantId: string;
  fromSequence: number;
  toSequence: number;
  /** The hash the first event chains from: the previous batch's `lastHash`, or the chain genesis. */
  previousHash: string;
  lastHash: string;
  /** Events in chain order. */
  events: AuditEvent[];
}

export interface AuditArchiveOptions {
  /**
   * Stores one batch durably (object storage, a SIEM, a write-once bucket) and resolves only when
   * it is safe. Batches arrive in chain order per tenant. After a crash a batch can be written
   * again, possibly covering a longer range, so key it by `tenantId`, `fromSequence`, and
   * `toSequence`, and never replace a stored batch with different content: reject that as a
   * conflict (throw). Readers take events by `sequence`.
   */
  write(batch: AuditArchiveBatch): Promise<void>;
  /** Events per batch (default 1000, 1-10000). */
  batchSize?: number;
  /**
   * How long one run may hold a tenant before another may take it over (default 10 minutes,
   * 1 minute to 1 hour). Keep it well above the slowest `write`.
   */
  leaseMs?: number;
}

export interface AuditArchiveResult {
  /** Events archived per tenant in this run. */
  archived: Record<string, number>;
  batches: number;
  /** Tenants whose chain did not verify or whose sink failed; their cursor did not move. */
  failed: { tenantId: string; code: string; message: string }[];
  /** Sequences deleted before they were archived (pruned without an archive configured). */
  gaps: { tenantId: string; fromSequence: number; toSequence: number }[];
  /** Tenants another run is archiving right now (it holds their lease); they were skipped. */
  busy: string[];
  /** The run stopped at `limit`; run it again to continue. */
  truncated: boolean;
}

/** How far a tenant's chain has been archived, and which run is archiving it. */
export interface AuditArchiveCursor extends StoredRecord {
  sequence: number;
  hash: string;
  updatedAt: number;
  leaseId?: string;
  leaseUntil?: number;
}

const CURSORS = 'auditArchiveCursors';

/**
 * Continuous audit archiving: copies each tenant's hash-chained audit events, verified and in
 * order, to the configured sink, and records how far each chain has been archived. One run at a
 * time holds a tenant (a lease on its cursor), so overlapping runs never race each other's
 * batches. `pruneAudit` never deletes past the cursor, so the database only ever drops events the
 * archive already holds.
 */
export function createAuditArchive(ctx: ServerContext) {
  const sink = ctx.options.auditArchive;
  const batchSize = sink?.batchSize ?? 1000;
  const leaseMs = sink?.leaseMs ?? 10 * 60_000;
  if (sink && (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 10_000))
    throw new IamError('INVALID_CONFIG', 'auditArchive.batchSize must be between 1 and 10000');
  if (sink && (!Number.isSafeInteger(leaseMs) || leaseMs < 60_000 || leaseMs > 3_600_000))
    throw new IamError('INVALID_CONFIG', 'auditArchive.leaseMs must be between 60000 and 3600000');

  /** Takes or renews this run's lease on a tenant; undefined when another live run holds it. */
  const claim = (tenantId: string, leaseId: string) =>
    ctx.store.transaction(async (tx) => {
      const current = await tx.get<AuditArchiveCursor>(CURSORS, tenantId);
      const now = Date.now();
      if (current?.leaseId && current.leaseId !== leaseId && (current.leaseUntil ?? 0) > now)
        return undefined;
      const next: AuditArchiveCursor = {
        id: tenantId,
        tenantId,
        sequence: current?.sequence ?? 0,
        hash: current?.hash ?? auditGenesis,
        updatedAt: current?.updatedAt ?? ctx.now(),
        leaseId,
        leaseUntil: now + leaseMs,
      };
      if (current) await tx.put(CURSORS, next);
      else await tx.insert(CURSORS, next);
      return next;
    });
  const release = (tenantId: string, leaseId: string) =>
    ctx.store.transaction(async (tx) => {
      const current = await tx.get<AuditArchiveCursor>(CURSORS, tenantId);
      if (current?.leaseId === leaseId) {
        const { leaseId: _leaseId, leaseUntil: _leaseUntil, ...rest } = current;
        await tx.put(CURSORS, rest);
      }
    });

  async function archiveTenant(
    tenantId: string,
    budget: () => number,
    result: AuditArchiveResult,
  ): Promise<boolean> {
    const leaseId = randomUUID();
    try {
      for (;;) {
        const size = Math.min(batchSize, budget());
        if (size === 0) return false;
        // Renewed before every batch, so a run that holds the lease never loses it mid-batch
        // unless one write outlasts the whole lease.
        const cursor = await claim(tenantId, leaseId);
        if (!cursor) {
          if (!result.busy.includes(tenantId)) result.busy.push(tenantId);
          return true;
        }
        const after = cursor.sequence;
        const events = await findOrdered<AuditEvent>(
          ctx.store,
          'audit',
          { tenantId },
          { field: 'sequence', from: after + 1, limit: size },
        );
        if (!events.length) return true;
        const first = events[0]!;
        const contiguous = first.sequence === after + 1;
        if (!contiguous)
          result.gaps.push({ tenantId, fromSequence: after + 1, toSequence: first.sequence! - 1 });
        const previousHash = contiguous ? cursor.hash : (first.previousHash ?? auditGenesis);
        const verification = await verifyAuditChain(events, { previousHash });
        if (!verification.valid || verification.checked !== events.length) {
          result.failed.push({
            tenantId,
            code: 'AUDIT_CHAIN_BROKEN',
            message: `The chain does not verify at sequence ${verification.failure?.sequence ?? first.sequence}`,
          });
          return true;
        }
        const batch: AuditArchiveBatch = {
          tenantId,
          fromSequence: first.sequence!,
          toSequence: verification.last!,
          previousHash,
          lastHash: verification.lastHash!,
          events,
        };
        try {
          // Outside any transaction: the sink is an external side effect.
          await sink!.write(batch);
        } catch (error) {
          result.failed.push({
            tenantId,
            code:
              error instanceof IamError && error.code === 'ARCHIVE_CONFLICT'
                ? 'ARCHIVE_CONFLICT'
                : 'ARCHIVE_WRITE_FAILED',
            message: error instanceof Error ? error.message.slice(0, 256) : String(error),
          });
          return true;
        }
        const advanced = await ctx.store.transaction(async (tx) => {
          const current = await tx.get<AuditArchiveCursor>(CURSORS, tenantId);
          // Only the lease holder moves the cursor, and only from where it read.
          if (current?.leaseId !== leaseId || current.sequence !== after) return false;
          await tx.put(CURSORS, {
            ...current,
            sequence: batch.toSequence,
            hash: batch.lastHash,
            updatedAt: ctx.now(),
          });
          return true;
        });
        if (!advanced) {
          if (!result.busy.includes(tenantId)) result.busy.push(tenantId);
          return true;
        }
        result.archived[tenantId] = (result.archived[tenantId] ?? 0) + events.length;
        result.batches++;
        if (events.length < size) return true;
      }
    } finally {
      await release(tenantId, leaseId);
    }
  }

  return {
    /**
     * Archives every tenant's new audit events (or one `tenantId`'s), at most `limit` events per
     * run (default 100000). A scheduler job; run it before `pruneAudit`.
     */
    async archiveAudit(
      input: { tenantId?: string; limit?: number } = {},
    ): Promise<AuditArchiveResult> {
      if (!sink)
        throw new IamError(
          'NO_AUDIT_ARCHIVE',
          'Configure auditArchive (for example createJsonlAuditArchive) to archive audit events',
          501,
        );
      const limit = input.limit ?? 100_000;
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 10_000_000)
        throw new IamError('INVALID_INPUT', 'limit must be between 1 and 10000000');
      const result: AuditArchiveResult = {
        archived: {},
        batches: 0,
        failed: [],
        gaps: [],
        busy: [],
        truncated: false,
      };
      const budget = () => limit - Object.values(result.archived).reduce((a, b) => a + b, 0);
      const tenants =
        input.tenantId !== undefined
          ? [input.tenantId]
          : (await ctx.store.find<AuditChainHead>('auditChains')).map((head) => head.id);
      for (const tenantId of tenants)
        if (!(await archiveTenant(tenantId, budget, result))) {
          result.truncated = true;
          break;
        }
      return result;
    },
    /** The archive position of one tenant's chain, or undefined when nothing was archived yet. */
    archiveCursor: (tenantId: string) => ctx.store.get<AuditArchiveCursor>(CURSORS, tenantId),
  };
}

/** Flushes a directory entry (a created or renamed file) to disk; Windows cannot open directories for that. */
async function syncDirectory(path: string): Promise<void> {
  if (process.platform === 'win32') return;
  const handle = await open(path, 'r');
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

/**
 * A file sink for `auditArchive`: one JSON Lines file per batch at
 * `{directory}/{tenantId}/{fromSequence}-{toSequence}.jsonl` (sequences zero-padded, so files sort
 * in chain order). Files are write-once: each is written under a unique temporary name, flushed,
 * and published with a hard link that never replaces an existing file. Writing the same batch
 * again is accepted; a different batch under an existing name is refused (`ARCHIVE_CONFLICT`), so
 * a restored or tampered database can never overwrite archived events. After a crash, files can
 * overlap; read events by `sequence`.
 */
export function createJsonlAuditArchive(options: { directory: string }): AuditArchiveOptions {
  const root = resolve(options.directory);
  const pad = (value: number) => String(value).padStart(12, '0');
  return {
    async write(batch) {
      if (!/^[\w.-]{1,200}$/.test(batch.tenantId) || batch.tenantId.startsWith('.'))
        throw new IamError('INVALID_INPUT', 'Tenant id is not a safe file name');
      const folder = join(root, batch.tenantId);
      // A newly created tenant folder must itself be durable before its files are.
      if (await mkdir(folder, { recursive: true })) await syncDirectory(root);
      const name = `${pad(batch.fromSequence)}-${pad(batch.toSequence)}.jsonl`;
      const target = join(folder, name);
      const content = batch.events.map((event) => JSON.stringify(event)).join('\n') + '\n';
      const temporary = join(folder, `.${name}.${randomUUID()}.tmp`);
      const file = await open(temporary, 'wx', 0o600);
      try {
        await file.writeFile(content);
        await file.sync();
      } finally {
        await file.close();
      }
      try {
        await link(temporary, target);
      } catch (error) {
        if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error;
        // Already archived: fine when identical, a conflict otherwise; the stored file stays.
        if ((await readFile(target, 'utf8')) !== content)
          throw new IamError(
            'ARCHIVE_CONFLICT',
            `${batch.tenantId}/${name} already holds different events`,
            409,
          );
      } finally {
        await rm(temporary, { force: true });
      }
      await syncDirectory(folder);
    },
  };
}
