import { IamError, findOrdered, type IamStore, type StoredRecord } from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { DueOptions } from './self-check.js';

const DAY = 86_400_000;
/**
 * Session kinds whose expired records nothing reads: user sessions, role sessions (classic and web identity), session
 * tokens, and delegated agent sessions. API keys stay: they are listed as expired and can be renewed.
 */
const SWEPT_SESSION_KINDS: ReadonlySet<unknown> = new Set([
  'user',
  'role',
  'session-token',
  'delegated',
]);
/**
 * Expired OAuth Grant rows stay this long: an IAM session (at most 30 days) bound to the grant may
 * end later, and back-channel logout (`logoutEndedSessions`) finds the client through the row.
 */
const GRANT_RETENTION_MS = 31 * DAY;

export interface SweepOptions {
  /**
   * Epoch milliseconds to treat as now, for tests and backfills. By default each collection is
   * judged by the clock its writer uses: the authentication clock for sessions, devices,
   * relationships, the outbox, and audit hooks, and the wall clock for OAuth, SAML, and SSF records.
   */
  now?: number;
  /** Records read per transaction (default 500, 1-5000). Short transactions keep the write lock brief. */
  batchSize?: number;
  /** The most records one run deletes (default 10000, at most 1000000); see `truncated`. */
  limit?: number;
  /**
   * How long delivered and abandoned deliveries stay (outbox email, SMS, and webhook history, failed
   * Shared Signals deliveries): default 30 days, 0-3650 days. Pending deliveries are never swept.
   */
  deliveryRetentionMs?: number;
  /** A margin past expiry before a record is deleted, against clock skew between instances (default 5 minutes, at most 1 day). */
  graceMs?: number;
}

export interface SweepResult {
  /** Records deleted per collection; collections with nothing to delete are omitted. */
  deleted: Record<string, number>;
  total: number;
  /** The run stopped at `limit` before finishing; more records may be due, so run it again. */
  truncated: boolean;
}

interface SweepTarget {
  collection: string;
  /** Equality filter; used only for legacy records that lack the indexed field. */
  filter?: Record<string, unknown>;
  /** The numeric field the collection-wide expiry indexes order by; absent for flag-only targets. */
  field?: string;
  /** The newest field value that is due. */
  cutoff?: number;
  /** Due records that must stay anyway; the walk steps over them instead of reading them again. */
  keep?: (record: StoredRecord) => boolean;
}

function bounded(
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
  name: string,
) {
  const resolved = value ?? fallback;
  if (!Number.isSafeInteger(resolved) || resolved < min || resolved > max)
    throw new IamError('INVALID_INPUT', `${name} must be an integer between ${min} and ${max}`);
  return resolved;
}

/**
 * Deletes records the rest of the system already treats as dead, so storage stops growing with
 * traffic. It never removes anything a person or report can still use:
 *
 * - user sessions, role sessions, and session tokens past their absolute expiry (API keys and any
 *   other kind stay), trusted devices past expiry, and relationship tuples past expiry;
 * - redeemed web-identity tokens (`webIdentityReplays`) past the token's expiry plus the provider's
 *   clock tolerance, when the token could no longer be presented anyway;
 * - OAuth artifacts (codes, tokens, replay records; grants 31 days after expiry) and login states
 *   past expiry, and SAML request, relay-state, and assertion-replay records past expiry;
 * - delivered or abandoned outbox messages and abandoned Shared Signals deliveries older than the
 *   delivery retention, and audit hook rows once dispatched (the audit log keeps the events).
 *
 * `purgeDeleted` already removes expired challenges, rate-limit windows, network blocks, bindings,
 * memberships, and activations; invitations, access requests, usage records, and SCIM connections
 * are history or can be renewed, so neither function deletes them by age.
 */
/** The sweep's targets for one run; also what `countDue` counts. */
function sweepTargets(
  ctx: ServerContext,
  options: { now?: number; retention: number; grace: number },
): SweepTarget[] {
  const { retention, grace } = options;
  const appNow = options.now ?? ctx.now();
  const wallNow = options.now ?? Date.now();
  const expired = (collection: string, now: number, keep?: SweepTarget['keep']): SweepTarget => ({
    collection,
    field: 'expiresAt',
    cutoff: now - grace,
    keep,
  });
  return [
    expired('sessions', appNow, (record) => !SWEPT_SESSION_KINDS.has(record.kind)),
    expired('authDevices', appNow),
    expired('relationships', appNow),
    // Written on the authentication clock (the exchange verifies tokens against ctx.now()).
    expired('webIdentityReplays', appNow),
    expired(
      'oauthArtifacts',
      wallNow,
      (record) =>
        record.model === 'Grant' && (record.expiresAt as number) > wallNow - GRANT_RETENTION_MS,
    ),
    expired('oauthLoginStates', wallNow),
    expired('samlRequests', wallNow),
    expired('samlRelays', wallNow),
    expired('samlAssertions', wallNow),
    // Inference metering (inference.ts): usage records past `inference.usageRetentionDays`, budget counters 35 days
    // after their window, and unredeemed gateway tickets.
    expired('inferenceUsage', appNow),
    expired('inferenceCounters', appNow),
    expired('inferenceTickets', appNow),
    // Responses API ownership records, kept as long as usage records.
    expired('inferenceResponses', appNow),
    // Agent confirmation requests past their decision window or approval validity (delegations.ts).
    expired('delegationConfirmations', appNow),
    // Issued delegation tokens past their expiry (delegation-tokens.ts).
    expired('delegationTokens', appNow),
    // Agent directory entries whose attestation has expired (api/agents.ts).
    expired('agentCards', appNow),
    // Team memberships past their end (teams.ts); the backing group's copy lapsed with them. Join requests are history.
    expired('teamMembers', appNow),
    // Vault access records past `vault.accessRetentionDays` (vault.ts); leases are ended by `iam.vault.expireLeases`.
    expired('vaultAccess', appNow),
    // Quota window counters a day after their window, and idle throttle buckets once full again (quotas.ts).
    expired('quotaCounters', appNow),
    // Data-subject request exports past their download window (api/privacy.ts); the request keeps its record.
    expired('privacyExports', appNow),
    // Finished workflow runs 180 days after they ended (api/workflows.ts); active runs carry no expiry.
    expired('workflowRuns', appNow),
    // Compliance results and runs 400 days after their evaluation (api/compliance.ts).
    expired('complianceResults', appNow),
    expired('complianceRuns', appNow),
    // Compliance exceptions (revoked ones too) 400 days after they expired, so evidence packs keep their history.
    expired(
      'complianceExceptions',
      appNow,
      (record) => (record.expiresAt as number) > appNow - 400 * 86_400_000,
    ),
    // App assignments past their end (api/applications.ts).
    expired('appAssignments', appNow),
    // SSH certificate records `ssh.recordRetentionDays` after the certificate expired (ssh.ts).
    expired('sshCertificates', appNow),
    // Verifiable credential records past their retention, used or lapsed wallet offers, and proof nonces (vc.ts).
    expired('vcIssued', appNow),
    expired('vcOffers', appNow),
    expired('vcNonces', appNow),
    // Device enrollment codes past their expiry, used or not (devices.ts); the audit trail keeps their use.
    expired('deviceEnrollments', appNow),
    // Received Shared Signals events 90 days after receipt (signal-receiver.ts); the audit trail keeps them.
    expired('signalEvents', appNow),
    { collection: 'outbox', field: 'deliveredAt', cutoff: appNow - retention },
    { collection: 'outbox', field: 'failedAt', cutoff: appNow - retention },
    { collection: 'ssfDeliveries', field: 'failedAt', cutoff: wallNow - retention },
    { collection: 'auditHooks', field: 'deliveredAt', cutoff: appNow - grace },
    // Rows written before these timestamps existed: not indexed, but a shrinking set.
    {
      collection: 'ssfDeliveries',
      filter: { status: 'failed', failedAt: undefined },
      field: 'createdAt',
      cutoff: wallNow - retention,
    },
    { collection: 'auditHooks', filter: { delivered: true, deliveredAt: undefined } },
  ];
}

/**
 * Walks one target's due records oldest first, a batch at a time. `act` receives each batch
 * (inside a transaction when deleting) and returns the records it left in place; the walk steps
 * over those by moving its lower bound (`from`) and skipping the ones at the bound, so nothing is
 * read twice. Stops when the target is exhausted or `act` returns `stop`.
 */
async function walk(
  store: IamStore,
  target: SweepTarget,
  batchSize: () => number,
  act: (
    store: IamStore,
    records: StoredRecord[],
  ) => Promise<{ survivors: StoredRecord[]; stop?: boolean }>,
  transactional: boolean,
): Promise<boolean> {
  let from: number | undefined;
  let skip = 0;
  for (;;) {
    const size = batchSize();
    if (size === 0) return false;
    const step = async (reader: IamStore) => {
      const read: StoredRecord[] =
        target.field === undefined
          ? await reader.find(target.collection, target.filter ?? {}, {
              offset: skip,
              limit: size,
            })
          : await findOrdered(reader, target.collection, target.filter ?? {}, {
              field: target.field,
              ...(from === undefined ? {} : { from }),
              to: target.cutoff,
              offset: skip,
              limit: size,
            });
      return { read, ...(await act(reader, read)) };
    };
    // Deleting: each batch reads and deletes in one short transaction, so a record renewed
    // between batches is judged again on its current state.
    const batch = transactional ? await store.transaction(step) : await step(store);
    if (batch.read.length < size) return true;
    if (batch.stop) return false;
    if (!target.field) {
      skip += batch.survivors.length;
      continue;
    }
    const field = target.field;
    const last = batch.read.at(-1)![field];
    const atLast = batch.survivors.filter((record) => record[field] === last).length;
    if (from === last) skip += atLast;
    else {
      from = last as number;
      skip = atLast;
    }
  }
}

export function createRetention(ctx: ServerContext) {
  return {
    async sweepExpired(options: SweepOptions = {}): Promise<SweepResult> {
      if (options.now !== undefined && !Number.isFinite(options.now))
        throw new IamError('INVALID_INPUT', 'now must be a finite number of milliseconds');
      const batchSize = bounded(options.batchSize, 500, 1, 5000, 'batchSize');
      let remaining = bounded(options.limit, 10_000, 1, 1_000_000, 'limit');
      const retention = bounded(
        options.deliveryRetentionMs,
        30 * DAY,
        0,
        3650 * DAY,
        'deliveryRetentionMs',
      );
      const grace = bounded(options.graceMs, 5 * 60_000, 0, DAY, 'graceMs');
      const result: SweepResult = { deleted: {}, total: 0, truncated: false };
      for (const target of sweepTargets(ctx, { now: options.now, retention, grace })) {
        const finished = await walk(
          ctx.store,
          target,
          () => Math.min(batchSize, remaining),
          async (tx, records) => {
            const survivors: StoredRecord[] = [];
            for (const record of records)
              if (target.keep?.(record)) survivors.push(record);
              else await tx.delete(target.collection, record.id);
            const deleted = records.length - survivors.length;
            if (deleted) {
              result.deleted[target.collection] =
                (result.deleted[target.collection] ?? 0) + deleted;
              result.total += deleted;
              remaining -= deleted;
            }
            return { survivors };
          },
          true,
        );
        if (!finished) {
          result.truncated = true;
          break;
        }
      }
      return result;
    },

    /**
     * Records a sweep with these settings would delete that have been due for at least
     * `overdueMs`, per collection, counting at most `cap` per collection. Reads only; `selfCheck`
     * uses it to spot a sweep that is not running or not keeping up.
     */
    async countDue(options: DueOptions): Promise<Record<string, number>> {
      const { cap } = options;
      const retention = bounded(
        options.deliveryRetentionMs,
        30 * DAY,
        0,
        3650 * DAY,
        'deliveryRetentionMs',
      );
      const grace = bounded(options.graceMs, 5 * 60_000, 0, DAY, 'graceMs');
      const counts: Record<string, number> = {};
      for (const target of sweepTargets(ctx, { retention, grace })) {
        if (target.cutoff !== undefined) target.cutoff -= options.overdueMs;
        const seen = () => counts[target.collection] ?? 0;
        await walk(
          ctx.store,
          target,
          () => Math.min(500, cap - seen() + 1),
          async (_store, records) => {
            counts[target.collection] =
              seen() + records.filter((record) => !target.keep?.(record)).length;
            return { survivors: records, stop: seen() >= cap };
          },
          false,
        );
        counts[target.collection] = Math.min(seen(), cap);
      }
      return counts;
    },
  };
}
