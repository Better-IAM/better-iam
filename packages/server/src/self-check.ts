import {
  IamError,
  findOrdered,
  schemaMigrations,
  type AuditChainHead,
  type AuditEvent,
  type StoreDescription,
  type StoredRecord,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { SecretRotationResult } from './secrets.js';

export type SelfCheckSeverity = 'error' | 'warning' | 'info';

/** One problem `selfCheck` found, with the operator's next step. */
export interface SelfCheckFinding {
  /** Stable identifier, for suppressing or alerting on one check. */
  check: string;
  severity: SelfCheckSeverity;
  message: string;
  fix: string;
  /** How many records the finding concerns, when it is about stored data (capped at `cap`). */
  count?: number;
}

export interface SelfCheckResult {
  /** No error findings. */
  ok: boolean;
  findings: SelfCheckFinding[];
  /** The adapter's own view, when it can describe itself. */
  storage: StoreDescription | null;
}

export interface SelfCheckOptions {
  /** Most records counted per backlog check (default 1000); larger backlogs report the cap. */
  cap?: number;
  /** The `deliveryRetentionMs` your sweep runs with (default 30 days), so its backlog is judged the same way. */
  deliveryRetentionMs?: number;
  /** The `graceMs` your sweep runs with (default 5 minutes). */
  graceMs?: number;
}

/** What `countDue` needs to judge the sweep backlog the way the scheduled sweep would. */
export interface DueOptions {
  cap: number;
  deliveryRetentionMs?: number;
  graceMs?: number;
  /** Count only records due for at least this long, so a sweep on schedule never shows a backlog. */
  overdueMs: number;
}

const MINUTE = 60_000;
const DAY = 86_400_000;
/** A sweep scheduled at least daily leaves nothing due for this long. */
const SWEEP_OVERDUE_MS = 2 * DAY;
const PLACEHOLDER = /change[-_ ]?me|replace[-_ ]?me|example|placeholder|^(?:secret|password)/i;

/**
 * Checks a running deployment for configuration and storage problems an operator should act on:
 * a schema behind this release, a platform never bootstrapped, a guessable secret, settings that
 * lose data (an in-memory database, SQLite durability that can corrupt, PostgreSQL asynchronous
 * commit), missing delivery transports, and scheduled jobs that are not running (records `sweep`
 * or `purge` would remove, stalled outbox and audit hook deliveries). It only reads.
 */
export function createSelfCheck(
  ctx: ServerContext,
  countDue: (options: DueOptions) => Promise<Record<string, number>>,
  sampleSecrets: (limit: number) => Promise<SecretRotationResult>,
) {
  return async function selfCheck(options: SelfCheckOptions = {}): Promise<SelfCheckResult> {
    const cap = options.cap ?? 1000;
    if (!Number.isSafeInteger(cap) || cap < 1 || cap > 100_000)
      throw new IamError('INVALID_INPUT', 'cap must be an integer between 1 and 100000');
    for (const [name, value, max] of [
      ['deliveryRetentionMs', options.deliveryRetentionMs, 3650 * DAY],
      ['graceMs', options.graceMs, DAY],
    ] as const)
      if (value !== undefined && (!Number.isSafeInteger(value) || value < 0 || value > max))
        throw new IamError('INVALID_INPUT', `${name} must be an integer between 0 and ${max}`);
    const { options: settings, store } = ctx;
    const findings: SelfCheckFinding[] = [];
    const add = (finding: SelfCheckFinding) => findings.push(finding);
    const now = ctx.now();

    // --- storage ---------------------------------------------------------------------------
    const storage = store.describe ? await store.describe() : null;
    if (storage) {
      const applied = new Set(storage.migrations.map((migration) => migration.name));
      const missing = schemaMigrations('sqlite')
        .map((migration) => migration.name)
        .filter((name) => !applied.has(name));
      if (storage.schemaVersion === null || missing.length)
        add({
          check: 'schema-behind',
          severity: 'error',
          message:
            storage.schemaVersion === null
              ? 'The database has no IAM schema'
              : `Schema migrations not applied: ${missing.join(', ')}`,
          fix: 'Run `better-iam migrate` (or `iam.initialize()`) before serving traffic',
        });
      const setting = storage.settings;
      if (setting.inMemory === true || setting.location === 'memory')
        add({
          check: 'in-memory-database',
          severity: 'warning',
          message: 'The database lives in memory; everything is lost when the process exits',
          fix: 'Configure a file or server database for anything but tests',
        });
      if (
        storage.adapter === 'sqlite' &&
        setting.inMemory === false &&
        setting.journalMode === 'delete' &&
        (setting.synchronous === 'normal' || setting.synchronous === 'off')
      )
        add({
          check: 'sqlite-durability',
          severity: 'error',
          message: `SQLite runs a rollback journal with synchronous=${setting.synchronous}, which a power failure can corrupt`,
          fix: "Use `durability: 'full'`, or WAL mode (the default journalMode)",
        });
      if (setting.synchronousCommit === 'off')
        add({
          check: 'postgres-async-commit',
          severity: 'warning',
          message:
            'PostgreSQL synchronous_commit is off: a crash can lose recently committed changes',
          fix: 'Set synchronous_commit to on (or remote_apply with replicas) for the IAM database',
        });
    } else
      add({
        check: 'storage-undescribed',
        severity: 'info',
        message: 'The storage adapter cannot describe its schema, so migrations were not checked',
        fix: 'Implement `IamStore.describe()` in the adapter',
      });

    // --- platform ----------------------------------------------------------------------------
    if (!storage || storage.schemaVersion !== null) {
      const roots = await store.find('tenants', { parentId: null }, { limit: 2 });
      if (!roots.length)
        add({
          check: 'not-bootstrapped',
          severity: 'error',
          message: 'No root tenant exists yet',
          fix: 'Run `better-iam bootstrap` with BETTER_IAM_ROOT_EMAIL and BETTER_IAM_ROOT_PASSWORD',
        });
    }
    const secret = settings.secret;
    // Random hex, base64, or UUID secrets of the required length use far more than 8 characters.
    if (new Set(secret).size < 8 || PLACEHOLDER.test(secret))
      add({
        check: 'weak-secret',
        severity: 'warning',
        message: 'The deployment secret looks like a placeholder or has little variety',
        fix: 'Use a random value, for example `openssl rand -base64 48`, kept in a secret store',
      });
    const metricsToken =
      typeof settings.observability?.metrics === 'object'
        ? settings.observability.metrics.bearerToken
        : undefined;
    if (typeof metricsToken === 'string' && metricsToken.length < 24)
      add({
        check: 'weak-metrics-token',
        severity: 'warning',
        message: 'The metrics bearer token is shorter than 24 characters',
        fix: 'Use a random token of at least 24 characters',
      });
    if (!settings.authentication?.sendEmail)
      add({
        check: 'no-email-transport',
        severity: 'warning',
        message:
          'No email transport: invitations, password resets, and verification emails cannot be sent',
        fix: 'Configure `authentication.sendEmail`',
      });

    if (storage && storage.schemaVersion === null)
      return { ok: !findings.some((finding) => finding.severity === 'error'), findings, storage };

    // --- sealed values ----------------------------------------------------------------------
    // A secret changed without listing the old one in `previousSecrets` silently breaks every
    // authenticator app and webhook signature; a sample of the stored values shows it.
    const sealed = await sampleSecrets(cap);
    const total = (counts: Record<string, number>) =>
      Object.values(counts).reduce((sum, count) => sum + count, 0);
    const unreadable = total(sealed.unreadable);
    if (unreadable)
      add({
        check: 'unreadable-secrets',
        severity: 'error',
        message: `${unreadable} stored secret value(s) open with no configured secret (${Object.entries(
          sealed.unreadable,
        )
          .map(([collection, count]) => `${collection}: ${count}`)
          .join(', ')}); the deployment secret was probably changed without previousSecrets`,
        fix: 'Put the old secret in `previousSecrets`, run `better-iam rotate-secrets`, then remove it',
        count: unreadable,
      });
    const pending = total(sealed.resealed);
    if (pending)
      add({
        check: 'secret-rotation-pending',
        severity: 'warning',
        message: `${pending} stored secret value(s) are still sealed with a previous secret`,
        fix: 'Run `better-iam rotate-secrets` (or `iam.rotateSecrets()`) until it reports `done: true`, then remove `previousSecrets` a day later',
        count: pending,
      });
    else if (settings.previousSecrets?.length)
      add(
        sealed.complete
          ? {
              check: 'previous-secrets-configured',
              severity: 'info',
              message: 'previousSecrets is set, and no stored value needs it any more',
              fix: 'A day after the rotation (pending links and assertions), remove `previousSecrets` and give downstream verifiers only `iam.assertionKey()`',
            }
          : {
              // The sample covers the first records only, which a rotation also re-seals first.
              check: 'secret-rotation-unverified',
              severity: 'warning',
              message: `previousSecrets is set; no value in a sample of ${cap} per collection needs it, but not every record was examined`,
              fix: 'Run `better-iam rotate-secrets --dry-run` and remove `previousSecrets` only when it reports `done: true`',
            },
      );

    // --- scheduled jobs ----------------------------------------------------------------------
    // Judged by age, with the sweep's own settings: a sweep that runs at least daily leaves
    // nothing that has been due for two days, however busy the deployment is.
    const due = await countDue({
      cap,
      deliveryRetentionMs: options.deliveryRetentionMs,
      graceMs: options.graceMs,
      overdueMs: SWEEP_OVERDUE_MS,
    });
    const backlog = Math.min(
      cap,
      Object.values(due).reduce((sum, count) => sum + count, 0),
    );
    if (backlog)
      add({
        check: 'sweep-backlog',
        severity: 'warning',
        message: `${backlog >= cap ? `${cap}+` : backlog} record(s) have been due for the retention sweep for more than two days (${Object.entries(
          due,
        )
          .filter(([, count]) => count)
          .map(([collection, count]) => `${collection}: ${count}`)
          .join(', ')})`,
        fix: 'Schedule `better-iam sweep` (or `iam.sweepExpired()`) hourly or daily, with a `limit` that keeps up',
        count: backlog,
      });
    const lapsed = (
      await Promise.all(
        ['bindings', 'groupMembers', 'authChallenges'].map((collection) =>
          findOrdered(store, collection, {}, { field: 'expiresAt', to: now - DAY, limit: 1 }),
        ),
      )
    ).flat().length;
    if (lapsed)
      add({
        check: 'purge-not-running',
        severity: 'warning',
        message: 'Expired bindings, memberships, or challenges are more than a day old',
        fix: 'Schedule `better-iam purge` (or `iam.purgeDeleted()`) at least daily',
      });
    const stalled = (
      await findOrdered(
        store,
        'outbox',
        { deliveredAt: undefined, failedAt: undefined },
        { field: 'createdAt', to: now - 15 * MINUTE, limit: cap },
      )
    ).length;
    if (stalled)
      add({
        check: 'outbox-stalled',
        severity: 'warning',
        message: `${stalled >= cap ? `${cap}+` : stalled} outgoing message(s) have waited more than 15 minutes`,
        fix: 'Schedule `better-iam outbox` (or `iam.auth.dispatchOutbox()`) every minute, and check the delivery callbacks',
        count: stalled,
      });
    const abandoned = (
      await findOrdered(store, 'outbox', {}, { field: 'failedAt', from: now - DAY, limit: cap })
    ).length;
    if (abandoned)
      add({
        check: 'outbox-abandoned',
        severity: 'warning',
        message: `${abandoned} outgoing message(s) were abandoned in the last day after repeated failures`,
        fix: 'Check the email, SMS, and webhook delivery callbacks and their `lastError`',
        count: abandoned,
      });
    const hooks = await store.find<StoredRecord & { event?: { timestamp?: unknown } }>(
      'auditHooks',
      { delivered: false },
      { limit: cap },
    );
    const waiting = hooks.filter(
      (row) => typeof row.event?.timestamp === 'number' && row.event.timestamp <= now - 15 * MINUTE,
    ).length;
    if (waiting)
      add({
        check: 'audit-hooks-stalled',
        severity: 'warning',
        message: `${waiting} audit event(s) have waited more than 15 minutes for plugins, subscribers, or onEvent`,
        fix: 'Call `iam.dispatchAuditHooks()` every minute in the application process that registers event subscribers (the CLI `outbox` command serves only plugins and `events.onEvent`)',
        count: waiting,
      });
    if (settings.auditArchive) {
      // A tenant whose oldest unarchived event is over a day old: the archive job is not keeping up.
      // Every tenant is examined (a page of chain heads at a time); counting stops at `cap`.
      let behind = 0;
      let after: string | undefined;
      while (behind < cap) {
        const heads = await store.find<AuditChainHead>(
          'auditChains',
          {},
          { limit: 500, ...(after === undefined ? {} : { after }) },
        );
        for (const head of heads) {
          const cursor = await store.get<StoredRecord & { sequence: number }>(
            'auditArchiveCursors',
            head.id,
          );
          if (head.sequence <= (cursor?.sequence ?? 0)) continue;
          const [oldest] = await findOrdered<AuditEvent>(
            store,
            'audit',
            { tenantId: head.id },
            { field: 'sequence', from: (cursor?.sequence ?? 0) + 1, limit: 1 },
          );
          if (oldest && oldest.timestamp <= now - DAY) behind++;
          if (behind >= cap) break;
        }
        if (heads.length < 500) break;
        after = heads.at(-1)!.id;
      }
      if (behind)
        add({
          check: 'audit-archive-behind',
          severity: 'warning',
          message: `${behind >= cap ? `${cap}+` : behind} tenant(s) have audit events older than a day that are not archived`,
          fix: 'Schedule `better-iam audit-archive` (or `iam.archiveAudit()`) at least hourly, and check the sink for failures',
          count: behind,
        });
    }
    return { ok: !findings.some((finding) => finding.severity === 'error'), findings, storage };
  };
}
