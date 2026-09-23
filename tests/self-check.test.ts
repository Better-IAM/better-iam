import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore, StoredRecord } from '@better-iam/core';
import { betterIam, type SelfCheckResult } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

const day = 86_400_000;
const minute = 60_000;
const secret = 'self-check-test-secret-with-at-least-32-characters';
const work = resolve('work');
const created: string[] = [];
const stores: IamStore[] = [];
afterEach(async () => {
  await closeFixtures();
  for (const store of stores.splice(0)) await store.close();
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});
async function directory() {
  await mkdir(work, { recursive: true });
  const folder = await mkdtemp(join(work, 'self-check-test-'));
  created.push(folder);
  return folder;
}
const checks = (result: SelfCheckResult) =>
  Object.fromEntries(result.findings.map((finding) => [finding.check, finding.severity]));
async function seed(store: IamStore, collection: string, records: Record<string, unknown>[]) {
  await store.transaction(async (tx) => {
    for (const record of records)
      await tx.insert(collection, { tenantId: 't', ...record } as StoredRecord);
  });
}

describe('deployment self-check', () => {
  it('reports a database without the IAM schema, and nothing it cannot judge yet', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    const iam = betterIam({ database, secret, baseURL: 'http://localhost:3000' });
    const result = await iam.selfCheck();
    expect(result.ok).toBe(false);
    expect(checks(result)).toEqual({
      'schema-behind': 'error',
      'in-memory-database': 'warning',
      'no-email-transport': 'warning',
    });
    expect(result.storage).toMatchObject({ adapter: 'sqlite', schemaVersion: null });
    await iam.initialize();
    expect(checks(await iam.selfCheck())).toEqual({
      'not-bootstrapped': 'error',
      'in-memory-database': 'warning',
      'no-email-transport': 'warning',
    });
  });

  it('passes a healthy deployment and notices jobs that are not running', async () => {
    const f = await organizationFixture();
    const healthy = await f.iam.selfCheck();
    expect(healthy.ok).toBe(true);
    expect(checks(healthy)).toEqual({ 'in-memory-database': 'warning' });

    const now = f.now();
    // Due for three days: a sweep that runs at least daily would have removed them.
    await seed(
      f.database,
      'oauthArtifacts',
      Array.from({ length: 6 }, (_, index) => ({
        id: `a${index}`,
        expiresAt: Date.now() - 3 * day,
      })),
    );
    // Due for a day only: an on-schedule sweep may not have run yet, so this is no backlog.
    await seed(f.database, 'oauthLoginStates', [{ id: 'recent', expiresAt: Date.now() - day }]);
    await seed(f.database, 'authChallenges', [{ id: 'c', expiresAt: now - 2 * day }]);
    await seed(f.database, 'outbox', [
      { id: 'waiting', kind: 'email', createdAt: now - 20 * minute, attempts: 0 },
      { id: 'dead', kind: 'email', createdAt: now - 2 * day, attempts: 25, failedAt: now - minute },
    ]);
    await seed(f.database, 'auditHooks', [
      { id: 'hook', delivered: false, event: { timestamp: now - 20 * minute } },
    ]);
    const behind = await f.iam.selfCheck({ cap: 5 });
    expect(behind.ok).toBe(true);
    expect(checks(behind)).toEqual({
      'in-memory-database': 'warning',
      'sweep-backlog': 'warning',
      'purge-not-running': 'warning',
      'outbox-stalled': 'warning',
      'outbox-abandoned': 'warning',
      'audit-hooks-stalled': 'warning',
    });
    const backlog = behind.findings.find((finding) => finding.check === 'sweep-backlog')!;
    expect(backlog).toMatchObject({ count: 5 });
    expect(backlog.message).toContain('5+');
    expect(backlog.message).toContain('oauthArtifacts');
    expect(backlog.message).not.toContain('oauthLoginStates');

    // Running the jobs clears their findings.
    await f.iam.sweepExpired();
    await f.iam.purgeDeleted();
    await f.database.transaction(async (tx) => {
      await tx.delete('outbox', 'waiting');
      await tx.delete('auditHooks', 'hook');
    });
    expect(checks(await f.iam.selfCheck({ cap: 5 }))).toEqual({
      'in-memory-database': 'warning',
      'outbox-abandoned': 'warning',
    });
    for (const options of [{ cap: 0 }, { deliveryRetentionMs: -1 }, { graceMs: 2 * day }])
      await expect(f.iam.selfCheck(options)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('judges the sweep backlog with the retention the sweep uses', async () => {
    const f = await organizationFixture();
    const now = f.now();
    await seed(
      f.database,
      'outbox',
      Array.from({ length: 3 }, (_, index) => ({
        id: `sent${index}`,
        kind: 'email',
        createdAt: now - 41 * day,
        attempts: 1,
        deliveredAt: now - 40 * day,
      })),
    );
    expect(checks(await f.iam.selfCheck())).toMatchObject({ 'sweep-backlog': 'warning' });
    // A sweep keeping deliveries for 90 days deletes none of them, so nothing is overdue.
    const ninety = { deliveryRetentionMs: 90 * day };
    expect((await f.iam.sweepExpired(ninety)).deleted).toEqual({});
    expect(checks(await f.iam.selfCheck(ninety))['sweep-backlog']).toBeUndefined();
  });

  it('accepts random secrets and flags an in-memory libSQL database', async () => {
    const { libsqlAdapter } = await import('@better-iam/adapter-libsql');
    const database = libsqlAdapter({ url: ':memory:' });
    stores.push(database);
    // 32 hex digits with only ten distinct characters: random, not a placeholder.
    const iam = betterIam({
      database,
      secret: '3d5f6a92a99f9dffd33aacb3d2563256',
      baseURL: 'http://localhost:3000',
      authentication: { sendEmail: async () => {} },
    });
    await iam.initialize();
    await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    expect(checks(await iam.selfCheck())).toEqual({ 'in-memory-database': 'warning' });
  });

  it('flags settings that can lose data or be guessed', async () => {
    const folder = await directory();
    const database = sqliteAdapter({
      filename: join(folder, 'risky.db'),
      journalMode: 'delete',
      durability: 'normal',
    });
    stores.push(database);
    const iam = betterIam({
      database,
      secret: 'change-me-change-me-change-me-change-me',
      baseURL: 'http://localhost:3000',
      observability: { metrics: { bearerToken: 'short-token' } },
      authentication: { sendEmail: async () => {} },
    });
    await iam.initialize();
    await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const result = await iam.selfCheck();
    expect(result.ok).toBe(false);
    expect(checks(result)).toEqual({
      'sqlite-durability': 'error',
      'weak-secret': 'warning',
      'weak-metrics-token': 'warning',
    });
  });

  it('prints findings from doctor and fails with --strict', async () => {
    const folder = await directory();
    const config = join(folder, 'better-iam.config.mjs');
    await writeFile(
      config,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({ database: sqliteAdapter({ filename: ${JSON.stringify(join(folder, 'iam.db'))} }), secret: ${JSON.stringify(secret)}, baseURL: 'http://localhost:3000' });\n`,
    );
    const output: string[] = [];
    const io = { out: (line: string) => output.push(line), env: {} };
    // Before migrating: the missing schema is a finding, not a crash.
    await runCli(['doctor', '--config', config], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({
      ok: false,
      rootCount: 0,
      findings: expect.arrayContaining([expect.objectContaining({ check: 'schema-behind' })]),
    });
    await runCli(['migrate', '--config', config], io);
    await runCli(['doctor', '--config', config, '--retention-days', '90'], io);
    const report = JSON.parse(output.at(-1)!);
    expect(report).toMatchObject({ ok: false, storage: { adapter: 'sqlite' } });
    expect(report.findings.map((finding: { check: string }) => finding.check).sort()).toEqual([
      'no-email-transport',
      'not-bootstrapped',
    ]);
    await expect(runCli(['doctor', '--config', config, '--strict'], io)).rejects.toMatchObject({
      code: 'DOCTOR_FINDINGS',
    });
    await expect(
      runCli(['doctor', '--config', config, '--strict', '--tenant', 't'], io),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
  });
});
