import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  instrumentStore,
  type IamStore,
  type StoreCall,
  type StoredRecord,
} from '@better-iam/core';
import { betterIam } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

const day = 86_400_000;
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

const record = (collection: string, id: string, fields: Record<string, unknown>) => ({
  collection,
  record: { id, tenantId: 't', ...fields } as StoredRecord,
});
async function seed(store: IamStore, rows: { collection: string; record: StoredRecord }[]) {
  await store.transaction(async (tx) => {
    for (const row of rows) await tx.insert(row.collection, row.record);
  });
}
async function ids(store: IamStore, collection: string) {
  return (await store.find(collection)).map((entry) => entry.id).sort();
}

describe('retention sweep', () => {
  it('deletes expired sessions and keeps live sessions and renewable API keys', async () => {
    const f = await organizationFixture();
    await f.member('alice');
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci',
    });
    await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
      name: 'short',
      expiresInSeconds: 60,
    });
    const stale = await f.signIn('alice');
    const before = await f.database.find('sessions', { kind: 'user' });
    expect(before.length).toBeGreaterThanOrEqual(3);

    f.advance(8 * day);
    const fresh = await f.signIn('alice');
    const result = await f.iam.sweepExpired();
    expect(result.truncated).toBe(false);
    expect(result.deleted.sessions).toBe(before.length);
    const remaining = await f.database.find<StoredRecord & { kind: string }>('sessions');
    expect(remaining.map((session) => session.kind).sort()).toEqual(['api-key', 'user']);
    expect(remaining.find((session) => session.kind === 'user')!.id).not.toBe(stale.session?.id);
    expect(await f.iam.api.auth.getSession({ token: fresh.token })).toBeTruthy();
    await expect(f.iam.api.auth.getSession({ token: stale.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    // The expired key is still listed, so an administrator can see it and renew it.
    const owner = await f.ownerSignIn();
    const keys = await f.iam.api.credentials.list(owner, { tenantId: f.tenantId });
    expect(keys).toMatchObject([{ name: 'short', expired: true }]);

    // Nothing else expired: a second run deletes nothing.
    expect(await f.iam.sweepExpired()).toEqual({ deleted: {}, total: 0, truncated: false });
  });

  it('honors the grace period and the delivery retention', async () => {
    const f = await organizationFixture();
    const now = f.now();
    // The fixture delivered the owner invitation; add an abandoned message and a pending one.
    await seed(f.database, [
      record('outbox', 'failed', { kind: 'email', createdAt: now, attempts: 25, failedAt: now }),
      record('outbox', 'pending', { kind: 'email', createdAt: now - 60 * day, attempts: 3 }),
      record('sessions', 'just-expired', {
        identityId: 'x',
        kind: 'user',
        tokenHash: 'h1',
        createdAt: now - day,
        lastSeenAt: now - day,
        authenticatedAt: now - day,
        expiresAt: now - 60_000,
        mfa: false,
      }),
    ]);
    const delivered = (await f.database.find('outbox')).filter(
      (message) => typeof message.deliveredAt === 'number',
    );
    expect(delivered.length).toBeGreaterThan(0);

    expect((await f.iam.sweepExpired()).deleted).toEqual({});
    expect((await f.iam.sweepExpired({ graceMs: 0 })).deleted).toEqual({ sessions: 1 });

    f.advance(29 * day);
    expect((await f.iam.sweepExpired()).deleted.outbox).toBeUndefined();
    f.advance(2 * day);
    const result = await f.iam.sweepExpired();
    expect(result.deleted.outbox).toBe(delivered.length + 1);
    expect(await ids(f.database, 'outbox')).toEqual(['pending']);
    // A shorter retention applies at once; pending messages are never swept.
    await seed(f.database, [
      record('outbox', 'sent', {
        kind: 'sms',
        createdAt: f.now(),
        attempts: 1,
        deliveredAt: f.now(),
      }),
    ]);
    expect((await f.iam.sweepExpired({ deliveryRetentionMs: 0 })).deleted).toEqual({ outbox: 1 });
    expect(await ids(f.database, 'outbox')).toEqual(['pending']);
  });

  it('sweeps protocol artifacts, devices, relationship tuples, and dispatched audit hooks', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    const iam = betterIam({
      database,
      secret: 'retention-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    });
    await iam.initialize();
    const now = 1_900_000_000_000;
    const past = now - 10 * 60_000;
    const future = now + 60_000;
    const rows = [
      ...[
        'oauthArtifacts',
        'oauthLoginStates',
        'samlRequests',
        'samlRelays',
        'samlAssertions',
        'authDevices',
        'relationships',
      ].flatMap((collection) => [
        record(collection, 'old', { expiresAt: past }),
        record(collection, 'live', { expiresAt: future }),
      ]),
      record('relationships', 'forever', {}),
      record('sessions', 'role-old', { kind: 'role', tokenHash: 'r', expiresAt: past }),
      record('sessions', 'key-old', { kind: 'api-key', tokenHash: 'k', expiresAt: past }),
      record('sessions', 'future-kind', { kind: 'federated', tokenHash: 'f', expiresAt: past }),
      // Grants outlive their expiry by 31 days so back-channel logout can still find the client.
      record('oauthArtifacts', 'grant-recent', { model: 'Grant', expiresAt: now - 30 * day }),
      record('oauthArtifacts', 'grant-old', { model: 'Grant', expiresAt: now - 32 * day }),
      record('ssfDeliveries', 'failed-old', {
        status: 'failed',
        createdAt: now - 41 * day,
        failedAt: now - 40 * day,
      }),
      // Queued long ago, abandoned yesterday: kept for the retention from when it failed.
      record('ssfDeliveries', 'failed-new', {
        status: 'failed',
        createdAt: now - 60 * day,
        failedAt: now - day,
      }),
      record('ssfDeliveries', 'failed-legacy', { status: 'failed', createdAt: now - 40 * day }),
      record('ssfDeliveries', 'pending-old', { status: 'pending', createdAt: now - 40 * day }),
      record('auditHooks', 'done', { delivered: true, deliveredAt: past }),
      record('auditHooks', 'done-legacy', { delivered: true }),
      record('auditHooks', 'waiting', { delivered: false }),
      // Collections the sweep leaves alone even past expiry: history, or renewable.
      record('ownerInvitations', 'invite', { expiresAt: past, consumed: false }),
      record('scimConnections', 'scim', { expiresAt: past }),
      record('accessRequests', 'request', { expiresAt: past, status: 'pending' }),
    ];
    await seed(database, rows);
    const result = await iam.sweepExpired({ now });
    expect(result).toEqual({
      deleted: {
        sessions: 1,
        authDevices: 1,
        relationships: 1,
        oauthArtifacts: 2,
        oauthLoginStates: 1,
        samlRequests: 1,
        samlRelays: 1,
        samlAssertions: 1,
        ssfDeliveries: 2,
        auditHooks: 2,
      },
      total: 13,
      truncated: false,
    });
    expect(await ids(database, 'sessions')).toEqual(['future-kind', 'key-old']);
    expect(await ids(database, 'relationships')).toEqual(['forever', 'live']);
    expect(await ids(database, 'oauthArtifacts')).toEqual(['grant-recent', 'live']);
    expect(await ids(database, 'ssfDeliveries')).toEqual(['failed-new', 'pending-old']);
    expect(await ids(database, 'auditHooks')).toEqual(['waiting']);
    for (const collection of ['ownerInvitations', 'scimConnections', 'accessRequests'])
      expect(await ids(database, collection)).toHaveLength(1);
  });

  it('sweeps expired session tokens and redeemed web-identity tokens, keeping expired API keys', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    const iam = betterIam({
      database,
      secret: 'retention-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    });
    await iam.initialize();
    const now = 1_900_000_000_000;
    const past = now - 10 * 60_000;
    const future = now + 60_000;
    await seed(database, [
      record('sessions', 'sts-old', { kind: 'session-token', tokenHash: 's1', expiresAt: past }),
      record('sessions', 'sts-live', { kind: 'session-token', tokenHash: 's2', expiresAt: future }),
      record('sessions', 'key-old', { kind: 'api-key', tokenHash: 'k', expiresAt: past }),
      record('webIdentityReplays', 'replay-old', { providerId: 'p', expiresAt: past }),
      record('webIdentityReplays', 'replay-live', { providerId: 'p', expiresAt: future }),
    ]);
    expect(await iam.sweepExpired({ now })).toEqual({
      deleted: { sessions: 1, webIdentityReplays: 1 },
      total: 2,
      truncated: false,
    });
    expect(await ids(database, 'sessions')).toEqual(['key-old', 'sts-live']);
    expect(await ids(database, 'webIdentityReplays')).toEqual(['replay-live']);
    // Within the grace period nothing is due yet.
    await seed(database, [
      record('webIdentityReplays', 'replay-recent', { providerId: 'p', expiresAt: now - 1000 }),
    ]);
    expect((await iam.sweepExpired({ now })).deleted).toEqual({});
  });

  it('works in short batches, stops at the limit, and continues on the next run', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    const calls: StoreCall[] = [];
    const iam = betterIam({
      database: instrumentStore(database, (call) => calls.push(call)),
      secret: 'retention-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    });
    await iam.initialize();
    const now = 1_900_000_000_000;
    await seed(
      database,
      Array.from({ length: 23 }, (_, index) =>
        record('oauthArtifacts', `a${String(index).padStart(2, '0')}`, {
          expiresAt: now - (index + 1) * day,
        }),
      ),
    );
    calls.length = 0;
    const first = await iam.sweepExpired({ now, batchSize: 5, limit: 12 });
    expect(first).toEqual({ deleted: { oauthArtifacts: 12 }, total: 12, truncated: true });
    // Oldest first, and never more than one batch per read.
    expect(await ids(database, 'oauthArtifacts')).toEqual(
      Array.from({ length: 11 }, (_, index) => `a${String(index).padStart(2, '0')}`),
    );
    const reads = calls.filter((call) => call.method === 'findOrdered');
    expect(reads.every((call) => (call.page?.limit ?? Infinity) <= 5)).toBe(true);
    expect(calls.filter((call) => call.method === 'delete')).toHaveLength(12);
    expect(
      calls.filter((call) => call.method === 'delete').every((call) => call.inTransaction),
    ).toBe(true);
    const second = await iam.sweepExpired({ now, batchSize: 5 });
    expect(second).toEqual({ deleted: { oauthArtifacts: 11 }, total: 11, truncated: false });
  });

  it('steps over records it keeps instead of reading them again', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    const calls: StoreCall[] = [];
    const iam = betterIam({
      database: instrumentStore(database, (call) => calls.push(call)),
      secret: 'retention-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    });
    await iam.initialize();
    const now = 1_900_000_000_000;
    // Expired API keys interleaved with expired user sessions, several sharing one expiry.
    await seed(
      database,
      Array.from({ length: 24 }, (_, index) =>
        record('sessions', `s${String(index).padStart(2, '0')}`, {
          kind: index % 2 ? 'api-key' : 'user',
          tokenHash: `h${index}`,
          expiresAt: now - day - Math.floor(index / 6) * 60_000,
        }),
      ),
    );
    calls.length = 0;
    const result = await iam.sweepExpired({ now, batchSize: 5 });
    expect(result).toEqual({ deleted: { sessions: 12 }, total: 12, truncated: false });
    expect(
      (await database.find<StoredRecord & { kind: string }>('sessions')).map((s) => s.kind),
    ).toEqual(Array(12).fill('api-key'));
    const sessionReads = calls.filter(
      (call) => call.method === 'findOrdered' && call.collection === 'sessions',
    );
    // 24 due records in batches of 5: four full reads and one short one, never a re-read.
    expect(sessionReads.reduce((sum, call) => sum + call.records, 0)).toBe(24);
    expect(sessionReads).toHaveLength(5);
  });

  it('stamps dispatched audit hooks and tolerates rows removed by an overlapping dispatcher', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    let removeFirst = true;
    const iam = betterIam({
      database,
      secret: 'retention-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
      events: {
        // Meanwhile another dispatcher delivered the first row and a sweep deleted it.
        onEvent: async (event) => {
          if (!removeFirst) return;
          removeFirst = false;
          await database.transaction((tx) => tx.delete('auditHooks', event.id));
        },
      },
    });
    await iam.initialize();
    await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const pending = await database.find('auditHooks', { delivered: false });
    expect(pending.length).toBeGreaterThan(1);
    expect(await iam.events.dispatch()).toEqual({ dispatched: pending.length });
    const rows = await database.find('auditHooks');
    expect(rows).toHaveLength(pending.length - 1);
    expect(rows.every((row) => row.delivered === true && typeof row.deliveredAt === 'number')).toBe(
      true,
    );
    const later = Date.now() + 3_600_000;
    expect((await iam.sweepExpired({ now: later })).deleted.auditHooks).toBe(pending.length - 1);
  });

  it('validates its options', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    stores.push(database);
    const iam = betterIam({
      database,
      secret: 'retention-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    });
    await iam.initialize();
    for (const options of [
      { batchSize: 0 },
      { batchSize: 5001 },
      { limit: 0 },
      { limit: 1.5 },
      { graceMs: -1 },
      { graceMs: 2 * day },
      { deliveryRetentionMs: 3651 * day },
      { now: Number.NaN },
    ])
      await expect(iam.sweepExpired(options), JSON.stringify(options)).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
  });

  it('runs from the CLI', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'retention-test-'));
    created.push(folder);
    const file = join(folder, 'iam.db');
    const config = join(folder, 'better-iam.config.mjs');
    await writeFile(
      config,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({ database: sqliteAdapter({ filename: ${JSON.stringify(file)} }), secret: 'retention-test-secret-with-at-least-32-characters', baseURL: 'http://localhost:3000' });\n`,
    );
    const output: string[] = [];
    const io = { out: (line: string) => output.push(line), env: {} };
    await runCli(['migrate', '--config', config], io);
    const store = sqliteAdapter({ filename: file });
    await seed(store, [
      record('oauthArtifacts', 'old', { expiresAt: Date.now() - day }),
      record('oauthArtifacts', 'live', { expiresAt: Date.now() + day }),
    ]);
    await store.close();
    await runCli(['sweep', '--config', config, '--limit', '100', '--retention-days', '7'], io);
    expect(JSON.parse(output.at(-1)!)).toEqual({
      deleted: { oauthArtifacts: 1 },
      total: 1,
      truncated: false,
    });
    for (const argv of [
      ['sweep', '--config', config, '--limit', '0'],
      ['sweep', '--config', config, '--retention-days', '-1'],
      ['sweep', '--config', config, '--retention-days', '1.5'],
      ['sweep', '--config', config, '--tenant', 't'],
      ['sweep', '--config', config, '--limit', '5', '--limit', '6'],
    ])
      await expect(runCli(argv, io), argv.join(' ')).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
      });
  });
});
