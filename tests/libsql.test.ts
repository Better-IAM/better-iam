import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { libsqlAdapter } from '@better-iam/adapter-libsql';
import { betterIam } from '@better-iam/server';
import type { IamStore, StoredRecord } from '@better-iam/core';

let store: IamStore;
const opened: IamStore[] = [];
const directories: string[] = [];
beforeEach(async () => {
  store = libsqlAdapter({ url: ':memory:' });
  await store.migrate();
});
afterEach(async () => {
  for (const extra of opened.splice(0)) await extra.close();
  await store.close();
  // The native driver releases a file handle when its connection object is collected, so deletion may lag on Windows.
  for (const directory of directories.splice(0))
    await rm(directory, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }).catch(
      () => undefined,
    );
});
async function fileDatabase(): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), 'better-iam-libsql-'));
  directories.push(directory);
  return join(directory, 'iam.db');
}

describe('libSQL adapter guarantees', () => {
  it('validates configuration', () => {
    expect(() => libsqlAdapter({ url: '' })).toThrow();
    expect(() => libsqlAdapter({ url: 'mysql://nope' })).toThrow();
    expect(() => libsqlAdapter({ url: ':memory:', busyTimeoutMs: -1 })).toThrow();
  });

  it('migrates idempotently, rejects writes without a transaction, and enforces tenant-scoped keys', async () => {
    await store.migrate();
    await expect(store.insert('users', { id: 'one', tenantId: 'a' })).rejects.toMatchObject({
      code: 'TRANSACTION_REQUIRED',
    });
    await store.transaction(async (tx) => {
      await tx.insert('users', { id: 'one', tenantId: 'a', uniqueKey: 'same@example.com' });
      await tx.insert('users', { id: 'two', tenantId: 'b', uniqueKey: 'same@example.com' });
      await tx.insert('users', { id: 'three', tenantId: 'a' });
      await tx.insert('users', { id: 'four', tenantId: 'a' });
    });
    await expect(
      store.transaction((tx) =>
        tx.insert('users', { id: 'five', tenantId: 'a', uniqueKey: 'same@example.com' }),
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      store.transaction((tx) => tx.insert('users', { id: 'one', tenantId: 'b' })),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(await store.find('users', { tenantId: 'b' })).toHaveLength(1);
  });

  it('rolls back across awaits and nested transactions and rejects escaped handles', async () => {
    let leaked!: IamStore;
    await expect(
      store.transaction(async (tx) => {
        leaked = tx;
        await tx.insert('items', { id: 'first', tenantId: 'a' });
        await new Promise((resolve) => setTimeout(resolve, 2));
        await store.transaction(async (nested) => {
          await nested.insert('items', { id: 'second', tenantId: 'a' });
        });
        throw new Error('rollback-me');
      }),
    ).rejects.toThrow('rollback-me');
    expect(await store.find('items')).toEqual([]);
    await expect(leaked.get('items', 'first')).rejects.toMatchObject({
      code: 'TRANSACTION_CLOSED',
    });
    await expect(
      store.transaction(async (tx) => {
        await tx.insert('items', { id: 'first', tenantId: 'a' });
        try {
          await tx.transaction(async () => {
            throw new Error('nested');
          });
        } catch {
          /* Caller cannot commit a failed nested operation. */
        }
      }),
    ).rejects.toMatchObject({ code: 'TRANSACTION_ABORTED' });
    expect(await store.find('items')).toEqual([]);
  });

  it('does not resurrect missing records or change record tenant ownership', async () => {
    await expect(
      store.transaction((tx) => tx.put('items', { id: 'missing', tenantId: 'a' })),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await store.transaction((tx) => tx.insert('items', { id: 'one', tenantId: 'a', value: 1 }));
    await expect(
      store.transaction((tx) => tx.put('items', { id: 'one', tenantId: 'b', value: 2 })),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await store.transaction((tx) => tx.put('items', { id: 'one', tenantId: 'a', value: 3 }));
    expect((await store.get('items', 'one'))?.value).toBe(3);
  });

  it('uses strict JSON filters and deterministic pagination', async () => {
    await store.transaction(async (tx) => {
      await tx.insert('items', { id: 'a', tenantId: 't', value: 1, nested: { a: true, b: null } });
      await tx.insert('items', { id: 'b', tenantId: 't', value: '1' });
      await tx.insert('items', { id: 'c', tenantId: 't', value: null });
    });
    expect(await store.find('items', { value: 1 })).toHaveLength(1);
    expect(await store.find('items', { nested: { b: null, a: true } })).toHaveLength(1);
    expect(await store.find('items', { nested: { a: true } })).toHaveLength(0);
    expect(await store.find('items', { tenantId: 't' }, { offset: 1, limit: 1 })).toMatchObject([
      { id: 'b' },
    ]);
  });

  it('serializes concurrent read/modify/write across two adapters on one file', async () => {
    const file = await fileDatabase();
    // One adapter addresses the file by URL, the other by plain path; both share the process mutex.
    const first = libsqlAdapter({ url: `file:${file}` });
    const second = libsqlAdapter({ url: file });
    opened.push(first, second);
    await first.migrate();
    await second.migrate();
    await first.transaction((tx) =>
      tx.insert('counter', { id: 'counter', tenantId: 'a', value: 0 }),
    );
    await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        (index % 2 ? first : second).transaction(async (tx) => {
          const current = await tx.get<StoredRecord & { value: number }>('counter', 'counter');
          await new Promise((resolve) => setTimeout(resolve, 1));
          await tx.put('counter', { ...current!, value: current!.value + 1 });
        }),
      ),
    );
    expect((await second.get('counter', 'counter'))?.value).toBe(20);
    // Single-use records are consumed exactly once under concurrency.
    await first.transaction((tx) => tx.insert('tokens', { id: 'one', tenantId: 'a' }));
    const consume = (db: IamStore) =>
      db.transaction(async (tx) => {
        const record = await tx.get('tokens', 'one');
        await new Promise((resolve) => setTimeout(resolve, 1));
        if (!record) return false;
        await tx.delete('tokens', 'one');
        return true;
      });
    expect(
      (await Promise.all([consume(first), consume(second), consume(first)])).filter(Boolean),
    ).toHaveLength(1);
  });

  it('does not expose dirty reads through the root adapter', async () => {
    let notify!: () => void;
    const inserted = new Promise<void>((resolve) => {
      notify = resolve;
    });
    const transaction = store.transaction(async (tx) => {
      await tx.insert('items', { id: 'uncommitted', tenantId: 'a' });
      notify();
      await new Promise((resolve) => setTimeout(resolve, 10));
      throw new Error('rollback');
    });
    const rejection = expect(transaction).rejects.toThrow('rollback');
    await inserted;
    expect(await store.get('items', 'uncommitted')).toBeUndefined();
    await rejection;
  });

  it('closes idempotently and rejects operations after closure', async () => {
    await store.close();
    await store.close();
    await expect(store.get('items', 'one')).rejects.toMatchObject({ code: 'STORE_CLOSED' });
  });

  it('runs the whole IAM server on an in-memory libSQL database', async () => {
    const database = libsqlAdapter({ url: ':memory:' });
    const inbox: { template: string; tenantId: string; payload: Record<string, string> }[] = [];
    const iam = betterIam({
      database,
      secret: 'libsql-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
      authentication: {
        sendEmail: async (message) => {
          inbox.push(message);
        },
      },
      permissions: { resourceTypes: { folder: { managed: true, actions: ['folders:read'] } } },
    });
    try {
      await iam.initialize();
      await iam.initialize();
      const root = await iam.bootstrap({
        email: 'root@example.test',
        name: 'Root',
        password: 'a strong root test password',
      });
      const challenge = await iam.api.auth.signIn({
        tenantId: root.tenant.id,
        email: 'root@example.test',
        password: 'a strong root test password',
      });
      expect('mfaRequired' in challenge).toBe(true);
      await expect(
        iam.api.auth.signIn({
          tenantId: root.tenant.id,
          email: 'root@example.test',
          password: 'wrong password entirely',
        }),
      ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
      const events = await database.find('audit', { tenantId: root.tenant.id });
      expect(events.length).toBeGreaterThanOrEqual(2);
      expect(await database.get('auditChains', root.tenant.id)).toMatchObject({
        sequence: events.length,
      });
    } finally {
      await database.close();
    }
  });
});
