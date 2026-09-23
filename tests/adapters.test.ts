import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore, StoredRecord } from '@better-iam/core';

let directory: string;
let store: IamStore;
let second: IamStore | undefined;
beforeEach(async () => {
  directory = await mkdtemp(join(tmpdir(), 'better-iam-sqlite-'));
  store = sqliteAdapter({ filename: join(directory, 'iam.sqlite') });
  await store.migrate();
});
afterEach(async () => {
  await second?.close();
  second = undefined;
  await store.close();
  await rm(directory, { recursive: true, force: true });
});

describe('SQLite adapter guarantees', () => {
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

  it('uses strict JSON filters, deterministic pagination, and detached data', async () => {
    const record = {
      id: 'a',
      tenantId: 't',
      value: 1,
      nested: { a: true, b: null },
      tags: ['x', 'y'],
    };
    await store.transaction(async (tx) => {
      await tx.insert('items', record);
      await tx.insert('items', { id: 'b', tenantId: 't', value: '1' });
      await tx.insert('items', { id: 'c', tenantId: 't', value: null });
    });
    record.nested.a = false;
    expect(await store.find('items', { value: 1 })).toHaveLength(1);
    expect(
      await store.find('items', { nested: { b: null, a: true }, tags: ['x', 'y'] }),
    ).toHaveLength(1);
    expect(await store.find('items', { nested: { a: true } })).toHaveLength(0);
    expect(await store.find('items', { tenantId: 't' }, { offset: 1, limit: 1 })).toMatchObject([
      { id: 'b' },
    ]);
    expect(await store.find('items', {}, { limit: 0 })).toEqual([]);
    await expect(store.find('items', {}, { offset: -1 })).rejects.toMatchObject({
      code: 'INVALID_FILTER',
    });
  });

  it('serializes concurrent read/modify/write across two database connections', async () => {
    second = sqliteAdapter({ filename: join(directory, 'iam.sqlite') });
    await second.migrate();
    await store.transaction((tx) =>
      tx.insert('counter', { id: 'counter', tenantId: 'a', value: 0 }),
    );
    await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        (index % 2 ? store : second!).transaction(async (tx) => {
          const current = await tx.get<StoredRecord & { value: number }>('counter', 'counter');
          await new Promise((resolve) => setTimeout(resolve, 1));
          await tx.put('counter', { ...current!, value: current!.value + 1 });
        }),
      ),
    );
    expect((await store.get('counter', 'counter'))?.value).toBe(20);
  });

  it('atomically consumes single-use records under concurrency', async () => {
    second = sqliteAdapter({ filename: join(directory, 'iam.sqlite') });
    await store.transaction((tx) => tx.insert('tokens', { id: 'one', tenantId: 'a' }));
    const consume = (db: IamStore) =>
      db.transaction(async (tx) => {
        const record = await tx.get('tokens', 'one');
        await new Promise((resolve) => setTimeout(resolve, 1));
        if (!record) return false;
        await tx.delete('tokens', 'one');
        return true;
      });
    expect(
      (await Promise.all([consume(store), consume(second), consume(store)])).filter(Boolean),
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

  it('rejects oversized multibyte natural keys consistently with PostgreSQL index limits', async () => {
    await expect(
      store.transaction((tx) =>
        tx.insert('items', { id: 'unicode', tenantId: 'a', uniqueKey: '界'.repeat(171) }),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_RECORD' });
    await store.transaction((tx) =>
      tx.insert('items', { id: 'unicode', tenantId: 'a', uniqueKey: '界'.repeat(170) }),
    );
    expect(await store.get('items', 'unicode')).toBeTruthy();
  });
});
