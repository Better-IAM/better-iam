import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { postgresAdapter } from '@better-iam/adapter-postgres';
import type { IamStore, StoredRecord } from '@better-iam/core';

const url = process.env.BETTER_IAM_POSTGRES_URL;
describe.skipIf(!url)('PostgreSQL adapter (requires BETTER_IAM_POSTGRES_URL)', () => {
  let store: IamStore;
  let second: IamStore;
  const collection = `test-${randomUUID()}`;
  beforeAll(async () => {
    store = postgresAdapter({ connectionString: url! });
    second = postgresAdapter({ connectionString: url! });
    await Promise.all([store.migrate(), second.migrate()]);
  });
  afterAll(async () => {
    if (store) {
      await store.transaction(async (tx) => {
        for (const record of await tx.find(collection)) await tx.delete(collection, record.id);
      });
      await store.close();
    }
    await second?.close();
  });

  it('matches SQLite keys, transactions, strict filters, and update semantics', async () => {
    await store.migrate();
    await expect(store.insert(collection, { id: 'outside', tenantId: 'a' })).rejects.toMatchObject({
      code: 'TRANSACTION_REQUIRED',
    });
    await store.transaction(async (tx) => {
      await tx.insert(collection, { id: 'a', tenantId: 'a', uniqueKey: 'email', value: 1 });
      await tx.insert(collection, { id: 'b', tenantId: 'b', uniqueKey: 'email', value: '1' });
      await tx.insert(collection, { id: 'c', tenantId: 'a' });
      await tx.insert(collection, { id: 'd', tenantId: 'a' });
    });
    await expect(
      store.transaction((tx) =>
        tx.insert(collection, { id: 'duplicate', tenantId: 'a', uniqueKey: 'email' }),
      ),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      store.transaction((tx) => tx.put(collection, { id: 'missing', tenantId: 'a' })),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      store.transaction((tx) => tx.put(collection, { id: 'a', tenantId: 'b' })),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(await store.find(collection, { value: 1 })).toHaveLength(1);
    expect(await store.find(collection, { tenantId: 'a' }, { offset: 1, limit: 1 })).toMatchObject([
      { id: 'c' },
    ]);
    await expect(
      store.transaction(async (tx) => {
        await tx.insert(collection, { id: 'rollback', tenantId: 'a' });
        await store.transaction(async (nested) => {
          await nested.put(collection, { id: 'a', tenantId: 'a', uniqueKey: 'email', value: 2 });
        });
        throw new Error('rollback');
      }),
    ).rejects.toThrow('rollback');
    expect(await store.get(collection, 'rollback')).toBeUndefined();
    expect((await store.get(collection, 'a'))?.value).toBe(1);
  });

  it('serializes awaited read/modify/write and consumption across two pools', async () => {
    await store.transaction(async (tx) => {
      await tx.insert(collection, { id: 'counter', tenantId: 'a', value: 0 });
      await tx.insert(collection, { id: 'token', tenantId: 'a' });
    });
    await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        (index % 2 ? store : second).transaction(async (tx) => {
          const current = await tx.get<StoredRecord & { value: number }>(collection, 'counter');
          await new Promise((resolve) => setTimeout(resolve, 1));
          await tx.put(collection, { ...current!, value: current!.value + 1 });
        }),
      ),
    );
    expect((await store.get(collection, 'counter'))?.value).toBe(20);
    const consume = (db: IamStore) =>
      db.transaction(async (tx) => {
        const token = await tx.get(collection, 'token');
        if (!token) return false;
        await tx.delete(collection, 'token');
        return true;
      });
    expect(
      (await Promise.all([consume(store), consume(second), consume(store)])).filter(Boolean),
    ).toHaveLength(1);
  });
});
