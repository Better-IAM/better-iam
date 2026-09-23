import { mkdir, mkdtemp, rm } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { libsqlAdapter } from '@better-iam/adapter-libsql';
import {
  findOrdered,
  instrumentStore,
  summarizeStoreCalls,
  type IamStore,
  type StoreCall,
} from '@better-iam/core';

const work = resolve('work');
const created: string[] = [];
const stores: IamStore[] = [];
afterEach(async () => {
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
  const folder = await mkdtemp(join(work, 'describe-test-'));
  created.push(folder);
  return folder;
}
const open = <T extends IamStore>(store: T): T => {
  stores.push(store);
  return store;
};
const tenant = (id: string, sequence: number) => ({
  id,
  tenantId: 'root',
  name: id,
  sequence,
  createdAt: new Date(0).toISOString(),
  updatedAt: new Date(0).toISOString(),
});

describe('store diagnostics', () => {
  it('reports schema, migrations, record counts, and durability for each adapter', async () => {
    const folder = await directory();
    const cases: [string, IamStore, Record<string, unknown>][] = [
      [
        'sqlite',
        open(sqliteAdapter({ filename: ':memory:' })),
        { inMemory: true, synchronous: 'full' },
      ],
      [
        'sqlite',
        open(sqliteAdapter({ filename: join(folder, 'wal.db') })),
        { inMemory: false, journalMode: 'wal', synchronous: 'full' },
      ],
      [
        'sqlite',
        open(
          sqliteAdapter({
            filename: join(folder, 'rollback.db'),
            journalMode: 'delete',
            durability: 'normal',
          }),
        ),
        { inMemory: false, journalMode: 'delete', synchronous: 'normal' },
      ],
      ['libsql', open(libsqlAdapter({ url: ':memory:' })), { location: 'memory' }],
    ];
    for (const [adapter, store, settings] of cases) {
      // Before migrating: no schema yet, and describe() still answers instead of failing.
      const empty = await store.describe!();
      expect(empty).toMatchObject({
        adapter,
        schemaVersion: null,
        migrations: [],
        collections: [],
      });
      await store.migrate();
      await store.transaction(async (tx) => {
        await tx.insert('tenants', tenant('a', 1));
        await tx.insert('tenants', tenant('b', 2));
        await tx.insert('audit', { ...tenant('e', 1), tenantId: 'a' });
      });
      const description = await store.describe!();
      expect(description.adapter).toBe(adapter);
      expect(description.schemaVersion).toEqual(expect.any(Number));
      expect(description.migrations.map((migration) => migration.name)).toEqual([
        '0001_records',
        '0002_query_indexes',
        '0003_ordered_indexes',
        '0004_expiry_indexes',
        '0005_lookup_indexes',
      ]);
      expect(description.migrations.every((migration) => migration.appliedAt > 0)).toBe(true);
      expect(description.collections).toEqual([
        { name: 'audit', records: 1 },
        { name: 'tenants', records: 2 },
      ]);
      expect(description.settings).toMatchObject(settings);
      expect(await store.collections!()).toEqual(['audit', 'tenants']);
      // Inside a transaction, describe() sees the transaction's own writes.
      await store.transaction(async (tx) => {
        await tx.insert('tenants', tenant('c', 3));
        expect((await tx.describe!()).collections).toContainEqual({ name: 'tenants', records: 3 });
      });
    }
  });

  it('fails instead of reporting an unreachable database as empty', async () => {
    const store = open(libsqlAdapter({ url: 'http://127.0.0.1:9' }));
    await expect(store.describe!()).rejects.toMatchObject({ code: expect.any(String) });
    await expect(store.find('tenants')).rejects.toBeDefined();
  });

  it('refuses unknown SQLite journal and durability modes', () => {
    expect(() =>
      sqliteAdapter({ filename: ':memory:', journalMode: 'memory' as 'wal' }),
    ).toThrowError(expect.objectContaining({ code: 'INVALID_CONFIG' }));
    expect(() => sqliteAdapter({ filename: ':memory:', durability: 'off' as 'full' })).toThrowError(
      expect.objectContaining({ code: 'INVALID_CONFIG' }),
    );
  });

  it('instruments every call, including ordered reads, without changing results', async () => {
    const store = open(sqliteAdapter({ filename: ':memory:' }));
    await store.migrate();
    const calls: StoreCall[] = [];
    let clock = 0;
    const observed = instrumentStore(
      store,
      (call) => calls.push(call),
      () => (clock += 5),
    );
    await observed.transaction(async (tx) => {
      for (let index = 1; index <= 5; index++)
        await tx.insert('tenants', tenant(`t${index}`, index));
    });
    expect(calls).toHaveLength(5);
    expect(calls.every((call) => call.method === 'insert' && call.inTransaction)).toBe(true);
    calls.length = 0;

    const ordered = await findOrdered(
      observed,
      'tenants',
      { tenantId: 'root' },
      {
        field: 'sequence',
        direction: 'desc',
        from: 2,
        limit: 2,
      },
    );
    expect(ordered.map((record) => record.id)).toEqual(['t5', 't4']);
    expect(calls).toEqual([
      {
        method: 'findOrdered',
        collection: 'tenants',
        filterKeys: ['tenantId'],
        page: { offset: undefined, limit: 2 },
        records: 2,
        durationMs: 5,
        inTransaction: false,
        failed: false,
      },
    ]);
    // Filter values (which can be secrets or hashes) never reach the observer.
    await observed.find('tenants', { name: 'secret-value' });
    expect(JSON.stringify(calls)).not.toContain('secret-value');
    expect(await observed.collections!()).toEqual(['tenants']);
    expect((await observed.describe!()).collections).toEqual([{ name: 'tenants', records: 5 }]);
    expect(calls.slice(-2).map((call) => [call.method, call.collection, call.records])).toEqual([
      ['collections', '*', 1],
      ['describe', '*', 1],
    ]);

    // A failed call is reported and still throws; an observer that throws changes nothing.
    await expect(
      observed.transaction((tx) => tx.insert('tenants', tenant('t1', 9))),
    ).rejects.toBeDefined();
    expect(calls.at(-1)).toMatchObject({ method: 'insert', failed: true, records: 0 });
    const noisy = instrumentStore(store, () => {
      throw new Error('observer failure');
    });
    expect(await noisy.get('tenants', 't1')).toMatchObject({ id: 't1' });
    expect(summarizeStoreCalls(calls)).toMatchObject({
      'findOrdered:tenants': { calls: 1, records: 2 },
      'find:tenants': { calls: 1, records: 0 },
      'insert:tenants': { calls: 1, records: 0 },
    });
  });

  it('omits optional methods the wrapped store does not have', async () => {
    const store = open(sqliteAdapter({ filename: ':memory:' }));
    const minimal: IamStore = {
      get: (collection, id) => store.get(collection, id),
      find: (collection, filter, options) => store.find(collection, filter, options),
      insert: (collection, record) => store.insert(collection, record),
      put: (collection, record) => store.put(collection, record),
      delete: (collection, id) => store.delete(collection, id),
      transaction: (fn) => store.transaction(fn),
      migrate: () => store.migrate(),
      close: async () => {},
    };
    const observed = instrumentStore(minimal, () => {});
    expect(observed.findOrdered).toBeUndefined();
    expect(observed.collections).toBeUndefined();
    expect(observed.describe).toBeUndefined();
    // The shared helper still orders through plain find().
    await observed.migrate();
    await observed.transaction(async (tx) => {
      await tx.insert('tenants', tenant('x', 2));
      await tx.insert('tenants', tenant('y', 1));
    });
    const ordered = await findOrdered(observed, 'tenants', {}, { field: 'sequence' });
    expect(ordered.map((record) => record.id)).toEqual(['y', 'x']);
  });
});
