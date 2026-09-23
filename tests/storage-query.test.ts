import { AsyncLocalStorage } from 'node:async_hooks';
import { createRequire } from 'node:module';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { randomUUID } from 'node:crypto';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { postgresAdapter } from '@better-iam/adapter-postgres';
import {
  IamError,
  INDEXED_FIELDS,
  RecordStore,
  MAX_QUERY_CONDITIONS,
  compareIds,
  decodeJsonbDocument,
  encodeJsonbDocument,
  matchesFilter,
  planQuery,
  postgresSelect,
  schemaMigrations,
  sqliteSelect,
  storableString,
  type IamStore,
  type RecordDriver,
  type RecordQuery,
  type StorageRow,
  type StoredRecord,
} from '@better-iam/core';
import { adapterConformanceCases, runAdapterConformance } from '@better-iam/core/conformance';

const Database = createRequire(new URL('../packages/adapter-sqlite/package.json', import.meta.url))(
  'better-sqlite3',
) as typeof import('better-sqlite3');
const pg = createRequire(new URL('../packages/adapter-postgres/package.json', import.meta.url))(
  'pg',
) as typeof import('pg');

type Mutation = (driver: RecordDriver) => RecordDriver;

/**
 * A minimal map-backed adapter. Without a mutation it has no `query` method, so it exercises
 * RecordStore's in-memory fallback; mutations bolt on deliberately wrong drivers.
 */
class MemoryStore extends RecordStore {
  private rows = new Map<string, StorageRow>();
  private closed = false;
  private tail = Promise.resolve();
  private scope = new AsyncLocalStorage<{
    active: boolean;
    rollbackOnly: boolean;
    store: MemoryStore;
  }>();
  constructor(
    private readonly mutate?: Mutation,
    private readonly root?: MemoryStore,
    private readonly context?: { active: boolean; rollbackOnly: boolean; store: MemoryStore },
  ) {
    super();
  }
  private base(): MemoryStore {
    return this.root ?? this;
  }
  private current() {
    if (this.base().closed) throw new IamError('STORE_CLOSED', 'closed', 500);
    const context = this.context ?? this.base().scope.getStore();
    if (context && !context.active) throw new IamError('TRANSACTION_CLOSED', 'closed', 500);
    return context;
  }
  private driver(): RecordDriver {
    const rows = this.base().rows;
    const key = (collection: string, id: string) => JSON.stringify([collection, id]);
    const driver: RecordDriver = {
      async select(collection, id, tenantId) {
        return [...rows.values()]
          .filter((row) => row.collection === collection && (id === undefined || row.id === id))
          .filter((row) => tenantId === undefined || row.tenant_id === tenantId)
          .map((row) => ({ ...row }));
      },
      async insert(row) {
        const clash = [...rows.values()].some(
          (other) =>
            other.collection === row.collection &&
            (other.id === row.id ||
              (row.unique_key !== null &&
                other.tenant_id === row.tenant_id &&
                other.unique_key === row.unique_key)),
        );
        if (clash) throw new IamError('CONFLICT', 'conflict', 409);
        rows.set(key(row.collection, row.id), { ...row });
      },
      async update(row) {
        const clash = [...rows.values()].some(
          (other) =>
            other.collection === row.collection &&
            other.id !== row.id &&
            row.unique_key !== null &&
            other.tenant_id === row.tenant_id &&
            other.unique_key === row.unique_key,
        );
        if (clash) throw new IamError('CONFLICT', 'conflict', 409);
        if (!rows.has(key(row.collection, row.id))) return false;
        rows.set(key(row.collection, row.id), { ...row });
        return true;
      },
      async delete(collection, id) {
        rows.delete(key(collection, id));
      },
    };
    return this.mutate ? this.mutate(driver) : driver;
  }
  protected async read<T>(operation: (driver: RecordDriver) => Promise<T>): Promise<T> {
    const context = this.current();
    try {
      return await operation(this.driver());
    } catch (error) {
      if (context) context.rollbackOnly = true;
      throw error;
    }
  }
  protected async write<T>(operation: (driver: RecordDriver) => Promise<T>): Promise<T> {
    if (!this.current()) throw new IamError('TRANSACTION_REQUIRED', 'transaction required', 500);
    return this.read(operation);
  }
  async transaction<T>(fn: (tx: IamStore) => Promise<T>): Promise<T> {
    const current = this.current();
    if (current) {
      try {
        return await fn(current.store);
      } catch (error) {
        current.rollbackOnly = true;
        throw error;
      }
    }
    const base = this.base();
    const previous = base.tail;
    let release!: () => void;
    base.tail = new Promise((done) => (release = done));
    await previous;
    const snapshot = new Map(base.rows);
    const context = { active: true, rollbackOnly: false } as {
      active: boolean;
      rollbackOnly: boolean;
      store: MemoryStore;
    };
    context.store = new MemoryStore(this.mutate, base, context);
    try {
      const result = await base.scope.run(context, () => fn(context.store));
      if (context.rollbackOnly) throw new IamError('TRANSACTION_ABORTED', 'aborted', 409);
      return result;
    } catch (error) {
      base.rows = snapshot;
      throw error;
    } finally {
      context.active = false;
      release();
    }
  }
  async migrate() {
    this.current();
  }
  async close() {
    this.base().closed = true;
  }
}

type Defect =
  | 'drop-large-numbers'
  | 'case-folded-strings'
  | 'utf16-order'
  | 'page-before-filter'
  | 'loose-strings'
  | 'ignore-cursor';

/** Evaluates a RecordQuery in memory, optionally breaking one aspect of the contract. */
function queryDriver(defect?: Defect): Mutation {
  return (driver) => ({
    ...driver,
    queryCapabilities: { json: true },
    async query(query: RecordQuery) {
      let rows = (await driver.select(query.collection, query.id, query.tenantId)).filter(
        (row) => query.uniqueKey === undefined || row.unique_key === query.uniqueKey,
      );
      const after = query.after;
      if (after !== undefined && defect !== 'ignore-cursor')
        rows = rows.filter((row) =>
          defect === 'utf16-order' ? row.id > after : compareIds(row.id, after) > 0,
        );
      if (defect === 'page-before-filter' && query.page) {
        rows.sort((a, b) => compareIds(a.id, b.id));
        const end =
          query.page.limit === undefined ? undefined : query.page.offset + query.page.limit;
        rows = rows.slice(query.page.offset, end);
      }
      const matching = rows.filter((row) => {
        const data = JSON.parse(row.data) as Record<string, unknown>;
        return query.conditions.every((condition) => {
          const present = Object.hasOwn(data, condition.field);
          const value = data[condition.field];
          switch (condition.kind) {
            case 'absent':
              return !present;
            case 'null':
              return present && value === null;
            case 'number':
              // Mimics SQLite comparing a parsed double with an exact 64-bit integer literal.
              if (defect === 'drop-large-numbers' && Math.abs(condition.value) >= 2 ** 53)
                return false;
              return value === condition.value;
            case 'string':
              if (defect === 'loose-strings')
                return String(value).toLowerCase() === condition.value.toLowerCase();
              if (defect === 'case-folded-strings')
                return typeof value === 'string' && value.toLowerCase() === condition.value;
              return value === condition.value;
            case 'boolean':
              return value === condition.value;
            case 'json':
              return matchesFilter(data as StoredRecord, {
                [condition.field]: JSON.parse(condition.value),
              });
          }
        });
      });
      matching.sort((a, b) =>
        defect === 'utf16-order'
          ? a.id < b.id
            ? -1
            : a.id > b.id
              ? 1
              : 0
          : compareIds(a.id, b.id),
      );
      const offset = query.page?.offset ?? 0;
      const limit = query.page?.limit;
      return query.page && defect !== 'page-before-filter'
        ? matching.slice(offset, limit === undefined ? undefined : offset + limit)
        : matching;
    },
  });
}

describe('storage query planning', () => {
  it('turns scalar filters into typed conditions and keeps the rest in memory', () => {
    const exact = planQuery('sessions', {
      tenantId: 't',
      tokenHash: 'h',
      count: 2,
      active: true,
      revokedAt: null,
      deletedAt: undefined,
    });
    expect(exact.exact).toBe(true);
    expect(exact.query).toEqual({
      collection: 'sessions',
      tenantId: 't',
      conditions: [
        { field: 'tokenHash', kind: 'string', value: 'h' },
        { field: 'count', kind: 'number', value: 2 },
        { field: 'active', kind: 'boolean', value: true },
        { field: 'revokedAt', kind: 'null' },
        { field: 'deletedAt', kind: 'absent' },
      ],
    });
    expect(planQuery('x', { nested: { a: 1 } }).exact).toBe(false);
    expect(planQuery('x', { nested: { a: 1 } }, { json: true }).query.conditions).toEqual([
      { field: 'nested', kind: 'json', value: '{"a":1}' },
    ]);
    expect(planQuery('x', { nested: { a: undefined } }, { json: true }).exact).toBe(false);
    expect(planQuery('x', { 'odd key': 1 }).exact).toBe(false);
    expect(planQuery('x', { id: 5 }).query.conditions).toEqual([
      { field: 'id', kind: 'number', value: 5 },
    ]);
  });

  it('orders ids by code point, like SQLite BINARY and PostgreSQL "C"', () => {
    const ids = ['', '😀', 'z', 'Z', '￿', 'é'];
    expect([...ids].sort(compareIds)).toEqual(['Z', 'z', 'é', '', '￿', '😀']);
    expect(compareIds('a', 'ab')).toBeLessThan(0);
  });

  it('renders parameterized SQL and never inlines values', () => {
    const query: RecordQuery = {
      collection: 'sessions',
      tenantId: "t'; DROP TABLE iam_records; --",
      conditions: [
        { field: 'tokenHash', kind: 'string', value: "' OR 1=1 --" },
        { field: 'deletedAt', kind: 'absent' },
      ],
      page: { offset: 2, limit: 5 },
    };
    const sqlite = sqliteSelect(query);
    expect(sqlite.text).not.toContain('DROP');
    expect(sqlite.text).not.toContain('OR 1=1');
    expect(sqlite.values).toEqual(['sessions', query.tenantId, "' OR 1=1 --", 5, 2]);
    const postgres = postgresSelect(query);
    expect(postgres.text).not.toContain('DROP');
    expect(postgres.values).toContain(JSON.stringify({ tokenHash: "' OR 1=1 --" }));
    expect(() =>
      sqliteSelect({ collection: 'x', conditions: [{ field: "a'b", kind: 'null' }] }),
    ).toThrow(IamError);
    expect(() =>
      sqliteSelect({ collection: 'x', conditions: [{ field: 'a', kind: 'json', value: '{}' }] }),
    ).toThrow(IamError);
  });
});

describe('adapter conformance suite', () => {
  it('passes on a reference adapter through the in-memory fallback and a query driver', async () => {
    for (const mutation of [undefined, queryDriver()]) {
      const result = await runAdapterConformance(() => new MemoryStore(mutation));
      expect(result.failed.map((failure) => `${failure.name}: ${String(failure.error)}`)).toEqual(
        [],
      );
      expect(result.passed).toHaveLength(adapterConformanceCases().length);
    }
  });

  it.each([
    ['drop-large-numbers', 'finds numbers by value across the whole double range'],
    ['case-folded-strings', 'matches filters with strict, typed JSON equality'],
    ['utf16-order', 'orders by id in code-point order and paginates deterministically'],
    ['page-before-filter', 'pages selectively filtered results across many rows'],
  ] as const)('detects a driver that loses rows: %s', async (defect, expectedCase) => {
    const result = await runAdapterConformance(() => new MemoryStore(queryDriver(defect)));
    expect(result.failed.map((failure) => failure.name)).toContain(expectedCase);
  });

  it.each(['loose-strings', 'ignore-cursor'] as const)(
    'stays correct when a driver returns extra rows, by filtering them in memory: %s',
    async (defect) => {
      const result = await runAdapterConformance(() => new MemoryStore(queryDriver(defect)));
      expect(result.failed).toEqual([]);
    },
  );
});

describe('PostgreSQL value encoding', () => {
  const escapeKey = '\u0001better-iam';
  const records = [
    { id: 'plain', tenantId: 't', v: 'text', n: [1, { a: null }] },
    { id: 'nul', tenantId: 't', v: 'a\u0000b', tokenHash: 'h' },
    { id: 'lone', tenantId: 't', v: ['\ud800', 'x\udfffy', '😀'] },
    {
      id: 'keys',
      tenantId: 't',
      v: { ['k\u0000']: 1, [escapeKey]: 2, ['\udc00']: { [escapeKey]: 'z' } },
    },
    { id: 'marker', tenantId: 't', v: { [escapeKey]: 'deadbeef' }, w: escapeKey },
    { id: 'escaped text', tenantId: 't', v: '\\u0000 and \\ud800 as plain text' },
  ];

  it('round-trips every record and always produces text PostgreSQL jsonb accepts', () => {
    for (const record of records) {
      const data = JSON.stringify(record);
      const encoded = encodeJsonbDocument(data);
      // jsonb rejects exactly U+0000 and unpaired surrogates, in values and in keys.
      const unstorable: string[] = [];
      const walk = (value: unknown): void => {
        if (typeof value === 'string') {
          if (!storableString(value)) unstorable.push(value);
        } else if (value && typeof value === 'object')
          for (const [key, item] of Object.entries(value)) {
            if (!storableString(key)) unstorable.push(key);
            walk(item);
          }
      };
      walk(JSON.parse(encoded));
      expect(unstorable).toEqual([]);
      expect(JSON.parse(encoded)).toMatchObject({ id: record.id, tenantId: record.tenantId });
      expect(JSON.parse(decodeJsonbDocument(encoded))).toEqual(record);
    }
    const plain = JSON.stringify(records[0]);
    expect(encodeJsonbDocument(plain)).toBe(plain);
    expect(decodeJsonbDocument(plain)).toBe(plain);
    // Ordinary top-level fields stay queryable; only the unstorable value is replaced.
    expect(JSON.parse(encodeJsonbDocument(JSON.stringify(records[1])))).toMatchObject({
      tokenHash: 'h',
    });
  });

  it('refuses corrupt escape markers instead of guessing', () => {
    expect(() =>
      decodeJsonbDocument(JSON.stringify({ id: 'x', v: { [escapeKey]: 'xyz' } })),
    ).toThrow(IamError);
    expect(() =>
      decodeJsonbDocument(JSON.stringify({ id: 'x', v: { [escapeKey]: [['zz']] } })),
    ).toThrow(IamError);
  });

  it('keeps filters on escaped values and reserved keys out of SQL', () => {
    expect(planQuery('x', { v: 'a\u0000b' }).exact).toBe(false);
    expect(planQuery('x', { v: { [escapeKey]: 'deadbeef' } }, { json: true }).exact).toBe(false);
    expect(planQuery('x', { v: ['\ud800'] }, { json: true }).exact).toBe(false);
    const sparse: unknown[] = [];
    sparse[2] = 1;
    expect(planQuery('x', { v: sparse }, { json: true }).exact).toBe(false);
    expect(planQuery('x', { id: 'x\ud800' }).empty).toBe(true);
    const wide = Object.fromEntries(
      Array.from({ length: MAX_QUERY_CONDITIONS + 1 }, (_, i) => [`f${i}`, i]),
    );
    const plan = planQuery('x', wide);
    expect(plan.exact).toBe(false);
    expect(plan.query.conditions).toHaveLength(MAX_QUERY_CONDITIONS);
  });

  it('binds numbers to SQLite as their JSON text', () => {
    const statement = sqliteSelect({
      collection: 'x',
      conditions: [{ field: 'n', kind: 'number', value: 2 ** 60 }],
    });
    expect(statement.values).toEqual(['x', '1152921504606847000']);
  });
});

describe('SQLite query indexes', () => {
  let directory: string;
  let filename: string;
  let store: IamStore;
  beforeAll(async () => {
    directory = await mkdtemp(join(tmpdir(), 'better-iam-query-plan-'));
    filename = join(directory, 'plan.sqlite');
    store = sqliteAdapter({ filename });
    await store.migrate();
    await store.transaction(async (tx) => {
      for (let index = 0; index < 500; index++)
        await tx.insert('sessions', {
          id: `s${index}`,
          tenantId: `t${index % 20}`,
          uniqueKey: `key-${index}`,
          tokenHash: `hash-${index}`,
          identityId: `i${index % 50}`,
        });
    });
  });
  afterAll(async () => {
    await store.close();
    await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
  });

  const plan = (query: RecordQuery) => {
    const statement = sqliteSelect(query);
    const database = new Database(filename, { readonly: true });
    try {
      return (
        database
          .prepare(`EXPLAIN QUERY PLAN ${statement.text}`)
          .all(...(statement.values as never[])) as {
          detail: string;
        }[]
      )
        .map((row) => row.detail)
        .join('\n');
    } finally {
      database.close();
    }
  };

  it('records every migration in the ledger', () => {
    const database = new Database(filename, { readonly: true });
    try {
      const names = (
        database.prepare('SELECT name FROM iam_migrations ORDER BY name').all() as {
          name: string;
        }[]
      ).map((row) => row.name);
      expect(names).toEqual(schemaMigrations('sqlite').map((migration) => migration.name));
    } finally {
      database.close();
    }
  });

  it('serves hot field lookups from expression indexes', async () => {
    expect(
      plan({
        collection: 'sessions',
        conditions: [{ field: 'tokenHash', kind: 'string', value: 'hash-7' }],
      }),
    ).toContain('iam_records_field_tokenHash');
    expect(plan({ collection: 'sessions', uniqueKey: 'key-7', conditions: [] })).toContain(
      'iam_records_unique_key',
    );
    expect(await store.find('sessions', { tokenHash: 'hash-7' })).toMatchObject([{ id: 's7' }]);
    expect(INDEXED_FIELDS).toContain('tokenHash');
    // Fields added by a later step (0005) are indexed too.
    for (const field of ['sourceSessionId', 'trustId'])
      expect(
        plan({ collection: 'sessions', conditions: [{ field, kind: 'string', value: 'x' }] }),
      ).toContain(`iam_records_field_${field}`);
  });

  it('pages tenant-scoped reads in index order without a sort step', () => {
    const tenantPage = plan({
      collection: 'sessions',
      tenantId: 't3',
      conditions: [],
      page: { offset: 5, limit: 5 },
    });
    expect(tenantPage).toContain('iam_records_tenant_id');
    for (const query of [
      { collection: 'sessions', tenantId: 't3', conditions: [], page: { offset: 5, limit: 5 } },
      { collection: 'sessions', conditions: [{ field: 'tokenHash', kind: 'string', value: 'x' }] },
      { collection: 'sessions', conditions: [], page: { offset: 0, limit: 5 } },
    ] satisfies RecordQuery[])
      expect(plan(query)).not.toContain('TEMP B-TREE');
  });

  it('finds expired and long-delivered records for retention sweeps through expiry indexes', () => {
    for (const [collection, field, conditions] of [
      ['sessions', 'expiresAt', [{ field: 'kind', kind: 'string', value: 'user' }]],
      ['oauthArtifacts', 'expiresAt', []],
      ['outbox', 'deliveredAt', []],
      ['outbox', 'failedAt', []],
    ] as const) {
      const detail = plan({
        collection,
        conditions: [...conditions],
        order: { field, direction: 'asc', to: 1_900_000_000_000 },
        page: { offset: 0, limit: 500 },
      });
      expect(detail, `${collection}.${field}`).toContain(`iam_records_expiry_${field}`);
      expect(detail, `${collection}.${field}`).not.toContain('TEMP B-TREE');
    }
  });

  it('seeks to an id cursor instead of scanning the pages before it', async () => {
    const collectionPage = plan({
      collection: 'sessions',
      after: 's400',
      conditions: [],
      page: { offset: 0, limit: 5 },
    });
    expect(collectionPage).toMatch(
      /SEARCH iam_records USING (?:INDEX \S+|PRIMARY KEY) \(collection=\? AND id>\?\)/,
    );
    expect(collectionPage).not.toContain('TEMP B-TREE');
    const tenantPage = plan({
      collection: 'sessions',
      tenantId: 't3',
      after: 's400',
      conditions: [],
      page: { offset: 0, limit: 5 },
    });
    expect(tenantPage).toContain('iam_records_tenant_id (collection=? AND tenant_id=? AND id>?)');
    const ids = (await store.find('sessions', {}, { after: 's400', limit: 3 })).map((r) => r.id);
    expect(ids).toEqual(['s401', 's402', 's403']);
  });

  it('pages in SQL when the whole filter is expressed there', async () => {
    const page = await store.find('sessions', { identityId: 'i3' }, { offset: 2, limit: 3 });
    const all = (await store.find('sessions', { identityId: 'i3' })).map((record) => record.id);
    expect(page.map((record) => record.id)).toEqual(all.slice(2, 5));
    expect(
      plan({
        collection: 'sessions',
        conditions: [{ field: 'identityId', kind: 'string', value: 'i3' }],
      }),
    ).toContain('iam_records_field_identityId');
  });
});

const postgresUrl = process.env.BETTER_IAM_POSTGRES_URL;
describe.skipIf(!postgresUrl)('PostgreSQL query indexes', () => {
  // A private collection in the database's default schema: works on servers without schema support.
  const collection = `plan-${randomUUID()}`;
  let store: IamStore;
  let client: InstanceType<typeof pg.Client>;
  beforeAll(async () => {
    client = new pg.Client({ connectionString: postgresUrl });
    await client.connect();
    store = postgresAdapter({ connectionString: postgresUrl! });
    await store.migrate();
    await store.transaction(async (tx) => {
      for (let index = 0; index < 300; index++)
        await tx.insert(collection, {
          id: `s${index}`,
          tenantId: `t${index % 20}`,
          uniqueKey: `key-${index}`,
          tokenHash: `hash-${index}-${collection}`,
        });
    });
    // Rows inserted after the GIN index exists wait in its pending list until a vacuum merges them
    // (autovacuum does this in production); the planner rightly avoids scanning a long pending list.
    await client.query('VACUUM ANALYZE iam_records');
  });
  afterAll(async () => {
    await store?.transaction(async (tx) => {
      for (const record of await tx.find(collection)) await tx.delete(collection, record.id);
    });
    await store?.close();
    await client?.end();
  });

  const plan = async (query: RecordQuery) => {
    const statement = postgresSelect(query);
    await client.query('SET enable_seqscan = off');
    try {
      const result = await client.query(
        `EXPLAIN (FORMAT JSON) ${statement.text}`,
        statement.values,
      );
      return JSON.stringify(result.rows[0]);
    } finally {
      await client.query('RESET enable_seqscan');
    }
  };

  it('serves field lookups from the jsonb GIN index and natural keys from their index', async () => {
    const token = `hash-7-${collection}`;
    expect(
      await plan({
        collection,
        conditions: [{ field: 'tokenHash', kind: 'string', value: token }],
      }),
    ).toContain('iam_records_document');
    expect(await plan({ collection, uniqueKey: 'key-7', conditions: [] })).toContain(
      'iam_records_unique_key',
    );
    expect(await store.find(collection, { tokenHash: token })).toMatchObject([{ id: 's7' }]);
    // t7 holds s7, s27, …, s287; in code-point order: s107, s127, s147, …
    expect(await store.find(collection, { tenantId: 't7' }, { offset: 1, limit: 2 })).toMatchObject(
      [{ id: 's127' }, { id: 's147' }],
    );
    const names = (await client.query('SELECT name FROM iam_migrations ORDER BY name')).rows.map(
      (row) => row.name,
    );
    expect(names).toEqual(
      expect.arrayContaining(schemaMigrations('postgres').map((migration) => migration.name)),
    );
  });
});
