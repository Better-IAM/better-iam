import { afterAll, beforeAll, describe, it } from 'vitest';
import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { libsqlAdapter } from '@better-iam/adapter-libsql';
import { postgresAdapter } from '@better-iam/adapter-postgres';
import type { IamStore } from '@better-iam/core';
import { adapterConformanceCases } from '@better-iam/core/conformance';

const postgresUrl = process.env.BETTER_IAM_POSTGRES_URL;
const pg = createRequire(new URL('../packages/adapter-postgres/package.json', import.meta.url))(
  'pg',
) as typeof import('pg');

let directory: string;
beforeAll(async () => {
  directory = await mkdtemp(join(tmpdir(), 'better-iam-conformance-'));
});
afterAll(async () => {
  await rm(directory, { recursive: true, force: true, maxRetries: 5, retryDelay: 100 });
});

const poolSize = Number(process.env.BETTER_IAM_POSTGRES_POOL_SIZE ?? 3);
async function withClient<T>(
  url: string,
  fn: (client: InstanceType<typeof pg.Client>) => Promise<T>,
): Promise<T> {
  const client = new pg.Client({ connectionString: url });
  await client.connect();
  try {
    return await fn(client);
  } finally {
    await client.end();
  }
}

/** Servers that ignore the startup `options` parameter (for example PGlite) share one schema. */
let schemasSupported: Promise<boolean> | undefined;
function supportsSchemaIsolation(): Promise<boolean> {
  return (schemasSupported ??= (async () => {
    const schema = `conformance_probe_${randomUUID().replaceAll('-', '')}`;
    try {
      await withClient(postgresUrl!, (client) => client.query(`CREATE SCHEMA ${schema}`));
    } catch {
      return false; // No CREATE privilege: fall back to collection prefixes.
    }
    try {
      const url = new URL(postgresUrl!);
      url.searchParams.set('options', `-c search_path=${schema}`);
      const shown = await withClient(url.href, (client) => client.query('SHOW search_path'));
      return shown.rows[0]?.search_path === schema;
    } catch {
      return false; // The server refused the startup options.
    } finally {
      await withClient(postgresUrl!, (client) =>
        client.query(`DROP SCHEMA IF EXISTS ${schema} CASCADE`),
      ).catch(() => undefined);
    }
  })());
}

/** Keeps a case's collections apart from every other case's when schemas are unavailable. */
function prefixed(store: IamStore, prefix: string, used: Set<string>): IamStore {
  const name = (collection: string) => {
    used.add(collection);
    return `${prefix}${collection}`;
  };
  const wrap = (db: IamStore): IamStore => ({
    get: (collection, id) => db.get(name(collection), id),
    find: (collection, filter, options) => db.find(name(collection), filter, options),
    insert: (collection, record) => db.insert(name(collection), record),
    put: (collection, record) => db.put(name(collection), record),
    delete: (collection, id) => db.delete(name(collection), id),
    transaction: (fn) => db.transaction((tx) => fn(wrap(tx))),
    migrate: () => db.migrate(),
    close: () => db.close(),
  });
  return wrap(store);
}

/** Each case starts from an empty schema, or from empty collections on single-schema servers. */
async function postgresStore(): Promise<IamStore & { dispose(): Promise<void> }> {
  if (await supportsSchemaIsolation()) {
    const schema = `conformance_${randomUUID().replaceAll('-', '')}`;
    await withClient(postgresUrl!, (client) => client.query(`CREATE SCHEMA ${schema}`));
    const url = new URL(postgresUrl!);
    url.searchParams.set('options', `-c search_path=${schema}`);
    return Object.assign(postgresAdapter({ connectionString: url.href, poolSize }), {
      dispose: () =>
        withClient(postgresUrl!, (client) => client.query(`DROP SCHEMA ${schema} CASCADE`)).then(
          () => undefined,
        ),
    });
  }
  const prefix = `c${randomUUID().replaceAll('-', '').slice(0, 12)}_`;
  const used = new Set<string>();
  return Object.assign(
    prefixed(postgresAdapter({ connectionString: postgresUrl!, poolSize }), prefix, used),
    {
      async dispose() {
        const cleaner = postgresAdapter({ connectionString: postgresUrl!, poolSize: 1 });
        try {
          await cleaner.transaction(async (tx) => {
            for (const collection of used)
              for (const record of await tx.find(`${prefix}${collection}`))
                await tx.delete(`${prefix}${collection}`, record.id);
          });
        } finally {
          await cleaner.close();
        }
      },
    },
  );
}

const backends: { name: string; skip?: boolean; create(): Promise<IamStore> | IamStore }[] = [
  { name: 'SQLite (memory)', create: () => sqliteAdapter({ filename: ':memory:' }) },
  {
    name: 'SQLite (file)',
    create: () => sqliteAdapter({ filename: join(directory, `${randomUUID()}.sqlite`) }),
  },
  { name: 'libSQL (memory)', create: () => libsqlAdapter({ url: ':memory:' }) },
  { name: 'PostgreSQL', skip: !postgresUrl, create: postgresStore },
];

for (const backend of backends)
  describe.skipIf(backend.skip)(`${backend.name} adapter conformance`, () => {
    for (const test of adapterConformanceCases())
      it(test.name, async () => {
        const store = await backend.create();
        try {
          await store.migrate();
          await test.run(store);
        } finally {
          await store.close();
          await (store as { dispose?(): Promise<void> }).dispose?.();
        }
      });
  });
