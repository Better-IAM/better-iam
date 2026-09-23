import { access, mkdir, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { createRequire } from 'node:module';
import { join, resolve, sep } from 'node:path';
import { pathToFileURL } from 'node:url';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { libsqlAdapter } from '@better-iam/adapter-libsql';
import {
  SNAPSHOT_FORMAT,
  copyStore,
  exportStore,
  importStore,
  instrumentStore,
  type FindOptions,
  type IamStore,
  type StoreCall,
  type StoredRecord,
} from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const secret = 'snapshot-test-secret-with-at-least-32-characters';
const work = resolve('work');
const created: string[] = [];
const stores: IamStore[] = [];
afterEach(async () => {
  for (const store of stores.splice(0)) await store.close();
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    // The native libSQL driver releases a file when its connection is collected, so deletion can
    // lag on Windows (see libsql.test.ts); a leftover temporary folder is harmless.
    await rm(folder, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});

async function directory() {
  await mkdir(work, { recursive: true });
  const folder = await mkdtemp(join(work, 'snapshot-test-'));
  created.push(folder);
  return folder;
}

/** A trusted `.mjs` configuration for the CLI; `adapter` is the factory call. */
async function config(folder: string, name: string, adapter: string): Promise<string> {
  const path = join(folder, `${name}.config.mjs`);
  await writeFile(
    path,
    `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nimport { libsqlAdapter } from '@better-iam/adapter-libsql';\nexport default () => ({ database: ${adapter}, secret: ${JSON.stringify(secret)}, baseURL: 'http://localhost:3000' });\n`,
  );
  return path;
}
const sqliteAt = (file: string) => `sqliteAdapter({ filename: ${JSON.stringify(file)} })`;
const libsqlAt = (file: string) => `libsqlAdapter({ url: ${JSON.stringify(file)} })`;

function cli() {
  const output: string[] = [];
  return {
    output,
    last: () => JSON.parse(output.at(-1)!) as Record<string, any>,
    run: (...argv: string[]) => runCli(argv, { out: (line) => output.push(line), env: {} }),
  };
}

/** Root with MFA, an organization with an owner, and a member with a password: real credentials. */
async function populate(database: IamStore) {
  const inbox: DeliveryMessage[] = [];
  const iam = betterIam({
    database,
    secret,
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
  });
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
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const organization = await iam.api.tenants.create(
    { token: session.token },
    {
      parentId: root.tenant.id,
      name: 'Acme',
      type: 'organization',
      ownerEmail: 'owner@acme.test',
    },
  );
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) =>
      message.tenantId === organization.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: organization.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  await iam.api.identities.create(
    { token: owner.token },
    {
      tenantId: organization.tenant.id,
      email: 'member@acme.test',
      name: 'Member',
      password: 'a strong member password',
    },
  );
  return {
    rootTenantId: root.tenant.id,
    tenantId: organization.tenant.id,
    ownerToken: owner.token,
  };
}

async function everything(store: IamStore): Promise<Record<string, StoredRecord[]>> {
  const result: Record<string, StoredRecord[]> = {};
  for (const collection of await store.collections!())
    result[collection] = await store.find(collection);
  return result;
}

describe('store snapshots', () => {
  it('moves a live deployment to another adapter with credentials and audit chains intact', async () => {
    const folder = await directory();
    const sourceFile = join(folder, 'source.db'),
      targetFile = join(folder, 'target.db'),
      snapshot = join(folder, 'snapshot.jsonl');
    const source = sqliteAdapter({ filename: sourceFile });
    const facts = await populate(source);
    const before = await everything(source);
    await source.close();

    const { run, last, output } = cli();
    const sourceConfig = await config(folder, 'source', sqliteAt(sourceFile));
    const targetConfig = await config(folder, 'target', libsqlAt(targetFile));
    await run('store-export', '--config', sourceConfig, '--output', snapshot);
    const exported = last();
    expect(exported.output).toBe(snapshot);
    expect(exported.records).toBe(Object.values(before).flat().length);
    expect(exported.collections.identities).toBe(before.identities!.length);

    const lines = (await readFile(snapshot, 'utf8')).trimEnd().split('\n');
    expect(JSON.parse(lines[0]!)).toMatchObject({ format: SNAPSHOT_FORMAT, version: 1 });
    expect(JSON.parse(lines.at(-1)!)).toMatchObject({ end: true, records: exported.records });
    expect(lines).toHaveLength(exported.records + 2);

    await run('store-import', '--config', targetConfig, '--input', snapshot);
    expect(last()).toMatchObject({ records: exported.records, collections: exported.collections });

    // The imported store is the same deployment: records verbatim, passwords, sessions, and chains.
    const target = libsqlAdapter({ url: targetFile });
    stores.push(target);
    expect(await everything(target)).toEqual(before);
    const iam = betterIam({ database: target, secret, baseURL: 'http://localhost:3000' });
    const login = await iam.api.auth.signIn({
      tenantId: facts.tenantId,
      email: 'member@acme.test',
      password: 'a strong member password',
    });
    expect('token' in login).toBe(true);
    expect(await iam.api.auth.getSession({ token: facts.ownerToken })).toBeTruthy();
    await target.close();
    stores.splice(0);

    for (const tenantId of [facts.rootTenantId, facts.tenantId]) {
      await run('audit-verify', '--config', targetConfig, '--tenant', tenantId);
      expect(last()).toMatchObject({ tenantId, valid: true });
    }
    await run('doctor', '--config', targetConfig);
    const storage = last().storage;
    expect(storage).toMatchObject({ adapter: 'libsql', schemaVersion: expect.any(Number) });
    expect(storage.settings).toMatchObject({ location: 'file' });
    expect(storage.migrations.map((migration: { name: string }) => migration.name)).toContain(
      '0001_records',
    );
    // The sign-in above wrote a session and audit events, so counts are at least the snapshot's.
    const counts = Object.fromEntries(
      storage.collections.map((entry: { name: string; records: number }) => [
        entry.name,
        entry.records,
      ]),
    );
    for (const [name, count] of Object.entries(exported.collections))
      expect(counts[name]).toBeGreaterThanOrEqual(count as number);

    // An import never merges into existing data, and an export never overwrites a file.
    const printed = output.length;
    await expect(
      run('store-import', '--config', targetConfig, '--input', snapshot),
    ).rejects.toMatchObject({ code: 'STORE_NOT_EMPTY' });
    const original = await readFile(snapshot, 'utf8');
    await expect(
      run('store-export', '--config', sourceConfig, '--output', snapshot),
    ).rejects.toMatchObject({ code: 'EEXIST' });
    expect(await readFile(snapshot, 'utf8')).toBe(original);
    expect(output).toHaveLength(printed);
  });

  it('copies between databases directly, all or nothing, into an empty target only', async () => {
    const folder = await directory();
    const sourceFile = join(folder, 'source.db');
    const source = sqliteAdapter({ filename: sourceFile });
    await populate(source);
    const before = await everything(source);
    await source.close();

    const { run, last } = cli();
    const sourceConfig = await config(folder, 'source', sqliteAt(sourceFile));
    const targetConfig = await config(folder, 'target', libsqlAt(join(folder, 'copy.db')));
    await run('store-copy', '--config', sourceConfig, '--target-config', targetConfig);
    expect(last()).toMatchObject({ records: Object.values(before).flat().length });
    await expect(
      run('store-copy', '--config', sourceConfig, '--target-config', targetConfig),
    ).rejects.toMatchObject({ code: 'STORE_NOT_EMPTY' });
    await expect(
      run('store-copy', '--config', sourceConfig, '--target-config', sourceConfig),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });

    const copy = libsqlAdapter({ url: join(folder, 'copy.db') });
    stores.push(copy);
    expect(await everything(copy)).toEqual(before);

    // Two configurations naming one database fail fast instead of waiting on their own lock.
    const alias = await config(folder, 'alias', sqliteAt(sourceFile));
    await expect(
      run('store-copy', '--config', sourceConfig, '--target-config', alias),
    ).rejects.toMatchObject({ code: 'SAME_DATABASE' });
    const libsqlAlias = await config(folder, 'copy-alias', libsqlAt(join(folder, 'copy.db')));
    const libsqlCopy = await config(folder, 'copy', libsqlAt(join(folder, 'copy.db')));
    await expect(
      run('store-copy', '--config', libsqlCopy, '--target-config', libsqlAlias),
    ).rejects.toMatchObject({ code: 'SAME_DATABASE' });
  });

  it('refuses re-entry into a database the call chain already holds through another instance', async () => {
    const folder = await directory();
    const file = join(folder, 'shared.db');
    const first = sqliteAdapter({ filename: file });
    const second = sqliteAdapter({ filename: file });
    stores.push(first, second);
    await first.migrate();
    await expect(first.transaction(() => second.find('tenants'))).rejects.toMatchObject({
      code: 'DATABASE_IN_USE',
    });
    // Outside the transaction, and in parallel call chains, the instances simply take turns.
    await Promise.all([
      first.transaction((tx) => tx.insert('tenants', { id: 'a', tenantId: 'a' })),
      second.transaction((tx) => tx.insert('tenants', { id: 'b', tenantId: 'b' })),
    ]);
    expect((await second.find('tenants')).map((record) => record.id)).toEqual(['a', 'b']);

    // libSQL: a plain path and a file:// URL name the same file.
    const libsqlFile = join(folder, 'shared-libsql.db');
    const byPath = libsqlAdapter({ url: libsqlFile });
    const byUrl = libsqlAdapter({ url: pathToFileURL(libsqlFile).href });
    stores.push(byPath, byUrl);
    await byPath.migrate();
    await expect(byPath.transaction(() => byUrl.find('tenants'))).rejects.toMatchObject({
      code: 'DATABASE_IN_USE',
    });
  });

  it('round-trips collections named after Object.prototype members', async () => {
    const source = sqliteAdapter({ filename: ':memory:' });
    const target = sqliteAdapter({ filename: ':memory:' });
    stores.push(source, target);
    await source.migrate();
    await target.migrate();
    await source.transaction(async (tx) => {
      for (const collection of ['constructor', 'toString', '__proto__', 'tenants'])
        await tx.insert(collection, { id: 'x', tenantId: 't' });
    });
    const lines: string[] = [];
    const summary = await exportStore(source, (line) => void lines.push(line));
    expect(summary.records).toBe(4);
    expect(Object.keys(summary.collections).sort()).toEqual(
      ['__proto__', 'constructor', 'tenants', 'toString'].sort(),
    );
    expect((await importStore(target, lines)).records).toBe(4);
    expect(await target.collections!()).toEqual(await source.collections!());
  });

  it('imports and copies into a store that cannot list its collections', async () => {
    const source = sqliteAdapter({ filename: ':memory:' });
    const target = sqliteAdapter({ filename: ':memory:' });
    stores.push(source, target);
    await source.migrate();
    await target.migrate();
    await source.transaction((tx) => tx.insert('tenants', { id: 'x', tenantId: 't' }));
    // A store whose collections() is refused, as a RecordStore driver without the method does.
    const unlisted = (store: IamStore): IamStore =>
      new Proxy(store, {
        get(inner, key) {
          if (key === 'collections')
            return async () => {
              throw Object.assign(new Error('unsupported'), { code: 'UNSUPPORTED' });
            };
          if (key === 'transaction')
            return <T>(fn: (tx: IamStore) => Promise<T>) =>
              inner.transaction((tx) => fn(unlisted(tx)));
          const value = Reflect.get(inner, key);
          return typeof value === 'function' ? value.bind(inner) : value;
        },
      });
    const lines: string[] = [];
    await exportStore(source, (line) => void lines.push(line));
    expect((await importStore(unlisted(target), lines)).records).toBe(1);
    await expect(importStore(unlisted(target), lines)).rejects.toMatchObject({
      code: 'STORE_NOT_EMPTY',
    });
    await expect(exportStore(unlisted(source), () => {})).rejects.toMatchObject({
      code: 'UNSUPPORTED',
    });
    const other = sqliteAdapter({ filename: ':memory:' });
    stores.push(other);
    await other.migrate();
    expect(
      (await copyStore(unlisted(source), unlisted(other), { collections: ['tenants'] })).records,
    ).toBe(1);
  });

  it('imports nothing from a truncated, corrupt, or foreign snapshot', async () => {
    const source = sqliteAdapter({ filename: ':memory:' });
    stores.push(source);
    await populate(source);
    const lines: string[] = [];
    const summary = await exportStore(
      source,
      (line) => {
        lines.push(line);
      },
      { pageSize: 3 },
    );
    expect(lines).toHaveLength(summary.records + 2);
    const record = lines.findIndex((line, index) => index > 0 && line.includes('"c":"identities"'));

    const variants: [string, string[], string][] = [
      ['no trailer', lines.slice(0, -1), 'SNAPSHOT_TRUNCATED'],
      ['a missing record', lines.filter((_, index) => index !== record), 'SNAPSHOT_TRUNCATED'],
      [
        'a corrupt line',
        lines.map((line, index) => (index === record ? line.slice(0, 20) : line)),
        'SNAPSHOT_INVALID',
      ],
      [
        'a foreign header',
        [JSON.stringify({ format: 'other', version: 1 }), ...lines.slice(1)],
        'SNAPSHOT_INVALID',
      ],
      [
        'a newer version',
        [lines[0]!.replace('"version":1', '"version":2'), ...lines.slice(1)],
        'SNAPSHOT_INVALID',
      ],
      ['content after the trailer', [...lines, lines[record]!], 'SNAPSHOT_INVALID'],
      ['an empty file', [], 'SNAPSHOT_INVALID'],
      [
        'a record entry without a collection',
        lines.map((line, index) => (index === record ? '{"r":{}}' : line)),
        'SNAPSHOT_INVALID',
      ],
      // A duplicated record (with a trailer that agrees) is refused by the store itself.
      [
        'a duplicated record',
        [
          ...lines.slice(0, -1),
          lines[record]!,
          lines.at(-1)!.replace(`"records":${summary.records}`, `"records":${summary.records + 1}`),
        ],
        'CONFLICT',
      ],
    ];
    for (const [label, variant, code] of variants) {
      const target = sqliteAdapter({ filename: ':memory:' });
      stores.push(target);
      await target.migrate();
      const failure = await importStore(target, variant).then(
        () => undefined,
        (error: { code?: string }) => error,
      );
      expect(failure, label).toBeDefined();
      if (code !== 'CONFLICT') expect(failure!.code, label).toBe(code);
      expect(await target.collections!(), label).toEqual([]);
    }

    // The unmodified lines import, including from an async source.
    const target = sqliteAdapter({ filename: ':memory:' });
    stores.push(target);
    await target.migrate();
    async function* stream() {
      for (const line of lines) yield `${line}\r`;
    }
    expect(await importStore(target, stream())).toEqual(summary);
    expect(await everything(target)).toEqual(await everything(source));
  });

  it('pages by id cursor, and by offset for a store that ignores the cursor', async () => {
    const source = sqliteAdapter({ filename: ':memory:' });
    stores.push(source);
    await populate(source);
    const pages: NonNullable<StoreCall['page']>[] = [];
    const observed = instrumentStore(source, (call) => {
      if (call.method === 'find' && call.page) pages.push(call.page);
    });
    const lines: string[] = [];
    await exportStore(observed, (line) => void lines.push(line), { pageSize: 2 });
    expect(pages.some((page) => page.keyset)).toBe(true);
    expect(pages.every((page) => page.offset === undefined)).toBe(true);

    // A store that drops the cursor would repeat its first page forever; export detects it.
    const ignoreCursor = (store: IamStore): IamStore =>
      new Proxy(store, {
        get(target, key) {
          if (key === 'find')
            return (collection: string, filter?: Record<string, unknown>, options?: FindOptions) =>
              target.find(
                collection,
                filter,
                options && {
                  ...(options.offset !== undefined ? { offset: options.offset } : {}),
                  ...(options.limit !== undefined ? { limit: options.limit } : {}),
                },
              );
          if (key === 'transaction')
            return <T>(fn: (tx: IamStore) => Promise<T>) =>
              target.transaction((tx) => fn(ignoreCursor(tx)));
          const value = Reflect.get(target, key);
          return typeof value === 'function' ? value.bind(target) : value;
        },
      });
    const fallback: string[] = [];
    await exportStore(ignoreCursor(source), (line) => void fallback.push(line), { pageSize: 2 });
    expect(fallback.slice(1)).toEqual(lines.slice(1));
  });

  it('copies selected collections and refuses a target that already holds records', async () => {
    const source = sqliteAdapter({ filename: ':memory:' });
    const target = libsqlAdapter({ url: ':memory:' });
    stores.push(source, target);
    await populate(source);
    await target.migrate();
    const summary = await copyStore(source, target, {
      collections: ['tenants', 'identities'],
      pageSize: 1,
    });
    expect(Object.keys(summary.collections)).toEqual(['identities', 'tenants']);
    expect(await target.collections!()).toEqual(['identities', 'tenants']);
    expect(await target.find('identities')).toEqual(await source.find('identities'));
    await expect(copyStore(source, target)).rejects.toMatchObject({ code: 'STORE_NOT_EMPTY' });
    await expect(exportStore(source, () => {}, { pageSize: 0 })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });

  it('validates arguments and opens files before touching a database', async () => {
    const folder = await directory();
    const databaseFile = join(folder, 'untouched.db');
    const sourceConfig = await config(folder, 'source', sqliteAt(databaseFile));
    const { run } = cli();
    const refused = [
      ['store-export', '--config', sourceConfig],
      ['store-export', '--config', sourceConfig, '--output', join(folder, 'a'), '--tenant', 't'],
      [
        'store-export',
        '--config',
        sourceConfig,
        '--output',
        join(folder, 'a'),
        '--output',
        join(folder, 'b'),
      ],
      ['store-import', '--config', sourceConfig, '--output', join(folder, 'a')],
      ['store-copy', '--config', sourceConfig],
      ['store-copy', '--target-config', '--config'],
    ];
    for (const argv of refused)
      await expect(run(...argv), argv.join(' ')).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
      });
    await expect(
      run('store-import', '--config', sourceConfig, '--input', join(folder, 'missing.jsonl')),
    ).rejects.toMatchObject({ code: 'ENOENT' });
    await expect(access(databaseFile)).rejects.toMatchObject({ code: 'ENOENT' });
  });

  it('removes a partial snapshot when the export fails', async () => {
    const folder = await directory();
    const databaseFile = join(folder, 'source.db');
    const source = sqliteAdapter({ filename: databaseFile });
    await populate(source);
    await source.close();
    // A store whose reads of one collection fail part-way through the export.
    const failing = join(folder, 'failing.config.mjs');
    await writeFile(
      failing,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';
const store = sqliteAdapter({ filename: ${JSON.stringify(databaseFile)} });
const bound = (target, key) => (typeof target[key] === 'function' ? target[key].bind(target) : target[key]);
const broken = (tx) => new Proxy(tx, { get: (target, key) => key === 'find'
  ? async (collection, ...rest) => { if (collection === 'sessions') throw new Error('disk failure'); return target.find(collection, ...rest); }
  : bound(target, key) });
const database = new Proxy(store, { get: (target, key) => key === 'transaction'
  ? (fn) => target.transaction((tx) => fn(broken(tx)))
  : bound(target, key) });
export default () => ({ database, secret: ${JSON.stringify(secret)}, baseURL: 'http://localhost:3000' });
`,
    );
    const output = join(folder, 'partial.jsonl');
    const { run } = cli();
    await expect(run('store-export', '--config', failing, '--output', output)).rejects.toThrow(
      'disk failure',
    );
    await expect(access(output)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});
