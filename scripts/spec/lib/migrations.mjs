// spec/storage/migrations/{sqlite,postgres,libsql}/: the exact SQL each reference adapter sends to its database when
// `migrate()` runs, captured by running the real adapters against recording drivers: one NNNN_<name>.sql per schema
// migration (one statement per line, `;`-terminated), bookkeeping.sql (the iam_migrations / iam_schema_version
// statements), and runner.json (the complete ordered sequence with bound parameters, for a fresh database and for an
// up-to-date one, plus connection setup). The postgres adapter's pg.Pool, the sqlite adapter's better-sqlite3 handle
// and the libsql adapter's client are wrapped; nothing else is simulated.
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { dist, fromPackage, json, root } from './util.mjs';

const FIXED_NOW = 1767225600000; // 2026-01-01T00:00:00.000Z, the applied_at the vectors record

/** Answers for the migration runner's reads: a fresh database, or one where every migration already ran. */
function answer(text, state) {
  if (/^SELECT version FROM iam_schema_version/.test(text))
    return state.current ? [{ version: 1 }] : [];
  if (/^SELECT name FROM iam_migrations/.test(text))
    return state.current ? state.names.map((name) => ({ name })) : [];
  return [];
}

async function capturePostgres(state) {
  const pg = (await fromPackage('adapter-postgres', 'pg')).default;
  const { postgresAdapter } = await dist('adapter-postgres');
  const log = [];
  class RecordingPool {
    constructor(config) {
      log.push({
        event: 'pool',
        config: { max: config.max, connectionTimeoutMillis: config.connectionTimeoutMillis },
      });
    }
    async connect() {
      return {
        query: async (text, values = []) => {
          log.push({ sql: text, params: values });
          const rows = answer(text, state);
          return { rows, rowCount: rows.length, command: text.split(' ')[0].toUpperCase() };
        },
        release() {},
      };
    }
    on() {
      return this;
    }
    async end() {}
  }
  const original = pg.Pool;
  pg.Pool = RecordingPool;
  try {
    const store = postgresAdapter({ connectionString: 'postgres://spec@localhost/spec' });
    await store.migrate();
    await store.close();
  } finally {
    pg.Pool = original;
  }
  return log;
}

async function captureSqlite(state) {
  const Database = (await fromPackage('adapter-sqlite', 'better-sqlite3')).default;
  const { sqliteAdapter } = await dist('adapter-sqlite');
  const log = [];
  const prepare = Database.prototype.prepare;
  const pragma = Database.prototype.pragma;
  Database.prototype.pragma = function (source, options) {
    log.push({ sql: `PRAGMA ${source}`, params: [], via: 'pragma' });
    return pragma.call(this, source, options);
  };
  Database.prototype.prepare = function (source) {
    const statement = prepare.call(this, source);
    const record = (params) => log.push({ sql: source, params: [...(params ?? [])] });
    return new Proxy(statement, {
      get(target, property) {
        const value = Reflect.get(target, property, target);
        if (
          property === 'all' ||
          property === 'run' ||
          property === 'get' ||
          property === 'iterate'
        )
          return (...args) => {
            record(args[0]);
            return value.apply(target, args);
          };
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
  };
  try {
    const store = sqliteAdapter({ filename: ':memory:' });
    if (state.current) {
      // Bring the database up to date first, then record a second run.
      await store.migrate();
      log.length = 0;
    }
    await store.migrate();
    await store.close();
  } finally {
    Database.prototype.prepare = prepare;
    Database.prototype.pragma = pragma;
  }
  return log;
}

async function captureLibsql(state) {
  const { libsqlAdapter } = await dist('adapter-libsql');
  const log = [];
  const store = libsqlAdapter({ url: ':memory:' });
  const client = store.client;
  if (!client || typeof client.transaction !== 'function')
    throw new Error('libsql adapter: client not found');
  const wrap = (executor) => {
    const execute = executor.execute.bind(executor);
    executor.execute = async (statement) => {
      const sql = typeof statement === 'string' ? statement : statement.sql;
      const args = typeof statement === 'string' ? [] : [...(statement.args ?? [])];
      log.push({ sql, params: args });
      return execute(statement);
    };
    return executor;
  };
  if (state.current) await store.migrate();
  const transaction = client.transaction.bind(client);
  client.transaction = async (mode) => {
    log.push({
      event: `client.transaction('${mode}')`,
      note: 'the libSQL client opens it with BEGIN IMMEDIATE',
    });
    const tx = wrap(await transaction(mode));
    const commit = tx.commit.bind(tx);
    const rollback = tx.rollback.bind(tx);
    tx.commit = async () => {
      log.push({ event: 'commit' });
      return commit();
    };
    tx.rollback = async () => {
      log.push({ event: 'rollback' });
      return rollback();
    };
    return tx;
  };
  await store.migrate();
  await store.close();
  return log;
}

export async function generateMigrations(output) {
  for (const [file, fragments] of [
    [
      'packages/adapter-sqlite/src/index.ts',
      [
        "database.pragma('foreign_keys = ON')",
        "journal_mode = ${options.journalMode === 'delete' ? 'DELETE' : 'WAL'}",
        "synchronous = ${options.durability === 'normal' ? 'NORMAL' : 'FULL'}",
        'BEGIN IMMEDIATE',
        'options.busyTimeoutMs ?? 5000',
      ],
    ],
    [
      'packages/adapter-postgres/src/index.ts',
      [
        "set_config('lock_timeout'",
        'pg_advisory_xact_lock(1647206759, 1)',
        'MIGRATION_LOCK_TIMEOUT_MS = 10 * 60_000',
        'options.lockTimeoutMs ?? 5000',
        ".setIsolationLevel('read committed')",
      ],
    ],
    ['packages/adapter-libsql/src/index.ts', ["this.client.transaction('write')"]],
  ]) {
    const text = await readFile(join(root, file), 'utf8');
    for (const fragment of fragments)
      if (!text.includes(fragment))
        throw new Error(
          `${file} no longer contains ${fragment}: update scripts/spec/lib/migrations.mjs`,
        );
  }
  const sql = await dist('core', 'sql.js');
  const names = sql.schemaMigrations('sqlite').map((migration) => migration.name);
  const realNow = Date.now;
  Date.now = () => FIXED_NOW;
  const runs = {};
  try {
    for (const [dialect, capture] of [
      ['postgres', capturePostgres],
      ['sqlite', captureSqlite],
      ['libsql', captureLibsql],
    ]) {
      runs[dialect] = {
        fresh: await capture({ current: false, names }),
        current: await capture({ current: true, names }),
      };
    }
  } finally {
    Date.now = realNow;
  }
  let files = 0;
  for (const dialect of ['postgres', 'sqlite', 'libsql']) {
    const migrations = sql.schemaMigrations(dialect === 'libsql' ? 'sqlite' : dialect);
    const fresh = runs[dialect].fresh;
    const executed = fresh.filter((entry) => entry.sql !== undefined).map((entry) => entry.sql);
    // Every statement of every migration must appear in the captured run, in order.
    let cursor = 0;
    for (const migration of migrations)
      for (const statement of migration.statements) {
        const at = executed.indexOf(statement, cursor);
        if (at < 0)
          throw new Error(`${dialect}: ${migration.name} statement not executed: ${statement}`);
        cursor = at + 1;
      }
    migrations.forEach((migration) => {
      output.add(
        `storage/migrations/${dialect}/${migration.name}.sql`,
        migration.statements.map((statement) => `${statement};\n`).join(''),
      );
      files++;
    });
    const migrationStatements = new Set(migrations.flatMap((migration) => migration.statements));
    const bookkeeping = [];
    for (const statement of executed)
      if (/iam_migrations|iam_schema_version/.test(statement) && !bookkeeping.includes(statement))
        bookkeeping.push(statement);
    output.add(
      `storage/migrations/${dialect}/bookkeeping.sql`,
      bookkeeping.map((statement) => `${statement};\n`).join(''),
    );
    files++;
    const tag = (entry) =>
      entry.sql === undefined
        ? entry
        : {
            ...entry,
            kind: migrationStatements.has(entry.sql)
              ? 'migration'
              : /iam_migrations|iam_schema_version/.test(entry.sql)
                ? 'bookkeeping'
                : 'adapter',
          };
    output.add(
      `storage/migrations/${dialect}/runner.json`,
      json(
        {
          adapter: `@better-iam/adapter-${dialect}`,
          dialect: dialect === 'libsql' ? 'sqlite' : dialect,
          description:
            'Everything the adapter sends while migrate() runs, in order, captured from the real adapter (adapter construction included). `fresh` is an empty database; `current` one where every migration ran already. applied_at is the clock at migrate() time (fixed here).',
          appliedAtClock: FIXED_NOW,
          migrations: migrations.map((migration) => ({
            name: migration.name,
            statements: migration.statements.length,
          })),
          fresh: fresh.map(tag),
          current: runs[dialect].current.map(tag),
        },
        { sorted: false },
      ),
    );
    files++;
  }
  output.add(
    'storage/migrations/index.json',
    json(
      {
        source: 'packages/core/src/sql.ts schemaMigrations / applyMigrations',
        names,
        dialects: {
          postgres: {
            adapter: '@better-iam/adapter-postgres',
            sqlDialect: 'postgres',
            placeholders: '$1, $2, ...',
          },
          sqlite: {
            adapter: '@better-iam/adapter-sqlite',
            sqlDialect: 'sqlite',
            placeholders: '?',
          },
          libsql: {
            adapter: '@better-iam/adapter-libsql',
            sqlDialect: 'sqlite',
            placeholders: '?',
          },
        },
        statements: Object.fromEntries(
          ['postgres', 'sqlite'].map((dialect) => [
            dialect,
            Object.fromEntries(
              sql
                .schemaMigrations(dialect)
                .map((migration) => [migration.name, [...migration.statements]]),
            ),
          ]),
        ),
        rules: [
          'applyMigrations runs inside the adapter write transaction: create iam_schema_version, refuse any version other than 1 (SCHEMA_VERSION 500), create iam_migrations, then for each migration not yet recorded run its statements and insert (name, applied_at), and finally insert the schema version row (ON CONFLICT DO NOTHING).',
          'PostgreSQL runs encodeLegacyPostgresRows before 0002_query_indexes (rewrites legacy rows jsonb cannot hold).',
          'A released migration never changes; new schema work is a new step.',
          "SQLite adapter connection setup (better-sqlite3, busy timeout busyTimeoutMs default 5000): PRAGMA foreign_keys = ON; for a file database PRAGMA journal_mode = WAL (DELETE with journalMode: 'delete'); PRAGMA synchronous = FULL (NORMAL with durability: 'normal'). Every write transaction starts with BEGIN IMMEDIATE and ends with COMMIT or ROLLBACK.",
          "PostgreSQL adapter: every transaction is start transaction isolation level read committed, SELECT set_config('lock_timeout', '<ms>ms', true) (lockTimeoutMs, default 5000; migrations 600000), SELECT pg_advisory_xact_lock(1647206759, 1), then the work and commit.",
          "libSQL adapter: client.transaction('write') (BEGIN IMMEDIATE on local databases); the shared migration runner uses the sqlite dialect.",
        ],
      },
      { sorted: false },
    ),
  );
  files++;
  return `migrations (${names.length} migrations x 3 dialects, ${files} files)`;
}
