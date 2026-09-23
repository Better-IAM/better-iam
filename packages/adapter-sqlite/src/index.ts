import { AsyncLocalStorage } from 'node:async_hooks';
import { realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import Database from 'better-sqlite3';
import { CompiledQuery, Kysely, SqliteDialect, sql } from 'kysely';
import {
  COLLECTIONS_SQL,
  IamError,
  RecordStore,
  applyMigrations,
  describeRecords,
  sqliteSelect,
  storageError,
  type IamStore,
  type RecordDriver,
  type SqlExecutor,
  type StorageRow,
  type StoreDescription,
} from '@better-iam/core';

function executor(db: Kysely<Schema>): SqlExecutor {
  return async (text, values = []) =>
    (await db.executeQuery<Record<string, unknown>>(CompiledQuery.raw(text, [...values]))).rows;
}

const synchronousModes = ['off', 'normal', 'full', 'extra'];

interface Schema {
  iam_records: StorageRow;
}
interface TransactionContext {
  store: SqliteStore;
  active: boolean;
  rollbackOnly: boolean;
}
export interface SqliteAdapterOptions {
  filename: string;
  busyTimeoutMs?: number;
  /**
   * Journal of a database file. `wal` (default) lets readers proceed during a write and commits with
   * one sequential flush; `delete` is SQLite's classic rollback journal, for file systems without
   * shared-memory support (network shares). Ignored for `:memory:`.
   */
  journalMode?: 'wal' | 'delete';
  /**
   * `full` (default) flushes every commit to disk, so a committed revocation survives power loss.
   * `normal` in WAL mode can lose the last commits on power loss or an OS crash (never the database)
   * in exchange for much cheaper writes.
   */
  durability?: 'full' | 'normal';
}

// Share locks even when more than one installed copy of the adapter is loaded.
const key = Symbol.for('better-iam.sqlite.mutexes.v1');
const shared = globalThis as typeof globalThis & { [key: symbol]: unknown };
/** The per-file locks the current async call chain holds, so re-entry fails instead of waiting on itself. */
interface Held {
  mutex: object;
  active: boolean;
}
const heldKey = Symbol.for('better-iam.sqlite.held.v1');
const held = (shared[heldKey] ??= new AsyncLocalStorage<readonly Held[]>()) as AsyncLocalStorage<
  readonly Held[]
>;

class Mutex {
  private tail: Promise<void> = Promise.resolve();
  async run<T>(operation: () => Promise<T>): Promise<T> {
    // Another adapter instance on the same file, called inside this instance's transaction (for
    // example copying a database onto itself), would otherwise wait for a lock its caller holds.
    const chain = held.getStore();
    if (chain?.some((entry) => entry.mutex === this && entry.active))
      throw new IamError(
        'DATABASE_IN_USE',
        'This call chain already holds this database through another adapter instance',
        409,
      );
    const previous = this.tail;
    let release!: () => void;
    this.tail = new Promise<void>((done) => {
      release = done;
    });
    await previous;
    const entry: Held = { mutex: this, active: true };
    try {
      return await held.run([...(chain ?? []), entry], operation);
    } finally {
      entry.active = false;
      release();
    }
  }
}

const mutexes = (shared[key] ??= new Map<string, Mutex>()) as Map<string, Mutex>;
function mutexFor(filename: string): Mutex {
  if (filename === ':memory:') return new Mutex();
  let absolute = resolve(filename);
  // The native realpath also expands Windows 8.3 short names, so every spelling of a file
  // shares one lock.
  try {
    absolute = realpathSync.native(absolute);
  } catch {
    try {
      absolute = join(
        realpathSync.native(dirname(absolute)),
        absolute.slice(dirname(absolute).length + 1),
      );
    } catch {
      /* Driver reports an invalid path. */
    }
  }
  if (process.platform === 'win32') absolute = absolute.toLowerCase();
  let mutex = mutexes.get(absolute);
  if (!mutex) {
    mutex = new Mutex();
    mutexes.set(absolute, mutex);
  }
  return mutex;
}

/**
 * Kysely prepares every query afresh, and SQLite's compile time grows with each index an INSERT
 * or UPDATE maintains. Reusing statements by SQL text keeps writes cheap. better-sqlite3 runs
 * synchronously on one connection and this adapter never streams rows, so a cached statement is
 * never in use twice at once; SQLite recompiles cached statements itself after schema changes.
 */
function cachePreparedStatements(database: Database.Database, size = 256): void {
  const cache = new Map<string, Database.Statement>();
  const prepare = database.prepare.bind(database);
  database.prepare = ((source: string) => {
    let statement = cache.get(source);
    if (statement) cache.delete(source);
    else statement = prepare(source);
    cache.set(source, statement);
    if (cache.size > size) cache.delete(cache.keys().next().value!);
    return statement;
  }) as typeof database.prepare;
}

function driverFor(db: Kysely<Schema>): RecordDriver {
  return {
    async select(collection, id, tenantId) {
      let query = db.selectFrom('iam_records').selectAll().where('collection', '=', collection);
      if (id !== undefined) query = query.where('id', '=', id);
      if (tenantId !== undefined) query = query.where('tenant_id', '=', tenantId);
      return query.orderBy('id', 'asc').execute();
    },
    async insert(row) {
      await db.insertInto('iam_records').values(row).execute();
    },
    async update(row) {
      const result = await db
        .updateTable('iam_records')
        .set({ data: row.data, unique_key: row.unique_key })
        .where('collection', '=', row.collection)
        .where('id', '=', row.id)
        .where('tenant_id', '=', row.tenant_id)
        .executeTakeFirst();
      return result.numUpdatedRows === 1n;
    },
    async delete(collection, id) {
      await db
        .deleteFrom('iam_records')
        .where('collection', '=', collection)
        .where('id', '=', id)
        .execute();
    },
    queryCapabilities: { order: true },
    async query(query) {
      const statement = sqliteSelect(query);
      return (
        await db.executeQuery<StorageRow>(CompiledQuery.raw(statement.text, statement.values))
      ).rows;
    },
    async collections() {
      return (await executor(db)(COLLECTIONS_SQL)).map((row) => String(row.collection));
    },
  };
}

class SqliteStore extends RecordStore {
  private closed = false;
  constructor(
    private readonly db: Kysely<Schema>,
    private readonly mutex: Mutex,
    private readonly scope: AsyncLocalStorage<TransactionContext>,
    private readonly context?: TransactionContext,
    /** The underlying connection of the root store, closed directly when Kysely never opened it (no query ran). */
    private readonly raw?: Database.Database,
    private readonly inMemory = false,
  ) {
    super();
  }

  private active(): TransactionContext | undefined {
    if (this.closed) throw new IamError('STORE_CLOSED', 'Database adapter is closed', 500);
    const context = this.context ?? this.scope.getStore();
    if (context && !context.active)
      throw new IamError('TRANSACTION_CLOSED', 'Transaction has already completed', 500);
    return context;
  }

  protected async read<T>(operation: (driver: RecordDriver) => Promise<T>): Promise<T> {
    const context = this.active();
    if (context) {
      try {
        return await operation(driverFor(context.store.db));
      } catch (error) {
        context.rollbackOnly = true;
        throw storageError(error);
      }
    }
    return this.mutex.run(async () => {
      this.active();
      try {
        return await operation(driverFor(this.db));
      } catch (error) {
        throw storageError(error);
      }
    });
  }

  protected async write<T>(operation: (driver: RecordDriver) => Promise<T>): Promise<T> {
    if (!this.active())
      throw new IamError('TRANSACTION_REQUIRED', 'Database writes require transaction()', 500);
    return this.read(operation);
  }

  async transaction<T>(fn: (tx: IamStore) => Promise<T>): Promise<T> {
    const current = this.active();
    if (current) {
      try {
        return await fn(current.store);
      } catch (error) {
        current.rollbackOnly = true;
        throw error;
      }
    }
    return this.mutex.run(async () => {
      this.active();
      return this.db.connection().execute(async (connection) => {
        // Acquire the SQLite writer lock before any reads, and keep one connection
        // across awaited application code. A deferred transaction is not sufficient.
        try {
          await sql`BEGIN IMMEDIATE`.execute(connection);
        } catch (error) {
          throw storageError(error);
        }
        const context = { active: true, rollbackOnly: false } as TransactionContext;
        const tx = new SqliteStore(
          connection,
          this.mutex,
          this.scope,
          context,
          undefined,
          this.inMemory,
        );
        context.store = tx;
        try {
          const result = await this.scope.run(context, () => fn(tx));
          if (context.rollbackOnly)
            throw new IamError(
              'TRANSACTION_ABORTED',
              'A nested database operation failed; transaction rolled back',
              409,
            );
          try {
            await sql`COMMIT`.execute(connection);
          } catch (error) {
            throw storageError(error);
          }
          return result;
        } catch (error) {
          try {
            await sql`ROLLBACK`.execute(connection);
          } catch {
            /* Preserve the original failure. */
          }
          throw error;
        } finally {
          context.active = false;
        }
      });
    });
  }

  async migrate(): Promise<void> {
    await this.transaction(async (store) => {
      const db = (store as SqliteStore).db;
      try {
        await applyMigrations(executor(db), 'sqlite');
      } catch (error) {
        throw storageError(error);
      }
    });
  }

  async describe(): Promise<StoreDescription> {
    const run = async (db: Kysely<Schema>) => {
      const execute = executor(db);
      const pragma = async (name: string) => {
        const [row] = await execute(`PRAGMA ${name}`);
        return row ? Object.values(row)[0] : undefined;
      };
      try {
        const pageSize = Number(await pragma('page_size'));
        return await describeRecords(execute, 'sqlite', {
          journalMode: String(await pragma('journal_mode')),
          synchronous: synchronousModes[Number(await pragma('synchronous'))] ?? null,
          sizeBytes: Number(await pragma('page_count')) * pageSize,
          freeBytes: Number(await pragma('freelist_count')) * pageSize,
          inMemory: this.inMemory,
        });
      } catch (error) {
        throw storageError(error);
      }
    };
    const context = this.active();
    if (context) return run(context.store.db);
    return this.mutex.run(async () => {
      this.active();
      return run(this.db);
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    if (this.active())
      throw new IamError('TRANSACTION_ACTIVE', 'Cannot close an adapter inside a transaction', 500);
    await this.mutex.run(async () => {
      if (!this.closed) {
        this.closed = true;
        await this.db.destroy();
        // Kysely opens the driver lazily; a store closed before its first query would otherwise hold the file.
        if (this.raw?.open) this.raw.close();
      }
    });
  }
}

/**
 * SQLite serializes operations per canonical filename in this process. SQLite's
 * own BEGIN IMMEDIATE lock coordinates other processes with a bounded wait.
 * Use PostgreSQL when sustained concurrent writes or large datasets are expected.
 */
export function sqliteAdapter(options: SqliteAdapterOptions): IamStore {
  if (
    !options ||
    typeof options.filename !== 'string' ||
    !options.filename ||
    options.filename.startsWith('file:')
  )
    throw new IamError(
      'INVALID_CONFIG',
      'SQLite requires a filename or :memory:; URI filenames are unsupported',
    );
  const timeout = options.busyTimeoutMs ?? 5000;
  if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > 60_000)
    throw new IamError('INVALID_CONFIG', 'busyTimeoutMs must be between 0 and 60000');
  if (options.journalMode !== undefined && !['wal', 'delete'].includes(options.journalMode))
    throw new IamError('INVALID_CONFIG', 'journalMode must be wal or delete');
  if (options.durability !== undefined && !['full', 'normal'].includes(options.durability))
    throw new IamError('INVALID_CONFIG', 'durability must be full or normal');
  const mutex = mutexFor(options.filename);
  let database: Database.Database;
  try {
    database = new Database(options.filename, { timeout });
    database.pragma('foreign_keys = ON');
    if (options.filename !== ':memory:')
      database.pragma(`journal_mode = ${options.journalMode === 'delete' ? 'DELETE' : 'WAL'}`);
    database.pragma(`synchronous = ${options.durability === 'normal' ? 'NORMAL' : 'FULL'}`);
    cachePreparedStatements(database);
  } catch (error) {
    throw storageError(error);
  }
  return new SqliteStore(
    new Kysely<Schema>({ dialect: new SqliteDialect({ database }) }),
    mutex,
    new AsyncLocalStorage<TransactionContext>(),
    undefined,
    database,
    options.filename === ':memory:',
  );
}
