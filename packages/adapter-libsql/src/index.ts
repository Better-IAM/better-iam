import { AsyncLocalStorage } from 'node:async_hooks';
import { realpathSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  createClient,
  type Client,
  type InArgs,
  type InStatement,
  type ResultSet,
  type Transaction,
} from '@libsql/client';
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

interface TransactionContext {
  store: LibsqlStore;
  active: boolean;
  rollbackOnly: boolean;
}
export interface LibsqlAdapterOptions {
  /** `:memory:`, `file:./iam.db`, a plain path, or a remote `libsql:`, `https:`, `wss:` URL (Turso, sqld). */
  url: string;
  /** Bearer token for remote databases. */
  authToken?: string;
  /** Encryption key for local encrypted files. */
  encryptionKey?: string;
  /** Embedded replica: a local file kept in sync with this remote URL. */
  syncUrl?: string;
  /** Sync interval in seconds for embedded replicas. */
  syncInterval?: number;
  /** How long local file operations wait for another connection's lock (default 5000, 0-60000). */
  busyTimeoutMs?: number;
}
interface Executor {
  execute(stmt: InStatement): Promise<ResultSet>;
}

// Share locks even when more than one installed copy of the adapter is loaded.
const key = Symbol.for('better-iam.libsql.mutexes.v1');
const shared = globalThis as typeof globalThis & { [key: symbol]: unknown };
/** The per-database locks the current async call chain holds, so re-entry fails instead of waiting on itself. */
interface Held {
  mutex: object;
  active: boolean;
}
const heldKey = Symbol.for('better-iam.libsql.held.v1');
const held = (shared[heldKey] ??= new AsyncLocalStorage<readonly Held[]>()) as AsyncLocalStorage<
  readonly Held[]
>;

class Mutex {
  private tail: Promise<void> = Promise.resolve();
  async run<T>(operation: () => Promise<T>): Promise<T> {
    // Another adapter instance on the same database, called inside this instance's transaction
    // (for example copying a database onto itself), would otherwise wait for a lock its caller holds.
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
const memory = (url: string) => url === ':memory:' || url.startsWith('file::memory:');
/** A URL scheme of two or more characters; a single letter followed by a colon is a Windows drive. */
const scheme = /^[a-z][a-z0-9+.-]+:/i;

function mutexFor(url: string): Mutex {
  if (memory(url)) return new Mutex();
  let canonical = url;
  if (url.startsWith('file:') || !scheme.test(url)) {
    const path = url.split('?')[0]!;
    let absolute: string;
    try {
      // `file:///C:/x.db` and `file:///srv/x.db` are URLs; `file:x.db` and plain paths are not.
      absolute = path.startsWith('file://')
        ? fileURLToPath(path)
        : resolve(path.replace(/^file:/, ''));
    } catch {
      absolute = resolve(path.replace(/^file:(?:\/\/)?/, ''));
    }
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
        /* The driver reports an invalid path. */
      }
    }
    canonical = `file:${process.platform === 'win32' ? absolute.toLowerCase() : absolute}`;
  }
  let mutex = mutexes.get(canonical);
  if (!mutex) {
    mutex = new Mutex();
    mutexes.set(canonical, mutex);
  }
  return mutex;
}

/** libsql reports SQLite's extended code separately; the shared mapper expects it in `code`. */
function mapError(error: unknown): Error {
  if (error && typeof error === 'object' && !(error instanceof IamError)) {
    const { code, extendedCode } = error as { code?: unknown; extendedCode?: unknown };
    const effective = typeof extendedCode === 'string' ? extendedCode : code;
    if (typeof effective === 'string') return storageError({ code: effective });
  }
  return storageError(error);
}

function storageRows(result: ResultSet): StorageRow[] {
  return result.rows.map((row) => ({
    collection: String(row.collection),
    id: String(row.id),
    tenant_id: String(row.tenant_id),
    unique_key:
      row.unique_key === null || row.unique_key === undefined ? null : String(row.unique_key),
    data: String(row.data),
  }));
}

/** Plain objects keyed by column name, for the shared migration runner. */
function plainRows(result: ResultSet): Record<string, unknown>[] {
  return result.rows.map((row) =>
    Object.fromEntries(result.columns.map((column, index) => [column, row[index]])),
  );
}

function driverFor(run: Executor): RecordDriver {
  return {
    async select(collection, id, tenantId) {
      let sql =
        'SELECT collection, id, tenant_id, unique_key, data FROM iam_records WHERE collection = ?';
      const args: string[] = [collection];
      if (id !== undefined) {
        sql += ' AND id = ?';
        args.push(id);
      }
      if (tenantId !== undefined) {
        sql += ' AND tenant_id = ?';
        args.push(tenantId);
      }
      return storageRows(await run.execute({ sql: `${sql} ORDER BY id ASC`, args }));
    },
    queryCapabilities: { order: true },
    async query(query) {
      const statement = sqliteSelect(query);
      return storageRows(
        await run.execute({ sql: statement.text, args: statement.values as InArgs }),
      );
    },
    async collections() {
      return plainRows(await run.execute(COLLECTIONS_SQL)).map((row) => String(row.collection));
    },
    async insert(row) {
      await run.execute({
        sql: 'INSERT INTO iam_records (collection, id, tenant_id, unique_key, data) VALUES (?, ?, ?, ?, ?)',
        args: [row.collection, row.id, row.tenant_id, row.unique_key, row.data],
      });
    },
    async update(row) {
      const result = await run.execute({
        sql: 'UPDATE iam_records SET data = ?, unique_key = ? WHERE collection = ? AND id = ? AND tenant_id = ?',
        args: [row.data, row.unique_key, row.collection, row.id, row.tenant_id],
      });
      return result.rowsAffected === 1;
    },
    async delete(collection, id) {
      await run.execute({
        sql: 'DELETE FROM iam_records WHERE collection = ? AND id = ?',
        args: [collection, id],
      });
    },
  };
}

class LibsqlStore extends RecordStore {
  private closed = false;
  constructor(
    private readonly client: Client,
    private readonly mutex: Mutex,
    private readonly scope: AsyncLocalStorage<TransactionContext>,
    private readonly context?: TransactionContext,
    private readonly tx?: Transaction,
    private readonly location: 'memory' | 'file' | 'remote' = 'file',
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
        return await operation(driverFor(context.store.tx!));
      } catch (error) {
        context.rollbackOnly = true;
        throw mapError(error);
      }
    }
    // Root reads wait for the current transaction: an in-memory database has a single connection.
    return this.mutex.run(async () => {
      this.active();
      try {
        return await operation(driverFor(this.client));
      } catch (error) {
        throw mapError(error);
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
      // "write" starts with BEGIN IMMEDIATE, so the writer lock is held before any application read.
      let transaction: Transaction;
      try {
        transaction = await this.client.transaction('write');
      } catch (error) {
        throw mapError(error);
      }
      const context = { active: true, rollbackOnly: false } as TransactionContext;
      const store = new LibsqlStore(
        this.client,
        this.mutex,
        this.scope,
        context,
        transaction,
        this.location,
      );
      context.store = store;
      try {
        const result = await this.scope.run(context, () => fn(store));
        if (context.rollbackOnly)
          throw new IamError(
            'TRANSACTION_ABORTED',
            'A nested database operation failed; transaction rolled back',
            409,
          );
        try {
          await transaction.commit();
        } catch (error) {
          throw mapError(error);
        }
        return result;
      } catch (error) {
        try {
          await transaction.rollback();
        } catch {
          /* Preserve the original failure. */
        }
        throw error;
      } finally {
        context.active = false;
        transaction.close();
      }
    });
  }

  async migrate(): Promise<void> {
    await this.transaction(async (store) => {
      const run = (store as LibsqlStore).tx!;
      try {
        await applyMigrations(
          async (sql, values = []) =>
            plainRows(await run.execute({ sql, args: [...values] as InArgs })),
          'sqlite',
        );
      } catch (error) {
        throw mapError(error);
      }
    });
  }

  async describe(): Promise<StoreDescription> {
    const run = async (target: Executor) => {
      const execute: SqlExecutor = async (sql, values = []) =>
        plainRows(await target.execute({ sql, args: [...values] as InArgs }));
      let journalMode: string | null = null;
      try {
        const [row] = await execute('PRAGMA journal_mode');
        journalMode = row ? String(Object.values(row)[0]) : null;
      } catch {
        /* Remote servers may refuse PRAGMA statements; the queries below still surface outages. */
      }
      try {
        return await describeRecords(execute, 'libsql', {
          location: this.location,
          inMemory: this.location === 'memory',
          journalMode,
        });
      } catch (error) {
        throw mapError(error);
      }
    };
    const context = this.active();
    if (context) return run(context.store.tx!);
    return this.mutex.run(async () => {
      this.active();
      return run(this.client);
    });
  }

  async close(): Promise<void> {
    if (this.closed) return;
    if (this.active())
      throw new IamError('TRANSACTION_ACTIVE', 'Cannot close an adapter inside a transaction', 500);
    await this.mutex.run(async () => {
      if (!this.closed) {
        this.closed = true;
        this.client.close();
      }
    });
  }
}

/**
 * libSQL persistence: local files (including encrypted ones and embedded replicas) and remote Turso or sqld
 * databases through one adapter. Transactions serialize per database in this process and take the writer lock
 * (`BEGIN IMMEDIATE`) before any read; remote servers queue write transactions themselves.
 */
export function libsqlAdapter(options: LibsqlAdapterOptions): IamStore {
  if (!options || typeof options.url !== 'string' || !options.url)
    throw new IamError(
      'INVALID_CONFIG',
      'libSQL requires a url: :memory:, file:, libsql:, https:, or wss:',
    );
  if (
    !memory(options.url) &&
    !/^(file|libsql|https?|wss?):/.test(options.url) &&
    scheme.test(options.url)
  )
    throw new IamError('INVALID_CONFIG', 'Unsupported libSQL URL scheme');
  const timeout = options.busyTimeoutMs ?? 5000;
  if (!Number.isSafeInteger(timeout) || timeout < 0 || timeout > 60_000)
    throw new IamError('INVALID_CONFIG', 'busyTimeoutMs must be between 0 and 60000');
  const url = memory(options.url) || scheme.test(options.url) ? options.url : `file:${options.url}`;
  let client: Client;
  try {
    client = createClient({
      url,
      authToken: options.authToken,
      encryptionKey: options.encryptionKey,
      syncUrl: options.syncUrl,
      syncInterval: options.syncInterval,
      timeout,
      intMode: 'number',
    });
  } catch (error) {
    throw mapError(error);
  }
  return new LibsqlStore(
    client,
    mutexFor(url),
    new AsyncLocalStorage<TransactionContext>(),
    undefined,
    undefined,
    memory(url) ? 'memory' : url.startsWith('file:') ? 'file' : 'remote',
  );
}
