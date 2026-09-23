import { AsyncLocalStorage } from 'node:async_hooks';
import { CompiledQuery, Kysely, PostgresDialect, sql } from 'kysely';
import pg from 'pg';
import {
  COLLECTIONS_SQL,
  IamError,
  RecordStore,
  applyMigrations,
  decodeJsonbDocument,
  describeRecords,
  encodeJsonbDocument,
  encodeLegacyPostgresRows,
  isMissingTable,
  postgresSelect,
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

/** Documents are stored jsonb-compatible (see `encodeJsonbDocument`) and decoded on every read. */
const stored = (row: StorageRow): StorageRow => ({ ...row, data: encodeJsonbDocument(row.data) });
const loaded = (rows: StorageRow[]): StorageRow[] =>
  rows.map((row) => ({ ...row, data: decodeJsonbDocument(row.data) }));
/** How long a migration waits for other instances' transactions, including another migration. */
const MIGRATION_LOCK_TIMEOUT_MS = 10 * 60_000;

interface Schema {
  iam_records: StorageRow;
}
interface TransactionContext {
  store: PostgresStore;
  active: boolean;
  rollbackOnly: boolean;
}
export interface PostgresAdapterOptions {
  connectionString: string;
  poolSize?: number;
  lockTimeoutMs?: number;
}

function driverFor(db: Kysely<Schema>): RecordDriver {
  return {
    async select(collection, id, tenantId) {
      let query = db.selectFrom('iam_records').selectAll().where('collection', '=', collection);
      if (id !== undefined) query = query.where('id', '=', id);
      if (tenantId !== undefined) query = query.where('tenant_id', '=', tenantId);
      return loaded(await query.orderBy('id', 'asc').execute());
    },
    async insert(row) {
      await db.insertInto('iam_records').values(stored(row)).execute();
    },
    async update(row) {
      const result = await db
        .updateTable('iam_records')
        .set({ data: encodeJsonbDocument(row.data), unique_key: row.unique_key })
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
    queryCapabilities: { json: true, order: true },
    async query(query) {
      const statement = postgresSelect(query);
      return loaded(
        (await db.executeQuery<StorageRow>(CompiledQuery.raw(statement.text, statement.values)))
          .rows,
      );
    },
    async collections() {
      return (await executor(db)(COLLECTIONS_SQL)).map((row) => String(row.collection));
    },
  };
}

class PostgresStore extends RecordStore {
  private closed = false;
  constructor(
    private readonly db: Kysely<Schema>,
    private readonly scope: AsyncLocalStorage<TransactionContext>,
    private readonly timeout: number,
    private readonly context?: TransactionContext,
    /** The pool, also on transaction handles: `describe()` never runs on a transaction. */
    private readonly pool: Kysely<Schema> = db,
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
    try {
      return await operation(driverFor(context?.store.db ?? this.db));
    } catch (error) {
      if (context) context.rollbackOnly = true;
      throw storageError(error);
    }
  }

  protected async write<T>(operation: (driver: RecordDriver) => Promise<T>): Promise<T> {
    if (!this.active())
      throw new IamError('TRANSACTION_REQUIRED', 'Database writes require transaction()', 500);
    return this.read(operation);
  }

  transaction<T>(fn: (tx: IamStore) => Promise<T>): Promise<T> {
    return this.serialized(fn, this.timeout);
  }

  private async serialized<T>(fn: (tx: IamStore) => Promise<T>, lockTimeoutMs: number): Promise<T> {
    const current = this.active();
    if (current) {
      try {
        return await fn(current.store);
      } catch (error) {
        current.rollbackOnly = true;
        throw error;
      }
    }
    let callbackFailure: { error: unknown } | undefined;
    try {
      return await this.db
        .transaction()
        .setIsolationLevel('read committed')
        .execute(async (connection) => {
          // All application transactions take the same database advisory lock before
          // reading. READ COMMITTED deliberately takes its data snapshot AFTER this
          // wait; SERIALIZABLE would pin a stale snapshot while waiting for the lock.
          await sql`SELECT set_config('lock_timeout', ${`${lockTimeoutMs}ms`}, true)`.execute(
            connection,
          );
          await sql`SELECT pg_advisory_xact_lock(1647206759, 1)`.execute(connection);
          const context = { active: true, rollbackOnly: false } as TransactionContext;
          const tx = new PostgresStore(connection, this.scope, this.timeout, context, this.pool);
          context.store = tx;
          try {
            const result = await this.scope.run(context, () => fn(tx));
            if (context.rollbackOnly)
              throw new IamError(
                'TRANSACTION_ABORTED',
                'A nested database operation failed; transaction rolled back',
                409,
              );
            return result;
          } catch (error) {
            callbackFailure = { error };
            throw error;
          } finally {
            context.active = false;
          }
        });
    } catch (error) {
      if (callbackFailure && callbackFailure.error === error) throw error;
      throw storageError(error);
    }
  }

  async migrate(): Promise<void> {
    // Index builds on a large table can take minutes; other instances migrating at the same time
    // wait for the lock instead of failing with STORAGE_BUSY.
    await this.serialized(async (store) => {
      const db = (store as PostgresStore).db;
      try {
        await applyMigrations(executor(db), 'postgres', { before: encodeLegacyPostgresRows });
      } catch (error) {
        throw storageError(error);
      }
    }, MIGRATION_LOCK_TIMEOUT_MS);
  }

  /**
   * Always runs on the pool, never on a caller's transaction: a probe of a table that does not
   * exist yet would abort that transaction. Inside a transaction it therefore reports committed
   * data and needs a free pool connection.
   */
  async describe(): Promise<StoreDescription> {
    this.active();
    const execute = executor(this.pool);
    const single = async (text: string) => {
      try {
        const [row] = await execute(text);
        const value = row ? Object.values(row)[0] : undefined;
        return value === undefined || value === null ? null : value;
      } catch (error) {
        if (isMissingTable(error)) return null;
        throw error;
      }
    };
    try {
      const size = await single("SELECT pg_total_relation_size('iam_records') AS size");
      const version = await single('SHOW server_version');
      const synchronousCommit = await single('SHOW synchronous_commit');
      return await describeRecords(execute, 'postgres', {
        serverVersion: version === null ? null : String(version),
        synchronousCommit: synchronousCommit === null ? null : String(synchronousCommit),
        sizeBytes: size === null ? null : Number(size),
        lockTimeoutMs: this.timeout,
      });
    } catch (error) {
      throw storageError(error);
    }
  }

  async close(): Promise<void> {
    if (this.closed) return;
    if (this.active())
      throw new IamError('TRANSACTION_ACTIVE', 'Cannot close an adapter inside a transaction', 500);
    this.closed = true;
    await this.db.destroy();
  }
}

/** Transactions serialize through a database advisory lock, including other adapter instances. */
export function postgresAdapter(options: PostgresAdapterOptions): IamStore {
  if (
    !options ||
    typeof options.connectionString !== 'string' ||
    !/^postgres(?:ql)?:\/\//u.test(options.connectionString)
  )
    throw new IamError('INVALID_CONFIG', 'A PostgreSQL connection string is required');
  const timeout = options.lockTimeoutMs ?? 5000;
  const max = options.poolSize ?? 10;
  if (
    !Number.isSafeInteger(timeout) ||
    timeout < 1 ||
    timeout > 60_000 ||
    !Number.isSafeInteger(max) ||
    max < 1 ||
    max > 100
  )
    throw new IamError('INVALID_CONFIG', 'Invalid PostgreSQL pool size or lock timeout');
  const pool = new pg.Pool({
    connectionString: options.connectionString,
    max,
    connectionTimeoutMillis: timeout,
  });
  return new PostgresStore(
    new Kysely<Schema>({ dialect: new PostgresDialect({ pool }) }),
    new AsyncLocalStorage<TransactionContext>(),
    timeout,
  );
}
