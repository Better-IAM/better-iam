import type { FindOptions, IamStore, OrderOptions, StoredRecord } from './index.js';

/** One storage call observed by `instrumentStore`. Never carries record data or filter values. */
export interface StoreCall {
  method: 'get' | 'find' | 'findOrdered' | 'insert' | 'put' | 'delete' | 'collections' | 'describe';
  /** The collection, or `*` for whole-store calls (`collections`, `describe`). */
  collection: string;
  /** Filter keys of a `find`, sorted; values are omitted because they can be secrets or hashes. */
  filterKeys?: string[];
  /** Pagination of a `find`, when given. A keyset cursor is reported as `keyset: true`, not its id. */
  page?: Omit<FindOptions, 'after'> & { keyset?: true };
  /**
   * Records returned (`find`, `get`) or written (`insert`, `put`, `delete`: 1); collections
   * listed or described for whole-store calls.
   */
  records: number;
  durationMs: number;
  /**
   * The call was made through the handle a `transaction()` callback received. Calls on the outer
   * store that an adapter routes into the current transaction report false.
   */
  inTransaction: boolean;
  /** The call failed; `records` is 0. */
  failed: boolean;
}

/**
 * Wraps a store so every data call is reported to `onCall` (reads, writes, `collections`, and
 * `describe`; `transaction`, `migrate`, and `close` pass straight through), for slow-query logging, capacity planning,
 * and tests that bound how much work an operation does. The wrapper adds no behavior: results,
 * errors, and transactions are the underlying store's. `onCall` runs synchronously after each
 * call; exceptions it throws are ignored.
 */
export function instrumentStore(
  store: IamStore,
  onCall: (call: StoreCall) => void,
  now: () => number = () => performance.now(),
): IamStore {
  const report = (call: StoreCall) => {
    try {
      onCall(call);
    } catch {
      /* Observability must never change the outcome of a storage call. */
    }
  };
  const wrap = (target: IamStore, inTransaction: boolean): IamStore => {
    const timed = async <T>(
      method: StoreCall['method'],
      collection: string,
      run: () => Promise<T>,
      count: (value: T) => number,
      extra: Partial<StoreCall> = {},
    ): Promise<T> => {
      const started = now();
      try {
        const value = await run();
        report({
          method,
          collection,
          records: count(value),
          durationMs: now() - started,
          inTransaction,
          failed: false,
          ...extra,
        });
        return value;
      } catch (error) {
        report({
          method,
          collection,
          records: 0,
          durationMs: now() - started,
          inTransaction,
          failed: true,
          ...extra,
        });
        throw error;
      }
    };
    const wrapped: IamStore = {
      get: <T extends StoredRecord = StoredRecord>(collection: string, id: string) =>
        timed(
          'get',
          collection,
          () => target.get<T>(collection, id),
          (value) => (value ? 1 : 0),
        ),
      find: <T extends StoredRecord = StoredRecord>(
        collection: string,
        filter?: Record<string, unknown>,
        options?: FindOptions,
      ) =>
        timed(
          'find',
          collection,
          () => target.find<T>(collection, filter, options),
          (value) => value.length,
          {
            filterKeys: Object.keys(filter ?? {}).sort(),
            ...(options &&
            (options.limit !== undefined ||
              options.offset !== undefined ||
              options.after !== undefined)
              ? {
                  page: {
                    ...(options.offset !== undefined ? { offset: options.offset } : {}),
                    ...(options.limit !== undefined ? { limit: options.limit } : {}),
                    ...(options.after !== undefined ? { keyset: true as const } : {}),
                  },
                }
              : {}),
          },
        ),
      ...(target.findOrdered
        ? {
            findOrdered: <T extends StoredRecord = StoredRecord>(
              collection: string,
              filter: Record<string, unknown>,
              order: OrderOptions,
            ) =>
              timed(
                'findOrdered',
                collection,
                () => target.findOrdered!<T>(collection, filter, order),
                (value) => value.length,
                {
                  filterKeys: Object.keys(filter ?? {}).sort(),
                  page: { offset: order.offset, limit: order.limit },
                },
              ),
          }
        : {}),
      insert: <T extends StoredRecord>(collection: string, record: T) =>
        timed(
          'insert',
          collection,
          () => target.insert(collection, record),
          () => 1,
        ),
      put: <T extends StoredRecord>(collection: string, record: T) =>
        timed(
          'put',
          collection,
          () => target.put(collection, record),
          () => 1,
        ),
      delete: (collection: string, id: string) =>
        timed(
          'delete',
          collection,
          () => target.delete(collection, id),
          () => 1,
        ),
      transaction: <T>(fn: (tx: IamStore) => Promise<T>) =>
        target.transaction((tx) => fn(wrap(tx, true))),
      ...(target.collections
        ? {
            collections: () =>
              timed(
                'collections',
                '*',
                () => target.collections!(),
                (names) => names.length,
              ),
          }
        : {}),
      ...(target.describe
        ? {
            describe: () =>
              timed(
                'describe',
                '*',
                () => target.describe!(),
                (description) => description.collections.length,
              ),
          }
        : {}),
      migrate: () => target.migrate(),
      close: () => target.close(),
    };
    return wrapped;
  };
  return wrap(store, false);
}

/** Totals of a list of calls, grouped by method and collection (`find:sessions`). */
export function summarizeStoreCalls(
  calls: readonly StoreCall[],
): Record<string, { calls: number; records: number; durationMs: number }> {
  const summary: Record<string, { calls: number; records: number; durationMs: number }> = {};
  for (const call of calls) {
    const key = `${call.method}:${call.collection}`;
    const entry = (summary[key] ??= { calls: 0, records: 0, durationMs: 0 });
    entry.calls++;
    entry.records += call.records;
    entry.durationMs += call.durationMs;
  }
  return summary;
}
