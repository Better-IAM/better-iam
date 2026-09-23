import {
  IamError,
  type FindOptions,
  type IamStore,
  type OrderOptions,
  type StoredRecord,
} from './index.js';

/** Low-level adapter building blocks. Applications should use the IamStore contract. */
export interface StorageRow {
  collection: string;
  id: string;
  tenant_id: string;
  unique_key: string | null;
  data: string;
}

/**
 * A typed equality test on one top-level JSON field. Each kind matches exactly the records the
 * in-memory `find` filter would match for that field, so a driver can evaluate it in SQL.
 */
export type FieldCondition =
  | { field: string; kind: 'string'; value: string }
  | { field: string; kind: 'number'; value: number }
  | { field: string; kind: 'boolean'; value: boolean }
  /** The field is present and JSON `null`. */
  | { field: string; kind: 'null' }
  /** The field is not present in the stored document. */
  | { field: string; kind: 'absent' }
  /** Deep JSON equality with an object or array (object key order ignored, array order kept). */
  | { field: string; kind: 'json'; value: string };

export interface RecordQuery {
  collection: string;
  id?: string;
  tenantId?: string;
  uniqueKey?: string;
  conditions: FieldCondition[];
  /** Only rows whose id sorts after this id in code-point order (`id > after`); never with `order`. */
  after?: string;
  /**
   * Order by a numeric top-level field instead of id (ties by id, ascending), keeping only rows
   * whose field is a JSON number within `[from, to]`. Requires `queryCapabilities.order`.
   */
  order?: { field: string; direction: 'asc' | 'desc'; from?: number; to?: number };
  /**
   * Present only when the query expresses the caller's complete filter. The driver then returns
   * the requested page of rows ordered by id in code-point (UTF-8 byte) order, or by `order`.
   */
  page?: { offset: number; limit?: number };
}

export interface QueryCapabilities {
  /** The driver evaluates `json` (object and array) conditions. Scalar kinds are always required. */
  json?: boolean;
  /** The driver evaluates `RecordQuery.order`. */
  order?: boolean;
}

/** Numeric fields SQL adapters index for `findOrdered` within a tenant (audit time and sequence). */
export const ORDERED_FIELDS: readonly string[] = Object.freeze(['timestamp', 'sequence']);
/**
 * Numeric fields SQL adapters index for `findOrdered` across a whole collection, so retention
 * sweeps find expired and long-delivered records without scanning (`0004_expiry_indexes`).
 */
export const EXPIRY_FIELDS: readonly string[] = Object.freeze([
  'expiresAt',
  'deliveredAt',
  'failedAt',
]);

export interface RecordDriver {
  select(collection: string, id?: string, tenantId?: string): Promise<StorageRow[]>;
  insert(row: StorageRow): Promise<void>;
  update(row: StorageRow): Promise<boolean>;
  delete(collection: string, id: string): Promise<void>;
  /**
   * Optional filtered read. It must return exactly the rows of `collection` matching every column
   * and field condition, ordered by id in code-point order, applying `page` when present. Drivers
   * without it are still correct: `find` then narrows by collection, id, and tenant only.
   */
  query?(query: RecordQuery): Promise<StorageRow[]>;
  queryCapabilities?: QueryCapabilities;
  /** Optional: the distinct collection names in the table, sorted. */
  collections?(): Promise<string[]>;
}

/** Field names a driver may inline into SQL paths. Other names are filtered in memory. */
export const QUERYABLE_FIELD = /^[A-Za-z_][A-Za-z0-9_]{0,127}$/;

/**
 * The lookup fields each schema step indexes (SQLite and libSQL; PostgreSQL's document index covers
 * every field). A released step never changes: new fields get a new step.
 */
export const LOOKUP_INDEX_STEPS: Readonly<Record<string, readonly string[]>> = Object.freeze({
  '0002_query_indexes': Object.freeze([
    'tokenHash',
    'identityId',
    'email',
    'parentId',
    'subjectId',
    'groupId',
    'roleId',
    'credentialId',
    'originalIdentityId',
    'impersonatorSessionId',
    'accountId',
    'clientId',
    'uidHash',
    'userCodeHash',
    'grantIdHash',
    'connectionId',
    'targetId',
    'streamId',
    'jti',
  ]),
  // Session cascades: role and temporary sessions by their source session, and by trust.
  '0005_lookup_indexes': Object.freeze(['sourceSessionId', 'trustId']),
});

/**
 * High-cardinality string fields looked up across tenants or inside large collections (sessions,
 * identities, memberships, bindings, protocol artifacts, delivery queues). SQL adapters may index
 * them; the list only affects performance, never results. Every index adds work to each write, so
 * keep it to fields on hot or unscoped lookup paths.
 */
export const INDEXED_FIELDS: readonly string[] = Object.freeze(
  Object.values(LOOKUP_INDEX_STEPS).flat(),
);

function validIdentifier(value: unknown, name: string): asserts value is string {
  // Keep composite natural-key indexes below PostgreSQL's B-tree tuple limit,
  // including multibyte UTF-8 input. Apply the same limit in every adapter.
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.length > 512 ||
    new TextEncoder().encode(value).byteLength > 512 ||
    /[\u0000-\u001f]/u.test(value)
  )
    throw new IamError(
      'INVALID_RECORD',
      `${name} must be a nonempty string of at most 512 UTF-8 bytes`,
    );
}

/**
 * Refuses identifiers (collection, id, tenant, natural key) that a database column cannot hold
 * unchanged. Drivers encode strings as UTF-8, which turns an unpaired surrogate into U+FFFD, so
 * two different ids would share one row.
 */
function storableIdentifier(value: unknown, name: string): asserts value is string {
  validIdentifier(value, name);
  if (!storableString(value))
    throw new IamError('INVALID_RECORD', `${name} cannot contain unpaired surrogates`);
}

/**
 * Reserved object key of the PostgreSQL value encoding (`encodeJsonbDocument`), which stores
 * strings jsonb cannot hold. Filters whose objects use it are evaluated in memory.
 */
export const JSONB_ESCAPE_KEY = '\u0001better-iam';

/** Most typed conditions `planQuery` hands to a driver; further keys are filtered in memory. */
export const MAX_QUERY_CONDITIONS = 24;

/**
 * True when the string has no U+0000 and no unpaired surrogate. Such strings can be stored as
 * record values, but database text comparisons cannot represent them, so `find` evaluates filters
 * holding them in memory. Identifiers must satisfy it.
 */
export function storableString(value: string): boolean {
  for (let index = 0; index < value.length; index++) {
    const unit = value.charCodeAt(index);
    if (unit === 0) return false;
    if (unit >= 0xd800 && unit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return false;
      index++;
    } else if (unit >= 0xdc00 && unit <= 0xdfff) return false;
  }
  return true;
}

function jsonValue(value: unknown, ancestors = new Set<object>(), depth = 0): void {
  if (depth > 64) throw new IamError('INVALID_RECORD', 'Record nesting exceeds 64 levels');
  if (
    value === null ||
    value === undefined ||
    typeof value === 'string' ||
    typeof value === 'boolean'
  )
    return;
  if (typeof value === 'number' && Number.isFinite(value)) return;
  if (
    typeof value !== 'object' ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null &&
      !Array.isArray(value))
  )
    throw new IamError('INVALID_RECORD', 'Records must contain JSON data only');
  if (ancestors.has(value))
    throw new IamError('INVALID_RECORD', 'Circular records are not supported');
  if (Object.getOwnPropertySymbols(value).length > 0)
    throw new IamError('INVALID_RECORD', 'Records cannot contain symbols');
  ancestors.add(value);
  for (const [key, item] of Object.entries(value)) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype')
      throw new IamError('INVALID_RECORD', 'Unsafe JSON property');
    if (Array.isArray(value) && item === undefined)
      throw new IamError('INVALID_RECORD', 'Undefined array items are not JSON values');
    jsonValue(item, ancestors, depth + 1);
  }
  ancestors.delete(value);
}

/**
 * A filter value a database can compare exactly: storable strings, finite numbers, and plain
 * objects and dense arrays without undefined members, extra array properties, or the reserved
 * PostgreSQL escape key. Anything else is filtered in memory.
 */
function pushableJson(value: unknown): boolean {
  if (value === null || typeof value === 'boolean') return true;
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value === 'string') return storableString(value);
  if (typeof value !== 'object' || value === undefined) return false;
  if (Array.isArray(value)) {
    if (Object.keys(value).length !== value.length) return false;
    for (let index = 0; index < value.length; index++)
      if (!(index in value) || !pushableJson(value[index])) return false;
    return true;
  }
  return Object.entries(value).every(
    ([key, item]) =>
      key !== JSONB_ESCAPE_KEY && storableString(key) && item !== undefined && pushableJson(item),
  );
}

function rowFor(collection: string, record: StoredRecord): StorageRow {
  storableIdentifier(collection, 'collection');
  if (!record || typeof record !== 'object' || Array.isArray(record))
    throw new IamError('INVALID_RECORD', 'Record must be an object');
  storableIdentifier(record.id, 'id');
  storableIdentifier(record.tenantId, 'tenantId');
  if (record.uniqueKey !== undefined) storableIdentifier(record.uniqueKey, 'uniqueKey');
  jsonValue(record);
  const data = JSON.stringify(record);
  if (data.length > 1_048_576)
    throw new IamError('INVALID_RECORD', 'Record exceeds one million characters');
  return {
    collection,
    id: record.id,
    tenant_id: record.tenantId,
    unique_key: record.uniqueKey ?? null,
    data,
  };
}

function decode<T extends StoredRecord>(row: StorageRow): T {
  let record: T;
  try {
    record = JSON.parse(row.data) as T;
  } catch {
    throw new IamError('STORAGE_CORRUPT', 'Invalid stored JSON', 500);
  }
  if (
    !record ||
    record.id !== row.id ||
    record.tenantId !== row.tenant_id ||
    (record.uniqueKey ?? null) !== row.unique_key
  )
    throw new IamError('STORAGE_CORRUPT', 'Record metadata mismatch', 500);
  return record;
}

function equal(actual: unknown, expected: unknown): boolean {
  if (actual === expected) return true;
  if (
    actual === null ||
    expected === null ||
    typeof actual !== 'object' ||
    typeof expected !== 'object'
  )
    return false;
  if (Array.isArray(actual) !== Array.isArray(expected)) return false;
  const left = Object.keys(actual);
  const right = Object.keys(expected);
  if (left.length !== right.length) return false;
  return left.every(
    (key) =>
      Object.hasOwn(expected, key) &&
      equal((actual as Record<string, unknown>)[key], (expected as Record<string, unknown>)[key]),
  );
}

/** The in-memory definition of filter semantics. Drivers' SQL must agree with it. */
export function matchesFilter(record: StoredRecord, filter: Record<string, unknown>): boolean {
  return Object.entries(filter).every(([key, value]) =>
    equal(Object.hasOwn(record, key) ? record[key] : undefined, value),
  );
}

/** Code-point (UTF-8 byte) order, the order of SQLite's BINARY and PostgreSQL's "C" collation. */
export function compareIds(left: string, right: string): number {
  const length = Math.min(left.length, right.length);
  for (let index = 0; index < length; index++) {
    let a = left.charCodeAt(index);
    let b = right.charCodeAt(index);
    if (a === b) continue;
    // UTF-16 puts surrogates (code points above U+FFFF) before U+E000-U+FFFF; code points do not.
    if (a >= 0xd800) a = a >= 0xe000 ? a - 0x800 : a + 0x2000;
    if (b >= 0xd800) b = b >= 0xe000 ? b - 0x800 : b + 0x2000;
    return a - b;
  }
  return left.length - right.length;
}

interface FindPlan {
  query: RecordQuery;
  /** Every filter key became part of the query, so the driver's rows need no further filtering. */
  exact: boolean;
  /** A column filter no stored record can satisfy (an identifier no column can hold). */
  empty: boolean;
}

/** Splits a validated filter into driver conditions and keys left to the in-memory filter. */
export function planQuery(
  collection: string,
  filter: Record<string, unknown>,
  capabilities: QueryCapabilities = {},
): FindPlan {
  const query: RecordQuery = { collection, conditions: [] };
  let exact = true;
  let empty = false;
  for (const [field, value] of Object.entries(filter)) {
    if (
      typeof value === 'string' &&
      (field === 'id' || field === 'tenantId' || field === 'uniqueKey')
    ) {
      // decode() guarantees these JSON fields equal their columns; writes refuse unstorable ones.
      if (!storableString(value)) empty = true;
      else if (field === 'id') query.id = value;
      else if (field === 'tenantId') query.tenantId = value;
      else query.uniqueKey = value;
      continue;
    }
    if (!QUERYABLE_FIELD.test(field) || query.conditions.length >= MAX_QUERY_CONDITIONS) {
      exact = false;
      continue;
    }
    if (typeof value === 'string' && storableString(value))
      query.conditions.push({ field, kind: 'string', value });
    else if (typeof value === 'number') query.conditions.push({ field, kind: 'number', value });
    else if (typeof value === 'boolean') query.conditions.push({ field, kind: 'boolean', value });
    else if (value === null) query.conditions.push({ field, kind: 'null' });
    else if (value === undefined) query.conditions.push({ field, kind: 'absent' });
    else if (
      capabilities.json &&
      typeof value === 'object' &&
      value !== null &&
      pushableJson(value)
    )
      query.conditions.push({ field, kind: 'json', value: JSON.stringify(value) });
    else exact = false;
  }
  return { query, exact, empty };
}

/** Shared strict JSON behavior keeps SQLite, libSQL, and PostgreSQL semantically identical. */
export abstract class RecordStore implements IamStore {
  protected abstract read<T>(operation: (driver: RecordDriver) => Promise<T>): Promise<T>;
  protected abstract write<T>(operation: (driver: RecordDriver) => Promise<T>): Promise<T>;
  abstract transaction<T>(fn: (tx: IamStore) => Promise<T>): Promise<T>;
  abstract migrate(): Promise<void>;
  abstract close(): Promise<void>;

  async get<T extends StoredRecord = StoredRecord>(
    collection: string,
    id: string,
  ): Promise<T | undefined> {
    validIdentifier(collection, 'collection');
    validIdentifier(id, 'id');
    return this.read(async (driver) => {
      // Writes refuse such identifiers; querying would match the row of the U+FFFD spelling.
      if (!storableString(collection) || !storableString(id)) return undefined;
      const [row] = await driver.select(collection, id);
      return row ? decode<T>(row) : undefined;
    });
  }

  async find<T extends StoredRecord = StoredRecord>(
    collection: string,
    filter: Record<string, unknown> = {},
    options: FindOptions = {},
  ): Promise<T[]> {
    validIdentifier(collection, 'collection');
    if (!filter || typeof filter !== 'object' || Array.isArray(filter))
      throw new IamError('INVALID_FILTER', 'Filter must be a JSON object');
    jsonValue(filter);
    const { offset = 0, limit, after } = options;
    if (
      !Number.isSafeInteger(offset) ||
      offset < 0 ||
      (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 0))
    )
      throw new IamError('INVALID_FILTER', 'Pagination must use nonnegative safe integers');
    if (after !== undefined && typeof after !== 'string')
      throw new IamError('INVALID_FILTER', 'The pagination cursor must be an id');
    const wanted = (record: T) =>
      matchesFilter(record, filter) && (after === undefined || compareIds(record.id, after) > 0);
    return this.read(async (driver) => {
      if (limit === 0 || !storableString(collection)) return [];
      if (driver.query) {
        const plan = planQuery(collection, filter, driver.queryCapabilities);
        if (plan.empty) return [];
        // A cursor the database cannot hold exactly (an unpaired surrogate) is applied in memory.
        const query =
          after !== undefined && storableString(after) ? { ...plan.query, after } : plan.query;
        const page = (records: T[]) =>
          records.filter(wanted).slice(offset, limit === undefined ? undefined : offset + limit);
        if (plan.exact && query.after === after) {
          // With a cursor, read from it and skip `offset` here: a driver that ignores the cursor
          // then returns a row at or before it whenever that would change the page, which fails
          // the check below instead of silently shifting the page.
          const window =
            after === undefined
              ? { offset, limit }
              : { offset: 0, limit: limit === undefined ? undefined : offset + limit };
          const records = (await driver.query({ ...query, page: window })).map((row) =>
            decode<T>(row),
          );
          if (records.every(wanted)) return after === undefined ? records : records.slice(offset);
          // A driver that disagrees with the reference semantics (or ignores the cursor) must not
          // shift pages: redo the query without paging and filter in memory.
        }
        return page((await driver.query(query)).map((row) => decode<T>(row)));
      }
      for (const column of [filter.id, filter.tenantId])
        if (typeof column === 'string' && !storableString(column)) return [];
      const rows = await driver.select(
        collection,
        typeof filter.id === 'string' ? filter.id : undefined,
        typeof filter.tenantId === 'string' ? filter.tenantId : undefined,
      );
      const records = rows.map((row) => decode<T>(row)).filter(wanted);
      // Do not inherit installation-dependent collation from a third-party driver.
      records.sort((left, right) => compareIds(left.id, right.id));
      return records.slice(offset, limit === undefined ? undefined : offset + limit);
    });
  }

  async findOrdered<T extends StoredRecord = StoredRecord>(
    collection: string,
    filter: Record<string, unknown>,
    order: OrderOptions,
  ): Promise<T[]> {
    validIdentifier(collection, 'collection');
    if (!filter || typeof filter !== 'object' || Array.isArray(filter))
      throw new IamError('INVALID_FILTER', 'Filter must be a JSON object');
    jsonValue(filter);
    const { field, direction, from, to, offset, limit } = orderOptions(order);
    return this.read(async (driver) => {
      if (limit === 0 || !storableString(collection)) return [];
      const inOrder = (records: T[]) =>
        orderRecords(
          records.filter((record) => matchesFilter(record, filter) && inRange(record, order)),
          field,
          direction,
        ).slice(offset, limit === undefined ? undefined : offset + limit);
      if (driver.query && driver.queryCapabilities?.order) {
        const plan = planQuery(collection, filter, driver.queryCapabilities);
        if (plan.empty) return [];
        const query = { ...plan.query, order: { field, direction, from, to } };
        if (plan.exact) {
          const records = (await driver.query({ ...query, page: { offset, limit } })).map((row) =>
            decode<T>(row),
          );
          if (records.every((record) => matchesFilter(record, filter) && inRange(record, order)))
            return records;
        }
        return inOrder((await driver.query(query)).map((row) => decode<T>(row)));
      }
      // Stores without ordered queries: read the matching records and order them here.
      return inOrder(await this.find<T>(collection, filter));
    });
  }

  /**
   * Collections holding records, sorted by code point. A driver without `collections()` makes this
   * reject with `UNSUPPORTED`; the refusal is raised after the read, so probing it inside a
   * transaction does not roll the transaction back.
   */
  async collections(): Promise<string[]> {
    const listed = await this.read(async (driver) =>
      driver.collections ? await driver.collections() : undefined,
    );
    if (!listed) throw new IamError('UNSUPPORTED', 'This adapter cannot list its collections', 501);
    return listed.sort(compareIds);
  }

  async insert<T extends StoredRecord>(collection: string, record: T): Promise<T> {
    const row = rowFor(collection, record);
    return this.write(async (driver) => {
      await driver.insert(row);
      return decode<T>(row);
    });
  }

  async put<T extends StoredRecord>(collection: string, record: T): Promise<T> {
    const row = rowFor(collection, record);
    return this.write(async (driver) => {
      const [existing] = await driver.select(collection, record.id);
      if (!existing) throw new IamError('NOT_FOUND', 'Cannot update a missing record', 404);
      if (existing.tenant_id !== record.tenantId)
        throw new IamError('CONFLICT', 'Record tenant cannot be changed', 409);
      if (!(await driver.update(row)))
        throw new IamError('NOT_FOUND', 'Cannot update a missing record', 404);
      return decode<T>(row);
    });
  }

  async delete(collection: string, id: string): Promise<void> {
    validIdentifier(collection, 'collection');
    validIdentifier(id, 'id');
    return this.write(async (driver) => {
      // No stored record can have such an identifier (see get).
      if (storableString(collection) && storableString(id)) await driver.delete(collection, id);
    });
  }
}

/** Validated `OrderOptions` with defaults applied. */
function orderOptions(order: OrderOptions) {
  if (!order || typeof order !== 'object')
    throw new IamError('INVALID_FILTER', 'Order options are required');
  const { field, direction = 'asc', from, to, offset = 0, limit } = order;
  if (typeof field !== 'string' || !QUERYABLE_FIELD.test(field))
    throw new IamError('INVALID_FILTER', 'The order field must be a top-level identifier');
  if (direction !== 'asc' && direction !== 'desc')
    throw new IamError('INVALID_FILTER', 'Order direction must be asc or desc');
  for (const bound of [from, to])
    if (bound !== undefined && (typeof bound !== 'number' || !Number.isFinite(bound)))
      throw new IamError('INVALID_FILTER', 'Range bounds must be finite numbers');
  if (
    !Number.isSafeInteger(offset) ||
    offset < 0 ||
    (limit !== undefined && (!Number.isSafeInteger(limit) || limit < 0))
  )
    throw new IamError('INVALID_FILTER', 'Pagination must use nonnegative safe integers');
  return { field, direction, from, to, offset, limit } as const;
}

function inRange(record: StoredRecord, order: OrderOptions): boolean {
  const value = Object.hasOwn(record, order.field) ? record[order.field] : undefined;
  return (
    typeof value === 'number' &&
    (order.from === undefined || value >= order.from) &&
    (order.to === undefined || value <= order.to)
  );
}

function orderRecords<T extends StoredRecord>(
  records: T[],
  field: string,
  direction: 'asc' | 'desc',
): T[] {
  const sign = direction === 'desc' ? -1 : 1;
  return records.sort(
    (left, right) =>
      sign * ((left[field] as number) - (right[field] as number)) || compareIds(left.id, right.id),
  );
}

/**
 * Records matching `filter` whose numeric `order.field` lies in `[from, to]`, ordered by that field
 * (ties by id, ascending) and paged. Uses the store's `findOrdered` when it has one and otherwise
 * orders a plain `find` in memory. `where` adds an in-memory predicate (for example a glob); the
 * store is then read in ordered chunks until the page is full, so it never loads everything.
 */
export async function findOrdered<T extends StoredRecord = StoredRecord>(
  store: IamStore,
  collection: string,
  filter: Record<string, unknown>,
  order: OrderOptions & { where?: (record: T) => boolean },
): Promise<T[]> {
  const { where, ...options } = order;
  const { field, direction, offset, limit } = orderOptions(options);
  if (!store.findOrdered) {
    const records = (await store.find<T>(collection, filter)).filter(
      (record) => inRange(record, options) && (!where || where(record)),
    );
    return orderRecords(records, field, direction).slice(
      offset,
      limit === undefined ? undefined : offset + limit,
    );
  }
  if (!where) return store.findOrdered<T>(collection, filter, options);
  const wanted = limit === undefined ? Number.POSITIVE_INFINITY : offset + limit;
  const chunk = Math.min(
    Math.max(wanted === Number.POSITIVE_INFINITY ? 500 : wanted * 2, 100),
    2000,
  );
  const matches: T[] = [];
  for (let read = 0; matches.length < wanted; read += chunk) {
    const batch = await store.findOrdered<T>(collection, filter, {
      ...options,
      offset: read,
      limit: chunk,
    });
    for (const record of batch) if (where(record)) matches.push(record);
    if (batch.length < chunk) break;
  }
  return matches.slice(offset, limit === undefined ? undefined : offset + limit);
}

/** A named, idempotent schema step. The ledger `iam_migrations` records which ones ran. */
export interface SchemaMigration {
  name: string;
  statements: readonly string[];
}

/** Map database failures without leaking SQL or credential-bearing record data. */
export function storageError(error: unknown): Error {
  if (error instanceof IamError) return error;
  const code = error && typeof error === 'object' && 'code' in error ? String(error.code) : '';
  if (
    code === '23505' ||
    code === 'SQLITE_CONSTRAINT_UNIQUE' ||
    code === 'SQLITE_CONSTRAINT_PRIMARYKEY'
  )
    return new IamError(
      'CONFLICT',
      'A record with this identifier or tenant key already exists',
      409,
    );
  if (
    [
      '40001',
      '40P01',
      '55P03',
      '57014',
      'SQLITE_BUSY',
      'SQLITE_BUSY_SNAPSHOT',
      'SQLITE_LOCKED',
    ].includes(code)
  )
    return new IamError('STORAGE_BUSY', 'Database is busy; retry the complete operation', 503);
  return new IamError('STORAGE_ERROR', 'Database operation failed', 500);
}
