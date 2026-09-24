import { IamError, type StoreDescription } from './index.js';
import {
  EXPIRY_FIELDS,
  JSONB_ESCAPE_KEY,
  LOOKUP_INDEX_STEPS,
  ORDERED_FIELDS,
  QUERYABLE_FIELD,
  storableString,
  type FieldCondition,
  type RecordQuery,
  type SchemaMigration,
} from './storage.js';

/**
 * SQL shared by the reference adapters. Everything here is plain string building: adapters pass
 * the text and values to their own driver. Field names are validated against QUERYABLE_FIELD
 * before they appear in SQL; every value is a bound parameter.
 */
export interface SqlStatement {
  text: string;
  values: unknown[];
}
export type SqlDialect = 'sqlite' | 'postgres';
export type SqlExecutor = (
  text: string,
  values?: readonly unknown[],
) => Promise<Record<string, unknown>[]>;

const COLUMNS = 'collection, id, tenant_id, unique_key, data';

function field(condition: Pick<FieldCondition, 'field'>): string {
  if (!QUERYABLE_FIELD.test(condition.field))
    throw new IamError('INVALID_FILTER', 'Field names in SQL conditions must be identifiers');
  return condition.field;
}

const direction = (order: NonNullable<RecordQuery['order']>) =>
  order.direction === 'desc' ? 'DESC' : 'ASC';

/** SQLite path literal. Identical text in the query and the index lets the planner use the index. */
const sqlitePath = (name: string) => `'$."${name}"'`;

/** SELECT for SQLite and libSQL (JSON1). `json` conditions are not supported. */
export function sqliteSelect(query: RecordQuery): SqlStatement {
  const where = ['collection = ?'];
  const values: unknown[] = [query.collection];
  for (const [column, value] of [
    ['id', query.id],
    ['tenant_id', query.tenantId],
    ['unique_key', query.uniqueKey],
  ] as const) {
    if (value === undefined) continue;
    where.push(`${column} = ?`);
    values.push(value);
  }
  // BINARY collation compares UTF-8 bytes, which is code-point order (`compareIds`).
  if (query.after !== undefined) {
    where.push('id > ?');
    values.push(query.after);
  }
  for (const condition of query.conditions) {
    const path = sqlitePath(field(condition));
    const type = `json_type(data, ${path})`;
    const value = `json_extract(data, ${path})`;
    switch (condition.kind) {
      case 'string':
        where.push(`${type} = 'text' AND ${value} = ?`);
        values.push(condition.value);
        break;
      case 'number':
        // Compare the literal's text, not a parsed double. SQLite reads integer literals above
        // 2^53 as exact 64-bit integers and some builds parse large exponents inexactly, while
        // every stored number and every bound value is JSON.stringify output of a double.
        where.push(`${type} IN ('integer', 'real') AND (data -> ${path}) = ?`);
        values.push(JSON.stringify(condition.value));
        break;
      case 'boolean':
        where.push(`${type} = '${condition.value ? 'true' : 'false'}'`);
        break;
      case 'null':
        where.push(`${type} = 'null'`);
        break;
      case 'absent':
        where.push(`${type} IS NULL`);
        break;
      default:
        throw new IamError('INVALID_FILTER', 'SQLite adapters do not evaluate JSON conditions');
    }
  }
  let orderBy = 'id';
  if (query.order) {
    const path = sqlitePath(field(query.order));
    const value = `json_extract(data, ${path})`;
    // `IS NOT NULL` repeats the partial index predicate so the ordered indexes qualify.
    where.push(`${value} IS NOT NULL AND json_type(data, ${path}) IN ('integer', 'real')`);
    // Bounds are parsed from JSON text like stored values, so large integers compare consistently.
    for (const [operator, bound] of [
      ['>=', query.order.from],
      ['<=', query.order.to],
    ] as const) {
      if (bound === undefined) continue;
      where.push(`${value} ${operator} json_extract(?, '$')`);
      values.push(JSON.stringify(bound));
    }
    orderBy = `${value} ${direction(query.order)}, id`;
  }
  let text = `SELECT ${COLUMNS} FROM iam_records WHERE ${where.join(' AND ')} ORDER BY ${orderBy}`;
  if (query.page) {
    text += ' LIMIT ? OFFSET ?';
    values.push(query.page.limit ?? -1, query.page.offset);
  }
  return { text, values };
}

const postgresTypes = { string: 'string', number: 'number', boolean: 'boolean', null: 'null' };

/** SELECT for PostgreSQL. Scalar tests share one jsonb containment test, served by a GIN index. */
export function postgresSelect(query: RecordQuery): SqlStatement {
  const values: unknown[] = [];
  const bind = (value: unknown) => `$${values.push(value)}`;
  const where = [`collection = ${bind(query.collection)}`];
  if (query.id !== undefined) where.push(`id = ${bind(query.id)}`);
  if (query.tenantId !== undefined) where.push(`tenant_id = ${bind(query.tenantId)}`);
  if (query.uniqueKey !== undefined) where.push(`unique_key = ${bind(query.uniqueKey)}`);
  // The id column uses the "C" collation: byte order, which is code-point order.
  if (query.after !== undefined) where.push(`id > ${bind(query.after)}`);
  const contains: Record<string, unknown> = {};
  for (const condition of query.conditions) {
    const name = field(condition);
    const member = `((data::jsonb) -> ${bind(name)}::text)`;
    switch (condition.kind) {
      case 'string':
      case 'number':
      case 'boolean':
      case 'null':
        // Containment finds candidates through the index; the type test makes it exact equality.
        contains[name] = condition.kind === 'null' ? null : condition.value;
        where.push(`jsonb_typeof${member} = '${postgresTypes[condition.kind]}'`);
        break;
      case 'absent':
        where.push(`${member} IS NULL`);
        break;
      case 'json':
        where.push(`${member} = ${bind(condition.value)}::jsonb`);
        break;
    }
  }
  if (Object.keys(contains).length)
    where.push(`(data::jsonb) @> ${bind(JSON.stringify(contains))}::jsonb`);
  let orderBy = 'id';
  if (query.order) {
    // The validated field name is inlined so the expression matches the ordered indexes.
    const member = `((data::jsonb) -> '${field(query.order)}')`;
    where.push(`jsonb_typeof${member} = 'number'`);
    if (query.order.from !== undefined)
      where.push(`${member} >= ${bind(JSON.stringify(query.order.from))}::jsonb`);
    if (query.order.to !== undefined)
      where.push(`${member} <= ${bind(JSON.stringify(query.order.to))}::jsonb`);
    orderBy = `${member} ${direction(query.order)}, id`;
  }
  let text = `SELECT ${COLUMNS} FROM iam_records WHERE ${where.join(' AND ')} ORDER BY ${orderBy}`;
  if (query.page) {
    const limit = query.page.limit === undefined ? 'ALL' : bind(query.page.limit);
    text += ` LIMIT ${limit} OFFSET ${bind(query.page.offset)}`;
  }
  return { text, values };
}

const recordsTable = (dialect: SqlDialect) => {
  const text = dialect === 'postgres' ? 'TEXT COLLATE "C"' : 'TEXT';
  return `CREATE TABLE IF NOT EXISTS iam_records (collection ${text} NOT NULL, id ${text} NOT NULL, tenant_id ${text} NOT NULL, unique_key ${text}, data TEXT NOT NULL, PRIMARY KEY (collection, id), UNIQUE (collection, tenant_id, unique_key))`;
};

/**
 * Ordered, append-only schema steps. Never edit a released step; add a new one.
 *
 * Secondary indexes end in `id` so one index both finds rows and yields them in `ORDER BY id`
 * order. Without that, SQLite (which has no statistics until ANALYZE) prefers walking the
 * primary key in id order over an index lookup followed by a sort.
 */
export function schemaMigrations(dialect: SqlDialect): readonly SchemaMigration[] {
  // SQLite and libSQL index each lookup field; PostgreSQL's one document index serves them all.
  const fieldIndexes = (step: string) =>
    dialect === 'postgres'
      ? []
      : LOOKUP_INDEX_STEPS[step]!.map(
          (name) =>
            `CREATE INDEX IF NOT EXISTS iam_records_field_${name} ON iam_records (collection, json_extract(data, ${sqlitePath(name)}), id) WHERE json_extract(data, ${sqlitePath(name)}) IS NOT NULL`,
        );
  const lookups =
    dialect === 'postgres'
      ? [
          'CREATE INDEX IF NOT EXISTS iam_records_document ON iam_records USING gin ((data::jsonb) jsonb_path_ops)',
        ]
      : fieldIndexes('0002_query_indexes');
  return [
    {
      name: '0001_records',
      statements: [
        recordsTable(dialect),
        'CREATE INDEX IF NOT EXISTS iam_records_tenant ON iam_records (collection, tenant_id)',
      ],
    },
    {
      // The older (collection, tenant_id) index is kept: dropping it would take PostgreSQL's
      // ACCESS EXCLUSIVE lock, blocking every read until the whole migration commits.
      name: '0002_query_indexes',
      statements: [
        'CREATE INDEX IF NOT EXISTS iam_records_tenant_id ON iam_records (collection, tenant_id, id)',
        'CREATE INDEX IF NOT EXISTS iam_records_unique_key ON iam_records (collection, unique_key, id) WHERE unique_key IS NOT NULL',
        ...lookups,
      ],
    },
    {
      // Tenant-scoped ordered reads (`findOrdered`): the audit log by time and by chain sequence.
      name: '0003_ordered_indexes',
      statements: ORDERED_FIELDS.map((name) =>
        dialect === 'postgres'
          ? `CREATE INDEX IF NOT EXISTS iam_records_order_${name} ON iam_records (collection, tenant_id, ((data::jsonb) -> '${name}'), id) WHERE jsonb_typeof((data::jsonb) -> '${name}') = 'number'`
          : `CREATE INDEX IF NOT EXISTS iam_records_order_${name} ON iam_records (collection, tenant_id, json_extract(data, ${sqlitePath(name)}), id) WHERE json_extract(data, ${sqlitePath(name)}) IS NOT NULL`,
      ),
    },
    {
      // Collection-wide ordered reads: retention sweeps by expiry and delivery time.
      name: '0004_expiry_indexes',
      statements: EXPIRY_FIELDS.map((name) =>
        dialect === 'postgres'
          ? `CREATE INDEX IF NOT EXISTS iam_records_expiry_${name} ON iam_records (collection, ((data::jsonb) -> '${name}'), id) WHERE jsonb_typeof((data::jsonb) -> '${name}') = 'number'`
          : `CREATE INDEX IF NOT EXISTS iam_records_expiry_${name} ON iam_records (collection, json_extract(data, ${sqlitePath(name)}), id) WHERE json_extract(data, ${sqlitePath(name)}) IS NOT NULL`,
      ),
    },
    {
      // Session cascade lookups (role and temporary sessions by source session and by trust).
      name: '0005_lookup_indexes',
      statements: fieldIndexes('0005_lookup_indexes'),
    },
    {
      // Data protection token lookups by keyed value fingerprint.
      name: '0006_protection_indexes',
      statements: fieldIndexes('0006_protection_indexes'),
    },
  ];
}

export interface MigrationOptions {
  now?: number;
  /** Runs before a migration's statements, in the same transaction (for data rewrites). */
  before?(name: string, execute: SqlExecutor): Promise<void>;
}

/**
 * Creates the schema and applies missing named migrations, recording each in `iam_migrations`.
 * Run it inside the adapter's serialized write transaction. Returns the names applied now.
 */
export async function applyMigrations(
  execute: SqlExecutor,
  dialect: SqlDialect,
  options: MigrationOptions = {},
): Promise<string[]> {
  const now = options.now ?? Date.now();
  await execute(
    'CREATE TABLE IF NOT EXISTS iam_schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)',
  );
  const [version] = await execute('SELECT version FROM iam_schema_version WHERE id = 1');
  if (version && Number(version.version) !== 1)
    throw new IamError('SCHEMA_VERSION', 'Unsupported database schema version', 500);
  await execute(
    'CREATE TABLE IF NOT EXISTS iam_migrations (name TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)',
  );
  const applied = new Set(
    (await execute('SELECT name FROM iam_migrations')).map((row) => String(row.name)),
  );
  const ran: string[] = [];
  const insert =
    dialect === 'postgres'
      ? 'INSERT INTO iam_migrations (name, applied_at) VALUES ($1, $2)'
      : 'INSERT INTO iam_migrations (name, applied_at) VALUES (?, ?)';
  for (const migration of schemaMigrations(dialect)) {
    if (applied.has(migration.name)) continue;
    await options.before?.(migration.name, execute);
    for (const statement of migration.statements) await execute(statement);
    await execute(insert, [migration.name, now]);
    ran.push(migration.name);
  }
  await execute(
    'INSERT INTO iam_schema_version (id, version) VALUES (1, 1) ON CONFLICT (id) DO NOTHING',
  );
  return ran;
}

/** A query failed because a table does not exist (PostgreSQL 42P01, SQLite "no such table"). */
export function isMissingTable(error: unknown): boolean {
  const { code, message } = (error ?? {}) as { code?: unknown; message?: unknown };
  return code === '42P01' || /no such table/i.test(String(message ?? ''));
}

/** Distinct collection names in the records table. */
export const COLLECTIONS_SQL = 'SELECT DISTINCT collection FROM iam_records ORDER BY collection';

/**
 * The adapter-independent part of `IamStore.describe()`: schema version, applied migrations, and
 * record counts per collection. Missing tables read as empty, so an unmigrated database reports
 * empty lists; any other failure rejects. Run it outside a transaction on PostgreSQL (a failed
 * statement would abort the transaction).
 */
export async function describeRecords(
  execute: SqlExecutor,
  adapter: string,
  settings: StoreDescription['settings'],
): Promise<StoreDescription> {
  // Only a table that does not exist yet reads as empty; a database that cannot be reached must
  // fail rather than look like a fresh, unmigrated one.
  const attempt = async (text: string) => {
    try {
      return await execute(text);
    } catch (error) {
      if (isMissingTable(error)) return [];
      throw error;
    }
  };
  const [version] = await attempt('SELECT version FROM iam_schema_version WHERE id = 1');
  const migrations = (
    await attempt('SELECT name, applied_at FROM iam_migrations ORDER BY name')
  ).map((row) => ({ name: String(row.name), appliedAt: Number(row.applied_at) }));
  const collections = (
    await attempt(
      'SELECT collection, COUNT(*) AS records FROM iam_records GROUP BY collection ORDER BY collection',
    )
  ).map((row) => ({ name: String(row.collection), records: Number(row.records) }));
  return {
    adapter,
    schemaVersion: version ? Number(version.version) : null,
    migrations,
    collections,
    settings,
  };
}

// --- PostgreSQL value encoding -------------------------------------------------------------------
//
// PostgreSQL's jsonb rejects U+0000 and unpaired surrogates, and the PostgreSQL adapter indexes
// `data::jsonb`. Record values may still hold such strings, so that adapter stores them encoded:
// a string becomes `{ [JSONB_ESCAPE_KEY]: "<UTF-16 code units as hex>" }`, and an object's keys
// that are unstorable (or equal to the escape key itself) move into `[JSONB_ESCAPE_KEY]: [[hex key,
// value], ...]`. Other keys and values stay in place, so typed conditions on ordinary fields remain
// exact; an encoded value never equals a pushable filter value (see `planQuery`). Decoding restores
// the original record; only the order of escaped keys within their object can change.

const escapedJson = /\\u0000|\\ud[89a-f][0-9a-f]{2}|\\u0001better-iam/i;
const hexString = (value: string) => {
  let out = '';
  for (let index = 0; index < value.length; index++)
    out += value.charCodeAt(index).toString(16).padStart(4, '0');
  return out;
};
const fromHex = (value: unknown): string => {
  if (typeof value !== 'string' || !/^(?:[0-9a-f]{4})*$/.test(value))
    throw new IamError('STORAGE_CORRUPT', 'Invalid escaped value', 500);
  let out = '';
  for (let index = 0; index < value.length; index += 4)
    out += String.fromCharCode(Number.parseInt(value.slice(index, index + 4), 16));
  return out;
};

function encodeValue(value: unknown): unknown {
  if (typeof value === 'string')
    return storableString(value) ? value : { [JSONB_ESCAPE_KEY]: hexString(value) };
  if (Array.isArray(value)) return value.map(encodeValue);
  if (value === null || typeof value !== 'object') return value;
  const out: Record<string, unknown> = {};
  const escaped: [string, unknown][] = [];
  for (const [key, item] of Object.entries(value)) {
    if (item === undefined) continue;
    if (key === JSONB_ESCAPE_KEY || !storableString(key))
      escaped.push([hexString(key), encodeValue(item)]);
    else out[key] = encodeValue(item);
  }
  if (escaped.length) out[JSONB_ESCAPE_KEY] = escaped;
  return out;
}

function decodeValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(decodeValue);
  if (value === null || typeof value !== 'object') return value;
  const entries = value as Record<string, unknown>;
  const marker = entries[JSONB_ESCAPE_KEY];
  if (typeof marker === 'string' && Object.keys(entries).length === 1) return fromHex(marker);
  const out: Record<string, unknown> = {};
  for (const [key, item] of Object.entries(entries))
    if (key !== JSONB_ESCAPE_KEY) out[key] = decodeValue(item);
  if (marker !== undefined) {
    if (!Array.isArray(marker)) throw new IamError('STORAGE_CORRUPT', 'Invalid escaped keys', 500);
    for (const pair of marker) {
      if (!Array.isArray(pair) || pair.length !== 2)
        throw new IamError('STORAGE_CORRUPT', 'Invalid escaped keys', 500);
      out[fromHex(pair[0])] = decodeValue(pair[1]);
    }
  }
  return out;
}

/** Record JSON as the PostgreSQL adapter stores it: valid jsonb, reversible by `decodeJsonbDocument`. */
export function encodeJsonbDocument(data: string): string {
  // Only JSON text containing one of the escapes can need a rewrite (false positives re-encode to
  // the same text); JSON.stringify never writes these characters unescaped.
  return escapedJson.test(data) ? JSON.stringify(encodeValue(JSON.parse(data))) : data;
}

/** The original record JSON of a document written by `encodeJsonbDocument`. */
export function decodeJsonbDocument(data: string): string {
  return data.includes('\\u0001better-iam') ? JSON.stringify(decodeValue(JSON.parse(data))) : data;
}

/**
 * Migration hook for PostgreSQL: rewrites rows written before the value encoding existed, whose
 * text jsonb would reject, so the jsonb index of `0002_query_indexes` can be built.
 */
export async function encodeLegacyPostgresRows(name: string, execute: SqlExecutor): Promise<void> {
  if (name !== '0002_query_indexes') return;
  const rows = await execute(
    `SELECT collection, id, data FROM iam_records WHERE strpos(data, '\\u0000') > 0 OR data ~* '\\\\ud[89a-f]'`,
  );
  for (const row of rows) {
    const data = String(row.data);
    const encoded = encodeJsonbDocument(data);
    if (encoded !== data)
      await execute('UPDATE iam_records SET data = $1 WHERE collection = $2 AND id = $3', [
        encoded,
        row.collection,
        row.id,
      ]);
  }
}
