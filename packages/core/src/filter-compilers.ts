import { IamError } from './index.js';
import { parseGlob, globMatches, type FilterValue, type ResourceFilter } from './plan.js';
import { ipMatches, isIpRange } from './policy.js';

/**
 * Compilers for query plans (plan.ts): the same filter as a JavaScript predicate, SQL for PostgreSQL and SQLite,
 * a Prisma `where`, and a MongoDB query. Each atom is NULL-safe (a missing field satisfies nothing but `not exists`),
 * so negations behave like the policy engine rather than like SQL's three-valued logic.
 */

function unsupported(kind: string, target: string): never {
  throw new IamError(
    'UNSUPPORTED_FILTER',
    `${kind} conditions cannot be expressed in ${target}; filter these resources with filterMatches or authorize`,
  );
}

const timestampPattern = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/u;

/** An ISO 8601 timestamp as epoch milliseconds, with the engine's validation (policy.ts `timestamp`). */
function timestamp(value: unknown): number | undefined {
  if (typeof value !== 'string' || !timestampPattern.test(value)) return undefined;
  const date = Number(Date.parse(value));
  if (!Number.isFinite(date)) return undefined;
  const year = Number(value.slice(0, 4));
  const month = Number(value.slice(5, 7));
  const day = Number(value.slice(8, 10));
  const days = new Date(Date.UTC(year === 0 ? 400 : year, month, 0)).getUTCDate();
  if (
    month < 1 ||
    month > 12 ||
    day < 1 ||
    day > days ||
    Number(value.slice(11, 13)) > 23 ||
    Number(value.slice(14, 16)) > 59 ||
    Number(value.slice(17, 19)) > 59
  )
    return undefined;
  return date;
}

const isAddress = (value: unknown): value is string =>
  typeof value === 'string' && !value.includes('/') && isIpRange(value);

function sameValue(actual: unknown, expected: FilterValue, ignoreCase: boolean): boolean {
  if (typeof expected === 'number')
    return typeof actual === 'number' && Number.isFinite(actual) && actual === expected;
  if (typeof actual !== typeof expected) return false;
  return ignoreCase && typeof actual === 'string'
    ? actual.toLowerCase() === (expected as string).toLowerCase()
    : actual === expected;
}

/**
 * Whether a resource passes a filter: `record.id` is the id and every other field is read by name (`record['tag.team']`
 * for `resource.tag.team`). This is exact, with the policy engine's semantics, and supports every filter.
 */
export function filterMatches(filter: ResourceFilter, record: Record<string, unknown>): boolean {
  const read = (field: string) => (Object.hasOwn(record, field) ? record[field] : undefined);
  switch (filter.kind) {
    case 'true':
      return true;
    case 'false':
      return false;
    case 'and':
      return filter.filters.every((item) => filterMatches(item, record));
    case 'or':
      return filter.filters.some((item) => filterMatches(item, record));
    case 'not':
      return !filterMatches(filter.filter, record);
    case 'exists':
      return read(filter.field) !== undefined;
    case 'type': {
      const value = read(filter.field);
      return filter.type === 'ip'
        ? isAddress(value)
        : filter.type === 'number'
          ? typeof value === 'number' && Number.isFinite(value)
          : typeof value === filter.type;
    }
    case 'equals': {
      const value = read(filter.field);
      return filter.values.some((expected) => sameValue(value, expected, filter.ignoreCase === true));
    }
    case 'compare': {
      const value = read(filter.field);
      if (typeof value !== 'number' || !Number.isFinite(value)) return false;
      return filter.operator === 'lt'
        ? value < filter.value
        : filter.operator === 'le'
          ? value <= filter.value
          : filter.operator === 'gt'
            ? value > filter.value
            : value >= filter.value;
    }
    case 'like': {
      const value = read(filter.field);
      if (typeof value !== 'string') return false;
      return globMatches(
        parseGlob(filter.ignoreCase ? filter.pattern.toLowerCase() : filter.pattern),
        filter.ignoreCase ? value.toLowerCase() : value,
      );
    }
    case 'date': {
      const left = timestamp(read(filter.field));
      const right = timestamp(filter.value);
      return (
        left !== undefined &&
        right !== undefined &&
        (filter.operator === 'before' ? left < right : left > right)
      );
    }
    case 'ip': {
      const value = read(filter.field);
      return typeof value === 'string' && ipMatches(value, filter.network);
    }
    case 'contains': {
      const value = read(filter.field);
      return Array.isArray(value) && value.includes(filter.value);
    }
  }
}

// --- SQL -----------------------------------------------------------------------------------------

export interface SqlFilterOptions {
  dialect: 'postgres' | 'sqlite';
  /**
   * The SQL expression for a field: a trusted column name or JSON path expression of your schema (`"owner_id"`,
   * `data->>'owner'`). Return undefined to refuse a field the plan names that your table does not have.
   */
  column: (field: string) => string | undefined;
  /** PostgreSQL placeholders start after this many parameters, for a filter inside a larger query (default 0). */
  offset?: number;
}

export interface SqlFilter {
  /** A boolean SQL expression, for a `WHERE` clause. */
  sql: string;
  params: unknown[];
}

/** A glob as a SQLite GLOB pattern: wildcards stay, literal `*`, `?` and `[` become character classes. */
function sqliteGlob(pattern: string, lower: boolean): string {
  return parseGlob(lower ? pattern.toLowerCase() : pattern)
    .map((token) =>
      token.kind === 'star'
        ? '*'
        : token.kind === 'any'
          ? '?'
          : token.value === '*' || token.value === '?' || token.value === '['
            ? `[${token.value}]`
            : token.value,
    )
    .join('');
}

/** A glob as a LIKE pattern with `\` as the escape character. */
function likePattern(pattern: string, lower: boolean): string {
  return parseGlob(lower ? pattern.toLowerCase() : pattern)
    .map((token) =>
      token.kind === 'star'
        ? '%'
        : token.kind === 'any'
          ? '_'
          : '%_\\'.includes(token.value)
            ? `\\${token.value}`
            : token.value,
    )
    .join('');
}

/**
 * The filter as a parameterized SQL expression. Columns are expected to hold values of the types the policy compares
 * (text for string conditions, numbers, booleans, ISO 8601 text for dates), with `NULL` for absent attributes.
 * PostgreSQL uses `$n` placeholders and SQLite `?`. IP and array conditions refuse with UNSUPPORTED_FILTER.
 */
export function filterToSql(filter: ResourceFilter, options: SqlFilterOptions): SqlFilter {
  const params: unknown[] = [];
  const postgres = options.dialect === 'postgres';
  const offset = options.offset ?? 0;
  const bind = (value: unknown) => {
    params.push(!postgres && typeof value === 'boolean' ? (value ? 1 : 0) : value);
    return postgres ? `$${offset + params.length}` : '?';
  };
  const column = (field: string) => {
    const expression = options.column(field);
    if (!expression)
      throw new IamError('INVALID_INPUT', `The plan filters on ${field}, which has no column`);
    return expression;
  };
  const guarded = (field: string, predicate: (expression: string) => string) => {
    const expression = column(field);
    return `(${expression} IS NOT NULL AND ${predicate(expression)})`;
  };
  const compile = (item: ResourceFilter): string => {
    switch (item.kind) {
      case 'true':
        return postgres ? 'TRUE' : '1 = 1';
      case 'false':
        return postgres ? 'FALSE' : '1 = 0';
      case 'and':
        return `(${item.filters.map(compile).join(' AND ')})`;
      case 'or':
        return `(${item.filters.map(compile).join(' OR ')})`;
      case 'not':
        return `(NOT ${compile(item.filter)})`;
      case 'exists':
      case 'type':
        if (item.kind === 'type' && item.type === 'ip') unsupported('IP address', 'SQL');
        return `(${column(item.field)} IS NOT NULL)`;
      case 'equals':
        return guarded(item.field, (expression) => {
          const values = item.ignoreCase
            ? item.values.map((value) => (typeof value === 'string' ? value.toLowerCase() : value))
            : item.values;
          const target = item.ignoreCase ? `LOWER(${expression})` : expression;
          return `${target} IN (${values.map(bind).join(', ')})`;
        });
      case 'compare':
        return guarded(
          item.field,
          (expression) =>
            `${expression} ${{ lt: '<', le: '<=', gt: '>', ge: '>=' }[item.operator]} ${bind(item.value)}`,
        );
      case 'like':
        return guarded(item.field, (expression) => {
          const target = item.ignoreCase ? `LOWER(${expression})` : expression;
          return postgres
            ? `${target} LIKE ${bind(likePattern(item.pattern, item.ignoreCase === true))} ESCAPE '\\'`
            : `${target} GLOB ${bind(sqliteGlob(item.pattern, item.ignoreCase === true))}`;
        });
      case 'date':
        return guarded(item.field, (expression) =>
          postgres
            ? `(${expression})::timestamptz ${item.operator === 'before' ? '<' : '>'} ${bind(item.value)}::timestamptz`
            : `julianday(${expression}) ${item.operator === 'before' ? '<' : '>'} julianday(${bind(item.value)})`,
        );
      case 'ip':
        return unsupported('IP address', 'SQL');
      case 'contains':
        return unsupported('Array', 'SQL');
    }
  };
  return { sql: compile(filter), params };
}

// --- Prisma --------------------------------------------------------------------------------------

export interface PrismaFilterOptions {
  /** The model field for a plan field (default: the same name). */
  field?: (field: string) => string;
}

/** A glob that Prisma's string filters can express: exact, a prefix, a suffix, or a substring. */
function simpleGlob(pattern: string): { kind: 'equals' | 'startsWith' | 'endsWith' | 'contains'; text: string } | undefined {
  const tokens = parseGlob(pattern);
  if (tokens.some((token) => token.kind === 'any')) return undefined;
  const stars = tokens.map((token, index) => (token.kind === 'star' ? index : -1)).filter((index) => index >= 0);
  const text = tokens
    .filter((token) => token.kind === 'char')
    .map((token) => (token as { value: string }).value)
    .join('');
  const last = tokens.length - 1;
  if (stars.length === 0) return { kind: 'equals', text };
  if (stars.length === 1 && stars[0] === last) return { kind: 'startsWith', text };
  if (stars.length === 1 && stars[0] === 0) return { kind: 'endsWith', text };
  if (stars.length === 2 && stars[0] === 0 && stars[1] === last) return { kind: 'contains', text };
  return undefined;
}

/**
 * The filter as a Prisma `where` object. Globs must be exact, a prefix (`abc*`), a suffix (`*abc`) or a substring
 * (`*abc*`); dates, IP addresses, and other globs refuse with UNSUPPORTED_FILTER. Case-insensitive comparisons use
 * `mode: 'insensitive'` (PostgreSQL and MongoDB).
 */
export function filterToPrisma(
  filter: ResourceFilter,
  options: PrismaFilterOptions = {},
): Record<string, unknown> {
  const name = (field: string) => options.field?.(field) ?? field;
  const present = (field: string) => ({ [name(field)]: { not: null } });
  const compile = (item: ResourceFilter): Record<string, unknown> => {
    switch (item.kind) {
      case 'true':
        return {};
      case 'false':
        return { [name('id')]: { in: [] } };
      case 'and':
        return { AND: item.filters.map(compile) };
      case 'or':
        return { OR: item.filters.map(compile) };
      case 'not':
        return { NOT: compile(item.filter) };
      case 'exists':
      case 'type':
        if (item.kind === 'type' && item.type === 'ip') unsupported('IP address', 'Prisma');
        return present(item.field);
      case 'equals':
        return {
          AND: [
            present(item.field),
            item.ignoreCase
              ? {
                  OR: item.values.map((value) => ({
                    [name(item.field)]: { equals: value, mode: 'insensitive' },
                  })),
                }
              : { [name(item.field)]: { in: item.values } },
          ],
        };
      case 'compare':
        return { AND: [present(item.field), { [name(item.field)]: { [item.operator === 'le' ? 'lte' : item.operator === 'ge' ? 'gte' : item.operator]: item.value } }] };
      case 'like': {
        const simple = simpleGlob(item.pattern);
        if (!simple) return unsupported('This wildcard', 'Prisma');
        return {
          AND: [
            present(item.field),
            {
              [name(item.field)]: {
                [simple.kind]: simple.text,
                ...(item.ignoreCase ? { mode: 'insensitive' } : {}),
              },
            },
          ],
        };
      }
      case 'contains':
        return { [name(item.field)]: { has: item.value } };
      case 'date':
        return unsupported('Date', 'Prisma');
      case 'ip':
        return unsupported('IP address', 'Prisma');
    }
  };
  return compile(filter);
}

// --- MongoDB -------------------------------------------------------------------------------------

export interface MongoFilterOptions {
  /** The document field for a plan field (default: the same name; map `id` to `_id` if that is where ids live). */
  field?: (field: string) => string;
}

const regexEscape = (text: string) => text.replace(/[.*+?^${}()|[\]\\/]/g, '\\$&');

/** A glob as an anchored regular expression source. */
function globRegex(pattern: string): string {
  return `^${parseGlob(pattern)
    .map((token) =>
      token.kind === 'star' ? '[\\s\\S]*' : token.kind === 'any' ? '[\\s\\S]' : regexEscape(token.value),
    )
    .join('')}$`;
}

/** The filter as a MongoDB query document. Dates and IP addresses refuse with UNSUPPORTED_FILTER. */
export function filterToMongo(
  filter: ResourceFilter,
  options: MongoFilterOptions = {},
): Record<string, unknown> {
  const name = (field: string) => options.field?.(field) ?? field;
  const compile = (item: ResourceFilter): Record<string, unknown> => {
    switch (item.kind) {
      case 'true':
        return {};
      case 'false':
        return { [name('id')]: { $in: [] } };
      case 'and':
        return { $and: item.filters.map(compile) };
      case 'or':
        return { $or: item.filters.map(compile) };
      case 'not':
        return { $nor: [compile(item.filter)] };
      case 'exists':
        return { [name(item.field)]: { $exists: true, $ne: null } };
      case 'type':
        if (item.type === 'ip') return unsupported('IP address', 'MongoDB');
        return {
          [name(item.field)]: { $type: item.type === 'string' ? 'string' : item.type === 'number' ? 'number' : 'bool' },
        };
      case 'equals':
        return item.ignoreCase
          ? {
              [name(item.field)]: {
                $in: item.values.map((value) =>
                  typeof value === 'string' ? new RegExp(`^${regexEscape(value)}$`, 'iu') : value,
                ),
              },
            }
          : { [name(item.field)]: { $in: item.values } };
      case 'compare':
        return { [name(item.field)]: { [`$${item.operator === 'le' ? 'lte' : item.operator === 'ge' ? 'gte' : item.operator}`]: item.value } };
      case 'like':
        return {
          [name(item.field)]: {
            $regex: globRegex(item.ignoreCase ? item.pattern.toLowerCase() : item.pattern),
            ...(item.ignoreCase ? { $options: 'iu' } : { $options: 'u' }),
          },
        };
      case 'contains':
        return { [name(item.field)]: { $elemMatch: { $eq: item.value } } };
      case 'date':
        return unsupported('Date', 'MongoDB');
      case 'ip':
        return unsupported('IP address', 'MongoDB');
    }
  };
  return compile(filter);
}

// --- description ---------------------------------------------------------------------------------

/** A readable rendering of a filter, for logs, UIs and tests. */
export function describeFilter(filter: ResourceFilter): string {
  const value = (item: FilterValue) => JSON.stringify(item);
  switch (filter.kind) {
    case 'true':
      return 'true';
    case 'false':
      return 'false';
    case 'and':
      return filter.filters.map((item) => (item.kind === 'or' ? `(${describeFilter(item)})` : describeFilter(item))).join(' and ');
    case 'or':
      return filter.filters.map((item) => (item.kind === 'and' ? `(${describeFilter(item)})` : describeFilter(item))).join(' or ');
    case 'not':
      return `not (${describeFilter(filter.filter)})`;
    case 'exists':
      return `${filter.field} exists`;
    case 'type':
      return `${filter.field} is ${filter.type}`;
    case 'equals':
      return filter.values.length === 1
        ? `${filter.field} = ${value(filter.values[0]!)}${filter.ignoreCase ? ' (any case)' : ''}`
        : `${filter.field} in [${filter.values.map(value).join(', ')}]${filter.ignoreCase ? ' (any case)' : ''}`;
    case 'compare':
      return `${filter.field} ${{ lt: '<', le: '<=', gt: '>', ge: '>=' }[filter.operator]} ${filter.value}`;
    case 'like':
      return `${filter.field} like ${JSON.stringify(filter.pattern)}${filter.ignoreCase ? ' (any case)' : ''}`;
    case 'date':
      return `${filter.field} ${filter.operator} ${filter.value}`;
    case 'ip':
      return `${filter.field} in ${filter.network}`;
    case 'contains':
      return `${filter.field} contains ${value(filter.value)}`;
  }
}
