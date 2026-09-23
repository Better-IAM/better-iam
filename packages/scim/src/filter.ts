import { IamError } from '@better-iam/core';
import { ENTERPRISE_SCHEMA, GROUP_SCHEMA, USER_SCHEMA, type ObjectValue } from './types.js';

/**
 * RFC 7644 §3.4.2.2 filters: `and`/`or`/`not(...)`, grouping, value paths (`emails[type eq "work"]`), sub-attributes,
 * schema-qualified names, and `eq ne co sw ew pr gt ge lt le`. The grammar is bounded (length, depth, comparison
 * count); anything outside it receives invalidFilter, never an unfiltered result.
 */
export type FilterNode =
  | { kind: 'and' | 'or'; left: FilterNode; right: FilterNode }
  | { kind: 'not'; node: FilterNode }
  | { kind: 'compare'; path: string[]; op: string; value?: unknown }
  | { kind: 'valuePath'; path: string[]; filter: FilterNode };

const MAX_FILTER_LENGTH = 2048;
const MAX_DEPTH = 16;
const MAX_COMPARISONS = 64;
const OPERATORS = new Set(['eq', 'ne', 'co', 'sw', 'ew', 'pr', 'gt', 'ge', 'lt', 'le']);
/** Case-exact attributes: identifiers compare byte-for-byte, everything else case-insensitively. */
const CASE_EXACT = new Set(['id', 'externalid', 'members.value']);
const BOOLEAN = new Set(['active', 'primary']);

type Token = { type: 'word' | 'string' | '(' | ')' | '[' | ']'; value: string };

function tokenize(input: string): Token[] {
  const tokens: Token[] = [];
  let index = 0;
  while (index < input.length) {
    const char = input[index]!;
    if (/\s/.test(char)) {
      index++;
      continue;
    }
    if ('()[]'.includes(char)) {
      tokens.push({ type: char as Token['type'], value: char });
      index++;
      continue;
    }
    if (char === '"') {
      const match = /^"(?:[^"\\]|\\.)*"/.exec(input.slice(index));
      if (!match) throw new IamError('invalidFilter', 'Unterminated string in filter.');
      tokens.push({ type: 'string', value: match[0] });
      index += match[0].length;
      continue;
    }
    const match = /^[A-Za-z0-9_:.$+-]+/.exec(input.slice(index));
    if (!match) throw new IamError('invalidFilter', `Unexpected character "${char}" in filter.`);
    tokens.push({ type: 'word', value: match[0] });
    index += match[0].length;
  }
  return tokens;
}

/** Splits a (possibly schema-qualified) attribute path into lowercase segments; the enterprise extension is one key. */
export function attributePath(raw: string): string[] {
  const lower = raw.toLowerCase();
  for (const schema of [ENTERPRISE_SCHEMA, USER_SCHEMA, GROUP_SCHEMA]) {
    const prefix = `${schema.toLowerCase()}:`;
    if (!lower.startsWith(prefix)) continue;
    const rest = raw.slice(prefix.length);
    if (!rest)
      throw new IamError('invalidFilter', 'Attribute name is missing after the schema URN.');
    return schema === ENTERPRISE_SCHEMA
      ? [ENTERPRISE_SCHEMA.toLowerCase(), ...attributePath(rest)]
      : attributePath(rest);
  }
  if (lower === ENTERPRISE_SCHEMA.toLowerCase()) return [lower];
  if (lower.startsWith('urn:')) throw new IamError('invalidFilter', 'Unsupported schema URN.');
  const segments = lower.split('.');
  if (segments.length > 3 || segments.some((segment) => !/^[a-z$][a-z0-9_$-]*$/.test(segment)))
    throw new IamError('invalidFilter', `Invalid attribute path "${raw}".`);
  return segments;
}

class Parser {
  private position = 0;
  private comparisons = 0;
  constructor(private readonly tokens: Token[]) {}

  parse(): FilterNode {
    const node = this.or(0);
    if (this.position !== this.tokens.length)
      throw new IamError('invalidFilter', 'Unexpected trailing filter content.');
    return node;
  }
  private peek(): Token | undefined {
    return this.tokens[this.position];
  }
  private keyword(word: string): boolean {
    const token = this.peek();
    if (token?.type === 'word' && token.value.toLowerCase() === word) {
      this.position++;
      return true;
    }
    return false;
  }
  private expect(type: Token['type']): Token {
    const token = this.tokens[this.position++];
    if (!token || token.type !== type)
      throw new IamError('invalidFilter', `Expected "${type}" in filter.`);
    return token;
  }
  private or(depth: number): FilterNode {
    let node = this.and(depth);
    while (this.keyword('or')) node = { kind: 'or', left: node, right: this.and(depth) };
    return node;
  }
  private and(depth: number): FilterNode {
    let node = this.unary(depth);
    while (this.keyword('and')) node = { kind: 'and', left: node, right: this.unary(depth) };
    return node;
  }
  private unary(depth: number): FilterNode {
    if (depth > MAX_DEPTH) throw new IamError('invalidFilter', 'Filter is nested too deeply.');
    const token = this.peek();
    if (token?.type === 'word' && token.value.toLowerCase() === 'not') {
      const next = this.tokens[this.position + 1];
      if (next?.type === '(') {
        this.position += 2;
        const node = this.or(depth + 1);
        this.expect(')');
        return { kind: 'not', node };
      }
    }
    if (token?.type === '(') {
      this.position++;
      const node = this.or(depth + 1);
      this.expect(')');
      return node;
    }
    return this.comparison(depth);
  }
  private comparison(depth: number): FilterNode {
    const attribute = this.expect('word');
    const path = attributePath(attribute.value);
    if (this.peek()?.type === '[') {
      this.position++;
      const filter = this.or(depth + 1);
      this.expect(']');
      return { kind: 'valuePath', path, filter };
    }
    if (++this.comparisons > MAX_COMPARISONS)
      throw new IamError('invalidFilter', 'Filter has too many comparisons.');
    const operator = this.expect('word').value.toLowerCase();
    if (!OPERATORS.has(operator))
      throw new IamError('invalidFilter', `Unsupported filter operator "${operator}".`);
    if (operator === 'pr') return { kind: 'compare', path, op: operator };
    const token = this.tokens[this.position++];
    if (!token || (token.type !== 'string' && token.type !== 'word'))
      throw new IamError('invalidFilter', 'Filter comparison is missing a value.');
    let value: unknown;
    try {
      value = JSON.parse(token.type === 'word' ? token.value.toLowerCase() : token.value);
    } catch {
      throw new IamError('invalidFilter', `Invalid filter value ${token.value}.`);
    }
    if (typeof value === 'object' && value !== null)
      throw new IamError(
        'invalidFilter',
        'Filter values must be strings, numbers, booleans or null.',
      );
    const leaf = path[path.length - 1]!;
    if (BOOLEAN.has(leaf) && typeof value !== 'boolean' && value !== null)
      throw new IamError('invalidFilter', `${leaf} requires a boolean comparison.`);
    if (typeof value === 'boolean' && !['eq', 'ne'].includes(operator))
      throw new IamError('invalidFilter', 'Booleans support only eq and ne.');
    if (['co', 'sw', 'ew'].includes(operator) && typeof value !== 'string')
      throw new IamError('invalidFilter', `${operator} requires a string value.`);
    return { kind: 'compare', path, op: operator, value };
  }
}

export function parseFilterExpression(filter: string): FilterNode {
  if (filter.length > MAX_FILTER_LENGTH) throw new IamError('invalidFilter', 'Filter is too long.');
  const tokens = tokenize(filter);
  if (!tokens.length) throw new IamError('invalidFilter', 'Filter is empty.');
  return new Parser(tokens).parse();
}

/** Case-insensitive property lookup, as SCIM attribute names are case-insensitive. */
export function property(value: unknown, key: string): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const record = value as ObjectValue;
  if (key in record) return record[key];
  const found = Object.keys(record).find((name) => name.toLowerCase() === key);
  return found === undefined ? undefined : record[found];
}

/** All leaf values at a path; multi-valued attributes fan out and a complex value compares by its `value`. */
function resolve(value: unknown, path: string[]): unknown[] {
  let current: unknown[] = [value];
  for (const segment of path) {
    const next: unknown[] = [];
    for (const item of current)
      for (const child of [property(item, segment)].flat())
        if (child !== undefined && child !== null) next.push(child);
    current = next;
  }
  return current.map((item) =>
    item && typeof item === 'object' && !Array.isArray(item) ? property(item, 'value') : item,
  );
}

function compare(actual: unknown, op: string, expected: unknown, caseExact: boolean): boolean {
  if (actual === undefined || actual === null) return op === 'ne' && expected !== null;
  const normalize = (item: unknown) =>
    typeof item === 'string' && !caseExact ? item.toLowerCase() : item;
  const left = normalize(actual);
  const right = normalize(expected);
  switch (op) {
    case 'eq':
      return left === right;
    case 'ne':
      return left !== right;
    case 'co':
      return typeof left === 'string' && left.includes(right as string);
    case 'sw':
      return typeof left === 'string' && left.startsWith(right as string);
    case 'ew':
      return typeof left === 'string' && left.endsWith(right as string);
    default: {
      if (typeof left !== typeof right || (typeof left !== 'string' && typeof left !== 'number'))
        return false;
      const a = left as string | number;
      const b = right as string | number;
      return op === 'gt' ? a > b : op === 'ge' ? a >= b : op === 'lt' ? a < b : a <= b;
    }
  }
}

export function evaluateFilter(node: FilterNode, value: unknown, prefix: string[] = []): boolean {
  switch (node.kind) {
    case 'and':
      return evaluateFilter(node.left, value, prefix) && evaluateFilter(node.right, value, prefix);
    case 'or':
      return evaluateFilter(node.left, value, prefix) || evaluateFilter(node.right, value, prefix);
    case 'not':
      return !evaluateFilter(node.node, value, prefix);
    case 'valuePath': {
      let items: unknown[] = [value];
      for (const segment of node.path)
        items = items.flatMap((item) => [property(item, segment)].flat()).filter(Boolean);
      return items.some((item) => evaluateFilter(node.filter, item, [...prefix, ...node.path]));
    }
    case 'compare': {
      const caseExact = CASE_EXACT.has([...prefix, ...node.path].join('.'));
      if (node.op === 'pr') {
        let items: unknown[] = [value];
        for (const segment of node.path)
          items = items.flatMap((item) => [property(item, segment)].flat());
        return items.some(
          (item) =>
            item !== undefined &&
            item !== null &&
            item !== '' &&
            !(Array.isArray(item) && !item.length),
        );
      }
      const values = resolve(value, node.path);
      if (!values.length) return compare(undefined, node.op, node.value, caseExact);
      return node.op === 'ne'
        ? values.every((item) => compare(item, 'ne', node.value, caseExact))
        : values.some((item) => compare(item, node.op, node.value, caseExact));
    }
  }
}

/** Parses a filter into a predicate over rendered SCIM resources; an absent filter matches everything. */
export function parseScimFilter(
  filter: string | null | undefined,
): (value: ObjectValue) => boolean {
  if (!filter) return () => true;
  const node = parseFilterExpression(filter);
  return (value) => evaluateFilter(node, value);
}

/** A sort key per RFC 7644 §3.4.2.3: multi-valued attributes sort by their primary (or first) value. */
function sortKey(resource: unknown, path: string[]): unknown {
  let current: unknown = resource;
  for (const segment of path) {
    let next = property(current, segment);
    if (Array.isArray(next))
      next = next.find((item) => property(item, 'primary') === true) ?? next[0];
    current = next;
  }
  if (current && typeof current === 'object') current = property(current, 'value');
  return typeof current === 'string' ? current.toLowerCase() : current;
}

export function sortResources<T extends ObjectValue>(
  resources: T[],
  sortBy: string | null | undefined,
  sortOrder: string | null | undefined,
): T[] {
  if (!sortBy) return resources;
  const order = (sortOrder ?? 'ascending').toLowerCase();
  if (order !== 'ascending' && order !== 'descending')
    throw new IamError('invalidValue', 'sortOrder must be ascending or descending.');
  const path = attributePath(sortBy);
  const direction = order === 'ascending' ? 1 : -1;
  return resources
    .map((resource) => ({ resource, key: sortKey(resource, path) }))
    .sort((a, b) => {
      // Unassigned values sort last in either direction.
      if (a.key === undefined || a.key === null)
        return b.key === undefined || b.key === null ? 0 : 1;
      if (b.key === undefined || b.key === null) return -1;
      return (a.key < b.key ? -1 : a.key > b.key ? 1 : 0) * direction;
    })
    .map((row) => row.resource);
}

/** Attribute projection (§3.4.2.5); `id` and `schemas` are always returned. */
export function projectResource(
  resource: ObjectValue,
  attributes: string[] | undefined,
  excluded: string[] | undefined,
): ObjectValue {
  if (attributes?.length && excluded?.length)
    throw new IamError('invalidValue', 'attributes and excludedAttributes are mutually exclusive.');
  const always = new Set(['id', 'schemas']);
  const match = (key: string) =>
    Object.keys(resource).find((name) => name.toLowerCase() === key) ?? key;
  if (attributes?.length) {
    const result: ObjectValue = { schemas: resource.schemas, id: resource.id };
    for (const raw of attributes) {
      const [top, ...rest] = attributePath(raw);
      const key = match(top!);
      const value = resource[key];
      if (value === undefined || always.has(key)) continue;
      if (!rest.length) result[key] = value;
      else {
        const pick = (item: unknown) => {
          const picked: ObjectValue = {};
          let source = item;
          let target = picked;
          rest.forEach((segment, index) => {
            const name =
              Object.keys((source as ObjectValue) ?? {}).find((n) => n.toLowerCase() === segment) ??
              segment;
            const child = property(source, segment);
            if (child === undefined) return;
            if (index === rest.length - 1) target[name] = child;
            else {
              target[name] = {};
              target = target[name] as ObjectValue;
              source = child;
            }
          });
          return picked;
        };
        const projected = Array.isArray(value) ? value.map(pick) : pick(value);
        const existing = result[key];
        result[key] =
          existing && typeof existing === 'object' && !Array.isArray(existing)
            ? { ...(existing as ObjectValue), ...(projected as ObjectValue) }
            : projected;
      }
    }
    return result;
  }
  if (excluded?.length) {
    const result: ObjectValue = structuredClone(resource);
    for (const raw of excluded) {
      const [top, ...rest] = attributePath(raw);
      const key = match(top!);
      if (always.has(key)) continue;
      if (!rest.length) delete result[key];
      else
        for (const item of [result[key]].flat()) {
          if (!item || typeof item !== 'object') continue;
          const leaf = rest[rest.length - 1]!;
          let parent = item as ObjectValue;
          for (const segment of rest.slice(0, -1))
            parent = property(parent, segment) as ObjectValue;
          if (parent && typeof parent === 'object') {
            const name = Object.keys(parent).find((n) => n.toLowerCase() === leaf);
            if (name) delete parent[name];
          }
        }
    }
    return result;
  }
  return resource;
}

/** Splits a comma-separated `attributes` / `excludedAttributes` query value. */
export function attributeList(value: unknown): string[] | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  const list = Array.isArray(value) ? value : String(value).split(',');
  if (list.length > 50 || list.some((item) => typeof item !== 'string'))
    throw new IamError('invalidValue', 'Attribute lists hold at most 50 attribute names.');
  return list.map((item: string) => item.trim()).filter(Boolean);
}
