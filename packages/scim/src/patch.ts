import { IamError } from '@better-iam/core';
import { attributePath, evaluateFilter, parseFilterExpression, type FilterNode } from './filter.js';
import { ENTERPRISE_SCHEMA, type ObjectValue, type ResourceType } from './types.js';

/** Canonical casing for every attribute PATCH may address; SCIM attribute names are case-insensitive. */
const CANONICAL = new Map(
  [
    'userName',
    'displayName',
    'externalId',
    'active',
    'emails',
    'name',
    'title',
    'members',
    'formatted',
    'familyName',
    'givenName',
    'middleName',
    'honorificPrefix',
    'honorificSuffix',
    'value',
    'type',
    'primary',
    'display',
    '$ref',
    'employeeNumber',
    'costCenter',
    'organization',
    'division',
    'department',
    'manager',
    ENTERPRISE_SCHEMA,
  ].map((name) => [name.toLowerCase(), name]),
);
const TOP_LEVEL: Record<ResourceType, string[]> = {
  Users: [
    'userName',
    'displayName',
    'externalId',
    'active',
    'emails',
    'name',
    'title',
    ENTERPRISE_SCHEMA,
  ],
  Groups: ['displayName', 'externalId', 'members'],
};
const REQUIRED: Record<ResourceType, string[]> = {
  Users: ['userName', 'active'],
  Groups: ['displayName'],
};
const BOOLEAN = new Set(['active', 'primary']);

interface PatchPath {
  keys: string[];
  filter?: FilterNode;
  sub?: string;
}

function canonical(segments: string[], type: ResourceType): string[] {
  const keys = segments.map((segment) => {
    const name = CANONICAL.get(segment);
    if (!name) throw new IamError('invalidPath', `Unsupported PATCH attribute "${segment}".`);
    return name;
  });
  if (!TOP_LEVEL[type].includes(keys[0]!))
    throw new IamError('invalidPath', `"${keys[0]}" is not a mutable ${type} attribute.`);
  return keys;
}

/** `attrPath [ "[" valFilter "]" ] [ "." subAttr ]`, with schema-qualified names (RFC 7644 §3.5.2). */
export function parsePatchPath(path: string, type: ResourceType): PatchPath {
  const open = path.indexOf('[');
  const segments = (raw: string) => {
    try {
      return attributePath(raw);
    } catch {
      throw new IamError('invalidPath', `Invalid PATCH path "${path}".`);
    }
  };
  if (open === -1) return { keys: canonical(segments(path), type) };
  const close = path.lastIndexOf(']');
  const rest = path.slice(close + 1);
  if (close < open || (rest && !/^\.[A-Za-z$][\w$-]*$/.test(rest)))
    throw new IamError('invalidPath', `Invalid PATCH path "${path}".`);
  const keys = canonical(segments(path.slice(0, open)), type);
  if (keys.length !== 1 || !['emails', 'members'].includes(keys[0]!))
    throw new IamError('invalidPath', 'Value filters apply only to multi-valued attributes.');
  const filter = parseFilterExpression(path.slice(open + 1, close));
  const sub = rest
    ? canonical([keys[0]!.toLowerCase(), rest.slice(1).toLowerCase()], type)[1]
    : undefined;
  return { keys, filter, ...(sub ? { sub } : {}) };
}

/** Entra ID sends booleans as "True"/"False" strings; accept exactly those spellings for boolean attributes. */
function coerce(key: string, value: unknown): unknown {
  if (BOOLEAN.has(key) && typeof value === 'string' && /^(true|false)$/i.test(value))
    return value.toLowerCase() === 'true';
  return value;
}
const isObject = (value: unknown): value is ObjectValue =>
  !!value && typeof value === 'object' && !Array.isArray(value);

/** The attributes a simple `sub eq "x"` (optionally and-ed) filter pins, used to seed an added multi-valued entry. */
function seed(filter: FilterNode): ObjectValue | undefined {
  if (filter.kind === 'compare' && filter.op === 'eq' && filter.path.length === 1) {
    const key = CANONICAL.get(filter.path[0]!);
    return key ? { [key]: filter.value } : undefined;
  }
  if (filter.kind === 'and') {
    const left = seed(filter.left);
    const right = seed(filter.right);
    return left && right ? { ...left, ...right } : undefined;
  }
  return undefined;
}

function applyFiltered(
  document: ObjectValue,
  operation: string,
  path: PatchPath,
  value: unknown,
): void {
  const key = path.keys[0]!;
  const items = (Array.isArray(document[key]) ? document[key] : []) as ObjectValue[];
  const matched = items.filter((item) => evaluateFilter(path.filter!, item, [key.toLowerCase()]));
  if (operation === 'remove') {
    if (!path.sub) document[key] = items.filter((item) => !matched.includes(item));
    else for (const item of matched) delete item[path.sub];
    return;
  }
  if (!matched.length) {
    const initial = seed(path.filter!);
    if (operation === 'replace' || !initial)
      throw new IamError('noTarget', 'The value filter matched no values.');
    const entry = path.sub
      ? { ...initial, [path.sub]: coerce(path.sub, value) }
      : { ...initial, ...(isObject(value) ? value : {}) };
    document[key] = [...items, entry];
    return;
  }
  for (const item of matched) {
    if (path.sub) item[path.sub] = coerce(path.sub, value);
    else {
      if (!isObject(value)) throw new IamError('invalidValue', 'Expected an object value.');
      if (operation === 'replace') for (const name of Object.keys(item)) delete item[name];
      Object.assign(item, value);
    }
  }
}

function applyAt(
  document: ObjectValue,
  type: ResourceType,
  operation: string,
  keys: string[],
  input: unknown,
): void {
  const leaf = keys[keys.length - 1]!;
  const value = coerce(leaf, input);
  let parent = document;
  for (const key of keys.slice(0, -1)) {
    const child = parent[key];
    if (Array.isArray(child))
      throw new IamError('invalidPath', `Use a value filter to modify one value of ${key}.`);
    if (!isObject(child)) {
      if (operation === 'remove') return;
      parent[key] = {};
    }
    parent = parent[key] as ObjectValue;
  }
  const current = parent[leaf];
  if (operation === 'remove') {
    if (keys.length === 1 && REQUIRED[type].includes(leaf))
      throw new IamError('mutability', 'Required attribute cannot be removed.');
    // Entra ID removes individual members as `{ op: "remove", path: "members", value: [{ value }] }`.
    if (Array.isArray(current) && Array.isArray(value)) {
      const removed = new Set(value.map((item) => (isObject(item) ? item.value : item)));
      parent[leaf] = current.filter((item) => !removed.has(isObject(item) ? item.value : item));
    } else delete parent[leaf];
    return;
  }
  if (operation === 'add' && Array.isArray(current)) parent[leaf] = [...current, ...[value].flat()];
  else if (operation === 'add' && isObject(current) && isObject(value))
    parent[leaf] = { ...current, ...value };
  else parent[leaf] = value;
}

/** Applies one PatchOp operation in place to a resource's writable document. */
export function applyPatchOperation(
  document: ObjectValue,
  type: ResourceType,
  operation: string,
  path: string | undefined,
  value: unknown,
): void {
  if (path === undefined) {
    if (operation === 'remove') throw new IamError('noTarget', 'remove requires a path.');
    if (!isObject(value))
      throw new IamError('invalidValue', 'A PATCH without a path requires an object value.');
    for (const [name, item] of Object.entries(value)) {
      if (name === 'schemas') continue;
      let segments: string[];
      try {
        segments = attributePath(name);
      } catch {
        throw new IamError('invalidPath', `Invalid attribute "${name}".`);
      }
      const keys = canonical(segments, type);
      // A whole extension object merges key by key so schema-qualified and nested forms behave alike.
      if (keys.length === 1 && keys[0] === ENTERPRISE_SCHEMA && isObject(item))
        for (const [sub, subValue] of Object.entries(item))
          applyAt(
            document,
            type,
            operation,
            canonical([...segments, sub.toLowerCase()], type),
            subValue,
          );
      else applyAt(document, type, operation, keys, item);
    }
    return;
  }
  const parsed = parsePatchPath(path, type);
  if (parsed.filter) applyFiltered(document, operation, parsed, value);
  else applyAt(document, type, operation, parsed.keys, value);
}
