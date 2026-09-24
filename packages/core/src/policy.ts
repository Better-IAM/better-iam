import { IamError } from './index.js';

export type ConditionOperator =
  | 'StringEquals'
  | 'StringNotEquals'
  | 'StringEqualsIgnoreCase'
  | 'StringNotEqualsIgnoreCase'
  | 'StringLike'
  | 'StringNotLike'
  | 'StringLikeIgnoreCase'
  | 'Bool'
  | 'NumericEquals'
  | 'NumericNotEquals'
  | 'NumericLessThan'
  | 'NumericLessThanEquals'
  | 'NumericGreaterThan'
  | 'NumericGreaterThanEquals'
  | 'DateBefore'
  | 'DateAfter'
  | 'IpAddress'
  | 'NotIpAddress'
  | 'ArrayContains'
  | 'ArrayContainsAll'
  | 'Exists';
type ConditionValue = string | number | boolean;
export interface PolicyStatement {
  sid?: string;
  effect: 'allow' | 'deny';
  actions: string[];
  resources: string[];
  conditions?: Partial<
    Record<ConditionOperator, Record<string, ConditionValue | ConditionValue[]>>
  >;
}
export interface PolicyDocument {
  version: 1;
  statements: PolicyStatement[];
}
export interface EvaluationRequest {
  action: string;
  resource: string;
  context?: Record<string, unknown>;
}
export interface EvaluationInput extends EvaluationRequest {
  grants: PolicyDocument[];
  boundaries?: PolicyDocument[];
}
export interface Decision {
  allowed: boolean;
  reason: string;
  matched: string[];
}

const operators = new Set<ConditionOperator>([
  'StringEquals',
  'StringNotEquals',
  'StringEqualsIgnoreCase',
  'StringNotEqualsIgnoreCase',
  'StringLike',
  'StringNotLike',
  'StringLikeIgnoreCase',
  'Bool',
  'NumericEquals',
  'NumericNotEquals',
  'NumericLessThan',
  'NumericLessThanEquals',
  'NumericGreaterThan',
  'NumericGreaterThanEquals',
  'DateBefore',
  'DateAfter',
  'IpAddress',
  'NotIpAddress',
  'ArrayContains',
  'ArrayContainsAll',
  'Exists',
]);
/**
 * Negated operators succeed only when the actual value differs from every listed value; every other operator
 * succeeds when any listed value matches. `ArrayContainsAll` requires every listed value to be present.
 */
const negated = new Set<ConditionOperator>([
  'StringNotEquals',
  'StringNotEqualsIgnoreCase',
  'StringNotLike',
  'NumericNotEquals',
  'NotIpAddress',
]);
const everyValue = new Set<ConditionOperator>([...negated, 'ArrayContainsAll']);
const unsafeKeys = new Set(['__proto__', 'prototype', 'constructor']);
function invalid(message: string): never {
  throw new IamError('INVALID_POLICY', message);
}
const object = (value: unknown): value is Record<string, unknown> =>
  value !== null &&
  typeof value === 'object' &&
  !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));
const nonempty = (value: unknown, max = 512): value is string =>
  typeof value === 'string' &&
  value.length > 0 &&
  value.length <= max &&
  !/[\u0000-\u001f\u007f]/u.test(value);

function onlyKeys(value: Record<string, unknown>, allowed: string[]): void {
  if (
    Object.keys(value).some((key) => !allowed.includes(key)) ||
    Object.getOwnPropertySymbols(value).length
  )
    invalid('Unknown policy field');
}

/**
 * Policy variables: `${principal.id}` inside a resource pattern or a string condition value is replaced
 * with the trusted context value of that key before matching. Substituted values always match literally,
 * so a value containing `*` or `?` cannot widen a pattern. An unresolved variable never matches.
 */
const variable = /\$\{([A-Za-z_][A-Za-z0-9_.:-]{0,127})\}/y;
const variableMarker = '${';
// Without the `u` flag the class sees UTF-16 code units, so it finds the halves of any astral character.
const surrogate = /[\uD800-\uDFFF]/;
type Token = { kind: 'star' } | { kind: 'any' } | { kind: 'char'; value: string };

function globTokens(pattern: string, into: Token[]): void {
  for (const char of pattern)
    into.push(
      char === '*'
        ? { kind: 'star' }
        : char === '?'
          ? { kind: 'any' }
          : { kind: 'char', value: char },
    );
}
function literalTokens(value: string, into: Token[]): void {
  for (const char of value) into.push({ kind: 'char', value: char });
}
/** Splits a pattern into wildcard and literal tokens, substituting variables from context. Returns undefined when a variable is unresolved. */
function tokenize(
  pattern: string,
  context: Record<string, unknown> | undefined,
): Token[] | undefined {
  const tokens: Token[] = [];
  let cursor = 0;
  let search = 0;
  for (
    let index = pattern.indexOf(variableMarker, search);
    index !== -1;
    index = pattern.indexOf(variableMarker, search)
  ) {
    variable.lastIndex = index;
    const match = variable.exec(pattern);
    // A malformed reference is rejected by validation; at evaluation it is treated as literal text.
    if (!match) {
      search = index + variableMarker.length;
      continue;
    }
    globTokens(pattern.slice(cursor, index), tokens);
    const value = context?.[match[1]!];
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean')
      return undefined;
    literalTokens(String(value), tokens);
    cursor = search = index + match[0].length;
  }
  globTokens(pattern.slice(cursor), tokens);
  return tokens;
}
/**
 * Work left in the running evaluation, in characters examined (roughly). evaluatePolicy sets it; matching outside an
 * evaluation is unbounded. The engine is synchronous, so one oversized document or context value would otherwise hold
 * the event loop (and, with a database lock, every tenant) for as long as it takes.
 */
let workLeft = Infinity;
const evaluationWork = 4_000_000;
class EvaluationLimit extends Error {}
function spend(units: number): void {
  workLeft -= units;
  if (workLeft < 0) throw new EvaluationLimit('Policy evaluation limit');
}

function matchTokens(tokens: Token[], value: string): boolean {
  // Greedy wildcard matching avoids catastrophic regular-expression backtracking.
  const chars = [...value];
  spend(chars.length + tokens.length);
  let p = 0;
  let v = 0;
  let star = -1;
  let retry = 0;
  while (v < chars.length) {
    spend(1);
    const token = tokens[p];
    if (token && (token.kind === 'any' || (token.kind === 'char' && token.value === chars[v]))) {
      p++;
      v++;
    } else if (token?.kind === 'star') {
      star = p++;
      retry = v;
    } else if (star !== -1) {
      p = star + 1;
      v = ++retry;
    } else return false;
  }
  while (tokens[p]?.kind === 'star') p++;
  return p === tokens.length;
}
/** Every `${...}` in a value must be a well-formed variable reference. */
export function validPolicyVariables(value: string): boolean {
  for (let index = value.indexOf(variableMarker); index !== -1; ) {
    variable.lastIndex = index;
    const match = variable.exec(value);
    if (!match) return false;
    index = value.indexOf(variableMarker, index + match[0].length);
  }
  return true;
}
/** Resolves the variables of a string condition value. Returns undefined when any variable is unresolved. */
export function resolvePolicyValue(
  value: string,
  context: Record<string, unknown> | undefined,
): string | undefined {
  if (!value.includes(variableMarker)) return value;
  const tokens = tokenize(value, context);
  return tokens
    ?.map((token) => (token.kind === 'star' ? '*' : token.kind === 'any' ? '?' : token.value))
    .join('');
}

/** Glob matching is anchored; only * and ? are operators. No regular expressions are accepted. Variables resolve from context. */
export function matchPattern(
  pattern: string,
  value: string,
  context?: Record<string, unknown>,
): boolean {
  if (pattern.includes(variableMarker)) {
    const tokens = tokenize(pattern, context);
    return tokens !== undefined && matchTokens(tokens, value);
  }
  // `?` is one character (code point) on every path; astral characters take the token path, which counts them so.
  if (pattern.includes('?') || surrogate.test(pattern) || surrogate.test(value)) {
    const tokens: Token[] = [];
    globTokens(pattern, tokens);
    return matchTokens(tokens, value);
  }
  return matchStars(pattern, value);
}

/**
 * A glob whose only operator is `*`: the text before the first `*` and after the last must anchor the value, and each
 * piece in between is found at its leftmost place after the previous one (which is optimal for `*`). The searches are
 * the engine's native substring search, so a long pattern against a long value costs about their combined length. A
 * literal `*` in the value is ordinary text here, so it never stands in for the pattern's wildcard.
 */
function matchStars(pattern: string, value: string): boolean {
  spend(pattern.length + value.length);
  const pieces = pattern.split('*');
  if (pieces.length === 1) return pattern === value;
  const first = pieces[0]!;
  const last = pieces[pieces.length - 1]!;
  if (
    value.length < first.length + last.length ||
    !value.startsWith(first) ||
    !value.endsWith(last)
  )
    return false;
  const end = value.length - last.length;
  let cursor = first.length;
  for (let index = 1; index < pieces.length - 1; index++) {
    const piece = pieces[index]!;
    if (!piece) continue;
    const at = value.indexOf(piece, cursor);
    if (at === -1 || at + piece.length > end) return false;
    cursor = at + piece.length;
  }
  return true;
}

interface Address {
  bits: number;
  value: bigint;
}
function ipv4(value: string): Address | undefined {
  const parts = value.split('.');
  if (
    parts.length !== 4 ||
    parts.some((part) => !/^(0|[1-9]\d{0,2})$/u.test(part) || Number(part) > 255)
  )
    return undefined;
  return { bits: 32, value: parts.reduce((result, part) => (result << 8n) | BigInt(part), 0n) };
}

function ip(value: string): Address | undefined {
  if (value.includes('%') || value.includes('/') || value.includes('[') || value.includes(']'))
    return undefined;
  if (!value.includes(':')) return ipv4(value);
  let normalized = value;
  if (normalized.includes('.')) {
    const boundary = normalized.lastIndexOf(':');
    const suffix = ipv4(normalized.slice(boundary + 1));
    if (!suffix) return undefined;
    normalized = `${normalized.slice(0, boundary + 1)}${(suffix.value >> 16n).toString(16)}:${(suffix.value & 65535n).toString(16)}`;
  }
  const halves = normalized.split('::');
  if (halves.length > 2) return undefined;
  const left = halves[0] === '' ? [] : halves[0]!.split(':');
  const right = halves.length === 2 && halves[1] !== '' ? halves[1]!.split(':') : [];
  if ([...left, ...right].some((part) => !/^[\da-f]{1,4}$/iu.test(part))) return undefined;
  const total = left.length + right.length;
  if ((halves.length === 1 && total !== 8) || (halves.length === 2 && total >= 8)) return undefined;
  const parts =
    halves.length === 2 ? [...left, ...Array<string>(8 - total).fill('0'), ...right] : left;
  return {
    bits: 128,
    value: parts.reduce((result, part) => (result << 16n) | BigInt(`0x${part}`), 0n),
  };
}

function cidr(value: string): { address: Address; prefix: number } | undefined {
  const parts = value.split('/');
  if (parts.length > 2) return undefined;
  const address = ip(parts[0]!);
  if (!address) return undefined;
  if (parts.length === 2 && !/^(0|[1-9]\d{0,2})$/u.test(parts[1]!)) return undefined;
  const prefix = parts.length === 2 ? Number(parts[1]) : address.bits;
  return prefix <= address.bits ? { address, prefix } : undefined;
}

/** The IPv4 address carried by an IPv4-mapped IPv6 address (`::ffff:a.b.c.d`, RFC 4291 2.5.5.2), if it is one. */
function mappedIpv4(address: Address): Address | undefined {
  return address.bits === 128 && address.value >> 32n === 0xffffn
    ? { bits: 32, value: address.value & 0xffffffffn }
    : undefined;
}

function inNetwork(actual: string, expected: string): boolean {
  let address = ip(actual);
  const network = cidr(expected);
  if (!address || !network) return false;
  let base = network.address;
  let prefix = network.prefix;
  // Dual-stack listeners and proxies report IPv4 clients as IPv4-mapped IPv6 (::ffff:198.51.100.7, or the hex
  // ::ffff:c633:6407). Across families the mapped form stands for its IPv4 address, on either side, so how the
  // listener spelled a client can neither sidestep a block nor get an allowed office refused. Same-family
  // comparisons are unchanged, so this only ever adds matches between equivalent addresses.
  if (address.bits !== base.bits) {
    const unmapped = mappedIpv4(address);
    const mappedNetwork = prefix >= 96 ? mappedIpv4(base) : undefined;
    if (unmapped) address = unmapped;
    else if (mappedNetwork) {
      base = mappedNetwork;
      prefix -= 96;
    } else return false;
  }
  const shift = BigInt(address.bits - prefix);
  return address.value >> shift === base.value >> shift;
}

/** True for an IPv4/IPv6 address or CIDR block, as accepted by the `IpAddress` operator. */
export function isIpRange(value: string): boolean {
  return typeof value === 'string' && cidr(value) !== undefined;
}

/**
 * True when `address` lies inside `network` (an address or CIDR block of the same family). An IPv4-mapped IPv6
 * address (`::ffff:198.51.100.7`) matches the IPv4 networks that contain its IPv4 address, and an IPv4 address the
 * IPv4-mapped networks (`::ffff:198.51.100.0/120`) that contain it.
 */
export function ipMatches(address: string, network: string): boolean {
  return inNetwork(address, network);
}

/**
 * The key a per-address counter uses for a client: an IPv4 address as itself (the IPv4-mapped IPv6 form folded to
 * it), an IPv6 address as its /64 (`2001:db8:1:2::/64`), since one subscriber or host normally controls a whole
 * /64 and can rotate through it at will. Spelling variants of one address (case, zero compression) share a key.
 * Undefined when the value is not an IP address.
 */
export function ipCounterKey(address: string): string | undefined {
  if (typeof address !== 'string') return undefined;
  const parsed = ip(address.trim());
  if (!parsed) return undefined;
  const v4 = parsed.bits === 32 ? parsed : mappedIpv4(parsed);
  if (v4) return [24n, 16n, 8n, 0n].map((shift) => String((v4.value >> shift) & 255n)).join('.');
  const groups = [112n, 96n, 80n, 64n].map((shift) =>
    ((parsed.value >> shift) & 0xffffn).toString(16),
  );
  return `${groups.join(':')}::/64`;
}

function timestamp(value: unknown): number | undefined {
  if (
    typeof value !== 'string' ||
    !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?(?:Z|[+-]\d\d:\d\d)$/u.test(value)
  )
    return undefined;
  const date = Number(Date.parse(value));
  if (!Number.isFinite(date)) return undefined;
  // Reject normalised invalid calendar dates (for example February 31).
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

function validValue(operator: ConditionOperator, value: unknown): boolean {
  switch (operator) {
    case 'Bool':
    case 'Exists':
      return typeof value === 'boolean';
    case 'NumericEquals':
    case 'NumericNotEquals':
    case 'NumericLessThan':
    case 'NumericLessThanEquals':
    case 'NumericGreaterThan':
    case 'NumericGreaterThanEquals':
      return typeof value === 'number' && Number.isFinite(value);
    case 'DateBefore':
    case 'DateAfter':
      return timestamp(value) !== undefined;
    case 'IpAddress':
    case 'NotIpAddress':
      return typeof value === 'string' && cidr(value) !== undefined;
    case 'StringEquals':
    case 'StringNotEquals':
    case 'StringEqualsIgnoreCase':
    case 'StringNotEqualsIgnoreCase':
    case 'StringLike':
    case 'StringNotLike':
    case 'StringLikeIgnoreCase':
      return typeof value === 'string' && value.length <= 2048;
    case 'ArrayContains':
    case 'ArrayContainsAll':
      return (
        (typeof value === 'string' && value.length <= 2048) ||
        (typeof value === 'number' && Number.isFinite(value)) ||
        typeof value === 'boolean'
      );
  }
}

/** Validate untrusted documents before storage and again before evaluation. */
export function validatePolicy(value: unknown): asserts value is PolicyDocument {
  if (!object(value)) invalid('Policy must be a plain object');
  onlyKeys(value, ['version', 'statements']);
  if (value.version !== 1 || !Array.isArray(value.statements) || value.statements.length > 128)
    invalid('Expected policy version 1 and at most 128 statements');
  const sids = new Set<string>();
  for (const statement of value.statements) {
    if (!object(statement)) invalid('Statement must be a plain object');
    onlyKeys(statement, ['sid', 'effect', 'actions', 'resources', 'conditions']);
    if (statement.effect !== 'allow' && statement.effect !== 'deny')
      invalid('Statement effect must be allow or deny');
    if (statement.sid !== undefined) {
      if (!nonempty(statement.sid, 128) || sids.has(statement.sid))
        invalid('Statement IDs must be nonempty and unique');
      sids.add(statement.sid);
    }
    for (const field of ['actions', 'resources'] as const) {
      const items = statement[field];
      if (
        !Array.isArray(items) ||
        items.length === 0 ||
        items.length > 128 ||
        !items.every((item) => nonempty(item))
      )
        invalid(`${field} must contain 1–128 nonempty patterns`);
      if (field === 'actions' && items.some((item) => item.includes(variableMarker)))
        invalid('Policy variables are not allowed in actions');
      if (field === 'resources')
        for (const item of items) {
          if (!validPolicyVariables(item))
            invalid(`Malformed policy variable in resource pattern ${item}`);
          if (item.split('/')[0]!.includes(variableMarker))
            invalid('Policy variables may only appear after the resource type');
        }
    }
    if (statement.conditions !== undefined) {
      if (!object(statement.conditions) || Object.keys(statement.conditions).length === 0)
        invalid('Conditions must be a nonempty operator map');
      for (const [name, entries] of Object.entries(statement.conditions)) {
        if (
          !operators.has(name as ConditionOperator) ||
          !object(entries) ||
          Object.keys(entries).length === 0 ||
          Object.keys(entries).length > 64
        )
          invalid('Unknown operator or invalid condition attributes');
        for (const [key, expected] of Object.entries(entries)) {
          if (!nonempty(key, 128) || unsafeKeys.has(key)) invalid('Invalid condition attribute');
          const values = Array.isArray(expected) ? expected : [expected];
          if (
            values.length === 0 ||
            values.length > 64 ||
            !values.every((item) => validValue(name as ConditionOperator, item))
          )
            invalid(`Invalid value for condition ${name}`);
          if (values.some((item) => typeof item === 'string' && !validPolicyVariables(item)))
            invalid(`Malformed policy variable in condition ${name}`);
        }
      }
    }
  }
}

/** Typed document builder. Returns a detached document after runtime validation. */
export function definePolicy<const T extends PolicyDocument>(document: T): T {
  validatePolicy(document);
  return structuredClone(document);
}

const finite = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);
/** A scalar member test for array context values; string members honour policy variables. */
function member(
  actual: unknown[],
  expected: ConditionValue,
  context: Record<string, unknown> | undefined,
): boolean {
  const wanted = typeof expected === 'string' ? resolvePolicyValue(expected, context) : expected;
  spend(actual.length);
  return wanted !== undefined && actual.includes(wanted);
}

/** The positive comparison for an operator; negated operators are evaluated as the inverse of their positive form. */
function compare(
  operator: ConditionOperator,
  actual: unknown,
  expected: ConditionValue,
  context: Record<string, unknown> | undefined,
): boolean {
  switch (operator) {
    case 'Exists':
      return actual === expected;
    case 'StringEquals':
    case 'StringNotEquals':
      return (
        typeof actual === 'string' &&
        typeof expected === 'string' &&
        actual === resolvePolicyValue(expected, context)
      );
    case 'StringEqualsIgnoreCase':
    case 'StringNotEqualsIgnoreCase': {
      const resolved =
        typeof expected === 'string' ? resolvePolicyValue(expected, context) : undefined;
      return (
        typeof actual === 'string' &&
        resolved !== undefined &&
        actual.toLowerCase() === resolved.toLowerCase()
      );
    }
    case 'StringLike':
    case 'StringNotLike':
      return (
        typeof actual === 'string' &&
        typeof expected === 'string' &&
        matchPattern(expected, actual, context)
      );
    case 'StringLikeIgnoreCase':
      return (
        typeof actual === 'string' &&
        typeof expected === 'string' &&
        matchPattern(expected.toLowerCase(), actual.toLowerCase(), lowerCaseContext(context))
      );
    case 'Bool':
      return typeof actual === 'boolean' && actual === expected;
    case 'NumericEquals':
    case 'NumericNotEquals':
      return finite(actual) && actual === expected;
    case 'NumericLessThan':
      return finite(actual) && typeof expected === 'number' && actual < expected;
    case 'NumericLessThanEquals':
      return finite(actual) && typeof expected === 'number' && actual <= expected;
    case 'NumericGreaterThan':
      return finite(actual) && typeof expected === 'number' && actual > expected;
    case 'NumericGreaterThanEquals':
      return finite(actual) && typeof expected === 'number' && actual >= expected;
    case 'DateBefore':
    case 'DateAfter': {
      const left = timestamp(actual);
      const right = timestamp(expected);
      return (
        left !== undefined &&
        right !== undefined &&
        (operator === 'DateBefore' ? left < right : left > right)
      );
    }
    case 'IpAddress':
    case 'NotIpAddress':
      return (
        typeof actual === 'string' && typeof expected === 'string' && inNetwork(actual, expected)
      );
    case 'ArrayContains':
    case 'ArrayContainsAll':
      return Array.isArray(actual) && member(actual, expected, context);
  }
}

/** A negated operator only negates a comparison that could have succeeded: the actual value must have the operator's type. */
function wellTyped(operator: ConditionOperator, actual: unknown): boolean {
  switch (operator) {
    case 'NumericNotEquals':
      return finite(actual);
    case 'NotIpAddress':
      return typeof actual === 'string' && ip(actual) !== undefined;
    default:
      return typeof actual === 'string';
  }
}

/** Case-insensitive matching lowers variable values too, so `${principal.team}-*` behaves consistently. */
function lowerCaseContext(
  context: Record<string, unknown> | undefined,
): Record<string, unknown> | undefined {
  if (!context) return context;
  const lowered: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(context))
    lowered[key] = typeof value === 'string' ? value.toLowerCase() : value;
  return lowered;
}

function matches(statement: PolicyStatement, request: EvaluationRequest): boolean {
  if (
    !statement.actions.some((pattern) => matchPattern(pattern, request.action)) ||
    !statement.resources.some((pattern) => matchPattern(pattern, request.resource, request.context))
  )
    return false;
  return Object.entries(statement.conditions ?? {}).every(([name, attributes]) =>
    Object.entries(attributes).every(([key, expected]) => {
      const operator = name as ConditionOperator;
      const exists =
        request.context !== undefined &&
        Object.hasOwn(request.context, key) &&
        request.context[key] !== undefined;
      // Missing or wrongly typed values never satisfy a condition, including negated ones; use Exists for absence checks.
      if (operator !== 'Exists' && !exists) return false;
      const actual = operator === 'Exists' ? exists : request.context![key];
      if (negated.has(operator) && !wellTyped(operator, actual)) return false;
      const values = Array.isArray(expected) ? expected : [expected];
      const test = (item: ConditionValue) => {
        spend(1 + (typeof actual === 'string' ? actual.length : 0));
        const outcome = compare(operator, actual, item, request.context);
        return negated.has(operator) ? !outcome : outcome;
      };
      return everyValue.has(operator) ? values.every(test) : values.some(test);
    }),
  );
}

/**
 * Grants form a union; every boundary is an independent intersection. A boundary
 * never grants access. Callers must establish trusted context and tenant scope.
 */
export function evaluatePolicy(input: EvaluationInput): Decision {
  if (
    !input ||
    !nonempty(input.action) ||
    !nonempty(input.resource, 2048) ||
    !Array.isArray(input.grants) ||
    (input.boundaries !== undefined && !Array.isArray(input.boundaries)) ||
    (input.context !== undefined && !object(input.context))
  ) {
    throw new IamError('INVALID_REQUEST', 'Invalid policy evaluation request');
  }
  const boundaries = input.boundaries ?? [];
  [...input.grants, ...boundaries].forEach(validatePolicy);
  const matched: string[] = [];
  let granted = false;
  const boundaryAllows = boundaries.map(() => false);
  let denied = false;
  const outer = workLeft;
  workLeft = evaluationWork;
  try {
    for (const [kind, policies] of [
      ['grant', input.grants],
      ['boundary', boundaries],
    ] as const) {
      policies.forEach((document, policyIndex) =>
        document.statements.forEach((statement, statementIndex) => {
          if (!matches(statement, input)) return;
          matched.push(`${kind}:${policyIndex}:${statement.sid ?? statementIndex}`);
          if (statement.effect === 'deny') denied = true;
          else if (kind === 'grant') granted = true;
          else boundaryAllows[policyIndex] = true;
        }),
      );
    }
  } catch (error) {
    // Too much matching work refuses, like a deny: nothing is granted on a partial evaluation.
    if (error instanceof EvaluationLimit)
      return { allowed: false, reason: 'evaluation-limit', matched };
    throw error;
  } finally {
    workLeft = outer;
  }
  if (denied) return { allowed: false, reason: 'explicit-deny', matched };
  if (!granted) return { allowed: false, reason: 'no-grant', matched };
  if (boundaryAllows.some((allowed) => !allowed))
    return { allowed: false, reason: 'boundary-deny', matched };
  return { allowed: true, reason: 'allowed', matched };
}
