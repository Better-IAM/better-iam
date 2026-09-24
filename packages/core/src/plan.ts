import { IamError } from './index.js';
import {
  evaluatePolicy,
  matchPattern,
  resolvePolicyValue,
  validatePolicy,
  type ConditionOperator,
  type PolicyDocument,
  type PolicyStatement,
} from './policy.js';

/**
 * Query planning (partial evaluation): which resources of one type may a principal perform one action on, as a filter
 * over the resource's `id` and attributes that a database can apply. The planner evaluates everything it knows (the
 * action, the principal's context, the tenant) and leaves the rest as a filter with the same semantics as the policy
 * engine: a resource passes the filter exactly when `evaluatePolicy` would allow it (except refusals for exceeding the
 * evaluation work budget, which a database has no equivalent of).
 */

export type FilterValue = string | number | boolean;

/**
 * A filter over one resource: its `id` and its attributes by name (the names `resource.{name}` conditions use). A field
 * that is absent (or SQL `NULL`) satisfies nothing but `not exists`.
 */
export type ResourceFilter =
  | { kind: 'true' }
  | { kind: 'false' }
  | { kind: 'and'; filters: ResourceFilter[] }
  | { kind: 'or'; filters: ResourceFilter[] }
  | { kind: 'not'; filter: ResourceFilter }
  /** The field is present. */
  | { kind: 'exists'; field: string }
  /** The field holds a value of this type (`ip`: a string that is an IP address). */
  | { kind: 'type'; field: string; type: 'string' | 'number' | 'boolean' | 'ip' }
  /** The field equals one of the values, compared with the value's type (strings optionally ignoring case). */
  | { kind: 'equals'; field: string; values: FilterValue[]; ignoreCase?: boolean }
  /** A numeric comparison. */
  | { kind: 'compare'; field: string; operator: 'lt' | 'le' | 'gt' | 'ge'; value: number }
  /**
   * A glob over a string field: `*` matches any run of characters, `?` one character, and `\` escapes the next
   * character (a literal `*`, `?` or `\`).
   */
  | { kind: 'like'; field: string; pattern: string; ignoreCase?: boolean }
  /** An ISO 8601 timestamp field before or after a moment. */
  | { kind: 'date'; field: string; operator: 'before' | 'after'; value: string }
  /** An IP address field inside a network (an address or CIDR block). */
  | { kind: 'ip'; field: string; network: string }
  /** An array field contains the value. */
  | { kind: 'contains'; field: string; value: FilterValue };

/** The planner's answer: every resource, none, or those that pass `filter`. */
export interface ResourcePlan {
  kind: 'always' | 'never' | 'conditional';
  filter: ResourceFilter;
}

/** One way a principal holds grants: the grant documents and the ceilings that bound them. */
export interface PlanPath {
  grants: PolicyDocument[];
  boundaries: PolicyDocument[];
}

/** Relationship tuples the principal holds (directly or through a group) on one resource. */
export interface PlanRelation {
  type: string;
  id: string;
  relations: string[];
}

export interface PlanInput {
  action: string;
  /** The resource type planned for; `resource.type` of every candidate. */
  resourceType: string;
  /** `resource.tenantId` of every candidate. */
  tenantId: string;
  /** Principal, request and tenant keys, as the decision's context holds them (no resource keys). */
  context: Record<string, unknown>;
  /** Deny statements that apply across grant paths. */
  denies: PolicyDocument[];
  /** Ceilings over every path (tenant boundaries, session policies, key scopes). */
  boundaries: PolicyDocument[];
  /** Grant paths; a resource is allowed through any one of them. */
  paths: PlanPath[];
  /** Relations held on resources, for `resource.relations` and `resource.parentRelations`. */
  relations?: PlanRelation[];
}

// --- filter constructors -------------------------------------------------------------------------

/** The filter every resource passes. */
export const trueFilter: ResourceFilter = { kind: 'true' };
/** The filter no resource passes. */
export const falseFilter: ResourceFilter = { kind: 'false' };

const key = (filter: ResourceFilter) => JSON.stringify(filter);

/** Conjunction, simplified: nested ands flattened, `true` dropped, `false` absorbing, duplicates removed. */
export function andFilter(filters: ResourceFilter[]): ResourceFilter {
  const kept = new Map<string, ResourceFilter>();
  for (const filter of filters.flatMap((item) => (item.kind === 'and' ? item.filters : [item]))) {
    if (filter.kind === 'false') return falseFilter;
    if (filter.kind === 'true') continue;
    kept.set(key(filter), filter);
  }
  const items = [...kept.values()];
  return items.length === 0 ? trueFilter : items.length === 1 ? items[0]! : { kind: 'and', filters: items };
}

/**
 * Disjunction, simplified: nested ors flattened, `false` dropped, `true` absorbing, duplicates removed, and `equals` on
 * the same field (and case rule) merged into one value list.
 */
export function orFilter(filters: ResourceFilter[]): ResourceFilter {
  const kept = new Map<string, ResourceFilter>();
  const equals = new Map<string, Extract<ResourceFilter, { kind: 'equals' }>>();
  for (const filter of filters.flatMap((item) => (item.kind === 'or' ? item.filters : [item]))) {
    if (filter.kind === 'true') return trueFilter;
    if (filter.kind === 'false') continue;
    if (filter.kind === 'equals') {
      const slot = `${filter.field}\u0000${filter.ignoreCase ? 1 : 0}`;
      const merged = equals.get(slot);
      if (merged) {
        for (const value of filter.values)
          if (!merged.values.some((item) => item === value)) merged.values.push(value);
      } else {
        const copy = { ...filter, values: [...filter.values] };
        equals.set(slot, copy);
        kept.set(`equals:${slot}`, copy);
      }
      continue;
    }
    kept.set(key(filter), filter);
  }
  const items = [...kept.values()];
  return items.length === 0 ? falseFilter : items.length === 1 ? items[0]! : { kind: 'or', filters: items };
}

/** Negation, simplified: constants flip and a double negation cancels. */
export function notFilter(filter: ResourceFilter): ResourceFilter {
  if (filter.kind === 'true') return falseFilter;
  if (filter.kind === 'false') return trueFilter;
  if (filter.kind === 'not') return filter.filter;
  return { kind: 'not', filter };
}

const exists = (field: string): ResourceFilter => ({ kind: 'exists', field });
const typed = (field: string, type: Extract<ResourceFilter, { kind: 'type' }>['type']): ResourceFilter => ({
  kind: 'type',
  field,
  type,
});
const equalsFilter = (field: string, values: FilterValue[], ignoreCase = false): ResourceFilter =>
  values.length === 0
    ? falseFilter
    : { kind: 'equals', field, values: [...new Set(values)], ...(ignoreCase ? { ignoreCase: true } : {}) };

// --- globs ---------------------------------------------------------------------------------------

/** One element of a glob: a star, a single-character wildcard, or a literal character. */
export type GlobToken = { kind: 'star' } | { kind: 'any' } | { kind: 'char'; value: string };
type Token = GlobToken;

/** The same variable syntax as the policy engine (policy.ts); substituted values match literally. */
const variable = /\$\{([A-Za-z_][A-Za-z0-9_.:-]{0,127})\}/y;
const variableMarker = '${';

function globTokens(pattern: string, into: Token[]): void {
  for (const char of pattern)
    into.push(char === '*' ? { kind: 'star' } : char === '?' ? { kind: 'any' } : { kind: 'char', value: char });
}

/**
 * Resource keys whose variables resolve the same way for every resource of a plan: the tenant (known), and the
 * relation lists (arrays, which never substitute).
 */
const constantResourceKeys = new Set(['resource.tenantId', 'resource.relations', 'resource.parentRelations']);

/** A variable whose value is the resource's own: it differs from row to row, so the planner cannot substitute it. */
const rowVariable = (name: string) => name.startsWith('resource.') && !constantResourceKeys.has(name);

/** Whether a pattern or condition value refers to a row-dependent variable (`${resource.owner}`). */
function hasRowVariable(value: string): boolean {
  let search = 0;
  for (let index = value.indexOf(variableMarker); index !== -1; index = value.indexOf(variableMarker, search)) {
    variable.lastIndex = index;
    const match = variable.exec(value);
    if (!match) {
      search = index + variableMarker.length;
      continue;
    }
    if (rowVariable(match[1]!)) return true;
    search = index + match[0].length;
  }
  return false;
}

/**
 * A pattern's tokens with variables substituted from context, as the engine reads them; undefined when unresolved.
 * With `rowAsStar`, a row-dependent variable becomes a star: the widest pattern it could turn into.
 */
function tokenize(pattern: string, context: Record<string, unknown>, rowAsStar = false): Token[] | undefined {
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
    if (!match) {
      search = index + variableMarker.length;
      continue;
    }
    globTokens(pattern.slice(cursor, index), tokens);
    if (rowAsStar && rowVariable(match[1]!)) {
      tokens.push({ kind: 'star' });
      cursor = search = index + match[0].length;
      continue;
    }
    const value = context[match[1]!];
    if (typeof value !== 'string' && typeof value !== 'number' && typeof value !== 'boolean')
      return undefined;
    for (const char of String(value)) tokens.push({ kind: 'char', value: char });
    cursor = search = index + match[0].length;
  }
  globTokens(pattern.slice(cursor), tokens);
  return tokens;
}

/** Tokens as a filter glob: wildcards as `*` / `?`, literal `*`, `?` and `\` escaped with `\`. */
function globString(tokens: Token[]): string {
  return tokens
    .map((token) =>
      token.kind === 'star'
        ? '*'
        : token.kind === 'any'
          ? '?'
          : '*?\\'.includes(token.value)
            ? `\\${token.value}`
            : token.value,
    )
    .join('');
}

/** A filter glob back into tokens (the inverse of `globString`). */
export function parseGlob(pattern: string): Token[] {
  const tokens: Token[] = [];
  const chars = [...pattern];
  for (let index = 0; index < chars.length; index++) {
    const char = chars[index]!;
    if (char === '\\' && index + 1 < chars.length) tokens.push({ kind: 'char', value: chars[++index]! });
    else if (char === '*') tokens.push({ kind: 'star' });
    else if (char === '?') tokens.push({ kind: 'any' });
    else tokens.push({ kind: 'char', value: char });
  }
  return tokens;
}

/** Glob matching over code points, greedy with backtracking to the last star (as the engine does). */
export function globMatches(tokens: Token[], value: string): boolean {
  const chars = [...value];
  let p = 0;
  let v = 0;
  let star = -1;
  let retry = 0;
  while (v < chars.length) {
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

/** A glob filter on a field, or plain equality when the glob has no wildcard. */
function globFilter(field: string, tokens: Token[], ignoreCase: boolean): ResourceFilter {
  if (tokens.every((token) => token.kind === 'char'))
    return equalsFilter(field, [tokens.map((token) => (token as { value: string }).value).join('')], ignoreCase);
  if (tokens.length > 0 && tokens.every((token) => token.kind === 'star'))
    return typed(field, 'string');
  return { kind: 'like', field, pattern: globString(tokens), ...(ignoreCase ? { ignoreCase: true } : {}) };
}

/**
 * The ids a resource pattern admits for a type: the pattern is matched against `{type}/{id}`, so after consuming the
 * known `{type}/` prefix (tracking every place a star could be) the rest of the pattern constrains the id.
 */
function idFilter(planner: Planner, tokens: Token[], prefix: string): ResourceFilter {
  const closure = (states: Set<number>) => {
    for (const state of [...states]) {
      let at = state;
      while (tokens[at]?.kind === 'star') states.add(++at);
    }
    return states;
  };
  let states = closure(new Set([0]));
  for (const char of prefix) {
    spend(planner, states.size);
    const next = new Set<number>();
    for (const state of states) {
      const token = tokens[state];
      if (!token) continue;
      if (token.kind === 'star') next.add(state);
      else if (token.kind === 'any' || token.value === char) next.add(state + 1);
    }
    states = closure(next);
    if (!states.size) return falseFilter;
  }
  // Ids are nonempty strings: a residue that matches only the empty string admits none, one of stars alone all.
  return orFilter(
    [...states].map((state) => {
      const rest = tokens.slice(state);
      spend(planner, rest.length + 1);
      if (rest.length === 0) return falseFilter;
      if (rest.every((token) => token.kind === 'star')) return trueFilter;
      return globFilter('id', rest, false);
    }),
  );
}

// --- statements ----------------------------------------------------------------------------------

const negated = new Set<ConditionOperator>([
  'StringNotEquals',
  'StringNotEqualsIgnoreCase',
  'StringNotLike',
  'NumericNotEquals',
  'NotIpAddress',
]);

/** One condition entry evaluated by the engine itself, for keys the context holds. */
function concrete(
  operator: ConditionOperator,
  conditionKey: string,
  expected: unknown,
  context: Record<string, unknown>,
): boolean {
  return evaluatePolicy({
    action: 'plan',
    resource: 'plan/plan',
    context,
    grants: [
      {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['*'],
            resources: ['*'],
            conditions: { [operator]: { [conditionKey]: expected } } as PolicyStatement['conditions'],
          },
        ],
      },
    ],
  }).allowed;
}

function lowerCaseContext(context: Record<string, unknown>): Record<string, unknown> {
  const lowered: Record<string, unknown> = {};
  for (const [name, value] of Object.entries(context))
    lowered[name] = typeof value === 'string' ? value.toLowerCase() : value;
  return lowered;
}

/** A condition on a resource attribute, as a filter with the engine's semantics. */
function attributeCondition(
  operator: ConditionOperator,
  field: string,
  expected: FilterValue[],
  context: Record<string, unknown>,
): ResourceFilter {
  const strings = () =>
    expected.flatMap((value) => {
      if (typeof value !== 'string') return [];
      const resolved = resolvePolicyValue(value, context);
      return resolved === undefined ? [] : [resolved];
    });
  const likes = (ignoreCase: boolean) =>
    expected.map((value) => {
      if (typeof value !== 'string') return falseFilter;
      const tokens = ignoreCase
        ? tokenize(value.toLowerCase(), lowerCaseContext(context))
        : tokenize(value, context);
      return tokens ? globFilter(field, tokens, ignoreCase) : falseFilter;
    });
  const numbers = expected.filter((value): value is number => typeof value === 'number');
  switch (operator) {
    case 'Exists':
      return orFilter(expected.map((value) => (value === true ? exists(field) : notFilter(exists(field)))));
    case 'StringEquals':
      return equalsFilter(field, strings());
    case 'StringNotEquals':
      return andFilter([typed(field, 'string'), notFilter(equalsFilter(field, strings()))]);
    case 'StringEqualsIgnoreCase':
      return equalsFilter(field, strings().map((value) => value.toLowerCase()), true);
    case 'StringNotEqualsIgnoreCase':
      return andFilter([
        typed(field, 'string'),
        notFilter(equalsFilter(field, strings().map((value) => value.toLowerCase()), true)),
      ]);
    case 'StringLike':
      return orFilter(likes(false));
    case 'StringNotLike':
      return andFilter([typed(field, 'string'), notFilter(orFilter(likes(false)))]);
    case 'StringLikeIgnoreCase':
      return orFilter(likes(true));
    case 'Bool':
      return equalsFilter(
        field,
        expected.filter((value) => typeof value === 'boolean'),
      );
    case 'NumericEquals':
      return equalsFilter(field, numbers);
    case 'NumericNotEquals':
      return andFilter([typed(field, 'number'), notFilter(equalsFilter(field, numbers))]);
    case 'NumericLessThan':
    case 'NumericLessThanEquals':
    case 'NumericGreaterThan':
    case 'NumericGreaterThanEquals': {
      const comparison = ({
        NumericLessThan: 'lt',
        NumericLessThanEquals: 'le',
        NumericGreaterThan: 'gt',
        NumericGreaterThanEquals: 'ge',
      } as const)[operator];
      return orFilter(numbers.map((value) => ({ kind: 'compare', field, operator: comparison, value })));
    }
    case 'DateBefore':
    case 'DateAfter':
      return orFilter(
        expected.map((value) =>
          typeof value === 'string'
            ? { kind: 'date', field, operator: operator === 'DateBefore' ? 'before' : 'after', value }
            : falseFilter,
        ),
      );
    case 'IpAddress':
      return orFilter(
        expected.map((value) => (typeof value === 'string' ? { kind: 'ip', field, network: value } : falseFilter)),
      );
    case 'NotIpAddress':
      return andFilter([
        typed(field, 'ip'),
        notFilter(
          orFilter(
            expected.map((value) =>
              typeof value === 'string' ? { kind: 'ip', field, network: value } : falseFilter,
            ),
          ),
        ),
      ]);
    case 'ArrayContains':
    case 'ArrayContainsAll': {
      const members = expected.map((value): ResourceFilter => {
        const wanted = typeof value === 'string' ? resolvePolicyValue(value, context) : value;
        return wanted === undefined ? falseFilter : { kind: 'contains', field, value: wanted };
      });
      return operator === 'ArrayContains' ? orFilter(members) : andFilter(members);
    }
  }
}

interface Planner {
  input: PlanInput;
  /**
   * What variables and principal conditions read: the input context with the resource keys every candidate shares
   * (`resource.tenantId`; the relation lists, which never substitute).
   */
  context: Record<string, unknown>;
  /** Resource ids of the planned type by relation held on them. */
  idsByRelation: Map<string, string[]>;
  /** `(parentType, parentId)` pairs by relation held on them. */
  parentsByRelation: Map<string, { type: string; id: string }[]>;
  /** Work done so far, against `planWorkLimit`. */
  work: number;
}

/**
 * The most work one plan may take (pattern states visited and filter atoms built), so that policies full of wildcards
 * cannot make planning slow or its filter huge. A plan that needs more refuses with UNSUPPORTED_FILTER.
 */
export const planWorkLimit = 200_000;

function spend(planner: Planner, units: number): void {
  planner.work += units;
  if (planner.work > planWorkLimit)
    throw new IamError(
      'UNSUPPORTED_FILTER',
      'These policies are too complex to plan as a filter; check the resources with authorize',
    );
}

/** Operators whose string values substitute variables. */
const substituting = new Set<ConditionOperator>([
  'StringEquals',
  'StringNotEquals',
  'StringEqualsIgnoreCase',
  'StringNotEqualsIgnoreCase',
  'StringLike',
  'StringNotLike',
  'StringLikeIgnoreCase',
  'ArrayContains',
  'ArrayContainsAll',
]);

/** A condition on `resource.relations` or `resource.parentRelations`. */
function relationCondition(
  planner: Planner,
  operator: ConditionOperator,
  conditionKey: string,
  expected: FilterValue[],
): ResourceFilter {
  const { context } = planner;
  if (operator !== 'ArrayContains' && operator !== 'ArrayContainsAll')
    // Every other operator reads the list as a whole, and a list satisfies each one the same way whatever it holds.
    return concrete(operator, conditionKey, expected, { ...context, [conditionKey]: [] })
      ? trueFilter
      : falseFilter;
  const members = expected.map((value): ResourceFilter => {
    const wanted = typeof value === 'string' ? resolvePolicyValue(value, context) : value;
    if (typeof wanted !== 'string') return falseFilter;
    if (conditionKey === 'resource.relations')
      return equalsFilter('id', planner.idsByRelation.get(wanted) ?? []);
    return orFilter(
      (planner.parentsByRelation.get(wanted) ?? []).map((parent) =>
        andFilter([equalsFilter('parentType', [parent.type]), equalsFilter('parentId', [parent.id])]),
      ),
    );
  });
  return operator === 'ArrayContains' ? orFilter(members) : andFilter(members);
}

/** When the resource lacks an attribute, the evaluation context may still carry `resource.{name}` from elsewhere. */
function withFallback(
  field: string,
  present: ResourceFilter,
  fallback: boolean | undefined,
): ResourceFilter {
  if (fallback === undefined) return present;
  return orFilter([
    andFilter([exists(field), present]),
    ...(fallback ? [notFilter(exists(field))] : []),
  ]);
}

/** When a statement matches the planned action on a resource of the planned type. */
function statementFilter(planner: Planner, statement: PolicyStatement): ResourceFilter {
  const { input } = planner;
  if (!statement.actions.some((pattern) => matchPattern(pattern, input.action))) return falseFilter;
  const { context } = planner;
  const prefix = `${input.resourceType}/`;
  // A value compared with the resource's own attributes (`${resource.owner}`) differs from row to row: the planner
  // refuses rather than guess, once the statement could otherwise apply.
  let rowDependent = false;
  const resource = orFilter(
    statement.resources.map((pattern) => {
      if (hasRowVariable(pattern)) {
        const widest = tokenize(pattern, context, true);
        if (widest && idFilter(planner, widest, prefix).kind !== 'false') rowDependent = true;
        return falseFilter;
      }
      const tokens = tokenize(pattern, context);
      return tokens ? idFilter(planner, tokens, prefix) : falseFilter;
    }),
  );
  if (resource.kind === 'false' && !rowDependent) return falseFilter;
  const conditions: ResourceFilter[] = [resource];
  let idCondition = false;
  for (const [name, entries] of Object.entries(statement.conditions ?? {})) {
    const operator = name as ConditionOperator;
    for (const [conditionKey, expectedValue] of Object.entries(entries ?? {})) {
      const expected = (Array.isArray(expectedValue) ? expectedValue : [expectedValue]) as FilterValue[];
      spend(planner, expected.length);
      if (
        substituting.has(operator) &&
        expected.some((value) => typeof value === 'string' && hasRowVariable(value))
      ) {
        rowDependent = true;
        continue;
      }
      // The engine reads `resource.id` as an attribute named `id`, which a filter cannot tell from the resource's id.
      if (conditionKey === 'resource.id') {
        idCondition = true;
        continue;
      }
      let filter: ResourceFilter;
      if (conditionKey === 'resource.tenantId')
        filter = concrete(operator, conditionKey, expectedValue, context) ? trueFilter : falseFilter;
      else if (conditionKey === 'resource.relations' || conditionKey === 'resource.parentRelations')
        filter = relationCondition(planner, operator, conditionKey, expected);
      else if (conditionKey.startsWith('resource.')) {
        const field = conditionKey.slice('resource.'.length);
        const inherited = Object.hasOwn(input.context, conditionKey)
          ? input.context[conditionKey]
          : undefined;
        filter = withFallback(
          field,
          attributeCondition(operator, field, expected, context),
          inherited === undefined ? undefined : concrete(operator, conditionKey, expectedValue, context),
        );
      } else filter = concrete(operator, conditionKey, expectedValue, context) ? trueFilter : falseFilter;
      if (filter.kind === 'false') return falseFilter;
      conditions.push(filter);
    }
  }
  if (rowDependent)
    throw new IamError(
      'UNSUPPORTED_FILTER',
      'A policy compares a value with ${resource.…}, one of the resource’s own attributes, which a filter cannot express; check the resources with authorize',
    );
  if (idCondition)
    throw new IamError(
      'UNSUPPORTED_FILTER',
      'A policy has a condition on resource.id, which names an attribute called id rather than the resource’s id (match ids with the statement’s resources); check the resources with authorize',
    );
  return andFilter(conditions);
}

/** Resources some statement of `effect` in the documents matches. */
function anyStatement(
  planner: Planner,
  documents: PolicyDocument[],
  effect: 'allow' | 'deny',
): ResourceFilter {
  return orFilter(
    documents.flatMap((document) =>
      document.statements
        .filter((statement) => statement.effect === effect)
        .map((statement) => statementFilter(planner, statement)),
    ),
  );
}

/** Resources every document lets through: each has a matching allow statement (a boundary). */
function everyBoundary(planner: Planner, documents: PolicyDocument[]): ResourceFilter {
  return andFilter(documents.map((document) => anyStatement(planner, [document], 'allow')));
}

/**
 * Plans the resources of `resourceType` the principal may perform `action` on. The result mirrors the decision the
 * server makes for each resource: no deny statement applies (across every grant path and ceiling), every ceiling
 * lets the resource through, and some grant path allows it within its own ceilings.
 */
export function planResources(input: PlanInput): ResourcePlan {
  for (const document of [
    ...input.denies,
    ...input.boundaries,
    ...input.paths.flatMap((path) => [...path.grants, ...path.boundaries]),
  ])
    validatePolicy(document);
  if (!input.resourceType || input.resourceType.includes('/'))
    throw new IamError('INVALID_INPUT', 'Invalid resource type');
  const idsByRelation = new Map<string, string[]>();
  const parentsByRelation = new Map<string, { type: string; id: string }[]>();
  for (const tuple of input.relations ?? [])
    for (const relation of tuple.relations) {
      if (tuple.type === input.resourceType)
        idsByRelation.set(relation, [...(idsByRelation.get(relation) ?? []), tuple.id]);
      parentsByRelation.set(relation, [
        ...(parentsByRelation.get(relation) ?? []),
        { type: tuple.type, id: tuple.id },
      ]);
    }
  const planner: Planner = {
    input,
    context: {
      ...input.context,
      'resource.tenantId': input.tenantId,
      'resource.relations': [],
      'resource.parentRelations': [],
    },
    idsByRelation,
    parentsByRelation,
    work: 0,
  };
  const filter = andFilter([
    notFilter(anyStatement(planner, [...input.denies, ...input.boundaries], 'deny')),
    everyBoundary(planner, input.boundaries),
    orFilter(
      input.paths.map((path) =>
        andFilter([
          notFilter(anyStatement(planner, [...path.grants, ...path.boundaries], 'deny')),
          anyStatement(planner, path.grants, 'allow'),
          everyBoundary(planner, path.boundaries),
        ]),
      ),
    ),
  ]);
  return {
    kind: filter.kind === 'true' ? 'always' : filter.kind === 'false' ? 'never' : 'conditional',
    filter,
  };
}

/** A plan that allows everything or nothing (root override, a fixed refusal). */
export function fixedPlan(allowed: boolean): ResourcePlan {
  return allowed ? { kind: 'always', filter: trueFilter } : { kind: 'never', filter: falseFilter };
}

/** Both plans at once: what each allows (an impersonation session and the administrator behind it). */
export function intersectPlans(left: ResourcePlan, right: ResourcePlan): ResourcePlan {
  const filter = andFilter([left.filter, right.filter]);
  return {
    kind: filter.kind === 'true' ? 'always' : filter.kind === 'false' ? 'never' : 'conditional',
    filter,
  };
}
