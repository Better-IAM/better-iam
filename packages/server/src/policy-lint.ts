import {
  IamError,
  matchPattern,
  validatePolicy,
  type AttributeType,
  type ConditionOperator,
  type PolicyStatement,
} from '@better-iam/core';
import {
  optionalPrincipalServerKeys,
  principalServerKeys,
  sessionTagName,
  sessionTagPrefix,
  tenantServerKeys,
} from './context-keys.js';

/** One observation about a policy document. `statement` is the zero-based statement index, or -1 for the whole document. */
export interface PolicyLintWarning {
  code: string;
  /** `warning`: the document likely does not do what it says; `info`: worth a look, often intended. */
  severity: 'warning' | 'info';
  statement: number;
  sid?: string;
  message: string;
}
/** What the linter may assume about the deployment beyond the keys the server always derives. */
export interface PolicyLintContext {
  /** Declared identity attributes, exposed to policies as principal.{name}. */
  identityAttributes?: Record<string, AttributeType>;
  /** Known resource attribute names across resource types; when omitted, any resource.{name} key is accepted. */
  resourceAttributes?: string[];
  /** Keys the application supplies through resolveContext. */
  contextKeys?: string[];
}
export interface PolicyLintResult {
  valid: boolean;
  /** Why the document was rejected; warnings are empty when validation fails. */
  error?: { code: string; message: string };
  /** Sorted by statement index, then code. */
  warnings: PolicyLintWarning[];
}

type Scalar = string | number | boolean;
/** What a context key holds. `identifier` strings are never timestamps; declared `string` attributes may hold one. */
type KeyType = 'identifier' | 'timestamp' | 'string' | 'number' | 'boolean' | 'list';
interface KeyInfo {
  /** Set by the server, declared by configuration, or supplied by the application. */
  known: boolean;
  /** Missing from some decisions; every operator except Exists is then false. */
  optional: boolean;
  type?: KeyType;
}

/** Every key the server derives: the shared principal and request registry plus the resource keys decisions add. */
const serverKeys = new Map<string, KeyType>([
  ...principalServerKeys,
  ...tenantServerKeys,
  ['resource.tenantId', 'identifier'],
  ['resource.relations', 'list'],
  ['resource.parentRelations', 'list'],
]);
/**
 * Server keys absent from some decisions: API keys and role sessions have no sign-in method, the session attribution
 * keys exist only when set, and request.sourceIp needs a known client address (see `optionalPrincipalServerKeys`).
 */
const optionalServerKeys = optionalPrincipalServerKeys;
/** Links every managed resource may carry besides its declared attributes. */
const resourceLinks = new Set(['ownerId', 'parentId', 'parentType']);
/** Keys people commonly expect but the server never sets, with the usual alternative. */
const missingKeyHints = new Map([
  ['resource.type', 'or match the type in the resource pattern'],
  ['resource.id', 'or match the ID in the resource pattern'],
  ['principal.email', 'or declare it as an identity attribute'],
  ['principal.name', 'or declare it as an identity attribute'],
  ['principal.managerId', 'or declare it as an identity attribute'],
  ['request.ip', 'or use request.sourceIp, which the server sets from the client address'],
  ['principal.tokenIssuedAt', 'or use principal.tokenIssueTime'],
  [
    'principal.risk',
    'or use principal.riskLevel (none, low, medium, high) or principal.riskScore (0-100)',
  ],
]);
const typeLabels: Record<KeyType, string> = {
  identifier: 'a string',
  timestamp: 'a timestamp string',
  string: 'a string',
  number: 'a number',
  boolean: 'a boolean',
  list: 'a list',
};

const numericOperators = new Set<ConditionOperator>([
  'NumericEquals',
  'NumericNotEquals',
  'NumericLessThan',
  'NumericLessThanEquals',
  'NumericGreaterThan',
  'NumericGreaterThanEquals',
]);
const dateOperators = new Set<ConditionOperator>(['DateBefore', 'DateAfter']);
const arrayOperators = new Set<ConditionOperator>(['ArrayContains', 'ArrayContainsAll']);
/** Negated string operators: an unresolved variable in their value makes the comparison true. */
const negatedStringOperators = new Set<ConditionOperator>([
  'StringNotEquals',
  'StringNotEqualsIgnoreCase',
  'StringNotLike',
]);
const variablePattern = /\$\{([A-Za-z_][A-Za-z0-9_.:-]{0,127})\}/g;

const list = (value: Scalar | Scalar[]): Scalar[] => (Array.isArray(value) ? value : [value]);
const variablesOf = (value: Scalar): string[] =>
  typeof value === 'string' ? [...value.matchAll(variablePattern)].map((match) => match[1]!) : [];
const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);

function keyInfo(key: string, context: PolicyLintContext): KeyInfo {
  const server = serverKeys.get(key);
  if (server) return { known: true, optional: optionalServerKeys.has(key), type: server };
  // Session tags: a valid tag name is an optional server string; an invalid one can never be set.
  if (key.startsWith(sessionTagPrefix))
    return sessionTagName(key.slice(sessionTagPrefix.length)) !== undefined
      ? { known: true, optional: true, type: 'string' }
      : { known: false, optional: true };
  // The bare family name is reserved and stripped from application context before every decision, so an application
  // listing it in contextKeys still never supplies it.
  if (key === sessionTagPrefix.slice(0, -1)) return { known: false, optional: true };
  const attributes = context.identityAttributes ?? {};
  const attribute = key.slice('principal.'.length);
  if (key.startsWith('principal.') && Object.hasOwn(attributes, attribute))
    return { known: true, optional: true, type: attributes[attribute] };
  if (key.startsWith('resource.')) {
    const name = key.slice('resource.'.length);
    if (resourceLinks.has(name)) return { known: true, optional: true, type: 'identifier' };
    const declared = context.resourceAttributes
      ? context.resourceAttributes.includes(name)
      : !missingKeyHints.has(key);
    if (declared) return { known: true, optional: true };
  }
  return { known: context.contextKeys?.includes(key) === true, optional: true };
}

/** Why an operator can never match a key of this type, or undefined when the pairing is sound. */
function typeMismatch(operator: ConditionOperator, key: string, type: KeyType): string | undefined {
  if (operator === 'Exists' || type === 'list') return undefined;
  if (operator === 'Bool')
    return type === 'boolean'
      ? undefined
      : `Bool never matches ${key}, which holds ${typeLabels[type]}.`;
  if (type === 'boolean') return `${operator} never matches ${key}, which is a boolean; use Bool.`;
  if (numericOperators.has(operator))
    return type === 'number'
      ? undefined
      : `${operator} never matches ${key}, which holds ${typeLabels[type]}.`;
  if (dateOperators.has(operator))
    return type === 'timestamp' || type === 'string'
      ? undefined
      : `${operator} compares timestamps, but ${key} holds ${type === 'number' ? 'a number' : 'an identifier'}; only request.time, principal.tokenIssueTime, principal.authTime, principal.mfaTime, or a string attribute holding ISO timestamps works with date operators.`;
  if (arrayOperators.has(operator))
    return `${operator} never matches ${key}, which holds a single value; compare it with a String, Numeric, or Bool operator.`;
  return type === 'number'
    ? `${operator} never matches ${key}, which is a number; use a Numeric operator.`
    : undefined;
}

/** A set of statement positions, 32 per word. */
type Bits = Uint32Array;
type Field = 'actions' | 'resources';
const bitWords = (size: number) => Math.max(1, Math.ceil(size / 32));
const addBit = (bits: Bits, position: number) => {
  bits[position >>> 5] = bits[position >>> 5]! | (1 << (position & 31));
};
const orBits = (target: Bits, source: Bits) => {
  for (let word = 0; word < target.length; word++) target[word] = target[word]! | source[word]!;
};
const andBits = (target: Bits, source: Bits) => {
  for (let word = 0; word < target.length; word++) target[word] = target[word]! & source[word]!;
};
const emptyBits = (bits: Bits) => bits.every((word) => word === 0);
function subsetOf(subset: Bits, bits: Bits): boolean {
  for (let word = 0; word < subset.length; word++) if (subset[word]! & ~bits[word]!) return false;
  return true;
}
/** The lowest position in both sets, or -1. */
function firstCommon(a: Bits, b: Bits): number {
  for (let word = 0; word < a.length; word++) {
    const common = a[word]! & b[word]!;
    if (common) return word * 32 + 31 - Math.clz32(common & -common);
  }
  return -1;
}

/**
 * Work one coverage index may spend, in rough character comparisons: far more than any realistic document needs,
 * and a bound of tens of milliseconds on a hostile one (up to 128 statements of 128 patterns each).
 */
const coverageBudget = 2_000_000;
interface Wildcard {
  pattern: string;
  /** The pattern is `{head}*`: it covers every value, wildcards included, that starts with the head. */
  prefixOnly: boolean;
  /** Literal text before the first wildcard and after the last: every value the pattern matches has both. */
  head: string;
  tail: string;
  /** Bounds matchPattern's comparisons per value character: the longest run between stars, plus one. */
  factor: number;
  holders: Bits;
}

/**
 * Which of `statements` cover an action or resource, as a set of their positions. A pattern covers a value when it
 * is all stars or the same text, when it matches the value as a literal (no wildcards or variables), or when it is
 * `prefix*` and the value starts with that prefix. Each distinct value is resolved once against each distinct
 * pattern; the lookup returns undefined once the matching work exceeds the budget.
 */
function coverage(
  statements: PolicyStatement[],
): (field: Field, value: string) => Bits | undefined {
  const words = bitWords(statements.length);
  let budget = coverageBudget;
  const index = (field: Field) => {
    const all = new Uint32Array(words);
    const exact = new Map<string, Bits>();
    const wildcards = new Map<string, Wildcard>();
    statements.forEach((statement, position) => {
      for (const pattern of statement[field]) {
        if (/^\*+$/.test(pattern)) {
          addBit(all, position);
          continue;
        }
        let same = exact.get(pattern);
        if (!same) exact.set(pattern, (same = new Uint32Array(words)));
        addBit(same, position);
        if (pattern.includes('${') || !/[*?]/.test(pattern)) continue;
        let wildcard = wildcards.get(pattern);
        if (!wildcard) {
          const head = pattern.slice(0, pattern.search(/[*?]/));
          wildcard = {
            pattern,
            prefixOnly: pattern === `${head}*`,
            head,
            tail: pattern.slice(Math.max(pattern.lastIndexOf('*'), pattern.lastIndexOf('?')) + 1),
            factor:
              pattern.split('*').reduce((longest, run) => Math.max(longest, run.length), 0) + 1,
            holders: new Uint32Array(words),
          };
          wildcards.set(pattern, wildcard);
        }
        addBit(wildcard.holders, position);
      }
    });
    return { all, exact, wildcards: [...wildcards.values()], resolved: new Map<string, Bits>() };
  };
  const fields = { actions: index('actions'), resources: index('resources') };
  return (field, value) => {
    const { all, exact, wildcards, resolved } = fields[field];
    const known = resolved.get(value);
    if (known) return known;
    const covered = all.slice();
    const same = exact.get(value);
    if (same) orBits(covered, same);
    const literal = !/[*?]/.test(value) && !value.includes('${');
    for (const wildcard of wildcards) {
      if ((budget -= 4) < 0) return undefined;
      if (subsetOf(wildcard.holders, covered) || !(literal || wildcard.prefixOnly)) continue;
      budget -= wildcard.head.length + wildcard.tail.length;
      if (!value.startsWith(wildcard.head) || !value.endsWith(wildcard.tail)) continue;
      if (!wildcard.prefixOnly) {
        budget -= wildcard.pattern.length + value.length * wildcard.factor;
        if (budget < 0) return undefined;
        if (!matchPattern(wildcard.pattern, value)) continue;
      }
      orBits(covered, wildcard.holders);
    }
    resolved.set(value, covered);
    return covered;
  };
}

/** The key a deny tests for absence when that is its only condition (Exists false), so it applies exactly then. */
function absenceKey(statement: PolicyStatement): string | undefined {
  const operators = Object.entries(statement.conditions ?? {});
  if (statement.effect !== 'deny' || operators.length !== 1 || operators[0]![0] !== 'Exists')
    return undefined;
  const keys = Object.entries(operators[0]![1] ?? {});
  return keys.length === 1 && list(keys[0]![1]).includes(false) ? keys[0]![0] : undefined;
}

/** Order-insensitive fingerprint of a statement (its sid aside). */
function fingerprint(statement: PolicyStatement): string {
  const conditions = Object.entries(statement.conditions ?? {})
    .map(([operator, attributes]) => [
      operator,
      Object.entries(attributes ?? {})
        .map(([key, value]) => [
          key,
          [...new Set(list(value).map((v) => JSON.stringify(v)))].sort(),
        ])
        .sort((a, b) => compare(a[0] as string, b[0] as string)),
    ])
    .sort((a, b) => compare(a[0] as string, b[0] as string));
  return JSON.stringify([
    statement.effect,
    [...new Set(statement.actions)].sort(),
    [...new Set(statement.resources)].sort(),
    conditions,
  ]);
}

/**
 * Lints a policy document: validates it as storage would, then reports statements that grant more than intended,
 * conditions that can never match or silently fail open, and statements that are shadowed or duplicated. The
 * context tells the linter which identity attributes, resource attributes, and application keys exist. Pattern
 * comparisons are budgeted: past the budget, a `shadowed-allow-skipped` note replaces the rest of the shadow check.
 */
export function lintPolicy(document: unknown, context: PolicyLintContext = {}): PolicyLintResult {
  try {
    validatePolicy(document);
  } catch (error) {
    if (error instanceof IamError)
      return { valid: false, error: { code: error.code, message: error.message }, warnings: [] };
    throw error;
  }
  const cache = new Map<string, KeyInfo>();
  const info = (key: string): KeyInfo => {
    let found = cache.get(key);
    if (!found) cache.set(key, (found = keyInfo(key, context)));
    return found;
  };
  const statements = document.statements;
  const warnings: PolicyLintWarning[] = [];
  const fingerprints = new Map<string, number>();

  // Denies whose only condition is Exists false on one key. Such a deny makes another deny on that key safe when
  // it covers every action and resource of the other.
  const guards = statements.filter((statement) => absenceKey(statement) !== undefined);
  const guardsByKey = new Map<string, Bits>();
  guards.forEach((guard, position) => {
    const key = absenceKey(guard)!;
    let bits = guardsByKey.get(key);
    if (!bits) guardsByKey.set(key, (bits = new Uint32Array(bitWords(guards.length))));
    addBit(bits, position);
  });
  const guarding = coverage(guards);
  /** Some deny for the missing-key case covers the whole statement; false when the check runs out of budget. */
  const absenceGuarded = (statement: PolicyStatement, key: string): boolean => {
    const candidates = guardsByKey.get(key)?.slice();
    if (!candidates) return false;
    for (const field of ['actions', 'resources'] as const)
      for (const value of new Set(statement[field])) {
        const covering = guarding(field, value);
        if (!covering) return false;
        andBits(candidates, covering);
        if (emptyBits(candidates)) return false;
      }
    return true;
  };

  // Allows whose every action and resource pair an unconditional deny covers, with those denies' indexes.
  const denyIndexes = statements.flatMap((statement, index) =>
    statement.effect === 'deny' && !statement.conditions ? [index] : [],
  );
  const denying = coverage(denyIndexes.map((index) => statements[index]!));
  const shadowingDenies = (statement: PolicyStatement): number[] | undefined => {
    const sides: Bits[][] = [];
    for (const field of ['actions', 'resources'] as const) {
      const side: Bits[] = [];
      for (const value of new Set(statement[field])) {
        const covering = denying(field, value);
        if (!covering) return undefined;
        if (emptyBits(covering)) return [];
        side.push(covering);
      }
      sides.push(side);
    }
    const shadowing = new Set<number>();
    for (const action of sides[0]!)
      for (const resource of sides[1]!) {
        const first = firstCommon(action, resource);
        if (first < 0) return [];
        shadowing.add(denyIndexes[first]!);
      }
    return [...shadowing].sort((a, b) => a - b);
  };
  const shadowed = new Map<number, number[]>();
  /** The first allow the shadow check had no budget left for. */
  let unchecked: number | undefined;
  if (denyIndexes.length)
    for (const [index, statement] of statements.entries()) {
      if (statement.effect !== 'allow') continue;
      const shadowing = shadowingDenies(statement);
      if (!shadowing) {
        unchecked = index;
        break;
      }
      if (shadowing.length) shadowed.set(index, shadowing);
    }

  statements.forEach((statement, index) => {
    const warn = (code: string, severity: PolicyLintWarning['severity'], message: string) =>
      warnings.push({
        code,
        severity,
        statement: index,
        ...(statement.sid !== undefined ? { sid: statement.sid } : {}),
        message,
      });
    const once = new Set<string>();
    const first = (code: string, subject: string) => {
      const marker = `${code}\u0000${subject}`;
      if (once.has(marker)) return false;
      once.add(marker);
      return true;
    };
    const entries = Object.entries(statement.conditions ?? {}).flatMap(([operator, attributes]) =>
      Object.entries(attributes ?? {}).map(
        ([key, value]): [ConditionOperator, string, Scalar[]] => [
          operator as ConditionOperator,
          key,
          list(value),
        ],
      ),
    );
    const exists = statement.conditions?.Exists ?? {};
    const variables = [
      ...statement.resources.flatMap(variablesOf),
      ...entries.flatMap(([, , values]) => values.flatMap(variablesOf)),
    ];

    if (statement.effect === 'allow' && !statement.conditions) {
      const everything =
        statement.actions.some((action) => action === '*' || action === 'iam:*') &&
        statement.resources.some((resource) => /^(iam\/)?\*+$/.test(resource));
      const serviceWide = statement.actions.filter(
        (action) => action !== '*' && action !== 'iam:*' && /(^|:)\*$/.test(action),
      );
      if (everything)
        warn(
          'unrestricted-admin',
          'warning',
          'An unconditional allow of every action on every resource makes each holder a full administrator. Scope the actions and resources, or add conditions such as principal.mfa.',
        );
      else if (serviceWide.length)
        warn(
          'service-wildcard',
          'info',
          `Unconditional ${serviceWide.join(', ')} also grants actions added to ${serviceWide.length === 1 ? 'that service' : 'those services'} later. List the actions holders need.`,
        );
    }

    for (const [kind, keys] of [
      ['Condition key', entries.map(([, key]) => key)],
      ['Variable', variables],
    ] as const)
      for (const key of keys) {
        if (info(key).known || !first('unknown-context-key', key)) continue;
        const hint = missingKeyHints.get(key);
        warn(
          'unknown-context-key',
          'warning',
          `${kind} ${key} is never set by the server; supply it with resolveContext${hint ? `, ${hint}` : ''}. ${kind === 'Variable' ? 'Until then the variable never resolves.' : 'Until then every operator except Exists is false for it.'}`,
        );
      }

    if (statement.effect === 'deny')
      for (const [operator, key] of entries) {
        if (
          operator === 'Exists' ||
          !info(key).optional ||
          Object.hasOwn(exists, key) ||
          !first('optional-key-deny', key) ||
          absenceGuarded(statement, key)
        )
          continue;
        warn(
          'optional-key-deny',
          'warning',
          `This deny tests ${key}, which is missing from some requests; when it is missing the deny silently never applies. Add a deny whose only condition is Exists { "${key}": false } over the same actions and resources for that case, or test Exists on the key here to make the intent explicit.`,
        );
      }

    for (const [operator, key, values] of entries) {
      const type = info(key).type;
      const variableKeys = values.flatMap(variablesOf);
      if (negatedStringOperators.has(operator))
        for (const variable of variableKeys) {
          const guarded =
            Object.hasOwn(exists, variable) && list(exists[variable]!).every((v) => v === true);
          if (!info(variable).optional || guarded || !first('negated-variable', variable)) continue;
          warn(
            'negated-variable',
            'warning',
            `${operator} on ${key} compares with \${${variable}}, which can be missing; an unresolved variable makes the negated comparison true. Add Exists { "${variable}": true } to this statement.`,
          );
        }
      if (operator === 'StringLikeIgnoreCase')
        for (const variable of variableKeys)
          if (/[A-Z]/.test(variable) && first('ignorecase-variable', variable))
            warn(
              'ignorecase-variable',
              'warning',
              `StringLikeIgnoreCase lowercases its pattern, so \${${variable}} is looked up as \${${variable.toLowerCase()}} and does not resolve. Use StringLike or a lowercase key.`,
            );
      if (
        type === 'list' &&
        operator !== 'Exists' &&
        !arrayOperators.has(operator) &&
        first('array-key-string-operator', `${operator}:${key}`)
      )
        warn(
          'array-key-string-operator',
          'warning',
          `${operator} never matches ${key}, which holds a list. Use ArrayContains or ArrayContainsAll.`,
        );
      const mismatch = type && typeMismatch(operator, key, type);
      if (mismatch && first('type-mismatch', `${operator}:${key}`))
        warn('type-mismatch', 'warning', mismatch);
      if (
        (operator === 'Bool' || operator === 'Exists') &&
        values.includes(true) &&
        values.includes(false)
      )
        warn(
          'always-true-condition',
          'info',
          `${operator} lists both true and false for ${key}, so it ${operator === 'Exists' ? 'always holds' : 'holds for any boolean value'}. Remove the condition or keep one value.`,
        );
    }

    for (const variable of variables)
      if (info(variable).type === 'list' && first('array-variable', variable))
        warn(
          'array-variable',
          'warning',
          `\${${variable}} names a list, and variables only resolve to strings, numbers, and booleans, so it never resolves. Test the list with ArrayContains instead.`,
        );

    const print = fingerprint(statement);
    const earlier = fingerprints.get(print);
    if (earlier === undefined) fingerprints.set(print, index);
    else
      warn(
        'duplicate-statement',
        'info',
        `This statement repeats statement ${earlier}${statements[earlier]!.sid !== undefined ? ` (${statements[earlier]!.sid})` : ''}; remove one of them.`,
      );

    const shadowing = shadowed.get(index);
    if (shadowing)
      warn(
        'shadowed-allow',
        'warning',
        `Every action and resource of this allow is also denied unconditionally (statement ${shadowing.join(', ')}), so it never grants anything.`,
      );
  });

  if (!statements.some((statement) => statement.effect === 'allow'))
    warnings.push({
      code: 'deny-only',
      severity: 'info',
      statement: -1,
      message:
        'The document has no allow statements, so it grants nothing; its denies still restrict every holder.',
    });
  if (unchecked !== undefined)
    warnings.push({
      code: 'shadowed-allow-skipped',
      severity: 'info',
      statement: -1,
      message: `The document has too many patterns to compare every allow with the unconditional denies; allows from statement ${unchecked} on were not checked for shadowing.`,
    });
  warnings.sort(
    (a, b) => a.statement - b.statement || compare(a.code, b.code) || compare(a.message, b.message),
  );
  return { valid: true, warnings };
}
