/**
 * The rule language of automatic (birthright) access packages. Pure: no store, no server context. A rule is a list
 * of `include` clauses (any may match) and `exclude` clauses (any match denies), each exactly a policy statement's
 * `conditions` block, compiled into a policy document and evaluated by the core policy engine against a context
 * built from the identity alone.
 */
import {
  IamError,
  evaluatePolicy,
  validatePolicy,
  type AttributeType,
  type ConditionOperator,
  type Identity,
  type PolicyDocument,
} from '@better-iam/core';
import { sessionScopedPrincipalKeys, sessionTagPrefix } from './context-keys.js';
import type { AutoAssignRule, PackageRuleConditions } from './models.js';
import { integer } from './validation.js';

/** What an administrator writes: the rule without its runtime state (owner, authority, revision, approval). */
export interface AutoAssignInput {
  include: PackageRuleConditions[];
  exclude?: PackageRuleConditions[];
  graceMs?: number;
  maxGrants?: number;
  maxRemovals?: number;
}
export type RuleKeyType = 'string' | 'number' | 'boolean' | 'array';
/** A key a rule may test, with its type and the operators that apply to it. */
export interface RuleKey {
  key: string;
  type: RuleKeyType;
  operators: ConditionOperator[];
}
export interface RuleEnvironment {
  identityAttributes: Record<string, AttributeType>;
  /** Valid identity.groups values (group IDs, or names in a configuration document); omitted = not checked. */
  groups?: ReadonlySet<string>;
  /** The package's own groups, in the same form; identity.groups may not name them. */
  packagedGroups?: ReadonlySet<string>;
  /**
   * The org structure keys `identity.teams` and `identity.departments` (org-rules.ts), offered only where the caller
   * evaluates them (access packages, not onboarding flows). The sets hold the valid values (team and department IDs,
   * or team slugs and department names in a configuration document); omitted = not checked.
   */
  org?: {
    teams?: Pick<ReadonlySet<string>, 'has'>;
    departments?: Pick<ReadonlySet<string>, 'has'>;
  };
}
/** What `identity.teams` and `identity.departments` hold for one identity (see org-rules.ts). */
export interface RuleOrgFacts {
  teams: readonly string[];
  departments: readonly string[];
}
/** The rule keys that test the org structure, and what their values name. */
export const orgRuleKeys = {
  'identity.teams': 'team',
  'identity.departments': 'department',
} as const;
const isOrgRuleKey = (key: string): key is keyof typeof orgRuleKeys =>
  Object.hasOwn(orgRuleKeys, key);
export interface RuleMatch {
  matched: boolean;
  matchedBy: string[];
  excludedBy: string[];
}

export const maxRuleClauses = 10;
export const maxRuleBytes = 16_384;
export const maxGraceMs = 90 * 86_400_000;
export const defaultMaxGrants = 100;
export const defaultMaxRemovals = 25;
export const automaticJustification = 'Automatic: matches the package rule';
/** Synthetic action used only inside rule documents; never a catalog action, grants nothing. */
export const ruleAction = 'auto-assign';

const stringOps: ConditionOperator[] = [
  'StringEquals',
  'StringNotEquals',
  'StringEqualsIgnoreCase',
  'StringNotEqualsIgnoreCase',
  'StringLike',
  'StringNotLike',
  'StringLikeIgnoreCase',
];
const numericOps: ConditionOperator[] = [
  'NumericEquals',
  'NumericNotEquals',
  'NumericLessThan',
  'NumericLessThanEquals',
  'NumericGreaterThan',
  'NumericGreaterThanEquals',
];
const boolOps: ConditionOperator[] = ['Bool'];
const arrayOps: ConditionOperator[] = ['ArrayContains', 'ArrayContainsAll'];
const withExists = (operators: ConditionOperator[]): ConditionOperator[] => [
  ...operators,
  'Exists',
];
/**
 * Keys that describe a session or a grant rather than the person, with the reason a rule cannot use them. The
 * session-derived keys (`sessionScopedPrincipalKeys`) belong here too, and so does every `principal.sessionTags.` key.
 */
const sessionKeys = new Set([
  'principal.mfa',
  'principal.sessionKind',
  'principal.authMethod',
  'principal.impersonated',
  'principal.impersonatorId',
  'principal.roles',
  'principal.tenantId',
  'principal.rootAdmin',
  ...sessionScopedPrincipalKeys,
]);

/**
 * Every key a rule may test, in a stable order: fixed keys first, then the declared identity attributes. `org` adds
 * `identity.teams` and `identity.departments` for callers that evaluate them.
 */
export function ruleKeys(
  identityAttributes: Record<string, AttributeType>,
  options: { org?: boolean } = {},
): RuleKey[] {
  const keys: RuleKey[] = [
    { key: 'principal.id', type: 'string', operators: withExists(stringOps) },
    { key: 'principal.kind', type: 'string', operators: withExists(stringOps) },
    { key: 'principal.owner', type: 'boolean', operators: withExists(boolOps) },
    { key: 'identity.email', type: 'string', operators: withExists(stringOps) },
    { key: 'identity.emailDomain', type: 'string', operators: withExists(stringOps) },
    { key: 'identity.emailVerified', type: 'boolean', operators: withExists(boolOps) },
    { key: 'identity.managerId', type: 'string', operators: withExists(stringOps) },
    { key: 'identity.groups', type: 'array', operators: withExists(arrayOps) },
    ...(options.org
      ? Object.keys(orgRuleKeys).map(
          (key): RuleKey => ({ key, type: 'array', operators: withExists(arrayOps) }),
        )
      : []),
  ];
  for (const name of Object.keys(identityAttributes).sort()) {
    const type = identityAttributes[name]!;
    keys.push({
      key: `principal.${name}`,
      type,
      operators: withExists(
        type === 'string'
          ? [...stringOps, 'DateBefore', 'DateAfter']
          : type === 'number'
            ? numericOps
            : boolOps,
      ),
    });
  }
  return keys;
}

const plainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;

/**
 * Validates a rule against the deployment's declared attributes and (when known) the tenant's groups. Every error
 * message starts with `path`, so configuration documents point at the offending package. Values keep the scalar or
 * array form they were given, so export and plan compare canonically.
 */
export function parseAutoAssign(
  value: unknown,
  env: RuleEnvironment,
  path = 'autoAssign',
): AutoAssignInput {
  if (!plainObject(value)) throw new IamError('INVALID_INPUT', `${path} must be an object`);
  for (const key of Object.keys(value))
    if (!['include', 'exclude', 'graceMs', 'maxGrants', 'maxRemovals'].includes(key))
      throw new IamError('INVALID_INPUT', `${path}: unknown field ${key}`);
  const include = value.include;
  if (!Array.isArray(include) || include.length < 1 || include.length > maxRuleClauses)
    throw new IamError(
      'INVALID_INPUT',
      `${path}.include must list 1-${maxRuleClauses} condition sets`,
    );
  const exclude = value.exclude === undefined ? [] : value.exclude;
  if (!Array.isArray(exclude) || exclude.length > maxRuleClauses)
    throw new IamError(
      'INVALID_INPUT',
      `${path}.exclude must list at most ${maxRuleClauses} condition sets`,
    );
  const keys = new Map(
    ruleKeys(env.identityAttributes, { org: env.org !== undefined }).map((key) => [key.key, key]),
  );
  const declared = Object.keys(env.identityAttributes).sort();
  const clause = (item: unknown, clausePath: string): PackageRuleConditions => {
    if (!plainObject(item) || Object.keys(item).length === 0)
      throw new IamError('INVALID_INPUT', `${clausePath} must be a nonempty condition set`);
    try {
      validatePolicy({
        version: 1,
        statements: [
          { effect: 'allow', actions: [ruleAction], resources: ['identity/*'], conditions: item },
        ],
      });
    } catch (error) {
      if (error instanceof IamError)
        throw new IamError('INVALID_POLICY', `${clausePath}: ${error.message}`);
      throw error;
    }
    for (const [operator, entries] of Object.entries(item)) {
      for (const [key, expected] of Object.entries(entries as Record<string, unknown>)) {
        const known = keys.get(key);
        if (!known) {
          if (key === 'principal.groups')
            throw new IamError(
              'INVALID_INPUT',
              `${clausePath}: use identity.groups (memberships not created by access packages) instead of principal.groups`,
            );
          if (sessionKeys.has(key) || key.startsWith(sessionTagPrefix))
            throw new IamError(
              'INVALID_INPUT',
              `${clausePath}: ${key} describes a session or grant and is not available to package rules`,
            );
          if (isOrgRuleKey(key))
            throw new IamError(
              'INVALID_INPUT',
              `${clausePath}: ${key} is available to access package rules only`,
            );
          throw new IamError(
            'INVALID_INPUT',
            `${clausePath}: unknown key ${key}; use principal.id, principal.kind, principal.owner, identity.email, identity.emailDomain, identity.emailVerified, identity.managerId, identity.groups, ${env.org ? 'identity.teams, identity.departments, ' : ''}or principal.<declared attribute> (${declared.length ? declared.join(', ') : 'none declared'})`,
          );
        }
        if (!known.operators.includes(operator as ConditionOperator))
          throw new IamError(
            'INVALID_INPUT',
            `${clausePath}: ${operator} cannot test ${key} (${known.type}); use ${known.operators.join(', ')}`,
          );
        const values = Array.isArray(expected) ? expected : [expected];
        if (values.some((entry) => typeof entry === 'string' && entry.includes('${')))
          throw new IamError(
            'INVALID_INPUT',
            `${clausePath}: policy variables are not available in package rules`,
          );
        if (
          key === 'principal.kind' &&
          [
            'StringEquals',
            'StringNotEquals',
            'StringEqualsIgnoreCase',
            'StringNotEqualsIgnoreCase',
          ].includes(operator) &&
          values.some(
            (entry) =>
              typeof entry !== 'string' || !['user', 'service'].includes(entry.toLowerCase()),
          )
        )
          throw new IamError(
            'INVALID_INPUT',
            `${clausePath}: principal.kind is 'user' or 'service'`,
          );
        if (key === 'identity.groups' && operator !== 'Exists')
          for (const entry of values) {
            if (typeof entry !== 'string')
              throw new IamError('INVALID_INPUT', `${clausePath}: identity.groups lists groups`);
            if (env.groups && !env.groups.has(entry))
              throw new IamError('INVALID_INPUT', `${clausePath}: unknown group ${entry}`);
            if (env.packagedGroups?.has(entry))
              throw new IamError(
                'INVALID_INPUT',
                `${clausePath}: identity.groups cannot name ${entry}, a group this package grants`,
              );
          }
        if (isOrgRuleKey(key) && operator !== 'Exists') {
          const noun = orgRuleKeys[key];
          const valid = noun === 'team' ? env.org?.teams : env.org?.departments;
          for (const entry of values) {
            if (typeof entry !== 'string')
              throw new IamError('INVALID_INPUT', `${clausePath}: ${key} lists ${noun}s`);
            if (valid && !valid.has(entry))
              throw new IamError('INVALID_INPUT', `${clausePath}: unknown ${noun} ${entry}`);
          }
        }
      }
    }
    return item as PackageRuleConditions;
  };
  const parsedInclude = include.map((item, index) => clause(item, `${path}.include[${index}]`));
  const parsedExclude = exclude.map((item, index) => clause(item, `${path}.exclude[${index}]`));
  if (JSON.stringify({ include: parsedInclude, exclude: parsedExclude }).length > maxRuleBytes)
    throw new IamError('INVALID_INPUT', `${path} is larger than ${maxRuleBytes} bytes`);
  const graceMs =
    value.graceMs === undefined
      ? undefined
      : integer(value.graceMs, `${path}.graceMs`, 0, maxGraceMs);
  const maxGrants =
    value.maxGrants === undefined
      ? undefined
      : integer(value.maxGrants, `${path}.maxGrants`, 1, 100_000);
  const maxRemovals =
    value.maxRemovals === undefined
      ? undefined
      : integer(value.maxRemovals, `${path}.maxRemovals`, 1, 100_000);
  return structuredClone({
    include: parsedInclude,
    ...(parsedExclude.length ? { exclude: parsedExclude } : {}),
    ...(graceMs ? { graceMs } : {}),
    ...(maxGrants !== undefined ? { maxGrants } : {}),
    ...(maxRemovals !== undefined ? { maxRemovals } : {}),
  });
}

/** The administrator-written part of a stored rule (or a rule input), without runtime state. */
export function ruleInput(rule: AutoAssignRule | AutoAssignInput): AutoAssignInput {
  return {
    include: rule.include,
    ...(rule.exclude?.length ? { exclude: rule.exclude } : {}),
    ...(rule.graceMs ? { graceMs: rule.graceMs } : {}),
    ...(rule.maxGrants !== undefined ? { maxGrants: rule.maxGrants } : {}),
    ...(rule.maxRemovals !== undefined ? { maxRemovals: rule.maxRemovals } : {}),
  };
}

/** The reason a stored rule no longer validates (an attribute declaration removed, a group gone), if any. */
export function ruleProblem(
  rule: AutoAssignRule | AutoAssignInput,
  env: RuleEnvironment,
): string | undefined {
  try {
    parseAutoAssign(ruleInput(rule), env);
    return undefined;
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
}

function stableJson(value: unknown): string {
  return JSON.stringify(value, (_key, item) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item as Record<string, unknown>)
            .filter(([, entry]) => entry !== undefined)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : item,
  );
}

/** Whether two rules say the same thing (runtime state ignored). */
export function sameRuleInput(
  a: AutoAssignRule | AutoAssignInput,
  b: AutoAssignRule | AutoAssignInput,
): boolean {
  return stableJson(ruleInput(a)) === stableJson(ruleInput(b));
}

/** Include clauses become allow statements and exclude clauses deny statements of one policy document. */
export function ruleDocument(rule: AutoAssignRule | AutoAssignInput): PolicyDocument {
  return {
    version: 1,
    statements: [
      ...rule.include.map((conditions, index) => ({
        sid: `include-${index}`,
        effect: 'allow' as const,
        actions: [ruleAction],
        resources: ['identity/*'],
        conditions,
      })),
      ...(rule.exclude ?? []).map((conditions, index) => ({
        sid: `exclude-${index}`,
        effect: 'deny' as const,
        actions: [ruleAction],
        resources: ['identity/*'],
        conditions,
      })),
    ],
  };
}

/**
 * The context a rule sees: the identity's declared attributes and fixed facts, and its group memberships that no
 * access package created (so rules never chain onto another package or keep themselves alive). No session,
 * request, or resource keys: a scheduler cannot replay them, and a preview must equal a reconcile. `org` supplies
 * `identity.teams` and `identity.departments` where the caller evaluates them.
 */
export function ruleContext(
  identity: Identity,
  directGroupIds: Iterable<string>,
  org?: RuleOrgFacts,
): Record<string, unknown> {
  const context: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(identity.attributes ?? {}))
    context[`principal.${key}`] = value;
  context['principal.id'] = identity.id;
  context['principal.kind'] = identity.kind;
  context['principal.owner'] = identity.owner;
  if (identity.email) {
    const email = identity.email.toLowerCase();
    context['identity.email'] = email;
    context['identity.emailDomain'] = email.slice(email.lastIndexOf('@') + 1);
  }
  context['identity.emailVerified'] = identity.emailVerified;
  if (identity.managerId) context['identity.managerId'] = identity.managerId;
  context['identity.groups'] = [...new Set(directGroupIds)].sort();
  if (org) {
    context['identity.teams'] = [...new Set(org.teams)].sort();
    context['identity.departments'] = [...new Set(org.departments)].sort();
  }
  return context;
}

/** Evaluates a compiled rule for one identity; `matchedBy`/`excludedBy` name the clauses that held. */
export function ruleMatch(
  document: PolicyDocument,
  identity: Identity,
  context: Record<string, unknown>,
): RuleMatch {
  const decision = evaluatePolicy({
    action: ruleAction,
    resource: `identity/${identity.id}`,
    context,
    grants: [document],
  });
  const sids = decision.matched.map((entry) => entry.split(':').slice(2).join(':'));
  return {
    matched: decision.allowed,
    matchedBy: sids.filter((sid) => sid.startsWith('include-')),
    excludedBy: sids.filter((sid) => sid.startsWith('exclude-')),
  };
}

const operatorsOf = (clause: PackageRuleConditions) =>
  Object.entries(clause) as Array<[ConditionOperator, Record<string, unknown>]>;

/** Keys fixed when an identity is created (or moved only by an ownership transfer); other `principal.` keys are attributes. */
const fixedPrincipalKeys = new Set(['principal.id', 'principal.kind', 'principal.owner']);

/**
 * Advice, not errors: rules that also match service accounts, email tests that accept unverified addresses, and
 * clauses on facts that callers with fewer rights than the rule's owner control. A rule grants under its owner's
 * authority to whoever matches, so whoever sets those facts picks the recipients: declared attributes and
 * identity.managerId (iam:identities:update), and memberships of groups without role bindings (iam:groups:update
 * alone; adding to a group with bindings needs their authorities). `boundGroups` holds the tenant's groups that have
 * role bindings; without it, groups are not checked.
 */
export function ruleWarnings(
  rule: AutoAssignRule | AutoAssignInput,
  env: { boundGroups?: ReadonlySet<string> } = {},
): string[] {
  const warnings: string[] = [];
  const controlled = (clause: PackageRuleConditions, path: string, consequence: string) => {
    const keys = [
      ...new Set(
        operatorsOf(clause).flatMap(([, entries]) =>
          Object.keys(entries).filter(
            (key) =>
              key === 'identity.managerId' ||
              (key.startsWith('principal.') && !fixedPrincipalKeys.has(key)),
          ),
        ),
      ),
    ].sort();
    if (keys.length)
      warnings.push(
        `${path} tests ${keys.join(', ')}, which anyone holding iam:identities:update can set, so ${consequence}`,
      );
    const unbound = env.boundGroups
      ? ruleGroupIds({ include: [clause] }).filter((groupId) => !env.boundGroups!.has(groupId))
      : [];
    if (unbound.length)
      warnings.push(
        `${path} tests identity.groups for ${unbound.join(', ')}, ${unbound.length === 1 ? 'a group' : 'groups'} without role bindings whose members anyone holding iam:groups:update can change, so ${consequence}`,
      );
  };
  rule.include.forEach((clause, index) => {
    const tests = operatorsOf(clause);
    if (
      !tests.some(([operator, keys]) => operator.startsWith('String') && 'principal.kind' in keys)
    )
      warnings.push(
        `include[${index}] does not test principal.kind, so it also matches service accounts`,
      );
    const email = tests.some(
      ([, keys]) => 'identity.email' in keys || 'identity.emailDomain' in keys,
    );
    if (email && clause.Bool?.['identity.emailVerified'] !== true)
      warnings.push(
        `include[${index}] tests an email address without requiring Bool identity.emailVerified: true, so unverified addresses match (SCIM-provisioned and administrator-set addresses are unverified)`,
      );
    controlled(
      clause,
      `include[${index}]`,
      'they choose who receives this package under its owner’s authority',
    );
  });
  (rule.exclude ?? []).forEach((clause, index) =>
    controlled(clause, `exclude[${index}]`, 'they can lift the exclusion'),
  );
  return warnings;
}

/** The values a rule tests an array key (identity.groups, identity.teams, identity.departments) for. */
export function ruleValues(
  rule: Pick<AutoAssignInput, 'include' | 'exclude'> | undefined,
  key: string,
): string[] {
  if (!rule) return [];
  const found = new Set<string>();
  for (const clause of [...rule.include, ...(rule.exclude ?? [])])
    for (const [operator, keys] of operatorsOf(clause)) {
      if (operator !== 'ArrayContains' && operator !== 'ArrayContainsAll') continue;
      const expected = keys[key];
      for (const value of Array.isArray(expected) ? expected : [expected])
        if (typeof value === 'string') found.add(value);
    }
  return [...found];
}

/** The group IDs (or names) a rule tests with identity.groups. */
export function ruleGroupIds(rule?: Pick<AutoAssignInput, 'include' | 'exclude'>): string[] {
  return ruleValues(rule, 'identity.groups');
}

/** A copy of a rule with the values it tests an array key for mapped (IDs to names for export, names to IDs for apply). */
export function mapRuleValues<T extends Pick<AutoAssignInput, 'include' | 'exclude'>>(
  rule: T,
  key: string,
  map: (value: string) => string,
): T {
  const clone = structuredClone(rule);
  for (const clause of [...clone.include, ...(clone.exclude ?? [])])
    for (const [operator, keys] of operatorsOf(clause)) {
      if (operator !== 'ArrayContains' && operator !== 'ArrayContainsAll') continue;
      const expected = keys[key];
      if (expected === undefined) continue;
      keys[key] = Array.isArray(expected)
        ? expected.map((value) => (typeof value === 'string' ? map(value) : value))
        : typeof expected === 'string'
          ? map(expected)
          : expected;
    }
  return clone;
}

/** A copy of a rule with its identity.groups values mapped (IDs to names for export, names to IDs for apply). */
export function mapRuleGroups<T extends Pick<AutoAssignInput, 'include' | 'exclude'>>(
  rule: T,
  map: (value: string) => string,
): T {
  return mapRuleValues(rule, 'identity.groups', map);
}
