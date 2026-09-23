import {
  IamError,
  type IamStore,
  type PolicyDocument,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { hash } from './utils.js';
import { integer, object, text } from './validation.js';

/**
 * A feature flag. Flags the root tenant defines are platform flags and reach every tenant; flags another tenant
 * defines reach only that tenant and its descendants. Keys are unique per defining tenant (`uniqueKey` = key), and
 * when an ancestor defines the same key its flag wins, so a tenant can never shadow a platform flag.
 */
export interface FeatureFlag extends StoredRecord {
  key: string;
  description?: string;
  /** The value when no target, override, or rollout decides. */
  defaultValue: boolean;
  /**
   * 0-100: the share of branches directly below the defining tenant that get `true` (a whole organization, with its
   * projects, lands on the same side). Requires `defaultValue: false`; raising it keeps earlier tenants enabled.
   */
  rolloutPercentage?: number;
  /** Tenants below the defining tenant may choose their own value (`features.setOverride`). */
  tenantOverridable: boolean;
  /** Off everywhere, whatever targets and overrides say: the incident switch. */
  killSwitch: boolean;
  /**
   * Evaluated only by trusted code (`iam.features`) and policy conditions; hidden from `features.evaluate` and from
   * the listings of tenants below the defining tenant. Internal flags cannot be tenant-overridable.
   */
  internal: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

/**
 * A value pinned for one tenant and its descendants. `target` entries are set by the flag's managers in the defining
 * tenant (a `locked` target also keeps tenants in its subtree from overriding); `override` entries are a tenant's own
 * choice for a tenant-overridable flag. The record lives in the tenant it applies to (`uniqueKey` `{flagId}:{source}`),
 * so purging that tenant removes it; deleting the flag removes all of them.
 */
export interface FeatureTarget extends StoredRecord {
  flagId: string;
  key: string;
  /** The flag's defining tenant. */
  definerId: string;
  source: 'target' | 'override';
  value: boolean;
  locked?: boolean;
  expiresAt?: number;
  note?: string;
  setAt: number;
  setBy: string;
}

/** Why a flag has its value for a tenant, in precedence order. `UNKNOWN`: no flag with that key reaches the tenant. */
export type FeatureReason =
  | 'KILL_SWITCH'
  | 'TARGET'
  | 'OVERRIDE'
  | 'ROLLOUT'
  | 'DEFAULT'
  | 'UNKNOWN';

/** A flag's value for one tenant, with the reason and where it was decided. */
export interface FeatureEvaluation {
  key: string;
  value: boolean;
  reason: FeatureReason;
  /** `platform` for flags the root tenant defines, `tenant` for flags of an organization or project. */
  scope: 'platform' | 'tenant';
  /** The defining tenant (absent for `UNKNOWN`). */
  definedBy?: string;
  /** The tenant whose target or override decided: the evaluated tenant or one of its ancestors. */
  decidedBy?: string;
  /** When the deciding target or override lapses. */
  expiresAt?: number;
  /** A locked target at or above the tenant keeps overrides from applying. */
  locked: boolean;
  /** Whether the evaluated tenant's administrators may set their own value now (`features.setOverride`). */
  overridable: boolean;
}

export const featureCollections = { flags: 'featureFlags', targets: 'featureTargets' } as const;
/** Flags one tenant may define. */
export const maxFeatureFlagsPerTenant = 200;
/** Lowercase letters and digits in segments joined by `-`, `_`, or `.`, starting with a letter: `new-billing`, `reports.v2`. */
const keyPattern = /^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$/;
/** The policy context key holding the sorted keys of every flag that is on for the decision's tenant. */
export const featureContextKey = 'tenant.features';

/** Validates a flag key: at most 64 characters matching `keyPattern`. */
export function featureKey(value: unknown): string {
  const key = text(value, 'key', 64);
  if (!keyPattern.test(key))
    throw new IamError(
      'INVALID_INPUT',
      'Flag keys are lowercase letters and digits joined by "-", "_", or ".", starting with a letter',
    );
  return key;
}

export type FeatureFlagSettings = Pick<
  FeatureFlag,
  | 'description'
  | 'defaultValue'
  | 'rolloutPercentage'
  | 'tenantOverridable'
  | 'killSwitch'
  | 'internal'
>;

const settingKeys = new Set([
  'description',
  'defaultValue',
  'rolloutPercentage',
  'tenantOverridable',
  'killSwitch',
  'internal',
]);

/**
 * Applies a settings patch to `current` (defaults for a new flag) and validates the result. `null` clears
 * `description` and `rolloutPercentage`; unknown fields are refused.
 */
export function featureSettings(
  input: Record<string, unknown>,
  current: FeatureFlagSettings = {
    defaultValue: false,
    tenantOverridable: false,
    killSwitch: false,
    internal: false,
  },
): FeatureFlagSettings {
  for (const field of Object.keys(object(input)))
    if (!settingKeys.has(field) && field !== 'tenantId' && field !== 'key')
      throw new IamError('INVALID_INPUT', `Unknown flag field ${field}`);
  const next: FeatureFlagSettings = {
    defaultValue: current.defaultValue,
    tenantOverridable: current.tenantOverridable,
    killSwitch: current.killSwitch,
    internal: current.internal,
    ...(current.description !== undefined ? { description: current.description } : {}),
    ...(current.rolloutPercentage !== undefined
      ? { rolloutPercentage: current.rolloutPercentage }
      : {}),
  };
  for (const field of ['defaultValue', 'tenantOverridable', 'killSwitch', 'internal'] as const) {
    const value = input[field];
    if (value === undefined) continue;
    if (typeof value !== 'boolean')
      throw new IamError('INVALID_INPUT', `${field} must be a boolean`);
    next[field] = value;
  }
  if (input.description === null) delete next.description;
  else if (input.description !== undefined)
    next.description = text(input.description, 'description', 512).trim();
  if (input.rolloutPercentage === null) delete next.rolloutPercentage;
  else if (input.rolloutPercentage !== undefined)
    next.rolloutPercentage = integer(input.rolloutPercentage, 'rolloutPercentage', 0, 100);
  if (next.rolloutPercentage !== undefined && next.defaultValue)
    throw new IamError(
      'INVALID_INPUT',
      'A rollout turns a flag on gradually: set defaultValue to false or remove rolloutPercentage',
    );
  if (next.internal && next.tenantOverridable)
    throw new IamError('INVALID_INPUT', 'Internal flags cannot be tenant-overridable');
  return next;
}

/**
 * The rollout position (0 to 99.99) of a tenant branch for a flag: stable per key and tenant, so raising the
 * percentage only ever adds tenants, and different flags spread over different tenants.
 */
export function rolloutBucket(key: string, tenantId: string): number {
  return (parseInt(hash(`feature:${key}:${tenantId}`).slice(0, 8), 16) % 10_000) / 100;
}

/** Whether any statement of the documents names the `tenant.features` context key in a condition. */
export function mentionsFeatures(documents: Iterable<PolicyDocument>): boolean {
  for (const document of documents)
    for (const statement of document.statements)
      for (const block of Object.values(statement.conditions ?? {}))
        if (block && Object.hasOwn(block, featureContextKey)) return true;
  return false;
}

/** What evaluation needs about one tenant: its ancestry, the flags that reach it, and the pinned values along it. */
export interface FeatureState {
  /** The tenant and its ancestors, nearest first (`ctx.ancestry`). */
  chain: Tenant[];
  /** The effective flag per key: the one defined closest to the root. */
  flags: Map<string, FeatureFlag>;
  /** Flags defined along the chain that an ancestor's flag of the same key overrides. */
  shadowed: FeatureFlag[];
  /** Live (unexpired) targets and overrides along the chain, by flag id. */
  entries: Map<string, FeatureTarget[]>;
}

/** Reads the flags and pinned values along a tenant's ancestry (two lookups per tenant in the chain). */
export async function featureState(
  tx: IamStore,
  chain: Tenant[],
  now: number,
): Promise<FeatureState> {
  const flags = new Map<string, FeatureFlag>();
  const shadowed: FeatureFlag[] = [];
  // Root first, so a flag defined closer to the root claims its key before a descendant's flag of the same key.
  for (const realm of [...chain].reverse())
    for (const flag of await tx.find<FeatureFlag>(featureCollections.flags, { tenantId: realm.id }))
      if (flags.has(flag.key)) shadowed.push(flag);
      else flags.set(flag.key, flag);
  const entries = new Map<string, FeatureTarget[]>();
  for (const realm of chain)
    for (const entry of await tx.find<FeatureTarget>(featureCollections.targets, {
      tenantId: realm.id,
    }))
      if (entry.expiresAt === undefined || entry.expiresAt > now)
        entries.set(entry.flagId, [...(entries.get(entry.flagId) ?? []), entry]);
  return { chain, flags, shadowed, entries };
}

/**
 * One flag's value for `state.chain[0]`. Precedence: the kill switch; then, walking from the tenant up to (not
 * including) the defining tenant, the nearest tenant with an override or a target, where a tenant's own override
 * beats a target on the same tenant and a locked target silences overrides at and below its tenant; then the
 * rollout; then the default.
 */
export function evaluateFlag(state: FeatureState, flag: FeatureFlag): FeatureEvaluation {
  const { chain } = state;
  const depth = chain.findIndex((realm) => realm.id === flag.tenantId);
  const scope = chain.at(-1)?.id === flag.tenantId ? 'platform' : 'tenant';
  const base = { key: flag.key, scope, definedBy: flag.tenantId } as const;
  // Only tenants strictly below the defining tenant carry targets and overrides for its flag.
  const below = depth < 0 ? [] : chain.slice(0, depth);
  const entries = (state.entries.get(flag.id) ?? []).filter(
    (entry) => entry.definerId === flag.tenantId,
  );
  const at = (realm: Tenant, source: FeatureTarget['source']) =>
    entries.find((entry) => entry.tenantId === realm.id && entry.source === source);
  let lockedAt = -1;
  below.forEach((realm, index) => {
    if (at(realm, 'target')?.locked) lockedAt = index;
  });
  const overridesApply = flag.tenantOverridable && !flag.internal;
  const overridable = overridesApply && depth > 0 && lockedAt < 0;
  const locked = lockedAt >= 0;
  if (flag.killSwitch) return { ...base, value: false, reason: 'KILL_SWITCH', locked, overridable };
  for (const [index, realm] of below.entries()) {
    const override = overridesApply && index > lockedAt ? at(realm, 'override') : undefined;
    const decided = override ?? at(realm, 'target');
    if (decided)
      return {
        ...base,
        value: decided.value,
        reason: decided.source === 'override' ? 'OVERRIDE' : 'TARGET',
        decidedBy: realm.id,
        ...(decided.expiresAt !== undefined ? { expiresAt: decided.expiresAt } : {}),
        locked,
        overridable,
      };
  }
  if (flag.rolloutPercentage !== undefined) {
    // The branch directly below the defining tenant, so an organization and its projects agree.
    const unit = below.at(-1) ?? chain[0]!;
    return {
      ...base,
      value: rolloutBucket(flag.key, unit.id) < flag.rolloutPercentage,
      reason: 'ROLLOUT',
      locked,
      overridable,
    };
  }
  return { ...base, value: flag.defaultValue, reason: 'DEFAULT', locked, overridable };
}

/** The evaluation reported for a key no flag defines along the tenant's ancestry. */
export function unknownFeature(key: string): FeatureEvaluation {
  return {
    key,
    value: false,
    reason: 'UNKNOWN',
    scope: 'platform',
    locked: false,
    overridable: false,
  };
}

/**
 * Evaluates the flags that reach a tenant, sorted by key. `keys` restricts the result (unknown keys evaluate to
 * `false` with reason `UNKNOWN`); internal flags are included only with `includeInternal`.
 */
export function evaluateFeatures(
  state: FeatureState,
  options: { keys?: readonly string[]; includeInternal?: boolean } = {},
): FeatureEvaluation[] {
  const visible = (flag: FeatureFlag) =>
    options.includeInternal === true ||
    !flag.internal ||
    // Internal flags stay visible to the tenant that defines them.
    flag.tenantId === state.chain[0]?.id;
  if (options.keys) {
    return [...new Set(options.keys)].sort().map((key) => {
      const flag = state.flags.get(key);
      return flag && visible(flag) ? evaluateFlag(state, flag) : unknownFeature(key);
    });
  }
  return [...state.flags.values()]
    .filter(visible)
    .sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : 0))
    .map((flag) => evaluateFlag(state, flag));
}

/** The sorted keys of every flag (internal ones included) that is on for the tenant: the `tenant.features` context. */
export function enabledFeatureKeys(state: FeatureState): string[] {
  return evaluateFeatures(state, { includeInternal: true })
    .filter((evaluation) => evaluation.value)
    .map((evaluation) => evaluation.key);
}
