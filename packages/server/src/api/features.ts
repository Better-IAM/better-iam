import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Json,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import {
  evaluateFeatures,
  evaluateFlag,
  featureCollections,
  featureKey,
  featureSettings,
  featureState,
  maxFeatureFlagsPerTenant,
  type FeatureEvaluation,
  type FeatureFlag,
  type FeatureFlagSettings,
  type FeatureState,
  type FeatureTarget,
} from '../features.js';
import { id } from '../utils.js';
import { object, strings, text } from '../validation.js';

/** A flag's definition as the managers of its defining tenant see it. */
export interface FeatureFlagDefinition {
  id: string;
  key: string;
  /** The defining tenant. */
  tenantId: string;
  /** `platform` when the root tenant defines the flag. */
  scope: 'platform' | 'tenant';
  description?: string;
  defaultValue: boolean;
  rolloutPercentage?: number;
  tenantOverridable: boolean;
  killSwitch: boolean;
  internal: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

/** One flag as a tenant's administrators see it (`features.list`). */
export interface FeatureFlagView {
  key: string;
  description?: string;
  scope: 'platform' | 'tenant';
  /** The defining tenant: this tenant or one of its ancestors. */
  definedBy: string;
  /** The flag's settings, present when this tenant defines the flag (or the caller is a root administrator). */
  definition?: FeatureFlagDefinition;
  tenantOverridable: boolean;
  /** The flag's value for this tenant and why. */
  evaluation: FeatureEvaluation;
  /** The value this tenant chose (`setOverride`); it applies only while the evaluation's reason says `OVERRIDE`. */
  override?: { value: boolean; setAt: number; setBy: string };
  /** The value the flag's managers pinned for this tenant (`setTarget`). */
  target?: { value: boolean; locked: boolean; expiresAt?: number };
}

/** A target or override somewhere below a flag's defining tenant (`features.listTargets`). */
export interface FeatureTargetView {
  id: string;
  /** The tenant the value applies to, with its descendants. */
  tenantId: string;
  tenantName: string;
  tenantStatus: Tenant['status'];
  source: 'target' | 'override';
  value: boolean;
  locked: boolean;
  expiresAt?: number;
  /** Past `expiresAt`, or an override the flag no longer allows: kept, but ignored by evaluation. */
  active: boolean;
  note?: string;
  setAt: number;
  setBy: string;
}

/** Trusted, credential-free evaluation for the deployment's own code (`iam.features`). */
export interface IamFeatures {
  /** Every flag that reaches the tenant (internal ones included), or only `keys`, with values and reasons. */
  evaluate(tenantId: string, options?: { keys?: string[] }): Promise<FeatureEvaluation[]>;
  /** `{ key: value }` for every flag that reaches the tenant, internal ones included. */
  values(tenantId: string): Promise<Record<string, boolean>>;
  /** Whether one flag is on for the tenant; `false` when no flag with the key reaches it. */
  isEnabled(tenantId: string, key: string): Promise<boolean>;
}

const byKey = (a: { key: string }, b: { key: string }) =>
  a.key < b.key ? -1 : a.key > b.key ? 1 : 0;

function definition(flag: FeatureFlag, rootId: string): FeatureFlagDefinition {
  return {
    id: flag.id,
    key: flag.key,
    tenantId: flag.tenantId,
    scope: flag.tenantId === rootId ? 'platform' : 'tenant',
    ...(flag.description !== undefined ? { description: flag.description } : {}),
    defaultValue: flag.defaultValue,
    ...(flag.rolloutPercentage !== undefined ? { rolloutPercentage: flag.rolloutPercentage } : {}),
    tenantOverridable: flag.tenantOverridable,
    killSwitch: flag.killSwitch,
    internal: flag.internal,
    createdAt: flag.createdAt,
    createdBy: flag.createdBy,
    updatedAt: flag.updatedAt,
    updatedBy: flag.updatedBy,
  };
}

/** Audit metadata for a flag's settings. */
function settingsMetadata(flag: FeatureFlagSettings & { key: string }): Record<string, Json> {
  return {
    key: flag.key,
    defaultValue: flag.defaultValue,
    rolloutPercentage: flag.rolloutPercentage ?? null,
    tenantOverridable: flag.tenantOverridable,
    killSwitch: flag.killSwitch,
    internal: flag.internal,
  };
}

/** Credential-free evaluation, shared by `iam.features` and tests. */
export function createFeatureEvaluator(ctx: ServerContext): IamFeatures {
  const evaluate = (tenantId: string, keys?: string[]) =>
    ctx.store.transaction(async (tx) => {
      const realm = await ctx.tenant(tx, text(tenantId, 'tenantId'));
      const state = await featureState(tx, await ctx.ancestry(tx, realm), ctx.now());
      return evaluateFeatures(state, { keys, includeInternal: true });
    });
  return {
    evaluate: (tenantId, options) =>
      evaluate(
        tenantId,
        options?.keys === undefined ? undefined : strings(options.keys, 'keys').map(featureKey),
      ),
    async values(tenantId) {
      return Object.fromEntries(
        (await evaluate(tenantId)).map((evaluation) => [evaluation.key, evaluation.value]),
      );
    },
    async isEnabled(tenantId, key) {
      return (await evaluate(tenantId, [featureKey(key)]))[0]!.value;
    },
  };
}

/**
 * Feature flags at platform and tenant level. The root tenant's flags are platform flags; any organization or
 * project can define flags for its own subtree. A flag's value for a tenant comes from, in order: its kill switch,
 * the nearest target or tenant override along the ancestry (a tenant's own override beats a target on the same
 * tenant; a locked target silences overrides beneath it), a percentage rollout, and its default. Values reach
 * applications through `features.evaluate` (any session of the tenant), `iam.features` on the server, and policy
 * conditions through the `tenant.features` context key.
 */
export function createFeaturesApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const rootOf = (chain: Tenant[]) => chain.at(-1)!.id;
  const resource = (key: string) => `features/${key}`;
  async function ownFlag(tx: IamStore, tenantId: string, key: string): Promise<FeatureFlag> {
    const flag = (
      await tx.find<FeatureFlag>(featureCollections.flags, { tenantId, uniqueKey: key })
    )[0];
    if (!flag) throw new IamError('NOT_FOUND', 'Feature flag not found', 404);
    return flag;
  }
  function writable(realm: Tenant): void {
    if (realm.status === 'deleted')
      throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
  }
  async function entryAt(
    tx: IamStore,
    tenantId: string,
    flag: FeatureFlag,
    source: FeatureTarget['source'],
  ): Promise<FeatureTarget | undefined> {
    return (
      await tx.find<FeatureTarget>(featureCollections.targets, {
        tenantId,
        uniqueKey: `${flag.id}:${source}`,
      })
    )[0];
  }
  async function view(
    tx: IamStore,
    state: FeatureState,
    flag: FeatureFlag,
    withDefinition: boolean,
  ): Promise<FeatureFlagView> {
    const realm = state.chain[0]!;
    const evaluation = evaluateFlag(state, flag);
    const own = (source: FeatureTarget['source']) =>
      flag.tenantId === realm.id ? undefined : entryAt(tx, realm.id, flag, source);
    const override = await own('override');
    const target = await own('target');
    return {
      key: flag.key,
      ...(flag.description !== undefined ? { description: flag.description } : {}),
      scope: evaluation.scope,
      definedBy: flag.tenantId,
      ...(withDefinition ? { definition: definition(flag, rootOf(state.chain)) } : {}),
      tenantOverridable: flag.tenantOverridable,
      evaluation,
      ...(override
        ? { override: { value: override.value, setAt: override.setAt, setBy: override.setBy } }
        : {}),
      ...(target
        ? {
            target: {
              value: target.value,
              locked: target.locked === true,
              ...(target.expiresAt !== undefined ? { expiresAt: target.expiresAt } : {}),
            },
          }
        : {}),
    };
  }
  /** Settings input without the addressing fields. */
  const settingsInput = (input: object) => {
    const { tenantId: _tenant, key: _key, ...rest } = object(input);
    return rest;
  };
  async function audit(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    key: string,
    metadata: Record<string, Json>,
  ) {
    await ctx.events.audit(
      tx,
      principal,
      action,
      tenantId,
      resource(key),
      'allow',
      false,
      metadata,
    );
  }

  return {
    /**
     * The flags that reach the tenant, sorted by key, each with its value for the tenant, the reason, and this
     * tenant's own override and target. `definition` holds the settings of flags the tenant defines itself; internal
     * flags of ancestors are left out (root administrators see everything). `shadowed` lists flags this tenant
     * defines whose key an ancestor also defines: the ancestor's flag applies. Requires iam:features:read.
     */
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:features:read',
        'features',
        async ({ tx, tenant: realm, principal }) => {
          const root = await ctx.rootPrincipal(tx, principal);
          const state = await featureState(tx, await ctx.ancestry(tx, realm), ctx.now());
          const flags: FeatureFlagView[] = [];
          for (const flag of [...state.flags.values()].sort(byKey)) {
            const definedHere = flag.tenantId === realm.id;
            if (flag.internal && !definedHere && !root) continue;
            flags.push(await view(tx, state, flag, definedHere || root));
          }
          return {
            tenantId: realm.id,
            flags,
            shadowed: state.shadowed
              .filter((flag) => flag.tenantId === realm.id)
              .sort(byKey)
              .map((flag) => definition(flag, rootOf(state.chain))),
          };
        },
      ),
    /**
     * Defines a flag in the tenant: on the root tenant a platform flag, elsewhere a flag for the tenant's subtree.
     * Keys are unique per tenant and may not repeat a key an ancestor defines; at most 200 flags per tenant. Requires
     * iam:features:manage on `iam/features/{key}`; audited as `feature:create`.
     */
    create: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        key: string;
        description?: string;
        defaultValue?: boolean;
        rolloutPercentage?: number;
        tenantOverridable?: boolean;
        killSwitch?: boolean;
        internal?: boolean;
      },
    ) => {
      const key = featureKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:features:manage',
        resource(key),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const settings = featureSettings(settingsInput(input));
          const chain = await ctx.ancestry(tx, realm);
          for (const ancestor of chain.slice(1))
            if (
              (await tx.find(featureCollections.flags, { tenantId: ancestor.id, uniqueKey: key }))
                .length
            )
              throw new IamError(
                'CONFLICT',
                ancestor.parentId === null
                  ? 'A platform flag already uses this key'
                  : 'An enclosing tenant already defines a flag with this key',
                409,
              );
          const existing = await tx.find<FeatureFlag>(featureCollections.flags, {
            tenantId: realm.id,
          });
          if (existing.some((flag) => flag.key === key))
            throw new IamError('CONFLICT', 'A flag with this key already exists', 409);
          if (existing.length >= maxFeatureFlagsPerTenant)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can define at most ${maxFeatureFlagsPerTenant} feature flags`,
              409,
            );
          const now = ctx.now();
          const flag = await tx.insert<FeatureFlag>(featureCollections.flags, {
            id: id(),
            tenantId: realm.id,
            uniqueKey: key,
            key,
            ...settings,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          });
          await audit(tx, principal, 'feature:create', realm.id, key, settingsMetadata(flag));
          return definition(flag, rootOf(chain));
        },
      );
    },
    /**
     * Changes a flag's settings; fields left out keep their value and `null` clears `description` or
     * `rolloutPercentage`. Turning `killSwitch` on switches the flag off everywhere at once. Requires
     * iam:features:manage; audited as `feature:update` with the settings before and after.
     */
    update: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        key: string;
        description?: string | null;
        defaultValue?: boolean;
        rolloutPercentage?: number | null;
        tenantOverridable?: boolean;
        killSwitch?: boolean;
        internal?: boolean;
      },
    ) => {
      const key = featureKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:features:manage',
        resource(key),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const flag = await ownFlag(tx, realm.id, key);
          const settings = featureSettings(settingsInput(input), flag);
          const { description: _description, rolloutPercentage: _rollout, ...rest } = flag;
          const next = await tx.put<FeatureFlag>(featureCollections.flags, {
            ...rest,
            ...settings,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await audit(tx, principal, 'feature:update', realm.id, key, {
            before: settingsMetadata(flag),
            after: settingsMetadata(next),
          });
          return definition(next, rootOf(await ctx.ancestry(tx, realm)));
        },
      );
    },
    /**
     * Deletes a flag with every target and override set for it; code that still asks for the key gets `false`.
     * Requires iam:features:manage; audited as `feature:delete`.
     */
    delete: async (credential: CredentialInput, input: { tenantId: string; key: string }) => {
      const key = featureKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:features:manage',
        resource(key),
        async ({ tx, tenant: realm, principal }) => {
          const flag = await ownFlag(tx, realm.id, key);
          const entries = await tx.find<FeatureTarget>(featureCollections.targets, {
            flagId: flag.id,
          });
          for (const entry of entries) await tx.delete(featureCollections.targets, entry.id);
          await tx.delete(featureCollections.flags, flag.id);
          await audit(tx, principal, 'feature:delete', realm.id, key, {
            key,
            removedTargets: entries.length,
          });
          return { success: true as const, removedTargets: entries.length };
        },
      );
    },
    /**
     * Pins the flag's value for a tenant below the defining tenant (`tenantId`), and for that tenant's descendants
     * unless they have a closer target or override. `locked` also keeps tenants in that subtree from overriding;
     * `expiresAt` makes the target lapse by itself (a trial, a temporary block); `value: null` removes the target.
     * Requires iam:features:manage in the defining tenant; audited as `feature:target`.
     */
    setTarget: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        key: string;
        targetTenantId: string;
        value: boolean | null;
        locked?: boolean;
        expiresAt?: number;
        note?: string;
      },
    ) => {
      const key = featureKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:features:manage',
        resource(key),
        async ({ tx, tenant: definer, principal }): Promise<FeatureTargetView | null> => {
          const flag = await ownFlag(tx, definer.id, key);
          const target = await ctx.tenant(tx, text(input.targetTenantId, 'targetTenantId'));
          const chain = await ctx.ancestry(tx, target);
          if (target.id === definer.id || !chain.some((realm) => realm.id === definer.id))
            throw new IamError(
              'INVALID_INPUT',
              'targetTenantId must be a tenant below the one that defines the flag; use defaultValue for the tenant itself',
            );
          const existing = await entryAt(tx, target.id, flag, 'target');
          if (input.value === null) {
            if (existing) await tx.delete(featureCollections.targets, existing.id);
            await audit(tx, principal, 'feature:target', definer.id, key, {
              key,
              targetTenantId: target.id,
              value: null,
            });
            return null;
          }
          writable(target);
          if (typeof input.value !== 'boolean')
            throw new IamError('INVALID_INPUT', 'value must be a boolean or null');
          if (input.locked !== undefined && typeof input.locked !== 'boolean')
            throw new IamError('INVALID_INPUT', 'locked must be a boolean');
          const entry: FeatureTarget = {
            id: existing?.id ?? id(),
            tenantId: target.id,
            uniqueKey: `${flag.id}:target`,
            flagId: flag.id,
            key,
            definerId: definer.id,
            source: 'target',
            value: input.value,
            setAt: ctx.now(),
            setBy: principal.identity.id,
          };
          if (input.locked === true) entry.locked = true;
          if (input.expiresAt !== undefined) entry.expiresAt = ctx.bindingExpiry(input.expiresAt);
          if (input.note !== undefined) entry.note = text(input.note, 'note', 512).trim();
          if (existing) await tx.put(featureCollections.targets, entry);
          else await tx.insert(featureCollections.targets, entry);
          await audit(tx, principal, 'feature:target', definer.id, key, {
            key,
            targetTenantId: target.id,
            value: entry.value,
            locked: entry.locked === true,
            ...(entry.expiresAt !== undefined ? { expiresAt: entry.expiresAt } : {}),
          });
          return {
            id: entry.id,
            tenantId: target.id,
            tenantName: target.name,
            tenantStatus: target.status,
            source: 'target',
            value: entry.value,
            locked: entry.locked === true,
            ...(entry.expiresAt !== undefined ? { expiresAt: entry.expiresAt } : {}),
            active: true,
            ...(entry.note !== undefined ? { note: entry.note } : {}),
            setAt: entry.setAt,
            setBy: entry.setBy,
          };
        },
      );
    },
    /**
     * Every target the defining tenant set for the flag and every override tenants below it chose, newest first,
     * with the tenant's name and whether the entry currently counts. Requires iam:features:read.
     */
    listTargets: async (credential: CredentialInput, input: { tenantId: string; key: string }) => {
      const key = featureKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:features:read',
        resource(key),
        async ({ tx, tenant: definer }) => {
          const flag = await ownFlag(tx, definer.id, key);
          const now = ctx.now();
          const views: FeatureTargetView[] = [];
          for (const entry of await tx.find<FeatureTarget>(featureCollections.targets, {
            flagId: flag.id,
          })) {
            const realm = await tx.get<Tenant>('tenants', entry.tenantId);
            if (!realm) continue;
            const lapsed = entry.expiresAt !== undefined && entry.expiresAt <= now;
            views.push({
              id: entry.id,
              tenantId: realm.id,
              tenantName: realm.name,
              tenantStatus: realm.status,
              source: entry.source,
              value: entry.value,
              locked: entry.locked === true,
              ...(entry.expiresAt !== undefined ? { expiresAt: entry.expiresAt } : {}),
              active:
                !lapsed &&
                (entry.source === 'target' || (flag.tenantOverridable && !flag.internal)),
              ...(entry.note !== undefined ? { note: entry.note } : {}),
              setAt: entry.setAt,
              setBy: entry.setBy,
            });
          }
          return views.sort((a, b) => b.setAt - a.setAt || (a.id < b.id ? -1 : 1));
        },
      );
    },
    /**
     * The tenant's own choice for a flag an ancestor defines with `tenantOverridable`; it applies to the tenant and
     * its descendants unless they are closer to a decision. Refused with FEATURE_LOCKED when the flag does not allow
     * overrides or a locked target covers the tenant; `value: null` withdraws the choice (always allowed). Requires
     * iam:features:override on `iam/features/{key}`; audited as `feature:override`. Returns the new evaluation.
     */
    setOverride: async (
      credential: CredentialInput,
      input: { tenantId: string; key: string; value: boolean | null },
    ) => {
      const key = featureKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:features:override',
        resource(key),
        async ({ tx, tenant: realm, principal }): Promise<FeatureEvaluation> => {
          const chain = await ctx.ancestry(tx, realm);
          const state = await featureState(tx, chain, ctx.now());
          const flag = state.flags.get(key);
          if (!flag || (flag.internal && flag.tenantId !== realm.id))
            throw new IamError('NOT_FOUND', 'Feature flag not found', 404);
          if (flag.tenantId === realm.id)
            throw new IamError(
              'INVALID_INPUT',
              'This tenant defines the flag; change its settings with features.update',
            );
          const existing = await entryAt(tx, realm.id, flag, 'override');
          if (input.value === null) {
            if (existing) await tx.delete(featureCollections.targets, existing.id);
          } else {
            writable(realm);
            if (typeof input.value !== 'boolean')
              throw new IamError('INVALID_INPUT', 'value must be a boolean or null');
            if (!flag.tenantOverridable)
              throw new IamError(
                'FEATURE_LOCKED',
                'This flag does not let tenants choose their own value',
                409,
              );
            if (evaluateFlag(state, flag).locked)
              throw new IamError(
                'FEATURE_LOCKED',
                'A locked target decides this flag for the tenant',
                409,
              );
            const entry: FeatureTarget = {
              id: existing?.id ?? id(),
              tenantId: realm.id,
              uniqueKey: `${flag.id}:override`,
              flagId: flag.id,
              key,
              definerId: flag.tenantId,
              source: 'override',
              value: input.value,
              setAt: ctx.now(),
              setBy: principal.identity.id,
            };
            if (existing) await tx.put(featureCollections.targets, entry);
            else await tx.insert(featureCollections.targets, entry);
          }
          await audit(tx, principal, 'feature:override', realm.id, key, {
            key,
            value: input.value,
            definedBy: flag.tenantId,
          });
          return evaluateFlag(await featureState(tx, chain, ctx.now()), flag);
        },
      );
    },
    /**
     * `{ key: value }` for the flags that reach the tenant (internal flags of ancestors excluded), or for `keys` only
     * (at most 100; unknown keys are `false`). Needs only a session of the tenant, like the calls an application makes
     * to decide what to show; root administrators may evaluate any tenant. Not audited.
     */
    evaluate: async (
      credential: CredentialInput,
      input: { tenantId: string; keys?: string[] },
    ): Promise<{ tenantId: string; flags: Record<string, boolean> }> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const keys =
        input.keys === undefined ? undefined : strings(input.keys, 'keys').map(featureKey);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const realm = await ctx.tenant(tx, tenantId);
        if (principal.session.tenantId !== realm.id && !(await ctx.rootPrincipal(tx, principal)))
          throw new IamError(
            'ACCESS_DENIED',
            'Feature flags are evaluated from a session of their tenant',
            403,
          );
        const state = await featureState(tx, await ctx.ancestry(tx, realm), ctx.now());
        return {
          tenantId: realm.id,
          flags: Object.fromEntries(
            evaluateFeatures(state, { keys }).map((evaluation) => [
              evaluation.key,
              evaluation.value,
            ]),
          ),
        };
      });
    },
  };
}
