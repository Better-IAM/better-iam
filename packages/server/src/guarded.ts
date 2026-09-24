import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type Decision,
  type IamStore,
  type Json,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { PreparedDecision } from './decisions.js';
import { useConfirmation } from './delegations.js';
import { OperationDenied } from './operations.js';
import { text } from './validation.js';

/**
 * The authorization envelope for resources the platform itself owns and describes with attributes (KMS keys,
 * certificate authorities): the `operation` envelope of operations.ts, except that the decision sees the resource's
 * attributes (`resource.{name}`), a module may add a fallback allow path (KMS grants), and one call may need several
 * decisions (every name on a certificate). Sessions that view as someone else are refused outright.
 */

export interface GuardTarget {
  /** The audited resource, without the `iam/` prefix (`kms/{keyId}`, `pki/{authorityId}`). */
  resourceId: string;
  /** Presented to policies as `resource.{name}`. */
  attributes: Record<string, unknown>;
}

export interface GuardCall<Target extends GuardTarget = GuardTarget> {
  tx: IamStore;
  principal: AuthenticatedPrincipal;
  tenant: Tenant;
  /** Added to the call's audit event. */
  metadata: Record<string, Json>;
  /** Evaluates another action or target for the caller by policy alone (no fallback). */
  allowed(action: string, target: Target | GuardTarget): Promise<boolean>;
}

export interface GuardOptions<Target extends GuardTarget> {
  /**
   * A second way to allow a call no policy decides: consulted only when the policy decision's reason is
   * `NO_APPLICABLE_GRANT` (so boundaries, session policies, key scopes and explicit denies have all passed). Returns
   * audit metadata naming what allowed the call, or undefined.
   */
  fallback?: (
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    target: Target,
  ) => Promise<Record<string, Json> | undefined>;
  /** Audit metadata every allowed call of a target starts with. */
  describe?: (target: Target) => Record<string, Json>;
  /** Error codes thrown after authorization that are recorded as a denied call (with `reason`). */
  recordedFailures?: Record<string, string>;
  /** What plugin `afterOperation` hooks see of a result (strip plaintexts and tokens); the result itself otherwise. */
  hookResult?: (value: unknown) => unknown;
}

export function createGuard<Target extends GuardTarget>(
  ctx: ServerContext,
  /** The tenant-wide resource (`kms`, `pki`): where refusals before any lookup are recorded. */
  collection: string,
  options: GuardOptions<Target> = {},
) {
  async function decide(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    action: string,
    target: Target | GuardTarget,
    useFallback = true,
    /** Prepared decisions by action, reused across the several decisions of one call. */
    cache?: Map<string, PreparedDecision>,
  ): Promise<Decision & { note?: Record<string, Json> }> {
    if (principal.session.impersonatorId)
      return { allowed: false, reason: 'IMPERSONATION_RESTRICTED', matched: [] };
    let prepared = cache?.get(action);
    if (!prepared) {
      prepared = await ctx.decisions.prepareDecision(tx, principal, tenant, action);
      cache?.set(action, prepared);
    }
    const decision =
      'fixed' in prepared
        ? prepared.fixed
        : prepared.evaluate(
            {
              tenantId: tenant.id,
              type: 'iam',
              id: target.resourceId,
              attributes: target.attributes,
            },
            action,
          );
    if (
      decision.allowed ||
      !useFallback ||
      !options.fallback ||
      decision.reason !== 'NO_APPLICABLE_GRANT'
    )
      return decision;
    const note = await options.fallback(tx, principal, action, target as Target);
    return note ? { allowed: true, reason: 'FALLBACK', matched: [], note } : decision;
  }

  /**
   * Authenticate, locate the target, decide, run, audit. A denial commits only its audit record; a refusal inside
   * the call (`OperationDenied`) or a recorded failure after authorization is audited as `deny` once the call's own
   * transaction has rolled back.
   */
  function run<T>(
    credential: CredentialInput,
    tenantId: string,
    action: string | ((target: Target) => string),
    /** Finds the target once the caller is known to belong to the tenant (it may depend on who calls). */
    locate: (tx: IamStore, principal: AuthenticatedPrincipal) => Promise<Target>,
    fn: (call: GuardCall<Target>, target: Target) => Promise<T>,
  ): Promise<T> {
    const label = typeof action === 'string' ? action : 'iam:call';
    return ctx.observe.span('operation', label, tenantId, async () => {
      const authenticated = await ctx.principals.authenticate(credential);
      let actor: AuthenticatedPrincipal | undefined;
      let resolvedAction = label;
      let resourceId = '';
      try {
        const outcome = await ctx.store.transaction(async (tx) => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          const tenant = await ctx.tenant(tx, text(tenantId, 'tenantId'));
          // Callers from another tenant (and "view as" sessions) are refused before anything is looked up, so
          // they learn nothing about which resources exist.
          if (
            principal.session.impersonatorId ||
            (principal.session.tenantId !== tenant.id && !(await ctx.rootPrincipal(tx, principal)))
          ) {
            resourceId = collection;
            await ctx.events.audit(tx, principal, label, tenant.id, collection, 'deny', false, {
              reason: principal.session.impersonatorId ? 'impersonation' : 'tenant',
            });
            return { denied: true as const };
          }
          const target = await locate(tx, principal);
          resolvedAction = typeof action === 'string' ? action : action(target);
          resourceId = target.resourceId;
          const prepared = new Map<string, PreparedDecision>();
          const decision = await decide(
            tx,
            principal,
            tenant,
            resolvedAction,
            target,
            true,
            prepared,
          );
          if (!decision.allowed) {
            // A refusal names what was asked for (a profile, a purpose) as an allowed call would.
            const refused: Record<string, Json> = {
              ...options.describe?.(target),
              ...(decision.reason === 'IMPERSONATION_RESTRICTED'
                ? { reason: 'impersonation' }
                : {}),
            };
            await ctx.events.audit(
              tx,
              principal,
              resolvedAction,
              tenant.id,
              target.resourceId,
              'deny',
              false,
              Object.keys(refused).length ? refused : undefined,
            );
            return { denied: true as const };
          }
          // A call a delegation holds back uses up the person's one confirmation (rolled back if the call fails).
          await useConfirmation(tx, principal, resolvedAction, 'iam', target.resourceId, ctx.now());
          actor = principal;
          const hook = {
            store: tx,
            principal,
            tenantId: tenant.id,
            action: resolvedAction,
            resourceId: target.resourceId,
          };
          for (const plugin of ctx.plugins) await plugin.hooks?.beforeOperation?.(hook);
          const metadata: Record<string, Json> = {
            ...options.describe?.(target),
            ...decision.note,
          };
          const value = await fn(
            {
              tx,
              principal,
              tenant,
              metadata,
              allowed: async (other, otherTarget) =>
                (await decide(tx, principal, tenant, other, otherTarget, false, prepared)).allowed,
            },
            target,
          );
          const result = options.hookResult ? options.hookResult(value) : value;
          for (const plugin of ctx.plugins)
            await plugin.hooks?.afterOperation?.({ ...hook, result });
          await ctx.events.audit(
            tx,
            principal,
            resolvedAction,
            tenant.id,
            target.resourceId,
            'allow',
            decision.reason === 'ROOT_OVERRIDE',
            Object.keys(metadata).length ? metadata : undefined,
          );
          return {
            denied: false as const,
            value,
            rootOverride: decision.reason === 'ROOT_OVERRIDE',
          };
        });
        if (outcome.denied) throw new IamError('ACCESS_DENIED', 'Access denied', 403);
        if (!authenticated.session.impersonatorId && !outcome.rootOverride)
          ctx.usage.record(tenantId, authenticated.identity.id, resolvedAction);
        return outcome.value;
      } catch (error) {
        const reason =
          error instanceof OperationDenied
            ? 'refused'
            : error instanceof IamError
              ? options.recordedFailures?.[error.code]
              : undefined;
        // `actor` is set only once the call was authorized.
        if (actor && reason)
          try {
            await ctx.store.transaction((tx) =>
              ctx.events.audit(tx, actor!, resolvedAction, tenantId, resourceId, 'deny', false, {
                reason,
              }),
            );
          } catch {
            /* Bookkeeping never masks the failure. */
          }
        throw error;
      }
    });
  }

  /**
   * For list pages: the targets the caller may perform `action` on, decided per target (policies only) with one
   * prepared decision. Refuses (and audits) callers the tenant refuses outright; otherwise audits one allowed event
   * on `resourceId` with the number listed.
   */
  async function visible<Item>(
    credential: CredentialInput,
    tenantId: string,
    action: string,
    resourceId: string,
    load: (tx: IamStore, tenant: Tenant) => Promise<Array<{ item: Item; target: GuardTarget }>>,
  ): Promise<Item[]> {
    return ctx.observe.span('operation', action, tenantId, async () => {
      const authenticated = await ctx.principals.authenticate(credential);
      const outcome = await ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const tenant = await ctx.tenant(tx, text(tenantId, 'tenantId'));
        const refuse = async () => {
          await ctx.events.audit(tx, principal, action, tenant.id, resourceId, 'deny');
          return { denied: true as const };
        };
        if (principal.session.impersonatorId) return refuse();
        const prepared = await ctx.decisions.prepareDecision(tx, principal, tenant, action);
        if ('fixed' in prepared && !prepared.fixed.allowed) return refuse();
        const items = (await load(tx, tenant))
          .filter(
            ({ target }) =>
              'fixed' in prepared ||
              prepared.evaluate(
                {
                  tenantId: tenant.id,
                  type: 'iam',
                  id: target.resourceId,
                  attributes: target.attributes,
                },
                action,
              ).allowed,
          )
          .map(({ item }) => item);
        await ctx.events.audit(
          tx,
          principal,
          action,
          tenant.id,
          resourceId,
          'allow',
          'fixed' in prepared && prepared.fixed.reason === 'ROOT_OVERRIDE',
          { listed: items.length },
        );
        return { denied: false as const, items };
      });
      if (outcome.denied) throw new IamError('ACCESS_DENIED', 'Access denied', 403);
      return outcome.items;
    });
  }

  return { run, decide, visible };
}
