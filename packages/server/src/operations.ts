import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type Decision,
  type IamStore,
  type Identity,
  type Session,
  type Tenant,
} from '@better-iam/core';
import { resolvedManaged } from './catalog.js';
import type { ServerContext } from './context.js';
import type { ResourceRecord } from './models.js';
import { sodSnapshot, sodVerify } from './sod.js';
import { invariantSnapshot, invariantVerify } from './invariants.js';
import type {
  AccessibleResourcesRequest,
  AuthorizationCheck,
  AuthorizationRequest,
  BatchAuthorizationRequest,
} from './options.js';
import { integer, object, text } from './validation.js';

export interface MutationContext {
  tx: IamStore;
  principal: AuthenticatedPrincipal;
  tenant: Tenant;
}
export type BatchResult = AuthorizationCheck & { allowed: boolean; reason: string };

/**
 * Thrown by a mutation to refuse an operation its permission alone does not cover (a protected target, for example).
 * The mutation rolls back like any failure, and `operation` then records the refusal as a `deny` audit event, the
 * way an authorization denial is recorded. It surfaces as `ACCESS_DENIED` (403).
 */
export class OperationDenied extends IamError {
  constructor(message = 'Access denied') {
    super('ACCESS_DENIED', message, 403);
  }
}

export interface OperationService {
  /**
   * The transactional envelope of every provisioning call: authenticate, re-validate the principal, authorize
   * `action` on `iam/{resourceId}`, run the mutation, and append one audit event. A denial commits only its audit record.
   */
  operation<T>(
    credential: CredentialInput,
    tenantId: string,
    action: string,
    resourceId: string,
    fn: (ctx: MutationContext) => Promise<T>,
    rootOnly?: boolean,
  ): Promise<T>;
  /** A decision that records denials and root overrides, with matched statements stripped for callers. */
  recordedDecision(
    tx: IamStore,
    current: AuthenticatedPrincipal,
    request: AuthorizationRequest,
  ): Promise<Decision>;
  authorize(request: AuthorizationRequest): Promise<Decision>;
  /** Evaluates up to 50 checks for one tenant in a single transaction. Results are advisory UI state, not enforcement. */
  authorizeMany(request: BatchAuthorizationRequest): Promise<{ results: BatchResult[] }>;
  /** The batch evaluation behind `authorizeMany`, without the observability span. */
  evaluateMany(request: BatchAuthorizationRequest): Promise<{ results: BatchResult[] }>;
  /**
   * Reverse query for list pages: the registered resources of one managed type that the caller may perform an action on.
   * Grants and boundaries are loaded once and evaluated against every registration; results are advisory like authorizeMany.
   */
  listAccessible(
    request: AccessibleResourcesRequest,
  ): Promise<{ resources: ResourceRecord[]; total: number }>;
  /** The reverse query behind `listAccessible`, without the observability span. */
  queryAccessible(
    request: AccessibleResourcesRequest,
  ): Promise<{ resources: ResourceRecord[]; total: number }>;
  requireAccess(request: AuthorizationRequest): Promise<void>;
  /** Dispatches a plugin endpoint through the same validated, transactional envelope as built-in operations. */
  callPlugin(
    credential: CredentialInput,
    input: { pluginId: string; path: string; tenantId: string; input?: unknown },
  ): Promise<unknown>;
}

const byResourceKey = (a: ResourceRecord, b: ResourceRecord) =>
  a.uniqueKey! < b.uniqueKey! ? -1 : a.uniqueKey! > b.uniqueKey! ? 1 : 0;

export function createOperations(ctx: ServerContext): OperationService {
  const { store, plugins, catalog } = ctx;
  /**
   * The administrator behind an impersonation ("view as") session, acting through their own source session; undefined
   * for every other principal. currentPrincipal has already checked that the source session and identity are live.
   */
  async function impersonator(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
  ): Promise<AuthenticatedPrincipal | undefined> {
    const actorId = principal.session.impersonatorId;
    if (!actorId) return undefined;
    const sourceId = principal.session.impersonatorSessionId;
    const session = sourceId ? await tx.get<Session>('sessions', sourceId) : undefined;
    const identity = await tx.get<Identity>('identities', actorId);
    if (!session || !identity || session.identityId !== identity.id || identity.status !== 'active')
      throw new IamError('UNAUTHENTICATED', 'Impersonation has ended', 401);
    return { identity, session };
  }
  /**
   * One authorization decision. "View as" never exceeds the administrator's own rights: an impersonation session is
   * allowed only what both the member and the impersonating administrator may do, so support staff cannot use a more
   * privileged member's session to act, or to grant themselves lasting access, beyond their own role.
   */
  async function decide(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    request: AuthorizationRequest,
    internalResource = false,
  ): Promise<Decision> {
    const decision = await ctx.decisions.decide(tx, principal, request, internalResource);
    const actor = decision.allowed ? await impersonator(tx, principal) : undefined;
    if (!actor) return decision;
    const own = await ctx.decisions.decide(tx, actor, request, internalResource);
    return own.allowed ? decision : { allowed: false, reason: 'IMPERSONATOR_DENIED', matched: [] };
  }
  /**
   * Runs an operation's transaction. A mutation that refuses with `OperationDenied` is rolled back like any failure;
   * the refusal is then recorded in its own transaction as a `deny` event, like an authorization denial.
   */
  async function refusable<T>(
    principal: AuthenticatedPrincipal,
    tenantId: string,
    action: string,
    resourceId: string,
    run: (tx: IamStore) => Promise<T>,
  ): Promise<T> {
    try {
      return await store.transaction(run);
    } catch (error) {
      if (error instanceof OperationDenied)
        try {
          await store.transaction((tx) =>
            ctx.events.audit(tx, principal, action, tenantId, resourceId, 'deny'),
          );
        } catch {
          /* Bookkeeping never masks the refusal. */
        }
      throw error;
    }
  }
  const service: OperationService = {
    operation(credential, tenantId, action, resourceId, fn, rootOnly = false) {
      return ctx.observe.span('operation', action, tenantId, async () => {
        const authenticated = await ctx.principals.authenticate(credential);
        const outcome = await refusable(authenticated, tenantId, action, resourceId, async (tx) => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          const target = await ctx.tenant(tx, tenantId);
          const decision = await decide(
            tx,
            principal,
            { tenantId, action, resource: { type: 'iam', id: resourceId } },
            true,
          );
          if (!decision.allowed || (rootOnly && !(await ctx.rootPrincipal(tx, principal)))) {
            await ctx.events.audit(tx, principal, action, tenantId, resourceId, 'deny');
            return { denied: true as const };
          }
          const hook = { store: tx, principal, tenantId, action, resourceId };
          for (const plugin of plugins) await plugin.hooks?.beforeOperation?.(hook);
          const separation = await sodSnapshot(ctx, tx, tenantId, action);
          const guardrails = await invariantSnapshot(ctx, tx, tenantId, action);
          const value = await fn({ tx, principal, tenant: target });
          await sodVerify(ctx, tx, tenantId, separation);
          await invariantVerify(ctx, tx, tenantId, guardrails);
          for (const plugin of plugins)
            await plugin.hooks?.afterOperation?.({ ...hook, result: value });
          await ctx.events.audit(
            tx,
            principal,
            action,
            tenantId,
            resourceId,
            'allow',
            decision.reason === 'ROOT_OVERRIDE',
          );
          return {
            denied: false as const,
            value,
            rootOverride: decision.reason === 'ROOT_OVERRIDE',
          };
        });
        if (outcome.denied) throw new IamError('ACCESS_DENIED', 'Access denied', 403);
        // Access usage: what the person used through their grants, not a root override or what an impersonating
        // administrator did as them. Recorded after the commit.
        if (!authenticated.session.impersonatorId && !outcome.rootOverride)
          ctx.usage.record(tenantId, authenticated.identity.id, action);
        return outcome.value;
      });
    },
    async recordedDecision(tx, current, request) {
      const decision = await decide(tx, current, request);
      if (
        decision.allowed &&
        decision.reason !== 'ROOT_OVERRIDE' &&
        !current.session.impersonatorId
      )
        ctx.usage.record(request.tenantId, current.identity.id, request.action);
      if (decision.reason === 'ROOT_OVERRIDE' || !decision.allowed)
        await ctx.events.audit(
          tx,
          current,
          request.action,
          request.tenantId,
          request.resource.id,
          decision.allowed ? 'allow' : 'deny',
          decision.reason === 'ROOT_OVERRIDE',
        );
      return {
        allowed: decision.allowed,
        reason: decision.allowed ? decision.reason : 'ACCESS_DENIED',
        matched: [],
      };
    },
    authorize(request) {
      return ctx.observe.span(
        'authorize',
        typeof request.action === 'string' ? request.action : 'invalid',
        typeof request.tenantId === 'string' ? request.tenantId : undefined,
        async () => {
          const principal = await ctx.principals.authenticate(request);
          return store.transaction(async (tx) =>
            service.recordedDecision(
              tx,
              await ctx.principals.currentPrincipal(tx, principal),
              request,
            ),
          );
        },
        (decision) => ({ outcome: decision.allowed ? 'ok' : 'denied', code: decision.reason }),
      );
    },
    authorizeMany(request) {
      return ctx.observe.span(
        'authorizeMany',
        'authorizeMany',
        typeof request.tenantId === 'string' ? request.tenantId : undefined,
        () => service.evaluateMany(request),
      );
    },
    async evaluateMany(request) {
      const tenantId = text(request.tenantId, 'tenantId');
      if (
        !Array.isArray(request.checks) ||
        request.checks.length === 0 ||
        request.checks.length > 50
      )
        throw new IamError('INVALID_INPUT', 'Provide 1-50 authorization checks');
      const checks: AuthorizationCheck[] = request.checks.map((check) => {
        const item = object(check);
        const resource = object(item.resource);
        return {
          action: text(item.action, 'action'),
          resource: {
            type: text(resource.type, 'resource type'),
            id: text(resource.id, 'resource id'),
          },
        };
      });
      const principal = await ctx.principals.authenticate(request);
      return store.transaction(async (tx) => {
        const current = await ctx.principals.currentPrincipal(tx, principal);
        const results: BatchResult[] = [];
        for (const check of checks) {
          const decision = await service.recordedDecision(tx, current, { tenantId, ...check });
          results.push({ ...check, allowed: decision.allowed, reason: decision.reason });
        }
        return { results };
      });
    },
    listAccessible(request) {
      return ctx.observe.span(
        'listAccessible',
        typeof request.action === 'string' ? request.action : 'invalid',
        typeof request.tenantId === 'string' ? request.tenantId : undefined,
        () => service.queryAccessible(request),
      );
    },
    async queryAccessible(request) {
      const tenantId = text(request.tenantId, 'tenantId');
      const action = text(request.action, 'action');
      const type = text(request.type, 'resource type', 64);
      const limit = integer(request.limit ?? 100, 'limit', 1, 1000);
      const offset = integer(request.offset ?? 0, 'offset', 0, 1000000);
      const principal = await ctx.principals.authenticate(request);
      return store.transaction(async (tx) => {
        const current = await ctx.principals.currentPrincipal(tx, principal);
        const target = await ctx.tenant(tx, tenantId);
        if (!(await catalog.knownAction(tx, target.id, action)))
          throw new IamError('INVALID_ACTION', `Unknown action ${action}`);
        const definition = await catalog.managedDefinition(tx, target.id, type);
        const prepared = await ctx.decisions.prepareDecision(tx, current, target, action);
        // An impersonation session lists only what the administrator behind it could reach too.
        const actor = await impersonator(tx, current);
        const own = actor && (await ctx.decisions.prepareDecision(tx, actor, target, action));
        const allows = (evaluator: typeof prepared, item: ResourceRecord) =>
          ('fixed' in evaluator ? evaluator.fixed : evaluator.evaluate(resolvedManaged(item)))
            .allowed;
        const records = (
          await tx.find<ResourceRecord>('resources', { tenantId: target.id, type: definition.name })
        ).sort(byResourceKey);
        const accessible = records.filter(
          (item) => allows(prepared, item) && (!own || allows(own, item)),
        );
        // Listing what one may act on is using the action (not for root overrides or impersonation).
        if (
          accessible.length &&
          !current.session.impersonatorId &&
          !('fixed' in prepared && prepared.fixed.reason === 'ROOT_OVERRIDE')
        )
          ctx.usage.record(target.id, current.identity.id, action);
        return { resources: accessible.slice(offset, offset + limit), total: accessible.length };
      });
    },
    async requireAccess(request) {
      if (!(await service.authorize(request)).allowed)
        throw new IamError('ACCESS_DENIED', 'Access denied', 403);
    },
    async callPlugin(credential, input) {
      const pluginId = text(input.pluginId, 'pluginId');
      const path = text(input.path, 'path').replace(/^\//, '');
      const tenantId = text(input.tenantId, 'tenantId');
      const endpoint = plugins
        .find((plugin) => plugin.id === pluginId)
        ?.endpoints?.find(
          (candidate) => candidate.method === 'POST' && candidate.path.replace(/^\//, '') === path,
        );
      if (!endpoint) throw new IamError('NOT_FOUND', 'Endpoint not found', 404);
      const raw = object(input.input ?? {});
      if (Object.hasOwn(raw, 'tenantId') && raw.tenantId !== tenantId)
        throw new IamError('INVALID_INPUT', 'Plugin input tenant does not match request scope');
      const validated = object(endpoint.validate({ ...raw, tenantId }));
      if (Object.hasOwn(validated, 'tenantId') && validated.tenantId !== tenantId)
        throw new IamError('INVALID_INPUT', 'Plugin validation changed tenant scope');
      return service.operation(
        credential,
        tenantId,
        endpoint.action,
        tenantId,
        ({ tx, principal }) =>
          endpoint.handler(
            {
              store: tx,
              principal,
              tenantId,
              deliver: (delivery) => ctx.auth.enqueueDelivery(tx, { ...delivery, tenantId }),
            },
            validated,
          ),
      );
    },
  };
  return service;
}
