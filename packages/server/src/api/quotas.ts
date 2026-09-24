import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Session,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { Group } from '../models.js';
import {
  QuotaExceededError,
  alertThresholds,
  consumeQuota,
  quotaCollections,
  quotaLimits,
  quotaName,
  quotaThrottle,
  quotaWindow,
  subjectOf,
  timeZone,
  type QuotaAssignment,
  type QuotaCounter,
  type QuotaDecision,
  type QuotaLimit,
  type QuotaLimitStatus,
  type QuotaPlan,
  type QuotaSubjectType,
  type QuotaThrottle,
} from '../quotas.js';
import { id } from '../utils.js';
import { integer, text } from '../validation.js';

/** A plan as its managers see it. */
export interface QuotaPlanView {
  name: string;
  description?: string;
  meter: string;
  throttle?: QuotaThrottle;
  limits: QuotaLimit[];
  scope: QuotaPlan['scope'];
  default: boolean;
  priority: number;
  timeZone: string;
  alertThresholds: number[];
  /** How many subjects are assigned the plan directly. */
  assignments: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

export interface QuotaAssignmentView {
  plan: string;
  meter: string;
  subjectType: QuotaSubjectType;
  subjectId: string;
  /** The identity's or group's name; for an API key, its label. */
  subjectName?: string;
  createdAt: number;
  createdBy: string;
}

/** One subject's use of a plan in the current windows. */
export interface QuotaUsageView {
  subject: string;
  subjectName?: string;
  limits: QuotaLimitStatus[];
  /** When a window of this subject first refused, if it did. */
  exceededAt?: number;
}

export interface QuotaConsumeRequest extends CredentialInput {
  tenantId: string;
  meter: string;
  /** Units to count (default 1). */
  cost?: number;
}

const planResource = (name: string) => `quotas/${name}`;

function planView(plan: QuotaPlan, assignments: number): QuotaPlanView {
  return {
    name: plan.name,
    ...(plan.description !== undefined ? { description: plan.description } : {}),
    meter: plan.meter,
    ...(plan.throttle ? { throttle: plan.throttle } : {}),
    limits: plan.limits,
    scope: plan.scope,
    default: plan.default,
    priority: plan.priority,
    timeZone: plan.timeZone,
    alertThresholds: plan.alertThresholds,
    assignments,
    createdAt: plan.createdAt,
    createdBy: plan.createdBy,
    updatedAt: plan.updatedAt,
    updatedBy: plan.updatedBy,
  };
}

function cost(value: unknown): number {
  return value === undefined ? 1 : integer(value, 'cost', 1, 1_000_000_000);
}

async function findPlan(tx: IamStore, tenantId: string, name: string): Promise<QuotaPlan> {
  const plan = (await tx.find<QuotaPlan>(quotaCollections.plans, { tenantId, uniqueKey: name }))[0];
  if (!plan) throw new IamError('NOT_FOUND', 'Quota plan not found', 404);
  return plan;
}

function writable(realm: Tenant): void {
  if (realm.status === 'deleted')
    throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
}

/** The consumption of the caller's own session, which must belong to the tenant. */
async function callerDecision(
  ctx: ServerContext,
  credential: CredentialInput,
  input: { tenantId: unknown; meter: unknown; cost?: unknown },
  dryRun: boolean,
): Promise<QuotaDecision> {
  const tenantId = text(input.tenantId, 'tenantId');
  const meter = quotaName(input.meter, 'meter');
  const units = dryRun ? 0 : cost(input.cost);
  const authenticated = await ctx.principals.authenticate(credential);
  return ctx.store.transaction(async (tx) => {
    const principal = await ctx.principals.currentPrincipal(tx, authenticated);
    const realm = await ctx.tenant(tx, tenantId);
    if (principal.session.tenantId !== realm.id)
      throw new IamError('ACCESS_DENIED', 'Quotas count in the session’s own tenant', 403);
    return consumeQuota(
      ctx,
      tx,
      subjectOf(principal),
      meter,
      units,
      (store, action, metadata) =>
        ctx.events.audit(
          store,
          principal,
          action,
          realm.id,
          planResource(String(metadata.plan)),
          action === 'quota:exceeded' ? 'deny' : 'allow',
          false,
          metadata,
        ),
      dryRun,
    );
  });
}

/**
 * API usage plans and quotas. Managers define plans (`iam:quotas:manage` on `iam/quotas/{plan}`) and assign them to
 * API keys, agents, people or groups, or make one the tenant's default for its meter; applications count use with
 * `iam.quotas.consume` (or `quotas.consume` over HTTP with the caller's own credential) and show callers their
 * remaining quota with `quotas.status`.
 */
export function createQuotasApi(ctx: ServerContext) {
  const { operation } = ctx.operations;

  async function audit(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    name: string,
    metadata: Record<string, Json>,
  ) {
    await ctx.events.audit(tx, principal, action, tenantId, planResource(name), 'allow', false, metadata);
  }

  async function assignmentCount(tx: IamStore, plan: QuotaPlan) {
    return (await tx.find(quotaCollections.assignments, { tenantId: plan.tenantId, planId: plan.id })).length;
  }

  /** The label of an assignment's subject. */
  async function subjectName(tx: IamStore, tenantId: string, type: QuotaSubjectType, subjectId: string) {
    if (type === 'group') {
      const group = await tx.get<Group>('groups', subjectId);
      return group?.tenantId === tenantId ? group.name : undefined;
    }
    if (type === 'identity') {
      const identity = await tx.get<Identity>('identities', subjectId);
      return identity?.tenantId === tenantId ? identity.name : undefined;
    }
    const session = await tx.get<Session>('sessions', subjectId);
    const label = (session as { name?: unknown } | undefined)?.name;
    return session?.tenantId === tenantId && typeof label === 'string' ? label : undefined;
  }

  /** Refuses subjects outside the tenant, deleted identities, and sessions that are not API keys. */
  async function validSubject(
    tx: IamStore,
    tenantId: string,
    type: unknown,
    subjectId: unknown,
  ): Promise<{ subjectType: QuotaSubjectType; subjectId: string }> {
    const subject = text(subjectId, 'subjectId');
    if (type === 'identity') {
      await ctx.activeIdentity(tx, subject, tenantId);
      return { subjectType: 'identity', subjectId: subject };
    }
    if (type === 'group') {
      await ctx.scoped<Group>(tx, 'groups', subject, tenantId);
      return { subjectType: 'group', subjectId: subject };
    }
    if (type === 'apiKey') {
      const session = await tx.get<Session>('sessions', subject);
      if (!session || session.tenantId !== tenantId || session.kind !== 'api-key')
        throw new IamError('NOT_FOUND', 'API key not found', 404);
      return { subjectType: 'apiKey', subjectId: subject };
    }
    throw new IamError('INVALID_INPUT', 'subjectType must be apiKey, identity or group');
  }

  return {
    /**
     * Defines a plan for a meter: a `throttle` (`ratePerSecond`, `burst`), period `limits` (minute to month), or both.
     * `default: true` makes it the plan for everyone in the tenant without one of their own (one per meter);
     * `scope: 'tenant'` makes everyone it covers share one set of counters. Requires iam:quotas:manage; audited as
     * `quota:plan-create`.
     */
    createPlan: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        meter: string;
        description?: string;
        throttle?: QuotaThrottle;
        limits?: QuotaLimit[];
        scope?: QuotaPlan['scope'];
        default?: boolean;
        priority?: number;
        timeZone?: string;
        alertThresholds?: number[];
      },
    ): Promise<QuotaPlanView> => {
      const name = quotaName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:quotas:manage',
        planResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          if ((await tx.find(quotaCollections.plans, { tenantId: realm.id, uniqueKey: name })).length)
            throw new IamError('CONFLICT', 'A plan with this name already exists', 409);
          const meter = quotaName(input.meter, 'meter');
          const throttle = quotaThrottle(input.throttle);
          const limits = quotaLimits(input.limits);
          if (!throttle && !limits.length)
            throw new IamError('INVALID_INPUT', 'A plan needs a throttle, limits, or both');
          if (input.scope !== undefined && input.scope !== 'subject' && input.scope !== 'tenant')
            throw new IamError('INVALID_INPUT', 'scope must be subject or tenant');
          if (input.default !== undefined && typeof input.default !== 'boolean')
            throw new IamError('INVALID_INPUT', 'default must be a boolean');
          if (
            input.default === true &&
            (await tx.find(quotaCollections.plans, { tenantId: realm.id, meter, default: true })).length
          )
            throw new IamError('CONFLICT', `The tenant already has a default plan for ${meter}`, 409);
          const now = ctx.now();
          const plan: QuotaPlan = {
            id: id(),
            tenantId: realm.id,
            uniqueKey: name,
            name,
            meter,
            ...(throttle ? { throttle } : {}),
            limits,
            scope: input.scope ?? 'subject',
            default: input.default === true,
            priority: input.priority === undefined ? 0 : integer(input.priority, 'priority', -1000, 1000),
            timeZone: timeZone(input.timeZone),
            alertThresholds: alertThresholds(input.alertThresholds),
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          };
          if (input.description !== undefined)
            plan.description = text(input.description, 'description', 512).trim();
          await tx.insert(quotaCollections.plans, plan);
          await audit(tx, principal, 'quota:plan-create', realm.id, name, {
            name,
            meter,
            limits: plan.limits.map((limit) => `${limit.limit}/${limit.period}`),
            throttle: plan.throttle ? `${plan.throttle.ratePerSecond}/s burst ${plan.throttle.burst}` : null,
            default: plan.default,
          });
          return planView(plan, 0);
        },
      );
    },

    /**
     * Changes a plan: fields left out keep their value; `throttle: null` and `description: null` clear them; `limits`
     * replaces the whole list. The meter cannot change. Counters in progress keep counting under the new limits.
     * Requires iam:quotas:manage; audited as `quota:plan-update`.
     */
    updatePlan: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        description?: string | null;
        throttle?: QuotaThrottle | null;
        limits?: QuotaLimit[];
        scope?: QuotaPlan['scope'];
        default?: boolean;
        priority?: number;
        timeZone?: string;
        alertThresholds?: number[];
      },
    ): Promise<QuotaPlanView> => {
      const name = quotaName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:quotas:manage',
        planResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const plan = await findPlan(tx, realm.id, name);
          const { description: _description, throttle: _throttle, ...rest } = plan;
          const next: QuotaPlan = { ...rest, updatedAt: ctx.now(), updatedBy: principal.identity.id };
          if (input.description === undefined) {
            if (plan.description !== undefined) next.description = plan.description;
          } else if (input.description !== null)
            next.description = text(input.description, 'description', 512).trim();
          const throttle = input.throttle === undefined ? plan.throttle : quotaThrottle(input.throttle);
          if (throttle) next.throttle = throttle;
          if (input.limits !== undefined) next.limits = quotaLimits(input.limits);
          if (!next.throttle && !next.limits.length)
            throw new IamError('INVALID_INPUT', 'A plan needs a throttle, limits, or both');
          if (input.scope !== undefined) {
            if (input.scope !== 'subject' && input.scope !== 'tenant')
              throw new IamError('INVALID_INPUT', 'scope must be subject or tenant');
            next.scope = input.scope;
          }
          if (input.default !== undefined) {
            if (typeof input.default !== 'boolean')
              throw new IamError('INVALID_INPUT', 'default must be a boolean');
            if (
              input.default &&
              !plan.default &&
              (
                await tx.find(quotaCollections.plans, {
                  tenantId: realm.id,
                  meter: plan.meter,
                  default: true,
                })
              ).length
            )
              throw new IamError('CONFLICT', `The tenant already has a default plan for ${plan.meter}`, 409);
            next.default = input.default;
          }
          if (input.priority !== undefined) next.priority = integer(input.priority, 'priority', -1000, 1000);
          if (input.timeZone !== undefined) next.timeZone = timeZone(input.timeZone);
          if (input.alertThresholds !== undefined)
            next.alertThresholds = alertThresholds(input.alertThresholds);
          const stored = await tx.put<QuotaPlan>(quotaCollections.plans, next);
          await audit(tx, principal, 'quota:plan-update', realm.id, name, {
            name,
            limits: stored.limits.map((limit) => `${limit.limit}/${limit.period}`),
            throttle: stored.throttle
              ? `${stored.throttle.ratePerSecond}/s burst ${stored.throttle.burst}`
              : null,
            default: stored.default,
            scope: stored.scope,
          });
          return planView(stored, await assignmentCount(tx, stored));
        },
      );
    },

    /** Deletes a plan with its assignments and counters. Requires iam:quotas:manage; audited as `quota:plan-delete`. */
    deletePlan: (credential: CredentialInput, input: { tenantId: string; name: string }) => {
      const name = quotaName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:quotas:manage',
        planResource(name),
        async ({ tx, tenant: realm, principal }) => {
          const plan = await findPlan(tx, realm.id, name);
          let removed = 0;
          for (const collection of [quotaCollections.assignments, quotaCollections.counters])
            for (const record of await tx.find(collection, { tenantId: realm.id, planId: plan.id })) {
              await tx.delete(collection, record.id);
              if (collection === quotaCollections.assignments) removed++;
            }
          await tx.delete(quotaCollections.plans, plan.id);
          await audit(tx, principal, 'quota:plan-delete', realm.id, name, { name, assignments: removed });
          return { deleted: true as const, assignments: removed };
        },
      );
    },

    /** Every plan of the tenant, by name. Requires iam:quotas:read on `iam/quotas`. */
    listPlans: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:quotas:read',
        'quotas',
        async ({ tx, tenant: realm }): Promise<QuotaPlanView[]> => {
          const plans = (await tx.find<QuotaPlan>(quotaCollections.plans, { tenantId: realm.id })).sort(
            (a, b) => (a.name < b.name ? -1 : 1),
          );
          const views: QuotaPlanView[] = [];
          for (const plan of plans) views.push(planView(plan, await assignmentCount(tx, plan)));
          return views;
        },
      ),

    /** One plan. Requires iam:quotas:read. */
    getPlan: (credential: CredentialInput, input: { tenantId: string; name: string }) => {
      const name = quotaName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:quotas:read',
        planResource(name),
        async ({ tx, tenant: realm }) => {
          const plan = await findPlan(tx, realm.id, name);
          return planView(plan, await assignmentCount(tx, plan));
        },
      );
    },

    /**
     * Assigns a plan to an API key (a session id of kind `api-key`), an identity (a person, service account or agent)
     * or a group, replacing the subject's plan for the same meter. Requires iam:quotas:manage on the plan; audited as
     * `quota:assign`.
     */
    assign: (
      credential: CredentialInput,
      input: { tenantId: string; plan: string; subjectType: QuotaSubjectType; subjectId: string },
    ): Promise<QuotaAssignmentView> => {
      const name = quotaName(input.plan, 'plan');
      return operation(
        credential,
        input.tenantId,
        'iam:quotas:manage',
        planResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const plan = await findPlan(tx, realm.id, name);
          const subject = await validSubject(tx, realm.id, input.subjectType, input.subjectId);
          const uniqueKey = `${plan.meter}:${subject.subjectType}:${subject.subjectId}`;
          const existing = (
            await tx.find<QuotaAssignment>(quotaCollections.assignments, { tenantId: realm.id, uniqueKey })
          )[0];
          const record: QuotaAssignment = {
            id: existing?.id ?? id(),
            tenantId: realm.id,
            uniqueKey,
            planId: plan.id,
            meter: plan.meter,
            ...subject,
            createdAt: ctx.now(),
            createdBy: principal.identity.id,
          };
          if (existing) await tx.put(quotaCollections.assignments, record);
          else await tx.insert(quotaCollections.assignments, record);
          await audit(tx, principal, 'quota:assign', realm.id, name, {
            plan: name,
            meter: plan.meter,
            subjectType: subject.subjectType,
            subjectId: subject.subjectId,
          });
          const label = await subjectName(tx, realm.id, subject.subjectType, subject.subjectId);
          return {
            plan: name,
            meter: plan.meter,
            ...subject,
            ...(label !== undefined ? { subjectName: label } : {}),
            createdAt: record.createdAt,
            createdBy: record.createdBy,
          };
        },
      );
    },

    /** Removes a subject's plan for a meter. Requires iam:quotas:manage on `iam/quotas`; audited as `quota:unassign`. */
    unassign: (
      credential: CredentialInput,
      input: { tenantId: string; meter: string; subjectType: QuotaSubjectType; subjectId: string },
    ) => {
      const meter = quotaName(input.meter, 'meter');
      return operation(
        credential,
        input.tenantId,
        'iam:quotas:manage',
        'quotas',
        async ({ tx, tenant: realm, principal }) => {
          const uniqueKey = `${meter}:${String(input.subjectType)}:${text(input.subjectId, 'subjectId')}`;
          const existing = (
            await tx.find<QuotaAssignment>(quotaCollections.assignments, { tenantId: realm.id, uniqueKey })
          )[0];
          if (!existing) return { removed: false };
          await tx.delete(quotaCollections.assignments, existing.id);
          const plan = await tx.get<QuotaPlan>(quotaCollections.plans, existing.planId);
          await audit(tx, principal, 'quota:unassign', realm.id, plan?.name ?? meter, {
            plan: plan?.name ?? null,
            meter,
            subjectType: existing.subjectType,
            subjectId: existing.subjectId,
          });
          return { removed: true };
        },
      );
    },

    /** Assignments, optionally of one plan, with their subjects' names. Requires iam:quotas:read on `iam/quotas`. */
    listAssignments: (credential: CredentialInput, input: { tenantId: string; plan?: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:quotas:read',
        'quotas',
        async ({ tx, tenant: realm }): Promise<QuotaAssignmentView[]> => {
          const plans = new Map(
            (await tx.find<QuotaPlan>(quotaCollections.plans, { tenantId: realm.id })).map((plan) => [
              plan.id,
              plan,
            ]),
          );
          const only = input.plan === undefined ? undefined : quotaName(input.plan, 'plan');
          const views: QuotaAssignmentView[] = [];
          for (const assignment of await tx.find<QuotaAssignment>(quotaCollections.assignments, {
            tenantId: realm.id,
          })) {
            const plan = plans.get(assignment.planId);
            if (!plan || (only !== undefined && plan.name !== only)) continue;
            const label = await subjectName(tx, realm.id, assignment.subjectType, assignment.subjectId);
            views.push({
              plan: plan.name,
              meter: assignment.meter,
              subjectType: assignment.subjectType,
              subjectId: assignment.subjectId,
              ...(label !== undefined ? { subjectName: label } : {}),
              createdAt: assignment.createdAt,
              createdBy: assignment.createdBy,
            });
          }
          return views.sort((a, b) => (a.plan < b.plan ? -1 : a.plan > b.plan ? 1 : a.subjectId < b.subjectId ? -1 : 1));
        },
      ),

    /** Every subject's use of a plan in the current windows, most used first. Requires iam:quotas:read. */
    usage: (credential: CredentialInput, input: { tenantId: string; plan: string }) => {
      const name = quotaName(input.plan, 'plan');
      return operation(
        credential,
        input.tenantId,
        'iam:quotas:read',
        planResource(name),
        async ({ tx, tenant: realm }): Promise<QuotaUsageView[]> => {
          const plan = await findPlan(tx, realm.id, name);
          const now = ctx.now();
          const current = new Map(
            plan.limits.map((limit) => [limit.period, quotaWindow(limit.period, now, plan.timeZone)]),
          );
          const bySubject = new Map<string, QuotaCounter[]>();
          for (const counter of await tx.find<QuotaCounter>(quotaCollections.counters, {
            tenantId: realm.id,
            planId: plan.id,
            kind: 'window',
          }))
            if (counter.period && current.get(counter.period)?.start === counter.windowStart)
              bySubject.set(counter.subjectKey, [...(bySubject.get(counter.subjectKey) ?? []), counter]);
          const views: QuotaUsageView[] = [];
          for (const [subject, counters] of bySubject) {
            const [kind, subjectId] = [subject.slice(0, subject.indexOf(':')), subject.slice(subject.indexOf(':') + 1)];
            const label =
              kind === 'identity'
                ? await subjectName(tx, realm.id, 'identity', subjectId)
                : kind === 'key'
                  ? await subjectName(tx, realm.id, 'apiKey', subjectId)
                  : undefined;
            const exceeded = counters.map((counter) => counter.exceededAt).filter((at): at is number => at !== undefined);
            views.push({
              subject,
              ...(label !== undefined ? { subjectName: label } : {}),
              limits: plan.limits.map((limit) => {
                const counter = counters.find((item) => item.period === limit.period);
                const used = counter?.used ?? 0;
                return {
                  period: limit.period,
                  limit: limit.limit,
                  used,
                  remaining: Math.max(0, limit.limit - used),
                  resetAt: current.get(limit.period)!.end,
                };
              }),
              ...(exceeded.length ? { exceededAt: Math.min(...exceeded) } : {}),
            });
          }
          const share = (view: QuotaUsageView) =>
            Math.max(0, ...view.limits.map((limit) => limit.used / limit.limit));
          return views.sort((a, b) => share(b) - share(a) || (a.subject < b.subject ? -1 : 1));
        },
      );
    },

    /**
     * Starts a subject's counters (and throttle) over, or every subject's with no subject given. Requires
     * iam:quotas:manage; audited as `quota:reset`.
     */
    reset: (
      credential: CredentialInput,
      input: { tenantId: string; plan: string; subject?: string },
    ) => {
      const name = quotaName(input.plan, 'plan');
      return operation(
        credential,
        input.tenantId,
        'iam:quotas:manage',
        planResource(name),
        async ({ tx, tenant: realm, principal }) => {
          const plan = await findPlan(tx, realm.id, name);
          const subject = input.subject === undefined ? undefined : text(input.subject, 'subject');
          let removed = 0;
          for (const counter of await tx.find<QuotaCounter>(quotaCollections.counters, {
            tenantId: realm.id,
            planId: plan.id,
          }))
            if (subject === undefined || counter.subjectKey === subject) {
              await tx.delete(quotaCollections.counters, counter.id);
              removed++;
            }
          await audit(tx, principal, 'quota:reset', realm.id, name, {
            plan: name,
            subject: subject ?? null,
            counters: removed,
          });
          return { reset: removed };
        },
      );
    },

    /**
     * The caller's own quota for a meter without counting anything: the plan that applies, what is left in each
     * window, and the throttle's tokens. Needs only a session of the tenant; not audited.
     */
    status: (credential: CredentialInput, input: { tenantId: string; meter: string }) =>
      callerDecision(ctx, credential, input, true),

    /**
     * Counts `cost` (default 1) units of a meter for the caller's own session, or refuses without counting when the
     * plan's throttle or a period limit would be exceeded (`allowed: false`, with `reason` and `retryAfterMs`).
     * Needs only a session of the tenant. Thresholds crossed are audited as `quota:threshold`, and a window's first
     * refusal as `quota:exceeded`.
     */
    consume: (
      credential: CredentialInput,
      input: { tenantId: string; meter: string; cost?: number },
    ) => callerDecision(ctx, credential, input, false),
  };
}

/** Trusted quota checks for the deployment's own request handlers (`iam.quotas`). */
export interface IamQuotas {
  /** Counts use for the request's credential (as `quotas.consume`) and returns the decision. */
  consume(request: QuotaConsumeRequest): Promise<QuotaDecision>;
  /** As `consume`, but throws QUOTA_EXCEEDED (429, with `retryAfterMs` for the Retry-After header) when refused. */
  enforce(request: QuotaConsumeRequest): Promise<QuotaDecision>;
  /** The request credential's quota for a meter without counting. */
  status(request: Omit<QuotaConsumeRequest, 'cost'>): Promise<QuotaDecision>;
  /**
   * Counts use for a subject your code identified itself (a background job, a webhook sender): an identity of the
   * tenant, optionally through one of its API keys. No credential; events are recorded as `deployment-operator`.
   */
  consumeFor(input: {
    tenantId: string;
    identityId: string;
    apiKeyId?: string;
    meter: string;
    cost?: number;
  }): Promise<QuotaDecision>;
}

export function createQuotasRuntime(ctx: ServerContext): IamQuotas {
  const api = createQuotasApi(ctx);
  const split = (request: QuotaConsumeRequest) => {
    const { tenantId, meter, cost: units, ...credential } = request;
    return { credential, input: { tenantId, meter, ...(units !== undefined ? { cost: units } : {}) } };
  };
  return {
    consume(request) {
      const { credential, input } = split(request);
      return api.consume(credential, input);
    },
    async enforce(request) {
      const { credential, input } = split(request);
      const decision = await api.consume(credential, input);
      if (!decision.allowed) throw new QuotaExceededError(decision, decision.retryAfterMs);
      return decision;
    },
    status(request) {
      const { tenantId, meter, ...credential } = request;
      return api.status(credential, { tenantId, meter });
    },
    async consumeFor(input) {
      const tenantId = text(input.tenantId, 'tenantId');
      const meter = quotaName(input.meter, 'meter');
      const units = cost(input.cost);
      return ctx.store.transaction(async (tx) => {
        const realm = await ctx.tenant(tx, tenantId);
        const identity = await ctx.activeIdentity(tx, text(input.identityId, 'identityId'), realm.id);
        let apiKeyId: string | undefined;
        if (input.apiKeyId !== undefined) {
          const session = await tx.get<Session>('sessions', text(input.apiKeyId, 'apiKeyId'));
          if (!session || session.kind !== 'api-key' || session.identityId !== identity.id)
            throw new IamError('NOT_FOUND', 'API key not found', 404);
          apiKeyId = session.id;
        }
        return consumeQuota(
          ctx,
          tx,
          { tenantId: realm.id, identityId: identity.id, ...(apiKeyId ? { apiKeyId } : {}) },
          meter,
          units,
          (store, action, metadata) =>
            ctx.events.recordAudit(store, {
              id: id(),
              tenantId: realm.id,
              actorId: 'deployment-operator',
              action,
              resourceId: planResource(String(metadata.plan)),
              timestamp: ctx.now(),
              outcome: action === 'quota:exceeded' ? 'deny' : 'allow',
              metadata,
            }),
        );
      });
    },
  };
}
