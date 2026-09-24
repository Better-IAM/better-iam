import {
  IamError,
  type AuthenticatedPrincipal,
  type IamStore,
  type Json,
  type StoredRecord,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import { integer, object, text } from './validation.js';

/**
 * API usage plans and quotas (like AWS API Gateway usage plans): a plan throttles a meter (a token bucket of
 * `ratePerSecond` with room for `burst`) and caps it per minute, hour, day, week or month. Plans apply to API keys,
 * agents, people and groups, or to everyone in the tenant by default; `iam.quotas.consume` counts use and refuses what
 * a plan does not allow, with the time to retry. Counters live in the database, so every server instance sees the same
 * totals.
 */

export const quotaCollections = {
  plans: 'quotaPlans',
  assignments: 'quotaAssignments',
  counters: 'quotaCounters',
} as const;

export type QuotaPeriod = 'minute' | 'hour' | 'day' | 'week' | 'month';
export const quotaPeriods: readonly QuotaPeriod[] = ['minute', 'hour', 'day', 'week', 'month'];

export interface QuotaLimit {
  period: QuotaPeriod;
  /** Units of the meter a subject may use per period window. */
  limit: number;
}

export interface QuotaThrottle {
  /** Tokens added per second. */
  ratePerSecond: number;
  /** The most tokens the bucket holds: the largest burst after a quiet spell. */
  burst: number;
}

export interface QuotaPlan extends StoredRecord {
  tenantId: string;
  uniqueKey: string;
  name: string;
  description?: string;
  /** What the plan counts: the meter `consume` names (`requests`, `exports`, `tokens`...). */
  meter: string;
  throttle?: QuotaThrottle;
  limits: QuotaLimit[];
  /** `subject`: each API key, agent or person has its own counters; `tenant`: everyone the plan covers shares one. */
  scope: 'subject' | 'tenant';
  /** The plan for everyone in the tenant without a plan of their own for the meter. */
  default: boolean;
  /** Among several group plans for the same meter, the highest priority applies. */
  priority: number;
  /** Day, week and month windows start at midnight (Monday, the 1st) in this IANA time zone. */
  timeZone: string;
  /** Percentages of a period limit that record `quota:threshold` once per window. */
  alertThresholds: number[];
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

export type QuotaSubjectType = 'apiKey' | 'identity' | 'group';

export interface QuotaAssignment extends StoredRecord {
  tenantId: string;
  /** `{meter}:{subjectType}:{subjectId}`: one plan per meter for each subject. */
  uniqueKey: string;
  planId: string;
  meter: string;
  subjectType: QuotaSubjectType;
  subjectId: string;
  createdAt: number;
  createdBy: string;
}

export interface QuotaCounter extends StoredRecord {
  tenantId: string;
  kind: 'window' | 'bucket';
  planId: string;
  subjectKey: string;
  /** Windows: the period and its bounds. */
  period?: QuotaPeriod;
  windowStart?: number;
  windowEnd?: number;
  used?: number;
  /** Thresholds already recorded in this window, and when the window was first exceeded. */
  alerted?: number[];
  exceededAt?: number;
  /** Buckets: tokens left at `updatedAt`. */
  tokens?: number;
  updatedAt?: number;
  /** When the retention sweep may delete the record. */
  expiresAt: number;
}

// --- validation ----------------------------------------------------------------------------------

const namePattern = /^[a-z0-9][a-z0-9._-]{0,63}$/;

export function quotaName(value: unknown, name = 'name'): string {
  const result = text(value, name, 64);
  if (!namePattern.test(result))
    throw new IamError(
      'INVALID_INPUT',
      `${name} must be 1-64 lowercase letters, digits and ._- starting with a letter or digit`,
    );
  return result;
}

export function quotaLimits(value: unknown): QuotaLimit[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > quotaPeriods.length)
    throw new IamError('INVALID_INPUT', 'limits must list at most one limit per period');
  const seen = new Set<QuotaPeriod>();
  const limits = value.map((item) => {
    const entry = object(item);
    const period = entry.period as QuotaPeriod;
    if (!quotaPeriods.includes(period))
      throw new IamError('INVALID_INPUT', 'period must be minute, hour, day, week or month');
    if (seen.has(period)) throw new IamError('INVALID_INPUT', `Only one ${period} limit per plan`);
    seen.add(period);
    return { period, limit: integer(entry.limit, `${period} limit`, 1, 1_000_000_000_000) };
  });
  return limits.sort((a, b) => quotaPeriods.indexOf(a.period) - quotaPeriods.indexOf(b.period));
}

export function quotaThrottle(value: unknown): QuotaThrottle | undefined {
  if (value === undefined || value === null) return undefined;
  const input = object(value);
  const rate = input.ratePerSecond;
  if (typeof rate !== 'number' || !Number.isFinite(rate) || rate < 0.001 || rate > 1_000_000)
    throw new IamError('INVALID_INPUT', 'throttle.ratePerSecond must be 0.001 to 1000000');
  const burst =
    input.burst === undefined
      ? Math.max(1, Math.ceil(rate))
      : integer(input.burst, 'throttle.burst', 1, 1_000_000_000);
  return { ratePerSecond: rate, burst };
}

export function timeZone(value: unknown): string {
  if (value === undefined) return 'UTC';
  const zone = text(value, 'timeZone', 64);
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: zone });
  } catch {
    throw new IamError('INVALID_INPUT', 'Unknown timeZone');
  }
  return zone;
}

export function alertThresholds(value: unknown): number[] {
  if (value === undefined) return [];
  if (!Array.isArray(value) || value.length > 5)
    throw new IamError('INVALID_INPUT', 'alertThresholds lists at most 5 percentages');
  return [...new Set(value.map((item) => integer(item, 'alert threshold', 1, 100)))].sort(
    (a, b) => a - b,
  );
}

// --- windows -------------------------------------------------------------------------------------

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/** The wall-clock parts of an instant in a time zone. */
function zoned(at: number, zone: string) {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone: zone,
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    weekday: 'short',
  }).formatToParts(new Date(at));
  const read = (type: string) => parts.find((part) => part.type === type)?.value ?? '';
  return {
    year: Number(read('year')),
    month: Number(read('month')),
    day: Number(read('day')),
    hour: Number(read('hour')) % 24,
    minute: Number(read('minute')),
    second: Number(read('second')),
    weekday: ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].indexOf(read('weekday')),
  };
}

/** The instant a local date's midnight falls on in a time zone (the first instant of that local day). */
function localMidnight(year: number, month: number, day: number, zone: string): number {
  let guess = Date.UTC(year, month - 1, day);
  // Two corrections settle the zone offset, including on days a daylight-saving change shifts it.
  for (let step = 0; step < 2; step++) {
    const parts = zoned(guess, zone);
    const shown = Date.UTC(parts.year, parts.month - 1, parts.day, parts.hour, parts.minute, parts.second);
    guess -= shown - Date.UTC(year, month - 1, day);
  }
  return guess;
}

/** The window of a period that contains `at`: minutes and hours in UTC, days, ISO weeks and months in `zone`. */
export function quotaWindow(period: QuotaPeriod, at: number, zone: string): { start: number; end: number } {
  if (period === 'minute') {
    const start = Math.floor(at / MINUTE) * MINUTE;
    return { start, end: start + MINUTE };
  }
  if (period === 'hour') {
    const start = Math.floor(at / HOUR) * HOUR;
    return { start, end: start + HOUR };
  }
  const local = zoned(at, zone);
  if (period === 'day') {
    const start = localMidnight(local.year, local.month, local.day, zone);
    const next = new Date(Date.UTC(local.year, local.month - 1, local.day + 1));
    return {
      start,
      end: localMidnight(next.getUTCFullYear(), next.getUTCMonth() + 1, next.getUTCDate(), zone),
    };
  }
  if (period === 'week') {
    const back = (local.weekday + 6) % 7; // days since Monday
    const monday = new Date(Date.UTC(local.year, local.month - 1, local.day - back));
    const following = new Date(Date.UTC(local.year, local.month - 1, local.day - back + 7));
    return {
      start: localMidnight(monday.getUTCFullYear(), monday.getUTCMonth() + 1, monday.getUTCDate(), zone),
      end: localMidnight(
        following.getUTCFullYear(),
        following.getUTCMonth() + 1,
        following.getUTCDate(),
        zone,
      ),
    };
  }
  const nextMonth = new Date(Date.UTC(local.year, local.month, 1));
  return {
    start: localMidnight(local.year, local.month, 1, zone),
    end: localMidnight(nextMonth.getUTCFullYear(), nextMonth.getUTCMonth() + 1, 1, zone),
  };
}

// --- resolution ----------------------------------------------------------------------------------

/** Who a consumption counts against, and the plan that applies. */
export interface QuotaSubject {
  tenantId: string;
  identityId: string;
  /** The API key the request used, when it used one. */
  apiKeyId?: string;
  /** The agent acting in a delegated session. */
  agentId?: string;
}

export interface ResolvedPlan {
  plan: QuotaPlan;
  /** How the plan applies: through the API key, the agent, the identity, a group, or the tenant default. */
  via: QuotaSubjectType | 'agent' | 'default';
  /** The counters' key: the subject that uses them. */
  subjectKey: string;
}

/** The subject of a principal: its API key (for an API-key session), the agent of a delegated session, the identity. */
export function subjectOf(principal: AuthenticatedPrincipal): QuotaSubject {
  const session = principal.session;
  return {
    tenantId: session.tenantId,
    identityId: principal.identity.id,
    ...(session.kind === 'api-key' ? { apiKeyId: session.id } : {}),
    ...(session.agentId ? { agentId: session.agentId } : {}),
  };
}

/**
 * The plan for a subject and meter, most specific first: an assignment to the API key, to the acting agent, to the
 * identity, to one of its groups (the highest priority, then the name), else the tenant's default plan for the meter.
 */
export async function resolvePlan(
  ctx: ServerContext,
  tx: IamStore,
  subject: QuotaSubject,
  meter: string,
): Promise<ResolvedPlan | undefined> {
  const plans = new Map<string, QuotaPlan>();
  const load = async (planId: string) => {
    if (!plans.has(planId)) {
      const plan = await tx.get<QuotaPlan>(quotaCollections.plans, planId);
      if (plan && plan.tenantId === subject.tenantId) plans.set(planId, plan);
    }
    return plans.get(planId);
  };
  const assigned = async (subjectType: QuotaSubjectType, subjectId: string) => {
    const found = (
      await tx.find<QuotaAssignment>(quotaCollections.assignments, {
        tenantId: subject.tenantId,
        uniqueKey: `${meter}:${subjectType}:${subjectId}`,
      })
    )[0];
    return found ? load(found.planId) : undefined;
  };
  const keyOf = (plan: QuotaPlan, own: string) => (plan.scope === 'tenant' ? 'tenant' : own);
  if (subject.apiKeyId) {
    const plan = await assigned('apiKey', subject.apiKeyId);
    if (plan) return { plan, via: 'apiKey', subjectKey: keyOf(plan, `key:${subject.apiKeyId}`) };
  }
  if (subject.agentId) {
    const plan = await assigned('identity', subject.agentId);
    if (plan) return { plan, via: 'agent', subjectKey: keyOf(plan, `identity:${subject.agentId}`) };
  }
  const own = await assigned('identity', subject.identityId);
  if (own) return { plan: own, via: 'identity', subjectKey: keyOf(own, `identity:${subject.identityId}`) };
  const { groupIds } = await ctx.decisions.grantSources(tx, subject.identityId, subject.tenantId);
  const candidates: QuotaPlan[] = [];
  for (const groupId of groupIds) {
    const plan = await assigned('group', groupId);
    if (plan) candidates.push(plan);
  }
  candidates.sort((a, b) => b.priority - a.priority || (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  if (candidates[0])
    return {
      plan: candidates[0],
      via: 'group',
      subjectKey: keyOf(candidates[0], `identity:${subject.identityId}`),
    };
  const fallback = (
    await tx.find<QuotaPlan>(quotaCollections.plans, { tenantId: subject.tenantId, meter, default: true })
  ).sort((a, b) => (a.name < b.name ? -1 : 1))[0];
  return fallback
    ? { plan: fallback, via: 'default', subjectKey: keyOf(fallback, `identity:${subject.identityId}`) }
    : undefined;
}

// --- consumption ---------------------------------------------------------------------------------

export interface QuotaLimitStatus {
  period: QuotaPeriod;
  limit: number;
  used: number;
  remaining: number;
  /** When the window ends and the count starts over. */
  resetAt: number;
}

export interface QuotaDecision {
  allowed: boolean;
  meter: string;
  /** The plan that decided, or null when none applies (use is unlimited). */
  plan: string | null;
  via?: ResolvedPlan['via'];
  cost: number;
  limits: QuotaLimitStatus[];
  /** Tokens left in the throttle's bucket after this call. */
  throttle?: { ratePerSecond: number; burst: number; tokens: number };
  /** Why a refusal happened: `throttle`, or the period whose limit is spent. */
  reason?: 'throttle' | QuotaPeriod;
  /** When a refused call may succeed. */
  retryAfterMs?: number;
}

const counterId = (planId: string, subjectKey: string, suffix: string) =>
  `quota:${planId}:${subjectKey}:${suffix}`;

/** What an audit event of the quota machinery records. */
type Recorder = (tx: IamStore, action: string, metadata: Record<string, Json>) => Promise<void>;

/**
 * Counts `cost` units of `meter` for a subject inside the caller's transaction, or refuses without counting anything
 * when the throttle or a period limit would be exceeded. `dryRun` reports the status without counting.
 */
export async function consumeQuota(
  ctx: ServerContext,
  tx: IamStore,
  subject: QuotaSubject,
  meter: string,
  cost: number,
  record: Recorder,
  dryRun = false,
): Promise<QuotaDecision> {
  const resolved = await resolvePlan(ctx, tx, subject, meter);
  if (!resolved) return { allowed: true, meter, plan: null, cost, limits: [] };
  const { plan, subjectKey } = resolved;
  const now = ctx.now();
  let reason: QuotaDecision['reason'];
  let retryAfterMs: number | undefined;
  // The throttle: a token bucket refilled continuously.
  let bucket: QuotaCounter | undefined;
  let tokens = 0;
  if (plan.throttle) {
    bucket = await tx.get<QuotaCounter>(quotaCollections.counters, counterId(plan.id, subjectKey, 'bucket'));
    const elapsed = bucket?.updatedAt === undefined ? Infinity : Math.max(0, now - bucket.updatedAt);
    tokens = Math.min(
      plan.throttle.burst,
      (bucket?.tokens ?? plan.throttle.burst) + (elapsed / 1000) * plan.throttle.ratePerSecond,
    );
    if (tokens < cost && !dryRun) {
      reason = 'throttle';
      retryAfterMs =
        cost > plan.throttle.burst
          ? undefined
          : Math.ceil(((cost - tokens) / plan.throttle.ratePerSecond) * 1000);
    }
  }
  // Period limits: fixed windows.
  const windows: { limit: QuotaLimit; window: { start: number; end: number }; counter?: QuotaCounter }[] = [];
  for (const limit of plan.limits) {
    const window = quotaWindow(limit.period, now, plan.timeZone);
    const counter = await tx.get<QuotaCounter>(
      quotaCollections.counters,
      counterId(plan.id, subjectKey, `${limit.period}:${window.start}`),
    );
    windows.push({ limit, window, counter });
    if (!reason && !dryRun && (counter?.used ?? 0) + cost > limit.limit) {
      reason = limit.period;
      retryAfterMs = cost > limit.limit ? undefined : window.end - now;
    }
  }
  const allowed = reason === undefined;
  const statuses = (spent: number) =>
    windows.map(({ limit, window, counter }) => {
      const used = (counter?.used ?? 0) + spent;
      return {
        period: limit.period,
        limit: limit.limit,
        used,
        remaining: Math.max(0, limit.limit - used),
        resetAt: window.end,
      };
    });
  if (dryRun)
    return {
      allowed: true,
      meter,
      plan: plan.name,
      via: resolved.via,
      cost: 0,
      limits: statuses(0),
      ...(plan.throttle ? { throttle: { ...plan.throttle, tokens: Math.floor(tokens) } } : {}),
    };
  const base = { tenantId: plan.tenantId, planId: plan.id, subjectKey };
  if (!allowed) {
    // Recorded once per window, the first time the window refuses.
    const refused = windows.find(({ limit }) => limit.period === reason);
    if (refused && refused.counter?.exceededAt === undefined) {
      const counter: QuotaCounter = refused.counter ?? {
        id: counterId(plan.id, subjectKey, `${refused.limit.period}:${refused.window.start}`),
        ...base,
        kind: 'window',
        period: refused.limit.period,
        windowStart: refused.window.start,
        windowEnd: refused.window.end,
        used: 0,
        expiresAt: refused.window.end + DAY,
      };
      const next = { ...counter, exceededAt: now };
      if (refused.counter) await tx.put(quotaCollections.counters, next);
      else await tx.insert(quotaCollections.counters, next);
      await record(tx, 'quota:exceeded', {
        plan: plan.name,
        meter,
        period: refused.limit.period,
        limit: refused.limit.limit,
        subject: subjectKey,
      });
    }
    return {
      allowed: false,
      meter,
      plan: plan.name,
      via: resolved.via,
      cost,
      limits: statuses(0),
      ...(plan.throttle ? { throttle: { ...plan.throttle, tokens: Math.floor(tokens) } } : {}),
      reason: reason!,
      ...(retryAfterMs !== undefined ? { retryAfterMs } : {}),
    };
  }
  if (plan.throttle) {
    const next: QuotaCounter = {
      id: counterId(plan.id, subjectKey, 'bucket'),
      ...base,
      kind: 'bucket',
      tokens: tokens - cost,
      updatedAt: now,
      // A full bucket after this long is the same as no record.
      expiresAt: now + Math.ceil((plan.throttle.burst / plan.throttle.ratePerSecond) * 1000) + MINUTE,
    };
    if (bucket) await tx.put(quotaCollections.counters, next);
    else await tx.insert(quotaCollections.counters, next);
  }
  for (const { limit, window, counter } of windows) {
    const used = (counter?.used ?? 0) + cost;
    const crossed = plan.alertThresholds.filter(
      (threshold) =>
        used * 100 >= threshold * limit.limit && !(counter?.alerted ?? []).includes(threshold),
    );
    const next: QuotaCounter = {
      ...(counter ?? {
        id: counterId(plan.id, subjectKey, `${limit.period}:${window.start}`),
        ...base,
        kind: 'window' as const,
        period: limit.period,
        windowStart: window.start,
        windowEnd: window.end,
        expiresAt: window.end + DAY,
      }),
      used,
      ...(crossed.length ? { alerted: [...(counter?.alerted ?? []), ...crossed].sort((a, b) => a - b) } : {}),
    };
    if (counter) await tx.put(quotaCollections.counters, next);
    else await tx.insert(quotaCollections.counters, next);
    for (const threshold of crossed)
      await record(tx, 'quota:threshold', {
        plan: plan.name,
        meter,
        period: limit.period,
        threshold,
        limit: limit.limit,
        used,
        subject: subjectKey,
      });
  }
  return {
    allowed: true,
    meter,
    plan: plan.name,
    via: resolved.via,
    cost,
    limits: statuses(cost),
    ...(plan.throttle ? { throttle: { ...plan.throttle, tokens: Math.floor(tokens - cost) } } : {}),
  };
}

/** The error `enforce` throws: 429 with the time to retry (`Retry-After` over HTTP). */
export class QuotaExceededError extends IamError {
  constructor(
    readonly decision: QuotaDecision,
    readonly retryAfterMs?: number,
  ) {
    super(
      'QUOTA_EXCEEDED',
      decision.reason === 'throttle'
        ? `Too many ${decision.meter} requests; slow down`
        : `The ${decision.reason} ${decision.meter} quota of plan ${decision.plan} is used up`,
      429,
    );
  }
}
