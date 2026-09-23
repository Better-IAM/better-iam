/**
 * Background work for Next.js: deliver queued outbox messages and dispatch events after the response with `after()`,
 * and run maintenance jobs from a scheduler through a bearer-protected route handler. Nothing here imports Node
 * built-ins, React, or `next/headers`, so it works in route handlers, server actions, middleware, and edge runtimes.
 */
import { IamError } from '@better-iam/core';

/** The instance surface background work uses; a `betterIam()` instance satisfies it. */
export interface BackgroundIam {
  auth?: {
    dispatchOutbox?(
      limit?: number,
    ): Promise<{ delivered: number; failed: number; abandoned: number }>;
  };
  dispatchAuditHooks?(): Promise<{ dispatched: number }>;
  purgeDeleted?(input?: { retentionMs?: number }): Promise<unknown>;
  pruneAudit?(input: { tenantId: string; retentionMs: number }): Promise<unknown>;
  sendAccessDigest?(input?: Record<string, unknown>): Promise<unknown>;
  sendExpiryReminders?(input?: Record<string, unknown>): Promise<unknown>;
  store?: { find(collection: string, filter?: Record<string, unknown>): Promise<unknown[]> };
}

export interface BackgroundOptions {
  /**
   * Receives failures nobody awaits, defaulting to `console.error`: scheduled and deferred dispatch parts
   * (`dispatch:outbox`, `dispatch:events`, or `dispatch` when the instance cannot be resolved) and cron tasks.
   */
  onError?(error: unknown, task: string): void;
  /**
   * Runs a task after the response; defaults to `after()` from `next/server`, loaded when the helper is created so
   * `schedule()` can hand its task over before the response ends. Where `after()` is unavailable or throws (outside
   * a request scope, the Pages Router), the task starts immediately without being awaited.
   */
  after?(task: () => Promise<unknown>): void;
  /** Messages per outbox round, 1 to 1000 (default 100). */
  outboxLimit?: number;
  /** Outbox rounds per dispatch; another round runs only while the last one was full (default 10). */
  maxRounds?: number;
}

/** Outbox totals across rounds; `failed` includes `abandoned` (messages out of attempts). */
export interface OutboxSummary {
  delivered: number;
  failed: number;
  abandoned: number;
  rounds: number;
}
/** What a dispatch did; a part is absent when the instance lacks its method. */
export interface DispatchSummary {
  outbox?: OutboxSummary;
  events?: { dispatched: number };
  /**
   * Set, with no parts, when `dispatch()` was called from inside a background run (an event subscriber, a plugin's
   * `afterAudit`, a delivery callback): it cannot wait for the run it belongs to, so it queued the follow-up run,
   * whose failures go to `onError`, and resolved at once.
   */
  deferred?: true;
}

export interface CronTasks {
  /** Deliver queued outbox messages (default true). */
  outbox?: boolean;
  /** Dispatch pending events to plugins, `events.onEvent`, and subscribers (default true). */
  events?: boolean;
  /** `purgeDeleted`: expire lapsed access and remove deleted tenants past retention (default off). */
  purge?: boolean | { retentionMs?: number };
  /** `pruneAudit` for each tenant; without `tenants`, every tenant that is not deleted (default off). */
  auditRetention?: false | { retentionMs: number; tenants?: string[] };
  /** `sendAccessDigest` with these options (default off). */
  digest?: boolean | Record<string, unknown>;
  /** `sendExpiryReminders` with these options (default off). */
  reminders?: boolean | Record<string, unknown>;
}
export interface CronOptions {
  /** The bearer token schedulers send; defaults to `process.env.CRON_SECRET`. Without one the route runs nothing. */
  secret?: string;
  tasks?: CronTasks;
  /**
   * How long the events task waits for an event dispatch already running in this process before failing with `BUSY`
   * instead of holding the request (default 10 000 ms).
   */
  eventsWaitMs?: number;
}
export type CronTask = 'purge' | 'auditRetention' | 'digest' | 'reminders' | 'outbox' | 'events';
/**
 * The JSON body of a cron run: each enabled task has a result, an error, or both (a partial audit retention). Errors
 * other than the server's `IamError` and this route's own (`UNSUPPORTED`, `BUSY`) read `TASK_FAILED`; `onError`
 * receives the full error.
 */
export interface CronReport {
  ok: boolean;
  results: Partial<Record<CronTask, unknown>>;
  errors: Partial<Record<CronTask, { code: string; message: string }>>;
}

export interface IamBackground {
  /**
   * Delivers queued outbox messages (emails, SMS, webhooks) and dispatches pending events now. Each part is
   * single-flight per process and instance: a call while it runs waits for that run and then triggers exactly one
   * more. The parts never wait on each other, so a slow event handler does not hold back email, and an outbox run
   * older than the server's 60-second claim lease no longer holds back new ones. Rejects with the failure of the
   * part that failed, or an `AggregateError` when both did.
   *
   * Event handlers and delivery callbacks should call `schedule()`. Where `AsyncLocalStorage` is available (Next.js
   * provides it on Node and edge), awaiting `dispatch()` inside one resolves with `{ deferred: true }`; elsewhere it
   * would wait for its own run and never settle.
   */
  dispatch(): Promise<DispatchSummary>;
  /** Schedules `dispatch()` after the current response with `after()`; never throws, safe inside event handlers. */
  schedule(): void;
  /**
   * Route handler for a scheduler (Vercel Cron, GitHub Actions, any HTTP cron): `export const GET = background.cron()`.
   * Requires `Authorization: Bearer <secret>`, runs the enabled tasks in order (jobs first, then outbox and events so
   * the messages they queue go out in the same run), and answers 200 when every task succeeded, else 500.
   */
  cron(options?: CronOptions): (request: Request) => Promise<Response>;
}

type AfterFunction = (task: () => Promise<unknown>) => void;
interface AfterModule {
  after?: unknown;
  unstable_after?: unknown;
  default?: { after?: unknown };
}

const noop = () => {};
const encoder = new TextEncoder();
const noStore = { 'cache-control': 'no-store' };
/** The server's outbox claim lease: by then a stuck run's claims have lapsed and another drain may take them. */
const outboxLeaseMs = 60_000;
const maxTimerMs = 2_147_483_647;

let nextAfter: AfterFunction | null | undefined;
let loadingAfter: Promise<AfterFunction | null> | undefined;
function loadAfter(): Promise<AfterFunction | null> {
  // Next's entry files are CommonJS; the explicit .js specifier resolves under Node ESM and bundlers alike.
  loadingAfter ??= import('next/server.js')
    .then((loaded) => {
      const mod = loaded as unknown as AfterModule;
      const after = mod.after ?? mod.unstable_after ?? mod.default?.after;
      return typeof after === 'function' ? (after as AfterFunction) : null;
    })
    .catch(() => null)
    .then((after) => (nextAfter = after));
  return loadingAfter;
}

/** A task failure with a stable code; `result` carries what a partly failed task still did. */
class TaskError extends Error {
  declare readonly result?: unknown;
  constructor(
    readonly code: string,
    message: string,
    options: { result?: unknown; cause?: unknown } = {},
  ) {
    super(message, 'cause' in options ? { cause: options.cause } : undefined);
    this.name = 'TaskError';
    if (options.result !== undefined) this.result = options.result;
  }
}
function unsupported(member: string): TaskError {
  return new TaskError('UNSUPPORTED', `The IAM instance does not provide ${member}`);
}
/** The server's errors (also a copy of `IamError` from another bundle) and this route's own are meant for callers. */
function describable(error: unknown): error is Error & { code: string } {
  return (
    (error instanceof IamError ||
      error instanceof TaskError ||
      (error instanceof Error && error.name === 'IamError')) &&
    typeof (error as { code?: unknown }).code === 'string' &&
    error.message !== ''
  );
}
/** Anything else (driver, network, configuration) may describe internals, so it is masked as the server masks it. */
function errorBody(error: unknown): { code: string; message: string } {
  return describable(error)
    ? { code: error.code, message: error.message }
    : { code: 'TASK_FAILED', message: 'The task failed' };
}
function defaultOnError(error: unknown, task: string): void {
  console.error(`[better-iam/next] Background task "${task}" failed:`, error);
}

function jsonError(
  code: string,
  message: string,
  status: number,
  headers: Record<string, string> = {},
): Response {
  return Response.json(
    { error: { code, message } },
    { status, headers: { ...noStore, ...headers } },
  );
}
async function sha256(value: string): Promise<Uint8Array> {
  return new Uint8Array(await crypto.subtle.digest('SHA-256', encoder.encode(value)));
}
function constantTimeEqual(left: Uint8Array, right: Uint8Array): boolean {
  if (left.length !== right.length) return false;
  let difference = 0;
  for (let index = 0; index < left.length; index++) difference |= left[index]! ^ right[index]!;
  return difference === 0;
}
/** Compares SHA-256 digests, so timing reveals neither the secret's content nor its length. */
async function bearerMatches(request: Request, secret: string): Promise<boolean> {
  const match = /^Bearer[ \t]+(.+)$/i.exec(request.headers.get('authorization') ?? '');
  const [provided, expected] = await Promise.all([sha256(match?.[1] ?? ''), sha256(secret)]);
  return constantTimeEqual(provided, expected) && match !== null;
}
function environmentSecret(): string | undefined {
  return typeof process === 'undefined' ? undefined : process.env?.CRON_SECRET;
}
/** Whether `promise` settles within `ms` milliseconds. */
function settlesWithin(promise: Promise<unknown>, ms: number): Promise<boolean> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<boolean>((resolve) => {
    timer = setTimeout(() => resolve(false), Math.max(0, ms));
  });
  return Promise.race([
    promise.then(
      () => true,
      () => true,
    ),
    timeout,
  ]).finally(() => clearTimeout(timer));
}

/** A single flight: the run in progress, when it started, and the one follow-up run queued behind it. */
interface Lane<R> {
  running?: Promise<R>;
  startedAt: number;
  queued?: Promise<R>;
}
/** Outbox delivery and event dispatch fly separately: only event dispatch lacks claims and must not overlap. */
interface Flight {
  outbox: Lane<OutboxSummary>;
  events: Lane<{ dispatched: number }>;
}
interface RunMarker {
  active: boolean;
}
interface RunContext {
  getStore(): RunMarker | undefined;
  run<R>(store: RunMarker, callback: () => R): R;
}
interface Shared {
  flights: WeakMap<object, Flight>;
  context?: RunContext;
}
const sharedKey = Symbol.for('better-iam.next.background');
/**
 * Kept on globalThis: Next can evaluate this module more than once per process (server and route bundles,
 * development reloads), and the single flights and the run context must span all of them.
 */
function shared(): Shared {
  const store = globalThis as { [sharedKey]?: Shared };
  return (store[sharedKey] ??= { flights: new WeakMap() });
}
function flightOf(iam: object): Flight {
  const { flights } = shared();
  let flight = flights.get(iam);
  if (!flight) flights.set(iam, (flight = { outbox: { startedAt: 0 }, events: { startedAt: 0 } }));
  return flight;
}
/** Marks background runs so a `dispatch()` from inside one is recognized; Next installs `AsyncLocalStorage` globally. */
function runContext(): RunContext | undefined {
  const Storage = (globalThis as { AsyncLocalStorage?: new () => RunContext }).AsyncLocalStorage;
  if (typeof Storage !== 'function') return undefined;
  const state = shared();
  if (!(state.context instanceof Storage)) state.context = new Storage();
  return state.context;
}
function insideRun(): boolean {
  return runContext()?.getStore()?.active === true;
}
function start<R>(lane: Lane<R>, work: () => Promise<R>): Promise<R> {
  const marker: RunMarker = { active: true };
  const context = runContext();
  const begin = async () => (context ? context.run(marker, work) : work());
  const current: Promise<R> = begin().finally(() => {
    marker.active = false;
    if (lane.running === current) lane.running = undefined;
  });
  lane.running = current;
  lane.startedAt = Date.now();
  return current;
}
/**
 * Starts a run when none is in progress, else shares the one follow-up run queued behind it. A run older than
 * `staleMs` is left to finish on its own and no longer holds new callers back.
 */
function join<R>(lane: Lane<R>, work: () => Promise<R>, staleMs = Infinity): Promise<R> {
  if (lane.running && Date.now() - lane.startedAt >= staleMs) {
    lane.queued = undefined;
    return start(lane, work);
  }
  // Checked before `running`: between a run's end and its follow-up's start only `queued` is set.
  if (lane.queued) return lane.queued;
  const running = lane.running;
  if (!running) return start(lane, work);
  const next = running.then(noop, noop).then(() => {
    if (lane.queued === next) lane.queued = undefined;
    return start(lane, work);
  });
  lane.queued = next;
  return next;
}

type Deliver = (limit: number) => Promise<{ delivered: number; failed: number; abandoned: number }>;
function outboxOf(iam: BackgroundIam): Deliver | undefined {
  const auth = iam.auth;
  const method = auth?.dispatchOutbox;
  return method ? (limit) => method.call(auth, limit) : undefined;
}
function eventsOf(iam: BackgroundIam): (() => Promise<{ dispatched: number }>) | undefined {
  const method = iam.dispatchAuditHooks;
  return method ? () => method.call(iam) : undefined;
}
async function drainOutbox(deliver: Deliver, limit: number, maxRounds: number) {
  const total: OutboxSummary = { delivered: 0, failed: 0, abandoned: 0, rounds: 0 };
  while (total.rounds < maxRounds) {
    const round = await deliver(limit);
    total.rounds++;
    total.delivered += round.delivered;
    total.failed += round.failed;
    total.abandoned += round.abandoned;
    // Abandoned messages are also counted as failed, so a full round is delivered + failed.
    if (round.delivered + round.failed < limit) break;
  }
  return total;
}
async function activeTenants(iam: BackgroundIam): Promise<string[]> {
  if (!iam.store)
    throw new TaskError(
      'UNSUPPORTED',
      'The IAM instance does not provide store to list tenants; pass auditRetention.tenants',
    );
  const ids: string[] = [];
  for (const record of await iam.store.find('tenants')) {
    const tenant = record as { id?: unknown; status?: unknown } | null;
    if (typeof tenant?.id === 'string' && tenant.status !== 'deleted') ids.push(tenant.id);
  }
  return ids;
}
function jobInput(value: boolean | Record<string, unknown>): Record<string, unknown> {
  return value === true ? {} : (value as Record<string, unknown>);
}

type Part = 'outbox' | 'events';
interface Settled {
  summary: DispatchSummary;
  failures: [Part, unknown][];
}

/**
 * Background delivery and maintenance for a Better IAM instance in Next.js. Call `background.schedule()` after
 * actions that queue email (sign-up, password reset, invitations) so it goes out after the response, and mount
 * `background.cron()` for periodic jobs and as a safety net when `after()` cannot run.
 *
 * ```ts
 * export const background = createBackground(getIam);
 * // app/api/cron/iam/route.ts
 * export const GET = background.cron({ tasks: { purge: true, digest: true } });
 * ```
 */
export function createBackground<T extends BackgroundIam>(
  resolve: () => T | Promise<T>,
  options: BackgroundOptions = {},
): IamBackground {
  const limit = options.outboxLimit ?? 100;
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
    throw new RangeError('outboxLimit must be an integer from 1 to 1000');
  const maxRounds = options.maxRounds ?? 10;
  if (!Number.isInteger(maxRounds) || maxRounds < 1)
    throw new RangeError('maxRounds must be a positive integer');
  // Callers sharing one failed run all see its error; report it once.
  const reported = new WeakSet<object>();
  const report = (error: unknown, task: string) => {
    if (typeof error === 'object' && error !== null) {
      if (reported.has(error)) return;
      reported.add(error);
    }
    try {
      if (options.onError) options.onError(error, task);
      else defaultOnError(error, task);
    } catch {
      /* A failing reporter must not break background work. */
    }
  };

  const settle = async (deferInsideRun: boolean): Promise<Settled> => {
    const iam = await resolve();
    const flight = flightOf(iam);
    const deliver = outboxOf(iam);
    const dispatchEvents = eventsOf(iam);
    const outbox =
      deliver && join(flight.outbox, () => drainOutbox(deliver, limit, maxRounds), outboxLeaseMs);
    const events = dispatchEvents && join(flight.events, dispatchEvents);
    if (deferInsideRun && insideRun()) {
      // Waiting would wait for the run this call is part of; the follow-ups finish on their own.
      outbox?.catch((error: unknown) => report(error, 'dispatch:outbox'));
      events?.catch((error: unknown) => report(error, 'dispatch:events'));
      return { summary: { deferred: true }, failures: [] };
    }
    const [delivered, dispatched] = await Promise.allSettled([outbox, events]);
    const summary: DispatchSummary = {};
    const failures: [Part, unknown][] = [];
    if (delivered.status === 'rejected') failures.push(['outbox', delivered.reason]);
    else if (delivered.value) summary.outbox = delivered.value;
    if (dispatched.status === 'rejected') failures.push(['events', dispatched.reason]);
    else if (dispatched.value) summary.events = dispatched.value;
    return { summary, failures };
  };
  const dispatch = async (): Promise<DispatchSummary> => {
    const { summary, failures } = await settle(true);
    const [first, second] = failures;
    if (second)
      throw new AggregateError(
        failures.map(([, error]) => error),
        'Outbox delivery and event dispatch both failed',
      );
    if (first) throw first[1];
    return summary;
  };

  const custom = options.after;
  if (!custom) void loadAfter();
  const schedule = (): void => {
    // Never deferred: no run awaits a scheduled task, so it may wait for the run it was scheduled from.
    const task = () =>
      settle(false).then(
        ({ failures }) => {
          for (const [part, error] of failures) report(error, `dispatch:${part}`);
        },
        (error: unknown) => report(error, 'dispatch'),
      );
    const hand = (after: AfterFunction | null | undefined) => {
      if (after)
        try {
          after(task);
          return;
        } catch {
          /* Outside a request scope: run now instead. */
        }
      void task();
    };
    if (custom) hand((work) => custom.call(options, work));
    else if (nextAfter !== undefined) hand(nextAfter);
    // Only before the import started at creation settles; a response that ends first skips the task.
    else void loadAfter().then(hand);
  };

  const cron = (cronOptions: CronOptions = {}) => {
    const tasks = cronOptions.tasks ?? {};
    const eventsWaitMs = cronOptions.eventsWaitMs ?? 10_000;
    if (!Number.isInteger(eventsWaitMs) || eventsWaitMs < 0 || eventsWaitMs > maxTimerMs)
      throw new RangeError(`eventsWaitMs must be an integer from 0 to ${maxTimerMs}`);
    const plan: [CronTask, (iam: T) => Promise<unknown>][] = [];
    const { purge, auditRetention, digest, reminders } = tasks;
    if (purge)
      plan.push([
        'purge',
        async (iam) => {
          if (!iam.purgeDeleted) throw unsupported('purgeDeleted');
          return iam.purgeDeleted(purge === true ? {} : purge);
        },
      ]);
    if (auditRetention)
      plan.push([
        'auditRetention',
        async (iam) => {
          if (!iam.pruneAudit) throw unsupported('pruneAudit');
          const tenants = auditRetention.tenants ?? (await activeTenants(iam));
          const pruned: Record<string, unknown> = {};
          const failures: [string, unknown][] = [];
          let deleted = 0;
          for (const tenantId of tenants)
            try {
              const result = await iam.pruneAudit({
                tenantId,
                retentionMs: auditRetention.retentionMs,
              });
              pruned[tenantId] = result;
              const count = (result as { deleted?: unknown } | null)?.deleted;
              if (typeof count === 'number') deleted += count;
            } catch (error) {
              failures.push([tenantId, error]);
            }
          const result = { deleted, tenants: pruned };
          const [first] = failures;
          if (first) {
            const cause = errorBody(first[1]);
            throw new TaskError(
              cause.code,
              `Audit pruning failed for ${failures.length} of ${tenants.length} tenants (${first[0]}: ${cause.message})`,
              { result, cause: first[1] },
            );
          }
          return result;
        },
      ]);
    if (digest)
      plan.push([
        'digest',
        async (iam) => {
          if (!iam.sendAccessDigest) throw unsupported('sendAccessDigest');
          return iam.sendAccessDigest(jobInput(digest));
        },
      ]);
    if (reminders)
      plan.push([
        'reminders',
        async (iam) => {
          if (!iam.sendExpiryReminders) throw unsupported('sendExpiryReminders');
          return iam.sendExpiryReminders(jobInput(reminders));
        },
      ]);
    if (tasks.outbox !== false)
      plan.push([
        'outbox',
        async (iam) => {
          const deliver = outboxOf(iam);
          if (!deliver) throw unsupported('auth.dispatchOutbox');
          // Per-message claims make concurrent drains safe, so a stuck in-process run holds nothing back here.
          return drainOutbox(deliver, limit, maxRounds);
        },
      ]);
    if (tasks.events !== false)
      plan.push([
        'events',
        async (iam) => {
          const dispatchEvents = eventsOf(iam);
          if (!dispatchEvents) throw unsupported('dispatchAuditHooks');
          const lane = flightOf(iam).events;
          const deadline = Date.now() + eventsWaitMs;
          for (let busy = lane.queued ?? lane.running; busy; busy = lane.queued ?? lane.running)
            if (!(await settlesWithin(busy, deadline - Date.now())))
              throw new TaskError(
                'BUSY',
                `Event dispatch in this process was still running after ${eventsWaitMs} ms`,
              );
          // Started in the same turn as the idle check, so no other run slips in between.
          return start(lane, dispatchEvents);
        },
      ]);

    return async (request: Request): Promise<Response> => {
      if (request.method !== 'GET' && request.method !== 'POST')
        return jsonError('METHOD_NOT_ALLOWED', 'Use GET or POST', 405, { allow: 'GET, POST' });
      const secret = cronOptions.secret ?? environmentSecret();
      if (!secret)
        return jsonError(
          'CRON_NOT_CONFIGURED',
          'Set CRON_SECRET or pass a secret to enable this route',
          500,
        );
      if (!(await bearerMatches(request, secret)))
        return jsonError('UNAUTHENTICATED', 'A valid cron bearer token is required', 401, {
          'www-authenticate': 'Bearer',
        });
      const body: CronReport = { ok: true, results: {}, errors: {} };
      let iam: T | undefined;
      let unavailable: unknown;
      try {
        iam = await resolve();
      } catch (error) {
        unavailable = error;
        report(error, 'cron');
      }
      for (const [name, task] of plan) {
        if (!iam) {
          body.errors[name] = errorBody(unavailable);
          continue;
        }
        try {
          body.results[name] = await task(iam);
        } catch (error) {
          if (error instanceof TaskError && error.result !== undefined)
            body.results[name] = error.result;
          body.errors[name] = errorBody(error);
          report(error, name);
        }
      }
      body.ok = Object.keys(body.errors).length === 0;
      return Response.json(body, { status: body.ok ? 200 : 500, headers: noStore });
    };
  };

  return { dispatch, schedule, cron };
}
