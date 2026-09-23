import { AsyncLocalStorage } from 'node:async_hooks';
import { createRequire } from 'node:module';
import { resolve as resolvePath } from 'node:path';
import { afterEach, describe, expect, it, vi, type Mock } from 'vitest';
import { IamError } from '@better-iam/core';
import {
  createBackground,
  type BackgroundIam,
  type CronReport,
  type DispatchSummary,
  type IamBackground,
} from '../packages/next/src/background.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

// Resolved from packages/next: that is where background.ts imports next/server from.
const nextServer = createRequire(resolvePath('packages/next/package.json')).resolve(
  'next/server.js',
);

afterEach(closeFixtures);
afterEach(() => {
  vi.unstubAllEnvs();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.doUnmock(nextServer);
});

const secret = 'cron-test-secret-with enough entropy';
const url = 'http://localhost:3000/api/cron/iam';
const cronRequest = (init: { method?: string; token?: string | null } = {}) =>
  new Request(url, {
    method: init.method ?? 'GET',
    headers: init.token === null ? {} : { authorization: `Bearer ${init.token ?? secret}` },
  });
const read = async (response: Response) => (await response.json()) as CronReport;
const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
/** Fails fast instead of letting a wedged promise run into the test timeout. */
const settles = <T>(promise: Promise<T>, ms = 2000) =>
  Promise.race([
    promise,
    sleep(ms).then((): never => {
      throw new Error(`Did not settle within ${ms} ms`);
    }),
  ]);
function gate<T = void>() {
  let open!: (value: T) => void;
  const promise = new Promise<T>((resolve) => {
    open = resolve;
  });
  return { promise, open };
}
const nothing = { delivered: 0, failed: 0, abandoned: 0 };

/** A real instance with a password reset queued for the Acme owner (a verified address). */
async function queuedReset() {
  const f = await organizationFixture();
  await f.iam.api.auth.requestPasswordReset({ tenantId: f.tenantId, email: 'owner@acme.test' });
  const resets = () => f.inbox.filter((message) => message.template === 'password-reset');
  expect(resets()).toHaveLength(0);
  return { ...f, resets };
}

describe('background dispatch', () => {
  it('schedule() hands the dispatch to after(), which delivers queued email after the response', async () => {
    const f = await queuedReset();
    const tasks: (() => Promise<unknown>)[] = [];
    const background = createBackground(async () => f.iam, { after: (task) => tasks.push(task) });
    background.schedule();
    expect(tasks).toHaveLength(1);
    expect(f.resets()).toHaveLength(0);
    await tasks[0]!();
    expect(f.resets()).toHaveLength(1);
    expect(f.resets()[0]).toMatchObject({ to: 'owner@acme.test', tenantId: f.tenantId });
  });

  it('schedule() runs the dispatch immediately when after() throws (outside a request scope)', async () => {
    const f = await queuedReset();
    const onError = vi.fn();
    const background = createBackground(() => f.iam, {
      onError,
      after: () => {
        throw new Error('`after` was called outside a request scope');
      },
    });
    expect(() => background.schedule()).not.toThrow();
    await vi.waitFor(() => expect(f.resets()).toHaveLength(1));
    expect(onError).not.toHaveBeenCalled();
  });

  it('dispatch() delivers the outbox and dispatches events to in-process subscribers', async () => {
    const f = await queuedReset();
    const seen: string[] = [];
    const unsubscribe = f.iam.events.subscribe('auth:session:create', (event) => {
      seen.push(event.tenantId);
    });
    await f.member('dana');
    await f.signIn('dana');
    expect(seen).toEqual([]);
    const summary = await createBackground(() => f.iam).dispatch();
    expect(summary.outbox).toMatchObject({ delivered: 1, failed: 0, abandoned: 0, rounds: 1 });
    expect(summary.events!.dispatched).toBeGreaterThanOrEqual(1);
    expect(summary.deferred).toBeUndefined();
    expect(seen).toContain(f.tenantId);
    expect(f.resets()).toHaveLength(1);
    unsubscribe();
  });

  it('dispatch() is single-flight: calls during a run share exactly one follow-up run', async () => {
    let runs = 0;
    let active = 0;
    let peak = 0;
    const iam: BackgroundIam = {
      auth: {
        async dispatchOutbox() {
          runs++;
          active++;
          peak = Math.max(peak, active);
          await sleep(20);
          active--;
          return { delivered: runs, failed: 0, abandoned: 0 };
        },
      },
    };
    const background = createBackground(async () => iam);
    const [first, second, third] = await Promise.all([
      background.dispatch(),
      background.dispatch(),
      background.dispatch(),
    ]);
    expect(runs).toBe(2);
    expect(peak).toBe(1);
    expect(first.outbox!.delivered).toBe(1);
    expect(second.outbox).toBe(third.outbox);
    expect(second.outbox!.delivered).toBe(2);
    expect(second.events).toBeUndefined();
    await background.dispatch();
    expect(runs).toBe(3);
    // A second helper over the same instance (another bundle, a dev reload) shares the flight.
    const other = createBackground(() => iam);
    await Promise.all([background.dispatch(), other.dispatch(), other.dispatch()]);
    expect(runs).toBe(5);
    expect(peak).toBe(1);
  });

  it('never overlaps event dispatch between scheduled runs and the cron route', async () => {
    let active = 0;
    let peak = 0;
    const iam: BackgroundIam = {
      async dispatchAuditHooks() {
        active++;
        peak = Math.max(peak, active);
        await sleep(15);
        active--;
        return { dispatched: 1 };
      },
    };
    const background = createBackground(() => iam);
    const route = background.cron({ secret, tasks: { outbox: false } });
    const [, response] = await Promise.all([background.dispatch(), route(cronRequest())]);
    expect(response.status).toBe(200);
    expect(peak).toBe(1);
  });

  it('a hung event handler holds back neither email nor the cron route, whose events task answers BUSY', async () => {
    const handler = gate();
    let deliveries = 0;
    let eventRuns = 0;
    const iam: BackgroundIam = {
      auth: {
        async dispatchOutbox() {
          deliveries++;
          return { delivered: 1, failed: 0, abandoned: 0 };
        },
      },
      async dispatchAuditHooks() {
        eventRuns++;
        if (eventRuns === 1) await handler.promise;
        return { dispatched: 1 };
      },
    };
    const onError = vi.fn();
    const background = createBackground(() => iam, { onError, after: (task) => void task() });
    const first = background.dispatch();
    await vi.waitFor(() => expect(deliveries).toBe(1));
    // A password reset queued while the handler hangs still goes out.
    background.schedule();
    await vi.waitFor(() => expect(deliveries).toBe(2));
    const route = background.cron({ secret, eventsWaitMs: 50 });
    const response = await settles(route(cronRequest()));
    expect(response.status).toBe(500);
    const body = await read(response);
    expect(body.results).toEqual({ outbox: { delivered: 1, failed: 0, abandoned: 0, rounds: 1 } });
    expect(body.errors).toEqual({
      events: {
        code: 'BUSY',
        message: 'Event dispatch in this process was still running after 50 ms',
      },
    });
    expect(deliveries).toBe(3);
    expect(eventRuns).toBe(1);
    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0]![1]).toBe('events');

    handler.open();
    expect(await settles(first)).toEqual({
      outbox: { delivered: 1, failed: 0, abandoned: 0, rounds: 1 },
      events: { dispatched: 1 },
    });
    // The scheduled follow-up dispatches once more, and the lane is free again.
    await vi.waitFor(() => expect(eventRuns).toBe(2));
    expect((await settles(route(cronRequest()))).status).toBe(200);
    expect(eventRuns).toBe(3);
    expect(onError).toHaveBeenCalledOnce();
    expect(() => background.cron({ eventsWaitMs: -1 })).toThrow(RangeError);
    expect(() => background.cron({ eventsWaitMs: 1.5 })).toThrow(RangeError);
    expect(() => background.cron({ eventsWaitMs: 2 ** 31 })).toThrow(RangeError);
  });

  it('a stuck outbox run never holds back the cron drain, and scheduled drains only until the claim lease lapses', async () => {
    const stuck = gate<typeof nothing>();
    let calls = 0;
    const iam: BackgroundIam = {
      auth: {
        async dispatchOutbox() {
          calls++;
          return calls === 1 ? stuck.promise : nothing;
        },
      },
    };
    const background = createBackground(() => iam);
    const first = background.dispatch();
    await vi.waitFor(() => expect(calls).toBe(1));
    const response = await settles(
      background.cron({ secret, tasks: { events: false } })(cronRequest()),
    );
    expect(response.status).toBe(200);
    expect(calls).toBe(2);
    // Within the lease a scheduled drain queues behind the stuck run...
    const queued = background.dispatch();
    await sleep(10);
    expect(calls).toBe(2);
    // ...and past it one starts beside it.
    vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 60_000);
    expect(await settles(background.dispatch())).toEqual({ outbox: { ...nothing, rounds: 1 } });
    expect(calls).toBe(3);
    stuck.open({ delivered: 1, failed: 0, abandoned: 0 });
    expect((await settles(first)).outbox).toMatchObject({ delivered: 1 });
    expect(await settles(queued)).toEqual({ outbox: { ...nothing, rounds: 1 } });
    expect(calls).toBe(4);
  });

  it('dispatch() awaited inside a run resolves deferred, and the subscriber, dispatch, and cron still settle', async () => {
    vi.stubGlobal('AsyncLocalStorage', AsyncLocalStorage);
    const f = await queuedReset();
    const onError = vi.fn();
    const background = createBackground(() => f.iam, { onError });
    const inner: DispatchSummary[] = [];
    f.iam.events.subscribe('auth:session:create', async () => {
      inner.push(await background.dispatch());
    });
    await f.member('dana');
    await f.signIn('dana');
    const outer = await settles(background.dispatch());
    expect(outer.outbox).toMatchObject({ delivered: 1 });
    expect(outer.events!.dispatched).toBeGreaterThanOrEqual(1);
    expect(inner).toEqual([{ deferred: true }]);
    expect(f.resets()).toHaveLength(1);
    // The instance is not wedged: a later dispatch and a cron run whose own handler dispatches both settle.
    await f.signIn('dana');
    expect((await settles(background.dispatch())).events!.dispatched).toBeGreaterThanOrEqual(1);
    await f.signIn('dana');
    const response = await settles(background.cron({ secret })(cronRequest()));
    expect(response.status).toBe(200);
    expect(inner).toEqual([{ deferred: true }, { deferred: true }, { deferred: true }]);
    await settles(background.dispatch());
    expect(onError).not.toHaveBeenCalled();
  });

  it('a delivery callback awaiting dispatch() defers to a follow-up whose failure reaches onError', async () => {
    vi.stubGlobal('AsyncLocalStorage', AsyncLocalStorage);
    let background!: IamBackground;
    let runs = 0;
    const inner: DispatchSummary[] = [];
    let later: Promise<DispatchSummary> | undefined;
    const iam: BackgroundIam = {
      auth: {
        async dispatchOutbox() {
          runs++;
          if (runs === 1) {
            inner.push(await background.dispatch());
            // Continuations that outlive the run are not inside it any more.
            later = sleep(30).then(() => background.dispatch());
          }
          if (runs === 2) throw new Error('relay down');
          return nothing;
        },
      },
    };
    const onError = vi.fn();
    background = createBackground(() => iam, { onError });
    expect(await settles(background.dispatch())).toEqual({ outbox: { ...nothing, rounds: 1 } });
    expect(inner).toEqual([{ deferred: true }]);
    await vi.waitFor(() => expect(onError).toHaveBeenCalledOnce());
    expect(onError.mock.calls[0]).toEqual([
      expect.objectContaining({ message: 'relay down' }),
      'dispatch:outbox',
    ]);
    expect(await settles(later!)).toEqual({ outbox: { ...nothing, rounds: 1 } });
    expect(runs).toBe(3);
  });

  it('without AsyncLocalStorage, a subscriber calling schedule() gets its follow-up run', async () => {
    const f = await queuedReset();
    const onError = vi.fn();
    const background = createBackground(() => f.iam, { onError, after: (task) => void task() });
    let handled = 0;
    f.iam.events.subscribe('auth:session:create', () => {
      handled++;
      background.schedule();
    });
    await f.member('dana');
    await f.signIn('dana');
    await settles(background.dispatch());
    expect(handled).toBe(1);
    await f.signIn('dana');
    await settles(background.dispatch());
    expect(handled).toBe(2);
    // Joins the follow-up the last handler scheduled.
    await settles(background.dispatch());
    expect(onError).not.toHaveBeenCalled();
  });

  it('drains the outbox in rounds while a round is full, up to maxRounds', async () => {
    const rounds: number[] = [];
    let pending = 5;
    const iam: BackgroundIam = {
      auth: {
        async dispatchOutbox(limit = 100) {
          rounds.push(limit);
          const taken = Math.min(limit, pending);
          pending -= taken;
          // One abandoned message is also a failed one, as the server counts it.
          return taken === 2 && pending === 1
            ? { delivered: 1, failed: 1, abandoned: 1 }
            : { delivered: taken, failed: 0, abandoned: 0 };
        },
      },
    };
    const summary = await createBackground(() => iam, { outboxLimit: 2 }).dispatch();
    expect(rounds).toEqual([2, 2, 2]);
    expect(summary.outbox).toEqual({ delivered: 4, failed: 1, abandoned: 1, rounds: 3 });
    pending = 10;
    const capped = await createBackground(() => iam, { outboxLimit: 2, maxRounds: 2 }).dispatch();
    expect(capped.outbox).toMatchObject({ delivered: 4, rounds: 2 });
    expect(() => createBackground(() => iam, { outboxLimit: 1001 })).toThrow(RangeError);
    expect(() => createBackground(() => iam, { maxRounds: 0 })).toThrow(RangeError);
  });

  it('reports each failed part to onError (console.error by default), once per failure, and never throws', async () => {
    const relayDown = () =>
      Object.assign(new Error('mail relay down'), { code: 'DELIVERY_FAILED' });
    const failing: BackgroundIam = {
      auth: {
        async dispatchOutbox() {
          throw relayDown();
        },
      },
      async dispatchAuditHooks() {
        return { dispatched: 0 };
      },
    };
    const now = (task: () => Promise<unknown>) => void task();
    const onError = vi.fn();
    createBackground(() => failing, { onError, after: now }).schedule();
    await vi.waitFor(() => expect(onError).toHaveBeenCalledOnce());
    expect(onError.mock.calls[0]).toEqual([
      expect.objectContaining({ message: 'mail relay down' }),
      'dispatch:outbox',
    ]);
    await expect(createBackground(() => failing).dispatch()).rejects.toMatchObject({
      code: 'DELIVERY_FAILED',
    });

    // Both parts failing: each is reported, and dispatch() rejects with both.
    const broken: BackgroundIam = {
      ...failing,
      async dispatchAuditHooks() {
        throw new Error('subscriber failed');
      },
    };
    const both = vi.fn();
    const background = createBackground(() => broken, { onError: both, after: now });
    background.schedule();
    await vi.waitFor(() => expect(both).toHaveBeenCalledTimes(2));
    expect(both.mock.calls.map(([error, task]) => [(error as Error).message, task])).toEqual([
      ['mail relay down', 'dispatch:outbox'],
      ['subscriber failed', 'dispatch:events'],
    ]);
    const rejected = await background.dispatch().catch((error: unknown) => error);
    expect(rejected).toBeInstanceOf(AggregateError);
    expect((rejected as AggregateError).errors.map((error: Error) => error.message)).toEqual([
      'mail relay down',
      'subscriber failed',
    ]);

    // One failed run shared by several scheduled calls is reported once.
    const slow = gate();
    let attempts = 0;
    const flaky: BackgroundIam = {
      auth: {
        async dispatchOutbox() {
          if (++attempts === 1) {
            await slow.promise;
            return nothing;
          }
          throw relayDown();
        },
      },
    };
    const once = vi.fn();
    const shared = createBackground(() => flaky, { onError: once, after: now });
    shared.schedule();
    await vi.waitFor(() => expect(attempts).toBe(1));
    shared.schedule();
    shared.schedule();
    await sleep(5);
    slow.open();
    await vi.waitFor(() => expect(once).toHaveBeenCalled());
    await sleep(10);
    expect(attempts).toBe(2);
    expect(once).toHaveBeenCalledOnce();

    const unresolved = vi.fn();
    createBackground(
      async (): Promise<BackgroundIam> => {
        throw new Error('no database');
      },
      { onError: unresolved, after: now },
    ).schedule();
    await vi.waitFor(() => expect(unresolved).toHaveBeenCalledOnce());
    expect(unresolved.mock.calls[0]![1]).toBe('dispatch');

    const logged = vi.spyOn(console, 'error').mockImplementation(() => {});
    createBackground(() => failing, { after: now }).schedule();
    await vi.waitFor(() => expect(logged).toHaveBeenCalledOnce());
    expect(logged.mock.calls[0]![0]).toBe(
      '[better-iam/next] Background task "dispatch:outbox" failed:',
    );
  });
});

describe('after() from next/server', () => {
  /** A fresh copy of the module (its after() cache empty) whose next/server import sees `exports`. */
  async function withNextServer(exports: () => Record<string, unknown>) {
    vi.resetModules();
    vi.doMock(nextServer, exports);
    return (await import('../packages/next/src/background.js')).createBackground;
  }
  const shape = (keys: Record<string, unknown>) => () => ({
    after: undefined,
    unstable_after: undefined,
    default: undefined,
    ...keys,
  });

  it('hands the task to the real after() from next/server.js, which throws outside a request scope, then runs it', async () => {
    const f = await queuedReset();
    let after: Mock | undefined;
    vi.resetModules();
    vi.doMock(nextServer, async (importOriginal) => {
      const real = (await importOriginal()) as { after?: unknown; default?: { after?: unknown } };
      const original = (real.after ?? real.default?.after) as (task: unknown) => void;
      expect(original).toBeTypeOf('function');
      after = vi.fn(original);
      return shape({ after })();
    });
    const create = (await import('../packages/next/src/background.js')).createBackground;
    const background = create(() => f.iam);
    await vi.dynamicImportSettled();
    background.schedule();
    expect(after).toHaveBeenCalledOnce();
    expect(after!.mock.calls[0]![0]).toBeTypeOf('function');
    expect(after!.mock.results[0]).toMatchObject({
      type: 'throw',
      value: { message: expect.stringContaining('outside a request scope') },
    });
    await vi.waitFor(() => expect(f.resets()).toHaveLength(1));
  });

  it('loads after() when the helper is created, so schedule() hands over at once; unstable_after and default.after work too', async () => {
    for (const exported of ['after', 'unstable_after', 'default'] as const) {
      const f = await queuedReset();
      const tasks: (() => Promise<unknown>)[] = [];
      const after = vi.fn((task: () => Promise<unknown>) => void tasks.push(task));
      const create = await withNextServer(
        shape(exported === 'default' ? { default: { after } } : { [exported]: after }),
      );
      const background = create(() => f.iam);
      await vi.dynamicImportSettled();
      background.schedule();
      expect(after).toHaveBeenCalledOnce();
      expect(f.resets()).toHaveLength(0);
      await tasks[0]!();
      expect(f.resets()).toHaveLength(1);
    }
  });

  it('hands over once the import settles when schedule() comes first, and runs at once without after()', async () => {
    const f = await queuedReset();
    const tasks: (() => Promise<unknown>)[] = [];
    const after = vi.fn((task: () => Promise<unknown>) => void tasks.push(task));
    const create = await withNextServer(shape({ after }));
    create(() => f.iam).schedule();
    expect(after).not.toHaveBeenCalled();
    await vi.waitFor(() => expect(after).toHaveBeenCalledOnce());
    await tasks[0]!();
    expect(f.resets()).toHaveLength(1);

    for (const exports of [
      shape({}),
      () => {
        throw new Error('next/server failed to load');
      },
    ]) {
      const g = await queuedReset();
      const onError = vi.fn();
      (await withNextServer(exports))(() => g.iam, { onError }).schedule();
      await vi.waitFor(() => expect(g.resets()).toHaveLength(1));
      expect(onError).not.toHaveBeenCalled();
    }
  });
});

describe('background cron route', () => {
  const outboxOnly = () => {
    const calls: string[] = [];
    const iam: BackgroundIam = {
      auth: {
        async dispatchOutbox() {
          calls.push('outbox');
          return nothing;
        },
      },
      async dispatchAuditHooks() {
        calls.push('events');
        return { dispatched: 0 };
      },
    };
    return { iam, calls };
  };

  it('fails closed without a secret, rejects wrong or missing bearers, and allows only GET and POST', async () => {
    vi.stubEnv('CRON_SECRET', '');
    const { iam, calls } = outboxOnly();
    const background = createBackground(() => iam);
    const unconfigured = await background.cron()(cronRequest());
    expect(unconfigured.status).toBe(500);
    expect(unconfigured.headers.get('cache-control')).toBe('no-store');
    expect(await unconfigured.json()).toEqual({
      error: { code: 'CRON_NOT_CONFIGURED', message: expect.any(String) },
    });
    const route = background.cron({ secret });
    for (const token of [null, 'wrong', `${secret}x`, secret.slice(0, -1)]) {
      const denied = await route(cronRequest({ token }));
      expect(denied.status).toBe(401);
      expect(denied.headers.get('www-authenticate')).toBe('Bearer');
      expect(await denied.json()).toMatchObject({ error: { code: 'UNAUTHENTICATED' } });
    }
    const basic = await route(
      new Request(url, { headers: { authorization: `Basic ${btoa(`cron:${secret}`)}` } }),
    );
    expect(basic.status).toBe(401);
    const put = await route(cronRequest({ method: 'PUT' }));
    expect(put.status).toBe(405);
    expect(put.headers.get('allow')).toBe('GET, POST');
    expect(await put.json()).toMatchObject({ error: { code: 'METHOD_NOT_ALLOWED' } });
    expect(calls).toEqual([]);
    const posted = await route(cronRequest({ method: 'POST' }));
    expect(posted.status).toBe(200);
    expect(calls).toEqual(['outbox', 'events']);
  });

  it('reads CRON_SECRET from the environment by default', async () => {
    vi.stubEnv('CRON_SECRET', 'from-the-environment');
    const { iam } = outboxOnly();
    const route = createBackground(() => iam).cron();
    expect((await route(cronRequest())).status).toBe(401);
    const response = await route(cronRequest({ token: 'from-the-environment' }));
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      ok: true,
      results: {
        outbox: { ...nothing, rounds: 1 },
        events: { dispatched: 0 },
      },
      errors: {},
    });
  });

  it('delivers the outbox and dispatches events on a real instance', async () => {
    const f = await queuedReset();
    const seen: string[] = [];
    f.iam.events.subscribe('auth:session:create', (event) => {
      seen.push(event.action);
    });
    await f.member('erin');
    await f.signIn('erin');
    const response = await createBackground(() => f.iam).cron({ secret })(cronRequest());
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await read(response);
    expect(body.ok).toBe(true);
    expect(body.errors).toEqual({});
    expect(body.results.outbox).toMatchObject({ delivered: 1, failed: 0, rounds: 1 });
    expect((body.results.events as { dispatched: number }).dispatched).toBeGreaterThanOrEqual(1);
    expect(seen).toContain('auth:session:create');
    expect(f.resets()).toHaveLength(1);
  });

  it('prunes audit trails of every tenant not deleted, then purges deleted tenants', async () => {
    const f = await organizationFixture();
    const beta = await f.iam.api.tenants.create(f.rootCredential, {
      parentId: f.root.tenant.id,
      name: 'Beta',
      type: 'organization',
      ownerEmail: 'owner@beta.test',
    });
    await f.iam.api.tenants.setStatus(f.rootCredential, {
      tenantId: beta.tenant.id,
      status: 'deleted',
    });
    // pruneAudit and purgeDeleted compare with the wall clock: let the events above age past a zero retention.
    await sleep(5);
    const background = createBackground(() => f.iam);
    const pruned = await read(
      await background.cron({
        secret,
        tasks: { auditRetention: { retentionMs: 0 }, outbox: false, events: false },
      })(cronRequest()),
    );
    expect(pruned.ok).toBe(true);
    const retention = pruned.results.auditRetention as {
      deleted: number;
      tenants: Record<string, { deleted: number }>;
    };
    expect(Object.keys(retention.tenants).sort()).toEqual([f.root.tenant.id, f.tenantId].sort());
    expect(retention.tenants[f.tenantId]!.deleted).toBeGreaterThan(0);
    expect(retention.tenants[f.root.tenant.id]!.deleted).toBeGreaterThan(0);
    expect(retention.deleted).toBe(
      retention.tenants[f.tenantId]!.deleted + retention.tenants[f.root.tenant.id]!.deleted,
    );
    expect(pruned.results).not.toHaveProperty('outbox');

    const listed = await read(
      await background.cron({
        secret,
        tasks: { auditRetention: { retentionMs: 0, tenants: [f.tenantId] }, events: false },
      })(cronRequest()),
    );
    expect(Object.keys((listed.results.auditRetention as { tenants: object }).tenants)).toEqual([
      f.tenantId,
    ]);

    await sleep(5);
    const purged = await read(
      await background.cron({ secret, tasks: { purge: { retentionMs: 0 } } })(cronRequest()),
    );
    expect(purged.ok).toBe(true);
    expect(purged.results.purge).toMatchObject({ purgedTenants: [beta.tenant.id] });
    expect(purged.results).toHaveProperty('outbox');
    expect(purged.results).toHaveProperty('events');
    expect(await f.iam.store.get('tenants', beta.tenant.id)).toBeUndefined();
  });

  it('keeps running later tasks after one fails, answers 500 with the error, and never leaks stacks', async () => {
    const f = await queuedReset();
    const onError = vi.fn();
    const response = await createBackground(() => f.iam, { onError }).cron({
      secret,
      tasks: { digest: true, reminders: { withinMs: 1 } },
    })(cronRequest());
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).not.toMatch(/\n\s+at /);
    const body = JSON.parse(text) as CronReport;
    expect(body.ok).toBe(false);
    expect(body.errors).toEqual({
      reminders: { code: 'INVALID_INPUT', message: expect.any(String) },
    });
    expect(body.results.digest).toMatchObject({ sent: [] });
    expect(body.results.outbox).toMatchObject({ delivered: 1 });
    expect(body.results.events).toBeDefined();
    expect(f.resets()).toHaveLength(1);
    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0]![1]).toBe('reminders');
  });

  it('runs jobs before delivery, reports UNSUPPORTED for missing methods, and keeps partial audit results', async () => {
    const calls: string[] = [];
    const offline = Object.assign(new Error('connect ECONNREFUSED 10.0.0.5:5432'), {
      code: 'ECONNREFUSED',
    });
    const iam: BackgroundIam = {
      auth: {
        async dispatchOutbox() {
          calls.push('outbox');
          return nothing;
        },
      },
      async dispatchAuditHooks() {
        calls.push('events');
        return { dispatched: 0 };
      },
      async purgeDeleted(input) {
        calls.push(`purge:${input?.retentionMs}`);
        return { purgedTenants: [] };
      },
      async pruneAudit({ tenantId }) {
        calls.push(`prune:${tenantId}`);
        if (tenantId === 'broken') throw new IamError('CONFLICT', 'Audit chain is locked', 409);
        if (tenantId === 'offline') throw offline;
        return { deleted: 2 };
      },
      async sendAccessDigest(input) {
        calls.push(`digest:${JSON.stringify(input)}`);
        return { sent: [] };
      },
    };
    const onError = vi.fn();
    const background = createBackground(() => iam, { onError });
    const response = await background.cron({
      secret,
      tasks: {
        events: true,
        outbox: true,
        reminders: true,
        digest: { withinMs: 86400000 },
        auditRetention: { retentionMs: 1000, tenants: ['acme', 'broken', 'offline', 'beta'] },
        purge: { retentionMs: 0 },
      },
    })(cronRequest());
    expect(response.status).toBe(500);
    expect(calls).toEqual([
      'purge:0',
      'prune:acme',
      'prune:broken',
      'prune:offline',
      'prune:beta',
      'digest:{"withinMs":86400000}',
      'outbox',
      'events',
    ]);
    const body = await read(response);
    expect(body.errors.reminders).toEqual({
      code: 'UNSUPPORTED',
      message: 'The IAM instance does not provide sendExpiryReminders',
    });
    expect(body.errors.auditRetention).toEqual({
      code: 'CONFLICT',
      message: 'Audit pruning failed for 2 of 4 tenants (broken: Audit chain is locked)',
    });
    expect(body.results.auditRetention).toEqual({
      deleted: 4,
      tenants: { acme: { deleted: 2 }, beta: { deleted: 2 } },
    });
    expect(Object.keys(body.errors).sort()).toEqual(['auditRetention', 'reminders']);
    expect(onError.mock.calls.map(([, task]) => task).sort()).toEqual([
      'auditRetention',
      'reminders',
    ]);
    expect(
      onError.mock.calls.find(([, task]) => task === 'auditRetention')![0].cause,
    ).toMatchObject({ code: 'CONFLICT' });

    // A failure that is not the server's is masked in the body; onError still gets it whole.
    const quiet = { onError: () => {} };
    const masked = vi.fn();
    const maskedResponse = await createBackground(() => iam, { onError: masked }).cron({
      secret,
      tasks: { auditRetention: { retentionMs: 0, tenants: ['offline'] }, events: false },
    })(cronRequest());
    const maskedText = await maskedResponse.text();
    expect(maskedText).not.toMatch(/ECONNREFUSED|10\.0\.0\.5/);
    expect((JSON.parse(maskedText) as CronReport).errors.auditRetention).toEqual({
      code: 'TASK_FAILED',
      message: 'Audit pruning failed for 1 of 1 tenants (offline: The task failed)',
    });
    expect(masked.mock.calls[0]![0].cause).toBe(offline);

    const bare = await read(
      await createBackground(() => ({}) as BackgroundIam, quiet).cron({
        secret,
        tasks: { purge: true, auditRetention: { retentionMs: 0 } },
      })(cronRequest()),
    );
    expect(bare.results).toEqual({});
    expect(
      Object.fromEntries(Object.entries(bare.errors).map(([task, e]) => [task, e.code])),
    ).toEqual({
      purge: 'UNSUPPORTED',
      auditRetention: 'UNSUPPORTED',
      outbox: 'UNSUPPORTED',
      events: 'UNSUPPORTED',
    });
    const noStore = await read(
      await createBackground(() => ({ pruneAudit: iam.pruneAudit }) as BackgroundIam, quiet).cron({
        secret,
        tasks: { auditRetention: { retentionMs: 0 }, outbox: false, events: false },
      })(cronRequest()),
    );
    expect(noStore.errors.auditRetention).toMatchObject({
      code: 'UNSUPPORTED',
      message: expect.stringContaining('auditRetention.tenants'),
    });
    expect(await createBackground(() => ({}) as BackgroundIam).dispatch()).toEqual({});
  });

  it('answers 500 for every task, without internals, when the instance cannot be resolved', async () => {
    const onError = vi.fn();
    const failure = Object.assign(
      new Error("The URL 'libsql://db.internal?authToken=secret' is not in a valid format"),
      { code: 'URL_INVALID' },
    );
    const route = createBackground(
      async (): Promise<BackgroundIam> => {
        throw failure;
      },
      { onError },
    ).cron({ secret });
    const response = await route(cronRequest());
    expect(response.status).toBe(500);
    const text = await response.text();
    expect(text).not.toMatch(/authToken|db\.internal|URL_INVALID/);
    expect(JSON.parse(text)).toEqual({
      ok: false,
      results: {},
      errors: {
        outbox: { code: 'TASK_FAILED', message: 'The task failed' },
        events: { code: 'TASK_FAILED', message: 'The task failed' },
      },
    });
    expect(onError).toHaveBeenCalledOnce();
    expect(onError.mock.calls[0]).toEqual([failure, 'cron']);
  });
});
