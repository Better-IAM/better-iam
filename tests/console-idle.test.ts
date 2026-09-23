import { act, createElement } from 'react';
import type { Root } from 'react-dom/client';
import { renderToString } from 'react-dom/server';
import { afterAll, afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { builtinEnvironments } from 'vitest/environments';

const nav = await vi.hoisted(async () => {
  // Resolved from the console: that is where its components import next/navigation from.
  const { createRequire } = await import('node:module');
  const { resolve } = await import('node:path');
  return {
    path: createRequire(resolve('apps/console/package.json')).resolve('next/navigation.js'),
    router: { push: vi.fn(), refresh: vi.fn() },
    pathname: { current: '/cloud/acme' },
  };
});
vi.mock(nav.path, () => ({ useRouter: () => nav.router, usePathname: () => nav.pathname.current }));
vi.mock('@/lib/idle', () => import('../apps/console/src/lib/idle.js'));
vi.mock('@/lib/client', () => ({
  describeError: (error: unknown) => ({ code: 'ERROR', message: String(error) }),
}));

// A DOM set up by hand: the happy-dom environment would transform the console's modules for the browser, where its
// `@/` imports (mocked above) are unresolvable. React DOM checks for a DOM when it loads, so it is imported after.
const dom = await builtinEnvironments['happy-dom'].setup(globalThis, {});
afterAll(() => dom.teardown(globalThis));
const { createRoot, hydrateRoot } = await import('react-dom/client');

const idle = await import('../apps/console/src/lib/idle.js');
const { IdleWarning } = await import('../apps/console/src/components/idle-warning.js');
const { SessionEndedNotice, sessionEndedMessage } = await import(
  '../apps/console/src/components/session-notice.js'
);
const { ImpersonationBanner } = await import('../apps/console/src/components/impersonation.js');

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const MIN = 60_000;
const DAY = 24 * 60 * MIN;
const T0 = Date.UTC(2026, 8, 22, 12, 0, 0);
const LOGIN = '/cloud/login?org=acme';

describe('console idle clock', () => {
  const snapshot = { sessionId: 's1', idleTimeoutMs: 15 * MIN, expiresAt: T0 + 60 * MIN };

  it('keeps deadlines on the server clock whatever the browser clock says', () => {
    for (const skew of [2 * 60 * MIN, 10 * MIN, 0, -10 * MIN, -2 * 60 * MIN]) {
      const clock = idle.clockFrom(snapshot, T0, T0 + skew);
      expect(clock.lastTouch).toBe(T0);
      expect(idle.idleState(clock, T0 + skew + 1_000)).toEqual({ kind: 'active' });
      expect(idle.idleState(clock, T0 + skew + 13 * MIN + 1_000)).toMatchObject({
        kind: 'warning',
        absolute: false,
      });
      expect(idle.idleState(clock, T0 + skew + 15 * MIN)).toEqual({ kind: 'due', reason: 'idle' });
    }
    // Near the absolute end the warning says so, and the deadline is the session's expiry.
    const late = idle.clockFrom(snapshot, T0 + 50 * MIN, T0 + 50 * MIN + 2 * 60 * MIN);
    expect(idle.idleState(late, T0 + 58 * MIN + 2 * 60 * MIN + 1_000)).toMatchObject({
      kind: 'warning',
      absolute: true,
    });
    expect(idle.idleState(late, T0 + 60 * MIN + 2 * 60 * MIN)).toEqual({
      kind: 'due',
      reason: 'expired',
    });
    // An older server without `limits.now` keeps the previous offset.
    expect(idle.clockFrom(snapshot, undefined, T0 + 5_000, -5_000).lastTouch).toBe(T0);
  });

  it('follows newer renders, touches, and other tabs, and ignores older ones', () => {
    const clock = idle.clockFrom(snapshot, T0 + 10 * MIN, T0 + 10 * MIN + 500);
    // A replayed (cached) render of the same session changes neither the touch nor the offset.
    const replay = idle.clockFromRender(clock, snapshot, T0, T0 + 20 * MIN);
    expect(replay).toMatchObject({ lastTouch: T0 + 10 * MIN, offset: -500 });
    const fresh = idle.clockFromRender(clock, snapshot, T0 + 20 * MIN, T0 + 20 * MIN + 100);
    expect(fresh).toMatchObject({ lastTouch: T0 + 20 * MIN, offset: -100 });
    const replaced = idle.clockFromRender(
      clock,
      { sessionId: 's2', idleTimeoutMs: 30 * MIN, expiresAt: T0 + DAY },
      T0 + 5 * MIN,
      T0 + 20 * MIN,
    );
    expect(replaced).toMatchObject({
      sessionId: 's2',
      idleTimeoutMs: 30 * MIN,
      lastTouch: T0 + 5 * MIN,
    });
    expect(idle.touchedAt(clock, T0).lastTouch).toBe(T0 + 10 * MIN);
    expect(idle.touchedAt(clock, T0 + 12 * MIN).lastTouch).toBe(T0 + 12 * MIN);
    const touch = { type: 'touch' as const, ...snapshot, at: T0 + 11 * MIN };
    expect(idle.mergeTouch(clock, touch).lastTouch).toBe(T0 + 11 * MIN);
    expect(idle.mergeTouch(clock, { ...touch, at: T0 })).toBe(clock);
    expect(idle.mergeTouch(clock, { ...touch, sessionId: 's2' }).sessionId).toBe('s2');
    expect(idle.parseIdleMessage({ type: 'touch', sessionId: 's1', at: 'soon' })).toBeUndefined();
    expect(idle.parseIdleMessage({ type: 'ended', sessionId: 's1', reason: '__proto__' })).toEqual({
      type: 'ended',
      sessionId: 's1',
    });
  });

  it('treats only a definite 401 as the end of the session', () => {
    const data = {
      session: { id: 's1', expiresAt: T0 + DAY },
      limits: { idleTimeoutMs: MIN, now: T0 },
    };
    expect(idle.classifyTouch(200, { data })).toEqual({
      kind: 'ok',
      sessionId: 's1',
      expiresAt: T0 + DAY,
      idleTimeoutMs: MIN,
      serverNow: T0,
    });
    const error = (code: string) => ({ error: { code, message: code } });
    expect(idle.classifyTouch(401, error('UNAUTHENTICATED'))).toEqual({ kind: 'gone' });
    expect(idle.classifyTouch(401, error('SESSION_NETWORK_MISMATCH'))).toEqual({ kind: 'gone' });
    expect(idle.classifyTouch(500, error('INTERNAL_ERROR'))).toEqual({ kind: 'retry' });
    expect(idle.classifyTouch(503, undefined)).toEqual({ kind: 'retry' });
    expect(idle.classifyTouch(429, error('RATE_LIMITED'))).toEqual({ kind: 'retry' });
    expect(idle.classifyTouch(200, { data: {} })).toEqual({ kind: 'retry' });
    expect(idle.classifyTouch(403, error('MFA_REQUIRED'))).toEqual({ kind: 'denied' });
    expect(idle.classifyTouch(401, undefined)).toEqual({ kind: 'denied' });
    const clock = idle.clockFrom(snapshot, T0, T0);
    expect(idle.goneReason(clock, T0 + MIN)).toBe('ended');
    expect(idle.goneReason(clock, T0 + 14 * MIN)).toBe('idle');
    expect(idle.goneReason(null, T0)).toBe('ended');
    expect(idle.loginUrl(LOGIN, 'idle')).toBe(`${LOGIN}&reason=idle`);
    expect(idle.loginUrl('/admin/login', 'ended')).toBe('/admin/login?reason=ended');
  });
});

describe('IdleWarning', () => {
  type Reply = { status: number; body?: unknown } | 'offline';
  let replies: Reply[];
  let calls: string[];
  let container: HTMLElement;
  let root: Root | undefined;
  const ok = (
    sessionId: string,
    now: number,
    expiresAt = T0 + 7 * DAY,
    idleTimeoutMs = 15 * MIN,
  ) => ({
    status: 200,
    body: { data: { session: { id: sessionId, expiresAt }, limits: { idleTimeoutMs, now } } },
  });
  const unauthenticated = { status: 401, body: { error: { code: 'UNAUTHENTICATED' } } };
  const props = (extra: Partial<Parameters<typeof IdleWarning>[0]> = {}) => ({
    sessionId: 's1',
    idleTimeoutMs: 15 * MIN,
    expiresAt: T0 + 7 * DAY,
    serverNow: T0,
    loginHref: LOGIN,
    ...extra,
  });
  const render = async (value: ReturnType<typeof props>) => {
    root ??= createRoot(container);
    await act(async () => root!.render(createElement(IdleWarning, value)));
  };
  const advance = async (ms: number) => {
    await act(async () => {
      await vi.advanceTimersByTimeAsync(ms);
    });
  };
  const activity = async () => {
    await act(async () => {
      window.dispatchEvent(new Event('pointerdown'));
      await vi.advanceTimersByTimeAsync(0);
    });
  };

  class FakeChannel {
    static open = new Set<FakeChannel>();
    onmessage: ((event: { data: unknown }) => void) | null = null;
    constructor(readonly name: string) {
      FakeChannel.open.add(this);
    }
    postMessage(data: unknown) {
      for (const other of FakeChannel.open)
        if (other !== this && other.name === this.name) other.onmessage?.({ data });
    }
    close() {
      FakeChannel.open.delete(this);
    }
  }

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(T0);
    vi.stubGlobal('BroadcastChannel', FakeChannel);
    FakeChannel.open.clear();
    nav.router.push.mockClear();
    nav.router.refresh.mockClear();
    nav.pathname.current = '/cloud/acme';
    replies = [];
    calls = [];
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string) => {
        const path = String(url).replace('/api/iam/', '');
        calls.push(path);
        const reply: Reply =
          path === 'auth/signOut'
            ? { status: 200, body: { data: { success: true } } }
            : (replies.shift() ?? { status: 500 });
        if (reply === 'offline') throw new TypeError('Failed to fetch');
        return { status: reply.status, ok: reply.status < 300, json: async () => reply.body };
      }),
    );
    container = document.createElement('div');
    document.body.append(container);
  });

  afterEach(async () => {
    if (root) await act(async () => root!.unmount());
    root = undefined;
    container.remove();
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it('does not sign a fast-clocked browser out early, and warns before the real maximum length', async () => {
    vi.setSystemTime(T0 + 2 * 60 * MIN);
    await render(props({ idleTimeoutMs: DAY, expiresAt: T0 + 60 * MIN }));
    await advance(5_000);
    expect(nav.router.push).not.toHaveBeenCalled();
    expect(container.textContent).toBe('');
    await advance(58 * MIN);
    expect(container.textContent).toContain('maximum length in 1:55');
    replies.push(unauthenticated);
    await advance(2 * MIN);
    expect(calls).toEqual(['auth/getSession']);
    expect(nav.router.push).toHaveBeenCalledWith(`${LOGIN}&reason=expired`);
  });

  it('signs the session out on the server at the idle deadline before leaving', async () => {
    await render(props());
    await advance(13 * MIN + 1_000);
    expect(container.textContent).toContain('signed out in 1:59');
    // The server still accepts the session (its own clock was touched by something this tab did not see).
    replies.push(ok('s1', T0 + 15 * MIN));
    await advance(2 * MIN);
    expect(calls).toEqual(['auth/getSession', 'auth/signOut']);
    expect(nav.router.push).toHaveBeenCalledTimes(1);
    expect(nav.router.push).toHaveBeenCalledWith(`${LOGIN}&reason=idle`);
  });

  it('does not sign out a newer session that another tab started', async () => {
    await render(props());
    replies.push(ok('s2', T0 + 15 * MIN));
    await advance(15 * MIN);
    expect(calls).toEqual(['auth/getSession']);
    expect(nav.router.push).not.toHaveBeenCalled();
    expect(nav.router.refresh).toHaveBeenCalled();
    expect(container.textContent).toBe('');
  });

  it('counts navigations and other tabs as touches, and shares its own', async () => {
    const other = new FakeChannel(idle.IDLE_CHANNEL);
    const heard: unknown[] = [];
    other.onmessage = (event) => heard.push(event.data);
    await render(props());
    expect(heard).toContainEqual(
      expect.objectContaining({ type: 'touch', sessionId: 's1', at: T0 }),
    );
    await advance(10 * MIN);
    nav.pathname.current = '/cloud/acme/members';
    await render(props());
    expect(heard).toContainEqual(expect.objectContaining({ type: 'touch', at: T0 + 10 * MIN }));
    await advance(10 * MIN);
    expect(container.textContent).toBe('');
    // Another tab is used at minute 20.
    await act(async () =>
      other.postMessage({ type: 'touch', ...props(), at: T0 + 20 * MIN, sessionId: 's1' }),
    );
    await advance(12 * MIN);
    expect(container.textContent).toBe('');
    expect(nav.router.push).not.toHaveBeenCalled();
    await advance(2 * MIN);
    expect(container.textContent).toContain('inactive');
    // Signing out in another tab ends this one too.
    await act(async () => other.postMessage({ type: 'ended', sessionId: 's1' }));
    expect(nav.router.push).toHaveBeenCalledWith(LOGIN);
    expect(calls).toEqual([]);
  });

  it('follows new props when the session is replaced while a warning shows', async () => {
    vi.setSystemTime(T0 + 58 * MIN);
    await render(props({ sessionId: 'view', expiresAt: T0 + 60 * MIN, serverNow: T0 + 58 * MIN }));
    await advance(1_000);
    expect(container.textContent).toContain('maximum length');
    // "Stop viewing as" restored the administrator's own session, which has days left.
    await render(props({ sessionId: 'admin', serverNow: T0 + 58 * MIN + 1_000 }));
    expect(container.textContent).toBe('');
    await advance(5 * MIN);
    expect(nav.router.push).not.toHaveBeenCalled();
    expect(calls).toEqual([]);
  });

  it('leaves only when the server says the session is gone, backing off after failures', async () => {
    await render(props());
    await advance(6 * MIN);
    replies.push({ status: 500, body: { error: { code: 'INTERNAL_ERROR' } } });
    await activity();
    await activity();
    expect(calls).toHaveLength(1);
    for (const reply of [
      { status: 429, body: { error: { code: 'RATE_LIMITED' } } },
      'offline' as const,
      { status: 403, body: { error: { code: 'MFA_REQUIRED' } } },
    ]) {
      await advance(idle.RETRY_MS);
      replies.push(reply);
      await activity();
    }
    expect(calls).toHaveLength(4);
    expect(nav.router.push).not.toHaveBeenCalled();
    await advance(idle.RETRY_MS);
    replies.push(unauthenticated);
    await activity();
    // Revoked elsewhere, long before any deadline: a neutral reason, not "maximum length".
    expect(nav.router.push).toHaveBeenCalledWith(`${LOGIN}&reason=ended`);
  });

  it('keeps an active person signed in with a ping that re-derives the clock offset', async () => {
    // The page was rendered at server time T0 and arrives with this browser's clock reading ten minutes later.
    vi.setSystemTime(T0 + 10 * MIN);
    await render(props({ serverNow: T0 }));
    await advance(6 * MIN);
    // The ping's `limits.now` shows the server is only five minutes behind: deadlines move by that.
    replies.push(ok('s1', T0 + 11 * MIN));
    await activity();
    expect(calls).toEqual(['auth/getSession']);
    await advance(12 * MIN);
    expect(container.textContent).toBe('');
    await advance(90_000);
    expect(container.textContent).toContain('signed out in 1:30');
  });
});

describe('login-page reasons', () => {
  it('explains known reasons and ignores anything else, including inherited names', () => {
    expect(sessionEndedMessage('idle')).toContain('inactivity');
    expect(sessionEndedMessage('expired')).toContain('maximum length');
    expect(sessionEndedMessage('ended')).toContain('ended');
    for (const reason of [
      '__proto__',
      'toString',
      'constructor',
      'hasOwnProperty',
      'bogus',
      '',
      undefined,
    ])
      expect(sessionEndedMessage(reason)).toBeUndefined();
    expect(renderToString(createElement(SessionEndedNotice, { reason: '__proto__' }))).toBe('');
    expect(renderToString(createElement(SessionEndedNotice, { reason: 'toString' }))).toBe('');
    expect(renderToString(createElement(SessionEndedNotice, { reason: 'idle' }))).toContain(
      'alert info',
    );
  });
});

describe('ImpersonationBanner', () => {
  it('formats the end time in the browser only, so hydration never disagrees', async () => {
    const zone = process.env.TZ;
    const expiresAt = Date.UTC(2026, 8, 22, 15, 45, 0);
    try {
      process.env.TZ = 'UTC';
      const banner = createElement(ImpersonationBanner, {
        memberName: 'Alice',
        expiresAt,
        base: '/cloud/acme',
      });
      const html = renderToString(banner);
      expect(html).toContain('Viewing as');
      expect(html).not.toContain('Ends');
      // The administrator's browser is elsewhere.
      process.env.TZ = 'Asia/Tokyo';
      const container = document.createElement('div');
      container.innerHTML = html;
      document.body.append(container);
      const errors: unknown[] = [];
      let root: Root | undefined;
      await act(async () => {
        root = hydrateRoot(container, banner, {
          onRecoverableError: (error) => errors.push(error),
        });
      });
      expect(errors).toEqual([]);
      expect(container.textContent).toContain(`Ends ${new Date(expiresAt).toLocaleTimeString()}.`);
      await act(async () => root!.unmount());
      container.remove();
    } finally {
      if (zone === undefined) delete process.env.TZ;
      else process.env.TZ = zone;
    }
  });
});
