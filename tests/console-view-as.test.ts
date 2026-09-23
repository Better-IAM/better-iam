import { afterEach, describe, expect, it, vi } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

// The console's routes import `@/lib/*`; the IAM instance is the test fixture's.
const state = vi.hoisted(() => ({ iam: undefined as unknown }));
vi.mock('@/lib/iam', () => ({ getIam: async () => state.iam }));
vi.mock('@/lib/errors', () => import('../apps/console/src/lib/errors.js'));
vi.mock('@/lib/view-as', () => import('../apps/console/src/lib/view-as.js'));

const viewAs = await import('../apps/console/src/app/api/console/impersonate/route.js');
const iamRoute = await import('../apps/console/src/app/api/iam/[...path]/route.js');

afterEach(closeFixtures);

type Jar = Map<string, string>;

/** Applies Set-Cookie lines the way a browser would (Max-Age=0 deletes). */
function apply(jar: Jar, response: Response): string[] {
  const lines = response.headers.getSetCookie();
  for (const line of lines) {
    const [pair] = line.split(';');
    const index = pair!.indexOf('=');
    const name = pair!.slice(0, index);
    if (/;\s*Max-Age=0(;|$)/.test(line)) jar.delete(name);
    else jar.set(name, pair!.slice(index + 1));
  }
  return lines;
}

function request(
  origin: string,
  path: string,
  jar: Jar,
  init: { method?: string; body?: unknown; headers?: Record<string, string> } = {},
): Request {
  const cookie = [...jar].map(([name, value]) => `${name}=${value}`).join('; ');
  return new Request(`${origin}${path}`, {
    method: init.method ?? 'POST',
    headers: {
      'content-type': 'application/json',
      'x-better-iam': '1',
      origin,
      'user-agent': 'console-test',
      ...(cookie ? { cookie } : {}),
      ...init.headers,
    },
    body:
      init.body === undefined
        ? init.method === 'DELETE'
          ? undefined
          : '{}'
        : JSON.stringify(init.body),
  });
}

async function setup(
  options: { http?: { cookieSameSite?: 'lax' | 'strict' }; baseURL?: string } = {},
) {
  const f = await organizationFixture(options);
  state.iam = f.iam;
  const origin = new URL(options.baseURL ?? 'http://localhost:3000').origin;
  await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
    tenantId: f.tenantId,
    authPolicy: { allowImpersonation: true },
  });
  const alice = await f.member('alice');
  await f.member('bob');
  const jar: Jar = new Map();
  /** Signs the owner in through the console's /api/iam route, as the login page does. */
  const signIn = async (
    persistent: boolean,
    email = 'owner@acme.test',
    password = 'a strong tenant owner password',
  ) => {
    const response = await iamRoute.POST(
      request(origin, '/api/iam/auth/signIn', jar, {
        body: { tenantId: f.tenantId, email, password },
        headers: { 'x-better-iam-persistent': persistent ? '1' : '0' },
      }),
    );
    expect(response.status).toBe(200);
    return apply(jar, response);
  };
  const start = async () => {
    const response = await viewAs.POST(
      request(origin, '/api/console/impersonate', jar, {
        body: { tenantId: f.tenantId, identityId: alice.id, reason: 'ticket 7' },
      }),
    );
    expect(response.status).toBe(200);
    return apply(jar, response);
  };
  const stop = async (from: Jar = jar) => {
    const response = await viewAs.DELETE(
      request(origin, '/api/console/impersonate', from, { method: 'DELETE' }),
    );
    return { response, lines: apply(from, response) };
  };
  const call = (path: string, init: Parameters<typeof request>[3] = {}, from: Jar = jar) =>
    iamRoute.POST(request(origin, `/api/iam/${path}`, from, init));
  const valid = async (token: string | undefined) =>
    f.iam.api.auth.getSession({ token: decodeURIComponent(token!) }).then(
      (session) => session.identity.email,
      (error: { code?: string }) => error.code,
    );
  return { f, jar, signIn, start, stop, call, valid };
}

describe('console view-as cookies', () => {
  it('keep a browser-session sign-in a browser-session cookie with the configured SameSite', async () => {
    const t = await setup({ http: { cookieSameSite: 'strict' } });
    const [signedIn] = await t.signIn(false);
    expect(signedIn).toMatch(/SameSite=Strict; Path=\/$/);
    // The login page records the unticked "Keep me signed in" in a browser-session cookie.
    t.jar.set('better-iam.remember', '0');
    const ownerToken = t.jar.get('better-iam.session');
    const started = await t.start();
    expect(started).toHaveLength(2);
    for (const line of started) {
      expect(line).toContain('SameSite=Strict');
      expect(line).not.toContain('Max-Age');
    }
    expect(t.jar.get('better-iam.impersonator')).toBe(ownerToken);
    expect(await t.valid(t.jar.get('better-iam.session'))).toBe('alice@acme.test');
    const { response, lines } = await t.stop();
    expect(await response.json()).toEqual({ data: { restored: true } });
    const restored = lines.find((line) => line.startsWith('better-iam.session='))!;
    expect(restored).toBe(`better-iam.session=${ownerToken}; HttpOnly; SameSite=Strict; Path=/`);
    expect(t.jar.has('better-iam.impersonator')).toBe(false);
  });

  it('give a persistent sign-in cookies that end with the view-as session, under __Host- on HTTPS', async () => {
    const t = await setup({ baseURL: 'https://console.example.test' });
    await t.signIn(true);
    const started = await t.start();
    expect(started.map((line) => line.split('=')[0]).sort()).toEqual([
      '__Host-better-iam.impersonator',
      '__Host-better-iam.session',
    ]);
    for (const line of started) {
      expect(line).toContain('Secure; SameSite=Lax');
      expect(Number(/Max-Age=(\d+)/.exec(line)?.[1])).toBeGreaterThan(3500);
    }
    const { lines } = await t.stop();
    const restored = lines.find((line) => line.startsWith('__Host-better-iam.session='))!;
    // The administrator's own session has days left.
    expect(Number(/Max-Age=(\d+)/.exec(restored)?.[1])).toBeGreaterThan(86400);
  });
});

describe('console sign-out during view-as', () => {
  it('ends the parked administrator session and clears its cookie', async () => {
    const t = await setup();
    await t.signIn(true);
    const ownerToken = t.jar.get('better-iam.session');
    await t.start();
    const memberToken = t.jar.get('better-iam.session');
    const before = new Map(t.jar);
    const response = await t.call('auth/signOut');
    expect(response.status).toBe(200);
    const lines = apply(t.jar, response);
    expect(lines).toContain('better-iam.impersonator=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
    expect(t.jar.has('better-iam.impersonator')).toBe(false);
    expect(await t.valid(memberToken)).toBe('UNAUTHENTICATED');
    expect(await t.valid(ownerToken)).toBe('UNAUTHENTICATED');
    // Nothing is left to restore: not from the cleared jar, and not from a copy of the old cookies either.
    expect((await t.stop()).response.status).toBe(404);
    const replay = await t.stop(before);
    expect(await replay.response.json()).toEqual({ data: { restored: false } });
    expect(replay.lines).toContain(
      'better-iam.session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0',
    );
  });

  it('also ends it when the member session had already ended (a 401 sign-out)', async () => {
    const t = await setup();
    await t.signIn(true);
    const ownerToken = t.jar.get('better-iam.session');
    await t.start();
    await t.f.iam.api.auth.signOut({ token: decodeURIComponent(t.jar.get('better-iam.session')!) });
    const response = await t.call('auth/signOut');
    expect(response.status).toBe(401);
    apply(t.jar, response);
    expect(t.jar.has('better-iam.impersonator')).toBe(false);
    expect(await t.valid(ownerToken)).toBe('UNAUTHENTICATED');
  });

  it('ends it when a new sign-in replaces the session, and leaves it alone otherwise', async () => {
    const t = await setup();
    await t.signIn(true);
    const ownerToken = t.jar.get('better-iam.session');
    await t.start();
    // Ordinary calls and requests the handler refuses (here: no CSRF header) keep the view-as state.
    const read = await t.call('auth/getSession');
    expect(read.status).toBe(200);
    expect(read.headers.getSetCookie()).toEqual([]);
    const forged = await t.call('auth/signOut', { headers: { 'x-better-iam': '' } });
    expect(forged.status).toBe(403);
    expect(forged.headers.getSetCookie()).toEqual([]);
    expect(await t.valid(ownerToken)).toBe('owner@acme.test');
    // Someone signs in at this browser: the administrator's parked session must not linger.
    const lines = await t.signIn(true, 'bob@acme.test', 'a strong bob password');
    expect(lines.some((line) => line.startsWith('better-iam.impersonator=;'))).toBe(true);
    expect(t.jar.has('better-iam.impersonator')).toBe(false);
    expect(await t.valid(ownerToken)).toBe('UNAUTHENTICATED');
    expect(await t.valid(t.jar.get('better-iam.session'))).toBe('bob@acme.test');
  });
});
