import { createHmac } from 'node:crypto';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';
import { betterIam, verifyWebhookSignature } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  AssertionError,
  createIamMiddleware,
  createIamNext,
  createWebhookHandler,
  matchPath,
  parseSetCookie,
  pathnameHeader,
  safeRedirectPath,
  verifyAssertionToken,
  verifyWebhook,
  withAssertion,
  type CookieOptions,
} from '@better-iam/next';
import type { IamStore } from '@better-iam/core';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
const noParams = { params: Promise.resolve({}) };
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const iam = betterIam({
    database,
    secret: 'next-integration-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    permissions: { actions: ['documents:read', 'documents:write'] },
    resolveResource: async (reference) => reference,
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const member = await iam.api.identities.create(
    { token: session.token },
    {
      tenantId: root.tenant.id,
      email: 'member@example.test',
      name: 'Member',
      password: 'a strong member test password',
    },
  );
  const login = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'member@example.test',
    password: 'a strong member test password',
  });
  if (!('token' in login)) throw new Error('Unexpected MFA');
  return {
    iam,
    tenantId: root.tenant.id,
    member,
    memberToken: login.token,
    cookie: `better-iam.session=${login.token}`,
    rootToken: session.token,
    totpSecret: enrollment.secret as string,
  };
}

/** A stand-in for Next's cookies() store: records writes and serializes like RequestCookies. */
function cookieJar(initial: Record<string, string> = {}) {
  const values = new Map(Object.entries(initial));
  const writes: { name: string; value: string; options?: CookieOptions }[] = [];
  return {
    writes,
    values,
    set(name: string, value: string, options?: CookieOptions) {
      writes.push({ name, value, options });
      if (options?.maxAge === 0) values.delete(name);
      else values.set(name, value);
    },
    toString() {
      return [...values].map(([name, value]) => `${name}=${encodeURIComponent(value)}`).join('; ');
    },
  };
}
class Interrupt extends Error {
  constructor(readonly target: string) {
    super(`INTERRUPT:${target}`);
  }
}
const throwing = (target: string) => (): never => {
  throw new Interrupt(target);
};
const redirect = (url: string): never => {
  throw new Interrupt(`redirect:${url}`);
};

describe('Next.js integration helpers', () => {
  it('signs in and out from server actions through the in-process typed client, syncing cookies', async () => {
    const f = await fixture();
    const jar = cookieJar();
    const iamNext = createIamNext(f.iam, {
      headers: () => new Headers({ cookie: jar.toString(), 'user-agent': 'vitest-browser' }),
      cookies: () => jar,
      redirect,
    });
    expect(await iamNext.getSession()).toBeNull();
    const client = iamNext.client();
    const result = await client.auth.signIn({
      tenantId: f.tenantId,
      email: 'member@example.test',
      password: 'a strong member test password',
    });
    expect('token' in result).toBe(true);
    expect(jar.writes).toHaveLength(1);
    expect(jar.writes[0]).toMatchObject({
      name: 'better-iam.session',
      options: { httpOnly: true, sameSite: 'lax', path: '/' },
    });
    expect(jar.writes[0]!.options!.maxAge).toBeGreaterThan(0);
    const session = await iamNext.getSession(new Headers({ cookie: jar.toString() }));
    expect(session?.identity.id).toBe(f.member.id);
    expect(session?.session.client?.userAgent).toBe('vitest-browser');
    const current = await iamNext.client().auth.getSession();
    expectTypeOf(current.identity.id).toEqualTypeOf<string>();
    expect(current.identity.id).toBe(f.member.id);
    await iamNext.client().auth.signOut();
    expect(jar.writes.at(-1)).toMatchObject({ name: 'better-iam.session', value: '' });
    expect(jar.writes.at(-1)!.options!.maxAge).toBe(0);
    expect(await iamNext.getSession(new Headers({ cookie: jar.toString() }))).toBeNull();
    await expect(
      iamNext.client().auth.signIn({
        tenantId: f.tenantId,
        email: 'member@example.test',
        password: 'the wrong password entirely',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS', status: 401 });

    const rootJar = cookieJar();
    const rootNext = createIamNext(f.iam, {
      headers: () => new Headers({ cookie: rootJar.toString() }),
      cookies: () => rootJar,
    });
    const challenge = await rootNext.client().auth.signIn({
      tenantId: f.tenantId,
      email: 'root@example.test',
      password: 'a strong root test password',
    });
    if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
    expect(rootJar.writes).toHaveLength(0);
    await rootNext.client().auth.verifyMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
      // The fixture spent this window's code; replay protection requires the next one (within the accepted drift).
      code: Object.assign(authenticator.clone(), {
        options: { epoch: Date.now() + 30_000 },
      }).generate(f.totpSecret),
      rememberDevice: true,
    });
    expect(rootJar.writes.map((write) => write.name).sort()).toEqual(['better-iam.session']);
    expect((await rootNext.getSession())?.session.mfa).toBe(true);

    const readOnly = createIamNext(f.iam, {
      headers: () => new Headers(),
      cookies: () => ({
        set() {
          throw new Error('Cookies can only be modified in a Server Action or Route Handler');
        },
        toString: () => '',
      }),
    });
    await expect(
      readOnly.client().auth.signIn({
        tenantId: f.tenantId,
        email: 'member@example.test',
        password: 'a strong member test password',
      }),
    ).rejects.toThrow(/server action or route handler/);
  });

  it('guards route handlers with JSON errors, params, and authorization', async () => {
    const f = await fixture();
    const iamNext = createIamNext(f.iam, { headers: () => new Headers() });
    const GET = iamNext.route<{ id: string }>(
      async (_request, { session, params }) => ({ id: params.id, who: session.identity.id }),
      {
        authorize: {
          action: 'documents:read',
          resource: ({ params }) => ({ type: 'document', id: params.id }),
        },
      },
    );
    const call = (headers: HeadersInit) =>
      GET(new Request('http://localhost:3000/api/docs/a', { headers }), {
        params: Promise.resolve({ id: 'a' }),
      });
    const anonymous = await call({});
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toMatchObject({ error: { code: 'UNAUTHENTICATED' } });
    const denied = await call({ cookie: f.cookie });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: { code: 'ACCESS_DENIED' } });
    const allowed = await call({ authorization: `Bearer ${f.rootToken}` });
    expect(allowed.status).toBe(200);
    expect(await allowed.json()).toMatchObject({ id: 'a' });
    const DELETE = iamNext.route(() => undefined);
    expect(
      (
        await DELETE(
          new Request('http://localhost:3000/x', { headers: { cookie: f.cookie } }),
          noParams,
        )
      ).status,
    ).toBe(204);
    const broken = iamNext.route(() => {
      throw new Error('boom');
    });
    await expect(
      broken(new Request('http://localhost:3000/x', { headers: { cookie: f.cookie } }), noParams),
    ).rejects.toThrow('boom');
  });

  it('wraps server actions with ActionResult and lets Next control flow through', async () => {
    const f = await fixture();
    let headers = new Headers();
    const iamNext = createIamNext(f.iam, { headers: () => headers, cache: (fn) => fn });
    const save = iamNext.action(
      async (session, id: string, title: string) => ({ id, title, by: session.identity.id }),
      {
        authorize: {
          action: 'documents:write',
          resource: ({ args: [id] }) => ({ type: 'document', id }),
        },
      },
    );
    expect(await save('a', 'Title')).toEqual({
      ok: false,
      error: { code: 'UNAUTHENTICATED', message: 'Sign in to continue' },
    });
    headers = new Headers({ cookie: f.cookie });
    expect(await save('a', 'Title')).toMatchObject({ ok: false, error: { code: 'ACCESS_DENIED' } });
    headers = new Headers({ authorization: `Bearer ${f.rootToken}` });
    const saved = await save('a', 'Title');
    expect(saved).toMatchObject({ ok: true, data: { id: 'a', title: 'Title' } });
    if (saved.ok) expectTypeOf(saved.data.title).toEqualTypeOf<string>();
    const redirecting = iamNext.action(async () => {
      throw Object.assign(new Error('NEXT_REDIRECT'), {
        digest: 'NEXT_REDIRECT;replace;/done;307;',
      });
    });
    await expect(redirecting()).rejects.toThrow('NEXT_REDIRECT');

    // Interrupts and redirects are for pages: actions and route handlers report denials themselves.
    const interrupting = createIamNext(f.iam, {
      headers: () => new Headers({ cookie: f.cookie }),
      cache: (fn) => fn,
      interrupts: true,
      forbidden: throwing('forbidden'),
      unauthorized: throwing('unauthorized'),
    });
    const guarded = interrupting.action(async () => 'written', {
      authorize: { action: 'documents:write' },
    });
    expect(await guarded()).toMatchObject({ ok: false, error: { code: 'ACCESS_DENIED' } });
    const guardedRoute = interrupting.route(() => 'read', {
      authorize: { action: 'documents:read' },
    });
    expect(
      (
        await guardedRoute(
          new Request('http://localhost:3000/x', { headers: { cookie: f.cookie } }),
          noParams,
        )
      ).status,
    ).toBe(403);
    const forbiddenOnly = createIamNext(f.iam, {
      headers: () => new Headers({ [pathnameHeader]: '/x' }),
      redirect,
      interrupts: 'forbidden',
      forbidden: throwing('forbidden'),
    });
    await expect(forbiddenOnly.requireSession()).rejects.toThrow(
      'INTERRUPT:redirect:/login?next=%2Fx',
    );
  });

  it('protects pages with forwarded return paths, interrupts, and a per-request session cache', async () => {
    const f = await fixture();
    let headers = new Headers({ [pathnameHeader]: '/documents/a?tab=history' });
    const iamNext = createIamNext(f.iam, {
      loginPath: '/signin',
      headers: () => headers,
      redirect,
    });
    const Page = iamNext.page(
      async (_props: { params: Promise<{ id: string }> }, { session, params }) =>
        `${params.id}:${session.identity.name}`,
      {
        authorize: {
          action: 'documents:read',
          resource: ({ params }) => ({ type: 'document', id: params.id }),
          redirectTo: '/forbidden',
        },
      },
    );
    const props = { params: Promise.resolve({ id: 'a' }) };
    await expect(Page(props)).rejects.toThrow(
      'INTERRUPT:redirect:/signin?next=%2Fdocuments%2Fa%3Ftab%3Dhistory',
    );
    headers = new Headers({ [pathnameHeader]: '//evil.example/x' });
    await expect(Page(props)).rejects.toThrow('INTERRUPT:redirect:/signin');
    // A stale cookie (revoked or from a reset database) always gets ?next=, which the middleware respects.
    headers = new Headers({ cookie: 'better-iam.session=revoked-token-value-0000000000000000' });
    await expect(Page(props)).rejects.toThrow('INTERRUPT:redirect:/signin?next=%2F');
    headers = new Headers({ cookie: f.cookie });
    await expect(Page(props)).rejects.toThrow('INTERRUPT:redirect:/forbidden');
    headers = new Headers({ authorization: `Bearer ${f.rootToken}` });
    expect(await Page(props)).toBe('a:Root');

    const interrupting = createIamNext(f.iam, {
      headers: () => headers,
      interrupts: true,
      unauthorized: throwing('unauthorized'),
      forbidden: throwing('forbidden'),
    });
    headers = new Headers();
    await expect(interrupting.requireSession()).rejects.toThrow('INTERRUPT:unauthorized');
    headers = new Headers({ cookie: f.cookie });
    await expect(
      interrupting.require({
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'a' },
      }),
    ).rejects.toThrow('INTERRUPT:forbidden');

    let reads = 0;
    const counting = {
      ...f.iam,
      api: {
        ...f.iam.api,
        auth: {
          ...f.iam.api.auth,
          getSession: (credential: Parameters<typeof f.iam.api.auth.getSession>[0]) => {
            reads++;
            return f.iam.api.auth.getSession(credential);
          },
        },
      },
    };
    const memo = new Map<unknown, unknown>();
    const cached = createIamNext(counting, {
      headers: () => new Headers({ cookie: f.cookie }),
      cache: <F extends (...args: never[]) => unknown>(fn: F) =>
        ((...args: never[]) => {
          if (!memo.has(fn)) memo.set(fn, fn(...args));
          return memo.get(fn);
        }) as F,
    });
    await cached.getSession();
    await cached.requireSession();
    expect(reads).toBe(1);
    await cached.getSession(new Headers({ cookie: f.cookie }));
    expect(reads).toBe(2);
    const plain = await cached.sessionForClient();
    expect(plain?.identity.id).toBe(f.member.id);
  });

  it('batches allowed() checks per request and renders server <Can>', async () => {
    const f = await fixture();
    const batches: number[] = [];
    const counting = {
      ...f.iam,
      authorizeMany: (request: Parameters<typeof f.iam.authorizeMany>[0]) => {
        batches.push(request.checks.length);
        return f.iam.authorizeMany(request);
      },
    };
    // One Map per simulated request, standing in for React's per-render cache.
    const perRequest = () => {
      const memo = new Map<unknown, unknown>();
      return <F extends (...args: never[]) => unknown>(fn: F) =>
        ((...args: never[]) => {
          if (!memo.has(fn)) memo.set(fn, fn(...args));
          return memo.get(fn);
        }) as F;
    };
    const root = createIamNext(counting, {
      headers: () => new Headers({ authorization: `Bearer ${f.rootToken}` }),
      cache: perRequest(),
    });
    const doc = { type: 'document', id: 'a' };
    expect(
      await Promise.all([
        root.allowed('documents:read', doc),
        root.allowed('documents:write', doc),
        root.allowed('documents:read', doc),
        root.allowed('iam:identities:read'),
      ]),
    ).toEqual([true, true, true, true]);
    expect(batches).toEqual([3]);
    expect(await root.allowed('documents:read', doc)).toBe(true);
    expect(batches).toEqual([3]);
    await Promise.all(
      Array.from({ length: 60 }, (_, index) =>
        root.allowed('documents:read', { type: 'document', id: `d${index}` }),
      ),
    );
    expect(batches).toEqual([3, 50, 10]);

    const member = createIamNext(counting, {
      headers: () => new Headers({ cookie: f.cookie }),
      cache: perRequest(),
    });
    expect(
      await member.Can({
        action: 'documents:read',
        resource: doc,
        children: 'yes',
        fallback: 'no',
      }),
    ).toBe('no');
    expect(await root.Can({ action: 'documents:read', resource: doc, children: 'yes' })).toBe(
      'yes',
    );
    const anonymous = createIamNext(counting, {
      headers: () => new Headers(),
      cache: perRequest(),
    });
    batches.length = 0;
    expect(await anonymous.allowed('documents:read', doc)).toBe(false);
    expect(await anonymous.Can({ action: 'documents:read', children: 'yes' })).toBeNull();
    expect(batches).toEqual([]);
  });
  it('routes organization aliases to tenant sessions', async () => {
    const f = await fixture();
    await f.iam.api.tenants.setSlug({ token: f.rootToken }, { tenantId: f.tenantId, slug: 'acme' });
    let headers = new Headers({ [pathnameHeader]: '/acme/settings' });
    const iamNext = createIamNext(f.iam, {
      headers: () => headers,
      redirect,
      notFound: throwing('notFound'),
    });
    expect(await iamNext.tenant('acme')).toMatchObject({ tenantId: f.tenantId, slug: 'acme' });
    expect(await iamNext.tenant('missing')).toBeNull();
    await expect(iamNext.requireTenantSession({ slug: 'missing' })).rejects.toThrow(
      'INTERRUPT:notFound',
    );
    await expect(iamNext.requireTenantSession({ slug: 'acme' })).rejects.toThrow(
      'INTERRUPT:redirect:/login?org=acme&next=%2Facme%2Fsettings',
    );
    headers = new Headers({ cookie: f.cookie });
    const { tenant, session } = await iamNext.requireTenantSession({ slug: 'acme' });
    expect(tenant.name).toBeTruthy();
    expect(session.identity.id).toBe(f.member.id);
  });

  it('extends middleware with public globs, signed-in redirects, and path forwarding', () => {
    const forwarded: Headers[] = [];
    const next = (init: { request: { headers: Headers } }) => {
      forwarded.push(init.request.headers);
      return new Response(null, { headers: { 'x-middleware-next': '1' } });
    };
    const middleware = createIamMiddleware({
      loginPath: '/signin',
      publicPaths: ['/docs/**', '/invite/*'],
      signedInRedirect: '/dashboard',
      next,
    });
    const request = (url: string, cookies: string[] = []) => ({
      nextUrl: new URL(url),
      cookies: { has: (name: string) => cookies.includes(name) },
      headers: new Headers({ 'x-custom': '1' }),
    });
    expect(
      middleware(request('http://localhost:3000/docs/a/b'))!.headers.get('x-middleware-next'),
    ).toBe('1');
    expect(forwarded.at(-1)!.get(pathnameHeader)).toBe('/docs/a/b');
    expect(forwarded.at(-1)!.get('x-custom')).toBe('1');
    expect(middleware(request('http://localhost:3000/invite/abc'))!.status).toBe(200);
    expect(middleware(request('http://localhost:3000/invite/abc/def'))!.status).toBe(307);
    const signedIn = ['better-iam.session'];
    expect(
      middleware(request('http://localhost:3000/signin', signedIn))!.headers.get('location'),
    ).toBe('http://localhost:3000/dashboard');
    // A login visit with ?next= came from a server guard that found the cookie stale: it must render, or the guard
    // and the middleware would bounce the visitor between them forever.
    const bounced = middleware(
      request('http://localhost:3000/signin?next=%2Freports%3Fq%3D1', signedIn),
    )!;
    expect(bounced.headers.get('location')).toBeNull();
    expect(bounced.headers.get('x-middleware-next')).toBe('1');
    middleware(request('http://localhost:3000/projects/1?x=2', signedIn));
    expect(forwarded.at(-1)!.get(pathnameHeader)).toBe('/projects/1?x=2');

    expect(safeRedirectPath('/a/b?c=1#d')).toBe('/a/b?c=1#d');
    expect(safeRedirectPath('//evil.test')).toBe('/');
    // Dot segments must not normalize into a protocol-relative redirect.
    for (const payload of [
      '/.//evil.test',
      '/..//evil.test',
      '/a/..//evil.test',
      '/%2e//evil.test',
      '/%2E%2E//evil.test',
    ])
      expect(safeRedirectPath(payload), payload).toBe('/');
    expect(safeRedirectPath('/a/../b/./c?x=1#y')).toBe('/b/c?x=1#y');
    expect(safeRedirectPath('/\\evil.test')).toBe('/');
    expect(safeRedirectPath('https://evil.test', '/home')).toBe('/home');
    expect(safeRedirectPath('/a\nb')).toBe('/');
    expect(safeRedirectPath(undefined)).toBe('/');
    expect(matchPath('/docs/**', '/docs/a/b')).toBe(true);
    expect(matchPath('/docs/*', '/docs/a/b')).toBe(false);
    expect(matchPath('/a.b', '/axb')).toBe(false);
    expect(
      parseSetCookie(
        '__Host-better-iam.session=a%2Bb; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=60',
      ),
    ).toEqual({
      name: '__Host-better-iam.session',
      value: 'a+b',
      options: { httpOnly: true, secure: true, sameSite: 'lax', path: '/', maxAge: 60 },
    });
    expect(parseSetCookie('garbage')).toBeUndefined();
  });

  it('verifies assertions at the edge exactly like the server', async () => {
    const f = await fixture();
    const issued = await f.iam.api.assertions.issue(
      { token: f.rootToken },
      { tenantId: f.tenantId, audience: 'reports', claims: { plan: 'pro' } },
    );
    const key = f.iam.assertionKey();
    const claims = await verifyAssertionToken(issued.token, { key, audience: 'reports' });
    expect(claims).toEqual(issued.claims);
    await expect(verifyAssertionToken(issued.token, { key, audience: 'billing' })).rejects.toThrow(
      'Audience mismatch',
    );
    const [header, payload, signature] = issued.token.split('.');
    const flipped = `${header}.${payload}.${signature!.slice(0, -2)}${signature!.endsWith('AA') ? 'AB' : 'AA'}`;
    await expect(
      verifyAssertionToken(flipped, { key, audience: 'reports' }),
    ).rejects.toBeInstanceOf(AssertionError);
    await expect(
      verifyAssertionToken(issued.token, {
        key,
        audience: 'reports',
        now: (issued.expiresAt as number) + 60_000,
      }),
    ).rejects.toThrow('Assertion expired');
    await expect(
      verifyAssertionToken(issued.token, { key, audience: 'reports', issuer: 'https://other' }),
    ).rejects.toThrow('Issuer mismatch');

    const GET = withAssertion(
      { key, audience: 'reports', authorize: (verified) => verified.mfa },
      async (_request, { claims: verified }) => Response.json({ tenant: verified.tid }),
    );
    expect((await GET(new Request('http://svc/x'), undefined)).status).toBe(401);
    expect(
      (
        await GET(
          new Request('http://svc/x', { headers: { authorization: 'Bearer nope.nope.nope' } }),
          undefined,
        )
      ).status,
    ).toBe(401);
    const ok = await GET(
      new Request('http://svc/x', { headers: { authorization: `Bearer ${issued.token}` } }),
      undefined,
    );
    expect(await ok.json()).toEqual({ tenant: f.tenantId });
    const strict = withAssertion({ key, audience: 'reports', authorize: () => false }, async () =>
      Response.json({}),
    );
    expect(
      (
        await strict(
          new Request('http://svc/x', { headers: { authorization: `Bearer ${issued.token}` } }),
          undefined,
        )
      ).status,
    ).toBe(403);
  });

  it('receives signed webhooks with rotation, freshness, and retry semantics', async () => {
    const secret = 'whsec_current_secret_value';
    const body = JSON.stringify({
      id: 'evt_1',
      type: 'identity:create',
      tenantId: 't1',
      outcome: 'success',
      timestamp: Date.now(),
    });
    const timestamp = Math.floor(Date.now() / 1000);
    const sign = (key: string, at = timestamp, payload = body) =>
      `v1=${createHmac('sha256', key).update(`${at}.${payload}`).digest('hex')}`;
    expect(await verifyWebhook({ secret, timestamp, body, signature: sign(secret) })).toBe(true);
    expect(verifyWebhookSignature({ secret, timestamp, body, signature: sign(secret) })).toBe(true);
    expect(await verifyWebhook({ secret, timestamp, body, signature: sign('other') })).toBe(false);
    expect(
      await verifyWebhook({
        secret,
        timestamp: timestamp - 900,
        body,
        signature: sign(secret, timestamp - 900),
      }),
    ).toBe(false);

    const received: { type: string; deliveryId: string | null }[] = [];
    let fail = false;
    const POST = createWebhookHandler({
      secret: ['whsec_previous_secret', secret],
      onEvent: (event, delivery) => {
        if (fail) throw new Error('downstream unavailable');
        received.push({ type: event.type, deliveryId: delivery.deliveryId });
      },
    });
    const deliver = (signature: string, method = 'POST') =>
      POST(
        new Request('http://app/api/webhooks/iam', {
          method,
          headers: {
            'content-type': 'application/json',
            'x-better-iam-timestamp': String(timestamp),
            'x-better-iam-signature': signature,
            'x-better-iam-delivery': 'dlv_1',
          },
          ...(method === 'POST' ? { body } : {}),
        }),
      );
    expect((await deliver(sign(secret))).status).toBe(200);
    expect(received).toEqual([{ type: 'identity:create', deliveryId: 'dlv_1' }]);
    expect((await deliver(sign('whsec_previous_secret'))).status).toBe(200);
    expect((await deliver(sign('whsec_unknown'))).status).toBe(401);
    expect((await deliver(sign(secret), 'GET')).status).toBe(405);
    fail = true;
    expect((await deliver(sign(secret))).status).toBe(500);
    expect(received).toHaveLength(2);
    expect(() => createWebhookHandler({ secret: '', onEvent: () => undefined })).toThrow();
  });
});
