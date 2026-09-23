import type { AddressInfo } from 'node:net';
import { createServer, type Server } from 'node:http';
import express from 'express';
import Fastify, { type FastifyRequest } from 'fastify';
import { Hono } from 'hono';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  IamRequestError,
  checkStepUp,
  parseCookieHeader,
  refusalResponse,
  safeRedirectPath,
  setCookieSummary,
  type IamRequest,
} from '@better-iam/middleware';
import { createIamExpress } from '@better-iam/middleware/express';
import { createIamFastify } from '@better-iam/middleware/fastify';
import { createIamHono, type IamVariables } from '@better-iam/middleware/hono';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
  await closeFixtures();
});

type Fetch = (path: string, init?: RequestInit) => Promise<Response>;
type Helpers = IamRequest<OrganizationFixture['iam']>;
// How an Express app types `req.iam`.
declare global {
  // eslint-disable-next-line @typescript-eslint/no-namespace
  namespace Express {
    interface Request {
      iam: Helpers;
    }
  }
}
// And how a Fastify app types `request.iam`.
declare module 'fastify' {
  interface FastifyRequest {
    iam: Helpers;
  }
}
const origin = 'http://localhost:3000';
const json = { 'content-type': 'application/json', 'x-better-iam': '1', origin };
const cookieOf = (response: Response) =>
  response.headers
    .getSetCookie()
    .find((header) => header.startsWith('better-iam.session='))
    ?.split(';')[0];

/** Routes every adapter mounts, written against the shared helpers. */
const routes = {
  me: async (iam: Helpers) => {
    const session = await iam.getSession();
    return { email: session?.identity.email, canUpdate: await iam.can('iam:identities:update') };
  },
  login: async (iam: Helpers, tenantId: string, body: { email: string; password: string }) => {
    await iam.client.auth.signIn({ tenantId, ...body });
    // The session the in-process client just issued counts for the rest of this request.
    return { signedInAs: (await iam.getSession())?.identity.email };
  },
  logout: async (iam: Helpers) => {
    await iam.signOut();
    return { signedOut: (await iam.getSession()) === null };
  },
  thrower: async (iam: Helpers) => {
    await iam.require('iam:identities:delete');
    return { unreachable: true };
  },
};

/** The same scenario against any adapter: API mount, guards, page redirects, in-process sign-in, errors, sign-out. */
async function scenario(fixture: OrganizationFixture, call: Fetch) {
  // The IAM API is answered by the adapter.
  const signIn = await call('/api/iam/auth/signIn', {
    method: 'POST',
    headers: json,
    body: JSON.stringify({
      tenantId: fixture.tenantId,
      email: 'owner@acme.test',
      password: 'a strong tenant owner password',
    }),
  });
  expect(signIn.status).toBe(200);
  const owner = cookieOf(signIn)!;
  expect(owner).toBeTruthy();
  expect((await (await call('/api/iam/health')).json()).status).toBe('ok');

  // Guards: JSON envelope for API calls, redirects for page navigations.
  const anonymous = await call('/me');
  expect(anonymous.status).toBe(401);
  expect(await anonymous.json()).toEqual({
    error: { code: 'UNAUTHENTICATED', message: 'A session is required' },
  });
  expect(anonymous.headers.get('cache-control')).toBe('no-store');
  const page = await call('/me?tab=1', { headers: { accept: 'text/html' } });
  expect(page.status).toBe(303);
  expect(page.headers.get('location')).toBe('/login?next=%2Fme%3Ftab%3D1');
  expect(await (await call('/me', { headers: { cookie: owner } })).json()).toEqual({
    email: 'owner@acme.test',
    canUpdate: true,
  });

  // CSRF: cookie-authenticated unsafe requests to guarded routes must come from a trusted origin.
  const danger = (headers: Record<string, string>) => call('/danger', { method: 'POST', headers });
  const crossSite = await danger({ cookie: owner, origin: 'http://evil.test' });
  expect(crossSite.status).toBe(403);
  expect((await crossSite.json()).error.code).toBe('UNTRUSTED_ORIGIN');
  const noOrigin = await danger({ cookie: owner });
  expect((await noOrigin.json()).error.code).toBe('CSRF_REJECTED');
  expect((await danger({ cookie: owner, origin })).status).toBe(200); // the IAM origin is trusted
  expect((await danger({ cookie: owner, 'sec-fetch-site': 'same-origin' })).status).toBe(200);
  const token = owner.slice('better-iam.session='.length);
  expect(
    (await danger({ authorization: `Bearer ${token}`, origin: 'http://evil.test' })).status,
  ).toBe(200); // bearer credentials are not ambient, so no Origin check

  // Step-up: a password-only session is refused (API) or sent to the step-up page (navigation).
  const secure = await call('/secure', { headers: { cookie: owner } });
  expect(secure.status).toBe(403);
  expect((await secure.json()).error.code).toBe('MFA_REQUIRED');
  const secureNav = await call('/secure', { headers: { cookie: owner, accept: 'text/html' } });
  expect(secureNav.headers.get('location')).toBe('/verify?next=%2Fsecure&reason=mfa');

  // Authorization guard: the owner may update identities, a plain member may not.
  expect((await call('/admin', { headers: { cookie: owner } })).status).toBe(200);
  await fixture.member('bob');
  const bobLogin = await call('/login', {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ email: 'bob@acme.test', password: 'a strong bob password' }),
  });
  expect(await bobLogin.json()).toEqual({ signedInAs: 'bob@acme.test' });
  const bob = cookieOf(bobLogin)!;
  expect(bobLogin.headers.getSetCookie().join('\n')).toMatch(/HttpOnly/i);
  const denied = await call('/admin', { headers: { cookie: bob } });
  expect(denied.status).toBe(403);
  expect((await denied.json()).error.code).toBe('ACCESS_DENIED');
  expect(await (await call('/me', { headers: { cookie: bob } })).json()).toEqual({
    email: 'bob@acme.test',
    canUpdate: false,
  });

  // A refusal thrown inside a route reaches the adapter's error handler.
  const thrown = await call('/thrower', { headers: { cookie: bob } });
  expect(thrown.status).toBe(403);
  expect((await thrown.json()).error.code).toBe('ACCESS_DENIED');

  // Sign-out ends the session server-side and clears the cookie.
  const logout = await call('/logout', { method: 'POST', headers: { cookie: bob } });
  expect(await logout.json()).toEqual({ signedOut: true });
  expect(logout.headers.getSetCookie().join('\n')).toMatch(/better-iam\.session=;.*Max-Age=0/i);
  expect((await call('/me', { headers: { cookie: bob } })).status).toBe(401);
}

async function listen(server: Server): Promise<Fetch> {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  cleanups.push(() => new Promise((resolve) => server.close(() => resolve())));
  const { port } = server.address() as AddressInfo;
  return (path, init) => fetch(`http://127.0.0.1:${port}${path}`, { redirect: 'manual', ...init });
}

describe('Express, Hono, and Fastify middleware', () => {
  it('Express: mounts the API before body parsers, guards routes, and handles refusals', async () => {
    const fixture = await organizationFixture();
    const iamExpress = createIamExpress(fixture.iam, {
      loginPath: '/login',
      stepUpPath: '/verify',
    });
    const app = express();
    app.use(iamExpress.middleware);
    app.use(express.json());
    const iamOf = (req: express.Request) => req.iam;
    app.get('/me', iamExpress.requireSession(), async (req, res) => {
      res.json(await routes.me(iamOf(req)));
    });
    app.get('/secure', iamExpress.requireSession({ stepUp: { mfa: true } }), (_req, res) => {
      res.json({ ok: true });
    });
    app.post('/danger', iamExpress.requireSession(), (_req, res) => {
      res.json({ ok: true });
    });
    app.get('/admin', iamExpress.authorize('iam:identities:update'), (_req, res) => {
      res.json({ ok: true });
    });
    app.post('/login', async (req, res) => {
      res.json(await routes.login(iamOf(req), fixture.tenantId, req.body));
    });
    app.post('/logout', async (req, res) => {
      res.json(await routes.logout(iamOf(req)));
    });
    app.get('/thrower', async (req, res) => {
      res.json(await routes.thrower(iamOf(req)));
    });
    app.use(iamExpress.errorHandler);
    await scenario(fixture, await listen(createServer(app)));
  });

  it('Express: serves the API even when a body parser already consumed the request', async () => {
    const fixture = await organizationFixture();
    const iamExpress = createIamExpress(fixture.iam);
    const app = express();
    app.use(express.json());
    app.use('/api/iam', iamExpress.middleware);
    const call = await listen(createServer(app));
    const signIn = await call('/api/iam/auth/signIn', {
      method: 'POST',
      headers: json,
      body: JSON.stringify({
        tenantId: fixture.tenantId,
        email: 'owner@acme.test',
        password: 'a strong tenant owner password',
      }),
    });
    expect(signIn.status).toBe(200);
    expect(cookieOf(signIn)).toBeTruthy();
    // Mounted under a path, Express strips the prefix from req.url; the adapter restores it.
    const session = await call('/api/iam/auth/getSession', {
      method: 'POST',
      headers: { ...json, cookie: cookieOf(signIn)! },
      body: '{}',
    });
    expect((await session.json()).data.identity.email).toBe('owner@acme.test');
  });

  it('Hono: answers the API with the fetch handler and exposes c.get("iam")', async () => {
    const fixture = await organizationFixture();
    const iamHono = createIamHono(fixture.iam, { loginPath: '/login', stepUpPath: '/verify' });
    const app = new Hono<{ Variables: IamVariables<typeof fixture.iam> }>();
    app.use(iamHono.middleware);
    app.get('/me', iamHono.requireSession(), async (c) => c.json(await routes.me(c.get('iam'))));
    app.get('/secure', iamHono.requireSession({ stepUp: { mfa: true } }), (c) =>
      c.json({ ok: true }),
    );
    app.post('/danger', iamHono.requireSession(), (c) => c.json({ ok: true }));
    app.get('/admin', iamHono.authorize('iam:identities:update'), (c) => c.json({ ok: true }));
    app.post('/login', async (c) =>
      c.json(await routes.login(c.get('iam'), fixture.tenantId, await c.req.json())),
    );
    app.post('/logout', async (c) => c.json(await routes.logout(c.get('iam'))));
    app.get('/thrower', async (c) => c.json(await routes.thrower(c.get('iam'))));
    app.onError(iamHono.onError);
    await scenario(fixture, async (path, init) =>
      app.fetch(new Request(`http://127.0.0.1${path}`, init)),
    );
  });

  it('Fastify: answers the API before body parsing and guards routes with preHandlers', async () => {
    const fixture = await organizationFixture();
    const iamFastify = createIamFastify(fixture.iam, {
      loginPath: '/login',
      stepUpPath: '/verify',
    });
    const app = Fastify();
    cleanups.push(() => app.close());
    await app.register(iamFastify.plugin);
    const iamOf = (request: FastifyRequest) => request.iam;
    app.get('/me', { preHandler: iamFastify.requireSession() }, (request) =>
      routes.me(iamOf(request)),
    );
    app.get(
      '/secure',
      { preHandler: iamFastify.requireSession({ stepUp: { mfa: true } }) },
      () => ({
        ok: true,
      }),
    );
    app.post('/danger', { preHandler: iamFastify.requireSession() }, () => ({ ok: true }));
    app.get('/admin', { preHandler: iamFastify.authorize('iam:identities:update') }, () => ({
      ok: true,
    }));
    app.post('/login', (request) =>
      routes.login(
        iamOf(request),
        fixture.tenantId,
        request.body as { email: string; password: string },
      ),
    );
    app.post('/logout', (request) => routes.logout(iamOf(request)));
    app.get('/thrower', (request) => routes.thrower(iamOf(request)));
    app.setErrorHandler(iamFastify.errorHandler);
    await app.listen({ port: 0, host: '127.0.0.1' });
    const { port } = app.server.address() as AddressInfo;
    await scenario(fixture, (path, init) =>
      fetch(`http://127.0.0.1:${port}${path}`, { redirect: 'manual', ...init }),
    );
  });

  it('Express and Fastify reach node-only protocol mounts listed in `serve`', async () => {
    const fixture = await organizationFixture();
    fixture.iam.useProtocol({
      basePath: '/node-proto',
      nodeHandler: async (req, res) => {
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify({ served: req.url }));
      },
    });
    const serve = ['/api/iam', '/node-proto'];
    const expressApp = express();
    expressApp.use(createIamExpress(fixture.iam, { serve }).middleware);
    expressApp.get('/node-proto/x', (_req, res) => {
      res.json({ served: 'by the app' });
    });
    const viaExpress = await listen(createServer(expressApp));
    expect(await (await viaExpress('/node-proto/metadata?x=1')).json()).toEqual({
      served: '/node-proto/metadata?x=1',
    });
    expect(await (await viaExpress('/node-proto/x')).json()).toEqual({ served: '/node-proto/x' });

    const fastifyApp = Fastify();
    cleanups.push(() => fastifyApp.close());
    await fastifyApp.register(createIamFastify(fixture.iam, { serve }).plugin);
    await fastifyApp.listen({ port: 0, host: '127.0.0.1' });
    const { port } = fastifyApp.server.address() as AddressInfo;
    const viaFastify = await fetch(`http://127.0.0.1:${port}/node-proto/metadata`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: '{"a":1}',
    });
    expect(await viaFastify.json()).toEqual({ served: '/node-proto/metadata' });
  });

  it('batches advisory checks per request', async () => {
    const fixture = await organizationFixture();
    const iamHono = createIamHono(fixture.iam);
    const spy = vi.spyOn(fixture.iam, 'authorizeMany');
    const app = new Hono<{ Variables: IamVariables<typeof fixture.iam> }>();
    app.use(iamHono.middleware);
    app.get('/checks', async (c) => {
      const iam = c.get('iam');
      const answers = await Promise.all([
        iam.can('iam:identities:read'),
        iam.can('iam:identities:update'),
        iam.can('iam:identities:read'),
      ]);
      return c.json(answers);
    });
    const token = (await fixture.ownerSignIn()).token;
    const response = await app.fetch(
      new Request('http://127.0.0.1/checks', {
        headers: { cookie: `better-iam.session=${token}` },
      }),
    );
    expect(await response.json()).toEqual([true, true, true]);
    expect(spy).toHaveBeenCalledTimes(1);
  });
});

describe('middleware helpers', () => {
  it('parses cookies, recognises deletions, and keeps redirects on this site', () => {
    expect([...parseCookieHeader('a=1; b=x%20y; a=2; junk')]).toEqual([
      ['a', '1'],
      ['b', 'x%20y'],
    ]);
    expect(setCookieSummary('s=abc; Path=/; HttpOnly')).toEqual({
      name: 's',
      value: 'abc',
      deleted: false,
    });
    expect(setCookieSummary('s=; Max-Age=0')?.deleted).toBe(true);
    expect(setCookieSummary('s=; Expires=Thu, 01 Jan 1970 00:00:00 GMT')?.deleted).toBe(true);
    expect(safeRedirectPath('//evil.test')).toBe('/');
    expect(safeRedirectPath('/ok?x=1')).toBe('/ok?x=1');
    expect(checkStepUp({ session: { mfa: true, kind: 'user' } }, { mfa: 'fresh' })).toBeNull();
    expect(
      checkStepUp({ session: { mfa: true, trustedDeviceId: 'd' } }, { mfa: 'fresh' })?.code,
    ).toBe('MFA_REQUIRED');
    // POST navigations never redirect: a form post gets the JSON refusal.
    const error = new IamRequestError('UNAUTHENTICATED', 'A session is required', 401);
    const request = {
      url: new URL('http://x/app'),
      headers: new Headers({ accept: 'text/html' }),
      method: 'POST',
    };
    expect(refusalResponse(error, request, { loginPath: '/login' })).toMatchObject({ status: 401 });
    expect(refusalResponse(error, { ...request, method: 'GET' }, { loginPath: '/login' })).toEqual({
      redirect: '/login?next=%2Fapp',
    });
  });
});
