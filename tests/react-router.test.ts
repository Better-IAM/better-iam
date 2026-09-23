import { RouterContextProvider } from 'react-router';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamRouter, type RouteArgs } from '@better-iam/react-router';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const origin = 'http://localhost:3000';
/** What a loader/action produced: a returned value, a thrown redirect Response, or thrown `data()`. */
type Outcome =
  | { kind: 'value'; value: unknown }
  | { kind: 'response'; response: Response }
  | { kind: 'data'; status: number | undefined; data: unknown };

/** Runs one request through the root middleware and a route function, like React Router's server does. */
async function run<R>(
  iamRouter: Pick<ReturnType<typeof createIamRouter>, 'middleware'>,
  request: Request,
  route: (args: RouteArgs & { params: Record<string, string> }) => Promise<R> | R,
): Promise<{ outcome: Outcome; response: Response }> {
  const context = new RouterContextProvider();
  let outcome!: Outcome;
  const response = await iamRouter.middleware({ request, context }, async () => {
    try {
      const value = await route({ request, context, params: {} });
      if (value instanceof Response) {
        outcome = { kind: 'response', response: value };
        return value;
      }
      const init = (value as { type?: string; init?: ResponseInit | null }) ?? {};
      if (init.type === 'DataWithResponseInit') {
        outcome = {
          kind: 'data',
          status: init.init?.status,
          data: (value as unknown as { data: unknown }).data,
        };
        return Response.json(outcome.data, { status: init.init?.status ?? 200 });
      }
      outcome = { kind: 'value', value };
      return Response.json(value);
    } catch (error) {
      if (error instanceof Response) {
        outcome = { kind: 'response', response: error };
        return error;
      }
      const thrown = error as { type?: string; data?: unknown; init?: ResponseInit | null };
      if (thrown?.type === 'DataWithResponseInit') {
        outcome = { kind: 'data', status: thrown.init?.status, data: thrown.data };
        return Response.json(thrown.data, { status: thrown.init?.status ?? 500 });
      }
      throw error;
    }
  });
  return { outcome, response };
}
const page = (path: string, init: RequestInit = {}) =>
  new Request(new URL(path, 'http://localhost:3000'), init);
const sessionCookie = (response: Response) =>
  response.headers
    .getSetCookie()
    .find((header) => header.startsWith('better-iam.session='))
    ?.split(';')[0];

describe('React Router integration', () => {
  it('serves the API, signs in from an action, and puts the cookie on the redirect', async () => {
    const f = await organizationFixture();
    const iamRouter = createIamRouter(f.iam);
    const api = await iamRouter.api({
      request: page('/api/iam/health'),
    });
    expect((await api.json()).status).toBe('ok');

    const { response, outcome } = await run(
      iamRouter,
      page('/login?next=%2Fprojects', { method: 'POST', headers: { origin } }),
      async (args) => {
        await iamRouter.helpers(args).client.auth.signIn({
          tenantId: f.tenantId,
          email: 'owner@acme.test',
          password: 'a strong tenant owner password',
        });
        const session = await iamRouter.helpers(args).getSession();
        expect(session?.identity.email).toBe('owner@acme.test');
        throw new Response(null, { status: 302, headers: { location: '/projects' } });
      },
    );
    expect(outcome.kind).toBe('response');
    expect(response.status).toBe(302);
    expect(sessionCookie(response)).toBeTruthy();
    expect(response.headers.getSetCookie().join('\n')).toMatch(/HttpOnly/i);
  });

  it('guards loaders: login redirect (also for .data requests), step-up, and authorization', async () => {
    const f = await organizationFixture();
    const iamRouter = createIamRouter(f.iam, { loginPath: '/signin', stepUpPath: '/verify' });
    const owner = `better-iam.session=${(await f.ownerSignIn()).token}`;
    const members = iamRouter.guard(async (_args, session) => ({ name: session.identity.name }), {
      authorize: { action: 'iam:identities:read' },
    });

    const anonymous = await run(iamRouter, page('/members?tab=2'), members);
    expect(anonymous.response.status).toBe(302);
    expect(anonymous.response.headers.get('location')).toBe('/signin?next=%2Fmembers%3Ftab%3D2');
    const dataRequest = await run(iamRouter, page('/members.data'), members);
    expect(dataRequest.response.headers.get('location')).toBe('/signin?next=%2Fmembers');

    const allowed = await run(iamRouter, page('/members', { headers: { cookie: owner } }), members);
    expect(allowed.outcome).toEqual({ kind: 'value', value: { name: 'Owner' } });

    const mfa = iamRouter.guard(() => 'secret', { stepUp: { mfa: true } });
    const stepUp = await run(iamRouter, page('/billing', { headers: { cookie: owner } }), mfa);
    expect(stepUp.response.headers.get('location')).toBe('/verify?next=%2Fbilling&reason=mfa');

    await f.member('carol');
    const carol = `better-iam.session=${(await f.signIn('carol')).token}`;
    const denied = await run(iamRouter, page('/members', { headers: { cookie: carol } }), members);
    expect(denied.outcome).toMatchObject({
      kind: 'data',
      status: 403,
      data: { code: 'ACCESS_DENIED' },
    });
    const redirected = await run(
      iamRouter,
      page('/members', { headers: { cookie: carol } }),
      iamRouter.guard(() => 'x', {
        authorize: { action: 'iam:identities:read' },
        deniedRedirect: '/',
      }),
    );
    expect(redirected.response.headers.get('location')).toBe('/');
  });

  it('wraps actions: CSRF origin check, refusals as data(), and the session argument', async () => {
    const f = await organizationFixture();
    const iamRouter = createIamRouter(f.iam);
    const owner = `better-iam.session=${(await f.ownerSignIn()).token}`;
    const invite = iamRouter.action(
      async (args, session) => {
        await f.iam.api.identities.create(iamRouter.helpers(args).credential(), {
          tenantId: session.session.tenantId,
          email: 'not-an-email',
          name: 'Broken',
        });
        return { created: true };
      },
      { authorize: { action: 'iam:identities:create' } },
    );
    const post = (headers: Record<string, string>) => page('/members', { method: 'POST', headers });

    const crossSite = await run(
      iamRouter,
      post({ cookie: owner, origin: 'http://evil.test' }),
      invite,
    );
    expect(crossSite.outcome).toMatchObject({
      kind: 'data',
      status: 403,
      data: { code: 'UNTRUSTED_ORIGIN' },
    });
    const anonymous = await run(iamRouter, post({ origin }), invite);
    expect(anonymous.outcome).toMatchObject({ status: 401, data: { code: 'UNAUTHENTICATED' } });
    const invalid = await run(iamRouter, post({ cookie: owner, origin }), invite);
    expect(invalid.outcome).toMatchObject({ status: 400, data: { code: 'INVALID_INPUT' } });

    await f.member('dave');
    const dave = `better-iam.session=${(await f.signIn('dave')).token}`;
    const denied = await run(iamRouter, post({ cookie: dave, origin }), invite);
    expect(denied.outcome).toMatchObject({ status: 403, data: { code: 'ACCESS_DENIED' } });

    const whoami = iamRouter.action((_args, session) => ({ id: session.identity.id }));
    const ok = await run(
      iamRouter,
      post({ cookie: owner, 'sec-fetch-site': 'same-origin' }),
      whoami,
    );
    expect(ok.outcome).toEqual({ kind: 'value', value: { id: f.ownerId } });
  });

  it('signs out, provides session data, and explains a missing middleware', async () => {
    const f = await organizationFixture();
    const iamRouter = createIamRouter(f.iam);
    const token = (await f.ownerSignIn()).token;
    const cookie = `better-iam.session=${token}`;
    const data = await run(iamRouter, page('/', { headers: { cookie } }), (args) =>
      iamRouter.sessionData(args),
    );
    expect(data.outcome).toMatchObject({
      kind: 'value',
      value: { session: { identity: { email: 'owner@acme.test' } } },
    });
    const out = await run(
      iamRouter,
      page('/logout', { method: 'POST', headers: { cookie, origin } }),
      async (args) => {
        await iamRouter.helpers(args).signOut();
        return { signedOut: (await iamRouter.helpers(args).getSession()) === null };
      },
    );
    expect(out.outcome).toEqual({ kind: 'value', value: { signedOut: true } });
    expect(out.response.headers.getSetCookie().join('\n')).toMatch(
      /better-iam\.session=;.*Max-Age=0/i,
    );
    await expect(f.iam.api.auth.getSession({ token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect(() =>
      iamRouter.helpers({ request: page('/'), context: new RouterContextProvider() }),
    ).toThrow(/middleware/);
  });
});
