import { isActionFailure, isHttpError, isRedirect } from '@sveltejs/kit';
import { afterEach, describe, expect, it, vi } from 'vitest';
import {
  createIamKit,
  parseSetCookie,
  safeRedirectPath,
  type KitCookieOptions,
  type KitEvent,
} from '@better-iam/svelte/kit';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

/**
 * A request event with SvelteKit's cookie semantics: `set` needs a path, later `get`/`getAll` in the same request see
 * what was set, and `outgoing` holds what the response would carry.
 */
function kitEvent(
  path: string,
  input: {
    method?: string;
    body?: unknown;
    cookies?: Record<string, string>;
    headers?: HeadersInit;
  } = {},
) {
  const jar = new Map(Object.entries(input.cookies ?? {}));
  const outgoing = new Map<string, { value: string; options: KitCookieOptions }>();
  const url = new URL(path, 'http://localhost:3000');
  const headers = new Headers(input.headers);
  if (jar.size)
    headers.set(
      'cookie',
      [...jar].map(([name, value]) => `${name}=${encodeURIComponent(value)}`).join('; '),
    );
  const event = {
    url,
    request: new Request(url, {
      method: input.method ?? 'GET',
      headers,
      ...(input.body === undefined ? {} : { body: JSON.stringify(input.body) }),
    }),
    locals: {} as Record<string, unknown>,
    isDataRequest: false,
    cookies: {
      get: (name: string) => jar.get(name),
      getAll: () => [...jar].map(([name, value]) => ({ name, value })),
      set(name: string, value: string, options: KitCookieOptions) {
        if (!options?.path) throw new Error('SvelteKit requires a cookie path');
        if (options.maxAge === 0) jar.delete(name);
        else jar.set(name, value);
        outgoing.set(name, { value, options });
      },
    },
  } satisfies KitEvent & Record<string, unknown>;
  return { event, outgoing, jar };
}
async function caught(promise: Promise<unknown>): Promise<unknown> {
  try {
    await promise;
  } catch (error) {
    return error;
  }
  throw new Error('Expected a throw');
}
const resolved = () => new Response('page');

describe('SvelteKit integration', () => {
  it('serves the IAM API from handle and protects routes with login and step-up redirects', async () => {
    const fixture = await organizationFixture();
    const kit = createIamKit(fixture.iam, {
      stepUpPath: '/verify',
      protect: [
        { path: '/app' },
        { path: /^\/secure/, stepUp: { mfa: true } },
        {
          path: '/admin',
          authorize: { action: 'iam:identities:update' },
          deniedRedirect: '/app?denied=1',
        },
      ],
    });
    const resolve = vi.fn(resolved);

    // The API is answered by the IAM handler, never by the app.
    const api = kitEvent('/api/iam/auth/signIn', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        origin: 'http://localhost:3000',
        'x-better-iam': '1',
      },
      body: {
        tenantId: fixture.tenantId,
        email: 'owner@acme.test',
        password: 'a strong tenant owner password',
      },
    });
    const apiResponse = await kit.handle({ event: api.event, resolve });
    expect(apiResponse.status).toBe(200);
    expect(resolve).not.toHaveBeenCalled();
    const issued = parseSetCookie(apiResponse.headers.getSetCookie()[0]!)!;
    expect(issued).toMatchObject({
      name: 'better-iam.session',
      options: { httpOnly: true, path: '/' },
    });

    // Public pages pass and get locals.
    const home = kitEvent('/');
    expect(await (await kit.handle({ event: home.event, resolve })).text()).toBe('page');
    expect(home.event.locals.iam).toBe(kit.locals(home.event));
    expect(await kit.locals(home.event).getSession()).toBeNull();

    // Signed-out visitors to protected paths go to the login page with the path they wanted.
    const anonymous = await caught(
      kit.handle({ event: kitEvent('/app/projects?tab=2').event, resolve }),
    );
    expect(isRedirect(anonymous) && anonymous.location).toBe(
      '/login?next=%2Fapp%2Fprojects%3Ftab%3D2',
    );
    // Prefix rules match on segment boundaries.
    expect(
      await (await kit.handle({ event: kitEvent('/application').event, resolve })).text(),
    ).toBe('page');

    const owner = { 'better-iam.session': issued.value };
    const app = kitEvent('/app', { cookies: owner });
    expect(await (await kit.handle({ event: app.event, resolve })).text()).toBe('page');
    expect(await kit.locals(app.event).getSession()).toMatchObject({
      identity: { email: 'owner@acme.test' },
    });

    // A password-only session is sent to step up.
    const secure = await caught(
      kit.handle({ event: kitEvent('/secure', { cookies: owner }).event, resolve }),
    );
    expect(isRedirect(secure) && secure.location).toBe('/verify?next=%2Fsecure&reason=mfa');

    // The owner may manage identities; a member without grants is redirected away.
    expect(
      await (
        await kit.handle({ event: kitEvent('/admin', { cookies: owner }).event, resolve })
      ).text(),
    ).toBe('page');
    await fixture.member('bob');
    const bob = await fixture.signIn('bob');
    const denied = await caught(
      kit.handle({
        event: kitEvent('/admin/users', { cookies: { 'better-iam.session': bob.token } }).event,
        resolve,
      }),
    );
    expect(isRedirect(denied) && denied.location).toBe('/app?denied=1');
  });

  it('signs in from a form action through the in-process client and sees the new session in the same request', async () => {
    const fixture = await organizationFixture();
    const kit = createIamKit(fixture.iam);
    const { event, outgoing } = kitEvent('/login', {
      method: 'POST',
      headers: { 'user-agent': 'kit-test' },
    });
    const locals = kit.locals(event);
    expect(await locals.getSession()).toBeNull();
    const result = await locals.client.auth.signIn({
      tenantId: fixture.tenantId,
      email: 'owner@acme.test',
      password: 'a strong tenant owner password',
    });
    expect('token' in result).toBe(true);
    const cookie = outgoing.get('better-iam.session');
    expect(cookie?.options).toMatchObject({
      path: '/',
      httpOnly: true,
      secure: false,
      sameSite: 'lax',
    });
    const session = await locals.getSession();
    expect(session).toMatchObject({
      identity: { email: 'owner@acme.test' },
      session: { tenantId: fixture.tenantId },
    });
    expect(await kit.sessionData(event)).toEqual({ session });

    // Signing out revokes the session server-side and clears the cookie.
    await locals.signOut();
    expect(outgoing.get('better-iam.session')?.options.maxAge).toBe(0);
    expect(await locals.getSession()).toBeNull();
    await expect(fixture.iam.api.auth.getSession({ token: cookie!.value })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });

  it('guards server loads: login redirect, step-up, authorization, and the session argument', async () => {
    const fixture = await organizationFixture();
    const kit = createIamKit(fixture.iam, { loginPath: '/signin' });
    const owner = { 'better-iam.session': (await fixture.ownerSignIn()).token };
    const load = kit.guard(async (_event, session) => ({ name: session.identity.name }), {
      authorize: { action: 'iam:identities:read' },
    });
    const anonymous = await caught(load(kitEvent('/members').event));
    expect(isRedirect(anonymous) && anonymous.location).toBe('/signin?next=%2Fmembers');
    expect(await load(kitEvent('/members', { cookies: owner }).event)).toEqual({ name: 'Owner' });

    const recent = kit.guard(() => 'ok', { stepUp: { mfa: true } });
    const stepUp = await caught(recent(kitEvent('/billing', { cookies: owner }).event));
    expect(isHttpError(stepUp) && stepUp.status).toBe(403);
    expect(isHttpError(stepUp) && stepUp.body).toMatchObject({ code: 'MFA_REQUIRED' });

    await fixture.member('carol');
    const carol = { 'better-iam.session': (await fixture.signIn('carol')).token };
    const forbidden = await caught(load(kitEvent('/members', { cookies: carol }).event));
    expect(isHttpError(forbidden) && forbidden.status).toBe(403);
    expect(isHttpError(forbidden) && forbidden.body).toMatchObject({ code: 'ACCESS_DENIED' });

    // locals.require: same semantics for hand-written loads.
    const locals = kit.locals(kitEvent('/members', { cookies: carol }).event);
    const direct = await caught(locals.require('iam:identities:update'));
    expect(isHttpError(direct) && direct.status).toBe(403);
    await expect(
      locals
        .require('iam:identities:update', undefined, { deniedRedirect: '/nope' })
        .catch((error) => error.location),
    ).resolves.toBe('/nope');
  });

  it('turns IAM refusals in form actions into fail() results', async () => {
    const fixture = await organizationFixture();
    const kit = createIamKit(fixture.iam);
    const owner = { 'better-iam.session': (await fixture.ownerSignIn()).token };
    await fixture.member('dave');
    const dave = { 'better-iam.session': (await fixture.signIn('dave')).token };
    const invite = kit.action(
      async (event, session) => {
        const locals = kit.locals(event);
        await fixture.iam.api.identities.create(locals.credential(), {
          tenantId: session.session.tenantId,
          email: 'not-an-email',
          name: 'Broken',
        });
        return { created: true };
      },
      { authorize: { action: 'iam:identities:create' } },
    );
    const anonymous = await invite(kitEvent('/members', { method: 'POST' }).event);
    expect(isActionFailure(anonymous) && anonymous.status).toBe(401);
    const forbidden = await invite(kitEvent('/members', { method: 'POST', cookies: dave }).event);
    expect(isActionFailure(forbidden) && forbidden).toMatchObject({
      status: 403,
      data: { code: 'ACCESS_DENIED' },
    });
    // The owner passes the check; the invalid input comes back as a 400 failure instead of an error page.
    const invalid = await invite(kitEvent('/members', { method: 'POST', cookies: owner }).event);
    expect(isActionFailure(invalid) && invalid).toMatchObject({
      status: 400,
      data: { code: 'INVALID_INPUT' },
    });

    const mfaOnly = kit.action(() => ({ done: true }), { stepUp: { mfa: true } });
    const stepUp = await mfaOnly(kitEvent('/members', { method: 'POST', cookies: owner }).event);
    expect(isActionFailure(stepUp) && stepUp.data).toMatchObject({ code: 'MFA_REQUIRED' });
    const plain = kit.action((_event, session) => ({ id: session.identity.id }));
    expect(await plain(kitEvent('/members', { method: 'POST', cookies: owner }).event)).toEqual({
      id: fixture.ownerId,
    });
  });

  it('batches advisory checks per request and returns store-ready decisions', async () => {
    const fixture = await organizationFixture();
    const kit = createIamKit(fixture.iam);
    await fixture.member('erin');
    const erin = { 'better-iam.session': (await fixture.signIn('erin')).token };
    const spy = vi.spyOn(fixture.iam, 'authorizeMany');
    const locals = kit.locals(kitEvent('/', { cookies: erin }).event);
    const [read, update, again] = await Promise.all([
      locals.can('iam:identities:read'),
      locals.can('iam:identities:update'),
      locals.can('iam:identities:read'),
    ]);
    expect([read, update, again]).toEqual([false, false, false]);
    expect(spy).toHaveBeenCalledTimes(1);

    const ownerLocals = kit.locals(
      kitEvent('/', { cookies: { 'better-iam.session': (await fixture.ownerSignIn()).token } })
        .event,
    );
    const results = await ownerLocals.authorize([
      { action: 'iam:identities:read' },
      { action: 'documents:read', resource: { type: 'document', id: 'd1' } },
    ]);
    expect(results.map((result) => [result.action, result.resource, result.allowed])).toEqual([
      ['iam:identities:read', { type: 'iam', id: fixture.tenantId }, true],
      ['documents:read', { type: 'document', id: 'd1' }, true],
    ]);
    const anonymous = kit.locals(kitEvent('/').event);
    expect(await anonymous.can('iam:identities:read')).toBe(false);
    expect(await anonymous.authorize([{ action: 'iam:identities:read' }])).toEqual([
      {
        action: 'iam:identities:read',
        resource: { type: 'iam', id: '' },
        allowed: false,
        reason: 'UNAUTHENTICATED',
      },
    ]);
  });

  it('keeps redirects on this site and parses Set-Cookie headers', () => {
    expect(safeRedirectPath('/app?x=1#top')).toBe('/app?x=1#top');
    for (const unsafe of [
      '//evil.test',
      '/\\evil.test',
      'https://evil.test',
      'javascript:alert(1)',
      '/%0a',
      '',
    ])
      expect(safeRedirectPath(unsafe, '/home'), unsafe).toBe(unsafe === '/%0a' ? '/%0a' : '/home');
    expect(
      parseSetCookie('a=b%20c; Path=/x; Max-Age=0; SameSite=Strict; Secure; HttpOnly'),
    ).toEqual({
      name: 'a',
      value: 'b c',
      options: { path: '/x', maxAge: 0, sameSite: 'strict', secure: true, httpOnly: true },
    });
    expect(parseSetCookie('garbage')).toBeUndefined();
  });
});
