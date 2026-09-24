import { isRedirect } from '@sveltejs/kit';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createIamKit, type KitCookieOptions, type KitEvent } from '@better-iam/svelte/kit';
import { checkRequestOrigin } from '@better-iam/middleware';
import { createIamNext } from '@better-iam/next';
import { createIamH3 } from '@better-iam/nuxt/h3';
import { Readable } from 'node:stream';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

/** Security review regressions (session e15e8e) for the HTTP edge and framework integrations. */

function kitEvent(path: string, routeId?: string | null): KitEvent {
  const url = new URL(path, 'http://localhost:3000');
  return {
    url,
    request: new Request(url),
    locals: {},
    cookies: {
      get: () => undefined,
      getAll: () => [],
      set(_name: string, _value: string, _options: KitCookieOptions) {},
    },
    ...(routeId === undefined ? {} : { route: { id: routeId } }),
  } as KitEvent;
}
async function outcome(promise: Promise<Response>): Promise<string> {
  try {
    return await (await promise).text();
  } catch (error) {
    if (isRedirect(error)) return `redirect ${error.location}`;
    throw error;
  }
}

describe('request bodies on fallback paths', () => {
  it('are capped by the h3 Node fallback with a 413 instead of being buffered without limit', async () => {
    const f = await organizationFixture();
    const megabyte = Buffer.alloc(1024 * 1024, 32);
    const req = Object.assign(Readable.from([megabyte, megabyte, Buffer.from('{}')]), {
      method: 'POST',
      url: '/api/iam/auth/signIn',
      headers: { host: 'localhost:3000', 'content-type': 'application/json' },
      socket: {},
    });
    const response = await createIamH3(f.iam).handler({ node: { req }, context: {} } as never);
    expect(response.status).toBe(413);
    expect(await response.json()).toMatchObject({ error: { code: 'PAYLOAD_TOO_LARGE' } });
  });
});

describe('organization address pinning', () => {
  it('applies to the tenant confirmMfa names inside its credential', async () => {
    const f = await organizationFixture({
      hosts: { patterns: ['{tenant}.localhost:3000'], signInPath: '/login' },
    });
    await f.iam.api.tenants.setSlug(f.rootCredential, { tenantId: f.tenantId, slug: 'acme' });
    const created = await f.iam.api.tenants.create(f.rootCredential, {
      parentId: f.root.tenant.id,
      name: 'Globex',
      type: 'organization',
      ownerEmail: 'owner@globex.test',
      slug: 'globex',
    });
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find(
      (message) =>
        message.tenantId === created.tenant.id && message.template === 'owner-invitation',
    )!;
    const globexOwner = await f.iam.api.tenants.acceptInvitation({
      tenantId: created.tenant.id,
      token: invitation.payload.token!,
      name: 'Owner',
      password: 'a strong tenant owner password',
    });
    if (!('token' in globexOwner)) throw new Error('Unexpected owner MFA');
    await f.iam.api.tenants.setAuthPolicy(
      { token: globexOwner.token },
      { tenantId: created.tenant.id, authPolicy: { requireMfa: true } },
    );
    const challenge = await f.iam.api.auth.signIn({
      tenantId: created.tenant.id,
      email: 'owner@globex.test',
      password: 'a strong tenant owner password',
    });
    if (!('mfaRequired' in challenge)) throw new Error('MFA expected');
    const acmeOrigin = 'http://acme.localhost:3000';
    const response = await f.iam.handler(
      new Request(`${acmeOrigin}/api/iam/auth/confirmMfa`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1', origin: acmeOrigin },
        body: JSON.stringify({
          credential: { tenantId: created.tenant.id, challenge: challenge.challenge },
          code: '123456',
        }),
      }),
    );
    expect(response.status).toBe(403);
    expect(await response.json()).toMatchObject({ error: { code: 'HOST_MISMATCH' } });
  });
});

describe('Origin: null on cookie-authenticated mutations', () => {
  // `new URL('capacitor://localhost').origin` is the string "null", as is the Origin browsers send from sandboxed
  // frames, after cross-origin redirects, and for no-referrer form posts.
  const trustedOrigins = ['capacitor://localhost', 'https://admin.example.test'];
  it('is refused by the shared middleware check even when a trusted entry has an opaque origin', () => {
    const request = (origin: string) => ({
      method: 'POST',
      url: new URL('http://localhost:3000/api/transfer'),
      headers: new Headers({ cookie: 'better-iam.session=abc', origin }),
    });
    expect(checkRequestOrigin(request('null'), trustedOrigins)).toMatchObject({
      code: 'UNTRUSTED_ORIGIN',
    });
    expect(checkRequestOrigin(request('https://admin.example.test'), trustedOrigins)).toBeNull();
    expect(checkRequestOrigin(request('http://localhost:3000'), trustedOrigins)).toBeNull();
  });

  it('is refused by Next route wrappers', async () => {
    const f = await organizationFixture();
    const iamNext = createIamNext(f.iam, { headers: () => new Headers(), trustedOrigins });
    let calls = 0;
    const wrapped = iamNext.route(() => {
      calls++;
      return { moved: true };
    }) as (request: Request, context: { params: Promise<object> }) => Promise<Response>;
    const cookie = `better-iam.session=${(await f.ownerSignIn()).token}`;
    const send = (origin: string) =>
      wrapped(
        new Request('http://localhost:3000/api/transfer', {
          method: 'POST',
          headers: { cookie, origin },
        }),
        { params: Promise.resolve({}) },
      );
    const refused = await send('null');
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: { code: 'UNTRUSTED_ORIGIN' } });
    expect(calls).toBe(0);
    expect((await send('https://admin.example.test')).status).toBe(200);
    expect(calls).toBe(1);
  });
});

describe('SvelteKit protect rules', () => {
  it('apply to percent-encoded paths, which SvelteKit decodes before routing', async () => {
    const fixture = await organizationFixture();
    const kit = createIamKit(fixture.iam, {
      protect: [{ path: '/admin' }, { path: /^\/secure(\/|$)/ }, { path: (url) => url.pathname === '/fn' }],
    });
    const resolve = vi.fn(() => new Response('page'));
    for (const path of ['/%61dmin/users', '/adm%69n', '/%73ecure/x', '/%66n'])
      expect(await outcome(kit.handle({ event: kitEvent(path), resolve })), path).toMatch(
        /^redirect \/login\?next=/,
      );
    // Public paths, and prefixes that only share letters with a rule, still render.
    expect(await outcome(kit.handle({ event: kitEvent('/about'), resolve }))).toBe('page');
    expect(await outcome(kit.handle({ event: kitEvent('/administrator'), resolve }))).toBe('page');
    expect(resolve).toHaveBeenCalledTimes(2);
  });

  it('apply to the route a reroute hook chose, by its id without groups', async () => {
    const fixture = await organizationFixture();
    const kit = createIamKit(fixture.iam, { protect: [{ path: '/admin' }] });
    const resolve = vi.fn(() => new Response('page'));
    // `/de/verwaltung` rerouted to routes/(console)/admin/[section].
    expect(
      await outcome(
        kit.handle({ event: kitEvent('/de/verwaltung', '/(console)/admin/[section]'), resolve }),
      ),
    ).toMatch(/^redirect \/login\?next=/);
    expect(
      await outcome(kit.handle({ event: kitEvent('/de/start', '/(console)/home'), resolve })),
    ).toBe('page');
    expect(await outcome(kit.handle({ event: kitEvent('/nowhere', null), resolve }))).toBe('page');
  });
});
