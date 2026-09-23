import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';
import {
  createApp,
  createError,
  createRouter,
  defineEventHandler,
  getRouterParam,
  toNodeListener,
  toWebRequest,
} from 'h3';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  IamH3Error,
  createIamH3,
  eventHeaders,
  eventRequest,
  isAuthenticationError,
} from '@better-iam/nuxt/h3';
import type { IamStore } from '@better-iam/core';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const cleanups: (() => Promise<void>)[] = [];
afterEach(async () => {
  for (const cleanup of cleanups.splice(0)) await cleanup();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  cleanups.push(() => database.close());
  const iam = betterIam({
    database,
    secret: 'nuxt-h3-test-secret-with-at-least-32-characters',
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
  return { iam, root, member, rootToken: session.token };
}

/** An h3 v1 app on a real Node server, the way Nitro runs it. */
async function serve(iamH3: ReturnType<typeof createIamH3>, tenantId: string) {
  const app = createApp();
  // Prefix mounts strip the prefix from node.req.url; the handler must still see the original path.
  app.use(
    '/api/iam',
    defineEventHandler((event) => iamH3.handler(event)),
  );
  const router = createRouter()
    .get(
      '/me',
      defineEventHandler(async (event) => {
        const session = await iamH3.requireSession(event);
        const again = await iamH3.getSession(event);
        return { id: session.identity.id, memoized: again === session };
      }),
    )
    .get(
      '/documents/:id',
      defineEventHandler(async (event) => {
        await iamH3.require(event, {
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: getRouterParam(event, 'id')! },
        });
        return { ok: true };
      }),
    )
    .get(
      '/can',
      defineEventHandler((event) =>
        iamH3.can(event, { tenantId, checks: [{ action: 'iam:identities:read' }] }),
      ),
    );
  app.use(router);
  const server: Server = createServer(toNodeListener(app));
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  cleanups.push(() => new Promise((resolve) => server.close(() => resolve())));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

const json = {
  'content-type': 'application/json',
  'x-better-iam': '1',
  origin: 'http://localhost:3000',
};

describe('h3 / Nitro server helpers', () => {
  it('mounts the IAM API, reads cookie sessions, enforces, and batches decisions in an h3 v1 app', async () => {
    const f = await fixture();
    const tenantId = f.root.tenant.id;
    const iamH3 = createIamH3(() => f.iam);
    const base = await serve(iamH3, tenantId);

    // Sign in through the mounted handler: the body is read from the Node stream and the cookie comes back.
    const signIn = await fetch(`${base}/api/iam/auth/signIn`, {
      method: 'POST',
      headers: json,
      body: JSON.stringify({
        tenantId,
        email: 'member@example.test',
        password: 'a strong member test password',
      }),
    });
    expect(signIn.status).toBe(200);
    const cookie = signIn.headers.get('set-cookie')!.split(';')[0]!;
    expect(cookie).toMatch(/^better-iam\.session=/);

    const me = await fetch(`${base}/me`, { headers: { cookie } });
    expect(await me.json()).toEqual({ id: f.member.id, memoized: true });
    const anonymous = await fetch(`${base}/me`);
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toMatchObject({
      statusCode: 401,
      data: { code: 'UNAUTHENTICATED' },
    });

    const denied = await fetch(`${base}/documents/a`, { headers: { cookie } });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ data: { code: 'ACCESS_DENIED' } });
    const rootRead = await fetch(`${base}/documents/a`, {
      headers: { authorization: `Bearer ${f.rootToken}` },
    });
    expect(await rootRead.json()).toEqual({ ok: true });

    const key = `iam:identities:read@iam/${tenantId}`;
    expect(await (await fetch(`${base}/can`, { headers: { cookie } })).json()).toEqual({
      [key]: false,
    });
    expect(
      await (
        await fetch(`${base}/can`, { headers: { authorization: `Bearer ${f.rootToken}` } })
      ).json(),
    ).toEqual({ [key]: true });
    expect(await (await fetch(`${base}/can`)).json()).toEqual({ [key]: false });

    // Cookie requests to the API still need a trusted Origin (the CSRF boundary is the server's, not the adapter's).
    const csrf = await fetch(`${base}/api/iam/auth/getSession`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-better-iam': '1', cookie },
      body: '{}',
    });
    expect(csrf.status).toBe(403);
    const health = await fetch(`${base}/api/iam/health`);
    expect(await health.json()).toMatchObject({ status: 'ok' });
  });

  it('uses h3 utilities when given, binds an in-process session client, and reads h3 v2 events', async () => {
    const f = await fixture();
    const tenantId = f.root.tenant.id;
    const iamH3 = createIamH3(f.iam, { toRequest: toWebRequest, createError });
    const base = await serve(iamH3, tenantId);
    const signIn = await fetch(`${base}/api/iam/auth/signIn`, {
      method: 'POST',
      headers: json,
      body: JSON.stringify({
        tenantId,
        email: 'member@example.test',
        password: 'a strong member test password',
      }),
    });
    const cookie = signIn.headers.get('set-cookie')!.split(';')[0]!;
    const denied = await fetch(`${base}/documents/b`, { headers: { cookie } });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ statusMessage: 'ACCESS_DENIED' });

    // An h3 v2 event carries a Web Request.
    const v2 = {
      req: new Request('http://localhost:3000/x', { headers: { cookie } }),
      context: {},
    };
    expect(eventHeaders(v2).get('cookie')).toBe(cookie);
    expect(await eventRequest(v2)).toBe(v2.req);
    const session = await iamH3.getSession(v2);
    expect(session?.identity.id).toBe(f.member.id);
    expectTypeOf(session!.identity.email).toEqualTypeOf<string | undefined>();

    // The bound client is what Nuxt server rendering hands to the Vue bindings.
    const bound = iamH3.bind(v2);
    expect((await bound.auth.getSession()).identity.id).toBe(f.member.id);
    const { results } = await bound.authorizeMany({
      tenantId,
      checks: [{ action: 'documents:read', resource: { type: 'document', id: 'a' } }],
    });
    expect(results[0]?.allowed).toBe(false);
    // Delegates to the server, which only lists managed resource types.
    await expect(
      bound.listAccessible({ tenantId, action: 'documents:read', type: 'document' }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
    const anonymous = iamH3.bind({ context: {}, req: new Request('http://localhost:3000/x') });
    await expect(anonymous.auth.getSession()).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      status: 401,
    });
    await expect(bound.auth.signOut()).rejects.toThrow(/browser/);

    const assertion = await iamH3.assertion(
      {
        context: {},
        req: new Request('http://x/', { headers: { authorization: `Bearer ${f.rootToken}` } }),
      },
      { tenantId, audience: 'reports' },
    );
    expect(typeof assertion.token).toBe('string');
    await expect(iamH3.assertion(v2, { tenantId, audience: 'reports' })).rejects.toMatchObject({
      statusCode: 403,
    });

    const plain = createIamH3(f.iam);
    await expect(
      plain.requireSession({ context: {}, req: new Request('http://x/') }),
    ).rejects.toBeInstanceOf(IamH3Error);
    expect(isAuthenticationError({ code: 'MFA_REQUIRED' })).toBe(true);
    expect(isAuthenticationError({ code: 'ACCESS_DENIED' })).toBe(false);
  });
});
