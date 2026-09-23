import { createRequire } from 'node:module';
import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  createIamMiddleware,
  createIamNext,
  isAuthenticationError,
  sessionCookieName,
} from '@better-iam/next';
import type { IamStore } from '@better-iam/core';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const iam = betterIam({
    database,
    secret: 'next-test-secret-with-at-least-32-characters',
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
    root,
    member,
    cookie: `better-iam.session=${login.token}`,
    rootToken: session.token,
  };
}

describe('Next.js server helpers', () => {
  it('reads sessions from request cookies, enforces, batches decisions, and mounts the handler', async () => {
    const f = await fixture();
    const redirects: string[] = [];
    const iamNext = createIamNext(() => f.iam, {
      loginPath: '/signin',
      headers: () => new Headers({ cookie: f.cookie }),
      redirect: (url: string): never => {
        redirects.push(url);
        throw new Error(`REDIRECT:${url}`);
      },
    });
    const session = await iamNext.getSession();
    expect(session?.identity.id).toBe(f.member.id);
    expectTypeOf(session!.identity.email).toEqualTypeOf<string | undefined>();
    expect(await iamNext.getSession(new Headers())).toBeNull();
    expect(
      await iamNext.getSession({
        cookie: 'better-iam.session=not-a-valid-token-value-at-all-0000000000',
      }),
    ).toBeNull();
    expect((await iamNext.requireSession()).identity.id).toBe(f.member.id);
    await expect(
      iamNext.requireSession({ headers: new Headers(), returnTo: '/projects/1?tab=x' }),
    ).rejects.toThrow('REDIRECT:/signin?next=%2Fprojects%2F1%3Ftab%3Dx');
    await expect(iamNext.requireSession({ headers: {}, redirectTo: '/other?x=1' })).rejects.toThrow(
      'REDIRECT:/other?x=1',
    );
    const tenantId = f.root.tenant.id;
    await expect(
      iamNext.require({
        tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'a' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      iamNext.require({
        tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'a' },
        redirectTo: '/forbidden',
      }),
    ).rejects.toThrow('REDIRECT:/forbidden');
    await expect(
      iamNext.require({
        tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'a' },
        headers: {},
        redirectTo: '/forbidden',
      }),
    ).rejects.toThrow('REDIRECT:/forbidden');
    await expect(
      iamNext.require({
        tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'a' },
        headers: { authorization: `Bearer ${f.rootToken}` },
      }),
    ).resolves.toBeUndefined();
    expect(redirects).toEqual([
      '/signin?next=%2Fprojects%2F1%3Ftab%3Dx',
      '/other?x=1',
      '/forbidden',
      '/forbidden',
    ]);
    expect(
      await iamNext.can({
        tenantId,
        checks: [
          { action: 'documents:read', resource: { type: 'document', id: 'a' } },
          { action: 'iam:identities:read' },
        ],
      }),
    ).toEqual({
      'documents:read@document/a': false,
      [`iam:identities:read@iam/${tenantId}`]: false,
    });
    expect(
      await iamNext.can({
        tenantId,
        checks: [{ action: 'iam:identities:read' }],
        headers: { authorization: `Bearer ${f.rootToken}` },
      }),
    ).toEqual({ [`iam:identities:read@iam/${tenantId}`]: true });
    expect(
      await iamNext.can({ tenantId, checks: [{ action: 'iam:identities:read' }], headers: {} }),
    ).toEqual({ [`iam:identities:read@iam/${tenantId}`]: false });
    const { POST, OPTIONS } = iamNext.handlers();
    const response = await POST(
      new Request('http://localhost:3000/api/iam/auth/getSession', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          cookie: f.cookie,
          origin: 'http://localhost:3000',
        },
        body: '{}',
      }),
    );
    expect(response.status).toBe(200);
    expect(
      ((await response.json()) as { data: { identity: { id: string } } }).data.identity.id,
    ).toBe(f.member.id);
    expect(
      (
        await OPTIONS(
          new Request('http://localhost:3000/api/iam/auth/getSession', {
            method: 'OPTIONS',
            headers: { origin: 'http://localhost:3000' },
          }),
        )
      ).status,
    ).toBe(204);
    expect(isAuthenticationError({ code: 'MFA_REQUIRED' })).toBe(true);
    expect(isAuthenticationError({ code: 'ACCESS_DENIED' })).toBe(false);
    expect(isAuthenticationError(new Error('x'))).toBe(false);
  });

  it('redirects visitors without a session cookie from middleware and leaves public paths alone', () => {
    const middleware = createIamMiddleware({ loginPath: '/signin' });
    const request = (url: string, cookies: string[] = []) => ({
      nextUrl: new URL(url),
      cookies: { has: (name: string) => cookies.includes(name) },
    });
    expect(middleware(request('http://localhost:3000/signin'))).toBeUndefined();
    expect(middleware(request('http://localhost:3000/api/iam/auth/signIn'))).toBeUndefined();
    const redirected = middleware(request('http://localhost:3000/projects/1?tab=x'))!;
    expect(redirected.status).toBe(307);
    expect(redirected.headers.get('location')).toBe(
      'http://localhost:3000/signin?next=%2Fprojects%2F1%3Ftab%3Dx',
    );
    expect(
      middleware(request('http://localhost:3000/projects/1', [sessionCookieName(false)])),
    ).toBeUndefined();
    expect(
      middleware(request('https://app.example.test/projects/1', [sessionCookieName(false)]))!
        .status,
    ).toBe(307);
    expect(
      middleware(request('https://app.example.test/projects/1', [sessionCookieName(true)])),
    ).toBeUndefined();
    const custom = createIamMiddleware({
      loginPath: '/login',
      protect: (pathname) => pathname.startsWith('/app'),
      nextParam: false,
    });
    expect(custom(request('http://localhost:3000/marketing'))).toBeUndefined();
    expect(custom(request('http://localhost:3000/app/x'))!.headers.get('location')).toBe(
      'http://localhost:3000/login',
    );
  });
});
