import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type BetterIamOptions } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

const ORIGIN = 'https://iam.example.com';

async function fixture(http?: BetterIamOptions['http']) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const iam = betterIam({
    database,
    secret: 'cookie-options-test-secret-with-32-chars!!',
    baseURL: ORIGIN,
    ...(http ? { http } : {}),
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  await iam.store.transaction((tx) =>
    iam.auth.createIdentity(tx, {
      tenantId: root.tenant.id,
      email: 'owner@example.test',
      name: 'Owner',
      password: 'a strong tenant owner password',
      emailVerified: true,
    }),
  );
  const signIn = (headers: Record<string, string> = {}) =>
    iam.handler(
      new Request(`${ORIGIN}/api/iam/auth/signIn`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1', ...headers },
        body: JSON.stringify({
          tenantId: root.tenant.id,
          email: 'owner@example.test',
          password: 'a strong tenant owner password',
        }),
      }),
    );
  const sessionCookie = (response: Response) =>
    response.headers.getSetCookie().find((line) => line.startsWith('__Host-better-iam.session='))!;
  return { iam, signIn, sessionCookie };
}

describe('cookie options', () => {
  it('issues persistent cookies by default and browser-session cookies on request', async () => {
    const f = await fixture();
    const persistent = f.sessionCookie(await f.signIn());
    expect(persistent).toMatch(/; Max-Age=\d+/);
    expect(persistent).toContain('HttpOnly; Secure; SameSite=Lax; Path=/');
    const transient = f.sessionCookie(await f.signIn({ 'x-better-iam-persistent': '0' }));
    expect(transient).not.toContain('Max-Age');
    expect(transient).toContain('HttpOnly; Secure; SameSite=Lax; Path=/');
    // An unknown header value falls back to the default.
    expect(f.sessionCookie(await f.signIn({ 'x-better-iam-persistent': 'maybe' }))).toMatch(
      /Max-Age=\d+/,
    );
    // Preflight requests advertise the header, and the request identifier, to cross-origin callers.
    const preflight = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/auth/signIn`, {
        method: 'OPTIONS',
        headers: { origin: ORIGIN },
      }),
    );
    expect(preflight.status).toBe(204);
    expect(preflight.headers.get('access-control-allow-headers')).toContain(
      'x-better-iam-persistent',
    );
    expect(preflight.headers.get('access-control-allow-headers')).toContain('x-request-id');
  });

  it('honours a deployment default of browser-session cookies and a strict SameSite policy', async () => {
    const f = await fixture({ persistentCookies: false, cookieSameSite: 'strict' });
    const transient = f.sessionCookie(await f.signIn());
    expect(transient).not.toContain('Max-Age');
    expect(transient).toContain('SameSite=Strict');
    const persistent = f.sessionCookie(await f.signIn({ 'x-better-iam-persistent': '1' }));
    expect(persistent).toMatch(/Max-Age=\d+/);
    expect(persistent).toContain('SameSite=Strict');
    // Signing out clears the cookie with the same attributes.
    const signedIn = await f.signIn();
    const token = f.sessionCookie(signedIn).split(';')[0]!.split('=')[1]!;
    const signOut = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/auth/signOut`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          origin: ORIGIN,
          cookie: `__Host-better-iam.session=${token}`,
        },
        body: '{}',
      }),
    );
    expect(signOut.status).toBe(200);
    expect(f.sessionCookie(signOut)).toContain('SameSite=Strict; Path=/; Max-Age=0');
    // The options are validated at construction.
    expect(() =>
      betterIam({
        database: sqliteAdapter({ filename: ':memory:' }),
        secret: 'cookie-options-test-secret-with-32-chars!!',
        baseURL: ORIGIN,
        http: { cookieSameSite: 'none' as never },
      }),
    ).toThrow(/cookieSameSite/);
  });
});
