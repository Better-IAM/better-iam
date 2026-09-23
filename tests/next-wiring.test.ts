import { afterEach, describe, expect, it } from 'vitest';
import { createIamNext, type CookieOptions } from '@better-iam/next';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

/** A stand-in for Next's cookies() store. */
function cookieJar() {
  const values = new Map<string, string>();
  const writes: { name: string; value: string; options?: CookieOptions }[] = [];
  return {
    values,
    writes,
    set(name: string, value: string, options?: CookieOptions) {
      writes.push({ name, value, options });
      if (options?.maxAge === 0) values.delete(name);
      else values.set(name, value);
    },
    toString: () =>
      [...values].map(([name, value]) => `${name}=${encodeURIComponent(value)}`).join('; '),
  };
}
class Redirect extends Error {
  constructor(readonly url: string) {
    super(`REDIRECT:${url}`);
  }
}
const redirect = (url: string): never => {
  throw new Redirect(url);
};
const form = (entries: Record<string, string>) => {
  const data = new FormData();
  for (const [key, value] of Object.entries(entries)) data.append(key, value);
  return data;
};

describe('createIamNext wiring for auth actions and background work', () => {
  it('binds auth actions to the request, dispatches mail after responses, and clears stale cookies', async () => {
    const f = await organizationFixture({ authentication: { passwordlessEmail: true } });
    await f.member('ada');
    await f.iam.api.tenants.setSlug(await f.ownerSignIn(), { tenantId: f.tenantId, slug: 'acme' });
    const jar = cookieJar();
    const deferred: (() => Promise<unknown>)[] = [];
    const iamNext = createIamNext(f.iam, {
      loginPath: '/signin',
      headers: () => new Headers({ cookie: jar.toString() }),
      cookies: () => jar,
      redirect,
      dispatchAfterResponse: true,
      background: {
        after: (task) => {
          deferred.push(task);
        },
      },
    });
    expect(iamNext.background).toBe(iamNext.background);
    const auth = iamNext.authActions({ afterSignIn: '/home' });

    await expect(
      auth.signIn(
        null,
        form({ org: 'acme', email: 'ada@acme.test', password: 'a strong ada password' }),
      ),
    ).rejects.toThrow('REDIRECT:/home');
    expect(jar.values.has('better-iam.session')).toBe(true);
    expect(
      (await iamNext.getSession(new Headers({ cookie: jar.toString() })))?.identity.email,
    ).toBe('ada@acme.test');

    // Mail queued by an action goes out only when the after-response task runs.
    deferred.length = 0;
    const delivered = f.inbox.length;
    const sent = await auth.signIn(
      null,
      form({ intent: 'send-code', org: 'acme', email: 'ada@acme.test' }),
    );
    expect(sent?.step).toBe('code-sent');
    expect(f.inbox.length).toBe(delivered);
    expect(deferred.length).toBeGreaterThan(0);
    for (const task of deferred.splice(0)) await task();
    expect(f.inbox.length).toBe(delivered + 1);
    expect(f.inbox.at(-1)).toMatchObject({ to: 'ada@acme.test' });

    // The HTTP mount schedules for POSTs only.
    const { GET, POST } = iamNext.handlers();
    await GET(new Request('http://localhost:3000/api/iam/health'));
    expect(deferred).toHaveLength(0);
    const response = await POST(
      new Request('http://localhost:3000/api/iam/auth/startPasswordless', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          origin: 'http://localhost:3000',
        },
        body: JSON.stringify({
          tenantId: f.tenantId,
          destination: 'ada@acme.test',
          channel: 'email',
          kind: 'code',
        }),
      }),
    );
    expect(response.status).toBe(200);
    expect(deferred).toHaveLength(1);
    await deferred.pop()!();
    expect(f.inbox.length).toBe(delivered + 2);

    // A session the server already ended: sign-out still clears the cookie and redirects to the login path.
    const token = decodeURIComponent(jar.values.get('better-iam.session')!);
    await f.iam.api.auth.signOut({ token });
    expect(await iamNext.getSession(new Headers({ cookie: jar.toString() }))).toBeNull();
    await expect(auth.signOut()).rejects.toThrow('REDIRECT:/signin');
    expect(jar.values.has('better-iam.session')).toBe(false);
    expect(jar.writes.at(-1)).toMatchObject({
      name: 'better-iam.session',
      value: '',
      options: { maxAge: 0, path: '/', httpOnly: true, secure: false },
    });

    // On HTTPS deployments the cleared cookie is the host-prefixed one.
    const secureJar = cookieJar();
    const secure = createIamNext(
      { ...f.iam, endpoint: { ...f.iam.endpoint, secure: true } },
      { cookies: () => secureJar, headers: () => new Headers() },
    );
    await secure.clearSessionCookie();
    expect(secureJar.writes).toEqual([
      {
        name: '__Host-better-iam.session',
        value: '',
        options: { maxAge: 0, path: '/', httpOnly: true, secure: true, sameSite: 'lax' },
      },
    ]);
  });
});
