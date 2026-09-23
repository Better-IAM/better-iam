import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { IamError } from '@better-iam/core';
import type { BetterIamOptions } from '@better-iam/server';
import { createIamNext, type CookieOptions } from '@better-iam/next';
import {
  authHiddenFields,
  createAuthActions,
  type AuthActionsHost,
} from '../packages/next/src/auth-actions.js';
import type { AuthAction, AuthFormState } from '../packages/next/src/auth-types.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
afterEach(closeFixtures);

const OWNER = 'owner@acme.test';
const OWNER_PASSWORD = 'a strong tenant owner password';
/** Records the address the in-process client forwards (`x-real-ip`), so the tenant's network policies apply. */
const networkOptions: Partial<BetterIamOptions> = {
  http: {
    clientInfo: (request) => {
      const ip = request.headers.get('x-real-ip');
      return ip ? { ip } : {};
    },
  },
};

/** A stand-in for Next's cookies() store: records writes and serializes like RequestCookies. */
function cookieJar() {
  const values = new Map<string, string>();
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
class Redirect extends Error {
  constructor(readonly target: string) {
    super(`NEXT_REDIRECT:${target}`);
  }
}
const redirect = (url: string): never => {
  throw new Redirect(url);
};

type Fields = Record<string, string | string[] | undefined>;
function formData(fields: Fields): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields))
    for (const item of value === undefined ? [] : Array.isArray(value) ? value : [value])
      data.append(name, item);
  return data;
}
/** Runs an action like a form submission: either a state to render or the redirect it performed. */
async function submit(
  action: AuthAction,
  fields: Fields,
): Promise<{ state?: AuthFormState | null; redirect?: string }> {
  try {
    return { state: await action(null, formData(fields)) };
  } catch (error) {
    if (error instanceof Redirect) return { redirect: error.target };
    throw error;
  }
}
const hidden = (state: AuthFormState | null | undefined): Record<string, string> =>
  Object.fromEntries(authHiddenFields(state ?? null));

/**
 * The shared organization fixture ("Acme", owner@acme.test) with sign-up, emailed sign-in codes and emailed MFA codes
 * on, MFA required for addresses starting with "mfa", and a fake DNS for domain discovery. The actions run against
 * `createIamNext` with a cookie jar standing in for Next's `cookies()`.
 */
async function setup(overrides: Partial<BetterIamOptions> = {}) {
  const dns = new Map<string, string[][]>();
  const f = await organizationFixture({
    domains: {
      resolveTxt: async (hostname) => {
        const records = dns.get(hostname);
        if (!records) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
        return records;
      },
    },
    ...overrides,
    authentication: {
      signUpEnabled: true,
      passwordlessEmail: true,
      mfaEmailCodes: true,
      requireMfa: (_tenant, identity) => identity.email?.startsWith('mfa') === true,
      ...overrides.authentication,
    },
  });
  const jar = cookieJar();
  let ip: string | undefined;
  const iamNext = createIamNext(f.iam, {
    headers: () => new Headers({ cookie: jar.toString(), ...(ip ? { 'x-real-ip': ip } : {}) }),
    cookies: () => jar,
    redirect,
  });
  let cleared = 0;
  const host = Object.assign(iamNext, {
    async clearSessionCookie() {
      cleared++;
      jar.set('better-iam.session', '', { maxAge: 0 });
    },
  });
  const mail = async (template: string, to: string): Promise<Record<string, string>> => {
    await f.iam.auth.dispatchOutbox();
    const message = f.inbox.filter((item) => item.template === template && item.to === to).at(-1);
    if (!message) throw new Error(`No ${template} email to ${to}`);
    return message.payload;
  };
  return {
    ...f,
    dns,
    jar,
    iamNext,
    host,
    actions: createAuthActions(host, { redirect }),
    cleared: () => cleared,
    mail,
    session: () => iamNext.getSession(new Headers({ cookie: jar.toString() })),
    sessionToken: () => jar.values.get('better-iam.session'),
    /** The last session cookie written: its `maxAge` is undefined for a browser-session cookie. */
    lastSessionWrite: () =>
      jar.writes.filter((write) => write.name === 'better-iam.session').at(-1),
    /** Whether the server still accepts a session token. */
    live: (token: string | undefined) =>
      f.iam.api.auth.getSession({ token: token ?? '' }).then(
        () => true,
        (error: { code?: string }) => {
          if (error.code === 'UNAUTHENTICATED') return false;
          throw error;
        },
      ),
    /** The client address of the requests that follow (recorded with the `clientInfo` of `networkOptions`). */
    from: (address: string | undefined) => {
      ip = address;
    },
    /** Invites `email` as the owner and returns the token from the invitation email. */
    invite: async (email: string, name?: string): Promise<string> => {
      await f.iam.api.identities.invite(f.ownerCredential, {
        tenantId: f.tenantId,
        email,
        ...(name ? { name } : {}),
      });
      return (await mail('member-invitation', email)).token!;
    },
    /** A TOTP code `steps` periods after the server's clock (replay protection refuses a spent period). */
    totp: (secret: string, steps = 0): string => {
      const generator = authenticator.clone();
      generator.options = { epoch: f.now() + steps * 30_000 };
      return generator.generate(secret);
    },
  };
}

describe('Next.js auth server actions', () => {
  it('signs in with a password, honors a safe next, and writes the session cookie', async () => {
    const t = await setup();
    const signIn = (fields: Fields) =>
      submit(t.actions.signIn, {
        tenantId: t.tenantId,
        email: OWNER,
        password: OWNER_PASSWORD,
        ...fields,
      });
    expect(await signIn({ next: '/projects?tab=1#top' })).toEqual({
      redirect: '/projects?tab=1#top',
    });
    expect(t.jar.writes).toHaveLength(1);
    expect(t.jar.writes[0]).toMatchObject({
      name: 'better-iam.session',
      options: { httpOnly: true, path: '/' },
    });
    expect(t.jar.writes[0]!.options!.maxAge).toBeGreaterThan(0);
    expect((await t.session())?.identity.id).toBe(t.ownerId);

    for (const unsafe of [
      '//evil.example/x',
      'https://evil.example',
      '/\\evil.example',
      'relative',
    ])
      expect(await signIn({ next: unsafe })).toEqual({ redirect: '/' });
    const home = createAuthActions(t.host, { redirect, afterSignIn: '/home' });
    expect(
      await submit(home.signIn, { tenantId: t.tenantId, email: OWNER, password: OWNER_PASSWORD }),
    ).toEqual({ redirect: '/home' });

    // "Keep me signed in": a hidden 0 before the checkbox; unticked means a browser-session cookie.
    await signIn({ keepSignedIn: '0' });
    expect(t.jar.writes.at(-1)!.options!.maxAge).toBeUndefined();
    await signIn({ keepSignedIn: ['0', '1'] });
    expect(t.jar.writes.at(-1)!.options!.maxAge).toBeGreaterThan(0);

    // An organization alias instead of a tenant ID, typed with any case.
    await t.iam.api.tenants.setSlug(t.rootCredential, { tenantId: t.tenantId, slug: 'acme' });
    expect(
      await submit(t.actions.signIn, { org: ' Acme ', email: OWNER, password: OWNER_PASSWORD }),
    ).toEqual({ redirect: '/' });
  });

  it('never redirects off-site, also when dot segments resolve to a protocol-relative path', async () => {
    const t = await setup();
    const signIn = (next: string, password = OWNER_PASSWORD) =>
      submit(t.actions.signIn, { tenantId: t.tenantId, email: OWNER, password, next });
    // Resolving `.` and `..` segments turns each of these into //evil.example, another origin.
    for (const unsafe of [
      '/.//evil.example/login',
      '/..//evil.example',
      '/%2e//evil.example',
      '/a/..//evil.example',
    ])
      expect(await signIn(unsafe)).toEqual({ redirect: '/' });
    const { state } = await signIn('/.//evil.example', 'not the right password');
    expect(state).toMatchObject({ step: 'credentials', error: { code: 'INVALID_CREDENTIALS' } });
    expect(state!.next).toBeUndefined();
    expect(hidden(state)).toEqual({});
    // Dot segments that stay on this site resolve as usual.
    expect(await signIn('/a/../projects')).toEqual({ redirect: '/projects' });
  });

  it('reports refusals on the right field without echoing secrets', async () => {
    const t = await setup();
    const { state: wrong } = await submit(t.actions.signIn, {
      tenantId: t.tenantId,
      email: OWNER,
      password: 'not the right password',
      next: '/after',
    });
    expect(wrong).toEqual({
      step: 'credentials',
      values: { email: OWNER, tenantId: t.tenantId },
      next: '/after',
      error: {
        code: 'INVALID_CREDENTIALS',
        message: 'Invalid email or password',
        field: 'password',
      },
    });
    expect(JSON.stringify(wrong)).not.toContain('not the right password');
    expect(t.jar.writes).toHaveLength(0);

    const { state: unknown } = await submit(t.actions.signIn, {
      org: 'nope',
      email: OWNER,
      password: OWNER_PASSWORD,
    });
    expect(unknown).toMatchObject({
      step: 'credentials',
      values: { org: 'nope', email: OWNER },
      error: { code: 'UNKNOWN_ORGANIZATION', field: 'org' },
    });
    expect(
      (await submit(t.actions.signIn, { email: OWNER, password: OWNER_PASSWORD })).state?.error,
    ).toMatchObject({ code: 'INVALID_INPUT', field: 'org' });
    expect(
      (await submit(t.actions.signIn, { tenantId: t.tenantId, email: OWNER })).state?.error,
    ).toMatchObject({ code: 'INVALID_INPUT', field: 'password' });

    const translated = createAuthActions(t.host, {
      redirect,
      messages: { INVALID_CREDENTIALS: 'E-Mail oder Passwort falsch' },
    });
    expect(
      (
        await submit(translated.signIn, {
          tenantId: t.tenantId,
          email: OWNER,
          password: 'still not the password',
        })
      ).state?.error,
    ).toEqual({
      code: 'INVALID_CREDENTIALS',
      message: 'E-Mail oder Passwort falsch',
      field: 'password',
    });

    // A host-provided tenant (single-tenant apps, subdomains) replaces the form fields.
    const fixed = createAuthActions(t.host, { redirect, resolveTenant: async () => t.tenantId });
    expect(await submit(fixed.signIn, { email: OWNER, password: OWNER_PASSWORD })).toEqual({
      redirect: '/',
    });
    const none = createAuthActions(t.host, { redirect, resolveTenant: async () => null });
    expect(
      (await submit(none.signIn, { email: OWNER, password: OWNER_PASSWORD })).state?.error,
    ).toMatchObject({ code: 'UNKNOWN_ORGANIZATION', field: 'org' });
  });

  it('enrolls an authenticator during sign-in, then takes its codes, recovery codes, and step-up', async () => {
    const t = await setup();
    const email = 'mfa-grace@acme.test';
    const password = 'a strong grace password';
    // The account exists without an authenticator: the invitation's enrollment was never finished.
    const accepted = await t.iam.api.identities.acceptInvitation({
      tenantId: t.tenantId,
      token: await t.invite(email, 'Grace'),
      password,
    });
    expect('mfaRequired' in accepted).toBe(true);
    const signIn = (fields: Fields = {}) =>
      submit(t.actions.signIn, { tenantId: t.tenantId, email, password, ...fields });

    const { state: enroll } = await signIn({ next: '/secure', keepSignedIn: ['0', '1'] });
    expect(enroll).toMatchObject({
      step: 'enroll',
      next: '/secure',
      keepSignedIn: true,
      values: { email, tenantId: t.tenantId },
      mfa: {
        tenantId: t.tenantId,
        enrollmentRequired: true,
        emailCodeAvailable: true,
        passkeyAvailable: false,
        enrollment: {
          secret: expect.any(String),
          uri: expect.stringMatching(/^otpauth:\/\/totp\//),
        },
      },
    });
    expect(JSON.stringify(enroll)).not.toContain(password);
    expect(t.jar.writes).toHaveLength(0);
    const secret = enroll!.mfa!.enrollment!.secret;
    expect(hidden(enroll)).toEqual({
      next: '/secure',
      keepSignedIn: '1',
      email,
      tenantId: t.tenantId,
      challenge: enroll!.mfa!.challenge,
      enrollmentRequired: '1',
      emailCodeAvailable: '1',
      secret,
      uri: enroll!.mfa!.enrollment!.uri,
    });

    // A refused code keeps the same secret on screen, rebuilt from the hidden fields.
    const { state: retry } = await submit(t.actions.signIn, {
      ...hidden(enroll),
      intent: 'enroll',
      code: '12345',
    });
    expect(retry).toMatchObject({
      step: 'enroll',
      error: { code: 'INVALID_MFA', field: 'code' },
      mfa: { challenge: enroll!.mfa!.challenge, enrollment: { secret } },
    });
    const { state: done } = await submit(t.actions.signIn, {
      ...hidden(retry),
      intent: 'enroll',
      code: t.totp(secret),
    });
    expect(done).toMatchObject({ step: 'done', next: '/secure', keepSignedIn: true });
    expect(done!.recoveryCodes).toHaveLength(10);
    expect(JSON.stringify(done)).not.toMatch(/"token"|"session"|"challenge"/);
    expect(t.jar.writes).toHaveLength(1);
    expect(t.jar.writes[0]!.options!.maxAge).toBeGreaterThan(0);
    expect((await t.session())?.session.mfa).toBe(true);

    // Enrolled: the next sign-in asks for a code. The enrollment spent this period's code, so use the next one.
    t.jar.values.clear();
    const { state: challenge } = await signIn();
    expect(challenge).toMatchObject({
      step: 'mfa',
      mfa: { enrollmentRequired: false, emailCodeAvailable: false, passkeyAvailable: false },
    });
    expect(challenge!.mfa!.enrollment).toBeUndefined();
    expect(
      (await submit(t.actions.signIn, { ...hidden(challenge), intent: 'mfa' })).state,
    ).toMatchObject({ step: 'mfa', error: { code: 'INVALID_INPUT', field: 'code' } });
    expect(
      await submit(t.actions.signIn, {
        ...hidden(challenge),
        intent: 'mfa',
        code: t.totp(secret, 1),
        next: '/after-mfa',
      }),
    ).toEqual({ redirect: '/after-mfa' });
    expect((await t.session())?.session.mfa).toBe(true);

    // A recovery code, typed grouped and uppercase, is spent once.
    const recoveryCode = done!.recoveryCodes![0]!;
    const { state: again } = await signIn();
    expect(
      await submit(t.actions.signIn, {
        ...hidden(again),
        intent: 'recovery',
        code: recoveryCode.toUpperCase().replace(/(.{4})(?!$)/g, '$1-'),
      }),
    ).toEqual({ redirect: '/' });
    const { state: third } = await signIn();
    const { state: reused } = await submit(t.actions.signIn, {
      ...hidden(third),
      intent: 'recovery',
      code: recoveryCode,
    });
    expect(reused).toMatchObject({ step: 'mfa', error: { code: 'INVALID_MFA', field: 'code' } });
    expect(JSON.stringify(reused)).not.toContain(recoveryCode);

    // A challenge that is gone cannot be retried: back to the credentials.
    const { state: expired } = await submit(t.actions.signIn, {
      ...hidden(third),
      challenge: 'a-challenge-that-does-not-exist',
      intent: 'mfa',
      code: '123456',
    });
    expect(expired).toMatchObject({ step: 'credentials', error: { code: 'INVALID_CHALLENGE' } });
    expect(expired!.mfa).toBeUndefined();
    expect(await submit(t.actions.signIn, { ...hidden(third), intent: 'cancel' })).toEqual({
      state: { step: 'credentials', values: { email } },
    });

    // Step-up for the current session: password, then the authenticator, then a new session.
    t.advance(30_000);
    const before = t.sessionToken();
    const { state: stepUp } = await submit(t.actions.reauthenticate, {
      password,
      next: '/settings',
    });
    expect(stepUp).toMatchObject({ step: 'mfa', next: '/settings', mfa: { tenantId: t.tenantId } });
    expect(
      await submit(t.actions.reauthenticate, {
        ...hidden(stepUp),
        intent: 'mfa',
        code: t.totp(secret, 1),
      }),
    ).toEqual({ redirect: '/settings' });
    expect(t.sessionToken()).not.toBe(before);
    expect((await t.session())?.session.mfa).toBe(true);
    // The session it replaced is ended, and the form never asked for a persistent cookie.
    expect(await t.live(before)).toBe(false);
    expect(t.lastSessionWrite()!.options!.maxAge).toBeUndefined();
  });

  it('accepts an invitation into an MFA account and finishes with an emailed code', async () => {
    const t = await setup();
    const email = 'mfa-ada@acme.test';
    const token = await t.invite(email, 'Ada');
    const { state: enroll } = await submit(t.actions.acceptInvitation, {
      tenantId: t.tenantId,
      token,
      password: 'a strong ada password',
      confirmPassword: 'a strong ada password',
      next: '/welcome',
    });
    expect(enroll).toMatchObject({
      step: 'enroll',
      next: '/welcome',
      mfa: { tenantId: t.tenantId, enrollmentRequired: true, emailCodeAvailable: true },
    });
    expect(JSON.stringify(enroll)).not.toContain(token);
    expect(t.jar.writes).toHaveLength(0);

    const { state: emailed } = await submit(t.actions.acceptInvitation, {
      ...hidden(enroll),
      intent: 'email-code',
    });
    expect(emailed).toMatchObject({
      step: 'mfa',
      notice: 'We emailed you a sign-in code.',
      mfa: { emailCodeAvailable: true, enrollment: enroll!.mfa!.enrollment },
    });
    const { code } = await t.mail('mfa-code', email);
    expect(
      await submit(t.actions.acceptInvitation, { ...hidden(emailed), intent: 'mfa', code }),
    ).toEqual({ redirect: '/welcome' });
    const session = await t.session();
    expect(session?.identity.email).toBe(email);
    expect(session?.session.mfa).toBe(true);
  });

  it('sends an invited person to sign in when the MFA step of the invitation lapses', async () => {
    const t = await setup();
    const email = 'mfa-lee@acme.test';
    const password = 'a strong lee password';
    const token = await t.invite(email, 'Lee');
    const { state: enroll } = await submit(t.actions.acceptInvitation, {
      tenantId: t.tenantId,
      token,
      password,
      next: '/welcome',
    });
    expect(enroll).toMatchObject({ step: 'enroll', next: '/welcome' });
    // Installing an authenticator took longer than the five-minute challenge.
    t.advance(6 * 60_000);
    const { state: lapsed } = await submit(t.actions.acceptInvitation, {
      ...hidden(enroll),
      intent: 'enroll',
      code: t.totp(enroll!.mfa!.enrollment!.secret),
    });
    expect(lapsed).toEqual({
      step: 'done',
      values: {},
      next: '/login?next=%2Fwelcome',
      notice: 'Your account is ready, but this verification step has expired. Sign in to continue.',
    });
    expect(hidden(lapsed)).toEqual({ next: '/login?next=%2Fwelcome' });
    expect(t.jar.writes).toHaveLength(0);
    // The invitation is spent, so its form can only fail; signing in starts a fresh enrollment.
    expect(
      (await submit(t.actions.acceptInvitation, { tenantId: t.tenantId, token, password })).state
        ?.error,
    ).toMatchObject({ code: 'INVITATION_INVALID' });
    expect(
      (await submit(t.actions.signIn, { tenantId: t.tenantId, email, password })).state,
    ).toMatchObject({ step: 'enroll', mfa: { enrollment: { secret: expect.any(String) } } });

    // A step posted without its challenge ends the same way; the link follows `loginPath`.
    const custom = createAuthActions(t.host, { redirect, loginPath: '/sign-in' });
    expect(
      (await submit(custom.acceptInvitation, { intent: 'mfa', code: '123456' })).state,
    ).toMatchObject({ step: 'done', next: '/sign-in' });
    // Sign-in itself keeps starting over at the credentials.
    expect((await submit(t.actions.signIn, { intent: 'mfa', code: '123456' })).state).toMatchObject(
      { step: 'credentials', error: { code: 'INVALID_CHALLENGE' } },
    );
  });

  it('carries "keep me signed in" through the MFA steps and remembers the device', async () => {
    const t = await setup();
    const email = 'mfa-kim@acme.test';
    const password = 'a strong kim password';
    const { state: enroll } = await submit(t.actions.acceptInvitation, {
      tenantId: t.tenantId,
      token: await t.invite(email, 'Kim'),
      password,
      keepSignedIn: '0',
    });
    expect(enroll).toMatchObject({ step: 'enroll', keepSignedIn: false });
    const secret = enroll!.mfa!.enrollment!.secret;
    const { state: done } = await submit(t.actions.acceptInvitation, {
      ...hidden(enroll),
      intent: 'enroll',
      code: t.totp(secret),
    });
    expect(done).toMatchObject({ step: 'done', keepSignedIn: false });
    expect(t.lastSessionWrite()!.options!.maxAge).toBeUndefined();

    const signIn = (fields: Fields = {}) =>
      submit(t.actions.signIn, { tenantId: t.tenantId, email, password, ...fields });
    // Unticked, a recovery code and an authenticator code both issue browser-session cookies.
    t.jar.values.clear();
    const { state: first } = await signIn({ keepSignedIn: '0' });
    expect(hidden(first)).toMatchObject({ keepSignedIn: '0' });
    expect(
      await submit(t.actions.signIn, {
        ...hidden(first),
        intent: 'recovery',
        code: done!.recoveryCodes![0]!,
      }),
    ).toEqual({ redirect: '/' });
    expect(t.lastSessionWrite()!.options!.maxAge).toBeUndefined();

    t.jar.values.clear();
    const { state: second } = await signIn({ keepSignedIn: '0' });
    expect(
      await submit(t.actions.signIn, {
        ...hidden(second),
        intent: 'mfa',
        code: t.totp(secret, 1),
        rememberDevice: '1',
      }),
    ).toEqual({ redirect: '/' });
    expect(t.lastSessionWrite()!.options!.maxAge).toBeUndefined();
    const device = t.jar.writes.find((write) => write.name === 'better-iam.device');
    expect(device?.options?.maxAge).toBeGreaterThan(0);

    // The remembered device skips the second factor at the next sign-in; ticked, the cookie persists.
    t.jar.values.delete('better-iam.session');
    expect(await signIn({ keepSignedIn: ['0', '1'] })).toEqual({ redirect: '/' });
    expect(t.lastSessionWrite()!.options!.maxAge).toBeGreaterThan(0);
    expect((await t.session())?.session.mfa).toBe(true);
  });

  it('signs in with an emailed code without revealing which addresses have accounts', async () => {
    const t = await setup();
    const { state: sent } = await submit(t.actions.signIn, {
      intent: 'send-code',
      tenantId: t.tenantId,
      email: OWNER,
      keepSignedIn: '0',
    });
    expect(sent).toEqual({
      step: 'code-sent',
      values: { email: OWNER, tenantId: t.tenantId },
      keepSignedIn: false,
      notice: `If ${OWNER} has an account, we sent it a sign-in code.`,
    });
    const { state: nobody } = await submit(t.actions.signIn, {
      intent: 'send-code',
      tenantId: t.tenantId,
      email: 'nobody@acme.test',
    });
    expect(nobody).toEqual({
      step: 'code-sent',
      values: { email: 'nobody@acme.test', tenantId: t.tenantId },
      notice: 'If nobody@acme.test has an account, we sent it a sign-in code.',
    });
    const { token } = await t.mail('code', OWNER);
    expect(t.inbox.some((message) => message.to === 'nobody@acme.test')).toBe(false);

    expect(hidden(sent)).toEqual({ keepSignedIn: '0', email: OWNER, tenantId: t.tenantId });
    const { state: wrong } = await submit(t.actions.signIn, {
      ...hidden(sent),
      intent: 'code',
      code: token === '000000' ? '111111' : '000000',
    });
    expect(wrong).toMatchObject({
      step: 'code-sent',
      error: { code: 'INVALID_CHALLENGE', field: 'code' },
    });
    expect(
      await submit(t.actions.signIn, { ...hidden(sent), intent: 'code', code: token! }),
    ).toEqual({ redirect: '/' });
    expect(t.jar.writes.at(-1)).toMatchObject({ name: 'better-iam.session' });
    expect(t.jar.writes.at(-1)!.options!.maxAge).toBeUndefined();
    expect((await t.session())?.identity.id).toBe(t.ownerId);
  });

  it('resets a forgotten password from the emailed link', async () => {
    const t = await setup();
    const { state: sent } = await submit(t.actions.requestPasswordReset, {
      tenantId: t.tenantId,
      email: OWNER,
    });
    expect(sent).toEqual({
      step: 'sent',
      values: { email: OWNER, tenantId: t.tenantId },
      notice: `If ${OWNER} has an account, we sent it a link to reset the password.`,
    });
    expect(
      (
        await submit(t.actions.requestPasswordReset, {
          tenantId: t.tenantId,
          email: 'nobody@acme.test',
        })
      ).state?.step,
    ).toBe('sent');
    // Addresses may contain `$`, which a string replacement would read as a pattern like $' or $&.
    const dollar = "a$'b$&c@acme.test";
    expect(
      (await submit(t.actions.requestPasswordReset, { tenantId: t.tenantId, email: dollar })).state
        ?.notice,
    ).toBe(`If ${dollar} has an account, we sent it a link to reset the password.`);
    const { token } = await t.mail('password-reset', OWNER);
    const reset = (fields: Fields) =>
      submit(t.actions.resetPassword, { tenantId: t.tenantId, token, ...fields });

    const { state: mismatch } = await reset({
      password: 'a brand new owner password',
      confirmPassword: 'a different new password',
    });
    expect(mismatch).toMatchObject({
      step: 'credentials',
      error: { code: 'PASSWORD_MISMATCH', field: 'confirmPassword' },
    });
    expect(JSON.stringify(mismatch)).not.toMatch(/brand new|different new/);
    expect(JSON.stringify(mismatch)).not.toContain(token!);
    expect((await reset({ password: 'short' })).state?.error).toMatchObject({
      code: 'WEAK_PASSWORD',
      field: 'password',
    });
    expect(
      await reset({
        password: 'a brand new owner password',
        confirmPassword: 'a brand new owner password',
      }),
    ).toEqual({ redirect: '/login?reset=1' });
    expect((await reset({ password: 'yet another new password' })).state?.error).toMatchObject({
      code: 'INVALID_CHALLENGE',
      field: 'token',
    });
    expect(
      (await submit(t.actions.resetPassword, { tenantId: t.tenantId })).state?.error,
    ).toMatchObject({
      code: 'INVALID_CHALLENGE',
      field: 'token',
    });

    const signIn = (password: string) =>
      submit(t.actions.signIn, { tenantId: t.tenantId, email: OWNER, password });
    expect((await signIn(OWNER_PASSWORD)).state?.error?.code).toBe('INVALID_CREDENTIALS');
    expect(await signIn('a brand new owner password')).toEqual({ redirect: '/' });
  });

  it('registers an account and verifies its email address', async () => {
    const t = await setup();
    const email = 'sam@acme.test';
    const password = 'a strong sam password';
    const { state } = await submit(t.actions.signUp, {
      tenantId: t.tenantId,
      email,
      name: 'Sam',
      password,
      confirmPassword: password,
    });
    expect(state).toEqual({
      step: 'sent',
      values: { email, name: 'Sam', tenantId: t.tenantId },
      notice: `We sent a link to ${email}. Open it to confirm your address, then sign in.`,
    });
    expect(
      (await submit(t.actions.signUp, { tenantId: t.tenantId, email, name: 'Sam', password })).state
        ?.error,
    ).toMatchObject({ code: 'IDENTITY_EXISTS', field: 'email' });
    expect(
      (await submit(t.actions.signUp, { tenantId: t.tenantId, email: 'x@acme.test', password }))
        .state?.error,
    ).toMatchObject({ code: 'INVALID_INPUT', field: 'name' });

    const signIn = () => submit(t.actions.signIn, { tenantId: t.tenantId, email, password });
    expect((await signIn()).state?.error?.code).toBe('EMAIL_UNVERIFIED');
    expect(
      (await submit(t.actions.verifyEmail, { tenantId: t.tenantId, token: 'not-a-real-token' }))
        .state?.error,
    ).toMatchObject({ code: 'INVALID_CHALLENGE', field: 'token' });
    const { token } = await t.mail('verify-email', email);
    expect(await submit(t.actions.verifyEmail, { tenantId: t.tenantId, token })).toEqual({
      redirect: '/login?verified=1',
    });
    expect(await signIn()).toEqual({ redirect: '/' });
  });

  it('accepts member and owner invitations and signs the new account in', async () => {
    const t = await setup();
    const token = await t.invite('lin@acme.test', 'Lin');
    const accept = (fields: Fields) =>
      submit(t.actions.acceptInvitation, { tenantId: t.tenantId, token, ...fields });
    expect(
      (await accept({ password: 'a strong lin password', confirmPassword: 'typo' })).state?.error,
    ).toMatchObject({ code: 'PASSWORD_MISMATCH', field: 'confirmPassword' });
    expect(await accept({ password: 'a strong lin password', next: '/start' })).toEqual({
      redirect: '/start',
    });
    expect(t.jar.writes).toHaveLength(1);
    expect((await t.session())?.identity).toMatchObject({ email: 'lin@acme.test', name: 'Lin' });
    const { state: spent } = await accept({ password: 'a strong lin password' });
    expect(spent).toMatchObject({
      step: 'credentials',
      values: { tenantId: t.tenantId },
      error: { code: 'INVITATION_INVALID', field: 'token' },
    });
    expect(JSON.stringify(spent)).not.toContain(token);

    const created = await t.iam.api.tenants.create(t.rootCredential, {
      parentId: t.root.tenant.id,
      name: 'Globex',
      type: 'organization',
      ownerEmail: 'owner@globex.test',
    });
    const { token: ownerToken } = await t.mail('owner-invitation', 'owner@globex.test');
    const owner = (fields: Fields) =>
      submit(t.actions.acceptInvitation, {
        kind: 'owner',
        tenantId: created.tenant.id,
        token: ownerToken,
        password: 'a strong globex owner password',
        ...fields,
      });
    expect((await owner({})).state?.error).toMatchObject({ code: 'INVALID_INPUT', field: 'name' });
    expect(await owner({ name: 'Globex Owner' })).toEqual({ redirect: '/' });
    expect((await t.session())?.identity).toMatchObject({
      email: 'owner@globex.test',
      owner: true,
    });
  });

  it('reauthenticates into a new session, ends the old one, and never extends the cookie', async () => {
    const t = await setup();
    const signIn = (fields: Fields = {}) =>
      submit(t.actions.signIn, {
        tenantId: t.tenantId,
        email: OWNER,
        password: OWNER_PASSWORD,
        ...fields,
      });
    // Signed in without "keep me signed in" on a shared computer: a browser-session cookie.
    await signIn({ keepSignedIn: '0' });
    const before = t.sessionToken();
    expect(before).toBeTruthy();
    const { state: wrong } = await submit(t.actions.reauthenticate, { password: 'wrong password' });
    expect(wrong).toMatchObject({
      step: 'credentials',
      error: { code: 'INVALID_CREDENTIALS', field: 'password' },
    });
    expect(t.sessionToken()).toBe(before);
    expect(await t.live(before)).toBe(true);
    expect(
      await submit(t.actions.reauthenticate, { password: OWNER_PASSWORD, next: '/danger-zone' }),
    ).toEqual({ redirect: '/danger-zone' });
    const after = t.sessionToken();
    expect(after).not.toBe(before);
    expect((await t.session())?.identity.id).toBe(t.ownerId);
    // Still a browser-session cookie, and a copy of the replaced token no longer works.
    expect(t.lastSessionWrite()!.options!.maxAge).toBeUndefined();
    expect(await t.live(before)).toBe(false);
    // Signing out afterwards leaves no session of this browser alive.
    await expect(t.actions.signOut()).rejects.toThrow('NEXT_REDIRECT:/login');
    expect(await t.live(after)).toBe(false);

    // A form that offers the choice can still ask for a persistent cookie.
    await signIn();
    expect(
      await submit(t.actions.reauthenticate, {
        password: OWNER_PASSWORD,
        keepSignedIn: ['0', '1'],
      }),
    ).toEqual({ redirect: '/' });
    expect(t.lastSessionWrite()!.options!.maxAge).toBeGreaterThan(0);
    // Signed out, there is nothing to step up.
    t.jar.values.clear();
    expect(
      (await submit(t.actions.reauthenticate, { password: OWNER_PASSWORD })).state?.error,
    ).toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it('signs out, clearing the cookie even when the session is already gone', async () => {
    const t = await setup();
    const signIn = () =>
      submit(t.actions.signIn, { tenantId: t.tenantId, email: OWNER, password: OWNER_PASSWORD });
    await signIn();
    await expect(t.actions.signOut(new FormData())).rejects.toThrow('NEXT_REDIRECT:/login');
    expect(t.jar.writes.at(-1)).toMatchObject({
      name: 'better-iam.session',
      value: '',
      options: { maxAge: 0 },
    });
    expect(t.sessionToken()).toBeUndefined();
    expect(t.cleared()).toBe(0);

    await signIn();
    await t.iam.api.auth.signOut({ token: t.sessionToken()! });
    const away = createAuthActions(t.host, { redirect, afterSignOut: '/goodbye' });
    await expect(away.signOut()).rejects.toThrow('NEXT_REDIRECT:/goodbye');
    expect(t.cleared()).toBe(1);
    expect(t.sessionToken()).toBeUndefined();

    const failing: AuthActionsHost = {
      client: () => ({
        $request: async () => {
          throw Object.assign(new Error('Internal error'), { code: 'INTERNAL_ERROR', status: 500 });
        },
      }),
      tenant: async () => null,
    };
    await expect(createAuthActions(failing, { redirect }).signOut()).rejects.toMatchObject({
      code: 'INTERNAL_ERROR',
    });
  });

  it('signs out of a session its network policy refuses by clearing the cookie', async () => {
    const t = await setup(networkOptions);
    const signIn = () =>
      submit(t.actions.signIn, { tenantId: t.tenantId, email: OWNER, password: OWNER_PASSWORD });

    // Bound to the office network, the session is refused at home (401 SESSION_NETWORK_MISMATCH).
    t.from('203.0.113.7');
    await signIn();
    await t.iam.api.tenants.setAuthPolicy(t.ownerCredential, {
      tenantId: t.tenantId,
      authPolicy: { bindSessionsToIp: true },
    });
    t.from('198.51.100.9');
    await expect(t.iamNext.client().auth.getSession()).rejects.toMatchObject({
      code: 'SESSION_NETWORK_MISMATCH',
    });
    await expect(t.actions.signOut()).rejects.toThrow('NEXT_REDIRECT:/login');
    expect(t.cleared()).toBe(1);
    expect(t.sessionToken()).toBeUndefined();

    // The organization stops allowing the network a session came from (403 IP_NOT_ALLOWED).
    await signIn();
    await t.iam.api.tenants.setAuthPolicy(t.ownerCredential, {
      tenantId: t.tenantId,
      authPolicy: { allowedIpRanges: ['203.0.113.0/24'] },
    });
    await expect(t.iamNext.client().auth.getSession()).rejects.toMatchObject({
      code: 'IP_NOT_ALLOWED',
    });
    await expect(t.actions.signOut()).rejects.toThrow('NEXT_REDIRECT:/login');
    expect(t.cleared()).toBe(2);
    expect(t.sessionToken()).toBeUndefined();

    // A refusal of the request rather than the session propagates, and the cookie stays.
    let cleared = false;
    const rejecting: AuthActionsHost = {
      client: () => ({
        $request: async () => {
          throw Object.assign(new Error('Origin is not trusted'), {
            name: 'IamClientError',
            code: 'UNTRUSTED_ORIGIN',
            status: 403,
          });
        },
      }),
      tenant: async () => null,
      clearSessionCookie: async () => {
        cleared = true;
      },
    };
    await expect(createAuthActions(rejecting, { redirect }).signOut()).rejects.toMatchObject({
      code: 'UNTRUSTED_ORIGIN',
    });
    expect(cleared).toBe(false);
  });

  it('carries retryAfterMs on RATE_LIMITED and redirects sign-ups that need no verification', async () => {
    const t = await setup({
      authentication: { rateLimits: { attempts: 2 }, requireEmailVerification: false },
    });
    const attempt = () =>
      submit(t.actions.signIn, { tenantId: t.tenantId, email: OWNER, password: 'wrong password' });
    expect((await attempt()).state?.error?.code).toBe('INVALID_CREDENTIALS');
    expect((await attempt()).state?.error?.code).toBe('INVALID_CREDENTIALS');
    const { state } = await attempt();
    expect(state).toMatchObject({ step: 'credentials', error: { code: 'RATE_LIMITED' } });
    expect(state!.error!.retryAfterMs).toBeGreaterThan(0);
    expect(state!.error!.field).toBeUndefined();

    const custom = createAuthActions(t.host, { redirect, loginPath: '/sign-in' });
    expect(
      await submit(custom.signUp, {
        tenantId: t.tenantId,
        email: 'kim@acme.test',
        name: 'Kim',
        password: 'a strong kim password',
      }),
    ).toEqual({ redirect: '/sign-in?registered=1' });
  });

  it('discovers the organization from a verified email domain', async () => {
    const t = await setup();
    const claimed = await t.iam.api.domains.add(t.ownerCredential, {
      tenantId: t.tenantId,
      domain: 'acme.example',
    });
    t.dns.set(claimed.dnsRecord.name, [[claimed.dnsRecord.value]]);
    await t.iam.api.domains.verify(t.ownerCredential, {
      tenantId: t.tenantId,
      domainId: claimed.id,
    });
    await t.iam.api.identities.acceptInvitation({
      tenantId: t.tenantId,
      token: await t.invite('lin@acme.example', 'Lin'),
      password: 'a strong lin password',
    });
    const discovering = createAuthActions(t.host, { redirect, discover: true });
    expect(
      await submit(discovering.signIn, {
        email: 'lin@acme.example',
        password: 'a strong lin password',
      }),
    ).toEqual({ redirect: '/' });
    expect((await t.session())?.identity.email).toBe('lin@acme.example');
    expect(
      (
        await submit(discovering.signIn, {
          email: 'lin@unknown.example',
          password: 'whatever it is',
        })
      ).state?.error,
    ).toMatchObject({ code: 'UNKNOWN_ORGANIZATION', field: 'org' });
  });

  it('lets bugs and Next control flow propagate', async () => {
    const buggy: AuthActionsHost = {
      client: () => ({
        $request: async () => {
          throw new Error('boom');
        },
      }),
      tenant: async () => {
        throw Object.assign(new Error('NEXT_HTTP_ERROR_FALLBACK'), {
          digest: 'NEXT_HTTP_ERROR_FALLBACK;404',
          code: 'NOT_FOUND',
        });
      },
    };
    const actions = createAuthActions(buggy, { redirect });
    await expect(
      actions.signIn(null, formData({ tenantId: 't', email: 'a@b.test', password: 'pw' })),
    ).rejects.toThrow('boom');
    await expect(
      actions.signIn(null, formData({ org: 'acme', email: 'a@b.test', password: 'pw' })),
    ).rejects.toMatchObject({ digest: 'NEXT_HTTP_ERROR_FALLBACK;404' });
    expect(authHiddenFields(null)).toEqual([]);

    // Host code failing with a code of its own (a database outage) is not a form error: its message stays private.
    const outage = createAuthActions(buggy, {
      redirect,
      resolveTenant: async () => {
        throw Object.assign(new Error('connect ECONNREFUSED 10.0.4.17:5432'), {
          code: 'ECONNREFUSED',
        });
      },
    });
    await expect(
      outage.signIn(null, formData({ email: 'a@b.test', password: 'pw' })),
    ).rejects.toMatchObject({ code: 'ECONNREFUSED' });
    // An IamError from host code is a refusal like the server's own.
    const closed = createAuthActions(buggy, {
      redirect,
      resolveTenant: async () => {
        throw new IamError('TENANT_UNAVAILABLE', 'Tenant is not active', 403);
      },
    });
    expect(
      (await closed.signIn(null, formData({ email: 'a@b.test', password: 'pw' })))?.error,
    ).toEqual({ code: 'TENANT_UNAVAILABLE', message: 'Tenant is not active' });
  });
});
