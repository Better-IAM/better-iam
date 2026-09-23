import { createRequire } from 'node:module';
import type { GetServerSidePropsContext, NextApiRequest, NextApiResponse } from 'next';
import { afterEach, describe, expect, expectTypeOf, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  checkStepUp,
  createIamNext,
  isNextControlError,
  pathnameHeader,
  type IamPrincipal,
} from '@better-iam/next';
import { IamClientError } from '@better-iam/client';
import { IamError, type IamStore, type Session } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';
import { generateTestKey } from './support/jwt-keys.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
// Next's own digest step for errors thrown by server components; production error.tsx receives only its result.
const { createFlightReactServerErrorHandler } = createRequire(
  new URL('../packages/next/package.json', import.meta.url),
)('next/dist/server/app-render/create-error-handler.js') as {
  createFlightReactServerErrorHandler: (
    format: boolean,
    report: (error: unknown) => void,
  ) => (error: unknown) => string | undefined;
};
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});
afterEach(closeFixtures);
const minute = 60_000;
const noParams = { params: Promise.resolve({}) };

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const iam = betterIam({
    database,
    secret: 'next-step-up-test-secret-with-32-characters',
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
  const tenantId = root.tenant.id;
  const challenge = await iam.api.auth.signIn({
    tenantId,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({ tenantId, challenge: challenge.challenge });
  const rootSession = await iam.api.auth.confirmMfa({
    credential: { tenantId, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const owner = { token: rootSession.token };
  const member = await iam.api.identities.create(owner, {
    tenantId,
    email: 'member@example.test',
    name: 'Member',
    password: 'a strong member test password',
  });
  const login = await iam.api.auth.signIn({
    tenantId,
    email: 'member@example.test',
    password: 'a strong member test password',
  });
  if (!('token' in login)) throw new Error('Unexpected MFA');
  const account = await iam.api.serviceAccounts.create(owner, { tenantId, name: 'ci' });
  const reader = await iam.api.roles.create(owner, {
    tenantId,
    name: 'Document reader',
    document: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['document/*'] }],
    },
  });
  await iam.api.bindings.create(owner, {
    tenantId,
    roleId: reader.id,
    subjectType: 'identity',
    subjectId: account.id,
  });
  const key = await iam.api.credentials.create(owner, {
    tenantId,
    identityId: account.id,
    name: 'deploy',
  });
  return {
    iam,
    tenantId,
    member,
    account,
    memberToken: login.token,
    cookie: `better-iam.session=${login.token}`,
    rootToken: rootSession.token,
    apiKey: key.token,
  };
}

/**
 * A platform operator ("ops", root tenant) who may impersonate members there and assume a document-reader role in
 * the Acme organization through a trust that requires MFA. Ops enrolls MFA and remembers this browser: `remembered`
 * is a session whose second factor came from the device, `enrolled` one that verified it first-hand.
 */
async function operatorFixture() {
  const f = await organizationFixture();
  const { iam } = f;
  const platform = f.root.tenant.id;
  const password = 'a strong operator test password';
  const ops = await iam.api.identities.create(f.rootCredential, {
    tenantId: platform,
    email: 'ops@example.test',
    name: 'Ops',
    password,
  });
  const customer = await iam.api.identities.create(f.rootCredential, {
    tenantId: platform,
    email: 'customer@example.test',
    name: 'Customer',
    password: 'a strong customer test password',
  });
  const support = await iam.api.roles.create(f.rootCredential, {
    tenantId: platform,
    name: 'Support',
    document: {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['iam:roles:assume', 'iam:identities:impersonate'],
          resources: ['*'],
        },
      ],
    },
  });
  await iam.api.bindings.create(f.rootCredential, {
    tenantId: platform,
    roleId: support.id,
    subjectType: 'identity',
    subjectId: ops.id,
  });
  await iam.api.tenants.setAuthPolicy(f.rootCredential, {
    tenantId: platform,
    authPolicy: { allowImpersonation: true },
  });
  const reader = await iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Document reader',
    document: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['document/*'] }],
    },
  });
  const trust = await iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: platform,
    sourceIdentityId: ops.id,
    roleId: reader.id,
    requireMfa: true,
  });
  const login = await iam.api.auth.signIn({
    tenantId: platform,
    email: 'ops@example.test',
    password,
  });
  if (!('token' in login)) throw new Error('Unexpected MFA');
  const enrollment = await iam.api.auth.beginMfa({ token: login.token });
  const generator = authenticator.clone();
  generator.options = { epoch: f.now() };
  const enrolled = await iam.api.auth.confirmMfa({
    credential: { token: login.token },
    code: generator.generate(enrollment.secret),
    rememberDevice: true,
  });
  const remembered = await iam.api.auth.signIn({
    tenantId: platform,
    email: 'ops@example.test',
    password,
    deviceToken: enrolled.deviceToken!,
  });
  if (!('token' in remembered) || !remembered.session.trustedDeviceId)
    throw new Error('The remembered device should satisfy MFA');
  return { ...f, platform, ops, customer, reader, trust, enrolled, remembered };
}
const bearer = (token: string) => ({ authorization: `Bearer ${token}` });

/** A clock the tests move forward; sessions issued just before it are recent. */
function testClock() {
  const clock = { at: Date.now(), now: () => clock.at };
  return clock;
}
class Interrupt extends Error {
  constructor(readonly target: string) {
    super(`INTERRUPT:${target}`);
  }
}
const redirect = (url: string): never => {
  throw new Interrupt(`redirect:${url}`);
};
const call = (
  handler: (request: Request, context: typeof noParams) => Promise<Response>,
  headers: HeadersInit,
) => handler(new Request('http://localhost:3000/api/x', { headers }), noParams);

function pagesContext(headers: Record<string, string>, resolvedUrl = '/billing?tab=2') {
  return {
    req: { headers },
    res: {},
    params: {},
    query: {},
    resolvedUrl,
  } as unknown as GetServerSidePropsContext;
}
function pagesResponse() {
  const state = { status: 200, body: undefined as unknown, ended: false };
  const res = {
    headersSent: false,
    get writableEnded() {
      return state.ended;
    },
    setHeader: () => res,
    status(code: number) {
      state.status = code;
      return res;
    },
    json(body: unknown) {
      state.body = body;
      state.ended = true;
      return res;
    },
    end() {
      state.ended = true;
      return res;
    },
  };
  return { res: res as unknown as NextApiResponse, state };
}
const pagesRequest = (headers: Record<string, string>, method = 'GET') =>
  ({ headers, method, url: '/api/x', query: {}, cookies: {} }) as unknown as NextApiRequest;

describe('checkStepUp', () => {
  const now = 1_000_000_000_000;
  const session = (fields: Record<string, unknown> = {}) => ({
    identity: { id: 'i1' },
    session: { id: 's1', kind: 'user', mfa: false, authenticatedAt: now, ...fields },
    limits: {},
  });

  it('requires MFA, and a fresh second factor for mfa: fresh', () => {
    expect(checkStepUp(session(), {}, now)).toBeNull();
    expect(checkStepUp(session(), { mfa: true }, now)).toEqual({
      code: 'MFA_REQUIRED',
      reason: 'mfa',
      message: 'Multi-factor authentication is required',
      status: 403,
    });
    expect(checkStepUp(session({ mfa: true }), { mfa: true }, now)).toBeNull();
    expect(checkStepUp(session(), { mfa: false }, now)).toBeNull();
    const remembered = session({ mfa: true, trustedDeviceId: 'device-1' });
    expect(checkStepUp(remembered, { mfa: true }, now)).toBeNull();
    expect(checkStepUp(remembered, { mfa: 'fresh' }, now)).toMatchObject({
      code: 'MFA_REQUIRED',
      reason: 'mfa',
      status: 403,
    });
    expect(checkStepUp(session({ mfa: true }), { mfa: 'fresh' }, now)).toBeNull();
    expect(checkStepUp(session(), { mfa: 'fresh' }, now)?.code).toBe('MFA_REQUIRED');
    // The inner session record works as well as the getSession result; unknown input fails closed.
    expect(checkStepUp(session({ mfa: true }).session, { mfa: 'fresh' }, now)).toBeNull();
    expect(checkStepUp(remembered.session, { mfa: 'fresh' }, now)?.code).toBe('MFA_REQUIRED');
    expect(checkStepUp(null, { mfa: true }, now)?.code).toBe('MFA_REQUIRED');
    expect(checkStepUp(undefined, { maxAgeMs: minute }, now)?.code).toBe('RECENT_AUTH_REQUIRED');
  });

  it('measures recency against the injected clock, inclusive at the window edge', () => {
    const recent = { maxAgeMs: 5 * minute };
    expect(checkStepUp(session(), recent, now)).toBeNull();
    expect(checkStepUp(session({ authenticatedAt: now - 5 * minute }), recent, now)).toBeNull();
    expect(checkStepUp(session({ authenticatedAt: now - 5 * minute - 1 }), recent, now)).toEqual({
      code: 'RECENT_AUTH_REQUIRED',
      reason: 'recent',
      message: 'Reauthenticate to perform this operation',
      status: 403,
    });
    // A timestamp from the future (clock skew or tampering) is not recent.
    expect(checkStepUp(session({ authenticatedAt: now + 1 }), recent, now)?.reason).toBe('recent');
    expect(checkStepUp(session({ authenticatedAt: undefined }), recent, now)?.reason).toBe(
      'recent',
    );
    expect(checkStepUp(session({ authenticatedAt: '1' }), recent, now)?.reason).toBe('recent');
    expect(checkStepUp(session(), recent, Number.NaN)?.reason).toBe('recent');
    expect(checkStepUp({ authenticatedAt: Date.now() }, recent)).toBeNull();
    expect(checkStepUp({ authenticatedAt: Date.now() - 6 * minute }, recent)?.reason).toBe(
      'recent',
    );
  });

  it('refuses impersonated sessions any recency requirement, checking impersonation, MFA, then age', () => {
    const impersonated = session({ mfa: true, impersonatorId: 'admin-1' });
    expect(checkStepUp(impersonated, { maxAgeMs: minute }, now)).toEqual({
      code: 'IMPERSONATION_RESTRICTED',
      reason: 'impersonation',
      message: 'This operation is unavailable while impersonating a member',
      status: 403,
    });
    // Impersonation inherits the administrator's MFA, so an MFA-only requirement still passes.
    expect(checkStepUp(impersonated, { mfa: true }, now)).toBeNull();
    const everything = { mfa: true, maxAgeMs: minute } as const;
    expect(
      checkStepUp(
        session({ impersonatorId: 'admin-1', authenticatedAt: now - 10 * minute }),
        everything,
        now,
      )?.code,
    ).toBe('IMPERSONATION_RESTRICTED');
    expect(
      checkStepUp(session({ authenticatedAt: now - 10 * minute }), everything, now)?.code,
    ).toBe('MFA_REQUIRED');
    expect(
      checkStepUp(session({ mfa: true, authenticatedAt: now - 10 * minute }), everything, now)
        ?.code,
    ).toBe('RECENT_AUTH_REQUIRED');
  });

  it("fails mfa: 'fresh' closed for records that inherited their MFA or cannot show how it was met", () => {
    const fresh = { mfa: 'fresh' } as const;
    // Impersonation copies the administrator's MFA flag, never the remembered-device marker.
    expect(checkStepUp(session({ mfa: true, impersonatorId: 'admin-1' }), fresh, now)).toEqual({
      code: 'IMPERSONATION_RESTRICTED',
      reason: 'impersonation',
      message: 'This operation is unavailable while impersonating a member',
      status: 403,
    });
    expect(checkStepUp(session({ mfa: true, method: 'impersonation' }), fresh, now)?.code).toBe(
      'IMPERSONATION_RESTRICTED',
    );
    const role = session({ kind: 'role', mfa: true, roleId: 'r1', sourceSessionId: 's0' });
    expect(checkStepUp(role, { mfa: true }, now)).toBeNull();
    expect(checkStepUp(role, fresh, now)).toEqual({
      code: 'MFA_REQUIRED',
      reason: 'mfa',
      message: 'This credential cannot show a fresh second factor; use a signed-in session',
      status: 403,
    });
    expect(checkStepUp(session({ mfa: true, sourceSessionId: 's0' }), fresh, now)?.code).toBe(
      'MFA_REQUIRED',
    );
    expect(checkStepUp(session({ kind: 'api-key', mfa: true }), fresh, now)?.code).toBe(
      'MFA_REQUIRED',
    );
    // A record that does not say it is a user session (assertion claims, hand-built objects) proves nothing.
    expect(checkStepUp({ mfa: true }, fresh, now)?.code).toBe('MFA_REQUIRED');
    expect(checkStepUp({ kind: 'user', mfa: true }, fresh, now)).toBeNull();
  });

  it('refuses temporary credentials a recency requirement, as the server’s requireRecent does', () => {
    const recent = { maxAgeMs: 5 * 60_000 };
    const temporary = {
      code: 'RECENT_AUTH_REQUIRED',
      reason: 'recent',
      message: 'Temporary credentials cannot perform this operation; use a signed-in session',
      status: 403,
    };
    // Signed in just now, but derived from another session: the sign-in time is inherited, not their own.
    for (const fields of [
      { kind: 'role', roleId: 'r1', sourceSessionId: 's0' },
      { kind: 'role', roleId: 'r1', webIdentity: { providerId: 'p1', subject: 'repo:x' } },
      { kind: 'session-token', sourceSessionId: 's0' },
      { kind: 'session-token' },
      { kind: 'user', sourceSessionId: 's0' },
      { kind: 'api-key', sourceSessionId: 's0' },
      { kind: 'something-new' },
    ])
      expect(checkStepUp(session({ mfa: true, ...fields }), recent, now)).toEqual(temporary);
    // The inner record and apiRoute principals are judged the same way.
    expect(checkStepUp({ kind: 'session-token', authenticatedAt: now }, recent, now)?.message).toBe(
      temporary.message,
    );
    // Signed-in sessions and API keys are judged by their own time; MFA-only requirements still pass for roles.
    expect(checkStepUp(session(), recent, now)).toBeNull();
    expect(checkStepUp(session({ kind: 'api-key' }), recent, now)).toBeNull();
    expect(
      checkStepUp(session({ kind: 'role', mfa: true, sourceSessionId: 's0' }), { mfa: true }, now),
    ).toBeNull();
    // Impersonation keeps its own refusal.
    expect(
      checkStepUp(session({ kind: 'role', impersonatorId: 'admin-1' }), recent, now)?.code,
    ).toBe('IMPERSONATION_RESTRICTED');
  });

  it('rejects invalid requirements with a TypeError', () => {
    for (const maxAgeMs of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, '60000'])
      expect(() => checkStepUp(session(), { maxAgeMs: maxAgeMs as number }, now)).toThrow(
        TypeError,
      );
    expect(() => checkStepUp(session(), { mfa: 'always' as 'fresh' }, now)).toThrow(TypeError);
    expect(checkStepUp(session(), { maxAgeMs: 0.5 }, now)).toBeNull();
  });
});

describe('Next.js step-up guards', () => {
  it('redirects pages to the step-up path with next and reason, before authorization', async () => {
    const f = await fixture();
    const clock = testClock();
    let headers = new Headers({ cookie: f.cookie, [pathnameHeader]: '/settings/security' });
    const iamNext = createIamNext(f.iam, {
      headers: () => headers,
      cache: (fn) => fn,
      redirect,
      stepUpPath: '/reauth',
      now: clock.now,
    });
    const Recent = iamNext.page(async (_props: object, { session }) => session.identity.name, {
      stepUp: { maxAgeMs: 5 * minute },
    });
    expect(await Recent({})).toBe('Member');
    clock.at += 5 * minute + 1;
    await expect(Recent({})).rejects.toThrow(
      'INTERRUPT:redirect:/reauth?next=%2Fsettings%2Fsecurity&reason=recent',
    );
    const Mfa = iamNext.page(async () => 'secret', {
      stepUp: { mfa: true, redirectTo: '/verify?source=page' },
      returnTo: () => '/vault',
    });
    await expect(Mfa({})).rejects.toThrow(
      'INTERRUPT:redirect:/verify?source=page&next=%2Fvault&reason=mfa',
    );
    // Step-up runs before authorize: the member lacks documents:read but is sent to step up, not refused.
    const Guarded = iamNext.page(async () => 'document', {
      stepUp: { maxAgeMs: minute },
      authorize: { action: 'documents:read', redirectTo: '/forbidden' },
    });
    await expect(Guarded({})).rejects.toThrow('INTERRUPT:redirect:/reauth?next=');
    headers = new Headers({ cookie: f.cookie });
    await expect(Recent({})).rejects.toThrow('INTERRUPT:redirect:/reauth?next=%2F&reason=recent');
    // Signed-out visitors still go to the login path.
    headers = new Headers({ [pathnameHeader]: '/settings/security' });
    await expect(Recent({})).rejects.toThrow(
      'INTERRUPT:redirect:/login?next=%2Fsettings%2Fsecurity',
    );
    headers = new Headers({ authorization: `Bearer ${f.rootToken}` });
    clock.at = Date.now();
    expect(
      await iamNext.page(async () => 'ok', { stepUp: { mfa: 'fresh', maxAgeMs: 5 * minute } })({}),
    ).toBe('ok');

    // An impersonated session is never recent enough.
    await f.iam.api.tenants.setAuthPolicy(
      { token: f.rootToken },
      { tenantId: f.tenantId, authPolicy: { allowImpersonation: true } },
    );
    const impersonation = await f.iam.api.identities.impersonate(
      { token: f.rootToken },
      { tenantId: f.tenantId, identityId: f.member.id, reason: 'support ticket 42' },
    );
    headers = new Headers({
      authorization: `Bearer ${impersonation.token}`,
      [pathnameHeader]: '/account',
    });
    await expect(Recent({})).rejects.toThrow(
      'INTERRUPT:redirect:/reauth?next=%2Faccount&reason=impersonation',
    );
  });

  it('throws the coded failure from requireSession when no step-up path is configured', async () => {
    const f = await fixture();
    const clock = testClock();
    const iamNext = createIamNext(f.iam, {
      headers: () => new Headers({ cookie: f.cookie }),
      cache: (fn) => fn,
      redirect,
      now: clock.now,
    });
    const session = await iamNext.requireSession({ stepUp: { maxAgeMs: minute } });
    expect(session.identity.id).toBe(f.member.id);
    clock.at += 2 * minute;
    const failure = await iamNext
      .requireSession({ stepUp: { maxAgeMs: minute } })
      .catch((error: unknown) => error);
    expect(failure).toBeInstanceOf(IamError);
    expect(failure).toMatchObject({
      name: 'IamError',
      code: 'RECENT_AUTH_REQUIRED',
      status: 403,
      reason: 'recent',
      message: 'Reauthenticate to perform this operation',
      digest: 'BETTER_IAM_STEP_UP:RECENT_AUTH_REQUIRED:recent',
    });
    expect(isNextControlError(failure)).toBe(false);
    // Production error.tsx sees only the digest Next computes; a preset digest passes through unchanged.
    const reported: unknown[] = [];
    const digestOf = createFlightReactServerErrorHandler(false, (error) => reported.push(error));
    expect(digestOf(failure)).toBe('BETTER_IAM_STEP_UP:RECENT_AUTH_REQUIRED:recent');
    expect(digestOf(new Error('crash'))).toMatch(/^\d+$/);
    expect(reported).toHaveLength(2);
    await expect(iamNext.requireSession({ stepUp: { mfa: true } })).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
      status: 403,
    });
    await expect(
      iamNext.requireSession({ stepUp: { mfa: true, redirectTo: '/mfa' }, returnTo: '/x' }),
    ).rejects.toThrow('INTERRUPT:redirect:/mfa?next=%2Fx&reason=mfa');
    const page = iamNext.page(async () => 'never', { stepUp: { mfa: true } });
    await expect(page({})).rejects.toThrow('Multi-factor authentication is required');
    await expect(page({})).rejects.toMatchObject({ digest: 'BETTER_IAM_STEP_UP:MFA_REQUIRED:mfa' });
    await expect(iamNext.requireSession({ stepUp: { maxAgeMs: -5 } })).rejects.toThrow(TypeError);
    // Wrappers validate their requirement when they are created.
    expect(() => iamNext.route(() => null, { stepUp: { maxAgeMs: 0 } })).toThrow(TypeError);
    expect(() => iamNext.action(async () => null, { stepUp: { maxAgeMs: Number.NaN } })).toThrow(
      TypeError,
    );
    expect(() => iamNext.apiRoute(() => null, { stepUp: { maxAgeMs: -1 } })).toThrow(TypeError);
    expect(() => iamNext.page(async () => null, { stepUp: { maxAgeMs: -1 } })).toThrow(TypeError);
  });

  it('answers route handlers with the 403 envelope and actions with an ActionResult', async () => {
    const f = await fixture();
    const clock = testClock();
    let headers = new Headers({ cookie: f.cookie });
    const iamNext = createIamNext(f.iam, {
      headers: () => headers,
      cache: (fn) => fn,
      now: clock.now,
    });
    let calls = 0;
    const GET = iamNext.route(
      (_request, { session }) => {
        calls++;
        return { who: session.identity.name };
      },
      { stepUp: { mfa: true } },
    );
    const denied = await call(GET, { cookie: f.cookie });
    expect(denied.status).toBe(403);
    expect(denied.headers.get('cache-control')).toBe('no-store');
    expect(await denied.json()).toEqual({
      error: { code: 'MFA_REQUIRED', message: 'Multi-factor authentication is required' },
    });
    expect((await call(GET, {})).status).toBe(401);
    expect(calls).toBe(0);
    const allowed = await call(GET, { authorization: `Bearer ${f.rootToken}` });
    expect(await allowed.json()).toEqual({ who: 'Root' });

    const POST = iamNext.route(() => ({ saved: true }), {
      stepUp: { maxAgeMs: 5 * minute },
      authorize: { action: 'documents:write' },
    });
    expect((await call(POST, { authorization: `Bearer ${f.rootToken}` })).status).toBe(200);
    // Step-up is checked before authorization: the member sees the step-up code, not ACCESS_DENIED.
    clock.at += 6 * minute;
    const stale = await call(POST, { cookie: f.cookie });
    expect(stale.status).toBe(403);
    expect(await stale.json()).toMatchObject({ error: { code: 'RECENT_AUTH_REQUIRED' } });
    expect(await (await call(POST, { authorization: `Bearer ${f.rootToken}` })).json()).toEqual({
      error: { code: 'RECENT_AUTH_REQUIRED', message: 'Reauthenticate to perform this operation' },
    });
    // route() stays session-only: API keys belong to apiRoute().
    expect((await call(GET, { authorization: `Bearer ${f.apiKey}` })).status).toBe(401);

    let ran = 0;
    const rename = iamNext.action(
      async (session, title: string) => {
        ran++;
        return `${session.identity.name}:${title}`;
      },
      { stepUp: { maxAgeMs: 5 * minute } },
    );
    expect(await rename('Draft')).toEqual({
      ok: false,
      error: { code: 'RECENT_AUTH_REQUIRED', message: 'Reauthenticate to perform this operation' },
    });
    expect(ran).toBe(0);
    clock.at = Date.now();
    expect(await rename('Draft')).toEqual({ ok: true, data: 'Member:Draft' });
    const enroll = iamNext.action(async () => 'enrolled', { stepUp: { mfa: true } });
    expect(await enroll()).toEqual({
      ok: false,
      error: { code: 'MFA_REQUIRED', message: 'Multi-factor authentication is required' },
    });
    headers = new Headers();
    expect(await enroll()).toMatchObject({ ok: false, error: { code: 'UNAUTHENTICATED' } });
  });

  it('guards Pages Router props and API routes', async () => {
    const f = await fixture();
    const clock = testClock();
    const iamNext = createIamNext(f.iam, { stepUpPath: '/reauth', now: clock.now });
    const gssp = iamNext.pages.withSession(async () => ({ props: { plan: 'pro' } }), {
      stepUp: { mfa: true },
    });
    expect(await gssp(pagesContext({ cookie: f.cookie }))).toEqual({
      redirect: { destination: '/reauth?next=%2Fbilling%3Ftab%3D2&reason=mfa', permanent: false },
    });
    expect(await gssp(pagesContext({ cookie: f.cookie }, 'https://evil.example/'))).toEqual({
      redirect: { destination: '/reauth?next=%2F&reason=mfa', permanent: false },
    });
    expect(await gssp(pagesContext({}))).toEqual({
      redirect: { destination: '/login?next=%2Fbilling%3Ftab%3D2', permanent: false },
    });
    const allowed = await gssp(pagesContext({ authorization: `Bearer ${f.rootToken}` }));
    if (!('props' in allowed)) throw new Error('Expected props');
    const props = await allowed.props;
    expect(props.plan).toBe('pro');
    expect(props.session.identity.name).toBe('Root');
    expect(props.session.session).not.toHaveProperty('uniqueKey');
    expect(props.session.session).not.toHaveProperty('tokenHash');
    const recent = iamNext.pages.withSession(undefined, {
      stepUp: { maxAgeMs: minute, redirectTo: '/confirm-password' },
    });
    clock.at += 2 * minute;
    expect(await recent(pagesContext({ cookie: f.cookie }))).toEqual({
      redirect: {
        destination: '/confirm-password?next=%2Fbilling%3Ftab%3D2&reason=recent',
        permanent: false,
      },
    });
    const unconfigured = createIamNext(f.iam).pages.withSession(undefined, {
      stepUp: { mfa: true },
    });
    await expect(unconfigured(pagesContext({ cookie: f.cookie }))).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
      status: 403,
      digest: 'BETTER_IAM_STEP_UP:MFA_REQUIRED:mfa',
    });

    const api = iamNext.pages.api(async (_req, _res, { session }) => session.identity.name, {
      stepUp: { mfa: true },
    });
    let out = pagesResponse();
    await api(pagesRequest({ cookie: f.cookie }), out.res);
    expect(out.state).toMatchObject({
      status: 403,
      body: { error: { code: 'MFA_REQUIRED', message: 'Multi-factor authentication is required' } },
    });
    out = pagesResponse();
    await api(pagesRequest({ authorization: `Bearer ${f.rootToken}` }), out.res);
    expect(out.state).toMatchObject({ status: 200, body: 'Root' });
    const stale = iamNext.pages.api(async () => 'saved', { stepUp: { maxAgeMs: minute } });
    out = pagesResponse();
    await stale(pagesRequest({ authorization: `Bearer ${f.rootToken}` }), out.res);
    expect(out.state).toMatchObject({
      status: 403,
      body: { error: { code: 'RECENT_AUTH_REQUIRED' } },
    });
  });

  it('admits API keys to apiRoute with a sanitized principal, authorization, and step-up', async () => {
    const f = await fixture();
    const iamNext = createIamNext(f.iam, { headers: () => new Headers() });
    const seen: IamPrincipal[] = [];
    const GET = iamNext.apiRoute<{ id: string }>(
      (_request, { principal, params }) => {
        seen.push(principal);
        expectTypeOf(principal.session.kind).toEqualTypeOf<
          'user' | 'role' | 'api-key' | 'session-token' | 'delegated'
        >();
        return { id: params.id, by: principal.identity.id };
      },
      {
        authorize: {
          action: 'documents:read',
          resource: ({ params }) => ({ type: 'document', id: params.id }),
        },
      },
    );
    const request = (headers: HeadersInit) =>
      GET(new Request('http://localhost:3000/api/docs/a', { headers }), {
        params: Promise.resolve({ id: 'a' }),
      });
    const response = await request({ authorization: `Bearer ${f.apiKey}` });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ id: 'a', by: f.account.id });
    const principal = seen[0]!;
    expect(principal.identity).toEqual({
      id: f.account.id,
      tenantId: f.tenantId,
      name: 'ci',
      kind: 'service',
      status: 'active',
    });
    expect(Object.keys(principal.session).sort()).toEqual(
      ['authenticatedAt', 'expiresAt', 'id', 'kind', 'mfa', 'tenantId'].sort(),
    );
    expect(principal.session).toMatchObject({ kind: 'api-key', mfa: false, tenantId: f.tenantId });
    const stored = await f.iam.store.find<Session>('sessions', { kind: 'api-key' });
    const serialized = JSON.stringify(principal);
    expect(stored).toHaveLength(1);
    expect(serialized).not.toContain(stored[0]!.tokenHash);
    expect(serialized).not.toContain(f.apiKey);
    for (const field of ['tokenHash', 'uniqueKey', 'policy', 'credentialAuthorityId'])
      expect(serialized).not.toContain(field);

    // User sessions work too; the member has no documents:read.
    const member = await request({ cookie: f.cookie });
    expect(member.status).toBe(403);
    expect(await member.json()).toMatchObject({ error: { code: 'ACCESS_DENIED' } });
    expect((await request({ authorization: `Bearer ${f.rootToken}` })).status).toBe(200);
    expect(seen.at(-1)!.session).toMatchObject({ kind: 'user', mfa: true });
    const whoami = iamNext.apiRoute((_request, { principal }) => principal);
    const self = (await (await call(whoami, { cookie: f.cookie })).json()) as IamPrincipal;
    expect(self.identity).toMatchObject({
      id: f.member.id,
      kind: 'user',
      email: 'member@example.test',
    });
    expect(self.session).toMatchObject({ kind: 'user', mfa: false, method: 'password' });
    expect(JSON.stringify(self)).not.toContain('uniqueKey');
    expect(JSON.stringify(self)).not.toContain('passwordHash');
    const anonymous = await request({});
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toMatchObject({ error: { code: 'UNAUTHENTICATED' } });
    const revoked = await request({ authorization: 'Bearer not-a-real-api-key-value-000000000' });
    expect(revoked.status).toBe(401);

    const write = iamNext.apiRoute(() => 'written', {
      authorize: {
        action: 'documents:write',
        resource: () => ({ type: 'document', id: 'a' }),
      },
    });
    const denied = await call(write, { authorization: `Bearer ${f.apiKey}` });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({ error: { code: 'ACCESS_DENIED' } });

    let reached = false;
    const mfaOnly = iamNext.apiRoute(
      () => {
        reached = true;
        return 'never';
      },
      { stepUp: { mfa: true } },
    );
    const refused = await call(mfaOnly, { authorization: `Bearer ${f.apiKey}` });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toEqual({
      error: { code: 'MFA_REQUIRED', message: 'Multi-factor authentication is required' },
    });
    expect(reached).toBe(false);
    expect((await call(mfaOnly, { authorization: `Bearer ${f.rootToken}` })).status).toBe(200);
    const empty = iamNext.apiRoute(() => undefined);
    expect((await call(empty, { authorization: `Bearer ${f.apiKey}` })).status).toBe(204);

    const limited = createIamNext({ ...f.iam, authenticate: undefined });
    await expect(
      call(
        limited.apiRoute(() => null),
        { authorization: `Bearer ${f.apiKey}` },
      ),
    ).rejects.toThrow(/authenticate\(\)/);
  });

  it("admits session tokens (opaque and JWT) to apiRoute with exact keys, but never as mfa: 'fresh'", async () => {
    const f = await organizationFixture({
      sts: { jwt: { signingKeys: [generateTestKey('EdDSA', 'k1').privateJwk as never] } },
    });
    const iamNext = createIamNext(f.iam, { headers: () => new Headers() });
    const seen: IamPrincipal[] = [];
    const whoami = iamNext.apiRoute((_request, { principal }) => {
      seen.push(principal);
      return principal.session.kind;
    });
    // The owner mints an opaque session token without a name: the principal keeps the API-key key set.
    const opaque = await f.iam.api.sts.getSessionToken(f.ownerCredential);
    expect(opaque.token).toMatch(/^biam_sts_/);
    const response = await call(whoami, bearer(opaque.token));
    expect(response.status).toBe(200);
    expect(await response.json()).toBe('session-token');
    const principal = seen[0]!;
    expect(principal.identity).toMatchObject({ id: f.ownerId, tenantId: f.tenantId, kind: 'user' });
    expect(principal.session).toMatchObject({
      id: opaque.session.id,
      kind: 'session-token',
      tenantId: f.tenantId,
      mfa: false,
    });
    expect(Object.keys(principal.session).sort()).toEqual(
      ['authenticatedAt', 'expiresAt', 'id', 'kind', 'mfa', 'tenantId'].sort(),
    );
    const serialized = JSON.stringify(principal);
    expect(serialized).not.toContain(opaque.token);
    for (const field of ['tokenHash', 'uniqueKey', 'sourceSessionId', 'sourcePolicy', 'client'])
      expect(serialized).not.toContain(field);

    // A named session JWT: the name is copied, as a string, and nothing else is added.
    const jwt = await f.iam.api.sts.getSessionToken(f.ownerCredential, {
      format: 'jwt',
      sessionName: 'deploy-bot',
    });
    expect(jwt.token.split('.')).toHaveLength(3);
    expect((await call(whoami, bearer(jwt.token))).status).toBe(200);
    expect(seen[1]!.session).toMatchObject({
      id: jwt.session.id,
      kind: 'session-token',
      sessionName: 'deploy-bot',
    });
    expect(Object.keys(seen[1]!.session).sort()).toEqual(
      ['authenticatedAt', 'expiresAt', 'id', 'kind', 'mfa', 'sessionName', 'tenantId'].sort(),
    );
    expect(seen[1]!.session).not.toHaveProperty('sourceIdentity');

    // A token minted from root's MFA session copies the MFA flag: it passes mfa: true, never 'fresh'.
    const attested = await f.iam.api.sts.getSessionToken(f.rootCredential);
    expect(attested.session).toMatchObject({ kind: 'session-token', mfa: true });
    const mfaApi = iamNext.apiRoute(() => 'ok', { stepUp: { mfa: true } });
    const freshApi = iamNext.apiRoute(() => 'ok', { stepUp: { mfa: 'fresh' } });
    expect((await call(mfaApi, bearer(attested.token))).status).toBe(200);
    const refused = await call(freshApi, bearer(attested.token));
    expect(refused.status).toBe(403);
    expect(await refused.json()).toEqual({
      error: {
        code: 'MFA_REQUIRED',
        message: 'This credential cannot show a fresh second factor; use a signed-in session',
      },
    });
    expect((await call(freshApi, bearer(f.rootCredential.token))).status).toBe(200);
    expect(
      checkStepUp({ kind: 'session-token', mfa: true, authenticatedAt: f.now() }, { mfa: 'fresh' }),
    ).toMatchObject({ code: 'MFA_REQUIRED', reason: 'mfa' });
    // route() stays session-only: a session token is not a signed-in session.
    expect(
      (
        await call(
          iamNext.route(() => 'ok'),
          bearer(opaque.token),
        )
      ).status,
    ).toBe(401);
  });

  it('keeps the token hash out of sessionForClient and refuses remembered devices for mfa: fresh', async () => {
    const f = await fixture();
    let headers = new Headers({ cookie: f.cookie });
    const iamNext = createIamNext(f.iam, { headers: () => headers, cache: (fn) => fn });
    const plain = await iamNext.sessionForClient();
    expect(plain?.identity.id).toBe(f.member.id);
    expect(plain?.session).not.toHaveProperty('uniqueKey');
    expect(plain?.session).not.toHaveProperty('tokenHash');
    const [stored] = await f.iam.store.find<Session>('sessions', { identityId: f.member.id });
    expect(JSON.stringify(plain)).not.toContain(stored!.tokenHash);
    expect(plain?.session.id).toBe(stored!.id);

    // The member enrolls MFA and remembers this browser; the next sign-in skips the code.
    const enrollment = await f.iam.api.auth.beginMfa({ token: f.memberToken });
    const enrolled = await f.iam.api.auth.confirmMfa({
      credential: { token: f.memberToken },
      code: authenticator.generate(enrollment.secret),
      rememberDevice: true,
    });
    expect(typeof enrolled.deviceToken).toBe('string');
    const remembered = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'member@example.test',
      password: 'a strong member test password',
      deviceToken: enrolled.deviceToken!,
    });
    if (!('token' in remembered)) throw new Error('The remembered device should skip MFA');
    expect(remembered.session).toMatchObject({ mfa: true });
    expect(remembered.session.trustedDeviceId).toBeTruthy();

    const fresh = iamNext.route(() => 'ok', { stepUp: { mfa: 'fresh' } });
    const trusted = iamNext.route(() => 'ok', { stepUp: { mfa: true } });
    const viaDevice = { authorization: `Bearer ${remembered.token}` };
    expect((await call(trusted, viaDevice)).status).toBe(200);
    const refused = await call(fresh, viaDevice);
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ error: { code: 'MFA_REQUIRED' } });
    expect((await call(fresh, { authorization: `Bearer ${enrolled.token}` })).status).toBe(200);
    headers = new Headers({ cookie: `better-iam.session=${remembered.token}` });
    await expect(iamNext.requireSession({ stepUp: { mfa: 'fresh' } })).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
    });
  });

  it("refuses mfa: 'fresh' to impersonation and role sessions derived from a remembered device", async () => {
    const f = await operatorFixture();
    let headers = new Headers();
    const iamNext = createIamNext(f.iam, {
      headers: () => headers,
      cache: (fn) => fn,
      redirect,
      stepUpPath: '/reauth',
    });
    const fresh = iamNext.route(() => 'ok', { stepUp: { mfa: 'fresh' } });
    const mfa = iamNext.route(() => 'ok', { stepUp: { mfa: true } });
    expect((await call(fresh, bearer(f.remembered.token))).status).toBe(403);
    expect((await call(fresh, bearer(f.enrolled.token))).status).toBe(200);

    // The server copies the administrator's MFA flag onto the impersonation session, not the device marker.
    const impersonation = await f.iam.api.identities.impersonate(
      { token: f.remembered.token },
      { tenantId: f.platform, identityId: f.customer.id, reason: 'support ticket 7' },
    );
    expect(impersonation.session).toMatchObject({ mfa: true, impersonatorId: f.ops.id });
    expect(impersonation.session).not.toHaveProperty('trustedDeviceId');
    expect((await call(mfa, bearer(impersonation.token))).status).toBe(200);
    const impersonated = await call(fresh, bearer(impersonation.token));
    expect(impersonated.status).toBe(403);
    expect(await impersonated.json()).toEqual({
      error: {
        code: 'IMPERSONATION_RESTRICTED',
        message: 'This operation is unavailable while impersonating a member',
      },
    });
    headers = new Headers({ ...bearer(impersonation.token), [pathnameHeader]: '/vault' });
    await expect(
      iamNext.page(async () => 'vault', { stepUp: { mfa: 'fresh' } })({}),
    ).rejects.toThrow('INTERRUPT:redirect:/reauth?next=%2Fvault&reason=impersonation');

    // An assumed role copies the MFA flag too; apiRoute admits it, but never as fresh.
    const role = await f.iam.api.roles.assume(
      { token: f.remembered.token },
      { tenantId: f.tenantId, trustId: f.trust.id },
    );
    const freshApi = iamNext.apiRoute(() => 'ok', { stepUp: { mfa: 'fresh' } });
    const mfaApi = iamNext.apiRoute(() => 'ok', { stepUp: { mfa: true } });
    expect((await call(mfaApi, bearer(role.token))).status).toBe(200);
    const assumed = await call(freshApi, bearer(role.token));
    expect(assumed.status).toBe(403);
    expect(await assumed.json()).toEqual({
      error: {
        code: 'MFA_REQUIRED',
        message: 'This credential cannot show a fresh second factor; use a signed-in session',
      },
    });
    // Fails closed: a role assumed from a first-hand MFA session cannot prove it either.
    const fromFresh = await f.iam.api.roles.assume(
      { token: f.enrolled.token },
      { tenantId: f.tenantId, trustId: f.trust.id },
    );
    expect((await call(freshApi, bearer(fromFresh.token))).status).toBe(403);
    expect((await call(freshApi, bearer(f.enrolled.token))).status).toBe(200);
  });

  it('admits assumed roles to apiRoute, authorizing in the tenant the role acts in', async () => {
    const f = await operatorFixture();
    const iamNext = createIamNext(f.iam, { headers: () => new Headers() });
    const seen: IamPrincipal[] = [];
    const document = () => ({ type: 'document', id: 'a' });
    const read = iamNext.apiRoute(
      (_request, { principal }) => {
        seen.push(principal);
        return 'read';
      },
      { authorize: { action: 'documents:read', resource: document } },
    );
    const role = await f.iam.api.roles.assume(
      { token: f.enrolled.token },
      { tenantId: f.tenantId, trustId: f.trust.id },
    );
    expect((await call(read, bearer(role.token))).status).toBe(200);
    const principal = seen[0]!;
    expect(principal.identity).toMatchObject({ id: f.ops.id, tenantId: f.platform, kind: 'user' });
    expect(principal.session).toMatchObject({
      id: role.session.id,
      kind: 'role',
      roleId: f.reader.id,
      tenantId: f.tenantId,
      mfa: true,
    });
    expect(principal.session.tenantId).not.toBe(principal.identity.tenantId);
    expect(Object.keys(principal.session).sort()).toEqual(
      ['authenticatedAt', 'expiresAt', 'id', 'kind', 'mfa', 'roleId', 'tenantId'].sort(),
    );
    // Only the role grants documents:read, and only in Acme: ops's own session and the platform tenant are refused.
    const own = await call(read, bearer(f.enrolled.token));
    expect(own.status).toBe(403);
    expect(await own.json()).toMatchObject({ error: { code: 'ACCESS_DENIED' } });
    const home = iamNext.apiRoute(() => 'read', {
      authorize: {
        action: 'documents:read',
        resource: document,
        tenantId: ({ principal }) => principal.identity.tenantId,
      },
    });
    expect((await call(home, bearer(role.token))).status).toBe(403);
    expect(seen).toHaveLength(1);
    // route() stays session-only.
    expect(
      (
        await call(
          iamNext.route(() => 'read'),
          bearer(role.token),
        )
      ).status,
    ).toBe(401);

    // Handlers can make their own step-up decisions from the principal.
    const decide = iamNext.apiRoute((_request, { principal: caller }) => ({
      device: caller.session.trustedDeviceId ?? null,
      failure: checkStepUp(caller, { mfa: 'fresh' }),
    }));
    expect(await (await call(decide, bearer(f.remembered.token))).json()).toEqual({
      device: f.remembered.session.trustedDeviceId,
      failure: {
        code: 'MFA_REQUIRED',
        reason: 'mfa',
        message: 'Verify your second factor again to continue',
        status: 403,
      },
    });
    expect(await (await call(decide, bearer(f.enrolled.token))).json()).toEqual({
      device: null,
      failure: null,
    });
    expect((await (await call(decide, bearer(role.token))).json()).failure).toMatchObject({
      code: 'MFA_REQUIRED',
    });
  });

  it('answers only IAM errors with the envelope and rethrows everything else', async () => {
    const f = await fixture();
    const root = bearer(f.rootToken);
    const iamNext = createIamNext(f.iam, { headers: () => new Headers(root), cache: (fn) => fn });
    const leak = (): never => {
      throw Object.assign(
        new Error("ENOENT: no such file or directory, open '/srv/app/secrets/db.json'"),
        { code: 'ENOENT', status: 500 },
      );
    };
    await expect(call(iamNext.route(leak), root)).rejects.toThrow('ENOENT');
    await expect(call(iamNext.apiRoute(leak), root)).rejects.toThrow('ENOENT');
    await expect(iamNext.action(async () => leak())()).rejects.toThrow('ENOENT');
    const out = pagesResponse();
    await expect(
      iamNext.pages.api(async () => leak())(pagesRequest(root), out.res),
    ).rejects.toThrow('ENOENT');
    expect(out.state.ended).toBe(false);

    const conflict = (): never => {
      throw new IamError('CONFLICT', 'That title is taken', 409);
    };
    const answered = await call(iamNext.route(conflict), root);
    expect(answered.status).toBe(409);
    expect(await answered.json()).toEqual({
      error: { code: 'CONFLICT', message: 'That title is taken' },
    });
    expect(await iamNext.action(async () => conflict())()).toEqual({
      ok: false,
      error: { code: 'CONFLICT', message: 'That title is taken' },
    });
    const pages = pagesResponse();
    await iamNext.pages.api(async () => conflict())(pagesRequest(root), pages.res);
    expect(pages.state).toMatchObject({ status: 409, body: { error: { code: 'CONFLICT' } } });
    // Failures the typed client reports from the IAM handler are IAM errors too.
    const limited = await call(
      iamNext.apiRoute(() => {
        throw new IamClientError('RATE_LIMITED', 'Too many requests', 429, 1000);
      }),
      root,
    );
    expect(limited.status).toBe(429);
    expect(await limited.json()).toEqual({
      error: { code: 'RATE_LIMITED', message: 'Too many requests' },
    });
  });

  it('refuses cookie-authenticated mutations from other origins, as the IAM handler does', async () => {
    const f = await fixture();
    const iamNext = createIamNext(f.iam, {
      headers: () => new Headers(),
      trustedOrigins: ['https://admin.example.test/'],
    });
    let calls = 0;
    const handler = () => {
      calls++;
      return { saved: true };
    };
    type Wrapped = (request: Request, context: typeof noParams) => Promise<Response>;
    const send = (wrapped: Wrapped, method: string, headers: HeadersInit, url = '/api/transfer') =>
      wrapped(new Request(new URL(url, 'http://localhost:3000'), { method, headers }), noParams);
    const cookie = f.cookie;
    for (const wrapped of [iamNext.route(handler), iamNext.apiRoute(handler)] as Wrapped[]) {
      calls = 0;
      const missing = await send(wrapped, 'POST', { cookie });
      expect(missing.status).toBe(403);
      expect(await missing.json()).toEqual({
        error: { code: 'CSRF_REJECTED', message: 'Cookie requests require Origin' },
      });
      const sibling = await send(wrapped, 'DELETE', {
        cookie,
        origin: 'http://uploads.localhost:3000',
      });
      expect(sibling.status).toBe(403);
      expect(await sibling.json()).toEqual({
        error: { code: 'UNTRUSTED_ORIGIN', message: 'Origin is not trusted' },
      });
      expect((await send(wrapped, 'POST', { cookie, origin: 'null' })).status).toBe(403);
      expect((await send(wrapped, 'POST', { cookie, 'sec-fetch-site': 'same-site' })).status).toBe(
        403,
      );
      expect(calls).toBe(0);
      // This origin, the forwarded host behind a proxy, Sec-Fetch-Site, the IAM origin, and trustedOrigins pass.
      expect(
        (await send(wrapped, 'POST', { cookie, origin: 'http://localhost:3000' })).status,
      ).toBe(200);
      expect(
        (
          await send(wrapped, 'POST', {
            cookie,
            origin: 'https://app.example.test',
            'x-forwarded-host': 'app.example.test',
          })
        ).status,
      ).toBe(200);
      expect(
        (await send(wrapped, 'PATCH', { cookie, 'sec-fetch-site': 'same-origin' })).status,
      ).toBe(200);
      expect(
        (
          await send(
            wrapped,
            'POST',
            { cookie, origin: 'http://localhost:3000' },
            'http://internal:8080/api/transfer',
          )
        ).status,
      ).toBe(200);
      expect(
        (await send(wrapped, 'PUT', { cookie, origin: 'https://admin.example.test' })).status,
      ).toBe(200);
      // Safe methods and bearer credentials are not cookie CSRF; without a session cookie authentication decides.
      expect((await send(wrapped, 'GET', { cookie })).status).toBe(200);
      expect((await send(wrapped, 'POST', bearer(f.memberToken))).status).toBe(200);
      expect((await send(wrapped, 'POST', { cookie: 'theme=dark' })).status).toBe(401);
      expect(calls).toBe(7);
    }

    const api = iamNext.pages.api(async () => 'saved');
    const host = 'localhost:3000';
    let out = pagesResponse();
    await api(pagesRequest({ cookie, host }, 'POST'), out.res);
    expect(out.state).toMatchObject({ status: 403, body: { error: { code: 'CSRF_REJECTED' } } });
    out = pagesResponse();
    await api(pagesRequest({ cookie, host, origin: 'https://evil.example' }, 'POST'), out.res);
    expect(out.state).toMatchObject({ status: 403, body: { error: { code: 'UNTRUSTED_ORIGIN' } } });
    out = pagesResponse();
    await api(pagesRequest({ cookie, host, origin: 'http://localhost:3000' }, 'POST'), out.res);
    expect(out.state).toMatchObject({ status: 200, body: 'saved' });
    out = pagesResponse();
    await api(pagesRequest({ cookie, host }), out.res);
    expect(out.state).toMatchObject({ status: 200, body: 'saved' });
  });
});
