import { randomUUID } from 'node:crypto';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createSessionTokenVerifier,
  type CallerIdentity,
  type TemporaryCredential,
} from '@better-iam/server';
import { generateTestKey, signTestJwt } from './support/jwt-keys.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Temporary credentials end to end, over `iam.handler` only (Wave 5): an owner registers an OIDC provider and a
 * web-identity trust, a CI job exchanges its external token for a session JWT on the public route, uses it as a
 * Bearer inside IAM and has it verified offline from the JWKS route; revoking the role's sessions refuses the JWT
 * inside IAM at once while offline verification keeps passing until `exp`. A person then enrolls TOTP, steps up
 * through `sts/getSessionToken` with an `mfaCode`, and assumes an MFA-gated trust from that session token.
 * `sts/getCallerIdentity` is checked at every hop, and no `sts/*` or `oidcProviders/*` answer ever sets a cookie.
 */
const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const ORIGIN = 'http://localhost:3000';
const ISSUER = `${ORIGIN}/api/iam`;
const IDP_ISSUER = 'https://token.actions.example.test';
const IDP_AUDIENCE = 'https://acme.example';
const SUBJECT = 'repo:acme/app:ref:refs/heads/main';

/** The TOTP code an authenticator shows at `at` (epoch ms). */
function totp(secret: string, at: number): string {
  const generator = authenticator.clone();
  generator.options = { epoch: at };
  return generator.generate(secret);
}

interface Answer<T> {
  status: number;
  data: T;
  error?: { code: string; message: string };
}

/** An HTTP client over the fixture's Fetch handler that records whether each route set a cookie. */
function client(f: OrganizationFixture) {
  const cookies: { path: string; setCookie: string | null }[] = [];
  async function post<T = Record<string, unknown>>(
    path: string,
    body: unknown,
    headers: Record<string, string> = {},
  ): Promise<Answer<T>> {
    const response = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1', ...headers },
        body: JSON.stringify(body),
      }),
    );
    cookies.push({ path, setCookie: response.headers.get('set-cookie') });
    const json = (await response.json()) as { data: T; error?: Answer<T>['error'] };
    return {
      status: response.status,
      data: json.data,
      ...(json.error ? { error: json.error } : {}),
    };
  }
  const bearer = (token: string) => ({ authorization: `Bearer ${token}` });
  /** A browser request: the credential in the session cookie, with a trusted Origin. */
  const browser = (token: string) => ({
    cookie: `better-iam.session=${encodeURIComponent(token)}`,
    origin: ORIGIN,
  });
  const whoami = async (token: string) => {
    const answer = await post<CallerIdentity>('sts/getCallerIdentity', {}, bearer(token));
    expect(answer.status).toBe(200);
    return answer.data;
  };
  const allowed = async (token: string, action: string, id = 'release') => {
    const answer = await post<{ allowed: boolean; reason: string }>(
      'authorize',
      { tenantId: f.tenantId, action, resource: { type: 'document', id } },
      bearer(token),
    );
    return answer;
  };
  return { post, bearer, browser, whoami, allowed, cookies };
}

describe('temporary credentials over HTTP', () => {
  it('federates a CI job to a session JWT, verifies it offline, and revokes it inside IAM at once', async () => {
    const iamKey = generateTestKey('EdDSA', 'iam-1');
    const idpKey = generateTestKey('RS256', 'idp-1');
    const f = await organizationFixture({
      sts: {
        jwt: { signingKeys: [iamKey.privateJwk as never] },
        webIdentity: { enabled: true },
      },
    });
    const http = client(f);
    const owner = http.bearer(f.ownerCredential.token);

    // Hop 0: the owner, in their own right.
    expect(await http.whoami(f.ownerCredential.token)).toMatchObject({
      identityId: f.ownerId,
      tenantId: f.tenantId,
      sessionKind: 'user',
      format: 'opaque',
    });

    // The owner registers the identity provider and a web-identity trust, all over HTTP.
    const provider = await http.post<{ id: string; issuer: string; authorityId: string }>(
      'oidcProviders/create',
      {
        tenantId: f.tenantId,
        name: 'GitHub Actions',
        issuer: IDP_ISSUER,
        audiences: [IDP_AUDIENCE],
        jwks: { keys: [idpKey.publicJwk] },
      },
      owner,
    );
    expect(provider.status).toBe(200);
    expect(provider.data).toMatchObject({ issuer: IDP_ISSUER, enabled: true });
    const account = await http.post<{ id: string }>(
      'serviceAccounts/create',
      { tenantId: f.tenantId, name: 'ci' },
      owner,
    );
    expect(account.status).toBe(200);
    const role = await http.post<{ id: string }>(
      'roles/create',
      { tenantId: f.tenantId, name: 'Deployer', permissions: ['documents:read'] },
      owner,
    );
    expect(role.status).toBe(200);
    const trust = await http.post<{ id: string; kind: string }>(
      'trust/create',
      {
        tenantId: f.tenantId,
        kind: 'web-identity',
        providerId: provider.data.id,
        serviceAccountId: account.data.id,
        roleId: role.data.id,
        conditions: { StringEquals: { 'token.sub': SUBJECT } },
      },
      owner,
    );
    expect(trust.status).toBe(200);
    expect(trust.data.kind).toBe('web-identity');
    // Provider reads work over a browser session too, and never touch its cookie.
    const listed = await http.post<{ id: string }[]>(
      'oidcProviders/list',
      { tenantId: f.tenantId },
      http.browser(f.ownerCredential.token),
    );
    expect(listed.status).toBe(200);
    expect(listed.data.map((entry) => entry.id)).toEqual([provider.data.id]);

    // The CI job: an external token from its identity provider, exchanged on the public route with the
    // X-Better-IAM header and no cookie or credential of its own.
    const external = () => {
      const iat = Math.floor(f.now() / 1000);
      return signTestJwt(idpKey, {
        iss: IDP_ISSUER,
        aud: IDP_AUDIENCE,
        sub: SUBJECT,
        iat,
        exp: iat + 300,
        jti: randomUUID(),
      });
    };
    const exchange = (headers: Record<string, string> = {}) =>
      http.post<TemporaryCredential & { webIdentity: Record<string, string> }>(
        'sts/assumeRoleWithWebIdentity',
        {
          tenantId: f.tenantId,
          trustId: trust.data.id,
          webIdentityToken: external(),
          sessionName: 'ci-run-1',
          format: 'jwt',
        },
        headers,
      );
    const issued = await exchange();
    expect(issued.status).toBe(200);
    const jwt = issued.data.token;
    expect(jwt.split('.')).toHaveLength(3);
    expect(issued.data).toMatchObject({
      tokenType: 'Bearer',
      format: 'jwt',
      audience: [ISSUER],
      session: {
        kind: 'role',
        identityId: account.data.id,
        roleId: role.data.id,
        trustId: trust.data.id,
        sessionName: 'ci-run-1',
      },
      webIdentity: { providerId: provider.data.id, issuer: IDP_ISSUER, subject: SUBJECT },
    });

    // Hop 1: the JWT as a Bearer inside IAM.
    expect(await http.whoami(jwt)).toMatchObject({
      identityId: account.data.id,
      tenantId: f.tenantId,
      identityKind: 'service',
      sessionId: issued.data.session.id,
      sessionKind: 'role',
      format: 'jwt',
      roleId: role.data.id,
      trustId: trust.data.id,
      sessionName: 'ci-run-1',
      audience: [ISSUER],
      webIdentity: { providerId: provider.data.id, issuer: IDP_ISSUER, subject: SUBJECT },
    });
    expect((await http.allowed(jwt, 'documents:read')).data.allowed).toBe(true);
    expect((await http.allowed(jwt, 'documents:write')).data.allowed).toBe(false);

    // Offline: a downstream service verifies the JWT with the published keys only.
    const jwksResponse = await f.iam.handler(new Request(`${ISSUER}/.well-known/jwks.json`));
    expect(jwksResponse.status).toBe(200);
    expect(jwksResponse.headers.get('set-cookie')).toBeNull();
    const jwks = (await jwksResponse.json()) as { keys: Record<string, unknown>[] };
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty('d');
    const verifier = createSessionTokenVerifier({
      issuer: ISSUER,
      audience: ISSUER,
      jwks,
      now: f.now,
    });
    const expected = {
      iss: ISSUER,
      sub: account.data.id,
      tid: f.tenantId,
      sid: issued.data.session.id,
      kind: 'role',
      role: role.data.id,
      trust: trust.data.id,
      session_name: 'ci-run-1',
      idp: provider.data.id,
      idp_sub: SUBJECT,
    };
    expect(await verifier.verify(jwt)).toMatchObject(expected);
    expect(
      await verifier.verifyRequest({ headers: { authorization: `bearer ${jwt}` } }),
    ).toMatchObject(expected);

    // The owner revokes the role's sessions: the very next IAM call is refused, offline verification still passes
    // until exp (the documented lag), and the in-process online check reports the revocation.
    const revoked = await http.post<{ revoked: number }>(
      'roles/revokeSessions',
      { tenantId: f.tenantId, roleId: role.data.id },
      http.bearer((await f.ownerSignIn()).token),
    );
    expect(revoked.status).toBe(200);
    expect(revoked.data.revoked).toBe(1);
    const refused = await http.allowed(jwt, 'documents:read');
    expect(refused.status).toBe(401);
    expect(refused.error?.code).toBe('UNAUTHENTICATED');
    const whoamiRefused = await http.post('sts/getCallerIdentity', {}, http.bearer(jwt));
    expect(whoamiRefused.status).toBe(401);
    expect(await verifier.verify(jwt)).toMatchObject(expected);
    await expect(f.iam.sessionTokens!.verify(jwt)).rejects.toMatchObject({
      code: 'INVALID_SESSION_TOKEN',
      reason: 'revoked',
    });

    // Revocation covers sessions issued so far only: the next run federates again, even with a stray browser
    // cookie and Origin on the request (the public route ignores both and sets no cookie).
    f.advance(1000);
    const again = await exchange(http.browser(f.ownerCredential.token));
    expect(again.status).toBe(200);
    expect(again.data.session.id).not.toBe(issued.data.session.id);
    expect((await http.whoami(again.data.token)).sessionKind).toBe('role');

    for (const entry of http.cookies.filter(
      (call) => call.path.startsWith('sts/') || call.path.startsWith('oidcProviders/'),
    ))
      expect(entry, entry.path).toMatchObject({ setCookie: null });
  });

  it('steps up with TOTP for a session token, then assumes an MFA-gated trust from it', async () => {
    const f = await organizationFixture();
    const http = client(f);
    const owner = http.bearer(f.ownerCredential.token);
    const alice = await http.post<{ id: string }>(
      'identities/create',
      {
        tenantId: f.tenantId,
        email: 'alice@acme.test',
        name: 'alice',
        password: 'a strong alice password',
      },
      owner,
    );
    expect(alice.status).toBe(200);
    const grants = await http.post<{ id: string }>(
      'roles/create',
      {
        tenantId: f.tenantId,
        name: 'Temporary credentials',
        permissions: ['iam:session-tokens:create', 'iam:roles:assume'],
      },
      owner,
    );
    const bound = await http.post(
      'bindings/create',
      {
        tenantId: f.tenantId,
        roleId: grants.data.id,
        subjectType: 'identity',
        subjectId: alice.data.id,
      },
      owner,
    );
    expect(bound.status).toBe(200);
    const writer = await http.post<{ id: string }>(
      'roles/create',
      { tenantId: f.tenantId, name: 'Writer', permissions: ['documents:write'] },
      owner,
    );
    // Identity trusts stay platform-controlled: the root administrator creates the MFA-gated one.
    const trust = await http.post<{ id: string; requireMfa: boolean }>(
      'trust/create',
      {
        tenantId: f.tenantId,
        sourceTenantId: f.tenantId,
        sourceIdentityId: alice.data.id,
        roleId: writer.data.id,
        requireMfa: true,
      },
      http.bearer(f.rootCredential.token),
    );
    expect(trust.status).toBe(200);
    expect(trust.data.requireMfa).toBe(true);

    // Alice signs in and enrolls an authenticator over HTTP.
    const login = await f.signIn('alice');
    expect(await http.whoami(login.token)).toMatchObject({
      identityId: alice.data.id,
      sessionKind: 'user',
      mfa: false,
    });
    // Control: a session token minted from the password-only sign-in carries no MFA, and the gated trust refuses it.
    const unverified = await http.post<TemporaryCredential>(
      'sts/getSessionToken',
      { sessionName: 'alice-password-only' },
      http.bearer(login.token),
    );
    expect(unverified.status).toBe(200);
    expect(unverified.data.session).toMatchObject({ kind: 'session-token', mfa: false });
    expect((await http.whoami(unverified.data.token)).mfa).toBe(false);
    const refusedAssume = await http.post(
      'roles/assume',
      { tenantId: f.tenantId, trustId: trust.data.id, sessionName: 'alice-no-mfa' },
      http.bearer(unverified.data.token),
    );
    expect(refusedAssume.status).toBe(403);
    expect(refusedAssume.error?.code).toBe('ACCESS_DENIED');
    const enrollment = await http.post<{ secret: string }>(
      'auth/beginMfa',
      {},
      http.bearer(login.token),
    );
    expect(enrollment.status).toBe(200);
    const enrollmentCode = totp(enrollment.data.secret, f.now());
    const confirmed = await http.post<{ token: string }>(
      'auth/confirmMfa',
      { code: enrollmentCode },
      http.bearer(login.token),
    );
    expect(confirmed.status).toBe(200);
    const person = confirmed.data.token;
    expect(await http.whoami(person)).toMatchObject({
      identityId: alice.data.id,
      sessionKind: 'user',
      mfa: true,
    });
    // Enrolling ended the earlier sessions, and the session token minted from one of them.
    expect(
      (await http.post('sts/getCallerIdentity', {}, http.bearer(unverified.data.token))).status,
    ).toBe(401);

    // The route verifies the code: a wrong code and the spent enrollment code (same time step) are refused.
    const stepUp = (mfaCode: string) =>
      http.post<TemporaryCredential>(
        'sts/getSessionToken',
        { mfaCode, sessionName: 'alice-laptop' },
        http.bearer(person),
      );
    for (const code of [totp(enrollment.data.secret, f.now() + 600_000), enrollmentCode]) {
      const refusedCode = await stepUp(code);
      expect(refusedCode.status).toBe(401);
      expect(refusedCode.error?.code).toBe('INVALID_MFA');
    }

    // Step up: a first-hand code from the next time step (the enrollment code's step is spent).
    f.advance(30_000);
    const stepUpCode = totp(enrollment.data.secret, f.now());
    const stepped = await stepUp(stepUpCode);
    expect(stepped.status).toBe(200);
    expect(stepped.data.token).toMatch(/^biam_sts_[A-Za-z0-9_-]{49}$/);
    expect(stepped.data.session).toMatchObject({ kind: 'session-token', mfa: true });
    // The source session is already MFA, so the flag alone proves nothing: the step-up itself is on record, and the
    // same code cannot be used twice.
    const replayed = await stepUp(stepUpCode);
    expect(replayed.status).toBe(401);
    expect(replayed.error?.code).toBe('INVALID_MFA');
    const issuedEvents = async () => {
      const listed = await http.post<{ metadata?: { sessionId?: string; mfaStepUp?: boolean } }[]>(
        'audit/list',
        { tenantId: f.tenantId, action: 'session-token:issued' },
        owner,
      );
      expect(listed.status).toBe(200);
      return listed.data;
    };
    expect(
      (await issuedEvents()).find((event) => event.metadata?.sessionId === stepped.data.session.id)
        ?.metadata,
    ).toMatchObject({ mfaStepUp: true });
    const stepUps = await http.post<{ actorId?: string }[]>(
      'audit/list',
      { tenantId: f.tenantId, action: 'auth:mfa:step-up' },
      owner,
    );
    expect(stepUps.status).toBe(200);
    expect(stepUps.data.map((event) => event.actorId)).toEqual([alice.data.id]);
    const sessionToken = stepped.data.token;
    expect(await http.whoami(sessionToken)).toMatchObject({
      identityId: alice.data.id,
      sessionKind: 'session-token',
      sessionId: stepped.data.session.id,
      sessionName: 'alice-laptop',
      mfa: true,
      format: 'opaque',
    });
    // The session token itself cannot write, and cannot mint another session token.
    expect((await http.allowed(sessionToken, 'documents:write')).data.allowed).toBe(false);
    const chained = await http.post('sts/getSessionToken', {}, http.bearer(sessionToken));
    expect(chained.status).toBe(400);
    expect(chained.error?.code).toBe('CREDENTIAL_CHAINING_DISABLED');

    // AssumeRole from the stepped-up session token satisfies the MFA-gated trust.
    const assumed = await http.post<TemporaryCredential>(
      'roles/assume',
      { tenantId: f.tenantId, trustId: trust.data.id, sessionName: 'alice-write' },
      http.bearer(sessionToken),
    );
    expect(assumed.status).toBe(200);
    expect(assumed.data.token).toMatch(/^biam_rol_/);
    expect(assumed.data.session).toMatchObject({
      kind: 'role',
      mfa: true,
      roleId: writer.data.id,
      trustId: trust.data.id,
    });
    expect(await http.whoami(assumed.data.token)).toMatchObject({
      identityId: alice.data.id,
      sessionKind: 'role',
      roleId: writer.data.id,
      trustId: trust.data.id,
      sessionName: 'alice-write',
      mfa: true,
    });
    expect((await http.allowed(assumed.data.token, 'documents:write')).data.allowed).toBe(true);

    // Browser requests (cookie plus a trusted Origin) reach the sts routes without any cookie coming back.
    const browserWhoami = await http.post<CallerIdentity>(
      'sts/getCallerIdentity',
      {},
      http.browser(person),
    );
    expect(browserWhoami.status).toBe(200);
    expect(browserWhoami.data.sessionKind).toBe('user');
    const browserToken = await http.post<TemporaryCredential>(
      'sts/getSessionToken',
      {},
      http.browser(person),
    );
    expect(browserToken.status).toBe(200);
    expect(browserToken.data.token).toMatch(/^biam_sts_/);
    // Without a code the token copies the source's MFA state, and the audit says no step-up happened.
    expect(browserToken.data.session.mfa).toBe(true);
    expect(
      (await issuedEvents()).find(
        (event) => event.metadata?.sessionId === browserToken.data.session.id,
      )?.metadata,
    ).toMatchObject({ mfaStepUp: false });

    // Revoking the session token ends the role session derived from it, on the next use.
    const revoke = await http.post(
      'auth/revokeSession',
      { sessionId: stepped.data.session.id },
      http.bearer(person),
    );
    expect(revoke.status).toBe(200);
    for (const token of [sessionToken, assumed.data.token]) {
      const answer = await http.post('sts/getCallerIdentity', {}, http.bearer(token));
      expect(answer.status).toBe(401);
    }

    const stsCalls = http.cookies.filter((call) => call.path.startsWith('sts/'));
    expect(stsCalls.length).toBeGreaterThanOrEqual(8);
    for (const entry of stsCalls) expect(entry, entry.path).toMatchObject({ setCookie: null });
  });
});
