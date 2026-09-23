import { createRequire } from 'node:module';
import { once } from 'node:events';
import { createServer, request as httpRequest } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type IamSpan } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { PublicJwk } from '../packages/server/src/models.js';
import { generateTestKey, signTestJwt } from './support/jwt-keys.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);

const databases: IamStore[] = [];
afterEach(async () => {
  await closeFixtures();
  for (const database of databases.splice(0)) await database.close();
});

const ORIGIN = 'http://localhost:3000';
const byRealIp = {
  clientInfo: (request: Request) => ({ ip: request.headers.get('x-real-ip') ?? undefined }),
};

function post(
  iam: { handler(request: Request): Promise<Response> },
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
): Promise<Response> {
  return iam.handler(
    new Request(`${ORIGIN}/api/iam/${path}`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', 'x-better-iam': '1', ...headers },
      body: JSON.stringify(body),
    }),
  );
}

const cookieOf = (response: Response, name = 'better-iam.session') =>
  response.headers.getSetCookie().find((line) => line.startsWith(`${name}=`));

/** One request over a real socket to a Node listener, with the given headers. */
async function nodeRequest(
  listener: Parameters<typeof createServer>[1],
  path: string,
  headers: Record<string, string>,
): Promise<{ status: number; body: string }> {
  const server = createServer(listener);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected a TCP server');
  try {
    return await new Promise((resolve, reject) => {
      const outgoing = httpRequest(
        { hostname: '127.0.0.1', port: address.port, method: 'POST', path, headers, agent: false },
        (incoming) => {
          const chunks: Buffer[] = [];
          incoming.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
          incoming.on('error', reject);
          incoming.on('end', () =>
            resolve({
              status: incoming.statusCode!,
              body: Buffer.concat(chunks).toString('utf8'),
            }),
          );
        },
      );
      outgoing.on('error', reject);
      outgoing.end();
    });
  } finally {
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
}

describe('HTTP handler hardening', () => {
  it('runs protocol mounts with the request client, so federated sessions meet allowlists and IP binding', async () => {
    const f = await organizationFixture({ http: byRealIp });
    // A mounted protocol finishing a federated sign-in, the way the SAML ACS and OAuth login callbacks do.
    const federated = (subject: string) =>
      f.iam.protocolHost.completeAuthentication({
        tenantId: f.tenantId,
        providerId: 'fake-idp',
        issuer: 'https://idp.example.test',
        subject,
        email: `${subject}@acme.test`,
        emailVerified: true,
      });
    f.iam.useProtocol({
      basePath: '/fake-sso',
      handler: async (request) =>
        new URL(request.url).pathname === '/fake-sso/acs'
          ? Response.json(await federated('sso'))
          : undefined,
    });
    f.iam.useProtocol({
      basePath: '/node-sso',
      nodeHandler: async (_req, res) => {
        const result = await federated('node');
        res.setHeader('content-type', 'application/json');
        res.end(JSON.stringify(result));
      },
    });
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowedIpRanges: ['203.0.113.0/24'], bindSessionsToIp: true },
    });
    const acs = (ip: string) =>
      f.iam.handler(
        new Request(`${ORIGIN}/fake-sso/acs`, { method: 'POST', headers: { 'x-real-ip': ip } }),
      );
    const outside = await acs('198.51.100.7');
    expect(outside.status).toBe(403);
    expect((await outside.json()).error.code).toBe('IP_NOT_ALLOWED');
    const inside = await acs('203.0.113.5');
    expect(inside.status).toBe(200);
    const issued = (await inside.json()) as {
      token: string;
      session: { client?: { ip?: string } };
    };
    expect(issued.session.client?.ip).toBe('203.0.113.5');
    // The federated session is bound to its address: another one, even inside the allowlist, is refused.
    const elsewhere = await post(
      f.iam,
      'auth/getSession',
      {},
      { authorization: `Bearer ${issued.token}`, 'x-real-ip': '203.0.113.9' },
    );
    expect(elsewhere.status).toBe(401);
    expect((await elsewhere.json()).error.code).toBe('SESSION_NETWORK_MISMATCH');
    // The Node transport gives its protocol mounts the same client.
    const refused = await nodeRequest(f.iam.nodeHandler, '/node-sso/acs', {
      'x-real-ip': '198.51.100.7',
    });
    expect(refused.status).toBe(403);
    expect(JSON.parse(refused.body).error.code).toBe('IP_NOT_ALLOWED');
    const admitted = await nodeRequest(f.iam.nodeHandler, '/node-sso/acs', {
      'x-real-ip': '203.0.113.6',
    });
    expect(admitted.status).toBe(200);
    expect(JSON.parse(admitted.body).session.client.ip).toBe('203.0.113.6');
  });

  it('judges in-process calls that carry request headers by the client those headers describe', async () => {
    const f = await organizationFixture({ http: byRealIp });
    await f.member('alice');
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { bindSessionsToIp: true },
    });
    const signedIn = await post(
      f.iam,
      'auth/signIn',
      { tenantId: f.tenantId, email: 'alice@acme.test', password: 'a strong alice password' },
      { 'x-real-ip': '203.0.113.7' },
    );
    const { token } = ((await signedIn.json()) as { data: { token: string } }).data;
    const cookie = `better-iam.session=${token}`;
    // Framework integrations (Next, Nuxt) pass the incoming request's headers as the credential.
    const session = await f.iam.api.auth.getSession({
      headers: { cookie, 'x-real-ip': '203.0.113.7' },
    });
    expect(session.identity.email).toBe('alice@acme.test');
    await expect(
      f.iam.api.auth.getSession({ headers: { cookie, 'x-real-ip': '198.51.100.9' } }),
    ).rejects.toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
    // A client scope the caller set explicitly is kept.
    const scoped = await f.iam.auth.withClient({ ip: '203.0.113.7' }, () =>
      f.iam.api.auth.getSession({ headers: { cookie, 'x-real-ip': '198.51.100.9' } }),
    );
    expect(scoped.session.id).toBe(session.session.id);
    // A session issued in-process from request headers records that client.
    const again = await f.iam.api.auth.reauthenticate(
      { headers: { cookie, 'x-real-ip': '203.0.113.7' } },
      { password: 'a strong alice password' },
    );
    if (!('token' in again)) throw new Error('Unexpected MFA');
    expect((again.session as { client?: { ip?: string } }).client?.ip).toBe('203.0.113.7');
  });

  it('adds CORS and request-ID headers to errors, refusals, preflights, and operational endpoints', async () => {
    const f = await organizationFixture({
      trustedOrigins: ['https://app.example.com'],
      observability: { metrics: { bearerToken: 'scrape-token' } },
    });
    const app = { origin: 'https://app.example.com', 'x-request-id': 'req-1' };
    const expectCors = (response: Response) => {
      expect(response.headers.get('access-control-allow-origin')).toBe('https://app.example.com');
      expect(response.headers.get('access-control-allow-credentials')).toBe('true');
      expect(response.headers.get('vary')).toBe('Origin');
      expect(response.headers.get('access-control-expose-headers')).toBe(
        'retry-after, x-request-id',
      );
      expect(response.headers.get('x-request-id')).toBe('req-1');
    };
    const wrong = await post(
      f.iam,
      'auth/signIn',
      { tenantId: f.tenantId, email: 'owner@acme.test', password: 'not the password' },
      app,
    );
    expect(wrong.status).toBe(401);
    expectCors(wrong);
    expect(wrong.headers.get('cache-control')).toBe('no-store');
    const anonymous = await post(f.iam, 'auth/getSession', {}, app);
    expect(anonymous.status).toBe(401);
    expectCors(anonymous);
    // A request refused before dispatch (no JSON, no X-Better-IAM header) is readable too.
    const csrf = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/auth/getSession`, {
        method: 'POST',
        headers: app,
        body: '{}',
      }),
    );
    expect(csrf.status).toBe(403);
    expectCors(csrf);
    // GET endpoints and preflights, success included.
    const health = await f.iam.handler(new Request(`${ORIGIN}/api/iam/health`, { headers: app }));
    expect(health.status).toBe(200);
    expectCors(health);
    const metrics = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/metrics`, {
        headers: { ...app, authorization: 'Bearer scrape-token' },
      }),
    );
    expect(metrics.status).toBe(200);
    expectCors(metrics);
    const preflight = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/auth/signIn`, { method: 'OPTIONS', headers: app }),
    );
    expect(preflight.status).toBe(204);
    expectCors(preflight);
    const outside = await f.iam.handler(
      new Request(`${ORIGIN}/elsewhere`, { headers: { 'x-request-id': 'req-3' } }),
    );
    expect(outside.status).toBe(404);
    expect(outside.headers.get('x-request-id')).toBe('req-3');
    // An untrusted Origin is refused without CORS headers.
    const untrusted = await post(
      f.iam,
      'auth/getSession',
      {},
      { origin: 'https://evil.example.com', 'x-request-id': 'req-2' },
    );
    expect(untrusted.status).toBe(403);
    expect(untrusted.headers.get('access-control-allow-origin')).toBeNull();
    expect(untrusted.headers.get('x-request-id')).toBe('req-2');
  });

  it('sets the session cookie only for browser sign-ins and clears it on every cookie sign-out', async () => {
    const f = await organizationFixture();
    const browser = { origin: ORIGIN };
    const signedIn = await post(
      f.iam,
      'auth/signIn',
      {
        tenantId: f.tenantId,
        email: 'owner@acme.test',
        password: 'a strong tenant owner password',
      },
      browser,
    );
    const cookie = cookieOf(signedIn)!.split(';')[0]!;
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId: f.tenantId,
      sourceTenantId: f.tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: false,
    });
    // An assumed role's token is returned in the body only; the person's cookie session stays in place.
    const assumed = await post(
      f.iam,
      'roles/assume',
      { tenantId: f.tenantId, trustId: trust.id },
      { ...browser, cookie },
    );
    expect(assumed.status).toBe(200);
    expect(((await assumed.json()) as { data: { token: string } }).data.token).toBeTruthy();
    expect(assumed.headers.getSetCookie()).toEqual([]);
    expect((await post(f.iam, 'auth/getSession', {}, { ...browser, cookie })).status).toBe(200);
    // A bearer request never touches the cookie: signing out a bearer session leaves it alone.
    const other = await f.ownerSignIn();
    const bearerOut = await post(
      f.iam,
      'auth/signOut',
      {},
      { authorization: `Bearer ${other.token}` },
    );
    expect(bearerOut.status).toBe(200);
    expect(bearerOut.headers.getSetCookie()).toEqual([]);
    // Signing out clears the cookie, and still does when the session is already gone.
    const signedOut = await post(f.iam, 'auth/signOut', {}, { ...browser, cookie });
    expect(signedOut.status).toBe(200);
    expect(cookieOf(signedOut)).toContain('Max-Age=0');
    const again = await post(f.iam, 'auth/signOut', {}, { ...browser, cookie });
    expect(again.status).toBe(401);
    expect(cookieOf(again)).toContain('Max-Age=0');
  });

  it('names HTTP spans by the route table, never by caller-chosen paths or actions', async () => {
    const spans: IamSpan[] = [];
    const f = await organizationFixture({
      observability: { metrics: { maxSeries: 10 }, onSpan: (span) => void spans.push(span) },
    });
    f.iam.metrics!.reset();
    spans.length = 0;
    for (let index = 0; index < 15; index++)
      expect((await post(f.iam, `plugins/attacker-${index}/x`, {})).status).toBe(400);
    expect(
      (await post(f.iam, `plugins/p/${'j'.repeat(5000)}`, { tenantId: f.tenantId })).status,
    ).toBe(400);
    for (let index = 0; index < 15; index++)
      expect(
        (
          await post(f.iam, 'authorize', {
            tenantId: f.tenantId,
            action: `junk:${index}:${'x'.repeat(50)}`,
            resource: { type: 'document', id: 'memo' },
          })
        ).status,
      ).toBe(401);
    expect((await post(f.iam, 'auth/getSession', {})).status).toBe(401);
    const snapshot = f.iam.metrics!.snapshot();
    expect(new Set(snapshot.http.map((row) => row.path))).toEqual(
      new Set(['(unknown)', 'authorize', 'auth/getSession']),
    );
    expect(snapshot.http).toContainEqual({ path: 'auth/getSession', status: 401, count: 1 });
    expect(
      snapshot.spans.some((row) => row.name.includes('attacker') || row.name.includes('junk')),
    ).toBe(false);
    expect(snapshot.spans).toContainEqual(
      expect.objectContaining({
        kind: 'authorize',
        name: '(invalid)',
        code: 'UNAUTHENTICATED',
        count: 15,
      }),
    );
    // The spans themselves carry the route name, so tracers see bounded names too.
    expect(
      spans
        .filter((span) => span.kind === 'http')
        .every((span) => ['(unknown)', 'authorize', 'auth/getSession'].includes(span.name)),
    ).toBe(true);
  });

  it('enrolls MFA over HTTP with auth spans and a remembered device', async () => {
    const spans: IamSpan[] = [];
    const f = await organizationFixture({
      authentication: {
        requireMfa: (_tenant, identity) => identity.email?.startsWith('mfa-') === true,
      },
      observability: { onSpan: (span) => void spans.push(span) },
    });
    await f.member('mfa-alice');
    spans.length = 0;
    const browser = { origin: ORIGIN };
    const signIn = await post(
      f.iam,
      'auth/signIn',
      {
        tenantId: f.tenantId,
        email: 'mfa-alice@acme.test',
        password: 'a strong mfa-alice password',
      },
      browser,
    );
    const { challenge } = ((await signIn.json()) as { data: { challenge: string } }).data;
    const begun = await post(f.iam, 'auth/beginMfa', { tenantId: f.tenantId, challenge }, browser);
    expect(begun.status).toBe(200);
    const { secret } = ((await begun.json()) as { data: { secret: string } }).data;
    const credential = { tenantId: f.tenantId, challenge };
    const refused = await post(
      f.iam,
      'auth/confirmMfa',
      { credential, code: 'abcdef', rememberDevice: true },
      browser,
    );
    expect(refused.status).toBe(401);
    const generator = authenticator.clone();
    generator.options = { epoch: f.now() };
    const confirmed = await post(
      f.iam,
      'auth/confirmMfa',
      { credential, code: generator.generate(secret), rememberDevice: true },
      browser,
    );
    expect(confirmed.status).toBe(200);
    const data = ((await confirmed.json()) as { data: { deviceToken?: string } }).data;
    // "Remember this device" at enrollment returns the device token and its cookie.
    expect(data.deviceToken).toBeTruthy();
    const devicePair = cookieOf(confirmed, 'better-iam.device')!.split(';')[0]!;
    expect(decodeURIComponent(devicePair.slice('better-iam.device='.length))).toBe(
      data.deviceToken,
    );
    expect(cookieOf(confirmed)).toBeTruthy();
    // Enrollment over HTTP is instrumented like the in-process API, and the http span names the refusal.
    expect(spans).toContainEqual(
      expect.objectContaining({ kind: 'auth', name: 'beginMfa', outcome: 'ok' }),
    );
    expect(spans).toContainEqual(
      expect.objectContaining({ kind: 'auth', name: 'confirmMfa', outcome: 'denied' }),
    );
    expect(spans).toContainEqual(
      expect.objectContaining({ kind: 'auth', name: 'confirmMfa', outcome: 'ok' }),
    );
    const refusal = spans.find(
      (span) => span.kind === 'http' && span.name === 'auth/confirmMfa' && span.status === 401,
    );
    expect(refusal).toMatchObject({ outcome: 'denied' });
    expect(refusal!.code).toBeTruthy();
    // The remembered device lets the next browser sign-in skip the second factor.
    const quick = await post(
      f.iam,
      'auth/signIn',
      {
        tenantId: f.tenantId,
        email: 'mfa-alice@acme.test',
        password: 'a strong mfa-alice password',
      },
      { ...browser, cookie: devicePair },
    );
    expect(((await quick.json()) as { data: { token?: string } }).data.token).toBeTruthy();
  });

  it('counts rate-limited HTTP requests as denied and carries the error code', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    const spans: IamSpan[] = [];
    const iam = betterIam({
      database,
      secret: 'http-hardening-test-secret-with-32-characters',
      baseURL: ORIGIN,
      authentication: { rateLimits: { attempts: 2, windowMs: 60_000 } },
      observability: { onSpan: (span) => void spans.push(span) },
    });
    await iam.initialize();
    const root = await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const attempt = () =>
      post(iam, 'auth/signIn', {
        tenantId: root.tenant.id,
        email: 'root@example.test',
        password: 'not the password',
      });
    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(401);
    expect((await attempt()).status).toBe(429);
    const http = spans.filter((span) => span.kind === 'http');
    expect(http.map((span) => [span.status, span.outcome, span.code])).toEqual([
      [401, 'denied', 'INVALID_CREDENTIALS'],
      [401, 'denied', 'INVALID_CREDENTIALS'],
      [429, 'denied', 'RATE_LIMITED'],
    ]);
  });

  it('computes cookie lifetimes and live-session gauges on the authentication clock', async () => {
    const f = await organizationFixture({
      observability: { metrics: { bearerToken: 'scrape-token', gauges: true } },
    });
    const scrape = async () =>
      (
        await f.iam.handler(
          new Request(`${ORIGIN}/api/iam/metrics`, {
            headers: { authorization: 'Bearer scrape-token' },
          }),
        )
      ).text();
    // Thirty days on: every session from the fixture's setup (seven-day lifetime) has lapsed on this clock.
    f.advance(30 * 86400000);
    expect(await scrape()).toContain('better_iam_sessions_live{kind="user"} 0');
    const signedIn = await post(
      f.iam,
      'auth/signIn',
      {
        tenantId: f.tenantId,
        email: 'owner@acme.test',
        password: 'a strong tenant owner password',
      },
      { origin: ORIGIN },
    );
    expect(signedIn.status).toBe(200);
    expect(cookieOf(signedIn)).toContain(`Max-Age=${7 * 86400}`);
    expect(await scrape()).toContain('better_iam_sessions_live{kind="user"} 1');
  });

  it('answers health with a constant-cost read and refuses odd metrics tokens with 401', async () => {
    const base = sqliteAdapter({ filename: ':memory:' });
    databases.push(base);
    let tenantScans = 0;
    // Counts collection reads of `tenants`; everything else passes straight through.
    const database = new Proxy(base, {
      get(target, key) {
        if (key === 'find')
          return (collection: string, ...rest: unknown[]) => {
            if (collection === 'tenants') tenantScans++;
            return (target.find as (...args: unknown[]) => unknown).call(
              target,
              collection,
              ...rest,
            );
          };
        const value = Reflect.get(target, key, target) as unknown;
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });
    const token = 't'.repeat(32);
    const iam = betterIam({
      database,
      secret: 'http-hardening-test-secret-with-32-characters',
      baseURL: ORIGIN,
      observability: { metrics: { bearerToken: token } },
    });
    await iam.initialize();
    await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    tenantScans = 0;
    const health = await iam.handler(new Request(`${ORIGIN}/api/iam/health`));
    expect(health.status).toBe(200);
    expect(await health.json()).toMatchObject({ status: 'ok', database: 'ok' });
    expect(tenantScans).toBe(0);
    const metrics = (authorization: string) =>
      iam.handler(new Request(`${ORIGIN}/api/iam/metrics`, { headers: { authorization } }));
    // Same character count as the real header, more bytes: refused, not an internal error.
    const latin1 = await metrics(`Bearer ${'é'.repeat(token.length)}`);
    expect(latin1.status).toBe(401);
    expect((await latin1.json()).error.code).toBe('UNAUTHENTICATED');
    expect((await metrics(`Bearer ${'u'.repeat(token.length)}`)).status).toBe(401);
    expect((await metrics(`Bearer ${token}`)).status).toBe(200);
  });
});

describe('temporary-credential routes', () => {
  it('never set a cookie on sts/getSessionToken or sts/assumeRoleWithWebIdentity, even for browsers', async () => {
    const f = await organizationFixture({ sts: { webIdentity: { enabled: true } } });
    const idp = generateTestKey('ES256', 'idp');
    const issuer = 'https://token.actions.example.test';
    const provider = await f.iam.api.oidcProviders.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'CI',
      issuer,
      audiences: ['acme'],
      jwks: { keys: [idp.publicJwk as PublicJwk] },
    });
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const trust = await f.iam.api.trust.create(f.ownerCredential, {
      tenantId: f.tenantId,
      kind: 'web-identity',
      providerId: provider.id,
      serviceAccountId: account.id,
      roleId: role.id,
      conditions: { StringEquals: { 'token.sub': 'repo:acme/app' } },
    });
    // Each token carries its own run id: without a jti, tokens with identical claims are one token for replay purposes.
    let run = 0;
    const external = (sub = 'repo:acme/app') => {
      const iat = Math.floor(f.now() / 1000);
      run += 1;
      return signTestJwt(idp, { iss: issuer, aud: 'acme', sub, iat, exp: iat + 300, run_id: run });
    };
    const browser = {
      cookie: `better-iam.session=${encodeURIComponent(f.ownerCredential.token)}`,
      origin: ORIGIN,
    };
    const answers: Response[] = [];
    const call = async (path: string, body: unknown, headers: Record<string, string>) => {
      const response = await post(f.iam, path, body, headers);
      answers.push(response);
      return response;
    };
    const exchange = { tenantId: f.tenantId, trustId: trust.id, sessionName: 'ci-run' };

    const cookieToken = await call('sts/getSessionToken', {}, browser);
    expect(cookieToken.status).toBe(200);
    const bearerToken = await call(
      'sts/getSessionToken',
      {},
      { authorization: `Bearer ${f.ownerCredential.token}` },
    );
    expect(bearerToken.status).toBe(200);
    const refusedToken = await call('sts/getSessionToken', { durationSeconds: 1 }, browser);
    expect(refusedToken.status).toBe(400);
    const federated = await call(
      'sts/assumeRoleWithWebIdentity',
      { ...exchange, webIdentityToken: external() },
      browser,
    );
    expect(federated.status).toBe(200);
    const workload = await call(
      'sts/assumeRoleWithWebIdentity',
      { ...exchange, webIdentityToken: external() },
      {},
    );
    expect(workload.status).toBe(200);
    const rejected = await call(
      'sts/assumeRoleWithWebIdentity',
      { ...exchange, webIdentityToken: external('repo:evil/app') },
      browser,
    );
    expect(rejected.status).toBe(403);
    expect((await rejected.json()).error.code).toBe('WEB_IDENTITY_REJECTED');
    for (const response of answers) {
      expect(response.headers.get('set-cookie')).toBeNull();
      expect(response.headers.getSetCookie()).toEqual([]);
    }
    // The tokens came back in the body only.
    for (const response of [cookieToken, bearerToken, federated, workload])
      expect((await response.json()).data.token).toMatch(/^biam_(sts|rol)_/);
    // The public exchange keeps the CSRF header requirement.
    const bare = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/sts/assumeRoleWithWebIdentity`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ...exchange, webIdentityToken: external() }),
      }),
    );
    expect(bare.status).toBe(403);
    expect((await bare.json()).error.code).toBe('CSRF_REJECTED');
  });

  it('refuses an untrusted Origin on the JWKS route like every other route', async () => {
    const f = await organizationFixture({
      sts: { jwt: { signingKeys: [generateTestKey('EdDSA', 'k1').privateJwk as never] } },
    });
    const jwks = (headers: Record<string, string> = {}) =>
      f.iam.handler(new Request(`${ORIGIN}/api/iam/.well-known/jwks.json`, { headers }));
    const untrusted = await jwks({ origin: 'https://evil.example.com', 'x-request-id': 'req-9' });
    expect(untrusted.status).toBe(403);
    expect((await untrusted.json()).error.code).toBe('UNTRUSTED_ORIGIN');
    expect(untrusted.headers.get('access-control-allow-origin')).toBeNull();
    expect(untrusted.headers.get('x-request-id')).toBe('req-9');
    expect(untrusted.headers.get('cache-control')).not.toBe('public, max-age=300');
    // A trusted Origin and a server-to-server fetch (no Origin) both get the keys, cacheable, with no cookie.
    const trusted = await jwks({ origin: ORIGIN });
    expect(trusted.status).toBe(200);
    expect(trusted.headers.get('access-control-allow-origin')).toBe(ORIGIN);
    const server = await jwks();
    expect(server.status).toBe(200);
    for (const response of [trusted, server]) {
      expect(response.headers.get('cache-control')).toBe('public, max-age=300');
      expect(response.headers.get('content-type')).toContain('application/jwk-set+json');
      expect(response.headers.get('set-cookie')).toBeNull();
      const body = (await response.json()) as { keys: Record<string, unknown>[] };
      expect(body.keys.map((key) => key.kid)).toEqual(['k1']);
      expect(body.keys[0]).not.toHaveProperty('d');
    }
  });
});
