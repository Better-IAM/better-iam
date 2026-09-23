import { createHash, randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { publicApiMethods, routeGroups } from '@better-iam/server';
import { newCredentialToken } from '@better-iam/auth';
import type { IamPlugin, Session } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';
import { generateTestKey } from './support/jwt-keys.js';

afterEach(closeFixtures);

/**
 * The HTTP transport for temporary credentials: the session JWT key set route, the session-token gauge, the pre-wired
 * `sts` and `oidcProviders` route groups, and the strip of token hashes from any `session` object in a JSON answer.
 */
const ORIGIN = 'http://localhost:3000';
const JWKS = `${ORIGIN}/api/iam/.well-known/jwks.json`;
const publicMembers = new Set(['kty', 'crv', 'x', 'y', 'kid', 'alg', 'use']);

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

describe('session JWT key set', () => {
  it('publishes the public members of the signing and verification keys', async () => {
    const active = generateTestKey('EdDSA', 'k1');
    const next = generateTestKey('ES256', 'k2');
    const retired = generateTestKey('EdDSA', 'k0');
    const f = await organizationFixture({
      sts: {
        jwt: {
          signingKeys: [active.privateJwk as never, next.privateJwk as never],
          verificationKeys: [retired.publicJwk as never],
        },
      },
    });
    const response = await f.iam.handler(new Request(JWKS));
    expect(response.status).toBe(200);
    expect(response.headers.get('content-type')).toBe('application/jwk-set+json');
    expect(response.headers.get('cache-control')).toBe('public, max-age=300');
    expect(response.headers.get('x-content-type-options')).toBe('nosniff');
    const body = (await response.json()) as { keys: Record<string, unknown>[] };
    expect(body.keys.map((key) => key.kid)).toEqual(['k1', 'k2', 'k0']);
    for (const key of body.keys) {
      expect(Object.keys(key).every((member) => publicMembers.has(member))).toBe(true);
      expect(key).not.toHaveProperty('d');
      expect(key.use).toBe('sig');
    }
    expect(body.keys[1]).toMatchObject({ kty: 'EC', crv: 'P-256', alg: 'ES256' });
    expect(body).toEqual(f.iam.sessionTokens!.jwks());
    // The key set is a GET resource only; the standard CORS refusal applies to untrusted origins.
    const foreign = await f.iam.handler(
      new Request(JWKS, { headers: { origin: 'https://evil.example' } }),
    );
    expect(foreign.status).toBe(403);
    expect(((await foreign.json()) as { error: { code: string } }).error.code).toBe(
      'UNTRUSTED_ORIGIN',
    );
  });

  it('answers 404 with the error envelope when sts.jwt is not configured', async () => {
    const f = await organizationFixture();
    const response = await f.iam.handler(new Request(JWKS));
    expect(response.status).toBe(404);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.json()).toEqual({
      error: { code: 'NOT_FOUND', message: 'Endpoint not found' },
    });
  });
});

describe('storage gauges', () => {
  it('counts live session tokens', async () => {
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
    expect(await scrape()).toContain('better_iam_sessions_live{kind="session-token"} 0');
    const [source] = await f.iam.store.find<Session>('sessions', {
      identityId: f.ownerId,
      kind: 'user',
    });
    const token = newCredentialToken('sts');
    const tokenHash = createHash('sha256').update(token).digest('hex');
    const now = f.now();
    await f.iam.store.transaction((tx) =>
      tx.insert<Session>('sessions', {
        id: randomUUID(),
        tenantId: f.tenantId,
        identityId: f.ownerId,
        kind: 'session-token',
        sourceSessionId: source!.id,
        tokenHash,
        uniqueKey: tokenHash,
        createdAt: now,
        lastSeenAt: now,
        authenticatedAt: source!.authenticatedAt,
        expiresAt: now + 3600_000,
        mfa: false,
      }),
    );
    expect(await scrape()).toContain('better_iam_sessions_live{kind="session-token"} 1');
    f.advance(3600_000);
    expect(await scrape()).toContain('better_iam_sessions_live{kind="session-token"} 0');
  });
});

describe('route tables', () => {
  it('pre-wires the sts and oidcProviders groups and the public web-identity exchange', async () => {
    expect(routeGroups.has('sts')).toBe(true);
    expect(routeGroups.has('oidcProviders')).toBe(true);
    expect(publicApiMethods.has('sts/assumeRoleWithWebIdentity')).toBe(true);
    const f = await organizationFixture();
    expect(typeof f.iam.api.sts).toBe('object');
    expect(typeof f.iam.api.oidcProviders).toBe('object');
    const unknown = await post(
      f.iam,
      'sts/noSuchMethod',
      {},
      { authorization: `Bearer ${f.ownerCredential.token}` },
    );
    expect(unknown.status).toBe(404);
  });
});

describe('token hashes in JSON answers', () => {
  it('sign-in bodies carry no token hash', async () => {
    const f = await organizationFixture();
    const response = await post(f.iam, 'auth/signIn', {
      tenantId: f.tenantId,
      email: 'owner@acme.test',
      password: 'a strong tenant owner password',
    });
    expect(response.status).toBe(200);
    const text = await response.text();
    const body = JSON.parse(text) as { data: { token: string; session: Record<string, unknown> } };
    expect(body.data.token).toMatch(/^biam_ses_/);
    expect(body.data.session.id).toEqual(expect.any(String));
    expect(body.data.session).not.toHaveProperty('tokenHash');
    expect(body.data.session).not.toHaveProperty('uniqueKey');
    expect(text).not.toContain(createHash('sha256').update(body.data.token).digest('hex'));
  });

  it('strips tokenHash and uniqueKey from any top-level session object', async () => {
    const leaky: IamPlugin = {
      id: 'leaky',
      actions: ['leaky:run'],
      endpoints: [
        {
          method: 'POST',
          path: 'session',
          action: 'leaky:run',
          validate: (value) => ({ tenantId: (value as { tenantId?: unknown }).tenantId }),
          handler: async () => ({
            note: 'kept',
            session: { id: 'ses-1', tokenHash: 'hash', uniqueKey: 'hash', expiresAt: 1 },
          }),
        },
      ],
    };
    const f = await organizationFixture({ plugins: [leaky] });
    const response = await post(
      f.iam,
      'plugins/leaky/session',
      { tenantId: f.tenantId },
      { authorization: `Bearer ${f.ownerCredential.token}` },
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      data: { note: 'kept', session: { id: 'ses-1', expiresAt: 1 } },
    });
  });
});
