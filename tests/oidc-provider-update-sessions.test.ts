import { randomUUID } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { Session } from '@better-iam/core';
import type { PublicJwk } from '../packages/server/src/models.js';
import { generateTestKey, signTestJwt } from './support/jwt-keys.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

/**
 * Pins what apps/docs/descriptions/api/oidcProviders.md#update and docs/temporary-credentials.md say about live
 * web-identity sessions: renaming a provider or changing its replay protection keeps them, while changing its keys
 * (even adding one for a rotation), algorithms, audiences, token lifetime or clock tolerance, or disabling it, ends
 * every session issued through it so far, for good.
 */
const issuer = 'https://oidc.cluster.example.test';
const audience = 'https://acme.example';
const subject = 'system:serviceaccount:billing:exporter';

async function setup() {
  const f = await organizationFixture({ sts: { webIdentity: { enabled: true } } });
  const key = generateTestKey('RS256', 'cluster-1');
  const provider = await f.iam.api.oidcProviders.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Cluster',
    issuer,
    audiences: [audience],
    jwks: { keys: [key.publicJwk as PublicJwk] },
  });
  const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'exporter',
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
    conditions: { StringEquals: { 'token.sub': subject } },
  });
  const exchange = async () => {
    const iat = Math.floor(f.now() / 1000);
    const token = signTestJwt(key, {
      iss: issuer,
      aud: audience,
      sub: subject,
      iat,
      exp: iat + 300,
      jti: randomUUID(),
    });
    return (
      await f.iam.api.sts.assumeRoleWithWebIdentity({
        tenantId: f.tenantId,
        trustId: trust.id,
        webIdentityToken: token,
        sessionName: 'exporter',
      })
    ).token;
  };
  const works = async (token: string) => {
    try {
      await f.iam.authenticate({ token });
      return true;
    } catch {
      return false;
    }
  };
  const live = async () =>
    (await f.iam.store.find<Session>('sessions', { roleId: role.id })).filter(
      (session) => session.trustId === trust.id,
    ).length;
  const update = (fields: Record<string, unknown>) =>
    f.iam.api.oidcProviders.update(f.ownerCredential, {
      tenantId: f.tenantId,
      providerId: provider.id,
      ...fields,
    } as never);
  return { f, key, exchange, works, live, update };
}

describe('oidcProviders.update and live sessions', () => {
  it('keeps sessions across a rename or a replay-protection change', async () => {
    const s = await setup();
    const token = await s.exchange();
    s.f.advance(1000);
    await s.update({ name: 'Billing cluster' });
    await s.update({ replayProtection: 'off' });
    expect(await s.works(token)).toBe(true);
    expect(await s.live()).toBe(1);
  });

  it.each([
    ['jwks (a key added for rotation)', 'jwks'],
    ['algorithms', 'algorithms'],
    ['audiences', 'audiences'],
    ['maxTokenLifetimeSeconds', 'maxTokenLifetimeSeconds'],
    ['clockToleranceSeconds', 'clockToleranceSeconds'],
  ])('ends every session when %s changes', async (_label, field) => {
    const s = await setup();
    const token = await s.exchange();
    s.f.advance(1000);
    const next = generateTestKey('RS256', 'cluster-2');
    const values: Record<string, unknown> = {
      jwks: { keys: [s.key.publicJwk, next.publicJwk] },
      algorithms: ['RS256', 'ES256', 'EdDSA'],
      audiences: [audience, 'https://other.example'],
      maxTokenLifetimeSeconds: 1800,
      clockToleranceSeconds: 10,
    };
    const updated = await s.update({ [field]: values[field] });
    expect(updated.sessionsRevokedBefore).toBe(s.f.now() + 1);
    expect(await s.works(token)).toBe(false);
    expect(await s.live()).toBe(0);
    // New exchanges keep working.
    s.f.advance(1000);
    expect(await s.works(await s.exchange())).toBe(true);
  });

  it('ends sessions for good when the provider is disabled', async () => {
    const s = await setup();
    const token = await s.exchange();
    s.f.advance(1000);
    await s.update({ enabled: false });
    expect(await s.works(token)).toBe(false);
    expect(await s.live()).toBe(0);
    await s.update({ enabled: true });
    expect(await s.works(token)).toBe(false);
  });
});
