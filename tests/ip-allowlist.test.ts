import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { ipMatches, isIpRange, type IamStore, type Tenant } from '@better-iam/core';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const iam = betterIam({
    database,
    secret: 'ip-allowlist-test-secret-with-at-least-32-chars',
    baseURL: 'http://localhost:3000',
    http: {
      clientInfo: (request) => ({
        ip: request.headers.get('x-real-ip') ?? undefined,
        userAgent: request.headers.get('user-agent') ?? undefined,
      }),
    },
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  await iam.store.transaction(async (tx) => {
    await iam.auth.createIdentity(tx, {
      tenantId: root.tenant.id,
      email: 'alice@example.test',
      name: 'Alice',
      password: 'a strong alice password',
      emailVerified: true,
    });
  });
  const setRanges = (allowedIpRanges?: string[]) =>
    iam.store.transaction(async (tx) => {
      const realm = (await tx.get<Tenant>('tenants', root.tenant.id))!;
      const { authPolicy: _old, ...rest } = realm;
      await tx.put(
        'tenants',
        allowedIpRanges ? { ...rest, authPolicy: { allowedIpRanges } } : rest,
      );
    });
  const signIn = (ip?: string) =>
    iam.auth.withClient(ip ? { ip, userAgent: 'test' } : undefined, () =>
      iam.api.auth.signIn({
        tenantId: root.tenant.id,
        email: 'alice@example.test',
        password: 'a strong alice password',
      }),
    );
  return { iam, tenantId: root.tenant.id, setRanges, signIn };
}

describe('tenant IP allowlists', () => {
  it('validates ranges and exposes the matching helpers', () => {
    expect(isIpRange('203.0.113.0/24')).toBe(true);
    expect(isIpRange('2001:db8::/32')).toBe(true);
    expect(isIpRange('203.0.113.9')).toBe(true);
    expect(isIpRange('office')).toBe(false);
    expect(isIpRange('203.0.113.0/33')).toBe(false);
    expect(ipMatches('203.0.113.9', '203.0.113.0/24')).toBe(true);
    expect(ipMatches('203.0.114.9', '203.0.113.0/24')).toBe(false);
    expect(ipMatches('2001:db8:1::5', '2001:db8::/32')).toBe(true);
    expect(ipMatches('203.0.113.9', '2001:db8::/32')).toBe(false);
    for (const allowedIpRanges of [[], ['office'], ['10.0.0.0/8', 'nope']])
      expect(() =>
        betterIam({
          database: sqliteAdapter({ filename: ':memory:' }),
          secret: 'ip-allowlist-test-secret-with-at-least-32-chars',
          baseURL: 'http://localhost:3000',
          tenantDefaults: { authPolicy: { allowedIpRanges } },
        }),
      ).toThrow(/allowedIpRanges/);
  });

  it('refuses sign-ins and later use from outside the allowed networks, when an IP is known', async () => {
    const f = await fixture();
    // Before the policy: sessions from anywhere; one of them is kept to show it stops working later.
    const outside = await f.signIn('198.51.100.7');
    if (!('token' in outside)) throw new Error('Unexpected MFA');
    await f.setRanges(['203.0.113.0/24', '2001:db8::/32']);
    await expect(f.signIn('198.51.100.7')).rejects.toMatchObject({
      code: 'IP_NOT_ALLOWED',
      status: 403,
    });
    const inside = await f.signIn('203.0.113.42');
    if (!('token' in inside)) throw new Error('Unexpected MFA');
    expect(inside.session.client?.ip).toBe('203.0.113.42');
    const v6 = await f.signIn('2001:db8:cafe::1');
    expect('token' in v6).toBe(true);
    // No recorded IP: nothing to judge.
    expect('token' in (await f.signIn())).toBe(true);
    // The pre-policy session from outside is refused at its next use; the inside one keeps working.
    await expect(f.iam.api.auth.getSession({ token: outside.token })).rejects.toMatchObject({
      code: 'IP_NOT_ALLOWED',
    });
    expect((await f.iam.api.auth.getSession({ token: inside.token })).identity.email).toBe(
      'alice@example.test',
    );
    // Through the HTTP handler the proxy-derived IP from clientInfo is what counts.
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/auth/signIn', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          'x-real-ip': '198.51.100.8',
        },
        body: JSON.stringify({
          tenantId: f.tenantId,
          email: 'alice@example.test',
          password: 'a strong alice password',
        }),
      }),
    );
    expect(response.status).toBe(403);
    expect((await response.json()).error.code).toBe('IP_NOT_ALLOWED');
    // Clearing the policy restores the outside session.
    await f.setRanges(undefined);
    expect((await f.iam.api.auth.getSession({ token: outside.token })).session.id).toBe(
      outside.session.id,
    );
  });
});
