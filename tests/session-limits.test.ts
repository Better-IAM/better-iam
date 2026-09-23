import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore, Tenant } from '@better-iam/core';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

describe('session limits on getSession', () => {
  it('reports the lifetime, idle timeout, and idle expiry in force, honouring the tenant policy', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    let clock = Date.now();
    const iam = betterIam({
      database,
      secret: 'session-limits-test-secret-with-32-chars!',
      baseURL: 'http://localhost:3000',
      authentication: {
        now: () => clock,
        sessionLifetimeMs: 10 * 60_000,
        sessionIdleTimeoutMs: 4 * 60_000,
      },
      tenantDefaults: {},
    });
    await iam.initialize();
    const root = await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const tenantId = root.tenant.id;
    await iam.store.transaction((tx) =>
      iam.auth.createIdentity(tx, {
        tenantId,
        email: 'owner@example.test',
        name: 'Owner',
        password: 'a strong tenant owner password',
        emailVerified: true,
      }),
    );
    const signed = await iam.api.auth.signIn({
      tenantId,
      email: 'owner@example.test',
      password: 'a strong tenant owner password',
    });
    if (!('token' in signed)) throw new Error('Unexpected MFA');
    const first = await iam.api.auth.getSession({ token: signed.token });
    expect(first.limits).toEqual({
      lifetimeMs: 10 * 60_000,
      idleTimeoutMs: 4 * 60_000,
      idleExpiresAt: clock + 4 * 60_000,
      now: clock,
    });
    expect(first.session.expiresAt).toBe(clock + 10 * 60_000);
    // A tenant may shorten the idle timeout; every later call reports the new window from its own touch.
    await iam.store.transaction(async (tx) => {
      const realm = (await tx.get<Tenant>('tenants', tenantId))!;
      await tx.put('tenants', { ...realm, authPolicy: { sessionIdleTimeoutMs: 2 * 60_000 } });
    });
    clock += 60_000;
    const shortened = await iam.api.auth.getSession({ token: signed.token });
    expect(shortened.limits.idleTimeoutMs).toBe(2 * 60_000);
    expect(shortened.limits.idleExpiresAt).toBe(clock + 2 * 60_000);
    expect(shortened.session.lastSeenAt).toBe(clock);
    // Touched every 90 seconds the session stays alive; near the absolute end the idle expiry can never exceed
    // the session's own expiry.
    while (signed.session.expiresAt - clock > 2 * 60_000) {
      clock += 90_000;
      const touched = await iam.api.auth.getSession({ token: signed.token });
      expect(touched.limits.idleExpiresAt).toBe(
        Math.min(clock + 2 * 60_000, signed.session.expiresAt),
      );
    }
    const ending = await iam.api.auth.getSession({ token: signed.token });
    expect(ending.limits.idleExpiresAt).toBe(signed.session.expiresAt);
    expect(ending.limits.idleExpiresAt).toBeLessThan(clock + 2 * 60_000);
    // Silence past the idle window (here also the lifetime) ends the session.
    clock += 2 * 60_000 + 1;
    await expect(iam.api.auth.getSession({ token: signed.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    // Over HTTP the same shape comes back in the envelope.
    const again = await iam.api.auth.signIn({
      tenantId,
      email: 'owner@example.test',
      password: 'a strong tenant owner password',
    });
    if (!('token' in again)) throw new Error('Unexpected MFA');
    const response = await iam.handler(
      new Request('http://localhost:3000/api/iam/auth/getSession', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${again.token}`,
        },
        body: '{}',
      }),
    );
    expect(response.status).toBe(200);
    const body = (await response.json()) as { data: { limits: Record<string, number> } };
    expect(body.data.limits).toEqual({
      lifetimeMs: 10 * 60_000,
      idleTimeoutMs: 2 * 60_000,
      idleExpiresAt: clock + 2 * 60_000,
      now: clock,
    });
  });
});
