import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const PASSWORD = 'a strong tenant owner password';
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture(options: { ipAttempts?: number; failedSignInAlerts?: number } = {}) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const iam = betterIam({
    database,
    secret: 'brute-force-test-secret-with-at-least-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      rateLimits: { attempts: 10, sensitiveAttempts: 10, windowMs: 90_000, ...options },
      ...(options.failedSignInAlerts !== undefined
        ? { failedSignInAlerts: options.failedSignInAlerts }
        : {}),
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
  const people = await iam.store.transaction(async (tx) => ({
    owner: await iam.auth.createIdentity(tx, {
      tenantId,
      email: 'owner@example.test',
      name: 'Owner',
      password: PASSWORD,
      emailVerified: true,
    }),
    bob: await iam.auth.createIdentity(tx, {
      tenantId,
      email: 'bob@example.test',
      name: 'Bob',
      password: PASSWORD,
      emailVerified: false,
    }),
  }));
  const attempt = (email: string, password: string, ip?: string) =>
    iam.auth.withClient(ip ? { ip, userAgent: 'curl/8' } : undefined, () =>
      iam.api.auth.signIn({ tenantId, email, password }),
    );
  const alerts = () => inbox.filter((message) => message.template === 'sign-in-failures');
  return { iam, tenantId, ...people, attempt, alerts, inbox };
}

describe('brute-force defenses', () => {
  it('caps attempts per client IP across accounts and flows, independently of the per-account limits', async () => {
    const f = await fixture({ ipAttempts: 3 });
    const sprayer = '198.51.100.9';
    // Three different accounts (one of them unknown) from one address: each judged on its own merits.
    await expect(f.attempt('owner@example.test', 'wrong', sprayer)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    await expect(f.attempt('bob@example.test', 'wrong', sprayer)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    await expect(f.attempt('nobody@example.test', 'wrong', sprayer)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    // The fourth attempt from that address is refused before any account is examined, whatever it names,
    // and so is a sensitive flow such as a password reset request.
    await expect(f.attempt('carol@example.test', 'wrong', sprayer)).rejects.toMatchObject({
      code: 'RATE_LIMITED',
      status: 429,
      retryAfterMs: 90_000,
    });
    await expect(
      f.iam.auth.withClient({ ip: sprayer }, () =>
        f.iam.api.auth.requestPasswordReset({ tenantId: f.tenantId, email: 'owner@example.test' }),
      ),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    // Refused attempts are not counted against the accounts they named.
    await f.iam.auth.settleBookkeeping();
    expect(
      (await f.iam.store.find('audit', { tenantId: f.tenantId, actorId: f.owner.id })).filter(
        (event) => event.action === 'auth:signin:fail',
      ),
    ).toHaveLength(1);
    // Other addresses, and calls without a recorded IP, are unaffected; the right password still works.
    await expect(f.attempt('owner@example.test', 'wrong', '203.0.113.7')).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    await expect(f.attempt('owner@example.test', 'wrong')).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    const session = await f.attempt('owner@example.test', PASSWORD, '203.0.113.7');
    expect('token' in session).toBe(true);
    // Unlocking a person clears their own counters, never the network's.
    await f.iam.auth.resetRateLimits(f.owner);
    await expect(f.attempt('owner@example.test', PASSWORD, sprayer)).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    // The option is validated like the other limits.
    expect(() =>
      betterIam({
        database: sqliteAdapter({ filename: ':memory:' }),
        secret: 'brute-force-test-secret-with-at-least-32-chars',
        baseURL: 'http://localhost:3000',
        authentication: { rateLimits: { ipAttempts: -1 } },
      }),
    ).toThrow(/ipAttempts/);
  });

  it('emails a person once per streak when their failed attempts reach the threshold', async () => {
    const f = await fixture({ failedSignInAlerts: 2 });
    const guesser = '198.51.100.9';
    await expect(f.attempt('owner@example.test', 'wrong', guesser)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    await f.iam.auth.settleBookkeeping();
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(0);
    await expect(f.attempt('owner@example.test', 'wrong again', guesser)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    await f.iam.auth.settleBookkeeping();
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(1);
    expect(f.alerts()[0]).toMatchObject({
      to: 'owner@example.test',
      payload: { attempts: '2', ip: guesser, userAgent: 'curl/8' },
    });
    expect(f.alerts()[0]!.payload.time).toMatch(/^\d{4}-\d{2}-\d{2}T/);
    // Further failures in the same streak stay quiet; a sign-in ends the streak and a new one alerts again.
    await expect(f.attempt('owner@example.test', 'and again', guesser)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    await f.iam.auth.settleBookkeeping();
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(1);
    const session = await f.attempt('owner@example.test', PASSWORD, '203.0.113.7');
    if (!('token' in session)) throw new Error('Unexpected MFA');
    expect(session.session.previousSignIn?.failedAttempts).toBe(3);
    for (const password of ['x', 'y'])
      await expect(f.attempt('owner@example.test', password, guesser)).rejects.toMatchObject({
        code: 'INVALID_CREDENTIALS',
      });
    await f.iam.auth.settleBookkeeping();
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts()).toHaveLength(2);
    // Unverified addresses never receive the alert, and the option needs a mail transport.
    for (const password of ['x', 'y', 'z'])
      await expect(f.attempt('bob@example.test', password, guesser)).rejects.toMatchObject({
        code: 'INVALID_CREDENTIALS',
      });
    await f.iam.auth.settleBookkeeping();
    await f.iam.auth.dispatchOutbox();
    expect(f.alerts().filter((message) => message.to === 'bob@example.test')).toHaveLength(0);
    expect(() =>
      betterIam({
        database: sqliteAdapter({ filename: ':memory:' }),
        secret: 'brute-force-test-secret-with-at-least-32-chars',
        baseURL: 'http://localhost:3000',
        authentication: { failedSignInAlerts: 3 },
      }),
    ).toThrow(/failedSignInAlerts requires sendEmail/);
    expect(() =>
      betterIam({
        database: sqliteAdapter({ filename: ':memory:' }),
        secret: 'brute-force-test-secret-with-at-least-32-chars',
        baseURL: 'http://localhost:3000',
        authentication: { failedSignInAlerts: 5_000, sendEmail: async () => {} },
      }),
    ).toThrow(/failedSignInAlerts/);
  });
});
