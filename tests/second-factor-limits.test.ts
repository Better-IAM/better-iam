import { createRequire } from 'node:module';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  createAuth,
  createMemoryRateLimiter,
  createStoreRateLimiter,
  type SignInLedger,
} from '@better-iam/auth';
import type { AuditEvent, IamStore, Tenant } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
) as typeof import('otplib');

const stores: IamStore[] = [];
afterEach(async () => {
  await closeFixtures();
  for (const store of stores.splice(0)) await store.close();
});

const totp = (f: OrganizationFixture, secret: string) => {
  const generator = authenticator.clone();
  generator.options = { epoch: f.now() };
  return generator.generate(secret);
};
/** A six-digit code that is not the current one (nor, all but certainly, a neighbouring step's). */
const wrong = (right: string) => String((Number(right) + 500_000) % 1_000_000).padStart(6, '0');

/** Creates `{name}@acme.test` with an authenticator; `challenge()` signs in with the password for a fresh MFA challenge. */
async function enrolled(f: OrganizationFixture, name: string) {
  const identity = await f.member(name);
  const first = await f.signIn(name);
  const enrollment = await f.iam.api.auth.beginMfa({ token: first.token });
  const confirmed = await f.iam.api.auth.confirmMfa({
    credential: { token: first.token },
    code: totp(f, enrollment.secret),
  });
  // Past the time step the enrollment used, so the current code is fresh.
  f.advance(31_000);
  return {
    id: identity.id,
    recoveryCodes: confirmed.recoveryCodes,
    code: () => totp(f, enrollment.secret),
    challenge: async () => {
      const result = await f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: `${name}@acme.test`,
        password: `a strong ${name} password`,
      });
      if (!('mfaRequired' in result)) throw new Error('Expected MFA');
      return result.challenge;
    },
  };
}

describe('second-factor rate limits per person', () => {
  it('does not grant fresh code guesses with every correct password', async () => {
    const f = await organizationFixture();
    const alice = await enrolled(f, 'alice');
    const verify = (challenge: string, code: string) =>
      f.iam.api.auth.verifyMfa({ tenantId: f.tenantId, challenge, code });
    // Five wrong codes (the sensitive allowance) spread over two sign-ins, each well inside its own challenge's limit...
    const first = await alice.challenge();
    for (let attempt = 0; attempt < 3; attempt++)
      await expect(verify(first, wrong(alice.code()))).rejects.toMatchObject({
        code: 'INVALID_MFA',
      });
    const second = await alice.challenge();
    for (let attempt = 0; attempt < 2; attempt++)
      await expect(verify(second, wrong(alice.code()))).rejects.toMatchObject({
        code: 'INVALID_MFA',
      });
    // ...use up Alice's allowance: a new challenge from yet another correct password earns no new guesses.
    const third = await alice.challenge();
    await expect(verify(third, wrong(alice.code()))).rejects.toMatchObject({
      code: 'RATE_LIMITED',
      status: 429,
    });
    await expect(verify(third, alice.code())).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    // The limit is Alice's own: Bob's second factor is judged normally.
    const bob = await enrolled(f, 'bob');
    await expect(verify(await bob.challenge(), wrong(bob.code()))).rejects.toMatchObject({
      code: 'INVALID_MFA',
    });
    // Unlocking the account clears the per-person counters, and the right code completes the sign-in.
    const unlocked = await f.iam.api.identities.unlock(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(unlocked.supported).toBe(true);
    const session = await verify(third, alice.code());
    expect(session.session.mfa).toBe(true);
  });

  it('limits recovery-code guesses per person across challenges', async () => {
    const f = await organizationFixture();
    const alice = await enrolled(f, 'alice');
    const recover = (challenge: string, code: string) =>
      f.iam.api.auth.recoverMfa({ tenantId: f.tenantId, challenge, code });
    const first = await alice.challenge();
    for (let attempt = 0; attempt < 3; attempt++)
      await expect(recover(first, `not-a-recovery-code-${attempt}`)).rejects.toMatchObject({
        code: 'INVALID_MFA',
      });
    const second = await alice.challenge();
    for (let attempt = 0; attempt < 2; attempt++)
      await expect(recover(second, `still-not-one-${attempt}`)).rejects.toMatchObject({
        code: 'INVALID_MFA',
      });
    const third = await alice.challenge();
    await expect(recover(third, alice.recoveryCodes[0]!)).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    // Wrong authenticator codes have their own allowance.
    await expect(
      f.iam.api.auth.verifyMfa({
        tenantId: f.tenantId,
        challenge: third,
        code: wrong(alice.code()),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_MFA' });
  });

  it('caps emailed MFA codes per person, however many sign-ins ask for them', async () => {
    const f = await organizationFixture({ authentication: { mfaEmailCodes: true } });
    await f.iam.store.transaction(async (tx) => {
      const tenant = (await tx.get<Tenant>('tenants', f.tenantId))!;
      await tx.put<Tenant>('tenants', { ...tenant, authPolicy: { requireMfa: true } });
      await f.iam.auth.createIdentity(tx, {
        tenantId: f.tenantId,
        email: 'carol@acme.test',
        name: 'Carol',
        password: 'a strong carol password',
        emailVerified: true,
      });
    });
    const challenge = async () => {
      const result = await f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'carol@acme.test',
        password: 'a strong carol password',
      });
      if (!('mfaRequired' in result) || !result.emailCodeAvailable)
        throw new Error('Expected an emailed-code MFA challenge');
      return result.challenge;
    };
    const request = (token: string) =>
      f.iam.api.auth.requestMfaCode({ tenantId: f.tenantId, challenge: token });
    const first = await challenge();
    for (let attempt = 0; attempt < 3; attempt++) await request(first);
    const second = await challenge();
    for (let attempt = 0; attempt < 2; attempt++) await request(second);
    await expect(request(await challenge())).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox.filter(
        (message) => message.template === 'mfa-code' && message.to === 'carol@acme.test',
      ),
    ).toHaveLength(5);
  });

  it('limits starting passkey second factors per person', async () => {
    const f = await organizationFixture({ authentication: { passkeys: { rpID: 'localhost' } } });
    const alice = await enrolled(f, 'alice');
    const begin = (challenge: string) =>
      f.iam.api.auth.beginPasskeyMfa({ tenantId: f.tenantId, challenge });
    const first = await alice.challenge();
    for (let attempt = 0; attempt < 3; attempt++)
      await expect(begin(first)).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    const second = await alice.challenge();
    for (let attempt = 0; attempt < 2; attempt++)
      await expect(begin(second)).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    await expect(begin(await alice.challenge())).rejects.toMatchObject({ code: 'RATE_LIMITED' });
  });
});

describe('failed-attempt bookkeeping', () => {
  it('answers a wrong password without waiting for the failure to be recorded', async () => {
    const store = sqliteAdapter({ filename: ':memory:' });
    stores.push(store);
    await store.migrate();
    let release!: () => void;
    const gate = new Promise<void>((resolve) => {
      release = resolve;
    });
    const auth = createAuth({
      store,
      secret: 'bookkeeping-test-secret-with-32-characters',
      baseURL: 'http://localhost:3000',
      // Holds the failure record's transaction open until the test lets it finish.
      onAudit: async (_tx, event) => {
        if (event.action === 'auth:signin:fail') await gate;
      },
    });
    await store.transaction(async (tx) => {
      await tx.insert<Tenant>('tenants', {
        id: 'org',
        tenantId: 'org',
        name: 'org',
        parentId: null,
        type: 'root',
        status: 'active',
        createdAt: Date.now(),
      });
    });
    const alice = await store.transaction((tx) =>
      auth.createIdentity(tx, {
        tenantId: 'org',
        email: 'alice@example.test',
        name: 'Alice',
        password: 'a strong alice password',
      }),
    );
    // A real account's refusal must not take longer than an unknown one's, so it cannot wait on the record.
    let timer: ReturnType<typeof setTimeout> | undefined;
    const outcome = await Promise.race([
      auth
        .signIn({ tenantId: 'org', email: 'alice@example.test', password: 'not the password' })
        .then(
          () => 'signed in',
          (error: { code?: string }) => error.code,
        ),
      new Promise((resolve) => {
        timer = setTimeout(resolve, 2_000, 'still waiting');
      }),
    ]);
    clearTimeout(timer);
    release();
    expect(outcome).toBe('INVALID_CREDENTIALS');
    await auth.settleBookkeeping();
    expect(await store.get<SignInLedger>('authSignIns', alice.id)).toMatchObject({
      failedAttempts: 1,
    });
  });

  it('records wrong passwords given to reauthenticate and changePassword', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const session = await f.iam.auth.withClient({ ip: '203.0.113.7', userAgent: 'laptop' }, () =>
      f.signIn('alice'),
    );
    const credential = { token: session.token };
    const guesser = { ip: '198.51.100.9', userAgent: 'curl/8' };
    for (const password of ['guess one', 'guess two'])
      await expect(
        f.iam.auth.withClient(guesser, () =>
          f.iam.api.auth.reauthenticate(credential, { password }),
        ),
      ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(
      f.iam.auth.withClient(guesser, () =>
        f.iam.api.auth.changePassword(credential, {
          currentPassword: 'guess three',
          password: 'a brand new alice password',
        }),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await f.iam.auth.settleBookkeeping();
    expect(await f.iam.store.get<SignInLedger>('authSignIns', alice.id)).toMatchObject({
      failedAttempts: 3,
      lastFailedClient: guesser,
    });
    const failures = (
      await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId, actorId: alice.id })
    ).filter((event) => event.action === 'auth:signin:fail');
    expect(failures.map((event) => event.metadata)).toEqual(
      Array(3).fill({ reason: 'password', ip: guesser.ip, userAgent: guesser.userAgent }),
    );
    // The next reauthentication reports them and restarts the record.
    const again = await f.iam.api.auth.reauthenticate(credential, {
      password: 'a strong alice password',
    });
    if (!('token' in again)) throw new Error('Unexpected MFA');
    expect(again.session.previousSignIn).toMatchObject({ failedAttempts: 3 });
  });
});

describe('rate limiter storage', () => {
  it('bounds the in-memory limiter, dropping expired counters first and then the oldest', async () => {
    expect(() => createMemoryRateLimiter({ maxKeys: 0 })).toThrow(/maxKeys/);
    const limiter = createMemoryRateLimiter({ maxKeys: 2 });
    const consume = (key: string, now: number, windowMs = 1_000) =>
      limiter.consume({ key, tenantId: 't', limit: 1, windowMs, now });
    expect(await consume('a', 0)).toBe(true);
    expect(await consume('a', 0)).toBe(false);
    expect(await consume('b', 0, 10_000)).toBe(true);
    // At the cap, an expired counter makes room before any live one is dropped.
    expect(await consume('c', 5_000)).toBe(true);
    expect(await consume('b', 5_000)).toBe(false);
    // With nothing expired, the oldest window (b) goes; its counter starts over.
    expect(await consume('d', 5_000)).toBe(true);
    expect(await consume('c', 5_000)).toBe(false);
    expect(await consume('b', 5_000)).toBe(true);
  });

  it('keeps the in-memory limiter cheap when flooded with fresh keys', async () => {
    const limiter = createMemoryRateLimiter();
    const started = performance.now();
    // Past the default cap of 100,000 live keys, none of them expired: a scan of the whole map per call would
    // take many seconds here.
    for (let index = 0; index < 120_000; index++)
      await limiter.consume({
        key: `k${index}`,
        tenantId: 't',
        limit: 5,
        windowMs: 60_000,
        now: 0,
      });
    expect(performance.now() - started).toBeLessThan(3_000);
    // The oldest counters made room for the newest.
    expect(
      await limiter.consume({ key: 'k0', tenantId: 't', limit: 1, windowMs: 60_000, now: 0 }),
    ).toBe(true);
  });

  it('deletes expired store counters, including those of made-up tenants', async () => {
    const store = sqliteAdapter({ filename: ':memory:' });
    stores.push(store);
    await store.migrate();
    const limiter = createStoreRateLimiter(store);
    const day = 24 * 60 * 60_000;
    for (let index = 0; index < 30; index++)
      await limiter.consume({
        key: `key-${index}`,
        tenantId: index % 3 ? 'org' : `ghost-${index}`,
        limit: 5,
        windowMs: 60_000,
        now: 1_000 + index,
      });
    expect(await store.find('authRateLimits')).toHaveLength(30);
    // Two days later every one of them has lapsed; the next attempt sweeps them away and keeps its own.
    expect(
      await limiter.consume({
        key: 'fresh',
        tenantId: 'org',
        limit: 5,
        windowMs: 60_000,
        now: 2 * day,
      }),
    ).toBe(true);
    await vi.waitFor(async () =>
      expect((await store.find('authRateLimits')).map((row) => row.id)).toEqual(['fresh']),
    );
    // A live counter keeps counting.
    for (let attempt = 1; attempt < 5; attempt++)
      await limiter.consume({
        key: 'fresh',
        tenantId: 'org',
        limit: 5,
        windowMs: 60_000,
        now: 2 * day,
      });
    expect(
      await limiter.consume({
        key: 'fresh',
        tenantId: 'org',
        limit: 5,
        windowMs: 60_000,
        now: 2 * day,
      }),
    ).toBe(false);
  });
});
