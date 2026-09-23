import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { verifyAuditChain, type AuditEvent, type IamStore, type Identity } from '@better-iam/core';
import type { SignInLedger } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
) as typeof import('otplib');

const PASSWORD = 'a strong tenant owner password';
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture(options: { attempts?: number } = {}) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'sign-in-insight-test-secret-with-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      now: () => clock,
      ...(options.attempts ? { rateLimits: { attempts: options.attempts } } : {}),
    },
    tenantDefaults: {},
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const owner = await iam.store.transaction((tx) =>
    iam.auth.createIdentity(tx, {
      tenantId: root.tenant.id,
      email: 'owner@example.test',
      name: 'Owner',
      password: PASSWORD,
      emailVerified: true,
    }),
  );
  const tenantId = root.tenant.id;
  const signIn = (password: string, client?: { userAgent?: string; ip?: string }) =>
    iam.auth.withClient(client, () =>
      iam.api.auth.signIn({ tenantId, email: 'owner@example.test', password }),
    );
  const ledger = () => iam.store.get<SignInLedger>('authSignIns', owner.id);
  // Ordered by chain sequence: two failures within one clock tick share a timestamp.
  const failures = async () =>
    (await iam.store.find<AuditEvent>('audit', { tenantId, actorId: owner.id }))
      .filter((event) => event.action === 'auth:signin:fail')
      .sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
  const totp = (secret: string) => {
    const generator = authenticator.clone();
    generator.options = { epoch: clock };
    return generator.generate(secret);
  };
  return {
    iam,
    tenantId,
    owner,
    signIn,
    ledger,
    failures,
    totp,
    tick: (ms: number) => {
      clock += ms;
    },
    now: () => clock,
  };
}

describe('sign-in record and failed attempts', () => {
  it('counts wrong passwords, stamps the previous sign-in on the next session, and shows both in the trail', async () => {
    const f = await fixture();
    const laptop = { userAgent: 'Mozilla/5.0 (Macintosh)', ip: '203.0.113.7' };
    const guesser = { userAgent: 'curl/8', ip: '198.51.100.9' };
    await expect(f.signIn('not the password', guesser)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    f.tick(1_000);
    await expect(f.signIn('still wrong', guesser)).rejects.toMatchObject({
      code: 'INVALID_CREDENTIALS',
    });
    const secondFailureAt = f.now();
    // The refused transactions rolled back, yet the ledger and the events were written (after the refusals were
    // answered, so they cannot slow them down).
    await f.iam.auth.settleBookkeeping();
    expect(await f.ledger()).toMatchObject({
      failedAttempts: 2,
      lastFailedAt: secondFailureAt,
      lastFailedClient: guesser,
    });
    expect((await f.ledger())!.lastAt).toBeUndefined();
    expect(await f.failures()).toHaveLength(2);
    f.tick(1_000);
    const first = await f.signIn(PASSWORD, laptop);
    if (!('token' in first)) throw new Error('Unexpected MFA');
    expect(first.session.previousSignIn).toEqual({
      failedAttempts: 2,
      lastFailedAt: secondFailureAt,
      lastFailedClient: guesser,
    });
    // The ledger restarts from this session.
    expect(await f.ledger()).toEqual({
      id: f.owner.id,
      tenantId: f.tenantId,
      identityId: f.owner.id,
      lastAt: first.session.createdAt,
      lastClient: laptop,
      failedAttempts: 0,
    });
    // A clean second sign-in reports the first one and nothing failed since; getSession carries it too.
    f.tick(60_000);
    const second = await f.signIn(PASSWORD, laptop);
    if (!('token' in second)) throw new Error('Unexpected MFA');
    expect(second.session.previousSignIn).toEqual({
      failedAttempts: 0,
      lastAt: first.session.createdAt,
      lastClient: laptop,
    });
    const current = await f.iam.api.auth.getSession({ token: second.token });
    expect(current.session.previousSignIn).toEqual(second.session.previousSignIn);
    expect(current.session.id).toBe(second.session.id);
    // The person's trail names the reason and the client of each failure, and the client of each sign-in.
    const events = await f.iam.api.auth.listSecurityEvents({ token: second.token }, { limit: 20 });
    const failed = events.filter((event) => event.action === 'auth:signin:fail');
    expect(failed).toHaveLength(2);
    expect(failed[0]!.metadata).toEqual({
      reason: 'password',
      ip: guesser.ip,
      userAgent: guesser.userAgent,
    });
    const created = events.filter((event) => event.action === 'auth:session:create');
    expect(created[0]!.metadata).toEqual({
      method: 'password',
      ip: laptop.ip,
      userAgent: laptop.userAgent,
    });
    expect(JSON.stringify(events)).not.toContain(PASSWORD);
    // Events appended outside the refused transactions still form one valid chain.
    const chain = (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).sort(
      (a, b) => a.sequence! - b.sequence!,
    );
    expect(await verifyAuditChain(chain)).toMatchObject({ valid: true, checked: chain.length });
  });

  it('ignores unknown addresses, attempts the rate limiter refused, and disabled accounts', async () => {
    const f = await fixture({ attempts: 3 });
    await expect(
      f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'nobody@example.test',
        password: 'whatever',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await f.iam.auth.settleBookkeeping();
    expect(await f.failures()).toHaveLength(0);
    expect(await f.iam.store.find('authSignIns', { tenantId: f.tenantId })).toHaveLength(0);
    // Three wrong passwords count; the fourth is refused by the limiter before any account is examined.
    for (let attempt = 0; attempt < 3; attempt++)
      await expect(f.signIn('wrong')).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(f.signIn('wrong')).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    await f.iam.auth.settleBookkeeping();
    expect(await f.failures()).toHaveLength(3);
    expect(await f.ledger()).toMatchObject({ failedAttempts: 3 });
    expect((await f.ledger())!.lastFailedClient).toBeUndefined();
    // A disabled account is refused like a wrong password and records nothing.
    const identity = await f.iam.store.transaction(async (tx) => {
      const stored = (await tx.get<Identity>('identities', f.owner.id))!;
      return tx.put<Identity>('identities', { ...stored, status: 'disabled' });
    });
    await f.iam.auth.resetRateLimits(identity);
    await expect(f.signIn(PASSWORD)).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(f.signIn('wrong')).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await f.iam.auth.settleBookkeeping();
    expect(await f.failures()).toHaveLength(3);
    expect(await f.ledger()).toMatchObject({ failedAttempts: 3 });
  });

  it('counts wrong authenticator and recovery codes once the password was right', async () => {
    const f = await fixture();
    const first = await f.signIn(PASSWORD);
    if (!('token' in first)) throw new Error('Unexpected MFA');
    const enrollment = await f.iam.api.auth.beginMfa({ token: first.token });
    const enrolled = await f.iam.api.auth.confirmMfa({
      credential: { token: first.token },
      code: f.totp(enrollment.secret),
    });
    expect(enrolled.session.previousSignIn).toMatchObject({
      failedAttempts: 0,
      lastAt: first.session.createdAt,
    });
    // Password right, then a wrong code and a wrong recovery code: two failures with their reasons.
    f.tick(31_000);
    const challenge = await f.signIn(PASSWORD, { ip: '198.51.100.9' });
    if (!('mfaRequired' in challenge)) throw new Error('Expected MFA');
    const right = f.totp(enrollment.secret);
    const wrong = String((Number(right) + 1) % 1_000_000).padStart(6, '0');
    await expect(
      f.iam.api.auth.verifyMfa({
        tenantId: f.tenantId,
        challenge: challenge.challenge,
        code: wrong,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_MFA' });
    await expect(
      f.iam.api.auth.recoverMfa({
        tenantId: f.tenantId,
        challenge: challenge.challenge,
        code: 'not-a-recovery-code',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_MFA' });
    await f.iam.auth.settleBookkeeping();
    expect((await f.failures()).map((event) => event.metadata?.reason)).toEqual([
      'mfa',
      'recovery-code',
    ]);
    // An invalid challenge is not an attempt against anyone.
    await expect(
      f.iam.api.auth.verifyMfa({ tenantId: f.tenantId, challenge: 'x'.repeat(40), code: right }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    await f.iam.auth.settleBookkeeping();
    expect(await f.failures()).toHaveLength(2);
    // The right code completes the sign-in and reports both failures since the enrollment session.
    const session = await f.iam.api.auth.verifyMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
      code: right,
    });
    expect(session.session.previousSignIn).toMatchObject({
      failedAttempts: 2,
      lastAt: enrolled.session.createdAt,
    });
    expect(session.session.previousSignIn?.lastFailedAt).toBe(f.now());
    expect(await f.ledger()).toMatchObject({
      failedAttempts: 0,
      lastAt: session.session.createdAt,
    });
  });
});
