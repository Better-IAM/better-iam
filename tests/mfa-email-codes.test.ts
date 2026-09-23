import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore, Tenant } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture(deploymentDefault?: boolean) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'mfa-email-codes-test-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
      ...(deploymentDefault === undefined ? {} : { mfaEmailCodes: deploymentDefault }),
    },
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const tenantId = root.tenant.id;
  await iam.store.transaction(async (tx) => {
    await iam.auth.createIdentity(tx, {
      tenantId,
      email: 'alice@example.test',
      name: 'Alice',
      password: 'a strong alice password',
      emailVerified: true,
    });
  });
  const setPolicy = (authPolicy?: Tenant['authPolicy']) =>
    iam.store.transaction(async (tx) => {
      const realm = (await tx.get<Tenant>('tenants', tenantId))!;
      const { authPolicy: _old, ...rest } = realm;
      await tx.put('tenants', authPolicy ? { ...rest, authPolicy } : rest);
    });
  const signIn = (email = 'alice@example.test', password = 'a strong alice password') =>
    iam.api.auth.signIn({ tenantId, email, password });
  const lastCode = () => inbox.filter((m) => m.template === 'mfa-code').at(-1)?.payload.code;
  return {
    iam,
    inbox,
    tenantId,
    setPolicy,
    signIn,
    lastCode,
    advance: (ms: number) => {
      clock += ms;
    },
    now: () => clock,
  };
}

describe('emailed MFA codes', () => {
  it('lets a member without an authenticator complete a required MFA with a single-use emailed code', async () => {
    const f = await fixture();
    await f.setPolicy({ requireMfa: true });
    // Off by default: the challenge offers enrollment only, and asking for a code is refused.
    const plain = await f.signIn();
    if (!('mfaRequired' in plain)) throw new Error('MFA expected');
    expect(plain.enrollmentRequired).toBe(true);
    expect(plain.emailCodeAvailable).toBeUndefined();
    await expect(
      f.iam.api.auth.requestMfaCode({ tenantId: f.tenantId, challenge: plain.challenge }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    // The tenant opts in.
    await f.setPolicy({ requireMfa: true, mfaEmailCodes: true });
    const offered = await f.signIn();
    if (!('mfaRequired' in offered)) throw new Error('MFA expected');
    expect(offered).toMatchObject({ enrollmentRequired: true, emailCodeAvailable: true });
    // A wrong code before any was sent, then a wrong code after one was sent.
    await expect(
      f.iam.api.auth.verifyMfa({
        tenantId: f.tenantId,
        challenge: offered.challenge,
        code: '000000',
      }),
    ).rejects.toMatchObject({ code: 'MFA_NOT_ENROLLED' });
    const requested = await f.iam.api.auth.requestMfaCode({
      tenantId: f.tenantId,
      challenge: offered.challenge,
    });
    expect(requested.expiresAt).toBeLessThanOrEqual(f.now() + 5 * 60_000);
    await f.iam.auth.dispatchOutbox();
    const code = f.lastCode()!;
    expect(code).toMatch(/^\d{6}$/);
    await expect(
      f.iam.api.auth.verifyMfa({
        tenantId: f.tenantId,
        challenge: offered.challenge,
        code: code === '111111' ? '222222' : '111111',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_MFA' });
    // Requesting again replaces the code; the old one stops working; the new one signs in with mfa: true.
    await f.iam.api.auth.requestMfaCode({ tenantId: f.tenantId, challenge: offered.challenge });
    await f.iam.auth.dispatchOutbox();
    const fresh = f.lastCode()!;
    if (fresh !== code)
      await expect(
        f.iam.api.auth.verifyMfa({ tenantId: f.tenantId, challenge: offered.challenge, code }),
      ).rejects.toMatchObject({ code: 'INVALID_MFA' });
    const session = await f.iam.api.auth.verifyMfa({
      tenantId: f.tenantId,
      challenge: offered.challenge,
      code: fresh,
      rememberDevice: true,
    });
    expect(session.session.mfa).toBe(true);
    expect(session.deviceToken).toBeDefined();
    // The challenge was consumed with the code.
    await expect(
      f.iam.api.auth.verifyMfa({ tenantId: f.tenantId, challenge: offered.challenge, code: fresh }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    // Codes never outlive the five-minute login challenge.
    const later = await f.signIn();
    if (!('mfaRequired' in later)) throw new Error('MFA expected');
    const timed = await f.iam.api.auth.requestMfaCode({
      tenantId: f.tenantId,
      challenge: later.challenge,
    });
    expect(timed.expiresAt).toBeLessThanOrEqual(f.now() + 5 * 60_000);
    await f.iam.auth.dispatchOutbox();
    const expiring = f.lastCode()!;
    f.advance(5 * 60_000 + 1_000);
    await expect(
      f.iam.api.auth.verifyMfa({
        tenantId: f.tenantId,
        challenge: later.challenge,
        code: expiring,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
  });

  it('never offers codes to root administrators or to people with an authenticator, and honours the deployment default', async () => {
    const f = await fixture(true);
    // Deployment default on: Alice is offered a code without a tenant policy.
    await f.setPolicy({ requireMfa: true });
    const alice = await f.signIn();
    if (!('mfaRequired' in alice)) throw new Error('MFA expected');
    expect(alice.emailCodeAvailable).toBe(true);
    // Root: authenticator only.
    const rootChallenge = await f.signIn('root@example.test', 'a strong root test password');
    if (!('mfaRequired' in rootChallenge)) throw new Error('Root must require MFA');
    expect(rootChallenge.emailCodeAvailable).toBeUndefined();
    await expect(
      f.iam.api.auth.requestMfaCode({ tenantId: f.tenantId, challenge: rootChallenge.challenge }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    // Once Alice enrolls an authenticator, codes are no longer offered and the authenticator is checked.
    await f.iam.api.auth.requestMfaCode({ tenantId: f.tenantId, challenge: alice.challenge });
    await f.iam.auth.dispatchOutbox();
    const first = await f.iam.api.auth.verifyMfa({
      tenantId: f.tenantId,
      challenge: alice.challenge,
      code: f.lastCode()!,
    });
    const enrollment = await f.iam.api.auth.beginMfa({ token: first.token });
    const generator = authenticator.clone();
    generator.options = { epoch: f.now() };
    await f.iam.api.auth.confirmMfa({
      credential: { token: first.token },
      code: generator.generate(enrollment.secret),
    });
    const enrolled = await f.signIn();
    if (!('mfaRequired' in enrolled)) throw new Error('MFA expected');
    expect(enrolled).toMatchObject({ enrollmentRequired: false });
    expect(enrolled.emailCodeAvailable).toBeUndefined();
    await expect(
      f.iam.api.auth.requestMfaCode({ tenantId: f.tenantId, challenge: enrolled.challenge }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
    // A tenant can switch the deployment default off.
    await f.setPolicy({ requireMfa: true, mfaEmailCodes: false });
    await f.iam.store.transaction(async (tx) => {
      await tx.delete('authMfa', first.session.identityId);
    });
    const off = await f.signIn();
    if (!('mfaRequired' in off)) throw new Error('MFA expected');
    expect(off.emailCodeAvailable).toBeUndefined();
  });
});
