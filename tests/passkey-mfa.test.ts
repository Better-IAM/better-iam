import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore, Tenant } from '@better-iam/core';
import { VirtualAuthenticator } from './support/webauthn.js';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

const ORIGIN = 'https://iam.example.com';

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'passkey-mfa-test-secret-with-at-least-32-chars',
    baseURL: ORIGIN,
    authentication: {
      sendEmail: async () => {},
      passkeys: { rpID: 'iam.example.com', rpName: 'IAM' },
      now: () => clock,
    },
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const tenantId = root.tenant.id;
  const alice = await iam.store.transaction((tx) =>
    iam.auth.createIdentity(tx, {
      tenantId,
      email: 'alice@example.test',
      name: 'Alice',
      password: 'a strong alice password',
      emailVerified: true,
    }),
  );
  const setPolicy = (authPolicy?: Tenant['authPolicy']) =>
    iam.store.transaction(async (tx) => {
      const realm = (await tx.get<Tenant>('tenants', tenantId))!;
      const { authPolicy: _old, ...rest } = realm;
      await tx.put('tenants', authPolicy ? { ...rest, authPolicy } : rest);
    });
  const signIn = () =>
    iam.api.auth.signIn({
      tenantId,
      email: 'alice@example.test',
      password: 'a strong alice password',
    });
  return {
    iam,
    tenantId,
    alice,
    setPolicy,
    signIn,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('passkeys as the second factor', () => {
  it('offers a registered passkey at the MFA step and issues an MFA session from a valid assertion only', async () => {
    const f = await fixture();
    const authenticator = new VirtualAuthenticator('iam.example.com', ORIGIN);
    // Register a passkey from an ordinary session while no MFA is required yet.
    const plain = await f.signIn();
    if (!('token' in plain)) throw new Error('No MFA expected yet');
    const registration = await f.iam.api.auth.beginPasskeyRegistration({ token: plain.token });
    await f.iam.api.auth.finishPasskeyRegistration(
      { token: plain.token },
      {
        challengeId: registration.challengeId,
        response: authenticator.register(registration.options.challenge),
      },
    );
    // Now the tenant requires MFA: the challenge offers the passkey even though no authenticator app is enrolled.
    await f.setPolicy({ requireMfa: true });
    const challenge = await f.signIn();
    if (!('mfaRequired' in challenge)) throw new Error('MFA expected');
    expect(challenge).toMatchObject({ enrollmentRequired: true, passkeyAvailable: true });
    const begun = await f.iam.api.auth.beginPasskeyMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
    });
    expect(begun.options.allowCredentials?.map((item) => item.id)).toEqual([
      authenticator.credentialId.toString('base64url'),
    ]);
    // Wrong origin, then a foreign tenant, are refused; the real assertion signs in with MFA satisfied.
    await expect(
      f.iam.api.auth.finishPasskeyMfa({
        tenantId: f.tenantId,
        challengeId: begun.challengeId,
        response: authenticator.assert(
          begun.options.challenge,
          f.alice.id,
          'https://attacker.example',
        ),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_PASSKEY' });
    await expect(
      f.iam.api.auth.finishPasskeyMfa({
        tenantId: 'elsewhere',
        challengeId: begun.challengeId,
        response: authenticator.assert(begun.options.challenge, f.alice.id),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    const session = await f.iam.api.auth.finishPasskeyMfa({
      tenantId: f.tenantId,
      challengeId: begun.challengeId,
      response: authenticator.assert(begun.options.challenge, f.alice.id),
      rememberDevice: true,
    });
    expect(session.session).toMatchObject({ mfa: true, method: 'password' });
    expect(session.deviceToken).toBeDefined();
    expect((await f.iam.api.auth.getSession({ token: session.token })).identity.id).toBe(
      f.alice.id,
    );
    // Both challenges are consumed: the assertion cannot be replayed and the login challenge is gone.
    await expect(
      f.iam.api.auth.finishPasskeyMfa({
        tenantId: f.tenantId,
        challengeId: begun.challengeId,
        response: authenticator.assert(begun.options.challenge, f.alice.id),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    await expect(
      f.iam.api.auth.beginPasskeyMfa({ tenantId: f.tenantId, challenge: challenge.challenge }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    // A person without a passkey is not offered one and cannot start the ceremony.
    await f.iam.api.auth.deletePasskey(
      { token: session.token },
      { id: (await f.iam.api.auth.listPasskeys({ token: session.token }))[0]!.id },
    );
    const bare = await f.signIn();
    if (!('mfaRequired' in bare)) throw new Error('MFA expected');
    expect(bare.passkeyAvailable).toBeUndefined();
    await expect(
      f.iam.api.auth.beginPasskeyMfa({ tenantId: f.tenantId, challenge: bare.challenge }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
  });

  it('refuses an assertion once the underlying sign-in challenge has expired', async () => {
    const f = await fixture();
    const authenticator = new VirtualAuthenticator('iam.example.com', ORIGIN);
    const plain = await f.signIn();
    if (!('token' in plain)) throw new Error('No MFA expected yet');
    const registration = await f.iam.api.auth.beginPasskeyRegistration({ token: plain.token });
    await f.iam.api.auth.finishPasskeyRegistration(
      { token: plain.token },
      {
        challengeId: registration.challengeId,
        response: authenticator.register(registration.options.challenge),
      },
    );
    await f.setPolicy({ requireMfa: true });
    const challenge = await f.signIn();
    if (!('mfaRequired' in challenge)) throw new Error('MFA expected');
    f.advance(4 * 60_000);
    const begun = await f.iam.api.auth.beginPasskeyMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
    });
    // The passkey challenge is fresh, but the five-minute login challenge behind it has lapsed.
    f.advance(2 * 60_000);
    await expect(
      f.iam.api.auth.finishPasskeyMfa({
        tenantId: f.tenantId,
        challengeId: begun.challengeId,
        response: authenticator.assert(begun.options.challenge, f.alice.id),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
  });
});
