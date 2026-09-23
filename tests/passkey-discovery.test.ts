import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore, Identity } from '@better-iam/core';
import { VirtualAuthenticator } from './support/webauthn.js';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

const ORIGIN = 'https://iam.example.com';

describe('discoverable passkey sign-in', () => {
  it('signs a person in from the credential alone, refuses foreign or mismatched credentials, and keeps the email flow', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    const iam = betterIam({
      database,
      secret: 'passkey-discovery-test-secret-with-32-chars',
      baseURL: ORIGIN,
      authentication: {
        passkeys: { rpID: 'iam.example.com', rpName: 'IAM' },
        rateLimits: { attempts: 3 },
      },
    });
    await iam.initialize();
    const root = await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const tenantId = root.tenant.id;
    const person = async (name: string) => {
      const identity = await iam.store.transaction((tx) =>
        iam.auth.createIdentity(tx, {
          tenantId,
          email: `${name}@example.test`,
          name,
          password: `a strong ${name} password`,
          emailVerified: true,
        }),
      );
      const session = await iam.api.auth.signIn({
        tenantId,
        email: `${name}@example.test`,
        password: `a strong ${name} password`,
      });
      if (!('token' in session)) throw new Error('Unexpected MFA');
      const authenticator = new VirtualAuthenticator('iam.example.com', ORIGIN);
      const registration = await iam.api.auth.beginPasskeyRegistration({ token: session.token });
      await iam.api.auth.finishPasskeyRegistration(
        { token: session.token },
        {
          challengeId: registration.challengeId,
          response: authenticator.register(registration.options.challenge),
          name: `${name}'s key`,
        },
      );
      return { identity, authenticator };
    };
    const alice = await person('alice');
    const bob = await person('bob');
    // No email: the options carry no allow list, and the credential picks the account.
    const discovery = await iam.api.auth.beginPasskeyAuthentication({ tenantId });
    expect(discovery.options.allowCredentials ?? []).toEqual([]);
    expect(discovery.options.userVerification).toBe('required');
    const signedIn = await iam.api.auth.finishPasskeyAuthentication({
      tenantId,
      challengeId: discovery.challengeId,
      response: alice.authenticator.assert(discovery.options.challenge, alice.identity.id),
    });
    expect(signedIn.session).toMatchObject({
      identityId: alice.identity.id,
      method: 'passkey',
      mfa: true,
    });
    // The challenge was consumed.
    await expect(
      iam.api.auth.finishPasskeyAuthentication({
        tenantId,
        challengeId: discovery.challengeId,
        response: bob.authenticator.assert(discovery.options.challenge, bob.identity.id),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CHALLENGE' });
    // A user handle that disagrees with the credential's owner, and an unregistered credential, are refused.
    const again = await iam.api.auth.beginPasskeyAuthentication({ tenantId });
    await expect(
      iam.api.auth.finishPasskeyAuthentication({
        tenantId,
        challengeId: again.challengeId,
        response: bob.authenticator.assert(again.options.challenge, alice.identity.id),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_PASSKEY' });
    const stranger = new VirtualAuthenticator('iam.example.com', ORIGIN);
    const third = await iam.api.auth.beginPasskeyAuthentication({ tenantId });
    await expect(
      iam.api.auth.finishPasskeyAuthentication({
        tenantId,
        challengeId: third.challengeId,
        response: stranger.assert(third.options.challenge, alice.identity.id),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_PASSKEY' });
    // Discovery starts are anonymous, so their allowance is ten times the ordinary one (per address).
    for (let index = 0; index < 27; index++)
      await iam.api.auth.beginPasskeyAuthentication({ tenantId });
    await expect(iam.api.auth.beginPasskeyAuthentication({ tenantId })).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    // The email flow still lists exactly that person's credentials.
    const named = await iam.api.auth.beginPasskeyAuthentication({
      tenantId,
      email: 'bob@example.test',
    });
    expect(named.options.allowCredentials?.map((item) => item.id)).toEqual([
      bob.authenticator.credentialId.toString('base64url'),
    ]);
    const bobSession = await iam.api.auth.finishPasskeyAuthentication({
      tenantId,
      challengeId: named.challengeId,
      response: bob.authenticator.assert(named.options.challenge, bob.identity.id),
    });
    expect(bobSession.session.identityId).toBe(bob.identity.id);
    // A disabled account cannot sign in by discovery either.
    await iam.store.transaction(async (tx) => {
      const stored = (await tx.get<Identity>('identities', alice.identity.id))!;
      await tx.put('identities', { ...stored, status: 'disabled' });
    });
    const blocked = await iam.auth.withClient({ ip: '203.0.113.9' }, () =>
      iam.api.auth.beginPasskeyAuthentication({ tenantId }),
    );
    await expect(
      iam.api.auth.finishPasskeyAuthentication({
        tenantId,
        challengeId: blocked.challengeId,
        response: alice.authenticator.assert(blocked.options.challenge, alice.identity.id),
      }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });
});
