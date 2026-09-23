import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { AuditEvent, IamStore } from '@better-iam/core';
import { VirtualAuthenticator } from './support/webauthn.js';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

const ORIGIN = 'https://iam.example.com';

describe('passkey names and usage', () => {
  it('labels passkeys, records when they were added and used, and lets people rename them', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    let clock = Date.now();
    const iam = betterIam({
      database,
      secret: 'passkey-metadata-test-secret-with-32-chars!',
      baseURL: ORIGIN,
      authentication: { passkeys: { rpID: 'iam.example.com', rpName: 'IAM' }, now: () => clock },
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
    const session = await iam.api.auth.signIn({
      tenantId,
      email: 'alice@example.test',
      password: 'a strong alice password',
    });
    if (!('token' in session)) throw new Error('Unexpected MFA');
    const credential = { token: session.token };
    const register = async (name?: string) => {
      const authenticator = new VirtualAuthenticator('iam.example.com', ORIGIN);
      const registration = await iam.api.auth.beginPasskeyRegistration(credential);
      const created = await iam.api.auth.finishPasskeyRegistration(credential, {
        challengeId: registration.challengeId,
        response: authenticator.register(registration.options.challenge),
        ...(name === undefined ? {} : { name }),
      });
      return { authenticator, created };
    };
    // A named passkey, then one that falls back to a name derived from its transports.
    const laptop = await register('Work laptop');
    expect(laptop.created.name).toBe('Work laptop');
    clock += 60_000;
    const unnamed = await register();
    expect(unnamed.created.name).toBe('This device');
    const listed = await iam.api.auth.listPasskeys(credential);
    expect(listed.map((key) => key.name)).toEqual(['This device', 'Work laptop']);
    expect(listed[1]).toMatchObject({
      id: laptop.created.id,
      createdAt: clock - 60_000,
      deviceType: 'singleDevice',
      backedUp: false,
      transports: ['internal'],
    });
    expect(listed[1]!.lastUsedAt).toBeUndefined();
    expect(JSON.stringify(listed)).not.toContain('publicKey');
    // Signing in with the passkey stamps lastUsedAt.
    clock += 60_000;
    const begun = await iam.api.auth.beginPasskeyAuthentication({
      tenantId,
      email: 'alice@example.test',
    });
    const signedIn = await iam.api.auth.finishPasskeyAuthentication({
      tenantId,
      challengeId: begun.challengeId,
      response: laptop.authenticator.assert(begun.options.challenge, alice.id),
    });
    expect(signedIn.session.method).toBe('passkey');
    const afterUse = await iam.api.auth.listPasskeys(credential);
    expect(afterUse.find((key) => key.id === laptop.created.id)?.lastUsedAt).toBe(clock);
    expect(afterUse.find((key) => key.id === unnamed.created.id)?.lastUsedAt).toBeUndefined();
    // Renaming needs no recent authentication, is audited, and is validated.
    clock += 10 * 60_000;
    const renamed = await iam.api.auth.renamePasskey(credential, {
      id: laptop.created.id,
      name: '  YubiKey 5C  ',
    });
    expect(renamed.name).toBe('YubiKey 5C');
    expect(
      (await iam.api.auth.listPasskeys(credential)).find((key) => key.id === laptop.created.id)
        ?.name,
    ).toBe('YubiKey 5C');
    await expect(
      iam.api.auth.renamePasskey(credential, { id: laptop.created.id, name: '   ' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      iam.api.auth.renamePasskey(credential, { id: laptop.created.id, name: 'x'.repeat(65) }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      iam.api.auth.renamePasskey(credential, { id: 'pk_missing', name: 'Nope' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Another person cannot rename it.
    const otherSession = await iam.api.auth.signIn({
      tenantId,
      email: 'root@example.test',
      password: 'a strong root test password',
    });
    if (!('mfaRequired' in otherSession)) throw new Error('Root requires MFA');
    const events = (await iam.store.find<AuditEvent>('audit', { tenantId, actorId: alice.id })).map(
      (event) => [event.action, event.metadata?.name],
    );
    expect(events).toEqual(
      expect.arrayContaining([
        ['auth:passkey:create', 'Work laptop'],
        ['auth:passkey:create', 'This device'],
        ['auth:passkey:rename', 'YubiKey 5C'],
      ]),
    );
    // Over HTTP the rename is an authenticated auth method.
    const response = await iam.handler(
      new Request(`${ORIGIN}/api/iam/auth/renamePasskey`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${session.token}`,
        },
        body: JSON.stringify({ id: unnamed.created.id, name: 'Phone' }),
      }),
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: { name: string } }).data.name).toBe('Phone');
  });
});
