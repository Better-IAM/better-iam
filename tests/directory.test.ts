import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const iam = betterIam({
    database,
    secret: 'directory-test-secret-with-at-least-32-chars!!',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const created = await iam.api.tenants.create(
    { token: session.token },
    {
      parentId: root.tenant.id,
      name: 'Acme',
      type: 'organization',
      ownerEmail: 'owner@acme.test',
    },
  );
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  return { iam, tenantId: created.tenant.id, ownerCredential: { token: owner.token } };
}

describe('directory search and administrative session lists', () => {
  it('searches identities by name or email with stable pagination', async () => {
    const f = await fixture();
    await f.iam.api.identities.createMany(f.ownerCredential, {
      tenantId: f.tenantId,
      identities: [
        { email: 'zoe@acme.test', name: 'Zoe Zhang' },
        { email: 'alice@acme.test', name: 'Alice Adams' },
        { email: 'bob@other.test', name: 'Bob Brown' },
      ],
    });
    await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci-bot',
    });
    const all = await f.iam.api.identities.list(f.ownerCredential, { tenantId: f.tenantId });
    // Ordered by name, case-insensitively.
    expect(all.map((identity) => identity.name)).toEqual([
      'Alice Adams',
      'Bob Brown',
      'ci-bot',
      'Owner',
      'Zoe Zhang',
    ]);
    expect(
      (
        await f.iam.api.identities.list(f.ownerCredential, { tenantId: f.tenantId, query: 'ACME' })
      ).map((identity) => identity.email),
    ).toEqual(['alice@acme.test', 'owner@acme.test', 'zoe@acme.test']);
    expect(
      (
        await f.iam.api.identities.list(f.ownerCredential, { tenantId: f.tenantId, query: 'bo' })
      ).map((identity) => identity.name),
    ).toEqual(['Bob Brown', 'ci-bot']);
    const page = await f.iam.api.identities.list(f.ownerCredential, {
      tenantId: f.tenantId,
      kind: 'user',
      limit: 2,
      offset: 1,
    });
    expect(page.map((identity) => identity.name)).toEqual(['Bob Brown', 'Owner']);
    await expect(
      f.iam.api.identities.list(f.ownerCredential, { tenantId: f.tenantId, limit: 0 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('lets administrators change a member email, revoking sessions and verification', async () => {
    const f = await fixture();
    const alice = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'taken@acme.test',
      name: 'Taken',
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    await expect(
      f.iam.api.identities.update(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.id,
        email: 'taken@acme.test',
      }),
    ).rejects.toMatchObject({ code: 'IDENTITY_EXISTS' });
    const updated = await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      email: 'Alice.New@Acme.test',
    });
    expect(updated.email).toBe('alice.new@acme.test');
    expect(updated.emailVerified).toBe(false);
    await expect(f.iam.api.auth.getSession({ token: login.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    const again = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice.new@acme.test',
      password: 'a strong alice password',
    });
    expect('token' in again).toBe(true);
    const trail = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'identity:email-change',
    });
    expect(trail[0]?.metadata).toEqual({ from: 'alice@acme.test', to: 'alice.new@acme.test' });
    // Setting the same email again changes nothing and is not audited twice.
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      email: 'alice.new@acme.test',
    });
    expect(
      await f.iam.api.audit.list(f.ownerCredential, {
        tenantId: f.tenantId,
        action: 'identity:email-change',
      }),
    ).toHaveLength(1);
  });

  it('lists a member’s active sessions for administrators without token material', async () => {
    const f = await fixture();
    const alice = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    const login = async () => {
      const result = await f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'alice@acme.test',
        password: 'a strong alice password',
      });
      if (!('token' in result)) throw new Error('Unexpected MFA');
      return result;
    };
    const first = await login();
    await login();
    const sessions = await f.iam.api.identities.listSessions(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(sessions).toHaveLength(2);
    expect(sessions.every((session) => session.method === 'password')).toBe(true);
    expect(JSON.stringify(sessions)).not.toContain(first.token);
    expect(sessions[0]).not.toHaveProperty('tokenHash');
    await expect(
      f.iam.api.identities.listSessions(
        { token: first.token },
        { tenantId: f.tenantId, identityId: alice.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.api.auth.revokeSession({ token: first.token }, { sessionId: sessions[1]!.id });
    expect(
      await f.iam.api.identities.listSessions(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.id,
      }),
    ).toHaveLength(1);
  });
});
