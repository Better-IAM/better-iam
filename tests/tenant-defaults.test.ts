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
    secret: 'tenant-defaults-test-secret-with-32-chars!!!',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    tenantDefaults: {
      limits: { identities: 2 },
      authPolicy: { minPasswordLength: 16 },
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
  return { iam, inbox, root, rootCredential: { token: session.token } };
}

describe('tenant defaults and invitation resends', () => {
  it('rejects invalid defaults at construction', () => {
    expect(() =>
      betterIam({
        database: sqliteAdapter({ filename: ':memory:' }),
        secret: 'tenant-defaults-test-secret-with-32-chars!!!',
        baseURL: 'http://localhost:3000',
        tenantDefaults: { limits: { seats: 1 } as never },
      }),
    ).toThrow(/tenantDefaults/);
    expect(() =>
      betterIam({
        database: sqliteAdapter({ filename: ':memory:' }),
        secret: 'tenant-defaults-test-secret-with-32-chars!!!',
        baseURL: 'http://localhost:3000',
        tenantDefaults: { authPolicy: { minPasswordLength: 4 } },
      }),
    ).toThrow(/tenantDefaults/);
  });

  it('applies limits and the authentication policy to new organizations and re-sends invitations', async () => {
    const f = await fixture();
    const created = await f.iam.api.tenants.create(f.rootCredential, {
      parentId: f.root.tenant.id,
      name: 'Acme',
      type: 'organization',
      ownerEmail: 'owner@acme.test',
    });
    expect(created.tenant.limits).toEqual({ identities: 2 });
    expect(created.tenant.authPolicy).toEqual({ minPasswordLength: 16 });
    await f.iam.auth.dispatchOutbox();
    const first = f.inbox.find(
      (message) =>
        message.tenantId === created.tenant.id && message.template === 'owner-invitation',
    )!;
    // Re-sending rotates the token: the old link stops working, the new one is delivered.
    const resent = await f.iam.api.tenants.resendInvitation(f.rootCredential, {
      tenantId: created.tenant.id,
      invitationId: created.invitationId,
    });
    expect(resent.email).toBe('owner@acme.test');
    await f.iam.auth.dispatchOutbox();
    const owners = f.inbox.filter(
      (message) =>
        message.tenantId === created.tenant.id && message.template === 'owner-invitation',
    );
    expect(owners).toHaveLength(2);
    const second = owners[1]!;
    expect(second.payload.token).not.toBe(first.payload.token);
    await expect(
      f.iam.api.tenants.acceptInvitation({
        tenantId: created.tenant.id,
        token: first.payload.token!,
        name: 'Owner',
        password: 'a strong tenant owner password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    // The default policy applies to the owner's first password.
    await expect(
      f.iam.api.tenants.acceptInvitation({
        tenantId: created.tenant.id,
        token: second.payload.token!,
        name: 'Owner',
        password: 'twelve chars!',
      }),
    ).rejects.toMatchObject({ code: 'WEAK_PASSWORD' });
    const owner = await f.iam.api.tenants.acceptInvitation({
      tenantId: created.tenant.id,
      token: second.payload.token!,
      name: 'Owner',
      password: 'a strong tenant owner password',
    });
    if (!('token' in owner)) throw new Error('Unexpected owner MFA');
    await expect(
      f.iam.api.tenants.resendInvitation(f.rootCredential, {
        tenantId: created.tenant.id,
        invitationId: created.invitationId,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    // Member invitations resend the same way, and the default limit counts the invited member.
    const ownerCredential = { token: owner.token };
    const invitation = await f.iam.api.identities.invite(ownerCredential, {
      tenantId: created.tenant.id,
      email: 'alice@acme.test',
    });
    await f.iam.auth.dispatchOutbox();
    const memberFirst = f.inbox
      .filter((message) => message.template === 'member-invitation')
      .at(-1)!;
    await f.iam.api.identities.resendInvitation(ownerCredential, {
      tenantId: created.tenant.id,
      invitationId: invitation.invitationId,
    });
    await f.iam.auth.dispatchOutbox();
    const memberSecond = f.inbox
      .filter((message) => message.template === 'member-invitation')
      .at(-1)!;
    expect(memberSecond.payload.token).not.toBe(memberFirst.payload.token);
    expect(memberSecond.payload.inviterName).toBe('Owner');
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId: created.tenant.id,
        token: memberFirst.payload.token!,
        name: 'Alice',
        password: 'a strong alice password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    const alice = await f.iam.api.identities.acceptInvitation({
      tenantId: created.tenant.id,
      token: memberSecond.payload.token!,
      name: 'Alice',
      password: 'a strong alice password',
    });
    expect(alice.identity.email).toBe('alice@acme.test');
    await expect(
      f.iam.api.identities.create(ownerCredential, {
        tenantId: created.tenant.id,
        email: 'bob@acme.test',
        name: 'Bob',
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
  });
});
