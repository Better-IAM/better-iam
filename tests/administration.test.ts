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
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'admin-test-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
    },
    permissions: { actions: ['documents:read', 'documents:write'] },
    onboarding: { mode: 'linked' },
    resolveResource: async (reference) => reference,
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
  const credential = { token: session.token };
  const createTenant = async (name: string) => {
    const created = await iam.api.tenants.create(credential, {
      parentId: root.tenant.id,
      name,
      type: 'organization',
      ownerEmail: `${name}@example.test`,
    });
    await iam.auth.dispatchOutbox();
    const message = inbox.find(
      (m) => m.tenantId === created.tenant.id && m.template === 'owner-invitation',
    )!;
    const owner = await iam.api.tenants.acceptInvitation({
      tenantId: created.tenant.id,
      token: message.payload.token!,
      name: `${name} owner`,
      password: 'a strong tenant owner password',
    });
    if (!('token' in owner)) throw new Error('Unexpected owner MFA');
    return { tenant: created.tenant, owner, credential: { token: owner.token } };
  };
  return {
    iam,
    database,
    root,
    credential,
    inbox,
    createTenant,
    advance: (ms: number) => {
      clock += ms;
    },
    now: () => clock,
  };
}

describe('identity deletion', () => {
  it('removes credentials, factors, bindings, memberships, and links while keeping a resolvable tombstone', async () => {
    const f = await fixture();
    const a = await f.createTenant('acme');
    const member = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'member@acme.test',
      name: 'Member',
      password: 'a strong member test password',
    });
    const role = await f.iam.api.roles.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const binding = await f.iam.api.bindings.create(a.credential, {
      tenantId: a.tenant.id,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: member.id,
    });
    const group = await f.iam.api.groups.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Readers',
    });
    await f.iam.api.groups.addMember(a.credential, {
      tenantId: a.tenant.id,
      groupId: group.id,
      identityId: member.id,
    });
    await f.iam.api.authorities.create(a.credential, {
      tenantId: a.tenant.id,
      identityId: member.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: a.tenant.id,
      email: 'member@acme.test',
      password: 'a strong member test password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    await expect(
      f.iam.api.identities.delete(a.credential, {
        tenantId: a.tenant.id,
        identityId: a.owner.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.identities.delete(
        { token: login.token },
        { tenantId: a.tenant.id, identityId: member.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const deleted = await f.iam.api.identities.delete(a.credential, {
      tenantId: a.tenant.id,
      identityId: member.id,
    });
    expect(deleted).toMatchObject({
      id: member.id,
      status: 'deleted',
      deletedEmail: 'member@acme.test',
      owner: false,
    });
    expect(deleted).not.toHaveProperty('email');
    expect(deleted).not.toHaveProperty('passwordHash');
    expect(typeof deleted.deletedAt).toBe('number');
    await expect(f.iam.api.auth.getSession({ token: login.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect(await f.database.get('bindings', binding.id)).toBeUndefined();
    expect(
      await f.iam.api.groups.listMembers(a.credential, {
        tenantId: a.tenant.id,
        groupId: group.id,
      }),
    ).toEqual([]);
    expect(
      (
        await f.database.find('grantAuthorities', { tenantId: a.tenant.id, identityId: member.id })
      ).every((authority) => authority.revoked),
    ).toBe(true);
    expect(
      (await f.iam.api.identities.list(a.credential, { tenantId: a.tenant.id })).map(
        (identity) => identity.id,
      ),
    ).toEqual([a.owner.identity.id]);
    expect(
      (
        await f.iam.api.identities.list(a.credential, {
          tenantId: a.tenant.id,
          includeDeleted: true,
        })
      )
        .map((identity) => identity.status)
        .sort(),
    ).toEqual(['active', 'deleted']);
    expect(
      (
        await f.iam.api.identities.list(a.credential, { tenantId: a.tenant.id, status: 'deleted' })
      ).map((identity) => identity.id),
    ).toEqual([member.id]);
    expect(
      (
        await f.iam.api.identities.get(a.credential, {
          tenantId: a.tenant.id,
          identityId: member.id,
        })
      ).status,
    ).toBe('deleted');
    // The email is free again, the tombstone cannot be reused, and the deletion is audited.
    const replacement = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'member@acme.test',
      name: 'Member again',
      password: 'a strong replacement password',
    });
    expect(replacement.id).not.toBe(member.id);
    await expect(
      f.iam.api.bindings.create(a.credential, {
        tenantId: a.tenant.id,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: member.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.identities.setStatus(a.credential, {
        tenantId: a.tenant.id,
        identityId: member.id,
        status: 'active',
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.identities.delete(a.credential, { tenantId: a.tenant.id, identityId: member.id }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      f.iam.api.auth.signIn({
        tenantId: a.tenant.id,
        email: 'member@acme.test',
        password: 'a strong member test password',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    const trail = await f.iam.api.audit.list(a.credential, {
      tenantId: a.tenant.id,
      action: 'identity:delete',
    });
    expect(trail).toHaveLength(1);
    expect(trail[0]!.metadata).toMatchObject({ email: 'member@acme.test', kind: 'user' });
    // Owners and root administrators keep their last-of-kind protection.
    await expect(
      f.iam.api.identities.delete(f.credential, {
        tenantId: a.tenant.id,
        identityId: a.owner.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'LAST_OWNER' });
    await expect(
      f.iam.api.identities.delete(a.credential, {
        tenantId: f.root.tenant.id,
        identityId: f.root.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});

describe('service accounts, credentials, trusts, and root administrators', () => {
  it('lists, updates, disables, and deletes service accounts and their API keys', async () => {
    const f = await fixture();
    const a = await f.createTenant('acme');
    const account = await f.iam.api.serviceAccounts.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'CI',
      description: 'Build pipeline',
    });
    expect(account.description).toBe('Build pipeline');
    expect(
      (await f.iam.api.serviceAccounts.list(a.credential, { tenantId: a.tenant.id })).map(
        (item) => item.id,
      ),
    ).toEqual([account.id]);
    expect(
      (
        await f.iam.api.identities.list(a.credential, { tenantId: a.tenant.id, kind: 'service' })
      ).map((item) => item.id),
    ).toEqual([account.id]);
    await expect(
      f.iam.api.serviceAccounts.get(a.credential, {
        tenantId: a.tenant.id,
        identityId: a.owner.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(
      (
        await f.iam.api.serviceAccounts.update(a.credential, {
          tenantId: a.tenant.id,
          identityId: account.id,
          name: 'CI runner',
        })
      ).name,
    ).toBe('CI runner');
    await expect(
      f.iam.api.serviceAccounts.update(a.credential, {
        tenantId: a.tenant.id,
        identityId: account.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const key = await f.iam.api.credentials.create(a.credential, {
      tenantId: a.tenant.id,
      identityId: account.id,
      expiresInSeconds: 3600,
    });
    const second = await f.iam.api.credentials.create(a.credential, {
      tenantId: a.tenant.id,
      identityId: account.id,
    });
    const listed = await f.iam.api.credentials.list(a.credential, {
      tenantId: a.tenant.id,
      identityId: account.id,
    });
    expect(listed.map((item) => item.id).sort()).toEqual(
      [key.credentialId, second.credentialId].sort(),
    );
    expect(JSON.stringify(listed)).not.toContain(key.token);
    expect(listed.every((item) => item.expired === false)).toBe(true);
    expect((await f.iam.api.credentials.list(a.credential, { tenantId: a.tenant.id })).length).toBe(
      2,
    );
    expect(
      (await f.iam.api.auth.getSession({ token: key.token }).catch((error) => error)).code,
    ).toBe('UNAUTHENTICATED');
    expect(
      (
        await f.iam.authorize({
          token: key.token,
          tenantId: a.tenant.id,
          action: 'documents:read',
          resource: { type: 'document', id: 'x' },
        })
      ).allowed,
    ).toBe(false);
    await f.iam.api.serviceAccounts.setStatus(a.credential, {
      tenantId: a.tenant.id,
      identityId: account.id,
      status: 'disabled',
    });
    await expect(
      f.iam.authorize({
        token: key.token,
        tenantId: a.tenant.id,
        action: 'documents:read',
        resource: { type: 'document', id: 'x' },
      }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(
      await f.iam.api.credentials.list(a.credential, {
        tenantId: a.tenant.id,
        identityId: account.id,
      }),
    ).toEqual([]);
    await f.iam.api.serviceAccounts.setStatus(a.credential, {
      tenantId: a.tenant.id,
      identityId: account.id,
      status: 'active',
    });
    const third = await f.iam.api.credentials.create(a.credential, {
      tenantId: a.tenant.id,
      identityId: account.id,
      expiresInSeconds: 60,
    });
    f.advance(61_000);
    expect(
      (
        await f.iam.api.credentials.list(a.credential, {
          tenantId: a.tenant.id,
          identityId: account.id,
        })
      )[0]!.expired,
    ).toBe(true);
    await expect(
      f.iam.authorize({
        token: third.token,
        tenantId: a.tenant.id,
        action: 'documents:read',
        resource: { type: 'document', id: 'x' },
      }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    const removed = await f.iam.api.serviceAccounts.delete(a.credential, {
      tenantId: a.tenant.id,
      identityId: account.id,
    });
    expect(removed.status).toBe('deleted');
    expect(await f.iam.api.serviceAccounts.list(a.credential, { tenantId: a.tenant.id })).toEqual(
      [],
    );
    expect(
      await f.iam.api.credentials.list(a.credential, {
        tenantId: a.tenant.id,
        identityId: account.id,
      }),
    ).toEqual([]);
    await expect(
      f.iam.api.credentials.create(a.credential, { tenantId: a.tenant.id, identityId: account.id }),
    ).rejects.toMatchObject({ code: 'INVALID_IDENTITY' });
  });

  it('lists trusts without external identifiers and root administrators from the root tenant', async () => {
    const f = await fixture();
    const a = await f.createTenant('acme');
    const b = await f.createTenant('beta');
    const role = await f.iam.api.roles.create(b.credential, {
      tenantId: b.tenant.id,
      name: 'Auditor',
      permissions: ['documents:read'],
    });
    const trust = await f.iam.api.trust.create(f.credential, {
      tenantId: b.tenant.id,
      sourceTenantId: a.tenant.id,
      sourceIdentityId: a.owner.identity.id,
      roleId: role.id,
      externalId: 'contract-7',
    });
    const listed = await f.iam.api.trust.list(b.credential, { tenantId: b.tenant.id });
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({
      id: trust.id,
      roleId: role.id,
      sourceTenantId: a.tenant.id,
      requiresExternalId: true,
    });
    expect(listed[0]).not.toHaveProperty('externalIdHash');
    await f.iam.api.trust.revoke(f.credential, { tenantId: b.tenant.id, trustId: trust.id });
    expect(await f.iam.api.trust.list(b.credential, { tenantId: b.tenant.id })).toEqual([]);
    expect(
      (
        await f.iam.api.trust.list(b.credential, { tenantId: b.tenant.id, includeRevoked: true })
      ).map((item) => item.revoked),
    ).toEqual([true]);
    await expect(
      f.iam.api.trust.list(a.credential, { tenantId: b.tenant.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const second = await f.iam.api.identities.create(f.credential, {
      tenantId: f.root.tenant.id,
      email: 'second@example.test',
      name: 'Second',
      password: 'a strong second root password',
    });
    await f.iam.api.root.setAdministrator(f.credential, {
      tenantId: f.root.tenant.id,
      identityId: second.id,
      enabled: true,
    });
    expect(
      (await f.iam.api.root.listAdministrators(f.credential, { tenantId: f.root.tenant.id }))
        .map((item) => item.email)
        .sort(),
    ).toEqual(['root@example.test', 'second@example.test']);
    await expect(
      f.iam.api.root.listAdministrators(a.credential, { tenantId: a.tenant.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.root.listAdministrators(f.credential, { tenantId: a.tenant.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('audit filtering', () => {
  it('filters by actor, action pattern, resource, outcome, and time range, newest first', async () => {
    const f = await fixture();
    const a = await f.createTenant('acme');
    const start = f.now();
    const member = await f.iam.api.identities.create(a.credential, {
      tenantId: a.tenant.id,
      email: 'member@acme.test',
      name: 'Member',
      password: 'a strong member test password',
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: a.tenant.id,
      email: 'member@acme.test',
      password: 'a strong member test password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    await expect(
      f.iam.api.groups.create({ token: login.token }, { tenantId: a.tenant.id, name: 'Denied' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const group = await f.iam.api.groups.create(a.credential, {
      tenantId: a.tenant.id,
      name: 'Allowed',
    });
    const all = await f.iam.api.audit.list(a.credential, { tenantId: a.tenant.id });
    expect(all.length).toBeGreaterThan(3);
    for (let index = 1; index < all.length; index++)
      expect(all[index - 1]!.timestamp).toBeGreaterThanOrEqual(all[index]!.timestamp);
    expect(
      (
        await f.iam.api.audit.list(a.credential, { tenantId: a.tenant.id, actorId: member.id })
      ).every((event) => event.actorId === member.id),
    ).toBe(true);
    expect(
      (await f.iam.api.audit.list(a.credential, { tenantId: a.tenant.id, outcome: 'deny' })).map(
        (event) => [event.action, event.actorId],
      ),
    ).toEqual([['iam:groups:create', member.id]]);
    expect(
      (
        await f.iam.api.audit.list(a.credential, {
          tenantId: a.tenant.id,
          action: 'iam:groups:*',
          outcome: 'allow',
        })
      ).map((event) => event.resourceId),
    ).toEqual([a.tenant.id]);
    expect(
      (await f.iam.api.audit.list(a.credential, { tenantId: a.tenant.id, resourceId: group.id }))
        .length,
    ).toBe(0);
    // Reads are audited too, so every listing adds an iam:audit:read event; range assertions use the stable group events.
    const ranged = await f.iam.api.audit.list(a.credential, {
      tenantId: a.tenant.id,
      from: start,
      to: Date.now(),
    });
    expect(ranged.length).toBeGreaterThanOrEqual(all.length);
    expect(ranged.every((event) => event.timestamp >= start)).toBe(true);
    expect(
      (
        await f.iam.api.audit.list(a.credential, { tenantId: a.tenant.id, from: all[0]!.timestamp })
      ).map((event) => event.id),
    ).toContain(all[0]!.id);
    expect(
      await f.iam.api.audit.list(a.credential, { tenantId: a.tenant.id, to: start - 1 }),
    ).toEqual([]);
    const groupEvents = await f.iam.api.audit.list(a.credential, {
      tenantId: a.tenant.id,
      action: 'iam:groups:*',
    });
    expect(groupEvents.map((event) => event.outcome)).toEqual(['allow', 'deny']);
    expect(
      (
        await f.iam.api.audit.list(a.credential, {
          tenantId: a.tenant.id,
          action: 'iam:groups:*',
          limit: 1,
        })
      ).map((event) => event.id),
    ).toEqual([groupEvents[0]!.id]);
    expect(
      (
        await f.iam.api.audit.list(a.credential, {
          tenantId: a.tenant.id,
          action: 'iam:groups:*',
          limit: 1,
          offset: 1,
        })
      ).map((event) => event.id),
    ).toEqual([groupEvents[1]!.id]);
    await expect(
      f.iam.api.audit.list(a.credential, { tenantId: a.tenant.id, outcome: 'maybe' as 'allow' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
