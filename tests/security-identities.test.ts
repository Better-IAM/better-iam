import { afterEach, describe, expect, it } from 'vitest';
import type { Identity, StoredRecord } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const everything = {
  version: 1 as const,
  statements: [{ effect: 'allow' as const, actions: ['*'], resources: ['*'] }],
};

/** Binds a new role with `permissions` to `identityId` in the fixture's organization, as the owner. */
async function grant(f: OrganizationFixture, identityId: string, permissions: string[]) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Role ${permissions.join(' ')}`,
    permissions,
  });
  const binding = await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identityId,
  });
  return { role, binding };
}

/** A member of the fixture's organization with `permissions`, and a fresh session of theirs. */
async function administrator(f: OrganizationFixture, name: string, permissions: string[]) {
  const identity = await f.member(name);
  await grant(f, identity.id, permissions);
  return { identity, credential: { token: (await f.signIn(name)).token } };
}

/** The token of the latest member invitation mailed to `to`. */
async function invitationToken(f: OrganizationFixture, to: string): Promise<string> {
  await f.iam.auth.dispatchOutbox();
  return f.inbox.filter((message) => message.template === 'member-invitation' && message.to === to).at(-1)!
    .payload.token!;
}

describe('owners are removed only by owners', () => {
  it('refuses a non-owner administrator disabling, expiring or deleting a co-owner', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const bob = await f.member('bob');
    const alice = await f.member('alice');
    await api.identities.setOwner(owner, { tenantId, identityId: bob.id, owner: true });
    const carol = await administrator(f, 'carol', [
      'iam:identities:read',
      'iam:identities:update',
      'iam:identities:delete',
    ]);

    await expect(
      api.identities.setStatus(carol.credential, { tenantId, identityId: bob.id, status: 'disabled' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    for (const expiresAt of [f.now() + 120_000, null])
      await expect(
        api.identities.update(carol.credential, { tenantId, identityId: bob.id, expiresAt }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      api.identities.delete(carol.credential, { tenantId, identityId: bob.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const stored = await f.database.get<Identity>('identities', bob.id);
    expect(stored).toMatchObject({ status: 'active', owner: true });
    expect(stored?.expiresAt).toBeUndefined();
    // The refusals are audited as denials.
    const denials = await api.audit.list(owner, { tenantId, actorId: carol.identity.id, outcome: 'deny' });
    expect(denials.length).toBeGreaterThanOrEqual(4);

    // Ordinary members are still theirs to manage.
    await expect(
      api.identities.setStatus(carol.credential, { tenantId, identityId: alice.id, status: 'disabled' }),
    ).resolves.toMatchObject({ status: 'disabled' });
    // An owner may act on a co-owner.
    await expect(
      api.identities.setStatus(owner, { tenantId, identityId: bob.id, status: 'disabled' }),
    ).resolves.toMatchObject({ status: 'disabled' });
  });

  it('keeps at least one active owner without an expiry', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const bob = await f.member('bob');
    await api.identities.setOwner(owner, { tenantId, identityId: bob.id, owner: true });
    const later = f.now() + 86_400_000;
    await expect(
      api.identities.update(owner, { tenantId, identityId: bob.id, expiresAt: later }),
    ).resolves.toMatchObject({ expiresAt: later });
    // The founder is now the last owner without an expiry.
    await expect(
      api.identities.update(owner, { tenantId, identityId: f.ownerId, expiresAt: later }),
    ).rejects.toMatchObject({ code: 'LAST_OWNER' });
    // An expiring owner's own deadline can still move.
    await expect(
      api.identities.update(owner, { tenantId, identityId: bob.id, expiresAt: later + 1000 }),
    ).resolves.toMatchObject({ expiresAt: later + 1000 });
    await api.identities.update(owner, { tenantId, identityId: bob.id, expiresAt: null });
    await expect(
      api.identities.update(owner, { tenantId, identityId: f.ownerId, expiresAt: later }),
    ).resolves.toMatchObject({ expiresAt: later });
  });
});

describe('attributes that feed birthright rules', () => {
  const withAttributes = () =>
    organizationFixture({
      permissions: {
        actions: ['documents:read', 'documents:write'],
        identityAttributes: { department: 'string' },
      },
    });

  it('refuses an administrator changing their own attributes, manager or expiry', async () => {
    const f = await withAttributes();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const alice = await f.member('alice');
    const desk = await administrator(f, 'desk', ['iam:identities:read', 'iam:identities:update']);
    const itAdmin = await api.roles.create(owner, {
      tenantId,
      name: 'IT administrators',
      permissions: ['iam:identities:delete'],
    });
    await api.packages.create(owner, {
      tenantId,
      name: 'IT department',
      roleIds: [itAdmin.id],
      autoAssign: {
        include: [{ StringEquals: { 'principal.kind': 'user', 'principal.department': 'it' } }],
      },
    });
    const self = { tenantId, identityId: desk.identity.id };

    for (const change of [
      { attributes: { department: 'it' } },
      { managerId: alice.id },
      { expiresAt: f.now() + 86_400_000 },
    ])
      await expect(api.identities.update(desk.credential, { ...self, ...change })).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
      });
    expect(
      await f.database.find<StoredRecord>('bindings', { tenantId, subjectId: desk.identity.id, roleId: itAdmin.id }),
    ).toHaveLength(0);

    // Their name is theirs to change, and re-sending attributes they already have is not a change.
    await api.identities.update(owner, { ...self, attributes: { department: 'support' } });
    await expect(
      api.identities.update(desk.credential, {
        ...self,
        name: 'Help desk',
        attributes: { department: 'support' },
      }),
    ).resolves.toMatchObject({ name: 'Help desk' });
    // Other people's attributes are what the permission is for; an owner may edit their own.
    await expect(
      api.identities.update(desk.credential, {
        tenantId,
        identityId: alice.id,
        attributes: { department: 'sales' },
      }),
    ).resolves.toMatchObject({ attributes: { department: 'sales' } });
    await expect(
      api.identities.update(owner, {
        tenantId,
        identityId: f.ownerId,
        attributes: { department: 'it' },
      }),
    ).resolves.toMatchObject({ attributes: { department: 'it' } });
  });

  it('needs iam:identities:update to choose attributes or a manager when creating identities', async () => {
    const f = await withAttributes();
    const { tenantId } = f;
    const api = f.iam.api;
    const alice = await f.member('alice');
    const hank = await administrator(f, 'hank', ['iam:identities:create']);
    await expect(
      api.identities.createMany(hank.credential, {
        tenantId,
        identities: [
          {
            email: 'sock@acme.test',
            name: 'Sock',
            password: 'a strong sock puppet password',
            attributes: { department: 'finance' },
          },
        ],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      api.identities.create(hank.credential, {
        tenantId,
        email: 'report@acme.test',
        name: 'Report',
        managerId: alice.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await f.database.find('identities', { tenantId, email: 'sock@acme.test' })).toHaveLength(0);
    // Plain creation still works, and a caller who may update identities may set them.
    await expect(
      api.identities.createMany(hank.credential, {
        tenantId,
        identities: [{ email: 'plain@acme.test', name: 'Plain' }],
      }),
    ).resolves.toMatchObject({ identities: [{ email: 'plain@acme.test' }] });
    const hr = await administrator(f, 'hr', ['iam:identities:create', 'iam:identities:update']);
    await expect(
      api.identities.createMany(hr.credential, {
        tenantId,
        identities: [{ email: 'new@acme.test', name: 'New', attributes: { department: 'finance' } }],
      }),
    ).resolves.toMatchObject({ identities: [{ attributes: { department: 'finance' } }] });
    await expect(
      api.identities.create(hr.credential, {
        tenantId,
        email: 'managed@acme.test',
        name: 'Managed',
        managerId: alice.id,
      }),
    ).resolves.toMatchObject({ managerId: alice.id });
  });
});

describe('member invitations are re-checked against the inviter at redemption', () => {
  async function inviterFixture() {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const mallory = await f.member('mallory');
    const { role, binding } = await grant(f, mallory.id, [
      'iam:identities:create',
      'iam:bindings:create',
      'iam:groups:update',
      'iam:roles:read',
    ]);
    await f.iam.api.authorities.create(owner, { tenantId, identityId: mallory.id, ceiling: everything });
    const group = await f.iam.api.groups.create(owner, { tenantId, name: 'Staff' });
    const asMallory = { token: (await f.signIn('mallory')).token };
    return { f, tenantId, owner, mallory, role, binding, group, asMallory };
  }

  it('refuses an invitation whose inviter lost the right to grant it', async () => {
    const { f, tenantId, owner, role, binding, asMallory } = await inviterFixture();
    await f.iam.api.identities.invite(asMallory, {
      tenantId,
      email: 'backup@evil.test',
      name: 'Backup',
      roleIds: [role.id],
    });
    // Demoted, though still active.
    await f.iam.api.bindings.delete(owner, { tenantId, bindingId: binding.id });
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId,
        token: await invitationToken(f, 'backup@evil.test'),
        password: 'a strong backup password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    expect(await f.database.find('identities', { tenantId, email: 'backup@evil.test' })).toHaveLength(0);
  });

  it('revokes and refuses the invitations of a disabled inviter', async () => {
    const { f, tenantId, owner, mallory, asMallory } = await inviterFixture();
    const sent = await f.iam.api.identities.invite(asMallory, { tenantId, email: 'plain@evil.test' });
    await f.iam.api.identities.setStatus(owner, { tenantId, identityId: mallory.id, status: 'disabled' });
    const listed = await f.iam.api.identities.listInvitations(owner, { tenantId });
    expect(listed.find((invitation) => invitation.id === sent.invitationId)).toMatchObject({ revoked: true });
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId,
        token: await invitationToken(f, 'plain@evil.test'),
        name: 'Plain',
        password: 'a strong plain password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
  });

  it('still applies roles and groups while the inviter may grant them', async () => {
    const { f, tenantId, role, group, asMallory } = await inviterFixture();
    await f.iam.api.identities.invite(asMallory, {
      tenantId,
      email: 'new@acme.test',
      name: 'New',
      roleIds: [role.id],
      groupIds: [group.id],
    });
    const accepted = await f.iam.api.identities.acceptInvitation({
      tenantId,
      token: await invitationToken(f, 'new@acme.test'),
      password: 'a strong new member password',
    });
    if (!('token' in accepted)) throw new Error('Unexpected MFA');
    expect(accepted.session.method).toBe('password');
    expect(
      await f.database.find('bindings', { tenantId, subjectId: accepted.identity.id, roleId: role.id }),
    ).toHaveLength(1);
    expect(
      await f.database.find('groupMembers', { tenantId, identityId: accepted.identity.id, groupId: group.id }),
    ).toHaveLength(1);
  });

  it('treats redemption as a password sign-in under the organization’s allowed methods', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    await f.iam.api.identities.invite(f.ownerCredential, { tenantId, email: 'fed@acme.test', name: 'Fed' });
    await f.iam.api.tenants.setAuthPolicy(f.rootCredential, {
      tenantId,
      authPolicy: { allowedMethods: ['federated'] },
    });
    const token = await invitationToken(f, 'fed@acme.test');
    const accept = () =>
      f.iam.api.identities.acceptInvitation({ tenantId, token, password: 'a strong federated password' });
    await expect(accept()).rejects.toMatchObject({ code: 'METHOD_NOT_ALLOWED' });
    expect(await f.database.find('identities', { tenantId, email: 'fed@acme.test' })).toHaveLength(0);
    await f.iam.api.tenants.setAuthPolicy(f.rootCredential, { tenantId, authPolicy: null });
    const accepted = await accept();
    if (!('token' in accepted)) throw new Error('Unexpected MFA');
    expect((await f.iam.api.auth.getSession({ token: accepted.token })).session.method).toBe('password');
  });

  it('records the owner invitation session as a password sign-in', async () => {
    const f = await organizationFixture();
    expect((await f.iam.api.auth.getSession(f.ownerCredential)).session.method).toBe('password');
  });
});

describe('plan limits reach child projects', () => {
  async function projectOwner(f: OrganizationFixture, projectId: string) {
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find(
      (message) => message.tenantId === projectId && message.template === 'owner-invitation',
    )!;
    const accepted = await f.iam.api.tenants.acceptInvitation({
      tenantId: projectId,
      token: invitation.payload.token!,
      name: 'Project owner',
      password: 'a strong project owner password',
    });
    if (!('token' in accepted)) throw new Error('Unexpected MFA');
    return { token: accepted.token };
  }

  it('gives a new project the stricter of its parent’s limits and the defaults', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    await f.iam.api.tenants.setLimits(f.rootCredential, {
      tenantId,
      limits: { identities: 1, serviceAccounts: 0 },
    });
    const project = await f.iam.api.tenants.create(owner, {
      parentId: tenantId,
      type: 'project',
      name: 'Overflow',
      ownerEmail: 'owner+project@acme.test',
    });
    expect(project.tenant.limits).toEqual({ identities: 1, serviceAccounts: 0 });
    const inProject = await projectOwner(f, project.tenant.id);
    await expect(
      f.iam.api.identities.create(inProject, {
        tenantId: project.tenant.id,
        email: 'member@acme.test',
        name: 'Member',
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await expect(
      f.iam.api.serviceAccounts.create(inProject, { tenantId: project.tenant.id, name: 'bot' }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
  });

  it('tightens existing projects when root tightens the organization, and never loosens them', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const project = await f.iam.api.tenants.create(owner, {
      parentId: tenantId,
      type: 'project',
      name: 'Early',
      ownerEmail: 'owner+early@acme.test',
    });
    expect(project.tenant.limits).toBeUndefined();
    const limitsOf = async (id: string) =>
      (await f.iam.api.tenants.get(f.rootCredential, { tenantId: id })).limits;
    await f.iam.api.tenants.setLimits(f.rootCredential, { tenantId, limits: { identities: 3 } });
    expect(await limitsOf(project.tenant.id)).toEqual({ identities: 3 });
    await f.iam.api.tenants.setLimits(f.rootCredential, {
      tenantId,
      limits: { identities: 10, groups: 2 },
    });
    expect(await limitsOf(project.tenant.id)).toEqual({ identities: 3, groups: 2 });
    // The root tenant's own limits are not an organization's plan.
    await f.iam.api.tenants.setLimits(f.rootCredential, {
      tenantId: f.root.tenant.id,
      limits: { groups: 50 },
    });
    const organization = await f.iam.api.tenants.create(f.rootCredential, {
      parentId: f.root.tenant.id,
      type: 'organization',
      name: 'Globex',
      ownerEmail: 'owner@globex.test',
    });
    expect(organization.tenant.limits).toBeUndefined();
  });
});

describe('root tenant and subtree controls are root’s', () => {
  async function platformStaff(f: OrganizationFixture, permissions: string[]) {
    const platformId = f.root.tenant.id;
    const staff = await f.iam.api.identities.create(f.rootCredential, {
      tenantId: platformId,
      email: 'ops@example.test',
      name: 'Ops',
      password: 'a strong platform ops password',
    });
    const role = await f.iam.api.roles.create(f.rootCredential, {
      tenantId: platformId,
      name: 'Platform operator',
      permissions,
    });
    await f.iam.api.bindings.create(f.rootCredential, {
      tenantId: platformId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: staff.id,
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: platformId,
      email: 'ops@example.test',
      password: 'a strong platform ops password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    return { platformId, credential: { token: login.token } };
  }

  it('refuses a non-root operator every change to a subtree webhook', async () => {
    const f = await organizationFixture();
    const { platformId, credential: ops } = await platformStaff(f, [
      'iam:webhooks:read',
      'iam:webhooks:update',
      'iam:webhooks:delete',
      'iam:webhooks:create',
    ]);
    const subtree = await f.iam.api.webhooks.create(f.rootCredential, {
      tenantId: platformId,
      url: 'https://siem.platform.test/ingest',
      events: ['iam:groups:*'],
      scope: 'subtree',
    });
    const target = { tenantId: platformId, webhookId: subtree.webhook.id };
    for (const attempt of [
      () => f.iam.api.webhooks.update(ops, { ...target, url: 'https://attacker.example.test/collect' }),
      () => f.iam.api.webhooks.rotateSecret(ops, target),
      () => f.iam.api.webhooks.ping(ops, target),
      () => f.iam.api.webhooks.redeliver(ops, { ...target, deliveryId: 'any' }),
      () => f.iam.api.webhooks.delete(ops, target),
    ])
      await expect(attempt()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await f.iam.api.webhooks.get(f.rootCredential, target)).url).toBe(
      'https://siem.platform.test/ingest',
    );
    // Their own tenant-scoped subscriptions stay theirs to manage; root may change the subtree one.
    const own = await f.iam.api.webhooks.create(ops, {
      tenantId: platformId,
      url: 'https://ops.platform.test/hook',
      events: ['iam:roles:*'],
    });
    await expect(
      f.iam.api.webhooks.update(ops, {
        tenantId: platformId,
        webhookId: own.webhook.id,
        description: 'ops',
      }),
    ).resolves.toMatchObject({ description: 'ops' });
    await expect(
      f.iam.api.webhooks.update(f.rootCredential, { ...target, description: 'siem' }),
    ).resolves.toMatchObject({ description: 'siem' });
  });

  it('keeps the root tenant’s sign-in policy, sessions and network blocks for root', async () => {
    const f = await organizationFixture();
    const { platformId, credential: ops } = await platformStaff(f, [
      'iam:tenants:read',
      'iam:tenants:update',
      'iam:security:manage',
      'iam:security:read',
    ]);
    await expect(
      f.iam.api.tenants.setAuthPolicy(ops, {
        tenantId: platformId,
        authPolicy: { allowedIpRanges: ['198.51.100.7/32'] },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(f.iam.api.tenants.revokeSessions(ops, { tenantId: platformId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      f.iam.api.security.blockNetwork(ops, {
        tenantId: platformId,
        network: '192.0.2.0/24',
        reason: 'root admins sit here',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await f.iam.api.tenants.get(f.rootCredential, { tenantId: platformId })).authPolicy).toBeUndefined();
    // Root still can, and an organization's owner still governs their own organization.
    const block = await f.iam.api.security.blockNetwork(f.rootCredential, {
      tenantId: platformId,
      network: '192.0.2.0/24',
      reason: 'scanner',
    });
    await expect(
      f.iam.api.security.unblockNetwork(ops, { tenantId: platformId, blockId: block.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.api.security.unblockNetwork(f.rootCredential, { tenantId: platformId, blockId: block.id });
    await expect(
      f.iam.api.tenants.setAuthPolicy(f.rootCredential, {
        tenantId: platformId,
        authPolicy: { maxAttempts: 100 },
      }),
    ).resolves.toMatchObject({ authPolicy: { maxAttempts: 100 } });
    await expect(
      f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
        tenantId: f.tenantId,
        authPolicy: { maxAttempts: 100 },
      }),
    ).resolves.toMatchObject({ authPolicy: { maxAttempts: 100 } });
    await expect(
      f.iam.api.tenants.revokeSessions(f.rootCredential, { tenantId: platformId }),
    ).resolves.toMatchObject({ revoked: expect.any(Number) });
  });
});

describe('scoped API keys issue only keys within their scopes', () => {
  async function keyFixture() {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const account = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'deployer' });
    await grant(f, account.id, ['iam:credentials:create', 'documents:read']);
    await f.iam.api.authorities.create(owner, { tenantId, identityId: account.id, ceiling: everything });
    const scoped = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: account.id,
      scopes: ['iam:credentials:*'],
    });
    const reads = (token: string) =>
      f.iam.authorize({ token, tenantId, action: 'documents:read', resource: { type: 'document', id: 'd' } });
    return { f, tenantId, owner, account, scoped: { token: scoped.token }, reads };
  }

  it('passes its scopes on and refuses anything broader', async () => {
    const { f, tenantId, owner, account, scoped, reads } = await keyFixture();
    const inherited = await f.iam.api.credentials.create(scoped, { tenantId, identityId: account.id });
    expect(
      (await f.iam.api.credentials.get(owner, { tenantId, credentialId: inherited.credentialId })).scopes,
    ).toEqual(['iam:credentials:*']);
    expect((await reads(inherited.token)).allowed).toBe(false);
    for (const extra of [
      { scopes: ['documents:read'] },
      { scopes: ['iam:*'] },
      { scopes: ['iam:credentials:create', 'documents:read'] },
      { policy: everything },
    ])
      await expect(
        f.iam.api.credentials.create(scoped, { tenantId, identityId: account.id, ...extra }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Narrower scopes are fine.
    const narrower = await f.iam.api.credentials.create(scoped, {
      tenantId,
      identityId: account.id,
      scopes: ['iam:credentials:create'],
    });
    expect(
      (await f.iam.api.credentials.get(owner, { tenantId, credentialId: narrower.credentialId })).scopes,
    ).toEqual(['iam:credentials:create']);
  });

  it('refuses rotating a broader key, while unscoped keys keep minting freely', async () => {
    const { f, tenantId, owner, account, scoped, reads } = await keyFixture();
    const unscoped = await f.iam.api.credentials.create(owner, { tenantId, identityId: account.id });
    // An unscoped key of the account issues any key the account may have.
    const minted = await f.iam.api.credentials.create(
      { token: unscoped.token },
      { tenantId, identityId: account.id },
    );
    expect((await reads(minted.token)).allowed).toBe(true);
    await expect(
      f.iam.api.credentials.rotate(scoped, { tenantId, credentialId: minted.credentialId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED', message: expect.stringContaining('scopes') });
    expect((await reads(minted.token)).allowed).toBe(true);
  });
});

describe('ownership removal', () => {
  const authoritiesOf = (f: OrganizationFixture, identityId: string) =>
    f.database.find<StoredRecord & { revoked: boolean }>('grantAuthorities', {
      tenantId: f.tenantId,
      identityId,
      revoked: false,
    });

  it('takes the owner grant authority from a demoted owner and keeps what they granted', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const bob = await f.member('bob');
    const alice = await f.member('alice');
    await api.identities.setOwner(owner, { tenantId, identityId: bob.id, owner: true });
    const asBob = { token: (await f.signIn('bob')).token };
    const readers = await api.roles.create(asBob, { tenantId, name: 'Readers', permissions: ['documents:read'] });
    await api.bindings.create(asBob, { tenantId, roleId: readers.id, subjectType: 'identity', subjectId: alice.id });
    expect(await authoritiesOf(f, bob.id)).toHaveLength(1);

    await api.identities.setOwner(owner, { tenantId, identityId: bob.id, owner: false });
    expect(await authoritiesOf(f, bob.id)).toHaveLength(0);
    const aliceToken = (await f.signIn('alice')).token;
    expect(
      (
        await f.iam.authorize({
          token: aliceToken,
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'd' },
        })
      ).allowed,
    ).toBe(true);
    // Bob keeps an administrator role but no longer grants under the ownership he gave up.
    await grant(f, bob.id, ['iam:bindings:create', 'iam:roles:read']);
    await expect(
      api.bindings.create({ token: (await f.signIn('bob')).token }, {
        tenantId,
        roleId: readers.id,
        subjectType: 'identity',
        subjectId: bob.id,
      }),
    ).rejects.toMatchObject({ code: 'GRANT_AUTHORITY_REQUIRED' });
  });

  it('leaves the remaining owner in charge when the founder steps down', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: founder } = f;
    const api = f.iam.api;
    const bob = await f.member('bob');
    const alice = await f.member('alice');
    const readers = await api.roles.create(founder, { tenantId, name: 'Readers', permissions: ['documents:read'] });
    await api.bindings.create(founder, { tenantId, roleId: readers.id, subjectType: 'identity', subjectId: alice.id });
    await api.identities.setOwner(founder, { tenantId, identityId: bob.id, owner: true });
    const asBob = { token: (await f.signIn('bob')).token };
    await api.identities.setOwner(asBob, { tenantId, identityId: f.ownerId, owner: false });
    expect(await authoritiesOf(f, f.ownerId)).toHaveLength(0);
    // Bob's ownership (granted through the founder's authority) and the founder's grants keep working.
    await expect(api.groups.create(asBob, { tenantId, name: 'After' })).resolves.toMatchObject({ name: 'After' });
    const decision = await f.iam.authorize({
      token: (await f.signIn('alice')).token,
      tenantId,
      action: 'documents:read',
      resource: { type: 'document', id: 'd' },
    });
    expect(decision.allowed).toBe(true);
  });
});

describe('agents keep their own status rules', () => {
  it('refuses identities.setStatus on an agent', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const alice = await f.member('alice');
    const agent = await f.iam.api.agents.create(owner, { tenantId, name: 'Agent', sponsorId: alice.id });
    await f.iam.api.agents.suspend(owner, { tenantId, agentId: agent.id, reason: 'incident' });
    for (const status of ['active', 'disabled'] as const)
      await expect(
        f.iam.api.identities.setStatus(owner, { tenantId, identityId: agent.id, status }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: expect.stringContaining('agents.resume') });
    expect((await f.iam.api.agents.get(owner, { tenantId, agentId: agent.id })).standing).toBe('suspended');
  });
});

describe('claimed domains and hostnames reveal nothing before authorization', () => {
  async function claimsFixture() {
    const dns = new Map<string, string[][]>();
    const lookups: string[] = [];
    const f = await organizationFixture({
      hosts: { patterns: ['{tenant}.localhost:3000'], customHostnames: true },
      domains: {
        resolveTxt: async (name) => {
          lookups.push(name);
          const records = dns.get(name);
          if (!records) throw Object.assign(new Error('ENOTFOUND'), { code: 'ENOTFOUND' });
          return records;
        },
      },
    });
    const outsider = await administrator(f, 'outsider', ['documents:read']);
    return { f, dns, lookups, outsider: outsider.credential };
  }

  it('answers an unauthorized caller the same for a real and a made-up domain', async () => {
    const { f, dns, lookups, outsider } = await claimsFixture();
    const { tenantId, ownerCredential: owner } = f;
    const claim = await f.iam.api.domains.add(owner, { tenantId, domain: 'acme.example' });
    dns.set(claim.dnsRecord.name, [[claim.dnsRecord.value]]);
    for (const domainId of [claim.id, 'no-such-claim']) {
      await expect(f.iam.api.domains.delete(outsider, { tenantId, domainId })).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
      });
      await expect(f.iam.api.domains.verify(outsider, { tenantId, domainId })).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
      });
    }
    // Refused callers never trigger a DNS query.
    expect(lookups).toEqual([]);
    // The owner still verifies and deletes; a made-up ID is simply not found for them.
    await expect(f.iam.api.domains.verify(owner, { tenantId, domainId: claim.id })).resolves.toMatchObject({
      verified: true,
    });
    await expect(
      f.iam.api.domains.delete(owner, { tenantId, domainId: 'no-such-claim' }),
    ).rejects.toMatchObject({ status: 404 });
    await expect(f.iam.api.domains.delete(owner, { tenantId, domainId: claim.id })).resolves.toEqual({
      deleted: true,
    });
  });

  it('answers an unauthorized caller the same for a real and a made-up hostname', async () => {
    const { f, dns, lookups, outsider } = await claimsFixture();
    const { tenantId, ownerCredential: owner } = f;
    const claim = await f.iam.api.hostnames.add(owner, { tenantId, hostname: 'login.acme.test' });
    dns.set(claim.dnsRecords.verification.name, [[claim.dnsRecords.verification.value]]);
    for (const hostnameId of [claim.id, 'no-such-claim']) {
      for (const attempt of [
        () => f.iam.api.hostnames.verify(outsider, { tenantId, hostnameId }),
        () => f.iam.api.hostnames.setPrimary(outsider, { tenantId, hostnameId }),
        () => f.iam.api.hostnames.delete(outsider, { tenantId, hostnameId }),
      ])
        await expect(attempt()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    }
    expect(lookups).toEqual([]);
    await expect(
      f.iam.api.hostnames.verify(owner, { tenantId, hostnameId: claim.id }),
    ).resolves.toMatchObject({ verified: true });
    await expect(
      f.iam.api.hostnames.setPrimary(owner, { tenantId, hostnameId: claim.id }),
    ).resolves.toMatchObject({ primary: { hostname: 'login.acme.test', primary: true } });
    await expect(
      f.iam.api.hostnames.setPrimary(owner, { tenantId, hostnameId: 'no-such-claim' }),
    ).rejects.toMatchObject({ status: 404 });
    await expect(f.iam.api.hostnames.delete(owner, { tenantId, hostnameId: claim.id })).resolves.toEqual({
      deleted: true,
    });
  });
});
