import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, Identity, StoredRecord } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const documents = {
  permissions: {
    actions: ['documents:read', 'documents:write'],
    resourceTypes: {
      document: { managed: true, actions: ['documents:read', 'documents:write'] },
    },
  },
};

describe('impersonation never exceeds the administrator', () => {
  it('allows a view-as session only what both the member and the impersonator may do', async () => {
    const f = await organizationFixture(documents);
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    await api.tenants.setAuthPolicy(owner, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const support = await f.member('support');
    const admin = await f.member('admin');
    const supportRole = await api.roles.create(owner, {
      tenantId,
      name: 'Support',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:identities:read', 'iam:identities:impersonate'],
            resources: ['*'],
          },
          { effect: 'allow', actions: ['documents:read'], resources: ['document/public-*'] },
        ],
      },
    });
    const admins = await api.roles.create(owner, {
      tenantId,
      name: 'Admins',
      permissions: [
        'iam:bindings:create',
        'iam:identities:update',
        'iam:identities:read',
        'iam:roles:read',
        'documents:read',
      ],
    });
    for (const [roleId, subjectId] of [
      [supportRole.id, support.id],
      [admins.id, admin.id],
    ] as const)
      await api.bindings.create(owner, { tenantId, roleId, subjectType: 'identity', subjectId });
    // The administrator may grant under a delegated authority of their own.
    await api.authorities.create(owner, {
      tenantId,
      identityId: admin.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['iam:*'], resources: ['*'] }],
      },
    });
    await api.resources.registerMany(owner, {
      tenantId,
      resources: [
        { type: 'document', id: 'public-handbook' },
        { type: 'document', id: 'salaries' },
      ],
    });
    const supportLogin = await f.signIn('support');
    const grantAdmins = (token: string) =>
      api.bindings.create(
        { token },
        { tenantId, roleId: admins.id, subjectType: 'identity', subjectId: support.id },
      );
    await expect(grantAdmins(supportLogin.token)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const viewAs = await api.identities.impersonate(
      { token: supportLogin.token },
      { tenantId, identityId: admin.id, reason: 'ticket 9' },
    );
    // The administrator's session cannot be borrowed to grant support their role.
    await expect(grantAdmins(viewAs.token)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const granted = await f.database.find<StoredRecord>('bindings', {
      tenantId,
      subjectId: support.id,
      roleId: admins.id,
    });
    expect(granted).toHaveLength(0);
    const denials = (await f.database.find<AuditEvent>('audit', { tenantId })).filter(
      (event) =>
        event.action === 'iam:bindings:create' &&
        event.outcome === 'deny' &&
        event.actorId === admin.id &&
        event.impersonatorId === support.id,
    );
    expect(denials).toHaveLength(1);
    await expect(
      api.identities.update(
        { token: viewAs.token },
        { tenantId, identityId: support.id, name: 'Promoted' },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // What both may do still works, and advisory checks agree with enforcement.
    expect(
      (await api.identities.get({ token: viewAs.token }, { tenantId, identityId: support.id })).id,
    ).toBe(support.id);
    const iamCheck = (action: string) => ({ action, resource: { type: 'iam', id: support.id } });
    expect(
      (
        await f.iam.authorize({
          token: viewAs.token,
          tenantId,
          ...iamCheck('iam:identities:update'),
        })
      ).allowed,
    ).toBe(false);
    const batch = await f.iam.authorizeMany({
      token: viewAs.token,
      tenantId,
      checks: [iamCheck('iam:identities:read'), iamCheck('iam:identities:update')],
    });
    expect(batch.results.map((result) => result.allowed)).toEqual([true, false]);
    const readable = await f.iam.listAccessible({
      token: viewAs.token,
      tenantId,
      action: 'documents:read',
      type: 'document',
    });
    expect(readable.resources.map((resource) => resource.resourceId)).toEqual(['public-handbook']);

    // The administrator's own session keeps every right the role gives.
    const adminLogin = await f.signIn('admin');
    expect(
      (
        await f.iam.authorize({
          token: adminLogin.token,
          tenantId,
          ...iamCheck('iam:identities:update'),
        })
      ).allowed,
    ).toBe(true);
    expect(
      (
        await f.iam.listAccessible({
          token: adminLogin.token,
          tenantId,
          action: 'documents:read',
          type: 'document',
        })
      ).total,
    ).toBe(2);
  });
});

describe('owners and root administrators', () => {
  it('cannot have their sign-in address changed or a reset sent by an ordinary administrator', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner, ownerId } = f;
    const api = f.iam.api;
    const helpdesk = await f.member('helpdesk');
    const alice = await f.member('alice');
    const role = await api.roles.create(owner, {
      tenantId,
      name: 'Helpdesk',
      permissions: ['iam:identities:read', 'iam:identities:update'],
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: helpdesk.id,
    });
    const desk = { token: (await f.signIn('helpdesk')).token };
    const resets = async (identityId: string) =>
      (
        await f.database.find<StoredRecord>('authChallenges', {
          identityId,
          purpose: 'password-reset',
        })
      ).length;

    await expect(
      api.identities.update(desk, { tenantId, identityId: ownerId, email: 'evil@attacker.test' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED', message: expect.stringContaining('owner') });
    await expect(
      api.identities.requestPasswordReset(desk, { tenantId, identityId: ownerId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const stored = await f.database.get<Identity>('identities', ownerId);
    expect(stored?.email).toBe('owner@acme.test');
    expect(await resets(ownerId)).toBe(0);
    // Both refusals are in the trail as denials by the helpdesk account.
    const denials = (await f.database.find<AuditEvent>('audit', { tenantId })).filter(
      (event) =>
        event.actorId === helpdesk.id &&
        event.outcome === 'deny' &&
        event.action === 'iam:identities:update' &&
        event.resourceId === ownerId,
    );
    expect(denials).toHaveLength(2);
    // The owner's session is untouched.
    expect((await api.auth.getSession(owner)).identity.id).toBe(ownerId);

    // Ordinary members are still the helpdesk's to manage.
    expect(
      (await api.identities.update(desk, { tenantId, identityId: alice.id, email: 'al@acme.test' }))
        .email,
    ).toBe('al@acme.test');
    expect(
      await api.identities.requestPasswordReset(desk, { tenantId, identityId: alice.id }),
    ).toEqual({ queued: true, email: 'al@acme.test' });

    // An owner (here, for themselves) and a root administrator may.
    expect(
      await api.identities.requestPasswordReset(owner, { tenantId, identityId: ownerId }),
    ).toMatchObject({ queued: true });
    expect(
      await api.identities.requestPasswordReset(f.rootCredential, {
        tenantId,
        identityId: ownerId,
      }),
    ).toMatchObject({ queued: true });
    expect(await resets(ownerId)).toBe(2);
    expect(
      (
        await api.identities.update(owner, {
          tenantId,
          identityId: ownerId,
          email: 'owner.new@acme.test',
        })
      ).email,
    ).toBe('owner.new@acme.test');

    // A root administrator's address is only a root administrator's to change.
    const rootTenant = f.root.tenant.id;
    const rootAdmin = (
      await f.database.find<Identity>('identities', { tenantId: rootTenant, rootAdmin: true })
    )[0]!;
    const operator = await api.identities.create(f.rootCredential, {
      tenantId: rootTenant,
      email: 'operator@example.test',
      name: 'Operator',
      password: 'a strong operator password',
    });
    const operatorRole = await api.roles.create(f.rootCredential, {
      tenantId: rootTenant,
      name: 'Operators',
      permissions: ['iam:identities:read', 'iam:identities:update'],
    });
    await api.bindings.create(f.rootCredential, {
      tenantId: rootTenant,
      roleId: operatorRole.id,
      subjectType: 'identity',
      subjectId: operator.id,
    });
    const operatorLogin = await api.auth.signIn({
      tenantId: rootTenant,
      email: 'operator@example.test',
      password: 'a strong operator password',
    });
    if (!('token' in operatorLogin)) throw new Error('Unexpected MFA');
    await expect(
      api.identities.update(
        { token: operatorLogin.token },
        { tenantId: rootTenant, identityId: rootAdmin.id, email: 'evil@attacker.test' },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED', message: expect.stringContaining('root') });
    await expect(
      api.identities.requestPasswordReset(
        { token: operatorLogin.token },
        { tenantId: rootTenant, identityId: rootAdmin.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await f.database.get<Identity>('identities', rootAdmin.id))?.email).toBe(
      'root@example.test',
    );
  });
});
