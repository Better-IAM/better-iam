import { afterEach, describe, expect, it } from 'vitest';
import type { StoredRecord } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization';

afterEach(closeFixtures);

/**
 * Support staff who may "view as" a broader administrator. Support can create people and review requests, and may
 * create bindings, but only under a documents:read ceiling; the administrator can grant anything in iam:*.
 */
async function viewAsBroaderAdmin() {
  const f = await organizationFixture();
  const { tenantId, ownerCredential: owner } = f;
  const api = f.iam.api;
  await api.tenants.setAuthPolicy(owner, { tenantId, authPolicy: { allowImpersonation: true } });
  const support = await f.member('support');
  const admin = await f.member('admin');
  const supportRole = await api.roles.create(owner, {
    tenantId,
    name: 'Support',
    permissions: [
      'iam:identities:read',
      'iam:identities:impersonate',
      'iam:identities:create',
      'iam:bindings:create',
      'iam:roles:read',
      'iam:access-requests:create',
      'iam:access-requests:review',
    ],
  });
  const admins = await api.roles.create(owner, {
    tenantId,
    name: 'Admins',
    permissions: [
      'iam:bindings:create',
      'iam:identities:read',
      'iam:identities:create',
      'iam:identities:update',
      'iam:groups:update',
      'iam:access-requests:review',
      'iam:roles:read',
    ],
  });
  for (const [roleId, subjectId] of [
    [supportRole.id, support.id],
    [admins.id, admin.id],
  ] as const)
    await api.bindings.create(owner, { tenantId, roleId, subjectType: 'identity', subjectId });
  const ownerFresh = await f.ownerSignIn();
  await api.authorities.create(ownerFresh, {
    tenantId,
    identityId: support.id,
    ceiling: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
    },
  });
  await api.authorities.create(ownerFresh, {
    tenantId,
    identityId: admin.id,
    ceiling: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['iam:*'], resources: ['*'] }],
    },
  });
  const supportLogin = { token: (await f.signIn('support')).token };
  const viewAs = await api.identities.impersonate(supportLogin, {
    tenantId,
    identityId: admin.id,
    reason: 'ticket 42',
  });
  const bindingsOf = (subjectId: string) =>
    f.database.find<StoredRecord>('bindings', { tenantId, subjectId, roleId: admins.id });
  return {
    f,
    api,
    tenantId,
    support,
    admin,
    admins,
    supportLogin,
    viewAs: { token: viewAs.token },
    bindingsOf,
  };
}

describe('view-as sessions never spend the member’s grant authority', () => {
  it('refuses a binding under the member’s authority even when both may create bindings', async () => {
    const { api, tenantId, support, admins, viewAs, bindingsOf } = await viewAsBroaderAdmin();
    await expect(
      api.bindings.create(viewAs, {
        tenantId,
        roleId: admins.id,
        subjectType: 'identity',
        subjectId: support.id,
      }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    expect(await bindingsOf(support.id)).toHaveLength(0);
  });

  it('refuses creating people with roles through the member’s session', async () => {
    const { f, api, tenantId, admins, viewAs } = await viewAsBroaderAdmin();
    await expect(
      api.identities.createMany(viewAs, {
        tenantId,
        identities: [
          {
            email: 'sock@acme.test',
            name: 'Sock',
            password: 'a strong sock puppet password',
            roleIds: [admins.id],
          },
        ],
      }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    expect(
      await f.database.find<StoredRecord>('identities', { tenantId, email: 'sock@acme.test' }),
    ).toHaveLength(0);
  });

  it('applies the administrator’s own rights to checks an operation makes on the side', async () => {
    const { f, api, tenantId, viewAs } = await viewAsBroaderAdmin();
    // The member may change this group; the support administrator may not. The group grants nothing, so no grant
    // authority is involved: only the nested iam:groups:update decision stands between support and membership.
    const approvers = await api.groups.create(f.ownerCredential, { tenantId, name: 'Approvers' });
    await expect(
      api.identities.createMany(viewAs, {
        tenantId,
        identities: [
          {
            email: 'sock@acme.test',
            name: 'Sock',
            password: 'a strong sock puppet password',
            groupIds: [approvers.id],
          },
        ],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await f.database.find<StoredRecord>('groupMembers', { tenantId, groupId: approvers.id }),
    ).toHaveLength(0);
  });

  it('refuses deciding access requests while impersonating', async () => {
    const { api, tenantId, support, admins, supportLogin, viewAs, bindingsOf } =
      await viewAsBroaderAdmin();
    const request = await api.accessRequests.create(supportLogin, {
      tenantId,
      roleIds: [admins.id],
    });
    await expect(
      api.accessRequests.approve(viewAs, { tenantId, requestId: request.id }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    await expect(
      api.accessRequests.deny(viewAs, { tenantId, requestId: request.id }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    expect(await bindingsOf(support.id)).toHaveLength(0);
  });

  it('refuses lengthening or removing a binding the member issued', async () => {
    const { f, api, tenantId, support, admins, viewAs, bindingsOf } = await viewAsBroaderAdmin();
    const adminLogin = { token: (await f.signIn('admin')).token };
    const temporary = await api.bindings.create(adminLogin, {
      tenantId,
      roleId: admins.id,
      subjectType: 'identity',
      subjectId: support.id,
      expiresAt: f.now() + 3_600_000,
    });
    await expect(
      api.bindings.update(viewAs, { tenantId, bindingId: temporary.id, expiresAt: null }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      api.bindings.delete(viewAs, { tenantId, bindingId: temporary.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await bindingsOf(support.id)).toMatchObject([{ expiresAt: temporary.expiresAt }]);
    // The member's own session still manages what they granted.
    await api.bindings.update(adminLogin, { tenantId, bindingId: temporary.id, expiresAt: null });
  });

  it('leaves the member’s own session able to grant under their authority', async () => {
    const { f, api, tenantId, admins, bindingsOf } = await viewAsBroaderAdmin();
    const colleague = await f.member('colleague');
    const adminLogin = { token: (await f.signIn('admin')).token };
    await api.bindings.create(adminLogin, {
      tenantId,
      roleId: admins.id,
      subjectType: 'identity',
      subjectId: colleague.id,
    });
    expect(await bindingsOf(colleague.id)).toHaveLength(1);
  });
});
