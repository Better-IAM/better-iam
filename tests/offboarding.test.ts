import { afterEach, describe, expect, it } from 'vitest';
import type { GrantAuthority } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('offboarding', () => {
  it('removes every access an identity holds in one transaction and hands its resources to a successor', async () => {
    const f = await organizationFixture({
      permissions: {
        actions: ['documents:read', 'documents:write'],
        resourceTypes: {
          workspace: { managed: true, actions: ['workspaces:read'], relations: ['viewer'] },
        },
      },
    });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const editor = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Editor',
      permissions: ['documents:write'],
    });
    const member = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:bindings:activate', 'iam:access-requests:create'],
    });
    const auditor = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Auditor',
      permissions: ['iam:audit:read'],
    });
    const engineering = await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: engineering.id,
      identityId: alice.id,
    });
    for (const roleId of [editor.id, member.id])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId,
        subjectType: 'identity',
        subjectId: alice.id,
      });
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: auditor.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
    });
    await f.iam.api.resources.register(owner, {
      tenantId,
      type: 'workspace',
      id: 'roadmap',
      ownerId: alice.id,
    });
    await f.iam.api.relationships.create(owner, {
      tenantId,
      type: 'workspace',
      id: 'roadmap',
      relation: 'viewer',
      subjectType: 'identity',
      subjectId: alice.id,
    });
    await f.iam.api.authorities.create(owner, {
      tenantId,
      identityId: alice.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: eligible.id });
    const request = await f.iam.api.accessRequests.create(asAlice, {
      tenantId,
      roleIds: [editor.id],
      justification: 'need it',
    });
    // Validation and protections.
    const offboard = (input: Record<string, unknown>) =>
      f.iam.api.identities.offboard(owner, {
        tenantId,
        identityId: alice.id,
        reason: 'left the company',
        ...input,
      });
    await expect(offboard({ reason: '' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(offboard({ successorId: alice.id })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(offboard({ identityId: f.ownerId })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(
      f.iam.api.identities.offboard(asAlice, {
        tenantId,
        identityId: bob.id,
        reason: 'no permission',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const result = await offboard({ successorId: bob.id });
    expect(result).toMatchObject({
      sessions: 1,
      bindings: 3,
      memberships: 1,
      activations: 1,
      relationships: 1,
      accessRequests: 1,
      authorities: 1,
      resourcesReassigned: 1,
      resourcesOwned: 0,
    });
    expect(result.identity.status).toBe('disabled');
    // Everything is gone and the session no longer works.
    await expect(
      f.iam.authorize({
        ...asAlice,
        tenantId,
        action: 'documents:write',
        resource: { type: 'documents', id: 'a' },
      }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(await f.iam.api.bindings.list(owner, { tenantId, subjectId: alice.id })).toEqual([]);
    expect(
      await f.iam.api.groups.listMembers(owner, { tenantId, groupId: engineering.id }),
    ).toEqual([]);
    expect(
      await f.iam.api.bindings.listActivations(owner, { tenantId, identityId: alice.id }),
    ).toEqual([]);
    expect(
      await f.iam.api.relationships.list(owner, {
        tenantId,
        subjectType: 'identity',
        subjectId: alice.id,
      }),
    ).toEqual([]);
    expect(
      (await f.iam.api.accessRequests.get(owner, { tenantId, requestId: request.id })).status,
    ).toBe('cancelled');
    expect(
      (
        await f.database.find<GrantAuthority>('grantAuthorities', {
          tenantId,
          identityId: alice.id,
        })
      ).every((authority) => authority.revoked),
    ).toBe(true);
    expect(
      (await f.iam.api.resources.get(owner, { tenantId, type: 'workspace', id: 'roadmap' }))
        .ownerId,
    ).toBe(bob.id);
    const trail = await f.iam.api.audit.list(owner, { tenantId, action: 'identity:offboard' });
    expect(trail[0]).toMatchObject({
      actorId: f.ownerId,
      resourceId: alice.id,
      metadata: { reason: 'left the company', successorId: bob.id, bindings: 3 },
    });
    // Offboarding is not deletion: the record stays for retention, and can be tombstoned later.
    expect((await f.iam.api.identities.get(owner, { tenantId, identityId: alice.id })).status).toBe(
      'disabled',
    );
    // Running it again is harmless: nothing is left to remove.
    expect(await offboard({})).toMatchObject({ bindings: 0, memberships: 0, sessions: 0 });
    expect(
      (await f.iam.api.identities.delete(owner, { tenantId, identityId: alice.id })).status,
    ).toBe('deleted');
  });

  it('protects owners and the last owner, and leaves resources without a successor in place', async () => {
    const f = await organizationFixture({
      permissions: {
        actions: ['documents:read'],
        resourceTypes: { workspace: { managed: true, actions: ['workspaces:read'] } },
      },
    });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    await f.iam.api.identities.setOwner(owner, { tenantId, identityId: bob.id, owner: true });
    await f.iam.api.resources.register(owner, {
      tenantId,
      type: 'workspace',
      id: 'ops',
      ownerId: bob.id,
    });
    // A plain administrator may not offboard an owner.
    const admin = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Admin',
      permissions: ['iam:identities:update', 'iam:identities:read'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: admin.id,
      subjectType: 'identity',
      subjectId: carol.id,
    });
    const asCarol = { token: (await f.signIn('carol')).token };
    await expect(
      f.iam.api.identities.offboard(asCarol, { tenantId, identityId: bob.id, reason: 'x' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // An owner may, and the co-owner's resources stay behind for reassignment.
    const result = await f.iam.api.identities.offboard(owner, {
      tenantId,
      identityId: bob.id,
      reason: 'resigned',
    });
    expect(result).toMatchObject({ bindings: 1, resourcesOwned: 1, resourcesReassigned: 0 });
    expect(result.identity.owner).toBe(false);
    expect(
      (await f.iam.api.resources.get(owner, { tenantId, type: 'workspace', id: 'ops' })).ownerId,
    ).toBe(bob.id);
    // The offboarded owner cannot sign in; the last owner cannot be offboarded.
    await expect(
      f.iam.api.auth.signIn({
        tenantId,
        email: 'bob@acme.test',
        password: 'a strong bob password',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(
      f.iam.api.identities.offboard(asCarol, { tenantId, identityId: f.ownerId, reason: 'x' }),
    ).rejects.toMatchObject({ code: 'LAST_OWNER' });
  });
});
