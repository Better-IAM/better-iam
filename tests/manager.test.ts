import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('managers', () => {
  it('records reporting lines, routes approvals to the manager, and follows offboarding', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const bob = await f.iam.api.identities.create(owner, {
      tenantId,
      email: 'bob@acme.test',
      name: 'bob',
      password: 'a strong bob password',
      managerId: alice.id,
    });
    expect(bob.managerId).toBe(alice.id);
    const carol = await f.member('carol');
    await f.iam.api.identities.update(owner, { tenantId, identityId: carol.id, managerId: bob.id });
    // No cycles, no self-management, no strangers.
    await expect(
      f.iam.api.identities.update(owner, { tenantId, identityId: alice.id, managerId: carol.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.identities.update(owner, { tenantId, identityId: alice.id, managerId: alice.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.identities.update(owner, { tenantId, identityId: alice.id, managerId: 'missing' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(
      (await f.iam.api.identities.listReports(owner, { tenantId, identityId: alice.id })).map(
        (report) => report.id,
      ),
    ).toEqual([bob.id]);
    expect(
      (await f.iam.api.identities.listReports(owner, { tenantId, identityId: bob.id })).map(
        (report) => report.id,
      ),
    ).toEqual([carol.id]);
    expect(
      (await f.iam.api.identities.get(owner, { tenantId, identityId: carol.id })).managerId,
    ).toBe(bob.id);
    // Manager approval: package requests and activation requests of Carol go to Bob.
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const writer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Writer',
      permissions: ['documents:write'],
    });
    const everyone = await f.iam.api.groups.create(owner, { tenantId, name: 'Everyone' });
    const member = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:packages:request', 'iam:bindings:activate'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: member.id,
      subjectType: 'group',
      subjectId: everyone.id,
    });
    await f.iam.api.groups.addMembers(owner, {
      tenantId,
      groupId: everyone.id,
      identityIds: [alice.id, bob.id, carol.id],
    });
    const manager = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Manager',
      permissions: [
        'iam:packages:approve',
        'iam:bindings:approve',
        'iam:bindings:create',
        'iam:groups:update',
      ],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: manager.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await f.iam.api.authorities.create(owner, {
      tenantId,
      identityId: bob.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
      },
    });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
      managerApproval: true,
    });
    const asBob = { token: (await f.signIn('bob')).token };
    const asCarol = { token: (await f.signIn('carol')).token };
    const request = await f.iam.api.packages.request(asCarol, { tenantId, packageId: kit.id });
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox.filter((message) => message.template === 'package-request').map((m) => m.to),
    ).toEqual(['bob@acme.test']);
    // The owner holds the permission but is not Carol's manager; Bob is.
    await expect(
      f.iam.api.packages.approveRequest(owner, { tenantId, requestId: request.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await f.iam.api.packages.listApprovals(asBob, { tenantId })).map((item) => item.id),
    ).toEqual([request.id]);
    expect(
      (await f.iam.api.packages.listMine(asCarol, { tenantId })).packages[0]!.managerApproval,
    ).toBe(true);
    expect(
      (await f.iam.api.packages.approveRequest(asBob, { tenantId, requestId: request.id })).status,
    ).toBe('approved');
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: writer.id,
      subjectType: 'group',
      subjectId: everyone.id,
      eligible: true,
      requireApproval: true,
      managerApproval: true,
    });
    const activation = await f.iam.api.bindings.activate(asCarol, {
      tenantId,
      bindingId: eligible.id,
    });
    expect(activation.status).toBe('pending');
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox.filter((message) => message.template === 'activation-request').map((m) => m.to),
    ).toEqual(['bob@acme.test']);
    await expect(
      f.iam.api.bindings.approveActivation(owner, { tenantId, activationId: activation.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await f.iam.api.bindings.listApprovals(asBob, { tenantId })).map((item) => item.id),
    ).toEqual([activation.id]);
    expect(
      (await f.iam.api.bindings.approveActivation(asBob, { tenantId, activationId: activation.id }))
        .active,
    ).toBe(true);
    // The configuration document carries the flags.
    const exported = await f.iam.api.config.export(owner, { tenantId });
    expect(exported.packages![0]).toMatchObject({ name: 'Kit', managerApproval: true });
    expect(exported.bindings!.find((binding) => binding.role === 'Writer')).toMatchObject({
      eligible: true,
      requireApproval: true,
      managerApproval: true,
    });
    // Offboarding a manager hands their reports to the successor; without one they are left unmanaged.
    const admin = await f.ownerSignIn();
    const offboarded = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: bob.id,
      reason: 'Left',
      successorId: alice.id,
    });
    expect(offboarded).toMatchObject({ reportsReassigned: 1 });
    expect(
      (await f.iam.api.identities.get(admin, { tenantId, identityId: carol.id })).managerId,
    ).toBe(alice.id);
    expect(
      await f.iam.api.identities.offboard(admin, {
        tenantId,
        identityId: alice.id,
        reason: 'Left',
      }),
    ).toMatchObject({ reportsReassigned: 2 });
    expect(
      (await f.iam.api.identities.get(admin, { tenantId, identityId: carol.id })).managerId,
    ).toBeUndefined();
    // Clearing explicitly, and tombstoning a manager.
    await f.iam.api.identities.update(admin, {
      tenantId,
      identityId: carol.id,
      managerId: f.ownerId,
    });
    await f.iam.api.identities.update(admin, { tenantId, identityId: carol.id, managerId: null });
    expect(
      (await f.iam.api.identities.get(admin, { tenantId, identityId: carol.id })).managerId,
    ).toBeUndefined();
    expect(
      await f.iam.api.identities.listReports(admin, { tenantId, identityId: f.ownerId }),
    ).toEqual([]);
  });
});
