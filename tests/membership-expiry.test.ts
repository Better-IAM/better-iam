import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('temporary group memberships', () => {
  it('end by themselves, drop the group’s grants and activations, and are swept by the worker', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const project = await f.iam.api.groups.create(owner, { tenantId, name: 'Project X' });
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'group',
      subjectId: project.id,
    });
    await expect(
      f.iam.api.groups.addMember(owner, {
        tenantId,
        groupId: project.id,
        identityId: alice.id,
        expiresAt: f.now() - 1,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const membership = await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: alice.id,
      expiresAt: f.now() + 2 * day,
    });
    expect(membership.expiresAt).toBe(f.now() + 2 * day);
    await expect(
      f.iam.api.groups.addMember(owner, { tenantId, groupId: project.id, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const asAlice = { token: (await f.signIn('alice')).token };
    const can = async () =>
      (
        await f.iam.authorize({
          ...asAlice,
          tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed;
    expect(await can()).toBe(true);
    expect(
      (await f.iam.api.groups.listMembers(owner, { tenantId, groupId: project.id })).map(
        (member) => [member.id, member.membershipExpiresAt],
      ),
    ).toEqual([[alice.id, f.now() + 2 * day]]);
    expect(
      (await f.iam.api.identities.listGroups(owner, { tenantId, identityId: alice.id })).map(
        (group) => group.membershipExpiresAt,
      ),
    ).toEqual([f.now() + 2 * day]);
    // Extending, then letting it lapse.
    const extended = await f.iam.api.groups.updateMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: alice.id,
      expiresAt: f.now() + 3 * day,
    });
    expect(extended.expiresAt).toBe(f.now() + 3 * day);
    const report = await f.iam.api.reports.access(owner, { tenantId, withinMs: 7 * day });
    expect(report.bindings!.expiringMemberships).toEqual([
      expect.objectContaining({ groupName: 'Project X', identityName: 'alice' }),
    ]);
    f.advance(3 * day + 1);
    expect(await can()).toBe(false);
    expect(await f.iam.api.groups.listMembers(owner, { tenantId, groupId: project.id })).toEqual(
      [],
    );
    expect(
      await f.iam.api.identities.listGroups(owner, { tenantId, identityId: alice.id }),
    ).toEqual([]);
    expect(
      (await f.iam.api.identities.listBindings(owner, { tenantId, identityId: alice.id })).map(
        (binding) => binding.roleId,
      ),
    ).toEqual([]);
    // Re-adding a lapsed member renews the membership; clearing the expiry makes it permanent.
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: alice.id,
    });
    expect(await can()).toBe(true);
    await f.iam.api.groups.updateMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    const permanent = await f.iam.api.groups.updateMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: alice.id,
      expiresAt: null,
    });
    expect(permanent.expiresAt).toBeUndefined();
    await expect(
      f.iam.api.groups.updateMember(owner, {
        tenantId,
        groupId: project.id,
        identityId: f.ownerId,
        expiresAt: null,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // The purge worker removes lapsed memberships and the activations they carried.
    const bob = await f.member('bob');
    const member = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:bindings:activate'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: member.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const writer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Writer',
      permissions: ['documents:write'],
    });
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: writer.id,
      subjectType: 'group',
      subjectId: project.id,
      eligible: true,
    });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: bob.id,
      expiresAt: f.now() + 60_000,
    });
    const asBob = { token: (await f.signIn('bob')).token };
    await f.iam.api.bindings.activate(asBob, { tenantId, bindingId: eligible.id });
    f.advance(60_001);
    const purge = await f.iam.purgeDeleted();
    expect(purge.expiredMemberships).toBe(1);
    expect(
      await f.iam.api.bindings.listActivations(owner, {
        tenantId,
        identityId: bob.id,
        includeExpired: true,
      }),
    ).toEqual([]);
    expect(await f.database.find('groupMembers', { tenantId, identityId: bob.id })).toEqual([]);
  });
});

describe('batch membership', () => {
  it('adds a cohort in one transaction with a shared expiry, and rejects the batch on one failure', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const cohort = await f.iam.api.groups.create(owner, { tenantId, name: 'Cohort' });
    const added = await f.iam.api.groups.addMembers(owner, {
      tenantId,
      groupId: cohort.id,
      identityIds: [alice.id, bob.id, alice.id],
      expiresAt: f.now() + 7 * day,
    });
    expect(added.members.map((member) => [member.identityId, member.expiresAt])).toEqual([
      [alice.id, f.now() + 7 * day],
      [bob.id, f.now() + 7 * day],
    ]);
    await expect(
      f.iam.api.groups.addMembers(owner, { tenantId, groupId: cohort.id, identityIds: [] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const carol = await f.member('carol');
    // Bob is already a member, so the whole batch is refused and Carol is not added either.
    await expect(
      f.iam.api.groups.addMembers(owner, {
        tenantId,
        groupId: cohort.id,
        identityIds: [carol.id, bob.id],
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(
      (await f.iam.api.groups.listMembers(owner, { tenantId, groupId: cohort.id }))
        .map((m) => m.id)
        .sort(),
    ).toEqual([alice.id, bob.id].sort());
  });
});

describe('future-dated bindings', () => {
  it('grant nothing before startsAt, show up as scheduled, and are never purged early', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    await expect(
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: reader.id,
        subjectType: 'identity',
        subjectId: alice.id,
        startsAt: f.now() - 3_600_000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: reader.id,
        subjectType: 'identity',
        subjectId: alice.id,
        startsAt: f.now() + 2 * day,
        expiresAt: f.now() + day,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const scheduled = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
      startsAt: f.now() + day,
      expiresAt: f.now() + 5 * day,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const can = async () =>
      (
        await f.iam.authorize({
          ...asAlice,
          tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed;
    expect(await can()).toBe(false);
    // Listed everywhere with its start, but not granting yet.
    expect(
      (await f.iam.api.identities.listBindings(owner, { tenantId, identityId: alice.id })).map(
        (binding) => binding.startsAt,
      ),
    ).toEqual([scheduled.startsAt]);
    expect(
      (await f.iam.api.roles.listBindings(owner, { tenantId, roleId: reader.id })).map((b) => b.id),
    ).toEqual([scheduled.id]);
    expect(
      (await f.iam.api.reports.access(owner, { tenantId, withinMs: 7 * day })).bindings!.starting,
    ).toEqual([expect.objectContaining({ id: scheduled.id, expiresAt: scheduled.startsAt })]);
    expect((await f.iam.purgeDeleted()).expiredBindings).toBe(0);
    f.advance(day + 1);
    expect(await can()).toBe(true);
    // Moving the start back into the future switches it off again; clearing it grants immediately.
    const admin = await f.ownerSignIn();
    await f.iam.api.bindings.update(admin, {
      tenantId,
      bindingId: scheduled.id,
      startsAt: f.now() + day,
    });
    expect(await can()).toBe(false);
    await f.iam.api.bindings.update(admin, { tenantId, bindingId: scheduled.id, startsAt: null });
    expect(await can()).toBe(true);
    await expect(
      f.iam.api.bindings.update(admin, {
        tenantId,
        bindingId: scheduled.id,
        startsAt: f.now() + 10 * day,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
