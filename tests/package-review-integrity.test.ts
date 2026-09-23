import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;
const hour = 3600000;

type MemberRow = { id: string; groupId: string; packageAssignmentId?: string; expiresAt?: number };
type BindingRow = { id: string; roleId: string; packageAssignmentId?: string; expiresAt?: number };

/** Acme with Reader and Writer roles and an Engineering group that carries Writer (granted by the owner). */
async function setup() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
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
  const engineering = await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
  await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: writer.id,
    subjectType: 'group',
    subjectId: engineering.id,
  });
  const sessions = new Map<string, string>();
  const can = async (name: string, action: string) => {
    if (!sessions.has(name)) sessions.set(name, (await f.signIn(name)).token);
    return (
      await f.iam.authorize({
        token: sessions.get(name)!,
        tenantId,
        action,
        resource: { type: 'documents', id: 'a' },
      })
    ).allowed;
  };
  const membership = async (groupId: string, identityId: string) =>
    (await f.database.find<MemberRow>('groupMembers', { tenantId, groupId, identityId }))[0];
  const binding = async (bindingId: string) => f.database.get<BindingRow>('bindings', bindingId);
  const inGroup = async (groupId: string, name: string) =>
    (await f.iam.api.groups.listMembers(owner, { tenantId, groupId })).some(
      (member) => member.name === name,
    );
  return { f, tenantId, owner, reader, writer, engineering, can, membership, binding, inGroup };
}

describe('regress-integrity: approver groups cannot disappear under their packages and bindings', () => {
  it('refuses deleting the approver group of a package or of a live eligible binding', async () => {
    const { f, tenantId, owner, reader } = await setup();
    const approvers = await f.iam.api.groups.create(owner, { tenantId, name: 'Approvers' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
      approverGroupId: approvers.id,
    });
    await expect(
      f.iam.api.groups.delete(owner, { tenantId, groupId: approvers.id }),
    ).rejects.toMatchObject({
      code: 'RESOURCE_IN_USE',
      message: expect.stringContaining('package Kit'),
    });
    expect(await f.database.get('groups', approvers.id)).toBeDefined();
    // The package's approver field still points at the group.
    expect(
      (await f.iam.api.packages.get(owner, { tenantId, packageId: kit.id })).approverGroupId,
    ).toBe(approvers.id);
    // A live eligible binding of another subject that names the group as approver also blocks the delete.
    const alice = await f.member('alice');
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      requireApproval: true,
      approverGroupId: approvers.id,
      expiresAt: f.now() + day,
    });
    await f.iam.api.packages.update(owner, { tenantId, packageId: kit.id, approverGroupId: null });
    await expect(
      f.iam.api.groups.delete(owner, { tenantId, groupId: approvers.id }),
    ).rejects.toMatchObject({
      code: 'RESOURCE_IN_USE',
      message: expect.stringContaining('1 eligible binding'),
    });
    expect(await f.database.get('groups', approvers.id)).toBeDefined();
    // Once that binding has ended it no longer holds the group.
    f.advance(day + 1);
    await expect(
      f.iam.api.groups.delete(owner, { tenantId, groupId: approvers.id }),
    ).resolves.toEqual({ deleted: true });
  });

  it('still deletes a group whose own eligible bindings name it as approver', async () => {
    const { f, tenantId, owner, reader } = await setup();
    const oncall = await f.iam.api.groups.create(owner, { tenantId, name: 'On-call' });
    const own = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'group',
      subjectId: oncall.id,
      eligible: true,
      requireApproval: true,
      approverGroupId: oncall.id,
    });
    await expect(f.iam.api.groups.delete(owner, { tenantId, groupId: oncall.id })).resolves.toEqual(
      { deleted: true },
    );
    expect(await f.database.get('bindings', own.id)).toBeUndefined();
  });
});

describe('regress-integrity: package bindings are independent of direct ones', () => {
  it('adds its own binding beside a direct one and leaves the direct one on revoke', async () => {
    const { f, tenantId, owner, reader, can } = await setup();
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
    });
    const bob = await f.member('bob');
    const direct = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: bob.id,
    });
    expect(assigned.created).toEqual({ bindings: 1, memberships: 0 });
    expect(assigned.skipped).toEqual([]);
    expect(assigned.bindingIds).toHaveLength(1);
    expect(assigned.bindingIds).not.toContain(direct.id);
    expect(
      (await f.database.get<BindingRow>('bindings', assigned.bindingIds[0]!))?.packageAssignmentId,
    ).toBe(assigned.id);
    expect(
      await f.iam.api.packages.revoke(owner, { tenantId, packageId: kit.id, identityId: bob.id }),
    ).toEqual({ revoked: true, bindings: 1, memberships: 0 });
    expect(await f.database.get('bindings', direct.id)).toBeDefined();
    expect(await can('bob', 'documents:read')).toBe(true);
  });

  it('allows a direct binding of a role someone holds through a package, and keeps it on revoke', async () => {
    const { f, tenantId, owner, reader, can } = await setup();
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
    });
    const alice = await f.member('alice');
    await f.iam.api.packages.assign(owner, { tenantId, packageId: kit.id, identityId: alice.id });
    const direct = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    expect(direct.packageAssignmentId).toBeUndefined();
    expect(
      await f.iam.api.packages.revoke(owner, { tenantId, packageId: kit.id, identityId: alice.id }),
    ).toEqual({ revoked: true, bindings: 1, memberships: 0 });
    expect(await f.database.get('bindings', direct.id)).toBeDefined();
    expect(await can('alice', 'documents:read')).toBe(true);
  });

  it('two packages with the same role each get their own binding, so one ending leaves the other', async () => {
    const { f, tenantId, owner, reader, can } = await setup();
    const project = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Project',
      roleIds: [reader.id],
    });
    const base = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Base',
      roleIds: [reader.id],
    });
    const alice = await f.member('alice');
    const temporary = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: project.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    const permanent = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: base.id,
      identityId: alice.id,
    });
    expect(permanent.created).toEqual({ bindings: 1, memberships: 0 });
    expect(permanent.skipped).toEqual([]);
    expect(permanent.bindingIds).not.toContain(temporary.bindingIds[0]);
    expect(
      (await f.database.get<BindingRow>('bindings', permanent.bindingIds[0]!))?.expiresAt,
    ).toBeUndefined();
    // Project ends; Base still grants Reader through its own binding.
    f.advance(2 * day);
    expect(await can('alice', 'documents:read')).toBe(true);
    expect(
      await f.iam.api.packages.revoke(owner, {
        tenantId,
        packageId: project.id,
        identityId: alice.id,
      }),
    ).toEqual({ revoked: true, bindings: 1, memberships: 0 });
    expect(await f.database.get('bindings', permanent.bindingIds[0]!)).toBeDefined();
    expect(await can('alice', 'documents:read')).toBe(true);
  });
});

describe('regress-integrity: records edited by hand leave the package', () => {
  it('re-adding to the group or editing the binding after the assignment ended detaches them', async () => {
    const { f, tenantId, owner, reader, engineering, can, membership, binding } = await setup();
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      groupIds: [engineering.id],
    });
    const alice = await f.member('alice');
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + hour,
    });
    expect(assigned.created).toEqual({ bindings: 1, memberships: 1 });
    f.advance(2 * hour);
    expect(await can('alice', 'documents:read')).toBe(false);
    expect(await can('alice', 'documents:write')).toBe(false);
    // The owner puts alice back in Engineering by hand and makes the old package binding permanent.
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: engineering.id,
      identityId: alice.id,
    });
    const renewed = await membership(engineering.id, alice.id);
    expect(renewed).toBeDefined();
    expect(renewed!.packageAssignmentId).toBeUndefined();
    expect(renewed!.expiresAt).toBeUndefined();
    const bindingId = assigned.bindingIds[0]!;
    await f.iam.api.bindings.update(owner, { tenantId, bindingId, expiresAt: null });
    const edited = await binding(bindingId);
    expect(edited).toBeDefined();
    expect(edited!.packageAssignmentId).toBeUndefined();
    expect(edited!.expiresAt).toBeUndefined();
    // Cleaning up the ended assignment no longer takes them away.
    expect(
      await f.iam.api.packages.revoke(owner, { tenantId, packageId: kit.id, identityId: alice.id }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 0 });
    expect(await binding(bindingId)).toBeDefined();
    expect(await membership(engineering.id, alice.id)).toBeDefined();
    expect(await can('alice', 'documents:read')).toBe(true);
    expect(await can('alice', 'documents:write')).toBe(true);
  });

  it('groups.updateMember takes a package membership over, so revoking the ended assignment keeps it', async () => {
    const { f, tenantId, owner, engineering, can, membership, inGroup } = await setup();
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      groupIds: [engineering.id],
    });
    const alice = await f.member('alice');
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + hour,
    });
    expect((await membership(engineering.id, alice.id))!.packageAssignmentId).toBe(assigned.id);
    await f.iam.api.groups.updateMember(owner, {
      tenantId,
      groupId: engineering.id,
      identityId: alice.id,
      expiresAt: null,
    });
    const taken = await membership(engineering.id, alice.id);
    expect(taken!.packageAssignmentId).toBeUndefined();
    expect(taken!.expiresAt).toBeUndefined();
    f.advance(2 * hour);
    expect(
      await f.iam.api.packages.revoke(owner, { tenantId, packageId: kit.id, identityId: alice.id }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 0 });
    expect(await inGroup(engineering.id, 'alice')).toBe(true);
    expect(await can('alice', 'documents:write')).toBe(true);
  });
});

describe('regress-integrity: packages that share a group share one membership', () => {
  async function shared() {
    const s = await setup();
    const { f, tenantId, owner, engineering } = s;
    const short = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Short',
      groupIds: [engineering.id],
    });
    const long = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Long',
      groupIds: [engineering.id],
    });
    const alice = await f.member('alice');
    return { ...s, short, long, alice };
  }

  it('the longer assignment owns it; revoking it hands the membership to the other', async () => {
    const { f, tenantId, owner, engineering, short, long, alice, membership, inGroup, can } =
      await shared();
    const a = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: short.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    const b = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: long.id,
      identityId: alice.id,
    });
    expect(b.skipped).toEqual([]);
    const record = await membership(engineering.id, alice.id);
    expect(record!.packageAssignmentId).toBe(b.id);
    expect(record!.expiresAt).toBeUndefined();
    expect(
      await f.database.find('groupMembers', {
        tenantId,
        groupId: engineering.id,
        identityId: alice.id,
      }),
    ).toHaveLength(1);
    // Revoking the owner of the record hands it to the live survivor, with the survivor's end.
    await f.iam.api.packages.revoke(owner, { tenantId, packageId: long.id, identityId: alice.id });
    const handed = await membership(engineering.id, alice.id);
    expect(handed).toBeDefined();
    expect(handed!.id).toBe(record!.id);
    expect(handed!.packageAssignmentId).toBe(a.id);
    expect(handed!.expiresAt).toBe(a.expiresAt);
    expect(await inGroup(engineering.id, 'alice')).toBe(true);
    expect(await can('alice', 'documents:write')).toBe(true);
    // Revoking the last one removes it.
    expect(
      await f.iam.api.packages.revoke(owner, {
        tenantId,
        packageId: short.id,
        identityId: alice.id,
      }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 1 });
    expect(await membership(engineering.id, alice.id)).toBeUndefined();
    expect(await can('alice', 'documents:write')).toBe(false);
  });

  it('revoking the shorter assignment first leaves the longer one its membership', async () => {
    const { f, tenantId, owner, engineering, short, long, alice, membership, inGroup } =
      await shared();
    await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: short.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    const b = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: long.id,
      identityId: alice.id,
    });
    expect(
      await f.iam.api.packages.revoke(owner, {
        tenantId,
        packageId: short.id,
        identityId: alice.id,
      }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 0 });
    const kept = await membership(engineering.id, alice.id);
    expect(kept!.packageAssignmentId).toBe(b.id);
    expect(kept!.expiresAt).toBeUndefined();
    expect(await inGroup(engineering.id, 'alice')).toBe(true);
    f.advance(2 * day);
    expect(await inGroup(engineering.id, 'alice')).toBe(true);
    expect(
      await f.iam.api.packages.revoke(owner, {
        tenantId,
        packageId: long.id,
        identityId: alice.id,
      }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 1 });
    expect(await membership(engineering.id, alice.id)).toBeUndefined();
  });

  it('a permanent assignment made first is skipped by the shorter one, which takes over on revoke', async () => {
    const { f, tenantId, owner, engineering, short, long, alice, membership, inGroup } =
      await shared();
    const b = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: long.id,
      identityId: alice.id,
    });
    const a = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: short.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    expect(a.skipped).toEqual(['already a member of group Engineering (through package Long)']);
    expect((await membership(engineering.id, alice.id))!.packageAssignmentId).toBe(b.id);
    await f.iam.api.packages.revoke(owner, { tenantId, packageId: long.id, identityId: alice.id });
    const handed = await membership(engineering.id, alice.id);
    expect(handed!.packageAssignmentId).toBe(a.id);
    expect(handed!.expiresAt).toBe(a.expiresAt);
    expect(await inGroup(engineering.id, 'alice')).toBe(true);
    expect(
      await f.iam.api.packages.revoke(owner, {
        tenantId,
        packageId: short.id,
        identityId: alice.id,
      }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 1 });
    expect(await inGroup(engineering.id, 'alice')).toBe(false);
  });

  it('shortening an assignment hands the membership to one that needs it longer', async () => {
    const { f, tenantId, owner, engineering, short, long, alice, membership, inGroup } =
      await shared();
    // "Long" is permanent and owns the membership; "Short" lasts three days and is skipped.
    const permanent = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: long.id,
      identityId: alice.id,
    });
    const threeDays = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: short.id,
      identityId: alice.id,
      expiresAt: f.now() + 3 * day,
    });
    expect((await membership(engineering.id, alice.id))!.packageAssignmentId).toBe(permanent.id);
    // Cut "Long" down to one day: the membership goes to "Short" (three days) instead of ending after one.
    const shortened = await f.iam.api.packages.extend(owner, {
      tenantId,
      packageId: long.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    expect(shortened.expiresAt).toBe(f.now() + day);
    const handed = await membership(engineering.id, alice.id);
    expect(handed!.packageAssignmentId).toBe(threeDays.id);
    expect(handed!.expiresAt).toBe(threeDays.expiresAt);
    f.advance(2 * day);
    expect(await inGroup(engineering.id, 'alice')).toBe(true);
    // Cleaning up the ended "Long" assignment leaves the membership "Short" now owns.
    expect(
      await f.iam.api.packages.revoke(owner, {
        tenantId,
        packageId: long.id,
        identityId: alice.id,
      }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 0 });
    expect(await inGroup(engineering.id, 'alice')).toBe(true);
    expect(
      await f.iam.api.packages.revoke(owner, {
        tenantId,
        packageId: short.id,
        identityId: alice.id,
      }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 1 });
    expect(await inGroup(engineering.id, 'alice')).toBe(false);
  });
});

describe('regress-integrity: memberships held by hand', () => {
  it('a permanent hand membership is skipped and survives revoking the package', async () => {
    const { f, tenantId, owner, engineering, membership, inGroup } = await setup();
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      groupIds: [engineering.id],
    });
    const alice = await f.member('alice');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: engineering.id,
      identityId: alice.id,
    });
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    expect(assigned.skipped).toEqual(['already a member of group Engineering']);
    expect(assigned.created).toEqual({ bindings: 0, memberships: 0 });
    expect((await membership(engineering.id, alice.id))!.packageAssignmentId).toBeUndefined();
    expect(
      await f.iam.api.packages.revoke(owner, { tenantId, packageId: kit.id, identityId: alice.id }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 0 });
    expect(await inGroup(engineering.id, 'alice')).toBe(true);
    expect((await membership(engineering.id, alice.id))!.expiresAt).toBeUndefined();
  });

  it('a shorter hand membership is extended to the assignment end and belongs to it', async () => {
    const { f, tenantId, owner, engineering, membership, inGroup } = await setup();
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      groupIds: [engineering.id],
    });
    const bob = await f.member('bob');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: engineering.id,
      identityId: bob.id,
      expiresAt: f.now() + day,
    });
    const before = await membership(engineering.id, bob.id);
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: bob.id,
      expiresAt: f.now() + 3 * day,
    });
    expect(assigned.skipped).toEqual([]);
    expect(assigned.created).toEqual({ bindings: 0, memberships: 1 });
    const extended = await membership(engineering.id, bob.id);
    expect(extended!.id).toBe(before!.id);
    expect(extended!.expiresAt).toBe(f.now() + 3 * day);
    expect(extended!.packageAssignmentId).toBe(assigned.id);
    f.advance(2 * day);
    expect(await inGroup(engineering.id, 'bob')).toBe(true);
    expect(
      await f.iam.api.packages.revoke(owner, { tenantId, packageId: kit.id, identityId: bob.id }),
    ).toEqual({ revoked: true, bindings: 0, memberships: 1 });
    expect(await inGroup(engineering.id, 'bob')).toBe(false);
  });
});

/**
 * Bob, a delegated administrator who may assign packages, and a requestable package of Reader plus Newsletter.
 * With `groupBinding`, Newsletter confers Writer under Bob's own authority.
 */
async function delegated({ groupBinding = false } = {}) {
  const s = await setup();
  const { f, tenantId, owner, reader, writer } = s;
  const newsletter = await f.iam.api.groups.create(owner, { tenantId, name: 'Newsletter' });
  const admin = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Package admin',
    permissions: ['iam:packages:assign', 'iam:bindings:create', 'iam:groups:update'],
  });
  const requester = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Requester',
    permissions: ['iam:packages:request'],
  });
  const bob = await f.member('bob');
  const alice = await f.member('alice');
  await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: admin.id,
    subjectType: 'identity',
    subjectId: bob.id,
  });
  await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: requester.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  await f.iam.api.authorities.create(owner, {
    tenantId,
    identityId: bob.id,
    ceiling: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
    },
  });
  const asBob = { token: (await f.signIn('bob')).token };
  // Newsletter then confers Writer under Bob's own authority, so only Bob (or root) may manage its members directly.
  if (groupBinding)
    await f.iam.api.bindings.create(asBob, {
      tenantId,
      roleId: writer.id,
      subjectType: 'group',
      subjectId: newsletter.id,
    });
  const kit = await f.iam.api.packages.create(owner, {
    tenantId,
    name: 'Kit',
    roleIds: [reader.id],
    groupIds: [newsletter.id],
    requestable: true,
  });
  return { ...s, newsletter, bob, alice, asBob, kit };
}

describe('regress-integrity: assignments made by a delegated administrator', () => {
  it('breaks when the assigner is offboarded and can then be replaced or requested again', async () => {
    const { f, tenantId, owner, kit, bob, alice, asBob, can, newsletter, membership } =
      await delegated();
    const first = await f.iam.api.packages.assign(asBob, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
    });
    expect(first.created).toEqual({ bindings: 1, memberships: 1 });
    expect(await can('alice', 'documents:read')).toBe(true);
    expect(
      (await f.iam.api.packages.listAssignments(owner, { tenantId, identityId: alice.id }))[0],
    ).toMatchObject({ id: first.id, broken: false });
    const admin = await f.ownerSignIn();
    await f.iam.api.identities.offboard(admin, { tenantId, identityId: bob.id, reason: 'Left' });
    expect(await can('alice', 'documents:read')).toBe(false);
    const listed = await f.iam.api.packages.listAssignments(owner, {
      tenantId,
      identityId: alice.id,
    });
    expect(
      listed.map((assignment) => [assignment.id, assignment.expired, assignment.broken]),
    ).toEqual([[first.id, false, true]]);
    // Alice may ask for it again while it grants nothing.
    const asAlice = { token: (await f.signIn('alice')).token };
    const request = await f.iam.api.packages.request(asAlice, { tenantId, packageId: kit.id });
    expect(request.status).toBe('pending');
    // The owner may replace it.
    const second = await f.iam.api.packages.assign(admin, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
    });
    expect(second.id).not.toBe(first.id);
    expect(second.broken).toBe(false);
    expect(second.created).toEqual({ bindings: 1, memberships: 1 });
    expect(second.skipped).toEqual([]);
    // The broken assignment's records are gone; the new one owns the membership.
    expect(await f.database.get('bindings', first.bindingIds[0]!)).toBeUndefined();
    expect(await f.database.get('packageAssignments', first.id)).toBeUndefined();
    expect((await membership(newsletter.id, alice.id))!.packageAssignmentId).toBe(second.id);
    expect(await can('alice', 'documents:read')).toBe(true);
    expect(
      (await f.iam.api.packages.listAssignments(owner, { tenantId, identityId: alice.id })).map(
        (assignment) => [assignment.id, assignment.broken],
      ),
    ).toEqual([[second.id, false]]);
    expect(
      (await f.iam.api.packages.listRequests(owner, { tenantId, identityId: alice.id })).map(
        (item) => [item.id, item.status, item.assignmentId],
      ),
    ).toEqual([[request.id, 'approved', second.id]]);
  });

  it('offboarding the holder succeeds for the owner and counts the package records', async () => {
    const { f, tenantId, kit, alice, asBob, can } = await delegated({ groupBinding: true });
    await f.iam.api.packages.assign(asBob, { tenantId, packageId: kit.id, identityId: alice.id });
    expect(await can('alice', 'documents:read')).toBe(true);
    expect(await can('alice', 'documents:write')).toBe(true);
    const admin = await f.ownerSignIn();
    const offboarded = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: alice.id,
      reason: 'Contract ended',
    });
    // Alice also holds the Requester role directly (granted by the owner): 1 direct + 1 package binding.
    expect(offboarded).toMatchObject({ packages: 1, bindings: 2, memberships: 1 });
    expect(await f.database.find('packageAssignments', { tenantId, identityId: alice.id })).toEqual(
      [],
    );
    expect(
      await f.database.find('bindings', { tenantId, subjectType: 'identity', subjectId: alice.id }),
    ).toEqual([]);
    expect(await f.database.find('groupMembers', { tenantId, identityId: alice.id })).toEqual([]);
  });
});

describe('regress-integrity: a direct assignment fulfils a pending request', () => {
  it('marks the pending request approved with the assignment and drops it from approvals', async () => {
    const { f, tenantId, owner, reader } = await setup();
    const requester = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Requester',
      permissions: ['iam:packages:request'],
    });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const alice = await f.member('alice');
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: requester.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const request = await f.iam.api.packages.request(asAlice, { tenantId, packageId: kit.id });
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).map((item) => item.id),
    ).toEqual([request.id]);
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
    });
    const listed = await f.iam.api.packages.listRequests(owner, {
      tenantId,
      identityId: alice.id,
    });
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({
      id: request.id,
      status: 'approved',
      assignmentId: assigned.id,
      decidedBy: f.ownerId,
    });
    expect(await f.iam.api.packages.listApprovals(owner, { tenantId })).toEqual([]);
    expect(
      (await f.iam.api.packages.listRequests(owner, { tenantId, status: 'pending' })).length,
    ).toBe(0);
  });
});
