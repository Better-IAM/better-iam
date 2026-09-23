import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

/** Acme with a Reader role, a Writer role, and an Engineering group that carries Writer. */
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
  return { f, tenantId, owner, reader, writer, engineering, can };
}

describe('access packages', () => {
  it('bundles roles and groups, grants them together, and revokes only what it added', async () => {
    const { f, tenantId, owner, reader, engineering, can } = await setup();
    await expect(
      f.iam.api.packages.create(owner, { tenantId, name: 'Empty' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.packages.create(owner, { tenantId, name: 'Ghost', roleIds: ['missing'] }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const ownerRole = (await f.iam.api.roles.list(owner, { tenantId })).find(
      (role) => role.protected,
    )!;
    await expect(
      f.iam.api.packages.create(owner, { tenantId, name: 'Owners', roleIds: [ownerRole.id] }),
    ).rejects.toMatchObject({ code: 'PROTECTED_RESOURCE' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Engineer kit',
      description: 'Document access and the Engineering group',
      roleIds: [reader.id],
      groupIds: [engineering.id],
    });
    expect(kit).toMatchObject({
      name: 'Engineer kit',
      roleIds: [reader.id],
      groupIds: [engineering.id],
      assignments: 0,
    });
    await expect(
      f.iam.api.packages.create(owner, { tenantId, name: 'engineer KIT', roleIds: [reader.id] }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const alice = await f.member('alice');
    expect(await can('alice', 'documents:read')).toBe(false);
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + 5 * day,
      justification: 'Joined the platform team',
    });
    expect(assigned).toMatchObject({
      packageName: 'Engineer kit',
      identityName: 'alice',
      identityEmail: 'alice@acme.test',
      expired: false,
      created: { bindings: 1, memberships: 1 },
      skipped: [],
    });
    expect(await can('alice', 'documents:read')).toBe(true);
    expect(await can('alice', 'documents:write')).toBe(true);
    // The grants are ordinary records tagged with the assignment and ending with it.
    expect(
      (
        await f.database.find<{ roleId: string; expiresAt?: number }>('bindings', {
          tenantId,
          packageAssignmentId: assigned.id,
        })
      ).map((binding) => [binding.roleId, binding.expiresAt]),
    ).toEqual([[reader.id, f.now() + 5 * day]]);
    expect(
      (
        await f.database.find<{ groupId: string; expiresAt?: number }>('groupMembers', {
          tenantId,
          packageAssignmentId: assigned.id,
        })
      ).map((member) => [member.groupId, member.expiresAt]),
    ).toEqual([[engineering.id, f.now() + 5 * day]]);
    await expect(
      f.iam.api.packages.assign(owner, { tenantId, packageId: kit.id, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect((await f.iam.api.packages.list(owner, { tenantId }))[0]!.assignments).toBe(1);
    expect(
      (await f.iam.api.packages.listAssignments(owner, { tenantId, identityId: alice.id })).map(
        (assignment) => assignment.packageId,
      ),
    ).toEqual([kit.id]);
    // Bob already holds Reader directly: the package adds a binding of its own beside it (so each can end on
    // its own) and never touches the direct one.
    const bob = await f.member('bob');
    const direct = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const partial = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: bob.id,
    });
    expect(partial.created).toEqual({ bindings: 1, memberships: 1 });
    expect(partial.skipped).toEqual([]);
    expect(partial.bindingIds).not.toContain(direct.id);
    expect(await can('bob', 'documents:write')).toBe(true);
    await f.iam.api.packages.revoke(owner, { tenantId, packageId: kit.id, identityId: bob.id });
    expect(await can('bob', 'documents:read')).toBe(true);
    expect(await can('bob', 'documents:write')).toBe(false);
    // Nothing is deleted from under a package; revoking clears the way.
    await expect(
      f.iam.api.packages.delete(owner, { tenantId, packageId: kit.id }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await expect(
      f.iam.api.roles.delete(owner, { tenantId, roleId: reader.id }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await expect(
      f.iam.api.groups.delete(owner, { tenantId, groupId: engineering.id }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    const revoked = await f.iam.api.packages.revoke(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
    });
    expect(revoked).toEqual({ revoked: true, bindings: 1, memberships: 1 });
    expect(await can('alice', 'documents:read')).toBe(false);
    expect(await can('alice', 'documents:write')).toBe(false);
    await expect(
      f.iam.api.packages.revoke(owner, { tenantId, packageId: kit.id, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const trail = await f.iam.api.audit.list(owner, { tenantId, action: 'package:assign' });
    expect(trail).toHaveLength(2);
    expect(trail.find((event) => event.metadata?.identityId === bob.id)!.metadata).toMatchObject({
      packageName: 'Engineer kit',
      bindings: 1,
      memberships: 1,
      skipped: [],
    });
    expect(await f.iam.api.audit.list(owner, { tenantId, action: 'package:revoke' })).toHaveLength(
      2,
    );
    await f.iam.api.packages.delete(owner, { tenantId, packageId: kit.id });
    expect(await f.iam.api.packages.list(owner, { tenantId })).toEqual([]);
  });

  it('enforces the package rules, ends with its expiry, and follows offboarding and permissions', async () => {
    const { f, tenantId, owner, reader, engineering, can } = await setup();
    const vendor = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Vendor',
      roleIds: [reader.id],
      groupIds: [engineering.id],
      maxDurationMs: 2 * day,
      requireJustification: true,
    });
    const alice = await f.member('alice');
    const assign = (input: { expiresAt?: number; justification?: string }) =>
      f.iam.api.packages.assign(owner, {
        tenantId,
        packageId: vendor.id,
        identityId: alice.id,
        ...input,
      });
    // An end date within the cap and a justification are mandatory here.
    await expect(assign({ justification: 'Audit' })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(
      assign({ justification: 'Audit', expiresAt: f.now() + 3 * day }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(assign({ expiresAt: f.now() + day })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await assign({ expiresAt: f.now() + day, justification: 'Quarterly audit' });
    expect(await can('alice', 'documents:read')).toBe(true);
    f.advance(day + 1);
    expect(await can('alice', 'documents:read')).toBe(false);
    expect(await can('alice', 'documents:write')).toBe(false);
    expect(
      await f.iam.api.packages.listAssignments(owner, { tenantId, packageId: vendor.id }),
    ).toEqual([]);
    expect(
      (
        await f.iam.api.packages.listAssignments(owner, {
          tenantId,
          packageId: vendor.id,
          includeExpired: true,
        })
      ).map((assignment) => assignment.expired),
    ).toEqual([true]);
    expect(await f.iam.purgeDeleted()).toMatchObject({
      expiredBindings: 1,
      expiredMemberships: 1,
      expiredAssignments: 1,
    });
    // Reassigning after the end starts afresh; offboarding removes the assignment with everything else.
    const again = await assign({ expiresAt: f.now() + day, justification: 'Follow-up audit' });
    expect(again.created).toEqual({ bindings: 1, memberships: 1 });
    expect(await can('alice', 'documents:read')).toBe(true);
    const admin = await f.ownerSignIn();
    const offboarded = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: alice.id,
      reason: 'Contract ended',
    });
    expect(offboarded).toMatchObject({ packages: 1, bindings: 1, memberships: 1 });
    expect(
      await f.iam.api.packages.listAssignments(owner, { tenantId, includeExpired: true }),
    ).toEqual([]);
    // Assigning needs the package permission and the right to grant every part of it.
    const carol = await f.member('carol');
    const assigner = await f.iam.api.roles.create(admin, {
      tenantId,
      name: 'Assigner',
      permissions: ['iam:packages:read', 'iam:packages:assign'],
    });
    await f.iam.api.bindings.create(admin, {
      tenantId,
      roleId: assigner.id,
      subjectType: 'identity',
      subjectId: carol.id,
    });
    const asCarol = { token: (await f.signIn('carol')).token };
    const dave = await f.member('dave');
    await expect(
      f.iam.api.packages.assign(asCarol, {
        tenantId,
        packageId: vendor.id,
        identityId: dave.id,
        expiresAt: f.now() + day,
        justification: 'Onboarding',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.packages.create(asCarol, { tenantId, name: 'Nope', roleIds: [reader.id] }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await f.iam.api.packages.list(asCarol, { tenantId })).map((pkg) => pkg.name)).toEqual([
      'Vendor',
    ]);
    const asDave = { token: (await f.signIn('dave')).token };
    await expect(f.iam.api.packages.list(asDave, { tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // Editing a package changes future assignments only.
    const updated = await f.iam.api.packages.update(admin, {
      tenantId,
      packageId: vendor.id,
      groupIds: [],
      maxDurationMs: null,
      requireJustification: false,
    });
    expect(updated).toMatchObject({ roleIds: [reader.id], groupIds: [], assignments: 0 });
    expect(updated.maxDurationMs).toBeUndefined();
    const plain = await f.iam.api.packages.assign(admin, {
      tenantId,
      packageId: vendor.id,
      identityId: dave.id,
    });
    expect(plain.created).toEqual({ bindings: 1, memberships: 0 });
    expect(plain.expiresAt).toBeUndefined();
  });

  it('travels with the configuration document', async () => {
    const { f, tenantId, owner, reader, engineering } = await setup();
    await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Engineer kit',
      roleIds: [reader.id],
      groupIds: [engineering.id],
      maxDurationMs: 30 * day,
      requireJustification: true,
    });
    const exported = await f.iam.api.config.export(owner, { tenantId });
    expect(exported.packages).toEqual([
      {
        name: 'Engineer kit',
        roles: ['Reader'],
        groups: ['Engineering'],
        maxDurationMs: 30 * day,
        requireJustification: true,
      },
    ]);
    const plan = await f.iam.api.config.plan(owner, { tenantId, config: exported, prune: true });
    expect(plan.summary.create + plan.summary.update + plan.summary.delete).toBe(0);
    const applied = await f.iam.api.config.apply(owner, {
      tenantId,
      config: {
        ...exported,
        packages: [
          { name: 'Engineer kit', roles: ['Reader', 'Writer'], groups: [] },
          { name: 'Reviewer kit', roles: ['Writer'] },
        ],
      },
      prune: true,
    });
    expect(
      applied.changes
        .filter((change) => change.kind === 'package')
        .map((change) => [change.name, change.action, change.fields]),
    ).toEqual([
      ['Engineer kit', 'update', ['groups', 'maxDurationMs', 'requireJustification', 'roles']],
      ['Reviewer kit', 'create', undefined],
    ]);
    expect(
      (await f.iam.api.packages.list(owner, { tenantId })).map((pkg) => [
        pkg.name,
        pkg.roleIds.length,
        pkg.groupIds.length,
        pkg.maxDurationMs,
        pkg.requireJustification,
      ]),
    ).toEqual([
      ['Engineer kit', 2, 0, undefined, undefined],
      ['Reviewer kit', 1, 0, undefined, undefined],
    ]);
    await expect(
      f.iam.api.config.plan(owner, {
        tenantId,
        config: { version: 1, packages: [{ name: 'Bad', roles: ['Nope'] }] },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Pruning packages out of the document removes them before the roles they reference.
    const pruned = await f.iam.api.config.apply(owner, {
      tenantId,
      config: {
        version: 1,
        roles: [{ name: 'Reader', permissions: ['documents:read'] }],
        packages: [],
      },
      prune: true,
    });
    expect(
      pruned.changes.filter((change) => change.kind === 'package').map((change) => change.action),
    ).toEqual(['delete', 'delete']);
    expect(await f.iam.api.packages.list(owner, { tenantId })).toEqual([]);
    expect(
      (await f.iam.api.roles.list(owner, { tenantId }))
        .filter((role) => !role.protected)
        .map((role) => role.name),
    ).toEqual(['Reader']);
  });
});
