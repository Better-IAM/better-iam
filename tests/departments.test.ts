import { afterEach, describe, expect, it } from 'vitest';
import { departmentHeads, departmentOf, departmentPath } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

async function scenario() {
  const f = await organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write'],
      identityAttributes: { department: 'string' },
    },
    // Documents named `doc-{departmentId}` belong to that department.
    resolveResource: async (reference) => ({
      ...reference,
      attributes: { departmentId: reference.id.replace(/^doc-/, '') },
    }),
  });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const [alice, bob, carol, dave] = [
    await f.member('alice'),
    await f.member('bob'),
    await f.member('carol'),
    await f.member('dave'),
  ];
  const engineering = await f.iam.api.departments.create(owner, {
    tenantId,
    name: 'Engineering',
    code: 'ENG',
    headId: alice.id,
    costCenter: 'CC-100',
  });
  const platform = await f.iam.api.departments.create(owner, {
    tenantId,
    name: 'Platform',
    code: 'ENG-PLT',
    parentId: engineering.id,
    headId: bob.id,
  });
  return { f, tenantId, owner, alice, bob, carol, dave, engineering, platform };
}

describe('departments', () => {
  it('builds a department tree with heads, codes, and unique names', async () => {
    const s = await scenario();
    expect(s.engineering).toMatchObject({
      name: 'Engineering',
      code: 'ENG',
      costCenter: 'CC-100',
      head: { id: s.alice.id },
      path: [],
    });
    expect(s.platform.path.map((step) => step.code)).toEqual(['ENG']);
    await expect(
      s.f.iam.api.departments.create(s.owner, { tenantId: s.tenantId, name: 'engineering' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      s.f.iam.api.departments.create(s.owner, { tenantId: s.tenantId, name: 'Eng 2', code: 'eng' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      s.f.iam.api.departments.update(s.owner, {
        tenantId: s.tenantId,
        departmentId: s.engineering.id,
        parentId: s.platform.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const service = await s.f.iam.api.serviceAccounts.create(s.owner, {
      tenantId: s.tenantId,
      name: 'ci',
    });
    await expect(
      s.f.iam.api.departments.update(s.owner, {
        tenantId: s.tenantId,
        departmentId: s.platform.id,
        headId: service.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const cleared = await s.f.iam.api.departments.update(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platform.id,
      code: null,
      description: 'Runs shared infrastructure',
    });
    expect(cleared.code).toBeUndefined();
    expect(cleared.description).toBe('Runs shared infrastructure');
  });

  it('places people, one department each, and rolls counts up the tree', async () => {
    const s = await scenario();
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.engineering.id,
      identityIds: [s.alice.id, s.carol.id],
    });
    const moved = await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platform.id,
      identityIds: [s.bob.id, s.carol.id],
      title: 'Engineer',
    });
    expect(moved).toEqual({ assigned: 2, unchanged: 0 });
    const tree = await s.f.iam.api.departments.tree(s.owner, { tenantId: s.tenantId });
    expect(tree).toHaveLength(1);
    expect(tree[0]).toMatchObject({ name: 'Engineering', memberCount: 1, totalMemberCount: 3 });
    expect(tree[0]!.children[0]).toMatchObject({
      name: 'Platform',
      memberCount: 2,
      head: { id: s.bob.id },
    });
    const everyone = await s.f.iam.api.departments.listMembers(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.engineering.id,
      includeSubdepartments: true,
    });
    expect(
      everyone.map((member) => [member.name, member.department.name, member.head ?? false]),
    ).toEqual([
      ['alice', 'Engineering', true],
      ['bob', 'Platform', true],
      ['carol', 'Platform', false],
    ]);
    const carol = await s.f.iam.api.departments.ofIdentity(s.owner, {
      tenantId: s.tenantId,
      identityId: s.carol.id,
    });
    expect(carol).toMatchObject({
      department: { name: 'Platform' },
      title: 'Engineer',
      head: { id: s.bob.id },
    });
    expect(carol!.path.map((step) => step.name)).toEqual(['Engineering', 'Platform']);

    await s.f.iam.store.transaction(async (tx) => {
      expect(await departmentOf(tx, s.tenantId, s.carol.id)).toBe(s.platform.id);
      expect(await departmentPath(tx, s.tenantId, s.platform.id)).toEqual([
        s.engineering.id,
        s.platform.id,
      ]);
      expect(await departmentHeads(tx, s.tenantId, s.platform.id)).toEqual([s.bob.id]);
      expect(
        await departmentHeads(tx, s.tenantId, s.platform.id, { includeAncestors: true }),
      ).toEqual([s.bob.id, s.alice.id]);
    });

    await s.f.iam.api.departments.unassign(s.owner, {
      tenantId: s.tenantId,
      identityId: s.carol.id,
    });
    expect(
      await s.f.iam.api.departments.ofIdentity(s.owner, {
        tenantId: s.tenantId,
        identityId: s.carol.id,
      }),
    ).toBeNull();
  });

  it('exposes principal.departments and principal.departmentId to policies', async () => {
    const s = await scenario();
    const role = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Engineering documents',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['*'],
            conditions: { ArrayContains: { 'principal.departments': [s.engineering.id] } },
          },
          {
            effect: 'allow',
            actions: ['documents:write'],
            resources: ['*'],
            conditions: { StringEquals: { 'principal.departmentId': '${resource.departmentId}' } },
          },
        ],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: s.carol.id,
    });
    const carol = await s.f.signIn('carol');
    const check = async (action: string, departmentId: string) =>
      (
        await s.f.iam.authorize({
          token: carol.token,
          tenantId: s.tenantId,
          action,
          resource: { type: 'documents', id: `doc-${departmentId}` },
        })
      ).allowed;
    expect(await check('documents:read', 'x')).toBe(false);
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platform.id,
      identityIds: [s.carol.id],
    });
    // Platform sits under Engineering.
    expect(await check('documents:read', 'x')).toBe(true);
    // A policy variable compares the person's own department with the resource's.
    expect(await check('documents:write', s.platform.id)).toBe(true);
    expect(await check('documents:write', s.engineering.id)).toBe(false);
  });

  it('imports departments from an identity attribute', async () => {
    const s = await scenario();
    for (const [person, value] of [
      [s.carol, 'eng'],
      [s.dave, 'Sales'],
      [s.bob, 'Platform'],
    ] as const)
      await s.f.iam.api.identities.update(s.owner, {
        tenantId: s.tenantId,
        identityId: person.id,
        attributes: { department: value },
      });
    const preview = await s.f.iam.api.departments.importFromAttribute(s.owner, {
      tenantId: s.tenantId,
      attribute: 'department',
      dryRun: true,
    });
    expect(preview).toMatchObject({
      dryRun: true,
      created: [],
      assigned: 2,
      unmatched: ['Sales'],
    });
    expect(
      await s.f.iam.api.departments.ofIdentity(s.owner, {
        tenantId: s.tenantId,
        identityId: s.carol.id,
      }),
    ).toBeNull();
    const applied = await s.f.iam.api.departments.importFromAttribute(s.owner, {
      tenantId: s.tenantId,
      attribute: 'department',
      createMissing: true,
    });
    expect(applied).toMatchObject({ created: ['Sales'], assigned: 3, unmatched: [] });
    const again = await s.f.iam.api.departments.importFromAttribute(s.owner, {
      tenantId: s.tenantId,
      attribute: 'department',
    });
    expect(again).toMatchObject({ assigned: 0, unchanged: 3 });
    await expect(
      s.f.iam.api.departments.importFromAttribute(s.owner, {
        tenantId: s.tenantId,
        attribute: 'title',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('turns department heads into managers without creating cycles', async () => {
    const s = await scenario();
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.engineering.id,
      identityIds: [s.alice.id],
    });
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platform.id,
      identityIds: [s.bob.id, s.carol.id, s.dave.id],
    });
    // Dave already reports to Alice; without overwrite he keeps her.
    await s.f.iam.api.identities.update(s.owner, {
      tenantId: s.tenantId,
      identityId: s.dave.id,
      managerId: s.alice.id,
    });
    const preview = await s.f.iam.api.departments.syncManagers(s.owner, {
      tenantId: s.tenantId,
      dryRun: true,
    });
    expect(preview).toMatchObject({ dryRun: true, kept: 1, noHead: 1 });
    expect(preview.updated.map((item) => `${item.name} -> ${item.managerName}`).sort()).toEqual([
      'bob -> alice',
      'carol -> bob',
    ]);
    expect(preview.updated.find((item) => item.name === 'carol')).toMatchObject({
      identityId: s.carol.id,
      managerId: s.bob.id,
    });
    await s.f.iam.api.departments.syncManagers(s.owner, { tenantId: s.tenantId });
    const reports = await s.f.iam.api.identities.listReports(s.owner, {
      tenantId: s.tenantId,
      identityId: s.bob.id,
    });
    expect(reports.map((report) => report.id)).toEqual([s.carol.id]);
    const forced = await s.f.iam.api.departments.syncManagers(s.owner, {
      tenantId: s.tenantId,
      overwrite: true,
    });
    expect(forced.updated).toEqual([
      { identityId: s.dave.id, name: 'dave', managerId: s.bob.id, managerName: 'bob' },
    ]);
  });

  it('deletes departments, unassigning people and unfiling teams, and hands heads over on offboarding', async () => {
    const s = await scenario();
    await expect(
      s.f.iam.api.departments.delete(s.owner, {
        tenantId: s.tenantId,
        departmentId: s.engineering.id,
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platform.id,
      identityIds: [s.carol.id],
    });
    const team = await s.f.iam.api.teams.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Build',
      departmentId: s.platform.id,
    });
    expect(team.department).toMatchObject({ name: 'Platform' });
    const platform = await s.f.iam.api.departments.get(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platform.id,
    });
    expect(platform.teams.map((item) => item.slug)).toEqual(['build']);

    const owner = await s.f.ownerSignIn();
    const offboarded = await s.f.iam.api.identities.offboard(owner, {
      tenantId: s.tenantId,
      identityId: s.bob.id,
      reason: 'Moved on',
      successorId: s.dave.id,
    });
    expect(offboarded).toMatchObject({ departmentsReassigned: 1 });
    expect(
      (
        await s.f.iam.api.departments.get(owner, {
          tenantId: s.tenantId,
          departmentId: s.platform.id,
        })
      ).head,
    ).toMatchObject({ id: s.dave.id });

    const removed = await s.f.iam.api.departments.delete(owner, {
      tenantId: s.tenantId,
      departmentId: s.platform.id,
    });
    expect(removed).toEqual({ deleted: true, unassigned: 1, teams: 1 });
    const build = await s.f.iam.api.teams.get(owner, { tenantId: s.tenantId, teamId: team.id });
    expect(build.departmentId).toBeUndefined();
    await s.f.iam.api.identities.delete(owner, { tenantId: s.tenantId, identityId: s.alice.id });
    expect(
      (
        await s.f.iam.api.departments.get(owner, {
          tenantId: s.tenantId,
          departmentId: s.engineering.id,
        })
      ).head,
    ).toBeUndefined();
  });

  it('shows people their own department and heads the people they lead', async () => {
    const s = await scenario();
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.engineering.id,
      identityIds: [s.alice.id],
    });
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platform.id,
      identityIds: [s.bob.id, s.carol.id],
      title: 'Engineer',
    });
    const carol = await s.f.signIn('carol');
    const mine = await s.f.iam.api.departments.mine(carol, { tenantId: s.tenantId });
    expect(mine.leads).toEqual([]);
    expect(mine.department).toMatchObject({
      department: { name: 'Platform' },
      title: 'Engineer',
      head: { id: s.bob.id },
    });
    expect(mine.department!.path.map((step) => step.name)).toEqual(['Engineering', 'Platform']);
    // Alice heads Engineering, so she sees everyone in it and in Platform below it.
    const alice = await s.f.signIn('alice');
    const leads = (await s.f.iam.api.departments.mine(alice, { tenantId: s.tenantId })).leads;
    expect(leads.map((lead) => lead.department.name)).toEqual(['Engineering']);
    expect(leads[0]!.people.map((person) => `${person.name}:${person.department.name}`)).toEqual([
      'alice:Engineering',
      'bob:Platform',
      'carol:Platform',
    ]);
    // Dave has no department and leads none.
    const dave = await s.f.signIn('dave');
    expect(await s.f.iam.api.departments.mine(dave, { tenantId: s.tenantId })).toEqual({
      department: null,
      leads: [],
    });
  });

  it('keeps reads and changes behind their permissions', async () => {
    const s = await scenario();
    const carol = await s.f.signIn('carol');
    await expect(
      s.f.iam.api.departments.list(carol, { tenantId: s.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      s.f.iam.api.departments.create(carol, { tenantId: s.tenantId, name: 'Shadow IT' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});
