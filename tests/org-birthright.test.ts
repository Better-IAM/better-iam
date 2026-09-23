import { afterEach, describe, expect, it } from 'vitest';
import type { TenantConfig } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const [alice, bob, carol, dave] = [
    await f.member('alice'),
    await f.member('bob'),
    await f.member('carol'),
    await f.member('dave'),
  ];
  const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Wiki editors' });
  const engineering = await f.iam.api.departments.create(owner, { tenantId, name: 'Engineering' });
  const platformDepartment = await f.iam.api.departments.create(owner, {
    tenantId,
    name: 'Platform',
    parentId: engineering.id,
  });
  const platform = await f.iam.api.teams.create(owner, { tenantId, name: 'Platform' });
  const sre = await f.iam.api.teams.create(owner, {
    tenantId,
    name: 'Site Reliability',
    slug: 'sre',
    parentId: platform.id,
  });
  const holders = async (packageId: string) =>
    (await f.iam.api.packages.listAssignments(owner, { tenantId, packageId, source: 'automatic' }))
      .map((assignment) => assignment.identityId)
      .sort();
  return {
    f,
    tenantId,
    owner,
    alice,
    bob,
    carol,
    dave,
    wiki,
    engineering,
    platformDepartment,
    platform,
    sre,
    holders,
  };
}

const people = { StringEquals: { 'principal.kind': 'user' } } as const;

describe('birthright packages by team and department', () => {
  it('grants a package to a department and the departments below it, as people join and leave', async () => {
    const s = await scenario();
    const pkg = await s.f.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Engineering basics',
      groupIds: [s.wiki.id],
      autoAssign: {
        include: [{ ...people, ArrayContains: { 'identity.departments': [s.engineering.id] } }],
      },
    });
    expect(await s.holders(pkg.id)).toEqual([]);
    const preview = await s.f.iam.api.packages.previewAutoAssign(s.owner, {
      tenantId: s.tenantId,
    });
    expect(preview.keys.map((key) => key.key)).toEqual(
      expect.arrayContaining(['identity.teams', 'identity.departments']),
    );

    // Placing people re-evaluates the rule at once: a sub-department counts for Engineering.
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platformDepartment.id,
      identityIds: [s.carol.id, s.dave.id],
    });
    expect(await s.holders(pkg.id)).toEqual([s.carol.id, s.dave.id].sort());
    const groupMembers = await s.f.iam.api.groups.listMembers(s.owner, {
      tenantId: s.tenantId,
      groupId: s.wiki.id,
    });
    expect(groupMembers.map((member) => member.id)).toEqual(
      expect.arrayContaining([s.carol.id, s.dave.id]),
    );

    // Leavers lose it (no grace period), and so does everyone when their department moves out from under Engineering.
    await s.f.iam.api.departments.unassign(s.owner, {
      tenantId: s.tenantId,
      identityId: s.carol.id,
    });
    expect(await s.holders(pkg.id)).toEqual([s.dave.id]);
    await s.f.iam.api.departments.update(s.owner, {
      tenantId: s.tenantId,
      departmentId: s.platformDepartment.id,
      parentId: null,
    });
    expect(await s.holders(pkg.id)).toEqual([]);

    // A department a rule names stays until the rule stops naming it.
    await expect(
      s.f.iam.api.departments.delete(s.owner, {
        tenantId: s.tenantId,
        departmentId: s.engineering.id,
      }),
    ).rejects.toMatchObject({
      code: 'RESOURCE_IN_USE',
      message: expect.stringContaining('Engineering basics'),
    });
  });

  it('matches members of a team and of the teams below it, but not memberships a package created', async () => {
    const s = await scenario();
    const pkg = await s.f.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Platform tools',
      groupIds: [s.wiki.id],
      autoAssign: {
        include: [{ ...people, ArrayContains: { 'identity.teams': [s.platform.id] } }],
      },
    });
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    expect(await s.holders(pkg.id)).toEqual([s.alice.id]);
    await s.f.iam.api.teams.removeMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    expect(await s.holders(pkg.id)).toEqual([]);

    // A team synced from a group: a membership of the source group counts only when no package created it.
    const contractors = await s.f.iam.api.groups.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Contractors',
    });
    const kit = await s.f.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Contractor kit',
      groupIds: [contractors.id],
    });
    const vendors = await s.f.iam.api.teams.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Vendors',
      parentId: s.platform.id,
      syncGroupIds: [contractors.id],
    });
    await s.f.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: kit.id,
      identityId: s.bob.id,
    });
    await s.f.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: contractors.id,
      identityId: s.carol.id,
    });
    const synced = await s.f.iam.api.teams.listMembers(s.owner, {
      tenantId: s.tenantId,
      teamId: vendors.id,
    });
    expect(synced.map((member) => member.id).sort()).toEqual([s.bob.id, s.carol.id].sort());
    await s.f.iam.api.packages.reconcile(s.owner, { tenantId: s.tenantId, packageId: pkg.id });
    expect(await s.holders(pkg.id)).toEqual([s.carol.id]);

    // Teams no rule names can go; the one the rule names stays until the rule stops naming it.
    await expect(
      s.f.iam.api.teams.delete(s.owner, { tenantId: s.tenantId, teamId: vendors.id }),
    ).resolves.toMatchObject({ deleted: true });
    await expect(
      s.f.iam.api.teams.delete(s.owner, { tenantId: s.tenantId, teamId: s.sre.id }),
    ).resolves.toMatchObject({ deleted: true });
    await expect(
      s.f.iam.api.teams.delete(s.owner, { tenantId: s.tenantId, teamId: s.platform.id }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
  });

  it('validates the teams and departments a rule names', async () => {
    const s = await scenario();
    const create = (conditions: Record<string, unknown>) =>
      s.f.iam.api.packages.create(s.owner, {
        tenantId: s.tenantId,
        name: 'Checked',
        groupIds: [s.wiki.id],
        autoAssign: { include: [{ ...people, ...conditions }] } as never,
      });
    await expect(
      create({ ArrayContains: { 'identity.teams': ['no-such-team'] } }),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('unknown team'),
    });
    await expect(
      create({ ArrayContains: { 'identity.departments': [s.platform.id] } }),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('unknown department'),
    });
    await expect(
      create({ StringEquals: { 'identity.teams': s.platform.id } }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(create({ Exists: { 'identity.departments': true } })).resolves.toMatchObject({
      name: 'Checked',
    });
  });

  it('names teams by slug and departments by name in configuration documents', async () => {
    const s = await scenario();
    const config: TenantConfig = {
      version: 1,
      departments: [
        { name: 'Engineering' },
        { name: 'Platform', parent: 'Engineering' },
        { name: 'Data' },
      ],
      teams: [
        { name: 'Platform', slug: 'platform' },
        { name: 'Site Reliability', slug: 'sre', parent: 'platform' },
        { name: 'Analytics', slug: 'analytics' },
      ],
      groups: [{ name: 'Wiki editors' }],
      packages: [
        {
          name: 'Org kit',
          groups: ['Wiki editors'],
          autoAssign: {
            include: [
              { ...people, ArrayContains: { 'identity.teams': ['analytics'] } },
              { ...people, ArrayContains: { 'identity.departments': ['data'] } },
            ],
          },
        },
      ],
    };
    const plan = await s.f.iam.api.config.plan(s.owner, { tenantId: s.tenantId, config });
    expect(
      plan.changes
        .filter((change) => change.action !== 'unchanged')
        .map((change) => `${change.kind}:${change.name}:${change.action}`)
        .sort(),
    ).toEqual(['department:Data:create', 'package:Org kit:create', 'team:analytics:create'].sort());
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config });
    const stored = (await s.f.iam.api.packages.list(s.owner, { tenantId: s.tenantId })).find(
      (pkg) => pkg.name === 'Org kit',
    )!;
    const analytics = (await s.f.iam.api.teams.list(s.owner, { tenantId: s.tenantId })).find(
      (team) => team.slug === 'analytics',
    )!;
    const data = (await s.f.iam.api.departments.list(s.owner, { tenantId: s.tenantId })).find(
      (department) => department.name === 'Data',
    )!;
    expect(stored.autoAssign?.include).toEqual([
      { ...people, ArrayContains: { 'identity.teams': [analytics.id] } },
      { ...people, ArrayContains: { 'identity.departments': [data.id] } },
    ]);
    expect(stored.autoAssign?.status).toBe('active');
    const exported = await s.f.iam.api.config.export(s.owner, { tenantId: s.tenantId });
    expect(exported.packages?.find((pkg) => pkg.name === 'Org kit')?.autoAssign).toEqual({
      include: [
        { ...people, ArrayContains: { 'identity.teams': ['analytics'] } },
        { ...people, ArrayContains: { 'identity.departments': ['Data'] } },
      ],
    });
    // The spelling of the department does not matter, and the document now matches the tenant.
    const again = await s.f.iam.api.config.plan(s.owner, { tenantId: s.tenantId, config });
    expect(again.changes.every((change) => change.action === 'unchanged')).toBe(true);

    // People placed through the API get the package.
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: data.id,
      identityId: s.dave.id,
    });
    expect(await s.holders(stored.id)).toEqual([s.dave.id]);

    // Unknown names fail the plan; removing a team and the rule that names it in one document works.
    await expect(
      s.f.iam.api.config.plan(s.owner, {
        tenantId: s.tenantId,
        config: {
          ...config,
          packages: [
            {
              ...config.packages![0]!,
              autoAssign: {
                include: [{ ...people, ArrayContains: { 'identity.teams': ['nope'] } }],
              },
            },
          ],
        },
      }),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('unknown team nope'),
    });
    await s.f.iam.api.config.apply(s.owner, {
      tenantId: s.tenantId,
      prune: true,
      config: {
        ...config,
        teams: config.teams!.filter((team) => team.slug !== 'analytics'),
        packages: [
          {
            ...config.packages![0]!,
            autoAssign: {
              include: [{ ...people, ArrayContains: { 'identity.departments': ['Data'] } }],
            },
          },
        ],
      },
    });
    expect(
      (await s.f.iam.api.teams.list(s.owner, { tenantId: s.tenantId })).map((team) => team.slug),
    ).not.toContain('analytics');
  });
  it('suggests birthright packages from the access most of a department or team already holds', async () => {
    const s = await scenario();
    const { f, tenantId, owner } = s;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['iam:resources:read'],
    });
    const writer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Writer',
      permissions: ['iam:resources:read'],
    });
    // Engineering: Dave directly; Platform (below it): Alice, Bob, Carol.
    await f.iam.api.departments.assign(owner, {
      tenantId,
      departmentId: s.platformDepartment.id,
      identityIds: [s.alice.id, s.bob.id, s.carol.id],
    });
    await f.iam.api.departments.assign(owner, {
      tenantId,
      departmentId: s.engineering.id,
      identityId: s.dave.id,
    });
    for (const person of [s.alice, s.bob, s.carol, s.dave])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: reader.id,
        subjectType: 'identity',
        subjectId: person.id,
      });
    for (const person of [s.alice, s.bob])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: writer.id,
        subjectType: 'identity',
        subjectId: person.id,
      });
    for (const person of [s.alice, s.bob, s.carol])
      await f.iam.api.groups.addMember(owner, {
        tenantId,
        groupId: s.wiki.id,
        identityId: person.id,
      });

    const suggestions = await f.iam.api.departments.suggestBirthright(owner, { tenantId });
    expect(
      suggestions.map((item) => ({
        unit: item.unit.name,
        people: item.people,
        roles: item.roles.map((role) => role.name),
        groups: item.groups.map((group) => `${group.name} ${group.share}`),
        wouldGrant: item.wouldGrant,
      })),
    ).toEqual([
      // Everyone in Engineering (with Platform) reads; Platform adds only what Engineering does not.
      { unit: 'Engineering', people: 4, roles: ['Reader'], groups: [], wouldGrant: 0 },
      { unit: 'Platform', people: 3, roles: [], groups: ['Wiki editors 1'], wouldGrant: 0 },
    ]);
    const lower = await f.iam.api.departments.suggestBirthright(owner, {
      tenantId,
      departmentId: s.platformDepartment.id,
      minShare: 0.6,
    });
    expect(lower).toHaveLength(1);
    expect(lower[0]!.roles.map((role) => `${role.name} ${role.share}`)).toEqual(['Writer 0.67']);
    expect(lower[0]!.wouldGrant).toBe(1);

    // The suggested package is ready to create; afterwards its contents are covered.
    const engineering = suggestions[0]!;
    const created = await f.iam.api.packages.create(owner, { tenantId, ...engineering.package });
    expect(created.autoAssign).toMatchObject({ status: 'active' });
    expect(await s.holders(created.id)).toEqual(
      [s.alice.id, s.bob.id, s.carol.id, s.dave.id].sort(),
    );
    const after = await f.iam.api.departments.suggestBirthright(owner, { tenantId });
    expect(after.map((item) => item.unit.name)).toEqual(['Platform']);
    expect(after[0]!.existingPackages).toEqual([engineering.package.name]);

    // Teams: Platform with SRE below it.
    await f.iam.api.teams.addMembers(owner, {
      tenantId,
      teamId: s.sre.id,
      identityIds: [s.alice.id, s.bob.id, s.carol.id],
    });
    // SRE's members also count for Platform above it, so the suggestion goes to Platform and SRE does not repeat it.
    const teams = await f.iam.api.teams.suggestBirthright(owner, { tenantId });
    expect(teams.map((item) => [item.unit.name, item.groups.map((group) => group.name)])).toEqual([
      ['Platform', ['Wiki editors']],
    ]);
    expect(await f.iam.api.teams.suggestBirthright(owner, { tenantId, teamId: s.sre.id })).toEqual(
      [],
    );
    const team = teams[0]!;
    // The Reader role now comes from the package, so only hand-granted access counts.
    expect(team.roles).toEqual([]);
    expect(team.package.autoAssign.include).toEqual([
      {
        StringEquals: { 'principal.kind': 'user' },
        ArrayContains: { 'identity.teams': [s.platform.id] },
      },
    ]);
    // Analysis permission required.
    const carol = await f.signIn('carol');
    await expect(
      f.iam.api.departments.suggestBirthright({ token: carol.token }, { tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.teams.suggestBirthright(owner, { tenantId, minShare: 0.2 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
