import { afterEach, describe, expect, it } from 'vitest';
import type { TenantConfig } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const people = {
    alice: await f.member('alice'),
    bob: await f.member('bob'),
    carol: await f.member('carol'),
    dave: await f.member('dave'),
  };
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
  return { f, tenantId, owner, people, reader, writer };
}

const base: TenantConfig = {
  version: 1,
  departments: [
    { name: 'Engineering', code: 'ENG', head: 'alice@acme.test', members: ['alice@acme.test'] },
    {
      name: 'Platform',
      parent: 'Engineering',
      head: 'bob@acme.test',
      costCenter: 'CC-7',
      members: ['bob@acme.test', 'carol@acme.test'],
    },
  ],
  teams: [
    {
      name: 'Site Reliability',
      slug: 'sre',
      parent: 'platform',
      members: ['carol@acme.test'],
    },
    {
      name: 'Platform',
      slug: 'platform',
      department: 'Platform',
      joinPolicy: 'request',
      maintainers: ['bob@acme.test'],
      members: ['alice@acme.test'],
      roles: ['Reader'],
    },
  ],
};

describe('configuration as code for teams and departments', () => {
  it('applies teams and departments from a document and exports them back unchanged', async () => {
    const s = await scenario();
    const plan = await s.f.iam.api.config.plan(s.owner, { tenantId: s.tenantId, config: base });
    expect(
      plan.changes
        .filter((change) => change.kind === 'team' || change.kind === 'department')
        .map((change) => `${change.kind}:${change.name}:${change.action}`),
    ).toEqual([
      'department:Engineering:create',
      'department:Platform:create',
      'team:platform:create',
      'team:sre:create',
    ]);
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: base });

    const teams = await s.f.iam.api.teams.list(s.owner, { tenantId: s.tenantId });
    const platform = teams.find((team) => team.slug === 'platform')!;
    const sre = teams.find((team) => team.slug === 'sre')!;
    expect(sre.parentId).toBe(platform.id);
    expect(platform).toMatchObject({ joinPolicy: 'request', memberCount: 2, maintainerCount: 1 });
    const detail = await s.f.iam.api.teams.get(s.owner, {
      tenantId: s.tenantId,
      teamId: platform.id,
    });
    expect(detail.department?.name).toBe('Platform');
    expect(detail.roles.map((grant) => grant.roleName)).toEqual(['Reader']);
    // Carol is in SRE, so she holds Reader through Platform.
    const carol = await s.f.signIn('carol');
    expect(
      (
        await s.f.iam.authorize({
          token: carol.token,
          tenantId: s.tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed,
    ).toBe(true);
    const tree = await s.f.iam.api.departments.tree(s.owner, { tenantId: s.tenantId });
    expect(tree[0]).toMatchObject({ name: 'Engineering', head: { name: 'alice' } });
    expect(tree[0]!.children[0]).toMatchObject({
      name: 'Platform',
      costCenter: 'CC-7',
      memberCount: 2,
    });

    const exported = await s.f.iam.api.config.export(s.owner, { tenantId: s.tenantId });
    expect(exported.teams?.find((team) => team.slug === 'platform')).toEqual({
      name: 'Platform',
      slug: 'platform',
      department: 'Platform',
      joinPolicy: 'request',
      memberManagement: 'maintainers',
      maintainers: ['bob@acme.test'],
      members: ['alice@acme.test'],
      roles: ['Reader'],
    });
    expect(exported.departments?.map((department) => department.name)).toEqual([
      'Engineering',
      'Platform',
    ]);
    const again = await s.f.iam.api.config.plan(s.owner, {
      tenantId: s.tenantId,
      config: exported,
      prune: true,
    });
    expect(again.changes.filter((change) => change.action !== 'unchanged')).toEqual([]);
  });

  it('updates membership, roles, settings, and structure, and prunes what the document omits', async () => {
    const s = await scenario();
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: base });
    const next: TenantConfig = {
      version: 1,
      departments: [
        { name: 'Engineering', code: 'ENG', head: 'alice@acme.test', members: ['alice@acme.test'] },
      ],
      teams: [
        {
          name: 'Platform Engineering',
          slug: 'platform',
          joinPolicy: 'closed',
          maintainers: ['alice@acme.test'],
          members: ['bob@acme.test', 'dave@acme.test'],
          roles: ['Writer'],
        },
      ],
    };
    const plan = await s.f.iam.api.config.plan(s.owner, {
      tenantId: s.tenantId,
      config: next,
      prune: true,
    });
    const platform = plan.changes.find(
      (change) => change.kind === 'team' && change.name === 'platform',
    );
    expect(platform).toMatchObject({ action: 'update' });
    expect(platform!.fields).toEqual(
      expect.arrayContaining([
        'department',
        'joinPolicy',
        'maintainers',
        'members',
        'name',
        'roles',
      ]),
    );
    expect(
      plan.changes
        .filter((change) => change.action === 'delete')
        .map((change) => `${change.kind}:${change.name}`)
        .sort(),
    ).toEqual(['department:Platform', 'team:sre']);
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: next, prune: true });

    const teams = await s.f.iam.api.teams.list(s.owner, { tenantId: s.tenantId });
    expect(teams.map((team) => team.slug)).toEqual(['platform']);
    const members = await s.f.iam.api.teams.listMembers(s.owner, {
      tenantId: s.tenantId,
      teamId: teams[0]!.id,
    });
    expect(members.map((member) => `${member.name}:${member.role}`).sort()).toEqual([
      'alice:maintainer',
      'bob:member',
      'dave:member',
    ]);
    const detail = await s.f.iam.api.teams.get(s.owner, {
      tenantId: s.tenantId,
      teamId: teams[0]!.id,
    });
    expect(detail).toMatchObject({ name: 'Platform Engineering', joinPolicy: 'closed' });
    expect(detail.department).toBeUndefined();
    expect(detail.roles.map((grant) => grant.roleName)).toEqual(['Writer']);
    const departments = await s.f.iam.api.departments.list(s.owner, { tenantId: s.tenantId });
    expect(departments.map((department) => department.name)).toEqual(['Engineering']);
    // Bob and Carol lost their department with Platform.
    expect(
      await s.f.iam.api.departments.ofIdentity(s.owner, {
        tenantId: s.tenantId,
        identityId: s.people.bob.id,
      }),
    ).toBeNull();
    const converged = await s.f.iam.api.config.plan(s.owner, {
      tenantId: s.tenantId,
      config: next,
      prune: true,
    });
    expect(converged.changes.filter((change) => change.action !== 'unchanged')).toEqual([]);
  });

  it('configures team sync by group name and keeps synced members out of the document', async () => {
    const s = await scenario();
    const document: TenantConfig = {
      version: 1,
      groups: [{ name: 'Okta: Engineers', members: ['carol@acme.test', 'dave@acme.test'] }],
      teams: [
        {
          name: 'Engineers',
          slug: 'engineers',
          syncGroups: ['Okta: Engineers'],
          maintainers: ['alice@acme.test'],
        },
      ],
    };
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: document });
    const team = (await s.f.iam.api.teams.list(s.owner, { tenantId: s.tenantId }))[0]!;
    const members = await s.f.iam.api.teams.listMembers(s.owner, {
      tenantId: s.tenantId,
      teamId: team.id,
    });
    expect(members.map((member) => `${member.name}:${member.source ?? 'manual'}`).sort()).toEqual([
      'alice:manual',
      'carol:sync',
      'dave:sync',
    ]);
    const exported = await s.f.iam.api.config.export(s.owner, { tenantId: s.tenantId });
    expect(exported.teams).toEqual([
      expect.objectContaining({
        slug: 'engineers',
        syncGroups: ['Okta: Engineers'],
        maintainers: ['alice@acme.test'],
        members: [],
      }),
    ]);
    const converged = await s.f.iam.api.config.plan(s.owner, {
      tenantId: s.tenantId,
      config: exported,
      prune: true,
    });
    expect(converged.changes.filter((change) => change.action !== 'unchanged')).toEqual([]);
    // Dropping the source stops syncing: the synced members go, the manual maintainer stays.
    await s.f.iam.api.config.apply(s.owner, {
      tenantId: s.tenantId,
      config: {
        version: 1,
        teams: [
          {
            name: 'Engineers',
            slug: 'engineers',
            syncGroups: [],
            maintainers: ['alice@acme.test'],
          },
        ],
      },
    });
    expect(
      (await s.f.iam.api.teams.listMembers(s.owner, { tenantId: s.tenantId, teamId: team.id })).map(
        (member) => member.name,
      ),
    ).toEqual(['alice']);
    await expect(
      s.f.iam.api.config.plan(s.owner, {
        tenantId: s.tenantId,
        config: { version: 1, teams: [{ name: 'X', slug: 'x', syncGroups: ['Nope'] }] },
      }),
    ).rejects.toThrow(/unknown sync group/);
  });

  it('leaves temporary memberships alone and rejects dangling references', async () => {
    const s = await scenario();
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: base });
    const team = (await s.f.iam.api.teams.list(s.owner, { tenantId: s.tenantId })).find(
      (item) => item.slug === 'platform',
    )!;
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: team.id,
      identityId: s.people.dave.id,
      expiresAt: s.f.now() + 86_400_000,
    });
    const plan = await s.f.iam.api.config.plan(s.owner, { tenantId: s.tenantId, config: base });
    expect(plan.changes.filter((change) => change.action !== 'unchanged')).toEqual([]);
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: base });
    const members = await s.f.iam.api.teams.listMembers(s.owner, {
      tenantId: s.tenantId,
      teamId: team.id,
    });
    expect(members.some((member) => member.name === 'dave')).toBe(true);

    const broken = (patch: Partial<NonNullable<TenantConfig['teams']>[number]>) => ({
      version: 1 as const,
      teams: [{ name: 'Data', slug: 'data', ...patch }],
    });
    for (const [patch, message] of [
      [{ members: ['nobody@acme.test'] }, /unknown person/],
      [{ roles: ['Missing'] }, /unknown role/],
      [{ parent: 'ghost' }, /unknown parent/],
      [{ department: 'Nowhere' }, /unknown department/],
      [
        { maintainers: ['bob@acme.test'], members: ['bob@acme.test'] },
        /both maintainer and member/,
      ],
    ] as const)
      await expect(
        s.f.iam.api.config.plan(s.owner, { tenantId: s.tenantId, config: broken(patch) }),
      ).rejects.toThrow(message);
    await expect(
      s.f.iam.api.config.plan(s.owner, {
        tenantId: s.tenantId,
        config: {
          version: 1,
          teams: [
            { name: 'A', slug: 'a', parent: 'b' },
            { name: 'B', slug: 'b', parent: 'a' },
          ],
        },
      }),
    ).rejects.toThrow(/cycle/);
  });
});
