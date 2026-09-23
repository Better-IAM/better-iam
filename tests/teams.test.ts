import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';
import { teamsOf, isTeamMaintainer, primaryTeamOf, teamMaintainers } from '@better-iam/server';

afterEach(closeFixtures);

const doc = { type: 'documents', id: 'a' };

async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const alice = await f.member('alice');
  const bob = await f.member('bob');
  const carol = await f.member('carol');
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
  const platform = await f.iam.api.teams.create(owner, {
    tenantId,
    name: 'Platform',
    description: 'Runs the platform',
    maintainerIds: [bob.id],
  });
  const sre = await f.iam.api.teams.create(owner, {
    tenantId,
    name: 'Site Reliability',
    slug: 'sre',
    parentId: platform.id,
  });
  const can = async (token: string, action = 'documents:read') =>
    (await f.iam.authorize({ token, tenantId, action, resource: doc })).allowed;
  return { f, tenantId, owner, alice, bob, carol, reader, writer, platform, sre, can };
}

describe('teams', () => {
  it('creates nested teams with backing groups and derived slugs', async () => {
    const s = await scenario();
    expect(s.platform).toMatchObject({
      name: 'Platform',
      slug: 'platform',
      joinPolicy: 'closed',
      memberManagement: 'maintainers',
      memberCount: 1,
      maintainerCount: 1,
      path: [],
    });
    expect(s.platform.maintainers.map((person) => person.id)).toEqual([s.bob.id]);
    expect(s.sre).toMatchObject({ slug: 'sre', parentId: s.platform.id });
    expect(s.sre.path.map((step) => step.slug)).toEqual(['platform']);
    const group = await s.f.iam.api.groups.get(s.owner, {
      tenantId: s.tenantId,
      groupId: s.platform.groupId,
    });
    expect(group).toMatchObject({ name: 'team:platform', teamId: s.platform.id });
    await expect(
      s.f.iam.api.teams.create(s.owner, { tenantId: s.tenantId, name: 'platform' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const list = await s.f.iam.api.teams.list(s.owner, { tenantId: s.tenantId });
    expect(list.map((team) => [team.slug, team.childCount])).toEqual([
      ['platform', 1],
      ['sre', 0],
    ]);
    expect(
      (await s.f.iam.api.teams.list(s.owner, { tenantId: s.tenantId, parentId: null })).map(
        (team) => team.slug,
      ),
    ).toEqual(['platform']);
  });

  it('gives child-team members the parent team’s roles through the backing groups', async () => {
    const s = await scenario();
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'group',
      subjectId: s.platform.groupId,
    });
    const alice = await s.f.signIn('alice');
    expect(await s.can(alice.token)).toBe(false);
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    expect(await s.can(alice.token)).toBe(true);
    const detail = await s.f.iam.api.teams.get(s.owner, { tenantId: s.tenantId, teamId: s.sre.id });
    expect(detail.roles).toEqual([
      expect.objectContaining({
        roleName: 'Reader',
        inherited: true,
        team: expect.objectContaining({ slug: 'platform' }),
      }),
    ]);
    const platform = await s.f.iam.api.teams.get(s.owner, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
    });
    // Bob directly, Alice through SRE.
    expect(platform.totalMemberCount).toBe(2);
    expect(platform.memberCount).toBe(1);
    const members = await s.f.iam.api.teams.listMembers(s.owner, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
      includeChildTeams: true,
    });
    expect(members.map((member) => [member.name, member.role, member.team.slug])).toEqual([
      ['bob', 'maintainer', 'platform'],
      ['alice', 'member', 'sre'],
    ]);

    // Helpers other modules use (billing attributes spend with them).
    const store = s.f.iam.store;
    await store.transaction(async (tx) => {
      expect(await teamsOf(tx, s.tenantId, s.alice.id)).toEqual([s.sre.id]);
      expect(
        (await teamsOf(tx, s.tenantId, s.alice.id, { includeAncestors: true })).sort(),
      ).toEqual([s.platform.id, s.sre.id].sort());
      expect(await primaryTeamOf(tx, s.tenantId, s.alice.id)).toBe(s.sre.id);
      expect(await teamMaintainers(tx, s.tenantId, s.platform.id)).toEqual([s.bob.id]);
      expect(await isTeamMaintainer(tx, s.tenantId, s.sre.id, s.bob.id)).toBe(false);
      expect(
        await isTeamMaintainer(tx, s.tenantId, s.sre.id, s.bob.id, { includeAncestors: true }),
      ).toBe(true);
    });

    await s.f.iam.api.teams.removeMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    expect(await s.can(alice.token)).toBe(false);
  });

  it('lets maintainers manage membership without an administrator permission', async () => {
    const s = await scenario();
    const bob = await s.f.signIn('bob');
    // Bob maintains Platform, so he manages SRE below it too.
    await s.f.iam.api.teams.addMember(bob, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.carol.id,
      role: 'maintainer',
    });
    const carol = await s.f.signIn('carol');
    await s.f.iam.api.teams.addMember(carol, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    // Carol maintains SRE, not Platform.
    await expect(
      s.f.iam.api.teams.addMember(carol, {
        tenantId: s.tenantId,
        teamId: s.platform.id,
        identityId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Settings stay with administrators.
    await expect(
      s.f.iam.api.teams.update(bob, { tenantId: s.tenantId, teamId: s.sre.id, name: 'Ops' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const added = await s.f.iam.api.audit.list(s.owner, {
      tenantId: s.tenantId,
      action: 'team:member:add',
    });
    expect(added.filter((event) => event.metadata?.via === 'maintainer')).toHaveLength(2);
    const updates = await s.f.iam.api.audit.list(s.owner, {
      tenantId: s.tenantId,
      action: 'iam:teams:update',
    });
    expect(
      updates.some(
        (event) => event.outcome === 'allow' && event.metadata?.via === 'team-maintainer',
      ),
    ).toBe(true);

    // With memberManagement 'admins' maintainers are refused.
    await s.f.iam.api.teams.update(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      memberManagement: 'admins',
    });
    await expect(
      s.f.iam.api.teams.removeMember(carol, {
        tenantId: s.tenantId,
        teamId: s.sre.id,
        identityId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('lets members read their own team but not others', async () => {
    const s = await scenario();
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    const other = await s.f.iam.api.teams.create(s.owner, { tenantId: s.tenantId, name: 'Sales' });
    const alice = await s.f.signIn('alice');
    const own = await s.f.iam.api.teams.get(alice, { tenantId: s.tenantId, teamId: s.sre.id });
    expect(own.slug).toBe('sre');
    // Being in SRE makes Alice part of Platform as well.
    await s.f.iam.api.teams.listMembers(alice, { tenantId: s.tenantId, teamId: s.platform.id });
    await expect(
      s.f.iam.api.teams.get(alice, { tenantId: s.tenantId, teamId: other.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(s.f.iam.api.teams.list(alice, { tenantId: s.tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // Members are not maintainers.
    await expect(
      s.f.iam.api.teams.addMember(alice, {
        tenantId: s.tenantId,
        teamId: s.sre.id,
        identityId: s.carol.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('keeps team-managed groups out of the groups, packages, and invitation APIs', async () => {
    const s = await scenario();
    const { groupId } = s.platform;
    await expect(
      s.f.iam.api.groups.addMember(s.owner, {
        tenantId: s.tenantId,
        groupId,
        identityId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'TEAM_MANAGED' });
    await expect(
      s.f.iam.api.groups.removeMember(s.owner, {
        tenantId: s.tenantId,
        groupId,
        identityId: s.bob.id,
      }),
    ).rejects.toMatchObject({ code: 'TEAM_MANAGED' });
    await expect(
      s.f.iam.api.groups.delete(s.owner, { tenantId: s.tenantId, groupId }),
    ).rejects.toMatchObject({ code: 'TEAM_MANAGED' });
    await expect(
      s.f.iam.api.packages.create(s.owner, {
        tenantId: s.tenantId,
        name: 'Platform kit',
        groupIds: [groupId],
      }),
    ).rejects.toMatchObject({ code: 'TEAM_MANAGED' });
    // Configuration sync leaves team groups (and what is bound to them) alone.
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'group',
      subjectId: groupId,
    });
    const exported = await s.f.iam.api.config.export(s.owner, { tenantId: s.tenantId });
    expect(exported.groups?.some((group) => group.name.startsWith('team:'))).toBe(false);
    expect(exported.bindings ?? []).toEqual([]);
    const plan = await s.f.iam.api.config.plan(s.owner, {
      tenantId: s.tenantId,
      config: { ...exported },
      prune: true,
    });
    expect(plan.changes.filter((change) => change.action !== 'unchanged')).toEqual([]);
  });

  it('refuses cycles, overly deep nesting, and deleting a team with teams below it', async () => {
    const s = await scenario();
    await expect(
      s.f.iam.api.teams.update(s.owner, {
        tenantId: s.tenantId,
        teamId: s.platform.id,
        parentId: s.sre.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.f.iam.api.teams.delete(s.owner, { tenantId: s.tenantId, teamId: s.platform.id }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    let parent = s.sre.id;
    for (let depth = 3; depth <= 10; depth++)
      parent = (
        await s.f.iam.api.teams.create(s.owner, {
          tenantId: s.tenantId,
          name: `Level ${depth}`,
          parentId: parent,
        })
      ).id;
    await expect(
      s.f.iam.api.teams.create(s.owner, {
        tenantId: s.tenantId,
        name: 'Too deep',
        parentId: parent,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('moves a team and recomputes both parents', async () => {
    const s = await scenario();
    const other = await s.f.iam.api.teams.create(s.owner, { tenantId: s.tenantId, name: 'Data' });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'group',
      subjectId: s.platform.groupId,
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.writer.id,
      subjectType: 'group',
      subjectId: other.groupId,
    });
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    const alice = await s.f.signIn('alice');
    expect([await s.can(alice.token), await s.can(alice.token, 'documents:write')]).toEqual([
      true,
      false,
    ]);
    const moved = await s.f.iam.api.teams.update(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      parentId: other.id,
    });
    expect(moved.path.map((step) => step.slug)).toEqual(['data']);
    expect([await s.can(alice.token), await s.can(alice.token, 'documents:write')]).toEqual([
      false,
      true,
    ]);
    const top = await s.f.iam.api.teams.update(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      parentId: null,
    });
    expect(top.parentId).toBeUndefined();
    expect(await s.can(alice.token, 'documents:write')).toBe(false);
  });

  it('handles join requests end to end', async () => {
    const s = await scenario();
    await s.f.iam.api.teams.update(s.owner, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
      joinPolicy: 'request',
    });
    const alice = await s.f.signIn('alice');
    const mine = await s.f.iam.api.teams.listMine(alice, { tenantId: s.tenantId });
    expect(mine.joinable.map((team) => team.slug)).toEqual(['platform']);
    await expect(
      s.f.iam.api.teams.requestToJoin(alice, { tenantId: s.tenantId, teamId: s.sre.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const request = await s.f.iam.api.teams.requestToJoin(alice, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
      justification: 'On call next week',
    });
    expect(request).toMatchObject({ status: 'pending', justification: 'On call next week' });
    await expect(
      s.f.iam.api.teams.requestToJoin(alice, { tenantId: s.tenantId, teamId: s.platform.id }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await s.f.iam.auth.dispatchOutbox();
    const mail = s.f.inbox.find((message) => message.template === 'team-join-request');
    expect(mail).toMatchObject({ to: 'bob@acme.test' });
    expect(mail?.payload).toMatchObject({ teamName: 'Platform', requesterName: 'alice' });

    const bob = await s.f.signIn('bob');
    const pending = await s.f.iam.api.teams.listRequests(bob, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
    });
    expect(pending.map((item) => item.requester.id)).toEqual([s.alice.id]);
    const approved = await s.f.iam.api.teams.approveRequest(bob, {
      tenantId: s.tenantId,
      requestId: request.id,
      note: 'Welcome',
    });
    expect(approved).toMatchObject({ status: 'approved', decidedBy: s.bob.id, note: 'Welcome' });
    await s.f.iam.auth.dispatchOutbox();
    expect(
      s.f.inbox.find((message) => message.template === 'team-join-decided')?.payload,
    ).toMatchObject({ decision: 'approved', teamName: 'Platform' });
    const after = await s.f.iam.api.teams.listMine(alice, { tenantId: s.tenantId });
    expect(after.teams.map((team) => [team.slug, team.role])).toEqual([['platform', 'member']]);
    expect(after.joinable).toEqual([]);

    // Nobody decides their own request; carol asks, then withdraws.
    const carol = await s.f.signIn('carol');
    const second = await s.f.iam.api.teams.requestToJoin(carol, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
    });
    await expect(
      s.f.iam.api.teams.approveRequest(carol, { tenantId: s.tenantId, requestId: second.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const cancelled = await s.f.iam.api.teams.cancelRequest(carol, {
      tenantId: s.tenantId,
      requestId: second.id,
    });
    expect(cancelled.status).toBe('cancelled');
    await expect(
      s.f.iam.api.teams.denyRequest(bob, { tenantId: s.tenantId, requestId: second.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });

    // Requests lapse after fourteen days.
    const third = await s.f.iam.api.teams.requestToJoin(carol, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
    });
    s.f.advance(15 * 86_400_000);
    const late = await s.f.signIn('bob');
    await expect(
      s.f.iam.api.teams.approveRequest(late, { tenantId: s.tenantId, requestId: third.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });

    // Alice leaves.
    const aliceAgain = await s.f.signIn('alice');
    await s.f.iam.api.teams.leave(aliceAgain, { tenantId: s.tenantId, teamId: s.platform.id });
    expect((await s.f.iam.api.teams.listMine(aliceAgain, { tenantId: s.tenantId })).teams).toEqual(
      [],
    );
  });

  it('exposes principal.teams to policies, including the teams above', async () => {
    const s = await scenario();
    const role = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Platform readers',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['*'],
            conditions: { ArrayContains: { 'principal.teams': [s.platform.id] } },
          },
        ],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: s.alice.id,
    });
    const alice = await s.f.signIn('alice');
    expect(await s.can(alice.token)).toBe(false);
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    expect(await s.can(alice.token)).toBe(true);
  });

  it('enforces separation of duties across teams', async () => {
    const s = await scenario();
    const payments = await s.f.iam.api.teams.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Payments',
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'group',
      subjectId: s.platform.groupId,
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.writer.id,
      subjectType: 'group',
      subjectId: payments.groupId,
    });
    await s.f.iam.api.sod.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Readers never write',
      roleIds: [s.reader.id, s.writer.id],
    });
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: payments.id,
      identityId: s.alice.id,
    });
    await expect(
      s.f.iam.api.teams.addMember(s.owner, {
        tenantId: s.tenantId,
        teamId: s.sre.id,
        identityId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
    // The maintainer path is checked too.
    const bob = await s.f.signIn('bob');
    await expect(
      s.f.iam.api.teams.addMember(bob, {
        tenantId: s.tenantId,
        teamId: s.sre.id,
        identityId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
  });

  it('ends temporary memberships and cleans up on offboarding and deletion', async () => {
    const s = await scenario();
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'group',
      subjectId: s.platform.groupId,
    });
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
      expiresAt: s.f.now() + 3_600_000,
    });
    const alice = await s.f.signIn('alice');
    expect(await s.can(alice.token)).toBe(true);
    s.f.advance(2 * 3_600_000);
    expect(await s.can(alice.token)).toBe(false);
    // The retention sweep removes the ended membership record.
    expect((await s.f.iam.sweepExpired()).deleted.teamMembers).toBe(1);
    expect(
      await s.f.iam.store.find('teamMembers', { tenantId: s.tenantId, identityId: s.alice.id }),
    ).toEqual([]);

    await s.f.iam.api.teams.addMember(s.f.ownerCredential, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    const owner = await s.f.ownerSignIn();
    const result = await s.f.iam.api.identities.offboard(owner, {
      tenantId: s.tenantId,
      identityId: s.alice.id,
      reason: 'Left the company',
    });
    expect(result).toMatchObject({ teamsLeft: 1 });
    const group = await s.f.iam.store.find('groupMembers', {
      tenantId: s.tenantId,
      identityId: s.alice.id,
    });
    expect(group).toEqual([]);

    await s.f.iam.api.identities.delete(owner, { tenantId: s.tenantId, identityId: s.bob.id });
    const platform = await s.f.iam.api.teams.get(owner, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
    });
    expect(platform.maintainers).toEqual([]);
    expect(platform.totalMemberCount).toBe(0);
  });

  it('keeps a team in step with its source groups (team sync)', async () => {
    const s = await scenario();
    const directory = await s.f.iam.api.groups.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Okta: Engineers',
    });
    await s.f.iam.api.groups.addMembers(s.owner, {
      tenantId: s.tenantId,
      groupId: directory.id,
      identityIds: [s.alice.id, s.bob.id],
    });
    const engineers = await s.f.iam.api.teams.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Engineers',
      syncGroupIds: [directory.id],
    });
    expect(engineers.syncGroups).toEqual([{ id: directory.id, name: 'Okta: Engineers' }]);
    const members = async () =>
      (
        await s.f.iam.api.teams.listMembers(s.owner, {
          tenantId: s.tenantId,
          teamId: engineers.id,
        })
      )
        .map((member) => `${member.name}:${member.source ?? 'manual'}`)
        .sort();
    expect(await members()).toEqual(['alice:sync', 'bob:sync']);

    // Group changes flow into the team; manual members stay.
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: engineers.id,
      identityId: s.carol.id,
    });
    await s.f.iam.api.groups.removeMember(s.owner, {
      tenantId: s.tenantId,
      groupId: directory.id,
      identityId: s.alice.id,
    });
    await s.f.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: directory.id,
      identityId: s.carol.id,
      expiresAt: s.f.now() + 86_400_000,
    });
    expect(await members()).toEqual(['bob:sync', 'carol:manual']);

    // A temporary source membership makes a temporary synced membership.
    const dave = await s.f.member('dave');
    await s.f.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: directory.id,
      identityId: dave.id,
      expiresAt: s.f.now() + 3_600_000,
    });
    const listed = await s.f.iam.api.teams.listMembers(s.owner, {
      tenantId: s.tenantId,
      teamId: engineers.id,
    });
    expect(listed.find((member) => member.name === 'dave')).toMatchObject({
      source: 'sync',
      expiresAt: s.f.now() + 3_600_000,
    });

    // Synced members are managed through the source group.
    await expect(
      s.f.iam.api.teams.removeMember(s.owner, {
        tenantId: s.tenantId,
        teamId: engineers.id,
        identityId: s.bob.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await expect(
      s.f.iam.api.groups.delete(s.owner, { tenantId: s.tenantId, groupId: directory.id }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });

    // A directory push (SCIM) that drops Bob reaches the team through the protocol host.
    await s.f.iam.store.transaction(async (tx) => {
      for (const row of await tx.find('groupMembers', {
        tenantId: s.tenantId,
        groupId: directory.id,
        identityId: s.bob.id,
      }))
        await tx.delete('groupMembers', row.id);
      await s.f.iam.protocolHost.syncRoleMappings(tx, {
        tenantId: s.tenantId,
        connectionId: 'scim',
        groupId: directory.id,
        identityIds: [],
        roleIds: [],
      });
    });
    expect(await members()).toEqual(['carol:manual', 'dave:sync']);
    const events = await s.f.iam.api.audit.list(s.owner, {
      tenantId: s.tenantId,
      action: 'team:member:remove',
    });
    expect(events.some((event) => event.actorId === 'directory-sync')).toBe(true);

    // Turning sync off removes the synced members and keeps the manual ones.
    await s.f.iam.api.teams.update(s.owner, {
      tenantId: s.tenantId,
      teamId: engineers.id,
      syncGroupIds: null,
    });
    expect(await members()).toEqual(['carol:manual']);
    await s.f.iam.api.groups.delete(s.owner, { tenantId: s.tenantId, groupId: directory.id });
    await expect(
      s.f.iam.api.teams.create(s.owner, {
        tenantId: s.tenantId,
        name: 'Loop',
        syncGroupIds: [s.platform.groupId],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('follows access packages that grant a source group', async () => {
    const s = await scenario();
    const directory = await s.f.iam.api.groups.create(s.owner, {
      tenantId: s.tenantId,
      name: 'On-call',
    });
    const team = await s.f.iam.api.teams.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Responders',
      syncGroupIds: [directory.id],
    });
    const pkg = await s.f.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'On-call kit',
      groupIds: [directory.id],
    });
    await s.f.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
      expiresAt: s.f.now() + 7 * 86_400_000,
    });
    const members = async () =>
      (await s.f.iam.api.teams.listMembers(s.owner, { tenantId: s.tenantId, teamId: team.id })).map(
        (member) => `${member.name}:${member.expiresAt ?? 'permanent'}`,
      );
    expect(await members()).toEqual([`alice:${s.f.now() + 7 * 86_400_000}`]);
    // Extending the package extends the synced membership.
    await s.f.iam.api.packages.extend(await s.f.ownerSignIn(), {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
      expiresAt: s.f.now() + 14 * 86_400_000,
    });
    expect(await members()).toEqual([`alice:${s.f.now() + 14 * 86_400_000}`]);
    await s.f.iam.api.packages.revoke(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
    });
    expect(await members()).toEqual([]);
  });

  it('reports risky teams and departments in access analysis', async () => {
    const s = await scenario();
    const admin = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Administrator',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: admin.id,
      subjectType: 'group',
      subjectId: s.platform.groupId,
    });
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    const orphan = await s.f.iam.api.teams.create(s.owner, { tenantId: s.tenantId, name: 'Data' });
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: orphan.id,
      identityId: s.carol.id,
    });
    const sales = await s.f.iam.api.departments.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Sales',
    });
    await s.f.iam.api.departments.assign(s.owner, {
      tenantId: s.tenantId,
      departmentId: sales.id,
      identityIds: [s.carol.id],
    });
    const kinds = async () =>
      (await s.f.iam.api.analysis.findings(s.owner, { tenantId: s.tenantId })).findings
        .filter((finding) => ['team', 'department'].includes(finding.subject.type))
        .map((finding) => `${finding.kind}:${finding.subject.name}`)
        .sort();
    // Bob maintains Platform, so he can make anyone an administrator through Platform or SRE.
    expect(await kinds()).toEqual([
      'department-without-head:Sales',
      'team-maintainers-grant-admin:Platform',
      'team-maintainers-grant-admin:Site Reliability',
      'team-without-maintainer:Data',
    ]);
    await s.f.iam.api.teams.update(s.owner, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
      memberManagement: 'admins',
    });
    await s.f.iam.api.departments.update(s.owner, {
      tenantId: s.tenantId,
      departmentId: sales.id,
      headId: s.bob.id,
    });
    expect(await kinds()).toEqual([
      'team-maintainers-grant-admin:Site Reliability',
      'team-without-maintainer:Data',
    ]);
  });

  it('deletes a team with its backing group and rejects people who cannot belong', async () => {
    const s = await scenario();
    const service = await s.f.iam.api.serviceAccounts.create(s.owner, {
      tenantId: s.tenantId,
      name: 'deployer',
    });
    await expect(
      s.f.iam.api.teams.addMember(s.owner, {
        tenantId: s.tenantId,
        teamId: s.sre.id,
        identityId: service.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await s.f.iam.api.teams.addMember(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
      identityId: s.alice.id,
    });
    await expect(
      s.f.iam.api.teams.addMember(s.owner, {
        tenantId: s.tenantId,
        teamId: s.sre.id,
        identityId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const removed = await s.f.iam.api.teams.delete(s.owner, {
      tenantId: s.tenantId,
      teamId: s.sre.id,
    });
    expect(removed).toEqual({ deleted: true, members: 1 });
    expect(await s.f.iam.store.get('groups', s.sre.groupId)).toBeUndefined();
    const platform = await s.f.iam.api.teams.get(s.owner, {
      tenantId: s.tenantId,
      teamId: s.platform.id,
    });
    // Only Bob remains in Platform's group once SRE is gone.
    expect(platform.totalMemberCount).toBe(1);
    const repaired = await s.f.iam.api.teams.reconcile(s.owner, { tenantId: s.tenantId });
    expect(repaired).toEqual({
      added: 0,
      removed: 0,
      updated: 0,
      synced: { added: 0, removed: 0, updated: 0, teams: [] },
    });
  });
});
