import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization';

afterEach(closeFixtures);

const doc = { type: 'documents', id: 'a' };

/** Mallory administers teams (no grant authority); Ops's backing group holds the owner-bound Writer role. */
async function privilegedTeam(ops: (eveId: string) => Record<string, unknown> = () => ({})) {
  const f = await organizationFixture();
  const { iam, tenantId, ownerCredential: owner } = f;
  const mallory = await f.member('mallory');
  const eve = await f.member('eve');
  const teamAdmin = await iam.api.roles.create(owner, {
    tenantId,
    name: 'Team admin',
    permissions: ['iam:teams:create', 'iam:teams:update', 'iam:teams:read'],
  });
  await iam.api.bindings.create(owner, {
    tenantId,
    roleId: teamAdmin.id,
    subjectType: 'identity',
    subjectId: mallory.id,
  });
  const writer = await iam.api.roles.create(owner, {
    tenantId,
    name: 'Writer',
    permissions: ['documents:write'],
  });
  const team = await iam.api.teams.create(owner, { tenantId, name: 'Ops', ...ops(eve.id) });
  await iam.api.bindings.create(owner, {
    tenantId,
    roleId: writer.id,
    subjectType: 'group',
    subjectId: team.groupId,
  });
  const m = { token: (await f.signIn('mallory')).token };
  const e = { token: (await f.signIn('eve')).token };
  const mayWrite = async () =>
    (await iam.authorize({ ...m, tenantId, action: 'documents:write', resource: doc })).allowed;
  return { f, iam, tenantId, owner, mallory, eve, ops: team, m, e, mayWrite };
}

describe('team administration never hands out what a team holds without grant authority', () => {
  it('refuses moving a privileged team under a team whose maintainers the mover chose', async () => {
    const { iam, tenantId, mallory, eve, ops, m, e, mayWrite } = await privilegedTeam();
    const shadow = await iam.api.teams.create(m, {
      tenantId,
      name: 'Shadow',
      maintainerIds: [eve.id],
    });
    await expect(
      iam.api.teams.update(m, { tenantId, teamId: ops.id, parentId: shadow.id }),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      iam.api.teams.addMember(e, { tenantId, teamId: ops.id, identityId: mallory.id }),
    ).rejects.toThrow();
    expect(await mayWrite()).toBe(false);
  });

  it('refuses opening an admins-only team to its maintainers without grant authority', async () => {
    const { iam, tenantId, mallory, ops, m, e, mayWrite } = await privilegedTeam((eveId) => ({
      memberManagement: 'admins',
      maintainerIds: [eveId],
    }));
    await expect(
      iam.api.teams.update(m, { tenantId, teamId: ops.id, memberManagement: 'maintainers' }),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      iam.api.teams.addMember(e, { tenantId, teamId: ops.id, identityId: mallory.id }),
    ).rejects.toThrow();
    expect(await mayWrite()).toBe(false);
  });

  it('still lets an administrator with grant authority move and open teams', async () => {
    const { iam, tenantId, owner, ops } = await privilegedTeam(() => ({
      memberManagement: 'admins',
    }));
    const parent = await iam.api.teams.create(owner, { tenantId, name: 'Engineering' });
    await iam.api.teams.update(owner, {
      tenantId,
      teamId: ops.id,
      parentId: parent.id,
      memberManagement: 'maintainers',
    });
    expect(await iam.api.teams.get(owner, { tenantId, teamId: ops.id })).toMatchObject({
      parentId: parent.id,
      memberManagement: 'maintainers',
    });
  });
});

describe('the maintainer path stands in for a missing grant only', () => {
  it('keeps an explicit deny in force for a maintainer', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const bob = await f.member('bob');
    const alice = await f.member('alice');
    const platform = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Platform',
      maintainerIds: [bob.id],
    });
    const b = { token: (await f.signIn('bob')).token };
    // Without the deny, the maintainer path works as designed.
    await iam.api.teams.addMember(b, { tenantId, teamId: platform.id, identityId: alice.id });
    const lockout = await iam.api.roles.create(owner, {
      tenantId,
      name: 'No team management',
      document: {
        version: 1,
        statements: [{ effect: 'deny', actions: ['iam:teams:*'], resources: ['*'] }],
      },
    });
    await iam.api.bindings.create(owner, {
      tenantId,
      roleId: lockout.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await expect(
      iam.api.teams.removeMember(b, { tenantId, teamId: platform.id, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const members = await iam.api.teams.listMembers(owner, { tenantId, teamId: platform.id });
    expect(members.map((member) => member.id)).toContain(alice.id);
  });
});
