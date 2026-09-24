import { afterEach, describe, expect, it } from 'vitest';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const doc = { type: 'documents', id: 'a' };
const acknowledge = [{ id: 'ok', kind: 'acknowledge', title: 'OK', content: 'Read this.' }];

/** A role with `permissions` bound to one person; returns the binding (to take it away again). */
async function grant(f: OrganizationFixture, identityId: string, permissions: string[]) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Grants for ${identityId}`,
    permissions,
  });
  return f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identityId,
  });
}

/** A role that denies documents:write, bound to a group (a team's backing group or an ordinary one). */
async function denyWrites(f: OrganizationFixture, groupId: string) {
  const guard = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `No writes ${groupId}`,
    document: {
      version: 1,
      statements: [{ effect: 'deny', actions: ['documents:write'], resources: ['*'] }],
    },
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: guard.id,
    subjectType: 'group',
    subjectId: groupId,
  });
}

/** Binds a Writer role (documents:write) to a group under the owner's authority. */
async function allowWrites(f: OrganizationFixture, groupId: string) {
  const writer = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Writer ${groupId}`,
    permissions: ['documents:write'],
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: writer.id,
    subjectType: 'group',
    subjectId: groupId,
  });
}

async function mayWrite(f: OrganizationFixture, name: string) {
  const { token } = await f.signIn(name);
  return (
    await f.iam.authorize({ token, tenantId: f.tenantId, action: 'documents:write', resource: doc })
  ).allowed;
}

async function groupMemberIds(f: OrganizationFixture, groupId: string) {
  return (
    await f.iam.api.groups.listMembers(f.ownerCredential, { tenantId: f.tenantId, groupId })
  ).map((member) => member.id);
}

describe('onboarding completion groups stand on grant authority', () => {
  it('refuses iam:onboarding:manage alone changing who completes a flow with completion groups', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const mallory = await f.member('mallory');
    await grant(f, mallory.id, ['iam:onboarding:manage', 'iam:onboarding:read']);
    const engineers = await iam.api.groups.create(owner, { tenantId, name: 'Engineers' });
    await allowWrites(f, engineers.id);
    f.advance(60_000); // Mallory predates the flow
    const flow = await iam.api.onboarding.createFlow(owner, {
      tenantId,
      name: 'Engineering onboarding',
      audience: 'member',
      completionGroupIds: [engineers.id],
      steps: [{ id: 'laptop', kind: 'task', title: 'Collect your laptop', verification: 'admin' }],
    });
    const m = { token: (await f.signIn('mallory')).token };
    const update = (changes: Record<string, unknown>) =>
      iam.api.onboarding.updateFlow(m, { tenantId, flowId: flow.id, ...changes });

    for (const changes of [
      { includeExisting: true, steps: acknowledge },
      { steps: acknowledge },
      { includeExisting: true },
      { rule: { include: [{ StringEquals: { 'principal.kind': 'user' } }] } },
      { appliesTo: 'subtree' },
    ])
      await expect(update(changes)).rejects.toMatchObject({ status: 403 });
    // Pausing hands nothing out; resuming does.
    await update({ enabled: false });
    await expect(update({ enabled: true })).rejects.toMatchObject({ status: 403 });
    await iam.api.onboarding.updateFlow(owner, { tenantId, flowId: flow.id, enabled: true });

    // Edits that leave who completes it alone still work, and the groups keep their owner.
    const renamed = await update({ name: 'Engineering start', description: 'Day one' });
    expect(renamed).toMatchObject({ authorId: mallory.id, groupsOwnerId: f.ownerId });
    // Naming the same groups again (as the console does) passes quietly without handing them over.
    const resaved = await update({ completionGroupIds: [engineers.id], required: false });
    expect(resaved.groupsOwnerId).toBe(f.ownerId);

    expect((await iam.api.onboarding.mine(m, { tenantId })).flows).toEqual([]);
    expect(await groupMemberIds(f, engineers.id)).not.toContain(mallory.id);
    expect(await mayWrite(f, 'mallory')).toBe(false);

    // The owner may widen the flow; the groups then stand on the owner's authority.
    const widened = await iam.api.onboarding.updateFlow(owner, {
      tenantId,
      flowId: flow.id,
      includeExisting: true,
    });
    expect(widened.groupsOwnerId).toBe(f.ownerId);
  });

  it('applies the groups under the owner’s authority and skips those the owner lost', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const ada = await f.member('ada');
    const adaAdmin = await grant(f, ada.id, [
      'iam:onboarding:manage',
      'iam:onboarding:read',
      'iam:groups:update',
    ]);
    const engineers = await iam.api.groups.create(owner, { tenantId, name: 'Engineers' });
    const a = { token: (await f.signIn('ada')).token };
    const flow = await iam.api.onboarding.createFlow(a, {
      tenantId,
      name: 'Welcome',
      audience: 'member',
      completionGroupIds: [engineers.id],
      steps: acknowledge,
    });
    expect(flow.groupsOwnerId).toBe(ada.id);
    f.advance(1_000);
    const complete = async (name: string) => {
      await f.member(name);
      const session = { token: (await f.signIn(name)).token };
      await iam.api.onboarding.submitStep(session, {
        tenantId,
        flowId: flow.id,
        stepId: 'ok',
        acknowledged: true,
      });
      return session;
    };

    // While Ada may add people to the group, finishing the flow adds them.
    const bob = await complete('bob');
    expect((await iam.api.onboarding.mine(bob, { tenantId })).complete).toBe(true);
    expect(await groupMemberIds(f, engineers.id)).toHaveLength(1);

    // Once she may not, the group is skipped, reported on the progress, and audited once.
    await iam.api.bindings.delete(owner, { tenantId, bindingId: adaAdmin.id });
    const carol = await complete('carol');
    await iam.api.onboarding.mine(carol, { tenantId });
    expect(await groupMemberIds(f, engineers.id)).toHaveLength(1);
    const report = await iam.api.onboarding.progress(owner, { tenantId, flowId: flow.id });
    expect(report.members?.find((row) => row.identity.name === 'carol')).toMatchObject({
      complete: true,
      completionError: expect.stringContaining('Completion groups skipped'),
    });
    const skipped = await iam.api.audit.list(owner, {
      tenantId,
      action: 'onboarding:groups-skipped',
    });
    expect(skipped).toHaveLength(1);
    expect(skipped[0]!.metadata).toMatchObject({ groupIds: [engineers.id], ownerId: ada.id });

    // An administrator who may add people to it takes the groups over by naming them again.
    const retaken = await iam.api.onboarding.updateFlow(owner, {
      tenantId,
      flowId: flow.id,
      completionGroupIds: [engineers.id],
    });
    expect(retaken.groupsOwnerId).toBe(f.ownerId);
    await iam.api.onboarding.mine(carol, { tenantId });
    expect(await groupMemberIds(f, engineers.id)).toHaveLength(2);
  });

  it('keeps enforced access invariants for completion groups', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const writers = await iam.api.groups.create(owner, { tenantId, name: 'Writers' });
    await allowWrites(f, writers.id);
    const flow = await iam.api.onboarding.createFlow(owner, {
      tenantId,
      name: 'Welcome',
      audience: 'member',
      completionGroupIds: [writers.id],
      steps: acknowledge,
    });
    f.advance(1_000);
    const bob = await f.member('bob');
    await iam.api.invariants.create(owner, {
      tenantId,
      name: 'Bob never writes',
      subject: { identityId: bob.id },
      action: 'documents:write',
      resource: doc,
      expect: 'deny',
      mode: 'enforce',
    });
    const b = { token: (await f.signIn('bob')).token };
    await iam.api.onboarding.submitStep(b, {
      tenantId,
      flowId: flow.id,
      stepId: 'ok',
      acknowledged: true,
    });
    expect(await groupMemberIds(f, writers.id)).toEqual([]);
    expect(await mayWrite(f, 'bob')).toBe(false);
    const report = await iam.api.onboarding.progress(owner, { tenantId, flowId: flow.id });
    expect(report.members?.[0]).toMatchObject({
      complete: true,
      completionError: expect.stringContaining('Bob never writes'),
    });
  });

  it('refuses resetting one’s own progress to rejoin a completion group', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const writers = await iam.api.groups.create(owner, { tenantId, name: 'Writers' });
    await allowWrites(f, writers.id);
    const flow = await iam.api.onboarding.createFlow(owner, {
      tenantId,
      name: 'Welcome',
      audience: 'member',
      completionGroupIds: [writers.id],
      steps: acknowledge,
    });
    f.advance(1_000);
    const mallory = await f.member('mallory');
    await grant(f, mallory.id, ['iam:onboarding:manage', 'iam:onboarding:read']);
    const m = { token: (await f.signIn('mallory')).token };
    await iam.api.onboarding.submitStep(m, {
      tenantId,
      flowId: flow.id,
      stepId: 'ok',
      acknowledged: true,
    });
    expect(await groupMemberIds(f, writers.id)).toEqual([mallory.id]);
    // An administrator takes her out of the group again.
    await iam.api.groups.removeMember(owner, {
      tenantId,
      groupId: writers.id,
      identityId: mallory.id,
    });
    await expect(
      iam.api.onboarding.resetProgress(m, { tenantId, flowId: flow.id, subjectId: mallory.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      iam.api.onboarding.resetProgress(m, { tenantId, flowId: flow.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await iam.api.onboarding.mine(m, { tenantId });
    expect(await groupMemberIds(f, writers.id)).toEqual([]);
    expect(await mayWrite(f, 'mallory')).toBe(false);
    // Administrators still reset anyone.
    expect(
      await iam.api.onboarding.resetProgress(owner, {
        tenantId,
        flowId: flow.id,
        subjectId: mallory.id,
      }),
    ).toEqual({ reset: 1 });
  });
});

describe('team sync from groups needs authority over what the teams hold', () => {
  it('refuses changing a source group when the synced team (or a team above it) grants more', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const mallory = await f.member('mallory');
    const eve = await f.member('eve');
    await grant(f, mallory.id, ['iam:groups:update', 'iam:groups:read']);
    const m = { token: (await f.signIn('mallory')).token };

    // prod-admins (Writer) syncs from an ordinary group that holds nothing itself.
    const source = await iam.api.groups.create(owner, { tenantId, name: 'Okta: prod' });
    const admins = await iam.api.teams.create(owner, {
      tenantId,
      name: 'prod-admins',
      syncGroupIds: [source.id],
    });
    await allowWrites(f, admins.groupId);
    await expect(
      iam.api.groups.addMember(m, { tenantId, groupId: source.id, identityId: mallory.id }),
    ).rejects.toMatchObject({ status: 403 });
    expect(await groupMemberIds(f, source.id)).toEqual([]);
    expect(await mayWrite(f, 'mallory')).toBe(false);

    // The same through a team whose parent holds the role.
    const parent = await iam.api.teams.create(owner, { tenantId, name: 'Production' });
    await allowWrites(f, parent.groupId);
    const nested = await iam.api.groups.create(owner, { tenantId, name: 'Okta: on-call' });
    await iam.api.teams.create(owner, {
      tenantId,
      name: 'On-call',
      parentId: parent.id,
      syncGroupIds: [nested.id],
    });
    await expect(
      iam.api.groups.addMembers(m, { tenantId, groupId: nested.id, identityIds: [mallory.id] }),
    ).rejects.toMatchObject({ status: 403 });
    expect(await mayWrite(f, 'mallory')).toBe(false);

    // Taking someone out, or changing their end, moves the team as well.
    await iam.api.groups.addMember(owner, { tenantId, groupId: source.id, identityId: eve.id });
    expect(await mayWrite(f, 'eve')).toBe(true);
    await expect(
      iam.api.groups.updateMember(m, {
        tenantId,
        groupId: source.id,
        identityId: eve.id,
        expiresAt: f.now() + 3_600_000,
      }),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      iam.api.groups.removeMember(m, { tenantId, groupId: source.id, identityId: eve.id }),
    ).rejects.toMatchObject({ status: 403 });
    expect(await groupMemberIds(f, source.id)).toEqual([eve.id]);

    // A team that holds nothing follows its source for anyone who may update the group.
    const plain = await iam.api.groups.create(owner, { tenantId, name: 'Okta: readers' });
    const book = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Book club',
      syncGroupIds: [plain.id],
    });
    await iam.api.groups.addMember(m, { tenantId, groupId: plain.id, identityId: mallory.id });
    const members = await iam.api.teams.listMembers(owner, { tenantId, teamId: book.id });
    expect(members.map((member) => [member.id, member.source])).toEqual([[mallory.id, 'sync']]);
  });
});

describe('leaving a team keeps the denies bound to it', () => {
  it('refuses leaving a team whose backing group carries a deny', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const contractor = await f.member('contractor');
    await grant(f, contractor.id, ['documents:write']);
    const team = await iam.api.teams.create(owner, { tenantId, name: 'Contractors' });
    await denyWrites(f, team.groupId);
    await iam.api.teams.addMember(owner, { tenantId, teamId: team.id, identityId: contractor.id });
    const c = { token: (await f.signIn('contractor')).token };
    await expect(iam.api.teams.leave(c, { tenantId, teamId: team.id })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    expect(await mayWrite(f, 'contractor')).toBe(false);
    // An administrator with the authority removes them.
    await iam.api.teams.removeMember(owner, {
      tenantId,
      teamId: team.id,
      identityId: contractor.id,
    });
    expect(await mayWrite(f, 'contractor')).toBe(true);
  });

  it('looks at the teams above, unless another team keeps the person in them', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const contractor = await f.member('contractor');
    await grant(f, contractor.id, ['documents:write']);
    const vendors = await iam.api.teams.create(owner, { tenantId, name: 'Vendors' });
    await denyWrites(f, vendors.groupId);
    const design = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Design',
      parentId: vendors.id,
    });
    const support = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Support',
      parentId: vendors.id,
    });
    await iam.api.teams.addMember(owner, {
      tenantId,
      teamId: design.id,
      identityId: contractor.id,
    });
    const c = { token: (await f.signIn('contractor')).token };
    await expect(iam.api.teams.leave(c, { tenantId, teamId: design.id })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // Still in Vendors through Support, so leaving Design lifts nothing.
    await iam.api.teams.addMember(owner, {
      tenantId,
      teamId: support.id,
      identityId: contractor.id,
    });
    await iam.api.teams.leave(c, { tenantId, teamId: design.id });
    expect(await mayWrite(f, 'contractor')).toBe(false);
  });

  it('refuses a maintainer removing themselves or shortening their own membership', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const bob = await f.member('bob');
    await grant(f, bob.id, ['documents:write']);
    const team = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Contractors',
      maintainerIds: [bob.id],
    });
    await denyWrites(f, team.groupId);
    const b = { token: (await f.signIn('bob')).token };
    await expect(
      iam.api.teams.removeMember(b, { tenantId, teamId: team.id, identityId: bob.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      iam.api.teams.updateMember(b, {
        tenantId,
        teamId: team.id,
        identityId: bob.id,
        expiresAt: f.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await mayWrite(f, 'bob')).toBe(false);
  });

  it('still lets people leave teams that carry no deny', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const alice = await f.member('alice');
    const team = await iam.api.teams.create(owner, { tenantId, name: 'Readers' });
    await allowWrites(f, team.groupId);
    await iam.api.teams.addMember(owner, { tenantId, teamId: team.id, identityId: alice.id });
    const a = { token: (await f.signIn('alice')).token };
    expect(await iam.api.teams.leave(a, { tenantId, teamId: team.id })).toEqual({ left: true });
    expect(await mayWrite(f, 'alice')).toBe(false);
  });
});

describe('maintainer standing', () => {
  it('does not reach through an admins-only team', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const bob = await f.member('bob');
    const dora = await f.member('dora');
    const mallory = await f.member('mallory');
    const production = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Production',
      memberManagement: 'admins',
      maintainerIds: [bob.id],
    });
    await allowWrites(f, production.groupId);
    const oncall = await iam.api.teams.create(owner, {
      tenantId,
      name: 'On-call',
      parentId: production.id,
    });
    const b = { token: (await f.signIn('bob')).token };
    await expect(
      iam.api.teams.addMember(b, { tenantId, teamId: oncall.id, identityId: mallory.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await mayWrite(f, 'mallory')).toBe(false);

    // Further down: Bob maintains Platform, above the admins-only Locked, above Leaf (maintained by Dora).
    const platform = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Platform',
      maintainerIds: [bob.id],
    });
    const locked = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Locked',
      parentId: platform.id,
      memberManagement: 'admins',
    });
    await allowWrites(f, locked.groupId);
    const leaf = await iam.api.teams.create(owner, {
      tenantId,
      name: 'Leaf',
      parentId: locked.id,
      maintainerIds: [dora.id],
    });
    await expect(
      iam.api.teams.addMember(b, { tenantId, teamId: leaf.id, identityId: mallory.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await mayWrite(f, 'mallory')).toBe(false);
    // Bob still manages Platform itself, and Dora her own team (as its administrators delegated).
    await iam.api.teams.addMember(b, { tenantId, teamId: platform.id, identityId: mallory.id });
    const d = { token: (await f.signIn('dora')).token };
    await iam.api.teams.addMember(d, { tenantId, teamId: leaf.id, identityId: mallory.id });
    expect(await mayWrite(f, 'mallory')).toBe(true);
  });

  it('keeps a temporary maintainer from outlasting their own membership', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const bob = await f.member('bob');
    const day = 86_400_000;
    const platform = await iam.api.teams.create(owner, { tenantId, name: 'Platform' });
    const sre = await iam.api.teams.create(owner, {
      tenantId,
      name: 'SRE',
      parentId: platform.id,
    });
    await iam.api.teams.addMember(owner, {
      tenantId,
      teamId: platform.id,
      identityId: bob.id,
      role: 'maintainer',
      expiresAt: f.now() + day,
    });
    const b = { token: (await f.signIn('bob')).token };
    const updateSelf = (expiresAt: number | null) =>
      iam.api.teams.updateMember(b, {
        tenantId,
        teamId: platform.id,
        identityId: bob.id,
        expiresAt,
      });
    await expect(updateSelf(null)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(updateSelf(f.now() + 2 * day)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      iam.api.teams.addMember(b, { tenantId, teamId: sre.id, identityId: bob.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      iam.api.teams.addMember(b, {
        tenantId,
        teamId: sre.id,
        identityId: bob.id,
        expiresAt: f.now() + 2 * day,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Within his own end he may do both.
    expect((await updateSelf(f.now() + day / 2)).expiresAt).toBe(f.now() + day / 2);
    await iam.api.teams.addMember(b, {
      tenantId,
      teamId: sre.id,
      identityId: bob.id,
      expiresAt: f.now() + day / 4,
    });
    // An administrator may make him permanent.
    const permanent = await iam.api.teams.updateMember(owner, {
      tenantId,
      teamId: platform.id,
      identityId: bob.id,
      expiresAt: null,
    });
    expect(permanent.expiresAt).toBeUndefined();
  });
});

describe('managers from the org chart', () => {
  it('leaves people whose identity the caller may not update', async () => {
    const f = await organizationFixture();
    const { iam, tenantId, ownerCredential: owner } = f;
    const [ada, head, carol, dave] = [
      await f.member('ada'),
      await f.member('head'),
      await f.member('carol'),
      await f.member('dave'),
    ];
    await grant(f, ada.id, ['iam:identities:update', 'iam:departments:read']);
    const protect = await iam.api.roles.create(owner, {
      tenantId,
      name: 'Carol is protected',
      document: {
        version: 1,
        statements: [
          { effect: 'deny', actions: ['iam:identities:update'], resources: [`iam/${carol.id}`] },
        ],
      },
    });
    await iam.api.bindings.create(owner, {
      tenantId,
      roleId: protect.id,
      subjectType: 'identity',
      subjectId: ada.id,
    });
    const sales = await iam.api.departments.create(owner, {
      tenantId,
      name: 'Sales',
      headId: head.id,
    });
    await iam.api.departments.assign(owner, {
      tenantId,
      departmentId: sales.id,
      identityIds: [carol.id, dave.id],
    });
    const a = { token: (await f.signIn('ada')).token };
    await expect(
      iam.api.identities.update(a, { tenantId, identityId: carol.id, managerId: head.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const result = await iam.api.departments.syncManagers(a, { tenantId });
    expect(result.updated.map((entry) => entry.identityId)).toEqual([dave.id]);
    expect(result.kept).toBe(1);
    const get = (identityId: string) => iam.api.identities.get(owner, { tenantId, identityId });
    expect((await get(carol.id)).managerId).toBeUndefined();
    expect((await get(dave.id)).managerId).toBe(head.id);
  });
});
