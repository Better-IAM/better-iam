import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;
const people = { StringEquals: { 'principal.kind': 'user' } } as const;

type MemberRow = { id: string; groupId: string; packageAssignmentId?: string; expiresAt?: number };
type BindingRow = { id: string; roleId: string; authorityId: string; expiresAt?: number };

/**
 * Acme with Writer and Reader roles, a Finance group that carries Reader, an empty Lounge group, and Mallory, a
 * package manager who may edit and assign packages and update groups but grant nothing.
 */
async function setup(options: Parameters<typeof organizationFixture>[0] = {}) {
  const f = await organizationFixture(options);
  const { tenantId, iam } = f;
  const owner = f.ownerCredential;
  const writer = await iam.api.roles.create(owner, {
    tenantId,
    name: 'Writer',
    permissions: ['documents:write'],
  });
  const reader = await iam.api.roles.create(owner, {
    tenantId,
    name: 'Reader',
    permissions: ['documents:read'],
  });
  const finance = await iam.api.groups.create(owner, { tenantId, name: 'Finance' });
  await iam.api.bindings.create(owner, {
    tenantId,
    roleId: reader.id,
    subjectType: 'group',
    subjectId: finance.id,
  });
  const lounge = await iam.api.groups.create(owner, { tenantId, name: 'Lounge' });
  const alice = await f.member('alice');
  const mallory = await f.member('mallory');
  const manager = await iam.api.roles.create(owner, {
    tenantId,
    name: 'Package manager',
    permissions: [
      'iam:packages:update',
      'iam:packages:assign',
      'iam:packages:read',
      'iam:groups:update',
    ],
  });
  await iam.api.bindings.create(owner, {
    tenantId,
    roleId: manager.id,
    subjectType: 'identity',
    subjectId: mallory.id,
  });
  const asMallory = { token: (await f.signIn('mallory')).token };
  const can = async (name: string, action: string) =>
    (
      await iam.authorize({
        token: (await f.signIn(name)).token,
        tenantId,
        action,
        resource: { type: 'documents', id: 'a' },
      })
    ).allowed;
  const membership = async (groupId: string, identityId: string) =>
    (await f.database.find<MemberRow>('groupMembers', { tenantId, groupId, identityId }))[0];
  const bindingsOf = (assignmentId: string) =>
    f.database.find<BindingRow>('bindings', { tenantId, packageAssignmentId: assignmentId });
  return {
    f,
    iam,
    tenantId,
    owner,
    writer,
    reader,
    finance,
    lounge,
    alice,
    mallory,
    asMallory,
    can,
    membership,
    bindingsOf,
  };
}

describe('packages.extend lengthens only what the package bundles and the extender may grant', () => {
  it('refuses to turn a one-day grant permanent after the package was emptied of it', async () => {
    const s = await setup();
    const pkg = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Temporary access',
      roleIds: [s.writer.id],
      groupIds: [s.finance.id],
    });
    const ends = s.f.now() + day;
    const assigned = await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
      expiresAt: ends,
    });
    await expect(
      s.iam.api.packages.extend(s.asMallory, {
        tenantId: s.tenantId,
        packageId: pkg.id,
        identityId: s.alice.id,
        expiresAt: null,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // Emptying the package of what Mallory cannot grant does not let her lengthen what the assignment holds.
    await s.iam.api.packages.update(s.asMallory, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      roleIds: [],
      groupIds: [s.lounge.id],
    });
    await s.iam.api.packages.extend(s.asMallory, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
      expiresAt: null,
    });
    const bindings = await s.bindingsOf(assigned.id);
    expect(bindings.map((binding) => [binding.roleId, binding.expiresAt])).toEqual([
      [s.writer.id, ends],
    ]);
    expect((await s.membership(s.finance.id, s.alice.id))!.expiresAt).toBe(ends);
    s.f.advance(3 * day);
    expect(await s.can('alice', 'documents:write')).toBe(false);
    expect(await s.can('alice', 'documents:read')).toBe(false);
  });

  it('still lengthens every record of what the package bundles for an extender with the rights', async () => {
    const s = await setup();
    const pkg = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Temporary access',
      roleIds: [s.writer.id],
      groupIds: [s.finance.id],
    });
    const ends = s.f.now() + day;
    const assigned = await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
      expiresAt: ends,
    });
    const extended = await s.iam.api.packages.extend(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
      expiresAt: null,
    });
    expect(extended.expiresAt).toBeUndefined();
    expect(
      (await s.bindingsOf(assigned.id)).map((binding) => [binding.roleId, binding.expiresAt]),
    ).toEqual([[s.writer.id, undefined]]);
    expect((await s.membership(s.finance.id, s.alice.id))!.expiresAt).toBeUndefined();
    s.f.advance(3 * day);
    expect(await s.can('alice', 'documents:write')).toBe(true);
    expect(await s.can('alice', 'documents:read')).toBe(true);
  });

  it('leaves records of roles and groups taken out of the package at their end', async () => {
    const s = await setup();
    const pkg = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Temporary access',
      roleIds: [s.writer.id, s.reader.id],
      groupIds: [s.finance.id],
    });
    const ends = s.f.now() + day;
    const assigned = await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
      expiresAt: ends,
    });
    await s.iam.api.packages.update(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      roleIds: [s.reader.id],
      groupIds: [s.lounge.id],
    });
    const later = s.f.now() + 10 * day;
    await s.iam.api.packages.extend(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.alice.id,
      expiresAt: later,
    });
    const byRole = new Map(
      (await s.bindingsOf(assigned.id)).map((binding) => [binding.roleId, binding.expiresAt]),
    );
    expect(byRole.get(s.writer.id)).toBe(ends);
    expect(byRole.get(s.reader.id)).toBe(later);
    expect((await s.membership(s.finance.id, s.alice.id))!.expiresAt).toBe(ends);
  });
});

describe('handing a shared membership over never lengthens it', () => {
  it('a package that gained the group later does not make a one-day membership permanent', async () => {
    const s = await setup();
    const temporary = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Finance for a day',
      groupIds: [s.finance.id],
    });
    const everyday = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Everyday',
      groupIds: [s.lounge.id],
    });
    const ends = s.f.now() + day;
    await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: temporary.id,
      identityId: s.alice.id,
      expiresAt: ends,
    });
    await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: everyday.id,
      identityId: s.alice.id,
    });
    await s.iam.api.packages.update(s.asMallory, {
      tenantId: s.tenantId,
      packageId: everyday.id,
      groupIds: [s.lounge.id, s.finance.id],
    });
    await s.iam.api.packages.revoke(s.asMallory, {
      tenantId: s.tenantId,
      packageId: temporary.id,
      identityId: s.alice.id,
    });
    const member = await s.membership(s.finance.id, s.alice.id);
    expect(member?.expiresAt).toBe(ends);
    s.f.advance(3 * day);
    expect(await s.can('alice', 'documents:read')).toBe(false);
  });

  it('shortening with a shared group hands the membership over at no later end', async () => {
    const s = await setup();
    const temporary = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Finance for a day',
      groupIds: [s.finance.id],
    });
    const everyday = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Everyday',
      groupIds: [s.lounge.id],
    });
    const ends = s.f.now() + day;
    await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: temporary.id,
      identityId: s.alice.id,
      expiresAt: ends,
    });
    const permanent = await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: everyday.id,
      identityId: s.alice.id,
    });
    await s.iam.api.packages.update(s.asMallory, {
      tenantId: s.tenantId,
      packageId: everyday.id,
      groupIds: [s.lounge.id, s.finance.id],
    });
    await s.iam.api.packages.extend(s.asMallory, {
      tenantId: s.tenantId,
      packageId: temporary.id,
      identityId: s.alice.id,
      expiresAt: s.f.now() + 60_000,
    });
    const member = await s.membership(s.finance.id, s.alice.id);
    expect(member).toMatchObject({ packageAssignmentId: permanent.id, expiresAt: ends });
  });

  it('a package that bundled the group from the start still takes the membership over with its own end', async () => {
    const s = await setup();
    const long = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Long',
      groupIds: [s.finance.id],
    });
    const short = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Short',
      groupIds: [s.finance.id],
    });
    await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: long.id,
      identityId: s.alice.id,
    });
    const threeDays = await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: short.id,
      identityId: s.alice.id,
      expiresAt: s.f.now() + 3 * day,
    });
    await s.iam.api.packages.revoke(s.owner, {
      tenantId: s.tenantId,
      packageId: long.id,
      identityId: s.alice.id,
    });
    expect(await s.membership(s.finance.id, s.alice.id)).toMatchObject({
      packageAssignmentId: threeDays.id,
      expiresAt: threeDays.expiresAt,
    });
    s.f.advance(2 * day);
    expect(await s.can('alice', 'documents:read')).toBe(true);
  });
});

describe('automatic package grants honour enforced access invariants', () => {
  it('records the grant an invariant forbids as a failed issue and still grants everyone else', async () => {
    const s = await setup({
      permissions: {
        actions: ['documents:read', 'documents:write'],
        identityAttributes: { contractor: 'boolean' },
      },
    });
    await s.iam.api.identities.update(s.owner, {
      tenantId: s.tenantId,
      identityId: s.alice.id,
      attributes: { contractor: true },
    });
    await s.iam.api.invariants.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Contractors never write',
      subject: { attribute: { name: 'contractor', value: true } },
      action: 'documents:write',
      resource: { type: 'documents', id: 'a' },
      expect: 'deny',
      mode: 'enforce',
    });
    const pkg = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Writers',
      roleIds: [s.writer.id],
      autoAssign: { include: [people] },
    });
    expect(pkg.reconcile?.failed).toEqual([
      expect.objectContaining({ identityId: s.alice.id, code: 'INVARIANT_VIOLATION' }),
    ]);
    const holders = (
      await s.iam.api.packages.listAssignments(s.owner, {
        tenantId: s.tenantId,
        packageId: pkg.id,
      })
    ).map((assignment) => assignment.identityId);
    expect(holders).toContain(s.mallory.id);
    expect(holders).not.toContain(s.alice.id);
    expect(await s.can('alice', 'documents:write')).toBe(false);
    expect(await s.can('mallory', 'documents:write')).toBe(true);
    const view = await s.iam.api.packages.get(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
    });
    expect(view.autoAssign?.issues).toEqual([
      expect.objectContaining({ identityId: s.alice.id, code: 'INVARIANT_VIOLATION' }),
    ]);
    const run = await s.iam.api.invariants.run(s.owner, { tenantId: s.tenantId });
    expect(JSON.stringify(run)).not.toContain(s.alice.id);
  });
});

describe('package rules warn about facts lower-privileged callers control', () => {
  it('flags attributes, managerId and groups without bindings, in include and exclude clauses', async () => {
    const s = await setup({
      permissions: {
        actions: ['documents:read', 'documents:write'],
        identityAttributes: { department: 'string', contractor: 'boolean' },
      },
    });
    const pkg = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Finance birthright',
      roleIds: [s.writer.id],
      autoAssign: {
        include: [
          {
            ...people,
            StringEquals: { ...people.StringEquals, 'principal.department': 'finance' },
          },
          {
            ...people,
            StringEquals: { ...people.StringEquals, 'identity.managerId': s.mallory.id },
          },
          { ...people, ArrayContains: { 'identity.groups': [s.lounge.id, s.finance.id] } },
        ],
        exclude: [{ Bool: { 'principal.contractor': true } }],
      },
    });
    const warnings = pkg.autoAssign!.warnings;
    expect(warnings).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/^include\[0\] tests principal\.department, .*iam:identities:update/),
        expect.stringMatching(/^include\[1\] tests identity\.managerId, .*iam:identities:update/),
        expect.stringMatching(
          /^include\[2\] tests identity\.groups for [^,]+, a group without role bindings/,
        ),
        expect.stringMatching(/^exclude\[0\] tests principal\.contractor, .*lift the exclusion/),
      ]),
    );
    // Finance carries a binding, so adding members to it needs that binding's authority: not flagged.
    expect(warnings.find((warning) => warning.includes(s.finance.id))).toBeUndefined();
    expect(warnings.find((warning) => warning.includes(s.lounge.id))).toBeDefined();
    const preview = await s.iam.api.packages.previewAutoAssign(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
    });
    expect(preview.warnings).toEqual(warnings);
  });

  it('does not flag rules on fixed facts', async () => {
    const s = await setup();
    const pkg = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Everyone',
      roleIds: [s.reader.id],
      autoAssign: {
        include: [{ ...people, ArrayContains: { 'identity.groups': [s.finance.id] } }],
      },
    });
    expect(pkg.autoAssign!.warnings).toEqual([]);
  });
});

describe('rules do not feed on team memberships that access packages created', () => {
  it('ignores a team backing group joined only through a package-granted source group', async () => {
    const s = await setup();
    const contractors = await s.iam.api.groups.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Contractors',
    });
    const vendors = await s.iam.api.teams.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Vendors',
      syncGroupIds: [contractors.id],
    });
    const kit = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Contractor kit',
      groupIds: [contractors.id],
    });
    const chained = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Vendor tools',
      roleIds: [s.writer.id],
      autoAssign: {
        include: [{ ...people, ArrayContains: { 'identity.groups': [vendors.groupId] } }],
      },
    });
    const holders = async () =>
      (
        await s.iam.api.packages.listAssignments(s.owner, {
          tenantId: s.tenantId,
          packageId: chained.id,
          source: 'automatic',
        })
      ).map((assignment) => assignment.identityId);

    // Alice reaches the Vendors team (and its backing group) only through the Contractor kit package.
    await s.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: kit.id,
      identityId: s.alice.id,
    });
    expect(await s.membership(vendors.groupId, s.alice.id)).toBeDefined();
    await s.iam.api.packages.reconcile(s.owner, { tenantId: s.tenantId, packageId: chained.id });
    expect(await holders()).toEqual([]);

    // A direct membership of the source group counts.
    const bob = await s.f.member('bob');
    await s.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: contractors.id,
      identityId: bob.id,
    });
    await s.iam.api.packages.reconcile(s.owner, { tenantId: s.tenantId, packageId: chained.id });
    expect(await holders()).toEqual([bob.id]);
  });

  it('a package cannot keep itself alive through a team synced from its own group', async () => {
    const s = await setup();
    const seed = await s.iam.api.groups.create(s.owner, { tenantId: s.tenantId, name: 'Seed' });
    const granted = await s.iam.api.groups.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Granted',
    });
    const echo = await s.iam.api.teams.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Echo',
      syncGroupIds: [granted.id],
    });
    const pkg = await s.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Loop',
      groupIds: [granted.id],
      autoAssign: {
        include: [
          { ...people, ArrayContains: { 'identity.groups': [seed.id] } },
          { ...people, ArrayContains: { 'identity.groups': [echo.groupId] } },
        ],
      },
    });
    await s.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: seed.id,
      identityId: s.alice.id,
    });
    await s.iam.api.packages.reconcile(s.owner, { tenantId: s.tenantId, packageId: pkg.id });
    const holders = async () =>
      (
        await s.iam.api.packages.listAssignments(s.owner, {
          tenantId: s.tenantId,
          packageId: pkg.id,
        })
      ).map((assignment) => assignment.identityId);
    expect(await holders()).toEqual([s.alice.id]);
    expect(await s.membership(echo.groupId, s.alice.id)).toBeDefined();

    await s.iam.api.groups.removeMember(s.owner, {
      tenantId: s.tenantId,
      groupId: seed.id,
      identityId: s.alice.id,
    });
    await s.iam.api.packages.reconcile(s.owner, { tenantId: s.tenantId, packageId: pkg.id });
    expect(await holders()).toEqual([]);
    expect(await s.membership(echo.groupId, s.alice.id)).toBeUndefined();
  });
});
