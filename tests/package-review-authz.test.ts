import { afterEach, describe, expect, it } from 'vitest';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

type Credential = { token: string };
type StoredBinding = { id: string; authorityId: string; expiresAt?: number; roleId: string };
type StoredMember = { id: string; expiresAt?: number };

const everything = {
  version: 1 as const,
  statements: [{ effect: 'allow' as const, actions: ['documents:*'], resources: ['*'] }],
};

/** Binds a fresh role with these permissions to an identity, as the owner. */
async function grant(
  f: OrganizationFixture,
  identityId: string,
  name: string,
  permissions: string[],
) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name,
    permissions,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identityId,
  });
  return role;
}

async function allowed(f: OrganizationFixture, credential: Credential, action: string) {
  return (
    await f.iam.authorize({
      token: credential.token,
      tenantId: f.tenantId,
      action,
      resource: { type: 'documents', id: 'a' },
    })
  ).allowed;
}

async function assignmentBindings(f: OrganizationFixture, assignmentId: string) {
  return f.database.find<StoredBinding & { tenantId: string }>('bindings', {
    tenantId: f.tenantId,
    packageAssignmentId: assignmentId,
  });
}
async function assignmentMembers(f: OrganizationFixture, assignmentId: string) {
  return f.database.find<StoredMember & { tenantId: string }>('groupMembers', {
    tenantId: f.tenantId,
    packageAssignmentId: assignmentId,
  });
}

describe('regress-authz: packages.extend needs the rights of assign to lengthen', () => {
  it('lets a holder of only iam:packages:assign shorten, but refuses a later end or no end', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const engineering = await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      groupIds: [engineering.id],
    });
    const alice = await f.member('alice');
    const carol = await f.member('carol');
    await grant(f, carol.id, 'Package operator', ['iam:packages:assign', 'iam:packages:read']);
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + 2 * day,
    });
    const [original] = await assignmentBindings(f, assigned.id);
    expect(original).toBeDefined();
    const ownerAuthorityId = original!.authorityId;
    const asCarol = { token: (await f.signIn('carol')).token };
    const extend = (expiresAt: number | null) =>
      f.iam.api.packages.extend(asCarol, {
        tenantId,
        packageId: kit.id,
        identityId: alice.id,
        expiresAt,
      });

    // Shortening is like revoking: iam:packages:assign on the package suffices.
    const shortened = await extend(f.now() + day);
    expect(shortened.expiresAt).toBe(f.now() + day);
    expect(
      (await assignmentBindings(f, assigned.id)).map((binding) => [
        binding.expiresAt,
        binding.authorityId,
      ]),
    ).toEqual([[f.now() + day, ownerAuthorityId]]);
    expect((await assignmentMembers(f, assigned.id)).map((member) => member.expiresAt)).toEqual([
      f.now() + day,
    ]);

    // Lengthening is granting: a later end or no end is refused without the rights assign needs.
    await expect(extend(f.now() + 2 * day)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      status: 403,
    });
    await expect(extend(null)).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    // Nothing moved.
    expect(
      (await assignmentBindings(f, assigned.id)).map((binding) => [
        binding.expiresAt,
        binding.authorityId,
      ]),
    ).toEqual([[f.now() + day, ownerAuthorityId]]);
    expect((await assignmentMembers(f, assigned.id)).map((member) => member.expiresAt)).toEqual([
      f.now() + day,
    ]);
    expect(
      (await f.iam.api.packages.listAssignments(owner, { tenantId, packageId: kit.id }))[0]!
        .expiresAt,
    ).toBe(f.now() + day);
    expect(await f.iam.api.audit.list(owner, { tenantId, action: 'package:extend' })).toHaveLength(
      1,
    );
  });

  it('requires iam:bindings:create on every packaged role, iam:groups:update on every packaged group, and a grant authority', async () => {
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
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id, writer.id],
      groupIds: [engineering.id],
    });
    const alice = await f.member('alice');
    const erin = await f.member('erin');
    const frank = await f.member('frank');
    const gina = await f.member('gina');
    // Erin may create bindings but not update groups.
    await grant(f, erin.id, 'No groups', [
      'iam:packages:assign',
      'iam:packages:read',
      'iam:bindings:create',
    ]);
    // Frank may update groups but create bindings for the Reader role only.
    await grant(f, frank.id, 'Groups', [
      'iam:packages:assign',
      'iam:packages:read',
      'iam:groups:update',
    ]);
    const readerOnly = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader grants only',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['iam:bindings:create'], resources: [`iam/${reader.id}`] },
        ],
      },
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: readerOnly.id,
      subjectType: 'identity',
      subjectId: frank.id,
    });
    // Gina has every permission but, at first, no grant authority.
    await grant(f, gina.id, 'Full grants', [
      'iam:packages:assign',
      'iam:packages:read',
      'iam:bindings:create',
      'iam:groups:update',
    ]);
    for (const who of [erin.id, frank.id])
      await f.iam.api.authorities.create(owner, { tenantId, identityId: who, ceiling: everything });
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    const before = await assignmentBindings(f, assigned.id);
    expect(before).toHaveLength(2);
    const ownerAuthorityId = before[0]!.authorityId;
    expect(before.every((binding) => binding.authorityId === ownerAuthorityId)).toBe(true);
    const extendAs = async (name: string, expiresAt: number | null) =>
      f.iam.api.packages.extend(
        { token: (await f.signIn(name)).token },
        { tenantId, packageId: kit.id, identityId: alice.id, expiresAt },
      );

    await expect(extendAs('erin', f.now() + 2 * day)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(extendAs('erin', null)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(extendAs('frank', f.now() + 2 * day)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(extendAs('frank', null)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(extendAs('gina', f.now() + 2 * day)).rejects.toMatchObject({
      code: 'GRANT_AUTHORITY_REQUIRED',
      status: 403,
    });
    await expect(extendAs('gina', null)).rejects.toMatchObject({
      code: 'GRANT_AUTHORITY_REQUIRED',
    });
    expect((await assignmentBindings(f, assigned.id)).map((binding) => binding.expiresAt)).toEqual([
      f.now() + day,
      f.now() + day,
    ]);
    // Each of them may still shorten.
    expect((await extendAs('erin', f.now() + day - 60_000)).expiresAt).toBe(f.now() + day - 60_000);

    // The owner lengthening keeps the owner's own authority.
    await f.iam.api.packages.extend(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + 2 * day,
    });
    expect(
      (await assignmentBindings(f, assigned.id)).map((binding) => [
        binding.expiresAt,
        binding.authorityId,
      ]),
    ).toEqual([
      [f.now() + 2 * day, ownerAuthorityId],
      [f.now() + 2 * day, ownerAuthorityId],
    ]);

    // With a grant authority Gina may lengthen, and the package's bindings move to her authority.
    const ginaAuthority = await f.iam.api.authorities.create(owner, {
      tenantId,
      identityId: gina.id,
      ceiling: everything,
    });
    const extended = await extendAs('gina', null);
    expect(extended.expiresAt).toBeUndefined();
    for (const bindingId of assigned.bindingIds) {
      const stored = await f.database.get<StoredBinding & { tenantId: string }>(
        'bindings',
        bindingId,
      );
      expect(stored).toMatchObject({ authorityId: ginaAuthority.id });
      expect(stored!.expiresAt).toBeUndefined();
    }
    expect((await assignmentMembers(f, assigned.id)).map((member) => member.expiresAt)).toEqual([
      undefined,
    ]);
    expect(
      (await f.iam.api.packages.listAssignments(owner, { tenantId, packageId: kit.id }))[0],
    ).toMatchObject({ broken: false });
    const asAlice = { token: (await f.signIn('alice')).token };
    expect(await allowed(f, asAlice, 'documents:read')).toBe(true);
    expect(await allowed(f, asAlice, 'documents:write')).toBe(true);
  });

  it('checks iam:groups:update on every packaged group, not just one of them', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const engineering = await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
    const ops = await f.iam.api.groups.create(owner, { tenantId, name: 'Ops' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      groupIds: [engineering.id, ops.id],
    });
    const alice = await f.member('alice');
    const ivan = await f.member('ivan');
    await grant(f, ivan.id, 'Binder', [
      'iam:packages:assign',
      'iam:packages:read',
      'iam:bindings:create',
    ]);
    const groupUpdate = (name: string, groupId: string) =>
      f.iam.api.roles.create(owner, {
        tenantId,
        name,
        document: {
          version: 1,
          statements: [
            { effect: 'allow', actions: ['iam:groups:update'], resources: [`iam/${groupId}`] },
          ],
        },
      });
    const bindTo = async (roleId: string) =>
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId,
        subjectType: 'identity',
        subjectId: ivan.id,
      });
    await bindTo((await groupUpdate('Engineering editor', engineering.id)).id);
    const ivanAuthority = await f.iam.api.authorities.create(owner, {
      tenantId,
      identityId: ivan.id,
      ceiling: everything,
    });
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    const end = f.now() + day;
    expect((await assignmentMembers(f, assigned.id)).map((member) => member.expiresAt)).toEqual([
      end,
      end,
    ]);
    const [original] = await assignmentBindings(f, assigned.id);
    const ownerAuthorityId = original!.authorityId;
    expect(ownerAuthorityId).not.toBe(ivanAuthority.id);
    const asIvan = { token: (await f.signIn('ivan')).token };
    const extend = (expiresAt: number | null) =>
      f.iam.api.packages.extend(asIvan, {
        tenantId,
        packageId: kit.id,
        identityId: alice.id,
        expiresAt,
      });

    // groups:update on Engineering alone does not cover Ops.
    await expect(extend(f.now() + 2 * day)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      status: 403,
    });
    await expect(extend(null)).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    expect((await assignmentMembers(f, assigned.id)).map((member) => member.expiresAt)).toEqual([
      end,
      end,
    ]);
    expect(
      (await assignmentBindings(f, assigned.id)).map((binding) => [
        binding.expiresAt,
        binding.authorityId,
      ]),
    ).toEqual([[end, ownerAuthorityId]]);

    // With groups:update on Ops as well, the same call goes through.
    await bindTo((await groupUpdate('Ops editor', ops.id)).id);
    expect((await extend(f.now() + 2 * day)).expiresAt).toBe(f.now() + 2 * day);
    expect((await assignmentMembers(f, assigned.id)).map((member) => member.expiresAt)).toEqual([
      f.now() + 2 * day,
      f.now() + 2 * day,
    ]);
    expect(
      (await assignmentBindings(f, assigned.id)).map((binding) => [
        binding.expiresAt,
        binding.authorityId,
      ]),
    ).toEqual([[f.now() + 2 * day, ivanAuthority.id]]);
  });

  it('bounds a lengthened grant by the extender’s own ceiling', async () => {
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
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id, writer.id],
    });
    const alice = await f.member('alice');
    const hank = await f.member('hank');
    await grant(f, hank.id, 'Extender', [
      'iam:packages:assign',
      'iam:packages:read',
      'iam:bindings:create',
      'iam:groups:update',
    ]);
    const hankAuthority = await f.iam.api.authorities.create(owner, {
      tenantId,
      identityId: hank.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    expect(await allowed(f, asAlice, 'documents:write')).toBe(true);
    const asHank = { token: (await f.signIn('hank')).token };
    await f.iam.api.packages.extend(asHank, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + 2 * day,
    });
    expect(
      (await assignmentBindings(f, assigned.id)).map((binding) => binding.authorityId),
    ).toEqual([hankAuthority.id, hankAuthority.id]);
    // Hank could never have granted documents:write, so the longer grant does not carry it.
    expect(await allowed(f, asAlice, 'documents:read')).toBe(true);
    expect(await allowed(f, asAlice, 'documents:write')).toBe(false);
  });

  it('refuses self-extension by a member holding only iam:packages:assign', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const writer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Writer',
      permissions: ['documents:write'],
    });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [writer.id],
    });
    const alice = await f.member('alice');
    await grant(f, alice.id, 'Package operator', ['iam:packages:assign', 'iam:packages:read']);
    const assigned = await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + day,
    });
    const originalEnd = f.now() + day;
    const asAlice = { token: (await f.signIn('alice')).token };
    const extend = (expiresAt: number | null) =>
      f.iam.api.packages.extend(asAlice, {
        tenantId,
        packageId: kit.id,
        identityId: alice.id,
        expiresAt,
      });
    await expect(extend(f.now() + 2 * day)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(extend(null)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Rolling the end forward from "now" is lengthening too.
    f.advance(day / 2);
    await expect(extend(f.now() + day)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await assignmentBindings(f, assigned.id)).map((binding) => binding.expiresAt)).toEqual([
      originalEnd,
    ]);
    f.advance(day / 2 + 1000);
    expect(await allowed(f, asAlice, 'documents:write')).toBe(false);
  });
});

describe('regress-authz: impersonation sessions cannot decide requests', () => {
  it('refuses packages.approveRequest and denyRequest while impersonating a designated approver', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const approvers = await f.iam.api.groups.create(owner, { tenantId, name: 'Approvers' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
      approverGroupId: approvers.id,
    });
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const erin = await f.member('erin');
    await grant(f, alice.id, 'Member', ['iam:packages:request']);
    await grant(f, bob.id, 'Package approver', [
      'iam:packages:approve',
      'iam:packages:read',
      'iam:bindings:create',
      'iam:groups:update',
    ]);
    await grant(f, erin.id, 'Approver with support', [
      'iam:packages:approve',
      'iam:packages:request',
      'iam:bindings:create',
      'iam:groups:update',
      'iam:identities:impersonate',
    ]);
    for (const who of [bob.id, erin.id]) {
      await f.iam.api.groups.addMember(owner, { tenantId, groupId: approvers.id, identityId: who });
      await f.iam.api.authorities.create(owner, { tenantId, identityId: who, ceiling: everything });
    }
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const asErin = { token: (await f.signIn('erin')).token };
    const aliceRequest = await f.iam.api.packages.request(asAlice, { tenantId, packageId: kit.id });
    const erinRequest = await f.iam.api.packages.request(asErin, { tenantId, packageId: kit.id });

    // The owner viewing as Bob (a legitimate approver) cannot decide in his name.
    const ownerAsBob = await f.iam.api.identities.impersonate(owner, {
      tenantId,
      identityId: bob.id,
      reason: 'ticket 1',
    });
    const viewAsBob = { token: ownerAsBob.token };
    await expect(
      f.iam.api.packages.approveRequest(viewAsBob, { tenantId, requestId: aliceRequest.id }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });
    await expect(
      f.iam.api.packages.denyRequest(viewAsBob, { tenantId, requestId: aliceRequest.id }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });

    // Erin, refused on her own request, cannot approve it by viewing as a fellow approver either.
    await expect(
      f.iam.api.packages.approveRequest(asErin, { tenantId, requestId: erinRequest.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const erinAsBob = await f.iam.api.identities.impersonate(asErin, {
      tenantId,
      identityId: bob.id,
      reason: 'ticket 2',
    });
    await expect(
      f.iam.api.packages.approveRequest(
        { token: erinAsBob.token },
        { tenantId, requestId: erinRequest.id },
      ),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });
    await expect(
      f.iam.api.packages.denyRequest(
        { token: erinAsBob.token },
        { tenantId, requestId: aliceRequest.id },
      ),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });

    // Both requests still wait, nothing was granted, and no decision was recorded.
    expect(
      (await f.iam.api.packages.listRequests(owner, { tenantId, packageId: kit.id }))
        .map((request) => request.status)
        .sort(),
    ).toEqual(['pending', 'pending']);
    expect(await allowed(f, asAlice, 'documents:read')).toBe(false);
    expect(await allowed(f, asErin, 'documents:read')).toBe(false);
    const audit = await f.database.find<{ action: string }>('audit', { tenantId });
    expect(audit.filter((event) => event.action.startsWith('package:request-'))).toEqual([]);

    // Bob from his own session decides normally.
    expect(
      (await f.iam.api.packages.approveRequest(asBob, { tenantId, requestId: aliceRequest.id }))
        .status,
    ).toBe('approved');
    expect(
      (await f.iam.api.packages.denyRequest(asBob, { tenantId, requestId: erinRequest.id })).status,
    ).toBe('denied');
    expect(await allowed(f, asAlice, 'documents:read')).toBe(true);
  });

  it('refuses bindings.approveActivation and denyActivation while impersonating a designated approver', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const writer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Writer',
      permissions: ['documents:write'],
    });
    const approvers = await f.iam.api.groups.create(owner, { tenantId, name: 'Approvers' });
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const erin = await f.member('erin');
    await grant(f, alice.id, 'Member', ['iam:bindings:activate']);
    await grant(f, bob.id, 'Approver', ['iam:bindings:approve']);
    await grant(f, erin.id, 'Approver with support', [
      'iam:bindings:approve',
      'iam:bindings:activate',
      'iam:identities:impersonate',
    ]);
    for (const who of [bob.id, erin.id])
      await f.iam.api.groups.addMember(owner, { tenantId, groupId: approvers.id, identityId: who });
    const eligibleFor = (identityId: string) =>
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: writer.id,
        subjectType: 'identity',
        subjectId: identityId,
        eligible: true,
        requireApproval: true,
        approverGroupId: approvers.id,
      });
    const aliceBinding = await eligibleFor(alice.id);
    const erinBinding = await eligibleFor(erin.id);
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const asErin = { token: (await f.signIn('erin')).token };
    const aliceActivation = await f.iam.api.bindings.activate(asAlice, {
      tenantId,
      bindingId: aliceBinding.id,
    });
    const erinActivation = await f.iam.api.bindings.activate(asErin, {
      tenantId,
      bindingId: erinBinding.id,
    });
    expect([aliceActivation.status, erinActivation.status]).toEqual(['pending', 'pending']);

    const ownerAsBob = await f.iam.api.identities.impersonate(owner, {
      tenantId,
      identityId: bob.id,
      reason: 'ticket 1',
    });
    const viewAsBob = { token: ownerAsBob.token };
    await expect(
      f.iam.api.bindings.approveActivation(viewAsBob, {
        tenantId,
        activationId: aliceActivation.id,
      }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });
    await expect(
      f.iam.api.bindings.denyActivation(viewAsBob, { tenantId, activationId: aliceActivation.id }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });

    await expect(
      f.iam.api.bindings.approveActivation(asErin, { tenantId, activationId: erinActivation.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const erinAsBob = await f.iam.api.identities.impersonate(asErin, {
      tenantId,
      identityId: bob.id,
      reason: 'ticket 2',
    });
    await expect(
      f.iam.api.bindings.approveActivation(
        { token: erinAsBob.token },
        { tenantId, activationId: erinActivation.id },
      ),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });
    await expect(
      f.iam.api.bindings.denyActivation(
        { token: erinAsBob.token },
        { tenantId, activationId: aliceActivation.id },
      ),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });

    expect(await allowed(f, asAlice, 'documents:write')).toBe(false);
    expect(await allowed(f, asErin, 'documents:write')).toBe(false);
    const stored = await f.database.find<{ id: string; status?: string }>('bindingActivations', {
      tenantId,
    });
    expect(stored.map((activation) => activation.status)).toEqual(['pending', 'pending']);

    expect(
      (
        await f.iam.api.bindings.approveActivation(asBob, {
          tenantId,
          activationId: aliceActivation.id,
        })
      ).active,
    ).toBe(true);
    expect(
      (
        await f.iam.api.bindings.denyActivation(asBob, {
          tenantId,
          activationId: erinActivation.id,
        })
      ).status,
    ).toBe('denied');
    expect(await allowed(f, asAlice, 'documents:write')).toBe(true);
  });
});

describe('regress-authz: packages.listApprovals is scoped per package', () => {
  it('lists only requests of requestable packages on which the caller holds iam:packages:approve', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const create = (name: string) =>
      f.iam.api.packages.create(owner, {
        tenantId,
        name,
        roleIds: [reader.id],
        requestable: true,
      });
    const secret = await create('Secret');
    const other = await create('Other');
    const legacy = await create('Legacy');
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    const gus = await f.member('gus');
    for (const who of [alice.id, bob.id, carol.id])
      await grant(f, who, `Member ${who}`, ['iam:packages:request']);
    const scoped = (name: string, resources: string[]) =>
      f.iam.api.roles.create(owner, {
        tenantId,
        name,
        document: {
          version: 1,
          statements: [{ effect: 'allow', actions: ['iam:packages:approve'], resources }],
        },
      });
    const daveRole = await scoped('Other approver', [
      `iam/${tenantId}`,
      `iam/${other.id}`,
      `iam/${legacy.id}`,
    ]);
    const gusRole = await scoped('Package-only approver', [`iam/${other.id}`]);
    const tina = await f.member('tina');
    const tinaRole = await scoped('Tenant-only approver', [`iam/${tenantId}`]);
    for (const [roleId, subjectId] of [
      [daveRole.id, dave.id],
      [gusRole.id, gus.id],
      [tinaRole.id, tina.id],
    ] as const)
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId,
        subjectType: 'identity',
        subjectId,
      });
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const asCarol = { token: (await f.signIn('carol')).token };
    const asDave = { token: (await f.signIn('dave')).token };
    const asGus = { token: (await f.signIn('gus')).token };
    const secretRequest = await f.iam.api.packages.request(asAlice, {
      tenantId,
      packageId: secret.id,
      justification: 'confidential: HR case 42',
    });
    const otherRequest = await f.iam.api.packages.request(asBob, {
      tenantId,
      packageId: other.id,
    });
    const legacyRequest = await f.iam.api.packages.request(asCarol, {
      tenantId,
      packageId: legacy.id,
    });
    // A pending request left on a package that is no longer requestable (the update path cancels such
    // requests, so the state is written to the store directly) is not something anyone can grant.
    const legacyRecord = await f.database.get<
      Record<string, unknown> & { id: string; tenantId: string }
    >('accessPackages', legacy.id);
    const { requestable: _requestable, ...closed } = legacyRecord!;
    await f.database.transaction((tx) =>
      tx.put('accessPackages', closed as { id: string; tenantId: string }),
    );

    // Dave may decide Other (and Legacy, were it requestable), never Secret.
    expect(
      (await f.iam.api.packages.listApprovals(asDave, { tenantId })).map((request) => request.id),
    ).toEqual([otherRequest.id]);
    await expect(
      f.iam.api.packages.denyRequest(asDave, { tenantId, requestId: secretRequest.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // The owner may decide everything, but still sees nothing of the closed package.
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId }))
        .map((request) => request.id)
        .sort(),
    ).toEqual([secretRequest.id, otherRequest.id].sort());
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).some(
        (request) => request.id === legacyRequest.id,
      ),
    ).toBe(false);
    // The list itself needs iam:packages:approve on the tenant.
    await expect(f.iam.api.packages.listApprovals(asGus, { tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // ...but the tenant grant alone opens the list, not any package's requests.
    const asTina = { token: (await f.signIn('tina')).token };
    expect(await f.iam.api.packages.listApprovals(asTina, { tenantId })).toEqual([]);
    // Deciding what the list shows works, after which it is empty.
    expect(
      (await f.iam.api.packages.denyRequest(asDave, { tenantId, requestId: otherRequest.id }))
        .status,
    ).toBe('denied');
    expect(await f.iam.api.packages.listApprovals(asDave, { tenantId })).toEqual([]);
  });
});

describe('regress-authz: a request that names approvers must reach an active one', () => {
  it('refuses packages.request with no active approver, and accepts packages that name none', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const everyone = await f.iam.api.groups.create(owner, { tenantId, name: 'Everyone' });
    const member = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:packages:request'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: member.id,
      subjectType: 'group',
      subjectId: everyone.id,
    });
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const frank = await f.member('frank');
    const erin = await f.member('erin');
    await f.iam.api.groups.addMembers(owner, {
      tenantId,
      groupId: everyone.id,
      identityIds: [alice.id, bob.id, carol.id],
    });
    const empty = await f.iam.api.groups.create(owner, { tenantId, name: 'Empty approvers' });
    const solo = await f.iam.api.groups.create(owner, { tenantId, name: 'Solo approvers' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: solo.id, identityId: alice.id });
    const dormant = await f.iam.api.groups.create(owner, { tenantId, name: 'Dormant approvers' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: dormant.id, identityId: erin.id });
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: erin.id,
      status: 'disabled',
    });
    const create = (name: string, extra: object) =>
      f.iam.api.packages.create(owner, {
        tenantId,
        name,
        roleIds: [reader.id],
        requestable: true,
        ...extra,
      });
    const emptyKit = await create('Empty group kit', { approverGroupId: empty.id });
    const soloKit = await create('Solo group kit', { approverGroupId: solo.id });
    const dormantKit = await create('Dormant group kit', { approverGroupId: dormant.id });
    const managerKit = await create('Manager kit', { managerApproval: true });
    const bothKit = await create('Both kit', { approverGroupId: empty.id, managerApproval: true });
    const openKit = await create('Open kit', {});
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const asCarol = { token: (await f.signIn('carol')).token };
    const request = (credential: Credential, packageId: string) =>
      f.iam.api.packages.request(credential, { tenantId, packageId });
    const refused = { code: 'INVALID_TRANSITION', status: 409 };

    // An empty approver group, the requester as its only member, or only disabled members.
    await expect(request(asAlice, emptyKit.id)).rejects.toMatchObject(refused);
    await expect(request(asAlice, soloKit.id)).rejects.toMatchObject(refused);
    await expect(request(asAlice, dormantKit.id)).rejects.toMatchObject(refused);
    // Someone else can reach Alice through the solo group.
    expect((await request(asCarol, soloKit.id)).status).toBe('pending');
    // Manager approval without a manager, or with a disabled one.
    await expect(request(asAlice, managerKit.id)).rejects.toMatchObject(refused);
    await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: alice.id,
      managerId: frank.id,
    });
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: frank.id,
      status: 'disabled',
    });
    await expect(request(asAlice, managerKit.id)).rejects.toMatchObject(refused);
    // Both routes named, neither reachable.
    await expect(request(asBob, bothKit.id)).rejects.toMatchObject(refused);
    // One reachable route suffices.
    await f.iam.api.identities.update(owner, { tenantId, identityId: bob.id, managerId: carol.id });
    expect((await request(asBob, bothKit.id)).status).toBe('pending');
    await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: alice.id,
      managerId: carol.id,
    });
    expect((await request(asAlice, managerKit.id)).status).toBe('pending');
    // A package that names no approvers still accepts requests.
    expect((await request(asAlice, openKit.id)).status).toBe('pending');

    // Refused requests left nothing behind.
    expect(
      (await f.iam.api.packages.listRequests(owner, { tenantId }))
        .map((item) => `${item.packageName}:${item.identityName}`)
        .sort(),
    ).toEqual(['Both kit:bob', 'Manager kit:alice', 'Open kit:alice', 'Solo group kit:carol']);
  });

  it('refuses bindings.activate for approval with no active approver, and accepts bindings that name none', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const carol = await f.member('carol');
    const frank = await f.member('frank');
    const erin = await f.member('erin');
    await grant(f, alice.id, 'Member', ['iam:bindings:activate']);
    const empty = await f.iam.api.groups.create(owner, { tenantId, name: 'Empty approvers' });
    const solo = await f.iam.api.groups.create(owner, { tenantId, name: 'Solo approvers' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: solo.id, identityId: alice.id });
    const dormant = await f.iam.api.groups.create(owner, { tenantId, name: 'Dormant approvers' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: dormant.id, identityId: erin.id });
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: erin.id,
      status: 'disabled',
    });
    let count = 0;
    const eligible = async (extra: object) => {
      const role = await f.iam.api.roles.create(owner, {
        tenantId,
        name: `Writer ${++count}`,
        permissions: ['documents:write'],
      });
      return f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: alice.id,
        eligible: true,
        requireApproval: true,
        ...extra,
      });
    };
    const emptyBinding = await eligible({ approverGroupId: empty.id });
    const soloBinding = await eligible({ approverGroupId: solo.id });
    const dormantBinding = await eligible({ approverGroupId: dormant.id });
    const managerBinding = await eligible({ managerApproval: true });
    const bothBinding = await eligible({ approverGroupId: empty.id, managerApproval: true });
    const openBinding = await eligible({});
    const asAlice = { token: (await f.signIn('alice')).token };
    const activate = (bindingId: string) =>
      f.iam.api.bindings.activate(asAlice, { tenantId, bindingId });
    const refused = { code: 'INVALID_TRANSITION', status: 409 };

    await expect(activate(emptyBinding.id)).rejects.toMatchObject(refused);
    await expect(activate(soloBinding.id)).rejects.toMatchObject(refused);
    await expect(activate(dormantBinding.id)).rejects.toMatchObject(refused);
    await expect(activate(managerBinding.id)).rejects.toMatchObject(refused);
    await expect(activate(bothBinding.id)).rejects.toMatchObject(refused);
    await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: alice.id,
      managerId: frank.id,
    });
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: frank.id,
      status: 'disabled',
    });
    await expect(activate(managerBinding.id)).rejects.toMatchObject(refused);
    await expect(activate(bothBinding.id)).rejects.toMatchObject(refused);
    expect(await f.database.find('bindingActivations', { tenantId, identityId: alice.id })).toEqual(
      [],
    );

    // An active manager is reachable; a binding that names no approvers still accepts requests.
    await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: alice.id,
      managerId: carol.id,
    });
    expect((await activate(managerBinding.id)).status).toBe('pending');
    expect((await activate(bothBinding.id)).status).toBe('pending');
    expect((await activate(openBinding.id)).status).toBe('pending');
    expect(
      (
        await f.database.find<{ bindingId: string; status?: string }>('bindingActivations', {
          tenantId,
          identityId: alice.id,
        })
      )
        .map((activation) => activation.bindingId)
        .sort(),
    ).toEqual([managerBinding.id, bothBinding.id, openBinding.id].sort());
  });
});
