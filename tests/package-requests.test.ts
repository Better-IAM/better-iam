import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('package requests', () => {
  it('lets members request a package, routes it to approvers, and assigns it on approval', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const engineering = await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
    const approvers = await f.iam.api.groups.create(owner, { tenantId, name: 'Approvers' });
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
    // Approvers decide and, because approval assigns under their authority, may grant every part.
    const approver = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Package approver',
      permissions: ['iam:packages:approve', 'iam:bindings:create', 'iam:groups:update'],
    });
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    await f.iam.api.groups.addMembers(owner, {
      tenantId,
      groupId: everyone.id,
      identityIds: [alice.id, bob.id],
    });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: approvers.id,
      identityId: bob.id,
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: approver.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await f.iam.api.authorities.create(owner, {
      tenantId,
      identityId: bob.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
      },
    });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Engineer kit',
      roleIds: [reader.id],
      groupIds: [engineering.id],
      approverGroupId: approvers.id,
      requireJustification: true,
      maxDurationMs: 30 * day,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const asCarol = { token: (await f.signIn('carol')).token };
    const request = (credential: { token: string }, input: object) =>
      f.iam.api.packages.request(credential, { tenantId, packageId: kit.id, ...input });
    // Only requestable packages, only by members holding iam:packages:request, within the package's rules.
    await expect(
      request(asAlice, { justification: 'x', expiresAt: f.now() + day }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await f.iam.api.packages.update(owner, { tenantId, packageId: kit.id, requestable: true });
    await expect(
      request(asCarol, { justification: 'x', expiresAt: f.now() + day }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(request(asAlice, { expiresAt: f.now() + day })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(
      request(asAlice, { justification: 'x', expiresAt: f.now() + 60 * day }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const first = await request(asAlice, {
      justification: 'Joining the platform team',
      expiresAt: f.now() + 10 * day,
    });
    expect(first).toMatchObject({
      status: 'pending',
      packageName: 'Engineer kit',
      identityName: 'alice',
      desiredExpiresAt: f.now() + 10 * day,
      expiresAt: f.now() + day,
    });
    await expect(
      request(asAlice, { justification: 'again', expiresAt: f.now() + day }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox
        .filter((message) => message.template === 'package-request')
        .map((message) => [message.to, message.payload.requesterName, message.payload.packageName]),
    ).toEqual([['bob@acme.test', 'alice', 'Engineer kit']]);
    const mine = await f.iam.api.packages.listMine(asAlice, { tenantId });
    expect(
      mine.packages.map((pkg) => [
        pkg.name,
        pkg.roles.map((role) => role.name),
        pkg.groups.map((group) => group.name),
        pkg.approverGroupName,
        pkg.pending?.id,
        pkg.assignment,
      ]),
    ).toEqual([['Engineer kit', ['Reader'], ['Engineering'], 'Approvers', first.id, undefined]]);
    // Deciding takes iam:packages:approve and membership of the approver group; nobody decides on their own.
    await expect(
      f.iam.api.packages.approveRequest(asAlice, { tenantId, requestId: first.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.packages.approveRequest(owner, { tenantId, requestId: first.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await f.iam.api.packages.listApprovals(asBob, { tenantId })).map((item) => item.id),
    ).toEqual([first.id]);
    const approved = await f.iam.api.packages.approveRequest(asBob, {
      tenantId,
      requestId: first.id,
      note: 'Welcome',
    });
    expect(approved).toMatchObject({ status: 'approved', decidedBy: bob.id, note: 'Welcome' });
    expect(
      (
        await f.iam.authorize({
          ...asAlice,
          tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed,
    ).toBe(true);
    const assignment = (
      await f.iam.api.packages.listAssignments(owner, { tenantId, packageId: kit.id })
    )[0]!;
    expect(assignment).toMatchObject({
      id: approved.assignmentId,
      identityId: alice.id,
      assignedBy: bob.id,
      expiresAt: f.now() + 10 * day,
      justification: 'Joining the platform team',
    });
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox
        .filter((message) => message.template === 'package-decided')
        .map((message) => [message.to, message.payload.decision, message.payload.note]),
    ).toEqual([['alice@acme.test', 'approved', 'Welcome']]);
    expect(await f.iam.api.packages.listApprovals(asBob, { tenantId })).toEqual([]);
    expect(
      (await f.iam.api.packages.listMine(asAlice, { tenantId })).packages[0]!.assignment?.id,
    ).toBe(approved.assignmentId);
    await expect(
      request(asAlice, { justification: 'more', expiresAt: f.now() + day }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      f.iam.api.packages.approveRequest(asBob, { tenantId, requestId: first.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // Bob is the only approver, and nobody decides on their own request: his request could reach no one.
    await expect(
      request(asBob, { justification: 'Me too', expiresAt: f.now() + day }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // Cancelling, denying, and lapsing.
    const dave = await f.member('dave');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: everyone.id,
      identityId: dave.id,
    });
    const asDave = { token: (await f.signIn('dave')).token };
    const second = await request(asDave, { justification: 'Me too', expiresAt: f.now() + day });
    await expect(
      f.iam.api.packages.cancelRequest(asAlice, { tenantId, requestId: second.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (await f.iam.api.packages.cancelRequest(asDave, { tenantId, requestId: second.id })).status,
    ).toBe('cancelled');
    const third = await request(asDave, { justification: 'Curious', expiresAt: f.now() + day });
    const denied = await f.iam.api.packages.denyRequest(asBob, {
      tenantId,
      requestId: third.id,
      note: 'Not yet',
    });
    expect(denied).toMatchObject({ status: 'denied', decidedBy: bob.id, note: 'Not yet' });
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox.filter((message) => message.template === 'package-decided').at(-1),
    ).toMatchObject({ to: 'dave@acme.test', payload: { decision: 'denied', note: 'Not yet' } });
    const erin = await f.member('erin');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: everyone.id,
      identityId: erin.id,
    });
    const asErin = { token: (await f.signIn('erin')).token };
    const fourth = await request(asErin, { justification: 'Later', expiresAt: f.now() + 5 * day });
    f.advance(day + 1);
    expect((await f.iam.purgeDeleted()).expiredRequests).toBe(1);
    await expect(
      f.iam.api.packages.approveRequest(asBob, { tenantId, requestId: fourth.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const admin = await f.ownerSignIn();
    expect(
      (await f.iam.api.packages.listRequests(admin, { tenantId, status: 'expired' })).map(
        (item) => item.id,
      ),
    ).toEqual([fourth.id]);
    expect(
      (await f.iam.api.packages.listRequests(admin, { tenantId, packageId: kit.id }))
        .map((item) => item.status)
        .sort(),
    ).toEqual(['approved', 'cancelled', 'denied', 'expired']);
    // Offboarding cancels a pending request; the audit trail and the configuration document carry the flow.
    const frank = await f.member('frank');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: everyone.id,
      identityId: frank.id,
    });
    const asFrank = { token: (await f.signIn('frank')).token };
    await request(asFrank, { justification: 'Leaving soon', expiresAt: f.now() + day });
    const offboarded = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: frank.id,
      reason: 'Left',
    });
    expect(offboarded).toMatchObject({ accessRequests: 1 });
    expect(
      (await f.iam.api.packages.listRequests(admin, { tenantId, identityId: frank.id })).map(
        (item) => item.status,
      ),
    ).toEqual(['cancelled']);
    expect(
      await f.iam.api.audit.list(admin, { tenantId, action: 'package:request-approved' }),
    ).toHaveLength(1);
    expect((await f.iam.api.config.export(admin, { tenantId })).packages).toEqual([
      {
        name: 'Engineer kit',
        roles: ['Reader'],
        groups: ['Engineering'],
        maxDurationMs: 30 * day,
        requireJustification: true,
        requestable: true,
        approverGroup: 'Approvers',
      },
    ]);
    // The owner revokes what the approver granted (the assignment owns its records), then deletes the package.
    expect(
      await f.iam.api.packages.revoke(admin, { tenantId, packageId: kit.id, identityId: alice.id }),
    ).toEqual({ revoked: true, bindings: 1, memberships: 1 });
    expect(
      (
        await f.iam.authorize({
          ...asAlice,
          tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed,
    ).toBe(false);
    await f.iam.api.packages.delete(admin, { tenantId, packageId: kit.id });
    expect(await f.iam.api.packages.listRequests(admin, { tenantId })).toEqual([]);
  });
});
