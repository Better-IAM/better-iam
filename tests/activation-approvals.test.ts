import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('approval-gated activation', () => {
  it('turns activation into a request that an approver grants or denies, with emails and audit', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const auditor = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Auditor',
      permissions: ['iam:audit:read'],
    });
    const member = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:bindings:activate'],
    });
    const approver = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Approver',
      permissions: ['iam:bindings:approve'],
    });
    const approvers = await f.iam.api.groups.create(owner, { tenantId, name: 'Approvers' });
    for (const identity of [alice, bob, carol])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: member.id,
        subjectType: 'identity',
        subjectId: identity.id,
      });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: approver.id,
      subjectType: 'group',
      subjectId: approvers.id,
    });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: approvers.id,
      identityId: bob.id,
    });
    // The approver group must exist and only applies to eligible bindings.
    await expect(
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: auditor.id,
        subjectType: 'identity',
        subjectId: alice.id,
        eligible: true,
        approverGroupId: 'missing',
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: auditor.id,
        subjectType: 'identity',
        subjectId: alice.id,
        requireApproval: true,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: auditor.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      requireApproval: true,
      approverGroupId: approvers.id,
      maxActivationMs: 2 * 3_600_000,
    });
    expect(eligible).toMatchObject({ requireApproval: true, approverGroupId: approvers.id });
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const asCarol = { token: (await f.signIn('carol')).token };
    const audit = (credential: { token: string }) =>
      f.iam.api.audit.list(credential, { tenantId, limit: 1 });
    // The request grants nothing yet, shows as pending, and emails the approver group.
    const request = await f.iam.api.bindings.activate(asAlice, {
      tenantId,
      bindingId: eligible.id,
      justification: 'INC-7',
      durationMs: 30 * 60_000,
    });
    expect(request).toMatchObject({
      status: 'pending',
      active: false,
      requestedDurationMs: 30 * 60_000,
    });
    expect(request.expiresAt).toBe(f.now() + 24 * 3_600_000);
    await expect(audit(asAlice)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: eligible.id }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const mine = await f.iam.api.bindings.listMine(asAlice, { tenantId });
    expect(mine.find((binding) => binding.id === eligible.id)).toMatchObject({
      pendingActivation: { id: request.id, expiresAt: request.expiresAt },
    });
    await f.iam.auth.dispatchOutbox();
    const notices = f.inbox.filter((message) => message.template === 'activation-request');
    expect(notices.map((message) => message.to)).toEqual(['bob@acme.test']);
    expect(notices[0]!.payload).toMatchObject({
      activationId: request.id,
      roleName: 'Auditor',
      requesterName: 'alice',
      justification: 'INC-7',
    });
    expect(
      (await f.iam.api.audit.list(owner, { tenantId, action: 'binding:activation-requested' }))[0],
    ).toMatchObject({ actorId: alice.id, metadata: { activationId: request.id } });
    // Who may decide: not the requester, not a holder outside the approver group, not without the permission.
    await expect(
      f.iam.api.bindings.approveActivation(asAlice, { tenantId, activationId: request.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.bindings.approveActivation(asCarol, { tenantId, activationId: request.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: approvers.id,
      identityId: alice.id,
    });
    await expect(
      f.iam.api.bindings.approveActivation(asAlice, { tenantId, activationId: request.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await f.iam.api.bindings.listApprovals(asAlice, { tenantId })).toEqual([]);
    const inbox = await f.iam.api.bindings.listApprovals(asBob, { tenantId });
    expect(inbox).toHaveLength(1);
    expect(inbox[0]).toMatchObject({
      id: request.id,
      status: 'pending',
      role: { id: auditor.id, name: 'Auditor' },
      requester: { id: alice.id, email: 'alice@acme.test' },
    });
    expect(
      await f.iam.api.bindings.listActivations(owner, { tenantId, status: 'pending' }),
    ).toHaveLength(1);
    expect(await f.iam.api.bindings.listActivations(owner, { tenantId })).toEqual([]);
    // Approval with a shorter duration makes the role live from now.
    const approved = await f.iam.api.bindings.approveActivation(asBob, {
      tenantId,
      activationId: request.id,
      durationMs: 10 * 60_000,
      note: 'ok for the incident',
    });
    expect(approved).toMatchObject({
      status: 'active',
      active: true,
      decidedBy: bob.id,
      note: 'ok for the incident',
      expiresAt: f.now() + 10 * 60_000,
    });
    expect((await audit(asAlice)).length).toBe(1);
    await f.iam.auth.dispatchOutbox();
    const decided = f.inbox.filter((message) => message.template === 'activation-decided');
    expect(decided).toHaveLength(1);
    expect(decided[0]).toMatchObject({
      to: 'alice@acme.test',
      payload: { decision: 'approved', deciderName: 'bob', note: 'ok for the incident' },
    });
    expect(await f.iam.api.bindings.listApprovals(asBob, { tenantId })).toEqual([]);
    await expect(
      f.iam.api.bindings.approveActivation(asBob, { tenantId, activationId: request.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    f.advance(10 * 60_000 + 1);
    await expect(audit(asAlice)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Denial keeps a record until the worker sweeps it; cancelling one's own request is allowed.
    const second = await f.iam.api.bindings.activate(asAlice, {
      tenantId,
      bindingId: eligible.id,
    });
    const denied = await f.iam.api.bindings.denyActivation(asBob, {
      tenantId,
      activationId: second.id,
      note: 'not now',
    });
    expect(denied).toMatchObject({ status: 'denied', active: false, note: 'not now' });
    expect(
      (await f.iam.api.bindings.listActivations(owner, { tenantId, status: 'denied' })).map(
        (item) => item.id,
      ),
    ).toEqual([second.id]);
    expect(
      (await f.iam.api.audit.list(owner, { tenantId, action: 'binding:activation-denied' }))[0],
    ).toMatchObject({ actorId: bob.id, metadata: { note: 'not now', identityId: alice.id } });
    const third = await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: eligible.id });
    expect(third.status).toBe('pending');
    expect(
      await f.iam.api.bindings.deactivate(asAlice, { tenantId, activationId: third.id }),
    ).toEqual({ deactivated: true });
    expect(
      (await f.iam.api.audit.list(owner, { tenantId, action: 'binding:deactivate' }))[0]!.metadata,
    ).toMatchObject({ cancelled: true });
    // Requests lapse after a day and are swept by the worker.
    const fourth = await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: eligible.id });
    f.advance(24 * 3_600_000 + 1);
    expect(
      await f.iam.api.bindings.listActivations(owner, { tenantId, status: 'pending' }),
    ).toEqual([]);
    const admin = await f.ownerSignIn();
    await expect(
      f.iam.api.bindings.approveActivation(admin, { tenantId, activationId: fourth.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // One record per binding and identity: each new request replaced the previous ended one.
    expect((await f.iam.purgeDeleted()).expiredActivations).toBe(1);
    // Without an approver group, anyone holding the permission on the role may decide (owner included).
    await f.iam.api.bindings.update(admin, {
      tenantId,
      bindingId: eligible.id,
      approverGroupId: null,
    });
    const fifth = await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: eligible.id });
    await expect(f.iam.api.bindings.listApprovals(asCarol, { tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    expect((await f.iam.api.bindings.listApprovals(admin, { tenantId })).map((i) => i.id)).toEqual([
      fifth.id,
    ]);
    const granted = await f.iam.api.bindings.approveActivation(admin, {
      tenantId,
      activationId: fifth.id,
    });
    // No duration was requested, so the binding's maximum (two hours) applies.
    expect(granted.expiresAt).toBe(f.now() + 2 * 3_600_000);
    // Configuration sync carries the approval settings by group name.
    const exported = await f.iam.api.config.export(admin, { tenantId });
    await f.iam.api.config.apply(admin, {
      tenantId,
      config: {
        version: 1,
        bindings: [
          {
            group: 'Approvers',
            role: 'Auditor',
            eligible: true,
            requireApproval: true,
            approverGroup: 'Approvers',
          },
        ],
      },
    });
    expect(
      (await f.iam.api.config.export(admin, { tenantId })).bindings?.find(
        (binding) => binding.role === 'Auditor' && binding.group === 'Approvers',
      ),
    ).toEqual({
      group: 'Approvers',
      role: 'Auditor',
      eligible: true,
      requireApproval: true,
      approverGroup: 'Approvers',
    });
    expect(exported.bindings?.some((binding) => binding.approverGroup)).toBe(false);
  });
});
