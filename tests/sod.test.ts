import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('separation of duties', () => {
  it('prevents conflicting grants on every granting path and reports existing conflicts', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const role = (name: string) =>
      api.roles.create(owner, { tenantId, name, permissions: ['documents:read'] });
    const requester = await role('Payment requester');
    const approver = await role('Payment approver');
    const auditor = await role('Auditor');
    const bind = (
      roleId: string,
      subjectId: string,
      subjectType: 'identity' | 'group' = 'identity',
    ) => api.bindings.create(owner, { tenantId, roleId, subjectType, subjectId });
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    await bind(requester.id, alice.id);
    // Carol's conflict predates the rule.
    await bind(requester.id, carol.id);
    await bind(approver.id, carol.id);

    for (const input of [
      { name: 'One role', roleIds: [requester.id] },
      { name: 'Unknown', roleIds: [requester.id, 'missing'] },
      { name: 'Bad mode', roleIds: [requester.id, approver.id], mode: 'maybe' },
    ])
      await expect(api.sod.create(owner, { tenantId, ...input } as never)).rejects.toMatchObject({
        status: expect.any(Number),
      });
    const ownerRole = (await f.iam.store.find('roles', { tenantId })).find((r) => r.protected)!;
    await expect(
      api.sod.create(owner, { tenantId, name: 'Owners', roleIds: [ownerRole.id, auditor.id] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    const rule = await api.sod.create(owner, {
      tenantId,
      name: 'Payments',
      roleIds: [requester.id, approver.id],
    });
    expect(rule).toMatchObject({ mode: 'prevent', existingViolations: 1 });

    // Direct binding.
    await expect(bind(approver.id, alice.id)).rejects.toMatchObject({
      code: 'SOD_CONFLICT',
      status: 409,
    });
    expect(await f.iam.store.find('bindings', { tenantId, subjectId: alice.id })).toHaveLength(1);
    // A future-dated grant counts too: the conflict would begin when it starts.
    await expect(
      api.bindings.create(owner, {
        tenantId,
        roleId: approver.id,
        subjectType: 'identity',
        subjectId: alice.id,
        startsAt: f.now() + 86_400_000,
      } as never),
    ).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
    // Group membership that would confer the conflicting role.
    const approvers = await api.groups.create(owner, { tenantId, name: 'Approvers' });
    await bind(approver.id, approvers.id, 'group');
    await expect(
      api.groups.addMember(owner, { tenantId, groupId: approvers.id, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
    await api.groups.addMember(owner, { tenantId, groupId: approvers.id, identityId: bob.id });
    // Bulk onboarding.
    await expect(
      api.identities.createMany(owner, {
        tenantId,
        identities: [
          {
            email: 'dave@acme.test',
            name: 'Dave',
            roleIds: [requester.id],
            groupIds: [approvers.id],
          },
        ],
      } as never),
    ).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
    expect(await f.iam.store.find('identities', { email: 'dave@acme.test' })).toHaveLength(0);
    // Invitation acceptance runs outside the operation envelope and is checked too.
    await api.identities.invite(owner, {
      tenantId,
      email: 'erin@acme.test',
      roleIds: [requester.id],
      groupIds: [approvers.id],
    });
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.filter((m) => m.template === 'member-invitation').at(-1)!;
    await expect(
      api.identities.acceptInvitation({
        tenantId,
        token: invitation.payload.token!,
        name: 'Erin',
        password: 'a strong erin password',
      }),
    ).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
    // Access packages materialize bindings too.
    const kit = await api.packages.create(owner, {
      tenantId,
      name: 'Approver kit',
      roleIds: [approver.id],
    });
    await expect(
      api.packages.assign(owner, { tenantId, packageId: kit.id, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'SOD_CONFLICT' });
    expect(
      await f.iam.store.find('packageAssignments', { tenantId, identityId: alice.id }),
    ).toHaveLength(0);

    // The pre-existing conflict never blocks unrelated grants, and it is reported.
    await bind(auditor.id, carol.id);
    const violations = await api.sod.violations(owner, { tenantId });
    expect(violations).toEqual([
      expect.objectContaining({
        ruleName: 'Payments',
        identityId: carol.id,
        identityName: 'carol@acme.test',
        roleNames: ['Payment requester', 'Payment approver'],
      }),
    ]);
    const report = await api.analysis.findings(owner, { tenantId });
    expect(report.findings.filter((finding) => finding.kind === 'separation-of-duties')).toEqual([
      expect.objectContaining({
        severity: 'high',
        subject: expect.objectContaining({ id: carol.id }),
      }),
    ]);

    // Detect mode reports without blocking; switching modes and deleting take effect immediately.
    await api.sod.update(owner, { tenantId, ruleId: rule.id, mode: 'detect' });
    await bind(approver.id, alice.id);
    expect((await api.sod.violations(owner, { tenantId })).map((v) => v.identityId).sort()).toEqual(
      [alice.id, carol.id].sort(),
    );
    await api.sod.delete(owner, { tenantId, ruleId: rule.id });
    expect(await api.sod.violations(owner, { tenantId })).toEqual([]);
    expect(await api.sod.list(owner, { tenantId })).toEqual([]);
  });

  it('requires sod permissions', async () => {
    const f = await organizationFixture();
    await f.member('mallory');
    const mallory = await f.signIn('mallory');
    await expect(
      f.iam.api.sod.list({ token: mallory.token }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ status: 403 });
  });
});
