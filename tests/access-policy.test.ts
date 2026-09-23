import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('tenant access policy', () => {
  it('sets organization-wide floors that every eligible binding inherits and that sync carries', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const auditor = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Auditor',
      permissions: ['iam:audit:read'],
    });
    const member = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:bindings:activate', 'iam:bindings:approve'],
    });
    for (const identity of [alice, bob])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: member.id,
        subjectType: 'identity',
        subjectId: identity.id,
      });
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: auditor.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      maxActivationMs: 4 * 3_600_000,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    // Without a policy the binding's own settings apply: four hours, no justification.
    const first = await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: eligible.id });
    expect(first.expiresAt).toBe(f.now() + 4 * 3_600_000);
    await f.iam.api.bindings.deactivate(asAlice, { tenantId, activationId: first.id });
    // Validation of the policy itself.
    for (const accessPolicy of [
      { maxActivationMs: 1 },
      { approvalLifetimeMs: 1 },
      { requireMfa: 'yes' },
      { unknown: true },
    ])
      await expect(
        f.iam.api.tenants.setAccessPolicy(owner, { tenantId, accessPolicy: accessPolicy as never }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.tenants.setAccessPolicy(asAlice, { tenantId, accessPolicy: { requireMfa: true } }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const tenant = await f.iam.api.tenants.setAccessPolicy(owner, {
      tenantId,
      accessPolicy: {
        maxActivationMs: 30 * 60_000,
        requireJustification: true,
        requireApproval: true,
        approvalLifetimeMs: 2 * 3_600_000,
        requireMfa: false,
      },
    });
    expect(tenant.accessPolicy).toEqual({
      maxActivationMs: 30 * 60_000,
      requireJustification: true,
      requireApproval: true,
      approvalLifetimeMs: 2 * 3_600_000,
    });
    expect(
      (await f.iam.api.audit.list(owner, { tenantId, action: 'tenant:access-policy' }))[0]!
        .metadata,
    ).toMatchObject({ accessPolicy: { requireApproval: true } });
    // The floors now govern the binding: justification, approval, a shorter cap, a shorter request lifetime.
    await expect(
      f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: eligible.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.bindings.activate(asAlice, {
        tenantId,
        bindingId: eligible.id,
        justification: 'audit',
        durationMs: 45 * 60_000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const request = await f.iam.api.bindings.activate(asAlice, {
      tenantId,
      bindingId: eligible.id,
      justification: 'audit',
    });
    expect(request).toMatchObject({
      status: 'pending',
      requestedDurationMs: 30 * 60_000,
      expiresAt: f.now() + 2 * 3_600_000,
    });
    const approved = await f.iam.api.bindings.approveActivation(asBob, {
      tenantId,
      activationId: request.id,
    });
    expect(approved.expiresAt).toBe(f.now() + 30 * 60_000);
    // Configuration sync exports the policy, plans changes to it, and clears it with `{}`.
    const exported = await f.iam.api.config.export(owner, { tenantId });
    expect(exported.accessPolicy).toEqual(tenant.accessPolicy);
    const plan = await f.iam.api.config.plan(owner, {
      tenantId,
      config: { version: 1, accessPolicy: { requireMfa: true } },
    });
    expect(plan.changes).toEqual([
      expect.objectContaining({
        kind: 'accessPolicy',
        action: 'update',
        fields: [
          'approvalLifetimeMs',
          'maxActivationMs',
          'requireApproval',
          'requireJustification',
          'requireMfa',
        ],
      }),
    ]);
    await f.iam.api.config.apply(owner, { tenantId, config: { version: 1, accessPolicy: {} } });
    expect((await f.iam.api.tenants.get(owner, { tenantId })).accessPolicy).toBeUndefined();
    expect(
      (await f.iam.api.config.plan(owner, { tenantId, config: { version: 1, accessPolicy: {} } }))
        .summary.unchanged,
    ).toBe(1);
    // Clearing through the API works too, and the binding is back to its own rules.
    await f.iam.api.tenants.setAccessPolicy(owner, {
      tenantId,
      accessPolicy: { requireMfa: true },
    });
    await f.iam.api.tenants.setAccessPolicy(owner, { tenantId, accessPolicy: null });
    await f.iam.api.bindings.revokeActivation(owner, { tenantId, activationId: request.id });
    const again = await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: eligible.id });
    expect(again.status).toBe('active');
  });
});
