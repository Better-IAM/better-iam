import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('eligible role bindings (just-in-time access)', () => {
  it('grants nothing until activated, enforces the activation rules, and expires', async () => {
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
      permissions: ['iam:bindings:activate'],
    });
    for (const identity of [alice, bob])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: member.id,
        subjectType: 'identity',
        subjectId: identity.id,
      });
    // Activation settings belong to eligible bindings only.
    await expect(
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: auditor.id,
        subjectType: 'identity',
        subjectId: alice.id,
        maxActivationMs: 60_000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: auditor.id,
        subjectType: 'identity',
        subjectId: alice.id,
        eligible: 'yes' as never,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: auditor.id,
        subjectType: 'identity',
        subjectId: alice.id,
        eligible: true,
        maxActivationMs: 8 * 86400_000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: auditor.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      maxActivationMs: 600_000,
      requireJustification: true,
    });
    expect(eligible).toMatchObject({ eligible: true, maxActivationMs: 600_000 });
    expect(
      (await f.iam.api.bindings.list(owner, { tenantId, eligible: true })).map((b) => b.id),
    ).toEqual([eligible.id]);
    expect(
      (await f.iam.api.bindings.list(owner, { tenantId, roleId: member.id, eligible: false })).map(
        (b) => b.roleId,
      ),
    ).toEqual([member.id, member.id]);
    expect(
      await f.iam.api.bindings.list(owner, { tenantId, roleId: auditor.id, eligible: false }),
    ).toEqual([]);
    const aliceLogin = await f.signIn('alice');
    const bobLogin = await f.signIn('bob');
    const asAlice = { token: aliceLogin.token };
    const asBob = { token: bobLogin.token };
    const audit = (credential: { token: string }) =>
      f.iam.api.audit.list(credential, { tenantId, limit: 5 });
    await expect(audit(asAlice)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // She can see what she may elevate to without holding iam:bindings:read.
    const mine = await f.iam.api.bindings.listMine(asAlice, { tenantId });
    expect(mine.map((binding) => [binding.roleId, binding.eligible === true])).toEqual(
      expect.arrayContaining([
        [member.id, false],
        [auditor.id, true],
      ]),
    );
    expect(mine.find((binding) => binding.id === eligible.id)!.activation).toBeUndefined();
    const activate = (credential: { token: string }, input: Record<string, unknown> = {}) =>
      f.iam.api.bindings.activate(credential, { tenantId, bindingId: eligible.id, ...input });
    await expect(activate(asAlice)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      activate(asAlice, { justification: 'quarterly review', durationMs: 600_001 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(activate(asBob, { justification: 'not mine' })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      f.iam.api.bindings.activate(asAlice, {
        tenantId,
        bindingId: (
          await f.iam.api.bindings.list(owner, { tenantId, subjectId: alice.id, eligible: false })
        )[0]!.id,
        justification: 'standing role',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const activation = await activate(asAlice, { justification: 'quarterly review' });
    expect(activation).toMatchObject({
      bindingId: eligible.id,
      identityId: alice.id,
      roleId: auditor.id,
      active: true,
      justification: 'quarterly review',
      expiresAt: f.now() + 600_000,
    });
    expect((await audit(asAlice)).length).toBeGreaterThan(0);
    await expect(activate(asAlice, { justification: 'again' })).rejects.toMatchObject({
      code: 'CONFLICT',
    });
    // Administrators see the activation on her effective roles and in the trail.
    const effective = await f.iam.api.identities.listBindings(owner, {
      tenantId,
      identityId: alice.id,
    });
    expect(effective.find((binding) => binding.id === eligible.id)!.activation).toMatchObject({
      id: activation.id,
      expiresAt: activation.expiresAt,
    });
    const started = (
      await f.iam.api.audit.list(owner, { tenantId, action: 'binding:activate' })
    )[0]!;
    expect(started).toMatchObject({
      actorId: alice.id,
      resourceId: eligible.id,
      metadata: {
        activationId: activation.id,
        roleId: auditor.id,
        justification: 'quarterly review',
      },
    });
    expect(
      await f.iam.api.bindings.listActivations(owner, { tenantId, roleId: auditor.id }),
    ).toHaveLength(1);
    // Reviews and policy context see the activated role only while it is live.
    expect(
      (
        await f.iam.api.policies.whoCan(owner, {
          tenantId,
          action: 'iam:audit:read',
          resource: { type: 'iam', id: tenantId },
        })
      ).identities.map((match) => match.identityId),
    ).toContain(alice.id);
    f.advance(600_001);
    await expect(audit(asAlice)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await f.iam.api.bindings.listActivations(owner, { tenantId })).toEqual([]);
    expect(
      (await f.iam.api.bindings.listActivations(owner, { tenantId, includeExpired: true })).map(
        (item) => item.active,
      ),
    ).toEqual([false]);
    expect(
      (
        await f.iam.api.policies.whoCan(owner, {
          tenantId,
          action: 'iam:audit:read',
          resource: { type: 'iam', id: tenantId },
        })
      ).identities.map((match) => match.identityId),
    ).not.toContain(alice.id);
    // Re-activation replaces the ended record; the holder may end it early, nobody else.
    const second = await activate(asAlice, { justification: 'follow-up', durationMs: 60_000 });
    expect(second.expiresAt).toBe(f.now() + 60_000);
    await expect(
      f.iam.api.bindings.deactivate(asBob, { tenantId, activationId: second.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await f.iam.api.bindings.deactivate(asAlice, { tenantId, activationId: second.id }),
    ).toEqual({ deactivated: true });
    await expect(audit(asAlice)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await f.iam.purgeDeleted()).expiredActivations).toBe(0);
    // Requiring MFA refuses password-only sessions.
    const admin = await f.ownerSignIn();
    await f.iam.api.bindings.update(admin, { tenantId, bindingId: eligible.id, requireMfa: true });
    await expect(activate(asAlice, { justification: 'mfa' })).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
    });
    await f.iam.api.bindings.update(admin, {
      tenantId,
      bindingId: eligible.id,
      requireMfa: false,
      requireJustification: false,
    });
    const third = await activate(asAlice);
    expect(third.justification).toBeUndefined();
    // Administrators can end someone's activation, and turning eligibility off ends them all.
    expect(
      await f.iam.api.bindings.revokeActivation(admin, { tenantId, activationId: third.id }),
    ).toEqual({ deactivated: true });
    expect(
      (await f.iam.api.audit.list(admin, { tenantId, action: 'binding:deactivate' }))[0],
    ).toMatchObject({ actorId: f.ownerId, metadata: { identityId: alice.id, revoked: true } });
    await activate(asAlice);
    const standing = await f.iam.api.bindings.update(admin, {
      tenantId,
      bindingId: eligible.id,
      eligible: false,
    });
    expect(standing.eligible).toBeUndefined();
    expect(standing.maxActivationMs).toBeUndefined();
    expect(await f.iam.api.bindings.listActivations(admin, { tenantId })).toEqual([]);
    // Now a standing binding: the role applies without activation.
    expect((await audit(asAlice)).length).toBeGreaterThan(0);
    await expect(activate(asAlice)).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // Expired activations are swept by the worker.
    await f.iam.api.bindings.update(admin, { tenantId, bindingId: eligible.id, eligible: true });
    await activate(asAlice, { durationMs: 60_000 });
    f.advance(60_001);
    expect((await f.iam.purgeDeleted()).expiredActivations).toBe(1);
  });

  it('applies to group members and ends with the membership', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const bob = await f.member('bob');
    const responders = await f.iam.api.groups.create(owner, { tenantId, name: 'Responders' });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: responders.id,
      identityId: bob.id,
    });
    const member = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:bindings:activate'],
    });
    const responder = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Incident responder',
      permissions: ['iam:identities:read'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: member.id,
      subjectType: 'group',
      subjectId: responders.id,
    });
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: responder.id,
      subjectType: 'group',
      subjectId: responders.id,
      eligible: true,
    });
    const asBob = { token: (await f.signIn('bob')).token };
    const members = () => f.iam.api.identities.list(asBob, { tenantId });
    await expect(members()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const mine = await f.iam.api.bindings.listMine(asBob, { tenantId });
    expect(mine.find((binding) => binding.id === eligible.id)).toMatchObject({
      via: { groupId: responders.id },
      eligible: true,
    });
    const activation = await f.iam.api.bindings.activate(asBob, {
      tenantId,
      bindingId: eligible.id,
    });
    // The default activation is one hour.
    expect(activation.expiresAt).toBe(f.now() + 3_600_000);
    expect((await members()).length).toBeGreaterThan(0);
    // Leaving the group ends the activation immediately.
    await f.iam.api.groups.removeMember(owner, {
      tenantId,
      groupId: responders.id,
      identityId: bob.id,
    });
    expect(
      await f.iam.api.bindings.listActivations(owner, { tenantId, identityId: bob.id }),
    ).toEqual([]);
    await expect(members()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Someone outside the group cannot activate the group's binding.
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: member.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await expect(
      f.iam.api.bindings.activate(asBob, { tenantId, bindingId: eligible.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Deleting the binding removes its activations; deleting a role removes both.
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: responders.id,
      identityId: bob.id,
    });
    const again = await f.iam.api.bindings.activate(asBob, { tenantId, bindingId: eligible.id });
    expect(again.active).toBe(true);
    await f.iam.api.roles.delete(owner, { tenantId, roleId: responder.id });
    expect(await f.database.find('bindingActivations', { tenantId })).toEqual([]);
  });
});
