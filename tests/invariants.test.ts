import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const d1 = { type: 'document', id: 'd1' };

async function scenario() {
  const f = await organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write'],
      identityAttributes: { contractor: 'boolean' },
    },
  });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const [alice, bob, carol] = [
    await f.member('alice'),
    await f.member('bob'),
    await f.member('carol'),
  ];
  await f.iam.api.identities.update(owner, {
    tenantId,
    identityId: alice.id,
    attributes: { contractor: true },
  });
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
  const oncall = await f.iam.api.groups.create(owner, { tenantId, name: 'On-call' });
  await f.iam.api.groups.addMember(owner, { tenantId, groupId: oncall.id, identityId: bob.id });
  const oncallWriter = await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: writer.id,
    subjectType: 'group',
    subjectId: oncall.id,
  });
  return { f, tenantId, owner, alice, bob, carol, reader, writer, oncall, oncallWriter };
}

describe('access invariants', () => {
  it('refuses changes that newly break an enforced invariant', async () => {
    const s = await scenario();
    const { invariant, result } = await s.f.iam.api.invariants.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Contractors never write d1',
      subject: { attribute: { name: 'contractor', value: true } },
      action: 'documents:write',
      resource: d1,
      expect: 'deny',
      mode: 'enforce',
    });
    expect(invariant.assumeMfa).toBe(true);
    expect(result).toMatchObject({ passed: true, evaluated: 1, violations: [] });

    // A direct binding, a group membership, and a role edit would each let Alice write.
    await expect(
      s.f.iam.api.bindings.create(s.owner, {
        tenantId: s.tenantId,
        roleId: s.writer.id,
        subjectType: 'identity',
        subjectId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
    await expect(
      s.f.iam.api.groups.addMember(s.owner, {
        tenantId: s.tenantId,
        groupId: s.oncall.id,
        identityId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'identity',
      subjectId: s.alice.id,
    });
    await expect(
      s.f.iam.api.roles.update(s.owner, {
        tenantId: s.tenantId,
        roleId: s.reader.id,
        permissions: ['documents:read', 'documents:write'],
      }),
    ).rejects.toMatchObject({
      code: 'INVARIANT_VIOLATION',
      message: expect.stringContaining('Contractors never write d1'),
    });
    // Nothing was written: the transaction rolled back.
    const bindings = await s.f.iam.api.bindings.list(s.owner, { tenantId: s.tenantId });
    expect(bindings.filter((binding) => binding.subjectId === s.alice.id)).toHaveLength(1);
    const members = await s.f.iam.api.groups.listMembers(s.owner, {
      tenantId: s.tenantId,
      groupId: s.oncall.id,
    });
    expect(JSON.stringify(members)).not.toContain(s.alice.id);
    // Unrelated changes still go through, and the same change is fine for a non-contractor.
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.writer.id,
      subjectType: 'identity',
      subjectId: s.carol.id,
    });
    // Changing Alice's attribute so she is no longer a contractor lifts the guard for her.
    await s.f.iam.api.identities.update(s.owner, {
      tenantId: s.tenantId,
      identityId: s.alice.id,
      attributes: { contractor: false },
    });
    await s.f.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: s.oncall.id,
      identityId: s.alice.id,
    });
    // ...but making her a contractor again now breaks the invariant, so that update is refused.
    await expect(
      s.f.iam.api.identities.update(s.owner, {
        tenantId: s.tenantId,
        identityId: s.alice.id,
        attributes: { contractor: true },
      }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
  });

  it('protects must-allow invariants and tolerates violations that predate enforcement', async () => {
    const s = await scenario();
    await s.f.iam.api.invariants.create(s.owner, {
      tenantId: s.tenantId,
      name: 'On-call can always write d1',
      subject: { groupId: s.oncall.id },
      action: 'documents:write',
      resource: d1,
      expect: 'allow',
      mode: 'enforce',
    });
    await expect(
      s.f.iam.api.bindings.delete(s.owner, {
        tenantId: s.tenantId,
        bindingId: s.oncallWriter.id,
      }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });

    // Carol is not allowed to read yet; an enforced must-allow invariant about her starts out broken.
    const broken = await s.f.iam.api.invariants.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Carol reads d1',
      subject: { identityId: s.carol.id },
      action: 'documents:read',
      resource: d1,
      expect: 'allow',
    });
    expect(broken.result.passed).toBe(false);
    expect(broken.result.violations[0]).toMatchObject({ identity: { id: s.carol.id } });
    const enforced = await s.f.iam.api.invariants.update(s.owner, {
      tenantId: s.tenantId,
      invariantId: broken.invariant.id,
      mode: 'enforce',
    });
    expect(enforced.invariant.mode).toBe('enforce');
    // The pre-existing violation does not block unrelated work.
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'identity',
      subjectId: s.bob.id,
    });

    const run = await s.f.iam.api.invariants.run(s.owner, { tenantId: s.tenantId });
    expect(run.summary).toEqual({ passed: 1, failed: 1, errors: 0 });
    expect(run.results.map((result) => [result.invariant.name, result.passed])).toEqual([
      ['Carol reads d1', false],
      ['On-call can always write d1', true],
    ]);
    // Granting Carol read fixes it.
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'identity',
      subjectId: s.carol.id,
    });
    const single = await s.f.iam.api.invariants.run(s.owner, {
      tenantId: s.tenantId,
      invariantId: broken.invariant.id,
    });
    expect(single.summary).toEqual({ passed: 1, failed: 0, errors: 0 });

    // Deleting the group an enforced invariant is about would switch it off silently, so it is refused.
    await expect(
      s.f.iam.api.groups.delete(s.owner, { tenantId: s.tenantId, groupId: s.oncall.id }),
    ).rejects.toMatchObject({
      code: 'INVARIANT_VIOLATION',
      message: expect.stringContaining('could no longer be evaluated'),
    });

    // Deleting the invariant lifts enforcement.
    const list = await s.f.iam.api.invariants.list(s.owner, { tenantId: s.tenantId });
    const guard = list.find((invariant) => invariant.name === 'On-call can always write d1')!;
    await s.f.iam.api.invariants.delete(s.owner, { tenantId: s.tenantId, invariantId: guard.id });
    await s.f.iam.api.bindings.delete(s.owner, {
      tenantId: s.tenantId,
      bindingId: s.oncallWriter.id,
    });
  });

  it('shows broken invariants in impact previews', async () => {
    const s = await scenario();
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
      subjectType: 'identity',
      subjectId: s.alice.id,
    });
    const created = await s.f.iam.api.invariants.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Alice never writes',
      subject: { identityId: s.alice.id },
      action: 'documents:write',
      resource: d1,
      expect: 'deny',
    });
    const preview = await s.f.iam.api.impact.preview(s.owner, {
      tenantId: s.tenantId,
      change: { role: { roleId: s.reader.id, permissions: ['documents:read', 'documents:write'] } },
      resources: [d1],
    });
    expect(preview.invariants.broken).toEqual([
      {
        id: created.invariant.id,
        name: 'Alice never writes',
        mode: 'monitor',
        violations: [
          { identity: { id: s.alice.id, name: 'alice@acme.test' }, reason: expect.any(String) },
        ],
      },
    ]);
    expect(preview.invariants.fixed).toEqual([]);
  });

  it('monitors invariants on a schedule and audits breaks and restorations once', async () => {
    const s = await scenario();
    const { invariant } = await s.f.iam.api.invariants.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Carol never writes',
      subject: { identityId: s.carol.id },
      action: 'documents:write',
      resource: d1,
      expect: 'deny',
    });
    expect(await s.f.iam.checkInvariants()).toEqual({ checked: 1, broken: [], restored: [] });
    // Monitor mode lets the change through; the next check reports it once.
    const binding = await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: s.writer.id,
      subjectType: 'identity',
      subjectId: s.carol.id,
    });
    expect(await s.f.iam.checkInvariants({ tenantId: s.tenantId })).toEqual({
      checked: 1,
      broken: [
        {
          tenantId: s.tenantId,
          invariantId: invariant.id,
          name: 'Carol never writes',
          violations: [s.carol.id],
        },
      ],
      restored: [],
    });
    expect((await s.f.iam.checkInvariants()).broken).toEqual([]);
    const [stored] = await s.f.iam.api.invariants.list(s.owner, { tenantId: s.tenantId });
    expect(stored!.lastCheck).toMatchObject({ passed: false, violations: [s.carol.id] });
    await s.f.iam.api.bindings.delete(s.owner, { tenantId: s.tenantId, bindingId: binding.id });
    expect((await s.f.iam.checkInvariants()).restored).toEqual([
      { tenantId: s.tenantId, invariantId: invariant.id, name: 'Carol never writes' },
    ]);
    const events = JSON.stringify(
      await s.f.iam.api.audit.list(await s.f.ownerSignIn(), { tenantId: s.tenantId }),
    );
    expect(events).toContain('invariant:broken');
    expect(events).toContain('invariant:restored');
  });

  it('validates invariants and requires permissions', async () => {
    const s = await scenario();
    const base = {
      tenantId: s.tenantId,
      name: 'x',
      subject: { everyone: true as const },
      action: 'documents:read',
      resource: d1,
      expect: 'deny' as const,
    };
    await s.f.iam.api.invariants.create(s.owner, base);
    await expect(
      s.f.iam.api.invariants.create(s.owner, { ...base, name: 'X' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      s.f.iam.api.invariants.create(s.owner, { ...base, name: 'y', action: 'documents:fly' }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    await expect(
      s.f.iam.api.invariants.create(s.owner, {
        ...base,
        name: 'z',
        subject: { everyone: true, identityId: s.alice.id } as never,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.f.iam.api.invariants.create(s.owner, {
        ...base,
        name: 'w',
        subject: { attribute: { name: 'contractor', value: 'yes' } },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const alice = { token: (await s.f.signIn('alice')).token };
    await expect(
      s.f.iam.api.invariants.list(alice, { tenantId: s.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      s.f.iam.api.invariants.create(alice, { ...base, name: 'mine' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});
