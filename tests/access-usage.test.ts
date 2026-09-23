import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

async function scenario(accessUsage: boolean) {
  const f = await organizationFixture({ accessUsage });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const reader = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Reader',
    permissions: ['documents:read'],
  });
  const editor = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Editor',
    permissions: ['documents:read', 'documents:write'],
  });
  const [alice, bob, carol] = [
    await f.member('alice'),
    await f.member('bob'),
    await f.member('carol'),
  ];
  const readers = await f.iam.api.groups.create(owner, { tenantId, name: 'Readers' });
  await f.iam.api.groups.addMembers(owner, {
    tenantId,
    groupId: readers.id,
    identityIds: [bob.id],
  });
  await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: editor.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: reader.id,
    subjectType: 'group',
    subjectId: readers.id,
  });
  await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: reader.id,
    subjectType: 'identity',
    subjectId: carol.id,
  });
  const check = async (name: string, action: string) =>
    f.iam.authorize({
      token: (await f.signIn(name)).token,
      tenantId,
      action,
      resource: { type: 'document', id: 'd1' },
    });
  return { f, tenantId, owner, reader, editor, alice, bob, carol, readers, check };
}

describe('access usage', () => {
  it('records allowed checks and right-sizes bindings against them', async () => {
    const s = await scenario(true);
    expect((await s.check('alice', 'documents:read')).allowed).toBe(true);
    expect((await s.check('alice', 'documents:read')).allowed).toBe(true);
    expect((await s.check('bob', 'documents:read')).allowed).toBe(true);
    // Denied checks are not usage.
    expect((await s.check('carol', 'documents:write')).allowed).toBe(false);
    await s.f.iam.authorizeMany({
      token: (await s.f.signIn('bob')).token,
      tenantId: s.tenantId,
      checks: [{ action: 'documents:read', resource: { type: 'document', id: 'd2' } }],
    });

    const usage = await s.f.iam.api.roleMining.usage(s.owner, {
      tenantId: s.tenantId,
      identityId: s.alice.id,
    });
    expect(usage.tracking).toBe(true);
    expect(usage.records).toEqual([
      expect.objectContaining({ identityId: s.alice.id, action: 'documents:read', count: 2 }),
    ]);
    const bob = await s.f.iam.api.roleMining.usage(s.owner, {
      tenantId: s.tenantId,
      identityId: s.bob.id,
    });
    expect(bob.records[0]).toMatchObject({ action: 'documents:read', count: 2 });
    expect(
      (
        await s.f.iam.api.roleMining.usage(s.owner, {
          tenantId: s.tenantId,
          identityId: s.carol.id,
        })
      ).records,
    ).toEqual([]);
    // The owner's own provisioning operations count as usage too.
    const ownerUsage = await s.f.iam.api.roleMining.usage(s.owner, {
      tenantId: s.tenantId,
      identityId: s.f.ownerId,
    });
    expect(ownerUsage.records.map((record) => record.action)).toContain('iam:bindings:create');

    const report = await s.f.iam.api.roleMining.rightSize(s.owner, { tenantId: s.tenantId });
    expect(report).toMatchObject({ tracking: true, unusedDays: 90, complete: false });
    expect(report.trackingSince).toBeTypeOf('number');
    expect(
      report.entries.map((entry) => [entry.identity.id, entry.role.name, entry.status]),
    ).toEqual([
      [s.carol.id, 'Reader', 'unused'],
      [s.alice.id, 'Editor', 'partial'],
    ]);
    const alice = report.entries.find((entry) => entry.identity.id === s.alice.id)!;
    expect(alice).toMatchObject({
      via: { type: 'identity' },
      grantedActions: 2,
      usedActions: ['documents:read'],
      unusedActions: ['documents:write'],
      unusedCount: 1,
    });
    expect(alice.lastUsedAt).toBeTypeOf('number');
    const roles = Object.fromEntries(report.roles.map((role) => [role.role.name, role]));
    expect(roles.Editor).toMatchObject({ holders: 1, neverUsed: ['documents:write'] });
    expect(roles.Reader).toMatchObject({
      holders: 2,
      neverUsed: [],
      usedActions: ['documents:read'],
    });

    // Once the window is covered, old use no longer counts.
    s.f.advance(2 * 86_400_000);
    const later = await s.f.iam.api.roleMining.rightSize(await s.f.ownerSignIn(), {
      tenantId: s.tenantId,
      unusedDays: 1,
    });
    expect(later.complete).toBe(true);
    expect(later.entries.every((entry) => entry.status === 'unused')).toBe(true);
    expect(later.entries.find((entry) => entry.identity.id === s.bob.id)?.via).toEqual({
      type: 'group',
      id: s.readers.id,
      name: 'Readers',
    });
  });

  it('merges buffered usage into stored records across flushes', async () => {
    const s = await scenario(true);
    await s.check('alice', 'documents:read');
    expect((await s.f.iam.flushAccessUsage()).written).toBeGreaterThan(0);
    expect((await s.f.iam.flushAccessUsage()).written).toBe(0);
    s.f.advance(60_000);
    await s.check('alice', 'documents:read');
    await s.f.iam.flushAccessUsage();
    const [record] = (
      await s.f.iam.api.roleMining.usage(s.owner, { tenantId: s.tenantId, identityId: s.alice.id })
    ).records;
    expect(record!.count).toBe(2);
    expect(record!.lastUsedAt - record!.firstUsedAt).toBe(60_000);
  });

  it('writes on its own schedule and early, outside the transactions that recorded usage', async () => {
    const f = await organizationFixture({ accessUsage: { flushIntervalMs: 1000, maxBuffered: 2 } });
    const { tenantId } = f;
    const reader = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const alice = await f.member('alice');
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const token = (await f.signIn('alice')).token;
    // The first uses happen inside authorize's transaction; the buffer passes maxBuffered right away.
    for (const id of ['d1', 'd2', 'd3'])
      expect(
        (
          await f.iam.authorize({
            token,
            tenantId,
            action: 'documents:read',
            resource: { type: 'document', id },
          })
        ).allowed,
      ).toBe(true);
    await new Promise((resolve) => setTimeout(resolve, 1300));
    // Read storage directly: the usage API would flush on its own.
    const stored = await f.iam.store.transaction((tx) =>
      tx.find<{ identityId: string; action: string; count: number }>('accessUsage', { tenantId }),
    );
    expect(
      stored.find((record) => record.identityId === alice.id && record.action === 'documents:read')
        ?.count,
    ).toBe(3);
  });

  it('records nothing when tracking is off', async () => {
    const s = await scenario(false);
    await s.check('alice', 'documents:read');
    expect(await s.f.iam.flushAccessUsage()).toEqual({ written: 0 });
    const usage = await s.f.iam.api.roleMining.usage(s.owner, { tenantId: s.tenantId });
    expect(usage).toMatchObject({ tracking: false, total: 0, records: [] });
    const report = await s.f.iam.api.roleMining.rightSize(s.owner, { tenantId: s.tenantId });
    expect(report).toMatchObject({ tracking: false, complete: false });
    expect(report.trackingSince).toBeUndefined();
    await expect(
      s.f.iam.api.roleMining.rightSize(s.owner, { tenantId: s.tenantId, unusedDays: 0 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
