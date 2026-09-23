import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const doc = { type: 'document', id: 'd1' };

async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const [alice, bob, carol, dave] = [
    await f.member('alice'),
    await f.member('bob'),
    await f.member('carol'),
    await f.member('dave'),
  ];
  const reader = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Reader',
    permissions: ['documents:read'],
  });
  const senior = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Senior',
    inherits: [reader.id],
  });
  const writing = await f.iam.api.policies.create(owner, {
    tenantId,
    name: 'Writing',
    document: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['documents:write'], resources: ['*'] }],
    },
  });
  const writer = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Writer',
    policyIds: [writing.id],
  });
  const team = await f.iam.api.groups.create(owner, { tenantId, name: 'Team' });
  await f.iam.api.groups.addMembers(owner, { tenantId, groupId: team.id, identityIds: [bob.id] });
  const bind = (roleId: string, subjectType: 'identity' | 'group', subjectId: string) =>
    f.iam.api.bindings.create(owner, { tenantId, roleId, subjectType, subjectId });
  await bind(reader.id, 'identity', alice.id);
  await bind(reader.id, 'group', team.id);
  await bind(senior.id, 'identity', carol.id);
  await bind(writer.id, 'identity', dave.id);
  return { f, tenantId, owner, alice, bob, carol, dave, reader, senior, writer, writing };
}

describe('change impact preview', () => {
  it('shows who gains access from a role change, through groups and inheritance, without saving it', async () => {
    const s = await scenario();
    const preview = await s.f.iam.api.impact.preview(s.owner, {
      tenantId: s.tenantId,
      change: { role: { roleId: s.reader.id, permissions: ['documents:read', 'documents:write'] } },
      resources: [doc],
    });
    expect(preview.roles.map((role) => role.name)).toEqual(['Reader', 'Senior']);
    expect(preview.evaluated).toBe(3);
    expect(preview.truncated).toBe(false);
    expect(preview.gainedTotal).toBe(3);
    expect(preview.lostTotal).toBe(0);
    expect(preview.identities.map((entry) => entry.identity.id).sort()).toEqual(
      [s.alice.id, s.bob.id, s.carol.id].sort(),
    );
    expect(preview.identities[0]!.changes).toEqual([
      { resource: 'document/d1', gained: ['documents:write'], lost: [] },
    ]);
    // Nothing was saved.
    const role = await s.f.iam.api.roles.get(s.owner, {
      tenantId: s.tenantId,
      roleId: s.reader.id,
    });
    expect(JSON.stringify(role)).not.toContain('documents:write');
    const check = await s.f.iam.authorize({
      token: (await s.f.signIn('alice')).token,
      tenantId: s.tenantId,
      action: 'documents:write',
      resource: doc,
    });
    expect(check.allowed).toBe(false);
  });

  it('previews policy edits and role deletion with the real validation', async () => {
    const s = await scenario();
    const policy = await s.f.iam.api.impact.preview(s.owner, {
      tenantId: s.tenantId,
      change: {
        policy: {
          policyId: s.writing.id,
          document: {
            version: 1,
            statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
          },
        },
      },
      resources: [doc],
    });
    expect(policy.identities).toEqual([
      {
        identity: { id: s.dave.id, name: 'dave@acme.test' },
        changes: [
          { resource: 'document/d1', gained: ['documents:read'], lost: ['documents:write'] },
        ],
      },
    ]);
    const current = await s.f.iam.api.policies.get(s.owner, {
      tenantId: s.tenantId,
      policyId: s.writing.id,
    });
    expect(current.version).toBe(1);

    const removal = await s.f.iam.api.impact.preview(s.owner, {
      tenantId: s.tenantId,
      change: { deleteRole: s.writer.id },
      resources: [doc],
      actions: ['documents:write'],
    });
    expect(removal.lostTotal).toBe(1);
    expect(removal.identities[0]!.changes[0]!.lost).toEqual(['documents:write']);
    // Deleting a role others inherit is refused exactly as roles.delete would refuse it.
    await expect(
      s.f.iam.api.impact.preview(s.owner, {
        tenantId: s.tenantId,
        change: { deleteRole: s.reader.id },
        resources: [doc],
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    const bindings = await s.f.iam.api.bindings.list(s.owner, { tenantId: s.tenantId });
    expect(bindings.some((binding) => binding.roleId === s.writer.id)).toBe(true);
  });

  it('validates input and requires simulate permission', async () => {
    const s = await scenario();
    await expect(
      s.f.iam.api.impact.preview(s.owner, {
        tenantId: s.tenantId,
        change: { deleteRole: s.writer.id, role: { roleId: s.reader.id } },
        resources: [doc],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.f.iam.api.impact.preview(s.owner, {
        tenantId: s.tenantId,
        change: { deleteRole: s.writer.id },
        resources: [],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.f.iam.api.impact.preview(s.owner, {
        tenantId: s.tenantId,
        change: { deleteRole: s.writer.id },
        resources: [doc],
        actions: ['documents:fly'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    const alice = { token: (await s.f.signIn('alice')).token };
    await expect(
      s.f.iam.api.impact.preview(alice, {
        tenantId: s.tenantId,
        change: { deleteRole: s.writer.id },
        resources: [doc],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Simulating is not enough: the preview also needs the permission the real change needs.
    const simulator = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Simulator',
      permissions: ['iam:policies:simulate'],
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: simulator.id,
      subjectType: 'identity',
      subjectId: s.bob.id,
    });
    const bob = { token: (await s.f.signIn('bob')).token };
    for (const change of [
      { deleteRole: s.writer.id },
      { role: { roleId: s.reader.id, permissions: ['documents:write'] } },
    ])
      await expect(
        s.f.iam.api.impact.preview(bob, { tenantId: s.tenantId, change, resources: [doc] }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});
