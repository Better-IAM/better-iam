import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

describe('role inheritance', () => {
  it('includes inherited grants, validates the hierarchy, and protects inherited roles from deletion', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const viewer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewer',
      permissions: ['documents:read'],
    });
    const editor = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Editor',
      permissions: ['documents:write'],
      inherits: [viewer.id],
    });
    expect(editor.inherits).toEqual([viewer.id]);
    // Cycles, self-inheritance, protected roles, and unknown roles are refused.
    await expect(
      f.iam.api.roles.update(owner, { tenantId, roleId: viewer.id, inherits: [editor.id] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.roles.update(owner, { tenantId, roleId: viewer.id, inherits: [viewer.id] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const ownerRole = (await f.iam.api.roles.list(owner, { tenantId })).find(
      (role) => role.protected,
    )!;
    await expect(
      f.iam.api.roles.update(owner, { tenantId, roleId: editor.id, inherits: [ownerRole.id] }),
    ).rejects.toMatchObject({ code: 'PROTECTED_RESOURCE' });
    await expect(
      f.iam.api.roles.create(owner, { tenantId, name: 'Broken', inherits: ['missing'] }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Editors read through Viewer; viewers cannot write.
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: editor.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: viewer.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const can = async (credential: { token: string }, action: string) =>
      (
        await f.iam.authorize({
          ...credential,
          tenantId,
          action,
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed;
    expect([await can(asAlice, 'documents:read'), await can(asAlice, 'documents:write')]).toEqual([
      true,
      true,
    ]);
    expect([await can(asBob, 'documents:read'), await can(asBob, 'documents:write')]).toEqual([
      true,
      false,
    ]);
    const review = await f.iam.api.policies.effectiveActions(owner, {
      tenantId,
      identityId: alice.id,
      resource: { type: 'documents', id: 'a' },
      actions: ['documents:read', 'documents:write'],
    });
    expect(review.allowed).toEqual(['documents:read', 'documents:write']);
    // An inherited role cannot be deleted; clearing the inheritance removes the inherited grant.
    await expect(
      f.iam.api.roles.delete(owner, { tenantId, roleId: viewer.id }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    const cleared = await f.iam.api.roles.update(owner, {
      tenantId,
      roleId: editor.id,
      inherits: [],
    });
    expect(cleared.inherits).toBeUndefined();
    expect(await can(asAlice, 'documents:read')).toBe(false);
    await f.iam.api.roles.delete(owner, { tenantId, roleId: viewer.id });
  });

  it('bounds inherited grants by the inheriting role’s own authority ceiling', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const full = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Full',
      permissions: ['documents:read', 'documents:write'],
    });
    // Bob administers under a ceiling that only allows reads, plus the permissions to create roles and bindings.
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const admin = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Delegated admin',
      permissions: [
        'iam:roles:create',
        'iam:roles:read',
        'iam:roles:update',
        'iam:bindings:create',
      ],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: admin.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await f.iam.api.authorities.create(owner, {
      tenantId,
      identityId: bob.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    const asBob = { token: (await f.signIn('bob')).token };
    const narrow = await f.iam.api.roles.create(asBob, {
      tenantId,
      name: 'Narrow',
      inherits: [full.id],
    });
    await f.iam.api.bindings.create(asBob, {
      tenantId,
      roleId: narrow.id,
      subjectType: 'identity',
      subjectId: carol.id,
    });
    const asCarol = { token: (await f.signIn('carol')).token };
    const can = async (action: string) =>
      (
        await f.iam.authorize({
          ...asCarol,
          tenantId,
          action,
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed;
    expect(await can('documents:read')).toBe(true);
    expect(await can('documents:write')).toBe(false);
    // Configuration sync carries inheritance by name, parent and child in one document.
    const exported = await f.iam.api.config.export(owner, { tenantId });
    expect(exported.roles?.find((role) => role.name === 'Narrow')).toEqual({
      name: 'Narrow',
      policies: [],
      inherits: ['Full'],
    });
    // A role created under Bob's authority is not the owner's to edit, even through configuration sync.
    await expect(
      f.iam.api.config.apply(owner, {
        tenantId,
        config: { version: 1, roles: [{ name: 'Narrow', inherits: [] }] },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const applied = await f.iam.api.config.apply(owner, {
      tenantId,
      config: {
        version: 1,
        roles: [
          { name: 'Base', permissions: ['documents:read'] },
          { name: 'Lead', permissions: ['documents:write'], inherits: ['Base'] },
        ],
      },
    });
    expect(applied.summary).toEqual({ create: 2, update: 0, delete: 0, unchanged: 0 });
    const roles = await f.iam.api.roles.list(owner, { tenantId });
    const base = roles.find((role) => role.name === 'Base')!;
    expect(roles.find((role) => role.name === 'Lead')!.inherits).toEqual([base.id]);
    expect(roles.find((role) => role.name === 'Narrow')!.inherits).toEqual([full.id]);
    const cleared = await f.iam.api.roles.update(asBob, {
      tenantId,
      roleId: narrow.id,
      inherits: [],
    });
    expect(cleared.inherits).toBeUndefined();
    await expect(
      f.iam.api.config.plan(owner, {
        tenantId,
        config: { version: 1, roles: [{ name: 'Loop', inherits: ['Loop'] }] },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
