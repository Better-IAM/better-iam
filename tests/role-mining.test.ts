import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

async function scenario() {
  const f = await organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write'],
      identityAttributes: { department: 'string' },
    },
  });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const person = async (name: string, department: string) => {
    const created = await f.member(name);
    await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: created.id,
      attributes: { department },
    });
    return created;
  };
  const [ana, ben, cai, dee, eve] = [
    await person('ana', 'eng'),
    await person('ben', 'eng'),
    await person('cai', 'eng'),
    await person('dee', 'eng'),
    await person('eve', 'sales'),
  ];
  const role = (name: string, permissions: string[]) =>
    f.iam.api.roles.create(owner, { tenantId, name, permissions });
  const reader = await role('Reader', ['documents:read']);
  const writer = await role('Writer', ['documents:write']);
  const auditor = await role('Auditor', ['documents:read']);
  const deployer = await role('Deployer', ['documents:read', 'documents:write']);
  const bind = (roleId: string, subjectType: 'identity' | 'group', subjectId: string) =>
    f.iam.api.bindings.create(owner, { tenantId, roleId, subjectType, subjectId });
  for (const who of [ana, ben, cai]) {
    await bind(reader.id, 'identity', who.id);
    await bind(writer.id, 'identity', who.id);
  }
  const eng = await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
  await f.iam.api.groups.addMembers(owner, {
    tenantId,
    groupId: eng.id,
    identityIds: [ana.id, ben.id, cai.id],
  });
  const ops = await f.iam.api.groups.create(owner, { tenantId, name: 'Operations' });
  await f.iam.api.groups.addMembers(owner, {
    tenantId,
    groupId: ops.id,
    identityIds: [dee.id, eve.id],
  });
  await bind(deployer.id, 'group', ops.id);
  const direct = await bind(deployer.id, 'identity', dee.id);
  return {
    f,
    tenantId,
    owner,
    ana,
    ben,
    cai,
    dee,
    eve,
    reader,
    writer,
    auditor,
    deployer,
    eng,
    ops,
    direct,
  };
}

describe('role mining', () => {
  it('suggests bundles, group bindings, redundant bindings, and duplicate roles', async () => {
    const s = await scenario();
    const result = await s.f.iam.api.roleMining.suggest(s.owner, { tenantId: s.tenantId });
    expect(result.summary).toEqual({
      bundle: 1,
      'group-binding': 2,
      'redundant-binding': 1,
      'duplicate-roles': 1,
    });
    const [first] = result.suggestions;
    expect(first).toMatchObject({
      kind: 'redundant-binding',
      group: { id: s.ops.id, name: 'Operations' },
      bindingIds: [s.direct.id],
      identities: [{ id: s.dee.id, name: 'dee@acme.test' }],
      applicable: true,
    });
    const bundle = result.suggestions.find((entry) => entry.kind === 'bundle')!;
    expect(bundle.roles.map((ref) => ref.name).sort()).toEqual(['Reader', 'Writer']);
    expect(bundle.identities.map((ref) => ref.id).sort()).toEqual(
      [s.ana.id, s.ben.id, s.cai.id].sort(),
    );
    expect(bundle.savings).toBe(3);
    const duplicate = result.suggestions.find((entry) => entry.kind === 'duplicate-roles')!;
    expect(duplicate.roles.map((ref) => ref.name).sort()).toEqual(['Auditor', 'Reader']);
    const groupBindings = result.suggestions.filter((entry) => entry.kind === 'group-binding');
    expect(groupBindings.map((entry) => entry.roles[0]!.name).sort()).toEqual(['Reader', 'Writer']);
    expect(
      groupBindings.every((entry) => entry.group?.id === s.eng.id && entry.savings === 2),
    ).toBe(true);
    // Stable IDs across runs; kinds and thresholds filter.
    const again = await s.f.iam.api.roleMining.suggest(s.owner, { tenantId: s.tenantId });
    expect(again.suggestions.map((entry) => entry.id)).toEqual(
      result.suggestions.map((entry) => entry.id),
    );
    const bundles = await s.f.iam.api.roleMining.suggest(s.owner, {
      tenantId: s.tenantId,
      kinds: ['bundle'],
    });
    expect(bundles.suggestions.map((entry) => entry.kind)).toEqual(['bundle']);
    const strict = await s.f.iam.api.roleMining.suggest(s.owner, {
      tenantId: s.tenantId,
      minIdentities: 4,
    });
    expect(strict.summary.bundle).toBe(0);
    expect(strict.summary['group-binding']).toBe(0);
    await expect(
      s.f.iam.api.roleMining.suggest(s.owner, { tenantId: s.tenantId, minIdentities: 1 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('applies group-binding and redundant-binding suggestions without changing access', async () => {
    const s = await scenario();
    const { suggestions } = await s.f.iam.api.roleMining.suggest(s.owner, { tenantId: s.tenantId });
    const readerToGroup = suggestions.find(
      (entry) => entry.kind === 'group-binding' && entry.roles[0]!.id === s.reader.id,
    )!;
    const applied = await s.f.iam.api.roleMining.apply(s.owner, {
      tenantId: s.tenantId,
      suggestionId: readerToGroup.id,
    });
    expect(applied.applied).toBe('group-binding');
    expect(applied.removedBindingIds).toHaveLength(3);
    const bindings = await s.f.iam.api.bindings.list(s.owner, { tenantId: s.tenantId });
    const readerBindings = bindings.filter((binding) => binding.roleId === s.reader.id);
    expect(readerBindings).toEqual([
      expect.objectContaining({
        subjectType: 'group',
        subjectId: s.eng.id,
        id: applied.createdBindingId,
      }),
    ]);
    // Same suggestion again: it no longer holds.
    await expect(
      s.f.iam.api.roleMining.apply(s.owner, {
        tenantId: s.tenantId,
        suggestionId: readerToGroup.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    const redundant = suggestions.find((entry) => entry.kind === 'redundant-binding')!;
    await s.f.iam.api.roleMining.apply(s.owner, {
      tenantId: s.tenantId,
      suggestionId: redundant.id,
    });
    const after = await s.f.iam.api.bindings.list(s.owner, { tenantId: s.tenantId });
    expect(after.some((binding) => binding.id === s.direct.id)).toBe(false);
    expect(
      after.some((binding) => binding.roleId === s.deployer.id && binding.subjectId === s.ops.id),
    ).toBe(true);

    const bundle = suggestions.find((entry) => entry.kind === 'bundle')!;
    await expect(
      s.f.iam.api.roleMining.apply(s.owner, { tenantId: s.tenantId, suggestionId: bundle.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const remaining = await s.f.iam.api.roleMining.suggest(s.owner, { tenantId: s.tenantId });
    expect(remaining.summary).toMatchObject({
      'group-binding': 1,
      'redundant-binding': 0,
      bundle: 1,
    });
  });

  it('finds peer outliers by attribute and by manager', async () => {
    const s = await scenario();
    const byDepartment = await s.f.iam.api.roleMining.outliers(s.owner, {
      tenantId: s.tenantId,
      peerBy: 'attribute:department',
    });
    // Sales has one person, so only the four engineers are compared.
    expect(byDepartment.identitiesCompared).toBe(4);
    expect(byDepartment.outliers).toHaveLength(1);
    const [dee] = byDepartment.outliers;
    expect(dee).toMatchObject({
      identity: { id: s.dee.id },
      peerValue: 'eng',
      peers: 3,
      unusualRoles: [{ role: { name: 'Deployer' }, peersHolding: 0, share: 0 }],
    });
    expect(dee!.missingRoles.map((entry) => entry.role.name).sort()).toEqual(['Reader', 'Writer']);

    // Manager cohorts: everyone reporting to Eve.
    for (const who of [s.ana, s.ben, s.cai, s.dee])
      await s.f.iam.api.identities.update(s.owner, {
        tenantId: s.tenantId,
        identityId: who.id,
        managerId: s.eve.id,
      });
    const byManager = await s.f.iam.api.roleMining.outliers(s.owner, { tenantId: s.tenantId });
    expect(byManager.peerBy).toBe('manager');
    expect(byManager.outliers.map((entry) => entry.identity.id)).toEqual([s.dee.id]);
    expect(byManager.outliers[0]!.peerValue).toBe(s.eve.id);

    await expect(
      s.f.iam.api.roleMining.outliers(s.owner, { tenantId: s.tenantId, peerBy: 'attribute:shoe' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      s.f.iam.api.roleMining.outliers(s.owner, { tenantId: s.tenantId, threshold: 2 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('does not rely on package-owned memberships or groups with inactive members', async () => {
    const s = await scenario();
    // Operations' Deployer binding reaches Dee only through a package-owned membership from now on.
    await s.f.iam.api.groups.removeMember(s.owner, {
      tenantId: s.tenantId,
      groupId: s.ops.id,
      identityId: s.dee.id,
    });
    const pkg = await s.f.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Ops kit',
      groupIds: [s.ops.id],
    });
    await s.f.iam.api.packages.assign(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      identityId: s.dee.id,
    });
    // A disabled engineer makes "every member holds it directly" unsafe for Engineering.
    await s.f.iam.api.identities.setStatus(s.owner, {
      tenantId: s.tenantId,
      identityId: s.cai.id,
      status: 'disabled',
    });
    const result = await s.f.iam.api.roleMining.suggest(s.owner, {
      tenantId: s.tenantId,
      minIdentities: 2,
    });
    expect(result.summary['redundant-binding']).toBe(0);
    expect(result.summary['group-binding']).toBe(0);
  });

  it('requires analysis permissions', async () => {
    const s = await scenario();
    const session = await s.f.iam.api.auth.signIn({
      tenantId: s.tenantId,
      email: 'eve@acme.test',
      password: 'a strong eve password',
    });
    if (!('token' in session)) throw new Error('Unexpected MFA');
    const eve = { token: session.token };
    await expect(
      s.f.iam.api.roleMining.suggest(eve, { tenantId: s.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      s.f.iam.api.roleMining.outliers(eve, { tenantId: s.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      s.f.iam.api.roleMining.apply(eve, { tenantId: s.tenantId, suggestionId: 'a'.repeat(24) }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});
