import { afterEach, describe, expect, it } from 'vitest';
import { lintPolicy, type BetterIamOptions } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const HOUR = 3_600_000;

/** Holds `ArrayContains principal.licenses: pro`: may read documents while holding an active Pro seat. */
const proReaders = {
  version: 1 as const,
  statements: [
    {
      effect: 'allow' as const,
      actions: ['documents:read'],
      resources: ['*'],
      conditions: { ArrayContains: { 'principal.licenses': 'pro' } },
    },
  ],
};

/** Acme with a product "pro" (one seat), alice and bob, and a role that reads documents on a Pro seat. */
async function scenario(overrides: Partial<BetterIamOptions> = {}) {
  const f = await organizationFixture(overrides);
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const licenses = f.iam.api.licenses;
  const pro = await licenses.createProduct(owner, {
    tenantId,
    key: 'pro',
    name: 'Pro',
    featureKeys: ['exports'],
  });
  const pool = (await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 1 })).pool;
  const alice = await f.member('alice');
  const bob = await f.member('bob');
  const assign = async (identityId: string) => {
    f.advance(1000);
    return licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'identity',
      subjectId: identityId,
    });
  };
  const unassign = (identityId: string) =>
    licenses.unassign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'identity',
      subjectId: identityId,
    });
  return { f, tenantId, owner, licenses, pro, pool, alice, bob, assign, unassign };
}

describe('principal.licenses in decisions', () => {
  it('lets policies test the products a person holds an active seat for, and no one else can claim them', async () => {
    const s = await scenario({
      // An application claiming the key must not satisfy the condition.
      resolveContext: async () => ({ 'principal.licenses': ['pro'] }),
    });
    const { f, tenantId, owner, licenses, pro, alice, bob } = s;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Pro reader',
      document: proReaders,
    });
    for (const person of [alice, bob])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: reader.id,
        subjectType: 'identity',
        subjectId: person.id,
      });
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const canRead = async (credential: { token: string }) =>
      (
        await f.iam.authorize({
          ...credential,
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'd1' },
        })
      ).allowed;
    expect(await canRead(asAlice)).toBe(false);
    await s.assign(alice.id);
    expect(await canRead(asAlice)).toBe(true);
    // A waiting seat unlocks nothing.
    await s.assign(bob.id);
    expect(await canRead(asBob)).toBe(false);
    // Simulations and access reviews see the real seats.
    expect(
      await f.iam.api.policies.simulate(owner, {
        tenantId,
        identityId: alice.id,
        action: 'documents:read',
        resource: { type: 'document', id: 'd1' },
      }),
    ).toMatchObject({ allowed: true });
    const review = await f.iam.api.policies.whoCan(owner, {
      tenantId,
      action: 'documents:read',
      resource: { type: 'document', id: 'd1' },
    });
    expect(review.identities.map((match) => match.identityId)).toContain(alice.id);
    expect(review.identities.map((match) => match.identityId)).not.toContain(bob.id);
    // When the seat moves, access follows at once.
    await s.unassign(alice.id);
    expect(await canRead(asAlice)).toBe(false);
    expect(await canRead(asBob)).toBe(true);

    // A seat held through a group counts only while the membership is live, even before a reconcile.
    const crew = await f.iam.api.groups.create(owner, { tenantId, name: 'Crew' });
    await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 5 });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: crew.id,
      identityId: alice.id,
      expiresAt: f.now() + HOUR,
    });
    await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: crew.id,
    });
    expect(await canRead(asAlice)).toBe(true);
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual(['pro']);
    f.advance(2 * HOUR);
    expect(await canRead(asAlice)).toBe(false);
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual([]);
    expect(
      (await licenses.listSeats(owner, { tenantId, identityId: alice.id })).seats[0]?.status,
    ).toBe('active');

    // Retiring the product ends it for everyone.
    await licenses.retireProduct(await f.ownerSignIn(), { tenantId, productId: pro.id });
    expect(await canRead(asBob)).toBe(false);
  });

  it('gives assumed roles no licenses', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses } = s;
    // The owner holds the seat and may assume a role that reads documents on a Pro seat.
    await s.assign(f.ownerId);
    const role = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Pro reader',
      document: proReaders,
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId,
      sourceTenantId: tenantId,
      sourceIdentityId: f.ownerId,
      roleId: role.id,
      requireMfa: false,
    });
    const assumed = await f.iam.api.roles.assume(owner, {
      tenantId,
      trustId: trust.id,
      sessionName: 'batch',
    });
    expect(
      (
        await f.iam.authorize({
          token: assumed.token,
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'd1' },
        })
      ).allowed,
    ).toBe(false);
    expect(await licenses.mine({ token: assumed.token }, { tenantId })).toEqual({
      tenantId,
      identityId: f.ownerId,
      licenses: [],
      featureKeys: [],
      allFeatureKeys: [],
    });
    expect((await licenses.mine(owner, { tenantId })).licenses).toEqual([
      expect.objectContaining({ key: 'pro', status: 'active' }),
    ]);
  });

  it('is known to policy lint and filled in by policies.test', async () => {
    const { f, tenantId, owner } = await scenario();
    expect(lintPolicy(proReaders)).toEqual({ valid: true, warnings: [] });
    const misspelled = lintPolicy({
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['documents:read'],
          resources: ['*'],
          conditions: { ArrayContains: { 'principal.license': 'pro' } },
        },
      ],
    });
    expect(JSON.stringify(misspelled.warnings)).toContain('principal.licenses');
    const test = (context?: Record<string, unknown>) =>
      f.iam.api.policies.test(owner, {
        tenantId,
        document: proReaders,
        action: 'documents:read',
        resource: 'document/1',
        ...(context ? { context } : {}),
      });
    expect((await test()).allowed).toBe(false);
    expect((await test({ 'principal.licenses': ['pro'] })).allowed).toBe(true);
  });
});

describe('license seats and access invariants', () => {
  it('refuses seat changes that newly break an enforced invariant, wherever the capacity comes from', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pool, alice, bob } = s;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Pro reader',
      document: proReaders,
    });
    for (const person of [alice, bob])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: reader.id,
        subjectType: 'identity',
        subjectId: person.id,
      });
    const d1 = { type: 'document', id: 'd1' };
    await f.iam.api.invariants.create(owner, {
      tenantId,
      name: 'Bob never reads d1',
      subject: { identityId: bob.id },
      action: 'documents:read',
      resource: d1,
      expect: 'deny',
      mode: 'enforce',
    });
    await f.iam.api.invariants.create(owner, {
      tenantId,
      name: 'Alice always reads d1',
      subject: { identityId: alice.id },
      action: 'documents:read',
      resource: d1,
      expect: 'allow',
      mode: 'monitor',
    });
    await s.assign(alice.id);
    // Bob only waits, which grants nothing.
    await s.assign(bob.id);
    const seats = async () =>
      (await licenses.listSeats(owner, { tenantId })).seats.map((seat) => [
        seat.identityId,
        seat.status,
      ]);
    const before = await seats();
    expect(before).toEqual([
      [alice.id, 'active'],
      [bob.id, 'waiting'],
    ]);
    // More capacity would seat bob.
    await expect(
      licenses.updatePool(owner, { tenantId, poolId: pool.id, quantity: 2 }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION', status: 409 });
    // So would unassigning alice.
    await expect(s.unassign(alice.id)).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
    expect(await seats()).toEqual(before);

    // Capacity granted from the platform is held to the receiving tenant's invariants as well.
    const rootId = f.root.tenant.id;
    const platformPro = await licenses.createProduct(f.rootCredential, {
      tenantId: rootId,
      key: 'pro',
      name: 'Platform Pro',
    });
    await licenses.assign(owner, {
      tenantId,
      productId: platformPro.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await expect(
      licenses.addPool(f.rootCredential, { tenantId, productId: platformPro.id, quantity: 1 }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
    expect((await licenses.listPools(owner, { tenantId, productId: platformPro.id })).total).toBe(
      0,
    );
    expect(await f.iam.licenses.products(bob.id, tenantId)).toEqual([]);

    // With the enforced invariant in monitor mode the same grant goes through.
    const invariants = await f.iam.api.invariants.list(owner, { tenantId });
    const strict = invariants.find((item) => item.name === 'Bob never reads d1')!;
    await f.iam.api.invariants.update(owner, {
      tenantId,
      invariantId: strict.id,
      mode: 'monitor',
    });
    await expect(
      licenses.addPool(f.rootCredential, { tenantId, productId: platformPro.id, quantity: 1 }),
    ).resolves.toMatchObject({ seats: [expect.objectContaining({ identityId: bob.id })] });
    expect(await f.iam.licenses.products(bob.id, tenantId)).toEqual(['pro']);
  });
});

describe('identity.licenses in birthright packages', () => {
  it('grants and removes a package as seats come and go', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, pool, alice, bob } = s;
    const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Pro wiki' });
    const pkg = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Pro tools',
      groupIds: [wiki.id],
      autoAssign: {
        include: [
          {
            StringEquals: { 'principal.kind': 'user' },
            ArrayContains: { 'identity.licenses': ['pro'] },
          },
        ],
      },
    });
    expect(pkg.autoAssign?.warnings).toContainEqual(
      expect.stringContaining('tests identity.licenses, which anyone holding iam:licenses:assign'),
    );
    const holders = async () =>
      (
        await f.iam.api.packages.listAssignments(owner, {
          tenantId,
          packageId: pkg.id,
          source: 'automatic',
        })
      )
        .map((assignment) => assignment.identityId)
        .sort();
    expect(await holders()).toEqual([]);
    await s.assign(alice.id);
    expect(await holders()).toEqual([alice.id]);
    expect(
      (await f.iam.api.groups.listMembers(owner, { tenantId, groupId: wiki.id })).map(
        (member) => member.id,
      ),
    ).toEqual([alice.id]);
    // Waiting holds nothing.
    await s.assign(bob.id);
    expect(await holders()).toEqual([alice.id]);
    // More capacity seats bob; less takes the newest seat and its package back.
    await licenses.updatePool(owner, { tenantId, poolId: pool.id, quantity: 2 });
    expect(await holders()).toEqual([alice.id, bob.id].sort());
    await licenses.updatePool(owner, { tenantId, poolId: pool.id, quantity: 1 });
    expect(await holders()).toEqual([alice.id]);
    // Unassigning alice moves bob up, and the package moves with the seat.
    await s.unassign(alice.id);
    expect(await holders()).toEqual([bob.id]);
    // Disabling bob releases his seat (disabled people keep what rules gave them until they return).
    const fresh = await f.ownerSignIn();
    await f.iam.api.identities.setStatus(fresh, {
      tenantId,
      identityId: bob.id,
      status: 'disabled',
    });
    expect((await licenses.listSeats(owner, { tenantId })).seats).toEqual([]);

    const preview = await f.iam.api.packages.previewAutoAssign(owner, { tenantId });
    expect(preview.keys.map((key) => key.key)).toContain('identity.licenses');
    // The product key stays valid once retired.
    await licenses.retireProduct(fresh, { tenantId, productId: pro.id });
    await expect(
      f.iam.api.packages.update(owner, {
        tenantId,
        packageId: pkg.id,
        autoAssign: {
          include: [
            {
              StringEquals: { 'principal.kind': 'user' },
              ArrayContains: { 'identity.licenses': ['pro'] },
            },
          ],
          graceMs: 60_000,
        },
      }),
    ).resolves.toMatchObject({ name: 'Pro tools' });
  });

  it('validates the products a rule names', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses } = s;
    const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Wiki' });
    const create = (conditions: Record<string, unknown>, name = 'Checked') =>
      f.iam.api.packages.create(owner, {
        tenantId,
        name,
        groupIds: [wiki.id],
        autoAssign: {
          include: [{ StringEquals: { 'principal.kind': 'user' }, ...conditions }],
        } as never,
      });
    await expect(
      create({ ArrayContains: { 'identity.licenses': ['nope'] } }),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('unknown license nope'),
    });
    await expect(create({ StringEquals: { 'identity.licenses': 'pro' } })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(create({ ArrayContains: { 'identity.licenses': [7] } })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('identity.licenses lists licenses'),
    });
    // Another organization's key is unknown here; a platform product's is known everywhere.
    const globex = await f.iam.api.tenants.create(f.rootCredential, {
      parentId: f.root.tenant.id,
      name: 'Globex',
      type: 'organization',
      ownerEmail: 'owner@globex.test',
    });
    await licenses.createProduct(f.rootCredential, {
      tenantId: globex.tenant.id,
      key: 'globex-only',
      name: 'Globex only',
    });
    await expect(
      create({ ArrayContains: { 'identity.licenses': ['globex-only'] } }),
    ).rejects.toMatchObject({ message: expect.stringContaining('unknown license globex-only') });
    await licenses.createProduct(f.rootCredential, {
      tenantId: f.root.tenant.id,
      key: 'suite',
      name: 'Suite',
    });
    await expect(
      create({ ArrayContains: { 'identity.licenses': ['suite', 'pro'] } }, 'Both'),
    ).resolves.toMatchObject({ name: 'Both' });
    await expect(
      create({ Exists: { 'identity.licenses': true } }, 'Anyone licensed'),
    ).resolves.toMatchObject({ name: 'Anyone licensed' });
  });

  it('names products by key in configuration documents, and plans refuse unknown keys like apply does', async () => {
    const s = await scenario();
    const { f, tenantId, owner, alice } = s;
    const rule = (key: string) => ({
      include: [
        {
          StringEquals: { 'principal.kind': 'user' },
          ArrayContains: { 'identity.licenses': [key] },
        },
      ],
    });
    const config = (key: string) => ({
      version: 1 as const,
      groups: [{ name: 'Pro wiki' }],
      packages: [{ name: 'Pro tools', groups: ['Pro wiki'], autoAssign: rule(key) }],
    });
    await expect(
      f.iam.api.config.plan(owner, { tenantId, config: config('nope') }),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('unknown license nope'),
    });
    await expect(
      f.iam.api.config.apply(owner, { tenantId, config: config('nope') }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await f.iam.api.packages.list(owner, { tenantId })).toEqual([]);

    const plan = await f.iam.api.config.plan(owner, { tenantId, config: config('pro') });
    expect(
      plan.changes
        .filter((change) => change.action !== 'unchanged')
        .map((change) => `${change.kind}:${change.name}:${change.action}`)
        .sort(),
    ).toEqual(['group:Pro wiki:create', 'package:Pro tools:create']);
    await f.iam.api.config.apply(owner, { tenantId, config: config('pro') });
    const exported = await f.iam.api.config.export(owner, { tenantId });
    expect(exported.packages?.find((pkg) => pkg.name === 'Pro tools')?.autoAssign).toEqual(
      rule('pro'),
    );
    const again = await f.iam.api.config.plan(owner, { tenantId, config: config('pro') });
    expect(again.changes.every((change) => change.action === 'unchanged')).toBe(true);
    // The package applied from the document works like one made through the API.
    const pkg = (await f.iam.api.packages.list(owner, { tenantId })).find(
      (item) => item.name === 'Pro tools',
    )!;
    await s.assign(alice.id);
    expect(
      (
        await f.iam.api.packages.listAssignments(owner, {
          tenantId,
          packageId: pkg.id,
          source: 'automatic',
        })
      ).map((assignment) => assignment.identityId),
    ).toEqual([alice.id]);
  });

  it('counts only seats that no access package brought, and suspends a rule whose product is gone', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, alice, bob } = s;
    await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 5 });
    // Contractors get their group from a package; the group carries a Pro license.
    const contractors = await f.iam.api.groups.create(owner, { tenantId, name: 'Contractors' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Contractor kit',
      groupIds: [contractors.id],
    });
    await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: contractors.id,
    });
    await f.iam.api.packages.assign(owner, { tenantId, packageId: kit.id, identityId: alice.id });
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual(['pro']);
    const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Wiki' });
    const pkg = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Pro tools',
      groupIds: [wiki.id],
      autoAssign: {
        include: [
          {
            StringEquals: { 'principal.kind': 'user' },
            ArrayContains: { 'identity.licenses': ['pro'] },
          },
        ],
      },
    });
    const holders = async () =>
      (
        await f.iam.api.packages.listAssignments(owner, {
          tenantId,
          packageId: pkg.id,
          source: 'automatic',
        })
      ).map((assignment) => assignment.identityId);
    // Alice's seat came through a package, so the rule does not feed on it; bob's direct seat counts.
    await s.assign(bob.id);
    expect(await holders()).toEqual([bob.id]);
    await f.iam.api.packages.reconcile(owner, { tenantId, packageId: pkg.id });
    expect(await holders()).toEqual([bob.id]);

    // A product that disappeared from under a rule (a restored backup, say) suspends it instead of revoking.
    await f.iam.store.transaction((tx) => tx.delete('licenseProducts', pro.id));
    const run = await f.iam.api.packages.reconcile(owner, { tenantId, packageId: pkg.id });
    expect(run.suspended).toEqual([
      expect.objectContaining({
        packageId: pkg.id,
        reason: 'invalid-rule',
        detail: expect.stringContaining('unknown license pro'),
      }),
    ]);
    expect(await holders()).toEqual([bob.id]);
    // The seats of a vanished product go on the next run; the suspended rule still revokes nothing.
    expect(await f.iam.licenses.reconcile({ tenantId })).toMatchObject({ released: 2 });
    expect(await holders()).toEqual([bob.id]);
  });
});
