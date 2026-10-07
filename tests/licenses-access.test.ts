import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import { routeGroups } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/** A tenant created by `creator` under `parentId` whose owner has accepted the invitation. */
async function tenant(
  f: OrganizationFixture,
  creator: { token: string },
  parentId: string,
  name: string,
  type: 'organization' | 'project',
) {
  const created = await f.iam.api.tenants.create(creator, {
    parentId,
    name,
    type,
    ownerEmail: `owner@${name.toLowerCase()}.test`,
  });
  await f.iam.auth.dispatchOutbox();
  const invitation = f.inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await f.iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: `${name} owner`,
    password: `a strong ${name} owner password`,
  });
  if (!('token' in owner)) throw new Error('Unexpected MFA');
  const credential = { token: owner.token };
  const ownerId = (await f.iam.api.auth.getSession(credential)).identity.id;
  return { tenantId: created.tenant.id, credential, ownerId };
}

/** Acme with a product, a pool, a group and an assignment to alice. */
async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const licenses = f.iam.api.licenses;
  const pro = await licenses.createProduct(owner, {
    tenantId,
    key: 'pro',
    name: 'Pro',
    featureKeys: ['exports'],
  });
  const pool = (await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 2 })).pool;
  const alice = await f.member('alice');
  const design = await f.iam.api.groups.create(owner, { tenantId, name: 'Design' });
  const assignment = (
    await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'identity',
      subjectId: alice.id,
    })
  ).assignment;
  /** A member holding a role with `permissions` (none when empty), signed in. */
  const member = async (name: string, permissions: string[]) => {
    const identity = await f.member(name);
    if (permissions.length) {
      const role = await f.iam.api.roles.create(owner, {
        tenantId,
        name: `${name} role`,
        permissions,
      });
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: identity.id,
      });
    }
    return { identity, credential: { token: (await f.signIn(name)).token } };
  };
  return { f, tenantId, owner, licenses, pro, pool, alice, design, assignment, member };
}

type Scenario = Awaited<ReturnType<typeof scenario>>;

/** Every licenses call against Acme, by kind. */
function calls(s: Scenario, credential: { token: string }, subjectId: string) {
  const { licenses, tenantId, pro, pool, assignment } = s;
  return {
    read: {
      listProducts: () => licenses.listProducts(credential, { tenantId }),
      getProduct: () => licenses.getProduct(credential, { tenantId, productId: pro.id }),
      listPools: () => licenses.listPools(credential, { tenantId }),
      listAssignments: () => licenses.listAssignments(credential, { tenantId }),
      listSeats: () => licenses.listSeats(credential, { tenantId }),
      usage: () => licenses.usage(credential, { tenantId }),
      getSettings: () => licenses.getSettings(credential, { tenantId }),
    },
    manage: {
      createProduct: () =>
        licenses.createProduct(credential, {
          tenantId,
          key: `made-${subjectId.length}`,
          name: 'Made',
        }),
      updateProduct: () =>
        licenses.updateProduct(credential, { tenantId, productId: pro.id, name: 'Renamed' }),
      addPool: () => licenses.addPool(credential, { tenantId, productId: pro.id, quantity: 1 }),
      updatePool: () => licenses.updatePool(credential, { tenantId, poolId: pool.id, quantity: 3 }),
      configure: () => licenses.configure(credential, { tenantId, notifyWaiting: true }),
    },
    assign: {
      assign: () =>
        licenses.assign(credential, {
          tenantId,
          productId: pro.id,
          subjectType: 'identity',
          subjectId,
        }),
      assignMany: () =>
        licenses.assignMany(credential, { tenantId, productId: pro.id, identityIds: [subjectId] }),
      unassign: () => licenses.unassign(credential, { tenantId, assignmentId: assignment.id }),
    },
    destructive: {
      removePool: () => licenses.removePool(credential, { tenantId, poolId: pool.id }),
      retireProduct: () => licenses.retireProduct(credential, { tenantId, productId: pro.id }),
    },
  };
}

describe('license permissions', () => {
  it('denies every administrative call to members without license actions, and audits it', async () => {
    const s = await scenario();
    const dave = await s.member('dave', []);
    const all = calls(s, dave.credential, dave.identity.id);
    for (const group of Object.values(all))
      for (const [name, call] of Object.entries(group))
        await expect(call(), name).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    // Their own licenses need no permission.
    await expect(s.licenses.mine(dave.credential, { tenantId: s.tenantId })).resolves.toMatchObject(
      { identityId: dave.identity.id, licenses: [] },
    );
    const denials = (await s.f.iam.store.find<AuditEvent>('audit', { tenantId: s.tenantId }))
      .filter((event) => event.actorId === dave.identity.id && event.outcome === 'deny')
      .map((event) => event.action);
    expect(new Set(denials)).toEqual(
      new Set(['iam:licenses:read', 'iam:licenses:manage', 'iam:licenses:assign']),
    );
    expect(denials).toHaveLength(17);
    // Nothing changed.
    expect((await s.licenses.listSeats(s.owner, { tenantId: s.tenantId })).seats).toEqual([
      expect.objectContaining({ identityId: s.alice.id, status: 'active' }),
    ]);
  });

  it('separates reading, assigning and managing', async () => {
    const s = await scenario();
    const reader = await s.member('reader', ['iam:licenses:read']);
    const assigner = await s.member('assigner', ['iam:licenses:read', 'iam:licenses:assign']);
    const manager = await s.member('manager', ['iam:licenses:read', 'iam:licenses:manage']);
    const bob = await s.f.member('bob');

    const asReader = calls(s, reader.credential, bob.id);
    for (const [name, call] of Object.entries(asReader.read))
      await expect(call(), name).resolves.toBeDefined();
    for (const [name, call] of Object.entries({ ...asReader.manage, ...asReader.assign }))
      await expect(call(), name).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const asAssigner = calls(s, assigner.credential, bob.id);
    await expect(asAssigner.assign.assign()).resolves.toMatchObject({
      assignment: { subjectId: bob.id, assignedBy: assigner.identity.id },
    });
    await expect(asAssigner.assign.unassign()).resolves.toMatchObject({ removed: true });
    await expect(
      s.licenses.assignMany(assigner.credential, {
        tenantId: s.tenantId,
        productId: s.pro.id,
        identityIds: [s.alice.id],
      }),
    ).resolves.toMatchObject({ assigned: [{ subjectId: s.alice.id }] });
    for (const [name, call] of Object.entries({ ...asAssigner.manage, ...asAssigner.destructive }))
      await expect(call(), name).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const asManager = calls(s, manager.credential, bob.id);
    for (const [name, call] of Object.entries(asManager.manage))
      await expect(call(), name).resolves.toBeDefined();
    for (const [name, call] of Object.entries(asManager.assign))
      await expect(call(), name).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(asManager.destructive.removePool()).resolves.toMatchObject({ removed: true });
    // Retiring needs a recent sign-in as well as the permission.
    s.f.advance(6 * 60_000);
    await expect(asManager.destructive.retireProduct()).rejects.toMatchObject({
      code: 'RECENT_AUTH_REQUIRED',
    });
    await expect(asManager.manage.createProduct()).rejects.toMatchObject({
      code: 'RECENT_AUTH_REQUIRED',
    });
    const fresh = { token: (await s.f.signIn('manager')).token };
    await expect(
      s.licenses.retireProduct(fresh, { tenantId: s.tenantId, productId: s.pro.id }),
    ).resolves.toMatchObject({ product: { status: 'retired', updatedBy: manager.identity.id } });
  });

  it('keeps platform pools to root administrators and lets a tenant grant its own products below it', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses } = s;
    const rootId = f.root.tenant.id;
    const suite = await licenses.createProduct(f.rootCredential, {
      tenantId: rootId,
      key: 'suite',
      name: 'Suite',
    });
    // Capacity of a platform product is bought from the platform: an owner cannot add it to their own tenant.
    await expect(
      licenses.addPool(owner, { tenantId, productId: suite.id, quantity: 5 }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Authorized in the root tenant, the refusal is recorded in the caller's own tenant, naming the target.
    const refused = (await f.iam.store.find<AuditEvent>('audit', {})).filter(
      (event) => event.actorId === f.ownerId && event.outcome === 'deny',
    );
    expect(refused).toEqual([
      expect.objectContaining({
        action: 'iam:licenses:manage',
        tenantId,
        resourceId: 'licenses/pools',
        metadata: { targetTenantId: rootId },
      }),
    ]);

    const granted = await licenses.addPool(f.rootCredential, {
      tenantId,
      productId: suite.id,
      quantity: 3,
      note: 'Contract 42',
    });
    expect(granted.pool).toMatchObject({ tenantId, tenantName: 'Acme', productKey: 'suite' });
    // The grant is recorded where the capacity lands; the permission check where the product is defined.
    const added = (await f.iam.store.find<AuditEvent>('audit', { tenantId })).filter(
      (event) =>
        event.action === 'license:pool-add' &&
        event.resourceId === `licenses/pools/${granted.pool.id}`,
    );
    expect(added).toEqual([
      expect.objectContaining({
        actorId: f.root.identity.id,
        metadata: expect.objectContaining({ productKey: 'suite', quantity: 3, source: 'manual' }),
      }),
    ]);
    expect(
      (await f.iam.store.find<AuditEvent>('audit', { tenantId: rootId })).some(
        (event) =>
          event.action === 'iam:licenses:manage' &&
          event.outcome === 'allow' &&
          event.resourceId === 'licenses/pools',
      ),
    ).toBe(true);
    expect(
      (await licenses.listPools(owner, { tenantId })).pools.map((pool) => pool.productKey).sort(),
    ).toEqual(['pro', 'suite']);
    // The root tenant sees the pools it granted.
    expect(
      (await licenses.listPools(f.rootCredential, { tenantId: rootId })).pools.map((pool) => [
        pool.tenantName,
        pool.productKey,
      ]),
    ).toEqual([['Acme', 'suite']]);
    await expect(
      licenses.updatePool(owner, { tenantId, poolId: granted.pool.id, quantity: 30 }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      licenses.removePool(owner, { tenantId, poolId: granted.pool.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      licenses.updatePool(f.rootCredential, { tenantId, poolId: granted.pool.id, quantity: 4 }),
    ).resolves.toMatchObject({ pool: { quantity: 4 } });
    // People of the tenant take the platform product's seats like any other.
    await expect(
      licenses.assign(owner, {
        tenantId,
        productId: suite.id,
        subjectType: 'identity',
        subjectId: s.alice.id,
      }),
    ).resolves.toMatchObject({ seats: [{ to: 'active' }] });

    // Acme's own product can be granted to its project, by Acme's managers only.
    const apollo = await tenant(f, owner, tenantId, 'Apollo', 'project');
    const forApollo = await licenses.addPool(owner, {
      tenantId: apollo.tenantId,
      productId: s.pro.id,
      quantity: 1,
    });
    expect(forApollo.pool).toMatchObject({ tenantId: apollo.tenantId, tenantName: 'Apollo' });
    expect(
      (await licenses.listPools(owner, { tenantId })).pools.map((pool) => pool.tenantName).sort(),
    ).toEqual(['Acme', 'Acme', 'Apollo']);
    expect(
      (await licenses.listPools(apollo.credential, { tenantId: apollo.tenantId })).pools.map(
        (pool) => pool.id,
      ),
    ).toEqual([forApollo.pool.id]);
    for (const call of [
      () =>
        licenses.addPool(apollo.credential, {
          tenantId: apollo.tenantId,
          productId: s.pro.id,
          quantity: 10,
        }),
      () =>
        licenses.updatePool(apollo.credential, {
          tenantId: apollo.tenantId,
          poolId: forApollo.pool.id,
          quantity: 10,
        }),
      () =>
        licenses.removePool(apollo.credential, {
          tenantId: apollo.tenantId,
          poolId: forApollo.pool.id,
        }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const seated = await licenses.assign(apollo.credential, {
      tenantId: apollo.tenantId,
      productId: s.pro.id,
      subjectType: 'identity',
      subjectId: apollo.ownerId,
    });
    expect(seated.seats).toEqual([
      expect.objectContaining({ tenantId: apollo.tenantId, productKey: 'pro', to: 'active' }),
    ]);
    // Acme's seats and Apollo's are counted apart.
    expect((await licenses.usage(owner, { tenantId })).products).toContainEqual(
      expect.objectContaining({ key: 'pro', capacity: 2, active: 1 }),
    );
    expect(
      (await licenses.usage(apollo.credential, { tenantId: apollo.tenantId })).products,
    ).toEqual([expect.objectContaining({ key: 'pro', capacity: 1, active: 1, assignments: 1 })]);
    await expect(
      licenses.updatePool(owner, {
        tenantId: apollo.tenantId,
        poolId: forApollo.pool.id,
        quantity: 2,
      }),
    ).resolves.toMatchObject({ pool: { quantity: 2 } });
  });
});

describe('license tenant isolation', () => {
  it('lets another organization neither read nor act on Acme’s licenses', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, pool, alice, design, assignment } = s;
    const globex = await tenant(f, f.rootCredential, f.root.tenant.id, 'Globex', 'organization');
    const outsider = globex.credential;
    const gx = await licenses.createProduct(outsider, {
      tenantId: globex.tenantId,
      key: 'gx',
      name: 'Globex plan',
    });
    await licenses.addPool(outsider, { tenantId: globex.tenantId, productId: gx.id, quantity: 5 });
    const own = { tenantId: globex.tenantId };

    // Acme's tenant is closed to them.
    for (const call of Object.values(calls(s, outsider, globex.ownerId)).flatMap((group) =>
      Object.values(group),
    ))
      await expect(call()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(licenses.mine(outsider, { tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });

    // Acme's records are invisible from their own tenant.
    for (const call of [
      () => licenses.getProduct(outsider, { ...own, productId: pro.id }),
      () => licenses.updateProduct(outsider, { ...own, productId: pro.id, name: 'Taken' }),
      () => licenses.retireProduct(outsider, { ...own, productId: pro.id }),
      () =>
        licenses.assign(outsider, {
          ...own,
          productId: pro.id,
          subjectType: 'identity',
          subjectId: globex.ownerId,
        }),
      () =>
        licenses.assign(outsider, {
          ...own,
          productId: gx.id,
          subjectType: 'identity',
          subjectId: alice.id,
        }),
      () =>
        licenses.assign(outsider, {
          ...own,
          productId: gx.id,
          subjectType: 'group',
          subjectId: design.id,
        }),
      () => licenses.assignMany(outsider, { ...own, productId: gx.id, identityIds: [alice.id] }),
      () => licenses.unassign(outsider, { ...own, assignmentId: assignment.id }),
      () =>
        licenses.unassign(outsider, {
          ...own,
          productId: pro.id,
          subjectType: 'identity',
          subjectId: alice.id,
        }),
      () => licenses.updatePool(outsider, { ...own, poolId: pool.id, quantity: 9 }),
      () => licenses.removePool(outsider, { ...own, poolId: pool.id }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Capacity of Acme's product is granted by Acme only, and only within its subtree.
    await expect(
      licenses.addPool(outsider, { ...own, productId: pro.id, quantity: 50 }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      licenses.addPool(outsider, { tenantId, productId: gx.id, quantity: 50 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      licenses.createProduct(outsider, { ...own, key: 'pro', name: 'Their pro' }),
    ).resolves.toMatchObject({ key: 'pro', definedBy: globex.tenantId });
    expect(
      (await licenses.listProducts(outsider, own)).products.map((product) => product.id),
    ).not.toContain(pro.id);
    expect(await licenses.listPools(outsider, { ...own, productId: pro.id })).toEqual({
      pools: [],
      total: 0,
    });
    expect(await licenses.listAssignments(outsider, { ...own, productId: pro.id })).toEqual({
      assignments: [],
      total: 0,
    });
    expect(await licenses.listSeats(outsider, { ...own, identityId: alice.id })).toEqual({
      seats: [],
      total: 0,
    });
    expect(await f.iam.licenses.products(alice.id, globex.tenantId)).toEqual([]);
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual(['pro']);

    // Nothing of Acme's moved, and Acme's audit chain holds nothing of theirs.
    expect((await licenses.listPools(owner, { tenantId })).pools).toEqual([
      expect.objectContaining({ id: pool.id, quantity: 2 }),
    ]);
    expect((await licenses.listAssignments(owner, { tenantId })).total).toBe(1);
    expect((await licenses.getProduct(owner, { tenantId, productId: pro.id })).name).toBe('Pro');
    expect(
      (await f.iam.store.find<AuditEvent>('audit', { tenantId })).filter(
        (event) => event.actorId === globex.ownerId,
      ),
    ).toEqual([]);
  });

  it('is routed over HTTP', async () => {
    const s = await scenario();
    expect(routeGroups.has('licenses')).toBe(true);
    const call = (method: string, token: string, body: unknown) =>
      s.f.iam.handler(
        new Request(`http://localhost:3000/api/iam/licenses/${method}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-better-iam': '1',
            authorization: `Bearer ${token}`,
          },
          body: JSON.stringify(body),
        }),
      );
    const listed = await call('listProducts', s.owner.token, { tenantId: s.tenantId });
    expect(listed.status).toBe(200);
    expect(((await listed.json()) as { data: { products: unknown[] } }).data.products).toEqual([
      expect.objectContaining({ key: 'pro' }),
    ]);
    const alice = (await s.f.signIn('alice')).token;
    const mine = await call('mine', alice, { tenantId: s.tenantId });
    expect(mine.status).toBe(200);
    expect(((await mine.json()) as { data: unknown }).data).toMatchObject({
      identityId: s.alice.id,
      featureKeys: [],
      allFeatureKeys: ['exports'],
    });
    const denied = await call('usage', alice, { tenantId: s.tenantId });
    expect(denied.status).toBe(403);
    expect(((await denied.json()) as { error: { code: string } }).error.code).toBe('ACCESS_DENIED');
  });
});
