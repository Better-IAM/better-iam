import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import type { LicenseSeatChange } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const HOUR = 3_600_000;

/** A project under Acme whose owner has accepted the invitation. */
async function project(f: OrganizationFixture, name = 'Apollo') {
  const created = await f.iam.api.tenants.create(f.ownerCredential, {
    parentId: f.tenantId,
    name,
    type: 'project',
    ownerEmail: `${name.toLowerCase()}@acme.test`,
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

/** The license audit events of a tenant, oldest first. */
async function trail(f: OrganizationFixture, tenantId: string, prefix = 'license:') {
  return (await f.iam.store.find<AuditEvent>('audit', { tenantId }))
    .filter((event) => event.action.startsWith(prefix))
    .sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
}

/**
 * Acme with a product "pro" and three people. `assign` moves the (frozen) fixture clock a second first, so seniority
 * never falls back to identity order.
 */
async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const licenses = f.iam.api.licenses;
  const pro = await licenses.createProduct(owner, {
    tenantId,
    key: 'pro',
    name: 'Pro',
    description: 'Everything in Pro',
    featureKeys: ['sso', 'exports'],
  });
  const alice = await f.member('alice');
  const bob = await f.member('bob');
  const carol = await f.member('carol');
  const names = new Map<string, string>([
    [alice.id, 'alice'],
    [bob.id, 'bob'],
    [carol.id, 'carol'],
  ]);
  const person = async (name: string) => {
    const identity = await f.member(name);
    names.set(identity.id, name);
    return identity;
  };
  const assign = async (identityId: string, productId = pro.id) => {
    f.advance(1000);
    return licenses.assign(owner, {
      tenantId,
      productId,
      subjectType: 'identity',
      subjectId: identityId,
    });
  };
  const seats = async (productId = pro.id) =>
    (await licenses.listSeats(owner, { tenantId, productId })).seats.map(
      (seat) =>
        `${seat.identityName} ${seat.status}${seat.position !== undefined ? ` #${seat.position}` : ''}`,
    );
  const changes = (list: readonly LicenseSeatChange[]) =>
    list.map((change) => `${names.get(change.identityId)} ${change.from}->${change.to}`);
  return {
    f,
    tenantId,
    owner,
    licenses,
    pro,
    alice,
    bob,
    carol,
    person,
    assign,
    seats,
    changes,
  };
}

describe('license products', () => {
  it('defines, validates, updates and lists a tenant product', async () => {
    const { f, tenantId, owner, licenses, pro } = await scenario();
    expect(pro).toEqual({
      id: expect.any(String),
      key: 'pro',
      name: 'Pro',
      description: 'Everything in Pro',
      featureKeys: ['exports', 'sso'],
      status: 'active',
      scope: 'tenant',
      definedBy: tenantId,
      definedHere: true,
      shadowed: false,
      createdAt: f.now(),
      createdBy: f.ownerId,
      updatedAt: f.now(),
      updatedBy: f.ownerId,
    });

    const create = (input: Record<string, unknown>) =>
      licenses.createProduct(owner, { tenantId, key: 'team', name: 'Team', ...input } as never);
    for (const key of ['Pro', '-pro', 'pro plan', '', 'x'.repeat(65), 'pro/plan', 7])
      await expect(create({ key })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    for (const input of [
      { name: ' ' },
      { name: 'x'.repeat(101) },
      { description: 'x'.repeat(513) },
      { featureKeys: ['Bad Key'] },
      { featureKeys: 'sso' },
      { featureKeys: Array.from({ length: 51 }, (_, index) => `feature-${index}`) },
    ])
      await expect(create(input)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(create({ key: 'pro' })).rejects.toMatchObject({ code: 'CONFLICT', status: 409 });
    const team = await create({ key: 'team.v2_b-1' });
    expect(team).toMatchObject({ key: 'team.v2_b-1', featureKeys: [] });
    expect(team).not.toHaveProperty('description');

    // The key never changes; the name, description (null clears) and feature keys do.
    f.advance(1000);
    const renamed = await licenses.updateProduct(owner, {
      tenantId,
      productId: pro.id,
      name: 'Pro plan',
      description: null,
      featureKeys: ['sso', 'sso', 'audit-log'],
    });
    expect(renamed).toMatchObject({
      key: 'pro',
      name: 'Pro plan',
      featureKeys: ['audit-log', 'sso'],
      updatedAt: f.now(),
      createdAt: pro.createdAt,
    });
    expect(renamed).not.toHaveProperty('description');
    await expect(
      licenses.updateProduct(owner, { tenantId, productId: pro.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: 'Nothing to update' });
    await expect(
      licenses.updateProduct(owner, { tenantId, productId: 'missing', name: 'x' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      licenses.updateProduct(owner, { tenantId, productId: pro.id, featureKeys: ['Nope'] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await licenses.getProduct(owner, { tenantId, productId: pro.id })).toEqual(renamed);
    await expect(
      licenses.getProduct(owner, { tenantId, productId: 'missing' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND', status: 404 });

    const listed = await licenses.listProducts(owner, { tenantId });
    expect(listed.tenantId).toBe(tenantId);
    expect(listed.products.map((product) => product.key)).toEqual(['pro', 'team.v2_b-1']);
    expect((await licenses.listProducts(owner, { tenantId, status: 'retired' })).products).toEqual(
      [],
    );
    await expect(
      licenses.listProducts(owner, { tenantId, status: 'gone' as never }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    const events = await trail(f, tenantId);
    expect(events.map((event) => event.action)).toEqual([
      'license:product-create',
      'license:product-create',
      'license:product-update',
    ]);
    expect(events[0]).toMatchObject({
      actorId: f.ownerId,
      resourceId: `licenses/products/${pro.id}`,
      metadata: {
        productId: pro.id,
        key: 'pro',
        name: 'Pro',
        description: 'Everything in Pro',
        featureKeys: ['exports', 'sso'],
        status: 'active',
      },
    });
    expect(events[2]!.metadata).toMatchObject({
      before: { name: 'Pro', description: 'Everything in Pro' },
      after: { name: 'Pro plan', description: null, featureKeys: ['audit-log', 'sso'] },
    });
  });

  it('requires recent authentication to define or retire a product', async () => {
    const { f, tenantId, owner, licenses, pro } = await scenario();
    f.advance(6 * 60_000);
    await expect(
      licenses.createProduct(owner, { tenantId, key: 'team', name: 'Team' }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    await expect(
      licenses.retireProduct(owner, { tenantId, productId: pro.id }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    // Renaming does not.
    await expect(
      licenses.updateProduct(owner, { tenantId, productId: pro.id, name: 'Pro 2' }),
    ).resolves.toMatchObject({ name: 'Pro 2' });
    const fresh = await f.ownerSignIn();
    await expect(
      licenses.createProduct(fresh, { tenantId, key: 'team', name: 'Team' }),
    ).resolves.toMatchObject({ key: 'team' });
    await expect(
      licenses.retireProduct(fresh, { tenantId, productId: pro.id }),
    ).resolves.toMatchObject({ product: { status: 'retired' } });
  });

  it('shows platform products to every tenant and ancestors’ products to their subtree', async () => {
    const { f, tenantId, owner, licenses, pro } = await scenario();
    const rootId = f.root.tenant.id;
    const suite = await licenses.createProduct(f.rootCredential, {
      tenantId: rootId,
      key: 'suite',
      name: 'Suite',
      featureKeys: ['suite'],
    });
    expect(suite).toMatchObject({ scope: 'platform', definedBy: rootId, definedHere: true });
    expect((await licenses.listProducts(owner, { tenantId })).products).toEqual([
      expect.objectContaining({ key: 'pro', scope: 'tenant', definedHere: true }),
      expect.objectContaining({
        key: 'suite',
        scope: 'platform',
        definedBy: rootId,
        definedHere: false,
        shadowed: false,
      }),
    ]);
    expect(await licenses.getProduct(owner, { tenantId, productId: suite.id })).toMatchObject({
      key: 'suite',
      definedHere: false,
    });
    // Only root administrators define and change platform products; tenants never repeat their keys.
    await expect(
      licenses.createProduct(owner, { tenantId: rootId, key: 'mine', name: 'Mine' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      licenses.createProduct(owner, { tenantId, key: 'suite', name: 'Suite copy' }),
    ).rejects.toMatchObject({
      code: 'CONFLICT',
      message: 'A platform license product already uses this key',
    });
    await expect(
      licenses.updateProduct(owner, { tenantId, productId: suite.id, name: 'Mine now' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      licenses.retireProduct(owner, { tenantId, productId: suite.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      licenses.updateProduct(owner, { tenantId: rootId, productId: suite.id, name: 'Mine now' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // A project sees Acme's products and the platform's, and may not repeat an enclosing key.
    const apollo = await project(f);
    expect(
      (await licenses.listProducts(apollo.credential, { tenantId: apollo.tenantId })).products.map(
        (product) => [product.key, product.scope, product.definedBy === tenantId],
      ),
    ).toEqual([
      ['pro', 'tenant', true],
      ['suite', 'platform', false],
    ]);
    await expect(
      licenses.createProduct(apollo.credential, {
        tenantId: apollo.tenantId,
        key: 'pro',
        name: 'Pro copy',
      }),
    ).rejects.toMatchObject({
      code: 'CONFLICT',
      message: 'An enclosing tenant already defines a license product with this key',
    });
    const addon = await licenses.createProduct(apollo.credential, {
      tenantId: apollo.tenantId,
      key: 'apollo-addon',
      name: 'Apollo add-on',
    });
    expect(
      (await licenses.listProducts(owner, { tenantId })).products.map((product) => product.key),
    ).toEqual(['pro', 'suite']);
    await expect(
      licenses.getProduct(owner, { tenantId, productId: addon.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // The platform may later define a key a tenant already uses: the tenant's product is then shadowed.
    const platformPro = await licenses.createProduct(f.rootCredential, {
      tenantId: rootId,
      key: 'pro',
      name: 'Platform Pro',
    });
    expect(
      (await licenses.listProducts(owner, { tenantId })).products.map((product) => [
        product.id,
        product.shadowed,
      ]),
    ).toEqual([
      [platformPro.id, false],
      [pro.id, true],
      [suite.id, false],
    ]);
    expect(await licenses.getProduct(owner, { tenantId, productId: pro.id })).toMatchObject({
      shadowed: true,
    });
  });

  it('retires a product for good, releasing its seats in every tenant', async () => {
    const { f, tenantId, owner, licenses, alice, bob, carol, changes } = await scenario();
    const rootId = f.root.tenant.id;
    const apollo = await project(f);
    const suite = await licenses.createProduct(f.rootCredential, {
      tenantId: rootId,
      key: 'suite',
      name: 'Suite',
      featureKeys: ['suite'],
    });
    const acmePool = await licenses.addPool(f.rootCredential, {
      tenantId,
      productId: suite.id,
      quantity: 2,
    });
    await licenses.addPool(f.rootCredential, {
      tenantId: apollo.tenantId,
      productId: suite.id,
      quantity: 1,
    });
    await licenses.assignMany(owner, {
      tenantId,
      productId: suite.id,
      identityIds: [alice.id, bob.id],
    });
    const held = await licenses.assign(apollo.credential, {
      tenantId: apollo.tenantId,
      productId: suite.id,
      subjectType: 'identity',
      subjectId: apollo.ownerId,
    });
    expect(held.seats).toEqual([expect.objectContaining({ from: 'none', to: 'active' })]);

    const retired = await licenses.retireProduct(f.rootCredential, {
      tenantId: rootId,
      productId: suite.id,
    });
    expect(retired.product).toMatchObject({ key: 'suite', status: 'retired' });
    expect(
      retired.seats
        .map((change) => `${change.tenantId === tenantId ? 'acme' : 'apollo'} ${change.to}`)
        .sort(),
    ).toEqual(['acme none', 'acme none', 'apollo none']);
    expect(changes(retired.seats.filter((change) => change.tenantId === tenantId)).sort()).toEqual([
      'alice active->none',
      'bob active->none',
    ]);
    expect((await licenses.listSeats(owner, { tenantId })).seats).toEqual([]);

    // Retired is final: no seats, no new assignments or pool changes, and the key stays taken.
    await expect(
      licenses.retireProduct(f.rootCredential, { tenantId: rootId, productId: suite.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION', status: 409 });
    await expect(
      licenses.assign(owner, {
        tenantId,
        productId: suite.id,
        subjectType: 'identity',
        subjectId: carol.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await expect(
      licenses.assignMany(owner, { tenantId, productId: suite.id, identityIds: [carol.id] }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await expect(
      licenses.addPool(f.rootCredential, { tenantId, productId: suite.id, quantity: 1 }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await expect(
      licenses.updatePool(f.rootCredential, { tenantId, poolId: acmePool.pool.id, quantity: 5 }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await expect(
      licenses.removePool(f.rootCredential, { tenantId, poolId: acmePool.pool.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await expect(
      licenses.createProduct(f.rootCredential, { tenantId: rootId, key: 'suite', name: 'Again' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(
      (await licenses.listProducts(owner, { tenantId, status: 'retired' })).products.map(
        (product) => product.key,
      ),
    ).toEqual(['suite']);
    expect(
      (await licenses.usage(owner, { tenantId })).products.find(
        (product) => product.key === 'suite',
      ),
    ).toMatchObject({ status: 'retired', capacity: 2, active: 0, waiting: 0, assignments: 2 });
    // The safety net never brings seats back; unassigning still tidies up.
    await f.iam.licenses.reconcile();
    expect((await licenses.listSeats(owner, { tenantId })).seats).toEqual([]);
    await expect(
      licenses.unassign(owner, {
        tenantId,
        productId: suite.id,
        subjectType: 'identity',
        subjectId: alice.id,
      }),
    ).resolves.toEqual({ removed: true, seats: [] });
    const asAlice = { token: (await f.signIn('alice')).token };
    expect(await licenses.mine(asAlice, { tenantId })).toMatchObject({
      licenses: [],
      featureKeys: [],
      allFeatureKeys: [],
    });

    // Retirement is audited in the defining tenant, each release where the seat was.
    expect((await trail(f, rootId, 'license:product-retire'))[0]!.metadata).toEqual({
      productId: suite.id,
      key: 'suite',
      releasedSeats: 3,
      tenants: 2,
    });
    expect(
      (await trail(f, apollo.tenantId, 'license:seat-release')).map((event) => [
        event.resourceId,
        event.metadata?.reason,
      ]),
    ).toEqual([[apollo.ownerId, 'product-retired']]);
  });
});

describe('license pools and seats', () => {
  it('ranks claimants by seniority against the capacity of the live pools', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro } = s;
    const first = await s.assign(s.alice.id);
    expect(first.assignment).toEqual({
      id: expect.any(String),
      tenantId,
      productId: pro.id,
      productKey: 'pro',
      productName: 'Pro',
      subjectType: 'identity',
      subjectId: s.alice.id,
      subjectName: 'alice',
      subjectEmail: 'alice@acme.test',
      assignedBy: f.ownerId,
      assignedAt: f.now(),
    });
    // No capacity yet: the claim waits.
    expect(s.changes(first.seats)).toEqual(['alice none->waiting']);
    const initial = await licenses.addPool(owner, {
      tenantId,
      productId: pro.id,
      quantity: 2,
      note: 'Initial purchase',
    });
    expect(initial.pool).toEqual({
      id: expect.any(String),
      tenantId,
      tenantName: 'Acme',
      productId: pro.id,
      productKey: 'pro',
      productName: 'Pro',
      quantity: 2,
      note: 'Initial purchase',
      source: 'manual',
      live: true,
      createdAt: f.now(),
      createdBy: f.ownerId,
    });
    expect(s.changes(initial.seats)).toEqual(['alice waiting->active']);
    expect(s.changes((await s.assign(s.bob.id)).seats)).toEqual(['bob none->active']);
    expect(s.changes((await s.assign(s.carol.id)).seats)).toEqual(['carol none->waiting']);
    expect(await s.seats()).toEqual(['alice active', 'bob active', 'carol waiting #1']);
    expect(await licenses.usage(owner, { tenantId })).toEqual({
      tenantId,
      products: [
        {
          productId: pro.id,
          key: 'pro',
          name: 'Pro',
          scope: 'tenant',
          status: 'active',
          capacity: 2,
          active: 2,
          waiting: 1,
          available: 0,
          pools: 1,
          assignments: 3,
          reclaimable: 0,
          reclaimableThroughGroups: 0,
        },
      ],
    });

    // A capacity cut moves the newest active seat to the head of the waiting list; it is never an error.
    f.advance(1000);
    const cut = await licenses.updatePool(owner, {
      tenantId,
      poolId: initial.pool.id,
      quantity: 1,
    });
    expect(cut.pool).toMatchObject({ quantity: 1, updatedAt: f.now(), updatedBy: f.ownerId });
    expect(s.changes(cut.seats)).toEqual(['bob active->waiting']);
    expect(await s.seats()).toEqual(['alice active', 'bob waiting #1', 'carol waiting #2']);
    // Seats filter by status and person, and page.
    const waitingList = await licenses.listSeats(owner, { tenantId, status: 'waiting' });
    expect(waitingList.total).toBe(2);
    expect(waitingList.seats.map((seat) => [seat.identityName, seat.position])).toEqual([
      ['bob', 1],
      ['carol', 2],
    ]);
    expect(
      await licenses.listSeats(owner, { tenantId, status: 'waiting', limit: 1, offset: 1 }),
    ).toMatchObject({ total: 2, seats: [{ identityName: 'carol', position: 2 }] });
    expect(
      await licenses.listSeats(owner, { tenantId, identityId: s.alice.id, status: 'waiting' }),
    ).toEqual({ seats: [], total: 0 });
    for (const input of [{ status: 'gone' }, { limit: 0 }, { limit: 1001 }, { offset: -1 }])
      await expect(
        licenses.listSeats(owner, { tenantId, ...input } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // A pool with an end: waiting people take its seats at once and keep them until the term ends.
    f.advance(1000);
    const trial = await licenses.addPool(owner, {
      tenantId,
      productId: pro.id,
      quantity: 5,
      endsAt: f.now() + HOUR,
      note: 'Trial',
    });
    expect(trial.pool).toMatchObject({ endsAt: f.now() + HOUR, live: true });
    expect(s.changes(trial.seats)).toEqual(['bob waiting->active', 'carol waiting->active']);
    expect((await licenses.listPools(owner, { tenantId })).pools.map((pool) => pool.note)).toEqual([
      'Trial',
      'Initial purchase',
    ]);
    f.advance(2 * HOUR);
    const job = await f.iam.licenses.reconcile();
    expect(job).toEqual({ tenants: 1, activated: 0, waiting: 2, released: 0, failedTenants: [] });
    expect(await s.seats()).toEqual(['alice active', 'bob waiting #1', 'carol waiting #2']);
    expect(await f.iam.licenses.reconcile({ tenantId })).toEqual({
      tenants: 1,
      activated: 0,
      waiting: 0,
      released: 0,
      failedTenants: [],
    });
    const pools = await licenses.listPools(owner, { tenantId });
    expect(pools).toMatchObject({ total: 1, pools: [{ note: 'Initial purchase' }] });
    const everything = await licenses.listPools(owner, { tenantId, includeEnded: true });
    expect(everything.pools.map((pool) => [pool.note, pool.live])).toEqual([
      ['Trial', false],
      ['Initial purchase', true],
    ]);
    expect(
      await licenses.listPools(owner, { tenantId, includeEnded: true, limit: 1, offset: 1 }),
    ).toMatchObject({ total: 2, pools: [{ note: 'Initial purchase' }] });

    // An ended pool can be reopened (null clears the end) and removed.
    const reopened = await licenses.updatePool(owner, {
      tenantId,
      poolId: trial.pool.id,
      endsAt: null,
      note: null,
    });
    expect(reopened.pool).not.toHaveProperty('endsAt');
    expect(reopened.pool).not.toHaveProperty('note');
    expect(reopened.pool.live).toBe(true);
    expect(s.changes(reopened.seats)).toEqual(['bob waiting->active', 'carol waiting->active']);
    const removed = await licenses.removePool(owner, { tenantId, poolId: trial.pool.id });
    expect(removed.removed).toBe(true);
    expect(s.changes(removed.seats)).toEqual(['bob active->waiting', 'carol active->waiting']);
    await expect(
      licenses.removePool(owner, { tenantId, poolId: trial.pool.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // A pool that starts later adds nothing until it starts.
    const later = await licenses.addPool(owner, {
      tenantId,
      productId: pro.id,
      quantity: 1,
      startsAt: f.now() + HOUR,
    });
    expect(later.pool.live).toBe(false);
    expect(later.seats).toEqual([]);
    expect((await licenses.usage(owner, { tenantId })).products[0]).toMatchObject({
      capacity: 1,
      pools: 1,
    });
    f.advance(2 * HOUR);
    expect(await f.iam.licenses.reconcile()).toMatchObject({ activated: 1 });
    expect(await s.seats()).toEqual(['alice active', 'bob active', 'carol waiting #1']);

    const actions = (await trail(f, tenantId)).map((event) => event.action);
    expect(actions.filter((action) => action.startsWith('license:pool-'))).toEqual([
      'license:pool-add',
      'license:pool-update',
      'license:pool-add',
      'license:pool-update',
      'license:pool-remove',
      'license:pool-add',
    ]);
    const update = (await trail(f, tenantId, 'license:pool-update'))[0]!;
    expect(update).toMatchObject({
      resourceId: `licenses/pools/${initial.pool.id}`,
      metadata: {
        before: { poolId: initial.pool.id, quantity: 2, productKey: 'pro' },
        after: { quantity: 1 },
      },
    });
    const scheduled = (await trail(f, tenantId, 'license:seat-waiting')).filter(
      (event) => event.actorId === 'deployment-operator',
    );
    expect(scheduled.map((event) => [event.resourceId, event.metadata?.reason])).toEqual([
      [s.bob.id, 'schedule'],
      [s.carol.id, 'schedule'],
    ]);
  });

  it('never gives an existing seat to a claimant who arrives in the same millisecond', async () => {
    const { f, tenantId, owner, licenses, pro, alice, bob, carol } = await scenario();
    await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 1 });
    // Assign in descending ID order without moving the clock, so identity order alone would reverse seniority.
    const [first, second, third] = [alice, bob, carol].sort((a, b) => (a.id < b.id ? 1 : -1));
    const assign = (identityId: string) =>
      licenses.assign(owner, {
        tenantId,
        productId: pro.id,
        subjectType: 'identity',
        subjectId: identityId,
      });
    expect((await assign(first!.id)).seats).toEqual([
      expect.objectContaining({ identityId: first!.id, from: 'none', to: 'active' }),
    ]);
    expect((await assign(second!.id)).seats).toEqual([
      expect.objectContaining({ identityId: second!.id, from: 'none', to: 'waiting' }),
    ]);
    expect((await assign(third!.id)).seats).toEqual([
      expect.objectContaining({ identityId: third!.id, from: 'none', to: 'waiting' }),
    ]);
    const holders = async () =>
      (await licenses.listSeats(owner, { tenantId })).seats.map((seat) => [
        seat.identityId,
        seat.status,
        seat.position ?? null,
      ]);
    const expected = [
      [first!.id, 'active', null],
      [third!.id, 'waiting', 1],
      [second!.id, 'waiting', 2],
    ];
    expect(await holders()).toEqual(expected);
    // Later runs keep it that way, and the next free seat goes to the head of the waiting list.
    expect(await f.iam.licenses.reconcile()).toMatchObject({ activated: 0, waiting: 0 });
    expect(await holders()).toEqual(expected);
    const more = await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 1 });
    expect(more.seats).toEqual([
      expect.objectContaining({ identityId: third!.id, from: 'waiting', to: 'active' }),
    ]);
  });

  it('validates pools', async () => {
    const { f, tenantId, owner, licenses, pro } = await scenario();
    const add = (input: Record<string, unknown>) =>
      licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 1, ...input } as never);
    for (const quantity of [0, -1, 1.5, 1_000_001, '3'])
      await expect(add({ quantity })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(add({ endsAt: f.now() - 1 })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(add({ endsAt: f.now() })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      add({ startsAt: f.now() + 2 * HOUR, endsAt: f.now() + HOUR }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(add({ startsAt: -5 })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(add({ note: 'x'.repeat(513) })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(add({ subscriptionId: 'missing' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await expect(add({ productId: 'missing' })).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(add({ quantity: 1_000_000 })).resolves.toMatchObject({
      pool: { quantity: 1_000_000 },
    });
    const later = await add({ startsAt: f.now() + HOUR, endsAt: f.now() + 3 * HOUR });
    await expect(
      licenses.updatePool(owner, { tenantId, poolId: later.pool.id }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: 'Nothing to update' });
    await expect(
      licenses.updatePool(owner, { tenantId, poolId: later.pool.id, endsAt: f.now() + HOUR }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      licenses.updatePool(owner, { tenantId, poolId: later.pool.id, quantity: 0 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      licenses.updatePool(owner, { tenantId, poolId: 'missing', quantity: 2 }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(licenses.listPools(owner, { tenantId, limit: 0 })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(
      licenses.listPools(owner, { tenantId, includeEnded: 'yes' as never }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Ended pools are kept 400 days after their end as purchase history, then swept.
    const ending = await add({ endsAt: f.now() + HOUR });
    f.advance(HOUR + 399 * 24 * HOUR);
    expect((await f.iam.sweepExpired()).deleted.licensePools).toBeUndefined();
    f.advance(2 * 24 * HOUR);
    expect((await f.iam.sweepExpired()).deleted).toMatchObject({ licensePools: 2 });
    const left = await f.iam.store.find('licensePools', { tenantId });
    expect(left.map((pool) => pool.id)).not.toContain(ending.pool.id);
    expect(left).toHaveLength(1);
  });

  it('assigns people and groups, and follows group membership', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, alice, bob, carol } = s;
    await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 10 });
    const design = await f.iam.api.groups.create(owner, { tenantId, name: 'Design' });
    await f.iam.api.groups.addMembers(owner, {
      tenantId,
      groupId: design.id,
      identityIds: [alice.id, bob.id],
    });
    f.advance(1000);
    const grouped = await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: design.id,
    });
    expect(grouped.assignment).toMatchObject({
      subjectType: 'group',
      subjectId: design.id,
      subjectName: 'Design',
    });
    expect(grouped.assignment).not.toHaveProperty('subjectEmail');
    expect(s.changes(grouped.seats).sort()).toEqual(['alice none->active', 'bob none->active']);
    // A direct assignment on top only adds a source.
    const direct = await s.assign(alice.id);
    expect(direct.seats).toEqual([]);
    expect((await licenses.listSeats(owner, { tenantId, identityId: alice.id })).seats).toEqual([
      expect.objectContaining({
        identityName: 'alice',
        identityEmail: 'alice@acme.test',
        identityKind: 'user',
        status: 'active',
        direct: true,
        groupIds: [design.id],
      }),
    ]);

    // Membership changes move seats in the same transaction, whoever writes them.
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: design.id, identityId: carol.id });
    expect((await s.seats()).sort()).toEqual(['alice active', 'bob active', 'carol active']);
    await f.iam.api.groups.removeMember(owner, {
      tenantId,
      groupId: design.id,
      identityId: bob.id,
    });
    await f.iam.api.groups.removeMember(owner, {
      tenantId,
      groupId: design.id,
      identityId: alice.id,
    });
    expect(await s.seats()).toEqual(['alice active', 'carol active']);
    expect(
      (await licenses.listSeats(owner, { tenantId, identityId: alice.id })).seats[0],
    ).toMatchObject({ direct: true, groupIds: [] });
    const release = (await trail(f, tenantId, 'license:seat-release')).at(-1)!;
    expect(release).toMatchObject({
      actorId: f.ownerId,
      resourceId: bob.id,
      metadata: {
        productId: pro.id,
        productKey: 'pro',
        from: 'active',
        to: 'none',
        reason: 'group-membership',
      },
    });

    // A temporary membership ends by itself; the next reconcile releases the seat.
    const erin = await s.person('erin');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: design.id,
      identityId: erin.id,
      expiresAt: f.now() + HOUR,
    });
    expect(await s.seats()).toContain('erin active');
    f.advance(2 * HOUR);
    expect(await f.iam.licenses.reconcile()).toMatchObject({ released: 1 });
    expect(await s.seats()).toEqual(['alice active', 'carol active']);

    // Duplicates and unknown subjects are refused.
    await expect(s.assign(alice.id)).rejects.toMatchObject({ code: 'CONFLICT', status: 409 });
    await expect(s.assign('missing')).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(s.assign(alice.id, 'missing')).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      licenses.assign(owner, {
        tenantId,
        productId: pro.id,
        subjectType: 'group',
        subjectId: 'missing',
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      licenses.assign(owner, {
        tenantId,
        productId: pro.id,
        subjectType: 'team' as never,
        subjectId: alice.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Listing assignments: newest first, filtered and paged.
    const all = await licenses.listAssignments(owner, { tenantId });
    expect(all.total).toBe(2);
    expect(all.assignments.map((assignment) => assignment.subjectName)).toEqual([
      'alice',
      'Design',
    ]);
    expect(
      (await licenses.listAssignments(owner, { tenantId, subjectType: 'group' })).assignments,
    ).toEqual([expect.objectContaining({ subjectId: design.id })]);
    expect(
      await licenses.listAssignments(owner, { tenantId, subjectId: alice.id, productId: pro.id }),
    ).toMatchObject({ total: 1, assignments: [{ id: direct.assignment.id }] });
    expect(await licenses.listAssignments(owner, { tenantId, limit: 1, offset: 1 })).toMatchObject({
      total: 2,
      assignments: [{ subjectName: 'Design' }],
    });
    await expect(
      licenses.listAssignments(owner, { tenantId, subjectType: 'robot' as never }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Unassigning by product and subject, or by ID; seats a remaining assignment covers stay.
    const ungrouped = await licenses.unassign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: design.id,
    });
    expect(s.changes(ungrouped.seats)).toEqual(['carol active->none']);
    await expect(
      licenses.unassign(owner, {
        tenantId,
        productId: pro.id,
        subjectType: 'group',
        subjectId: design.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(
      s.changes(
        (await licenses.unassign(owner, { tenantId, assignmentId: direct.assignment.id })).seats,
      ),
    ).toEqual(['alice active->none']);
    await expect(
      licenses.unassign(owner, { tenantId, assignmentId: direct.assignment.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(licenses.unassign(owner, { tenantId })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    expect(await s.seats()).toEqual([]);
    expect(
      (await trail(f, tenantId, 'license:unassign')).map((event) => [
        event.resourceId,
        event.metadata?.subjectType,
      ]),
    ).toEqual([
      [design.id, 'group'],
      [alice.id, 'identity'],
    ]);
  });

  it('assigns many people at once and releases a deleted group’s seats', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, alice, bob, carol } = s;
    await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 3 });
    await s.assign(bob.id);
    const dave = await s.person('dave');
    f.advance(1000);
    const many = await licenses.assignMany(owner, {
      tenantId,
      productId: pro.id,
      identityIds: [bob.id, dave.id, dave.id, carol.id],
    });
    expect(many.skipped).toEqual([bob.id]);
    expect(many.assigned.map((assignment) => assignment.subjectName)).toEqual(['dave', 'carol']);
    expect(s.changes(many.seats).sort()).toEqual(['carol none->active', 'dave none->active']);
    expect((await trail(f, tenantId, 'license:assign')).map((event) => event.resourceId)).toEqual([
      bob.id,
      dave.id,
      carol.id,
    ]);
    // Nothing new: no seat run, no error.
    await expect(
      licenses.assignMany(owner, { tenantId, productId: pro.id, identityIds: [bob.id] }),
    ).resolves.toEqual({ assigned: [], skipped: [bob.id], seats: [] });
    for (const identityIds of [[], 'x', Array.from({ length: 101 }, (_, index) => `id-${index}`)])
      await expect(
        licenses.assignMany(owner, {
          tenantId,
          productId: pro.id,
          identityIds: identityIds as never,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // One unknown person rejects the whole batch.
    await expect(
      licenses.assignMany(owner, {
        tenantId,
        productId: pro.id,
        identityIds: [alice.id, 'missing'],
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect((await licenses.listAssignments(owner, { tenantId, subjectId: alice.id })).total).toBe(
      0,
    );

    // Deleting a group deletes its license assignments; the seats they carried go.
    const ops = await f.iam.api.groups.create(owner, { tenantId, name: 'Ops' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: ops.id, identityId: alice.id });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: ops.id, identityId: bob.id });
    f.advance(1000);
    const grouped = await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: ops.id,
    });
    expect(s.changes(grouped.seats)).toEqual(['alice none->waiting']);
    await f.iam.api.groups.delete(owner, { tenantId, groupId: ops.id });
    expect((await licenses.listAssignments(owner, { tenantId, subjectType: 'group' })).total).toBe(
      0,
    );
    expect((await s.seats()).sort()).toEqual(['bob active', 'carol active', 'dave active']);
    expect((await trail(f, tenantId, 'license:seat-release')).at(-1)).toMatchObject({
      resourceId: alice.id,
      metadata: { from: 'waiting', reason: 'group-deleted' },
    });
  });
});

describe('license limits', () => {
  it('caps products per tenant, pools per product and assignments per product', async () => {
    const { f, tenantId, owner, licenses, pro, alice } = await scenario();
    const now = f.now();
    await f.iam.store.transaction(async (tx) => {
      for (let index = 1; index < 200; index++)
        await tx.insert('licenseProducts', {
          id: `product-${index}`,
          tenantId,
          uniqueKey: `key:bulk-${index}`,
          key: `bulk-${index}`,
          name: `Bulk ${index}`,
          featureKeys: [],
          status: 'active',
          createdAt: now,
          createdBy: f.ownerId,
          updatedAt: now,
          updatedBy: f.ownerId,
        });
      for (let index = 0; index < 100; index++)
        await tx.insert('licensePools', {
          id: `pool-${index}`,
          tenantId,
          productId: pro.id,
          quantity: 1,
          source: 'manual',
          createdAt: now,
          createdBy: f.ownerId,
        });
      for (let index = 0; index < 10_000; index++)
        await tx.insert('licenseAssignments', {
          id: `assignment-${index}`,
          tenantId,
          uniqueKey: `${pro.id}:identity:ghost-${index}`,
          productId: pro.id,
          subjectType: 'identity',
          subjectId: `ghost-${index}`,
          assignedBy: f.ownerId,
          assignedAt: now,
        });
    });
    await expect(
      licenses.createProduct(owner, { tenantId, key: 'one-more', name: 'One more' }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED', status: 409 });
    await expect(
      licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 1 }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await expect(
      licenses.assign(owner, {
        tenantId,
        productId: pro.id,
        subjectType: 'identity',
        subjectId: alice.id,
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await expect(
      licenses.assignMany(owner, { tenantId, productId: pro.id, identityIds: [alice.id] }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    // Another product has room.
    await expect(
      licenses.addPool(owner, { tenantId, productId: 'product-1', quantity: 1 }),
    ).resolves.toMatchObject({ pool: { productKey: 'bulk-1' } });
  });
});

describe('license settings and self-service', () => {
  it('configures reclaim and waiting-list email', async () => {
    const { f, tenantId, owner, licenses } = await scenario();
    expect(await licenses.getSettings(owner, { tenantId })).toEqual({
      tenantId,
      notifyWaiting: false,
    });
    expect(await licenses.configure(owner, { tenantId, reclaimAfterDays: 30 })).toEqual({
      tenantId,
      reclaimAfterDays: 30,
      notifyWaiting: false,
      updatedAt: f.now(),
      updatedBy: f.ownerId,
    });
    expect(await licenses.configure(owner, { tenantId, notifyWaiting: true })).toMatchObject({
      reclaimAfterDays: 30,
      notifyWaiting: true,
    });
    const cleared = await licenses.configure(owner, { tenantId, reclaimAfterDays: null });
    expect(cleared).toMatchObject({ notifyWaiting: true });
    expect(cleared).not.toHaveProperty('reclaimAfterDays');
    expect(await licenses.getSettings(owner, { tenantId })).toEqual(cleared);
    for (const input of [
      {},
      { reclaimAfterDays: 6 },
      { reclaimAfterDays: 366 },
      { reclaimAfterDays: 7.5 },
      { reclaimAfterDays: '30' },
      { notifyWaiting: 'yes' },
    ])
      await expect(
        licenses.configure(owner, { tenantId, ...input } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect((await trail(f, tenantId, 'license:settings')).map((event) => event.metadata)).toEqual([
      {
        reclaimAfterDays: 30,
        notifyWaiting: false,
        previousReclaimAfterDays: null,
        previousNotifyWaiting: false,
      },
      {
        reclaimAfterDays: 30,
        notifyWaiting: true,
        previousReclaimAfterDays: 30,
        previousNotifyWaiting: false,
      },
      {
        reclaimAfterDays: null,
        notifyWaiting: true,
        previousReclaimAfterDays: 30,
        previousNotifyWaiting: true,
      },
    ]);
  });

  it('shows people their own licenses without auditing the read', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, alice, bob } = s;
    const team = await licenses.createProduct(owner, {
      tenantId,
      key: 'team',
      name: 'Team',
      featureKeys: ['boards', 'sso'],
    });
    await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 1 });
    await licenses.addPool(owner, { tenantId, productId: team.id, quantity: 5 });
    await s.assign(alice.id);
    await s.assign(alice.id, team.id);
    await s.assign(bob.id);
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const asCarol = { token: (await f.signIn('carol')).token };
    expect(await licenses.mine(asAlice, { tenantId })).toEqual({
      tenantId,
      identityId: alice.id,
      licenses: [
        {
          productId: pro.id,
          key: 'pro',
          name: 'Pro',
          description: 'Everything in Pro',
          status: 'active',
          featureKeys: ['exports', 'sso'],
          platform: false,
          definedBy: tenantId,
        },
        {
          productId: team.id,
          key: 'team',
          name: 'Team',
          status: 'active',
          featureKeys: ['boards', 'sso'],
          platform: false,
          definedBy: tenantId,
        },
      ],
      // Acme's own products: their feature keys are not the platform's entitlements.
      featureKeys: [],
      allFeatureKeys: ['boards', 'exports', 'sso'],
    });
    expect(await licenses.mine(asBob, { tenantId })).toEqual({
      tenantId,
      identityId: bob.id,
      licenses: [
        {
          productId: pro.id,
          key: 'pro',
          name: 'Pro',
          description: 'Everything in Pro',
          status: 'waiting',
          position: 1,
          featureKeys: [],
          platform: false,
          definedBy: tenantId,
        },
      ],
      featureKeys: [],
      allFeatureKeys: [],
    });
    expect(await licenses.mine(asCarol, { tenantId })).toEqual({
      tenantId,
      identityId: s.carol.id,
      licenses: [],
      featureKeys: [],
      allFeatureKeys: [],
    });
    const acme = { trustedTenantId: tenantId };
    expect(await f.iam.licenses.features(alice.id, tenantId, acme)).toEqual([
      'boards',
      'exports',
      'sso',
    ]);
    expect(await f.iam.licenses.features(alice.id, tenantId)).toEqual([]);
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual(['pro', 'team']);
    expect(await f.iam.licenses.features(bob.id, tenantId, acme)).toEqual([]);

    const count = async () => (await f.iam.store.find('audit', { tenantId })).length;
    const before = await count();
    await licenses.mine(asAlice, { tenantId });
    expect(await count()).toBe(before);

    // Only the caller's own tenant; administrators of other tenants see nothing of theirs here.
    await expect(licenses.mine(asAlice, { tenantId: f.root.tenant.id })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(licenses.mine({ token: 'not-a-token' }, { tenantId })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(licenses.mine(asAlice, { tenantId: '' })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    expect(await licenses.mine(f.rootCredential, { tenantId })).toMatchObject({
      licenses: [],
      featureKeys: [],
      allFeatureKeys: [],
    });
    expect(await licenses.mine(owner, { tenantId })).toMatchObject({
      identityId: f.ownerId,
      licenses: [],
    });
  });
});
