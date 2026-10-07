import { afterEach, describe, expect, it } from 'vitest';
import { renderDeliveryMessage } from '@better-iam/auth';
import type { AuditEvent } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** Acme with a product "pro" with one seat, alice and bob, and a birthright package for Pro holders. */
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
  const pool = (await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 1 })).pool;
  const alice = await f.member('alice');
  const bob = await f.member('bob');
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
  const assign = async (identityId: string) => {
    f.advance(1000);
    return licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'identity',
      subjectId: identityId,
    });
  };
  const seats = async () =>
    (await licenses.listSeats(owner, { tenantId })).seats.map(
      (seat) =>
        `${seat.identityName} ${seat.status}${seat.position !== undefined ? ` #${seat.position}` : ''}`,
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
  const events = async (action: string) =>
    (await f.iam.store.find<AuditEvent>('audit', { tenantId }))
      .filter((event) => event.action === action)
      .sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
  return {
    f,
    tenantId,
    owner,
    licenses,
    pro,
    pool,
    alice,
    bob,
    pkg,
    assign,
    seats,
    holders,
    events,
  };
}

describe('licenses through the identity lifecycle', () => {
  it('releases a deleted person’s seats and assignments, and the next in line moves up', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, alice, bob } = s;
    const design = await f.iam.api.groups.create(owner, { tenantId, name: 'Design' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: design.id, identityId: alice.id });
    await s.assign(alice.id);
    await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: design.id,
    });
    await s.assign(bob.id);
    expect(await s.seats()).toEqual(['alice active', 'bob waiting #1']);
    expect(await s.holders()).toEqual([alice.id]);

    await f.iam.api.identities.delete(await f.ownerSignIn(), { tenantId, identityId: alice.id });
    expect(await s.seats()).toEqual(['bob active']);
    // Her direct assignment went; the group's stays for its other members.
    expect(
      (await licenses.listAssignments(owner, { tenantId })).assignments.map(
        (assignment) => assignment.subjectName,
      ),
    ).toEqual(['bob', 'Design']);
    expect((await s.events('license:seat-release')).at(-1)).toMatchObject({
      actorId: f.ownerId,
      resourceId: alice.id,
      metadata: { from: 'active', to: 'none', reason: 'identity-deleted' },
    });
    expect((await s.events('license:seat-activate')).at(-1)).toMatchObject({
      resourceId: bob.id,
      metadata: { from: 'waiting', to: 'active', reason: 'identity-deleted' },
    });
    // Birthright packages follow on the next package run.
    await f.iam.reconcilePackages();
    expect(await s.holders()).toEqual([bob.id]);
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual([]);
  });

  it('releases an offboarded person’s seat and hands it, with its package, to the next in line at once', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, alice, bob } = s;
    await s.assign(alice.id);
    await s.assign(bob.id);
    expect(await s.holders()).toEqual([alice.id]);
    await f.iam.api.identities.offboard(await f.ownerSignIn(), {
      tenantId,
      identityId: alice.id,
      reason: 'Left the company',
    });
    expect(await s.seats()).toEqual(['bob active']);
    expect(await s.holders()).toEqual([bob.id]);
    // The assignment stays (reclaim or an administrator removes it); a returning person queues again.
    expect((await licenses.listAssignments(owner, { tenantId, subjectId: alice.id })).total).toBe(
      1,
    );
    expect((await s.events('license:seat-release')).at(-1)).toMatchObject({
      actorId: 'deployment-operator',
      resourceId: alice.id,
      metadata: { reason: 'identity-change' },
    });
    await f.iam.api.identities.setStatus(await f.ownerSignIn(), {
      tenantId,
      identityId: alice.id,
      status: 'active',
    });
    expect(await s.seats()).toEqual(['bob active', 'alice waiting #1']);
  });

  it('gives disabled and expired people no seat', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pool, alice, bob } = s;
    await s.assign(alice.id);
    await s.assign(bob.id);
    const admin = await f.ownerSignIn();
    await f.iam.api.identities.setStatus(admin, {
      tenantId,
      identityId: alice.id,
      status: 'disabled',
    });
    expect(await s.seats()).toEqual(['bob active']);
    expect(await s.holders()).toEqual([alice.id, bob.id].sort());
    // Acme's own product: its feature keys count where Acme is trusted.
    const acme = { trustedTenantId: tenantId };
    expect(await f.iam.licenses.features(alice.id, tenantId, acme)).toEqual([]);
    expect(await f.iam.licenses.features(bob.id, tenantId, acme)).toEqual(['exports']);
    f.advance(1000);
    await f.iam.api.identities.setStatus(admin, {
      tenantId,
      identityId: alice.id,
      status: 'active',
    });
    expect(await s.seats()).toEqual(['bob active', 'alice waiting #1']);

    // A person whose account expires stops counting at once and loses the seat on the next run.
    const carol = await f.member('carol', { expiresAt: f.now() + HOUR });
    await licenses.updatePool(owner, { tenantId, poolId: pool.id, quantity: 3 });
    await s.assign(carol.id);
    expect(await s.seats()).toEqual(['bob active', 'alice active', 'carol active']);
    f.advance(2 * HOUR);
    expect(await f.iam.licenses.features(carol.id, tenantId, acme)).toEqual([]);
    expect(await f.iam.licenses.reconcile()).toEqual({
      tenants: 1,
      activated: 0,
      waiting: 0,
      released: 1,
      failedTenants: [],
    });
    expect(await s.seats()).toEqual(['bob active', 'alice active']);
  });

  it('seats the members of a team whose backing group holds a license, and the teams below it', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, pool, alice, bob } = s;
    await licenses.updatePool(owner, { tenantId, poolId: pool.id, quantity: 5 });
    const platform = await f.iam.api.teams.create(owner, { tenantId, name: 'Platform' });
    const sre = await f.iam.api.teams.create(owner, {
      tenantId,
      name: 'Site Reliability',
      slug: 'sre',
      parentId: platform.id,
    });
    await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: platform.groupId,
    });
    await f.iam.api.teams.addMember(owner, { tenantId, teamId: platform.id, identityId: alice.id });
    await f.iam.api.teams.addMember(owner, { tenantId, teamId: sre.id, identityId: bob.id });
    expect((await s.seats()).sort()).toEqual(['alice active', 'bob active']);
    // Team seats count for birthright rules: the backing group of a counted team is not a package's.
    expect(await s.holders()).toEqual([alice.id, bob.id].sort());
    await f.iam.api.teams.removeMember(owner, { tenantId, teamId: sre.id, identityId: bob.id });
    expect(await s.seats()).toEqual(['alice active']);
    expect(await s.holders()).toEqual([alice.id]);
  });

  it('seats people created straight into a licensed group', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, pool } = s;
    await licenses.updatePool(owner, { tenantId, poolId: pool.id, quantity: 5 });
    const field = await f.iam.api.groups.create(owner, { tenantId, name: 'Field' });
    await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: field.id,
    });
    const created = await f.iam.api.identities.createMany(owner, {
      tenantId,
      identities: [
        { email: 'erin@acme.test', name: 'erin', groupIds: [field.id] },
        { email: 'frank@acme.test', name: 'frank', groupIds: [field.id] },
      ],
    });
    const ids = created.identities.map((identity) => identity.id).sort();
    expect((await s.seats()).sort()).toEqual(['erin active', 'frank active']);
    expect(await s.holders()).toEqual(ids);
  });
});

describe('license jobs', () => {
  it('reconciles only tenants with licenses', async () => {
    const s = await scenario();
    const { f, tenantId, alice } = s;
    expect(await f.iam.licenses.reconcile()).toEqual({
      tenants: 0,
      activated: 0,
      waiting: 0,
      released: 0,
      failedTenants: [],
    });
    await s.assign(alice.id);
    expect(await f.iam.licenses.reconcile()).toMatchObject({ tenants: 1, activated: 0 });
    await expect(f.iam.licenses.reconcile({ tenantId: 'missing' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    // Inconsistent state (a seat nobody claims any more) is repaired.
    await f.iam.store.transaction(async (tx) => {
      for (const row of await tx.find('licenseAssignments', { tenantId }))
        await tx.delete('licenseAssignments', row.id);
    });
    expect(await f.iam.licenses.reconcile({ tenantId })).toMatchObject({ released: 1 });
    expect(await s.seats()).toEqual([]);
    expect(await s.holders()).toEqual([]);
    // Suspended tenants are left alone.
    await s.assign(alice.id);
    await f.iam.store.transaction(async (tx) => {
      for (const row of await tx.find('licenseSeats', { tenantId }))
        await tx.delete('licenseSeats', row.id);
    });
    await f.iam.api.tenants.setStatus(f.rootCredential, { tenantId, status: 'suspended' });
    expect(await f.iam.licenses.reconcile()).toMatchObject({ tenants: 0 });
    expect(await f.iam.licenses.reconcile({ tenantId })).toMatchObject({ tenants: 0 });
  });

  it('reclaims direct assignments of people inactive for the configured time', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, pool, alice, bob } = s;
    await licenses.updatePool(owner, { tenantId, poolId: pool.id, quantity: 10 });
    // Reclaim is off by default.
    expect(await f.iam.licenses.reclaim()).toEqual({
      tenants: 0,
      reclaimed: [],
      failedTenants: [],
    });
    await licenses.configure(owner, { tenantId, reclaimAfterDays: 30 });
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    const erin = await f.member('erin');
    const robot = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'robot' });
    const key = await f.iam.api.credentials.create(owner, { tenantId, identityId: robot.id });
    const field = await f.iam.api.groups.create(owner, { tenantId, name: 'Field' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: field.id, identityId: erin.id });
    await licenses.assign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'group',
      subjectId: field.id,
    });
    await licenses.assignMany(owner, {
      tenantId,
      productId: pro.id,
      identityIds: [alice.id, bob.id, dave.id, robot.id],
    });
    // Day 2: dave is disabled. Day 15: the robot's key is used. Day 20: alice signs in. Day 25: carol gets Pro.
    f.advance(2 * DAY);
    await f.iam.api.identities.setStatus(await f.ownerSignIn(), {
      tenantId,
      identityId: dave.id,
      status: 'disabled',
    });
    f.advance(13 * DAY);
    await licenses.mine({ token: key.token }, { tenantId });
    f.advance(5 * DAY);
    await f.signIn('alice');
    f.advance(5 * DAY);
    const admin = await f.ownerSignIn();
    await licenses.assign(admin, {
      tenantId,
      productId: pro.id,
      subjectType: 'identity',
      subjectId: carol.id,
    });
    f.advance(6 * DAY);
    const current = await f.ownerSignIn();
    // Usage reports inactive active seats, including those held through groups.
    expect((await licenses.usage(current, { tenantId })).products[0]).toMatchObject({
      active: 5,
      reclaimable: 2,
      reclaimableThroughGroups: 1,
    });

    const result = await f.iam.licenses.reclaim();
    expect(result.tenants).toBe(1);
    expect(result.failedTenants).toEqual([]);
    expect(result.reclaimed.map((item) => item.identityId).sort()).toEqual(
      [bob.id, dave.id].sort(),
    );
    expect(result.reclaimed.find((item) => item.identityId === bob.id)).toEqual({
      tenantId,
      productId: pro.id,
      productKey: 'pro',
      identityId: bob.id,
      lastActivityAt: bob.createdAt,
    });
    const held = new Map(
      (await licenses.listSeats(current, { tenantId })).seats.map((seat) => [
        seat.identityId,
        seat,
      ]),
    );
    expect([...held.keys()].sort()).toEqual([alice.id, carol.id, erin.id, robot.id].sort());
    // The pass records what it saw on each seat.
    expect(held.get(alice.id)?.lastActivityAt).toBe(f.now() - 11 * DAY);
    expect(held.get(robot.id)?.lastActivityAt).toBe(f.now() - 16 * DAY);
    expect(held.get(erin.id)?.lastActivityAt).toBe(erin.createdAt);
    expect(
      (await licenses.listAssignments(current, { tenantId, subjectType: 'identity' })).assignments
        .map((assignment) => assignment.subjectId)
        .sort(),
    ).toEqual([alice.id, carol.id, robot.id].sort());
    expect((await licenses.usage(current, { tenantId })).products[0]).toMatchObject({
      active: 4,
      reclaimable: 1,
      reclaimableThroughGroups: 1,
    });
    const reclaims = await s.events('license:reclaim');
    expect(reclaims.map((event) => event.resourceId).sort()).toEqual([bob.id, dave.id].sort());
    expect(reclaims.find((event) => event.resourceId === bob.id)).toMatchObject({
      actorId: 'deployment-operator',
      metadata: {
        productId: pro.id,
        productKey: 'pro',
        lastActivityAt: bob.createdAt,
        reclaimAfterDays: 30,
      },
    });
    expect((await s.events('license:seat-release')).at(-1)).toMatchObject({
      resourceId: bob.id,
      metadata: { reason: 'reclaim' },
    });
    // A second pass finds nothing more; turning reclaim off stops it.
    expect((await f.iam.licenses.reclaim({ tenantId })).reclaimed).toEqual([]);
    await licenses.configure(current, { tenantId, reclaimAfterDays: null });
    expect(await f.iam.licenses.reclaim({ tenantId })).toEqual({
      tenants: 0,
      reclaimed: [],
      failedTenants: [],
    });
    expect(await f.iam.licenses.reclaim()).toEqual({
      tenants: 0,
      reclaimed: [],
      failedTenants: [],
    });
    expect(await f.iam.licenses.reclaim({ tenantId: 'missing' })).toMatchObject({
      tenants: 0,
      failedTenants: [expect.objectContaining({ tenantId: 'missing', code: 'NOT_FOUND' })],
    });
  });
});

describe('license notifications and retention', () => {
  it('emails people when they join the waiting list and when their seat is ready, when asked to', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro, alice, bob } = s;
    const mail = async () => {
      await f.iam.auth.dispatchOutbox();
      return f.inbox.filter((message) => message.template.startsWith('license-'));
    };
    await s.assign(alice.id);
    await s.assign(bob.id);
    expect(await mail()).toEqual([]);
    await licenses.configure(owner, { tenantId, notifyWaiting: true });
    const carol = await f.member('carol');
    await s.assign(carol.id);
    const robot = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'robot' });
    await s.assign(robot.id);
    const waiting = await mail();
    expect(waiting).toEqual([
      expect.objectContaining({
        tenantId,
        to: 'carol@acme.test',
        template: 'license-waiting',
        payload: { tenantId, tenantName: 'Acme', productKey: 'pro', productName: 'Pro' },
      }),
    ]);
    expect(renderDeliveryMessage(waiting[0]!)!.subject).toBe('You are on the waiting list for Pro');
    await licenses.unassign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const all = await mail();
    expect(all.map((message) => [message.to, message.template])).toEqual([
      ['carol@acme.test', 'license-waiting'],
      ['bob@acme.test', 'license-activated'],
    ]);
    expect(renderDeliveryMessage(all[1]!)!.subject).toBe('Your Pro seat is ready');
    expect(await s.seats()).toEqual(['bob active', 'carol waiting #1', 'robot waiting #2']);
  });

  it('removes a tenant’s license records when the tenant is purged', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro } = s;
    const created = await f.iam.api.tenants.create(owner, {
      parentId: tenantId,
      name: 'Apollo',
      type: 'project',
      ownerEmail: 'apollo@acme.test',
    });
    const apolloId = created.tenant.id;
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find(
      (message) => message.tenantId === apolloId && message.template === 'owner-invitation',
    )!;
    const accepted = await f.iam.api.tenants.acceptInvitation({
      tenantId: apolloId,
      token: invitation.payload.token!,
      name: 'Apollo owner',
      password: 'a strong Apollo owner password',
    });
    if (!('token' in accepted)) throw new Error('Unexpected MFA');
    const apollo = { token: accepted.token };
    const apolloOwner = (await f.iam.api.auth.getSession(apollo)).identity.id;
    const addon = await licenses.createProduct(apollo, {
      tenantId: apolloId,
      key: 'addon',
      name: 'Add-on',
    });
    await licenses.addPool(apollo, { tenantId: apolloId, productId: addon.id, quantity: 1 });
    await licenses.addPool(owner, { tenantId: apolloId, productId: pro.id, quantity: 1 });
    for (const productId of [addon.id, pro.id])
      await licenses.assign(apollo, {
        tenantId: apolloId,
        productId,
        subjectType: 'identity',
        subjectId: apolloOwner,
      });
    await licenses.configure(apollo, { tenantId: apolloId, notifyWaiting: true });
    const collections = [
      'licenseProducts',
      'licensePools',
      'licenseAssignments',
      'licenseSeats',
      'licenseSettings',
    ];
    const count = async (id: string) => {
      const counts: Record<string, number> = {};
      for (const collection of collections)
        counts[collection] = (await f.iam.store.find(collection, { tenantId: id })).length;
      return counts;
    };
    expect(await count(apolloId)).toEqual({
      licenseProducts: 1,
      licensePools: 2,
      licenseAssignments: 2,
      licenseSeats: 2,
      licenseSettings: 1,
    });
    const acmeBefore = await count(tenantId);
    await f.iam.api.tenants.setStatus(f.rootCredential, { tenantId: apolloId, status: 'deleted' });
    const purge = await f.iam.purgeDeleted({ retentionMs: 0 });
    expect(purge.purgedTenants).toContain(apolloId);
    expect(await count(apolloId)).toEqual({
      licenseProducts: 0,
      licensePools: 0,
      licenseAssignments: 0,
      licenseSeats: 0,
      licenseSettings: 0,
    });
    expect(await count(tenantId)).toEqual(acmeBefore);
  });
});
