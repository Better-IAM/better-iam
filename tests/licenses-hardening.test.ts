import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, IamStore } from '@better-iam/core';
import { createScimService } from '@better-iam/scim';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

/**
 * Review fixes for license management: keys an enclosing tenant defines win, seats follow every membership writer
 * (team sync, invitations, SCIM) in the same transaction, membership of licensed groups needs iam:licenses:assign,
 * moved tenants and retired products hold nothing, and batches reconcile each product once.
 */

afterEach(closeFixtures);

const DAY = 86_400_000;
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';

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

/** Acme with a product "pro" of `quantity` seats. */
async function scenario(quantity = 5) {
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
  const pool = (await licenses.addPool(owner, { tenantId, productId: pro.id, quantity })).pool;
  const names = new Map<string, string>();
  const person = async (name: string) => {
    const identity = await f.member(name);
    names.set(identity.id, name);
    return identity;
  };
  const seats = async (productId = pro.id, credential = owner, inTenant = tenantId) =>
    (await licenses.listSeats(credential, { tenantId: inTenant, productId })).seats.map(
      (seat) =>
        `${seat.identityName} ${seat.status}${seat.position !== undefined ? ` #${seat.position}` : ''}`,
    );
  const assign = async (subjectId: string, subjectType: 'identity' | 'group' = 'identity') => {
    f.advance(1000);
    return licenses.assign(owner, { tenantId, productId: pro.id, subjectType, subjectId });
  };
  const events = async (action: string, inTenant = tenantId) =>
    (await f.iam.store.find<AuditEvent>('audit', { tenantId: inTenant }))
      .filter((event) => event.action === action)
      .sort((a, b) => (a.sequence ?? 0) - (b.sequence ?? 0));
  /** A person holding a role with `permissions`, signed in. */
  const staff = async (name: string, permissions: string[]) => {
    const identity = await person(name);
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
    return { identity, credential: { token: (await f.signIn(name)).token } };
  };
  return { f, tenantId, owner, licenses, pro, pool, person, seats, assign, events, staff };
}

describe('license keys', () => {
  it('lets the platform’s product win a key a tenant defined first, so self-issued seats never count as it', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses } = s;
    const rootId = f.root.tenant.id;
    // Acme pre-registers a guessable key and gives itself plenty of seats.
    const squatted = await licenses.createProduct(owner, {
      tenantId,
      key: 'enterprise',
      name: 'Our enterprise',
      featureKeys: ['premium-api'],
    });
    await licenses.addPool(owner, { tenantId, productId: squatted.id, quantity: 1_000_000 });
    const alice = await s.person('alice');
    await licenses.assign(owner, {
      tenantId,
      productId: squatted.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Enterprise reader',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['*'],
            conditions: { ArrayContains: { 'principal.licenses': 'enterprise' } },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Enterprise wiki' });
    const pkg = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Enterprise tools',
      groupIds: [wiki.id],
      autoAssign: {
        include: [
          {
            StringEquals: { 'principal.kind': 'user' },
            ArrayContains: { 'identity.licenses': ['enterprise'] },
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
    await f.iam.reconcilePackages();
    const asAlice = { token: (await f.signIn('alice')).token };
    const canRead = async () =>
      (
        await f.iam.authorize({
          ...asAlice,
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'd1' },
        })
      ).allowed;
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual(['enterprise']);
    expect(await canRead()).toBe(true);
    expect(await holders()).toEqual([alice.id]);

    // The platform launches the key later: its product wins and Acme's self-issued seats stop counting at once.
    const platform = await licenses.createProduct(f.rootCredential, {
      tenantId: rootId,
      key: 'enterprise',
      name: 'Enterprise',
      featureKeys: ['enterprise-support'],
    });
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual([]);
    expect(
      await f.iam.licenses.features(alice.id, tenantId, { trustedTenantId: tenantId }),
    ).toEqual([]);
    expect(await canRead()).toBe(false);
    expect(await licenses.mine(asAlice, { tenantId })).toMatchObject({
      licenses: [],
      featureKeys: [],
      allFeatureKeys: [],
    });
    await f.iam.reconcilePackages();
    expect(await holders()).toEqual([]);
    expect(
      (await licenses.listProducts(owner, { tenantId })).products
        .filter((product) => product.key === 'enterprise')
        .map((product) => [product.definedBy, product.shadowed]),
    ).toEqual([
      [rootId, false],
      [tenantId, true],
    ]);
    // The seats stay (Acme's administrators move people over or unassign them); they just grant nothing.
    expect(await s.seats(squatted.id)).toEqual(['alice active']);

    // Seats the platform grants count as the key.
    await licenses.addPool(f.rootCredential, { tenantId, productId: platform.id, quantity: 1 });
    await licenses.assign(owner, {
      tenantId,
      productId: platform.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual(['enterprise']);
    expect(await f.iam.licenses.features(alice.id, tenantId)).toEqual(['enterprise-support']);
    expect(await canRead()).toBe(true);
    expect(await holders()).toEqual([alice.id]);
  });

  it('stops granting a product to a tenant moved out from under its definer, and lets the definer take its pool back', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro } = s;
    const rootId = f.root.tenant.id;
    const apollo = await tenant(f, owner, tenantId, 'Apollo', 'project');
    const pool = (
      await licenses.addPool(owner, { tenantId: apollo.tenantId, productId: pro.id, quantity: 3 })
    ).pool;
    await licenses.assign(apollo.credential, {
      tenantId: apollo.tenantId,
      productId: pro.id,
      subjectType: 'identity',
      subjectId: apollo.ownerId,
    });
    expect(await f.iam.licenses.products(apollo.ownerId, apollo.tenantId)).toEqual(['pro']);

    const globex = await tenant(f, f.rootCredential, rootId, 'Globex', 'organization');
    await f.iam.api.tenants.reparent(f.rootCredential, {
      tenantId: apollo.tenantId,
      parentId: globex.tenantId,
    });
    // At once: Acme's product is no longer Apollo's to use.
    expect(await f.iam.licenses.products(apollo.ownerId, apollo.tenantId)).toEqual([]);
    expect(
      await f.iam.licenses.features(apollo.ownerId, apollo.tenantId, { trustedTenantId: tenantId }),
    ).toEqual([]);
    // The next reconcile releases the seat; the assignment stays as history.
    expect(await f.iam.licenses.reconcile({ tenantId: apollo.tenantId })).toMatchObject({
      tenants: 1,
      released: 1,
    });
    expect(await f.iam.store.find('licenseSeats', { tenantId: apollo.tenantId })).toEqual([]);
    expect(
      await f.iam.store.find('licenseAssignments', { tenantId: apollo.tenantId }),
    ).toHaveLength(1);
    expect(await f.iam.licenses.reconcile({ tenantId: apollo.tenantId })).toMatchObject({
      released: 0,
      activated: 0,
    });

    // Acme still lists the pool it granted and may remove it, but no longer add or change capacity there.
    expect(
      (await licenses.listPools(owner, { tenantId })).pools.map((item) => item.tenantName),
    ).toContain('Apollo');
    await expect(
      licenses.updatePool(owner, { tenantId: apollo.tenantId, poolId: pool.id, quantity: 5 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      licenses.addPool(owner, { tenantId: apollo.tenantId, productId: pro.id, quantity: 1 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      licenses.removePool(owner, { tenantId: apollo.tenantId, poolId: pool.id }),
    ).resolves.toEqual({ removed: true, seats: [] });
    expect(await f.iam.store.find('licensePools', { tenantId: apollo.tenantId })).toEqual([]);
    expect((await s.events('license:pool-remove', apollo.tenantId)).at(-1)).toMatchObject({
      actorId: f.ownerId,
      resourceId: `licenses/pools/${pool.id}`,
    });
  });
});

describe('license seats and group membership writers', () => {
  it('asks for iam:licenses:assign to change the members of a licensed group', async () => {
    const s = await scenario();
    const { f, tenantId, owner } = s;
    const helpdesk = await s.staff('helpdesk', ['iam:groups:update', 'iam:groups:read']);
    const proUsers = await f.iam.api.groups.create(owner, { tenantId, name: 'Pro users' });
    const plain = await f.iam.api.groups.create(owner, { tenantId, name: 'Plain' });
    await s.assign(proUsers.id, 'group');
    const join = (groupId: string) =>
      f.iam.api.groups.addMember(helpdesk.credential, {
        tenantId,
        groupId,
        identityId: helpdesk.identity.id,
      });
    await expect(join(proUsers.id)).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    expect(await f.iam.licenses.products(helpdesk.identity.id, tenantId)).toEqual([]);
    expect(await s.seats()).toEqual([]);
    expect((await s.events('iam:groups:update')).at(-1)).toMatchObject({
      actorId: helpdesk.identity.id,
      outcome: 'deny',
    });
    // Groups without products are theirs to manage as before.
    await expect(join(plain.id)).resolves.toMatchObject({ groupId: plain.id });
    // A group that syncs into a team whose backing group (or one above it) holds a product counts as licensed.
    const platform = await f.iam.api.teams.create(owner, { tenantId, name: 'Platform' });
    const directory = await f.iam.api.groups.create(owner, { tenantId, name: 'Directory design' });
    await f.iam.api.teams.create(owner, {
      tenantId,
      name: 'Design',
      parentId: platform.id,
      syncGroupIds: [directory.id],
    });
    await s.assign(platform.groupId, 'group');
    await expect(join(directory.id)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Extending someone's stay in a licensed group is changing its members as well.
    const bob = await s.person('bob');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: proUsers.id,
      identityId: bob.id,
      expiresAt: f.now() + DAY,
    });
    await expect(
      f.iam.api.groups.updateMember(helpdesk.credential, {
        tenantId,
        groupId: proUsers.id,
        identityId: bob.id,
        expiresAt: null,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // With iam:licenses:assign the same call goes through, and the seat follows at once.
    const assigner = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Assigner',
      permissions: ['iam:licenses:assign'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: assigner.id,
      subjectType: 'identity',
      subjectId: helpdesk.identity.id,
    });
    await expect(join(proUsers.id)).resolves.toMatchObject({ groupId: proUsers.id });
    expect(await f.iam.licenses.products(helpdesk.identity.id, tenantId)).toEqual(['pro']);

    // Rules on identity.licenses warn about who else changes a licensed group's members.
    const pkg = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Pro tools',
      groupIds: [plain.id],
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
      expect.stringContaining(
        "whoever manages the members of a group a product is assigned to without it (a team's maintainers, directory sync)",
      ),
    );
  });

  it('seats people team sync puts into a licensed team’s backing group, and releases them when they leave', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses } = s;
    const org = await licenses.createProduct(owner, { tenantId, key: 'org', name: 'Org-wide' });
    await licenses.addPool(owner, { tenantId, productId: org.id, quantity: 5 });
    const platform = await f.iam.api.teams.create(owner, { tenantId, name: 'Platform' });
    const directory = await f.iam.api.groups.create(owner, { tenantId, name: 'Directory design' });
    const design = await f.iam.api.teams.create(owner, {
      tenantId,
      name: 'Design',
      parentId: platform.id,
      syncGroupIds: [directory.id],
    });
    // Pro through the synced team's own backing group, Org-wide through the team above it.
    await s.assign(design.groupId, 'group');
    await licenses.assign(owner, {
      tenantId,
      productId: org.id,
      subjectType: 'group',
      subjectId: platform.groupId,
    });
    const alice = await s.person('alice');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: directory.id,
      identityId: alice.id,
    });
    expect(await s.seats()).toEqual(['alice active']);
    expect(await s.seats(org.id)).toEqual(['alice active']);
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual(['org', 'pro']);
    expect((await s.events('license:seat-activate')).at(-1)).toMatchObject({
      actorId: f.ownerId,
      resourceId: alice.id,
      metadata: { reason: 'group-membership' },
    });

    // Leaving the source group takes the person out of the team, and the seats go in the same call.
    await f.iam.api.groups.removeMember(owner, {
      tenantId,
      groupId: directory.id,
      identityId: alice.id,
    });
    expect(await s.seats()).toEqual([]);
    expect(await s.seats(org.id)).toEqual([]);
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual([]);
  });

  it('seats a member who accepts an invitation into a licensed group', async () => {
    const s = await scenario();
    const { f, tenantId, owner } = s;
    const licensed = await f.iam.api.groups.create(owner, { tenantId, name: 'Licensed' });
    await s.assign(licensed.id, 'group');
    await f.iam.api.identities.invite(owner, {
      tenantId,
      email: 'dave@acme.test',
      name: 'dave',
      groupIds: [licensed.id],
    });
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find(
      (message) => message.template === 'member-invitation' && message.to === 'dave@acme.test',
    )!;
    const accepted = await f.iam.api.identities.acceptInvitation({
      tenantId,
      token: invitation.payload.token!,
      password: 'a strong dave password',
    });
    if (!('token' in accepted)) throw new Error('Unexpected MFA');
    expect(await s.seats()).toEqual(['dave active']);
    expect(await f.iam.licenses.products(accepted.identity.id, tenantId)).toEqual(['pro']);
    expect((await s.events('license:seat-activate')).at(-1)).toMatchObject({
      actorId: f.ownerId,
      resourceId: accepted.identity.id,
      metadata: { reason: 'group-membership' },
    });
  });

  it('reconciles each product once for a batch of new members', async () => {
    const s = await scenario(10);
    const { f, tenantId, owner, pro } = s;
    const staff = await f.iam.api.groups.create(owner, { tenantId, name: 'All staff' });
    await s.assign(staff.id, 'group');
    const people = [];
    for (let index = 0; index < 12; index++) people.push(await s.person(`person${index}`));
    // Count the seat runs of the product (each reads its seats once) inside the batch's transaction.
    const database = f.database as IamStore;
    const original = database.transaction.bind(database);
    let runs = 0;
    database.transaction = (<T>(fn: (tx: IamStore) => Promise<T>) =>
      original((tx) =>
        fn(
          new Proxy(tx, {
            get(target, property) {
              const value = Reflect.get(target, property, target) as unknown;
              if (property === 'find')
                return (
                  collection: string,
                  filter?: Record<string, unknown>,
                  options?: unknown,
                ) => {
                  if (collection === 'licenseSeats' && filter?.productId === pro.id) runs++;
                  return (value as IamStore['find']).call(
                    target,
                    collection,
                    filter as never,
                    options as never,
                  );
                };
              return typeof value === 'function' ? value.bind(target) : value;
            },
          }),
        ),
      )) as IamStore['transaction'];
    try {
      await f.iam.api.groups.addMembers(owner, {
        tenantId,
        groupId: staff.id,
        identityIds: people.map((identity) => identity.id),
      });
    } finally {
      database.transaction = original;
    }
    expect(runs).toBe(1);
    const seats = await s.seats();
    expect(seats.filter((seat) => seat.endsWith(' active'))).toHaveLength(10);
    expect(seats.filter((seat) => seat.includes(' waiting #'))).toHaveLength(2);
  });
});

describe('license reclaim', () => {
  it('leaves the assignments of retired products alone', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses, pro } = s;
    const legacy = await licenses.createProduct(owner, { tenantId, key: 'legacy', name: 'Legacy' });
    await licenses.addPool(owner, { tenantId, productId: legacy.id, quantity: 5 });
    const alice = await s.person('alice');
    await s.assign(alice.id);
    await licenses.assign(owner, {
      tenantId,
      productId: legacy.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    await licenses.configure(owner, { tenantId, reclaimAfterDays: 30 });
    await licenses.retireProduct(await f.ownerSignIn(), { tenantId, productId: legacy.id });
    f.advance(31 * DAY);
    const result = await f.iam.licenses.reclaim({ tenantId });
    expect(result.failedTenants).toEqual([]);
    expect(result.reclaimed.map((item) => [item.identityId, item.productKey])).toEqual([
      [alice.id, 'pro'],
    ]);
    const admin = await f.ownerSignIn();
    expect(
      (await licenses.listAssignments(admin, { tenantId, productId: legacy.id })).assignments.map(
        (assignment) => assignment.subjectId,
      ),
    ).toEqual([alice.id]);
    expect((await licenses.listAssignments(admin, { tenantId, productId: pro.id })).total).toBe(0);
    expect((await s.events('license:reclaim')).map((event) => event.metadata?.productKey)).toEqual([
      'pro',
    ]);
  });
});

describe('licenses and SCIM provisioning', () => {
  async function directory(s: Awaited<ReturnType<typeof scenario>>) {
    const service = createScimService({ ...s.f.iam.protocolHost });
    const connection = await service.createConnection(s.owner, {
      tenantId: s.tenantId,
      name: 'Directory',
    });
    const request = async (resource: string, method = 'GET', body?: unknown) =>
      (await service.handler(
        new Request(`https://iam.test${connection.path}/${resource}`, {
          method,
          headers: {
            authorization: `Bearer ${connection.token}`,
            'content-type': 'application/scim+json',
          },
          body: body === undefined ? undefined : JSON.stringify(body),
        }),
      ))!;
    const user = async (userName: string) => {
      const created = (await (
        await request('Users', 'POST', { userName, active: true })
      ).json()) as {
        id: string;
      };
      const link = await s.f.database.get<{ identityId: string }>('scimUsers', created.id);
      return { scimId: created.id, identityId: link!.identityId };
    };
    return { request, user };
  }

  it('moves seats as soon as the directory deactivates, reactivates or deletes a person', async () => {
    const s = await scenario(1);
    const { f, tenantId, owner, licenses, pro } = s;
    const scim = await directory(s);
    const alice = await scim.user('alice@acme.test');
    const bob = await s.person('bob');
    await s.assign(alice.identityId);
    await s.assign(bob.id);
    expect(await s.seats()).toEqual(['alice@acme.test active', 'bob waiting #1']);
    const active = (value: boolean) => ({
      schemas: [PATCH],
      Operations: [{ op: 'replace', path: 'active', value }],
    });
    expect((await scim.request(`Users/${alice.scimId}`, 'PATCH', active(false))).status).toBe(200);
    expect(await s.seats()).toEqual(['bob active']);
    expect((await s.events('license:seat-release')).at(-1)).toMatchObject({
      actorId: 'directory-sync',
      resourceId: alice.identityId,
      metadata: { reason: 'identity-change' },
    });
    expect((await scim.request(`Users/${alice.scimId}`, 'PATCH', active(true))).status).toBe(200);
    expect(await s.seats()).toEqual(['bob active', 'alice@acme.test waiting #1']);
    await licenses.unassign(owner, {
      tenantId,
      productId: pro.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    expect(await s.seats()).toEqual(['alice@acme.test active']);
    const carol = await s.person('carol');
    await s.assign(carol.id);
    // DELETE releases a seat held through a direct assignment too, not only those of the SCIM groups.
    expect((await scim.request(`Users/${alice.scimId}`, 'DELETE')).status).toBe(204);
    expect(await s.seats()).toEqual(['carol active']);
    expect(await f.iam.licenses.products(alice.identityId, tenantId)).toEqual([]);
  });

  it('removes a deleted directory group’s license assignments with it', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licenses } = s;
    const scim = await directory(s);
    const alice = await scim.user('alice@acme.test');
    const created = (await (
      await scim.request('Groups', 'POST', {
        displayName: 'Designers',
        members: [{ value: alice.scimId }],
      })
    ).json()) as { id: string };
    const groupId = (await f.database.get<{ groupId: string }>('scimGroups', created.id))!.groupId;
    await s.assign(groupId, 'group');
    expect(await s.seats()).toEqual(['alice@acme.test active']);
    expect((await scim.request(`Groups/${created.id}`, 'DELETE')).status).toBe(204);
    expect(await f.iam.store.get('groups', groupId)).toBeUndefined();
    expect(await s.seats()).toEqual([]);
    expect((await licenses.listAssignments(owner, { tenantId, subjectType: 'group' })).total).toBe(
      0,
    );
    expect((await licenses.usage(owner, { tenantId })).products[0]).toMatchObject({
      key: 'pro',
      assignments: 0,
      active: 0,
    });
    expect((await s.events('license:seat-release')).at(-1)).toMatchObject({
      actorId: 'directory-sync',
      resourceId: alice.identityId,
    });
  });
});
