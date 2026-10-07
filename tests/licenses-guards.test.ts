import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import { createScimService } from '@better-iam/scim';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { guestPassword, invitationToken, redeemGuest } from './support/guests.js';

/**
 * License guards: which feature keys application code may trust (`iam.licenses.features` counts platform products by
 * default, `trustedTenantId` widens it, `licenses.mine` says who defined each product), and who may claim a seat by
 * putting people into a licensed group. Every writer asks for iam:licenses:assign (identities, invitations and their
 * resending, guests and their conversion for good, access packages and their rules, onboarding completion groups, the
 * teams API and configuration sync for administrators); team maintainers, directory sync, and renewing a guest (which
 * moves only what the invitation granted) are the documented exemptions.
 */

afterEach(closeFixtures);

const DAY = 86_400_000;
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const ceiling = {
  version: 1 as const,
  statements: [{ effect: 'allow' as const, actions: ['documents:*'], resources: ['*'] }],
};

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

/** Acme with its own product "pro" (5 seats), assigned to the group "Licensed". */
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
  await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 5 });
  const licensed = await f.iam.api.groups.create(owner, { tenantId, name: 'Licensed' });
  const plain = await f.iam.api.groups.create(owner, { tenantId, name: 'Plain' });
  await licenses.assign(owner, {
    tenantId,
    productId: pro.id,
    subjectType: 'group',
    subjectId: licensed.id,
  });
  /** A person holding a role with `permissions` (and a grant authority when asked), signed in. */
  const staff = async (name: string, permissions: string[], authority = false) => {
    const identity = await f.member(name);
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
    if (authority)
      await f.iam.api.authorities.create(owner, { tenantId, identityId: identity.id, ceiling });
    return { identity, credential: { token: (await f.signIn(name)).token } };
  };
  /** Gives someone iam:licenses:assign. */
  const mayAssign = async (identityId: string) => {
    const role = await f.iam.api.roles.create(owner, {
      tenantId,
      name: `Assigner ${identityId}`,
      permissions: ['iam:licenses:assign'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: identityId,
    });
  };
  /** How many times `actorId` was refused `action` in Acme. */
  const denials = async (actorId: string, action: string) =>
    (await f.iam.store.find<AuditEvent>('audit', { tenantId })).filter(
      (event) => event.actorId === actorId && event.action === action && event.outcome === 'deny',
    ).length;
  const seats = async (credential: { token: string } = owner) =>
    (await licenses.listSeats(credential, { tenantId, productId: pro.id })).seats
      .map((seat) => `${seat.identityName} ${seat.status}`)
      .sort();
  const refused = { code: 'ACCESS_DENIED', status: 403 };
  return {
    f,
    tenantId,
    owner,
    licenses,
    pro,
    licensed,
    plain,
    staff,
    mayAssign,
    denials,
    seats,
    refused,
  };
}

describe('feature keys and whose products to trust', () => {
  it('counts platform products by default, and a tenant’s own products only where that tenant is trusted', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const licenses = f.iam.api.licenses;
    const rootId = f.root.tenant.id;
    // The platform sells premium-api; Acme mints a product of its own listing the same feature key.
    const enterprise = await licenses.createProduct(f.rootCredential, {
      tenantId: rootId,
      key: 'enterprise',
      name: 'Enterprise',
      featureKeys: ['premium-api'],
    });
    await licenses.addPool(f.rootCredential, { tenantId, productId: enterprise.id, quantity: 1 });
    const homebrew = await licenses.createProduct(owner, {
      tenantId,
      key: 'homebrew',
      name: 'Homebrew',
      featureKeys: ['premium-api', 'dark-mode'],
    });
    await licenses.addPool(owner, { tenantId, productId: homebrew.id, quantity: 1_000 });
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const give = (productId: string, identityId: string) =>
      licenses.assign(owner, {
        tenantId,
        productId,
        subjectType: 'identity',
        subjectId: identityId,
      });
    await give(homebrew.id, alice.id);
    await give(enterprise.id, bob.id);

    // Acme's self-issued seat unlocks nothing the platform sells.
    expect(await f.iam.licenses.features(alice.id, tenantId)).toEqual([]);
    expect(await f.iam.licenses.features(alice.id, tenantId, {})).toEqual([]);
    expect(await f.iam.licenses.features(bob.id, tenantId)).toEqual(['premium-api']);
    // An application that sells Acme's own products trusts Acme (and the tenants above it).
    const acme = { trustedTenantId: tenantId };
    expect(await f.iam.licenses.features(alice.id, tenantId, acme)).toEqual([
      'dark-mode',
      'premium-api',
    ]);
    expect(await f.iam.licenses.features(bob.id, tenantId, acme)).toEqual(['premium-api']);
    expect(await f.iam.licenses.features(alice.id, tenantId, { trustedTenantId: rootId })).toEqual(
      [],
    );
    // principal.licenses and iam.licenses.products name every product that counts in the tenant, as before.
    expect(await f.iam.licenses.products(alice.id, tenantId)).toEqual(['homebrew']);

    // A project below Acme: Acme grants it Homebrew seats, and it defines a product of its own.
    const apollo = await tenant(f, owner, tenantId, 'Apollo', 'project');
    await licenses.addPool(owner, {
      tenantId: apollo.tenantId,
      productId: homebrew.id,
      quantity: 2,
    });
    const extra = await licenses.createProduct(apollo.credential, {
      tenantId: apollo.tenantId,
      key: 'apollo-extra',
      name: 'Apollo extra',
      featureKeys: ['apollo-reports'],
    });
    await licenses.addPool(apollo.credential, {
      tenantId: apollo.tenantId,
      productId: extra.id,
      quantity: 2,
    });
    for (const productId of [homebrew.id, extra.id])
      await licenses.assign(apollo.credential, {
        tenantId: apollo.tenantId,
        productId,
        subjectType: 'identity',
        subjectId: apollo.ownerId,
      });
    const inApollo = (trustedTenantId?: string) =>
      f.iam.licenses.features(
        apollo.ownerId,
        apollo.tenantId,
        trustedTenantId === undefined ? undefined : { trustedTenantId },
      );
    expect(await inApollo()).toEqual([]);
    // Trusting Acme counts Acme's product but never the project's own, which the project could list anything in.
    expect(await inApollo(tenantId)).toEqual(['dark-mode', 'premium-api']);
    expect(await inApollo(apollo.tenantId)).toEqual(['apollo-reports', 'dark-mode', 'premium-api']);
    // A tenant elsewhere in the tree shares only the platform with Apollo.
    const globex = await tenant(f, f.rootCredential, rootId, 'Globex', 'organization');
    expect(await inApollo(globex.tenantId)).toEqual([]);

    await expect(
      f.iam.licenses.features(alice.id, tenantId, { trustedTenantId: 'no-such-tenant' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.licenses.features(alice.id, tenantId, { trustedTenantId: '' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('shows people in licenses.mine who defined each product and which feature keys are the platform’s', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const licenses = f.iam.api.licenses;
    const rootId = f.root.tenant.id;
    const enterprise = await licenses.createProduct(f.rootCredential, {
      tenantId: rootId,
      key: 'enterprise',
      name: 'Enterprise',
      featureKeys: ['premium-api'],
    });
    await licenses.addPool(f.rootCredential, { tenantId, productId: enterprise.id, quantity: 1 });
    const homebrew = await licenses.createProduct(owner, {
      tenantId,
      key: 'homebrew',
      name: 'Homebrew',
      featureKeys: ['premium-api', 'dark-mode'],
    });
    await licenses.addPool(owner, { tenantId, productId: homebrew.id, quantity: 5 });
    const alice = await f.member('alice');
    for (const productId of [enterprise.id, homebrew.id])
      await licenses.assign(owner, {
        tenantId,
        productId,
        subjectType: 'identity',
        subjectId: alice.id,
      });
    const asAlice = { token: (await f.signIn('alice')).token };
    expect(await licenses.mine(asAlice, { tenantId })).toEqual({
      tenantId,
      identityId: alice.id,
      licenses: [
        {
          productId: enterprise.id,
          key: 'enterprise',
          name: 'Enterprise',
          status: 'active',
          featureKeys: ['premium-api'],
          platform: true,
          definedBy: rootId,
        },
        {
          productId: homebrew.id,
          key: 'homebrew',
          name: 'Homebrew',
          status: 'active',
          featureKeys: ['dark-mode', 'premium-api'],
          platform: false,
          definedBy: tenantId,
        },
      ],
      featureKeys: ['premium-api'],
      allFeatureKeys: ['dark-mode', 'premium-api'],
    });

    // Without the platform seat, Acme's product alone unlocks no platform feature key, whatever it lists.
    await licenses.unassign(owner, {
      tenantId,
      productId: enterprise.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    expect(await licenses.mine(asAlice, { tenantId })).toMatchObject({
      licenses: [expect.objectContaining({ key: 'homebrew', platform: false })],
      featureKeys: [],
      allFeatureKeys: ['dark-mode', 'premium-api'],
    });
    expect(await f.iam.licenses.features(alice.id, tenantId)).toEqual([]);
  });
});

describe('who may claim a seat', () => {
  it('asks identities.createMany and identities.invite for iam:licenses:assign, and re-checks at acceptance', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licensed, plain } = s;
    const onboarder = await s.staff(
      'onboarder',
      ['iam:identities:create', 'iam:groups:update'],
      true,
    );
    const createMany = (groupId: string, name: string) =>
      f.iam.api.identities.createMany(onboarder.credential, {
        tenantId,
        identities: [{ email: `${name}@acme.test`, name, groupIds: [groupId] }],
      });
    await expect(createMany(licensed.id, 'erin')).rejects.toMatchObject(s.refused);
    expect(await s.denials(onboarder.identity.id, 'iam:identities:create')).toBe(1);
    expect(await f.iam.store.find('identities', { tenantId, email: 'erin@acme.test' })).toEqual([]);
    await expect(createMany(plain.id, 'frank')).resolves.toMatchObject({
      identities: [expect.objectContaining({ email: 'frank@acme.test' })],
    });

    const invite = (groupId: string, address: string) =>
      f.iam.api.identities.invite(onboarder.credential, {
        tenantId,
        email: address,
        name: address.split('@')[0],
        groupIds: [groupId],
      });
    await expect(invite(licensed.id, 'gail@acme.test')).rejects.toMatchObject(s.refused);
    expect(await s.denials(onboarder.identity.id, 'iam:identities:create')).toBe(2);

    // An invitation sent into a group that carries seats only later is refused at acceptance.
    await invite(plain.id, 'hank@acme.test');
    await s.licenses.assign(owner, {
      tenantId,
      productId: s.pro.id,
      subjectType: 'group',
      subjectId: plain.id,
    });
    await f.iam.auth.dispatchOutbox();
    const message = f.inbox.find(
      (item) => item.template === 'member-invitation' && item.to === 'hank@acme.test',
    )!;
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId,
        token: message.payload.token!,
        password: 'a strong hank password',
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });

    // With iam:licenses:assign both go through, and the new people take their seats.
    await s.mayAssign(onboarder.identity.id);
    await createMany(licensed.id, 'erin');
    await f.iam.api.identities.acceptInvitation({
      tenantId,
      token: message.payload.token!,
      password: 'a strong hank password',
    });
    await invite(licensed.id, 'gail@acme.test');
    // Frank's plain group carries seats now too.
    expect(await s.seats()).toEqual(['erin active', 'frank active', 'hank active']);
  });

  it('asks guest invitations for iam:licenses:assign, and re-checks at redemption', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licensed, plain } = s;
    const host = await s.staff('host', ['iam:guests:invite', 'iam:groups:update'], true);
    const invite = (address: string, input: { groupIds?: string[]; packageIds?: string[] }) =>
      f.iam.api.guests.invite(host.credential, { tenantId, email: address, ...input });
    await expect(invite('gil@partner.test', { groupIds: [licensed.id] })).rejects.toMatchObject(
      s.refused,
    );
    expect(await s.denials(host.identity.id, 'iam:guests:invite')).toBe(1);
    // A package that includes a licensed group too.
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Partner kit',
      groupIds: [licensed.id],
    });
    const packager = await s.staff(
      'packager',
      ['iam:guests:invite', 'iam:groups:update', 'iam:packages:assign'],
      true,
    );
    await expect(
      f.iam.api.guests.invite(packager.credential, {
        tenantId,
        email: 'pia@partner.test',
        packageIds: [kit.id],
      }),
    ).rejects.toMatchObject(s.refused);
    expect(await s.denials(packager.identity.id, 'iam:guests:invite')).toBe(1);

    // Invited into a plain group that carries seats by the time the guest redeems: refused then.
    await invite('ivy@partner.test', { groupIds: [plain.id] });
    await s.licenses.assign(owner, {
      tenantId,
      productId: s.pro.id,
      subjectType: 'group',
      subjectId: plain.id,
    });
    await expect(
      f.iam.api.guests.redeem({
        tenantId,
        token: await invitationToken(f, 'ivy@partner.test'),
        name: 'Ivy',
        password: guestPassword('Ivy'),
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });

    await s.mayAssign(packager.identity.id);
    await f.iam.api.guests.invite(packager.credential, {
      tenantId,
      email: 'pia@partner.test',
      packageIds: [kit.id],
    });
    await s.mayAssign(host.identity.id);
    await invite('gil@partner.test', { groupIds: [licensed.id] });
    const gil = await redeemGuest(f, 'gil@partner.test', 'Gil');
    const ivy = await redeemGuest(f, 'ivy@partner.test', 'Ivy');
    expect(await f.iam.licenses.products(gil.identity.id, tenantId)).toEqual(['pro']);
    expect(await f.iam.licenses.products(ivy.identity.id, tenantId)).toEqual(['pro']);
  });

  it('asks access packages for iam:licenses:assign: assigning, approving, extending, and saving a rule', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licensed } = s;
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Pro kit',
      groupIds: [licensed.id],
      requestable: true,
    });
    const alice = await f.member('alice');
    const assigner = await s.staff('assigner', ['iam:packages:assign', 'iam:groups:update']);
    await expect(
      f.iam.api.packages.assign(assigner.credential, {
        tenantId,
        packageId: kit.id,
        identityId: alice.id,
      }),
    ).rejects.toMatchObject(s.refused);
    expect(await s.denials(assigner.identity.id, 'iam:packages:assign')).toBe(1);
    expect(await s.seats()).toEqual([]);

    // Approving a request assigns under the approver's rights.
    const requester = await s.staff('requester', ['iam:packages:request']);
    const approver = await s.staff('approver', ['iam:packages:approve', 'iam:groups:update']);
    const request = await f.iam.api.packages.request(requester.credential, {
      tenantId,
      packageId: kit.id,
    });
    await expect(
      f.iam.api.packages.approveRequest(approver.credential, { tenantId, requestId: request.id }),
    ).rejects.toMatchObject(s.refused);
    expect(await s.denials(approver.identity.id, 'iam:packages:approve')).toBe(1);

    // Lengthening an assignment is granting again; shortening is not.
    await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: alice.id,
      expiresAt: f.now() + 2 * DAY,
    });
    const extend = (expiresAt: number | null) =>
      f.iam.api.packages.extend(assigner.credential, {
        tenantId,
        packageId: kit.id,
        identityId: alice.id,
        expiresAt,
      });
    await expect(extend(f.now() + 10 * DAY)).rejects.toMatchObject(s.refused);
    await expect(extend(null)).rejects.toMatchObject(s.refused);
    await expect(extend(f.now() + DAY)).resolves.toMatchObject({ expiresAt: f.now() + DAY });

    // A rule on a package with a licensed group needs its owner to hold iam:licenses:assign from the start.
    const author = await s.staff(
      'author',
      ['iam:packages:create', 'iam:packages:assign', 'iam:packages:read', 'iam:groups:update'],
      true,
    );
    await expect(
      f.iam.api.packages.create(author.credential, {
        tenantId,
        name: 'Everyone gets Pro',
        groupIds: [licensed.id],
        autoAssign: { include: [{ StringEquals: { 'principal.kind': 'user' } }] },
      }),
    ).rejects.toMatchObject(s.refused);
    expect(await s.denials(author.identity.id, 'iam:packages:create')).toBe(1);

    await s.mayAssign(assigner.identity.id);
    await s.mayAssign(approver.identity.id);
    await expect(extend(f.now() + 10 * DAY)).resolves.toMatchObject({
      expiresAt: f.now() + 10 * DAY,
    });
    await expect(
      f.iam.api.packages.approveRequest(approver.credential, { tenantId, requestId: request.id }),
    ).resolves.toMatchObject({ status: 'approved' });
    expect(await s.seats()).toEqual(['alice active', 'requester active']);
    await s.mayAssign(author.identity.id);
    await expect(
      f.iam.api.packages.create(author.credential, {
        tenantId,
        name: 'Everyone gets Pro',
        groupIds: [licensed.id],
        autoAssign: { include: [{ StringEquals: { 'principal.kind': 'user' } }] },
      }),
    ).resolves.toMatchObject({ autoAssign: expect.objectContaining({ status: 'active' }) });
  });

  it('suspends the additions of a rule whose owner cannot claim the seats a packaged group now carries', async () => {
    const s = await scenario();
    const { f, tenantId, owner } = s;
    const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Wiki' });
    const author = await s.staff(
      'author',
      ['iam:packages:create', 'iam:packages:assign', 'iam:packages:read', 'iam:groups:update'],
      true,
    );
    const pkg = await f.iam.api.packages.create(author.credential, {
      tenantId,
      name: 'Wiki for everyone',
      groupIds: [wiki.id],
      autoAssign: { include: [{ StringEquals: { 'principal.kind': 'user' } }] },
    });
    expect(pkg.autoAssign).toMatchObject({ status: 'active', ownerName: 'author' });
    // An administrator licenses the wiki group afterwards.
    await s.licenses.assign(owner, {
      tenantId,
      productId: s.pro.id,
      subjectType: 'group',
      subjectId: wiki.id,
    });
    // The next grant the rule would make suspends it up front, naming the missing permission, instead of failing
    // person by person.
    const newbie = await f.member('newbie');
    const rule = (await f.iam.api.packages.get(owner, { tenantId, packageId: pkg.id })).autoAssign!;
    expect(rule).toMatchObject({
      status: 'suspended',
      suspendedReason: 'owner-lacks-rights',
      suspendedDetail: expect.stringContaining('iam:licenses:assign'),
    });
    expect(rule.issues.filter((issue) => issue.kind === 'failed')).toEqual([]);
    expect(
      (await f.iam.api.packages.listAssignments(owner, { tenantId, packageId: pkg.id })).map(
        (assignment) => assignment.identityId,
      ),
    ).not.toContain(newbie.id);

    // Once the owner may assign licenses, the rule resumes and grants.
    await s.mayAssign(author.identity.id);
    await f.iam.reconcilePackages();
    expect(
      (await f.iam.api.packages.get(owner, { tenantId, packageId: pkg.id })).autoAssign,
    ).toMatchObject({ status: 'active' });
    expect(
      (await f.iam.api.packages.listAssignments(owner, { tenantId, packageId: pkg.id })).map(
        (assignment) => assignment.identityId,
      ),
    ).toContain(newbie.id);
  });

  it('asks onboarding flows for iam:licenses:assign on a licensed completion group', async () => {
    const s = await scenario();
    const { f, tenantId, licensed } = s;
    const designer = await s.staff('designer', [
      'iam:onboarding:manage',
      'iam:onboarding:read',
      'iam:groups:update',
    ]);
    const create = () =>
      f.iam.api.onboarding.createFlow(designer.credential, {
        tenantId,
        name: 'Pro onboarding',
        audience: 'member',
        completionGroupIds: [licensed.id],
        steps: [
          { id: 'laptop', kind: 'task', title: 'Collect your laptop', verification: 'admin' },
        ],
      });
    await expect(create()).rejects.toMatchObject(s.refused);
    await s.mayAssign(designer.identity.id);
    await expect(create()).resolves.toMatchObject({ groupsOwnerId: designer.identity.id });
  });

  it('asks team administrators for iam:licenses:assign on a licensed team or a team below one', async () => {
    const s = await scenario();
    const { f, tenantId, owner } = s;
    const teams = f.iam.api.teams;
    const platform = await teams.create(owner, { tenantId, name: 'Platform' });
    const design = await teams.create(owner, {
      tenantId,
      name: 'Design',
      parentId: platform.id,
      joinPolicy: 'request',
    });
    const locked = await teams.create(owner, {
      tenantId,
      name: 'Locked',
      parentId: platform.id,
      memberManagement: 'admins',
    });
    const other = await teams.create(owner, { tenantId, name: 'Other' });
    // Seats of Pro go to the Platform team and every team below it.
    await s.licenses.assign(owner, {
      tenantId,
      productId: s.pro.id,
      subjectType: 'group',
      subjectId: platform.groupId,
    });
    const admin = await s.staff('admin', [
      'iam:teams:update',
      'iam:teams:read',
      'iam:teams:create',
    ]);
    const [bob, carol, dave, eve] = [
      await f.member('bob'),
      await f.member('carol'),
      await f.member('dave'),
      await f.member('eve'),
    ];
    const as = admin.credential;
    const denied = () => s.denials(admin.identity.id, 'iam:teams:update');

    await expect(
      teams.addMember(as, { tenantId, teamId: design.id, identityId: bob.id }),
    ).rejects.toMatchObject(s.refused);
    expect(await denied()).toBe(1);
    await expect(
      teams.addMembers(as, { tenantId, teamId: design.id, identityIds: [bob.id, carol.id] }),
    ).rejects.toMatchObject(s.refused);
    // Approving a join request adds the requester.
    const request = await teams.requestToJoin(
      { token: (await f.signIn('dave')).token },
      { tenantId, teamId: design.id },
    );
    await expect(
      teams.approveRequest(as, { tenantId, requestId: request.id }),
    ).rejects.toMatchObject(s.refused);
    // Keeping someone longer, or appointing a maintainer; shortening is not a claim.
    await teams.addMember(owner, {
      tenantId,
      teamId: design.id,
      identityId: eve.id,
      expiresAt: f.now() + 2 * DAY,
    });
    await expect(
      teams.updateMember(as, { tenantId, teamId: design.id, identityId: eve.id, expiresAt: null }),
    ).rejects.toMatchObject(s.refused);
    await expect(
      teams.updateMember(as, {
        tenantId,
        teamId: design.id,
        identityId: eve.id,
        role: 'maintainer',
      }),
    ).rejects.toMatchObject(s.refused);
    await expect(
      teams.updateMember(as, {
        tenantId,
        teamId: design.id,
        identityId: eve.id,
        expiresAt: f.now() + DAY,
      }),
    ).resolves.toMatchObject({ expiresAt: f.now() + DAY });
    // Syncing a group in, moving a staffed team under a licensed one, opening an admins-only team to maintainers.
    const directory = await f.iam.api.groups.create(owner, { tenantId, name: 'Directory design' });
    await expect(
      teams.update(as, { tenantId, teamId: design.id, syncGroupIds: [directory.id] }),
    ).rejects.toMatchObject(s.refused);
    await teams.addMember(owner, { tenantId, teamId: other.id, identityId: carol.id });
    await expect(
      teams.update(as, { tenantId, teamId: other.id, parentId: platform.id }),
    ).rejects.toMatchObject(s.refused);
    await expect(
      teams.update(as, { tenantId, teamId: locked.id, memberManagement: 'maintainers' }),
    ).rejects.toMatchObject(s.refused);
    // Creating a team below a licensed one with maintainers, or syncing a group into it.
    await expect(
      teams.create(as, {
        tenantId,
        name: 'Research',
        parentId: platform.id,
        maintainerIds: [bob.id],
      }),
    ).rejects.toMatchObject(s.refused);
    await expect(
      teams.create(as, {
        tenantId,
        name: 'Research',
        parentId: platform.id,
        syncGroupIds: [directory.id],
      }),
    ).rejects.toMatchObject(s.refused);
    expect(await s.denials(admin.identity.id, 'iam:teams:create')).toBe(2);
    // Teams without products are managed as before.
    await expect(
      teams.addMember(as, { tenantId, teamId: other.id, identityId: dave.id }),
    ).resolves.toMatchObject({ identityId: dave.id });
    expect(await s.seats()).toEqual(['eve active']);

    // With iam:licenses:assign every one of those goes through.
    await s.mayAssign(admin.identity.id);
    await teams.addMember(as, { tenantId, teamId: design.id, identityId: bob.id });
    await teams.approveRequest(as, { tenantId, requestId: request.id });
    await teams.updateMember(as, {
      tenantId,
      teamId: design.id,
      identityId: eve.id,
      role: 'maintainer',
      expiresAt: null,
    });
    await teams.update(as, { tenantId, teamId: design.id, syncGroupIds: [directory.id] });
    await teams.update(as, { tenantId, teamId: other.id, parentId: platform.id });
    await teams.update(as, { tenantId, teamId: locked.id, memberManagement: 'maintainers' });
    await teams.create(as, {
      tenantId,
      name: 'Research',
      parentId: platform.id,
      maintainerIds: [bob.id],
      syncGroupIds: [directory.id],
    });
    expect(await s.seats()).toEqual(['bob active', 'carol active', 'dave active', 'eve active']);
  });

  it('asks configuration sync for iam:licenses:assign to put people into a licensed team', async () => {
    const s = await scenario();
    const { f, tenantId, owner } = s;
    const support = await f.iam.api.teams.create(owner, { tenantId, name: 'Support' });
    await s.licenses.assign(owner, {
      tenantId,
      productId: s.pro.id,
      subjectType: 'group',
      subjectId: support.groupId,
    });
    await f.member('erin');
    const operator = await s.staff('operator', [
      'iam:config:apply',
      'iam:config:read',
      'iam:teams:update',
      'iam:teams:read',
    ]);
    const apply = () =>
      f.iam.api.config.apply(operator.credential, {
        tenantId,
        config: {
          version: 1,
          teams: [{ name: 'Support', slug: support.slug, members: ['erin@acme.test'] }],
        },
      });
    await expect(apply()).rejects.toMatchObject(s.refused);
    expect(await s.denials(operator.identity.id, 'iam:config:apply')).toBe(1);
    await s.mayAssign(operator.identity.id);
    await apply();
    expect(await s.seats()).toEqual(['erin active']);
  });

  it('asks guests.convertToMember with clearExpiry for iam:licenses:assign on a licensed group the guest keeps', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licensed, plain } = s;
    const alice = await f.member('alice');
    const proKit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Pro kit',
      groupIds: [licensed.id],
    });
    const guest = async (name: string, input: { groupIds?: string[]; packageIds?: string[] }) => {
      await f.iam.api.guests.invite(owner, {
        tenantId,
        email: `${name.toLowerCase()}@partner.test`,
        sponsorId: alice.id,
        accessDays: 10,
        ...input,
      });
      return (await redeemGuest(f, `${name.toLowerCase()}@partner.test`, name)).identity;
    };
    const gil = await guest('Gil', { groupIds: [licensed.id] });
    const pia = await guest('Pia', { packageIds: [proKit.id] });
    const ned = await guest('Ned', { groupIds: [plain.id] });
    const gm = await s.staff('gm', ['iam:guests:manage', 'iam:guests:read', 'iam:groups:update']);
    const end = async (identityId: string, groupId: string) =>
      (
        await f.database.find<{ expiresAt?: number }>('groupMembers', {
          tenantId,
          identityId,
          groupId,
        })
      )[0]!.expiresAt;
    const convert = (identityId: string, clearExpiry?: boolean) =>
      f.iam.api.guests.convertToMember(gm.credential, {
        tenantId,
        identityId,
        ...(clearExpiry !== undefined ? { clearExpiry } : {}),
      });
    // groups.updateMember(expiresAt: null) refuses gm, and so does clearing the end through a conversion, for a
    // licensed group the invitation granted directly or through a package.
    await expect(
      f.iam.api.groups.updateMember(gm.credential, {
        tenantId,
        groupId: licensed.id,
        identityId: gil.id,
        expiresAt: null,
      }),
    ).rejects.toMatchObject(s.refused);
    await expect(convert(gil.id, true)).rejects.toMatchObject(s.refused);
    await expect(convert(pia.id, true)).rejects.toMatchObject(s.refused);
    expect(await s.denials(gm.identity.id, 'iam:guests:manage')).toBe(2);
    expect((await f.database.get<{ guest?: unknown }>('identities', gil.id))!.guest).toBeDefined();
    expect(await end(gil.id, licensed.id)).toBe(f.now() + 10 * DAY);
    expect(await end(pia.id, licensed.id)).toBe(f.now() + 10 * DAY);
    // A conversion that keeps the end, and one without licensed groups, need nothing more; neither does a renewal,
    // which ends again (the documented exemption, for administrators as for the sponsor).
    await expect(convert(pia.id)).resolves.toMatchObject({ id: pia.id });
    expect(await end(pia.id, licensed.id)).toBe(f.now() + 10 * DAY);
    await expect(convert(ned.id, true)).resolves.toMatchObject({ id: ned.id });
    expect(await end(ned.id, plain.id)).toBeUndefined();
    await f.iam.api.guests.attest(gm.credential, { tenantId, identityId: gil.id, days: 30 });
    expect(await end(gil.id, licensed.id)).toBe(f.now() + 30 * DAY);

    await s.mayAssign(gm.identity.id);
    await expect(convert(gil.id, true)).resolves.toMatchObject({ id: gil.id });
    expect(await end(gil.id, licensed.id)).toBeUndefined();
    f.advance(40 * DAY);
    await f.iam.licenses.reconcile({ tenantId });
    expect(await s.seats(await f.ownerSignIn())).toEqual(['Gil active']);
  });

  it('refuses to resend a member invitation its inviter can no longer grant', async () => {
    const s = await scenario();
    const { f, tenantId, owner, plain } = s;
    const onboarder = await s.staff(
      'onboarder',
      ['iam:identities:create', 'iam:groups:update'],
      true,
    );
    await f.iam.api.identities.invite(onboarder.credential, {
      tenantId,
      email: 'hank@acme.test',
      name: 'hank',
      groupIds: [plain.id],
    });
    // IT licenses the group afterwards: acceptance would refuse the invitation, so resending it (even by the owner,
    // who could grant it) is refused too, instead of mailing a link that cannot work.
    await s.licenses.assign(owner, {
      tenantId,
      productId: s.pro.id,
      subjectType: 'group',
      subjectId: plain.id,
    });
    const [invitation] = (await f.iam.api.identities.listInvitations(owner, { tenantId })).filter(
      (item) => item.email === 'hank@acme.test',
    );
    const resend = () =>
      f.iam.api.identities.resendInvitation(owner, { tenantId, invitationId: invitation!.id });
    await expect(resend()).rejects.toMatchObject({
      code: 'INVITATION_INVALID',
      message: expect.stringContaining('revoke this invitation'),
    });
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox.filter(
        (item) => item.template === 'member-invitation' && item.to === 'hank@acme.test',
      ),
    ).toHaveLength(1);

    await s.mayAssign(onboarder.identity.id);
    await resend();
    await f.iam.auth.dispatchOutbox();
    const latest = f.inbox
      .filter((item) => item.template === 'member-invitation' && item.to === 'hank@acme.test')
      .at(-1)!;
    await f.iam.api.identities.acceptInvitation({
      tenantId,
      token: latest.payload.token!,
      password: 'a strong hank password',
    });
    expect(await s.seats()).toEqual(['hank active']);
  });
});

describe('who claims seats without iam:licenses:assign, by design', () => {
  it('lets a team’s maintainers manage its members themselves', async () => {
    const s = await scenario();
    const { f, tenantId, owner } = s;
    const teams = f.iam.api.teams;
    const platform = await teams.create(owner, { tenantId, name: 'Platform' });
    const design = await teams.create(owner, { tenantId, name: 'Design', parentId: platform.id });
    await s.licenses.assign(owner, {
      tenantId,
      productId: s.pro.id,
      subjectType: 'group',
      subjectId: platform.groupId,
    });
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    await teams.addMember(owner, {
      tenantId,
      teamId: design.id,
      identityId: carol.id,
      role: 'maintainer',
    });
    const asCarol = { token: (await f.signIn('carol')).token };
    await expect(
      teams.addMember(asCarol, { tenantId, teamId: design.id, identityId: dave.id }),
    ).resolves.toMatchObject({ identityId: dave.id });
    expect(await s.seats()).toEqual(['carol active', 'dave active']);
  });

  it('lets directory sync (SCIM) set a licensed group’s members as the directory says', async () => {
    const s = await scenario();
    const { f, tenantId, owner } = s;
    const service = createScimService({ ...f.iam.protocolHost });
    const connection = await service.createConnection(owner, { tenantId, name: 'Directory' });
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
    const created = (await (
      await request('Groups', 'POST', { displayName: 'Designers' })
    ).json()) as { id: string };
    const groupId = (await f.database.get<{ groupId: string }>('scimGroups', created.id))!.groupId;
    await s.licenses.assign(owner, {
      tenantId,
      productId: s.pro.id,
      subjectType: 'group',
      subjectId: groupId,
    });
    const user = (await (
      await request('Users', 'POST', { userName: 'zoe@acme.test', active: true })
    ).json()) as { id: string };
    const added = await request(`Groups/${created.id}`, 'PATCH', {
      schemas: [PATCH],
      Operations: [{ op: 'add', path: 'members', value: [{ value: user.id }] }],
    });
    expect(added.status).toBeLessThan(300);
    expect(await s.seats()).toEqual(['zoe@acme.test active']);
  });

  it('lets a sponsor renew a guest invited into a licensed group', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licensed } = s;
    const alice = await f.member('alice');
    await f.iam.api.guests.invite(owner, {
      tenantId,
      email: 'gil@partner.test',
      sponsorId: alice.id,
      groupIds: [licensed.id],
      accessDays: 10,
    });
    const gil = await redeemGuest(f, 'gil@partner.test', 'Gil');
    expect(await s.seats()).toEqual(['Gil active']);
    f.advance(5 * DAY);
    const renewed = await f.iam.api.guests.attest(
      { token: (await f.signIn('alice')).token },
      { tenantId, identityId: gil.identity.id, days: 30 },
    );
    expect(renewed.expiresAt).toBe(f.now() + 30 * DAY);
    const [membership] = await f.database.find<{ expiresAt?: number }>('groupMembers', {
      tenantId,
      identityId: gil.identity.id,
      groupId: licensed.id,
    });
    expect(membership!.expiresAt).toBe(f.now() + 30 * DAY);
    // Past the original end: the renewed membership still holds the seat.
    f.advance(20 * DAY);
    await f.iam.licenses.reconcile({ tenantId });
    expect(await s.seats(await f.ownerSignIn())).toEqual(['Gil active']);
  });

  it('renews only what the invitation granted: a licensed group a package gained since keeps its end', async () => {
    const s = await scenario();
    const { f, tenantId, owner, licensed, plain } = s;
    const alice = await f.member('alice');
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Partner kit',
      groupIds: [plain.id],
    });
    const guest = async (name: string) => {
      await f.iam.api.guests.invite(owner, {
        tenantId,
        email: `${name.toLowerCase()}@partner.test`,
        sponsorId: alice.id,
        packageIds: [kit.id],
        accessDays: 10,
      });
      return (await redeemGuest(f, `${name.toLowerCase()}@partner.test`, name)).identity;
    };
    const hal = await guest('Hal');
    const ian = await guest('Ian');
    // Hal holds a one-day seat by hand; Ian holds one through another package, for 60 days.
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: licensed.id,
      identityId: hal.id,
      expiresAt: f.now() + DAY,
    });
    const proAccess = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Pro access',
      groupIds: [licensed.id],
    });
    await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: proAccess.id,
      identityId: ian.id,
      expiresAt: f.now() + 60 * DAY,
    });
    // Someone who may only edit packages adds the licensed group to the guests' package (which grants nothing).
    const pm = await s.staff('pm', ['iam:packages:update', 'iam:packages:read']);
    await f.iam.api.packages.update(pm.credential, {
      tenantId,
      packageId: kit.id,
      groupIds: [plain.id, licensed.id],
    });
    // Revoking Ian's other package hands his membership to the guests' package, until its end.
    await f.iam.api.packages.revoke(owner, {
      tenantId,
      packageId: proAccess.id,
      identityId: ian.id,
    });
    const membership = async (identityId: string, groupId: string) =>
      (
        await f.database.find<{ expiresAt?: number; packageAssignmentId?: string }>(
          'groupMembers',
          { tenantId, identityId, groupId },
        )
      )[0]!;
    expect(await membership(ian.id, licensed.id)).toMatchObject({
      expiresAt: f.now() + 10 * DAY,
      packageAssignmentId: expect.any(String),
    });

    const asAlice = { token: (await f.signIn('alice')).token };
    for (const identityId of [hal.id, ian.id])
      await f.iam.api.guests.attest(asAlice, { tenantId, identityId, days: 30 });
    // What the invitation granted follows the renewal; the licensed memberships keep the ends they had.
    expect((await membership(hal.id, plain.id)).expiresAt).toBe(f.now() + 30 * DAY);
    expect(await membership(hal.id, licensed.id)).toEqual(
      expect.not.objectContaining({ packageAssignmentId: expect.anything() }),
    );
    expect((await membership(hal.id, licensed.id)).expiresAt).toBe(f.now() + DAY);
    expect((await membership(ian.id, licensed.id)).expiresAt).toBe(f.now() + 10 * DAY);
    f.advance(15 * DAY);
    await f.iam.licenses.reconcile({ tenantId });
    expect(await s.seats(await f.ownerSignIn())).toEqual([]);
  });
});
