import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, Identity } from '@better-iam/core';
import { renderDeliveryMessage } from '@better-iam/auth';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  betterIam,
  type Binding,
  type GroupMember,
  type GuestAccount,
  type PackageAssignment,
} from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';
import {
  addGuest,
  administrator,
  guestPassword,
  guestSignIn,
  invitationToken,
  otherOrganization,
  redeemGuest,
} from './support/guests.js';

afterEach(closeFixtures);

const day = 86_400_000;

describe('renewing guest access', () => {
  it('lets the sponsor or an administrator renew it, never a guest, and moves what the invitation granted', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    await f.member('bob');
    const viewer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewer',
      permissions: ['documents:read'],
    });
    const guestAdmin = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Guest admin',
      permissions: ['iam:guests:manage'],
    });
    const partners = await f.iam.api.groups.create(owner, { tenantId, name: 'Partners' });
    const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Wiki' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Partner kit',
      groupIds: [wiki.id],
      maxDurationMs: 120 * day,
    });
    const gina = await addGuest(f, 'gina', {
      sponsorId: alice.id,
      roleIds: [viewer.id],
      groupIds: [partners.id],
      packageIds: [kit.id],
    });
    const hal = await addGuest(f, 'hal', { sponsorId: alice.id, roleIds: [guestAdmin.id] });
    const guestId = gina.identity.id;
    const firstEnd = f.now() + 90 * day;
    const ends = async () => {
      const bindings = await f.database.find<Binding>('bindings', {
        tenantId,
        subjectType: 'identity',
        subjectId: guestId,
      });
      const members = await f.database.find<GroupMember>('groupMembers', {
        tenantId,
        identityId: guestId,
      });
      const [assignment] = await f.database.find<PackageAssignment>('packageAssignments', {
        tenantId,
        identityId: guestId,
      });
      return {
        identity: (await f.database.get<Identity>('identities', guestId))!.expiresAt,
        role: bindings.find((binding) => binding.roleId === viewer.id)?.expiresAt,
        partners: members.find((member) => member.groupId === partners.id)?.expiresAt,
        wiki: members.find((member) => member.groupId === wiki.id)?.expiresAt,
        package: assignment?.expiresAt,
      };
    };
    expect(await ends()).toEqual({
      identity: firstEnd,
      role: firstEnd,
      partners: firstEnd,
      wiki: firstEnd,
      package: firstEnd,
    });
    const account = await f.database.get<GuestAccount>('guestAccounts', guestId);
    expect(account).toMatchObject({
      status: 'active',
      reviewDueAt: firstEnd,
      grants: {
        bindingIds: [expect.any(String)],
        membershipIds: [expect.any(String)],
        packageAssignmentIds: [expect.any(String)],
      },
    });

    // A month in, the sponsor renews for 60 days without any permission.
    f.advance(30 * day);
    const asAlice = { token: (await f.signIn('alice')).token };
    const secondEnd = f.now() + 60 * day;
    const renewed = await f.iam.api.guests.attest(asAlice, {
      tenantId,
      identityId: guestId,
      days: 60,
    });
    expect(renewed).toMatchObject({
      expiresAt: secondEnd,
      attestedAt: f.now(),
      attestedBy: alice.id,
      reviewDueAt: secondEnd,
      accountStatus: 'active',
    });
    expect(await ends()).toEqual({
      identity: secondEnd,
      role: secondEnd,
      partners: secondEnd,
      wiki: secondEnd,
      package: secondEnd,
    });
    for (const days of [0, 366, 1.5, '30'])
      await expect(
        f.iam.api.guests.attest(asAlice, { tenantId, identityId: guestId, days } as never),
        String(days),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Nobody else renews without iam:guests:manage; guests never renew, themselves or others.
    const asBob = { token: (await f.signIn('bob')).token };
    await expect(
      f.iam.api.guests.attest(asBob, { tenantId, identityId: guestId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const asGina = await guestSignIn(f, 'gina@partner.test', 'gina');
    await expect(
      f.iam.api.guests.attest(asGina, { tenantId, identityId: guestId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const asHal = await guestSignIn(f, 'hal@partner.test', 'hal');
    for (const identityId of [hal.identity.id, guestId])
      await expect(
        f.iam.api.guests.attest(asHal, { tenantId, identityId }),
        identityId,
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    const owned = await f.ownerSignIn();
    await expect(
      f.iam.api.guests.attest(owned, { tenantId, identityId: 'missing' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.guests.attest(owned, { tenantId, identityId: alice.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // An administrator renews for longer than the package may last: the package keeps its own end.
    const thirdEnd = f.now() + 200 * day;
    await f.iam.api.guests.attest(owned, { tenantId, identityId: guestId, days: 200 });
    expect(await ends()).toEqual({
      identity: thirdEnd,
      role: thirdEnd,
      partners: thirdEnd,
      wiki: secondEnd,
      package: secondEnd,
    });
    // Past the first two ends the guest still reads through the renewed role.
    f.advance(70 * day);
    const later = await guestSignIn(f, 'gina@partner.test', 'gina');
    expect(
      (
        await f.iam.authorize({
          ...later,
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'plan' },
        })
      ).allowed,
    ).toBe(true);

    const events = await f.database.find<AuditEvent>('audit', { tenantId });
    const attests = events
      .filter((event) => event.action === 'guest:attest' && event.resourceId === guestId)
      .sort((a, b) => a.sequence! - b.sequence!);
    expect(attests.map((event) => [event.actorId, event.metadata?.asSponsor])).toEqual([
      [alice.id, true],
      [f.ownerId, false],
    ]);
    expect(attests[0]!.metadata).toMatchObject({
      days: 60,
      expiresAt: secondEnd,
      previousExpiresAt: firstEnd,
    });
    // The sponsor's renewal needs no permission check; the administrator's goes through one.
    const manage = events.filter(
      (event) => event.action === 'iam:guests:manage' && event.outcome === 'allow',
    );
    expect(manage.map((event) => event.actorId)).toEqual([f.ownerId]);
  });

  it('refuses to renew a guest whose access ended or who is disabled', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    const ivy = await addGuest(f, 'ivy', { sponsorId: alice.id, accessDays: 1 });
    const jo = await addGuest(f, 'jo', { sponsorId: alice.id });
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId,
      identityId: jo.identity.id,
      status: 'disabled',
    });
    f.advance(2 * day);
    const asAlice = { token: (await f.signIn('alice')).token };
    for (const identityId of [ivy.identity.id, jo.identity.id])
      await expect(
        f.iam.api.guests.attest(asAlice, { tenantId, identityId }),
        identityId,
      ).rejects.toMatchObject({ code: 'INVALID_TRANSITION', status: 409 });
    // The ended guest reads as expired straight away.
    expect(
      await f.iam.api.guests.get(await f.ownerSignIn(), { tenantId, identityId: ivy.identity.id }),
    ).toMatchObject({ accountStatus: 'expired', status: 'active' });
    await expect(guestSignIn(f, 'ivy@partner.test', 'ivy')).rejects.toBeDefined();
  });
});

describe('sponsors, conversion and removal', () => {
  it('moves a guest to another sponsor', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: carol.id,
      status: 'disabled',
    });
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id });
    const hal = await addGuest(f, 'hal');
    const setSponsor = (sponsorId: unknown, identityId = gina.identity.id) =>
      f.iam.api.guests.setSponsor(owner, { tenantId, identityId, sponsorId } as never);
    for (const sponsorId of [gina.identity.id, hal.identity.id, carol.id, 'missing'])
      await expect(setSponsor(sponsorId), sponsorId).rejects.toMatchObject({
        code: 'INVALID_SPONSOR',
      });
    await expect(setSponsor('')).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    for (const identityId of ['missing', bob.id])
      await expect(setSponsor(bob.id, identityId), identityId).rejects.toMatchObject({
        code: 'NOT_FOUND',
      });
    const moved = await setSponsor(bob.id);
    expect(moved).toMatchObject({ sponsorId: bob.id, sponsorName: 'bob', sponsorMissing: false });
    expect((await f.database.get<Identity>('identities', gina.identity.id))!.guest?.sponsorId).toBe(
      bob.id,
    );
    const asBob = { token: (await f.signIn('bob')).token };
    const asAlice = { token: (await f.signIn('alice')).token };
    expect(
      (await f.iam.api.guests.mine(asBob, { tenantId })).map((view) => view.identityId),
    ).toEqual([gina.identity.id]);
    expect(await f.iam.api.guests.mine(asAlice, { tenantId })).toEqual([]);
    // The former sponsor lost the right to renew; the new one has it.
    await expect(
      f.iam.api.guests.attest(asAlice, { tenantId, identityId: gina.identity.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.guests.attest(asBob, { tenantId, identityId: gina.identity.id }),
    ).resolves.toMatchObject({ attestedBy: bob.id });
    expect(
      (await f.iam.api.guests.list(owner, { tenantId, sponsorId: bob.id })).guests.map(
        (view) => view.identityId,
      ),
    ).toEqual([gina.identity.id]);
    const [event] = (await f.database.find<AuditEvent>('audit', { tenantId })).filter(
      (item) => item.action === 'guest:sponsor-change',
    );
    expect(event).toMatchObject({
      actorId: f.ownerId,
      resourceId: gina.identity.id,
      metadata: { from: alice.id, to: bob.id, reason: 'administrator' },
    });
  });

  it('converts a guest into an ordinary member', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const viewer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewer',
      permissions: ['documents:read'],
    });
    const gina = await addGuest(f, 'gina', { roleIds: [viewer.id] });
    const hal = await addGuest(f, 'hal', { roleIds: [viewer.id] });
    const end = f.now() + 90 * day;
    await expect(
      f.iam.api.guests.convertToMember(owner, {
        tenantId,
        identityId: gina.identity.id,
        clearExpiry: 'yes',
      } as never),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const member = await f.iam.api.guests.convertToMember(owner, {
      tenantId,
      identityId: gina.identity.id,
    });
    expect(member).not.toHaveProperty('guest');
    expect(member).toMatchObject({ id: gina.identity.id, status: 'active', expiresAt: end });
    expect(
      await f.iam.api.guests.get(owner, { tenantId, identityId: gina.identity.id }),
    ).toMatchObject({ accountStatus: 'converted', status: 'active' });
    const [account] = await f.database.find<GuestAccount>('guestAccounts', {
      tenantId,
      identityId: gina.identity.id,
    });
    expect(account).toMatchObject({ status: 'converted', endedAt: f.now(), endedBy: f.ownerId });
    expect(
      (await f.iam.api.guests.list(owner, { tenantId, status: 'converted' })).guests.map(
        (view) => view.identityId,
      ),
    ).toEqual([gina.identity.id]);
    expect(
      (await f.iam.api.guests.list(owner, { tenantId, status: 'active' })).guests.map(
        (view) => view.identityId,
      ),
    ).toEqual([hal.identity.id]);
    // Its grants keep their end unless the expiry is cleared.
    const [binding] = await f.iam.api.bindings.list(owner, {
      tenantId,
      subjectId: gina.identity.id,
    });
    expect(binding!.expiresAt).toBe(end);
    // A member is no guest any more: the guest actions no longer apply, and a member's address may change.
    for (const call of [
      () => f.iam.api.guests.attest(owner, { tenantId, identityId: gina.identity.id }),
      () =>
        f.iam.api.guests.setSponsor(owner, {
          tenantId,
          identityId: gina.identity.id,
          sponsorId: f.ownerId,
        }),
      () => f.iam.api.guests.convertToMember(owner, { tenantId, identityId: gina.identity.id }),
      () => f.iam.api.guests.remove(owner, { tenantId, identityId: gina.identity.id, reason: 'x' }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'INVALID_TRANSITION', status: 409 });
    await expect(
      f.iam.api.identities.update(owner, {
        tenantId,
        identityId: gina.identity.id,
        email: 'gina@acme.test',
      }),
    ).resolves.toMatchObject({ email: 'gina@acme.test' });

    // Clearing the expiry frees the grants of their end too.
    const cleared = await f.iam.api.guests.convertToMember(owner, {
      tenantId,
      identityId: hal.identity.id,
      clearExpiry: true,
    });
    expect(cleared).not.toHaveProperty('expiresAt');
    const [halBinding] = await f.iam.api.bindings.list(owner, {
      tenantId,
      subjectId: hal.identity.id,
    });
    expect(halBinding).not.toHaveProperty('expiresAt');
    const converts = (await f.database.find<AuditEvent>('audit', { tenantId }))
      .filter((event) => event.action === 'guest:convert')
      .sort((a, b) => a.sequence! - b.sequence!);
    expect(converts.map((event) => event.metadata)).toEqual([
      { sponsorId: f.ownerId, clearExpiry: false, expiresAt: end },
      { sponsorId: f.ownerId, clearExpiry: true, expiresAt: end },
    ]);
  });

  it('removes a guest with everything it holds, whoever granted it', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const viewer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewer',
      permissions: ['documents:read'],
    });
    const partners = await f.iam.api.groups.create(owner, { tenantId, name: 'Partners' });
    const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Wiki' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Partner kit',
      groupIds: [wiki.id],
    });
    const ivy = await addGuest(f, 'ivy', {
      roleIds: [viewer.id],
      groupIds: [partners.id],
      packageIds: [kit.id],
    });
    // A delegated administrator removes what the owner's authority granted.
    const admin = await administrator(f, 'admin', ['iam:guests:manage', 'iam:guests:read']);
    const remove = (input: Record<string, unknown>) =>
      f.iam.api.guests.remove(admin.credential, {
        tenantId,
        identityId: ivy.identity.id,
        reason: 'Project ended',
        ...input,
      } as never);
    for (const reason of ['', '   ', 'x'.repeat(513)])
      await expect(remove({ reason }), reason).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(remove({ identityId: admin.identity.id })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    const removal = await remove({});
    expect(removal).toEqual({
      guest: expect.objectContaining({
        identityId: ivy.identity.id,
        status: 'disabled',
        accountStatus: 'removed',
      }),
      sessions: 1,
      bindings: 1,
      memberships: 2,
      packages: 1,
    });
    await expect(
      f.iam.authorize({
        ...ivy.credential,
        tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'plan' },
      }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    await expect(guestSignIn(f, 'ivy@partner.test', 'ivy')).rejects.toBeDefined();
    for (const collection of ['groupMembers', 'packageAssignments'])
      expect(
        await f.database.find(collection, { tenantId, identityId: ivy.identity.id }),
        collection,
      ).toEqual([]);
    expect(await f.database.find('bindings', { tenantId, subjectId: ivy.identity.id })).toEqual([]);
    expect(await f.database.get<GuestAccount>('guestAccounts', ivy.identity.id)).toMatchObject({
      status: 'removed',
      endedBy: admin.identity.id,
      removalReason: 'Project ended',
    });
    await expect(remove({})).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const [event] = (await f.database.find<AuditEvent>('audit', { tenantId })).filter(
      (item) => item.action === 'guest:remove',
    );
    expect(event).toMatchObject({
      actorId: admin.identity.id,
      resourceId: ivy.identity.id,
      metadata: {
        reason: 'Project ended',
        sponsorId: f.ownerId,
        sessions: 1,
        bindings: 1,
        memberships: 2,
        packages: 1,
      },
    });
    // An expired guest can still be removed; an owning one cannot.
    const jo = await addGuest(f, 'jo', { accessDays: 1 });
    f.advance(2 * day);
    const fresh = await f.ownerSignIn();
    await expect(
      f.iam.api.guests.remove(fresh, { tenantId, identityId: jo.identity.id, reason: 'Lapsed' }),
    ).resolves.toMatchObject({ guest: { accountStatus: 'removed' } });
    const kim = await addGuest(f, 'kim', {}, fresh);
    await f.iam.api.identities.setOwner(fresh, {
      tenantId,
      identityId: kim.identity.id,
      owner: true,
    });
    await expect(
      f.iam.api.guests.remove(fresh, { tenantId, identityId: kim.identity.id, reason: 'x' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('guest jobs', () => {
  it('sweeps lapsed invitations, ended guests and missing sponsors', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    await f.iam.api.guests.invite(f.ownerCredential, {
      tenantId,
      email: 'late@partner.test',
      expiresInDays: 1,
    });
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id, accessDays: 3 });
    const hal = await addGuest(f, 'hal', { sponsorId: bob.id, accessDays: 30 });
    const zero = {
      invitationsExpired: 0,
      accountsExpired: 0,
      accountsRestored: 0,
      sponsorsMissing: 0,
      ownersNotified: 0,
      partnersRemoved: 0,
    };
    expect(await f.iam.guests.sweep()).toEqual(zero);
    f.advance(2 * day);
    expect(await f.iam.guests.sweep()).toEqual({ ...zero, invitationsExpired: 1 });
    const [late] = await f.database.find<{ status: string; uniqueKey?: string }>(
      'guestInvitations',
      { tenantId, email: 'late@partner.test' },
    );
    expect(late).toMatchObject({ status: 'expired' });
    expect(late).not.toHaveProperty('uniqueKey');

    // An ended guest reads as expired at once; the identity worker disables it and the sweep records it.
    f.advance(2 * day);
    let owner = await f.ownerSignIn();
    expect(
      (await f.iam.api.guests.list(owner, { tenantId, status: 'expired' })).guests.map(
        (view) => view.identityId,
      ),
    ).toEqual([gina.identity.id]);
    expect((await f.iam.purgeDeleted()).expiredIdentities).toBe(1);
    expect(await f.iam.guests.sweep()).toEqual({ ...zero, accountsExpired: 1 });
    expect(await f.iam.guests.sweep()).toEqual(zero);
    expect(await f.database.get<GuestAccount>('guestAccounts', gina.identity.id)).toMatchObject({
      status: 'expired',
      endedAt: gina.identity.expiresAt,
    });
    // An administrator gives the guest a later end and enables them again: the account comes back.
    await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: gina.identity.id,
      expiresAt: f.now() + 10 * day,
    });
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: gina.identity.id,
      status: 'active',
    });
    expect(await f.iam.guests.sweep()).toEqual({ ...zero, accountsRestored: 1 });
    expect(
      await f.iam.api.guests.get(owner, { tenantId, identityId: gina.identity.id }),
    ).toMatchObject({ accountStatus: 'active', status: 'active' });
    const restored = await f.database.get<GuestAccount>('guestAccounts', gina.identity.id);
    expect(restored).not.toHaveProperty('endedAt');

    // A sponsor who can no longer sponsor leaves the guest flagged, and the owners hear about it once per loss.
    f.inbox.length = 0;
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: bob.id,
      status: 'disabled',
    });
    expect(await f.iam.guests.sweep()).toEqual({ ...zero, sponsorsMissing: 1, ownersNotified: 1 });
    expect(await f.iam.guests.sweep()).toEqual(zero);
    await f.iam.auth.dispatchOutbox();
    const notices = f.inbox.filter((message) => message.template === 'guest-sponsor-missing');
    expect(notices).toEqual([
      expect.objectContaining({
        to: 'owner@acme.test',
        payload: {
          tenantId,
          tenantName: 'Acme',
          guestId: hal.identity.id,
          guestName: 'hal',
          guestEmail: 'hal@partner.test',
          sponsorName: 'bob',
        },
      }),
    ]);
    expect(renderDeliveryMessage(notices[0]!)!.subject).toBe('hal at Acme has no sponsor');
    expect(
      await f.iam.api.guests.get(owner, { tenantId, identityId: hal.identity.id }),
    ).toMatchObject({ sponsorMissing: true, sponsorId: bob.id });
    // The sponsor returns: the flag clears. They leave again: a new loss, a new notice.
    await f.iam.api.identities.setStatus(owner, { tenantId, identityId: bob.id, status: 'active' });
    expect(await f.iam.guests.sweep()).toEqual(zero);
    expect(
      (await f.iam.api.guests.get(owner, { tenantId, identityId: hal.identity.id })).sponsorMissing,
    ).toBe(false);
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: bob.id,
      status: 'disabled',
    });
    expect(await f.iam.guests.sweep()).toEqual({ ...zero, sponsorsMissing: 1, ownersNotified: 1 });
    // A new sponsor settles it.
    owner = await f.ownerSignIn();
    await f.iam.api.guests.setSponsor(owner, {
      tenantId,
      identityId: hal.identity.id,
      sponsorId: alice.id,
    });
    expect(
      (await f.iam.api.guests.get(owner, { tenantId, identityId: hal.identity.id })).sponsorMissing,
    ).toBe(false);
    expect(await f.iam.guests.sweep()).toEqual(zero);
    const events = (await f.database.find<AuditEvent>('audit', { tenantId })).filter((event) =>
      ['guest:expire', 'guest:sponsor-missing'].includes(event.action),
    );
    expect(
      events
        .sort((a, b) => a.sequence! - b.sequence!)
        .map((event) => [event.action, event.actorId, event.resourceId]),
    ).toEqual([
      ['guest:expire', 'deployment-operator', gina.identity.id],
      ['guest:sponsor-missing', 'deployment-operator', hal.identity.id],
      ['guest:sponsor-missing', 'deployment-operator', hal.identity.id],
    ]);

    // Partner entries naming an organization that was purged since are dropped.
    const root = await f.rootSignIn();
    const initech = await otherOrganization(f, 'Initech', 'initech', root);
    await f.iam.api.guests.configure(owner, {
      tenantId,
      inbound: { partners: [{ tenantId: initech.tenantId, allow: true }] },
      outbound: { partners: [{ tenantId: initech.tenantId, allow: false }] },
    });
    await f.iam.api.tenants.setStatus(root, { tenantId: initech.tenantId, status: 'deleted' });
    expect(await f.iam.guests.sweep({ tenantId })).toEqual(zero);
    await f.iam.purgeDeleted({ retentionMs: 0 });
    expect(await f.iam.guests.sweep({ tenantId: initech.tenantId })).toEqual(zero);
    expect(await f.iam.guests.sweep({ tenantId })).toEqual({ ...zero, partnersRemoved: 2 });
    const settings = await f.iam.api.guests.getSettings(owner, { tenantId });
    expect([settings.inbound.partners, settings.outbound.partners]).toEqual([[], []]);
  });

  it('reminds sponsors of reviews and access ends, once per due date', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    await f.iam.api.guests.configure(f.ownerCredential, { tenantId, reviewEveryDays: 30 });
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id });
    const hal = await addGuest(f, 'hal', { sponsorId: alice.id, accessDays: 10 });
    const start = f.now();
    for (const withinDays of [0, 91, 1.5])
      await expect(f.iam.guests.sendReviewReminders({ withinDays })).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
    f.inbox.length = 0;
    // Hal's access ends in ten days; Gina's review is a month out.
    expect(await f.iam.guests.sendReviewReminders()).toEqual({
      sent: [{ tenantId, guestId: hal.identity.id, sponsorId: alice.id, dueAt: start + 10 * day }],
      skipped: { inactive: 0, quiet: 0 },
    });
    await f.iam.auth.dispatchOutbox();
    const [reminder] = f.inbox.filter((message) => message.template === 'guest-review');
    expect(reminder).toMatchObject({
      to: 'alice@acme.test',
      payload: {
        tenantId,
        tenantName: 'Acme',
        guestId: hal.identity.id,
        guestName: 'hal',
        guestEmail: 'hal@partner.test',
        dueAt: new Date(start + 10 * day).toISOString(),
        reviewDueAt: new Date(start + 10 * day).toISOString(),
        expiresAt: new Date(start + 10 * day).toISOString(),
      },
    });
    const rendered = renderDeliveryMessage(reminder!, {
      links: {
        guests: ({ tenantId: realm, guestId }) =>
          `https://app.example.test/${realm}/guests/${guestId}`,
      },
    })!;
    expect(rendered.subject).toBe('Does hal still need access to Acme?');
    expect(rendered.text).toContain(
      `https://app.example.test/${tenantId}/guests/${hal.identity.id}`,
    );
    // Nothing new: nothing sent.
    expect(await f.iam.guests.sendReviewReminders()).toEqual({
      sent: [],
      skipped: { inactive: 0, quiet: 1 },
    });
    // Seventeen days on, Gina's review is near; Hal's access has ended, so nobody is reminded about him.
    f.advance(17 * day);
    expect((await f.iam.guests.sendReviewReminders()).sent).toEqual([
      { tenantId, guestId: gina.identity.id, sponsorId: alice.id, dueAt: start + 30 * day },
    ]);
    // Renewing moves the due date; the new one is reminded when it nears.
    const asAlice = { token: (await f.signIn('alice')).token };
    await f.iam.api.guests.attest(asAlice, { tenantId, identityId: gina.identity.id, days: 20 });
    expect((await f.iam.guests.sendReviewReminders()).sent).toEqual([]);
    f.advance(10 * day);
    expect((await f.iam.guests.sendReviewReminders()).sent).toEqual([
      {
        tenantId,
        guestId: gina.identity.id,
        sponsorId: alice.id,
        dueAt: start + 37 * day,
      },
    ]);
    const events = (await f.database.find<AuditEvent>('audit', { tenantId })).filter(
      (event) => event.action === 'guest:review-reminder',
    );
    expect(events.map((event) => [event.actorId, event.resourceId]).sort()).toEqual(
      [
        ['deployment-operator', gina.identity.id],
        ['deployment-operator', gina.identity.id],
        ['deployment-operator', hal.identity.id],
      ].sort(),
    );
    // A suspended organization is left alone.
    await f.iam.api.tenants.setStatus(await f.rootSignIn(), { tenantId, status: 'suspended' });
    f.advance(40 * day);
    expect(await f.iam.guests.sendReviewReminders({ tenantId })).toEqual({
      sent: [],
      skipped: { inactive: 1, quiet: 0 },
    });
  });

  it('needs an email delivery callback for reminders', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    try {
      const iam = betterIam({
        database,
        secret: 'guests-test-secret-with-32-characters-x',
        baseURL: 'http://localhost:3000',
      });
      await iam.initialize();
      await expect(iam.guests.sendReviewReminders()).rejects.toMatchObject({
        code: 'DELIVERY_REQUIRED',
      });
      expect(await iam.guests.sweep()).toEqual({
        invitationsExpired: 0,
        accountsExpired: 0,
        accountsRestored: 0,
        sponsorsMissing: 0,
        ownersNotified: 0,
        partnersRemoved: 0,
      });
    } finally {
      await database.close();
    }
  });
});

describe('guests when people leave', () => {
  it('hands guests to a successor at offboarding, or flags them for a new sponsor', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id });
    const hal = await addGuest(f, 'hal', { sponsorId: alice.id });
    const ivy = await addGuest(f, 'ivy', { sponsorId: carol.id });
    const jo = await addGuest(f, 'jo', { sponsorId: dave.id });
    // With a successor who can sponsor, the guests move to them.
    const first = await f.iam.api.identities.offboard(owner, {
      tenantId,
      identityId: alice.id,
      reason: 'left',
      successorId: bob.id,
    });
    expect(first).toMatchObject({ guestsReassigned: 2 });
    expect(first).not.toHaveProperty('guestsUnsponsored');
    for (const guest of [gina, hal])
      expect(
        (await f.database.get<Identity>('identities', guest.identity.id))!.guest?.sponsorId,
      ).toBe(bob.id);
    // Without one, or with a guest as successor, they are flagged.
    const second = await f.iam.api.identities.offboard(owner, {
      tenantId,
      identityId: carol.id,
      reason: 'left',
    });
    expect(second).toMatchObject({ guestsUnsponsored: 1 });
    expect(second).not.toHaveProperty('guestsReassigned');
    const third = await f.iam.api.identities.offboard(owner, {
      tenantId,
      identityId: dave.id,
      reason: 'left',
      successorId: gina.identity.id,
    });
    expect(third).toMatchObject({ guestsUnsponsored: 1 });
    for (const guest of [ivy, jo])
      expect(
        await f.iam.api.guests.get(owner, { tenantId, identityId: guest.identity.id }),
      ).toMatchObject({ sponsorMissing: true });
    // Offboarding a guest closes its guest account; people without guests keep the usual result.
    const fourth = await f.iam.api.identities.offboard(owner, {
      tenantId,
      identityId: hal.identity.id,
      reason: 'contract over',
    });
    expect(fourth).not.toHaveProperty('guestsReassigned');
    expect(fourth).not.toHaveProperty('guestsUnsponsored');
    expect(await f.database.get<GuestAccount>('guestAccounts', hal.identity.id)).toMatchObject({
      status: 'removed',
      removalReason: 'Offboarded',
      endedBy: f.ownerId,
    });
    const events = (await f.database.find<AuditEvent>('audit', { tenantId }))
      .filter(
        (event) =>
          event.action === 'guest:sponsor-change' || event.action === 'guest:sponsor-missing',
      )
      .sort((a, b) => a.sequence! - b.sequence!);
    expect(events.map((event) => [event.action, event.resourceId, event.metadata])).toEqual([
      [
        'guest:sponsor-change',
        expect.any(String),
        { from: alice.id, to: bob.id, reason: 'offboarding' },
      ],
      [
        'guest:sponsor-change',
        expect.any(String),
        { from: alice.id, to: bob.id, reason: 'offboarding' },
      ],
      ['guest:sponsor-missing', ivy.identity.id, { sponsorId: carol.id, reason: 'offboarding' }],
      ['guest:sponsor-missing', jo.identity.id, { sponsorId: dave.id, reason: 'offboarding' }],
    ]);
    // The sweep tells the owners about the flagged guests (already audited, so not counted again).
    expect(await f.iam.guests.sweep()).toMatchObject({ sponsorsMissing: 0, ownersNotified: 2 });
  });

  it('removes a deleted guest’s account and flags the guests of a deleted sponsor', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id });
    const hal = await addGuest(f, 'hal');
    await f.iam.api.identities.delete(owner, { tenantId, identityId: hal.identity.id });
    expect(await f.database.get('guestAccounts', hal.identity.id)).toBeUndefined();
    await expect(
      f.iam.api.guests.get(owner, { tenantId, identityId: hal.identity.id }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(
      (await f.iam.api.guests.list(owner, { tenantId })).guests.map((view) => view.identityId),
    ).toEqual([gina.identity.id]);
    expect(
      (await f.iam.api.guests.listInvitations(owner, { tenantId })).find(
        (invitation) => invitation.identityId === hal.identity.id,
      )?.status,
    ).toBe('redeemed');
    await f.iam.api.identities.delete(owner, { tenantId, identityId: alice.id });
    expect(
      await f.iam.api.guests.get(owner, { tenantId, identityId: gina.identity.id }),
    ).toMatchObject({ sponsorMissing: true, sponsorId: alice.id });
    const [event] = (await f.database.find<AuditEvent>('audit', { tenantId })).filter(
      (item) => item.action === 'guest:sponsor-missing',
    );
    expect(event).toMatchObject({
      actorId: f.ownerId,
      resourceId: gina.identity.id,
      metadata: { sponsorId: alice.id, reason: 'deletion' },
    });
  });

  it('revokes the pending invitations of a disabled inviter or sponsor', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const lead = await administrator(f, 'lead', ['iam:guests:invite']);
    const alice = await f.member('alice');
    const byLead = await f.iam.api.guests.invite(lead.credential, {
      tenantId,
      email: 'a@partner.test',
    });
    const forAlice = await f.iam.api.guests.invite(owner, {
      tenantId,
      email: 'b@partner.test',
      sponsorId: alice.id,
    });
    const untouched = await f.iam.api.guests.invite(owner, { tenantId, email: 'c@partner.test' });
    const leadToken = await invitationToken(f, 'a@partner.test');
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: lead.identity.id,
      status: 'disabled',
    });
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: alice.id,
      status: 'disabled',
    });
    const invitations = new Map(
      (await f.iam.api.guests.listInvitations(owner, { tenantId })).map((invitation) => [
        invitation.id,
        invitation,
      ]),
    );
    expect(invitations.get(byLead.id)).toMatchObject({
      status: 'revoked',
      revokedReason: 'inviter-inactive',
    });
    expect(invitations.get(forAlice.id)).toMatchObject({
      status: 'revoked',
      revokedReason: 'sponsor-inactive',
    });
    expect(invitations.get(untouched.id)).toMatchObject({ status: 'pending' });
    await expect(
      f.iam.api.guests.redeem({
        tenantId,
        token: leadToken,
        name: 'A',
        password: guestPassword('A'),
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    // The address can be invited again.
    await expect(
      f.iam.api.guests.invite(owner, { tenantId, email: 'b@partner.test' }),
    ).resolves.toMatchObject({ status: 'pending' });
  });
});

describe('redemption safeguards', () => {
  it('refuses a sponsor who can no longer sponsor, separation-of-duties conflicts and inactive tenants', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const temp = await f.member('temp', { expiresAt: f.now() + day });
    await f.iam.api.guests.invite(owner, { tenantId, email: 'a@partner.test', sponsorId: temp.id });
    const initiate = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Initiate payments',
      permissions: ['documents:write'],
    });
    const approve = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Approve payments',
      permissions: ['documents:read'],
    });
    await f.iam.api.sod.create(owner, {
      tenantId,
      name: 'Payments',
      roleIds: [initiate.id, approve.id],
    });
    const conflicted = await f.iam.api.guests.invite(owner, {
      tenantId,
      email: 'b@partner.test',
      roleIds: [initiate.id, approve.id],
    });
    await expect(redeemGuest(f, 'b@partner.test', 'Bea')).rejects.toMatchObject({
      code: 'SOD_CONFLICT',
    });
    expect(await f.database.find('identities', { tenantId, email: 'b@partner.test' })).toEqual([]);
    expect(
      (await f.iam.api.guests.listInvitations(owner, { tenantId })).find(
        (invitation) => invitation.id === conflicted.id,
      )?.status,
    ).toBe('pending');
    f.advance(2 * day);
    await expect(redeemGuest(f, 'a@partner.test', 'Ann')).rejects.toMatchObject({
      code: 'INVITATION_INVALID',
      message: 'The sponsor can no longer sponsor guests',
    });
    await f.iam.api.guests.invite(await f.ownerSignIn(), { tenantId, email: 'c@partner.test' });
    await f.iam.api.tenants.setStatus(await f.rootSignIn(), { tenantId, status: 'suspended' });
    await expect(redeemGuest(f, 'c@partner.test', 'Cy')).rejects.toMatchObject({ status: 403 });
  });

  it('rate limits redemption per token and per client address', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    await f.iam.api.guests.invite(f.ownerCredential, { tenantId, email: 'a@partner.test' });
    const redeem = (token: string) =>
      f.iam.api.guests.redeem({ tenantId, token, name: 'A', password: guestPassword('A') });
    for (let attempt = 0; attempt < 10; attempt++)
      await expect(redeem('biam_gst_guess')).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    await expect(redeem('biam_gst_guess')).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    await expect(redeem('biam_gst_other')).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    // From one address, twenty tries per window whatever the token.
    const from = <T>(fn: () => Promise<T>) =>
      f.iam.auth.withClient({ ip: '203.0.113.7', userAgent: 'test' }, fn);
    for (let attempt = 0; attempt < 20; attempt++)
      await expect(from(() => redeem(`biam_gst_try${attempt}`))).rejects.toMatchObject({
        code: 'INVITATION_INVALID',
      });
    await expect(from(() => redeem(`biam_gst_last`))).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    const token = await invitationToken(f, 'a@partner.test');
    await expect(from(() => redeem(token))).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    // Another address still redeems.
    await expect(
      f.iam.auth.withClient({ ip: '198.51.100.4', userAgent: 'test' }, () => redeem(token)),
    ).resolves.toMatchObject({ identity: { email: 'a@partner.test' } });
  });
});

describe('guest records', () => {
  it('keeps a guest’s email address the invited one', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const gina = await addGuest(f, 'gina');
    await expect(
      f.iam.api.identities.update(f.ownerCredential, {
        tenantId,
        identityId: gina.identity.id,
        email: 'gina@elsewhere.test',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Other changes keep the guest marker.
    const renamed = await f.iam.api.identities.update(f.ownerCredential, {
      tenantId,
      identityId: gina.identity.id,
      name: 'Gina P.',
    });
    expect(renamed).toMatchObject({ name: 'Gina P.', guest: gina.identity.guest });
    // Nor can the guest change it themselves.
    await expect(
      f.iam.api.auth.requestEmailChange(gina.credential, { email: 'gina@elsewhere.test' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.some((message) => message.template === 'email-change')).toBe(false);
    expect((await f.database.get<Identity>('identities', gina.identity.id))!.email).toBe(
      'gina@partner.test',
    );
    // Members still change theirs.
    const alice = await f.member('alice');
    await f.iam.api.auth.requestEmailChange(
      { token: (await f.signIn('alice')).token },
      { email: 'alice.new@acme.test' },
    );
    await f.iam.auth.dispatchOutbox();
    const change = f.inbox.find((message) => message.template === 'email-change')!;
    await f.iam.api.auth.confirmEmailChange({ tenantId, token: change.payload.token! });
    expect((await f.database.get<Identity>('identities', alice.id))!.email).toBe(
      'alice.new@acme.test',
    );
  });

  it('keeps settled invitations 90 days past their lapse, and purges guests with their tenant', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    // A purged organization takes its guest records along.
    const globex = await otherOrganization(f, 'Globex', 'globex');
    const other = globex.tenantId;
    await f.iam.api.guests.configure(globex.ownerCredential, { tenantId: other, accessDays: 5 });
    await f.iam.api.guests.invite(globex.ownerCredential, {
      tenantId: other,
      email: 'x@partner.test',
    });
    await redeemGuest(f, 'x@partner.test', 'Xena', other);
    for (const collection of ['guestInvitations', 'guestAccounts', 'crossTenantAccess'])
      expect(await f.database.find(collection, { tenantId: other }), collection).toHaveLength(1);
    await f.iam.api.tenants.setStatus(f.rootCredential, { tenantId: other, status: 'deleted' });
    expect((await f.iam.purgeDeleted({ retentionMs: 0 })).purgedTenants).toEqual([other]);
    for (const collection of ['guestInvitations', 'guestAccounts', 'crossTenantAccess'])
      expect(await f.database.find(collection, { tenantId: other }), collection).toEqual([]);

    await addGuest(f, 'gina');
    const revoked = await f.iam.api.guests.invite(owner, { tenantId, email: 'r@partner.test' });
    await f.iam.api.guests.revokeInvitation(owner, { tenantId, invitationId: revoked.id });
    await f.iam.api.guests.invite(owner, { tenantId, email: 'p@partner.test', expiresInDays: 1 });
    // Not yet: the redeemed and revoked invitations lapse after 14 days, and are kept 90 more.
    f.advance(14 * day + 89 * day);
    expect((await f.iam.sweepExpired()).deleted.guestInvitations).toBeUndefined();
    f.advance(2 * day);
    expect((await f.iam.sweepExpired()).deleted.guestInvitations).toBe(2);
    // A pending invitation waits for the guest sweep to mark it expired.
    expect(await f.database.find('guestInvitations', { tenantId })).toEqual([
      expect.objectContaining({ email: 'p@partner.test', status: 'pending' }),
    ]);
    expect((await f.iam.guests.sweep()).invitationsExpired).toBe(1);
    expect((await f.iam.sweepExpired()).deleted.guestInvitations).toBe(1);
    expect(await f.database.find('guestInvitations', { tenantId })).toEqual([]);
  });
});
