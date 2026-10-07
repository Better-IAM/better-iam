import { afterEach, describe, expect, it } from 'vitest';
import type { Identity } from '@better-iam/core';
import type { Binding, GroupMember, GuestAccount } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';
import { addGuest, guestPassword, invitationToken, redeemGuest } from './support/guests.js';

afterEach(closeFixtures);

const day = 86_400_000;

describe('guest edge cases', () => {
  it('renews what the invitation granted even after an administrator moved the guest’s end', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const viewer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewer',
      permissions: ['documents:read'],
    });
    const partners = await f.iam.api.groups.create(owner, { tenantId, name: 'Partners' });
    const gina = await addGuest(f, 'gina', {
      sponsorId: alice.id,
      roleIds: [viewer.id],
      groupIds: [partners.id],
    });
    const guestId = gina.identity.id;
    const ends = async () => {
      const [binding] = await f.database.find<Binding>('bindings', {
        tenantId,
        subjectType: 'identity',
        subjectId: guestId,
      });
      const [member] = await f.database.find<GroupMember>('groupMembers', {
        tenantId,
        identityId: guestId,
      });
      return {
        identity: (await f.database.get<Identity>('identities', guestId))!.expiresAt,
        role: binding?.expiresAt,
        partners: member?.expiresAt,
      };
    };
    // An administrator gives the guest a later end on the member page (identities.update).
    await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: guestId,
      expiresAt: f.now() + 120 * day,
    });
    // The sponsor renews: the invitation's grants follow the renewed access.
    const asAlice = { token: (await f.signIn('alice')).token };
    const renewed = await f.iam.api.guests.attest(asAlice, {
      tenantId,
      identityId: guestId,
      days: 200,
    });
    const end = f.now() + 200 * day;
    expect(renewed.expiresAt).toBe(end);
    expect(await ends()).toEqual({ identity: end, role: end, partners: end });
    // A grant an administrator changed on its own keeps its end.
    const [binding] = await f.database.find<Binding>('bindings', {
      tenantId,
      subjectType: 'identity',
      subjectId: guestId,
    });
    await f.iam.api.bindings.update(owner, {
      tenantId,
      bindingId: binding!.id,
      expiresAt: f.now() + 10 * day,
    });
    await f.iam.api.guests.attest(asAlice, { tenantId, identityId: guestId, days: 300 });
    expect(await ends()).toEqual({
      identity: f.now() + 300 * day,
      role: f.now() + 10 * day,
      partners: f.now() + 300 * day,
    });
    // Clearing the expiry at conversion frees the grants still following the guest's end.
    await f.iam.api.guests.convertToMember(owner, {
      tenantId,
      identityId: guestId,
      clearExpiry: true,
    });
    expect(await ends()).toEqual({
      identity: undefined,
      role: f.now() + 10 * day,
      partners: undefined,
    });
  });

  it('warns the sponsor before the access ends even after a review reminder went unanswered', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    await f.iam.api.guests.configure(f.ownerCredential, { tenantId, reviewEveryDays: 30 });
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id });
    const start = f.now();
    f.advance(16 * day);
    expect((await f.iam.guests.sendReviewReminders()).sent).toEqual([
      { tenantId, guestId: gina.identity.id, sponsorId: alice.id, dueAt: start + 30 * day },
    ]);
    expect((await f.iam.guests.sendReviewReminders()).sent).toEqual([]);
    // The review went unanswered; the access end nears and the sponsor hears about that too, once.
    f.advance(60 * day);
    await f.iam.purgeDeleted();
    expect((await f.iam.guests.sendReviewReminders()).sent).toEqual([
      { tenantId, guestId: gina.identity.id, sponsorId: alice.id, dueAt: start + 90 * day },
    ]);
    expect((await f.iam.guests.sendReviewReminders()).sent).toEqual([]);
    await f.iam.auth.dispatchOutbox();
    const reminders = f.inbox.filter((message) => message.template === 'guest-review');
    expect(reminders.map((message) => message.payload.dueAt)).toEqual([
      new Date(start + 30 * day).toISOString(),
      new Date(start + 90 * day).toISOString(),
    ]);
  });

  it('does not send again an invitation its sponsor or inviter can no longer stand behind', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const lead = await f.member('lead');
    const role = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Guest inviter',
      permissions: ['iam:guests:invite'],
    });
    const binding = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: lead.id,
    });
    const asLead = { token: (await f.signIn('lead')).token };
    const sponsored = await f.iam.api.guests.invite(owner, {
      tenantId,
      email: 'a@partner.test',
      sponsorId: alice.id,
      expiresInDays: 1,
    });
    const invited = await f.iam.api.guests.invite(asLead, {
      tenantId,
      email: 'b@partner.test',
      expiresInDays: 1,
    });
    await f.iam.auth.dispatchOutbox();
    f.inbox.length = 0;
    f.advance(2 * day);
    expect((await f.iam.guests.sweep()).invitationsExpired).toBe(2);
    const fresh = await f.ownerSignIn();
    // The sponsor left after the invitation lapsed.
    await f.iam.api.identities.setStatus(fresh, {
      tenantId,
      identityId: alice.id,
      status: 'disabled',
    });
    await expect(
      f.iam.api.guests.resendInvitation(fresh, { tenantId, invitationId: sponsored.id }),
    ).rejects.toMatchObject({ code: 'INVALID_SPONSOR' });
    await f.iam.api.identities.setStatus(fresh, {
      tenantId,
      identityId: alice.id,
      status: 'active',
    });
    // The inviter lost the right to invite guests.
    await f.iam.api.bindings.delete(fresh, { tenantId, bindingId: binding.id });
    await expect(
      f.iam.api.guests.resendInvitation(fresh, { tenantId, invitationId: invited.id }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    // Nothing was sent for either.
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.filter((message) => message.template === 'guest-invitation')).toEqual([]);
    // A sendable one still goes out, and redeems.
    await expect(
      f.iam.api.guests.resendInvitation(fresh, { tenantId, invitationId: sponsored.id }),
    ).resolves.toMatchObject({ status: 'pending' });
    await expect(redeemGuest(f, 'a@partner.test', 'Ann')).resolves.toMatchObject({
      identity: { guest: { sponsorId: alice.id } },
    });
  });

  it('grants a group once when the invitation names it directly and through a package', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const wiki = await f.iam.api.groups.create(owner, { tenantId, name: 'Wiki' });
    const viewer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewer',
      permissions: ['documents:read'],
    });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Partner kit',
      groupIds: [wiki.id],
      roleIds: [viewer.id],
    });
    await f.iam.api.guests.invite(owner, {
      tenantId,
      email: 'gina@partner.test',
      groupIds: [wiki.id],
      roleIds: [viewer.id],
      packageIds: [kit.id],
    });
    const gina = await redeemGuest(f, 'gina@partner.test', 'gina');
    const members = await f.database.find<GroupMember>('groupMembers', {
      tenantId,
      identityId: gina.identity.id,
    });
    expect(members.map((member) => member.groupId)).toEqual([wiki.id]);
    expect(
      (await f.iam.api.guests.get(owner, { tenantId, identityId: gina.identity.id })).accountStatus,
    ).toBe('active');
    const account = await f.database.get<GuestAccount>('guestAccounts', gina.identity.id);
    expect(account!.grants.packageAssignmentIds).toHaveLength(1);
    // Removal takes everything, whichever record holds it.
    const removal = await f.iam.api.guests.remove(owner, {
      tenantId,
      identityId: gina.identity.id,
      reason: 'done',
    });
    expect(removal.packages).toBe(1);
    expect(
      await f.database.find('groupMembers', { tenantId, identityId: gina.identity.id }),
    ).toEqual([]);
    expect(await f.database.find('bindings', { tenantId, subjectId: gina.identity.id })).toEqual(
      [],
    );
  });

  it('follows the tenant’s sign-in rules at redemption, and keeps the token out of storage', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    await f.iam.api.guests.invite(owner, { tenantId, email: 'gina@partner.test' });
    await f.iam.api.guests.invite(owner, { tenantId, email: 'hal@partner.test' });
    const token = await invitationToken(f, 'gina@partner.test');
    for (const collection of ['outbox', 'audit', 'guestInvitations'])
      expect(
        JSON.stringify(await f.database.find(collection, { tenantId })),
        collection,
      ).not.toContain(token);
    // A tenant that takes no passwords cannot seat a guest by password: nothing is left behind.
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId,
      authPolicy: { allowedMethods: ['passkey'] },
    });
    await expect(
      f.iam.api.guests.redeem({ tenantId, token, name: 'Gina', password: guestPassword('Gina') }),
    ).rejects.toMatchObject({ code: 'METHOD_NOT_ALLOWED' });
    expect(await f.database.find('identities', { tenantId, email: 'gina@partner.test' })).toEqual(
      [],
    );
    // Where MFA is required, the new guest enrolls a factor before a session is issued.
    await f.iam.api.tenants.setAuthPolicy(owner, { tenantId, authPolicy: { requireMfa: true } });
    const result = await f.iam.api.guests.redeem({
      tenantId,
      token,
      name: 'Gina',
      password: guestPassword('Gina'),
    });
    expect(result).toMatchObject({
      identity: { email: 'gina@partner.test', guest: { sponsorId: f.ownerId } },
      mfaRequired: true,
    });
    expect(result).not.toHaveProperty('token');
    expect(await f.database.get<GuestAccount>('guestAccounts', result.identity.id)).toMatchObject({
      status: 'active',
    });
  });

  it('pages and filters the guest directory', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const zed = await addGuest(f, 'zed', { accessDays: 5 });
    const amy = await addGuest(f, 'amy', { sponsorId: alice.id });
    const kai = await addGuest(f, 'kai', { accessDays: 20 });
    const ids = (page: { guests: Array<{ identityId: string }> }) =>
      page.guests.map((guest) => guest.identityId);
    const all = await f.iam.api.guests.list(owner, { tenantId });
    expect(ids(all)).toEqual([amy.identity.id, kai.identity.id, zed.identity.id]);
    expect(all.total).toBe(3);
    const page = await f.iam.api.guests.list(owner, { tenantId, limit: 1, offset: 1 });
    expect([ids(page), page.total]).toEqual([[kai.identity.id], 3]);
    expect(ids(await f.iam.api.guests.list(owner, { tenantId, sponsorId: alice.id }))).toEqual([
      amy.identity.id,
    ]);
    expect(ids(await f.iam.api.guests.list(owner, { tenantId, expiringWithinDays: 7 }))).toEqual([
      zed.identity.id,
    ]);
    expect(ids(await f.iam.api.guests.list(owner, { tenantId, expiringWithinDays: 30 }))).toEqual([
      kai.identity.id,
      zed.identity.id,
    ]);
    for (const input of [
      { limit: 0 },
      { limit: 1001 },
      { offset: -1 },
      { status: 'gone' },
      { sponsorId: '' },
      { expiringWithinDays: -1 },
    ])
      await expect(
        f.iam.api.guests.list(owner, { tenantId, ...input } as never),
        JSON.stringify(input),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    for (const input of [{ identityId: '' }, { identityId: 42 }])
      await expect(
        f.iam.api.guests.get(owner, { tenantId, ...input } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The sponsor's own list puts the soonest review first.
    const asOwner = f.ownerCredential;
    expect(
      (await f.iam.api.guests.mine(asOwner, { tenantId })).map((guest) => guest.identityId),
    ).toEqual([zed.identity.id, kai.identity.id]);
  });
});
