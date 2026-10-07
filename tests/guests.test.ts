import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import { renderDeliveryMessage } from '@better-iam/auth';
import { publicApiMethods, routeGroups } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';
import {
  addGuest,
  guestPassword,
  guestSignIn,
  invitationToken,
  redeemGuest,
} from './support/guests.js';

afterEach(closeFixtures);

const day = 86_400_000;

describe('guest invitations and redemption', () => {
  it('invites a person by email and turns the redeemed invitation into a signed-in guest', async () => {
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
    const invitedAt = f.now();
    const invitation = await f.iam.api.guests.invite(owner, {
      tenantId,
      email: 'Gina@Partner.test',
      sponsorId: alice.id,
      message: '  Welcome to the launch project  ',
      roleIds: [viewer.id, viewer.id],
      groupIds: [partners.id],
      accessDays: 30,
      expiresInDays: 7,
    });
    expect(invitation).toEqual({
      id: expect.any(String),
      tenantId,
      email: 'gina@partner.test',
      status: 'pending',
      sponsorId: alice.id,
      sponsorName: 'alice',
      invitedBy: f.ownerId,
      inviterName: 'Owner',
      message: 'Welcome to the launch project',
      roleIds: [viewer.id],
      groupIds: [partners.id],
      packageIds: [],
      accessDays: 30,
      expiresAt: invitedAt + 7 * day,
      createdAt: invitedAt,
      sentAt: invitedAt,
    });
    // Only the token's hash is stored; the address holds the pending slot.
    const [stored] = await f.database.find<{
      tokenHash: string;
      uniqueKey?: string;
    }>('guestInvitations', { tenantId });
    expect(stored!.uniqueKey).toBe('pending:gina@partner.test');

    // The invitee gets a personal email with the token.
    await f.iam.auth.dispatchOutbox();
    const email = f.inbox.find((message) => message.template === 'guest-invitation')!;
    expect(email).toMatchObject({ tenantId, to: 'gina@partner.test' });
    expect(email.payload).toEqual({
      tenantId,
      tenantName: 'Acme',
      inviterName: 'Owner',
      sponsorName: 'alice',
      message: 'Welcome to the launch project',
      token: expect.stringMatching(/^biam_gst_[A-Za-z0-9_-]{43}$/),
      expiresAt: new Date(invitedAt + 7 * day).toISOString(),
    });
    expect(stored!.tokenHash).not.toContain(email.payload.token!);
    const rendered = renderDeliveryMessage(email, {
      links: {
        guestInvitation: ({ tenantId: realm, token }) =>
          `https://app.example.test/guest?tenant=${realm}&token=${token}`,
      },
    })!;
    expect(rendered.subject).toBe('Owner invited you to join Acme as a guest');
    expect(rendered.text).toContain('alice sponsors your access.');
    expect(rendered.text).toContain('Welcome to the launch project');
    expect(rendered.text).toContain(`token=${email.payload.token}`);

    expect(await f.iam.api.guests.listInvitations(owner, { tenantId })).toEqual([invitation]);

    // Redemption creates the guest with a verified address, an access end and a sponsor, and signs them in.
    f.advance(60_000);
    const redeemedAt = f.now();
    const result = await f.iam.api.guests.redeem({
      tenantId,
      token: email.payload.token!,
      name: 'Gina',
      password: guestPassword('Gina'),
    });
    if (!('token' in result)) throw new Error('Unexpected MFA');
    expect(result.identity).toMatchObject({
      tenantId,
      kind: 'user',
      email: 'gina@partner.test',
      emailVerified: true,
      name: 'Gina',
      status: 'active',
      owner: false,
      expiresAt: redeemedAt + 30 * day,
      guest: { sponsorId: alice.id, since: redeemedAt, homeDomain: 'partner.test' },
    });
    expect(result.identity.guest).not.toHaveProperty('homeTenantId');
    expect(result.identity).not.toHaveProperty('passwordHash');
    expect(result.session).toMatchObject({ identityId: result.identity.id, method: 'password' });
    const guestId = result.identity.id;
    const gina = { token: result.token };

    // What the invitation granted lasts exactly as long as the guest's access.
    expect(
      (
        await f.iam.authorize({
          ...gina,
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'plan' },
        })
      ).allowed,
    ).toBe(true);
    const bindings = await f.iam.api.bindings.list(owner, { tenantId, subjectId: guestId });
    expect(bindings).toEqual([
      expect.objectContaining({ roleId: viewer.id, expiresAt: redeemedAt + 30 * day }),
    ]);
    const memberships = await f.database.find<{ groupId: string; expiresAt?: number }>(
      'groupMembers',
      { tenantId, identityId: guestId },
    );
    expect(memberships).toEqual([
      expect.objectContaining({ groupId: partners.id, expiresAt: redeemedAt + 30 * day }),
    ]);

    // The invitation is spent.
    const [redeemed] = await f.iam.api.guests.listInvitations(owner, { tenantId });
    expect(redeemed).toMatchObject({ status: 'redeemed', redeemedAt, identityId: guestId });
    const [spent] = await f.database.find<{ uniqueKey?: string }>('guestInvitations', {
      tenantId,
    });
    expect(spent).not.toHaveProperty('uniqueKey');
    await expect(
      f.iam.api.guests.redeem({
        tenantId,
        token: email.payload.token!,
        name: 'Gina again',
        password: guestPassword('Gina'),
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });

    // The guest signs in with the password they chose.
    f.advance(60_000);
    const signedInAt = f.now();
    await guestSignIn(f, 'gina@partner.test', 'Gina');
    const view = await f.iam.api.guests.get(owner, { tenantId, identityId: guestId });
    expect(view).toEqual({
      identityId: guestId,
      tenantId,
      name: 'Gina',
      email: 'gina@partner.test',
      status: 'active',
      accountStatus: 'active',
      sponsorId: alice.id,
      sponsorName: 'alice',
      sponsorMissing: false,
      homeDomain: 'partner.test',
      invitationId: invitation.id,
      invitedBy: f.ownerId,
      redeemedAt,
      reviewDueAt: redeemedAt + 30 * day,
      expiresAt: redeemedAt + 30 * day,
      lastSignInAt: signedInAt,
    });
    expect(await f.iam.api.guests.list(owner, { tenantId })).toEqual({ guests: [view], total: 1 });
    // The sponsor sees the guests they vouch for without any permission; others see none.
    const asAlice = { token: (await f.signIn('alice')).token };
    expect(await f.iam.api.guests.mine(asAlice, { tenantId })).toEqual([view]);
    expect(await f.iam.api.guests.mine(owner, { tenantId })).toEqual([]);

    // Everything is audited.
    const events = await f.database.find<AuditEvent>('audit', { tenantId });
    expect(events.find((event) => event.action === 'guest:invite')).toMatchObject({
      actorId: f.ownerId,
      resourceId: invitation.id,
      outcome: 'allow',
      metadata: {
        email: 'gina@partner.test',
        sponsorId: alice.id,
        roleIds: [viewer.id],
        groupIds: [partners.id],
        packageIds: [],
        accessDays: 30,
        expiresAt: invitedAt + 7 * day,
      },
    });
    expect(events.find((event) => event.action === 'guest:redeem')).toMatchObject({
      actorId: guestId,
      resourceId: guestId,
      outcome: 'allow',
      metadata: {
        invitationId: invitation.id,
        invitedBy: f.ownerId,
        sponsorId: alice.id,
        roleIds: [viewer.id],
        groupIds: [partners.id],
        packageIds: [],
        expiresAt: redeemedAt + 30 * day,
      },
    });
    for (const action of ['iam:guests:invite', 'iam:guests:read'])
      expect(
        events.some((event) => event.action === action && event.outcome === 'allow'),
        action,
      ).toBe(true);
  });

  it('redeems over HTTP as a public route whose session becomes the browser session', async () => {
    const f = await organizationFixture();
    expect(routeGroups.has('guests')).toBe(true);
    expect(publicApiMethods.has('guests/redeem')).toBe(true);
    const invitation = await f.iam.api.guests.invite(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'hana@partner.test',
    });
    const post = (method: string, body: unknown, token?: string) =>
      f.iam.handler(
        new Request(`http://localhost:3000/api/iam/guests/${method}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-better-iam': '1',
            ...(token ? { authorization: `Bearer ${token}` } : {}),
          },
          body: JSON.stringify(body),
        }),
      );
    const response = await post('redeem', {
      tenantId: f.tenantId,
      token: await invitationToken(f, 'hana@partner.test'),
      name: 'Hana',
      password: guestPassword('Hana'),
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('set-cookie')).toMatch(/better-iam/);
    const { data } = (await response.json()) as {
      data: { token: string; identity: { id: string; guest?: { sponsorId: string } } };
    };
    expect(data.identity.guest).toMatchObject({ sponsorId: f.ownerId });
    expect(
      (
        await f.iam.api.guests.get(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: data.identity.id,
        })
      ).invitationId,
    ).toBe(invitation.id);
    // Every other method needs a credential over HTTP too.
    const listed = await post('list', { tenantId: f.tenantId });
    expect(listed.status).toBe(401);
    const mine = await post('mine', { tenantId: f.tenantId }, data.token);
    expect(mine.status).toBe(200);
    expect(((await mine.json()) as { data: unknown }).data).toEqual([]);
    const byOwner = await post('list', { tenantId: f.tenantId }, f.ownerCredential.token);
    expect(((await byOwner.json()) as { data: { total: number } }).data.total).toBe(1);
  });

  it('validates what an invitation asks for', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const invite = (input: Record<string, unknown>) =>
      f.iam.api.guests.invite(owner, { tenantId, email: 'val@partner.test', ...input } as never);
    for (const input of [
      { email: 'not an address' },
      { email: 42 },
      { accessDays: 0 },
      { accessDays: 366 },
      { accessDays: 1.5 },
      { expiresInDays: 0 },
      { expiresInDays: 31 },
      { message: 'x'.repeat(1001) },
      { roleIds: 'role' },
      { groupIds: [42] },
      { packageIds: {} },
    ])
      await expect(invite(input), JSON.stringify(input)).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
    await expect(invite({ roleIds: ['missing'] })).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(invite({ groupIds: ['missing'] })).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(invite({ packageIds: ['missing'] })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    // Protected roles pass by ownership transfer only; team backing groups by the team.
    const [ownerRole] = await f.database.find<{ id: string }>('roles', {
      tenantId,
      uniqueKey: 'system:owner',
    });
    await expect(invite({ roleIds: [ownerRole!.id] })).rejects.toMatchObject({
      code: 'PROTECTED_RESOURCE',
      status: 403,
    });
    const team = await f.iam.api.teams.create(owner, { tenantId, name: 'Launch' });
    await expect(invite({ groupIds: [team.groupId] })).rejects.toMatchObject({
      code: 'TEAM_MANAGED',
    });
    // Sponsors are active members who are not guests.
    const guest = await addGuest(f, 'gus');
    const bob = await f.member('bob');
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: bob.id,
      status: 'disabled',
    });
    for (const sponsorId of [guest.identity.id, bob.id, 'missing', ''])
      await expect(invite({ sponsorId }), sponsorId).rejects.toMatchObject({
        code: sponsorId === '' ? 'INVALID_INPUT' : 'INVALID_SPONSOR',
      });
    // An address that already belongs to someone here, or already has a pending invitation.
    for (const email of ['alice@acme.test', 'gus@partner.test', 'GUS@partner.test'])
      await expect(invite({ email }), email).rejects.toMatchObject({
        code: 'CONFLICT',
        status: 409,
      });
    await invite({ sponsorId: alice.id });
    await expect(invite({})).rejects.toMatchObject({ code: 'CONFLICT', status: 409 });
    // The platform tenant takes no guests.
    await expect(
      f.iam.api.guests.invite(f.rootCredential, {
        tenantId: f.root.tenant.id,
        email: 'someone@partner.test',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Nothing was sent for the refused invitations.
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox.filter((message) => message.template === 'guest-invitation').map((m) => m.to),
    ).toEqual(['gus@partner.test', 'val@partner.test']);
    expect(await f.iam.api.guests.listInvitations(owner, { tenantId, status: 'pending' })).toEqual([
      expect.objectContaining({ email: 'val@partner.test', sponsorId: alice.id }),
    ]);
  });

  it('checks the redemption itself', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    await f.iam.api.guests.invite(f.ownerCredential, { tenantId, email: 'ivy@partner.test' });
    const token = await invitationToken(f, 'ivy@partner.test');
    const redeem = (input: Record<string, unknown>) =>
      f.iam.api.guests.redeem({
        tenantId,
        token,
        name: 'Ivy',
        password: guestPassword('Ivy'),
        ...input,
      } as never);
    for (const input of [{ name: '' }, { password: undefined }, { password: 42 }, { token: '' }])
      await expect(redeem(input), JSON.stringify(input)).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
    await expect(redeem({ password: 'short' })).rejects.toMatchObject({ status: 400 });
    await expect(redeem({ token: 'biam_gst_unknown' })).rejects.toMatchObject({
      code: 'INVITATION_INVALID',
    });
    await expect(redeem({ tenantId: 'missing' })).rejects.toMatchObject({ status: 404 });
    // A refused redemption leaves no trace behind: the invitation still works.
    expect(await f.database.find('identities', { tenantId, email: 'ivy@partner.test' })).toEqual(
      [],
    );
    const result = await redeem({});
    expect(result.identity.email).toBe('ivy@partner.test');
  });
});

describe('guest lifecycle', () => {
  it('revokes, resends and lapses invitations', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const first = await f.iam.api.guests.invite(owner, { tenantId, email: 'jo@partner.test' });
    const firstToken = await invitationToken(f, 'jo@partner.test');
    const revoked = await f.iam.api.guests.revokeInvitation(owner, {
      tenantId,
      invitationId: first.id,
    });
    expect(revoked).toMatchObject({ status: 'revoked', revokedAt: f.now(), revokedBy: f.ownerId });
    await expect(
      f.iam.api.guests.redeem({
        tenantId,
        token: firstToken,
        name: 'Jo',
        password: guestPassword('Jo'),
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    for (const call of [
      () => f.iam.api.guests.revokeInvitation(owner, { tenantId, invitationId: first.id }),
      () => f.iam.api.guests.resendInvitation(owner, { tenantId, invitationId: first.id }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'INVALID_TRANSITION', status: 409 });
    for (const call of [
      () => f.iam.api.guests.revokeInvitation(owner, { tenantId, invitationId: 'missing' }),
      () => f.iam.api.guests.resendInvitation(owner, { tenantId, invitationId: 'missing' }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // Revoking frees the address for a new invitation; sending again rotates its token.
    const second = await f.iam.api.guests.invite(owner, { tenantId, email: 'jo@partner.test' });
    const oldToken = await invitationToken(f, 'jo@partner.test');
    f.advance(day);
    const resent = await f.iam.api.guests.resendInvitation(owner, {
      tenantId,
      invitationId: second.id,
      expiresInDays: 3,
    });
    expect(resent).toMatchObject({
      id: second.id,
      status: 'pending',
      createdAt: second.createdAt,
      sentAt: f.now(),
      expiresAt: f.now() + 3 * day,
    });
    const newToken = await invitationToken(f, 'jo@partner.test');
    expect(newToken).not.toBe(oldToken);
    await expect(
      f.iam.api.guests.redeem({
        tenantId,
        token: oldToken,
        name: 'Jo',
        password: guestPassword('Jo'),
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    for (const expiresInDays of [0, 31])
      await expect(
        f.iam.api.guests.resendInvitation(owner, {
          tenantId,
          invitationId: second.id,
          expiresInDays,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // A lapsed invitation reads as expired at once, cannot be redeemed, and can be sent again.
    f.advance(3 * day);
    expect(
      (await f.iam.api.guests.listInvitations(owner, { tenantId, status: 'expired' })).map(
        (invitation) => invitation.id,
      ),
    ).toEqual([second.id]);
    await expect(
      f.iam.api.guests.redeem({
        tenantId,
        token: newToken,
        name: 'Jo',
        password: guestPassword('Jo'),
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    const again = await f.iam.api.guests.resendInvitation(owner, {
      tenantId,
      invitationId: second.id,
    });
    expect(again).toMatchObject({ status: 'pending', expiresAt: f.now() + 14 * day });
    const guest = await redeemGuest(f, 'jo@partner.test', 'Jo');
    expect(guest.identity.guest?.sponsorId).toBe(f.ownerId);
    // A redeemed invitation is neither revoked nor sent again.
    await expect(
      f.iam.api.guests.revokeInvitation(owner, { tenantId, invitationId: second.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await expect(
      f.iam.api.guests.resendInvitation(owner, { tenantId, invitationId: second.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });

    // A new invitation to a lapsed address takes over its pending slot.
    await f.iam.api.guests.invite(owner, { tenantId, email: 'kim@partner.test', expiresInDays: 1 });
    f.advance(2 * day);
    const kim = await f.iam.api.guests.invite(owner, { tenantId, email: 'kim@partner.test' });
    const statuses = (await f.iam.api.guests.listInvitations(owner, { tenantId }))
      .filter((invitation) => invitation.email === 'kim@partner.test')
      .map((invitation) => [invitation.id === kim.id, invitation.status]);
    expect(statuses).toEqual([
      [true, 'pending'],
      [false, 'expired'],
    ]);
    await expect(
      f.iam.api.guests.listInvitations(owner, { tenantId, status: 'lost' as never }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    const trail = (await f.database.find<AuditEvent>('audit', { tenantId }))
      .filter((event) => event.action.startsWith('guest:invitation-'))
      .map((event) => event.action)
      .sort();
    expect(trail).toEqual([
      'guest:invitation-resend',
      'guest:invitation-resend',
      'guest:invitation-revoke',
    ]);
  });
});
