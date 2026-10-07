import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';
import {
  addGuest,
  administrator,
  guestPassword,
  invitationToken,
  otherOrganization,
  redeemGuest,
  verifyDomain,
} from './support/guests.js';

afterEach(closeFixtures);

const day = 86_400_000;

describe('guest permissions', () => {
  it('keeps every method to its action, and the sensitive ones to a recent sign-in', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const guest = await addGuest(f, 'gina');
    const [invitation] = await f.iam.api.guests.listInvitations(owner, { tenantId });
    await f.iam.api.guests.invite(owner, { tenantId, email: 'pending@partner.test' });
    const [pending] = await f.iam.api.guests.listInvitations(owner, {
      tenantId,
      status: 'pending',
    });
    await f.member('mallory');
    const mallory = { token: (await f.signIn('mallory')).token };
    const bob = await f.member('bob');
    const calls: Record<string, (credential: { token: string }) => Promise<unknown>> = {
      invite: (c) => f.iam.api.guests.invite(c, { tenantId, email: 'new@partner.test' }),
      listInvitations: (c) => f.iam.api.guests.listInvitations(c, { tenantId }),
      revokeInvitation: (c) =>
        f.iam.api.guests.revokeInvitation(c, { tenantId, invitationId: pending!.id }),
      resendInvitation: (c) =>
        f.iam.api.guests.resendInvitation(c, { tenantId, invitationId: pending!.id }),
      list: (c) => f.iam.api.guests.list(c, { tenantId }),
      get: (c) => f.iam.api.guests.get(c, { tenantId, identityId: guest.identity.id }),
      attest: (c) => f.iam.api.guests.attest(c, { tenantId, identityId: guest.identity.id }),
      setSponsor: (c) =>
        f.iam.api.guests.setSponsor(c, {
          tenantId,
          identityId: guest.identity.id,
          sponsorId: bob.id,
        }),
      remove: (c) =>
        f.iam.api.guests.remove(c, { tenantId, identityId: guest.identity.id, reason: 'x' }),
      convertToMember: (c) =>
        f.iam.api.guests.convertToMember(c, { tenantId, identityId: guest.identity.id }),
      getSettings: (c) => f.iam.api.guests.getSettings(c, { tenantId }),
      configure: (c) =>
        f.iam.api.guests.configure(c, { tenantId, inbound: { allowGuests: false } }),
    };
    // A member without permissions, and the guest itself, are refused everything but their own list.
    for (const credential of [mallory, guest.credential])
      for (const [name, call] of Object.entries(calls))
        await expect(call(credential), name).rejects.toMatchObject({
          code: 'ACCESS_DENIED',
          status: 403,
        });
    expect(await f.iam.api.guests.mine(mallory, { tenantId })).toEqual([]);
    expect(await f.iam.api.guests.mine(guest.credential, { tenantId })).toEqual([]);
    const denials = (await f.database.find<AuditEvent>('audit', { tenantId }))
      .filter((event) => event.outcome === 'deny' && event.action.startsWith('iam:guests:'))
      .map((event) => event.action);
    for (const action of [
      'iam:guests:invite',
      'iam:guests:read',
      'iam:guests:manage',
      'iam:guests:settings',
    ])
      expect(denials, action).toContain(action);

    // Each action opens only its methods.
    const reader = await administrator(f, 'reader', ['iam:guests:read']);
    const inviter = await administrator(f, 'inviter', ['iam:guests:invite']);
    const settings = await administrator(f, 'settings', ['iam:guests:settings']);
    for (const name of ['listInvitations', 'list', 'get', 'getSettings'])
      await expect(calls[name]!(reader.credential), name).resolves.toBeDefined();
    for (const name of ['invite', 'resendInvitation', 'revokeInvitation', 'attest', 'configure'])
      await expect(calls[name]!(reader.credential), name).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
      });
    await expect(calls.resendInvitation!(inviter.credential)).resolves.toMatchObject({
      status: 'pending',
      invitedBy: f.ownerId,
    });
    for (const name of ['revokeInvitation', 'list', 'configure'])
      await expect(calls[name]!(inviter.credential), name).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
      });
    await expect(calls.configure!(settings.credential)).resolves.toMatchObject({
      inbound: { allowGuests: false },
    });
    await expect(calls.list!(settings.credential)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.api.guests.configure(settings.credential, {
      tenantId,
      inbound: { allowGuests: true },
    });

    // Past five minutes the settings, sponsor changes, removal and conversion want a fresh sign-in.
    f.advance(6 * 60_000);
    for (const name of ['configure', 'setSponsor', 'remove', 'convertToMember'])
      await expect(calls[name]!(owner), name).rejects.toMatchObject({
        code: 'RECENT_AUTH_REQUIRED',
      });
    await expect(calls.invite!(owner)).resolves.toMatchObject({ email: 'new@partner.test' });
    await expect(calls.attest!(owner)).resolves.toMatchObject({ attestedBy: f.ownerId });
    await expect(calls.revokeInvitation!(owner)).resolves.toMatchObject({ status: 'revoked' });
    const fresh = await f.ownerSignIn();
    await expect(calls.setSponsor!(fresh)).resolves.toMatchObject({ sponsorId: bob.id });
    await expect(calls.convertToMember!(fresh)).resolves.toMatchObject({
      id: guest.identity.id,
    });
    expect(invitation!.identityId).toBe(guest.identity.id);
  });

  it('lets delegated administrators invite only what they could grant themselves', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const viewer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewer',
      permissions: ['documents:read'],
    });
    const editor = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Editor',
      permissions: ['documents:write'],
    });
    const partners = await f.iam.api.groups.create(owner, { tenantId, name: 'Partners' });
    const staff = await f.iam.api.groups.create(owner, { tenantId, name: 'Staff' });
    const lead = await f.member('lead');
    const role = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Guest inviter',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['iam:guests:invite'], resources: ['iam/guests/*'] },
          { effect: 'allow', actions: ['iam:bindings:create'], resources: [`iam/${viewer.id}`] },
          { effect: 'allow', actions: ['iam:groups:update'], resources: [`iam/${partners.id}`] },
        ],
      },
    });
    const leadBinding = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: lead.id,
    });
    const asLead = { token: (await f.signIn('lead')).token };
    // Roles need a grant authority of their own; plain invitations do not.
    await expect(
      f.iam.api.guests.invite(asLead, { tenantId, email: 'a@partner.test', roleIds: [viewer.id] }),
    ).rejects.toMatchObject({ code: 'GRANT_AUTHORITY_REQUIRED' });
    await expect(
      f.iam.api.guests.invite(asLead, { tenantId, email: 'plain@partner.test' }),
    ).resolves.toMatchObject({ sponsorId: lead.id, invitedBy: lead.id });
    await f.iam.api.authorities.create(owner, {
      tenantId,
      identityId: lead.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    await expect(
      f.iam.api.guests.invite(asLead, { tenantId, email: 'b@partner.test', roleIds: [editor.id] }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.guests.invite(asLead, { tenantId, email: 'b@partner.test', groupIds: [staff.id] }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const granted = await f.iam.api.guests.invite(asLead, {
      tenantId,
      email: 'c@partner.test',
      roleIds: [viewer.id],
      groupIds: [partners.id],
    });
    const second = await f.iam.api.guests.invite(asLead, {
      tenantId,
      email: 'd@partner.test',
      roleIds: [viewer.id],
    });
    const guest = await redeemGuest(f, 'c@partner.test', 'Cara');
    const [binding] = await f.iam.api.bindings.list(owner, {
      tenantId,
      subjectId: guest.identity.id,
    });
    const [authority] = await f.database.find<{ id: string }>('grantAuthorities', {
      tenantId,
      identityId: lead.id,
    });
    expect(binding).toMatchObject({ roleId: viewer.id, authorityId: authority!.id });
    expect(granted.invitedBy).toBe(lead.id);

    // Redemption checks the inviter's rights again: without them the invitation grants nothing.
    await f.iam.api.bindings.delete(owner, { tenantId, bindingId: leadBinding.id });
    const token = await invitationToken(f, 'd@partner.test');
    await expect(
      f.iam.api.guests.redeem({ tenantId, token, name: 'Dee', password: guestPassword('Dee') }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    expect(
      (await f.iam.api.guests.listInvitations(owner, { tenantId })).find(
        (invitation) => invitation.id === second.id,
      )?.status,
    ).toBe('pending');
  });

  it('refuses invitations made while impersonating, and lets root administrators name a sponsor', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const admin = await administrator(f, 'admin', ['iam:guests:invite']);
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const session = await f.iam.api.identities.impersonate(f.ownerCredential, {
      tenantId,
      identityId: admin.identity.id,
      reason: 'support',
    });
    await expect(
      f.iam.api.guests.invite({ token: session.token }, { tenantId, email: 'x@partner.test' }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.some((message) => message.template === 'guest-invitation')).toBe(false);
    // A root administrator is no member of the organization, so cannot vouch for a guest: it names a sponsor.
    await expect(
      f.iam.api.guests.invite(f.rootCredential, { tenantId, email: 'y@partner.test' }),
    ).rejects.toMatchObject({ code: 'INVALID_SPONSOR' });
    const viewer = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Viewer',
      permissions: ['documents:read'],
    });
    const invitation = await f.iam.api.guests.invite(f.rootCredential, {
      tenantId,
      email: 'y@partner.test',
      sponsorId: admin.identity.id,
      roleIds: [viewer.id],
    });
    expect(invitation).toMatchObject({ sponsorId: admin.identity.id, inviterName: 'Root' });
    const guest = await redeemGuest(f, 'y@partner.test', 'Yuri');
    expect(guest.identity.guest?.sponsorId).toBe(admin.identity.id);
    expect(
      await f.iam.api.bindings.list(f.ownerCredential, { tenantId, subjectId: guest.identity.id }),
    ).toEqual([expect.objectContaining({ roleId: viewer.id })]);
  });
});

describe('guest tenant isolation', () => {
  it('keeps one organization from reading or acting on another one’s guests', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const globex = await otherOrganization(f, 'Globex', 'globex');
    const guest = await addGuest(f, 'gina');
    const [invitation] = await f.iam.api.guests.listInvitations(f.ownerCredential, { tenantId });
    await f.iam.api.guests.invite(f.ownerCredential, { tenantId, email: 'open@partner.test' });
    const [pending] = await f.iam.api.guests.listInvitations(f.ownerCredential, {
      tenantId,
      status: 'pending',
    });
    const other = globex.ownerCredential;
    // Naming Acme from a Globex session is refused outright.
    for (const call of [
      () => f.iam.api.guests.list(other, { tenantId }),
      () => f.iam.api.guests.get(other, { tenantId, identityId: guest.identity.id }),
      () => f.iam.api.guests.listInvitations(other, { tenantId }),
      () => f.iam.api.guests.invite(other, { tenantId, email: 'z@partner.test' }),
      () => f.iam.api.guests.attest(other, { tenantId, identityId: guest.identity.id }),
      () => f.iam.api.guests.getSettings(other, { tenantId }),
      () => f.iam.api.guests.configure(other, { tenantId, accessDays: 1 }),
      () =>
        f.iam.api.guests.remove(other, { tenantId, identityId: guest.identity.id, reason: 'x' }),
    ])
      await expect(call()).rejects.toMatchObject({ status: 403 });
    await expect(f.iam.api.guests.mine(other, { tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // Acme's records are unknown inside Globex.
    const at = globex.tenantId;
    for (const call of [
      () => f.iam.api.guests.get(other, { tenantId: at, identityId: guest.identity.id }),
      () => f.iam.api.guests.attest(other, { tenantId: at, identityId: guest.identity.id }),
      () =>
        f.iam.api.guests.setSponsor(other, {
          tenantId: at,
          identityId: guest.identity.id,
          sponsorId: globex.ownerId,
        }),
      () =>
        f.iam.api.guests.remove(other, {
          tenantId: at,
          identityId: guest.identity.id,
          reason: 'x',
        }),
      () =>
        f.iam.api.guests.convertToMember(other, { tenantId: at, identityId: guest.identity.id }),
      () => f.iam.api.guests.revokeInvitation(other, { tenantId: at, invitationId: pending!.id }),
      () => f.iam.api.guests.resendInvitation(other, { tenantId: at, invitationId: pending!.id }),
    ])
      await expect(call()).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(await f.iam.api.guests.list(other, { tenantId: at })).toEqual({ guests: [], total: 0 });
    expect(await f.iam.api.guests.listInvitations(other, { tenantId: at })).toEqual([]);
    // A member of another organization sponsors nobody here, and an Acme token redeems nothing in Globex.
    await expect(
      f.iam.api.guests.setSponsor(await f.ownerSignIn(), {
        tenantId,
        identityId: guest.identity.id,
        sponsorId: globex.ownerId,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_SPONSOR' });
    await expect(
      f.iam.api.guests.invite(f.ownerCredential, {
        tenantId,
        email: 'w@partner.test',
        sponsorId: globex.ownerId,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_SPONSOR' });
    await expect(
      f.iam.api.guests.redeem({
        tenantId: at,
        token: await invitationToken(f, 'open@partner.test'),
        name: 'Open',
        password: guestPassword('Open'),
      }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
    // The guest's session is Acme's only.
    await expect(f.iam.api.guests.mine(guest.credential, { tenantId: at })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // Nothing changed in Acme.
    expect(
      await f.iam.api.guests.get(f.ownerCredential, { tenantId, identityId: guest.identity.id }),
    ).toMatchObject({
      sponsorId: f.ownerId,
      accountStatus: 'active',
      invitationId: invitation!.id,
    });
    expect(
      (await f.iam.api.guests.listInvitations(f.ownerCredential, { tenantId, status: 'pending' }))
        .length,
    ).toBe(1);
  });
});

describe('cross-tenant access settings', () => {
  it('defaults to open, validates changes, and audits them', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const globex = await otherOrganization(f, 'Globex', 'globex');
    expect(await f.iam.api.guests.getSettings(f.ownerCredential, { tenantId })).toEqual({
      tenantId,
      configured: false,
      inbound: { allowGuests: true, allowedDomains: [], blockedDomains: [], partners: [] },
      outbound: { allowGuestInvitations: true, partners: [] },
      accessDays: 90,
      reviewEveryDays: 90,
    });
    const configure = (input: Record<string, unknown>) =>
      f.iam.api.guests.configure(f.ownerCredential, { tenantId, ...input } as never);
    for (const input of [
      {},
      { inbound: {} },
      { inbound: 'open' },
      { inbound: { allowGuests: 'yes' } },
      { inbound: { colour: 'blue' } },
      { inbound: { allowedDomains: 'partner.test' } },
      { inbound: { allowedDomains: ['not a domain'] } },
      { inbound: { blockedDomains: ['http://partner.test'] } },
      { inbound: { partners: [{ tenantId }] } },
      { inbound: { partners: [{ tenantId, allow: true }] } },
      { inbound: { partners: [{ tenantId: 'missing', allow: true }] } },
      { inbound: { partners: [{ tenantId: globex.tenantId, allow: 'yes' }] } },
      { inbound: { partners: [{ tenantId: globex.tenantId, allow: true, note: 'x' }] } },
      {
        inbound: {
          partners: [
            { tenantId: globex.tenantId, allow: true },
            { tenantId: globex.tenantId, allow: false },
          ],
        },
      },
      { outbound: { allowGuestInvitations: 1 } },
      { outbound: { allowGuests: true } },
      { outbound: { partners: [{ tenantId: f.root.tenant.id + 'x', allow: true }] } },
      { accessDays: 0 },
      { accessDays: 366 },
      { reviewEveryDays: 6 },
      { reviewEveryDays: 366 },
      { colour: 'blue', accessDays: 5 },
    ])
      await expect(configure(input), JSON.stringify(input)).rejects.toMatchObject({
        code: 'INVALID_INPUT',
      });
    // The boundary is checked like any policy, actions included.
    await expect(
      configure({ guestBoundary: { version: 1, statements: 'none' } }),
    ).rejects.toMatchObject({ code: 'INVALID_POLICY' });
    await expect(
      configure({
        guestBoundary: {
          version: 1,
          statements: [{ effect: 'allow', actions: ['documents:shred'], resources: ['*'] }],
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    const boundary = {
      version: 1 as const,
      statements: [
        { effect: 'allow' as const, actions: ['documents:read'], resources: ['document/shared-*'] },
      ],
    };
    const configured = await configure({
      inbound: {
        allowedDomains: ['Partner.test', 'partner.test', 'agency.test'],
        partners: [{ tenantId: globex.tenantId, allow: true }],
      },
      outbound: { partners: [{ tenantId: globex.tenantId, allow: false }] },
      accessDays: 30,
      reviewEveryDays: 14,
      guestBoundary: boundary,
    });
    expect(configured).toEqual({
      tenantId,
      configured: true,
      inbound: {
        allowGuests: true,
        allowedDomains: ['agency.test', 'partner.test'],
        blockedDomains: [],
        partners: [{ tenantId: globex.tenantId, allow: true }],
      },
      outbound: {
        allowGuestInvitations: true,
        partners: [{ tenantId: globex.tenantId, allow: false }],
      },
      accessDays: 30,
      reviewEveryDays: 14,
      guestBoundary: boundary,
      updatedAt: f.now(),
      updatedBy: f.ownerId,
    });
    expect(await f.iam.api.guests.getSettings(f.ownerCredential, { tenantId })).toEqual(configured);
    // Only the fields given change, inside inbound and outbound too; null removes the boundary.
    const next = await configure({ inbound: { allowGuests: false }, guestBoundary: null });
    expect(next.inbound).toEqual({ ...configured.inbound, allowGuests: false });
    expect(next.outbound).toEqual(configured.outbound);
    expect(next).not.toHaveProperty('guestBoundary');
    expect(next.accessDays).toBe(30);
    const [latest] = (await f.database.find<AuditEvent>('audit', { tenantId }))
      .filter((event) => event.action === 'guest:settings')
      .sort((a, b) => b.sequence! - a.sequence!);
    expect(latest).toMatchObject({
      actorId: f.ownerId,
      resourceId: tenantId,
      metadata: {
        changed: ['inbound.allowGuests', 'guestBoundary'],
        allowGuests: false,
        allowedDomains: ['agency.test', 'partner.test'],
        inboundPartners: [{ tenantId: globex.tenantId, allow: true }],
        outboundPartners: [{ tenantId: globex.tenantId, allow: false }],
        guestBoundary: false,
      },
    });
    // A root administrator may configure any organization, with a recent sign-in.
    expect(
      await f.iam.api.guests.configure(f.rootCredential, {
        tenantId: globex.tenantId,
        accessDays: 10,
      }),
    ).toMatchObject({ tenantId: globex.tenantId, accessDays: 10, configured: true });
    // The tenant's durations shape new guests.
    await configure({ inbound: { allowGuests: true } });
    const guest = await addGuest(f, 'gina');
    expect(guest.identity.expiresAt).toBe(f.now() + 30 * day);
    expect(guest.invitation.accessDays).toBe(30);
    expect(
      (await f.iam.api.guests.get(f.ownerCredential, { tenantId, identityId: guest.identity.id }))
        .reviewDueAt,
    ).toBe(f.now() + 14 * day);
  });

  it('admits guests only as the host’s inbound settings allow', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const globex = await otherOrganization(f, 'Globex', 'globex');
    await verifyDomain(f, globex.tenantId, 'globex.test');
    await verifyDomain(f, tenantId, 'acme.example');
    const configure = (input: Record<string, unknown>) =>
      f.iam.api.guests.configure(f.ownerCredential, { tenantId, ...input } as never);
    const invite = (email: string) =>
      f.iam.api.guests.invite(f.ownerCredential, { tenantId, email });
    const refused = (email: string, message?: string) =>
      expect(invite(email), email).rejects.toMatchObject({
        code: 'GUEST_NOT_ALLOWED',
        status: 403,
        ...(message ? { message } : {}),
      });
    // An address at the host's own verified domain belongs to a member.
    await refused(
      'someone@acme.example',
      'acme.example is a verified domain of this organization: invite the person as a member',
    );

    await configure({ inbound: { allowGuests: false } });
    await refused('a@partner.test', 'This organization does not accept guests');
    await configure({
      inbound: {
        allowGuests: true,
        allowedDomains: ['partner.test'],
        blockedDomains: ['bad.partner.test'],
      },
    });
    await refused(
      'a@agency.test',
      'This organization accepts guests only from its allowed domains',
    );
    await refused(
      'a@bad.partner.test',
      'This organization does not accept guests from bad.partner.test',
    );
    await refused('a@deeper.bad.partner.test');
    await expect(invite('a@sub.partner.test')).resolves.toMatchObject({ status: 'pending' });
    await expect(invite('b@partner.test')).resolves.toMatchObject({ status: 'pending' });
    // A partner entry admits its people over the defaults, and a refusing one wins over everything else.
    await refused('c@globex.test');
    await configure({
      inbound: { allowGuests: false, partners: [{ tenantId: globex.tenantId, allow: true }] },
    });
    await expect(invite('c@globex.test')).resolves.toMatchObject({ homeTenantId: globex.tenantId });
    await refused('d@partner.test');
    await configure({
      inbound: {
        allowGuests: true,
        allowedDomains: [],
        partners: [{ tenantId: globex.tenantId, allow: false }],
      },
    });
    await refused(
      'e@globex.test',
      'This organization does not accept guests from the person’s organization',
    );
    await configure({
      inbound: {
        partners: [{ tenantId: globex.tenantId, allow: true }],
        blockedDomains: ['globex.test'],
      },
    });
    await refused('e@globex.test', 'This organization does not accept guests from globex.test');

    // Redemption checks the settings again.
    await configure({ inbound: { blockedDomains: [], allowGuests: true, partners: [] } });
    await invite('late@partner.test');
    await configure({ inbound: { blockedDomains: ['partner.test'] } });
    await expect(
      f.iam.api.guests.redeem({
        tenantId,
        token: await invitationToken(f, 'late@partner.test'),
        name: 'Late',
        password: guestPassword('Late'),
      }),
    ).rejects.toMatchObject({ code: 'GUEST_NOT_ALLOWED' });
    await configure({ inbound: { blockedDomains: [] } });
    await expect(redeemGuest(f, 'late@partner.test', 'Late')).resolves.toMatchObject({
      identity: { email: 'late@partner.test' },
    });
  });

  it('respects the home organization’s outbound settings without revealing them', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const globex = await otherOrganization(f, 'Globex', 'globex');
    const initech = await otherOrganization(f, 'Initech', 'initech');
    await verifyDomain(f, globex.tenantId, 'globex.test');
    const outbound = (input: Record<string, unknown>) =>
      f.iam.api.guests.configure(globex.ownerCredential, {
        tenantId: globex.tenantId,
        outbound: input,
      });
    const message =
      'The person’s organization does not allow its members to join this organization as guests';
    await outbound({ allowGuestInvitations: false });
    await expect(
      f.iam.api.guests.invite(f.ownerCredential, { tenantId, email: 'gil@globex.test' }),
    ).rejects.toMatchObject({ code: 'GUEST_NOT_ALLOWED', status: 403, message });
    // A partner entry for the host lets its people join there (and only there).
    await outbound({ partners: [{ tenantId, allow: true }] });
    const invitation = await f.iam.api.guests.invite(f.ownerCredential, {
      tenantId,
      email: 'gil@globex.test',
    });
    expect(invitation.homeTenantId).toBe(globex.tenantId);
    await expect(
      f.iam.api.guests.invite(initech.ownerCredential, {
        tenantId: initech.tenantId,
        email: 'gil@globex.test',
      }),
    ).rejects.toMatchObject({ code: 'GUEST_NOT_ALLOWED', message });
    // The home organization can change its mind before redemption.
    await outbound({ partners: [{ tenantId, allow: false }], allowGuestInvitations: true });
    const token = await invitationToken(f, 'gil@globex.test');
    await expect(
      f.iam.api.guests.redeem({ tenantId, token, name: 'Gil', password: guestPassword('Gil') }),
    ).rejects.toMatchObject({ code: 'GUEST_NOT_ALLOWED', message });
    await outbound({ partners: [] });
    const guest = await f.iam.api.guests.redeem({
      tenantId,
      token,
      name: 'Gil',
      password: guestPassword('Gil'),
    });
    expect(guest.identity.guest).toEqual({
      sponsorId: f.ownerId,
      since: f.now(),
      homeDomain: 'globex.test',
      homeTenantId: globex.tenantId,
    });
    expect(
      await f.iam.api.guests.get(f.ownerCredential, { tenantId, identityId: guest.identity.id }),
    ).toMatchObject({ homeTenantId: globex.tenantId, homeDomain: 'globex.test' });
    const events = await f.database.find<AuditEvent>('audit', { tenantId });
    expect(events.find((event) => event.action === 'guest:redeem')?.metadata).toMatchObject({
      homeTenantId: globex.tenantId,
    });
    // Globex's own audit trail and settings stay its own.
    expect(
      (await f.database.find<AuditEvent>('audit', { tenantId: globex.tenantId })).some((event) =>
        event.action.startsWith('guest:invite'),
      ),
    ).toBe(false);
  });
});
