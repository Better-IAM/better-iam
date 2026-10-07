import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import type { AuditEvent, Identity } from '@better-iam/core';
import type { GuestInvitation } from '@better-iam/server';
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

describe('guest hardening', () => {
  it('reads an address’s domain as verified domains and domain lists spell it', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const globex = await otherOrganization(f, 'Globex', 'globex');
    await verifyDomain(f, globex.tenantId, 'globex.test');
    await verifyDomain(f, tenantId, 'acme.example');
    const invite = (email: string) => f.iam.api.guests.invite(owner, { tenantId, email });
    // An invitation sent while Globex allowed it, stored with a trailing dot as it was before addresses were
    // normalized: redemption still finds Globex behind the address.
    const legacy = await invite('lee@globex.test');
    await f.iam.store.transaction(async (tx) => {
      const stored = (await tx.get<GuestInvitation>('guestInvitations', legacy.id))!;
      await tx.put('guestInvitations', { ...stored, email: 'lee@globex.test.' });
    });
    await f.iam.api.guests.configure(globex.ownerCredential, {
      tenantId: globex.tenantId,
      outbound: { allowGuestInvitations: false },
    });
    const outbound =
      'The person’s organization does not allow its members to join this organization as guests';
    // A trailing dot (which mail relays drop) reaches the same mailbox: Globex's outbound refusal still applies.
    for (const email of ['gil@globex.test.', 'gil@GLOBEX.test.'])
      await expect(invite(email), email).rejects.toMatchObject({
        code: 'GUEST_NOT_ALLOWED',
        message: outbound,
      });
    await expect(
      f.iam.api.guests.redeem({
        tenantId,
        token: await invitationToken(f, 'lee@globex.test'),
        name: 'Lee',
        password: guestPassword('Lee'),
      }),
    ).rejects.toMatchObject({ code: 'GUEST_NOT_ALLOWED', message: outbound });
    // The host's own verified domain, however it is spelled, belongs to members.
    await expect(invite('someone@acme.example.')).rejects.toMatchObject({
      code: 'GUEST_NOT_ALLOWED',
      message:
        'acme.example is a verified domain of this organization: invite the person as a member',
    });
    // Internationalized domains are compared in their punycode form, as mail transports send them.
    await f.iam.api.guests.configure(owner, {
      tenantId,
      inbound: { blockedDomains: ['xn--bcher-kva.example'] },
    });
    for (const email of ['bob@bücher.example', 'bob@BÜCHER.example.', 'bob@ｂüｃｈｅｒ.example'])
      await expect(invite(email), email).rejects.toMatchObject({
        code: 'GUEST_NOT_ALLOWED',
        message: 'This organization does not accept guests from xn--bcher-kva.example',
      });
    // A domain that is no DNS name is refused outright.
    for (const email of ['x@partner..test', 'x@[192.0.2.1]', 'x@partner.test..'])
      await expect(invite(email), email).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // An admitted address is stored, emailed and redeemed in its canonical spelling.
    const ann = await invite('Ann@Partner.Test.');
    expect(ann.email).toBe('ann@partner.test');
    const redeemed = await redeemGuest(f, 'ann@partner.test', 'Ann');
    expect(redeemed.identity).toMatchObject({
      email: 'ann@partner.test',
      guest: { homeDomain: 'partner.test' },
    });
    await expect(invite('ann@partner.test.')).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('keeps an owner’s protection for a guest who owns the organization', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id });
    const identityId = gina.identity.id;
    const owner = await f.ownerSignIn();
    await f.iam.api.identities.setOwner(owner, { tenantId, identityId, owner: true });
    const admin = await administrator(f, 'admin', ['iam:guests:manage', 'iam:guests:read']);
    const asAlice = { token: (await f.signIn('alice')).token };
    // Neither the sponsor nor an administrator who is no owner moves an owner's end, either way.
    for (const [credential, days] of [
      [asAlice, 365],
      [asAlice, 1],
      [admin.credential, 365],
    ] as const)
      await expect(
        f.iam.api.guests.attest(credential, { tenantId, identityId, days }),
      ).rejects.toMatchObject({
        code: 'ACCESS_DENIED',
        message: 'Only an owner can change an owner’s expiry',
      });
    await expect(
      f.iam.api.guests.convertToMember(admin.credential, {
        tenantId,
        identityId,
        clearExpiry: true,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const stored = async () => (await f.database.get<Identity>('identities', identityId))!;
    expect(await stored()).toMatchObject({ expiresAt: gina.identity.expiresAt, guest: {} });
    // Another owner can.
    await expect(
      f.iam.api.guests.attest(owner, { tenantId, identityId, days: 30 }),
    ).resolves.toMatchObject({ expiresAt: f.now() + 30 * day });
    await expect(
      f.iam.api.guests.convertToMember(owner, { tenantId, identityId, clearExpiry: true }),
    ).resolves.not.toHaveProperty('expiresAt');
  });

  it('never lets a guest make guests members or choose their sponsor', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    const manager = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Guest manager',
      permissions: ['iam:guests:manage', 'iam:guests:read'],
    });
    const gina = await addGuest(f, 'gina', { roleIds: [manager.id] });
    const hal = await addGuest(f, 'hal');
    for (const identityId of [gina.identity.id, hal.identity.id]) {
      await expect(
        f.iam.api.guests.convertToMember(gina.credential, {
          tenantId,
          identityId,
          clearExpiry: true,
        }),
        identityId,
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
      await expect(
        f.iam.api.guests.setSponsor(gina.credential, { tenantId, identityId, sponsorId: alice.id }),
        identityId,
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    }
    for (const guest of [gina, hal])
      expect(await f.database.get<Identity>('identities', guest.identity.id)).toMatchObject({
        expiresAt: guest.identity.expiresAt,
        guest: { sponsorId: f.ownerId },
      });
    // The refusals are audited as denials of the guest.
    const denials = (await f.database.find<AuditEvent>('audit', { tenantId })).filter(
      (event) =>
        event.action === 'iam:guests:manage' &&
        event.outcome === 'deny' &&
        event.actorId === gina.identity.id,
    );
    expect(denials).toHaveLength(4);
  });

  it('needs iam:guests:manage to name someone else as the sponsor', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const cfo = await f.member('cfo');
    const lead = await administrator(f, 'lead', ['iam:guests:invite']);
    const invite = (credential: { token: string }, email: string, sponsorId?: string) =>
      f.iam.api.guests.invite(credential, {
        tenantId,
        email,
        ...(sponsorId !== undefined ? { sponsorId } : {}),
      });
    // Whether the person exists or not, the refusal is the same.
    for (const sponsorId of [cfo.id, 'missing'])
      await expect(
        invite(lead.credential, 'a@partner.test', sponsorId),
        sponsorId,
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.some((message) => message.template === 'guest-invitation')).toBe(false);
    // The inviter sponsors their own guests, named or not.
    await expect(invite(lead.credential, 'a@partner.test')).resolves.toMatchObject({
      sponsorId: lead.identity.id,
    });
    await expect(
      invite(lead.credential, 'b@partner.test', lead.identity.id),
    ).resolves.toMatchObject({ sponsorId: lead.identity.id });
    // Someone who could give a guest another sponsor may name one.
    const manager = await administrator(f, 'manager', ['iam:guests:invite', 'iam:guests:manage']);
    await expect(invite(manager.credential, 'c@partner.test', cfo.id)).resolves.toMatchObject({
      sponsorId: cfo.id,
    });
  });

  it('refuses invitations from an assumed role, which redemption could never re-check', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    const globex = await otherOrganization(f, 'Globex', 'globex');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Partner guest desk',
      permissions: ['iam:guests:invite', 'iam:guests:manage'],
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId,
      sourceTenantId: globex.tenantId,
      sourceIdentityId: globex.ownerId,
      roleId: role.id,
      requireMfa: false,
    });
    const assumed = await f.iam.api.roles.assume(globex.ownerCredential, {
      tenantId,
      trustId: trust.id,
    });
    await expect(
      f.iam.api.guests.invite(
        { token: assumed.token },
        { tenantId, email: 'gina@partner.test', sponsorId: alice.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.some((message) => message.template === 'guest-invitation')).toBe(false);
    expect(await f.database.find('guestInvitations', { tenantId })).toEqual([]);
  });

  it('keeps one client from spending the redemption budget every invitee shares', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    await f.iam.api.guests.invite(f.ownerCredential, { tenantId, email: 'gina@partner.test' });
    const token = await invitationToken(f, 'gina@partner.test');
    const from = <T>(ip: string, fn: () => Promise<T>) =>
      f.iam.auth.withClient({ ip, userAgent: 'test' }, fn);
    const junk = () =>
      from('203.0.113.9', () =>
        f.iam.api.guests.redeem({
          tenantId,
          token: 'biam_gst_junk',
          name: 'Mallory',
          password: guestPassword('Mallory'),
        }),
      );
    // More attempts than the tenant-wide budget, all from one client: it is cut off after its own 20.
    const codes = new Map<string, number>();
    for (let attempt = 0; attempt < 505; attempt++) {
      const code = await junk().then(
        () => 'ok',
        (error: { code: string }) => error.code,
      );
      codes.set(code, (codes.get(code) ?? 0) + 1);
    }
    expect(codes.get('RATE_LIMITED')).toBeGreaterThanOrEqual(485);
    expect(codes.has('ok')).toBe(false);
    // The real invitee, elsewhere, still redeems.
    await expect(
      from('198.51.100.20', () =>
        f.iam.api.guests.redeem({ tenantId, token, name: 'Gina', password: guestPassword('Gina') }),
      ),
    ).resolves.toMatchObject({ identity: { email: 'gina@partner.test' } });
  });

  it('revokes the guest invitations of a person a workflow disables', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const lead = await administrator(f, 'lead', ['iam:guests:invite']);
    const invitation = await f.iam.api.guests.invite(lead.credential, {
      tenantId,
      email: 'gina@partner.test',
    });
    const token = await invitationToken(f, 'gina@partner.test');
    const workflow = await f.iam.api.workflows.create(f.ownerCredential, {
      tenantId,
      name: 'Suspend',
      trigger: { kind: 'manual' },
      steps: [{ kind: 'disable' }],
    });
    const owner = await f.ownerSignIn();
    const [run] = await f.iam.api.workflows.run(owner, {
      tenantId,
      workflowId: workflow.id,
      identityIds: [lead.identity.id],
    });
    expect(run).toMatchObject({ status: 'completed' });
    const [revoked] = await f.iam.api.guests.listInvitations(owner, { tenantId });
    expect(revoked).toMatchObject({
      id: invitation.id,
      status: 'revoked',
      revokedReason: 'inviter-inactive',
    });
    // The inviter comes back: the old token stays dead.
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: lead.identity.id,
      status: 'active',
    });
    await expect(
      f.iam.api.guests.redeem({ tenantId, token, name: 'Gina', password: guestPassword('Gina') }),
    ).rejects.toMatchObject({ code: 'INVITATION_INVALID' });
  });

  it('bounds a guest’s delegation tokens by the tenant’s guest boundary', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const f = await organizationFixture({
      a2a: {
        signingKeys: [
          { ...privateKey.export({ format: 'jwk' }), kid: 'card-1', alg: 'EdDSA', use: 'sig' },
        ],
        jwksUrl: 'https://iam.acme.test/jwks',
      },
    });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const calendar = 'https://calendar.example.com';
    const agent = await f.iam.api.agents.create(owner, {
      tenantId,
      name: 'Assistant',
      tokenAudiences: [calendar],
    });
    const key = await f.iam.api.credentials.create(owner, { tenantId, identityId: agent.id });
    const editor = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Editor',
      permissions: ['documents:read', 'documents:write'],
    });
    const gina = await addGuest(f, 'gina', { roleIds: [editor.id] });
    const delegation = await f.iam.api.delegations.grant(gina.credential, {
      tenantId,
      agentId: agent.id,
      scopes: ['documents:read', 'documents:write'],
    });
    const acting = await f.iam.api.delegations.assume(
      { token: key.token },
      { tenantId, delegationId: delegation.id },
    );
    const session = { token: acting.token };
    const issue = (scopes?: string[]) =>
      f.iam.api.delegations.issueToken(session, {
        tenantId,
        audience: calendar,
        ...(scopes ? { scopes } : {}),
      });
    const early = await issue();
    expect(early.scopes).toEqual(['documents:read', 'documents:write']);
    await f.iam.api.guests.configure(owner, {
      tenantId,
      guestBoundary: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    // No token claims what every decision for the guest refuses, and one issued before stops standing.
    await expect(issue()).rejects.toMatchObject({ code: 'DELEGATION_NOT_ALLOWED' });
    await expect(issue(['documents:read'])).resolves.toMatchObject({ scopes: ['documents:read'] });
    await expect(
      f.iam.a2a.verifyDelegationToken(early.token, { audience: calendar, live: true }),
    ).rejects.toMatchObject({ code: 'DELEGATION_TOKEN_INVALID' });
  });

  it('releases a removed guest’s license seat at once', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const licenses = f.iam.api.licenses;
    const pro = await licenses.createProduct(owner, { tenantId, key: 'pro', name: 'Pro' });
    await licenses.addPool(owner, { tenantId, productId: pro.id, quantity: 1 });
    const bob = await f.member('bob');
    const gina = await addGuest(f, 'gina');
    for (const subjectId of [gina.identity.id, bob.id]) {
      f.advance(1000);
      await licenses.assign(owner, {
        tenantId,
        productId: pro.id,
        subjectType: 'identity',
        subjectId,
      });
    }
    const seats = async () =>
      (await licenses.listSeats(owner, { tenantId })).seats.map(
        (seat) => `${seat.identityName} ${seat.status}`,
      );
    expect(await seats()).toEqual(['gina active', 'bob waiting']);
    await f.iam.api.guests.remove(await f.ownerSignIn(), {
      tenantId,
      identityId: gina.identity.id,
      reason: 'Project ended',
    });
    expect(await seats()).toEqual(['bob active']);
  });

  it('reminds a sponsor of an overdue review once, also for a guest without an end', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const alice = await f.member('alice');
    await f.iam.api.guests.configure(f.ownerCredential, { tenantId, reviewEveryDays: 30 });
    const gina = await addGuest(f, 'gina', { sponsorId: alice.id });
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId,
      identityId: gina.identity.id,
      expiresAt: null,
    });
    const start = f.now();
    f.advance(16 * day);
    expect((await f.iam.guests.sendReviewReminders()).sent).toEqual([
      { tenantId, guestId: gina.identity.id, sponsorId: alice.id, dueAt: start + 30 * day },
    ]);
    // The review goes unanswered for months while both jobs keep running.
    for (let cycle = 0; cycle < 30; cycle++) {
      f.advance(5 * day);
      await f.iam.purgeDeleted();
      expect((await f.iam.guests.sendReviewReminders()).sent, `cycle ${cycle}`).toEqual([]);
    }
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.filter((message) => message.template === 'guest-review')).toHaveLength(1);
    // Renewed, the next review is reminded as usual.
    await f.iam.api.guests.attest(
      { token: (await f.signIn('alice')).token },
      { tenantId, identityId: gina.identity.id, days: 90 },
    );
    f.advance(20 * day);
    expect((await f.iam.guests.sendReviewReminders()).sent).toHaveLength(1);
  });

  it('says how to invite a former guest again, and lets it happen once their account is gone', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const gina = await addGuest(f, 'gina');
    await f.iam.api.guests.remove(owner, {
      tenantId,
      identityId: gina.identity.id,
      reason: 'Project ended',
    });
    await expect(
      f.iam.api.guests.attest(owner, { tenantId, identityId: gina.identity.id }),
    ).rejects.toMatchObject({
      code: 'INVALID_TRANSITION',
      message: expect.stringContaining('delete the account and invite the person again'),
    });
    await expect(
      f.iam.api.guests.invite(owner, { tenantId, email: 'gina@partner.test' }),
    ).rejects.toMatchObject({
      code: 'CONFLICT',
      message: expect.stringContaining('former guest'),
    });
    await f.iam.api.identities.delete(await f.ownerSignIn(), {
      tenantId,
      identityId: gina.identity.id,
    });
    await f.iam.api.guests.invite(owner, { tenantId, email: 'gina@partner.test' });
    const again = await redeemGuest(f, 'gina@partner.test', 'Gina');
    expect(again.identity.id).not.toBe(gina.identity.id);
    expect(again.identity.guest).toMatchObject({ sponsorId: f.ownerId });
  });
});
