import type { GuestInviteInput } from '@better-iam/server';
import type { OrganizationFixture } from './organization.js';

/** The newest guest invitation token emailed to `address` (delivers the outbox first). */
export async function invitationToken(f: OrganizationFixture, address: string): Promise<string> {
  await f.iam.auth.dispatchOutbox();
  const message = [...f.inbox]
    .reverse()
    .find((item) => item.template === 'guest-invitation' && item.to === address.toLowerCase());
  if (!message?.payload.token) throw new Error(`No guest invitation was emailed to ${address}`);
  return message.payload.token;
}

/** Redeems the newest invitation emailed to `address`, with the password `a strong {name} password`. */
export async function redeemGuest(
  f: OrganizationFixture,
  address: string,
  name: string,
  tenantId = f.tenantId,
) {
  const result = await f.iam.api.guests.redeem({
    tenantId,
    token: await invitationToken(f, address),
    name,
    password: guestPassword(name),
  });
  if (!('token' in result)) throw new Error('Unexpected MFA at redemption');
  return result;
}

export const guestPassword = (name: string) => `a strong ${name} password`;

/**
 * Invites `{name}@partner.test` (or `input.email`) as the owner (or `credential`) and redeems the invitation: the guest
 * identity, its session credential, and the invitation.
 */
export async function addGuest(
  f: OrganizationFixture,
  name: string,
  input: Partial<Omit<GuestInviteInput, 'tenantId'>> = {},
  credential: { token: string } = f.ownerCredential,
) {
  const invitation = await f.iam.api.guests.invite(credential, {
    tenantId: f.tenantId,
    email: `${name}@partner.test`,
    ...input,
  });
  const redeemed = await redeemGuest(f, invitation.email, name);
  return { invitation, identity: redeemed.identity, credential: { token: redeemed.token } };
}

/** Signs a guest in with their password. */
export async function guestSignIn(f: OrganizationFixture, address: string, name: string) {
  const result = await f.iam.api.auth.signIn({
    tenantId: f.tenantId,
    email: address,
    password: guestPassword(name),
  });
  if (!('token' in result)) throw new Error('Unexpected MFA');
  return { token: result.token };
}

/**
 * Another organization under the platform, with its owner signed in (`owner@{slug}.test`). Pass a fresh root session
 * (`f.rootSignIn()`) once the clock moved past the fixture's recent sign-in.
 */
export async function otherOrganization(
  f: OrganizationFixture,
  name: string,
  slug: string,
  root: { token: string } = f.rootCredential,
) {
  const created = await f.iam.api.tenants.create(root, {
    parentId: f.root.tenant.id,
    name,
    type: 'organization',
    ownerEmail: `owner@${slug}.test`,
  });
  await f.iam.auth.dispatchOutbox();
  const invitation = f.inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await f.iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: `${name} owner`,
    password: 'a strong other owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  return {
    tenantId: created.tenant.id,
    ownerCredential: { token: owner.token },
    ownerId: owner.identity.id,
    /** A fresh, recently authenticated owner session. */
    ownerSignIn: async () => {
      const result = await f.iam.api.auth.signIn({
        tenantId: created.tenant.id,
        email: `owner@${slug}.test`,
        password: 'a strong other owner password',
      });
      if (!('token' in result)) throw new Error('Unexpected owner MFA');
      return { token: result.token };
    },
  };
}

/** Records the tenant as the verifier of `domain`, as a verified domain claim does (domains.ts). */
export async function verifyDomain(f: OrganizationFixture, tenantId: string, domain: string) {
  await f.iam.store.transaction((tx) =>
    tx.insert('domainOwners', {
      id: domain,
      tenantId,
      domainId: `domain-${domain}`,
      verifiedAt: f.now(),
    }),
  );
}

/** A member `{name}@acme.test` holding a role with `permissions`, signed in: identity and credential. */
export async function administrator(f: OrganizationFixture, name: string, permissions: string[]) {
  const identity = await f.member(name);
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `${name} role`,
    permissions,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identity.id,
  });
  return { identity, role, credential: { token: (await f.signIn(name)).token } };
}
