/**
 * B2B guest collaboration (the API is api/guests.ts). People from outside the organization, or from another tenant,
 * join as guests: invited by email, vouched for by a sponsor, given limited access for a limited time that the sponsor
 * renews (attests), and admitted only when the host's inbound and the home organization's outbound cross-tenant access
 * settings both allow it. A guest is an ordinary `kind: 'user'` identity of the host tenant carrying the server-owned
 * `Identity.guest` marker (never an attribute, never a new kind), so everything tenant-local (bindings, groups,
 * packages, separation of duties, invariants, certifications, expiry, offboarding) applies to guests unchanged.
 * Policies see `principal.guest`, `principal.guestSponsorId` and `principal.homeTenantId`, and a tenant's
 * `guestBoundary` is a ceiling on every guest's decisions there.
 */
import { domainToASCII } from 'node:url';
import {
  IamError,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { domainName } from './api/domains.js';
import type { ServerContext } from './context.js';
import { email, text } from './validation.js';

/** The collections this module owns, all tenant-scoped (lifecycle.ts purges them with their tenant). */
export const guestCollections = {
  invitations: 'guestInvitations',
  accounts: 'guestAccounts',
  settings: 'crossTenantAccess',
} as const;

/** Guest lifetimes and list sizes: defaults and bounds, in days where they are durations. */
export const guestLimits = {
  /** How long a guest keeps access after redeeming (or being attested), unless the tenant sets its own. */
  accessDays: 90,
  maxAccessDays: 365,
  /** How often the sponsor confirms that the guest still needs access, unless the tenant sets its own. */
  reviewEveryDays: 90,
  minReviewEveryDays: 7,
  maxReviewEveryDays: 365,
  /** How long an invitation can be redeemed, unless the inviter chooses 1 to 30 days. */
  invitationDays: 14,
  maxInvitationDays: 30,
  /** Sponsors are reminded this many days before a review is due or a guest's access ends. */
  reminderDays: 14,
} as const;

export const guestDayMs = 86_400_000;

export type GuestInvitationStatus = 'pending' | 'redeemed' | 'revoked' | 'expired';

/**
 * An emailed invitation to join the tenant as a guest (`guests.invite`). The token is stored only as its SHA-256
 * hash. While pending, the invitation holds `uniqueKey` `pending:{email}`, so an address has at most one open
 * invitation per tenant. Its roles, groups and packages are granted at redemption under the inviter's authority, for
 * as long as the guest's access lasts, and only if the inviter could still grant them then.
 */
export interface GuestInvitation extends StoredRecord {
  /** The invited address, normalized; the guest identity is created with it at redemption. */
  email: string;
  tokenHash: string;
  /** The member who vouches for the guest. */
  sponsorId: string;
  /** Who sent the invitation; its grants are made under this person's authority, re-checked at redemption. */
  invitedBy: string;
  /** A note from the inviter, included in the email. */
  message?: string;
  roleIds: string[];
  groupIds: string[];
  packageIds: string[];
  /** The inviter's grant authority behind the roles and groups; absent when the invitation grants neither. */
  authorityId?: string;
  /** How long the guest's access lasts from redemption, in days. */
  accessDays: number;
  /** The tenant that had verified the address's domain when the invitation was sent (a tenant-sourced guest). */
  homeTenantId?: string;
  /** When the current token lapses (epoch milliseconds). */
  expiresAt: number;
  createdAt: number;
  /** When the current token was sent: creation, or the last `resendInvitation`. */
  sentAt: number;
  status: GuestInvitationStatus;
  redeemedAt?: number;
  /** The guest identity the redemption created. */
  identityId?: string;
  /** Set when an administrator revoked the invitation (`revokeInvitation`). */
  revokedAt?: number;
  revokedBy?: string;
  /** Set when the invitation was revoked because its inviter or sponsor was disabled or left. */
  revokedReason?: 'inviter-inactive' | 'sponsor-inactive';
}

/**
 * `active` while the guest may use their access; `expired` once it ended (the identity passed its `expiresAt`);
 * `removed` after `guests.remove` or offboarding; `converted` once the guest became an ordinary member.
 */
export type GuestAccountStatus = 'active' | 'expired' | 'removed' | 'converted';

/** What the invitation granted at redemption; attestation moves their end together with the guest's own. */
export interface GuestGrants {
  bindingIds: string[];
  membershipIds: string[];
  packageAssignmentIds: string[];
  /**
   * The memberships the package assignments created at redemption. Renewals lengthen only these: a group a package
   * gained since was never authorized for the guest (`packages.update` grants nothing). Absent on accounts redeemed
   * before it was recorded, whose renewals lengthen the assignments' own memberships.
   */
  packageMembershipIds?: string[];
}

/**
 * One guest's governance record (id = the guest identity's id), with top-level fields so guests can be found by
 * sponsor and status. Decisions read the identity's `guest` marker; this row carries the lifecycle.
 */
export interface GuestAccount extends StoredRecord {
  identityId: string;
  sponsorId: string;
  email: string;
  /** The tenant that verified the guest's email domain, when another tenant had. */
  homeTenantId?: string;
  source: 'invitation';
  invitationId: string;
  invitedBy: string;
  redeemedAt: number;
  /** The last time the sponsor (or an administrator) renewed the guest's access, and who did. */
  attestedAt?: number;
  attestedBy?: string;
  /** When the sponsor is next asked to confirm that the guest still needs access. */
  reviewDueAt: number;
  status: GuestAccountStatus;
  /** The sponsor left or can no longer sponsor guests; set a new one with `guests.setSponsor`. */
  sponsorMissing?: boolean;
  /** When the tenant's owners were emailed about the missing sponsor (once per loss). */
  sponsorMissingNotifiedAt?: number;
  grants: GuestGrants;
  /**
   * The end the invitation's grants were last given: the guest's access end at redemption, then at each renewal; absent
   * once a conversion cleared it. Renewals move the grants still ending then, so an administrator changing the guest's
   * own end in between (`identities.update`) does not leave them behind.
   */
  grantsEndAt?: number;
  /** When the account stopped being active (expired, removed, converted), and who ended it. */
  endedAt?: number;
  endedBy?: string;
  /** Why an administrator removed the guest. */
  removalReason?: string;
}

/** One organization's entry in a partner list: `allow: true` admits it over the defaults, `false` refuses it. */
export interface CrossTenantPartner {
  tenantId: string;
  allow: boolean;
}

/** Who may join this tenant as a guest. */
export interface InboundGuestSettings {
  /** Whether the tenant accepts guests at all (partners with `allow: true` excepted). */
  allowGuests: boolean;
  /** When non-empty, only addresses at these domains (or their subdomains) may be invited. */
  allowedDomains: string[];
  /** Addresses at these domains (or their subdomains) are never invited; this wins over every allow. */
  blockedDomains: string[];
  /** Organizations (by the tenant that verified the address's domain) admitted or refused over the defaults. */
  partners: CrossTenantPartner[];
}

/** Whether this tenant's people may become guests elsewhere. */
export interface OutboundGuestSettings {
  /**
   * Whether people whose address is at one of this tenant's verified domains may redeem guest invitations of other
   * tenants (partners excepted).
   */
  allowGuestInvitations: boolean;
  /** Host organizations allowed or refused over the default. */
  partners: CrossTenantPartner[];
}

/** A tenant's guest settings, stored or defaulted. */
export interface GuestSettings {
  inbound: InboundGuestSettings;
  outbound: OutboundGuestSettings;
  /** How long a guest's access lasts after redemption or attestation, in days (1 to 365). */
  accessDays: number;
  /** How often the sponsor confirms a guest still needs access, in days (7 to 365). */
  reviewEveryDays: number;
  /** A ceiling applied to every guest's decisions in this tenant. */
  guestBoundary?: PolicyDocument;
}

/** The stored cross-tenant access settings of one tenant (id = the tenant's id). */
export interface CrossTenantAccess extends StoredRecord, GuestSettings {
  updatedAt: number;
  updatedBy: string;
}

/** Where an invited address comes from. */
export interface GuestOrigin {
  /** The address's domain. */
  domain: string;
  /** The tenant that verified the domain, when another tenant did. */
  homeTenantId?: string;
}

/** Whether an identity is a guest: it carries the server-owned `guest` marker. */
export function isGuest(identity: Pick<Identity, 'guest'>): boolean {
  return identity.guest !== undefined;
}

/**
 * The guest keys of a decision: `principal.guest` always, and `principal.guestSponsorId` and `principal.homeTenantId`
 * when set. Only an identity acting in its own tenant can be a guest there; an assumed role never is.
 */
export function guestContext(identity: Identity, ownTenant: boolean): Record<string, unknown> {
  const guest = ownTenant ? identity.guest : undefined;
  return {
    'principal.guest': guest !== undefined,
    ...(typeof guest?.sponsorId === 'string'
      ? { 'principal.guestSponsorId': guest.sponsorId }
      : {}),
    ...(typeof guest?.homeTenantId === 'string'
      ? { 'principal.homeTenantId': guest.homeTenantId }
      : {}),
  };
}

/** The settings a tenant has without stored ones. */
export function defaultGuestSettings(): GuestSettings {
  return {
    inbound: { allowGuests: true, allowedDomains: [], blockedDomains: [], partners: [] },
    outbound: { allowGuestInvitations: true, partners: [] },
    accessDays: guestLimits.accessDays,
    reviewEveryDays: guestLimits.reviewEveryDays,
  };
}

/** A tenant's stored settings, if it saved any. */
export async function readGuestSettings(
  tx: IamStore,
  tenantId: string,
): Promise<CrossTenantAccess | undefined> {
  const stored = await tx.get<CrossTenantAccess>(guestCollections.settings, tenantId);
  return stored?.tenantId === tenantId ? stored : undefined;
}

/** A tenant's settings: the stored ones, or the defaults. */
export async function guestSettings(tx: IamStore, tenantId: string): Promise<GuestSettings> {
  const stored = await readGuestSettings(tx, tenantId);
  if (!stored) return defaultGuestSettings();
  return {
    inbound: stored.inbound,
    outbound: stored.outbound,
    accessDays: stored.accessDays,
    reviewEveryDays: stored.reviewEveryDays,
    ...(stored.guestBoundary ? { guestBoundary: stored.guestBoundary } : {}),
  };
}

/** The ceiling a tenant sets on every guest's decisions, if any (decisions.ts reads it for guests only). */
export async function guestBoundary(
  tx: IamStore,
  tenantId: string,
): Promise<PolicyDocument | undefined> {
  return (await readGuestSettings(tx, tenantId))?.guestBoundary;
}

/**
 * An address's domain spelled as verified domains and the domain lists are (domains.ts `domainName`): lowercase ASCII,
 * an internationalized name in its punycode form (UTS #46 mapping, as mail transports convert it), without a trailing
 * dot. Otherwise `bob@partner.com.` or `bob@bücher.example` would reach the same mailbox as the canonical spelling
 * while matching no verified domain, blocked domain or partner. INVALID_INPUT for a domain that is not a DNS name.
 */
export function emailDomain(address: string): string {
  try {
    return domainName(domainToASCII(address.slice(address.lastIndexOf('@') + 1)));
  } catch {
    throw new IamError('INVALID_INPUT', 'Invalid email: its domain is not a DNS name');
  }
}

/** An invited address: a valid email whose domain is spelled as `emailDomain` spells it. */
export function guestAddress(value: unknown): string {
  const address = email(value);
  return `${address.slice(0, address.lastIndexOf('@') + 1)}${emailDomain(address)}`;
}

/**
 * Where an address comes from: its domain, and the tenant that verified that domain (`domainOwners`) unless that is
 * the host itself or a deleted tenant. An address at one of the host's own verified domains belongs to a member, so it
 * is refused (GUEST_NOT_ALLOWED): invite the person as a member instead.
 */
export async function guestOrigin(
  tx: IamStore,
  hostTenantId: string,
  address: string,
): Promise<GuestOrigin> {
  const domain = emailDomain(address);
  const owner = await tx.get<StoredRecord>('domainOwners', domain);
  if (!owner) return { domain };
  if (owner.tenantId === hostTenantId)
    throw new IamError(
      'GUEST_NOT_ALLOWED',
      `${domain} is a verified domain of this organization: invite the person as a member`,
      403,
    );
  const home = await tx.get<Tenant>('tenants', owner.tenantId);
  return home && home.status !== 'deleted' ? { domain, homeTenantId: home.id } : { domain };
}

/** Whether a domain is one of `entries` or a subdomain of one. */
export function domainListed(domain: string, entries: readonly string[]): boolean {
  return entries.some((entry) => domain === entry || domain.endsWith(`.${entry}`));
}

/**
 * Why the host's inbound settings refuse a guest from `origin`, or undefined when they admit them. A refusal wins
 * (a partner entry with `allow: false`, a blocked domain); a partner entry with `allow: true` then admits the guest
 * over the defaults (`allowGuests`, `allowedDomains`).
 */
export function inboundRefusal(settings: GuestSettings, origin: GuestOrigin): string | undefined {
  const partner = origin.homeTenantId
    ? settings.inbound.partners.find((entry) => entry.tenantId === origin.homeTenantId)
    : undefined;
  if (partner && !partner.allow)
    return 'This organization does not accept guests from the person’s organization';
  if (domainListed(origin.domain, settings.inbound.blockedDomains))
    return `This organization does not accept guests from ${origin.domain}`;
  if (partner?.allow) return undefined;
  if (!settings.inbound.allowGuests) return 'This organization does not accept guests';
  if (
    settings.inbound.allowedDomains.length &&
    !domainListed(origin.domain, settings.inbound.allowedDomains)
  )
    return 'This organization accepts guests only from its allowed domains';
  return undefined;
}

/** Whether a home tenant's outbound settings let its people become guests of `hostTenantId`. */
export function outboundAllows(settings: GuestSettings, hostTenantId: string): boolean {
  const partner = settings.outbound.partners.find((entry) => entry.tenantId === hostTenantId);
  return partner ? partner.allow : settings.outbound.allowGuestInvitations;
}

/**
 * Refuses (GUEST_NOT_ALLOWED, 403) a guest the host's inbound settings or the home tenant's outbound settings do not
 * admit. The outbound refusal says only that the person's organization does not allow it, never what it configured.
 */
export async function assertGuestAdmitted(
  tx: IamStore,
  host: GuestSettings,
  hostTenantId: string,
  origin: GuestOrigin,
): Promise<void> {
  const refusal = inboundRefusal(host, origin);
  if (refusal) throw new IamError('GUEST_NOT_ALLOWED', refusal, 403);
  if (
    origin.homeTenantId &&
    !outboundAllows(await guestSettings(tx, origin.homeTenantId), hostTenantId)
  )
    throw new IamError(
      'GUEST_NOT_ALLOWED',
      'The person’s organization does not allow its members to join this organization as guests',
      403,
    );
}

/** Whether an identity can sponsor guests of `tenantId` now: an active, unexpired person of it who is no guest. */
export function canSponsor(
  ctx: ServerContext,
  identity: Identity | undefined,
  tenantId: string,
): identity is Identity {
  return (
    identity !== undefined &&
    identity.tenantId === tenantId &&
    identity.kind === 'user' &&
    identity.status === 'active' &&
    !ctx.identityExpired(identity) &&
    !isGuest(identity)
  );
}

/** A guest's sponsor by id; refuses (INVALID_SPONSOR) anyone `canSponsor` does not accept. */
export async function guestSponsor(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  sponsorId: unknown,
): Promise<Identity> {
  const sponsor = await tx.get<Identity>('identities', text(sponsorId, 'sponsorId'));
  if (!canSponsor(ctx, sponsor, tenantId))
    throw new IamError(
      'INVALID_SPONSOR',
      'A guest’s sponsor must be an active member of the organization who is not a guest',
    );
  return sponsor;
}

/** Moves a guest to a new sponsor: the identity's marker and the account, clearing a missing-sponsor flag. */
export async function setGuestSponsor(
  tx: IamStore,
  account: GuestAccount,
  guest: Identity,
  sponsorId: string,
): Promise<{ account: GuestAccount; identity: Identity }> {
  const identity = guest.guest
    ? await tx.put<Identity>('identities', { ...guest, guest: { ...guest.guest, sponsorId } })
    : guest;
  const { sponsorMissing: _missing, sponsorMissingNotifiedAt: _notified, ...rest } = account;
  return {
    account: await tx.put<GuestAccount>(guestCollections.accounts, { ...rest, sponsorId }),
    identity,
  };
}

/**
 * The pending guest invitations a person sent or sponsors are revoked when they are disabled or leave (called by
 * `revokeInvitationsBy` in api/identities.ts). Redemption would refuse them anyway; this keeps the list truthful.
 */
export async function revokeGuestInvitationsBy(tx: IamStore, identityId: string): Promise<void> {
  const found = new Map<string, GuestInvitation>();
  for (const field of ['invitedBy', 'sponsorId'] as const)
    for (const invitation of await tx.find<GuestInvitation>(guestCollections.invitations, {
      [field]: identityId,
      status: 'pending',
    }))
      found.set(invitation.id, invitation);
  for (const invitation of found.values()) {
    const { uniqueKey: _open, ...rest } = invitation;
    await tx.put<GuestInvitation>(guestCollections.invitations, {
      ...rest,
      status: 'revoked',
      revokedReason: invitation.invitedBy === identityId ? 'inviter-inactive' : 'sponsor-inactive',
    });
  }
}

/**
 * Offboarding (identities.offboard): a leaver who is a guest has their guest account closed as `removed`, and the
 * guests the leaver sponsors move to `successor` when that person can sponsor (each audited as
 * `guest:sponsor-change`); otherwise they are flagged `sponsorMissing` so the owners assign someone.
 */
export async function handOverGuests(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  leaver: Identity,
  successor: Identity | undefined,
): Promise<{ reassigned: number; unsponsored: number }> {
  const counts = { reassigned: 0, unsponsored: 0 };
  const own = await tx.get<GuestAccount>(guestCollections.accounts, leaver.id);
  if (own?.tenantId === leaver.tenantId && own.status === 'active')
    await tx.put<GuestAccount>(guestCollections.accounts, {
      ...own,
      status: 'removed',
      endedAt: ctx.now(),
      endedBy: principal.identity.id,
      removalReason: 'Offboarded',
    });
  const heir =
    successor && successor.id !== leaver.id && canSponsor(ctx, successor, leaver.tenantId)
      ? successor
      : undefined;
  for (const account of await tx.find<GuestAccount>(guestCollections.accounts, {
    tenantId: leaver.tenantId,
    sponsorId: leaver.id,
    status: 'active',
  })) {
    const guest = await tx.get<Identity>('identities', account.identityId);
    if (!guest || guest.status === 'deleted') continue;
    if (heir && heir.id !== guest.id) {
      await setGuestSponsor(tx, account, guest, heir.id);
      await ctx.events.audit(
        tx,
        principal,
        'guest:sponsor-change',
        leaver.tenantId,
        guest.id,
        'allow',
        false,
        { from: leaver.id, to: heir.id, reason: 'offboarding' },
      );
      counts.reassigned++;
      continue;
    }
    await flagSponsorMissing(ctx, tx, principal, account, 'offboarding');
    counts.unsponsored++;
  }
  return counts;
}

/**
 * Identity deletion (identities.ts `deleteIdentity`): a deleted guest's account row goes (the audit trail keeps its
 * history), and the guests the person sponsored are flagged `sponsorMissing`.
 */
export async function releaseGuestRecords(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  identity: Pick<Identity, 'id' | 'tenantId'>,
): Promise<void> {
  const own = await tx.get<GuestAccount>(guestCollections.accounts, identity.id);
  if (own?.tenantId === identity.tenantId) await tx.delete(guestCollections.accounts, own.id);
  for (const account of await tx.find<GuestAccount>(guestCollections.accounts, {
    tenantId: identity.tenantId,
    sponsorId: identity.id,
    status: 'active',
  }))
    await flagSponsorMissing(ctx, tx, principal, account, 'deletion');
}

/** Flags a guest whose sponsor is leaving, audited as `guest:sponsor-missing` (the worker emails the owners). */
async function flagSponsorMissing(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  account: GuestAccount,
  reason: 'offboarding' | 'deletion',
): Promise<void> {
  if (account.sponsorMissing) return;
  await tx.put<GuestAccount>(guestCollections.accounts, { ...account, sponsorMissing: true });
  await ctx.events.audit(
    tx,
    principal,
    'guest:sponsor-missing',
    account.tenantId,
    account.identityId,
    'allow',
    false,
    { sponsorId: account.sponsorId, reason },
  );
}
