import { randomBytes } from 'node:crypto';
import {
  IamError,
  ipCounterKey,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type SignInRecord,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { revokeDelegationsOf } from '../delegations.js';
import { releaseDepartments } from '../departments.js';
import type { EnrollmentResult } from '../flows.js';
import {
  assertGuestAdmitted,
  canSponsor,
  guestCollections,
  guestAddress,
  guestDayMs,
  guestLimits,
  guestOrigin,
  guestSettings,
  guestSponsor,
  isGuest,
  readGuestSettings,
  setGuestSponsor,
  type CrossTenantAccess,
  type CrossTenantPartner,
  type GuestAccount,
  type GuestAccountStatus,
  type GuestGrants,
  type GuestInvitation,
  type GuestInvitationStatus,
  type GuestSettings,
  type InboundGuestSettings,
  type OutboundGuestSettings,
} from '../guests.js';
import { invariantSnapshot, invariantVerify } from '../invariants.js';
import type {
  AccessPackage,
  AccessRequest,
  Binding,
  ExpiryReminderMark,
  GrantAuthority,
  Group,
  GroupMember,
  PackageAssignment,
  Relationship,
  Role,
} from '../models.js';
import { OperationDenied } from '../operations.js';
import { actsInOwnRight } from '../session-kinds.js';
import { sodAssertIdentity } from '../sod.js';
import {
  assertNotTeamGroup,
  isTeamGroup,
  removeFromAllTeams,
  syncTeamsFromGroups,
} from '../teams.js';
import { endContainment } from '../threats.js';
import { byNewest, hash, id, publicIdentity, type PublicIdentity } from '../utils.js';
import { integer, object, strings, text } from '../validation.js';
import { domainName } from './domains.js';
import { assertMayClaimLicenses } from './groups.js';
import { assertOwnerControl, revokeInvitationsBy } from './identities.js';
import { afterIdentityChange } from './package-automation.js';
import {
  allow,
  assignPackage,
  authorizePackage,
  retimeAssignment,
  revokeAssignment,
} from './packages.js';

/** A guest as administrators and sponsors see them. */
export interface GuestView {
  identityId: string;
  tenantId: string;
  name: string;
  email?: string;
  /** The identity's own status. */
  status: Identity['status'];
  /** The guest account's status; `expired` as soon as the guest's access ended, before the worker records it. */
  accountStatus: GuestAccountStatus;
  sponsorId: string;
  sponsorName?: string;
  /** The sponsor left or can no longer sponsor guests: assign another one with `setSponsor`. */
  sponsorMissing: boolean;
  /** The tenant that verified the guest's email domain, when another tenant had. */
  homeTenantId?: string;
  /** The domain of the guest's email address. */
  homeDomain?: string;
  invitationId: string;
  invitedBy: string;
  redeemedAt: number;
  attestedAt?: number;
  attestedBy?: string;
  /** When the sponsor is next asked to confirm that the guest still needs access. */
  reviewDueAt: number;
  /** When the guest's access ends (the identity's `expiresAt`). */
  expiresAt?: number;
  /** The guest's most recent sign-in, if any. */
  lastSignInAt?: number;
}

/** One page of guests (`guests.list`). */
export interface GuestPage {
  guests: GuestView[];
  total: number;
}

/** A guest invitation without its token. */
export interface GuestInvitationView {
  id: string;
  tenantId: string;
  email: string;
  /** `expired` as soon as a pending invitation lapsed, before the worker records it. */
  status: GuestInvitationStatus;
  sponsorId: string;
  sponsorName?: string;
  invitedBy: string;
  inviterName?: string;
  message?: string;
  roleIds: string[];
  groupIds: string[];
  packageIds: string[];
  /** How long the guest's access lasts from redemption, in days. */
  accessDays: number;
  homeTenantId?: string;
  expiresAt: number;
  createdAt: number;
  sentAt: number;
  redeemedAt?: number;
  identityId?: string;
  revokedAt?: number;
  revokedBy?: string;
  revokedReason?: GuestInvitation['revokedReason'];
}

/** What `guests.invite` takes. */
export interface GuestInviteInput {
  tenantId: string;
  email: string;
  /** The member who vouches for the guest; the caller when omitted, who must then be able to sponsor guests. */
  sponsorId?: string;
  /** A note for the invitee, included in the email (one line, at most 1000 characters). */
  message?: string;
  /** Roles bound to the guest at redemption, until their access ends. */
  roleIds?: string[];
  /** Groups the guest joins at redemption, until their access ends (never a team's backing group). */
  groupIds?: string[];
  /** Access packages assigned at redemption, until their access ends (or the package's maximum duration). */
  packageIds?: string[];
  /** How long the guest's access lasts after redemption, 1 to 365 days (default: the tenant's `accessDays`). */
  accessDays?: number;
  /** How long the invitation can be redeemed, 1 to 30 days (default 14). */
  expiresInDays?: number;
}

/** A tenant's cross-tenant access settings as `getSettings` and `configure` return them. */
export interface GuestSettingsView extends GuestSettings {
  tenantId: string;
  /** False while the tenant uses the defaults. */
  configured: boolean;
  updatedAt?: number;
  updatedBy?: string;
}

/** What `guests.configure` takes: only the fields given change. */
export interface GuestSettingsInput {
  tenantId: string;
  inbound?: Partial<InboundGuestSettings>;
  outbound?: Partial<OutboundGuestSettings>;
  /** How long a guest's access lasts after redemption or attestation, 1 to 365 days. */
  accessDays?: number;
  /** How often sponsors confirm their guests still need access, 7 to 365 days. */
  reviewEveryDays?: number;
  /** A ceiling on every guest's decisions in the tenant; null removes it. */
  guestBoundary?: PolicyDocument | null;
}

/** What `guests.remove` did. */
export interface GuestRemoval {
  guest: GuestView;
  sessions: number;
  bindings: number;
  memberships: number;
  packages: number;
}

/** What `iam.guests.sendReviewReminders` sent. */
export interface GuestReminderResult {
  /** One entry per reminder emailed to a sponsor. */
  sent: Array<{ tenantId: string; guestId: string; sponsorId: string; dueAt: number }>;
  /** Tenants left alone: not active, or with nothing new to remind anyone about. */
  skipped: { inactive: number; quiet: number };
}

/** What `iam.guests.sweep` changed. */
export interface GuestSweepResult {
  /** Pending invitations past their lapse, now marked expired. */
  invitationsExpired: number;
  /** Guest accounts whose access ended, now marked expired. */
  accountsExpired: number;
  /** Expired accounts active again because an administrator re-enabled the guest with a later end. */
  accountsRestored: number;
  /** Guests newly flagged because their sponsor left or can no longer sponsor guests. */
  sponsorsMissing: number;
  /** Emails sent to tenant owners about guests without a sponsor (once per guest and loss). */
  ownersNotified: number;
  /** Partner entries naming tenants that no longer exist, removed from settings. */
  partnersRemoved: number;
}

/** The guest scheduler jobs on the instance (`iam.guests`); run both hourly. */
export interface IamGuests {
  /**
   * Emails each sponsor (template `guest-review`) about guests whose review is due or whose access ends within
   * `withinDays` (default 14): each review date and each access end once, one email covering whatever is due.
   * Requires an email delivery callback.
   */
  sendReviewReminders(input?: {
    tenantId?: string;
    withinDays?: number;
  }): Promise<GuestReminderResult>;
  /**
   * Bookkeeping: marks lapsed invitations and ended guest accounts expired, flags guests whose sponsor left (and emails
   * the tenant's owners once, template `guest-sponsor-missing`), and drops partner entries naming purged tenants.
   */
  sweep(input?: { tenantId?: string }): Promise<GuestSweepResult>;
}

const accountStatuses: ReadonlySet<string> = new Set<GuestAccountStatus>([
  'active',
  'expired',
  'removed',
  'converted',
]);
const invitationStatuses: ReadonlySet<string> = new Set<GuestInvitationStatus>([
  'pending',
  'redeemed',
  'revoked',
  'expired',
]);
const guestResource = (identityId: string) => `guests/${identityId}`;
const invitationResource = (invitationId: string) => `guests/invitations/${invitationId}`;
const pendingKey = (address: string) => `pending:${address}`;
const iso = (at: number) => new Date(at).toISOString();
/** A new invitation token: `biam_gst_` and 43 random base64url characters, a prefix secret scanners can look for. */
const invitationToken = () => `biam_gst_${randomBytes(32).toString('base64url')}`;

function flag(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') throw new IamError('INVALID_INPUT', `${name} must be a boolean`);
  return value;
}

/** An object whose keys are all among `allowed`. */
function fields(value: unknown, name: string, allowed: readonly string[]): Record<string, unknown> {
  const record = object(value);
  for (const key of Object.keys(record))
    if (!allowed.includes(key))
      throw new IamError('INVALID_INPUT', `Unknown ${name} setting ${key}`);
  return record;
}

/** Lowercase domains, each checked like a verified domain, deduplicated and sorted. */
function domainList(value: unknown, name: string): string[] {
  return [...new Set(strings(value, name).map((entry) => domainName(entry)))].sort();
}

/** Partner organizations by tenant ID: existing tenants other than this one, each named once. */
async function partnerList(
  tx: IamStore,
  tenantId: string,
  value: unknown,
  name: string,
): Promise<CrossTenantPartner[]> {
  if (!Array.isArray(value) || value.length > 100)
    throw new IamError('INVALID_INPUT', `${name} must list at most 100 organizations`);
  const partners: CrossTenantPartner[] = [];
  for (const item of value) {
    const entry = fields(item, name, ['tenantId', 'allow']);
    const partnerId = text(entry.tenantId, `${name}.tenantId`);
    const allowed = flag(entry.allow, `${name}.allow`);
    if (partnerId === tenantId)
      throw new IamError('INVALID_INPUT', `${name} cannot name this organization`);
    if (partners.some((partner) => partner.tenantId === partnerId))
      throw new IamError('INVALID_INPUT', `${name} names ${partnerId} more than once`);
    const partner = await tx.get<Tenant>('tenants', partnerId);
    if (!partner || partner.status === 'deleted')
      throw new IamError('INVALID_INPUT', `${name}: unknown organization ${partnerId}`);
    partners.push({ tenantId: partnerId, allow: allowed });
  }
  return partners.sort((a, b) => (a.tenantId < b.tenantId ? -1 : a.tenantId > b.tenantId ? 1 : 0));
}

/** A person's own session in the tenant: an ordinary user session or their API key, of that tenant. */
function ownSession(principal: AuthenticatedPrincipal, tenantId: string, what: string): void {
  if (
    !actsInOwnRight(principal.session) ||
    principal.session.tenantId !== tenantId ||
    principal.identity.tenantId !== tenantId
  )
    throw new IamError(
      'ACCESS_DENIED',
      `${what} from an ordinary session of the organization`,
      403,
    );
}

/** The caller as the sponsor of the guests they invite, when they can sponsor guests themselves. */
function callerSponsor(
  ctx: ServerContext,
  principal: AuthenticatedPrincipal,
  tenantId: string,
): Identity {
  if (
    !actsInOwnRight(principal.session) ||
    principal.session.tenantId !== tenantId ||
    !canSponsor(ctx, principal.identity, tenantId)
  )
    throw new IamError(
      'INVALID_SPONSOR',
      'Name a sponsor (sponsorId): only an active member of the organization who is not a guest can sponsor guests',
    );
  return principal.identity;
}

/**
 * Naming someone other than oneself as a guest's sponsor makes them accountable for the guest, and gives the guest
 * whatever policies grant on `principal.guestSponsorId` (such as what the sponsor owns), so it needs what giving a guest
 * another sponsor needs: iam:guests:manage (here on iam/guests/invitations). Checked before the sponsor is validated,
 * so it reveals nothing about them; the refusal is audited as a denial.
 */
async function authorizeOtherSponsor(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  sponsorId: unknown,
): Promise<void> {
  if (
    text(sponsorId, 'sponsorId') === principal.identity.id &&
    actsInOwnRight(principal.session) &&
    principal.session.tenantId === tenantId
  )
    return;
  const decision = await ctx.decisions.decide(
    tx,
    principal,
    { tenantId, action: 'iam:guests:manage', resource: { type: 'iam', id: 'guests/invitations' } },
    true,
  );
  if (!decision.allowed)
    throw new OperationDenied('Naming someone else as the sponsor needs iam:guests:manage');
}

/**
 * Moving the access end of a guest who owns the organization (or is a root administrator) changes an owner's expiry,
 * so it needs what `identities.update` asks for: an owner of the tenant in person or a root caller; and an end (`next`)
 * is never given to the last active owner, nor to the last owner without one.
 */
async function assertOwnerExpiryControl(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  identity: Identity,
  next: number | undefined,
): Promise<void> {
  if (identity.rootAdmin && !(await ctx.rootPrincipal(tx, principal)))
    throw new IamError('ACCESS_DENIED', 'Root capability is protected', 403);
  await assertOwnerControl(
    ctx,
    tx,
    principal,
    identity,
    'Only an owner can change an owner’s expiry',
  );
  if (!identity.owner || next === undefined) return;
  await ctx.protectLastOwner(tx, identity);
  if (
    typeof identity.expiresAt !== 'number' &&
    !(
      await tx.find<Identity>('identities', {
        tenantId: identity.tenantId,
        owner: true,
        status: 'active',
      })
    ).some((other) => other.id !== identity.id && typeof other.expiresAt !== 'number')
  )
    throw new IamError('LAST_OWNER', 'The last owner without an expiry cannot be given one', 409);
}

/** Display names by identity ID, each read once per call. */
function nameReader(tx: IamStore): (identityId: string) => Promise<string | undefined> {
  const names = new Map<string, string | undefined>();
  return async (identityId) => {
    if (!names.has(identityId))
      names.set(identityId, (await tx.get<Identity>('identities', identityId))?.name);
    return names.get(identityId);
  };
}

/** A guest's account and identity in the tenant; NOT_FOUND for anyone else. */
async function loadGuest(
  tx: IamStore,
  tenantId: string,
  identityId: string,
): Promise<{ account: GuestAccount; identity: Identity }> {
  const account = await tx.get<GuestAccount>(guestCollections.accounts, identityId);
  const identity =
    account?.tenantId === tenantId
      ? await tx.get<Identity>('identities', account.identityId)
      : undefined;
  if (!account || !identity || identity.tenantId !== tenantId || identity.status === 'deleted')
    throw new IamError('NOT_FOUND', 'Guest not found', 404);
  return { account, identity };
}

/**
 * Refuses an address that already belongs to someone in the tenant. A former guest's disabled account keeps its
 * address, so the refusal says how to go on: delete that account first (the audit trail keeps its history).
 */
async function assertNewcomer(tx: IamStore, tenantId: string, address: string): Promise<void> {
  const [existing] = await tx.find<Identity>('identities', { tenantId, email: address });
  if (existing)
    throw new IamError(
      'CONFLICT',
      existing.guest && existing.status === 'disabled'
        ? 'This address belongs to a former guest whose disabled account still holds it: delete that account to invite the address again'
        : 'Someone with this email address already belongs to this organization',
      409,
    );
}

/**
 * Makes way for a pending invitation to `address`: another one still open is a conflict, and one that lapsed without
 * the worker noticing is marked expired first. `except` is the invitation being sent again.
 */
async function claimPendingKey(
  tx: IamStore,
  tenantId: string,
  address: string,
  now: number,
  except?: string,
): Promise<void> {
  for (const open of await tx.find<GuestInvitation>(guestCollections.invitations, {
    tenantId,
    uniqueKey: pendingKey(address),
  })) {
    if (open.id === except) continue;
    if (open.expiresAt > now)
      throw new IamError(
        'CONFLICT',
        'This address already has a pending guest invitation: send it again or revoke it',
        409,
      );
    const { uniqueKey: _open, ...rest } = open;
    await tx.put<GuestInvitation>(guestCollections.invitations, { ...rest, status: 'expired' });
  }
}

/** The account's status as it stands: an active account whose access end passed is expired already. */
function accountStatus(
  ctx: ServerContext,
  account: GuestAccount,
  identity: Identity,
): GuestAccountStatus {
  return account.status === 'active' && ctx.identityExpired(identity) ? 'expired' : account.status;
}

async function guestView(
  ctx: ServerContext,
  tx: IamStore,
  account: GuestAccount,
  identity: Identity,
  nameOf: (identityId: string) => Promise<string | undefined>,
): Promise<GuestView> {
  const sponsorName = await nameOf(account.sponsorId);
  const signIns = await tx.get<StoredRecord & SignInRecord>('authSignIns', identity.id);
  return {
    identityId: identity.id,
    tenantId: identity.tenantId,
    name: identity.name,
    ...(identity.email ? { email: identity.email } : {}),
    status: identity.status,
    accountStatus: accountStatus(ctx, account, identity),
    sponsorId: account.sponsorId,
    ...(sponsorName !== undefined ? { sponsorName } : {}),
    sponsorMissing: account.sponsorMissing === true,
    ...(account.homeTenantId ? { homeTenantId: account.homeTenantId } : {}),
    ...(identity.guest?.homeDomain ? { homeDomain: identity.guest.homeDomain } : {}),
    invitationId: account.invitationId,
    invitedBy: account.invitedBy,
    redeemedAt: account.redeemedAt,
    ...(account.attestedAt !== undefined ? { attestedAt: account.attestedAt } : {}),
    ...(account.attestedBy !== undefined ? { attestedBy: account.attestedBy } : {}),
    reviewDueAt: account.reviewDueAt,
    ...(identity.expiresAt !== undefined ? { expiresAt: identity.expiresAt } : {}),
    ...(typeof signIns?.lastAt === 'number' ? { lastSignInAt: signIns.lastAt } : {}),
  };
}

async function invitationView(
  ctx: ServerContext,
  invitation: GuestInvitation,
  nameOf: (identityId: string) => Promise<string | undefined>,
): Promise<GuestInvitationView> {
  const sponsorName = await nameOf(invitation.sponsorId);
  const inviterName = await nameOf(invitation.invitedBy);
  return {
    id: invitation.id,
    tenantId: invitation.tenantId,
    email: invitation.email,
    status:
      invitation.status === 'pending' && invitation.expiresAt <= ctx.now()
        ? 'expired'
        : invitation.status,
    sponsorId: invitation.sponsorId,
    ...(sponsorName !== undefined ? { sponsorName } : {}),
    invitedBy: invitation.invitedBy,
    ...(inviterName !== undefined ? { inviterName } : {}),
    ...(invitation.message !== undefined ? { message: invitation.message } : {}),
    roleIds: invitation.roleIds,
    groupIds: invitation.groupIds,
    packageIds: invitation.packageIds,
    accessDays: invitation.accessDays,
    ...(invitation.homeTenantId ? { homeTenantId: invitation.homeTenantId } : {}),
    expiresAt: invitation.expiresAt,
    createdAt: invitation.createdAt,
    sentAt: invitation.sentAt,
    ...(invitation.redeemedAt !== undefined ? { redeemedAt: invitation.redeemedAt } : {}),
    ...(invitation.identityId !== undefined ? { identityId: invitation.identityId } : {}),
    ...(invitation.revokedAt !== undefined ? { revokedAt: invitation.revokedAt } : {}),
    ...(invitation.revokedBy !== undefined ? { revokedBy: invitation.revokedBy } : {}),
    ...(invitation.revokedReason !== undefined ? { revokedReason: invitation.revokedReason } : {}),
  };
}

function settingsView(
  tenantId: string,
  settings: GuestSettings,
  stored: CrossTenantAccess | undefined,
): GuestSettingsView {
  return {
    tenantId,
    configured: stored !== undefined,
    inbound: settings.inbound,
    outbound: settings.outbound,
    accessDays: settings.accessDays,
    reviewEveryDays: settings.reviewEveryDays,
    ...(settings.guestBoundary ? { guestBoundary: settings.guestBoundary } : {}),
    ...(stored ? { updatedAt: stored.updatedAt, updatedBy: stored.updatedBy } : {}),
  };
}

/**
 * What an invitation may grant, authorized like `identities.invite` and `packages.assign`: iam:bindings:create on
 * each role (never a protected one) under the caller's grant authority, iam:groups:update on each group (never a
 * team's backing group) plus the authorities of the group's own bindings and, when a license product is assigned to one
 * of the groups, iam:licenses:assign (api/groups.ts), and iam:packages:assign on each package with the rights to
 * assign it by hand. Returns the grant authority the roles and groups are made under.
 */
async function authorizeGrants(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  grants: { roleIds: string[]; groupIds: string[]; packageIds: string[] },
): Promise<string | undefined> {
  const authorityId =
    grants.roleIds.length || grants.groupIds.length
      ? (await ctx.grantingAuthority(tx, principal, tenantId)).id
      : undefined;
  for (const roleId of grants.roleIds) {
    const role = await ctx.scoped<Role>(tx, 'roles', roleId, tenantId);
    if (role.protected)
      throw new IamError('PROTECTED_RESOURCE', 'Use owner transfer for protected roles', 403);
    await allow(ctx, tx, principal, tenantId, 'iam:bindings:create', role.id, 'grant this role');
  }
  for (const groupId of grants.groupIds) {
    assertNotTeamGroup(await ctx.scoped<Group>(tx, 'groups', groupId, tenantId));
    await allow(ctx, tx, principal, tenantId, 'iam:groups:update', groupId, 'add to this group');
    for (const binding of await tx.find<Binding>('bindings', {
      tenantId,
      subjectType: 'group',
      subjectId: groupId,
    }))
      await ctx.grantingAuthority(tx, principal, tenantId, binding.authorityId);
  }
  // The guest claims the seats of licensed groups (re-checked at redemption, inviterStillGrants).
  await assertMayClaimLicenses(
    ctx,
    tx,
    principal,
    tenantId,
    grants.groupIds,
    'A group you invite the guest into carries license seats; that needs iam:licenses:assign',
  );
  for (const packageId of grants.packageIds) {
    const pkg = await ctx.scoped<AccessPackage>(tx, 'accessPackages', packageId, tenantId);
    await allow(ctx, tx, principal, tenantId, 'iam:packages:assign', pkg.id, 'assign this package');
    await authorizePackage(ctx, tx, principal, pkg);
  }
  return authorityId;
}

/**
 * An invitation grants no more than its inviter could grant directly, at redemption as when it was sent: the inviter
 * must still be active and hold iam:guests:invite, the invitation's grant authority, iam:bindings:create on each role,
 * iam:groups:update on each group with the authorities of the group's bindings (and iam:licenses:assign when a license
 * product is assigned to one of them), and iam:packages:assign on each package with the rights to assign it by hand.
 * Returns the inviter as a simulated principal, under whom the grants are made.
 */
async function inviterStillGrants(
  ctx: ServerContext,
  tx: IamStore,
  invitation: GuestInvitation,
  tenantId: string,
): Promise<AuthenticatedPrincipal> {
  const refused = (message = 'The inviter can no longer grant this access') =>
    new IamError('INVITATION_INVALID', message);
  const inviter = await tx.get<Identity>('identities', invitation.invitedBy);
  if (!inviter || inviter.status !== 'active' || ctx.identityExpired(inviter))
    throw refused('The inviter can no longer invite guests');
  const asInviter = ctx.decisions.simulatedPrincipal(inviter, true);
  const may = async (action: string, resourceId: string) =>
    (
      await ctx.decisions.decide(
        tx,
        asInviter,
        { tenantId, action, resource: { type: 'iam', id: resourceId } },
        true,
      )
    ).allowed;
  const holds = (authorityId: string) =>
    ctx.grantingAuthority(tx, asInviter, tenantId, authorityId).then(
      () => true,
      () => false,
    );
  if (!(await may('iam:guests:invite', 'guests/invitations')))
    throw refused('The inviter can no longer invite guests');
  if (invitation.authorityId !== undefined && !(await holds(invitation.authorityId)))
    throw refused();
  for (const roleId of invitation.roleIds) {
    const role = await tx.get<Role>('roles', roleId);
    if (
      !role ||
      role.tenantId !== tenantId ||
      role.protected ||
      !(await may('iam:bindings:create', role.id))
    )
      throw refused();
  }
  for (const groupId of invitation.groupIds) {
    const group = await tx.get<Group>('groups', groupId);
    if (
      !group ||
      group.tenantId !== tenantId ||
      isTeamGroup(group) ||
      !(await may('iam:groups:update', group.id))
    )
      throw refused();
    for (const binding of await tx.find<Binding>('bindings', {
      tenantId,
      subjectType: 'group',
      subjectId: group.id,
    }))
      if (!(await holds(binding.authorityId))) throw refused();
  }
  // Groups that carry license seats, then or since, need the inviter's iam:licenses:assign.
  try {
    await assertMayClaimLicenses(ctx, tx, asInviter, tenantId, invitation.groupIds);
  } catch (error) {
    if (!(error instanceof OperationDenied)) throw error;
    throw refused();
  }
  for (const packageId of invitation.packageIds) {
    const pkg = await tx.get<AccessPackage>('accessPackages', packageId);
    if (!pkg || pkg.tenantId !== tenantId || !(await may('iam:packages:assign', pkg.id)))
      throw refused();
    try {
      await authorizePackage(ctx, tx, asInviter, pkg);
    } catch {
      throw refused();
    }
  }
  return asInviter;
}

/** Emails a guest invitation (template `guest-invitation`) with its token. */
async function sendInvitation(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  invitation: GuestInvitation,
  secret: string,
  nameOf: (identityId: string) => Promise<string | undefined>,
): Promise<void> {
  const inviterName = await nameOf(invitation.invitedBy);
  const sponsorName = await nameOf(invitation.sponsorId);
  await ctx.auth.enqueueDelivery(tx, {
    tenantId: tenant.id,
    kind: 'email',
    to: invitation.email,
    template: 'guest-invitation',
    payload: {
      tenantId: tenant.id,
      tenantName: tenant.name,
      ...(inviterName ? { inviterName } : {}),
      ...(sponsorName ? { sponsorName } : {}),
      ...(invitation.message ? { message: invitation.message } : {}),
      token: secret,
      expiresAt: iso(invitation.expiresAt),
    },
  });
}

/**
 * Moves the end of what the invitation granted (the account's tracked bindings, memberships and package assignments)
 * from `previous`, the end they were last given (`grantsEndAt`), to `next` (undefined: no end). Grants whose end was
 * changed since, and package assignments the package's maximum duration would not allow, keep theirs. A package
 * assignment lengthens only the memberships it created at redemption (`grants.packageMembershipIds`): nobody
 * authorizes a renewal for the package's current contents, so a group the package gained since, or a membership the
 * guest holds another way, keeps its end (retimeAssignment). When the end moves later and `claim` is given, it is
 * first shown the groups whose memberships move (convertToMember asks it for iam:licenses:assign).
 */
async function followAccessEnd(
  ctx: ServerContext,
  tx: IamStore,
  account: GuestAccount,
  previous: number | undefined,
  next: number | undefined,
  actorId: string,
  claim?: (groupIds: string[]) => Promise<void>,
): Promise<void> {
  if (previous === undefined || previous === next) return;
  const retime = <T extends { expiresAt?: number }>(record: T): T => {
    const { expiresAt: _end, ...rest } = record;
    return (next === undefined ? rest : { ...rest, expiresAt: next }) as T;
  };
  const bindings: Binding[] = [];
  for (const bindingId of account.grants.bindingIds) {
    const binding = await tx.get<Binding>('bindings', bindingId);
    if (
      !binding ||
      binding.tenantId !== account.tenantId ||
      binding.subjectType !== 'identity' ||
      binding.subjectId !== account.identityId ||
      binding.expiresAt !== previous
    )
      continue;
    bindings.push(binding);
  }
  const members: GroupMember[] = [];
  for (const membershipId of account.grants.membershipIds) {
    const member = await tx.get<GroupMember>('groupMembers', membershipId);
    if (
      !member ||
      member.tenantId !== account.tenantId ||
      member.identityId !== account.identityId ||
      member.expiresAt !== previous
    )
      continue;
    members.push(member);
  }
  const assignments: { pkg: AccessPackage; assignment: PackageAssignment }[] = [];
  for (const assignmentId of account.grants.packageAssignmentIds) {
    const assignment = await tx.get<PackageAssignment>('packageAssignments', assignmentId);
    if (
      !assignment ||
      assignment.tenantId !== account.tenantId ||
      assignment.identityId !== account.identityId ||
      assignment.expiresAt !== previous
    )
      continue;
    const pkg = await tx.get<AccessPackage>('accessPackages', assignment.packageId);
    if (!pkg || pkg.tenantId !== account.tenantId) continue;
    if (
      pkg.maxDurationMs !== undefined &&
      (next === undefined || next > ctx.now() + pkg.maxDurationMs)
    )
      continue;
    assignments.push({ pkg, assignment });
  }
  // Accounts redeemed before the package memberships were recorded lengthen the assignments' own memberships.
  const created = (assignment: PackageAssignment) =>
    new Set(account.grants.packageMembershipIds ?? assignment.membershipIds);
  if (claim && (next === undefined || next > previous)) {
    const groupIds = members.map((member) => member.groupId);
    for (const { pkg, assignment } of assignments) {
      const lengthened = created(assignment);
      for (const membershipId of assignment.membershipIds) {
        if (!lengthened.has(membershipId)) continue;
        const member = await tx.get<GroupMember>('groupMembers', membershipId);
        if (
          member?.packageAssignmentId === assignment.id &&
          ctx.liveMembership(member) &&
          pkg.groupIds.includes(member.groupId)
        )
          groupIds.push(member.groupId);
      }
    }
    await claim(groupIds);
  }
  for (const binding of bindings) await tx.put<Binding>('bindings', retime(binding));
  for (const member of members) await tx.put<GroupMember>('groupMembers', retime(member));
  // Teams that sync their members from these groups follow the new end (teams.ts).
  for (const groupId of new Set(members.map((member) => member.groupId)))
    await syncTeamsFromGroups(ctx, tx, account.tenantId, { groupId, actorId });
  for (const { pkg, assignment } of assignments)
    await retimeAssignment(ctx, tx, pkg, assignment, next, created(assignment));
}

/**
 * B2B guest collaboration (guests.ts): email invitations and their public redemption, the guest directory, sponsor
 * attestation, sponsor changes, removal, conversion to a member, and the tenant's cross-tenant access settings. Actions
 * `iam:guests:read`, `iam:guests:invite`, `iam:guests:manage` and `iam:guests:settings` on `iam/guests`,
 * `iam/guests/{identityId}`, `iam/guests/invitations[/{id}]` and `iam/guests/settings`.
 */
export function createGuestsApi(ctx: ServerContext) {
  const { auth, catalog, options } = ctx;
  const { operation } = ctx.operations;

  /** Renews a guest's access; `asSponsor` when the caller is the guest's sponsor acting without iam:guests:manage. */
  async function attestGuest(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    identityId: string,
    days: unknown,
    asSponsor: boolean,
  ): Promise<GuestView> {
    if (principal.identity.id === identityId)
      throw new OperationDenied('Guests cannot renew their own access');
    if (isGuest(principal.identity))
      throw new OperationDenied('Guests cannot renew guests’ access');
    const { account, identity } = await loadGuest(tx, tenantId, identityId);
    if (
      asSponsor &&
      (account.sponsorId !== principal.identity.id ||
        !canSponsor(ctx, principal.identity, tenantId))
    )
      throw new IamError(
        'ACCESS_DENIED',
        'Only the guest’s sponsor or an administrator can renew their access',
        403,
      );
    if (
      account.status !== 'active' ||
      !identity.guest ||
      identity.status !== 'active' ||
      ctx.identityExpired(identity)
    )
      throw new IamError(
        'INVALID_TRANSITION',
        'This guest is disabled or their access has ended: an administrator can restore it (a later expiresAt, then re-enable the account), or delete the account and invite the person again',
        409,
      );
    const settings = await guestSettings(tx, tenantId);
    const accessDays = integer(days ?? settings.accessDays, 'days', 1, guestLimits.maxAccessDays);
    const now = ctx.now();
    const expiresAt = now + accessDays * guestDayMs;
    // A guest who owns the organization keeps an owner's protection: their sponsor alone cannot move their end.
    await assertOwnerExpiryControl(ctx, tx, principal, identity, expiresAt);
    const previous = identity.expiresAt;
    const updated = await tx.put<Identity>('identities', { ...identity, expiresAt });
    await followAccessEnd(ctx, tx, account, account.grantsEndAt, expiresAt, principal.identity.id);
    const reviewDueAt = Math.min(now + settings.reviewEveryDays * guestDayMs, expiresAt);
    const renewed = await tx.put<GuestAccount>(guestCollections.accounts, {
      ...account,
      attestedAt: now,
      attestedBy: principal.identity.id,
      reviewDueAt,
      grantsEndAt: expiresAt,
    });
    await ctx.events.audit(tx, principal, 'guest:attest', tenantId, identity.id, 'allow', false, {
      days: accessDays,
      expiresAt,
      reviewDueAt,
      asSponsor,
      ...(previous !== undefined ? { previousExpiresAt: previous } : {}),
    });
    return guestView(ctx, tx, renewed, updated, nameReader(tx));
  }

  return {
    /**
     * Invites a person from outside the organization (or from another tenant) as a guest: emails them a personal
     * invitation (template `guest-invitation`) to redeem within `expiresInDays`. Refused when the address already
     * belongs to someone here or has a pending invitation (CONFLICT), is on one of the tenant's own verified domains, or
     * when the tenant's inbound or the person's organization's outbound settings do not admit it (GUEST_NOT_ALLOWED).
     * The sponsor is the caller unless `sponsorId` names another member. Roles, groups and packages are authorized now
     * like `identities.invite` and granted at redemption under the caller's authority, until the guest's access ends.
     * Requires iam:guests:invite on iam/guests/invitations and an email delivery callback; audited as `guest:invite`.
     * Naming someone else as the sponsor also needs iam:guests:manage there. The address's domain is compared (and
     * stored) in its canonical form (lowercase, punycode, no trailing dot); an assumed role cannot invite.
     */
    invite: async (
      credential: CredentialInput,
      input: GuestInviteInput,
    ): Promise<GuestInvitationView> =>
      operation(
        credential,
        input.tenantId,
        'iam:guests:invite',
        'guests/invitations',
        async ({ tx, principal, tenant }) => {
          if (!options.authentication?.sendEmail)
            throw new IamError(
              'DELIVERY_REQUIRED',
              'Guest invitations require an email delivery callback',
            );
          if (tenant.status !== 'active')
            throw new IamError('TENANT_INACTIVE', 'Tenant must be active');
          if (tenant.parentId === null)
            throw new IamError('INVALID_INPUT', 'The platform tenant does not take guests');
          if (principal.session.impersonatorId)
            throw new IamError(
              'IMPERSONATION_RESTRICTED',
              'Guests cannot be invited while impersonating',
              403,
            );
          // Redemption re-checks the inviter's rights as the inviter acting in their own right (inviterStillGrants);
          // an assumed role is not there to re-check, so an invitation sent from one could never be redeemed.
          if (principal.session.kind === 'role')
            throw new OperationDenied(
              'Guests are invited from your own session, not an assumed role',
            );
          const to = guestAddress(input.email);
          const settings = await guestSettings(tx, tenant.id);
          const accessDays = integer(
            input.accessDays ?? settings.accessDays,
            'accessDays',
            1,
            guestLimits.maxAccessDays,
          );
          const lifetime = integer(
            input.expiresInDays ?? guestLimits.invitationDays,
            'expiresInDays',
            1,
            guestLimits.maxInvitationDays,
          );
          const message =
            input.message !== undefined ? text(input.message, 'message', 1000).trim() : undefined;
          const roleIds = [...new Set(strings(input.roleIds ?? [], 'roleIds'))];
          const groupIds = [...new Set(strings(input.groupIds ?? [], 'groupIds'))];
          const packageIds = [...new Set(strings(input.packageIds ?? [], 'packageIds'))];
          await assertNewcomer(tx, tenant.id, to);
          const origin = await guestOrigin(tx, tenant.id, to);
          await assertGuestAdmitted(tx, settings, tenant.id, origin);
          if (input.sponsorId !== undefined)
            await authorizeOtherSponsor(ctx, tx, principal, tenant.id, input.sponsorId);
          const sponsor =
            input.sponsorId !== undefined
              ? await guestSponsor(ctx, tx, tenant.id, input.sponsorId)
              : callerSponsor(ctx, principal, tenant.id);
          const authorityId = await authorizeGrants(ctx, tx, principal, tenant.id, {
            roleIds,
            groupIds,
            packageIds,
          });
          const now = ctx.now();
          await claimPendingKey(tx, tenant.id, to, now);
          const secret = invitationToken();
          const invitation: GuestInvitation = {
            id: id(),
            tenantId: tenant.id,
            uniqueKey: pendingKey(to),
            email: to,
            tokenHash: hash(secret),
            sponsorId: sponsor.id,
            invitedBy: principal.identity.id,
            ...(message ? { message } : {}),
            roleIds,
            groupIds,
            packageIds,
            ...(authorityId !== undefined ? { authorityId } : {}),
            accessDays,
            ...(origin.homeTenantId ? { homeTenantId: origin.homeTenantId } : {}),
            expiresAt: now + lifetime * guestDayMs,
            createdAt: now,
            sentAt: now,
            status: 'pending',
          };
          await tx.insert<GuestInvitation>(guestCollections.invitations, invitation);
          const nameOf = nameReader(tx);
          await sendInvitation(ctx, tx, tenant, invitation, secret, nameOf);
          await ctx.events.audit(
            tx,
            principal,
            'guest:invite',
            tenant.id,
            invitation.id,
            'allow',
            false,
            {
              email: to,
              sponsorId: sponsor.id,
              roleIds,
              groupIds,
              packageIds,
              accessDays,
              expiresAt: invitation.expiresAt,
              ...(origin.homeTenantId ? { homeTenantId: origin.homeTenantId } : {}),
            },
          );
          return invitationView(ctx, invitation, nameOf);
        },
      ),
    /**
     * The tenant's guest invitations, newest first, optionally one `status` (a lapsed pending invitation counts as
     * expired). Tokens are never returned. Requires iam:guests:read on iam/guests/invitations.
     */
    listInvitations: async (
      credential: CredentialInput,
      input: { tenantId: string; status?: GuestInvitationStatus },
    ): Promise<GuestInvitationView[]> => {
      if (input.status !== undefined && !invitationStatuses.has(input.status))
        throw new IamError('INVALID_INPUT', 'status must be pending, redeemed, revoked or expired');
      return operation(
        credential,
        input.tenantId,
        'iam:guests:read',
        'guests/invitations',
        async ({ tx, tenant }) => {
          const nameOf = nameReader(tx);
          const views: GuestInvitationView[] = [];
          for (const invitation of (
            await tx.find<GuestInvitation>(guestCollections.invitations, { tenantId: tenant.id })
          ).sort(byNewest)) {
            const view = await invitationView(ctx, invitation, nameOf);
            if (input.status === undefined || view.status === input.status) views.push(view);
          }
          return views;
        },
      );
    },
    /**
     * Revokes a pending guest invitation; its token stops working. Requires iam:guests:manage on
     * iam/guests/invitations/{id}; audited as `guest:invitation-revoke`.
     */
    revokeInvitation: async (
      credential: CredentialInput,
      input: { tenantId: string; invitationId: string },
    ): Promise<GuestInvitationView> => {
      const invitationId = text(input.invitationId, 'invitationId');
      return operation(
        credential,
        input.tenantId,
        'iam:guests:manage',
        invitationResource(invitationId),
        async ({ tx, principal, tenant }) => {
          const invitation = await ctx.scoped<GuestInvitation>(
            tx,
            guestCollections.invitations,
            invitationId,
            tenant.id,
          );
          if (invitation.status !== 'pending')
            throw new IamError(
              'INVALID_TRANSITION',
              'Only a pending invitation can be revoked',
              409,
            );
          const { uniqueKey: _open, ...rest } = invitation;
          const revoked = await tx.put<GuestInvitation>(guestCollections.invitations, {
            ...rest,
            status: 'revoked',
            revokedAt: ctx.now(),
            revokedBy: principal.identity.id,
          });
          await ctx.events.audit(
            tx,
            principal,
            'guest:invitation-revoke',
            tenant.id,
            invitation.id,
            'allow',
            false,
            { email: invitation.email },
          );
          return invitationView(ctx, revoked, nameReader(tx));
        },
      );
    },
    /**
     * Sends a pending or lapsed guest invitation again with a new token (the earlier one stops working) and a new
     * lifetime (`expiresInDays`, default 14). The address and the cross-tenant settings are checked again, and so are the
     * sponsor (INVALID_SPONSOR) and the inviter's rights (INVITATION_INVALID). Requires iam:guests:invite on
     * iam/guests/invitations/{id}; audited as `guest:invitation-resend`.
     */
    resendInvitation: async (
      credential: CredentialInput,
      input: { tenantId: string; invitationId: string; expiresInDays?: number },
    ): Promise<GuestInvitationView> => {
      const invitationId = text(input.invitationId, 'invitationId');
      const lifetime = integer(
        input.expiresInDays ?? guestLimits.invitationDays,
        'expiresInDays',
        1,
        guestLimits.maxInvitationDays,
      );
      return operation(
        credential,
        input.tenantId,
        'iam:guests:invite',
        invitationResource(invitationId),
        async ({ tx, principal, tenant }) => {
          if (!options.authentication?.sendEmail)
            throw new IamError(
              'DELIVERY_REQUIRED',
              'Guest invitations require an email delivery callback',
            );
          if (tenant.status !== 'active')
            throw new IamError('TENANT_INACTIVE', 'Tenant must be active');
          const invitation = await ctx.scoped<GuestInvitation>(
            tx,
            guestCollections.invitations,
            invitationId,
            tenant.id,
          );
          if (invitation.status !== 'pending' && invitation.status !== 'expired')
            throw new IamError(
              'INVALID_TRANSITION',
              'Only a pending or lapsed invitation can be sent again',
              409,
            );
          await assertNewcomer(tx, tenant.id, invitation.email);
          const origin = await guestOrigin(tx, tenant.id, invitation.email);
          await assertGuestAdmitted(tx, await guestSettings(tx, tenant.id), tenant.id, origin);
          // Only an invitation that can still be redeemed goes out: its sponsor must still be able to sponsor, and its
          // inviter still grant what it grants (INVITATION_INVALID), as redemption checks again.
          await guestSponsor(ctx, tx, tenant.id, invitation.sponsorId);
          await inviterStillGrants(ctx, tx, invitation, tenant.id);
          const now = ctx.now();
          await claimPendingKey(tx, tenant.id, invitation.email, now, invitation.id);
          const secret = invitationToken();
          const { homeTenantId: _home, ...rest } = invitation;
          const renewed = await tx.put<GuestInvitation>(guestCollections.invitations, {
            ...rest,
            uniqueKey: pendingKey(invitation.email),
            tokenHash: hash(secret),
            status: 'pending',
            expiresAt: now + lifetime * guestDayMs,
            sentAt: now,
            ...(origin.homeTenantId ? { homeTenantId: origin.homeTenantId } : {}),
          });
          const nameOf = nameReader(tx);
          await sendInvitation(ctx, tx, tenant, renewed, secret, nameOf);
          await ctx.events.audit(
            tx,
            principal,
            'guest:invitation-resend',
            tenant.id,
            invitation.id,
            'allow',
            false,
            { email: invitation.email, expiresAt: renewed.expiresAt },
          );
          return invitationView(ctx, renewed, nameOf);
        },
      );
    },
    /**
     * Public: redeems a guest invitation with the invitee's name and a new password, creates the guest identity (email
     * verified, since the invitation reached the address), and signs them in with a password session. The invitation
     * must be pending and unexpired, the tenant's inbound and the home organization's outbound settings must still
     * admit the person, the inviter must still be able to grant what the invitation grants, and the sponsor must still
     * be able to sponsor (INVITATION_INVALID otherwise). The guest's access ends after the invitation's `accessDays`;
     * roles, groups and packages are granted under the inviter's authority until then. Separation-of-duties rules and
     * enforced invariants apply. Rate limited per tenant, client address and token; audited as `guest:redeem`.
     */
    redeem: async (input: {
      tenantId: string;
      token: string;
      name: string;
      password: string;
    }): Promise<EnrollmentResult> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const presented = text(input.token, 'token', 512);
      const name = text(input.name, 'name');
      // The guest signs in with this password from now on (the tenant's password rules apply when it is set).
      if (typeof input.password !== 'string')
        throw new IamError('INVALID_INPUT', 'A password is required');
      // Counted outside the transaction, so a refusal cannot roll the counters back. The client's own budget comes
      // first (with the network steps): a client refused there spends none of the budget every invitee shares.
      const ip = auth.currentClient()?.ip;
      if (ip)
        await auth.limitAttempt(tenantId, `guest-redeem:ip:${ipCounterKey(ip) ?? ip}`, {
          limit: 20,
        });
      await auth.limitAttempt(tenantId, 'guest-redeem', {
        limit: 500,
        ...(ip ? { countClient: false } : {}),
      });
      await auth.limitAttempt(tenantId, `guest-redeem:${hash(presented)}`, {
        limit: 10,
        countClient: false,
      });
      const result = await ctx.store.transaction(async (tx) => {
        const realm = await ctx.tenant(tx, tenantId);
        await auth.assertTenantActive(tx, realm.id);
        const invitation = (
          await tx.find<GuestInvitation>(guestCollections.invitations, {
            tenantId: realm.id,
            tokenHash: hash(presented),
          })
        )[0];
        const now = ctx.now();
        if (!invitation || invitation.status !== 'pending' || invitation.expiresAt <= now)
          throw new IamError('INVITATION_INVALID', 'Invitation is invalid');
        // Either side may have changed its settings (or verified the domain) since the invitation was sent.
        const settings = await guestSettings(tx, realm.id);
        const origin = await guestOrigin(tx, realm.id, invitation.email);
        await assertGuestAdmitted(tx, settings, realm.id, origin);
        const asInviter = await inviterStillGrants(ctx, tx, invitation, realm.id);
        const sponsor = await tx.get<Identity>('identities', invitation.sponsorId);
        if (!canSponsor(ctx, sponsor, realm.id))
          throw new IamError('INVITATION_INVALID', 'The sponsor can no longer sponsor guests');
        const guardrails = await invariantSnapshot(ctx, tx, realm.id, 'iam:identities:create');
        const created = await auth.createIdentity(tx, {
          tenantId: realm.id,
          email: invitation.email,
          name,
          password: input.password,
          emailVerified: true,
        });
        const expiresAt = now + invitation.accessDays * guestDayMs;
        const identity = await tx.put<Identity>('identities', {
          ...created,
          expiresAt,
          guest: {
            sponsorId: sponsor.id,
            since: now,
            homeDomain: origin.domain,
            ...(origin.homeTenantId ? { homeTenantId: origin.homeTenantId } : {}),
          },
        });
        const grants: GuestGrants = {
          bindingIds: [],
          membershipIds: [],
          packageAssignmentIds: [],
          packageMembershipIds: [],
        };
        for (const roleId of invitation.roleIds) {
          const binding = await tx.insert<Binding>('bindings', {
            id: id(),
            tenantId: realm.id,
            uniqueKey: `identity:${identity.id}:${roleId}:${invitation.authorityId}`,
            subjectType: 'identity',
            subjectId: identity.id,
            roleId,
            authorityId: invitation.authorityId!,
            expiresAt,
          });
          grants.bindingIds.push(binding.id);
        }
        for (const groupId of invitation.groupIds) {
          const member = await tx.insert<GroupMember>('groupMembers', {
            id: id(),
            tenantId: realm.id,
            uniqueKey: `${groupId}:${identity.id}`,
            groupId,
            identityId: identity.id,
            expiresAt,
          });
          grants.membershipIds.push(member.id);
          await syncTeamsFromGroups(ctx, tx, realm.id, { groupId, actorId: invitation.invitedBy });
        }
        for (const packageId of invitation.packageIds) {
          const pkg = await ctx.scoped<AccessPackage>(tx, 'accessPackages', packageId, realm.id);
          const { assignment } = await assignPackage(ctx, tx, asInviter, pkg, {
            identityId: identity.id,
            // A package's maximum duration can end its assignment before the guest's access.
            expiresAt:
              pkg.maxDurationMs !== undefined
                ? Math.min(expiresAt, now + pkg.maxDurationMs)
                : expiresAt,
            justification: `Guest invitation ${invitation.id}`,
          });
          grants.packageAssignmentIds.push(assignment.id);
          grants.packageMembershipIds!.push(...assignment.membershipIds);
        }
        await sodAssertIdentity(ctx, tx, realm.id, identity.id);
        await invariantVerify(ctx, tx, realm.id, guardrails);
        await tx.insert<GuestAccount>(guestCollections.accounts, {
          id: identity.id,
          tenantId: realm.id,
          identityId: identity.id,
          sponsorId: sponsor.id,
          email: invitation.email,
          ...(origin.homeTenantId ? { homeTenantId: origin.homeTenantId } : {}),
          source: 'invitation',
          invitationId: invitation.id,
          invitedBy: invitation.invitedBy,
          redeemedAt: now,
          reviewDueAt: Math.min(now + settings.reviewEveryDays * guestDayMs, expiresAt),
          status: 'active',
          grants,
          grantsEndAt: expiresAt,
        });
        const { uniqueKey: _open, ...rest } = invitation;
        await tx.put<GuestInvitation>(guestCollections.invitations, {
          ...rest,
          status: 'redeemed',
          redeemedAt: now,
          identityId: identity.id,
        });
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: realm.id,
          actorId: identity.id,
          action: 'guest:redeem',
          resourceId: identity.id,
          timestamp: now,
          outcome: 'allow',
          metadata: {
            invitationId: invitation.id,
            invitedBy: invitation.invitedBy,
            sponsorId: sponsor.id,
            roleIds: invitation.roleIds,
            groupIds: invitation.groupIds,
            packageIds: invitation.packageIds,
            expiresAt,
            ...(origin.homeTenantId ? { homeTenantId: origin.homeTenantId } : {}),
          },
        });
        // The guest just set a password: a password sign-in, refused like one where the tenant does not accept them.
        const issued = await auth.completeAuthentication(tx, identity, 'password');
        return { identity: publicIdentity(identity), ...issued };
      });
      // Birthright rules that test identity.guest apply now rather than at the next scheduled reconcile.
      return afterIdentityChange(ctx, tenantId, [result.identity.id], result);
    },
    /**
     * The tenant's guests by name, optionally those of one sponsor, one account `status`, or whose access ends within
     * `expiringWithinDays`; `limit`/`offset` page through them. Each carries the sponsor's name, the access end, the
     * next review and the last sign-in. Requires iam:guests:read on iam/guests.
     */
    list: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        sponsorId?: string;
        status?: GuestAccountStatus;
        expiringWithinDays?: number;
        limit?: number;
        offset?: number;
      },
    ): Promise<GuestPage> => {
      const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
      const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
      if (input.status !== undefined && !accountStatuses.has(input.status))
        throw new IamError('INVALID_INPUT', 'status must be active, expired, removed or converted');
      const sponsorId =
        input.sponsorId !== undefined ? text(input.sponsorId, 'sponsorId') : undefined;
      const within =
        input.expiringWithinDays !== undefined
          ? integer(input.expiringWithinDays, 'expiringWithinDays', 0, 3650)
          : undefined;
      return operation(
        credential,
        input.tenantId,
        'iam:guests:read',
        'guests',
        async ({ tx, tenant }) => {
          const horizon = within !== undefined ? ctx.now() + within * guestDayMs : undefined;
          const rows: Array<{ account: GuestAccount; identity: Identity }> = [];
          for (const account of await tx.find<GuestAccount>(guestCollections.accounts, {
            tenantId: tenant.id,
            ...(sponsorId !== undefined ? { sponsorId } : {}),
          })) {
            const identity = await tx.get<Identity>('identities', account.identityId);
            if (!identity || identity.tenantId !== tenant.id || identity.status === 'deleted')
              continue;
            if (
              input.status !== undefined &&
              accountStatus(ctx, account, identity) !== input.status
            )
              continue;
            if (
              horizon !== undefined &&
              (identity.expiresAt === undefined || identity.expiresAt > horizon)
            )
              continue;
            rows.push({ account, identity });
          }
          rows.sort(
            (a, b) =>
              a.identity.name.localeCompare(b.identity.name, 'en') ||
              (a.identity.id < b.identity.id ? -1 : 1),
          );
          const nameOf = nameReader(tx);
          const guests: GuestView[] = [];
          for (const row of rows.slice(offset, offset + limit))
            guests.push(await guestView(ctx, tx, row.account, row.identity, nameOf));
          return { guests, total: rows.length };
        },
      );
    },
    /** One guest. Requires iam:guests:read on iam/guests/{identityId}. */
    get: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string },
    ): Promise<GuestView> => {
      const identityId = text(input.identityId, 'identityId');
      return operation(
        credential,
        input.tenantId,
        'iam:guests:read',
        guestResource(identityId),
        async ({ tx, tenant }) => {
          const { account, identity } = await loadGuest(tx, tenant.id, identityId);
          return guestView(ctx, tx, account, identity, nameReader(tx));
        },
      );
    },
    /**
     * Renews a guest's access: their access (and what the invitation granted with it) now ends `days` from now (1 to
     * 365, default the tenant's `accessDays`), and the next review is due after the tenant's `reviewEveryDays`. The
     * guest's sponsor may do it without any permission; anyone else needs iam:guests:manage on iam/guests/{identityId}.
     * Guests renew nobody's access, their own included. An ended or disabled guest is refused (INVALID_TRANSITION).
     * Audited as `guest:attest`. Renewing moves only what the invitation granted at redemption (never a group a
     * package gained since) and never past 365 days, so it needs no iam:licenses:assign for licensed groups, from the
     * sponsor or an administrator (who could name themselves sponsor with `setSponsor` anyway).
     */
    attest: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; days?: number },
    ): Promise<GuestView> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const identityId = text(input.identityId, 'identityId');
      const authenticated = await ctx.principals.authenticate(credential);
      const sponsoring = await ctx.store.transaction(async (tx) => {
        const account = await tx.get<GuestAccount>(guestCollections.accounts, identityId);
        return account?.tenantId === tenantId && account.sponsorId === authenticated.identity.id;
      });
      // Anyone but the sponsor goes through the permission check (and its audit).
      if (!sponsoring)
        return operation(
          credential,
          tenantId,
          'iam:guests:manage',
          guestResource(identityId),
          ({ tx, principal }) =>
            attestGuest(tx, principal, tenantId, identityId, input.days, false),
        );
      return ctx.store.transaction(async (tx) => {
        await auth.assertTenantActive(tx, tenantId);
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        ownSession(principal, tenantId, 'Sponsors renew their guests’ access');
        if (principal.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'A guest’s access cannot be renewed while impersonating',
            403,
          );
        return attestGuest(tx, principal, tenantId, identityId, input.days, true);
      });
    },
    /**
     * Gives an active guest a new sponsor (an active member who is not a guest), clearing a missing-sponsor flag.
     * Requires recent authentication and iam:guests:manage on iam/guests/{identityId}; audited as
     * `guest:sponsor-change`.
     */
    setSponsor: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; sponsorId: string },
    ): Promise<GuestView> => {
      const identityId = text(input.identityId, 'identityId');
      return operation(
        credential,
        input.tenantId,
        'iam:guests:manage',
        guestResource(identityId),
        async ({ tx, principal, tenant }) => {
          auth.requireRecent(principal);
          // The sponsor renews the guest and policies grant on principal.guestSponsorId: guests never choose one,
          // their own included, as they never renew anyone (attest).
          if (identityId === principal.identity.id || isGuest(principal.identity))
            throw new OperationDenied('Guests cannot change a guest’s sponsor');
          const { account, identity } = await loadGuest(tx, tenant.id, identityId);
          if (account.status !== 'active' || !identity.guest)
            throw new IamError(
              'INVALID_TRANSITION',
              'Only an active guest has a sponsor to change',
              409,
            );
          const sponsor = await guestSponsor(ctx, tx, tenant.id, input.sponsorId);
          const moved = await setGuestSponsor(tx, account, identity, sponsor.id);
          await ctx.events.audit(
            tx,
            principal,
            'guest:sponsor-change',
            tenant.id,
            identity.id,
            'allow',
            false,
            { from: account.sponsorId, to: sponsor.id, reason: 'administrator' },
          );
          return guestView(ctx, tx, moved.account, moved.identity, nameReader(tx));
        },
      );
    },
    /**
     * Removes a guest in one transaction: disables the identity, ends its sessions, keys and delegations, removes every
     * role binding, group and team membership, package assignment, activation and relationship it holds (whichever
     * authority granted them, as deleting an identity does), cancels its pending requests and invitations, revokes the
     * grant authorities it holds, and closes the guest account as `removed`. An owner is refused (transfer ownership
     * first). Requires recent authentication and iam:guests:manage on iam/guests/{identityId}; audited as
     * `guest:remove` with the reason and counts.
     */
    remove: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; reason: string },
    ): Promise<GuestRemoval> => {
      const identityId = text(input.identityId, 'identityId');
      return operation(
        credential,
        input.tenantId,
        'iam:guests:manage',
        guestResource(identityId),
        async ({ tx, principal, tenant }) => {
          auth.requireRecent(principal);
          const reason = text(input.reason, 'reason', 512).trim();
          const { account, identity } = await loadGuest(tx, tenant.id, identityId);
          if (account.status === 'removed' || account.status === 'converted')
            throw new IamError(
              'INVALID_TRANSITION',
              'This guest was already removed or became a member',
              409,
            );
          if (identity.id === principal.identity.id)
            throw new IamError('INVALID_INPUT', 'You cannot remove yourself');
          if (identity.owner)
            throw new IamError(
              'INVALID_INPUT',
              'This guest owns the organization: transfer ownership first',
            );
          const tenantId = tenant.id;
          const now = ctx.now();
          const counts = {
            sessions: (await tx.find<StoredRecord>('sessions', { identityId: identity.id })).length,
            bindings: 0,
            memberships: 0,
            packages: 0,
          };
          // Package assignments first: they own their bindings and memberships, whichever authority issued them.
          for (const assignment of await tx.find<PackageAssignment>('packageAssignments', {
            tenantId,
            identityId: identity.id,
          })) {
            const removed = await revokeAssignment(ctx, tx, assignment);
            counts.bindings += removed.bindings;
            counts.memberships += removed.memberships;
            counts.packages++;
          }
          for (const activation of await tx.find<StoredRecord>('bindingActivations', {
            tenantId,
            identityId: identity.id,
          }))
            await tx.delete('bindingActivations', activation.id);
          for (const binding of await tx.find<Binding>('bindings', {
            tenantId,
            subjectType: 'identity',
            subjectId: identity.id,
          })) {
            await tx.delete('bindings', binding.id);
            counts.bindings++;
          }
          // Team memberships go first, taking the team-managed group memberships with them (teams.ts).
          await removeFromAllTeams(tx, tenantId, identity.id, now);
          await releaseDepartments(tx, tenantId, identity.id, now);
          const groups = new Set<string>();
          for (const membership of await tx.find<GroupMember>('groupMembers', {
            tenantId,
            identityId: identity.id,
          })) {
            await tx.delete('groupMembers', membership.id);
            groups.add(membership.groupId);
            counts.memberships++;
          }
          for (const groupId of groups)
            await syncTeamsFromGroups(ctx, tx, tenantId, {
              groupId,
              actorId: principal.identity.id,
            });
          for (const tuple of await tx.find<Relationship>('relationships', {
            tenantId,
            subjectType: 'identity',
            subjectId: identity.id,
          }))
            await tx.delete('relationships', tuple.id);
          for (const request of await tx.find<AccessRequest>('accessRequests', {
            tenantId,
            requesterId: identity.id,
            status: 'pending',
          }))
            await tx.put('accessRequests', { ...request, status: 'cancelled', reviewedAt: now });
          for (const request of await tx.find<StoredRecord>('packageRequests', {
            tenantId,
            identityId: identity.id,
            status: 'pending',
          }))
            await tx.put('packageRequests', { ...request, status: 'cancelled', decidedAt: now });
          for (const authority of await tx.find<GrantAuthority>('grantAuthorities', {
            tenantId,
            identityId: identity.id,
          }))
            if (!authority.revoked)
              await tx.put('grantAuthorities', { ...authority, revoked: true });
          await revokeDelegationsOf(ctx, tx, identity, principal.identity.id);
          await ctx.revokeAll(tx, identity.id);
          await revokeInvitationsBy(tx, identity.id);
          const disabled = await tx.put<Identity>('identities', {
            ...identity,
            status: 'disabled',
          });
          // A removed guest stays disabled: a threats containment of it can no longer be released.
          await endContainment(tx, identity.id, now);
          const removed = await tx.put<GuestAccount>(guestCollections.accounts, {
            ...account,
            status: 'removed',
            endedAt: now,
            endedBy: principal.identity.id,
            removalReason: reason,
          });
          await ctx.events.audit(
            tx,
            principal,
            'guest:remove',
            tenantId,
            identity.id,
            'allow',
            false,
            {
              reason,
              sponsorId: account.sponsorId,
              ...counts,
            },
          );
          return {
            guest: await guestView(ctx, tx, removed, disabled, nameReader(tx)),
            ...counts,
          };
        },
        // A disabled identity claims no license seat: reconciling releases the guest's seats (licenses.ts), as
        // identities.setStatus does.
      ).then((result) => afterIdentityChange(ctx, input.tenantId, [identityId], result));
    },
    /**
     * Makes an active guest an ordinary member: the `guest` marker goes (policies see `principal.guest: false`, and
     * birthright rules apply as to any member), the guest account closes as `converted`, and the access end stays
     * unless `clearExpiry` removes it together with the end of what the invitation granted. Requires recent
     * authentication and iam:guests:manage on iam/guests/{identityId}, and with `clearExpiry` iam:licenses:assign when
     * a license product is assigned to a group whose membership would lose its end (refused as `ACCESS_DENIED`, audited
     * as a denial); audited as `guest:convert`.
     */
    convertToMember: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; clearExpiry?: boolean },
    ): Promise<PublicIdentity> => {
      const identityId = text(input.identityId, 'identityId');
      const clearExpiry =
        input.clearExpiry === undefined ? false : flag(input.clearExpiry, 'clearExpiry');
      const converted = await operation(
        credential,
        input.tenantId,
        'iam:guests:manage',
        guestResource(identityId),
        async ({ tx, principal, tenant }) => {
          auth.requireRecent(principal);
          // Becoming a member lifts the guest boundary (and, with clearExpiry, the end): guests never make anyone a
          // member, themselves included, as they never renew anyone (attest).
          if (identityId === principal.identity.id)
            throw new OperationDenied('Guests cannot make themselves members');
          if (isGuest(principal.identity))
            throw new OperationDenied('Guests cannot make guests members');
          const { account, identity } = await loadGuest(tx, tenant.id, identityId);
          if (
            account.status !== 'active' ||
            !identity.guest ||
            identity.status !== 'active' ||
            ctx.identityExpired(identity)
          )
            throw new IamError(
              'INVALID_TRANSITION',
              'Only an active guest can become a member',
              409,
            );
          // Clearing an owner's end changes an owner's expiry.
          if (clearExpiry && identity.expiresAt !== undefined)
            await assertOwnerExpiryControl(ctx, tx, principal, identity, undefined);
          const { guest: _marker, expiresAt: previous, ...member } = identity;
          const updated = await tx.put<Identity>(
            'identities',
            clearExpiry || previous === undefined ? member : { ...member, expiresAt: previous },
          );
          // Keeping the guest in a licensed group for good is a claim on its seats, as clearing a membership's end
          // is in the groups API: unlike a renewal, which ends again, it needs iam:licenses:assign (api/groups.ts).
          if (clearExpiry)
            await followAccessEnd(
              ctx,
              tx,
              account,
              account.grantsEndAt,
              undefined,
              principal.identity.id,
              (groupIds) =>
                assertMayClaimLicenses(
                  ctx,
                  tx,
                  principal,
                  tenant.id,
                  groupIds,
                  'A group the guest would stay in for good carries license seats; clearing the end needs iam:licenses:assign',
                ),
            );
          const { grantsEndAt: _grantsEnd, ...closed } = account;
          await tx.put<GuestAccount>(guestCollections.accounts, {
            ...(clearExpiry ? closed : account),
            status: 'converted',
            endedAt: ctx.now(),
            endedBy: principal.identity.id,
          });
          await ctx.events.audit(
            tx,
            principal,
            'guest:convert',
            tenant.id,
            identity.id,
            'allow',
            false,
            {
              sponsorId: account.sponsorId,
              clearExpiry,
              ...(previous !== undefined ? { expiresAt: previous } : {}),
            },
          );
          return publicIdentity(updated);
        },
      );
      return afterIdentityChange(ctx, input.tenantId, [converted.id], converted);
    },
    /** The tenant's cross-tenant access settings (the defaults until configured). Requires iam:guests:read on iam/guests/settings. */
    getSettings: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<GuestSettingsView> =>
      operation(
        credential,
        input.tenantId,
        'iam:guests:read',
        'guests/settings',
        async ({ tx, tenant }) =>
          settingsView(
            tenant.id,
            await guestSettings(tx, tenant.id),
            await readGuestSettings(tx, tenant.id),
          ),
      ),
    /**
     * Changes the tenant's cross-tenant access settings; only the fields given change (inside `inbound` and
     * `outbound` too). Domains are lowercase host names matching themselves and their subdomains; partners name
     * existing tenants other than this one; `guestBoundary` is validated like any policy (null removes it). Requires
     * recent authentication and iam:guests:settings on iam/guests/settings; audited as `guest:settings`.
     */
    configure: async (
      credential: CredentialInput,
      input: GuestSettingsInput,
    ): Promise<GuestSettingsView> =>
      operation(
        credential,
        input.tenantId,
        'iam:guests:settings',
        'guests/settings',
        async ({ tx, principal, tenant }) => {
          auth.requireRecent(principal);
          // A misspelled setting (a `guestBoundry`) must fail rather than leave the tenant as it was.
          fields(input, 'guest', [
            'tenantId',
            'inbound',
            'outbound',
            'accessDays',
            'reviewEveryDays',
            'guestBoundary',
          ]);
          const stored = await readGuestSettings(tx, tenant.id);
          const current = await guestSettings(tx, tenant.id);
          const next: GuestSettings = {
            inbound: { ...current.inbound },
            outbound: { ...current.outbound },
            accessDays: current.accessDays,
            reviewEveryDays: current.reviewEveryDays,
            ...(current.guestBoundary ? { guestBoundary: current.guestBoundary } : {}),
          };
          const changed: string[] = [];
          if (input.inbound !== undefined) {
            const inbound = fields(input.inbound, 'inbound', [
              'allowGuests',
              'allowedDomains',
              'blockedDomains',
              'partners',
            ]);
            if (inbound.allowGuests !== undefined)
              next.inbound.allowGuests = flag(inbound.allowGuests, 'inbound.allowGuests');
            if (inbound.allowedDomains !== undefined)
              next.inbound.allowedDomains = domainList(
                inbound.allowedDomains,
                'inbound.allowedDomains',
              );
            if (inbound.blockedDomains !== undefined)
              next.inbound.blockedDomains = domainList(
                inbound.blockedDomains,
                'inbound.blockedDomains',
              );
            if (inbound.partners !== undefined)
              next.inbound.partners = await partnerList(
                tx,
                tenant.id,
                inbound.partners,
                'inbound.partners',
              );
            changed.push(...Object.keys(inbound).map((key) => `inbound.${key}`));
          }
          if (input.outbound !== undefined) {
            const outbound = fields(input.outbound, 'outbound', [
              'allowGuestInvitations',
              'partners',
            ]);
            if (outbound.allowGuestInvitations !== undefined)
              next.outbound.allowGuestInvitations = flag(
                outbound.allowGuestInvitations,
                'outbound.allowGuestInvitations',
              );
            if (outbound.partners !== undefined)
              next.outbound.partners = await partnerList(
                tx,
                tenant.id,
                outbound.partners,
                'outbound.partners',
              );
            changed.push(...Object.keys(outbound).map((key) => `outbound.${key}`));
          }
          if (input.accessDays !== undefined) {
            next.accessDays = integer(input.accessDays, 'accessDays', 1, guestLimits.maxAccessDays);
            changed.push('accessDays');
          }
          if (input.reviewEveryDays !== undefined) {
            next.reviewEveryDays = integer(
              input.reviewEveryDays,
              'reviewEveryDays',
              guestLimits.minReviewEveryDays,
              guestLimits.maxReviewEveryDays,
            );
            changed.push('reviewEveryDays');
          }
          if (input.guestBoundary !== undefined) {
            if (input.guestBoundary === null) delete next.guestBoundary;
            else {
              await catalog.validate(tx, tenant.id, input.guestBoundary);
              next.guestBoundary = input.guestBoundary;
            }
            changed.push('guestBoundary');
          }
          if (!changed.length) throw new IamError('INVALID_INPUT', 'Nothing to change');
          const record: CrossTenantAccess = {
            id: tenant.id,
            tenantId: tenant.id,
            ...next,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          };
          await (stored
            ? tx.put<CrossTenantAccess>(guestCollections.settings, record)
            : tx.insert<CrossTenantAccess>(guestCollections.settings, record));
          const partners = (list: CrossTenantPartner[]) =>
            list.map((partner) => ({ tenantId: partner.tenantId, allow: partner.allow }));
          await ctx.events.audit(
            tx,
            principal,
            'guest:settings',
            tenant.id,
            tenant.id,
            'allow',
            false,
            {
              changed,
              allowGuests: next.inbound.allowGuests,
              allowedDomains: next.inbound.allowedDomains,
              blockedDomains: next.inbound.blockedDomains,
              inboundPartners: partners(next.inbound.partners),
              allowGuestInvitations: next.outbound.allowGuestInvitations,
              outboundPartners: partners(next.outbound.partners),
              accessDays: next.accessDays,
              reviewEveryDays: next.reviewEveryDays,
              guestBoundary: next.guestBoundary !== undefined,
            },
          );
          return settingsView(tenant.id, next, record);
        },
      ),
    /**
     * The active guests the caller sponsors, the soonest review first; needs only an ordinary session of the tenant
     * (no permission).
     */
    mine: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<GuestView[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        ownSession(principal, tenantId, 'The guests you sponsor are listed');
        const nameOf = nameReader(tx);
        const views: GuestView[] = [];
        for (const account of await tx.find<GuestAccount>(guestCollections.accounts, {
          tenantId,
          sponsorId: principal.identity.id,
          status: 'active',
        })) {
          const identity = await tx.get<Identity>('identities', account.identityId);
          if (!identity || identity.tenantId !== tenantId || identity.status === 'deleted')
            continue;
          views.push(await guestView(ctx, tx, account, identity, nameOf));
        }
        return views.sort(
          (a, b) =>
            a.reviewDueAt - b.reviewDueAt ||
            a.name.localeCompare(b.name, 'en') ||
            (a.identityId < b.identityId ? -1 : 1),
        );
      });
    },
  };
}

/** Reminds sponsors of guests whose review is due or whose access ends soon (see `IamGuests.sendReviewReminders`). */
async function sendReviewReminders(
  ctx: ServerContext,
  input: { tenantId?: string; withinDays?: number },
): Promise<GuestReminderResult> {
  const withinDays = integer(input.withinDays ?? guestLimits.reminderDays, 'withinDays', 1, 90);
  if (!ctx.options.authentication?.sendEmail)
    throw new IamError(
      'DELIVERY_REQUIRED',
      'Guest review reminders require an email delivery callback',
    );
  const tenantIds =
    input.tenantId !== undefined
      ? [text(input.tenantId, 'tenantId')]
      : [
          ...new Set(
            (
              await ctx.store.find<GuestAccount>(guestCollections.accounts, { status: 'active' })
            ).map((account) => account.tenantId),
          ),
        ].sort();
  const result: GuestReminderResult = { sent: [], skipped: { inactive: 0, quiet: 0 } };
  for (const tenantId of tenantIds) {
    // Counted once the tenant's transaction committed.
    const outcome = await ctx.store.transaction(async (tx) => {
      const sent: GuestReminderResult['sent'] = [];
      const tenant = await tx.get<Tenant>('tenants', tenantId);
      if (!tenant || tenant.status !== 'active') return 'inactive' as const;
      const now = ctx.now();
      const horizon = now + withinDays * guestDayMs;
      // Reminder marks (lifecycle.ts) remember each guest and due date reminded; they outlive the due date.
      const reminded = new Map(
        (await tx.find<ExpiryReminderMark>('expiryReminderMarks', { tenantId })).map(
          (mark) => [mark.uniqueKey, mark] as const,
        ),
      );
      for (const account of (
        await tx.find<GuestAccount>(guestCollections.accounts, { tenantId, status: 'active' })
      ).sort((a, b) => (a.id < b.id ? -1 : 1))) {
        const guest = await tx.get<Identity>('identities', account.identityId);
        if (
          !guest ||
          guest.tenantId !== tenantId ||
          guest.status !== 'active' ||
          ctx.identityExpired(guest) ||
          !isGuest(guest)
        )
          continue;
        const reviewKey = `guest-review:${guest.id}:${account.reviewDueAt}`;
        // A reminded review stays reminded while it is outstanding: its mark is kept alive past the end it was given
        // (a guest without an end, or whose end an administrator moved), so the purge cannot let it go out again.
        const reviewMark = reminded.get(reviewKey);
        if (reviewMark && reviewMark.expiresAt <= horizon)
          await tx.put<ExpiryReminderMark>('expiryReminderMarks', {
            ...reviewMark,
            expiresAt: horizon + withinDays * guestDayMs,
          });
        // The review and the access end are each reminded once per date, so a review reminder that went unanswered
        // does not stand in for the warning that the access is about to end. One email covers whatever is due.
        const due = [
          {
            key: reviewKey,
            at: account.reviewDueAt,
            // Kept while the review stays overdue (until the access ends), so it is not reminded again.
            until: Math.max(account.reviewDueAt, guest.expiresAt ?? account.reviewDueAt),
          },
          ...(guest.expiresAt !== undefined
            ? [
                {
                  key: `guest-end:${guest.id}:${guest.expiresAt}`,
                  at: guest.expiresAt,
                  until: guest.expiresAt,
                },
              ]
            : []),
        ].filter((event) => event.at <= horizon && !reminded.has(event.key));
        if (!due.length) continue;
        const dueAt = Math.min(...due.map((event) => event.at));
        const sponsor = await tx.get<Identity>('identities', account.sponsorId);
        if (!canSponsor(ctx, sponsor, tenantId) || !sponsor.email) continue;
        await ctx.auth.enqueueDelivery(tx, {
          tenantId,
          kind: 'email',
          to: sponsor.email,
          template: 'guest-review',
          payload: {
            tenantId,
            tenantName: tenant.name,
            guestId: guest.id,
            guestName: guest.name,
            ...(guest.email ? { guestEmail: guest.email } : {}),
            dueAt: iso(dueAt),
            reviewDueAt: iso(account.reviewDueAt),
            ...(guest.expiresAt !== undefined ? { expiresAt: iso(guest.expiresAt) } : {}),
          },
        });
        for (const event of due)
          await tx.insert<ExpiryReminderMark>('expiryReminderMarks', {
            id: id(),
            tenantId,
            uniqueKey: event.key,
            identityId: guest.id,
            expiresAt: event.until + withinDays * guestDayMs,
          });
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'deployment-operator',
          action: 'guest:review-reminder',
          resourceId: guest.id,
          timestamp: now,
          outcome: 'allow',
          metadata: {
            sponsorId: sponsor.id,
            dueAt,
            ...(guest.expiresAt !== undefined ? { expiresAt: guest.expiresAt } : {}),
          },
        });
        sent.push({ tenantId, guestId: guest.id, sponsorId: sponsor.id, dueAt });
      }
      return sent;
    });
    if (outcome === 'inactive') result.skipped.inactive++;
    else if (!outcome.length) result.skipped.quiet++;
    else result.sent.push(...outcome);
  }
  return result;
}

/** The zero sweep result. */
const noSweep = (): GuestSweepResult => ({
  invitationsExpired: 0,
  accountsExpired: 0,
  accountsRestored: 0,
  sponsorsMissing: 0,
  ownersNotified: 0,
  partnersRemoved: 0,
});

/** One tenant's guest bookkeeping (see `IamGuests.sweep`); returns what it changed. */
async function sweepTenant(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
): Promise<GuestSweepResult> {
  const result = noSweep();
  const now = ctx.now();
  const tenant = await tx.get<Tenant>('tenants', tenantId);
  const record = (action: string, resourceId: string, metadata: Record<string, string | number>) =>
    ctx.events.recordAudit(tx, {
      id: id(),
      tenantId,
      actorId: 'deployment-operator',
      action,
      resourceId,
      timestamp: now,
      outcome: 'allow',
      metadata,
    });
  for (const invitation of await tx.find<GuestInvitation>(guestCollections.invitations, {
    tenantId,
    status: 'pending',
  }))
    if (invitation.expiresAt <= now) {
      const { uniqueKey: _open, ...rest } = invitation;
      await tx.put<GuestInvitation>(guestCollections.invitations, { ...rest, status: 'expired' });
      result.invitationsExpired++;
    }
  let owners: Identity[] | undefined;
  const accounts = [
    ...(await tx.find<GuestAccount>(guestCollections.accounts, { tenantId, status: 'active' })),
    ...(await tx.find<GuestAccount>(guestCollections.accounts, { tenantId, status: 'expired' })),
  ];
  for (let account of accounts) {
    const identity = await tx.get<Identity>('identities', account.identityId);
    if (!identity || identity.tenantId !== tenantId || identity.status === 'deleted') {
      // The identity is gone: its account goes with it (deleteIdentity removes it too).
      await tx.delete(guestCollections.accounts, account.id);
      continue;
    }
    if (account.status === 'active' && ctx.identityExpired(identity)) {
      account = await tx.put<GuestAccount>(guestCollections.accounts, {
        ...account,
        status: 'expired',
        endedAt: identity.expiresAt ?? now,
      });
      await record('guest:expire', identity.id, {
        sponsorId: account.sponsorId,
        expiresAt: identity.expiresAt ?? now,
      });
      result.accountsExpired++;
    } else if (
      account.status === 'expired' &&
      identity.status === 'active' &&
      !ctx.identityExpired(identity) &&
      isGuest(identity)
    ) {
      // An administrator gave the guest a later end and enabled them again.
      const { endedAt: _ended, endedBy: _by, ...rest } = account;
      account = await tx.put<GuestAccount>(guestCollections.accounts, {
        ...rest,
        status: 'active',
      });
      result.accountsRestored++;
    }
    if (account.status !== 'active') continue;
    const sponsor = await tx.get<Identity>('identities', account.sponsorId);
    const sponsorName = sponsor?.tenantId === tenantId ? sponsor.name : undefined;
    if (canSponsor(ctx, sponsor, tenantId)) {
      if (account.sponsorMissing || account.sponsorMissingNotifiedAt !== undefined) {
        const { sponsorMissing: _missing, sponsorMissingNotifiedAt: _notified, ...rest } = account;
        await tx.put<GuestAccount>(guestCollections.accounts, rest);
      }
      continue;
    }
    if (!account.sponsorMissing) {
      account = await tx.put<GuestAccount>(guestCollections.accounts, {
        ...account,
        sponsorMissing: true,
      });
      await record('guest:sponsor-missing', identity.id, { sponsorId: account.sponsorId });
      result.sponsorsMissing++;
    }
    // The owners hear about each guest once per loss, when the deployment can email and the tenant is active.
    if (
      account.sponsorMissingNotifiedAt === undefined &&
      tenant?.status === 'active' &&
      ctx.options.authentication?.sendEmail
    ) {
      owners ??= (
        await tx.find<Identity>('identities', { tenantId, owner: true, status: 'active' })
      ).filter((owner) => owner.email && !ctx.identityExpired(owner));
      for (const owner of owners) {
        await ctx.auth.enqueueDelivery(tx, {
          tenantId,
          kind: 'email',
          to: owner.email!,
          template: 'guest-sponsor-missing',
          payload: {
            tenantId,
            tenantName: tenant.name,
            guestId: identity.id,
            guestName: identity.name,
            ...(identity.email ? { guestEmail: identity.email } : {}),
            ...(sponsorName ? { sponsorName } : {}),
          },
        });
        result.ownersNotified++;
      }
      if (owners.length)
        await tx.put<GuestAccount>(guestCollections.accounts, {
          ...account,
          sponsorMissingNotifiedAt: now,
        });
    }
  }
  // Partner entries naming tenants that were purged since can never match again.
  const stored = await readGuestSettings(tx, tenantId);
  if (stored) {
    const existing = async (list: CrossTenantPartner[]) => {
      const kept: CrossTenantPartner[] = [];
      for (const partner of list)
        if (await tx.get<Tenant>('tenants', partner.tenantId)) kept.push(partner);
      return kept;
    };
    const inbound = await existing(stored.inbound.partners);
    const outbound = await existing(stored.outbound.partners);
    const removed =
      stored.inbound.partners.length -
      inbound.length +
      (stored.outbound.partners.length - outbound.length);
    if (removed) {
      await tx.put<CrossTenantAccess>(guestCollections.settings, {
        ...stored,
        inbound: { ...stored.inbound, partners: inbound },
        outbound: { ...stored.outbound, partners: outbound },
      });
      await record('guest:settings', tenantId, { partnersRemoved: removed });
      result.partnersRemoved += removed;
    }
  }
  return result;
}

/** Guest bookkeeping across tenants, one transaction per tenant (see `IamGuests.sweep`). */
async function sweepGuests(
  ctx: ServerContext,
  input: { tenantId?: string },
): Promise<GuestSweepResult> {
  const filter = input.tenantId !== undefined ? { tenantId: text(input.tenantId, 'tenantId') } : {};
  const result = noSweep();
  const tenantIds = new Set<string>();
  for (const invitation of await ctx.store.find<GuestInvitation>(guestCollections.invitations, {
    ...filter,
    status: 'pending',
  }))
    tenantIds.add(invitation.tenantId);
  for (const status of ['active', 'expired'] as const)
    for (const account of await ctx.store.find<GuestAccount>(guestCollections.accounts, {
      ...filter,
      status,
    }))
      tenantIds.add(account.tenantId);
  for (const settings of await ctx.store.find<CrossTenantAccess>(guestCollections.settings, filter))
    tenantIds.add(settings.tenantId);
  for (const tenantId of [...tenantIds].sort()) {
    // Counted once the tenant's transaction committed.
    const swept = await ctx.store.transaction((tx) => sweepTenant(ctx, tx, tenantId));
    for (const key of Object.keys(result) as Array<keyof GuestSweepResult>)
      result[key] += swept[key];
  }
  return result;
}

/** The guest scheduler jobs on the instance (`iam.guests`). */
export function createGuestsRuntime(ctx: ServerContext): IamGuests {
  return {
    sendReviewReminders: (input = {}) => sendReviewReminders(ctx, input),
    sweep: (input = {}) => sweepGuests(ctx, input),
  };
}
