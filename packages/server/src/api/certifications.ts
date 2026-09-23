import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type Identity,
  type IamStore,
  type StoredRecord,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { Binding, Group, GroupMember, Role } from '../models.js';
import { actsInOwnRight } from '../session-kinds.js';
import { byNewest, id } from '../utils.js';
import { strings, text } from '../validation.js';
import { deleteBinding } from './bindings.js';

export type CertificationDecision = 'keep' | 'revoke';
export type CertificationOutcome = 'kept' | 'revoked' | 'already-removed' | 'revocation-failed';

/** A periodic review of who holds which role: reviewers keep or revoke each binding, and closing applies it. */
export interface CertificationCampaign extends StoredRecord {
  name: string;
  status: 'open' | 'closed';
  createdBy: string;
  createdAt: number;
  dueAt?: number;
  /** Only bindings of these roles are reviewed; unset reviews every non-protected role. */
  roleIds?: string[];
  subjectType?: 'identity' | 'group';
  /** Identities allowed to decide; empty lets anyone holding `iam:certifications:review` decide. */
  reviewerIds: string[];
  /**
   * `manager` assigns each person's items to their manager (`CertificationItem.reviewerId`); items without one fall
   * back to `reviewerIds`. Absent on campaigns created before reviewer modes, which are `named`.
   */
  reviewerMode?: 'named' | 'manager';
  /** The deployment worker (`closeOverdueCertifications`) closes the campaign once `dueAt` has passed. */
  autoClose?: boolean;
  /** What closing does with items nobody decided. */
  undecided: CertificationDecision;
  closedAt?: number;
  /** Who closed the campaign; `deployment-operator` when the worker closed it. */
  closedBy?: string;
}
/** One binding as it stood when the campaign opened, with the reviewer's decision and the closing outcome. */
export interface CertificationItem extends StoredRecord {
  campaignId: string;
  bindingId: string;
  roleId: string;
  roleName: string;
  subjectType: 'identity' | 'group';
  subjectId: string;
  subjectName: string;
  bindingExpiresAt?: number;
  eligible?: boolean;
  /** Manager-mode campaigns: the person's manager, who reviews this item (administrators may still decide it). */
  reviewerId?: string;
  decision?: CertificationDecision;
  decidedBy?: string;
  decidedAt?: number;
  note?: string;
  outcome?: CertificationOutcome;
  outcomeDetail?: string;
}
export interface CertificationProgress {
  total: number;
  decided: number;
  keep: number;
  revoke: number;
}
/** One reviewer decision, as `decide` and `review` accept it. */
export interface CertificationDecisionInput {
  itemId: string;
  decision: CertificationDecision;
  note?: string;
}
/** How `applyCampaign` attributes the close. */
export interface ApplyCampaignOptions {
  /**
   * A deployment actor (such as `deployment-operator`) recorded as `closedBy` and as the actor of each revocation's
   * `iam:bindings:delete` event (with the campaign ID) instead of the principal.
   */
  operator?: string;
}

const maxItems = 5000;
const decisions = new Set<CertificationDecision>(['keep', 'revoke']);

function progress(items: CertificationItem[]): CertificationProgress {
  return {
    total: items.length,
    decided: items.filter((item) => item.decision).length,
    keep: items.filter((item) => item.decision === 'keep').length,
    revoke: items.filter((item) => item.decision === 'revoke').length,
  };
}

const byRoleAndSubject = (a: CertificationItem, b: CertificationItem) =>
  a.roleName.localeCompare(b.roleName) ||
  a.subjectName.localeCompare(b.subjectName) ||
  a.id.localeCompare(b.id);

/** The groups an identity belongs to, for the rule that nobody certifies their own access. */
async function groupsOf(tx: IamStore, tenantId: string, identityId: string): Promise<Set<string>> {
  return new Set(
    (await tx.find<GroupMember>('groupMembers', { tenantId, identityId })).map(
      (member) => member.groupId,
    ),
  );
}

/** Whether an item certifies the identity's own access, directly or through one of its groups. */
const ownItem = (item: CertificationItem, identityId: string, groups: Set<string>) =>
  item.subjectType === 'identity' ? item.subjectId === identityId : groups.has(item.subjectId);

const selfReview = () =>
  new IamError(
    'SELF_REVIEW',
    'Reviewers cannot certify their own access; ask another reviewer',
    403,
  );

/** The item with a reviewer's decision (and optional note) recorded. */
function decided(
  item: CertificationItem,
  entry: CertificationDecisionInput,
  reviewerId: string,
  now: number,
): CertificationItem {
  const updated: CertificationItem = {
    ...item,
    decision: entry.decision,
    decidedBy: reviewerId,
    decidedAt: now,
  };
  if (entry.note !== undefined) updated.note = text(entry.note, 'note', 500).trim();
  else delete updated.note;
  return updated;
}

/**
 * Items per reviewer: manager-assigned items count for their manager, the others for every named reviewer. Named
 * reviewers of a manager-mode campaign are left out when nothing falls back to them.
 */
function reviewLoad(campaign: CertificationCampaign, items: CertificationItem[]) {
  const load = new Map<string, number>();
  let unassigned = 0;
  for (const item of items)
    if (item.reviewerId) load.set(item.reviewerId, (load.get(item.reviewerId) ?? 0) + 1);
    else unassigned++;
  if (unassigned || campaign.reviewerMode !== 'manager')
    for (const reviewerId of campaign.reviewerIds)
      load.set(reviewerId, (load.get(reviewerId) ?? 0) + unassigned);
  return load;
}

/**
 * Rejects credentials that are not an ordinary session of the tenant (self-service reviews act as oneself), including
 * role sessions, session tokens and unknown kinds.
 */
function requireTenantSession(principal: AuthenticatedPrincipal, tenantId: string): void {
  if (!actsInOwnRight(principal.session) || principal.session.tenantId !== tenantId)
    throw new IamError(
      'ACCESS_DENIED',
      'Reviews are made from an ordinary session of the campaign tenant',
      403,
    );
}

/**
 * Applies an open campaign and closes it inside the caller's transaction: revoked (and, with `undecided: 'revoke'`,
 * undecided) bindings are removed under the principal's grant authority, and each item records its outcome.
 * Bindings the principal may not remove are reported as `revocation-failed`; without a principal (the creator of an
 * auto-closing campaign no longer exists) every revocation is.
 */
export async function applyCampaign(
  ctx: ServerContext,
  tx: IamStore,
  campaign: CertificationCampaign,
  principal: AuthenticatedPrincipal | undefined,
  options: ApplyCampaignOptions = {},
): Promise<CertificationCampaign & { outcomes: Record<CertificationOutcome, number> }> {
  const closedBy = options.operator ?? principal?.identity.id;
  if (closedBy === undefined)
    throw new IamError('INVALID_INPUT', 'Closing a campaign needs a principal or an operator');
  const tenantId = campaign.tenantId;
  const outcomes: Record<CertificationOutcome, number> = {
    kept: 0,
    revoked: 0,
    'already-removed': 0,
    'revocation-failed': 0,
  };
  for (const item of await tx.find<CertificationItem>('certificationItems', {
    tenantId,
    campaignId: campaign.id,
  })) {
    const decision = item.decision ?? campaign.undecided;
    const binding = await tx.get<Binding>('bindings', item.bindingId);
    let outcome: CertificationOutcome;
    let detail: string | undefined;
    if (
      !binding ||
      binding.tenantId !== tenantId ||
      binding.roleId !== item.roleId ||
      binding.subjectId !== item.subjectId
    )
      outcome = decision === 'revoke' ? 'already-removed' : 'kept';
    else if (decision === 'keep') outcome = 'kept';
    else if (!principal) {
      outcome = 'revocation-failed';
      detail = 'The campaign creator no longer exists, so nothing is revoked under their authority';
    } else
      try {
        // deleteBinding validates before it writes, so a refusal leaves nothing half-done.
        await deleteBinding(ctx, tx, principal, binding);
        if (options.operator !== undefined)
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId,
            actorId: options.operator,
            action: 'iam:bindings:delete',
            resourceId: binding.id,
            timestamp: ctx.now(),
            outcome: 'allow',
            metadata: { campaignId: campaign.id },
          });
        else
          await ctx.events.audit(
            tx,
            principal,
            'iam:bindings:delete',
            tenantId,
            binding.id,
            'allow',
          );
        outcome = 'revoked';
      } catch (error) {
        if (!(error instanceof IamError)) throw error;
        outcome = 'revocation-failed';
        detail = error.message;
      }
    outcomes[outcome]++;
    await tx.put<CertificationItem>('certificationItems', {
      ...item,
      outcome,
      ...(detail ? { outcomeDetail: detail } : {}),
    });
  }
  const closed = await tx.put<CertificationCampaign>('certificationCampaigns', {
    ...campaign,
    status: 'closed',
    closedAt: ctx.now(),
    closedBy,
  });
  return { ...closed, outcomes };
}

/**
 * Access certification campaigns. An administrator snapshots the tenant's role bindings (optionally for some roles or
 * subject types); designated reviewers — or, in manager mode, each person's manager — keep or revoke each one, never
 * their own access, and closing the campaign removes the revoked bindings under the closer's grant authority.
 * Bindings the closer may not remove are reported as `revocation-failed` for a higher administrator instead of being
 * forced.
 */
export function createCertificationsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const { auth, store } = ctx;
  async function campaignOf(tx: IamStore, tenantId: string, campaignId: string) {
    return ctx.scoped<CertificationCampaign>(
      tx,
      'certificationCampaigns',
      text(campaignId, 'campaignId'),
      tenantId,
    );
  }
  const itemsOf = (tx: IamStore, tenantId: string, campaignId: string) =>
    tx.find<CertificationItem>('certificationItems', { tenantId, campaignId });

  return {
    /**
     * Opens a campaign over the current bindings. `reviewerMode: 'manager'` assigns each person's items to their
     * active manager, the rest to the named reviewers; `autoClose` (which needs `dueAt`) lets the deployment worker
     * close it when due. When email delivery is configured, each reviewer is emailed (`certification-review`) with
     * their item count. Requires iam:certifications:manage.
     */
    create: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        roleIds?: string[];
        subjectType?: 'identity' | 'group';
        reviewerIds?: string[];
        reviewerMode?: 'named' | 'manager';
        dueAt?: number;
        autoClose?: boolean;
        undecided?: CertificationDecision;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:certifications:manage',
        'certifications/*',
        async ({ tx, principal }) => {
          const tenantId = input.tenantId;
          const name = text(input.name, 'name', 200).trim();
          if (input.subjectType !== undefined && !['identity', 'group'].includes(input.subjectType))
            throw new IamError('INVALID_INPUT', 'subjectType must be identity or group');
          const reviewerMode = input.reviewerMode ?? 'named';
          if (!['named', 'manager'].includes(reviewerMode))
            throw new IamError('INVALID_INPUT', 'reviewerMode must be named or manager');
          const undecided = input.undecided ?? 'keep';
          if (!decisions.has(undecided))
            throw new IamError('INVALID_INPUT', 'undecided must be keep or revoke');
          const now = ctx.now();
          if (
            input.dueAt !== undefined &&
            (!Number.isSafeInteger(input.dueAt) || input.dueAt <= now)
          )
            throw new IamError('INVALID_INPUT', 'dueAt must be a future timestamp in milliseconds');
          if (input.autoClose !== undefined && typeof input.autoClose !== 'boolean')
            throw new IamError('INVALID_INPUT', 'autoClose must be boolean');
          if (input.autoClose && input.dueAt === undefined)
            throw new IamError('INVALID_INPUT', 'autoClose requires dueAt');
          const roleIds =
            input.roleIds === undefined
              ? undefined
              : [...new Set(strings(input.roleIds, 'roleIds'))];
          const roles = new Map<string, Role>();
          for (const role of await tx.find<Role>('roles', { tenantId })) roles.set(role.id, role);
          for (const roleId of roleIds ?? [])
            if (!roles.has(roleId) || roles.get(roleId)!.protected)
              throw new IamError('INVALID_INPUT', `Role ${roleId} cannot be certified`);
          const reviewerIds = [...new Set(strings(input.reviewerIds ?? [], 'reviewerIds'))];
          for (const reviewerId of reviewerIds) await ctx.activeIdentity(tx, reviewerId, tenantId);

          const bindings = (await tx.find<Binding>('bindings', { tenantId })).filter(
            (binding) =>
              ctx.liveBinding(binding) &&
              roles.has(binding.roleId) &&
              !roles.get(binding.roleId)!.protected &&
              (!roleIds || roleIds.includes(binding.roleId)) &&
              (!input.subjectType || binding.subjectType === input.subjectType),
          );
          if (bindings.length > maxItems)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A campaign covers at most ${maxItems} bindings; narrow it by role or subject type`,
              409,
            );
          const campaign: CertificationCampaign = {
            id: id(),
            tenantId,
            name,
            status: 'open',
            createdBy: principal.identity.id,
            createdAt: now,
            reviewerIds,
            reviewerMode,
            undecided,
          };
          if (input.dueAt !== undefined) campaign.dueAt = input.dueAt;
          if (input.autoClose) campaign.autoClose = true;
          if (roleIds) campaign.roleIds = roleIds;
          if (input.subjectType) campaign.subjectType = input.subjectType;
          await tx.insert('certificationCampaigns', campaign);
          // Manager mode: a person's reviewer is their manager while that manager is an active member of the tenant.
          const managers = new Map<string, boolean>();
          const reviewerFor = async (subject: Identity | undefined) => {
            if (
              reviewerMode !== 'manager' ||
              !subject?.managerId ||
              subject.managerId === subject.id
            )
              return undefined;
            const managerId = subject.managerId;
            if (!managers.has(managerId)) {
              const manager = await tx.get<Identity>('identities', managerId);
              managers.set(
                managerId,
                manager?.tenantId === tenantId &&
                  manager.status === 'active' &&
                  !ctx.identityExpired(manager),
              );
            }
            return managers.get(managerId) ? managerId : undefined;
          };
          const items: CertificationItem[] = [];
          for (const binding of bindings) {
            const subject =
              binding.subjectType === 'identity'
                ? await tx.get<Identity>('identities', binding.subjectId)
                : await tx.get<Group>('groups', binding.subjectId);
            const item: CertificationItem = {
              id: id(),
              tenantId,
              campaignId: campaign.id,
              bindingId: binding.id,
              roleId: binding.roleId,
              roleName: roles.get(binding.roleId)!.name,
              subjectType: binding.subjectType,
              subjectId: binding.subjectId,
              subjectName:
                (subject as Identity | undefined)?.email ??
                (subject as Group | Identity | undefined)?.name ??
                binding.subjectId,
            };
            if (binding.expiresAt !== undefined) item.bindingExpiresAt = binding.expiresAt;
            if (binding.eligible) item.eligible = true;
            const reviewerId =
              binding.subjectType === 'identity'
                ? await reviewerFor(subject as Identity | undefined)
                : undefined;
            if (reviewerId) item.reviewerId = reviewerId;
            await tx.insert('certificationItems', item);
            items.push(item);
          }
          // Reviewers hear about the campaign through the outbox, in the same transaction.
          if (ctx.options.authentication?.sendEmail)
            for (const [reviewerId, count] of reviewLoad(campaign, items)) {
              const reviewer = await tx.get<Identity>('identities', reviewerId);
              if (!reviewer?.email) continue;
              await auth.enqueueDelivery(tx, {
                tenantId,
                kind: 'email',
                to: reviewer.email,
                template: 'certification-review',
                payload: {
                  campaignId: campaign.id,
                  campaignName: name,
                  items: String(count),
                  ...(campaign.dueAt ? { dueAt: new Date(campaign.dueAt).toISOString() } : {}),
                },
              });
            }
          return { ...campaign, progress: progress([]), items: bindings.length };
        },
      ),
    /** Campaigns with their progress, newest first. Requires iam:certifications:read. */
    list: (credential: CredentialInput, input: { tenantId: string; status?: 'open' | 'closed' }) =>
      operation(
        credential,
        input.tenantId,
        'iam:certifications:read',
        'certifications/*',
        async ({ tx }) => {
          const campaigns = (
            await tx.find<CertificationCampaign>('certificationCampaigns', {
              tenantId: input.tenantId,
              ...(input.status ? { status: input.status } : {}),
            })
          ).sort(byNewest);
          const result = [];
          for (const campaign of campaigns)
            result.push({
              ...campaign,
              progress: progress(await itemsOf(tx, input.tenantId, campaign.id)),
            });
          return result;
        },
      ),
    /** One campaign and its items; `mine` limits items to those the caller may decide. */
    get: async (
      credential: CredentialInput,
      input: { tenantId: string; campaignId: string; mine?: boolean },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:certifications:read',
        `certifications/${text(input.campaignId, 'campaignId')}`,
        async ({ tx, principal }) => {
          const campaign = await campaignOf(tx, input.tenantId, input.campaignId);
          const items = await itemsOf(tx, input.tenantId, campaign.id);
          const memberOf = await groupsOf(tx, input.tenantId, principal.identity.id);
          return {
            ...campaign,
            progress: progress(items),
            items: items
              .filter((item) => !input.mine || !ownItem(item, principal.identity.id, memberOf))
              .sort(byRoleAndSubject),
          };
        },
      ),
    /**
     * Records keep/revoke decisions (at most 200 per call). Reviewers must be listed on the campaign when it names
     * reviewers, and nobody decides on their own access, directly or through a group. In manager mode an item
     * assigned to a manager is theirs to decide, though holders of iam:certifications:manage may decide it too.
     * Requires iam:certifications:review on the campaign. A role session holding it may decide (the decision records
     * its source identity); a session token (a derived copy of the reviewer's own credential) and an impersonation
     * session never do.
     */
    decide: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        campaignId: string;
        decisions: CertificationDecisionInput[];
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:certifications:review',
        `certifications/${text(input.campaignId, 'campaignId')}`,
        async ({ tx, principal }) => {
          // A decision is recorded in the reviewer's name. An administrator impersonating a member never records
          // one for them, and neither does a session token or any other derived kind but an assumed role, which is
          // an explicit, audited delegation that has always been able to review with the permission.
          if (principal.session.impersonatorId)
            throw new IamError(
              'IMPERSONATION_RESTRICTED',
              'Access cannot be reviewed while impersonating',
              403,
            );
          if (!actsInOwnRight(principal.session) && principal.session.kind !== 'role')
            throw new IamError(
              'ACCESS_DENIED',
              'Reviews are made from an ordinary session of the campaign tenant',
              403,
            );
          const campaign = await campaignOf(tx, input.tenantId, input.campaignId);
          if (campaign.status !== 'open')
            throw new IamError('CONFLICT', 'The campaign is closed', 409);
          const named =
            !campaign.reviewerIds.length || campaign.reviewerIds.includes(principal.identity.id);
          if (!named && campaign.reviewerMode !== 'manager')
            throw new IamError('ACCESS_DENIED', 'You are not a reviewer of this campaign', 403);
          if (
            !Array.isArray(input.decisions) ||
            !input.decisions.length ||
            input.decisions.length > 200
          )
            throw new IamError('INVALID_INPUT', 'decisions must contain 1 to 200 entries');
          const memberOf = await groupsOf(tx, input.tenantId, principal.identity.id);
          let manages: boolean | undefined;
          const mayManage = async () =>
            (manages ??= (
              await ctx.decisions.decide(
                tx,
                principal,
                {
                  tenantId: input.tenantId,
                  action: 'iam:certifications:manage',
                  resource: { type: 'iam', id: `certifications/${campaign.id}` },
                },
                true,
              )
            ).allowed);
          const now = ctx.now();
          let recorded = 0;
          for (const entry of input.decisions) {
            const item = await ctx.scoped<CertificationItem>(
              tx,
              'certificationItems',
              text(entry.itemId, 'itemId'),
              input.tenantId,
            );
            if (item.campaignId !== campaign.id)
              throw new IamError('NOT_FOUND', 'Item not found', 404);
            if (!decisions.has(entry.decision))
              throw new IamError('INVALID_INPUT', 'decision must be keep or revoke');
            if (ownItem(item, principal.identity.id, memberOf)) throw selfReview();
            if (item.reviewerId !== undefined) {
              if (item.reviewerId !== principal.identity.id && !(await mayManage()))
                throw new IamError(
                  'ACCESS_DENIED',
                  "This item is assigned to the person's manager",
                  403,
                );
            } else if (!named)
              throw new IamError('ACCESS_DENIED', 'You are not a reviewer of this campaign', 403);
            await tx.put('certificationItems', decided(item, entry, principal.identity.id, now));
            recorded++;
          }
          return { recorded };
        },
      ),
    /**
     * Self-service for manager-mode reviewers: records keep/revoke decisions (at most 200 per call) on items assigned
     * to the caller, without needing iam:certifications:review. Requires an ordinary, non-impersonated session of the
     * tenant; nobody decides on their own access. Audited as `certification:review`.
     */
    review: async (
      credential: CredentialInput,
      input: { tenantId: string; campaignId: string; decisions: CertificationDecisionInput[] },
    ): Promise<{ recorded: number }> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const campaignId = text(input.campaignId, 'campaignId');
      if (
        !Array.isArray(input.decisions) ||
        !input.decisions.length ||
        input.decisions.length > 200
      )
        throw new IamError('INVALID_INPUT', 'decisions must contain 1 to 200 entries');
      const entries = input.decisions.map((entry) => {
        if (!entry || typeof entry !== 'object' || !decisions.has(entry.decision))
          throw new IamError('INVALID_INPUT', 'decision must be keep or revoke');
        return { ...entry, itemId: text(entry.itemId, 'itemId') };
      });
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        requireTenantSession(principal, tenantId);
        if (principal.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'Access cannot be reviewed while impersonating',
            403,
          );
        const campaign = await campaignOf(tx, tenantId, campaignId);
        if (campaign.status !== 'open')
          throw new IamError('CONFLICT', 'The campaign is closed', 409);
        const memberOf = await groupsOf(tx, tenantId, principal.identity.id);
        const now = ctx.now();
        const counts = { keep: 0, revoke: 0 };
        for (const entry of entries) {
          const item = await tx.get<CertificationItem>('certificationItems', entry.itemId);
          if (
            !item ||
            item.tenantId !== tenantId ||
            item.campaignId !== campaign.id ||
            item.reviewerId !== principal.identity.id
          )
            throw new IamError('ACCESS_DENIED', 'This item is not assigned to you', 403);
          if (ownItem(item, principal.identity.id, memberOf)) throw selfReview();
          await tx.put('certificationItems', decided(item, entry, principal.identity.id, now));
          counts[entry.decision]++;
        }
        await ctx.events.audit(
          tx,
          principal,
          'certification:review',
          tenantId,
          campaign.id,
          'allow',
          false,
          { recorded: entries.length, ...counts },
        );
        return { recorded: entries.length };
      });
    },
    /**
     * The caller's review work: open campaigns with items assigned to them (manager mode), newest first, each with
     * only those items and their progress. Needs no permission beyond an ordinary session of the tenant.
     */
    listMine: async (credential: CredentialInput, input: { tenantId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        requireTenantSession(principal, tenantId);
        const result: Array<{
          id: string;
          name: string;
          dueAt?: number;
          reviewerMode: 'named' | 'manager';
          items: CertificationItem[];
          progress: CertificationProgress;
        }> = [];
        for (const campaign of (
          await tx.find<CertificationCampaign>('certificationCampaigns', {
            tenantId,
            status: 'open',
          })
        ).sort(byNewest)) {
          const mine = await tx.find<CertificationItem>('certificationItems', {
            tenantId,
            campaignId: campaign.id,
            reviewerId: principal.identity.id,
          });
          if (!mine.length) continue;
          result.push({
            id: campaign.id,
            name: campaign.name,
            ...(campaign.dueAt !== undefined ? { dueAt: campaign.dueAt } : {}),
            reviewerMode: campaign.reviewerMode ?? 'named',
            items: mine.sort(byRoleAndSubject),
            progress: progress(mine),
          });
        }
        return result;
      });
    },
    /**
     * Emails a `certification-reminder` to every reviewer with undecided items: managers their assigned count, and the
     * named reviewers the undecided items that fall back to them (nobody, when the campaign names no reviewers).
     * Returns how many people were reminded and how many items are undecided. Requires iam:certifications:manage
     * and an email delivery callback. Audited as `certification:remind`.
     */
    remind: async (credential: CredentialInput, input: { tenantId: string; campaignId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:certifications:manage',
        `certifications/${text(input.campaignId, 'campaignId')}`,
        async ({ tx, principal }) => {
          if (!ctx.options.authentication?.sendEmail)
            throw new IamError('DELIVERY_REQUIRED', 'Reminders require an email delivery callback');
          const campaign = await campaignOf(tx, input.tenantId, input.campaignId);
          if (campaign.status !== 'open')
            throw new IamError('CONFLICT', 'The campaign is closed', 409);
          const undecided = (await itemsOf(tx, input.tenantId, campaign.id)).filter(
            (item) => !item.decision,
          );
          let reminded = 0;
          for (const [reviewerId, pending] of reviewLoad(campaign, undecided)) {
            if (!pending) continue;
            const reviewer = await tx.get<Identity>('identities', reviewerId);
            if (reviewer?.status !== 'active' || !reviewer.email) continue;
            await auth.enqueueDelivery(tx, {
              tenantId: input.tenantId,
              kind: 'email',
              to: reviewer.email,
              template: 'certification-reminder',
              payload: {
                campaignId: campaign.id,
                campaignName: campaign.name,
                pending: String(pending),
                ...(campaign.dueAt ? { dueAt: new Date(campaign.dueAt).toISOString() } : {}),
              },
            });
            reminded++;
          }
          await ctx.events.audit(
            tx,
            principal,
            'certification:remind',
            input.tenantId,
            campaign.id,
            'allow',
            false,
            { reminded, pending: undecided.length },
          );
          return { reminded, pending: undecided.length };
        },
      ),
    /**
     * Closes the campaign and applies it: revoked (and, with `undecided: 'revoke'`, undecided) bindings are removed
     * under the caller's grant authority; each item records its outcome. Requires iam:certifications:manage and
     * recent authentication.
     */
    close: async (credential: CredentialInput, input: { tenantId: string; campaignId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:certifications:manage',
        `certifications/${text(input.campaignId, 'campaignId')}`,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const campaign = await campaignOf(tx, input.tenantId, input.campaignId);
          if (campaign.status !== 'open')
            throw new IamError('CONFLICT', 'The campaign is already closed', 409);
          return applyCampaign(ctx, tx, campaign, principal);
        },
      ),
    /** Deletes a closed campaign and its items. Requires iam:certifications:manage. */
    delete: async (credential: CredentialInput, input: { tenantId: string; campaignId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:certifications:manage',
        `certifications/${text(input.campaignId, 'campaignId')}`,
        async ({ tx }) => {
          const campaign = await campaignOf(tx, input.tenantId, input.campaignId);
          if (campaign.status !== 'closed')
            throw new IamError('CONFLICT', 'Close the campaign before deleting it', 409);
          for (const item of await itemsOf(tx, input.tenantId, campaign.id))
            await tx.delete('certificationItems', item.id);
          await tx.delete('certificationCampaigns', campaign.id);
          return { deleted: true };
        },
      ),
  };
}
