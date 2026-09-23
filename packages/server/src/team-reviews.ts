import {
  type AuthenticatedPrincipal,
  type IamStore,
  type Json,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { afterIdentityChange } from './api/package-automation.js';
import type { ServerContext } from './context.js';
import {
  liveTeamMember,
  syncTeamGroups,
  teamCollections,
  type Team,
  type TeamMember,
  type TeamRole,
} from './teams.js';
import { id } from './utils.js';

/**
 * Team membership reviews: an administrator opens a review of a team's manual members, the team's maintainers (or
 * those of a team above it, or administrators) decide `keep` or `remove` for each person, and completing the review
 * removes everyone decided `remove` and, by the review's `onUndecided` rule, those nobody decided on. Members team sync
 * manages are not reviewed (their source group is). A review past its `dueAt` is completed by the scheduler job
 * `closeOverdueTeamReviews`.
 */
export const teamReviewCollections = { reviews: 'teamReviews', items: 'teamReviewItems' } as const;

export type TeamReviewStatus = 'open' | 'completed' | 'cancelled';
export type TeamReviewDecision = 'keep' | 'remove';

export interface TeamReviewOutcome {
  kept: number;
  removed: number;
  /** People nobody decided on (they followed `onUndecided`). */
  undecided: number;
  /** People who had already left the team when the review completed. */
  gone: number;
}
/** A review of one team's membership; at most one is open per team (uniqueKey `open:{teamId}` while open). */
export interface TeamReview extends StoredRecord {
  teamId: string;
  status: TeamReviewStatus;
  /** What happens to people nobody decided on when the review completes. */
  onUndecided: TeamReviewDecision;
  startedAt: number;
  startedBy: string;
  dueAt: number;
  note?: string;
  completedAt?: number;
  /** The person who completed or cancelled it, or `deployment-operator` for the scheduler job. */
  completedBy?: string;
  outcome?: TeamReviewOutcome;
}
/** One person under review (uniqueKey `{reviewId}:{identityId}`). */
export interface TeamReviewItem extends StoredRecord {
  reviewId: string;
  teamId: string;
  identityId: string;
  role: TeamRole;
  decision?: TeamReviewDecision;
  decidedBy?: string;
  decidedAt?: number;
  note?: string;
}

/** Shortest and longest time a review stays open. */
export const minReviewMs = 86_400_000;
export const maxReviewMs = 90 * 86_400_000;
export const defaultReviewMs = 14 * 86_400_000;

export interface TeamReviewCompletion {
  review: TeamReview;
  /** People removed from the team, for re-evaluating their birthright packages after commit. */
  removed: string[];
}

/**
 * Completes an open review inside the caller's transaction: removes the people decided (or defaulted to) `remove` who
 * are still manual members, updates the backing groups, and audits every removal and the completion. `principal` is
 * the person completing it; without one the scheduler (`deployment-operator`) is the actor.
 */
export async function completeTeamReview(
  ctx: ServerContext,
  tx: IamStore,
  review: TeamReview,
  principal: AuthenticatedPrincipal | undefined,
): Promise<TeamReviewCompletion> {
  const now = ctx.now();
  const record = async (action: string, metadata: Record<string, Json>) => {
    if (principal)
      await ctx.events.audit(
        tx,
        principal,
        action,
        review.tenantId,
        review.teamId,
        'allow',
        false,
        metadata,
      );
    else
      await ctx.events.recordAudit(tx, {
        id: id(),
        tenantId: review.tenantId,
        actorId: 'deployment-operator',
        action,
        resourceId: review.teamId,
        timestamp: now,
        outcome: 'allow',
        metadata,
      });
  };
  const outcome: TeamReviewOutcome = { kept: 0, removed: 0, undecided: 0, gone: 0 };
  const removed: string[] = [];
  for (const item of await tx.find<TeamReviewItem>(teamReviewCollections.items, {
    tenantId: review.tenantId,
    reviewId: review.id,
  })) {
    if (item.decision === undefined) outcome.undecided++;
    const member = (
      await tx.find<TeamMember>(teamCollections.members, {
        tenantId: review.tenantId,
        uniqueKey: `${review.teamId}:${item.identityId}`,
      })
    )[0];
    // Someone who left, or whom team sync now manages, is outside the review.
    if (!member || !liveTeamMember(member, now) || member.source === 'sync') {
      outcome.gone++;
      continue;
    }
    if ((item.decision ?? review.onUndecided) === 'keep') {
      outcome.kept++;
      continue;
    }
    await tx.delete(teamCollections.members, member.id);
    removed.push(member.identityId);
    outcome.removed++;
    await record('team:member:remove', {
      identityId: member.identityId,
      role: member.role,
      source: 'review',
      reviewId: review.id,
      ...(item.decision === undefined ? { undecided: true } : {}),
    });
  }
  if (removed.length) await syncTeamGroups(tx, review.tenantId, [review.teamId], now);
  const { uniqueKey: _open, ...rest } = review;
  const completed = await tx.put<TeamReview>(teamReviewCollections.reviews, {
    ...rest,
    status: 'completed',
    completedAt: now,
    completedBy: principal?.identity.id ?? 'deployment-operator',
    outcome,
  });
  await record('team:review:complete', { reviewId: review.id, ...outcome });
  return { review: completed, removed };
}

/**
 * The scheduler job: completes every open team review past its due date (in active organizations), each in its own
 * transaction, then re-evaluates the birthright packages of the people it removed.
 */
export async function closeOverdueTeamReviews(
  ctx: ServerContext,
  input: { tenantId?: string } = {},
): Promise<{
  completed: number;
  removed: number;
  failed: Array<{ reviewId: string; message: string }>;
}> {
  const now = ctx.now();
  const due = (
    await ctx.store.find<TeamReview>(teamReviewCollections.reviews, {
      status: 'open',
      ...(input.tenantId ? { tenantId: input.tenantId } : {}),
    })
  ).filter((review) => review.dueAt <= now);
  const result = {
    completed: 0,
    removed: 0,
    failed: [] as Array<{ reviewId: string; message: string }>,
  };
  for (const candidate of due) {
    try {
      const done = await ctx.store.transaction(async (tx) => {
        const review = await tx.get<TeamReview>(teamReviewCollections.reviews, candidate.id);
        if (!review || review.status !== 'open' || review.dueAt > ctx.now()) return undefined;
        const tenant = await tx.get<Tenant>('tenants', review.tenantId);
        if (!tenant || tenant.status !== 'active') return undefined;
        if (!(await tx.get<Team>(teamCollections.teams, review.teamId))) return undefined;
        return completeTeamReview(ctx, tx, review, undefined);
      });
      if (!done) continue;
      result.completed++;
      result.removed += done.removed.length;
      await afterIdentityChange(ctx, candidate.tenantId, done.removed, undefined);
    } catch (error) {
      result.failed.push({
        reviewId: candidate.id,
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return result;
}
