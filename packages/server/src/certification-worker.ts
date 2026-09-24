import type { AuthenticatedPrincipal, IamStore, Identity } from '@better-iam/core';
import {
  applyCampaign,
  type CertificationCampaign,
  type CertificationOutcome,
} from './api/certifications.js';
import type { ServerContext } from './context.js';
import { id } from './utils.js';
import { text } from './validation.js';

export interface CertificationAutoCloseResult {
  /** Campaigns closed in this run, with how their items ended. */
  closed: Array<{
    tenantId: string;
    campaignId: string;
    outcomes: Record<CertificationOutcome, number>;
  }>;
  /** Open auto-closing campaigns that are not due yet. */
  skipped: number;
}

/** Deployment worker for access certifications. Not an HTTP endpoint. */
export function createCertificationWorker(ctx: ServerContext) {
  const { store } = ctx;
  /**
   * The creator as the principal revocations run under, only while they could still close the campaign themselves:
   * active, not expired, and allowed iam:certifications:manage on it. Offboarding (disabling, expiry, losing the
   * permission) ends their authority here too, as deletion does.
   */
  async function actingCreator(
    tx: IamStore,
    campaign: CertificationCampaign,
    creator: Identity,
  ): Promise<AuthenticatedPrincipal | undefined> {
    if (creator.status !== 'active' || ctx.identityExpired(creator)) return undefined;
    const principal = ctx.decisions.simulatedPrincipal(creator);
    const decision = await ctx.decisions.decide(
      tx,
      principal,
      {
        tenantId: campaign.tenantId,
        action: 'iam:certifications:manage',
        resource: { type: 'iam', id: `certifications/${campaign.id}` },
      },
      true,
    );
    return decision.allowed ? principal : undefined;
  }
  return {
    /**
     * Closes every open `autoClose` campaign whose `dueAt` has passed (or only those of `tenantId`), each in its own
     * transaction. Revocations run under the campaign creator's grant authority; when the creator no longer exists,
     * is disabled or expired, or no longer holds iam:certifications:manage on the campaign, the campaign still closes
     * and every revocation is reported as `revocation-failed`. Audited as
     * `certification:auto-close` (with the outcome counts) plus one `iam:bindings:delete` per removed binding, both
     * by `deployment-operator`. A deployment operation for schedulers: no credential.
     */
    async closeOverdueCertifications(
      input: { tenantId?: string } = {},
    ): Promise<CertificationAutoCloseResult> {
      const tenantId =
        input.tenantId === undefined
          ? undefined
          : (await ctx.tenant(store, text(input.tenantId, 'tenantId'))).id;
      const candidates = (
        await store.find<CertificationCampaign>('certificationCampaigns', {
          status: 'open',
          autoClose: true,
          ...(tenantId ? { tenantId } : {}),
        })
      ).sort((a, b) => (a.dueAt ?? 0) - (b.dueAt ?? 0) || (a.id < b.id ? -1 : 1));
      const closed: CertificationAutoCloseResult['closed'] = [];
      let skipped = 0;
      for (const candidate of candidates) {
        if (candidate.dueAt === undefined || candidate.dueAt > ctx.now()) {
          skipped++;
          continue;
        }
        const result = await store.transaction(async (tx) => {
          const campaign = await tx.get<CertificationCampaign>(
            'certificationCampaigns',
            candidate.id,
          );
          // An administrator may have closed or deleted it since the scan.
          if (campaign?.status !== 'open') return undefined;
          const creator = await tx.get<Identity>('identities', campaign.createdBy);
          const principal = creator && (await actingCreator(tx, campaign, creator));
          const { outcomes } = await applyCampaign(ctx, tx, campaign, principal, {
            operator: 'deployment-operator',
          });
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: campaign.tenantId,
            actorId: 'deployment-operator',
            action: 'certification:auto-close',
            resourceId: campaign.id,
            timestamp: ctx.now(),
            outcome: 'allow',
            metadata: outcomes,
          });
          return { tenantId: campaign.tenantId, campaignId: campaign.id, outcomes };
        });
        if (result) closed.push(result);
      }
      return { closed, skipped };
    },
  };
}
