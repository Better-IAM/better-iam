import {
  IamError,
  ipMatches,
  isIpRange,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type Json,
  type Session,
  type Tenant,
} from '@better-iam/core';
import type { NetworkBlock } from '@better-iam/auth';
import { assertOwnerControl, revokeInvitationsBy } from './api/identities.js';
import { afterIdentityChange } from './api/package-automation.js';
import type { ServerContext } from './context.js';
import { deleteDelegatedSessions } from './delegations.js';
import { OperationDenied } from './operations.js';
import {
  severityAtLeast,
  threatActor,
  threatCollections,
  type IdentityRisk,
  type ResolvedThreatSettings,
  type ResponseAction,
  type ThreatDetection,
  type ThreatIncident,
  type ThreatResponse,
  type ThreatSeverity,
  type ThreatSubject,
} from './threats.js';
import { id } from './utils.js';
import { integer } from './validation.js';

/**
 * Response actions of the threats module (`threats.ts`): ending an identity's sessions, forgetting its remembered
 * devices, containing it (disabled until `threats.release`), blocking a network, and emailing an incident. The same
 * primitives serve people responding through the API (who act under their own principal and are checked like the
 * identities and security APIs check them) and automatic playbooks (the `threat-detection` actor, which never touches
 * owners or root administrators and is braked by `maxAutomaticContainments`). Every action taken or skipped is kept
 * as a `ThreatResponse` row for the incident timeline; the applied ones are audited under `threat:*` actions.
 */

const minute = 60_000;
const day = 24 * 60 * minute;
/** Bounds of a `block-network` response's length. */
export const blockDurationBounds = { min: minute, max: 30 * day, default: day } as const;

/** Who responds: a person through the API, or the detection engine running a playbook. */
export type ResponseActor = { principal: AuthenticatedPrincipal } | { automatic: true };

/** One response action to take for an incident, a detection, or directly for an identity or network. */
export interface ResponseRequest {
  action: ResponseAction;
  /** What the response is about; identity actions fall back to `identityId`, `block-network` to `network`. */
  subject: ThreatSubject;
  identityId?: string;
  network?: string;
  incidentId?: string;
  detectionId?: string;
  playbookId?: string;
  /** Why, recorded on the response, the audit event, and (for `contain`) the identity's risk record. */
  reason: string;
  /** A person responding (API) or the automatic actor. */
  actor: ResponseActor;
}

/**
 * The per-run containment brake of automatic playbooks: `contained` counts the identities contained so far, and
 * `braked` the containments held back once it reached the tenant's `maxAutomaticContainments`.
 */
export interface PlaybookBrake {
  contained: number;
  braked?: number;
}

const manualPrincipal = (actor: ResponseActor): AuthenticatedPrincipal | undefined =>
  'principal' in actor ? actor.principal : undefined;
const actorIdOf = (actor: ResponseActor): string =>
  'principal' in actor ? actor.principal.identity.id : threatActor;

/**
 * Records an audit event of the threats module: under the responding person (with their session context) or under
 * the `threat-detection` actor, stamped with the service clock. Always `allow`, so SSF receivers and webhooks see it.
 */
export async function threatAudit(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  actor: ResponseActor,
  action: string,
  resourceId: string,
  metadata: Record<string, Json>,
): Promise<void> {
  const principal = manualPrincipal(actor);
  if (principal) {
    await ctx.events.audit(tx, principal, action, tenantId, resourceId, 'allow', false, metadata);
    return;
  }
  const event: AuditEvent = {
    id: id(),
    tenantId,
    actorId: threatActor,
    action,
    resourceId,
    timestamp: ctx.now(),
    outcome: 'allow',
    metadata,
  };
  await ctx.events.recordAudit(tx, event);
}

/** A display name for an identity: its name, else its email. */
const identityName = (identity: Identity): string => identity.name || identity.email || identity.id;

/** Two networks (addresses or CIDR blocks) overlap when either contains the other's first address. */
function overlaps(a: string, b: string): boolean {
  const first = (network: string) => network.split('/')[0]!;
  return ipMatches(first(a), b) || ipMatches(first(b), a);
}
/** The prefix length of a network (an address counts as a full-length block). */
function prefixOf(network: string): number {
  const slash = network.indexOf('/');
  if (slash >= 0) return Number(network.slice(slash + 1));
  return network.includes(':') ? 128 : 32;
}
/** True when `outer` covers every address of `inner`. */
const covers = (outer: string, inner: string): boolean =>
  prefixOf(outer) <= prefixOf(inner) && ipMatches(inner.split('/')[0]!, outer);

/** Refs shared by the response row and the audit metadata. */
function references(request: ResponseRequest): Record<string, string> {
  return {
    ...(request.incidentId !== undefined ? { incidentId: request.incidentId } : {}),
    ...(request.detectionId !== undefined ? { detectionId: request.detectionId } : {}),
    ...(request.playbookId !== undefined ? { playbookId: request.playbookId } : {}),
  };
}

/**
 * Takes one response action and records it: inserts the `ThreatResponse` row (applied or skipped with a reason) and,
 * when applied, the audit event (`threat:revoke-sessions`, `threat:forget-devices`, `threat:contain`,
 * `threat:block-network`, `threat:notify`). Automatic actors skip protected targets (owners and root administrators
 * are never contained automatically) and, with a `brake`, containments beyond the tenant's
 * `maxAutomaticContainments` (skipped `braked`, audited once per brake as `threat:response-braked`), and never block
 * networks on the root tenant. People are refused instead: a root administrator only by root, an owner only by an
 * owner in person or root, the last owner (`LAST_OWNER`), themselves, networks that cover their own address, and
 * blocks on the root tenant unless they are root. Runs inside the caller's transaction; after it commits the caller runs
 * `afterThreatResponses` (package reconciliation of contained identities, network block caches).
 */
export async function applyResponse(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  request: ResponseRequest,
  settings: ResolvedThreatSettings,
  brake?: PlaybookBrake,
): Promise<ThreatResponse> {
  const now = ctx.now();
  const principal = manualPrincipal(request.actor);
  const actorId = actorIdOf(request.actor);
  const reason = request.reason.trim().slice(0, 512) || 'Threat response';
  const refs = references(request);
  const save = (
    subject: ThreatSubject,
    outcome: ThreatResponse['outcome'],
    extra: { reason?: string; details?: Record<string, Json> } = {},
  ) =>
    tx.insert<ThreatResponse>(threatCollections.responses, {
      id: id(),
      tenantId,
      action: request.action.kind,
      subject,
      outcome,
      ...(extra.reason !== undefined ? { reason: extra.reason } : {}),
      ...refs,
      actorId,
      ...(extra.details !== undefined ? { details: extra.details } : {}),
      createdAt: now,
    });
  const skip = (why: string, subject: ThreatSubject = request.subject) =>
    save(subject, 'skipped', { reason: why });

  /** The identity an identity action targets, or why there is none. */
  const target = async (): Promise<Identity | string> => {
    const identityId =
      request.subject.type === 'identity' ? request.subject.id : request.identityId;
    if (!identityId) return 'not-identity';
    if (principal) return ctx.activeIdentity(tx, identityId, tenantId);
    const identity = await tx.get<Identity>('identities', identityId);
    if (!identity || identity.tenantId !== tenantId || identity.status === 'deleted')
      return 'not-found';
    return identity;
  };
  const identitySubject = (identity: Identity): ThreatSubject => ({
    type: 'identity',
    id: identity.id,
    name: identityName(identity),
  });

  switch (request.action.kind) {
    case 'revoke-sessions': {
      const identity = await target();
      if (typeof identity === 'string') return skip(identity);
      // As identities.revokeSessions: a root administrator's sessions are ended by root (or by themselves).
      if (
        principal &&
        identity.rootAdmin &&
        principal.identity.id !== identity.id &&
        !(await ctx.rootPrincipal(tx, principal))
      )
        throw new OperationDenied('Root capability is protected');
      const keepApiKeys = request.action.keepApiKeys !== false;
      // A person revoking their own sessions keeps the one they are responding from.
      const own = principal?.session.id;
      let revoked = 0;
      for (const session of await tx.find<Session>('sessions', { identityId: identity.id })) {
        if (session.id === own || (keepApiKeys && session.kind === 'api-key')) continue;
        await ctx.auth.endSession(tx, session.id);
        revoked++;
      }
      // Role sessions the identity assumed in other tenants, then delegated sessions acting as an agent.
      for (const session of await tx.find<Session>('sessions', {
        originalIdentityId: identity.id,
      })) {
        if (session.id === own || (keepApiKeys && session.kind === 'api-key')) continue;
        await tx.delete('sessions', session.id);
        revoked++;
      }
      if (identity.kind === 'agent')
        revoked += await deleteDelegatedSessions(tx, { agentId: identity.id });
      for (const challenge of await tx.find('authChallenges', { identityId: identity.id }))
        await tx.delete('authChallenges', challenge.id);
      await threatAudit(ctx, tx, tenantId, request.actor, 'threat:revoke-sessions', identity.id, {
        revoked,
        keptApiKeys: keepApiKeys,
        reason,
        ...refs,
      });
      return save(identitySubject(identity), 'applied', {
        details: { revoked, keptApiKeys: keepApiKeys },
      });
    }
    case 'forget-devices': {
      const identity = await target();
      if (typeof identity === 'string') return skip(identity);
      let removed = 0;
      for (const device of await tx.find('authDevices', { identityId: identity.id })) {
        await tx.delete('authDevices', device.id);
        removed++;
      }
      await threatAudit(ctx, tx, tenantId, request.actor, 'threat:forget-devices', identity.id, {
        removed,
        reason,
        ...refs,
      });
      return save(identitySubject(identity), 'applied', { details: { removed } });
    }
    case 'contain': {
      const identity = await target();
      if (typeof identity === 'string') return skip(identity);
      const subject = identitySubject(identity);
      if (principal && principal.identity.id === identity.id)
        throw new IamError('INVALID_INPUT', 'You cannot contain yourself');
      const stored = await tx.get<IdentityRisk>(threatCollections.risk, identity.id);
      const risk = stored?.tenantId === tenantId ? stored : undefined;
      if (identity.status !== 'active')
        return skip(risk?.contained ? 'already-applied' : 'inactive', subject);
      if (identity.rootAdmin) {
        if (!principal) return skip('protected', subject);
        if (!(await ctx.rootPrincipal(tx, principal)))
          throw new OperationDenied('Root capability is protected');
      }
      if (identity.owner && !principal) return skip('protected', subject);
      if (principal) {
        // As identities.setStatus: disabling an owner takes an owner of the tenant in person or a root principal,
        // never a permission alone.
        await assertOwnerControl(
          ctx,
          tx,
          principal,
          identity,
          'Only an owner can contain an owner',
        );
        await ctx.protectLastOwner(tx, identity);
      }
      if (brake && brake.contained >= settings.maxAutomaticContainments) {
        const first = !brake.braked;
        brake.braked = (brake.braked ?? 0) + 1;
        if (first)
          await threatAudit(
            ctx,
            tx,
            tenantId,
            request.actor,
            'threat:response-braked',
            request.playbookId ? `threats/playbooks/${request.playbookId}` : 'threats/playbooks',
            {
              threshold: settings.maxAutomaticContainments,
              identityId: identity.id,
              ...refs,
            },
          );
        return skip('braked', subject);
      }
      await tx.put<Identity>('identities', { ...identity, status: 'disabled' });
      // Every credential but the API keys ends now; the keys are refused while the identity is disabled and work
      // again after a release, so containment is reversible without reissuing them.
      let sessionsEnded = 0;
      for (const session of await tx.find<Session>('sessions', { identityId: identity.id })) {
        if (session.kind === 'api-key') continue;
        await ctx.auth.endSession(tx, session.id);
        sessionsEnded++;
      }
      for (const session of await tx.find<Session>('sessions', {
        originalIdentityId: identity.id,
      })) {
        if (session.kind === 'api-key') continue;
        await tx.delete('sessions', session.id);
        sessionsEnded++;
      }
      if (identity.kind === 'agent')
        sessionsEnded += await deleteDelegatedSessions(tx, { agentId: identity.id });
      for (const device of await tx.find('authDevices', { identityId: identity.id }))
        await tx.delete('authDevices', device.id);
      for (const challenge of await tx.find('authChallenges', { identityId: identity.id }))
        await tx.delete('authChallenges', challenge.id);
      // As when an identity is disabled: invitations it sent (an intruder's among them) stay dead after a release.
      await revokeInvitationsBy(tx, identity.id);
      const contained: NonNullable<IdentityRisk['contained']> = {
        at: now,
        by: actorId,
        reason,
        ...(request.incidentId !== undefined ? { incidentId: request.incidentId } : {}),
      };
      if (risk)
        await tx.put<IdentityRisk>(threatCollections.risk, { ...risk, contained, updatedAt: now });
      else
        await tx.insert<IdentityRisk>(threatCollections.risk, {
          id: identity.id,
          tenantId,
          identityId: identity.id,
          contributions: [],
          score: 0,
          level: 'none',
          contained,
          updatedAt: now,
        });
      if (brake) brake.contained++;
      await threatAudit(ctx, tx, tenantId, request.actor, 'threat:contain', identity.id, {
        reason,
        sessionsEnded,
        ...refs,
      });
      return save(subject, 'applied', { details: { sessionsEnded } });
    }
    case 'block-network': {
      const network = (
        request.subject.type === 'network' ? request.subject.id : request.network
      )?.trim();
      if (!network) return skip('no-network');
      const subject: ThreatSubject = { type: 'network', id: network };
      if (!isIpRange(network)) {
        if (principal)
          throw new IamError('INVALID_INPUT', 'network must be an IPv4/IPv6 address or CIDR block');
        return skip('invalid-network', subject);
      }
      // As security.blockNetwork: the root tenant's blocks decide whether root administrators can sign in, so only
      // root sets them. Playbooks, which any iam:threats:manage holder may write, never do.
      if ((await ctx.tenant(tx, tenantId)).parentId === null) {
        if (!principal) return skip('protected', subject);
        if (!(await ctx.rootPrincipal(tx, principal)))
          throw new OperationDenied('Blocks on the root tenant are set by root administrators');
      }
      if (settings.trustedNetworks.some((trusted) => overlaps(network, trusted)))
        return skip('trusted-network', subject);
      if (principal) {
        // As security.blockNetwork: never the address the responder's session came from or this request comes from.
        const own = [principal.session.client?.ip, ctx.auth.currentClient()?.ip];
        if (own.some((ip) => ip !== undefined && ipMatches(ip, network)))
          throw new IamError('INVALID_INPUT', 'That network includes your own address');
      }
      const requested = request.action.durationMs ?? blockDurationBounds.default;
      const durationMs = principal
        ? integer(requested, 'durationMs', blockDurationBounds.min, blockDurationBounds.max)
        : Math.min(
            blockDurationBounds.max,
            Math.max(
              blockDurationBounds.min,
              Number.isSafeInteger(requested) ? requested : blockDurationBounds.default,
            ),
          );
      const expiresAt = now + durationMs;
      // The tenant's own blocks plus the platform-wide ones, which apply to every tenant.
      const blocks = [
        ...(await tx.find<NetworkBlock>('authBlocks', { tenantId })),
        ...(await tx.find<NetworkBlock>('authBlocks', { platform: true })),
      ];
      // A block that already covers the network for at least as long makes this one redundant.
      const lasting = (block: NetworkBlock) =>
        block.expiresAt === undefined || block.expiresAt >= expiresAt;
      if (
        blocks.some(
          (block) => isIpRange(block.network) && lasting(block) && covers(block.network, network),
        )
      )
        return skip('already-applied', subject);
      const existing = blocks.find(
        (block) => block.tenantId === tenantId && !block.platform && block.network === network,
      );
      const block: NetworkBlock = {
        id: existing?.id ?? id(),
        tenantId,
        network,
        reason: `threat: ${reason}`.slice(0, 512),
        createdAt: now,
        createdBy: actorId,
        expiresAt,
      };
      if (existing) await tx.put('authBlocks', block);
      else await tx.insert('authBlocks', block);
      ctx.auth.invalidateNetworkBlocks();
      await threatAudit(
        ctx,
        tx,
        tenantId,
        request.actor,
        'threat:block-network',
        `threats/networks/${network}`,
        { network, expiresAt, renewed: Boolean(existing), reason, ...refs },
      );
      return save(subject, 'applied', {
        details: { network, blockId: block.id, expiresAt, renewed: Boolean(existing) },
      });
    }
    case 'notify': {
      const stored =
        request.incidentId !== undefined
          ? await tx.get<ThreatIncident>(threatCollections.incidents, request.incidentId)
          : undefined;
      const incident = stored?.tenantId === tenantId ? stored : undefined;
      if (!incident) return skip('no-incident');
      if (!ctx.options.authentication?.sendEmail) return skip('no-transport');
      const recipients = await incidentRecipients(tx, tenantId, settings);
      if (!recipients.length) return skip('no-recipients');
      if (!principal) {
        // Playbooks email an incident once, and again only when its severity has risen since.
        const earlier = await tx.find<ThreatResponse>(threatCollections.responses, {
          tenantId,
          incidentId: incident.id,
          action: 'notify',
          outcome: 'applied',
        });
        if (
          earlier.some(
            (response) =>
              typeof response.details?.severity === 'string' &&
              severityAtLeast(response.details.severity as ThreatSeverity, incident.severity),
          )
        )
          return skip('already-applied');
      }
      const sent = await deliverIncident(ctx, tx, tenantId, incident, recipients, request.actor);
      return save(request.subject, 'applied', {
        details: { recipients: sent, severity: incident.severity },
      });
    }
    default:
      throw new IamError('INVALID_INPUT', 'Unknown response action');
  }
}

/**
 * Lifts a containment: the identity is active again and its risk record no longer marks it contained (the risk
 * score is kept). Only an identity the threats module contained and that nothing else has disabled, suspended, or
 * re-enabled since can be released (`INVALID_TRANSITION` 409 otherwise, or when it has expired since); a root
 * administrator only by root. Audited as
 * `threat:release` and kept as a `release` response. After commit the caller runs `afterThreatResponses`.
 */
export async function releaseIdentity(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  identityId: string,
  actor: ResponseActor,
  note?: string,
): Promise<ThreatResponse> {
  const now = ctx.now();
  const identity = await ctx.activeIdentity(tx, identityId, tenantId);
  const stored = await tx.get<IdentityRisk>(threatCollections.risk, identity.id);
  const risk = stored?.tenantId === tenantId ? stored : undefined;
  // A suspended agent is held by its kill switch (agents.resume lifts it); other paths that disable or re-enable an
  // identity drop the mark (endContainment), so what they did is never undone here.
  if (!risk?.contained || identity.status !== 'disabled' || identity.agent?.suspended)
    throw new IamError('INVALID_TRANSITION', 'The identity is not contained', 409);
  const principal = manualPrincipal(actor);
  if (principal && identity.rootAdmin && !(await ctx.rootPrincipal(tx, principal)))
    throw new OperationDenied('Root capability is protected');
  if (ctx.identityExpired(identity))
    throw new IamError(
      'INVALID_TRANSITION',
      'Extend or clear expiresAt before releasing an expired identity',
      409,
    );
  const { contained, ...rest } = risk;
  await tx.put<Identity>('identities', { ...identity, status: 'active' });
  await tx.put<IdentityRisk>(threatCollections.risk, { ...rest, updatedAt: now });
  const cleaned = note?.trim().slice(0, 1024);
  await threatAudit(ctx, tx, tenantId, actor, 'threat:release', identity.id, {
    ...(cleaned ? { note: cleaned } : {}),
    containedAt: contained.at,
    ...(contained.incidentId !== undefined ? { incidentId: contained.incidentId } : {}),
  });
  return tx.insert<ThreatResponse>(threatCollections.responses, {
    id: id(),
    tenantId,
    action: 'release',
    subject: { type: 'identity', id: identity.id, name: identityName(identity) },
    outcome: 'applied',
    ...(contained.incidentId !== undefined ? { incidentId: contained.incidentId } : {}),
    actorId: actorIdOf(actor),
    ...(cleaned ? { details: { note: cleaned } } : {}),
    createdAt: now,
  });
}

/**
 * Who is emailed about incidents: the tenant's listed addresses plus, when `notify.owners` is set, its active owners
 * with a verified email. Lowercased, without duplicates.
 */
async function incidentRecipients(
  tx: IamStore,
  tenantId: string,
  settings: ResolvedThreatSettings,
): Promise<string[]> {
  const recipients = new Set(settings.notify.emails.map((address) => address.toLowerCase()));
  if (settings.notify.owners)
    for (const owner of await tx.find<Identity>('identities', {
      tenantId,
      owner: true,
      status: 'active',
    }))
      if (owner.email && owner.emailVerified) recipients.add(owner.email.toLowerCase());
  return [...recipients].sort();
}

/** Queues one `threat-alert` email per recipient and audits `threat:notify`; returns the number queued. */
async function deliverIncident(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  incident: ThreatIncident,
  recipients: string[],
  actor: ResponseActor,
): Promise<number> {
  const tenant = await tx.get<Tenant>('tenants', tenantId);
  const latestId = incident.detectionIds.at(-1);
  const latest =
    latestId !== undefined
      ? await tx.get<ThreatDetection>(threatCollections.detections, latestId)
      : undefined;
  const payload: Record<string, string> = {
    incidentId: incident.id,
    title: incident.title,
    severity: incident.severity,
    subject: incident.subject.name ?? incident.subject.id,
    subjectType: incident.subject.type,
    detections: String(incident.detectionCount),
    tenantName: tenant?.name ?? tenantId,
    ...(latest?.tenantId === tenantId ? { summary: latest.summary } : {}),
  };
  for (const to of recipients)
    await ctx.auth.enqueueDelivery(tx, {
      tenantId,
      kind: 'email',
      to,
      template: 'threat-alert',
      payload,
    });
  await threatAudit(ctx, tx, tenantId, actor, 'threat:notify', `threats/incidents/${incident.id}`, {
    recipients: recipients.length,
    severity: incident.severity,
    incidentId: incident.id,
  });
  return recipients.length;
}

/**
 * Emails an incident to the tenant's configured recipients (`threat-alert` template) and audits `threat:notify`.
 * Sends nothing (`sent: 0`, no audit) without an email delivery callback or recipients. The automatic actor is used
 * unless a responding person is given.
 */
export async function notifyIncident(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  incident: ThreatIncident,
  settings: ResolvedThreatSettings,
  actor: ResponseActor = { automatic: true },
): Promise<{ sent: number }> {
  if (!ctx.options.authentication?.sendEmail) return { sent: 0 };
  const recipients = await incidentRecipients(tx, tenantId, settings);
  if (!recipients.length) return { sent: 0 };
  return { sent: await deliverIncident(ctx, tx, tenantId, incident, recipients, actor) };
}

/**
 * Post-commit follow-up of responses: reconciles access-package rules for identities contained or released
 * (`afterIdentityChange`, which never throws) and clears this process's network block cache again after a block,
 * so a read racing the transaction cannot keep the pre-change list for a few seconds.
 */
export async function afterThreatResponses(
  ctx: ServerContext,
  tenantId: string,
  responses: readonly ThreatResponse[],
): Promise<void> {
  const applied = responses.filter((response) => response.outcome === 'applied');
  if (applied.some((response) => response.action === 'block-network'))
    ctx.auth.invalidateNetworkBlocks();
  const changed = [
    ...new Set(
      applied
        .filter(
          (response) =>
            (response.action === 'contain' || response.action === 'release') &&
            response.subject.type === 'identity',
        )
        .map((response) => response.subject.id),
    ),
  ];
  await afterIdentityChange(ctx, tenantId, changed, undefined);
}
