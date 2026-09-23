import {
  IamError,
  findOrdered,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Session,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { signAgentCard, type SignedAgentCard } from '../a2a.js';
import {
  agentProfile,
  agentStanding,
  agentSummary,
  sponsorFor,
  type AgentProfileInput,
  type AgentSummary,
} from '../agents.js';
import { attributeValues } from '../catalog.js';
import type { ServerContext } from '../context.js';
import { deleteDelegatedSessions, revokeDelegationsOf, type Delegation } from '../delegations.js';
import { actsInOwnRight } from '../session-kinds.js';
import { byNewest, id } from '../utils.js';
import { integer, text } from '../validation.js';
import { deleteIdentity } from './identities.js';

/** Paging of activity reads: newest first, 1-500 events (100 by default), optionally between `from` and `to`. */
export interface ActivityQuery {
  limit?: number;
  offset?: number;
  from?: number;
  to?: number;
}

/** Audit events newest first in a tenant that match `where`, with the paging of an activity query. */
export async function auditActivity(
  tx: IamStore,
  tenantId: string,
  query: ActivityQuery,
  where: (event: AuditEvent) => boolean,
): Promise<AuditEvent[]> {
  return findOrdered<AuditEvent>(
    tx,
    'audit',
    { tenantId },
    {
      field: 'timestamp',
      direction: 'desc',
      limit: integer(query.limit ?? 100, 'limit', 1, 500),
      offset: integer(query.offset ?? 0, 'offset', 0, 100_000),
      ...(query.from !== undefined
        ? { from: integer(query.from, 'from', 0, Number.MAX_SAFE_INTEGER) }
        : {}),
      ...(query.to !== undefined
        ? { to: integer(query.to, 'to', 0, Number.MAX_SAFE_INTEGER) }
        : {}),
      where,
    },
  );
}

export interface CreateAgentInput extends AgentProfileInput {
  tenantId: string;
  name: string;
  description?: string;
  /** The accountable person; defaults to the caller when the caller is a person of the tenant. */
  sponsorId?: string;
  /** Scheduled deactivation (epoch milliseconds), as for service accounts. */
  expiresAt?: number;
  attributes?: Record<string, Json>;
}

export interface UpdateAgentInput extends AgentProfileInput {
  tenantId: string;
  agentId: string;
  name?: string;
  description?: string | null;
  sponsorId?: string;
  expiresAt?: number | null;
  attributes?: Record<string, Json>;
}

/** An agent with the credentials and delegations it holds, for its detail page. */
export interface AgentDetail extends AgentSummary {
  keys: { id: string; name?: string; createdAt: number; expiresAt: number; lastUsedAt?: number }[];
  delegations: { active: number; pending: number };
  liveDelegatedSessions: number;
}

/** An agent as the catalog shows it to people deciding whether to delegate to it. */
export interface AgentListing {
  id: string;
  name: string;
  description?: string;
  purpose?: string;
  model?: string;
  provider?: string;
  url?: string;
  protocols?: string[];
  /** Services outside Better IAM the agent may present a person's delegation to (`delegations.issueToken`). */
  tokenAudiences?: string[];
  sponsorName: string;
}

/** An agent's latest attested A2A card (`signCard`): its entry in the tenant's agent directory. */
export interface AgentCardRecord extends StoredRecord {
  agentId: string;
  card: SignedAgentCard['card'];
  attestation: SignedAgentCard['attestation'];
  signedAt: number;
  /** When the attestation expires; the entry leaves the directory then. */
  expiresAt: number;
}

/** One agent in the directory: its current attested card, ready to verify with `verifyAgentCard`. */
export interface AgentDirectoryEntry {
  agentId: string;
  name: string;
  card: SignedAgentCard['card'];
  attestation: SignedAgentCard['attestation'];
  expiresAt: number;
}

/** A person's own session of the tenant (not a role, token, delegated or impersonation session). */
function personalSession(principal: AuthenticatedPrincipal, tenantId: string): boolean {
  return (
    actsInOwnRight(principal.session) &&
    principal.identity.kind === 'user' &&
    principal.identity.tenantId === tenantId &&
    principal.session.tenantId === tenantId &&
    !principal.session.impersonatorId
  );
}

/**
 * Agent changes without a credential, for the `agents` API (which authorizes first) and for configuration sync
 * (ai-sync.ts). Every function runs inside the caller's transaction and audits like the API.
 */
export function agentMutations(ctx: ServerContext) {
  /** Registers an agent sponsored by `sponsorId`; counts toward the tenant's `agents` limit. */
  async function createAgent(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    input: Omit<CreateAgentInput, 'tenantId'> & { sponsorId: string },
  ): Promise<Identity> {
    const name = text(input.name, 'name');
    const sponsor = await sponsorFor(ctx, tx, tenant.id, input.sponsorId);
    await ctx.enforceLimit(
      tx,
      tenant,
      'agents',
      async () =>
        (await tx.find<Identity>('identities', { tenantId: tenant.id, kind: 'agent' })).filter(
          (item) => item.status !== 'deleted',
        ).length,
    );
    const agent: Identity = {
      id: id(),
      tenantId: tenant.id,
      kind: 'agent',
      name,
      status: 'active',
      emailVerified: false,
      owner: false,
      rootAdmin: false,
      createdAt: ctx.now(),
      agent: await agentProfile(ctx, tx, tenant.id, input, { sponsorId: sponsor.id }),
    };
    if (input.description !== undefined)
      agent.description = text(input.description, 'description', 512);
    if (input.expiresAt !== undefined) agent.expiresAt = ctx.bindingExpiry(input.expiresAt);
    if (input.attributes !== undefined)
      agent.attributes = attributeValues(ctx.catalog.identityAttributes, input.attributes);
    await tx.insert<Identity>('identities', agent);
    await ctx.events.audit(tx, principal, 'agent:create', tenant.id, agent.id, 'allow', false, {
      sponsorId: sponsor.id,
      ...(agent.agent!.model ? { model: agent.agent!.model } : {}),
      ...(agent.agent!.provider ? { provider: agent.agent!.provider } : {}),
    });
    return agent;
  }

  /** Changes an agent (see `agents.update`); a new sponsor is audited as `agent:sponsor-change`. */
  async function updateAgent(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    agent: Identity,
    input: Omit<UpdateAgentInput, 'tenantId' | 'agentId'>,
  ): Promise<Identity> {
    if (agent.status === 'deleted') throw new IamError('NOT_FOUND', 'Agent has been deleted', 404);
    const next: Identity = { ...agent };
    if (input.name !== undefined) next.name = text(input.name, 'name');
    if (input.description === null) delete next.description;
    else if (input.description !== undefined)
      next.description = text(input.description, 'description', 512);
    if (input.attributes !== undefined)
      next.attributes = attributeValues(ctx.catalog.identityAttributes, input.attributes);
    if (input.expiresAt === null) delete next.expiresAt;
    else if (input.expiresAt !== undefined) next.expiresAt = ctx.bindingExpiry(input.expiresAt);
    let profile = await agentProfile(ctx, tx, agent.tenantId, input, {
      ...(agent.agent ?? { sponsorId: '' }),
    });
    const previousSponsor = agent.agent?.sponsorId;
    if (input.sponsorId !== undefined) {
      const sponsor = await sponsorFor(ctx, tx, agent.tenantId, input.sponsorId);
      profile = { ...profile, sponsorId: sponsor.id };
    }
    next.agent = profile;
    const updated = await tx.put<Identity>('identities', next);
    if (previousSponsor !== profile.sponsorId)
      await ctx.events.audit(
        tx,
        principal,
        'agent:sponsor-change',
        agent.tenantId,
        agent.id,
        'allow',
        false,
        { from: previousSponsor ?? null, to: profile.sponsorId },
      );
    return updated;
  }

  /** Deletes an agent: revokes every delegation to it, ends its sessions, leaves a tombstone. */
  async function deleteAgent(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    agent: Identity,
  ): ReturnType<typeof deleteIdentity> {
    const delegations = await revokeDelegationsOf(ctx, tx, agent, principal.identity.id);
    await deleteDelegatedSessions(tx, { agentId: agent.id });
    if (await tx.get('agentCards', agent.id)) await tx.delete('agentCards', agent.id);
    const result = await deleteIdentity(ctx, tx, principal, agent);
    await ctx.events.audit(
      tx,
      principal,
      'identity:delete',
      agent.tenantId,
      agent.id,
      'allow',
      false,
      { kind: 'agent', delegationsRevoked: delegations },
    );
    return result;
  }

  return { createAgent, updateAgent, deleteAgent };
}

/**
 * The `agents` group: AI agents as accounts. Administrators create agents with `iam:agents:create` (the caller is the
 * sponsor unless `sponsorId` names another active person), read them with `iam:agents:read`, change them with
 * `iam:agents:update` and delete them with `iam:agents:delete`. Keys come from `credentials.create` like a service
 * account's. A sponsor manages their own agents without a permission: `listMine`, and the `suspend` kill switch (and
 * `resume` when they were the one who suspended it).
 */
export function createAgentsApi(ctx: ServerContext) {
  const { auth } = ctx;
  const { operation } = ctx.operations;
  const mutations = agentMutations(ctx);

  async function agentRecord(tx: IamStore, agentId: string, tenantId: string): Promise<Identity> {
    const agent = await ctx.scoped<Identity>(tx, 'identities', agentId, tenantId);
    if (agent.kind !== 'agent') throw new IamError('NOT_FOUND', 'Agent not found', 404);
    return agent;
  }

  async function agentDetail(tx: IamStore, agent: Identity): Promise<AgentDetail> {
    const now = ctx.now();
    const keys = (await tx.find<Session>('sessions', { identityId: agent.id, kind: 'api-key' }))
      .filter((session) => session.expiresAt > now)
      .sort(byNewest)
      .map((session) => ({
        id: session.id,
        ...(session.name !== undefined ? { name: session.name } : {}),
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        ...(session.lastSeenAt > session.createdAt ? { lastUsedAt: session.lastSeenAt } : {}),
      }));
    const delegations = await tx.find<Delegation>('delegations', {
      tenantId: agent.tenantId,
      agentId: agent.id,
    });
    const live = (
      await tx.find<Session>('sessions', { kind: 'delegated', agentId: agent.id })
    ).filter((session) => session.expiresAt > now).length;
    return {
      ...(await agentSummary(ctx, tx, agent)),
      keys,
      delegations: {
        active: delegations.filter((item) => item.status === 'active' && item.expiresAt > now)
          .length,
        pending: delegations.filter((item) => item.status === 'pending' && item.expiresAt > now)
          .length,
      },
      liveDelegatedSessions: live,
    };
  }

  /**
   * Suspends an agent: its keys, session tokens and delegated sessions are refused while it is suspended, and live
   * delegated sessions and session tokens are ended now. Keys are kept, so `resume` restores the agent as it was.
   */
  async function suspendAgent(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    agent: Identity,
    reason: string | undefined,
  ): Promise<AgentSummary> {
    if (agent.status === 'deleted') throw new IamError('NOT_FOUND', 'Agent has been deleted', 404);
    if (agent.status === 'disabled' && agent.agent?.suspended)
      throw new IamError('CONFLICT', 'The agent is already suspended', 409);
    const now = ctx.now();
    const suspended = await tx.put<Identity>('identities', {
      ...agent,
      status: 'disabled',
      agent: {
        ...agent.agent!,
        suspended: { by: principal.identity.id, at: now, ...(reason ? { reason } : {}) },
      },
    });
    const sessions = await deleteDelegatedSessions(tx, { agentId: agent.id });
    let tokens = 0;
    for (const session of await tx.find<Session>('sessions', { identityId: agent.id })) {
      if (session.kind === 'api-key') continue;
      await tx.delete('sessions', session.id);
      tokens++;
    }
    await ctx.events.audit(
      tx,
      principal,
      'agent:suspend',
      agent.tenantId,
      agent.id,
      'allow',
      false,
      {
        ...(reason ? { reason } : {}),
        delegatedSessionsEnded: sessions,
        sessionsEnded: tokens,
      },
    );
    return agentSummary(ctx, tx, suspended);
  }

  async function resumeAgent(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    agent: Identity,
  ): Promise<AgentSummary> {
    if (agent.status === 'deleted') throw new IamError('NOT_FOUND', 'Agent has been deleted', 404);
    if (agent.status === 'active')
      throw new IamError('CONFLICT', 'The agent is not suspended', 409);
    if (ctx.identityExpired(agent))
      throw new IamError(
        'INVALID_TRANSITION',
        'Extend or clear expiresAt before resuming an expired agent',
        409,
      );
    const { suspended: _gone, ...profile } = agent.agent!;
    const resumed = await tx.put<Identity>('identities', {
      ...agent,
      status: 'active',
      agent: profile,
    });
    await ctx.events.audit(tx, principal, 'agent:resume', agent.tenantId, agent.id, 'allow');
    return agentSummary(ctx, tx, resumed);
  }

  /**
   * Runs `fn` as the agent's sponsor when the caller is that person in their own session, otherwise as an
   * administrative operation needing `action` on `iam/{agentId}`.
   */
  async function asSponsorOr<T>(
    credential: CredentialInput,
    input: { tenantId: string; agentId: string },
    action: string,
    fn: (
      tx: IamStore,
      principal: AuthenticatedPrincipal,
      agent: Identity,
      sponsor: boolean,
    ) => Promise<T>,
  ): Promise<T> {
    const tenantId = text(input.tenantId, 'tenantId');
    const agentId = text(input.agentId, 'agentId');
    const authenticated = await ctx.principals.authenticate(credential);
    const own = await ctx.store.transaction(async (tx) => {
      const principal = await ctx.principals.currentPrincipal(tx, authenticated);
      if (!personalSession(principal, tenantId)) return undefined;
      const agent = await tx.get<Identity>('identities', agentId);
      if (
        !agent ||
        agent.kind !== 'agent' ||
        agent.tenantId !== tenantId ||
        agent.agent?.sponsorId !== principal.identity.id
      )
        return undefined;
      return { value: await fn(tx, principal, agent, true) };
    });
    if (own) return own.value;
    return operation(credential, tenantId, action, agentId, async ({ tx, principal }) =>
      fn(tx, principal, await agentRecord(tx, agentId, tenantId), false),
    );
  }

  return {
    /**
     * Registers an AI agent. The sponsor (the caller when they are a person of the tenant, else `sponsorId`) must be an
     * active person of the tenant; the agent stops working whenever its sponsor does. Counts toward the tenant's
     * `agents` limit. Audited as the operation plus `agent:create`.
     */
    create: (credential: CredentialInput, input: CreateAgentInput): Promise<AgentSummary> =>
      operation(
        credential,
        input.tenantId,
        'iam:agents:create',
        input.tenantId,
        async ({ tx, principal, tenant }) => {
          const sponsorId =
            input.sponsorId ??
            (personalSession(principal, tenant.id) ? principal.identity.id : undefined);
          if (sponsorId === undefined)
            throw new IamError(
              'INVALID_SPONSOR',
              'Name the person accountable for the agent (sponsorId)',
            );
          const agent = await mutations.createAgent(tx, principal, tenant, {
            ...input,
            sponsorId,
          });
          return agentSummary(ctx, tx, agent);
        },
      ),

    /** One agent with its standing, live keys (labels only) and delegation counts. Needs `iam:agents:read`. */
    get: (credential: CredentialInput, input: { tenantId: string; agentId: string }) =>
      asSponsorOr(credential, input, 'iam:agents:read', async (tx, _principal, agent) =>
        agentDetail(tx, agent),
      ),

    /**
     * The tenant's agents, newest first, optionally of one sponsor or in one standing. Deleted agents are left out
     * unless `includeDeleted`. Needs `iam:agents:read`.
     */
    list: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        sponsorId?: string;
        standing?: AgentSummary['standing'];
        includeDeleted?: boolean;
      },
    ): Promise<AgentSummary[]> =>
      operation(credential, input.tenantId, 'iam:agents:read', input.tenantId, async ({ tx }) => {
        const sponsorId =
          input.sponsorId !== undefined ? text(input.sponsorId, 'sponsorId') : undefined;
        const summaries: AgentSummary[] = [];
        for (const agent of (
          await tx.find<Identity>('identities', { tenantId: input.tenantId, kind: 'agent' })
        ).sort(byNewest)) {
          if (agent.status === 'deleted' && input.includeDeleted !== true) continue;
          if (sponsorId !== undefined && agent.agent?.sponsorId !== sponsorId) continue;
          const summary = await agentSummary(ctx, tx, agent);
          if (input.standing !== undefined && summary.standing !== input.standing) continue;
          summaries.push(summary);
        }
        return summaries;
      }),

    /**
     * The agents people of the tenant may delegate to: active, delegable agents in good standing, with what a person
     * needs to decide (name, purpose, model, provider, url, protocols and the sponsor's name). Any person's own
     * session of the tenant; needs no permission.
     */
    catalog: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<AgentListing[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (!personalSession(principal, tenantId))
          throw new IamError(
            'ACCESS_DENIED',
            'The agent catalog is read from a person’s own session of the tenant',
            403,
          );
        const listings: AgentListing[] = [];
        for (const agent of (
          await tx.find<Identity>('identities', { tenantId, kind: 'agent' })
        ).sort((a, b) => a.name.localeCompare(b.name))) {
          const profile = agent.agent;
          if (!profile || profile.delegable === false) continue;
          if ((await agentStanding(ctx, tx, agent)) !== 'ok') continue;
          const sponsor = await tx.get<Identity>('identities', profile.sponsorId);
          listings.push({
            id: agent.id,
            name: agent.name,
            ...(agent.description !== undefined ? { description: agent.description } : {}),
            ...(profile.purpose !== undefined ? { purpose: profile.purpose } : {}),
            ...(profile.model !== undefined ? { model: profile.model } : {}),
            ...(profile.provider !== undefined ? { provider: profile.provider } : {}),
            ...(profile.url !== undefined ? { url: profile.url } : {}),
            ...(profile.protocols !== undefined ? { protocols: [...profile.protocols] } : {}),
            ...(profile.tokenAudiences?.length
              ? { tokenAudiences: [...profile.tokenAudiences] }
              : {}),
            sponsorName: sponsor?.name ?? '',
          });
        }
        return listings;
      });
    },

    /** The agents the caller sponsors (a person's own session of the tenant); needs no permission. */
    listMine: async (credential: CredentialInput, input: { tenantId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (!personalSession(principal, tenantId))
          throw new IamError(
            'ACCESS_DENIED',
            'Sponsored agents are listed from a person’s own session of the tenant',
            403,
          );
        const details: AgentDetail[] = [];
        for (const agent of (
          await tx.find<Identity>('identities', { tenantId, kind: 'agent' })
        ).sort(byNewest))
          if (agent.status !== 'deleted' && agent.agent?.sponsorId === principal.identity.id)
            details.push(await agentDetail(tx, agent));
        return details;
      });
    },

    /**
     * Changes an agent's name, description, attributes, expiry or profile (model, provider, purpose, url, protocols,
     * delegable, maxDelegatedSessionSeconds, boundary, tokenAudiences; null clears). A new `sponsorId` must be an active person of the
     * tenant (audited `agent:sponsor-change`). Changes to the boundary and to `delegable` apply to live sessions at
     * once. Needs `iam:agents:update`.
     */
    update: (credential: CredentialInput, input: UpdateAgentInput): Promise<AgentSummary> =>
      operation(
        credential,
        input.tenantId,
        'iam:agents:update',
        text(input.agentId, 'agentId'),
        async ({ tx, principal }) => {
          const agent = await agentRecord(tx, input.agentId, input.tenantId);
          return agentSummary(ctx, tx, await mutations.updateAgent(tx, principal, agent, input));
        },
      ),

    /**
     * The kill switch. The agent's sponsor (in their own session) or an administrator with `iam:agents:update` stops
     * the agent at once: every credential is refused while it is suspended and live delegated sessions and session
     * tokens end now. API keys are kept for `resume`. Audited as `agent:suspend`.
     */
    suspend: (
      credential: CredentialInput,
      input: { tenantId: string; agentId: string; reason?: string },
    ): Promise<AgentSummary> => {
      const reason = input.reason !== undefined ? text(input.reason, 'reason', 512) : undefined;
      return asSponsorOr(credential, input, 'iam:agents:update', (tx, principal, agent) =>
        suspendAgent(tx, principal, agent, reason),
      );
    },

    /**
     * The organization-wide emergency stop: suspends every active agent of the tenant at once (during an incident, for
     * example), each exactly as `suspend` does, optionally only those of one `sponsorId` or running on one `provider` or
     * `model`. Needs `iam:agents:update` on the tenant and no recent sign-in, so it works in a hurry. Agents come back
     * one at a time with `resume`. Audited as `agent:suspend-all` with the count, and `agent:suspend` for each agent.
     */
    suspendAll: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        reason: string;
        sponsorId?: string;
        provider?: string;
        model?: string;
      },
    ): Promise<{ suspended: number; agentIds: string[] }> =>
      operation(
        credential,
        input.tenantId,
        'iam:agents:update',
        input.tenantId,
        async ({ tx, principal, tenant }) => {
          const reason = text(input.reason, 'reason', 512);
          const sponsorId =
            input.sponsorId !== undefined ? text(input.sponsorId, 'sponsorId') : undefined;
          const provider =
            input.provider !== undefined
              ? text(input.provider, 'provider', 64).toLowerCase()
              : undefined;
          const model = input.model !== undefined ? text(input.model, 'model', 128) : undefined;
          const agentIds: string[] = [];
          for (const agent of (
            await tx.find<Identity>('identities', { tenantId: tenant.id, kind: 'agent' })
          ).sort(byNewest)) {
            if (agent.status !== 'active') continue;
            if (sponsorId !== undefined && agent.agent?.sponsorId !== sponsorId) continue;
            if (provider !== undefined && agent.agent?.provider !== provider) continue;
            if (model !== undefined && agent.agent?.model !== model) continue;
            await suspendAgent(tx, principal, agent, reason);
            agentIds.push(agent.id);
          }
          await ctx.events.audit(
            tx,
            principal,
            'agent:suspend-all',
            tenant.id,
            tenant.id,
            'allow',
            false,
            {
              reason,
              suspended: agentIds.length,
              ...(sponsorId ? { sponsorId } : {}),
              ...(provider ? { provider } : {}),
              ...(model ? { model } : {}),
            },
          );
          return { suspended: agentIds.length, agentIds };
        },
      ),

    /**
     * Lifts a suspension. An administrator with `iam:agents:update` needs a recent sign-in; the sponsor may resume an
     * agent only when they suspended it themselves. Audited as `agent:resume`.
     */
    resume: (credential: CredentialInput, input: { tenantId: string; agentId: string }) =>
      asSponsorOr(credential, input, 'iam:agents:update', async (tx, principal, agent, sponsor) => {
        if (sponsor) {
          if (agent.agent?.suspended?.by !== principal.identity.id)
            throw new IamError(
              'ACCESS_DENIED',
              'Only an administrator can resume an agent someone else suspended',
              403,
            );
        } else auth.requireRecent(principal);
        return resumeAgent(tx, principal, agent);
      }),

    /**
     * Deletes an agent: its keys and sessions end, every delegation to it is revoked, and a tombstone keeps audit
     * records resolvable. Needs `iam:agents:delete` and a recent sign-in.
     */
    delete: (credential: CredentialInput, input: { tenantId: string; agentId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:agents:delete',
        text(input.agentId, 'agentId'),
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const agent = await agentRecord(tx, input.agentId, input.tenantId);
          return mutations.deleteAgent(tx, principal, agent);
        },
      ),

    /**
     * What the agent did, newest first: every audit event recorded for its own credentials and for the sessions in
     * which it acted for people (allowed and denied). For the agent's sponsor in their own session, or an administrator
     * with `iam:agents:read`.
     */
    activity: (
      credential: CredentialInput,
      input: ActivityQuery & { tenantId: string; agentId: string },
    ): Promise<AuditEvent[]> =>
      asSponsorOr(credential, input, 'iam:agents:read', (tx, _principal, agent) =>
        auditActivity(
          tx,
          agent.tenantId,
          input,
          (event) => event.actorId === agent.id || event.sessionContext?.agentId === agent.id,
        ),
      ),

    /** Whether the agent may act right now, and why not: `ok`, `suspended`, `expired`, `sponsor-inactive`, ... */
    standing: (credential: CredentialInput, input: { tenantId: string; agentId: string }) =>
      asSponsorOr(credential, input, 'iam:agents:read', async (tx, _principal, agent) => ({
        agentId: agent.id,
        standing: await agentStanding(ctx, tx, agent),
      })),

    /**
     * Signs the agent's A2A agent card (needs the `a2a` option). The card's `url` and every `additionalInterfaces[].url`
     * must be on the origin of the agent's registered `url`; IAM sets `provider.organization` to the tenant's name,
     * adds the attestation extension `urn:better-iam:a2a:attestation:v1` (agent, organization, sponsorship, model,
     * expiry) and signs the canonical card (RFC 8785) as a detached JWS. The agent must be in good standing. The agent
     * itself may call this with its own unscoped API key (so its A2A server re-signs before the attestation expires), as
     * may its sponsor in their own session or an administrator with `iam:agents:update`. Audited as `agent:card-sign`.
     */
    signCard: async (
      credential: CredentialInput,
      input: { tenantId: string; agentId: string; card: Record<string, unknown> },
    ): Promise<SignedAgentCard> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const agentId = text(input.agentId, 'agentId');
      const sign = async (tx: IamStore, principal: AuthenticatedPrincipal, agent: Identity) => {
        if ((await agentStanding(ctx, tx, agent)) !== 'ok')
          throw new IamError('INVALID_IDENTITY', 'The agent is not in good standing', 409);
        const tenant = await tx.get<Tenant>('tenants', agent.tenantId);
        if (!tenant) throw new IamError('NOT_FOUND', 'Tenant not found', 404);
        const signed = await signAgentCard(ctx, tenant, agent, input.card);
        // The latest attested card is the agent's entry in the tenant's directory (`directory`).
        const entry: AgentCardRecord = {
          id: agent.id,
          tenantId: agent.tenantId,
          agentId: agent.id,
          card: signed.card,
          attestation: signed.attestation,
          signedAt: ctx.now(),
          expiresAt: signed.expiresAt,
        };
        await ((await tx.get('agentCards', agent.id))
          ? tx.put<AgentCardRecord>('agentCards', entry)
          : tx.insert<AgentCardRecord>('agentCards', entry));
        await ctx.events.audit(
          tx,
          principal,
          'agent:card-sign',
          agent.tenantId,
          agent.id,
          'allow',
          false,
          { url: String(signed.card.url), expiresAt: signed.expiresAt },
        );
        return signed;
      };
      const authenticated = await ctx.principals.authenticate(credential);
      const own = await ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        // The agent's own unscoped API key: not a temporary credential minted from it, and not a key whose scopes
        // (session policy) limit what it may do.
        if (
          principal.identity.id !== agentId ||
          principal.identity.kind !== 'agent' ||
          principal.identity.tenantId !== tenantId ||
          principal.session.tenantId !== tenantId ||
          principal.session.kind !== 'api-key' ||
          !actsInOwnRight(principal.session) ||
          principal.session.impersonatorId ||
          principal.session.policy
        )
          return undefined;
        return { value: await sign(tx, principal, principal.identity) };
      });
      if (own) return own.value;
      return asSponsorOr(credential, { tenantId, agentId }, 'iam:agents:update', sign);
    },

    /**
     * The tenant's agent directory: the current attested A2A card of every agent in good standing whose attestation
     * has not expired (each agent's latest `signCard`), sorted by name, optionally only agents offering a `skill` (by
     * skill id or tag) or speaking a `protocol`. For finding the agent to hand work to. Any credential of the tenant (a
     * person, an agent's key, an agent acting for someone); needs no permission.
     */
    directory: async (
      credential: CredentialInput,
      input: { tenantId: string; skill?: string; protocol?: string },
    ): Promise<AgentDirectoryEntry[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const skill = input.skill !== undefined ? text(input.skill, 'skill', 128) : undefined;
      const protocol =
        input.protocol !== undefined
          ? text(input.protocol, 'protocol', 32).toLowerCase()
          : undefined;
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (principal.session.tenantId !== tenantId && principal.identity.tenantId !== tenantId)
          throw new IamError(
            'ACCESS_DENIED',
            'The agent directory is read from within the tenant',
            403,
          );
        const now = ctx.now();
        const entries: AgentDirectoryEntry[] = [];
        for (const record of await tx.find<AgentCardRecord>('agentCards', { tenantId })) {
          if (record.expiresAt <= now) continue;
          const agent = await tx.get<Identity>('identities', record.agentId);
          if (!agent || agent.kind !== 'agent' || agent.tenantId !== tenantId) continue;
          if ((await agentStanding(ctx, tx, agent)) !== 'ok') continue;
          if (protocol !== undefined && !record.attestation.protocols?.includes(protocol)) continue;
          if (skill !== undefined) {
            const skills = Array.isArray(record.card.skills)
              ? (record.card.skills as unknown[])
              : [];
            const offers = skills.some((item) => {
              if (!item || typeof item !== 'object') return false;
              const entry = item as { id?: unknown; tags?: unknown };
              return (
                entry.id === skill || (Array.isArray(entry.tags) && entry.tags.includes(skill))
              );
            });
            if (!offers) continue;
          }
          entries.push({
            agentId: agent.id,
            name: agent.name,
            card: record.card,
            attestation: record.attestation,
            expiresAt: record.expiresAt,
          });
        }
        return entries.sort((a, b) => a.name.localeCompare(b.name));
      });
    },
  };
}
