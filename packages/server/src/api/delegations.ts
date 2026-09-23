import {
  IamError,
  delegationActor,
  delegationTokenLimits,
  delegationTokenScopePattern as tokenScopePattern,
  delegationTokenType,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type DelegationTokenClaims,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Session,
  type Tenant,
} from '@better-iam/core';
import { newCredentialToken } from '@better-iam/auth';
import { cardSigner } from '../a2a.js';
import { agentSessionSeconds, agentStanding, tokenAudience } from '../agents.js';
import { auditActivity, type ActivityQuery } from './agents.js';
import { clientFromHeaders } from '../client-info.js';
import type { ServerContext } from '../context.js';
import { audienceRefusal, scopeRefusal, type DelegationTokenRecord } from '../delegation-tokens.js';
import {
  confirmationLimits,
  confirmPatterns,
  delegationLifetime,
  delegationLive,
  delegationPending,
  delegationScope,
  delegationSeconds,
  deleteDelegatedSessions,
  handoffLimits,
  handoffSetting,
  liveAncestors,
  maxSessionsPerDelegation,
  needsConfirmation,
  revokeHandoffsBelow,
  spendSetting,
  type Delegation,
  type DelegationConfirmation,
  type DelegationHandoff,
  type DelegationSpend,
} from '../delegations.js';
import { delegationSpendStanding } from '../inference.js';
import { actsInOwnRight, nextWatermark } from '../session-kinds.js';
import { sessionNameValue } from '../temporary-credentials.js';
import { byNewest, hash, id, token as randomToken } from '../utils.js';
import { email, integer, object, strings, text } from '../validation.js';

/** A delegation as the people and agents involved see it (never session material). */
export interface DelegationSummary {
  id: string;
  tenantId: string;
  status: Delegation['status'];
  /** Pending requests past their decision window and active delegations past their end read as expired. */
  expired: boolean;
  agent: { id: string; name: string; model?: string; provider?: string };
  subject: { id: string; name: string; email?: string };
  scopes?: string[];
  policy: PolicyDocument;
  requestedBy: Delegation['requestedBy'];
  reason?: string;
  createdAt: number;
  expiresAt: number;
  /** Pending requests: how long the delegation will last once approved, in seconds. */
  requestedSeconds?: number;
  maxSessionSeconds?: number;
  decidedAt?: number;
  revokedAt?: number;
  revokedBy?: string;
  lastUsedAt?: number;
  /** Actions the person confirms one call at a time. */
  confirm?: string[];
  /** Whether (and to which agents, how deep) the agent may hand parts of this delegation on. */
  handoff?: DelegationHandoff;
  /** A hand-off: the delegation it was handed on from. */
  parentId?: string;
  /** A hand-off: the agents above it, the person's own delegate first. */
  chain?: { id: string; name: string }[];
  /** The person's cap on AI model use under this delegation, and how much of it the current window has used. */
  spend?: {
    period: DelegationSpend['period'];
    maxTokens?: number;
    maxCostUsd?: number;
    maxRequests?: number;
    usedTokens: number;
    usedCostUsd: number;
    usedRequests: number;
    resetsAt: number;
  };
}

/** A confirmation request as the person and the agent see it. */
export interface ConfirmationSummary {
  id: string;
  tenantId: string;
  delegationId: string;
  agent: { id: string; name: string };
  subjectId: string;
  action: string;
  resource: { type: string; id: string };
  reason?: string;
  status: DelegationConfirmation['status'];
  /** Pending requests past their decision window and approvals past their validity read as expired. */
  expired: boolean;
  createdAt: number;
  expiresAt: number;
  validSeconds: number;
  decidedAt?: number;
}

/** What `delegations.assume` returns: a delegated session's bearer token, shown once. */
export interface DelegatedCredential {
  token: string;
  tokenType: 'Bearer';
  expiresAt: number;
  expiresIn: number;
  session: {
    id: string;
    kind: 'delegated';
    tenantId: string;
    /** The person the agent acts for. */
    identityId: string;
    agentId: string;
    delegationId: string;
    sessionName?: string;
  };
}

/** What `delegations.issueToken` returns: a delegation token for one service outside Better IAM. */
export interface DelegationToken {
  /** The signed JWT (`typ` `biam-delegation+jwt`); send it to the service, for example as a bearer token. */
  token: string;
  tokenType: typeof delegationTokenType;
  /** The token's `jti`. */
  tokenId: string;
  issuer: string;
  audience: string;
  /** The scopes it carries (empty for a delegation given as a policy). */
  scopes: string[];
  /** The agents from the person's own delegate to the one acting now. */
  chain: string[];
  /** Epoch milliseconds. */
  expiresAt: number;
  expiresIn: number;
}

export interface DelegationScopeInput {
  /** Actions the agent may take for the person (wildcards allowed); an alternative to `policy`. */
  scopes?: string[];
  /** A scope-down policy document; the person's own grants still decide. */
  policy?: PolicyDocument;
  /**
   * Action patterns the person confirms one call at a time (for example `billing:*`): refused with
   * `CONFIRMATION_REQUIRED` until the person approves that action on that resource (`requestConfirmation`).
   */
  confirm?: string[];
  /**
   * Lets the agent hand parts of the delegation on to other agents (`handoff`): to any agent that accepts delegation or
   * only to `agents`, for `depth` hand-offs down the line (1 to 3; 1 by default). Off when absent; `null` in `approve`
   * turns it off.
   */
  handoff?: { agents?: string[]; depth?: number } | null;
  /**
   * Caps what AI model calls made under the delegation (and hand-offs below it) may use per `period` (`minute`, `hour`,
   * `day` or `month`): `maxTokens`, `maxCostUsd` and/or `maxRequests`. `null` in `approve` removes it.
   */
  spend?: {
    period: DelegationSpend['period'];
    maxTokens?: number;
    maxCostUsd?: number;
    maxRequests?: number;
  } | null;
}

/**
 * The `delegations` group: people let AI agents act for them. A person grants a delegation directly (`grant`) or
 * approves an agent's request (`request` → `approve` / `deny`); the agent then opens short delegated sessions with its
 * own key (`assume`). Delegated sessions act as the person, within the delegation's scope and the agent's ceiling, and
 * never pass recent-authentication, ownership or self-service checks. The person, the agent's sponsor, the agent
 * itself or an administrator (`iam:delegations:revoke`) can revoke a delegation, which ends its sessions at once.
 * Administrators list and read delegations with `iam:delegations:read`.
 */
export function createDelegationsApi(ctx: ServerContext) {
  const { auth, store } = ctx;
  const { operation } = ctx.operations;

  const refuse = (message: string) => new IamError('ACCESS_DENIED', message, 403);

  /** A person in their own session of the tenant (not impersonated). */
  function assertPerson(principal: AuthenticatedPrincipal, tenantId: string): void {
    if (principal.session.impersonatorId)
      throw new IamError(
        'IMPERSONATION_RESTRICTED',
        'Delegations cannot be managed while impersonating a member',
        403,
      );
    if (
      !actsInOwnRight(principal.session) ||
      principal.session.kind !== 'user' ||
      principal.identity.kind !== 'user' ||
      principal.identity.tenantId !== tenantId ||
      principal.session.tenantId !== tenantId
    )
      throw refuse('Delegations are decided by a person in their own session of the organization');
  }

  /** An agent acting with its own API key in its own tenant. */
  function assertAgentKey(principal: AuthenticatedPrincipal, tenantId: string): void {
    if (
      principal.identity.kind !== 'agent' ||
      principal.session.kind !== 'api-key' ||
      principal.identity.tenantId !== tenantId ||
      principal.session.tenantId !== tenantId
    )
      throw refuse('Only an agent using its own API key can do this');
  }

  /** An agent of the tenant that may receive a delegation right now. */
  async function delegableAgent(
    tx: IamStore,
    agentId: unknown,
    tenantId: string,
  ): Promise<Identity> {
    const agent = await tx.get<Identity>('identities', text(agentId, 'agentId'));
    if (
      !agent ||
      agent.kind !== 'agent' ||
      agent.tenantId !== tenantId ||
      agent.status === 'deleted'
    )
      throw new IamError('NOT_FOUND', 'Agent not found', 404);
    if (agent.agent?.delegable === false)
      throw new IamError('DELEGATION_NOT_ALLOWED', 'This agent does not accept delegation', 403);
    if ((await agentStanding(ctx, tx, agent)) !== 'ok')
      throw new IamError('INVALID_IDENTITY', 'The agent is not in good standing', 409);
    return agent;
  }

  async function summary(tx: IamStore, delegation: Delegation): Promise<DelegationSummary> {
    const now = ctx.now();
    const agent = await tx.get<Identity>('identities', delegation.agentId);
    const subject = await tx.get<Identity>('identities', delegation.subjectId);
    const result: DelegationSummary = {
      id: delegation.id,
      tenantId: delegation.tenantId,
      status: delegation.status,
      expired:
        (delegation.status === 'active' || delegation.status === 'pending') &&
        delegation.expiresAt <= now,
      agent: {
        id: delegation.agentId,
        name: agent?.name ?? delegation.agentId,
        ...(agent?.agent?.model ? { model: agent.agent.model } : {}),
        ...(agent?.agent?.provider ? { provider: agent.agent.provider } : {}),
      },
      subject: {
        id: delegation.subjectId,
        name: subject?.name ?? delegation.subjectId,
        ...(subject?.email ? { email: subject.email } : {}),
      },
      policy: delegation.policy,
      requestedBy: delegation.requestedBy,
      createdAt: delegation.createdAt,
      expiresAt: delegation.expiresAt,
    };
    if (delegation.scopes) result.scopes = [...delegation.scopes];
    if (delegation.reason !== undefined) result.reason = delegation.reason;
    if (delegation.lifetimeMs !== undefined)
      result.requestedSeconds = Math.floor(delegation.lifetimeMs / 1000);
    if (delegation.maxSessionSeconds !== undefined)
      result.maxSessionSeconds = delegation.maxSessionSeconds;
    if (delegation.decidedAt !== undefined) result.decidedAt = delegation.decidedAt;
    if (delegation.revokedAt !== undefined) result.revokedAt = delegation.revokedAt;
    if (delegation.revokedBy !== undefined) result.revokedBy = delegation.revokedBy;
    if (delegation.lastUsedAt !== undefined) result.lastUsedAt = delegation.lastUsedAt;
    if (delegation.confirm?.length) result.confirm = [...delegation.confirm];
    if (delegation.handoff)
      result.handoff = {
        depth: delegation.handoff.depth,
        ...(delegation.handoff.agents ? { agents: [...delegation.handoff.agents] } : {}),
      };
    if (delegation.parentId !== undefined) result.parentId = delegation.parentId;
    const spent = await delegationSpendStanding(tx, delegation, now);
    if (delegation.spend && spent)
      result.spend = {
        period: delegation.spend.period,
        ...(delegation.spend.maxTokens !== undefined
          ? { maxTokens: delegation.spend.maxTokens }
          : {}),
        ...(delegation.spend.maxCostMicros !== undefined
          ? { maxCostUsd: delegation.spend.maxCostMicros / 1_000_000 }
          : {}),
        ...(delegation.spend.maxRequests !== undefined
          ? { maxRequests: delegation.spend.maxRequests }
          : {}),
        usedTokens: spent.usedTokens,
        usedCostUsd: spent.usedCostMicros / 1_000_000,
        usedRequests: spent.usedRequests,
        resetsAt: spent.resetsAt,
      };
    if (delegation.chain?.length)
      result.chain = await Promise.all(
        delegation.chain.map(async (agentId) => ({
          id: agentId,
          name: (await tx.get<Identity>('identities', agentId))?.name ?? agentId,
        })),
      );
    return result;
  }

  /** The live (pending or active) delegation between an agent and a person, if any. */
  async function liveBetween(
    tx: IamStore,
    tenantId: string,
    agentId: string,
    subjectId: string,
  ): Promise<Delegation | undefined> {
    const now = ctx.now();
    // Hand-offs from other agents do not count: they are part of another delegation.
    return (await tx.find<Delegation>('delegations', { tenantId, agentId, subjectId })).find(
      (item) =>
        item.parentId === undefined && (delegationLive(item, now) || delegationPending(item, now)),
    );
  }

  const sessionCap = (value: unknown) =>
    value === undefined
      ? undefined
      : integer(value, 'maxSessionSeconds', agentSessionSeconds.min, agentSessionSeconds.max);

  /**
   * Whether the principal is involved in the delegation: its person, its agent, the agent's sponsor, or (for a
   * hand-off) the agent that handed it on, acting under the delegation above.
   */
  async function involved(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    delegation: Delegation,
  ): Promise<'subject' | 'agent' | 'sponsor' | 'delegator' | undefined> {
    if (principal.session.impersonatorId) return undefined;
    // The agent acting under this very delegation (its delegated session) counts as the agent.
    if (
      principal.session.kind === 'delegated' &&
      principal.session.delegationId === delegation.id &&
      principal.session.tenantId === delegation.tenantId
    )
      return 'agent';
    if (
      principal.session.kind === 'delegated' &&
      delegation.parentId !== undefined &&
      principal.session.delegationId === delegation.parentId &&
      principal.session.tenantId === delegation.tenantId
    )
      return 'delegator';
    if (!actsInOwnRight(principal.session)) return undefined;
    if (principal.session.tenantId !== delegation.tenantId) return undefined;
    if (principal.identity.id === delegation.subjectId && principal.identity.kind === 'user')
      return 'subject';
    if (principal.identity.id === delegation.agentId && principal.identity.kind === 'agent')
      return 'agent';
    if (principal.identity.kind === 'user') {
      const agent = await tx.get<Identity>('identities', delegation.agentId);
      if (agent?.agent?.sponsorId === principal.identity.id) return 'sponsor';
    }
    return undefined;
  }

  /** Runs `fn` when the caller is involved in the delegation, else as an operation needing `action`. */
  async function involvedOr<T>(
    credential: CredentialInput,
    input: { tenantId: string; delegationId: string },
    action: string,
    fn: (tx: IamStore, principal: AuthenticatedPrincipal, delegation: Delegation) => Promise<T>,
  ): Promise<T> {
    const tenantId = text(input.tenantId, 'tenantId');
    const delegationId = text(input.delegationId, 'delegationId');
    const authenticated = await ctx.principals.authenticate(credential);
    const own = await store.transaction(async (tx) => {
      const principal = await ctx.principals.currentPrincipal(tx, authenticated);
      const delegation = await tx.get<Delegation>('delegations', delegationId);
      if (!delegation || delegation.tenantId !== tenantId) return undefined;
      if (!(await involved(tx, principal, delegation))) return undefined;
      return { value: await fn(tx, principal, delegation) };
    });
    if (own) return own.value;
    return operation(credential, tenantId, action, delegationId, async ({ tx, principal }) =>
      fn(tx, principal, await ctx.scoped<Delegation>(tx, 'delegations', delegationId, tenantId)),
    );
  }

  /** Revokes a pending or active delegation, ending its sessions; audited as `delegation:revoke`. */
  async function revokeDelegation(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    delegation: Delegation,
    reason: string | undefined,
  ): Promise<DelegationSummary> {
    if (delegation.status !== 'active' && delegation.status !== 'pending')
      throw new IamError(
        'INVALID_TRANSITION',
        `The delegation is already ${delegation.status}`,
        409,
      );
    const now = ctx.now();
    // An agent revoking in a delegated session (its own hand-off, or one it handed on) is the one who revoked.
    const revokedBy =
      principal.session.kind === 'delegated' && typeof principal.session.agentId === 'string'
        ? principal.session.agentId
        : principal.identity.id;
    const revoked = await tx.put<Delegation>('delegations', {
      ...delegation,
      status: 'revoked',
      revokedAt: now,
      revokedBy,
      sessionsRevokedBefore: nextWatermark(delegation.sessionsRevokedBefore, undefined, now),
    });
    const ended = await deleteDelegatedSessions(tx, { delegationId: delegation.id });
    const handoffs = await revokeHandoffsBelow(tx, delegation, revokedBy, now);
    await ctx.events.audit(
      tx,
      principal,
      'delegation:revoke',
      delegation.tenantId,
      delegation.id,
      'allow',
      false,
      {
        agentId: delegation.agentId,
        subjectId: delegation.subjectId,
        sessionsEnded: ended,
        ...(handoffs ? { handoffsRevoked: handoffs } : {}),
        ...(reason ? { reason } : {}),
      },
    );
    return summary(tx, revoked);
  }

  async function confirmationSummary(
    tx: IamStore,
    confirmation: DelegationConfirmation,
  ): Promise<ConfirmationSummary> {
    const agent = await tx.get<Identity>('identities', confirmation.agentId);
    const result: ConfirmationSummary = {
      id: confirmation.id,
      tenantId: confirmation.tenantId,
      delegationId: confirmation.delegationId,
      agent: { id: confirmation.agentId, name: agent?.name ?? confirmation.agentId },
      subjectId: confirmation.subjectId,
      action: confirmation.action,
      resource: { type: confirmation.resourceType, id: confirmation.resourceId },
      status: confirmation.status,
      expired: confirmation.status !== 'rejected' && confirmation.expiresAt <= ctx.now(),
      createdAt: confirmation.createdAt,
      expiresAt: confirmation.expiresAt,
      validSeconds: confirmation.validSeconds,
    };
    if (confirmation.reason !== undefined) result.reason = confirmation.reason;
    if (confirmation.decidedAt !== undefined) result.decidedAt = confirmation.decidedAt;
    return result;
  }

  /**
   * Which confirmation requests a caller may see: a person's own session sees those addressed to them, an agent's own
   * key those it made, and a delegated session those of its delegation. Anyone else is refused.
   */
  function confirmationScope(
    principal: AuthenticatedPrincipal,
    tenantId: string,
  ): Record<string, string> {
    if (principal.session.tenantId !== tenantId || principal.session.impersonatorId)
      throw refuse('Confirmation requests are read by the person or the agent involved');
    if (
      principal.session.kind === 'delegated' &&
      typeof principal.session.delegationId === 'string'
    )
      return { delegationId: principal.session.delegationId };
    if (principal.identity.kind === 'agent' && principal.session.kind === 'api-key')
      return { agentId: principal.identity.id };
    if (principal.identity.kind === 'user' && principal.session.kind === 'user')
      return { subjectId: principal.identity.id };
    throw refuse('Confirmation requests are read by the person or the agent involved');
  }

  /** Issues a delegated session (see `assume`). */
  async function assumeDelegation(
    credential: CredentialInput,
    input: {
      tenantId: string;
      delegationId: string;
      durationSeconds?: number;
      sessionName?: string;
      policy?: PolicyDocument;
    },
  ): Promise<DelegatedCredential> {
    const tenantId = text(input.tenantId, 'tenantId');
    const delegationId = text(input.delegationId, 'delegationId');
    const sessionName = sessionNameValue(input.sessionName);
    if (input.policy !== undefined) object(input.policy);
    const authenticated = await ctx.principals.authenticate(credential);
    return store.transaction(async (tx) => {
      const principal = await ctx.principals.currentPrincipal(tx, authenticated);
      assertAgentKey(principal, tenantId);
      const agent = principal.identity;
      const delegation = await tx.get<Delegation>('delegations', delegationId);
      const now = ctx.now();
      if (!delegation || delegation.tenantId !== tenantId || delegation.agentId !== agent.id)
        throw new IamError('NOT_FOUND', 'Delegation not found', 404);
      if (delegation.status === 'pending' && delegation.expiresAt > now)
        throw new IamError(
          'DELEGATION_PENDING',
          'The person has not approved this delegation yet',
          409,
        );
      if (!delegationLive(delegation, now))
        throw new IamError('DELEGATION_INACTIVE', 'This delegation is no longer active', 403);
      // A hand-off can be used only while every delegation, agent and key above it still can.
      if (delegation.parentId !== undefined && !(await liveAncestors(ctx, tx, delegation, now)))
        throw new IamError('DELEGATION_INACTIVE', 'A delegation above this one has ended', 403);
      if (agent.agent?.delegable === false)
        throw new IamError('DELEGATION_NOT_ALLOWED', 'This agent does not accept delegation', 403);
      const subject = await tx.get<Identity>('identities', delegation.subjectId);
      if (
        !subject ||
        subject.kind !== 'user' ||
        subject.tenantId !== tenantId ||
        subject.status !== 'active' ||
        ctx.identityExpired(subject)
      )
        throw new IamError(
          'DELEGATION_INACTIVE',
          'The person behind this delegation is not active',
          403,
        );
      if (input.policy !== undefined) await ctx.catalog.validate(tx, tenantId, input.policy);
      const max = Math.min(
        agent.agent?.maxDelegatedSessionSeconds ?? agentSessionSeconds.fallback,
        delegation.maxSessionSeconds ?? agentSessionSeconds.max,
      );
      const durationSeconds =
        input.durationSeconds === undefined
          ? Math.min(900, max)
          : integer(input.durationSeconds, 'durationSeconds', agentSessionSeconds.min, max);
      // Dead sessions of the delegation are deleted here, so the cap bounds the stored rows too.
      let live = 0;
      for (const session of await tx.find<Session>('sessions', {
        kind: 'delegated',
        delegationId,
      })) {
        if (session.expiresAt <= now) await tx.delete('sessions', session.id);
        else live++;
      }
      if (live >= maxSessionsPerDelegation)
        throw new IamError(
          'LIMIT_EXCEEDED',
          'This delegation holds the maximum number of live sessions',
          409,
        );
      const token = newCredentialToken('dlg');
      const row: Session = {
        id: id(),
        tenantId,
        identityId: subject.id,
        kind: 'delegated',
        agentId: agent.id,
        delegationId: delegation.id,
        sourceSessionId: principal.session.id,
        tokenHash: hash(token),
        uniqueKey: hash(token),
        createdAt: now,
        lastSeenAt: now,
        // The person last authenticated for this when they decided on the delegation.
        authenticatedAt: delegation.decidedAt ?? delegation.createdAt,
        expiresAt: Math.min(
          now + durationSeconds * 1000,
          delegation.expiresAt,
          principal.session.expiresAt,
        ),
        mfa: false,
      };
      if (input.policy !== undefined) row.policy = input.policy;
      // The agent key's own limits carry over: its scopes (or session policy) and its issuer's authority bound the
      // delegated session too, as they bound session tokens minted from a key.
      if (principal.session.policy) row.sourcePolicy = principal.session.policy;
      if (typeof principal.session.credentialAuthorityId === 'string')
        row.credentialAuthorityId = principal.session.credentialAuthorityId;
      if (sessionName !== undefined) row.sessionName = sessionName;
      const client = auth.currentClient();
      if (client && Object.keys(client).length) row.client = { ...client };
      const session = await tx.insert<Session>('sessions', row);
      await tx.put<Delegation>('delegations', { ...delegation, lastUsedAt: now });
      await ctx.events.audit(
        tx,
        principal,
        'delegation:assume',
        tenantId,
        delegation.id,
        'allow',
        false,
        { subjectId: subject.id, sessionId: session.id, durationSeconds },
      );
      const result: DelegatedCredential = {
        token,
        tokenType: 'Bearer',
        expiresAt: session.expiresAt,
        expiresIn: Math.max(0, Math.floor((session.expiresAt - now) / 1000)),
        session: {
          id: session.id,
          kind: 'delegated',
          tenantId,
          identityId: subject.id,
          agentId: agent.id,
          delegationId: delegation.id,
        },
      };
      if (sessionName !== undefined) result.session.sessionName = sessionName;
      return result;
    });
  }

  return {
    /**
     * A person lets an agent act for them: `scopes` (actions, wildcards allowed) or a `policy` bound what the agent may
     * do, and it can never do more than the person could. Lasts `expiresInSeconds` (5 minutes to a year; 30 days by
     * default); `maxSessionSeconds` caps each delegated session below the agent's own limit. Needs the person's own
     * session with a recent sign-in; refused while an undecided request or an active delegation already links the two.
     * Audited as `delegation:grant`.
     */
    grant: async (
      credential: CredentialInput,
      input: DelegationScopeInput & {
        tenantId: string;
        agentId: string;
        expiresInSeconds?: number;
        maxSessionSeconds?: number;
      },
    ): Promise<DelegationSummary> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const seconds = delegationSeconds(input.expiresInSeconds);
      const maxSessionSeconds = sessionCap(input.maxSessionSeconds);
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        assertPerson(principal, tenantId);
        auth.requireRecent(principal);
        const agent = await delegableAgent(tx, input.agentId, tenantId);
        const existing = await liveBetween(tx, tenantId, agent.id, principal.identity.id);
        if (existing)
          throw new IamError(
            'DELEGATION_EXISTS',
            existing.status === 'pending'
              ? 'This agent is waiting for your decision on a request; approve or deny it'
              : 'You already delegate to this agent; revoke that delegation first',
            409,
          );
        const scope = await delegationScope(ctx, tx, tenantId, input);
        const now = ctx.now();
        const delegation: Delegation = {
          id: id(),
          tenantId,
          agentId: agent.id,
          subjectId: principal.identity.id,
          status: 'active',
          policy: scope.policy,
          requestedBy: 'subject',
          createdAt: now,
          decidedAt: now,
          expiresAt: now + seconds * 1000,
        };
        if (scope.scopes) delegation.scopes = scope.scopes;
        if (maxSessionSeconds !== undefined) delegation.maxSessionSeconds = maxSessionSeconds;
        const confirm = confirmPatterns(input.confirm);
        if (confirm) delegation.confirm = confirm;
        const handoff = await handoffSetting(tx, tenantId, input.handoff);
        if (handoff) delegation.handoff = handoff;
        const spend = spendSetting(input.spend);
        if (spend) delegation.spend = spend;
        await tx.insert<Delegation>('delegations', delegation);
        await ctx.events.audit(
          tx,
          principal,
          'delegation:grant',
          tenantId,
          delegation.id,
          'allow',
          false,
          {
            agentId: agent.id,
            expiresAt: delegation.expiresAt,
            ...(scope.scopes ? { scopes: scope.scopes.join(' ') } : {}),
          },
        );
        return summary(tx, delegation);
      });
    },

    /**
     * An agent asks a person (`subjectId`, or `subjectEmail`) to delegate to it: the request waits up to seven days
     * for their decision and is emailed to them (template `delegation-request`) when the deployment sends email.
     * `reason` is shown to the person; `expiresInSeconds` is how long the delegation lasts once approved. Needs the
     * agent's own API key. Requests are rate limited per agent. Audited as `delegation:request`.
     */
    request: async (
      credential: CredentialInput,
      input: DelegationScopeInput & {
        tenantId: string;
        subjectId?: string;
        subjectEmail?: string;
        reason: string;
        expiresInSeconds?: number;
        maxSessionSeconds?: number;
      },
    ): Promise<DelegationSummary> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const reason = text(input.reason, 'reason', 1024);
      const seconds = delegationSeconds(input.expiresInSeconds);
      const maxSessionSeconds = sessionCap(input.maxSessionSeconds);
      if ((input.subjectId === undefined) === (input.subjectEmail === undefined))
        throw new IamError('INVALID_INPUT', 'Provide either subjectId or subjectEmail');
      const authenticated = await ctx.principals.authenticate(credential);
      assertAgentKey(authenticated, tenantId);
      // Counted outside any transaction, so a refused request cannot roll the attempt back.
      await auth.limitAttempt(tenantId, `delegation-request:${authenticated.identity.id}`, {
        tier: 'sensitive',
      });
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        assertAgentKey(principal, tenantId);
        const agent = await delegableAgent(tx, principal.identity.id, tenantId);
        let subject: Identity | undefined;
        if (input.subjectId !== undefined)
          subject = await tx.get<Identity>('identities', text(input.subjectId, 'subjectId'));
        else {
          const address = email(input.subjectEmail);
          subject = (await tx.find<Identity>('identities', { tenantId, email: address }))[0];
        }
        if (
          !subject ||
          subject.tenantId !== tenantId ||
          subject.kind !== 'user' ||
          subject.status !== 'active' ||
          ctx.identityExpired(subject)
        )
          throw new IamError('NOT_FOUND', 'No active person with that identifier', 404);
        if (await liveBetween(tx, tenantId, agent.id, subject.id))
          throw new IamError(
            'DELEGATION_EXISTS',
            'A request or delegation between this agent and person already exists',
            409,
          );
        const scope = await delegationScope(ctx, tx, tenantId, input);
        const now = ctx.now();
        const delegation: Delegation = {
          id: id(),
          tenantId,
          agentId: agent.id,
          subjectId: subject.id,
          status: 'pending',
          policy: scope.policy,
          requestedBy: 'agent',
          reason,
          createdAt: now,
          expiresAt: now + delegationLifetime.requestMs,
          lifetimeMs: seconds * 1000,
        };
        if (scope.scopes) delegation.scopes = scope.scopes;
        if (maxSessionSeconds !== undefined) delegation.maxSessionSeconds = maxSessionSeconds;
        const confirm = confirmPatterns(input.confirm);
        if (confirm) delegation.confirm = confirm;
        const handoff = await handoffSetting(tx, tenantId, input.handoff);
        if (handoff) delegation.handoff = handoff;
        const spend = spendSetting(input.spend);
        if (spend) delegation.spend = spend;
        await tx.insert<Delegation>('delegations', delegation);
        if (subject.email && ctx.options.authentication?.sendEmail)
          await auth.enqueueDelivery(tx, {
            tenantId,
            kind: 'email',
            to: subject.email,
            template: 'delegation-request',
            payload: {
              delegationId: delegation.id,
              agentName: agent.name,
              reason,
              scopes: scope.scopes?.join(', ') ?? 'a custom policy',
              days: String(Math.max(1, Math.round(seconds / 86_400))),
              ...(agent.agent?.model ? { model: agent.agent.model } : {}),
            },
          });
        await ctx.events.audit(
          tx,
          principal,
          'delegation:request',
          tenantId,
          delegation.id,
          'allow',
          false,
          { subjectId: subject.id, ...(scope.scopes ? { scopes: scope.scopes.join(' ') } : {}) },
        );
        return summary(tx, delegation);
      });
    },

    /**
     * The person approves an agent's request, optionally narrowing (or replacing) its scope with `scopes`/`policy`,
     * choosing another `expiresInSeconds`, or capping `maxSessionSeconds`. Needs their own session with a recent
     * sign-in. Audited as `delegation:approve`.
     */
    approve: async (
      credential: CredentialInput,
      input: DelegationScopeInput & {
        tenantId: string;
        delegationId: string;
        expiresInSeconds?: number;
        maxSessionSeconds?: number;
      },
    ): Promise<DelegationSummary> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const delegationId = text(input.delegationId, 'delegationId');
      const maxSessionSeconds = sessionCap(input.maxSessionSeconds);
      const seconds =
        input.expiresInSeconds === undefined
          ? undefined
          : delegationSeconds(input.expiresInSeconds);
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        assertPerson(principal, tenantId);
        auth.requireRecent(principal);
        const delegation = await tx.get<Delegation>('delegations', delegationId);
        if (
          !delegation ||
          delegation.tenantId !== tenantId ||
          delegation.subjectId !== principal.identity.id
        )
          throw new IamError('NOT_FOUND', 'Delegation not found', 404);
        const now = ctx.now();
        if (!delegationPending(delegation, now))
          throw new IamError('INVALID_TRANSITION', 'Only a pending request can be approved', 409);
        await delegableAgent(tx, delegation.agentId, tenantId);
        const next: Delegation = { ...delegation, status: 'active', decidedAt: now };
        if (input.scopes !== undefined || input.policy !== undefined) {
          const scope = await delegationScope(ctx, tx, tenantId, input);
          next.policy = scope.policy;
          if (scope.scopes) next.scopes = scope.scopes;
          else delete next.scopes;
        }
        next.expiresAt =
          now +
          (seconds !== undefined
            ? seconds * 1000
            : (delegation.lifetimeMs ?? delegationLifetime.fallbackSeconds * 1000));
        delete next.lifetimeMs;
        if (maxSessionSeconds !== undefined) next.maxSessionSeconds = maxSessionSeconds;
        // The person may add (or drop, with an empty list) actions to confirm one call at a time.
        if (input.confirm !== undefined) {
          const confirm = confirmPatterns(input.confirm);
          if (confirm) next.confirm = confirm;
          else delete next.confirm;
        }
        // Hand-offs widen what happens in the person's name, so an agent's request for them counts only when the person
        // states it themselves here: a plain approval leaves them out.
        const handoff = await handoffSetting(tx, tenantId, input.handoff);
        if (handoff) next.handoff = handoff;
        else delete next.handoff;
        // And set, change, or (with null) remove a spending cap.
        if (input.spend !== undefined) {
          const spend = spendSetting(input.spend);
          if (spend) next.spend = spend;
          else delete next.spend;
        }
        const approved = await tx.put<Delegation>('delegations', next);
        await ctx.events.audit(
          tx,
          principal,
          'delegation:approve',
          tenantId,
          delegation.id,
          'allow',
          false,
          {
            agentId: delegation.agentId,
            expiresAt: approved.expiresAt,
          },
        );
        return summary(tx, approved);
      });
    },

    /** The person turns an agent's request down. Audited as `delegation:deny`. */
    deny: async (
      credential: CredentialInput,
      input: { tenantId: string; delegationId: string },
    ): Promise<DelegationSummary> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const delegationId = text(input.delegationId, 'delegationId');
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        assertPerson(principal, tenantId);
        const delegation = await tx.get<Delegation>('delegations', delegationId);
        if (
          !delegation ||
          delegation.tenantId !== tenantId ||
          delegation.subjectId !== principal.identity.id
        )
          throw new IamError('NOT_FOUND', 'Delegation not found', 404);
        if (!delegationPending(delegation, ctx.now()))
          throw new IamError('INVALID_TRANSITION', 'Only a pending request can be denied', 409);
        const denied = await tx.put<Delegation>('delegations', {
          ...delegation,
          status: 'denied',
          decidedAt: ctx.now(),
        });
        await ctx.events.audit(
          tx,
          principal,
          'delegation:deny',
          tenantId,
          delegation.id,
          'allow',
          false,
          {
            agentId: delegation.agentId,
          },
        );
        return summary(tx, denied);
      });
    },

    /**
     * Ends a pending or active delegation and its live sessions at once. The person, the agent (with its own key), the
     * agent's sponsor or an administrator with `iam:delegations:revoke` may revoke. Audited as `delegation:revoke`.
     */
    revoke: (
      credential: CredentialInput,
      input: { tenantId: string; delegationId: string; reason?: string },
    ): Promise<DelegationSummary> => {
      const reason = input.reason !== undefined ? text(input.reason, 'reason', 512) : undefined;
      return involvedOr(credential, input, 'iam:delegations:revoke', (tx, principal, delegation) =>
        revokeDelegation(tx, principal, delegation, reason),
      );
    },

    /**
     * One delegation, for the person, the agent (agents poll this while a request is pending), the agent's sponsor, or
     * an administrator with `iam:delegations:read`.
     */
    get: (credential: CredentialInput, input: { tenantId: string; delegationId: string }) =>
      involvedOr(credential, input, 'iam:delegations:read', (tx, _principal, delegation) =>
        summary(tx, delegation),
      ),

    /**
     * What happened under a delegation, newest first: its lifecycle (grant, request, approval, sessions opened,
     * revocation) and every audit event of the agent's sessions acting for the person, allowed and denied. For the
     * person, the agent, the agent's sponsor, or an administrator with `iam:delegations:read`.
     */
    activity: (
      credential: CredentialInput,
      input: ActivityQuery & { tenantId: string; delegationId: string },
    ): Promise<AuditEvent[]> =>
      involvedOr(credential, input, 'iam:delegations:read', async (tx, _principal, delegation) => {
        // Work handed on to other agents belongs to this delegation's story too.
        const ids = new Set([delegation.id]);
        const pending = [delegation.id];
        while (pending.length && ids.size <= 1000)
          for (const child of await tx.find<Delegation>('delegations', {
            tenantId: delegation.tenantId,
            parentId: pending.pop()!,
          }))
            if (!ids.has(child.id)) {
              ids.add(child.id);
              pending.push(child.id);
            }
        return auditActivity(
          tx,
          delegation.tenantId,
          input,
          (event) =>
            ids.has(event.resourceId ?? '') ||
            (typeof event.sessionContext?.delegationId === 'string' &&
              ids.has(event.sessionContext.delegationId)),
        );
      }),

    /** The tenant's delegations, newest first, filtered by agent, person or status. Needs `iam:delegations:read`. */
    list: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        agentId?: string;
        subjectId?: string;
        status?: Delegation['status'];
      },
    ): Promise<DelegationSummary[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:delegations:read',
        input.tenantId,
        async ({ tx }) => {
          const filter: Record<string, unknown> = { tenantId: input.tenantId };
          if (input.agentId !== undefined) filter.agentId = text(input.agentId, 'agentId');
          if (input.subjectId !== undefined) filter.subjectId = text(input.subjectId, 'subjectId');
          if (input.status !== undefined) filter.status = text(input.status, 'status', 16);
          const found = (await tx.find<Delegation>('delegations', filter)).sort(byNewest);
          return Promise.all(found.map((delegation) => summary(tx, delegation)));
        },
      ),

    /**
     * The caller's own delegations, newest first: for a person, the agents acting (or asking to act) for them; for an
     * agent with its own key, the people it acts for. Needs no permission.
     */
    listMine: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<DelegationSummary[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const filter: Record<string, unknown> = { tenantId };
        if (principal.identity.kind === 'agent') {
          assertAgentKey(principal, tenantId);
          filter.agentId = principal.identity.id;
        } else {
          assertPerson(principal, tenantId);
          filter.subjectId = principal.identity.id;
        }
        const found = (await tx.find<Delegation>('delegations', filter)).sort(byNewest);
        return Promise.all(found.map((delegation) => summary(tx, delegation)));
      });
    },

    /**
     * The agent opens a delegated session (a `biam_dlg_…` bearer token) to act for the person: the token's identity is
     * the person, bounded by the delegation's scope, the agent's ceiling and an optional scope-down `policy`. Lasts
     * `durationSeconds` (60 up to the agent's `maxDelegatedSessionSeconds` and the delegation's `maxSessionSeconds`;
     * 900 or less by default), never past the delegation or the agent's key. Needs the agent's own API key; at most 20
     * live sessions per delegation. Audited as `delegation:assume`.
     */
    assume: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        delegationId: string;
        durationSeconds?: number;
        sessionName?: string;
        policy?: PolicyDocument;
      },
    ): Promise<DelegatedCredential> =>
      !auth.currentClient() && credential?.headers
        ? auth.withClient(
            clientFromHeaders(ctx.options, credential.headers, ctx.config.baseURL),
            () => assumeDelegation(credential, input),
          )
        : assumeDelegation(credential, input),

    /**
     * An agent acting for a person hands part of that work on to another agent (for example one it calls over A2A): a
     * new delegation from the same person to `agentId`, within `scopes`/`policy`. Needs a delegated session whose
     * delegation lets the agent hand on (`handoff`, set by the person) to that agent. The hand-off never allows more
     * than the delegations above it, the ceilings of the agents that handed it on, and the limits of the handing session
     * (its scope-down policy, its key's scopes and issuer), and it works only while every delegation above it does. It
     * keeps the person's `confirm` list (plus any given here) and lasts `expiresInSeconds` (60 seconds up to the
     * delegation above; one hour by default). The other agent opens sessions with its own key (`assume`). No agent may
     * appear twice in a chain; at most 20 live hand-offs per delegation. Audited as `delegation:handoff`.
     */
    handoff: async (
      credential: CredentialInput,
      input: Omit<DelegationScopeInput, 'handoff'> & {
        tenantId: string;
        agentId: string;
        expiresInSeconds?: number;
        maxSessionSeconds?: number;
        reason?: string;
      },
    ): Promise<DelegationSummary> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const reason = input.reason !== undefined ? text(input.reason, 'reason', 1024) : undefined;
      const maxSessionSeconds = sessionCap(input.maxSessionSeconds);
      const seconds =
        input.expiresInSeconds === undefined
          ? 3600
          : integer(input.expiresInSeconds, 'expiresInSeconds', 60, delegationLifetime.maxSeconds);
      const extraConfirm = confirmPatterns(input.confirm) ?? [];
      const authenticated = await ctx.principals.authenticate(credential);
      // Counted outside the transaction (a refusal cannot roll it back), per delegation handing on.
      if (typeof authenticated.session.delegationId === 'string')
        await auth.limitAttempt(
          tenantId,
          `delegation-handoff:${authenticated.session.delegationId}`,
          { tier: 'sensitive' },
        );
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const session = principal.session;
        if (
          session.kind !== 'delegated' ||
          session.tenantId !== tenantId ||
          typeof session.delegationId !== 'string' ||
          typeof session.agentId !== 'string'
        )
          throw refuse('Only an agent acting for a person (a delegated session) can hand work on');
        const now = ctx.now();
        const parent = await tx.get<Delegation>('delegations', session.delegationId);
        if (
          !parent ||
          !delegationLive(parent, now) ||
          parent.tenantId !== tenantId ||
          parent.agentId !== session.agentId ||
          parent.subjectId !== principal.identity.id ||
          !(await liveAncestors(ctx, tx, parent, now))
        )
          throw new IamError('DELEGATION_INACTIVE', 'This delegation is no longer active', 403);
        const allowed = parent.handoff;
        if (!allowed || allowed.depth < 1)
          throw new IamError(
            'DELEGATION_NOT_ALLOWED',
            'The person did not allow this delegation to be handed on',
            403,
          );
        const chain = [...(parent.chain ?? []), parent.agentId];
        const target = await delegableAgent(tx, input.agentId, tenantId);
        if (chain.includes(target.id))
          throw new IamError(
            'DELEGATION_NOT_ALLOWED',
            'An agent cannot receive a hand-off from its own delegation chain',
            403,
          );
        if (allowed.agents && !allowed.agents.includes(target.id))
          throw new IamError(
            'DELEGATION_NOT_ALLOWED',
            'The person did not allow hand-offs to this agent',
            403,
          );
        const live = (
          await tx.find<Delegation>('delegations', { tenantId, parentId: parent.id })
        ).filter((item) => delegationLive(item, now)).length;
        if (live >= handoffLimits.maxLive)
          throw new IamError(
            'LIMIT_EXCEEDED',
            'This delegation holds the maximum number of live hand-offs',
            409,
          );
        const scope = await delegationScope(ctx, tx, tenantId, input);
        // The key the handing agent acts with: the hand-off never outlives it, and ends when it is revoked.
        const key =
          typeof session.sourceSessionId === 'string'
            ? await tx.get<Session>('sessions', session.sourceSessionId)
            : undefined;
        if (!key || key.kind !== 'api-key' || key.identityId !== parent.agentId)
          throw new IamError('DELEGATION_INACTIVE', 'This delegation is no longer active', 403);
        const delegation: Delegation = {
          id: id(),
          tenantId,
          agentId: target.id,
          subjectId: parent.subjectId,
          status: 'active',
          policy: scope.policy,
          requestedBy: 'handoff',
          createdAt: now,
          decidedAt: now,
          expiresAt: Math.min(now + seconds * 1000, parent.expiresAt, key.expiresAt),
          parentId: parent.id,
          chain,
          keyId: key.id,
        };
        if (scope.scopes) delegation.scopes = scope.scopes;
        if (reason !== undefined) delegation.reason = reason;
        const cap = [maxSessionSeconds, parent.maxSessionSeconds].filter(
          (value): value is number => value !== undefined,
        );
        if (cap.length) delegation.maxSessionSeconds = Math.min(...cap);
        const confirm = confirmPatterns([...(parent.confirm ?? []), ...extraConfirm]);
        if (confirm) delegation.confirm = confirm;
        if (allowed.depth > 1)
          delegation.handoff = {
            depth: allowed.depth - 1,
            ...(allowed.agents ? { agents: [...allowed.agents] } : {}),
          };
        // The handing session's own limits travel with the hand-off.
        const ceilings = [session.policy, session.sourcePolicy].filter(
          (policy): policy is PolicyDocument => !!policy,
        );
        if (ceilings.length) delegation.ceilings = ceilings;
        if (typeof session.credentialAuthorityId === 'string')
          delegation.authorityId = session.credentialAuthorityId;
        // A cap of its own, on top of the caps of the delegations above (which count the hand-off's calls too).
        const spend = spendSetting(input.spend);
        if (spend) delegation.spend = spend;
        await tx.insert<Delegation>('delegations', delegation);
        await ctx.events.audit(
          tx,
          principal,
          'delegation:handoff',
          tenantId,
          delegation.id,
          'allow',
          false,
          {
            parentId: parent.id,
            fromAgentId: parent.agentId,
            toAgentId: target.id,
            depth: chain.length,
            ...(scope.scopes ? { scopes: scope.scopes.join(' ') } : {}),
          },
        );
        return summary(tx, delegation);
      });
    },

    /**
     * An agent acting for a person (its delegated session) gets a delegation token to show a service outside Better IAM
     * that it acts for that person: a JWT signed with the deployment's `a2a` keys (`typ` `biam-delegation+jwt`) whose
     * `sub` is the person and whose `act` claim is the agent, with the agents that handed the work to it nested inside
     * (RFC 8693). `audience` must be one service that every agent in the chain lists in its `tokenAudiences`. `scopes`
     * (the delegation's own by default) must each be allowed outright by every limit on the session: the delegation and
     * those above it, the agents' ceilings, the session's scope-down policy, its key's scopes and issuer, and the
     * person's and tenant's boundaries. None may be an action the person confirms call by call, or one a deny among the
     * person's own grants could touch. Lasts `lifetimeSeconds` (30 to 3600; 300 by default), never past the session or
     * a delegation in the chain. Needs the `a2a` option. Rate limited per delegation. Audited as `delegation:token-issue`.
     */
    issueToken: async (
      credential: CredentialInput,
      input: { tenantId: string; audience: string; scopes?: string[]; lifetimeSeconds?: number },
    ): Promise<DelegationToken> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const audience = tokenAudience(input.audience);
      const requested =
        input.scopes === undefined ? undefined : [...new Set(strings(input.scopes, 'scopes'))];
      const lifetime =
        input.lifetimeSeconds === undefined
          ? delegationTokenLimits.defaultSeconds
          : integer(
              input.lifetimeSeconds,
              'lifetimeSeconds',
              delegationTokenLimits.minSeconds,
              delegationTokenLimits.maxSeconds,
            );
      const signer = cardSigner(ctx);
      if (!signer)
        throw new IamError(
          'FEATURE_DISABLED',
          'Delegation tokens need the deployment’s a2a signing keys',
          403,
        );
      const authenticated = await ctx.principals.authenticate(credential);
      // Counted outside the transaction, per delegation, in a budget of its own.
      if (typeof authenticated.session.delegationId === 'string')
        await auth.limitAttempt(
          tenantId,
          `delegation-token:${authenticated.session.delegationId}`,
          { limit: 120 },
        );
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const session = principal.session;
        if (
          session.kind !== 'delegated' ||
          session.tenantId !== tenantId ||
          typeof session.delegationId !== 'string' ||
          typeof session.agentId !== 'string'
        )
          throw refuse(
            'Only an agent acting for a person (a delegated session) gets delegation tokens',
          );
        const now = ctx.now();
        const inactive = () =>
          new IamError('DELEGATION_INACTIVE', 'This delegation is no longer active', 403);
        const delegation = await tx.get<Delegation>('delegations', session.delegationId);
        const ancestors = delegation ? await liveAncestors(ctx, tx, delegation, now) : undefined;
        const agent = await tx.get<Identity>('identities', session.agentId);
        const tenant = await tx.get<Tenant>('tenants', tenantId);
        // The agent's API key the session came from: the token is live only while it is.
        const key =
          typeof session.sourceSessionId === 'string'
            ? await tx.get<Session>('sessions', session.sourceSessionId)
            : undefined;
        if (
          !delegation ||
          !ancestors ||
          !agent ||
          !tenant ||
          !key ||
          key.kind !== 'api-key' ||
          key.identityId !== session.agentId ||
          !delegationLive(delegation, now) ||
          delegation.tenantId !== tenantId ||
          delegation.agentId !== agent.id ||
          delegation.subjectId !== principal.identity.id
        )
          throw inactive();
        // Every agent the work passed through must be allowed to present it to this service.
        const agents = [...ancestors.map((ancestor) => ancestor.agent).reverse(), agent];
        const outsider = audienceRefusal(agents, audience);
        if (outsider)
          throw new IamError(
            'DELEGATION_NOT_ALLOWED',
            `Agent ${outsider.name} may not present delegations to ${audience}`,
            403,
          );
        const scopes = requested ?? delegation.scopes ?? [];
        if (scopes.length > 50 || scopes.some((scope) => !tokenScopePattern.test(scope)))
          throw new IamError(
            'INVALID_INPUT',
            'scopes must list at most 50 actions or action patterns (letters, digits, :_./- and *)',
          );
        const sessionPolicies = [session.policy, session.sourcePolicy].filter(
          (policy): policy is PolicyDocument => !!policy,
        );
        const authorityId =
          typeof session.credentialAuthorityId === 'string'
            ? session.credentialAuthorityId
            : undefined;
        const refusal = await scopeRefusal(
          ctx,
          tx,
          {
            tenant,
            personId: principal.identity.id,
            delegation,
            ancestors,
            agents,
            sessionPolicies,
            authorityIds: authorityId ? [authorityId] : [],
          },
          scopes,
        );
        if (refusal && 'inactive' in refusal) throw inactive();
        if (refusal)
          throw new IamError(
            'DELEGATION_NOT_ALLOWED',
            refusal.why === 'confirm'
              ? `The person confirms ${refusal.scope} call by call; a token cannot carry it`
              : refusal.why === 'deny'
                ? `A deny statement of the person's own access may touch ${refusal.scope}`
                : `The delegation does not allow ${refusal.scope} outright`,
            403,
          );
        const issuedAt = Math.floor(now / 1000);
        const expiresAt = Math.min(
          issuedAt + lifetime,
          ...[session, delegation, ...ancestors.map((ancestor) => ancestor.delegation)].map(
            (item) => Math.floor(item.expiresAt / 1000),
          ),
        );
        if (expiresAt <= issuedAt) throw inactive();
        const chain = agents.map((item) => item.id);
        const claims: DelegationTokenClaims = {
          iss: signer.issuer,
          sub: principal.identity.id,
          aud: audience,
          iat: issuedAt,
          nbf: issuedAt,
          exp: expiresAt,
          jti: randomToken(),
          tenant_id: tenantId,
          delegation_id: delegation.id,
          act: delegationActor(chain),
          ...(scopes.length ? { scope: scopes.join(' ') } : {}),
        };
        const token = await signer.signJwt({ ...claims }, delegationTokenType);
        // Kept until it expires, so a live verification can re-check what the token stands on.
        await tx.insert<DelegationTokenRecord>('delegationTokens', {
          id: claims.jti,
          tenantId,
          delegationId: delegation.id,
          personId: principal.identity.id,
          agentId: agent.id,
          keyId: key.id,
          audience,
          scopes: [...scopes],
          sessionPolicies,
          ...(authorityId ? { authorityId } : {}),
          createdAt: now,
          expiresAt: expiresAt * 1000,
        });
        await ctx.events.audit(
          tx,
          principal,
          'delegation:token-issue',
          tenantId,
          delegation.id,
          'allow',
          false,
          {
            audience: audience,
            tokenId: claims.jti,
            expiresAt: expiresAt * 1000,
            ...(scopes.length ? { scopes: scopes.join(' ') } : {}),
          },
        );
        return {
          token,
          tokenType: delegationTokenType,
          tokenId: claims.jti,
          issuer: signer.issuer,
          audience: audience,
          scopes: [...scopes],
          chain,
          expiresAt: expiresAt * 1000,
          expiresIn: expiresAt - issuedAt,
        };
      });
    },

    /**
     * An agent acting for a person (with its delegated session) asks them to confirm one action the delegation holds
     * back (`confirm`): `action` on `resource`, with a `reason` shown to the person. The request waits up to 30 minutes
     * and is emailed to the person (template `delegation-confirmation`); an identical pending request is returned as
     * it is. Once approved, that action on that resource is allowed for `validSeconds` (30 to 3600; 300 by default).
     * Rate limited per delegation. Audited as `delegation:confirmation-request`.
     */
    requestConfirmation: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        action: string;
        resource: { type: string; id: string };
        reason: string;
        validSeconds?: number;
      },
    ): Promise<ConfirmationSummary> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const action = text(input.action, 'action', 256);
      const resource = object(input.resource);
      const resourceType = text(resource.type, 'resource type', 64);
      const resourceId = text(resource.id, 'resource id', 2048);
      const reason = text(input.reason, 'reason', 1024);
      const validSeconds =
        input.validSeconds === undefined
          ? confirmationLimits.fallbackValidSeconds
          : integer(
              input.validSeconds,
              'validSeconds',
              confirmationLimits.minValidSeconds,
              confirmationLimits.maxValidSeconds,
            );
      const authenticated = await ctx.principals.authenticate(credential);
      if (
        authenticated.session.kind !== 'delegated' ||
        authenticated.session.tenantId !== tenantId ||
        typeof authenticated.session.delegationId !== 'string'
      )
        throw refuse('Only an agent acting for a person can ask them to confirm an action');
      // Counted outside any transaction, so a refused request cannot roll the attempt back.
      await auth.limitAttempt(
        tenantId,
        `delegation-confirm:${authenticated.session.delegationId}`,
        {},
      );
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const delegation = await tx.get<Delegation>(
          'delegations',
          principal.session.delegationId as string,
        );
        if (!delegation) throw new IamError('UNAUTHENTICATED', 'Delegation revoked', 401);
        if (!needsConfirmation(delegation, action))
          throw new IamError(
            'INVALID_INPUT',
            'This delegation does not hold that action back for confirmation',
          );
        const now = ctx.now();
        const pending = (
          await tx.find<DelegationConfirmation>('delegationConfirmations', {
            tenantId,
            delegationId: delegation.id,
            status: 'pending',
          })
        ).find(
          (item) =>
            item.expiresAt > now &&
            item.action === action &&
            item.resourceType === resourceType &&
            item.resourceId === resourceId,
        );
        if (pending) return confirmationSummary(tx, pending);
        const confirmation: DelegationConfirmation = {
          id: id(),
          tenantId,
          delegationId: delegation.id,
          agentId: delegation.agentId,
          subjectId: delegation.subjectId,
          action,
          resourceType,
          resourceId,
          reason,
          status: 'pending',
          createdAt: now,
          expiresAt: now + confirmationLimits.decideMs,
          validSeconds,
        };
        await tx.insert<DelegationConfirmation>('delegationConfirmations', confirmation);
        const agent = await tx.get<Identity>('identities', delegation.agentId);
        if (principal.identity.email && ctx.options.authentication?.sendEmail)
          await auth.enqueueDelivery(tx, {
            tenantId,
            kind: 'email',
            to: principal.identity.email,
            template: 'delegation-confirmation',
            payload: {
              delegationId: delegation.id,
              confirmationId: confirmation.id,
              agentName: agent?.name ?? 'An AI agent',
              action,
              resource: `${resourceType}/${resourceId}`,
              reason,
              minutes: String(Math.round(confirmationLimits.decideMs / 60_000)),
            },
          });
        await ctx.events.audit(
          tx,
          principal,
          'delegation:confirmation-request',
          tenantId,
          delegation.id,
          'allow',
          false,
          { confirmationId: confirmation.id, action, resource: `${resourceType}/${resourceId}` },
        );
        return confirmationSummary(tx, confirmation);
      });
    },

    /**
     * The person approves (`approve: true`) or rejects an agent's pending confirmation request from their own session.
     * An approval allows exactly that action on that resource, for the agent acting for them, for the request's
     * `validSeconds`. Audited as `delegation:confirm` or `delegation:reject`.
     */
    decideConfirmation: async (
      credential: CredentialInput,
      input: { tenantId: string; confirmationId: string; approve: boolean },
    ): Promise<ConfirmationSummary> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const confirmationId = text(input.confirmationId, 'confirmationId');
      if (typeof input.approve !== 'boolean')
        throw new IamError('INVALID_INPUT', 'approve must be a boolean');
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        assertPerson(principal, tenantId);
        const confirmation = await tx.get<DelegationConfirmation>(
          'delegationConfirmations',
          confirmationId,
        );
        if (
          !confirmation ||
          confirmation.tenantId !== tenantId ||
          confirmation.subjectId !== principal.identity.id
        )
          throw new IamError('NOT_FOUND', 'Confirmation request not found', 404);
        const now = ctx.now();
        if (confirmation.status !== 'pending' || confirmation.expiresAt <= now)
          throw new IamError('INVALID_TRANSITION', 'Only a pending request can be decided', 409);
        const delegation = await tx.get<Delegation>('delegations', confirmation.delegationId);
        if (!delegation || !delegationLive(delegation, now))
          throw new IamError('DELEGATION_INACTIVE', 'This delegation is no longer active', 403);
        const decided = await tx.put<DelegationConfirmation>('delegationConfirmations', {
          ...confirmation,
          status: input.approve ? 'approved' : 'rejected',
          decidedAt: now,
          expiresAt: input.approve ? now + confirmation.validSeconds * 1000 : now,
        });
        await ctx.events.audit(
          tx,
          principal,
          input.approve ? 'delegation:confirm' : 'delegation:reject',
          tenantId,
          delegation.id,
          'allow',
          false,
          {
            confirmationId: confirmation.id,
            action: confirmation.action,
            resource: `${confirmation.resourceType}/${confirmation.resourceId}`,
          },
        );
        return confirmationSummary(tx, decided);
      });
    },

    /**
     * Confirmation requests, newest first: for a person, the ones addressed to them; for an agent's own key, every one
     * it made; for a delegated session, those of its delegation. `status` filters. Needs no permission.
     */
    listConfirmations: async (
      credential: CredentialInput,
      input: { tenantId: string; status?: DelegationConfirmation['status'] },
    ): Promise<ConfirmationSummary[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const filter: Record<string, unknown> = {
          tenantId,
          ...confirmationScope(principal, tenantId),
        };
        if (input.status !== undefined) filter.status = text(input.status, 'status', 16);
        const found = (
          await tx.find<DelegationConfirmation>('delegationConfirmations', filter)
        ).sort(byNewest);
        return Promise.all(found.map((item) => confirmationSummary(tx, item)));
      });
    },

    /** One confirmation request, for the person it asks or the agent that asked (agents poll it while it is pending). */
    getConfirmation: async (
      credential: CredentialInput,
      input: { tenantId: string; confirmationId: string },
    ): Promise<ConfirmationSummary> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const confirmationId = text(input.confirmationId, 'confirmationId');
      const authenticated = await ctx.principals.authenticate(credential);
      return store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const scope = confirmationScope(principal, tenantId);
        const confirmation = await tx.get<DelegationConfirmation>(
          'delegationConfirmations',
          confirmationId,
        );
        if (
          !confirmation ||
          confirmation.tenantId !== tenantId ||
          Object.entries(scope).some(
            ([key, value]) => (confirmation as Record<string, unknown>)[key] !== value,
          )
        )
          throw new IamError('NOT_FOUND', 'Confirmation request not found', 404);
        return confirmationSummary(tx, confirmation);
      });
    },
  };
}
