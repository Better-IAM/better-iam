import {
  IamError,
  matchPattern,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Session,
  type StoredRecord,
} from '@better-iam/core';
import { assertAgentUsable } from './agents.js';
import type { ServerContext } from './context.js';
import { revokedByWatermark } from './session-kinds.js';
import { integer, object, strings } from './validation.js';

/**
 * Delegations: a person lets an AI agent act on their behalf within a scope, for a limited time. The agent exchanges
 * its own API key for a short delegated session (`delegations.assume`, kind `delegated`) whose identity is the
 * person, so decisions use the person's grants, bounded by the delegation's scope, the agent's own ceiling, and any
 * scope-down the agent asked for. Every use re-validates the whole chain: the delegation, the person, the agent, its
 * sponsor and the agent key the session came from. Revoking a delegation ends its sessions at once.
 */
export interface Delegation extends StoredRecord {
  /** The agent that may act. */
  agentId: string;
  /** The person it acts for. */
  subjectId: string;
  /**
   * `pending` (an agent asked; the person has not decided), `active`, `denied` (the person refused the request) or
   * `revoked` (ended early by the person, the agent's sponsor, the agent itself or an administrator).
   */
  status: 'pending' | 'active' | 'denied' | 'revoked';
  /** What the agent may do for the person: a ceiling over the person's own access, never a grant of its own. */
  policy: PolicyDocument;
  /** The action list the scope was given as, when it was given as `scopes`. */
  scopes?: string[];
  /**
   * Who created it: the person granting directly, the agent asking (`delegations.request`), or another agent handing
   * part of its own delegation on (`delegations.handoff`).
   */
  requestedBy: 'subject' | 'agent' | 'handoff';
  /** The agent's stated reason, shown to the person deciding. */
  reason?: string;
  createdAt: number;
  /** Pending: when the request lapses undecided. Active: when the delegation ends. */
  expiresAt: number;
  /** Pending requests: how long the delegation lasts once approved (milliseconds). */
  lifetimeMs?: number;
  /** Longest single delegated session in seconds, below the agent's own limit. */
  maxSessionSeconds?: number;
  decidedAt?: number;
  revokedAt?: number;
  revokedBy?: string;
  /** Delegated sessions created before this time are refused (set on revocation). */
  sessionsRevokedBefore?: number;
  /** When the agent last opened a delegated session with it. */
  lastUsedAt?: number;
  /**
   * Action patterns the person must confirm one call at a time: a delegated session is refused them
   * (`CONFIRMATION_REQUIRED`) unless the person approved that action on that resource moments before
   * (`delegations.requestConfirmation`).
   */
  confirm?: string[];
  /**
   * The person lets the agent hand parts of this delegation on to other agents (`delegations.handoff`): to any agent
   * that accepts delegation, or only to `agents`, for `depth` more hand-offs down the line (1 to 3).
   */
  handoff?: DelegationHandoff;
  /** A hand-off: the delegation it was handed on from. Using it needs every delegation above it live. */
  parentId?: string;
  /** A hand-off: the agents of the delegations above it, the person's own delegate first. */
  chain?: string[];
  /**
   * A hand-off: the limits of the session that handed it on (its scope-down policy and its key's scopes), ceilings
   * over every use, so a hand-off never allows more than the handing session could do.
   */
  ceilings?: PolicyDocument[];
  /** A hand-off: the issuer authority of the key behind the handing session, whose ceilings apply too. */
  authorityId?: string;
  /**
   * A hand-off: the API key the handing agent acted with. The hand-off works only while that key does, so revoking a
   * compromised agent's key also stops what it handed on.
   */
  keyId?: string;
  /**
   * The person's cap on what AI model calls made under this delegation (and the hand-offs below it) may use per window:
   * checked and metered like an inference budget (`BUDGET_EXCEEDED` once spent).
   */
  spend?: DelegationSpend;
}

/** A spending cap on a delegation: tokens, cost (micro-dollars) and/or calls per window. */
export interface DelegationSpend {
  period: 'minute' | 'hour' | 'day' | 'month';
  maxTokens?: number;
  maxCostMicros?: number;
  maxRequests?: number;
}

/**
 * Reads a `spend` setting: `{ period, maxTokens?, maxCostUsd?, maxRequests? }` with at least one limit. `null` means
 * none (for clearing); `undefined` leaves the caller's choice alone.
 */
export function spendSetting(value: unknown): DelegationSpend | null | undefined {
  if (value === undefined || value === null) return value;
  const input = object(value) as {
    period?: unknown;
    maxTokens?: unknown;
    maxCostUsd?: unknown;
    maxRequests?: unknown;
  };
  const period = input.period;
  if (period !== 'minute' && period !== 'hour' && period !== 'day' && period !== 'month')
    throw new IamError('INVALID_INPUT', "spend.period must be 'minute', 'hour', 'day' or 'month'");
  const spend: DelegationSpend = { period };
  if (input.maxTokens !== undefined)
    spend.maxTokens = integer(input.maxTokens, 'spend.maxTokens', 1, 1_000_000_000_000);
  if (input.maxCostUsd !== undefined) {
    const usd = input.maxCostUsd;
    // At least one micro-dollar: a smaller cap would round to zero and refuse every call.
    if (typeof usd !== 'number' || !Number.isFinite(usd) || usd < 0.000001 || usd > 1_000_000)
      throw new IamError(
        'INVALID_INPUT',
        'spend.maxCostUsd must be at least 0.000001 and at most 1000000',
      );
    spend.maxCostMicros = Math.round(usd * 1_000_000);
  }
  if (input.maxRequests !== undefined)
    spend.maxRequests = integer(input.maxRequests, 'spend.maxRequests', 1, 1_000_000_000);
  if (
    spend.maxTokens === undefined &&
    spend.maxCostMicros === undefined &&
    spend.maxRequests === undefined
  )
    throw new IamError('INVALID_INPUT', 'spend needs maxTokens, maxCostUsd or maxRequests');
  return spend;
}

/** What a delegation lets its agent hand on. */
export interface DelegationHandoff {
  /** The agents it may hand on to; any delegable agent of the tenant when absent. */
  agents?: string[];
  /** How many hand-offs may follow down the line, 1 to 3. */
  depth: number;
}

/** Bounds of hand-offs: the deepest chain below a person's own delegation, and live hand-offs per delegation. */
export const handoffLimits = { maxDepth: 3, maxLive: 20, maxAgents: 20 } as const;

/**
 * A person's answer to an agent asking to take one sensitive action on their behalf (a human-in-the-loop check, like
 * OpenID CIBA): pending until the person decides or it lapses, then an approval valid for `validSeconds` for exactly
 * that action on that resource.
 */
export interface DelegationConfirmation extends StoredRecord {
  delegationId: string;
  agentId: string;
  subjectId: string;
  action: string;
  resourceType: string;
  resourceId: string;
  /** The agent's explanation, shown to the person. */
  reason?: string;
  /** `used` once the approval opened the one call it was for (approvals are single-use). */
  status: 'pending' | 'approved' | 'rejected' | 'used';
  createdAt: number;
  /** Pending: when the request lapses undecided. Approved: when the approval stops opening the action. */
  expiresAt: number;
  /** How long an approval waits to be used, in seconds. */
  validSeconds: number;
  decidedAt?: number;
  /** When the approval was used. */
  usedAt?: number;
}

/** Bounds of confirmation requests: how long the person has to decide, and how long an approval lasts. */
export const confirmationLimits = {
  decideMs: 30 * 60_000,
  minValidSeconds: 30,
  maxValidSeconds: 3_600,
  fallbackValidSeconds: 300,
} as const;

/** The key a confirmation opens: an action on a resource. */
export const confirmationKey = (action: string, resourceType: string, resourceId: string) =>
  `${action}|${resourceType}/${resourceId}`;

/** Whether a delegation requires the person's confirmation for an action. */
export function needsConfirmation(
  delegation: Pick<Delegation, 'confirm'>,
  action: string,
): boolean {
  return (delegation.confirm ?? []).some((pattern) => matchPattern(pattern, action));
}

/** Reads a `confirm` list: action patterns (wildcards allowed), at most 50; an empty list means none. */
export function confirmPatterns(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  const patterns = [...new Set(strings(value, 'confirm'))];
  if (patterns.length > 50)
    throw new IamError('INVALID_INPUT', 'confirm may list at most 50 actions');
  for (const pattern of patterns)
    if (!/^[A-Za-z0-9*?][A-Za-z0-9:_*?.-]{0,127}$/.test(pattern))
      throw new IamError('INVALID_INPUT', `Invalid action pattern ${pattern}`);
  return patterns.length ? patterns : undefined;
}

/**
 * Approvals used inside a transaction still open their call for the rest of it (one operation may check the same
 * action more than once); keyed by the transaction handle, so they end with it.
 */
const usedIn = new WeakMap<IamStore, Set<string>>();

/** The approved, unexpired (and not yet used) confirmations of a delegation, as the keys they open. */
export async function approvedConfirmations(
  tx: IamStore,
  delegation: Pick<Delegation, 'id' | 'tenantId'>,
  now: number,
): Promise<Set<string>> {
  const keys = new Set<string>();
  const used = usedIn.get(tx);
  for (const confirmation of await tx.find<DelegationConfirmation>('delegationConfirmations', {
    tenantId: delegation.tenantId,
    delegationId: delegation.id,
  }))
    if (
      (confirmation.status === 'approved' && confirmation.expiresAt > now) ||
      (confirmation.status === 'used' && used?.has(confirmation.id))
    )
      keys.add(
        confirmationKey(confirmation.action, confirmation.resourceType, confirmation.resourceId),
      );
  return keys;
}

/**
 * Uses up the person's approval behind an allowed call of a delegated session, so each approval opens exactly one
 * call ("confirm one call at a time"): called by a one-shot decision inside its transaction, it marks the matching
 * approval `used` (rolled back with a refused operation). Actions the delegation does not hold back, and other
 * sessions, are left alone.
 */
export async function useConfirmation(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  action: string,
  resourceType: string,
  resourceId: string,
  now: number,
): Promise<void> {
  const session = principal.session;
  if (session.kind !== 'delegated' || typeof session.delegationId !== 'string') return;
  const delegation = await tx.get<Delegation>('delegations', session.delegationId);
  if (!delegation || !needsConfirmation(delegation, action)) return;
  const used = usedIn.get(tx) ?? new Set<string>();
  const matching = (
    await tx.find<DelegationConfirmation>('delegationConfirmations', {
      tenantId: delegation.tenantId,
      delegationId: delegation.id,
    })
  ).filter(
    (item) =>
      item.action === action &&
      item.resourceType === resourceType &&
      item.resourceId === resourceId,
  );
  // Already used earlier in this very transaction: the same call checked again.
  if (matching.some((item) => item.status === 'used' && used.has(item.id))) return;
  const approval = matching
    .filter((item) => item.status === 'approved' && item.expiresAt > now)
    .sort((a, b) => a.expiresAt - b.expiresAt)[0];
  if (!approval) return;
  await tx.put<DelegationConfirmation>('delegationConfirmations', {
    ...approval,
    status: 'used',
    usedAt: now,
  });
  used.add(approval.id);
  usedIn.set(tx, used);
}

/** Bounds of a delegation's lifetime and of a pending request. */
export const delegationLifetime = {
  minSeconds: 300,
  maxSeconds: 365 * 86_400,
  fallbackSeconds: 30 * 86_400,
  requestMs: 7 * 86_400_000,
} as const;
/** Live delegated sessions one delegation may hold at a time. */
export const maxSessionsPerDelegation = 20;

const scopeSid = 'DelegationScopes';

/** A scope given as actions compiles to an allow on every resource; the person's own grants still decide. */
export function delegationScopesPolicy(scopes: string[]): PolicyDocument {
  return {
    version: 1,
    statements: [{ sid: scopeSid, effect: 'allow', actions: scopes, resources: ['*'] }],
  };
}

/**
 * Reads a delegation scope: `scopes` (an action list, wildcards allowed) or a `policy` document, exactly one of them,
 * validated against the tenant's catalog. The scope only ever narrows: the delegated session acts with the person's
 * grants, and this becomes one more ceiling over them.
 */
export async function delegationScope(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  input: { scopes?: unknown; policy?: unknown },
): Promise<{ policy: PolicyDocument; scopes?: string[] }> {
  if ((input.scopes === undefined) === (input.policy === undefined))
    throw new IamError('INVALID_INPUT', 'Provide either scopes or a policy');
  if (input.scopes !== undefined) {
    const scopes = [...new Set(strings(input.scopes, 'scopes'))];
    if (!scopes.length) throw new IamError('INVALID_INPUT', 'scopes must name at least one action');
    const policy = delegationScopesPolicy(scopes);
    await ctx.catalog.validate(tx, tenantId, policy);
    return { policy, scopes };
  }
  const policy = object(input.policy) as unknown as PolicyDocument;
  await ctx.catalog.validate(tx, tenantId, policy);
  return { policy };
}

/** A delegation lifetime in seconds (`expiresInSeconds`), within bounds; the fallback is 30 days. */
export function delegationSeconds(value: unknown): number {
  return value === undefined
    ? delegationLifetime.fallbackSeconds
    : integer(
        value,
        'expiresInSeconds',
        delegationLifetime.minSeconds,
        delegationLifetime.maxSeconds,
      );
}

const wildcard = /[*?]/;

/** The literal text of a glob before its first wildcard and after its last one. */
function globEnds(pattern: string): [string, string] {
  const first = pattern.search(wildcard);
  if (first === -1) return [pattern, pattern];
  let last = pattern.length - 1;
  while (last >= 0 && !wildcard.test(pattern[last]!)) last--;
  return [pattern.slice(0, first), pattern.slice(last + 1)];
}

/** Whether some action could match both action patterns (conservative: true unless their literal ends disagree). */
export function actionsMayOverlap(pattern: string, scope: string): boolean {
  if (pattern.includes('${')) return true;
  if (!scope.includes('*')) return matchPattern(pattern, scope);
  const [prefixA, suffixA] = globEnds(pattern);
  const [prefixB, suffixB] = globEnds(scope);
  return (
    (prefixA.startsWith(prefixB) || prefixB.startsWith(prefixA)) &&
    (suffixA.endsWith(suffixB) || suffixB.endsWith(suffixA))
  );
}

/**
 * Whether a policy document allows a whole scope (an action or a `*` pattern of actions) outright: some statement
 * allows every action it covers on every resource without conditions, and no deny statement could touch any of them.
 * Conservative by design: a document that allows the scope only for some resources or under conditions does not count.
 */
export function policyAllowsScope(document: PolicyDocument, scope: string): boolean {
  let allowed = false;
  for (const statement of document.statements) {
    if (statement.effect === 'deny') {
      if (statement.actions.some((pattern) => actionsMayOverlap(pattern, scope))) return false;
      continue;
    }
    if (statement.conditions && Object.keys(statement.conditions).length) continue;
    if (!statement.resources.includes('*')) continue;
    // A pattern covers a `*` scope only when its own wildcards are `*` (a `?` or a variable would match less).
    if (
      statement.actions.some(
        (pattern) =>
          (!scope.includes('*') || !/[?]|\$\{/.test(pattern)) && matchPattern(pattern, scope),
      )
    )
      allowed = true;
  }
  return allowed;
}

/** Whether a delegation lets its agent act right now. */
export function delegationLive(delegation: Delegation, now: number): boolean {
  return delegation.status === 'active' && delegation.expiresAt > now;
}

/** Whether a request still waits for the person's decision. */
export function delegationPending(delegation: Delegation, now: number): boolean {
  return delegation.status === 'pending' && delegation.expiresAt > now;
}

/**
 * Reads a `handoff` setting: `{ agents?, depth? }` with agents of the tenant (at most 20) and a depth of 1 to 3 (1 by
 * default). `null` means none (for clearing); `undefined` leaves the caller's choice alone.
 */
export async function handoffSetting(
  tx: IamStore,
  tenantId: string,
  value: unknown,
): Promise<DelegationHandoff | null | undefined> {
  if (value === undefined || value === null) return value;
  const input = object(value) as { agents?: unknown; depth?: unknown };
  const depth =
    input.depth === undefined
      ? 1
      : integer(input.depth, 'handoff.depth', 1, handoffLimits.maxDepth);
  if (input.agents === undefined) return { depth };
  const agents = [...new Set(strings(input.agents, 'handoff.agents'))];
  if (!agents.length || agents.length > handoffLimits.maxAgents)
    throw new IamError(
      'INVALID_INPUT',
      `handoff.agents must name 1 to ${handoffLimits.maxAgents} agents`,
    );
  for (const agentId of agents) {
    const agent = await tx.get<Identity>('identities', agentId);
    if (!agent || agent.kind !== 'agent' || agent.tenantId !== tenantId)
      throw new IamError(
        'INVALID_INPUT',
        `handoff.agents: ${agentId} is not an agent of this tenant`,
      );
  }
  return { agents, depth };
}

/**
 * The delegations above a hand-off, nearest first, when every one of them is live and names the same person, and its
 * agent is an agent of the tenant that still accepts delegation. Undefined when any link is broken (the hand-off may
 * not be used). A delegation the person gave directly has no ancestors. `liveAncestors` also checks each agent's
 * standing.
 */
export async function delegationAncestors(
  tx: IamStore,
  delegation: Delegation,
  now: number,
): Promise<{ delegation: Delegation; agent: Identity }[] | undefined> {
  const ancestors: { delegation: Delegation; agent: Identity }[] = [];
  const seen = new Set([delegation.id]);
  let current = delegation;
  while (current.parentId !== undefined) {
    if (ancestors.length >= handoffLimits.maxDepth) return undefined;
    const parent = await tx.get<Delegation>('delegations', current.parentId);
    if (
      !parent ||
      seen.has(parent.id) ||
      !delegationLive(parent, now) ||
      parent.tenantId !== delegation.tenantId ||
      parent.subjectId !== delegation.subjectId
    )
      return undefined;
    const agent = await tx.get<Identity>('identities', parent.agentId);
    if (
      !agent ||
      agent.kind !== 'agent' ||
      agent.tenantId !== delegation.tenantId ||
      agent.agent?.delegable === false
    )
      return undefined;
    // The key the handing agent acted with must still be one of its live API keys.
    if (current.keyId !== undefined) {
      const key = await tx.get<Session>('sessions', current.keyId);
      if (!key || key.kind !== 'api-key' || key.identityId !== agent.id || key.expiresAt <= now)
        return undefined;
    }
    ancestors.push({ delegation: parent, agent });
    seen.add(parent.id);
    current = parent;
  }
  return ancestors;
}

/** `delegationAncestors`, with every agent above also in good standing (itself and its sponsor active). */
export async function liveAncestors(
  ctx: ServerContext,
  tx: IamStore,
  delegation: Delegation,
  now: number,
): Promise<{ delegation: Delegation; agent: Identity }[] | undefined> {
  const ancestors = await delegationAncestors(tx, delegation, now);
  if (!ancestors) return undefined;
  try {
    for (const { agent } of ancestors) await assertAgentUsable(ctx, tx, agent);
  } catch {
    return undefined;
  }
  return ancestors;
}

/**
 * Revokes every live hand-off below a delegation (at any depth) and deletes their sessions, recording `revokedBy`.
 * Returns how many were revoked. Their use is refused anyway once a delegation above them ends; this keeps their
 * records honest.
 */
export async function revokeHandoffsBelow(
  tx: IamStore,
  delegation: Pick<Delegation, 'id' | 'tenantId'>,
  revokedBy: string,
  now: number,
): Promise<number> {
  let revoked = 0;
  const pending = [delegation.id];
  const seen = new Set(pending);
  while (pending.length) {
    const parentId = pending.pop()!;
    for (const child of await tx.find<Delegation>('delegations', {
      tenantId: delegation.tenantId,
      parentId,
    })) {
      if (seen.has(child.id)) continue;
      seen.add(child.id);
      // An ended hand-off's own hand-offs ended with it; only live ones are followed down.
      if (child.status !== 'active' && child.status !== 'pending') continue;
      pending.push(child.id);
      await tx.put<Delegation>('delegations', {
        ...child,
        status: 'revoked',
        revokedAt: now,
        revokedBy,
        sessionsRevokedBefore: now + 1,
      });
      await deleteDelegatedSessions(tx, { delegationId: child.id });
      revoked++;
    }
  }
  return revoked;
}

/**
 * The checks a delegated session passes on every use: its delegation is active, unexpired, and names this person and
 * agent in this tenant, and was not revoked after the session began; the person is an active person of the tenant;
 * the agent is an agent in good standing (itself and its sponsor active) that still accepts delegation; and the agent
 * key the session came from is re-validated under its own rules (`revalidate`). Anything else is a 401.
 */
export async function checkDelegatedSession(
  ctx: ServerContext,
  tx: IamStore,
  identity: Identity,
  session: Session,
  revalidate: (principal: AuthenticatedPrincipal) => Promise<unknown>,
): Promise<void> {
  const revoked = () => new IamError('UNAUTHENTICATED', 'Delegation revoked', 401);
  const now = ctx.now();
  const delegation =
    typeof session.delegationId === 'string'
      ? await tx.get<Delegation>('delegations', session.delegationId)
      : undefined;
  const agent =
    typeof session.agentId === 'string'
      ? await tx.get<Identity>('identities', session.agentId)
      : undefined;
  const source =
    typeof session.sourceSessionId === 'string'
      ? await tx.get<Session>('sessions', session.sourceSessionId)
      : undefined;
  if (
    !delegation ||
    !delegationLive(delegation, now) ||
    delegation.tenantId !== session.tenantId ||
    delegation.subjectId !== identity.id ||
    delegation.agentId !== session.agentId ||
    revokedByWatermark(session.createdAt, delegation.sessionsRevokedBefore) ||
    session.expiresAt > delegation.expiresAt ||
    identity.kind !== 'user' ||
    identity.tenantId !== session.tenantId ||
    !agent ||
    agent.kind !== 'agent' ||
    agent.tenantId !== session.tenantId ||
    agent.agent?.delegable === false ||
    !source ||
    source.kind !== 'api-key' ||
    source.identityId !== agent.id ||
    source.tenantId !== session.tenantId ||
    session.expiresAt > source.expiresAt ||
    // The session carries the key's issuer authority (a ceiling in decisions); it must still be the key's.
    session.credentialAuthorityId !== source.credentialAuthorityId
  )
    throw revoked();
  await assertAgentUsable(ctx, tx, agent);
  // A hand-off works only while every delegation above it does, with its agents in good standing.
  if (delegation.parentId !== undefined && !(await liveAncestors(ctx, tx, delegation, now)))
    throw revoked();
  await revalidate({ identity: agent, session: source });
}

/** Deletes the live delegated sessions of a delegation (or of every delegation of an agent); returns the count. */
export async function deleteDelegatedSessions(
  tx: IamStore,
  filter: { delegationId: string } | { agentId: string },
): Promise<number> {
  let deleted = 0;
  const rows = await tx.find<Session>('sessions', { kind: 'delegated', ...filter });
  for (const session of rows) {
    await tx.delete('sessions', session.id);
    deleted++;
  }
  return deleted;
}

/**
 * Ends every delegation that involves an identity (as the agent or as the person) and their sessions: used when an
 * identity is deleted. Records stay as `revoked` for the audit trail. Returns the number of delegations ended.
 */
export async function revokeDelegationsOf(
  ctx: ServerContext,
  tx: IamStore,
  identity: Pick<Identity, 'id' | 'tenantId'>,
  revokedBy: string,
): Promise<number> {
  const now = ctx.now();
  let ended = 0;
  const found = [
    ...(await tx.find<Delegation>('delegations', {
      tenantId: identity.tenantId,
      agentId: identity.id,
    })),
    ...(await tx.find<Delegation>('delegations', {
      tenantId: identity.tenantId,
      subjectId: identity.id,
    })),
  ];
  for (const delegation of found) {
    if (delegation.status !== 'active' && delegation.status !== 'pending') continue;
    await tx.put<Delegation>('delegations', {
      ...delegation,
      status: 'revoked',
      revokedAt: now,
      revokedBy,
      sessionsRevokedBefore: now + 1,
    });
    await deleteDelegatedSessions(tx, { delegationId: delegation.id });
    ended++;
  }
  // Hand-offs below the ended delegations end with them.
  for (const delegation of found)
    ended += await revokeHandoffsBelow(tx, delegation, revokedBy, now);
  return ended;
}
