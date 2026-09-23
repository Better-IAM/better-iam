import {
  IamError,
  type AgentProfile,
  type AuthenticatedPrincipal,
  type Decision,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Session,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import {
  approvedConfirmations,
  confirmationKey,
  delegationAncestors,
  needsConfirmation,
  type Delegation,
} from './delegations.js';
import { integer, strings, text } from './validation.js';

/**
 * AI agents as accounts. An agent is an identity of kind `agent`: a machine account like a service account (API keys,
 * no sign-in) that always has a sponsor, the person accountable for it. Its credentials work only while the sponsor is
 * an active, unexpired person of the same tenant, and every decision it takes part in (its own keys, and sessions in
 * which it acts for someone under a delegation) is bounded by the agent's own ceiling (`AgentProfile.boundary`).
 */

/** Default and bounds of `AgentProfile.maxDelegatedSessionSeconds`. */
export const agentSessionSeconds = { min: 60, max: 43_200, fallback: 3_600 } as const;

/** Why an agent may not act right now; `ok` when it may. */
export type AgentStanding =
  | 'ok'
  | 'suspended'
  | 'expired'
  | 'deleted'
  | 'sponsor-missing'
  | 'sponsor-inactive';

/** What `agents.update` and `agents.create` accept for the profile; null clears an optional field. */
export interface AgentProfileInput {
  model?: string | null;
  provider?: string | null;
  purpose?: string | null;
  url?: string | null;
  protocols?: string[] | null;
  delegable?: boolean;
  maxDelegatedSessionSeconds?: number | null;
  boundary?: PolicyDocument | null;
  tokenAudiences?: string[] | null;
}

/** URI path characters (RFC 3986 pchar and `/`); `*` among them is a wildcard in audience patterns. */
const pathChars = "[A-Za-z0-9\\-._~!$&'()*+,;=:@%/]";
/**
 * An http(s) audience: scheme, host (a pattern may start it with `*.`), optional port, optional path. No user info,
 * query or fragment.
 */
const httpAudience = new RegExp(
  `^(https?)://(\\*\\.)?([A-Za-z0-9-]+(?:\\.[A-Za-z0-9-]+)*)(:\\d{1,5})?(/${pathChars}*)?$`,
  'i',
);
/** Any other absolute URI, such as `urn:example:api`. */
const otherAudience = new RegExp(`^(?!https?:)[A-Za-z][A-Za-z0-9+.-]*:${pathChars}{1,500}$`, 'i');

/** Glob matching where only `*` is special (any characters), in linear-ish time: no regular expression backtracking. */
function globMatch(pattern: string, value: string): boolean {
  let p = 0;
  let v = 0;
  let star = -1;
  let retry = 0;
  while (v < value.length) {
    if (p < pattern.length && pattern[p] !== '*' && pattern[p] === value[v]) {
      p++;
      v++;
    } else if (pattern[p] === '*') {
      star = p++;
      retry = v;
    } else if (star !== -1) {
      p = star + 1;
      v = ++retry;
    } else return false;
  }
  while (pattern[p] === '*') p++;
  return p === pattern.length;
}

/**
 * Whether a token audience pattern matches a requested audience. For http(s) patterns the scheme and port must be
 * equal, the host equal (case-insensitively) or, for `*.example.com`, a subdomain of it, and the path must match with
 * `*` as a wildcard (no path means `/`); a `*` never reaches across the host. Other URIs match as a whole, with `*`.
 */
export function audienceMatches(pattern: string, audience: string): boolean {
  if (audience.length > 512) return false;
  const wanted = httpAudience.exec(pattern);
  if (wanted) {
    const given = httpAudience.exec(audience);
    if (!given || given[2] || audience.includes('*')) return false;
    if (wanted[1]!.toLowerCase() !== given[1]!.toLowerCase()) return false;
    const host = given[3]!.toLowerCase();
    const base = wanted[3]!.toLowerCase();
    if (wanted[2] ? !host.endsWith(`.${base}`) : host !== base) return false;
    if ((wanted[4] ?? '') !== (given[4] ?? '')) return false;
    return globMatch(wanted[5] || '/', given[5] || '/');
  }
  return (
    !httpAudience.test(audience) && otherAudience.test(audience) && globMatch(pattern, audience)
  );
}

/** Whether a value is a well-formed audience (`patterns`: with `*` where audience patterns allow it). */
function audienceSyntax(value: string, patterns: boolean): boolean {
  if (value.length > 512 || (!patterns && value.includes('*'))) return false;
  // The host part of the http(s) form cannot hold `*` beyond a leading `*.`.
  return httpAudience.test(value) || otherAudience.test(value);
}

/**
 * Reads a list of token audiences (at most 16): http(s) URLs such as `https://api.example.com` or
 * `https://*.example.com/v1/*` (no user info, query or fragment), or other absolute URIs such as `urn:example:api`.
 */
export function tokenAudienceList(value: unknown, field = 'tokenAudiences'): string[] {
  const list = [...new Set(strings(value, field))];
  if (list.length > 16 || list.some((item) => !audienceSyntax(item, true)))
    throw new IamError(
      'INVALID_INPUT',
      `${field} must list at most 16 absolute URIs (such as https://api.example.com, https://*.example.com or urn:example:api)`,
    );
  return list.sort();
}

/** Reads one requested token audience: an http(s) URL or other absolute URI, without `*`. */
export function tokenAudience(value: unknown): string {
  const audience = text(value, 'audience', 512);
  if (!audienceSyntax(audience, false))
    throw new IamError(
      'INVALID_INPUT',
      'audience must name one service: an http(s) URL without user info, query, fragment or *, or another absolute URI',
    );
  return audience;
}

const modelPattern = /^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,127}$/;
const providerPattern = /^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$/;
const protocolPattern = /^[a-z][a-z0-9.-]{0,31}$/;

/** Machine accounts: service accounts and agents. They hold API keys and never sign in. */
export function machineIdentity(identity: Pick<Identity, 'kind'>): boolean {
  return identity.kind === 'service' || identity.kind === 'agent';
}

/**
 * Validates profile fields over `previous` (a stored profile, or a fresh one with only the sponsor). Policy
 * documents are checked against the tenant's catalog; unknown keys are ignored. Returns a new profile object.
 */
export async function agentProfile(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  input: AgentProfileInput,
  previous: AgentProfile,
): Promise<AgentProfile> {
  const next: AgentProfile = { ...previous };
  const optional = <K extends keyof AgentProfile>(
    key: K,
    value: unknown,
    read: (value: unknown) => AgentProfile[K],
  ) => {
    if (value === undefined) return;
    if (value === null) delete next[key];
    else next[key] = read(value);
  };
  optional('model', input.model, (value) => {
    if (typeof value !== 'string' || !modelPattern.test(value))
      throw new IamError(
        'INVALID_INPUT',
        'model must be 1-128 letters, digits or ._:/@+- characters',
      );
    return value;
  });
  optional('provider', input.provider, (value) => {
    if (typeof value !== 'string' || !providerPattern.test(value))
      throw new IamError(
        'INVALID_INPUT',
        'provider must be 1-64 letters, digits or ._- characters',
      );
    return value.toLowerCase();
  });
  optional('purpose', input.purpose, (value) => text(value, 'purpose', 1024));
  optional('url', input.url, (value) => {
    const url = text(value, 'url', 2048);
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch {
      throw new IamError('INVALID_INPUT', 'url must be an http(s) URL');
    }
    if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
      throw new IamError('INVALID_INPUT', 'url must be an http(s) URL');
    return url;
  });
  optional('protocols', input.protocols, (value) => {
    const list = [...new Set(strings(value, 'protocols').map((item) => item.toLowerCase()))];
    if (list.length > 16 || list.some((item) => !protocolPattern.test(item)))
      throw new IamError('INVALID_INPUT', 'protocols must list at most 16 short lowercase names');
    return list.sort();
  });
  if (input.delegable !== undefined) {
    if (typeof input.delegable !== 'boolean')
      throw new IamError('INVALID_INPUT', 'delegable must be a boolean');
    if (input.delegable) delete next.delegable;
    else next.delegable = false;
  }
  optional('maxDelegatedSessionSeconds', input.maxDelegatedSessionSeconds, (value) =>
    integer(value, 'maxDelegatedSessionSeconds', agentSessionSeconds.min, agentSessionSeconds.max),
  );
  if (input.boundary !== undefined && input.boundary !== null)
    await ctx.catalog.validate(tx, tenantId, input.boundary);
  optional('boundary', input.boundary, (value) => value as PolicyDocument);
  optional('tokenAudiences', input.tokenAudiences, (value) => tokenAudienceList(value));
  return next;
}

/** A sponsor is an active, unexpired person of the agent's tenant. */
export async function sponsorFor(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  sponsorId: unknown,
): Promise<Identity> {
  const sponsor = await tx.get<Identity>('identities', text(sponsorId, 'sponsorId'));
  if (
    !sponsor ||
    sponsor.tenantId !== tenantId ||
    sponsor.kind !== 'user' ||
    sponsor.status !== 'active' ||
    ctx.identityExpired(sponsor)
  )
    throw new IamError(
      'INVALID_SPONSOR',
      'An agent sponsor must be an active person of the same tenant',
    );
  return sponsor;
}

/** Whether (and why not) an agent may act right now: itself active and unexpired, its sponsor too. */
export async function agentStanding(
  ctx: ServerContext,
  tx: IamStore,
  agent: Identity,
): Promise<AgentStanding> {
  if (agent.status === 'deleted') return 'deleted';
  if (agent.status !== 'active') return 'suspended';
  if (ctx.identityExpired(agent)) return 'expired';
  const sponsorId = agent.agent?.sponsorId;
  const sponsor =
    typeof sponsorId === 'string' ? await tx.get<Identity>('identities', sponsorId) : undefined;
  if (!sponsor || sponsor.tenantId !== agent.tenantId || sponsor.kind !== 'user')
    return 'sponsor-missing';
  if (sponsor.status !== 'active' || ctx.identityExpired(sponsor)) return 'sponsor-inactive';
  return 'ok';
}

/** Refuses an agent credential (401) unless the agent is an agent of `tenantId` in good standing. */
export async function assertAgentUsable(
  ctx: ServerContext,
  tx: IamStore,
  agent: Identity,
): Promise<void> {
  if (agent.kind !== 'agent' || !agent.agent)
    throw new IamError('UNAUTHENTICATED', 'Agent credential revoked', 401);
  const standing = await agentStanding(ctx, tx, agent);
  if (standing === 'sponsor-missing' || standing === 'sponsor-inactive')
    throw new IamError('UNAUTHENTICATED', 'The agent’s sponsor is no longer active', 401);
  if (standing !== 'ok') throw new IamError('UNAUTHENTICATED', 'Agent disabled', 401);
}

/** The agent behind a principal: the identity of an agent's own credential, or the agent of a delegated session. */
export async function actingAgent(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
): Promise<Identity | undefined> {
  if (principal.session.kind === 'delegated') {
    const agentId = principal.session.agentId;
    const agent =
      typeof agentId === 'string' ? await tx.get<Identity>('identities', agentId) : undefined;
    return agent?.kind === 'agent' ? agent : undefined;
  }
  return principal.identity.kind === 'agent' ? principal.identity : undefined;
}

/** What a decision adds for agents: context keys and the ceilings of the agent and the delegation. */
export interface AgentDecisionScope {
  keys: Record<string, unknown>;
  boundaries: PolicyDocument[];
  /**
   * Delegations with `confirm` patterns: turns an otherwise allowed decision for such an action into a refusal
   * (`CONFIRMATION_REQUIRED`) unless the person approved that action on that resource and the approval is still
   * valid. Undefined when nothing needs confirmation.
   */
  confirm?: (action: string, resourceType: string, resourceId: string) => Decision | undefined;
  /** Credential issuer authorities whose ceilings apply as well (the keys behind the sessions that handed work on). */
  authorities?: string[];
}

/**
 * The agent part of a decision. Every principal gets `principal.delegated`; an agent's own credential and a delegated
 * session also get `principal.agentId`, `principal.agentSponsorId`, `principal.agentModel` and
 * `principal.agentProvider` (when set), plus the agent's `boundary` as a ceiling. A delegated session adds
 * `principal.delegationId` and the delegation's scope as a ceiling, read live so narrowing or revoking a delegation
 * applies at once, and `principal.delegationChain` (the agents from the person's own delegate to this one). A hand-off
 * adds the scopes of the delegations above it and the ceilings of the agents that handed it on. Undefined when a
 * delegated session's agent or delegation (or one above it) cannot be read or has ended: the decision is refused.
 */
export async function agentDecisionScope(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  now: number = Date.now(),
): Promise<AgentDecisionScope | undefined> {
  const session: Session = principal.session;
  const delegated = session.kind === 'delegated';
  const scope: AgentDecisionScope = { keys: { 'principal.delegated': delegated }, boundaries: [] };
  const agent = await actingAgent(tx, principal);
  if (!agent) return delegated ? undefined : scope;
  const profile = agent.agent;
  scope.keys['principal.agentId'] = agent.id;
  if (typeof profile?.sponsorId === 'string')
    scope.keys['principal.agentSponsorId'] = profile.sponsorId;
  if (typeof profile?.model === 'string') scope.keys['principal.agentModel'] = profile.model;
  if (typeof profile?.provider === 'string')
    scope.keys['principal.agentProvider'] = profile.provider;
  if (profile?.boundary) scope.boundaries.push(profile.boundary);
  if (delegated) {
    const delegationId = session.delegationId;
    const delegation =
      typeof delegationId === 'string'
        ? await tx.get<Delegation>('delegations', delegationId)
        : undefined;
    if (
      !delegation ||
      delegation.status !== 'active' ||
      delegation.agentId !== agent.id ||
      delegation.subjectId !== principal.identity.id ||
      !delegation.policy
    )
      return undefined;
    scope.keys['principal.delegationId'] = delegation.id;
    scope.boundaries.push(delegation.policy);
    // A hand-off is bounded by every delegation above it, the ceilings of the agents that handed it on, and the limits
    // of the sessions that did (their scope-down policies, key scopes and key issuers' authority).
    const ancestors = await delegationAncestors(tx, delegation, now);
    if (!ancestors) return undefined;
    const handedOn = (item: Delegation) => {
      scope.boundaries.push(...(item.ceilings ?? []));
      if (typeof item.authorityId === 'string') (scope.authorities ??= []).push(item.authorityId);
    };
    handedOn(delegation);
    for (const ancestor of ancestors) {
      if (!ancestor.delegation.policy) return undefined;
      scope.boundaries.push(ancestor.delegation.policy);
      if (ancestor.agent.agent?.boundary) scope.boundaries.push(ancestor.agent.agent.boundary);
      handedOn(ancestor.delegation);
    }
    scope.keys['principal.delegationChain'] = [
      ...ancestors.map((ancestor) => ancestor.agent.id).reverse(),
      agent.id,
    ];
    if (delegation.confirm?.length) {
      const approved = await approvedConfirmations(tx, delegation, now);
      scope.confirm = (action, resourceType, resourceId) =>
        needsConfirmation(delegation, action) &&
        !approved.has(confirmationKey(action, resourceType, resourceId))
          ? { allowed: false, reason: 'CONFIRMATION_REQUIRED', matched: [] }
          : undefined;
    }
  }
  return scope;
}

/**
 * Offboarding: the leaver's agents move to `successor` when that is an active person (each audited as
 * `agent:sponsor-change`); otherwise they stay with the leaver and are refused until an administrator reassigns them.
 */
export async function handOverAgents(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  leaver: Identity,
  successor: Identity | undefined,
): Promise<{ reassigned: number; unsponsored: number }> {
  const counts = { reassigned: 0, unsponsored: 0 };
  const heir =
    successor && successor.kind === 'user' && successor.status === 'active' ? successor : undefined;
  for (const agent of await tx.find<Identity>('identities', {
    tenantId: leaver.tenantId,
    kind: 'agent',
  })) {
    if (agent.status === 'deleted' || agent.agent?.sponsorId !== leaver.id) continue;
    if (!heir) {
      counts.unsponsored++;
      continue;
    }
    await tx.put<Identity>('identities', {
      ...agent,
      agent: { ...agent.agent, sponsorId: heir.id },
    });
    await ctx.events.audit(
      tx,
      principal,
      'agent:sponsor-change',
      agent.tenantId,
      agent.id,
      'allow',
      false,
      { from: leaver.id, to: heir.id, reason: 'offboarding' },
    );
    counts.reassigned++;
  }
  return counts;
}

/** An agent as administrators and sponsors see it: the identity's public fields plus its standing. */
export interface AgentSummary {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  status: Identity['status'];
  createdAt: number;
  expiresAt?: number;
  attributes?: Identity['attributes'];
  agent: AgentProfile;
  standing: AgentStanding;
  sponsor?: { id: string; name: string; email?: string; status: Identity['status'] };
}

export async function agentSummary(
  ctx: ServerContext,
  tx: IamStore,
  agent: Identity,
): Promise<AgentSummary> {
  const sponsorId = agent.agent?.sponsorId;
  const sponsor =
    typeof sponsorId === 'string' ? await tx.get<Identity>('identities', sponsorId) : undefined;
  const summary: AgentSummary = {
    id: agent.id,
    tenantId: agent.tenantId,
    name: agent.name,
    status: agent.status,
    createdAt: agent.createdAt,
    agent: { ...(agent.agent ?? { sponsorId: '' }) },
    standing: await agentStanding(ctx, tx, agent),
  };
  if (agent.description !== undefined) summary.description = agent.description;
  if (agent.expiresAt !== undefined) summary.expiresAt = agent.expiresAt;
  if (agent.attributes !== undefined) summary.attributes = agent.attributes;
  if (sponsor && sponsor.tenantId === agent.tenantId)
    summary.sponsor = {
      id: sponsor.id,
      name: sponsor.name,
      status: sponsor.status,
      ...(sponsor.email !== undefined ? { email: sponsor.email } : {}),
    };
  return summary;
}
