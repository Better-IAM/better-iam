import type {
  IamStore,
  Identity,
  PolicyDocument,
  Session,
  StoredRecord,
  Tenant,
} from '@better-iam/core';
import { assertAgentUsable, audienceMatches } from './agents.js';
import type { ServerContext } from './context.js';
import {
  actionsMayOverlap,
  delegationLive,
  liveAncestors,
  policyAllowsScope,
  type Delegation,
} from './delegations.js';
import type { PrincipalBoundary } from './models.js';

/**
 * What delegation tokens (`delegations.issueToken`) stand on, shared by issuing them and by live verification
 * (`iam.a2a.verifyDelegationToken(token, { live: true })`): the delegation chain, where the token may go, and which
 * scopes it may carry.
 */

/** An issued delegation token, kept until it expires so a live verification can re-check what it stands on. */
export interface DelegationTokenRecord extends StoredRecord {
  /** The token's `jti`. */
  id: string;
  delegationId: string;
  personId: string;
  agentId: string;
  /** The API key the acting agent's session came from: the token is live only while the key is. */
  keyId: string;
  audience: string;
  scopes: string[];
  /** The limits of the session that asked for the token (its scope-down policy and its key's policy). */
  sessionPolicies: PolicyDocument[];
  /** The issuer authority of the acting agent's key, whose ceilings apply too. */
  authorityId?: string;
  createdAt: number;
  expiresAt: number;
}

/** A delegation chain as a token names it. */
export interface TokenBasis {
  tenant: Tenant;
  personId: string;
  delegation: Delegation;
  /** The delegations above a hand-off, nearest first, with their agents. */
  ancestors: { delegation: Delegation; agent: Identity }[];
  /** The agents from the person's own delegate to the one acting now. */
  agents: Identity[];
  sessionPolicies: PolicyDocument[];
  /** Key issuer authorities beyond those the chain records (the acting key's). */
  authorityIds: string[];
}

/** Why a scope may not be carried: a limit does not allow it outright, the person confirms it, or a deny may touch it. */
export type ScopeRefusal =
  | { scope: string; why: 'limit' | 'confirm' | 'deny' }
  | { inactive: true };

/** The first agent of the chain that may not present delegations to `audience`, if any. */
export function audienceRefusal(agents: Identity[], audience: string): Identity | undefined {
  return agents.find(
    (agent) => !agent.agent?.tokenAudiences?.some((pattern) => audienceMatches(pattern, audience)),
  );
}

/**
 * The first scope the chain may not carry, or undefined when it may carry them all. Every scope must be allowed
 * outright by every limit a decision for the acting session applies (the delegations and their ceilings, the agents'
 * boundaries, the session's policies, the key issuers' authority, the tenant's and the person's boundaries). None may
 * be one the person confirms call by call (`confirm`, anywhere in the chain), nor one a deny statement among the
 * person's own grants could touch: a token carries no resource or condition to refine them with.
 */
export async function scopeRefusal(
  ctx: ServerContext,
  tx: IamStore,
  basis: TokenBasis,
  scopes: string[],
): Promise<ScopeRefusal | undefined> {
  if (!scopes.length) return undefined;
  const chain = [basis.delegation, ...basis.ancestors.map((ancestor) => ancestor.delegation)];
  const limits: PolicyDocument[] = [...basis.sessionPolicies];
  const authorityIds = new Set(basis.authorityIds);
  for (const delegation of chain) {
    limits.push(delegation.policy, ...(delegation.ceilings ?? []));
    if (typeof delegation.authorityId === 'string') authorityIds.add(delegation.authorityId);
  }
  for (const agent of basis.agents) if (agent.agent?.boundary) limits.push(agent.agent.boundary);
  for (const authorityId of authorityIds) {
    const ceilings = await ctx.authorityChain(tx, authorityId);
    if (!ceilings) return { inactive: true };
    limits.push(...ceilings);
  }
  for (const realm of await ctx.ancestry(tx, basis.tenant))
    if (realm.boundary) limits.push(realm.boundary);
  for (const boundary of await tx.find<PrincipalBoundary>('principalBoundaries', {
    tenantId: basis.tenant.id,
    identityId: basis.personId,
  }))
    limits.push(boundary.document);
  const confirm = chain.flatMap((delegation) => delegation.confirm ?? []);
  const denies = (await ctx.decisions.identityGrants(tx, basis.personId, basis.tenant.id))
    .flatMap((path) => [...path.grants, ...path.boundaries])
    .flatMap((document) => document.statements)
    .filter((statement) => statement.effect === 'deny')
    .flatMap((statement) => statement.actions);
  for (const scope of scopes) {
    if (!limits.every((document) => policyAllowsScope(document, scope)))
      return { scope, why: 'limit' };
    if (confirm.some((pattern) => actionsMayOverlap(pattern, scope)))
      return { scope, why: 'confirm' };
    if (denies.some((pattern) => actionsMayOverlap(pattern, scope))) return { scope, why: 'deny' };
  }
  return undefined;
}

/**
 * Re-checks an issued token's record against the current state: the delegation and those above it live, the person
 * active, every agent in good standing and still allowed the audience, the acting key live, and the scopes still
 * allowed. False when anything the token stands on has changed.
 */
export async function tokenStillStands(
  ctx: ServerContext,
  tx: IamStore,
  record: DelegationTokenRecord,
  now: number,
): Promise<boolean> {
  const delegation = await tx.get<Delegation>('delegations', record.delegationId);
  const tenant = await tx.get<Tenant>('tenants', record.tenantId);
  const person = await tx.get<Identity>('identities', record.personId);
  const agent = await tx.get<Identity>('identities', record.agentId);
  const key = await tx.get<Session>('sessions', record.keyId);
  if (
    !delegation ||
    !tenant ||
    !person ||
    !agent ||
    !key ||
    !delegationLive(delegation, now) ||
    delegation.tenantId !== record.tenantId ||
    delegation.subjectId !== record.personId ||
    delegation.agentId !== record.agentId ||
    person.tenantId !== record.tenantId ||
    person.status !== 'active' ||
    ctx.identityExpired(person) ||
    agent.agent?.delegable === false ||
    key.kind !== 'api-key' ||
    key.identityId !== agent.id ||
    key.expiresAt <= now
  )
    return false;
  if ((await ctx.ancestry(tx, tenant)).some((realm) => realm.status !== 'active')) return false;
  try {
    await assertAgentUsable(ctx, tx, agent);
  } catch {
    return false;
  }
  const ancestors = await liveAncestors(ctx, tx, delegation, now);
  if (!ancestors) return false;
  const agents = [...ancestors.map((ancestor) => ancestor.agent).reverse(), agent];
  if (audienceRefusal(agents, record.audience)) return false;
  return !(await scopeRefusal(
    ctx,
    tx,
    {
      tenant,
      personId: record.personId,
      delegation,
      ancestors,
      agents,
      sessionPolicies: record.sessionPolicies,
      authorityIds: record.authorityId ? [record.authorityId] : [],
    },
    record.scopes,
  ));
}
