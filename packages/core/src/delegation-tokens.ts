/**
 * Delegation tokens: short-lived signed JWTs with which an AI agent acting for a person shows a service outside Better
 * IAM that it does so (`delegations.issueToken`). The subject is the person; the actor (`act`, RFC 8693 section 4.1) is
 * the agent acting now, with the agents that handed the work to it nested inside. The token names one audience and,
 * optionally, the scopes of the delegation it carries. Verified by `verifyDelegationToken` (`@better-iam/a2a`) or
 * `iam.a2a.verifyDelegationToken` in the deployment itself; this module only reads the claims (no cryptography).
 */

/** The JWT `typ` header of delegation tokens: verifiers refuse any other. */
export const delegationTokenType = 'biam-delegation+jwt';

/** Lifetimes (seconds) and the longest chain of actors a delegation token carries. */
export const delegationTokenLimits = {
  minSeconds: 30,
  maxSeconds: 3600,
  defaultSeconds: 300,
  /** The person's own delegate plus up to three hand-offs. */
  maxActors: 4,
} as const;

/** An actor (RFC 8693 `act`): the agent acting, and in `act` the agent that handed the work on to it. */
export interface DelegationActor {
  sub: string;
  act?: DelegationActor;
}

/** The claims of a delegation token. */
export interface DelegationTokenClaims {
  /** The Better IAM deployment that issued it (its `a2a` issuer). */
  iss: string;
  /** The person the agent acts for (their identity id). */
  sub: string;
  /** The one service the token is for. */
  aud: string;
  iat: number;
  nbf: number;
  exp: number;
  /** A unique token id, for replay checks. */
  jti: string;
  /** The person's organization (tenant id). */
  tenant_id: string;
  /** The delegation the token carries. */
  delegation_id: string;
  /** The agent acting now; nested `act`, the agents that handed the work on (the person's own delegate innermost). */
  act: DelegationActor;
  /** Space-separated scopes of the delegation the token carries, when it has any. */
  scope?: string;
}

/** A delegation token as a verifier reports it. */
export interface DelegationTokenSummary {
  issuer: string;
  /** The person the agent acts for. */
  personId: string;
  tenantId: string;
  delegationId: string;
  /** The agent presenting the token (the actor acting now). */
  agentId: string;
  /** The agents from the person's own delegate to `agentId` (one entry unless the work was handed on). */
  chain: string[];
  /** The scopes it carries (empty when the delegation was given as a policy). */
  scopes: string[];
  audience: string;
  tokenId: string;
  /** Epoch milliseconds. */
  issuedAt: number;
  expiresAt: number;
  claims: DelegationTokenClaims;
}

/** Why claims were refused. */
export type DelegationTokenRejection =
  | 'malformed'
  | 'issuer'
  | 'audience'
  | 'tenant'
  | 'expired'
  | 'not-yet-valid'
  | 'lifetime';

export interface DelegationTokenExpectations {
  /** The issuer (or issuers) to accept. */
  issuer: string | readonly string[];
  /** The audience the verifier answers to; the token's `aud` must be exactly this. */
  audience: string;
  /** Accept only tokens of this organization. */
  tenantId?: string;
  /** Epoch milliseconds. */
  now: number;
  /** Allowed clock difference in seconds (default 30). */
  clockToleranceSeconds?: number;
}

const idPattern = /^[A-Za-z0-9._:-]{1,128}$/;
/** One scope a delegation token may carry: an action, or an action pattern whose only wildcard is `*`. */
export const delegationTokenScopePattern = /^[A-Za-z0-9*][A-Za-z0-9:_*./-]{0,127}$/;
const scopePattern = delegationTokenScopePattern;
const seconds = (value: unknown): value is number =>
  typeof value === 'number' && Number.isSafeInteger(value) && value > 0;

/**
 * Checks the claims of a (signature-verified) delegation token against what the verifier expects: well formed, from an
 * accepted issuer, for exactly this audience (and tenant), current within the clock tolerance, and issued for at most
 * `delegationTokenLimits.maxSeconds`.
 */
export function readDelegationTokenClaims(
  claims: unknown,
  expected: DelegationTokenExpectations,
): { token: DelegationTokenSummary } | { rejected: DelegationTokenRejection; message: string } {
  const malformed = (message: string) => ({ rejected: 'malformed' as const, message });
  if (!claims || typeof claims !== 'object' || Array.isArray(claims))
    return malformed('The token has no claims object');
  const value = claims as Record<string, unknown>;
  for (const field of ['iss', 'sub', 'aud', 'jti', 'tenant_id', 'delegation_id'] as const)
    if (typeof value[field] !== 'string' || !value[field])
      return malformed(`The token has no ${field}`);
  for (const field of ['sub', 'tenant_id', 'delegation_id'] as const)
    if (!idPattern.test(value[field] as string))
      return malformed(`The token's ${field} is invalid`);
  if (!seconds(value.iat) || !seconds(value.nbf) || !seconds(value.exp))
    return malformed('The token has no valid iat, nbf and exp');
  const actors: string[] = [];
  let actor: unknown = value.act;
  while (actor !== undefined) {
    if (!actor || typeof actor !== 'object' || Array.isArray(actor))
      return malformed('The token has an invalid act claim');
    const sub = (actor as Record<string, unknown>).sub;
    if (typeof sub !== 'string' || !idPattern.test(sub))
      return malformed('The token has an invalid act claim');
    actors.push(sub);
    if (actors.length > delegationTokenLimits.maxActors)
      return malformed('The token names too many actors');
    actor = (actor as Record<string, unknown>).act;
  }
  if (!actors.length) return malformed('The token names no actor (act)');
  if (new Set(actors).size !== actors.length || actors.includes(value.sub as string))
    return malformed('The token repeats an actor');
  let scopes: string[] = [];
  if (value.scope !== undefined) {
    if (typeof value.scope !== 'string') return malformed('The token has an invalid scope');
    scopes = value.scope.split(' ').filter(Boolean);
    if (scopes.length > 50 || scopes.some((scope) => !scopePattern.test(scope)))
      return malformed('The token has an invalid scope');
  }
  const issuers = typeof expected.issuer === 'string' ? [expected.issuer] : expected.issuer;
  if (!issuers.includes(value.iss as string))
    return { rejected: 'issuer', message: `The token was issued by ${String(value.iss)}` };
  if (value.aud !== expected.audience)
    return { rejected: 'audience', message: 'The token is for another audience' };
  if (expected.tenantId !== undefined && value.tenant_id !== expected.tenantId)
    return { rejected: 'tenant', message: 'The token is from another organization' };
  const iat = value.iat as number;
  const nbf = value.nbf as number;
  const exp = value.exp as number;
  if (exp <= iat || nbf < iat || exp - iat > delegationTokenLimits.maxSeconds)
    return { rejected: 'lifetime', message: 'The token lives longer than a delegation token may' };
  // A NaN or infinite tolerance (or clock) would make every time comparison below false and accept any token.
  const toleranceSeconds = expected.clockToleranceSeconds ?? 30;
  if (
    typeof toleranceSeconds !== 'number' ||
    !Number.isFinite(toleranceSeconds) ||
    toleranceSeconds < 0 ||
    toleranceSeconds > 300 ||
    typeof expected.now !== 'number' ||
    !Number.isFinite(expected.now)
  )
    throw new TypeError('clockToleranceSeconds must be 0 to 300 seconds and now a finite time');
  const tolerance = toleranceSeconds * 1000;
  if (exp * 1000 <= expected.now - tolerance)
    return { rejected: 'expired', message: 'The token has expired' };
  if (nbf * 1000 > expected.now + tolerance || iat * 1000 > expected.now + tolerance)
    return { rejected: 'not-yet-valid', message: 'The token is not valid yet' };
  return {
    token: {
      issuer: value.iss as string,
      personId: value.sub as string,
      tenantId: value.tenant_id as string,
      delegationId: value.delegation_id as string,
      agentId: actors[0]!,
      chain: [...actors].reverse(),
      scopes,
      audience: value.aud as string,
      tokenId: value.jti as string,
      issuedAt: iat * 1000,
      expiresAt: exp * 1000,
      claims: value as unknown as DelegationTokenClaims,
    },
  };
}

/** The `act` claim for a chain of agents, the person's own delegate first and the agent acting now last. */
export function delegationActor(chain: readonly string[]): DelegationActor {
  if (!chain.length) throw new TypeError('A delegation token needs at least one actor');
  let actor: DelegationActor | undefined;
  for (const sub of chain) actor = actor ? { sub, act: actor } : { sub };
  return actor!;
}
