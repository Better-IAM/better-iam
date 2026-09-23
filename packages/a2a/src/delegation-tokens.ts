import {
  delegationTokenType,
  readDelegationTokenClaims,
  type DelegationTokenRejection,
  type DelegationTokenSummary,
} from '@better-iam/core';
import {
  AgentCardError,
  fetchJwks,
  fromBase64Url,
  plain,
  verifySignature,
  type CardJwk,
  type CardJwks,
} from './cards.js';

/**
 * Delegation tokens for services outside Better IAM: an agent acting for a person gets one from
 * `delegations.issueToken` and presents it (typically as a bearer token); the service checks it here, offline, with the
 * issuing deployment's public keys (the same JWKS as its agent cards). The token says who the person is (`personId`),
 * which agent acts for them (`agentId`, and `chain` when the work was handed on between agents), which organization,
 * and which scopes of the delegation it carries. The service still decides what that person may do.
 */

export type DelegationTokenErrorReason =
  | DelegationTokenRejection
  | 'type'
  | 'untrusted-key'
  | 'signature'
  | 'replay'
  | 'fetch';

/**
 * Why `verifyDelegationToken` refused a token: `reason` is `malformed`, `type`, `issuer`, `untrusted-key`,
 * `signature`, `audience`, `tenant`, `expired`, `not-yet-valid`, `lifetime`, `replay` or `fetch`.
 */
export class DelegationTokenError extends Error {
  constructor(
    public readonly reason: DelegationTokenErrorReason,
    message: string,
  ) {
    super(message);
    this.name = 'DelegationTokenError';
  }
}

export interface VerifyDelegationTokenOptions {
  /** The audience your service answers to: the token's `aud` must be exactly this. */
  audience: string;
  /**
   * The Better IAM deployments you trust, by issuer (their `a2a` issuer): each one's JWKS URL (`a2a.jwksUrl`) or its
   * JWKS. A token is checked only with the keys of the issuer it names.
   */
  trustedIssuers: Record<string, string | CardJwks>;
  /** Accept only tokens of this organization (tenant id). */
  tenantId?: string;
  /**
   * Records a verified token's id until it expires; return false when the id was seen before to refuse the replay.
   * Without it a token may be used again until it expires (at most an hour, usually five minutes).
   */
  replay?: (tokenId: string, expiresAt: number) => boolean | Promise<boolean>;
  /** Allowed clock difference in seconds (default 30). */
  clockToleranceSeconds?: number;
  /** How long fetched key sets are kept, in seconds (default 300). */
  jwksCacheSeconds?: number;
  now?: () => number;
  fetch?: typeof fetch;
}

const decodeJson = (part: string): unknown => {
  try {
    return JSON.parse(new TextDecoder().decode(fromBase64Url(part)));
  } catch {
    return undefined;
  }
};

/**
 * Verifies a delegation token: a compact JWT of type `biam-delegation+jwt`, signed (EdDSA or ES256) by a key of the
 * trusted issuer it names, for exactly `audience` (and `tenantId`), current, and issued for at most an hour. Returns
 * who acts for whom; throws `DelegationTokenError` otherwise. Revocation reaches a token only when it expires, so keep
 * lifetimes short, or verify inside the deployment with `iam.a2a.verifyDelegationToken(token, { live: true })`.
 */
export async function verifyDelegationToken(
  token: string,
  options: VerifyDelegationTokenOptions,
): Promise<DelegationTokenSummary> {
  if (!options?.trustedIssuers || typeof options.audience !== 'string' || !options.audience)
    throw new TypeError('verifyDelegationToken needs audience and trustedIssuers');
  if (typeof token !== 'string' || token.length > 16_384)
    throw new DelegationTokenError('malformed', 'Not a delegation token');
  const parts = token.split('.');
  if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]+$/.test(part)))
    throw new DelegationTokenError('malformed', 'Not a compact JWT');
  const [protectedHeader, payload, signaturePart] = parts as [string, string, string];
  const header = decodeJson(protectedHeader);
  const claims = decodeJson(payload);
  if (!plain(header) || !plain(claims))
    throw new DelegationTokenError('malformed', 'The token is not a JWT');
  if (header.typ !== delegationTokenType)
    throw new DelegationTokenError('type', 'The token is not a delegation token');
  const alg = header.alg;
  const kid = header.kid;
  if (
    (alg !== 'EdDSA' && alg !== 'ES256') ||
    typeof kid !== 'string' ||
    header.crit !== undefined ||
    header.b64 !== undefined
  )
    throw new DelegationTokenError('malformed', 'The token header is not acceptable');
  // The issuer is read before the signature is checked only to pick its keys; the signature then binds the two.
  const issuer = claims.iss;
  if (typeof issuer !== 'string' || !Object.hasOwn(options.trustedIssuers, issuer))
    throw new DelegationTokenError('issuer', `The token was issued by ${String(issuer)}`);
  const source = options.trustedIssuers[issuer]!;
  const now = (options.now ?? Date.now)();
  const fetcher = options.fetch ?? globalThis.fetch;
  const pick = (jwks: CardJwks) =>
    jwks.keys.find(
      (key: CardJwk) =>
        key.kid === kid && (key.alg === undefined || key.alg === alg) && key.use !== 'enc',
    );
  let jwk: CardJwk | undefined;
  try {
    if (typeof source === 'string') {
      const cacheSeconds = options.jwksCacheSeconds ?? 300;
      jwk =
        pick(await fetchJwks(source, fetcher, now, cacheSeconds)) ??
        pick(await fetchJwks(source, fetcher, now, cacheSeconds, true));
    } else jwk = pick(source);
  } catch (error) {
    if (error instanceof AgentCardError && error.reason !== 'fetch')
      throw new DelegationTokenError('untrusted-key', error.message);
    throw new DelegationTokenError('fetch', `Could not fetch the keys of ${issuer}`);
  }
  if (!jwk)
    throw new DelegationTokenError('untrusted-key', 'The token is not signed with a trusted key');
  let signature: Uint8Array<ArrayBuffer>;
  try {
    signature = fromBase64Url(signaturePart);
  } catch {
    throw new DelegationTokenError('malformed', 'The token signature is not base64url');
  }
  const signingInput = new TextEncoder().encode(`${protectedHeader}.${payload}`);
  if (!(await verifySignature(jwk, alg, signingInput, signature)))
    throw new DelegationTokenError('signature', 'The token signature does not verify');
  const read = readDelegationTokenClaims(claims, {
    issuer,
    audience: options.audience,
    now,
    ...(options.tenantId !== undefined ? { tenantId: options.tenantId } : {}),
    ...(options.clockToleranceSeconds !== undefined
      ? { clockToleranceSeconds: options.clockToleranceSeconds }
      : {}),
  });
  if ('rejected' in read) throw new DelegationTokenError(read.rejected, read.message);
  if (options.replay && !(await options.replay(read.token.tokenId, read.token.expiresAt)))
    throw new DelegationTokenError('replay', 'The token was used before');
  return read.token;
}

export interface DelegationTokenCacheOptions {
  /**
   * Gets a new token, for example
   * `(audience, scopes) => iam.api.delegations.issueToken({ token: delegatedToken }, { tenantId, audience, scopes })`.
   */
  issue(
    audience: string,
    scopes: string[] | undefined,
  ): Promise<{ token: string; expiresAt: number }>;
  /** Get a new token once less than this share of its lifetime is left (default 0.2), or 15 seconds. */
  refreshShare?: number;
  now?: () => number;
}

/**
 * For the agent side: returns a function yielding a current delegation token for an audience (and scopes), issuing one
 * on first use and again when it nears its end, so an agent calling a service repeatedly does not ask for a token on
 * every call. Concurrent calls for the same audience share one request.
 */
export function createDelegationTokenCache(
  options: DelegationTokenCacheOptions,
): (audience: string, scopes?: string[]) => Promise<string> {
  const now = options.now ?? Date.now;
  const share = options.refreshShare ?? 0.2;
  const tokens = new Map<string, { token: string; issuedAt: number; expiresAt: number }>();
  const pending = new Map<string, Promise<string>>();
  return (audience, scopes) => {
    const key = JSON.stringify([audience, scopes ? [...scopes].sort() : null]);
    const current = tokens.get(key);
    const at = now();
    if (current) {
      const left = current.expiresAt - at;
      if (left > Math.max(15_000, (current.expiresAt - current.issuedAt) * share))
        return Promise.resolve(current.token);
    }
    const running = pending.get(key);
    if (running) return running;
    const run = (async () => {
      try {
        const issued = await options.issue(audience, scopes);
        tokens.set(key, { token: issued.token, issuedAt: at, expiresAt: issued.expiresAt });
        if (tokens.size > 256) tokens.delete(tokens.keys().next().value!);
        return issued.token;
      } finally {
        pending.delete(key);
      }
    })();
    pending.set(key, run);
    return run;
  };
}
