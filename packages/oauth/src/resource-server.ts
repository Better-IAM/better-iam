import { createHash } from 'node:crypto';
import {
  EmbeddedJWK,
  calculateJwkThumbprint,
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeProtectedHeader,
  jwtVerify,
  type JSONWebKeySet,
  type JWK,
  type JWTPayload,
} from 'jose';
import { IamError } from '@better-iam/core';

export interface AccessTokenVerifierOptions {
  /** The authorization server issuer, exactly as in its discovery document. */
  issuer: string;
  /** The `aud` this API accepts: its resource indicator or the configured resource server `audience`. */
  audience: string | string[];
  /** Public signing keys; defaults to fetching `{issuer}/jwks` (cached, refreshed on unknown `kid`). */
  jwks?: JSONWebKeySet;
  jwksUri?: string;
  /** Seconds of clock skew tolerated for `exp`, `nbf`, and DPoP `iat` (default 30). */
  clockTolerance?: number;
  /** Maximum age of a DPoP proof in seconds (default 300). */
  dpopMaxAge?: number;
  /** Signature algorithms accepted for access tokens (default asymmetric JOSE algorithms). */
  algorithms?: string[];
  /**
   * The organization this API serves. Resource servers are deployment-wide, so any tenant's client may be given tokens
   * for this audience: an API that serves one organization (and does not scope its data by `tenantId` itself) sets this
   * to refuse tokens of every other tenant.
   */
  tenantId?: string;
}

/** The request parts a DPoP-aware API check needs. */
export interface ProtectedRequest {
  /** The `Authorization` header: `Bearer <token>` or `DPoP <token>`. */
  authorization: string | null | undefined;
  /** The `DPoP` proof header, required with the `DPoP` scheme. */
  dpop?: string | null;
  method: string;
  /** The absolute request URL; query and fragment are ignored for `htu`. */
  url: string;
}

export interface VerifiedAccessToken {
  /** The account, or the client for client-credentials tokens. */
  subject?: string;
  clientId: string;
  tenantId?: string;
  /** The service account behind a client-credentials client. */
  identityId?: string;
  scopes: string[];
  audience: string[];
  issuedAt?: number;
  expiresAt: number;
  tokenId?: string;
  /** JWK SHA-256 thumbprint the token is bound to (DPoP). */
  boundKey?: string;
  /** The delegation chain of an exchanged token (RFC 8693 `act`): the client acting for `subject`. */
  actor?: { sub: string; act?: unknown };
  claims: JWTPayload;
}

const asymmetric = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
  'Ed25519',
];

function invalid(message: string): IamError {
  return new IamError('INVALID_TOKEN', message, 401);
}
const base64url = (value: string) => createHash('sha256').update(value).digest('base64url');
function targetUri(value: string): string {
  const url = new URL(value);
  url.search = '';
  url.hash = '';
  return url.href;
}

/**
 * Offline verification of JWT access tokens issued for a resource server (RFC 9068), including DPoP proof of
 * possession (RFC 9449) with in-memory proof replay detection. Opaque tokens need the provider's introspection.
 */
export function createAccessTokenVerifier(options: AccessTokenVerifierOptions) {
  const issuer = options.issuer.replace(/\/$/, '');
  // The provider writes `iss` exactly as its issuer is configured, trailing slash included; both spellings are accepted.
  const issuers = [...new Set([options.issuer, issuer])];
  const keys = options.jwks
    ? createLocalJWKSet(options.jwks)
    : createRemoteJWKSet(new URL(options.jwksUri ?? `${issuer}/jwks`));
  const clockTolerance = options.clockTolerance ?? 30;
  const dpopMaxAge = options.dpopMaxAge ?? 300;
  const algorithms = options.algorithms ?? asymmetric;
  const seenProofs = new Map<string, number>();

  /**
   * Refuses a proof seen before, remembering each one until it can no longer be accepted: a proof is valid while
   * `iat` is at most `clockTolerance` ahead and `dpopMaxAge` (plus tolerance) behind, so one issued slightly in the
   * future stays usable up to `iat + dpopMaxAge + clockTolerance`. Expired entries are pruned from the oldest end, so
   * each request does a bounded amount of work however many proofs are remembered.
   */
  function rememberProof(jti: string, keyThumbprint: string, issuedAt: number): void {
    const now = Date.now();
    for (const [key, expires] of seenProofs) {
      if (expires > now) break;
      seenProofs.delete(key);
    }
    const key = `${keyThumbprint}:${jti}`;
    const seen = seenProofs.get(key);
    if (seen !== undefined && seen > now) throw invalid('DPoP proof was already used.');
    const until = Math.max(now, issuedAt * 1000) + (dpopMaxAge + clockTolerance) * 1000;
    seenProofs.delete(key);
    seenProofs.set(key, until);
  }

  async function verifyToken(token: string): Promise<VerifiedAccessToken> {
    let payload: JWTPayload;
    try {
      ({ payload } = await jwtVerify(token, keys, {
        issuer: issuers,
        audience: options.audience,
        typ: 'at+jwt',
        clockTolerance,
        algorithms,
        requiredClaims: ['exp', 'client_id'],
      }));
    } catch {
      throw invalid('The access token is invalid or expired.');
    }
    if (options.tenantId !== undefined && payload.tenant_id !== options.tenantId)
      throw invalid('The access token was issued for another organization.');
    const cnf = payload.cnf as { jkt?: unknown } | undefined;
    return {
      ...(typeof payload.sub === 'string' ? { subject: payload.sub } : {}),
      clientId: String(payload.client_id),
      ...(typeof payload.tenant_id === 'string' ? { tenantId: payload.tenant_id } : {}),
      ...(typeof payload.identity_id === 'string' ? { identityId: payload.identity_id } : {}),
      scopes: typeof payload.scope === 'string' ? payload.scope.split(' ').filter(Boolean) : [],
      audience: Array.isArray(payload.aud) ? payload.aud : payload.aud ? [payload.aud] : [],
      ...(typeof payload.iat === 'number' ? { issuedAt: payload.iat } : {}),
      expiresAt: payload.exp!,
      ...(typeof payload.jti === 'string' ? { tokenId: payload.jti } : {}),
      ...(typeof cnf?.jkt === 'string' ? { boundKey: cnf.jkt } : {}),
      ...(payload.act && typeof (payload.act as { sub?: unknown }).sub === 'string'
        ? { actor: payload.act as { sub: string; act?: unknown } }
        : {}),
      claims: payload,
    };
  }

  async function verifyProof(
    proof: string,
    token: string,
    request: ProtectedRequest,
    boundKey: string,
  ): Promise<void> {
    let payload: JWTPayload;
    let jwk: JWK | undefined;
    try {
      jwk = decodeProtectedHeader(proof).jwk;
      ({ payload } = await jwtVerify(proof, EmbeddedJWK, {
        typ: 'dpop+jwt',
        algorithms: asymmetric,
        maxTokenAge: dpopMaxAge,
        clockTolerance,
        requiredClaims: ['iat', 'jti', 'htm', 'htu', 'ath'],
      }));
    } catch {
      throw invalid('The DPoP proof is invalid.');
    }
    if (!jwk || (await calculateJwkThumbprint(jwk, 'sha256')) !== boundKey)
      throw invalid('The DPoP proof key does not match the token binding.');
    let htu: string;
    try {
      htu = targetUri(String(payload.htu));
    } catch {
      throw invalid('The DPoP proof target is invalid.');
    }
    if (
      payload.htm !== request.method.toUpperCase() ||
      htu !== targetUri(request.url) ||
      payload.ath !== base64url(token)
    )
      throw invalid('The DPoP proof does not match this request.');
    rememberProof(String(payload.jti), boundKey, Number(payload.iat));
  }

  function requireScopes(verified: VerifiedAccessToken, scopes: string[] | undefined): void {
    const missing = (scopes ?? []).filter((scope) => !verified.scopes.includes(scope));
    if (missing.length)
      throw new IamError('INSUFFICIENT_SCOPE', `Missing scope: ${missing.join(' ')}.`, 403);
  }

  return {
    /**
     * Verifies a bearer access token string. Sender-constrained (DPoP-bound) tokens are rejected here because their
     * proof cannot be checked; use `verifyRequest` for them.
     */
    async verify(token: string, requirement: { scopes?: string[] } = {}) {
      const verified = await verifyToken(token);
      if (verified.boundKey) throw invalid('A DPoP-bound token requires a DPoP proof.');
      requireScopes(verified, requirement.scopes);
      return verified;
    },
    /** Verifies the `Authorization` header of a request, checking the DPoP proof when the token is bound. */
    async verifyRequest(request: ProtectedRequest, requirement: { scopes?: string[] } = {}) {
      const match = /^(Bearer|DPoP) ([A-Za-z0-9._~+/-]+=*)$/i.exec(request.authorization ?? '');
      if (!match) throw invalid('An access token is required.');
      const scheme = match[1]!.toLowerCase();
      const token = match[2]!;
      const verified = await verifyToken(token);
      if (verified.boundKey) {
        if (scheme !== 'dpop' || !request.dpop)
          throw invalid('A DPoP-bound token requires the DPoP scheme and proof.');
        await verifyProof(request.dpop, token, request, verified.boundKey);
      } else if (scheme === 'dpop') throw invalid('The access token is not DPoP-bound.');
      requireScopes(verified, requirement.scopes);
      return verified;
    },
    /**
     * A `WWW-Authenticate` challenge for a failed verification. `resourceMetadata` (RFC 9728) points clients such as
     * MCP hosts at the protected resource metadata, from which they discover the authorization server; `scopes` names
     * what an `insufficient_scope` failure needs.
     */
    challenge(
      error: unknown,
      realm?: string,
      options: { resourceMetadata?: string; scopes?: string[] } = {},
    ): string {
      const code =
        error instanceof IamError && error.code === 'INSUFFICIENT_SCOPE'
          ? 'insufficient_scope'
          : 'invalid_token';
      const quoted = (value: string) => value.replace(/["\\]/g, '');
      const shared = [
        ...(realm ? [`realm="${quoted(realm)}"`] : []),
        `error="${code}"`,
        ...(options.resourceMetadata
          ? [`resource_metadata="${quoted(options.resourceMetadata)}"`]
          : []),
        ...(code === 'insufficient_scope' && options.scopes?.length
          ? [`scope="${quoted(options.scopes.join(' '))}"`]
          : []),
      ];
      const algs = `algs="${asymmetric.filter((alg) => alg !== 'Ed25519').join(' ')}"`;
      return `DPoP ${[...shared, algs].join(', ')}, Bearer ${shared.join(', ')}`;
    },
  };
}

export type AccessTokenVerifier = ReturnType<typeof createAccessTokenVerifier>;

/** RFC 9728 protected resource metadata for one API. */
export interface ProtectedResourceMetadataOptions {
  /** The API's resource identifier: the resource indicator its access tokens are issued for. */
  resource: string;
  /** Issuer URLs of the authorization servers that issue tokens for it. */
  authorizationServers: string[];
  scopes?: string[];
  resourceName?: string;
  /** A page describing the API for developers. */
  documentation?: string;
  /** Advertise that only DPoP-bound access tokens are accepted. */
  requireDpop?: boolean;
}

function absolute(value: string, label: string): URL {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new IamError('configuration', `${label} must be an absolute URL.`);
  }
  if (parsed.hash || parsed.username || parsed.password)
    throw new IamError('configuration', `${label} cannot carry a fragment or credentials.`);
  return parsed;
}

/** The metadata document (RFC 9728 §2) clients fetch to find the authorization server for an API. */
export function protectedResourceMetadata(options: ProtectedResourceMetadataOptions) {
  absolute(options.resource, 'The resource');
  if (!options.authorizationServers?.length)
    throw new IamError('configuration', 'At least one authorization server is required.');
  for (const server of options.authorizationServers) absolute(server, 'An authorization server');
  return {
    resource: options.resource,
    authorization_servers: [...options.authorizationServers],
    ...(options.scopes?.length ? { scopes_supported: [...options.scopes] } : {}),
    bearer_methods_supported: ['header'],
    ...(options.resourceName ? { resource_name: options.resourceName } : {}),
    ...(options.documentation ? { resource_documentation: options.documentation } : {}),
    dpop_signing_alg_values_supported: asymmetric.filter((alg) => alg !== 'Ed25519'),
    ...(options.requireDpop ? { dpop_bound_access_tokens_required: true } : {}),
  };
}

/** Where the metadata lives: `/.well-known/oauth-protected-resource` inserted before the resource's path. */
export function protectedResourceMetadataUrl(resource: string): string {
  const parsed = absolute(resource, 'The resource');
  const path = parsed.pathname === '/' ? '' : parsed.pathname.replace(/\/$/, '');
  return `${parsed.origin}/.well-known/oauth-protected-resource${path}`;
}

/**
 * Serves the metadata document at its well-known path (GET, HEAD, and CORS preflight, readable from any origin);
 * returns undefined for every other request so it can sit in front of the API's own routing.
 */
export function createProtectedResourceHandler(options: ProtectedResourceMetadataOptions) {
  const document = JSON.stringify(protectedResourceMetadata(options));
  const path = new URL(protectedResourceMetadataUrl(options.resource)).pathname;
  const cors = {
    'access-control-allow-origin': '*',
    'access-control-allow-methods': 'GET, HEAD, OPTIONS',
  };
  return (request: Request): Response | undefined => {
    if (new URL(request.url).pathname !== path) return undefined;
    if (request.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (request.method !== 'GET' && request.method !== 'HEAD')
      return new Response(null, { status: 405, headers: { ...cors, allow: 'GET, HEAD, OPTIONS' } });
    return new Response(request.method === 'HEAD' ? null : document, {
      headers: {
        ...cors,
        'content-type': 'application/json',
        'cache-control': 'public, max-age=3600',
      },
    });
  };
}

export interface ResourceGuardOptions extends ProtectedResourceMetadataOptions {
  /** The token issuer to trust; defaults to the first authorization server. */
  issuer?: string;
  /** Accepted `aud` values; defaults to the resource identifier. */
  audience?: string | string[];
  jwks?: JSONWebKeySet;
  jwksUri?: string;
  clockTolerance?: number;
  /** Scopes every request needs; `check(request, { scopes })` adds per-route scopes. */
  requiredScopes?: string[];
  realm?: string;
  /** Refuses tokens of every other organization (see `AccessTokenVerifierOptions.tenantId`). */
  tenantId?: string;
}

/**
 * Everything an API (such as an MCP server) needs in front of its routes: it serves the RFC 9728 metadata document,
 * verifies bearer or DPoP access tokens, and answers failures with 401/403 and a `WWW-Authenticate` challenge that
 * names the metadata URL, so OAuth clients can discover the authorization server and try again.
 */
export function createResourceGuard(options: ResourceGuardOptions) {
  const metadata = createProtectedResourceHandler(options);
  const metadataUrl = protectedResourceMetadataUrl(options.resource);
  const verifier = createAccessTokenVerifier({
    issuer: options.issuer ?? options.authorizationServers[0]!,
    audience: options.audience ?? options.resource,
    ...(options.jwks ? { jwks: options.jwks } : {}),
    ...(options.jwksUri ? { jwksUri: options.jwksUri } : {}),
    ...(options.clockTolerance !== undefined ? { clockTolerance: options.clockTolerance } : {}),
    ...(options.tenantId !== undefined ? { tenantId: options.tenantId } : {}),
  });
  const quoted = (value: string) => value.replace(/["\\]/g, '');
  return {
    metadataUrl,
    verifier,
    /**
     * `{ response }` for the metadata document or a refusal (return it as is), `{ token }` for an authorized request.
     */
    async check(
      request: Request,
      requirement: { scopes?: string[] } = {},
    ): Promise<
      | { response: Response; token?: undefined }
      | { token: VerifiedAccessToken; response?: undefined }
    > {
      const served = metadata(request);
      if (served) return { response: served };
      const scopes = [
        ...new Set([...(options.requiredScopes ?? []), ...(requirement.scopes ?? [])]),
      ];
      const authorization = request.headers.get('authorization');
      if (!authorization)
        // RFC 6750 §3.1: no error code when the request carried no credentials at all.
        return {
          response: new Response(null, {
            status: 401,
            headers: {
              'cache-control': 'no-store',
              'www-authenticate': `Bearer ${[
                ...(options.realm ? [`realm="${quoted(options.realm)}"`] : []),
                `resource_metadata="${quoted(metadataUrl)}"`,
                ...(scopes.length ? [`scope="${quoted(scopes.join(' '))}"`] : []),
              ].join(', ')}`,
            },
          }),
        };
      try {
        const token = await verifier.verifyRequest(
          {
            authorization,
            dpop: request.headers.get('dpop'),
            method: request.method,
            url: request.url,
          },
          { scopes },
        );
        return { token };
      } catch (error) {
        if (!(error instanceof IamError)) throw error;
        const insufficient = error.code === 'INSUFFICIENT_SCOPE';
        return {
          response: Response.json(
            {
              error: insufficient ? 'insufficient_scope' : 'invalid_token',
              error_description: error.message,
            },
            {
              status: insufficient ? 403 : 401,
              headers: {
                'cache-control': 'no-store',
                'www-authenticate': verifier.challenge(error, options.realm, {
                  resourceMetadata: metadataUrl,
                  scopes,
                }),
              },
            },
          ),
        };
      }
    },
  };
}

export type ResourceGuard = ReturnType<typeof createResourceGuard>;
