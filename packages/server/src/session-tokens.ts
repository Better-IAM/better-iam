/**
 * Verification of IAM-signed session JWTs (`format: 'jwt'` role sessions and session tokens) for downstream services.
 *
 * Runtime-neutral: this module imports only `jose` (plus types), never `node:*`, so it runs in Node, Bun, Deno,
 * workers and edge runtimes. It is published as `@better-iam/server/session-tokens` and re-exported by the umbrella
 * as `better-iam/session-tokens`. IAM itself verifies with the same code path before it checks the stored row.
 *
 * Offline verification learns of revocation only at `exp`; use short lifetimes for high-risk services, or an online
 * check (`sts.getCallerIdentity`, or `iam.sessionTokens.verify` in process).
 */
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  decodeProtectedHeader,
  errors,
  jwtVerify,
  type JWSHeaderParameters,
  type JWTPayload,
  type JWTVerifyGetKey,
  type JSONWebKeySet,
} from 'jose';

/** The `typ` header of every IAM session JWT; other token classes (assertions, OAuth `at+jwt`) never carry it. */
export const SESSION_TOKEN_TYPE = 'biam-session+jwt';
/** The only signature algorithms IAM issues or accepts for session JWTs. */
export const SESSION_TOKEN_ALGORITHMS = ['EdDSA', 'ES256'] as const;
/** Longest accepted compact serialization, in characters. */
export const MAX_SESSION_TOKEN_LENGTH = 4096;

export type SessionTokenAlgorithm = (typeof SESSION_TOKEN_ALGORITHMS)[number];
/** The session kinds that may be issued as JWTs. User sessions and API keys are never JWTs. */
export type SessionTokenKind = 'role' | 'session-token';

/** The claims of an IAM session JWT. Tags, policies, authority ids and hashes are never included. */
export interface SessionTokenClaims {
  iss: string;
  /** One audience as a string, several as an array; always includes the IAM issuer for tokens IAM accepts. */
  aud: string | string[];
  /** The identity the session acts as. */
  sub: string;
  /** The tenant the session belongs to. */
  tid: string;
  /** The session id; equal to `jti`. */
  sid: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  /** When the credential behind the session was authenticated (epoch seconds). */
  auth_time: number;
  kind: SessionTokenKind;
  mfa: boolean;
  role?: string;
  trust?: string;
  src_tid?: string;
  session_name?: string;
  source_identity?: string;
  /** The OIDC provider id of a web-identity role session. */
  idp?: string;
  /** The verified external subject of a web-identity role session. */
  idp_sub?: string;
}

/** A public signing key as published at `{basePath}/.well-known/jwks.json`. */
export interface PublicSessionJwk {
  kty: 'OKP' | 'EC';
  crv: 'Ed25519' | 'P-256';
  x: string;
  y?: string;
  kid: string;
  alg: SessionTokenAlgorithm;
  use: 'sig';
}

export type SessionTokenErrorReason =
  | 'malformed'
  | 'too-large'
  | 'type'
  | 'algorithm'
  | 'unknown-key'
  | 'signature'
  | 'expired'
  | 'not-yet-valid'
  | 'issuer'
  | 'audience'
  | 'claims'
  | 'lifetime'
  | 'kind'
  | 'jwks'
  | 'revoked';

/** Every verification failure. `reason` is for logs and metrics; clients should only see the 401. */
export class SessionTokenError extends Error {
  readonly code = 'INVALID_SESSION_TOKEN';
  readonly status = 401;
  constructor(
    readonly reason: SessionTokenErrorReason,
    message = 'The session token is invalid or expired',
  ) {
    super(message);
    this.name = 'SessionTokenError';
  }
}

export interface SessionTokenVerifierOptions {
  /** The IAM issuer, exactly: `${baseURL.origin}${basePath}` unless `sts.jwt.issuer` overrides it. */
  issuer: string;
  /** The audiences this service accepts; a token must name at least one of them. */
  audience: string | string[];
  /**
   * The public keys: a JWK set (for example `iam.sessionTokens.jwks()`), or the URL of the JWKS route, which must be
   * https except on localhost. A remote set is cached and refetched on an unknown `kid`, at most once per cooldown.
   */
  jwks: { keys: readonly object[] } | URL | string;
  /** A subset of `SESSION_TOKEN_ALGORITHMS` (default both). */
  algorithms?: SessionTokenAlgorithm[];
  /** The session kinds accepted (default both). */
  kinds?: SessionTokenKind[];
  /** Tolerated clock skew for `exp` and `nbf`, 0..60 seconds (default 5). */
  clockToleranceSeconds?: number;
  /** Longest accepted `exp - iat` in seconds (default 43200). */
  maxLifetimeSeconds?: number;
  /** The clock, in epoch milliseconds (default `Date.now`). */
  now?: () => number;
  /** Remote JWKS: cache lifetime in seconds (default 600). */
  cacheMaxAgeSeconds?: number;
  /** Remote JWKS: minimum seconds between refetches triggered by an unknown `kid` (default 30). */
  cooldownSeconds?: number;
  /** Remote JWKS: fetch timeout in milliseconds (default 5000). */
  timeoutMs?: number;
}

export interface SessionTokenVerifier {
  /** Verifies a compact session JWT and returns its claims, or throws `SessionTokenError`. */
  verify(token: string): Promise<SessionTokenClaims>;
  /** Verifies the `Authorization: Bearer <jwt>` header of a request (the scheme is case-insensitive). */
  verifyRequest(request: { headers: Headers | HeadersInit }): Promise<SessionTokenClaims>;
}

const segments = /^[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}$/;
const bearer = /^Bearer (\S+)$/i;
const kidPattern = /^[A-Za-z0-9._-]{1,64}$/;
const tokenKinds: readonly SessionTokenKind[] = ['role', 'session-token'];
const optionalStringClaims = [
  'role',
  'trust',
  'src_tid',
  'session_name',
  'source_identity',
  'idp',
  'idp_sub',
] as const;

/** True for a compact JWS shape (three base64url segments); says nothing about validity. */
export function looksLikeJwt(value: unknown): value is string {
  return typeof value === 'string' && segments.test(value);
}

/** Raised by the key resolver when the key set itself cannot be obtained; mapped to reason `jwks`. */
class KeySetUnavailable extends Error {}

function invalidOption(name: string): never {
  throw new TypeError(`Invalid session token verifier option: ${name}`);
}
function seconds(value: unknown, fallback: number, name: string, min: number, max: number) {
  const result = value ?? fallback;
  if (typeof result !== 'number' || !Number.isFinite(result) || result < min || result > max)
    invalidOption(name);
  return result;
}
function remoteUrl(value: URL | string): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return invalidOption('jwks');
  }
  const local = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
  if (url.protocol !== 'https:' && !(local && url.protocol === 'http:')) invalidOption('jwks');
  if (url.username || url.password || url.hash) invalidOption('jwks');
  return url;
}

/** Maps jose errors to failure reasons; anything unrecognised is `malformed`. */
function reasonFor(error: unknown): SessionTokenErrorReason {
  if (error instanceof SessionTokenError) return error.reason;
  if (error instanceof KeySetUnavailable) return 'jwks';
  if (error instanceof errors.JWTExpired) return 'expired';
  if (error instanceof errors.JWTClaimValidationFailed) {
    if (error.claim === 'typ') return 'type';
    if (error.reason === 'missing' || error.reason === 'invalid') return 'claims';
    if (error.claim === 'iss') return 'issuer';
    if (error.claim === 'aud') return 'audience';
    if (error.claim === 'nbf' || error.claim === 'iat') return 'not-yet-valid';
    return 'claims';
  }
  if (error instanceof errors.JOSEAlgNotAllowed) return 'algorithm';
  if (error instanceof errors.JWKSNoMatchingKey) return 'unknown-key';
  if (error instanceof errors.JWKSMultipleMatchingKeys) return 'unknown-key';
  if (error instanceof errors.JWSSignatureVerificationFailed) return 'signature';
  if (error instanceof errors.JWKSTimeout || error instanceof errors.JWKSInvalid) return 'jwks';
  return 'malformed';
}

const nonEmpty = (value: unknown, max = 256): value is string =>
  typeof value === 'string' && value.length > 0 && value.length <= max;
const numeric = (value: unknown): value is number =>
  typeof value === 'number' && Number.isFinite(value);

/** Checks claim types and returns an allowlisted copy; unknown claims are dropped. */
function claimsOf(payload: JWTPayload): SessionTokenClaims {
  const aud = payload.aud;
  const audienceValid =
    nonEmpty(aud, 2048) ||
    (Array.isArray(aud) && aud.length > 0 && aud.every((item) => nonEmpty(item, 2048)));
  if (
    !nonEmpty(payload.iss, 2048) ||
    !audienceValid ||
    !nonEmpty(payload.sub) ||
    !nonEmpty(payload.tid) ||
    !nonEmpty(payload.sid) ||
    payload.jti !== payload.sid ||
    !numeric(payload.iat) ||
    !numeric(payload.nbf) ||
    !numeric(payload.exp) ||
    !numeric(payload.auth_time) ||
    typeof payload.mfa !== 'boolean'
  )
    throw new SessionTokenError('claims');
  const claims: SessionTokenClaims = {
    iss: payload.iss,
    aud: Array.isArray(aud) ? [...(aud as string[])] : (aud as string),
    sub: payload.sub,
    tid: payload.tid,
    sid: payload.sid,
    jti: payload.sid,
    iat: payload.iat,
    nbf: payload.nbf,
    exp: payload.exp,
    auth_time: payload.auth_time,
    kind: payload.kind as SessionTokenKind,
    mfa: payload.mfa,
  };
  for (const name of optionalStringClaims) {
    const value = payload[name];
    if (value === undefined) continue;
    if (!nonEmpty(value, 1024)) throw new SessionTokenError('claims');
    claims[name] = value;
  }
  return claims;
}

/**
 * Creates an offline verifier for IAM session JWTs. It enforces the `biam-session+jwt` type, the EdDSA/ES256
 * allowlist (pinned to each key's `alg` for a local key set), the exact issuer, one of the configured audiences,
 * `exp`/`nbf` with clock tolerance, the lifetime cap, the accepted kinds and the claim types.
 */
export function createSessionTokenVerifier(
  options: SessionTokenVerifierOptions,
): SessionTokenVerifier {
  if (!options || !nonEmpty(options.issuer, 2048)) invalidOption('issuer');
  const audience = Array.isArray(options.audience) ? [...options.audience] : [options.audience];
  if (!audience.length || !audience.every((item) => nonEmpty(item, 2048)))
    invalidOption('audience');
  const algorithms = [...(options.algorithms ?? SESSION_TOKEN_ALGORITHMS)];
  if (
    !algorithms.length ||
    !algorithms.every((alg) => (SESSION_TOKEN_ALGORITHMS as readonly string[]).includes(alg))
  )
    invalidOption('algorithms');
  const kinds = [...(options.kinds ?? tokenKinds)];
  if (!kinds.length || !kinds.every((kind) => tokenKinds.includes(kind))) invalidOption('kinds');
  const clockTolerance = seconds(options.clockToleranceSeconds, 5, 'clockToleranceSeconds', 0, 60);
  const maxLifetime = seconds(
    options.maxLifetimeSeconds,
    43200,
    'maxLifetimeSeconds',
    1,
    10 * 365 * 86400,
  );
  const now = options.now ?? Date.now;
  if (typeof now !== 'function') invalidOption('now');

  let resolveKey: JWTVerifyGetKey;
  // For a local set the algorithm is pinned per kid before any cryptography runs.
  let pinned: Map<string, string> | undefined;
  if (options.jwks instanceof URL || typeof options.jwks === 'string') {
    const remote = createRemoteJWKSet(remoteUrl(options.jwks), {
      timeoutDuration: seconds(options.timeoutMs, 5000, 'timeoutMs', 1, 60_000),
      cooldownDuration: seconds(options.cooldownSeconds, 30, 'cooldownSeconds', 0, 86400) * 1000,
      cacheMaxAge: seconds(options.cacheMaxAgeSeconds, 600, 'cacheMaxAgeSeconds', 1, 86400) * 1000,
    });
    resolveKey = async (header, token) => {
      try {
        return await remote(header, token);
      } catch (error) {
        if (
          error instanceof errors.JWKSNoMatchingKey ||
          error instanceof errors.JWKSMultipleMatchingKeys
        )
          throw error;
        throw new KeySetUnavailable();
      }
    };
  } else {
    const keys = options.jwks?.keys;
    if (!Array.isArray(keys)) invalidOption('jwks');
    pinned = new Map();
    for (const key of keys as readonly Record<string, unknown>[]) {
      if (!key || typeof key !== 'object') invalidOption('jwks');
      if (typeof key.kid === 'string' && typeof key.alg === 'string') pinned.set(key.kid, key.alg);
    }
    let local: ReturnType<typeof createLocalJWKSet>;
    try {
      local = createLocalJWKSet({ keys: keys as JSONWebKeySet['keys'] });
    } catch {
      return invalidOption('jwks');
    }
    resolveKey = (header, token) => local(header, token);
  }

  async function verify(token: string): Promise<SessionTokenClaims> {
    try {
      if (typeof token !== 'string') throw new SessionTokenError('malformed');
      if (token.length > MAX_SESSION_TOKEN_LENGTH) throw new SessionTokenError('too-large');
      if (!looksLikeJwt(token)) throw new SessionTokenError('malformed');
      let header: JWSHeaderParameters;
      try {
        header = decodeProtectedHeader(token);
      } catch {
        throw new SessionTokenError('malformed');
      }
      if (typeof header.kid !== 'string' || !kidPattern.test(header.kid))
        throw new SessionTokenError('unknown-key');
      if (typeof header.alg !== 'string' || !(algorithms as string[]).includes(header.alg))
        throw new SessionTokenError('algorithm');
      if (pinned) {
        const alg = pinned.get(header.kid);
        if (alg === undefined) throw new SessionTokenError('unknown-key');
        if (alg !== header.alg) throw new SessionTokenError('algorithm');
      }
      const { payload } = await jwtVerify(token, resolveKey, {
        algorithms,
        issuer: options.issuer,
        audience,
        typ: SESSION_TOKEN_TYPE,
        clockTolerance,
        currentDate: new Date(now()),
        requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat', 'sid', 'tid', 'kind'],
      });
      if (typeof payload.kind !== 'string' || !(kinds as string[]).includes(payload.kind))
        throw new SessionTokenError('kind');
      if (!numeric(payload.exp) || !numeric(payload.iat) || payload.exp - payload.iat > maxLifetime)
        throw new SessionTokenError('lifetime');
      return claimsOf(payload);
    } catch (error) {
      if (error instanceof SessionTokenError) throw error;
      throw new SessionTokenError(reasonFor(error));
    }
  }

  return {
    verify,
    async verifyRequest(request) {
      let authorization: string | null;
      try {
        authorization = new Headers(request?.headers).get('authorization');
      } catch {
        authorization = null;
      }
      const match = bearer.exec(authorization ?? '');
      if (!match) throw new SessionTokenError('malformed', 'A bearer session token is required');
      return verify(match[1]!);
    },
  };
}
