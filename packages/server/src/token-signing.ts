import { createPrivateKey, createPublicKey } from 'node:crypto';
import { importJWK, SignJWT, type JWK, type JWTPayload } from 'jose';
import { IamError } from '@better-iam/core';
import type { SessionTokenSigningOptions } from './options.js';
import {
  createSessionTokenVerifier,
  SESSION_TOKEN_TYPE,
  SessionTokenError,
  type PublicSessionJwk,
  type SessionTokenAlgorithm,
  type SessionTokenClaims,
  type SessionTokenVerifier,
} from './session-tokens.js';

/**
 * Signs IAM session JWTs with the deployment's `sts.jwt` keys and verifies them with the same checks downstream
 * verifiers apply. Verification here proves only the signature and claims; IAM additionally requires the stored
 * session row (principals.ts), so revocation inside IAM is immediate.
 */
export interface SessionTokenSigner {
  /** The `iss` of every token. */
  readonly issuer: string;
  /** The audiences tokens may be issued for; always includes the issuer (first). */
  readonly audiences: readonly string[];
  /** Longest allowed `exp - iat`, in seconds. */
  readonly maxLifetimeSeconds: number;
  /** Signs the claims with the active key; the header is `{ alg, kid, typ: 'biam-session+jwt' }`. */
  sign(claims: SessionTokenClaims): Promise<string>;
  /** Verifies a token for `audience` (default: the issuer) with a 5 second clock tolerance. */
  verify(token: string, options?: { audience?: string }): Promise<SessionTokenClaims>;
  /** The public members of the signing and verification keys, for the JWKS route. */
  publicJwks(): { keys: PublicSessionJwk[] };
}

const kidPattern = /^[A-Za-z0-9._-]{1,64}$/;
const audiencePattern = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/;
const privateMembers = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k'] as const;
const maxCachedVerifiers = 32;

function invalid(field: string, detail: string): never {
  throw new IamError('INVALID_CONFIG', `sts.jwt.${field} ${detail}`);
}

interface CheckedKey {
  /** The key material only (kty, crv, x, y, d); metadata such as key_ops, use and ext is dropped for import. */
  jwk: JWK;
  kid: string;
  alg: SessionTokenAlgorithm;
  publicJwk: PublicSessionJwk;
}

/** Validates one configured JWK and derives its public projection; `signing` keys must be private. */
function checkKey(value: unknown, field: string, signing: boolean): CheckedKey {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    invalid(field, 'must contain JWK objects');
  const jwk = value as JWK & Record<string, unknown>;
  const pair =
    jwk.kty === 'OKP' && jwk.crv === 'Ed25519' && jwk.alg === 'EdDSA'
      ? 'EdDSA'
      : jwk.kty === 'EC' && jwk.crv === 'P-256' && jwk.alg === 'ES256'
        ? 'ES256'
        : undefined;
  if (!pair)
    invalid(field, 'keys must be kty OKP/crv Ed25519/alg EdDSA or kty EC/crv P-256/alg ES256');
  if (typeof jwk.kid !== 'string' || !kidPattern.test(jwk.kid))
    invalid(field, 'keys need a kid matching /^[A-Za-z0-9._-]{1,64}$/');
  if (jwk.use !== undefined && jwk.use !== 'sig') invalid(field, "keys must have use 'sig'");
  if (
    jwk.key_ops !== undefined &&
    (!Array.isArray(jwk.key_ops) || !jwk.key_ops.includes(signing ? 'sign' : 'verify'))
  )
    invalid(field, `key_ops must include '${signing ? 'sign' : 'verify'}'`);
  if (typeof jwk.x !== 'string' || (pair === 'ES256' && typeof jwk.y !== 'string'))
    invalid(field, 'keys need their public coordinates');
  if (signing) {
    if (typeof jwk.d !== 'string') invalid(field, 'keys must be private keys');
  } else if (privateMembers.some((member) => jwk[member] !== undefined))
    invalid(field, 'must contain public keys only');
  // Only the key material is kept: WebCrypto refuses a private key whose key_ops also lists 'verify', and the
  // configured metadata has been checked above.
  const material: JWK = {
    kty: jwk.kty,
    crv: jwk.crv,
    x: jwk.x,
    ...(pair === 'ES256' ? { y: jwk.y } : {}),
    ...(signing ? { d: jwk.d } : {}),
  };
  // Parse the key material now, so a broken key fails at construction rather than at the first issuance.
  try {
    if (signing) {
      const derived = createPublicKey(
        createPrivateKey({ key: material as never, format: 'jwk' }),
      ).export({ format: 'jwk' });
      if (derived.x !== jwk.x || (pair === 'ES256' && derived.y !== jwk.y)) throw new Error();
    } else createPublicKey({ key: material as never, format: 'jwk' });
  } catch {
    invalid(field, `key ${jwk.kid} is not a valid ${pair} key`);
  }
  return {
    jwk: material,
    kid: jwk.kid,
    alg: pair,
    publicJwk: {
      kty: jwk.kty as PublicSessionJwk['kty'],
      crv: jwk.crv as PublicSessionJwk['crv'],
      x: jwk.x,
      ...(pair === 'ES256' ? { y: jwk.y as string } : {}),
      kid: jwk.kid,
      alg: pair,
      use: 'sig',
    },
  };
}

function checkIssuer(value: unknown): string {
  let url: URL | undefined;
  try {
    url = typeof value === 'string' ? new URL(value) : undefined;
  } catch {
    url = undefined;
  }
  if (
    !url ||
    (url.protocol !== 'https:' && url.protocol !== 'http:') ||
    url.username ||
    url.password ||
    url.search ||
    url.hash ||
    !audiencePattern.test(value as string)
  )
    invalid('issuer', 'must be an absolute http(s) URL without credentials, query or fragment');
  return value as string;
}

/**
 * Creates the deployment's session token signer, or undefined when `sts.jwt` is not configured. Every option is
 * validated synchronously (INVALID_CONFIG); the private keys are imported lazily, once, on the first signature.
 */
export function createSessionTokenSigner(
  options: SessionTokenSigningOptions | undefined,
  context: { issuer: string; now: () => number },
): SessionTokenSigner | undefined {
  if (options === undefined) return undefined;
  if (!options || typeof options !== 'object') invalid('options', 'must be an object');
  const signingKeys = options.signingKeys as unknown;
  if (!Array.isArray(signingKeys) || signingKeys.length < 1 || signingKeys.length > 10)
    invalid('signingKeys', 'must contain 1 to 10 keys');
  const verificationKeys = (options.verificationKeys ?? []) as unknown;
  if (!Array.isArray(verificationKeys) || verificationKeys.length > 10)
    invalid('verificationKeys', 'must contain at most 10 keys');
  const signing = signingKeys.map((key) => checkKey(key, 'signingKeys', true));
  const retired = verificationKeys.map((key) => checkKey(key, 'verificationKeys', false));
  const kids = new Set<string>();
  for (const key of [...signing, ...retired]) {
    if (kids.has(key.kid)) invalid('signingKeys', `kid ${key.kid} is used more than once`);
    kids.add(key.kid);
  }
  const activeKeyId = options.activeKeyId ?? signing[0]!.kid;
  const active = signing.find((key) => key.kid === activeKeyId);
  if (!active) invalid('activeKeyId', 'must name one of the signing keys');
  const issuer = checkIssuer(options.issuer ?? context.issuer);
  const configured = (options.audiences ?? []) as unknown;
  if (!Array.isArray(configured) || configured.length > 50)
    invalid('audiences', 'must be an array of at most 50 audiences');
  for (const audience of configured)
    if (typeof audience !== 'string' || !audiencePattern.test(audience))
      invalid('audiences', 'entries must match /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$/');
  const audiences = Object.freeze([...new Set([issuer, ...(configured as string[])])]);
  const maxLifetimeSeconds = options.maxLifetimeSeconds ?? 3600;
  if (
    typeof maxLifetimeSeconds !== 'number' ||
    !Number.isSafeInteger(maxLifetimeSeconds) ||
    maxLifetimeSeconds < 300 ||
    maxLifetimeSeconds > 43200
  )
    invalid('maxLifetimeSeconds', 'must be an integer from 300 to 43200');
  if (typeof context.now !== 'function') invalid('options', 'need a clock');

  const jwks = { keys: [...signing, ...retired].map((key) => key.publicJwk) };
  let signingKey: ReturnType<typeof importJWK> | undefined;
  const key = () => {
    signingKey ??= importJWK(active.jwk, active.alg).catch((error: unknown) => {
      signingKey = undefined;
      throw error;
    });
    return signingKey;
  };
  const verifiers = new Map<string, SessionTokenVerifier>();
  const verifier = (audience: string): SessionTokenVerifier => {
    let found = verifiers.get(audience);
    if (!found) {
      found = createSessionTokenVerifier({
        issuer,
        audience,
        jwks,
        clockToleranceSeconds: 5,
        maxLifetimeSeconds,
        now: context.now,
      });
      if (verifiers.size >= maxCachedVerifiers) verifiers.clear();
      verifiers.set(audience, found);
    }
    return found;
  };

  return {
    issuer,
    audiences,
    maxLifetimeSeconds,
    async sign(claims) {
      return new SignJWT(claims as unknown as JWTPayload)
        .setProtectedHeader({ alg: active.alg, kid: active.kid, typ: SESSION_TOKEN_TYPE })
        .sign(await key());
    },
    async verify(token, verifyOptions) {
      let checker: SessionTokenVerifier;
      try {
        checker = verifier(verifyOptions?.audience ?? issuer);
      } catch {
        throw new SessionTokenError('audience');
      }
      return checker.verify(token);
    },
    publicJwks() {
      return { keys: jwks.keys.map((jwk) => ({ ...jwk })) };
    },
  };
}
