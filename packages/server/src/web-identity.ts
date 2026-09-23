import { createHash } from 'node:crypto';
import {
  createLocalJWKSet,
  decodeProtectedHeader,
  errors,
  jwtVerify,
  type JSONWebKeySet,
  type JWSHeaderParameters,
  type JWTPayload,
  type JWTVerifyGetKey,
} from 'jose';
import { evaluatePolicy, IamError, validatePolicy, type PolicyStatement } from '@better-iam/core';
import { checkFetchUrl, fetchJsonSafely, SafeFetchError } from './safe-fetch.js';

/**
 * Verification of external OIDC tokens for AssumeRoleWithWebIdentity (GitHub Actions, GitLab, Kubernetes, cloud
 * workload identity), plus the validators for OIDC provider and web-identity trust settings.
 *
 * This is a separate verifier from IAM's own session JWTs: algorithms come from each provider's allowlist, the `typ`
 * must be absent, `JWT` or `application/jwt` (never `biam-session+jwt` or `at+jwt`), and IAM's own issuer is refused.
 */

/** Signature algorithms a provider may allow. Symmetric algorithms and `none` are never accepted. */
export const WEB_IDENTITY_ALGORITHMS = [
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'EdDSA',
] as const;
type Algorithm = (typeof WEB_IDENTITY_ALGORITHMS)[number];
/** Used when a provider does not name its algorithms. */
export const DEFAULT_WEB_IDENTITY_ALGORITHMS: readonly Algorithm[] = ['RS256', 'ES256'];

/** The provider settings verification needs; a stored OIDC provider record satisfies it. */
export interface WebIdentityProviderConfig {
  id: string;
  issuer: string;
  audiences: readonly string[];
  /** Where the keys live; without it and without `jwks`, OIDC discovery at `{issuer}/.well-known/openid-configuration`. */
  jwksUri?: string;
  /** Static public keys; never fetched. */
  jwks?: { keys: readonly object[] };
  algorithms: readonly Algorithm[];
  maxTokenLifetimeSeconds: number;
  clockToleranceSeconds: number;
  /** Cached keys are discarded when this changes. */
  updatedAt: number;
}

/** A verified external token. `context` holds the flattened claims as `token.<claim>` condition keys. */
export interface VerifiedWebIdentity {
  issuer: string;
  subject: string;
  /** The provider audience the token was accepted for. */
  audience: string;
  jti?: string;
  /** Epoch seconds. */
  issuedAt: number;
  /** Epoch seconds. */
  expiresAt: number;
  context: Record<string, WebIdentityClaimValue>;
}

export type WebIdentityClaimValue = string | number | boolean | (string | number | boolean)[];

export type WebIdentityFailureReason =
  | 'malformed'
  | 'type'
  | 'algorithm'
  | 'unknown-key'
  | 'signature'
  | 'issuer'
  | 'audience'
  | 'expired'
  | 'not-yet-valid'
  | 'too-old'
  | 'lifetime'
  | 'claims'
  | 'jwks-unavailable';

/** A refused external token. Callers turn every reason into the same public error; `reason` is for audits. */
export class WebIdentityFailure extends Error {
  constructor(readonly reason: WebIdentityFailureReason) {
    super(`The web identity token was not accepted (${reason})`);
    this.name = 'WebIdentityFailure';
  }
}

export interface WebIdentityVerifierOptions {
  /** How long fetched keys are used before they are fetched again, in seconds. */
  jwksCacheSeconds: number;
  fetchTimeoutMs: number;
  maxJwksBytes: number;
  allowPrivateNetworks: boolean;
  allowInsecureLocalhost: boolean;
  /** A host transport replacing the guarded fetch; the host is responsible for its safety. */
  fetchJson?: (url: URL) => Promise<unknown>;
  /** The clock, in epoch milliseconds. */
  now: () => number;
  /** IAM's own session token issuer, never accepted from a provider. */
  selfIssuer?: string;
}

export interface WebIdentityVerifier {
  /** Verifies an external token against a provider, or throws `WebIdentityFailure`. */
  verify(provider: WebIdentityProviderConfig, token: string): Promise<VerifiedWebIdentity>;
  /** Drops the cached keys of a provider (after an update or deletion). */
  forget(providerId: string): void;
}

const maxTokenLength = 8192;
const maxFetchedKeys = 32;
const negativeCacheMs = 30_000;
const refetchCooldownMs = 30_000;
const maxCachedProviders = 1000;
const tokenShape = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/;
const acceptedTypes = new Set(['application/jwt']);

/** Raised by the key resolver when keys cannot be obtained. */
class KeysUnavailable extends Error {}

function reasonFor(error: unknown): WebIdentityFailureReason {
  if (error instanceof WebIdentityFailure) return error.reason;
  if (error instanceof KeysUnavailable) return 'jwks-unavailable';
  if (error instanceof errors.JWTExpired) return error.claim === 'iat' ? 'too-old' : 'expired';
  if (error instanceof errors.JWTClaimValidationFailed) {
    if (error.reason === 'missing' || error.reason === 'invalid') return 'claims';
    if (error.claim === 'iss') return 'issuer';
    if (error.claim === 'aud') return 'audience';
    if (error.claim === 'nbf' || error.claim === 'iat') return 'not-yet-valid';
    if (error.claim === 'typ') return 'type';
    return 'claims';
  }
  if (error instanceof errors.JOSEAlgNotAllowed || error instanceof errors.JOSENotSupported)
    return 'algorithm';
  if (error instanceof errors.JWKSNoMatchingKey || error instanceof errors.JWKSMultipleMatchingKeys)
    return 'unknown-key';
  if (error instanceof errors.JWSSignatureVerificationFailed) return 'signature';
  return 'malformed';
}

const base64urlBytes = (value: unknown): number =>
  typeof value === 'string' && /^[A-Za-z0-9_-]+$/.test(value)
    ? Math.floor((value.length * 6) / 8)
    : 0;
/** The bit length of a base64url big-endian integer (leading zero bits excluded). */
function modulusBits(value: unknown): number {
  if (!base64urlBytes(value)) return 0;
  const bytes = Buffer.from(value as string, 'base64url');
  let index = 0;
  while (index < bytes.length && bytes[index] === 0) index++;
  if (index === bytes.length) return 0;
  return (bytes.length - index) * 8 - Math.clz32(bytes[index]!) + 24;
}

/** The allowlisted public members of an acceptable verification key, or undefined when the key is unusable. */
function usableKey(value: unknown): Record<string, string> | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const key = value as Record<string, unknown>;
  if (['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'].some((member) => key[member] !== undefined))
    return undefined;
  if (key.use !== undefined && key.use !== 'sig') return undefined;
  if (key.key_ops !== undefined && (!Array.isArray(key.key_ops) || !key.key_ops.includes('verify')))
    return undefined;
  if (key.kid !== undefined && (typeof key.kid !== 'string' || key.kid.length > 256))
    return undefined;
  if (key.alg !== undefined && !(WEB_IDENTITY_ALGORITHMS as readonly unknown[]).includes(key.alg))
    return undefined;
  const common = {
    kty: key.kty as string,
    ...(key.kid !== undefined ? { kid: key.kid as string } : {}),
    ...(key.alg !== undefined ? { alg: key.alg as string } : {}),
    ...(key.use !== undefined ? { use: 'sig' } : {}),
  };
  if (key.kty === 'RSA') {
    // RSA keys under 2048 bits are refused; e must be present.
    if (modulusBits(key.n) < 2048 || !base64urlBytes(key.e)) return undefined;
    return { ...common, n: key.n as string, e: key.e as string };
  }
  if (key.kty === 'EC') {
    if (!['P-256', 'P-384', 'P-521'].includes(key.crv as string)) return undefined;
    if (!base64urlBytes(key.x) || !base64urlBytes(key.y)) return undefined;
    return { ...common, crv: key.crv as string, x: key.x as string, y: key.y as string };
  }
  if (key.kty === 'OKP') {
    if (key.crv !== 'Ed25519' || !base64urlBytes(key.x)) return undefined;
    return { ...common, crv: 'Ed25519', x: key.x as string };
  }
  return undefined;
}

function invalidInput(message: string): never {
  throw new IamError('INVALID_INPUT', message);
}
const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]']);
const controlCharacters = /[\u0000-\u001f\u007f]/;

/**
 * Validates an issuer: an absolute https URL without credentials, query or fragment, at most 512 characters
 * (http only for loopback hosts with `allowInsecureLocalhost`). IAM's own issuer is refused, and when
 * `allowedIssuers` is given the issuer must be on it. Returns the value unchanged; comparisons are exact.
 */
export function webIdentityIssuer(
  value: unknown,
  options: {
    allowInsecureLocalhost: boolean;
    selfIssuer?: string;
    allowedIssuers?: readonly string[];
  },
): string {
  if (
    typeof value !== 'string' ||
    !value.length ||
    value.length > 512 ||
    controlCharacters.test(value)
  )
    invalidInput('Invalid issuer');
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return invalidInput('The issuer must be an absolute URL');
  }
  const insecureLocal = options.allowInsecureLocalhost && loopbackHosts.has(url.hostname);
  if (url.protocol !== 'https:' && !(insecureLocal && url.protocol === 'http:'))
    invalidInput('The issuer must use https');
  if (url.username || url.password || url.search || url.hash || /[?#]/.test(value))
    invalidInput('The issuer cannot carry credentials, a query or a fragment');
  const trimmed = (issuer: string) => issuer.replace(/\/+$/, '');
  if (options.selfIssuer !== undefined && trimmed(value) === trimmed(options.selfIssuer))
    invalidInput('IAM cannot trust its own issuer as a web identity provider');
  if (options.allowedIssuers !== undefined && !options.allowedIssuers.includes(value))
    invalidInput('The issuer is not in sts.webIdentity.allowedIssuers');
  return value;
}

/** Validates a JWKS URL: https on port 443 without credentials or a fragment (loopback http with the dev option). */
export function webIdentityJwksUri(
  value: unknown,
  options: { allowInsecureLocalhost: boolean; allowPrivateNetworks?: boolean },
): string {
  if (
    typeof value !== 'string' ||
    !value.length ||
    value.length > 2048 ||
    controlCharacters.test(value)
  )
    invalidInput('Invalid jwksUri');
  try {
    checkFetchUrl(value, {
      timeoutMs: 1,
      maxBytes: 1,
      allowInsecureLocalhost: options.allowInsecureLocalhost,
      allowPrivateNetworks: options.allowPrivateNetworks === true,
    });
  } catch (error) {
    if (error instanceof SafeFetchError && error.reason === 'address')
      invalidInput('The jwksUri must not point at a private address');
    invalidInput('The jwksUri must be an https URL on port 443 without credentials or a fragment');
  }
  return value;
}

/**
 * Validates static provider keys: 1 to 20 public keys (RSA of at least 2048 bits, EC P-256/P-384/P-521, OKP
 * Ed25519), `use` absent or `sig`. Returns an allowlisted copy.
 */
export function webIdentityKeys(value: unknown): {
  keys: { kty: string; kid?: string; alg?: string; use?: string; [member: string]: unknown }[];
} {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    invalidInput('jwks must be an object with keys');
  const keys = (value as { keys?: unknown }).keys;
  if (!Array.isArray(keys) || keys.length < 1 || keys.length > 20)
    invalidInput('jwks must contain 1 to 20 keys');
  return {
    keys: keys.map((key) => {
      const usable = usableKey(key);
      if (!usable)
        invalidInput(
          'jwks keys must be public RSA (at least 2048 bits), EC (P-256, P-384, P-521) or Ed25519 signature keys',
        );
      return usable as { kty: string };
    }),
  };
}

/** Validates an algorithm allowlist: a non-empty subset of `WEB_IDENTITY_ALGORITHMS` (default RS256 and ES256). */
export function webIdentityAlgorithms(value: unknown): Algorithm[] {
  if (value === undefined) return [...DEFAULT_WEB_IDENTITY_ALGORITHMS];
  if (
    !Array.isArray(value) ||
    !value.length ||
    !value.every((alg) => (WEB_IDENTITY_ALGORITHMS as readonly unknown[]).includes(alg))
  )
    invalidInput(`algorithms must be a non-empty subset of ${WEB_IDENTITY_ALGORITHMS.join(', ')}`);
  return [...new Set(value as Algorithm[])];
}

/** Validates the accepted audiences: 1 to 10 strings of 1 to 256 characters. */
export function webIdentityAudiences(value: unknown): string[] {
  if (
    !Array.isArray(value) ||
    value.length < 1 ||
    value.length > 10 ||
    !value.every(
      (item) =>
        typeof item === 'string' &&
        item.length > 0 &&
        item.length <= 256 &&
        !controlCharacters.test(item),
    )
  )
    invalidInput('audiences must contain 1 to 10 strings of at most 256 characters');
  return [...new Set(value as string[])];
}

const claimKey = /^token\.[A-Za-z0-9_:.-]{1,122}$/;
const maxConditionEntries = 20;
const conditionAction = 'sts:AssumeRoleWithWebIdentity';
type TrustConditions = NonNullable<PolicyStatement['conditions']>;

/** Validates a flattened claim name as used in conditions, `tagClaims` and `sourceIdentityClaim`: `token.<claim>`. */
export function webIdentityClaimName(value: unknown): string {
  if (typeof value !== 'string' || !claimKey.test(value))
    invalidInput('Claim names must look like token.<claim> (letters, digits, _ : . -)');
  return value;
}

/**
 * Validates web-identity trust conditions: the core condition grammar over `token.<claim>` keys, at most 20
 * operator/key entries, no policy variables, and a mandatory subject pin — a `StringEquals` or `StringLike` entry on
 * `token.sub` whose values are non-empty and do not start with a wildcard (else WEAK_TRUST_CONDITIONS).
 */
export function webIdentityConditions(value: unknown): TrustConditions {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    invalidInput('conditions must be an operator map');
  let entries = 0;
  for (const attributes of Object.values(value as Record<string, unknown>)) {
    if (!attributes || typeof attributes !== 'object' || Array.isArray(attributes))
      invalidInput('conditions must map operators to claim keys');
    for (const [key, expected] of Object.entries(attributes as Record<string, unknown>)) {
      entries++;
      if (!claimKey.test(key)) invalidInput(`Condition key ${key} must look like token.<claim>`);
      const values = Array.isArray(expected) ? expected : [expected];
      if (values.some((item) => typeof item === 'string' && item.includes('${')))
        invalidInput('Policy variables are not allowed in web identity conditions');
    }
  }
  if (entries > maxConditionEntries)
    invalidInput(`conditions may contain at most ${maxConditionEntries} entries`);
  validatePolicy({
    version: 1,
    statements: [
      { effect: 'allow', actions: [conditionAction], resources: ['trust/*'], conditions: value },
    ],
  });
  const conditions = value as TrustConditions;
  const pinned = (['StringEquals', 'StringLike'] as const).some((operator) => {
    const expected = conditions[operator]?.['token.sub'];
    if (expected === undefined) return false;
    const values = Array.isArray(expected) ? expected : [expected];
    return values.every(
      (item) =>
        typeof item === 'string' &&
        item.length > 0 &&
        !item.startsWith('*') &&
        !item.startsWith('?'),
    );
  });
  if (!pinned)
    throw new IamError(
      'WEAK_TRUST_CONDITIONS',
      'Web identity trusts must pin token.sub with StringEquals or StringLike (no leading wildcard)',
    );
  return structuredClone(conditions);
}

const segment = /^[A-Za-z0-9_:.-]{1,64}$/;
const unsafeSegments = new Set(['__proto__', 'prototype', 'constructor']);
const maxClaimKeys = 128;
const maxClaimDepth = 3;
const maxClaimString = 1024;
const maxClaimArray = 64;

function scalar(value: unknown): value is string | number | boolean {
  return (
    (typeof value === 'string' && value.length <= maxClaimString) ||
    (typeof value === 'number' && Number.isFinite(value)) ||
    typeof value === 'boolean'
  );
}

/**
 * Flattens a verified payload into `token.<path>` condition keys: nested objects to depth 3 joined with '.', segments
 * matching /^[A-Za-z0-9_:.-]{1,64}$/, strings up to 1024 characters, finite numbers, booleans, and arrays of up to 64
 * such scalars; at most 128 keys. Anything else is left out.
 */
export function flattenClaims(
  payload: Record<string, unknown>,
): Record<string, WebIdentityClaimValue> {
  const result: Record<string, WebIdentityClaimValue> = {};
  let count = 0;
  const walk = (value: Record<string, unknown>, prefix: string, depth: number) => {
    for (const [name, item] of Object.entries(value)) {
      if (count >= maxClaimKeys) return;
      if (!segment.test(name) || unsafeSegments.has(name)) continue;
      const key = `${prefix}.${name}`;
      if (!claimKey.test(key)) continue;
      if (scalar(item)) {
        result[key] = item;
        count++;
      } else if (Array.isArray(item)) {
        if (item.length <= maxClaimArray && item.every(scalar)) {
          result[key] = [...item];
          count++;
        }
      } else if (item && typeof item === 'object' && depth < maxClaimDepth)
        walk(item as Record<string, unknown>, key, depth + 1);
    }
  };
  walk(payload, 'token', 1);
  return result;
}

function conditionStatement(conditions: TrustConditions, trustId: string): PolicyStatement {
  return {
    effect: 'allow',
    actions: [conditionAction],
    resources: [`trust/${trustId}`],
    conditions,
  };
}

/**
 * Evaluates trust conditions against flattened claims with the core policy engine (an allow statement for
 * `sts:AssumeRoleWithWebIdentity` on `trust/{trustId}`). `failed` lists each unmet entry as `Operator:key`.
 */
export function matchWebIdentityConditions(
  conditions: TrustConditions,
  context: Record<string, unknown>,
  trustId: string,
): { matched: boolean; failed: string[] } {
  const evaluate = (entries: TrustConditions) =>
    evaluatePolicy({
      grants: [{ version: 1, statements: [conditionStatement(entries, trustId)] }],
      action: conditionAction,
      resource: `trust/${trustId}`,
      context: { ...context },
    }).allowed;
  const failed: string[] = [];
  for (const [operator, attributes] of Object.entries(conditions))
    for (const [key, expected] of Object.entries(attributes ?? {}))
      if (!evaluate({ [operator]: { [key]: expected } } as TrustConditions))
        failed.push(`${operator}:${key}`);
  return { matched: failed.length === 0 && evaluate(conditions), failed };
}

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

/**
 * The replay-cache key of a token at a provider (hex): by `jti` when present, else by the hash of the token's signed
 * content (`header.payload`). The signature segment is left out on purpose: it is malleable without the key (unused
 * trailing base64url bits, and ECDSA's (r, s) / (r, n - s) pair), so hashing the whole token would let one token be
 * redeemed several times under different spellings.
 */
export function webIdentityReplayId(
  providerId: string,
  jti: string | undefined,
  token: string,
): string {
  const signed = token.slice(0, Math.max(0, token.lastIndexOf('.')));
  return sha256(`wi\n${providerId}\n${jti ? `jti:${jti}` : `tok:${sha256(signed)}`}`);
}

interface CachedKeys {
  updatedAt: number;
  /** When the current keys were fetched (ms); undefined before the first success. */
  fetchedAt?: number;
  keys?: JWTVerifyGetKey;
  /** When the last fetch failed (ms), for the negative cache. */
  failedAt?: number;
  pending?: Promise<JWTVerifyGetKey>;
  /** The imported static keys of a provider configured with `jwks`. */
  local?: JWTVerifyGetKey;
}

/**
 * Creates the web-identity verifier. Fetched keys are cached per provider id (dropped when `updatedAt` changes) for
 * `jwksCacheSeconds`, fetched single-flight, remembered as unavailable for 30 s after a failure, and refetched on an
 * unknown `kid` at most once per 30 s. Nothing is fetched until a token needs it.
 */
export function createWebIdentityVerifier(
  options: WebIdentityVerifierOptions,
): WebIdentityVerifier {
  const cache = new Map<string, CachedKeys>();
  const cacheMs = options.jwksCacheSeconds * 1000;

  const fetchJson = async (url: URL): Promise<unknown> => {
    if (options.fetchJson) return options.fetchJson(url);
    return fetchJsonSafely(url, {
      timeoutMs: options.fetchTimeoutMs,
      maxBytes: options.maxJwksBytes,
      allowPrivateNetworks: options.allowPrivateNetworks,
      allowInsecureLocalhost: options.allowInsecureLocalhost,
    });
  };

  const checkedUrl = (value: unknown): URL => {
    try {
      return new URL(webIdentityJwksUri(value, options));
    } catch {
      throw new KeysUnavailable();
    }
  };

  async function download(provider: WebIdentityProviderConfig): Promise<JWTVerifyGetKey> {
    let jwksUri = provider.jwksUri;
    if (jwksUri === undefined) {
      const discovery = new URL(
        `${provider.issuer.replace(/\/+$/, '')}/.well-known/openid-configuration`,
      );
      const document = (await fetchJson(checkedUrl(discovery.href))) as Record<string, unknown>;
      if (!document || typeof document !== 'object' || document.issuer !== provider.issuer)
        throw new KeysUnavailable();
      jwksUri = document.jwks_uri as string;
    }
    const body = (await fetchJson(checkedUrl(jwksUri))) as { keys?: unknown };
    if (!body || typeof body !== 'object' || !Array.isArray(body.keys)) throw new KeysUnavailable();
    const keys = body.keys
      .map(usableKey)
      .filter((key) => key !== undefined)
      .slice(0, maxFetchedKeys);
    if (!keys.length) throw new KeysUnavailable();
    return createLocalJWKSet({ keys } as JSONWebKeySet);
  }

  /** Fetches the provider's keys once for all concurrent callers and records the outcome. */
  function refresh(
    provider: WebIdentityProviderConfig,
    entry: CachedKeys,
  ): Promise<JWTVerifyGetKey> {
    entry.pending ??= download(provider)
      .then((keys) => {
        entry.keys = keys;
        entry.fetchedAt = options.now();
        entry.failedAt = undefined;
        return keys;
      })
      .catch(() => {
        entry.failedAt = options.now();
        throw new KeysUnavailable();
      })
      .finally(() => {
        entry.pending = undefined;
      });
    return entry.pending;
  }

  function entryFor(provider: WebIdentityProviderConfig): CachedKeys {
    let entry = cache.get(provider.id);
    if (!entry || entry.updatedAt !== provider.updatedAt) {
      if (!entry && cache.size >= maxCachedProviders) cache.delete(cache.keys().next().value!);
      entry = { updatedAt: provider.updatedAt };
      cache.set(provider.id, entry);
    }
    return entry;
  }

  async function fetchedKeys(provider: WebIdentityProviderConfig): Promise<JWTVerifyGetKey> {
    const entry = entryFor(provider);
    const now = options.now();
    if (entry.keys && entry.fetchedAt !== undefined && now - entry.fetchedAt < cacheMs)
      return entry.keys;
    if (entry.failedAt !== undefined && now - entry.failedAt < negativeCacheMs && !entry.pending)
      throw new KeysUnavailable();
    return refresh(provider, entry);
  }

  /**
   * Refetches after an unknown kid, unless the cooldown since the last fetch attempt is still running. A failed
   * attempt starts the cooldown too, so an unreachable IdP is not refetched for every token with a random kid.
   */
  async function refetchForUnknownKid(
    provider: WebIdentityProviderConfig,
  ): Promise<JWTVerifyGetKey | undefined> {
    const entry = entryFor(provider);
    if (entry.pending) return entry.pending;
    const lastAttempt = Math.max(entry.fetchedAt ?? -Infinity, entry.failedAt ?? -Infinity);
    if (options.now() - lastAttempt < Math.max(refetchCooldownMs, negativeCacheMs))
      return undefined;
    return refresh(provider, entry);
  }

  /** Static keys are imported once per provider version; a changed key list comes with a new `updatedAt`. */
  function localKeys(provider: WebIdentityProviderConfig): JWTVerifyGetKey {
    const entry = entryFor(provider);
    if (!entry.local) {
      const keys = provider.jwks?.keys;
      const usable = (Array.isArray(keys) ? keys : [])
        .map(usableKey)
        .filter((key) => key !== undefined);
      entry.local = createLocalJWKSet({ keys: usable } as JSONWebKeySet);
    }
    return entry.local;
  }

  async function check(
    provider: WebIdentityProviderConfig,
    token: string,
    keys: JWTVerifyGetKey,
  ): Promise<JWTPayload> {
    const { payload } = await jwtVerify(token, keys, {
      algorithms: [...provider.algorithms],
      issuer: provider.issuer,
      audience: [...provider.audiences],
      requiredClaims: ['iss', 'sub', 'aud', 'exp', 'iat'],
      currentDate: new Date(options.now()),
      clockTolerance: provider.clockToleranceSeconds,
      maxTokenAge: provider.maxTokenLifetimeSeconds,
    });
    return payload;
  }

  async function verify(
    provider: WebIdentityProviderConfig,
    token: string,
  ): Promise<VerifiedWebIdentity> {
    if (typeof token !== 'string' || token.length > maxTokenLength || !tokenShape.test(token))
      throw new WebIdentityFailure('malformed');
    let header: JWSHeaderParameters;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      throw new WebIdentityFailure('malformed');
    }
    if (header.typ !== undefined) {
      const typ = typeof header.typ === 'string' ? header.typ.toLowerCase() : '';
      if (!acceptedTypes.has(typ.includes('/') ? typ : `application/${typ}`))
        throw new WebIdentityFailure('type');
    }
    if (
      typeof header.alg !== 'string' ||
      !(provider.algorithms as readonly string[]).includes(header.alg) ||
      !(WEB_IDENTITY_ALGORITHMS as readonly string[]).includes(header.alg)
    )
      throw new WebIdentityFailure('algorithm');
    if (header.kid !== undefined && typeof header.kid !== 'string')
      throw new WebIdentityFailure('malformed');
    const selfIssuer = options.selfIssuer?.replace(/\/+$/, '');
    if (selfIssuer !== undefined && provider.issuer.replace(/\/+$/, '') === selfIssuer)
      throw new WebIdentityFailure('issuer');

    let payload: JWTPayload;
    try {
      if (provider.jwks) payload = await check(provider, token, localKeys(provider));
      else {
        const keys = await fetchedKeys(provider);
        try {
          payload = await check(provider, token, keys);
        } catch (error) {
          if (!(error instanceof errors.JWKSNoMatchingKey)) throw error;
          const refreshed = await refetchForUnknownKid(provider);
          if (!refreshed) throw error;
          payload = await check(provider, token, refreshed);
        }
      }
    } catch (error) {
      throw new WebIdentityFailure(reasonFor(error));
    }

    const { iat, exp, sub, jti, aud } = payload;
    if (typeof iat !== 'number' || typeof exp !== 'number') throw new WebIdentityFailure('claims');
    if (exp - iat > provider.maxTokenLifetimeSeconds) throw new WebIdentityFailure('lifetime');
    if (typeof sub !== 'string' || !sub.length || sub.length > 512)
      throw new WebIdentityFailure('claims');
    if (jti !== undefined && (typeof jti !== 'string' || !jti.length || jti.length > 256))
      throw new WebIdentityFailure('claims');
    const audiences = Array.isArray(aud) ? aud : [aud];
    const audience = provider.audiences.find((item) => audiences.includes(item));
    if (audience === undefined) throw new WebIdentityFailure('audience');
    return {
      issuer: provider.issuer,
      subject: sub,
      audience,
      ...(jti !== undefined ? { jti } : {}),
      issuedAt: iat,
      expiresAt: exp,
      context: flattenClaims(payload as Record<string, unknown>),
    };
  }

  return {
    verify,
    forget(providerId) {
      cache.delete(providerId);
    },
  };
}
