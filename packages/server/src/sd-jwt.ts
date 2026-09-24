import { createHash, randomBytes, type KeyObject } from 'node:crypto';
import { deflateSync, inflateSync } from 'node:zlib';
import {
  EmbeddedJWK,
  calculateJwkThumbprint,
  decodeJwt,
  decodeProtectedHeader,
  importJWK,
  jwtVerify,
  SignJWT,
  type CryptoKey,
  type JWK,
  type JWTPayload,
} from 'jose';

/**
 * Selective Disclosure JWTs (RFC 9901) as SD-JWT VCs (IETF SD-JWT-based Verifiable Credentials), the Token Status List
 * (IETF OAuth Status List) that revokes them, and OpenID4VCI holder proofs. Pure functions over `jose`: issuing,
 * presenting with key binding, and verifying. Storage and policy live in vc.ts.
 */

/** The `typ` of an SD-JWT VC (`vc+sd-jwt`, the earlier name, is accepted when verifying). */
export const SD_JWT_VC_TYPE = 'dc+sd-jwt';
export const KB_JWT_TYPE = 'kb+jwt';
export const STATUS_LIST_JWT_TYPE = 'statuslist+jwt';
export const HOLDER_PROOF_TYPE = 'openid4vci-proof+jwt';
/** Signature algorithms accepted from holders and issuers. */
export const sdJwtAlgorithms = ['ES256', 'ES384', 'EdDSA'] as const;
/** Claims that are never selectively disclosable and never come from a disclosure. */
export const reservedVcClaims = new Set([
  'iss',
  'sub',
  'iat',
  'nbf',
  'exp',
  'cnf',
  'vct',
  'vct#integrity',
  'status',
  'jti',
  'aud',
  '_sd',
  '_sd_alg',
  '...',
  // Never object keys that change an object's prototype.
  '__proto__',
  'constructor',
  'prototype',
]);

export type SdJwtFailure =
  | 'malformed'
  | 'unsupported-type'
  | 'unknown-issuer'
  | 'bad-signature'
  | 'expired'
  | 'not-yet-valid'
  | 'bad-disclosure'
  | 'key-binding-required'
  | 'bad-key-binding'
  | 'wrong-audience'
  | 'wrong-nonce'
  | 'stale-key-binding'
  | 'revoked'
  | 'suspended'
  | 'status-unavailable';

/** A presentation or credential that did not verify, with the reason. */
export class SdJwtError extends Error {
  constructor(
    readonly reason: SdJwtFailure,
    message: string,
  ) {
    super(message);
    this.name = 'SdJwtError';
  }
}

const digestOf = (encoded: string) => createHash('sha256').update(encoded, 'ascii').digest('base64url');

/** One disclosure: `[salt, name, value]`, base64url-encoded JSON, and its SHA-256 digest. */
export interface SdJwtDisclosure {
  encoded: string;
  digest: string;
  name: string;
  value: unknown;
}

export function createDisclosure(name: string, value: unknown): SdJwtDisclosure {
  const encoded = Buffer.from(
    JSON.stringify([randomBytes(16).toString('base64url'), name, value]),
    'utf8',
  ).toString('base64url');
  return { encoded, digest: digestOf(encoded), name, value };
}

/**
 * Issues an SD-JWT: `plain` claims are visible to anyone holding the credential; each `disclosable` claim becomes a
 * disclosure the holder decides to reveal or keep. Random decoy digests hide how many claims exist. Returns the issued
 * form `<jwt>~<disclosure>~...~` and its parts.
 */
export async function issueSdJwt(input: {
  alg: (typeof sdJwtAlgorithms)[number];
  kid: string;
  key: KeyObject | CryptoKey;
  typ?: string;
  plain: Record<string, unknown>;
  disclosable: Record<string, unknown>;
  decoys?: number;
}): Promise<{ sdJwt: string; jwt: string; disclosures: SdJwtDisclosure[] }> {
  // What a verifier refuses to accept from a disclosure is never issued as one.
  for (const name of Object.keys(input.disclosable))
    if (reservedVcClaims.has(name) || Object.hasOwn(input.plain, name))
      throw new SdJwtError('bad-disclosure', `${name.slice(0, 64)} cannot be selectively disclosable`);
  const disclosures = Object.entries(input.disclosable).map(([name, value]) =>
    createDisclosure(name, value),
  );
  const decoys = Array.from({ length: input.decoys ?? 0 }, () => digestOf(randomBytes(32).toString('base64url')));
  const payload: JWTPayload = {
    ...input.plain,
    ...(disclosures.length || decoys.length
      ? { _sd: [...disclosures.map((item) => item.digest), ...decoys].sort(), _sd_alg: 'sha-256' }
      : {}),
  };
  const jwt = await new SignJWT(payload)
    .setProtectedHeader({ alg: input.alg, kid: input.kid, typ: input.typ ?? SD_JWT_VC_TYPE })
    .sign(input.key);
  return {
    sdJwt: `${jwt}~${disclosures.map((item) => `${item.encoded}~`).join('')}`,
    jwt,
    disclosures,
  };
}

/** Splits `<jwt>~<d1>~...~<dn>~[<kb-jwt>]`. */
export function splitSdJwt(value: string): { jwt: string; disclosures: string[]; keyBinding?: string } {
  if (typeof value !== 'string' || value.length > 65536 || !value.includes('~'))
    throw new SdJwtError('malformed', 'Not an SD-JWT');
  const parts = value.split('~');
  const jwt = parts[0]!;
  const last = parts.at(-1)!;
  const disclosures = parts.slice(1, -1);
  if (!jwt || disclosures.some((item) => !item)) throw new SdJwtError('malformed', 'Not an SD-JWT');
  return { jwt, disclosures, ...(last ? { keyBinding: last } : {}) };
}

/** Decodes a disclosure without trusting it (for wallets choosing what to reveal). */
export function readDisclosure(encoded: string): { name: string; value: unknown } {
  let decoded: unknown;
  try {
    decoded = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw new SdJwtError('bad-disclosure', 'A disclosure is not base64url JSON');
  }
  if (
    !Array.isArray(decoded) ||
    decoded.length !== 3 ||
    typeof decoded[0] !== 'string' ||
    typeof decoded[1] !== 'string'
  )
    throw new SdJwtError('bad-disclosure', 'A disclosure is not [salt, name, value]');
  return { name: decoded[1], value: decoded[2] };
}

/**
 * The holder's presentation: the credential with only the named claims disclosed, and a key-binding JWT signed with
 * the holder key over `aud`, `nonce`, `iat` and the hash of everything before it.
 */
export async function presentSdJwt(
  credential: string,
  options: {
    disclose: string[] | 'all';
    holderKey: KeyObject | CryptoKey;
    alg: (typeof sdJwtAlgorithms)[number];
    audience: string;
    nonce: string;
    issuedAt?: number;
  },
): Promise<string> {
  const { jwt, disclosures } = splitSdJwt(credential);
  const kept = disclosures.filter(
    (encoded) => options.disclose === 'all' || options.disclose.includes(readDisclosure(encoded).name),
  );
  const presented = `${jwt}~${kept.map((item) => `${item}~`).join('')}`;
  const keyBinding = await new SignJWT({
    aud: options.audience,
    nonce: options.nonce,
    iat: Math.floor((options.issuedAt ?? Date.now()) / 1000),
    sd_hash: digestOf(presented),
  })
    .setProtectedHeader({ alg: options.alg, typ: KB_JWT_TYPE })
    .sign(options.holderKey);
  return presented + keyBinding;
}

/** A verified credential: the issuer's claims plus the disclosed ones. */
export interface VerifiedSdJwt {
  issuer: string;
  keyId: string;
  vct?: string;
  /** Every claim: signed plain claims and the disclosures presented (never `_sd`/`_sd_alg`). */
  claims: Record<string, unknown>;
  /** Names of the claims that came from disclosures. */
  disclosed: string[];
  holderKey?: JWK;
  status?: { index: number; uri: string };
  issuedAt?: number;
  expiresAt?: number;
  keyBound: boolean;
  /** The key-binding JWT's audience, nonce and time, for verifiers that check them themselves. */
  keyBinding?: { audience?: string; nonce?: string; issuedAt: number };
}

function publicJwk(value: unknown): JWK {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new SdJwtError('bad-key-binding', 'The credential has no holder key');
  const jwk = value as JWK;
  if ('d' in jwk || 'k' in jwk) throw new SdJwtError('bad-key-binding', 'The holder key must be public');
  return jwk;
}

/**
 * Verifies an SD-JWT VC or presentation: the issuer's signature (`issuerKey` resolves `kid`/`iss`), validity times,
 * every disclosure against the signed digests, and, for presentations, the key-binding JWT (`audience`, `nonce`,
 * freshness, `sd_hash`) with the holder key in `cnf.jwk`. Throws `SdJwtError` with the reason.
 */
export async function verifySdJwt(
  value: string,
  options: {
    issuerKey(kid: string, issuer: string): Promise<KeyObject | CryptoKey | JWK | undefined> | KeyObject | CryptoKey | JWK | undefined;
    /** Require a key-binding JWT (a presentation); default true. */
    requireKeyBinding?: boolean;
    audience?: string;
    nonce?: string;
    /** Milliseconds. */
    now?: number;
    /** Oldest acceptable key-binding `iat`, in seconds (default 300). */
    maxKeyBindingAgeSeconds?: number;
    clockToleranceSeconds?: number;
  },
): Promise<VerifiedSdJwt> {
  const { jwt, disclosures, keyBinding } = splitSdJwt(value);
  let header: ReturnType<typeof decodeProtectedHeader>;
  let unverified: JWTPayload;
  try {
    header = decodeProtectedHeader(jwt);
    unverified = decodeJwt(jwt);
  } catch {
    throw new SdJwtError('malformed', 'The issuer JWT cannot be decoded');
  }
  if (header.typ !== SD_JWT_VC_TYPE && header.typ !== 'vc+sd-jwt')
    throw new SdJwtError('unsupported-type', 'Not an SD-JWT VC');
  if (!sdJwtAlgorithms.includes(header.alg as never) || typeof header.kid !== 'string')
    throw new SdJwtError('unsupported-type', 'Unsupported issuer algorithm');
  if (typeof unverified.iss !== 'string') throw new SdJwtError('malformed', 'The credential names no issuer');
  const found = await options.issuerKey(header.kid, unverified.iss);
  if (!found) throw new SdJwtError('unknown-issuer', 'The issuer or its key is not trusted');
  let key: KeyObject | CryptoKey | Uint8Array;
  try {
    key = 'kty' in (found as object) ? await importJWK(found as JWK, header.alg) : (found as KeyObject | CryptoKey);
  } catch {
    // The header names an algorithm the issuer's key does not have.
    throw new SdJwtError('unsupported-type', 'The issuer key does not match the credential algorithm');
  }
  const now = options.now ?? Date.now();
  const tolerance = options.clockToleranceSeconds ?? 5;
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(jwt, key, {
      algorithms: [header.alg!],
      currentDate: new Date(now),
      clockTolerance: tolerance,
    }));
  } catch (error) {
    const code = (error as { code?: string }).code;
    if (code === 'ERR_JWT_EXPIRED') throw new SdJwtError('expired', 'The credential has expired');
    if (code === 'ERR_JWT_CLAIM_VALIDATION_FAILED')
      throw new SdJwtError('not-yet-valid', 'The credential is not valid yet');
    throw new SdJwtError('bad-signature', 'The issuer signature does not verify');
  }
  if (payload._sd_alg !== undefined && payload._sd_alg !== 'sha-256')
    throw new SdJwtError('unsupported-type', 'Unsupported disclosure digest');
  const signedDigests = Array.isArray(payload._sd) ? payload._sd.filter((item) => typeof item === 'string') : [];
  const digests = new Set(signedDigests);
  if (digests.size !== signedDigests.length) throw new SdJwtError('bad-disclosure', 'The credential repeats a digest');
  // No prototype: a claim named like an Object property stays data.
  const claims: Record<string, unknown> = Object.assign(Object.create(null) as Record<string, unknown>, payload);
  delete claims._sd;
  delete claims._sd_alg;
  const used = new Set<string>();
  const disclosed: string[] = [];
  for (const encoded of disclosures) {
    const digest = digestOf(encoded);
    if (!digests.has(digest) || used.has(digest))
      throw new SdJwtError('bad-disclosure', 'A disclosure was not signed by the issuer');
    used.add(digest);
    const { name, value: claim } = readDisclosure(encoded);
    if (reservedVcClaims.has(name) || Object.hasOwn(claims, name))
      throw new SdJwtError('bad-disclosure', `The disclosure of ${name.slice(0, 64)} is not allowed`);
    claims[name] = claim;
    disclosed.push(name);
  }
  const cnf = payload.cnf as { jwk?: unknown } | undefined;
  const holderKey = cnf?.jwk !== undefined ? publicJwk(cnf.jwk) : undefined;
  let keyBindingClaims: VerifiedSdJwt['keyBinding'];
  if (keyBinding) {
    if (!holderKey) throw new SdJwtError('bad-key-binding', 'The credential has no holder key');
    let kbHeader: ReturnType<typeof decodeProtectedHeader>;
    try {
      kbHeader = decodeProtectedHeader(keyBinding);
    } catch {
      throw new SdJwtError('bad-key-binding', 'The key-binding JWT cannot be decoded');
    }
    if (kbHeader.typ !== KB_JWT_TYPE || !sdJwtAlgorithms.includes(kbHeader.alg as never))
      throw new SdJwtError('bad-key-binding', 'Not a key-binding JWT');
    let kb: JWTPayload;
    try {
      ({ payload: kb } = await jwtVerify(keyBinding, await importJWK(holderKey, kbHeader.alg), {
        algorithms: [kbHeader.alg!],
        currentDate: new Date(now),
        clockTolerance: tolerance,
      }));
    } catch {
      throw new SdJwtError('bad-key-binding', 'The key-binding signature does not verify');
    }
    if (kb.sd_hash !== digestOf(value.slice(0, value.length - keyBinding.length)))
      throw new SdJwtError('bad-key-binding', 'The key-binding JWT covers another presentation');
    if (options.audience !== undefined && kb.aud !== options.audience)
      throw new SdJwtError('wrong-audience', 'The presentation is for another verifier');
    if (options.nonce !== undefined && kb.nonce !== options.nonce)
      throw new SdJwtError('wrong-nonce', 'The presentation answers another request');
    const age = now / 1000 - (typeof kb.iat === 'number' ? kb.iat : 0);
    if (typeof kb.iat !== 'number' || age > (options.maxKeyBindingAgeSeconds ?? 300) || age < -tolerance)
      throw new SdJwtError('stale-key-binding', 'The presentation is too old');
    keyBindingClaims = {
      ...(typeof kb.aud === 'string' ? { audience: kb.aud } : {}),
      ...(typeof kb.nonce === 'string' ? { nonce: kb.nonce } : {}),
      issuedAt: kb.iat * 1000,
    };
  } else if (options.requireKeyBinding !== false)
    throw new SdJwtError('key-binding-required', 'A presentation needs a key-binding JWT');
  const reference = (payload.status as { status_list?: { idx?: unknown; uri?: unknown } } | undefined)?.status_list;
  return {
    issuer: payload.iss!,
    keyId: header.kid,
    ...(typeof payload.vct === 'string' ? { vct: payload.vct } : {}),
    // A plain copy: spreading defines own properties, so no key can reach a prototype.
    claims: { ...claims },
    disclosed,
    ...(holderKey ? { holderKey } : {}),
    ...(reference && typeof reference.idx === 'number' && typeof reference.uri === 'string'
      ? { status: { index: reference.idx, uri: reference.uri } }
      : {}),
    ...(typeof payload.iat === 'number' ? { issuedAt: payload.iat * 1000 } : {}),
    ...(typeof payload.exp === 'number' ? { expiresAt: payload.exp * 1000 } : {}),
    keyBound: Boolean(keyBinding),
    ...(keyBindingClaims ? { keyBinding: keyBindingClaims } : {}),
  };
}

/** Status values of the Token Status List. */
export const STATUS_VALID = 0;
export const STATUS_INVALID = 1;
export const STATUS_SUSPENDED = 2;

/** Reads the status of `index` from a raw list of `bits`-bit entries (index 0 is the low bits of byte 0). */
export function statusAt(bytes: Buffer, index: number, bits: 1 | 2 | 4 | 8): number {
  const perByte = 8 / bits;
  const byte = bytes[Math.floor(index / perByte)];
  if (byte === undefined) throw new SdJwtError('status-unavailable', 'The status index is outside the list');
  return (byte >> ((index % perByte) * bits)) & ((1 << bits) - 1);
}

/** Writes the status of `index` into a raw list. */
export function setStatusAt(bytes: Buffer, index: number, bits: 1 | 2 | 4 | 8, value: number): void {
  const perByte = 8 / bits;
  const position = Math.floor(index / perByte);
  if (position >= bytes.length || value < 0 || value >= 1 << bits) throw new RangeError('Status out of range');
  const shift = (index % perByte) * bits;
  const mask = ((1 << bits) - 1) << shift;
  bytes[position] = (bytes[position]! & ~mask) | (value << shift);
}

/** A Status List Token (JWT, `typ: statuslist+jwt`) for a raw list. */
export async function signStatusList(input: {
  uri: string;
  bytes: Buffer;
  bits: 1 | 2 | 4 | 8;
  alg: (typeof sdJwtAlgorithms)[number];
  kid: string;
  key: KeyObject | CryptoKey;
  issuedAt: number;
  expiresAt: number;
  ttlSeconds: number;
}): Promise<string> {
  return new SignJWT({
    sub: input.uri,
    iat: Math.floor(input.issuedAt / 1000),
    exp: Math.floor(input.expiresAt / 1000),
    ttl: input.ttlSeconds,
    status_list: { bits: input.bits, lst: deflateSync(input.bytes).toString('base64url') },
  })
    .setProtectedHeader({ alg: input.alg, kid: input.kid, typ: STATUS_LIST_JWT_TYPE })
    .sign(input.key);
}

/** Verifies a Status List Token for `uri` and returns its raw list. */
export async function readStatusList(
  token: string,
  key: KeyObject | CryptoKey | JWK,
  options: { uri: string; now?: number },
): Promise<{ bits: 1 | 2 | 4 | 8; bytes: Buffer }> {
  try {
    const header = decodeProtectedHeader(token);
    if (header.typ !== STATUS_LIST_JWT_TYPE) throw new Error('typ');
    const verifying = 'kty' in (key as object) ? await importJWK(key as JWK, header.alg) : (key as KeyObject);
    const { payload } = await jwtVerify(token, verifying, {
      algorithms: [...sdJwtAlgorithms],
      requiredClaims: ['iat'],
      subject: options.uri,
      currentDate: new Date(options.now ?? Date.now()),
      clockTolerance: 5,
    });
    const list = payload.status_list as { bits?: unknown; lst?: unknown } | undefined;
    if (![1, 2, 4, 8].includes(list?.bits as number) || typeof list?.lst !== 'string') throw new Error('list');
    return {
      bits: list.bits as 1 | 2 | 4 | 8,
      bytes: inflateSync(Buffer.from(list.lst, 'base64url'), { maxOutputLength: 16 * 1024 * 1024 }),
    };
  } catch (error) {
    if (error instanceof SdJwtError) throw error;
    throw new SdJwtError('status-unavailable', 'The status list does not verify');
  }
}

/**
 * Verifies an OpenID4VCI holder proof (`typ: openid4vci-proof+jwt`, the holder's public key in the `jwk` header):
 * signature, `aud` (the credential issuer), freshness, and the nonce the issuer handed out. Returns the holder key and
 * its RFC 7638 thumbprint.
 */
export async function verifyHolderProof(
  proof: unknown,
  options: { audience: string; now?: number; maxAgeSeconds?: number },
): Promise<{ jwk: JWK; thumbprint: string; nonce?: string }> {
  if (typeof proof !== 'string' || proof.length > 8192) throw new SdJwtError('malformed', 'Invalid proof');
  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(proof);
  } catch {
    throw new SdJwtError('malformed', 'Invalid proof');
  }
  if (header.typ !== HOLDER_PROOF_TYPE || !sdJwtAlgorithms.includes(header.alg as never) || !header.jwk)
    throw new SdJwtError('malformed', 'The proof must be an openid4vci-proof+jwt with a jwk header');
  // OpenID4VCI: exactly one way to name the key.
  if (header.kid !== undefined || header.x5c !== undefined)
    throw new SdJwtError('malformed', 'A proof names its key with jwk only (no kid or x5c)');
  const jwk = publicJwk(header.jwk);
  const now = options.now ?? Date.now();
  let payload: JWTPayload;
  try {
    ({ payload } = await jwtVerify(proof, EmbeddedJWK, {
      algorithms: [header.alg!],
      audience: options.audience,
      currentDate: new Date(now),
      clockTolerance: 5,
    }));
  } catch {
    throw new SdJwtError('bad-key-binding', 'The proof does not verify for this issuer');
  }
  const age = now / 1000 - (typeof payload.iat === 'number' ? payload.iat : 0);
  if (typeof payload.iat !== 'number' || age > (options.maxAgeSeconds ?? 300) || age < -5)
    throw new SdJwtError('stale-key-binding', 'The proof is too old');
  const { kty, crv, x, y, n, e } = jwk as Record<string, string | undefined>;
  const clean = Object.fromEntries(
    Object.entries({ kty, crv, x, y, n, e }).filter(([, item]) => item !== undefined),
  ) as JWK;
  return {
    jwk: clean,
    thumbprint: await calculateJwkThumbprint(clean),
    ...(typeof payload.nonce === 'string' ? { nonce: payload.nonce } : {}),
  };
}
