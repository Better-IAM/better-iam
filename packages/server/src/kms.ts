import {
  constants,
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPair,
  privateDecrypt,
  publicEncrypt,
  randomBytes,
  sign as signData,
  timingSafeEqual,
  verify as verifyData,
  type JsonWebKey,
  type KeyObject,
} from 'node:crypto';
import { promisify } from 'node:util';
import { encryptSecret, openSecret } from '@better-iam/auth';
import {
  IamError,
  canonicalizeJson,
  type AuthenticatedPrincipal,
  type IamStore,
  type Json,
  type StoredRecord,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import { id } from './utils.js';
import { object, text } from './validation.js';

/**
 * Key management (KMS): tenant keys whose material never leaves the server. Symmetric keys encrypt and decrypt
 * (AES-256-GCM, bound to an encryption context), asymmetric keys sign and verify (ECDSA, Ed25519, RSA) or encrypt
 * (RSA-OAEP), and HMAC keys compute and check message authentication codes. Every key keeps its old versions, so
 * rotation never breaks existing ciphertexts or signatures. Material is sealed under the deployment secret (and
 * re-sealed by `iam.rotateSecrets()`); the API lives in api/keys.ts.
 */

export type KeySpec =
  | 'aes-256-gcm'
  | 'hmac-sha256'
  | 'hmac-sha384'
  | 'hmac-sha512'
  | 'ecc-p256'
  | 'ecc-p384'
  | 'ed25519'
  | 'rsa-2048'
  | 'rsa-3072'
  | 'rsa-4096';
export type KeyUsage = 'encrypt' | 'sign' | 'mac';
export type KeyState = 'enabled' | 'disabled' | 'pending-deletion';
export type SigningAlgorithm =
  | 'ES256'
  | 'ES384'
  | 'EdDSA'
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512';
export type MacAlgorithm = 'HS256' | 'HS384' | 'HS512';
/** The operations a key grant can allow; each maps to one `iam:kms:*` action. */
export type GrantOperation =
  | 'read'
  | 'encrypt'
  | 'decrypt'
  | 'generate-data-key'
  | 'sign'
  | 'verify'
  | 'generate-mac'
  | 'verify-mac';

interface SpecInfo {
  usages: readonly KeyUsage[];
  family: 'aes' | 'hmac' | 'ec' | 'ed25519' | 'rsa';
  /** HMAC key length in bytes, or the RSA modulus length in bits. */
  size?: number;
  hash?: 'sha256' | 'sha384' | 'sha512';
  curve?: 'P-256' | 'P-384';
}

export const keySpecs: Readonly<Record<KeySpec, SpecInfo>> = Object.freeze({
  'aes-256-gcm': { usages: ['encrypt'], family: 'aes' },
  'hmac-sha256': { usages: ['mac'], family: 'hmac', size: 32, hash: 'sha256' },
  'hmac-sha384': { usages: ['mac'], family: 'hmac', size: 48, hash: 'sha384' },
  'hmac-sha512': { usages: ['mac'], family: 'hmac', size: 64, hash: 'sha512' },
  'ecc-p256': { usages: ['sign'], family: 'ec', curve: 'P-256', hash: 'sha256' },
  'ecc-p384': { usages: ['sign'], family: 'ec', curve: 'P-384', hash: 'sha384' },
  ed25519: { usages: ['sign'], family: 'ed25519' },
  'rsa-2048': { usages: ['encrypt', 'sign'], family: 'rsa', size: 2048 },
  'rsa-3072': { usages: ['encrypt', 'sign'], family: 'rsa', size: 3072 },
  'rsa-4096': { usages: ['encrypt', 'sign'], family: 'rsa', size: 4096 },
});

/** The actions KMS authorizes, by operation. Management actions are `create/read/update/delete/grant`. */
export const kmsActions = Object.freeze({
  create: 'iam:kms:create',
  read: 'iam:kms:read',
  update: 'iam:kms:update',
  delete: 'iam:kms:delete',
  grant: 'iam:kms:grant',
  encrypt: 'iam:kms:encrypt',
  decrypt: 'iam:kms:decrypt',
  'generate-data-key': 'iam:kms:generate-data-key',
  sign: 'iam:kms:sign',
  verify: 'iam:kms:verify',
  'generate-mac': 'iam:kms:generate-mac',
  'verify-mac': 'iam:kms:verify-mac',
});

/** Grant operations, keyed by the action they allow. */
export const grantOperationOf: Readonly<Record<string, GrantOperation>> = Object.freeze({
  [kmsActions.read]: 'read',
  [kmsActions.encrypt]: 'encrypt',
  [kmsActions.decrypt]: 'decrypt',
  [kmsActions['generate-data-key']]: 'generate-data-key',
  [kmsActions.sign]: 'sign',
  [kmsActions.verify]: 'verify',
  [kmsActions['generate-mac']]: 'generate-mac',
  [kmsActions['verify-mac']]: 'verify-mac',
});

const operationsByUsage: Readonly<Record<KeyUsage, readonly GrantOperation[]>> = {
  encrypt: ['read', 'encrypt', 'decrypt', 'generate-data-key'],
  sign: ['read', 'sign', 'verify'],
  mac: ['read', 'generate-mac', 'verify-mac'],
};
/** Operations that carry an encryption context, the only ones a context-constrained grant may allow. */
const contextOperations = new Set<GrantOperation>(['encrypt', 'decrypt', 'generate-data-key']);

export interface KmsKey extends StoredRecord {
  description?: string;
  keySpec: KeySpec;
  keyUsage: KeyUsage;
  state: KeyState;
  /** The version encrypt, sign and MAC calls use; older versions still decrypt and verify. */
  currentVersion: number;
  tags: Record<string, string>;
  /** Automatic rotation period; absent when the key rotates only on demand. */
  rotationPeriodDays?: number;
  nextRotationAt?: number;
  lastRotatedAt?: number;
  /** When a key pending deletion is destroyed, with every version, alias and grant. */
  deletionDate?: number;
  /**
   * A key that belongs to another module (a certificate authority's signing key, a protection profile's key): the KMS
   * API refuses to encrypt, decrypt, sign or grant with it directly, so nobody can use it around that module's own
   * checks. It can still be read, tagged, disabled and deleted.
   */
  managedBy?: 'pki' | 'protection';
  managedId?: string;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export interface KmsKeyVersion extends StoredRecord {
  keyId: string;
  version: number;
  /** How the material is sealed: `secret` = under the deployment secret (re-sealed by `iam.rotateSecrets()`). */
  wrapper: 'secret';
  materialSealed: string;
  /** SPKI PEM of an asymmetric key version. */
  publicKeyPem?: string;
  createdAt: number;
  /** `create`, `rotate` (on demand) or `automatic`. */
  origin: 'create' | 'rotate' | 'automatic';
}

export interface KmsAlias extends StoredRecord {
  /** `alias/{name}`; also the uniqueKey, so an alias names one key per tenant. */
  name: string;
  keyId: string;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export interface GrantConstraints {
  /** The request's encryption context must equal this one exactly. */
  encryptionContextEquals?: Record<string, string>;
  /** The request's encryption context must contain every one of these pairs. */
  encryptionContextSubset?: Record<string, string>;
}

export interface KmsGrant extends StoredRecord {
  keyId: string;
  name?: string;
  /** Grants name one identity (a person, service account or agent); groups are not grantees. */
  granteeType: 'identity';
  granteeId: string;
  operations: GrantOperation[];
  constraints?: GrantConstraints;
  expiresAt?: number;
  createdAt: number;
  createdBy: string;
}

/** The public view of a key: never its material. */
export interface KeySummary {
  id: string;
  tenantId: string;
  description?: string;
  keySpec: KeySpec;
  keyUsage: KeyUsage;
  state: KeyState;
  currentVersion: number;
  tags: Record<string, string>;
  aliases: string[];
  /** Signing or MAC algorithms the key supports (none for encryption keys). */
  algorithms: string[];
  rotationPeriodDays?: number;
  nextRotationAt?: number;
  lastRotatedAt?: number;
  deletionDate?: number;
  /** The module the key belongs to; the KMS API does not use it directly. */
  managedBy?: 'pki' | 'protection';
  managedId?: string;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export interface GrantSummary {
  id: string;
  tenantId: string;
  keyId: string;
  name?: string;
  /** Grants name one identity (a person, service account or agent); groups are not grantees. */
  granteeType: 'identity';
  granteeId: string;
  operations: GrantOperation[];
  constraints?: GrantConstraints;
  expiresAt?: number;
  active: boolean;
  createdAt: number;
  createdBy: string;
}

export type EncryptionContext = Record<string, string>;

export const MAX_KEYS_PER_TENANT = 1000;
export const MAX_VERSIONS = 1000;
export const MAX_ALIASES_PER_KEY = 50;
export const MAX_GRANTS_PER_KEY = 50;
/** Plaintext accepted by `encrypt` (AES-GCM); RSA-OAEP accepts what the modulus allows. */
export const MAX_PLAINTEXT_BYTES = 4096;
/** Messages accepted by `sign`, `verify` and the MAC calls. */
export const MAX_MESSAGE_BYTES = 65536;
const MAX_CIPHERTEXT_CHARS = 16384;

const CIPHERTEXT_PREFIX = 'kms1';
const tagKey = /^[A-Za-z0-9_.:/=+@-]{1,128}$/;
const contextKey = /^[A-Za-z0-9_.:/=+@-]{1,128}$/;
const unsafeKeys = new Set(['__proto__', 'prototype', 'constructor']);
export const aliasPattern = /^alias\/[A-Za-z0-9/_-]{1,250}$/;
const keyIdPattern = /^[A-Za-z0-9-]{1,64}$/;

const b64url = (value: Uint8Array | string): string => Buffer.from(value).toString('base64url');

export function keySpec(value: unknown): KeySpec {
  if (typeof value !== 'string' || !Object.hasOwn(keySpecs, value))
    throw new IamError(
      'INVALID_INPUT',
      `keySpec must be one of ${Object.keys(keySpecs).join(', ')}`,
    );
  return value as KeySpec;
}

/** The usage a new key gets: the one its spec allows, or (for RSA) the one asked for. */
export function keyUsageFor(spec: KeySpec, value: unknown): KeyUsage {
  const usages = keySpecs[spec].usages;
  if (value === undefined) {
    if (usages.length === 1) return usages[0]!;
    throw new IamError('INVALID_INPUT', `keyUsage is required for ${spec} (encrypt or sign)`);
  }
  if (typeof value !== 'string' || !usages.includes(value as KeyUsage))
    throw new IamError('INVALID_INPUT', `${spec} keys support keyUsage ${usages.join(' or ')}`);
  return value as KeyUsage;
}

/** Up to 50 tags; keys are identifiers, values short strings (they become `resource.tags.{key}`). */
export function keyTags(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  const input = object(value);
  const entries = Object.entries(input);
  if (entries.length > 50) throw new IamError('INVALID_INPUT', 'At most 50 tags');
  const tags: Record<string, string> = {};
  for (const [key, item] of entries) {
    if (!tagKey.test(key) || unsafeKeys.has(key))
      throw new IamError('INVALID_INPUT', `Invalid tag key ${key}`);
    if (typeof item !== 'string' || item.length > 256 || /[\u0000-\u001f]/.test(item))
      throw new IamError('INVALID_INPUT', `Tag ${key} must be a string of at most 256 characters`);
    tags[key] = item;
  }
  return tags;
}

/**
 * An encryption context: up to 16 non-secret key/value pairs bound to a ciphertext as additional authenticated data.
 * Decryption must present the same pairs. They are recorded in the audit trail and exposed to policies as
 * `resource.encryptionContext.{key}`, so never put secrets in them.
 */
export function encryptionContext(value: unknown, name = 'encryptionContext'): EncryptionContext {
  if (value === undefined) return {};
  const input = object(value);
  const entries = Object.entries(input);
  if (entries.length > 16) throw new IamError('INVALID_INPUT', `${name} has more than 16 pairs`);
  const result: EncryptionContext = {};
  for (const [key, item] of entries) {
    if (!contextKey.test(key) || unsafeKeys.has(key))
      throw new IamError('INVALID_INPUT', `Invalid ${name} key ${key}`);
    if (typeof item !== 'string' || !item || item.length > 1024 || /[\u0000-\u001f]/.test(item))
      throw new IamError(
        'INVALID_INPUT',
        `${name} values must be non-empty strings of at most 1024 characters`,
      );
    result[key] = item;
  }
  return result;
}

/**
 * Decodes canonical standard or URL-safe base64 (padding optional), refusing anything else and anything longer
 * than `max` bytes. Canonical only: one byte string has one accepted spelling, so string-keyed replay caches hold.
 */
export function base64Bytes(value: unknown, name: string, max: number): Buffer {
  const urlSafe = typeof value === 'string' && /^[A-Za-z0-9_-]*$/.test(value);
  if (
    typeof value !== 'string' ||
    value.length > Math.ceil((max * 4) / 3) + 4 ||
    !(urlSafe || /^[A-Za-z0-9+/]*={0,2}$/.test(value))
  )
    throw new IamError('INVALID_INPUT', `${name} must be base64`);
  const bytes = Buffer.from(value, urlSafe ? 'base64url' : 'base64');
  const again = bytes.toString(urlSafe ? 'base64url' : 'base64');
  if (again.replace(/=+$/, '') !== value.replace(/=+$/, ''))
    throw new IamError('INVALID_INPUT', `${name} must be canonical base64`);
  if (bytes.length > max)
    throw new IamError('INVALID_INPUT', `${name} is longer than ${max} bytes`);
  return bytes;
}

/**
 * Reads a payload given as text (`{name}`, UTF-8) or bytes (`{name}Base64`): exactly one of the two. Says which, so
 * decryption can return the same form.
 */
export function payload(
  input: Record<string, unknown>,
  name: string,
  max: number,
): { bytes: Buffer; text: boolean } {
  const plain = input[name];
  const encoded = input[`${name}Base64`];
  if ((plain === undefined) === (encoded === undefined))
    throw new IamError('INVALID_INPUT', `Provide either ${name} or ${name}Base64`);
  if (plain !== undefined) {
    if (typeof plain !== 'string') throw new IamError('INVALID_INPUT', `${name} must be a string`);
    const bytes = Buffer.from(plain, 'utf8');
    if (bytes.length > max)
      throw new IamError('INVALID_INPUT', `${name} is longer than ${max} bytes`);
    return { bytes, text: true };
  }
  return { bytes: base64Bytes(encoded, `${name}Base64`, max), text: false };
}

/** The algorithms a key signs or computes MACs with (encryption keys: none). */
export function keyAlgorithms(key: Pick<KmsKey, 'keySpec' | 'keyUsage'>): string[] {
  const spec = keySpecs[key.keySpec];
  if (key.keyUsage === 'mac') return [`HS${spec.hash!.slice(3)}`];
  if (key.keyUsage !== 'sign') return [];
  if (spec.family === 'ec') return [spec.curve === 'P-256' ? 'ES256' : 'ES384'];
  if (spec.family === 'ed25519') return ['EdDSA'];
  return ['PS256', 'PS384', 'PS512', 'RS256', 'RS384', 'RS512'];
}

export function signingAlgorithm(
  key: Pick<KmsKey, 'keySpec' | 'keyUsage'>,
  value: unknown,
): string {
  const supported = keyAlgorithms(key);
  if (value === undefined) return supported[0]!;
  if (typeof value !== 'string' || !supported.includes(value))
    throw new IamError('INVALID_INPUT', `This key supports the algorithms ${supported.join(', ')}`);
  return value;
}

export function summarizeKey(key: KmsKey, aliases: string[]): KeySummary {
  const summary: KeySummary = {
    id: key.id,
    tenantId: key.tenantId,
    keySpec: key.keySpec,
    keyUsage: key.keyUsage,
    state: key.state,
    currentVersion: key.currentVersion,
    tags: { ...key.tags },
    aliases: [...aliases].sort(),
    algorithms: keyAlgorithms(key),
    createdAt: key.createdAt,
    createdBy: key.createdBy,
    updatedAt: key.updatedAt,
  };
  if (key.description !== undefined) summary.description = key.description;
  if (key.rotationPeriodDays !== undefined) summary.rotationPeriodDays = key.rotationPeriodDays;
  if (key.nextRotationAt !== undefined) summary.nextRotationAt = key.nextRotationAt;
  if (key.lastRotatedAt !== undefined) summary.lastRotatedAt = key.lastRotatedAt;
  if (key.deletionDate !== undefined) summary.deletionDate = key.deletionDate;
  if (key.managedBy !== undefined) summary.managedBy = key.managedBy;
  if (key.managedId !== undefined) summary.managedId = key.managedId;
  return summary;
}

/** Refuses direct cryptographic use of a key another module owns (`KEY_MANAGED`). */
export function assertUnmanaged(key: Pick<KmsKey, 'managedBy'>): void {
  if (key.managedBy)
    throw new IamError(
      'KEY_MANAGED',
      key.managedBy === 'pki'
        ? 'This key signs for a certificate authority; issue certificates through the pki API'
        : 'This key protects a data protection profile; use the protection API',
      409,
    );
}

export function summarizeGrant(grant: KmsGrant, now: number): GrantSummary {
  const summary: GrantSummary = {
    id: grant.id,
    tenantId: grant.tenantId,
    keyId: grant.keyId,
    granteeType: grant.granteeType,
    granteeId: grant.granteeId,
    operations: [...grant.operations],
    active: grant.expiresAt === undefined || grant.expiresAt > now,
    createdAt: grant.createdAt,
    createdBy: grant.createdBy,
  };
  if (grant.name !== undefined) summary.name = grant.name;
  if (grant.constraints !== undefined) summary.constraints = structuredClone(grant.constraints);
  if (grant.expiresAt !== undefined) summary.expiresAt = grant.expiresAt;
  return summary;
}

/**
 * The attributes a key presents to policies (`resource.{name}`): identity, spec, usage, state, aliases, tags as
 * `resource.tags.{key}`, and for calls with one the encryption context as `resource.encryptionContext.{key}` plus
 * `resource.encryptionContextKeys`, and a signing call's `resource.algorithm`.
 */
export function keyAttributes(
  key: Pick<KmsKey, 'id' | 'keySpec' | 'keyUsage' | 'state' | 'tags' | 'createdBy' | 'managedBy'>,
  aliases: string[],
  extra: { context?: EncryptionContext; algorithm?: string } = {},
): Record<string, unknown> {
  const attributes: Record<string, unknown> = {
    keyId: key.id,
    keySpec: key.keySpec,
    keyUsage: key.keyUsage,
    keyState: key.state,
    aliases: [...aliases].sort(),
    createdBy: key.createdBy,
    ...(key.managedBy ? { managedBy: key.managedBy } : {}),
  };
  for (const [name, value] of Object.entries(key.tags)) attributes[`tags.${name}`] = value;
  if (extra.context) {
    const keys = Object.keys(extra.context).sort();
    attributes.encryptionContextKeys = keys;
    for (const name of keys) attributes[`encryptionContext.${name}`] = extra.context[name];
  }
  if (extra.algorithm !== undefined) attributes.algorithm = extra.algorithm;
  return attributes;
}

/** Attributes for creating a key: what it would be, so policies can require tags or specs (`resource.tags.team`). */
export function requestAttributes(
  spec: KeySpec,
  usage: KeyUsage,
  tags: Record<string, string>,
): Record<string, unknown> {
  const attributes: Record<string, unknown> = { keySpec: spec, keyUsage: usage };
  for (const [name, value] of Object.entries(tags)) attributes[`tags.${name}`] = value;
  return attributes;
}

// ---------------------------------------------------------------------------------------------------------------
// Key material

const versionContext = (keyId: string, version: number) => `kms-key:${keyId}:${version}`;

/** Where sealed key material lives, for `iam.rotateSecrets()` (secrets.ts). */
export const kmsSealedField = {
  collection: 'kmsKeyVersions',
  filter: { wrapper: 'secret' },
  read: (record: StoredRecord) =>
    typeof record.materialSealed === 'string' ? record.materialSealed : undefined,
  write: (record: StoredRecord, sealed: string) => ({ ...record, materialSealed: sealed }),
  context: (record: StoredRecord) => versionContext(String(record.keyId), Number(record.version)),
};

const generatePair = promisify(generateKeyPair) as (
  type: 'ec' | 'ed25519' | 'rsa',
  options: Record<string, unknown>,
) => Promise<{ publicKey: KeyObject; privateKey: KeyObject }>;

/**
 * New key material: raw bytes (base64url) for AES and HMAC keys, a PKCS#8 PEM private key otherwise. Key pairs are
 * generated off the event loop (RSA-4096 takes up to a second), so one tenant's rotation never stalls the others.
 */
async function generateMaterial(
  spec: KeySpec,
): Promise<{ material: string; publicKeyPem?: string }> {
  const info = keySpecs[spec];
  if (info.family === 'aes') return { material: b64url(randomBytes(32)) };
  if (info.family === 'hmac') return { material: b64url(randomBytes(info.size!)) };
  const pair =
    info.family === 'ec'
      ? await generatePair('ec', { namedCurve: info.curve! })
      : info.family === 'ed25519'
        ? await generatePair('ed25519', {})
        : await generatePair('rsa', { modulusLength: info.size!, publicExponent: 65537 });
  return {
    material: pair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
    publicKeyPem: pair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
  };
}

/** Generates, seals and stores a new version of a key. */
export async function addKeyVersion(
  ctx: ServerContext,
  tx: IamStore,
  key: Pick<KmsKey, 'id' | 'tenantId' | 'keySpec'>,
  version: number,
  origin: KmsKeyVersion['origin'],
): Promise<KmsKeyVersion> {
  const { material, publicKeyPem } = await generateMaterial(key.keySpec);
  const record: KmsKeyVersion = {
    id: id(),
    tenantId: key.tenantId,
    uniqueKey: `${key.id}:${version}`,
    keyId: key.id,
    version,
    wrapper: 'secret',
    materialSealed: encryptSecret(material, ctx.options.secret, versionContext(key.id, version)),
    createdAt: ctx.now(),
    origin,
  };
  if (publicKeyPem !== undefined) record.publicKeyPem = publicKeyPem;
  return tx.insert<KmsKeyVersion>('kmsKeyVersions', record);
}

export async function keyVersion(
  tx: IamStore,
  key: Pick<KmsKey, 'id' | 'tenantId'>,
  version: number,
): Promise<KmsKeyVersion> {
  const found = (
    await tx.find<KmsKeyVersion>('kmsKeyVersions', {
      tenantId: key.tenantId,
      uniqueKey: `${key.id}:${version}`,
    })
  )[0];
  if (!found) throw new IamError('NOT_FOUND', 'Key version not found', 404);
  return found;
}

/** Opens a version's sealed material with the deployment secret (or a previous one during a rotation). */
function openMaterial(ctx: ServerContext, version: KmsKeyVersion): string {
  const opened = openSecret(
    version.materialSealed,
    [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])],
    versionContext(version.keyId, version.version),
  );
  if (!opened)
    throw new IamError(
      'KEY_MATERIAL_UNAVAILABLE',
      'The key material cannot be opened with the configured secrets',
      500,
    );
  return opened.value;
}

const symmetricKey = (ctx: ServerContext, version: KmsKeyVersion): Buffer =>
  Buffer.from(openMaterial(ctx, version), 'base64url');
const privateKey = (ctx: ServerContext, version: KmsKeyVersion): KeyObject =>
  createPrivateKey(openMaterial(ctx, version));
function publicKey(version: KmsKeyVersion): KeyObject {
  if (!version.publicKeyPem) throw new IamError('INVALID_INPUT', 'This key has no public key');
  return createPublicKey(version.publicKeyPem);
}

// ---------------------------------------------------------------------------------------------------------------
// Ciphertexts: `kms1.{keyId}.{version}.{t|b}.{payload}`. The header (with the plaintext form `t` text / `b` bytes)
// and the canonical encryption context are authenticated; the payload is iv|tag|ciphertext (AES-GCM) or the
// RSA-OAEP (SHA-256) ciphertext, whose label carries the same associated data.

export interface CiphertextHeader {
  keyId: string;
  version: number;
  text: boolean;
  payload: Buffer;
  header: string;
}

export function parseCiphertext(value: unknown): CiphertextHeader {
  const invalid = () => new IamError('INVALID_CIPHERTEXT', 'The ciphertext is not valid', 400);
  if (typeof value !== 'string' || value.length > MAX_CIPHERTEXT_CHARS) throw invalid();
  const parts = value.split('.');
  if (parts.length !== 5 || parts[0] !== CIPHERTEXT_PREFIX) throw invalid();
  const [, keyId, versionText, form, encoded] = parts as [string, string, string, string, string];
  if (!keyIdPattern.test(keyId) || !/^[1-9]\d{0,5}$/.test(versionText)) throw invalid();
  if (form !== 't' && form !== 'b') throw invalid();
  if (!/^[A-Za-z0-9_-]+$/.test(encoded)) throw invalid();
  const payload = Buffer.from(encoded, 'base64url');
  // One spelling per ciphertext: non-canonical trailing bits would give the same bytes several string forms.
  if (payload.toString('base64url') !== encoded) throw invalid();
  return {
    keyId,
    version: Number(versionText),
    text: form === 't',
    payload,
    header: `${CIPHERTEXT_PREFIX}.${keyId}.${versionText}.${form}`,
  };
}

const associatedData = (header: string, context: EncryptionContext) =>
  Buffer.from(`${header}\n${canonicalizeJson(context)}`, 'utf8');

const oaepCapacity = (spec: KeySpec) => keySpecs[spec].size! / 8 - 2 * 32 - 2;

export function encryptWith(
  ctx: ServerContext,
  key: KmsKey,
  version: KmsKeyVersion,
  plaintext: Buffer,
  isText: boolean,
  context: EncryptionContext,
): string {
  const header = `${CIPHERTEXT_PREFIX}.${key.id}.${version.version}.${isText ? 't' : 'b'}`;
  const aad = associatedData(header, context);
  if (keySpecs[key.keySpec].family === 'rsa') {
    if (plaintext.length > oaepCapacity(key.keySpec))
      throw new IamError(
        'INVALID_INPUT',
        `${key.keySpec} keys encrypt at most ${oaepCapacity(key.keySpec)} bytes; encrypt a data key instead`,
      );
    const encrypted = publicEncrypt(
      {
        key: publicKey(version),
        padding: constants.RSA_PKCS1_OAEP_PADDING,
        oaepHash: 'sha256',
        oaepLabel: aad,
      },
      plaintext,
    );
    return `${header}.${b64url(encrypted)}`;
  }
  if (plaintext.length > MAX_PLAINTEXT_BYTES)
    throw new IamError(
      'INVALID_INPUT',
      `Encrypt at most ${MAX_PLAINTEXT_BYTES} bytes directly; use generateDataKey for more`,
    );
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', symmetricKey(ctx, version), iv);
  cipher.setAAD(aad);
  const encrypted = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  return `${header}.${b64url(Buffer.concat([iv, cipher.getAuthTag(), encrypted]))}`;
}

/** Decrypts; any tampering, wrong key version or different encryption context fails the same way. */
export function decryptWith(
  ctx: ServerContext,
  key: KmsKey,
  version: KmsKeyVersion,
  parsed: CiphertextHeader,
  context: EncryptionContext,
): Buffer {
  const aad = associatedData(parsed.header, context);
  try {
    if (keySpecs[key.keySpec].family === 'rsa')
      return privateDecrypt(
        {
          key: privateKey(ctx, version),
          padding: constants.RSA_PKCS1_OAEP_PADDING,
          oaepHash: 'sha256',
          oaepLabel: aad,
        },
        parsed.payload,
      );
    if (parsed.payload.length < 28) throw new Error('short');
    const decipher = createDecipheriv(
      'aes-256-gcm',
      symmetricKey(ctx, version),
      parsed.payload.subarray(0, 12),
    );
    decipher.setAAD(aad);
    decipher.setAuthTag(parsed.payload.subarray(12, 28));
    return Buffer.concat([decipher.update(parsed.payload.subarray(28)), decipher.final()]);
  } catch (error) {
    if (error instanceof IamError && error.code === 'KEY_MATERIAL_UNAVAILABLE') throw error;
    throw new IamError(
      'INVALID_CIPHERTEXT',
      'The ciphertext could not be decrypted with this key and encryption context',
      400,
    );
  }
}

// ---------------------------------------------------------------------------------------------------------------
// Signatures and MACs

const hashOf = (algorithm: string): 'sha256' | 'sha384' | 'sha512' =>
  algorithm.endsWith('384') ? 'sha384' : algorithm.endsWith('512') ? 'sha512' : 'sha256';

export type SignatureFormat = 'der' | 'jose';

export function signWith(
  ctx: ServerContext,
  version: KmsKeyVersion,
  algorithm: string,
  message: Buffer,
  format: SignatureFormat = 'der',
): Buffer {
  const key = privateKey(ctx, version);
  if (algorithm === 'EdDSA') return signData(null, message, key);
  if (algorithm.startsWith('ES'))
    return signData(hashOf(algorithm), message, {
      key,
      dsaEncoding: format === 'jose' ? 'ieee-p1363' : 'der',
    });
  if (algorithm.startsWith('PS'))
    return signData(hashOf(algorithm), message, {
      key,
      padding: constants.RSA_PKCS1_PSS_PADDING,
      saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
    });
  return signData(hashOf(algorithm), message, { key, padding: constants.RSA_PKCS1_PADDING });
}

export function verifyWith(
  version: KmsKeyVersion,
  algorithm: string,
  message: Buffer,
  signature: Buffer,
  format: SignatureFormat = 'der',
): boolean {
  const key = publicKey(version);
  try {
    if (algorithm === 'EdDSA') return verifyData(null, message, key, signature);
    if (algorithm.startsWith('ES'))
      return verifyData(
        hashOf(algorithm),
        message,
        { key, dsaEncoding: format === 'jose' ? 'ieee-p1363' : 'der' },
        signature,
      );
    if (algorithm.startsWith('PS'))
      return verifyData(
        hashOf(algorithm),
        message,
        {
          key,
          padding: constants.RSA_PKCS1_PSS_PADDING,
          saltLength: constants.RSA_PSS_SALTLEN_DIGEST,
        },
        signature,
      );
    return verifyData(
      hashOf(algorithm),
      message,
      { key, padding: constants.RSA_PKCS1_PADDING },
      signature,
    );
  } catch {
    return false;
  }
}

export function macWith(
  ctx: ServerContext,
  key: Pick<KmsKey, 'keySpec'>,
  version: KmsKeyVersion,
  message: Buffer,
): Buffer {
  return createHmac(keySpecs[key.keySpec].hash!, symmetricKey(ctx, version))
    .update(message)
    .digest();
}

export function sameBytes(left: Buffer, right: Buffer): boolean {
  return left.length === right.length && timingSafeEqual(left, right);
}

/** The public key of an asymmetric version as a JWK, `kid` = `{keyId}.{version}`. */
export function publicJwk(key: KmsKey, version: KmsKeyVersion): JsonWebKey & { kid: string } {
  const jwk = publicKey(version).export({ format: 'jwk' }) as JsonWebKey;
  const result: JsonWebKey & { kid: string } = {
    ...jwk,
    kid: `${key.id}.${version.version}`,
    use: key.keyUsage === 'sign' ? 'sig' : 'enc',
  };
  const algorithms = keyAlgorithms(key);
  if (key.keyUsage === 'sign' && algorithms.length === 1) result.alg = algorithms[0];
  // No `alg` for RSA encryption keys: KMS binds its header and encryption context as the OAEP label, so what a
  // plain RSA-OAEP-256 encrypter produces offline is not a KMS ciphertext.
  return result;
}

/** A JWT `kid` of the form `{keyId}.{version}`. */
export function parseKid(value: unknown): { keyId: string; version: number } | undefined {
  if (typeof value !== 'string') return undefined;
  const match = /^([A-Za-z0-9-]{1,64})\.([1-9]\d{0,5})$/.exec(value);
  return match ? { keyId: match[1]!, version: Number(match[2]) } : undefined;
}

// ---------------------------------------------------------------------------------------------------------------
// Grants

export function grantOperations(value: unknown, usage: KeyUsage): GrantOperation[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 8)
    throw new IamError('INVALID_INPUT', 'operations must list 1-8 grant operations');
  const allowed = operationsByUsage[usage];
  const operations = [...new Set(value)];
  for (const operation of operations)
    if (typeof operation !== 'string' || !allowed.includes(operation as GrantOperation))
      throw new IamError(
        'INVALID_INPUT',
        `A ${usage} key's grants may allow ${allowed.join(', ')}`,
      );
  return (operations as GrantOperation[]).sort();
}

export function grantConstraints(
  value: unknown,
  operations: GrantOperation[],
): GrantConstraints | undefined {
  if (value === undefined) return undefined;
  const input = object(value);
  for (const name of Object.keys(input))
    if (name !== 'encryptionContextEquals' && name !== 'encryptionContextSubset')
      throw new IamError('INVALID_INPUT', `Unknown grant constraint ${name}`);
  const constraints: GrantConstraints = {};
  if (input.encryptionContextEquals !== undefined)
    constraints.encryptionContextEquals = encryptionContext(
      input.encryptionContextEquals,
      'encryptionContextEquals',
    );
  if (input.encryptionContextSubset !== undefined)
    constraints.encryptionContextSubset = encryptionContext(
      input.encryptionContextSubset,
      'encryptionContextSubset',
    );
  if (!constraints.encryptionContextEquals && !constraints.encryptionContextSubset)
    throw new IamError('INVALID_INPUT', 'constraints must name an encryption context');
  if (operations.some((operation) => !contextOperations.has(operation)))
    throw new IamError(
      'INVALID_INPUT',
      'Encryption context constraints apply only to encrypt, decrypt and generate-data-key grants',
    );
  return constraints;
}

function contextSatisfies(
  constraints: GrantConstraints | undefined,
  context: EncryptionContext | undefined,
): boolean {
  if (!constraints) return true;
  const actual = context ?? {};
  if (constraints.encryptionContextEquals) {
    const wanted = constraints.encryptionContextEquals;
    const keys = Object.keys(wanted);
    if (keys.length !== Object.keys(actual).length) return false;
    if (keys.some((key) => actual[key] !== wanted[key])) return false;
  }
  if (constraints.encryptionContextSubset)
    for (const [key, value] of Object.entries(constraints.encryptionContextSubset))
      if (!Object.hasOwn(actual, key) || actual[key] !== value) return false;
  return true;
}

/** A session that acts in its own right: a user session or an API key, not derived, not "view as". */
export function actsInOwnRight(principal: AuthenticatedPrincipal): boolean {
  const session = principal.session;
  return (
    (session.kind === 'user' || session.kind === 'api-key') &&
    !session.impersonatorId &&
    session.sourceSessionId === undefined
  );
}

/**
 * The live grants on the key that allow `operation` to the principal's own identity, satisfying their constraints,
 * oldest first. Grants serve people and machine accounts acting in their own right (user sessions and API keys):
 * assumed roles, session tokens, delegated agent sessions and impersonation never use them. The caller still checks
 * that each grant's creator could make the call now (api/keys.ts), so a grant never outlives its creator's access.
 */
export async function candidateGrants(
  ctx: ServerContext,
  tx: IamStore,
  key: KmsKey,
  principal: AuthenticatedPrincipal,
  operation: GrantOperation,
  context: EncryptionContext | undefined,
): Promise<KmsGrant[]> {
  if (
    !actsInOwnRight(principal) ||
    principal.session.tenantId !== key.tenantId ||
    principal.identity.tenantId !== key.tenantId
  )
    return [];
  const now = ctx.now();
  return (
    await tx.find<KmsGrant>('kmsGrants', {
      tenantId: key.tenantId,
      keyId: key.id,
      granteeId: principal.identity.id,
    })
  )
    .filter(
      (grant) =>
        grant.granteeType === 'identity' &&
        (grant.expiresAt === undefined || grant.expiresAt > now) &&
        grant.operations.includes(operation) &&
        contextSatisfies(grant.constraints, context),
    )
    .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1));
}

// ---------------------------------------------------------------------------------------------------------------
// Lookups

/** A key by id or `alias/{name}` within a tenant. */
export async function findKey(tx: IamStore, tenantId: string, reference: unknown): Promise<KmsKey> {
  const value = text(reference, 'keyId', 256);
  if (value.startsWith('alias/')) {
    const alias = (await tx.find<KmsAlias>('kmsAliases', { tenantId, uniqueKey: value }))[0];
    const key = alias && (await tx.get<KmsKey>('kmsKeys', alias.keyId));
    if (!key || key.tenantId !== tenantId) throw new IamError('NOT_FOUND', 'Key not found', 404);
    return key;
  }
  const key = keyIdPattern.test(value) ? await tx.get<KmsKey>('kmsKeys', value) : undefined;
  if (!key || key.tenantId !== tenantId) throw new IamError('NOT_FOUND', 'Key not found', 404);
  return key;
}

export async function aliasNames(tx: IamStore, key: Pick<KmsKey, 'id' | 'tenantId'>) {
  return (await tx.find<KmsAlias>('kmsAliases', { tenantId: key.tenantId, keyId: key.id }))
    .map((alias) => alias.name)
    .sort();
}

export function assertUsable(key: KmsKey, usage: KeyUsage): void {
  if (key.state !== 'enabled')
    throw new IamError(
      'KEY_STATE_INVALID',
      key.state === 'disabled' ? 'The key is disabled' : 'The key is pending deletion',
      409,
    );
  if (key.keyUsage !== usage)
    throw new IamError('INVALID_INPUT', `This key is for ${key.keyUsage}, not ${usage}`);
}

// ---------------------------------------------------------------------------------------------------------------
// Service helpers for other modules (the secrets vault): encryption under a tenant key without a caller permission
// check. The calling module authorizes its own caller; the key's state is still enforced and the use is audited.

export interface KmsServiceUse {
  /** The module using the key, recorded as `metadata.via` (for example `vault`). */
  via: string;
  /** The caller the module acts for, recorded as the event's actor; otherwise `deployment-operator`. */
  principal?: AuthenticatedPrincipal;
}

async function serviceAudit(
  ctx: ServerContext,
  tx: IamStore,
  use: KmsServiceUse,
  action: string,
  key: KmsKey,
  metadata: Record<string, Json>,
) {
  const details = { ...metadata, via: text(use.via, 'via', 64) };
  if (use.principal)
    await ctx.events.audit(
      tx,
      use.principal,
      action,
      key.tenantId,
      `kms/${key.id}`,
      'allow',
      false,
      details,
    );
  else
    await ctx.events.recordAudit(tx, {
      id: id(),
      tenantId: key.tenantId,
      actorId: 'deployment-operator',
      action,
      resourceId: `kms/${key.id}`,
      timestamp: ctx.now(),
      outcome: 'allow',
      metadata: details,
    });
}

const serviceContext = (context: EncryptionContext | string): EncryptionContext =>
  typeof context === 'string'
    ? { context: text(context, 'context', 1024) }
    : encryptionContext(context);

/** A key the service helpers accept: AES only, since they wrap data keys of any payload size. */
function serviceKey(key: KmsKey): void {
  assertUsable(key, 'encrypt');
  if (key.keySpec !== 'aes-256-gcm')
    throw new IamError('INVALID_INPUT', 'Only aes-256-gcm keys can protect stored values');
}

/** At most 16 MiB through the service helpers. */
const MAX_SERVICE_PLAINTEXT = 16 * 1024 * 1024;

/**
 * Encrypts a UTF-8 string of any size (up to 16 MiB) under a tenant's AES key (id or alias) by envelope encryption:
 * a fresh data key encrypts the value locally and the key's current version wraps the data key. The result is
 * `{wrapped data key}~{iv|tag|ciphertext}`, both bound to the encryption context (a string `context` is bound as
 * `{ context }`). Refuses disabled keys, keys pending deletion and non-AES keys.
 */
export async function kmsEncryptFor(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  keyRef: string,
  plaintext: string,
  context: EncryptionContext | string,
  use: KmsServiceUse = { via: 'service' },
): Promise<{ ciphertext: string; keyId: string; keyVersion: number }> {
  const key = await findKey(tx, tenantId, keyRef);
  serviceKey(key);
  const value = Buffer.from(plaintext, 'utf8');
  if (value.length > MAX_SERVICE_PLAINTEXT)
    throw new IamError('INVALID_INPUT', 'The value is larger than 16 MiB');
  const version = await keyVersion(tx, key, key.currentVersion);
  const bound = serviceContext(context);
  const dataKey = randomBytes(32);
  try {
    const wrapped = encryptWith(ctx, key, version, dataKey, false, bound);
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', dataKey, iv);
    // The wrapped key is associated data too, so a payload cannot be paired with another wrapped key.
    cipher.setAAD(associatedData(wrapped, bound));
    const sealed = Buffer.concat([cipher.update(value), cipher.final()]);
    await serviceAudit(ctx, tx, use, kmsActions.encrypt, key, {
      keyVersion: version.version,
      encryptionContextKeys: Object.keys(bound).sort(),
    });
    return {
      ciphertext: `${wrapped}~${b64url(Buffer.concat([iv, cipher.getAuthTag(), sealed]))}`,
      keyId: key.id,
      keyVersion: version.version,
    };
  } finally {
    dataKey.fill(0);
  }
}

/** Decrypts what `kmsEncryptFor` returned; the key must still be enabled and the context the same. */
export async function kmsDecryptFor(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  sealed: { ciphertext: string; keyId?: string; keyVersion?: number },
  context: EncryptionContext | string,
  use: KmsServiceUse = { via: 'service' },
): Promise<string> {
  const invalid = () => new IamError('INVALID_CIPHERTEXT', 'The ciphertext is not valid', 400);
  if (typeof sealed.ciphertext !== 'string' || sealed.ciphertext.length > 23_000_000)
    throw invalid();
  const [wrapped = '', payload = '', ...rest] = sealed.ciphertext.split('~');
  if (rest.length || !/^[A-Za-z0-9_-]+$/.test(payload)) throw invalid();
  const parsed = parseCiphertext(wrapped);
  if (
    (sealed.keyId !== undefined && sealed.keyId !== parsed.keyId) ||
    (sealed.keyVersion !== undefined && sealed.keyVersion !== parsed.version)
  )
    throw invalid();
  const key = await findKey(tx, tenantId, parsed.keyId);
  serviceKey(key);
  const version = await keyVersion(tx, key, parsed.version);
  const bound = serviceContext(context);
  const dataKey = decryptWith(ctx, key, version, parsed, bound);
  try {
    const bytes = Buffer.from(payload, 'base64url');
    if (bytes.length < 28 || dataKey.length !== 32) throw invalid();
    const decipher = createDecipheriv('aes-256-gcm', dataKey, bytes.subarray(0, 12));
    decipher.setAAD(associatedData(wrapped, bound));
    decipher.setAuthTag(bytes.subarray(12, 28));
    let plaintext: Buffer;
    try {
      plaintext = Buffer.concat([decipher.update(bytes.subarray(28)), decipher.final()]);
    } catch {
      throw invalid();
    }
    await serviceAudit(ctx, tx, use, kmsActions.decrypt, key, {
      keyVersion: version.version,
      encryptionContextKeys: Object.keys(bound).sort(),
    });
    return plaintext.toString('utf8');
  } finally {
    dataKey.fill(0);
  }
}

/**
 * A fresh 32-byte data key wrapped under a tenant AES key, for a module that protects many values in one call
 * (tokenization): the caller encrypts locally, stores `wrapped` beside the data, and must wipe `dataKey` after use.
 * Audited once as `iam:kms:generate-data-key` with `metadata.via`.
 */
export async function kmsDataKeyFor(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  keyRef: string,
  context: EncryptionContext,
  use: KmsServiceUse,
): Promise<{ dataKey: Buffer; wrapped: string; keyId: string; keyVersion: number }> {
  const key = await findKey(tx, tenantId, keyRef);
  serviceKey(key);
  const version = await keyVersion(tx, key, key.currentVersion);
  const bound = encryptionContext(context);
  const dataKey = randomBytes(32);
  const wrapped = encryptWith(ctx, key, version, dataKey, false, bound);
  await serviceAudit(ctx, tx, use, kmsActions['generate-data-key'], key, {
    keyVersion: version.version,
    encryptionContextKeys: Object.keys(bound).sort(),
  });
  return { dataKey, wrapped, keyId: key.id, keyVersion: version.version };
}

/** Unwraps a data key from `kmsDataKeyFor`; the key must still be enabled and the context the same. */
export async function kmsOpenDataKeyFor(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  wrapped: string,
  context: EncryptionContext,
  use: KmsServiceUse,
): Promise<Buffer> {
  const parsed = parseCiphertext(wrapped);
  const key = await findKey(tx, tenantId, parsed.keyId);
  serviceKey(key);
  const version = await keyVersion(tx, key, parsed.version);
  const bound = encryptionContext(context);
  const dataKey = decryptWith(ctx, key, version, parsed, bound);
  if (dataKey.length !== 32)
    throw new IamError('INVALID_CIPHERTEXT', 'The ciphertext is not valid', 400);
  await serviceAudit(ctx, tx, use, kmsActions.decrypt, key, {
    keyVersion: version.version,
    encryptionContextKeys: Object.keys(bound).sort(),
  });
  return dataKey;
}

/**
 * Creates a key for another module's own use, such as a certificate authority's signing key, without a caller
 * permission check (the calling module authorizes its caller). The key is an ordinary KMS key: visible, taggable,
 * and disabled or deleted like any other.
 */
export async function createServiceKey(
  ctx: ServerContext,
  tx: IamStore,
  input: {
    tenantId: string;
    keySpec: KeySpec;
    keyUsage: KeyUsage;
    description: string;
    tags: Record<string, string>;
    createdBy: string;
    /** The owning module: the KMS API then refuses to use the key directly. */
    managedBy: 'pki' | 'protection';
    managedId: string;
  },
): Promise<KmsKey> {
  if (
    (await tx.find<KmsKey>('kmsKeys', { tenantId: input.tenantId })).length >= MAX_KEYS_PER_TENANT
  )
    throw new IamError('LIMIT_EXCEEDED', `A tenant keeps at most ${MAX_KEYS_PER_TENANT} keys`, 409);
  const now = ctx.now();
  const key: KmsKey = {
    id: id(),
    tenantId: input.tenantId,
    description: text(input.description, 'description', 512),
    keySpec: input.keySpec,
    keyUsage: keyUsageFor(input.keySpec, input.keyUsage),
    state: 'enabled',
    currentVersion: 1,
    tags: keyTags(input.tags),
    managedBy: input.managedBy,
    managedId: input.managedId,
    createdAt: now,
    createdBy: input.createdBy,
    updatedAt: now,
  };
  await tx.insert('kmsKeys', key);
  await addKeyVersion(ctx, tx, key, 1, 'create');
  return key;
}

/**
 * Schedules deletion of a key a module created for its own use once the module is done with it (a deleted data
 * protection profile), after the shortest waiting period. Keys the module does not manage are left alone. Returns
 * the deletion date, or undefined when nothing was scheduled.
 */
export async function retireServiceKey(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  keyId: string,
  managedBy: 'pki' | 'protection',
  managedId: string,
): Promise<number | undefined> {
  const key = await tx.get<KmsKey>('kmsKeys', keyId);
  if (
    !key ||
    key.tenantId !== tenantId ||
    key.managedBy !== managedBy ||
    key.managedId !== managedId ||
    key.state === 'pending-deletion'
  )
    return undefined;
  const now = ctx.now();
  const deletionDate = now + 7 * 86_400_000;
  await tx.put<KmsKey>('kmsKeys', {
    ...key,
    state: 'pending-deletion',
    deletionDate,
    updatedAt: now,
  });
  return deletionDate;
}

/**
 * Signs `data` with one pinned version of a signing key for another module (a certificate authority signing
 * certificates and CRLs). The key must be enabled; the use is audited as `iam:kms:sign` with `metadata.via`.
 */
export async function kmsSignFor(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  keyId: string,
  version: number,
  algorithm: string,
  data: Buffer,
  use: KmsServiceUse,
): Promise<Buffer> {
  const key = await findKey(tx, tenantId, keyId);
  assertUsable(key, 'sign');
  if (!keyAlgorithms(key).includes(algorithm))
    throw new IamError('INVALID_INPUT', `This key does not sign with ${algorithm}`);
  const pinned = await keyVersion(tx, key, version);
  const signature = signWith(ctx, pinned, algorithm, data, 'der');
  await serviceAudit(ctx, tx, use, kmsActions.sign, key, { keyVersion: version, algorithm });
  return signature;
}

/** A short fingerprint of public material, for listings (never of secret material). */
export const fingerprint = (pem: string): string =>
  createHash('sha256').update(pem).digest('base64url').slice(0, 16);
