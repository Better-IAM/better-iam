import { randomInt } from 'node:crypto';
import { encryptSecret, openSecret } from '@better-iam/auth';
import {
  IamError,
  type AuthenticatedPrincipal,
  type IamStore,
  type Json,
  type StoredRecord,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import { kmsDecryptFor, kmsEncryptFor } from './kms.js';
import type { ResolvedResource } from './options.js';
import { id } from './utils.js';
import { integer, object, text } from './validation.js';

/**
 * The secrets vault: tenant-scoped secrets with versions, stage labels, rotation, check-out leases for shared
 * privileged credentials, and dynamic secrets minted per caller by an engine. Values are sealed at rest with the
 * deployment secret (AES-256-GCM, bound to tenant, secret, and version) and leave storage only through `reveal`,
 * a check-out, a lease, or the trusted `iam.vault` runtime. Access is decided like every administrative action:
 * `iam:vault:*` on `iam/vault/secrets/{name}`, where the secret's tags and settings are resource attributes.
 */

export const vaultCollections = {
  secrets: 'vaultSecrets',
  versions: 'vaultVersions',
  leases: 'vaultLeases',
  access: 'vaultAccess',
} as const;

/** The resource ID prefix of secrets: `iam/vault/secrets/{name}` in policies. */
export const secretResourcePrefix = 'vault/secrets/';
export const secretResource = (name: string) => `${secretResourcePrefix}${name}`;

/** The audit actor of the scheduler jobs, as elsewhere. */
export const vaultOperator = 'deployment-operator';

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

export type SecretFormat = 'text' | 'json';
export type SecretKind = 'static' | 'dynamic';

export type GeneratorCharset = 'alphanumeric' | 'ascii' | 'hex' | 'base64url' | 'numeric';

/** How generated values look: rotation and `create({ generate })` draw them from the system's CSPRNG. */
export interface PasswordGenerator {
  /** 8-256 characters. */
  length: number;
  charset: GeneratorCharset;
  /** Characters never used (a target system that rejects some symbols, say). */
  exclude?: string;
  /** At least one character of each class the charset keeps (lowercase, uppercase, digits, symbols). */
  eachClass: boolean;
}

export interface SecretRotation {
  /** Rotate automatically this many days after the last rotation (`iam.vault.rotateDue`); absent: on demand only. */
  intervalDays?: number;
  /** Generates the next value; absent with a rotator means the default generator. */
  generator?: PasswordGenerator;
  /** For `json` secrets: the field the generated value replaces (the rest is carried over). */
  field?: string;
  /** The name of a rotator in the `vault.rotators` option that applies new values to the system they unlock. */
  rotator?: string;
  lastRotatedAt?: number;
  nextRotationAt?: number;
  /** The last attempt failed; the pending version stays staged and the next attempt retries it. */
  lastFailure?: { at: number; message: string };
  failures?: number;
  /** When the manual-rotation reminder for the current due date was recorded (no generator and no rotator). */
  dueNotifiedAt?: number;
}

/** Check-out rules for shared privileged credentials (the "password vault" of privileged access management). */
export interface CheckoutPolicy {
  /** The value is handed out only through a check-out (reveal is refused with CHECKOUT_REQUIRED). */
  required: boolean;
  /** One holder at a time; others get SECRET_CHECKED_OUT until it is checked in or expires. */
  exclusive: boolean;
  /** Longest check-out (1 minute to 24 hours). */
  maxDurationMs: number;
  /** Rotate the value when a check-out ends, so a returned password stops working. */
  rotateOnCheckin: boolean;
  /** A check-out must say why (kept with the lease and in the audit log). */
  requireReason: boolean;
}

/** Lease lengths of a dynamic secret. */
export interface LeaseSettings {
  defaultTtlMs: number;
  maxTtlMs: number;
}

export interface VaultSecret extends StoredRecord {
  tenantId: string;
  /** The name: unique per tenant. */
  uniqueKey: string;
  name: string;
  description?: string;
  kind: SecretKind;
  format: SecretFormat;
  tags: Record<string, string>;
  status: 'active' | 'pending-deletion';
  /** When a pending deletion becomes final (`iam.vault.purgeDeleted`). */
  deletionAt?: number;
  deletionRequestedBy?: string;
  /** Stage labels and the version each points at; `current` is what callers get by default. */
  stages: Record<string, number>;
  latestVersion: number;
  maxVersions: number;
  rotation?: SecretRotation;
  checkout?: CheckoutPolicy;
  /** Dynamic secrets: the engine (from the `vault.engines` option) and its configuration. */
  engine?: string;
  engineConfig?: Json;
  lease?: LeaseSettings;
  /**
   * A customer-managed key (a tenant KMS encryption key's id): new versions are encrypted under it instead of the
   * deployment secret, and disabling the key makes every such version unreadable.
   */
  kmsKeyId?: string;
  /**
   * The pending version a rotation staged and has not completed. Only this version is handed to the rotator again on a
   * retry; a `pending` label set by `put` or `setStage` is never applied to the target system.
   */
  rotationPending?: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
  lastAccessedAt?: number;
}

export interface VaultVersion extends StoredRecord {
  tenantId: string;
  uniqueKey: string;
  secretId: string;
  version: number;
  state: 'enabled' | 'disabled' | 'destroyed';
  /** Absent once destroyed: sealed with the deployment secret, or a KMS ciphertext when `kmsKeyId` is set. */
  sealed?: string;
  /** The customer-managed key the value is encrypted under. */
  kmsKeyId?: string;
  source: 'put' | 'generated' | 'rotation';
  createdAt: number;
  createdBy: string;
  disabledAt?: number;
  destroyedAt?: number;
}

export type LeaseState = 'issuing' | 'active' | 'revoking' | 'ended' | 'expired' | 'failed';

export interface VaultLease extends StoredRecord {
  tenantId: string;
  secretId: string;
  name: string;
  kind: 'checkout' | 'dynamic';
  holderId: string;
  sessionId?: string;
  /**
   * A lease an agent took for a person in a delegated session: the agent and the delegation. The lease ends when the
   * delegation does or the agent may no longer act (`iam.vault.expireLeases`).
   */
  agentId?: string;
  delegationId?: string;
  /** The version a check-out handed out. */
  version?: number;
  reason?: string;
  state: LeaseState;
  issuedAt: number;
  expiresAt: number;
  /** Renewals never extend a lease past this. */
  maxExpiresAt: number;
  /** The length the lease was issued for; a renewal without `ttlMs` extends by this much. */
  ttlMs?: number;
  endedAt?: number;
  endedBy?: string;
  /** The engine's revocation handle, sealed. */
  handleSealed?: string;
  revokeAttempts?: number;
  /** When the first revocation attempt failed; revocations are retried with backoff for seven days from then. */
  revokeStartedAt?: number;
  /** The next revocation retry is not before this. */
  retryAt?: number;
  /** The state a revocation in progress (`revoking`) ends the lease in. */
  endState?: 'ended' | 'expired' | 'failed';
  lastError?: string;
}

export type VaultAccessAction =
  | 'reveal'
  | 'checkout'
  | 'checkin'
  | 'lease'
  | 'renew'
  | 'revoke'
  | 'put'
  | 'rotate'
  | 'share';

/** One use of a secret, kept `accessRetentionDays` (default 90) for the per-secret access log. */
export interface VaultAccessRecord extends StoredRecord {
  tenantId: string;
  secretId: string;
  name: string;
  identityId: string;
  action: VaultAccessAction;
  version?: number;
  leaseId?: string;
  at: number;
  expiresAt: number;
  sessionKind?: string;
  agentId?: string;
}

// --- options -------------------------------------------------------------------------------------

export interface RotatorInput {
  tenantId: string;
  name: string;
  /** The pending version being rotated in. */
  version: number;
  value: string;
  /** The parsed value of a `json` secret. */
  fields?: Record<string, Json>;
  /** The value being rotated out, when there is one. */
  previous?: string;
  previousFields?: Record<string, Json>;
  tags: Record<string, string>;
}

/**
 * Applies a new value to the system a secret unlocks (a database user's password, an upstream API key). Throw to
 * fail the rotation: the pending version stays staged and the next attempt calls the rotator with the same value, so
 * it must be idempotent.
 */
export interface VaultRotator {
  rotate(input: RotatorInput): Promise<void>;
}

export interface EngineHolder {
  id: string;
  kind: string;
  name: string;
  email?: string;
}

export interface EngineIssueInput {
  tenantId: string;
  name: string;
  leaseId: string;
  config: Json;
  ttlMs: number;
  holder: EngineHolder;
}

export interface EngineIssued {
  /** The credential, for `text` secrets. */
  value?: string;
  /** The credential's fields (`username`, `password`, ...), for `json` secrets. */
  fields?: Record<string, Json>;
  /** Opaque data `revoke` and `renew` receive back (at most 4096 characters); sealed at rest. */
  handle?: string;
}

export interface EngineLeaseInput {
  tenantId: string;
  name: string;
  leaseId: string;
  config: Json;
  handle?: string;
}

/**
 * Mints short-lived credentials per lease (a database role, a cloud token) and takes them back. Credentials should
 * also expire on their own at the lease's end: a revocation that keeps failing is retried, but cannot be forced.
 */
export interface VaultEngine {
  issue(input: EngineIssueInput): Promise<EngineIssued>;
  revoke?(input: EngineLeaseInput): Promise<void>;
  renew?(input: EngineLeaseInput & { ttlMs: number }): Promise<void>;
}

export interface VaultOptions {
  /** Rotators by name (`rotation.rotator` on a secret). */
  rotators?: Record<string, VaultRotator>;
  /** Dynamic secret engines by name (`engine` on a dynamic secret). */
  engines?: Record<string, VaultEngine>;
  /** Largest secret value in UTF-8 bytes (default 65536, at most 1048576). */
  maxValueBytes?: number;
  /** Secrets per tenant, pending deletions included (default 1000, at most 100000). */
  maxSecretsPerTenant?: number;
  /** How long per-secret access records stay (default 90 days, 1-3650). */
  accessRetentionDays?: number;
  /** How long a rotator or engine call may take (default 30 seconds, 1 second to 5 minutes). */
  callTimeoutMs?: number;
}

export interface VaultSettings {
  rotators: Record<string, VaultRotator>;
  engines: Record<string, VaultEngine>;
  maxValueBytes: number;
  maxSecretsPerTenant: number;
  accessRetentionMs: number;
  callTimeoutMs: number;
}

const pluginName = /^[a-z][a-z0-9-]{0,63}$/;
const settingsCache = new WeakMap<object, VaultSettings>();

/** The validated `vault` option (INVALID_CONFIG on a bad value); cached per options object. */
export function vaultSettings(ctx: Pick<ServerContext, 'options'>): VaultSettings {
  const cached = settingsCache.get(ctx.options);
  if (cached) return cached;
  const raw: unknown = (ctx.options as { vault?: unknown }).vault ?? {};
  if (!raw || typeof raw !== 'object' || Array.isArray(raw))
    throw new IamError('INVALID_CONFIG', 'vault must be an options object');
  const input = raw as VaultOptions;
  const bounded = (value: unknown, fallback: number, min: number, max: number, name: string) => {
    if (value === undefined) return fallback;
    if (typeof value !== 'number' || !Number.isSafeInteger(value) || value < min || value > max)
      throw new IamError('INVALID_CONFIG', `vault.${name} must be an integer from ${min} to ${max}`);
    return value;
  };
  const named = <T>(value: unknown, name: string, method: keyof T & string): Record<string, T> => {
    if (value === undefined) return {};
    if (!value || typeof value !== 'object' || Array.isArray(value))
      throw new IamError('INVALID_CONFIG', `vault.${name} must be an object`);
    for (const [key, item] of Object.entries(value)) {
      if (!pluginName.test(key))
        throw new IamError('INVALID_CONFIG', `vault.${name} keys must be lowercase identifiers`);
      if (!item || typeof (item as Record<string, unknown>)[method] !== 'function')
        throw new IamError('INVALID_CONFIG', `vault.${name}.${key} must have a ${method} function`);
    }
    return value as Record<string, T>;
  };
  const settings: VaultSettings = {
    rotators: named<VaultRotator>(input.rotators, 'rotators', 'rotate'),
    engines: named<VaultEngine>(input.engines, 'engines', 'issue'),
    maxValueBytes: bounded(input.maxValueBytes, 65536, 16, 1048576, 'maxValueBytes'),
    maxSecretsPerTenant: bounded(
      input.maxSecretsPerTenant,
      1000,
      1,
      100000,
      'maxSecretsPerTenant',
    ),
    accessRetentionMs: bounded(input.accessRetentionDays, 90, 1, 3650, 'accessRetentionDays') * DAY,
    callTimeoutMs: bounded(input.callTimeoutMs, 30_000, 1000, 300_000, 'callTimeoutMs'),
  };
  settingsCache.set(ctx.options, settings);
  return settings;
}

// --- validation ----------------------------------------------------------------------------------

const segment = /^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/;

/** A secret name: 1-16 `/`-separated segments of letters, digits and `_.-` (not starting with `.` or `-`). */
export function secretName(value: unknown): string {
  const name = text(value, 'name', 256);
  const parts = name.split('/');
  if (parts.length > 16 || !parts.every((part) => segment.test(part)))
    throw new IamError(
      'INVALID_INPUT',
      'Secret names are 1-16 segments of letters, digits and _.- (not starting with . or -) separated by /',
    );
  return name;
}

/** A listing prefix: a name prefix, optionally ending in `/`; the empty string lists everything. */
export function secretPrefix(value: unknown): string {
  if (value === undefined || value === '') return '';
  const prefix = text(value, 'prefix', 256);
  const trimmed = prefix.endsWith('/') ? prefix.slice(0, -1) : prefix;
  if (trimmed) secretName(trimmed);
  return prefix;
}

const tagKey = /^[a-zA-Z][a-zA-Z0-9_-]{0,63}$/;

/** Up to 20 tags; keys are identifiers, values 1-256 printable characters. */
export function secretTags(value: unknown): Record<string, string> {
  if (value === undefined) return {};
  const input = object(value);
  const entries = Object.entries(input);
  if (entries.length > 20) throw new IamError('INVALID_INPUT', 'A secret has at most 20 tags');
  const tags: Record<string, string> = {};
  for (const [key, item] of entries.sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (!tagKey.test(key)) throw new IamError('INVALID_INPUT', `Invalid tag name ${key}`);
    tags[key] = text(item, `tag ${key}`, 256);
  }
  return tags;
}

const stageLabel = /^[a-z][a-z0-9-]{0,31}$/;
/** Stage labels the vault moves itself. */
export const systemStages = new Set(['current', 'previous', 'pending']);

export function stageName(value: unknown): string {
  const label = text(value, 'stage', 32);
  if (!stageLabel.test(label))
    throw new IamError(
      'INVALID_INPUT',
      'Stage labels are 1-32 lowercase letters, digits or hyphens, starting with a letter',
    );
  return label;
}

export function secretFormat(value: unknown): SecretFormat {
  if (value === undefined) return 'text';
  if (value !== 'text' && value !== 'json')
    throw new IamError('INVALID_INPUT', 'format must be text or json');
  return value;
}

/**
 * The stored form of a value: the text itself, or for `json` secrets the object serialized (callers may pass it as a
 * JSON string or as `fields`). Refuses empty values and values over the size limit.
 */
export function secretValue(
  settings: VaultSettings,
  format: SecretFormat,
  input: { value?: unknown; fields?: unknown },
): string {
  let value: string;
  if (input.fields !== undefined) {
    if (format !== 'json')
      throw new IamError('INVALID_INPUT', 'fields are for json secrets; pass value instead');
    value = JSON.stringify(object(input.fields));
  } else {
    if (typeof input.value !== 'string' || input.value.length === 0)
      throw new IamError('INVALID_INPUT', 'value must be a nonempty string');
    value = input.value;
  }
  if (Buffer.byteLength(value, 'utf8') > settings.maxValueBytes)
    throw new IamError(
      'INVALID_INPUT',
      `Secret values are at most ${settings.maxValueBytes} bytes`,
    );
  if (format === 'json') parseFields(value);
  return value;
}

const reservedFieldNames = new Set(['__proto__', 'constructor', 'prototype']);

/** A json secret's field name: 1-64 letters, digits and `_.-`, never one that names an object's prototype. */
export function fieldName(value: unknown, name: string): string {
  const field = text(value, name, 64);
  if (!/^[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}$/.test(field) || reservedFieldNames.has(field))
    throw new IamError('INVALID_INPUT', `${name} must be a field name of letters, digits and _.-`);
  return field;
}

/** One field of a json secret's parsed value, own properties only. */
export function ownField(fields: Record<string, Json> | undefined, field: string): Json | undefined {
  return fields && Object.hasOwn(fields, field) ? fields[field] : undefined;
}

/** A json secret's fields; INVALID_INPUT when the value is not a JSON object. */
export function parseFields(value: string): Record<string, Json> {
  let parsed: unknown;
  try {
    parsed = JSON.parse(value);
  } catch {
    throw new IamError('INVALID_INPUT', 'json secrets hold a JSON object');
  }
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
    throw new IamError('INVALID_INPUT', 'json secrets hold a JSON object');
  return parsed as Record<string, Json>;
}

const charsets: Record<GeneratorCharset, string> = {
  alphanumeric: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789',
  // Printable ASCII without space, quotes, backslash and backtick, which break shells and connection strings.
  ascii:
    'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&()*+,-./:;<=>?@[]^_{|}~',
  hex: '0123456789abcdef',
  base64url: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_',
  numeric: '0123456789',
};
const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/];

export const defaultGenerator: PasswordGenerator = {
  length: 32,
  charset: 'alphanumeric',
  eachClass: true,
};

export function passwordGenerator(value: unknown): PasswordGenerator {
  if (value === undefined || value === true) return { ...defaultGenerator };
  const input = object(value);
  const generator: PasswordGenerator = {
    length: input.length === undefined ? 32 : integer(input.length, 'generator.length', 8, 256),
    charset: (input.charset ?? 'alphanumeric') as GeneratorCharset,
    eachClass: input.eachClass === undefined ? true : input.eachClass === true,
  };
  if (!Object.hasOwn(charsets, generator.charset))
    throw new IamError(
      'INVALID_INPUT',
      'generator.charset must be alphanumeric, ascii, hex, base64url or numeric',
    );
  if (input.eachClass !== undefined && typeof input.eachClass !== 'boolean')
    throw new IamError('INVALID_INPUT', 'generator.eachClass must be a boolean');
  if (input.exclude !== undefined && input.exclude !== '') {
    generator.exclude = text(input.exclude, 'generator.exclude', 64);
  }
  if (pool(generator).length < 10)
    throw new IamError('INVALID_INPUT', 'The generator must keep at least 10 characters');
  return generator;
}

function pool(generator: PasswordGenerator): string {
  const excluded = new Set(generator.exclude ?? '');
  return [...charsets[generator.charset]].filter((char) => !excluded.has(char)).join('');
}

/** A random value from the generator: uniform draws, with one character of each kept class placed at random. */
export function generateValue(generator: PasswordGenerator): string {
  const characters = pool(generator);
  const draw = (from: string) => from[randomInt(from.length)]!;
  const required = generator.eachClass
    ? classes
        .map((pattern) => [...characters].filter((char) => pattern.test(char)).join(''))
        .filter((set) => set.length > 0)
    : [];
  const result = required.map(draw);
  while (result.length < generator.length) result.push(draw(characters));
  // Fisher-Yates, so the required characters land anywhere.
  for (let index = result.length - 1; index > 0; index--) {
    const other = randomInt(index + 1);
    [result[index], result[other]] = [result[other]!, result[index]!];
  }
  return result.join('');
}

export function rotationSettings(
  settings: VaultSettings,
  format: SecretFormat,
  value: unknown,
  previous?: SecretRotation,
): SecretRotation | undefined {
  if (value === undefined) return previous;
  if (value === null) return undefined;
  const input = object(value);
  const rotation: SecretRotation = {};
  if (input.intervalDays !== undefined && input.intervalDays !== null)
    rotation.intervalDays = integer(input.intervalDays, 'rotation.intervalDays', 1, 365);
  if (input.rotator !== undefined && input.rotator !== null) {
    const rotator = text(input.rotator, 'rotation.rotator', 64);
    if (!Object.hasOwn(settings.rotators, rotator))
      throw new IamError('INVALID_INPUT', `Unknown rotator ${rotator}`);
    rotation.rotator = rotator;
  }
  if (input.generator !== undefined && input.generator !== null && input.generator !== false)
    rotation.generator = passwordGenerator(input.generator);
  if (input.field !== undefined && input.field !== null) {
    if (format !== 'json')
      throw new IamError('INVALID_INPUT', 'rotation.field is for json secrets');
    rotation.field = fieldName(input.field, 'rotation.field');
  }
  if (format === 'json' && (rotation.generator || rotation.rotator) && !rotation.field)
    throw new IamError(
      'INVALID_INPUT',
      'json secrets name the field rotation replaces (rotation.field)',
    );
  // History carries over; a new interval counts from the last rotation.
  if (previous?.lastRotatedAt !== undefined) rotation.lastRotatedAt = previous.lastRotatedAt;
  return rotation;
}

export function checkoutPolicy(value: unknown, previous?: CheckoutPolicy): CheckoutPolicy | undefined {
  if (value === undefined) return previous;
  if (value === null) return undefined;
  const input = object(value);
  const flag = (key: string, fallback: boolean) => {
    const item = input[key];
    if (item === undefined) return fallback;
    if (typeof item !== 'boolean')
      throw new IamError('INVALID_INPUT', `checkout.${key} must be a boolean`);
    return item;
  };
  return {
    required: flag('required', true),
    exclusive: flag('exclusive', false),
    maxDurationMs:
      input.maxDurationMs === undefined
        ? HOUR
        : integer(input.maxDurationMs, 'checkout.maxDurationMs', MINUTE, DAY),
    rotateOnCheckin: flag('rotateOnCheckin', false),
    requireReason: flag('requireReason', false),
  };
}

export function leaseSettings(value: unknown, previous?: LeaseSettings): LeaseSettings {
  if (value === undefined && previous) return previous;
  const input = value === undefined ? {} : object(value);
  const defaultTtlMs =
    input.defaultTtlMs === undefined
      ? HOUR
      : integer(input.defaultTtlMs, 'lease.defaultTtlMs', MINUTE, 30 * DAY);
  const maxTtlMs =
    input.maxTtlMs === undefined
      ? Math.max(DAY, defaultTtlMs)
      : integer(input.maxTtlMs, 'lease.maxTtlMs', MINUTE, 30 * DAY);
  if (defaultTtlMs > maxTtlMs)
    throw new IamError('INVALID_INPUT', 'lease.defaultTtlMs must not exceed lease.maxTtlMs');
  return { defaultTtlMs, maxTtlMs };
}

/** Engine configuration: any JSON value up to 8 KiB. */
export function engineConfig(value: unknown): Json {
  if (value === undefined) return {};
  let serialized: string;
  try {
    serialized = JSON.stringify(value);
  } catch {
    throw new IamError('INVALID_INPUT', 'engineConfig must be JSON');
  }
  if (serialized === undefined || serialized.length > 8192)
    throw new IamError('INVALID_INPUT', 'engineConfig must be JSON of at most 8 KiB');
  return JSON.parse(serialized) as Json;
}

// --- sealing -------------------------------------------------------------------------------------

/** The encryption context of a version: a sealed value opens only as that version of that secret. */
export const versionContext = (record: { tenantId: string; secretId: string; version: number }) =>
  `vault:${record.tenantId}:${record.secretId}:${record.version}`;
export const leaseHandleContext = (leaseId: string) => `vault-lease:${leaseId}`;

export function sealValue(ctx: ServerContext, value: string, context: string): string {
  return encryptSecret(value, ctx.options.secret, context);
}

/** Opens a sealed value with the current secret or a previous one (`rotateSecrets` re-seals). */
export function openValue(ctx: ServerContext, sealed: string, context: string): string {
  const opened = openSecret(
    sealed,
    [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])],
    context,
  );
  if (!opened)
    throw new IamError('INVALID_SEALED_VALUE', 'The secret value cannot be opened', 500);
  return opened.value;
}

// --- records -------------------------------------------------------------------------------------

export async function findSecret(
  tx: IamStore,
  tenantId: string,
  name: string,
): Promise<VaultSecret | undefined> {
  return (
    await tx.find<VaultSecret>(vaultCollections.secrets, { tenantId, uniqueKey: name })
  )[0];
}

export async function secretVersions(tx: IamStore, secret: VaultSecret): Promise<VaultVersion[]> {
  return (
    await tx.find<VaultVersion>(vaultCollections.versions, {
      tenantId: secret.tenantId,
      secretId: secret.id,
    })
  ).sort((a, b) => b.version - a.version);
}

export async function versionOf(
  tx: IamStore,
  secret: VaultSecret,
  version: number,
): Promise<VaultVersion | undefined> {
  return (
    await tx.find<VaultVersion>(vaultCollections.versions, {
      tenantId: secret.tenantId,
      uniqueKey: `${secret.id}:${version}`,
    })
  )[0];
}

/** Who a value is encrypted or opened for: recorded on the customer-managed key's `iam:kms:*` audit events. */
export type ValueUse = AuthenticatedPrincipal | undefined;

/** Encrypts a version's value: under the secret's customer-managed key when it has one, else the deployment secret. */
export async function encryptVersion(
  ctx: ServerContext,
  tx: IamStore,
  secret: Pick<VaultSecret, 'kmsKeyId'>,
  record: VaultVersion,
  value: string,
  use: ValueUse,
): Promise<VaultVersion> {
  const { sealed: _sealed, kmsKeyId: _key, ...rest } = record;
  if (secret.kmsKeyId === undefined)
    return { ...rest, sealed: sealValue(ctx, value, versionContext(record)) };
  const encrypted = await kmsEncryptFor(
    ctx,
    tx,
    record.tenantId,
    secret.kmsKeyId,
    value,
    versionContext(record),
    { via: 'vault', ...(use ? { principal: use } : {}) },
  );
  return { ...rest, sealed: encrypted.ciphertext, kmsKeyId: encrypted.keyId };
}

/** Adds a version (encrypted) and returns it; the caller moves stages. */
export async function addVersion(
  ctx: ServerContext,
  tx: IamStore,
  secret: VaultSecret,
  value: string,
  source: VaultVersion['source'],
  actorId: string,
  use?: ValueUse,
): Promise<{ secret: VaultSecret; version: VaultVersion }> {
  const number = secret.latestVersion + 1;
  const record = await encryptVersion(
    ctx,
    tx,
    secret,
    {
      id: id(),
      tenantId: secret.tenantId,
      uniqueKey: `${secret.id}:${number}`,
      secretId: secret.id,
      version: number,
      state: 'enabled',
      source,
      createdAt: ctx.now(),
      createdBy: actorId,
    },
    value,
    use,
  );
  await tx.insert(vaultCollections.versions, record);
  return { secret: { ...secret, latestVersion: number }, version: record };
}

/**
 * Makes a version current: the old current becomes `previous`, a `pending` label on it is dropped, and versions past
 * `maxVersions` that no stage names are deleted. Returns the stored secret.
 */
export async function promoteVersion(
  ctx: ServerContext,
  tx: IamStore,
  secret: VaultSecret,
  version: number,
  actorId: string,
  rotated = false,
): Promise<VaultSecret> {
  const stages = { ...secret.stages };
  // A newer value restarts the rotation clock; rolling back to an older version does not.
  const fresher = stages.current === undefined || version > stages.current;
  if (stages.current !== version) {
    if (stages.current !== undefined) stages.previous = stages.current;
    stages.current = version;
  }
  if (stages.pending === version) delete stages.pending;
  if (stages.previous === version) delete stages.previous;
  const now = ctx.now();
  const { rotationPending, ...rest } = secret;
  const next: VaultSecret = {
    ...rest,
    // A rotation's staged version stays marked until it becomes current (or another version does).
    ...(rotationPending !== undefined && rotationPending !== version && stages.pending === rotationPending
      ? { rotationPending }
      : {}),
    stages,
    updatedAt: now,
    updatedBy: actorId,
  };
  if (rotated || (next.rotation && fresher))
    next.rotation = rotationAfter(next.rotation, now, rotated);
  const stored = await tx.put<VaultSecret>(vaultCollections.secrets, next);
  await pruneVersions(tx, stored);
  return stored;
}

/** Rotation bookkeeping after a new current version: the next due date counts from now. */
function rotationAfter(
  rotation: SecretRotation | undefined,
  now: number,
  rotated: boolean,
): SecretRotation | undefined {
  if (!rotation) return rotated ? { lastRotatedAt: now } : undefined;
  const {
    lastFailure: _failure,
    failures: _failures,
    dueNotifiedAt: _notified,
    nextRotationAt: _next,
    ...rest
  } = rotation;
  const next: SecretRotation = { ...rest, lastRotatedAt: now };
  if (next.intervalDays !== undefined) next.nextRotationAt = now + next.intervalDays * DAY;
  return next;
}

/** Recomputes the next due date after settings change (the interval counts from the last rotation or creation). */
export function scheduleRotation(
  rotation: SecretRotation | undefined,
  createdAt: number,
  now: number,
): SecretRotation | undefined {
  if (!rotation) return undefined;
  const { nextRotationAt: _next, ...rest } = rotation;
  if (rest.intervalDays === undefined) return rest;
  const from = rest.lastRotatedAt ?? createdAt;
  return { ...rest, nextRotationAt: Math.max(from + rest.intervalDays * DAY, now) };
}

export async function pruneVersions(tx: IamStore, secret: VaultSecret): Promise<number> {
  const staged = new Set(Object.values(secret.stages));
  const versions = await secretVersions(tx, secret);
  let removed = 0;
  for (const [index, version] of versions.entries())
    if (index >= secret.maxVersions && !staged.has(version.version)) {
      await tx.delete(vaultCollections.versions, version.id);
      removed++;
    }
  return removed;
}

/**
 * The value of one version; refuses disabled and destroyed versions. A version under a customer-managed key opens only
 * while that key is enabled (KEY_STATE_INVALID otherwise); the key's audit log records the use.
 */
export async function openVersion(
  ctx: ServerContext,
  tx: IamStore,
  version: VaultVersion,
  use?: ValueUse,
): Promise<string> {
  if (version.state === 'disabled')
    throw new IamError('VERSION_DISABLED', 'This version is disabled', 409);
  return openStored(ctx, tx, version, use);
}

/** A version's value whatever its state (re-encryption under another key); destroyed versions have none. */
export async function openStored(
  ctx: ServerContext,
  tx: IamStore,
  version: VaultVersion,
  use?: ValueUse,
): Promise<string> {
  if (version.state === 'destroyed' || version.sealed === undefined)
    throw new IamError('VERSION_DESTROYED', 'This version was destroyed', 410);
  if (version.kmsKeyId === undefined) return openValue(ctx, version.sealed, versionContext(version));
  return kmsDecryptFor(
    ctx,
    tx,
    version.tenantId,
    { ciphertext: version.sealed, keyId: version.kmsKeyId },
    versionContext(version),
    { via: 'vault', ...(use ? { principal: use } : {}) },
  );
}

/** Resolves `version` / `stage` (default `current`) to a version record of the secret. */
export async function selectVersion(
  tx: IamStore,
  secret: VaultSecret,
  input: { version?: unknown; stage?: unknown },
): Promise<VaultVersion> {
  if (input.version !== undefined && input.stage !== undefined)
    throw new IamError('INVALID_INPUT', 'Pass version or stage, not both');
  const number =
    input.version !== undefined
      ? integer(input.version, 'version', 1, Number.MAX_SAFE_INTEGER)
      : secret.stages[input.stage === undefined ? 'current' : stageName(input.stage)];
  if (number === undefined)
    throw new IamError(
      'NOT_FOUND',
      input.stage === undefined
        ? 'This secret has no current version'
        : 'No version has this stage',
      404,
    );
  const version = await versionOf(tx, secret, number);
  if (!version) throw new IamError('NOT_FOUND', 'Version not found', 404);
  return version;
}

export async function recordAccess(
  ctx: ServerContext,
  tx: IamStore,
  secret: VaultSecret,
  entry: {
    identityId: string;
    action: VaultAccessAction;
    version?: number;
    leaseId?: string;
    sessionKind?: string;
    agentId?: string;
  },
): Promise<void> {
  const at = ctx.now();
  await tx.insert<VaultAccessRecord>(vaultCollections.access, {
    id: id(),
    tenantId: secret.tenantId,
    secretId: secret.id,
    name: secret.name,
    identityId: entry.identityId,
    action: entry.action,
    ...(entry.version !== undefined ? { version: entry.version } : {}),
    ...(entry.leaseId !== undefined ? { leaseId: entry.leaseId } : {}),
    ...(entry.sessionKind !== undefined ? { sessionKind: entry.sessionKind } : {}),
    ...(entry.agentId !== undefined ? { agentId: entry.agentId } : {}),
    at,
    expiresAt: at + vaultSettings(ctx).accessRetentionMs,
  });
  if (entry.action === 'reveal' || entry.action === 'checkout' || entry.action === 'lease') {
    const current = await tx.get<VaultSecret>(vaultCollections.secrets, secret.id);
    if (current) await tx.put(vaultCollections.secrets, { ...current, lastAccessedAt: at });
  }
}

/** Active check-outs and leases of a secret, in issue order. */
export async function liveLeases(
  ctx: ServerContext,
  tx: IamStore,
  secret: VaultSecret,
): Promise<VaultLease[]> {
  const now = ctx.now();
  return (
    await tx.find<VaultLease>(vaultCollections.leases, {
      tenantId: secret.tenantId,
      secretId: secret.id,
      state: 'active',
    })
  )
    .filter((lease) => lease.expiresAt > now)
    .sort((a, b) => a.issuedAt - b.issuedAt);
}

/** The policy attributes of a secret: `resource.name`, `resource.tag.{key}`, and its settings. */
export function secretAttributes(secret: VaultSecret): Record<string, Json> {
  const attributes: Record<string, Json> = {
    name: secret.name,
    kind: secret.kind,
    format: secret.format,
    status: secret.status,
    createdBy: secret.createdBy,
    checkoutRequired: secret.checkout?.required === true,
    rotationEnabled: secret.rotation?.intervalDays !== undefined,
    customerManagedKey: secret.kmsKeyId !== undefined,
  };
  if (secret.engine !== undefined) attributes.engine = secret.engine;
  for (const [key, value] of Object.entries(secret.tags)) attributes[`tag.${key}`] = value;
  return attributes;
}

/**
 * The decision engine's resolver for `iam/vault/secrets/{name}`: an existing secret carries its attributes; a name
 * nobody uses yet resolves without any (conditions on them then fail closed), never falling through to a managed
 * resource that could plant attributes. Undefined for other resources.
 */
export async function resolveSecretResource(
  tx: IamStore,
  reference: { tenantId: string; type: string; id: string },
): Promise<ResolvedResource | undefined> {
  if (reference.type !== 'iam' || !reference.id.startsWith(secretResourcePrefix)) return undefined;
  const name = reference.id.slice(secretResourcePrefix.length);
  const secret =
    name && name.length <= 256 ? await findSecret(tx, reference.tenantId, name) : undefined;
  return secret ? { ...reference, attributes: secretAttributes(secret) } : { ...reference };
}

// --- external calls ------------------------------------------------------------------------------

/** Runs a rotator or engine call with the configured timeout. */
export async function withTimeout<T>(
  ctx: ServerContext,
  what: string,
  call: () => Promise<T>,
): Promise<T> {
  const timeout = vaultSettings(ctx).callTimeoutMs;
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      Promise.resolve().then(call),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`${what} did not finish within ${timeout} ms`)),
          timeout,
        );
      }),
    ]);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

/**
 * Every form a secret value might take inside an error message: the value itself and, for a JSON object, each string
 * (and number) field, each with its JSON-escaped, URL-encoded and base64 spellings. Longest first, so a field inside a
 * longer match is not left half-redacted.
 */
function sensitiveForms(values: (string | undefined)[]): string[] {
  const plain = new Set<string>();
  for (const value of values) {
    if (!value) continue;
    plain.add(value);
    if (value.startsWith('{'))
      try {
        const parsed = JSON.parse(value) as unknown;
        if (parsed && typeof parsed === 'object')
          for (const field of Object.values(parsed as Record<string, unknown>))
            if (typeof field === 'string' || typeof field === 'number') plain.add(String(field));
      } catch {
        /* Not JSON: the value alone. */
      }
  }
  const forms = new Set<string>();
  for (const value of plain) {
    if (value.length < 4) continue;
    forms.add(value);
    forms.add(JSON.stringify(value).slice(1, -1));
    forms.add(encodeURIComponent(value));
    forms.add(Buffer.from(value, 'utf8').toString('base64').replace(/=+$/, ''));
  }
  return [...forms].filter((form) => form.length >= 4).sort((a, b) => b.length - a.length);
}

/** An error message safe to store: at most 512 characters, with any secret value (or field of one) it quotes redacted. */
export function redactedMessage(error: unknown, values: (string | undefined)[]): string {
  let message = error instanceof Error ? error.message : String(error);
  for (const form of sensitiveForms(values)) message = message.split(form).join('[redacted]');
  return message.replace(/[\u0000-\u001f]/g, ' ').slice(0, 512) || 'Unknown error';
}

export const vaultTime = { MINUTE, HOUR, DAY };
