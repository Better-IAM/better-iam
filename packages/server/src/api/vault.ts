import {
  IamError,
  findOrdered,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { agentStanding } from '../agents.js';
import type { ServerContext } from '../context.js';
import { impersonatingActor } from '../decisions.js';
import { delegationAncestors, delegationLive, useConfirmation, type Delegation } from '../delegations.js';
import { aliasNames, assertUsable, findKey, keyAttributes } from '../kms.js';
import { OperationDenied } from '../operations.js';
import { id } from '../utils.js';
import { integer, text } from '../validation.js';
import {
  addVersion,
  checkoutPolicy,
  defaultGenerator,
  encryptVersion,
  engineConfig,
  findSecret,
  generateValue,
  leaseHandleContext,
  leaseSettings,
  liveLeases,
  openStored,
  openValue,
  openVersion,
  ownField,
  parseFields,
  passwordGenerator,
  promoteVersion,
  pruneVersions,
  recordAccess,
  redactedMessage,
  rotationSettings,
  scheduleRotation,
  sealValue,
  secretAttributes,
  secretFormat,
  secretName,
  secretPrefix,
  secretResource,
  secretTags,
  secretValue,
  secretVersions,
  selectVersion,
  stageName,
  systemStages,
  vaultCollections,
  vaultOperator,
  vaultSettings,
  vaultTime,
  versionOf,
  withTimeout,
  type CheckoutPolicy,
  type EngineIssued,
  type LeaseSettings,
  type PasswordGenerator,
  type SecretFormat,
  type SecretKind,
  type ValueUse,
  type VaultAccessAction,
  type VaultAccessRecord,
  type VaultLease,
  type VaultSecret,
  type VaultVersion,
} from '../vault.js';

const { MINUTE, DAY } = vaultTime;

/** Every action decided on `iam/vault/secrets/{name}`. */
const secretActions = [
  'iam:vault:read',
  'iam:vault:reveal',
  'iam:vault:write',
  'iam:vault:rotate',
  'iam:vault:lease',
  'iam:vault:manage',
] as const;

// --- views ---------------------------------------------------------------------------------------

/** A secret's metadata, as `iam:vault:read` shows it. Never carries a value. */
export interface SecretView {
  name: string;
  description?: string;
  kind: SecretKind;
  format: SecretFormat;
  tags: Record<string, string>;
  status: VaultSecret['status'];
  /** When a pending deletion becomes final. */
  deletionAt?: number;
  /** Stage labels and the version each points at. */
  stages: Record<string, number>;
  latestVersion: number;
  maxVersions: number;
  rotation?: {
    intervalDays?: number;
    generator?: PasswordGenerator;
    field?: string;
    rotator?: string;
    lastRotatedAt?: number;
    nextRotationAt?: number;
    /** A scheduled rotation is past due. */
    due: boolean;
    lastFailure?: { at: number; message: string };
    failures?: number;
  };
  checkout?: CheckoutPolicy;
  engine?: string;
  engineConfig?: Json;
  lease?: LeaseSettings;
  /** The customer-managed key the values are encrypted under. */
  kmsKeyId?: string;
  /** Live check-outs (who holds the value, until when). */
  checkedOut: { leaseId: string; holderId: string; expiresAt: number }[];
  /** Live dynamic leases. */
  activeLeases: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
  lastAccessedAt?: number;
}

export interface SecretVersionView {
  version: number;
  state: VaultVersion['state'];
  /** Stage labels pointing at this version. */
  stages: string[];
  source: VaultVersion['source'];
  createdAt: number;
  createdBy: string;
  disabledAt?: number;
  destroyedAt?: number;
}

/** A revealed value: `value` always, and the parsed `fields` of a `json` secret. */
export interface RevealedSecret {
  name: string;
  version: number;
  stages: string[];
  format: SecretFormat;
  value: string;
  fields?: Record<string, Json>;
  createdAt: number;
}

export interface CheckoutResult extends RevealedSecret {
  leaseId: string;
  expiresAt: number;
  maxExpiresAt: number;
}

export interface DynamicLeaseResult {
  leaseId: string;
  name: string;
  format: SecretFormat;
  value: string;
  fields?: Record<string, Json>;
  issuedAt: number;
  expiresAt: number;
  maxExpiresAt: number;
  renewable: boolean;
}

export interface SecretLeaseView {
  id: string;
  name: string;
  kind: VaultLease['kind'];
  holderId: string;
  holderName?: string;
  version?: number;
  reason?: string;
  state: VaultLease['state'];
  issuedAt: number;
  expiresAt: number;
  maxExpiresAt: number;
  endedAt?: number;
  endedBy?: string;
  lastError?: string;
}

export interface SecretAccessView {
  at: number;
  identityId: string;
  identityName?: string;
  action: VaultAccessAction;
  version?: number;
  leaseId?: string;
  sessionKind?: string;
  agentId?: string;
}

export interface RotationResult {
  name: string;
  version: number;
  rotatedAt: number;
  rotator?: string;
  stages: Record<string, number>;
}

export interface VaultJobResult {
  rotated: { tenantId: string; name: string; version: number }[];
  failed: { tenantId: string; name: string; message: string }[];
  /** Scheduled rotations with neither a generator nor a rotator: recorded as `vault:rotation-due` once per due date. */
  reminded: { tenantId: string; name: string }[];
}

export interface LeaseJobResult {
  /** Check-outs and dynamic leases ended because they expired or their holder is no longer active. */
  expired: number;
  /** Revocations that failed and will be retried. */
  retrying: number;
  /** Revocations given up after repeated failures. */
  abandoned: number;
  /** Ended leases past the history retention, deleted. */
  pruned: number;
  rotated: number;
}

// --- helpers -------------------------------------------------------------------------------------

type Recorder = (
  tx: IamStore,
  action: string,
  outcome: 'allow' | 'deny',
  metadata: Record<string, Json>,
) => Promise<void>;

/** A state the rotation machinery carries from the staging transaction to the promotion one. */
interface StagedRotation {
  tenantId: string;
  secretId: string;
  name: string;
  version: number;
  value: string;
  previous?: string;
  format: SecretFormat;
  tags: Record<string, string>;
  rotator?: string;
}

function view(secret: VaultSecret, leases: VaultLease[], now: number): SecretView {
  const rotation = secret.rotation;
  return {
    name: secret.name,
    ...(secret.description !== undefined ? { description: secret.description } : {}),
    kind: secret.kind,
    format: secret.format,
    tags: secret.tags,
    status: secret.status,
    ...(secret.deletionAt !== undefined ? { deletionAt: secret.deletionAt } : {}),
    stages: secret.stages,
    latestVersion: secret.latestVersion,
    maxVersions: secret.maxVersions,
    ...(rotation
      ? {
          rotation: {
            ...(rotation.intervalDays !== undefined ? { intervalDays: rotation.intervalDays } : {}),
            ...(rotation.generator ? { generator: rotation.generator } : {}),
            ...(rotation.field !== undefined ? { field: rotation.field } : {}),
            ...(rotation.rotator !== undefined ? { rotator: rotation.rotator } : {}),
            ...(rotation.lastRotatedAt !== undefined
              ? { lastRotatedAt: rotation.lastRotatedAt }
              : {}),
            ...(rotation.nextRotationAt !== undefined
              ? { nextRotationAt: rotation.nextRotationAt }
              : {}),
            due: rotation.nextRotationAt !== undefined && rotation.nextRotationAt <= now,
            ...(rotation.lastFailure ? { lastFailure: rotation.lastFailure } : {}),
            ...(rotation.failures ? { failures: rotation.failures } : {}),
          },
        }
      : {}),
    ...(secret.checkout ? { checkout: secret.checkout } : {}),
    ...(secret.engine !== undefined ? { engine: secret.engine } : {}),
    ...(secret.engineConfig !== undefined ? { engineConfig: secret.engineConfig } : {}),
    ...(secret.lease ? { lease: secret.lease } : {}),
    ...(secret.kmsKeyId !== undefined ? { kmsKeyId: secret.kmsKeyId } : {}),
    checkedOut: leases
      .filter((lease) => lease.kind === 'checkout')
      .map((lease) => ({ leaseId: lease.id, holderId: lease.holderId, expiresAt: lease.expiresAt })),
    activeLeases: leases.filter((lease) => lease.kind === 'dynamic').length,
    createdAt: secret.createdAt,
    createdBy: secret.createdBy,
    updatedAt: secret.updatedAt,
    updatedBy: secret.updatedBy,
    ...(secret.lastAccessedAt !== undefined ? { lastAccessedAt: secret.lastAccessedAt } : {}),
  };
}

function stagesOf(secret: VaultSecret, version: number): string[] {
  return Object.entries(secret.stages)
    .filter(([, value]) => value === version)
    .map(([label]) => label)
    .sort();
}

function versionView(secret: VaultSecret, version: VaultVersion): SecretVersionView {
  return {
    version: version.version,
    state: version.state,
    stages: stagesOf(secret, version.version),
    source: version.source,
    createdAt: version.createdAt,
    createdBy: version.createdBy,
    ...(version.disabledAt !== undefined ? { disabledAt: version.disabledAt } : {}),
    ...(version.destroyedAt !== undefined ? { destroyedAt: version.destroyedAt } : {}),
  };
}

/** A revealed secret split into what plugin hooks may see and the values they may not. */
function splitValues<T extends { value: string; fields?: Record<string, Json> }>(shown: T) {
  const { value, fields, ...answer } = shown;
  return { answer, values: { value, ...(fields !== undefined ? { fields } : {}) } };
}

/** The agent and delegation behind a delegated session, recorded on the leases it takes. */
function leaseActor(principal: AuthenticatedPrincipal): Pick<VaultLease, 'agentId' | 'delegationId'> {
  const { agentId, delegationId } = principal.session;
  return {
    ...(typeof agentId === 'string' ? { agentId } : {}),
    ...(typeof delegationId === 'string' ? { delegationId } : {}),
  };
}

function revealed(secret: VaultSecret, version: VaultVersion, value: string): RevealedSecret {
  return {
    name: secret.name,
    version: version.version,
    stages: stagesOf(secret, version.version),
    format: secret.format,
    value,
    ...(secret.format === 'json' ? { fields: parseFields(value) } : {}),
    createdAt: version.createdAt,
  };
}

function leaseView(lease: VaultLease, holderName?: string): SecretLeaseView {
  return {
    id: lease.id,
    name: lease.name,
    kind: lease.kind,
    holderId: lease.holderId,
    ...(holderName !== undefined ? { holderName } : {}),
    ...(lease.version !== undefined ? { version: lease.version } : {}),
    ...(lease.reason !== undefined ? { reason: lease.reason } : {}),
    state: lease.state,
    issuedAt: lease.issuedAt,
    expiresAt: lease.expiresAt,
    maxExpiresAt: lease.maxExpiresAt,
    ...(lease.endedAt !== undefined ? { endedAt: lease.endedAt } : {}),
    ...(lease.endedBy !== undefined ? { endedBy: lease.endedBy } : {}),
    ...(lease.lastError !== undefined ? { lastError: lease.lastError } : {}),
  };
}

function writable(realm: Tenant): void {
  if (realm.status === 'deleted')
    throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
}

async function existingSecret(tx: IamStore, tenantId: string, name: string): Promise<VaultSecret> {
  const secret = await findSecret(tx, tenantId, name);
  if (!secret) throw new IamError('NOT_FOUND', 'Secret not found', 404);
  return secret;
}

function activeSecret(secret: VaultSecret): VaultSecret {
  if (secret.status !== 'active')
    throw new IamError(
      'SECRET_PENDING_DELETION',
      'This secret is scheduled for deletion; restore it first',
      409,
    );
  return secret;
}

function staticSecret(secret: VaultSecret): VaultSecret {
  if (secret.kind !== 'static')
    throw new IamError(
      'INVALID_INPUT',
      'Dynamic secrets have no stored value; request a lease with vault.lease',
    );
  return secret;
}

/** Values leave the vault only for the person themselves, never through "view as". */
function refuseImpersonation(principal: AuthenticatedPrincipal): void {
  if (principal.session.impersonatorId)
    throw new OperationDenied('Secret values are not available while viewing as another member');
}

function accessEntry(principal: AuthenticatedPrincipal) {
  return {
    identityId: principal.identity.id,
    sessionKind: principal.session.kind,
    ...(principal.session.agentId ? { agentId: principal.session.agentId } : {}),
  };
}

/** A json secret that rotates when checked in must say which field rotation replaces, or returns would not rotate. */
function checkoutFits(secret: VaultSecret): void {
  if (secret.checkout?.rotateOnCheckin && secret.format === 'json' && !secret.rotation?.field)
    throw new IamError(
      'INVALID_INPUT',
      'A json secret that rotates on check-in needs rotation.field, the field rotation replaces',
    );
}

function maxVersions(value: unknown, fallback = 10): number {
  return value === undefined ? fallback : integer(value, 'maxVersions', 1, 100);
}

/** The next value a rotation writes: the explicit one, or the generator's (into `rotation.field` for json secrets). */
function nextValue(
  ctx: ServerContext,
  secret: VaultSecret,
  previous: string | undefined,
  explicit: { value?: unknown; fields?: unknown },
): { value: string; source: VaultVersion['source'] } {
  if (explicit.value !== undefined || explicit.fields !== undefined)
    return { value: secretValue(vaultSettings(ctx), secret.format, explicit), source: 'put' };
  const generated = generateValue(secret.rotation?.generator ?? defaultGenerator);
  if (secret.format === 'text') return { value: generated, source: 'rotation' };
  const field = secret.rotation?.field;
  if (!field)
    throw new IamError(
      'INVALID_INPUT',
      'Pass the new fields, or set rotation.field so rotation can generate one',
    );
  const fields = previous ? parseFields(previous) : {};
  fields[field] = generated;
  return {
    value: secretValue(vaultSettings(ctx), 'json', { fields }),
    source: 'rotation',
  };
}

/**
 * Stages the next version as `pending` (or reuses a pending version left by a failed attempt, so a rotator sees the
 * same value on every retry) and returns what the rotator needs. Runs inside the caller's transaction.
 */
async function stageRotation(
  ctx: ServerContext,
  tx: IamStore,
  original: VaultSecret,
  actorId: string,
  explicit: { value?: unknown; fields?: unknown } = {},
  use?: ValueUse,
): Promise<StagedRotation> {
  let secret = staticSecret(activeSecret(original));
  const current =
    secret.stages.current !== undefined
      ? await versionOf(tx, secret, secret.stages.current)
      : undefined;
  const previous =
    current && current.state === 'enabled' ? await openVersion(ctx, tx, current, use) : undefined;
  const pending =
    secret.stages.pending !== undefined
      ? await versionOf(tx, secret, secret.stages.pending)
      : undefined;
  const fresh = explicit.value !== undefined || explicit.fields !== undefined;
  let version: VaultVersion;
  let value: string;
  // Only a version this machinery staged (and whose attempt failed) is retried: a `pending` label someone set with
  // `put` or `setStage` is never handed to the rotator, or `iam:vault:write` could choose the live credential.
  if (
    !fresh &&
    pending &&
    pending.state === 'enabled' &&
    secret.rotationPending === pending.version
  ) {
    version = pending;
    value = await openVersion(ctx, tx, pending, use);
  } else {
    const next = nextValue(ctx, secret, previous, explicit);
    const added = await addVersion(ctx, tx, secret, next.value, next.source, actorId, use);
    secret = await tx.put<VaultSecret>(vaultCollections.secrets, {
      ...added.secret,
      stages: { ...secret.stages, pending: added.version.version },
      rotationPending: added.version.version,
      updatedAt: ctx.now(),
      updatedBy: actorId,
    });
    version = added.version;
    value = next.value;
  }
  return {
    tenantId: secret.tenantId,
    secretId: secret.id,
    name: secret.name,
    version: version.version,
    value,
    ...(previous !== undefined ? { previous } : {}),
    format: secret.format,
    tags: secret.tags,
    ...(secret.rotation?.rotator !== undefined ? { rotator: secret.rotation.rotator } : {}),
  };
}

/**
 * Records a failed rotation on the secret (the message must already be redacted) and schedules the retry: one hour,
 * doubling up to a day, for secrets that rotate on a schedule or when a check-out comes back. An on-demand rotation is
 * retried by calling it again.
 */
async function recordRotationFailure(
  ctx: ServerContext,
  tx: IamStore,
  secret: VaultSecret,
  message: string,
): Promise<void> {
  const now = ctx.now();
  const failures = (secret.rotation?.failures ?? 0) + 1;
  const retryIn = Math.min(DAY, 60 * MINUTE * 2 ** Math.min(failures - 1, 5));
  const scheduled =
    secret.rotation?.intervalDays !== undefined || secret.checkout?.rotateOnCheckin === true;
  await tx.put<VaultSecret>(vaultCollections.secrets, {
    ...secret,
    rotation: {
      ...secret.rotation,
      lastFailure: { at: now, message },
      failures,
      ...(scheduled ? { nextRotationAt: now + retryIn } : {}),
    },
  });
}

/**
 * Calls the rotator (outside any transaction), then promotes the pending version, or records the failure with a
 * growing retry delay. Returns the outcome; the caller decides whether a failure throws.
 */
async function completeRotation(
  ctx: ServerContext,
  staged: StagedRotation,
  actorId: string,
  record: Recorder,
): Promise<{ ok: true; result: RotationResult } | { ok: false; message: string }> {
  let failure: string | undefined;
  if (staged.rotator !== undefined) {
    const rotator = vaultSettings(ctx).rotators[staged.rotator];
    if (!rotator) failure = `The rotator ${staged.rotator} is not configured`;
    else
      try {
        await withTimeout(ctx, `The rotator ${staged.rotator}`, () =>
          rotator.rotate({
            tenantId: staged.tenantId,
            name: staged.name,
            version: staged.version,
            value: staged.value,
            ...(staged.format === 'json' ? { fields: parseFields(staged.value) } : {}),
            ...(staged.previous !== undefined ? { previous: staged.previous } : {}),
            ...(staged.previous !== undefined && staged.format === 'json'
              ? { previousFields: parseFields(staged.previous) }
              : {}),
            tags: { ...staged.tags },
          }),
        );
      } catch (error) {
        failure = redactedMessage(error, [staged.value, staged.previous]);
      }
  }
  return ctx.store.transaction(async (tx) => {
    const secret = await tx.get<VaultSecret>(vaultCollections.secrets, staged.secretId);
    if (!secret || secret.status !== 'active')
      return { ok: false as const, message: 'The secret was deleted during rotation' };
    if (failure !== undefined) {
      await recordRotationFailure(ctx, tx, secret, failure);
      await record(tx, 'vault:rotate', 'deny', {
        name: secret.name,
        version: staged.version,
        ...(staged.rotator !== undefined ? { rotator: staged.rotator } : {}),
        error: failure,
      });
      return { ok: false as const, message: failure };
    }
    if (secret.stages.pending !== staged.version && secret.stages.current !== staged.version)
      return {
        ok: false as const,
        message: 'Another change replaced the pending version during rotation',
      };
    // The version may have been disabled or destroyed while the rotator ran: never make that current.
    const version = await versionOf(tx, secret, staged.version);
    if (!version || version.state !== 'enabled')
      return {
        ok: false as const,
        message: 'The pending version was disabled or destroyed during rotation',
      };
    const promoted = await promoteVersion(ctx, tx, secret, staged.version, actorId, true);
    await recordAccess(ctx, tx, promoted, {
      identityId: actorId,
      action: 'rotate',
      version: staged.version,
    });
    await record(tx, 'vault:rotate', 'allow', {
      name: secret.name,
      version: staged.version,
      ...(staged.rotator !== undefined ? { rotator: staged.rotator } : {}),
    });
    return {
      ok: true as const,
      result: {
        name: promoted.name,
        version: staged.version,
        rotatedAt: promoted.rotation?.lastRotatedAt ?? ctx.now(),
        ...(staged.rotator !== undefined ? { rotator: staged.rotator } : {}),
        stages: promoted.stages,
      },
    };
  });
}

/**
 * Rotates a `rotateOnCheckin` secret once its last check-out has ended (returned, revoked or expired). Failures,
 * including one that stops the rotation before the rotator runs, are recorded on the secret and audited, and
 * `iam.vault.rotateDue` retries them; they are never thrown, because the check-out has ended either way.
 */
async function rotateReturned(
  ctx: ServerContext,
  tenantId: string,
  secretId: string,
  actorId: string,
  record: (name: string) => Recorder,
): Promise<number | undefined> {
  let staged: StagedRotation | undefined;
  try {
    staged = await ctx.store.transaction(async (tx) => {
      const secret = await tx.get<VaultSecret>(vaultCollections.secrets, secretId);
      if (
        !secret ||
        secret.tenantId !== tenantId ||
        secret.status !== 'active' ||
        !secret.checkout?.rotateOnCheckin
      )
        return undefined;
      // Another holder still has the value: rotate once the last one returns it.
      if ((await liveLeases(ctx, tx, secret)).some((lease) => lease.kind === 'checkout'))
        return undefined;
      return stageRotation(ctx, tx, secret, actorId);
    });
  } catch (error) {
    await ctx.store
      .transaction(async (tx) => {
        const secret = await tx.get<VaultSecret>(vaultCollections.secrets, secretId);
        if (!secret || secret.status !== 'active') return;
        const message = redactedMessage(error, []);
        await recordRotationFailure(ctx, tx, secret, message);
        await record(secret.name)(tx, 'vault:rotate', 'deny', { name: secret.name, error: message });
      })
      .catch(() => undefined);
    return undefined;
  }
  if (!staged) return undefined;
  const outcome = await completeRotation(ctx, staged, actorId, record(staged.name));
  return outcome.ok ? outcome.result.version : undefined;
}

/** The engine's credential, validated against the secret's format and the size limit. */
function issuedValue(
  ctx: ServerContext,
  format: SecretFormat,
  issued: EngineIssued,
): { value: string; handle?: string } {
  if (!issued || typeof issued !== 'object')
    throw new Error('The engine returned no credential');
  const value =
    format === 'json'
      ? issued.fields !== undefined
        ? secretValue(vaultSettings(ctx), 'json', { fields: issued.fields })
        : secretValue(vaultSettings(ctx), 'json', { value: issued.value })
      : secretValue(vaultSettings(ctx), 'text', { value: issued.value });
  if (issued.handle !== undefined && (typeof issued.handle !== 'string' || issued.handle.length > 4096))
    throw new Error('The engine returned an invalid handle');
  return { value, ...(issued.handle !== undefined ? { handle: issued.handle } : {}) };
}

/** Ends a dynamic lease at its engine; the caller records the outcome. Throws the redacted failure message. */
async function revokeAtEngine(ctx: ServerContext, lease: VaultLease, secret?: VaultSecret) {
  const engineName = secret?.engine;
  const engine = engineName ? vaultSettings(ctx).engines[engineName] : undefined;
  if (!engine?.revoke) return;
  const handle = lease.handleSealed
    ? openValue(ctx, lease.handleSealed, leaseHandleContext(lease.id))
    : undefined;
  try {
    await withTimeout(ctx, `The engine ${engineName}`, () =>
      engine.revoke!({
        tenantId: lease.tenantId,
        name: lease.name,
        leaseId: lease.id,
        config: secret?.engineConfig ?? {},
        ...(handle !== undefined ? { handle } : {}),
      }),
    );
  } catch (error) {
    throw new Error(redactedMessage(error, [handle]));
  }
}

/** How long revocations that keep failing are retried before the lease is given up. */
const REVOKE_PATIENCE_MS = 7 * DAY;

/**
 * Revokes a dynamic lease at its engine and records the outcome: the lease ends in its `endState` (default `ended`),
 * or stays `revoking` with a retry scheduled (one minute, doubling up to six hours) for `iam.vault.expireLeases`. The
 * lease must already be `revoking`. Engines without `revoke` end the lease at once.
 */
async function revokeAndRecord(
  ctx: ServerContext,
  leaseId: string,
): Promise<{ ok: boolean; error?: string }> {
  const lease = await ctx.store.get<VaultLease>(vaultCollections.leases, leaseId);
  if (!lease || lease.state !== 'revoking') return { ok: true };
  const secret = await ctx.store.get<VaultSecret>(vaultCollections.secrets, lease.secretId);
  let error: string | undefined;
  try {
    await revokeAtEngine(ctx, lease, secret);
  } catch (failure) {
    error = (failure as Error).message;
  }
  await ctx.store.transaction(async (tx) => {
    const current = await tx.get<VaultLease>(vaultCollections.leases, leaseId);
    if (!current || current.state !== 'revoking') return;
    const now = ctx.now();
    if (error === undefined) {
      const { retryAt: _retry, endState, ...rest } = current;
      await tx.put<VaultLease>(vaultCollections.leases, {
        ...rest,
        state: endState ?? 'ended',
        endedAt: current.endedAt ?? now,
      });
      return;
    }
    const attempts = (current.revokeAttempts ?? 0) + 1;
    await tx.put<VaultLease>(vaultCollections.leases, {
      ...current,
      revokeAttempts: attempts,
      revokeStartedAt: current.revokeStartedAt ?? now,
      retryAt: now + Math.min(6 * 60 * MINUTE, MINUTE * 2 ** Math.min(attempts - 1, 9)),
      lastError: error,
    });
  });
  return error === undefined ? { ok: true } : { ok: false, error };
}

/** Who acted, as the vault's audit recorder for a principal. */
function principalRecorder(ctx: ServerContext, principal: AuthenticatedPrincipal, tenantId: string, name: string): Recorder {
  return (tx, action, outcome, metadata) =>
    ctx.events.audit(tx, principal, action, tenantId, secretResource(name), outcome, false, metadata);
}

/** The scheduler's audit recorder. */
function operatorRecorder(ctx: ServerContext, tenantId: string, name: string): Recorder {
  return (tx, action, outcome, metadata) =>
    ctx.events.recordAudit(tx, {
      id: id(),
      tenantId,
      actorId: vaultOperator,
      action,
      resourceId: secretResource(name),
      timestamp: ctx.now(),
      outcome,
      metadata,
    });
}

// --- the API -------------------------------------------------------------------------------------

/**
 * The secrets vault. Secrets live in one tenant under a path-like name and are authorized as
 * `iam/vault/secrets/{name}`: `iam:vault:read` (metadata), `iam:vault:reveal` (values), `iam:vault:write` (new
 * versions and stages), `iam:vault:rotate`, `iam:vault:lease` (check-outs and dynamic leases) and `iam:vault:manage`
 * (create, settings, delete, versions' state). Policy conditions see `resource.name`, `resource.tag.{key}`,
 * `resource.kind`, `resource.createdBy`, `resource.checkoutRequired` and `resource.rotationEnabled`.
 */
export function createVaultApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const settings = () => vaultSettings(ctx);

  async function views(tx: IamStore, secret: VaultSecret): Promise<SecretView> {
    return view(secret, await liveLeases(ctx, tx, secret), ctx.now());
  }

  /**
   * A customer-managed key the caller may bind secrets to: an enabled encryption key of the tenant (id or
   * `alias/{name}`) on which they hold `iam:kms:encrypt`, so vault rights cannot put values under a key they cannot use.
   */
  async function usableKey(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    realm: Tenant,
    reference: unknown,
  ): Promise<string> {
    const key = await findKey(tx, realm.id, reference);
    assertUsable(key, 'encrypt');
    // The KMS service helpers envelope-encrypt with AES-256-GCM keys only; refuse others when binding, not later.
    if (key.keySpec !== 'aes-256-gcm')
      throw new IamError(
        'INVALID_INPUT',
        'Customer-managed keys for the vault are aes-256-gcm encryption keys',
      );
    await requireKeyAction(tx, principal, realm, key.id, 'iam:kms:encrypt');
    return key.id;
  }

  /**
   * The key-owner's say over a customer-managed secret, as with AWS KMS: values come out only for callers who may also
   * decrypt with its key, and go in only for callers who may encrypt with it. Jobs and `iam.vault` are not asked.
   */
  async function requireSecretKey(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    realm: Tenant,
    secret: VaultSecret,
    actions: ('iam:kms:encrypt' | 'iam:kms:decrypt')[],
  ): Promise<void> {
    if (secret.kmsKeyId === undefined) return;
    for (const action of actions)
      await requireKeyAction(tx, principal, realm, secret.kmsKeyId, action);
  }

  /**
   * Refuses with ACCESS_DENIED unless the caller (and, in "view as", the administrator behind the session) may perform
   * `action` on the KMS key: binding a secret to a key, and taking a secret's values out from under one.
   */
  async function requireKeyAction(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    realm: Tenant,
    keyId: string,
    action: 'iam:kms:encrypt' | 'iam:kms:decrypt',
  ): Promise<void> {
    const key = await findKey(tx, realm.id, keyId);
    const resource = {
      tenantId: realm.id,
      type: 'iam',
      id: `kms/${key.id}`,
      attributes: keyAttributes(key, await aliasNames(tx, key)),
    };
    const actor = await impersonatingActor(tx, principal);
    for (const subject of actor ? [principal, actor] : [principal]) {
      const prepared = await ctx.decisions.prepareDecision(tx, subject, realm, action);
      const decision = 'fixed' in prepared ? prepared.fixed : prepared.evaluate(resource);
      if (!decision.allowed)
        throw new OperationDenied(
          action === 'iam:kms:encrypt'
            ? 'This needs iam:kms:encrypt on the secret’s customer-managed key'
            : 'This needs iam:kms:decrypt on the secret’s customer-managed key',
        );
    }
    // A delegation that holds the key action back for the person's confirmation: this call uses the approval up.
    await useConfirmation(tx, principal, action, 'iam', resource.id, ctx.now());
  }

  /**
   * Re-decides `action` on a secret as it is now inside the transaction (after its attributes changed, or a second
   * action one call also needs), for the caller and any "view as" administrator. An allowed call uses up a delegation's
   * confirmation of that action, as the operation's own action does.
   */
  async function requireStill(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    realm: Tenant,
    name: string,
    action: string,
    message = 'The new tags put the secret outside what you may manage',
  ): Promise<void> {
    const actor = await impersonatingActor(tx, principal);
    for (const subject of actor ? [principal, actor] : [principal]) {
      const decision = await ctx.decisions.decide(
        tx,
        subject,
        { tenantId: realm.id, action, resource: { type: 'iam', id: secretResource(name) } },
        true,
      );
      if (!decision.allowed) throw new OperationDenied(message);
    }
    await useConfirmation(tx, principal, action, 'iam', secretResource(name), ctx.now());
  }

  /**
   * The vault actions the caller, and any "view as" administrator behind the session, may perform on a secret as it
   * is stored now (one set per subject), to compare before and after a change of its attributes.
   */
  async function reach(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    realm: Tenant,
    name: string,
  ): Promise<Set<string>[]> {
    const actor = await impersonatingActor(tx, principal);
    const result: Set<string>[] = [];
    for (const subject of actor ? [principal, actor] : [principal]) {
      const allowed = new Set<string>();
      for (const action of secretActions) {
        const decision = await ctx.decisions.decide(
          tx,
          subject,
          { tenantId: realm.id, action, resource: { type: 'iam', id: secretResource(name) } },
          true,
        );
        if (decision.allowed) allowed.add(action);
      }
      result.push(allowed);
    }
    return result;
  }

  /**
   * Refuses a change of a secret's attributes (tags, settings, key) that opens an action on it to the caller that the
   * secret as it was did not: managing a secret must not move it into what the caller may reveal, lease or rotate.
   */
  async function requireNoWider(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    realm: Tenant,
    name: string,
    before: Set<string>[],
  ): Promise<void> {
    const after = await reach(tx, principal, realm, name);
    for (const [index, allowed] of after.entries())
      for (const action of allowed)
        if (!before[index]?.has(action))
          throw new OperationDenied(
            `The change would give you ${action} on the secret, which you do not have on it now`,
          );
  }

  /**
   * An operation whose answer carries secret values: plugins' `afterOperation` hooks see the answer without them, as
   * with the KMS's plaintexts. `fn` returns the answer and the values apart; the caller gets both.
   */
  async function valueOperation<A extends object, V extends object>(
    credential: CredentialInput,
    tenantId: string,
    action: string,
    resourceId: string,
    fn: (call: {
      tx: IamStore;
      principal: AuthenticatedPrincipal;
      tenant: Tenant;
    }) => Promise<{ answer: A; values: V }>,
  ): Promise<A & V> {
    let values: V | undefined;
    const answer = await operation(credential, tenantId, action, resourceId, async (call) => {
      const split = await fn(call);
      values = split.values;
      return split.answer;
    });
    return { ...answer, ...values! };
  }

  /**
   * A call on a lease by its holder (no further permission: returning a check-out must always be possible) or, for
   * anyone else, an `iam:vault:manage` operation on the secret.
   */
  async function onLease<T>(
    credential: CredentialInput,
    input: { tenantId: string; leaseId: string },
    verb: string,
    fn: (call: {
      tx: IamStore;
      principal: AuthenticatedPrincipal;
      lease: VaultLease;
      secret: VaultSecret | undefined;
      holder: boolean;
    }) => Promise<T>,
  ): Promise<T> {
    const tenantId = text(input.tenantId, 'tenantId');
    const leaseId = text(input.leaseId, 'leaseId');
    const authenticated = await ctx.principals.authenticate(credential);
    const peek = await ctx.store.get<VaultLease>(vaultCollections.leases, leaseId);
    if (!peek || peek.tenantId !== tenantId) throw new IamError('NOT_FOUND', 'Lease not found', 404);
    const load = async (tx: IamStore) => {
      const lease = await tx.get<VaultLease>(vaultCollections.leases, leaseId);
      if (!lease || lease.tenantId !== tenantId)
        throw new IamError('NOT_FOUND', 'Lease not found', 404);
      const secret = await tx.get<VaultSecret>(vaultCollections.secrets, lease.secretId);
      return { lease, secret };
    };
    if (peek.holderId === authenticated.identity.id)
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        await ctx.tenant(tx, tenantId);
        if (principal.session.impersonatorId)
          throw new IamError(
            'ACCESS_DENIED',
            'Leases cannot be changed while viewing as another member',
            403,
          );
        const { lease, secret } = await load(tx);
        // The session that took the lease may always return it. Another session of the holder (a delegated session,
        // an API key a session policy narrows) acts on it only while it could take the lease itself.
        if (lease.sessionId !== principal.session.id)
          await requireStill(
            tx,
            principal,
            await ctx.tenant(tx, tenantId),
            lease.name,
            'iam:vault:lease',
            'This session may not lease the secret; use the session that took the lease',
          );
        const value = await fn({ tx, principal, lease, secret, holder: true });
        await ctx.events.audit(
          tx,
          principal,
          `vault:${verb}`,
          tenantId,
          secretResource(lease.name),
          'allow',
          false,
          { leaseId: lease.id, kind: lease.kind },
        );
        return value;
      });
    return operation(
      credential,
      tenantId,
      'iam:vault:manage',
      secretResource(peek.name),
      async ({ tx, principal }) => {
        const { lease, secret } = await load(tx);
        const value = await fn({ tx, principal, lease, secret, holder: false });
        await ctx.events.audit(
          tx,
          principal,
          `vault:${verb}`,
          tenantId,
          secretResource(lease.name),
          'allow',
          false,
          { leaseId: lease.id, kind: lease.kind, holderId: lease.holderId },
        );
        return value;
      },
    );
  }

  /** Rotation after a check-out ends, when the secret asks for it; failures are recorded, never thrown. */
  async function rotateAfterCheckin(
    tenantId: string,
    secretId: string,
    actorId: string,
    record: (name: string) => Recorder,
  ): Promise<number | undefined> {
    return rotateReturned(ctx, tenantId, secretId, actorId, record);
  }

  return {
    /**
     * Creates a secret. Static secrets may start with a value (`value`, or `fields` for `json` secrets), a generated
     * one (`generate: true` or a generator), or none yet. Dynamic secrets name an `engine` from the `vault.engines`
     * option and have no stored value: each `vault.lease` mints a credential. Requires iam:vault:manage on
     * `iam/vault/secrets/{name}`; audited as `vault:create`.
     */
    create: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        description?: string;
        kind?: SecretKind;
        format?: SecretFormat;
        tags?: Record<string, string>;
        value?: string;
        fields?: Record<string, Json>;
        generate?: boolean | Partial<PasswordGenerator>;
        maxVersions?: number;
        rotation?: {
          intervalDays?: number;
          generator?: boolean | Partial<PasswordGenerator>;
          field?: string;
          rotator?: string;
        };
        checkout?: Partial<CheckoutPolicy>;
        engine?: string;
        engineConfig?: Json;
        lease?: Partial<LeaseSettings>;
        /** A customer-managed key (KMS key id or `alias/{name}`) to encrypt the values under. */
        kmsKey?: string;
      },
    ): Promise<SecretView> => {
      const name = secretName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:manage',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const vault = settings();
          const kind: SecretKind = input.kind ?? 'static';
          if (kind === 'dynamic' && input.kmsKey !== undefined)
            throw new IamError('INVALID_INPUT', 'Dynamic secrets store no values to encrypt');
          if (kind !== 'static' && kind !== 'dynamic')
            throw new IamError('INVALID_INPUT', 'kind must be static or dynamic');
          const format = secretFormat(input.format);
          const existing = await findSecret(tx, realm.id, name);
          if (existing)
            throw new IamError(
              'CONFLICT',
              existing.status === 'pending-deletion'
                ? 'A secret with this name is scheduled for deletion; restore it or wait until it is purged'
                : 'A secret with this name already exists',
              409,
            );
          const count = (await tx.find(vaultCollections.secrets, { tenantId: realm.id })).length;
          if (count >= vault.maxSecretsPerTenant)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can hold at most ${vault.maxSecretsPerTenant} secrets`,
              409,
            );
          const now = ctx.now();
          let secret: VaultSecret = {
            id: id(),
            tenantId: realm.id,
            uniqueKey: name,
            name,
            kind,
            format,
            tags: secretTags(input.tags),
            status: 'active',
            stages: {},
            latestVersion: 0,
            maxVersions: maxVersions(input.maxVersions),
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          };
          if (input.description !== undefined)
            secret.description = text(input.description, 'description', 1024).trim();
          if (kind === 'dynamic') {
            const engine = text(input.engine, 'engine', 64);
            if (!Object.hasOwn(vault.engines, engine))
              throw new IamError('INVALID_INPUT', `Unknown engine ${engine}`);
            for (const key of ['value', 'fields', 'generate', 'rotation', 'checkout'] as const)
              if (input[key] !== undefined)
                throw new IamError('INVALID_INPUT', `Dynamic secrets take no ${key}`);
            secret.engine = engine;
            secret.engineConfig = engineConfig(input.engineConfig);
            secret.lease = leaseSettings(input.lease);
          } else {
            if (input.engine !== undefined || input.engineConfig !== undefined || input.lease)
              throw new IamError('INVALID_INPUT', 'engine settings are for dynamic secrets');
            const rotation = scheduleRotation(
              rotationSettings(vault, format, input.rotation),
              now,
              now,
            );
            if (rotation) secret.rotation = rotation;
            const checkout = checkoutPolicy(input.checkout);
            if (checkout) secret.checkout = checkout;
            if (input.kmsKey !== undefined)
              secret.kmsKeyId = await usableKey(tx, principal, realm, input.kmsKey);
            checkoutFits(secret);
          }
          await tx.insert(vaultCollections.secrets, secret);
          // Decided again with the new secret's attributes (tags, kind, engine, settings), which the first decision
          // could not see: a name nobody uses yet has none.
          await requireStill(
            tx,
            principal,
            realm,
            name,
            'iam:vault:manage',
            'You may not create a secret with these attributes',
          );
          let initial: number | undefined;
          if (kind === 'static' && (input.value !== undefined || input.fields !== undefined || input.generate)) {
            if (input.generate && (input.value !== undefined || input.fields !== undefined))
              throw new IamError('INVALID_INPUT', 'Pass a value or generate, not both');
            let value: string;
            if (input.generate) {
              const generated = generateValue(passwordGenerator(input.generate));
              if (format === 'json') {
                const field = secret.rotation?.field;
                if (!field)
                  throw new IamError(
                    'INVALID_INPUT',
                    'json secrets generate into rotation.field; set it or pass fields',
                  );
                value = JSON.stringify({ [field]: generated });
              } else value = generated;
            } else value = secretValue(vault, format, input);
            const added = await addVersion(
              ctx,
              tx,
              secret,
              value,
              input.generate ? 'generated' : 'put',
              principal.identity.id,
              principal,
            );
            secret = await promoteVersion(
              ctx,
              tx,
              added.secret,
              added.version.version,
              principal.identity.id,
            );
            initial = added.version.version;
            await recordAccess(ctx, tx, secret, {
              ...accessEntry(principal),
              action: 'put',
              version: initial,
            });
          }
          await ctx.events.audit(
            tx,
            principal,
            'vault:create',
            realm.id,
            secretResource(name),
            'allow',
            false,
            {
              name,
              kind,
              format,
              tags: secret.tags,
              ...(initial !== undefined ? { version: initial } : {}),
              ...(secret.engine !== undefined ? { engine: secret.engine } : {}),
              ...(secret.kmsKeyId !== undefined ? { kmsKeyId: secret.kmsKeyId } : {}),
            },
          );
          return views(tx, secret);
        },
      );
    },

    /**
     * Changes a secret's settings: `description` (`null` clears), `tags` (replaced as a whole), `maxVersions`,
     * `rotation` and `checkout` (`null` removes them), and a dynamic secret's `engineConfig` and `lease`. Values change
     * through `put` and `rotate`. Requires iam:vault:manage; audited as `vault:update`.
     */
    update: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        description?: string | null;
        tags?: Record<string, string>;
        maxVersions?: number;
        rotation?: {
          intervalDays?: number | null;
          generator?: boolean | Partial<PasswordGenerator> | null;
          field?: string | null;
          rotator?: string | null;
        } | null;
        checkout?: Partial<CheckoutPolicy> | null;
        engineConfig?: Json;
        lease?: Partial<LeaseSettings>;
        /**
         * A customer-managed key to move the values under (every kept version is re-encrypted), or `null` to move them
         * back under the deployment secret.
         */
        kmsKey?: string | null;
      },
    ): Promise<SecretView> => {
      const name = secretName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:manage',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const secret = activeSecret(await existingSecret(tx, realm.id, name));
          const before = await reach(tx, principal, realm, name);
          const vault = settings();
          const now = ctx.now();
          const { description: _description, rotation: _rotation, checkout: _checkout, ...rest } =
            secret;
          const next: VaultSecret = { ...rest, updatedAt: now, updatedBy: principal.identity.id };
          if (input.description === undefined) {
            if (secret.description !== undefined) next.description = secret.description;
          } else if (input.description !== null)
            next.description = text(input.description, 'description', 1024).trim();
          if (input.tags !== undefined) next.tags = secretTags(input.tags);
          if (input.maxVersions !== undefined) next.maxVersions = maxVersions(input.maxVersions);
          if (secret.kind === 'dynamic') {
            if (input.rotation !== undefined || input.checkout !== undefined)
              throw new IamError('INVALID_INPUT', 'Dynamic secrets are not rotated or checked out');
            if (input.engineConfig !== undefined) next.engineConfig = engineConfig(input.engineConfig);
            if (input.lease !== undefined) next.lease = leaseSettings(input.lease);
          } else {
            if (input.engineConfig !== undefined || input.lease !== undefined)
              throw new IamError('INVALID_INPUT', 'engine settings are for dynamic secrets');
            const rotation = scheduleRotation(
              rotationSettings(vault, secret.format, input.rotation, secret.rotation),
              secret.createdAt,
              now,
            );
            if (rotation) next.rotation = rotation;
            const checkout = checkoutPolicy(input.checkout, secret.checkout);
            if (checkout) next.checkout = checkout;
          }
          let reencrypted = 0;
          if (input.kmsKey !== undefined) {
            if (secret.kind === 'dynamic')
              throw new IamError('INVALID_INPUT', 'Dynamic secrets store no values to encrypt');
            const { kmsKeyId: _previous, ...unkeyed } = next;
            const target: VaultSecret =
              input.kmsKey === null
                ? unkeyed
                : { ...unkeyed, kmsKeyId: await usableKey(tx, principal, realm, input.kmsKey) };
            if (target.kmsKeyId !== secret.kmsKeyId) {
              // Taking values out from under a customer-managed key is a decryption with it.
              if (secret.kmsKeyId !== undefined)
                await requireKeyAction(tx, principal, realm, secret.kmsKeyId, 'iam:kms:decrypt');
              for (const version of await secretVersions(tx, secret)) {
                if (version.sealed === undefined) continue;
                const value = await openStored(ctx, tx, version, principal);
                await tx.put(
                  vaultCollections.versions,
                  await encryptVersion(ctx, tx, target, version, value, principal),
                );
                reencrypted++;
              }
            }
            Object.assign(next, target);
            if (target.kmsKeyId === undefined) delete next.kmsKeyId;
          }
          checkoutFits(next);
          const stored = await tx.put<VaultSecret>(vaultCollections.secrets, next);
          // New tags and settings are new attributes: the caller must still be allowed to manage the secret with them,
          // and may not gain any other action on it by the change.
          await requireStill(
            tx,
            principal,
            realm,
            name,
            'iam:vault:manage',
            'The change puts the secret outside what you may manage',
          );
          await requireNoWider(tx, principal, realm, name, before);
          await pruneVersions(tx, stored);
          await ctx.events.audit(
            tx,
            principal,
            'vault:update',
            realm.id,
            secretResource(name),
            'allow',
            false,
            {
              name,
              tags: stored.tags,
              maxVersions: stored.maxVersions,
              rotation: stored.rotation?.intervalDays ?? null,
              rotator: stored.rotation?.rotator ?? null,
              checkout: stored.checkout ? true : false,
              kmsKeyId: stored.kmsKeyId ?? null,
              ...(reencrypted ? { reencrypted } : {}),
            },
          );
          return views(tx, stored);
        },
      );
    },

    /**
     * Schedules a secret for deletion after a recovery window of `recoveryDays` (7-30, default 30), during which it
     * can be restored but not read; `recoveryDays: 0` deletes it at once (versions, leases and access records; live
     * dynamic leases are revoked at their engine first). Live check-outs end. Requires iam:vault:manage; audited as
     * `vault:delete`.
     */
    delete: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; recoveryDays?: number },
    ): Promise<{ name: string; status: 'pending-deletion' | 'deleted'; deletionAt: number }> => {
      const name = secretName(input.name);
      const days =
        input.recoveryDays === undefined
          ? 30
          : input.recoveryDays === 0
            ? 0
            : integer(input.recoveryDays, 'recoveryDays', 7, 30);
      const scheduled = await operation(
        credential,
        input.tenantId,
        'iam:vault:manage',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          // Deleting at once destroys every value for good: only from a recently signed-in session.
          if (days === 0) ctx.auth.requireRecent(principal);
          const secret = await existingSecret(tx, realm.id, name);
          if (secret.status === 'pending-deletion' && days !== 0)
            throw new IamError('SECRET_PENDING_DELETION', 'This secret is already scheduled for deletion', 409);
          const now = ctx.now();
          const deletionAt = now + days * DAY;
          const stored = await tx.put<VaultSecret>(vaultCollections.secrets, {
            ...secret,
            status: 'pending-deletion',
            deletionAt,
            deletionRequestedBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          });
          for (const lease of await liveLeases(ctx, tx, secret))
            if (lease.kind === 'checkout')
              await tx.put<VaultLease>(vaultCollections.leases, {
                ...lease,
                state: 'ended',
                endedAt: now,
                endedBy: principal.identity.id,
              });
          await ctx.events.audit(
            tx,
            principal,
            'vault:delete',
            realm.id,
            secretResource(name),
            'allow',
            false,
            { name, recoveryDays: days, deletionAt },
          );
          return { secretId: stored.id, tenantId: realm.id, deletionAt };
        },
      );
      if (days === 0) {
        await purgeSecret(ctx, scheduled.secretId);
        return { name, status: 'deleted', deletionAt: scheduled.deletionAt };
      }
      return { name, status: 'pending-deletion', deletionAt: scheduled.deletionAt };
    },

    /** Cancels a scheduled deletion. Requires iam:vault:manage; audited as `vault:restore`. */
    restore: async (credential: CredentialInput, input: { tenantId: string; name: string }) => {
      const name = secretName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:manage',
        secretResource(name),
        async ({ tx, tenant: realm, principal }): Promise<SecretView> => {
          writable(realm);
          const secret = await existingSecret(tx, realm.id, name);
          if (secret.status !== 'pending-deletion')
            throw new IamError('INVALID_TRANSITION', 'This secret is not scheduled for deletion');
          const {
            deletionAt: _at,
            deletionRequestedBy: _by,
            ...rest
          } = secret;
          const stored = await tx.put<VaultSecret>(vaultCollections.secrets, {
            ...rest,
            status: 'active',
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await ctx.events.audit(
            tx,
            principal,
            'vault:restore',
            realm.id,
            secretResource(name),
            'allow',
            false,
            { name },
          );
          return views(tx, stored);
        },
      );
    },

    /** A secret's metadata and live check-outs. Requires iam:vault:read. */
    get: async (credential: CredentialInput, input: { tenantId: string; name: string }) => {
      const name = secretName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:read',
        secretResource(name),
        async ({ tx, tenant: realm }) => views(tx, await existingSecret(tx, realm.id, name)),
      );
    },

    /**
     * The secrets the caller may read (`iam:vault:read` on each), sorted by name: optionally under `prefix`, with all
     * of `tags`, and by `status` (default `active`; `all` includes pending deletions). At most `limit` (1-500,
     * default 100) from `offset`, with the `total` the caller may see. Needs only a session of the tenant; the
     * listing itself is not audited.
     */
    list: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        prefix?: string;
        tags?: Record<string, string>;
        status?: 'active' | 'pending-deletion' | 'all';
        limit?: number;
        offset?: number;
      },
    ): Promise<{ secrets: SecretView[]; total: number }> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const prefix = secretPrefix(input.prefix);
      const tags = input.tags === undefined ? {} : secretTags(input.tags);
      const status = input.status ?? 'active';
      if (!['active', 'pending-deletion', 'all'].includes(status))
        throw new IamError('INVALID_INPUT', 'status must be active, pending-deletion or all');
      const limit = input.limit === undefined ? 100 : integer(input.limit, 'limit', 1, 500);
      const offset = input.offset === undefined ? 0 : integer(input.offset, 'offset', 0, 1_000_000);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const realm = await ctx.tenant(tx, tenantId);
        const prepared = await ctx.decisions.prepareDecision(tx, principal, realm, 'iam:vault:read');
        const actor = await impersonatingActor(tx, principal);
        const own = actor && (await ctx.decisions.prepareDecision(tx, actor, realm, 'iam:vault:read'));
        const allows = (evaluator: typeof prepared, secret: VaultSecret) =>
          ('fixed' in evaluator
            ? evaluator.fixed
            : evaluator.evaluate({
                tenantId: realm.id,
                type: 'iam',
                id: secretResource(secret.name),
                attributes: secretAttributes(secret),
              })
          ).allowed;
        const visible = (await tx.find<VaultSecret>(vaultCollections.secrets, { tenantId: realm.id }))
          .filter(
            (secret) =>
              (status === 'all' || secret.status === status) &&
              secret.name.startsWith(prefix) &&
              Object.entries(tags).every(([key, value]) => secret.tags[key] === value),
          )
          .filter((secret) => allows(prepared, secret) && (!own || allows(own, secret)))
          .sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
        const page: SecretView[] = [];
        for (const secret of visible.slice(offset, offset + limit)) page.push(await views(tx, secret));
        return { secrets: page, total: visible.length };
      });
    },

    /**
     * A secret's value: the `current` version, or `version` / `stage`. Refused while viewing as another member, for
     * dynamic secrets (use `lease`), for disabled (VERSION_DISABLED) and destroyed (VERSION_DESTROYED) versions, and
     * with CHECKOUT_REQUIRED when the secret is handed out only through check-outs (the holder of a live check-out
     * may reveal the version they checked out). Requires iam:vault:reveal; audited as `vault:reveal`.
     */
    reveal: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; version?: number; stage?: string },
    ): Promise<RevealedSecret> => {
      const name = secretName(input.name);
      return valueOperation(
        credential,
        input.tenantId,
        'iam:vault:reveal',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          refuseImpersonation(principal);
          const secret = staticSecret(activeSecret(await existingSecret(tx, realm.id, name)));
          await requireSecretKey(tx, principal, realm, secret, ['iam:kms:decrypt']);
          let version = await selectVersion(tx, secret, input);
          if (secret.checkout?.required) {
            const held = (await liveLeases(ctx, tx, secret)).find(
              (lease) => lease.kind === 'checkout' && lease.holderId === principal.identity.id,
            );
            if (!held)
              throw new IamError(
                'CHECKOUT_REQUIRED',
                'This secret is handed out only through check-outs (vault.checkout)',
                409,
              );
            if (input.version === undefined && input.stage === undefined && held.version !== undefined)
              version = (await versionOf(tx, secret, held.version)) ?? version;
            if (version.version !== held.version)
              throw new IamError(
                'CHECKOUT_REQUIRED',
                'A check-out reveals only the version it handed out',
                409,
              );
          }
          const value = await openVersion(ctx, tx, version, principal);
          await recordAccess(ctx, tx, secret, {
            ...accessEntry(principal),
            action: 'reveal',
            version: version.version,
          });
          await ctx.events.audit(
            tx,
            principal,
            'vault:reveal',
            realm.id,
            secretResource(name),
            'allow',
            false,
            { name, version: version.version },
          );
          return splitValues(revealed(secret, version, value));
        },
      );
    },

    /**
     * Stores a new version (`value`, `fields` for json secrets, or `generate`). It becomes `current` (the old one
     * `previous`) unless `stage` names another label: `pending` stages it for a later `promote` or `rotate`, any custom
     * label just points at it. Versions past `maxVersions` that no stage names are deleted. Requires iam:vault:write;
     * audited as `vault:put`.
     */
    put: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        value?: string;
        fields?: Record<string, Json>;
        generate?: boolean | Partial<PasswordGenerator>;
        stage?: string;
      },
    ): Promise<SecretVersionView> => {
      const name = secretName(input.name);
      const stage = input.stage === undefined ? 'current' : stageName(input.stage);
      if (stage === 'previous')
        throw new IamError('INVALID_INPUT', 'previous moves by itself when a version becomes current');
      return operation(
        credential,
        input.tenantId,
        'iam:vault:write',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          let secret = staticSecret(activeSecret(await existingSecret(tx, realm.id, name)));
          // Generating into a json secret reads its current fields, which is a decryption as well.
          await requireSecretKey(
            tx,
            principal,
            realm,
            secret,
            input.generate && secret.format === 'json'
              ? ['iam:kms:encrypt', 'iam:kms:decrypt']
              : ['iam:kms:encrypt'],
          );
          let value: string;
          if (input.generate) {
            if (input.value !== undefined || input.fields !== undefined)
              throw new IamError('INVALID_INPUT', 'Pass a value or generate, not both');
            const generated = generateValue(passwordGenerator(input.generate));
            if (secret.format === 'json') {
              const field = secret.rotation?.field;
              if (!field)
                throw new IamError('INVALID_INPUT', 'json secrets generate into rotation.field');
              const current =
                secret.stages.current !== undefined
                  ? await versionOf(tx, secret, secret.stages.current)
                  : undefined;
              const fields =
                current && current.state === 'enabled'
                  ? parseFields(await openVersion(ctx, tx, current, principal))
                  : {};
              fields[field] = generated;
              value = JSON.stringify(fields);
            } else value = generated;
          } else value = secretValue(settings(), secret.format, input);
          const added = await addVersion(
            ctx,
            tx,
            secret,
            value,
            input.generate ? 'generated' : 'put',
            principal.identity.id,
            principal,
          );
          if (stage === 'current')
            secret = await promoteVersion(ctx, tx, added.secret, added.version.version, principal.identity.id);
          else {
            const stages = { ...added.secret.stages, [stage]: added.version.version };
            if (Object.keys(stages).filter((label) => !systemStages.has(label)).length > 8)
              throw new IamError('LIMIT_EXCEEDED', 'A secret has at most 8 custom stage labels', 409);
            secret = await tx.put<VaultSecret>(vaultCollections.secrets, {
              ...added.secret,
              stages,
              updatedAt: ctx.now(),
              updatedBy: principal.identity.id,
            });
            await pruneVersions(tx, secret);
          }
          await recordAccess(ctx, tx, secret, {
            ...accessEntry(principal),
            action: 'put',
            version: added.version.version,
          });
          await ctx.events.audit(
            tx,
            principal,
            'vault:put',
            realm.id,
            secretResource(name),
            'allow',
            false,
            { name, version: added.version.version, stage },
          );
          return versionView(secret, added.version);
        },
      );
    },

    /** Every kept version, newest first, with its state and stage labels. Requires iam:vault:read. */
    listVersions: async (credential: CredentialInput, input: { tenantId: string; name: string }) => {
      const name = secretName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:read',
        secretResource(name),
        async ({ tx, tenant: realm }): Promise<SecretVersionView[]> => {
          const secret = await existingSecret(tx, realm.id, name);
          return (await secretVersions(tx, secret)).map((version) => versionView(secret, version));
        },
      );
    },

    /**
     * Makes an enabled version `current` (the old one becomes `previous`); rolls back as well as forward. Requires
     * iam:vault:write; audited as `vault:promote`.
     */
    promote: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; version: number },
    ): Promise<SecretView> => {
      const name = secretName(input.name);
      const number = integer(input.version, 'version', 1, Number.MAX_SAFE_INTEGER);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:write',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const secret = staticSecret(activeSecret(await existingSecret(tx, realm.id, name)));
          const version = await versionOf(tx, secret, number);
          if (!version) throw new IamError('NOT_FOUND', 'Version not found', 404);
          if (version.state !== 'enabled')
            throw new IamError('VERSION_DISABLED', 'Only enabled versions can become current', 409);
          const stored = await promoteVersion(ctx, tx, secret, number, principal.identity.id);
          await ctx.events.audit(
            tx,
            principal,
            'vault:promote',
            realm.id,
            secretResource(name),
            'allow',
            false,
            { name, version: number, previous: secret.stages.current ?? null },
          );
          return views(tx, stored);
        },
      );
    },

    /**
     * Points a custom stage label (or `pending`) at a version, or removes it with `version: null`. `current` and
     * `previous` move only through `put`, `promote` and `rotate`. At most 8 custom labels. Requires iam:vault:write;
     * audited as `vault:stage`.
     */
    setStage: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; stage: string; version: number | null },
    ): Promise<SecretView> => {
      const name = secretName(input.name);
      const stage = stageName(input.stage);
      if (stage === 'current' || stage === 'previous')
        throw new IamError('INVALID_INPUT', 'Use promote to change the current version');
      return operation(
        credential,
        input.tenantId,
        'iam:vault:write',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const secret = staticSecret(activeSecret(await existingSecret(tx, realm.id, name)));
          const stages = { ...secret.stages };
          if (input.version === null) delete stages[stage];
          else {
            const number = integer(input.version, 'version', 1, Number.MAX_SAFE_INTEGER);
            const version = await versionOf(tx, secret, number);
            if (!version || version.state === 'destroyed')
              throw new IamError('NOT_FOUND', 'Version not found', 404);
            stages[stage] = number;
            if (Object.keys(stages).filter((label) => !systemStages.has(label)).length > 8)
              throw new IamError('LIMIT_EXCEEDED', 'A secret has at most 8 custom stage labels', 409);
          }
          const stored = await tx.put<VaultSecret>(vaultCollections.secrets, {
            ...secret,
            stages,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await pruneVersions(tx, stored);
          await ctx.events.audit(
            tx,
            principal,
            'vault:stage',
            realm.id,
            secretResource(name),
            'allow',
            false,
            { name, stage, version: input.version === null ? null : stages[stage]! },
          );
          return views(tx, stored);
        },
      );
    },

    /**
     * Disables a version (`state: 'disabled'`: kept, but not revealed) or enables it again. The current version cannot
     * be disabled. Requires iam:vault:manage; audited as `vault:version-state`.
     */
    setVersionState: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; version: number; state: 'enabled' | 'disabled' },
    ): Promise<SecretVersionView> => {
      const name = secretName(input.name);
      const number = integer(input.version, 'version', 1, Number.MAX_SAFE_INTEGER);
      if (input.state !== 'enabled' && input.state !== 'disabled')
        throw new IamError('INVALID_INPUT', 'state must be enabled or disabled');
      return operation(
        credential,
        input.tenantId,
        'iam:vault:manage',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const secret = staticSecret(await existingSecret(tx, realm.id, name));
          const version = await versionOf(tx, secret, number);
          if (!version) throw new IamError('NOT_FOUND', 'Version not found', 404);
          if (version.state === 'destroyed')
            throw new IamError('VERSION_DESTROYED', 'This version was destroyed', 410);
          if (input.state === 'disabled' && secret.stages.current === number)
            throw new IamError(
              'INVALID_TRANSITION',
              'The current version cannot be disabled; promote another version first',
            );
          const now = ctx.now();
          const { disabledAt: _disabled, ...rest } = version;
          const next = await tx.put<VaultVersion>(vaultCollections.versions, {
            ...rest,
            state: input.state,
            ...(input.state === 'disabled' ? { disabledAt: now } : {}),
          });
          await ctx.events.audit(
            tx,
            principal,
            'vault:version-state',
            realm.id,
            secretResource(name),
            'allow',
            false,
            { name, version: number, state: input.state },
          );
          return versionView(secret, next);
        },
      );
    },

    /**
     * Destroys a version's value for good (the record stays as history); stage labels on it are removed. The current
     * version cannot be destroyed. Requires iam:vault:manage; audited as `vault:destroy-version`.
     */
    destroyVersion: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; version: number },
    ): Promise<SecretVersionView> => {
      const name = secretName(input.name);
      const number = integer(input.version, 'version', 1, Number.MAX_SAFE_INTEGER);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:manage',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          ctx.auth.requireRecent(principal);
          const secret = staticSecret(await existingSecret(tx, realm.id, name));
          const version = await versionOf(tx, secret, number);
          if (!version) throw new IamError('NOT_FOUND', 'Version not found', 404);
          if (secret.stages.current === number)
            throw new IamError(
              'INVALID_TRANSITION',
              'The current version cannot be destroyed; promote another version first',
            );
          const { sealed: _sealed, ...rest } = version;
          const next = await tx.put<VaultVersion>(vaultCollections.versions, {
            ...rest,
            state: 'destroyed',
            destroyedAt: ctx.now(),
          });
          const stages = Object.fromEntries(
            Object.entries(secret.stages).filter(([, value]) => value !== number),
          );
          const stored = await tx.put<VaultSecret>(vaultCollections.secrets, {
            ...secret,
            stages,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await ctx.events.audit(
            tx,
            principal,
            'vault:destroy-version',
            realm.id,
            secretResource(name),
            'allow',
            false,
            { name, version: number },
          );
          return versionView(stored, next);
        },
      );
    },

    /**
     * Rotates a static secret now: stages a new version as `pending` (generated, or `value` / `fields` when given),
     * lets the secret's rotator apply it to the system it unlocks, then makes it current. A failing rotator leaves the
     * pending version for the next attempt, records the error, and fails with ROTATION_FAILED (502). Requires
     * iam:vault:rotate; audited as `vault:rotate` (outcome deny on failure).
     */
    rotate: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; value?: string; fields?: Record<string, Json> },
    ): Promise<RotationResult> => {
      const name = secretName(input.name);
      let principal: AuthenticatedPrincipal | undefined;
      const staged: StagedRotation = await valueOperation(
        credential,
        input.tenantId,
        'iam:vault:rotate',
        secretResource(name),
        async ({ tx, tenant: realm, principal: caller }) => {
          writable(realm);
          principal = caller;
          const secret = await existingSecret(tx, realm.id, name);
          if (input.value !== undefined || input.fields !== undefined) {
            // A value the caller chooses is one they know, and the rotator makes it live: never for secrets that
            // leave only through check-outs, and otherwise only for callers who may write and reveal it anyway.
            if (secret.checkout?.required)
              throw new IamError(
                'INVALID_INPUT',
                'Secrets handed out only through check-outs rotate to generated values',
              );
            await requireStill(
              tx,
              caller,
              realm,
              name,
              'iam:vault:write',
              'Rotating to a value you choose needs iam:vault:write on the secret',
            );
            await requireStill(
              tx,
              caller,
              realm,
              name,
              'iam:vault:reveal',
              'Rotating to a value you choose needs iam:vault:reveal on the secret',
            );
          }
          await requireSecretKey(tx, caller, realm, secret, ['iam:kms:encrypt', 'iam:kms:decrypt']);
          const { value, previous, ...answer } = await stageRotation(
            ctx,
            tx,
            secret,
            caller.identity.id,
            input,
            caller,
          );
          return { answer, values: { value, ...(previous !== undefined ? { previous } : {}) } };
        },
      );
      const outcome = await completeRotation(
        ctx,
        staged,
        principal!.identity.id,
        principalRecorder(ctx, principal!, staged.tenantId, name),
      );
      if (!outcome.ok) throw new IamError('ROTATION_FAILED', outcome.message, 502);
      return outcome.result;
    },

    /**
     * Checks out a static secret: its current value with a lease of `durationMs` (default and at most the policy's
     * `maxDurationMs`; one hour without a policy). An exclusive secret has one holder at a time (SECRET_CHECKED_OUT
     * otherwise); `reason` is required when the policy says so. Refused while viewing as another member. Requires
     * iam:vault:lease; audited as `vault:checkout`.
     */
    checkout: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; durationMs?: number; reason?: string },
    ): Promise<CheckoutResult> => {
      const name = secretName(input.name);
      return valueOperation(
        credential,
        input.tenantId,
        'iam:vault:lease',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          refuseImpersonation(principal);
          const secret = staticSecret(activeSecret(await existingSecret(tx, realm.id, name)));
          await requireSecretKey(tx, principal, realm, secret, ['iam:kms:decrypt']);
          // Without a policy there is nothing to check out: iam:vault:lease granted for dynamic secrets must not
          // hand out stored values that iam:vault:reveal guards.
          const policy = secret.checkout;
          if (!policy)
            throw new IamError(
              'INVALID_INPUT',
              'This secret has no check-out policy; reveal it with vault.reveal',
            );
          const reason =
            input.reason === undefined || input.reason === ''
              ? undefined
              : text(input.reason, 'reason', 512).trim();
          if (policy.requireReason && !reason)
            throw new IamError('INVALID_INPUT', 'A check-out of this secret needs a reason');
          const duration =
            input.durationMs === undefined
              ? policy.maxDurationMs
              : integer(input.durationMs, 'durationMs', MINUTE, policy.maxDurationMs);
          const live = await liveLeases(ctx, tx, secret);
          const holders = live.filter((lease) => lease.kind === 'checkout');
          if (holders.some((lease) => lease.holderId === principal.identity.id))
            throw new IamError(
              'SECRET_CHECKED_OUT',
              'You already hold a check-out of this secret; check it in or renew it',
              409,
            );
          if (policy.exclusive && holders.length)
            throw new IamError(
              'SECRET_CHECKED_OUT',
              'Someone else has this secret checked out; try again when it is checked in',
              409,
            );
          const version = await selectVersion(tx, secret, {});
          const value = await openVersion(ctx, tx, version, principal);
          const now = ctx.now();
          const lease: VaultLease = {
            id: id(),
            tenantId: realm.id,
            secretId: secret.id,
            name,
            kind: 'checkout',
            holderId: principal.identity.id,
            sessionId: principal.session.id,
            ...leaseActor(principal),
            version: version.version,
            ...(reason ? { reason } : {}),
            state: 'active',
            issuedAt: now,
            expiresAt: now + duration,
            maxExpiresAt: now + policy.maxDurationMs,
            ttlMs: duration,
          };
          await tx.insert(vaultCollections.leases, lease);
          await recordAccess(ctx, tx, secret, {
            ...accessEntry(principal),
            action: 'checkout',
            version: version.version,
            leaseId: lease.id,
          });
          await ctx.events.audit(
            tx,
            principal,
            'vault:checkout',
            realm.id,
            secretResource(name),
            'allow',
            false,
            {
              name,
              version: version.version,
              leaseId: lease.id,
              expiresAt: lease.expiresAt,
              ...(reason ? { reason } : {}),
            },
          );
          return splitValues({
            ...revealed(secret, version, value),
            leaseId: lease.id,
            expiresAt: lease.expiresAt,
            maxExpiresAt: lease.maxExpiresAt,
          });
        },
      );
    },

    /**
     * Returns a check-out (its holder needs no further permission; anyone else needs iam:vault:manage). A secret with
     * `rotateOnCheckin` rotates once its last holder returns it; `rotated` says to which version. Audited as
     * `vault:checkin`.
     */
    checkin: async (
      credential: CredentialInput,
      input: { tenantId: string; leaseId: string },
    ): Promise<{ leaseId: string; state: 'ended'; rotated?: number }> => {
      let actor: AuthenticatedPrincipal | undefined;
      const ended = await onLease(credential, input, 'checkin', async ({ tx, principal, lease, secret }) => {
        if (lease.kind !== 'checkout')
          throw new IamError('INVALID_INPUT', 'This is a dynamic lease; use revokeLease');
        if (lease.state !== 'active' || lease.expiresAt <= ctx.now())
          throw new IamError('INVALID_TRANSITION', 'This check-out has already ended');
        actor = principal;
        await tx.put<VaultLease>(vaultCollections.leases, {
          ...lease,
          state: 'ended',
          endedAt: ctx.now(),
          endedBy: principal.identity.id,
        });
        if (secret)
          await recordAccess(ctx, tx, secret, {
            ...accessEntry(principal),
            action: 'checkin',
            leaseId: lease.id,
            ...(lease.version !== undefined ? { version: lease.version } : {}),
          });
        return { tenantId: lease.tenantId, secretId: lease.secretId };
      });
      const rotated = await rotateAfterCheckin(ended.tenantId, ended.secretId, actor!.identity.id, (name) =>
        principalRecorder(ctx, actor!, ended.tenantId, name),
      );
      return {
        leaseId: input.leaseId,
        state: 'ended',
        ...(rotated !== undefined ? { rotated } : {}),
      };
    },

    /**
     * A dynamic secret's credential, minted by its engine for the caller with a lease of `ttlMs` (default and maximum
     * from the secret's `lease` settings). The value is returned once and never stored; the lease is revoked at the
     * engine by `revokeLease`, or by `iam.vault.expireLeases` once it expires. Engine failures fail with
     * ENGINE_FAILED (502). Refused while viewing as another member. Requires iam:vault:lease; audited as `vault:lease`.
     */
    lease: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; ttlMs?: number },
    ): Promise<DynamicLeaseResult> => {
      const name = secretName(input.name);
      let caller: AuthenticatedPrincipal | undefined;
      const issuing = await operation(
        credential,
        input.tenantId,
        'iam:vault:lease',
        secretResource(name),
        async ({ tx, tenant: realm, principal }) => {
          refuseImpersonation(principal);
          const secret = activeSecret(await existingSecret(tx, realm.id, name));
          if (secret.kind !== 'dynamic')
            throw new IamError('INVALID_INPUT', 'Static secrets are revealed or checked out, not leased');
          const lease = secret.lease ?? leaseSettings(undefined);
          const ttl =
            input.ttlMs === undefined
              ? lease.defaultTtlMs
              : integer(input.ttlMs, 'ttlMs', MINUTE, lease.maxTtlMs);
          const now = ctx.now();
          const record: VaultLease = {
            id: id(),
            tenantId: realm.id,
            secretId: secret.id,
            name,
            kind: 'dynamic',
            holderId: principal.identity.id,
            sessionId: principal.session.id,
            ...leaseActor(principal),
            state: 'issuing',
            issuedAt: now,
            expiresAt: now + ttl,
            maxExpiresAt: now + lease.maxTtlMs,
            ttlMs: ttl,
          };
          await tx.insert(vaultCollections.leases, record);
          caller = principal;
          return {
            lease: record,
            secret,
            holder: {
              id: principal.identity.id,
              kind: principal.identity.kind ?? 'user',
              name: principal.identity.name,
              ...(principal.identity.email ? { email: principal.identity.email } : {}),
            },
            ttl,
          };
        },
      );
      const { lease, secret, holder, ttl } = issuing;
      const engine = settings().engines[secret.engine!];
      let raw: EngineIssued | undefined;
      let issued: { value: string; handle?: string } | undefined;
      let failure: string | undefined;
      if (!engine) failure = `The engine ${secret.engine} is not configured`;
      else
        try {
          raw = await withTimeout(ctx, `The engine ${secret.engine}`, () =>
            engine.issue({
              tenantId: lease.tenantId,
              name,
              leaseId: lease.id,
              config: secret.engineConfig ?? {},
              ttlMs: ttl,
              holder,
            }),
          );
          issued = issuedValue(ctx, secret.format, raw);
        } catch (error) {
          failure = redactedMessage(error, [
            typeof raw?.value === 'string' ? raw.value : undefined,
            raw?.fields ? JSON.stringify(raw.fields) : undefined,
          ]);
        }
      // Once `issue` was called, a credential may exist even when the call failed or timed out: such leases are
      // revoked at the engine by id (with the handle when one came back), and retried until the engine confirms.
      const handle =
        typeof raw?.handle === 'string' && raw.handle.length <= 4096 ? raw.handle : undefined;
      const record = principalRecorder(ctx, caller!, lease.tenantId, name);
      const stored = await ctx.store.transaction(async (tx) => {
        const current = await tx.get<VaultLease>(vaultCollections.leases, lease.id);
        if (failure !== undefined || !issued || !current || current.state !== 'issuing') {
          if (current)
            await tx.put<VaultLease>(vaultCollections.leases, {
              ...current,
              state: engine ? 'revoking' : 'failed',
              endedAt: ctx.now(),
              endedBy: current.endedBy ?? vaultOperator,
              ...(engine ? { endState: failure !== undefined ? 'failed' : 'ended' } : {}),
              ...(handle !== undefined
                ? { handleSealed: sealValue(ctx, handle, leaseHandleContext(current.id)) }
                : {}),
              lastError: failure ?? 'The lease was ended while it was issued',
            });
          await record(tx, 'vault:lease', 'deny', {
            name,
            leaseId: lease.id,
            error: failure ?? 'ended while issuing',
          });
          return undefined;
        }
        const next: VaultLease = {
          ...current,
          state: 'active',
          ...(issued.handle !== undefined
            ? { handleSealed: sealValue(ctx, issued.handle, leaseHandleContext(current.id)) }
            : {}),
        };
        await tx.put(vaultCollections.leases, next);
        await recordAccess(ctx, tx, secret, {
          ...accessEntry(caller!),
          action: 'lease',
          leaseId: current.id,
        });
        await record(tx, 'vault:lease', 'allow', {
          name,
          leaseId: current.id,
          expiresAt: current.expiresAt,
        });
        return next;
      });
      if (!stored) {
        // Take back whatever the engine may have minted now; a refusal is retried by iam.vault.expireLeases.
        if (engine) await revokeAndRecord(ctx, lease.id);
        throw new IamError('ENGINE_FAILED', failure ?? 'The lease was ended while it was issued', 502);
      }
      return {
        leaseId: stored.id,
        name,
        format: secret.format,
        value: issued!.value,
        ...(secret.format === 'json' ? { fields: parseFields(issued!.value) } : {}),
        issuedAt: stored.issuedAt,
        expiresAt: stored.expiresAt,
        maxExpiresAt: stored.maxExpiresAt,
        renewable: stored.expiresAt < stored.maxExpiresAt,
      };
    },

    /**
     * Extends a live check-out or dynamic lease by `ttlMs` from now (default: its original length), never past its
     * `maxExpiresAt`; a dynamic lease's engine is told through `renew` when it has one. Holder only. Audited as
     * `vault:renew`.
     */
    renewLease: async (
      credential: CredentialInput,
      input: { tenantId: string; leaseId: string; ttlMs?: number },
    ): Promise<{ leaseId: string; expiresAt: number; maxExpiresAt: number }> => {
      let renewal: { lease: VaultLease; secret?: VaultSecret; ttl: number } | undefined;
      const result = await onLease(credential, input, 'renew', async ({ tx, principal, lease, secret, holder }) => {
        if (!holder)
          throw new IamError('ACCESS_DENIED', 'Only the holder renews a lease', 403);
        const now = ctx.now();
        if (lease.state !== 'active' || lease.expiresAt <= now)
          throw new IamError('INVALID_TRANSITION', 'This lease has already ended');
        if (secret?.status !== 'active')
          throw new IamError('SECRET_PENDING_DELETION', 'This secret is scheduled for deletion', 409);
        // Extending access is using it again: the holder must still be allowed to lease the secret.
        await requireStill(
          tx,
          principal,
          await ctx.tenant(tx, lease.tenantId),
          lease.name,
          'iam:vault:lease',
          'Renewing needs iam:vault:lease on the secret',
        );
        const length =
          input.ttlMs === undefined
            ? (lease.ttlMs ?? lease.expiresAt - lease.issuedAt)
            : integer(input.ttlMs, 'ttlMs', MINUTE, 30 * DAY);
        const expiresAt = Math.min(now + length, lease.maxExpiresAt);
        if (expiresAt <= lease.expiresAt)
          throw new IamError('LIMIT_EXCEEDED', 'This lease has reached its longest allowed length', 409);
        const next = await tx.put<VaultLease>(vaultCollections.leases, { ...lease, expiresAt });
        await recordAccess(ctx, tx, secret, {
          ...accessEntry(principal),
          action: 'renew',
          leaseId: lease.id,
        });
        renewal = { lease: next, secret, ttl: expiresAt - now };
        return { leaseId: next.id, expiresAt: next.expiresAt, maxExpiresAt: next.maxExpiresAt };
      });
      const engine = renewal?.secret?.engine ? settings().engines[renewal.secret.engine] : undefined;
      if (renewal && renewal.lease.kind === 'dynamic' && engine?.renew) {
        const { lease, secret, ttl } = renewal;
        const handle = lease.handleSealed
          ? openValue(ctx, lease.handleSealed, leaseHandleContext(lease.id))
          : undefined;
        await withTimeout(ctx, `The engine ${secret!.engine}`, () =>
          engine.renew!({
            tenantId: lease.tenantId,
            name: lease.name,
            leaseId: lease.id,
            config: secret!.engineConfig ?? {},
            ttlMs: ttl,
            ...(handle !== undefined ? { handle } : {}),
          }),
        ).catch((error: unknown) => {
          throw new IamError('ENGINE_FAILED', redactedMessage(error, [handle]), 502);
        });
      }
      return result;
    },

    /**
     * Ends a lease now: a check-out is checked in (without rotation), a dynamic lease is revoked at its engine. Holder,
     * or iam:vault:manage for anyone's. A revocation the engine refuses stays `revoking` and is retried by
     * `iam.vault.expireLeases`. Audited as `vault:revoke`.
     */
    revokeLease: async (
      credential: CredentialInput,
      input: { tenantId: string; leaseId: string },
    ): Promise<{ leaseId: string; state: VaultLease['state']; error?: string; rotated?: number }> => {
      let actor: AuthenticatedPrincipal | undefined;
      const outcome = await onLease(credential, input, 'revoke', async ({ tx, principal, lease, secret }) => {
        if (lease.state !== 'active' && lease.state !== 'revoking' && lease.state !== 'issuing')
          throw new IamError('INVALID_TRANSITION', 'This lease has already ended');
        actor = principal;
        const now = ctx.now();
        if (secret)
          await recordAccess(ctx, tx, secret, {
            ...accessEntry(principal),
            action: 'revoke',
            leaseId: lease.id,
          });
        if (lease.kind === 'checkout') {
          await tx.put<VaultLease>(vaultCollections.leases, {
            ...lease,
            state: 'ended',
            endedAt: now,
            endedBy: principal.identity.id,
          });
          return { kind: 'checkout' as const, lease };
        }
        // A lease still being issued is marked here; the issue sees it and revokes what the engine minted.
        await tx.put<VaultLease>(vaultCollections.leases, {
          ...lease,
          state: lease.state === 'issuing' ? 'ended' : 'revoking',
          endedAt: lease.endedAt ?? now,
          endedBy: lease.endedBy ?? principal.identity.id,
          ...(lease.state === 'issuing' ? {} : { endState: lease.endState ?? ('ended' as const) }),
        });
        return { kind: lease.state === 'issuing' ? ('issuing' as const) : ('dynamic' as const), lease };
      });
      const { lease } = outcome;
      if (outcome.kind === 'checkout') {
        // Ending someone's check-out is returning it: a secret that rotates on check-in rotates now too.
        const rotated = await rotateReturned(ctx, lease.tenantId, lease.secretId, actor!.identity.id, (name) =>
          principalRecorder(ctx, actor!, lease.tenantId, name),
        );
        return { leaseId: lease.id, state: 'ended', ...(rotated !== undefined ? { rotated } : {}) };
      }
      if (outcome.kind === 'issuing') return { leaseId: lease.id, state: 'ended' };
      const revoked = await revokeAndRecord(ctx, lease.id);
      return revoked.ok
        ? { leaseId: lease.id, state: 'ended' }
        : { leaseId: lease.id, state: 'revoking', error: revoked.error! };
    },

    /**
     * A secret's leases and check-outs, newest first: live ones, or all kept history with `includeEnded`. Requires
     * iam:vault:read.
     */
    listLeases: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; includeEnded?: boolean },
    ) => {
      const name = secretName(input.name);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:read',
        secretResource(name),
        async ({ tx, tenant: realm }): Promise<SecretLeaseView[]> => {
          const secret = await existingSecret(tx, realm.id, name);
          const now = ctx.now();
          const leases = (
            await tx.find<VaultLease>(vaultCollections.leases, {
              tenantId: realm.id,
              secretId: secret.id,
            })
          )
            .filter(
              (lease) =>
                input.includeEnded === true ||
                (lease.state === 'active' && lease.expiresAt > now) ||
                lease.state === 'revoking',
            )
            .sort((a, b) => b.issuedAt - a.issuedAt);
          const names = new Map<string, string>();
          for (const lease of leases)
            if (!names.has(lease.holderId)) {
              const identity = await tx.get<Identity>('identities', lease.holderId);
              if (identity) names.set(lease.holderId, identity.name);
            }
          return leases.map((lease) => leaseView(lease, names.get(lease.holderId)));
        },
      );
    },

    /** The caller's own live check-outs and leases in the tenant. Needs only a session of the tenant. */
    listMine: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<SecretLeaseView[]> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        await ctx.tenant(tx, tenantId);
        const now = ctx.now();
        return (
          await tx.find<VaultLease>(vaultCollections.leases, {
            tenantId,
            holderId: principal.identity.id,
          })
        )
          .filter((lease) => lease.state === 'active' && lease.expiresAt > now)
          .sort((a, b) => b.issuedAt - a.issuedAt)
          .map((lease) => leaseView(lease, principal.identity.name));
      });
    },

    /**
     * Who used a secret, newest first: reveals, check-outs and returns, leases, renewals, revocations, new versions
     * and rotations, kept `vault.accessRetentionDays` (default 90). At most `limit` (1-500, default 100), optionally
     * for one `identityId`. Requires iam:vault:read.
     */
    accessLog: async (
      credential: CredentialInput,
      input: { tenantId: string; name: string; identityId?: string; limit?: number },
    ) => {
      const name = secretName(input.name);
      const limit = input.limit === undefined ? 100 : integer(input.limit, 'limit', 1, 500);
      return operation(
        credential,
        input.tenantId,
        'iam:vault:read',
        secretResource(name),
        async ({ tx, tenant: realm }): Promise<SecretAccessView[]> => {
          const secret = await existingSecret(tx, realm.id, name);
          const filter: Record<string, unknown> = { tenantId: realm.id, secretId: secret.id };
          if (input.identityId !== undefined) filter.identityId = text(input.identityId, 'identityId');
          const records = await findOrdered<VaultAccessRecord>(tx, vaultCollections.access, filter, {
            field: 'at',
            direction: 'desc',
            limit,
          });
          const names = new Map<string, string>();
          for (const record of records)
            if (!names.has(record.identityId)) {
              const identity = await tx.get<Identity>('identities', record.identityId);
              if (identity) names.set(record.identityId, identity.name);
            }
          return records.map((record) => ({
            at: record.at,
            identityId: record.identityId,
            ...(names.has(record.identityId) ? { identityName: names.get(record.identityId)! } : {}),
            action: record.action,
            ...(record.version !== undefined ? { version: record.version } : {}),
            ...(record.leaseId !== undefined ? { leaseId: record.leaseId } : {}),
            ...(record.sessionKind !== undefined ? { sessionKind: record.sessionKind } : {}),
            ...(record.agentId !== undefined ? { agentId: record.agentId } : {}),
          }));
        },
      );
    },

    /**
     * A value from a generator without storing it (a password for a form, say): `length` 8-256, `charset`
     * (alphanumeric, ascii, hex, base64url, numeric), `exclude`, `eachClass`. Needs only a session.
     */
    generate: async (
      credential: CredentialInput,
      input: { generator?: Partial<PasswordGenerator> } = {},
    ): Promise<{ value: string }> => {
      await ctx.principals.authenticate(credential);
      return { value: generateValue(passwordGenerator(input.generator)) };
    },
  };
}

// --- maintenance ---------------------------------------------------------------------------------

const SCAN_PAGE = 500;

/**
 * Up to `limit` records of a collection that match `filter` and `keep`, read in keyset pages (id order), so a crowd of
 * records that do not qualify can never hide the ones that do from a job.
 */
async function scan<T extends StoredRecord>(
  store: IamStore,
  collection: string,
  filter: Record<string, unknown>,
  keep: (record: T) => boolean | Promise<boolean>,
  limit: number,
): Promise<T[]> {
  const found: T[] = [];
  let after: string | undefined;
  for (;;) {
    const page = await store.find<T>(collection, filter, {
      limit: SCAN_PAGE,
      ...(after !== undefined ? { after } : {}),
    });
    for (const record of page)
      if (await keep(record)) {
        found.push(record);
        if (found.length >= limit) return found;
      }
    if (page.length < SCAN_PAGE) return found;
    after = page.at(-1)!.id;
  }
}

/**
 * Deletes a secret with its versions, leases and access records, once every live dynamic lease has been revoked at
 * its engine: a revocation that fails keeps the secret (still pending deletion) for the next run, so no credential
 * outlives the records that could take it back. Audited as `vault:purge`.
 */
async function purgeSecret(ctx: ServerContext, secretId: string): Promise<boolean> {
  const live = await ctx.store.transaction(async (tx) => {
    const secret = await tx.get<VaultSecret>(vaultCollections.secrets, secretId);
    if (!secret || secret.status !== 'pending-deletion') return undefined;
    const leases = (
      await tx.find<VaultLease>(vaultCollections.leases, {
        tenantId: secret.tenantId,
        secretId: secret.id,
      })
    ).filter(
      (lease) =>
        lease.kind === 'dynamic' &&
        (lease.state === 'active' || lease.state === 'revoking' || lease.state === 'issuing'),
    );
    for (const lease of leases)
      if (lease.state !== 'revoking')
        await tx.put<VaultLease>(vaultCollections.leases, {
          ...lease,
          state: 'revoking',
          endedAt: lease.endedAt ?? ctx.now(),
          endedBy: lease.endedBy ?? vaultOperator,
          endState: 'ended',
        });
    return leases.map((lease) => lease.id);
  });
  if (!live) return false;
  let revoked = true;
  for (const leaseId of live) if (!(await revokeAndRecord(ctx, leaseId)).ok) revoked = false;
  if (!revoked) return false;
  return ctx.store.transaction(async (tx) => {
    const secret = await tx.get<VaultSecret>(vaultCollections.secrets, secretId);
    if (!secret || secret.status !== 'pending-deletion') return false;
    const scope = { tenantId: secret.tenantId, secretId: secret.id };
    let versions = 0;
    for (const collection of [
      vaultCollections.versions,
      vaultCollections.leases,
      vaultCollections.access,
    ])
      for (const record of await tx.find(collection, scope)) {
        await tx.delete(collection, record.id);
        if (collection === vaultCollections.versions) versions++;
      }
    await tx.delete(vaultCollections.secrets, secret.id);
    await operatorRecorder(ctx, secret.tenantId, secret.name)(tx, 'vault:purge', 'allow', {
      name: secret.name,
      versions,
    });
    return true;
  });
}

/** Trusted, credential-free access for the deployment's own code (`iam.vault`), and the vault's scheduler jobs. */
export interface IamVault {
  /**
   * A static secret's value for server code: the `current` version, or `version` / `stage`. No credential and no
   * audit event (the access log records nothing either); check-out rules do not apply. NOT_FOUND for secrets pending
   * deletion.
   */
  get(tenantId: string, name: string, options?: { version?: number; stage?: string }): Promise<RevealedSecret>;
  /**
   * Replaces every string of the form `vault://{name}` (the value) or `vault://{name}#{field}` (one field of a json
   * secret) inside a JSON value, for configuration objects. Each secret is read once per call.
   */
  resolve<T extends Json>(tenantId: string, value: T): Promise<T>;
  /**
   * Rotates every static secret whose scheduled rotation (or a retry of a failed one) is due (hourly job): generated
   * values and rotators run as `deployment-operator`; secrets with neither are recorded once per due date as
   * `vault:rotation-due`.
   */
  rotateDue(options?: { tenantId?: string; limit?: number }): Promise<VaultJobResult>;
  /**
   * Ends expired check-outs (rotating `rotateOnCheckin` secrets), revokes expired dynamic leases and those of people
   * who are no longer active at their engine, retries failed revocations with backoff for seven days, and deletes
   * lease history past `accessRetentionDays` (every few minutes).
   */
  expireLeases(options?: { limit?: number }): Promise<LeaseJobResult>;
  /** Deletes secrets whose recovery window has ended, once their dynamic leases are revoked (daily). */
  purgeDeleted(options?: { limit?: number }): Promise<{ purged: number }>;
}

export function createVaultRuntime(ctx: ServerContext): IamVault {
  // Validated now, so a bad `vault` option fails construction with INVALID_CONFIG.
  vaultSettings(ctx);
  const read = (tenantId: string, name: string, options: { version?: number; stage?: string } = {}) =>
    ctx.store.transaction(async (tx) => {
      const realm = await ctx.tenant(tx, text(tenantId, 'tenantId'));
      const secret = await findSecret(tx, realm.id, secretName(name));
      if (!secret || secret.status !== 'active')
        throw new IamError('NOT_FOUND', 'Secret not found', 404);
      staticSecret(secret);
      const version = await selectVersion(tx, secret, options);
      return revealed(secret, version, await openVersion(ctx, tx, version));
    });
  const reference = /^vault:\/\/([^#]+)(?:#(.+))?$/;
  const bounded = (value: number | undefined, fallback: number) =>
    value === undefined ? fallback : integer(value, 'limit', 1, 100_000);
  const operator = (tenantId: string) => (name: string) => operatorRecorder(ctx, tenantId, name);

  return {
    get: read,
    async resolve(tenantId, value) {
      const cache = new Map<string, Promise<RevealedSecret>>();
      const walk = async (item: Json): Promise<Json> => {
        if (typeof item === 'string') {
          const match = reference.exec(item);
          if (!match) return item;
          const name = match[1]!;
          if (!cache.has(name)) cache.set(name, read(tenantId, name));
          const secret = await cache.get(name)!;
          if (match[2] === undefined) return secret.value;
          const field = ownField(secret.fields, match[2]);
          if (field === undefined)
            throw new IamError('NOT_FOUND', `The secret ${name} has no field ${match[2]}`, 404);
          return field;
        }
        if (Array.isArray(item)) return Promise.all(item.map(walk));
        if (item && typeof item === 'object') {
          const result: Record<string, Json> = {};
          for (const [key, entry] of Object.entries(item)) result[key] = await walk(entry);
          return result;
        }
        return item;
      };
      return (await walk(value)) as never;
    },
    async rotateDue(options = {}) {
      const limit = bounded(options.limit, 1000);
      const now = ctx.now();
      const result: VaultJobResult = { rotated: [], failed: [], reminded: [] };
      const filter =
        options.tenantId === undefined ? {} : { tenantId: text(options.tenantId, 'tenantId') };
      const due = (await ctx.store.find<VaultSecret>(vaultCollections.secrets, filter))
        .filter(
          (secret) =>
            secret.status === 'active' &&
            secret.kind === 'static' &&
            secret.rotation?.nextRotationAt !== undefined &&
            secret.rotation.nextRotationAt <= now,
        )
        .sort((a, b) => a.rotation!.nextRotationAt! - b.rotation!.nextRotationAt!)
        .slice(0, limit);
      for (const candidate of due) {
        // Rotations the vault can run itself: a generator, a rotator, or a check-out return that failed to rotate.
        const automatic =
          candidate.rotation!.generator ||
          candidate.rotation!.rotator ||
          candidate.checkout?.rotateOnCheckin;
        if (!automatic) {
          const reminded = await ctx.store.transaction(async (tx) => {
            const secret = await tx.get<VaultSecret>(vaultCollections.secrets, candidate.id);
            const rotation = secret?.rotation;
            if (!secret || !rotation?.nextRotationAt || rotation.nextRotationAt > now) return false;
            if ((rotation.dueNotifiedAt ?? 0) >= rotation.nextRotationAt) return false;
            await tx.put<VaultSecret>(vaultCollections.secrets, {
              ...secret,
              rotation: { ...rotation, dueNotifiedAt: now },
            });
            await operatorRecorder(ctx, secret.tenantId, secret.name)(
              tx,
              'vault:rotation-due',
              'allow',
              { name: secret.name, dueAt: rotation.nextRotationAt },
            );
            return true;
          });
          if (reminded) result.reminded.push({ tenantId: candidate.tenantId, name: candidate.name });
          continue;
        }
        try {
          const staged = await ctx.store.transaction(async (tx) => {
            const secret = await tx.get<VaultSecret>(vaultCollections.secrets, candidate.id);
            if (
              !secret ||
              secret.status !== 'active' ||
              secret.rotation?.nextRotationAt === undefined ||
              secret.rotation.nextRotationAt > now
            )
              return undefined;
            // A shared credential that is checked out rotates when it comes back, not under its holder.
            if (
              secret.checkout?.rotateOnCheckin &&
              (await liveLeases(ctx, tx, secret)).some((lease) => lease.kind === 'checkout')
            )
              return undefined;
            return stageRotation(ctx, tx, secret, vaultOperator);
          });
          if (!staged) continue;
          const outcome = await completeRotation(
            ctx,
            staged,
            vaultOperator,
            operatorRecorder(ctx, staged.tenantId, staged.name),
          );
          if (outcome.ok)
            result.rotated.push({
              tenantId: staged.tenantId,
              name: staged.name,
              version: outcome.result.version,
            });
          else
            result.failed.push({
              tenantId: staged.tenantId,
              name: staged.name,
              message: outcome.message,
            });
        } catch (error) {
          // Refused before the rotator ran (a json secret without rotation.field, say): recorded and retried later.
          const message = redactedMessage(error, []);
          await ctx.store
            .transaction(async (tx) => {
              const secret = await tx.get<VaultSecret>(vaultCollections.secrets, candidate.id);
              if (!secret || secret.status !== 'active') return;
              await recordRotationFailure(ctx, tx, secret, message);
              await operatorRecorder(ctx, secret.tenantId, secret.name)(tx, 'vault:rotate', 'deny', {
                name: secret.name,
                error: message,
              });
            })
            .catch(() => undefined);
          result.failed.push({ tenantId: candidate.tenantId, name: candidate.name, message });
        }
      }
      return result;
    },
    async expireLeases(options = {}) {
      const limit = bounded(options.limit, 1000);
      const now = ctx.now();
      const result: LeaseJobResult = { expired: 0, retrying: 0, abandoned: 0, pruned: 0, rotated: 0 };
      const candidates: VaultLease[] = [
        ...(await findOrdered<VaultLease>(
          ctx.store,
          vaultCollections.leases,
          { state: 'active' },
          { field: 'expiresAt', to: now, limit },
        )),
        ...(await scan<VaultLease>(
          ctx.store,
          vaultCollections.leases,
          { state: 'revoking' },
          (lease) => (lease.retryAt ?? 0) <= now,
          limit,
        )),
        ...(await scan<VaultLease>(
          ctx.store,
          vaultCollections.leases,
          { state: 'issuing' },
          (lease) => lease.issuedAt <= now - 10 * MINUTE,
          limit,
        )),
      ];
      // Live leases whose holder may no longer have them end too: a person or agent who is no longer active, an agent
      // whose sponsor left, and a lease an agent took for a person under a delegation that has ended. Every active
      // lease is looked at, however many there are; at most `limit` of them end per run.
      const verdicts = new Map<string, Promise<boolean>>();
      const cached = (key: string, check: () => Promise<boolean>) => {
        if (!verdicts.has(key)) verdicts.set(key, check());
        return verdicts.get(key)!;
      };
      const mayAct = (identityId: string) =>
        cached(`identity:${identityId}`, async () => {
          const identity = await ctx.store.get<Identity>('identities', identityId);
          if (!identity || identity.status !== 'active' || ctx.identityExpired(identity)) return false;
          return identity.kind !== 'agent' || (await agentStanding(ctx, ctx.store, identity)) === 'ok';
        });
      const delegationStands = (delegationId: string) =>
        cached(`delegation:${delegationId}`, async () => {
          const delegation = await ctx.store.get<Delegation>('delegations', delegationId);
          return Boolean(
            delegation &&
              delegationLive(delegation, now) &&
              (await delegationAncestors(ctx.store, delegation, now)) !== undefined,
          );
        });
      candidates.push(
        ...(await scan<VaultLease>(
          ctx.store,
          vaultCollections.leases,
          { state: 'active' },
          async (lease) =>
            lease.expiresAt > now &&
            !(
              (await mayAct(lease.holderId)) &&
              (lease.agentId === undefined || (await mayAct(lease.agentId))) &&
              (lease.delegationId === undefined || (await delegationStands(lease.delegationId)))
            ),
          limit,
        )),
      );
      const seen = new Set<string>();
      for (const candidate of candidates) {
        if (seen.has(candidate.id)) continue;
        seen.add(candidate.id);
        if (candidate.state === 'issuing') {
          // An issue that never finished (the process stopped): whatever the engine minted is revoked by id.
          if (candidate.issuedAt > now - 10 * MINUTE) continue;
          const marked = await ctx.store.transaction(async (tx) => {
            const lease = await tx.get<VaultLease>(vaultCollections.leases, candidate.id);
            if (lease?.state !== 'issuing') return false;
            await tx.put<VaultLease>(vaultCollections.leases, {
              ...lease,
              state: 'revoking',
              endedAt: now,
              endedBy: vaultOperator,
              endState: 'failed',
              lastError: 'The issue never completed',
            });
            return true;
          });
          if (!marked) continue;
          if ((await revokeAndRecord(ctx, candidate.id)).ok) result.expired++;
          else result.retrying++;
          continue;
        }
        if (candidate.kind === 'checkout') {
          const ended = await ctx.store.transaction(async (tx) => {
            const lease = await tx.get<VaultLease>(vaultCollections.leases, candidate.id);
            if (!lease || lease.state !== 'active') return false;
            await tx.put<VaultLease>(vaultCollections.leases, {
              ...lease,
              state: 'expired',
              endedAt: now,
              endedBy: vaultOperator,
            });
            await operatorRecorder(ctx, lease.tenantId, lease.name)(
              tx,
              'vault:checkout-expired',
              'allow',
              { name: lease.name, leaseId: lease.id, holderId: lease.holderId },
            );
            return true;
          });
          if (!ended) continue;
          result.expired++;
          if (
            (await rotateReturned(
              ctx,
              candidate.tenantId,
              candidate.secretId,
              vaultOperator,
              operator(candidate.tenantId),
            )) !== undefined
          )
            result.rotated++;
          continue;
        }
        // Dynamic: mark the revocation (an expiry, or the end for a holder who left), then revoke at the engine.
        const lease = await ctx.store.transaction(async (tx) => {
          const current = await tx.get<VaultLease>(vaultCollections.leases, candidate.id);
          if (!current || (current.state !== 'active' && current.state !== 'revoking'))
            return undefined;
          if (current.state === 'active')
            return tx.put<VaultLease>(vaultCollections.leases, {
              ...current,
              state: 'revoking',
              endedAt: now,
              endedBy: vaultOperator,
              endState: current.expiresAt <= now ? 'expired' : 'ended',
            });
          // Given up after seven days of refusals: recorded, so someone revokes it by hand.
          if (current.revokeStartedAt !== undefined && now - current.revokeStartedAt > REVOKE_PATIENCE_MS) {
            await tx.put<VaultLease>(vaultCollections.leases, {
              ...current,
              state: 'failed',
              endedAt: current.endedAt ?? now,
            });
            await operatorRecorder(ctx, current.tenantId, current.name)(
              tx,
              'vault:revoke-failed',
              'deny',
              { name: current.name, leaseId: current.id, error: current.lastError ?? 'unknown' },
            );
            result.abandoned++;
            return undefined;
          }
          return current;
        });
        if (!lease) continue;
        const outcome = await revokeAndRecord(ctx, lease.id);
        if (!outcome.ok) {
          result.retrying++;
          continue;
        }
        result.expired++;
        await ctx.store.transaction((tx) =>
          operatorRecorder(ctx, lease.tenantId, lease.name)(tx, 'vault:lease-expired', 'allow', {
            name: lease.name,
            leaseId: lease.id,
            holderId: lease.holderId,
          }),
        );
      }
      // Lease history past the access retention.
      const cutoff = now - vaultSettings(ctx).accessRetentionMs;
      for (const state of ['ended', 'expired', 'failed'] as const)
        for (const lease of await scan<VaultLease>(
          ctx.store,
          vaultCollections.leases,
          { state },
          (lease) => (lease.endedAt ?? lease.expiresAt) < cutoff,
          limit,
        )) {
          await ctx.store.transaction((tx) => tx.delete(vaultCollections.leases, lease.id));
          result.pruned++;
        }
      return result;
    },
    async purgeDeleted(options = {}) {
      const limit = bounded(options.limit, 1000);
      const now = ctx.now();
      let purged = 0;
      const due = (
        await ctx.store.find<VaultSecret>(vaultCollections.secrets, { status: 'pending-deletion' })
      )
        .filter((secret) => (secret.deletionAt ?? 0) <= now)
        .slice(0, limit);
      for (const secret of due) if (await purgeSecret(ctx, secret.id)) purged++;
      return { purged };
    },
  };
}
