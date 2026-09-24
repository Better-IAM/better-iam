import { randomBytes } from 'node:crypto';
import {
  IamError,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { createGuard, type GuardCall, type GuardTarget } from '../guarded.js';
import {
  MAX_ALIASES_PER_KEY,
  MAX_GRANTS_PER_KEY,
  MAX_KEYS_PER_TENANT,
  MAX_MESSAGE_BYTES,
  MAX_PLAINTEXT_BYTES,
  MAX_VERSIONS,
  addKeyVersion,
  aliasNames,
  aliasPattern,
  assertUsable,
  base64Bytes,
  decryptWith,
  encryptWith,
  encryptionContext,
  findKey,
  grantConstraints,
  grantOperationOf,
  grantOperations,
  keyAlgorithms,
  keyAttributes,
  keySpec,
  keySpecs,
  keyTags,
  keyUsageFor,
  keyVersion,
  kmsActions,
  actsInOwnRight,
  assertUnmanaged,
  candidateGrants,
  macWith,
  parseCiphertext,
  parseKid,
  payload,
  publicJwk,
  requestAttributes,
  sameBytes,
  signWith,
  signingAlgorithm,
  summarizeGrant,
  summarizeKey,
  verifyWith,
  fingerprint,
  type EncryptionContext,
  type GrantConstraints,
  type GrantOperation,
  type GrantSummary,
  type KeySpec,
  type KeyState,
  type KeySummary,
  type KeyUsage,
  type KmsAlias,
  type KmsGrant,
  type KmsKey,
  type KmsKeyVersion,
  type SignatureFormat,
} from '../kms.js';
import type { Group } from '../models.js';
import { OperationDenied } from '../operations.js';
import { id } from '../utils.js';
import { integer, object, text } from '../validation.js';

const DAY = 86_400_000;

interface KeyTarget extends GuardTarget {
  /** The audited resource: `kms` (the tenant's key collection) or `kms/{keyId}`. */
  resourceId: string;
  key?: KmsKey;
  aliases?: string[];
  /** The call's encryption context, for context-constrained grants. */
  context?: EncryptionContext;
}

export interface KeyCreateInput {
  tenantId: string;
  /** Default `aes-256-gcm` (symmetric encryption). */
  keySpec?: KeySpec;
  /** Required for RSA keys (`encrypt` or `sign`); every other spec has exactly one usage. */
  keyUsage?: KeyUsage;
  description?: string;
  tags?: Record<string, string>;
  /** Rotate automatically every so many days (1-3650); `iam.kms.maintain()` performs it. */
  rotationPeriodDays?: number;
  /** Also create this alias (`alias/{name}`) for the key. */
  alias?: string;
}

export interface KeyVersionSummary {
  version: number;
  current: boolean;
  origin: KmsKeyVersion['origin'];
  createdAt: number;
  /** Asymmetric keys: a short fingerprint of the public key. */
  publicKeyFingerprint?: string;
}

export interface PublicKeyView {
  keyId: string;
  keyVersion: number;
  keySpec: KeySpec;
  keyUsage: KeyUsage;
  algorithms: string[];
  publicKeyPem: string;
  jwk: Record<string, unknown>;
}

export interface AliasSummary {
  name: string;
  keyId: string;
  createdAt: number;
  updatedAt: number;
}

export interface KeyMaintenanceResult {
  rotated: Array<{ tenantId: string; keyId: string; keyVersion: number }>;
  destroyed: Array<{ tenantId: string; keyId: string }>;
  /** Grants removed because they lapsed or their grantee is gone. */
  grantsRemoved: number;
}

export type JwtVerification =
  | {
      valid: true;
      keyId: string;
      keyVersion: number;
      algorithm: string;
      header: Record<string, unknown>;
      claims: Record<string, unknown>;
    }
  | {
      valid: false;
      reason:
        | 'signature'
        | 'expired'
        | 'not-yet-valid'
        | 'audience'
        | 'issuer'
        | 'algorithm'
        | 'header'
        | 'claims';
      keyId: string;
      keyVersion: number;
    };

const optionalText = (value: unknown, name: string, max: number) =>
  value === undefined ? undefined : text(value, name, max).trim();

function aliasName(value: unknown): string {
  const name = text(value, 'alias', 256);
  if (!aliasPattern.test(name))
    throw new IamError(
      'INVALID_INPUT',
      'alias must be alias/{name} with letters, digits, slashes, underscores or hyphens',
    );
  return name;
}

function rotationPeriod(value: unknown): number | undefined {
  if (value === undefined || value === null) return undefined;
  return integer(value, 'rotationPeriodDays', 1, 3650);
}

const signatureFormat = (value: unknown): SignatureFormat => {
  if (value === undefined) return 'der';
  if (value !== 'der' && value !== 'jose')
    throw new IamError('INVALID_INPUT', 'format must be der or jose');
  return value;
};

const b64url = (value: Uint8Array | string) => Buffer.from(value).toString('base64url');

/**
 * The algorithm a signing call asks for, as `resource.algorithm`: the key's default when none is named, otherwise the
 * name itself (bounded). It is validated against the key only once the call is authorized, so callers without
 * access learn nothing about the key.
 */
function requestedAlgorithm(key: KmsKey, value: unknown): string {
  if (value === undefined) return keyAlgorithms(key)[0] ?? 'none';
  return typeof value === 'string' && /^[A-Za-z0-9]{1,16}$/.test(value) ? value : 'invalid';
}

/** What a token names, as `resource.jwt.*`, so policies can limit the tokens a caller mints. */
function jwtAttributes(claims: Record<string, unknown>, type: string): Record<string, unknown> {
  const attributes: Record<string, unknown> = { jwt: true, 'jwt.typ': type };
  for (const name of ['sub', 'iss'] as const)
    if (typeof claims[name] === 'string') attributes[`jwt.${name}`] = claims[name];
  if (typeof claims.aud === 'string') attributes['jwt.aud'] = claims.aud;
  else if (Array.isArray(claims.aud))
    attributes['jwt.audiences'] = claims.aud.filter((item) => typeof item === 'string').sort();
  return attributes;
}

function jsonSegment(value: string, name: string): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(Buffer.from(value, 'base64url').toString('utf8'));
    return object(parsed);
  } catch {
    throw new IamError('INVALID_INPUT', `The token ${name} is not valid JSON`);
  }
}

/**
 * Key management (KMS). Keys belong to a tenant and are addressed by id or `alias/{name}`; policies name them as
 * `iam/kms/{keyId}` and may condition on `resource.keySpec`, `resource.keyUsage`, `resource.keyState`,
 * `resource.aliases`, `resource.tags.{key}`, `resource.encryptionContext.{key}` / `resource.encryptionContextKeys`
 * and, for signatures, `resource.algorithm`. Every call is authorized and audited (actions `iam:kms:*`, resource
 * `kms/{keyId}`, never the plaintext); a key grant allows named operations to one identity or group when no policy
 * does, within the caller's boundaries. Sessions viewing as someone else ("impersonation") are refused.
 */
export function createKeysApi(ctx: ServerContext) {
  /**
   * The envelope of every KMS call (guarded.ts): authenticate, locate the key, decide, run, audit. A key grant
   * stands in for a policy grant only when nothing denied the call and every boundary allowed it; a ciphertext that
   * fails to decrypt after the call was authorized is audited as a denied call.
   */
  const guard = createGuard<KeyTarget>(ctx, 'kms', {
    fallback: async (tx, principal, action, target) => {
      const operation = grantOperationOf[action];
      if (!operation || !target.key) return undefined;
      for (const grant of await candidateGrants(
        ctx,
        tx,
        target.key,
        principal,
        operation,
        target.context,
      ))
        if (await creatorStillAllowed(tx, grant, action, target)) return { grantId: grant.id };
      return undefined;
    },
    describe: (target) => ({
      ...(target.key ? { keyId: target.key.id } : {}),
      ...(target.context && Object.keys(target.context).length
        ? { encryptionContext: { ...target.context } }
        : {}),
    }),
    recordedFailures: {
      INVALID_CIPHERTEXT: 'invalid-ciphertext',
      KEY_STATE_INVALID: 'key-state',
      KEY_MANAGED: 'key-managed',
    },
    // Plugins see which key and version served a call, never plaintexts, data keys or signed tokens.
    hookResult: (value) => {
      if (!value || typeof value !== 'object') return value;
      const { plaintext, plaintextBase64, token, ...rest } = value as Record<string, unknown>;
      void plaintext;
      void plaintextBase64;
      void token;
      return rest;
    },
  });
  const keyOperation = guard.run;

  /**
   * A grant works only while its creator could make the same call now, with the same key attributes and encryption
   * context: an expired binding, a revoked role, a lapsed activation or a deny added later takes the grant down with
   * it. The creator is evaluated as a plain session of their own (no MFA, no session tags), which fails closed for
   * policies that need more.
   */
  async function creatorStillAllowed(
    tx: IamStore,
    grant: KmsGrant,
    action: string,
    target: KeyTarget,
  ): Promise<boolean> {
    const creator = await tx.get<Identity>('identities', grant.createdBy);
    if (
      !creator ||
      creator.tenantId !== grant.tenantId ||
      creator.status !== 'active' ||
      ctx.identityExpired(creator)
    )
      return false;
    const tenant = await ctx.tenant(tx, grant.tenantId);
    return (
      await guard.decide(
        tx,
        ctx.decisions.simulatedPrincipal(creator),
        tenant,
        action,
        target,
        false,
      )
    ).allowed;
  }

  /**
   * Alias names are a namespace of their own: creating, moving or removing `alias/{name}` also needs iam:kms:update
   * on `iam/kms/alias/{name}` (`resource.alias`), so whoever manages one key cannot claim a name others rely on.
   */
  async function assertAliasAllowed(call: GuardCall<KeyTarget>, name: string) {
    if (
      !(await call.allowed(kmsActions.update, {
        resourceId: `kms/${name}`,
        attributes: { alias: name },
      }))
    )
      throw new OperationDenied(`You may not manage the alias ${name}`);
  }

  /**
   * Changing what a key looks like to policies (its tags, its aliases) must not hand the caller rights on it: every
   * KMS action they may not take on the key as it is stays refused on the key as it would be. Otherwise someone who
   * manages every key but may decrypt only one team's could retag a key into that team, or drop the alias a deny
   * names.
   */
  async function assertNoNewRights(
    call: GuardCall<KeyTarget>,
    key: KmsKey,
    before: { tags: Record<string, string>; aliases: string[] },
    after: { tags: Record<string, string>; aliases: string[] },
  ) {
    const target = (view: { tags: Record<string, string>; aliases: string[] }) => ({
      resourceId: `kms/${key.id}`,
      attributes: keyAttributes({ ...key, tags: view.tags }, view.aliases),
    });
    for (const action of Object.values(kmsActions)) {
      if (action === kmsActions.create) continue;
      if (
        !(await call.allowed(action, target(before))) &&
        (await call.allowed(action, target(after)))
      )
        throw new OperationDenied(`That change would give you ${action} on this key`);
    }
  }

  /** Locates a key (id or alias) with its aliases and policy attributes. */
  const keyTarget =
    (
      tenantId: string,
      reference: unknown,
      extra: { context?: EncryptionContext; algorithm?: string } = {},
    ) =>
    async (tx: IamStore): Promise<KeyTarget> => {
      const key = await findKey(tx, text(tenantId, 'tenantId'), reference);
      const aliases = await aliasNames(tx, key);
      return {
        resourceId: `kms/${key.id}`,
        attributes: keyAttributes(key, aliases, extra),
        key,
        aliases,
        ...(extra.context ? { context: extra.context } : {}),
      };
    };
  const tenantTarget = async (): Promise<KeyTarget> => ({ resourceId: 'kms', attributes: {} });

  async function saveKey(tx: IamStore, key: KmsKey, changes: Partial<KmsKey>): Promise<KmsKey> {
    const next: KmsKey = { ...key, ...changes, updatedAt: ctx.now() };
    for (const [name, value] of Object.entries(changes))
      if (value === undefined) delete (next as Record<string, unknown>)[name];
    await tx.put('kmsKeys', next);
    return next;
  }

  async function rotateKey(
    tx: IamStore,
    key: KmsKey,
    origin: KmsKeyVersion['origin'],
  ): Promise<KmsKey> {
    if (key.currentVersion >= MAX_VERSIONS)
      throw new IamError('LIMIT_EXCEEDED', `A key keeps at most ${MAX_VERSIONS} versions`, 409);
    const version = key.currentVersion + 1;
    await addKeyVersion(ctx, tx, key, version, origin);
    const now = ctx.now();
    return saveKey(tx, key, {
      currentVersion: version,
      lastRotatedAt: now,
      ...(key.rotationPeriodDays !== undefined
        ? { nextRotationAt: now + key.rotationPeriodDays * DAY }
        : {}),
    });
  }

  function stateChange(key: KmsKey, allowedFrom: KeyState[], verb: string) {
    if (!allowedFrom.includes(key.state))
      throw new IamError(
        'KEY_STATE_INVALID',
        `A key that is ${key.state.replace('-', ' ')} cannot be ${verb}`,
        409,
      );
  }

  // ---- Crypto internals shared by the public calls (reEncrypt uses two of them) ------------------------------

  async function encryptCall(
    credential: CredentialInput,
    tenantId: string,
    keyRef: unknown,
    plaintext: Buffer,
    isText: boolean,
    context: EncryptionContext,
    note: Record<string, Json> = {},
  ) {
    return keyOperation(
      credential,
      tenantId,
      kmsActions.encrypt,
      keyTarget(tenantId, keyRef, { context }),
      async ({ tx, metadata }, { key }) => {
        assertUsable(key!, 'encrypt');
        assertUnmanaged(key!);
        const version = await keyVersion(tx, key!, key!.currentVersion);
        Object.assign(metadata, note, { keyVersion: version.version });
        return {
          ciphertext: encryptWith(ctx, key!, version, plaintext, isText, context),
          keyId: key!.id,
          keyVersion: version.version,
        };
      },
    );
  }

  async function decryptCall(
    credential: CredentialInput,
    tenantId: string,
    ciphertext: unknown,
    context: EncryptionContext,
    expectedKey?: unknown,
    note: Record<string, Json> = {},
  ) {
    const parsed = parseCiphertext(ciphertext);
    return keyOperation(
      credential,
      tenantId,
      kmsActions.decrypt,
      async (tx) => {
        const target = await keyTarget(tenantId, parsed.keyId, { context })(tx);
        if (expectedKey !== undefined) {
          const expected = await findKey(tx, tenantId, expectedKey);
          if (expected.id !== target.key!.id)
            throw new IamError(
              'INVALID_CIPHERTEXT',
              'The ciphertext was not produced by that key',
              400,
            );
        }
        return target;
      },
      async ({ tx, metadata }, { key }) => {
        assertUsable(key!, 'encrypt');
        assertUnmanaged(key!);
        const version = await keyVersion(tx, key!, parsed.version).catch(() => {
          throw new IamError('INVALID_CIPHERTEXT', 'The ciphertext is not valid', 400);
        });
        Object.assign(metadata, note, { keyVersion: version.version });
        return {
          plaintext: decryptWith(ctx, key!, version, parsed, context),
          text: parsed.text,
          keyId: key!.id,
          keyVersion: version.version,
        };
      },
    );
  }

  return {
    /**
     * Creates a key: `aes-256-gcm` (default; encrypt/decrypt and data keys), `hmac-sha256|384|512` (MACs),
     * `ecc-p256|p384` and `ed25519` (signatures), or `rsa-2048|3072|4096` with `keyUsage` `encrypt` (RSA-OAEP) or
     * `sign` (PS256-PS512, RS256-RS512). Policies can require request tags or specs through `resource.tags.{key}`,
     * `resource.keySpec` and `resource.keyUsage`. Requires iam:kms:create on `iam/kms`; audited as `iam:kms:create`.
     */
    async create(credential: CredentialInput, input: KeyCreateInput): Promise<KeySummary> {
      const spec = keySpec(input.keySpec ?? 'aes-256-gcm');
      const usage = keyUsageFor(spec, input.keyUsage);
      const tags = keyTags(input.tags);
      const description = optionalText(input.description, 'description', 512);
      const period = rotationPeriod(input.rotationPeriodDays);
      const alias = input.alias === undefined ? undefined : aliasName(input.alias);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.create,
        async () => ({ resourceId: 'kms', attributes: requestAttributes(spec, usage, tags) }),
        async (call) => {
          const { tx, principal, tenant, metadata } = call;
          if (alias) await assertAliasAllowed(call, alias);
          const existing = await tx.find<KmsKey>('kmsKeys', { tenantId: tenant.id });
          if (existing.length >= MAX_KEYS_PER_TENANT)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant keeps at most ${MAX_KEYS_PER_TENANT} keys`,
              409,
            );
          if (
            alias &&
            (await tx.find<KmsAlias>('kmsAliases', { tenantId: tenant.id, uniqueKey: alias }))
              .length
          )
            throw new IamError('CONFLICT', 'That alias is already in use', 409);
          const now = ctx.now();
          const key: KmsKey = {
            id: id(),
            tenantId: tenant.id,
            keySpec: spec,
            keyUsage: usage,
            state: 'enabled',
            currentVersion: 1,
            tags,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
          };
          if (description) key.description = description;
          if (period !== undefined) {
            key.rotationPeriodDays = period;
            key.nextRotationAt = now + period * DAY;
          }
          await tx.insert('kmsKeys', key);
          await addKeyVersion(ctx, tx, key, 1, 'create');
          if (alias)
            await tx.insert<KmsAlias>('kmsAliases', {
              id: id(),
              tenantId: tenant.id,
              uniqueKey: alias,
              name: alias,
              keyId: key.id,
              createdAt: now,
              createdBy: principal.identity.id,
              updatedAt: now,
            });
          Object.assign(metadata, {
            keyId: key.id,
            keySpec: spec,
            keyUsage: usage,
            ...(alias ? { alias } : {}),
          });
          return summarizeKey(key, alias ? [alias] : []);
        },
      );
    },

    /**
     * The tenant's keys the caller may read (`iam:kms:read`, evaluated per key so tag-scoped readers see theirs),
     * newest first, optionally only one `state` or `keyUsage`. Never material.
     */
    async list(
      credential: CredentialInput,
      input: {
        tenantId: string;
        state?: KeyState;
        keyUsage?: KeyUsage;
        limit?: number;
        offset?: number;
      },
    ): Promise<{ keys: KeySummary[]; total: number }> {
      const tenantId = text(input.tenantId, 'tenantId');
      const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
      const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
      if (
        input.state !== undefined &&
        !['enabled', 'disabled', 'pending-deletion'].includes(input.state)
      )
        throw new IamError('INVALID_INPUT', 'Invalid state');
      if (input.keyUsage !== undefined && !['encrypt', 'sign', 'mac'].includes(input.keyUsage))
        throw new IamError('INVALID_INPUT', 'Invalid keyUsage');
      const keys = await guard.visible(
        credential,
        tenantId,
        kmsActions.read,
        'kms',
        async (tx, tenant) => {
          const aliases = new Map<string, string[]>();
          for (const alias of await tx.find<KmsAlias>('kmsAliases', { tenantId: tenant.id }))
            aliases.set(alias.keyId, [...(aliases.get(alias.keyId) ?? []), alias.name]);
          return (await tx.find<KmsKey>('kmsKeys', { tenantId: tenant.id }))
            .filter(
              (key) =>
                (input.state === undefined || key.state === input.state) &&
                (input.keyUsage === undefined || key.keyUsage === input.keyUsage),
            )
            .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : 1))
            .map((key) => {
              const names = aliases.get(key.id) ?? [];
              return {
                item: summarizeKey(key, names),
                target: { resourceId: `kms/${key.id}`, attributes: keyAttributes(key, names) },
              };
            });
        },
      );
      return { keys: keys.slice(offset, offset + limit), total: keys.length };
    },

    /** One key by id or alias. Requires iam:kms:read (or a grant allowing `read`). */
    async get(
      credential: CredentialInput,
      input: { tenantId: string; keyId: string },
    ): Promise<KeySummary> {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.read,
        keyTarget(input.tenantId, input.keyId),
        async (_call, { key, aliases }) => summarizeKey(key!, aliases!),
      );
    },

    /** The key's versions, newest first, with the public key fingerprint of asymmetric ones. Requires iam:kms:read. */
    async listVersions(
      credential: CredentialInput,
      input: { tenantId: string; keyId: string },
    ): Promise<KeyVersionSummary[]> {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.read,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx }, { key }) =>
          (
            await tx.find<KmsKeyVersion>('kmsKeyVersions', {
              tenantId: key!.tenantId,
              keyId: key!.id,
            })
          )
            .sort((a, b) => b.version - a.version)
            .map((version) => ({
              version: version.version,
              current: version.version === key!.currentVersion,
              origin: version.origin,
              createdAt: version.createdAt,
              ...(version.publicKeyPem
                ? { publicKeyFingerprint: fingerprint(version.publicKeyPem) }
                : {}),
            })),
      );
    },

    /**
     * Changes the description, replaces the tags, or sets (`null` clears) the automatic rotation period. New tags
     * must leave the caller able to manage the key: iam:kms:update is evaluated again with them, so a tag-scoped
     * administrator cannot move a key out of their reach or into another team's. Requires iam:kms:update.
     */
    async update(
      credential: CredentialInput,
      input: {
        tenantId: string;
        keyId: string;
        description?: string | null;
        tags?: Record<string, string>;
        rotationPeriodDays?: number | null;
      },
    ): Promise<KeySummary> {
      const description =
        input.description === null ? null : optionalText(input.description, 'description', 512);
      const tags = input.tags === undefined ? undefined : keyTags(input.tags);
      const period =
        input.rotationPeriodDays === null ? null : rotationPeriod(input.rotationPeriodDays);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.update,
        keyTarget(input.tenantId, input.keyId),
        async (call, { key, aliases }) => {
          if (key!.state === 'pending-deletion')
            stateChange(key!, ['enabled', 'disabled'], 'updated');
          const changes: Partial<KmsKey> = {};
          if (description === null) changes.description = undefined;
          else if (description !== undefined) changes.description = description;
          if (tags) {
            const moved = { ...key!, tags };
            if (
              !(await call.allowed(kmsActions.update, {
                resourceId: `kms/${key!.id}`,
                attributes: keyAttributes(moved, aliases!),
                key: moved,
              }))
            )
              throw new OperationDenied('Those tags would take the key out of your reach');
            await assertNoNewRights(
              call,
              key!,
              { tags: key!.tags, aliases: aliases! },
              { tags, aliases: aliases! },
            );
            changes.tags = tags;
            call.metadata.tags = Object.keys(tags).sort();
          }
          if (period === null) {
            changes.rotationPeriodDays = undefined;
            changes.nextRotationAt = undefined;
          } else if (period !== undefined) {
            changes.rotationPeriodDays = period;
            changes.nextRotationAt = ctx.now() + period * DAY;
            call.metadata.rotationPeriodDays = period;
          }
          return summarizeKey(await saveKey(call.tx, key!, changes), aliases!);
        },
      );
    },

    /** Enables a disabled key. Requires iam:kms:update. */
    async enable(credential: CredentialInput, input: { tenantId: string; keyId: string }) {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.update,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx, metadata }, { key, aliases }) => {
          stateChange(key!, ['enabled', 'disabled'], 'enabled');
          metadata.state = 'enabled';
          return summarizeKey(await saveKey(tx, key!, { state: 'enabled' }), aliases!);
        },
      );
    },

    /**
     * Disables a key: every cryptographic call with it is refused (`KEY_STATE_INVALID`) until it is enabled again,
     * which makes everything encrypted under it unreadable meanwhile. Requires iam:kms:update.
     */
    async disable(credential: CredentialInput, input: { tenantId: string; keyId: string }) {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.update,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx, metadata }, { key, aliases }) => {
          stateChange(key!, ['enabled', 'disabled'], 'disabled');
          metadata.state = 'disabled';
          return summarizeKey(await saveKey(tx, key!, { state: 'disabled' }), aliases!);
        },
      );
    },

    /**
     * Rotates on demand: new material becomes the current version for encrypting, signing and MACs; older versions
     * keep decrypting and verifying. Requires iam:kms:update; enabled keys only.
     */
    async rotate(credential: CredentialInput, input: { tenantId: string; keyId: string }) {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.update,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx, metadata }, { key, aliases }) => {
          stateChange(key!, ['enabled'], 'rotated');
          // Each version is new key material (RSA generation is slow): ten on-demand rotations a day per key.
          const recent = (
            await tx.find<KmsKeyVersion>('kmsKeyVersions', {
              tenantId: key!.tenantId,
              keyId: key!.id,
              origin: 'rotate',
            })
          ).filter((version) => version.createdAt > ctx.now() - DAY);
          if (recent.length >= 10)
            throw new IamError(
              'RATE_LIMITED',
              'A key rotates on demand at most ten times a day',
              429,
            );
          const rotated = await rotateKey(tx, key!, 'rotate');
          metadata.rotated = true;
          metadata.keyVersion = rotated.currentVersion;
          return summarizeKey(rotated, aliases!);
        },
      );
    },

    /**
     * Schedules destruction after a waiting period (7-30 days, default 30). Meanwhile the key is unusable and the
     * deletion can be cancelled; afterwards `iam.kms.maintain()` destroys its material, aliases and grants, and
     * nothing encrypted under it can be decrypted again. Requires iam:kms:delete and recent authentication.
     */
    async scheduleDeletion(
      credential: CredentialInput,
      input: { tenantId: string; keyId: string; waitingDays?: number },
    ) {
      const waitingDays = integer(input.waitingDays ?? 30, 'waitingDays', 7, 30);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.delete,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx, principal, metadata }, { key, aliases }) => {
          ctx.auth.requireRecent(principal);
          stateChange(key!, ['enabled', 'disabled'], 'scheduled for deletion');
          const deletionDate = ctx.now() + waitingDays * DAY;
          metadata.deletionDate = deletionDate;
          return summarizeKey(
            await saveKey(tx, key!, { state: 'pending-deletion', deletionDate }),
            aliases!,
          );
        },
      );
    },

    /** Cancels a scheduled deletion; the key comes back disabled. Requires iam:kms:delete. */
    async cancelDeletion(credential: CredentialInput, input: { tenantId: string; keyId: string }) {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.delete,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx, metadata }, { key, aliases }) => {
          stateChange(key!, ['pending-deletion'], 'restored');
          metadata.cancelled = true;
          return summarizeKey(
            await saveKey(tx, key!, { state: 'disabled', deletionDate: undefined }),
            aliases!,
          );
        },
      );
    },

    /**
     * Names a key `alias/{name}` (unique in the tenant, at most 50 per key). Requires iam:kms:update on the key and on
     * `iam/kms/alias/{name}`.
     */
    async createAlias(
      credential: CredentialInput,
      input: { tenantId: string; alias: string; keyId: string },
    ): Promise<AliasSummary> {
      const name = aliasName(input.alias);
      if (typeof input.keyId === 'string' && input.keyId.startsWith('alias/'))
        throw new IamError('INVALID_INPUT', 'keyId must be a key id, not an alias');
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.update,
        keyTarget(input.tenantId, input.keyId),
        async (call, { key, aliases }) => {
          const { tx, principal, tenant, metadata } = call;
          await assertAliasAllowed(call, name);
          if (key!.state === 'pending-deletion')
            stateChange(key!, ['enabled', 'disabled'], 'given an alias');
          if (
            (await tx.find<KmsAlias>('kmsAliases', { tenantId: tenant.id, uniqueKey: name })).length
          )
            throw new IamError('CONFLICT', 'That alias is already in use', 409);
          if (aliases!.length >= MAX_ALIASES_PER_KEY)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A key has at most ${MAX_ALIASES_PER_KEY} aliases`,
              409,
            );
          await assertNoNewRights(
            call,
            key!,
            { tags: key!.tags, aliases: aliases! },
            { tags: key!.tags, aliases: [...aliases!, name] },
          );
          const now = ctx.now();
          const alias = await tx.insert<KmsAlias>('kmsAliases', {
            id: id(),
            tenantId: tenant.id,
            uniqueKey: name,
            name,
            keyId: key!.id,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
          });
          metadata.alias = name;
          return { name, keyId: alias.keyId, createdAt: now, updatedAt: now };
        },
      );
    },

    /**
     * Points an alias at another key of the same usage and kind, so applications that name the alias switch keys
     * without a deploy. Requires iam:kms:update on both keys and on `iam/kms/alias/{name}`.
     */
    async updateAlias(
      credential: CredentialInput,
      input: { tenantId: string; alias: string; keyId: string },
    ): Promise<AliasSummary> {
      const name = aliasName(input.alias);
      if (typeof input.keyId === 'string' && input.keyId.startsWith('alias/'))
        throw new IamError('INVALID_INPUT', 'keyId must be a key id, not an alias');
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.update,
        keyTarget(input.tenantId, input.keyId),
        async (call, { key, aliases }) => {
          await assertAliasAllowed(call, name);
          const alias = (
            await call.tx.find<KmsAlias>('kmsAliases', {
              tenantId: call.tenant.id,
              uniqueKey: name,
            })
          )[0];
          if (!alias) throw new IamError('NOT_FOUND', 'Alias not found', 404);
          if (key!.state === 'pending-deletion')
            stateChange(key!, ['enabled', 'disabled'], 'given an alias');
          if (alias.keyId !== key!.id && aliases!.length >= MAX_ALIASES_PER_KEY)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A key has at most ${MAX_ALIASES_PER_KEY} aliases`,
              409,
            );
          const previous = await findKey(call.tx, call.tenant.id, alias.keyId);
          if (
            previous.keyUsage !== key!.keyUsage ||
            keySpecs[previous.keySpec].family !== keySpecs[key!.keySpec].family
          )
            throw new IamError(
              'INVALID_INPUT',
              'An alias can only move to a key of the same kind and usage',
            );
          const previousAliases = await aliasNames(call.tx, previous);
          if (
            !(await call.allowed(kmsActions.update, {
              resourceId: `kms/${previous.id}`,
              attributes: keyAttributes(previous, previousAliases),
              key: previous,
            }))
          )
            throw new OperationDenied('You may not manage the key the alias names now');
          if (previous.id !== key!.id) {
            // The new key gains the name and the old one loses it: neither may open anything for the caller.
            await assertNoNewRights(
              call,
              key!,
              { tags: key!.tags, aliases: aliases! },
              { tags: key!.tags, aliases: [...aliases!, name] },
            );
            await assertNoNewRights(
              call,
              previous,
              { tags: previous.tags, aliases: previousAliases },
              { tags: previous.tags, aliases: previousAliases.filter((item) => item !== name) },
            );
          }
          const updated = { ...alias, keyId: key!.id, updatedAt: ctx.now() };
          await call.tx.put('kmsAliases', updated);
          Object.assign(call.metadata, { alias: name, previousKeyId: previous.id });
          return {
            name,
            keyId: updated.keyId,
            createdAt: updated.createdAt,
            updatedAt: updated.updatedAt,
          };
        },
      );
    },

    /** Removes an alias; the key stays. Requires iam:kms:update on the key it names and on `iam/kms/alias/{name}`. */
    async deleteAlias(credential: CredentialInput, input: { tenantId: string; alias: string }) {
      const name = aliasName(input.alias);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.update,
        keyTarget(input.tenantId, name),
        async (call, { key, aliases }) => {
          const { tx, tenant, metadata } = call;
          await assertAliasAllowed(call, name);
          await assertNoNewRights(
            call,
            key!,
            { tags: key!.tags, aliases: aliases! },
            { tags: key!.tags, aliases: aliases!.filter((item) => item !== name) },
          );
          const alias = (
            await tx.find<KmsAlias>('kmsAliases', { tenantId: tenant.id, uniqueKey: name })
          )[0]!;
          await tx.delete('kmsAliases', alias.id);
          metadata.alias = name;
          return { success: true as const };
        },
      );
    },

    /** Every alias of the tenant, or of one key. Requires iam:kms:read on `iam/kms` (or on that key). */
    async listAliases(
      credential: CredentialInput,
      input: { tenantId: string; keyId?: string },
    ): Promise<AliasSummary[]> {
      const view = (alias: KmsAlias): AliasSummary => ({
        name: alias.name,
        keyId: alias.keyId,
        createdAt: alias.createdAt,
        updatedAt: alias.updatedAt,
      });
      if (input.keyId !== undefined)
        return keyOperation(
          credential,
          input.tenantId,
          kmsActions.read,
          keyTarget(input.tenantId, input.keyId),
          async ({ tx }, { key }) =>
            (await tx.find<KmsAlias>('kmsAliases', { tenantId: key!.tenantId, keyId: key!.id }))
              .sort((a, b) => (a.name < b.name ? -1 : 1))
              .map(view),
        );
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.read,
        tenantTarget,
        async ({ tx, tenant }) =>
          (await tx.find<KmsAlias>('kmsAliases', { tenantId: tenant.id }))
            .sort((a, b) => (a.name < b.name ? -1 : 1))
            .map(view),
      );
    },

    /**
     * Grants an identity (a person, service account or agent) named operations on one key (`read`, `encrypt`,
     * `decrypt`, `generate-data-key`, `sign`, `verify`, `generate-mac`, `verify-mac`), optionally until `expiresAt`
     * and, for encryption operations, only with a given encryption context (`constraints.encryptionContextEquals` /
     * `encryptionContextSubset`). A grant only passes on what its creator holds: every operation must be allowed to
     * the caller by policy now, and each use checks again that the creator could still make that very call. Grants
     * never bypass boundaries, explicit denies, or session and key scopes. Requires iam:kms:grant from a user session
     * or API key acting in its own right; at most 50 per key.
     */
    async createGrant(
      credential: CredentialInput,
      input: {
        tenantId: string;
        keyId: string;
        granteeType?: 'identity';
        granteeId: string;
        operations: GrantOperation[];
        constraints?: GrantConstraints;
        expiresAt?: number;
        name?: string;
      },
    ): Promise<GrantSummary> {
      if (input.granteeType !== undefined && input.granteeType !== 'identity')
        throw new IamError(
          'INVALID_INPUT',
          'Grants name one identity; grant a group access with a role instead',
        );
      const granteeId = text(input.granteeId, 'granteeId');
      const name = optionalText(input.name, 'name', 128);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.grant,
        keyTarget(input.tenantId, input.keyId),
        async (call, { key, aliases }) => {
          const { tx, tenant, principal, metadata } = call;
          // A grant is checked against its creator's own access for as long as it lives, so it must be made by an
          // identity of this tenant acting in its own right, not a role, token or delegated session.
          if (!actsInOwnRight(principal) || principal.identity.tenantId !== tenant.id)
            throw new OperationDenied('Create grants from your own session or API key');
          if (key!.state === 'pending-deletion')
            stateChange(key!, ['enabled', 'disabled'], 'granted');
          assertUnmanaged(key!);
          const operations = grantOperations(input.operations, key!.keyUsage);
          const constraints = grantConstraints(input.constraints, operations);
          const expiresAt =
            input.expiresAt === undefined ? undefined : ctx.bindingExpiry(input.expiresAt);
          await ctx.activeIdentity(tx, granteeId, tenant.id);
          // Checked with the context the grant is limited to, where it names one exactly.
          const context = constraints?.encryptionContextEquals;
          for (const operation of operations) {
            const action = kmsActions[operation];
            if (
              !(await call.allowed(action, {
                resourceId: `kms/${key!.id}`,
                attributes: keyAttributes(
                  key!,
                  aliases!,
                  context && operation !== 'read' ? { context } : {},
                ),
                key,
              }))
            )
              throw new OperationDenied(`You may not grant ${operation}: you do not hold it`);
          }
          const existing = await tx.find<KmsGrant>('kmsGrants', {
            tenantId: tenant.id,
            keyId: key!.id,
          });
          if (existing.length >= MAX_GRANTS_PER_KEY)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A key has at most ${MAX_GRANTS_PER_KEY} grants`,
              409,
            );
          const grant: KmsGrant = {
            id: id(),
            tenantId: tenant.id,
            keyId: key!.id,
            granteeType: 'identity',
            granteeId,
            operations,
            createdAt: ctx.now(),
            createdBy: principal.identity.id,
          };
          if (name) grant.name = name;
          if (constraints) grant.constraints = constraints;
          if (expiresAt !== undefined) grant.expiresAt = expiresAt;
          await tx.insert('kmsGrants', grant);
          Object.assign(metadata, {
            grantId: grant.id,
            granteeType: grant.granteeType,
            granteeId,
            operations,
            ...(constraints ? { constraints: structuredClone(constraints) as Json } : {}),
            ...(expiresAt !== undefined ? { expiresAt } : {}),
          });
          return summarizeGrant(grant, ctx.now());
        },
      );
    },

    /**
     * The key's grants, newest first, with `active` (not lapsed). Requires iam:kms:read; a caller reading through a
     * `read` grant of its own sees only its own grants.
     */
    async listGrants(
      credential: CredentialInput,
      input: { tenantId: string; keyId: string },
    ): Promise<GrantSummary[]> {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.read,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx, principal, metadata }, { key }) =>
          (await tx.find<KmsGrant>('kmsGrants', { tenantId: key!.tenantId, keyId: key!.id }))
            .filter(
              (grant) =>
                metadata.grantId === undefined || grant.granteeId === principal.identity.id,
            )
            .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : 1))
            .map((grant) => summarizeGrant(grant, ctx.now())),
      );
    },

    /** Revokes a grant. Requires iam:kms:grant on its key. */
    async revokeGrant(credential: CredentialInput, input: { tenantId: string; grantId: string }) {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.grant,
        async (tx) => {
          const grant = await ctx.scoped<KmsGrant>(
            tx,
            'kmsGrants',
            text(input.grantId, 'grantId'),
            text(input.tenantId, 'tenantId'),
          );
          return keyTarget(input.tenantId, grant.keyId)(tx);
        },
        async ({ tx, metadata }) => {
          await tx.delete('kmsGrants', input.grantId);
          Object.assign(metadata, { grantId: input.grantId, revoked: true });
          return { success: true as const };
        },
      );
    },

    /**
     * Gives up a grant made to the caller's own identity: no permission needed, so a workload can drop access it
     * no longer uses. Audited as `kms:grant-retire`.
     */
    async retireGrant(credential: CredentialInput, input: { tenantId: string; grantId: string }) {
      const tenantId = text(input.tenantId, 'tenantId');
      const grantId = text(input.grantId, 'grantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const tenant = await ctx.tenant(tx, tenantId);
        if (tenant.status !== 'active')
          throw new IamError('TENANT_INACTIVE', 'The tenant is not active', 403);
        const grant = await ctx.scoped<KmsGrant>(tx, 'kmsGrants', grantId, tenantId);
        if (
          !actsInOwnRight(principal) ||
          principal.session.tenantId !== tenantId ||
          grant.granteeId !== principal.identity.id
        )
          throw new IamError('ACCESS_DENIED', 'Only the grantee can retire this grant', 403);
        await tx.delete('kmsGrants', grant.id);
        await ctx.events.audit(
          tx,
          principal,
          'kms:grant-retire',
          tenantId,
          `kms/${grant.keyId}`,
          'allow',
          false,
          { grantId: grant.id },
        );
        return { success: true as const };
      });
    },

    /**
     * The public key of an asymmetric key version (default: current) as SPKI PEM and JWK (`kid` =
     * `{keyId}.{version}`), for verifying signatures or encrypting offline. Requires iam:kms:read.
     */
    async publicKey(
      credential: CredentialInput,
      input: { tenantId: string; keyId: string; keyVersion?: number },
    ): Promise<PublicKeyView> {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.read,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx }, { key }) => {
          if (keySpecs[key!.keySpec].family === 'aes' || key!.keyUsage === 'mac')
            throw new IamError('INVALID_INPUT', 'Symmetric keys have no public key');
          const version = await keyVersion(
            tx,
            key!,
            input.keyVersion === undefined
              ? key!.currentVersion
              : integer(input.keyVersion, 'keyVersion', 1, MAX_VERSIONS),
          );
          return {
            keyId: key!.id,
            keyVersion: version.version,
            keySpec: key!.keySpec,
            keyUsage: key!.keyUsage,
            algorithms: keyAlgorithms(key!),
            publicKeyPem: version.publicKeyPem!,
            jwk: publicJwk(key!, version) as Record<string, unknown>,
          };
        },
      );
    },

    /** Every version's public key of an asymmetric key as a JWK Set, for JWT verifiers. Requires iam:kms:read. */
    async jwks(
      credential: CredentialInput,
      input: { tenantId: string; keyId: string },
    ): Promise<{ keys: Record<string, unknown>[] }> {
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.read,
        keyTarget(input.tenantId, input.keyId),
        async ({ tx }, { key }) => {
          if (keySpecs[key!.keySpec].family === 'aes' || key!.keyUsage === 'mac')
            throw new IamError('INVALID_INPUT', 'Symmetric keys have no public key');
          const versions = await tx.find<KmsKeyVersion>('kmsKeyVersions', {
            tenantId: key!.tenantId,
            keyId: key!.id,
          });
          return {
            keys: versions
              .sort((a, b) => b.version - a.version)
              .map((version) => publicJwk(key!, version) as Record<string, unknown>),
          };
        },
      );
    },

    /**
     * Encrypts up to 4 KiB (`plaintext` as UTF-8 text, or `plaintextBase64`) under an encryption key's current
     * version, bound to the optional `encryptionContext`. Returns a self-describing `ciphertext` (key and version
     * inside). For larger data encrypt locally with `generateDataKey`. Requires iam:kms:encrypt.
     */
    async encrypt(
      credential: CredentialInput,
      input: {
        tenantId: string;
        keyId: string;
        plaintext?: string;
        plaintextBase64?: string;
        encryptionContext?: EncryptionContext;
      },
    ): Promise<{ ciphertext: string; keyId: string; keyVersion: number }> {
      const { bytes, text: isText } = payload(object(input), 'plaintext', MAX_PLAINTEXT_BYTES);
      const context = encryptionContext(input.encryptionContext);
      return encryptCall(credential, input.tenantId, input.keyId, bytes, isText, context);
    },

    /**
     * Decrypts a ciphertext from `encrypt`, `generateDataKey` or `reEncrypt` with the same `encryptionContext`.
     * Text comes back as `plaintext`, bytes as `plaintextBase64`. The key is read from the ciphertext; `keyId`
     * (id or alias) additionally insists on it. A wrong context or a tampered ciphertext fails with
     * `INVALID_CIPHERTEXT` and is audited as a denied decrypt. Requires iam:kms:decrypt.
     */
    async decrypt(
      credential: CredentialInput,
      input: {
        tenantId: string;
        ciphertext: string;
        encryptionContext?: EncryptionContext;
        keyId?: string;
      },
    ): Promise<{
      plaintext?: string;
      plaintextBase64?: string;
      keyId: string;
      keyVersion: number;
    }> {
      const context = encryptionContext(input.encryptionContext);
      const opened = await decryptCall(
        credential,
        input.tenantId,
        input.ciphertext,
        context,
        input.keyId,
      );
      try {
        return {
          ...(opened.text
            ? { plaintext: opened.plaintext.toString('utf8') }
            : { plaintextBase64: opened.plaintext.toString('base64') }),
          keyId: opened.keyId,
          keyVersion: opened.keyVersion,
        };
      } finally {
        opened.plaintext.fill(0);
      }
    },

    /**
     * Decrypts and encrypts again under `destinationKeyId` (and context) without the plaintext leaving the server:
     * for moving data to a new key or context. Needs iam:kms:decrypt on the source key and iam:kms:encrypt on the
     * destination; audited as both.
     */
    async reEncrypt(
      credential: CredentialInput,
      input: {
        tenantId: string;
        ciphertext: string;
        sourceEncryptionContext?: EncryptionContext;
        destinationKeyId: string;
        destinationEncryptionContext?: EncryptionContext;
      },
    ): Promise<{
      ciphertext: string;
      keyId: string;
      keyVersion: number;
      sourceKeyId: string;
      sourceKeyVersion: number;
    }> {
      const source = encryptionContext(input.sourceEncryptionContext, 'sourceEncryptionContext');
      const destination = encryptionContext(
        input.destinationEncryptionContext,
        'destinationEncryptionContext',
      );
      // One id links the decrypt and encrypt events of the same re-encryption.
      const note = { reEncryptId: id() };
      const opened = await decryptCall(
        credential,
        input.tenantId,
        input.ciphertext,
        source,
        undefined,
        note,
      );
      try {
        const sealed = await encryptCall(
          credential,
          input.tenantId,
          input.destinationKeyId,
          opened.plaintext,
          opened.text,
          destination,
          note,
        );
        return { ...sealed, sourceKeyId: opened.keyId, sourceKeyVersion: opened.keyVersion };
      } finally {
        opened.plaintext.fill(0);
      }
    },

    /**
     * A fresh data key (`bytes`: 16, 24, 32 (default) or 64) for encrypting large data locally: the plaintext
     * (`plaintextBase64`, omitted with `includePlaintext: false`) to use and discard, and its `ciphertext` under the
     * KMS key to store beside the data. Decrypt the stored ciphertext to use it again. Requires
     * iam:kms:generate-data-key (and iam:kms:decrypt later).
     */
    async generateDataKey(
      credential: CredentialInput,
      input: {
        tenantId: string;
        keyId: string;
        bytes?: 16 | 24 | 32 | 64;
        encryptionContext?: EncryptionContext;
        includePlaintext?: boolean;
      },
    ): Promise<{
      ciphertext: string;
      plaintextBase64?: string;
      keyId: string;
      keyVersion: number;
      bytes: number;
    }> {
      const bytes = input.bytes ?? 32;
      if (![16, 24, 32, 64].includes(bytes))
        throw new IamError('INVALID_INPUT', 'bytes must be 16, 24, 32 or 64');
      const context = encryptionContext(input.encryptionContext);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions['generate-data-key'],
        keyTarget(input.tenantId, input.keyId, { context }),
        async ({ tx, metadata }, { key }) => {
          assertUsable(key!, 'encrypt');
          assertUnmanaged(key!);
          const version = await keyVersion(tx, key!, key!.currentVersion);
          const material = randomBytes(bytes);
          try {
            metadata.keyVersion = version.version;
            metadata.bytes = bytes;
            return {
              ciphertext: encryptWith(ctx, key!, version, material, false, context),
              ...(input.includePlaintext === false
                ? {}
                : { plaintextBase64: material.toString('base64') }),
              keyId: key!.id,
              keyVersion: version.version,
              bytes,
            };
          } finally {
            material.fill(0);
          }
        },
      );
    },

    /**
     * Signs a message (`message` UTF-8 or `messageBase64`, up to 64 KiB) with a signing key's current version.
     * `algorithm` defaults to the key's first (ES256, ES384, EdDSA, or PS256 for RSA); ECDSA signatures are DER
     * unless `format: 'jose'` (raw r||s, as in JWS). Returns `signature` (base64url) and the `keyVersion` to verify
     * with. Requires iam:kms:sign (`resource.algorithm` names the algorithm).
     */
    async sign(
      credential: CredentialInput,
      input: {
        tenantId: string;
        keyId: string;
        message?: string;
        messageBase64?: string;
        algorithm?: string;
        format?: SignatureFormat;
      },
    ): Promise<{
      signature: string;
      algorithm: string;
      format: SignatureFormat;
      keyId: string;
      keyVersion: number;
    }> {
      const { bytes } = payload(object(input), 'message', MAX_MESSAGE_BYTES);
      const format = signatureFormat(input.format);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.sign,
        async (tx) => {
          const key = await findKey(tx, text(input.tenantId, 'tenantId'), input.keyId);
          return keyTarget(input.tenantId, key.id, {
            algorithm: requestedAlgorithm(key, input.algorithm),
          })(tx);
        },
        async ({ tx, metadata }, { key, attributes }) => {
          assertUsable(key!, 'sign');
          // A certificate authority's key signs only through the pki API: a raw signature over a certificate body
          // would be a certificate nobody decided on.
          assertUnmanaged(key!);
          const algorithm = signingAlgorithm(key!, attributes.algorithm);
          const version = await keyVersion(tx, key!, key!.currentVersion);
          Object.assign(metadata, { keyVersion: version.version, algorithm });
          return {
            signature: signWith(ctx, version, algorithm, bytes, format).toString('base64url'),
            algorithm,
            format,
            keyId: key!.id,
            keyVersion: version.version,
          };
        },
      );
    },

    /**
     * Checks a signature from `sign` against the message, with `keyVersion` (default: current) and `algorithm`
     * (default: the key's first). Returns `{ valid }`; a mismatch is not an error. Requires iam:kms:verify.
     */
    async verify(
      credential: CredentialInput,
      input: {
        tenantId: string;
        keyId: string;
        message?: string;
        messageBase64?: string;
        signature: string;
        algorithm?: string;
        keyVersion?: number;
        format?: SignatureFormat;
      },
    ): Promise<{ valid: boolean; algorithm: string; keyId: string; keyVersion: number }> {
      const { bytes } = payload(object(input), 'message', MAX_MESSAGE_BYTES);
      const signature = base64Bytes(input.signature, 'signature', 1024);
      const format = signatureFormat(input.format);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions.verify,
        async (tx) => {
          const key = await findKey(tx, text(input.tenantId, 'tenantId'), input.keyId);
          return keyTarget(input.tenantId, key.id, {
            algorithm: requestedAlgorithm(key, input.algorithm),
          })(tx);
        },
        async ({ tx, metadata }, { key, attributes }) => {
          assertUsable(key!, 'sign');
          const algorithm = signingAlgorithm(key!, attributes.algorithm);
          const version = await keyVersion(
            tx,
            key!,
            input.keyVersion === undefined
              ? key!.currentVersion
              : integer(input.keyVersion, 'keyVersion', 1, MAX_VERSIONS),
          );
          const valid = verifyWith(version, algorithm, bytes, signature, format);
          Object.assign(metadata, { keyVersion: version.version, algorithm, valid });
          return { valid, algorithm, keyId: key!.id, keyVersion: version.version };
        },
      );
    },

    /** An HMAC (`mac`, base64url) of a message with a MAC key's current version. Requires iam:kms:generate-mac. */
    async generateMac(
      credential: CredentialInput,
      input: { tenantId: string; keyId: string; message?: string; messageBase64?: string },
    ): Promise<{ mac: string; algorithm: string; keyId: string; keyVersion: number }> {
      const { bytes } = payload(object(input), 'message', MAX_MESSAGE_BYTES);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions['generate-mac'],
        keyTarget(input.tenantId, input.keyId),
        async ({ tx, metadata }, { key }) => {
          assertUsable(key!, 'mac');
          assertUnmanaged(key!);
          const version = await keyVersion(tx, key!, key!.currentVersion);
          metadata.keyVersion = version.version;
          return {
            mac: macWith(ctx, key!, version, bytes).toString('base64url'),
            algorithm: keyAlgorithms(key!)[0]!,
            keyId: key!.id,
            keyVersion: version.version,
          };
        },
      );
    },

    /**
     * Checks a MAC in constant time with `keyVersion` (default: current). Returns `{ valid }`. Requires
     * iam:kms:verify-mac.
     */
    async verifyMac(
      credential: CredentialInput,
      input: {
        tenantId: string;
        keyId: string;
        message?: string;
        messageBase64?: string;
        mac: string;
        keyVersion?: number;
      },
    ): Promise<{ valid: boolean; keyId: string; keyVersion: number }> {
      const { bytes } = payload(object(input), 'message', MAX_MESSAGE_BYTES);
      const mac = base64Bytes(input.mac, 'mac', 128);
      return keyOperation(
        credential,
        input.tenantId,
        kmsActions['verify-mac'],
        keyTarget(input.tenantId, input.keyId),
        async ({ tx, metadata }, { key }) => {
          assertUsable(key!, 'mac');
          assertUnmanaged(key!);
          const version = await keyVersion(
            tx,
            key!,
            input.keyVersion === undefined
              ? key!.currentVersion
              : integer(input.keyVersion, 'keyVersion', 1, MAX_VERSIONS),
          );
          const valid = sameBytes(macWith(ctx, key!, version, bytes), mac);
          Object.assign(metadata, { keyVersion: version.version, valid });
          return { valid, keyId: key!.id, keyVersion: version.version };
        },
      );
    },

    /**
     * Signs a JWT with a signing key (ES256, ES384, EdDSA, PS256-PS512, RS256-RS512) or a MAC key (HS256-HS512):
     * header `{ alg, kid, typ }` with `kid` = `{keyId}.{version}` (matching `jwks`), the given `claims`, `iat` when
     * absent, and `exp` from `expiresInSeconds` (1 s to 1 year). Requires iam:kms:sign or iam:kms:generate-mac, with
     * `resource.algorithm`, `resource.jwt` (true), `resource.jwt.typ` and the `sub`, `iss` and `aud` claims as
     * `resource.jwt.sub`, `resource.jwt.iss` and `resource.jwt.aud` (or `resource.jwt.audiences`), so policies can
     * limit which tokens a caller may mint, or allow tokens but not raw signatures.
     */
    async signJwt(
      credential: CredentialInput,
      input: {
        tenantId: string;
        keyId: string;
        claims: Record<string, unknown>;
        algorithm?: string;
        expiresInSeconds?: number;
        type?: string;
      },
    ): Promise<{ token: string; algorithm: string; keyId: string; keyVersion: number }> {
      const claims = { ...object(input.claims) };
      const expiresIn =
        input.expiresInSeconds === undefined
          ? undefined
          : integer(input.expiresInSeconds, 'expiresInSeconds', 1, 366 * 86400);
      const type = input.type === undefined ? 'JWT' : text(input.type, 'type', 64);
      return keyOperation(
        credential,
        input.tenantId,
        (target) => (target.key!.keyUsage === 'mac' ? kmsActions['generate-mac'] : kmsActions.sign),
        async (tx) => {
          const key = await findKey(tx, text(input.tenantId, 'tenantId'), input.keyId);
          if (key.keyUsage === 'encrypt')
            throw new IamError('INVALID_INPUT', 'Encryption keys cannot sign tokens');
          const target = await keyTarget(input.tenantId, key.id, {
            algorithm: requestedAlgorithm(key, input.algorithm),
          })(tx);
          Object.assign(target.attributes, jwtAttributes(claims, type));
          return target;
        },
        async ({ tx, metadata }, { key, attributes }) => {
          assertUsable(key!, key!.keyUsage);
          assertUnmanaged(key!);
          const algorithm = signingAlgorithm(key!, attributes.algorithm);
          const version = await keyVersion(tx, key!, key!.currentVersion);
          const now = Math.floor(ctx.now() / 1000);
          if (claims.iat === undefined) claims.iat = now;
          if (expiresIn !== undefined) claims.exp = now + expiresIn;
          const encodedClaims = b64url(JSON.stringify(claims));
          if (encodedClaims.length > 65536)
            throw new IamError('INVALID_INPUT', 'claims are larger than 48 KiB');
          const header = { alg: algorithm, kid: `${key!.id}.${version.version}`, typ: type };
          const signingInput = `${b64url(JSON.stringify(header))}.${encodedClaims}`;
          const signature =
            key!.keyUsage === 'mac'
              ? macWith(ctx, key!, version, Buffer.from(signingInput))
              : signWith(ctx, version, algorithm, Buffer.from(signingInput), 'jose');
          Object.assign(metadata, { keyVersion: version.version, algorithm, jwt: true });
          return {
            token: `${signingInput}.${signature.toString('base64url')}`,
            algorithm,
            keyId: key!.id,
            keyVersion: version.version,
          };
        },
      );
    },

    /**
     * Verifies a JWT signed by `signJwt` (or any JWS made with the key): the `kid` names the key version, `alg`
     * must be one the key supports, and `exp` / `nbf` are checked with `clockToleranceSeconds` (default 60), plus
     * `audience` and `issuer` when given. Returns `{ valid: true, claims, header }` or `{ valid: false, reason }`.
     * Requires iam:kms:verify or iam:kms:verify-mac.
     */
    async verifyJwt(
      credential: CredentialInput,
      input: {
        tenantId: string;
        token: string;
        keyId?: string;
        audience?: string;
        issuer?: string;
        clockToleranceSeconds?: number;
      },
    ): Promise<JwtVerification> {
      const token = text(input.token, 'token', 131072);
      const parts = token.split('.');
      if (parts.length !== 3 || parts.some((part) => !/^[A-Za-z0-9_-]*$/.test(part)))
        throw new IamError('INVALID_INPUT', 'token must be a compact JWS');
      const header = jsonSegment(parts[0]!, 'header');
      const claims = jsonSegment(parts[1]!, 'claims');
      const kid = parseKid(header.kid);
      if (!kid && input.keyId === undefined)
        throw new IamError('INVALID_INPUT', 'The token has no KMS kid; pass keyId');
      const tolerance = integer(input.clockToleranceSeconds ?? 60, 'clockToleranceSeconds', 0, 600);
      return keyOperation(
        credential,
        input.tenantId,
        (target) => (target.key!.keyUsage === 'mac' ? kmsActions['verify-mac'] : kmsActions.verify),
        async (tx) => {
          const tenantId = text(input.tenantId, 'tenantId');
          const key = await findKey(tx, tenantId, input.keyId ?? kid!.keyId);
          if (kid && kid.keyId !== key.id)
            throw new IamError('INVALID_INPUT', 'The token was not signed with that key');
          if (key.keyUsage === 'encrypt')
            throw new IamError('INVALID_INPUT', 'Encryption keys do not sign tokens');
          // The token's own claim, bounded before it reaches policies as `resource.algorithm`.
          const algorithm =
            typeof header.alg === 'string' && /^[A-Za-z0-9]{1,16}$/.test(header.alg)
              ? header.alg
              : 'none';
          return keyTarget(tenantId, key.id, { algorithm })(tx);
        },
        async ({ tx, metadata }, { key, attributes }) => {
          assertUsable(key!, key!.keyUsage);
          const algorithm = attributes.algorithm as string;
          const version = await keyVersion(tx, key!, kid?.version ?? key!.currentVersion);
          const base = { keyId: key!.id, keyVersion: version.version };
          const outcome = (): JwtVerification => {
            if (!keyAlgorithms(key!).includes(algorithm))
              return { valid: false, reason: 'algorithm', ...base };
            // Critical extensions are not understood here, so a token that needs them is refused (RFC 7515 4.1.11).
            if (header.crit !== undefined) return { valid: false, reason: 'header', ...base };
            const timeClaim = (value: unknown) => value === undefined || Number.isFinite(value);
            if (!timeClaim(claims.exp) || !timeClaim(claims.nbf))
              return { valid: false, reason: 'claims', ...base };
            const signingInput = Buffer.from(`${parts[0]}.${parts[1]}`);
            const signature = Buffer.from(parts[2]!, 'base64url');
            // One spelling per signature, so string-keyed replay caches cannot be sidestepped.
            if (signature.toString('base64url') !== parts[2])
              return { valid: false, reason: 'signature', ...base };
            const valid =
              key!.keyUsage === 'mac'
                ? sameBytes(macWith(ctx, key!, version, signingInput), signature)
                : verifyWith(version, algorithm, signingInput, signature, 'jose');
            if (!valid) return { valid: false, reason: 'signature', ...base };
            const now = Math.floor(ctx.now() / 1000);
            if (typeof claims.exp === 'number' && claims.exp + tolerance <= now)
              return { valid: false, reason: 'expired', ...base };
            if (typeof claims.nbf === 'number' && claims.nbf - tolerance > now)
              return { valid: false, reason: 'not-yet-valid', ...base };
            if (input.audience !== undefined) {
              const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
              if (!audiences.includes(input.audience))
                return { valid: false, reason: 'audience', ...base };
            }
            if (input.issuer !== undefined && claims.iss !== input.issuer)
              return { valid: false, reason: 'issuer', ...base };
            return { valid: true, algorithm, header, claims, ...base };
          };
          const result = outcome();
          Object.assign(metadata, {
            keyVersion: version.version,
            algorithm,
            jwt: true,
            valid: result.valid,
            ...(result.valid ? {} : { reason: result.reason }),
          });
          return result;
        },
      );
    },
  };
}

/**
 * The KMS scheduler job: rotates keys whose automatic rotation is due, destroys keys whose deletion waiting period
 * has passed (material, aliases and grants; audited as `kms:key-destroy`), and removes lapsed grants and grants
 * whose grantee is gone. Run it hourly.
 */
export async function maintainKeys(
  ctx: ServerContext,
  input: { tenantId?: string } = {},
): Promise<KeyMaintenanceResult> {
  const result: KeyMaintenanceResult = { rotated: [], destroyed: [], grantsRemoved: 0 };
  const filter = input.tenantId ? { tenantId: text(input.tenantId, 'tenantId') } : {};
  const keys = await ctx.store.transaction((tx) => tx.find<KmsKey>('kmsKeys', filter));
  const system = (
    tenantId: string,
    action: string,
    keyId: string,
    metadata: Record<string, Json>,
  ) => ({
    id: id(),
    tenantId,
    actorId: 'deployment-operator',
    action,
    resourceId: `kms/${keyId}`,
    timestamp: ctx.now(),
    outcome: 'allow' as const,
    metadata,
  });
  for (const candidate of keys) {
    const now = ctx.now();
    if (candidate.state === 'pending-deletion' && (candidate.deletionDate ?? Infinity) <= now) {
      await ctx.store.transaction(async (tx) => {
        const key = await tx.get<KmsKey>('kmsKeys', candidate.id);
        if (!key || key.state !== 'pending-deletion' || (key.deletionDate ?? Infinity) > now)
          return;
        for (const collection of ['kmsKeyVersions', 'kmsAliases', 'kmsGrants'])
          for (const record of await tx.find(collection, { tenantId: key.tenantId, keyId: key.id }))
            await tx.delete(collection, record.id);
        await tx.delete('kmsKeys', key.id);
        await ctx.events.recordAudit(
          tx,
          system(key.tenantId, 'kms:key-destroy', key.id, {
            keySpec: key.keySpec,
            versions: key.currentVersion,
          }),
        );
        result.destroyed.push({ tenantId: key.tenantId, keyId: key.id });
      });
      continue;
    }
    if (
      candidate.state === 'enabled' &&
      candidate.nextRotationAt !== undefined &&
      candidate.nextRotationAt <= now
    )
      await ctx.store.transaction(async (tx) => {
        const key = await tx.get<KmsKey>('kmsKeys', candidate.id);
        if (
          !key ||
          key.state !== 'enabled' ||
          key.nextRotationAt === undefined ||
          key.nextRotationAt > now ||
          key.rotationPeriodDays === undefined ||
          key.currentVersion >= MAX_VERSIONS
        )
          return;
        const version = key.currentVersion + 1;
        await addKeyVersion(ctx, tx, key, version, 'automatic');
        await tx.put('kmsKeys', {
          ...key,
          currentVersion: version,
          lastRotatedAt: now,
          nextRotationAt: now + key.rotationPeriodDays * DAY,
          updatedAt: now,
        });
        await ctx.events.recordAudit(
          tx,
          system(key.tenantId, 'kms:key-rotate', key.id, { keyVersion: version, automatic: true }),
        );
        result.rotated.push({ tenantId: key.tenantId, keyId: key.id, keyVersion: version });
      });
  }
  // Lapsed grants, and grants whose grantee or creator is gone, one tenant per transaction.
  const tenants = await ctx.store.transaction(async (tx) => [
    ...new Set((await tx.find<KmsGrant>('kmsGrants', filter)).map((grant) => grant.tenantId)),
  ]);
  for (const tenantId of tenants)
    await ctx.store.transaction(async (tx) => {
      const now = ctx.now();
      const deleted = async (identityId: string) => {
        const identity = await tx.get<Identity>('identities', identityId);
        return !identity || identity.tenantId !== tenantId || identity.status === 'deleted';
      };
      for (const grant of await tx.find<KmsGrant>('kmsGrants', { tenantId })) {
        const gone =
          (grant.expiresAt !== undefined && grant.expiresAt <= now) ||
          (await deleted(grant.granteeId)) ||
          (await deleted(grant.createdBy));
        if (!gone) continue;
        await tx.delete('kmsGrants', grant.id);
        result.grantsRemoved++;
      }
    });
  return result;
}

/** `iam.kms`: the scheduler job and nothing else; applications use `api.keys`. */
export function createKmsRuntime(ctx: ServerContext) {
  return {
    /** Automatic rotation, destruction after the deletion waiting period, and grant cleanup (run hourly). */
    maintain: (input?: { tenantId?: string }) => maintainKeys(ctx, input),
  };
}
