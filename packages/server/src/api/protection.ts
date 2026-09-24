import { IamError, type CredentialInput, type IamStore, type Json } from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { createGuard, type GuardCall, type GuardTarget } from '../guarded.js';
import {
  aliasNames,
  assertUnmanaged,
  assertUsable,
  createServiceKey,
  findKey,
  keyAttributes,
  kmsActions,
  kmsDataKeyFor,
  kmsOpenDataKeyFor,
  retireServiceKey,
} from '../kms.js';
import { OperationDenied } from '../operations.js';
import {
  MAX_BATCH,
  MAX_PROFILES_PER_TENANT,
  dataTypes,
  defaultMask,
  fingerprint,
  formatPreservingSpace,
  lookupContext,
  maskStyle,
  maskValue,
  needsDeterministic,
  newToken,
  normalizeValue,
  openValue,
  profileName,
  protectionActions,
  sealValue,
  summarizeProfile,
  tokenKey,
  type DataType,
  type MaskStyle,
  type ProfileSummary,
  type ProtectedToken,
  type ProtectionProfile,
  type TokenFormat,
} from '../tokenization.js';
import { id } from '../utils.js';
import { integer, text } from '../validation.js';

const DAY = 86_400_000;
/** Tokens a retention sweep reads per transaction. */
const SWEEP_BATCH = 500;

interface ProtectionTarget extends GuardTarget {
  profile?: ProtectionProfile;
}

export interface ProfileCreateInput {
  tenantId: string;
  /** Lowercase letters, digits and hyphens; policies name the profile as `iam/protection/{name}`. */
  name: string;
  dataType: DataType;
  /** `format-preserving` (default for card, ssn, email and phone) or `random` (default for generic). */
  format?: TokenFormat;
  /**
   * The same value always gets the same token. Default false, except format-preserving `ssn` and `phone` profiles,
   * which must be deterministic (their tokens have few random digits).
   */
  deterministic?: boolean;
  /** A tenant AES key (id or alias) the caller may use; a new one is created when absent. */
  keyId?: string;
  /** One of the masks the data type allows (`maskStyles`). */
  mask?: MaskStyle;
  description?: string;
  /** Delete tokens this many days after they were created (1 to 3650). */
  retentionDays?: number;
}

const list = (value: unknown, name: string): unknown[] => {
  if (!Array.isArray(value) || value.length === 0 || value.length > MAX_BATCH)
    throw new IamError('INVALID_INPUT', `${name} must list 1 to ${MAX_BATCH} entries`);
  return value;
};

const purposeOf = (value: unknown): string => {
  const purpose = text(value, 'purpose', 64);
  if (!/^[a-z][a-z0-9-]{0,63}$/.test(purpose))
    throw new IamError(
      'INVALID_INPUT',
      'purpose is a short lowercase name, such as payment-processing or fraud-review',
    );
  return purpose;
};

const tokenList = (value: unknown): string[] =>
  list(value, 'tokens').map((item) => {
    if (typeof item !== 'string' || !item || item.length > 4096 || /[\u0000-\u001f]/.test(item))
      throw new IamError('INVALID_INPUT', 'Every token must be a string');
    return item;
  });

/**
 * Data protection by tokenization. A profile says how one kind of sensitive value is tokenized, masked and
 * protected; policies name it as `iam/protection/{name}` with `resource.profile`, `resource.dataType`,
 * `resource.format` and `resource.deterministic`; detokenizing adds `resource.purpose` and masking `resource.style`.
 * Values are encrypted under the profile's KMS key (one wrapped data key per call) and never written to the audit
 * trail; tokens are not either, only counts. Sessions that view as someone else are refused.
 */
export function createProtectionApi(ctx: ServerContext) {
  const guard = createGuard<ProtectionTarget>(ctx, 'protection', {
    // Refusals are audited with the profile and purpose too.
    describe: (target): Record<string, Json> => ({
      ...(target.profile ? { profile: target.profile.name } : {}),
      ...(typeof target.attributes.purpose === 'string'
        ? { purpose: target.attributes.purpose }
        : {}),
    }),
    recordedFailures: { KEY_STATE_INVALID: 'key-unavailable' },
    // Plugins see which profile served a call, never values or tokens (format-preserving ones keep digits).
    hookResult: (value) => {
      if (!value || typeof value !== 'object') return value;
      const { values, tokens, ...rest } = value as Record<string, unknown>;
      void values;
      void tokens;
      return rest;
    },
  });

  const profileAttributes = (profile: ProtectionProfile, extra: Record<string, unknown> = {}) => ({
    profile: profile.name,
    dataType: profile.dataType,
    format: profile.format,
    deterministic: profile.deterministic,
    ...extra,
  });

  async function findProfile(tx: IamStore, tenantId: string, name: unknown) {
    const profile = (
      await tx.find<ProtectionProfile>('protectionProfiles', {
        tenantId: text(tenantId, 'tenantId'),
        uniqueKey: `name:${profileName(name)}`,
      })
    )[0];
    if (!profile) throw new IamError('NOT_FOUND', 'Protection profile not found', 404);
    return profile;
  }

  const profileTarget =
    (
      tenantId: string,
      name: unknown,
      extra: (profile: ProtectionProfile) => Record<string, unknown> = () => ({}),
    ) =>
    async (tx: IamStore): Promise<ProtectionTarget> => {
      const profile = await findProfile(tx, tenantId, name);
      return {
        resourceId: `protection/${profile.name}`,
        attributes: profileAttributes(profile, extra(profile)),
        profile,
      };
    };

  /**
   * A profile bound to a customer key (one it did not create) leaves the key's owner in charge, as the vault does:
   * every call needs the caller's own KMS permission on the key, so revoking it stops the profile's use too.
   */
  async function requireKeyUse(
    call: GuardCall<ProtectionTarget>,
    profile: ProtectionProfile,
    action: string,
  ) {
    const key = await findKey(call.tx, profile.tenantId, profile.keyId);
    if (key.managedBy === 'protection' && key.managedId === profile.id) return;
    const target = {
      resourceId: `kms/${key.id}`,
      attributes: keyAttributes(key, await aliasNames(call.tx, key)),
    };
    if (!(await call.allowed(action, target)))
      throw new OperationDenied(`This needs ${action} on the profile's customer-managed key`);
  }

  /** The profile's fingerprint key, unwrapped by its KMS key (so it stops with the key). Wipe it after use. */
  const lookupKey = (
    tx: IamStore,
    profile: ProtectionProfile,
    principal: GuardCall['principal'],
  ): Promise<Buffer> =>
    kmsOpenDataKeyFor(
      ctx,
      tx,
      profile.tenantId,
      profile.lookupKeyWrapped,
      lookupContext(profile.id),
      {
        via: 'protection',
        principal,
      },
    );

  /** The stored records of `tokens` in a profile, keyed by token (absent tokens are missing from the map). */
  async function recordsOf(tx: IamStore, profile: ProtectionProfile, tokens: string[]) {
    const records = new Map<string, ProtectedToken>();
    for (const token of new Set(tokens)) {
      const record = (
        await tx.find<ProtectedToken>('protectionTokens', {
          tenantId: profile.tenantId,
          uniqueKey: tokenKey(profile.id, token),
        })
      )[0];
      if (record && record.profileId === profile.id && record.token === token)
        records.set(token, record);
    }
    return records;
  }

  /** Opens the values of stored tokens, unwrapping each distinct batch data key once. */
  async function openAll(
    tx: IamStore,
    profile: ProtectionProfile,
    records: Iterable<ProtectedToken>,
    principal: GuardCall['principal'],
  ): Promise<Map<string, string>> {
    const keys = new Map<string, Buffer>();
    const values = new Map<string, string>();
    try {
      for (const record of records) {
        let dataKey = keys.get(record.wrapped);
        if (!dataKey) {
          dataKey = await kmsOpenDataKeyFor(
            ctx,
            tx,
            profile.tenantId,
            record.wrapped,
            { protection: profile.id },
            { via: 'protection', principal },
          );
          keys.set(record.wrapped, dataKey);
        }
        values.set(record.token, openValue(dataKey, record));
      }
      return values;
    } finally {
      for (const key of keys.values()) key.fill(0);
    }
  }

  /** Whether any token remains in a profile (read by query, not by the counter). */
  const holdsTokens = async (tx: IamStore, profile: ProtectionProfile) =>
    (
      await tx.find(
        'protectionTokens',
        { tenantId: profile.tenantId, profileId: profile.id },
        { limit: 1 },
      )
    ).length > 0;

  return {
    /**
     * Creates a tokenization profile for one kind of value (`card`, `ssn`, `email`, `phone` or `generic`): its token
     * format, whether tokens are deterministic, its display mask, its retention, and the tenant AES key that protects
     * its values (an existing one the caller may use, or a new one managed by the profile). Requires
     * iam:protection:manage on `iam/protection/{name}`.
     */
    async createProfile(
      credential: CredentialInput,
      input: ProfileCreateInput,
    ): Promise<ProfileSummary> {
      const name = profileName(input.name);
      if (!dataTypes.includes(input.dataType))
        throw new IamError('INVALID_INPUT', `dataType must be one of ${dataTypes.join(', ')}`);
      const format: TokenFormat =
        input.format ?? (input.dataType === 'generic' ? 'random' : 'format-preserving');
      if (format !== 'random' && format !== 'format-preserving')
        throw new IamError('INVALID_INPUT', 'format must be random or format-preserving');
      if (input.deterministic !== undefined && typeof input.deterministic !== 'boolean')
        throw new IamError('INVALID_INPUT', 'deterministic must be true or false');
      const deterministic = input.deterministic ?? needsDeterministic(input.dataType, format);
      if (!deterministic && needsDeterministic(input.dataType, format))
        throw new IamError(
          'INVALID_INPUT',
          `Format-preserving ${input.dataType} tokens keep the last four digits and have few random ones left, so these profiles must be deterministic (or use random tokens)`,
        );
      const mask =
        input.mask === undefined
          ? defaultMask[input.dataType]
          : maskStyle(input.dataType, input.mask);
      const description =
        input.description === undefined ? undefined : text(input.description, 'description', 512);
      const retentionDays =
        input.retentionDays === undefined
          ? undefined
          : integer(input.retentionDays, 'retentionDays', 1, 3650);
      return guard.run(
        credential,
        input.tenantId,
        protectionActions.manage,
        async () => ({
          resourceId: `protection/${name}`,
          attributes: { profile: name, dataType: input.dataType, format, deterministic },
        }),
        async (call) => {
          const { tx, tenant, principal, metadata } = call;
          const existing = await tx.find<ProtectionProfile>('protectionProfiles', {
            tenantId: tenant.id,
          });
          if (existing.length >= MAX_PROFILES_PER_TENANT)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant keeps at most ${MAX_PROFILES_PER_TENANT} protection profiles`,
              409,
            );
          if (existing.some((profile) => profile.name === name))
            throw new IamError('CONFLICT', 'A profile with that name exists', 409);
          const profileId = id();
          let key;
          if (input.keyId !== undefined) {
            key = await findKey(tx, tenant.id, input.keyId);
            assertUsable(key, 'encrypt');
            // Another profile's or module's key stays theirs.
            assertUnmanaged(key);
            if (key.keySpec !== 'aes-256-gcm')
              throw new IamError('INVALID_INPUT', 'Profiles need an aes-256-gcm key');
            // Whoever binds a key to a profile must be able to use it for exactly this (and every caller will).
            const target = {
              resourceId: `kms/${key.id}`,
              attributes: keyAttributes(key, await aliasNames(tx, key)),
            };
            for (const action of [kmsActions['generate-data-key'], kmsActions.decrypt])
              if (!(await call.allowed(action, target)))
                throw new OperationDenied('You may not protect values with that key');
          } else
            key = await createServiceKey(ctx, tx, {
              tenantId: tenant.id,
              keySpec: 'aes-256-gcm',
              keyUsage: 'encrypt',
              description: `Data protection profile: ${name}`,
              tags: { 'protection-profile': name },
              createdBy: principal.identity.id,
              managedBy: 'protection',
              managedId: profileId,
            });
          const lookup = await kmsDataKeyFor(ctx, tx, tenant.id, key.id, lookupContext(profileId), {
            via: 'protection',
            principal,
          });
          lookup.dataKey.fill(0);
          const now = ctx.now();
          const profile: ProtectionProfile = {
            id: profileId,
            tenantId: tenant.id,
            uniqueKey: `name:${name}`,
            name,
            dataType: input.dataType,
            format,
            deterministic,
            keyId: key.id,
            mask,
            lookupKeyWrapped: lookup.wrapped,
            tokens: 0,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
          };
          if (description) profile.description = description;
          if (retentionDays !== undefined) profile.retentionDays = retentionDays;
          await tx.insert('protectionProfiles', profile);
          Object.assign(metadata, {
            profile: name,
            dataType: profile.dataType,
            format,
            deterministic,
            keyId: key.id,
          });
          return summarizeProfile(profile);
        },
      );
    },

    /** The tenant's profiles the caller may read (`iam:protection:read`, per profile). */
    async listProfiles(
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ProfileSummary[]> {
      return guard.visible(
        credential,
        input.tenantId,
        protectionActions.read,
        'protection',
        async (tx, tenant) =>
          (await tx.find<ProtectionProfile>('protectionProfiles', { tenantId: tenant.id }))
            .sort((a, b) => (a.name < b.name ? -1 : 1))
            .map((profile) => ({
              item: summarizeProfile(profile),
              target: {
                resourceId: `protection/${profile.name}`,
                attributes: profileAttributes(profile),
              },
            })),
      );
    },

    /** One profile, with the number of tokens it holds. Requires iam:protection:read. */
    async getProfile(
      credential: CredentialInput,
      input: { tenantId: string; profile: string },
    ): Promise<ProfileSummary> {
      return guard.run(
        credential,
        input.tenantId,
        protectionActions.read,
        profileTarget(input.tenantId, input.profile),
        async (_call, { profile }) => summarizeProfile(profile!),
      );
    },

    /**
     * Changes a profile's description, mask or retention (`retentionDays: null` keeps tokens until deleted). The data
     * type, format and key never change: tokens already issued depend on them. Requires iam:protection:manage;
     * setting or shortening retention deletes tokens, so it also needs iam:protection:delete and recent
     * authentication.
     */
    async updateProfile(
      credential: CredentialInput,
      input: {
        tenantId: string;
        profile: string;
        description?: string | null;
        mask?: MaskStyle;
        retentionDays?: number | null;
      },
    ): Promise<ProfileSummary> {
      return guard.run(
        credential,
        input.tenantId,
        protectionActions.manage,
        profileTarget(input.tenantId, input.profile),
        async (call, target) => {
          const { tx, principal, metadata } = call;
          const profile = target.profile!;
          const next: ProtectionProfile = { ...profile, updatedAt: ctx.now() };
          if (input.description === null) delete next.description;
          else if (input.description !== undefined)
            next.description = text(input.description, 'description', 512);
          if (input.mask !== undefined) next.mask = maskStyle(profile.dataType, input.mask);
          if (input.retentionDays === null) delete next.retentionDays;
          else if (input.retentionDays !== undefined) {
            const days = integer(input.retentionDays, 'retentionDays', 1, 3650);
            if (profile.retentionDays === undefined || days < profile.retentionDays) {
              if (!(await call.allowed(protectionActions.delete, target)))
                throw new OperationDenied(
                  'Setting or shortening retention deletes tokens: it needs iam:protection:delete',
                );
              ctx.auth.requireRecent(principal);
            }
            next.retentionDays = days;
          }
          await tx.put('protectionProfiles', next);
          Object.assign(metadata, {
            mask: next.mask,
            ...(next.retentionDays !== undefined ? { retentionDays: next.retentionDays } : {}),
          });
          return summarizeProfile(next);
        },
      );
    },

    /**
     * Deletes a profile that holds no tokens (delete its tokens first). Requires iam:protection:manage and recent
     * authentication. A key the profile created is scheduled for deletion (7 days); a customer key stays.
     */
    async deleteProfile(credential: CredentialInput, input: { tenantId: string; profile: string }) {
      return guard.run(
        credential,
        input.tenantId,
        protectionActions.manage,
        profileTarget(input.tenantId, input.profile),
        async ({ tx, principal, metadata }, { profile }) => {
          ctx.auth.requireRecent(principal);
          if (await holdsTokens(tx, profile!))
            throw new IamError('RESOURCE_IN_USE', 'The profile still holds tokens', 409);
          await tx.delete('protectionProfiles', profile!.id);
          const deletionDate = await retireServiceKey(
            ctx,
            tx,
            profile!.tenantId,
            profile!.keyId,
            'protection',
            profile!.id,
          );
          if (deletionDate !== undefined) metadata.keyDeletionDate = deletionDate;
          return { success: true as const };
        },
      );
    },

    /**
     * Replaces up to 100 values by tokens, in order. Values are validated and normalized for the profile's data type
     * (a card number must pass the Luhn check). A deterministic profile returns the token it already issued for a
     * value; otherwise every call issues new tokens. On a deterministic profile this permission can test guesses
     * against known tokens, so grant it as narrowly as detokenize (`resource.deterministic`). Requires
     * iam:protection:tokenize on the profile (and iam:kms:generate-data-key on a customer key); audited with counts
     * only.
     */
    async tokenize(
      credential: CredentialInput,
      input: { tenantId: string; profile: string; values: string[] },
    ): Promise<{ tokens: string[] }> {
      const raw = list(input.values, 'values');
      return guard.run(
        credential,
        input.tenantId,
        protectionActions.tokenize,
        profileTarget(input.tenantId, input.profile),
        async (call, { profile }) => {
          const { tx, principal, metadata } = call;
          const current = profile!;
          const values = raw.map((value) => normalizeValue(current.dataType, value));
          if (
            current.format === 'format-preserving' &&
            values.some((value) => !formatPreservingSpace(current.dataType, value))
          )
            throw new IamError(
              'INVALID_INPUT',
              'Format-preserving generic values need at least 12 letters or digits; use a random profile',
            );
          await requireKeyUse(call, current, kmsActions['generate-data-key']);
          const key = await lookupKey(tx, current, principal);
          const tokens: string[] = [];
          const issued = new Map<string, string>();
          let batch: { dataKey: Buffer; wrapped: string } | undefined;
          let created = 0;
          try {
            for (const value of values) {
              const print = fingerprint(key, value);
              if (current.deterministic) {
                const known =
                  issued.get(print) ??
                  (
                    await tx.find<ProtectedToken>('protectionTokens', {
                      tenantId: current.tenantId,
                      profileId: current.id,
                      fingerprint: print,
                    })
                  )[0]?.token;
                if (known) {
                  tokens.push(known);
                  issued.set(print, known);
                  continue;
                }
              }
              batch ??= await kmsDataKeyFor(
                ctx,
                tx,
                current.tenantId,
                current.keyId,
                { protection: current.id },
                { via: 'protection', principal },
              );
              let token: string | undefined;
              for (let attempt = 0; attempt < 10 && !token; attempt++) {
                const candidate = newToken(current.dataType, current.format, value);
                const taken = (
                  await tx.find('protectionTokens', {
                    tenantId: current.tenantId,
                    uniqueKey: tokenKey(current.id, candidate),
                  })
                ).length;
                if (!taken && ![...issued.values()].includes(candidate)) token = candidate;
              }
              if (!token)
                throw new IamError('CONFLICT', 'No free token could be found for a value', 409);
              await tx.insert<ProtectedToken>('protectionTokens', {
                id: id(),
                tenantId: current.tenantId,
                uniqueKey: tokenKey(current.id, token),
                profileId: current.id,
                token,
                fingerprint: print,
                wrapped: batch.wrapped,
                sealed: sealValue(batch.dataKey, current.tenantId, current.id, token, value),
                createdAt: ctx.now(),
                createdBy: principal.identity.id,
              });
              issued.set(print, token);
              tokens.push(token);
              created++;
            }
          } finally {
            key.fill(0);
            batch?.dataKey.fill(0);
          }
          if (created)
            await tx.put<ProtectionProfile>('protectionProfiles', {
              ...current,
              tokens: (current.tokens ?? 0) + created,
            });
          // Whether a value was known already stays in the audit trail: callers would learn who else is stored.
          Object.assign(metadata, { count: values.length, created });
          return { tokens };
        },
      );
    },

    /**
     * Turns up to 100 tokens of one profile back into their values, in order (`null` for tokens the profile does not
     * hold). `purpose` (a short lowercase name, such as `payment-processing`) is required: policies read it as
     * `resource.purpose` and the audit records it, refusals included. Requires iam:protection:detokenize on the
     * profile (and iam:kms:decrypt on a customer key).
     */
    async detokenize(
      credential: CredentialInput,
      input: { tenantId: string; profile: string; tokens: string[]; purpose: string },
    ): Promise<{ values: Array<string | null> }> {
      const tokens = tokenList(input.tokens);
      const purpose = purposeOf(input.purpose);
      return guard.run(
        credential,
        input.tenantId,
        protectionActions.detokenize,
        profileTarget(input.tenantId, input.profile, () => ({ purpose })),
        async (call, { profile }) => {
          const { tx, principal, metadata } = call;
          await requireKeyUse(call, profile!, kmsActions.decrypt);
          const records = await recordsOf(tx, profile!, tokens);
          const opened = await openAll(tx, profile!, records.values(), principal);
          Object.assign(metadata, { purpose, count: tokens.length, found: records.size });
          return { values: tokens.map((token) => opened.get(token) ?? null) };
        },
      );
    },

    /**
     * The masked form of up to 100 tokens' values, for display (`**** **** **** 4242`, `j***@example.com`), with the
     * profile's mask or `style` (one its data type allows). Policies see the style used as `resource.style`. A mask
     * never shows more than half of a value, except the first six and last four digits of a long card number.
     * Requires iam:protection:mask (and iam:kms:decrypt on a customer key).
     */
    async mask(
      credential: CredentialInput,
      input: { tenantId: string; profile: string; tokens: string[]; style?: MaskStyle },
    ): Promise<{ values: Array<string | null> }> {
      const tokens = tokenList(input.tokens);
      let style: MaskStyle;
      return guard.run(
        credential,
        input.tenantId,
        protectionActions.mask,
        profileTarget(input.tenantId, input.profile, (profile) => {
          style =
            input.style === undefined
              ? profile.mask
              : maskStyle(profile.dataType, input.style, 'style');
          return { style };
        }),
        async (call, { profile }) => {
          const { tx, principal, metadata } = call;
          await requireKeyUse(call, profile!, kmsActions.decrypt);
          const records = await recordsOf(tx, profile!, tokens);
          const opened = await openAll(tx, profile!, records.values(), principal);
          Object.assign(metadata, { style, count: tokens.length, found: records.size });
          return {
            values: tokens.map((token) => {
              const value = opened.get(token);
              return value === undefined ? null : maskValue(profile!.dataType, style, value);
            }),
          };
        },
      );
    },

    /**
     * Deletes tokens and their values for good (right to erasure), named by `tokens` or by `values` (every token
     * issued for each value, found by its keyed fingerprint, which needs the profile's key enabled). Up to 100
     * either way. Requires iam:protection:delete on the profile.
     */
    async deleteTokens(
      credential: CredentialInput,
      input: { tenantId: string; profile: string; tokens?: string[]; values?: string[] },
    ): Promise<{ deleted: number }> {
      if ((input.tokens === undefined) === (input.values === undefined))
        throw new IamError('INVALID_INPUT', 'Name either tokens or values');
      const tokens = input.tokens === undefined ? undefined : tokenList(input.tokens);
      const raw = input.values === undefined ? undefined : list(input.values, 'values');
      return guard.run(
        credential,
        input.tenantId,
        protectionActions.delete,
        profileTarget(input.tenantId, input.profile),
        async ({ tx, principal, metadata }, { profile }) => {
          const current = profile!;
          const doomed: ProtectedToken[] = [];
          if (tokens) doomed.push(...(await recordsOf(tx, current, tokens)).values());
          else {
            const values = new Set(raw!.map((item) => normalizeValue(current.dataType, item)));
            const key = await lookupKey(tx, current, principal);
            try {
              for (const value of values)
                doomed.push(
                  ...(await tx.find<ProtectedToken>('protectionTokens', {
                    tenantId: current.tenantId,
                    profileId: current.id,
                    fingerprint: fingerprint(key, value),
                  })),
                );
            } finally {
              key.fill(0);
            }
          }
          for (const record of doomed) await tx.delete('protectionTokens', record.id);
          if (doomed.length)
            await tx.put<ProtectionProfile>('protectionProfiles', {
              ...current,
              tokens: Math.max(0, (current.tokens ?? 0) - doomed.length),
            });
          Object.assign(metadata, { deleted: doomed.length, by: tokens ? 'token' : 'value' });
          return { deleted: doomed.length };
        },
      );
    },
  };
}

/**
 * Deletes tokens past their profile's retention, a batch per transaction (so the write lock is never held for a
 * whole profile), and audits each profile swept as `protection:retention-sweep`.
 */
export async function sweepTokens(
  ctx: ServerContext,
  input: { tenantId?: string } = {},
): Promise<{ deleted: number; profiles: number }> {
  const profiles = await ctx.store.transaction((tx) =>
    tx.find<ProtectionProfile>(
      'protectionProfiles',
      input.tenantId ? { tenantId: text(input.tenantId, 'tenantId') } : {},
    ),
  );
  let deleted = 0;
  let swept = 0;
  for (const listed of profiles) {
    if (listed.retentionDays === undefined) continue;
    swept++;
    let removed = 0;
    let after: string | undefined;
    for (;;) {
      const page = await ctx.store.transaction(async (tx) => {
        const profile = await tx.get<ProtectionProfile>('protectionProfiles', listed.id);
        if (!profile || profile.retentionDays === undefined) return undefined;
        const cutoff = ctx.now() - profile.retentionDays * DAY;
        const records = await tx.find<ProtectedToken>(
          'protectionTokens',
          { tenantId: profile.tenantId, profileId: profile.id },
          { limit: SWEEP_BATCH, ...(after === undefined ? {} : { after }) },
        );
        let count = 0;
        for (const record of records)
          if (record.createdAt <= cutoff) {
            await tx.delete('protectionTokens', record.id);
            count++;
          }
        if (count)
          await tx.put<ProtectionProfile>('protectionProfiles', {
            ...profile,
            tokens: Math.max(0, (profile.tokens ?? 0) - count),
          });
        return { count, last: records.at(-1)?.id, full: records.length === SWEEP_BATCH };
      });
      if (!page) break;
      removed += page.count;
      if (!page.full || page.last === undefined) break;
      after = page.last;
    }
    if (removed)
      await ctx.store.transaction((tx) =>
        ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: listed.tenantId,
          actorId: 'deployment-operator',
          action: 'protection:retention-sweep',
          resourceId: `protection/${listed.name}`,
          timestamp: ctx.now(),
          outcome: 'allow',
          metadata: { deleted: removed, retentionDays: listed.retentionDays ?? null },
        }),
      );
    deleted += removed;
  }
  return { deleted, profiles: swept };
}

/** `iam.protection`: the retention job. Applications use `api.protection`. */
export function createProtectionRuntime(ctx: ServerContext) {
  return {
    /** Deletes tokens older than their profile's `retentionDays` (run daily). */
    sweep: (input?: { tenantId?: string }) => sweepTokens(ctx, input),
  };
}
