import { encryptSecret, openSecret } from '@better-iam/auth';
import { IamError, type IamStore, type StoredRecord } from '@better-iam/core';
import type { ServerContext } from './context.js';
import { kmsSealedField } from './kms.js';

export interface SecretRotationOptions {
  /** Report what would change without writing anything. */
  dryRun?: boolean;
  /** Records read per transaction (default 200, 1-2000). */
  batchSize?: number;
  /** Most records examined per collection (a sample, for `selfCheck`); by default all of them. */
  limit?: number;
}

export interface SecretRotationResult {
  /** Values re-sealed with the current secret (or, in a dry run, that would be), per collection. */
  resealed: Record<string, number>;
  /** Values no configured secret opens, per collection: sealed with a secret that is gone. */
  unreadable: Record<string, number>;
  /** Values already sealed with the current secret. */
  current: number;
  /** Every record was examined; false when `limit` cut a collection short (the counts are a sample). */
  complete: boolean;
  /**
   * Nothing sealed with a previous secret remains: the run examined everything and (in a dry run)
   * found nothing to re-seal. Only then can `previousSecrets` go.
   */
  done: boolean;
}

/** A sealed value inside a record: where it lives and the context it was sealed for. */
interface SealedField {
  collection: string;
  /** Only records that still hold a sealed value (pending outbox messages, for example). */
  filter: Record<string, unknown>;
  read(record: StoredRecord): string | undefined;
  write(record: StoredRecord, sealed: string): StoredRecord;
  context(record: StoredRecord): string;
}

const FIELDS: SealedField[] = [
  {
    // TOTP authenticator secrets.
    collection: 'authMfa',
    filter: {},
    read: (record) =>
      typeof record.encryptedSecret === 'string' ? record.encryptedSecret : undefined,
    write: (record, sealed) => ({ ...record, encryptedSecret: sealed }),
    context: (record) => `mfa:${String(record.identityId)}`,
  },
  {
    // Webhook signing secrets.
    collection: 'webhooks',
    filter: {},
    read: (record) => (typeof record.secretSealed === 'string' ? record.secretSealed : undefined),
    write: (record, sealed) => ({ ...record, secretSealed: sealed }),
    context: (record) => `webhook:${record.id}`,
  },
  {
    // Undelivered email, SMS, and webhook payloads (delivered ones are cleared).
    collection: 'outbox',
    filter: { deliveredAt: undefined, failedAt: undefined },
    read: (record) => {
      const payload = record.payload as { sealed?: unknown } | undefined;
      return typeof payload?.sealed === 'string' ? payload.sealed : undefined;
    },
    write: (record, sealed) => ({
      ...record,
      payload: { ...(record.payload as object), sealed },
    }),
    context: (record) => `outbox:${record.id}`,
  },
  {
    // Inference provider API keys (inference.ts `providerKeyContext`).
    collection: 'inferenceProviders',
    filter: {},
    read: (record) => (typeof record.keySealed === 'string' ? record.keySealed : undefined),
    write: (record, sealed) => ({ ...record, keySealed: sealed }),
    context: (record) => `inference-provider:${record.id}`,
  },
  // KMS key material sealed under the deployment secret (kms.ts); data protection keys are wrapped under KMS keys.
  kmsSealedField,
  {
    // Vault secret values (vault.ts `versionContext`); destroyed versions hold none, and values under a
    // customer-managed key are KMS ciphertexts (the key's own material is re-sealed with the KMS entry).
    collection: 'vaultVersions',
    filter: {},
    read: (record) =>
      typeof record.sealed === 'string' && record.kmsKeyId === undefined ? record.sealed : undefined,
    write: (record, sealed) => ({ ...record, sealed }),
    context: (record) =>
      `vault:${String(record.tenantId)}:${String(record.secretId)}:${String(record.version)}`,
  },
  {
    // Dynamic secret engines' revocation handles (vault.ts `leaseHandleContext`).
    collection: 'vaultLeases',
    filter: {},
    read: (record) => (typeof record.handleSealed === 'string' ? record.handleSealed : undefined),
    write: (record, sealed) => ({ ...record, handleSealed: sealed }),
    context: (record) => `vault-lease:${record.id}`,
  },
  {
    // SSH certificate authority keys (ssh.ts `authorityContext`).
    collection: 'sshAuthorities',
    filter: {},
    read: (record) => (typeof record.keySealed === 'string' ? record.keySealed : undefined),
    write: (record, sealed) => ({ ...record, keySealed: sealed }),
    context: (record) => `ssh-authority:${record.id}`,
  },
  {
    // Verifiable credential issuer keys (vc.ts `keyContext`).
    collection: 'vcIssuerKeys',
    filter: {},
    read: (record) => (typeof record.keySealed === 'string' ? record.keySealed : undefined),
    write: (record, sealed) => ({ ...record, keySealed: sealed }),
    context: (record) => `vc-issuer-key:${record.id}`,
  },
  {
    // Shared Signals poll sources' bearer tokens (signal-receiver.ts `pollTokenContext`).
    collection: 'signalSources',
    filter: {},
    read: (record) => {
      const poll = record.poll as { tokenSealed?: unknown } | undefined;
      return typeof poll?.tokenSealed === 'string' ? poll.tokenSealed : undefined;
    },
    write: (record, sealed) => ({
      ...record,
      poll: { ...(record.poll as object), tokenSealed: sealed },
    }),
    context: (record) => `signal-poll:${record.id}`,
  },
];

/**
 * Re-seals every value encrypted with a previous deployment secret using the current one, so the
 * previous secret can be retired. Configure the new `secret` with the old one in
 * `previousSecrets`, run this until `done`, wait a day for pending challenges and assertions to
 * expire, then remove `previousSecrets`. Sessions and API keys are hashed without the secret, so
 * nobody is signed out.
 */
export function createSecretRotation(ctx: ServerContext) {
  return async function rotateSecrets(
    options: SecretRotationOptions = {},
  ): Promise<SecretRotationResult> {
    const batchSize = options.batchSize ?? 200;
    if (!Number.isSafeInteger(batchSize) || batchSize < 1 || batchSize > 2000)
      throw new IamError('INVALID_INPUT', 'batchSize must be an integer between 1 and 2000');
    const limit = options.limit ?? Number.POSITIVE_INFINITY;
    if (limit !== Number.POSITIVE_INFINITY && (!Number.isSafeInteger(limit) || limit < 1))
      throw new IamError('INVALID_INPUT', 'limit must be a positive integer');
    const secrets = [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])];
    const result: SecretRotationResult = {
      resealed: {},
      unreadable: {},
      current: 0,
      complete: true,
      done: true,
    };
    const count = (bucket: Record<string, number>, collection: string) => {
      bucket[collection] = (bucket[collection] ?? 0) + 1;
    };
    for (const field of FIELDS) {
      let after: string | undefined;
      let examined = 0;
      for (;;) {
        const size = Math.min(batchSize, limit - examined);
        if (size <= 0) {
          // The limit stopped this collection after a full page: records may remain unexamined.
          result.complete = false;
          break;
        }
        const page = async (tx: IamStore) => {
          const records = await tx.find(field.collection, field.filter, {
            limit: size,
            ...(after === undefined ? {} : { after }),
          });
          for (const record of records) {
            const sealed = field.read(record);
            if (sealed === undefined) continue;
            const opened = openSecret(sealed, secrets, field.context(record));
            if (!opened) {
              count(result.unreadable, field.collection);
              continue;
            }
            if (opened.index === 0) {
              result.current++;
              continue;
            }
            count(result.resealed, field.collection);
            if (!options.dryRun)
              await tx.put(
                field.collection,
                field.write(
                  record,
                  encryptSecret(opened.value, ctx.options.secret, field.context(record)),
                ),
              );
          }
          return records;
        };
        // Each page reads and rewrites in one short transaction, so a value changed meanwhile is
        // re-read rather than overwritten with a stale copy.
        const records = options.dryRun ? await page(ctx.store) : await ctx.store.transaction(page);
        examined += records.length;
        if (records.length < size) break;
        after = records.at(-1)!.id;
      }
    }
    result.done = result.complete && !(options.dryRun && Object.keys(result.resealed).length);
    return result;
  };
}
