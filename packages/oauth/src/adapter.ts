import { createCipheriv, createDecipheriv, createHash, randomBytes } from 'node:crypto';
import { errors, type Adapter, type AdapterConstructor, type AdapterPayload } from 'oidc-provider';
import {
  IamError,
  tenantTreeActive,
  type IamStore,
  type Identity,
  type Session,
  type StoredRecord,
} from '@better-iam/core';

export interface ClientRow extends StoredRecord {
  clientId: string;
  encrypted: string;
  revoked: boolean;
  serviceAccountId?: string;
  /** Resource indicators (RFC 8707) the client may request access tokens for. */
  resources?: string[];
  createdAt?: number;
  updatedAt?: number;
  secretRotatedAt?: number;
  /** A first-party application; reported to the consent screen. */
  firstParty?: boolean;
  /** How a dynamically registered client got here: a registration token ID, or `anonymous`. */
  registeredVia?: string;
}
export interface Artifact extends StoredRecord {
  model: string;
  boundTenantId: string;
  encrypted: string;
  expiresAt: number;
  clientId?: string;
  accountId?: string;
  uidHash?: string;
  userCodeHash?: string;
  grantIdHash?: string;
}
export interface GrantSession extends StoredRecord {
  sessionId: string;
  identityId: string;
}

export const hash = (text: string): string => createHash('sha256').update(text).digest('hex');
/** Sentinel tenant for artifacts that exist before any client or account is known (for example interactions). */
export const PROTOCOL_TENANT = '__protocol__';

/** AES-256-GCM sealing for provider artifacts; the key is separate from signing and cookie keys. */
export function cipher(key: Buffer) {
  return {
    seal(value: unknown): string {
      const iv = randomBytes(12);
      const crypt = createCipheriv('aes-256-gcm', key, iv);
      return Buffer.concat([
        iv,
        crypt.update(JSON.stringify(value)),
        crypt.final(),
        crypt.getAuthTag(),
      ]).toString('base64');
    },
    open<T>(value: string): T {
      const buffer = Buffer.from(value, 'base64');
      const crypt = createDecipheriv('aes-256-gcm', key, buffer.subarray(0, 12));
      crypt.setAuthTag(buffer.subarray(-16));
      return JSON.parse(
        Buffer.concat([crypt.update(buffer.subarray(12, -16)), crypt.final()]).toString('utf8'),
      ) as T;
    },
  };
}
export function encryptionKey(encoded: string): Buffer {
  const key = Buffer.from(encoded, 'base64');
  if (key.length !== 32)
    throw new IamError('configuration', 'OAuth encryptionKey must encode exactly 32 bytes.');
  return key;
}

/**
 * Provider persistence with encrypted payloads and hashed token identifiers. Every artifact is bound to the
 * tenant of its client and account, and every user grant is re-validated against its IAM session on each use.
 */
export function createProviderAdapter(
  store: IamStore,
  encodedKey: string,
  validateSession?: (sessionId: string) => Promise<unknown>,
  /** Stores a client created by dynamic registration; without it, only `registerClient()` creates clients. */
  registerClient?: (clientId: string, payload: AdapterPayload) => Promise<void>,
): AdapterConstructor {
  const crypt = cipher(encryptionKey(encodedKey));
  const pendingRevocations = new Map<string, Promise<void>>();
  async function client(id: string): Promise<ClientRow | undefined> {
    const row = await store.get<ClientRow>('oauthClients', hash(id));
    if (!row || row.revoked || !(await tenantTreeActive(store, row.tenantId))) return undefined;
    if (row.serviceAccountId) {
      const service = await store.get<Identity>('identities', row.serviceAccountId);
      if (
        !service ||
        service.kind !== 'service' ||
        service.status !== 'active' ||
        service.tenantId !== row.tenantId
      )
        return undefined;
    }
    return row;
  }
  async function validGrantSession(grantId: string, accountId?: string): Promise<void> {
    if (await store.get('oauthRevokedGrants', hash(grantId)))
      throw new errors.InvalidGrant('Grant is revoked.');
    const binding = await store.get<GrantSession>('oauthGrantSessions', hash(grantId));
    if (!binding || (accountId && binding.identityId !== accountId))
      throw new errors.InvalidGrant('Grant has no valid IAM session binding.');
    const session = await store.get<Session>('sessions', binding.sessionId);
    const identity = await store.get<Identity>('identities', binding.identityId);
    const mfa = await store.get('authMfa', binding.identityId);
    const usable =
      session &&
      identity &&
      session.kind === 'user' &&
      session.identityId === binding.identityId &&
      session.tenantId === binding.tenantId &&
      identity.tenantId === binding.tenantId &&
      identity.status === 'active' &&
      session.expiresAt > Date.now() &&
      (validateSession || Date.now() - session.lastSeenAt < 86400_000) &&
      !((identity.rootAdmin || mfa?.enabled) && !session.mfa) &&
      (await tenantTreeActive(store, binding.tenantId));
    if (!usable) throw new errors.InvalidGrant('IAM session is unavailable.');
    if (validateSession) await validateSession(session.id);
  }
  /** The tenant an artifact belongs to, derived from its client and account, which must agree. */
  async function scope(payload: AdapterPayload): Promise<string> {
    let tenantId: string | undefined;
    const clientId =
      payload.clientId ??
      (typeof payload.params?.client_id === 'string' ? payload.params.client_id : undefined);
    if (clientId) {
      const row = await client(clientId);
      if (!row) throw new errors.InvalidClient('Client is unavailable.');
      tenantId = row.tenantId;
    }
    if (payload.accountId) {
      const identity = await store.get<Identity>('identities', payload.accountId);
      if (
        !identity ||
        identity.status !== 'active' ||
        !(await tenantTreeActive(store, identity.tenantId))
      )
        throw new errors.InvalidGrant('Account is unavailable.');
      if (tenantId && identity.tenantId !== tenantId)
        throw new errors.InvalidGrant('Account and client belong to different tenants.');
      tenantId = identity.tenantId;
    }
    if (payload.grantId) {
      if (await store.get('oauthRevokedGrants', hash(payload.grantId)))
        throw new errors.InvalidGrant('Grant is revoked.');
      await validGrantSession(payload.grantId, payload.accountId);
    }
    return tenantId ?? PROTOCOL_TENANT;
  }
  class PersistentAdapter implements Adapter {
    constructor(private readonly model: string) {}
    async upsert(id: string, payload: AdapterPayload, expiresIn = 86400): Promise<void> {
      if (this.model === 'Client') {
        if (!registerClient)
          throw new IamError('PROTECTED_OPERATION', 'Use authenticated registerClient().', 403);
        return registerClient(id, payload);
      }
      await store.transaction(async (tx) => {
        const tenantId = await scope(payload);
        const recordId = hash(`${this.model}:${id}`);
        const previous = await tx.get<Artifact>('oauthArtifacts', recordId);
        if (
          previous &&
          previous.boundTenantId !== PROTOCOL_TENANT &&
          previous.boundTenantId !== tenantId
        )
          throw new errors.InvalidGrant('Immutable tenant binding changed.');
        const record: Artifact = {
          id: recordId,
          tenantId: previous?.tenantId ?? tenantId,
          boundTenantId: tenantId,
          model: this.model,
          encrypted: crypt.seal(payload),
          expiresAt: Date.now() + expiresIn * 1000,
          clientId: payload.clientId,
          accountId: payload.accountId,
          uidHash: payload.uid ? hash(payload.uid) : undefined,
          userCodeHash: payload.userCode ? hash(payload.userCode) : undefined,
          grantIdHash: payload.grantId ? hash(payload.grantId) : undefined,
        };
        if (previous) await tx.put('oauthArtifacts', record);
        else await tx.insert('oauthArtifacts', record);
      });
    }
    private async unpack(row: Artifact | undefined): Promise<AdapterPayload | undefined> {
      if (!row || row.expiresAt <= Date.now()) return undefined;
      const payload = crypt.open<AdapterPayload>(row.encrypted);
      try {
        if (row.boundTenantId !== (await scope(payload))) return undefined;
      } catch {
        return undefined;
      }
      if (this.model === 'Grant' && payload.jti) {
        try {
          await validGrantSession(payload.jti, payload.accountId);
        } catch {
          return undefined;
        }
      }
      if (this.model === 'Session' && payload.accountId) {
        const grants = Object.values(payload.authorizations ?? {}).flatMap((value) =>
          value.grantId ? [value.grantId] : [],
        );
        if (!grants.length) return undefined;
        const validity = await Promise.all(
          grants.map(async (grant) => {
            try {
              await validGrantSession(grant, payload.accountId);
              return true;
            } catch {
              return false;
            }
          }),
        );
        if (!validity.some(Boolean)) return undefined;
      }
      if (row.grantIdHash && (await store.get('oauthRevokedGrants', row.grantIdHash)))
        return undefined;
      return payload;
    }
    async find(id: string): Promise<AdapterPayload | undefined> {
      if (this.model === 'Client') {
        const row = await client(id);
        return row ? crypt.open<AdapterPayload>(row.encrypted) : undefined;
      }
      return this.unpack(await store.get<Artifact>('oauthArtifacts', hash(`${this.model}:${id}`)));
    }
    async findByUid(uid: string): Promise<AdapterPayload | undefined> {
      return this.unpack(
        (
          await store.find<Artifact>('oauthArtifacts', { model: this.model, uidHash: hash(uid) })
        )[0],
      );
    }
    async findByUserCode(userCode: string): Promise<AdapterPayload | undefined> {
      return this.unpack(
        (
          await store.find<Artifact>('oauthArtifacts', {
            model: this.model,
            userCodeHash: hash(userCode),
          })
        )[0],
      );
    }
    async destroy(id: string): Promise<void> {
      await store.transaction((tx) => tx.delete('oauthArtifacts', hash(`${this.model}:${id}`)));
    }
    /** Single use: a second consumption revokes the whole grant family, including tokens issued by a racing request. */
    async consume(id: string): Promise<void> {
      const outcome = await store.transaction(async (tx) => {
        const row = await tx.get<Artifact>('oauthArtifacts', hash(`${this.model}:${id}`));
        if (!row || row.expiresAt <= Date.now()) return { invalid: true };
        const payload = crypt.open<AdapterPayload>(row.encrypted);
        if (payload.consumed) return { invalid: true, grantId: payload.grantId };
        payload.consumed = Math.floor(Date.now() / 1000);
        await tx.put('oauthArtifacts', { ...row, encrypted: crypt.seal(payload) });
        return { invalid: false };
      });
      // Commit family revocation before throwing. Rejected requests cannot roll it back.
      if (outcome.invalid) {
        if (outcome.grantId) await this.revokeByGrantId(outcome.grantId);
        throw new errors.InvalidGrant('Credential is unavailable or has already been consumed.');
      }
    }
    async revokeByGrantId(grantId: string): Promise<void> {
      const grantIdHash = hash(grantId);
      const pending = pendingRevocations.get(grantIdHash);
      if (pending) return pending;
      const operation = store.transaction(async (tx) => {
        if (!(await tx.get('oauthRevokedGrants', grantIdHash)))
          await tx.insert('oauthRevokedGrants', {
            id: grantIdHash,
            tenantId: PROTOCOL_TENANT,
            revokedAt: Date.now(),
          });
        for (const row of await tx.find<Artifact>('oauthArtifacts', { grantIdHash }))
          await tx.delete('oauthArtifacts', row.id);
        await tx.delete('oauthArtifacts', hash(`Grant:${grantId}`));
      });
      pendingRevocations.set(grantIdHash, operation);
      try {
        await operation;
      } finally {
        pendingRevocations.delete(grantIdHash);
      }
    }
  }
  return PersistentAdapter;
}
