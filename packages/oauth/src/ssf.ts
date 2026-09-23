import { createCipheriv, createDecipheriv, randomBytes, randomUUID } from 'node:crypto';
import { SignJWT, importJWK, type JWK } from 'jose';
import {
  IamError,
  appendAuditEvent,
  tenantTreeActive,
  type AuditEvent,
  type CredentialInput,
  type IamStore,
  type Identity,
  type ResourceRef,
  type StoredRecord,
} from '@better-iam/core';

const CAEP = 'https://schemas.openid.net/secevent/caep/event-type';
const RISC = 'https://schemas.openid.net/secevent/risc/event-type';
const SSF = 'https://schemas.openid.net/secevent/ssf/event-type';
const PUSH = 'urn:ietf:rfc:8935';

/** Security event types the transmitter emits (CAEP and RISC). */
export const sharedSignalEvents = {
  sessionRevoked: `${CAEP}/session-revoked`,
  credentialChange: `${CAEP}/credential-change`,
  identifierChanged: `${RISC}/identifier-changed`,
  accountDisabled: `${RISC}/account-disabled`,
  accountPurged: `${RISC}/account-purged`,
} as const;
export type SharedSignalEvent = (typeof sharedSignalEvents)[keyof typeof sharedSignalEvents];
const supported = Object.values(sharedSignalEvents) as string[];

/** Which IAM audit events become which security event, and the event-specific claims. */
const mapping: Record<string, { type: SharedSignalEvent; claims?: Record<string, string> }> = {
  'auth:session:revoke': { type: sharedSignalEvents.sessionRevoked },
  'auth:session:revoke-others': { type: sharedSignalEvents.sessionRevoked },
  'identity:revoke-sessions': { type: sharedSignalEvents.sessionRevoked },
  'tenant:revoke-sessions': { type: sharedSignalEvents.sessionRevoked },
  'auth:password:change': {
    type: sharedSignalEvents.credentialChange,
    claims: { credential_type: 'password', change_type: 'update' },
  },
  'auth:password:reset': {
    type: sharedSignalEvents.credentialChange,
    claims: { credential_type: 'password', change_type: 'update' },
  },
  'auth:mfa:enable': {
    type: sharedSignalEvents.credentialChange,
    claims: { credential_type: 'app', change_type: 'create' },
  },
  'auth:mfa:disable': {
    type: sharedSignalEvents.credentialChange,
    claims: { credential_type: 'app', change_type: 'delete' },
  },
  'auth:passkey:create': {
    type: sharedSignalEvents.credentialChange,
    claims: { credential_type: 'fido2-platform', change_type: 'create' },
  },
  'auth:passkey:delete': {
    type: sharedSignalEvents.credentialChange,
    claims: { credential_type: 'fido2-platform', change_type: 'delete' },
  },
  'auth:email:change': { type: sharedSignalEvents.identifierChanged },
  'identity:email-change': { type: sharedSignalEvents.identifierChanged },
  'identity:offboard': { type: sharedSignalEvents.accountDisabled },
  'identity:expire': { type: sharedSignalEvents.accountDisabled },
  'identity:delete': { type: sharedSignalEvents.accountPurged },
};

export interface SharedSignalsConfig {
  store: IamStore;
  /** `iam:ssf:streams:*` on `ssf/{streamId}`; `iam.protocolHost` supplies it. */
  authorize(credential: CredentialInput, action: string, resource: ResourceRef): Promise<unknown>;
  authenticate(credential: CredentialInput): Promise<{ identity: { id: string } }>;
  /** The transmitter's issuer (usually the OAuth issuer); receivers check `iss` against it. */
  issuer: string;
  /** Private signing keys (JWKS); the first key with `alg` signs. Publish the public half at `jwksUri`. */
  jwks: { keys: JWK[] };
  /** Where receivers fetch the public keys; defaults to `{issuer}/jwks` (the OAuth provider's JWKS). */
  jwksUri?: string;
  /** Base64-encoded 32-byte key encrypting receivers' authorization headers at rest. */
  encryptionKey: string;
  /** Allows `http://` delivery to loopback addresses, for development and tests only. */
  allowInsecureLocalhost?: boolean;
  /** Per-delivery timeout (default 10 seconds). */
  timeoutMs?: number;
  fetch?: typeof fetch;
}

export interface StreamInput {
  name: string;
  /** The receiver's push endpoint (RFC 8935). */
  endpointUrl: string;
  /** `aud` of the events; defaults to the endpoint URL. */
  audience?: string;
  /** Sent as the `Authorization` header with every delivery (for example `Bearer …`). Write-only. */
  authorization?: string;
  /** Event types to send; defaults to every supported type. */
  events?: string[];
  /** How people are identified: `iss_sub` (default: this issuer and the identity ID) or `email`. */
  subjectFormat?: 'iss_sub' | 'email';
  enabled?: boolean;
}

export interface SharedSignalStream {
  id: string;
  tenantId: string;
  name: string;
  endpointUrl: string;
  audience: string;
  events: string[];
  subjectFormat: 'iss_sub' | 'email';
  enabled: boolean;
  hasAuthorization: boolean;
  createdAt: number;
  updatedAt: number;
  /** Deliveries waiting or retrying. */
  pending: number;
  lastDeliveredAt?: number;
  lastError?: string;
}

export interface SharedSignalDelivery {
  id: string;
  streamId: string;
  eventType: string;
  jti: string;
  status: 'pending' | 'delivered' | 'failed';
  attempts: number;
  createdAt: number;
  nextAttemptAt?: number;
  deliveredAt?: number;
  /** When the delivery was abandoned (status `failed`). */
  failedAt?: number;
  lastError?: string;
}

interface StreamRecord extends StoredRecord {
  name: string;
  endpointUrl: string;
  audience: string;
  sealedAuthorization?: string;
  events: string[];
  subjectFormat: 'iss_sub' | 'email';
  enabled: boolean;
  createdAt: number;
  updatedAt: number;
  lastDeliveredAt?: number;
  lastError?: string;
}
interface DeliveryRecord extends StoredRecord {
  streamId: string;
  eventType: string;
  jti: string;
  set: string;
  status: 'pending' | 'delivered' | 'failed';
  attempts: number;
  createdAt: number;
  nextAttemptAt: number;
  deliveredAt?: number;
  failedAt?: number;
  lastError?: string;
}

const loopback = ['localhost', '127.0.0.1', '[::1]'];
const MAX_ATTEMPTS = 8;
/** Backoff after each failed attempt: 30 s, 2 min, 8 min, ~30 min, then 2 h. */
const backoff = (attempts: number) => Math.min(30_000 * 4 ** (attempts - 1), 2 * 3600_000);

/**
 * An OpenID Shared Signals Framework transmitter: turns IAM audit events (sessions revoked, credentials changed,
 * identifiers changed, accounts disabled or deleted) into signed Security Event Tokens (RFC 8417) with CAEP and RISC
 * event types, and pushes them to each tenant's receivers (RFC 8935) with retries.
 */
export function createSharedSignalsTransmitter(config: SharedSignalsConfig) {
  const key = Buffer.from(config.encryptionKey ?? '', 'base64');
  if (key.length !== 32)
    throw new IamError('configuration', 'SSF encryptionKey must encode exactly 32 bytes.');
  const signer = config.jwks?.keys?.find((candidate) => candidate.alg && candidate.d);
  if (!signer)
    throw new IamError('configuration', 'SSF needs a private signing key with an `alg` in jwks.');
  const issuer = config.issuer.replace(/\/$/, '');
  const jwksUri = config.jwksUri ?? `${issuer}/jwks`;
  const signingKey = importJWK(signer, signer.alg);
  // Reported when an event is signed; never an unhandled rejection at startup.
  signingKey.catch(() => undefined);
  const request = config.fetch ?? fetch;
  const timeoutMs = config.timeoutMs ?? 10_000;

  const seal = (value: string) => {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    return Buffer.concat([
      iv,
      cipher.update(value, 'utf8'),
      cipher.final(),
      cipher.getAuthTag(),
    ]).toString('base64');
  };
  const open = (value: string) => {
    const buffer = Buffer.from(value, 'base64');
    const decipher = createDecipheriv('aes-256-gcm', key, buffer.subarray(0, 12));
    decipher.setAuthTag(buffer.subarray(-16));
    return Buffer.concat([decipher.update(buffer.subarray(12, -16)), decipher.final()]).toString(
      'utf8',
    );
  };

  function endpoint(value: unknown): string {
    let parsed: URL;
    try {
      parsed = new URL(String(value));
    } catch {
      throw new IamError('INVALID_INPUT', 'The receiver endpoint must be an absolute HTTPS URL.');
    }
    const local =
      config.allowInsecureLocalhost &&
      parsed.protocol === 'http:' &&
      loopback.includes(parsed.hostname);
    if (
      (parsed.protocol !== 'https:' && !local) ||
      parsed.username ||
      parsed.password ||
      parsed.hash
    )
      throw new IamError('INVALID_INPUT', 'The receiver endpoint must be an absolute HTTPS URL.');
    return parsed.href;
  }
  function settings(input: Partial<StreamInput>, current?: StreamRecord) {
    const name = input.name ?? current?.name;
    const endpointUrl = endpoint(input.endpointUrl ?? current?.endpointUrl);
    const audience = input.audience ?? current?.audience ?? endpointUrl;
    const events = input.events ?? current?.events ?? supported;
    const subjectFormat = input.subjectFormat ?? current?.subjectFormat ?? 'iss_sub';
    const enabled = input.enabled ?? current?.enabled ?? true;
    if (typeof name !== 'string' || !name.trim() || name.length > 200)
      throw new IamError('INVALID_INPUT', 'A stream name of at most 200 characters is required.');
    if (typeof audience !== 'string' || !audience || audience.length > 2048)
      throw new IamError('INVALID_INPUT', 'The audience must be a non-empty string.');
    if (
      !Array.isArray(events) ||
      !events.length ||
      events.some((type) => !supported.includes(type))
    )
      throw new IamError('INVALID_INPUT', `Supported event types: ${supported.join(', ')}.`);
    if (subjectFormat !== 'iss_sub' && subjectFormat !== 'email')
      throw new IamError('INVALID_INPUT', 'subjectFormat must be iss_sub or email.');
    if (typeof enabled !== 'boolean')
      throw new IamError('INVALID_INPUT', 'enabled must be a boolean.');
    if (
      input.authorization !== undefined &&
      (typeof input.authorization !== 'string' ||
        input.authorization.length > 4096 ||
        /[\r\n]/.test(input.authorization))
    )
      throw new IamError('INVALID_INPUT', 'The authorization header value is invalid.');
    return {
      name: name.trim(),
      endpointUrl,
      audience,
      events: [...new Set(events)],
      subjectFormat,
      enabled,
    };
  }
  async function authorized(
    credential: CredentialInput,
    action: string,
    tenantId: string,
    id: string,
  ) {
    await config.authorize(credential, action, { tenantId, type: 'ssf', id });
    return config.authenticate(credential);
  }
  async function owned(store: IamStore, tenantId: string, streamId: string) {
    const stream =
      typeof streamId === 'string' && streamId
        ? await store.get<StreamRecord>('ssfStreams', streamId)
        : undefined;
    if (!stream || stream.tenantId !== tenantId)
      throw new IamError('NOT_FOUND', 'Stream not found.', 404);
    return stream;
  }
  async function audit(
    tx: IamStore,
    tenantId: string,
    actorId: string,
    action: string,
    id: string,
  ) {
    await appendAuditEvent(tx, {
      id: randomUUID(),
      tenantId,
      actorId,
      action,
      resourceId: id,
      timestamp: Date.now(),
      outcome: 'allow',
    });
  }
  async function summary(
    stream: StreamRecord,
    store: IamStore = config.store,
  ): Promise<SharedSignalStream> {
    const pending = (
      await store.find<DeliveryRecord>('ssfDeliveries', { streamId: stream.id, status: 'pending' })
    ).length;
    return {
      id: stream.id,
      tenantId: stream.tenantId,
      name: stream.name,
      endpointUrl: stream.endpointUrl,
      audience: stream.audience,
      events: [...stream.events],
      subjectFormat: stream.subjectFormat,
      enabled: stream.enabled,
      hasAuthorization: !!stream.sealedAuthorization,
      createdAt: stream.createdAt,
      updatedAt: stream.updatedAt,
      pending,
      ...(stream.lastDeliveredAt ? { lastDeliveredAt: stream.lastDeliveredAt } : {}),
      ...(stream.lastError ? { lastError: stream.lastError } : {}),
    };
  }

  /** A signed Security Event Token for one receiver. */
  async function securityEvent(
    stream: StreamRecord,
    type: string,
    subject: Record<string, unknown>,
    claims: Record<string, unknown>,
    txn?: string,
  ): Promise<{ jti: string; set: string }> {
    const jti = randomUUID();
    const set = await new SignJWT({
      sub_id: subject,
      events: { [type]: claims },
      ...(txn ? { txn } : {}),
    })
      .setProtectedHeader({
        alg: signer!.alg!,
        typ: 'secevent+jwt',
        ...(signer!.kid ? { kid: signer!.kid } : {}),
      })
      .setIssuer(issuer)
      .setAudience(stream.audience)
      .setIssuedAt()
      .setJti(jti)
      .sign(await signingKey);
    return { jti, set };
  }
  async function enqueue(stream: StreamRecord, type: string, jti: string, set: string) {
    const now = Date.now();
    await config.store.transaction((tx) =>
      tx.insert<DeliveryRecord>('ssfDeliveries', {
        id: randomUUID(),
        tenantId: stream.tenantId,
        streamId: stream.id,
        eventType: type,
        jti,
        set,
        status: 'pending',
        attempts: 0,
        createdAt: now,
        nextAttemptAt: now,
      }),
    );
  }
  /** The subject of an event in the stream's format; email falls back to `iss_sub` when the address is gone. */
  async function subjectOf(
    stream: StreamRecord,
    event: AuditEvent,
  ): Promise<Record<string, unknown>> {
    if (event.action === 'tenant:revoke-sessions')
      return { format: 'complex', tenant: { format: 'opaque', id: event.tenantId } };
    if (stream.subjectFormat === 'email') {
      const identity = await config.store.get<Identity>('identities', event.resourceId);
      if (identity?.email) return { format: 'email', email: identity.email };
    }
    return { format: 'iss_sub', iss: issuer, sub: event.resourceId };
  }

  /** Turns one audit event into SETs for every enabled stream of its tenant that wants the event type. */
  async function publish(event: AuditEvent): Promise<number> {
    const mapped = mapping[event.action];
    if (!mapped || event.outcome !== 'allow') return 0;
    const streams = (
      await config.store.find<StreamRecord>('ssfStreams', { tenantId: event.tenantId })
    )
      // Paused streams keep receiving events; their deliveries wait until the stream is enabled again.
      .filter((stream) => stream.events.includes(mapped.type));
    const eventTimestamp = Math.floor(event.timestamp / 1000);
    for (const stream of streams) {
      const claims = {
        event_timestamp: eventTimestamp,
        initiating_entity: event.actorId === event.resourceId ? 'user' : 'admin',
        ...(mapped.claims ?? {}),
      };
      const { jti, set } = await securityEvent(
        stream,
        mapped.type,
        await subjectOf(stream, event),
        claims,
        event.id,
      );
      await enqueue(stream, mapped.type, jti, set);
    }
    return streams.length;
  }

  async function deliver(
    record: DeliveryRecord,
    stream: StreamRecord | undefined,
  ): Promise<boolean> {
    let error: string | undefined;
    if (!stream) error = 'The stream was deleted.';
    else if (!stream.enabled) return false;
    else if (!(await tenantTreeActive(config.store, stream.tenantId)))
      error = 'The tenant is unavailable.';
    else
      try {
        const response = await request(stream.endpointUrl, {
          method: 'POST',
          redirect: 'error',
          signal: AbortSignal.timeout(timeoutMs),
          headers: {
            'content-type': 'application/secevent+jwt',
            accept: 'application/json',
            ...(stream.sealedAuthorization
              ? { authorization: open(stream.sealedAuthorization) }
              : {}),
          },
          body: record.set,
        });
        if (response.status !== 202 && response.status !== 200 && response.status !== 204) {
          const text = (await response.text()).slice(0, 300);
          let detail = '';
          try {
            const body = JSON.parse(text) as { err?: unknown; description?: unknown };
            detail = `: ${String(body.err ?? '')} ${String(body.description ?? '')}`.trimEnd();
          } catch {
            detail = '';
          }
          error = `HTTP ${response.status}${detail}`;
        }
      } catch (cause) {
        error =
          cause instanceof Error && cause.name === 'TimeoutError'
            ? 'The receiver did not answer in time.'
            : 'The receiver is unreachable.';
      }
    const now = Date.now();
    const attempts = record.attempts + 1;
    await config.store.transaction(async (tx) => {
      const failed = !!error && (attempts >= MAX_ATTEMPTS || !stream);
      await tx.put<DeliveryRecord>('ssfDeliveries', {
        ...record,
        attempts,
        status: error ? (failed ? 'failed' : 'pending') : 'delivered',
        nextAttemptAt: error ? now + backoff(attempts) : record.nextAttemptAt,
        ...(error ? { lastError: error } : { deliveredAt: now }),
        // When it was abandoned: retention sweeps keep failed deliveries for a period from here.
        ...(failed ? { failedAt: now } : {}),
      });
      if (stream) {
        const current = await tx.get<StreamRecord>('ssfStreams', stream.id);
        if (current)
          await tx.put<StreamRecord>('ssfStreams', {
            ...current,
            ...(error ? { lastError: error } : { lastDeliveredAt: now, lastError: undefined }),
          });
      }
    });
    return !error;
  }

  /** Sends every due delivery (at most `limit`) and prunes delivered records older than a week. */
  async function dispatch(
    input: { limit?: number } = {},
  ): Promise<{ delivered: number; failed: number }> {
    const now = Date.now();
    const due = (await config.store.find<DeliveryRecord>('ssfDeliveries', { status: 'pending' }))
      .filter((record) => record.nextAttemptAt <= now)
      .sort((a, b) => a.createdAt - b.createdAt)
      .slice(0, input.limit ?? 200);
    const streams = new Map<string, StreamRecord | undefined>();
    let delivered = 0;
    let failed = 0;
    for (const record of due) {
      if (!streams.has(record.streamId))
        streams.set(
          record.streamId,
          await config.store.get<StreamRecord>('ssfStreams', record.streamId),
        );
      const stream = streams.get(record.streamId);
      if (stream && !stream.enabled) continue;
      if (await deliver(record, stream)) delivered++;
      else failed++;
    }
    const weekAgo = now - 7 * 86400_000;
    await config.store.transaction(async (tx) => {
      for (const old of await tx.find<DeliveryRecord>('ssfDeliveries', { status: 'delivered' }))
        if ((old.deliveredAt ?? 0) < weekAgo) await tx.delete('ssfDeliveries', old.id);
    });
    return { delivered, failed };
  }

  const discoveryPath = `/.well-known/ssf-configuration${new URL(issuer).pathname.replace(/\/$/, '')}`;
  /** SSF transmitter metadata (served by `handler` at `/.well-known/ssf-configuration{issuer path}`). */
  const metadata = () => ({
    spec_version: '1_0',
    issuer,
    jwks_uri: jwksUri,
    delivery_methods_supported: [PUSH],
    critical_subject_members: [],
    default_subjects: 'ALL',
  });

  return {
    metadata,
    /** Serves the transmitter metadata; undefined for every other request. */
    handler(request: Request): Response | undefined {
      if (new URL(request.url).pathname !== discoveryPath) return undefined;
      if (request.method !== 'GET' && request.method !== 'HEAD')
        return new Response(null, { status: 405, headers: { allow: 'GET, HEAD' } });
      return Response.json(metadata(), {
        headers: { 'cache-control': 'public, max-age=3600', 'access-control-allow-origin': '*' },
      });
    },
    /** Adds a receiver for the tenant's security events (`iam:ssf:streams:create`). */
    async createStream(
      credential: CredentialInput,
      input: StreamInput & { tenantId: string },
    ): Promise<SharedSignalStream> {
      const id = `ssf-${randomBytes(8).toString('hex')}`;
      const principal = await authorized(credential, 'iam:ssf:streams:create', input.tenantId, id);
      const values = settings(input);
      return config.store.transaction(async (tx) => {
        if (!(await tenantTreeActive(tx, input.tenantId)))
          throw new IamError('TENANT_INACTIVE', 'Tenant unavailable.', 403);
        const now = Date.now();
        const record: StreamRecord = {
          id,
          tenantId: input.tenantId,
          ...values,
          ...(input.authorization ? { sealedAuthorization: seal(input.authorization) } : {}),
          createdAt: now,
          updatedAt: now,
        };
        await tx.insert('ssfStreams', record);
        await audit(tx, input.tenantId, principal.identity.id, 'iam:ssf:CreateStream', id);
        return summary(record, tx);
      });
    },
    async listStreams(
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<SharedSignalStream[]> {
      await authorized(credential, 'iam:ssf:streams:read', input.tenantId, '*');
      const streams = await config.store.find<StreamRecord>('ssfStreams', {
        tenantId: input.tenantId,
      });
      return Promise.all(
        streams
          .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1))
          .map((s) => summary(s)),
      );
    },
    async getStream(
      credential: CredentialInput,
      input: { tenantId: string; streamId: string },
    ): Promise<SharedSignalStream> {
      await authorized(credential, 'iam:ssf:streams:read', input.tenantId, input.streamId);
      return summary(await owned(config.store, input.tenantId, input.streamId));
    },
    /** Changes a stream; `authorization: null` removes the header. Pausing holds deliveries until resumed. */
    async updateStream(
      credential: CredentialInput,
      input: Partial<Omit<StreamInput, 'authorization'>> & {
        tenantId: string;
        streamId: string;
        authorization?: string | null;
      },
    ): Promise<SharedSignalStream> {
      const principal = await authorized(
        credential,
        'iam:ssf:streams:update',
        input.tenantId,
        input.streamId,
      );
      return config.store.transaction(async (tx) => {
        const current = await owned(tx, input.tenantId, input.streamId);
        const values = settings(
          { ...input, authorization: input.authorization ?? undefined },
          current,
        );
        const record: StreamRecord = {
          ...current,
          ...values,
          updatedAt: Date.now(),
        };
        if (input.authorization === null) delete record.sealedAuthorization;
        else if (input.authorization !== undefined)
          record.sealedAuthorization = seal(input.authorization);
        await tx.put('ssfStreams', record);
        await audit(tx, input.tenantId, principal.identity.id, 'iam:ssf:UpdateStream', current.id);
        return summary(record, tx);
      });
    },
    /** Removes a stream and drops its undelivered events. */
    async deleteStream(
      credential: CredentialInput,
      input: { tenantId: string; streamId: string },
    ): Promise<void> {
      const principal = await authorized(
        credential,
        'iam:ssf:streams:delete',
        input.tenantId,
        input.streamId,
      );
      await config.store.transaction(async (tx) => {
        const current = await owned(tx, input.tenantId, input.streamId);
        for (const record of await tx.find<DeliveryRecord>('ssfDeliveries', {
          streamId: current.id,
        }))
          await tx.delete('ssfDeliveries', record.id);
        await tx.delete('ssfStreams', current.id);
        await audit(tx, input.tenantId, principal.identity.id, 'iam:ssf:DeleteStream', current.id);
      });
    },
    /**
     * Sends an SSF verification event (`state` echoes back) straight away, so administrators can check the endpoint,
     * credentials, and key setup. Returns whether the receiver accepted it.
     */
    async verifyStream(
      credential: CredentialInput,
      input: { tenantId: string; streamId: string; state?: string },
    ): Promise<{ delivered: boolean; error?: string; jti: string }> {
      await authorized(credential, 'iam:ssf:streams:update', input.tenantId, input.streamId);
      const stream = await owned(config.store, input.tenantId, input.streamId);
      const state = input.state ?? randomBytes(12).toString('base64url');
      const { jti, set } = await securityEvent(
        stream,
        `${SSF}/verification`,
        { format: 'opaque', id: stream.id },
        { state },
      );
      await enqueue(stream, `${SSF}/verification`, jti, set);
      const record = (await config.store.find<DeliveryRecord>('ssfDeliveries', { jti }))[0]!;
      const delivered = await deliver(record, stream);
      const after = await config.store.get<DeliveryRecord>('ssfDeliveries', record.id);
      return {
        delivered,
        jti,
        ...(after?.lastError && !delivered ? { error: after.lastError } : {}),
      };
    },
    /** Recent deliveries of a stream, newest first (`iam:ssf:streams:read`). */
    async listDeliveries(
      credential: CredentialInput,
      input: {
        tenantId: string;
        streamId: string;
        status?: SharedSignalDelivery['status'];
        limit?: number;
      },
    ): Promise<SharedSignalDelivery[]> {
      await authorized(credential, 'iam:ssf:streams:read', input.tenantId, input.streamId);
      await owned(config.store, input.tenantId, input.streamId);
      return (
        await config.store.find<DeliveryRecord>('ssfDeliveries', { streamId: input.streamId })
      )
        .filter((record) => !input.status || record.status === input.status)
        .sort((a, b) => b.createdAt - a.createdAt)
        .slice(0, Math.min(input.limit ?? 50, 500))
        .map((record) => ({
          id: record.id,
          streamId: record.streamId,
          eventType: record.eventType,
          jti: record.jti,
          status: record.status,
          attempts: record.attempts,
          createdAt: record.createdAt,
          ...(record.status === 'pending' ? { nextAttemptAt: record.nextAttemptAt } : {}),
          ...(record.deliveredAt ? { deliveredAt: record.deliveredAt } : {}),
          ...(record.failedAt ? { failedAt: record.failedAt } : {}),
          ...(record.lastError ? { lastError: record.lastError } : {}),
        }));
    },
    /** Queues SETs for one audit event; `subscribe` calls it for you. Returns the number of streams addressed. */
    publish,
    /** Deployment operation: sends due deliveries (retrying with backoff up to eight attempts). */
    dispatch,
    /**
     * Publishes matching IAM events as they are dispatched (`iam.events`), then delivers them. Returns the
     * unsubscribe function. Pair it with a periodic `dispatch()` for retries.
     */
    subscribe(
      events: { subscribe(pattern: string[], handler: (event: AuditEvent) => unknown): () => void },
      options: { onError?(error: unknown): void } = {},
    ): () => void {
      return events.subscribe(Object.keys(mapping), async (event) => {
        try {
          if ((await publish(event)) > 0) await dispatch();
        } catch (error) {
          options.onError?.(error);
        }
      });
    },
  };
}

export type SharedSignalsTransmitter = ReturnType<typeof createSharedSignalsTransmitter>;
