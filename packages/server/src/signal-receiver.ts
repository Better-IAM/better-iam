import { createHash } from 'node:crypto';
import {
  createLocalJWKSet,
  createRemoteJWKSet,
  customFetch,
  decodeProtectedHeader,
  errors,
  jwtVerify,
  type JSONWebKeySet,
  type JWSHeaderParameters,
  type JWTPayload,
  type JWTVerifyGetKey,
  type JWTVerifyOptions,
} from 'jose';
import { decryptSecret, encryptSecret } from '@better-iam/auth';
import {
  IamError,
  readSecurityEvent,
  SignalFormatError,
  userSubjects,
  type IamStore,
  type Identity,
  type Json,
  type SecurityEventClaims,
  type Session,
  type SignalEventType,
  type StoredRecord,
  type SubjectIdentifier,
  type Tenant,
} from '@better-iam/core';
import type { TenantDomain } from './api/domains.js';
import type { ServerContext } from './context.js';
import type { PublicJwk } from './models.js';
import type { ProtocolMount } from './options.js';
import { checkFetchUrl, createGuardedFetch, SafeFetchError } from './safe-fetch.js';
import { byId, hash, id, sameHash } from './utils.js';
import { email as normalizedEmail } from './validation.js';
import { WEB_IDENTITY_ALGORITHMS } from './web-identity.js';

/**
 * The Shared Signals receiver (OpenID SSF 1.0 with CAEP and RISC): security events an upstream identity provider sends
 * about the tenant's people. Each tenant registers its transmitters as signal sources (`signals` API group); events
 * arrive by push (RFC 8935, the `{signals.pushPath}/{sourceId}` protocol mount) or by poll (RFC 8936,
 * `iam.signals.poll()`), are verified against the source's keys, deduplicated on issuer and `jti`, mapped to an
 * identity of the source's tenant, recorded (`signalEvents`), and audited as `signal:received`, which threat detection
 * reads. The only action taken directly is ending sessions, and only for event types a source configures that way;
 * containment is left to threat-detection playbooks.
 */

/** Where the receiver keeps its records; both are tenant-scoped and purged with the tenant (lifecycle.ts). */
export const signalCollections = { sources: 'signalSources', events: 'signalEvents' } as const;

/** Signature algorithms a source may allow. Symmetric algorithms and `none` are never accepted. */
export type SignalAlgorithm = (typeof WEB_IDENTITY_ALGORITHMS)[number];
/** Used when a source does not name its algorithms. */
export const DEFAULT_SIGNAL_ALGORITHMS: readonly SignalAlgorithm[] = [
  'RS256',
  'ES256',
  'PS256',
  'EdDSA',
];
/** Signal sources one tenant may register. */
export const maxSignalSourcesPerTenant = 20;

/** What the receiver does with a matched event: record it (the default), or also end the person's sessions. */
export type SignalAction = 'record' | 'revoke-sessions';
/** How a source's events arrive: pushed to the receiver (RFC 8935) or polled from the transmitter (RFC 8936). */
export type SignalDelivery = 'push' | 'poll';
export type SignalSourceStatus = 'active' | 'disabled';
/**
 * A received event's outcome: `applied` (its configured action ran), `recorded` (kept, nothing to do or only record),
 * `unmatched` (no identity of the tenant matched its subject), `ignored` (an unsupported event type, or an action
 * refused for a protected identity) or `failed` (processing failed; an administrator may reprocess it).
 */
export type SignalStatus = 'applied' | 'recorded' | 'unmatched' | 'ignored' | 'failed';
/** Event types a source may configure an action for: every known type except the SSF control events. */
export type SignalActionableEvent = Exclude<
  SignalEventType,
  'verification' | 'stream-updated' | 'unknown'
>;

/** How a source's subjects are matched to the tenant's identities. */
export interface SignalSubjectMapping {
  /**
   * Sign-in connections (OAuth/OIDC login connection or SAML connection ids) whose federation links map `iss_sub`
   * subjects: a subject of the source's issuer (or an alias) matches the identity linked to that subject.
   */
  connectionIds: string[];
  /** Match `email` and `acct:` subjects to identities by email, only for domains the tenant verified. */
  matchEmail: boolean;
  /** SCIM connections whose provisioned users' `externalId` maps `iss_sub` and `opaque` subjects. */
  scimConnectionIds: string[];
}

/** A poll source's transmitter endpoint and the receiver's place in its queue. */
export interface SignalPollState {
  /** The transmitter's RFC 8936 poll endpoint. */
  endpoint: string;
  /** The bearer token for the endpoint, sealed with the deployment secret (`rotateSecrets` re-seals it). */
  tokenSealed: string;
  /** Events asked for per request. */
  maxEvents: number;
  /** `jti`s committed since the last successful request, acknowledged with the next one. */
  pendingAcks: string[];
  /** Events refused since the last successful request (`setErrs` of the next one), by `jti`. */
  pendingErrors?: Record<string, { err: string; description: string }>;
  lastPolledAt?: number;
}

/**
 * A registered transmitter (`signalSources`, natural key `issuer:{issuer}` per tenant). `updatedAt` versions the
 * settings verification depends on and moves only when an administrator changes the source; the receiver's own
 * bookkeeping (`lastEventAt`, `lastError`, poll state) leaves it alone.
 */
export interface SignalSource extends StoredRecord {
  name: string;
  /** The transmitter's `iss`, without a trailing slash (both spellings are accepted on SETs). */
  issuer: string;
  /** Other spellings of the issuer its SETs or federation links use (at most 5, without trailing slashes). */
  issuerAliases: string[];
  /** Accepted `aud` values (1 to 10); a SET must name one of them. */
  audiences: string[];
  /** Where the transmitter's keys live; without it and without `jwks`, SSF discovery on the issuer. */
  jwksUri?: string;
  /** Static public keys, used instead of fetching. */
  jwks?: { keys: PublicJwk[] };
  algorithms: SignalAlgorithm[];
  delivery: SignalDelivery;
  /** SHA-256 of the bearer token the transmitter presents on pushes, when the source has one. */
  pushTokenHash?: string;
  poll?: SignalPollState;
  subjects: SignalSubjectMapping;
  /** The action per event type; unlisted types are recorded only. */
  actions: Partial<Record<SignalActionableEvent, SignalAction>>;
  /** Require the `secevent+jwt` token type (default); false tolerates legacy RISC transmitters. */
  requireTyp: boolean;
  /**
   * When set, a SET must carry a `tenant_id` claim equal to it. A Better IAM transmitter signs every organization's
   * events with one issuer and key, so without this another organization of that deployment could point its own
   * stream at this source (with this source's audience) and have its events accepted here.
   */
  tenantClaim?: string;
  status: SignalSourceStatus;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
  lastEventAt?: number;
  /** The last refusal or transport failure, or a transmitter that paused or disabled the stream. */
  lastError?: { at: number; message: string };
  /** When the transmitter last sent a verification event. */
  lastVerifiedAt?: number;
}

/** A received security event (`signalEvents`, natural key `jti:{sha256(issuer|jti)}`), kept for 90 days. */
export interface ReceivedSignal extends StoredRecord {
  sourceId: string;
  /** The source id again, under the indexed lookup field `streamId`. */
  streamId: string;
  jti: string;
  eventType: SignalEventType;
  eventUri: string;
  /** The SET's `iat`, in epoch milliseconds. */
  issuedAt: number;
  /** When the event happened, per the transmitter (epoch milliseconds). */
  eventTimestamp?: number;
  txn?: string;
  /** The subject as parsed (RFC 9493 form), when the SET named one. */
  subject?: Record<string, Json>;
  /** The identity of the source's tenant the subject matched. */
  identityId?: string;
  status: SignalStatus;
  reason?: string;
  /** The event's own claims (at most 4 KiB; larger ones keep their shorter members and `_truncated`). */
  claims: Record<string, Json>;
  receivedAt: number;
  /** `receivedAt` again: the ordered field the event list pages by. */
  timestamp: number;
  /** When the retention sweep deletes the record. */
  expiresAt: number;
  reprocessedAt?: number;
  reprocessedBy?: string;
}

/** RFC 8935 / RFC 8936 error codes the receiver answers a refused SET with. */
export type SignalErrorCode =
  | 'invalid_request'
  | 'invalid_key'
  | 'invalid_issuer'
  | 'invalid_audience';

/**
 * A refused security event token. `err` is the RFC 8935 error code, the message its description. `temporary` marks a
 * refusal that may pass later (the source's keys could not be fetched): pushes answer 503 and polls leave the event
 * unacknowledged, so the transmitter delivers it again.
 */
export class SignalRejectedError extends IamError {
  constructor(
    readonly err: SignalErrorCode,
    description: string,
    readonly temporary = false,
  ) {
    super('SIGNAL_REJECTED', description, 400);
    this.name = 'SignalRejectedError';
  }
}

/** The outcome of accepting one security event. */
export interface SignalReceipt {
  /** The received event's id (`signals.getEvent`). */
  eventId: string;
  status: SignalStatus;
  /** The event had been received before (same issuer and `jti`); nothing was done again. */
  duplicate: boolean;
  identityId?: string;
}

/** What one poll run did. */
export interface SignalPollResult {
  /** Poll sources polled. */
  sources: number;
  /** New events recorded (duplicates excluded). */
  received: number;
  /** Events acknowledged to transmitters. */
  acknowledged: number;
  /** Failed poll requests and events left unacknowledged for redelivery. */
  errors: number;
}

/** The receiver's server-side runtime (`iam.signals`). */
export interface IamSignals {
  /**
   * Polls every active poll source (or one): acknowledges what earlier runs committed, then fetches, verifies and
   * records events, following `moreAvailable` for at most five requests per source. A scheduler job; run it every
   * minute or so.
   */
  poll(input?: { sourceId?: string }): Promise<SignalPollResult>;
  /**
   * Verifies and records one compact security event token for a source, as the push endpoint does: for custom
   * transports and tests. Throws `SignalRejectedError` for a refused token and NOT_FOUND for an unknown or disabled
   * source.
   */
  receive(sourceId: string, set: string): Promise<SignalReceipt>;
}

const DAY = 86_400_000;
const SIGNAL_RETENTION_MS = 90 * DAY;
const MAX_SET_BYTES = 16_384;
const MAX_PUSH_BYTES = 65_536;
const MAX_CLAIMS_CHARS = 4096;
const MAX_SUBJECT_CHARS = 8192;
const CLOCK_TOLERANCE_SECONDS = 300;
const MAX_SET_AGE_SECONDS = 7 * 86_400;
/** Pushes per source per rate-limit window. */
const PUSHES_PER_WINDOW = 3000;
const POLL_REQUESTS_PER_RUN = 5;
const POLL_TIMEOUT_MS = 10_000;
const POLL_MAX_BYTES = 1_048_576;
const JWKS_MAX_BYTES = 262_144;
const DISCOVERY_MAX_BYTES = 65_536;
const FETCH_TIMEOUT_MS = 5000;
const NEGATIVE_CACHE_MS = 30_000;
const REDISCOVER_MS = DAY;
const MAX_CACHED_SOURCES = 1000;
/** Keys tried when several of a source's keys match a token. */
const MAX_CANDIDATE_KEYS = 20;
const compactJws = /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/;
const sourceIdShape = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const forbiddenHeaders = ['jwk', 'jku', 'x5u', 'x5c'] as const;
/** Token types a source that does not require `secevent+jwt` still accepts (as well as none at all). */
const lenientTypes = new Set(['secevent+jwt', 'jwt']);
const unsafeKeys = new Set(['__proto__', 'constructor', 'prototype']);

const trimSlashes = (value: string) => value.replace(/\/+$/, '');
const clip = (value: string, max: number) => (value.length > max ? value.slice(0, max) : value);
const plain = (value: unknown): Record<string, unknown> | undefined =>
  value !== null && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
const own = (value: Record<string, unknown>, key: string): unknown =>
  Object.hasOwn(value, key) ? value[key] : undefined;
const normalizedTyp = (value: string) => {
  const lower = value.toLowerCase();
  return lower.startsWith('application/') ? lower.slice('application/'.length) : lower;
};

/** The system actor of the receiver's own audit events: `signal:{sourceId}`. */
export const signalActor = (sourceId: string) => `signal:${sourceId}`;
/** The encryption context of a poll source's bearer token: binds the ciphertext to its source. */
export const pollTokenContext = (sourceId: string) => `signal-poll:${sourceId}`;

/** Seals a poll source's bearer token with the current deployment secret. */
export function sealPollToken(ctx: ServerContext, sourceId: string, token: string): string {
  return encryptSecret(token, ctx.options.secret, pollTokenContext(sourceId));
}

/** Opens a poll source's bearer token with the current secret or a previous one. */
function openPollToken(ctx: ServerContext, source: SignalSource): string {
  return decryptSecret(
    source.poll!.tokenSealed,
    [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])],
    pollTokenContext(source.id),
  );
}

/** The issuer and its aliases, without trailing slashes. */
function issuerForms(source: SignalSource): string[] {
  return [...new Set([source.issuer, ...source.issuerAliases].map(trimSlashes))];
}

/** Whether an issuer names the source (its issuer or an alias, with or without a trailing slash). */
export function namesSignalSource(source: SignalSource, issuer: string): boolean {
  return issuerForms(source).includes(trimSlashes(issuer));
}

/** The received event's natural key: the SHA-256 of the source's issuer and the `jti`. */
export function signalEventKey(issuer: string, jti: string): string {
  return `jti:${createHash('sha256')
    .update(`${trimSlashes(issuer)}|${jti}`)
    .digest('hex')}`;
}

/** A plain JSON copy without prototype-polluting keys (storage refuses them), non-finite numbers or deep nesting. */
function jsonCopy(value: unknown, depth = 0): Json | undefined {
  if (value === null || typeof value === 'string' || typeof value === 'boolean') return value;
  if (typeof value === 'number') return Number.isFinite(value) ? value : undefined;
  if (depth >= 16 || typeof value !== 'object') return undefined;
  if (Array.isArray(value)) return value.map((entry) => jsonCopy(entry, depth + 1) ?? null);
  const result: Record<string, Json> = {};
  for (const [key, entry] of Object.entries(value)) {
    if (unsafeKeys.has(key)) continue;
    const copied = jsonCopy(entry, depth + 1);
    if (copied !== undefined) result[key] = copied;
  }
  return result;
}

/** The event claims as stored: all of them up to 4 KiB, else the members that fit (long strings shortened). */
function storedClaims(event: Record<string, unknown>): Record<string, Json> {
  const copy = (jsonCopy(event) ?? {}) as Record<string, Json>;
  if (JSON.stringify(copy).length <= MAX_CLAIMS_CHARS) return copy;
  const kept: Record<string, Json> = { _truncated: true };
  let size = JSON.stringify(kept).length;
  for (const [key, value] of Object.entries(copy)) {
    const entry = typeof value === 'string' ? clip(value, 256) : value;
    const cost = JSON.stringify({ [key]: entry }).length;
    if (size + cost > MAX_CLAIMS_CHARS) continue;
    kept[key] = entry;
    size += cost;
  }
  return kept;
}

function storedSubject(subject: SubjectIdentifier | undefined): Record<string, Json> | undefined {
  if (!subject) return undefined;
  const copy = jsonCopy(subject) as Record<string, Json>;
  return JSON.stringify(copy).length <= MAX_SUBJECT_CHARS
    ? copy
    : { format: subject.format, _truncated: true };
}

/** A localized claim (CAEP `reason_admin` is a language map; some transmitters send a plain string). */
function localized(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  const map = plain(value);
  if (!map) return undefined;
  const english = own(map, 'en');
  if (typeof english === 'string') return english;
  return Object.values(map).find((entry): entry is string => typeof entry === 'string');
}

/** A person of the source's tenant (not a service account or agent, not deleted), or undefined. */
async function person(
  tx: IamStore,
  source: SignalSource,
  identityId: unknown,
): Promise<Identity | undefined> {
  if (typeof identityId !== 'string' || !identityId) return undefined;
  const identity = await tx.get<Identity>('identities', identityId);
  if (
    !identity ||
    identity.tenantId !== source.tenantId ||
    identity.status === 'deleted' ||
    identity.kind === 'service' ||
    identity.kind === 'agent'
  )
    return undefined;
  return identity;
}

/** Federation links store the connection's issuer spelled as its tokens did: try every spelling the source accepts. */
function linkIssuers(source: SignalSource, iss: string): string[] {
  const spellings = [iss, trimSlashes(iss), `${trimSlashes(iss)}/`];
  for (const form of issuerForms(source)) spellings.push(form, `${form}/`);
  return [...new Set(spellings)];
}

async function byFederationLink(
  tx: IamStore,
  source: SignalSource,
  iss: string,
  sub: string,
): Promise<string | undefined> {
  for (const connectionId of source.subjects.connectionIds)
    for (const issuer of linkIssuers(source, iss)) {
      const link = (
        await tx.find('externalIdentities', {
          tenantId: source.tenantId,
          uniqueKey: JSON.stringify([connectionId, issuer, sub]),
        })
      )[0];
      const identity = link ? await person(tx, source, link.identityId) : undefined;
      if (identity) return identity.id;
    }
  return undefined;
}

async function byScimExternalId(
  tx: IamStore,
  source: SignalSource,
  externalId: string,
): Promise<string | undefined> {
  for (const connectionId of source.subjects.scimConnectionIds)
    for (const link of await tx.find('scimUsers', {
      tenantId: source.tenantId,
      connectionId,
      externalId,
    })) {
      const identity = await person(tx, source, link.identityId);
      if (identity) return identity.id;
    }
  return undefined;
}

async function byVerifiedEmail(
  tx: IamStore,
  source: SignalSource,
  address: string,
): Promise<string | undefined> {
  if (!source.subjects.matchEmail) return undefined;
  let normalized: string;
  try {
    normalized = normalizedEmail(address);
  } catch {
    return undefined;
  }
  // Only a domain the tenant proved it controls: anyone can hold an address at a domain the tenant does not own.
  const domain = normalized.slice(normalized.lastIndexOf('@') + 1);
  const claim = (
    await tx.find<TenantDomain>('tenantDomains', { tenantId: source.tenantId, uniqueKey: domain })
  )[0];
  if (!claim || claim.status !== 'verified' || claim.domain !== domain) return undefined;
  for (const identity of await tx.find<Identity>('identities', {
    tenantId: source.tenantId,
    email: normalized,
  })) {
    const match = await person(tx, source, identity.id);
    if (match) return match.id;
  }
  return undefined;
}

/**
 * The identity of the source's tenant an event's subject names, or undefined. Every identifier that may name a person
 * (the subject itself, a complex subject's `user`, each alias) is tried in order: `iss_sub` of the source's issuer (or
 * an alias) through the federation links of `subjects.connectionIds`, then the `externalId` of users provisioned
 * through `subjects.scimConnectionIds`; `opaque` through the SCIM `externalId`; `email` and `acct:` by email when
 * `subjects.matchEmail` is on and the tenant verified the domain. Deleted identities, service accounts and agents never
 * match, nor does anyone in another tenant.
 */
export async function resolveSubject(
  _ctx: ServerContext,
  tx: IamStore,
  source: SignalSource,
  subject: SubjectIdentifier | undefined,
): Promise<string | undefined> {
  for (const identifier of userSubjects(subject)) {
    let identityId: string | undefined;
    switch (identifier.format) {
      case 'iss_sub':
        if (!namesSignalSource(source, identifier.iss)) break;
        identityId =
          (await byFederationLink(tx, source, identifier.iss, identifier.sub)) ??
          (await byScimExternalId(tx, source, identifier.sub));
        break;
      case 'opaque':
        identityId = await byScimExternalId(tx, source, identifier.id);
        break;
      case 'email':
        identityId = await byVerifiedEmail(tx, source, identifier.email);
        break;
      case 'account': {
        let address = identifier.uri.slice('acct:'.length);
        try {
          address = decodeURIComponent(address);
        } catch {
          break;
        }
        identityId = await byVerifiedEmail(tx, source, address);
        break;
      }
      default:
        break;
    }
    if (identityId) return identityId;
  }
  return undefined;
}

/**
 * Ends an identity's sessions except its API keys: user, role and session-token sessions (with the impersonations
 * opened through them), role sessions it assumed elsewhere, and its pending sign-in challenges. Remembered devices
 * stay, so the person's next sign-in is as usual. Returns the number of sessions ended.
 */
async function endSessions(ctx: ServerContext, tx: IamStore, identityId: string): Promise<number> {
  let revoked = 0;
  for (const session of await tx.find<Session>('sessions', { identityId })) {
    if (session.kind === 'api-key') continue;
    await ctx.auth.endSession(tx, session.id);
    revoked++;
  }
  for (const session of await tx.find<Session>('sessions', { originalIdentityId: identityId })) {
    if (session.kind === 'api-key') continue;
    await tx.delete('sessions', session.id);
    revoked++;
  }
  for (const challenge of await tx.find('authChallenges', { identityId }))
    await tx.delete('authChallenges', challenge.id);
  return revoked;
}

async function signalAudit(
  ctx: ServerContext,
  tx: IamStore,
  source: SignalSource,
  action: string,
  resourceId: string,
  metadata: Record<string, Json>,
): Promise<void> {
  await ctx.events.recordAudit(tx, {
    id: id(),
    tenantId: source.tenantId,
    actorId: signalActor(source.id),
    action,
    resourceId,
    timestamp: ctx.now(),
    outcome: 'allow',
    metadata,
  });
}

/** What processing needs from a security event. */
export interface SignalInput {
  eventType: SignalEventType;
  subject?: SubjectIdentifier;
  /** The event's own claims. */
  event: Record<string, unknown>;
  jti: string;
}

/** The result of `applySignal`; `source` carries the bookkeeping a control event changed. */
export interface SignalOutcome {
  status: SignalStatus;
  identityId?: string;
  reason?: string;
  source: SignalSource;
}

/**
 * Handles one event inside the caller's transaction. Control events touch only the source: `verification` records
 * `lastVerifiedAt`; `stream-updated` to paused or disabled records the transmitter's status in `lastError`. Unknown
 * event types are ignored. Otherwise the subject is mapped (`resolveSubject`); for a match with the action
 * `revoke-sessions` configured for the event type, the person's sessions end (`signal:revoke-sessions`), except for a
 * root administrator unless the source belongs to the root tenant (ignored, reason `protected`).
 */
export async function applySignal(
  ctx: ServerContext,
  tx: IamStore,
  source: SignalSource,
  signal: SignalInput,
): Promise<SignalOutcome> {
  const now = ctx.now();
  if (signal.eventType === 'verification')
    return { status: 'recorded', source: { ...source, lastVerifiedAt: now } };
  if (signal.eventType === 'stream-updated') {
    const status = own(signal.event, 'status');
    if (status === 'paused' || status === 'disabled') {
      const reason = localized(own(signal.event, 'reason'));
      return {
        status: 'recorded',
        source: {
          ...source,
          lastError: {
            at: now,
            message: `The transmitter ${status === 'paused' ? 'paused' : 'disabled'} the stream${reason ? `: ${clip(reason, 200)}` : ''}`,
          },
        },
      };
    }
    return { status: 'recorded', source };
  }
  if (signal.eventType === 'unknown')
    return { status: 'ignored', reason: 'unsupported-event', source };
  const identityId = await resolveSubject(ctx, tx, source, signal.subject);
  if (!identityId)
    return { status: 'unmatched', reason: signal.subject ? 'no-match' : 'no-subject', source };
  if (source.actions[signal.eventType] !== 'revoke-sessions')
    return { status: 'recorded', identityId, source };
  const identity = (await tx.get<Identity>('identities', identityId))!;
  if (identity.rootAdmin) {
    const tenant = await tx.get<Tenant>('tenants', source.tenantId);
    if (tenant?.type !== 'root' || tenant.parentId !== null)
      return { status: 'ignored', identityId, reason: 'protected', source };
  }
  const revoked = await endSessions(ctx, tx, identity.id);
  // A name of its own: the transmitter maps `identity:revoke-sessions` and would echo the revocation upstream.
  await signalAudit(ctx, tx, source, 'signal:revoke-sessions', identity.id, {
    sourceId: source.id,
    eventType: signal.eventType,
    jti: signal.jti,
    revoked,
  });
  return { status: 'applied', identityId, source };
}

/**
 * Audits a received (or reprocessed) event as `signal:received` for threat detection: actor `signal:{sourceId}`, the
 * matched identity (else the source) as resource, and `{ sourceId, eventType, jti, status, identityId?, reasonAdmin?,
 * currentLevel?, credentialType? }` (`currentLevel` upper-cased, for `risk-level-change`).
 */
export async function recordSignalReceived(
  ctx: ServerContext,
  tx: IamStore,
  source: SignalSource,
  record: Pick<ReceivedSignal, 'eventType' | 'jti' | 'status' | 'identityId'>,
  event: Record<string, unknown>,
): Promise<void> {
  const metadata: Record<string, Json> = {
    sourceId: source.id,
    eventType: record.eventType,
    jti: record.jti,
    status: record.status,
  };
  if (record.identityId) metadata.identityId = record.identityId;
  const reasonAdmin = localized(own(event, 'reason_admin'));
  if (reasonAdmin) metadata.reasonAdmin = clip(reasonAdmin, 256);
  const level = own(event, 'current_level');
  if (record.eventType === 'risk-level-change' && typeof level === 'string' && level)
    metadata.currentLevel = clip(level.toUpperCase(), 32);
  const credentialType = own(event, 'credential_type');
  if (typeof credentialType === 'string' && credentialType)
    metadata.credentialType = clip(credentialType, 64);
  await signalAudit(
    ctx,
    tx,
    source,
    'signal:received',
    record.identityId ?? `signals/sources/${source.id}`,
    metadata,
  );
}

const receiptOf = (record: ReceivedSignal, duplicate: boolean): SignalReceipt => ({
  eventId: record.id,
  status: record.status,
  duplicate,
  ...(record.identityId ? { identityId: record.identityId } : {}),
});

const sourceGone = () => new IamError('NOT_FOUND', 'Signal source not found', 404);

/** The source inside a transaction, when it is active and its tenant (and every ancestor) is too; else NOT_FOUND. */
async function liveSource(
  ctx: ServerContext,
  tx: IamStore,
  sourceId: string,
): Promise<SignalSource> {
  const source = await tx.get<SignalSource>(signalCollections.sources, sourceId);
  if (!source || source.status !== 'active') throw sourceGone();
  try {
    await ctx.auth.assertTenantActive(tx, source.tenantId);
  } catch (error) {
    if (error instanceof IamError && error.status === 403) throw sourceGone();
    throw error;
  }
  return source;
}

async function receivedByKey(
  tx: IamStore,
  tenantId: string,
  uniqueKey: string,
): Promise<ReceivedSignal | undefined> {
  return (await tx.find<ReceivedSignal>(signalCollections.events, { tenantId, uniqueKey }))[0];
}

function receivedRecord(
  source: SignalSource,
  claims: SecurityEventClaims,
  uniqueKey: string,
  now: number,
  outcome: Pick<SignalOutcome, 'status' | 'identityId' | 'reason'>,
): ReceivedSignal {
  const subject = storedSubject(claims.subject);
  return {
    id: id(),
    tenantId: source.tenantId,
    uniqueKey,
    sourceId: source.id,
    streamId: source.id,
    jti: claims.jti,
    eventType: claims.eventType,
    eventUri: claims.eventUri,
    issuedAt: Math.round(claims.iat * 1000),
    ...(claims.eventTimestamp !== undefined ? { eventTimestamp: claims.eventTimestamp } : {}),
    ...(claims.txn !== undefined ? { txn: claims.txn } : {}),
    ...(subject ? { subject } : {}),
    ...(outcome.identityId ? { identityId: outcome.identityId } : {}),
    status: outcome.status,
    ...(outcome.reason ? { reason: outcome.reason } : {}),
    claims: storedClaims(claims.event),
    receivedAt: now,
    timestamp: now,
    expiresAt: now + SIGNAL_RETENTION_MS,
  };
}

/**
 * Records a verified event for a source in one transaction: deduplicates on issuer and `jti` (a repeat returns the
 * first receipt with `duplicate: true`), applies it (`applySignal`), stores it, audits `signal:received` and notes
 * `lastEventAt`. When applying fails, the event is stored as `failed` in a transaction of its own instead, so an
 * administrator can reprocess it and the transmitter is not asked for it again. Throws NOT_FOUND when the source is
 * gone or disabled, and storage contention (503) as is, so the caller can have the event delivered again.
 */
export async function processSignal(
  ctx: ServerContext,
  sourceId: string,
  claims: SecurityEventClaims,
): Promise<SignalReceipt> {
  try {
    return await ctx.store.transaction(async (tx) => {
      const source = await liveSource(ctx, tx, sourceId);
      const uniqueKey = signalEventKey(source.issuer, claims.jti);
      const existing = await receivedByKey(tx, source.tenantId, uniqueKey);
      if (existing) return receiptOf(existing, true);
      const now = ctx.now();
      const outcome = await applySignal(ctx, tx, source, {
        eventType: claims.eventType,
        ...(claims.subject ? { subject: claims.subject } : {}),
        event: claims.event,
        jti: claims.jti,
      });
      const record = await tx.insert<ReceivedSignal>(
        signalCollections.events,
        receivedRecord(source, claims, uniqueKey, now, outcome),
      );
      await recordSignalReceived(ctx, tx, source, record, claims.event);
      await tx.put<SignalSource>(signalCollections.sources, {
        ...outcome.source,
        lastEventAt: now,
      });
      return receiptOf(record, false);
    });
  } catch (error) {
    if (error instanceof IamError && (error.status === 404 || error.status >= 500)) throw error;
    // The same event committed concurrently (the natural key collided), or applying it failed.
    return ctx.store.transaction(async (tx) => {
      const source = await liveSource(ctx, tx, sourceId);
      const uniqueKey = signalEventKey(source.issuer, claims.jti);
      const existing = await receivedByKey(tx, source.tenantId, uniqueKey);
      if (existing) return receiptOf(existing, true);
      const now = ctx.now();
      const record = await tx.insert<ReceivedSignal>(
        signalCollections.events,
        receivedRecord(source, claims, uniqueKey, now, {
          status: 'failed',
          reason: error instanceof IamError ? error.code : 'INTERNAL_ERROR',
        }),
      );
      await recordSignalReceived(ctx, tx, source, record, claims.event);
      await tx.put<SignalSource>(signalCollections.sources, { ...source, lastEventAt: now });
      return receiptOf(record, false);
    });
  }
}

/** Raised by the key resolver when the source's keys cannot be obtained right now. */
class KeysUnavailable extends Error {}
/** A failed poll request; the message is safe to store as the source's `lastError`. */
class PollFailure extends Error {}

function rejectionFor(error: unknown, remoteKeys: boolean): SignalRejectedError {
  if (error instanceof SignalRejectedError) return error;
  if (error instanceof KeysUnavailable || error instanceof errors.JWKSTimeout)
    return new SignalRejectedError(
      'invalid_key',
      "The source's signing keys could not be obtained",
      true,
    );
  if (error instanceof errors.JWKSInvalid)
    return new SignalRejectedError('invalid_key', "The source's key set is invalid", true);
  if (error instanceof errors.JWKSNoMatchingKey)
    // A transmitter that rotated its keys moments ago is retried once the key set may be fetched again.
    return new SignalRejectedError(
      'invalid_key',
      'No key of the source matches the token',
      remoteKeys,
    );
  if (error instanceof errors.JWKSMultipleMatchingKeys)
    return new SignalRejectedError('invalid_key', 'Several keys of the source match the token');
  if (error instanceof errors.JWSSignatureVerificationFailed)
    return new SignalRejectedError('invalid_key', 'The token signature is invalid');
  if (error instanceof errors.JOSEAlgNotAllowed || error instanceof errors.JOSENotSupported)
    return new SignalRejectedError('invalid_key', 'The token algorithm or key is not accepted');
  if (error instanceof errors.JWTExpired)
    return new SignalRejectedError('invalid_request', 'The token has expired');
  if (error instanceof errors.JWTClaimValidationFailed) {
    if (error.claim === 'iss')
      return new SignalRejectedError(
        'invalid_issuer',
        "The token's issuer is not the source's issuer",
      );
    if (error.claim === 'aud')
      return new SignalRejectedError(
        'invalid_audience',
        'The token is not addressed to this receiver',
      );
    if (error.claim === 'typ')
      return new SignalRejectedError('invalid_request', 'The token type must be secevent+jwt');
    return new SignalRejectedError(
      'invalid_request',
      `The token's ${error.claim} claim is missing or invalid`,
    );
  }
  if (error instanceof SignalFormatError)
    return new SignalRejectedError('invalid_request', error.message);
  return new SignalRejectedError('invalid_request', 'The security event token is malformed');
}

/** The receiver's per-deployment state: key caches, guarded transports, and the push endpoint. */
export interface SignalReceiver {
  /** Verifies a compact SET for a source (signature, issuer, audience, type, age, claims) or throws `SignalRejectedError`. */
  verify(source: SignalSource, set: unknown): Promise<SecurityEventClaims>;
  /** Verifies and processes a SET; a refusal is noted on the source as `lastError`. */
  accept(source: SignalSource, set: unknown): Promise<SignalReceipt>;
  poll(input?: { sourceId?: string }): Promise<SignalPollResult>;
  /** Drops the cached keys of a source (after an update or deletion). */
  forget(sourceId: string): void;
  /** The RFC 8935 push endpoint. */
  handle(request: Request): Promise<Response | undefined>;
}

interface CachedKeys {
  updatedAt: number;
  keys?: JWTVerifyGetKey;
  discoveredAt?: number;
  pending?: Promise<JWTVerifyGetKey>;
  failedAt?: number;
}

const noStore = { 'cache-control': 'no-store' };
const pushError = (
  status: number,
  err: string,
  description: string,
  headers: Record<string, string> = {},
) => Response.json({ err, description }, { status, headers: { ...noStore, ...headers } });

/**
 * jose's `jwtVerify`, trying each candidate when several keys of the set could have signed the token (keys without a
 * `kid`, or a token without one): the first that verifies wins, and none verifying is a bad signature.
 */
async function verifiedPayload(
  token: string,
  keys: JWTVerifyGetKey,
  options: JWTVerifyOptions,
): Promise<JWTPayload> {
  try {
    return (await jwtVerify<JWTPayload>(token, keys, options)).payload;
  } catch (error) {
    if (!(error instanceof errors.JWKSMultipleMatchingKeys)) throw error;
    let tried = 0;
    for await (const key of error) {
      if (++tried > MAX_CANDIDATE_KEYS) break;
      try {
        return (await jwtVerify<JWTPayload>(token, key, options)).payload;
      } catch (inner) {
        if (!(inner instanceof errors.JWSSignatureVerificationFailed)) throw inner;
      }
    }
    throw new errors.JWSSignatureVerificationFailed();
  }
}

/**
 * Drops a response body by reading it (the guarded transport bounds it). Cancelling instead is not safe: a guarded
 * response with a size limit keeps emitting into its closed stream after `cancel()`, an uncaught exception.
 */
async function discard(response: Response): Promise<void> {
  try {
    await response.arrayBuffer();
  } catch {
    /* A body that failed or ran past the limit is dropped all the same. */
  }
}

/** Reads at most `limit` bytes of a request body; undefined when it is larger. */
async function boundedBody(request: Request, limit: number): Promise<string | undefined> {
  const reader = request.body?.getReader();
  if (!reader) return '';
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const item = await reader.read();
    if (item.done) break;
    size += item.value.byteLength;
    if (size > limit) {
      await reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(item.value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

function createSignalReceiver(ctx: ServerContext): SignalReceiver {
  const settings = ctx.config.signals;
  const addressRules = {
    anyPort: true,
    allowPrivateNetworks: settings.allowPrivateNetworks,
    allowInsecureLocalhost: settings.allowInsecureLocalhost,
  };
  const jwksFetch = createGuardedFetch({ ...addressRules, maxBytes: JWKS_MAX_BYTES });
  const discoveryFetch = createGuardedFetch({ ...addressRules, maxBytes: DISCOVERY_MAX_BYTES });
  const pollFetch = createGuardedFetch({ ...addressRules, maxBytes: POLL_MAX_BYTES });
  const cache = new Map<string, CachedKeys>();
  const prefix = `${settings.pushPath}/`;

  function entryFor(source: SignalSource): CachedKeys {
    let entry = cache.get(source.id);
    if (!entry || entry.updatedAt !== source.updatedAt) {
      if (!entry && cache.size >= MAX_CACHED_SOURCES) cache.delete(cache.keys().next().value!);
      entry = { updatedAt: source.updatedAt };
      cache.set(source.id, entry);
    }
    return entry;
  }

  /** A remote key set fetched through the guarded transport; transport failures read as unavailable keys. */
  function remoteKeys(url: URL): JWTVerifyGetKey {
    const set = createRemoteJWKSet(url, {
      [customFetch]: jwksFetch,
      timeoutDuration: FETCH_TIMEOUT_MS,
      cooldownDuration: 30_000,
      cacheMaxAge: 600_000,
    });
    return async (header, token) => {
      try {
        return await set(header, token);
      } catch (error) {
        // Which key signed the token is the token's matter. A key set that could not be fetched or read (a timeout, a
        // status other than 200, a body that is not a public key set) is the transmitter's, and may pass later.
        if (
          error instanceof errors.JWKSNoMatchingKey ||
          error instanceof errors.JWKSMultipleMatchingKeys ||
          error instanceof errors.JOSENotSupported
        )
          throw error;
        throw new KeysUnavailable();
      }
    };
  }

  async function getJson(url: URL): Promise<unknown> {
    const response = await discoveryFetch(url, {
      headers: { accept: 'application/json' },
      redirect: 'error',
      signal: AbortSignal.timeout(FETCH_TIMEOUT_MS),
    });
    if (
      response.status !== 200 ||
      !(response.headers.get('content-type') ?? '').toLowerCase().includes('json')
    ) {
      await discard(response);
      throw new KeysUnavailable();
    }
    return JSON.parse(await response.text());
  }

  /** SSF discovery (`/.well-known/ssf-configuration{path}`, then the legacy RISC document): the `jwks_uri`. */
  async function discover(source: SignalSource): Promise<URL> {
    const issuer = new URL(source.issuer);
    const path = trimSlashes(issuer.pathname);
    for (const name of ['ssf-configuration', 'risc-configuration']) {
      let document: Record<string, unknown> | undefined;
      try {
        document = plain(await getJson(new URL(`${issuer.origin}/.well-known/${name}${path}`)));
      } catch {
        continue;
      }
      const documentIssuer = document && own(document, 'issuer');
      const jwksUri = document && own(document, 'jwks_uri');
      if (typeof documentIssuer !== 'string' || !namesSignalSource(source, documentIssuer))
        continue;
      if (typeof jwksUri !== 'string') continue;
      try {
        return checkFetchUrl(jwksUri, addressRules);
      } catch {
        continue;
      }
    }
    throw new KeysUnavailable();
  }

  /** The source's keys: static ones, its key URL, or discovered (single-flight, 30 s negative cache, daily refresh). */
  async function keysFor(source: SignalSource): Promise<JWTVerifyGetKey> {
    const entry = entryFor(source);
    const now = Date.now();
    if (
      entry.keys &&
      (entry.discoveredAt === undefined || now - entry.discoveredAt < REDISCOVER_MS)
    )
      return entry.keys;
    if (source.jwks) {
      entry.keys = createLocalJWKSet({ keys: source.jwks.keys } as JSONWebKeySet);
      return entry.keys;
    }
    if (source.jwksUri) {
      let url: URL;
      try {
        url = checkFetchUrl(source.jwksUri, addressRules);
      } catch {
        // Stored under looser deployment settings than the current ones: it stays refused until an update fixes it.
        throw new SignalRejectedError('invalid_key', "The source's key URL is not allowed");
      }
      entry.keys = remoteKeys(url);
      return entry.keys;
    }
    // A daily rediscovery that fails keeps the keys found before, so a brief outage of the discovery document does
    // not refuse events the known keys still verify.
    const stale = entry.keys;
    if (
      entry.failedAt !== undefined &&
      now - entry.failedAt < NEGATIVE_CACHE_MS &&
      !entry.pending
    ) {
      if (stale) return stale;
      throw new KeysUnavailable();
    }
    entry.pending ??= discover(source)
      .then((url) => {
        const keys = remoteKeys(url);
        entry.keys = keys;
        entry.discoveredAt = Date.now();
        entry.failedAt = undefined;
        return keys;
      })
      .catch(() => {
        entry.failedAt = Date.now();
        if (entry.keys) return entry.keys;
        throw new KeysUnavailable();
      })
      .finally(() => {
        entry.pending = undefined;
      });
    return entry.pending;
  }

  async function verify(source: SignalSource, set: unknown): Promise<SecurityEventClaims> {
    const remote = source.jwks === undefined;
    try {
      if (typeof set !== 'string')
        throw new SignalRejectedError('invalid_request', 'Expected a compact security event token');
      const token = set.trim();
      if (Buffer.byteLength(token) > MAX_SET_BYTES)
        throw new SignalRejectedError(
          'invalid_request',
          'The security event token is larger than 16 KiB',
        );
      if (!compactJws.test(token))
        throw new SignalRejectedError('invalid_request', 'Expected a compact signed JWT');
      let header: JWSHeaderParameters;
      try {
        header = decodeProtectedHeader(token);
      } catch {
        throw new SignalRejectedError('invalid_request', 'The token header is malformed');
      }
      // Keys come from the source's configuration only, never from the token itself.
      for (const member of forbiddenHeaders)
        if (header[member] !== undefined)
          throw new SignalRejectedError(
            'invalid_request',
            `The token header must not carry ${member}`,
          );
      if (header.crit !== undefined)
        throw new SignalRejectedError(
          'invalid_request',
          'The token names critical header parameters',
        );
      if (typeof header.alg !== 'string' || !(source.algorithms as string[]).includes(header.alg))
        throw new SignalRejectedError(
          'invalid_key',
          'The token algorithm is not allowed for this source',
        );
      if (header.kid !== undefined && typeof header.kid !== 'string')
        throw new SignalRejectedError('invalid_request', 'The token header is malformed');
      if (source.requireTyp) {
        if (typeof header.typ !== 'string' || normalizedTyp(header.typ) !== 'secevent+jwt')
          throw new SignalRejectedError('invalid_request', 'The token type must be secevent+jwt');
      } else if (
        header.typ !== undefined &&
        (typeof header.typ !== 'string' || !lenientTypes.has(normalizedTyp(header.typ)))
      )
        throw new SignalRejectedError(
          'invalid_request',
          'The token type is not a security event token',
        );
      const now = ctx.now();
      const payload = await verifiedPayload(token, await keysFor(source), {
        issuer: issuerForms(source).flatMap((form) => [form, `${form}/`]),
        audience: [...source.audiences],
        ...(source.requireTyp ? { typ: 'secevent+jwt' } : {}),
        algorithms: [...source.algorithms],
        clockTolerance: CLOCK_TOLERANCE_SECONDS,
        currentDate: new Date(now),
        requiredClaims: ['iss', 'aud', 'iat', 'jti', 'events'],
      });
      const claims = readSecurityEvent(payload as Record<string, unknown>);
      if (
        source.tenantClaim !== undefined &&
        (payload as Record<string, unknown>).tenant_id !== source.tenantClaim
      )
        throw new SignalRejectedError(
          'invalid_audience',
          'The token is for another organization of its issuer',
        );
      // No maxTokenAge (a polled event can wait in the transmitter's queue), but nothing older than a week.
      const seconds = now / 1000;
      if (claims.iat > seconds + CLOCK_TOLERANCE_SECONDS)
        throw new SignalRejectedError('invalid_request', 'The token was issued in the future');
      if (claims.iat < seconds - MAX_SET_AGE_SECONDS)
        throw new SignalRejectedError('invalid_request', 'The token is older than seven days');
      return claims;
    } catch (error) {
      throw rejectionFor(error, remote);
    }
  }

  /** Notes a refusal or transport failure on the source, at most once a minute per message. */
  async function noteError(sourceId: string, message: string): Promise<void> {
    try {
      await ctx.store.transaction(async (tx) => {
        const current = await tx.get<SignalSource>(signalCollections.sources, sourceId);
        if (!current) return;
        const now = ctx.now();
        if (current.lastError?.message === message && now - current.lastError.at < 60_000) return;
        await tx.put<SignalSource>(signalCollections.sources, {
          ...current,
          lastError: { at: now, message: clip(message, 512) },
        });
      });
    } catch {
      /* Bookkeeping never hides the refusal itself. */
    }
  }

  async function accept(source: SignalSource, set: unknown): Promise<SignalReceipt> {
    let claims: SecurityEventClaims;
    try {
      claims = await verify(source, set);
    } catch (error) {
      const rejection = rejectionFor(error, source.jwks === undefined);
      await noteError(source.id, `Refused an event: ${rejection.message}`);
      throw rejection;
    }
    return processSignal(ctx, source.id, claims);
  }

  /** The source when it is active and its tenant is, read in a short transaction; undefined otherwise. */
  async function activeSource(sourceId: string): Promise<SignalSource | undefined> {
    try {
      return await ctx.store.transaction((tx) => liveSource(ctx, tx, sourceId));
    } catch (error) {
      if (error instanceof IamError && error.status === 404) return undefined;
      throw error;
    }
  }

  async function handle(request: Request): Promise<Response | undefined> {
    const url = new URL(request.url);
    if (!url.pathname.startsWith(prefix)) return undefined;
    const sourceId = url.pathname.slice(prefix.length);
    if (!sourceIdShape.test(sourceId)) return undefined;
    try {
      if (request.method !== 'POST')
        return pushError(405, 'invalid_request', 'Use POST', { allow: 'POST' });
      const type = (request.headers.get('content-type') ?? '').split(';')[0]!.trim().toLowerCase();
      if (type !== 'application/secevent+jwt')
        return pushError(
          415,
          'invalid_request',
          'The content type must be application/secevent+jwt',
        );
      const declared = Number(request.headers.get('content-length'));
      if (Number.isFinite(declared) && declared > MAX_PUSH_BYTES)
        return pushError(413, 'invalid_request', 'The request body is too large');
      const source = await activeSource(sourceId);
      if (!source || source.delivery !== 'push')
        return pushError(404, 'invalid_request', 'Unknown stream');
      try {
        await ctx.auth.limitAttempt(source.tenantId, `signals:${source.id}`, {
          limit: PUSHES_PER_WINDOW,
        });
      } catch (error) {
        if (!(error instanceof IamError)) throw error;
        if (error.status === 429) {
          const retryAfterMs = (error as unknown as { retryAfterMs?: unknown }).retryAfterMs;
          return pushError(429, 'invalid_request', 'Too many events; try again later', {
            ...(typeof retryAfterMs === 'number'
              ? { 'retry-after': String(Math.ceil(retryAfterMs / 1000)) }
              : {}),
          });
        }
        if (error.status === 403)
          return pushError(403, 'access_denied', 'The sender is not allowed');
        throw error;
      }
      if (source.pushTokenHash !== undefined) {
        const match = /^Bearer[ ]+([^\s]+)$/i.exec(request.headers.get('authorization') ?? '');
        if (!match || !sameHash(hash(match[1]!), source.pushTokenHash))
          return pushError(401, 'authentication_failed', 'The bearer token is missing or invalid', {
            'www-authenticate': 'Bearer',
          });
      }
      const body = await boundedBody(request, MAX_PUSH_BYTES);
      if (body === undefined)
        return pushError(413, 'invalid_request', 'The request body is too large');
      try {
        await accept(source, body);
      } catch (error) {
        if (!(error instanceof SignalRejectedError)) throw error;
        if (error.temporary)
          return pushError(503, error.err, error.message, { 'retry-after': '30' });
        return pushError(400, error.err, error.message);
      }
      return new Response(null, { status: 202, headers: noStore });
    } catch (error) {
      if (error instanceof IamError && error.status === 404)
        return pushError(404, 'invalid_request', 'Unknown stream');
      if (error instanceof IamError && error.status === 503)
        return pushError(503, 'invalid_request', 'The receiver is busy; try again later', {
          'retry-after': '1',
        });
      return pushError(500, 'invalid_request', 'The event could not be processed');
    }
  }

  /** One RFC 8936 poll request: acknowledgements and errors out, `{ sets, moreAvailable }` back. */
  async function pollRequest(
    source: SignalSource,
    token: string,
    body: Record<string, unknown>,
  ): Promise<{ sets: [string, unknown][]; moreAvailable: boolean }> {
    let response: Response;
    try {
      response = await pollFetch(source.poll!.endpoint, {
        method: 'POST',
        redirect: 'error',
        signal: AbortSignal.timeout(POLL_TIMEOUT_MS),
        headers: {
          'content-type': 'application/json',
          accept: 'application/json',
          authorization: `Bearer ${token}`,
          'user-agent': 'better-iam-signals/1',
        },
        body: JSON.stringify(body),
      });
    } catch (error) {
      const cause = (error as { cause?: unknown })?.cause;
      throw new PollFailure(
        cause instanceof SafeFetchError
          ? `The poll endpoint was refused (${cause.reason})`
          : 'The poll endpoint could not be reached',
      );
    }
    if (response.status !== 200) {
      await discard(response);
      throw new PollFailure(`The poll endpoint answered ${response.status}`);
    }
    let parsed: Record<string, unknown> | undefined;
    try {
      parsed = plain(JSON.parse(await response.text()));
    } catch {
      parsed = undefined;
    }
    const sets = parsed && plain(own(parsed, 'sets'));
    const more = parsed && own(parsed, 'moreAvailable');
    if (
      !parsed ||
      (own(parsed, 'sets') !== undefined && !sets) ||
      (more !== undefined && typeof more !== 'boolean')
    )
      throw new PollFailure('The poll endpoint sent an unreadable response');
    return { sets: Object.entries(sets ?? {}), moreAvailable: more === true };
  }

  /** Stores the acknowledgements and errors the next request carries, and the poll outcome. */
  async function pollBookkeeping(
    sourceId: string,
    endpoint: string,
    acks: string[],
    setErrs: Record<string, { err: string; description: string }>,
    failure?: string,
  ): Promise<void> {
    await ctx.store.transaction(async (tx) => {
      const current = await tx.get<SignalSource>(signalCollections.sources, sourceId);
      // A source deleted, switched to another endpoint or turned into a push source meanwhile keeps its own state.
      if (!current?.poll || current.poll.endpoint !== endpoint) return;
      const now = ctx.now();
      const { pendingErrors: _previous, ...state } = current.poll;
      await tx.put<SignalSource>(signalCollections.sources, {
        ...current,
        poll: {
          ...state,
          pendingAcks: acks,
          ...(Object.keys(setErrs).length ? { pendingErrors: setErrs } : {}),
          lastPolledAt: now,
        },
        ...(failure ? { lastError: { at: now, message: failure } } : {}),
      });
    });
  }

  async function pollSource(source: SignalSource, result: SignalPollResult): Promise<void> {
    const state = source.poll!;
    let token: string;
    try {
      token = openPollToken(ctx, source);
    } catch {
      result.errors++;
      await noteError(
        source.id,
        'The poll token cannot be opened: it was sealed with a secret that is gone',
      );
      return;
    }
    let acks = [...state.pendingAcks];
    let setErrs = { ...(state.pendingErrors ?? {}) };
    for (let request = 0; request < POLL_REQUESTS_PER_RUN; request++) {
      let answer: { sets: [string, unknown][]; moreAvailable: boolean };
      try {
        answer = await pollRequest(source, token, {
          maxEvents: state.maxEvents,
          returnImmediately: true,
          ack: acks,
          ...(Object.keys(setErrs).length ? { setErrs } : {}),
        });
      } catch (error) {
        result.errors++;
        await pollBookkeeping(
          source.id,
          state.endpoint,
          acks,
          setErrs,
          error instanceof PollFailure ? error.message : 'The poll request failed',
        );
        return;
      }
      // The transmitter answered, so it has the acknowledgements and errors this request carried.
      result.acknowledged += acks.length;
      acks = [];
      setErrs = {};
      for (const [jti, set] of answer.sets.slice(0, state.maxEvents)) {
        if (!jti || jti.length > 512) continue;
        try {
          const claims = await verify(source, set);
          if (claims.jti !== jti)
            throw new SignalRejectedError(
              'invalid_request',
              'The token jti does not match its key in sets',
            );
          const receipt = await processSignal(ctx, source.id, claims);
          // Acknowledged with the next request, now that the event is committed.
          acks.push(jti);
          if (!receipt.duplicate) result.received++;
        } catch (error) {
          if (error instanceof SignalRejectedError && !error.temporary) {
            setErrs[jti] = { err: error.err, description: error.message };
            await noteError(source.id, `Refused an event: ${error.message}`);
          } else if (error instanceof IamError && error.status === 404) {
            // The source was deleted or disabled while polling: stop without touching its state.
            return;
          } else result.errors++;
        }
      }
      await pollBookkeeping(source.id, state.endpoint, acks, setErrs);
      if (!answer.moreAvailable) break;
    }
  }

  async function poll(input: { sourceId?: string } = {}): Promise<SignalPollResult> {
    const result: SignalPollResult = { sources: 0, received: 0, acknowledged: 0, errors: 0 };
    let candidates: SignalSource[];
    if (input.sourceId !== undefined) {
      if (typeof input.sourceId !== 'string' || !sourceIdShape.test(input.sourceId))
        throw new IamError('INVALID_INPUT', 'Invalid sourceId');
      const source = await activeSource(input.sourceId);
      candidates = source ? [source] : [];
    } else
      candidates = await ctx.store.find<SignalSource>(signalCollections.sources, {
        delivery: 'poll',
        status: 'active',
      });
    for (const candidate of candidates.sort(byId)) {
      if (candidate.delivery !== 'poll' || candidate.status !== 'active' || !candidate.poll)
        continue;
      // Re-read under the tenant checks: a whole-collection scan also lists sources of suspended tenants.
      const source = input.sourceId === undefined ? await activeSource(candidate.id) : candidate;
      if (!source?.poll || source.delivery !== 'poll') continue;
      result.sources++;
      await pollSource(source, result);
    }
    return result;
  }

  return {
    verify,
    accept,
    poll,
    forget(sourceId) {
      cache.delete(sourceId);
    },
    handle,
  };
}

const receivers = new WeakMap<ServerContext, SignalReceiver>();

/** The deployment's signal receiver (one per server context, created on first use). */
export function signalReceiverOf(ctx: ServerContext): SignalReceiver {
  let receiver = receivers.get(ctx);
  if (!receiver) {
    receiver = createSignalReceiver(ctx);
    receivers.set(ctx, receiver);
  }
  return receiver;
}

/** Verifies a compact SET for a source (see `SignalReceiver.verify`). */
export function verifySignal(
  ctx: ServerContext,
  source: SignalSource,
  set: unknown,
): Promise<SecurityEventClaims> {
  return signalReceiverOf(ctx).verify(source, set);
}

/**
 * The RFC 8935 push endpoint, `POST {signals.pushPath}/{sourceId}` (default `{basePath}/signals/push/{sourceId}`),
 * mounted beside the HTTP API: `application/secevent+jwt` bodies of at most 64 KiB, rate limited per source, the
 * source's bearer token when it has one, then verification and processing. Answers 202 with no body, or
 * `{ err, description }`: 400 for a refused SET, 401 for a bad bearer token, 404 for an unknown, disabled or poll
 * source, 405, 413, 415, 429, and 503 while the source's keys cannot be fetched. Other paths pass through.
 */
export function createSignalsProtocol(ctx: ServerContext): ProtocolMount {
  return { handle: (request) => signalReceiverOf(ctx).handle(request) };
}

/** `iam.signals`: the poll job and in-process delivery. */
export function createSignalsRuntime(ctx: ServerContext): IamSignals {
  return {
    poll: (input) => signalReceiverOf(ctx).poll(input),
    async receive(sourceId, set) {
      if (typeof sourceId !== 'string' || !sourceIdShape.test(sourceId)) throw sourceGone();
      const receiver = signalReceiverOf(ctx);
      const source = await ctx.store.transaction((tx) => liveSource(ctx, tx, sourceId));
      return receiver.accept(source, set);
    },
  };
}
