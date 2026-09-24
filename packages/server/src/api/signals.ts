import {
  IamError,
  findOrdered,
  parseSubjectIdentifier,
  signalEventUris,
  type CredentialInput,
  type IamStore,
  type Json,
  type SignalEventType,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { PublicJwk } from '../models.js';
import { checkFetchUrl, SafeFetchError } from '../safe-fetch.js';
import {
  applySignal,
  DEFAULT_SIGNAL_ALGORITHMS,
  maxSignalSourcesPerTenant,
  recordSignalReceived,
  sealPollToken,
  signalCollections,
  signalReceiverOf,
  type ReceivedSignal,
  type SignalAction,
  type SignalActionableEvent,
  type SignalAlgorithm,
  type SignalDelivery,
  type SignalPollResult,
  type SignalPollState,
  type SignalSource,
  type SignalSourceStatus,
  type SignalStatus,
  type SignalSubjectMapping,
} from '../signal-receiver.js';
import { hash, id, token } from '../utils.js';
import { integer, text } from '../validation.js';
import {
  webIdentityAlgorithms,
  webIdentityAudiences,
  webIdentityIssuer,
  webIdentityKeys,
} from '../web-identity.js';

/** `signals.createSource` input. */
export interface SignalSourceCreateInput {
  tenantId: string;
  /** A label for administrators, at most 128 characters. */
  name: string;
  /** The transmitter's `iss`: https (loopback http with `signals.allowInsecureLocalhost`), at most 512 characters. */
  issuer: string;
  /** Other spellings of the issuer (at most 5), such as the authorization server issuer of Okta sign-in links. */
  issuerAliases?: string[];
  /** Accepted `aud` values (1 to 10 of at most 256 characters); a SET must name one of them. */
  audiences: string[];
  /** Where the transmitter's keys live. Without it and without `jwks`, SSF discovery on the issuer. */
  jwksUri?: string;
  /** Static public keys (1 to 20), used instead of fetching. */
  jwks?: { keys: PublicJwk[] };
  /** Accepted signature algorithms (default RS256, ES256, PS256 and EdDSA). */
  algorithms?: SignalAlgorithm[];
  /** `push`: the transmitter posts to the push URL (RFC 8935); `poll`: `iam.signals.poll()` fetches (RFC 8936). */
  delivery: SignalDelivery;
  /** Push sources: generate a bearer token the transmitter must send (default true), returned once. */
  pushToken?: boolean;
  /** Poll sources (required): the transmitter's poll endpoint, its bearer token, and events per request (1..100, default 25). */
  poll?: { endpoint: string; token: string; maxEvents?: number };
  /** How subjects map to identities (default: none, so every event is recorded as unmatched). */
  subjects?: Partial<SignalSubjectMapping>;
  /** The action per event type (default: record only). */
  actions?: Partial<Record<SignalActionableEvent, SignalAction>>;
  /** Require the `secevent+jwt` token type (default true); false tolerates legacy RISC transmitters. */
  requireTyp?: boolean;
  /**
   * Accept only SETs whose `tenant_id` claim equals this (at most 256 characters). Set it for a Better IAM
   * transmitter: it signs every organization's events with one issuer and key.
   */
  tenantClaim?: string;
}

/**
 * `signals.updateSource` input. The issuer and delivery cannot change; `null` clears `jwksUri` or `jwks`. A new poll
 * endpoint needs its token again, so a stored token never goes to an endpoint it was not given for.
 */
export interface SignalSourceUpdateInput {
  tenantId: string;
  sourceId: string;
  name?: string;
  issuerAliases?: string[];
  audiences?: string[];
  jwksUri?: string | null;
  jwks?: { keys: PublicJwk[] } | null;
  algorithms?: SignalAlgorithm[];
  poll?: { endpoint?: string; token?: string; maxEvents?: number };
  /** Replaces the given members of the mapping. */
  subjects?: Partial<SignalSubjectMapping>;
  /** Replaces the whole action map. */
  actions?: Partial<Record<SignalActionableEvent, SignalAction>>;
  requireTyp?: boolean;
  /** `null` stops requiring a `tenant_id` claim. */
  tenantClaim?: string | null;
  status?: SignalSourceStatus;
}

/** A signal source as the API returns it: no push token hash and no sealed poll token. */
export interface SignalSourceView {
  id: string;
  tenantId: string;
  name: string;
  issuer: string;
  issuerAliases: string[];
  audiences: string[];
  jwksUri?: string;
  jwks?: { keys: PublicJwk[] };
  algorithms: SignalAlgorithm[];
  delivery: SignalDelivery;
  /** Push sources: where the transmitter posts. */
  pushUrl?: string;
  /** Push sources: whether pushes must carry the source's bearer token. */
  hasPushToken: boolean;
  /** Poll sources: the endpoint, events per request, acknowledgements waiting for the next request. */
  poll?: { endpoint: string; maxEvents: number; pendingAcks: number; lastPolledAt?: number };
  subjects: SignalSubjectMapping;
  actions: Partial<Record<SignalActionableEvent, SignalAction>>;
  requireTyp: boolean;
  /** The `tenant_id` claim SETs must carry, when the source requires one. */
  tenantClaim?: string;
  status: SignalSourceStatus;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
  lastEventAt?: number;
  lastError?: { at: number; message: string };
  lastVerifiedAt?: number;
}

/** `signals.createSource` result: the push token is shown only here. */
export interface SignalSourceCreated {
  source: SignalSourceView;
  pushUrl?: string;
  pushToken?: string;
}

/** A received security event as the API returns it. */
export interface SignalEventView {
  id: string;
  tenantId: string;
  sourceId: string;
  jti: string;
  eventType: SignalEventType;
  eventUri: string;
  /** Epoch milliseconds. */
  issuedAt: number;
  eventTimestamp?: number;
  txn?: string;
  subject?: Record<string, Json>;
  identityId?: string;
  status: SignalStatus;
  reason?: string;
  claims: Record<string, Json>;
  receivedAt: number;
  expiresAt: number;
  reprocessedAt?: number;
  reprocessedBy?: string;
}

/** One page of received events (`signals.listEvents`), newest first. */
export interface SignalEventPage {
  events: SignalEventView[];
  total: number;
}

const { sources: sourcesCollection, events: eventsCollection } = signalCollections;
const sourceResource = (sourceId: string) => `signals/sources/${sourceId}`;
const eventResource = (eventId: string) => `signals/events/${eventId}`;
const deliveries = new Set<SignalDelivery>(['push', 'poll']);
const statuses = new Set<SignalStatus>(['applied', 'recorded', 'unmatched', 'ignored', 'failed']);
const sourceStatuses = new Set<SignalSourceStatus>(['active', 'disabled']);
const actionValues = new Set<SignalAction>(['record', 'revoke-sessions']);
const knownEventTypes = new Set<string>([...Object.keys(signalEventUris), 'unknown']);
const actionableEvents = new Set<string>(
  Object.keys(signalEventUris).filter(
    (type) => type !== 'verification' && type !== 'stream-updated',
  ),
);
const updatableFields = [
  'name',
  'issuerAliases',
  'audiences',
  'jwksUri',
  'jwks',
  'algorithms',
  'poll',
  'subjects',
  'actions',
  'requireTyp',
  'tenantClaim',
  'status',
] as const;
/** Printable ASCII without spaces: what a bearer token may contain. */
const bearerToken = /^[!-~]+$/;

function invalid(message: string): never {
  throw new IamError('INVALID_INPUT', message);
}

function booleanValue(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') invalid(`${name} must be a boolean`);
  return value;
}

/**
 * The source's natural key within its tenant, `issuer:{issuer}`; an issuer too long for the 512-byte key limit is
 * keyed by its SHA-256 instead.
 */
function issuerKey(issuer: string): string {
  const key = `issuer:${issuer}`;
  return new TextEncoder().encode(key).byteLength <= 512 ? key : `issuer#sha256:${hash(issuer)}`;
}

function identifierList(value: unknown, name: string): string[] {
  if (!Array.isArray(value) || value.length > 10) invalid(`${name} must list at most 10 ids`);
  return [...new Set(value.map((entry) => text(entry, name, 128).trim()))];
}

function subjectsValue(value: unknown, current?: SignalSubjectMapping): SignalSubjectMapping {
  const base: SignalSubjectMapping = current
    ? {
        connectionIds: [...current.connectionIds],
        matchEmail: current.matchEmail,
        scimConnectionIds: [...current.scimConnectionIds],
      }
    : { connectionIds: [], matchEmail: false, scimConnectionIds: [] };
  if (value === undefined) return base;
  if (!value || typeof value !== 'object' || Array.isArray(value))
    invalid('subjects must be an object');
  const input = value as Record<string, unknown>;
  for (const key of Object.keys(input))
    if (!['connectionIds', 'matchEmail', 'scimConnectionIds'].includes(key))
      invalid(`Unknown subjects member ${key}`);
  if (input.connectionIds !== undefined)
    base.connectionIds = identifierList(input.connectionIds, 'subjects.connectionIds');
  if (input.scimConnectionIds !== undefined)
    base.scimConnectionIds = identifierList(input.scimConnectionIds, 'subjects.scimConnectionIds');
  if (input.matchEmail !== undefined)
    base.matchEmail = booleanValue(input.matchEmail, 'subjects.matchEmail');
  return base;
}

function actionsValue(value: unknown): Partial<Record<SignalActionableEvent, SignalAction>> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    invalid('actions must map event types to record or revoke-sessions');
  const result: Partial<Record<SignalActionableEvent, SignalAction>> = {};
  for (const [type, action] of Object.entries(value as Record<string, unknown>)) {
    if (!actionableEvents.has(type)) invalid(`actions names an unsupported event type: ${type}`);
    if (!actionValues.has(action as SignalAction))
      invalid(`The action for ${type} must be record or revoke-sessions`);
    result[type as SignalActionableEvent] = action as SignalAction;
  }
  return result;
}

/** The `signals` view of a source: an explicit allowlist without the token hash and the sealed poll token. */
function publicSignalSource(ctx: ServerContext, source: SignalSource): SignalSourceView {
  const view: SignalSourceView = {
    id: source.id,
    tenantId: source.tenantId,
    name: source.name,
    issuer: source.issuer,
    issuerAliases: [...source.issuerAliases],
    audiences: [...source.audiences],
    algorithms: [...source.algorithms],
    delivery: source.delivery,
    hasPushToken: source.pushTokenHash !== undefined,
    subjects: {
      connectionIds: [...source.subjects.connectionIds],
      matchEmail: source.subjects.matchEmail === true,
      scimConnectionIds: [...source.subjects.scimConnectionIds],
    },
    actions: { ...source.actions },
    requireTyp: source.requireTyp !== false,
    status: source.status,
    createdAt: source.createdAt,
    createdBy: source.createdBy,
    updatedAt: source.updatedAt,
    updatedBy: source.updatedBy,
  };
  if (source.delivery === 'push')
    view.pushUrl = `${ctx.config.baseURL.origin}${ctx.config.signals.pushPath}/${source.id}`;
  if (source.jwksUri !== undefined) view.jwksUri = source.jwksUri;
  if (source.jwks !== undefined) view.jwks = structuredClone(source.jwks);
  if (source.tenantClaim !== undefined) view.tenantClaim = source.tenantClaim;
  if (source.poll)
    view.poll = {
      endpoint: source.poll.endpoint,
      maxEvents: source.poll.maxEvents,
      pendingAcks: source.poll.pendingAcks.length,
      ...(source.poll.lastPolledAt !== undefined ? { lastPolledAt: source.poll.lastPolledAt } : {}),
    };
  if (source.lastEventAt !== undefined) view.lastEventAt = source.lastEventAt;
  if (source.lastError !== undefined) view.lastError = { ...source.lastError };
  if (source.lastVerifiedAt !== undefined) view.lastVerifiedAt = source.lastVerifiedAt;
  return view;
}

function publicSignalEvent(record: ReceivedSignal): SignalEventView {
  const view: SignalEventView = {
    id: record.id,
    tenantId: record.tenantId,
    sourceId: record.sourceId,
    jti: record.jti,
    eventType: record.eventType,
    eventUri: record.eventUri,
    issuedAt: record.issuedAt,
    status: record.status,
    claims: structuredClone(record.claims),
    receivedAt: record.receivedAt,
    expiresAt: record.expiresAt,
  };
  if (record.eventTimestamp !== undefined) view.eventTimestamp = record.eventTimestamp;
  if (record.txn !== undefined) view.txn = record.txn;
  if (record.subject !== undefined) view.subject = structuredClone(record.subject);
  if (record.identityId !== undefined) view.identityId = record.identityId;
  if (record.reason !== undefined) view.reason = record.reason;
  if (record.reprocessedAt !== undefined) view.reprocessedAt = record.reprocessedAt;
  if (record.reprocessedBy !== undefined) view.reprocessedBy = record.reprocessedBy;
  return view;
}

/**
 * The `signals` group: the tenant's Shared Signals sources (upstream identity providers that send CAEP and RISC
 * security events about its people) and the events they sent. Reading needs `iam:signals:read`, everything else
 * `iam:signals:manage` on `iam/signals/sources[/{id}]` or `iam/signals/events[/{id}]`; changes need recent
 * authentication. Events arrive through the push endpoint or `iam.signals.poll()`, never through this group.
 */
export function createSignalsApi(ctx: ServerContext) {
  const { auth } = ctx;
  const { operation } = ctx.operations;
  const settings = ctx.config.signals;
  const addressRules = {
    anyPort: true,
    allowPrivateNetworks: settings.allowPrivateNetworks,
    allowInsecureLocalhost: settings.allowInsecureLocalhost,
  };

  /** An issuer: https (loopback http in development), no credentials, query or fragment; trailing slashes dropped. */
  const issuerValue = (value: unknown): string =>
    webIdentityIssuer(value, { allowInsecureLocalhost: settings.allowInsecureLocalhost }).replace(
      /\/+$/,
      '',
    );

  function aliasesValue(value: unknown, issuer: string): string[] {
    if (!Array.isArray(value) || value.length > 5)
      invalid('issuerAliases must list at most 5 issuers');
    const aliases = value.map((alias) => {
      try {
        return issuerValue(alias);
      } catch (error) {
        if (error instanceof IamError) invalid(`issuerAliases: ${error.message}`);
        throw error;
      }
    });
    return [...new Set(aliases)].filter((alias) => alias !== issuer);
  }

  /** A URL the receiver fetches: https on any port (loopback http in development) and a public address. */
  function urlValue(value: unknown, name: string): string {
    const raw = text(value, name, 2048);
    try {
      checkFetchUrl(raw, addressRules);
    } catch (error) {
      if (error instanceof SafeFetchError && error.reason === 'address')
        invalid(`${name} must not point at a private address`);
      invalid(`${name} must be an https URL without credentials or a fragment`);
    }
    return raw;
  }

  function pollTokenValue(value: unknown): string {
    if (
      typeof value !== 'string' ||
      !value.length ||
      value.length > 4096 ||
      !bearerToken.test(value)
    )
      invalid('poll.token must be 1 to 4096 printable characters without spaces');
    return value;
  }

  const maxEventsValue = (value: unknown) => integer(value, 'poll.maxEvents', 1, 100);

  function pollObject(value: unknown): Record<string, unknown> {
    if (!value || typeof value !== 'object' || Array.isArray(value))
      invalid('poll must be an object with endpoint, token and maxEvents');
    for (const key of Object.keys(value))
      if (!['endpoint', 'token', 'maxEvents'].includes(key)) invalid(`Unknown poll member ${key}`);
    return value as Record<string, unknown>;
  }

  /** A source of this tenant, else NOT_FOUND. */
  const scopedSource = (tx: IamStore, tenantId: string, sourceId: string) =>
    ctx.scoped<SignalSource>(tx, sourcesCollection, sourceId, tenantId);

  const forget = (sourceId: string) => signalReceiverOf(ctx).forget(sourceId);

  return {
    /**
     * Registers a transmitter (iam:signals:manage on iam/signals/sources, recent authentication), at most 20 per
     * tenant and one per issuer (CONFLICT). Push sources get a push URL and, unless `pushToken: false`, a bearer token
     * returned only here; poll sources store their poll token sealed. Static keys must be public signature keys; URLs
     * must be https and public (see the `signals` deployment option). Nothing is fetched now. Audited as
     * `signal:source-create`.
     */
    createSource: async (
      credential: CredentialInput,
      input: SignalSourceCreateInput,
    ): Promise<SignalSourceCreated> => {
      const name = text(input.name, 'name', 128).trim();
      const issuer = issuerValue(input.issuer);
      const issuerAliases =
        input.issuerAliases === undefined ? [] : aliasesValue(input.issuerAliases, issuer);
      const audiences = webIdentityAudiences(input.audiences);
      const jwksUri = input.jwksUri === undefined ? undefined : urlValue(input.jwksUri, 'jwksUri');
      const jwks =
        input.jwks === undefined
          ? undefined
          : (webIdentityKeys(input.jwks) as { keys: PublicJwk[] });
      if (jwksUri !== undefined && jwks !== undefined) invalid('Give jwks or jwksUri, not both');
      const algorithms =
        input.algorithms === undefined
          ? [...DEFAULT_SIGNAL_ALGORITHMS]
          : webIdentityAlgorithms(input.algorithms);
      if (!deliveries.has(input.delivery)) invalid('delivery must be push or poll');
      const delivery = input.delivery;
      const wantsPushToken =
        input.pushToken === undefined
          ? delivery === 'push'
          : booleanValue(input.pushToken, 'pushToken');
      if (delivery === 'poll' && wantsPushToken)
        invalid('Poll sources receive no pushes, so they take no push token');
      let poll: { endpoint: string; token: string; maxEvents: number } | undefined;
      if (delivery === 'poll') {
        if (input.poll === undefined) invalid('Poll sources need poll.endpoint and poll.token');
        const given = pollObject(input.poll);
        poll = {
          endpoint: urlValue(given.endpoint, 'poll.endpoint'),
          token: pollTokenValue(given.token),
          maxEvents: given.maxEvents === undefined ? 25 : maxEventsValue(given.maxEvents),
        };
      } else if (input.poll !== undefined) invalid('Only poll sources take poll settings');
      const subjects = subjectsValue(input.subjects);
      const actions = input.actions === undefined ? {} : actionsValue(input.actions);
      const requireTyp =
        input.requireTyp === undefined ? true : booleanValue(input.requireTyp, 'requireTyp');
      const tenantClaim =
        input.tenantClaim === undefined ? undefined : text(input.tenantClaim, 'tenantClaim').trim();
      return operation(
        credential,
        input.tenantId,
        'iam:signals:manage',
        'signals/sources',
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const existing = await tx.find<SignalSource>(sourcesCollection, {
            tenantId: input.tenantId,
          });
          if (existing.length >= maxSignalSourcesPerTenant)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant may register at most ${maxSignalSourcesPerTenant} signal sources`,
              409,
            );
          const uniqueKey = issuerKey(issuer);
          if (existing.some((source) => source.uniqueKey === uniqueKey))
            throw new IamError('CONFLICT', 'A signal source for this issuer already exists', 409);
          const now = ctx.now();
          const sourceId = id();
          const pushToken = wantsPushToken ? token() : undefined;
          const source: SignalSource = {
            id: sourceId,
            tenantId: input.tenantId,
            uniqueKey,
            name,
            issuer,
            issuerAliases,
            audiences,
            ...(jwksUri !== undefined ? { jwksUri } : {}),
            ...(jwks !== undefined ? { jwks } : {}),
            algorithms: algorithms as SignalAlgorithm[],
            delivery,
            ...(pushToken ? { pushTokenHash: hash(pushToken) } : {}),
            ...(poll
              ? {
                  poll: {
                    endpoint: poll.endpoint,
                    tokenSealed: sealPollToken(ctx, sourceId, poll.token),
                    maxEvents: poll.maxEvents,
                    pendingAcks: [],
                  },
                }
              : {}),
            subjects,
            actions,
            requireTyp,
            ...(tenantClaim !== undefined ? { tenantClaim } : {}),
            status: 'active',
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          };
          await tx.insert<SignalSource>(sourcesCollection, source);
          await ctx.events.audit(
            tx,
            principal,
            'signal:source-create',
            input.tenantId,
            sourceResource(sourceId),
            'allow',
            false,
            { name, issuer, delivery },
          );
          const view = publicSignalSource(ctx, source);
          return {
            source: view,
            ...(view.pushUrl !== undefined ? { pushUrl: view.pushUrl } : {}),
            ...(pushToken ? { pushToken } : {}),
          };
        },
      );
    },

    /** The tenant's signal sources, oldest first (iam:signals:read on iam/signals/sources). */
    listSources: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<SignalSourceView[]> =>
      operation(credential, input.tenantId, 'iam:signals:read', 'signals/sources', async ({ tx }) =>
        (await tx.find<SignalSource>(sourcesCollection, { tenantId: input.tenantId }))
          .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0))
          .map((source) => publicSignalSource(ctx, source)),
      ),

    /** One signal source (iam:signals:read on iam/signals/sources/{id}). */
    getSource: async (
      credential: CredentialInput,
      input: { tenantId: string; sourceId: string },
    ): Promise<SignalSourceView> => {
      const sourceId = text(input.sourceId, 'sourceId');
      return operation(
        credential,
        input.tenantId,
        'iam:signals:read',
        sourceResource(sourceId),
        async ({ tx }) => publicSignalSource(ctx, await scopedSource(tx, input.tenantId, sourceId)),
      );
    },

    /**
     * Changes a source (iam:signals:manage on iam/signals/sources/{id}, recent authentication): names, aliases,
     * audiences, keys (`null` clears `jwksUri` or `jwks`; without either, keys are discovered), algorithms, poll
     * settings (a new endpoint needs its token again and starts with no pending acknowledgements), subject mapping,
     * actions, `requireTyp` and `status` (a disabled source's pushes answer 404 and it is not polled). The issuer and
     * delivery cannot change. Cached keys are dropped. An update that changes nothing is INVALID_INPUT. Audited as
     * `signal:source-update` with the changed fields.
     */
    updateSource: async (
      credential: CredentialInput,
      input: SignalSourceUpdateInput,
    ): Promise<SignalSourceView> => {
      const given = input as unknown as Record<string, unknown>;
      if (given.issuer !== undefined) invalid('The issuer of a source cannot change');
      if (given.delivery !== undefined) invalid('The delivery of a source cannot change');
      if (given.pushToken !== undefined) invalid('Use rotatePushToken to change the push token');
      const sourceId = text(input.sourceId, 'sourceId');
      if (!updatableFields.some((field) => given[field] !== undefined))
        invalid('The update changes nothing');
      if (input.status !== undefined && !sourceStatuses.has(input.status))
        invalid('status must be active or disabled');
      const updated = await operation(
        credential,
        input.tenantId,
        'iam:signals:manage',
        sourceResource(sourceId),
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const source = await scopedSource(tx, input.tenantId, sourceId);
          const next: SignalSource = { ...source };
          if (input.name !== undefined) next.name = text(input.name, 'name', 128).trim();
          if (input.issuerAliases !== undefined)
            next.issuerAliases = aliasesValue(input.issuerAliases, source.issuer);
          if (input.audiences !== undefined) next.audiences = webIdentityAudiences(input.audiences);
          if (input.jwksUri === null) delete next.jwksUri;
          else if (input.jwksUri !== undefined) next.jwksUri = urlValue(input.jwksUri, 'jwksUri');
          if (input.jwks === null) delete next.jwks;
          else if (input.jwks !== undefined)
            next.jwks = webIdentityKeys(input.jwks) as { keys: PublicJwk[] };
          if (next.jwksUri !== undefined && next.jwks !== undefined)
            invalid('Give jwks or jwksUri, not both');
          if (input.algorithms !== undefined)
            next.algorithms = webIdentityAlgorithms(input.algorithms) as SignalAlgorithm[];
          if (input.poll !== undefined) {
            if (source.delivery !== 'poll' || !source.poll)
              invalid('Only poll sources take poll settings');
            const poll = pollObject(input.poll);
            const state: SignalPollState = {
              ...source.poll,
              pendingAcks: [...source.poll.pendingAcks],
            };
            if (poll.endpoint !== undefined) {
              const endpoint = urlValue(poll.endpoint, 'poll.endpoint');
              if (endpoint !== source.poll.endpoint) {
                // The stored token was given for the old endpoint only; the new one's queue starts fresh.
                if (poll.token === undefined) invalid('A new poll endpoint needs its token again');
                state.endpoint = endpoint;
                state.pendingAcks = [];
                delete state.pendingErrors;
              }
            }
            if (poll.token !== undefined)
              state.tokenSealed = sealPollToken(ctx, source.id, pollTokenValue(poll.token));
            if (poll.maxEvents !== undefined) state.maxEvents = maxEventsValue(poll.maxEvents);
            next.poll = state;
          }
          if (input.subjects !== undefined)
            next.subjects = subjectsValue(input.subjects, source.subjects);
          if (input.actions !== undefined) next.actions = actionsValue(input.actions);
          if (input.requireTyp !== undefined)
            next.requireTyp = booleanValue(input.requireTyp, 'requireTyp');
          if (input.tenantClaim === null) delete next.tenantClaim;
          else if (input.tenantClaim !== undefined)
            next.tenantClaim = text(input.tenantClaim, 'tenantClaim').trim();
          if (input.status !== undefined) next.status = input.status;
          const changed = updatableFields.filter(
            (field) =>
              JSON.stringify(source[field] ?? null) !== JSON.stringify(next[field] ?? null),
          );
          if (!changed.length) invalid('The update changes nothing');
          next.updatedAt = ctx.now();
          next.updatedBy = principal.identity.id;
          const stored = await tx.put<SignalSource>(sourcesCollection, next);
          await ctx.events.audit(
            tx,
            principal,
            'signal:source-update',
            input.tenantId,
            sourceResource(source.id),
            'allow',
            false,
            { changed: [...changed] },
          );
          return publicSignalSource(ctx, stored);
        },
      );
      forget(updated.id);
      return updated;
    },

    /**
     * Deletes a source (iam:signals:manage on iam/signals/sources/{id}, recent authentication). Its pushes answer 404
     * from now on; the events it sent stay until the retention sweep removes them. Audited as `signal:source-delete`.
     */
    deleteSource: async (
      credential: CredentialInput,
      input: { tenantId: string; sourceId: string },
    ): Promise<{ deleted: true }> => {
      const sourceId = text(input.sourceId, 'sourceId');
      const result = await operation(
        credential,
        input.tenantId,
        'iam:signals:manage',
        sourceResource(sourceId),
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const source = await scopedSource(tx, input.tenantId, sourceId);
          await tx.delete(sourcesCollection, source.id);
          await ctx.events.audit(
            tx,
            principal,
            'signal:source-delete',
            input.tenantId,
            sourceResource(source.id),
            'allow',
            false,
            { name: source.name, issuer: source.issuer },
          );
          return { deleted: true as const };
        },
      );
      forget(sourceId);
      return result;
    },

    /**
     * Replaces a push source's bearer token (iam:signals:manage on iam/signals/sources/{id}, recent authentication)
     * and returns the new one, shown only here; the old one stops working at once. Also gives a push source created
     * without a token one. Audited as `signal:source-rotate`.
     */
    rotatePushToken: async (
      credential: CredentialInput,
      input: { tenantId: string; sourceId: string },
    ): Promise<{ pushToken: string }> => {
      const sourceId = text(input.sourceId, 'sourceId');
      return operation(
        credential,
        input.tenantId,
        'iam:signals:manage',
        sourceResource(sourceId),
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const source = await scopedSource(tx, input.tenantId, sourceId);
          if (source.delivery !== 'push') invalid('Only push sources have a push token');
          const pushToken = token();
          await tx.put<SignalSource>(sourcesCollection, {
            ...source,
            pushTokenHash: hash(pushToken),
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await ctx.events.audit(
            tx,
            principal,
            'signal:source-rotate',
            input.tenantId,
            sourceResource(source.id),
            'allow',
            false,
            { replaced: source.pushTokenHash !== undefined },
          );
          return { pushToken };
        },
      );
    },

    /**
     * Received events, newest first, optionally of one source, status, identity or event type (iam:signals:read on
     * iam/signals/events). `limit` 1..1000 (default 100), `offset` from 0.
     */
    listEvents: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        sourceId?: string;
        status?: SignalStatus;
        identityId?: string;
        eventType?: SignalEventType;
        limit?: number;
        offset?: number;
      },
    ): Promise<SignalEventPage> => {
      const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
      const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
      const sourceId = input.sourceId === undefined ? undefined : text(input.sourceId, 'sourceId');
      const identityId =
        input.identityId === undefined ? undefined : text(input.identityId, 'identityId');
      if (input.status !== undefined && !statuses.has(input.status))
        invalid('status must be applied, recorded, unmatched, ignored or failed');
      if (input.eventType !== undefined && !knownEventTypes.has(input.eventType))
        invalid('Unknown eventType');
      return operation(
        credential,
        input.tenantId,
        'iam:signals:read',
        'signals/events',
        async ({ tx }) => {
          const events = await findOrdered<ReceivedSignal>(
            tx,
            eventsCollection,
            {
              tenantId: input.tenantId,
              ...(sourceId !== undefined ? { streamId: sourceId } : {}),
              ...(input.status !== undefined ? { status: input.status } : {}),
              ...(identityId !== undefined ? { identityId } : {}),
              ...(input.eventType !== undefined ? { eventType: input.eventType } : {}),
            },
            { field: 'timestamp', direction: 'desc' },
          );
          return {
            events: events.slice(offset, offset + limit).map(publicSignalEvent),
            total: events.length,
          };
        },
      );
    },

    /** One received event (iam:signals:read on iam/signals/events/{id}). */
    getEvent: async (
      credential: CredentialInput,
      input: { tenantId: string; eventId: string },
    ): Promise<SignalEventView> => {
      const eventId = text(input.eventId, 'eventId');
      return operation(
        credential,
        input.tenantId,
        'iam:signals:read',
        eventResource(eventId),
        async ({ tx }) =>
          publicSignalEvent(
            await ctx.scoped<ReceivedSignal>(tx, eventsCollection, eventId, input.tenantId),
          ),
      );
    },

    /**
     * Maps and applies an `unmatched` or `failed` event again, after the source's mapping or the directory changed
     * (iam:signals:manage on iam/signals/events/{id}, recent authentication; INVALID_TRANSITION for other statuses or a
     * disabled source, NOT_FOUND when the source is gone). The configured action runs as on receipt; an event that now
     * matches someone is audited as `signal:received` again for threat detection. Audited as `signal:reprocess`.
     */
    reprocess: async (
      credential: CredentialInput,
      input: { tenantId: string; eventId: string },
    ): Promise<SignalEventView> => {
      const eventId = text(input.eventId, 'eventId');
      return operation(
        credential,
        input.tenantId,
        'iam:signals:manage',
        eventResource(eventId),
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const record = await ctx.scoped<ReceivedSignal>(
            tx,
            eventsCollection,
            eventId,
            input.tenantId,
          );
          if (record.status !== 'unmatched' && record.status !== 'failed')
            throw new IamError(
              'INVALID_TRANSITION',
              'Only unmatched and failed events can be reprocessed',
              409,
            );
          const source = await tx.get<SignalSource>(sourcesCollection, record.sourceId);
          if (!source || source.tenantId !== input.tenantId)
            throw new IamError('NOT_FOUND', 'The source of this event no longer exists', 404);
          if (source.status !== 'active')
            throw new IamError('INVALID_TRANSITION', 'The source of this event is disabled', 409);
          const subject = record.subject ? parseSubjectIdentifier(record.subject) : undefined;
          const outcome = await applySignal(ctx, tx, source, {
            eventType: record.eventType,
            ...(subject ? { subject } : {}),
            event: record.claims,
            jti: record.jti,
          });
          const { identityId: _identityId, reason: _reason, ...rest } = record;
          const stored = await tx.put<ReceivedSignal>(eventsCollection, {
            ...rest,
            status: outcome.status,
            ...(outcome.identityId ? { identityId: outcome.identityId } : {}),
            ...(outcome.reason ? { reason: outcome.reason } : {}),
            reprocessedAt: ctx.now(),
            reprocessedBy: principal.identity.id,
          });
          if (outcome.source !== source)
            await tx.put<SignalSource>(sourcesCollection, outcome.source);
          if (stored.identityId) await recordSignalReceived(ctx, tx, source, stored, record.claims);
          await ctx.events.audit(
            tx,
            principal,
            'signal:reprocess',
            input.tenantId,
            eventResource(record.id),
            'allow',
            false,
            {
              sourceId: source.id,
              eventType: record.eventType,
              jti: record.jti,
              previousStatus: record.status,
              status: stored.status,
              ...(stored.identityId ? { identityId: stored.identityId } : {}),
            },
          );
          return publicSignalEvent(stored);
        },
      );
    },

    /**
     * Polls one poll source now (iam:signals:manage on iam/signals/sources/{id}), as the scheduled `iam.signals.poll()`
     * does: the permission and the source are checked first, then the transmitter is called outside any transaction.
     * INVALID_INPUT for a push source, INVALID_TRANSITION for a disabled one.
     */
    poll: async (
      credential: CredentialInput,
      input: { tenantId: string; sourceId: string },
    ): Promise<SignalPollResult> => {
      const sourceId = text(input.sourceId, 'sourceId');
      await operation(
        credential,
        input.tenantId,
        'iam:signals:manage',
        sourceResource(sourceId),
        async ({ tx }) => {
          const source = await scopedSource(tx, input.tenantId, sourceId);
          if (source.delivery !== 'poll') invalid('This source receives its events by push');
          if (source.status !== 'active')
            throw new IamError('INVALID_TRANSITION', 'The source is disabled', 409);
          return null;
        },
      );
      return signalReceiverOf(ctx).poll({ sourceId });
    },
  };
}
