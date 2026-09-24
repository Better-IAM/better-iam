import {
  IamError,
  canonicalJson,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Session,
  type SessionClientInfo,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { AccessRequest, Group, GroupMember, PackageRequest } from '../models.js';
import { OperationDenied } from '../operations.js';
import {
  activeHold,
  consentState,
  consentsOf,
  dayMs,
  days,
  decidable,
  emailSubject,
  externalSubjectId,
  identitySubject,
  legalBases,
  oneOf,
  privacySettings,
  prose,
  purposeKey,
  receiptFromEvent,
  receiptSignatureValid,
  regulationDeadlines,
  regulations,
  rejectionReasons,
  requestNumber,
  requestOverdue,
  resolveSubject,
  responseWindow,
  restrictionOf,
  restrictionState,
  subjectRequestTypes,
  type ConsentMode,
  type ConsentReceipt,
  type ConsentSource,
  type ConsentState,
  type LegalBasis,
  type PrivacyConsent,
  type PrivacyConsentEvent,
  type PrivacyExport,
  type PrivacyHold,
  type PrivacyPurpose,
  type PrivacyRestriction,
  type PrivacySettings,
  type Regulation,
  type RejectionReason,
  type ResolvedSubject,
  type SubjectInput,
  type SubjectRequest,
  type SubjectRequestEvent,
  type SubjectRequestType,
} from '../privacy.js';
import { actsInOwnRight } from '../session-kinds.js';
import { hash, id, publicIdentity, sameHash, token } from '../utils.js';
import { email, integer, object, strings, text } from '../validation.js';
import { deleteIdentity } from './identities.js';

export interface PurposeInput {
  key: string;
  name: string;
  description: string;
  legalBasis: LegalBasis;
  mode?: ConsentMode;
  dataCategories?: string[];
  retentionDays?: number;
  consentLifetimeDays?: number;
  reconsentOnVersion?: boolean;
}
/** A purpose as the signed-in person sees it, with their decision and what it means right now. */
export interface MyPurpose {
  id: string;
  key: string;
  name: string;
  description: string;
  legalBasis: LegalBasis;
  mode: ConsentMode;
  version: number;
  dataCategories: string[];
  retentionDays?: number;
  /** Whether the person decides (consent and legitimate-interest purposes); others are shown for information. */
  decidable: boolean;
  state: ConsentState;
  consent?: {
    granted: boolean;
    purposeVersion: number;
    recordedAt: number;
    expiresAt?: number;
    receiptId: string;
  };
}
export interface SubjectRequestView {
  id: string;
  tenantId: string;
  number: string;
  type: SubjectRequestType;
  regulation: Regulation;
  status: SubjectRequest['status'];
  subject: string;
  identityId?: string;
  externalId?: string;
  /** The account's display name or email, for identity subjects that still exist. */
  subjectName?: string;
  requesterEmail?: string;
  requesterName?: string;
  details?: string;
  purposeKeys?: string[];
  channel: SubjectRequest['channel'];
  verification: SubjectRequest['verification'];
  submittedAt: number;
  receivedAt?: number;
  dueAt?: number;
  extendedAt?: number;
  extensionReason?: string;
  assigneeId?: string;
  closedAt?: number;
  closedBy?: string;
  rejectionReason?: RejectionReason;
  actions?: string[];
  exportId?: string;
  redacted?: boolean;
  overdue: boolean;
  events: SubjectRequestEvent[];
}
export interface ConsentView {
  id: string;
  purposeKey: string;
  subject: string;
  identityId?: string;
  externalId?: string;
  granted: boolean;
  purposeVersion: number;
  source: ConsentSource;
  method?: string;
  recordedAt: number;
  recordedBy: string;
  expiresAt?: number;
  receiptId: string;
  state: ConsentState;
}
export interface ConsentHistoryEntry {
  receiptId: string;
  purposeKey: string;
  purposeVersion: number;
  subject: string;
  granted: boolean;
  source: ConsentSource;
  method?: string;
  evidence?: string;
  ip?: string;
  userAgent?: string;
  recordedAt: number;
  recordedBy: string;
  redacted?: boolean;
}
export interface PrivacySummary {
  purposes: Array<{
    id: string;
    key: string;
    name: string;
    legalBasis: LegalBasis;
    mode: ConsentMode;
    version: number;
    archived: boolean;
    /** Subjects the purpose may be processed for on the strength of a recorded decision. */
    granted: number;
    withdrawn: number;
    expired: number;
    outdated: number;
  }>;
  requests: {
    pendingVerification: number;
    open: number;
    overdue: number;
    /** Open requests due within seven days. */
    dueSoon: number;
    completedLast30Days: number;
    /** Median days from receipt to closing, over requests closed in the last 90 days. */
    medianDaysToClose?: number;
    byType: Record<SubjectRequestType, number>;
  };
  holds: number;
  restrictions: number;
}
export interface PrivacySettingsView {
  contactEmail?: string;
  contactName?: string;
  defaultRegulation: Regulation;
  responseDays?: Partial<Record<Regulation, number>>;
  publicIntake: boolean;
  exportLifetimeDays: number;
  /** Statutory windows, for display next to the tenant's own. */
  statutory: Record<Regulation, { responseDays: number; extensionDays: number }>;
}
export interface DeadlineReminderResult {
  reminded: Array<{ tenantId: string; requestId: string; kind: 'due-soon' | 'overdue' }>;
  /** Public requests nobody confirmed within seven days, now cancelled. */
  lapsed: number;
}

const maxPurposes = 200;
const maxEvents = 100;
const verificationLifetimeMs = 7 * dayMs;

/** Methods and evidence recorded with a decision: short labels and free text. */
function method(value: unknown): string | undefined {
  if (value === undefined || value === null || value === '') return undefined;
  const result = text(value, 'method', 64);
  if (!/^[\w .:/-]+$/.test(result)) throw new IamError('INVALID_INPUT', 'Invalid method');
  return result;
}
const evidence = (value: unknown): string | undefined =>
  value === undefined || value === null || value === ''
    ? undefined
    : prose(value, 'evidence', 2000);

function categories(value: unknown): string[] {
  if (value === undefined) return [];
  const list = [...new Set(strings(value, 'dataCategories'))];
  if (list.length > 32 || list.some((item) => !/^[a-z][a-z0-9_-]{0,63}$/.test(item)))
    throw new IamError(
      'INVALID_INPUT',
      'dataCategories must hold at most 32 lowercase identifiers such as contact or usage',
    );
  return list.sort();
}

/** Privacy self-service is the person's own business: refused for role sessions, delegated agents and other tenants. */
function selfSession(principal: AuthenticatedPrincipal, tenantId: string): void {
  if (
    !actsInOwnRight(principal.session) ||
    principal.session.kind !== 'user' ||
    principal.session.tenantId !== tenantId ||
    principal.identity.tenantId !== tenantId ||
    principal.identity.kind !== 'user'
  )
    throw new IamError(
      'ACCESS_DENIED',
      'Privacy choices are made by the person, from a signed-in session of their organization',
      403,
    );
  if (principal.session.impersonatorId)
    throw new IamError(
      'IMPERSONATION_RESTRICTED',
      'Privacy choices cannot be made while impersonating',
      403,
    );
}

function purposeFields(input: Partial<PurposeInput>, previous?: PrivacyPurpose) {
  const key = previous ? previous.key : purposeKey(input.key);
  if (previous && input.key !== undefined && input.key !== previous.key)
    throw new IamError('INVALID_INPUT', 'A purpose key cannot change; create a new purpose');
  const name = text(input.name ?? previous?.name, 'name', 120).trim();
  const description = prose(input.description ?? previous?.description, 'description', 5000);
  const legalBasis = oneOf(input.legalBasis ?? previous?.legalBasis, legalBases, 'legalBasis');
  const mode = oneOf(
    input.mode ?? previous?.mode ?? 'opt-in',
    ['opt-in', 'opt-out'] as const,
    'mode',
  );
  if (mode === 'opt-out' && legalBasis !== 'consent')
    throw new IamError('INVALID_INPUT', 'Only consent purposes can be opt-out');
  const retention =
    input.retentionDays === undefined
      ? previous?.retentionDays
      : input.retentionDays === null
        ? undefined
        : days(input.retentionDays, 'retentionDays', 36500);
  const lifetime =
    input.consentLifetimeDays === undefined
      ? previous?.consentLifetimeDays
      : input.consentLifetimeDays === null
        ? undefined
        : days(input.consentLifetimeDays, 'consentLifetimeDays');
  if (lifetime !== undefined && legalBasis !== 'consent')
    throw new IamError('INVALID_INPUT', 'consentLifetimeDays applies to consent purposes only');
  const reconsent = input.reconsentOnVersion ?? previous?.reconsentOnVersion ?? true;
  if (typeof reconsent !== 'boolean')
    throw new IamError('INVALID_INPUT', 'reconsentOnVersion must be a boolean');
  return {
    uniqueKey: `key:${key}`,
    key,
    name,
    description,
    legalBasis,
    mode,
    dataCategories:
      input.dataCategories === undefined
        ? (previous?.dataCategories ?? [])
        : categories(input.dataCategories),
    ...(retention !== undefined ? { retentionDays: retention } : {}),
    ...(lifetime !== undefined ? { consentLifetimeDays: lifetime } : {}),
    reconsentOnVersion: reconsent,
  };
}

async function purposeByKey(
  tx: IamStore,
  tenantId: string,
  key: unknown,
): Promise<PrivacyPurpose> {
  const found = (
    await tx.find<PrivacyPurpose>('privacyPurposes', {
      tenantId,
      uniqueKey: `key:${purposeKey(key)}`,
    })
  )[0];
  if (!found) throw new IamError('NOT_FOUND', 'Purpose not found', 404);
  return found;
}

function consentView(
  consent: PrivacyConsent,
  purpose: PrivacyPurpose,
  restricted: boolean,
  now: number,
): ConsentView {
  return {
    id: consent.id,
    purposeKey: consent.purposeKey,
    subject: consent.subject,
    ...(consent.identityId ? { identityId: consent.identityId } : {}),
    ...(consent.externalId !== undefined ? { externalId: consent.externalId } : {}),
    granted: consent.granted,
    purposeVersion: consent.purposeVersion,
    source: consent.source,
    ...(consent.method ? { method: consent.method } : {}),
    recordedAt: consent.recordedAt,
    recordedBy: consent.recordedBy,
    ...(consent.expiresAt !== undefined ? { expiresAt: consent.expiresAt } : {}),
    receiptId: consent.receiptId,
    state: consentState(purpose, consent, restricted, now),
  };
}

function historyEntry(event: PrivacyConsentEvent): ConsentHistoryEntry {
  return {
    receiptId: event.receiptId,
    purposeKey: event.purposeKey,
    purposeVersion: event.purposeVersion,
    subject: event.subject,
    granted: event.granted,
    source: event.source,
    ...(event.method ? { method: event.method } : {}),
    ...(event.evidence ? { evidence: event.evidence } : {}),
    ...(event.ip ? { ip: event.ip } : {}),
    ...(event.userAgent ? { userAgent: event.userAgent } : {}),
    recordedAt: event.recordedAt,
    recordedBy: event.recordedBy,
    ...(event.redacted ? { redacted: true } : {}),
  };
}

function requestView(
  request: SubjectRequest,
  now: number,
  subjectName?: string,
): SubjectRequestView {
  const { tokenHash: _hash, tokenExpiresAt: _expires, reminded: _reminded, ...rest } = request;
  return {
    id: rest.id,
    tenantId: rest.tenantId,
    number: rest.number,
    type: rest.type,
    regulation: rest.regulation,
    status: rest.status,
    subject: rest.subject,
    ...(rest.identityId ? { identityId: rest.identityId } : {}),
    ...(rest.externalId !== undefined ? { externalId: rest.externalId } : {}),
    ...(subjectName ? { subjectName } : {}),
    ...(rest.requesterEmail ? { requesterEmail: rest.requesterEmail } : {}),
    ...(rest.requesterName ? { requesterName: rest.requesterName } : {}),
    ...(rest.details ? { details: rest.details } : {}),
    ...(rest.purposeKeys?.length ? { purposeKeys: rest.purposeKeys } : {}),
    channel: rest.channel,
    verification: rest.verification,
    submittedAt: rest.submittedAt,
    ...(rest.receivedAt !== undefined ? { receivedAt: rest.receivedAt } : {}),
    ...(rest.dueAt !== undefined ? { dueAt: rest.dueAt } : {}),
    ...(rest.extendedAt !== undefined ? { extendedAt: rest.extendedAt } : {}),
    ...(rest.extensionReason ? { extensionReason: rest.extensionReason } : {}),
    ...(rest.assigneeId ? { assigneeId: rest.assigneeId } : {}),
    ...(rest.closedAt !== undefined ? { closedAt: rest.closedAt } : {}),
    ...(rest.closedBy ? { closedBy: rest.closedBy } : {}),
    ...(rest.rejectionReason ? { rejectionReason: rest.rejectionReason } : {}),
    ...(rest.actions?.length ? { actions: rest.actions } : {}),
    ...(rest.exportId ? { exportId: rest.exportId } : {}),
    ...(rest.redacted ? { redacted: true } : {}),
    overdue: requestOverdue(request, now),
    events: rest.events,
  };
}

/** The subject's own view: staff notes and assignment stay internal. */
function mineView(request: SubjectRequest, now: number): SubjectRequestView {
  const view = requestView(request, now);
  const { assigneeId: _assignee, closedBy: _closer, ...rest } = view;
  return {
    ...rest,
    events: view.events
      .filter((event) => event.what !== 'note' && event.what !== 'assigned')
      .map(({ note, by: _by, ...event }) =>
        event.what === 'rejected' || event.what === 'extended' || event.what === 'completed'
          ? { ...event, by: 'organization', ...(note ? { note } : {}) }
          : { ...event, by: 'organization' },
      ),
  };
}

const pushEvent = (request: SubjectRequest, event: SubjectRequestEvent): SubjectRequestEvent[] =>
  [...request.events, event].slice(-maxEvents);

/** Whether an email delivery callback exists; privacy emails are optional niceties otherwise. */
const canEmail = (ctx: ServerContext): boolean => Boolean(ctx.options.authentication?.sendEmail);

/** Tells the privacy contact about a request that now needs handling. */
async function notifyContact(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  request: SubjectRequest,
): Promise<void> {
  const settings = await privacySettings(tx, tenant.id);
  if (!settings.contactEmail || !canEmail(ctx)) return;
  await ctx.auth.enqueueDelivery(tx, {
    tenantId: tenant.id,
    kind: 'email',
    to: settings.contactEmail,
    template: 'privacy-request-received',
    payload: {
      tenantId: tenant.id,
      tenantName: tenant.name,
      requestId: request.id,
      number: request.number,
      type: request.type,
      regulation: request.regulation,
      ...(request.dueAt !== undefined ? { dueAt: String(request.dueAt) } : {}),
      channel: request.channel,
    },
  });
}

/** Where the subject hears back: their account's address, or the requester's. */
async function subjectAddress(
  tx: IamStore,
  request: SubjectRequest,
): Promise<string | undefined> {
  if (request.identityId) {
    const identity = await tx.get<Identity>('identities', request.identityId);
    if (identity?.email && identity.status !== 'deleted') return identity.email;
  }
  return request.requesterEmail;
}

async function notifySubject(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  request: SubjectRequest,
  event: 'completed' | 'rejected' | 'extended',
  to?: string,
): Promise<void> {
  const address = to ?? (await subjectAddress(tx, request));
  if (!address || !canEmail(ctx)) return;
  await ctx.auth.enqueueDelivery(tx, {
    tenantId: tenant.id,
    kind: 'email',
    to: address,
    template: 'privacy-request-update',
    payload: {
      tenantId: tenant.id,
      tenantName: tenant.name,
      requestId: request.id,
      number: request.number,
      type: request.type,
      event,
      ...(request.dueAt !== undefined ? { dueAt: String(request.dueAt) } : {}),
      ...(event === 'rejected' && request.rejectionReason
        ? { reason: request.rejectionReason }
        : {}),
      ...(event === 'completed' && request.exportId ? { exportReady: 'true' } : {}),
      ...(request.identityId && event === 'completed' && request.type !== 'erasure'
        ? { account: 'true' }
        : {}),
    },
  });
}

/**
 * Records one decision: the current state (unless a newer decision is already recorded, as imports can be older) and
 * an entry in the consent history. Returns the signed receipt.
 */
async function writeConsent(
  ctx: ServerContext,
  tx: IamStore,
  input: {
    tenantId: string;
    purpose: PrivacyPurpose;
    subject: ResolvedSubject;
    granted: boolean;
    source: ConsentSource;
    method?: string;
    evidence?: string;
    recordedBy: string;
    at: number;
    version?: number;
    client?: SessionClientInfo;
  },
): Promise<{ receipt: ConsentReceipt; current: boolean }> {
  const { purpose, subject } = input;
  if (!decidable(purpose))
    throw new IamError(
      'INVALID_INPUT',
      `Purpose ${purpose.key} relies on ${purpose.legalBasis}, not on consent`,
    );
  if (purpose.archived && input.granted)
    throw new IamError('CONFLICT', `Purpose ${purpose.key} is archived`, 409);
  const purposeVersion =
    input.version === undefined
      ? purpose.version
      : integer(input.version, 'version', 1, purpose.version);
  const receiptId = id();
  const expiresAt =
    input.granted && purpose.consentLifetimeDays !== undefined
      ? input.at + purpose.consentLifetimeDays * dayMs
      : undefined;
  const uniqueKey = `${purpose.id}:${subject.key}`;
  const existing = (
    await tx.find<PrivacyConsent>('privacyConsents', { tenantId: input.tenantId, uniqueKey })
  )[0];
  const event: PrivacyConsentEvent = {
    id: receiptId,
    tenantId: input.tenantId,
    receiptId,
    purposeId: purpose.id,
    purposeKey: purpose.key,
    purposeName: purpose.name,
    legalBasis: purpose.legalBasis,
    purposeVersion,
    subject: subject.key,
    ...(subject.identityId ? { identityId: subject.identityId } : {}),
    ...(subject.externalId !== undefined ? { externalId: subject.externalId } : {}),
    granted: input.granted,
    source: input.source,
    ...(input.method ? { method: input.method } : {}),
    ...(input.evidence ? { evidence: input.evidence } : {}),
    ...(input.client?.ip ? { ip: input.client.ip } : {}),
    ...(input.client?.userAgent ? { userAgent: input.client.userAgent.slice(0, 512) } : {}),
    recordedAt: input.at,
    recordedBy: input.recordedBy,
  };
  const current = !existing || existing.recordedAt <= input.at;
  if (current) {
    const record: PrivacyConsent = {
      id: existing?.id ?? id(),
      tenantId: input.tenantId,
      uniqueKey,
      purposeId: purpose.id,
      purposeKey: purpose.key,
      subject: subject.key,
      ...(subject.identityId ? { identityId: subject.identityId } : {}),
      ...(subject.externalId !== undefined ? { externalId: subject.externalId } : {}),
      granted: input.granted,
      purposeVersion,
      source: input.source,
      ...(input.method ? { method: input.method } : {}),
      recordedAt: input.at,
      recordedBy: input.recordedBy,
      ...(expiresAt !== undefined ? { expiresAt } : {}),
      receiptId,
    };
    await (existing ? tx.put('privacyConsents', record) : tx.insert('privacyConsents', record));
  }
  await tx.insert<PrivacyConsentEvent>('privacyConsentEvents', event);
  return { receipt: receiptFromEvent(ctx.options.secret, event), current };
}

/** Everything the tenant holds about a subject, as JSON: the answer to an access or portability request. */
async function buildExport(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  request: SubjectRequest,
  scope: 'full' | 'provided',
  /** The person's own activity from the audit log; only when the handler may read the audit log. */
  includeActivity: boolean,
): Promise<Json> {
  const tenantId = tenant.id;
  const subject = request.subject;
  const now = ctx.now();
  const purposes = new Map(
    (await tx.find<PrivacyPurpose>('privacyPurposes', { tenantId })).map((purpose) => [
      purpose.id,
      purpose,
    ]),
  );
  const restricted = restrictionState(await restrictionOf(tx, tenantId, subject));
  const consents = [...(await consentsOf(tx, tenantId, subject)).values()].map((consent) => {
    const purpose = purposes.get(consent.purposeId);
    return {
      purpose: consent.purposeKey,
      purposeName: purpose?.name ?? consent.purposeKey,
      granted: consent.granted,
      purposeVersion: consent.purposeVersion,
      recordedAt: new Date(consent.recordedAt).toISOString(),
      ...(consent.expiresAt !== undefined
        ? { expiresAt: new Date(consent.expiresAt).toISOString() }
        : {}),
      source: consent.source,
      ...(purpose ? { state: consentState(purpose, consent, restricted, now).reason } : {}),
    };
  });
  const history = (await tx.find<PrivacyConsentEvent>('privacyConsentEvents', { tenantId, subject }))
    .sort((a, b) => a.recordedAt - b.recordedAt)
    .map((event) => ({
      purpose: event.purposeKey,
      granted: event.granted,
      purposeVersion: event.purposeVersion,
      recordedAt: new Date(event.recordedAt).toISOString(),
      source: event.source,
      ...(event.method ? { method: event.method } : {}),
      ...(event.evidence ? { evidence: event.evidence } : {}),
      ...(event.ip ? { ip: event.ip } : {}),
      receiptId: event.receiptId,
    }));
  const processing = [...purposes.values()]
    .filter((purpose) => !purpose.archived)
    .map((purpose) => ({
      purpose: purpose.key,
      name: purpose.name,
      description: purpose.description,
      legalBasis: purpose.legalBasis,
      dataCategories: purpose.dataCategories,
      ...(purpose.retentionDays !== undefined ? { retentionDays: purpose.retentionDays } : {}),
    }));
  const requests = (await tx.find<SubjectRequest>('privacyRequests', { tenantId, subject })).map(
    (item) => ({
      number: item.number,
      type: item.type,
      status: item.status,
      submittedAt: new Date(item.submittedAt).toISOString(),
      ...(item.closedAt !== undefined ? { closedAt: new Date(item.closedAt).toISOString() } : {}),
    }),
  );
  const base = {
    format: 'better-iam.privacy-export',
    version: 1,
    scope,
    generatedAt: new Date(now).toISOString(),
    organization: { id: tenant.id, name: tenant.name },
    request: { number: request.number, type: request.type, regulation: request.regulation },
    subject: request.identityId
      ? { kind: 'account', id: request.identityId }
      : request.externalId !== undefined
        ? { kind: 'external', id: request.externalId }
        : { kind: 'requester', email: request.requesterEmail ?? '' },
    consents,
    consentHistory: history,
  };
  const identity = request.identityId
    ? await tx.get<Identity>('identities', request.identityId)
    : undefined;
  if (!identity || identity.status === 'deleted')
    return {
      ...base,
      ...(scope === 'full' ? { processing, requests } : {}),
    } as unknown as Json;
  const profile = publicIdentity(identity);
  const onboarding = (
    await tx.find('onboardingProgress', { tenantId, subjectId: identity.id })
  ).map(({ id: _id, tenantId: _tenant, uniqueKey: _key, ...rest }) => rest);
  const agreements = await Promise.all(
    (await tx.find('agreementAcceptances', { tenantId, identityId: identity.id })).map(
      async (acceptance) => {
        const agreement = await tx.get('agreements', acceptance.agreementId as string);
        return {
          agreement: (agreement?.name as string | undefined) ?? acceptance.agreementId,
          version: acceptance.version,
          acceptedAt: new Date(acceptance.acceptedAt as number).toISOString(),
        };
      },
    ),
  );
  if (scope === 'provided')
    return {
      ...base,
      profile: {
        name: profile.name,
        ...(profile.email ? { email: profile.email } : {}),
        ...(profile.phone ? { phone: profile.phone } : {}),
        ...(profile.attributes ? { attributes: profile.attributes } : {}),
      },
      onboarding,
      agreements,
    } as unknown as Json;
  const groups: Array<{ id: string; name: string; until?: string }> = [];
  for (const membership of await tx.find<GroupMember>('groupMembers', {
    tenantId,
    identityId: identity.id,
  })) {
    const group = await tx.get<Group>('groups', membership.groupId);
    if (group && group.tenantId === tenantId)
      groups.push({
        id: group.id,
        name: group.name,
        ...(membership.expiresAt !== undefined
          ? { until: new Date(membership.expiresAt).toISOString() }
          : {}),
      });
  }
  const signIns = await tx.get('authSignIns', identity.id);
  const activity = includeActivity
    ? (await tx.find<AuditEvent>('audit', { tenantId, actorId: identity.id }))
        .sort((a, b) => b.timestamp - a.timestamp || (a.id < b.id ? -1 : 1))
        .slice(0, 5000)
        .map((event) => ({
          at: new Date(event.timestamp).toISOString(),
          action: event.action,
          resource: event.resourceId,
          outcome: event.outcome,
        }))
    : undefined;
  return {
    ...base,
    profile,
    groups,
    access: (await ctx.decisions.effectiveBindings(tx, tenantId, identity.id)).map((binding) => ({
      role: binding.role?.name ?? binding.roleId,
      via: binding.via === 'identity' ? 'direct' : 'group',
      ...(binding.expiresAt !== undefined
        ? { until: new Date(binding.expiresAt).toISOString() }
        : {}),
    })),
    sessions: (await tx.find<Session>('sessions', { tenantId, identityId: identity.id })).map(
      (session) => ({
        kind: session.kind,
        createdAt: new Date(session.createdAt).toISOString(),
        lastSeenAt: new Date(session.lastSeenAt).toISOString(),
        expiresAt: new Date(session.expiresAt).toISOString(),
        ...(session.client ? { client: session.client } : {}),
      }),
    ),
    ...(signIns
      ? {
          signIns: {
            ...(typeof signIns.lastAt === 'number'
              ? { lastAt: new Date(signIns.lastAt).toISOString() }
              : {}),
            ...(signIns.lastClient ? { lastClient: signIns.lastClient } : {}),
            failedAttempts: signIns.failedAttempts ?? 0,
          },
        }
      : {}),
    mfa: { enabled: Boolean((await tx.get('authMfa', identity.id))?.enabled) },
    passkeys: (await tx.find('authPasskeys', { tenantId, identityId: identity.id })).map((key) => ({
      ...(key.name ? { name: key.name } : {}),
      ...(typeof key.createdAt === 'number'
        ? { createdAt: new Date(key.createdAt).toISOString() }
        : {}),
      ...(typeof key.lastUsedAt === 'number'
        ? { lastUsedAt: new Date(key.lastUsedAt).toISOString() }
        : {}),
    })),
    linkedSignIns: (await tx.find('externalIdentities', { tenantId, identityId: identity.id })).map(
      (mapping) => ({ issuer: mapping.issuer, subject: mapping.subject }),
    ),
    // The app launcher's history (applications.ts): which apps, how often, first and last time.
    appLaunches: await Promise.all(
      (await tx.find('appLaunches', { tenantId, identityId: identity.id })).map(async (launch) => ({
        app: String((await tx.get('applications', String(launch.appId)))?.name ?? launch.appId),
        count: Number(launch.count),
        firstAt: new Date(Number(launch.firstAt)).toISOString(),
        lastAt: new Date(Number(launch.lastAt)).toISOString(),
      })),
    ),
    agreements,
    onboarding,
    accessRequests: [
      ...(
        await tx.find<AccessRequest>('accessRequests', { tenantId, requesterId: identity.id })
      ).map((item) => ({
        kind: 'access',
        status: item.status,
        ...(typeof item.createdAt === 'number'
          ? { at: new Date(item.createdAt).toISOString() }
          : {}),
      })),
      ...(
        await tx.find<PackageRequest>('packageRequests', { tenantId, identityId: identity.id })
      ).map((item) => ({
        kind: 'package',
        status: item.status,
        ...(typeof item.requestedAt === 'number'
          ? { at: new Date(item.requestedAt).toISOString() }
          : {}),
      })),
    ],
    processing,
    requests,
    ...(activity ? { activity } : { activityOmitted: true }),
  } as unknown as Json;
}

/**
 * Erases what the tenant holds about a subject: the account (through identity deletion, which revokes and removes
 * every credential and grant), then the tombstone's name and remaining details, consent decisions and history,
 * restrictions, exports, sign-in records and queued messages, and the contact details on the subject's requests.
 */
async function eraseSubject(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenant: Tenant,
  request: SubjectRequest,
): Promise<string[]> {
  const tenantId = tenant.id;
  const actions: string[] = [];
  if (request.identityId) {
    const identity = await tx.get<Identity>('identities', request.identityId);
    if (identity && identity.tenantId === tenantId) {
      const address = identity.email ?? identity.deletedEmail;
      if (identity.status !== 'deleted') {
        await deleteIdentity(ctx, tx, principal, identity);
        // Webhooks, outbound SCIM and Shared Signals remove the account downstream on identity:delete; the address
        // stays out of the permanent audit record.
        await ctx.events.audit(
          tx,
          principal,
          'identity:delete',
          tenantId,
          identity.id,
          'allow',
          false,
          { kind: identity.kind, erasure: true },
        );
        actions.push('account-deleted');
      }
      const tombstone = await tx.get<Identity>('identities', identity.id);
      if (tombstone) {
        const {
          deletedEmail: _email,
          attributes: _attributes,
          description: _description,
          phone: _phone,
          ...kept
        } = tombstone;
        await tx.put<Identity>('identities', { ...kept, name: 'Erased person' });
      }
      if (await tx.get('authSignIns', identity.id)) await tx.delete('authSignIns', identity.id);
      for (const row of await tx.find('authDevices', { tenantId, identityId: identity.id }))
        await tx.delete('authDevices', row.id);
      for (const row of await tx.find('onboardingProgress', { tenantId, subjectId: identity.id }))
        await tx.delete('onboardingProgress', row.id);
      if (address)
        for (const row of await tx.find('outbox', { tenantId, to: address }))
          await tx.delete('outbox', row.id);
      actions.push('account-details-erased');
    }
  }
  const subject = request.subject;
  let consents = 0;
  for (const consent of await tx.find<PrivacyConsent>('privacyConsents', { tenantId, subject })) {
    await tx.delete('privacyConsents', consent.id);
    consents++;
  }
  let history = 0;
  for (const event of await tx.find<PrivacyConsentEvent>('privacyConsentEvents', {
    tenantId,
    subject,
  })) {
    if (event.redacted) continue;
    const { evidence: _evidence, ip: _ip, userAgent: _agent, ...kept } = event;
    await tx.put<PrivacyConsentEvent>('privacyConsentEvents', { ...kept, redacted: true });
    history++;
  }
  for (const restriction of await tx.find<PrivacyRestriction>('privacyRestrictions', {
    tenantId,
    subject,
  }))
    await tx.delete('privacyRestrictions', restriction.id);
  // An application subject keeps a suppression marker: the application may ask about the same identifier again, and
  // an opt-out or objection the erased records held must not turn back into "allowed".
  if (request.externalId !== undefined)
    await tx.insert<PrivacyRestriction>('privacyRestrictions', {
      id: id(),
      tenantId,
      subject,
      externalId: request.externalId,
      requestId: request.id,
      erased: true,
      restrictedAt: ctx.now(),
      restrictedBy: principal.identity.id,
    });
  for (const item of await tx.find<PrivacyExport>('privacyExports', { tenantId, subject }))
    await tx.delete('privacyExports', item.id);
  for (const other of await tx.find<SubjectRequest>('privacyRequests', { tenantId, subject }))
    if (other.id !== request.id && !other.redacted) await tx.put('privacyRequests', redact(other));
  if (consents) actions.push(`consents-deleted:${consents}`);
  if (history) actions.push(`history-redacted:${history}`);
  if (!actions.length) actions.push('nothing-held');
  return actions;
}

function redact(request: SubjectRequest): SubjectRequest {
  const {
    requesterEmail: _email,
    requesterName: _name,
    details: _details,
    ...kept
  } = request;
  return {
    ...kept,
    redacted: true,
    events: request.events.map(({ note: _note, ...event }) => event),
  };
}

function regulationOf(value: unknown, settings: PrivacySettings): Regulation {
  return value === undefined ? settings.defaultRegulation : oneOf(value, regulations, 'regulation');
}

function purposeKeysOf(value: unknown): string[] | undefined {
  if (value === undefined) return undefined;
  const keys = [...new Set(strings(value, 'purposeKeys').map((key) => purposeKey(key)))];
  if (keys.length > 50) throw new IamError('INVALID_INPUT', 'At most 50 purposeKeys');
  return keys.length ? keys.sort() : undefined;
}

/** Opens a verified request: the response window starts now. */
function opened(
  request: SubjectRequest,
  settings: PrivacySettings,
  now: number,
  verification: SubjectRequest['verification'],
): SubjectRequest {
  const window = responseWindow(request.regulation, settings);
  const { tokenHash: _hash, tokenExpiresAt: _expires, ...kept } = request;
  return {
    ...kept,
    status: 'open',
    verification,
    receivedAt: now,
    dueAt: now + window.responseDays * dayMs,
  };
}

/**
 * Privacy and consent management: processing purposes with their lawful basis, each person's consent (recorded by
 * the person, by an administrator, or by the application for its own customers), signed consent receipts and an
 * append-only history, data-subject requests (access, portability, erasure, rectification, restriction, objection,
 * opt-out) with statutory deadlines and automated fulfilment, legal holds, and restriction of processing. Policies
 * see `principal.consents`. Managing purposes and settings needs `iam:privacy:manage`; reading consents, requests and
 * reports `iam:privacy:read`; recording consents for application subjects `iam:privacy:record`; checking them
 * `iam:privacy:check`; handling requests `iam:privacy:handle`. People manage their own choices without a permission.
 */
export function createPrivacyApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const auth = ctx.auth;

  /** Runs a self-service call as the signed-in person of `tenantId`. */
  async function asPerson<T>(
    credential: CredentialInput,
    tenantId: string,
    fn: (tx: IamStore, principal: AuthenticatedPrincipal, tenant: Tenant) => Promise<T>,
  ): Promise<T> {
    const authenticated = await ctx.principals.authenticate(credential);
    return ctx.store.transaction(async (tx) => {
      const principal = await ctx.principals.currentPrincipal(tx, authenticated);
      selfSession(principal, tenantId);
      const tenant = await ctx.tenant(tx, tenantId);
      if (tenant.status !== 'active') throw new IamError('TENANT_INACTIVE', 'Tenant inactive', 403);
      return fn(tx, principal, tenant);
    });
  }

  async function subjectNames(
    tx: IamStore,
    requests: SubjectRequest[],
  ): Promise<Map<string, string>> {
    const names = new Map<string, string>();
    for (const request of requests)
      if (request.identityId && !names.has(request.identityId)) {
        const identity = await tx.get<Identity>('identities', request.identityId);
        if (identity) names.set(identity.id, identity.email ?? identity.name);
      }
    return names;
  }

  async function openRequest(
    tx: IamStore,
    tenantId: string,
    requestId: unknown,
  ): Promise<SubjectRequest> {
    const request = await ctx.scoped<SubjectRequest>(
      tx,
      'privacyRequests',
      text(requestId, 'requestId'),
      tenantId,
    );
    return request;
  }

  const api = {
    // ── Purposes ──────────────────────────────────────────────────────────────────────────────────────────────
    /** Adds a processing purpose at version 1. Keys are permanent; names and descriptions can change. */
    createPurpose: async (credential: CredentialInput, input: PurposeInput & { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:privacy:manage', input.tenantId, async ({ tx, tenant }) => {
        const values = purposeFields(input);
        const existing = await tx.find<PrivacyPurpose>('privacyPurposes', { tenantId: tenant.id });
        if (existing.some((purpose) => purpose.uniqueKey === values.uniqueKey))
          throw new IamError('CONFLICT', 'A purpose with this key exists', 409);
        if (existing.length >= maxPurposes)
          throw new IamError('LIMIT_EXCEEDED', `At most ${maxPurposes} purposes`, 409);
        const now = ctx.now();
        return tx.insert<PrivacyPurpose>('privacyPurposes', {
          ...values,
          id: id(),
          tenantId: tenant.id,
          version: 1,
          archived: false,
          createdAt: now,
          updatedAt: now,
        });
      }),
    /**
     * Edits a purpose. `newVersion: true` publishes the change as the next version: opt-in grants given to older
     * versions stop counting (unless `reconsentOnVersion` is false), so people are asked again. `archived: true` stops
     * all processing for it; decisions are kept.
     */
    updatePurpose: async (
      credential: CredentialInput,
      input: Partial<Omit<PurposeInput, 'retentionDays' | 'consentLifetimeDays'>> & {
        tenantId: string;
        purposeId: string;
        newVersion?: boolean;
        archived?: boolean;
        retentionDays?: number | null;
        consentLifetimeDays?: number | null;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:manage',
        text(input.purposeId, 'purposeId'),
        async ({ tx, tenant }) => {
          const previous = await ctx.scoped<PrivacyPurpose>(
            tx,
            'privacyPurposes',
            input.purposeId,
            tenant.id,
          );
          const values = purposeFields(input as Partial<PurposeInput>, previous);
          // A new basis or mode changes who may be processed (opt-in to opt-out makes everyone never asked
          // processable), so it is published as a new version people can see.
          if (
            (values.legalBasis !== previous.legalBasis || values.mode !== previous.mode) &&
            input.newVersion !== true
          )
            throw new IamError(
              'INVALID_INPUT',
              'Changing the legal basis or consent mode is a material change: publish it with newVersion',
            );
          if (input.archived !== undefined && typeof input.archived !== 'boolean')
            throw new IamError('INVALID_INPUT', 'archived must be a boolean');
          const {
            retentionDays: _retention,
            consentLifetimeDays: _lifetime,
            ...kept
          } = previous;
          return tx.put<PrivacyPurpose>('privacyPurposes', {
            ...kept,
            ...values,
            version: previous.version + (input.newVersion === true ? 1 : 0),
            archived: input.archived ?? previous.archived,
            updatedAt: ctx.now(),
          });
        },
      ),
    /** Deletes a purpose nobody has decided on yet; purposes with recorded decisions are archived instead. */
    deletePurpose: async (credential: CredentialInput, input: { tenantId: string; purposeId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:manage',
        text(input.purposeId, 'purposeId'),
        async ({ tx, tenant }) => {
          const purpose = await ctx.scoped<PrivacyPurpose>(
            tx,
            'privacyPurposes',
            input.purposeId,
            tenant.id,
          );
          if (
            (await tx.find('privacyConsentEvents', { tenantId: tenant.id, purposeId: purpose.id }))
              .length
          )
            throw new IamError(
              'RESOURCE_IN_USE',
              'Decisions are recorded for this purpose; archive it instead so the proof is kept',
              409,
            );
          await tx.delete('privacyPurposes', purpose.id);
          return { deleted: true };
        },
      ),
    listPurposes: async (
      credential: CredentialInput,
      input: { tenantId: string; includeArchived?: boolean },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) =>
        (await tx.find<PrivacyPurpose>('privacyPurposes', { tenantId: tenant.id }))
          .filter((purpose) => input.includeArchived === true || !purpose.archived)
          .sort((a, b) => a.name.localeCompare(b.name)),
      ),

    // ── The person's own choices ──────────────────────────────────────────────────────────────────────────────
    /**
     * The caller's privacy page: every purpose with their decision and its effect, whether processing is restricted,
     * their data-subject requests, and the privacy contact. Needs only a signed-in session of the organization.
     */
    mine: async (credential: CredentialInput, input: { tenantId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      return asPerson(credential, tenantId, async (tx, principal) => {
        const now = ctx.now();
        const subject = identitySubject(principal.identity.id);
        const consents = await consentsOf(tx, tenantId, subject);
        const restricted = Boolean(await restrictionOf(tx, tenantId, subject));
        const settings = await privacySettings(tx, tenantId);
        const purposes: MyPurpose[] = (
          await tx.find<PrivacyPurpose>('privacyPurposes', { tenantId })
        )
          .filter((purpose) => !purpose.archived)
          .sort(
            (a, b) =>
              Number(decidable(b)) - Number(decidable(a)) || a.name.localeCompare(b.name),
          )
          .map((purpose) => {
            const consent = consents.get(purpose.id);
            return {
              id: purpose.id,
              key: purpose.key,
              name: purpose.name,
              description: purpose.description,
              legalBasis: purpose.legalBasis,
              mode: purpose.mode,
              version: purpose.version,
              dataCategories: purpose.dataCategories,
              ...(purpose.retentionDays !== undefined
                ? { retentionDays: purpose.retentionDays }
                : {}),
              decidable: decidable(purpose),
              state: consentState(purpose, consent, restricted, now),
              ...(consent
                ? {
                    consent: {
                      granted: consent.granted,
                      purposeVersion: consent.purposeVersion,
                      recordedAt: consent.recordedAt,
                      ...(consent.expiresAt !== undefined ? { expiresAt: consent.expiresAt } : {}),
                      receiptId: consent.receiptId,
                    },
                  }
                : {}),
            };
          });
        const requests = (await tx.find<SubjectRequest>('privacyRequests', { tenantId, subject }))
          .sort((a, b) => b.submittedAt - a.submittedAt)
          .map((request) => mineView(request, now));
        return {
          purposes,
          restricted,
          requests,
          ...(settings.contactEmail
            ? {
                contact: {
                  email: settings.contactEmail,
                  ...(settings.contactName ? { name: settings.contactName } : {}),
                },
              }
            : {}),
        };
      });
    },
    /**
     * Records the caller's decision on a purpose: `granted: true` consents (or withdraws an objection), `false`
     * withdraws consent, opts out, or objects to a legitimate-interest purpose. `version` must be the purpose's current
     * version, so nobody agrees to text they were not shown. Returns a signed receipt; audited as `privacy:consent`.
     */
    decide: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        purposeKey: string;
        version: number;
        granted: boolean;
        method?: string;
        evidence?: string;
      },
    ) => {
      const tenantId = text(input.tenantId, 'tenantId');
      if (typeof input.granted !== 'boolean')
        throw new IamError('INVALID_INPUT', 'granted must be a boolean');
      const version = integer(input.version, 'version', 1, 1_000_000);
      return asPerson(credential, tenantId, async (tx, principal) => {
        const purpose = await purposeByKey(tx, tenantId, input.purposeKey);
        if (purpose.version !== version)
          throw new IamError(
            'VERSION_CONFLICT',
            'The purpose changed; review the current version before deciding',
            409,
          );
        const subject = await resolveSubject(tx, tenantId, { identityId: principal.identity.id });
        const { receipt } = await writeConsent(ctx, tx, {
          tenantId,
          purpose,
          subject,
          granted: input.granted,
          source: 'self',
          method: method(input.method) ?? 'self-service',
          evidence: evidence(input.evidence),
          recordedBy: principal.identity.id,
          at: ctx.now(),
          client: auth.currentClient(),
        });
        await ctx.events.audit(
          tx,
          principal,
          'privacy:consent',
          tenantId,
          principal.identity.id,
          'allow',
          false,
          {
            purposeKey: purpose.key,
            granted: input.granted,
            purposeVersion: version,
            source: 'self',
            receiptId: receipt.receiptId,
          },
        );
        return receipt;
      });
    },
    /** The caller's decision history (newest first, at most 500 entries). */
    myHistory: async (credential: CredentialInput, input: { tenantId: string; purposeKey?: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      return asPerson(credential, tenantId, async (tx, principal) => {
        const key = input.purposeKey === undefined ? undefined : purposeKey(input.purposeKey);
        return (
          await tx.find<PrivacyConsentEvent>('privacyConsentEvents', {
            tenantId,
            subject: identitySubject(principal.identity.id),
          })
        )
          .filter((event) => key === undefined || event.purposeKey === key)
          .sort((a, b) => b.recordedAt - a.recordedAt || (a.id < b.id ? -1 : 1))
          .slice(0, 500)
          .map(historyEntry);
      });
    },
    /** A signed receipt for one of the caller's own decisions. */
    myReceipt: async (credential: CredentialInput, input: { tenantId: string; receiptId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      return asPerson(credential, tenantId, async (tx, principal) => {
        const event = await tx.get<PrivacyConsentEvent>(
          'privacyConsentEvents',
          text(input.receiptId, 'receiptId'),
        );
        if (
          !event ||
          event.tenantId !== tenantId ||
          event.subject !== identitySubject(principal.identity.id)
        )
          throw new IamError('NOT_FOUND', 'Receipt not found', 404);
        return receiptFromEvent(ctx.options.secret, event);
      });
    },
    /**
     * Files a data-subject request for the caller. Signing in verified who they are, so the response window starts
     * at once; the privacy contact is emailed. One open request per type at a time. Audited as `privacy:request:submit`.
     */
    submitRequest: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type: SubjectRequestType;
        regulation?: Regulation;
        details?: string;
        purposeKeys?: string[];
      },
    ) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const type = oneOf(input.type, subjectRequestTypes, 'type');
      const details = input.details === undefined ? undefined : prose(input.details, 'details', 5000);
      const purposeKeys = purposeKeysOf(input.purposeKeys);
      return asPerson(credential, tenantId, async (tx, principal, tenant) => {
        const subject = identitySubject(principal.identity.id);
        const settings = await privacySettings(tx, tenantId);
        const regulation = regulationOf(input.regulation, settings);
        if (
          (await tx.find<SubjectRequest>('privacyRequests', { tenantId, subject })).some(
            (request) =>
              request.type === type &&
              (request.status === 'open' || request.status === 'pending-verification'),
          )
        )
          throw new IamError('CONFLICT', 'You already have an open request of this type', 409);
        if (purposeKeys) for (const key of purposeKeys) await purposeByKey(tx, tenantId, key);
        const now = ctx.now();
        const number = requestNumber();
        const request = opened(
          {
            id: id(),
            tenantId,
            uniqueKey: `number:${number}`,
            number,
            type,
            regulation,
            status: 'pending-verification',
            subject,
            identityId: principal.identity.id,
            ...(details ? { details } : {}),
            ...(purposeKeys ? { purposeKeys } : {}),
            channel: 'self-service',
            verification: { status: 'pending' },
            submittedAt: now,
            events: [{ at: now, by: principal.identity.id, what: 'submitted' }],
          },
          settings,
          now,
          { status: 'verified', method: 'authenticated-session', verifiedAt: now },
        );
        await tx.insert('privacyRequests', request);
        await notifyContact(ctx, tx, tenant, request);
        await ctx.events.audit(tx, principal, 'privacy:request:submit', tenantId, request.id, 'allow', false, {
          number,
          type,
          regulation,
          channel: 'self-service',
        });
        return mineView(request, now);
      });
    },
    /** Withdraws one of the caller's own requests while it is still being handled. */
    cancelMyRequest: async (credential: CredentialInput, input: { tenantId: string; requestId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      return asPerson(credential, tenantId, async (tx, principal) => {
        const request = await openRequest(tx, tenantId, input.requestId);
        if (request.subject !== identitySubject(principal.identity.id))
          throw new IamError('NOT_FOUND', 'Resource not found', 404);
        if (request.status !== 'open' && request.status !== 'pending-verification')
          throw new IamError('INVALID_TRANSITION', 'This request is already closed', 409);
        const now = ctx.now();
        const cancelled: SubjectRequest = {
          ...request,
          status: 'cancelled',
          closedAt: now,
          closedBy: principal.identity.id,
          events: pushEvent(request, { at: now, by: principal.identity.id, what: 'cancelled' }),
        };
        await tx.put('privacyRequests', cancelled);
        await ctx.events.audit(tx, principal, 'privacy:request:cancel', tenantId, request.id, 'allow', false, {
          number: request.number,
          type: request.type,
        });
        return mineView(cancelled, now);
      });
    },
    /**
     * Downloads the export an access or portability request produced: by the person it is about, or by a request
     * handler (`iam:privacy:handle`, recently signed in) who must deliver it another way. Audited as
     * `privacy:export:download`.
     */
    downloadExport: async (credential: CredentialInput, input: { tenantId: string; requestId: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const requestId = text(input.requestId, 'requestId');
      const authenticated = await ctx.principals.authenticate(credential);
      // A refusal is returned rather than thrown, so the transaction commits its deny audit record.
      const outcome = await ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const request = await tx.get<SubjectRequest>('privacyRequests', requestId);
        if (!request || request.tenantId !== tenantId || !request.exportId)
          throw new IamError('NOT_FOUND', 'Export not found', 404);
        const own =
          actsInOwnRight(principal.session) &&
          principal.session.kind === 'user' &&
          !principal.session.impersonatorId &&
          principal.session.tenantId === tenantId &&
          request.subject === identitySubject(principal.identity.id);
        if (!own) {
          const checks = [
            { action: 'iam:privacy:handle', id: request.id },
            // A handler reads everything about the person, as identities.export would let them.
            ...(request.identityId ? [{ action: 'iam:identities:read', id: request.identityId }] : []),
          ];
          for (const check of checks)
            if (
              !(
                await ctx.operations.recordedDecision(tx, principal, {
                  tenantId,
                  action: check.action,
                  resource: { type: 'iam', id: check.id },
                })
              ).allowed
            )
              return { denied: true as const };
          auth.requireRecent(principal);
        }
        const item = await tx.get<PrivacyExport>('privacyExports', request.exportId);
        if (!item || item.expiresAt <= ctx.now())
          throw new IamError('NOT_FOUND', 'The export has expired; file a new request', 404);
        await tx.put<PrivacyExport>('privacyExports', { ...item, downloads: item.downloads + 1 });
        await ctx.events.audit(tx, principal, 'privacy:export:download', tenantId, request.id, 'allow', false, {
          number: request.number,
          by: own ? 'subject' : 'handler',
        });
        return {
          denied: false as const,
          result: {
            number: request.number,
            createdAt: item.createdAt,
            expiresAt: item.expiresAt,
            sha256: item.sha256,
            data: item.data,
          },
        };
      });
      if (outcome.denied) throw new IamError('ACCESS_DENIED', 'Access denied', 403);
      return outcome.result;
    },

    // ── Consent records kept by the application ───────────────────────────────────────────────────────────────
    /**
     * Records a decision for a subject: a person here (`{ identityId }`) or one the application names
     * (`{ externalId }`, such as a customer number or a visitor ID). `source` is `api` (default), `admin` or `import`;
     * imports may carry an earlier `recordedAt` and `version`, and never overwrite a newer decision. Returns the receipt.
     */
    record: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        subject: SubjectInput;
        purposeKey: string;
        granted: boolean;
        version?: number;
        source?: 'api' | 'admin' | 'import';
        method?: string;
        evidence?: string;
        recordedAt?: number;
        ip?: string;
        userAgent?: string;
      },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:record', input.tenantId, async ({ tx, tenant, principal }) => {
        if (typeof input.granted !== 'boolean')
          throw new IamError('INVALID_INPUT', 'granted must be a boolean');
        const source = oneOf(input.source ?? 'api', ['api', 'admin', 'import'] as const, 'source');
        const now = ctx.now();
        const at =
          input.recordedAt === undefined
            ? now
            : integer(input.recordedAt, 'recordedAt', 0, now);
        if (at !== now && source !== 'import')
          throw new IamError('INVALID_INPUT', 'recordedAt is accepted for imports only');
        // An imported grant counts for the version the person saw, never silently for today's text.
        if (source === 'import' && input.version === undefined)
          throw new IamError('INVALID_INPUT', 'Imports must state the purpose version decided on');
        const purpose = await purposeByKey(tx, tenant.id, input.purposeKey);
        const subject = await resolveSubject(tx, tenant.id, input.subject);
        const client =
          input.ip !== undefined || input.userAgent !== undefined
            ? {
                ...(input.ip !== undefined ? { ip: text(input.ip, 'ip', 64) } : {}),
                ...(input.userAgent !== undefined
                  ? { userAgent: text(input.userAgent, 'userAgent', 512) }
                  : {}),
              }
            : undefined;
        const { receipt, current } = await writeConsent(ctx, tx, {
          tenantId: tenant.id,
          purpose,
          subject,
          granted: input.granted,
          source,
          method: method(input.method),
          evidence: evidence(input.evidence),
          recordedBy: principal.identity.id,
          at,
          ...(input.version !== undefined ? { version: input.version } : {}),
          ...(client ? { client } : {}),
        });
        await ctx.events.audit(
          tx,
          principal,
          'privacy:consent',
          tenant.id,
          subject.identityId ?? subject.key,
          'allow',
          false,
          {
            purposeKey: purpose.key,
            granted: input.granted,
            purposeVersion: receipt.purpose.version,
            source,
            receiptId: receipt.receiptId,
            ...(subject.externalId !== undefined ? { externalId: subject.externalId } : {}),
          },
        );
        return { ...receipt, current };
      }),
    /**
     * Imports up to 500 decisions in one transaction (all or nothing), for moving consent records from another
     * system. Entries follow `record` with `source: 'import'`; one `privacy:consent-import` audit event summarizes them.
     */
    importDecisions: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        decisions: Array<{
          subject: SubjectInput;
          purposeKey: string;
          granted: boolean;
          method?: string;
          evidence?: string;
          recordedAt: number;
          /** The purpose version the person decided on (required: imports never count for newer text). */
          version: number;
        }>;
      },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:record', input.tenantId, async ({ tx, tenant, principal }) => {
        if (!Array.isArray(input.decisions) || !input.decisions.length || input.decisions.length > 500)
          throw new IamError('INVALID_INPUT', 'Provide 1-500 decisions');
        const now = ctx.now();
        const purposes = new Map<string, PrivacyPurpose>();
        let current = 0;
        for (const raw of input.decisions) {
          const entry = object(raw);
          if (typeof entry.granted !== 'boolean')
            throw new IamError('INVALID_INPUT', 'granted must be a boolean');
          if (entry.version === undefined)
            throw new IamError('INVALID_INPUT', 'Each imported decision must state its purpose version');
          const key = purposeKey(entry.purposeKey);
          const purpose = purposes.get(key) ?? (await purposeByKey(tx, tenant.id, key));
          purposes.set(key, purpose);
          const written = await writeConsent(ctx, tx, {
            tenantId: tenant.id,
            purpose,
            subject: await resolveSubject(tx, tenant.id, entry.subject),
            granted: entry.granted,
            source: 'import',
            method: method(entry.method),
            evidence: evidence(entry.evidence),
            recordedBy: principal.identity.id,
            at: integer(entry.recordedAt, 'recordedAt', 0, now),
            version: entry.version as number,
          });
          if (written.current) current++;
        }
        await ctx.events.audit(tx, principal, 'privacy:consent-import', tenant.id, tenant.id, 'allow', false, {
          count: input.decisions.length,
          current,
          purposes: [...purposes.keys()].sort(),
        });
        return { imported: input.decisions.length, current };
      }),
    /**
     * Whether a purpose may be processed for a subject right now, and why (`CONSENT_GIVEN`, `NO_CONSENT`,
     * `CONSENT_WITHDRAWN`, `CONSENT_EXPIRED`, `CONSENT_OUTDATED`, `OBJECTED`, `RESTRICTED`, `LEGAL_BASIS`, ...).
     * Server code can call `iam.privacy.check` without a credential.
     */
    check: async (
      credential: CredentialInput,
      input: { tenantId: string; subject: SubjectInput; purposeKey: string },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:check', input.tenantId, async ({ tx, tenant }) =>
        checkSubject(ctx, tx, tenant.id, input.subject, input.purposeKey),
      ),
    /**
     * Splits up to 1 000 subjects into those a purpose may be processed for and those it may not (with the reason),
     * for batch jobs such as a marketing send.
     */
    filterSubjects: async (
      credential: CredentialInput,
      input: { tenantId: string; purposeKey: string; subjects: SubjectInput[] },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:check', input.tenantId, async ({ tx, tenant }) => {
        if (!Array.isArray(input.subjects) || input.subjects.length > 1000)
          throw new IamError('INVALID_INPUT', 'Provide at most 1000 subjects');
        const purpose = await purposeByKey(tx, tenant.id, input.purposeKey);
        const now = ctx.now();
        const allowed: SubjectInput[] = [];
        const refused: Array<{ subject: SubjectInput; reason: string }> = [];
        for (const raw of input.subjects) {
          let resolved: ResolvedSubject;
          try {
            resolved = await resolveSubject(tx, tenant.id, raw);
          } catch (error) {
            if (error instanceof IamError && error.code === 'NOT_FOUND') {
              refused.push({ subject: raw, reason: 'UNKNOWN_SUBJECT' });
              continue;
            }
            throw error;
          }
          const consent = (
            await tx.find<PrivacyConsent>('privacyConsents', {
              tenantId: tenant.id,
              uniqueKey: `${purpose.id}:${resolved.key}`,
            })
          )[0];
          const restricted = restrictionState(await restrictionOf(tx, tenant.id, resolved.key));
          const state = consentState(purpose, consent, restricted, now);
          if (state.allowed) allowed.push(raw);
          else refused.push({ subject: raw, reason: state.reason });
        }
        return { purposeKey: purpose.key, allowed, refused };
      }),
    /**
     * The subjects a purpose may currently be processed for: people of the tenant (every active person for opt-out
     * and legitimate-interest purposes, those who consented for opt-in ones) and application subjects with a
     * recorded decision. Paged by `offset` (at most 1 000 per page). People's emails and names are included only when
     * the caller may also read identities (`iam:identities:read`); otherwise they are listed by ID.
     */
    audience: async (
      credential: CredentialInput,
      input: { tenantId: string; purposeKey: string; limit?: number; offset?: number },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant, principal }) => {
        const directory = (
          await ctx.decisions.decide(
            tx,
            principal,
            {
              tenantId: tenant.id,
              action: 'iam:identities:read',
              resource: { type: 'iam', id: tenant.id },
            },
            true,
          )
        ).allowed;
        const limit = integer(input.limit ?? 1000, 'limit', 1, 1000);
        const offset = integer(input.offset ?? 0, 'offset', 0, 10_000_000);
        const purpose = await purposeByKey(tx, tenant.id, input.purposeKey);
        const now = ctx.now();
        const consents = new Map(
          (
            await tx.find<PrivacyConsent>('privacyConsents', {
              tenantId: tenant.id,
              purposeId: purpose.id,
            })
          ).map((consent) => [consent.subject, consent]),
        );
        const restricted = new Set(
          (await tx.find<PrivacyRestriction>('privacyRestrictions', { tenantId: tenant.id })).map(
            (restriction) => restriction.subject,
          ),
        );
        const members: Array<{
          subject: string;
          identityId?: string;
          externalId?: string;
          email?: string;
          name?: string;
        }> = [];
        const people = (await tx.find<Identity>('identities', { tenantId: tenant.id }))
          .filter((identity) => identity.kind === 'user' && identity.status === 'active')
          .sort((a, b) => (a.id < b.id ? -1 : 1));
        for (const person of people) {
          const key = identitySubject(person.id);
          if (consentState(purpose, consents.get(key), restricted.has(key), now).allowed)
            members.push({
              subject: key,
              identityId: person.id,
              ...(directory && person.email ? { email: person.email } : {}),
              ...(directory ? { name: person.name } : {}),
            });
        }
        for (const consent of [...consents.values()].sort((a, b) => (a.subject < b.subject ? -1 : 1)))
          if (
            consent.externalId !== undefined &&
            consentState(purpose, consent, restricted.has(consent.subject), now).allowed
          )
            members.push({ subject: consent.subject, externalId: consent.externalId });
        return {
          purposeKey: purpose.key,
          total: members.length,
          subjects: members.slice(offset, offset + limit),
        };
      }),
    /** Current decisions, filtered by purpose, subject or outcome; newest first. */
    listConsents: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        purposeKey?: string;
        subject?: SubjectInput;
        granted?: boolean;
        limit?: number;
        offset?: number;
      },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) => {
        const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
        const offset = integer(input.offset ?? 0, 'offset', 0, 10_000_000);
        const purposes = new Map(
          (await tx.find<PrivacyPurpose>('privacyPurposes', { tenantId: tenant.id })).map(
            (purpose) => [purpose.id, purpose],
          ),
        );
        const filter: Record<string, unknown> = { tenantId: tenant.id };
        if (input.purposeKey !== undefined)
          filter.purposeId = (await purposeByKey(tx, tenant.id, input.purposeKey)).id;
        if (input.subject !== undefined)
          filter.subject = (await resolveSubject(tx, tenant.id, input.subject, true)).key;
        if (input.granted !== undefined) {
          if (typeof input.granted !== 'boolean')
            throw new IamError('INVALID_INPUT', 'granted must be a boolean');
          filter.granted = input.granted;
        }
        const restricted = new Set(
          (await tx.find<PrivacyRestriction>('privacyRestrictions', { tenantId: tenant.id })).map(
            (restriction) => restriction.subject,
          ),
        );
        const now = ctx.now();
        const rows = (await tx.find<PrivacyConsent>('privacyConsents', filter)).sort(
          (a, b) => b.recordedAt - a.recordedAt || (a.id < b.id ? -1 : 1),
        );
        return {
          total: rows.length,
          consents: rows.slice(offset, offset + limit).flatMap((consent) => {
            const purpose = purposes.get(consent.purposeId);
            return purpose
              ? [consentView(consent, purpose, restricted.has(consent.subject), now)]
              : [];
          }),
        };
      }),
    /** A subject's decision history (newest first, at most 1 000 entries). */
    history: async (
      credential: CredentialInput,
      input: { tenantId: string; subject: SubjectInput; purposeKey?: string },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) => {
        const subject = await resolveSubject(tx, tenant.id, input.subject, true);
        const key = input.purposeKey === undefined ? undefined : purposeKey(input.purposeKey);
        return (
          await tx.find<PrivacyConsentEvent>('privacyConsentEvents', {
            tenantId: tenant.id,
            subject: subject.key,
          })
        )
          .filter((event) => key === undefined || event.purposeKey === key)
          .sort((a, b) => b.recordedAt - a.recordedAt || (a.id < b.id ? -1 : 1))
          .slice(0, 1000)
          .map(historyEntry);
      }),
    /**
     * Checks a consent receipt someone presents: the signature (current or previous deployment secret), that the
     * decision is in the history with the same content, and whether it is still the subject's current decision.
     */
    verifyReceipt: async (
      credential: CredentialInput,
      input: { tenantId: string; receipt: ConsentReceipt },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) => {
        const receipt = object(input.receipt) as unknown as ConsentReceipt;
        const secrets = [ctx.options.secret, ...(ctx.options.previousSecrets ?? [])];
        if (receipt.tenantId !== tenant.id || !receiptSignatureValid(secrets, receipt))
          return { valid: false as const, reason: 'SIGNATURE_INVALID' as const };
        const event =
          typeof receipt.receiptId === 'string'
            ? await tx.get<PrivacyConsentEvent>('privacyConsentEvents', receipt.receiptId)
            : undefined;
        if (!event || event.tenantId !== tenant.id)
          return { valid: false as const, reason: 'NOT_RECORDED' as const };
        // Rebuilt with the secret the receipt verified under, so receipts from before a rotation still match.
        const rebuilt = secrets
          .map((secret) => receiptFromEvent(secret, event))
          .find((candidate) => candidate.signature === receipt.signature);
        if (!rebuilt || canonicalJson(rebuilt) !== canonicalJson(receipt))
          return { valid: false as const, reason: 'CONTENT_MISMATCH' as const };
        const current = (
          await tx.find<PrivacyConsent>('privacyConsents', {
            tenantId: tenant.id,
            uniqueKey: `${event.purposeId}:${event.subject}`,
          })
        )[0];
        return {
          valid: true as const,
          current: current?.receiptId === event.receiptId,
          ...(event.redacted ? { redacted: true } : {}),
        };
      }),

    // ── Data-subject requests ─────────────────────────────────────────────────────────────────────────────────
    /**
     * Files a request on a subject's behalf (received by phone, mail or a support ticket). With `verified` (how the
     * handler confirmed who is asking) it opens at once; otherwise it waits for `verifyRequest`.
     */
    createRequest: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type: SubjectRequestType;
        subject?: SubjectInput;
        requesterEmail?: string;
        requesterName?: string;
        regulation?: Regulation;
        details?: string;
        purposeKeys?: string[];
        verified?: { method: string; note?: string };
      },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:handle', input.tenantId, async ({ tx, tenant, principal }) => {
        const type = oneOf(input.type, subjectRequestTypes, 'type');
        const settings = await privacySettings(tx, tenant.id);
        const regulation = regulationOf(input.regulation, settings);
        const requesterEmail =
          input.requesterEmail === undefined ? undefined : email(input.requesterEmail);
        const requesterName =
          input.requesterName === undefined ? undefined : text(input.requesterName, 'requesterName', 200);
        const subject =
          input.subject !== undefined
            ? await resolveSubject(tx, tenant.id, input.subject)
            : requesterEmail
              ? { key: emailSubject(ctx.options.secret, requesterEmail) }
              : undefined;
        if (!subject)
          throw new IamError('INVALID_INPUT', 'Name the subject or the requester’s email');
        const purposeKeys = purposeKeysOf(input.purposeKeys);
        if (purposeKeys) for (const key of purposeKeys) await purposeByKey(tx, tenant.id, key);
        const now = ctx.now();
        const number = requestNumber();
        let request: SubjectRequest = {
          id: id(),
          tenantId: tenant.id,
          uniqueKey: `number:${number}`,
          number,
          type,
          regulation,
          status: 'pending-verification',
          subject: subject.key,
          ...('identityId' in subject && subject.identityId ? { identityId: subject.identityId } : {}),
          ...('externalId' in subject && subject.externalId !== undefined
            ? { externalId: subject.externalId }
            : {}),
          ...(requesterEmail ? { requesterEmail } : {}),
          ...(requesterName ? { requesterName } : {}),
          ...(input.details !== undefined ? { details: prose(input.details, 'details', 5000) } : {}),
          ...(purposeKeys ? { purposeKeys } : {}),
          channel: 'staff',
          verification: { status: 'pending' },
          submittedAt: now,
          events: [{ at: now, by: principal.identity.id, what: 'submitted' }],
        };
        if (input.verified !== undefined) {
          const verified = object(input.verified);
          const how = text(verified.method, 'verified.method', 120);
          request = opened(request, settings, now, {
            status: 'verified',
            method: how,
            verifiedAt: now,
            verifiedBy: principal.identity.id,
          });
          request.events = pushEvent(request, {
            at: now,
            by: principal.identity.id,
            what: 'verified',
            ...(verified.note !== undefined ? { note: prose(verified.note, 'verified.note', 2000) } : {}),
          });
        }
        await tx.insert('privacyRequests', request);
        if (request.status === 'open') await notifyContact(ctx, tx, tenant, request);
        await ctx.events.audit(tx, principal, 'privacy:request:submit', tenant.id, request.id, 'allow', false, {
          number,
          type,
          regulation,
          channel: 'staff',
        });
        return requestView(request, now);
      }),
    /** Records how the requester's identity was confirmed, which starts the response window. */
    verifyRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; method: string; note?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:handle',
        text(input.requestId, 'requestId'),
        async ({ tx, tenant, principal }) => {
          const request = await openRequest(tx, tenant.id, input.requestId);
          if (request.status !== 'pending-verification')
            throw new IamError('INVALID_TRANSITION', 'Only unverified requests can be verified', 409);
          const now = ctx.now();
          const settings = await privacySettings(tx, tenant.id);
          const verified = opened(request, settings, now, {
            status: 'verified',
            method: text(input.method, 'method', 120),
            verifiedAt: now,
            verifiedBy: principal.identity.id,
          });
          verified.events = pushEvent(request, {
            at: now,
            by: principal.identity.id,
            what: 'verified',
            ...(input.note !== undefined ? { note: prose(input.note, 'note', 2000) } : {}),
          });
          await tx.put('privacyRequests', verified);
          await notifyContact(ctx, tx, tenant, verified);
          await ctx.events.audit(tx, principal, 'privacy:request:verify', tenant.id, request.id, 'allow', false, {
            number: request.number,
            method: verified.verification.method ?? '',
          });
          return requestView(verified, now);
        },
      ),
    /**
     * Links a request filed by email (someone the intake could not match to an account) to the account or application
     * subject it is about, once the handler has established that. Linking to an account also needs
     * `iam:identities:read` on it. Audited as `privacy:request:link`.
     */
    linkRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; subject: SubjectInput; note?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:handle',
        text(input.requestId, 'requestId'),
        async ({ tx, tenant, principal }) => {
          const request = await openRequest(tx, tenant.id, input.requestId);
          if (request.status !== 'open' && request.status !== 'pending-verification')
            throw new IamError('INVALID_TRANSITION', 'This request is closed', 409);
          if (!request.subject.startsWith('email:'))
            throw new IamError('CONFLICT', 'This request is already linked to its subject', 409);
          const subject = await resolveSubject(tx, tenant.id, input.subject);
          if (
            subject.identityId &&
            !(
              await ctx.decisions.decide(
                tx,
                principal,
                {
                  tenantId: tenant.id,
                  action: 'iam:identities:read',
                  resource: { type: 'iam', id: subject.identityId },
                },
                true,
              )
            ).allowed
          )
            throw new OperationDenied('Linking a request to an account also needs iam:identities:read');
          const now = ctx.now();
          const note = input.note === undefined ? undefined : prose(input.note, 'note', 2000);
          const linked: SubjectRequest = {
            ...request,
            subject: subject.key,
            ...(subject.identityId ? { identityId: subject.identityId } : {}),
            ...(subject.externalId !== undefined ? { externalId: subject.externalId } : {}),
            events: pushEvent(request, {
              at: now,
              by: principal.identity.id,
              what: 'linked',
              ...(note ? { note } : {}),
            }),
          };
          await tx.put('privacyRequests', linked);
          await ctx.events.audit(tx, principal, 'privacy:request:link', tenant.id, request.id, 'allow', false, {
            number: request.number,
            subjectKind: subject.identityId ? 'account' : 'external',
          });
          return requestView(linked, now);
        },
      ),
    /** Hands a request to a handler (a person of the tenant), or clears the assignment with `null`. */
    assignRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; assigneeId: string | null },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:handle',
        text(input.requestId, 'requestId'),
        async ({ tx, tenant, principal }) => {
          const request = await openRequest(tx, tenant.id, input.requestId);
          if (request.status !== 'open' && request.status !== 'pending-verification')
            throw new IamError('INVALID_TRANSITION', 'This request is closed', 409);
          const now = ctx.now();
          let assignee: Identity | undefined;
          if (input.assigneeId !== null) {
            assignee = await ctx.activeIdentity(tx, text(input.assigneeId, 'assigneeId'), tenant.id);
            if (assignee.kind !== 'user' || assignee.status !== 'active')
              throw new IamError('INVALID_INPUT', 'Assign requests to an active person');
          }
          const { assigneeId: _previous, ...rest } = request;
          const updated: SubjectRequest = {
            ...rest,
            ...(assignee ? { assigneeId: assignee.id } : {}),
            events: pushEvent(request, {
              at: now,
              by: principal.identity.id,
              what: 'assigned',
              note: assignee ? (assignee.email ?? assignee.name) : 'unassigned',
            }),
          };
          await tx.put('privacyRequests', updated);
          return requestView(updated, now);
        },
      ),
    /**
     * Extends the response window once by the regulation's extension (GDPR two months, CCPA 45 days; LGPD allows
     * none), telling the subject why. Audited as `privacy:request:extend`.
     */
    extendRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; reason: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:handle',
        text(input.requestId, 'requestId'),
        async ({ tx, tenant, principal }) => {
          const request = await openRequest(tx, tenant.id, input.requestId);
          if (request.status !== 'open' || request.dueAt === undefined)
            throw new IamError('INVALID_TRANSITION', 'Only open requests can be extended', 409);
          if (request.extendedAt !== undefined)
            throw new IamError('CONFLICT', 'This request was already extended', 409);
          const extension = regulationDeadlines[request.regulation].extensionDays;
          if (!extension)
            throw new IamError('CONFLICT', `${request.regulation} allows no extension`, 409);
          const reason = prose(input.reason, 'reason', 2000);
          const now = ctx.now();
          const extended: SubjectRequest = {
            ...request,
            dueAt: request.dueAt + extension * dayMs,
            extendedAt: now,
            extensionReason: reason,
            reminded: [],
            events: pushEvent(request, { at: now, by: principal.identity.id, what: 'extended', note: reason }),
          };
          await tx.put('privacyRequests', extended);
          await notifySubject(ctx, tx, tenant, extended, 'extended');
          await ctx.events.audit(tx, principal, 'privacy:request:extend', tenant.id, request.id, 'allow', false, {
            number: request.number,
            dueAt: extended.dueAt!,
          });
          return requestView(extended, now);
        },
      ),
    /** Adds an internal note to a request's timeline (not shown to the subject). */
    addNote: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; note: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:handle',
        text(input.requestId, 'requestId'),
        async ({ tx, tenant, principal }) => {
          const request = await openRequest(tx, tenant.id, input.requestId);
          if (request.redacted) throw new IamError('CONFLICT', 'This request was redacted', 409);
          const now = ctx.now();
          const updated: SubjectRequest = {
            ...request,
            events: pushEvent(request, {
              at: now,
              by: principal.identity.id,
              what: 'note',
              note: prose(input.note, 'note', 2000),
            }),
          };
          await tx.put('privacyRequests', updated);
          return requestView(updated, now);
        },
      ),
    /**
     * Fulfils an open request. Access and portability build the export (portability: only what the person provided);
     * erasure deletes the account (which also needs `iam:identities:delete` on it) and erases privacy records, refused
     * under a legal hold (`LEGAL_HOLD`); restriction restricts processing; objection and opt-out withdraw the named
     * purposes (or every purpose the person has a say in, opt-out: every opt-out purpose); rectification is done by
     * hand and needs a `note`. The subject is emailed; audited as `privacy:request:complete` (and `privacy:erasure`).
     */
    fulfilRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; note?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:handle',
        text(input.requestId, 'requestId'),
        async ({ tx, tenant, principal }) => {
          const request = await openRequest(tx, tenant.id, input.requestId);
          if (request.status !== 'open')
            throw new IamError(
              'INVALID_TRANSITION',
              request.status === 'pending-verification'
                ? 'Verify who is asking before fulfilling the request'
                : 'This request is closed',
              409,
            );
          const note = input.note === undefined ? undefined : prose(input.note, 'note', 2000);
          const now = ctx.now();
          const settings = await privacySettings(tx, tenant.id);
          const actions: string[] = [];
          let exportId: string | undefined;
          let notifyTo: string | undefined;
          const identityAllowed = async (action: string) =>
            !request.identityId ||
            (
              await ctx.decisions.decide(
                tx,
                principal,
                { tenantId: tenant.id, action, resource: { type: 'iam', id: request.identityId } },
                true,
              )
            ).allowed;
          if (
            request.type === 'access' ||
            request.type === 'portability' ||
            request.type === 'erasure'
          ) {
            // A request from an address nobody linked would answer "nothing held" while an account may exist.
            if (request.subject.startsWith('email:'))
              throw new IamError(
                'INVALID_INPUT',
                'Link the request to an account or an application subject (linkRequest), or decline it as no-data',
              );
            // Exporting or erasing everything about someone is as sensitive as identities.export / delete.
            auth.requireRecent(principal);
          }
          switch (request.type) {
            case 'access':
            case 'portability': {
              if (!(await identityAllowed('iam:identities:read')))
                throw new OperationDenied('Exporting a person’s data also needs iam:identities:read');
              const scope = request.type === 'access' ? 'full' : 'provided';
              const auditAllowed = (
                await ctx.decisions.decide(
                  tx,
                  principal,
                  { tenantId: tenant.id, action: 'iam:audit:read', resource: { type: 'iam', id: tenant.id } },
                  true,
                )
              ).allowed;
              const data = await buildExport(ctx, tx, tenant, request, scope, auditAllowed);
              exportId = id();
              await tx.insert<PrivacyExport>('privacyExports', {
                id: exportId,
                tenantId: tenant.id,
                requestId: request.id,
                subject: request.subject,
                ...(request.identityId ? { identityId: request.identityId } : {}),
                scope,
                createdAt: now,
                expiresAt: now + settings.exportLifetimeDays * dayMs,
                sha256: hash(canonicalJson(data)),
                data,
                downloads: 0,
              });
              actions.push(`export:${scope}`);
              break;
            }
            case 'erasure': {
              const hold = await activeHold(tx, tenant.id, request.subject, now);
              if (hold)
                throw new IamError(
                  'LEGAL_HOLD',
                  'This subject is under a legal hold; release it or reject the request as exempt',
                  409,
                );
              if (!(await identityAllowed('iam:identities:delete')))
                throw new OperationDenied('Erasing an account also needs iam:identities:delete');
              notifyTo = await subjectAddress(tx, request);
              actions.push(...(await eraseSubject(ctx, tx, principal, tenant, request)));
              break;
            }
            case 'restriction': {
              if (request.subject.startsWith('email:'))
                throw new IamError(
                  'INVALID_INPUT',
                  'Link the request to an account or an application subject before restricting processing',
                );
              if (!(await restrictionOf(tx, tenant.id, request.subject)))
                await tx.insert<PrivacyRestriction>('privacyRestrictions', {
                  id: id(),
                  tenantId: tenant.id,
                  subject: request.subject,
                  ...(request.identityId ? { identityId: request.identityId } : {}),
                  ...(request.externalId !== undefined ? { externalId: request.externalId } : {}),
                  requestId: request.id,
                  restrictedAt: now,
                  restrictedBy: principal.identity.id,
                });
              actions.push('restricted');
              break;
            }
            case 'objection':
            case 'opt-out': {
              if (request.subject.startsWith('email:'))
                throw new IamError(
                  'INVALID_INPUT',
                  'Link the request to an account or an application subject before withdrawing consent',
                );
              const all = await tx.find<PrivacyPurpose>('privacyPurposes', { tenantId: tenant.id });
              const targets = request.purposeKeys?.length
                ? all.filter((purpose) => request.purposeKeys!.includes(purpose.key))
                : all.filter((purpose) =>
                    request.type === 'opt-out'
                      ? purpose.legalBasis === 'consent' && purpose.mode === 'opt-out'
                      : decidable(purpose),
                  );
              const subject: ResolvedSubject = {
                key: request.subject,
                ...(request.identityId ? { identityId: request.identityId } : {}),
                ...(request.externalId !== undefined ? { externalId: request.externalId } : {}),
              };
              let withdrawn = 0;
              for (const purpose of targets.filter((item) => decidable(item))) {
                await writeConsent(ctx, tx, {
                  tenantId: tenant.id,
                  purpose,
                  subject,
                  granted: false,
                  source: 'request',
                  method: `request:${request.number}`,
                  recordedBy: principal.identity.id,
                  at: now,
                });
                withdrawn++;
              }
              actions.push(`consents-withdrawn:${withdrawn}`);
              break;
            }
            case 'rectification': {
              if (!note)
                throw new IamError('INVALID_INPUT', 'Describe what was corrected in the note');
              actions.push('rectified');
              break;
            }
          }
          const base = request.type === 'erasure' ? redact(request) : request;
          const completed: SubjectRequest = {
            ...base,
            status: 'completed',
            closedAt: now,
            closedBy: principal.identity.id,
            actions,
            ...(exportId ? { exportId } : {}),
            events: pushEvent(base, {
              at: now,
              by: principal.identity.id,
              what: 'completed',
              ...(note && request.type !== 'erasure' ? { note } : {}),
            }),
          };
          await tx.put('privacyRequests', completed);
          await notifySubject(ctx, tx, tenant, completed, 'completed', notifyTo);
          await ctx.events.audit(tx, principal, 'privacy:request:complete', tenant.id, request.id, 'allow', false, {
            number: request.number,
            type: request.type,
            actions,
          });
          if (request.type === 'erasure')
            await ctx.events.audit(
              tx,
              principal,
              'privacy:erasure',
              tenant.id,
              request.identityId ?? request.subject,
              'allow',
              false,
              {
                requestId: request.id,
                subjectKind: request.identityId
                  ? 'account'
                  : request.externalId !== undefined
                    ? 'external'
                    : 'requester',
                ...(request.externalId !== undefined ? { externalId: request.externalId } : {}),
              },
            );
          return requestView(completed, now);
        },
      ),
    /**
     * Refuses a request (`unverified`, `unfounded`, `excessive`, `exempt`, `duplicate`, `other`) with a note the
     * subject is told. Audited as `privacy:request:reject`.
     */
    rejectRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; reason: RejectionReason; note?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:handle',
        text(input.requestId, 'requestId'),
        async ({ tx, tenant, principal }) => {
          const request = await openRequest(tx, tenant.id, input.requestId);
          if (request.status !== 'open' && request.status !== 'pending-verification')
            throw new IamError('INVALID_TRANSITION', 'This request is closed', 409);
          const reason = oneOf(input.reason, rejectionReasons, 'reason');
          const now = ctx.now();
          const { tokenHash: _hash, tokenExpiresAt: _expires, ...kept } = request;
          const rejected: SubjectRequest = {
            ...kept,
            status: 'rejected',
            rejectionReason: reason,
            closedAt: now,
            closedBy: principal.identity.id,
            events: pushEvent(request, {
              at: now,
              by: principal.identity.id,
              what: 'rejected',
              ...(input.note !== undefined ? { note: prose(input.note, 'note', 2000) } : {}),
            }),
          };
          await tx.put('privacyRequests', rejected);
          await notifySubject(ctx, tx, tenant, rejected, 'rejected');
          await ctx.events.audit(tx, principal, 'privacy:request:reject', tenant.id, request.id, 'allow', false, {
            number: request.number,
            type: request.type,
            reason,
          });
          return requestView(rejected, now);
        },
      ),
    /** Requests, filtered by status, type, assignee or `overdue`; open ones by deadline, then newest first. */
    listRequests: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        status?: SubjectRequest['status'];
        type?: SubjectRequestType;
        assigneeId?: string;
        overdue?: boolean;
        subject?: SubjectInput;
        limit?: number;
        offset?: number;
      },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) => {
        const limit = integer(input.limit ?? 100, 'limit', 1, 500);
        const offset = integer(input.offset ?? 0, 'offset', 0, 10_000_000);
        const filter: Record<string, unknown> = { tenantId: tenant.id };
        if (input.status !== undefined)
          filter.status = oneOf(
            input.status,
            ['pending-verification', 'open', 'completed', 'rejected', 'cancelled'] as const,
            'status',
          );
        if (input.type !== undefined) filter.type = oneOf(input.type, subjectRequestTypes, 'type');
        if (input.assigneeId !== undefined) filter.assigneeId = text(input.assigneeId, 'assigneeId');
        if (input.subject !== undefined)
          filter.subject = (await resolveSubject(tx, tenant.id, input.subject, true)).key;
        const now = ctx.now();
        const rows = (await tx.find<SubjectRequest>('privacyRequests', filter))
          .filter((request) => input.overdue !== true || requestOverdue(request, now))
          .sort(
            (a, b) =>
              Number(b.status === 'open') - Number(a.status === 'open') ||
              (a.status === 'open' && b.status === 'open'
                ? (a.dueAt ?? 0) - (b.dueAt ?? 0)
                : b.submittedAt - a.submittedAt) ||
              (a.id < b.id ? -1 : 1),
          );
        const page = rows.slice(offset, offset + limit);
        const names = await subjectNames(tx, page);
        return {
          total: rows.length,
          requests: page.map((request) =>
            requestView(request, now, request.identityId ? names.get(request.identityId) : undefined),
          ),
        };
      }),
    getRequest: async (credential: CredentialInput, input: { tenantId: string; requestId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:read',
        text(input.requestId, 'requestId'),
        async ({ tx, tenant }) => {
          const request = await openRequest(tx, tenant.id, input.requestId);
          const names = await subjectNames(tx, [request]);
          const hold = await activeHold(tx, tenant.id, request.subject, ctx.now());
          return {
            ...requestView(
              request,
              ctx.now(),
              request.identityId ? names.get(request.identityId) : undefined,
            ),
            legalHold: Boolean(hold),
            restricted: Boolean(await restrictionOf(tx, tenant.id, request.subject)),
          };
        },
      ),

    // ── Public intake ─────────────────────────────────────────────────────────────────────────────────────────
    /**
     * Public request form for people without an account (or who cannot sign in), when the organization turned on
     * `publicIntake`. The requester confirms their email address through the emailed link (`confirmPublic`) before
     * anyone handles it; unconfirmed requests lapse after seven days. Rate limited per organization and address.
     */
    submitPublic: async (input: {
      tenantId: string;
      type: SubjectRequestType;
      email: string;
      name?: string;
      externalId?: string;
      regulation?: Regulation;
      details?: string;
      purposeKeys?: string[];
    }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const address = email(input.email);
      const type = oneOf(input.type, subjectRequestTypes, 'type');
      const details = input.details === undefined ? undefined : prose(input.details, 'details', 5000);
      const name = input.name === undefined ? undefined : text(input.name, 'name', 200);
      const externalId = input.externalId === undefined ? undefined : externalSubjectId(input.externalId);
      const purposeKeys = purposeKeysOf(input.purposeKeys);
      // Counted outside the transaction, so a refusal cannot roll the counters back.
      // The per-address budget is the main control (with the per-IP counter when `rateLimits.ipAttempts` is on); the
      // organization-wide one only caps floods, so it is generous enough that one sender cannot lock others out.
      await auth.limitAttempt(tenantId, 'privacy-intake', { limit: 500 });
      await auth.limitAttempt(tenantId, `privacy-intake:${address}`, { limit: 3 });
      return ctx.store.transaction(async (tx) => {
        const tenant = await tx.get<Tenant>('tenants', tenantId);
        const settings = tenant ? await privacySettings(tx, tenantId) : undefined;
        if (!tenant || tenant.status !== 'active' || !settings?.publicIntake)
          throw new IamError('NOT_FOUND', 'Not found', 404);
        if (!canEmail(ctx))
          throw new IamError('DELIVERY_REQUIRED', 'Public requests need an email delivery callback');
        if (purposeKeys) for (const key of purposeKeys) await purposeByKey(tx, tenantId, key);
        const now = ctx.now();
        const number = requestNumber();
        const secret = token();
        const request: SubjectRequest = {
          id: id(),
          tenantId,
          uniqueKey: `number:${number}`,
          number,
          type,
          regulation: regulationOf(input.regulation, settings),
          status: 'pending-verification',
          subject:
            externalId !== undefined
              ? `external:${externalId}`
              : emailSubject(ctx.options.secret, address),
          ...(externalId !== undefined ? { externalId } : {}),
          requesterEmail: address,
          ...(name ? { requesterName: name } : {}),
          ...(details ? { details } : {}),
          ...(purposeKeys ? { purposeKeys } : {}),
          channel: 'public',
          verification: { status: 'pending' },
          tokenHash: hash(secret),
          tokenExpiresAt: now + verificationLifetimeMs,
          submittedAt: now,
          events: [
            { at: now, by: 'requester', what: 'submitted' },
            { at: now, by: 'requester', what: 'verification-sent' },
          ],
        };
        await tx.insert('privacyRequests', request);
        await auth.enqueueDelivery(tx, {
          tenantId,
          kind: 'email',
          to: address,
          template: 'privacy-request-verify',
          payload: {
            tenantId,
            tenantName: tenant.name,
            requestId: request.id,
            number,
            type,
            token: secret,
          },
        });
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'public-intake',
          action: 'privacy:request:submit',
          resourceId: request.id,
          timestamp: now,
          outcome: 'allow',
          metadata: { number, type, regulation: request.regulation, channel: 'public' },
        });
        return { number, status: request.status };
      });
    },
    /**
     * Confirms a public request from the emailed link. The response window starts now; when the address belongs to a
     * person here with a verified email, the request is linked to their account. A request naming an application
     * identifier (`externalId`) stays unverified: owning the address does not prove owning the identifier, so a handler
     * checks it (`verifyRequest`) before anything is exported, withdrawn or erased.
     */
    confirmPublic: async (input: { tenantId: string; requestId: string; token: string }) => {
      const tenantId = text(input.tenantId, 'tenantId');
      const requestId = text(input.requestId, 'requestId');
      const presented = text(input.token, 'token', 512);
      await auth.limitAttempt(tenantId, `privacy-confirm:${requestId}`, { limit: 10 });
      return ctx.store.transaction(async (tx) => {
        const request = await tx.get<SubjectRequest>('privacyRequests', requestId);
        const now = ctx.now();
        if (
          !request ||
          request.tenantId !== tenantId ||
          request.status !== 'pending-verification' ||
          !request.tokenHash ||
          !sameHash(request.tokenHash, hash(presented)) ||
          (request.tokenExpiresAt ?? 0) <= now
        )
          throw new IamError(
            'CONFIRMATION_INVALID',
            'This confirmation link is invalid or has expired',
            400,
          );
        const tenant = await ctx.tenant(tx, tenantId);
        const settings = await privacySettings(tx, tenantId);
        if (request.externalId !== undefined) {
          const { tokenHash: _hash, tokenExpiresAt: _expires, ...kept } = request;
          const confirmed: SubjectRequest = {
            ...kept,
            emailConfirmedAt: now,
            events: pushEvent(request, {
              at: now,
              by: 'requester',
              what: 'email-confirmed',
              note: 'The address is confirmed; a handler must still confirm the identifier',
            }),
          };
          await tx.put('privacyRequests', confirmed);
          await notifyContact(ctx, tx, tenant, confirmed);
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId,
            actorId: 'public-intake',
            action: 'privacy:request:email-confirmed',
            resourceId: request.id,
            timestamp: now,
            outcome: 'allow',
            metadata: { number: request.number },
          });
          return { number: confirmed.number, status: confirmed.status };
        }
        let linked: SubjectRequest = request;
        if (request.requesterEmail) {
          const person = (
            await tx.find<Identity>('identities', { tenantId, email: request.requesterEmail })
          ).find(
            (identity) =>
              identity.kind === 'user' && identity.status !== 'deleted' && identity.emailVerified,
          );
          if (person)
            linked = { ...request, subject: identitySubject(person.id), identityId: person.id };
        }
        const verified = opened(linked, settings, now, {
          status: 'verified',
          method: 'email-link',
          verifiedAt: now,
        });
        verified.events = pushEvent(request, { at: now, by: 'requester', what: 'verified' });
        await tx.put('privacyRequests', verified);
        await notifyContact(ctx, tx, tenant, verified);
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'public-intake',
          action: 'privacy:request:verify',
          resourceId: request.id,
          timestamp: now,
          outcome: 'allow',
          metadata: { number: request.number, method: 'email-link', linked: Boolean(verified.identityId) },
        });
        return {
          number: verified.number,
          status: verified.status,
          ...(verified.dueAt !== undefined ? { dueAt: verified.dueAt } : {}),
        };
      });
    },

    // ── Holds and restriction ─────────────────────────────────────────────────────────────────────────────────
    /** Places a legal hold: erasure of the subject (and deletion of their account) is refused until it is released. */
    placeHold: async (
      credential: CredentialInput,
      input: { tenantId: string; subject: SubjectInput; reason: string; expiresAt?: number },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:manage', input.tenantId, async ({ tx, tenant, principal }) => {
        const subject = await resolveSubject(tx, tenant.id, input.subject);
        const now = ctx.now();
        const expiresAt =
          input.expiresAt === undefined ? undefined : ctx.bindingExpiry(input.expiresAt);
        const hold: PrivacyHold = {
          id: id(),
          tenantId: tenant.id,
          subject: subject.key,
          ...(subject.identityId ? { identityId: subject.identityId } : {}),
          ...(subject.externalId !== undefined ? { externalId: subject.externalId } : {}),
          reason: prose(input.reason, 'reason', 2000),
          placedBy: principal.identity.id,
          placedAt: now,
          ...(expiresAt !== undefined ? { expiresAt } : {}),
        };
        await tx.insert('privacyHolds', hold);
        await ctx.events.audit(tx, principal, 'privacy:hold:place', tenant.id, subject.identityId ?? subject.key, 'allow', false, {
          holdId: hold.id,
          ...(expiresAt !== undefined ? { expiresAt } : {}),
        });
        return hold;
      }),
    releaseHold: async (credential: CredentialInput, input: { tenantId: string; holdId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:privacy:manage',
        text(input.holdId, 'holdId'),
        async ({ tx, tenant, principal }) => {
          const hold = await ctx.scoped<PrivacyHold>(tx, 'privacyHolds', input.holdId, tenant.id);
          await tx.delete('privacyHolds', hold.id);
          await ctx.events.audit(tx, principal, 'privacy:hold:release', tenant.id, hold.identityId ?? hold.subject, 'allow', false, {
            holdId: hold.id,
          });
          return { released: true };
        },
      ),
    listHolds: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) => {
        const now = ctx.now();
        return (await tx.find<PrivacyHold>('privacyHolds', { tenantId: tenant.id }))
          .map((hold) => ({ ...hold, active: hold.expiresAt === undefined || hold.expiresAt > now }))
          .sort((a, b) => b.placedAt - a.placedAt);
      }),
    /** Subjects whose processing is restricted. */
    listRestrictions: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) =>
        (await tx.find<PrivacyRestriction>('privacyRestrictions', { tenantId: tenant.id })).sort(
          (a, b) => b.restrictedAt - a.restrictedAt,
        ),
      ),
    /** Ends a restriction of processing (the subject should be told before it ends). */
    liftRestriction: async (
      credential: CredentialInput,
      input: { tenantId: string; subject: SubjectInput },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:handle', input.tenantId, async ({ tx, tenant, principal }) => {
        const subject = await resolveSubject(tx, tenant.id, input.subject, true);
        const restriction = await restrictionOf(tx, tenant.id, subject.key);
        if (!restriction) throw new IamError('NOT_FOUND', 'No restriction for this subject', 404);
        await tx.delete('privacyRestrictions', restriction.id);
        await ctx.events.audit(tx, principal, 'privacy:restriction:lift', tenant.id, subject.identityId ?? subject.key, 'allow');
        return { lifted: true };
      }),

    // ── Settings and reporting ────────────────────────────────────────────────────────────────────────────────
    getSettings: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) =>
        settingsView(await privacySettings(tx, tenant.id)),
      ),
    /**
     * Updates the privacy contact, the default regulation, shorter internal response windows, public intake and how
     * long exports stay downloadable. `null` clears an optional field.
     */
    updateSettings: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        contactEmail?: string | null;
        contactName?: string | null;
        defaultRegulation?: Regulation;
        responseDays?: Partial<Record<Regulation, number>> | null;
        publicIntake?: boolean;
        exportLifetimeDays?: number;
      },
    ) =>
      operation(credential, input.tenantId, 'iam:privacy:manage', input.tenantId, async ({ tx, tenant }) => {
        const previous = await privacySettings(tx, tenant.id);
        const next: PrivacySettings = { ...previous, updatedAt: ctx.now() };
        if (input.contactEmail === null) delete next.contactEmail;
        else if (input.contactEmail !== undefined) next.contactEmail = email(input.contactEmail);
        if (input.contactName === null) delete next.contactName;
        else if (input.contactName !== undefined)
          next.contactName = text(input.contactName, 'contactName', 200);
        if (input.defaultRegulation !== undefined)
          next.defaultRegulation = oneOf(input.defaultRegulation, regulations, 'defaultRegulation');
        if (input.responseDays === null) delete next.responseDays;
        else if (input.responseDays !== undefined) {
          const entries = Object.entries(object(input.responseDays));
          const result: Partial<Record<Regulation, number>> = {};
          for (const [key, value] of entries) {
            const regulation = oneOf(key, regulations, 'responseDays key');
            result[regulation] = integer(
              value,
              `responseDays.${regulation}`,
              1,
              regulationDeadlines[regulation].responseDays,
            );
          }
          if (Object.keys(result).length) next.responseDays = result;
          else delete next.responseDays;
        }
        if (input.publicIntake !== undefined) {
          if (typeof input.publicIntake !== 'boolean')
            throw new IamError('INVALID_INPUT', 'publicIntake must be a boolean');
          if (input.publicIntake && !canEmail(ctx))
            throw new IamError(
              'DELIVERY_REQUIRED',
              'Public requests need an email delivery callback to confirm addresses',
            );
          next.publicIntake = input.publicIntake;
        }
        if (input.exportLifetimeDays !== undefined)
          next.exportLifetimeDays = integer(input.exportLifetimeDays, 'exportLifetimeDays', 1, 90);
        await ((await tx.get('privacySettings', next.id))
          ? tx.put('privacySettings', next)
          : tx.insert('privacySettings', next));
        return settingsView(next);
      }),
    /** Consent counts per purpose, the request queue, holds and restrictions at a glance. */
    summary: async (credential: CredentialInput, input: { tenantId: string }): Promise<PrivacySummary> =>
      operation(credential, input.tenantId, 'iam:privacy:read', input.tenantId, async ({ tx, tenant }) => {
        const now = ctx.now();
        const restricted = new Set(
          (await tx.find<PrivacyRestriction>('privacyRestrictions', { tenantId: tenant.id })).map(
            (restriction) => restriction.subject,
          ),
        );
        const consents = await tx.find<PrivacyConsent>('privacyConsents', { tenantId: tenant.id });
        const purposes = (await tx.find<PrivacyPurpose>('privacyPurposes', { tenantId: tenant.id }))
          .sort((a, b) => a.name.localeCompare(b.name))
          .map((purpose) => {
            const counts = { granted: 0, withdrawn: 0, expired: 0, outdated: 0 };
            for (const consent of consents)
              if (consent.purposeId === purpose.id) {
                const state = consentState(purpose, consent, restricted.has(consent.subject), now);
                if (state.allowed) counts.granted++;
                else if (state.reason === 'CONSENT_EXPIRED') counts.expired++;
                else if (state.reason === 'CONSENT_OUTDATED') counts.outdated++;
                else if (state.reason === 'CONSENT_WITHDRAWN' || state.reason === 'OBJECTED')
                  counts.withdrawn++;
              }
            return {
              id: purpose.id,
              key: purpose.key,
              name: purpose.name,
              legalBasis: purpose.legalBasis,
              mode: purpose.mode,
              version: purpose.version,
              archived: purpose.archived,
              ...counts,
            };
          });
        const requests = await tx.find<SubjectRequest>('privacyRequests', { tenantId: tenant.id });
        const byType = Object.fromEntries(subjectRequestTypes.map((type) => [type, 0])) as Record<
          SubjectRequestType,
          number
        >;
        const durations: number[] = [];
        let completedLast30Days = 0;
        for (const request of requests) {
          if (request.status === 'open' || request.status === 'pending-verification')
            byType[request.type]++;
          if (request.status === 'completed' && (request.closedAt ?? 0) > now - 30 * dayMs)
            completedLast30Days++;
          if (
            request.closedAt !== undefined &&
            request.receivedAt !== undefined &&
            request.closedAt > now - 90 * dayMs &&
            (request.status === 'completed' || request.status === 'rejected')
          )
            durations.push((request.closedAt - request.receivedAt) / dayMs);
        }
        durations.sort((a, b) => a - b);
        const median =
          durations.length === 0
            ? undefined
            : durations.length % 2
              ? durations[(durations.length - 1) / 2]!
              : (durations[durations.length / 2 - 1]! + durations[durations.length / 2]!) / 2;
        return {
          purposes,
          requests: {
            pendingVerification: requests.filter((r) => r.status === 'pending-verification').length,
            open: requests.filter((r) => r.status === 'open').length,
            overdue: requests.filter((r) => requestOverdue(r, now)).length,
            dueSoon: requests.filter(
              (r) =>
                r.status === 'open' &&
                r.dueAt !== undefined &&
                r.dueAt > now &&
                r.dueAt <= now + 7 * dayMs,
            ).length,
            completedLast30Days,
            ...(median !== undefined ? { medianDaysToClose: Math.round(median * 10) / 10 } : {}),
            byType,
          },
          holds: (await tx.find<PrivacyHold>('privacyHolds', { tenantId: tenant.id })).filter(
            (hold) => hold.expiresAt === undefined || hold.expiresAt > now,
          ).length,
          restrictions: restricted.size,
        };
      }),
  };
  return api;
}

function settingsView(settings: PrivacySettings): PrivacySettingsView {
  return {
    ...(settings.contactEmail ? { contactEmail: settings.contactEmail } : {}),
    ...(settings.contactName ? { contactName: settings.contactName } : {}),
    defaultRegulation: settings.defaultRegulation,
    ...(settings.responseDays ? { responseDays: settings.responseDays } : {}),
    publicIntake: settings.publicIntake,
    exportLifetimeDays: settings.exportLifetimeDays,
    statutory: { ...regulationDeadlines },
  };
}

/** The processing decision for a subject and purpose, shared by the API and the credential-free runtime. */
async function checkSubject(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  subjectInput: unknown,
  key: unknown,
) {
  const purpose = await purposeByKey(tx, tenantId, key);
  const subject = await resolveSubject(tx, tenantId, subjectInput);
  const consent = (
    await tx.find<PrivacyConsent>('privacyConsents', {
      tenantId,
      uniqueKey: `${purpose.id}:${subject.key}`,
    })
  )[0];
  const restricted = restrictionState(await restrictionOf(tx, tenantId, subject.key));
  const state = consentState(purpose, consent, restricted, ctx.now());
  return {
    purposeKey: purpose.key,
    purposeVersion: purpose.version,
    ...state,
    ...(consent
      ? {
          consent: {
            granted: consent.granted,
            purposeVersion: consent.purposeVersion,
            recordedAt: consent.recordedAt,
            ...(consent.expiresAt !== undefined ? { expiresAt: consent.expiresAt } : {}),
            receiptId: consent.receiptId,
          },
        }
      : {}),
  };
}

/**
 * Privacy for the deployment's own server code (`iam.privacy`): credential-free consent checks and recording (for
 * an application's own customers), and the deadline job.
 */
export function createPrivacyRuntime(ctx: ServerContext) {
  return {
    /** Whether a purpose may be processed for a subject right now; not audited. */
    check: (input: { tenantId: string; subject: SubjectInput; purposeKey: string }) =>
      ctx.store.transaction((tx) =>
        checkSubject(ctx, tx, text(input.tenantId, 'tenantId'), input.subject, input.purposeKey),
      ),
    /**
     * Records a decision the application captured itself (a cookie banner, a signup form), attributed to
     * `application`. Audited as `privacy:consent`; returns the receipt.
     */
    record: (input: {
      tenantId: string;
      subject: SubjectInput;
      purposeKey: string;
      granted: boolean;
      method?: string;
      evidence?: string;
      ip?: string;
      userAgent?: string;
    }) =>
      ctx.store.transaction(async (tx) => {
        const tenantId = text(input.tenantId, 'tenantId');
        if (typeof input.granted !== 'boolean')
          throw new IamError('INVALID_INPUT', 'granted must be a boolean');
        await ctx.tenant(tx, tenantId);
        const purpose = await purposeByKey(tx, tenantId, input.purposeKey);
        const subject = await resolveSubject(tx, tenantId, input.subject);
        const now = ctx.now();
        const { receipt } = await writeConsent(ctx, tx, {
          tenantId,
          purpose,
          subject,
          granted: input.granted,
          source: 'api',
          method: method(input.method),
          evidence: evidence(input.evidence),
          recordedBy: 'application',
          at: now,
          client: {
            ...(input.ip !== undefined ? { ip: text(input.ip, 'ip', 64) } : {}),
            ...(input.userAgent !== undefined
              ? { userAgent: text(input.userAgent, 'userAgent', 512) }
              : {}),
          },
        });
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'application',
          action: 'privacy:consent',
          resourceId: subject.identityId ?? subject.key,
          timestamp: now,
          outcome: 'allow',
          metadata: {
            purposeKey: purpose.key,
            granted: input.granted,
            purposeVersion: receipt.purpose.version,
            source: 'api',
            receiptId: receipt.receiptId,
            ...(subject.externalId !== undefined ? { externalId: subject.externalId } : {}),
          },
        });
        return receipt;
      }),
    /**
     * Deadline job (daily or hourly): emails the assignee (or the privacy contact) once when an open request is due
     * within `withinDays` (default 7) and once when it becomes overdue, audited as `privacy:request:due-soon` /
     * `privacy:request:overdue` so webhooks can alert too; cancels public requests nobody confirmed within seven days.
     */
    sendDeadlineReminders: async (
      input: { tenantId?: string; withinDays?: number } = {},
    ): Promise<DeadlineReminderResult> => {
      const withinDays = integer(input.withinDays ?? 7, 'withinDays', 1, 60);
      const tenantFilter = input.tenantId === undefined ? {} : { tenantId: text(input.tenantId, 'tenantId') };
      return ctx.store.transaction(async (tx) => {
        const now = ctx.now();
        const result: DeadlineReminderResult = { reminded: [], lapsed: 0 };
        const tenants = new Map<string, Tenant | undefined>();
        const tenantOf = async (tenantId: string) => {
          if (!tenants.has(tenantId)) tenants.set(tenantId, await tx.get<Tenant>('tenants', tenantId));
          return tenants.get(tenantId);
        };
        const pending = await tx.find<SubjectRequest>('privacyRequests', {
          ...tenantFilter,
          status: 'pending-verification',
        });
        for (const request of pending)
          if (
            request.channel === 'public' &&
            request.tokenHash !== undefined &&
            request.submittedAt + verificationLifetimeMs <= now
          ) {
            const { tokenHash: _hash, tokenExpiresAt: _expires, ...kept } = request;
            await tx.put<SubjectRequest>('privacyRequests', {
              ...kept,
              status: 'cancelled',
              closedAt: now,
              closedBy: 'deployment-operator',
              events: pushEvent(request, {
                at: now,
                by: 'deployment-operator',
                what: 'cancelled',
                note: 'The requester did not confirm their email address within seven days',
              }),
            });
            result.lapsed++;
          }
        const open = await tx.find<SubjectRequest>('privacyRequests', { ...tenantFilter, status: 'open' });
        for (const request of open) {
          if (request.dueAt === undefined) continue;
          const kind: 'due-soon' | 'overdue' | undefined =
            request.dueAt <= now
              ? 'overdue'
              : request.dueAt <= now + withinDays * dayMs
                ? 'due-soon'
                : undefined;
          if (!kind || request.reminded?.includes(kind)) continue;
          const tenant = await tenantOf(request.tenantId);
          if (!tenant || tenant.status !== 'active') continue;
          const settings = await privacySettings(tx, tenant.id);
          const assignee = request.assigneeId
            ? await tx.get<Identity>('identities', request.assigneeId)
            : undefined;
          const to =
            assignee?.status === 'active' && assignee.email ? assignee.email : settings.contactEmail;
          if (to && canEmail(ctx))
            await ctx.auth.enqueueDelivery(tx, {
              tenantId: tenant.id,
              kind: 'email',
              to,
              template: 'privacy-request-due',
              payload: {
                tenantId: tenant.id,
                tenantName: tenant.name,
                requestId: request.id,
                number: request.number,
                type: request.type,
                dueAt: String(request.dueAt),
                overdue: String(kind === 'overdue'),
              },
            });
          await tx.put<SubjectRequest>('privacyRequests', {
            ...request,
            reminded: [...(request.reminded ?? []), kind],
            events: pushEvent(request, {
              at: now,
              by: 'deployment-operator',
              what: 'reminded',
              note: kind,
            }),
          });
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: tenant.id,
            actorId: 'deployment-operator',
            action: `privacy:request:${kind}`,
            resourceId: request.id,
            timestamp: now,
            outcome: 'allow',
            metadata: { number: request.number, type: request.type, dueAt: request.dueAt },
          });
          result.reminded.push({ tenantId: tenant.id, requestId: request.id, kind });
        }
        return result;
      });
    },
  };
}
