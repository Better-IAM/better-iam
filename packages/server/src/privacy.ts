import { createHash, createHmac, randomBytes } from 'node:crypto';
import {
  IamError,
  canonicalJson,
  type IamStore,
  type Identity,
  type Json,
  type PolicyDocument,
  type StoredRecord,
} from '@better-iam/core';
import { sameHash } from './utils.js';
import { integer, text } from './validation.js';

/**
 * Privacy and consent management (GDPR, UK GDPR, CCPA/CPRA, LGPD, PIPEDA): the purposes a tenant processes personal
 * data for, each person's consent to them with a signed receipt and an append-only history, data-subject requests
 * with statutory deadlines, legal holds that stop erasure, and restriction of processing.
 */

/** The lawful basis a purpose relies on (GDPR Art. 6). Only `consent` and `legitimate-interests` give people a say. */
export type LegalBasis =
  | 'consent'
  | 'contract'
  | 'legal-obligation'
  | 'vital-interests'
  | 'public-task'
  | 'legitimate-interests';
export const legalBases: readonly LegalBasis[] = [
  'consent',
  'contract',
  'legal-obligation',
  'vital-interests',
  'public-task',
  'legitimate-interests',
];
/** `opt-in` needs a recorded grant; `opt-out` is allowed until the person withdraws (CCPA "do not sell or share"). */
export type ConsentMode = 'opt-in' | 'opt-out';

/** A processing purpose, such as `marketing-email` or `product-analytics`. Keys are unique per tenant. */
export interface PrivacyPurpose extends StoredRecord {
  key: string;
  name: string;
  /** What is processed and why, as shown to people when they decide (plain text, at most 5 000 characters). */
  description: string;
  legalBasis: LegalBasis;
  mode: ConsentMode;
  /** Bumped when the purpose changes materially; see `reconsentOnVersion`. */
  version: number;
  /** Categories of personal data the purpose uses (`contact`, `usage`, `location`, ...). */
  dataCategories: string[];
  /** How long data for this purpose is kept, for records of processing and people's information. */
  retentionDays?: number;
  /** A grant lapses this many days after it was given (cookie consent is often 365). */
  consentLifetimeDays?: number;
  /** Opt-in grants given to an older version stop counting when a new version is published (default true). */
  reconsentOnVersion: boolean;
  /** Archived purposes are no longer processed: every check refuses them and people no longer see them. */
  archived: boolean;
  createdAt: number;
  updatedAt: number;
}

/** Where a consent record came from. `request` records were written while fulfilling a data-subject request. */
export type ConsentSource = 'self' | 'admin' | 'api' | 'import' | 'request';

/** The current decision of one subject on one purpose (uniqueKey `{purposeId}:{subject}`). */
export interface PrivacyConsent extends StoredRecord {
  purposeId: string;
  purposeKey: string;
  /** `identity:{id}` for people with an account here, `external:{id}` for subjects the application names. */
  subject: string;
  identityId?: string;
  externalId?: string;
  granted: boolean;
  /** The purpose version the decision was made on. */
  purposeVersion: number;
  source: ConsentSource;
  method?: string;
  recordedAt: number;
  recordedBy: string;
  /** Grants only: when the grant lapses (`consentLifetimeDays`). */
  expiresAt?: number;
  receiptId: string;
}

/** One entry of the append-only consent history; erasure redacts `evidence`, `ip` and `userAgent`. */
export interface PrivacyConsentEvent extends StoredRecord {
  receiptId: string;
  purposeId: string;
  purposeKey: string;
  /** The purpose's name and basis when the decision was made, so the receipt can be rebuilt exactly later. */
  purposeName: string;
  legalBasis: LegalBasis;
  purposeVersion: number;
  subject: string;
  identityId?: string;
  externalId?: string;
  granted: boolean;
  source: ConsentSource;
  method?: string;
  /** What the person saw or where the decision was captured (a form version, a banner text hash). */
  evidence?: string;
  ip?: string;
  userAgent?: string;
  recordedAt: number;
  recordedBy: string;
  redacted?: boolean;
}

/** The regulations data-subject requests are answered under, with their statutory response windows. */
export type Regulation = 'gdpr' | 'uk-gdpr' | 'ccpa' | 'lgpd' | 'pipeda' | 'other';
export const regulationDeadlines: Readonly<
  Record<Regulation, { responseDays: number; extensionDays: number }>
> = {
  // One month, extendable by two further months (Art. 12(3)).
  gdpr: { responseDays: 30, extensionDays: 60 },
  'uk-gdpr': { responseDays: 30, extensionDays: 60 },
  // 45 days, extendable once by 45 (Cal. Civ. Code 1798.130).
  ccpa: { responseDays: 45, extensionDays: 45 },
  // 15 days for a complete answer (Art. 19), no extension.
  lgpd: { responseDays: 15, extensionDays: 0 },
  // 30 days, extendable by 30 (s. 8(3)).
  pipeda: { responseDays: 30, extensionDays: 30 },
  other: { responseDays: 30, extensionDays: 30 },
};
export const regulations = Object.keys(regulationDeadlines) as Regulation[];

/** What a data subject asks for. */
export type SubjectRequestType =
  | 'access'
  | 'portability'
  | 'erasure'
  | 'rectification'
  | 'restriction'
  | 'objection'
  | 'opt-out';
export const subjectRequestTypes: readonly SubjectRequestType[] = [
  'access',
  'portability',
  'erasure',
  'rectification',
  'restriction',
  'objection',
  'opt-out',
];
export type SubjectRequestStatus =
  | 'pending-verification'
  | 'open'
  | 'completed'
  | 'rejected'
  | 'cancelled';
export type RejectionReason =
  | 'unverified'
  | 'unfounded'
  | 'excessive'
  | 'exempt'
  | 'duplicate'
  | 'no-data'
  | 'other';
export const rejectionReasons: readonly RejectionReason[] = [
  'unverified',
  'unfounded',
  'excessive',
  'exempt',
  'duplicate',
  'no-data',
  'other',
];

export interface SubjectRequestEvent {
  at: number;
  /** Identity ID of whoever acted; `requester` for public intake steps, `deployment-operator` for jobs. */
  by: string;
  what:
    | 'submitted'
    | 'verification-sent'
    | 'email-confirmed'
    | 'verified'
    | 'linked'
    | 'assigned'
    | 'extended'
    | 'note'
    | 'completed'
    | 'rejected'
    | 'cancelled'
    | 'reminded';
  note?: string;
}

/** A data-subject request (DSR / DSAR); uniqueKey `number:{number}`. */
export interface SubjectRequest extends StoredRecord {
  /** Human reference such as `DSR-7K2M9QX4`. */
  number: string;
  type: SubjectRequestType;
  regulation: Regulation;
  status: SubjectRequestStatus;
  /** `identity:{id}` or `external:{id}`; public requests from an unknown address use `email:{sha256}`. */
  subject: string;
  identityId?: string;
  externalId?: string;
  requesterEmail?: string;
  requesterName?: string;
  details?: string;
  /** Objection, opt-out and restriction scope; empty means every purpose the person has a say in. */
  purposeKeys?: string[];
  channel: 'self-service' | 'staff' | 'public';
  verification: {
    status: 'verified' | 'pending';
    method?: string;
    verifiedAt?: number;
    verifiedBy?: string;
  };
  /** Public intake: the emailed confirmation token's hash and when it lapses. */
  tokenHash?: string;
  tokenExpiresAt?: number;
  /** Public intake: when the requester confirmed their address (requests naming an `externalId` still need a handler). */
  emailConfirmedAt?: number;
  submittedAt: number;
  /** When the response window started (verification) and when it ends; absent while unverified. */
  receivedAt?: number;
  dueAt?: number;
  extendedAt?: number;
  extensionReason?: string;
  assigneeId?: string;
  closedAt?: number;
  closedBy?: string;
  rejectionReason?: RejectionReason;
  /** What fulfilling it did (`export`, `erased`, `consents-withdrawn:3`, `restricted`, ...). */
  actions?: string[];
  exportId?: string;
  /** Deadline reminders already sent (`due-soon`, `overdue`). */
  reminded?: string[];
  /** Erasure removed the requester's contact details and free text from this record. */
  redacted?: boolean;
  events: SubjectRequestEvent[];
}

/** A legal hold: erasure of the subject is refused until it is released or lapses. */
export interface PrivacyHold extends StoredRecord {
  subject: string;
  identityId?: string;
  externalId?: string;
  reason: string;
  placedBy: string;
  placedAt: number;
  expiresAt?: number;
}

/**
 * Processing of a subject is restricted (GDPR Art. 18): only legal-obligation and vital-interests purposes pass. An
 * erasure of an application subject leaves one with `erased: true` as a suppression marker, so an opt-out or objection
 * the erased records held cannot turn back into "allowed" when the application asks about the same identifier again.
 */
export interface PrivacyRestriction extends StoredRecord {
  subject: string;
  identityId?: string;
  externalId?: string;
  requestId?: string;
  erased?: boolean;
  restrictedAt: number;
  restrictedBy: string;
}

/** A generated access or portability export, downloadable until `expiresAt`. */
export interface PrivacyExport extends StoredRecord {
  requestId: string;
  subject: string;
  identityId?: string;
  scope: 'full' | 'provided';
  createdAt: number;
  expiresAt: number;
  /** SHA-256 of the canonical JSON of `data`, so a copy handed over can be checked later. */
  sha256: string;
  data: Json;
  downloads: number;
}

/** Per-tenant privacy settings (one record per tenant, id `privacy:{tenantId}`). */
export interface PrivacySettings extends StoredRecord {
  /** The privacy contact (data protection officer): emailed about new requests and approaching deadlines. */
  contactEmail?: string;
  contactName?: string;
  defaultRegulation: Regulation;
  /** Shorter internal response windows per regulation (days, never longer than the statutory one). */
  responseDays?: Partial<Record<Regulation, number>>;
  /** Accept requests from people without an account through `privacy.submitPublic` (email confirmation). */
  publicIntake: boolean;
  /** How long a generated export stays downloadable (default 14 days). */
  exportLifetimeDays: number;
  updatedAt: number;
}

export const defaultPrivacySettings = (tenantId: string): PrivacySettings => ({
  id: `privacy:${tenantId}`,
  tenantId,
  defaultRegulation: 'gdpr',
  publicIntake: false,
  exportLifetimeDays: 14,
  updatedAt: 0,
});

export async function privacySettings(tx: IamStore, tenantId: string): Promise<PrivacySettings> {
  return (
    (await tx.get<PrivacySettings>('privacySettings', `privacy:${tenantId}`)) ??
    defaultPrivacySettings(tenantId)
  );
}

/** A subject as callers name it: a person with an account in the tenant, or an application-side identifier. */
export type SubjectInput = { identityId: string } | { externalId: string };
export interface ResolvedSubject {
  key: string;
  identityId?: string;
  externalId?: string;
  identity?: Identity;
}

/** Application-side subject identifiers: 1-256 visible characters (a customer number, a visitor ID, an email hash). */
export function externalSubjectId(value: unknown): string {
  const result = text(value, 'externalId', 256);
  if (result.trim() !== result) throw new IamError('INVALID_INPUT', 'Invalid externalId');
  return result;
}

/**
 * Resolves a subject reference inside a tenant. Identities must be people (service accounts and agents have no
 * privacy rights of their own) and, unless `allowDeleted`, not tombstones.
 */
export async function resolveSubject(
  tx: IamStore,
  tenantId: string,
  value: unknown,
  allowDeleted = false,
): Promise<ResolvedSubject> {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new IamError('INVALID_INPUT', 'subject must name an identityId or an externalId');
  const input = value as Record<string, unknown>;
  const hasIdentity = input.identityId !== undefined;
  const hasExternal = input.externalId !== undefined;
  if (hasIdentity === hasExternal)
    throw new IamError('INVALID_INPUT', 'subject must name exactly one of identityId or externalId');
  if (hasExternal) {
    const externalId = externalSubjectId(input.externalId);
    return { key: `external:${externalId}`, externalId };
  }
  const identityId = text(input.identityId, 'identityId');
  const identity = await tx.get<Identity>('identities', identityId);
  if (
    !identity ||
    identity.tenantId !== tenantId ||
    (!allowDeleted && identity.status === 'deleted')
  )
    throw new IamError('NOT_FOUND', 'Identity not found', 404);
  if (identity.kind !== 'user')
    throw new IamError('INVALID_INPUT', 'Only people are data subjects');
  return { key: `identity:${identity.id}`, identityId: identity.id, identity };
}

export const identitySubject = (identityId: string): string => `identity:${identityId}`;

/**
 * The subject of a request from someone without an account: a keyed hash of their address, so a redacted request
 * cannot be matched back to an email by hashing guesses.
 */
export const emailSubject = (secret: string, address: string): string =>
  `email:${createHmac('sha256', createHash('sha256').update(`better-iam:privacy-subject:${secret}`).digest()).update(address.toLowerCase()).digest('hex')}`;

/** Why a purpose may or may not be processed for a subject right now. */
export type ConsentReason =
  | 'CONSENT_GIVEN'
  | 'NOT_OPTED_OUT'
  | 'LEGITIMATE_INTERESTS'
  | 'LEGAL_BASIS'
  | 'NO_CONSENT'
  | 'CONSENT_WITHDRAWN'
  | 'CONSENT_EXPIRED'
  | 'CONSENT_OUTDATED'
  | 'OBJECTED'
  | 'RESTRICTED'
  | 'ERASED'
  | 'PURPOSE_ARCHIVED';
export interface ConsentState {
  allowed: boolean;
  reason: ConsentReason;
}

/** Purposes a person decides on: consent (opt-in or opt-out) and legitimate interests (objection). */
export const decidable = (purpose: Pick<PrivacyPurpose, 'legalBasis'>): boolean =>
  purpose.legalBasis === 'consent' || purpose.legalBasis === 'legitimate-interests';

/**
 * The processing decision for one purpose and subject. Restriction holds back everything except legal obligations
 * and vital interests; bases other than consent and legitimate interests are allowed without a record. Opt-out
 * purposes and legitimate interests are allowed until the person withdraws or objects; opt-in consent needs a live
 * grant for the current version (unless the purpose keeps older grants valid).
 */
export function consentState(
  purpose: PrivacyPurpose,
  consent: PrivacyConsent | undefined,
  restricted: boolean | 'erased',
  now: number,
): ConsentState {
  if (purpose.archived) return { allowed: false, reason: 'PURPOSE_ARCHIVED' };
  if (
    restricted &&
    purpose.legalBasis !== 'legal-obligation' &&
    purpose.legalBasis !== 'vital-interests'
  )
    return { allowed: false, reason: restricted === 'erased' ? 'ERASED' : 'RESTRICTED' };
  if (purpose.legalBasis === 'legitimate-interests')
    return consent && !consent.granted
      ? { allowed: false, reason: 'OBJECTED' }
      : { allowed: true, reason: 'LEGITIMATE_INTERESTS' };
  if (purpose.legalBasis !== 'consent') return { allowed: true, reason: 'LEGAL_BASIS' };
  if (consent && !consent.granted) return { allowed: false, reason: 'CONSENT_WITHDRAWN' };
  if (purpose.mode === 'opt-out') return { allowed: true, reason: 'NOT_OPTED_OUT' };
  if (!consent) return { allowed: false, reason: 'NO_CONSENT' };
  if (consent.expiresAt !== undefined && consent.expiresAt <= now)
    return { allowed: false, reason: 'CONSENT_EXPIRED' };
  if (purpose.reconsentOnVersion && consent.purposeVersion < purpose.version)
    return { allowed: false, reason: 'CONSENT_OUTDATED' };
  return { allowed: true, reason: 'CONSENT_GIVEN' };
}

export async function restrictionOf(
  tx: IamStore,
  tenantId: string,
  subject: string,
): Promise<PrivacyRestriction | undefined> {
  return (await tx.find<PrivacyRestriction>('privacyRestrictions', { tenantId, subject }))[0];
}

/** How a restriction record feeds `consentState`: none, an ordinary restriction, or an erasure's suppression marker. */
export const restrictionState = (restriction: PrivacyRestriction | undefined): boolean | 'erased' =>
  restriction ? (restriction.erased ? 'erased' : true) : false;

/** The subject's current decision on every purpose, keyed by purpose ID. */
export async function consentsOf(
  tx: IamStore,
  tenantId: string,
  subject: string,
): Promise<Map<string, PrivacyConsent>> {
  return new Map(
    (await tx.find<PrivacyConsent>('privacyConsents', { tenantId, subject })).map((consent) => [
      consent.purposeId,
      consent,
    ]),
  );
}

export const consentContextKey = 'principal.consents';
/** Whether any statement of the documents names `principal.consents` in a condition. */
export function mentionsConsents(documents: Iterable<PolicyDocument>): boolean {
  for (const document of documents)
    for (const statement of document.statements)
      for (const block of Object.values(statement.conditions ?? {}))
        if (block && Object.hasOwn(block, consentContextKey)) return true;
  return false;
}

/**
 * Policy context for a person in their own tenant: `principal.consents` lists the keys of the consent and
 * legitimate-interest purposes that may be processed for them right now (granted, not opted out, not objected to,
 * not restricted). Service accounts and agents are not data subjects, so theirs is empty.
 */
export async function consentContext(
  tx: IamStore,
  tenantId: string,
  identity: Identity,
  now: number,
): Promise<{ 'principal.consents': string[] }> {
  if (identity.kind !== 'user' || identity.tenantId !== tenantId)
    return { 'principal.consents': [] };
  const purposes = (await tx.find<PrivacyPurpose>('privacyPurposes', { tenantId })).filter(
    (purpose) => decidable(purpose) && !purpose.archived,
  );
  if (!purposes.length) return { 'principal.consents': [] };
  const subject = identitySubject(identity.id);
  const consents = await consentsOf(tx, tenantId, subject);
  const restricted = Boolean(await restrictionOf(tx, tenantId, subject));
  return {
    'principal.consents': purposes
      .filter(
        (purpose) => consentState(purpose, consents.get(purpose.id), restricted, now).allowed,
      )
      .map((purpose) => purpose.key)
      .sort(),
  };
}

/** A consent receipt the subject can keep: the decision, signed by the deployment (HMAC-SHA256 over canonical JSON). */
export interface ConsentReceipt {
  version: 1;
  receiptId: string;
  tenantId: string;
  subject: string;
  purpose: { key: string; name: string; version: number; legalBasis: LegalBasis };
  granted: boolean;
  recordedAt: number;
  source: ConsentSource;
  method?: string;
  signature: string;
}

const receiptKey = (secret: string) =>
  createHash('sha256').update(`better-iam:privacy-receipt:${secret}`).digest();

/** The receipt of a recorded decision; receipts are deterministic, so they are rebuilt rather than stored. */
export function receiptFromEvent(secret: string, event: PrivacyConsentEvent): ConsentReceipt {
  return signReceipt(secret, {
    version: 1,
    receiptId: event.receiptId,
    tenantId: event.tenantId,
    subject: event.subject,
    purpose: {
      key: event.purposeKey,
      name: event.purposeName,
      version: event.purposeVersion,
      legalBasis: event.legalBasis,
    },
    granted: event.granted,
    recordedAt: event.recordedAt,
    source: event.source,
    ...(event.method ? { method: event.method } : {}),
  });
}

export function signReceipt(
  secret: string,
  body: Omit<ConsentReceipt, 'signature'>,
): ConsentReceipt {
  const signature = createHmac('sha256', receiptKey(secret))
    .update(canonicalJson(body as unknown as Json))
    .digest('base64url');
  return { ...body, signature };
}

/** Whether a receipt was signed with one of the deployment's secrets (the current one or a previous one). */
export function receiptSignatureValid(secrets: string[], receipt: ConsentReceipt): boolean {
  const { signature, ...body } = receipt;
  if (typeof signature !== 'string') return false;
  return secrets.some((secret) =>
    sameHash(signReceipt(secret, body as Omit<ConsentReceipt, 'signature'>).signature, signature),
  );
}

/** A request reference: `DSR-` and eight characters of Crockford base32. */
export function requestNumber(): string {
  const alphabet = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
  const bytes = randomBytes(8);
  let result = 'DSR-';
  for (const byte of bytes) result += alphabet[byte & 31];
  return result;
}

/** The response window for a regulation, shortened by the tenant's own `responseDays` when set. */
export function responseWindow(
  regulation: Regulation,
  settings: Pick<PrivacySettings, 'responseDays'>,
): { responseDays: number; extensionDays: number } {
  const statutory = regulationDeadlines[regulation];
  const own = settings.responseDays?.[regulation];
  return {
    responseDays:
      own !== undefined ? Math.min(own, statutory.responseDays) : statutory.responseDays,
    extensionDays: statutory.extensionDays,
  };
}

export const dayMs = 86_400_000;

/** A request is overdue once its deadline passed while it is still being handled. */
export const requestOverdue = (request: SubjectRequest, now: number): boolean =>
  request.status === 'open' && request.dueAt !== undefined && request.dueAt <= now;

/** The live legal hold on a subject, if any. */
export async function activeHold(
  tx: IamStore,
  tenantId: string,
  subject: string,
  now: number,
): Promise<PrivacyHold | undefined> {
  return (await tx.find<PrivacyHold>('privacyHolds', { tenantId, subject })).find(
    (hold) => hold.expiresAt === undefined || hold.expiresAt > now,
  );
}

/**
 * Refuses to delete a person under a legal hold (`LEGAL_HOLD`, 409). Called from identity deletion, so every path that
 * deletes (an administrator, an erasure request, a workflow, agent removal) is refused; offboarding and SCIM
 * deprovisioning only disable the account, so its data stays anyway.
 */
export async function assertNoLegalHold(
  tx: IamStore,
  identity: Identity,
  now: number,
): Promise<void> {
  if (identity.kind !== 'user') return;
  const hold = await activeHold(tx, identity.tenantId, identitySubject(identity.id), now);
  if (hold)
    throw new IamError(
      'LEGAL_HOLD',
      'This person is under a legal hold; release the hold before deleting them',
      409,
    );
}

/**
 * Refuses to delete an organization (or the one above it) while a legal hold on anyone in it, or in a tenant below it,
 * is active (`LEGAL_HOLD`, 409): deleting the tenant would purge the held people with it.
 */
export async function assertNoTenantLegalHold(
  tx: IamStore,
  tenantId: string,
  now: number,
  maxDepth: number,
): Promise<void> {
  const realms = await tx.find<StoredRecord & { parentId?: string | null }>('tenants');
  const subtree = new Set([tenantId]);
  for (let depth = 0; depth < maxDepth; depth++)
    for (const realm of realms)
      if (realm.parentId && subtree.has(realm.parentId)) subtree.add(realm.id);
  for (const id of subtree)
    if (
      (await tx.find<PrivacyHold>('privacyHolds', { tenantId: id })).some(
        (hold) => hold.expiresAt === undefined || hold.expiresAt > now,
      )
    )
      throw new IamError(
        'LEGAL_HOLD',
        'People in this organization are under a legal hold; release the holds before deleting it',
        409,
      );
}

/**
 * Removes a deleted person's current consent decisions and restriction. The consent history stays as proof of what
 * was recorded (erasure redacts it separately), and data-subject requests stay as the record of their handling.
 */
export async function releasePrivacyRecords(tx: IamStore, identity: Identity): Promise<void> {
  const subject = identitySubject(identity.id);
  for (const consent of await tx.find<PrivacyConsent>('privacyConsents', {
    tenantId: identity.tenantId,
    subject,
  }))
    await tx.delete('privacyConsents', consent.id);
  for (const restriction of await tx.find<PrivacyRestriction>('privacyRestrictions', {
    tenantId: identity.tenantId,
    subject,
  }))
    await tx.delete('privacyRestrictions', restriction.id);
}

/** Free text up to `max` characters over several lines (tabs and line breaks allowed, other controls not). */
export function prose(value: unknown, name: string, max: number): string {
  if (
    typeof value !== 'string' ||
    !value.trim() ||
    value.length > max ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)
  )
    throw new IamError('INVALID_INPUT', `Invalid ${name}`);
  return value;
}

/** A purpose key: 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter. */
export function purposeKey(value: unknown): string {
  const key = text(value, 'purposeKey', 64);
  if (!/^[a-z][a-z0-9._-]{0,63}$/.test(key))
    throw new IamError(
      'INVALID_INPUT',
      'Purpose keys use lowercase letters, digits, dots, underscores or hyphens',
    );
  return key;
}

export function oneOf<T extends string>(value: unknown, allowed: readonly T[], name: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value))
    throw new IamError('INVALID_INPUT', `${name} must be one of ${allowed.join(', ')}`);
  return value as T;
}

export function days(value: unknown, name: string, max = 3650): number {
  return integer(value, name, 1, max);
}
