import {
  IamError,
  classificationTemplates,
  isValidClassificationLabel,
  labelCovers,
  validateLabel,
  validateScheme,
  type AuthenticatedPrincipal,
  type ClassificationLabel,
  type ClassificationLevel,
  type ClassificationSchemeDefinition,
  type ClassificationTemplateName,
  type CredentialInput,
  type DominanceFailure,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import { agentDecisionScope } from '../agents.js';
import { acceptanceCurrent, type Agreement, type AgreementAcceptance } from '../agreements.js';
import { reservedResourceTypes } from '../catalog.js';
import {
  applicableLabel,
  assertClearances,
  attachLabel,
  clearanceCollections,
  clearanceLimits,
  definedScheme,
  effectiveScheme,
  inheritedLabel,
  labelKey,
  notifyClearanceStatus,
  partiesFail,
  partyState,
  readClearance,
  schemeLevel,
  sessionParties,
  storedLabel,
  suspendClearance,
  type AdjudicationMode,
  type ClassificationScheme,
  type Clearance,
  type ClearanceStatus,
  type EffectiveClearanceStatus,
  type PartyState,
  type ResourceLabel,
} from '../clearances.js';
import type { ServerContext } from '../context.js';
import { narrowsAccessOnly } from '../invariants.js';
import type { ExpiryReminderMark } from '../models.js';
import { OperationDenied } from '../operations.js';
import type { ResolvedResource } from '../options.js';
import { actsInOwnRight } from '../session-kinds.js';
import { hash, id } from '../utils.js';
import { email, integer, object, text } from '../validation.js';

// --- public shapes ---------------------------------------------------------------------------------

/** A built-in starting point for a scheme (`clearances.templates`). */
export interface ClassificationTemplateView {
  id: ClassificationTemplateName;
  name: string;
  definition: ClassificationSchemeDefinition;
}

/** What `defineScheme` accepts; `updateScheme` takes the same fields, each optional (null clears an optional one). */
export interface ClassificationSchemeInput {
  name: string;
  /** Start from a built-in template; give either this or `definition`. */
  template?: ClassificationTemplateName;
  definition?: ClassificationSchemeDefinition;
  /** Resource types that must carry a label (`*`: every application type). */
  requireLabels?: string[];
  defaultLabel?: ClassificationLabel | null;
  /** Level id guests count at most at; null (the default) means guests hold no clearance. */
  guestCeiling?: string | null;
  interimAllowed?: boolean;
  /** `within-own` (the default) or `unrestricted`. */
  adjudication?: AdjudicationMode;
  /** Extra recipients of clearance reminders besides the owners. */
  notify?: { emails: string[] } | null;
}

/** A tenant's scheme as `getScheme`, `defineScheme` and `updateScheme` return it. */
export interface ClassificationSchemeView {
  /** The defining tenant: the scheme applies to it and every tenant below it. */
  tenantId: string;
  /** True when an ancestor of the asking tenant defines it (change it there). */
  inherited: boolean;
  name: string;
  definition: ClassificationSchemeDefinition;
  requireLabels: string[];
  defaultLabel?: ClassificationLabel;
  guestCeiling: string | null;
  interimAllowed: boolean;
  adjudication: AdjudicationMode;
  notify?: { emails: string[] };
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
  version: number;
}

export interface ClearanceGrantInput {
  tenantId: string;
  identityId: string;
  /** A level id of the scheme in force. */
  level: string;
  /** Adjudicated citizenship, ISO 3166-1 alpha-3 codes in upper case (at most 10; may be empty). */
  citizenship: string[];
  /** Grants an interim clearance (the scheme must allow interim clearances). */
  interim?: boolean;
  investigation?: { kind: string; completedAt: number };
  reinvestigationDue?: number;
  expiresAt?: number;
}

export interface ClearanceUpdateInput {
  tenantId: string;
  identityId: string;
  level?: string;
  citizenship?: string[];
  /** true makes the clearance interim, false final (active). */
  interim?: boolean;
  investigation?: { kind: string; completedAt: number } | null;
  reinvestigationDue?: number | null;
  expiresAt?: number | null;
}

/** One read-in as officers see it. */
export interface ClearanceReadInView {
  compartmentId: string;
  /** The compartment's name in the scheme (absent once the scheme no longer has it). */
  compartmentName?: string;
  readInAt: number;
  readInBy: string;
  agreementId?: string;
  acceptedAt?: number;
  /** Whether the read-in counts right now: the compartment exists and any NDA has a current acceptance. */
  current: boolean;
}

/** A clearance as officers see it (`get`, `list` and the mutations). */
export interface ClearanceView {
  identityId: string;
  identity: {
    id: string;
    name: string;
    email?: string;
    kind: Identity['kind'];
    status: Identity['status'];
    guest: boolean;
  };
  schemeTenantId: string;
  level: { id: string; name?: string; rank?: number };
  status: ClearanceStatus;
  /** What decisions see right now. */
  effectiveStatus: EffectiveClearanceStatus;
  /** The level decisions count (a guest's is capped); absent when the clearance does not count. */
  effectiveLevel?: string;
  citizenship: string[];
  investigation?: { kind: string; completedAt: number };
  reinvestigationDue?: number;
  expiresAt?: number;
  readIns: ClearanceReadInView[];
  grantedAt: number;
  grantedBy: string;
  updatedAt: number;
  updatedBy: string;
  suspended?: { by: string; at: number; reason: string; incidentId?: string };
  revoked?: { by: string; at: number; reason: string };
  terminated?: { by: string; at: number; reason: string };
}

export interface ClearancePage {
  clearances: ClearanceView[];
  total: number;
}

/** The caller's own clearance (`clearances.mine`). */
export interface MyClearance {
  scheme: { tenantId: string; name: string; levels: ClassificationLevel[] } | null;
  clearance: {
    level: { id: string; name?: string };
    status: ClearanceStatus;
    effectiveStatus: EffectiveClearanceStatus;
    effectiveLevel?: string;
    citizenship: string[];
    reinvestigationDue?: number;
    expiresAt?: number;
    readIns: Array<{
      compartmentId: string;
      compartmentName?: string;
      agreementId?: string;
      /** False while the compartment's NDA still needs accepting (or re-accepting). */
      current: boolean;
    }>;
  } | null;
}

/** One party of a decision as `explain` reports it. */
export interface ClearancePartyView {
  identityId: string;
  status: EffectiveClearanceStatus;
  level?: string;
  rank: number;
  compartments: string[];
  citizenship: string[];
}

/** Why a person may or may not read a resource (`clearances.explain`, officers only). */
export interface ClearanceExplanation {
  allowed: boolean;
  /** The dimension the first refused party failed; `invalid-label` also for a missing required label. */
  failure?: DominanceFailure;
  /** The label decisions apply (after inheritance, the resolver and the default); null when unlabeled. */
  label: ClassificationLabel | null;
  /** The party that failed, or the person when every party passes. */
  party: ClearancePartyView;
  /** Every party of the person's own sessions (an agent's sponsor too). */
  parties: ClearancePartyView[];
}

/** An IAM-held label. */
export interface ResourceLabelView {
  type: string;
  id: string;
  label: ClassificationLabel;
  levelName?: string;
  inheritToChildren: boolean;
  labeledBy: string;
  labeledAt: number;
  version: number;
}

export interface ResourceLabelPage {
  labels: ResourceLabelView[];
  total: number;
}

/** What `getLabel` returns: the resource's own IAM label and what it inherits from managed parents. */
export interface ResourceLabelState {
  type: string;
  id: string;
  label: ResourceLabelView | null;
  /** The join of the labels its managed ancestors pass down (`inheritToChildren`). */
  inherited: ClassificationLabel | null;
}

export interface ClearanceReminderResult {
  /** One entry per clearance reminded, with how many addresses were emailed. */
  sent: Array<{ tenantId: string; identityId: string; dueAt: number; recipients: number }>;
  skipped: {
    /** Tenants not active. */
    inactive: number;
    /** Clearances with something due but nobody to tell (no owner or notify address). */
    noRecipients: number;
  };
}

/** Clearances, server side. */
export interface IamClearances {
  /**
   * Emails the owners of each scheme's defining tenant and the scheme's `notify.emails` (template `clearance-reminder`,
   * naming the level only, never compartments) about clearances whose periodic reinvestigation is due or whose end
   * (interim or final) falls within `withinDays` (default 60): each date once. `tenantId` limits the run to the
   * clearances held in that tenant. Requires an email delivery callback and the `clearances` option.
   */
  sendReminders(input?: {
    tenantId?: string;
    withinDays?: number;
  }): Promise<ClearanceReminderResult>;
}

// --- validation ------------------------------------------------------------------------------------

const templateNames: Record<ClassificationTemplateName, string> = {
  us: 'United States',
  uk: 'United Kingdom',
  nato: 'NATO',
  corporate: 'Corporate',
};
const adjudicationModes: ReadonlySet<string> = new Set<AdjudicationMode>([
  'within-own',
  'unrestricted',
]);
const clearanceStatuses: ReadonlySet<string> = new Set<ClearanceStatus>([
  'interim',
  'active',
  'suspended',
  'revoked',
  'terminated',
]);
/** Statuses of a clearance that is in force or can be again (by reinstatement). */
const liveStatuses: ReadonlySet<string> = new Set<ClearanceStatus>([
  'interim',
  'active',
  'suspended',
]);
const countryPattern = /^[A-Z]{3}$/;
const yearMs = 365 * 86_400_000;
const dayMs = 86_400_000;

const clearanceResource = (identityId: unknown) => `clearances/${text(identityId, 'identityId')}`;
const schemeResource = 'classifications/scheme';
/**
 * `classifications/labels/{type}/{id}`. Too long to authorize as one resource id, the id becomes `sha256:{hex}` (so
 * per-type policy patterns keep working), and with a very long type the whole name does.
 */
function labelResource(type: string, resourceId: string): string {
  const plain = `classifications/labels/${type}/${resourceId}`;
  if (plain.length <= 256) return plain;
  const typed = `classifications/labels/${type}/sha256:${hash(resourceId)}`;
  return typed.length <= 256
    ? typed
    : `classifications/labels/sha256:${hash(`${type}/${resourceId}`)}`;
}

function flag(value: unknown, name: string): boolean | undefined {
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new IamError('INVALID_INPUT', `${name} must be a boolean`);
  return value;
}

function citizenshipList(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > clearanceLimits.maxCitizenship)
    throw new IamError(
      'INVALID_INPUT',
      `citizenship must list at most ${clearanceLimits.maxCitizenship} countries`,
    );
  const countries = new Set<string>();
  for (const country of value) {
    if (typeof country !== 'string' || !countryPattern.test(country))
      throw new IamError(
        'INVALID_INPUT',
        'citizenship must hold ISO 3166-1 alpha-3 codes in upper case',
      );
    countries.add(country);
  }
  return [...countries].sort();
}

/** A resource type that can carry a label: any type but the platform's own. */
function labelType(value: unknown): string {
  const type = text(value, 'type');
  if (reservedResourceTypes.has(type))
    throw new IamError('INVALID_INPUT', 'Platform resource types cannot be labeled');
  return type;
}

function requiredTypes(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > clearanceLimits.maxRequiredTypes)
    throw new IamError(
      'INVALID_INPUT',
      `requireLabels must list at most ${clearanceLimits.maxRequiredTypes} resource types`,
    );
  return [...new Set(value.map((type) => (type === '*' ? '*' : labelType(type))))].sort();
}

function notifyEmails(value: unknown): { emails: string[] } | undefined {
  if (value === null) return undefined;
  const input = object(value);
  if (!Array.isArray(input.emails) || input.emails.length > clearanceLimits.maxNotifyEmails)
    throw new IamError(
      'INVALID_INPUT',
      `notify.emails must list at most ${clearanceLimits.maxNotifyEmails} addresses`,
    );
  const emails = [...new Set(input.emails.map((address) => email(address)))].sort();
  return emails.length ? { emails } : undefined;
}

/** The settings of a scheme over `previous`, checked against `definition`. */
function schemeSettings(
  input: Partial<ClassificationSchemeInput>,
  definition: ClassificationSchemeDefinition,
  previous?: ClassificationScheme,
) {
  const name = input.name !== undefined ? text(input.name, 'name', 100).trim() : previous?.name;
  if (!name) throw new IamError('INVALID_INPUT', 'name is required');
  const requireLabels =
    input.requireLabels !== undefined
      ? requiredTypes(input.requireLabels)
      : (previous?.requireLabels ?? []);
  let defaultLabel: ClassificationLabel | undefined;
  if (input.defaultLabel === undefined) {
    defaultLabel = previous?.defaultLabel;
    if (defaultLabel && !isValidClassificationLabel(defaultLabel, definition))
      throw new IamError(
        'INVALID_INPUT',
        'The default label is not valid under the new definition; set a new defaultLabel or null',
      );
    if (defaultLabel) defaultLabel = validateLabel(defaultLabel, definition);
  } else if (input.defaultLabel !== null)
    defaultLabel = validateLabel(input.defaultLabel, definition);
  const guestCeiling =
    input.guestCeiling === undefined ? (previous?.guestCeiling ?? null) : input.guestCeiling;
  if (guestCeiling !== null && !schemeLevel({ definition }, guestCeiling as string))
    throw new IamError('INVALID_INPUT', 'guestCeiling must be a level id of the scheme, or null');
  const interimAllowed =
    flag(input.interimAllowed, 'interimAllowed') ?? previous?.interimAllowed ?? false;
  const adjudication = input.adjudication ?? previous?.adjudication ?? 'within-own';
  if (!adjudicationModes.has(adjudication))
    throw new IamError('INVALID_INPUT', 'adjudication must be within-own or unrestricted');
  const notify = input.notify === undefined ? previous?.notify : notifyEmails(input.notify);
  return {
    name,
    requireLabels,
    ...(defaultLabel ? { defaultLabel } : {}),
    guestCeiling: guestCeiling as string | null,
    interimAllowed,
    adjudication,
    ...(notify ? { notify } : {}),
  };
}

function schemeView(
  scheme: ClassificationScheme,
  askingTenantId: string,
): ClassificationSchemeView {
  return {
    tenantId: scheme.tenantId,
    inherited: scheme.tenantId !== askingTenantId,
    name: scheme.name,
    definition: scheme.definition,
    requireLabels: [...scheme.requireLabels],
    ...(scheme.defaultLabel ? { defaultLabel: scheme.defaultLabel } : {}),
    guestCeiling: scheme.guestCeiling,
    interimAllowed: scheme.interimAllowed,
    adjudication: scheme.adjudication,
    ...(scheme.notify ? { notify: { emails: [...scheme.notify.emails] } } : {}),
    createdAt: scheme.createdAt,
    createdBy: scheme.createdBy,
    updatedAt: scheme.updatedAt,
    updatedBy: scheme.updatedBy,
    version: scheme.version,
  };
}

function labelView(
  stored: ResourceLabel,
  scheme: ClassificationScheme | undefined,
): ResourceLabelView {
  const level = scheme ? schemeLevel(scheme, stored.label.level) : undefined;
  return {
    type: stored.type,
    id: stored.resourceId,
    label: stored.label,
    ...(level ? { levelName: level.name } : {}),
    inheritToChildren: stored.inheritToChildren,
    labeledBy: stored.labeledBy,
    labeledAt: stored.labeledAt,
    version: stored.version,
  };
}

/** Audit metadata for a label: level and compartment ids, never names. */
function labelMetadata(label: ClassificationLabel): Record<string, Json> {
  return {
    level: label.level,
    ...(label.compartments?.length ? { compartments: [...label.compartments] } : {}),
    ...(label.noforn ? { noforn: true } : {}),
    ...(label.releasableTo ? { releasableTo: [...label.releasableTo] } : {}),
  };
}

function partyView(state: PartyState): ClearancePartyView {
  return {
    identityId: state.party.identityId,
    status: state.status,
    ...(state.level && state.party.rank >= 0 ? { level: state.level.id } : {}),
    rank: state.party.rank,
    compartments: [...state.party.compartments].sort(),
    citizenship: [...state.party.citizenship].sort(),
  };
}

const iso = (at: number) => new Date(at).toISOString();

// --- the API ---------------------------------------------------------------------------------------

/**
 * Security clearances and classification labels (the `clearances` option; FEATURE_DISABLED otherwise). Schemes:
 * `templates` (no permission), `getScheme` (iam:clearances:read), `defineScheme` / `updateScheme`
 * (iam:classifications:manage, recent sign-in) on `iam/classifications/scheme`. Clearances on
 * `iam/clearances/{identityId}`: `grant`, `update`, `readIn`, `reinstate`, `revoke` (iam:clearances:adjudicate, recent
 * sign-in), `debrief` (adjudicate), `suspend` (iam:clearances:suspend, usable in an incident), `get` / `list`
 * (iam:clearances:read), `explain` (adjudicate), and `mine` (no permission). Nobody adjudicates their own clearance, not
 * even an owner or root; under `within-own` adjudication an officer grants only levels and compartments their own
 * clearance holds (an owner or root may bootstrap a level or compartment nobody in the scheme's subtree holds yet).
 * Labels on `iam/classifications/labels/{type}/{id}`: `label` raises (iam:classifications:label), `declassify` lowers or
 * removes (iam:classifications:declassify, recent sign-in, and the caller's own clearance must dominate the current
 * label), `getLabel` / `listLabels` (iam:clearances:read).
 */
export function createClearancesApi(ctx: ServerContext) {
  const { operation } = ctx.operations;

  /**
   * Runs `fn` only when the deployment enables clearances (FEATURE_DISABLED otherwise). Input it validates before
   * its first await (resource ids) rejects the promise too, rather than throwing at the call.
   */
  const enabled = <T>(fn: () => Promise<T>): Promise<T> => {
    try {
      assertClearances(ctx);
      return fn();
    } catch (error) {
      return Promise.reject(error);
    }
  };

  /** The scheme in force for a tenant; NOT_FOUND when none applies. */
  async function schemeIn(tx: IamStore, tenant: Tenant): Promise<ClassificationScheme> {
    const scheme = await effectiveScheme(tx, await ctx.ancestry(tx, tenant));
    if (!scheme)
      throw new IamError('NOT_FOUND', 'No classification scheme applies to this organization', 404);
    return scheme;
  }

  function noImpersonation(principal: AuthenticatedPrincipal): void {
    if (principal.session.impersonatorId)
      throw new IamError(
        'IMPERSONATION_RESTRICTED',
        'Clearances and labels cannot be changed while impersonating',
        403,
      );
  }

  /**
   * The officer acting: never while impersonating, never a guest, never on their own clearance (`subject`), whatever
   * their role (owners and root included). Returns their parties' clearances in the tenant, for `within-own`.
   */
  async function officer(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    scheme: ClassificationScheme,
    subject: Identity | undefined,
  ): Promise<{ states: PartyState[]; root: boolean }> {
    noImpersonation(principal);
    if (principal.identity.guest !== undefined && principal.identity.tenantId === tenant.id)
      throw new OperationDenied('Guests cannot adjudicate clearances');
    const root = await ctx.rootPrincipal(tx, principal);
    const scope = await agentDecisionScope(tx, principal, ctx.now());
    const states = await sessionParties(tx, principal, tenant, scope, scheme, ctx.now(), root);
    if (subject) {
      const self = new Set<string>([
        principal.identity.id,
        ...states.map((s) => s.party.identityId),
      ]);
      if (typeof principal.session.agentId === 'string') self.add(principal.session.agentId);
      if (typeof principal.session.originalIdentityId === 'string')
        self.add(principal.session.originalIdentityId);
      if (self.has(subject.id))
        throw new OperationDenied('Your own clearance is adjudicated by another officer');
    }
    return { states, root };
  }

  /**
   * Whether an active clearance of the scheme's subtree (people of active, unexpired accounts; guests do not count)
   * holds at least `need.rank`, or is read into `need.compartmentId`.
   */
  async function heldInSubtree(
    tx: IamStore,
    scheme: ClassificationScheme,
    need: { rank?: number; compartmentId?: string },
  ): Promise<boolean> {
    const now = ctx.now();
    for (const record of await tx.find<Clearance>(clearanceCollections.clearances, {
      schemeTenantId: scheme.tenantId,
      status: 'active',
    })) {
      if (record.schemeTenantId !== scheme.tenantId || record.status !== 'active') continue;
      if (typeof record.expiresAt === 'number' && record.expiresAt <= now) continue;
      if (need.rank !== undefined) {
        const level = schemeLevel(scheme, record.level);
        if (!level || level.rank < need.rank) continue;
      } else if (!(record.readIns ?? []).some((item) => item.compartmentId === need.compartmentId))
        continue;
      const holder = await tx.get<Identity>('identities', record.identityId);
      if (
        !holder ||
        holder.tenantId !== record.tenantId ||
        holder.status !== 'active' ||
        holder.guest !== undefined ||
        (typeof holder.expiresAt === 'number' && holder.expiresAt <= now)
      )
        continue;
      return true;
    }
    return false;
  }

  /**
   * `within-own` adjudication: every party of the officer must hold `need.rank` (or be read into `need.compartmentId`).
   * The bootstrap exception lets an owner of the tenant or root grant it when nobody in the scheme's subtree holds it
   * yet. Returns true for a bootstrap grant (audited as such); refuses (audited denial) otherwise.
   */
  async function withinOwn(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    scheme: ClassificationScheme,
    acting: { states: PartyState[]; root: boolean },
    need: { rank: number } | { compartmentId: string },
  ): Promise<boolean> {
    if (scheme.adjudication === 'unrestricted') return false;
    const covered =
      acting.states.length > 0 &&
      acting.states.every((state) =>
        'rank' in need
          ? state.party.rank >= need.rank
          : state.party.rank >= 0 && state.party.compartments.has(need.compartmentId),
      );
    if (covered) return false;
    const owner =
      principal.session.kind === 'user' &&
      principal.identity.owner &&
      principal.identity.tenantId === tenant.id &&
      principal.session.tenantId === tenant.id;
    if ((owner || acting.root) && !(await heldInSubtree(tx, scheme, need))) return true;
    throw new OperationDenied(
      'Under within-own adjudication an officer grants only what their own clearance holds',
    );
  }

  /** A level of the scheme by id (INVALID_INPUT otherwise). */
  function levelOf(scheme: ClassificationScheme, value: unknown): ClassificationLevel {
    const level = schemeLevel(scheme, text(value, 'level', 64));
    if (!level) throw new IamError('INVALID_INPUT', 'level must be a level id of the scheme');
    return level;
  }

  /** Guests hold at most the scheme's guest ceiling, and nothing when it sets none. */
  function assertGuestLevel(
    scheme: ClassificationScheme,
    identity: Identity,
    level: ClassificationLevel,
  ): void {
    if (identity.guest === undefined) return;
    const ceiling = schemeLevel(scheme, scheme.guestCeiling);
    if (!ceiling) throw new IamError('INVALID_INPUT', 'Guests hold no clearance under this scheme');
    if (level.rank > ceiling.rank)
      throw new IamError('INVALID_INPUT', 'Guests hold at most the scheme’s guest ceiling');
  }

  function investigationOf(value: unknown): { kind: string; completedAt: number } {
    const input = object(value);
    const completedAt = integer(
      input.completedAt,
      'investigation.completedAt',
      0,
      ctx.now() + dayMs,
    );
    return { kind: text(input.kind, 'investigation.kind', 64).trim(), completedAt };
  }
  function dueOf(value: unknown): number {
    const at = integer(value, 'reinvestigationDue', 0, Number.MAX_SAFE_INTEGER);
    if (at > ctx.now() + 20 * yearMs)
      throw new IamError('INVALID_INPUT', 'reinvestigationDue must be within twenty years');
    return at;
  }
  function endOf(value: unknown): number {
    const at = integer(value, 'expiresAt', 0, Number.MAX_SAFE_INTEGER);
    if (at <= ctx.now()) throw new IamError('INVALID_INPUT', 'expiresAt must be in the future');
    if (at > ctx.now() + 20 * yearMs)
      throw new IamError('INVALID_INPUT', 'expiresAt must be within twenty years');
    return at;
  }

  /** The record of a live (interim, active or suspended) clearance issued under the scheme in force. */
  async function liveRecord(
    tx: IamStore,
    identity: Identity,
    scheme: ClassificationScheme,
  ): Promise<Clearance> {
    const record = await readClearance(tx, identity);
    if (!record || !liveStatuses.has(record.status))
      throw new IamError('NOT_FOUND', 'This identity holds no clearance', 404);
    if (record.schemeTenantId !== scheme.tenantId)
      throw new IamError(
        'CONFLICT',
        'This clearance was issued under another scheme; revoke it and grant a new one',
        409,
      );
    return record;
  }

  async function clearanceView(
    tx: IamStore,
    record: Clearance,
    scheme: ClassificationScheme | undefined,
    identity?: Identity,
  ): Promise<ClearanceView> {
    const person = identity ?? (await tx.get<Identity>('identities', record.identityId));
    const now = ctx.now();
    const state = scheme
      ? await partyState(tx, scheme, person, record.identityId, record.tenantId, now)
      : undefined;
    const level = scheme ? schemeLevel(scheme, record.level) : undefined;
    const compartments = new Map(
      (scheme?.definition.compartments ?? []).map((compartment) => [
        compartment.id,
        compartment.name,
      ]),
    );
    const readIns: ClearanceReadInView[] = [];
    for (const readIn of record.readIns ?? [])
      readIns.push({
        compartmentId: readIn.compartmentId,
        ...(compartments.has(readIn.compartmentId)
          ? { compartmentName: compartments.get(readIn.compartmentId)! }
          : {}),
        readInAt: readIn.readInAt,
        readInBy: readIn.readInBy,
        ...(readIn.agreementId !== undefined ? { agreementId: readIn.agreementId } : {}),
        ...(readIn.acceptedAt !== undefined ? { acceptedAt: readIn.acceptedAt } : {}),
        current: await readInCurrent(
          tx,
          record,
          readIn.compartmentId,
          readIn.agreementId,
          compartments,
        ),
      });
    return {
      identityId: record.identityId,
      identity: {
        id: record.identityId,
        name: person?.name ?? record.identityId,
        ...(person?.email ? { email: person.email } : {}),
        kind: person?.kind ?? 'user',
        status: person?.status ?? 'deleted',
        guest: person?.guest !== undefined,
      },
      schemeTenantId: record.schemeTenantId,
      level: {
        id: record.level,
        ...(level ? { name: level.name, rank: level.rank } : {}),
      },
      status: record.status,
      effectiveStatus: state?.status ?? 'none',
      ...(state?.level && state.party.rank >= 0 ? { effectiveLevel: state.level.id } : {}),
      citizenship: [...(record.citizenship ?? [])],
      ...(record.investigation ? { investigation: { ...record.investigation } } : {}),
      ...(record.reinvestigationDue !== undefined
        ? { reinvestigationDue: record.reinvestigationDue }
        : {}),
      ...(record.expiresAt !== undefined ? { expiresAt: record.expiresAt } : {}),
      readIns,
      grantedAt: record.grantedAt,
      grantedBy: record.grantedBy,
      updatedAt: record.updatedAt,
      updatedBy: record.updatedBy,
      ...(record.suspended
        ? {
            suspended: {
              by: record.suspended.by,
              at: record.suspended.at,
              reason: record.suspended.reason,
              ...(record.suspended.incidentId !== undefined
                ? { incidentId: record.suspended.incidentId }
                : {}),
            },
          }
        : {}),
      ...(record.revoked ? { revoked: { ...record.revoked } } : {}),
      ...(record.terminated ? { terminated: { ...record.terminated } } : {}),
    };

    async function readInCurrent(
      store: IamStore,
      owner: Clearance,
      compartmentId: string,
      agreementId: string | undefined,
      known: Map<string, string>,
    ): Promise<boolean> {
      if (!known.has(compartmentId)) return false;
      if (agreementId === undefined) return true;
      const agreement = await store.get<Agreement>('agreements', agreementId);
      const acceptance = await store.get<AgreementAcceptance>(
        'agreementAcceptances',
        `${agreementId}:${owner.identityId}`,
      );
      return (
        agreement?.tenantId === owner.tenantId &&
        acceptance?.tenantId === owner.tenantId &&
        acceptanceCurrent(agreement, acceptance, now)
      );
    }
  }

  /** The labels' scheme: the one in force for the tenant (NOT_FOUND when none). */
  async function labelTarget(
    tx: IamStore,
    tenant: Tenant,
    input: { type: unknown; id: unknown },
  ): Promise<{ scheme: ClassificationScheme; type: string; resourceId: string }> {
    const type = labelType(input.type);
    const resourceId = text(input.id, 'id');
    return { scheme: await schemeIn(tx, tenant), type, resourceId };
  }

  return {
    /** The built-in scheme templates (us, uk, nato, corporate); any signed-in caller. */
    templates: (credential: CredentialInput): Promise<ClassificationTemplateView[]> =>
      enabled(async () => {
        await ctx.principals.authenticate(credential);
        return (Object.keys(templateNames) as ClassificationTemplateName[]).map((name) => ({
          id: name,
          name: templateNames[name],
          definition: validateScheme(classificationTemplates[name]),
        }));
      }),
    /**
     * The scheme in force for the tenant and where it is defined (`inherited` when an ancestor defines it), or null.
     * Requires iam:clearances:read.
     */
    getScheme: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<ClassificationSchemeView | null> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:read',
          schemeResource,
          async ({ tx, tenant }) => {
            const scheme = await effectiveScheme(tx, await ctx.ancestry(tx, tenant));
            return scheme ? schemeView(scheme, tenant.id) : null;
          },
        ),
      ),
    /**
     * Defines the tenant's classification scheme from a `template` or a `definition`. CONFLICT when the tenant, an
     * ancestor or a tenant below it already defines one (the scheme closest to the root is in force for its whole
     * subtree). Requires iam:classifications:manage and a recent sign-in; audited as `classification:scheme-define`.
     */
    defineScheme: (
      credential: CredentialInput,
      input: ClassificationSchemeInput & { tenantId: string },
    ): Promise<ClassificationSchemeView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:classifications:manage',
          schemeResource,
          async ({ tx, principal, tenant }) => {
            ctx.auth.requireRecent(principal);
            if ((input.template === undefined) === (input.definition === undefined))
              throw new IamError('INVALID_INPUT', 'Give either a template or a definition');
            let definition: ClassificationSchemeDefinition;
            if (input.template !== undefined) {
              if (!Object.hasOwn(templateNames, input.template))
                throw new IamError('INVALID_INPUT', 'template must be us, uk, nato or corporate');
              definition = validateScheme(classificationTemplates[input.template]);
            } else definition = validateScheme(input.definition);
            const settings = schemeSettings(input, definition);
            for (const realm of await ctx.ancestry(tx, tenant))
              if (await definedScheme(tx, realm.id))
                throw new IamError(
                  'CONFLICT',
                  realm.id === tenant.id
                    ? 'This tenant already defines a classification scheme'
                    : 'An ancestor tenant defines the classification scheme in force here',
                  409,
                );
            for (const other of await tx.find<ClassificationScheme>(clearanceCollections.schemes))
              if ((await ctx.ancestorIds(tx, other.tenantId)).includes(tenant.id))
                throw new IamError(
                  'CONFLICT',
                  'A tenant below this one defines its own classification scheme',
                  409,
                );
            const now = ctx.now();
            const scheme = await tx.insert<ClassificationScheme>(clearanceCollections.schemes, {
              id: id(),
              tenantId: tenant.id,
              uniqueKey: 'scheme',
              definition,
              ...settings,
              createdAt: now,
              createdBy: principal.identity.id,
              updatedAt: now,
              updatedBy: principal.identity.id,
              version: 1,
            });
            await ctx.events.audit(
              tx,
              principal,
              'classification:scheme-define',
              tenant.id,
              scheme.id,
              'allow',
              false,
              {
                ...(input.template !== undefined ? { template: input.template } : {}),
                levels: definition.levels.map((level) => level.id),
                compartments: definition.compartments.map((compartment) => compartment.id),
                requireLabels: settings.requireLabels,
                guestCeiling: settings.guestCeiling,
                interimAllowed: settings.interimAllowed,
                adjudication: settings.adjudication,
              },
            );
            return schemeView(scheme, tenant.id);
          },
        ),
      ),
    /**
     * Changes the scheme this tenant defines (an inherited one is changed where it is defined: CONFLICT). New levels go
     * above every remaining level; a level or compartment that a live clearance or a label uses cannot be removed or
     * re-ranked, and every label must stay valid (RESOURCE_IN_USE). Settings change freely. `version` (optional) must
     * match the stored one. Requires iam:classifications:manage and a recent sign-in; audited as
     * `classification:scheme-update`.
     */
    updateScheme: (
      credential: CredentialInput,
      input: Partial<ClassificationSchemeInput> & { tenantId: string; version?: number },
    ): Promise<ClassificationSchemeView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:classifications:manage',
          schemeResource,
          async ({ tx, principal, tenant }) => {
            ctx.auth.requireRecent(principal);
            if (input.template !== undefined)
              throw new IamError(
                'INVALID_INPUT',
                'Templates start a scheme; change it with definition',
              );
            const scheme = await definedScheme(tx, tenant.id);
            if (!scheme) {
              if (await effectiveScheme(tx, await ctx.ancestry(tx, tenant)))
                throw new IamError(
                  'CONFLICT',
                  'The scheme in force here is defined by an ancestor tenant; change it there',
                  409,
                );
              throw new IamError('NOT_FOUND', 'This tenant defines no classification scheme', 404);
            }
            if (input.version !== undefined && input.version !== scheme.version)
              throw new IamError('VERSION_CONFLICT', 'The scheme changed; reload it first', 409);
            const definition =
              input.definition !== undefined ? validateScheme(input.definition) : scheme.definition;
            const settings = schemeSettings(input, definition, scheme);
            if (input.definition !== undefined)
              await assertDefinitionChange(tx, scheme, definition);
            const changed = [
              ...(input.definition !== undefined ? ['definition'] : []),
              ...(
                [
                  'name',
                  'requireLabels',
                  'defaultLabel',
                  'guestCeiling',
                  'interimAllowed',
                  'adjudication',
                  'notify',
                ] as const
              ).filter((field) => input[field] !== undefined),
            ];
            const now = ctx.now();
            const { defaultLabel: _defaultLabel, notify: _notify, ...kept } = scheme;
            const next = await tx.put<ClassificationScheme>(clearanceCollections.schemes, {
              ...kept,
              definition,
              ...settings,
              updatedAt: now,
              updatedBy: principal.identity.id,
              version: scheme.version + 1,
            });
            await ctx.events.audit(
              tx,
              principal,
              'classification:scheme-update',
              tenant.id,
              scheme.id,
              'allow',
              false,
              {
                changed,
                version: next.version,
                ...(input.definition !== undefined
                  ? {
                      levels: definition.levels.map((level) => level.id),
                      compartments: definition.compartments.map((compartment) => compartment.id),
                      ownerCountries: [...definition.ownerCountries],
                    }
                  : {}),
                ...(input.guestCeiling !== undefined
                  ? { guestCeiling: settings.guestCeiling }
                  : {}),
                ...(input.adjudication !== undefined
                  ? { adjudication: settings.adjudication }
                  : {}),
                ...(input.interimAllowed !== undefined
                  ? { interimAllowed: settings.interimAllowed }
                  : {}),
              },
            );
            return schemeView(next, tenant.id);
          },
        ),
      ),
    /**
     * Grants a clearance under the scheme in force: a level, adjudicated citizenship, optionally interim, the
     * investigation and its dates. CONFLICT when the identity already holds a live one (use `update`). Guests are held
     * to the guest ceiling. Never your own; under `within-own` only within the officer's own clearance (bootstrap
     * aside). Requires iam:clearances:adjudicate and a recent sign-in; audited as `clearance:grant`.
     */
    grant: (credential: CredentialInput, input: ClearanceGrantInput): Promise<ClearanceView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:adjudicate',
          clearanceResource(input.identityId),
          async ({ tx, principal, tenant }) => {
            ctx.auth.requireRecent(principal);
            const scheme = await schemeIn(tx, tenant);
            const identity = await ctx.activeIdentity(tx, input.identityId, tenant.id);
            if (identity.status !== 'active')
              throw new IamError('INVALID_INPUT', 'Only active identities are granted clearances');
            const acting = await officer(tx, principal, tenant, scheme, identity);
            const level = levelOf(scheme, input.level);
            assertGuestLevel(scheme, identity, level);
            const interim = flag(input.interim, 'interim') ?? false;
            if (interim && !scheme.interimAllowed)
              throw new IamError('INVALID_INPUT', 'This scheme does not allow interim clearances');
            const citizenship = citizenshipList(input.citizenship);
            const investigation =
              input.investigation !== undefined ? investigationOf(input.investigation) : undefined;
            const reinvestigationDue =
              input.reinvestigationDue !== undefined ? dueOf(input.reinvestigationDue) : undefined;
            const expiresAt = input.expiresAt !== undefined ? endOf(input.expiresAt) : undefined;
            const existing = await readClearance(tx, identity);
            if (existing && liveStatuses.has(existing.status))
              throw new IamError(
                'CONFLICT',
                'This identity already holds a clearance; change it with update',
                409,
              );
            const bootstrap = await withinOwn(tx, principal, tenant, scheme, acting, {
              rank: level.rank,
            });
            const now = ctx.now();
            const record: Clearance = {
              id: identity.id,
              tenantId: tenant.id,
              uniqueKey: `identity:${identity.id}`,
              identityId: identity.id,
              schemeTenantId: scheme.tenantId,
              level: level.id,
              citizenship,
              status: interim ? 'interim' : 'active',
              ...(investigation ? { investigation } : {}),
              ...(reinvestigationDue !== undefined ? { reinvestigationDue } : {}),
              ...(expiresAt !== undefined ? { expiresAt } : {}),
              readIns: [],
              grantedAt: now,
              grantedBy: principal.identity.id,
              updatedAt: now,
              updatedBy: principal.identity.id,
            };
            const saved = existing
              ? await tx.put<Clearance>(clearanceCollections.clearances, record)
              : await tx.insert<Clearance>(clearanceCollections.clearances, record);
            await ctx.events.audit(
              tx,
              principal,
              'clearance:grant',
              tenant.id,
              identity.id,
              'allow',
              false,
              {
                level: level.id,
                status: saved.status,
                ...(expiresAt !== undefined ? { expiresAt } : {}),
                ...(bootstrap ? { bootstrap: true } : {}),
              },
            );
            return clearanceView(tx, saved, scheme, identity);
          },
        ),
      ),
    /**
     * Changes a live clearance: level, citizenship, interim or final, investigation and dates (null clears one). The
     * same rules as `grant` apply to the higher of the old and the new level. Requires iam:clearances:adjudicate and a
     * recent sign-in; audited as `clearance:update`.
     */
    update: (credential: CredentialInput, input: ClearanceUpdateInput): Promise<ClearanceView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:adjudicate',
          clearanceResource(input.identityId),
          async ({ tx, principal, tenant }) => {
            ctx.auth.requireRecent(principal);
            const scheme = await schemeIn(tx, tenant);
            const identity = await ctx.activeIdentity(tx, input.identityId, tenant.id);
            const acting = await officer(tx, principal, tenant, scheme, identity);
            const record = await liveRecord(tx, identity, scheme);
            const previous = schemeLevel(scheme, record.level);
            const level =
              input.level !== undefined
                ? levelOf(scheme, input.level)
                : (previous ??
                  (() => {
                    throw new IamError(
                      'INVALID_INPUT',
                      'The clearance’s level left the scheme; set a level',
                    );
                  })());
            assertGuestLevel(scheme, identity, level);
            const next: Clearance = { ...record, level: level.id };
            const changed: string[] = [];
            if (level.id !== record.level) changed.push('level');
            if (input.citizenship !== undefined) {
              next.citizenship = citizenshipList(input.citizenship);
              changed.push('citizenship');
            }
            const interim = flag(input.interim, 'interim');
            if (interim !== undefined) {
              if (interim && !scheme.interimAllowed)
                throw new IamError(
                  'INVALID_INPUT',
                  'This scheme does not allow interim clearances',
                );
              const status = interim ? 'interim' : 'active';
              if (record.status === 'suspended' && record.suspended)
                next.suspended = { ...record.suspended, previousStatus: status };
              else next.status = status;
              changed.push('interim');
            }
            if (input.investigation !== undefined) {
              if (input.investigation === null) delete next.investigation;
              else next.investigation = investigationOf(input.investigation);
              changed.push('investigation');
            }
            if (input.reinvestigationDue !== undefined) {
              if (input.reinvestigationDue === null) delete next.reinvestigationDue;
              else next.reinvestigationDue = dueOf(input.reinvestigationDue);
              changed.push('reinvestigationDue');
            }
            if (input.expiresAt !== undefined) {
              if (input.expiresAt === null) delete next.expiresAt;
              else next.expiresAt = endOf(input.expiresAt);
              changed.push('expiresAt');
            }
            if (!changed.length) return clearanceView(tx, record, scheme, identity);
            const bootstrap = await withinOwn(tx, principal, tenant, scheme, acting, {
              rank: Math.max(level.rank, previous?.rank ?? level.rank),
            });
            const now = ctx.now();
            const saved = await tx.put<Clearance>(clearanceCollections.clearances, {
              ...next,
              updatedAt: now,
              updatedBy: principal.identity.id,
            });
            await ctx.events.audit(
              tx,
              principal,
              'clearance:update',
              tenant.id,
              identity.id,
              'allow',
              false,
              {
                level: saved.level,
                ...(saved.level !== record.level ? { previousLevel: record.level } : {}),
                status: saved.status,
                changed,
                ...(bootstrap ? { bootstrap: true } : {}),
              },
            );
            return clearanceView(tx, saved, scheme, identity);
          },
        ),
      ),
    /**
     * Reads a person into a compartment of the scheme, optionally backed by an NDA (`agreementId`, an agreement of the
     * person's tenant; the read-in counts only while their acceptance of its current version is current). The
     * clearance must be active or interim; guests are never read in. Under `within-own` the officer must be read into
     * the compartment (an owner or root may bootstrap one nobody holds). Requires iam:clearances:adjudicate and a
     * recent sign-in; audited as `clearance:read-in` with the compartment id.
     */
    readIn: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; compartmentId: string; agreementId?: string },
    ): Promise<ClearanceView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:adjudicate',
          clearanceResource(input.identityId),
          async ({ tx, principal, tenant }) => {
            ctx.auth.requireRecent(principal);
            const scheme = await schemeIn(tx, tenant);
            const identity = await ctx.activeIdentity(tx, input.identityId, tenant.id);
            const acting = await officer(tx, principal, tenant, scheme, identity);
            if (identity.guest !== undefined)
              throw new IamError('INVALID_INPUT', 'Guests are not read into compartments');
            const record = await liveRecord(tx, identity, scheme);
            if (record.status === 'suspended')
              throw new IamError(
                'INVALID_TRANSITION',
                'A suspended clearance cannot be read into compartments',
                409,
              );
            const compartmentId = text(input.compartmentId, 'compartmentId', 64);
            if (!scheme.definition.compartments.some((item) => item.id === compartmentId))
              throw new IamError(
                'INVALID_INPUT',
                'compartmentId must be a compartment of the scheme',
              );
            if ((record.readIns ?? []).some((item) => item.compartmentId === compartmentId))
              throw new IamError('CONFLICT', 'Already read into this compartment', 409);
            let acceptedAt: number | undefined;
            let agreementId: string | undefined;
            if (input.agreementId !== undefined) {
              const agreement = await ctx.scoped<Agreement>(
                tx,
                'agreements',
                text(input.agreementId, 'agreementId'),
                identity.tenantId,
              );
              agreementId = agreement.id;
              const acceptance = await tx.get<AgreementAcceptance>(
                'agreementAcceptances',
                `${agreement.id}:${identity.id}`,
              );
              if (
                acceptance?.tenantId === identity.tenantId &&
                acceptanceCurrent(agreement, acceptance, ctx.now())
              )
                acceptedAt = acceptance.acceptedAt;
            }
            const bootstrap = await withinOwn(tx, principal, tenant, scheme, acting, {
              compartmentId,
            });
            const now = ctx.now();
            const saved = await tx.put<Clearance>(clearanceCollections.clearances, {
              ...record,
              readIns: [
                ...(record.readIns ?? []),
                {
                  compartmentId,
                  readInAt: now,
                  readInBy: principal.identity.id,
                  ...(agreementId !== undefined ? { agreementId } : {}),
                  ...(acceptedAt !== undefined ? { acceptedAt } : {}),
                },
              ],
              updatedAt: now,
              updatedBy: principal.identity.id,
            });
            await ctx.events.audit(
              tx,
              principal,
              'clearance:read-in',
              tenant.id,
              identity.id,
              'allow',
              false,
              {
                compartmentId,
                level: record.level,
                ...(agreementId !== undefined ? { agreementId } : {}),
                ...(bootstrap ? { bootstrap: true } : {}),
              },
            );
            return clearanceView(tx, saved, scheme, identity);
          },
        ),
      ),
    /**
     * Ends a read-in. Tightening, so it needs no recent sign-in and may be your own. Requires
     * iam:clearances:adjudicate; audited as `clearance:debrief` with the compartment id.
     */
    debrief: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; compartmentId: string; reason?: string },
    ): Promise<ClearanceView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:adjudicate',
          clearanceResource(input.identityId),
          async ({ tx, principal, tenant }) => {
            const scheme = await schemeIn(tx, tenant);
            await officer(tx, principal, tenant, scheme, undefined);
            const identity = await ctx.scoped<Identity>(
              tx,
              'identities',
              input.identityId,
              tenant.id,
            );
            const compartmentId = text(input.compartmentId, 'compartmentId', 64);
            const reason =
              input.reason !== undefined ? text(input.reason, 'reason', 512).trim() : undefined;
            const record = await readClearance(tx, identity);
            if (
              !record ||
              !(record.readIns ?? []).some((item) => item.compartmentId === compartmentId)
            )
              throw new IamError('NOT_FOUND', 'Not read into this compartment', 404);
            const now = ctx.now();
            const saved = await tx.put<Clearance>(clearanceCollections.clearances, {
              ...record,
              readIns: record.readIns.filter((item) => item.compartmentId !== compartmentId),
              updatedAt: now,
              updatedBy: principal.identity.id,
            });
            await ctx.events.audit(
              tx,
              principal,
              'clearance:debrief',
              tenant.id,
              identity.id,
              'allow',
              false,
              { compartmentId, ...(reason ? { reason } : {}) },
            );
            const view = await clearanceView(tx, saved, scheme, identity);
            // Only narrows: an "expect allow" invariant never blocks a debrief (invariants.ts).
            narrowsAccessOnly(tx);
            return view;
          },
        ),
      ),
    /**
     * Suspends an active or interim clearance at once (an incident, an investigation). Needs no recent sign-in so it
     * works during an incident; lifted only by `reinstate`. The person is emailed (`clearance-status`) unless
     * `notifyPerson` is false (an investigation that must not tip them off). Requires iam:clearances:suspend; audited
     * as `clearance:suspend`.
     */
    suspend: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        identityId: string;
        reason: string;
        incidentId?: string;
        notifyPerson?: boolean;
      },
    ): Promise<ClearanceView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:suspend',
          clearanceResource(input.identityId),
          async ({ tx, principal, tenant }) => {
            const scheme = await schemeIn(tx, tenant);
            await officer(tx, principal, tenant, scheme, undefined);
            const identity = await ctx.scoped<Identity>(
              tx,
              'identities',
              input.identityId,
              tenant.id,
            );
            const reason = text(input.reason, 'reason', 512).trim();
            const incidentId =
              input.incidentId !== undefined ? text(input.incidentId, 'incidentId') : undefined;
            const notifyPerson = flag(input.notifyPerson, 'notifyPerson') ?? true;
            const result = await suspendClearance(tx, identity, {
              by: principal.identity.id,
              at: ctx.now(),
              reason,
              ...(incidentId !== undefined ? { incidentId } : {}),
            });
            if (result.outcome === 'no-clearance')
              throw new IamError('NOT_FOUND', 'This identity holds no clearance to suspend', 404);
            if (result.outcome === 'already-applied')
              throw new IamError('INVALID_TRANSITION', 'The clearance is already suspended', 409);
            await ctx.events.audit(
              tx,
              principal,
              'clearance:suspend',
              tenant.id,
              identity.id,
              'allow',
              false,
              {
                level: result.record!.level,
                reason,
                ...(incidentId !== undefined ? { incidentId } : {}),
              },
            );
            if (notifyPerson)
              await notifyClearanceStatus(ctx, tx, identity, scheme, result.record!, 'suspended');
            return clearanceView(tx, result.record!, scheme, identity);
          },
        ),
      ),
    /**
     * Lifts a suspension (back to active or interim). Any officer but the person themselves, within their own clearance
     * under `within-own`: its level and every compartment it is read into, since reinstating gives them back. Requires
     * iam:clearances:adjudicate and a recent sign-in; audited as `clearance:reinstate`.
     */
    reinstate: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; reason?: string },
    ): Promise<ClearanceView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:adjudicate',
          clearanceResource(input.identityId),
          async ({ tx, principal, tenant }) => {
            ctx.auth.requireRecent(principal);
            const scheme = await schemeIn(tx, tenant);
            const identity = await ctx.activeIdentity(tx, input.identityId, tenant.id);
            const acting = await officer(tx, principal, tenant, scheme, identity);
            const reason =
              input.reason !== undefined ? text(input.reason, 'reason', 512).trim() : undefined;
            const record = await liveRecord(tx, identity, scheme);
            if (record.status !== 'suspended')
              throw new IamError(
                'INVALID_TRANSITION',
                'Only a suspended clearance is reinstated',
                409,
              );
            const level = schemeLevel(scheme, record.level);
            if (!level)
              throw new IamError(
                'INVALID_INPUT',
                'The clearance’s level left the scheme; grant anew',
              );
            let bootstrap = await withinOwn(tx, principal, tenant, scheme, acting, {
              rank: level.rank,
            });
            // The read-ins come back with the clearance: under within-own the officer must hold each compartment the
            // scheme still defines, as for a read-in (the others never count).
            for (const readIn of record.readIns ?? [])
              if (scheme.definition.compartments.some((item) => item.id === readIn.compartmentId))
                bootstrap =
                  (await withinOwn(tx, principal, tenant, scheme, acting, {
                    compartmentId: readIn.compartmentId,
                  })) || bootstrap;
            const now = ctx.now();
            const { suspended, ...rest } = record;
            const saved = await tx.put<Clearance>(clearanceCollections.clearances, {
              ...rest,
              status: suspended?.previousStatus ?? 'active',
              updatedAt: now,
              updatedBy: principal.identity.id,
            });
            await ctx.events.audit(
              tx,
              principal,
              'clearance:reinstate',
              tenant.id,
              identity.id,
              'allow',
              false,
              {
                level: saved.level,
                status: saved.status,
                ...(reason ? { reason } : {}),
                ...(bootstrap ? { bootstrap: true } : {}),
              },
            );
            await notifyClearanceStatus(ctx, tx, identity, scheme, saved, 'reinstated');
            return clearanceView(tx, saved, scheme, identity);
          },
        ),
      ),
    /**
     * Revokes a clearance for cause and debriefs every compartment; the record stays as history and a new clearance
     * needs a new grant. The person is emailed (`clearance-status`) unless `notifyPerson` is false. Requires
     * iam:clearances:adjudicate and a recent sign-in; audited as `clearance:revoke` with the debriefed compartment ids.
     */
    revoke: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; reason: string; notifyPerson?: boolean },
    ): Promise<ClearanceView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:adjudicate',
          clearanceResource(input.identityId),
          async ({ tx, principal, tenant }) => {
            ctx.auth.requireRecent(principal);
            const scheme = await schemeIn(tx, tenant);
            await officer(tx, principal, tenant, scheme, undefined);
            const identity = await ctx.scoped<Identity>(
              tx,
              'identities',
              input.identityId,
              tenant.id,
            );
            const reason = text(input.reason, 'reason', 512).trim();
            const notifyPerson = flag(input.notifyPerson, 'notifyPerson') ?? true;
            const record = await readClearance(tx, identity);
            if (!record || !liveStatuses.has(record.status))
              throw new IamError('NOT_FOUND', 'This identity holds no clearance to revoke', 404);
            const now = ctx.now();
            const { suspended: _suspended, ...rest } = record;
            const saved = await tx.put<Clearance>(clearanceCollections.clearances, {
              ...rest,
              status: 'revoked',
              readIns: [],
              revoked: { by: principal.identity.id, at: now, reason },
              updatedAt: now,
              updatedBy: principal.identity.id,
            });
            await ctx.events.audit(
              tx,
              principal,
              'clearance:revoke',
              tenant.id,
              identity.id,
              'allow',
              false,
              {
                level: record.level,
                reason,
                debriefed: (record.readIns ?? []).map((item) => item.compartmentId),
              },
            );
            if (notifyPerson)
              await notifyClearanceStatus(ctx, tx, identity, scheme, saved, 'revoked');
            const view = await clearanceView(tx, saved, scheme, identity);
            // Only narrows: an "expect allow" invariant never blocks revoking for cause (invariants.ts).
            narrowsAccessOnly(tx);
            return view;
          },
        ),
      ),
    /** One identity's clearance (null when it has none). Requires iam:clearances:read. */
    get: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string },
    ): Promise<ClearanceView | null> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:read',
          clearanceResource(input.identityId),
          async ({ tx, tenant }) => {
            const identity = await ctx.scoped<Identity>(
              tx,
              'identities',
              input.identityId,
              tenant.id,
            );
            const record = await readClearance(tx, identity);
            if (!record) return null;
            const scheme = await effectiveScheme(tx, await ctx.ancestry(tx, tenant));
            return clearanceView(tx, record, scheme, identity);
          },
        ),
      ),
    /**
     * The tenant's clearances, by name: optionally one stored `status`, one `level`, or those ending within
     * `expiringWithinDays` (ended ones included). Requires iam:clearances:read.
     */
    list: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        status?: ClearanceStatus;
        level?: string;
        expiringWithinDays?: number;
        limit?: number;
        offset?: number;
      },
    ): Promise<ClearancePage> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:read',
          'clearances',
          async ({ tx, tenant }) => {
            if (input.status !== undefined && !clearanceStatuses.has(input.status))
              throw new IamError('INVALID_INPUT', 'Invalid status');
            const level = input.level !== undefined ? text(input.level, 'level', 64) : undefined;
            const within =
              input.expiringWithinDays !== undefined
                ? integer(input.expiringWithinDays, 'expiringWithinDays', 1, 3650)
                : undefined;
            const limit = integer(input.limit ?? 100, 'limit', 1, 500);
            const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
            const scheme = await effectiveScheme(tx, await ctx.ancestry(tx, tenant));
            const horizon = within !== undefined ? ctx.now() + within * dayMs : undefined;
            const records = (
              await tx.find<Clearance>(clearanceCollections.clearances, {
                tenantId: tenant.id,
                ...(input.status !== undefined ? { status: input.status } : {}),
              })
            ).filter(
              (record) =>
                record.tenantId === tenant.id &&
                (level === undefined || record.level === level) &&
                (horizon === undefined ||
                  (typeof record.expiresAt === 'number' && record.expiresAt <= horizon)),
            );
            // Ordered by name first, so only the page's clearances are evaluated in full.
            const people: Array<{
              record: Clearance;
              identity: Identity | undefined;
              name: string;
            }> = [];
            for (const record of records) {
              const identity = await tx.get<Identity>('identities', record.identityId);
              people.push({ record, identity, name: identity?.name ?? record.identityId });
            }
            people.sort(
              (a, b) =>
                a.name.localeCompare(b.name, 'en') ||
                (a.record.identityId < b.record.identityId
                  ? -1
                  : a.record.identityId > b.record.identityId
                    ? 1
                    : 0),
            );
            const views: ClearanceView[] = [];
            for (const item of people.slice(offset, offset + limit))
              views.push(await clearanceView(tx, item.record, scheme, item.identity));
            return { clearances: views, total: people.length };
          },
        ),
      ),
    /**
     * The caller's own clearance under the scheme in force (levels of the scheme, their level, status, citizenship,
     * dates and the compartments they are read into with whether each NDA is current). Needs only an ordinary session
     * of the tenant (not while impersonating); no permission.
     */
    mine: (credential: CredentialInput, input: { tenantId: string }): Promise<MyClearance> =>
      enabled(async () => {
        const tenantId = text(input.tenantId, 'tenantId');
        const authenticated = await ctx.principals.authenticate(credential);
        return ctx.store.transaction(async (tx) => {
          const principal = await ctx.principals.currentPrincipal(tx, authenticated);
          if (
            !actsInOwnRight(principal.session) ||
            principal.session.tenantId !== tenantId ||
            principal.identity.tenantId !== tenantId
          )
            throw new IamError(
              'ACCESS_DENIED',
              'Your clearance is read from an ordinary session of its tenant',
              403,
            );
          if (principal.session.impersonatorId)
            throw new IamError(
              'IMPERSONATION_RESTRICTED',
              'A clearance is not shown while impersonating',
              403,
            );
          const tenant = await ctx.tenant(tx, tenantId);
          const scheme = await effectiveScheme(tx, await ctx.ancestry(tx, tenant));
          if (!scheme) return { scheme: null, clearance: null };
          const record = await readClearance(tx, principal.identity);
          const view = record
            ? await clearanceView(tx, record, scheme, principal.identity)
            : undefined;
          return {
            scheme: {
              tenantId: scheme.tenantId,
              name: scheme.name,
              levels: scheme.definition.levels.map((level) => ({ ...level })),
            },
            clearance: view
              ? {
                  level: {
                    id: view.level.id,
                    ...(view.level.name ? { name: view.level.name } : {}),
                  },
                  status: view.status,
                  effectiveStatus: view.effectiveStatus,
                  ...(view.effectiveLevel ? { effectiveLevel: view.effectiveLevel } : {}),
                  citizenship: view.citizenship,
                  ...(view.reinvestigationDue !== undefined
                    ? { reinvestigationDue: view.reinvestigationDue }
                    : {}),
                  ...(view.expiresAt !== undefined ? { expiresAt: view.expiresAt } : {}),
                  readIns: view.readIns.map((item) => ({
                    compartmentId: item.compartmentId,
                    ...(item.compartmentName ? { compartmentName: item.compartmentName } : {}),
                    ...(item.agreementId !== undefined ? { agreementId: item.agreementId } : {}),
                    current: item.current,
                  })),
                }
              : null,
          };
        });
      }),
    /**
     * For investigations: whether a person (their own sessions: an agent with its sponsor) may read a resource, which
     * dimension the first refused party fails, the label decisions apply and each party's clearance. Officers only:
     * requires iam:clearances:adjudicate.
     */
    explain: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string; type: string; id: string },
    ): Promise<ClearanceExplanation> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:adjudicate',
          clearanceResource(input.identityId),
          async ({ tx, tenant }) => {
            const type = text(input.type, 'type');
            const resourceId = text(input.id, 'id');
            const scheme = await schemeIn(tx, tenant);
            const identity = await ctx.activeIdentity(tx, input.identityId, tenant.id);
            const subject = ctx.decisions.simulatedPrincipal(identity);
            const states = await sessionParties(
              tx,
              subject,
              tenant,
              undefined,
              scheme,
              ctx.now(),
              false,
            );
            const reference = { tenantId: tenant.id, type, id: resourceId };
            let resolved: ResolvedResource = reference;
            try {
              resolved = await ctx.decisions.resolve(tx, reference, false);
            } catch (error) {
              // An unregistered or unresolvable resource still has its IAM-held label (labels outlive resources).
              if (!(error instanceof IamError)) throw error;
            }
            const labeled = await attachLabel(ctx, tx, tenant.id, resolved, { scheme });
            const label = applicableLabel(scheme, labeled);
            const views = states.map(partyView);
            if (label === undefined)
              return { allowed: true, label: null, party: views[0]!, parties: views };
            if (label === false)
              return {
                allowed: false,
                failure: 'invalid-label',
                label: null,
                party: views[0]!,
                parties: views,
              };
            for (const [index, state] of states.entries()) {
              const failure = partiesFail([state.party], label, scheme.definition);
              if (failure)
                return { allowed: false, failure, label, party: views[index]!, parties: views };
            }
            return { allowed: true, label, party: views[0]!, parties: views };
          },
        ),
      ),
    /**
     * Labels a resource (any application or tenant type; it need not exist yet, and the label outlives it). Only raises:
     * the new label must cover the current one in every dimension, and inheritance once on stays on; anything else is a
     * declassification. Requires iam:classifications:label; audited as `classification:label` with level and compartment
     * ids.
     */
    label: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type: string;
        id: string;
        label: ClassificationLabel;
        inheritToChildren?: boolean;
      },
    ): Promise<ResourceLabelView> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:classifications:label',
          labelResource(labelType(input.type), text(input.id, 'id')),
          async ({ tx, principal, tenant }) => {
            noImpersonation(principal);
            const { scheme, type, resourceId } = await labelTarget(tx, tenant, input);
            const label = validateLabel(input.label, scheme.definition);
            const inherit = flag(input.inheritToChildren, 'inheritToChildren');
            const existing = await storedLabel(tx, tenant.id, type, resourceId);
            const inheritToChildren = inherit ?? existing?.inheritToChildren ?? false;
            // A label written under another scheme refuses everyone, so replacing it is a declassification too.
            if (
              existing &&
              (existing.schemeTenantId !== scheme.tenantId ||
                !labelCovers(label, existing.label, scheme.definition) ||
                (existing.inheritToChildren && !inheritToChildren))
            )
              throw new OperationDenied(
                'Lowering or removing any part of a label is a declassification: use declassify',
              );
            if (
              existing &&
              existing.inheritToChildren === inheritToChildren &&
              JSON.stringify(existing.label) === JSON.stringify(label)
            )
              return labelView(existing, scheme);
            const saved = await writeLabel(
              tx,
              principal,
              tenant,
              scheme,
              type,
              resourceId,
              label,
              inheritToChildren,
              existing,
            );
            await ctx.events.audit(
              tx,
              principal,
              'classification:label',
              tenant.id,
              labelKey(type, resourceId),
              'allow',
              false,
              {
                type,
                ...labelMetadata(label),
                inheritToChildren,
                ...(existing ? { previousLevel: existing.label.level } : {}),
              },
            );
            return labelView(saved, scheme);
          },
        ),
      ),
    /**
     * Lowers, changes or (with `label: null`) removes a resource's label. The caller's own clearance must dominate the
     * current label (nobody declassifies what they could not read). Requires iam:classifications:declassify and a
     * recent sign-in; audited as `classification:declassify` with the reason.
     */
    declassify: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type: string;
        id: string;
        label: ClassificationLabel | null;
        reason: string;
        inheritToChildren?: boolean;
      },
    ): Promise<ResourceLabelView | null> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:classifications:declassify',
          labelResource(labelType(input.type), text(input.id, 'id')),
          async ({ tx, principal, tenant }) => {
            ctx.auth.requireRecent(principal);
            const { scheme, type, resourceId } = await labelTarget(tx, tenant, input);
            const reason = text(input.reason, 'reason', 512).trim();
            if (input.label === undefined)
              throw new IamError('INVALID_INPUT', 'label is required (null removes it)');
            const label =
              input.label === null ? null : validateLabel(input.label, scheme.definition);
            const inherit = flag(input.inheritToChildren, 'inheritToChildren');
            const existing = await storedLabel(tx, tenant.id, type, resourceId);
            if (!existing) throw new IamError('NOT_FOUND', 'This resource has no label', 404);
            const acting = await officer(tx, principal, tenant, scheme, undefined);
            // A label the scheme no longer reads (broken) may be repaired; a valid one only by someone who could read it.
            if (
              isValidClassificationLabel(existing.label, scheme.definition) &&
              partiesFail(
                acting.states.map((state) => state.party),
                existing.label,
                scheme.definition,
              )
            )
              throw new OperationDenied('Only someone cleared to read a label may declassify it');
            let saved: ResourceLabel | undefined;
            if (label === null) await tx.delete(clearanceCollections.labels, existing.id);
            else
              saved = await writeLabel(
                tx,
                principal,
                tenant,
                scheme,
                type,
                resourceId,
                label,
                inherit ?? existing.inheritToChildren,
                existing,
              );
            await ctx.events.audit(
              tx,
              principal,
              'classification:declassify',
              tenant.id,
              labelKey(type, resourceId),
              'allow',
              false,
              {
                type,
                previous: labelMetadata(existing.label),
                ...(label ? { label: labelMetadata(label) } : { removed: true }),
                reason,
              },
            );
            return saved ? labelView(saved, scheme) : null;
          },
        ),
      ),
    /**
     * A resource's own IAM label and what it inherits from its managed parents. Requires iam:clearances:read.
     */
    getLabel: (
      credential: CredentialInput,
      input: { tenantId: string; type: string; id: string },
    ): Promise<ResourceLabelState> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:read',
          labelResource(labelType(input.type), text(input.id, 'id')),
          async ({ tx, tenant }) => {
            const { scheme, type, resourceId } = await labelTarget(tx, tenant, input);
            const existing = await storedLabel(tx, tenant.id, type, resourceId);
            const inherited = await inheritedLabel(tx, tenant.id, scheme, type, resourceId);
            return {
              type,
              id: resourceId,
              label: existing ? labelView(existing, scheme) : null,
              inherited: inherited ?? null,
            };
          },
        ),
      ),
    /** The tenant's IAM labels, optionally of one type or level. Requires iam:clearances:read. */
    listLabels: (
      credential: CredentialInput,
      input: { tenantId: string; type?: string; level?: string; limit?: number; offset?: number },
    ): Promise<ResourceLabelPage> =>
      enabled(() =>
        operation(
          credential,
          input.tenantId,
          'iam:clearances:read',
          'classifications/labels',
          async ({ tx, tenant }) => {
            const type = input.type !== undefined ? labelType(input.type) : undefined;
            const level = input.level !== undefined ? text(input.level, 'level', 64) : undefined;
            const limit = integer(input.limit ?? 100, 'limit', 1, 500);
            const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
            const scheme = await effectiveScheme(tx, await ctx.ancestry(tx, tenant));
            const labels = (
              await tx.find<ResourceLabel>(clearanceCollections.labels, {
                tenantId: tenant.id,
                ...(type !== undefined ? { type } : {}),
              })
            )
              .filter((item) => level === undefined || item.label.level === level)
              .sort(
                (a, b) =>
                  (a.type < b.type ? -1 : a.type > b.type ? 1 : 0) ||
                  (a.resourceId < b.resourceId ? -1 : a.resourceId > b.resourceId ? 1 : 0),
              );
            return {
              labels: labels.slice(offset, offset + limit).map((item) => labelView(item, scheme)),
              total: labels.length,
            };
          },
        ),
      ),
  };

  /** Writes a label record (insert or new version). */
  async function writeLabel(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    scheme: ClassificationScheme,
    type: string,
    resourceId: string,
    label: ClassificationLabel,
    inheritToChildren: boolean,
    existing: ResourceLabel | undefined,
  ): Promise<ResourceLabel> {
    const now = ctx.now();
    const record: ResourceLabel = {
      id: existing?.id ?? id(),
      tenantId: tenant.id,
      uniqueKey: labelKey(type, resourceId),
      type,
      resourceId,
      label,
      inheritToChildren,
      schemeTenantId: scheme.tenantId,
      labeledBy: principal.identity.id,
      labeledAt: now,
      version: (existing?.version ?? 0) + 1,
    };
    return existing
      ? tx.put<ResourceLabel>(clearanceCollections.labels, record)
      : tx.insert<ResourceLabel>(clearanceCollections.labels, record);
  }
}

/**
 * Refuses a definition change that would reinterpret what is in use: new levels must rank above every level kept; a
 * level a live clearance or a label uses must keep its id and rank; a compartment in use must stay; every label must
 * remain valid.
 */
async function assertDefinitionChange(
  tx: IamStore,
  scheme: ClassificationScheme,
  next: ClassificationSchemeDefinition,
): Promise<void> {
  const before = new Map(scheme.definition.levels.map((level) => [level.id, level]));
  const after = new Map(next.levels.map((level) => [level.id, level]));
  const kept = next.levels.filter((level) => before.has(level.id));
  const keptTop = kept.length ? Math.max(...kept.map((level) => before.get(level.id)!.rank)) : -1;
  for (const level of next.levels)
    if (!before.has(level.id) && level.rank <= keptTop)
      throw new IamError('INVALID_INPUT', 'New levels go above every existing level');
  const records = (
    await tx.find<Clearance>(clearanceCollections.clearances, { schemeTenantId: scheme.tenantId })
  ).filter(
    (record) => record.schemeTenantId === scheme.tenantId && liveStatuses.has(record.status),
  );
  const labels = (
    await tx.find<ResourceLabel>(clearanceCollections.labels, { schemeTenantId: scheme.tenantId })
  ).filter((item) => item.schemeTenantId === scheme.tenantId);
  const levels = new Set([
    ...records.map((record) => record.level),
    ...labels.map((item) => item.label.level),
  ]);
  for (const levelId of levels) {
    const was = before.get(levelId);
    const now = after.get(levelId);
    if (was && (!now || now.rank !== was.rank))
      throw new IamError(
        'RESOURCE_IN_USE',
        'A level that clearances or labels use cannot be removed or re-ranked',
        409,
      );
  }
  const compartments = new Set(next.compartments.map((compartment) => compartment.id));
  const used = new Set([
    ...records.flatMap((record) => (record.readIns ?? []).map((item) => item.compartmentId)),
    ...labels.flatMap((item) => item.label.compartments ?? []),
  ]);
  for (const compartmentId of used)
    if (!compartments.has(compartmentId))
      throw new IamError(
        'RESOURCE_IN_USE',
        'A compartment that clearances or labels use cannot be removed',
        409,
      );
  for (const item of labels)
    if (
      isValidClassificationLabel(item.label, scheme.definition) &&
      !isValidClassificationLabel(item.label, next)
    )
      throw new IamError('RESOURCE_IN_USE', 'The change would invalidate existing labels', 409);
}

// --- reminders -------------------------------------------------------------------------------------

/** Reminds officers of reinvestigations and clearance ends (see `IamClearances.sendReminders`). */
async function sendReminders(
  ctx: ServerContext,
  input: { tenantId?: string; withinDays?: number },
): Promise<ClearanceReminderResult> {
  assertClearances(ctx);
  const withinDays = integer(
    input.withinDays ?? clearanceLimits.reminderDays,
    'withinDays',
    1,
    365,
  );
  if (!ctx.options.authentication?.sendEmail)
    throw new IamError(
      'DELIVERY_REQUIRED',
      'Clearance reminders require an email delivery callback',
    );
  const live = (record: Clearance) => record.status === 'active' || record.status === 'interim';
  const tenantIds =
    input.tenantId !== undefined
      ? [text(input.tenantId, 'tenantId')]
      : [
          ...new Set(
            (await ctx.store.find<Clearance>(clearanceCollections.clearances))
              .filter(live)
              .map((record) => record.tenantId),
          ),
        ].sort();
  const result: ClearanceReminderResult = { sent: [], skipped: { inactive: 0, noRecipients: 0 } };
  for (const tenantId of tenantIds) {
    const outcome = await ctx.store.transaction(async (tx) => {
      const tenant = await tx.get<Tenant>('tenants', tenantId);
      if (!tenant || tenant.status !== 'active') return 'inactive' as const;
      const scheme = await effectiveScheme(tx, await ctx.ancestry(tx, tenant));
      const sent: ClearanceReminderResult['sent'] = [];
      let noRecipients = 0;
      if (!scheme) return { sent, noRecipients };
      const now = ctx.now();
      const horizon = now + withinDays * 86_400_000;
      const reminded = new Set(
        (await tx.find<ExpiryReminderMark>('expiryReminderMarks', { tenantId })).map(
          (mark) => mark.uniqueKey,
        ),
      );
      let recipients: string[] | undefined;
      const recipientsOf = async () => {
        if (recipients) return recipients;
        const owners = (
          await tx.find<Identity>('identities', {
            tenantId: scheme.tenantId,
            owner: true,
            status: 'active',
          })
        ).filter(
          (owner) =>
            owner.kind === 'user' &&
            owner.guest === undefined &&
            typeof owner.email === 'string' &&
            !(typeof owner.expiresAt === 'number' && owner.expiresAt <= now),
        );
        recipients = [
          ...new Set([
            ...owners.map((owner) => owner.email!.toLowerCase()),
            ...(scheme.notify?.emails ?? []),
          ]),
        ].sort();
        return recipients;
      };
      const records = (await tx.find<Clearance>(clearanceCollections.clearances, { tenantId }))
        .filter((record) => record.tenantId === tenantId && live(record))
        .sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
      for (const record of records) {
        if (record.schemeTenantId !== scheme.tenantId) continue;
        const person = await tx.get<Identity>('identities', record.identityId);
        if (
          !person ||
          person.tenantId !== tenantId ||
          person.status !== 'active' ||
          (typeof person.expiresAt === 'number' && person.expiresAt <= now)
        )
          continue;
        const due = [
          ...(typeof record.reinvestigationDue === 'number' && record.reinvestigationDue <= horizon
            ? [{ kind: 'reinvestigation', at: record.reinvestigationDue }]
            : []),
          ...(typeof record.expiresAt === 'number' &&
          record.expiresAt > now &&
          record.expiresAt <= horizon
            ? [
                {
                  kind: record.status === 'interim' ? 'interim-end' : 'expiry',
                  at: record.expiresAt,
                },
              ]
            : []),
        ].filter((item) => !reminded.has(`clearance-reminder:${record.id}:${item.at}`));
        if (!due.length) continue;
        const to = await recipientsOf();
        if (!to.length) {
          noRecipients++;
          continue;
        }
        const dueAt = Math.min(...due.map((item) => item.at));
        const level = schemeLevel(scheme, record.level);
        for (const address of to)
          await ctx.auth.enqueueDelivery(tx, {
            tenantId,
            kind: 'email',
            to: address,
            template: 'clearance-reminder',
            payload: {
              tenantId,
              tenantName: tenant.name,
              identityId: person.id,
              personName: person.name,
              ...(level ? { levelName: level.name } : {}),
              status: record.status,
              dueAt: iso(dueAt),
              ...(typeof record.reinvestigationDue === 'number'
                ? { reinvestigationDue: iso(record.reinvestigationDue) }
                : {}),
              ...(typeof record.expiresAt === 'number' ? { expiresAt: iso(record.expiresAt) } : {}),
            },
          });
        for (const item of due) {
          const key = `clearance-reminder:${record.id}:${item.at}`;
          reminded.add(key);
          await tx.insert<ExpiryReminderMark>('expiryReminderMarks', {
            id: id(),
            tenantId,
            uniqueKey: key,
            identityId: person.id,
            // Outlives the date, so the purge cannot let the reminder go out again while it is due.
            expiresAt: Math.max(item.at, now) + withinDays * 86_400_000,
          });
        }
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'deployment-operator',
          action: 'clearance:reminder',
          resourceId: person.id,
          timestamp: now,
          outcome: 'allow',
          metadata: {
            level: record.level,
            dueAt,
            kinds: due.map((item) => item.kind),
            recipients: to.length,
          },
        });
        sent.push({ tenantId, identityId: person.id, dueAt, recipients: to.length });
      }
      return { sent, noRecipients };
    });
    if (outcome === 'inactive') result.skipped.inactive++;
    else {
      result.sent.push(...outcome.sent);
      result.skipped.noRecipients += outcome.noRecipients;
    }
  }
  return result;
}

export function createClearancesRuntime(ctx: ServerContext): IamClearances {
  return {
    sendReminders: (input = {}) => sendReminders(ctx, input),
  };
}
