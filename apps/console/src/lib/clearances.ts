// Pure helpers behind the clearance pages (cloud/[org]/clearances, cloud/[org]/classification, and the Clearance card
// on a member's page): labels, badge tones, classification markings, what needs an officer's attention, list filters,
// the advisory permission resources, and the request bodies the clearance, label and scheme forms send. Type-only
// imports (plus the structural IamError check), so tests can load this file by relative path.
//
// Compartment names may themselves be classified codewords. Every helper here that prints one takes them from a scheme
// definition the caller passes in, and the pages pass a definition only when it came from `clearances.getScheme`,
// which requires iam:clearances:read. Without it a compartment shows as its opaque id.
import type {
  AdjudicationMode,
  ClassificationLabel,
  ClassificationLevel,
  ClassificationSchemeDefinition,
  ClassificationSchemeInput,
  ClassificationSchemeView,
  ClearanceGrantInput,
  ClearanceStatus,
  ClearanceUpdateInput,
  ClearanceView,
  DominanceFailure,
  EffectiveClearanceStatus,
} from 'better-iam/server';
import type { Tone } from '@/components/ui';
import { isIamError } from './errors';
import { dateTimeLocalValue } from './form-body';
import { relativeDays } from './guests';

export { relativeDays };

const day = 86_400_000;

/** How far ahead the pages flag reinvestigations and clearance ends: the window `iam.clearances.sendReminders` uses. */
export const attentionDays = 60;

// ---------------------------------------------------------------------------------------------------------------
// Statuses and words

export const clearanceStatuses: readonly ClearanceStatus[] = [
  'active',
  'interim',
  'suspended',
  'revoked',
  'terminated',
];

/** Statuses of a clearance that is in force or can be again (by reinstatement): the API's "live" clearances. */
const liveStatuses: ReadonlySet<ClearanceStatus> = new Set(['active', 'interim', 'suspended']);

export function isLive(status: ClearanceStatus): boolean {
  return liveStatuses.has(status);
}

export const statusLabels: Record<ClearanceStatus, string> = {
  active: 'active',
  interim: 'interim',
  suspended: 'suspended',
  revoked: 'revoked',
  terminated: 'ended',
};

/** What decisions count the clearance as right now. */
export const effectiveStatusLabels: Record<EffectiveClearanceStatus, string> = {
  active: 'in force',
  interim: 'in force (interim)',
  none: 'not counted',
  expired: 'expired',
  suspended: 'suspended',
  revoked: 'revoked',
  terminated: 'ended',
};

export function statusTone(status: ClearanceStatus | EffectiveClearanceStatus): Tone {
  switch (status) {
    case 'active':
      return 'success';
    case 'interim':
      return 'accent';
    case 'suspended':
    case 'none':
      return 'warning';
    case 'expired':
    case 'revoked':
      return 'danger';
    default:
      return 'neutral';
  }
}

/** Why a party may not read a label, in words (`clearances.explain`, officers only). */
export const failureLabels: Record<DominanceFailure, string> = {
  level: 'Their level is below the label’s level, or their clearance does not count.',
  compartment:
    'They are not read into every compartment the label names (or an NDA is not current).',
  noforn: 'NOFORN: their adjudicated citizenship includes no owner country of the scheme.',
  releasability:
    'REL TO: their adjudicated citizenship is neither an owner country nor one the label is releasable to.',
  'invalid-label':
    'The label is missing on a type that must carry one, or is not valid under the scheme: everyone is refused.',
};

export const adjudicationLabels: Record<AdjudicationMode, string> = {
  'within-own': 'Within the officer’s own clearance',
  unrestricted: 'Unrestricted',
};

export const adjudicationHelp: Record<AdjudicationMode, string> = {
  'within-own':
    'An officer grants only levels and compartments their own clearance holds; an owner may bootstrap a level or compartment nobody holds yet.',
  unrestricted: 'Any officer with iam:clearances:adjudicate grants any level or compartment.',
};

// ---------------------------------------------------------------------------------------------------------------
// Advisory permission resources (lib/org.ts `can`; the server re-checks every operation)

export type IamResource = { type: 'iam'; id: string };

export const clearancesResource: IamResource = { type: 'iam', id: 'clearances' };
/** Stands for "any person's clearance" in advisory checks on pages that list many people. */
export const anyClearanceResource: IamResource = { type: 'iam', id: 'clearances/*' };
export const schemeResource: IamResource = { type: 'iam', id: 'classifications/scheme' };
/** Stands for "any resource's label" in advisory checks. */
export const anyLabelResource: IamResource = { type: 'iam', id: 'classifications/labels/*' };

export function clearanceResource(identityId: string): IamResource {
  return { type: 'iam', id: `clearances/${identityId}` };
}

/**
 * The resource label operations are authorized on, `classifications/labels/{type}/{id}`; undefined when it is longer
 * than 256 characters (the server then authorizes a hashed form, and the page falls back to `anyLabelResource`).
 */
export function labelResource(type: string, id: string): IamResource | undefined {
  const plain = `classifications/labels/${type}/${id}`;
  return plain.length <= 256 ? { type: 'iam', id: plain } : undefined;
}

// ---------------------------------------------------------------------------------------------------------------
// Reads that tell "not permitted" from "not enabled"

export type Attempt<T> = { ok: true; value: T } | { ok: false; code: string };

/** Runs a read; an IAM error becomes `{ ok: false, code }` (FEATURE_DISABLED, ACCESS_DENIED, ...), anything else throws. */
export async function attempt<T>(read: () => Promise<T>): Promise<Attempt<T>> {
  try {
    return { ok: true, value: await read() };
  } catch (error) {
    if (isIamError(error)) return { ok: false, code: error.code };
    throw error;
  }
}

/** Whether any of the reads says the deployment does not enable clearances (the `clearances` option). */
export function featureDisabled(...results: Attempt<unknown>[]): boolean {
  return results.some((result) => !result.ok && result.code === 'FEATURE_DISABLED');
}

export function valueOf<T>(result: Attempt<T>): T | undefined {
  return result.ok ? result.value : undefined;
}

// ---------------------------------------------------------------------------------------------------------------
// Levels, compartments and markings

export function levelsByRank(definition: ClassificationSchemeDefinition): ClassificationLevel[] {
  return [...definition.levels].sort((a, b) => a.rank - b.rank);
}

export function levelOf(
  definition: ClassificationSchemeDefinition | undefined,
  levelId: string,
): ClassificationLevel | undefined {
  return definition?.levels.find((level) => level.id === levelId);
}

/** A level's display name, or its id when the scheme is not known (or no longer has it). */
export function levelName(
  definition: ClassificationSchemeDefinition | undefined,
  levelId: string,
): string {
  return levelOf(definition, levelId)?.name ?? levelId;
}

/** Select options for the levels, lowest first. */
export function levelOptions(
  definition: ClassificationSchemeDefinition,
): Array<{ value: string; label: string }> {
  return levelsByRank(definition).map((level) => ({
    value: level.id,
    label: level.abbreviation ? `${level.name} (${level.abbreviation})` : level.name,
  }));
}

/** A compartment's name from the definition, or its id. Pass a definition only to someone with iam:clearances:read. */
export function compartmentName(
  definition: ClassificationSchemeDefinition | undefined,
  compartmentId: string,
): string {
  return (
    definition?.compartments.find((compartment) => compartment.id === compartmentId)?.name ??
    compartmentId
  );
}

/**
 * A label as a banner marking, such as `TOP SECRET // GAMMA/TALENT // NOFORN` or `SECRET // REL TO USA, GBR`. Names
 * come from `definition` (ids without it); REL TO lists the owner countries first.
 */
export function labelMarking(
  label: ClassificationLabel,
  definition?: ClassificationSchemeDefinition,
): string {
  const parts = [levelName(definition, label.level)];
  if (label.compartments?.length)
    parts.push(label.compartments.map((id) => compartmentName(definition, id)).join('/'));
  if (label.noforn) parts.push('NOFORN');
  else if (label.releasableTo) {
    const countries = [...new Set([...(definition?.ownerCountries ?? []), ...label.releasableTo])];
    parts.push(countries.length ? `REL TO ${countries.join(', ')}` : 'REL TO owner countries');
  }
  return parts.join(' // ');
}

// ---------------------------------------------------------------------------------------------------------------
// Dates and attention

/** `overdue` when the date passed, `soon` within the window, otherwise undefined (also for no date). */
export function dueState(
  at: number | undefined,
  now: number,
  withinDays = attentionDays,
): 'overdue' | 'soon' | undefined {
  if (at === undefined) return undefined;
  if (at <= now) return 'overdue';
  return at <= now + withinDays * day ? 'soon' : undefined;
}

export interface ClearanceAttention {
  label: string;
  tone: Tone;
}

type AttentionFields = Pick<
  ClearanceView,
  'status' | 'effectiveStatus' | 'reinvestigationDue' | 'expiresAt' | 'readIns'
>;

/**
 * What needs an officer's attention about a live clearance: it does not count (expired, or not counted for another
 * reason such as a disabled account or a guest without a ceiling), it ends within the window, its reinvestigation is
 * overdue or due, or an NDA behind a read-in is not current.
 */
export function clearanceAttention(
  clearance: AttentionFields,
  now: number,
  withinDays = attentionDays,
): ClearanceAttention[] {
  if (!isLive(clearance.status)) return [];
  const items: ClearanceAttention[] = [];
  if (clearance.effectiveStatus === 'expired') items.push({ label: 'expired', tone: 'danger' });
  else if (clearance.effectiveStatus === 'none')
    items.push({ label: 'not counted', tone: 'warning' });
  else if (dueState(clearance.expiresAt, now, withinDays) === 'soon')
    items.push({ label: 'ends soon', tone: 'warning' });
  const reinvestigation = dueState(clearance.reinvestigationDue, now, withinDays);
  if (reinvestigation === 'overdue')
    items.push({ label: 'reinvestigation overdue', tone: 'danger' });
  else if (reinvestigation === 'soon')
    items.push({ label: 'reinvestigation due', tone: 'warning' });
  const lapsed = clearance.readIns.filter((readIn) => !readIn.current).length;
  if (lapsed)
    items.push({
      label: lapsed === 1 ? '1 read-in not current' : `${lapsed} read-ins not current`,
      tone: 'warning',
    });
  return items;
}

export interface ClearanceSummary {
  /** Clearances decisions count right now (active or interim). */
  inForce: number;
  interim: number;
  suspended: number;
  /** Live clearances that expired or are not counted for another reason. */
  notCounted: number;
  /** Clearances in force that end within the window. */
  endingSoon: number;
  /** Live clearances whose reinvestigation is overdue or due within the window. */
  reinvestigationDue: number;
  /** Revoked or ended. */
  closed: number;
}

/** The counts on the Clearances page tiles. */
export function clearanceSummary(
  clearances: readonly AttentionFields[],
  now: number,
  withinDays = attentionDays,
): ClearanceSummary {
  const summary: ClearanceSummary = {
    inForce: 0,
    interim: 0,
    suspended: 0,
    notCounted: 0,
    endingSoon: 0,
    reinvestigationDue: 0,
    closed: 0,
  };
  for (const clearance of clearances) {
    if (!isLive(clearance.status)) {
      summary.closed++;
      continue;
    }
    if (clearance.status === 'suspended') summary.suspended++;
    else if (clearance.effectiveStatus === 'active' || clearance.effectiveStatus === 'interim') {
      summary.inForce++;
      if (clearance.effectiveStatus === 'interim') summary.interim++;
    } else summary.notCounted++;
    const labels = clearanceAttention(clearance, now, withinDays).map((item) => item.label);
    if (labels.includes('ends soon')) summary.endingSoon++;
    if (labels.includes('reinvestigation due') || labels.includes('reinvestigation overdue'))
      summary.reinvestigationDue++;
  }
  return summary;
}

// ---------------------------------------------------------------------------------------------------------------
// List filters (query string <-> clearances.list input)

export interface ClearanceFilters {
  status?: ClearanceStatus;
  level?: string;
  expiringWithinDays?: number;
}

export interface ClearanceFilterParams {
  status?: string;
  level?: string;
  ending?: string;
  page?: string;
}

/** The "ends within" choices, in days. */
export const endingOptions: readonly number[] = [30, 60, 90, 180, 365];

/** Level and compartment ids as the core defines them (`classificationIdPattern`). */
const identifierPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/;

/**
 * The clearance list filters in a query string; unknown values are ignored rather than refused. A level must be one of
 * `levelIds` when the scheme is known, otherwise any well-formed level id.
 */
export function clearanceFilters(
  params: ClearanceFilterParams,
  levelIds?: readonly string[],
): { filters: ClearanceFilters; page: number } {
  const level = params.level?.trim();
  const ending = Number.parseInt(params.ending ?? '', 10);
  const filters: ClearanceFilters = {
    ...(params.status && (clearanceStatuses as readonly string[]).includes(params.status)
      ? { status: params.status as ClearanceStatus }
      : {}),
    ...(level && (levelIds ? levelIds.includes(level) : identifierPattern.test(level))
      ? { level }
      : {}),
    ...(endingOptions.includes(ending) ? { expiringWithinDays: ending } : {}),
  };
  const page = Math.max(1, Number.parseInt(params.page ?? '1', 10) || 1);
  return { filters, page };
}

/** The query string (with its `?`, or empty) for clearance filters and a page. */
export function clearanceFilterQuery(filters: ClearanceFilters, page = 1): string {
  const search = new URLSearchParams();
  if (filters.status) search.set('status', filters.status);
  if (filters.level) search.set('level', filters.level);
  if (filters.expiringWithinDays !== undefined)
    search.set('ending', String(filters.expiringWithinDays));
  if (page > 1) search.set('page', String(page));
  const text = search.toString();
  return text ? `?${text}` : '';
}

export interface LabelFilters {
  type?: string;
  level?: string;
}

export interface LabelFilterParams {
  type?: string;
  level?: string;
  page?: string;
}

/** The label list filters in a query string (`clearances.listLabels`); unknown values are ignored. */
export function labelFilters(
  params: LabelFilterParams,
  levelIds?: readonly string[],
): { filters: LabelFilters; page: number } {
  const type = params.type?.trim();
  const level = params.level?.trim();
  const filters: LabelFilters = {
    ...(type && type.length <= 200 ? { type } : {}),
    ...(level && (levelIds ? levelIds.includes(level) : identifierPattern.test(level))
      ? { level }
      : {}),
  };
  const page = Math.max(1, Number.parseInt(params.page ?? '1', 10) || 1);
  return { filters, page };
}

export function labelFilterQuery(filters: LabelFilters, page = 1): string {
  const search = new URLSearchParams();
  if (filters.type) search.set('type', filters.type);
  if (filters.level) search.set('level', filters.level);
  if (page > 1) search.set('page', String(page));
  const text = search.toString();
  return text ? `?${text}` : '';
}

// ---------------------------------------------------------------------------------------------------------------
// Typed input

/** Entries typed one per line, or separated by commas or spaces, without blanks or repeats, in order. */
export function entries(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\s,]+/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ];
}

/** ISO 3166-1 alpha-3 country codes as typed (any case), upper-cased and sorted. Throws on anything else. */
export function countryCodes(value: string, label = 'Citizenship'): string[] {
  const codes = entries(value).map((code) => code.toUpperCase());
  const wrong = codes.find((code) => !/^[A-Z]{3}$/.test(code));
  if (wrong !== undefined)
    throw new Error(`${label} takes ISO 3166-1 alpha-3 country codes, such as USA or GBR`);
  return [...new Set(codes)].sort();
}

/** An epoch as a `date` input value (`YYYY-MM-DD`) in this runtime's time zone. Call it in the browser. */
export function dateValue(epoch: number): string {
  return dateTimeLocalValue(epoch).slice(0, 10);
}

/** A `date` input value as the start of that day in this runtime's time zone; undefined when empty. */
export function parseDate(value: string, label: string): number | undefined {
  const text = value.trim();
  if (!text) return undefined;
  const at = /^\d{4}-\d{2}-\d{2}$/.test(text) ? new Date(`${text}T00:00`).getTime() : Number.NaN;
  if (!Number.isFinite(at)) throw new Error(`${label} must be a date`);
  return at;
}

/** A `datetime-local` input value in this runtime's time zone; undefined when empty. */
export function parseDateTime(value: string, label: string): number | undefined {
  const text = value.trim();
  if (!text) return undefined;
  const at = new Date(text).getTime();
  if (!Number.isFinite(at)) throw new Error(`${label} must be a date and time`);
  return at;
}

// ---------------------------------------------------------------------------------------------------------------
// Clearance forms (clearances.grant / clearances.update)

/** What the grant and update forms hold while they are being edited: everything as typed. */
export interface ClearanceDraft {
  level: string;
  /** Alpha-3 codes, comma- or space-separated. */
  citizenship: string;
  /** Grant only: start as an interim clearance. */
  interim: boolean;
  investigationKind: string;
  /** `date` input value. */
  investigationCompletedOn: string;
  /** `date` input value. */
  reinvestigationDueOn: string;
  /** `datetime-local` input value. */
  expiresAt: string;
}

export function emptyClearanceDraft(level = ''): ClearanceDraft {
  return {
    level,
    citizenship: '',
    interim: false,
    investigationKind: '',
    investigationCompletedOn: '',
    reinvestigationDueOn: '',
    expiresAt: '',
  };
}

function investigationOf(draft: ClearanceDraft): { kind: string; completedAt: number } | undefined {
  const kind = draft.investigationKind.trim();
  const completedAt = parseDate(draft.investigationCompletedOn, 'The investigation’s completion');
  if (!kind && completedAt === undefined) return undefined;
  if (!kind || completedAt === undefined)
    throw new Error('Give the investigation’s kind and its completion date together');
  return { kind, completedAt };
}

/** The `clearances.grant` input for a draft. Throws on input the form can tell is wrong (the server checks the rest). */
export function grantBody(
  tenantId: string,
  identityId: string,
  draft: ClearanceDraft,
): ClearanceGrantInput {
  if (!draft.level) throw new Error('Choose a level');
  const investigation = investigationOf(draft);
  const reinvestigationDue = parseDate(draft.reinvestigationDueOn, 'The reinvestigation date');
  const expiresAt = parseDateTime(draft.expiresAt, 'The end');
  return {
    tenantId,
    identityId,
    level: draft.level,
    citizenship: countryCodes(draft.citizenship),
    ...(draft.interim ? { interim: true } : {}),
    ...(investigation ? { investigation } : {}),
    ...(reinvestigationDue !== undefined ? { reinvestigationDue } : {}),
    ...(expiresAt !== undefined ? { expiresAt } : {}),
  };
}

/** `keep` leaves interim or final as it is (a suspended clearance does not show which it returns to). */
export type TermChoice = 'keep' | 'interim' | 'final';

export interface ClearanceUpdateDraft extends ClearanceDraft {
  term: TermChoice;
}

/** The update form's starting point: the clearance as it stands. Dates are formatted in this runtime's zone. */
export function updateDraft(view: ClearanceView): ClearanceUpdateDraft {
  return {
    level: view.level.id,
    citizenship: view.citizenship.join(', '),
    interim: view.status === 'interim',
    investigationKind: view.investigation?.kind ?? '',
    investigationCompletedOn: view.investigation ? dateValue(view.investigation.completedAt) : '',
    reinvestigationDueOn:
      view.reinvestigationDue !== undefined ? dateValue(view.reinvestigationDue) : '',
    expiresAt: view.expiresAt !== undefined ? dateTimeLocalValue(view.expiresAt) : '',
    term: view.status === 'interim' ? 'interim' : view.status === 'active' ? 'final' : 'keep',
  };
}

export type ClearanceChange = Omit<ClearanceUpdateInput, 'tenantId' | 'identityId'>;

const sameList = (a: readonly string[], b: readonly string[]) =>
  JSON.stringify([...a].sort()) === JSON.stringify([...b].sort());

/**
 * The `clearances.update` change for a draft: only what differs from the clearance as it stands, so an untouched form
 * changes nothing and the audit event names exactly what changed. An emptied date or investigation is cleared (null);
 * an untouched date is not re-sent (an end already past would be refused).
 */
export function updateChange(view: ClearanceView, draft: ClearanceUpdateDraft): ClearanceChange {
  const change: ClearanceChange = {};
  if (!draft.level) throw new Error('Choose a level');
  if (draft.level !== view.level.id) change.level = draft.level;
  const citizenship = countryCodes(draft.citizenship);
  if (!sameList(citizenship, view.citizenship)) change.citizenship = citizenship;
  const known = view.status === 'interim' ? 'interim' : view.status === 'active' ? 'final' : 'keep';
  if (draft.term !== 'keep' && draft.term !== known) change.interim = draft.term === 'interim';
  const before = updateDraft(view);
  if (
    draft.investigationKind.trim() !== before.investigationKind ||
    draft.investigationCompletedOn !== before.investigationCompletedOn
  )
    change.investigation = investigationOf(draft) ?? null;
  if (draft.reinvestigationDueOn !== before.reinvestigationDueOn)
    change.reinvestigationDue =
      parseDate(draft.reinvestigationDueOn, 'The reinvestigation date') ?? null;
  if (draft.expiresAt !== before.expiresAt)
    change.expiresAt = parseDateTime(draft.expiresAt, 'The end') ?? null;
  return change;
}

// ---------------------------------------------------------------------------------------------------------------
// Label forms (clearances.label / clearances.declassify / a scheme's defaultLabel)

/** REL TO as the form offers it: no restriction, the owner countries only (an empty list), or listed countries. */
export type Releasability = 'unrestricted' | 'owners' | 'listed';

export interface LabelDraft {
  level: string;
  compartments: string[];
  noforn: boolean;
  release: Releasability;
  /** Alpha-3 codes as typed, for `listed`. */
  releasableTo: string;
}

export function labelDraft(label?: ClassificationLabel | null, level = ''): LabelDraft {
  return {
    level: label?.level ?? level,
    compartments: [...(label?.compartments ?? [])],
    noforn: label?.noforn === true,
    release: !label?.releasableTo
      ? 'unrestricted'
      : label.releasableTo.length
        ? 'listed'
        : 'owners',
    releasableTo: (label?.releasableTo ?? []).join(', '),
  };
}

/**
 * The label a draft describes. NOFORN already limits readers to owner-country citizens, so it drops REL TO. Throws when
 * no level is chosen or REL TO lists no country.
 */
export function labelFromDraft(draft: LabelDraft): ClassificationLabel {
  const level = draft.level.trim();
  if (!level) throw new Error('Choose a level');
  const compartments = [...new Set(draft.compartments.map((item) => item.trim()).filter(Boolean))];
  let releasableTo: string[] | undefined;
  if (!draft.noforn && draft.release === 'owners') releasableTo = [];
  if (!draft.noforn && draft.release === 'listed') {
    releasableTo = countryCodes(draft.releasableTo, 'REL TO');
    if (!releasableTo.length) throw new Error('List the countries it is releasable to');
  }
  return {
    level,
    ...(compartments.length ? { compartments: compartments.sort() } : {}),
    ...(draft.noforn ? { noforn: true } : {}),
    ...(releasableTo ? { releasableTo } : {}),
  };
}

// ---------------------------------------------------------------------------------------------------------------
// Scheme forms (clearances.updateScheme)

export interface SchemeSettingsDraft {
  name: string;
  /** Resource types, comma- or space-separated; `*` for every application type. */
  requireLabels: string;
  /** A level id; empty: guests hold no clearance. */
  guestCeiling: string;
  interimAllowed: boolean;
  adjudication: AdjudicationMode;
  /** Addresses, comma- or space-separated. */
  notifyEmails: string;
}

export type SchemeChange = Partial<
  Pick<
    ClassificationSchemeInput,
    | 'name'
    | 'requireLabels'
    | 'guestCeiling'
    | 'interimAllowed'
    | 'adjudication'
    | 'notify'
    | 'defaultLabel'
    | 'definition'
  >
>;

export function schemeSettingsDraft(scheme: ClassificationSchemeView): SchemeSettingsDraft {
  return {
    name: scheme.name,
    requireLabels: scheme.requireLabels.join(', '),
    guestCeiling: scheme.guestCeiling ?? '',
    interimAllowed: scheme.interimAllowed,
    adjudication: scheme.adjudication,
    notifyEmails: (scheme.notify?.emails ?? []).join(', '),
  };
}

/** The settings change for a draft: only what differs from the scheme (an emptied notify list removes it). */
export function schemeSettingsChange(
  scheme: ClassificationSchemeView,
  draft: SchemeSettingsDraft,
): SchemeChange {
  const change: SchemeChange = {};
  const name = draft.name.trim();
  if (!name) throw new Error('The scheme needs a name');
  if (name !== scheme.name) change.name = name;
  const requireLabels = entries(draft.requireLabels);
  if (!sameList(requireLabels, scheme.requireLabels)) change.requireLabels = requireLabels;
  const guestCeiling = draft.guestCeiling || null;
  if (guestCeiling !== scheme.guestCeiling) change.guestCeiling = guestCeiling;
  if (draft.interimAllowed !== scheme.interimAllowed) change.interimAllowed = draft.interimAllowed;
  if (draft.adjudication !== scheme.adjudication) change.adjudication = draft.adjudication;
  const emails = entries(draft.notifyEmails).map((address) => address.toLowerCase());
  const current = (scheme.notify?.emails ?? []).map((address) => address.toLowerCase());
  if (!sameList(emails, current)) change.notify = emails.length ? { emails } : null;
  return change;
}

/** A definition with one more compartment. Throws when the id is malformed or the id or name is taken. */
export function withCompartment(
  definition: ClassificationSchemeDefinition,
  compartment: { id: string; name: string },
): ClassificationSchemeDefinition {
  const id = compartment.id.trim();
  const name = compartment.name.trim();
  if (!identifierPattern.test(id))
    throw new Error(
      'A compartment id starts with a letter or digit and holds letters, digits, . _ : - (64 at most)',
    );
  if (!name) throw new Error('Give the compartment a name');
  if (definition.compartments.some((item) => item.id.toLowerCase() === id.toLowerCase()))
    throw new Error('A compartment with this id exists');
  if (definition.compartments.some((item) => item.name.toLowerCase() === name.toLowerCase()))
    throw new Error('A compartment with this name exists');
  return { ...definition, compartments: [...definition.compartments, { id, name }] };
}

/** A definition with a new level above every existing one (new levels can only go on top). */
export function withTopLevel(
  definition: ClassificationSchemeDefinition,
  level: { id: string; name: string; abbreviation?: string },
): ClassificationSchemeDefinition {
  const id = level.id.trim();
  const name = level.name.trim();
  const abbreviation = level.abbreviation?.trim();
  if (!identifierPattern.test(id))
    throw new Error(
      'A level id starts with a letter or digit and holds letters, digits, . _ : - (64 at most)',
    );
  if (!name) throw new Error('Give the level a name');
  if (definition.levels.some((item) => item.id.toLowerCase() === id.toLowerCase()))
    throw new Error('A level with this id exists');
  if (definition.levels.some((item) => item.name.toLowerCase() === name.toLowerCase()))
    throw new Error('A level with this name exists');
  const top = Math.max(-1, ...definition.levels.map((item) => item.rank));
  return {
    ...definition,
    levels: [
      ...levelsByRank(definition),
      { id, name, rank: top + 1, ...(abbreviation ? { abbreviation } : {}) },
    ],
  };
}

/** A definition typed as JSON. Throws when it is not JSON or not an object; the server validates the rest. */
export function parseDefinition(text: string): ClassificationSchemeDefinition {
  let value: unknown;
  try {
    value = JSON.parse(text);
  } catch {
    throw new Error('The definition must be valid JSON');
  }
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    throw new Error('The definition must be a JSON object with levels, compartments, ...');
  return value as ClassificationSchemeDefinition;
}

// ---------------------------------------------------------------------------------------------------------------
// History (audit events about one person's clearance)

/** The audit fields the history reads. */
export interface HistoryEvent {
  action: string;
  actorId: string;
  timestamp: number;
  metadata?: Record<string, unknown>;
}

export interface HistoryEntry {
  title: string;
  tone: Tone;
  details: string[];
}

const historyTitles: Record<string, { title: string; tone: Tone }> = {
  'clearance:grant': { title: 'Granted', tone: 'success' },
  'clearance:update': { title: 'Changed', tone: 'accent' },
  'clearance:read-in': { title: 'Read in', tone: 'accent' },
  'clearance:debrief': { title: 'Debriefed', tone: 'neutral' },
  'clearance:suspend': { title: 'Suspended', tone: 'warning' },
  'clearance:reinstate': { title: 'Reinstated', tone: 'success' },
  'clearance:revoke': { title: 'Revoked', tone: 'danger' },
  'clearance:terminate': { title: 'Ended (offboarded)', tone: 'neutral' },
  'clearance:reminder': { title: 'Officers reminded', tone: 'neutral' },
};

const changedLabels: Record<string, string> = {
  level: 'level',
  citizenship: 'citizenship',
  interim: 'interim or final',
  investigation: 'investigation',
  reinvestigationDue: 'reinvestigation date',
  expiresAt: 'end',
};

const textOf = (value: unknown): string | undefined =>
  typeof value === 'string' && value ? value : undefined;
const listOf = (value: unknown): string[] =>
  Array.isArray(value) ? value.filter((item): item is string => typeof item === 'string') : [];

/**
 * One audit event of a person's clearance in words. Level and compartment names come from `definition` (pass it only to
 * someone with iam:clearances:read); the events themselves carry ids only.
 */
export function historyEntry(
  event: HistoryEvent,
  definition?: ClassificationSchemeDefinition,
): HistoryEntry {
  const known = historyTitles[event.action] ?? { title: event.action, tone: 'neutral' as Tone };
  const metadata = event.metadata ?? {};
  const details: string[] = [];
  const level = textOf(metadata.level);
  const previousLevel = textOf(metadata.previousLevel);
  if (level && event.action !== 'clearance:read-in')
    details.push(
      previousLevel
        ? `${levelName(definition, previousLevel)} → ${levelName(definition, level)}`
        : levelName(definition, level),
    );
  const status = textOf(metadata.status);
  if (status && (event.action === 'clearance:grant' || event.action === 'clearance:reinstate'))
    details.push(`as ${status}`);
  const changed = listOf(metadata.changed).map((field) => changedLabels[field] ?? field);
  if (changed.length) details.push(`changed ${changed.join(', ')}`);
  const compartmentId = textOf(metadata.compartmentId);
  if (compartmentId) details.push(compartmentName(definition, compartmentId));
  if (textOf(metadata.agreementId)) details.push('backed by an NDA');
  const debriefed = listOf(metadata.debriefed);
  if (debriefed.length)
    details.push(`debriefed ${debriefed.map((id) => compartmentName(definition, id)).join(', ')}`);
  const previousStatus = textOf(metadata.previousStatus);
  if (previousStatus) details.push(`was ${previousStatus}`);
  if (metadata.bootstrap === true) details.push('bootstrap: nobody held it yet');
  const kinds = listOf(metadata.kinds);
  if (kinds.length) details.push(`${kinds.join(', ')} due`);
  if (typeof metadata.recipients === 'number')
    details.push(`${metadata.recipients} recipient${metadata.recipients === 1 ? '' : 's'}`);
  const incidentId = textOf(metadata.incidentId);
  if (incidentId) details.push(`incident ${incidentId}`);
  const reason = textOf(metadata.reason);
  if (reason) details.push(`“${reason}”`);
  return { title: known.title, tone: known.tone, details };
}
