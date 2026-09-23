/**
 * Customizable onboarding. A flow is an ordered checklist a newcomer completes: people joining a tenant (`member`
 * flows) or a new tenant's administrators setting it up (`tenant` flows). Flows are defined at any level of the
 * tenant hierarchy (the platform root, an organization, a project) and inherited downward, so the platform sets
 * defaults for every organization, an organization adds its own steps and switches off the platform's optional
 * flows, and a project does the same again. This module holds the records, the validators, the resolution of which
 * flows apply to whom, and the evaluation of step state; the `onboarding` API group builds on it.
 */
import {
  IamError,
  type AttributeType,
  type IamStore,
  type Identity,
  type Json,
  type PolicyDocument,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { acceptanceCurrent, type Agreement, type AgreementAcceptance } from './agreements.js';
import type { GroupMember, PackageRuleConditions } from './models.js';
import { parseAutoAssign, ruleContext, ruleDocument, ruleMatch } from './package-rules.js';
import { email as emailAddress, integer, text } from './validation.js';

export type OnboardingAudience = 'member' | 'tenant';
/**
 * `form` collects answers, `acknowledge` asks the reader to confirm a text, `task` is work done elsewhere (self-attested
 * or verified by an administrator). Member flows add steps that complete on their own: `agreement` (a terms-of-use
 * acceptance), `verify-email`, `mfa` and `passkey`. Tenant flows add `check` steps that watch the tenant's own setup.
 */
export type OnboardingStepKind =
  | 'form'
  | 'acknowledge'
  | 'task'
  | 'agreement'
  | 'verify-email'
  | 'mfa'
  | 'passkey'
  | 'check';
/** What a tenant `check` step watches. */
export type OnboardingCheck =
  | 'verified-domain'
  | 'members'
  | 'owners'
  | 'mfa-policy'
  | 'agreement'
  | 'slug'
  | 'sso'
  | 'directory-sync'
  | 'member-onboarding';
export type OnboardingFieldType =
  | 'text'
  | 'textarea'
  | 'email'
  | 'url'
  | 'number'
  | 'boolean'
  | 'select'
  | 'date';

export interface OnboardingField {
  /** Answer key: a letter, then letters, digits or underscores (at most 40). */
  name: string;
  label: string;
  type: OnboardingFieldType;
  /** A required boolean must be checked (a confirmation). */
  required?: boolean;
  help?: string;
  placeholder?: string;
  /** `select` choices (1-50). */
  options?: string[];
  /** Text length cap (text/textarea). */
  maxLength?: number;
  /** Number bounds. */
  min?: number;
  max?: number;
  /**
   * Member flows: the declared identity attribute (`permissions.identityAttributes`) this answer fills. Onboarding only
   * fills attributes that are empty, so it never overwrites a value an administrator or directory sync set.
   */
  attribute?: string;
}
export interface OnboardingStep {
  /** Stable within the flow: lowercase letters, digits and dashes (at most 40). Progress is recorded per step ID. */
  id: string;
  kind: OnboardingStepKind;
  title: string;
  /** Plain text or Markdown shown with the step. */
  description?: string;
  /** Optional steps never hold a flow back. */
  optional?: boolean;
  fields?: OnboardingField[];
  /** `acknowledge`: the text the reader confirms. */
  content?: string;
  /** `task`: where the work happens. */
  url?: string;
  /** `task`: `self` (the default) completes when marked done; `admin` waits for an administrator to verify it. */
  verification?: 'self' | 'admin';
  /** `agreement`: the name of a terms-of-use agreement in the member's own tenant. */
  agreement?: string;
  check?: OnboardingCheck;
  /** `check` members/owners: how many are needed (default 2). */
  minimum?: number;
}
/** Which members or tenants a flow reaches: its own tenant, the tenants below it, or both. */
export type OnboardingScope = 'tenant' | 'descendants' | 'subtree';
/** A targeting rule in the access-package rule language: include clauses (any matches) and exclude clauses. */
export interface OnboardingRule {
  include: PackageRuleConditions[];
  exclude?: PackageRuleConditions[];
}
export interface OnboardingFlow extends StoredRecord {
  name: string;
  description?: string;
  audience: OnboardingAudience;
  appliesTo: OnboardingScope;
  /** Descendant tenants of these types only (all types when absent). */
  tenantTypes?: string[];
  /** Member flows: only people this rule matches. */
  rule?: OnboardingRule;
  /** Required flows count toward `principal.pendingOnboarding` until complete. */
  required: boolean;
  /** Inherited flows a descendant tenant may not switch off. Tenant flows are always binding. */
  locked: boolean;
  /** Also applies to people and tenants that existed before the flow took effect. */
  includeExisting: boolean;
  enabled: boolean;
  /** When the flow first took effect; without `includeExisting` only newcomers from then on are asked. */
  effectiveFrom?: number;
  steps: OnboardingStep[];
  /** Member flows of the defining tenant: groups a person joins when they complete the flow. */
  completionGroupIds?: string[];
  /** Bumped whenever the steps change. */
  version: number;
  /** Who last saved the flow (left out where descendants see an inherited flow). */
  authorId?: string;
  createdAt: number;
  updatedAt: number;
}
/** A tenant's onboarding customization: welcome copy, support contacts, and inherited flows switched off here. */
export interface OnboardingSettings extends StoredRecord {
  welcomeTitle?: string;
  welcomeMessage?: string;
  supportEmail?: string;
  supportUrl?: string;
  /** Inherited, unlocked member flows switched off for this tenant and every tenant below it. */
  disabledFlowIds: string[];
  updatedAt: number;
}
export interface OnboardingStepRecord {
  stepId: string;
  completedAt?: number;
  completedBy?: string;
  /** Admin-verified tasks: marked done by the subject and waiting for an administrator. */
  submittedAt?: number;
  verifiedBy?: string;
  /** Sent back by an administrator, with an optional note for the subject. */
  rejectedAt?: number;
  note?: string;
  answers?: Record<string, Json>;
}
/**
 * One subject's progress through one flow; the ID is `{flowId}:{subjectId}` and the tenant is the subject's own
 * (the person's tenant, or the tenant being set up).
 */
export interface OnboardingProgress extends StoredRecord {
  flowId: string;
  flowTenantId: string;
  subjectType: 'identity' | 'tenant';
  subjectId: string;
  steps: OnboardingStepRecord[];
  startedAt: number;
  updatedAt: number;
  /** When the flow was last seen complete, and in which version. */
  completedAt?: number;
  completedVersion?: number;
  /** Member flows: the version whose completion groups were applied. */
  groupsAppliedVersion?: number;
  /** Why applying completion groups failed (a separation-of-duties rule, for example); retried later. */
  completionError?: string;
}

export type OnboardingStepState = 'complete' | 'pending' | 'submitted' | 'rejected' | 'unavailable';
export interface OnboardingStepStatus extends OnboardingStep {
  optional: boolean;
  state: OnboardingStepState;
  completedAt?: number;
  submittedAt?: number;
  rejectedAt?: number;
  note?: string;
  answers?: Record<string, Json>;
  /** A human-readable fact behind a self-completing step, such as `1 of 2 members`. */
  detail?: string;
}
export interface OnboardingSource {
  tenantId: string;
  name: string;
  type: string;
}
export interface OnboardingFlowStatus {
  id: string;
  name: string;
  description?: string;
  audience: OnboardingAudience;
  required: boolean;
  locked: boolean;
  version: number;
  source: OnboardingSource;
  inherited: boolean;
  steps: OnboardingStepStatus[];
  complete: boolean;
  completedAt?: number;
  done: number;
  total: number;
}
export interface ResolvedOnboardingSettings {
  welcomeTitle?: string;
  welcomeMessage?: string;
  supportEmail?: string;
  supportUrl?: string;
  /** The tenant each value came from (the nearest one that set it). */
  sources: Partial<
    Record<'welcomeTitle' | 'welcomeMessage' | 'supportEmail' | 'supportUrl', OnboardingSource>
  >;
}

export const maxFlowsPerTenant = 50;
export const maxSteps = 25;
export const maxFields = 20;
export const maxCompletionGroups = 10;
const stepIdPattern = /^[a-z0-9][a-z0-9-]{0,39}$/;
const fieldNamePattern = /^[a-zA-Z][a-zA-Z0-9_]{0,39}$/;
const stepKinds: Record<OnboardingAudience, OnboardingStepKind[]> = {
  member: ['form', 'acknowledge', 'task', 'agreement', 'verify-email', 'mfa', 'passkey'],
  tenant: ['form', 'acknowledge', 'task', 'check'],
};
export const onboardingChecks: OnboardingCheck[] = [
  'verified-domain',
  'members',
  'owners',
  'mfa-policy',
  'agreement',
  'slug',
  'sso',
  'directory-sync',
  'member-onboarding',
];
const fieldTypes: OnboardingFieldType[] = [
  'text',
  'textarea',
  'email',
  'url',
  'number',
  'boolean',
  'select',
  'date',
];
/** Steps that complete on their own and cannot be marked done. */
export const automaticSteps = new Set<OnboardingStepKind>([
  'agreement',
  'verify-email',
  'mfa',
  'passkey',
  'check',
]);

const plainObject = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' &&
  value !== null &&
  !Array.isArray(value) &&
  Object.getPrototypeOf(value) === Object.prototype;
const own = <T>(record: Record<string, T> | undefined, key: string): T | undefined =>
  record && Object.hasOwn(record, key) ? record[key] : undefined;

/** Multi-line text: tabs and line breaks allowed, other control characters not. */
export function longText(value: unknown, name: string, max: number): string {
  if (
    typeof value !== 'string' ||
    !value.trim() ||
    value.length > max ||
    /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(value)
  )
    throw new IamError('INVALID_INPUT', `Invalid ${name}`);
  return value;
}
export function httpUrl(value: unknown, name: string): string {
  const url = text(value, name, 2048).trim();
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    throw new IamError('INVALID_INPUT', `${name} must be an http(s) URL`);
  }
  if (parsed.protocol !== 'https:' && parsed.protocol !== 'http:')
    throw new IamError('INVALID_INPUT', `${name} must be an http(s) URL`);
  return url;
}
function flag(value: unknown, name: string, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  if (typeof value !== 'boolean') throw new IamError('INVALID_INPUT', `${name} must be a boolean`);
  return value;
}
function only(value: Record<string, unknown>, keys: string[], path: string): void {
  for (const key of Object.keys(value))
    if (!keys.includes(key)) throw new IamError('INVALID_INPUT', `${path}: unknown field ${key}`);
}

/** The identity attribute type an answer of this field type fills. */
export function attributeTypeOf(type: OnboardingFieldType): AttributeType {
  return type === 'number' ? 'number' : type === 'boolean' ? 'boolean' : 'string';
}

function parseField(
  value: unknown,
  path: string,
  audience: OnboardingAudience,
  identityAttributes: Record<string, AttributeType>,
): OnboardingField {
  if (!plainObject(value)) throw new IamError('INVALID_INPUT', `${path} must be an object`);
  only(
    value,
    [
      'name',
      'label',
      'type',
      'required',
      'help',
      'placeholder',
      'options',
      'maxLength',
      'min',
      'max',
      'attribute',
    ],
    path,
  );
  if (typeof value.name !== 'string' || !fieldNamePattern.test(value.name))
    throw new IamError(
      'INVALID_INPUT',
      `${path}.name must start with a letter and use letters, digits or underscores (at most 40)`,
    );
  const type = (value.type ?? 'text') as OnboardingFieldType;
  if (!fieldTypes.includes(type))
    throw new IamError('INVALID_INPUT', `${path}.type must be one of ${fieldTypes.join(', ')}`);
  const field: OnboardingField = {
    name: value.name,
    label: text(value.label, `${path}.label`, 100).trim(),
    type,
  };
  if (flag(value.required, `${path}.required`, false)) field.required = true;
  if (value.help !== undefined) field.help = text(value.help, `${path}.help`, 300).trim();
  if (value.placeholder !== undefined)
    field.placeholder = text(value.placeholder, `${path}.placeholder`, 100);
  if (type === 'select') {
    const options = value.options;
    if (!Array.isArray(options) || options.length < 1 || options.length > 50)
      throw new IamError('INVALID_INPUT', `${path}.options must list 1-50 choices`);
    field.options = options.map((option, index) =>
      text(option, `${path}.options[${index}]`, 100).trim(),
    );
    if (new Set(field.options).size !== field.options.length)
      throw new IamError('INVALID_INPUT', `${path}.options must be distinct`);
  } else if (value.options !== undefined)
    throw new IamError('INVALID_INPUT', `${path}.options apply to select fields only`);
  if (value.maxLength !== undefined) {
    if (type !== 'text' && type !== 'textarea')
      throw new IamError('INVALID_INPUT', `${path}.maxLength applies to text fields only`);
    field.maxLength = integer(
      value.maxLength,
      `${path}.maxLength`,
      1,
      type === 'textarea' ? 10_000 : 2_000,
    );
  }
  for (const bound of ['min', 'max'] as const)
    if (value[bound] !== undefined) {
      if (type !== 'number')
        throw new IamError('INVALID_INPUT', `${path}.${bound} applies to number fields only`);
      if (typeof value[bound] !== 'number' || !Number.isFinite(value[bound]))
        throw new IamError('INVALID_INPUT', `${path}.${bound} must be a number`);
      field[bound] = value[bound] as number;
    }
  if (field.min !== undefined && field.max !== undefined && field.min > field.max)
    throw new IamError('INVALID_INPUT', `${path}.min must not exceed max`);
  if (value.attribute !== undefined) {
    if (audience !== 'member')
      throw new IamError('INVALID_INPUT', `${path}.attribute applies to member flows only`);
    // Attribute values are single lines without control characters; a textarea answer is neither.
    if (type === 'textarea')
      throw new IamError(
        'INVALID_INPUT',
        `${path}.attribute: a textarea answer cannot fill an attribute`,
      );
    const attribute = text(value.attribute, `${path}.attribute`, 64);
    const declared = own(identityAttributes, attribute);
    if (!declared)
      throw new IamError(
        'INVALID_INPUT',
        `${path}.attribute ${attribute} is not a declared identity attribute`,
      );
    if (declared !== attributeTypeOf(type))
      throw new IamError(
        'INVALID_INPUT',
        `${path}.attribute ${attribute} holds a ${declared}; a ${type} field cannot fill it`,
      );
    field.attribute = attribute;
  }
  return field;
}

function parseStep(
  value: unknown,
  path: string,
  audience: OnboardingAudience,
  identityAttributes: Record<string, AttributeType>,
): OnboardingStep {
  if (!plainObject(value)) throw new IamError('INVALID_INPUT', `${path} must be an object`);
  only(
    value,
    [
      'id',
      'kind',
      'title',
      'description',
      'optional',
      'fields',
      'content',
      'url',
      'verification',
      'agreement',
      'check',
      'minimum',
    ],
    path,
  );
  if (typeof value.id !== 'string' || !stepIdPattern.test(value.id))
    throw new IamError(
      'INVALID_INPUT',
      `${path}.id must use lowercase letters, digits and dashes (at most 40)`,
    );
  const kind = value.kind as OnboardingStepKind;
  if (!stepKinds[audience].includes(kind))
    throw new IamError(
      'INVALID_INPUT',
      `${path}.kind must be one of ${stepKinds[audience].join(', ')} in a ${audience} flow`,
    );
  const step: OnboardingStep = {
    id: value.id,
    kind,
    title: text(value.title, `${path}.title`, 120).trim(),
  };
  if (value.description !== undefined)
    step.description = longText(value.description, `${path}.description`, 2_000);
  if (flag(value.optional, `${path}.optional`, false)) step.optional = true;
  const allowed: Record<OnboardingStepKind, string[]> = {
    form: ['fields'],
    acknowledge: ['content'],
    task: ['url', 'verification'],
    agreement: ['agreement'],
    'verify-email': [],
    mfa: [],
    passkey: [],
    check: ['check', 'minimum'],
  };
  for (const key of ['fields', 'content', 'url', 'verification', 'agreement', 'check', 'minimum'])
    if (value[key] !== undefined && !allowed[kind].includes(key))
      throw new IamError('INVALID_INPUT', `${path}.${key} does not apply to ${kind} steps`);
  if (kind === 'form') {
    const fields = value.fields;
    if (!Array.isArray(fields) || fields.length < 1 || fields.length > maxFields)
      throw new IamError('INVALID_INPUT', `${path}.fields must list 1-${maxFields} fields`);
    step.fields = fields.map((field, index) =>
      parseField(field, `${path}.fields[${index}]`, audience, identityAttributes),
    );
    const names = step.fields.map((field) => field.name.toLowerCase());
    if (new Set(names).size !== names.length)
      throw new IamError('INVALID_INPUT', `${path}.fields must have distinct names`);
    const attributes = step.fields.flatMap((field) => (field.attribute ? [field.attribute] : []));
    if (new Set(attributes).size !== attributes.length)
      throw new IamError('INVALID_INPUT', `${path}: two fields fill the same attribute`);
  }
  if (kind === 'acknowledge') step.content = longText(value.content, `${path}.content`, 20_000);
  if (kind === 'task') {
    if (value.url !== undefined) step.url = httpUrl(value.url, `${path}.url`);
    const verification = value.verification ?? 'self';
    if (verification !== 'self' && verification !== 'admin')
      throw new IamError('INVALID_INPUT', `${path}.verification must be self or admin`);
    step.verification = verification;
  }
  if (kind === 'agreement') step.agreement = text(value.agreement, `${path}.agreement`, 100).trim();
  if (kind === 'check') {
    if (!onboardingChecks.includes(value.check as OnboardingCheck))
      throw new IamError(
        'INVALID_INPUT',
        `${path}.check must be one of ${onboardingChecks.join(', ')}`,
      );
    step.check = value.check as OnboardingCheck;
    if (value.minimum !== undefined) {
      if (step.check !== 'members' && step.check !== 'owners')
        throw new IamError('INVALID_INPUT', `${path}.minimum applies to members and owners checks`);
      step.minimum = integer(value.minimum, `${path}.minimum`, 1, 10_000);
    }
  }
  return step;
}

/** Validates a flow's steps (1-25, distinct IDs, kinds allowed for the audience). */
export function parseSteps(
  value: unknown,
  audience: OnboardingAudience,
  identityAttributes: Record<string, AttributeType>,
): OnboardingStep[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > maxSteps)
    throw new IamError('INVALID_INPUT', `steps must list 1-${maxSteps} steps`);
  const steps = value.map((step, index) =>
    parseStep(step, `steps[${index}]`, audience, identityAttributes),
  );
  if (new Set(steps.map((step) => step.id)).size !== steps.length)
    throw new IamError('INVALID_INPUT', 'steps must have distinct IDs');
  if (JSON.stringify(steps).length > 200_000)
    throw new IamError('INVALID_INPUT', 'steps are larger than 200 000 characters');
  return steps;
}

/**
 * Validates a member flow's targeting rule. Group tests (`identity.groups`) name groups of the defining tenant, so
 * they are refused on flows that reach only descendant tenants, whose people are never members of those groups.
 */
export function parseRule(
  value: unknown,
  identityAttributes: Record<string, AttributeType>,
  groups: ReadonlySet<string>,
): OnboardingRule {
  if (!plainObject(value)) throw new IamError('INVALID_INPUT', 'rule must be an object');
  only(value, ['include', 'exclude'], 'rule');
  const parsed = parseAutoAssign(value, { identityAttributes, groups }, 'rule');
  return { include: parsed.include, ...(parsed.exclude ? { exclude: parsed.exclude } : {}) };
}

/** Whether a tenant type is one a flow at `source` reaches under `scope`/`types`. */
function reachesTenant(flow: OnboardingFlow, source: Tenant, target: Tenant): boolean {
  if (source.id === target.id) return flow.appliesTo !== 'descendants';
  if (flow.appliesTo === 'tenant') return false;
  return !flow.tenantTypes || flow.tenantTypes.includes(target.type);
}
const bySourceThenCreated = (
  a: { flow: OnboardingFlow; depth: number },
  b: { flow: OnboardingFlow; depth: number },
) =>
  b.depth - a.depth ||
  a.flow.createdAt - b.flow.createdAt ||
  (a.flow.id < b.flow.id ? -1 : a.flow.id > b.flow.id ? 1 : 0);

export interface CandidateFlow {
  flow: OnboardingFlow;
  source: Tenant;
  inherited: boolean;
  /** Depth of the defining tenant above the target (0 = the target itself). */
  depth: number;
  /** The tenant (the target or one between it and the source) that switched this inherited flow off. */
  disabledBy?: Tenant;
}

/** Reads each tenant's settings record at most once. */
export class SettingsReader {
  private readonly cache = new Map<string, Promise<OnboardingSettings | undefined>>();
  constructor(private readonly tx: IamStore) {}
  get(tenantId: string): Promise<OnboardingSettings | undefined> {
    let found = this.cache.get(tenantId);
    if (!found) {
      found = this.tx.get<OnboardingSettings>('onboardingSettings', settingsId(tenantId));
      this.cache.set(tenantId, found);
    }
    return found;
  }
}
export const settingsId = (tenantId: string) => `settings:${tenantId}`;
export const progressId = (flowId: string, subjectId: string) => `${flowId}:${subjectId}`;

/**
 * The flows of one audience that reach a tenant, before anything about a particular person is known: the tenant's
 * own flows for its members, and its ancestors' flows that reach down to it. `chain` is the tenant's ancestry
 * (`ctx.ancestry`: the tenant first, the root last). Disabled flows are included with `disabledBy` so administrators
 * can see them; locked flows ignore the switch.
 */
export async function candidateFlows(
  tx: IamStore,
  chain: Tenant[],
  audience: OnboardingAudience,
  settings = new SettingsReader(tx),
): Promise<CandidateFlow[]> {
  const target = chain[0]!;
  const found: CandidateFlow[] = [];
  for (const [depth, source] of chain.entries()) {
    // A tenant is never onboarded by its own tenant flows; they describe how its descendants set up.
    if (audience === 'tenant' && depth === 0) continue;
    for (const flow of await tx.find<OnboardingFlow>('onboardingFlows', {
      tenantId: source.id,
    })) {
      if (flow.audience !== audience || !flow.enabled || !reachesTenant(flow, source, target))
        continue;
      const candidate: CandidateFlow = { flow, source, inherited: depth > 0, depth };
      if (audience === 'member' && depth > 0 && !flow.locked)
        for (const between of chain.slice(0, depth))
          if ((await settings.get(between.id))?.disabledFlowIds.includes(flow.id)) {
            candidate.disabledBy = between;
            break;
          }
      found.push(candidate);
    }
  }
  return found.sort(bySourceThenCreated);
}

/** The group IDs an identity is a live member of in its tenant (targeting rules test these). */
export async function liveGroupIds(
  tx: IamStore,
  identity: Identity,
  now: number,
): Promise<string[]> {
  return (
    await tx.find<GroupMember>('groupMembers', {
      tenantId: identity.tenantId,
      identityId: identity.id,
    })
  )
    .filter((member) => member.expiresAt === undefined || member.expiresAt > now)
    .map((member) => member.groupId);
}

/** Whether a member flow applies to this person: people only, newcomers unless `includeExisting`, and the rule. */
export function flowAppliesTo(
  flow: OnboardingFlow,
  identity: Identity,
  groupIds: string[] | undefined,
): boolean {
  if (identity.kind !== 'user' || identity.status === 'deleted') return false;
  if (!flow.includeExisting && identity.createdAt < (flow.effectiveFrom ?? flow.createdAt))
    return false;
  if (!flow.rule) return true;
  return ruleMatch(ruleDocument(flow.rule), identity, ruleContext(identity, groupIds ?? []))
    .matched;
}

/** Whether a tenant flow applies to this tenant: newcomers unless `includeExisting`. */
export function tenantFlowApplies(flow: OnboardingFlow, tenant: Tenant): boolean {
  return (
    tenant.status !== 'deleted' &&
    (flow.includeExisting || tenant.createdAt >= (flow.effectiveFrom ?? flow.createdAt))
  );
}

/** The member flows a person is asked to complete (switched-off flows removed), in platform-first order. */
export async function flowsForIdentity(
  tx: IamStore,
  chain: Tenant[],
  identity: Identity,
  now: number,
  candidates?: CandidateFlow[],
): Promise<CandidateFlow[]> {
  if (identity.kind !== 'user') return [];
  const flows = (candidates ?? (await candidateFlows(tx, chain, 'member'))).filter(
    (candidate) => !candidate.disabledBy,
  );
  if (!flows.length) return [];
  const groupIds = flows.some((candidate) => candidate.flow.rule)
    ? await liveGroupIds(tx, identity, now)
    : undefined;
  return flows.filter((candidate) => flowAppliesTo(candidate.flow, identity, groupIds));
}

/** Facts a member flow's self-completing steps read, loaded only when a step needs them. */
export interface MemberFacts {
  mfa?: boolean;
  passkeys?: number;
  agreements?: Map<string, { agreement: Agreement; accepted: boolean }>;
}
export async function memberFacts(
  tx: IamStore,
  identity: Identity,
  flows: OnboardingFlow[],
  now: number,
): Promise<MemberFacts> {
  const kinds = new Set(flows.flatMap((flow) => flow.steps.map((step) => step.kind)));
  const facts: MemberFacts = {};
  if (kinds.has('mfa') || kinds.has('passkey')) {
    facts.passkeys = (
      await tx.find('authPasskeys', { tenantId: identity.tenantId, identityId: identity.id })
    ).length;
    facts.mfa =
      facts.passkeys > 0 ||
      Boolean(
        (await tx.get<StoredRecord & { enabled?: boolean }>('authMfa', identity.id))?.enabled,
      );
  }
  if (kinds.has('agreement')) {
    const acceptances = new Map(
      (
        await tx.find<AgreementAcceptance>('agreementAcceptances', {
          tenantId: identity.tenantId,
          identityId: identity.id,
        })
      ).map((acceptance) => [acceptance.agreementId, acceptance]),
    );
    facts.agreements = new Map(
      (await tx.find<Agreement>('agreements', { tenantId: identity.tenantId })).map((agreement) => [
        agreement.name.toLowerCase(),
        {
          agreement,
          accepted: acceptanceCurrent(agreement, acceptances.get(agreement.id), now),
        },
      ]),
    );
  }
  return facts;
}

/** Facts a tenant flow's check steps read, loaded only when a step needs them. */
export type TenantFacts = Partial<Record<OnboardingCheck, number | boolean>>;
export async function tenantFacts(
  tx: IamStore,
  tenant: Tenant,
  flows: OnboardingFlow[],
): Promise<TenantFacts> {
  const checks = new Set(
    flows.flatMap((flow) => flow.steps.flatMap((step) => (step.check ? [step.check] : []))),
  );
  const facts: TenantFacts = {};
  const people = async () =>
    (await tx.find<Identity>('identities', { tenantId: tenant.id })).filter(
      (identity) => identity.kind === 'user' && identity.status === 'active',
    );
  for (const check of checks) {
    if (check === 'verified-domain')
      facts[check] = (
        await tx.find<StoredRecord & { status?: string }>('tenantDomains', { tenantId: tenant.id })
      ).filter((domain) => domain.status === 'verified').length;
    else if (check === 'members') facts[check] = (await people()).length;
    else if (check === 'owners')
      facts[check] = (await people()).filter((identity) => identity.owner).length;
    else if (check === 'mfa-policy') facts[check] = tenant.authPolicy?.requireMfa === true;
    else if (check === 'agreement')
      facts[check] = (await tx.find('agreements', { tenantId: tenant.id })).length;
    else if (check === 'slug') facts[check] = tenant.slug !== undefined;
    else if (check === 'sso')
      facts[check] = (
        await tx.find<StoredRecord & { enabled?: boolean }>('samlConnections', {
          tenantId: tenant.id,
        })
      ).filter((connection) => connection.enabled !== false).length;
    else if (check === 'directory-sync')
      facts[check] = (
        await tx.find<StoredRecord & { revoked?: boolean }>('scimConnections', {
          tenantId: tenant.id,
        })
      ).filter((connection) => !connection.revoked).length;
    else if (check === 'member-onboarding')
      facts[check] = (
        await tx.find<OnboardingFlow>('onboardingFlows', { tenantId: tenant.id })
      ).filter(
        (flow) => flow.audience === 'member' && flow.enabled && flow.appliesTo !== 'descendants',
      ).length;
  }
  return facts;
}

const checkLabels: Record<OnboardingCheck, string> = {
  'verified-domain': 'verified domain',
  members: 'member',
  owners: 'owner',
  'mfa-policy': '',
  agreement: 'agreement',
  slug: '',
  sso: 'SSO connection',
  'directory-sync': 'directory connection',
  'member-onboarding': 'member onboarding flow',
};
function checkState(step: OnboardingStep, facts: TenantFacts): { done: boolean; detail: string } {
  const check = step.check!;
  const value = facts[check];
  if (typeof value === 'boolean')
    return {
      done: value,
      detail:
        check === 'mfa-policy'
          ? value
            ? 'MFA is required'
            : 'MFA is not required yet'
          : value
            ? 'Sign-in alias set'
            : 'No sign-in alias yet',
    };
  const count = value ?? 0;
  const needed = check === 'members' || check === 'owners' ? (step.minimum ?? 2) : 1;
  const label = checkLabels[check];
  return {
    done: count >= needed,
    detail: `${Math.min(count, needed)} of ${needed} ${label}${needed === 1 ? '' : 's'}`,
  };
}

/** The state of each step and of the whole flow for one subject. */
export function evaluateFlow(
  candidate: CandidateFlow,
  progress: OnboardingProgress | undefined,
  facts: { member?: { identity: Identity; facts: MemberFacts }; tenant?: TenantFacts },
  options: { answers?: boolean } = {},
): OnboardingFlowStatus {
  const { flow, source } = candidate;
  const records = new Map((progress?.steps ?? []).map((record) => [record.stepId, record]));
  const steps = flow.steps.map((step): OnboardingStepStatus => {
    const record = records.get(step.id);
    const status: OnboardingStepStatus = {
      ...step,
      optional: step.optional === true,
      state: 'pending',
    };
    if (record?.completedAt !== undefined) status.completedAt = record.completedAt;
    if (options.answers && record?.answers) status.answers = record.answers;
    switch (step.kind) {
      case 'form':
      case 'acknowledge':
        if (record?.completedAt !== undefined) status.state = 'complete';
        break;
      case 'task':
        if (record?.completedAt !== undefined) status.state = 'complete';
        else if (record?.submittedAt !== undefined) {
          status.state = 'submitted';
          status.submittedAt = record.submittedAt;
        } else if (record?.rejectedAt !== undefined) {
          status.state = 'rejected';
          status.rejectedAt = record.rejectedAt;
          if (record.note) status.note = record.note;
        }
        break;
      case 'verify-email':
        status.state = facts.member?.identity.emailVerified ? 'complete' : 'pending';
        break;
      case 'mfa':
        status.state = facts.member?.facts.mfa ? 'complete' : 'pending';
        break;
      case 'passkey':
        status.state = (facts.member?.facts.passkeys ?? 0) > 0 ? 'complete' : 'pending';
        break;
      case 'agreement': {
        const found = facts.member?.facts.agreements?.get(step.agreement!.toLowerCase());
        status.state = !found ? 'unavailable' : found.accepted ? 'complete' : 'pending';
        if (!found) status.detail = 'Your organization has not published this agreement';
        break;
      }
      case 'check': {
        const { done, detail } = checkState(step, facts.tenant ?? {});
        status.state = done ? 'complete' : 'pending';
        status.detail = detail;
        break;
      }
    }
    return status;
  });
  const counted = steps.filter((step) => !step.optional && step.state !== 'unavailable');
  const done = counted.filter((step) => step.state === 'complete').length;
  const result: OnboardingFlowStatus = {
    id: flow.id,
    name: flow.name,
    ...(flow.description ? { description: flow.description } : {}),
    audience: flow.audience,
    required: flow.required,
    locked: flow.locked,
    version: flow.version,
    source: sourceOf(source),
    inherited: candidate.inherited,
    steps,
    complete: done === counted.length,
    done,
    total: counted.length,
  };
  if (progress?.completedAt !== undefined && result.complete)
    result.completedAt = progress.completedAt;
  return result;
}

export const sourceOf = (tenant: Tenant): OnboardingSource => ({
  tenantId: tenant.id,
  name: tenant.name,
  type: tenant.type,
});

export const onboardingContextKeys = ['principal.onboarding', 'principal.pendingOnboarding'];
/** Whether any statement of the documents names an onboarding context key in a condition. */
export function mentionsOnboarding(documents: Iterable<PolicyDocument>): boolean {
  for (const document of documents)
    for (const statement of document.statements)
      for (const block of Object.values(statement.conditions ?? {}))
        if (block && onboardingContextKeys.some((key) => Object.hasOwn(block, key))) return true;
  return false;
}

/**
 * Policy context for a person in their own tenant: `principal.onboarding` names the member flows they have
 * completed, and `principal.pendingOnboarding` counts required ones still open. Service accounts are never onboarded.
 */
export async function onboardingContext(
  tx: IamStore,
  chain: Tenant[],
  identity: Identity,
  now: number,
): Promise<{ 'principal.onboarding': string[]; 'principal.pendingOnboarding': number }> {
  const none = { 'principal.onboarding': [], 'principal.pendingOnboarding': 0 };
  if (identity.kind !== 'user' || chain[0]?.id !== identity.tenantId) return none;
  const flows = await flowsForIdentity(tx, chain, identity, now);
  if (!flows.length) return none;
  const progress = new Map(
    (
      await tx.find<OnboardingProgress>('onboardingProgress', {
        tenantId: identity.tenantId,
        subjectId: identity.id,
      })
    ).map((record) => [record.flowId, record]),
  );
  const facts = await memberFacts(
    tx,
    identity,
    flows.map((candidate) => candidate.flow),
    now,
  );
  const completed: string[] = [];
  let pending = 0;
  for (const candidate of flows) {
    const status = evaluateFlow(candidate, progress.get(candidate.flow.id), {
      member: { identity, facts },
    });
    if (status.complete) completed.push(candidate.flow.name);
    else if (candidate.flow.required) pending++;
  }
  return {
    'principal.onboarding': [...new Set(completed)].sort(),
    'principal.pendingOnboarding': pending,
  };
}

/** Welcome copy and support contacts: for each value, the nearest tenant in the chain that set it wins. */
export async function resolveSettings(
  chain: Tenant[],
  settings: SettingsReader,
): Promise<ResolvedOnboardingSettings> {
  const resolved: ResolvedOnboardingSettings = { sources: {} };
  for (const tenant of chain) {
    const record = await settings.get(tenant.id);
    if (!record) continue;
    for (const key of ['welcomeTitle', 'welcomeMessage', 'supportEmail', 'supportUrl'] as const)
      if (resolved[key] === undefined && record[key] !== undefined) {
        resolved[key] = record[key];
        resolved.sources[key] = sourceOf(tenant);
      }
  }
  return resolved;
}

/** The administrator-written part of a tenant's onboarding settings. */
export interface OnboardingSettingsValues {
  welcomeTitle?: string;
  welcomeMessage?: string;
  supportEmail?: string;
  supportUrl?: string;
  disabledFlowIds: string[];
}
/** Validates settings input (replace semantics); `disabledFlowIds` is checked against the inherited flows by the caller. */
export function parseSettings(input: Record<string, unknown>): OnboardingSettingsValues {
  only(
    input,
    ['tenantId', 'welcomeTitle', 'welcomeMessage', 'supportEmail', 'supportUrl', 'disabledFlowIds'],
    'settings',
  );
  const optional = <T>(value: unknown, parse: (value: unknown) => T): T | undefined =>
    value === undefined || value === null || value === '' ? undefined : parse(value);
  const welcomeTitle = optional(input.welcomeTitle, (value) =>
    text(value, 'welcomeTitle', 120).trim(),
  );
  const welcomeMessage = optional(input.welcomeMessage, (value) =>
    longText(value, 'welcomeMessage', 5_000),
  );
  const supportEmail = optional(input.supportEmail, emailAddress);
  const supportUrl = optional(input.supportUrl, (value) => httpUrl(value, 'supportUrl'));
  const disabled = input.disabledFlowIds ?? [];
  if (!Array.isArray(disabled) || disabled.length > 100)
    throw new IamError('INVALID_INPUT', 'disabledFlowIds must list at most 100 flows');
  return {
    ...(welcomeTitle !== undefined ? { welcomeTitle } : {}),
    ...(welcomeMessage !== undefined ? { welcomeMessage } : {}),
    ...(supportEmail !== undefined ? { supportEmail } : {}),
    ...(supportUrl !== undefined ? { supportUrl } : {}),
    disabledFlowIds: [
      ...new Set(disabled.map((flowId) => text(flowId, 'disabledFlowIds', 128))),
    ].sort(),
  };
}

/**
 * Validates a form step's answers: every required field present, values of the declared type and within bounds.
 * Unknown answer keys are refused. Returns the answers to record (empty optional fields left out).
 */
export function parseAnswers(step: OnboardingStep, value: unknown): Record<string, Json> {
  if (value === undefined) value = {};
  if (!plainObject(value)) throw new IamError('INVALID_INPUT', 'answers must be an object');
  const fields = new Map(step.fields!.map((field) => [field.name, field]));
  for (const key of Object.keys(value))
    if (!fields.has(key)) throw new IamError('INVALID_INPUT', `Unknown answer ${key}`);
  const answers: Record<string, Json> = {};
  for (const field of step.fields!) {
    const raw = Object.hasOwn(value, field.name) ? value[field.name] : undefined;
    const empty =
      raw === undefined ||
      raw === null ||
      (typeof raw === 'string' && !raw.trim()) ||
      (field.type === 'boolean' && raw === false);
    if (empty) {
      if (field.required)
        throw new IamError(
          'INVALID_INPUT',
          field.type === 'boolean'
            ? `${field.label} must be confirmed`
            : `${field.label} is required`,
        );
      if (field.type === 'boolean' && raw === false) answers[field.name] = false;
      continue;
    }
    const invalid = () => new IamError('INVALID_INPUT', `${field.label} is not valid`);
    switch (field.type) {
      case 'text': {
        if (typeof raw !== 'string') throw invalid();
        const trimmed = raw.trim();
        if (trimmed.length > (field.maxLength ?? 200) || /[\u0000-\u001f\u007f]/.test(trimmed))
          throw invalid();
        answers[field.name] = trimmed;
        break;
      }
      case 'textarea': {
        if (typeof raw !== 'string') throw invalid();
        if (raw.length > (field.maxLength ?? 2_000)) throw invalid();
        answers[field.name] = longText(raw, field.label, field.maxLength ?? 2_000);
        break;
      }
      case 'email':
        try {
          answers[field.name] = emailAddress(raw);
        } catch {
          throw invalid();
        }
        break;
      case 'url':
        try {
          answers[field.name] = httpUrl(raw, field.label);
        } catch {
          throw invalid();
        }
        break;
      case 'number':
        if (
          typeof raw !== 'number' ||
          !Number.isFinite(raw) ||
          (field.min !== undefined && raw < field.min) ||
          (field.max !== undefined && raw > field.max)
        )
          throw invalid();
        answers[field.name] = raw;
        break;
      case 'boolean':
        if (typeof raw !== 'boolean') throw invalid();
        answers[field.name] = raw;
        break;
      case 'select':
        if (typeof raw !== 'string' || !field.options!.includes(raw)) throw invalid();
        answers[field.name] = raw;
        break;
      case 'date': {
        if (typeof raw !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(raw)) throw invalid();
        const date = new Date(`${raw}T00:00:00Z`);
        if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== raw)
          throw invalid();
        answers[field.name] = raw;
        break;
      }
    }
  }
  return answers;
}

/** A flow record without the fields only the defining tenant needs; what descendants and members see. */
export function publicFlow(flow: OnboardingFlow): OnboardingFlow {
  const { completionGroupIds: _groups, authorId: _author, ...rest } = flow;
  return rest;
}
