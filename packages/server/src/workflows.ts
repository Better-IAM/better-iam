import { createHash } from 'node:crypto';
import {
  IamError,
  canonicalJson,
  type AttributeType,
  type Identity,
  type Json,
  type StoredRecord,
} from '@better-iam/core';
import { parseAutoAssign, type AutoAssignInput, type RuleEnvironment } from './package-rules.js';
import { integer, object, text } from './validation.js';

/**
 * Identity lifecycle workflows (joiner, mover, leaver): a trigger, a scope in the access-package rule language, and
 * a list of steps that run for each person the trigger fires for, under the authority of the administrator who saved
 * the workflow (re-checked when each step runs). Pure: validation and trigger computation, no store access.
 */

/**
 * What starts a run for a person:
 * - `joiner`: the person is active and joined after the workflow was enabled (or already existed, with
 *   `includeExisting`);
 * - `mover`: one of the watched attributes (declared identity attributes, or `managerId`) changed;
 * - `leaver`: the person was disabled (by an administrator, offboarding, or account expiry);
 * - `date`: `offsetDays` after (or before, when negative) a date the person carries: a declared string attribute
 *   holding an ISO date such as `startDate`, or `createdAt` / `expiresAt`;
 * - `manual`: only `workflows.run`.
 */
export type WorkflowTrigger =
  | { kind: 'joiner' }
  | { kind: 'mover'; attributes: string[] }
  | { kind: 'leaver' }
  | { kind: 'date'; attribute: string; offsetDays: number }
  | { kind: 'manual' };

/** One step. Steps run in order; `wait` pauses the run. */
export type WorkflowStep =
  | { kind: 'add-to-group'; groupId: string; days?: number }
  | { kind: 'remove-from-group'; groupId: string }
  | { kind: 'remove-from-all-groups' }
  | { kind: 'assign-package'; packageId: string; days?: number }
  | { kind: 'revoke-packages'; packageId?: string }
  | { kind: 'send-email'; to: string; subject: string; body: string }
  | { kind: 'revoke-sessions' }
  | { kind: 'disable' }
  | { kind: 'enable' }
  | { kind: 'set-attributes'; attributes: Record<string, Json | null> }
  | { kind: 'set-expiry'; days: number | null }
  | { kind: 'delete' }
  | { kind: 'emit-event'; name: string }
  | { kind: 'wait'; hours: number };
export type WorkflowStepKind = WorkflowStep['kind'];
export const workflowStepKinds: readonly WorkflowStepKind[] = [
  'add-to-group',
  'remove-from-group',
  'remove-from-all-groups',
  'assign-package',
  'revoke-packages',
  'send-email',
  'revoke-sessions',
  'disable',
  'enable',
  'set-attributes',
  'set-expiry',
  'delete',
  'emit-event',
  'wait',
];
/** Steps that take something away; workflows with any of them default to a lower daily brake. */
export const destructiveSteps: ReadonlySet<WorkflowStepKind> = new Set([
  'remove-from-all-groups',
  'revoke-packages',
  'revoke-sessions',
  'disable',
  'delete',
]);

export interface Workflow extends StoredRecord {
  name: string;
  description?: string;
  enabled: boolean;
  trigger: WorkflowTrigger;
  /** Which people the workflow applies to; absent = every active person (service accounts and agents excluded). */
  scope?: AutoAssignInput;
  steps: WorkflowStep[];
  /** Joiner workflows: also run for people who were already active when the workflow was enabled. */
  includeExisting: boolean;
  /** At most this many runs start per day; more stops the workflow for the day (`workflow:brake`). */
  maxRunsPerDay: number;
  /** The administrator whose rights the steps use (whoever last saved the workflow). */
  ownerId: string;
  /** Whether the owner saved it from a session with a second factor; runs carry it into their decisions. */
  ownerMfa: boolean;
  version: number;
  /** The daily brake's counter: the UTC day and how many automatic runs started on it. */
  startedOn?: string;
  startedToday?: number;
  /** When the workflow was (last) enabled: joiners and dates before it do not fire. */
  activeSince: number;
  /** The day (`YYYY-MM-DD`, UTC) the brake last stopped the workflow, so it is reported once. */
  brakedOn?: string;
  createdAt: number;
  updatedAt: number;
}

export type WorkflowRunStatus = 'pending' | 'running' | 'waiting' | 'completed' | 'failed' | 'cancelled';
export interface WorkflowStepResult {
  index: number;
  kind: WorkflowStepKind;
  outcome: 'done' | 'skipped' | 'failed';
  at: number;
  detail?: string;
  code?: string;
}
/** One run of a workflow for one person (uniqueKey `{workflowId}:{identityId}:{occurrence}`). */
export interface WorkflowRun extends StoredRecord {
  workflowId: string;
  workflowName: string;
  workflowVersion: number;
  identityId: string;
  /** What fired: `joiner`, `mover:{n}`, `leaver:{n}`, `date:{target}`, or `manual:{id}`. */
  occurrence: string;
  trigger: WorkflowTrigger['kind'];
  /** The steps as they were when the run started; later edits apply to new runs only. */
  steps: WorkflowStep[];
  /** Whose rights the steps use: the owner who approved these steps (when the run started), not a later editor. */
  ownerId: string;
  ownerMfa: boolean;
  /** Finished runs are kept 180 days, then the retention sweep removes them. */
  expiresAt?: number;
  status: WorkflowRunStatus;
  stepIndex: number;
  nextAt: number;
  results: WorkflowStepResult[];
  startedAt: number;
  finishedAt?: number;
  startedBy?: string;
  error?: { code: string; message: string };
  leaseToken?: string;
  leaseUntil?: number;
}

/** What mover and leaver triggers compare against (uniqueKey `{workflowId}:{identityId}`). */
export interface WorkflowSubject extends StoredRecord {
  workflowId: string;
  identityId: string;
  values: Record<string, Json>;
  status: Identity['status'];
  /** How many times the trigger fired for this person, so the same change twice fires twice. */
  fired: number;
  /** The latest occurrences that started a run (joiner, dates), so each fires once even after its run expired. */
  occurrences?: string[];
}

export const maxSteps = 20;
export const maxWaits = 5;
const maxWaitHours = 365 * 24;
export const dayMs = 86_400_000;

const plain = (value: unknown): value is Record<string, unknown> =>
  typeof value === 'object' && value !== null && !Array.isArray(value);

function days(value: unknown, name: string): number {
  return integer(value, name, 1, 3650);
}

/** Validates a trigger against the deployment's declared identity attributes. */
export function parseTrigger(
  value: unknown,
  attributes: Record<string, AttributeType>,
): WorkflowTrigger {
  const input = object(value);
  switch (input.kind) {
    case 'joiner':
    case 'leaver':
    case 'manual':
      return { kind: input.kind };
    case 'mover': {
      if (!Array.isArray(input.attributes) || !input.attributes.length || input.attributes.length > 20)
        throw new IamError('INVALID_INPUT', 'trigger.attributes must name 1-20 attributes to watch');
      const watched = [...new Set(input.attributes.map((name) => text(name, 'trigger.attributes', 64)))];
      for (const name of watched)
        if (name !== 'managerId' && !Object.hasOwn(attributes, name))
          throw new IamError(
            'INVALID_INPUT',
            `trigger.attributes: ${name} is not a declared identity attribute (or managerId)`,
          );
      return { kind: 'mover', attributes: watched.sort() };
    }
    case 'date': {
      const attribute = text(input.attribute, 'trigger.attribute', 64);
      if (
        attribute !== 'createdAt' &&
        attribute !== 'expiresAt' &&
        !(Object.hasOwn(attributes, attribute) && attributes[attribute] === 'string')
      )
        throw new IamError(
          'INVALID_INPUT',
          'trigger.attribute must be createdAt, expiresAt, or a declared string attribute holding an ISO date',
        );
      return {
        kind: 'date',
        attribute,
        offsetDays: integer(input.offsetDays ?? 0, 'trigger.offsetDays', -365, 3650),
      };
    }
    default:
      throw new IamError(
        'INVALID_INPUT',
        'trigger.kind must be joiner, mover, leaver, date or manual',
      );
  }
}

const emailRecipient = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/** Validates the steps (references to groups and packages are checked against the store by the caller). */
export function parseSteps(
  value: unknown,
  attributes: Record<string, AttributeType>,
): WorkflowStep[] {
  if (!Array.isArray(value) || !value.length || value.length > maxSteps)
    throw new IamError('INVALID_INPUT', `steps must list 1-${maxSteps} steps`);
  let waits = 0;
  const steps = value.map((raw, index): WorkflowStep => {
    const path = `steps[${index}]`;
    if (!plain(raw)) throw new IamError('INVALID_INPUT', `${path} must be an object`);
    const kind = raw.kind;
    const only = (...keys: string[]) => {
      for (const key of Object.keys(raw))
        if (key !== 'kind' && !keys.includes(key))
          throw new IamError('INVALID_INPUT', `${path}: unknown field ${key}`);
    };
    switch (kind) {
      case 'add-to-group':
        only('groupId', 'days');
        return {
          kind,
          groupId: text(raw.groupId, `${path}.groupId`),
          ...(raw.days !== undefined ? { days: days(raw.days, `${path}.days`) } : {}),
        };
      case 'remove-from-group':
        only('groupId');
        return { kind, groupId: text(raw.groupId, `${path}.groupId`) };
      case 'assign-package':
        only('packageId', 'days');
        return {
          kind,
          packageId: text(raw.packageId, `${path}.packageId`),
          ...(raw.days !== undefined ? { days: days(raw.days, `${path}.days`) } : {}),
        };
      case 'revoke-packages':
        only('packageId');
        return {
          kind,
          ...(raw.packageId !== undefined
            ? { packageId: text(raw.packageId, `${path}.packageId`) }
            : {}),
        };
      case 'send-email': {
        only('to', 'subject', 'body');
        const to = text(raw.to, `${path}.to`, 254).trim().toLowerCase();
        if (to !== 'subject' && to !== 'manager' && !emailRecipient.test(to))
          throw new IamError(
            'INVALID_INPUT',
            `${path}.to must be subject, manager, or an email address`,
          );
        const subject = text(raw.subject, `${path}.subject`, 200);
        const body = raw.body;
        if (
          typeof body !== 'string' ||
          !body.trim() ||
          body.length > 5000 ||
          /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.test(body)
        )
          throw new IamError('INVALID_INPUT', `${path}.body must be text of at most 5000 characters`);
        return { kind, to, subject, body };
      }
      case 'remove-from-all-groups':
      case 'revoke-sessions':
      case 'disable':
      case 'enable':
      case 'delete':
        only();
        return { kind };
      case 'set-attributes': {
        only('attributes');
        if (!plain(raw.attributes) || !Object.keys(raw.attributes).length)
          throw new IamError('INVALID_INPUT', `${path}.attributes must set at least one attribute`);
        const result: Record<string, Json | null> = {};
        for (const [name, entry] of Object.entries(raw.attributes)) {
          const type = Object.hasOwn(attributes, name) ? attributes[name] : undefined;
          if (!type)
            throw new IamError(
              'INVALID_INPUT',
              `${path}.attributes: ${name} is not a declared identity attribute`,
            );
          if (
            entry !== null &&
            (typeof entry !== type ||
              (type === 'string' &&
                ((entry as string).length > 2048 || /[\u0000-\u001f]/.test(entry as string))) ||
              (type === 'number' && !Number.isFinite(entry)))
          )
            throw new IamError(
              'INVALID_INPUT',
              `${path}.attributes: ${name} must be a ${type} (or null to clear it)`,
            );
          result[name] = entry as Json | null;
        }
        return { kind, attributes: result };
      }
      case 'set-expiry':
        only('days');
        return { kind, days: raw.days === null ? null : days(raw.days, `${path}.days`) };
      case 'emit-event': {
        only('name');
        const name = text(raw.name, `${path}.name`, 64);
        if (!/^[a-z][a-z0-9._-]{0,63}$/.test(name))
          throw new IamError(
            'INVALID_INPUT',
            `${path}.name uses lowercase letters, digits, dots, underscores or hyphens`,
          );
        return { kind, name };
      }
      case 'wait':
        only('hours');
        waits++;
        return { kind, hours: integer(raw.hours, `${path}.hours`, 1, maxWaitHours) };
      default:
        throw new IamError(
          'INVALID_INPUT',
          `${path}.kind must be one of ${workflowStepKinds.join(', ')}`,
        );
    }
  });
  if (waits > maxWaits)
    throw new IamError('INVALID_INPUT', `A workflow may wait at most ${maxWaits} times`);
  if (steps.every((step) => step.kind === 'wait'))
    throw new IamError('INVALID_INPUT', 'A workflow needs at least one step that does something');
  if (steps.at(-1)!.kind === 'wait')
    throw new IamError('INVALID_INPUT', 'A workflow cannot end with a wait');
  const deleteAt = steps.findIndex((step) => step.kind === 'delete');
  if (deleteAt !== -1 && deleteAt !== steps.length - 1)
    throw new IamError('INVALID_INPUT', 'delete must be the last step');
  return steps;
}

/** Validates a scope in the access-package rule language (`include` / `exclude` condition sets). */
export function parseScope(value: unknown, env: RuleEnvironment): AutoAssignInput | undefined {
  if (value === undefined || value === null) return undefined;
  if (!plain(value)) throw new IamError('INVALID_INPUT', 'scope must be an object');
  for (const key of Object.keys(value))
    if (key !== 'include' && key !== 'exclude')
      throw new IamError('INVALID_INPUT', `scope: unknown field ${key} (use include and exclude)`);
  const parsed = parseAutoAssign(value, env, 'scope');
  return {
    include: parsed.include,
    ...(parsed.exclude?.length ? { exclude: parsed.exclude } : {}),
  };
}

/** The daily run brake: lower when a workflow takes access away. */
export function defaultBrake(steps: WorkflowStep[]): number {
  return steps.some((step) => destructiveSteps.has(step.kind)) ? 25 : 200;
}

const utcDay = (at: number): string => new Date(at).toISOString().slice(0, 10);
export { utcDay };

/** The values a mover trigger watches, as the snapshot stores them. */
export function watchedValues(
  trigger: Extract<WorkflowTrigger, { kind: 'mover' }>,
  identity: Identity,
): Record<string, Json> {
  const values: Record<string, Json> = {};
  for (const name of trigger.attributes) {
    const value = name === 'managerId' ? identity.managerId : identity.attributes?.[name];
    values[name] = value === undefined ? null : (value as Json);
  }
  return values;
}

const digest = (value: Json): string =>
  createHash('sha256').update(canonicalJson(value)).digest('hex').slice(0, 16);

/** The instant a date trigger fires for an identity, or undefined when the identity carries no usable date. */
export function dateTarget(
  trigger: Extract<WorkflowTrigger, { kind: 'date' }>,
  identity: Identity,
): number | undefined {
  let base: number | undefined;
  if (trigger.attribute === 'createdAt') base = identity.createdAt;
  else if (trigger.attribute === 'expiresAt') base = identity.expiresAt;
  else {
    const raw = identity.attributes?.[trigger.attribute];
    // A date (read as UTC midnight) or a full timestamp with its offset; a local time without one is ambiguous.
    if (
      typeof raw === 'string' &&
      /^\d{4}-\d{2}-\d{2}(?:T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,9})?)?(?:Z|[+-]\d{2}:\d{2}))?$/.test(raw)
    ) {
      const parsed = Date.parse(raw.length === 10 ? `${raw}T00:00:00Z` : raw);
      if (Number.isFinite(parsed)) base = parsed;
    }
  }
  return base === undefined ? undefined : base + trigger.offsetDays * dayMs;
}

/**
 * Whether the trigger fires for an identity now, and the snapshot to keep for mover and leaver triggers. `occurrence`
 * names the firing so each change runs once; the caller skips occurrences that already have a run.
 */
export function triggerOccurrence(
  workflow: Pick<Workflow, 'trigger' | 'activeSince' | 'includeExisting'>,
  identity: Identity,
  snapshot: Pick<WorkflowSubject, 'values' | 'status' | 'fired'> | undefined,
  now: number,
): {
  occurrence?: string;
  snapshot?: Pick<WorkflowSubject, 'values' | 'status' | 'fired'>;
} {
  const { trigger } = workflow;
  switch (trigger.kind) {
    case 'joiner':
      return identity.status === 'active' &&
        (workflow.includeExisting || identity.createdAt >= workflow.activeSince)
        ? { occurrence: 'joiner' }
        : {};
    case 'mover': {
      const values = watchedValues(trigger, identity);
      if (!snapshot) return { snapshot: { values, status: identity.status, fired: 0 } };
      if (digest(values) === digest(snapshot.values)) return {};
      const fired = snapshot.fired + 1;
      return {
        ...(identity.status === 'active' ? { occurrence: `mover:${fired}:${digest(values)}` } : {}),
        snapshot: { values, status: identity.status, fired },
      };
    }
    case 'leaver': {
      if (!snapshot) return { snapshot: { values: {}, status: identity.status, fired: 0 } };
      if (snapshot.status === identity.status) return {};
      const leaving = snapshot.status === 'active' && identity.status === 'disabled';
      const fired = snapshot.fired + (leaving ? 1 : 0);
      return {
        ...(leaving ? { occurrence: `leaver:${fired}` } : {}),
        snapshot: { values: {}, status: identity.status, fired },
      };
    }
    case 'date': {
      if (identity.status !== 'active') return {};
      const target = dateTarget(trigger, identity);
      // Dates well before the workflow existed never fire; a date that moves fires again.
      if (target === undefined || target > now || target < workflow.activeSince - dayMs) return {};
      return { occurrence: `date:${utcDay(target)}` };
    }
    case 'manual':
      return {};
  }
}

/** Fills `{name}`, `{email}`, `{organization}`, `{workflow}` and `{attribute.<name>}` in an email template. */
export function fillTemplate(
  template: string,
  values: { identity: Identity; organization: string; workflow: string },
): string {
  return template.replace(/\{([a-zA-Z][\w.]{0,80})\}/g, (match, key: string) => {
    if (key === 'name') return values.identity.name;
    if (key === 'email') return values.identity.email ?? '';
    if (key === 'organization') return values.organization;
    if (key === 'workflow') return values.workflow;
    if (key.startsWith('attribute.')) {
      const value = values.identity.attributes?.[key.slice('attribute.'.length)];
      return value === undefined || value === null ? '' : String(value);
    }
    return match;
  });
}
