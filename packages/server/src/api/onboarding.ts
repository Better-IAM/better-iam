import {
  IamError,
  type AttributeType,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import { attributeValues } from '../catalog.js';
import type { ServerContext } from '../context.js';
import type { Binding, Group, GroupMember } from '../models.js';
import {
  automaticSteps,
  candidateFlows,
  evaluateFlow,
  flowAppliesTo,
  flowsForIdentity,
  liveGroupIds,
  longText,
  maxCompletionGroups,
  maxFlowsPerTenant,
  memberFacts,
  parseAnswers,
  parseRule,
  parseSettings,
  parseSteps,
  progressId,
  publicFlow,
  resolveSettings,
  settingsId,
  SettingsReader,
  sourceOf,
  tenantFacts,
  tenantFlowApplies,
  type CandidateFlow,
  type OnboardingAudience,
  type OnboardingFlow,
  type OnboardingFlowStatus,
  type OnboardingProgress,
  type OnboardingRule,
  type OnboardingScope,
  type OnboardingSettings,
  type OnboardingSource,
  type OnboardingStep,
  type OnboardingStepRecord,
  type ResolvedOnboardingSettings,
} from '../onboarding.js';
import { invariantSnapshot, invariantVerify } from '../invariants.js';
import { actsInOwnRight } from '../session-kinds.js';
import { sodAssertIdentity } from '../sod.js';
import { assertNotTeamGroup, teamChainBindings, teamsSyncingFrom } from '../teams.js';
import { id } from '../utils.js';
import { text } from '../validation.js';
import { afterIdentityChange } from './package-automation.js';
import { allow } from './packages.js';

export interface OnboardingFlowInput {
  name: string;
  description?: string | null;
  audience: OnboardingAudience;
  /**
   * `tenant` (the defining tenant's own members), `descendants` (tenants below it) or `subtree` (both). Defaults to
   * `descendants` for tenant flows and flows defined at the platform root, `tenant` elsewhere.
   */
  appliesTo?: OnboardingScope;
  tenantTypes?: string[] | null;
  rule?: OnboardingRule | null;
  required?: boolean;
  locked?: boolean;
  includeExisting?: boolean;
  enabled?: boolean;
  steps: unknown[];
  completionGroupIds?: string[] | null;
}
export type OnboardingFlowUpdate = Partial<Omit<OnboardingFlowInput, 'audience'>> & {
  tenantId: string;
  flowId: string;
};
export interface OnboardingSettingsInput {
  tenantId: string;
  welcomeTitle?: string | null;
  welcomeMessage?: string | null;
  supportEmail?: string | null;
  supportUrl?: string | null;
  disabledFlowIds?: string[];
}
/** What a person (or a tenant being set up) sees: welcome copy and the flows to work through. */
export interface MyOnboarding {
  tenant: OnboardingSource;
  welcome: ResolvedOnboardingSettings;
  flows: OnboardingFlowStatus[];
  /** Required flows still open. */
  pending: number;
  complete: boolean;
}
/** A flow that reaches a tenant, as its administrators see it. */
export interface EffectiveOnboardingFlow {
  /** Inherited flows omit the defining tenant's completion groups and author. */
  flow: OnboardingFlow;
  source: OnboardingSource;
  inherited: boolean;
  /** Switched off for this tenant, by this tenant or one between it and the source. */
  disabledBy?: OnboardingSource;
  /** Whether this tenant may switch the flow off (inherited, unlocked member flows). */
  canDisable: boolean;
}
export interface EffectiveOnboarding {
  tenant: OnboardingSource;
  /** The tenant's ancestry, root first: the levels flows can come from. */
  levels: OnboardingSource[];
  /** Member flows that reach this tenant's people (own and inherited). */
  memberFlows: EffectiveOnboardingFlow[];
  /** Setup flows this tenant's administrators are asked to complete (defined above it). */
  setupFlows: EffectiveOnboardingFlow[];
  /** Every flow this tenant defines (for its own people, the tenants below it, or both), oldest first. */
  ownFlows: OnboardingFlow[];
  /** Tenant types that can exist below this tenant (what `tenantTypes` may name); empty for a leaf type. */
  descendantTypes: string[];
  /** The declared identity attributes form answers may fill, with their types. */
  identityAttributes: Record<string, AttributeType>;
  settings: {
    own?: OnboardingSettings;
    resolved: ResolvedOnboardingSettings;
  };
}
export interface OnboardingSubjectProgress {
  complete: boolean;
  done: number;
  total: number;
  completedAt?: number;
  startedAt?: number;
  /** Admin-verified task steps waiting for a decision. */
  awaiting: string[];
  /** Form answers by step ID (people of the reporting tenant, and tenants a flow defined here sets up). */
  answers?: Record<string, Record<string, Json>>;
  completionError?: string;
}
export interface OnboardingProgressReport {
  flow: {
    id: string;
    name: string;
    audience: OnboardingAudience;
    version: number;
    required: boolean;
    source: OnboardingSource;
    inherited: boolean;
    disabledBy?: OnboardingSource;
  };
  /** Member flows: this tenant's people the flow applies to. */
  members?: Array<
    { identity: { id: string; name: string; email?: string } } & OnboardingSubjectProgress
  >;
  /** Member flows defined here that reach descendant tenants: per-tenant counts, never names. */
  descendants?: Array<{ tenant: OnboardingSource; people: number; complete: number }>;
  /** Tenant flows defined here: every descendant tenant the flow applies to. */
  tenants?: Array<{ tenant: OnboardingSource & { status: string } } & OnboardingSubjectProgress>;
  summary: { subjects: number; complete: number };
  /** More than 1000 descendant tenants: the report covers the first 1000. */
  truncated?: boolean;
}

const maxDescendants = 1000;

/** Onboarding is the caller's own business: an ordinary session (or API key) of the tenant. */
function selfSession(principal: AuthenticatedPrincipal, tenantId: string): void {
  if (
    !actsInOwnRight(principal.session) ||
    principal.session.tenantId !== tenantId ||
    principal.identity.tenantId !== tenantId
  )
    throw new IamError(
      'ACCESS_DENIED',
      'Onboarding is completed from an ordinary session of its tenant',
      403,
    );
}
function notImpersonating(principal: AuthenticatedPrincipal, what: string): void {
  if (principal.session.impersonatorId)
    throw new IamError('IMPERSONATION_RESTRICTED', `${what} while impersonating`, 403);
}

async function flowRecord(tx: IamStore, flowId: unknown): Promise<OnboardingFlow> {
  const flow = await tx.get<OnboardingFlow>('onboardingFlows', text(flowId, 'flowId', 128));
  if (!flow) throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
  return flow;
}

/** Every tenant below `root`, breadth first, at most `maxDescendants`. */
async function descendantsOf(
  tx: IamStore,
  root: Tenant,
): Promise<{ tenants: Tenant[]; truncated: boolean }> {
  const tenants: Tenant[] = [];
  let frontier = [root.id];
  while (frontier.length) {
    const next: string[] = [];
    for (const parentId of frontier)
      for (const child of (await tx.find<Tenant>('tenants', { parentId })).sort(
        (a, b) => a.createdAt - b.createdAt,
      )) {
        if (tenants.length >= maxDescendants) return { tenants, truncated: true };
        tenants.push(child);
        next.push(child.id);
      }
    frontier = next;
  }
  return { tenants, truncated: false };
}

/** The tenant types that can appear below a tenant of `type`, following the hierarchy's allowed children. */
function descendantTypes(ctx: ServerContext, type: string): Set<string> {
  const found = new Set<string>();
  const queue = [...(ctx.config.hierarchy.types[type]?.allowedChildren ?? [])];
  while (queue.length) {
    const next = queue.shift()!;
    if (found.has(next)) continue;
    found.add(next);
    queue.push(...(ctx.config.hierarchy.types[next]?.allowedChildren ?? []));
  }
  return found;
}

const sameJson = (a: unknown, b: unknown) => JSON.stringify(a) === JSON.stringify(b);

/**
 * Whether `principal` may put people into a completion group: iam:groups:update on it and the use of the grant
 * authority behind each of its bindings, and behind those of the teams that sync from it (and of the teams above
 * them), since team sync copies the group's members there.
 */
async function authorizeCompletionGroup(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  groupId: string,
): Promise<void> {
  await allow(
    ctx,
    tx,
    principal,
    tenantId,
    'iam:groups:update',
    groupId,
    'add people to a completion group',
  );
  const syncing = (await teamsSyncingFrom(tx, tenantId, groupId)).map((team) => team.id);
  for (const binding of [
    ...(await tx.find<Binding>('bindings', { tenantId, subjectType: 'group', subjectId: groupId })),
    ...(await teamChainBindings(tx, tenantId, syncing)),
  ])
    await ctx.grantingAuthority(tx, principal, tenantId, binding.authorityId);
}

/**
 * Whether the flow's owner (`groupsOwnerId`) may still put people into a completion group: active, and passing the
 * check `saveFlow` made. Groups whose authority the owner lost (demoted, revoked, left) are skipped, like the
 * automatic rules of access packages whose owner lost the rights.
 */
async function ownerMayGrant(
  ctx: ServerContext,
  tx: IamStore,
  owner: Identity | undefined,
  tenantId: string,
  groupId: string,
): Promise<boolean> {
  if (!owner || owner.status !== 'active' || ctx.identityExpired(owner)) return false;
  try {
    await authorizeCompletionGroup(
      ctx,
      tx,
      ctx.decisions.simulatedPrincipal(owner, true),
      tenantId,
      groupId,
    );
    return true;
  } catch {
    return false;
  }
}

/**
 * Validates and stores a flow (a new one without `previous`). Answers that fill identity attributes need
 * iam:identities:update, and completion groups need iam:groups:update on each group plus the use of the grant
 * authorities behind the group's bindings, because finishing the flow makes the person a member. Every completion
 * group is checked again whenever a change alters who completes the flow or when (steps, rule, scope,
 * includeExisting, new groups), and the editor then becomes the owner the groups are applied under.
 */
async function saveFlow(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenant: Tenant,
  input: Partial<OnboardingFlowInput>,
  previous?: OnboardingFlow,
): Promise<OnboardingFlow> {
  const audience = previous?.audience ?? input.audience;
  if (audience !== 'member' && audience !== 'tenant')
    throw new IamError('INVALID_INPUT', 'audience must be member or tenant');
  if (previous && input.audience !== undefined && input.audience !== previous.audience)
    throw new IamError('INVALID_INPUT', 'A flow keeps its audience; create a new flow instead');
  const name = text(input.name ?? previous?.name, 'name', 100).trim();
  const description =
    input.description === undefined
      ? previous?.description
      : input.description === null || input.description === ''
        ? undefined
        : longText(input.description, 'description', 2_000);
  const below = descendantTypes(ctx, tenant.type);
  const appliesTo: OnboardingScope =
    input.appliesTo ??
    previous?.appliesTo ??
    (audience === 'tenant' || tenant.parentId === null ? 'descendants' : 'tenant');
  if (!['tenant', 'descendants', 'subtree'].includes(appliesTo))
    throw new IamError('INVALID_INPUT', 'appliesTo must be tenant, descendants or subtree');
  if (audience === 'tenant' && appliesTo !== 'descendants')
    throw new IamError('INVALID_INPUT', 'Tenant setup flows apply to descendant tenants');
  if (appliesTo !== 'tenant' && !below.size)
    throw new IamError(
      'INVALID_INPUT',
      `${tenant.type} tenants have no descendants; use appliesTo: tenant`,
    );
  let tenantTypes =
    input.tenantTypes === undefined
      ? previous?.tenantTypes
      : input.tenantTypes === null
        ? undefined
        : input.tenantTypes;
  if (tenantTypes !== undefined) {
    if (appliesTo === 'tenant')
      throw new IamError('INVALID_INPUT', 'tenantTypes applies to flows that reach descendants');
    if (!Array.isArray(tenantTypes) || tenantTypes.length < 1 || tenantTypes.length > 20)
      throw new IamError('INVALID_INPUT', 'tenantTypes must list 1-20 tenant types');
    tenantTypes = [...new Set(tenantTypes.map((type) => text(type, 'tenantTypes', 64)))].sort();
    for (const type of tenantTypes)
      if (!below.has(type))
        throw new IamError(
          'INVALID_INPUT',
          `tenantTypes: ${type} tenants cannot exist below a ${tenant.type} tenant`,
        );
  }
  const groups = new Set(
    (await tx.find<Group>('groups', { tenantId: tenant.id })).map((group) => group.id),
  );
  const ruleInput = input.rule === undefined ? previous?.rule : (input.rule ?? undefined);
  if (ruleInput !== undefined && audience !== 'member')
    throw new IamError('INVALID_INPUT', 'rule applies to member flows only');
  const rule =
    ruleInput === undefined
      ? undefined
      : parseRule(
          ruleInput,
          ctx.catalog.identityAttributes,
          appliesTo === 'descendants' ? new Set() : groups,
        );
  const flag = (value: unknown, key: string, fallback: boolean) => {
    if (value === undefined) return fallback;
    if (typeof value !== 'boolean') throw new IamError('INVALID_INPUT', `${key} must be a boolean`);
    return value;
  };
  const required = flag(input.required, 'required', previous?.required ?? true);
  const locked = flag(input.locked, 'locked', previous?.locked ?? false);
  const includeExisting = flag(
    input.includeExisting,
    'includeExisting',
    previous?.includeExisting ?? false,
  );
  const enabled = flag(input.enabled, 'enabled', previous?.enabled ?? true);
  if (input.steps === undefined && !previous)
    throw new IamError('INVALID_INPUT', 'steps are required');
  const steps: OnboardingStep[] =
    input.steps === undefined
      ? previous!.steps
      : parseSteps(input.steps, audience, ctx.catalog.identityAttributes);
  const groupInput =
    input.completionGroupIds === undefined
      ? previous?.completionGroupIds
      : (input.completionGroupIds ?? undefined);
  let completionGroupIds: string[] | undefined;
  if (groupInput !== undefined && groupInput.length) {
    if (audience !== 'member' || appliesTo === 'descendants')
      throw new IamError(
        'INVALID_INPUT',
        'completionGroupIds apply to member flows that reach the defining tenant’s own people',
      );
    if (!Array.isArray(groupInput) || groupInput.length > maxCompletionGroups)
      throw new IamError(
        'INVALID_INPUT',
        `completionGroupIds must list at most ${maxCompletionGroups} groups`,
      );
    completionGroupIds = [...new Set(groupInput.map((groupId) => text(groupId, 'groupId', 128)))];
    for (const groupId of completionGroupIds)
      if (!groups.has(groupId)) throw new IamError('NOT_FOUND', `Group ${groupId} not found`, 404);
      // A team's backing group takes its members from the team only (teams.ts).
      else assertNotTeamGroup(await tx.get<Group>('groups', groupId));
  }
  const mapped = steps.some((step) => step.fields?.some((field) => field.attribute !== undefined));
  // Answers fill attributes only for the defining tenant's own people: a tenant has no authority over the identities
  // of the tenants below it, whose policies may grant access by those attributes.
  if (mapped && appliesTo === 'descendants')
    throw new IamError(
      'INVALID_INPUT',
      'Answers fill identity attributes only for the defining tenant’s own people; a flow that reaches only tenants below cannot map fields to attributes',
    );
  const mapsAttributes = input.steps !== undefined && mapped;
  const newGroups = (completionGroupIds ?? []).filter(
    (groupId) => !previous?.completionGroupIds?.includes(groupId),
  );
  // Finishing the flow puts people into its completion groups, so a change to who finishes it or when (easier steps,
  // a wider rule or scope, existing people, resuming it, another group) re-checks every group, not only new ones.
  const reauthorize =
    Boolean(completionGroupIds?.length) &&
    (!previous ||
      newGroups.length > 0 ||
      !sameJson(previous.steps, steps) ||
      !sameJson(previous.rule, rule) ||
      previous.appliesTo !== appliesTo ||
      previous.includeExisting !== includeExisting ||
      (enabled && !previous.enabled));
  if (mapsAttributes || reauthorize) {
    if (!actsInOwnRight(principal.session))
      throw new IamError(
        'INVALID_INPUT',
        'Attribute answers and completion groups are set from an ordinary session or API key',
      );
    notImpersonating(principal, 'Attribute answers and completion groups cannot be set');
  }
  if (mapsAttributes)
    await allow(
      ctx,
      tx,
      principal,
      tenant.id,
      'iam:identities:update',
      tenant.id,
      'let answers fill identity attributes',
    );
  if (reauthorize)
    for (const groupId of completionGroupIds!)
      await authorizeCompletionGroup(ctx, tx, principal, tenant.id, groupId);
  // The groups stand on the authority of whoever last passed that check (kept by edits that change nothing of it).
  let groupsOwnerId = reauthorize
    ? principal.identity.id
    : (previous?.groupsOwnerId ?? previous?.authorId);
  // Naming the groups again hands them to an editor who passes the check (how an administrator takes over the groups
  // of an owner who lost the authority); an editor who does not pass it leaves the owner as it was.
  if (
    !reauthorize &&
    completionGroupIds?.length &&
    input.completionGroupIds !== undefined &&
    groupsOwnerId !== principal.identity.id &&
    actsInOwnRight(principal.session) &&
    !principal.session.impersonatorId
  )
    try {
      for (const groupId of completionGroupIds)
        await authorizeCompletionGroup(ctx, tx, principal, tenant.id, groupId);
      groupsOwnerId = principal.identity.id;
    } catch {
      /* the owner stays */
    }
  const others = (await tx.find<OnboardingFlow>('onboardingFlows', { tenantId: tenant.id })).filter(
    (flow) => flow.id !== previous?.id,
  );
  const uniqueKey = `name:${name.toLowerCase()}`;
  if (!name) throw new IamError('INVALID_INPUT', 'name is required');
  if (others.some((flow) => flow.uniqueKey === uniqueKey))
    throw new IamError('CONFLICT', 'An onboarding flow with this name exists', 409);
  if (!previous && others.length >= maxFlowsPerTenant)
    throw new IamError('LIMIT_EXCEEDED', `At most ${maxFlowsPerTenant} onboarding flows`, 409);
  const now = ctx.now();
  const record: OnboardingFlow = {
    id: previous?.id ?? id(),
    tenantId: tenant.id,
    uniqueKey,
    name,
    ...(description !== undefined ? { description } : {}),
    audience,
    appliesTo,
    ...(tenantTypes !== undefined ? { tenantTypes } : {}),
    ...(rule !== undefined ? { rule } : {}),
    required,
    locked,
    includeExisting,
    enabled,
    ...(previous?.effectiveFrom !== undefined
      ? { effectiveFrom: previous.effectiveFrom }
      : enabled
        ? { effectiveFrom: now }
        : {}),
    steps,
    ...(completionGroupIds?.length ? { completionGroupIds } : {}),
    ...(completionGroupIds?.length && groupsOwnerId !== undefined ? { groupsOwnerId } : {}),
    version: previous ? previous.version + (sameJson(previous.steps, steps) ? 0 : 1) : 1,
    authorId: principal.identity.id,
    createdAt: previous?.createdAt ?? now,
    updatedAt: now,
  };
  return previous
    ? tx.put<OnboardingFlow>('onboardingFlows', record)
    : tx.insert<OnboardingFlow>('onboardingFlows', record);
}

/** Deletes a flow with every progress record of it, in every tenant it reached. */
export async function deleteOnboardingFlow(tx: IamStore, flow: OnboardingFlow): Promise<number> {
  const progress = await tx.find<OnboardingProgress>('onboardingProgress', { flowId: flow.id });
  for (const record of progress) await tx.delete('onboardingProgress', record.id);
  for (const settings of await tx.find<OnboardingSettings>('onboardingSettings', {}))
    if (settings.disabledFlowIds.includes(flow.id))
      await tx.put<OnboardingSettings>('onboardingSettings', {
        ...settings,
        disabledFlowIds: settings.disabledFlowIds.filter((flowId) => flowId !== flow.id),
      });
  await tx.delete('onboardingFlows', flow.id);
  return progress.length;
}

async function progressFor(
  tx: IamStore,
  tenantId: string,
  subjectId: string,
): Promise<Map<string, OnboardingProgress>> {
  return new Map(
    (await tx.find<OnboardingProgress>('onboardingProgress', { tenantId, subjectId })).map(
      (record) => [record.flowId, record],
    ),
  );
}

async function upsertProgress(
  tx: IamStore,
  record: OnboardingProgress,
  existed: boolean,
): Promise<OnboardingProgress> {
  return existed
    ? tx.put<OnboardingProgress>('onboardingProgress', record)
    : tx.insert<OnboardingProgress>('onboardingProgress', record);
}

function newProgress(
  flow: OnboardingFlow,
  subject: { type: 'identity' | 'tenant'; id: string; tenantId: string },
  now: number,
): OnboardingProgress {
  return {
    id: progressId(flow.id, subject.id),
    tenantId: subject.tenantId,
    flowId: flow.id,
    flowTenantId: flow.tenantId,
    subjectType: subject.type,
    subjectId: subject.id,
    steps: [],
    startedAt: now,
    updatedAt: now,
  };
}

function withStep(progress: OnboardingProgress, record: OnboardingStepRecord): OnboardingProgress {
  return {
    ...progress,
    steps: [...progress.steps.filter((step) => step.stepId !== record.stepId), record],
  };
}

/**
 * Records flows seen complete that are not yet recorded in their current version (audited `onboarding:complete`),
 * and returns the member flows whose completion groups still need applying.
 */
async function recordCompletions(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  subject: { type: 'identity' | 'tenant'; id: string; tenantId: string },
  statuses: Array<{ candidate: CandidateFlow; status: OnboardingFlowStatus }>,
  progress: Map<string, OnboardingProgress>,
): Promise<string[]> {
  const pendingGroups: string[] = [];
  const now = ctx.now();
  for (const { candidate, status } of statuses) {
    if (!status.complete) continue;
    const { flow } = candidate;
    const existing = progress.get(flow.id);
    let record = existing;
    if (existing?.completedAt === undefined || existing.completedVersion !== flow.version) {
      record = await upsertProgress(
        tx,
        {
          ...(existing ?? newProgress(flow, subject, now)),
          completedAt: now,
          completedVersion: flow.version,
          updatedAt: now,
        },
        existing !== undefined,
      );
      progress.set(flow.id, record);
      status.completedAt = now;
      await ctx.events.audit(
        tx,
        principal,
        'onboarding:complete',
        subject.tenantId,
        subject.id,
        'allow',
        false,
        { flowId: flow.id, flow: flow.name, version: flow.version, subjectType: subject.type },
      );
    }
    if (
      subject.type === 'identity' &&
      flow.completionGroupIds?.length &&
      record!.groupsAppliedVersion !== flow.version
    )
      pendingGroups.push(flow.id);
  }
  return pendingGroups;
}

/**
 * Makes a person a member of the completion groups of flows they finished, one transaction per flow so a
 * separation-of-duties or invariant refusal in one leaves the others (and the recorded completion) in place. A refusal
 * is kept on the progress record as `completionError` and retried the next time the person's onboarding is read, and
 * so is a group the flow's owner may no longer add people to (audited once as `onboarding:groups-skipped`).
 */
async function applyCompletionGroups(
  ctx: ServerContext,
  tenantId: string,
  identityId: string,
  flowIds: string[],
): Promise<void> {
  let changed = false;
  for (const flowId of flowIds) {
    try {
      changed =
        (await ctx.store.transaction(async (tx) => {
          const flow = await tx.get<OnboardingFlow>('onboardingFlows', flowId);
          const progress = await tx.get<OnboardingProgress>(
            'onboardingProgress',
            progressId(flowId, identityId),
          );
          const identity = await tx.get<Identity>('identities', identityId);
          if (
            !flow?.completionGroupIds?.length ||
            !progress ||
            progress.completedVersion !== flow.version ||
            progress.groupsAppliedVersion === flow.version ||
            identity?.status !== 'active' ||
            identity.tenantId !== tenantId
          )
            return false;
          const now = ctx.now();
          // The groups are applied under the authority of the flow's owner (saveFlow), checked again now: a group
          // they can no longer add people to is skipped, reported, and retried on the next read.
          const ownerId = flow.groupsOwnerId ?? flow.authorId;
          const owner = ownerId ? await tx.get<Identity>('identities', ownerId) : undefined;
          const planned: Array<{ groupId: string; uniqueKey: string; existing?: GroupMember }> = [];
          const skipped: string[] = [];
          for (const groupId of flow.completionGroupIds) {
            const group = await tx.get<Group>('groups', groupId);
            if (group?.tenantId !== tenantId) continue;
            const uniqueKey = `${groupId}:${identityId}`;
            const existing = (
              await tx.find<GroupMember>('groupMembers', { tenantId, uniqueKey })
            )[0];
            if (existing && (existing.expiresAt === undefined || existing.expiresAt > now))
              continue;
            if (!(await ownerMayGrant(ctx, tx, owner, tenantId, groupId))) skipped.push(groupId);
            else planned.push({ groupId, uniqueKey, ...(existing ? { existing } : {}) });
          }
          // Enforced invariants and separation of duties hold for completion groups as for groups.addMember.
          const guardrails = planned.length
            ? await invariantSnapshot(ctx, tx, tenantId, 'iam:groups:update')
            : undefined;
          const added: string[] = [];
          for (const { groupId, uniqueKey, existing } of planned) {
            if (existing) {
              const { expiresAt: _ended, packageAssignmentId: _tag, ...kept } = existing;
              await tx.put<GroupMember>('groupMembers', kept);
            } else
              await tx.insert<GroupMember>('groupMembers', {
                id: id(),
                tenantId,
                uniqueKey,
                groupId,
                identityId,
              });
            added.push(groupId);
          }
          if (added.length) {
            await sodAssertIdentity(ctx, tx, tenantId, identityId);
            await invariantVerify(ctx, tx, tenantId, guardrails);
          }
          const { completionError: previousError, ...rest } = progress;
          const refusal = skipped.length
            ? `Completion groups skipped: the flow's owner can no longer add people to ${skipped.length === 1 ? 'group' : 'groups'} ${skipped.join(', ')}; an administrator who can should save the flow's completion groups again`
            : undefined;
          await tx.put<OnboardingProgress>(
            'onboardingProgress',
            refusal
              ? { ...rest, completionError: refusal }
              : { ...rest, groupsAppliedVersion: flow.version },
          );
          if (refusal && refusal !== previousError)
            await ctx.events.recordAudit(tx, {
              id: id(),
              tenantId,
              actorId: identityId,
              action: 'onboarding:groups-skipped',
              resourceId: identityId,
              timestamp: Date.now(),
              outcome: 'deny',
              metadata: {
                flowId,
                flow: flow.name,
                groupIds: skipped,
                ...(ownerId ? { ownerId } : {}),
              },
            });
          if (added.length)
            await ctx.events.recordAudit(tx, {
              id: id(),
              tenantId,
              actorId: identityId,
              action: 'onboarding:groups',
              resourceId: identityId,
              timestamp: Date.now(),
              outcome: 'allow',
              metadata: { flowId, flow: flow.name, groupIds: added },
            });
          return added.length > 0;
        })) || changed;
    } catch (error) {
      const message = error instanceof Error ? error.message.slice(0, 500) : 'Failed';
      try {
        await ctx.store.transaction(async (tx) => {
          const progress = await tx.get<OnboardingProgress>(
            'onboardingProgress',
            progressId(flowId, identityId),
          );
          if (progress && progress.completionError !== message)
            await tx.put<OnboardingProgress>('onboardingProgress', {
              ...progress,
              completionError: message,
            });
        });
      } catch {
        /* bookkeeping never masks the completion */
      }
    }
  }
  if (changed) await afterIdentityChange(ctx, tenantId, [identityId], undefined);
}

/** Evaluates a person's member flows (optionally with their answers). */
async function memberStatuses(
  ctx: ServerContext,
  tx: IamStore,
  chain: Tenant[],
  identity: Identity,
  options: { answers?: boolean; candidates?: CandidateFlow[] } = {},
) {
  const now = ctx.now();
  const flows = await flowsForIdentity(tx, chain, identity, now, options.candidates);
  const progress = await progressFor(tx, identity.tenantId, identity.id);
  const facts = await memberFacts(
    tx,
    identity,
    flows.map((candidate) => candidate.flow),
    now,
  );
  const statuses = flows.map((candidate) => ({
    candidate,
    status: evaluateFlow(
      candidate,
      progress.get(candidate.flow.id),
      { member: { identity, facts } },
      { answers: options.answers },
    ),
  }));
  return { statuses, progress };
}

/** Evaluates a tenant's setup flows (always with answers: the tenant's administrators and the definer see them). */
async function tenantStatuses(tx: IamStore, chain: Tenant[], candidates?: CandidateFlow[]) {
  const tenant = chain[0]!;
  const flows = (candidates ?? (await candidateFlows(tx, chain, 'tenant'))).filter((candidate) =>
    tenantFlowApplies(candidate.flow, tenant),
  );
  const progress = await progressFor(tx, tenant.id, tenant.id);
  const facts = await tenantFacts(
    tx,
    tenant,
    flows.map((candidate) => candidate.flow),
  );
  const statuses = flows.map((candidate) => ({
    candidate,
    status: evaluateFlow(
      candidate,
      progress.get(candidate.flow.id),
      { tenant: facts },
      { answers: true },
    ),
  }));
  return { statuses, progress };
}

function summarize(
  tenant: Tenant,
  welcome: ResolvedOnboardingSettings,
  statuses: Array<{ status: OnboardingFlowStatus }>,
): MyOnboarding {
  const flows = statuses.map(({ status }) => status);
  const pending = flows.filter((flow) => flow.required && !flow.complete).length;
  return { tenant: sourceOf(tenant), welcome, flows, pending, complete: pending === 0 };
}

function subjectProgress(
  status: OnboardingFlowStatus,
  record: OnboardingProgress | undefined,
  answers: boolean,
): OnboardingSubjectProgress {
  const result: OnboardingSubjectProgress = {
    complete: status.complete,
    done: status.done,
    total: status.total,
    awaiting: status.steps.filter((step) => step.state === 'submitted').map((step) => step.id),
  };
  if (status.completedAt !== undefined) result.completedAt = status.completedAt;
  if (record) result.startedAt = record.startedAt;
  if (record?.completionError) result.completionError = record.completionError;
  if (answers) {
    const collected: Record<string, Record<string, Json>> = {};
    for (const step of record?.steps ?? [])
      if (step.answers && Object.keys(step.answers).length) collected[step.stepId] = step.answers;
    if (Object.keys(collected).length) result.answers = collected;
  }
  return result;
}

/**
 * Records one step the subject completed by hand: form answers, an acknowledgement, or a task (done, or submitted
 * for verification). Steps that complete on their own are refused. Returns the step's progress record and the
 * identity attributes the answers filled.
 */
function completeStep(
  step: OnboardingStep,
  input: { answers?: unknown; acknowledged?: unknown },
  actorId: string,
  now: number,
): { record: OnboardingStepRecord } {
  if (automaticSteps.has(step.kind))
    throw new IamError(
      'INVALID_INPUT',
      step.kind === 'check'
        ? 'This step completes when the organization’s setup meets it'
        : 'This step completes on its own once you have done it',
    );
  if (step.kind === 'form')
    return {
      record: {
        stepId: step.id,
        completedAt: now,
        completedBy: actorId,
        answers: parseAnswers(step, input.answers),
      },
    };
  if (input.answers !== undefined)
    throw new IamError('INVALID_INPUT', 'answers apply to form steps only');
  if (step.kind === 'acknowledge' && input.acknowledged !== true)
    throw new IamError('INVALID_INPUT', 'Confirm that you have read this (acknowledged: true)');
  if (step.kind === 'task' && step.verification === 'admin')
    return { record: { stepId: step.id, submittedAt: now, completedBy: actorId } };
  return { record: { stepId: step.id, completedAt: now, completedBy: actorId } };
}

/**
 * Onboarding: checklists for newcomers, customized at every level of the tenant hierarchy. `member` flows walk people
 * through their first days (forms, acknowledgements, tasks, accepting terms, verifying their email, enrolling MFA or a
 * passkey); `tenant` flows walk a new organization's or project's administrators through setup (a verified domain,
 * enough owners and members, an MFA policy, SSO, directory sync). Flows defined at the platform root reach every
 * tenant below; organizations add their own and switch off the platform's unlocked ones; projects do the same.
 * Policies see `principal.onboarding` and `principal.pendingOnboarding`. Managing needs `iam:onboarding:manage`,
 * reports `iam:onboarding:read`; people work through their own flows without a permission.
 */
export function createOnboardingApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const scopedFlow = async (tx: IamStore, flowId: unknown, tenantId: string) => {
    const flow = await flowRecord(tx, flowId);
    if (flow.tenantId !== tenantId)
      throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
    return flow;
  };
  const api = {
    /** Creates a flow at this tenant's level (member onboarding for its people or those below; setup for tenants below). */
    createFlow: async (
      credential: CredentialInput,
      input: OnboardingFlowInput & { tenantId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:manage',
        input.tenantId,
        async ({ tx, principal, tenant }) => saveFlow(ctx, tx, principal, tenant, input),
      ),
    /**
     * Edits a flow. Changing the steps bumps the version: finished steps stay finished (progress is kept per step ID),
     * and a new required step reopens the flow for everyone it applies to.
     */
    updateFlow: async (credential: CredentialInput, input: OnboardingFlowUpdate) =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:manage',
        text(input.flowId, 'flowId', 128),
        async ({ tx, principal, tenant }) => {
          const previous = await scopedFlow(tx, input.flowId, tenant.id);
          const { tenantId: _tenant, flowId: _flow, ...changes } = input;
          return saveFlow(ctx, tx, principal, tenant, changes, previous);
        },
      ),
    /** Deletes a flow and everyone's progress through it. */
    deleteFlow: async (credential: CredentialInput, input: { tenantId: string; flowId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:manage',
        text(input.flowId, 'flowId', 128),
        async ({ tx, tenant }) => {
          const flow = await scopedFlow(tx, input.flowId, tenant.id);
          return { deleted: true, progressRemoved: await deleteOnboardingFlow(tx, flow) };
        },
      ),
    /** The flows this tenant defines, oldest first. */
    listFlows: async (
      credential: CredentialInput,
      input: { tenantId: string; audience?: OnboardingAudience },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:read',
        input.tenantId,
        async ({ tx, tenant }) =>
          (await tx.find<OnboardingFlow>('onboardingFlows', { tenantId: tenant.id }))
            .filter((flow) => input.audience === undefined || flow.audience === input.audience)
            .sort((a, b) => a.createdAt - b.createdAt || a.name.localeCompare(b.name)),
      ),
    getFlow: async (credential: CredentialInput, input: { tenantId: string; flowId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:read',
        text(input.flowId, 'flowId', 128),
        async ({ tx, tenant }) => scopedFlow(tx, input.flowId, tenant.id),
      ),
    /**
     * Everything onboarding looks like from this tenant: the member flows that reach its people (own and inherited,
     * with where each comes from and whether it is switched off), the setup flows its administrators complete, the
     * flows it defines for tenants below, and its welcome settings with the level each value comes from.
     */
    effective: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<EffectiveOnboarding> =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:read',
        input.tenantId,
        async ({ tx, tenant }) => {
          const chain = await ctx.ancestry(tx, tenant);
          const settings = new SettingsReader(tx);
          const describe = (candidate: CandidateFlow): EffectiveOnboardingFlow => ({
            flow: candidate.inherited ? publicFlow(candidate.flow) : candidate.flow,
            source: sourceOf(candidate.source),
            inherited: candidate.inherited,
            ...(candidate.disabledBy ? { disabledBy: sourceOf(candidate.disabledBy) } : {}),
            canDisable:
              candidate.inherited &&
              candidate.flow.audience === 'member' &&
              !candidate.flow.locked &&
              (!candidate.disabledBy || candidate.disabledBy.id === tenant.id),
          });
          return {
            tenant: sourceOf(tenant),
            levels: [...chain].reverse().map(sourceOf),
            memberFlows: (await candidateFlows(tx, chain, 'member', settings)).map(describe),
            setupFlows: (await candidateFlows(tx, chain, 'tenant', settings))
              .filter((candidate) => tenantFlowApplies(candidate.flow, tenant))
              .map(describe),
            ownFlows: (
              await tx.find<OnboardingFlow>('onboardingFlows', { tenantId: tenant.id })
            ).sort((a, b) => a.createdAt - b.createdAt || a.name.localeCompare(b.name)),
            descendantTypes: [...descendantTypes(ctx, tenant.type)].sort(),
            identityAttributes: { ...ctx.catalog.identityAttributes },
            settings: {
              ...(await settings.get(tenant.id).then((record) => (record ? { own: record } : {}))),
              resolved: await resolveSettings(chain, settings),
            },
          };
        },
      ),
    /**
     * Replaces this tenant's onboarding settings: welcome title and message, support contacts, and the inherited
     * (unlocked) member flows switched off for this tenant and every tenant below it. `null` values clear a field.
     */
    setSettings: async (credential: CredentialInput, input: OnboardingSettingsInput) =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:manage',
        input.tenantId,
        async ({ tx, tenant }) => {
          const values = parseSettings(input as unknown as Record<string, unknown>);
          const previous = await tx.get<OnboardingSettings>(
            'onboardingSettings',
            settingsId(tenant.id),
          );
          if (values.disabledFlowIds.length) {
            const chain = await ctx.ancestry(tx, tenant);
            const switchable = new Map(
              (await candidateFlows(tx, chain, 'member', new SettingsReader(tx)))
                .filter((candidate) => candidate.inherited)
                .map((candidate) => [candidate.flow.id, candidate.flow]),
            );
            // A switch kept from before whose flow no longer reaches here (deleted, retargeted, or now locked) is
            // dropped quietly, so re-saving the settings never fails on someone else's change.
            values.disabledFlowIds = values.disabledFlowIds.filter(
              (flowId) =>
                (switchable.has(flowId) && !switchable.get(flowId)!.locked) ||
                !previous?.disabledFlowIds.includes(flowId),
            );
            for (const flowId of values.disabledFlowIds) {
              const flow = switchable.get(flowId);
              if (!flow)
                throw new IamError(
                  'INVALID_INPUT',
                  `disabledFlowIds: ${flowId} is not an inherited member flow of this tenant`,
                );
              if (flow.locked)
                throw new IamError(
                  'INVALID_INPUT',
                  `disabledFlowIds: ${flow.name} is locked by the tenant that defines it`,
                );
            }
          }
          const record: OnboardingSettings = {
            id: settingsId(tenant.id),
            tenantId: tenant.id,
            ...values,
            updatedAt: ctx.now(),
          };
          return previous
            ? tx.put<OnboardingSettings>('onboardingSettings', record)
            : tx.insert<OnboardingSettings>('onboardingSettings', record);
        },
      ),
    /** The caller's own onboarding: welcome copy and their member flows; needs only an ordinary session of the tenant. */
    mine: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<MyOnboarding> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      const { result, pendingGroups, identityId } = await ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        selfSession(principal, tenantId);
        const tenant = await ctx.tenant(tx, tenantId);
        const chain = await ctx.ancestry(tx, tenant);
        const { statuses, progress } = await memberStatuses(ctx, tx, chain, principal.identity, {
          answers: true,
        });
        // Completions are recorded for the person themselves, never while an administrator views as them.
        const pendingGroups = principal.session.impersonatorId
          ? []
          : await recordCompletions(
              ctx,
              tx,
              principal,
              { type: 'identity', id: principal.identity.id, tenantId },
              statuses,
              progress,
            );
        const welcome = await resolveSettings(chain, new SettingsReader(tx));
        return {
          result: summarize(tenant, welcome, statuses),
          pendingGroups,
          identityId: principal.identity.id,
        };
      });
      if (pendingGroups.length)
        await applyCompletionGroups(ctx, tenantId, identityId, pendingGroups);
      return result;
    },
    /**
     * Completes one step of the caller's own flow: `answers` for a form, `acknowledged: true` for an acknowledgement,
     * nothing for a task (an admin-verified task waits for an administrator). Answers mapped to identity attributes
     * fill only empty attributes. Impersonating administrators cannot complete steps on someone's behalf. Audited as
     * `onboarding:step`, and `onboarding:complete` when the flow is done.
     */
    submitStep: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        flowId: string;
        stepId: string;
        answers?: Record<string, unknown>;
        acknowledged?: boolean;
      },
    ): Promise<{ flow: OnboardingFlowStatus; attributesFilled: string[] }> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const flowId = text(input.flowId, 'flowId', 128);
      const stepId = text(input.stepId, 'stepId', 64);
      const authenticated = await ctx.principals.authenticate(credential);
      const outcome = await ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        selfSession(principal, tenantId);
        notImpersonating(principal, 'Onboarding steps cannot be completed');
        if (principal.identity.kind !== 'user')
          throw new IamError('INVALID_INPUT', 'Only people complete onboarding');
        const tenant = await ctx.tenant(tx, tenantId);
        const chain = await ctx.ancestry(tx, tenant);
        const now = ctx.now();
        const candidate = (await flowsForIdentity(tx, chain, principal.identity, now)).find(
          (item) => item.flow.id === flowId,
        );
        if (!candidate) throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
        const step = candidate.flow.steps.find((item) => item.id === stepId);
        if (!step) throw new IamError('NOT_FOUND', 'Onboarding step not found', 404);
        const { record } = completeStep(step, input, principal.identity.id, now);
        // Answers fill the person's empty declared attributes, and only in the tenant that defines the flow (a flow
        // inherited from above records answers but never writes this tenant's identities); values someone else set
        // are kept, and every value passes the same validation as identities.update.
        const filled: string[] = [];
        let identity = principal.identity;
        if (step.kind === 'form' && candidate.flow.tenantId === tenantId) {
          const attributes = { ...(identity.attributes ?? {}) };
          for (const field of step.fields!) {
            const value =
              record.answers && Object.hasOwn(record.answers, field.name)
                ? record.answers[field.name]
                : undefined;
            if (
              !field.attribute ||
              value === undefined ||
              Object.hasOwn(attributes, field.attribute)
            )
              continue;
            if (field.type === 'boolean' && value === false && !field.required) continue;
            Object.assign(
              attributes,
              attributeValues(ctx.catalog.identityAttributes, { [field.attribute]: value }),
            );
            filled.push(field.attribute);
          }
          if (filled.length)
            identity = await tx.put<Identity>('identities', { ...identity, attributes });
        }
        const progress = await progressFor(tx, tenantId, identity.id);
        const existing = progress.get(flowId);
        const next = withStep(
          existing ??
            newProgress(candidate.flow, { type: 'identity', id: identity.id, tenantId }, now),
          record,
        );
        progress.set(
          flowId,
          await upsertProgress(tx, { ...next, updatedAt: now }, existing !== undefined),
        );
        await ctx.events.audit(
          tx,
          principal,
          'onboarding:step',
          tenantId,
          identity.id,
          'allow',
          false,
          {
            flowId,
            flow: candidate.flow.name,
            stepId,
            kind: step.kind,
            ...(record.submittedAt !== undefined ? { awaitingVerification: true } : {}),
            ...(filled.length ? { attributes: filled } : {}),
          },
        );
        const facts = await memberFacts(tx, identity, [candidate.flow], now);
        const status = evaluateFlow(
          candidate,
          progress.get(flowId),
          { member: { identity, facts } },
          { answers: true },
        );
        const pendingGroups = await recordCompletions(
          ctx,
          tx,
          { ...principal, identity },
          { type: 'identity', id: identity.id, tenantId },
          [{ candidate, status }],
          progress,
        );
        return { status, filled, pendingGroups, identityId: identity.id };
      });
      if (outcome.pendingGroups.length)
        await applyCompletionGroups(ctx, tenantId, outcome.identityId, outcome.pendingGroups);
      else if (outcome.filled.length)
        await afterIdentityChange(ctx, tenantId, [outcome.identityId], undefined);
      return { flow: outcome.status, attributesFilled: outcome.filled };
    },
    /** This tenant's own setup checklists (defined by the tenants above it), with the state of every step. */
    setup: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<MyOnboarding> =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:read',
        input.tenantId,
        async ({ tx, tenant, principal }) => {
          const chain = await ctx.ancestry(tx, tenant);
          const { statuses, progress } = await tenantStatuses(tx, chain);
          if (!principal.session.impersonatorId)
            await recordCompletions(
              ctx,
              tx,
              principal,
              { type: 'tenant', id: tenant.id, tenantId: tenant.id },
              statuses,
              progress,
            );
          return summarize(tenant, await resolveSettings(chain, new SettingsReader(tx)), statuses);
        },
      ),
    /** Completes a form, acknowledgement or task step of this tenant's setup; check steps follow the tenant's state. */
    submitSetupStep: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        flowId: string;
        stepId: string;
        answers?: Record<string, unknown>;
        acknowledged?: boolean;
      },
    ): Promise<{ flow: OnboardingFlowStatus }> =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:manage',
        text(input.flowId, 'flowId', 128),
        async ({ tx, tenant, principal }) => {
          notImpersonating(principal, 'Setup steps cannot be completed');
          const stepId = text(input.stepId, 'stepId', 64);
          const chain = await ctx.ancestry(tx, tenant);
          const candidate = (await candidateFlows(tx, chain, 'tenant')).find(
            (item) => item.flow.id === input.flowId && tenantFlowApplies(item.flow, tenant),
          );
          if (!candidate) throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
          const step = candidate.flow.steps.find((item) => item.id === stepId);
          if (!step) throw new IamError('NOT_FOUND', 'Onboarding step not found', 404);
          const now = ctx.now();
          const { record } = completeStep(step, input, principal.identity.id, now);
          const subject = { type: 'tenant' as const, id: tenant.id, tenantId: tenant.id };
          const progress = await progressFor(tx, tenant.id, tenant.id);
          const existing = progress.get(candidate.flow.id);
          progress.set(
            candidate.flow.id,
            await upsertProgress(
              tx,
              {
                ...withStep(existing ?? newProgress(candidate.flow, subject, now), record),
                updatedAt: now,
              },
              existing !== undefined,
            ),
          );
          await ctx.events.audit(
            tx,
            principal,
            'onboarding:step',
            tenant.id,
            tenant.id,
            'allow',
            false,
            {
              flowId: candidate.flow.id,
              flow: candidate.flow.name,
              stepId,
              kind: step.kind,
              ...(record.submittedAt !== undefined ? { awaitingVerification: true } : {}),
            },
          );
          const facts = await tenantFacts(tx, tenant, [candidate.flow]);
          const status = evaluateFlow(
            candidate,
            progress.get(candidate.flow.id),
            { tenant: facts },
            { answers: true },
          );
          await recordCompletions(ctx, tx, principal, subject, [{ candidate, status }], progress);
          return { flow: status };
        },
      ),
    /**
     * Progress through one flow as seen from this tenant. Member flows (own or inherited) list this tenant's people the
     * flow applies to, with their answers; a flow defined here that reaches descendant tenants adds per-tenant counts
     * (never names). Tenant setup flows defined here list every descendant tenant they apply to, with its answers.
     */
    progress: async (
      credential: CredentialInput,
      input: { tenantId: string; flowId: string },
    ): Promise<OnboardingProgressReport> =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:read',
        text(input.flowId, 'flowId', 128),
        async ({ tx, tenant }) => {
          const flow = await flowRecord(tx, input.flowId);
          const chain = await ctx.ancestry(tx, tenant);
          const settings = new SettingsReader(tx);
          const now = ctx.now();
          const candidate =
            flow.tenantId === tenant.id
              ? { flow, source: tenant, inherited: false, depth: 0 }
              : (await candidateFlows(tx, chain, flow.audience, settings)).find(
                  (item) => item.flow.id === flow.id,
                );
          if (!candidate || (flow.audience === 'tenant' && flow.tenantId !== tenant.id))
            throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
          const report: OnboardingProgressReport = {
            flow: {
              id: flow.id,
              name: flow.name,
              audience: flow.audience,
              version: flow.version,
              required: flow.required,
              source: sourceOf(candidate.source),
              inherited: candidate.inherited,
              ...(candidate.disabledBy ? { disabledBy: sourceOf(candidate.disabledBy) } : {}),
            },
            summary: { subjects: 0, complete: 0 },
          };
          if (flow.audience === 'tenant') {
            const { tenants, truncated } = await descendantsOf(tx, tenant);
            report.tenants = [];
            for (const target of tenants) {
              if (target.status === 'deleted') continue;
              const targetChain = await ctx.ancestry(tx, target);
              const found = (await candidateFlows(tx, targetChain, 'tenant', settings)).find(
                (item) => item.flow.id === flow.id && tenantFlowApplies(item.flow, target),
              );
              if (!found) continue;
              const { statuses, progress } = await tenantStatuses(tx, targetChain, [found]);
              const status = statuses[0]!.status;
              report.tenants.push({
                tenant: { ...sourceOf(target), status: target.status },
                ...subjectProgress(status, progress.get(flow.id), true),
              });
            }
            report.summary = {
              subjects: report.tenants.length,
              complete: report.tenants.filter((row) => row.complete).length,
            };
            if (truncated) report.truncated = true;
            return report;
          }
          report.members = [];
          const reachesHere =
            candidate.inherited || flow.appliesTo !== 'descendants' ? !candidate.disabledBy : false;
          if (reachesHere) {
            const people = (await tx.find<Identity>('identities', { tenantId: tenant.id }))
              .filter((identity) => identity.kind === 'user' && identity.status === 'active')
              .sort((a, b) => (a.email ?? a.name).localeCompare(b.email ?? b.name));
            for (const identity of people) {
              const groupIds = flow.rule ? await liveGroupIds(tx, identity, now) : undefined;
              if (!flowAppliesTo(flow, identity, groupIds)) continue;
              const { statuses, progress } = await memberStatuses(ctx, tx, chain, identity, {
                answers: true,
                candidates: [candidate],
              });
              const status = statuses[0]?.status;
              if (!status) continue;
              report.members.push({
                identity: {
                  id: identity.id,
                  name: identity.name,
                  ...(identity.email ? { email: identity.email } : {}),
                },
                ...subjectProgress(status, progress.get(flow.id), true),
              });
            }
          }
          report.summary = {
            subjects: report.members.length,
            complete: report.members.filter((row) => row.complete).length,
          };
          if (flow.tenantId === tenant.id && flow.appliesTo !== 'tenant') {
            const { tenants, truncated } = await descendantsOf(tx, tenant);
            report.descendants = [];
            for (const target of tenants) {
              if (target.status !== 'active') continue;
              const targetChain = await ctx.ancestry(tx, target);
              const found = (await candidateFlows(tx, targetChain, 'member', settings)).find(
                (item) => item.flow.id === flow.id && !item.disabledBy,
              );
              if (!found) continue;
              let people = 0;
              let complete = 0;
              for (const identity of await tx.find<Identity>('identities', {
                tenantId: target.id,
              })) {
                if (identity.kind !== 'user' || identity.status !== 'active') continue;
                const { statuses } = await memberStatuses(ctx, tx, targetChain, identity, {
                  candidates: [found],
                });
                if (!statuses.length) continue;
                people++;
                if (statuses[0]!.status.complete) complete++;
              }
              report.descendants.push({ tenant: sourceOf(target), people, complete });
            }
            if (truncated) report.truncated = true;
          }
          return report;
        },
      ),
    /** One person's onboarding in this tenant, with their answers (for member pages). */
    memberProgress: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string },
    ): Promise<{
      identity: { id: string; name: string; email?: string };
      flows: OnboardingFlowStatus[];
      pending: number;
    }> =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:read',
        text(input.identityId, 'identityId'),
        async ({ tx, tenant }) => {
          const identity = await ctx.activeIdentity(tx, input.identityId, tenant.id);
          const chain = await ctx.ancestry(tx, tenant);
          const { statuses } = await memberStatuses(ctx, tx, chain, identity, { answers: true });
          const flows = statuses.map(({ status }) => status);
          return {
            identity: {
              id: identity.id,
              name: identity.name,
              ...(identity.email ? { email: identity.email } : {}),
            },
            flows,
            pending: flows.filter((flow) => flow.required && !flow.complete).length,
          };
        },
      ),
    /**
     * Approves (the default) or sends back an administrator-verified task. For member flows the caller administers
     * the person's tenant (`tenantId` is the person's tenant); for setup flows the caller administers the tenant that
     * defines the flow and names the tenant being set up as `subjectId`. Audited as `onboarding:verify` or
     * `onboarding:reject`.
     */
    verifyStep: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        flowId: string;
        subjectId: string;
        stepId: string;
        approve?: boolean;
        note?: string;
      },
    ): Promise<{ flow: OnboardingFlowStatus }> =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:manage',
        text(input.subjectId, 'subjectId', 128),
        async ({ tx, tenant, principal }) => {
          notImpersonating(principal, 'Onboarding steps cannot be verified');
          const approve = input.approve ?? true;
          if (typeof approve !== 'boolean')
            throw new IamError('INVALID_INPUT', 'approve must be a boolean');
          const note =
            input.note === undefined || input.note === ''
              ? undefined
              : text(input.note, 'note', 500).trim();
          const flow = await flowRecord(tx, input.flowId);
          const now = ctx.now();
          let candidate: CandidateFlow | undefined;
          let subject: { type: 'identity' | 'tenant'; id: string; tenantId: string };
          let evaluate: (progress: OnboardingProgress | undefined) => Promise<OnboardingFlowStatus>;
          if (flow.audience === 'member') {
            const identity = await ctx.activeIdentity(tx, input.subjectId, tenant.id);
            if (identity.id === principal.identity.id)
              throw new IamError('INVALID_INPUT', 'People cannot verify their own onboarding');
            const chain = await ctx.ancestry(tx, tenant);
            candidate = (await flowsForIdentity(tx, chain, identity, now)).find(
              (item) => item.flow.id === flow.id,
            );
            subject = { type: 'identity', id: identity.id, tenantId: tenant.id };
            evaluate = async (progress) =>
              evaluateFlow(
                candidate!,
                progress,
                {
                  member: { identity, facts: await memberFacts(tx, identity, [flow], now) },
                },
                { answers: true },
              );
          } else {
            if (flow.tenantId !== tenant.id)
              throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
            const target = await ctx.tenant(tx, text(input.subjectId, 'subjectId', 128));
            const targetChain = await ctx.ancestry(tx, target);
            if (!targetChain.slice(1).some((item) => item.id === tenant.id))
              throw new IamError('NOT_FOUND', 'Tenant not found', 404);
            candidate = (await candidateFlows(tx, targetChain, 'tenant')).find(
              (item) => item.flow.id === flow.id && tenantFlowApplies(item.flow, target),
            );
            subject = { type: 'tenant', id: target.id, tenantId: target.id };
            evaluate = async (progress) =>
              evaluateFlow(
                candidate!,
                progress,
                { tenant: await tenantFacts(tx, target, [flow]) },
                { answers: true },
              );
          }
          if (!candidate) throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
          const step = flow.steps.find((item) => item.id === input.stepId);
          if (!step || step.kind !== 'task' || step.verification !== 'admin')
            throw new IamError('INVALID_INPUT', 'Only administrator-verified tasks are verified');
          const progress = await progressFor(tx, subject.tenantId, subject.id);
          const existing = progress.get(flow.id);
          const record: OnboardingStepRecord = approve
            ? {
                stepId: step.id,
                completedAt: now,
                completedBy: subject.id,
                verifiedBy: principal.identity.id,
                ...(note ? { note } : {}),
              }
            : {
                stepId: step.id,
                rejectedAt: now,
                verifiedBy: principal.identity.id,
                ...(note ? { note } : {}),
              };
          progress.set(
            flow.id,
            await upsertProgress(
              tx,
              { ...withStep(existing ?? newProgress(flow, subject, now), record), updatedAt: now },
              existing !== undefined,
            ),
          );
          await ctx.events.audit(
            tx,
            principal,
            approve ? 'onboarding:verify' : 'onboarding:reject',
            tenant.id,
            subject.id,
            'allow',
            false,
            {
              flowId: flow.id,
              flow: flow.name,
              stepId: step.id,
              subjectType: subject.type,
              ...(note ? { note } : {}),
            },
          );
          const status = await evaluate(progress.get(flow.id));
          // Completion is recorded here; completion groups are applied the next time the person reads their onboarding.
          await recordCompletions(ctx, tx, principal, subject, [{ candidate, status }], progress);
          return { flow: status };
        },
      ),
    /**
     * Clears progress so people (or tenants) go through a flow, or one step of it, again. The tenant that defines the
     * flow may reset anyone it reaches (everyone when `subjectId` is omitted); a tenant the flow reaches may reset its
     * own people. Resetting one's own progress through a flow with completion groups needs the right to add oneself to
     * those groups. Audited as `onboarding:reset`.
     */
    resetProgress: async (
      credential: CredentialInput,
      input: { tenantId: string; flowId: string; subjectId?: string; stepId?: string },
    ): Promise<{ reset: number }> =>
      operation(
        credential,
        input.tenantId,
        'iam:onboarding:manage',
        text(input.flowId, 'flowId', 128),
        async ({ tx, tenant, principal }) => {
          const flow = await flowRecord(tx, input.flowId);
          const stepId = input.stepId === undefined ? undefined : text(input.stepId, 'stepId', 64);
          if (stepId !== undefined && !flow.steps.some((step) => step.id === stepId))
            throw new IamError('NOT_FOUND', 'Onboarding step not found', 404);
          const definer = flow.tenantId === tenant.id;
          if (!definer) {
            if (flow.audience !== 'member')
              throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
            const chain = await ctx.ancestry(tx, tenant);
            if (
              !(await candidateFlows(tx, chain, 'member')).some((item) => item.flow.id === flow.id)
            )
              throw new IamError('NOT_FOUND', 'Onboarding flow not found', 404);
          }
          const subjectId =
            input.subjectId === undefined ? undefined : text(input.subjectId, 'subjectId', 128);
          const records = (
            await tx.find<OnboardingProgress>('onboardingProgress', {
              flowId: flow.id,
              ...(subjectId !== undefined ? { subjectId } : {}),
            })
          ).filter((record) => definer || record.tenantId === tenant.id);
          // Finishing the flow again would put the caller back into its completion groups (after an administrator
          // took them out, say), so resetting one's own progress needs the right to add oneself to them.
          if (
            flow.completionGroupIds?.length &&
            records.some(
              (record) =>
                record.subjectId === principal.identity.id && record.tenantId === flow.tenantId,
            )
          )
            try {
              for (const groupId of flow.completionGroupIds)
                await authorizeCompletionGroup(ctx, tx, principal, flow.tenantId, groupId);
            } catch {
              throw new IamError(
                'ACCESS_DENIED',
                'Resetting your own progress through a flow with completion groups needs the right to add yourself to them',
                403,
              );
            }
          for (const record of records) {
            if (stepId === undefined) await tx.delete('onboardingProgress', record.id);
            else {
              const { completedAt: _done, completedVersion: _version, ...rest } = record;
              await tx.put<OnboardingProgress>('onboardingProgress', {
                ...rest,
                steps: record.steps.filter((step) => step.stepId !== stepId),
                updatedAt: ctx.now(),
              });
            }
          }
          await ctx.events.audit(
            tx,
            principal,
            'onboarding:reset',
            tenant.id,
            flow.id,
            'allow',
            false,
            {
              flowId: flow.id,
              flow: flow.name,
              reset: records.length,
              ...(subjectId !== undefined ? { subjectId } : {}),
              ...(stepId !== undefined ? { stepId } : {}),
            },
          );
          return { reset: records.length };
        },
      ),
  };
  return api;
}

export type { OnboardingSource } from '../onboarding.js';
