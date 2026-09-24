import { randomBytes } from 'node:crypto';
import {
  IamError,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { attributeValues } from '../catalog.js';
import type { ServerContext } from '../context.js';
import type { AccessPackage, Group, GroupMember, PackageAssignment } from '../models.js';
import { OperationDenied } from '../operations.js';
import { loadOrgFacts, orgRuleEnvironment } from '../org-rules.js';
import { ruleContext, ruleDocument, ruleMatch, type AutoAssignInput } from '../package-rules.js';
import { actsInOwnRight } from '../session-kinds.js';
import { endContainment } from '../threats.js';
import { id } from '../utils.js';
import { integer, strings, text } from '../validation.js';
import {
  dateTarget,
  dayMs,
  defaultBrake,
  destructiveSteps,
  fillTemplate,
  parseScope,
  parseSteps,
  parseTrigger,
  triggerOccurrence,
  utcDay,
  type Workflow,
  type WorkflowRun,
  type WorkflowRunStatus,
  type WorkflowStep,
  type WorkflowStepResult,
  type WorkflowSubject,
  type WorkflowTrigger,
} from '../workflows.js';
import type { TenantDomain } from './domains.js';
import { addGroupMember, removeGroupMember } from './groups.js';
import { deleteIdentity } from './identities.js';
import { afterIdentityChange } from './package-automation.js';
import { allow, assignPackage, authorizePackage, revokeAssignment } from './packages.js';

export interface WorkflowInput {
  name: string;
  description?: string;
  trigger: WorkflowTrigger;
  scope?: AutoAssignInput | null;
  steps: WorkflowStep[];
  enabled?: boolean;
  includeExisting?: boolean;
  maxRunsPerDay?: number;
}
export interface WorkflowView {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  enabled: boolean;
  trigger: WorkflowTrigger;
  scope?: AutoAssignInput;
  steps: WorkflowStep[];
  includeExisting: boolean;
  maxRunsPerDay: number;
  ownerId: string;
  ownerName?: string;
  version: number;
  activeSince: number;
  brakedOn?: string;
  createdAt: number;
  updatedAt: number;
  runs?: { last30Days: number; active: number; failed: number; lastRunAt?: number };
}
export interface WorkflowRunView {
  id: string;
  workflowId: string;
  workflowName: string;
  workflowVersion: number;
  identityId: string;
  identityName?: string;
  occurrence: string;
  trigger: WorkflowTrigger['kind'];
  steps: WorkflowStep[];
  status: WorkflowRunStatus;
  stepIndex: number;
  nextAt: number;
  results: WorkflowStepResult[];
  startedAt: number;
  finishedAt?: number;
  startedBy?: string;
  error?: { code: string; message: string };
}
export interface WorkflowPreview {
  /** People the scope matches right now (active people only). */
  inScope: Array<{ id: string; name: string; email?: string }>;
  /** People a run would start for at the next evaluation (joiners, due dates), before the daily brake. */
  wouldStart: Array<{ id: string; name: string; occurrence: string }>;
  /** Date triggers: people whose date falls within the next 30 days. */
  upcoming: Array<{ id: string; name: string; at: number }>;
  /** Whether the owner may perform each step right now (steps that need no permission are always allowed). */
  steps: Array<{ index: number; kind: WorkflowStep['kind']; allowed: boolean; reason?: string }>;
}
export interface WorkflowJobResult {
  started: number;
  executed: number;
  completed: number;
  failed: number;
  waiting: number;
}

const maxWorkflows = 100;
const leaseMs = 5 * 60_000;
/** Finished runs stay this long for review, then the retention sweep removes them. */
const runRetentionMs = 180 * 86_400_000;

/** The rights a step needs, as the owner would need them by hand: [action, resource] pairs. */
function requirements(
  step: WorkflowStep,
  tenantId: string,
  identityId?: string,
): Array<[string, string]> {
  const person = identityId ?? tenantId;
  switch (step.kind) {
    case 'add-to-group':
    case 'remove-from-group':
      return [['iam:groups:update', step.groupId]];
    case 'assign-package':
      return [['iam:packages:assign', step.packageId]];
    case 'revoke-packages':
      return step.packageId ? [['iam:packages:assign', step.packageId]] : [];
    case 'revoke-sessions':
    case 'disable':
    case 'enable':
    case 'set-attributes':
    case 'set-expiry':
      return [['iam:identities:update', person]];
    case 'delete':
      return [['iam:identities:delete', person]];
    // An email carries the person's name, address and attributes: whoever automates it must be able to read them.
    case 'send-email':
      return [['iam:identities:read', person]];
    case 'remove-from-all-groups':
    case 'emit-event':
    case 'wait':
      return [];
  }
}

/**
 * Where a literal `send-email` address may point: an address of an active member of the organization, or one at a
 * domain the organization verified, so a workflow cannot mail people's details (or phishing) to arbitrary outsiders.
 */
async function assertRecipients(
  tx: IamStore,
  tenantId: string,
  steps: WorkflowStep[],
): Promise<void> {
  const literal = steps.flatMap((step) =>
    step.kind === 'send-email' && step.to !== 'subject' && step.to !== 'manager' ? [step.to] : [],
  );
  if (!literal.length) return;
  const domains = new Set(
    (await tx.find<TenantDomain>('tenantDomains', { tenantId }))
      .filter((record) => record.status === 'verified')
      .map((record) => String(record.domain).toLowerCase()),
  );
  for (const address of literal) {
    if (domains.has(address.slice(address.lastIndexOf('@') + 1))) continue;
    const member = (await tx.find<Identity>('identities', { tenantId, email: address })).some(
      (identity) => identity.status === 'active',
    );
    if (!member)
      throw new IamError(
        'INVALID_INPUT',
        `send-email may address subject, manager, a member of the organization, or a verified domain (not ${address})`,
      );
  }
}

/** Steps that change a person's own record: nobody may point them at themself through a workflow. */
const selfChanging: ReadonlySet<WorkflowStep['kind']> = new Set(['set-attributes', 'set-expiry', 'enable']);

function workflowView(
  workflow: Workflow,
  extra: { ownerName?: string; runs?: WorkflowView['runs'] } = {},
): WorkflowView {
  return {
    id: workflow.id,
    tenantId: workflow.tenantId,
    name: workflow.name,
    ...(workflow.description ? { description: workflow.description } : {}),
    enabled: workflow.enabled,
    trigger: workflow.trigger,
    ...(workflow.scope ? { scope: workflow.scope } : {}),
    steps: workflow.steps,
    includeExisting: workflow.includeExisting,
    maxRunsPerDay: workflow.maxRunsPerDay,
    ownerId: workflow.ownerId,
    ...(extra.ownerName ? { ownerName: extra.ownerName } : {}),
    version: workflow.version,
    activeSince: workflow.activeSince,
    ...(workflow.brakedOn ? { brakedOn: workflow.brakedOn } : {}),
    createdAt: workflow.createdAt,
    updatedAt: workflow.updatedAt,
    ...(extra.runs ? { runs: extra.runs } : {}),
  };
}

function runView(run: WorkflowRun, identityName?: string): WorkflowRunView {
  return {
    id: run.id,
    workflowId: run.workflowId,
    workflowName: run.workflowName,
    workflowVersion: run.workflowVersion,
    identityId: run.identityId,
    ...(identityName ? { identityName } : {}),
    occurrence: run.occurrence,
    trigger: run.trigger,
    steps: run.steps,
    status: run.status,
    stepIndex: run.stepIndex,
    nextAt: run.nextAt,
    results: run.results,
    startedAt: run.startedAt,
    ...(run.finishedAt !== undefined ? { finishedAt: run.finishedAt } : {}),
    ...(run.startedBy ? { startedBy: run.startedBy } : {}),
    ...(run.error ? { error: run.error } : {}),
  };
}

/** Validates a workflow's parts and the groups and packages its steps name. */
async function workflowFields(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  input: Partial<WorkflowInput>,
  previous?: Workflow,
) {
  const attributes = ctx.catalog.identityAttributes;
  const name = text(input.name ?? previous?.name, 'name', 120).trim();
  if (!name) throw new IamError('INVALID_INPUT', 'name is required');
  const description =
    input.description === undefined
      ? previous?.description
      : input.description === null || input.description === ''
        ? undefined
        : text(input.description, 'description', 1000);
  if (!previous && (input.trigger === undefined || input.steps === undefined))
    throw new IamError('INVALID_INPUT', 'A workflow needs a trigger and steps');
  const trigger =
    input.trigger === undefined ? previous!.trigger : parseTrigger(input.trigger, attributes);
  const steps = input.steps === undefined ? previous!.steps : parseSteps(input.steps, attributes);
  const groups = await tx.find<Group>('groups', { tenantId });
  const groupIds = new Set(groups.map((group) => group.id));
  const scope =
    input.scope === undefined
      ? previous?.scope
      : parseScope(input.scope, {
          identityAttributes: attributes,
          groups: groupIds,
          org: await orgRuleEnvironment(tx, tenantId),
        });
  for (const step of steps) {
    if (step.kind === 'add-to-group' || step.kind === 'remove-from-group') {
      const group = groups.find((item) => item.id === step.groupId);
      if (!group) throw new IamError('INVALID_INPUT', `Unknown group ${step.groupId}`);
      if (group.teamId)
        throw new IamError(
          'TEAM_MANAGED',
          `${group.name} belongs to a team; add people to the team instead`,
          409,
        );
    }
    if (step.kind === 'assign-package' || (step.kind === 'revoke-packages' && step.packageId))
      await ctx.scoped<AccessPackage>(tx, 'accessPackages', step.packageId!, tenantId);
  }
  await assertRecipients(tx, tenantId, steps);
  const includeExisting = input.includeExisting ?? previous?.includeExisting ?? false;
  if (typeof includeExisting !== 'boolean')
    throw new IamError('INVALID_INPUT', 'includeExisting must be a boolean');
  const maxRunsPerDay =
    input.maxRunsPerDay === undefined
      ? (previous?.maxRunsPerDay ?? defaultBrake(steps))
      : integer(input.maxRunsPerDay, 'maxRunsPerDay', 1, 10_000);
  const enabled = input.enabled ?? previous?.enabled ?? true;
  if (typeof enabled !== 'boolean') throw new IamError('INVALID_INPUT', 'enabled must be a boolean');
  return {
    uniqueKey: `name:${name.toLowerCase()}`,
    name,
    ...(description ? { description } : {}),
    enabled,
    trigger,
    ...(scope ? { scope } : {}),
    steps,
    includeExisting,
    maxRunsPerDay,
  };
}

/**
 * The saver becomes the workflow's owner: they must be a person or service account acting in their own right, and
 * hold every right the steps use, so nobody automates what they could not do by hand.
 */
async function assertOwnerRights(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  steps: WorkflowStep[],
  identityIds: readonly (string | undefined)[] = [undefined],
): Promise<void> {
  if (!actsInOwnRight(principal.session) || principal.session.impersonatorId)
    throw new IamError(
      'ACCESS_DENIED',
      'Workflows are saved and run from a signed-in session or an API key of their own',
      403,
    );
  if (principal.identity.tenantId !== tenantId && !(await ctx.rootPrincipal(tx, principal)))
    throw new IamError('ACCESS_DENIED', 'Workflows are managed from their own organization', 403);
  for (const identityId of identityIds)
    for (const step of steps)
      for (const [action, resource] of requirements(step, tenantId, identityId)) {
        const decision = await ctx.decisions.decide(
          tx,
          principal,
          { tenantId, action, resource: { type: 'iam', id: resource } },
          true,
        );
        if (!decision.allowed)
          throw new OperationDenied(
            `The ${step.kind} step needs ${action} on ${resource}, which you do not have`,
          );
      }
  if (steps.some((step) => step.kind === 'assign-package'))
    for (const step of steps)
      if (step.kind === 'assign-package')
        await authorizePackage(
          ctx,
          tx,
          principal,
          await ctx.scoped<AccessPackage>(tx, 'accessPackages', step.packageId, tenantId),
        );
}

/** Baselines for mover and leaver triggers, so only changes after this moment fire. */
async function rebuildSnapshots(
  tx: IamStore,
  workflow: Workflow,
  now: number,
): Promise<void> {
  for (const subject of await tx.find<WorkflowSubject>('workflowSubjects', {
    tenantId: workflow.tenantId,
    workflowId: workflow.id,
  }))
    await tx.delete('workflowSubjects', subject.id);
  if (workflow.trigger.kind !== 'mover' && workflow.trigger.kind !== 'leaver') return;
  for (const identity of await tx.find<Identity>('identities', { tenantId: workflow.tenantId })) {
    if (identity.kind !== 'user' || identity.status === 'deleted') continue;
    const { snapshot } = triggerOccurrence(workflow, identity, undefined, now);
    if (snapshot)
      await tx.insert<WorkflowSubject>('workflowSubjects', {
        id: id(),
        tenantId: workflow.tenantId,
        uniqueKey: `${workflow.id}:${identity.id}`,
        workflowId: workflow.id,
        identityId: identity.id,
        ...snapshot,
      });
  }
}

/** The run engine, shared by the API and the scheduler runtime. */
function engine(ctx: ServerContext) {
  const { store } = ctx;
  const canEmail = () => Boolean(ctx.options.authentication?.sendEmail);

  /**
   * A step that takes something away (or rewrites the record) never reaches owners, root administrators, or the
   * workflow's owner; nobody changes their own record through a workflow they own or started (identities.update
   * refuses that to non-owners by hand); re-enabling a root administrator needs a root owner, as setStatus does.
   */
  async function protect(
    tx: IamStore,
    step: WorkflowStep,
    target: Identity,
    owner: AuthenticatedPrincipal,
    run: WorkflowRun,
  ): Promise<void> {
    const guarded =
      destructiveSteps.has(step.kind) || step.kind === 'set-expiry' || step.kind === 'set-attributes';
    if (guarded && (target.owner || target.rootAdmin))
      throw new IamError(
        'PROTECTED_RESOURCE',
        'Workflows never disable, delete, sign out, strip access from, or edit owners or root administrators',
        403,
      );
    if (guarded && target.id === owner.identity.id)
      throw new IamError('INVALID_INPUT', 'A workflow does not act against its own owner');
    if (selfChanging.has(step.kind) && (target.id === owner.identity.id || target.id === run.startedBy))
      throw new IamError(
        'ACCESS_DENIED',
        'Nobody changes their own account through a workflow they own or started',
        403,
      );
    if (step.kind === 'enable' && target.rootAdmin && !(await ctx.rootPrincipal(tx, owner)))
      throw new IamError('ACCESS_DENIED', 'Root capability is protected', 403);
  }

  async function perform(
    tx: IamStore,
    owner: AuthenticatedPrincipal,
    tenant: Tenant,
    run: WorkflowRun,
    step: WorkflowStep,
  ): Promise<{ outcome: 'done' | 'skipped'; detail?: string; changed?: boolean }> {
    const tenantId = tenant.id;
    const target = await ctx.activeIdentity(tx, run.identityId, tenantId);
    await protect(tx, step, target, owner, run);
    if (step.kind === 'send-email') await assertRecipients(tx, tenantId, [step]);
    for (const [action, resource] of requirements(step, tenantId, target.id))
      await allow(ctx, tx, owner, tenantId, action, resource, `run the ${step.kind} step`);
    const now = ctx.now();
    const audit = (action: string, resourceId: string, metadata: Record<string, Json>) =>
      ctx.events.audit(tx, owner, action, tenantId, resourceId, 'allow', false, {
        ...metadata,
        via: 'workflow',
        workflowId: run.workflowId,
        runId: run.id,
      });
    switch (step.kind) {
      case 'add-to-group': {
        const group = await ctx.scoped<Group>(tx, 'groups', step.groupId, tenantId);
        // Already a member (a joiner run for someone who was added by hand, say): nothing to do.
        if (
          (await tx.find<GroupMember>('groupMembers', { tenantId, groupId: group.id, identityId: target.id })).some(
            (member) => ctx.liveMembership(member),
          )
        )
          return { outcome: 'skipped', detail: `already in ${group.name}` };
        await addGroupMember(ctx, tx, owner, {
          tenantId,
          groupId: group.id,
          identityId: target.id,
          ...(step.days ? { expiresAt: now + step.days * dayMs } : {}),
        });
        await audit('iam:groups:update', group.id, { identityId: target.id, added: true });
        return { outcome: 'done', detail: group.name, changed: true };
      }
      case 'remove-from-group': {
        const group = await ctx.scoped<Group>(tx, 'groups', step.groupId, tenantId);
        const members = await tx.find<GroupMember>('groupMembers', {
          tenantId,
          groupId: group.id,
          identityId: target.id,
        });
        if (!members.length) return { outcome: 'skipped', detail: `not in ${group.name}` };
        await removeGroupMember(ctx, tx, owner, {
          tenantId,
          groupId: group.id,
          identityId: target.id,
        });
        await audit('iam:groups:update', group.id, { identityId: target.id, removed: true });
        return { outcome: 'done', detail: group.name, changed: true };
      }
      case 'remove-from-all-groups': {
        // Memberships a team or an access package manages are left to them.
        const memberships = (
          await tx.find<GroupMember>('groupMembers', { tenantId, identityId: target.id })
        ).filter((member) => !member.teamId && !member.packageAssignmentId);
        const groups = [...new Set(memberships.map((member) => member.groupId))].sort();
        for (const groupId of groups) {
          await allow(ctx, tx, owner, tenantId, 'iam:groups:update', groupId, 'remove from a group');
          await removeGroupMember(ctx, tx, owner, { tenantId, groupId, identityId: target.id });
          await audit('iam:groups:update', groupId, { identityId: target.id, removed: true });
        }
        return groups.length
          ? { outcome: 'done', detail: `${groups.length} groups`, changed: true }
          : { outcome: 'skipped', detail: 'in no groups' };
      }
      case 'assign-package': {
        const pkg = await ctx.scoped<AccessPackage>(tx, 'accessPackages', step.packageId, tenantId);
        const { assignment, skipped } = await assignPackage(ctx, tx, owner, pkg, {
          identityId: target.id,
          ...(step.days ? { expiresAt: now + step.days * dayMs } : {}),
          justification: `Workflow: ${run.workflowName}`,
        });
        await audit('package:assign', pkg.id, {
          packageId: pkg.id,
          packageName: pkg.name,
          identityId: target.id,
          bindings: assignment.bindingIds.length,
          memberships: assignment.membershipIds.length,
          skipped,
        });
        return { outcome: 'done', detail: pkg.name, changed: true };
      }
      case 'revoke-packages': {
        // Assignments a package rule made belong to the rule (packages.revoke refuses them too): it removes them itself
        // once the person no longer matches.
        const assignments = (
          await tx.find<PackageAssignment>('packageAssignments', { tenantId, identityId: target.id })
        ).filter(
          (assignment) =>
            (!step.packageId || assignment.packageId === step.packageId) &&
            assignment.ruleRevision === undefined,
        );
        for (const assignment of assignments) {
          await allow(
            ctx,
            tx,
            owner,
            tenantId,
            'iam:packages:assign',
            assignment.packageId,
            'revoke a package',
          );
          await revokeAssignment(ctx, tx, assignment);
          await audit('package:revoke', assignment.packageId, {
            packageId: assignment.packageId,
            identityId: target.id,
          });
        }
        return assignments.length
          ? { outcome: 'done', detail: `${assignments.length} packages`, changed: true }
          : { outcome: 'skipped', detail: 'no packages' };
      }
      case 'send-email': {
        if (!canEmail()) return { outcome: 'skipped', detail: 'no email delivery configured' };
        let to: string | undefined;
        if (step.to === 'subject') to = target.email;
        else if (step.to === 'manager') {
          const manager = target.managerId
            ? await tx.get<Identity>('identities', target.managerId)
            : undefined;
          to = manager?.status === 'active' ? manager.email : undefined;
        } else to = step.to;
        if (!to) return { outcome: 'skipped', detail: `no address for ${step.to}` };
        const values = { identity: target, organization: tenant.name, workflow: run.workflowName };
        await ctx.auth.enqueueDelivery(tx, {
          tenantId,
          kind: 'email',
          to,
          template: 'workflow-message',
          payload: {
            tenantId,
            tenantName: tenant.name,
            workflowName: run.workflowName,
            subject: fillTemplate(step.subject, values).slice(0, 300),
            body: fillTemplate(step.body, values).slice(0, 10_000),
          },
        });
        return { outcome: 'done', detail: step.to === to ? 'sent' : `sent to ${step.to}` };
      }
      case 'revoke-sessions':
        await ctx.revokeAll(tx, target.id);
        await audit('identity:revoke-sessions', target.id, {});
        return { outcome: 'done' };
      case 'disable': {
        if (target.status === 'disabled') return { outcome: 'skipped', detail: 'already disabled' };
        await ctx.protectLastOwner(tx, target);
        await tx.put<Identity>('identities', { ...target, status: 'disabled' });
        await endContainment(tx, target.id, ctx.now());
        await ctx.revokeAll(tx, target.id);
        // As setStatus does: invitations the person sent and nobody redeemed yet are revoked.
        for (const invitation of await tx.find<StoredRecord>('memberInvitations', { inviterId: target.id }))
          if (!invitation.consumed && !invitation.revoked)
            await tx.put('memberInvitations', { ...invitation, revoked: true });
        await audit('iam:identities:update', target.id, { status: 'disabled' });
        return { outcome: 'done', changed: true };
      }
      case 'enable': {
        if (target.status === 'active') return { outcome: 'skipped', detail: 'already active' };
        if (ctx.identityExpired(target))
          throw new IamError(
            'INVALID_TRANSITION',
            'The account has expired; extend or clear expiresAt first',
            409,
          );
        await tx.put<Identity>('identities', { ...target, status: 'active' });
        // As setStatus does: re-enabling ends a threats containment.
        await endContainment(tx, target.id, ctx.now());
        await audit('iam:identities:update', target.id, { status: 'active' });
        return { outcome: 'done', changed: true };
      }
      case 'set-attributes': {
        const next: Record<string, Json> = { ...(target.attributes ?? {}) };
        const setting: Record<string, Json> = {};
        for (const [name, value] of Object.entries(step.attributes))
          if (value === null) delete next[name];
          else setting[name] = value;
        Object.assign(next, attributeValues(ctx.catalog.identityAttributes, setting));
        const { attributes: _previous, ...rest } = target;
        await tx.put<Identity>('identities', {
          ...rest,
          ...(Object.keys(next).length ? { attributes: next } : {}),
        });
        await audit('iam:identities:update', target.id, {
          attributes: Object.keys(step.attributes).sort(),
        });
        return { outcome: 'done', changed: true };
      }
      case 'set-expiry': {
        const { expiresAt: _previous, ...rest } = target;
        await tx.put<Identity>('identities', {
          ...rest,
          ...(step.days === null ? {} : { expiresAt: now + step.days * dayMs }),
        });
        await audit('iam:identities:update', target.id, {
          expiresAt: step.days === null ? null : now + step.days * dayMs,
        });
        return { outcome: 'done', changed: true };
      }
      case 'delete': {
        await deleteIdentity(ctx, tx, owner, target);
        await audit('identity:delete', target.id, { kind: target.kind });
        return { outcome: 'done', changed: true };
      }
      case 'emit-event':
        await audit('workflow:event', target.id, { name: step.name });
        return { outcome: 'done', detail: step.name };
      case 'wait':
        return { outcome: 'done' };
    }
  }

  const clearLease = (run: WorkflowRun): WorkflowRun => {
    const { leaseToken: _token, leaseUntil: _until, ...rest } = run;
    return rest;
  };

  /** Runs one run's steps until it waits, finishes or fails. Returns its final status. */
  async function execute(runId: string): Promise<WorkflowRunStatus | undefined> {
    const token = randomBytes(12).toString('base64url');
    const claimed = await store.transaction(async (tx) => {
      const run = await tx.get<WorkflowRun>('workflowRuns', runId);
      const now = ctx.now();
      if (!run) return false;
      if (run.status === 'running' && (run.leaseUntil ?? 0) > now) return false;
      if (!['pending', 'waiting', 'running'].includes(run.status) || run.nextAt > now) return false;
      await tx.put<WorkflowRun>('workflowRuns', {
        ...run,
        status: 'running',
        leaseToken: token,
        leaseUntil: now + leaseMs,
      });
      return true;
    });
    if (!claimed) return undefined;
    for (let guard = 0; guard <= 25; guard++) {
      let changed = false;
      let tenantId = '';
      let identityId = '';
      try {
        const next = await store.transaction(async (tx) => {
          const run = await tx.get<WorkflowRun>('workflowRuns', runId);
          if (!run || run.leaseToken !== token || run.status !== 'running') return 'stop' as const;
          tenantId = run.tenantId;
          identityId = run.identityId;
          const now = ctx.now();
          if (run.stepIndex >= run.steps.length) {
            await tx.put<WorkflowRun>('workflowRuns', {
              ...clearLease(run),
              status: 'completed',
              finishedAt: now,
              expiresAt: now + runRetentionMs,
            });
            await ctx.events.recordAudit(tx, {
              id: id(),
              tenantId: run.tenantId,
              actorId: 'deployment-operator',
              action: 'workflow:run:complete',
              resourceId: run.id,
              timestamp: now,
              outcome: 'allow',
              metadata: { workflowId: run.workflowId, identityId: run.identityId },
            });
            return 'stop' as const;
          }
          const workflow = await tx.get<Workflow>('workflows', run.workflowId);
          if (!workflow)
            throw new IamError('NOT_FOUND', 'The workflow was deleted', 404);
          // The rights of the owner who approved these steps: a later editor never lends theirs to old step lists.
          const owner = await tx.get<Identity>('identities', run.ownerId);
          if (!owner || owner.status !== 'active' || ctx.identityExpired(owner))
            throw new IamError(
              'OWNER_INACTIVE',
              'The owner of these steps is no longer active; cancel the run, or save the workflow again and start a new one',
              409,
            );
          const tenant = await ctx.tenant(tx, run.tenantId);
          if (tenant.status !== 'active')
            throw new IamError('TENANT_INACTIVE', 'Tenant inactive', 403);
          const step = run.steps[run.stepIndex]!;
          if (step.kind === 'wait') {
            const until = now + step.hours * 3_600_000;
            await tx.put<WorkflowRun>('workflowRuns', {
              ...clearLease(run),
              status: 'waiting',
              nextAt: until,
              stepIndex: run.stepIndex + 1,
              results: [
                ...run.results,
                {
                  index: run.stepIndex,
                  kind: 'wait',
                  outcome: 'done',
                  at: now,
                  detail: `until ${new Date(until).toISOString()}`,
                },
              ],
            });
            return 'stop' as const;
          }
          const principal = ctx.decisions.simulatedPrincipal(owner, run.ownerMfa === true);
          const result = await perform(tx, principal, tenant, run, step);
          changed = Boolean(result.changed);
          await tx.put<WorkflowRun>('workflowRuns', {
            ...run,
            stepIndex: run.stepIndex + 1,
            leaseUntil: now + leaseMs,
            results: [
              ...run.results,
              {
                index: run.stepIndex,
                kind: step.kind,
                outcome: result.outcome,
                at: now,
                ...(result.detail ? { detail: result.detail.slice(0, 300) } : {}),
              },
            ],
          });
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: run.tenantId,
            actorId: 'deployment-operator',
            action: 'workflow:step',
            resourceId: run.id,
            timestamp: now,
            outcome: 'allow',
            metadata: {
              workflowId: run.workflowId,
              identityId: run.identityId,
              index: run.stepIndex,
              kind: step.kind,
              outcome: result.outcome,
            },
          });
          return 'next' as const;
        });
        if (changed) await afterIdentityChange(ctx, tenantId, [identityId], undefined);
        if (next === 'stop') break;
      } catch (error) {
        const code = error instanceof IamError ? error.code : 'STEP_FAILED';
        const message = (error instanceof Error ? error.message : String(error)).slice(0, 500);
        await store.transaction(async (tx) => {
          const run = await tx.get<WorkflowRun>('workflowRuns', runId);
          if (!run || run.leaseToken !== token) return;
          const now = ctx.now();
          const step = run.steps[run.stepIndex];
          await tx.put<WorkflowRun>('workflowRuns', {
            ...clearLease(run),
            status: 'failed',
            finishedAt: now,
            expiresAt: now + runRetentionMs,
            error: { code, message },
            results: step
              ? [
                  ...run.results,
                  { index: run.stepIndex, kind: step.kind, outcome: 'failed', at: now, code, detail: message },
                ]
              : run.results,
          });
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: run.tenantId,
            actorId: 'deployment-operator',
            action: 'workflow:run:fail',
            resourceId: run.id,
            timestamp: now,
            outcome: 'deny',
            metadata: {
              workflowId: run.workflowId,
              identityId: run.identityId,
              index: run.stepIndex,
              code,
            },
          });
        });
        break;
      }
    }
    return (await store.transaction((tx) => tx.get<WorkflowRun>('workflowRuns', runId)))?.status;
  }

  /** Starts the runs a workflow's trigger calls for now. Returns how many started. */
  async function evaluateWorkflow(workflowId: string): Promise<number> {
    return store.transaction(async (tx) => {
      const workflow = await tx.get<Workflow>('workflows', workflowId);
      if (!workflow?.enabled || workflow.trigger.kind === 'manual') return 0;
      const tenant = await tx.get<Tenant>('tenants', workflow.tenantId);
      if (!tenant || tenant.status !== 'active') return 0;
      const now = ctx.now();
      const tenantId = workflow.tenantId;
      const people = (await tx.find<Identity>('identities', { tenantId })).filter(
        (identity) => identity.kind === 'user' && identity.status !== 'deleted',
      );
      const tracked = workflow.trigger.kind === 'mover' || workflow.trigger.kind === 'leaver';
      // Per person: the mover/leaver baseline, and which occurrences already fired (runs themselves expire).
      const snapshots = new Map(
        (
          await tx.find<WorkflowSubject>('workflowSubjects', {
            tenantId,
            workflowId: workflow.id,
          })
        ).map((subject) => [subject.identityId, subject]),
      );
      let facts: { members: Map<string, string[]>; org?: Awaited<ReturnType<typeof loadOrgFacts>> } | undefined;
      const scopeDocument = workflow.scope ? ruleDocument(workflow.scope) : undefined;
      const inScope = async (identity: Identity) => {
        if (!scopeDocument) return true;
        if (!facts) {
          const members = new Map<string, string[]>();
          for (const member of await tx.find<GroupMember>('groupMembers', { tenantId }))
            if (member.packageAssignmentId === undefined && ctx.liveMembership(member))
              members.set(member.identityId, [...(members.get(member.identityId) ?? []), member.groupId]);
          facts = { members, org: await loadOrgFacts(tx, tenantId, now) };
        }
        const direct = facts.members.get(identity.id) ?? [];
        return ruleMatch(
          scopeDocument,
          identity,
          ruleContext(identity, direct, facts.org?.of(identity.id, direct)),
        ).matched;
      };
      const writeSnapshot = async (
        identity: Identity,
        snapshot: Pick<WorkflowSubject, 'values' | 'status' | 'fired'>,
        occurrence?: string,
      ) => {
        const previous = snapshots.get(identity.id);
        const record: WorkflowSubject = {
          id: previous?.id ?? id(),
          tenantId,
          uniqueKey: `${workflow.id}:${identity.id}`,
          workflowId: workflow.id,
          identityId: identity.id,
          ...snapshot,
          ...(occurrence || previous?.occurrences?.length
            ? {
                occurrences: [...(previous?.occurrences ?? []), ...(occurrence ? [occurrence] : [])].slice(
                  -20,
                ),
              }
            : {}),
        };
        await (previous ? tx.put('workflowSubjects', record) : tx.insert('workflowSubjects', record));
        snapshots.set(identity.id, record);
      };
      const candidates: Array<{
        identity: Identity;
        occurrence: string;
        snapshot?: Pick<WorkflowSubject, 'values' | 'status' | 'fired'>;
      }> = [];
      for (const identity of people) {
        const previous = snapshots.get(identity.id);
        const { occurrence, snapshot } = triggerOccurrence(
          workflow,
          identity,
          tracked ? previous : undefined,
          now,
        );
        if (
          occurrence &&
          !previous?.occurrences?.includes(occurrence) &&
          (await inScope(identity))
        )
          candidates.push({ identity, occurrence, ...(snapshot ? { snapshot } : {}) });
        // A change outside the scope (or already run) is taken as the new baseline right away.
        else if (snapshot && tracked) await writeSnapshot(identity, snapshot);
      }
      if (!candidates.length) return 0;
      const today = utcDay(now);
      const startedToday = workflow.startedOn === today ? (workflow.startedToday ?? 0) : 0;
      // The brake admits runs up to the day's allowance and holds the rest (their baselines stay unchanged, so
      // they start on a later day or after someone raises the limit).
      const allowance = Math.max(0, workflow.maxRunsPerDay - startedToday);
      const admitted = candidates.slice(0, allowance);
      const held = candidates.length - admitted.length;
      const braked = held > 0 && workflow.brakedOn !== today;
      await tx.put<Workflow>('workflows', {
        ...workflow,
        startedOn: today,
        startedToday: startedToday + admitted.length,
        ...(braked ? { brakedOn: today } : {}),
      });
      if (braked)
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'deployment-operator',
          action: 'workflow:brake',
          resourceId: workflow.id,
          timestamp: now,
          outcome: 'deny',
          metadata: {
            held,
            startedToday: startedToday + admitted.length,
            maxRunsPerDay: workflow.maxRunsPerDay,
          },
        });
      for (const candidate of admitted) {
        const base = snapshots.get(candidate.identity.id);
        await writeSnapshot(
          candidate.identity,
          candidate.snapshot ??
            (base
              ? { values: base.values, status: base.status, fired: base.fired }
              : { values: {}, status: candidate.identity.status, fired: 0 }),
          candidate.occurrence,
        );
        const run: WorkflowRun = {
          id: id(),
          tenantId,
          // No uniqueKey: which occurrences already ran is kept on the person's workflowSubjects record, which a
          // restart resets, while older runs of the same occurrence may still exist.
          workflowId: workflow.id,
          workflowName: workflow.name,
          workflowVersion: workflow.version,
          identityId: candidate.identity.id,
          occurrence: candidate.occurrence,
          trigger: workflow.trigger.kind,
          steps: workflow.steps,
          ownerId: workflow.ownerId,
          ownerMfa: workflow.ownerMfa === true,
          status: 'pending',
          stepIndex: 0,
          nextAt: now,
          results: [],
          startedAt: now,
        };
        await tx.insert('workflowRuns', run);
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'deployment-operator',
          action: 'workflow:run:start',
          resourceId: run.id,
          timestamp: now,
          outcome: 'allow',
          metadata: {
            workflowId: workflow.id,
            identityId: candidate.identity.id,
            occurrence: candidate.occurrence,
          },
        });
      }
      return admitted.length;
    });
  }

  /** Evaluates every enabled workflow (of one tenant) and runs what is due. */
  async function runDue(
    input: { tenantId?: string; limit?: number } = {},
  ): Promise<WorkflowJobResult> {
    const limit = integer(input.limit ?? 500, 'limit', 1, 10_000);
    const filter = input.tenantId === undefined ? {} : { tenantId: text(input.tenantId, 'tenantId') };
    const result: WorkflowJobResult = { started: 0, executed: 0, completed: 0, failed: 0, waiting: 0 };
    const workflows = await store.transaction((tx) => tx.find<Workflow>('workflows', filter));
    for (const workflow of workflows)
      if (workflow.enabled && workflow.trigger.kind !== 'manual')
        try {
          result.started += await evaluateWorkflow(workflow.id);
        } catch {
          // One workflow's failure (a lock timeout, a record another process changed) never stops the others.
        }
    const now = ctx.now();
    const due = await store.transaction(async (tx) =>
      [
        ...(await tx.find<WorkflowRun>('workflowRuns', { ...filter, status: 'pending' })),
        ...(await tx.find<WorkflowRun>('workflowRuns', { ...filter, status: 'waiting' })),
        ...(await tx.find<WorkflowRun>('workflowRuns', { ...filter, status: 'running' })).filter(
          (run) => (run.leaseUntil ?? 0) <= now,
        ),
      ]
        .filter((run) => run.nextAt <= now)
        .sort((a, b) => a.nextAt - b.nextAt || (a.id < b.id ? -1 : 1))
        .slice(0, limit),
    );
    for (const run of due) {
      const status = await execute(run.id);
      if (!status) continue;
      result.executed++;
      if (status === 'completed') result.completed++;
      else if (status === 'failed') result.failed++;
      else if (status === 'waiting') result.waiting++;
    }
    return result;
  }

  return { execute, evaluateWorkflow, runDue, perform };
}

/**
 * Identity lifecycle workflows: joiner, mover and leaver automation. A workflow has a trigger, a scope (the
 * access-package rule language over the person's attributes, groups, teams and departments) and steps (group and
 * package changes, emails, sign-outs, disabling, attribute and expiry changes, deletion, events for webhooks, and
 * waits). Steps run under the rights of whoever saved the workflow, re-checked at every step. Managing needs
 * `iam:workflows:manage`, reading `iam:workflows:read`, starting and retrying runs `iam:workflows:run`.
 */
export function createWorkflowsApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const run = engine(ctx);
  /** May the caller see people's names and addresses (`iam:identities:read`)? Otherwise views carry IDs only. */
  const directory = async (tx: IamStore, principal: AuthenticatedPrincipal, tenantId: string) =>
    (
      await ctx.decisions.decide(
        tx,
        principal,
        { tenantId, action: 'iam:identities:read', resource: { type: 'iam', id: tenantId } },
        true,
      )
    ).allowed;
  const names = async (
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    identityIds: string[],
  ) => {
    const result = new Map<string, string>();
    if (!(await directory(tx, principal, tenantId))) return result;
    for (const identityId of new Set(identityIds)) {
      const identity = await tx.get<Identity>('identities', identityId);
      if (identity) result.set(identityId, identity.email ?? identity.name);
    }
    return result;
  };
  const runStats = (runs: WorkflowRun[], now: number): NonNullable<WorkflowView['runs']> => {
    const last = runs.reduce((latest, item) => Math.max(latest, item.startedAt), 0);
    return {
      last30Days: runs.filter((item) => item.startedAt > now - 30 * dayMs).length,
      active: runs.filter((item) => ['pending', 'running', 'waiting'].includes(item.status)).length,
      failed: runs.filter((item) => item.status === 'failed').length,
      ...(last ? { lastRunAt: last } : {}),
    };
  };
  /** Starts manual runs for people (the caller needs the steps' rights over each of them). */
  async function startManual(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    workflow: Workflow,
    identityIds: string[],
  ): Promise<WorkflowRun[]> {
    await assertOwnerRights(ctx, tx, principal, workflow.tenantId, workflow.steps, identityIds);
    if (
      identityIds.includes(principal.identity.id) &&
      workflow.steps.some((step) => selfChanging.has(step.kind))
    )
      throw new IamError(
        'ACCESS_DENIED',
        'Nobody changes their own account through a workflow they start',
        403,
      );
    const now = ctx.now();
    const created: WorkflowRun[] = [];
    for (const identityId of identityIds) {
      const identity = await ctx.activeIdentity(tx, identityId, workflow.tenantId);
      if (identity.kind !== 'user')
        throw new IamError('INVALID_INPUT', 'Workflows run for people');
      const occurrence = `manual:${id()}`;
      const record: WorkflowRun = {
        id: id(),
        tenantId: workflow.tenantId,
        workflowId: workflow.id,
        workflowName: workflow.name,
        workflowVersion: workflow.version,
        identityId: identity.id,
        occurrence,
        trigger: workflow.trigger.kind,
        steps: workflow.steps,
        ownerId: workflow.ownerId,
        ownerMfa: workflow.ownerMfa === true,
        status: 'pending',
        stepIndex: 0,
        nextAt: now,
        results: [],
        startedAt: now,
        startedBy: principal.identity.id,
      };
      await tx.insert('workflowRuns', record);
      await ctx.events.audit(tx, principal, 'workflow:run:start', workflow.tenantId, record.id, 'allow', false, {
        workflowId: workflow.id,
        identityId: identity.id,
        occurrence,
      });
      created.push(record);
    }
    return created;
  }
  const settle = async (tenantId: string, runIds: string[]): Promise<WorkflowRunView[]> => {
    for (const runId of runIds) await run.execute(runId);
    return ctx.store.transaction(async (tx) => {
      const records = (
        await Promise.all(runIds.map((runId) => tx.get<WorkflowRun>('workflowRuns', runId)))
      ).filter((item): item is WorkflowRun => Boolean(item && item.tenantId === tenantId));
      // Listed by ID: the caller may run steps without being allowed to read the directory.
      return records.map((item) => runView(item));
    });
  };

  return {
    /**
     * Creates a workflow owned by the caller, who must hold every right its steps use. Mover and leaver workflows
     * take everyone's current values as their baseline, so only later changes fire.
     */
    create: async (credential: CredentialInput, input: WorkflowInput & { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:workflows:manage', input.tenantId, async ({ tx, tenant, principal }) => {
        const values = await workflowFields(ctx, tx, tenant.id, input);
        const existing = await tx.find<Workflow>('workflows', { tenantId: tenant.id });
        if (existing.some((workflow) => workflow.uniqueKey === values.uniqueKey))
          throw new IamError('CONFLICT', 'A workflow with this name exists', 409);
        if (existing.length >= maxWorkflows)
          throw new IamError('LIMIT_EXCEEDED', `At most ${maxWorkflows} workflows`, 409);
        await assertOwnerRights(ctx, tx, principal, tenant.id, values.steps);
        if (values.steps.some((step) => destructiveSteps.has(step.kind)))
          ctx.auth.requireRecent(principal);
        const now = ctx.now();
        const workflow = await tx.insert<Workflow>('workflows', {
          ...values,
          id: id(),
          tenantId: tenant.id,
          ownerId: principal.identity.id,
          ownerMfa: principal.session.mfa,
          version: 1,
          activeSince: now,
          createdAt: now,
          updatedAt: now,
        });
        await rebuildSnapshots(tx, workflow, now);
        return workflowView(workflow, { ownerName: principal.identity.email ?? principal.identity.name });
      }),
    /**
     * Edits a workflow; the caller becomes its owner (and must hold the steps' rights). Changing the trigger or
     * enabling it again starts it afresh: joiners and dates count from now, and mover and leaver baselines are retaken.
     * Runs already started keep the steps they started with, and the rights of the owner who approved them, unless
     * `activeRuns: 'cancel'` stops them.
     */
    update: async (
      credential: CredentialInput,
      input: Partial<WorkflowInput> & {
        tenantId: string;
        workflowId: string;
        activeRuns?: 'keep' | 'cancel';
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:workflows:manage',
        text(input.workflowId, 'workflowId'),
        async ({ tx, tenant, principal }) => {
          const previous = await ctx.scoped<Workflow>(tx, 'workflows', input.workflowId, tenant.id);
          const values = await workflowFields(ctx, tx, tenant.id, input, previous);
          if (
            (await tx.find<Workflow>('workflows', { tenantId: tenant.id })).some(
              (workflow) => workflow.id !== previous.id && workflow.uniqueKey === values.uniqueKey,
            )
          )
            throw new IamError('CONFLICT', 'A workflow with this name exists', 409);
          await assertOwnerRights(ctx, tx, principal, tenant.id, values.steps);
          if (values.steps.some((step) => destructiveSteps.has(step.kind)))
            ctx.auth.requireRecent(principal);
          const now = ctx.now();
          const restart =
            JSON.stringify(values.trigger) !== JSON.stringify(previous.trigger) ||
            (values.enabled && !previous.enabled);
          const {
            description: _description,
            scope: _scope,
            brakedOn: _braked,
            ...kept
          } = previous;
          if (input.activeRuns !== undefined && input.activeRuns !== 'keep' && input.activeRuns !== 'cancel')
            throw new IamError('INVALID_INPUT', "activeRuns must be 'keep' or 'cancel'");
          const workflow = await tx.put<Workflow>('workflows', {
            ...kept,
            ...values,
            ownerId: principal.identity.id,
            ownerMfa: principal.session.mfa,
            version: previous.version + 1,
            activeSince: restart ? now : previous.activeSince,
            updatedAt: now,
            ...(previous.brakedOn && input.maxRunsPerDay === undefined
              ? { brakedOn: previous.brakedOn }
              : {}),
          });
          if (restart) await rebuildSnapshots(tx, workflow, now);
          if (input.activeRuns === 'cancel')
            for (const item of await tx.find<WorkflowRun>('workflowRuns', {
              tenantId: tenant.id,
              workflowId: workflow.id,
            }))
              if (['pending', 'waiting', 'running', 'failed'].includes(item.status)) {
                const { leaseToken: _token, leaseUntil: _until, ...rest } = item;
                await tx.put<WorkflowRun>('workflowRuns', {
                  ...rest,
                  status: 'cancelled',
                  finishedAt: now,
                  expiresAt: now + runRetentionMs,
                });
              }
          return workflowView(workflow, { ownerName: principal.identity.email ?? principal.identity.name });
        },
      ),
    /** Deletes a workflow and cancels its pending and waiting runs; finished runs stay as history. */
    delete: async (credential: CredentialInput, input: { tenantId: string; workflowId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:workflows:manage',
        text(input.workflowId, 'workflowId'),
        async ({ tx, tenant }) => {
          const workflow = await ctx.scoped<Workflow>(tx, 'workflows', input.workflowId, tenant.id);
          const now = ctx.now();
          let cancelled = 0;
          for (const item of await tx.find<WorkflowRun>('workflowRuns', {
            tenantId: tenant.id,
            workflowId: workflow.id,
          }))
            if (['pending', 'waiting', 'running'].includes(item.status)) {
              const { leaseToken: _token, leaseUntil: _until, ...rest } = item;
              await tx.put<WorkflowRun>('workflowRuns', {
                ...rest,
                status: 'cancelled',
                finishedAt: now,
                expiresAt: now + runRetentionMs,
              });
              cancelled++;
            }
          for (const subject of await tx.find<WorkflowSubject>('workflowSubjects', {
            tenantId: tenant.id,
            workflowId: workflow.id,
          }))
            await tx.delete('workflowSubjects', subject.id);
          await tx.delete('workflows', workflow.id);
          return { deleted: true, runsCancelled: cancelled };
        },
      ),
    list: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:workflows:read', input.tenantId, async ({ tx, tenant, principal }) => {
        const workflows = await tx.find<Workflow>('workflows', { tenantId: tenant.id });
        const runs = await tx.find<WorkflowRun>('workflowRuns', { tenantId: tenant.id });
        const owners = await names(tx, principal, tenant.id, workflows.map((workflow) => workflow.ownerId));
        const now = ctx.now();
        return workflows
          .sort((a, b) => a.name.localeCompare(b.name))
          .map((workflow) =>
            workflowView(workflow, {
              ...(owners.get(workflow.ownerId) ? { ownerName: owners.get(workflow.ownerId)! } : {}),
              runs: runStats(
                runs.filter((item) => item.workflowId === workflow.id),
                now,
              ),
            }),
          );
      }),
    get: async (credential: CredentialInput, input: { tenantId: string; workflowId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:workflows:read',
        text(input.workflowId, 'workflowId'),
        async ({ tx, tenant, principal }) => {
          const workflow = await ctx.scoped<Workflow>(tx, 'workflows', input.workflowId, tenant.id);
          const runs = (
            await tx.find<WorkflowRun>('workflowRuns', { tenantId: tenant.id, workflowId: workflow.id })
          ).sort((a, b) => b.startedAt - a.startedAt || (a.id < b.id ? -1 : 1));
          const known = await names(tx, principal, tenant.id, [
            workflow.ownerId,
            ...runs.slice(0, 50).map((item) => item.identityId),
          ]);
          return {
            ...workflowView(workflow, {
              ...(known.get(workflow.ownerId) ? { ownerName: known.get(workflow.ownerId)! } : {}),
              runs: runStats(runs, ctx.now()),
            }),
            recentRuns: runs.slice(0, 50).map((item) => runView(item, known.get(item.identityId))),
          };
        },
      ),
    /**
     * What the workflow would do right now: who its scope matches, who a run would start for at the next evaluation,
     * upcoming dates (30 days), and whether the owner still holds each step's rights. Changes nothing.
     */
    preview: async (
      credential: CredentialInput,
      input: { tenantId: string; workflowId: string },
    ): Promise<WorkflowPreview> =>
      operation(
        credential,
        input.tenantId,
        'iam:workflows:read',
        text(input.workflowId, 'workflowId'),
        async ({ tx, tenant, principal }) => {
          const workflow = await ctx.scoped<Workflow>(tx, 'workflows', input.workflowId, tenant.id);
          const now = ctx.now();
          const visible = await directory(tx, principal, tenant.id);
          const people = (await tx.find<Identity>('identities', { tenantId: tenant.id })).filter(
            (identity) => identity.kind === 'user' && identity.status === 'active',
          );
          const members = new Map<string, string[]>();
          for (const member of await tx.find<GroupMember>('groupMembers', { tenantId: tenant.id }))
            if (member.packageAssignmentId === undefined && ctx.liveMembership(member))
              members.set(member.identityId, [...(members.get(member.identityId) ?? []), member.groupId]);
          const org = await loadOrgFacts(tx, tenant.id, now);
          const document = workflow.scope ? ruleDocument(workflow.scope) : undefined;
          const snapshots = new Map(
            (
              await tx.find<WorkflowSubject>('workflowSubjects', {
                tenantId: tenant.id,
                workflowId: workflow.id,
              })
            ).map((subject) => [subject.identityId, subject]),
          );
          const tracked = workflow.trigger.kind === 'mover' || workflow.trigger.kind === 'leaver';
          const preview: WorkflowPreview = { inScope: [], wouldStart: [], upcoming: [], steps: [] };
          for (const identity of people) {
            const direct = members.get(identity.id) ?? [];
            if (
              document &&
              !ruleMatch(document, identity, ruleContext(identity, direct, org.of(identity.id, direct)))
                .matched
            )
              continue;
            // Names and addresses only for callers who may read the directory; IDs otherwise.
            const name = visible ? identity.name : identity.id;
            preview.inScope.push({
              id: identity.id,
              name,
              ...(visible && identity.email ? { email: identity.email } : {}),
            });
            const subject = snapshots.get(identity.id);
            const { occurrence } = triggerOccurrence(workflow, identity, tracked ? subject : undefined, now);
            if (workflow.enabled && occurrence && !subject?.occurrences?.includes(occurrence))
              preview.wouldStart.push({ id: identity.id, name, occurrence });
            if (workflow.trigger.kind === 'date') {
              const at = dateTarget(workflow.trigger, identity);
              if (at !== undefined && at > now && at <= now + 30 * dayMs)
                preview.upcoming.push({ id: identity.id, name, at });
            }
          }
          preview.upcoming.sort((a, b) => a.at - b.at);
          const owner = await tx.get<Identity>('identities', workflow.ownerId);
          const ownerPrincipal =
            owner && owner.status === 'active'
              ? ctx.decisions.simulatedPrincipal(owner, workflow.ownerMfa === true)
              : undefined;
          for (const [index, step] of workflow.steps.entries()) {
            let allowed = Boolean(ownerPrincipal);
            let reason: string | undefined = ownerPrincipal ? undefined : 'The owner is no longer active';
            if (ownerPrincipal)
              for (const [action, resource] of requirements(step, tenant.id)) {
                const decision = await ctx.decisions.decide(
                  tx,
                  ownerPrincipal,
                  { tenantId: tenant.id, action, resource: { type: 'iam', id: resource } },
                  true,
                );
                if (!decision.allowed) {
                  allowed = false;
                  reason = `The owner lacks ${action} on ${resource}`;
                  break;
                }
              }
            preview.steps.push({ index, kind: step.kind, allowed, ...(reason ? { reason } : {}) });
          }
          return preview;
        },
      ),
    /**
     * Runs a workflow now for up to 100 people, whatever its trigger (the scope is not applied: you choose the
     * people). The caller needs the steps' rights over each of them. Steps run until the first wait before this returns.
     */
    run: async (
      credential: CredentialInput,
      input: { tenantId: string; workflowId: string; identityIds: string[] },
    ) => {
      const identityIds = [...new Set(strings(input.identityIds, 'identityIds'))];
      if (!identityIds.length) throw new IamError('INVALID_INPUT', 'Provide 1-100 identityIds');
      const created = await operation(
        credential,
        input.tenantId,
        'iam:workflows:run',
        text(input.workflowId, 'workflowId'),
        async ({ tx, tenant, principal }) => {
          const workflow = await ctx.scoped<Workflow>(tx, 'workflows', input.workflowId, tenant.id);
          if (workflow.steps.some((step) => destructiveSteps.has(step.kind)))
            ctx.auth.requireRecent(principal);
          return startManual(tx, principal, workflow, identityIds);
        },
      );
      return settle(input.tenantId, created.map((item) => item.id));
    },
    listRuns: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        workflowId?: string;
        identityId?: string;
        status?: WorkflowRunStatus;
        limit?: number;
        offset?: number;
      },
    ) =>
      operation(credential, input.tenantId, 'iam:workflows:read', input.tenantId, async ({ tx, tenant, principal }) => {
        const limit = integer(input.limit ?? 100, 'limit', 1, 500);
        const offset = integer(input.offset ?? 0, 'offset', 0, 10_000_000);
        const filter: Record<string, unknown> = { tenantId: tenant.id };
        if (input.workflowId !== undefined) filter.workflowId = text(input.workflowId, 'workflowId');
        if (input.identityId !== undefined) filter.identityId = text(input.identityId, 'identityId');
        if (input.status !== undefined) filter.status = text(input.status, 'status', 32);
        const rows = (await tx.find<WorkflowRun>('workflowRuns', filter)).sort(
          (a, b) => b.startedAt - a.startedAt || (a.id < b.id ? -1 : 1),
        );
        const page = rows.slice(offset, offset + limit);
        const known = await names(tx, principal, tenant.id, page.map((item) => item.identityId));
        return { total: rows.length, runs: page.map((item) => runView(item, known.get(item.identityId))) };
      }),
    getRun: async (credential: CredentialInput, input: { tenantId: string; runId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:workflows:read',
        text(input.runId, 'runId'),
        async ({ tx, tenant, principal }) => {
          const item = await ctx.scoped<WorkflowRun>(tx, 'workflowRuns', input.runId, tenant.id);
          const known = await names(tx, principal, tenant.id, [item.identityId]);
          return runView(item, known.get(item.identityId));
        },
      ),
    /** Stops a pending, waiting or failed run; steps already done stay done. */
    cancelRun: async (credential: CredentialInput, input: { tenantId: string; runId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:workflows:run',
        text(input.runId, 'runId'),
        async ({ tx, tenant }) => {
          const item = await ctx.scoped<WorkflowRun>(tx, 'workflowRuns', input.runId, tenant.id);
          if (!['pending', 'waiting', 'failed', 'running'].includes(item.status))
            throw new IamError('INVALID_TRANSITION', 'This run already finished', 409);
          const { leaseToken: _token, leaseUntil: _until, ...rest } = item;
          const cancelled = await tx.put<WorkflowRun>('workflowRuns', {
            ...rest,
            status: 'cancelled',
            finishedAt: ctx.now(),
            expiresAt: ctx.now() + runRetentionMs,
          });
          return runView(cancelled);
        },
      ),
    /**
     * Resumes a failed run at the step that failed (after fixing the cause: a deleted group, an owner who left). The
     * caller needs the remaining steps' rights over the person, and the remaining steps then run with the caller's
     * rights: retrying is approving them.
     */
    retryRun: async (credential: CredentialInput, input: { tenantId: string; runId: string }) => {
      const retried = await operation(
        credential,
        input.tenantId,
        'iam:workflows:run',
        text(input.runId, 'runId'),
        async ({ tx, tenant, principal }) => {
          const item = await ctx.scoped<WorkflowRun>(tx, 'workflowRuns', input.runId, tenant.id);
          if (item.status !== 'failed')
            throw new IamError('INVALID_TRANSITION', 'Only failed runs can be retried', 409);
          const remaining = item.steps.slice(item.stepIndex);
          await assertOwnerRights(ctx, tx, principal, tenant.id, remaining, [item.identityId]);
          if (remaining.some((step) => destructiveSteps.has(step.kind))) ctx.auth.requireRecent(principal);
          if (
            item.identityId === principal.identity.id &&
            remaining.some((step) => selfChanging.has(step.kind))
          )
            throw new IamError(
              'ACCESS_DENIED',
              'Nobody changes their own account through a workflow they retry',
              403,
            );
          const { error: _error, finishedAt: _finished, expiresAt: _expires, ...rest } = item;
          await tx.put<WorkflowRun>('workflowRuns', {
            ...rest,
            status: 'pending',
            nextAt: ctx.now(),
            ownerId: principal.identity.id,
            ownerMfa: principal.session.mfa,
            startedBy: principal.identity.id,
          });
          return item.id;
        },
      );
      return (await settle(input.tenantId, [retried]))[0]!;
    },
    /** Evaluates this organization's workflows and runs what is due now, instead of waiting for the scheduler. */
    evaluate: async (credential: CredentialInput, input: { tenantId: string }) => {
      await operation(credential, input.tenantId, 'iam:workflows:run', input.tenantId, async () => true);
      return run.runDue({ tenantId: input.tenantId });
    },
  };
}

/** Audit actions that can change who a workflow fires for: people, their groups, teams and departments, and workflows. */
const reactingPrefixes = [
  'iam:identities:',
  'identity:',
  'iam:groups:',
  'iam:teams:',
  'iam:departments:',
  'iam:workflows:',
  'iam:scim',
  'scim:',
];

/**
 * Workflows for the deployment's own code (`iam.workflows`): the scheduler job `runDue` (every few minutes), and
 * `subscribe()`, which evaluates an organization's workflows shortly after a change to its people is recorded in the
 * audit log (it needs `iam.dispatchAuditHooks()` to be running, as the console does). Returns the unsubscribe
 * function. Evaluations run in the background, debounced per organization, so audit dispatch never waits for them;
 * `idle()` resolves once the scheduled ones have finished.
 */
export function createWorkflowsRuntime(ctx: ServerContext) {
  const run = engine(ctx);
  const busy = new Set<string>();
  const dirty = new Set<string>();
  const pending = new Map<string, Promise<void>>();
  const enabledCache = new Map<string, { at: number; value: boolean }>();
  async function hasWorkflows(tenantId: string): Promise<boolean> {
    const cached = enabledCache.get(tenantId);
    if (cached && cached.at > Date.now() - 15_000) return cached.value;
    const value = (
      await ctx.store.transaction((tx) => tx.find<Workflow>('workflows', { tenantId }))
    ).some((workflow) => workflow.enabled && workflow.trigger.kind !== 'manual');
    enabledCache.set(tenantId, { at: Date.now(), value });
    if (enabledCache.size > 10_000) enabledCache.clear();
    return value;
  }
  async function evaluate(tenantId: string): Promise<void> {
    busy.add(tenantId);
    try {
      do {
        dirty.delete(tenantId);
        if (!(await hasWorkflows(tenantId))) break;
        await run.runDue({ tenantId });
      } while (dirty.has(tenantId));
    } catch {
      // The scheduler catches up; a background evaluation never surfaces.
    } finally {
      busy.delete(tenantId);
      pending.delete(tenantId);
    }
  }
  function react(event: AuditEvent): void {
    // A workflow's own steps (and the run events) never retrigger evaluation; other workflows see them on schedule.
    if (event.metadata?.via === 'workflow') return;
    if (!reactingPrefixes.some((prefix) => event.action.startsWith(prefix))) return;
    const tenantId = event.tenantId;
    if (event.action.startsWith('iam:workflows:')) enabledCache.delete(tenantId);
    if (busy.has(tenantId) || pending.has(tenantId)) {
      dirty.add(tenantId);
      return;
    }
    pending.set(
      tenantId,
      new Promise<void>((resolve) => setTimeout(resolve, 200)).then(() => evaluate(tenantId)),
    );
  }
  return {
    /** Evaluates every enabled workflow and runs the steps that are due (a scheduler job, every few minutes). */
    runDue: run.runDue,
    /** Reacts to changes to each organization's people (see above); returns the unsubscribe function. */
    subscribe: () => ctx.events.subscribe('*', react),
    /** Resolves once every evaluation `subscribe()` scheduled has finished (for tests and graceful shutdown). */
    idle: async () => {
      while (pending.size) await Promise.all([...pending.values()]);
    },
  };
}
