import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
} from '@better-iam/core';
import { defaultApprovalLifetimeMs } from '../access-policy.js';
import type { ServerContext } from '../context.js';
import type {
  AccessPackage,
  AutoAssignRule,
  Binding,
  BindingActivation,
  GrantAuthority,
  Group,
  GroupMember,
  PackageAssignment,
  PackageRequest,
  PackageRequestStatus,
  PackageRuleIssue,
  Role,
} from '../models.js';
import {
  automaticJustification,
  parseAutoAssign,
  ruleInput,
  ruleProblem,
  type AutoAssignInput,
  type RuleEnvironment,
  type RuleKey,
} from '../package-rules.js';
import { orgRuleEnvironment } from '../org-rules.js';
import { actsInOwnRight } from '../session-kinds.js';
import { assertNotTeamGroup, syncTeamsFromGroups } from '../teams.js';
import { id } from '../utils.js';
import { integer, strings, text } from '../validation.js';
import { createBinding } from './bindings.js';
import { addGroupMember, updateGroupMember } from './groups.js';
import {
  approveRule,
  autoAssignView,
  previewRule,
  reconcilePackageRules,
} from './package-automation.js';

export type { AutoAssignInput } from '../package-rules.js';

export interface PackageInput {
  tenantId: string;
  name: string;
  description?: string;
  roleIds?: string[];
  groupIds?: string[];
  /** Longest assignment the package allows (a minute to ten years); assignments must then state an end within it. */
  maxDurationMs?: number;
  /** Assignments must state a justification. */
  requireJustification?: boolean;
  /** Members holding iam:packages:request may ask for the package. */
  requestable?: boolean;
  /** Group whose members decide on requests (and are emailed them); null means anyone holding iam:packages:approve. */
  approverGroupId?: string | null;
  /** The requester's manager may decide (and is emailed each request). */
  managerApproval?: boolean;
  /** Birthright rule; the caller becomes its owner. */
  autoAssign?: AutoAssignInput;
}
export interface PackageUpdate {
  name?: string;
  /** null clears it. */
  description?: string | null;
  roleIds?: string[];
  groupIds?: string[];
  /** null removes the cap. */
  maxDurationMs?: number | null;
  requireJustification?: boolean;
  requestable?: boolean;
  /** null clears the approver group. */
  approverGroupId?: string | null;
  managerApproval?: boolean;
  /** Sets or replaces the rule (the caller becomes its owner); null removes it, and reconciliation removes its automatic assignments. */
  autoAssign?: AutoAssignInput | null;
  /** With autoAssign: null, turns the live automatic assignments into manual ones instead (at most 5000). */
  keepAutomaticAssignments?: boolean;
}
export interface AssignmentInput {
  tenantId: string;
  packageId: string;
  identityId: string;
  expiresAt?: number;
  justification?: string;
}
/** An assignment as the API returns it: the record plus who and what it names, and whether it has ended. */
export interface PackageAssignmentSummary {
  id: string;
  tenantId: string;
  packageId: string;
  identityId: string;
  assignedBy: string;
  assignedAt: number;
  expiresAt?: number;
  justification?: string;
  bindingIds: string[];
  membershipIds: string[];
  packageName: string;
  identityName: string;
  identityEmail?: string;
  expired: boolean;
  /** Its bindings no longer grant (for example the assigner's authority was revoked); assign or request it again. */
  broken: boolean;
  /** Assigned by the package rule. */
  automatic: boolean;
}
/** A request as the API returns it, with the package and requester named. */
export interface PackageRequestSummary {
  id: string;
  tenantId: string;
  packageId: string;
  identityId: string;
  status: PackageRequestStatus;
  requestedAt: number;
  expiresAt: number;
  desiredExpiresAt?: number;
  justification?: string;
  decidedBy?: string;
  decidedAt?: number;
  note?: string;
  assignmentId?: string;
  packageName: string;
  identityName: string;
  identityEmail?: string;
}

export type ReconcileTrigger = 'schedule' | 'identity-change' | 'rule-change' | 'manual';
export type RuleChange = 'assign' | 'refresh' | 'restore' | 'ending' | 'revoke';
export type RuleSuspension =
  | 'invalid-rule'
  | 'owner-inactive'
  | 'authority-revoked'
  | 'owner-lacks-rights';
/** A package's rule as administrators see it: the rule, who it runs as, whether it runs, and what went wrong. */
export interface PublicAutoAssign extends AutoAssignRule {
  ownerName: string;
  status: 'active' | 'suspended';
  suspendedReason?: RuleSuspension;
  suspendedDetail?: string;
  warnings: string[];
  issueCount: number;
  /** Newest first, at most 20. */
  issues: Array<{
    kind: PackageRuleIssue['kind'];
    identityId?: string;
    identityName?: string;
    code: string;
    message: string;
    since: number;
  }>;
}
/** A package as the API returns it (declared field by field: Omit over a stored record loses its property types). */
export interface PublicPackage {
  id: string;
  tenantId: string;
  name: string;
  description?: string;
  roleIds: string[];
  groupIds: string[];
  maxDurationMs?: number;
  requireJustification?: boolean;
  requestable?: boolean;
  approverGroupId?: string;
  managerApproval?: boolean;
  createdAt: number;
  updatedAt: number;
  /** Live holders. */
  assignments: number;
  /** Live holders the rule assigned. */
  automaticAssignments: number;
  autoAssign?: PublicAutoAssign;
}
/** What a reconcile run did, and what needs attention. */
export interface PackageReconcileResult {
  trigger: ReconcileTrigger;
  assigned: number;
  refreshed: number;
  restored: number;
  ending: number;
  revoked: number;
  /** Planned changes skipped because the state moved between planning and applying; retried next run. */
  stale: number;
  failed: Array<{
    tenantId: string;
    packageId: string;
    identityId: string;
    change: RuleChange;
    code: string;
    message: string;
  }>;
  suspended: Array<{ tenantId: string; packageId: string; reason: RuleSuspension; detail: string }>;
  braked: Array<{
    tenantId: string;
    packageId: string;
    direction: 'grants' | 'removals';
    planned: number;
    threshold: number;
  }>;
  skipped: {
    inactiveTenants: number;
    failedTenants: Array<{ tenantId: string; code: string; message: string }>;
  };
  /** The change budget ran out; run again. */
  truncated: boolean;
}
/** What a rule matches and, for a package, what a run would change. */
export interface AutoAssignPreview {
  rule: 'stored' | 'candidate' | 'none';
  keys: RuleKey[];
  warnings: string[];
  matching: number;
  excluded: number;
  frozen: number;
  sample: Array<{
    identityId: string;
    name: string;
    email?: string;
    kind: 'user' | 'service' | 'agent';
    matchedBy: string[];
  }>;
  /** Only with packageId. */
  plan?: {
    assign: number;
    refresh: number;
    restore: number;
    ending: number;
    revoke: number;
    manual: number;
    keep: number;
  };
  changes?: Array<{ identityId: string; name: string; email?: string; change: RuleChange }>;
  brake?: {
    grants: { planned: number; threshold: number; trips: boolean };
    removals: { planned: number; threshold: number; trips: boolean };
  };
  status?: { status: 'active' | 'suspended'; reason?: RuleSuspension; detail?: string };
}

const maxContents = 50;
const tenYears = 315360000000;
const requestStatuses = new Set<PackageRequestStatus>([
  'pending',
  'approved',
  'denied',
  'cancelled',
  'expired',
]);
const nameKey = (name: string) => `name:${name.trim().toLowerCase()}`;
const unique = (items: string[]) => [...new Set(items)];
const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name, 'en');
const sameIds = (a: string[], b: string[]) =>
  a.length === b.length && new Set([...a, ...b]).size === new Set(a).size;

function boolean(value: unknown, name: string): boolean {
  if (typeof value !== 'boolean') throw new IamError('INVALID_INPUT', `${name} must be boolean`);
  return value;
}

/** Whether an assignment still applies; an ended one grants nothing and waits for the purge worker. */
export const liveAssignment = (ctx: ServerContext, assignment: PackageAssignment): boolean =>
  assignment.expiresAt === undefined || assignment.expiresAt > ctx.now();
/** A request that still waits for a decision. */
export const pendingRequest = (
  request: { status: PackageRequestStatus; expiresAt: number },
  now: number,
) => request.status === 'pending' && request.expiresAt > now;
/** Ends compare with "no end" last. */
export const endOf = (expiresAt: number | undefined) => expiresAt ?? Number.POSITIVE_INFINITY;

/** The roles and groups a package bundles must exist in the tenant, and protected roles are never packaged. */
async function contents(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  roleIds: string[],
  groupIds: string[],
): Promise<void> {
  if (roleIds.length > maxContents || groupIds.length > maxContents)
    throw new IamError(
      'INVALID_INPUT',
      `A package holds at most ${maxContents} roles and ${maxContents} groups`,
    );
  if (!roleIds.length && !groupIds.length)
    throw new IamError('INVALID_INPUT', 'A package needs at least one role or group');
  for (const roleId of roleIds) {
    const role = await ctx.scoped<Role>(tx, 'roles', roleId, tenantId);
    if (role.protected)
      throw new IamError('PROTECTED_RESOURCE', 'Protected roles cannot be packaged', 403);
  }
  // A team's backing group takes its members from the team only (teams.ts).
  for (const groupId of groupIds)
    assertNotTeamGroup(await ctx.scoped<Group>(tx, 'groups', groupId, tenantId));
}

async function packageByName(
  tx: IamStore,
  tenantId: string,
  name: string,
): Promise<AccessPackage | undefined> {
  return (
    await tx.find<AccessPackage>('accessPackages', { tenantId, uniqueKey: nameKey(name) })
  )[0];
}

/** Every part of an assignment is authorized like the direct call, so a package never widens what its assigner may grant. */
export async function allow(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  action: string,
  resourceId: string,
  what: string,
): Promise<void> {
  const decision = await ctx.decisions.decide(
    tx,
    principal,
    { tenantId, action, resource: { type: 'iam', id: resourceId } },
    true,
  );
  if (!decision.allowed)
    throw new IamError('ACCESS_DENIED', `Not allowed to ${what} (${action})`, 403);
}

/**
 * The rights assigning a package by hand needs: iam:bindings:create on each role and iam:groups:update on each
 * group, and (with `groupAuthorities`) the use of every grant authority behind the groups' own bindings, which
 * membership confers. Returns the caller's grant authority when the package has roles (or `requireAuthority`).
 * Callers outside a transaction must pass `authorityId`: the root path of grantingAuthority writes a record.
 */
export async function authorizePackage(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  pkg: AccessPackage,
  options: { groupAuthorities?: boolean; authorityId?: string; requireAuthority?: boolean } = {},
): Promise<GrantAuthority | undefined> {
  for (const roleId of pkg.roleIds)
    await allow(
      ctx,
      tx,
      principal,
      pkg.tenantId,
      'iam:bindings:create',
      roleId,
      'grant a packaged role',
    );
  for (const groupId of pkg.groupIds) {
    await allow(
      ctx,
      tx,
      principal,
      pkg.tenantId,
      'iam:groups:update',
      groupId,
      'add to a packaged group',
    );
    if (options.groupAuthorities)
      for (const binding of await tx.find<Binding>('bindings', {
        tenantId: pkg.tenantId,
        subjectType: 'group',
        subjectId: groupId,
      }))
        await ctx.grantingAuthority(tx, principal, pkg.tenantId, binding.authorityId);
  }
  if (!pkg.roleIds.length && !options.requireAuthority && !options.authorityId) return undefined;
  return ctx.grantingAuthority(tx, principal, pkg.tenantId, options.authorityId);
}

/** What a rule of this package may name: the deployment's declared attributes and the tenant's groups, teams, and departments. */
export async function ruleEnvironment(
  ctx: ServerContext,
  reader: IamStore,
  pkg: Pick<AccessPackage, 'tenantId' | 'groupIds'>,
): Promise<RuleEnvironment> {
  return {
    identityAttributes: ctx.catalog.identityAttributes,
    groups: new Set(
      (await reader.find<Group>('groups', { tenantId: pkg.tenantId })).map((group) => group.id),
    ),
    packagedGroups: new Set(pkg.groupIds),
    org: await orgRuleEnvironment(reader, pkg.tenantId),
  };
}

/**
 * The owner checks of a rule: an ordinary session or API key (never a role session, session token or
 * impersonation), iam:packages:assign on the package, the rights assigning by hand needs including the groups'
 * authorities, and a grant authority. The same owner re-saving keeps their authority when it is still usable, to
 * avoid re-issuing every binding.
 */
async function authorRule(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  pkg: AccessPackage,
  previous?: AutoAssignRule,
): Promise<{ ownerId: string; authorityId: string }> {
  if (!actsInOwnRight(principal.session))
    throw new IamError(
      'INVALID_INPUT',
      'Package rules are set from an ordinary session or API key of the tenant',
    );
  if (principal.session.impersonatorId)
    throw new IamError(
      'IMPERSONATION_RESTRICTED',
      'Package rules cannot be set while impersonating',
      403,
    );
  await allow(
    ctx,
    tx,
    principal,
    pkg.tenantId,
    'iam:packages:assign',
    pkg.id,
    'assign this package automatically',
  );
  let keep = previous?.ownerId === principal.identity.id ? previous.authorityId : undefined;
  if (keep)
    try {
      await ctx.grantingAuthority(tx, principal, pkg.tenantId, keep);
    } catch {
      keep = undefined;
    }
  const authority = (await authorizePackage(ctx, tx, principal, pkg, {
    groupAuthorities: true,
    requireAuthority: true,
    ...(keep ? { authorityId: keep } : {}),
  }))!;
  return { ownerId: principal.identity.id, authorityId: authority.id };
}

/**
 * Sets, changes, takes over, or clears a package's rule while the package is created or updated. Changing a rule
 * package's roles or groups re-authorizes the editor, who becomes the owner: someone holding only
 * iam:packages:update cannot add a role that is then granted under another administrator's authority.
 */
async function applyRuleChange(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal | undefined,
  previous: AccessPackage | undefined,
  next: AccessPackage,
  input: AutoAssignInput | null | undefined,
  keep = false,
): Promise<void> {
  const old = previous?.autoAssign;
  const contentsChanged = previous
    ? !sameIds(previous.roleIds, next.roleIds) || !sameIds(previous.groupIds, next.groupIds)
    : false;
  const requirePrincipal = (): AuthenticatedPrincipal => {
    if (!principal)
      throw new IamError('INVALID_INPUT', 'A principal is required to change a package rule');
    return principal;
  };
  const audit = async (change: string, metadata: Record<string, Json>) =>
    ctx.events.audit(
      tx,
      requirePrincipal(),
      'package:auto-rule',
      next.tenantId,
      next.id,
      'allow',
      false,
      { packageId: next.id, packageName: next.name, change, ...metadata },
    );
  const ruleMetadata = (rule: AutoAssignRule): Record<string, Json> => ({
    revision: rule.revision,
    ownerId: rule.ownerId,
    authorityId: rule.authorityId,
    include: rule.include as unknown as Json,
    ...(rule.exclude ? { exclude: rule.exclude as unknown as Json } : {}),
    ...(rule.graceMs !== undefined ? { graceMs: rule.graceMs } : {}),
    ...(rule.maxGrants !== undefined ? { maxGrants: rule.maxGrants } : {}),
    ...(rule.maxRemovals !== undefined ? { maxRemovals: rule.maxRemovals } : {}),
  });
  if (input === null) {
    if (!old) {
      if (keep)
        throw new IamError('INVALID_INPUT', 'keepAutomaticAssignments needs a rule to clear');
    } else {
      const caller = requirePrincipal();
      await allow(
        ctx,
        tx,
        caller,
        next.tenantId,
        'iam:packages:assign',
        next.id,
        'stop assigning this package automatically',
      );
      delete next.autoAssign;
      let kept = 0;
      if (keep) {
        const automatic = (await packageAssignments(ctx, tx, next)).filter(
          (assignment) => assignment.ruleRevision !== undefined,
        );
        if (automatic.length > 5000)
          throw new IamError(
            'INVALID_INPUT',
            'More than 5000 automatic holders; clear the rule without keepAutomaticAssignments',
          );
        for (const assignment of automatic) {
          const { ruleRevision: _revision, ...rest } = assignment;
          await tx.put<PackageAssignment>('packageAssignments', rest);
          kept++;
        }
      }
      for (const issue of await tx.find<PackageRuleIssue>('packageRuleIssues', {
        tenantId: next.tenantId,
        packageId: next.id,
      }))
        await tx.delete('packageRuleIssues', issue.id);
      await audit('clear', {
        revision: old.revision,
        ownerId: old.ownerId,
        ...(keep ? { kept } : {}),
      });
    }
  } else if (keep)
    throw new IamError(
      'INVALID_INPUT',
      'keepAutomaticAssignments applies only with autoAssign: null',
    );
  else if (input !== undefined) {
    const parsed = parseAutoAssign(input, await ruleEnvironment(ctx, tx, next));
    const author = await authorRule(ctx, tx, requirePrincipal(), next, old);
    const moved =
      old !== undefined &&
      (author.ownerId !== old.ownerId || author.authorityId !== old.authorityId);
    const rule: AutoAssignRule = {
      ...parsed,
      ...author,
      revision: old ? old.revision + (moved || contentsChanged ? 1 : 0) : 1,
      updatedAt: ctx.now(),
    };
    next.autoAssign = rule;
    await audit(!old ? 'set' : moved ? 'owner' : 'change', {
      ...ruleMetadata(rule),
      ...(moved ? { previousOwnerId: old!.ownerId } : {}),
    });
  } else if (old && contentsChanged) {
    const problem = ruleProblem(old, await ruleEnvironment(ctx, tx, next));
    if (problem)
      throw new IamError(
        'INVALID_INPUT',
        `The package rule no longer fits the new contents: ${problem}`,
      );
    const author = await authorRule(ctx, tx, requirePrincipal(), next, old);
    const rule: AutoAssignRule = {
      ...ruleInput(old),
      ...author,
      revision: old.revision + 1,
      updatedAt: ctx.now(),
    };
    next.autoAssign = rule;
    await audit('contents', {
      ...ruleMetadata(rule),
      ...(author.ownerId !== old.ownerId ? { previousOwnerId: old.ownerId } : {}),
    });
  }
  if (next.autoAssign && next.maxDurationMs !== undefined)
    throw new IamError(
      'INVALID_INPUT',
      'A package with an automatic-assignment rule cannot have a maximum duration; use graceMs for a delayed end',
    );
}

/** Creates a package; shared by `packages.create` and configuration sync. */
export async function createPackage(
  ctx: ServerContext,
  tx: IamStore,
  input: PackageInput,
  principal?: AuthenticatedPrincipal,
): Promise<AccessPackage> {
  const name = text(input.name, 'name', 128);
  if (await packageByName(tx, input.tenantId, name))
    throw new IamError('CONFLICT', 'A package with this name exists', 409);
  const roleIds = unique(input.roleIds === undefined ? [] : strings(input.roleIds, 'roleIds'));
  const groupIds = unique(input.groupIds === undefined ? [] : strings(input.groupIds, 'groupIds'));
  await contents(ctx, tx, input.tenantId, roleIds, groupIds);
  const now = ctx.now();
  const record: AccessPackage = {
    id: id(),
    tenantId: input.tenantId,
    uniqueKey: nameKey(name),
    name,
    roleIds,
    groupIds,
    createdAt: now,
    updatedAt: now,
  };
  if (input.description !== undefined)
    record.description = text(input.description, 'description', 512);
  if (input.maxDurationMs !== undefined)
    record.maxDurationMs = integer(input.maxDurationMs, 'maxDurationMs', 60_000, tenYears);
  if (
    input.requireJustification !== undefined &&
    boolean(input.requireJustification, 'requireJustification')
  )
    record.requireJustification = true;
  if (input.requestable !== undefined && boolean(input.requestable, 'requestable'))
    record.requestable = true;
  if (input.approverGroupId !== undefined && input.approverGroupId !== null) {
    await ctx.scoped<Group>(tx, 'groups', input.approverGroupId, input.tenantId);
    record.approverGroupId = input.approverGroupId;
  }
  if (input.managerApproval !== undefined && boolean(input.managerApproval, 'managerApproval'))
    record.managerApproval = true;
  if (input.autoAssign !== undefined)
    await applyRuleChange(ctx, tx, principal, undefined, record, input.autoAssign);
  return tx.insert<AccessPackage>('accessPackages', record);
}

/**
 * Changes a package's contents and rules; existing manual assignments keep what they were given. Changing the
 * contents of a package without a rule needs no rights over what is added or removed because it grants nothing:
 * extending an assignment lengthens only what the package still bundles (and the extender is authorized for), and
 * handing a shared membership over never lengthens it.
 */
export async function updatePackage(
  ctx: ServerContext,
  tx: IamStore,
  existing: AccessPackage,
  input: PackageUpdate,
  principal?: AuthenticatedPrincipal,
): Promise<AccessPackage> {
  const updated: AccessPackage = { ...existing, updatedAt: ctx.now() };
  if (input.name !== undefined) {
    const name = text(input.name, 'name', 128);
    const other = await packageByName(tx, existing.tenantId, name);
    if (other && other.id !== existing.id)
      throw new IamError('CONFLICT', 'A package with this name exists', 409);
    updated.name = name;
    updated.uniqueKey = nameKey(name);
  }
  if (input.description === null) delete updated.description;
  else if (input.description !== undefined)
    updated.description = text(input.description, 'description', 512);
  if (input.roleIds !== undefined) updated.roleIds = unique(strings(input.roleIds, 'roleIds'));
  if (input.groupIds !== undefined) updated.groupIds = unique(strings(input.groupIds, 'groupIds'));
  if (input.roleIds !== undefined || input.groupIds !== undefined)
    await contents(ctx, tx, existing.tenantId, updated.roleIds, updated.groupIds);
  if (input.maxDurationMs === null) delete updated.maxDurationMs;
  else if (input.maxDurationMs !== undefined)
    updated.maxDurationMs = integer(input.maxDurationMs, 'maxDurationMs', 60_000, tenYears);
  if (input.requireJustification !== undefined) {
    if (boolean(input.requireJustification, 'requireJustification'))
      updated.requireJustification = true;
    else delete updated.requireJustification;
  }
  if (input.requestable !== undefined) {
    if (boolean(input.requestable, 'requestable')) updated.requestable = true;
    else delete updated.requestable;
  }
  if (input.approverGroupId === null) delete updated.approverGroupId;
  else if (input.approverGroupId !== undefined) {
    await ctx.scoped<Group>(tx, 'groups', input.approverGroupId, existing.tenantId);
    updated.approverGroupId = input.approverGroupId;
  }
  if (input.managerApproval !== undefined) {
    if (boolean(input.managerApproval, 'managerApproval')) updated.managerApproval = true;
    else delete updated.managerApproval;
  }
  if (input.keepAutomaticAssignments !== undefined)
    boolean(input.keepAutomaticAssignments, 'keepAutomaticAssignments');
  await applyRuleChange(
    ctx,
    tx,
    principal,
    existing,
    updated,
    input.autoAssign,
    input.keepAutomaticAssignments === true,
  );
  // Pending requests the tightened rules no longer allow could never be approved; they are cancelled with the reason.
  const now = ctx.now();
  for (const request of await tx.find<PackageRequest>('packageRequests', {
    tenantId: existing.tenantId,
    packageId: existing.id,
    status: 'pending',
  })) {
    // A request that already lapsed keeps its history; the purge worker marks it expired.
    if (!pendingRequest(request, now)) continue;
    const reason = !updated.requestable
      ? 'The package can no longer be requested'
      : updated.requireJustification && request.justification === undefined
        ? 'The package now requires a justification'
        : updated.maxDurationMs !== undefined &&
            (request.desiredExpiresAt === undefined ||
              request.desiredExpiresAt > now + updated.maxDurationMs)
          ? 'The requested end no longer fits the package'
          : undefined;
    if (reason)
      await tx.put<PackageRequest>('packageRequests', {
        ...request,
        status: 'cancelled',
        decidedAt: now,
        note: reason,
      });
  }
  return tx.put<AccessPackage>('accessPackages', updated);
}

/** The assignments of a package, live ones only unless `includeExpired`. */
export async function packageAssignments(
  ctx: ServerContext,
  tx: IamStore,
  pkg: AccessPackage,
  includeExpired = false,
): Promise<PackageAssignment[]> {
  return (
    await tx.find<PackageAssignment>('packageAssignments', {
      tenantId: pkg.tenantId,
      packageId: pkg.id,
    })
  ).filter((assignment) => includeExpired || liveAssignment(ctx, assignment));
}

/** Deletes a package nobody holds, with its request history; shared by `packages.delete` and configuration sync. */
export async function deletePackage(
  ctx: ServerContext,
  tx: IamStore,
  pkg: AccessPackage,
): Promise<void> {
  const held = (await packageAssignments(ctx, tx, pkg)).length;
  if (held)
    throw new IamError(
      'RESOURCE_IN_USE',
      pkg.autoAssign
        ? `Still assigned to ${held} identit${held === 1 ? 'y' : 'ies'}; set autoAssign to null so reconciliation removes the automatic assignments, and revoke the manual ones`
        : `Still assigned to ${held} identit${held === 1 ? 'y' : 'ies'}; revoke first`,
      409,
    );
  for (const ended of await packageAssignments(ctx, tx, pkg, true))
    await tx.delete('packageAssignments', ended.id);
  for (const request of await tx.find<PackageRequest>('packageRequests', {
    tenantId: pkg.tenantId,
    packageId: pkg.id,
  }))
    await tx.delete('packageRequests', request.id);
  for (const issue of await tx.find<PackageRuleIssue>('packageRuleIssues', {
    tenantId: pkg.tenantId,
    packageId: pkg.id,
  }))
    await tx.delete('packageRuleIssues', issue.id);
  await tx.delete('accessPackages', pkg.id);
}

/** The end an assignment or request asks for, validated against the package's cap. */
function assignmentEnd(ctx: ServerContext, pkg: AccessPackage, value: unknown): number | undefined {
  const expiresAt = value !== undefined ? ctx.bindingExpiry(value) : undefined;
  if (pkg.maxDurationMs !== undefined) {
    if (expiresAt === undefined)
      throw new IamError('INVALID_INPUT', 'This package requires an end date (expiresAt)');
    if (expiresAt > ctx.now() + pkg.maxDurationMs)
      throw new IamError('INVALID_INPUT', 'expiresAt exceeds the maximum duration of this package');
  }
  return expiresAt;
}
function justificationFor(pkg: AccessPackage, value: unknown): string | undefined {
  const justification = value !== undefined ? text(value, 'justification', 2048) : undefined;
  if (pkg.requireJustification && justification === undefined)
    throw new IamError('INVALID_INPUT', 'This package requires a justification');
  return justification;
}

/**
 * An assignment whose bindings no longer grant (the issuing authority was revoked, for example when the assigner
 * was offboarded, or a binding was removed or taken over by hand) is broken: it may be replaced by a new one.
 */
export async function assignmentBroken(
  ctx: ServerContext,
  tx: IamStore,
  assignment: PackageAssignment,
): Promise<boolean> {
  for (const bindingId of assignment.bindingIds) {
    const binding = await tx.get<Binding>('bindings', bindingId);
    if (!binding || binding.packageAssignmentId !== assignment.id) return true;
    if (!(await ctx.authorityChain(tx, binding.authorityId))) return true;
  }
  return false;
}

/** The longest-lived other live assignment of the identity whose package includes the group. */
async function nextOwner(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  identityId: string,
  groupId: string,
  excludeId: string,
): Promise<PackageAssignment | undefined> {
  let best: PackageAssignment | undefined;
  for (const other of await tx.find<PackageAssignment>('packageAssignments', {
    tenantId,
    identityId,
  })) {
    if (other.id === excludeId || !liveAssignment(ctx, other)) continue;
    const pkg = await tx.get<AccessPackage>('accessPackages', other.packageId);
    if (!pkg?.groupIds.includes(groupId)) continue;
    if (!best || endOf(other.expiresAt) > endOf(best.expiresAt)) best = other;
  }
  return best;
}

/**
 * A group has one membership record per person, so packages that share a group share it: the record belongs to
 * the assignment that needs it longest. Handing it over moves its tag and end to the new owner, but never lengthens
 * it: the new owner's package may have gained the group after that assignment was made (packages.update grants
 * nothing), so the owner's end was never authorized for this group. Every assignment that did receive the group
 * already ends no later than the record (materialize and retimeAssignment keep the longest end on it).
 */
async function handOver(tx: IamStore, member: GroupMember, ownerId: string): Promise<void> {
  const owner = await tx.get<PackageAssignment>('packageAssignments', ownerId);
  if (!owner) return;
  const { expiresAt: _end, ...rest } = member;
  const end = Math.min(endOf(member.expiresAt), endOf(owner.expiresAt));
  await tx.put<GroupMember>('groupMembers', {
    ...rest,
    ...(end !== Number.POSITIVE_INFINITY ? { expiresAt: end } : {}),
    packageAssignmentId: owner.id,
  });
  if (!owner.membershipIds.includes(member.id))
    await tx.put<PackageAssignment>('packageAssignments', {
      ...owner,
      membershipIds: [...owner.membershipIds, member.id],
    });
}

/**
 * Creates what an assignment is missing: a binding of its own for each role (under `authority`, never depending on
 * or replacing a binding granted another way) and a membership for each group. A membership the person already
 * holds for at least as long is left alone and reported in the returned `skipped`; a shorter one is extended and
 * becomes the assignment's. Idempotent: what the assignment already holds is kept.
 */
async function materialize(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  pkg: AccessPackage,
  identityId: string,
  assignment: PackageAssignment,
  authority: GrantAuthority | undefined,
  expiresAt: number | undefined,
): Promise<string[]> {
  const { tenantId } = pkg;
  const skipped: string[] = [];
  const window = expiresAt !== undefined ? { expiresAt } : {};
  if (pkg.roleIds.length) {
    const own = (
      await tx.find<Binding>('bindings', {
        tenantId,
        subjectType: 'identity',
        subjectId: identityId,
      })
    ).filter((binding) => binding.packageAssignmentId === assignment.id);
    for (const roleId of pkg.roleIds) {
      const held = own.filter(
        (binding) => binding.roleId === roleId && binding.authorityId === authority!.id,
      );
      if (held.some((binding) => !ctx.expiredBinding(binding))) {
        for (const binding of held)
          if (!assignment.bindingIds.includes(binding.id)) assignment.bindingIds.push(binding.id);
        continue;
      }
      // A dead binding of the same key (the assignment's own, expired) is replaced.
      for (const binding of held) await removeTaggedBinding(tx, binding);
      const binding = await createBinding(
        ctx,
        tx,
        principal,
        {
          tenantId,
          roleId,
          subjectType: 'identity',
          subjectId: identityId,
          authorityId: authority!.id,
          ...window,
        },
        { packageAssignmentId: assignment.id },
      );
      assignment.bindingIds = [
        ...assignment.bindingIds.filter((existing) => !held.some((dead) => dead.id === existing)),
        binding.id,
      ];
    }
  }
  for (const groupId of pkg.groupIds) {
    const existing = (
      await tx.find<GroupMember>('groupMembers', {
        tenantId,
        uniqueKey: `${groupId}:${identityId}`,
      })
    )[0];
    let member: GroupMember;
    if (existing && ctx.liveMembership(existing)) {
      if (existing.packageAssignmentId === assignment.id) {
        if (!assignment.membershipIds.includes(existing.id))
          assignment.membershipIds.push(existing.id);
        continue;
      }
      if (endOf(existing.expiresAt) >= endOf(expiresAt)) {
        const label = (await tx.get<Group>('groups', groupId))?.name ?? groupId;
        const owner = existing.packageAssignmentId
          ? await tx.get<PackageAssignment>('packageAssignments', existing.packageAssignmentId)
          : undefined;
        const through = owner
          ? (await tx.get<AccessPackage>('accessPackages', owner.packageId))?.name
          : undefined;
        skipped.push(
          `already a member of group ${label}${through ? ` (through package ${through})` : ''}`,
        );
        continue;
      }
      // A shorter membership is extended to the assignment's end and becomes the assignment's.
      member = await updateGroupMember(ctx, tx, principal, {
        tenantId,
        groupId,
        identityId,
        expiresAt: expiresAt ?? null,
      });
    } else
      member = await addGroupMember(ctx, tx, principal, {
        tenantId,
        groupId,
        identityId,
        ...window,
      });
    await tx.put<GroupMember>('groupMembers', { ...member, packageAssignmentId: assignment.id });
    if (!assignment.membershipIds.includes(member.id)) assignment.membershipIds.push(member.id);
  }
  return skipped;
}

/**
 * Grants a package to an identity: every role becomes an identity binding of the assignment's own and every group a
 * membership, all ending at `expiresAt`, created under the caller's grant authority and tagged with the assignment
 * (see materialize). A live automatic assignment is taken over (revoked and replaced by this manual one); a broken
 * one is replaced. The identity's pending request for the package is marked approved (cancelled, for an automatic
 * assignment). With `automatic`, the rule engine assigns under the rule owner's authority.
 */
export async function assignPackage(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  pkg: AccessPackage,
  input: { identityId: string; expiresAt?: number; justification?: string },
  automatic?: { authority: GrantAuthority; ruleRevision: number },
): Promise<{ assignment: PackageAssignment; skipped: string[]; replacedAutomatic: boolean }> {
  const { tenantId } = pkg;
  const identity = await ctx.activeIdentity(tx, input.identityId, tenantId);
  const now = ctx.now();
  let replacedAutomatic = false;
  const previous = (
    await tx.find<PackageAssignment>('packageAssignments', {
      tenantId,
      uniqueKey: `${pkg.id}:${identity.id}`,
    })
  )[0];
  if (previous) {
    if (liveAssignment(ctx, previous)) {
      if (previous.ruleRevision !== undefined && !automatic) {
        // An administrator takes an automatic assignment over; it becomes manual under their authority.
        await revokeAssignment(ctx, tx, previous);
        replacedAutomatic = true;
      } else if (!(await assignmentBroken(ctx, tx, previous)))
        throw new IamError('CONFLICT', 'This package is already assigned to the identity', 409);
      // A broken assignment grants nothing any more: clear what is left of it and start over.
      else await revokeAssignment(ctx, tx, previous);
    } else await tx.delete('packageAssignments', previous.id);
  }
  const expiresAt = automatic ? undefined : assignmentEnd(ctx, pkg, input.expiresAt);
  const justification = justificationFor(
    pkg,
    automatic ? automaticJustification : input.justification,
  );
  const authority = automatic
    ? automatic.authority
    : await authorizePackage(ctx, tx, principal, pkg);
  const assignment: PackageAssignment = {
    id: id(),
    tenantId,
    uniqueKey: `${pkg.id}:${identity.id}`,
    packageId: pkg.id,
    identityId: identity.id,
    assignedBy: principal.identity.id,
    assignedAt: now,
    ...(expiresAt !== undefined ? { expiresAt } : {}),
    ...(justification !== undefined ? { justification } : {}),
    ...(automatic ? { ruleRevision: automatic.ruleRevision } : {}),
    bindingIds: [],
    membershipIds: [],
  };
  const skipped = await materialize(
    ctx,
    tx,
    principal,
    pkg,
    identity.id,
    assignment,
    authority,
    expiresAt,
  );
  const inserted = await tx.insert<PackageAssignment>('packageAssignments', assignment);
  // A request for the same package is fulfilled by the assignment.
  for (const request of await tx.find<PackageRequest>('packageRequests', {
    tenantId,
    packageId: pkg.id,
    identityId: identity.id,
    status: 'pending',
  }))
    await tx.put<PackageRequest>(
      'packageRequests',
      automatic
        ? {
            ...request,
            status: 'cancelled',
            decidedAt: now,
            note: 'Assigned automatically by the package rule',
          }
        : {
            ...request,
            status: 'approved',
            decidedBy: principal.identity.id,
            decidedAt: now,
            assignmentId: inserted.id,
          },
    );
  return { assignment: inserted, skipped, replacedAutomatic };
}

/** Removes one of an assignment's bindings with its activations. */
async function removeTaggedBinding(tx: IamStore, binding: Binding): Promise<void> {
  for (const activation of await tx.find<BindingActivation>('bindingActivations', {
    tenantId: binding.tenantId,
    bindingId: binding.id,
  }))
    await tx.delete('bindingActivations', activation.id);
  await tx.delete('bindings', binding.id);
}

/**
 * Removes one of an assignment's memberships, unless another live package of the person includes the group: then
 * that assignment takes it over. Removing ends the person's activations of the group's eligible bindings, as
 * groups.removeMember does. Returns whether the membership was removed.
 */
async function removeTaggedMembership(
  ctx: ServerContext,
  tx: IamStore,
  member: GroupMember,
  assignmentId: string,
): Promise<boolean> {
  const owner = await nextOwner(
    ctx,
    tx,
    member.tenantId,
    member.identityId,
    member.groupId,
    assignmentId,
  );
  if (owner) {
    await handOver(tx, member, owner.id);
    return false;
  }
  for (const groupBinding of await tx.find<Binding>('bindings', {
    tenantId: member.tenantId,
    subjectType: 'group',
    subjectId: member.groupId,
  }))
    for (const activation of await tx.find<BindingActivation>('bindingActivations', {
      tenantId: member.tenantId,
      bindingId: groupBinding.id,
      identityId: member.identityId,
    }))
      await tx.delete('bindingActivations', activation.id);
  await tx.delete('groupMembers', member.id);
  return true;
}

/**
 * Removes exactly the bindings and memberships an assignment created, then the assignment. The assignment owns
 * those records whichever authority issued them, so revoking needs only the right to manage the package.
 */
export async function revokeAssignment(
  ctx: ServerContext,
  tx: IamStore,
  assignment: PackageAssignment,
): Promise<{ bindings: number; memberships: number }> {
  const counts = { bindings: 0, memberships: 0 };
  for (const bindingId of assignment.bindingIds) {
    const binding = await tx.get<Binding>('bindings', bindingId);
    if (!binding || binding.packageAssignmentId !== assignment.id) continue;
    await removeTaggedBinding(tx, binding);
    counts.bindings++;
  }
  const groups = new Set<string>();
  for (const membershipId of assignment.membershipIds) {
    const member = await tx.get<GroupMember>('groupMembers', membershipId);
    if (!member || member.packageAssignmentId !== assignment.id) continue;
    groups.add(member.groupId);
    if (await removeTaggedMembership(ctx, tx, member, assignment.id)) counts.memberships++;
  }
  await tx.delete('packageAssignments', assignment.id);
  // Teams that sync their members from these groups follow (teams.ts).
  for (const groupId of groups)
    await syncTeamsFromGroups(ctx, tx, assignment.tenantId, { groupId, actorId: 'access-package' });
  return counts;
}

/**
 * Moves the end of an assignment and of exactly its records (undefined: no end). Shortening a shared membership
 * hands it to the package that still needs it longer; lengthening extends a shorter membership of the package's
 * groups (held by hand or through another package) and makes it the assignment's. Authorization is the caller's,
 * for the package's current contents: lengthening therefore reaches only records of roles and groups the package
 * still bundles, and those it no longer bundles (removed by packages.update since) keep their end.
 */
export async function retimeAssignment(
  ctx: ServerContext,
  tx: IamStore,
  pkg: AccessPackage,
  assignment: PackageAssignment,
  expiresAt: number | undefined,
): Promise<PackageAssignment> {
  const { tenantId } = assignment;
  const retime = <T extends { expiresAt?: number }>(record: T): T => {
    const { expiresAt: _previous, ...rest } = record;
    return (expiresAt === undefined ? rest : { ...rest, expiresAt }) as T;
  };
  const lengthening = endOf(expiresAt) > endOf(assignment.expiresAt);
  for (const bindingId of assignment.bindingIds) {
    const binding = await tx.get<Binding>('bindings', bindingId);
    if (binding?.packageAssignmentId !== assignment.id) continue;
    if (lengthening && !pkg.roleIds.includes(binding.roleId)) continue;
    await tx.put<Binding>('bindings', retime(binding));
  }
  let current = assignment;
  // The memberships the assignment holds, plus the person's memberships of the package's current groups.
  const members = new Map<string, GroupMember>();
  for (const membershipId of assignment.membershipIds) {
    const member = await tx.get<GroupMember>('groupMembers', membershipId);
    if (member?.packageAssignmentId === assignment.id) members.set(member.id, member);
  }
  for (const groupId of pkg.groupIds) {
    const member = (
      await tx.find<GroupMember>('groupMembers', {
        tenantId,
        uniqueKey: `${groupId}:${assignment.identityId}`,
      })
    )[0];
    if (member) members.set(member.id, member);
  }
  for (const member of members.values()) {
    if (!ctx.liveMembership(member)) continue;
    if (member.packageAssignmentId === assignment.id) {
      if (lengthening) {
        if (!pkg.groupIds.includes(member.groupId)) continue;
      } else {
        const owner = await nextOwner(
          ctx,
          tx,
          tenantId,
          assignment.identityId,
          member.groupId,
          assignment.id,
        );
        if (owner && endOf(owner.expiresAt) > endOf(expiresAt)) {
          await handOver(tx, member, owner.id);
          continue;
        }
      }
      await tx.put<GroupMember>('groupMembers', retime(member));
    } else if (
      lengthening &&
      pkg.groupIds.includes(member.groupId) &&
      endOf(member.expiresAt) < endOf(expiresAt)
    ) {
      const { packageAssignmentId: _owner, ...rest } = member;
      await tx.put<GroupMember>('groupMembers', {
        ...retime(rest as GroupMember),
        packageAssignmentId: assignment.id,
      });
      if (!current.membershipIds.includes(member.id))
        current = { ...current, membershipIds: [...current.membershipIds, member.id] };
    }
  }
  // Synced team memberships follow the new end of their source memberships (teams.ts).
  for (const groupId of new Set([...members.values()].map((member) => member.groupId)))
    await syncTeamsFromGroups(ctx, tx, tenantId, { groupId, actorId: 'access-package' });
  return tx.put<PackageAssignment>('packageAssignments', retime(current));
}

/**
 * Brings an automatic assignment up to its package and rule: bindings of roles no longer packaged, or issued under
 * another authority than the rule's, are removed; memberships of groups no longer packaged are removed (or handed
 * over); what is missing is materialized. Memberships that stay are untouched, so live activations survive.
 */
export async function refreshAssignment(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  pkg: AccessPackage,
  assignment: PackageAssignment,
  authority: GrantAuthority,
): Promise<{
  assignment: PackageAssignment;
  bindings: number;
  memberships: number;
  removedBindings: number;
  removedMemberships: number;
  skipped: string[];
}> {
  const keptBindings: string[] = [];
  const keptMemberships: string[] = [];
  let removedBindings = 0;
  let removedMemberships = 0;
  for (const bindingId of assignment.bindingIds) {
    const binding = await tx.get<Binding>('bindings', bindingId);
    if (!binding || binding.packageAssignmentId !== assignment.id) continue;
    if (!pkg.roleIds.includes(binding.roleId) || binding.authorityId !== authority.id) {
      await removeTaggedBinding(tx, binding);
      removedBindings++;
    } else keptBindings.push(binding.id);
  }
  for (const membershipId of assignment.membershipIds) {
    const member = await tx.get<GroupMember>('groupMembers', membershipId);
    if (!member || member.packageAssignmentId !== assignment.id) continue;
    if (!pkg.groupIds.includes(member.groupId)) {
      if (await removeTaggedMembership(ctx, tx, member, assignment.id)) removedMemberships++;
    } else keptMemberships.push(member.id);
  }
  const working: PackageAssignment = {
    ...assignment,
    bindingIds: keptBindings,
    membershipIds: keptMemberships,
  };
  const skipped = await materialize(
    ctx,
    tx,
    principal,
    pkg,
    working.identityId,
    working,
    authority,
    working.expiresAt,
  );
  working.ruleRevision = pkg.autoAssign!.revision;
  const saved = await tx.put<PackageAssignment>('packageAssignments', working);
  return {
    assignment: saved,
    bindings: saved.bindingIds.filter((bindingId) => !keptBindings.includes(bindingId)).length,
    memberships: saved.membershipIds.filter((memberId) => !keptMemberships.includes(memberId))
      .length,
    removedBindings,
    removedMemberships,
    skipped,
  };
}

async function summarize(
  ctx: ServerContext,
  tx: IamStore,
  assignments: PackageAssignment[],
): Promise<PackageAssignmentSummary[]> {
  const packages = new Map<string, AccessPackage | undefined>();
  const identities = new Map<string, Identity | undefined>();
  const summaries: PackageAssignmentSummary[] = [];
  for (const assignment of assignments) {
    if (!packages.has(assignment.packageId))
      packages.set(
        assignment.packageId,
        await tx.get<AccessPackage>('accessPackages', assignment.packageId),
      );
    if (!identities.has(assignment.identityId))
      identities.set(
        assignment.identityId,
        await tx.get<Identity>('identities', assignment.identityId),
      );
    const identity = identities.get(assignment.identityId);
    const { uniqueKey: _key, ruleRevision, ...rest } = assignment;
    const expired = !liveAssignment(ctx, assignment);
    summaries.push({
      ...rest,
      packageName: packages.get(assignment.packageId)?.name ?? assignment.packageId,
      identityName: identity?.name ?? assignment.identityId,
      ...(identity?.email ? { identityEmail: identity.email } : {}),
      expired,
      broken: !expired && (await assignmentBroken(ctx, tx, assignment)),
      automatic: ruleRevision !== undefined,
    });
  }
  return summaries.sort((a, b) => b.assignedAt - a.assignedAt);
}

/** A pending request past its lapse time is reported as expired even before the purge worker marks it. */
async function summarizeRequests(
  tx: IamStore,
  requests: PackageRequest[],
  now: number,
): Promise<PackageRequestSummary[]> {
  const packages = new Map<string, AccessPackage | undefined>();
  const identities = new Map<string, Identity | undefined>();
  const summaries: PackageRequestSummary[] = [];
  for (const request of requests) {
    if (!packages.has(request.packageId))
      packages.set(
        request.packageId,
        await tx.get<AccessPackage>('accessPackages', request.packageId),
      );
    if (!identities.has(request.identityId))
      identities.set(request.identityId, await tx.get<Identity>('identities', request.identityId));
    const identity = identities.get(request.identityId);
    const { uniqueKey: _key, ...rest } = request;
    summaries.push({
      ...rest,
      status: request.status === 'pending' && request.expiresAt <= now ? 'expired' : request.status,
      packageName: packages.get(request.packageId)?.name ?? request.packageId,
      identityName: identity?.name ?? request.identityId,
      ...(identity?.email ? { identityEmail: identity.email } : {}),
    });
  }
  return summaries.sort((a, b) => b.requestedAt - a.requestedAt);
}

/**
 * Whether the caller may decide on a request for this package: anyone holding the permission when the package
 * names no approvers; otherwise root, the requester's manager (`managerApproval`), or a member of the approver group.
 */
async function mayApprove(
  ctx: ServerContext,
  tx: IamStore,
  pkg: AccessPackage,
  principal: AuthenticatedPrincipal,
  requesterId: string,
): Promise<boolean> {
  if (!pkg.approverGroupId && !pkg.managerApproval) return true;
  if (await ctx.rootPrincipal(tx, principal)) return true;
  if (pkg.managerApproval) {
    const requester = await tx.get<Identity>('identities', requesterId);
    if (requester?.managerId === principal.identity.id) return true;
  }
  if (!pkg.approverGroupId) return false;
  return (
    await tx.find<GroupMember>('groupMembers', {
      tenantId: pkg.tenantId,
      groupId: pkg.approverGroupId,
      identityId: principal.identity.id,
    })
  ).some((member) => ctx.liveMembership(member));
}

/** Who is emailed a request: live approver-group members and, with `managerApproval`, the requester's manager. */
async function approverIds(
  ctx: ServerContext,
  tx: IamStore,
  pkg: AccessPackage,
  requesterId: string,
): Promise<Set<string>> {
  const recipients = new Set<string>();
  if (pkg.approverGroupId)
    for (const member of await tx.find<GroupMember>('groupMembers', {
      tenantId: pkg.tenantId,
      groupId: pkg.approverGroupId,
    }))
      if (ctx.liveMembership(member)) recipients.add(member.identityId);
  if (pkg.managerApproval) {
    const requester = await tx.get<Identity>('identities', requesterId);
    if (requester?.managerId) recipients.add(requester.managerId);
  }
  recipients.delete(requesterId);
  return recipients;
}

/** Queues an email through the host outbox when the deployment delivers email at all. */
async function notify(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  to: string | undefined,
  template: string,
  payload: Record<string, string>,
): Promise<void> {
  if (!to || !ctx.options.authentication?.sendEmail) return;
  await ctx.auth.enqueueDelivery(tx, { tenantId, kind: 'email', to, template, payload });
}

/** A package as the API returns it: holder counts and, for a rule package, the rule's view. */
export async function publicView(
  ctx: ServerContext,
  reader: IamStore,
  pkg: AccessPackage,
  env?: RuleEnvironment,
): Promise<PublicPackage> {
  const { uniqueKey: _key, autoAssign, ...rest } = pkg;
  const live = await packageAssignments(ctx, reader, pkg);
  return {
    ...rest,
    assignments: live.length,
    automaticAssignments: live.filter((assignment) => assignment.ruleRevision !== undefined).length,
    ...(autoAssign
      ? {
          autoAssign: await autoAssignView(
            ctx,
            reader,
            pkg,
            env ?? (await ruleEnvironment(ctx, reader, pkg)),
          ),
        }
      : {}),
  };
}

export function createPackagesApi(ctx: ServerContext) {
  const { store } = ctx;
  const { operation } = ctx.operations;
  /** Runs the post-commit reconcile of a rule change; a failure never fails the call (the scheduler catches up). */
  async function afterRuleChange(
    pkg: AccessPackage,
    requestedBy: string,
  ): Promise<{ view: PublicPackage; reconcile?: PackageReconcileResult }> {
    let reconcile: PackageReconcileResult | undefined;
    try {
      reconcile = await reconcilePackageRules(ctx, {
        tenantId: pkg.tenantId,
        packageId: pkg.id,
        limit: 200,
        trigger: 'rule-change',
        requestedBy,
      });
    } catch {
      reconcile = undefined;
    }
    const fresh = (await store.get<AccessPackage>('accessPackages', pkg.id)) ?? pkg;
    return { view: await publicView(ctx, store, fresh), ...(reconcile ? { reconcile } : {}) };
  }
  async function decideRequest(
    credential: CredentialInput,
    input: { tenantId: string; requestId: string; expiresAt?: number; note?: string },
    decision: 'approved' | 'denied',
  ) {
    const existing = await ctx.scoped<PackageRequest>(
      store,
      'packageRequests',
      input.requestId,
      text(input.tenantId, 'tenantId'),
    );
    return operation(
      credential,
      input.tenantId,
      'iam:packages:approve',
      existing.packageId,
      async ({ tx, principal }) => {
        const request = await ctx.scoped<PackageRequest>(
          tx,
          'packageRequests',
          input.requestId,
          input.tenantId,
        );
        const now = ctx.now();
        if (!pendingRequest(request, now))
          throw new IamError('INVALID_TRANSITION', 'This request is not awaiting a decision', 409);
        if (request.identityId === principal.identity.id)
          throw new IamError('INVALID_INPUT', 'You cannot decide on your own request');
        // Two-person control: an administrator viewing as an approver must not decide in their name.
        if (principal.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'Requests cannot be decided while impersonating',
            403,
          );
        const pkg = await tx.get<AccessPackage>('accessPackages', request.packageId);
        if (!pkg) throw new IamError('INVALID_TRANSITION', 'The package no longer exists', 409);
        if (decision === 'approved' && !pkg.requestable)
          throw new IamError('INVALID_TRANSITION', 'The package is no longer requestable', 409);
        if (!(await mayApprove(ctx, tx, pkg, principal, request.identityId)))
          throw new IamError('ACCESS_DENIED', 'Only the designated approvers may decide', 403);
        const note = input.note !== undefined ? text(input.note, 'note', 2048) : undefined;
        const decided: PackageRequest = {
          ...request,
          status: decision,
          decidedBy: principal.identity.id,
          decidedAt: now,
          ...(note !== undefined ? { note } : {}),
        };
        const metadata: Record<string, Json> = {
          requestId: request.id,
          packageId: pkg.id,
          packageName: pkg.name,
          identityId: request.identityId,
          ...(note !== undefined ? { note } : {}),
        };
        if (decision === 'approved') {
          const { assignment, skipped, replacedAutomatic } = await assignPackage(
            ctx,
            tx,
            principal,
            pkg,
            {
              identityId: request.identityId,
              expiresAt: input.expiresAt ?? request.desiredExpiresAt,
              justification: request.justification,
            },
          );
          decided.assignmentId = assignment.id;
          Object.assign(metadata, {
            assignmentId: assignment.id,
            bindings: assignment.bindingIds.length,
            memberships: assignment.membershipIds.length,
            skipped,
            ...(replacedAutomatic ? { replacedAutomatic } : {}),
            ...(assignment.expiresAt !== undefined ? { expiresAt: assignment.expiresAt } : {}),
          });
        }
        await tx.put('packageRequests', decided);
        await ctx.events.audit(
          tx,
          principal,
          `package:request-${decision}`,
          input.tenantId,
          pkg.id,
          'allow',
          false,
          metadata,
        );
        const requester = await tx.get<Identity>('identities', request.identityId);
        await notify(ctx, tx, input.tenantId, requester?.email, 'package-decided', {
          requestId: request.id,
          packageId: pkg.id,
          packageName: pkg.name,
          decision,
          deciderName: principal.identity.name,
          ...(note !== undefined ? { note } : {}),
          ...(typeof metadata.expiresAt === 'number'
            ? { expiresAt: String(metadata.expiresAt) }
            : {}),
        });
        return (await summarizeRequests(tx, [decided], now))[0]!;
      },
    );
  }
  return {
    /**
     * Defines a bundle of roles and groups granted together by `assign`. Names are unique per tenant; protected
     * roles cannot be packaged. `maxDurationMs` forces assignments to state an end within it,
     * `requireJustification` makes the justification mandatory, `requestable` lets members ask for it, and
     * `approverGroupId` / `managerApproval` name who decides. `autoAssign` makes it a birthright package: every
     * active identity matching the rule receives it automatically, under the caller's grant authority (the caller
     * then needs iam:packages:assign on the package and the rights to grant each part by hand); the response carries
     * the first `reconcile`. Requires iam:packages:create. Audited as `package:auto-rule` for a rule.
     */
    create: async (credential: CredentialInput, input: PackageInput) => {
      let ruled: { pkg: AccessPackage; requestedBy: string } | undefined;
      const view = await operation(
        credential,
        input.tenantId,
        'iam:packages:create',
        input.tenantId,
        async ({ tx, principal }) => {
          let pkg = await createPackage(ctx, tx, input, principal);
          if (pkg.autoAssign) {
            pkg = (await approveRule(ctx, tx, pkg)).pkg;
            ruled = { pkg, requestedBy: principal.identity.id };
          }
          return publicView(ctx, tx, pkg);
        },
      );
      if (!ruled) return view as PublicPackage & { reconcile?: PackageReconcileResult };
      const { view: fresh, reconcile } = await afterRuleChange(ruled.pkg, ruled.requestedBy);
      return { ...fresh, ...(reconcile ? { reconcile } : {}) };
    },
    /**
     * Changes name, description, contents, or rules; existing manual assignments keep what they were given, automatic
     * ones follow the package. `autoAssign` sets, changes, or takes over the rule (the caller becomes its owner, with
     * the checks of `create`); null clears it (automatic holders lose the package at the next reconcile, or keep it
     * as manual assignments with `keepAutomaticAssignments`). Changing a rule package's roles or groups makes the
     * caller its owner. Requires iam:packages:update. Audited as `package:auto-rule` when the rule changes.
     */
    update: async (
      credential: CredentialInput,
      input: { tenantId: string; packageId: string } & PackageUpdate,
    ) => {
      let ruled: { pkg: AccessPackage; requestedBy: string } | undefined;
      const view = await operation(
        credential,
        input.tenantId,
        'iam:packages:update',
        input.packageId,
        async ({ tx, principal }) => {
          const before = await ctx.scoped<AccessPackage>(
            tx,
            'accessPackages',
            input.packageId,
            input.tenantId,
          );
          let pkg = await updatePackage(ctx, tx, before, input, principal);
          const touched =
            before.autoAssign?.updatedAt !== pkg.autoAssign?.updatedAt ||
            !!before.autoAssign !== !!pkg.autoAssign;
          if (touched) {
            if (pkg.autoAssign) pkg = (await approveRule(ctx, tx, pkg)).pkg;
            ruled = { pkg, requestedBy: principal.identity.id };
          }
          return publicView(ctx, tx, pkg);
        },
      );
      if (!ruled) return view as PublicPackage & { reconcile?: PackageReconcileResult };
      const { view: fresh, reconcile } = await afterRuleChange(ruled.pkg, ruled.requestedBy);
      return { ...fresh, ...(reconcile ? { reconcile } : {}) };
    },
    /** Deletes a package nobody holds (RESOURCE_IN_USE otherwise) together with its request history. Requires iam:packages:delete. */
    delete: (credential: CredentialInput, input: { tenantId: string; packageId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:delete',
        input.packageId,
        async ({ tx }) => {
          await deletePackage(
            ctx,
            tx,
            await ctx.scoped<AccessPackage>(tx, 'accessPackages', input.packageId, input.tenantId),
          );
          return { deleted: true as const };
        },
      ),
    /** A package with its live holder counts and, for a rule package, the rule's status. Requires iam:packages:read. */
    get: (credential: CredentialInput, input: { tenantId: string; packageId: string }) =>
      operation(credential, input.tenantId, 'iam:packages:read', input.packageId, async ({ tx }) =>
        publicView(
          ctx,
          tx,
          await ctx.scoped<AccessPackage>(tx, 'accessPackages', input.packageId, input.tenantId),
        ),
      ),
    /** The tenant's packages by name, each with its live holder counts. Requires iam:packages:read. */
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:packages:read', input.tenantId, async ({ tx }) => {
        const packages = (
          await tx.find<AccessPackage>('accessPackages', { tenantId: input.tenantId })
        ).sort(byName);
        const listed: PublicPackage[] = [];
        let env: RuleEnvironment | undefined;
        for (const pkg of packages) {
          if (pkg.autoAssign && !env) env = await ruleEnvironment(ctx, tx, pkg);
          listed.push(
            await publicView(
              ctx,
              tx,
              pkg,
              pkg.autoAssign ? { ...env!, packagedGroups: new Set(pkg.groupIds) } : undefined,
            ),
          );
        }
        return listed;
      }),
    /**
     * Grants a package: every role becomes an identity binding of the assignment's own and every group a membership,
     * all ending at `expiresAt`, in one transaction under the caller's grant authority. Besides iam:packages:assign
     * on the package the caller needs iam:bindings:create on each role and iam:groups:update on each group, exactly
     * as for the direct calls. A membership the identity already holds for as long is left alone and listed in
     * `skipped`. An automatic assignment is taken over (`replacedAutomatic`). Audited as `package:assign`.
     */
    assign: (credential: CredentialInput, input: AssignmentInput) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:assign',
        input.packageId,
        async ({ tx, principal }) => {
          const pkg = await ctx.scoped<AccessPackage>(
            tx,
            'accessPackages',
            input.packageId,
            input.tenantId,
          );
          const { assignment, skipped, replacedAutomatic } = await assignPackage(
            ctx,
            tx,
            principal,
            pkg,
            input,
          );
          const created = {
            bindings: assignment.bindingIds.length,
            memberships: assignment.membershipIds.length,
          };
          await ctx.events.audit(
            tx,
            principal,
            'package:assign',
            input.tenantId,
            pkg.id,
            'allow',
            false,
            {
              packageId: pkg.id,
              packageName: pkg.name,
              identityId: assignment.identityId,
              ...created,
              skipped,
              ...(replacedAutomatic ? { replacedAutomatic } : {}),
              ...(assignment.expiresAt !== undefined ? { expiresAt: assignment.expiresAt } : {}),
              ...(assignment.justification !== undefined
                ? { justification: assignment.justification }
                : {}),
            },
          );
          return {
            ...(await summarize(ctx, tx, [assignment]))[0]!,
            created,
            skipped,
            replacedAutomatic,
          };
        },
      ),
    /**
     * Removes exactly what the assignment added and the assignment itself. The assignment owns its records
     * whichever authority issued them, so iam:packages:assign on the package is all it takes. An automatic assignment
     * of a package that still has its rule cannot be revoked (INVALID_TRANSITION): exclude the person in the rule.
     * Audited as `package:revoke`.
     */
    revoke: (
      credential: CredentialInput,
      input: { tenantId: string; packageId: string; identityId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:assign',
        input.packageId,
        async ({ tx, principal }) => {
          const pkg = await ctx.scoped<AccessPackage>(
            tx,
            'accessPackages',
            input.packageId,
            input.tenantId,
          );
          const assignment = (
            await tx.find<PackageAssignment>('packageAssignments', {
              tenantId: input.tenantId,
              uniqueKey: `${pkg.id}:${text(input.identityId, 'identityId')}`,
            })
          )[0];
          if (!assignment)
            throw new IamError('NOT_FOUND', 'The package is not assigned to this identity', 404);
          if (
            assignment.ruleRevision !== undefined &&
            pkg.autoAssign &&
            liveAssignment(ctx, assignment)
          )
            throw new IamError(
              'INVALID_TRANSITION',
              `Assigned by the package rule: exclude the person in the rule (exclude: [{ StringEquals: { "principal.id": "${assignment.identityId}" } }]), change their attributes, or assign the package manually to take it over`,
              409,
            );
          const counts = await revokeAssignment(ctx, tx, assignment);
          await ctx.events.audit(
            tx,
            principal,
            'package:revoke',
            input.tenantId,
            pkg.id,
            'allow',
            false,
            {
              packageId: pkg.id,
              packageName: pkg.name,
              identityId: assignment.identityId,
              ...counts,
            },
          );
          return { revoked: true as const, ...counts };
        },
      ),
    /**
     * Holders of a package, or the packages of an identity, newest first; ended assignments only with
     * `includeExpired`; `source` keeps only automatic or manual ones. Requires iam:packages:read.
     */
    listAssignments: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        packageId?: string;
        identityId?: string;
        includeExpired?: boolean;
        source?: 'automatic' | 'manual';
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:read',
        input.packageId ?? input.tenantId,
        async ({ tx }) => {
          if (
            input.source !== undefined &&
            input.source !== 'automatic' &&
            input.source !== 'manual'
          )
            throw new IamError('INVALID_INPUT', 'source must be automatic or manual');
          const filter: Record<string, string> = { tenantId: input.tenantId };
          if (input.packageId !== undefined) {
            await ctx.scoped<AccessPackage>(tx, 'accessPackages', input.packageId, input.tenantId);
            filter.packageId = input.packageId;
          }
          if (input.identityId !== undefined)
            filter.identityId = text(input.identityId, 'identityId');
          const assignments = (
            await tx.find<PackageAssignment>('packageAssignments', filter)
          ).filter(
            (assignment) =>
              (input.includeExpired === true || liveAssignment(ctx, assignment)) &&
              (input.source === undefined ||
                (input.source === 'automatic') === (assignment.ruleRevision !== undefined)),
          );
          return summarize(ctx, tx, assignments);
        },
      ),
    /**
     * Moves the end of an assignment: the assignment and every binding and membership it created get the new end
     * together (null makes them permanent, unless the package caps durations). Shortening requires
     * iam:packages:assign on the package; lengthening (or null) is granting, so it also needs the rights `assign`
     * needs and a grant authority, and the package's bindings move to the extender's authority. Lengthening reaches
     * only the roles and groups the package bundles now: records of ones taken out of the package since the
     * assignment keep their end. Automatic assignments cannot be extended (INVALID_TRANSITION). Audited as
     * `package:extend`.
     */
    extend: (
      credential: CredentialInput,
      input: { tenantId: string; packageId: string; identityId: string; expiresAt: number | null },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:assign',
        input.packageId,
        async ({ tx, principal }) => {
          const pkg = await ctx.scoped<AccessPackage>(
            tx,
            'accessPackages',
            input.packageId,
            input.tenantId,
          );
          const assignment = (
            await tx.find<PackageAssignment>('packageAssignments', {
              tenantId: input.tenantId,
              uniqueKey: `${pkg.id}:${text(input.identityId, 'identityId')}`,
            })
          )[0];
          if (!assignment || !liveAssignment(ctx, assignment))
            throw new IamError('NOT_FOUND', 'The package is not assigned to this identity', 404);
          if (assignment.ruleRevision !== undefined)
            throw new IamError(
              'INVALID_TRANSITION',
              'Automatic assignments end when the person stops matching the rule; assign the package manually to set an end',
              409,
            );
          if (input.expiresAt === undefined)
            throw new IamError('INVALID_INPUT', 'expiresAt is required (null for no end)');
          const expiresAt = assignmentEnd(
            ctx,
            pkg,
            input.expiresAt === null ? undefined : input.expiresAt,
          );
          const { tenantId } = input;
          // Lengthening is granting: it needs the rights `assign` needs, and the bindings move to the extender's
          // authority so the longer grant is bounded by what the extender may give. Those rights are checked for
          // the package's current contents, so only records of those roles and groups are lengthened (and moved);
          // the rest keep their end and authority (retimeAssignment). Shortening needs no more than
          // iam:packages:assign, like revoking.
          if (endOf(expiresAt) > endOf(assignment.expiresAt)) {
            const authority = await authorizePackage(ctx, tx, principal, pkg, {
              groupAuthorities: true,
            });
            if (authority)
              for (const bindingId of assignment.bindingIds) {
                const binding = await tx.get<Binding>('bindings', bindingId);
                if (
                  binding?.packageAssignmentId !== assignment.id ||
                  binding.authorityId === authority.id ||
                  !pkg.roleIds.includes(binding.roleId)
                )
                  continue;
                await tx.put<Binding>('bindings', {
                  ...binding,
                  authorityId: authority.id,
                  uniqueKey: `${binding.subjectType}:${binding.subjectId}:${binding.roleId}:${authority.id}:package:${assignment.id}`,
                });
              }
          }
          const updated = await retimeAssignment(ctx, tx, pkg, assignment, expiresAt);
          await ctx.events.audit(
            tx,
            principal,
            'package:extend',
            tenantId,
            pkg.id,
            'allow',
            false,
            {
              packageId: pkg.id,
              packageName: pkg.name,
              identityId: assignment.identityId,
              ...(assignment.expiresAt !== undefined
                ? { previousExpiresAt: assignment.expiresAt }
                : {}),
              ...(expiresAt !== undefined ? { expiresAt } : {}),
            },
          );
          return (await summarize(ctx, tx, [updated]))[0]!;
        },
      ),
    /**
     * What a rule matches: the stored rule of `packageId`, a candidate `autoAssign`, or neither (the valid keys
     * only). With `packageId` it also shows what a run would change and whether the brakes would hold it back.
     * Writes nothing. Requires iam:packages:read, and iam:identities:read to evaluate a rule.
     */
    previewAutoAssign: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        packageId?: string;
        autoAssign?: AutoAssignInput;
        sample?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:read',
        input.packageId ?? input.tenantId,
        async ({ tx, principal }) => previewRule(ctx, tx, principal, input),
      ),
    /**
     * Runs the rule reconciler now for the tenant or one package (at most `limit` changes). Unusually large changes
     * are held back unless `confirm` (with `packageId`), which approves the planned counts for a day and needs the
     * rights to assign the package by hand. Requires iam:packages:assign. Audited per change as `package:auto-*`.
     */
    reconcile: async (
      credential: CredentialInput,
      input: { tenantId: string; packageId?: string; confirm?: boolean; limit?: number },
    ) => {
      const prepared = await operation(
        credential,
        input.tenantId,
        'iam:packages:assign',
        input.packageId ?? input.tenantId,
        async ({ tx, principal }) => {
          if (input.packageId !== undefined)
            await ctx.scoped<AccessPackage>(tx, 'accessPackages', input.packageId, input.tenantId);
          const limit = integer(input.limit ?? 1000, 'limit', 1, 10000);
          if (input.confirm !== undefined) boolean(input.confirm, 'confirm');
          if (input.confirm) {
            if (input.packageId === undefined)
              throw new IamError('INVALID_INPUT', 'confirm needs packageId');
            const pkg = (await tx.get<AccessPackage>('accessPackages', input.packageId))!;
            if (!pkg.autoAssign)
              throw new IamError('INVALID_TRANSITION', 'This package has no rule', 409);
            // A confirmer must be able to grant the package by hand.
            await authorizePackage(ctx, tx, principal, pkg, { groupAuthorities: true });
          }
          return { limit, principal };
        },
      );
      return reconcilePackageRules(ctx, {
        tenantId: input.tenantId,
        ...(input.packageId !== undefined ? { packageId: input.packageId } : {}),
        limit: prepared.limit,
        trigger: 'manual',
        requestedBy: prepared.principal.identity.id,
        ...(input.confirm ? { confirmedBy: prepared.principal } : {}),
      });
    },
    /**
     * Self-service: asks for a requestable package for oneself, with the end and justification the package
     * requires, from an ordinary session of the tenant. The request waits for the tenant's `approvalLifetimeMs`
     * (one day by default) but never beyond the end it asks for; the designated approvers are emailed
     * (`package-request`), and a request no approver could act on is refused. Requires iam:packages:request on the
     * package. Audited as `package:request`.
     */
    request: (
      credential: CredentialInput,
      input: { tenantId: string; packageId: string; expiresAt?: number; justification?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:request',
        input.packageId,
        async ({ tx, principal, tenant }) => {
          const pkg = await ctx.scoped<AccessPackage>(
            tx,
            'accessPackages',
            input.packageId,
            input.tenantId,
          );
          if (!pkg.requestable)
            throw new IamError('INVALID_TRANSITION', 'This package cannot be requested', 409);
          if (!actsInOwnRight(principal.session) || principal.session.tenantId !== input.tenantId)
            throw new IamError(
              'INVALID_INPUT',
              'Requests are made from an ordinary session of the target tenant',
            );
          if (principal.session.impersonatorId)
            throw new IamError(
              'IMPERSONATION_RESTRICTED',
              'Packages cannot be requested while impersonating',
              403,
            );
          const identityId = principal.identity.id;
          const now = ctx.now();
          const held = (
            await tx.find<PackageAssignment>('packageAssignments', {
              tenantId: input.tenantId,
              uniqueKey: `${pkg.id}:${identityId}`,
            })
          )[0];
          if (held && liveAssignment(ctx, held) && !(await assignmentBroken(ctx, tx, held)))
            throw new IamError('CONFLICT', 'You already hold this package', 409);
          const open = (
            await tx.find<PackageRequest>('packageRequests', {
              tenantId: input.tenantId,
              packageId: pkg.id,
              identityId,
              status: 'pending',
            })
          ).some((request) => pendingRequest(request, now));
          if (open)
            throw new IamError('CONFLICT', 'Your request is still awaiting a decision', 409);
          const desiredExpiresAt = assignmentEnd(ctx, pkg, input.expiresAt);
          const justification = justificationFor(pkg, input.justification);
          // A request that names its approvers must reach at least one who can act on it.
          const approvers: Identity[] = [];
          for (const approverId of await approverIds(ctx, tx, pkg, identityId)) {
            const approver = await tx.get<Identity>('identities', approverId);
            if (approver?.status === 'active') approvers.push(approver);
          }
          if ((pkg.approverGroupId || pkg.managerApproval) && !approvers.length)
            throw new IamError(
              'INVALID_TRANSITION',
              'Nobody can approve this request: the approver group is empty and you have no active manager',
              409,
            );
          const request: PackageRequest = {
            id: id(),
            tenantId: input.tenantId,
            packageId: pkg.id,
            identityId,
            status: 'pending',
            requestedAt: now,
            // A request cannot outlive the access it asks for.
            expiresAt: Math.min(
              now + (tenant.accessPolicy?.approvalLifetimeMs ?? defaultApprovalLifetimeMs),
              desiredExpiresAt ?? Number.POSITIVE_INFINITY,
            ),
            ...(desiredExpiresAt !== undefined ? { desiredExpiresAt } : {}),
            ...(justification !== undefined ? { justification } : {}),
          };
          await tx.insert('packageRequests', request);
          await ctx.events.audit(
            tx,
            principal,
            'package:request',
            input.tenantId,
            pkg.id,
            'allow',
            false,
            {
              requestId: request.id,
              packageId: pkg.id,
              packageName: pkg.name,
              lapsesAt: request.expiresAt,
              ...(desiredExpiresAt !== undefined ? { desiredExpiresAt } : {}),
              ...(justification !== undefined ? { justification } : {}),
            },
          );
          for (const approver of approvers)
            await notify(ctx, tx, input.tenantId, approver.email, 'package-request', {
              requestId: request.id,
              packageId: pkg.id,
              packageName: pkg.name,
              requesterName: principal.identity.name,
              ...(principal.identity.email ? { requesterEmail: principal.identity.email } : {}),
              lapsesAt: String(request.expiresAt),
              ...(desiredExpiresAt !== undefined ? { expiresAt: String(desiredExpiresAt) } : {}),
              ...(justification !== undefined ? { justification } : {}),
            });
          return (await summarizeRequests(tx, [request], now))[0]!;
        },
      ),
    /**
     * Grants a pending request: the package is assigned to the requester under the approver's authority (so the
     * approver needs the same rights as `assign`), ending at `expiresAt` or the end the requester asked for.
     * Requires iam:packages:approve on the package and, when the package names approvers, membership of the approver
     * group or being the requester's manager (or root); nobody decides on their own request, and never while
     * impersonating. The requester is emailed (`package-decided`). Audited as `package:request-approved`.
     */
    approveRequest: (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; expiresAt?: number; note?: string },
    ) => decideRequest(credential, input, 'approved'),
    /** Refuses a pending request with an optional note; same rights as `approveRequest`. Audited as `package:request-denied`. */
    denyRequest: (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; note?: string },
    ) => decideRequest(credential, { ...input, expiresAt: undefined }, 'denied'),
    /**
     * Withdraws one's own pending request, from an ordinary session or API key of the tenant (never a role session or
     * session token). Audited as `package:request-cancelled`.
     */
    cancelRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string },
    ) => {
      const existing = await ctx.scoped<PackageRequest>(
        store,
        'packageRequests',
        input.requestId,
        text(input.tenantId, 'tenantId'),
      );
      return operation(
        credential,
        input.tenantId,
        'iam:packages:request',
        existing.packageId,
        async ({ tx, principal }) => {
          const request = await ctx.scoped<PackageRequest>(
            tx,
            'packageRequests',
            input.requestId,
            input.tenantId,
          );
          // Withdrawing acts in the requester's own right, like making the request: never through a role session
          // or session token.
          if (!actsInOwnRight(principal.session) || principal.session.tenantId !== input.tenantId)
            throw new IamError(
              'INVALID_INPUT',
              'Requests are made from an ordinary session of the target tenant',
            );
          if (request.identityId !== principal.identity.id)
            throw new IamError('ACCESS_DENIED', 'Only the requester may cancel a request', 403);
          const now = ctx.now();
          if (!pendingRequest(request, now))
            throw new IamError(
              'INVALID_TRANSITION',
              'This request is not awaiting a decision',
              409,
            );
          const cancelled: PackageRequest = { ...request, status: 'cancelled', decidedAt: now };
          await tx.put('packageRequests', cancelled);
          await ctx.events.audit(
            tx,
            principal,
            'package:request-cancelled',
            input.tenantId,
            request.packageId,
            'allow',
            false,
            { requestId: request.id, packageId: request.packageId },
          );
          return (await summarizeRequests(tx, [cancelled], now))[0]!;
        },
      );
    },
    /** Requests of a package or an identity, newest first, optionally by `status`. Requires iam:packages:read. */
    listRequests: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        packageId?: string;
        identityId?: string;
        status?: PackageRequestStatus;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:read',
        input.packageId ?? input.tenantId,
        async ({ tx }) => {
          const filter: Record<string, string> = { tenantId: input.tenantId };
          if (input.packageId !== undefined) {
            await ctx.scoped<AccessPackage>(tx, 'accessPackages', input.packageId, input.tenantId);
            filter.packageId = input.packageId;
          }
          if (input.identityId !== undefined)
            filter.identityId = text(input.identityId, 'identityId');
          if (input.status !== undefined && !requestStatuses.has(input.status))
            throw new IamError('INVALID_INPUT', 'Invalid status');
          // Filtered on the reported status, so a lapsed request counts as expired before the worker marks it.
          return (
            await summarizeRequests(
              tx,
              await tx.find<PackageRequest>('packageRequests', filter),
              ctx.now(),
            )
          ).filter((request) => input.status === undefined || request.status === input.status);
        },
      ),
    /**
     * The pending requests the caller may decide on: iam:packages:approve on each package, the package's approver
     * rules, never their own. Requires iam:packages:approve on the tenant.
     */
    listApprovals: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:approve',
        input.tenantId,
        async ({ tx, principal }) => {
          const now = ctx.now();
          const packages = new Map<string, AccessPackage | undefined>();
          const pending: PackageRequest[] = [];
          for (const request of await tx.find<PackageRequest>('packageRequests', {
            tenantId: input.tenantId,
            status: 'pending',
          })) {
            if (!pendingRequest(request, now) || request.identityId === principal.identity.id)
              continue;
            if (!packages.has(request.packageId)) {
              const pkg = await tx.get<AccessPackage>('accessPackages', request.packageId);
              const decidable =
                pkg?.requestable &&
                (
                  await ctx.decisions.decide(
                    tx,
                    principal,
                    {
                      tenantId: input.tenantId,
                      action: 'iam:packages:approve',
                      resource: { type: 'iam', id: pkg.id },
                    },
                    true,
                  )
                ).allowed;
              packages.set(request.packageId, decidable ? pkg : undefined);
            }
            const pkg = packages.get(request.packageId);
            if (pkg && (await mayApprove(ctx, tx, pkg, principal, request.identityId)))
              pending.push(request);
          }
          return summarizeRequests(tx, pending, now);
        },
      ),
    /**
     * Self-service view: the requestable packages (with their contents named, and the caller's live assignment
     * or pending request on each), the caller's live assignments, and their recent requests. A package's rule is
     * never shown here. Requires iam:packages:request on the tenant.
     */
    listMine: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:packages:request',
        input.tenantId,
        async ({ tx, principal }) => {
          const { tenantId } = input;
          const identityId = principal.identity.id;
          const now = ctx.now();
          const roleNames = new Map(
            (await tx.find<Role>('roles', { tenantId })).map((role) => [role.id, role.name]),
          );
          const groupNames = new Map(
            (await tx.find<Group>('groups', { tenantId })).map((group) => [group.id, group.name]),
          );
          const assignments = await summarize(
            ctx,
            tx,
            (
              await tx.find<PackageAssignment>('packageAssignments', { tenantId, identityId })
            ).filter((assignment) => liveAssignment(ctx, assignment)),
          );
          const requests = (
            await summarizeRequests(
              tx,
              await tx.find<PackageRequest>('packageRequests', { tenantId, identityId }),
              now,
            )
          ).slice(0, 50);
          const packages = (await tx.find<AccessPackage>('accessPackages', { tenantId }))
            .filter((pkg) => pkg.requestable)
            .sort(byName)
            .map((pkg) => {
              const { uniqueKey: _key, autoAssign: _rule, roleIds, groupIds, ...rest } = pkg;
              return {
                ...rest,
                roles: roleIds.map((roleId) => ({
                  id: roleId,
                  name: roleNames.get(roleId) ?? roleId,
                })),
                groups: groupIds.map((groupId) => ({
                  id: groupId,
                  name: groupNames.get(groupId) ?? groupId,
                })),
                ...(pkg.approverGroupId !== undefined
                  ? {
                      approverGroupName: groupNames.get(pkg.approverGroupId) ?? pkg.approverGroupId,
                    }
                  : {}),
                assignment: assignments.find((assignment) => assignment.packageId === pkg.id),
                pending: requests.find(
                  (request) => request.packageId === pkg.id && pendingRequest(request, now),
                ),
              };
            });
          return { packages, assignments, requests };
        },
      ),
  };
}
