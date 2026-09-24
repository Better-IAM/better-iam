/**
 * The reconciler of automatic (birthright) access packages: plans, per package, which identities should gain,
 * keep, or lose the package under its rule, and applies each change in its own transaction under the rule owner's
 * grant authority. Runs after identity changes and rule saves (post-commit), on demand, and as a scheduler job.
 *
 * Trust: a rule grants under its owner's authority to whoever matches, so whoever can change the facts it tests
 * chooses the recipients, with no grant rights of their own. Declared attributes and managerId are set with
 * iam:identities:update, and members of a group without role bindings with iam:groups:update alone; rules keyed on
 * them are only as safe as those permissions (ruleWarnings says so on every such clause). Facts access packages
 * create never count: package memberships, and team memberships synced from them (identityFacts, org-rules.ts), so
 * rules never chain onto another package or keep themselves alive.
 */
import {
  IamError,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type {
  AccessPackage,
  AutoAssignRule,
  Binding,
  GrantAuthority,
  Group,
  GroupMember,
  PackageAssignment,
  PackageRuleIssue,
} from '../models.js';
import {
  defaultMaxGrants,
  defaultMaxRemovals,
  parseAutoAssign,
  ruleContext,
  ruleDocument,
  ruleGroupIds,
  ruleKeys,
  ruleMatch,
  ruleProblem,
  ruleWarnings,
  type AutoAssignInput,
  type RuleEnvironment,
  type RuleMatch,
  type RuleOrgFacts,
} from '../package-rules.js';
import { invariantSnapshot, invariantVerify } from '../invariants.js';
import { loadOrgFacts, orgRuleEnvironment, type TenantOrgFacts } from '../org-rules.js';
import { sodVerify, sodViolations, type SodRule } from '../sod.js';
import { id } from '../utils.js';
import { integer, text } from '../validation.js';
import {
  allow,
  assignPackage,
  authorizePackage,
  endOf,
  liveAssignment,
  refreshAssignment,
  retimeAssignment,
  revokeAssignment,
  ruleEnvironment,
  type AutoAssignPreview,
  type PackageReconcileResult,
  type PublicAutoAssign,
  type ReconcileTrigger,
  type RuleChange,
  type RuleSuspension,
} from './packages.js';

export interface ReconcileOptions {
  tenantId?: string;
  packageId?: string;
  identityIds?: string[];
  /** Write attempts per tenant; unlimited for identity-change runs. */
  limit?: number;
  trigger: ReconcileTrigger;
  /** Approve the package's planned counts and exempt this run from brakes (needs packageId). */
  confirmedBy?: AuthenticatedPrincipal | 'deployment-operator';
  /** The person whose call triggered the run, for audit metadata. */
  requestedBy?: string;
}

interface IdentityFacts {
  identity: Identity;
  /**
   * Live memberships no access package owns, with team backing groups only through a team membership that counts:
   * what a rule sees as identity.groups.
   */
  directGroupIds: string[];
  /** What a rule sees as identity.teams and identity.departments (org-rules.ts). */
  org: RuleOrgFacts;
  memberships: GroupMember[];
  bindings: Binding[];
  assignment?: PackageAssignment;
}
interface TenantFacts {
  tenantId: string;
  identities: Identity[];
  memberships: Map<string, GroupMember[]>;
  bindings: Map<string, Binding[]>;
  assignments: Map<string, PackageAssignment>;
  groupIds: Set<string>;
  issues: Map<string, PackageRuleIssue>;
  org: TenantOrgFacts;
}
type Reason =
  | 'matches'
  | 'revision'
  | 'incomplete'
  | 'matches-again'
  | 'no-longer-matches'
  | 'rule-cleared';
interface PlannedStep {
  packageId: string;
  packageName: string;
  identityId: string;
  change: RuleChange;
  reason: Reason;
  ruleKey: string;
  matchedBy: string[];
  hasIssue: boolean;
}
type Bucket = 'manual' | 'frozen' | 'keep' | 'ending' | 'excluded' | 'none';
interface PackagePlan {
  steps: PlannedStep[];
  counts: Record<RuleChange, number> & {
    manual: number;
    frozen: number;
    keep: number;
    matching: number;
    excluded: number;
    revokeRuleCleared: number;
  };
}
type Health =
  | { ok: true; principal: AuthenticatedPrincipal; authority: GrantAuthority }
  | { ok: false; reason: RuleSuspension; detail: string };

const additive = new Set<RuleChange>(['assign', 'refresh', 'restore']);
const ruleKeyOf = (rule?: AutoAssignRule) => (rule ? `${rule.revision}:${rule.updatedAt}` : 'none');
const issueKey = {
  failed: (packageId: string, identityId: string) => `${packageId}:identity:${identityId}`,
  suspended: (packageId: string) => `${packageId}:suspended`,
  braked: (packageId: string, direction: 'grants' | 'removals') =>
    `${packageId}:braked:${direction}`,
};

/** Everything the planner needs about a tenant, read once per collection (the store loads every row anyway). */
async function loadFacts(
  ctx: ServerContext,
  reader: IamStore,
  tenantId: string,
  scope: { identityIds?: string[] },
): Promise<TenantFacts> {
  const wanted = scope.identityIds ? new Set(scope.identityIds) : undefined;
  const identities = (await reader.find<Identity>('identities', { tenantId }))
    .filter((identity) => identity.status !== 'deleted' && (!wanted || wanted.has(identity.id)))
    .sort((a, b) => (a.id < b.id ? -1 : 1));
  const memberships = new Map<string, GroupMember[]>();
  for (const member of await reader.find<GroupMember>('groupMembers', { tenantId }))
    memberships.set(member.identityId, [...(memberships.get(member.identityId) ?? []), member]);
  const bindings = new Map<string, Binding[]>();
  for (const binding of await reader.find<Binding>('bindings', {
    tenantId,
    subjectType: 'identity',
  }))
    bindings.set(binding.subjectId, [...(bindings.get(binding.subjectId) ?? []), binding]);
  const assignments = new Map(
    (await reader.find<PackageAssignment>('packageAssignments', { tenantId })).map((assignment) => [
      assignment.uniqueKey!,
      assignment,
    ]),
  );
  const groupIds = new Set(
    (await reader.find<Group>('groups', { tenantId })).map((group) => group.id),
  );
  const issues = new Map(
    (await reader.find<PackageRuleIssue>('packageRuleIssues', { tenantId })).map((issue) => [
      issue.uniqueKey!,
      issue,
    ]),
  );
  const org = await loadOrgFacts(reader, tenantId, ctx.now());
  return { tenantId, identities, memberships, bindings, assignments, groupIds, issues, org };
}

function identityFacts(
  ctx: ServerContext,
  facts: Pick<TenantFacts, 'memberships' | 'bindings' | 'assignments' | 'org'>,
  identity: Identity,
  packageId: string,
): IdentityFacts {
  const memberships = facts.memberships.get(identity.id) ?? [];
  const live = memberships.filter(
    (member) => member.packageAssignmentId === undefined && ctx.liveMembership(member),
  );
  const ordinary = live
    .filter((member) => member.teamId === undefined)
    .map((member) => member.groupId);
  const org = facts.org.of(identity.id, ordinary);
  // A team's backing group copies the team's members, and team sync copies package memberships of its source groups
  // into the team: the backing membership counts only while the team membership behind it does (org.teams holds the
  // counted teams and every team above them, exactly the teams whose backing groups that membership fills).
  const teams = new Set(org.teams);
  const directGroupIds = [
    ...ordinary,
    ...live
      .filter((member) => member.teamId !== undefined && teams.has(member.teamId))
      .map((member) => member.groupId),
  ];
  return {
    identity,
    memberships,
    directGroupIds,
    org,
    bindings: facts.bindings.get(identity.id) ?? [],
    assignment: facts.assignments.get(`${packageId}:${identity.id}`),
  };
}

/**
 * Whether an automatic assignment lacks something its package and rule call for (a role binding of its own under the
 * rule's authority, a membership lasting as long as it) or holds something they no longer call for. The same
 * predicate materialize satisfies, so a refresh converges in one pass.
 */
function incomplete(
  ctx: ServerContext,
  pkg: AccessPackage,
  rule: AutoAssignRule,
  f: IdentityFacts,
): boolean {
  const a = f.assignment!;
  const own = f.bindings.filter(
    (binding) => binding.packageAssignmentId === a.id && !ctx.expiredBinding(binding),
  );
  for (const roleId of pkg.roleIds)
    if (
      !own.some((binding) => binding.roleId === roleId && binding.authorityId === rule.authorityId)
    )
      return true;
  if (
    own.some(
      (binding) =>
        !pkg.roleIds.includes(binding.roleId) || binding.authorityId !== rule.authorityId,
    )
  )
    return true;
  for (const groupId of pkg.groupIds) {
    const member = f.memberships.find(
      (candidate) => candidate.groupId === groupId && ctx.liveMembership(candidate),
    );
    if (
      !member ||
      (member.packageAssignmentId !== a.id && endOf(member.expiresAt) < endOf(a.expiresAt))
    )
      return true;
  }
  return f.memberships.some(
    (member) =>
      member.packageAssignmentId === a.id &&
      ctx.liveMembership(member) &&
      !pkg.groupIds.includes(member.groupId),
  );
}

/** What a run should do for one identity and package, or which bucket it falls into when nothing. */
function decideChange(
  ctx: ServerContext,
  pkg: AccessPackage,
  doc: ReturnType<typeof ruleDocument> | undefined,
  f: IdentityFacts,
): { change?: RuleChange; reason?: Reason; bucket?: Bucket; match?: RuleMatch } {
  const a = f.assignment;
  const live = !!a && liveAssignment(ctx, a);
  const automatic = live && a!.ruleRevision !== undefined;
  const rule = pkg.autoAssign;
  if (live && !automatic) return { bucket: 'manual' };
  if (!rule || !doc)
    return automatic ? { change: 'revoke', reason: 'rule-cleared' } : { bucket: 'none' };
  // Disabled and expired identities are frozen: never assigned or removed by a rule (offboarding handles leavers).
  if (f.identity.status !== 'active' || ctx.identityExpired(f.identity))
    return { bucket: 'frozen' };
  const match = ruleMatch(doc, f.identity, ruleContext(f.identity, f.directGroupIds, f.org));
  if (!match.matched) {
    if (!automatic)
      return {
        bucket: match.matchedBy.length && match.excludedBy.length ? 'excluded' : 'none',
        match,
      };
    if (!rule.graceMs) return { change: 'revoke', reason: 'no-longer-matches', match };
    if (a!.expiresAt !== undefined) return { bucket: 'ending', match };
    return { change: 'ending', reason: 'no-longer-matches', match };
  }
  if (!live) return { change: 'assign', reason: 'matches', match };
  if (a!.expiresAt !== undefined) return { change: 'restore', reason: 'matches-again', match };
  if (a!.ruleRevision !== rule.revision) return { change: 'refresh', reason: 'revision', match };
  if (incomplete(ctx, pkg, rule, f)) return { change: 'refresh', reason: 'incomplete', match };
  return { bucket: 'keep', match };
}

function planPackage(ctx: ServerContext, facts: TenantFacts, pkg: AccessPackage): PackagePlan {
  const doc = pkg.autoAssign ? ruleDocument(pkg.autoAssign) : undefined;
  const counts: PackagePlan['counts'] = {
    assign: 0,
    refresh: 0,
    restore: 0,
    ending: 0,
    revoke: 0,
    manual: 0,
    frozen: 0,
    keep: 0,
    matching: 0,
    excluded: 0,
    revokeRuleCleared: 0,
  };
  const steps: PlannedStep[] = [];
  for (const identity of facts.identities) {
    const f = identityFacts(ctx, facts, identity, pkg.id);
    // Orphans of a cleared rule: only identities still holding an automatic assignment matter.
    if (!pkg.autoAssign && !(f.assignment && f.assignment.ruleRevision !== undefined)) continue;
    const decision = decideChange(ctx, pkg, doc, f);
    if (decision.match?.matched) counts.matching++;
    if (decision.bucket === 'excluded') counts.excluded++;
    if (decision.bucket && decision.bucket !== 'excluded' && decision.bucket !== 'none')
      counts[decision.bucket === 'ending' ? 'keep' : decision.bucket]++;
    if (!decision.change) continue;
    counts[decision.change]++;
    if (decision.change === 'revoke' && decision.reason === 'rule-cleared')
      counts.revokeRuleCleared++;
    steps.push({
      packageId: pkg.id,
      packageName: pkg.name,
      identityId: identity.id,
      change: decision.change,
      reason: decision.reason!,
      ruleKey: ruleKeyOf(pkg.autoAssign),
      matchedBy: decision.match?.matchedBy ?? [],
      hasIssue: facts.issues.has(issueKey.failed(pkg.id, identity.id)),
    });
  }
  return { steps, counts };
}

/**
 * Whether the rule may add anything right now: its owner is active, their grant authority is intact and theirs, and
 * (with `rights`) they still hold everything assigning the package by hand needs. Runs outside a transaction.
 */
async function ruleHealth(
  ctx: ServerContext,
  reader: IamStore,
  pkg: AccessPackage,
  rights: boolean,
): Promise<Health> {
  const rule = pkg.autoAssign!;
  const owner = await reader.get<Identity>('identities', rule.ownerId);
  if (!owner || owner.status !== 'active' || ctx.identityExpired(owner))
    return {
      ok: false,
      reason: 'owner-inactive',
      detail: `The rule owner ${owner?.name ?? rule.ownerId} is ${!owner || owner.status === 'deleted' ? 'deleted' : owner.status !== 'active' ? 'disabled' : 'expired'}`,
    };
  const principal = ctx.decisions.simulatedPrincipal(owner, true);
  let authority: GrantAuthority;
  try {
    authority = await ctx.grantingAuthority(reader, principal, pkg.tenantId, rule.authorityId);
  } catch {
    return {
      ok: false,
      reason: 'authority-revoked',
      detail: 'The rule owner’s grant authority is revoked or no longer theirs',
    };
  }
  if (rights)
    try {
      await allow(
        ctx,
        reader,
        principal,
        pkg.tenantId,
        'iam:packages:assign',
        pkg.id,
        'assign this package',
      );
      await authorizePackage(ctx, reader, principal, pkg, {
        groupAuthorities: true,
        authorityId: rule.authorityId,
      });
    } catch (error) {
      return {
        ok: false,
        reason: 'owner-lacks-rights',
        detail: error instanceof Error ? error.message : String(error),
      };
    }
  return { ok: true, principal, authority };
}

/**
 * Records a problem once per transition (new, or a new code or revision): written and audited only then, so a
 * persistent failure retried every run neither grows the audit log nor the table. Own transaction; never throws.
 */
async function recordIssue(
  ctx: ServerContext,
  tenantId: string,
  pkg: AccessPackage,
  issue: { kind: PackageRuleIssue['kind']; identityId?: string; code: string; message: string },
  action: string,
  metadata: Record<string, Json>,
): Promise<boolean> {
  const uniqueKey =
    issue.kind === 'failed'
      ? issueKey.failed(pkg.id, issue.identityId!)
      : issue.kind === 'suspended'
        ? issueKey.suspended(pkg.id)
        : issueKey.braked(pkg.id, issue.code as 'grants' | 'removals');
  const revision = pkg.autoAssign?.revision ?? 0;
  try {
    return await ctx.store.transaction(async (tx) => {
      const existing = (
        await tx.find<PackageRuleIssue>('packageRuleIssues', { tenantId, uniqueKey })
      )[0];
      if (existing && existing.code === issue.code && existing.revision === revision) return false;
      const record: PackageRuleIssue = {
        id: existing?.id ?? id(),
        tenantId,
        uniqueKey,
        packageId: pkg.id,
        kind: issue.kind,
        ...(issue.identityId ? { identityId: issue.identityId } : {}),
        code: issue.code,
        message: issue.message.slice(0, 1024),
        revision,
        since: ctx.now(),
      };
      if (existing) await tx.put('packageRuleIssues', record);
      else await tx.insert('packageRuleIssues', record);
      await ctx.events.recordAudit(tx, {
        id: id(),
        tenantId,
        actorId: 'deployment-operator',
        action,
        resourceId: pkg.id,
        timestamp: ctx.now(),
        outcome: 'deny',
        metadata,
      });
      return true;
    });
  } catch {
    return false;
  }
}

/** Deletes stored issues (own transaction; never throws). */
async function clearIssues(ctx: ServerContext, ids: string[]): Promise<void> {
  if (!ids.length) return;
  try {
    await ctx.store.transaction(async (tx) => {
      for (const issueId of ids)
        if (await tx.get('packageRuleIssues', issueId))
          await tx.delete('packageRuleIssues', issueId);
    });
  } catch {
    /* retried next run */
  }
}

/**
 * Applies one planned change in its own transaction, after re-deciding from fresh records: when the decision
 * changed since planning, nothing is written ('stale'). A separation-of-duties conflict, or a newly broken enforced
 * access invariant (INVARIANT_VIOLATION), that a grant would create rolls back only this change, which the caller
 * records as a failed issue.
 */
async function applyStep(
  ctx: ServerContext,
  tenantId: string,
  step: PlannedStep,
  state: { principal?: AuthenticatedPrincipal; authority?: GrantAuthority },
  base: Record<string, Json>,
): Promise<'applied' | 'stale'> {
  return ctx.store.transaction(async (tx) => {
    const pkg = await tx.get<AccessPackage>('accessPackages', step.packageId);
    if (!pkg || pkg.tenantId !== tenantId || ruleKeyOf(pkg.autoAssign) !== step.ruleKey)
      return 'stale';
    const identity = await tx.get<Identity>('identities', step.identityId);
    if (!identity || identity.tenantId !== tenantId || identity.status === 'deleted')
      return 'stale';
    const memberships = await tx.find<GroupMember>('groupMembers', {
      tenantId,
      identityId: identity.id,
    });
    const bindings = await tx.find<Binding>('bindings', {
      tenantId,
      subjectType: 'identity',
      subjectId: identity.id,
    });
    const assignment = (
      await tx.find<PackageAssignment>('packageAssignments', {
        tenantId,
        uniqueKey: `${pkg.id}:${identity.id}`,
      })
    )[0];
    const f = identityFacts(
      ctx,
      {
        memberships: new Map([[identity.id, memberships]]),
        bindings: new Map([[identity.id, bindings]]),
        assignments: assignment ? new Map([[assignment.uniqueKey!, assignment]]) : new Map(),
        org: await loadOrgFacts(tx, tenantId, ctx.now()),
      },
      identity,
      pkg.id,
    );
    const decision = decideChange(
      ctx,
      pkg,
      pkg.autoAssign ? ruleDocument(pkg.autoAssign) : undefined,
      f,
    );
    if (decision.change !== step.change) return 'stale';
    const rule = pkg.autoAssign;
    let snapshot: { rules: SodRule[]; existing: Set<string> } | undefined;
    if (additive.has(step.change)) {
      const rules = (await tx.find<SodRule>('sodRules', { tenantId })).filter(
        (candidate) => candidate.mode === 'prevent',
      );
      const closure = new Set(pkg.roleIds);
      for (const groupId of pkg.groupIds)
        for (const binding of await tx.find<Binding>('bindings', {
          tenantId,
          subjectType: 'group',
          subjectId: groupId,
        }))
          if (!ctx.expiredBinding(binding)) closure.add(binding.roleId);
      if (rules.some((candidate) => candidate.roleIds.some((roleId) => closure.has(roleId))))
        snapshot = {
          rules,
          existing: new Set(
            (await sodViolations(ctx, tx, tenantId, rules, [identity.id])).map(
              (violation) => `${violation.ruleId}:${violation.identityId}`,
            ),
          ),
        };
    }
    // Enforced access invariants bind automatic grants as they bind a manual assign (whose operation checks them):
    // this reconcile runs outside any operation, so it checks them itself.
    const guardrails = additive.has(step.change)
      ? await invariantSnapshot(ctx, tx, tenantId, 'iam:packages:assign')
      : undefined;
    const now = ctx.now();
    let action = '';
    let metadata: Record<string, Json> = {};
    switch (step.change) {
      case 'assign': {
        const { assignment: created, skipped } = await assignPackage(
          ctx,
          tx,
          state.principal!,
          pkg,
          { identityId: identity.id },
          { authority: state.authority!, ruleRevision: rule!.revision },
        );
        action = 'package:auto-assign';
        metadata = {
          mode: 'assign',
          reason: step.reason,
          bindings: created.bindingIds.length,
          memberships: created.membershipIds.length,
          skipped,
          matchedBy: step.matchedBy,
        };
        break;
      }
      case 'refresh':
      case 'restore': {
        let current = assignment!;
        if (step.change === 'restore')
          current = await retimeAssignment(ctx, tx, pkg, current, undefined);
        const refreshed = await refreshAssignment(
          ctx,
          tx,
          state.principal!,
          pkg,
          current,
          state.authority!,
        );
        action = 'package:auto-assign';
        metadata = {
          mode: step.change,
          reason: step.reason,
          bindings: refreshed.bindings,
          memberships: refreshed.memberships,
          removedBindings: refreshed.removedBindings,
          removedMemberships: refreshed.removedMemberships,
          skipped: refreshed.skipped,
          matchedBy: step.matchedBy,
        };
        break;
      }
      case 'ending': {
        const endsAt = now + rule!.graceMs!;
        await retimeAssignment(ctx, tx, pkg, assignment!, endsAt);
        action = 'package:auto-ending';
        metadata = { endsAt, graceMs: rule!.graceMs! };
        break;
      }
      case 'revoke': {
        const counts = await revokeAssignment(ctx, tx, assignment!);
        action = 'package:auto-revoke';
        metadata = { reason: step.reason, ...counts };
        break;
      }
    }
    await sodVerify(ctx, tx, tenantId, snapshot, [identity.id]);
    await invariantVerify(ctx, tx, tenantId, guardrails);
    const issue = (
      await tx.find<PackageRuleIssue>('packageRuleIssues', {
        tenantId,
        uniqueKey: issueKey.failed(pkg.id, identity.id),
      })
    )[0];
    if (issue) await tx.delete('packageRuleIssues', issue.id);
    await ctx.events.recordAudit(tx, {
      id: id(),
      tenantId,
      actorId: 'deployment-operator',
      action,
      resourceId: pkg.id,
      timestamp: now,
      outcome: 'allow',
      metadata: {
        ...base,
        packageId: pkg.id,
        packageName: pkg.name,
        revision: rule?.revision ?? 0,
        ...(rule ? { ownerId: rule.ownerId } : {}),
        identityId: identity.id,
        ...metadata,
      },
    });
    return 'applied';
  });
}

/**
 * Writes the rule's approval: the grants and removals a run would make now, which unattended runs may then apply
 * for the next day without tripping the brakes. Called when a person saves a rule or confirms held-back changes.
 */
export async function approveRule(
  ctx: ServerContext,
  tx: IamStore,
  pkg: AccessPackage,
): Promise<{ pkg: AccessPackage; grants: number; removals: number }> {
  const rule = pkg.autoAssign;
  if (!rule || ruleProblem(rule, await ruleEnvironment(ctx, tx, pkg)))
    return { pkg, grants: 0, removals: 0 };
  const plan = planPackage(ctx, await loadFacts(ctx, tx, pkg.tenantId, {}), pkg);
  const grants = plan.counts.assign + plan.counts.refresh;
  const removals = plan.counts.ending + plan.counts.revoke - plan.counts.revokeRuleCleared;
  const approved: AccessPackage = {
    ...pkg,
    autoAssign: { ...rule, approved: { grants, removals, until: ctx.now() + 86_400_000 } },
  };
  return { pkg: await tx.put<AccessPackage>('accessPackages', approved), grants, removals };
}

/**
 * The tenant's groups with role bindings, for ruleWarnings: adding members to them needs the bindings' authorities,
 * not iam:groups:update alone. Read only when the rule tests identity.groups.
 */
async function boundGroups(
  reader: IamStore,
  tenantId: string,
  rule: AutoAssignRule | AutoAssignInput,
): Promise<Set<string>> {
  if (!ruleGroupIds(rule).length) return new Set();
  return new Set(
    (await reader.find<Binding>('bindings', { tenantId, subjectType: 'group' })).map(
      (binding) => binding.subjectId,
    ),
  );
}

/** A rule as administrators see it: owner, whether it runs, warnings, and the latest problems. */
export async function autoAssignView(
  ctx: ServerContext,
  reader: IamStore,
  pkg: AccessPackage,
  env: RuleEnvironment,
): Promise<PublicAutoAssign> {
  const rule = pkg.autoAssign!;
  const owner = await reader.get<Identity>('identities', rule.ownerId);
  const issues = (
    await reader.find<PackageRuleIssue>('packageRuleIssues', {
      tenantId: pkg.tenantId,
      packageId: pkg.id,
    })
  ).sort((a, b) => b.since - a.since);
  let suspension: { reason: RuleSuspension; detail: string } | undefined;
  const problem = ruleProblem(rule, env);
  if (problem) suspension = { reason: 'invalid-rule', detail: problem };
  else if (!owner || owner.status !== 'active' || ctx.identityExpired(owner))
    suspension = {
      reason: 'owner-inactive',
      detail: `The rule owner ${owner?.name ?? rule.ownerId} is not active`,
    };
  else {
    const authority = await reader.get<GrantAuthority>('grantAuthorities', rule.authorityId);
    if (
      !authority ||
      authority.revoked ||
      (authority.identityId !== rule.ownerId && !authority.rootIssued) ||
      !(await ctx.authorityChain(reader, authority.id))
    )
      suspension = {
        reason: 'authority-revoked',
        detail: 'The rule owner’s grant authority is revoked or no longer theirs',
      };
    else {
      const stored = issues.find(
        (issue) => issue.kind === 'suspended' && issue.code === 'owner-lacks-rights',
      );
      if (stored) suspension = { reason: 'owner-lacks-rights', detail: stored.message };
    }
  }
  const names = new Map<string, string>();
  for (const issue of issues.slice(0, 20))
    if (issue.identityId && !names.has(issue.identityId))
      names.set(
        issue.identityId,
        (await reader.get<Identity>('identities', issue.identityId))?.name ?? issue.identityId,
      );
  return {
    ...rule,
    ownerName: owner?.name ?? rule.ownerId,
    status: suspension ? 'suspended' : 'active',
    ...(suspension
      ? { suspendedReason: suspension.reason, suspendedDetail: suspension.detail }
      : {}),
    warnings: ruleWarnings(rule, { boundGroups: await boundGroups(reader, pkg.tenantId, rule) }),
    issueCount: issues.length,
    issues: issues.slice(0, 20).map((issue) => ({
      kind: issue.kind,
      ...(issue.identityId
        ? { identityId: issue.identityId, identityName: names.get(issue.identityId)! }
        : {}),
      code: issue.code,
      message: issue.message,
      since: issue.since,
    })),
  };
}

const emptyResult = (trigger: ReconcileTrigger): PackageReconcileResult => ({
  trigger,
  assigned: 0,
  refreshed: 0,
  restored: 0,
  ending: 0,
  revoked: 0,
  stale: 0,
  failed: [],
  suspended: [],
  braked: [],
  skipped: { inactiveTenants: 0, failedTenants: [] },
  truncated: false,
});

/**
 * The reconciler. Plans from plain reads (no transaction), then applies each change in its own transaction under
 * the rule owner's authority, removals first. Never runs inside another transaction.
 */
export async function reconcilePackageRules(
  ctx: ServerContext,
  options: ReconcileOptions,
): Promise<PackageReconcileResult> {
  const result = emptyResult(options.trigger);
  const tenants = options.tenantId
    ? [await ctx.tenant(ctx.store, options.tenantId)]
    : (await ctx.store.find<Tenant>('tenants', { status: 'active' })).sort((a, b) =>
        a.id < b.id ? -1 : 1,
      );
  for (const tenant of tenants) {
    if (tenant.status !== 'active') {
      result.skipped.inactiveTenants++;
      continue;
    }
    try {
      await reconcileTenant(ctx, tenant.id, options, result);
    } catch (error) {
      result.skipped.failedTenants.push({
        tenantId: tenant.id,
        code: error instanceof IamError ? error.code : 'ERROR',
        message: error instanceof Error ? error.message : String(error),
      });
    }
  }
  return result;
}

async function reconcileTenant(
  ctx: ServerContext,
  tenantId: string,
  options: ReconcileOptions,
  result: PackageReconcileResult,
): Promise<void> {
  const reader = ctx.store;
  const now = ctx.now();
  const all = await reader.find<AccessPackage>('accessPackages', { tenantId });
  const scoped = options.packageId ? all.filter((pkg) => pkg.id === options.packageId) : all;
  const rulePackages = scoped.filter((pkg) => pkg.autoAssign);
  if (options.trigger === 'identity-change' && !rulePackages.length) return;
  const facts = await loadFacts(ctx, reader, tenantId, {
    ...(options.identityIds ? { identityIds: options.identityIds } : {}),
  });
  const orphanIds = new Set(
    [...facts.assignments.values()]
      .filter(
        (assignment) => assignment.ruleRevision !== undefined && liveAssignment(ctx, assignment),
      )
      .map((assignment) => assignment.packageId),
  );
  const packages = scoped
    .filter((pkg) => pkg.autoAssign || orphanIds.has(pkg.id))
    .sort((a, b) => a.name.localeCompare(b.name, 'en') || (a.id < b.id ? -1 : 1));
  const base: Record<string, Json> = {
    trigger: options.trigger,
    ...(options.requestedBy ? { requestedBy: options.requestedBy } : {}),
  };
  // A confirmation approves the package's planned counts and exempts this run from the brakes.
  let confirmed = false;
  if (options.confirmedBy && options.packageId) {
    const target = packages.find((pkg) => pkg.id === options.packageId);
    if (target?.autoAssign) {
      const confirmer = options.confirmedBy;
      await ctx.store.transaction(async (tx) => {
        const fresh = await tx.get<AccessPackage>('accessPackages', target.id);
        if (!fresh?.autoAssign) return;
        const approval = await approveRule(ctx, tx, fresh);
        const metadata = {
          packageId: fresh.id,
          packageName: fresh.name,
          grants: approval.grants,
          removals: approval.removals,
          until: approval.pkg.autoAssign!.approved!.until,
        };
        if (confirmer === 'deployment-operator')
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId,
            actorId: 'deployment-operator',
            action: 'package:auto-confirm',
            resourceId: fresh.id,
            timestamp: ctx.now(),
            outcome: 'allow',
            metadata,
          });
        else
          await ctx.events.audit(
            tx,
            confirmer,
            'package:auto-confirm',
            tenantId,
            fresh.id,
            'allow',
            false,
            metadata,
          );
        const index = packages.indexOf(target);
        packages[index] = approval.pkg;
      });
      confirmed = true;
    }
  }
  const braked = (options.trigger === 'schedule' || options.trigger === 'manual') && !confirmed;
  const removals: Array<{
    step: PlannedStep;
    state: { principal?: AuthenticatedPrincipal; authority?: GrantAuthority };
  }> = [];
  const additions: typeof removals = [];
  const resolvedIssues: string[] = [];
  const attempted = new Set<string>();
  for (const pkg of packages) {
    const rule = pkg.autoAssign;
    if (rule) {
      const problem = ruleProblem(rule, {
        identityAttributes: ctx.catalog.identityAttributes,
        groups: facts.groupIds,
        packagedGroups: new Set(pkg.groupIds),
        org: { teams: facts.org.teamIds, departments: facts.org.departmentIds },
      });
      if (problem) {
        // A rule that cannot be evaluated freezes everything: never "matches nobody, revoke everyone".
        result.suspended.push({
          tenantId,
          packageId: pkg.id,
          reason: 'invalid-rule',
          detail: problem,
        });
        await recordIssue(
          ctx,
          tenantId,
          pkg,
          { kind: 'suspended', code: 'invalid-rule', message: problem },
          'package:auto-suspended',
          {
            ...base,
            packageId: pkg.id,
            packageName: pkg.name,
            reason: 'invalid-rule',
            detail: problem,
          },
        );
        continue;
      }
    }
    const plan = planPackage(ctx, facts, pkg);
    let steps = plan.steps;
    let state: { principal?: AuthenticatedPrincipal; authority?: GrantAuthority } = {};
    if (rule && steps.some((step) => additive.has(step.change))) {
      const health = await ruleHealth(ctx, reader, pkg, true);
      const suspendedKey = issueKey.suspended(pkg.id);
      if (!health.ok) {
        // Removals continue: removing access needs no authority, so leavers still lose it when the owner has left.
        steps = steps.filter((step) => !additive.has(step.change));
        result.suspended.push({
          tenantId,
          packageId: pkg.id,
          reason: health.reason,
          detail: health.detail,
        });
        await recordIssue(
          ctx,
          tenantId,
          pkg,
          { kind: 'suspended', code: health.reason, message: health.detail },
          'package:auto-suspended',
          {
            ...base,
            packageId: pkg.id,
            packageName: pkg.name,
            reason: health.reason,
            detail: health.detail,
          },
        );
      } else {
        state = { principal: health.principal, authority: health.authority };
        const stored = facts.issues.get(suspendedKey);
        if (stored) {
          await ctx.store.transaction(async (tx) => {
            if (await tx.get('packageRuleIssues', stored.id))
              await tx.delete('packageRuleIssues', stored.id);
            await ctx.events.recordAudit(tx, {
              id: id(),
              tenantId,
              actorId: 'deployment-operator',
              action: 'package:auto-resumed',
              resourceId: pkg.id,
              timestamp: ctx.now(),
              outcome: 'allow',
              metadata: {
                ...base,
                packageId: pkg.id,
                packageName: pkg.name,
                previousReason: stored.code,
              },
            });
          });
          facts.issues.delete(suspendedKey);
        }
      }
    }
    // Brakes: unattended runs hold back unusually large changes until a person confirms them.
    if (rule && braked) {
      const approved = rule.approved && rule.approved.until > now ? rule.approved : undefined;
      const thresholds = {
        grants: Math.max(rule.maxGrants ?? defaultMaxGrants, approved?.grants ?? 0),
        removals: Math.max(rule.maxRemovals ?? defaultMaxRemovals, approved?.removals ?? 0),
      };
      const isGrant = (step: PlannedStep) => step.change === 'assign' || step.change === 'refresh';
      const isRemoval = (step: PlannedStep) =>
        step.change === 'ending' ||
        (step.change === 'revoke' && step.reason === 'no-longer-matches');
      for (const [direction, test] of [
        ['grants', isGrant],
        ['removals', isRemoval],
      ] as const) {
        const planned = steps.filter(test).length;
        const key = issueKey.braked(pkg.id, direction);
        if (planned > thresholds[direction]) {
          steps = steps.filter((step) => !test(step));
          result.braked.push({
            tenantId,
            packageId: pkg.id,
            direction,
            planned,
            threshold: thresholds[direction],
          });
          await recordIssue(
            ctx,
            tenantId,
            pkg,
            {
              kind: 'braked',
              code: direction,
              message: `${planned} planned, threshold ${thresholds[direction]}`,
            },
            'package:auto-braked',
            {
              ...base,
              packageId: pkg.id,
              packageName: pkg.name,
              direction,
              planned,
              threshold: thresholds[direction],
            },
          );
        } else {
          const stored = facts.issues.get(key);
          if (stored) resolvedIssues.push(stored.id);
        }
      }
    }
    for (const step of steps)
      (additive.has(step.change) ? additions : removals).push({ step, state });
    // Failed issues whose pair needs nothing any more are resolved.
    const planned = new Set(plan.steps.map((step) => step.identityId));
    for (const issue of facts.issues.values())
      if (
        issue.kind === 'failed' &&
        issue.packageId === pkg.id &&
        issue.identityId &&
        !planned.has(issue.identityId)
      )
        if (facts.identities.some((identity) => identity.id === issue.identityId))
          resolvedIssues.push(issue.id);
  }
  // Removals first (a mover's old access goes before their new access arrives), then additions; within each,
  // changes without a stored failure come first so persistent failures never starve fresh work.
  const order = (a: { step: PlannedStep }, b: { step: PlannedStep }) =>
    Number(a.step.hasIssue) - Number(b.step.hasIssue) ||
    a.step.packageName.localeCompare(b.step.packageName, 'en') ||
    (a.step.identityId < b.step.identityId ? -1 : a.step.identityId > b.step.identityId ? 1 : 0);
  const rank = (change: RuleChange) =>
    change === 'revoke'
      ? 0
      : change === 'ending'
        ? 1
        : change === 'restore'
          ? 2
          : change === 'refresh'
            ? 3
            : 4;
  removals.sort((a, b) => rank(a.step.change) - rank(b.step.change) || order(a, b));
  additions.sort((a, b) => rank(a.step.change) - rank(b.step.change) || order(a, b));
  let budget =
    options.trigger === 'identity-change' ? Number.POSITIVE_INFINITY : (options.limit ?? 1000);
  const queue = [...removals, ...additions];
  for (let index = 0; index < queue.length; index++) {
    if (budget <= 0) {
      result.truncated = true;
      break;
    }
    budget--;
    const { step, state } = queue[index]!;
    attempted.add(`${step.packageId}:${step.identityId}`);
    try {
      const outcome = await applyStep(ctx, tenantId, step, state, {
        ...base,
        ...(confirmed ? { confirmed: true } : {}),
      });
      if (outcome === 'stale') result.stale++;
      else if (step.change === 'assign') result.assigned++;
      else if (step.change === 'refresh') result.refreshed++;
      else if (step.change === 'restore') result.restored++;
      else if (step.change === 'ending') result.ending++;
      else result.revoked++;
    } catch (error) {
      if (error instanceof IamError && error.code === 'CONFLICT' && step.change === 'assign') {
        result.stale++;
        continue;
      }
      const code = error instanceof IamError ? error.code : 'ERROR';
      const message = error instanceof Error ? error.message : String(error);
      result.failed.push({
        tenantId,
        packageId: step.packageId,
        identityId: step.identityId,
        change: step.change,
        code,
        message,
      });
      const pkg = packages.find((candidate) => candidate.id === step.packageId)!;
      await recordIssue(
        ctx,
        tenantId,
        pkg,
        { kind: 'failed', identityId: step.identityId, code, message },
        'package:auto-failed',
        {
          ...base,
          packageId: pkg.id,
          packageName: pkg.name,
          identityId: step.identityId,
          change: step.change,
          code,
          message,
        },
      );
    }
  }
  // Full-tenant runs also forget issues of identities or packages that are gone.
  if (!options.identityIds && !options.packageId) {
    const present = new Set(facts.identities.map((identity) => identity.id));
    const byId = new Map(all.map((pkg) => [pkg.id, pkg]));
    for (const issue of facts.issues.values()) {
      const pkg = byId.get(issue.packageId);
      if (
        !pkg ||
        (issue.identityId && !present.has(issue.identityId)) ||
        (issue.kind !== 'failed' && !pkg.autoAssign)
      )
        resolvedIssues.push(issue.id);
    }
  }
  await clearIssues(
    ctx,
    [...new Set(resolvedIssues)].filter((issueId) => {
      const issue = [...facts.issues.values()].find((candidate) => candidate.id === issueId);
      return (
        !issue || !issue.identityId || !attempted.has(`${issue.packageId}:${issue.identityId}`)
      );
    }),
  );
}

/** Reconciles the package rules for identities an administrator just changed; never throws (the schedule catches up). */
export async function afterIdentityChange<T>(
  ctx: ServerContext,
  tenantId: string,
  identityIds: string[],
  result: T,
): Promise<T> {
  try {
    if (identityIds.length)
      await reconcilePackageRules(ctx, { tenantId, identityIds, trigger: 'identity-change' });
  } catch {
    /* the scheduled reconcile catches up */
  }
  return result;
}

/**
 * What a rule matches (stored, candidate, or neither: keys only) and, for a package, what a run would change.
 * Read-only; requires iam:identities:read (checked here) to evaluate a rule over the directory.
 */
export async function previewRule(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  input: { tenantId: string; packageId?: string; autoAssign?: AutoAssignInput; sample?: number },
): Promise<AutoAssignPreview> {
  const sample = integer(input.sample ?? 20, 'sample', 1, 100);
  const keys = ruleKeys(ctx.catalog.identityAttributes, { org: true });
  const pkg =
    input.packageId !== undefined
      ? await ctx.scoped<AccessPackage>(
          tx,
          'accessPackages',
          text(input.packageId, 'packageId'),
          input.tenantId,
        )
      : undefined;
  let rule: AutoAssignInput | AutoAssignRule | undefined;
  let kind: AutoAssignPreview['rule'] = 'none';
  if (input.autoAssign !== undefined) {
    rule = parseAutoAssign(input.autoAssign, {
      identityAttributes: ctx.catalog.identityAttributes,
      groups: new Set(
        (await tx.find<Group>('groups', { tenantId: input.tenantId })).map((group) => group.id),
      ),
      ...(pkg ? { packagedGroups: new Set(pkg.groupIds) } : {}),
      org: await orgRuleEnvironment(tx, input.tenantId),
    });
    kind = 'candidate';
  } else if (pkg?.autoAssign) {
    rule = pkg.autoAssign;
    kind = 'stored';
  }
  const empty: AutoAssignPreview = {
    rule: kind,
    keys,
    warnings: [],
    matching: 0,
    excluded: 0,
    frozen: 0,
    sample: [],
  };
  if (!rule) return empty;
  await allow(
    ctx,
    tx,
    principal,
    input.tenantId,
    'iam:identities:read',
    input.tenantId,
    'list identities',
  );
  const facts = await loadFacts(ctx, tx, input.tenantId, {});
  const doc = ruleDocument(rule);
  const matches: AutoAssignPreview['sample'] = [];
  let excluded = 0;
  let frozen = 0;
  for (const identity of facts.identities) {
    if (identity.status !== 'active' || ctx.identityExpired(identity)) {
      frozen++;
      continue;
    }
    const f = identityFacts(ctx, facts, identity, pkg?.id ?? '');
    const match = ruleMatch(doc, identity, ruleContext(identity, f.directGroupIds, f.org));
    if (match.matched)
      matches.push({
        identityId: identity.id,
        name: identity.name,
        ...(identity.email ? { email: identity.email } : {}),
        kind: identity.kind,
        matchedBy: match.matchedBy,
      });
    else if (match.matchedBy.length && match.excludedBy.length) excluded++;
  }
  matches.sort(
    (a, b) => a.name.localeCompare(b.name, 'en') || (a.identityId < b.identityId ? -1 : 1),
  );
  const preview: AutoAssignPreview = {
    rule: kind,
    keys,
    warnings: ruleWarnings(rule, { boundGroups: await boundGroups(tx, input.tenantId, rule) }),
    matching: matches.length,
    excluded,
    frozen,
    sample: matches.slice(0, sample),
  };
  if (!pkg) return preview;
  // What a run would change: the package with the candidate (or stored) rule, planned against the directory.
  const candidate: AccessPackage =
    kind === 'candidate'
      ? {
          ...pkg,
          autoAssign: {
            ...(rule as AutoAssignInput),
            ownerId: pkg.autoAssign?.ownerId ?? principal.identity.id,
            authorityId: pkg.autoAssign?.authorityId ?? '',
            revision: (pkg.autoAssign?.revision ?? 0) + 1,
            updatedAt: ctx.now(),
          },
        }
      : pkg;
  const plan = planPackage(ctx, facts, candidate);
  const names = new Map(facts.identities.map((identity) => [identity.id, identity]));
  preview.plan = {
    assign: plan.counts.assign,
    refresh: plan.counts.refresh,
    restore: plan.counts.restore,
    ending: plan.counts.ending,
    revoke: plan.counts.revoke,
    manual: plan.counts.manual,
    keep: plan.counts.keep,
  };
  preview.changes = plan.steps.slice(0, sample).map((step) => {
    const identity = names.get(step.identityId)!;
    return {
      identityId: step.identityId,
      name: identity.name,
      ...(identity.email ? { email: identity.email } : {}),
      change: step.change,
    };
  });
  const stored = candidate.autoAssign!;
  const approved =
    stored.approved && stored.approved.until > ctx.now() ? stored.approved : undefined;
  const grants = plan.counts.assign + plan.counts.refresh;
  const removals = plan.counts.ending + plan.counts.revoke - plan.counts.revokeRuleCleared;
  const grantThreshold = Math.max(stored.maxGrants ?? defaultMaxGrants, approved?.grants ?? 0);
  const removalThreshold = Math.max(
    stored.maxRemovals ?? defaultMaxRemovals,
    approved?.removals ?? 0,
  );
  preview.brake = {
    grants: { planned: grants, threshold: grantThreshold, trips: grants > grantThreshold },
    removals: {
      planned: removals,
      threshold: removalThreshold,
      trips: removals > removalThreshold,
    },
  };
  if (pkg.autoAssign) {
    const view = await autoAssignView(ctx, tx, pkg, await ruleEnvironment(ctx, tx, pkg));
    preview.status = {
      status: view.status,
      ...(view.suspendedReason
        ? { reason: view.suspendedReason, detail: view.suspendedDetail! }
        : {}),
    };
  }
  return preview;
}
