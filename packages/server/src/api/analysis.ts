import { createHash } from 'node:crypto';
import {
  IamError,
  findOrdered,
  type AuditEvent,
  type CredentialInput,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Session,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { agentStanding } from '../agents.js';
import type { ServerContext } from '../context.js';
import type { Delegation } from '../delegations.js';
import type {
  Binding,
  BindingActivation,
  GroupMember,
  Policy,
  ResourceTypeRecord,
  Role,
  Trust,
  Group,
} from '../models.js';
import { trustPassesSourceAttributes, trustRequiresMfa } from '../flows.js';
import { lintPolicy, type PolicyLintContext, type PolicyLintResult } from '../policy-lint.js';
import { sodViolations } from '../sod.js';
import { departmentCollections, type Department, type DepartmentMember } from '../departments.js';
import {
  liveTeamMember,
  teamChain,
  teamCollections,
  type Team,
  type TeamMember,
} from '../teams.js';
import { integer, strings, text } from '../validation.js';

export type FindingSeverity = 'high' | 'medium' | 'low';

/** Refusals in a day from which an agent is reported (`agent-denials`). */
const agentDenialThreshold = 20;
export type FindingKind =
  | 'unrestricted-admin-policy'
  | 'broad-action-wildcard'
  | 'admin-without-mfa'
  | 'separation-of-duties'
  | 'service-account-admin'
  | 'dormant-access'
  | 'stale-api-key'
  | 'trust-without-mfa'
  | 'trust-passes-foreign-attributes'
  | 'unattached-policy'
  | 'unused-role'
  | 'empty-role'
  | 'empty-group-with-access'
  | 'standing-privileged-access'
  | 'unused-eligible-binding'
  | 'orphaned-manager'
  | 'manager-cycle'
  | 'policy-lint'
  | 'agent-without-sponsor'
  | 'agent-admin'
  | 'unbounded-agent'
  | 'broad-delegation'
  | 'unused-delegation'
  | 'open-handoff'
  | 'agent-denials'
  | 'team-maintainers-grant-admin'
  | 'team-without-maintainer'
  | 'department-without-head';

/** One security observation about the tenant's configuration, stable across runs while the condition holds. */
export interface AccessFinding {
  /** Deterministic: the same condition on the same subject always yields the same ID, so it can be suppressed. */
  id: string;
  kind: FindingKind;
  severity: FindingSeverity;
  title: string;
  detail: string;
  subject: {
    type:
      | 'policy'
      | 'role'
      | 'identity'
      | 'group'
      | 'trust'
      | 'credential'
      | 'delegation'
      | 'team'
      | 'department';
    id: string;
    name?: string;
  };
  suppressed?: { reason: string; by: string; at: number };
}
interface Suppression extends StoredRecord {
  findingId: string;
  reason: string;
  createdBy: string;
  createdAt: number;
  /** The finding as it was when suppressed (`fingerprint`); absent on suppressions recorded before fingerprints. */
  fingerprint?: string;
}

const severityRank: Record<FindingSeverity, number> = { high: 0, medium: 1, low: 2 };
const findingId = (kind: FindingKind, subject: string) =>
  createHash('sha256').update(`${kind}:${subject}`).digest('hex').slice(0, 24);
/**
 * What a suppression accepts: the finding's severity and evidence (its detail, unless the check names something
 * steadier). A suppression only hides a finding whose fingerprint still matches, so one that grows worse shows again.
 */
const fingerprint = (severity: FindingSeverity, evidence: string) =>
  createHash('sha256').update(`${severity}\n${evidence}`).digest('hex').slice(0, 32);
const suppressionId = (tenantId: string, finding: string) => `${tenantId}:${finding}`;
/** Audit actions bindings.activate and approveActivation record for a live activation (resourceId is the binding ID). */
const activationActions = new Set(['binding:activate', 'binding:activation-approved']);
/**
 * An activation the bindings API recorded. Anyone can make authorize() audit a denied decision under any action and
 * resource ID, so only allowed events carrying the activation ID (which authorization decisions never have) count.
 */
const recordedActivation = (event: AuditEvent) =>
  activationActions.has(event.action) &&
  event.outcome === 'allow' &&
  typeof event.metadata?.activationId === 'string';
const systemPolicy = (policy: Policy) =>
  typeof policy.uniqueKey === 'string' && policy.uniqueKey.startsWith('system:');

/** An allow statement without conditions over every action (or every platform action) on every resource. */
export function unrestrictedAdmin(document: PolicyDocument | undefined): boolean {
  return (
    document?.statements.some(
      (statement) =>
        statement.effect === 'allow' &&
        !statement.conditions &&
        statement.actions.some((action) => action === '*' || action === 'iam:*') &&
        statement.resources.includes('*'),
    ) ?? false
  );
}
/** Unconditional service-wide action wildcards (`documents:*`) that are not already full administration. */
function broadActions(document: PolicyDocument | undefined): string[] {
  const found = new Set<string>();
  for (const statement of document?.statements ?? [])
    if (statement.effect === 'allow' && !statement.conditions)
      for (const action of statement.actions)
        if (action !== '*' && action !== 'iam:*' && /(^|:)\*$/.test(action)) found.add(action);
  return [...found];
}

/**
 * Access analysis: a read-only scan of a tenant's policies, roles, groups, bindings, trusts, and members that
 * reports risky or stale configuration — unrestricted administrator policies, administrators without a second
 * factor, dormant members who still hold access, trusts that skip MFA, and unused policies, roles, and groups —
 * plus standing administrator bindings, eligible bindings never activated, broken manager links, and policy lint
 * warnings. Findings can be suppressed with a recorded reason; suppressed findings stay listed on request.
 */
export function createAnalysisApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  /**
   * What the policy linter may assume for a tenant: the declared identity attributes and, when every resource is
   * registered with IAM (no application resolver, which may return any attribute), the known resource attributes.
   */
  async function lintContext(tx: IamStore, tenantId: string): Promise<PolicyLintContext> {
    const context: PolicyLintContext = { identityAttributes: ctx.catalog.identityAttributes };
    if (!ctx.options.resolveResource) {
      const names = new Set<string>();
      for (const type of ctx.catalog.resourceTypes.values())
        for (const name of Object.keys(type.attributes)) names.add(name);
      for (const record of await tx.find<ResourceTypeRecord>('resourceTypes', { tenantId }))
        for (const name of Object.keys(record.attributes ?? {})) names.add(name);
      context.resourceAttributes = [...names].sort();
    }
    return context;
  }
  /**
   * Every finding the checks report for the tenant now, before suppressions, with each finding's fingerprint (by ID):
   * what a suppression of it accepts.
   */
  async function scan(tx: IamStore, tenant: Tenant, dormantDays: number) {
    const tenantId = tenant.id;
    const now = ctx.now();
    // Sequential reads: a transaction holds one database connection.
    const policies = await tx.find<Policy>('policies', { tenantId });
    const roles = await tx.find<Role>('roles', { tenantId });
    const bindings = await tx.find<Binding>('bindings', { tenantId });
    const members = (await tx.find<GroupMember>('groupMembers', { tenantId })).filter((member) =>
      ctx.liveMembership(member),
    );
    const groups = await tx.find<Group>('groups', { tenantId });
    const identities = await tx.find<Identity>('identities', { tenantId });
    const trusts = await tx.find<Trust>('trusts', { tenantId });
    const live = bindings.filter((binding) => ctx.liveBinding(binding));
    const policyById = new Map(policies.map((policy) => [policy.id, policy]));
    const findings: AccessFinding[] = [];
    const fingerprints = new Map<string, string>();
    /** `evidence` (default: the detail) must not change while the condition stays the same, e.g. with time. */
    const report = (
      kind: FindingKind,
      severity: FindingSeverity,
      subject: AccessFinding['subject'],
      title: string,
      detail: string,
      key = `${subject.type}:${subject.id}`,
      evidence = detail,
    ) => {
      const id = findingId(kind, key);
      fingerprints.set(id, fingerprint(severity, evidence));
      findings.push({ id, kind, severity, title, detail, subject });
    };

    // Policies and inline role documents.
    const attached = new Set(roles.flatMap((role) => role.policyIds));
    for (const policy of policies) {
      const system = typeof policy.uniqueKey === 'string' && policy.uniqueKey.startsWith('system:');
      if (!system && unrestrictedAdmin(policy.document))
        report(
          'unrestricted-admin-policy',
          'high',
          { type: 'policy', id: policy.id, name: policy.name },
          `Policy ${policy.name} grants every action on every resource`,
          'An unconditional allow of * (or iam:*) on * makes every holder a full administrator. Scope the actions and resources, or add conditions such as principal.mfa.',
        );
      else if (!system && broadActions(policy.document).length)
        report(
          'broad-action-wildcard',
          'medium',
          { type: 'policy', id: policy.id, name: policy.name },
          `Policy ${policy.name} uses service-wide action wildcards`,
          `Unconditional ${broadActions(policy.document).join(', ')} also grants actions added to those services later. List the actions holders need.`,
        );
      if (!system && !attached.has(policy.id))
        report(
          'unattached-policy',
          'low',
          { type: 'policy', id: policy.id, name: policy.name },
          `Policy ${policy.name} is not attached to any role`,
          'Unattached policies grant nothing; delete them or attach them where intended.',
        );
    }
    const adminRoles = new Set<string>();
    for (const role of roles) {
      const documents = [
        role.document,
        ...role.policyIds.map((id) => policyById.get(id)?.document),
      ];
      if (documents.some(unrestrictedAdmin)) adminRoles.add(role.id);
      if (role.protected) continue;
      if (unrestrictedAdmin(role.document))
        report(
          'unrestricted-admin-policy',
          'high',
          { type: 'role', id: role.id, name: role.name },
          `Role ${role.name} has an inline document granting every action on every resource`,
          'Replace the inline * statement with scoped policies.',
        );
      if (!role.document && !role.policyIds.some((id) => policyById.has(id)))
        report(
          'empty-role',
          'low',
          { type: 'role', id: role.id, name: role.name },
          `Role ${role.name} grants nothing`,
          'The role has no inline document and no attached policies.',
        );
      const bound = live.some((binding) => binding.roleId === role.id);
      const trusted = trusts.some((trust) => !trust.revoked && trust.roleId === role.id);
      if (!bound && !trusted)
        report(
          'unused-role',
          'low',
          { type: 'role', id: role.id, name: role.name },
          `Role ${role.name} is not bound to anyone`,
          'No identity, group, or trust uses this role; remove it if it is no longer needed.',
        );
    }

    // Groups that hold access but have no members.
    for (const group of groups)
      if (
        live.some((b) => b.subjectType === 'group' && b.subjectId === group.id) &&
        !members.some((member) => member.groupId === group.id)
      )
        report(
          'empty-group-with-access',
          'low',
          { type: 'group', id: group.id, name: group.name },
          `Group ${group.name} holds role bindings but has no members`,
          'Anyone added later inherits the access immediately; review the bindings.',
        );

    // Identities: effective bindings (direct and through groups), factor enrollment, and last sign-in.
    const groupsOf = new Map<string, Set<string>>();
    for (const member of members) {
      const set = groupsOf.get(member.identityId) ?? new Set<string>();
      set.add(member.groupId);
      groupsOf.set(member.identityId, set);
    }
    const tenantRequiresMfa = tenant.authPolicy?.requireMfa === true;
    for (const identity of identities) {
      if (identity.status !== 'active') continue;
      const memberOf = groupsOf.get(identity.id) ?? new Set<string>();
      const held = live.filter((binding) =>
        binding.subjectType === 'identity'
          ? binding.subjectId === identity.id
          : memberOf.has(binding.subjectId),
      );
      const subject = {
        type: 'identity' as const,
        id: identity.id,
        name: identity.email ?? identity.name,
      };
      const admin = identity.owner || held.some((binding) => adminRoles.has(binding.roleId));
      if (admin && identity.kind === 'service')
        report(
          'service-account-admin',
          'medium',
          subject,
          `Service account ${identity.name} has full administrator access`,
          'A leaked API key would control the whole organization. Bind a role scoped to what the automation does.',
        );
      if (admin && identity.kind === 'agent')
        report(
          'agent-admin',
          'high',
          subject,
          `AI agent ${identity.name} has full administrator access`,
          'An agent follows instructions it reads, so a prompt injection or a leaked key would control the whole organization. Bind a role scoped to its task and set a ceiling (agents.update boundary).',
        );
      if (admin && identity.kind === 'user' && !tenantRequiresMfa) {
        const factor =
          (await tx.get<StoredRecord & { enabled?: boolean }>('authMfa', identity.id))?.enabled ===
            true ||
          (await tx.find('authPasskeys', { tenantId, identityId: identity.id })).length > 0;
        if (!factor)
          report(
            'admin-without-mfa',
            'high',
            subject,
            `${identity.email ?? identity.name} is an administrator without a second factor`,
            'Administrators should enroll an authenticator app or passkey; the tenant authentication policy can require MFA for everyone.',
          );
      }
      if (identity.kind === 'user' && (held.length || identity.owner)) {
        const signIns = await tx.find<AuditEvent>('audit', {
          tenantId,
          actorId: identity.id,
          action: 'auth:session:create',
        });
        // "View as" sessions are recorded on the member but are not the member signing in.
        const last = Math.max(
          0,
          ...signIns.filter((event) => !event.impersonatorId).map((event) => event.timestamp),
        );
        const since = last || identity.createdAt;
        if (now - since > dormantDays * 86_400_000)
          report(
            'dormant-access',
            'medium',
            subject,
            last
              ? `${identity.email ?? identity.name} has not signed in for ${Math.floor((now - last) / 86_400_000)} days`
              : `${identity.email ?? identity.name} has never signed in`,
            `The account still holds ${held.length} role binding(s)${identity.owner ? ' and ownership' : ''}. Disable it or remove its access if it is no longer used.`,
          );
      }
    }

    const identityById = new Map(identities.map((identity) => [identity.id, identity]));
    const roleName = new Map(roles.map((role) => [role.id, role.name]));
    for (const violation of await sodViolations(ctx, tx, tenantId)) {
      const identity = identityById.get(violation.identityId);
      if (!identity || identity.status !== 'active') continue;
      const held = violation.roleIds.map((roleId) => roleName.get(roleId) ?? roleId);
      report(
        'separation-of-duties',
        'high',
        {
          type: 'identity',
          id: identity.id,
          name: identity.email ?? identity.name,
        },
        `${identity.email ?? identity.name} holds conflicting roles (${violation.ruleName})`,
        `${held.join(' and ')} must not be held together. Remove one of the bindings${violation.mode === 'detect' ? ', or keep the rule in detect mode if the combination is accepted' : '; the conflict predates the rule, which now prevents new ones'}.`,
        `identity:${identity.id}:${violation.ruleId}`,
      );
    }

    // API keys nobody has used for the dormant window (lastSeenAt only moves when a key authenticates).
    for (const key of await tx.find<Session>('sessions', { tenantId, kind: 'api-key' })) {
      if (key.expiresAt <= now) continue;
      const lastUsed = key.lastSeenAt > key.createdAt ? key.lastSeenAt : undefined;
      if (now - (lastUsed ?? key.createdAt) <= dormantDays * 86_400_000) continue;
      const owner = identityById.get(key.identityId);
      const label = typeof key.name === 'string' ? key.name : key.id.slice(0, 8);
      report(
        'stale-api-key',
        'medium',
        { type: 'credential', id: key.id, name: label },
        lastUsed
          ? `API key ${label} has not been used for ${Math.floor((now - lastUsed) / 86_400_000)} days`
          : `API key ${label} has never been used`,
        `The key belongs to ${owner?.name ?? key.identityId} and stays valid until ${new Date(key.expiresAt).toISOString().slice(0, 10)}. Revoke it if nothing depends on it.`,
      );
    }

    // AI agents: the person accountable for each, their ceilings, and the delegations people gave them.
    for (const agent of identities) {
      if (agent.kind !== 'agent' || agent.status === 'deleted') continue;
      const subject = { type: 'identity' as const, id: agent.id, name: agent.name };
      const standing = await agentStanding(ctx, tx, agent);
      if (standing === 'sponsor-missing' || standing === 'sponsor-inactive')
        report(
          'agent-without-sponsor',
          'high',
          subject,
          `AI agent ${agent.name} has no active sponsor`,
          'Its credentials are refused until someone is accountable for it. Name an active person as its sponsor (agents.update) or delete the agent.',
        );
      else if (
        agent.status === 'active' &&
        !agent.agent?.boundary &&
        agent.agent?.delegable !== false
      )
        report(
          'unbounded-agent',
          'low',
          subject,
          `AI agent ${agent.name} accepts delegation without a ceiling`,
          'Each delegation lets it do whatever the delegation scope and the person allow. A boundary policy caps what any delegation, and its own keys, can reach.',
        );
    }
    const agentName = (agentId: string) => identityById.get(agentId)?.name ?? agentId;
    for (const delegation of await tx.find<Delegation>('delegations', { tenantId })) {
      if (delegation.status !== 'active' || delegation.expiresAt <= now) continue;
      const person = identityById.get(delegation.subjectId);
      const subject = {
        type: 'delegation' as const,
        id: delegation.id,
        name: `${person?.email ?? person?.name ?? delegation.subjectId} → ${agentName(delegation.agentId)}`,
      };
      const everything = delegation.policy.statements.some(
        (statement) =>
          statement.effect === 'allow' &&
          statement.actions.some((action) => action === '*' || action === 'iam:*'),
      );
      if (everything)
        report(
          'broad-delegation',
          'medium',
          subject,
          `${subject.name}: the agent may do anything the person can`,
          'The delegation scope allows every action. Revoke it and grant the actions the agent needs.',
        );
      const lastUsed = delegation.lastUsedAt ?? delegation.decidedAt ?? delegation.createdAt;
      if (now - lastUsed > dormantDays * 86_400_000)
        report(
          'unused-delegation',
          'low',
          subject,
          `${subject.name}: unused for ${Math.floor((now - lastUsed) / 86_400_000)} days`,
          `The delegation stays active until ${new Date(delegation.expiresAt).toISOString().slice(0, 10)}. Revoke it if the agent no longer acts for this person.`,
        );
      // Hand-offs to any agent at all (delegations.ts): the person's access can travel further than they chose.
      if (delegation.handoff && !delegation.handoff.agents?.length)
        report(
          'open-handoff',
          delegation.handoff.depth > 1 ? 'medium' : 'low',
          subject,
          `${subject.name}: the agent may hand the work on to any agent${delegation.handoff.depth > 1 ? `, ${delegation.handoff.depth} levels deep` : ''}`,
          'Name the agents it may hand work to (handoff.agents), or grant the delegation without hand-offs.',
          undefined,
          // A deeper hand-off is a worse finding.
          `depth:${delegation.handoff.depth}`,
        );
    }

    // Agents refused often in the last day, with their own keys or acting for people: a sign of an agent looping,
    // misconfigured, or following instructions injected into what it reads.
    const agentIds = new Set(
      identities.filter((identity) => identity.kind === 'agent').map((agent) => agent.id),
    );
    if (agentIds.size) {
      const denials = new Map<string, number>();
      for (const event of await findOrdered<AuditEvent>(
        tx,
        'audit',
        { tenantId },
        {
          field: 'timestamp',
          direction: 'desc',
          from: now - 86_400_000,
          limit: 10_000,
          where: (event) => event.outcome === 'deny',
        },
      )) {
        const agentId =
          event.sessionContext?.agentId ??
          (agentIds.has(event.actorId) ? event.actorId : undefined);
        if (agentId && agentIds.has(agentId)) denials.set(agentId, (denials.get(agentId) ?? 0) + 1);
      }
      for (const [agentId, count] of denials)
        if (count >= agentDenialThreshold)
          report(
            'agent-denials',
            'medium',
            { type: 'identity', id: agentId, name: agentName(agentId) },
            `AI agent ${agentName(agentId)} was refused ${count} times in the last day`,
            'Check what it attempted (agents.activity). Suspend it if it is looping or following instructions it should not.',
          );
    }

    // Teams and departments (teams.ts, departments.ts): who can hand out a team's access, and who leads.
    const teams = await tx.find<Team>(teamCollections.teams, { tenantId });
    if (teams.length) {
      const teamById = new Map(teams.map((team) => [team.id, team]));
      const teamMembers = (await tx.find<TeamMember>(teamCollections.members, { tenantId })).filter(
        (member) => liveTeamMember(member, now),
      );
      const activePerson = (identityId: string) =>
        identityById.get(identityId)?.status === 'active';
      for (const team of teams) {
        const chain = teamChain(teamById, team.id);
        const subject = { type: 'team' as const, id: team.id, name: team.name };
        const maintainers = teamMembers.filter(
          (member) =>
            member.role === 'maintainer' &&
            chain.some((holder) => holder.id === member.teamId) &&
            activePerson(member.identityId),
        );
        const adminGrant = live.find(
          (binding) =>
            binding.subjectType === 'group' &&
            adminRoles.has(binding.roleId) &&
            !binding.eligible &&
            chain.some((holder) => holder.groupId === binding.subjectId),
        );
        if (adminGrant && team.memberManagement !== 'admins' && maintainers.length)
          report(
            'team-maintainers-grant-admin',
            'high',
            subject,
            `Maintainers of ${team.name} can make anyone a full administrator`,
            `The team holds ${roleName.get(adminGrant.roleId) ?? 'an administrator role'} as standing access, and its ${maintainers.length} maintainer(s) add members without an administrator's authority. Set memberManagement to admins, or make the binding eligible (just-in-time).`,
          );
        const direct = teamMembers.filter(
          (member) => member.teamId === team.id && activePerson(member.identityId),
        );
        if (direct.length && !maintainers.length && team.memberManagement !== 'admins')
          report(
            'team-without-maintainer',
            'low',
            subject,
            `Team ${team.name} has members but no maintainer`,
            'Nobody but administrators can manage its membership or answer its join requests. Name a maintainer, or set memberManagement to admins to make that the rule.',
          );
      }
    }
    const departments = await tx.find<Department>(departmentCollections.departments, {
      tenantId,
    });
    if (departments.length) {
      const placed = new Map<string, number>();
      for (const member of await tx.find<DepartmentMember>(departmentCollections.members, {
        tenantId,
      }))
        if (identityById.get(member.identityId)?.status === 'active')
          placed.set(member.departmentId, (placed.get(member.departmentId) ?? 0) + 1);
      for (const department of departments) {
        const people = placed.get(department.id) ?? 0;
        const head = department.headId ? identityById.get(department.headId) : undefined;
        if (people && head?.status !== 'active')
          report(
            'department-without-head',
            'low',
            { type: 'department', id: department.id, name: department.name },
            head
              ? `The head of ${department.name} is no longer active`
              : `Department ${department.name} has no head`,
            `${people} ${people === 1 ? 'person' : 'people'} in it have no department head to report to, so manager approvals routed through the org chart stop there. Name a head (departments.update).`,
          );
      }
    }

    for (const trust of trusts) {
      if (trust.revoked) continue;
      // Web-identity trusts have no source session to verify; their claim conditions pin the workload.
      // Stored flags are read through the same fail-closed readers roles.assume enforces with.
      if (trust.kind !== 'web-identity' && !trustRequiresMfa(trust))
        report(
          'trust-without-mfa',
          'medium',
          { type: 'trust', id: trust.id },
          'A cross-tenant trust lets its source assume a role without MFA',
          'Recreate the trust with requireMfa so a stolen password alone cannot assume the role.',
        );
      // Another tenant controls the source identity's attributes, so they must not satisfy this tenant's
      // ABAC conditions. New cross-tenant trusts keep them out; legacy ones (no field) still pass them.
      if (
        trust.kind !== 'web-identity' &&
        trust.sourceTenantId !== tenantId &&
        trustPassesSourceAttributes(trust)
      )
        report(
          'trust-passes-foreign-attributes',
          'medium',
          { type: 'trust', id: trust.id },
          'A cross-tenant trust passes the source account’s attributes into role sessions',
          'The source tenant controls these attributes, so they can satisfy this tenant’s attribute conditions. Call trust.update({ passSourceAttributes: false }) and use session tags for the data role sessions need.',
        );
    }

    // Standing administrator access: direct, permanent, always-on bindings to administrator roles.
    const roleById = new Map(roles.map((role) => [role.id, role]));
    for (const binding of bindings) {
      const role = roleById.get(binding.roleId);
      const identity =
        binding.subjectType === 'identity' ? identityById.get(binding.subjectId) : undefined;
      if (
        !role ||
        role.protected ||
        !adminRoles.has(role.id) ||
        binding.eligible === true ||
        binding.expiresAt !== undefined ||
        identity?.kind !== 'user' ||
        identity.status !== 'active'
      )
        continue;
      report(
        'standing-privileged-access',
        'medium',
        { type: 'identity', id: identity.id, name: identity.email ?? identity.name },
        `${identity.email ?? identity.name} holds ${role.name} as standing administrator access`,
        `The binding grants full administration permanently and without activation. Make it eligible (just-in-time activation) or give it an expiry.`,
        `binding:${binding.id}`,
      );
    }

    // Eligible bindings nobody has ever activated. Bindings carry no creation time, so their age is bounded
    // from below by the subject's creation and from above by the first audit event naming the binding.
    const eligible = bindings.filter(
      (binding) => binding.eligible === true && !ctx.expiredBinding(binding),
    );
    if (eligible.length) {
      const ids = new Set(eligible.map((binding) => binding.id));
      const activated = new Set<string>();
      const firstSeen = new Map<string, number>();
      for (const event of await tx.find<AuditEvent>('audit', { tenantId })) {
        if (!ids.has(event.resourceId)) continue;
        if (recordedActivation(event)) activated.add(event.resourceId);
        firstSeen.set(
          event.resourceId,
          Math.min(firstSeen.get(event.resourceId) ?? Infinity, event.timestamp),
        );
      }
      for (const activation of await tx.find<BindingActivation>('bindingActivations', {
        tenantId,
      }))
        if (activation.status !== 'pending' && activation.status !== 'denied')
          activated.add(activation.bindingId);
      const groupById = new Map(groups.map((group) => [group.id, group]));
      const window = dormantDays * 86_400_000;
      for (const binding of eligible) {
        if (activated.has(binding.id)) continue;
        let subject: AccessFinding['subject'];
        let notBefore = Math.max(tenant.createdAt ?? 0, binding.startsAt ?? 0);
        if (binding.subjectType === 'identity') {
          const identity = identityById.get(binding.subjectId);
          if (identity?.status !== 'active') continue;
          subject = {
            type: 'identity',
            id: identity.id,
            name: identity.email ?? identity.name,
          };
          notBefore = Math.max(notBefore, identity.createdAt);
        } else {
          const group = groupById.get(binding.subjectId);
          if (!group) continue;
          subject = { type: 'group', id: group.id, name: group.name };
        }
        const seen = firstSeen.get(binding.id);
        const existedFor = seen !== undefined ? now - seen : undefined;
        if ((existedFor === undefined || existedFor <= window) && now - notBefore <= window)
          continue;
        const role = roleName.get(binding.roleId) ?? binding.roleId;
        report(
          'unused-eligible-binding',
          'low',
          subject,
          `Eligible ${role} binding for ${subject.name} has no recorded activation`,
          existedFor !== undefined && existedFor > window
            ? `The just-in-time binding has existed for at least ${Math.floor(existedFor / 86_400_000)} days and was never activated. Remove it if the access is no longer needed.`
            : 'The audit trail shows no activation of this just-in-time binding. Remove it if the access is no longer needed.',
          `binding:${binding.id}`,
          // The detail counts days; the binding's role and subject are what the suppression accepts.
          `role:${binding.roleId}`,
        );
      }
    }

    // Manager links that lead nowhere or back to the person. Manager links form a functional graph (one
    // outgoing link each), so a single walk that marks people in progress and done finds every loop in linear
    // time, however deep the reporting chains are.
    const loops = new Map<string, { members: Identity[]; position: number }>();
    const walked = new Map<string, 'walking' | 'done'>();
    for (const start of identities) {
      const path: Identity[] = [];
      let cursor: Identity | undefined = start;
      while (cursor && !walked.has(cursor.id)) {
        walked.set(cursor.id, 'walking');
        path.push(cursor);
        cursor = cursor.managerId ? identityById.get(cursor.managerId) : undefined;
      }
      // Reaching someone still in progress closes a loop from them to the end of this walk.
      if (cursor && walked.get(cursor.id) === 'walking') {
        const members = path.slice(path.indexOf(cursor));
        members.forEach((member, position) => loops.set(member.id, { members, position }));
      }
      for (const person of path) walked.set(person.id, 'done');
    }
    const label = (person: Identity) => person.email ?? person.name;
    for (const identity of identities) {
      if (identity.status !== 'active' || identity.managerId === undefined) continue;
      const subject = {
        type: 'identity' as const,
        id: identity.id,
        name: identity.email ?? identity.name,
      };
      const manager = identityById.get(identity.managerId);
      if (manager?.status !== 'active') {
        report(
          'orphaned-manager',
          'low',
          subject,
          manager
            ? `${subject.name}'s manager ${manager.email ?? manager.name} is ${manager.status}`
            : `${subject.name}'s manager no longer exists`,
          'Approvals routed to the manager and offboarding handoffs cannot reach them. Assign an active manager or clear the link.',
        );
        continue;
      }
      // Someone who only reports into a loop is not part of it; the loop is reported for its members.
      const loop = loops.get(identity.id);
      if (!loop) continue;
      // The loop as seen from this person, shortened when it is long.
      const { members, position } = loop;
      const chain = Array.from({ length: Math.min(members.length, 10) }, (_, step) =>
        label(members[(position + step) % members.length]!),
      );
      if (members.length > 10) chain.splice(9, 1, `… ${members.length - 9} more`);
      report(
        'manager-cycle',
        'medium',
        subject,
        `${subject.name}'s manager chain loops back to them`,
        `${[...chain, label(identity)].join(' → ')}. Manager approvals and offboarding handoffs cannot resolve a loop; give someone in it a manager outside the chain.`,
      );
    }

    // Stored policies and inline role documents the linter warns about.
    const linting = await lintContext(tx, tenantId);
    const lintFinding = (
      subject: AccessFinding['subject'],
      label: string,
      document: PolicyDocument,
    ) => {
      const warnings = lintPolicy(document, linting).warnings.filter(
        // unrestricted-admin already has its own high-severity finding.
        (warning) => warning.severity === 'warning' && warning.code !== 'unrestricted-admin',
      );
      if (!warnings.length) return;
      const codes = [...new Set(warnings.map((warning) => warning.code))];
      report(
        'policy-lint',
        'low',
        subject,
        `${label} has ${warnings.length} lint warning${warnings.length === 1 ? '' : 's'}`,
        `${codes.slice(0, 3).join(', ')}${codes.length > 3 ? ` and ${codes.length - 3} more` : ''}. Lint the document (analysis.lintPolicy) for details.`,
      );
    };
    for (const policy of policies)
      if (!systemPolicy(policy))
        lintFinding(
          { type: 'policy', id: policy.id, name: policy.name },
          `Policy ${policy.name}`,
          policy.document,
        );
    for (const role of roles)
      if (!role.protected && role.document)
        lintFinding(
          { type: 'role', id: role.id, name: role.name },
          `Role ${role.name}'s inline document`,
          role.document,
        );
    return { now, findings, fingerprints };
  }
  return {
    /**
     * Runs every check. `dormantDays` (default 90) sets when an unused account holding access is reported. A
     * suppressed finding is hidden only while it is as it was when suppressed (same severity and detail).
     */
    findings: (
      credential: CredentialInput,
      input: { tenantId: string; dormantDays?: number; includeSuppressed?: boolean },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:analysis:read',
        'analysis/*',
        async ({ tx, tenant }) => {
          const dormantDays = integer(input.dormantDays ?? 90, 'dormantDays', 1, 3650);
          const { now, findings, fingerprints } = await scan(tx, tenant, dormantDays);
          // A suppression stands for the finding it was accepted for: once the finding changes, it shows again.
          const suppressions = new Map(
            (await tx.find<Suppression>('analysisSuppressions', { tenantId: tenant.id }))
              .filter(
                (row) =>
                  row.fingerprint !== undefined &&
                  row.fingerprint === fingerprints.get(row.findingId),
              )
              .map((row) => [row.findingId, row]),
          );
          const annotated = findings
            .map((finding) => {
              const suppression = suppressions.get(finding.id);
              return suppression
                ? {
                    ...finding,
                    suppressed: {
                      reason: suppression.reason,
                      by: suppression.createdBy,
                      at: suppression.createdAt,
                    },
                  }
                : finding;
            })
            .filter((finding) => input.includeSuppressed === true || !finding.suppressed)
            .sort(
              (a, b) =>
                severityRank[a.severity] - severityRank[b.severity] ||
                a.kind.localeCompare(b.kind) ||
                a.id.localeCompare(b.id),
            );
          const summary = { high: 0, medium: 0, low: 0, suppressed: 0 };
          for (const finding of findings)
            if (suppressions.has(finding.id)) summary.suppressed++;
            else summary[finding.severity]++;
          return { generatedAt: now, dormantDays, summary, findings: annotated };
        },
      ),
    /**
     * Lints a candidate `document` or a stored policy (`policyId`, exactly one of the two): validation as storage
     * applies it (unknown actions and resource types included) plus warnings about grants broader than intended and
     * conditions that never match or fail open. A document storage would reject is reported without warnings.
     * `contextKeys` names keys the application supplies through resolveContext. Requires iam:policies:read on the
     * policy (or the tenant, for a candidate document).
     */
    lintPolicy: async (
      credential: CredentialInput,
      input: { tenantId: string; document?: unknown; policyId?: string; contextKeys?: string[] },
    ): Promise<PolicyLintResult> => {
      if ((input?.document === undefined) === (input?.policyId === undefined))
        throw new IamError('INVALID_INPUT', 'Provide either a document or a policyId');
      const policyId = input.policyId === undefined ? undefined : text(input.policyId, 'policyId');
      const contextKeys =
        input.contextKeys === undefined ? undefined : strings(input.contextKeys, 'contextKeys');
      return operation(
        credential,
        input.tenantId,
        'iam:policies:read',
        policyId ?? input.tenantId,
        async ({ tx, tenant }) => {
          const document =
            policyId === undefined
              ? input.document
              : (await ctx.scoped<Policy>(tx, 'policies', policyId, tenant.id)).document;
          // Validation first: it rejects unknown actions and resource types cheaply, before any pattern matching.
          try {
            await ctx.catalog.validate(tx, tenant.id, document as PolicyDocument);
          } catch (error) {
            if (!(error instanceof IamError)) throw error;
            return {
              valid: false,
              error: { code: error.code, message: error.message },
              warnings: [],
            };
          }
          return lintPolicy(document, {
            ...(await lintContext(tx, tenant.id)),
            ...(contextKeys ? { contextKeys } : {}),
          });
        },
      );
    },
    /**
     * Hides one finding the scan reports now from future results, with a reason kept for reviewers, for as long as
     * the finding stays as it is (same severity and detail); if it changes, it shows again. `dormantDays` (default 90)
     * must match the window the finding was listed with. Requires iam:analysis:update.
     */
    suppress: (
      credential: CredentialInput,
      input: { tenantId: string; findingId: string; reason: string; dormantDays?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:analysis:update',
        `analysis/${text(input.findingId, 'findingId', 64)}`,
        async ({ tx, tenant, principal }) => {
          if (!/^[0-9a-f]{24}$/.test(input.findingId))
            throw new IamError('INVALID_INPUT', 'Unknown finding ID');
          const reason = text(input.reason, 'reason', 500).trim();
          const dormantDays = integer(input.dormantDays ?? 90, 'dormantDays', 1, 3650);
          // Only a finding reported now can be accepted, and only as it is now: a predictable ID alone is not enough.
          const current = (await scan(tx, tenant, dormantDays)).fingerprints.get(input.findingId);
          if (current === undefined)
            throw new IamError(
              'INVALID_INPUT',
              'Unknown finding ID: only a finding reported now can be suppressed',
            );
          const record: Suppression = {
            id: suppressionId(input.tenantId, input.findingId),
            tenantId: input.tenantId,
            findingId: input.findingId,
            reason,
            createdBy: principal.identity.id,
            createdAt: ctx.now(),
            fingerprint: current,
          };
          await ((await tx.get('analysisSuppressions', record.id))
            ? tx.put('analysisSuppressions', record)
            : tx.insert('analysisSuppressions', record));
          return { suppressed: true };
        },
      ),
    /** Shows a suppressed finding again. Requires iam:analysis:update. */
    unsuppress: (credential: CredentialInput, input: { tenantId: string; findingId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:analysis:update',
        `analysis/${text(input.findingId, 'findingId', 64)}`,
        async ({ tx }) => {
          const id = suppressionId(input.tenantId, input.findingId);
          if (await tx.get('analysisSuppressions', id)) await tx.delete('analysisSuppressions', id);
          return { suppressed: false };
        },
      ),
  };
}
