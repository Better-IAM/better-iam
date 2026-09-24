import {
  IamError,
  findOrdered,
  matchPattern,
  verifyAuditChain,
  type AuditChainHead,
  type AuditEvent,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Session,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { CertificationCampaign, CertificationItem } from './api/certifications.js';
import type { ServerContext } from './context.js';
import type { Binding, BindingActivation, GroupMember, Policy, Role, Trust } from './models.js';
import { requestOverdue, type SubjectRequest } from './privacy.js';
import { sodViolations } from './sod.js';
import { integer } from './validation.js';

/**
 * The compliance center: automated checks over the IAM state (who has MFA, stale access, reviews, leavers, privileged
 * access, audit integrity, ...), mapped to the requirements of common frameworks. Tenants turn checks into controls,
 * evaluate them on a schedule, record exceptions with an expiry, and export signed evidence.
 *
 * Checks only read, and they read outside any transaction (`ctx.store`), so an evaluation never holds the store's
 * write lock while it walks a large tenant; only the results are written, in one short transaction. Findings name
 * their subject by ID (`identity:{id}`); names are looked up when results are read, so stored results carry no
 * personal data beyond pseudonymous IDs.
 */

export type CheckStatus = 'pass' | 'fail' | 'warn' | 'not-applicable';
export interface CheckFinding {
  /**
   * What the finding is about, specific enough that an exception covers only this finding: `identity:{id}`,
   * `identity:{id}:rule:{ruleId}`, `session:{id}`, `trust:{id}`, `role:{id}`, `campaign:{id}`, `request:{id}`, or
   * `tenant:{id}:{condition}` for organization-wide settings.
   */
  subject: string;
  /** Plain text without names; readers with directory access see the subject's name next to it. */
  detail: string;
}
export interface CheckOutcome {
  findings: CheckFinding[];
  metrics: Record<string, number>;
  /** The status given the findings that no exception covers. */
  judge(remaining: CheckFinding[]): { status: CheckStatus; summary: string };
  /** Audit verification progress to store (audit-integrity only). */
  checkpoint?: { sequence: number; hash: string };
}
export interface CheckParam {
  name: string;
  description: string;
  default: number;
  min: number;
  max: number;
}
export interface ComplianceCheck {
  id: string;
  title: string;
  description: string;
  params: CheckParam[];
  /** Exceptions may not cover this check's findings (a broken audit chain cannot be accepted). */
  noExceptions?: boolean;
  /** `store` is read outside any transaction. */
  evaluate(
    ctx: ServerContext,
    store: IamStore,
    tenant: Tenant,
    params: Record<string, number>,
    now: number,
  ): Promise<CheckOutcome>;
}

const dayMs = 86_400_000;
const hourMs = 3_600_000;
/** Audit events verified per evaluation (the rest continue from the checkpoint on the next run). */
const auditPageSize = 2_000;
const auditPages = 50;
const plural = (count: number, word: string) => `${count} ${word}${count === 1 ? '' : 's'}`;

/** Active, unexpired people. */
async function people(ctx: ServerContext, store: IamStore, tenantId: string): Promise<Identity[]> {
  return (await store.find<Identity>('identities', { tenantId })).filter(
    (identity) =>
      identity.kind === 'user' && identity.status === 'active' && !ctx.identityExpired(identity),
  );
}
const countJudge =
  (what: string, fine: string) =>
  (remaining: CheckFinding[]): { status: CheckStatus; summary: string } =>
    remaining.length === 0
      ? { status: 'pass', summary: fine }
      : {
          status: 'fail',
          summary: `${plural(remaining.length, what)} need${remaining.length === 1 ? 's' : ''} attention`,
        };

/** Actions that together amount to administering a tenant: whoever may do all of them can grant themselves anything. */
const adminProbes = ['iam:bindings:create', 'iam:roles:update', 'iam:policies:update'];
function safeMatch(pattern: string, value: string): boolean {
  try {
    return matchPattern(pattern, value);
  } catch {
    return false;
  }
}
/**
 * Whether documents allow administering the tenant: one allow statement covering every admin probe action on the
 * tenant's resource. Conditions are ignored on purpose: a condition (MFA, network, time) changes when someone may act,
 * not who holds the power.
 */
export function administers(
  documents: Array<PolicyDocument | undefined>,
  tenantId: string,
): boolean {
  const resource = `iam/${tenantId}`;
  return documents.some((document) =>
    (document?.statements ?? []).some(
      (statement) =>
        statement.effect === 'allow' &&
        adminProbes.every((probe) =>
          statement.actions.some((action) => safeMatch(action, probe)),
        ) &&
        statement.resources.some((pattern) => safeMatch(pattern, resource)),
    ),
  );
}

/**
 * Who holds full administration, by any path: owners and root administrators; live bindings (direct or through a
 * group) to a role that administers the tenant itself or through the roles it inherits; eligible bindings to such a
 * role while activated or when activation needs no approval; and trusts that let an identity or workload assume one.
 */
async function privilegedHolders(
  ctx: ServerContext,
  store: IamStore,
  tenantId: string,
  now: number,
): Promise<{ holders: Map<string, string>; eligibleWithApproval: number }> {
  const holders = new Map<string, string>();
  const everyone = (await store.find<Identity>('identities', { tenantId })).filter(
    (identity) => identity.status === 'active' && !ctx.identityExpired(identity),
  );
  for (const identity of everyone)
    if (identity.owner || identity.rootAdmin)
      holders.set(`identity:${identity.id}`, identity.rootAdmin ? 'root administrator' : 'owner');
  const policies = new Map(
    (await store.find<Policy>('policies', { tenantId })).map((policy) => [policy.id, policy]),
  );
  const roles = new Map(
    (await store.find<Role>('roles', { tenantId })).map((role) => [role.id, role]),
  );
  const own = (role: Role) => [
    role.document,
    ...(role.policyIds ?? []).map((policyId) => policies.get(policyId)?.document),
  ];
  // A role administers if it or any role it inherits (as decisions.ts follows them) does.
  const adminRoles = new Map<string, string>();
  for (const role of roles.values()) {
    const seen = new Set<string>([role.id]);
    const queue = [role];
    while (queue.length && seen.size <= 256) {
      const current = queue.shift()!;
      if (administers(own(current), tenantId)) {
        adminRoles.set(
          role.id,
          current.id === role.id ? role.name : `${role.name}, through ${current.name}`,
        );
        break;
      }
      for (const inheritedId of current.inherits ?? []) {
        const inherited = roles.get(inheritedId);
        if (!inherited || inherited.protected || seen.has(inheritedId)) continue;
        seen.add(inheritedId);
        queue.push(inherited);
      }
    }
  }
  let eligibleWithApproval = 0;
  if (!adminRoles.size) return { holders, eligibleWithApproval };
  const members = new Map<string, string[]>();
  for (const member of await store.find<GroupMember>('groupMembers', { tenantId }))
    if (member.expiresAt === undefined || member.expiresAt > now)
      members.set(member.groupId, [...(members.get(member.groupId) ?? []), member.identityId]);
  const activations = (
    await store.find<BindingActivation>('bindingActivations', { tenantId })
  ).filter(
    (activation) =>
      activation.status !== 'pending' &&
      activation.status !== 'denied' &&
      activation.expiresAt > now,
  );
  const active = new Set(everyone.map((identity) => identity.id));
  for (const binding of await store.find<Binding>('bindings', { tenantId })) {
    const role = adminRoles.get(binding.roleId);
    if (!role) continue;
    if (binding.startsAt !== undefined && binding.startsAt > now) continue;
    if (binding.expiresAt !== undefined && binding.expiresAt <= now) continue;
    const subjects =
      binding.subjectType === 'identity'
        ? [binding.subjectId]
        : (members.get(binding.subjectId) ?? []);
    for (const subject of subjects) {
      if (!active.has(subject) || holders.has(`identity:${subject}`)) continue;
      if (!binding.eligible) holders.set(`identity:${subject}`, `role ${role}`);
      else if (
        activations.some((item) => item.bindingId === binding.id && item.identityId === subject)
      )
        holders.set(`identity:${subject}`, `role ${role}, activated`);
      else if (!binding.requireApproval)
        holders.set(`identity:${subject}`, `role ${role}, eligible without approval`);
      else eligibleWithApproval++;
    }
  }
  for (const trust of await store.find<Trust>('trusts', { tenantId })) {
    const role = adminRoles.get(trust.roleId);
    if (!role || trust.revoked) continue;
    holders.set(
      `trust:${trust.id}`,
      trust.kind === 'web-identity'
        ? `a workload federation trust assumes role ${role}`
        : trust.sourceTenantId === tenantId
          ? `a trust lets identity ${trust.sourceIdentityId} assume role ${role}`
          : `a trust lets identity ${trust.sourceIdentityId} of tenant ${trust.sourceTenantId} assume role ${role}`,
    );
  }
  return { holders, eligibleWithApproval };
}

/** The built-in checks. */
export const complianceChecks: readonly ComplianceCheck[] = [
  {
    id: 'mfa-enforced',
    title: 'Multi-factor authentication is required',
    description:
      'The organization’s sign-in policy requires a second factor for everyone (requireMfa).',
    params: [],
    async evaluate(_ctx, _store, tenant) {
      const policy = tenant.authPolicy;
      const findings: CheckFinding[] = policy?.requireMfa
        ? []
        : policy?.requireMfaForOwners
          ? [
              {
                subject: `tenant:${tenant.id}:mfa-owners-only`,
                detail: 'Only owners must use a second factor',
              },
            ]
          : [
              {
                subject: `tenant:${tenant.id}:mfa-optional`,
                detail: 'The sign-in policy does not require a second factor',
              },
            ];
      return {
        findings,
        metrics: { required: policy?.requireMfa ? 1 : 0 },
        judge: (remaining) =>
          remaining.length === 0
            ? {
                status: 'pass',
                summary: policy?.requireMfa
                  ? 'Everyone must use a second factor'
                  : 'Accepted by exception',
              }
            : policy?.requireMfaForOwners
              ? { status: 'warn', summary: 'Only owners must use a second factor' }
              : { status: 'fail', summary: 'A second factor is optional' },
      };
    },
  },
  {
    id: 'mfa-coverage',
    title: 'People have a second factor',
    description:
      'The share of active people with an authenticator app, or a passkey where the deployment accepts passkeys as a second factor.',
    params: [
      {
        name: 'minimumPercent',
        description: 'Share of people that must be enrolled',
        default: 100,
        min: 50,
        max: 100,
      },
    ],
    async evaluate(ctx, store, tenant, params) {
      const list = await people(ctx, store, tenant.id);
      // Passkeys satisfy MFA only when the deployment enables them (auth base.ts passkeyFactor).
      const withPasskeys = ctx.options.authentication?.passkeys
        ? new Set(
            (
              await store.find<{ identityId: string } & StoredRecord>('authPasskeys', {
                tenantId: tenant.id,
              })
            ).map((passkey) => passkey.identityId),
          )
        : new Set<string>();
      const findings: CheckFinding[] = [];
      for (const person of list) {
        const mfa = await store.get<{ enabled?: boolean } & StoredRecord>('authMfa', person.id);
        if (!mfa?.enabled && !withPasskeys.has(person.id))
          findings.push({ subject: `identity:${person.id}`, detail: 'Has no second factor' });
      }
      const total = list.length;
      return {
        findings,
        metrics: { people: total, enrolled: total - findings.length },
        judge: (remaining) => {
          const percent = total ? Math.floor(((total - remaining.length) / total) * 100) : 100;
          return percent >= params.minimumPercent!
            ? { status: 'pass', summary: `${percent}% of people have a second factor` }
            : {
                status: 'fail',
                summary: `${percent}% of people have a second factor (at least ${params.minimumPercent}% required)`,
              };
        },
      };
    },
  },
  {
    id: 'password-length',
    title: 'Passwords are long enough',
    description:
      'The minimum password length the organization enforces (never below 12, the deployment’s floor), or passwords are not allowed at all.',
    params: [
      { name: 'minimum', description: 'Required minimum length', default: 12, min: 8, max: 64 },
    ],
    async evaluate(_ctx, _store, tenant, params) {
      const policy = tenant.authPolicy;
      const passwordless =
        policy?.allowedMethods !== undefined && !policy.allowedMethods.includes('password');
      const length = Math.max(12, policy?.minPasswordLength ?? 12);
      const ok = passwordless || length >= params.minimum!;
      return {
        findings: ok
          ? []
          : [
              {
                subject: `tenant:${tenant.id}:password-length-${length}`,
                detail: `Passwords may be ${length} characters long`,
              },
            ],
        metrics: { minimumLength: length, passwordless: passwordless ? 1 : 0 },
        judge: (remaining) =>
          remaining.length === 0
            ? {
                status: 'pass',
                summary: passwordless
                  ? 'Passwords are not used'
                  : ok
                    ? `Passwords need ${length} characters`
                    : 'Accepted by exception',
              }
            : {
                status: 'fail',
                summary: `Passwords need only ${length} characters (${params.minimum} required)`,
              },
      };
    },
  },
  {
    id: 'session-lifetime',
    title: 'Sessions end',
    description: 'Sessions end within a maximum lifetime and after a period of inactivity.',
    params: [
      { name: 'maxHours', description: 'Longest session', default: 24 * 7, min: 1, max: 24 * 30 },
      {
        name: 'idleMinutes',
        description: 'Longest inactivity before sign-out',
        default: 24 * 60,
        min: 5,
        max: 24 * 60 * 7,
      },
    ],
    async evaluate(ctx, _store, tenant, params) {
      const auth = ctx.options.authentication;
      const lifetime = Math.min(
        auth?.sessionLifetimeMs ?? 7 * 24 * hourMs,
        tenant.authPolicy?.sessionLifetimeMs ?? Infinity,
      );
      const idle = Math.min(
        auth?.sessionIdleTimeoutMs ?? Math.min(lifetime, 24 * hourMs),
        tenant.authPolicy?.sessionIdleTimeoutMs ?? Infinity,
      );
      const hours = Math.round(lifetime / hourMs);
      const minutes = Math.round(idle / 60_000);
      const findings: CheckFinding[] = [];
      if (lifetime > params.maxHours! * hourMs)
        findings.push({
          subject: `tenant:${tenant.id}:lifetime-${hours}h`,
          detail: `Sessions last ${hours} hours`,
        });
      if (idle > params.idleMinutes! * 60_000)
        findings.push({
          subject: `tenant:${tenant.id}:idle-${minutes}m`,
          detail: `Idle sessions last ${minutes} minutes`,
        });
      return {
        findings,
        metrics: { lifetimeHours: hours, idleMinutes: minutes },
        judge: countJudge('session limit', 'Sessions end on time'),
      };
    },
  },
  {
    id: 'inactive-accounts',
    title: 'Inactive accounts are removed',
    description:
      'Active people who have not signed in for a while (their access should be reviewed or removed).',
    params: [
      { name: 'days', description: 'Days without a sign-in', default: 90, min: 7, max: 730 },
    ],
    async evaluate(ctx, store, tenant, params, now) {
      const cutoff = now - params.days! * dayMs;
      const findings: CheckFinding[] = [];
      for (const person of await people(ctx, store, tenant.id)) {
        if (person.createdAt > cutoff) continue;
        const record = await store.get<{ lastAt?: number } & StoredRecord>(
          'authSignIns',
          person.id,
        );
        const last = record?.lastAt;
        if (last === undefined || last < cutoff)
          findings.push({
            subject: `identity:${person.id}`,
            detail: last
              ? `Last signed in ${Math.floor((now - last) / dayMs)} days ago`
              : 'Has never signed in',
          });
      }
      return {
        findings,
        metrics: { inactive: findings.length },
        judge: countJudge('inactive account', `Everyone signed in within ${params.days} days`),
      };
    },
  },
  {
    id: 'leaver-access',
    title: 'Leavers lose access',
    description:
      'Disabled or expired accounts hold no live sessions, API keys, role bindings or group memberships.',
    params: [],
    async evaluate(ctx, store, tenant, _params, now) {
      const findings: CheckFinding[] = [];
      for (const identity of await store.find<Identity>('identities', { tenantId: tenant.id })) {
        const leaving =
          identity.status === 'disabled' ||
          (identity.status === 'active' && ctx.identityExpired(identity));
        if (!leaving) continue;
        const sessions = (
          await store.find<Session>('sessions', { tenantId: tenant.id, identityId: identity.id })
        ).filter((session) => session.expiresAt > now).length;
        const bindings = (
          await store.find<Binding>('bindings', {
            tenantId: tenant.id,
            subjectType: 'identity',
            subjectId: identity.id,
          })
        ).filter((binding) => binding.expiresAt === undefined || binding.expiresAt > now).length;
        const groups = (
          await store.find<GroupMember>('groupMembers', {
            tenantId: tenant.id,
            identityId: identity.id,
          })
        ).filter((member) => member.expiresAt === undefined || member.expiresAt > now).length;
        if (sessions || bindings || groups)
          findings.push({
            subject: `identity:${identity.id}`,
            detail: `${identity.status === 'disabled' ? 'Disabled' : 'Expired'} but still holds ${[
              sessions ? plural(sessions, 'session') : '',
              bindings ? plural(bindings, 'role binding') : '',
              groups ? plural(groups, 'group membership') : '',
            ]
              .filter(Boolean)
              .join(', ')}`,
          });
      }
      return {
        findings,
        metrics: { leaversWithAccess: findings.length },
        judge: countJudge('leaver with access', 'Disabled and expired accounts hold no access'),
      };
    },
  },
  {
    id: 'stale-api-keys',
    title: 'Unused API keys are revoked',
    description: 'Live API keys (service accounts and agents) that have not been used for a while.',
    params: [{ name: 'days', description: 'Days without use', default: 90, min: 7, max: 730 }],
    async evaluate(_ctx, store, tenant, params, now) {
      const cutoff = now - params.days! * dayMs;
      const findings: CheckFinding[] = [];
      for (const session of await store.find<Session>('sessions', {
        tenantId: tenant.id,
        kind: 'api-key',
      })) {
        if (session.expiresAt <= now) continue;
        const last = session.lastSeenAt ?? session.createdAt;
        if (last < cutoff)
          findings.push({
            subject: `session:${session.id}`,
            detail: `${session.name ? `Key "${session.name}"` : 'An API key'} unused for ${Math.floor((now - last) / dayMs)} days`,
          });
      }
      return {
        findings,
        metrics: { staleKeys: findings.length },
        judge: countJudge('unused API key', `Every API key was used within ${params.days} days`),
      };
    },
  },
  {
    id: 'api-key-lifetime',
    title: 'API keys expire',
    description: 'Live API keys whose lifetime exceeds the maximum.',
    params: [
      { name: 'maxDays', description: 'Longest API key lifetime', default: 365, min: 1, max: 3650 },
    ],
    async evaluate(_ctx, store, tenant, params, now) {
      const findings: CheckFinding[] = [];
      for (const session of await store.find<Session>('sessions', {
        tenantId: tenant.id,
        kind: 'api-key',
      })) {
        if (session.expiresAt <= now) continue;
        const days = Math.floor((session.expiresAt - session.createdAt) / dayMs);
        if (days > params.maxDays!)
          findings.push({
            subject: `session:${session.id}`,
            detail: `${session.name ? `Key "${session.name}"` : 'An API key'} lives ${days} days`,
          });
      }
      return {
        findings,
        metrics: { longLivedKeys: findings.length },
        judge: countJudge(
          'long-lived API key',
          `Every API key expires within ${params.maxDays} days`,
        ),
      };
    },
  },
  {
    id: 'access-reviews',
    title: 'Access is reviewed periodically',
    description:
      'Within the interval, closed certification campaigns in which reviewers decided most items covered the roles people hold; no campaign is overdue. Campaigns closed with few human decisions do not count.',
    params: [
      {
        name: 'intervalDays',
        description: 'Longest time between completed reviews',
        default: 90,
        min: 7,
        max: 730,
      },
      {
        name: 'minDecidedPercent',
        description: 'Share of a campaign’s items a reviewer must decide for it to count',
        default: 80,
        min: 50,
        max: 100,
      },
      {
        name: 'minCoveragePercent',
        description: 'Share of the roles held today that counted reviews must have covered',
        default: 100,
        min: 50,
        max: 100,
      },
    ],
    async evaluate(_ctx, store, tenant, params, now) {
      const since = now - params.intervalDays! * dayMs;
      const campaigns = await store.find<CertificationCampaign>('certificationCampaigns', {
        tenantId: tenant.id,
      });
      const findings: CheckFinding[] = [];
      // Roles covered by campaigns that count: closed within the interval, not empty, mostly decided by people.
      const covered = new Set<string>();
      let qualifying = 0;
      let latestQualifying = 0;
      let latestClosed = 0;
      let lastDecidedPercent = -1;
      for (const campaign of campaigns) {
        if (
          campaign.status !== 'closed' ||
          campaign.closedAt === undefined ||
          campaign.closedAt < since
        )
          continue;
        const items = await store.find<CertificationItem>('certificationItems', {
          tenantId: tenant.id,
          campaignId: campaign.id,
        });
        const decided = items.filter((item) => item.decidedBy !== undefined).length;
        const percent = items.length ? Math.floor((decided / items.length) * 100) : 0;
        if (campaign.closedAt >= latestClosed) {
          latestClosed = campaign.closedAt;
          lastDecidedPercent = percent;
        }
        if (!items.length || percent < params.minDecidedPercent!) continue;
        qualifying++;
        latestQualifying = Math.max(latestQualifying, campaign.closedAt);
        for (const item of items) covered.add(item.roleId);
      }
      if (!qualifying)
        findings.push({
          subject: `tenant:${tenant.id}:no-review`,
          detail: `No review closed in the last ${params.intervalDays} days with at least ${params.minDecidedPercent}% of its items decided by a reviewer`,
        });
      // Roles held today (live bindings to unprotected roles); owners are the owner-redundancy and privileged checks'.
      const roles = new Map(
        (await store.find<Role>('roles', { tenantId: tenant.id }))
          .filter((role) => !role.protected)
          .map((role) => [role.id, role]),
      );
      const held = new Set<string>();
      for (const binding of await store.find<Binding>('bindings', { tenantId: tenant.id }))
        if (
          roles.has(binding.roleId) &&
          (binding.expiresAt === undefined || binding.expiresAt > now)
        )
          held.add(binding.roleId);
      const uncovered = [...held].filter((roleId) => !covered.has(roleId)).sort();
      if (qualifying)
        for (const roleId of uncovered)
          findings.push({
            subject: `role:${roleId}`,
            detail: `Role "${roles.get(roleId)!.name}" is held but no counted review covered it`,
          });
      for (const campaign of campaigns)
        if (campaign.status === 'open' && campaign.dueAt !== undefined && campaign.dueAt < now)
          findings.push({
            subject: `campaign:${campaign.id}`,
            detail: `Review "${campaign.name}" is ${Math.floor((now - campaign.dueAt) / dayMs)} days overdue`,
          });
      const coverage = held.size
        ? Math.floor(((held.size - uncovered.length) / held.size) * 100)
        : 100;
      return {
        findings,
        metrics: {
          campaigns: campaigns.length,
          qualifying,
          rolesHeld: held.size,
          coveragePercent: coverage,
          lastDecidedPercent,
          lastClosedDaysAgo: latestQualifying ? Math.floor((now - latestQualifying) / dayMs) : -1,
        },
        judge: (remaining) => {
          const noReview = remaining.some((finding) => finding.subject.endsWith(':no-review'));
          const overdue = remaining.filter((finding) =>
            finding.subject.startsWith('campaign:'),
          ).length;
          const missing = remaining.filter((finding) => finding.subject.startsWith('role:')).length;
          const percent = held.size ? Math.floor(((held.size - missing) / held.size) * 100) : 100;
          if (noReview) return { status: 'fail', summary: 'No counted review within the interval' };
          if (percent < params.minCoveragePercent!)
            return {
              status: 'fail',
              summary: `Reviews covered ${percent}% of the roles held (${params.minCoveragePercent}% required)`,
            };
          if (overdue) return { status: 'fail', summary: `${plural(overdue, 'review')} overdue` };
          return {
            status: 'pass',
            summary: `Access was reviewed within ${params.intervalDays} days (${percent}% of roles)`,
          };
        },
      };
    },
  },
  {
    id: 'privileged-access',
    title: 'Few people hold full administration',
    description:
      'Everyone who can administer the organization — owners, root administrators, holders of admin roles (also through inherited roles, activated or approval-free eligible bindings) and trusts that assume them — against a maximum.',
    params: [
      {
        name: 'maxHolders',
        description: 'Most people with full administration',
        default: 5,
        min: 1,
        max: 1000,
      },
    ],
    async evaluate(ctx, store, tenant, params, now) {
      const { holders, eligibleWithApproval } = await privilegedHolders(ctx, store, tenant.id, now);
      const findings: CheckFinding[] = [...holders].map(([subject, via]) => ({
        subject,
        detail: `Holds full administration (${via})`,
      }));
      return {
        findings,
        metrics: { holders: holders.size, eligibleWithApproval },
        judge: (remaining) =>
          remaining.length <= params.maxHolders!
            ? {
                status: 'pass',
                summary: `${plural(remaining.length, 'holder')} of full administration`,
              }
            : {
                status: 'fail',
                summary: `${plural(remaining.length, 'holder')} of full administration (at most ${params.maxHolders})`,
              },
      };
    },
  },
  {
    id: 'owner-redundancy',
    title: 'More than one owner',
    description:
      'At least two active owners, so losing one account does not lock the organization out.',
    params: [],
    async evaluate(ctx, store, tenant) {
      const owners = (await people(ctx, store, tenant.id)).filter((identity) => identity.owner);
      return {
        findings:
          owners.length >= 2
            ? []
            : [
                {
                  subject: `tenant:${tenant.id}:owners-${owners.length}`,
                  detail: plural(owners.length, 'active owner'),
                },
              ],
        metrics: { owners: owners.length },
        judge: (remaining) =>
          remaining.length === 0
            ? {
                status: 'pass',
                summary: owners.length >= 2 ? `${owners.length} owners` : 'Accepted by exception',
              }
            : {
                status: owners.length ? 'warn' : 'fail',
                summary: owners.length ? 'Only one owner' : 'No active owner',
              },
      };
    },
  },
  {
    id: 'separation-of-duties',
    title: 'Separation of duties holds',
    description:
      'Nobody holds two roles a separation-of-duties rule keeps apart. Without any rule the check warns.',
    params: [],
    async evaluate(ctx, store, tenant): Promise<CheckOutcome> {
      const rules = await store.find('sodRules', { tenantId: tenant.id });
      if (!rules.length)
        return {
          findings: [],
          metrics: { rules: 0 },
          // Frameworks that map here (ISO 5.3, NIST AC-5) expect duties to be separated: no rule is not a pass.
          judge: () => ({ status: 'warn', summary: 'No separation-of-duties rules are defined' }),
        };
      const violations = await sodViolations(ctx, store, tenant.id);
      return {
        findings: violations.map((violation) => ({
          subject: `identity:${violation.identityId}:rule:${violation.ruleId}`,
          detail: `Breaks rule "${violation.ruleName}"`,
        })),
        metrics: { rules: rules.length, violations: violations.length },
        judge: countJudge('separation-of-duties violation', 'No separation-of-duties violations'),
      };
    },
  },
  {
    id: 'audit-integrity',
    title: 'The audit log is intact',
    description:
      'The audit hash chain verifies: no event was changed, removed or inserted. Each evaluation continues from where the last one stopped (up to 100,000 events per run) and checks the newest event against the chain head; pruned prefixes must match their audit:prune record.',
    params: [],
    noExceptions: true,
    async evaluate(_ctx, store, tenant) {
      const head = await store.get<AuditChainHead>('auditChains', tenant.id);
      const saved = await store.get<ComplianceCheckpoint>(
        'complianceCheckpoints',
        checkpointId(tenant.id),
      );
      let sequence = saved?.sequence ?? 0;
      let hash = saved?.hash;
      let checked = 0;
      let failure: string | undefined;
      let partial = false;
      const target = head?.sequence ?? 0;
      while (!failure && sequence < target) {
        if (checked >= auditPageSize * auditPages) {
          partial = true;
          break;
        }
        const events = await findOrdered<AuditEvent>(
          store,
          'audit',
          { tenantId: tenant.id },
          { field: 'sequence', from: sequence + 1, to: target, limit: auditPageSize },
        );
        if (!events.length) {
          failure = `Events ${sequence + 1} to ${target} are missing`;
          break;
        }
        const first = events[0]!;
        let previousHash = hash;
        if (first.sequence !== sequence + 1) {
          // A gap is only acceptable as a pruned prefix, which audit:prune recorded with the hash it ended on.
          const pruned = (
            await store.find<AuditEvent>('audit', { tenantId: tenant.id, action: 'audit:prune' })
          ).some(
            (event) =>
              event.metadata?.prunedThroughSequence === first.sequence! - 1 &&
              event.metadata?.prunedThroughHash === first.previousHash,
          );
          if (!pruned) {
            failure = `Events ${sequence + 1} to ${first.sequence! - 1} are missing`;
            break;
          }
          previousHash = first.previousHash;
        }
        const verification = await verifyAuditChain(
          events,
          previousHash === undefined ? {} : { previousHash },
        );
        if (!verification.valid) {
          failure = `The chain breaks at sequence ${verification.failure?.sequence ?? '?'} (${verification.failure?.reason ?? 'unknown'})`;
          break;
        }
        checked += verification.checked;
        sequence = verification.last!;
        hash = verification.lastHash!;
      }
      if (!failure && !partial && head && (sequence !== head.sequence || hash !== head.hash))
        failure = 'The newest event does not match the chain head';
      return {
        findings: failure ? [{ subject: `tenant:${tenant.id}:audit-chain`, detail: failure }] : [],
        metrics: { checked, verifiedThrough: sequence, head: target },
        ...(!failure && hash !== undefined && sequence > 0
          ? { checkpoint: { sequence, hash } }
          : {}),
        judge: (remaining) =>
          remaining.length
            ? { status: 'fail', summary: failure! }
            : partial
              ? {
                  status: 'warn',
                  summary: `Verified through event ${sequence} of ${target}; the next run continues`,
                }
              : { status: 'pass', summary: `The audit chain verifies through event ${sequence}` },
      };
    },
  },
  {
    id: 'privacy-deadlines',
    title: 'Data-subject requests are answered on time',
    description: 'No privacy request (access, erasure, ...) is past its statutory deadline.',
    params: [],
    async evaluate(_ctx, store, tenant, _params, now) {
      const requests = await store.find<SubjectRequest>('privacyRequests', { tenantId: tenant.id });
      const overdue = requests.filter((request) => requestOverdue(request, now));
      return {
        findings: overdue.map((request) => ({
          subject: `request:${request.id}`,
          detail: `${request.number} (${request.type}) was due ${Math.floor((now - request.dueAt!) / dayMs)} days ago`,
        })),
        metrics: { requests: requests.length, overdue: overdue.length },
        judge: countJudge('overdue request', 'No data-subject request is overdue'),
      };
    },
  },
];

export const checkById = new Map(complianceChecks.map((check) => [check.id, check]));

/** A framework requirement and the checks that evidence it. */
export interface FrameworkRequirement {
  id: string;
  title: string;
  checks: string[];
}
export interface ComplianceFramework {
  id: string;
  name: string;
  requirements: FrameworkRequirement[];
}

/** Built-in mappings. They are evidence for these requirements, not the whole of them. */
export const complianceFrameworks: readonly ComplianceFramework[] = [
  {
    id: 'soc2',
    name: 'SOC 2 (Trust Services Criteria)',
    requirements: [
      {
        id: 'CC6.1',
        title: 'Logical access security',
        checks: [
          'mfa-enforced',
          'mfa-coverage',
          'password-length',
          'session-lifetime',
          'api-key-lifetime',
        ],
      },
      {
        id: 'CC6.2',
        title: 'Registration and deregistration of users',
        checks: ['leaver-access', 'inactive-accounts'],
      },
      {
        id: 'CC6.3',
        title: 'Role-based access, least privilege, and access review',
        checks: ['access-reviews', 'privileged-access', 'separation-of-duties', 'stale-api-keys'],
      },
      { id: 'CC7.2', title: 'Monitoring of system components', checks: ['audit-integrity'] },
    ],
  },
  {
    id: 'iso27001',
    name: 'ISO/IEC 27001:2022 Annex A',
    requirements: [
      { id: '5.3', title: 'Segregation of duties', checks: ['separation-of-duties'] },
      { id: '5.16', title: 'Identity management', checks: ['leaver-access', 'inactive-accounts'] },
      {
        id: '5.17',
        title: 'Authentication information',
        checks: ['password-length', 'api-key-lifetime'],
      },
      { id: '5.18', title: 'Access rights', checks: ['access-reviews', 'stale-api-keys'] },
      { id: '5.34', title: 'Privacy and protection of PII', checks: ['privacy-deadlines'] },
      {
        id: '8.2',
        title: 'Privileged access rights',
        checks: ['privileged-access', 'owner-redundancy'],
      },
      {
        id: '8.5',
        title: 'Secure authentication',
        checks: ['mfa-enforced', 'mfa-coverage', 'session-lifetime'],
      },
      { id: '8.15', title: 'Logging', checks: ['audit-integrity'] },
    ],
  },
  {
    id: 'nist-800-53',
    name: 'NIST SP 800-53 Rev. 5',
    requirements: [
      { id: 'AC-2', title: 'Account management', checks: ['leaver-access', 'inactive-accounts'] },
      { id: 'AC-5', title: 'Separation of duties', checks: ['separation-of-duties'] },
      { id: 'AC-6', title: 'Least privilege', checks: ['privileged-access'] },
      { id: 'AC-6(7)', title: 'Review of user privileges', checks: ['access-reviews'] },
      { id: 'AC-12', title: 'Session termination', checks: ['session-lifetime'] },
      {
        id: 'IA-2(1)',
        title: 'Multi-factor authentication',
        checks: ['mfa-enforced', 'mfa-coverage'],
      },
      {
        id: 'IA-5',
        title: 'Authenticator management',
        checks: ['password-length', 'api-key-lifetime', 'stale-api-keys'],
      },
      { id: 'AU-9', title: 'Protection of audit information', checks: ['audit-integrity'] },
    ],
  },
  {
    id: 'gdpr',
    name: 'GDPR (selected articles)',
    requirements: [
      {
        id: 'Art. 12',
        title: 'Responding to data subjects in time',
        checks: ['privacy-deadlines'],
      },
      {
        id: 'Art. 32',
        title: 'Security of processing',
        checks: ['mfa-coverage', 'audit-integrity', 'leaver-access'],
      },
    ],
  },
];
export const frameworkById = new Map(
  complianceFrameworks.map((framework) => [framework.id, framework]),
);

/** Validates check parameters, filling defaults. */
export function checkParams(check: ComplianceCheck, value: unknown): Record<string, number> {
  const input =
    value === undefined || value === null
      ? {}
      : typeof value === 'object' && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : undefined;
  if (!input) throw new IamError('INVALID_INPUT', 'params must be an object');
  for (const key of Object.keys(input))
    if (!check.params.some((param) => param.name === key))
      throw new IamError('INVALID_INPUT', `${check.id} has no parameter ${key}`);
  const result: Record<string, number> = {};
  for (const param of check.params)
    result[param.name] =
      input[param.name] === undefined
        ? param.default
        : integer(input[param.name], `params.${param.name}`, param.min, param.max);
  return result;
}
/** Stored parameters brought within the check's current bounds (bounds tighten over releases). */
export function effectiveParams(
  check: ComplianceCheck,
  stored: Record<string, number>,
): Record<string, number> {
  const result: Record<string, number> = {};
  for (const param of check.params) {
    const value = stored[param.name];
    result[param.name] =
      typeof value === 'number' && Number.isFinite(value)
        ? Math.min(param.max, Math.max(param.min, Math.trunc(value)))
        : param.default;
  }
  return result;
}

/** Tenant state: one control per check (or a custom one), with its framework mappings. */
export interface ComplianceControl extends StoredRecord {
  key: string;
  name: string;
  description?: string;
  checkId: string;
  params: Record<string, number>;
  /** Framework requirements this control evidences, as `framework:requirement` (or free-form references). */
  mappings: string[];
  enabled: boolean;
  lastStatus?: CheckStatus;
  lastEvaluatedAt?: number;
  /** The newest result, so reads never scan the result history. */
  lastResultId?: string;
  createdAt: number;
  updatedAt: number;
}
export interface ComplianceException extends StoredRecord {
  controlKey: string;
  subject: string;
  reason: string;
  expiresAt: number;
  createdBy: string;
  createdAt: number;
  /**
   * `pending` until a second person with `iam:compliance:manage` approves it; only `approved` exceptions cover
   * findings. Absent on exceptions created before approvals, which count as approved. Revoked ones stay as history.
   */
  status?: 'pending' | 'approved' | 'revoked';
  approvedBy?: string;
  approvedAt?: number;
  revokedBy?: string;
  revokedAt?: number;
}
/** Whether an exception covers findings now. */
export const exceptionActive = (exception: ComplianceException, now: number) =>
  (exception.status === undefined || exception.status === 'approved') && exception.expiresAt > now;
export interface ComplianceResult extends StoredRecord {
  runId: string;
  controlId: string;
  controlKey: string;
  checkId: string;
  status: CheckStatus;
  /** The status before exceptions were applied. */
  rawStatus: CheckStatus;
  summary: string;
  metrics: Record<string, number>;
  /** At most 200 findings, the excepted ones marked. */
  findings: Array<CheckFinding & { excepted?: boolean }>;
  findingsTotal: number;
  excepted: number;
  evaluatedAt: number;
  /** Results are kept 400 days (a year of history for an audit period), then the retention sweep removes them. */
  expiresAt?: number;
}
export interface ComplianceRun extends StoredRecord {
  evaluatedAt: number;
  counts: Record<CheckStatus, number>;
  /** SHA-256 of the run's results (canonical JSON), also recorded in the audit chain. */
  digest: string;
  triggeredBy: string;
  expiresAt?: number;
}
/** How far the audit-integrity check has verified a tenant's chain (`complianceCheckpoints`, ID `audit:{tenantId}`). */
export interface ComplianceCheckpoint extends StoredRecord {
  sequence: number;
  hash: string;
  verifiedAt: number;
}
export const checkpointId = (tenantId: string) => `audit:${tenantId}`;
