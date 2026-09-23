import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { loadDepartment, type Department } from '../departments.js';
import { invariantSnapshot, invariantVerify } from '../invariants.js';
import type { Binding, Group, GroupMember, Role } from '../models.js';
import type { MutationContext } from '../operations.js';
import { sodSnapshot, sodVerify } from '../sod.js';
import {
  isTeamMaintainer,
  liveTeamMember,
  loadTeam,
  maxTeamDepth,
  maxTeams,
  slugFromName,
  syncTeamGroups,
  syncTeamsFromGroups,
  teamChain,
  teamCollections,
  teamDescendants,
  teamMaintainers,
  teamSlug,
  teamSyncGroups,
  teamsOf,
  type TeamGroupSyncResult,
  type Team,
  type TeamJoinPolicy,
  type TeamJoinRequest,
  type TeamJoinRequestStatus,
  type TeamMember,
  type TeamMemberManagement,
  type TeamRole,
  type TeamSyncResult,
} from '../teams.js';
import {
  birthrightOptions,
  suggestBirthright,
  type BirthrightSuggestion,
} from '../org-insights.js';
import { packagesNaming } from '../org-rules.js';
import {
  completeTeamReview,
  defaultReviewMs,
  maxReviewMs,
  minReviewMs,
  teamReviewCollections,
  type TeamReview,
  type TeamReviewDecision,
  type TeamReviewItem,
  type TeamReviewOutcome,
  type TeamReviewStatus,
} from '../team-reviews.js';
import { actsInOwnRight } from '../session-kinds.js';
import { id } from '../utils.js';
import { integer, strings, text } from '../validation.js';
import { createGroup, deleteGroup } from './groups.js';
import { afterIdentityChange } from './package-automation.js';

export interface TeamInput {
  tenantId: string;
  name: string;
  /** Defaults to one derived from the name. */
  slug?: string;
  description?: string;
  parentId?: string;
  departmentId?: string;
  joinPolicy?: TeamJoinPolicy;
  memberManagement?: TeamMemberManagement;
  /** Up to 20 people made maintainers of the new team. */
  maintainerIds?: string[];
  /** Team sync: up to 10 ordinary groups whose members are kept as members of the team. */
  syncGroupIds?: string[];
}
export interface TeamUpdate {
  tenantId: string;
  teamId: string;
  name?: string;
  slug?: string;
  /** An empty string or null clears it. */
  description?: string | null;
  /** null makes it a top-level team. */
  parentId?: string | null;
  departmentId?: string | null;
  joinPolicy?: TeamJoinPolicy;
  memberManagement?: TeamMemberManagement;
  /** Team sync sources; null or an empty list stops syncing and removes the synced members. */
  syncGroupIds?: string[] | null;
}
/** A team as lists return it. */
export interface TeamSummary {
  id: string;
  tenantId: string;
  name: string;
  slug: string;
  description?: string;
  parentId?: string;
  departmentId?: string;
  groupId: string;
  joinPolicy: TeamJoinPolicy;
  memberManagement: TeamMemberManagement;
  /** Team sync sources, when the team syncs its members from groups. */
  syncGroupIds?: string[];
  /** Live direct members. */
  memberCount: number;
  maintainerCount: number;
  childCount: number;
  createdAt: number;
  updatedAt: number;
}
export interface TeamRef {
  id: string;
  name: string;
  slug: string;
}
export interface TeamPerson {
  id: string;
  name: string;
  email?: string;
  status: Identity['status'];
}
/** A role the team's members hold through the team or a team above it. */
export interface TeamRoleGrant {
  bindingId: string;
  roleId: string;
  roleName: string;
  /** The team whose backing group holds the binding. */
  team: TeamRef;
  /** True when the binding belongs to a team above this one. */
  inherited: boolean;
  eligible?: boolean;
  startsAt?: number;
  expiresAt?: number;
}
export interface TeamDetail extends TeamSummary {
  /** Teams above this one, top first. */
  path: TeamRef[];
  children: Array<TeamRef & { memberCount: number }>;
  department?: { id: string; name: string; code?: string };
  maintainers: TeamPerson[];
  /** Everyone in the backing group: members of this team and of every team below it. */
  totalMemberCount: number;
  roles: TeamRoleGrant[];
  /** The groups team sync keeps the membership in step with. */
  syncGroups: Array<{ id: string; name: string }>;
}
export interface TeamMemberView extends TeamPerson {
  role: TeamRole;
  /** The team the person belongs to directly (this team, or a team below it with `includeChildTeams`). */
  team: TeamRef;
  addedAt: number;
  addedBy: string;
  expiresAt?: number;
  /** `sync` for members team sync manages (they come and go with the source groups). */
  source?: 'sync';
}
export interface TeamJoinRequestView {
  id: string;
  team: TeamRef;
  requester: TeamPerson;
  status: TeamJoinRequestStatus;
  requestedAt: number;
  expiresAt: number;
  justification?: string;
  decidedBy?: string;
  decidedAt?: number;
  note?: string;
}
export interface MyTeams {
  teams: Array<
    TeamRef & {
      description?: string;
      role: TeamRole;
      expiresAt?: number;
      /** Teams above it, whose access the membership also brings. */
      parents: TeamRef[];
    }
  >;
  requests: TeamJoinRequestView[];
  /** Teams that take join requests and that the person is not in. */
  joinable: Array<TeamRef & { description?: string; memberCount: number }>;
  /** Open membership reviews of teams the person maintains (directly or through a team above). */
  reviews: Array<{ id: string; team: TeamRef; dueAt: number; undecided: number }>;
}
/** One person under a membership review. */
export interface TeamReviewItemView {
  person: TeamPerson;
  role: TeamRole;
  decision?: TeamReviewDecision;
  decidedBy?: TeamPerson;
  decidedAt?: number;
  note?: string;
}
/** A membership review; `items` in `getReview`, `startReview`, `decideReview`, and `completeReview`. */
export interface TeamReviewView {
  id: string;
  team: TeamRef;
  status: TeamReviewStatus;
  onUndecided: TeamReviewDecision;
  startedAt: number;
  startedBy: TeamPerson;
  dueAt: number;
  note?: string;
  completedAt?: number;
  completedBy?: string;
  outcome?: TeamReviewOutcome;
  counts: { total: number; keep: number; remove: number; undecided: number };
  items?: TeamReviewItemView[];
}

/** How long a join request waits for a maintainer (fourteen days). */
const joinRequestLifetimeMs = 14 * 86_400_000;
const maxMaintainersOnCreate = 20;
const joinPolicies: readonly TeamJoinPolicy[] = ['closed', 'request'];
const managementModes: readonly TeamMemberManagement[] = ['maintainers', 'admins'];
const teamRoles: readonly TeamRole[] = ['maintainer', 'member'];
const reviewDecisions: readonly TeamReviewDecision[] = ['keep', 'remove'];

type TeamMutation = MutationContext & { team: Team; via: 'permission' | 'maintainer' | 'member' };
/** What a team's own people may do without an administrator permission. */
type TeamLevel = 'maintainer' | 'member';

function choice<T extends string>(value: unknown, allowed: readonly T[], name: string): T {
  if (typeof value !== 'string' || !(allowed as readonly string[]).includes(value))
    throw new IamError('INVALID_INPUT', `${name} must be one of ${allowed.join(', ')}`);
  return value as T;
}
const ref = (team: Team): TeamRef => ({ id: team.id, name: team.name, slug: team.slug });
const person = (identity: Identity): TeamPerson => ({
  id: identity.id,
  name: identity.name,
  ...(identity.email ? { email: identity.email } : {}),
  status: identity.status,
});
const unknownPerson = (identityId: string): TeamPerson => ({
  id: identityId,
  name: identityId,
  status: 'deleted',
});

/** A person acting for themselves in their own tenant (the self-service calls and the maintainer path). */
function ownUserSession(principal: AuthenticatedPrincipal, tenantId: string): boolean {
  return (
    principal.session.kind === 'user' &&
    actsInOwnRight(principal.session) &&
    !principal.session.impersonatorId &&
    principal.session.tenantId === tenantId &&
    principal.identity.tenantId === tenantId &&
    principal.identity.kind === 'user'
  );
}
function requireOwnSession(principal: AuthenticatedPrincipal, tenantId: string): void {
  if (principal.session.impersonatorId)
    throw new IamError(
      'IMPERSONATION_RESTRICTED',
      'Teams cannot be joined or left while impersonating',
      403,
    );
  if (!ownUserSession(principal, tenantId))
    throw new IamError(
      'ACCESS_DENIED',
      'Teams are joined and left from a person’s own session in their organization',
      403,
    );
}

/**
 * Teams inside an organization (teams.ts). Administrators holding `iam:teams:*` manage every team; a team's maintainers
 * (and those of the teams above it) manage its membership and join requests themselves unless the team's
 * `memberManagement` is `admins`; members see their own team. Give a team access by binding roles to its backing group
 * (`team.groupId`) with `bindings.create`; everyone in the team and in the teams below it then holds them.
 */
function teamModule(ctx: ServerContext) {
  const { operation } = ctx.operations;

  /**
   * Runs a change, then (once it committed) re-evaluates the birthright access package rules of the people it touched:
   * rules may test identity.teams and the backing groups under identity.groups. Never fails the change; the schedule
   * catches up.
   */
  function reconciling<T>(
    tenantId: string,
    run: (touch: (identityIds: Iterable<string>) => void) => Promise<T>,
  ): Promise<T> {
    const touched = new Set<string>();
    return run((identityIds) => {
      for (const identityId of identityIds) touched.add(identityId);
    }).then((result) => afterIdentityChange(ctx, tenantId, [...touched], result));
  }

  /** The direct members (any expiry or source) of a team and of every team below it. */
  async function membersBelow(tx: IamStore, team: Team): Promise<string[]> {
    const scope = new Set([
      team.id,
      ...teamDescendants((await allTeams(tx, team.tenantId)).values(), team.id).map(
        (item) => item.id,
      ),
    ]);
    return (await tx.find<TeamMember>(teamCollections.members, { tenantId: team.tenantId }))
      .filter((member) => scope.has(member.teamId))
      .map((member) => member.identityId);
  }

  async function people(tx: IamStore, ids: Iterable<string>): Promise<Map<string, TeamPerson>> {
    const result = new Map<string, TeamPerson>();
    for (const identityId of new Set(ids)) {
      const identity = await tx.get<Identity>('identities', identityId);
      result.set(identityId, identity ? person(identity) : unknownPerson(identityId));
    }
    return result;
  }

  /** Whether the principal may act on the team at `level` through membership rather than a permission. */
  async function teamStanding(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    team: Team,
    level: TeamLevel,
  ): Promise<boolean> {
    if (!ownUserSession(principal, team.tenantId)) return false;
    const now = ctx.now();
    const maintains =
      team.memberManagement !== 'admins' &&
      (await isTeamMaintainer(tx, team.tenantId, team.id, principal.identity.id, {
        at: now,
        includeAncestors: true,
      }));
    if (maintains || level === 'maintainer') return maintains;
    // Members see their team: a direct membership of it or of any team below it.
    return (
      await teamsOf(tx, team.tenantId, principal.identity.id, { at: now, includeAncestors: true })
    ).includes(team.id);
  }

  /**
   * The team-scoped envelope. A caller holding `action` on `iam/{teamId}` goes through the ordinary operation; a
   * maintainer (or, for reads, a member) without it acts through the same transactional steps (separation of duties,
   * invariants, plugin hooks) and is audited with `via: team-maintainer` / `team-member`.
   */
  async function teamOperation<T>(
    credential: CredentialInput,
    tenantId: string,
    teamIdInput: unknown,
    action: string,
    level: TeamLevel | undefined,
    fn: (mutation: TeamMutation) => Promise<T>,
  ): Promise<T> {
    const teamId = text(teamIdInput, 'teamId', 128);
    if (level) {
      const authenticated = await ctx.principals.authenticate(credential);
      const byStanding = await ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const team = await tx.get<Team>(teamCollections.teams, teamId);
        if (!team || team.tenantId !== tenantId) return false;
        if (!(await teamStanding(tx, principal, team, level))) return false;
        try {
          const decision = await ctx.decisions.decide(
            tx,
            principal,
            { tenantId, action, resource: { type: 'iam', id: team.id } },
            true,
          );
          return !decision.allowed;
        } catch {
          return false;
        }
      });
      if (byStanding) return standingOperation(authenticated, tenantId, teamId, action, level, fn);
    }
    return operation(credential, tenantId, action, teamId, async (mutation) =>
      fn({ ...mutation, team: await loadTeam(mutation.tx, tenantId, teamId), via: 'permission' }),
    );
  }

  function standingOperation<T>(
    authenticated: AuthenticatedPrincipal,
    tenantId: string,
    teamId: string,
    action: string,
    level: TeamLevel,
    fn: (mutation: TeamMutation) => Promise<T>,
  ): Promise<T> {
    return ctx.observe.span('operation', action, tenantId, async () => {
      const outcome = await ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const tenant = await ctx.tenant(tx, tenantId);
        const chain = await ctx.ancestry(tx, tenant);
        const team = await tx.get<Team>(teamCollections.teams, teamId);
        const standing =
          chain.every((realm) => realm.status === 'active') &&
          team?.tenantId === tenantId &&
          (await teamStanding(tx, principal, team, level));
        if (!standing || !team) {
          await ctx.events.audit(tx, principal, action, tenantId, teamId, 'deny');
          return { denied: true as const };
        }
        const via = level === 'maintainer' ? 'maintainer' : ('member' as const);
        const hook = { store: tx, principal, tenantId, action, resourceId: teamId };
        for (const plugin of ctx.plugins) await plugin.hooks?.beforeOperation?.(hook);
        const separation = await sodSnapshot(ctx, tx, tenantId, action);
        const guardrails = await invariantSnapshot(ctx, tx, tenantId, action);
        const value = await fn({ tx, principal, tenant, team, via });
        await sodVerify(ctx, tx, tenantId, separation);
        await invariantVerify(ctx, tx, tenantId, guardrails);
        for (const plugin of ctx.plugins)
          await plugin.hooks?.afterOperation?.({ ...hook, result: value });
        await ctx.events.audit(tx, principal, action, tenantId, teamId, 'allow', false, {
          via: `team-${via}`,
        });
        return { denied: false as const, value };
      });
      if (outcome.denied) throw new IamError('ACCESS_DENIED', 'Access denied', 403);
      return outcome.value;
    });
  }

  /** Self-service calls: an ordinary session of a person in their own organization. */
  async function selfService<T>(
    credential: CredentialInput,
    tenantIdInput: unknown,
    fn: (tx: IamStore, principal: AuthenticatedPrincipal, tenantId: string) => Promise<T>,
  ): Promise<T> {
    const tenantId = text(tenantIdInput, 'tenantId');
    const authenticated = await ctx.principals.authenticate(credential);
    return ctx.store.transaction(async (tx) => {
      const principal = await ctx.principals.currentPrincipal(tx, authenticated);
      requireOwnSession(principal, tenantId);
      const chain = await ctx.ancestry(tx, await ctx.tenant(tx, tenantId));
      if (chain.some((realm) => realm.status !== 'active'))
        throw new IamError('TENANT_INACTIVE', 'The organization is not active', 403);
      return fn(tx, principal, tenantId);
    });
  }

  async function audit(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    team: Team,
    metadata: Record<string, Json>,
  ): Promise<void> {
    await ctx.events.audit(tx, principal, action, team.tenantId, team.id, 'allow', false, {
      team: team.slug,
      ...metadata,
    });
  }

  async function email(
    tx: IamStore,
    tenantId: string,
    identityIds: Iterable<string>,
    template: string,
    payload: Record<string, string>,
  ): Promise<void> {
    if (!ctx.options.authentication?.sendEmail) return;
    for (const identityId of new Set(identityIds)) {
      const identity = await tx.get<Identity>('identities', identityId);
      if (!identity?.email || identity.status !== 'active' || identity.tenantId !== tenantId)
        continue;
      await ctx.auth.enqueueDelivery(tx, {
        tenantId,
        kind: 'email',
        to: identity.email,
        template,
        payload,
      });
    }
  }

  /**
   * Administrators who grant through a team need authority over what the team's backing groups (and those of the
   * teams above it) are bound to, exactly as adding someone to those groups would. Maintainers act under the delegation
   * the team's administrators gave them and skip this.
   */
  async function assertAuthorityOver(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    teams: Team[],
  ): Promise<void> {
    for (const team of teams)
      for (const binding of await tx.find<Binding>('bindings', {
        tenantId,
        subjectType: 'group',
        subjectId: team.groupId,
      }))
        await ctx.grantingAuthority(tx, principal, tenantId, binding.authorityId);
  }

  async function allTeams(tx: IamStore, tenantId: string): Promise<Map<string, Team>> {
    return new Map(
      (await tx.find<Team>(teamCollections.teams, { tenantId })).map((team) => [team.id, team]),
    );
  }

  async function summaries(tx: IamStore, teams: Team[], all: Team[]): Promise<TeamSummary[]> {
    const now = ctx.now();
    const tenantIds = [...new Set(teams.map((team) => team.tenantId))];
    const members = new Map<string, TeamMember[]>();
    for (const tenantId of tenantIds)
      for (const member of await tx.find<TeamMember>(teamCollections.members, { tenantId }))
        if (liveTeamMember(member, now))
          members.set(member.teamId, [...(members.get(member.teamId) ?? []), member]);
    return teams.map((team) => summary(team, members.get(team.id) ?? [], all));
  }

  function summary(team: Team, members: TeamMember[], all: Team[]): TeamSummary {
    const { uniqueKey: _key, createdBy: _by, ...rest } = team;
    return {
      ...rest,
      memberCount: members.length,
      maintainerCount: members.filter((member) => member.role === 'maintainer').length,
      childCount: all.filter((other) => other.parentId === team.id).length,
    };
  }

  async function detail(tx: IamStore, team: Team): Promise<TeamDetail> {
    const now = ctx.now();
    const teams = await allTeams(tx, team.tenantId);
    const chain = teamChain(teams, team.id);
    const [base] = await summaries(tx, [team], [...teams.values()]);
    const children = [...teams.values()]
      .filter((other) => other.parentId === team.id)
      .sort((a, b) => a.name.localeCompare(b.name));
    const childCounts = await summaries(tx, children, [...teams.values()]);
    const maintainerIds = await teamMaintainers(tx, team.tenantId, team.id, now);
    const maintainers = await people(tx, maintainerIds);
    let department: TeamDetail['department'];
    if (team.departmentId) {
      const found = await tx.get<Department>('departments', team.departmentId);
      if (found?.tenantId === team.tenantId)
        department = {
          id: found.id,
          name: found.name,
          ...(found.code ? { code: found.code } : {}),
        };
    }
    const total = (
      await tx.find<GroupMember>('groupMembers', {
        tenantId: team.tenantId,
        groupId: team.groupId,
      })
    ).filter((member) => ctx.liveMembership(member)).length;
    const roles: TeamRoleGrant[] = [];
    for (const holder of chain)
      for (const binding of await tx.find<Binding>('bindings', {
        tenantId: team.tenantId,
        subjectType: 'group',
        subjectId: holder.groupId,
      })) {
        if (ctx.expiredBinding(binding)) continue;
        const role = await tx.get<Role>('roles', binding.roleId);
        roles.push({
          bindingId: binding.id,
          roleId: binding.roleId,
          roleName: role?.name ?? binding.roleId,
          team: ref(holder),
          inherited: holder.id !== team.id,
          ...(binding.eligible ? { eligible: true } : {}),
          ...(binding.startsAt !== undefined ? { startsAt: binding.startsAt } : {}),
          ...(binding.expiresAt !== undefined ? { expiresAt: binding.expiresAt } : {}),
        });
      }
    return {
      ...base!,
      path: chain.slice(1).reverse().map(ref),
      children: children.map((child, index) => ({
        ...ref(child),
        memberCount: childCounts[index]!.memberCount,
      })),
      ...(department ? { department } : {}),
      maintainers: maintainerIds.map((identityId) => maintainers.get(identityId)!),
      totalMemberCount: total,
      roles,
      syncGroups: await Promise.all(
        (team.syncGroupIds ?? []).map(async (groupId) => ({
          id: groupId,
          name: (await tx.get<Group>('groups', groupId))?.name ?? groupId,
        })),
      ),
    };
  }

  async function requestView(tx: IamStore, request: TeamJoinRequest): Promise<TeamJoinRequestView> {
    const team = await tx.get<Team>(teamCollections.teams, request.teamId);
    const requester = await tx.get<Identity>('identities', request.identityId);
    const {
      uniqueKey: _key,
      tenantId: _tenant,
      teamId: _team,
      identityId: _identity,
      ...rest
    } = request;
    return {
      ...rest,
      id: request.id,
      team: team ? ref(team) : { id: request.teamId, name: request.teamId, slug: '' },
      requester: requester ? person(requester) : unknownPerson(request.identityId),
    };
  }

  /** A slug that no other team of the tenant uses. */
  async function freeSlug(
    tx: IamStore,
    tenantId: string,
    slug: string,
    exceptId?: string,
  ): Promise<string> {
    const taken = (
      await tx.find<Team>(teamCollections.teams, { tenantId, uniqueKey: `slug:${slug}` })
    ).some((team) => team.id !== exceptId);
    if (taken) throw new IamError('CONFLICT', `A team with the slug ${slug} exists`, 409);
    return slug;
  }

  /** A person who can belong to a team: an active person (not a service account or agent) of the tenant. */
  async function teamPerson(tx: IamStore, tenantId: string, identityId: unknown) {
    const identity = await ctx.activeIdentity(tx, text(identityId, 'identityId', 128), tenantId);
    if (identity.kind !== 'user')
      throw new IamError(
        'INVALID_INPUT',
        'Teams hold people; service accounts and agents cannot join',
      );
    if (identity.status !== 'active')
      throw new IamError('INVALID_INPUT', 'Only active people can join a team');
    return identity;
  }

  /** Adds or re-adds a direct member, then refreshes the backing groups. Shared by add, approve and create. */
  async function putMember(
    mutation: TeamMutation,
    input: { identityId: unknown; role?: unknown; expiresAt?: unknown },
    source: string,
  ): Promise<TeamMember> {
    const { tx, principal, team } = mutation;
    const identity = await teamPerson(tx, team.tenantId, input.identityId);
    const role = input.role === undefined ? 'member' : choice(input.role, teamRoles, 'role');
    const expiresAt =
      input.expiresAt === undefined || input.expiresAt === null
        ? undefined
        : ctx.bindingExpiry(input.expiresAt);
    const uniqueKey = `${team.id}:${identity.id}`;
    const existing = (
      await tx.find<TeamMember>(teamCollections.members, { tenantId: team.tenantId, uniqueKey })
    )[0];
    const now = ctx.now();
    if (existing && liveTeamMember(existing, now))
      throw new IamError('CONFLICT', `${identity.name} is already in this team`, 409);
    const record: TeamMember = {
      id: existing?.id ?? id(),
      tenantId: team.tenantId,
      uniqueKey,
      teamId: team.id,
      identityId: identity.id,
      role,
      addedAt: now,
      addedBy: principal.identity.id,
      ...(expiresAt !== undefined ? { expiresAt } : {}),
    };
    await (existing
      ? tx.put<TeamMember>(teamCollections.members, record)
      : tx.insert<TeamMember>(teamCollections.members, record));
    await syncTeamGroups(tx, team.tenantId, [team.id], now);
    // A pending request of theirs is settled by the membership.
    for (const request of await tx.find<TeamJoinRequest>(teamCollections.requests, {
      tenantId: team.tenantId,
      teamId: team.id,
      identityId: identity.id,
      status: 'pending',
    }))
      if (source !== 'approve')
        await tx.put<TeamJoinRequest>(teamCollections.requests, {
          ...request,
          status: 'approved',
          decidedBy: principal.identity.id,
          decidedAt: now,
        });
    await audit(tx, principal, 'team:member:add', team, {
      identityId: identity.id,
      role,
      source,
      ...(expiresAt !== undefined ? { expiresAt } : {}),
      ...(mutation.via !== 'permission' ? { via: mutation.via } : {}),
    });
    return record;
  }

  async function memberRecord(tx: IamStore, team: Team, identityId: unknown): Promise<TeamMember> {
    const member = (
      await tx.find<TeamMember>(teamCollections.members, {
        tenantId: team.tenantId,
        uniqueKey: `${team.id}:${text(identityId, 'identityId', 128)}`,
      })
    )[0];
    if (!member || !liveTeamMember(member, ctx.now()))
      throw new IamError('NOT_FOUND', 'Not a member of this team', 404);
    return member;
  }

  async function removeMember(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    team: Team,
    member: TeamMember,
    action: string,
    via?: string,
  ): Promise<void> {
    await tx.delete(teamCollections.members, member.id);
    await syncTeamGroups(tx, team.tenantId, [team.id], ctx.now());
    await audit(tx, principal, action, team, {
      identityId: member.identityId,
      role: member.role,
      ...(via && via !== 'permission' ? { via } : {}),
    });
  }

  /** The chain a parent brings: its own chain, checked for depth against the subtree that moves under it. */
  function parentChain(teams: Map<string, Team>, parent: Team, subtreeHeight: number): Team[] {
    const chain = teamChain(teams, parent.id);
    if (chain.length + subtreeHeight > maxTeamDepth)
      throw new IamError('INVALID_INPUT', `Teams nest at most ${maxTeamDepth} levels deep`);
    return chain;
  }
  function subtreeHeight(teams: Map<string, Team>, team: Team): number {
    let height = 1;
    for (const descendant of teamDescendants(teams.values(), team.id)) {
      const depth = teamChain(teams, descendant.id).findIndex((item) => item.id === team.id) + 1;
      height = Math.max(height, depth);
    }
    return height;
  }

  /** Moving a team (or creating one) under a parent: the caller must be able to manage the parent and grant its access. */
  async function assertCanNestUnder(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    chain: Team[],
  ): Promise<void> {
    const parent = chain[0]!;
    const decision = await ctx.decisions.decide(
      tx,
      principal,
      { tenantId, action: 'iam:teams:update', resource: { type: 'iam', id: parent.id } },
      true,
    );
    if (!decision.allowed)
      throw new IamError(
        'ACCESS_DENIED',
        `Placing a team under ${parent.name} needs iam:teams:update on it`,
        403,
      );
    // Members of the nested team join the parent's groups, so its bindings must be within the caller's authority.
    await assertAuthorityOver(tx, principal, tenantId, chain);
  }

  /** Creates a team with its backing group (and maintainers); the caller has authorized `iam:teams:create`. */
  async function createTeam(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    input: TeamInput,
  ): Promise<Team> {
    const name = text(input.name, 'name', 100).trim();
    const existing = await allTeams(tx, tenant.id);
    if (existing.size >= maxTeams)
      throw new IamError('LIMIT_EXCEEDED', `At most ${maxTeams} teams`, 409);
    const derived = input.slug === undefined ? slugFromName(name) : teamSlug(input.slug);
    if (!derived)
      throw new IamError('INVALID_INPUT', 'Choose a slug: the name has no letters or digits');
    const slug = await freeSlug(tx, tenant.id, derived);
    let chain: Team[] = [];
    if (input.parentId !== undefined) {
      const parent = await loadTeam(tx, tenant.id, input.parentId);
      chain = parentChain(existing, parent, 1);
      await assertCanNestUnder(tx, principal, tenant.id, chain);
    }
    if (input.departmentId !== undefined) await loadDepartment(tx, tenant.id, input.departmentId);
    const maintainerIds = [
      ...new Set(
        input.maintainerIds === undefined ? [] : strings(input.maintainerIds, 'maintainerIds'),
      ),
    ];
    if (maintainerIds.length > maxMaintainersOnCreate)
      throw new IamError(
        'INVALID_INPUT',
        `Name at most ${maxMaintainersOnCreate} maintainers when creating a team`,
      );
    const syncGroupIds =
      input.syncGroupIds === undefined
        ? []
        : await teamSyncGroups(tx, tenant.id, input.syncGroupIds);
    const now = ctx.now();
    const group = await createGroup(ctx, tx, tenant, {
      tenantId: tenant.id,
      name: `team:${slug}`,
      description: `Members of team ${name} (managed by the team)`,
    });
    const team: Team = {
      id: id(),
      tenantId: tenant.id,
      uniqueKey: `slug:${slug}`,
      name,
      slug,
      ...(input.description !== undefined && input.description !== ''
        ? { description: text(input.description, 'description', 512) }
        : {}),
      ...(input.parentId !== undefined ? { parentId: chain[0]!.id } : {}),
      ...(input.departmentId !== undefined ? { departmentId: input.departmentId } : {}),
      groupId: group.id,
      joinPolicy:
        input.joinPolicy === undefined
          ? 'closed'
          : choice(input.joinPolicy, joinPolicies, 'joinPolicy'),
      memberManagement:
        input.memberManagement === undefined
          ? 'maintainers'
          : choice(input.memberManagement, managementModes, 'memberManagement'),
      ...(syncGroupIds.length ? { syncGroupIds } : {}),
      createdAt: now,
      createdBy: principal.identity.id,
      updatedAt: now,
    };
    await tx.put<Group>('groups', { ...group, teamId: team.id });
    await tx.insert<Team>(teamCollections.teams, team);
    for (const identityId of maintainerIds)
      await putMember(
        { tx, principal, tenant, team, via: 'permission' },
        { identityId, role: 'maintainer' },
        'create',
      );
    if (syncGroupIds.length)
      await syncTeamsFromGroups(ctx, tx, tenant.id, {
        teamIds: [team.id],
        actorId: principal.identity.id,
      });
    await audit(tx, principal, 'team:create', team, {
      name,
      ...(team.parentId ? { parentId: team.parentId } : {}),
    });
    return team;
  }

  /** Changes a team's settings or place; the caller has authorized `iam:teams:update` on it. */
  async function updateTeam(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    team: Team,
    input: TeamUpdate,
  ): Promise<Team> {
    const keys: (keyof TeamUpdate)[] = [
      'name',
      'slug',
      'description',
      'parentId',
      'departmentId',
      'joinPolicy',
      'memberManagement',
      'syncGroupIds',
    ];
    if (keys.every((key) => input[key] === undefined))
      throw new IamError('INVALID_INPUT', 'Nothing to update');
    const teams = await allTeams(tx, team.tenantId);
    const next: Team = { ...team, updatedAt: ctx.now() };
    if (input.name !== undefined) next.name = text(input.name, 'name', 100).trim();
    if (input.slug !== undefined && input.slug !== team.slug) {
      next.slug = await freeSlug(tx, team.tenantId, teamSlug(input.slug), team.id);
      next.uniqueKey = `slug:${next.slug}`;
    }
    if (input.description !== undefined) {
      delete next.description;
      if (input.description !== null && input.description !== '')
        next.description = text(input.description, 'description', 512);
    }
    if (input.departmentId !== undefined) {
      delete next.departmentId;
      if (input.departmentId !== null) {
        await loadDepartment(tx, team.tenantId, input.departmentId);
        next.departmentId = input.departmentId;
      }
    }
    if (input.joinPolicy !== undefined)
      next.joinPolicy = choice(input.joinPolicy, joinPolicies, 'joinPolicy');
    if (input.memberManagement !== undefined)
      next.memberManagement = choice(input.memberManagement, managementModes, 'memberManagement');
    if (input.syncGroupIds !== undefined) {
      delete next.syncGroupIds;
      const sources =
        input.syncGroupIds === null
          ? []
          : await teamSyncGroups(tx, team.tenantId, input.syncGroupIds);
      if (sources.length) next.syncGroupIds = sources;
      // Syncing brings people in, and with them what the team and the teams above it hold.
      if (sources.some((groupId) => !team.syncGroupIds?.includes(groupId)))
        await assertAuthorityOver(tx, principal, team.tenantId, teamChain(teams, team.id));
    }
    const previousParent = team.parentId;
    if (input.parentId !== undefined && (input.parentId ?? undefined) !== team.parentId) {
      delete next.parentId;
      if (input.parentId !== null) {
        const parent = await loadTeam(tx, team.tenantId, input.parentId);
        if (
          parent.id === team.id ||
          teamDescendants(teams.values(), team.id).some((item) => item.id === parent.id)
        )
          throw new IamError('INVALID_INPUT', 'A team cannot move under itself or its own team');
        const chain = parentChain(teams, parent, subtreeHeight(teams, team));
        await assertCanNestUnder(tx, principal, team.tenantId, chain);
        next.parentId = parent.id;
      }
    }
    await tx.put<Team>(teamCollections.teams, next);
    if (next.slug !== team.slug || next.name !== team.name) {
      const group = await tx.get<Group>('groups', team.groupId);
      if (group)
        await tx.put<Group>('groups', {
          ...group,
          name: `team:${next.slug}`,
          description: `Members of team ${next.name} (managed by the team)`,
        });
    }
    if (next.parentId !== previousParent)
      await syncTeamGroups(
        tx,
        team.tenantId,
        [team.id, ...(previousParent ? [previousParent] : [])],
        ctx.now(),
      );
    if (input.syncGroupIds !== undefined)
      await syncTeamsFromGroups(ctx, tx, team.tenantId, {
        teamIds: [team.id],
        actorId: principal.identity.id,
      });
    await audit(tx, principal, 'team:update', next, {
      fields: keys.filter((key) => input[key] !== undefined),
      ...(next.parentId !== previousParent
        ? { parentId: next.parentId ?? null, previousParentId: previousParent ?? null }
        : {}),
    });
    return next;
  }

  /** Deletes a team with its memberships, requests, and backing group; returns how many members it had. */
  async function deleteTeam(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    team: Team,
  ): Promise<number> {
    const children = (await tx.find<Team>(teamCollections.teams, { tenantId: team.tenantId }))
      .filter((other) => other.parentId === team.id)
      .map((other) => other.name);
    if (children.length)
      throw new IamError(
        'RESOURCE_IN_USE',
        `Move or delete the teams below it first: ${children.join(', ')}`,
        409,
      );
    // A team a birthright rule names stays until the package stops naming it (like groups).
    const naming = await packagesNaming(
      tx,
      team.tenantId,
      'identity.teams',
      [team.id],
      [team.groupId],
    );
    if (naming.length)
      throw new IamError(
        'RESOURCE_IN_USE',
        `Access packages name it in a rule: ${naming.join(', ')}`,
        409,
      );
    const members = await tx.find<TeamMember>(teamCollections.members, {
      tenantId: team.tenantId,
      teamId: team.id,
    });
    for (const member of members) await tx.delete(teamCollections.members, member.id);
    for (const request of await tx.find<TeamJoinRequest>(teamCollections.requests, {
      tenantId: team.tenantId,
      teamId: team.id,
    }))
      await tx.delete(teamCollections.requests, request.id);
    // Membership reviews go with the team (their outcome stays in the audit trail).
    for (const collection of [teamReviewCollections.items, teamReviewCollections.reviews])
      for (const record of await tx.find<TeamReview | TeamReviewItem>(collection, {
        tenantId: team.tenantId,
        teamId: team.id,
      }))
        await tx.delete(collection, record.id);
    const group = await tx.get<Group>('groups', team.groupId);
    if (group) await deleteGroup(ctx, tx, principal, group);
    await tx.delete(teamCollections.teams, team.id);
    if (team.parentId) await syncTeamGroups(tx, team.tenantId, [team.parentId], ctx.now());
    await audit(tx, principal, 'team:delete', team, {
      name: team.name,
      members: members.length,
    });
    return members.length;
  }

  const api = {
    /**
     * Creates a team with its backing group. `parentId` nests it (its members then also receive the parent's access;
     * needs iam:teams:update on the parent and authority over what the parent holds); `maintainerIds` names up to 20
     * people who manage its membership.
     */
    create: (credential: CredentialInput, input: TeamInput): Promise<TeamDetail> =>
      reconciling(input.tenantId, (touch) =>
        operation(
          credential,
          input.tenantId,
          'iam:teams:create',
          input.tenantId,
          async ({ tx, principal, tenant }) => {
            const team = await createTeam(tx, principal, tenant, input);
            touch(await membersBelow(tx, team));
            return detail(tx, team);
          },
        ),
      ),
    /**
     * Renames, re-slugs, re-describes, moves (`parentId`, null for top level), or re-files (`departmentId`) a team,
     * or changes its join policy or who manages members. Moving re-computes the backing groups of the old and new
     * parents; the new parent needs the same rights as creating under it.
     */
    update: (credential: CredentialInput, input: TeamUpdate): Promise<TeamDetail> =>
      reconciling(input.tenantId, (touch) =>
        teamOperation(
          credential,
          input.tenantId,
          input.teamId,
          'iam:teams:update',
          undefined,
          async ({ tx, principal, team }) => {
            // A move or a sync change alters identity.teams at or below the team.
            const moving = input.parentId !== undefined || input.syncGroupIds !== undefined;
            if (moving) touch(await membersBelow(tx, team));
            const updated = await updateTeam(tx, principal, team, input);
            if (moving) touch(await membersBelow(tx, updated));
            return detail(tx, updated);
          },
        ),
      ),
    /**
     * Deletes a team, its memberships and join requests, and its backing group with the bindings and relationships on
     * it (which needs authority over those bindings, as `groups.delete` does). Teams below it must be moved or deleted
     * first (RESOURCE_IN_USE).
     */
    delete: (credential: CredentialInput, input: { tenantId: string; teamId: string }) =>
      reconciling(input.tenantId, (touch) =>
        teamOperation(
          credential,
          input.tenantId,
          input.teamId,
          'iam:teams:delete',
          undefined,
          async ({ tx, principal, team }) => {
            touch(await membersBelow(tx, team));
            return { deleted: true as const, members: await deleteTeam(tx, principal, team) };
          },
        ),
      ),
    /**
     * Every team of the organization with member counts, name order. Filters: `parentId` (null for top-level teams),
     * `departmentId`, and `query` (name or slug, case-insensitive).
     */
    list: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        parentId?: string | null;
        departmentId?: string;
        query?: string;
      },
    ): Promise<TeamSummary[]> =>
      operation(credential, input.tenantId, 'iam:teams:read', input.tenantId, async ({ tx }) => {
        const all = [...(await allTeams(tx, input.tenantId)).values()];
        const query =
          input.query === undefined ? undefined : text(input.query, 'query', 100).toLowerCase();
        const selected = all
          .filter(
            (team) =>
              (input.parentId === undefined || (team.parentId ?? null) === input.parentId) &&
              (input.departmentId === undefined || team.departmentId === input.departmentId) &&
              (query === undefined ||
                team.name.toLowerCase().includes(query) ||
                team.slug.includes(query)),
          )
          .sort((a, b) => a.name.localeCompare(b.name) || (a.id < b.id ? -1 : 1));
        return summaries(tx, selected, all);
      }),
    /** One team with its place in the tree, maintainers, department, and the roles its members hold through it. Members may read their own team. */
    get: (credential: CredentialInput, input: { tenantId: string; teamId: string }) =>
      teamOperation(
        credential,
        input.tenantId,
        input.teamId,
        'iam:teams:read',
        'member',
        ({ tx, team }) => detail(tx, team),
      ),
    /**
     * The team's live direct members with their role; `includeChildTeams` adds the members of every team below it
     * (each with the team they belong to). Members may read their own team.
     */
    listMembers: (
      credential: CredentialInput,
      input: { tenantId: string; teamId: string; includeChildTeams?: boolean },
    ): Promise<TeamMemberView[]> =>
      teamOperation(
        credential,
        input.tenantId,
        input.teamId,
        'iam:teams:read',
        'member',
        async ({ tx, team }) => {
          const teams = await allTeams(tx, team.tenantId);
          const scope = [
            team,
            ...(input.includeChildTeams ? teamDescendants(teams.values(), team.id) : []),
          ];
          const now = ctx.now();
          const members: TeamMember[] = [];
          for (const item of scope)
            members.push(
              ...(
                await tx.find<TeamMember>(teamCollections.members, {
                  tenantId: team.tenantId,
                  teamId: item.id,
                })
              ).filter((member) => liveTeamMember(member, now)),
            );
          const directory = await people(
            tx,
            members.map((member) => member.identityId),
          );
          return members
            .map((member) => ({
              ...directory.get(member.identityId)!,
              role: member.role,
              team: ref(teams.get(member.teamId)!),
              addedAt: member.addedAt,
              addedBy: member.addedBy,
              ...(member.expiresAt !== undefined ? { expiresAt: member.expiresAt } : {}),
              ...(member.source ? { source: member.source } : {}),
            }))
            .filter((member) => member.status !== 'deleted')
            .sort(
              (a, b) =>
                Number(b.role === 'maintainer') - Number(a.role === 'maintainer') ||
                (a.email ?? a.name).localeCompare(b.email ?? b.name),
            );
        },
      ),
    /**
     * Adds a person (`role` member by default, or maintainer; `expiresAt` for a temporary membership). Maintainers of the
     * team or a team above it may do this without iam:teams:update unless the team's memberManagement is `admins`.
     */
    addMember: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        teamId: string;
        identityId: string;
        role?: TeamRole;
        expiresAt?: number;
      },
    ) =>
      reconciling(input.tenantId, (touch) =>
        teamOperation(
          credential,
          input.tenantId,
          input.teamId,
          'iam:teams:update',
          'maintainer',
          async (mutation) => {
            if (mutation.via === 'permission')
              await assertAuthorityOver(
                mutation.tx,
                mutation.principal,
                mutation.team.tenantId,
                teamChain(await allTeams(mutation.tx, mutation.team.tenantId), mutation.team.id),
              );
            const member = await putMember(mutation, input, 'add');
            touch([member.identityId]);
            return member;
          },
        ),
      ),
    /** Adds up to 100 people in one transaction with the same role and expiry; one failure rejects the batch. */
    addMembers: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        teamId: string;
        identityIds: string[];
        role?: TeamRole;
        expiresAt?: number;
      },
    ) =>
      reconciling(input.tenantId, (touch) =>
        teamOperation(
          credential,
          input.tenantId,
          input.teamId,
          'iam:teams:update',
          'maintainer',
          async (mutation) => {
            const identityIds = [...new Set(strings(input.identityIds, 'identityIds'))];
            if (!identityIds.length)
              throw new IamError('INVALID_INPUT', 'Provide 1-100 identityIds');
            if (mutation.via === 'permission')
              await assertAuthorityOver(
                mutation.tx,
                mutation.principal,
                mutation.team.tenantId,
                teamChain(await allTeams(mutation.tx, mutation.team.tenantId), mutation.team.id),
              );
            const members: TeamMember[] = [];
            for (const identityId of identityIds)
              members.push(
                await putMember(
                  mutation,
                  {
                    identityId,
                    ...(input.role !== undefined ? { role: input.role } : {}),
                    ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
                  },
                  'add',
                ),
              );
            touch(identityIds);
            return { members };
          },
        ),
      ),
    /** Changes a member's role or expiry (`expiresAt: null` makes the membership permanent). */
    updateMember: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        teamId: string;
        identityId: string;
        role?: TeamRole;
        expiresAt?: number | null;
      },
    ) =>
      reconciling(input.tenantId, (touch) =>
        teamOperation(
          credential,
          input.tenantId,
          input.teamId,
          'iam:teams:update',
          'maintainer',
          async ({ tx, principal, team, via }) => {
            if (input.role === undefined && input.expiresAt === undefined)
              throw new IamError('INVALID_INPUT', 'Nothing to update');
            if (via === 'permission')
              await assertAuthorityOver(
                tx,
                principal,
                team.tenantId,
                teamChain(await allTeams(tx, team.tenantId), team.id),
              );
            const member = await memberRecord(tx, team, input.identityId);
            if (member.source === 'sync' && input.expiresAt !== undefined)
              throw new IamError(
                'INVALID_TRANSITION',
                'A synced membership ends with the source group membership; change it there',
                409,
              );
            const next: TeamMember = { ...member };
            if (input.role !== undefined) next.role = choice(input.role, teamRoles, 'role');
            if (input.expiresAt !== undefined) {
              delete next.expiresAt;
              if (input.expiresAt !== null) next.expiresAt = ctx.bindingExpiry(input.expiresAt);
            }
            await tx.put<TeamMember>(teamCollections.members, next);
            await syncTeamGroups(tx, team.tenantId, [team.id], ctx.now());
            await audit(tx, principal, 'team:member:update', team, {
              identityId: member.identityId,
              role: next.role,
              ...(next.expiresAt !== undefined ? { expiresAt: next.expiresAt } : {}),
              ...(via !== 'permission' ? { via } : {}),
            });
            touch([member.identityId]);
            return next;
          },
        ),
      ),
    /** Removes a direct member; the backing groups (and their eligible-binding activations) follow. */
    removeMember: (
      credential: CredentialInput,
      input: { tenantId: string; teamId: string; identityId: string },
    ) =>
      reconciling(input.tenantId, (touch) =>
        teamOperation(
          credential,
          input.tenantId,
          input.teamId,
          'iam:teams:update',
          'maintainer',
          async ({ tx, principal, team, via }) => {
            if (via === 'permission')
              await assertAuthorityOver(
                tx,
                principal,
                team.tenantId,
                teamChain(await allTeams(tx, team.tenantId), team.id),
              );
            const member = await memberRecord(tx, team, input.identityId);
            // Team sync would add them straight back.
            if (member.source === 'sync')
              throw new IamError(
                'INVALID_TRANSITION',
                'This person is a member through team sync; remove them from the source group',
                409,
              );
            await removeMember(tx, principal, team, member, 'team:member:remove', via);
            touch([member.identityId]);
            return { deleted: true as const };
          },
        ),
      ),
    /**
     * People who could be added to the team: active people of the organization who are not direct members, matched on
     * name or email by `query` (at most `limit`, default 50). Maintainers may use it to pick people without
     * iam:identities:read.
     */
    candidates: (
      credential: CredentialInput,
      input: { tenantId: string; teamId: string; query?: string; limit?: number },
    ): Promise<TeamPerson[]> =>
      teamOperation(
        credential,
        input.tenantId,
        input.teamId,
        'iam:teams:update',
        'maintainer',
        async ({ tx, team }) => {
          const query =
            input.query === undefined || input.query === ''
              ? undefined
              : text(input.query, 'query', 100).toLowerCase();
          const limit = input.limit === undefined ? 50 : integer(input.limit, 'limit', 1, 200);
          const now = ctx.now();
          const members = new Set(
            (
              await tx.find<TeamMember>(teamCollections.members, {
                tenantId: team.tenantId,
                teamId: team.id,
              })
            )
              .filter((member) => liveTeamMember(member, now))
              .map((member) => member.identityId),
          );
          return (await tx.find<Identity>('identities', { tenantId: team.tenantId }))
            .filter(
              (identity) =>
                identity.kind === 'user' &&
                identity.status === 'active' &&
                !ctx.identityExpired(identity) &&
                !members.has(identity.id) &&
                (query === undefined ||
                  identity.name.toLowerCase().includes(query) ||
                  (identity.email ?? '').toLowerCase().includes(query)),
            )
            .sort((a, b) => (a.email ?? a.name).localeCompare(b.email ?? b.name))
            .slice(0, limit)
            .map(person);
        },
      ),
    /** The teams a person belongs to directly, with their role and the teams above each one. */
    listForIdentity: (
      credential: CredentialInput,
      input: { tenantId: string; identityId: string },
    ): Promise<MyTeams['teams']> =>
      operation(credential, input.tenantId, 'iam:teams:read', input.identityId, async ({ tx }) => {
        await ctx.scoped<Identity>(tx, 'identities', input.identityId, input.tenantId);
        return membershipsOf(tx, input.tenantId, input.identityId);
      }),
    /** The caller's teams, their join requests, and the teams they may ask to join. */
    listMine: (credential: CredentialInput, input: { tenantId: string }): Promise<MyTeams> =>
      selfService(credential, input.tenantId, async (tx, principal, tenantId) => {
        const teams = await membershipsOf(tx, tenantId, principal.identity.id);
        const requests = (
          await tx.find<TeamJoinRequest>(teamCollections.requests, {
            tenantId,
            identityId: principal.identity.id,
          })
        )
          .map((request) => lapse(request))
          .sort((a, b) => b.requestedAt - a.requestedAt)
          .slice(0, 50);
        const all = await allTeams(tx, tenantId);
        const mine = new Set(teams.map((team) => team.id));
        const joinable = [...all.values()]
          .filter((team) => team.joinPolicy === 'request' && !mine.has(team.id))
          .sort((a, b) => a.name.localeCompare(b.name));
        const counts = await summaries(tx, joinable, [...all.values()]);
        // Reviews waiting on the caller as a maintainer (their own membership is someone else's to decide).
        const reviews: MyTeams['reviews'] = [];
        for (const review of await tx.find<TeamReview>(teamReviewCollections.reviews, {
          tenantId,
          status: 'open',
        })) {
          const team = all.get(review.teamId);
          if (
            !team ||
            !(await isTeamMaintainer(tx, tenantId, team.id, principal.identity.id, {
              includeAncestors: true,
            }))
          )
            continue;
          const items = await tx.find<TeamReviewItem>(teamReviewCollections.items, {
            tenantId,
            reviewId: review.id,
          });
          reviews.push({
            id: review.id,
            team: ref(team),
            dueAt: review.dueAt,
            undecided: items.filter(
              (item) => item.decision === undefined && item.identityId !== principal.identity.id,
            ).length,
          });
        }
        reviews.sort((a, b) => a.dueAt - b.dueAt);
        return {
          reviews,
          teams,
          requests: await Promise.all(requests.map((request) => requestView(tx, request))),
          joinable: joinable.map((team, index) => ({
            ...ref(team),
            ...(team.description ? { description: team.description } : {}),
            memberCount: counts[index]!.memberCount,
          })),
        };
      }),
    /**
     * Asks to join a team whose join policy is `request`. Its maintainers (or, when it has none, those of the teams
     * above it) are emailed; the request lapses after fourteen days. Audited as `team:join:request`.
     */
    requestToJoin: (
      credential: CredentialInput,
      input: { tenantId: string; teamId: string; justification?: string },
    ): Promise<TeamJoinRequestView> =>
      selfService(credential, input.tenantId, async (tx, principal, tenantId) => {
        const team = await loadTeam(tx, tenantId, input.teamId);
        if (team.joinPolicy !== 'request')
          throw new IamError(
            'INVALID_TRANSITION',
            'This team does not take join requests; ask a maintainer to add you',
            409,
          );
        const now = ctx.now();
        const member = (
          await tx.find<TeamMember>(teamCollections.members, {
            tenantId,
            uniqueKey: `${team.id}:${principal.identity.id}`,
          })
        )[0];
        if (member && liveTeamMember(member, now))
          throw new IamError('CONFLICT', 'You are already in this team', 409);
        const pending = (
          await tx.find<TeamJoinRequest>(teamCollections.requests, {
            tenantId,
            teamId: team.id,
            identityId: principal.identity.id,
            status: 'pending',
          })
        ).find((request) => request.expiresAt > now);
        if (pending) throw new IamError('CONFLICT', 'You already asked to join this team', 409);
        const justification =
          input.justification === undefined || input.justification === ''
            ? undefined
            : text(input.justification, 'justification', 1000);
        const request: TeamJoinRequest = {
          id: id(),
          tenantId,
          teamId: team.id,
          identityId: principal.identity.id,
          status: 'pending',
          requestedAt: now,
          expiresAt: now + joinRequestLifetimeMs,
          ...(justification ? { justification } : {}),
        };
        await tx.insert<TeamJoinRequest>(teamCollections.requests, request);
        const teams = await allTeams(tx, tenantId);
        let recipients: string[] = [];
        for (const holder of teamChain(teams, team.id)) {
          recipients = await teamMaintainers(tx, tenantId, holder.id, now);
          if (recipients.length) break;
        }
        await email(
          tx,
          tenantId,
          recipients.filter((identityId) => identityId !== principal.identity.id),
          'team-join-request',
          {
            teamId: team.id,
            teamName: team.name,
            requestId: request.id,
            requesterName: principal.identity.name,
            ...(principal.identity.email ? { requesterEmail: principal.identity.email } : {}),
            ...(justification ? { justification } : {}),
          },
        );
        await audit(tx, principal, 'team:join:request', team, {
          requestId: request.id,
          ...(justification ? { justification } : {}),
        });
        return requestView(tx, request);
      }),
    /** Withdraws the caller's own pending request. */
    cancelRequest: (credential: CredentialInput, input: { tenantId: string; requestId: string }) =>
      selfService(credential, input.tenantId, async (tx, principal, tenantId) => {
        const request = await ctx.scoped<TeamJoinRequest>(
          tx,
          teamCollections.requests,
          text(input.requestId, 'requestId', 128),
          tenantId,
        );
        if (request.identityId !== principal.identity.id)
          throw new IamError('NOT_FOUND', 'Resource not found', 404);
        if (lapse(request).status !== 'pending')
          throw new IamError('INVALID_TRANSITION', 'The request is no longer pending', 409);
        const cancelled = await tx.put<TeamJoinRequest>(teamCollections.requests, {
          ...request,
          status: 'cancelled',
          decidedAt: ctx.now(),
        });
        const team = await tx.get<Team>(teamCollections.teams, request.teamId);
        if (team) await audit(tx, principal, 'team:join:cancel', team, { requestId: request.id });
        return requestView(tx, cancelled);
      }),
    /** Join requests for a team (pending by default; `status` picks another state). Maintainers may list their team's. */
    listRequests: (
      credential: CredentialInput,
      input: { tenantId: string; teamId: string; status?: TeamJoinRequestStatus },
    ): Promise<TeamJoinRequestView[]> =>
      teamOperation(
        credential,
        input.tenantId,
        input.teamId,
        'iam:teams:read',
        'maintainer',
        async ({ tx, team }) => {
          const status =
            input.status === undefined
              ? 'pending'
              : choice(
                  input.status,
                  ['pending', 'approved', 'denied', 'cancelled', 'expired'] as const,
                  'status',
                );
          const requests = (
            await tx.find<TeamJoinRequest>(teamCollections.requests, {
              tenantId: team.tenantId,
              teamId: team.id,
            })
          )
            .map((request) => lapse(request))
            .filter((request) => request.status === status)
            .sort((a, b) => b.requestedAt - a.requestedAt)
            .slice(0, 200);
          return Promise.all(requests.map((request) => requestView(tx, request)));
        },
      ),
    /**
     * Grants a pending join request: the requester joins as a member (optionally until `expiresAt`) and is emailed.
     * Nobody decides their own request. Maintainers may decide their team's requests.
     */
    approveRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; expiresAt?: number; note?: string },
    ): Promise<TeamJoinRequestView> => decide(credential, input, 'approved'),
    /** Refuses a pending join request; the requester is emailed with the note. */
    denyRequest: async (
      credential: CredentialInput,
      input: { tenantId: string; requestId: string; note?: string },
    ): Promise<TeamJoinRequestView> => decide(credential, input, 'denied'),
    /** Leaves a team the caller belongs to directly. Audited as `team:leave`. */
    leave: (credential: CredentialInput, input: { tenantId: string; teamId: string }) =>
      reconciling(input.tenantId, (touch) =>
        selfService(credential, input.tenantId, async (tx, principal, tenantId) => {
          const team = await loadTeam(tx, tenantId, input.teamId);
          const member = await memberRecord(tx, team, principal.identity.id);
          await removeMember(tx, principal, team, member, 'team:leave');
          touch([member.identityId]);
          return { left: true as const };
        }),
      ),
    /**
     * Runs team sync for every synced team (`synced`: team memberships added, removed, and updated from their source
     * groups), then re-computes every team's backing group from team membership (after a restore, an import, or a
     * manual repair): how many group memberships were added, removed, and updated.
     */
    reconcile: (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<TeamSyncResult & { synced: TeamGroupSyncResult }> =>
      operation(
        credential,
        input.tenantId,
        'iam:teams:update',
        input.tenantId,
        async ({ tx, principal }) => {
          const synced = await syncTeamsFromGroups(ctx, tx, input.tenantId, {
            actorId: principal.identity.id,
          });
          const groups = await syncTeamGroups(
            tx,
            input.tenantId,
            (await allTeams(tx, input.tenantId)).keys(),
            ctx.now(),
          );
          return { ...groups, synced };
        },
      ),
    /**
     * Birthright suggestions: roles and groups that at least `minShare` (default 0.8) of a team's members (with those of
     * the teams below it) hold by hand, for teams of at least `minPeople` (default 3), as a ready-made automatic access
     * package whose rule names the team. Never repeats what is suggested for a team above it or already granted by an
     * automatic package naming it. `teamId` limits the answer to one team. Read-only; requires iam:analysis:read.
     */
    suggestBirthright: (
      credential: CredentialInput,
      input: { tenantId: string; teamId?: string; minShare?: number; minPeople?: number },
    ): Promise<BirthrightSuggestion[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:analysis:read',
        input.tenantId,
        async ({ tx, tenant }) => {
          const options = birthrightOptions(input);
          if (input.teamId !== undefined) await loadTeam(tx, tenant.id, input.teamId);
          return suggestBirthright(ctx, tx, tenant.id, 'team', {
            ...options,
            ...(input.teamId !== undefined ? { unitId: input.teamId } : {}),
          });
        },
      ),
    /**
     * Opens a membership review of the team: every live manual member (team sync members are reviewed through their
     * source group) becomes an item its maintainers decide `keep` or `remove` by `dueAt` (default in 14 days, one to
     * 90 days ahead). `onUndecided` (`keep` by default) settles the people nobody decided on. The maintainers (or,
     * without any, those of the nearest team above) are emailed. One open review per team. Administrators only.
     */
    startReview: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        teamId: string;
        dueAt?: number;
        onUndecided?: TeamReviewDecision;
        note?: string;
      },
    ): Promise<TeamReviewView> =>
      teamOperation(
        credential,
        input.tenantId,
        input.teamId,
        'iam:teams:update',
        undefined,
        async ({ tx, principal, team }) => {
          const now = ctx.now();
          const dueAt =
            input.dueAt === undefined
              ? now + defaultReviewMs
              : integer(input.dueAt, 'dueAt', now + minReviewMs, now + maxReviewMs);
          const onUndecided =
            input.onUndecided === undefined
              ? 'keep'
              : choice(input.onUndecided, reviewDecisions, 'onUndecided');
          const note =
            input.note === undefined || input.note === ''
              ? undefined
              : text(input.note, 'note', 1000);
          const open = await tx.find<TeamReview>(teamReviewCollections.reviews, {
            tenantId: team.tenantId,
            uniqueKey: `open:${team.id}`,
          });
          if (open.length)
            throw new IamError('CONFLICT', 'This team already has an open membership review', 409);
          const members = (
            await tx.find<TeamMember>(teamCollections.members, {
              tenantId: team.tenantId,
              teamId: team.id,
            })
          ).filter((member) => liveTeamMember(member, now) && member.source !== 'sync');
          if (!members.length)
            throw new IamError(
              'INVALID_TRANSITION',
              'The team has no members to review (members team sync manages are reviewed through their source groups)',
              409,
            );
          const review = await tx.insert<TeamReview>(teamReviewCollections.reviews, {
            id: id(),
            tenantId: team.tenantId,
            uniqueKey: `open:${team.id}`,
            teamId: team.id,
            status: 'open',
            onUndecided,
            startedAt: now,
            startedBy: principal.identity.id,
            dueAt,
            ...(note ? { note } : {}),
          });
          for (const member of members)
            await tx.insert<TeamReviewItem>(teamReviewCollections.items, {
              id: id(),
              tenantId: team.tenantId,
              uniqueKey: `${review.id}:${member.identityId}`,
              reviewId: review.id,
              teamId: team.id,
              identityId: member.identityId,
              role: member.role,
            });
          const teams = await allTeams(tx, team.tenantId);
          let recipients: string[] = [];
          for (const holder of teamChain(teams, team.id)) {
            recipients = await teamMaintainers(tx, team.tenantId, holder.id, now);
            if (recipients.length) break;
          }
          await email(tx, team.tenantId, recipients, 'team-review-requested', {
            teamId: team.id,
            teamName: team.name,
            reviewId: review.id,
            memberCount: String(members.length),
            dueAt: new Date(dueAt).toISOString(),
            onUndecided,
            ...(note ? { note } : {}),
          });
          await audit(tx, principal, 'team:review:start', team, {
            reviewId: review.id,
            members: members.length,
            dueAt,
            onUndecided,
          });
          return reviewView(tx, review, team, true);
        },
      ),
    /** One review with every person under it. Maintainers of the team (or a team above) may read it. */
    getReview: async (
      credential: CredentialInput,
      input: { tenantId: string; reviewId: string },
    ): Promise<TeamReviewView> =>
      teamOperation(
        credential,
        input.tenantId,
        await reviewTeamId(input.tenantId, input.reviewId),
        'iam:teams:read',
        'maintainer',
        async ({ tx, team }) =>
          reviewView(tx, await loadReview(tx, team, input.reviewId), team, true),
      ),
    /**
     * Membership reviews, newest first (at most 100): of one team (`teamId`; its maintainers may list them) or, for
     * administrators holding iam:teams:read, of every team. `status` filters.
     */
    listReviews: async (
      credential: CredentialInput,
      input: { tenantId: string; teamId?: string; status?: TeamReviewStatus },
    ): Promise<TeamReviewView[]> => {
      const status =
        input.status === undefined
          ? undefined
          : choice(input.status, ['open', 'completed', 'cancelled'] as const, 'status');
      const list = async (tx: IamStore, teams: Team[]) => {
        const views: TeamReviewView[] = [];
        for (const team of teams)
          for (const review of await tx.find<TeamReview>(teamReviewCollections.reviews, {
            tenantId: team.tenantId,
            teamId: team.id,
            ...(status ? { status } : {}),
          }))
            views.push(await reviewView(tx, review, team, false));
        return views.sort((a, b) => b.startedAt - a.startedAt).slice(0, 100);
      };
      if (input.teamId !== undefined)
        return teamOperation(
          credential,
          input.tenantId,
          input.teamId,
          'iam:teams:read',
          'maintainer',
          ({ tx, team }) => list(tx, [team]),
        );
      return operation(
        credential,
        input.tenantId,
        'iam:teams:read',
        input.tenantId,
        async ({ tx }) => list(tx, [...(await allTeams(tx, input.tenantId)).values()]),
      );
    },
    /**
     * Records `keep` or `remove` for up to 200 people under an open review (a later decision replaces an earlier one).
     * Maintainers of the team or a team above, or administrators; nobody decides on their own membership. Removals
     * take effect when the review completes.
     */
    decideReview: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        reviewId: string;
        decisions: Array<{ identityId: string; decision: TeamReviewDecision; note?: string }>;
      },
    ): Promise<TeamReviewView> =>
      teamOperation(
        credential,
        input.tenantId,
        await reviewTeamId(input.tenantId, input.reviewId),
        'iam:teams:update',
        'maintainer',
        async ({ tx, principal, team, via }) => {
          const review = await loadReview(tx, team, input.reviewId);
          if (review.status !== 'open')
            throw new IamError('INVALID_TRANSITION', 'The review is no longer open', 409);
          if (
            !Array.isArray(input.decisions) ||
            input.decisions.length < 1 ||
            input.decisions.length > 200
          )
            throw new IamError('INVALID_INPUT', 'Provide 1-200 decisions');
          const now = ctx.now();
          const tally = { keep: 0, remove: 0 };
          for (const entry of input.decisions) {
            if (!entry || typeof entry !== 'object')
              throw new IamError('INVALID_INPUT', 'Each decision needs identityId and decision');
            const identityId = text(entry.identityId, 'identityId', 128);
            const decision = choice(entry.decision, reviewDecisions, 'decision');
            const note =
              entry.note === undefined || entry.note === ''
                ? undefined
                : text(entry.note, 'note', 1000);
            if (identityId === principal.identity.id)
              throw new IamError('ACCESS_DENIED', 'Nobody reviews their own membership', 403);
            const item = (
              await tx.find<TeamReviewItem>(teamReviewCollections.items, {
                tenantId: team.tenantId,
                uniqueKey: `${review.id}:${identityId}`,
              })
            )[0];
            if (!item) throw new IamError('NOT_FOUND', 'This person is not under review', 404);
            const { note: _previous, ...rest } = item;
            await tx.put<TeamReviewItem>(teamReviewCollections.items, {
              ...rest,
              decision,
              decidedBy: principal.identity.id,
              decidedAt: now,
              ...(note ? { note } : {}),
            });
            tally[decision]++;
          }
          await audit(tx, principal, 'team:review:decide', team, {
            reviewId: review.id,
            ...tally,
            ...(via !== 'permission' ? { via } : {}),
          });
          return reviewView(tx, review, team, true);
        },
      ),
    /**
     * Completes an open review: people decided `remove` leave the team (and lose what it gave them), and the people
     * nobody decided on follow `onUndecided`. Maintainers may complete it once every person is decided; administrators
     * at any time. Audited as `team:review:complete` with the counts, and `team:member:remove` (`source: review`) per
     * removal.
     */
    completeReview: async (
      credential: CredentialInput,
      input: { tenantId: string; reviewId: string },
    ): Promise<TeamReviewView> => {
      const teamId = await reviewTeamId(input.tenantId, input.reviewId);
      return reconciling(input.tenantId, (touch) =>
        teamOperation(
          credential,
          input.tenantId,
          teamId,
          'iam:teams:update',
          'maintainer',
          async ({ tx, principal, team, via }) => {
            const review = await loadReview(tx, team, input.reviewId);
            if (review.status !== 'open')
              throw new IamError('INVALID_TRANSITION', 'The review is no longer open', 409);
            if (via !== 'permission') {
              const undecided = (
                await tx.find<TeamReviewItem>(teamReviewCollections.items, {
                  tenantId: team.tenantId,
                  reviewId: review.id,
                })
              ).filter((item) => item.decision === undefined);
              if (undecided.length)
                throw new IamError(
                  'INVALID_TRANSITION',
                  `Decide every person first (${undecided.length} left); an administrator can complete it early`,
                  409,
                );
            }
            const done = await completeTeamReview(ctx, tx, review, principal);
            touch(done.removed);
            return reviewView(tx, done.review, team, true);
          },
        ),
      );
    },
    /** Cancels an open review without changing the team. Administrators only. */
    cancelReview: async (
      credential: CredentialInput,
      input: { tenantId: string; reviewId: string },
    ): Promise<TeamReviewView> =>
      teamOperation(
        credential,
        input.tenantId,
        await reviewTeamId(input.tenantId, input.reviewId),
        'iam:teams:update',
        undefined,
        async ({ tx, principal, team }) => {
          const review = await loadReview(tx, team, input.reviewId);
          if (review.status !== 'open')
            throw new IamError('INVALID_TRANSITION', 'The review is no longer open', 409);
          const { uniqueKey: _open, ...rest } = review;
          const cancelled = await tx.put<TeamReview>(teamReviewCollections.reviews, {
            ...rest,
            status: 'cancelled',
            completedAt: ctx.now(),
            completedBy: principal.identity.id,
          });
          await audit(tx, principal, 'team:review:cancel', team, { reviewId: review.id });
          return reviewView(tx, cancelled, team, false);
        },
      ),
  };
  return {
    api,
    helpers: {
      createTeam,
      updateTeam,
      deleteTeam,
      putMember,
      removeMember,
      memberRecord,
      assertAuthorityOver,
      allTeams,
    },
  };

  /** Routing only: the team a review belongs to (the operation re-reads and checks the review under authorization). */
  async function reviewTeamId(tenantIdInput: unknown, reviewIdInput: unknown): Promise<string> {
    const tenantId = text(tenantIdInput, 'tenantId');
    const reviewId = text(reviewIdInput, 'reviewId', 128);
    return ctx.store.transaction(async (tx) => {
      const review = await tx.get<TeamReview>(teamReviewCollections.reviews, reviewId);
      return review?.tenantId === tenantId ? review.teamId : reviewId;
    });
  }

  async function loadReview(tx: IamStore, team: Team, reviewId: unknown): Promise<TeamReview> {
    const review = await tx.get<TeamReview>(
      teamReviewCollections.reviews,
      text(reviewId, 'reviewId', 128),
    );
    if (!review || review.tenantId !== team.tenantId || review.teamId !== team.id)
      throw new IamError('NOT_FOUND', 'Resource not found', 404);
    return review;
  }

  async function reviewView(
    tx: IamStore,
    review: TeamReview,
    team: Team,
    withItems: boolean,
  ): Promise<TeamReviewView> {
    const items = (
      await tx.find<TeamReviewItem>(teamReviewCollections.items, {
        tenantId: review.tenantId,
        reviewId: review.id,
      })
    ).sort((a, b) => (a.identityId < b.identityId ? -1 : 1));
    const directory = await people(tx, [
      review.startedBy,
      ...items.flatMap((item) => [item.identityId, ...(item.decidedBy ? [item.decidedBy] : [])]),
    ]);
    const counts = { total: items.length, keep: 0, remove: 0, undecided: 0 };
    for (const item of items) counts[item.decision ?? 'undecided']++;
    return {
      id: review.id,
      team: ref(team),
      status: review.status,
      onUndecided: review.onUndecided,
      startedAt: review.startedAt,
      startedBy: directory.get(review.startedBy)!,
      dueAt: review.dueAt,
      ...(review.note ? { note: review.note } : {}),
      ...(review.completedAt !== undefined ? { completedAt: review.completedAt } : {}),
      ...(review.completedBy ? { completedBy: review.completedBy } : {}),
      ...(review.outcome ? { outcome: review.outcome } : {}),
      counts,
      ...(withItems
        ? {
            items: items
              .map((item) => ({
                person: directory.get(item.identityId)!,
                role: item.role,
                ...(item.decision ? { decision: item.decision } : {}),
                ...(item.decidedBy ? { decidedBy: directory.get(item.decidedBy)! } : {}),
                ...(item.decidedAt !== undefined ? { decidedAt: item.decidedAt } : {}),
                ...(item.note ? { note: item.note } : {}),
              }))
              .sort(
                (a, b) =>
                  Number(b.role === 'maintainer') - Number(a.role === 'maintainer') ||
                  (a.person.email ?? a.person.name).localeCompare(b.person.email ?? b.person.name),
              ),
          }
        : {}),
    };
  }

  /** A pending request past its lapse time reads as expired. */
  function lapse(request: TeamJoinRequest): TeamJoinRequest {
    return request.status === 'pending' && request.expiresAt <= ctx.now()
      ? { ...request, status: 'expired' }
      : request;
  }

  async function membershipsOf(
    tx: IamStore,
    tenantId: string,
    identityId: string,
  ): Promise<MyTeams['teams']> {
    const now = ctx.now();
    const teams = await allTeams(tx, tenantId);
    return (await tx.find<TeamMember>(teamCollections.members, { tenantId, identityId }))
      .filter((member) => liveTeamMember(member, now) && teams.has(member.teamId))
      .map((member) => {
        const team = teams.get(member.teamId)!;
        return {
          ...ref(team),
          ...(team.description ? { description: team.description } : {}),
          role: member.role,
          ...(member.expiresAt !== undefined ? { expiresAt: member.expiresAt } : {}),
          parents: teamChain(teams, team.id).slice(1).reverse().map(ref),
        };
      })
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async function decide(
    credential: CredentialInput,
    input: { tenantId: string; requestId: string; expiresAt?: number; note?: string },
    outcome: 'approved' | 'denied',
  ): Promise<TeamJoinRequestView> {
    const tenantId = text(input.tenantId, 'tenantId');
    const requestId = text(input.requestId, 'requestId', 128);
    // Routing only: the operation below re-reads and checks the request under authorization.
    const teamId = await ctx.store.transaction(async (tx) => {
      const request = await tx.get<TeamJoinRequest>(teamCollections.requests, requestId);
      return request?.tenantId === tenantId ? request.teamId : requestId;
    });
    const note =
      input.note === undefined || input.note === '' ? undefined : text(input.note, 'note', 1000);
    return reconciling(tenantId, (touch) =>
      teamOperation(
        credential,
        tenantId,
        teamId,
        'iam:teams:update',
        'maintainer',
        async (mutation) => {
          const { tx, principal, team } = mutation;
          const request = await ctx.scoped<TeamJoinRequest>(
            tx,
            teamCollections.requests,
            requestId,
            tenantId,
          );
          if (request.teamId !== team.id)
            throw new IamError('NOT_FOUND', 'Resource not found', 404);
          if (lapse(request).status !== 'pending')
            throw new IamError('INVALID_TRANSITION', 'The request is no longer pending', 409);
          if (request.identityId === principal.identity.id)
            throw new IamError('ACCESS_DENIED', 'Nobody decides their own join request', 403);
          if (outcome === 'approved') {
            if (mutation.via === 'permission')
              await assertAuthorityOver(
                tx,
                principal,
                team.tenantId,
                teamChain(await allTeams(tx, team.tenantId), team.id),
              );
            await putMember(
              mutation,
              {
                identityId: request.identityId,
                ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
              },
              'approve',
            );
            touch([request.identityId]);
          }
          const decided = await tx.put<TeamJoinRequest>(teamCollections.requests, {
            ...request,
            status: outcome,
            decidedBy: principal.identity.id,
            decidedAt: ctx.now(),
            ...(note ? { note } : {}),
          });
          await email(tx, tenantId, [request.identityId], 'team-join-decided', {
            teamId: team.id,
            teamName: team.name,
            decision: outcome,
            ...(note ? { note } : {}),
          });
          await audit(
            tx,
            principal,
            outcome === 'approved' ? 'team:join:approve' : 'team:join:deny',
            team,
            {
              requestId: request.id,
              identityId: request.identityId,
              ...(mutation.via !== 'permission' ? { via: mutation.via } : {}),
            },
          );
          return requestView(tx, decided);
        },
      ),
    );
  }
}

/** The `teams` API group. */
export function createTeamsApi(ctx: ServerContext) {
  return teamModule(ctx).api;
}

/**
 * Transaction-level team changes for configuration sync (org-sync.ts): the same validation, backing-group upkeep,
 * and audit events as the API. Callers authorize each change first.
 */
export function teamMutations(ctx: ServerContext) {
  return teamModule(ctx).helpers;
}
