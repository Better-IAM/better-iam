import {
  IamError,
  type IamStore,
  type Identity,
  type Json,
  type PolicyDocument,
  type StoredRecord,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { Binding, BindingActivation, Group, GroupMember, Policy, Role } from './models.js';
import { id } from './utils.js';

/**
 * Teams inside an organization: named groups of people with maintainers who manage the membership themselves, nested
 * under parent teams, optionally in a department. Every team owns a backing group (`Team.groupId`, marked with
 * `Group.teamId`) whose memberships this module writes: a team's backing group holds its own live members and those of
 * every descendant team, so a child team's members receive whatever is bound to the parent team. Role bindings,
 * relationships, separation of duties, reviews and analysis all read ordinary group memberships and need nothing else.
 */

/** Collections owned by the teams module. */
export const teamCollections = {
  teams: 'teams',
  members: 'teamMembers',
  requests: 'teamJoinRequests',
} as const;

/** How members join: only by being added (`closed`), or by asking a maintainer (`request`). */
export type TeamJoinPolicy = 'closed' | 'request';
/** Who manages membership: the team's maintainers as well as administrators, or administrators only. */
export type TeamMemberManagement = 'maintainers' | 'admins';
/** A maintainer manages the team's membership (and that of its descendant teams); a member only belongs. */
export type TeamRole = 'maintainer' | 'member';

/** A team; slugs are unique per tenant (uniqueKey `slug:{slug}`). */
export interface Team extends StoredRecord {
  name: string;
  slug: string;
  description?: string;
  /** The parent team: this team's members also belong to it (and receive what is bound to it). */
  parentId?: string;
  /** The department the team belongs to (departments.ts); informational and used for roll-ups. */
  departmentId?: string;
  /** The team-managed backing group; bind roles to it (`subjectType: 'group'`) to give the team access. */
  groupId: string;
  joinPolicy: TeamJoinPolicy;
  memberManagement: TeamMemberManagement;
  /**
   * Team sync: ordinary groups (such as SCIM-provisioned directory groups) whose members are kept as members of the
   * team (`syncTeamsFromGroups`). Synced memberships carry `source: 'sync'`; people added by hand are never touched.
   */
  syncGroupIds?: string[];
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

/** One person's direct membership of one team (uniqueKey `{teamId}:{identityId}`). */
export interface TeamMember extends StoredRecord {
  teamId: string;
  identityId: string;
  role: TeamRole;
  addedAt: number;
  addedBy: string;
  /** Temporary membership: past this time the person no longer belongs (the backing group membership ends with it). */
  expiresAt?: number;
  /** `sync` when team sync added the person from a source group (then it also removes them); absent for manual members. */
  source?: 'sync';
}

export type TeamJoinRequestStatus = 'pending' | 'approved' | 'denied' | 'cancelled' | 'expired';
/** A person's request to join a team whose join policy is `request`; `expiresAt` is when a pending request lapses. */
export interface TeamJoinRequest extends StoredRecord {
  teamId: string;
  identityId: string;
  status: TeamJoinRequestStatus;
  requestedAt: number;
  expiresAt: number;
  justification?: string;
  decidedBy?: string;
  decidedAt?: number;
  note?: string;
}

/** Deepest team nesting (a team and nine levels of ancestors). */
export const maxTeamDepth = 10;
/** Teams per tenant. */
export const maxTeams = 1000;
const slugPattern = /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/;

/** A team slug: 1-64 lowercase letters, digits or inner hyphens. */
export function teamSlug(value: unknown): string {
  if (typeof value !== 'string' || !slugPattern.test(value))
    throw new IamError(
      'INVALID_INPUT',
      'slug must use 1-64 lowercase letters, digits, or inner hyphens',
    );
  return value;
}

/** A slug derived from a team name ("Platform Team" → `platform-team`), or undefined when nothing usable is left. */
export function slugFromName(name: string): string | undefined {
  const candidate = name
    .normalize('NFKD')
    .replace(/\p{M}/gu, '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 64)
    .replace(/-+$/g, '');
  return candidate && slugPattern.test(candidate) ? candidate : undefined;
}

/** Whether a direct membership counts at `at` (no expiry, or one still ahead). */
export function liveTeamMember(member: TeamMember, at: number): boolean {
  return member.expiresAt === undefined || member.expiresAt > at;
}

/** Loads a team of the tenant or fails with NOT_FOUND. */
export async function loadTeam(tx: IamStore, tenantId: string, teamId: unknown): Promise<Team> {
  if (typeof teamId !== 'string' || !teamId) throw new IamError('INVALID_INPUT', 'Invalid teamId');
  const team = await tx.get<Team>(teamCollections.teams, teamId);
  if (!team || team.tenantId !== tenantId) throw new IamError('NOT_FOUND', 'Team not found', 404);
  return team;
}

/** The team followed by its ancestors, nearest first; tolerant of a missing parent (the chain stops there). */
export function teamChain(teams: ReadonlyMap<string, Team>, teamId: string): Team[] {
  const chain: Team[] = [];
  const seen = new Set<string>();
  let current = teams.get(teamId);
  while (current && !seen.has(current.id) && chain.length <= maxTeamDepth) {
    chain.push(current);
    seen.add(current.id);
    current = current.parentId ? teams.get(current.parentId) : undefined;
  }
  return chain;
}

/** Every team below `teamId` (children, grandchildren, …), not including the team itself. */
export function teamDescendants(teams: Iterable<Team>, teamId: string): Team[] {
  const children = new Map<string, Team[]>();
  for (const team of teams)
    if (team.parentId) children.set(team.parentId, [...(children.get(team.parentId) ?? []), team]);
  const result: Team[] = [];
  const seen = new Set([teamId]);
  const queue = [...(children.get(teamId) ?? [])];
  while (queue.length) {
    const next = queue.shift()!;
    if (seen.has(next.id)) continue;
    seen.add(next.id);
    result.push(next);
    queue.push(...(children.get(next.id) ?? []));
  }
  return result;
}

async function tenantTeams(tx: IamStore, tenantId: string): Promise<Map<string, Team>> {
  return new Map(
    (await tx.find<Team>(teamCollections.teams, { tenantId })).map((team) => [team.id, team]),
  );
}

/**
 * The teams a person belongs to at `at` (default now): their live direct memberships (oldest first) and, with
 * `includeAncestors`, the parent teams those memberships make them part of. Team IDs, never backing group IDs.
 * There is no membership history, so callers that attribute something to teams should call this when it happens.
 */
export async function teamsOf(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  options: { at?: number; includeAncestors?: boolean } = {},
): Promise<string[]> {
  const at = options.at ?? Date.now();
  const direct = (await tx.find<TeamMember>(teamCollections.members, { tenantId, identityId }))
    .filter((member) => liveTeamMember(member, at))
    .sort((a, b) => a.addedAt - b.addedAt || (a.teamId < b.teamId ? -1 : 1));
  if (!direct.length) return [];
  const teams = await tenantTeams(tx, tenantId);
  const ids = direct.map((member) => member.teamId).filter((teamId) => teams.has(teamId));
  if (!options.includeAncestors) return ids;
  const result = new Set(ids);
  for (const teamId of ids) for (const team of teamChain(teams, teamId)) result.add(team.id);
  return [...result];
}

/** The person's oldest live direct team membership, for callers that attribute to one team only. */
export async function primaryTeamOf(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  at?: number,
): Promise<string | undefined> {
  return (await teamsOf(tx, tenantId, identityId, at === undefined ? {} : { at }))[0];
}

/** The live direct maintainers of a team (identity IDs, oldest first). */
export async function teamMaintainers(
  tx: IamStore,
  tenantId: string,
  teamId: string,
  at = Date.now(),
): Promise<string[]> {
  return (await tx.find<TeamMember>(teamCollections.members, { tenantId, teamId }))
    .filter((member) => member.role === 'maintainer' && liveTeamMember(member, at))
    .sort((a, b) => a.addedAt - b.addedAt || (a.identityId < b.identityId ? -1 : 1))
    .map((member) => member.identityId);
}

/**
 * Whether a person maintains a team: a live maintainer membership of the team itself or, with `includeAncestors`, of
 * any team above it (a parent team's maintainers manage its child teams too).
 */
export async function isTeamMaintainer(
  tx: IamStore,
  tenantId: string,
  teamId: string,
  identityId: string,
  options: { at?: number; includeAncestors?: boolean } = {},
): Promise<boolean> {
  const at = options.at ?? Date.now();
  const memberships = (
    await tx.find<TeamMember>(teamCollections.members, { tenantId, identityId })
  ).filter((member) => member.role === 'maintainer' && liveTeamMember(member, at));
  if (!memberships.length) return false;
  const scope = options.includeAncestors
    ? teamChain(await tenantTeams(tx, tenantId), teamId).map((team) => team.id)
    : [teamId];
  return memberships.some((member) => scope.includes(member.teamId));
}

/** Refuses direct membership changes to a team's backing group: its members come from the team (TEAM_MANAGED). */
export function assertNotTeamGroup(group: Pick<Group, 'teamId'> | undefined): void {
  if (group && typeof group.teamId === 'string')
    throw new IamError(
      'TEAM_MANAGED',
      'This group belongs to a team; manage its members with the teams API',
      409,
    );
}

/** Whether a group is a team's backing group. */
export function isTeamGroup(group: Pick<Group, 'teamId'> | undefined): boolean {
  return Boolean(group && typeof group.teamId === 'string');
}

/** Refuses when any of `groupIds` is a team's backing group (packages, invitations, onboarding grant real groups). */
export async function assertNoTeamGroups(tx: IamStore, groupIds: Iterable<string>): Promise<void> {
  for (const groupId of groupIds) assertNotTeamGroup(await tx.get<Group>('groups', groupId));
}

export interface TeamSyncResult {
  added: number;
  removed: number;
  updated: number;
}

/**
 * Brings the backing groups of `teamIds` and of every team above them in line with team membership: a team's group
 * holds the live direct members of the team and of all its descendant teams (a permanent source wins over a temporary
 * one; otherwise the latest end counts). Deleted identities are left out. Removing a membership also ends the person's
 * activations of the group's eligible bindings, as `groups.removeMember` does. Idempotent.
 */
export async function syncTeamGroups(
  tx: IamStore,
  tenantId: string,
  teamIds: Iterable<string>,
  now: number,
): Promise<TeamSyncResult> {
  const result: TeamSyncResult = { added: 0, removed: 0, updated: 0 };
  const teams = await tenantTeams(tx, tenantId);
  const affected = new Map<string, Team>();
  for (const teamId of teamIds)
    for (const team of teamChain(teams, teamId)) affected.set(team.id, team);
  if (!affected.size) return result;
  const members = (await tx.find<TeamMember>(teamCollections.members, { tenantId })).filter(
    (member) => liveTeamMember(member, now),
  );
  const byTeam = new Map<string, TeamMember[]>();
  for (const member of members)
    byTeam.set(member.teamId, [...(byTeam.get(member.teamId) ?? []), member]);
  const usable = new Map<string, boolean>();
  const identityUsable = async (identityId: string) => {
    if (!usable.has(identityId)) {
      const identity = await tx.get<Identity>('identities', identityId);
      usable.set(
        identityId,
        Boolean(identity && identity.tenantId === tenantId && identity.status !== 'deleted'),
      );
    }
    return usable.get(identityId)!;
  };
  for (const team of affected.values()) {
    // Undefined means permanent.
    const desired = new Map<string, number | undefined>();
    for (const source of [team, ...teamDescendants(teams.values(), team.id)])
      for (const member of byTeam.get(source.id) ?? []) {
        if (!(await identityUsable(member.identityId))) continue;
        const known = desired.has(member.identityId);
        const previous = desired.get(member.identityId);
        if (!known) desired.set(member.identityId, member.expiresAt);
        else if (previous !== undefined)
          desired.set(
            member.identityId,
            member.expiresAt === undefined ? undefined : Math.max(previous, member.expiresAt),
          );
      }
    const group = await tx.get<Group>('groups', team.groupId);
    if (!group || group.tenantId !== tenantId) continue;
    const current = await tx.find<GroupMember>('groupMembers', { tenantId, groupId: group.id });
    let bindings: Binding[] | undefined;
    for (const membership of current) {
      if (!desired.has(membership.identityId)) {
        await tx.delete('groupMembers', membership.id);
        bindings ??= await tx.find<Binding>('bindings', {
          tenantId,
          subjectType: 'group',
          subjectId: group.id,
        });
        for (const activation of await tx.find<BindingActivation>('bindingActivations', {
          tenantId,
          identityId: membership.identityId,
        }))
          if (bindings.some((binding) => binding.id === activation.bindingId))
            await tx.delete('bindingActivations', activation.id);
        result.removed++;
        continue;
      }
      const expiresAt = desired.get(membership.identityId);
      desired.delete(membership.identityId);
      if (membership.expiresAt === expiresAt && membership.teamId === team.id) continue;
      const { expiresAt: _previous, packageAssignmentId: _package, ...rest } = membership;
      await tx.put<GroupMember>('groupMembers', {
        ...rest,
        teamId: team.id,
        ...(expiresAt !== undefined ? { expiresAt } : {}),
      });
      result.updated++;
    }
    for (const [identityId, expiresAt] of desired) {
      await tx.insert<GroupMember>('groupMembers', {
        id: id(),
        tenantId,
        uniqueKey: `${group.id}:${identityId}`,
        groupId: group.id,
        identityId,
        teamId: team.id,
        ...(expiresAt !== undefined ? { expiresAt } : {}),
      });
      result.added++;
    }
  }
  return result;
}

/**
 * Removes a person from every team of the tenant (offboarding, deletion) and from the teams' backing groups, and
 * cancels their pending join requests. Returns the number of team memberships removed.
 */
export async function removeFromAllTeams(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  now: number,
): Promise<number> {
  const memberships = await tx.find<TeamMember>(teamCollections.members, {
    tenantId,
    identityId,
  });
  for (const member of memberships) await tx.delete(teamCollections.members, member.id);
  for (const request of await tx.find<TeamJoinRequest>(teamCollections.requests, {
    tenantId,
    identityId,
    status: 'pending',
  }))
    await tx.put<TeamJoinRequest>(teamCollections.requests, {
      ...request,
      status: 'cancelled',
      decidedAt: now,
    });
  if (memberships.length)
    await syncTeamGroups(
      tx,
      tenantId,
      memberships.map((member) => member.teamId),
      now,
    );
  // Whatever still ties the person to a backing group (records written before a repair) goes as well.
  for (const membership of await tx.find<GroupMember>('groupMembers', { tenantId, identityId }))
    if (typeof membership.teamId === 'string') await tx.delete('groupMembers', membership.id);
  return memberships.length;
}

/**
 * Which organization-structure keys the documents name anywhere (condition keys, condition values such as
 * `${principal.departmentId}`, resource patterns), so decisions read team and department records only when needed.
 */
export function mentionedOrgKeys(documents: Iterable<PolicyDocument>): {
  teams: boolean;
  departments: boolean;
} {
  const found = { teams: false, departments: false };
  for (const document of documents) {
    const serialized = JSON.stringify(document.statements);
    if (serialized.includes('principal.teams')) found.teams = true;
    if (serialized.includes('principal.department')) found.departments = true;
    if (found.teams && found.departments) break;
  }
  return found;
}

/**
 * Policy context for a person in their own tenant: `principal.teams` lists the teams they belong to directly and the
 * teams above those (the same teams whose backing groups hold them). Nothing for other principals.
 */
export async function teamContext(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  now: number,
): Promise<{ 'principal.teams': string[] }> {
  return {
    'principal.teams': (
      await teamsOf(tx, tenantId, identityId, { at: now, includeAncestors: true })
    ).sort(),
  };
}

/** At most this many source groups per team. */
export const maxSyncGroups = 10;

export interface TeamGroupSyncResult {
  added: number;
  removed: number;
  updated: number;
  /** Teams whose membership changed. */
  teams: string[];
}

/**
 * Team sync: brings the synced members of teams with `syncGroupIds` in line with their source groups. Every active
 * person with a live membership of a source group is a member (added as `member` with `source: 'sync'`, expiring when
 * their last source membership does); synced members who left every source group are removed. Manual memberships are
 * never changed. `groupId` limits the run to teams syncing from that group, `teamIds` to those teams. Changes are
 * audited as `team:member:add` / `team:member:remove` with `source: 'sync'` under `actorId`.
 */
export async function syncTeamsFromGroups(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
  options: { groupId?: string; teamIds?: readonly string[]; actorId: string },
): Promise<TeamGroupSyncResult> {
  const result: TeamGroupSyncResult = { added: 0, removed: 0, updated: 0, teams: [] };
  // Named teams are included even without sources, so turning sync off removes their synced members.
  const synced = (await tx.find<Team>(teamCollections.teams, { tenantId })).filter(
    (team) =>
      (options.teamIds !== undefined
        ? options.teamIds.includes(team.id)
        : Boolean(team.syncGroupIds?.length)) &&
      (options.groupId === undefined || (team.syncGroupIds ?? []).includes(options.groupId)),
  );
  if (!synced.length) return result;
  const now = ctx.now();
  const people = new Map<string, boolean>();
  const active = async (identityId: string) => {
    if (!people.has(identityId)) {
      const identity = await tx.get<Identity>('identities', identityId);
      people.set(
        identityId,
        Boolean(
          identity &&
            identity.tenantId === tenantId &&
            identity.kind === 'user' &&
            identity.status === 'active' &&
            !ctx.identityExpired(identity),
        ),
      );
    }
    return people.get(identityId)!;
  };
  const audit = (action: string, team: Team, metadata: Record<string, Json>) =>
    ctx.events.recordAudit(tx, {
      id: id(),
      tenantId,
      actorId: options.actorId,
      action,
      resourceId: team.id,
      timestamp: now,
      outcome: 'allow',
      metadata: { team: team.slug, source: 'sync', ...metadata },
    });
  for (const team of synced) {
    // Undefined means permanent: the latest end among the person's source memberships.
    const desired = new Map<string, number | undefined>();
    for (const groupId of team.syncGroupIds ?? [])
      for (const membership of await tx.find<GroupMember>('groupMembers', { tenantId, groupId })) {
        if (!ctx.liveMembership(membership) || !(await active(membership.identityId))) continue;
        const known = desired.has(membership.identityId);
        const previous = desired.get(membership.identityId);
        if (!known) desired.set(membership.identityId, membership.expiresAt);
        else if (previous !== undefined)
          desired.set(
            membership.identityId,
            membership.expiresAt === undefined
              ? undefined
              : Math.max(previous, membership.expiresAt),
          );
      }
    let changed = false;
    const records = await tx.find<TeamMember>(teamCollections.members, {
      tenantId,
      teamId: team.id,
    });
    for (const member of records) {
      const live = liveTeamMember(member, now);
      if (!desired.has(member.identityId)) {
        if (member.source === 'sync' && live) {
          await tx.delete(teamCollections.members, member.id);
          await audit('team:member:remove', team, { identityId: member.identityId });
          result.removed++;
          changed = true;
        }
        continue;
      }
      if (!live) continue;
      const expiresAt = desired.get(member.identityId);
      desired.delete(member.identityId);
      // A synced member's end follows the source memberships; manual members keep their own.
      if (member.source === 'sync' && member.expiresAt !== expiresAt) {
        const { expiresAt: _previous, ...rest } = member;
        await tx.put<TeamMember>(teamCollections.members, {
          ...rest,
          ...(expiresAt !== undefined ? { expiresAt } : {}),
        });
        result.updated++;
        changed = true;
      }
    }
    for (const [identityId, expiresAt] of desired) {
      const uniqueKey = `${team.id}:${identityId}`;
      const lapsed = records.find((member) => member.uniqueKey === uniqueKey);
      const record: TeamMember = {
        id: lapsed?.id ?? id(),
        tenantId,
        uniqueKey,
        teamId: team.id,
        identityId,
        role: 'member',
        addedAt: now,
        addedBy: options.actorId,
        source: 'sync',
        ...(expiresAt !== undefined ? { expiresAt } : {}),
      };
      await (lapsed
        ? tx.put<TeamMember>(teamCollections.members, record)
        : tx.insert<TeamMember>(teamCollections.members, record));
      await audit('team:member:add', team, {
        identityId,
        role: 'member',
        ...(expiresAt !== undefined ? { expiresAt } : {}),
      });
      result.added++;
      changed = true;
    }
    if (changed) {
      await syncTeamGroups(tx, tenantId, [team.id], now);
      result.teams.push(team.id);
    }
  }
  return result;
}

/** Validates a team's source groups: ordinary groups (not teams' backing groups) of the tenant, at most ten. */
export async function teamSyncGroups(
  tx: IamStore,
  tenantId: string,
  value: unknown,
): Promise<string[]> {
  if (!Array.isArray(value) || value.length > maxSyncGroups)
    throw new IamError('INVALID_INPUT', `syncGroupIds must list at most ${maxSyncGroups} groups`);
  const ids = [...new Set(value.map((item) => String(item)))];
  for (const groupId of ids) {
    const group = await tx.get<Group>('groups', groupId);
    if (!group || group.tenantId !== tenantId)
      throw new IamError('NOT_FOUND', `Group ${groupId} not found`, 404);
    if (isTeamGroup(group))
      throw new IamError('INVALID_INPUT', 'A team cannot sync from another team’s backing group');
  }
  return ids;
}

/** Teams that sync their members from a group (a group they depend on). */
export async function teamsSyncingFrom(
  tx: IamStore,
  tenantId: string,
  groupId: string,
): Promise<Team[]> {
  return (await tx.find<Team>(teamCollections.teams, { tenantId })).filter((team) =>
    team.syncGroupIds?.includes(groupId),
  );
}

/**
 * The bindings on the backing groups of `teamIds` and of every team above them: what membership of those teams hands
 * out. Changing who is in them needs the grant authority behind each binding, as `groups.addMember` does for a group.
 */
export async function teamChainBindings(
  tx: IamStore,
  tenantId: string,
  teamIds: Iterable<string>,
): Promise<Binding[]> {
  const teams = await tenantTeams(tx, tenantId);
  const groupIds = new Set<string>();
  for (const teamId of teamIds)
    for (const team of teamChain(teams, teamId)) groupIds.add(team.groupId);
  const bindings: Binding[] = [];
  for (const groupId of groupIds)
    bindings.push(
      ...(await tx.find<Binding>('bindings', {
        tenantId,
        subjectType: 'group',
        subjectId: groupId,
      })),
    );
  return bindings;
}

/**
 * Whether a role, or a role it inherits, holds a deny statement (in its own document or an attached policy). Leaving
 * a group bound to such a role lifts a restriction, which needs the same authority as removing the person would.
 */
export async function roleHoldsDeny(tx: IamStore, roleId: string): Promise<boolean> {
  const seen = new Set<string>();
  const queue = [roleId];
  while (queue.length) {
    const current = queue.shift()!;
    if (seen.has(current)) continue;
    seen.add(current);
    const role = await tx.get<Role>('roles', current);
    if (!role) continue;
    const documents = role.document ? [role.document] : [];
    for (const policyId of role.policyIds ?? []) {
      const policy = await tx.get<Policy>('policies', policyId);
      if (policy) documents.push(policy.document);
    }
    if (
      documents.some((document) =>
        document.statements.some((statement) => statement.effect === 'deny'),
      )
    )
      return true;
    queue.push(...(role.inherits ?? []));
  }
  return false;
}
