import {
  IamError,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type Tenant,
} from '@better-iam/core';
import { createBinding, deleteBinding } from './api/bindings.js';
import { departmentMutations } from './api/departments.js';
import { teamMutations } from './api/teams.js';
import type { ServerContext } from './context.js';
import {
  departmentChain,
  departmentCode,
  departmentCollections,
  type Department,
  type DepartmentMember,
} from './departments.js';
import type { Binding } from './models.js';
import { mapRuleValues, type AutoAssignInput, type RuleEnvironment } from './package-rules.js';
import type { ConfigChange } from './sync.js';
import {
  liveTeamMember,
  slugFromName,
  syncTeamGroups,
  teamChain,
  teamCollections,
  teamSlug,
  type Team,
  type TeamJoinPolicy,
  type TeamMember,
  type TeamMemberManagement,
  type TeamRole,
} from './teams.js';
import { strings, text } from './validation.js';

/**
 * Configuration as code for teams and departments: the `teams` and `departments` kinds of a tenant configuration
 * (sync.ts). Teams are matched by slug and departments by name (ignoring case); people are named by email and roles by
 * name, so one document applies to several environments. Temporary team memberships and join requests are runtime
 * state and never synced.
 */

/** A team in a configuration document. */
export interface TenantConfigTeam {
  name: string;
  /** The key teams are matched by; derived from the name when left out. */
  slug: string;
  description?: string;
  /** Slug of the parent team. */
  parent?: string;
  /** Name of the department the team belongs to. */
  department?: string;
  /** Default `closed`. */
  joinPolicy?: TeamJoinPolicy;
  /** Default `maintainers`. */
  memberManagement?: TeamMemberManagement;
  /** Maintainer emails. With `members`, the team's permanent direct members are made to match exactly. */
  maintainers?: string[];
  /** Member emails (see `maintainers`). */
  members?: string[];
  /** Names of the roles the team holds as standing bindings; when present, made to match exactly. */
  roles?: string[];
  /** Team sync: names of the groups whose members the team keeps (their synced members are runtime state). */
  syncGroups?: string[];
}
/** A department in a configuration document. */
export interface TenantConfigDepartment {
  name: string;
  code?: string;
  description?: string;
  /** Name of the parent department. */
  parent?: string;
  /** Email of the department head. */
  head?: string;
  costCenter?: string;
  /** People's emails; when present, the department's people are made to match exactly. */
  members?: string[];
}

export interface OrgPlanned<D, R> {
  change: ConfigChange;
  desired?: D;
  record?: R;
}
export interface OrgPlan {
  teams: OrgPlanned<TenantConfigTeam, Team>[];
  departments: OrgPlanned<TenantConfigDepartment, Department>[];
}

/** The tenant's teams and departments with the records the configuration compares against. */
export interface OrgState {
  teams: Team[];
  /** Live direct team memberships. */
  teamMembers: TeamMember[];
  /** Standing bindings (not eligible, windowed, scheduled, temporary, or from a package) by backing group ID. */
  teamBindings: Map<string, Binding[]>;
  departments: Department[];
  placements: DepartmentMember[];
}

const lower = (value: string) => value.trim().toLowerCase();
const sortedUnique = (items: string[]) => [...new Set(items)].sort();

/**
 * Birthright rules (access package `autoAssign`) name teams by slug and departments by name in a configuration
 * document; the tenant stores IDs. `orgRuleNames` maps a stored rule's IDs to names (export and plan comparisons).
 */
export function orgRuleNames<T extends Pick<AutoAssignInput, 'include' | 'exclude'>>(
  state: Pick<OrgState, 'teams' | 'departments'>,
  rule: T,
): T {
  const slugs = new Map(state.teams.map((team) => [team.id, team.slug]));
  const names = new Map(state.departments.map((department) => [department.id, department.name]));
  return mapRuleValues(
    mapRuleValues(rule, 'identity.teams', (teamId) => slugs.get(teamId) ?? teamId),
    'identity.departments',
    (departmentId) => names.get(departmentId) ?? departmentId,
  );
}

/**
 * The teams and departments that exist after an apply, for validating package rules at plan time: team slugs, and
 * department names ignoring case. `canonical` rewrites a rule's department names to their spelling in the document
 * (or the tenant), so a case-only difference never shows as a change.
 */
export function orgRuleEnvironmentAfter(
  desired: { teams?: TenantConfigTeam[]; departments?: TenantConfigDepartment[] },
  state: Pick<OrgState, 'teams' | 'departments'>,
  prune: boolean,
): {
  env: NonNullable<RuleEnvironment['org']>;
  canonical<T extends Pick<AutoAssignInput, 'include' | 'exclude'>>(rule: T): T;
} {
  const teams = new Set(
    state.teams
      .filter(
        (record) =>
          !desired.teams || !prune || desired.teams.some((item) => item.slug === record.slug),
      )
      .map((record) => record.slug),
  );
  for (const team of desired.teams ?? []) teams.add(team.slug);
  const departments = new Map<string, string>();
  for (const record of state.departments)
    if (
      !desired.departments ||
      !prune ||
      desired.departments.some((item) => lower(item.name) === lower(record.name))
    )
      departments.set(lower(record.name), record.name);
  for (const department of desired.departments ?? [])
    departments.set(lower(department.name), department.name);
  return {
    env: { teams, departments: { has: (name) => departments.has(lower(name)) } },
    canonical: (rule) =>
      mapRuleValues(rule, 'identity.departments', (name) => departments.get(lower(name)) ?? name),
  };
}

/** Maps a document rule's team slugs and department names to the tenant's IDs (after teams and departments exist). */
export async function orgRuleIds(
  tx: IamStore,
  tenantId: string,
): Promise<<T extends Pick<AutoAssignInput, 'include' | 'exclude'>>(rule: T) => T> {
  const teams = new Map(
    (await tx.find<Team>(teamCollections.teams, { tenantId })).map((team) => [team.slug, team.id]),
  );
  const departments = new Map(
    (await tx.find<Department>(departmentCollections.departments, { tenantId })).map(
      (department) => [lower(department.name), department.id],
    ),
  );
  return (rule) =>
    mapRuleValues(
      mapRuleValues(rule, 'identity.teams', (slug) => teams.get(slug) ?? slug),
      'identity.departments',
      (name) => departments.get(lower(name)) ?? name,
    );
}
/** Stable JSON for comparisons: object keys sorted, undefined dropped. */
function canonical(value: unknown): string {
  return JSON.stringify(value, (_key, item) =>
    item && typeof item === 'object' && !Array.isArray(item)
      ? Object.fromEntries(
          Object.entries(item as Record<string, unknown>)
            .filter(([, entry]) => entry !== undefined)
            .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0)),
        )
      : item,
  );
}
function diff(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((key) => canonical(before[key]) !== canonical(after[key]))
    .sort();
}

function optionalText(item: Record<string, unknown>, key: string, max: number) {
  return item[key] === undefined ? undefined : text(item[key], key, max).trim();
}
function emails(item: Record<string, unknown>, key: string): string[] | undefined {
  return item[key] === undefined ? undefined : sortedUnique(strings(item[key], key).map(lower));
}

/** Validates the `teams` list of a configuration document. */
export function parseTeamsConfig(items: Record<string, unknown>[]): TenantConfigTeam[] {
  const teams = items.map((item): TenantConfigTeam => {
    const name = text(item.name, 'team name', 100).trim();
    const slug = item.slug === undefined ? slugFromName(name) : teamSlug(item.slug);
    if (!slug) throw new IamError('INVALID_INPUT', `Team ${name}: choose a slug`);
    const joinPolicy = item.joinPolicy;
    if (joinPolicy !== undefined && joinPolicy !== 'closed' && joinPolicy !== 'request')
      throw new IamError('INVALID_INPUT', `Team ${slug}: joinPolicy must be closed or request`);
    const management = item.memberManagement;
    if (management !== undefined && management !== 'maintainers' && management !== 'admins')
      throw new IamError(
        'INVALID_INPUT',
        `Team ${slug}: memberManagement must be maintainers or admins`,
      );
    const maintainers = emails(item, 'maintainers');
    const members = emails(item, 'members');
    const both = maintainers?.filter((email) => members?.includes(email)) ?? [];
    if (both.length)
      throw new IamError(
        'INVALID_INPUT',
        `Team ${slug}: ${both[0]} is listed as both maintainer and member`,
      );
    return {
      name,
      slug,
      description: optionalText(item, 'description', 512),
      parent: item.parent === undefined ? undefined : teamSlug(item.parent),
      department: optionalText(item, 'department', 100),
      joinPolicy: joinPolicy as TeamJoinPolicy | undefined,
      memberManagement: management as TeamMemberManagement | undefined,
      maintainers,
      members,
      roles: item.roles === undefined ? undefined : sortedUnique(strings(item.roles, 'roles')),
      syncGroups:
        item.syncGroups === undefined
          ? undefined
          : sortedUnique(strings(item.syncGroups, 'syncGroups')),
    };
  });
  const seen = new Set<string>();
  for (const team of teams) {
    if (seen.has(team.slug)) throw new IamError('INVALID_INPUT', `Duplicate team ${team.slug}`);
    seen.add(team.slug);
  }
  return teams;
}

/** Validates the `departments` list of a configuration document. */
export function parseDepartmentsConfig(items: Record<string, unknown>[]): TenantConfigDepartment[] {
  const departments = items.map(
    (item): TenantConfigDepartment => ({
      name: text(item.name, 'department name', 100).trim(),
      code: item.code === undefined ? undefined : departmentCode(item.code),
      description: optionalText(item, 'description', 512),
      parent: optionalText(item, 'parent', 100),
      head: item.head === undefined ? undefined : lower(text(item.head, 'head', 254)),
      costCenter: optionalText(item, 'costCenter', 64),
      members: emails(item, 'members'),
    }),
  );
  const names = new Set<string>();
  const codes = new Set<string>();
  for (const department of departments) {
    if (names.has(lower(department.name)))
      throw new IamError('INVALID_INPUT', `Duplicate department ${department.name}`);
    names.add(lower(department.name));
    if (department.code !== undefined) {
      if (codes.has(lower(department.code)))
        throw new IamError('INVALID_INPUT', `Duplicate department code ${department.code}`);
      codes.add(lower(department.code));
    }
  }
  return departments;
}

/** Reads what the `teams` and `departments` kinds compare against. */
export async function readOrgState(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
): Promise<OrgState> {
  const now = ctx.now();
  const teams = (await tx.find<Team>(teamCollections.teams, { tenantId })).sort((a, b) =>
    a.slug < b.slug ? -1 : a.slug > b.slug ? 1 : 0,
  );
  const teamMembers = (await tx.find<TeamMember>(teamCollections.members, { tenantId })).filter(
    (member) => liveTeamMember(member, now),
  );
  const teamBindings = new Map<string, Binding[]>();
  for (const team of teams)
    teamBindings.set(
      team.groupId,
      (
        await tx.find<Binding>('bindings', {
          tenantId,
          subjectType: 'group',
          subjectId: team.groupId,
        })
      ).filter(
        (binding) =>
          !binding.eligible &&
          binding.window === undefined &&
          binding.startsAt === undefined &&
          binding.expiresAt === undefined &&
          binding.packageAssignmentId === undefined,
      ),
    );
  const departments = (
    await tx.find<Department>(departmentCollections.departments, { tenantId })
  ).sort((a, b) => a.name.localeCompare(b.name, 'en'));
  const placements = await tx.find<DepartmentMember>(departmentCollections.members, {
    tenantId,
  });
  return { teams, teamMembers, teamBindings, departments, placements };
}

interface Directory {
  /** Identity ID to lowercase email, for people who are not deleted. */
  identityEmails: Map<string, string>;
  /** Role ID to name. */
  roleNames: Map<string, string>;
  /** Group ID to name, for ordinary (not team-backed) groups. */
  groupNames: Map<string, string>;
}

function exportedTeam(
  team: Team,
  state: OrgState,
  directory: Directory,
): Omit<TenantConfigTeam, 'name' | 'slug'> {
  const byId = new Map(state.teams.map((item) => [item.id, item]));
  const departments = new Map(state.departments.map((item) => [item.id, item]));
  // Temporary and synced memberships are runtime state.
  const permanent = state.teamMembers.filter(
    (member) =>
      member.teamId === team.id && member.expiresAt === undefined && member.source !== 'sync',
  );
  const emailsOf = (role: TeamRole) =>
    sortedUnique(
      permanent
        .filter((member) => member.role === role)
        .flatMap((member) => {
          const email = directory.identityEmails.get(member.identityId);
          return email ? [email] : [];
        }),
    );
  const parent = team.parentId ? byId.get(team.parentId) : undefined;
  const department = team.departmentId ? departments.get(team.departmentId) : undefined;
  return {
    ...(team.description !== undefined ? { description: team.description } : {}),
    ...(parent ? { parent: parent.slug } : {}),
    ...(department ? { department: department.name } : {}),
    joinPolicy: team.joinPolicy,
    memberManagement: team.memberManagement,
    maintainers: emailsOf('maintainer'),
    members: emailsOf('member'),
    roles: sortedUnique(
      (state.teamBindings.get(team.groupId) ?? []).flatMap((binding) => {
        const name = directory.roleNames.get(binding.roleId);
        return name === undefined ? [] : [name];
      }),
    ),
    ...(team.syncGroupIds?.length
      ? {
          syncGroups: sortedUnique(
            team.syncGroupIds.flatMap((groupId) => {
              const name = directory.groupNames.get(groupId);
              return name === undefined ? [] : [name];
            }),
          ),
        }
      : {}),
  };
}

function exportedDepartment(
  department: Department,
  state: OrgState,
  directory: Directory,
): Omit<TenantConfigDepartment, 'name'> {
  const byId = new Map(state.departments.map((item) => [item.id, item]));
  const parent = department.parentId ? byId.get(department.parentId) : undefined;
  const head = department.headId ? directory.identityEmails.get(department.headId) : undefined;
  return {
    ...(department.code !== undefined ? { code: department.code } : {}),
    ...(department.description !== undefined ? { description: department.description } : {}),
    ...(parent ? { parent: parent.name } : {}),
    ...(head ? { head } : {}),
    ...(department.costCenter !== undefined ? { costCenter: department.costCenter } : {}),
    members: sortedUnique(
      state.placements
        .filter((placement) => placement.departmentId === department.id)
        .flatMap((placement) => {
          const email = directory.identityEmails.get(placement.identityId);
          return email ? [email] : [];
        }),
    ),
  };
}

/** The tenant's teams and departments in document form; each kind appears only when the tenant has some. */
export function exportOrg(
  state: OrgState,
  directory: Directory,
): { teams?: TenantConfigTeam[]; departments?: TenantConfigDepartment[] } {
  return {
    ...(state.departments.length
      ? {
          departments: state.departments.map((department) => ({
            name: department.name,
            ...exportedDepartment(department, state, directory),
          })),
        }
      : {}),
    ...(state.teams.length
      ? {
          teams: state.teams.map((team) => ({
            name: team.name,
            slug: team.slug,
            ...exportedTeam(team, state, directory),
          })),
        }
      : {}),
  };
}

/** Normalizes a desired team to its exported form (defaults filled, membership lists only when given). */
function desiredTeamForm(team: TenantConfigTeam): Omit<TenantConfigTeam, 'name' | 'slug'> {
  const managesMembers = team.maintainers !== undefined || team.members !== undefined;
  return {
    ...(team.description !== undefined ? { description: team.description } : {}),
    ...(team.parent !== undefined ? { parent: team.parent } : {}),
    ...(team.department !== undefined ? { department: team.department } : {}),
    joinPolicy: team.joinPolicy ?? 'closed',
    memberManagement: team.memberManagement ?? 'maintainers',
    ...(managesMembers ? { maintainers: team.maintainers ?? [], members: team.members ?? [] } : {}),
    ...(team.roles !== undefined ? { roles: team.roles } : {}),
    ...(team.syncGroups?.length ? { syncGroups: team.syncGroups } : {}),
  };
}
function desiredDepartmentForm(
  department: TenantConfigDepartment,
): Omit<TenantConfigDepartment, 'name'> {
  return {
    ...(department.code !== undefined ? { code: department.code } : {}),
    ...(department.description !== undefined ? { description: department.description } : {}),
    ...(department.parent !== undefined ? { parent: department.parent } : {}),
    ...(department.head !== undefined ? { head: department.head } : {}),
    ...(department.costCenter !== undefined ? { costCenter: department.costCenter } : {}),
    ...(department.members !== undefined ? { members: department.members } : {}),
  };
}

/**
 * Plans the `teams` and `departments` kinds. References are checked against what will exist after the apply: people
 * now (by email), roles (`roleNamesAfter`), parents and departments from the document or the tenant. Kinds absent
 * from the document are left alone; with `prune`, listed kinds lose the items the document omits.
 */
export function planOrg(
  desired: { teams?: TenantConfigTeam[]; departments?: TenantConfigDepartment[] },
  state: OrgState,
  env: Directory & {
    identitiesByEmail: Map<string, Identity>;
    roleNamesAfter: Set<string>;
    /** Names of the ordinary groups that exist after the apply. */
    groupNamesAfter: Set<string>;
    prune: boolean;
  },
): OrgPlan {
  const plan: OrgPlan = { teams: [], departments: [] };
  const person = (email: string, where: string) => {
    const identity = env.identitiesByEmail.get(email);
    if (!identity || identity.kind !== 'user')
      throw new IamError('INVALID_INPUT', `${where}: unknown person ${email}`);
    return identity;
  };

  // Departments, by name regardless of case.
  const departmentNamesAfter = new Set(
    state.departments
      .filter(
        (record) =>
          !desired.departments ||
          !env.prune ||
          desired.departments.some((item) => lower(item.name) === lower(record.name)),
      )
      .map((record) => lower(record.name)),
  );
  for (const department of desired.departments ?? [])
    departmentNamesAfter.add(lower(department.name));
  if (desired.departments) {
    const existing = new Map(state.departments.map((record) => [lower(record.name), record]));
    const parents = new Map<string, string | undefined>();
    for (const record of state.departments)
      parents.set(
        lower(record.name),
        record.parentId
          ? state.departments.find((item) => item.id === record.parentId)?.name.toLowerCase()
          : undefined,
      );
    for (const department of desired.departments) {
      const where = `Department ${department.name}`;
      if (department.parent !== undefined && !departmentNamesAfter.has(lower(department.parent)))
        throw new IamError('INVALID_INPUT', `${where}: unknown parent ${department.parent}`);
      if (department.head !== undefined) person(department.head, where);
      for (const email of department.members ?? []) person(email, where);
      parents.set(
        lower(department.name),
        department.parent === undefined ? undefined : lower(department.parent),
      );
    }
    for (const name of departmentNamesAfter) {
      const seen = new Set<string>();
      for (let cursor: string | undefined = name; cursor; cursor = parents.get(cursor)) {
        if (seen.has(cursor))
          throw new IamError('INVALID_INPUT', `Departments ${name}: the parents form a cycle`);
        seen.add(cursor);
      }
    }
    for (const department of desired.departments) {
      const record = existing.get(lower(department.name));
      const after = desiredDepartmentForm(department);
      if (!record) {
        plan.departments.push({
          change: { kind: 'department', name: department.name, action: 'create', after },
          desired: department,
        });
        continue;
      }
      const current = exportedDepartment(record, state, env);
      const before: Record<string, unknown> = { ...current };
      if (department.members === undefined) delete before.members;
      const fields = diff(before, after as Record<string, unknown>);
      if (record.name !== department.name) fields.push('name');
      plan.departments.push({
        change: fields.length
          ? { kind: 'department', name: department.name, action: 'update', fields, before, after }
          : { kind: 'department', name: department.name, action: 'unchanged' },
        desired: department,
        record,
      });
    }
    if (env.prune)
      for (const record of state.departments)
        if (!desired.departments.some((item) => lower(item.name) === lower(record.name)))
          plan.departments.push({
            change: { kind: 'department', name: record.name, action: 'delete' },
            record,
          });
  }

  // Teams, by slug.
  if (desired.teams) {
    const existing = new Map(state.teams.map((record) => [record.slug, record]));
    const slugsAfter = new Set([
      ...state.teams
        .filter((record) => !env.prune || desired.teams!.some((item) => item.slug === record.slug))
        .map((record) => record.slug),
      ...desired.teams.map((team) => team.slug),
    ]);
    const parents = new Map<string, string | undefined>();
    for (const record of state.teams)
      parents.set(
        record.slug,
        record.parentId ? state.teams.find((item) => item.id === record.parentId)?.slug : undefined,
      );
    for (const team of desired.teams) {
      const where = `Team ${team.slug}`;
      if (team.parent !== undefined && !slugsAfter.has(team.parent))
        throw new IamError('INVALID_INPUT', `${where}: unknown parent ${team.parent}`);
      if (team.department !== undefined && !departmentNamesAfter.has(lower(team.department)))
        throw new IamError('INVALID_INPUT', `${where}: unknown department ${team.department}`);
      for (const email of [...(team.maintainers ?? []), ...(team.members ?? [])])
        person(email, where);
      for (const role of team.roles ?? [])
        if (!env.roleNamesAfter.has(role))
          throw new IamError('INVALID_INPUT', `${where}: unknown role ${role}`);
      for (const group of team.syncGroups ?? [])
        if (!env.groupNamesAfter.has(group))
          throw new IamError('INVALID_INPUT', `${where}: unknown sync group ${group}`);
      parents.set(team.slug, team.parent);
    }
    for (const slug of slugsAfter) {
      const seen = new Set<string>();
      for (let cursor: string | undefined = slug; cursor; cursor = parents.get(cursor)) {
        if (seen.has(cursor))
          throw new IamError('INVALID_INPUT', `Team ${slug}: the parents form a cycle`);
        seen.add(cursor);
      }
    }
    for (const team of desired.teams) {
      const record = existing.get(team.slug);
      const after = desiredTeamForm(team);
      if (!record) {
        plan.teams.push({
          change: { kind: 'team', name: team.slug, action: 'create', after },
          desired: team,
        });
        continue;
      }
      const before: Record<string, unknown> = { ...exportedTeam(record, state, env) };
      if (!('maintainers' in after)) {
        delete before.maintainers;
        delete before.members;
      }
      if (team.roles === undefined) delete before.roles;
      if (team.syncGroups === undefined) delete before.syncGroups;
      const fields = diff(before, after as Record<string, unknown>);
      if (record.name !== team.name) fields.push('name');
      plan.teams.push({
        change: fields.length
          ? { kind: 'team', name: team.slug, action: 'update', fields, before, after }
          : { kind: 'team', name: team.slug, action: 'unchanged' },
        desired: team,
        record,
      });
    }
    if (env.prune)
      for (const record of state.teams)
        if (!desired.teams.some((item) => item.slug === record.slug))
          plan.teams.push({
            change: { kind: 'team', name: record.slug, action: 'delete' },
            record,
          });
  }
  return plan;
}

/** Depth of an item in a name→parent map (0 for a top-level item). */
function depthOf(parents: Map<string, string | undefined>, key: string): number {
  let depth = 0;
  for (let cursor = parents.get(key); cursor && depth < 50; cursor = parents.get(cursor)) depth++;
  return depth;
}

/**
 * Applies a planned `teams`/`departments` change set inside the configuration apply transaction, after roles exist
 * and before any role is deleted. Every change is authorized like the equivalent API call (`allow`).
 */
export async function applyOrg(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenant: Tenant,
  plan: OrgPlan,
  env: {
    allow(action: string, resourceId: string, what: string): Promise<void>;
    roleIds: Map<string, string>;
    /** Ordinary group name to ID, including groups this apply created. */
    groupIds: Map<string, string>;
    identitiesByEmail: Map<string, Identity>;
  },
  /**
   * `upsert` creates and updates (before access packages, whose rules may name new teams and departments), `delete`
   * removes (after packages stop naming them); both by default.
   */
  phase: 'upsert' | 'delete' | 'all' = 'all',
): Promise<void> {
  const tenantId = tenant.id;
  const departments = departmentMutations(ctx);
  const teams = teamMutations(ctx);
  const personId = (email: string) => env.identitiesByEmail.get(email)!.id;
  const groupIdsOf = (names: string[]) =>
    names.map((name) => {
      const groupId = env.groupIds.get(name);
      if (!groupId) throw new IamError('INVALID_INPUT', `Unknown group ${name}`);
      return groupId;
    });

  if (phase !== 'delete') await upsertOrg();
  if (phase !== 'upsert') await deleteOrg();

  async function upsertOrg() {
    // Departments: creates top-down, then updates, then people.
    const departmentIds = new Map(
      (await tx.find<Department>(departmentCollections.departments, { tenantId })).map((record) => [
        lower(record.name),
        record.id,
      ]),
    );
    const departmentParents = new Map<string, string | undefined>(
      plan.departments
        .filter((item) => item.desired)
        .map((item) => [lower(item.desired!.name), item.desired!.parent?.toLowerCase()]),
    );
    const creates = plan.departments
      .filter((item) => item.change.action === 'create')
      .sort(
        (a, b) =>
          depthOf(departmentParents, lower(a.desired!.name)) -
          depthOf(departmentParents, lower(b.desired!.name)),
      );
    for (const { desired } of creates) {
      await env.allow('iam:departments:manage', tenantId, `create department ${desired!.name}`);
      const created = await departments.createDepartment(tx, principal, tenant, {
        tenantId,
        name: desired!.name,
        ...(desired!.code !== undefined ? { code: desired!.code } : {}),
        ...(desired!.description !== undefined ? { description: desired!.description } : {}),
        ...(desired!.parent !== undefined
          ? { parentId: departmentIds.get(lower(desired!.parent))! }
          : {}),
        ...(desired!.head !== undefined ? { headId: personId(desired!.head) } : {}),
        ...(desired!.costCenter !== undefined ? { costCenter: desired!.costCenter } : {}),
      });
      departmentIds.set(lower(created.name), created.id);
    }
    for (const { change, desired, record } of plan.departments) {
      if (change.action !== 'update') continue;
      const settings = (change.fields ?? []).filter((field) => field !== 'members');
      if (!settings.length) continue;
      await env.allow('iam:departments:manage', record!.id, `update department ${change.name}`);
      await departments.updateDepartment(tx, principal, tenant, {
        tenantId,
        departmentId: record!.id,
        name: desired!.name,
        code: desired!.code ?? null,
        description: desired!.description ?? null,
        parentId: desired!.parent !== undefined ? departmentIds.get(lower(desired!.parent))! : null,
        headId: desired!.head !== undefined ? personId(desired!.head) : null,
        costCenter: desired!.costCenter ?? null,
      });
    }
    for (const { change, desired } of plan.departments) {
      if (change.action === 'delete' || change.action === 'unchanged') continue;
      if (desired!.members === undefined) continue;
      if (change.action === 'update' && !change.fields?.includes('members')) continue;
      const departmentId = departmentIds.get(lower(desired!.name))!;
      const department = (await tx.get<Department>(
        departmentCollections.departments,
        departmentId,
      ))!;
      await env.allow('iam:departments:manage', departmentId, `place people in ${change.name}`);
      const wanted = new Set(desired!.members.map(personId));
      for (const placement of await tx.find<DepartmentMember>(departmentCollections.members, {
        tenantId,
        departmentId,
      }))
        if (!wanted.has(placement.identityId)) {
          await tx.delete(departmentCollections.members, placement.id);
          await ctx.events.audit(
            tx,
            principal,
            'department:unassign',
            tenantId,
            departmentId,
            'allow',
            false,
            { identityId: placement.identityId },
          );
        }
      for (const identityId of wanted) {
        const identity = await departments.departmentPerson(tx, tenantId, identityId);
        const current = (
          await tx.find<DepartmentMember>(departmentCollections.members, {
            tenantId,
            uniqueKey: `identity:${identityId}`,
          })
        )[0];
        if (current?.departmentId !== departmentId)
          await departments.place(tx, principal, department, identity, undefined);
      }
    }

    // Teams: creates top-down, then settings, then members and roles.
    const teamIds = new Map(
      (await tx.find<Team>(teamCollections.teams, { tenantId })).map((record) => [
        record.slug,
        record.id,
      ]),
    );
    const teamParents = new Map<string, string | undefined>(
      plan.teams
        .filter((item) => item.desired)
        .map((item) => [item.desired!.slug, item.desired!.parent]),
    );
    const teamCreates = plan.teams
      .filter((item) => item.change.action === 'create')
      .sort(
        (a, b) => depthOf(teamParents, a.desired!.slug) - depthOf(teamParents, b.desired!.slug),
      );
    for (const { desired } of teamCreates) {
      await env.allow('iam:teams:create', tenantId, `create team ${desired!.slug}`);
      const created = await teams.createTeam(tx, principal, tenant, {
        tenantId,
        name: desired!.name,
        slug: desired!.slug,
        ...(desired!.description !== undefined ? { description: desired!.description } : {}),
        ...(desired!.parent !== undefined ? { parentId: teamIds.get(desired!.parent)! } : {}),
        ...(desired!.department !== undefined
          ? { departmentId: departmentIds.get(lower(desired!.department))! }
          : {}),
        ...(desired!.joinPolicy !== undefined ? { joinPolicy: desired!.joinPolicy } : {}),
        ...(desired!.memberManagement !== undefined
          ? { memberManagement: desired!.memberManagement }
          : {}),
        ...(desired!.syncGroups?.length ? { syncGroupIds: groupIdsOf(desired!.syncGroups) } : {}),
      });
      teamIds.set(created.slug, created.id);
    }
    const current = async (slug: string) =>
      (await tx.get<Team>(teamCollections.teams, teamIds.get(slug)!))!;
    for (const { change, desired } of plan.teams) {
      if (change.action !== 'update') continue;
      const fields = change.fields ?? [];
      const team = await current(desired!.slug);
      const update: Parameters<typeof teams.updateTeam>[3] = { tenantId, teamId: team.id };
      if (fields.includes('name')) update.name = desired!.name;
      if (fields.includes('description')) update.description = desired!.description ?? null;
      if (fields.includes('parent'))
        update.parentId = desired!.parent !== undefined ? teamIds.get(desired!.parent)! : null;
      if (fields.includes('department'))
        update.departmentId =
          desired!.department !== undefined ? departmentIds.get(lower(desired!.department))! : null;
      if (fields.includes('joinPolicy')) update.joinPolicy = desired!.joinPolicy ?? 'closed';
      if (fields.includes('memberManagement'))
        update.memberManagement = desired!.memberManagement ?? 'maintainers';
      if (fields.includes('syncGroups'))
        update.syncGroupIds = desired!.syncGroups?.length ? groupIdsOf(desired!.syncGroups) : null;
      if (Object.keys(update).length === 2) continue;
      await env.allow('iam:teams:update', team.id, `update team ${change.name}`);
      await teams.updateTeam(tx, principal, team, update);
    }
    for (const { change, desired } of plan.teams) {
      if (change.action === 'delete' || change.action === 'unchanged') continue;
      const fields = change.fields ?? [];
      const team = await current(desired!.slug);
      const membership =
        (desired!.maintainers !== undefined || desired!.members !== undefined) &&
        (change.action === 'create' ||
          fields.includes('maintainers') ||
          fields.includes('members'));
      if (membership) {
        await env.allow('iam:teams:update', team.id, `set the members of team ${change.name}`);
        const all = new Map(
          (await tx.find<Team>(teamCollections.teams, { tenantId })).map((item) => [item.id, item]),
        );
        await teams.assertAuthorityOver(tx, principal, tenantId, teamChain(all, team.id));
        const wanted = new Map<string, TeamRole>([
          ...(desired!.members ?? []).map((email) => [personId(email), 'member'] as const),
          ...(desired!.maintainers ?? []).map((email) => [personId(email), 'maintainer'] as const),
        ]);
        const now = ctx.now();
        const live = (
          await tx.find<TeamMember>(teamCollections.members, { tenantId, teamId: team.id })
        ).filter((member) => liveTeamMember(member, now));
        const mutation = { tx, principal, tenant, team, via: 'permission' as const };
        for (const member of live) {
          const role = wanted.get(member.identityId);
          if (role === undefined) {
            // Temporary and synced memberships are runtime state: only permanent manual ones are removed.
            if (member.expiresAt === undefined && member.source !== 'sync')
              await teams.removeMember(tx, principal, team, member, 'team:member:remove');
            continue;
          }
          wanted.delete(member.identityId);
          // The document lists manual memberships: a temporary or synced member it names becomes a permanent manual one.
          if (member.role === role && member.expiresAt === undefined && member.source !== 'sync')
            continue;
          const { expiresAt: _temporary, source: _synced, ...rest } = member;
          await tx.put<TeamMember>(teamCollections.members, { ...rest, role });
          await syncTeamGroups(tx, tenantId, [team.id], now);
          await ctx.events.audit(
            tx,
            principal,
            'team:member:update',
            tenantId,
            team.id,
            'allow',
            false,
            {
              team: team.slug,
              identityId: member.identityId,
              role,
              source: 'config',
            },
          );
        }
        for (const [identityId, role] of wanted)
          await teams.putMember(mutation, { identityId, role }, 'config');
      }
      const roles =
        desired!.roles !== undefined && (change.action === 'create' || fields.includes('roles'));
      if (roles) {
        const wantedRoles = new Set(
          desired!.roles!.map((name) => {
            const roleId = env.roleIds.get(name);
            if (!roleId)
              throw new IamError('INVALID_INPUT', `Team ${change.name}: unknown role ${name}`);
            return roleId;
          }),
        );
        const held = (
          await tx.find<Binding>('bindings', {
            tenantId,
            subjectType: 'group',
            subjectId: team.groupId,
          })
        ).filter(
          (binding) =>
            !binding.eligible &&
            binding.window === undefined &&
            binding.startsAt === undefined &&
            binding.expiresAt === undefined &&
            binding.packageAssignmentId === undefined,
        );
        for (const binding of held) {
          if (wantedRoles.delete(binding.roleId)) continue;
          await env.allow(
            'iam:bindings:delete',
            binding.id,
            `remove a role from team ${change.name}`,
          );
          await deleteBinding(ctx, tx, principal, binding);
        }
        for (const roleId of wantedRoles) {
          await env.allow('iam:bindings:create', roleId, `give team ${change.name} a role`);
          await createBinding(ctx, tx, principal, {
            tenantId,
            roleId,
            subjectType: 'group',
            subjectId: team.groupId,
          });
        }
      }
    }
  }

  async function deleteOrg() {
    // Deletions, lowest teams and departments first.
    const allTeams = new Map(
      (await tx.find<Team>(teamCollections.teams, { tenantId })).map((item) => [item.id, item]),
    );
    const teamDeletes = plan.teams
      .filter((item) => item.change.action === 'delete')
      .sort(
        (a, b) =>
          teamChain(allTeams, b.record!.id).length - teamChain(allTeams, a.record!.id).length,
      );
    for (const { change, record } of teamDeletes) {
      await env.allow('iam:teams:delete', record!.id, `delete team ${change.name}`);
      const team = await tx.get<Team>(teamCollections.teams, record!.id);
      if (team) await teams.deleteTeam(tx, principal, team);
    }
    const allDepartments = new Map(
      (await tx.find<Department>(departmentCollections.departments, { tenantId })).map((item) => [
        item.id,
        item,
      ]),
    );
    const departmentDeletes = plan.departments
      .filter((item) => item.change.action === 'delete')
      .sort(
        (a, b) =>
          departmentChain(allDepartments, b.record!.id).length -
          departmentChain(allDepartments, a.record!.id).length,
      );
    for (const { change, record } of departmentDeletes) {
      await env.allow('iam:departments:manage', record!.id, `delete department ${change.name}`);
      await departments.deleteDepartment(tx, principal, tenant, {
        tenantId,
        departmentId: record!.id,
      });
    }
  }
}
