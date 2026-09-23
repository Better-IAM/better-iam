/**
 * The org structure as birthright rules (access package rules) see it: `identity.teams`, the teams a person belongs to
 * with every team above them, and `identity.departments`, their department with every department above it (the same
 * sets as the policy keys `principal.teams` and `principal.departments`). A synced team membership counts only while
 * the person is in one of the team's source groups by a membership no access package created, so a rule never feeds on
 * what a package granted (identity.groups follows the same rule).
 */
import type { IamStore } from '@better-iam/core';
import {
  departmentChain,
  departmentCollections,
  type Department,
  type DepartmentMember,
} from './departments.js';
import type { AccessPackage } from './models.js';
import {
  orgRuleKeys,
  ruleValues,
  type RuleEnvironment,
  type RuleOrgFacts,
} from './package-rules.js';
import { liveTeamMember, teamChain, teamCollections, type Team, type TeamMember } from './teams.js';

/** A tenant's teams and departments, read once, answering identity.teams / identity.departments per person. */
export interface TenantOrgFacts {
  teamIds: Set<string>;
  departmentIds: Set<string>;
  /** What a rule sees for one person, given their live memberships no access package created. */
  of(identityId: string, directGroupIds: readonly string[]): RuleOrgFacts;
}

export async function loadOrgFacts(
  reader: IamStore,
  tenantId: string,
  now: number,
): Promise<TenantOrgFacts> {
  const teams = new Map(
    (await reader.find<Team>(teamCollections.teams, { tenantId })).map((team) => [team.id, team]),
  );
  const members = new Map<string, TeamMember[]>();
  for (const member of await reader.find<TeamMember>(teamCollections.members, { tenantId }))
    if (liveTeamMember(member, now))
      members.set(member.identityId, [...(members.get(member.identityId) ?? []), member]);
  const departments = new Map(
    (await reader.find<Department>(departmentCollections.departments, { tenantId })).map(
      (department) => [department.id, department],
    ),
  );
  const placements = new Map(
    (await reader.find<DepartmentMember>(departmentCollections.members, { tenantId })).map(
      (placement) => [placement.identityId, placement.departmentId],
    ),
  );
  return {
    teamIds: new Set(teams.keys()),
    departmentIds: new Set(departments.keys()),
    of(identityId, directGroupIds) {
      const direct = new Set(directGroupIds);
      const teamIds = new Set<string>();
      for (const member of members.get(identityId) ?? []) {
        const team = teams.get(member.teamId);
        if (!team) continue;
        if (
          member.source === 'sync' &&
          !(team.syncGroupIds ?? []).some((groupId) => direct.has(groupId))
        )
          continue;
        for (const link of teamChain(teams, team.id)) teamIds.add(link.id);
      }
      const departmentId = placements.get(identityId);
      return {
        teams: [...teamIds].sort(),
        departments: departmentId
          ? departmentChain(departments, departmentId)
              .map((department) => department.id)
              .sort()
          : [],
      };
    },
  };
}

/** The valid identity.teams and identity.departments values of a tenant: its team and department IDs. */
export async function orgRuleEnvironment(
  reader: IamStore,
  tenantId: string,
): Promise<NonNullable<RuleEnvironment['org']>> {
  return {
    teams: new Set(
      (await reader.find<Team>(teamCollections.teams, { tenantId })).map((team) => team.id),
    ),
    departments: new Set(
      (await reader.find<Department>(departmentCollections.departments, { tenantId })).map(
        (department) => department.id,
      ),
    ),
  };
}

/**
 * The names of the tenant's access packages whose rule names one of `ids` under `key` (a team's backing group under
 * identity.groups counts for the team). Teams and departments stay while a rule names them, like groups.
 */
export async function packagesNaming(
  reader: IamStore,
  tenantId: string,
  key: keyof typeof orgRuleKeys,
  ids: readonly string[],
  backingGroupIds: readonly string[] = [],
): Promise<string[]> {
  const wanted = new Set(ids);
  const groups = new Set(backingGroupIds);
  return (await reader.find<AccessPackage>('accessPackages', { tenantId }))
    .filter(
      (pkg) =>
        ruleValues(pkg.autoAssign, key).some((value) => wanted.has(value)) ||
        ruleValues(pkg.autoAssign, 'identity.groups').some((value) => groups.has(value)),
    )
    .map((pkg) => pkg.name)
    .sort((a, b) => a.localeCompare(b, 'en'));
}
