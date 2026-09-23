/**
 * Birthright suggestions: access most people of a department (or team) already hold by hand, proposed as an automatic
 * access package whose rule names that department (or team). The population of a unit is exactly who such a rule
 * would match: active people whose `identity.departments` (or `identity.teams`) includes it, so a department counts
 * the people of the departments below it. Only plain grants count: standing, permanent role bindings made directly to
 * the person, and permanent memberships of ordinary groups, neither created by an access package. What most of a unit
 * already receives from an automatic package, or is suggested for a unit above it, is never suggested again.
 */
import { IamError, type IamStore, type Identity } from '@better-iam/core';
import type { ServerContext } from './context.js';
import { departmentChain, departmentCollections, type Department } from './departments.js';
import type {
  AccessPackage,
  Binding,
  Group,
  GroupMember,
  PackageAssignment,
  Role,
} from './models.js';
import { loadOrgFacts } from './org-rules.js';
import { ruleValues, type AutoAssignInput } from './package-rules.js';
import { teamChain, teamCollections, type Team } from './teams.js';
import { integer } from './validation.js';

export type OrgUnitKind = 'department' | 'team';

export interface BirthrightItem {
  id: string;
  name: string;
  /** People of the unit who hold it by hand. */
  holders: number;
  /** holders / people, rounded to two decimals. */
  share: number;
}
export interface BirthrightSuggestion {
  unit: { kind: OrgUnitKind; id: string; name: string };
  /** Active people a rule naming the unit would match. */
  people: number;
  roles: BirthrightItem[];
  groups: BirthrightItem[];
  /** People of the unit who lack at least one suggested item: what creating the package would grant. */
  wouldGrant: number;
  /** Automatic packages whose rule already names the unit or one above it (their contents are left out). */
  existingPackages: string[];
  /** Ready for `packages.create` (add `tenantId`); the caller becomes the rule's owner. */
  package: {
    name: string;
    description: string;
    roleIds: string[];
    groupIds: string[];
    autoAssign: AutoAssignInput;
  };
}
export interface BirthrightOptions {
  /** Only this unit (items suggested for a unit above it are still left out). */
  unitId?: string;
  /** Smallest share of the unit's people that must hold an item (default 0.8). */
  minShare: number;
  /** Smallest unit considered (default 3 people). */
  minPeople: number;
}

const ruleKey = { department: 'identity.departments', team: 'identity.teams' } as const;

/** Validates the API input of the `suggestBirthright` methods. */
export function birthrightOptions(input: {
  minShare?: number;
  minPeople?: number;
}): Omit<BirthrightOptions, 'unitId'> {
  const minShare = input.minShare ?? 0.8;
  if (typeof minShare !== 'number' || !Number.isFinite(minShare) || minShare < 0.5 || minShare > 1)
    throw new IamError('INVALID_INPUT', 'minShare must be between 0.5 and 1');
  return { minShare, minPeople: integer(input.minPeople ?? 3, 'minPeople', 2, 100_000) };
}

export async function suggestBirthright(
  ctx: ServerContext,
  reader: IamStore,
  tenantId: string,
  kind: OrgUnitKind,
  options: BirthrightOptions,
): Promise<BirthrightSuggestion[]> {
  const now = ctx.now();
  // Sequential reads: a transaction holds one database connection.
  const people = (await reader.find<Identity>('identities', { tenantId })).filter(
    (identity) =>
      identity.kind === 'user' && identity.status === 'active' && !ctx.identityExpired(identity),
  );
  const roles = new Map(
    (await reader.find<Role>('roles', { tenantId })).map((role) => [role.id, role]),
  );
  const groups = new Map(
    (await reader.find<Group>('groups', { tenantId })).map((group) => [group.id, group]),
  );
  const bindings = await reader.find<Binding>('bindings', { tenantId, subjectType: 'identity' });
  const memberships = await reader.find<GroupMember>('groupMembers', { tenantId });
  const packages = await reader.find<AccessPackage>('accessPackages', { tenantId });
  // Assignments an automatic package made: what they grant is birthright access already.
  const automatic = new Set(
    (await reader.find<PackageAssignment>('packageAssignments', { tenantId }))
      .filter((assignment) => assignment.ruleRevision !== undefined)
      .map((assignment) => assignment.id),
  );
  const org = await loadOrgFacts(reader, tenantId, now);
  const units: Map<string, Department | Team> =
    kind === 'department'
      ? new Map(
          (await reader.find<Department>(departmentCollections.departments, { tenantId })).map(
            (unit) => [unit.id, unit],
          ),
        )
      : new Map(
          (await reader.find<Team>(teamCollections.teams, { tenantId })).map((unit) => [
            unit.id,
            unit,
          ]),
        );
  const chainOf = (unitId: string): string[] =>
    (kind === 'department'
      ? departmentChain(units as Map<string, Department>, unitId)
      : teamChain(units as Map<string, Team>, unitId)
    ).map((unit) => unit.id);

  // What each person holds by hand, and which units a rule would see them in.
  const heldRoles = new Map<string, Set<string>>();
  const heldGroups = new Map<string, Set<string>>();
  const autoRoles = new Map<string, Set<string>>();
  const autoGroups = new Map<string, Set<string>>();
  const add = (map: Map<string, Set<string>>, identityId: string, itemId: string) =>
    map.set(identityId, (map.get(identityId) ?? new Set()).add(itemId));
  for (const binding of bindings) {
    const role = roles.get(binding.roleId);
    if (
      role &&
      binding.packageAssignmentId !== undefined &&
      automatic.has(binding.packageAssignmentId) &&
      ctx.liveBinding(binding)
    )
      add(autoRoles, binding.subjectId, role.id);
    if (
      !role ||
      role.protected ||
      !ctx.liveBinding(binding) ||
      binding.eligible === true ||
      binding.window !== undefined ||
      binding.startsAt !== undefined ||
      binding.expiresAt !== undefined ||
      binding.packageAssignmentId !== undefined
    )
      continue;
    add(heldRoles, binding.subjectId, role.id);
  }
  const directGroups = new Map<string, string[]>();
  for (const member of memberships) {
    if (
      member.packageAssignmentId !== undefined &&
      automatic.has(member.packageAssignmentId) &&
      ctx.liveMembership(member)
    )
      add(autoGroups, member.identityId, member.groupId);
    if (member.packageAssignmentId !== undefined || !ctx.liveMembership(member)) continue;
    directGroups.set(member.identityId, [
      ...(directGroups.get(member.identityId) ?? []),
      member.groupId,
    ]);
    const group = groups.get(member.groupId);
    if (!group || group.teamId !== undefined || member.expiresAt !== undefined) continue;
    add(heldGroups, member.identityId, group.id);
  }
  const population = new Map<string, Identity[]>();
  for (const person of people) {
    const facts = org.of(person.id, directGroups.get(person.id) ?? []);
    for (const unitId of kind === 'department' ? facts.departments : facts.teams)
      population.set(unitId, [...(population.get(unitId) ?? []), person]);
  }

  // Top-down, so a unit never repeats what is suggested for a unit above it.
  const ordered = [...units.values()].sort(
    (a, b) => chainOf(a.id).length - chainOf(b.id).length || a.name.localeCompare(b.name, 'en'),
  );
  const suggested = new Map<string, { roles: Set<string>; groups: Set<string> }>();
  const result: BirthrightSuggestion[] = [];
  for (const unit of ordered) {
    const members = population.get(unit.id) ?? [];
    const chain = chainOf(unit.id);
    const above = chain.slice(1);
    const inherited = { roles: new Set<string>(), groups: new Set<string>() };
    for (const unitId of above)
      for (const roleId of suggested.get(unitId)?.roles ?? []) inherited.roles.add(roleId);
    for (const unitId of above)
      for (const groupId of suggested.get(unitId)?.groups ?? []) inherited.groups.add(groupId);
    const existing = packages.filter((pkg) =>
      ruleValues(pkg.autoAssign, ruleKey[kind]).some((value) => chain.includes(value)),
    );
    const covered = {
      roles: new Set(existing.flatMap((pkg) => pkg.roleIds)),
      groups: new Set(existing.flatMap((pkg) => pkg.groupIds)),
    };
    if (members.length < options.minPeople) continue;
    const tally = (held: Map<string, Set<string>>) => {
      const counts = new Map<string, number>();
      for (const person of members)
        for (const itemId of held.get(person.id) ?? [])
          counts.set(itemId, (counts.get(itemId) ?? 0) + 1);
      return counts;
    };
    const share = (count: number) => count / members.length >= options.minShare;
    // Items most of the unit already receives from some automatic package are birthright access already.
    const already = (counts: Map<string, number>) =>
      [...counts].filter(([, count]) => share(count)).map(([itemId]) => itemId);
    const pick = (
      counts: Map<string, number>,
      skip: Set<string>,
      name: (itemId: string) => string,
    ): BirthrightItem[] =>
      [...counts]
        .filter(([itemId, holders]) => !skip.has(itemId) && share(holders))
        .map(([itemId, holders]) => ({
          id: itemId,
          name: name(itemId),
          holders,
          share: Math.round((holders / members.length) * 100) / 100,
        }))
        .sort((a, b) => b.holders - a.holders || a.name.localeCompare(b.name, 'en'));
    const roleItems = pick(
      tally(heldRoles),
      new Set([...covered.roles, ...inherited.roles, ...already(tally(autoRoles))]),
      (roleId) => roles.get(roleId)!.name,
    );
    const groupItems = pick(
      tally(heldGroups),
      new Set([...covered.groups, ...inherited.groups, ...already(tally(autoGroups))]),
      (groupId) => groups.get(groupId)!.name,
    );
    suggested.set(unit.id, {
      roles: new Set(roleItems.map((item) => item.id)),
      groups: new Set(groupItems.map((item) => item.id)),
    });
    if (!roleItems.length && !groupItems.length) continue;
    const wouldGrant = members.filter(
      (person) =>
        roleItems.some((item) => !heldRoles.get(person.id)?.has(item.id)) ||
        groupItems.some((item) => !heldGroups.get(person.id)?.has(item.id)),
    ).length;
    result.push({
      unit: { kind, id: unit.id, name: unit.name },
      people: members.length,
      roles: roleItems,
      groups: groupItems,
      wouldGrant,
      existingPackages: existing.map((pkg) => pkg.name).sort((a, b) => a.localeCompare(b, 'en')),
      package: {
        name: `${unit.name} ${kind === 'department' ? 'department' : 'team'} basics`.slice(0, 100),
        description: `Birthright access for everyone in the ${unit.name} ${kind}${kind === 'department' ? ' and the departments below it' : ' and the teams below it'}.`,
        roleIds: roleItems.map((item) => item.id),
        groupIds: groupItems.map((item) => item.id),
        autoAssign: {
          include: [
            {
              StringEquals: { 'principal.kind': 'user' },
              ArrayContains: { [ruleKey[kind]]: [unit.id] },
            },
          ],
        },
      },
    });
  }
  return (options.unitId ? result.filter((item) => item.unit.id === options.unitId) : result).sort(
    (a, b) => b.people - a.people || a.unit.name.localeCompare(b.unit.name, 'en'),
  );
}
