import { createHash } from 'node:crypto';
import {
  IamError,
  canonicalJson,
  matchPattern,
  type AuditEvent,
  type CredentialInput,
  type IamStore,
  type Identity,
  type PolicyStatement,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type {
  AccessPackage,
  ActionDefinition,
  Binding,
  Group,
  GroupMember,
  Policy,
  Role,
} from '../models.js';
import type { AccessUsageRecord, AccessUsageTracking } from '../usage.js';
import type { CertificationItem } from './certifications.js';
import { allow } from './packages.js';
import { createBinding, deleteBinding } from './bindings.js';
import { integer, text } from '../validation.js';

export type RoleSuggestionKind =
  | 'bundle'
  | 'group-binding'
  | 'redundant-binding'
  | 'duplicate-roles';

/** A named reference in a suggestion. */
export interface MiningRef {
  id: string;
  name: string;
}
/**
 * One way to simplify how a tenant grants access, derived from who holds what today. IDs are deterministic for
 * the same condition, so `roleMining.apply` can act on a suggestion listed earlier as long as it still holds.
 */
export interface RoleSuggestion {
  id: string;
  kind: RoleSuggestionKind;
  title: string;
  detail: string;
  roles: MiningRef[];
  identities: MiningRef[];
  /** The group a group-binding or redundant-binding suggestion concerns. */
  group?: MiningRef;
  /** Direct bindings the suggestion would remove (group-binding, redundant-binding). */
  bindingIds?: string[];
  /** Grants saved: assignments folded into one (bundle) or bindings removed net of those added. */
  savings: number;
  /** Whether `roleMining.apply` can carry the suggestion out (bundles become packages through `packages.create`). */
  applicable: boolean;
}
export interface RoleMiningResult {
  generatedAt: number;
  summary: Record<RoleSuggestionKind, number>;
  suggestions: RoleSuggestion[];
}
/** A role an identity holds that few of its peers hold, or one most of its peers hold that it lacks. */
export interface PeerRoleShare {
  role: MiningRef;
  /** How many peers (excluding the identity) hold the role. */
  peersHolding: number;
  /** peersHolding / peers, rounded to two decimals. */
  share: number;
}
export interface PeerOutlier {
  identity: MiningRef;
  /** The peer grouping: the manager's ID, or the attribute value. */
  peerValue: string;
  peers: number;
  unusualRoles: PeerRoleShare[];
  missingRoles: PeerRoleShare[];
}
export interface PeerOutlierResult {
  generatedAt: number;
  peerBy: string;
  identitiesCompared: number;
  outliers: PeerOutlier[];
}

/** One person's hold on one role, judged against the actions they actually used (`roleMining.rightSize`). */
export interface RightSizeEntry {
  identity: MiningRef;
  role: MiningRef;
  bindingId: string;
  /** How the role reaches the person: their own binding or a group's. */
  via: { type: 'identity' } | { type: 'group'; id: string; name: string };
  eligible: boolean;
  /** `unused`: none of the role's actions used in the window; `partial`: some never used. */
  status: 'unused' | 'partial';
  grantedActions: number;
  usedActions: string[];
  /** The first 50 unused actions, sorted; `unusedCount` has the total. */
  unusedActions: string[];
  unusedCount: number;
  lastUsedAt?: number;
}
/** Per role: which of its actions any holder used in the window. */
export interface RoleUsageSummary {
  role: MiningRef;
  holders: number;
  grantedActions: number;
  usedActions: string[];
  /** The first 100 actions no holder used, sorted; `neverUsedCount` has the total. */
  neverUsed: string[];
  neverUsedCount: number;
}
export interface RightSizeResult {
  generatedAt: number;
  unusedDays: number;
  /** Whether the deployment records usage (`accessUsage` option). */
  tracking: boolean;
  /** When this tenant's usage was first recorded. */
  trackingSince?: number;
  /** True once usage has been recorded for the whole window, so "unused" is conclusive. */
  complete: boolean;
  entries: RightSizeEntry[];
  roles: RoleUsageSummary[];
}

/** A suggested decision for one access-certification item, with the evidence behind it. */
export interface ReviewRecommendation {
  itemId: string;
  recommendation: 'keep' | 'revoke' | 'none';
  /** `usage`: recorded access usage; `sign-in`: last sign-in; `status`: the account is not active. */
  basis?: 'usage' | 'sign-in' | 'status';
  reason: string;
  lastUsedAt?: number;
}
export interface ReviewRecommendationsResult {
  campaignId: string;
  unusedDays: number;
  /** Whether recorded usage covers the whole window (otherwise sign-ins are the evidence). */
  usageComplete: boolean;
  recommendations: ReviewRecommendation[];
}

const suggestionId = (kind: RoleSuggestionKind, key: string) =>
  createHash('sha256').update(`${kind}:${key}`).digest('hex').slice(0, 24);
const setKey = (ids: Iterable<string>) => [...ids].sort().join(',');
const label = (identity: Identity) => identity.email ?? identity.name;
const round = (value: number) => Math.round(value * 100) / 100;
/** Distinct role sets considered as bundle seeds; pairwise intersections of these are the candidates. */
const maxSeedSets = 300;

interface Snapshot {
  roles: Role[];
  roleById: Map<string, Role>;
  identities: Identity[];
  identityById: Map<string, Identity>;
  groups: Group[];
  bindings: Binding[];
  members: GroupMember[];
  packages: AccessPackage[];
  policies: Policy[];
}

async function snapshot(ctx: ServerContext, tx: IamStore, tenantId: string): Promise<Snapshot> {
  // Sequential reads: a transaction holds one database connection.
  const roles = await tx.find<Role>('roles', { tenantId });
  const identities = (await tx.find<Identity>('identities', { tenantId })).filter(
    (identity) => identity.status === 'active' && !ctx.identityExpired(identity),
  );
  const groups = await tx.find<Group>('groups', { tenantId });
  const bindings = (await tx.find<Binding>('bindings', { tenantId })).filter((binding) =>
    ctx.liveBinding(binding),
  );
  const members = (await tx.find<GroupMember>('groupMembers', { tenantId })).filter((member) =>
    ctx.liveMembership(member),
  );
  const packages = await tx.find<AccessPackage>('accessPackages', { tenantId });
  const policies = await tx.find<Policy>('policies', { tenantId });
  return {
    roles,
    roleById: new Map(roles.map((role) => [role.id, role])),
    identities,
    identityById: new Map(identities.map((identity) => [identity.id, identity])),
    groups,
    bindings,
    members,
    packages,
    policies,
  };
}

/** Always-on grants: not just-in-time, not limited to a time window. */
const standing = (binding: Binding) => binding.eligible !== true && binding.window === undefined;
/** A direct grant an administrator can safely fold into a group: standing, permanent, not owned by a package. */
const plainDirect = (binding: Binding) =>
  binding.subjectType === 'identity' &&
  standing(binding) &&
  binding.expiresAt === undefined &&
  binding.startsAt === undefined &&
  binding.packageAssignmentId === undefined;

/** Role IDs each active identity holds, directly or through groups (`eligible` includes just-in-time bindings). */
function heldRoles(data: Snapshot, options: { eligible: boolean }): Map<string, Set<string>> {
  const groupsOf = new Map<string, Set<string>>();
  for (const member of data.members) {
    const set = groupsOf.get(member.identityId) ?? new Set<string>();
    set.add(member.groupId);
    groupsOf.set(member.identityId, set);
  }
  const held = new Map<string, Set<string>>();
  for (const identity of data.identities) held.set(identity.id, new Set());
  for (const binding of data.bindings) {
    if (!options.eligible && !standing(binding)) continue;
    if (data.roleById.get(binding.roleId)?.protected !== false) continue;
    if (binding.subjectType === 'identity') held.get(binding.subjectId)?.add(binding.roleId);
    else
      for (const [identityId, groups] of groupsOf)
        if (groups.has(binding.subjectId)) held.get(identityId)?.add(binding.roleId);
  }
  return held;
}

/** The statements a role grants (inline, attached policies, inherited roles), as a canonical comparable key. */
function grantKey(data: Snapshot, role: Role): string {
  const policyById = new Map(data.policies.map((policy) => [policy.id, policy]));
  const statements = new Set<string>();
  const seen = new Set<string>();
  const walk = (current: Role) => {
    if (seen.has(current.id)) return;
    seen.add(current.id);
    const documents = [
      current.document,
      ...current.policyIds.map((id) => policyById.get(id)?.document),
    ];
    for (const document of documents)
      for (const statement of document?.statements ?? [])
        statements.add(canonicalJson(normalizeStatement(statement)));
    for (const parent of current.inherits ?? []) {
      const inherited = data.roleById.get(parent);
      if (inherited) walk(inherited);
    }
  };
  walk(role);
  return [...statements].sort().join('\n');
}
/** Statement fields that do not change what it grants are dropped; action and resource order is irrelevant. */
function normalizeStatement(statement: PolicyStatement) {
  const { sid: _sid, ...rest } = statement as PolicyStatement & { sid?: unknown };
  return {
    ...rest,
    actions: [...statement.actions].sort(),
    resources: [...statement.resources].sort(),
  };
}

/**
 * The known actions a role can allow somewhere (its own, attached, and inherited allow statements). Resources and
 * conditions are not considered: this is what the role could grant, compared with what its holders used.
 */
function roleActions(data: Snapshot, role: Role, known: string[]): string[] {
  const policyById = new Map(data.policies.map((policy) => [policy.id, policy]));
  const patterns = new Set<string>();
  const seen = new Set<string>();
  const walk = (current: Role) => {
    if (seen.has(current.id)) return;
    seen.add(current.id);
    for (const document of [
      current.document,
      ...current.policyIds.map((id) => policyById.get(id)?.document),
    ])
      for (const statement of document?.statements ?? [])
        if (statement.effect === 'allow')
          for (const action of statement.actions) patterns.add(action);
    for (const parent of current.inherits ?? []) {
      const inherited = data.roleById.get(parent);
      if (inherited) walk(inherited);
    }
  };
  walk(role);
  return known.filter((action) => [...patterns].some((pattern) => matchPattern(pattern, action)));
}

function mine(
  data: Snapshot,
  settings: { minIdentities: number; minRoles: number },
): RoleSuggestion[] {
  const suggestions: RoleSuggestion[] = [];
  const roleRef = (roleId: string): MiningRef => ({
    id: roleId,
    name: data.roleById.get(roleId)?.name ?? roleId,
  });
  const identityRef = (identityId: string): MiningRef => {
    const identity = data.identityById.get(identityId);
    return { id: identityId, name: identity ? label(identity) : identityId };
  };
  const groupById = new Map(data.groups.map((group) => [group.id, group]));

  // Bundles: role combinations many people hold together, found as closed itemsets over the distinct role sets
  // and their pairwise intersections (every maximal shared combination is an intersection of two holders' sets).
  const held = heldRoles(data, { eligible: false });
  const distinct = new Map<string, { roles: string[]; count: number }>();
  for (const roles of held.values()) {
    if (roles.size < settings.minRoles) continue;
    const key = setKey(roles);
    const entry = distinct.get(key) ?? { roles: [...roles].sort(), count: 0 };
    entry.count++;
    distinct.set(key, entry);
  }
  const seeds = [...distinct.values()]
    .sort((a, b) => b.count - a.count || a.roles.join().localeCompare(b.roles.join()))
    .slice(0, maxSeedSets);
  const candidates = new Map<string, string[]>();
  for (let i = 0; i < seeds.length; i++) {
    candidates.set(setKey(seeds[i]!.roles), seeds[i]!.roles);
    const first = new Set(seeds[i]!.roles);
    for (let j = i + 1; j < seeds.length; j++) {
      const common = seeds[j]!.roles.filter((roleId) => first.has(roleId));
      if (common.length >= settings.minRoles) candidates.set(setKey(common), common);
    }
  }
  const holderSets = [...held.entries()].filter(([, roles]) => roles.size >= settings.minRoles);
  const supported = [...candidates.values()]
    .map((roles) => ({
      roles,
      holders: holderSets
        .filter(([, set]) => roles.every((roleId) => set.has(roleId)))
        .map(([identityId]) => identityId),
    }))
    .filter((candidate) => candidate.holders.length >= settings.minIdentities);
  // Closed sets only: a combination is dropped when a larger one has exactly the same holders.
  const closed = supported.filter(
    (candidate) =>
      !supported.some(
        (other) =>
          other.roles.length > candidate.roles.length &&
          other.holders.length === candidate.holders.length &&
          candidate.roles.every((roleId) => other.roles.includes(roleId)),
      ),
  );
  const packaged = new Set(
    data.packages.filter((pkg) => pkg.groupIds.length === 0).map((pkg) => setKey(pkg.roleIds)),
  );
  const composite = new Set(
    data.roles.filter((role) => role.inherits?.length).map((role) => setKey(role.inherits!)),
  );
  for (const candidate of closed) {
    const key = setKey(candidate.roles);
    if (packaged.has(key) || composite.has(key)) continue;
    const names = candidate.roles.map((roleId) => roleRef(roleId).name);
    suggestions.push({
      id: suggestionId('bundle', key),
      kind: 'bundle',
      title: `${candidate.holders.length} people hold ${names.join(' + ')} together`,
      detail:
        'Grant the combination as one access package (optionally assigned automatically by attribute) or as a role that inherits these roles, instead of binding each role separately.',
      roles: candidate.roles.map(roleRef),
      identities: candidate.holders.map(identityRef),
      savings: candidate.holders.length * (candidate.roles.length - 1),
      applicable: false,
    });
  }

  // Group bindings: a role every permanent member of a group holds through their own direct binding.
  const membersOf = new Map<string, GroupMember[]>();
  // Every live membership counts, including disabled or expired members: binding the role to the group would reach
  // them too (on re-activation), so a group qualifies only when all of them are active holders.
  for (const member of data.members) {
    const list = membersOf.get(member.groupId) ?? [];
    list.push(member);
    membersOf.set(member.groupId, list);
  }
  for (const [groupId, members] of membersOf) {
    const group = groupById.get(groupId);
    if (!group || members.length < settings.minIdentities) continue;
    if (members.some((member) => member.expiresAt !== undefined)) continue;
    if (members.some((member) => !data.identityById.has(member.identityId))) continue;
    const groupRoles = new Set(
      data.bindings
        .filter((binding) => binding.subjectType === 'group' && binding.subjectId === groupId)
        .map((binding) => binding.roleId),
    );
    const direct = new Map<string, Binding[]>();
    for (const binding of data.bindings)
      if (
        plainDirect(binding) &&
        !groupRoles.has(binding.roleId) &&
        data.roleById.get(binding.roleId)?.protected === false &&
        members.some((member) => member.identityId === binding.subjectId)
      ) {
        const list = direct.get(binding.roleId) ?? [];
        list.push(binding);
        direct.set(binding.roleId, list);
      }
    for (const [roleId, list] of direct) {
      const holders = new Set(list.map((binding) => binding.subjectId));
      if (!members.every((member) => holders.has(member.identityId))) continue;
      // One authority keeps the ceiling identical once the grant moves to the group.
      const authorities = new Set(list.map((binding) => binding.authorityId));
      const bindingIds = list.map((binding) => binding.id).sort();
      suggestions.push({
        id: suggestionId('group-binding', `${groupId}:${roleId}:${bindingIds.join(',')}`),
        kind: 'group-binding',
        title: `Every member of ${group.name} holds ${roleRef(roleId).name} directly`,
        detail: `Bind ${roleRef(roleId).name} to the group once and remove ${list.length} direct binding(s); new members then receive it automatically and leavers lose it.${authorities.size > 1 ? ' The direct bindings come from different grant authorities, so apply is not offered.' : ''}`,
        roles: [roleRef(roleId)],
        identities: [...holders].sort().map(identityRef),
        group: { id: group.id, name: group.name },
        bindingIds,
        savings: list.length - 1,
        applicable: authorities.size === 1,
      });
    }
  }

  // Redundant direct bindings: the same role already reaches the person through a permanent group membership,
  // under the same authority (so the same ceiling) and at least as broadly.
  const permanentGroups = new Map<string, Set<string>>();
  // Package-owned memberships end with their assignment, so they cannot stand in for a direct binding.
  for (const member of data.members)
    if (member.expiresAt === undefined && member.packageAssignmentId === undefined) {
      const set = permanentGroups.get(member.identityId) ?? new Set<string>();
      set.add(member.groupId);
      permanentGroups.set(member.identityId, set);
    }
  const redundant = new Map<string, { binding: Binding; group: Group }[]>();
  for (const binding of data.bindings) {
    if (
      binding.subjectType !== 'identity' ||
      binding.eligible === true ||
      binding.packageAssignmentId !== undefined ||
      !data.identityById.has(binding.subjectId) ||
      data.roleById.get(binding.roleId)?.protected !== false
    )
      continue;
    const groups = permanentGroups.get(binding.subjectId);
    if (!groups) continue;
    const cover = data.bindings.find(
      (other) =>
        other.subjectType === 'group' &&
        groups.has(other.subjectId) &&
        other.roleId === binding.roleId &&
        other.authorityId === binding.authorityId &&
        standing(other) &&
        other.startsAt === undefined &&
        (other.expiresAt === undefined ||
          (binding.expiresAt !== undefined && other.expiresAt >= binding.expiresAt)),
    );
    const group = cover && groupById.get(cover.subjectId);
    if (!group) continue;
    const key = `${group.id}:${binding.roleId}`;
    const list = redundant.get(key) ?? [];
    list.push({ binding, group });
    redundant.set(key, list);
  }
  for (const [key, list] of redundant) {
    const { group, binding } = list[0]!;
    const bindingIds = list.map((entry) => entry.binding.id).sort();
    suggestions.push({
      id: suggestionId('redundant-binding', `${key}:${bindingIds.join(',')}`),
      kind: 'redundant-binding',
      title: `${list.length} direct ${roleRef(binding.roleId).name} binding(s) duplicate ${group.name}'s`,
      detail: `These people already receive ${roleRef(binding.roleId).name} through their permanent membership in ${group.name}. Removing the direct bindings changes nothing today and keeps access tied to the group.`,
      roles: [roleRef(binding.roleId)],
      identities: list.map((entry) => identityRef(entry.binding.subjectId)),
      group: { id: group.id, name: group.name },
      bindingIds,
      savings: list.length,
      applicable: true,
    });
  }

  // Duplicate roles: different roles that grant exactly the same statements.
  const byGrant = new Map<string, Role[]>();
  for (const role of data.roles) {
    if (role.protected) continue;
    const key = grantKey(data, role);
    if (!key) continue;
    const list = byGrant.get(key) ?? [];
    list.push(role);
    byGrant.set(key, list);
  }
  for (const list of byGrant.values()) {
    if (list.length < 2) continue;
    const ids = list.map((role) => role.id).sort();
    suggestions.push({
      id: suggestionId('duplicate-roles', ids.join(',')),
      kind: 'duplicate-roles',
      title: `${list.map((role) => role.name).join(', ')} grant the same permissions`,
      detail:
        'The roles resolve to identical statements. Keep one, move its bindings over, and delete the rest so reviews have one thing to certify.',
      roles: ids.map(roleRef),
      identities: [],
      savings: list.length - 1,
      applicable: false,
    });
  }
  return suggestions;
}

const kindRank: Record<RoleSuggestionKind, number> = {
  'redundant-binding': 0,
  'group-binding': 1,
  'duplicate-roles': 2,
  bundle: 3,
};

/**
 * Role mining: reads who holds which roles and suggests simpler ways to grant the same access — role combinations
 * to bundle into access packages, roles every member of a group holds directly, direct bindings a group already
 * covers, and roles that duplicate each other — plus peer-group outliers: access a person holds that few people
 * sharing their manager or an identity attribute hold. Read methods need `iam:analysis:read`; `apply` needs
 * `iam:analysis:update` and the rights of the binding changes it makes.
 */
export function createRoleMiningApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const settingsOf = (input: { minIdentities?: number; minRoles?: number }) => ({
    minIdentities: integer(input.minIdentities ?? 3, 'minIdentities', 2, 10_000),
    minRoles: integer(input.minRoles ?? 2, 'minRoles', 2, 50),
  });
  return {
    /**
     * Lists suggestions, most actionable first. `minIdentities` (default 3) is how many people must share a
     * pattern; `minRoles` (default 2) the smallest role combination reported as a bundle; `limit` caps the list.
     */
    suggest: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        minIdentities?: number;
        minRoles?: number;
        kinds?: RoleSuggestionKind[];
        limit?: number;
      },
    ): Promise<RoleMiningResult> => {
      const settings = settingsOf(input);
      const limit = integer(input.limit ?? 50, 'limit', 1, 500);
      const kinds = input.kinds === undefined ? undefined : new Set(input.kinds);
      if (kinds && [...kinds].some((kind) => !(kind in kindRank)))
        throw new IamError('INVALID_INPUT', 'Unknown suggestion kind');
      return operation(
        credential,
        input.tenantId,
        'iam:analysis:read',
        'analysis/*',
        async ({ tx, tenant }) => {
          const all = mine(await snapshot(ctx, tx, tenant.id), settings).filter(
            (suggestion) => !kinds || kinds.has(suggestion.kind),
          );
          const summary: Record<RoleSuggestionKind, number> = {
            bundle: 0,
            'group-binding': 0,
            'redundant-binding': 0,
            'duplicate-roles': 0,
          };
          for (const suggestion of all) summary[suggestion.kind]++;
          all.sort(
            (a, b) =>
              kindRank[a.kind] - kindRank[b.kind] ||
              b.savings - a.savings ||
              a.id.localeCompare(b.id),
          );
          return { generatedAt: ctx.now(), summary, suggestions: all.slice(0, limit) };
        },
      );
    },
    /**
     * Peer-group outliers. `peerBy` is `manager` (default: people with the same manager) or `attribute:{name}` for a
     * declared identity attribute. A role is unusual when fewer than `threshold` (default 0.25) of the person's peers
     * hold it, and missing when at least `commonShare` (default 0.8) of them hold it; groups smaller than `minPeers`
     * (default 3, excluding the person) are skipped. Just-in-time (eligible) bindings count as held.
     */
    outliers: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        peerBy?: string;
        threshold?: number;
        commonShare?: number;
        minPeers?: number;
      },
    ): Promise<PeerOutlierResult> => {
      const peerBy = text(input.peerBy ?? 'manager', 'peerBy', 100);
      const attribute = peerBy.startsWith('attribute:') ? peerBy.slice(10) : undefined;
      if (peerBy !== 'manager' && attribute === undefined)
        throw new IamError('INVALID_INPUT', 'peerBy must be manager or attribute:{name}');
      if (attribute !== undefined && !(attribute in ctx.catalog.identityAttributes))
        throw new IamError('INVALID_INPUT', `Unknown identity attribute ${attribute}`);
      const share = (value: number | undefined, fallback: number, name: string) => {
        const result = value ?? fallback;
        if (typeof result !== 'number' || !(result > 0 && result <= 1))
          throw new IamError('INVALID_INPUT', `${name} must be a number above 0 and at most 1`);
        return result;
      };
      const threshold = share(input.threshold, 0.25, 'threshold');
      const commonShare = share(input.commonShare, 0.8, 'commonShare');
      const minPeers = integer(input.minPeers ?? 3, 'minPeers', 1, 10_000);
      return operation(
        credential,
        input.tenantId,
        'iam:analysis:read',
        'analysis/*',
        async ({ tx, tenant }) => {
          const data = await snapshot(ctx, tx, tenant.id);
          const held = heldRoles(data, { eligible: true });
          const peerValue = (identity: Identity): string | undefined => {
            if (attribute === undefined) return identity.managerId;
            const value = identity.attributes?.[attribute];
            return value === undefined || value === null || typeof value === 'object'
              ? undefined
              : String(value);
          };
          const cohorts = new Map<string, Identity[]>();
          for (const identity of data.identities) {
            const value = peerValue(identity);
            if (value === undefined) continue;
            const list = cohorts.get(value) ?? [];
            list.push(identity);
            cohorts.set(value, list);
          }
          const roleRef = (roleId: string): MiningRef => ({
            id: roleId,
            name: data.roleById.get(roleId)?.name ?? roleId,
          });
          const outliers: PeerOutlier[] = [];
          let compared = 0;
          for (const [value, cohort] of cohorts) {
            if (cohort.length - 1 < minPeers) continue;
            const counts = new Map<string, number>();
            for (const member of cohort)
              for (const roleId of held.get(member.id) ?? [])
                counts.set(roleId, (counts.get(roleId) ?? 0) + 1);
            for (const identity of cohort) {
              compared++;
              const own = held.get(identity.id) ?? new Set<string>();
              const peers = cohort.length - 1;
              const unusualRoles: PeerRoleShare[] = [];
              const missingRoles: PeerRoleShare[] = [];
              for (const [roleId, total] of counts) {
                const peersHolding = total - (own.has(roleId) ? 1 : 0);
                const fraction = peersHolding / peers;
                const entry = { role: roleRef(roleId), peersHolding, share: round(fraction) };
                if (own.has(roleId) && fraction < threshold) unusualRoles.push(entry);
                else if (!own.has(roleId) && fraction >= commonShare) missingRoles.push(entry);
              }
              if (!unusualRoles.length && !missingRoles.length) continue;
              const byShare = (a: PeerRoleShare, b: PeerRoleShare) =>
                a.share - b.share || a.role.name.localeCompare(b.role.name);
              outliers.push({
                identity: { id: identity.id, name: label(identity) },
                peerValue: value,
                peers,
                unusualRoles: unusualRoles.sort(byShare),
                missingRoles: missingRoles.sort((a, b) => -byShare(a, b)),
              });
            }
          }
          outliers.sort(
            (a, b) =>
              b.unusualRoles.length - a.unusualRoles.length ||
              b.missingRoles.length - a.missingRoles.length ||
              a.identity.name.localeCompare(b.identity.name),
          );
          return { generatedAt: ctx.now(), peerBy, identitiesCompared: compared, outliers };
        },
      );
    },
    /**
     * Carries out a `group-binding` or `redundant-binding` suggestion, recomputed inside the transaction so it
     * applies only while the condition still holds (`NOT_FOUND` otherwise). A group binding is created under the
     * authority the direct bindings share, so the caller must hold that authority (or be root) and
     * `iam:bindings:create` on the role; every removed binding needs `iam:bindings:delete`. Requires
     * iam:analysis:update. Bundles and duplicate roles are left to `packages.create` and role edits.
     */
    apply: async (
      credential: CredentialInput,
      input: { tenantId: string; suggestionId: string; minIdentities?: number; minRoles?: number },
    ) => {
      const settings = settingsOf(input);
      const wanted = text(input.suggestionId, 'suggestionId', 64);
      return operation(
        credential,
        input.tenantId,
        'iam:analysis:update',
        `analysis/${wanted}`,
        async ({ tx, tenant, principal }) => {
          const data = await snapshot(ctx, tx, tenant.id);
          const suggestion = mine(data, settings).find((entry) => entry.id === wanted);
          if (!suggestion)
            throw new IamError(
              'NOT_FOUND',
              'The suggestion no longer applies; list suggestions again',
              404,
            );
          if (!suggestion.applicable)
            throw new IamError(
              'INVALID_INPUT',
              suggestion.kind === 'bundle'
                ? 'Create an access package from a bundle with packages.create'
                : 'This suggestion cannot be applied automatically',
            );
          const bindingById = new Map(data.bindings.map((binding) => [binding.id, binding]));
          const removals = (suggestion.bindingIds ?? []).map(
            (bindingId) => bindingById.get(bindingId)!,
          );
          let created: string | undefined;
          if (suggestion.kind === 'group-binding') {
            const roleId = suggestion.roles[0]!.id;
            await allow(
              ctx,
              tx,
              principal,
              tenant.id,
              'iam:bindings:create',
              roleId,
              'bind this role',
            );
            created = (
              await createBinding(ctx, tx, principal, {
                tenantId: tenant.id,
                roleId,
                subjectType: 'group',
                subjectId: suggestion.group!.id,
                authorityId: removals[0]!.authorityId,
              })
            ).id;
          }
          for (const binding of removals) {
            await allow(
              ctx,
              tx,
              principal,
              tenant.id,
              'iam:bindings:delete',
              binding.id,
              'remove this binding',
            );
            await deleteBinding(ctx, tx, principal, binding);
          }
          return {
            applied: suggestion.kind,
            createdBindingId: created,
            removedBindingIds: removals.map((binding) => binding.id),
          };
        },
      );
    },
    /**
     * Recorded access usage (`accessUsage` option): per identity and action, when it was first and last allowed and
     * how often, newest first. Buffered usage is written first. Requires iam:analysis:read.
     */
    usage: async (
      credential: CredentialInput,
      input: { tenantId: string; identityId?: string; limit?: number; offset?: number },
    ) => {
      const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
      const offset = integer(input.offset ?? 0, 'offset', 0, 1_000_000);
      const identityId =
        input.identityId === undefined ? undefined : text(input.identityId, 'identityId');
      if (ctx.usage.enabled) await ctx.usage.flush();
      return operation(
        credential,
        input.tenantId,
        'iam:analysis:read',
        'analysis/*',
        async ({ tx, tenant }) => {
          const tracking = await tx.get<AccessUsageTracking>('accessUsageTracking', tenant.id);
          const records = (
            await tx.find<AccessUsageRecord>('accessUsage', {
              tenantId: tenant.id,
              ...(identityId ? { identityId } : {}),
            })
          ).sort(
            (a, b) =>
              b.lastUsedAt - a.lastUsedAt ||
              a.identityId.localeCompare(b.identityId) ||
              a.action.localeCompare(b.action),
          );
          return {
            tracking: ctx.usage.enabled,
            trackingSince: tracking?.startedAt,
            total: records.length,
            records: records.slice(offset, offset + limit).map((record) => ({
              identityId: record.identityId,
              action: record.action,
              firstUsedAt: record.firstUsedAt,
              lastUsedAt: record.lastUsedAt,
              count: record.count,
            })),
          };
        },
      );
    },
    /**
     * Least-privilege right-sizing from recorded usage: every live binding whose holder used none (`unused`) or only
     * some (`partial`) of the role's actions within `unusedDays` (default 90), plus per role the actions no holder
     * used. `complete` is false until usage has been recorded for the whole window. Requires iam:analysis:read.
     */
    rightSize: async (
      credential: CredentialInput,
      input: { tenantId: string; unusedDays?: number },
    ): Promise<RightSizeResult> => {
      const unusedDays = integer(input.unusedDays ?? 90, 'unusedDays', 1, 3650);
      if (ctx.usage.enabled) await ctx.usage.flush();
      return operation(
        credential,
        input.tenantId,
        'iam:analysis:read',
        'analysis/*',
        async ({ tx, tenant }) => {
          const data = await snapshot(ctx, tx, tenant.id);
          const now = ctx.now();
          const since = now - unusedDays * 86_400_000;
          const tracking = await tx.get<AccessUsageTracking>('accessUsageTracking', tenant.id);
          const used = new Map<string, Map<string, number>>();
          for (const record of await tx.find<AccessUsageRecord>('accessUsage', {
            tenantId: tenant.id,
          })) {
            if (record.lastUsedAt < since) continue;
            const actions = used.get(record.identityId) ?? new Map<string, number>();
            actions.set(record.action, record.lastUsedAt);
            used.set(record.identityId, actions);
          }
          const known = [
            ...new Set([
              ...ctx.catalog.actions,
              ...(await tx.find<ActionDefinition>('actions', { tenantId: tenant.id })).map(
                (action) => action.name,
              ),
            ]),
          ].sort();
          const granted = new Map<string, string[]>();
          const actionsOf = (role: Role) => {
            let list = granted.get(role.id);
            if (!list) granted.set(role.id, (list = roleActions(data, role, known)));
            return list;
          };
          const groupById = new Map(data.groups.map((group) => [group.id, group]));
          const entries: RightSizeEntry[] = [];
          const roleHolders = new Map<string, Set<string>>();
          const roleUsed = new Map<string, Set<string>>();
          for (const binding of data.bindings) {
            const role = data.roleById.get(binding.roleId);
            if (!role || role.protected) continue;
            const actions = actionsOf(role);
            if (!actions.length) continue;
            const group =
              binding.subjectType === 'group' ? groupById.get(binding.subjectId) : undefined;
            const holders =
              binding.subjectType === 'identity'
                ? [binding.subjectId]
                : data.members
                    .filter((member) => member.groupId === binding.subjectId)
                    .map((member) => member.identityId);
            for (const identityId of holders) {
              const identity = data.identityById.get(identityId);
              if (!identity) continue;
              const mine = used.get(identityId);
              const usedActions = actions.filter((action) => mine?.has(action));
              const holderSet = roleHolders.get(role.id) ?? new Set<string>();
              holderSet.add(identityId);
              roleHolders.set(role.id, holderSet);
              const usedSet = roleUsed.get(role.id) ?? new Set<string>();
              for (const action of usedActions) usedSet.add(action);
              roleUsed.set(role.id, usedSet);
              if (usedActions.length === actions.length) continue;
              const unused = actions.filter((action) => !mine?.has(action));
              const last = Math.max(0, ...usedActions.map((action) => mine!.get(action)!));
              entries.push({
                identity: { id: identity.id, name: label(identity) },
                role: { id: role.id, name: role.name },
                bindingId: binding.id,
                via: group
                  ? { type: 'group', id: group.id, name: group.name }
                  : { type: 'identity' },
                eligible: binding.eligible === true,
                status: usedActions.length ? 'partial' : 'unused',
                grantedActions: actions.length,
                usedActions,
                unusedActions: unused.slice(0, 50),
                unusedCount: unused.length,
                ...(last ? { lastUsedAt: last } : {}),
              });
            }
          }
          entries.sort(
            (a, b) =>
              (a.status === 'unused' ? 0 : 1) - (b.status === 'unused' ? 0 : 1) ||
              a.identity.name.localeCompare(b.identity.name) ||
              a.role.name.localeCompare(b.role.name),
          );
          const roles: RoleUsageSummary[] = [...roleHolders.entries()]
            .map(([roleId, holders]) => {
              const role = data.roleById.get(roleId)!;
              const actions = actionsOf(role);
              const usedSet = roleUsed.get(roleId) ?? new Set<string>();
              const neverUsed = actions.filter((action) => !usedSet.has(action));
              return {
                role: { id: role.id, name: role.name },
                holders: holders.size,
                grantedActions: actions.length,
                usedActions: actions.filter((action) => usedSet.has(action)),
                neverUsed: neverUsed.slice(0, 100),
                neverUsedCount: neverUsed.length,
              };
            })
            .sort(
              (a, b) =>
                b.neverUsedCount - a.neverUsedCount || a.role.name.localeCompare(b.role.name),
            );
          return {
            generatedAt: now,
            unusedDays,
            tracking: ctx.usage.enabled,
            ...(tracking ? { trackingSince: tracking.startedAt } : {}),
            complete: tracking !== undefined && tracking.startedAt <= since,
            entries,
            roles,
          };
        },
      );
    },
    /**
     * Suggested decisions for an access-certification campaign's items: `revoke` when the person is no longer
     * active or did not use the role within `unusedDays` (default 90; recorded usage when it covers the window,
     * otherwise their last sign-in), `keep` when they did, and `none` for group items and when there is no evidence.
     * Reviewers still decide. Requires iam:analysis:read.
     */
    reviewRecommendations: async (
      credential: CredentialInput,
      input: { tenantId: string; campaignId: string; unusedDays?: number },
    ): Promise<ReviewRecommendationsResult> => {
      const unusedDays = integer(input.unusedDays ?? 90, 'unusedDays', 1, 3650);
      const campaignId = text(input.campaignId, 'campaignId');
      if (ctx.usage.enabled) await ctx.usage.flush();
      return operation(
        credential,
        input.tenantId,
        'iam:analysis:read',
        'analysis/*',
        async ({ tx, tenant }) => {
          await ctx.scoped(tx, 'certificationCampaigns', campaignId, tenant.id);
          const items = await tx.find<CertificationItem>('certificationItems', {
            tenantId: tenant.id,
            campaignId,
          });
          const now = ctx.now();
          const since = now - unusedDays * 86_400_000;
          const tracking = await tx.get<AccessUsageTracking>('accessUsageTracking', tenant.id);
          const usageComplete = tracking !== undefined && tracking.startedAt <= since;
          const data = await snapshot(ctx, tx, tenant.id);
          const known = [
            ...new Set([
              ...ctx.catalog.actions,
              ...(await tx.find<ActionDefinition>('actions', { tenantId: tenant.id })).map(
                (action) => action.name,
              ),
            ]),
          ];
          const days = `${unusedDays} day${unusedDays === 1 ? '' : 's'}`;
          const recommendations: ReviewRecommendation[] = [];
          for (const item of items.sort((a, b) => a.id.localeCompare(b.id))) {
            if (item.subjectType !== 'identity') {
              recommendations.push({
                itemId: item.id,
                recommendation: 'none',
                reason: "A group's binding; review who belongs to the group instead.",
              });
              continue;
            }
            const identity = await tx.get<Identity>('identities', item.subjectId);
            if (!identity || identity.status !== 'active' || ctx.identityExpired(identity)) {
              recommendations.push({
                itemId: item.id,
                recommendation: 'revoke',
                basis: 'status',
                reason: identity
                  ? `The account is ${identity.status === 'active' ? 'expired' : identity.status}.`
                  : 'The account no longer exists.',
              });
              continue;
            }
            if (usageComplete) {
              const role = data.roleById.get(item.roleId);
              const actions = new Set(role ? roleActions(data, role, known) : []);
              const used = (
                await tx.find<AccessUsageRecord>('accessUsage', {
                  tenantId: tenant.id,
                  identityId: identity.id,
                })
              ).filter((record) => actions.has(record.action) && record.lastUsedAt >= since);
              const last = Math.max(0, ...used.map((record) => record.lastUsedAt));
              recommendations.push(
                used.length
                  ? {
                      itemId: item.id,
                      recommendation: 'keep',
                      basis: 'usage',
                      reason: `Used ${used.length} of the role's actions in the last ${days}.`,
                      lastUsedAt: last,
                    }
                  : {
                      itemId: item.id,
                      recommendation: 'revoke',
                      basis: 'usage',
                      reason: `None of the role's actions were used in the last ${days}.`,
                    },
              );
              continue;
            }
            if (identity.kind !== 'user') {
              recommendations.push({
                itemId: item.id,
                recommendation: 'none',
                reason:
                  'Service accounts do not sign in; enable access usage tracking for evidence.',
              });
              continue;
            }
            const signIns = await tx.find<AuditEvent>('audit', {
              tenantId: tenant.id,
              actorId: identity.id,
              action: 'auth:session:create',
            });
            // An administrator's "view as" session is recorded on the member but is not the member signing in.
            const own = signIns.filter((event) => !event.impersonatorId);
            const last = Math.max(0, ...own.map((event) => event.timestamp));
            recommendations.push(
              last >= since
                ? {
                    itemId: item.id,
                    recommendation: 'keep',
                    basis: 'sign-in',
                    reason: `Signed in within the last ${days}.`,
                    lastUsedAt: last,
                  }
                : {
                    itemId: item.id,
                    recommendation: 'revoke',
                    basis: 'sign-in',
                    reason: last ? `No sign-in in the last ${days}.` : 'Has never signed in.',
                  },
            );
          }
          return { campaignId, unusedDays, usageComplete, recommendations };
        },
      );
    },
  };
}
