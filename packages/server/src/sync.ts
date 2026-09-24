import {
  IamError,
  type AttributeType,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type PolicyDocument,
  type Tenant,
  type TenantAccessPolicy,
} from '@better-iam/core';
import { maxActivationMs, tenantAccessPolicy } from './access-policy.js';
import { createBinding, deleteBinding } from './api/bindings.js';
import { deleteResourceType, registerResourceType, updateResourceType } from './api/catalog.js';
import { addGroupMember, createGroup, deleteGroup, removeGroupMember } from './api/groups.js';
import { createPackage, deletePackage, updatePackage } from './api/packages.js';
import { mapRuleGroups, parseAutoAssign, ruleInput } from './package-rules.js';
import { isTeamGroup } from './teams.js';
import {
  applyOrg,
  exportOrg,
  orgRuleEnvironmentAfter,
  orgRuleIds,
  orgRuleNames,
  parseDepartmentsConfig,
  parseTeamsConfig,
  planOrg,
  readOrgState,
  type OrgPlan,
  type OrgState,
  type TenantConfigDepartment,
  type TenantConfigTeam,
} from './org-sync.js';
import {
  applyAi,
  exportAi,
  parseAgentsConfig,
  parseBudgetsConfig,
  parseModelsConfig,
  planAi,
  readAiState,
  type AiPlan,
  type AiState,
  type TenantConfigAgent,
  type TenantConfigInferenceBudget,
  type TenantConfigInferenceModel,
} from './ai-sync.js';
import { createPolicy, deletePolicy, updatePolicy } from './api/policies.js';
import { createRole, deleteRole, updateRole } from './api/roles.js';
import { deleteAgreement, saveAgreement } from './api/agreements.js';
import { saveInvariant } from './api/invariants.js';
import type { Agreement } from './agreements.js';
import type { AccessInvariant, InvariantSubject } from './invariants.js';
import type { ServerContext } from './context.js';
import type {
  PackageRuleConditions,
  AccessPackage,
  AccessWindow,
  Binding,
  Group,
  GroupMember,
  Policy,
  ResourceTypeRecord,
  Role,
} from './models.js';
import { integer, object, strings, text } from './validation.js';

/**
 * Declarative tenant configuration ("configuration as code"): the roles, policies, groups, tenant-defined resource
 * types, and group role bindings of one tenant, keyed by name so the same file applies to several environments.
 * Identities, their direct bindings, credentials, and webhooks are runtime state and are not part of it.
 */
export interface TenantConfig {
  version: 1;
  /** Tenant-defined resource types (only with `permissions.mode: 'tenant-defined'`); `actions` lists verbs. */
  resourceTypes?: TenantConfigResourceType[];
  policies?: TenantConfigPolicy[];
  roles?: TenantConfigRole[];
  groups?: TenantConfigGroup[];
  /** Group role bindings; identity bindings are assigned at runtime and never synced. */
  bindings?: TenantConfigBinding[];
  /** Organization-wide activation floors (`tenants.setAccessPolicy`); `{}` clears them. */
  accessPolicy?: TenantAccessPolicy;
  /** Access packages naming their roles, groups, and optional birthright rule; who holds them is runtime state and never synced. */
  packages?: TenantConfigPackage[];
  /** Access invariants (guardrails), naming groups and people by group name and email. */
  invariants?: TenantConfigInvariant[];
  /** Terms of use; a content change publishes a new version that everyone accepts again. */
  agreements?: TenantConfigAgreement[];
  /** Teams by slug, with maintainers and members by email and the roles they hold by name (org-sync.ts). */
  teams?: TenantConfigTeam[];
  /** Departments by name, with heads and people by email (org-sync.ts). */
  departments?: TenantConfigDepartment[];
  /** AI agents by name, with their sponsor by email; keys and delegations are runtime state (ai-sync.ts). */
  agents?: TenantConfigAgent[];
  /** The tenant's own AI models, with their provider by name (ai-sync.ts; needs the `inference` option). */
  inferenceModels?: TenantConfigInferenceModel[];
  /** Inference budgets, naming groups, people and agents (ai-sync.ts; needs the `inference` option). */
  inferenceBudgets?: TenantConfigInferenceBudget[];
}
/** An invariant's subject in a document: groups by name and people by email instead of IDs. */
export type TenantConfigInvariantSubject =
  | { everyone: true }
  | { group: string }
  | { identity: string }
  | { attribute: { name: string; value: string | number | boolean } };
export interface TenantConfigInvariant {
  name: string;
  description?: string;
  subject: TenantConfigInvariantSubject;
  action: string;
  resource: { type: string; id: string };
  expect: 'allow' | 'deny';
  /** Default `monitor`. */
  mode?: 'enforce' | 'monitor';
  /** Default true. */
  assumeMfa?: boolean;
}
export interface TenantConfigAgreement {
  name: string;
  content: string;
  url?: string;
  /** Default true. */
  required?: boolean;
  reacceptAfterDays?: number;
}
/** A package's birthright rule in a document: identity.groups values are group NAMES here (IDs in the tenant). */
export interface TenantConfigAutoAssign {
  include: PackageRuleConditions[];
  exclude?: PackageRuleConditions[];
  graceMs?: number;
  maxGrants?: number;
  maxRemovals?: number;
}
export interface TenantConfigPackage {
  name: string;
  description?: string;
  /** Role names from the same configuration or already in the tenant. */
  roles?: string[];
  /** Group names from the same configuration or already in the tenant. */
  groups?: string[];
  maxDurationMs?: number;
  requireJustification?: boolean;
  requestable?: boolean;
  /** Name of the group whose members decide on requests. */
  approverGroup?: string;
  /** The requester's manager may decide on requests. */
  managerApproval?: boolean;
  /** Birthright rule; omitted = left as it is, null = removed. Owner and revision are runtime state and never synced. */
  autoAssign?: TenantConfigAutoAssign | null;
}
export interface TenantConfigResourceType {
  name: string;
  description?: string;
  actions?: string[];
  attributes?: Record<string, AttributeType>;
  parent?: string;
  relations?: string[];
}
export interface TenantConfigPolicy {
  name: string;
  description?: string;
  document: PolicyDocument;
}
export interface TenantConfigRole {
  name: string;
  description?: string;
  /** Names of attached policies from the same configuration or already in the tenant. */
  policies?: string[];
  /** A plain permissions list (an inline allow over every resource) or a full inline document, not both. */
  permissions?: string[];
  document?: PolicyDocument;
  /** Names of roles this role inherits, from the same configuration or already in the tenant. */
  inherits?: string[];
}
export interface TenantConfigGroup {
  name: string;
  description?: string;
  /** Member emails; when present, membership is made to match exactly. */
  members?: string[];
}
export interface TenantConfigBinding {
  group: string;
  role: string;
  eligible?: boolean;
  maxActivationMs?: number;
  requireJustification?: boolean;
  requireMfa?: boolean;
  requireApproval?: boolean;
  /** Name of the group whose members approve activation requests. */
  approverGroup?: string;
  /** The requester's manager may approve activation requests. */
  managerApproval?: boolean;
  /** Business-hours access window; validated against the tenant like `bindings.create`. */
  window?: AccessWindow;
}
export type ConfigChangeKind =
  | 'resourceType'
  | 'policy'
  | 'role'
  | 'group'
  | 'binding'
  | 'package'
  | 'accessPolicy'
  | 'invariant'
  | 'agreement'
  | 'department'
  | 'team'
  | 'agent'
  | 'inferenceModel'
  | 'inferenceBudget';
export type ConfigChangeAction = 'create' | 'update' | 'delete' | 'unchanged';
export interface ConfigChange {
  kind: ConfigChangeKind;
  /** The item's name; for bindings, `{group} -> {role}`. */
  name: string;
  action: ConfigChangeAction;
  /** The properties that differ, for updates. */
  fields?: string[];
  before?: unknown;
  after?: unknown;
}
export interface ConfigPlan {
  tenantId: string;
  prune: boolean;
  changes: ConfigChange[];
  summary: Record<ConfigChangeAction, number>;
}

const kindOrder: ConfigChangeKind[] = [
  'accessPolicy',
  'resourceType',
  'policy',
  'role',
  'group',
  'binding',
  'package',
  'agreement',
  'invariant',
  'department',
  'team',
  'agent',
  'inferenceModel',
  'inferenceBudget',
];
const permissionsSid = 'RolePermissions';

/** Stable JSON for comparisons: object keys sorted at every level. */
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
const same = (a: unknown, b: unknown) => canonical(a) === canonical(b);
const sorted = (items: string[]) => [...new Set(items)].sort();

/** A role's inline document, from a permissions list or a document; undefined when it has neither. */
function roleDocument(role: TenantConfigRole): PolicyDocument | undefined {
  if (role.permissions !== undefined && role.document !== undefined)
    throw new IamError('INVALID_INPUT', `Role ${role.name}: provide permissions or a document`);
  if (role.permissions !== undefined)
    return {
      version: 1,
      statements: [
        { sid: permissionsSid, effect: 'allow', actions: role.permissions, resources: ['*'] },
      ],
    };
  return role.document;
}
/** Presents a stored inline document as a permissions list when it is exactly the compiled form. */
function exportedDocument(
  document: PolicyDocument | undefined,
): Pick<TenantConfigRole, 'permissions' | 'document'> {
  if (!document) return {};
  const statement = document.statements[0];
  if (
    document.statements.length === 1 &&
    statement &&
    statement.sid === permissionsSid &&
    statement.effect === 'allow' &&
    statement.resources.length === 1 &&
    statement.resources[0] === '*' &&
    !statement.conditions
  )
    return { permissions: [...statement.actions] };
  return { document };
}

function names<T extends { name: string }>(items: T[], kind: string): Map<string, T> {
  const map = new Map<string, T>();
  for (const item of items) {
    if (map.has(item.name)) throw new IamError('INVALID_INPUT', `Duplicate ${kind} ${item.name}`);
    map.set(item.name, item);
  }
  return map;
}

/** Validates the shape of a desired configuration; references are checked against the tenant during planning. */
export function validateTenantConfig(value: unknown): TenantConfig {
  const input = object(value);
  if (input.version !== 1) throw new IamError('INVALID_INPUT', 'Configuration version must be 1');
  const list = (key: string): Record<string, unknown>[] | undefined => {
    if (input[key] === undefined) return undefined;
    if (!Array.isArray(input[key]) || input[key].length > 1000)
      throw new IamError('INVALID_INPUT', `${key} must be an array of at most 1000 items`);
    return input[key].map((item) => object(item));
  };
  const optionalText = (item: Record<string, unknown>, key: string, max = 512) =>
    item[key] === undefined ? undefined : text(item[key], key, max);
  const optionalStrings = (item: Record<string, unknown>, key: string) =>
    item[key] === undefined ? undefined : strings(item[key], key);
  const optionalBoolean = (item: Record<string, unknown>, key: string) => {
    if (item[key] === undefined) return undefined;
    if (typeof item[key] !== 'boolean')
      throw new IamError('INVALID_INPUT', `${key} must be boolean`);
    return item[key];
  };
  /** A duration in milliseconds from a minute up to `max`; null and absent both mean none. */
  const optionalDuration = (item: Record<string, unknown>, key: string, max: number) =>
    item[key] === undefined || item[key] === null
      ? undefined
      : integer(item[key], key, 60_000, max);
  const config: TenantConfig = { version: 1 };
  const resourceTypes = list('resourceTypes');
  if (resourceTypes)
    config.resourceTypes = resourceTypes.map((item) => ({
      name: text(item.name, 'resource type name', 64),
      description: optionalText(item, 'description'),
      actions: optionalStrings(item, 'actions'),
      attributes:
        item.attributes === undefined
          ? undefined
          : (object(item.attributes) as Record<string, AttributeType>),
      parent: optionalText(item, 'parent', 64),
      relations: optionalStrings(item, 'relations'),
    }));
  const policies = list('policies');
  if (policies)
    config.policies = policies.map((item) => ({
      name: text(item.name, 'policy name'),
      description: optionalText(item, 'description'),
      document: object(item.document) as unknown as PolicyDocument,
    }));
  const roles = list('roles');
  if (roles)
    config.roles = roles.map((item) => ({
      name: text(item.name, 'role name'),
      description: optionalText(item, 'description'),
      policies: optionalStrings(item, 'policies'),
      permissions: optionalStrings(item, 'permissions'),
      document:
        item.document === undefined
          ? undefined
          : (object(item.document) as unknown as PolicyDocument),
      inherits: optionalStrings(item, 'inherits'),
    }));
  const groups = list('groups');
  if (groups)
    config.groups = groups.map((item) => ({
      name: text(item.name, 'group name'),
      description: optionalText(item, 'description'),
      members: optionalStrings(item, 'members')?.map((member) => member.trim().toLowerCase()),
    }));
  const bindings = list('bindings');
  if (bindings)
    config.bindings = bindings.map((item) => ({
      group: text(item.group, 'binding group'),
      role: text(item.role, 'binding role'),
      eligible: optionalBoolean(item, 'eligible'),
      maxActivationMs: optionalDuration(item, 'maxActivationMs', maxActivationMs),
      requireJustification: optionalBoolean(item, 'requireJustification'),
      requireMfa: optionalBoolean(item, 'requireMfa'),
      requireApproval: optionalBoolean(item, 'requireApproval'),
      approverGroup: optionalText(item, 'approverGroup'),
      managerApproval: optionalBoolean(item, 'managerApproval'),
      window:
        item.window === undefined ? undefined : (object(item.window) as unknown as AccessWindow),
    }));
  if (input.accessPolicy !== undefined)
    config.accessPolicy = tenantAccessPolicy(input.accessPolicy);
  const packages = list('packages');
  if (packages)
    config.packages = packages.map((item) => ({
      name: text(item.name, 'package name', 128),
      description: optionalText(item, 'description'),
      roles: optionalStrings(item, 'roles'),
      groups: optionalStrings(item, 'groups'),
      maxDurationMs: optionalDuration(item, 'maxDurationMs', 315360000000),
      requireJustification: optionalBoolean(item, 'requireJustification'),
      requestable: optionalBoolean(item, 'requestable'),
      approverGroup: optionalText(item, 'approverGroup'),
      managerApproval: optionalBoolean(item, 'managerApproval'),
      // Checked fully during planning, where the group names are known.
      autoAssign:
        item.autoAssign === undefined
          ? undefined
          : item.autoAssign === null
            ? null
            : (object(item.autoAssign) as unknown as TenantConfigAutoAssign),
    }));
  const invariants = list('invariants');
  if (invariants)
    config.invariants = invariants.map((item) => {
      const name = text(item.name, 'invariant name', 100);
      const subject = object(item.subject);
      const keys = Object.keys(subject);
      let parsed: TenantConfigInvariantSubject;
      if (keys.length === 1 && subject.everyone === true) parsed = { everyone: true };
      else if (keys.length === 1 && subject.group !== undefined)
        parsed = { group: text(subject.group, 'invariant subject group') };
      else if (keys.length === 1 && subject.identity !== undefined)
        parsed = { identity: text(subject.identity, 'invariant subject identity').toLowerCase() };
      else if (keys.length === 1 && subject.attribute !== undefined) {
        const attribute = object(subject.attribute);
        parsed = {
          attribute: {
            name: text(attribute.name, 'invariant subject attribute'),
            value: attribute.value as string | number | boolean,
          },
        };
      } else
        throw new IamError(
          'INVALID_INPUT',
          `Invariant ${name}: subject must be one of everyone, group, identity, or attribute`,
        );
      const resource = object(item.resource);
      if (item.expect !== 'allow' && item.expect !== 'deny')
        throw new IamError('INVALID_INPUT', `Invariant ${name}: expect must be allow or deny`);
      if (item.mode !== undefined && item.mode !== 'enforce' && item.mode !== 'monitor')
        throw new IamError('INVALID_INPUT', `Invariant ${name}: mode must be enforce or monitor`);
      return {
        name,
        description: optionalText(item, 'description', 500),
        subject: parsed,
        action: text(item.action, 'invariant action'),
        resource: {
          type: text(resource.type, 'invariant resource type'),
          id: text(resource.id, 'invariant resource id'),
        },
        expect: item.expect,
        mode: item.mode as TenantConfigInvariant['mode'],
        assumeMfa: optionalBoolean(item, 'assumeMfa'),
      };
    });
  const agreements = list('agreements');
  if (agreements)
    config.agreements = agreements.map((item) => {
      const name = text(item.name, 'agreement name', 100);
      if (typeof item.content !== 'string' || !item.content.trim())
        throw new IamError('INVALID_INPUT', `Agreement ${name}: content is required`);
      return {
        name,
        content: item.content,
        url: optionalText(item, 'url', 2048),
        required: optionalBoolean(item, 'required'),
        reacceptAfterDays:
          item.reacceptAfterDays === undefined || item.reacceptAfterDays === null
            ? undefined
            : integer(item.reacceptAfterDays, 'reacceptAfterDays', 1, 3650),
      };
    });
  // Teams and departments (org-sync.ts).
  const teams = list('teams');
  if (teams) config.teams = parseTeamsConfig(teams);
  const departments = list('departments');
  if (departments) config.departments = parseDepartmentsConfig(departments);
  // AI agents, models and budgets (ai-sync.ts).
  const agents = list('agents');
  if (agents) config.agents = parseAgentsConfig(agents);
  const inferenceModels = list('inferenceModels');
  if (inferenceModels) config.inferenceModels = parseModelsConfig(inferenceModels);
  const inferenceBudgets = list('inferenceBudgets');
  if (inferenceBudgets) config.inferenceBudgets = parseBudgetsConfig(inferenceBudgets);
  for (const [key, items] of [
    ['resource type', config.resourceTypes],
    ['policy', config.policies],
    ['role', config.roles],
    ['group', config.groups],
  ] as const)
    if (items) names(items, key);
  // Invariant and agreement names are unique regardless of case, as their APIs enforce.
  for (const [key, items] of [
    ['invariant', config.invariants],
    ['agreement', config.agreements],
  ] as const)
    if (items)
      names(
        items.map((item) => ({ name: item.name.trim().toLowerCase() })),
        key,
      );
  // Package names are unique regardless of case, as `packages.create` enforces.
  if (config.packages)
    names(
      config.packages.map((pkg) => ({ ...pkg, name: pkg.name.trim().toLowerCase() })),
      'package',
    );
  if (config.bindings) {
    const seen = new Set<string>();
    for (const binding of config.bindings) {
      const key = `${binding.group} -> ${binding.role}`;
      if (seen.has(key)) throw new IamError('INVALID_INPUT', `Duplicate binding ${key}`);
      seen.add(key);
    }
  }
  return config;
}

/** The tenant's current state in configuration form, with the records behind each item. */
interface CurrentState {
  tenant: Tenant;
  resourceTypes: ResourceTypeRecord[];
  resourceTypeActions: Map<string, string[]>;
  policies: Policy[];
  roles: Role[];
  groups: Group[];
  members: Map<string, Identity[]>;
  bindings: Binding[];
  packages: AccessPackage[];
  identitiesByEmail: Map<string, Identity>;
  identityEmails: Map<string, string>;
  invariants: AccessInvariant[];
  agreements: Agreement[];
  /** Teams and departments (org-sync.ts). */
  org: OrgState;
  /** AI agents, models and budgets (ai-sync.ts). */
  ai: AiState;
}

async function readState(
  ctx: ServerContext,
  tx: IamStore,
  tenantId: string,
): Promise<CurrentState> {
  const byName = (a: { name: string }, b: { name: string }) =>
    a.name < b.name ? -1 : a.name > b.name ? 1 : 0;
  const tenant = await ctx.tenant(tx, tenantId);
  const resourceTypes = (await tx.find<ResourceTypeRecord>('resourceTypes', { tenantId })).sort(
    byName,
  );
  const resourceTypeActions = new Map<string, string[]>();
  for (const type of resourceTypes)
    resourceTypeActions.set(
      type.name,
      (await ctx.catalog.resourceTypeDefinition(tx, tenantId, type.name))?.actions
        .map((action) => action.slice(type.name.length + 1))
        .sort() ?? [],
    );
  const policies = (await tx.find<Policy>('policies', { tenantId }))
    .filter((policy) => policy.uniqueKey !== 'system:owner')
    .sort(byName);
  const roles = (await tx.find<Role>('roles', { tenantId }))
    .filter((role) => !role.protected)
    .sort(byName);
  // Teams' backing groups (and what is bound to them) belong to the teams API, never to configuration sync.
  const allGroups = await tx.find<Group>('groups', { tenantId });
  const outsideGroupIds = new Set(allGroups.filter(isTeamGroup).map((group) => group.id));
  // Configuration names groups, and an identity provider's directory sync (SCIM) names the groups it creates: when
  // such a group shares its name with another group, the name means the other one, so an IdP cannot capture the roles
  // and approvals configuration gives a group by creating one of the same name. Those groups stay out of sync's view.
  const scimGroupIds = new Set(
    (await tx.find('scimGroups', { tenantId })).map((link) => String(link.groupId)),
  );
  const ownNames = new Set(
    allGroups
      .filter((group) => !outsideGroupIds.has(group.id) && !scimGroupIds.has(group.id))
      .map((group) => group.name),
  );
  for (const group of allGroups)
    if (scimGroupIds.has(group.id) && ownNames.has(group.name)) outsideGroupIds.add(group.id);
  const groups = allGroups.filter((group) => !outsideGroupIds.has(group.id)).sort(byName);
  const identities = (await tx.find<Identity>('identities', { tenantId })).filter(
    (identity) => identity.status !== 'deleted',
  );
  const identitiesByEmail = new Map<string, Identity>();
  for (const identity of identities)
    if (identity.email) identitiesByEmail.set(identity.email.toLowerCase(), identity);
  const members = new Map<string, Identity[]>();
  const byId = new Map(identities.map((identity) => [identity.id, identity]));
  for (const membership of await tx.find<GroupMember>('groupMembers', { tenantId })) {
    const identity = byId.get(membership.identityId);
    if (!identity || !ctx.liveMembership(membership)) continue;
    members.set(membership.groupId, [...(members.get(membership.groupId) ?? []), identity]);
  }
  const bindings = (await tx.find<Binding>('bindings', { tenantId, subjectType: 'group' })).filter(
    (binding) => !ctx.expiredBinding(binding) && !outsideGroupIds.has(binding.subjectId),
  );
  const packages = (await tx.find<AccessPackage>('accessPackages', { tenantId })).sort(byName);
  const invariants = (await tx.find<AccessInvariant>('accessInvariants', { tenantId })).sort(
    byName,
  );
  const agreements = (await tx.find<Agreement>('agreements', { tenantId })).sort(byName);
  const identityEmails = new Map<string, string>();
  for (const identity of identities)
    if (identity.email) identityEmails.set(identity.id, identity.email.toLowerCase());
  return {
    tenant,
    resourceTypes,
    resourceTypeActions,
    policies,
    roles,
    groups,
    members,
    bindings,
    packages,
    identitiesByEmail,
    identityEmails,
    invariants,
    agreements,
    org: await readOrgState(ctx, tx, tenantId),
    ai: await readAiState(ctx, tx, tenantId),
  };
}

/** An invariant's stored subject in document form (group names, member emails); unknown references keep their IDs. */
function portableSubject(
  subject: InvariantSubject,
  groupNames: Map<string, string>,
  identityEmails: Map<string, string>,
): TenantConfigInvariantSubject {
  if ('groupId' in subject) return { group: groupNames.get(subject.groupId) ?? subject.groupId };
  if ('identityId' in subject)
    return { identity: identityEmails.get(subject.identityId) ?? subject.identityId };
  if ('attribute' in subject) return { attribute: subject.attribute };
  return { everyone: true };
}
/** An invariant record in document form, with defaults filled in so plans compare like with like. */
function exportedInvariant(
  invariant: AccessInvariant,
  groupNames: Map<string, string>,
  identityEmails: Map<string, string>,
): Required<Omit<TenantConfigInvariant, 'description'>> & { description?: string } {
  return {
    name: invariant.name,
    ...(invariant.description !== undefined ? { description: invariant.description } : {}),
    subject: portableSubject(invariant.subject, groupNames, identityEmails),
    action: invariant.action,
    resource: invariant.resource,
    expect: invariant.expect,
    mode: invariant.mode,
    assumeMfa: invariant.assumeMfa,
  };
}
function exportedAgreement(agreement: Agreement): TenantConfigAgreement {
  return {
    name: agreement.name,
    content: agreement.content,
    ...(agreement.url !== undefined ? { url: agreement.url } : {}),
    required: agreement.required,
    ...(agreement.reacceptAfterDays !== undefined
      ? { reacceptAfterDays: agreement.reacceptAfterDays }
      : {}),
  };
}

function exportState(state: CurrentState): TenantConfig {
  const policyNames = new Map(state.policies.map((policy) => [policy.id, policy.name]));
  const roleNames = new Map(state.roles.map((role) => [role.id, role.name]));
  const groupNames = new Map(state.groups.map((group) => [group.id, group.name]));
  const config: TenantConfig = {
    version: 1,
    resourceTypes: state.resourceTypes.map((type) => ({
      name: type.name,
      ...(type.description !== undefined ? { description: type.description } : {}),
      actions: state.resourceTypeActions.get(type.name) ?? [],
      attributes: type.attributes,
      ...(type.parent !== undefined ? { parent: type.parent } : {}),
      relations: [...(type.relations ?? [])].sort(),
    })),
    policies: state.policies.map((policy) => ({
      name: policy.name,
      ...(policy.description !== undefined ? { description: policy.description } : {}),
      document: policy.document,
    })),
    roles: state.roles.map((role) => ({
      name: role.name,
      ...(role.description !== undefined ? { description: role.description } : {}),
      policies: sorted(
        role.policyIds.flatMap((policyId) => {
          const name = policyNames.get(policyId);
          return name === undefined ? [] : [name];
        }),
      ),
      ...exportedDocument(role.document),
      ...(role.inherits?.length
        ? {
            inherits: sorted(
              role.inherits.flatMap((roleId) => {
                const name = roleNames.get(roleId);
                return name === undefined ? [] : [name];
              }),
            ),
          }
        : {}),
    })),
    groups: state.groups.map((group) => ({
      name: group.name,
      ...(group.description !== undefined ? { description: group.description } : {}),
      members: sorted(
        (state.members.get(group.id) ?? []).flatMap((identity) =>
          identity.email ? [identity.email.toLowerCase()] : [],
        ),
      ),
    })),
    bindings: state.bindings
      .flatMap((binding) => {
        const group = groupNames.get(binding.subjectId);
        const role = roleNames.get(binding.roleId);
        if (group === undefined || role === undefined) return [];
        return [
          {
            group,
            role,
            ...(binding.eligible
              ? {
                  eligible: true,
                  ...(binding.maxActivationMs !== undefined
                    ? { maxActivationMs: binding.maxActivationMs }
                    : {}),
                  ...(binding.requireJustification ? { requireJustification: true } : {}),
                  ...(binding.requireMfa ? { requireMfa: true } : {}),
                  ...(binding.requireApproval ? { requireApproval: true } : {}),
                  ...(binding.approverGroupId && groupNames.has(binding.approverGroupId)
                    ? { approverGroup: groupNames.get(binding.approverGroupId)! }
                    : {}),
                  ...(binding.managerApproval ? { managerApproval: true } : {}),
                }
              : {}),
            ...(binding.window ? { window: binding.window } : {}),
          },
        ];
      })
      .sort((a, b) => `${a.group} -> ${a.role}`.localeCompare(`${b.group} -> ${b.role}`, 'en')),
    packages: state.packages.map((pkg) => ({
      name: pkg.name,
      ...(pkg.description !== undefined ? { description: pkg.description } : {}),
      roles: sorted(
        pkg.roleIds.flatMap((roleId) => {
          const name = roleNames.get(roleId);
          return name === undefined ? [] : [name];
        }),
      ),
      groups: sorted(
        pkg.groupIds.flatMap((groupId) => {
          const name = groupNames.get(groupId);
          return name === undefined ? [] : [name];
        }),
      ),
      ...(pkg.maxDurationMs !== undefined ? { maxDurationMs: pkg.maxDurationMs } : {}),
      ...(pkg.requireJustification ? { requireJustification: true } : {}),
      ...(pkg.requestable ? { requestable: true } : {}),
      ...(pkg.approverGroupId && groupNames.has(pkg.approverGroupId)
        ? { approverGroup: groupNames.get(pkg.approverGroupId)! }
        : {}),
      ...(pkg.managerApproval ? { managerApproval: true } : {}),
      // The rule as written, with group names; owner, authority, revision, and approval are runtime state.
      ...(pkg.autoAssign
        ? {
            autoAssign: orgRuleNames(
              state.org,
              mapRuleGroups(
                ruleInput(pkg.autoAssign),
                (groupId) => groupNames.get(groupId) ?? groupId,
              ),
            ),
          }
        : {}),
    })),
  };
  if (state.tenant.accessPolicy) config.accessPolicy = state.tenant.accessPolicy;
  // Listed only when the tenant has some, so documents of tenants that use neither stay unchanged.
  if (state.invariants.length)
    config.invariants = state.invariants.map((invariant) =>
      exportedInvariant(invariant, groupNames, state.identityEmails),
    );
  if (state.agreements.length) config.agreements = state.agreements.map(exportedAgreement);
  // Teams and departments (org-sync.ts), each only when the tenant has some.
  Object.assign(
    config,
    exportOrg(state.org, { identityEmails: state.identityEmails, roleNames, groupNames }),
  );
  // AI agents, models and budgets (ai-sync.ts), each only when the tenant has some.
  Object.assign(config, exportAi(state.ai, { identityEmails: state.identityEmails, groupNames }));
  return config;
}

/** One desired item next to the record it matches, if any. */
interface Planned<D, R> {
  change: ConfigChange;
  desired?: D;
  record?: R;
}

interface PlanResult {
  plan: ConfigPlan;
  accessPolicy?: Planned<TenantAccessPolicy, Tenant>;
  resourceTypes: Planned<TenantConfigResourceType, ResourceTypeRecord>[];
  policies: Planned<TenantConfigPolicy, Policy>[];
  roles: Planned<TenantConfigRole, Role>[];
  groups: Planned<TenantConfigGroup, Group>[];
  bindings: Planned<TenantConfigBinding, Binding[]>[];
  packages: Planned<TenantConfigPackage, AccessPackage>[];
  invariants: Planned<TenantConfigInvariant, AccessInvariant>[];
  agreements: Planned<TenantConfigAgreement, Agreement>[];
  /** Teams and departments (org-sync.ts). */
  org: OrgPlan;
  /** AI agents, models and budgets (ai-sync.ts). */
  ai: AiPlan;
}

function diffFields(before: Record<string, unknown>, after: Record<string, unknown>): string[] {
  return [...new Set([...Object.keys(before), ...Object.keys(after)])]
    .filter((key) => !same(before[key], after[key]))
    .sort();
}

function computePlan(
  ctx: ServerContext,
  tenantId: string,
  desired: TenantConfig,
  state: CurrentState,
  prune: boolean,
): PlanResult {
  const result: PlanResult = {
    plan: {
      tenantId,
      prune,
      changes: [],
      summary: { create: 0, update: 0, delete: 0, unchanged: 0 },
    },
    resourceTypes: [],
    policies: [],
    roles: [],
    groups: [],
    bindings: [],
    packages: [],
    invariants: [],
    agreements: [],
    org: { teams: [], departments: [] },
    ai: { agents: [], models: [], budgets: [] },
  };
  const push = <D, R>(list: Planned<D, R>[], item: Planned<D, R>) => {
    list.push(item);
    result.plan.changes.push(item.change);
    result.plan.summary[item.change.action]++;
  };
  // Access policy (one record; a present document value replaces it, `{}` clears it)
  if (desired.accessPolicy !== undefined) {
    const before = state.tenant.accessPolicy ?? {};
    const after = desired.accessPolicy;
    const fields = diffFields(
      { ...before } as Record<string, unknown>,
      {
        ...after,
      } as Record<string, unknown>,
    );
    const change: ConfigChange = fields.length
      ? { kind: 'accessPolicy', name: 'accessPolicy', action: 'update', fields, before, after }
      : { kind: 'accessPolicy', name: 'accessPolicy', action: 'unchanged' };
    result.accessPolicy = { change, desired: after, record: state.tenant };
    result.plan.changes.push(change);
    result.plan.summary[change.action]++;
  }
  // Resource types
  if (desired.resourceTypes) {
    const existing = new Map(state.resourceTypes.map((type) => [type.name, type]));
    for (const type of desired.resourceTypes) {
      const record = existing.get(type.name);
      const after = {
        description: type.description,
        actions: sorted(type.actions ?? []),
        attributes: type.attributes ?? {},
        parent: type.parent,
        relations: sorted(type.relations ?? []),
      };
      if (!record) {
        push(result.resourceTypes, {
          change: { kind: 'resourceType', name: type.name, action: 'create', after },
          desired: type,
        });
        continue;
      }
      const before = {
        description: record.description,
        actions: state.resourceTypeActions.get(record.name) ?? [],
        attributes: record.attributes,
        parent: record.parent,
        relations: sorted(record.relations ?? []),
      };
      const fields = diffFields(before, after);
      if (fields.includes('parent'))
        throw new IamError(
          'INVALID_INPUT',
          `Resource type ${type.name}: the parent cannot change; delete and recreate the type`,
        );
      push(result.resourceTypes, {
        change: fields.length
          ? { kind: 'resourceType', name: type.name, action: 'update', fields, before, after }
          : { kind: 'resourceType', name: type.name, action: 'unchanged' },
        desired: type,
        record,
      });
    }
    if (prune)
      for (const record of state.resourceTypes)
        if (!desired.resourceTypes.some((type) => type.name === record.name))
          push(result.resourceTypes, {
            change: { kind: 'resourceType', name: record.name, action: 'delete' },
            record,
          });
  }
  // Policies
  const policyNamesAfter = new Set<string>();
  if (desired.policies) {
    const existing = new Map(state.policies.map((policy) => [policy.name, policy]));
    for (const policy of desired.policies) {
      policyNamesAfter.add(policy.name);
      const record = existing.get(policy.name);
      const after = { description: policy.description, document: policy.document };
      if (!record) {
        push(result.policies, {
          change: { kind: 'policy', name: policy.name, action: 'create', after },
          desired: policy,
        });
        continue;
      }
      const before = { description: record.description, document: record.document };
      const fields = diffFields(before, after);
      push(result.policies, {
        change: fields.length
          ? { kind: 'policy', name: policy.name, action: 'update', fields, before, after }
          : { kind: 'policy', name: policy.name, action: 'unchanged' },
        desired: policy,
        record,
      });
    }
    for (const record of state.policies)
      if (!existing.has(record.name) || !desired.policies.some((p) => p.name === record.name)) {
        if (desired.policies.some((p) => p.name === record.name)) continue;
        if (prune)
          push(result.policies, {
            change: { kind: 'policy', name: record.name, action: 'delete' },
            record,
          });
        else policyNamesAfter.add(record.name);
      }
  } else for (const record of state.policies) policyNamesAfter.add(record.name);
  // Roles
  const roleNamesAfter = new Set<string>();
  if (desired.roles) {
    const existing = new Map(state.roles.map((role) => [role.name, role]));
    const policyNames = new Map(state.policies.map((policy) => [policy.id, policy.name]));
    const roleNames = new Map(state.roles.map((role) => [role.id, role.name]));
    // Every role of the document plus the survivors decides which inheritance targets exist afterwards.
    const rolesAfterApply = new Set(desired.roles.map((role) => role.name));
    if (!prune) for (const record of state.roles) rolesAfterApply.add(record.name);
    for (const role of desired.roles) {
      roleNamesAfter.add(role.name);
      for (const name of role.policies ?? [])
        if (!policyNamesAfter.has(name))
          throw new IamError('INVALID_INPUT', `Role ${role.name} attaches unknown policy ${name}`);
      for (const name of role.inherits ?? []) {
        if (name === role.name)
          throw new IamError('INVALID_INPUT', `Role ${role.name} cannot inherit itself`);
        if (!rolesAfterApply.has(name))
          throw new IamError('INVALID_INPUT', `Role ${role.name} inherits unknown role ${name}`);
      }
      const record = existing.get(role.name);
      const after = {
        description: role.description,
        policies: sorted(role.policies ?? []),
        document: roleDocument(role),
        inherits: sorted(role.inherits ?? []),
      };
      if (!record) {
        push(result.roles, {
          change: { kind: 'role', name: role.name, action: 'create', after },
          desired: role,
        });
        continue;
      }
      const before = {
        description: record.description,
        policies: sorted(
          record.policyIds.flatMap((policyId) => {
            const name = policyNames.get(policyId);
            return name === undefined ? [] : [name];
          }),
        ),
        document: record.document,
        inherits: sorted(
          (record.inherits ?? []).flatMap((roleId) => {
            const name = roleNames.get(roleId);
            return name === undefined ? [] : [name];
          }),
        ),
      };
      const fields = diffFields(before, after);
      push(result.roles, {
        change: fields.length
          ? { kind: 'role', name: role.name, action: 'update', fields, before, after }
          : { kind: 'role', name: role.name, action: 'unchanged' },
        desired: role,
        record,
      });
    }
    for (const record of state.roles)
      if (!desired.roles.some((role) => role.name === record.name)) {
        if (prune)
          push(result.roles, {
            change: { kind: 'role', name: record.name, action: 'delete' },
            record,
          });
        else roleNamesAfter.add(record.name);
      }
  } else for (const record of state.roles) roleNamesAfter.add(record.name);
  // Groups
  const groupNamesAfter = new Set<string>();
  if (desired.groups) {
    const existing = new Map(state.groups.map((group) => [group.name, group]));
    for (const group of desired.groups) {
      groupNamesAfter.add(group.name);
      for (const email of group.members ?? [])
        if (!state.identitiesByEmail.has(email))
          throw new IamError('INVALID_INPUT', `Group ${group.name}: unknown member ${email}`);
      const record = existing.get(group.name);
      const after = {
        description: group.description,
        ...(group.members !== undefined ? { members: sorted(group.members) } : {}),
      };
      if (!record) {
        push(result.groups, {
          change: { kind: 'group', name: group.name, action: 'create', after },
          desired: group,
        });
        continue;
      }
      const before = {
        description: record.description,
        ...(group.members !== undefined
          ? {
              members: sorted(
                (state.members.get(record.id) ?? []).flatMap((identity) =>
                  identity.email ? [identity.email.toLowerCase()] : [],
                ),
              ),
            }
          : {}),
      };
      const fields = diffFields(before, after);
      push(result.groups, {
        change: fields.length
          ? { kind: 'group', name: group.name, action: 'update', fields, before, after }
          : { kind: 'group', name: group.name, action: 'unchanged' },
        desired: group,
        record,
      });
    }
    for (const record of state.groups)
      if (!desired.groups.some((group) => group.name === record.name)) {
        if (prune)
          push(result.groups, {
            change: { kind: 'group', name: record.name, action: 'delete' },
            record,
          });
        else groupNamesAfter.add(record.name);
      }
  } else for (const record of state.groups) groupNamesAfter.add(record.name);
  // Group bindings
  if (desired.bindings) {
    const roleNames = new Map(state.roles.map((role) => [role.id, role.name]));
    const groupNames = new Map(state.groups.map((group) => [group.id, group.name]));
    const key = (binding: Binding) =>
      `${groupNames.get(binding.subjectId) ?? binding.subjectId} -> ${roleNames.get(binding.roleId) ?? binding.roleId}`;
    const existing = new Map<string, Binding[]>();
    for (const binding of state.bindings)
      if (groupNames.has(binding.subjectId) && roleNames.has(binding.roleId))
        existing.set(key(binding), [...(existing.get(key(binding)) ?? []), binding]);
    const wanted = new Set<string>();
    for (const binding of desired.bindings) {
      const name = `${binding.group} -> ${binding.role}`;
      wanted.add(name);
      if (!groupNamesAfter.has(binding.group))
        throw new IamError('INVALID_INPUT', `Binding ${name}: unknown group ${binding.group}`);
      if (!roleNamesAfter.has(binding.role))
        throw new IamError('INVALID_INPUT', `Binding ${name}: unknown role ${binding.role}`);
      const after = {
        eligible: binding.eligible === true,
        maxActivationMs: binding.eligible ? binding.maxActivationMs : undefined,
        requireJustification: binding.eligible ? binding.requireJustification === true : false,
        requireMfa: binding.eligible ? binding.requireMfa === true : false,
        requireApproval: binding.eligible ? binding.requireApproval === true : false,
        approverGroup: binding.eligible ? binding.approverGroup : undefined,
        managerApproval: binding.eligible ? binding.managerApproval === true : false,
        window: binding.window === undefined ? undefined : ctx.accessWindow(binding.window),
      };
      if (after.approverGroup !== undefined && !groupNamesAfter.has(after.approverGroup))
        throw new IamError(
          'INVALID_INPUT',
          `Binding ${name}: unknown approver group ${after.approverGroup}`,
        );
      const records = existing.get(name);
      if (!records) {
        push(result.bindings, {
          change: { kind: 'binding', name, action: 'create', after },
          desired: binding,
        });
        continue;
      }
      const first = records[0]!;
      const before = {
        eligible: first.eligible === true,
        maxActivationMs: first.maxActivationMs,
        requireJustification: first.requireJustification === true,
        requireMfa: first.requireMfa === true,
        requireApproval: first.requireApproval === true,
        approverGroup:
          first.approverGroupId !== undefined ? groupNames.get(first.approverGroupId) : undefined,
        managerApproval: first.managerApproval === true,
        window: first.window,
      };
      const fields = diffFields(before, after);
      push(result.bindings, {
        change: fields.length
          ? { kind: 'binding', name, action: 'update', fields, before, after }
          : { kind: 'binding', name, action: 'unchanged' },
        desired: binding,
        record: records,
      });
    }
    if (prune)
      for (const [name, records] of existing)
        if (!wanted.has(name))
          push(result.bindings, {
            change: { kind: 'binding', name, action: 'delete' },
            record: records,
          });
  }
  // Access packages
  if (desired.packages) {
    const roleNames = new Map(state.roles.map((role) => [role.id, role.name]));
    const groupNames = new Map(state.groups.map((group) => [group.id, group.name]));
    // Matched regardless of case, like package uniqueness; a case-only difference is a rename.
    const packageKey = (name: string) => name.trim().toLowerCase();
    const existing = new Map(state.packages.map((pkg) => [packageKey(pkg.name), pkg]));
    // Rules name teams by slug and departments by name (org-sync.ts).
    const orgAfter = orgRuleEnvironmentAfter(desired, state.org, prune);
    for (const pkg of desired.packages) {
      for (const name of pkg.roles ?? [])
        if (!roleNamesAfter.has(name))
          throw new IamError('INVALID_INPUT', `Package ${pkg.name}: unknown role ${name}`);
      for (const name of pkg.groups ?? [])
        if (!groupNamesAfter.has(name))
          throw new IamError('INVALID_INPUT', `Package ${pkg.name}: unknown group ${name}`);
      if (!pkg.roles?.length && !pkg.groups?.length)
        throw new IamError('INVALID_INPUT', `Package ${pkg.name} needs at least one role or group`);
      if (pkg.approverGroup !== undefined && !groupNamesAfter.has(pkg.approverGroup))
        throw new IamError(
          'INVALID_INPUT',
          `Package ${pkg.name}: unknown approver group ${pkg.approverGroup}`,
        );
      // A rule is compared only when the document names one: omission leaves it alone, null removes it.
      let rule: TenantConfigAutoAssign | null | undefined;
      if (pkg.autoAssign === null) rule = null;
      else if (pkg.autoAssign !== undefined) {
        rule = parseAutoAssign(
          pkg.autoAssign,
          {
            identityAttributes: ctx.catalog.identityAttributes,
            groups: groupNamesAfter,
            packagedGroups: new Set(pkg.groups ?? []),
            org: orgAfter.env,
          },
          `Package ${pkg.name}: autoAssign`,
        );
        rule = orgAfter.canonical(rule);
        if (pkg.maxDurationMs !== undefined)
          throw new IamError(
            'INVALID_INPUT',
            `Package ${pkg.name}: a package with autoAssign cannot have maxDurationMs`,
          );
      }
      const normalized: TenantConfigPackage =
        rule !== undefined ? { ...pkg, autoAssign: rule } : pkg;
      const renamed = existing.get(packageKey(pkg.name));
      const after = {
        ...(rule !== undefined ? { autoAssign: rule } : {}),
        ...(renamed && renamed.name !== pkg.name ? { name: pkg.name } : {}),
        description: pkg.description,
        roles: sorted(pkg.roles ?? []),
        groups: sorted(pkg.groups ?? []),
        maxDurationMs: pkg.maxDurationMs,
        requireJustification: pkg.requireJustification === true,
        requestable: pkg.requestable === true,
        approverGroup: pkg.approverGroup,
        managerApproval: pkg.managerApproval === true,
      };
      const record = existing.get(packageKey(pkg.name));
      if (!record) {
        push(result.packages, {
          change: { kind: 'package', name: pkg.name, action: 'create', after },
          desired: normalized,
        });
        continue;
      }
      const before = {
        ...(rule !== undefined
          ? {
              autoAssign: record.autoAssign
                ? orgRuleNames(
                    state.org,
                    mapRuleGroups(
                      ruleInput(record.autoAssign),
                      (groupId) => groupNames.get(groupId) ?? groupId,
                    ),
                  )
                : null,
            }
          : {}),
        ...(record.name !== pkg.name ? { name: record.name } : {}),
        description: record.description,
        roles: sorted(
          record.roleIds.flatMap((roleId) => {
            const name = roleNames.get(roleId);
            return name === undefined ? [] : [name];
          }),
        ),
        groups: sorted(
          record.groupIds.flatMap((groupId) => {
            const name = groupNames.get(groupId);
            return name === undefined ? [] : [name];
          }),
        ),
        maxDurationMs: record.maxDurationMs,
        requireJustification: record.requireJustification === true,
        requestable: record.requestable === true,
        approverGroup:
          record.approverGroupId !== undefined ? groupNames.get(record.approverGroupId) : undefined,
        managerApproval: record.managerApproval === true,
      };
      const fields = diffFields(before, after);
      push(result.packages, {
        change: fields.length
          ? { kind: 'package', name: pkg.name, action: 'update', fields, before, after }
          : { kind: 'package', name: pkg.name, action: 'unchanged' },
        desired: normalized,
        record,
      });
    }
    if (prune)
      for (const record of state.packages)
        if (!desired.packages.some((pkg) => packageKey(pkg.name) === packageKey(record.name)))
          push(result.packages, {
            change: { kind: 'package', name: record.name, action: 'delete' },
            record,
          });
  }
  // Terms of use (matched by name regardless of case)
  const lower = (name: string) => name.trim().toLowerCase();
  if (desired.agreements) {
    const existing = new Map(
      state.agreements.map((agreement) => [lower(agreement.name), agreement]),
    );
    for (const agreement of desired.agreements) {
      const record = existing.get(lower(agreement.name));
      const after = exportedAgreement({
        ...agreement,
        required: agreement.required ?? true,
      } as Agreement);
      if (!record) {
        push(result.agreements, {
          change: { kind: 'agreement', name: agreement.name, action: 'create', after },
          desired: agreement,
        });
        continue;
      }
      const before = exportedAgreement(record);
      const fields = diffFields(
        before as unknown as Record<string, unknown>,
        after as unknown as Record<string, unknown>,
      );
      push(result.agreements, {
        change: fields.length
          ? { kind: 'agreement', name: agreement.name, action: 'update', fields, before, after }
          : { kind: 'agreement', name: agreement.name, action: 'unchanged' },
        desired: agreement,
        record,
      });
    }
    if (prune)
      for (const record of state.agreements)
        if (!desired.agreements.some((agreement) => lower(agreement.name) === lower(record.name)))
          push(result.agreements, {
            change: { kind: 'agreement', name: record.name, action: 'delete' },
            record,
          });
  }
  // Access invariants: their groups must exist after the apply, their people now.
  if (desired.invariants) {
    const groupNames = new Map(state.groups.map((group) => [group.id, group.name]));
    const existing = new Map(
      state.invariants.map((invariant) => [lower(invariant.name), invariant]),
    );
    for (const invariant of desired.invariants) {
      const subject = invariant.subject;
      if ('group' in subject && !groupNamesAfter.has(subject.group))
        throw new IamError(
          'INVALID_INPUT',
          `Invariant ${invariant.name}: unknown group ${subject.group}`,
        );
      if ('identity' in subject && !state.identitiesByEmail.has(subject.identity))
        throw new IamError(
          'INVALID_INPUT',
          `Invariant ${invariant.name}: unknown person ${subject.identity}`,
        );
      const after = {
        ...(invariant.description !== undefined ? { description: invariant.description } : {}),
        subject,
        action: invariant.action,
        resource: invariant.resource,
        expect: invariant.expect,
        mode: invariant.mode ?? 'monitor',
        assumeMfa: invariant.assumeMfa ?? true,
      };
      const record = existing.get(lower(invariant.name));
      if (!record) {
        push(result.invariants, {
          change: { kind: 'invariant', name: invariant.name, action: 'create', after },
          desired: invariant,
        });
        continue;
      }
      const { name: _name, ...before } = exportedInvariant(
        record,
        groupNames,
        state.identityEmails,
      );
      const fields = diffFields(before, after);
      if (record.name !== invariant.name) fields.push('name');
      push(result.invariants, {
        change: fields.length
          ? { kind: 'invariant', name: invariant.name, action: 'update', fields, before, after }
          : { kind: 'invariant', name: invariant.name, action: 'unchanged' },
        desired: invariant,
        record,
      });
    }
    if (prune)
      for (const record of state.invariants)
        if (!desired.invariants.some((invariant) => lower(invariant.name) === lower(record.name)))
          push(result.invariants, {
            change: { kind: 'invariant', name: record.name, action: 'delete' },
            record,
          });
  }
  // Teams and departments (org-sync.ts): their roles must exist after the apply, their people now.
  if (desired.teams || desired.departments) {
    result.org = planOrg(desired, state.org, {
      identityEmails: state.identityEmails,
      roleNames: new Map(state.roles.map((role) => [role.id, role.name])),
      groupNames: new Map(state.groups.map((group) => [group.id, group.name])),
      identitiesByEmail: state.identitiesByEmail,
      roleNamesAfter,
      groupNamesAfter,
      prune,
    });
    for (const item of [...result.org.departments, ...result.org.teams]) {
      result.plan.changes.push(item.change);
      result.plan.summary[item.change.action]++;
    }
  }
  // AI agents, models and budgets (ai-sync.ts): sponsors are people now, budget groups exist after the apply.
  if (desired.agents || desired.inferenceModels || desired.inferenceBudgets) {
    result.ai = planAi(desired, state.ai, {
      identityEmails: state.identityEmails,
      groupNames: new Map(state.groups.map((group) => [group.id, group.name])),
      identitiesByEmail: state.identitiesByEmail,
      groupNamesAfter,
      prune,
    });
    for (const item of [...result.ai.agents, ...result.ai.models, ...result.ai.budgets]) {
      result.plan.changes.push(item.change);
      result.plan.summary[item.change.action]++;
    }
  }
  result.plan.changes.sort(
    (a, b) =>
      kindOrder.indexOf(a.kind) - kindOrder.indexOf(b.kind) || a.name.localeCompare(b.name, 'en'),
  );
  return result;
}

export function createConfigApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  /** Every change is authorized like the equivalent direct API call; one denial rejects the whole apply. */
  async function allow(
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
  async function apply(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenant: Tenant,
    planned: PlanResult,
    state: CurrentState,
  ): Promise<void> {
    const tenantId = tenant.id;
    if (planned.accessPolicy?.change.action === 'update') {
      await allow(
        tx,
        principal,
        tenantId,
        'iam:tenants:update',
        tenantId,
        'change the access policy',
      );
      // As `tenants.setAccessPolicy`: loosening elevation floors needs a fresh sign-in in person (not a stale,
      // impersonated, assumed-role or delegated session), and is audited as such.
      ctx.auth.requireRecent(principal);
      const { accessPolicy: _previous, ...rest } = planned.accessPolicy.record!;
      const policy = planned.accessPolicy.desired!;
      await tx.put<Tenant>(
        'tenants',
        Object.keys(policy).length ? { ...rest, accessPolicy: policy } : rest,
      );
      await ctx.events.audit(tx, principal, 'tenant:access-policy', tenantId, tenantId, 'allow', false, {
        accessPolicy: (Object.keys(policy).length ? policy : null) as Json,
      });
    }
    // Resource types first: policies and roles may name their actions.
    for (const item of planned.resourceTypes) {
      const { change, desired, record } = item;
      if (change.action === 'create') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:resource-types:create',
          tenantId,
          `create resource type ${change.name}`,
        );
        await registerResourceType(ctx, tx, { tenantId, ...desired! });
      } else if (change.action === 'update') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:resource-types:update',
          tenantId,
          `update resource type ${change.name}`,
        );
        await updateResourceType(
          ctx,
          tx,
          {
            tenantId,
            name: desired!.name,
            description: desired!.description,
            attributes: desired!.attributes ?? {},
            actions: desired!.actions ?? [],
            relations: desired!.relations ?? [],
          },
          true,
        );
      } else if (change.action === 'delete') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:resource-types:delete',
          tenantId,
          `delete resource type ${change.name}`,
        );
        await deleteResourceType(ctx, tx, record!);
      }
    }
    // Policies
    const policyIds = new Map(state.policies.map((policy) => [policy.name, policy.id]));
    for (const { change, desired, record } of planned.policies) {
      if (change.action === 'create') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:policies:create',
          tenantId,
          `create policy ${change.name}`,
        );
        const created = await createPolicy(ctx, tx, principal, tenant, { tenantId, ...desired! });
        policyIds.set(created.name, created.id);
      } else if (change.action === 'update') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:policies:update',
          record!.id,
          `update policy ${change.name}`,
        );
        await updatePolicy(ctx, tx, principal, {
          tenantId,
          policyId: record!.id,
          version: record!.version,
          description: desired!.description,
          document: desired!.document,
        });
      }
    }
    // Roles (creates and updates), then deletions after bindings are gone.
    const roleIds = new Map(state.roles.map((role) => [role.name, role.id]));
    for (const { change, desired, record } of planned.roles) {
      if (change.action === 'unchanged' || change.action === 'delete') continue;
      const policies = (desired!.policies ?? []).map((name) => {
        const policyId = policyIds.get(name);
        if (!policyId) throw new IamError('INVALID_INPUT', `Unknown policy ${name}`);
        return policyId;
      });
      const document = roleDocument(desired!);
      if (change.action === 'create') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:roles:create',
          tenantId,
          `create role ${change.name}`,
        );
        const created = await createRole(ctx, tx, principal, tenant, {
          tenantId,
          name: desired!.name,
          description: desired!.description,
          policyIds: policies,
          ...(document ? { document } : {}),
        });
        roleIds.set(created.name, created.id);
      } else {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:roles:update',
          record!.id,
          `update role ${change.name}`,
        );
        await updateRole(ctx, tx, principal, {
          tenantId,
          roleId: record!.id,
          description: desired!.description,
          policyIds: policies,
          document: document ?? null,
        });
      }
    }
    // Inheritance is applied once every role exists, so a document may introduce parent and child together.
    for (const { change, desired, record } of planned.roles) {
      if (change.action === 'delete') continue;
      const wanted = desired!.inherits ?? [];
      const current = (record?.inherits ?? []).flatMap((roleId) => {
        const name = state.roles.find((role) => role.id === roleId)?.name;
        return name === undefined ? [] : [name];
      });
      if (change.action === 'unchanged' || same(sorted(wanted), sorted(current))) continue;
      const roleId = roleIds.get(desired!.name);
      if (!roleId) continue;
      await allow(
        tx,
        principal,
        tenantId,
        'iam:roles:update',
        roleId,
        `set inheritance of role ${change.name}`,
      );
      await updateRole(ctx, tx, principal, {
        tenantId,
        roleId,
        inherits: wanted.map((name) => {
          const inheritedId = roleIds.get(name);
          if (!inheritedId) throw new IamError('INVALID_INPUT', `Unknown role ${name}`);
          return inheritedId;
        }),
      });
    }
    // Groups and their members
    const groupIds = new Map(state.groups.map((group) => [group.name, group.id]));
    /** Groups configuration sync manages; others (teams' backing groups) never appear in a document. */
    const managedGroupIds = new Set(state.groups.map((group) => group.id));
    for (const { change, desired, record } of planned.groups) {
      if (change.action === 'delete') continue;
      let groupId = record?.id;
      if (change.action === 'create') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:groups:create',
          tenantId,
          `create group ${change.name}`,
        );
        groupId = (await createGroup(ctx, tx, tenant, { tenantId, ...desired! })).id;
        groupIds.set(desired!.name, groupId);
      } else if (change.action === 'update' && change.fields?.includes('description')) {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:groups:update',
          groupId!,
          `update group ${change.name}`,
        );
        await tx.put<Group>('groups', {
          ...record!,
          ...(desired!.description === undefined
            ? {}
            : { description: text(desired!.description, 'description', 512) }),
        });
      }
      if (
        desired!.members !== undefined &&
        (change.action === 'create' || change.fields?.includes('members'))
      ) {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:groups:update',
          groupId!,
          `change members of ${change.name}`,
        );
        const wantedIds = new Set(
          desired!.members.map((email) => state.identitiesByEmail.get(email)!.id),
        );
        const currentIds = new Set(
          (state.members.get(groupId!) ?? []).map((identity) => identity.id),
        );
        for (const identityId of wantedIds)
          if (!currentIds.has(identityId))
            await addGroupMember(ctx, tx, principal, { tenantId, groupId: groupId!, identityId });
        for (const identityId of currentIds)
          if (!wantedIds.has(identityId))
            await removeGroupMember(ctx, tx, principal, {
              tenantId,
              groupId: groupId!,
              identityId,
            });
      }
    }
    // Group bindings
    for (const { change, desired, record } of planned.bindings) {
      if (change.action === 'unchanged') continue;
      if (change.action === 'delete') {
        for (const binding of record!) {
          await allow(
            tx,
            principal,
            tenantId,
            'iam:bindings:delete',
            binding.id,
            `delete binding ${change.name}`,
          );
          await deleteBinding(ctx, tx, principal, binding);
        }
        continue;
      }
      const roleId = roleIds.get(desired!.role);
      const groupId = groupIds.get(desired!.group);
      if (!roleId || !groupId)
        throw new IamError('INVALID_INPUT', `Unknown binding ${change.name}`);
      await allow(tx, principal, tenantId, 'iam:bindings:create', roleId, `bind ${change.name}`);
      // What configuration cannot express survives a replacement: an approver group sync does not manage (a team's
      // backing group, left out of exports), and the start and end dates of a temporary or future-dated grant.
      const previous = record ?? [];
      const keptApprover = previous.find(
        (binding) => binding.approverGroupId && !managedGroupIds.has(binding.approverGroupId),
      )?.approverGroupId;
      const now = ctx.now();
      const dates =
        previous.length && previous.every((binding) => binding.expiresAt !== undefined)
          ? { expiresAt: Math.max(...previous.map((binding) => binding.expiresAt!)) }
          : {};
      const pending = previous.filter(
        (binding) => binding.startsAt !== undefined && binding.startsAt > now,
      );
      const starts =
        previous.length && pending.length === previous.length
          ? { startsAt: Math.min(...pending.map((binding) => binding.startsAt!)) }
          : {};
      const eligibility = {
        ...(desired!.eligible
          ? {
              eligible: true,
              maxActivationMs: desired!.maxActivationMs,
              requireJustification: desired!.requireJustification,
              requireMfa: desired!.requireMfa,
              requireApproval: desired!.requireApproval,
              ...(desired!.approverGroup !== undefined
                ? { approverGroupId: groupIds.get(desired!.approverGroup) ?? null }
                : keptApprover
                  ? { approverGroupId: keptApprover }
                  : {}),
              managerApproval: desired!.managerApproval,
            }
          : { eligible: false }),
        ...(desired!.window !== undefined ? { window: desired!.window } : {}),
        ...(change.action === 'create' ? {} : { ...dates, ...starts }),
      };
      if (change.action === 'create')
        await createBinding(ctx, tx, principal, {
          tenantId,
          roleId,
          subjectType: 'group',
          subjectId: groupId,
          ...eligibility,
        });
      else {
        // Eligibility changes replace the binding so the authority and activations start clean.
        for (const binding of record!) await deleteBinding(ctx, tx, principal, binding);
        await createBinding(ctx, tx, principal, {
          tenantId,
          roleId,
          subjectType: 'group',
          subjectId: groupId,
          ...eligibility,
        });
      }
    }
    // Teams and departments (org-sync.ts) are created and updated before packages, whose rules may name them.
    await applyOrg(
      ctx,
      tx,
      principal,
      tenant,
      planned.org,
      {
        allow: (action, resourceId, what) =>
          allow(tx, principal, tenantId, action, resourceId, what),
        roleIds,
        groupIds,
        identitiesByEmail: state.identitiesByEmail,
      },
      'upsert',
    );
    // AI agents, models and budgets (ai-sync.ts), once groups exist; agents before the budgets that name them.
    await applyAi(
      ctx,
      tx,
      principal,
      tenant,
      planned.ai,
      {
        allow: (action, resourceId, what) =>
          allow(tx, principal, tenantId, action, resourceId, what),
        groupIds,
        identitiesByEmail: state.identitiesByEmail,
      },
      'upsert',
    );
    const orgIds = await orgRuleIds(tx, tenantId);
    // Access packages: created and updated once their roles and groups exist, deleted before those go.
    for (const { change, desired, record } of planned.packages) {
      if (change.action === 'unchanged') continue;
      if (change.action === 'delete') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:packages:delete',
          record!.id,
          `delete package ${change.name}`,
        );
        await deletePackage(ctx, tx, record!);
        continue;
      }
      const roles = (desired!.roles ?? []).map((name) => {
        const roleId = roleIds.get(name);
        if (!roleId) throw new IamError('INVALID_INPUT', `Unknown role ${name}`);
        return roleId;
      });
      const groups = (desired!.groups ?? []).map((name) => {
        const groupId = groupIds.get(name);
        if (!groupId) throw new IamError('INVALID_INPUT', `Unknown group ${name}`);
        return groupId;
      });
      // Rules name groups; the tenant stores their IDs (including groups this apply just created).
      const ruleIds = (rule: TenantConfigAutoAssign) =>
        orgIds(mapRuleGroups(rule, (name) => groupIds.get(name) ?? name));
      if (change.action === 'create') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:packages:create',
          tenantId,
          `create package ${change.name}`,
        );
        await createPackage(
          ctx,
          tx,
          {
            tenantId,
            name: desired!.name,
            description: desired!.description,
            roleIds: roles,
            groupIds: groups,
            maxDurationMs: desired!.maxDurationMs,
            requireJustification: desired!.requireJustification,
            requestable: desired!.requestable,
            ...(desired!.approverGroup !== undefined
              ? { approverGroupId: groupIds.get(desired!.approverGroup) ?? null }
              : {}),
            managerApproval: desired!.managerApproval,
            ...(desired!.autoAssign ? { autoAssign: ruleIds(desired!.autoAssign) } : {}),
          },
          principal,
        );
      } else {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:packages:update',
          record!.id,
          `update package ${change.name}`,
        );
        await updatePackage(
          ctx,
          tx,
          record!,
          {
            ...(record!.name !== desired!.name ? { name: desired!.name } : {}),
            description: desired!.description ?? null,
            roleIds: roles,
            groupIds: groups,
            maxDurationMs: desired!.maxDurationMs ?? null,
            requireJustification: desired!.requireJustification === true,
            requestable: desired!.requestable === true,
            // An approver group sync does not manage (a team's backing group) is not in the document; keep it.
            approverGroupId:
              desired!.approverGroup !== undefined
                ? (groupIds.get(desired!.approverGroup) ?? null)
                : record!.approverGroupId && !managedGroupIds.has(record!.approverGroupId)
                  ? record!.approverGroupId
                  : null,
            managerApproval: desired!.managerApproval === true,
            // Passed only when the plan lists the rule, so an unrelated edit never moves its ownership.
            ...(change.fields?.includes('autoAssign')
              ? {
                  autoAssign: desired!.autoAssign === null ? null : ruleIds(desired!.autoAssign!),
                }
              : {}),
          },
          principal,
        );
      }
    }
    // Terms of use: a content change publishes a new version (people accept what they were shown).
    for (const { change, desired, record } of planned.agreements) {
      if (change.action === 'unchanged') continue;
      await allow(
        tx,
        principal,
        tenantId,
        'iam:agreements:manage',
        record?.id ?? tenantId,
        `${change.action} agreement ${change.name}`,
      );
      if (change.action === 'delete') await deleteAgreement(tx, record!);
      else
        await saveAgreement(
          ctx,
          tx,
          tenantId,
          {
            name: desired!.name,
            content: desired!.content,
            url: desired!.url ?? '',
            required: desired!.required ?? true,
            reacceptAfterDays: desired!.reacceptAfterDays ?? null,
          },
          record,
          change.action === 'update' && change.fields!.includes('content'),
        );
    }
    // Access invariants, once their groups exist and before any group is deleted.
    for (const { change, desired, record } of planned.invariants) {
      if (change.action === 'unchanged') continue;
      await allow(
        tx,
        principal,
        tenantId,
        'iam:invariants:manage',
        record?.id ?? tenantId,
        `${change.action} invariant ${change.name}`,
      );
      if (change.action === 'delete') {
        await tx.delete('accessInvariants', record!.id);
        continue;
      }
      const subject = desired!.subject;
      const stored: InvariantSubject =
        'group' in subject
          ? { groupId: groupIds.get(subject.group)! }
          : 'identity' in subject
            ? { identityId: state.identitiesByEmail.get(subject.identity)!.id }
            : subject;
      await saveInvariant(
        ctx,
        tx,
        tenantId,
        {
          name: desired!.name,
          description: desired!.description ?? '',
          subject: stored,
          action: desired!.action,
          resource: desired!.resource,
          expect: desired!.expect,
          mode: desired!.mode ?? 'monitor',
          assumeMfa: desired!.assumeMfa ?? true,
        },
        principal.identity.id,
        record,
      );
    }
    // Team and department deletions (org-sync.ts), once packages stopped naming them and before any role is deleted.
    await applyOrg(
      ctx,
      tx,
      principal,
      tenant,
      planned.org,
      {
        allow: (action, resourceId, what) =>
          allow(tx, principal, tenantId, action, resourceId, what),
        roleIds,
        groupIds,
        identitiesByEmail: state.identitiesByEmail,
      },
      'delete',
    );
    // AI budget, model and agent deletions (ai-sync.ts), before the groups budgets name are deleted.
    await applyAi(
      ctx,
      tx,
      principal,
      tenant,
      planned.ai,
      {
        allow: (action, resourceId, what) =>
          allow(tx, principal, tenantId, action, resourceId, what),
        groupIds,
        identitiesByEmail: state.identitiesByEmail,
      },
      'delete',
    );
    // Deletions, dependents first.
    for (const { change, record } of planned.groups)
      if (change.action === 'delete') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:groups:delete',
          record!.id,
          `delete group ${change.name}`,
        );
        await deleteGroup(ctx, tx, principal, record!);
      }
    for (const { change, record } of planned.roles)
      if (change.action === 'delete') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:roles:delete',
          record!.id,
          `delete role ${change.name}`,
        );
        await deleteRole(ctx, tx, principal, record!);
      }
    for (const { change, record } of planned.policies)
      if (change.action === 'delete') {
        await allow(
          tx,
          principal,
          tenantId,
          'iam:policies:delete',
          record!.id,
          `delete policy ${change.name}`,
        );
        await deletePolicy(ctx, tx, principal, record!);
      }
  }
  return {
    /**
     * The tenant's roles, policies, groups (with member emails), tenant-defined resource types, group bindings,
     * and access packages as a configuration document that `plan`/`apply` accept. Requires iam:config:read.
     */
    export: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:config:read', input.tenantId, async ({ tx }) =>
        exportState(await readState(ctx, tx, input.tenantId)),
      ),
    /**
     * Dry run: the changes `apply` would make for a desired configuration, by name. Kinds absent from the
     * configuration are left alone; with `prune`, items of a listed kind that the configuration omits are deleted.
     * Requires iam:config:read; nothing is written.
     */
    plan: (
      credential: CredentialInput,
      input: { tenantId: string; config: unknown; prune?: boolean },
    ) =>
      operation(credential, input.tenantId, 'iam:config:read', input.tenantId, async ({ tx }) => {
        const desired = validateTenantConfig(input.config);
        const state = await readState(ctx, tx, input.tenantId);
        return computePlan(ctx, input.tenantId, desired, state, input.prune === true).plan;
      }),
    /**
     * Applies a desired configuration in one transaction: every change is authorized like the direct API call
     * (create/update/delete on the item) under the caller's grant authority, and one failure rolls everything
     * back. Requires iam:config:apply; audited as `config:apply` with the change summary.
     */
    apply: (
      credential: CredentialInput,
      input: { tenantId: string; config: unknown; prune?: boolean },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:config:apply',
        input.tenantId,
        async ({ tx, principal, tenant }) => {
          const desired = validateTenantConfig(input.config);
          const state = await readState(ctx, tx, input.tenantId);
          const planned = computePlan(ctx, input.tenantId, desired, state, input.prune === true);
          await apply(tx, principal, tenant, planned, state);
          await ctx.events.audit(
            tx,
            principal,
            'config:apply',
            input.tenantId,
            input.tenantId,
            'allow',
            false,
            {
              prune: planned.plan.prune,
              ...planned.plan.summary,
              changed: planned.plan.changes
                .filter((change) => change.action !== 'unchanged')
                .map((change) => `${change.action} ${change.kind} ${change.name}`),
            },
          );
          return { ...planned.plan, applied: true as const };
        },
      ),
  };
}
