import {
  IamError,
  validatePolicy,
  type AttributeType,
  type IamPlugin,
  type IamStore,
  type Json,
  type PolicyDocument,
  type ResourceTypeDefinition,
} from '@better-iam/core';
import { reservedSessionPrincipalNames } from './context-keys.js';
import type { ActionDefinition, ResourceRecord, ResourceTypeRecord } from './models.js';
import type { BetterIamOptions, ResolvedResource, ServerConfig } from './options.js';
import { id } from './utils.js';
import { object, strings, text } from './validation.js';

/** Every operation the platform itself authorizes. Products, plugins, and tenants add their own names. */
export const builtInActions = [
  'tenants:create',
  'tenants:read',
  'tenants:update',
  'tenants:delete',
  'identities:create',
  'identities:read',
  'identities:update',
  'identities:delete',
  'identities:impersonate',
  'groups:create',
  'groups:read',
  'groups:update',
  'groups:delete',
  'roles:create',
  'roles:read',
  'roles:update',
  'roles:delete',
  'policies:create',
  'policies:read',
  'policies:update',
  'policies:delete',
  'bindings:create',
  'bindings:read',
  'bindings:delete',
  'bindings:activate',
  'bindings:approve',
  'packages:create',
  'packages:read',
  'packages:update',
  'packages:delete',
  'packages:assign',
  'packages:request',
  'packages:approve',
  'authorities:create',
  'authorities:revoke',
  'boundaries:update',
  'actions:create',
  'actions:read',
  'actions:delete',
  'resource-types:create',
  'resource-types:read',
  'resource-types:update',
  'resource-types:delete',
  'resources:create',
  'resources:read',
  'resources:update',
  'resources:delete',
  'relationships:create',
  'relationships:read',
  'relationships:delete',
  'credentials:create',
  'credentials:read',
  'credentials:revoke',
  'trust:create',
  'trust:read',
  'trust:update',
  'trust:revoke',
  'roles:assume',
  'roles:revoke-sessions',
  'session-tokens:create',
  'oidc-providers:create',
  'oidc-providers:read',
  'oidc-providers:update',
  'oidc-providers:delete',
  'audit:read',
  'assertions:create',
  'policies:simulate',
  'config:read',
  'config:apply',
  'root:grant',
  'access-requests:create',
  'access-requests:read',
  'access-requests:review',
  'webhooks:create',
  'webhooks:read',
  'webhooks:update',
  'webhooks:delete',
  'oauth:clients:create',
  'oauth:clients:read',
  'oauth:clients:delete',
  'oauth:clients:update',
  'oauth:grants:read',
  'oauth:grants:revoke',
  'scim:connections:create',
  'scim:connections:read',
  'scim:connections:delete',
  'scim:credentials:create',
  'scim:credentials:revoke',
  'scim:mappings:update',
  'scim:targets:create',
  'scim:targets:read',
  'scim:targets:update',
  'scim:targets:delete',
  'scim:targets:sync',
  'saml:connections:create',
  'saml:connections:read',
  'saml:connections:update',
  'saml:connections:delete',
  'ssf:streams:create',
  'ssf:streams:read',
  'ssf:streams:update',
  'ssf:streams:delete',
  'domains:create',
  'domains:read',
  'domains:update',
  'domains:delete',
  'hostnames:create',
  'hostnames:read',
  'hostnames:update',
  'hostnames:delete',
  'analysis:read',
  'analysis:update',
  'certifications:read',
  'certifications:review',
  'certifications:manage',
  'sod:read',
  'sod:manage',
  'security:read',
  'security:manage',
  'invariants:read',
  'invariants:manage',
  'agreements:read',
  'agreements:manage',
  'features:read',
  'features:manage',
  'features:override',
  'onboarding:read',
  'onboarding:manage',
  // AI agents as accounts and the delegations people give them (agents.ts, delegations.ts).
  'agents:create',
  'agents:read',
  'agents:update',
  'agents:delete',
  'delegations:read',
  'delegations:revoke',
  // Inference access control (inference.ts): providers, models and budgets; usage reports; gateway metering.
  'inference:manage',
  'inference:read',
  'inference:record',
  // Teams inside the organization (teams.ts) and its department structure (departments.ts).
  'teams:create',
  'teams:read',
  'teams:update',
  'teams:delete',
  'departments:read',
  'departments:manage',
  // Billing and spend tracking (billing.ts): meters, prices, budgets, profiles; spend reports; usage metering.
  'billing:read',
  'billing:manage',
  'billing:record',
].map((action) => `iam:${action}`);

/** Resource types the platform resolves itself; products and tenants cannot redefine them. */
export const internalResourceTypes = new Set([
  'iam',
  'oauth-client',
  'scim',
  'saml',
  'ssf',
  'role',
]);
export const reservedResourceTypes = new Set([
  ...internalResourceTypes,
  'tenant',
  'identity',
  'session',
]);
export const resourceTypeName = /^[a-z][a-z0-9-]{0,63}$/;
const attributeTypes = new Set<AttributeType>(['string', 'number', 'boolean']);

export interface CatalogResourceType {
  name: string;
  source: 'platform' | 'tenant';
  description?: string;
  actions: string[];
  attributes: Record<string, AttributeType>;
  parent?: string;
  managed: boolean;
  /** Relation names identities and groups may hold on resources of this type. */
  relations: string[];
}

/** Relation names are short identifiers; at most 32 distinct relations per type. */
export function relationNames(value: unknown): string[] {
  if (value === undefined) return [];
  const names = strings(value, 'relations');
  const unique = [...new Set(names)];
  if (unique.length > 32 || unique.some((name) => !/^[a-z][a-z0-9_-]{0,63}$/.test(name)))
    throw new IamError('INVALID_INPUT', 'relations must contain at most 32 lowercase identifiers');
  return unique;
}

export function attributeSchema(value: unknown): Record<string, AttributeType> {
  if (value === undefined) return {};
  const schema = object(value);
  const result: Record<string, AttributeType> = {};
  if (Object.keys(schema).length > 64)
    throw new IamError('INVALID_INPUT', 'At most 64 attributes may be declared');
  for (const [key, type] of Object.entries(schema)) {
    if (!/^[a-zA-Z][a-zA-Z0-9_]{0,63}$/.test(key) || key === 'tenantId')
      throw new IamError('INVALID_INPUT', `Invalid attribute name ${key}`);
    if (typeof type !== 'string' || !attributeTypes.has(type as AttributeType))
      throw new IamError('INVALID_INPUT', `Attribute ${key} must be string, number, or boolean`);
    result[key] = type as AttributeType;
  }
  return result;
}

export function attributeValues(
  schema: Record<string, AttributeType>,
  value: unknown,
): Record<string, Json> {
  if (value === undefined) return {};
  const input = object(value);
  const result: Record<string, Json> = {};
  for (const [key, item] of Object.entries(input)) {
    const type = schema[key];
    if (!type)
      throw new IamError(
        'INVALID_INPUT',
        `Attribute ${key} is not declared for this resource type`,
      );
    const invalid =
      typeof item !== type ||
      (type === 'number' && !Number.isFinite(item)) ||
      (type === 'string' &&
        ((item as string).length > 2048 || /[\u0000-\u001f]/.test(item as string)));
    if (invalid) throw new IamError('INVALID_INPUT', `Attribute ${key} must be a ${type}`);
    result[key] = item as Json;
  }
  return result;
}

/** A registered managed resource, keyed by `{type}/{resourceId}` within its tenant. */
export async function managedResource(
  tx: IamStore,
  tenantId: string,
  type: string,
  resourceId: string,
): Promise<ResourceRecord | undefined> {
  return (
    await tx.find<ResourceRecord>('resources', { tenantId, uniqueKey: `${type}/${resourceId}` })
  )[0];
}

/** Presents a managed registration to the policy engine: attributes plus owner and parent links. */
export function resolvedManaged(record: ResourceRecord): ResolvedResource {
  const attributes: Record<string, unknown> = { ...record.attributes };
  if (record.ownerId !== undefined) attributes.ownerId = record.ownerId;
  if (record.parentId !== undefined) {
    attributes.parentId = record.parentId;
    attributes.parentType = record.parentType;
  }
  return { tenantId: record.tenantId, type: record.type, id: record.resourceId, attributes };
}

/**
 * The permission catalog: platform actions and resource types declared in configuration plus, per tenant,
 * the types and `{type}:{verb}` actions a tenant registered itself when `permissions.mode` is `tenant-defined`.
 */
/**
 * Principal context keys the server derives itself; identity attributes cannot shadow them. The session-derived
 * names (`reservedSessionPrincipalNames`, including the `sessionTags` prefix family) are reserved as well.
 */
export const reservedPrincipalKeys = new Set([
  'id',
  'tenantId',
  'mfa',
  'kind',
  'owner',
  'rootAdmin',
  'groups',
  'roles',
  'sessionKind',
  'authMethod',
  'impersonated',
  'impersonatorId',
  'agreements',
  'pendingAgreements',
  'onboarding',
  'pendingOnboarding',
  'teams',
  'departments',
  'departmentId',
  'spendExceeded',
  'budgetsExceeded',
  ...reservedSessionPrincipalNames,
]);

export class Catalog {
  readonly actions = new Set(builtInActions);
  readonly actionTypes = new Map<string, string>();
  readonly resourceTypes = new Map<string, CatalogResourceType>();
  readonly namespaces: Set<string>;
  /** Typed attributes administrators may set on identities; exposed to policies as principal.{name}. */
  readonly identityAttributes: Record<string, AttributeType>;

  constructor(
    options: BetterIamOptions,
    plugins: IamPlugin[],
    private readonly config: ServerConfig,
  ) {
    for (const action of [
      ...(options.permissions?.actions ?? []),
      ...plugins.flatMap((plugin) => plugin.actions ?? []),
    ])
      this.registerAction(action);
    try {
      this.identityAttributes = attributeSchema(options.permissions?.identityAttributes);
    } catch (error) {
      throw new IamError('INVALID_CONFIG', `identityAttributes: ${(error as Error).message}`);
    }
    for (const key of Object.keys(this.identityAttributes))
      if (reservedPrincipalKeys.has(key))
        throw new IamError('INVALID_CONFIG', `identityAttributes cannot redefine principal.${key}`);
    const declaredTypes = [
      ...Object.entries(options.permissions?.resourceTypes ?? {}),
      ...plugins.flatMap((plugin) => Object.entries(plugin.resourceTypes ?? {})),
    ];
    for (const [name, definition] of declaredTypes) {
      if (!resourceTypeName.test(name) || reservedResourceTypes.has(name))
        throw new IamError('INVALID_CONFIG', `Invalid or reserved resource type name ${name}`);
      if (this.resourceTypes.has(name))
        throw new IamError('INVALID_CONFIG', `Resource type ${name} is declared more than once`);
      const declared = object(definition) as ResourceTypeDefinition;
      let attributes: Record<string, AttributeType>;
      let relations: string[];
      try {
        attributes = attributeSchema(declared.attributes);
        relations = relationNames(declared.relations);
      } catch (error) {
        throw new IamError('INVALID_CONFIG', `Resource type ${name}: ${(error as Error).message}`);
      }
      const typeActions = strings(declared.actions ?? [], 'actions');
      for (const action of typeActions) this.registerAction(action, name);
      if (declared.description !== undefined) text(declared.description, 'description', 512);
      this.resourceTypes.set(name, {
        name,
        source: 'platform',
        description: declared.description,
        actions: typeActions,
        attributes,
        parent: declared.parent,
        managed: declared.managed ?? false,
        relations,
      });
    }
    for (const definition of this.resourceTypes.values()) {
      const seen = new Set<string>();
      let current = definition.parent;
      while (current !== undefined) {
        if (current === definition.name || seen.has(current) || !this.resourceTypes.has(current))
          throw new IamError(
            'INVALID_CONFIG',
            `Resource type ${definition.name} has an invalid parent chain`,
          );
        if (definition.managed && !this.resourceTypes.get(current)!.managed)
          throw new IamError(
            'INVALID_CONFIG',
            `Managed resource type ${definition.name} requires a managed parent`,
          );
        seen.add(current);
        current = this.resourceTypes.get(current)!.parent;
      }
    }
    this.namespaces = new Set([...this.actions].map((action) => action.split(':')[0]!));
  }

  private registerAction(action: string, resourceType?: string): void {
    text(action, 'action');
    if (action.startsWith('iam:') || action.startsWith('tenant/') || /[*?\s]/.test(action))
      throw new IamError('INVALID_CONFIG', 'Reserved or invalid action');
    this.actions.add(action);
    if (resourceType && !this.actionTypes.has(action)) this.actionTypes.set(action, resourceType);
  }

  async tenantResourceType(
    tx: IamStore,
    tenantId: string,
    name: string,
  ): Promise<ResourceTypeRecord | undefined> {
    return (await tx.find<ResourceTypeRecord>('resourceTypes', { tenantId, uniqueKey: name }))[0];
  }

  /** A platform or tenant-defined resource type, or undefined when the name is unknown. */
  async resourceTypeDefinition(
    tx: IamStore,
    tenantId: string,
    name: string,
  ): Promise<CatalogResourceType | undefined> {
    const platform = this.resourceTypes.get(name);
    if (platform) return platform;
    const record = await this.tenantResourceType(tx, tenantId, name);
    if (!record) return undefined;
    const typeActions = (
      await tx.find<ActionDefinition>('actions', { tenantId, resourceType: name })
    ).map((action) => action.name);
    return {
      name,
      source: 'tenant',
      description: record.description,
      actions: typeActions,
      attributes: record.attributes,
      parent: record.parent,
      managed: true,
      relations: record.relations ?? [],
    };
  }

  /** A managed type (platform-declared with `managed: true`, or any tenant-defined type). */
  async managedDefinition(
    tx: IamStore,
    tenantId: string,
    type: string,
  ): Promise<CatalogResourceType> {
    const definition = await this.resourceTypeDefinition(
      tx,
      tenantId,
      text(type, 'resource type', 64),
    );
    if (!definition) throw new IamError('INVALID_RESOURCE_TYPE', 'Unknown resource type');
    if (!definition.managed)
      throw new IamError(
        'INVALID_RESOURCE_TYPE',
        'This resource type is resolved by the application, not registered with IAM',
      );
    return definition;
  }

  async knownAction(tx: IamStore, tenantId: string, action: string): Promise<boolean> {
    return (
      this.actions.has(action) ||
      (await tx.find<ActionDefinition>('actions', { tenantId, uniqueKey: action })).length > 0
    );
  }

  /** Tenant-defined actions are namespaced under a tenant-defined resource type: `{type}:{verb}`. */
  async registerTenantAction(
    tx: IamStore,
    tenantId: string,
    rawName: string,
    description?: string,
  ): Promise<ActionDefinition> {
    if (!this.config.tenantDefined)
      throw new IamError('CATALOG_LOCKED', 'Tenant-defined actions are disabled', 403);
    const name = text(rawName, 'action', 128);
    const match = /^([a-z][a-z0-9-]{0,63}):([a-zA-Z][a-zA-Z0-9_-]{0,63})$/.exec(name);
    if (!match || this.actions.has(name) || this.namespaces.has(match[1]!))
      throw new IamError(
        'INVALID_ACTION',
        'Tenant actions must be {resourceType}:{verb} under a tenant-defined resource type',
      );
    if (!(await this.tenantResourceType(tx, tenantId, match[1]!)))
      throw new IamError('INVALID_ACTION', `Register resource type ${match[1]} before its actions`);
    if (await this.knownAction(tx, tenantId, name))
      throw new IamError('CONFLICT', 'Action already exists', 409);
    const definition: ActionDefinition = {
      id: id(),
      tenantId,
      uniqueKey: name,
      name,
      resourceType: match[1]!,
    };
    if (description !== undefined) definition.description = text(description, 'description', 512);
    return tx.insert('actions', definition);
  }

  /** Deleting an action is refused while any policy or inline role document still names it. */
  async assertActionUnused(tx: IamStore, tenantId: string, name: string): Promise<void> {
    const referenced = (documents: PolicyDocument[]) =>
      documents.some((document) =>
        document.statements.some((statement) => statement.actions.includes(name)),
      );
    const policies = (
      await tx.find<{ document: PolicyDocument; id: string; tenantId: string }>('policies', {
        tenantId,
      })
    ).map((policy) => policy.document);
    const inline = (
      await tx.find<{ document?: PolicyDocument; id: string; tenantId: string }>('roles', {
        tenantId,
      })
    ).flatMap((role) => (role.document ? [role.document] : []));
    if (referenced(policies) || referenced(inline))
      throw new IamError('RESOURCE_IN_USE', 'Remove the action from policies and roles first', 409);
  }

  /** Policies may only name actions and resource types that exist for the tenant; wildcard patterns are not resolved. */
  async validate(tx: IamStore, tenantId: string, document: PolicyDocument): Promise<void> {
    validatePolicy(document);
    for (const statement of document.statements) {
      for (const action of statement.actions) {
        if (!/[*?]/.test(action) && !(await this.knownAction(tx, tenantId, action)))
          throw new IamError('INVALID_ACTION', `Unknown action ${action}`);
      }
      if (!this.config.strictResourceTypes) continue;
      for (const pattern of statement.resources) {
        const type = pattern.split('/')[0]!;
        if (
          !/[*?]/.test(type) &&
          !internalResourceTypes.has(type) &&
          !(await this.resourceTypeDefinition(tx, tenantId, type))
        )
          throw new IamError('INVALID_RESOURCE_TYPE', `Unknown resource type ${type}`);
      }
    }
  }
}
