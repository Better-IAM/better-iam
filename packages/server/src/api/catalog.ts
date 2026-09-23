import {
  IamError,
  type AttributeType,
  type CredentialInput,
  type IamStore,
} from '@better-iam/core';
import {
  attributeSchema,
  attributeValues,
  relationNames,
  reservedResourceTypes,
  resourceTypeName,
  type CatalogResourceType,
} from '../catalog.js';
import type { ServerContext } from '../context.js';
import type {
  ActionDefinition,
  Relationship,
  ResourceRecord,
  ResourceTypeRecord,
} from '../models.js';
import { id } from '../utils.js';
import { strings, text } from '../validation.js';

export interface ActionSummary {
  name: string;
  source: 'platform' | 'tenant';
  resourceType?: string;
  description?: string;
}

export function createActionsApi(ctx: ServerContext) {
  const { catalog } = ctx;
  const { operation } = ctx.operations;
  return {
    /** Tenant-defined actions are namespaced under a tenant-defined resource type: `{type}:{verb}`. */
    register: (
      credential: CredentialInput,
      input: { tenantId: string; name: string; description?: string },
    ) =>
      operation(credential, input.tenantId, 'iam:actions:create', input.tenantId, ({ tx }) =>
        catalog.registerTenantAction(tx, input.tenantId, input.name, input.description),
      ),
    unregister: (credential: CredentialInput, input: { tenantId: string; name: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:actions:delete',
        input.tenantId,
        async ({ tx }) => {
          const definition = (
            await tx.find<ActionDefinition>('actions', {
              tenantId: input.tenantId,
              uniqueKey: text(input.name, 'action', 128),
            })
          )[0];
          if (!definition) throw new IamError('NOT_FOUND', 'Action not found', 404);
          await catalog.assertActionUnused(tx, input.tenantId, definition.name);
          await tx.delete('actions', definition.id);
          return { deleted: true };
        },
      ),
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:actions:read', input.tenantId, async ({ tx }) => {
        const result: ActionSummary[] = [...catalog.actions].map((name) => ({
          name,
          source: 'platform',
          resourceType: catalog.actionTypes.get(name),
        }));
        for (const definition of await tx.find<ActionDefinition>('actions', {
          tenantId: input.tenantId,
        }))
          result.push({
            name: definition.name,
            source: 'tenant',
            resourceType: definition.resourceType,
            description: definition.description,
          });
        return result;
      }),
  };
}

export interface ResourceTypeInput {
  tenantId: string;
  name: string;
  description?: string;
  /** Verbs; the registered actions are `{name}:{verb}`. */
  actions?: string[];
  attributes?: Record<string, AttributeType>;
  parent?: string;
  relations?: string[];
}
export interface ResourceTypeUpdate {
  tenantId: string;
  name: string;
  description?: string;
  attributes?: Record<string, AttributeType>;
  actions?: string[];
  relations?: string[];
}

/** Registers a tenant-defined resource type; shared by `resourceTypes.register` and configuration sync. */
export async function registerResourceType(
  ctx: ServerContext,
  tx: IamStore,
  input: ResourceTypeInput,
): Promise<CatalogResourceType> {
  const { catalog, config } = ctx;
  if (!config.tenantDefined)
    throw new IamError('CATALOG_LOCKED', 'Tenant-defined resource types are disabled', 403);
  const name = text(input.name, 'name', 64);
  if (
    !resourceTypeName.test(name) ||
    reservedResourceTypes.has(name) ||
    catalog.resourceTypes.has(name) ||
    catalog.namespaces.has(name)
  )
    throw new IamError(
      'INVALID_RESOURCE_TYPE',
      'Resource type name is reserved or already defined by the platform',
    );
  if (await catalog.tenantResourceType(tx, input.tenantId, name))
    throw new IamError('CONFLICT', 'Resource type already exists', 409);
  const record: ResourceTypeRecord = {
    id: id(),
    tenantId: input.tenantId,
    uniqueKey: name,
    name,
    attributes: attributeSchema(input.attributes),
    createdAt: Date.now(),
  };
  if (input.description !== undefined)
    record.description = text(input.description, 'description', 512);
  if (input.relations !== undefined) record.relations = relationNames(input.relations);
  if (input.parent !== undefined) {
    const parent = await catalog.resourceTypeDefinition(
      tx,
      input.tenantId,
      text(input.parent, 'parent', 64),
    );
    if (!parent || parent.name === name || !parent.managed)
      throw new IamError(
        'INVALID_RESOURCE_TYPE',
        'Parent must be an existing managed resource type',
      );
    record.parent = parent.name;
  }
  await tx.insert('resourceTypes', record);
  const registered: string[] = [];
  for (const verb of strings(input.actions ?? [], 'actions'))
    registered.push(
      (await catalog.registerTenantAction(tx, input.tenantId, `${name}:${verb}`)).name,
    );
  return {
    name,
    source: 'tenant',
    description: record.description,
    actions: registered,
    attributes: record.attributes,
    parent: record.parent,
    managed: true,
    relations: record.relations ?? [],
  };
}

/**
 * Updates a tenant-defined resource type. `actions` adds verbs; with `replaceActions` (configuration sync) verbs
 * no longer listed are removed too, provided no policy or role still names them.
 */
export async function updateResourceType(
  ctx: ServerContext,
  tx: IamStore,
  input: ResourceTypeUpdate,
  replaceActions = false,
): Promise<CatalogResourceType> {
  const { catalog } = ctx;
  const record = await catalog.tenantResourceType(tx, input.tenantId, text(input.name, 'name', 64));
  if (!record) throw new IamError('NOT_FOUND', 'Resource type not found', 404);
  const next: ResourceTypeRecord = { ...record };
  if (input.description !== undefined)
    next.description = text(input.description, 'description', 512);
  if (input.relations !== undefined) {
    next.relations = relationNames(input.relations);
    // A relation still held by someone cannot be removed from the type.
    const held = await tx.find<Relationship>('relationships', {
      tenantId: input.tenantId,
      type: record.name,
    });
    if (held.some((item) => !next.relations!.includes(item.relation)))
      throw new IamError('RESOURCE_IN_USE', 'Remove relationships before dropping a relation', 409);
  }
  if (input.attributes !== undefined) {
    next.attributes = attributeSchema(input.attributes);
    // Registered resources must keep satisfying the schema, otherwise conditions would silently stop matching.
    for (const resource of await tx.find<ResourceRecord>('resources', {
      tenantId: input.tenantId,
      type: record.name,
    }))
      attributeValues(next.attributes, resource.attributes);
  }
  await tx.put('resourceTypes', next);
  const verbs = strings(input.actions ?? [], 'actions');
  for (const verb of verbs) {
    const name = `${record.name}:${verb}`;
    if (!(await catalog.knownAction(tx, input.tenantId, name)))
      await catalog.registerTenantAction(tx, input.tenantId, name);
  }
  if (replaceActions && input.actions !== undefined)
    for (const action of await tx.find<ActionDefinition>('actions', {
      tenantId: input.tenantId,
      resourceType: record.name,
    }))
      if (!verbs.includes(action.name.slice(record.name.length + 1))) {
        await catalog.assertActionUnused(tx, input.tenantId, action.name);
        await tx.delete('actions', action.id);
      }
  return (await catalog.resourceTypeDefinition(tx, input.tenantId, record.name))!;
}

/** Deletes a tenant-defined resource type once nothing registered, related, nested, or granted depends on it. */
export async function deleteResourceType(
  ctx: ServerContext,
  tx: IamStore,
  record: ResourceTypeRecord,
): Promise<void> {
  const { catalog } = ctx;
  if (
    (await tx.find<ResourceRecord>('resources', { tenantId: record.tenantId, type: record.name }))
      .length
  )
    throw new IamError('RESOURCE_IN_USE', 'Delete registered resources first', 409);
  if (
    (
      await tx.find<Relationship>('relationships', {
        tenantId: record.tenantId,
        type: record.name,
      })
    ).length
  )
    throw new IamError('RESOURCE_IN_USE', 'Delete relationships first', 409);
  if (
    (
      await tx.find<ResourceTypeRecord>('resourceTypes', {
        tenantId: record.tenantId,
        parent: record.name,
      })
    ).length
  )
    throw new IamError(
      'RESOURCE_IN_USE',
      'Other resource types use this type as their parent',
      409,
    );
  for (const action of await tx.find<ActionDefinition>('actions', {
    tenantId: record.tenantId,
    resourceType: record.name,
  })) {
    await catalog.assertActionUnused(tx, record.tenantId, action.name);
    await tx.delete('actions', action.id);
  }
  await tx.delete('resourceTypes', record.id);
}

export function createResourceTypesApi(ctx: ServerContext) {
  const { catalog } = ctx;
  const { operation } = ctx.operations;
  return {
    /** Registers a tenant-defined resource type. Its resources are managed by IAM and its actions are `{name}:{verb}`. */
    register: (credential: CredentialInput, input: ResourceTypeInput) =>
      operation(credential, input.tenantId, 'iam:resource-types:create', input.tenantId, ({ tx }) =>
        registerResourceType(ctx, tx, input),
      ),
    /** Changes description, attributes, or relations, and adds action verbs; existing verbs are kept. */
    update: (credential: CredentialInput, input: ResourceTypeUpdate) =>
      operation(credential, input.tenantId, 'iam:resource-types:update', input.tenantId, ({ tx }) =>
        updateResourceType(ctx, tx, input),
      ),
    delete: (credential: CredentialInput, input: { tenantId: string; name: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:resource-types:delete',
        input.tenantId,
        async ({ tx }) => {
          const record = await catalog.tenantResourceType(
            tx,
            input.tenantId,
            text(input.name, 'name', 64),
          );
          if (!record) throw new IamError('NOT_FOUND', 'Resource type not found', 404);
          await deleteResourceType(ctx, tx, record);
          return { deleted: true };
        },
      ),
    get: (credential: CredentialInput, input: { tenantId: string; name: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:resource-types:read',
        input.tenantId,
        async ({ tx }) => {
          const definition = await catalog.resourceTypeDefinition(
            tx,
            input.tenantId,
            text(input.name, 'name', 64),
          );
          if (!definition) throw new IamError('NOT_FOUND', 'Resource type not found', 404);
          return definition;
        },
      ),
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:resource-types:read',
        input.tenantId,
        async ({ tx }) => {
          const result: CatalogResourceType[] = [...catalog.resourceTypes.values()];
          for (const record of await tx.find<ResourceTypeRecord>('resourceTypes', {
            tenantId: input.tenantId,
          }))
            result.push((await catalog.resourceTypeDefinition(tx, input.tenantId, record.name))!);
          return result;
        },
      ),
  };
}
