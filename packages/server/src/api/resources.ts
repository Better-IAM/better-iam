import {
  IamError,
  type CredentialInput,
  type Decision,
  type IamStore,
  type Json,
} from '@better-iam/core';
import {
  attributeValues,
  managedResource,
  resolvedManaged,
  type CatalogResourceType,
} from '../catalog.js';
import type { ServerContext } from '../context.js';
import { impersonatingActor } from '../decisions.js';
import type { ResourceRecord } from '../models.js';
import { id } from '../utils.js';
import { integer, object, text } from '../validation.js';

export interface ResourceInput {
  type: string;
  id: string;
  attributes?: Record<string, Json>;
  parentId?: string;
  ownerId?: string;
}
const byResourceKey = (a: ResourceRecord, b: ResourceRecord) =>
  a.uniqueKey! < b.uniqueKey! ? -1 : a.uniqueKey! > b.uniqueKey! ? 1 : 0;
const resourceKey = (input: { type: string; id: string }) =>
  `${text(input.type, 'resource type', 64)}/${text(input.id, 'resource id', 128)}`;
const countResources = async (tx: IamStore, tenantId: string) =>
  (await tx.find('resources', { tenantId })).length;

export function createResourcesApi(ctx: ServerContext) {
  const { store, catalog } = ctx;
  const { operation } = ctx.operations;

  async function applyResourceLinks(
    tx: IamStore,
    record: ResourceRecord,
    definition: CatalogResourceType,
    input: { parentId?: string; ownerId?: string },
  ): Promise<void> {
    if (definition.parent) {
      if (input.parentId === undefined)
        throw new IamError(
          'INVALID_INPUT',
          `Resources of type ${definition.name} require a ${definition.parent} parent`,
        );
      const parent = await managedResource(
        tx,
        record.tenantId,
        definition.parent,
        text(input.parentId, 'parentId', 128),
      );
      if (!parent) throw new IamError('NOT_FOUND', 'Parent resource is not registered', 404);
      record.parentType = definition.parent;
      record.parentId = parent.resourceId;
    } else if (input.parentId !== undefined)
      throw new IamError('INVALID_INPUT', 'This resource type has no parent');
    if (input.ownerId !== undefined) {
      await ctx.activeIdentity(tx, input.ownerId, record.tenantId);
      record.ownerId = input.ownerId;
    }
  }
  async function registerResource(
    tx: IamStore,
    tenantId: string,
    input: ResourceInput,
  ): Promise<ResourceRecord> {
    const definition = await catalog.managedDefinition(tx, tenantId, input.type);
    // Resource patterns treat `*` and `?` as wildcards: an ID holding them would read as a pattern in `iam/{type}/{id}`.
    if (/[*?]/.test(input.id))
      throw new IamError('INVALID_INPUT', 'A resource ID cannot contain * or ?');
    if (await managedResource(tx, tenantId, definition.name, input.id))
      throw new IamError('CONFLICT', 'Resource is already registered', 409);
    const at = Date.now();
    const item: ResourceRecord = {
      id: id(),
      tenantId,
      uniqueKey: `${definition.name}/${input.id}`,
      type: definition.name,
      resourceId: input.id,
      attributes: attributeValues(definition.attributes, input.attributes),
      createdAt: at,
      updatedAt: at,
    };
    await applyResourceLinks(tx, item, definition, input);
    return tx.insert('resources', item);
  }

  return {
    /** Registers a managed resource so authorization can resolve its ownership, attributes, and parent without an application callback. */
    register: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type: string;
        id: string;
        attributes?: Record<string, Json>;
        parentId?: string;
        ownerId?: string;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:resources:create',
        resourceKey(input),
        async ({ tx, tenant }) => {
          await ctx.enforceLimit(tx, tenant, 'resources', () => countResources(tx, tenant.id));
          return registerResource(tx, input.tenantId, input);
        },
      ),
    /** Registers up to 100 resources atomically. Each item is authorized as `iam:resources:create` on `iam/{type}/{id}`, so one denied item rejects the batch. */
    registerMany: async (
      credential: CredentialInput,
      input: { tenantId: string; resources: ResourceInput[] },
    ) => {
      const tenantId = text(input.tenantId, 'tenantId');
      if (
        !Array.isArray(input.resources) ||
        input.resources.length === 0 ||
        input.resources.length > 100
      )
        throw new IamError('INVALID_INPUT', 'Provide 1-100 resources');
      const items: ResourceInput[] = input.resources.map((item) => {
        const value = object(item);
        return {
          type: text(value.type, 'resource type', 64),
          id: text(value.id, 'resource id', 128),
          attributes: value.attributes as Record<string, Json> | undefined,
          parentId: value.parentId as string | undefined,
          ownerId: value.ownerId as string | undefined,
        };
      });
      const authenticated = await ctx.principals.authenticate(credential);
      const outcome = await store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const tenant = await ctx.tenant(tx, tenantId);
        await ctx.enforceLimit(
          tx,
          tenant,
          'resources',
          () => countResources(tx, tenantId),
          items.length,
        );
        // Authorize every item before writing anything, so a denial commits only its audit record.
        const decisions: Decision[] = [];
        for (const item of items) {
          const resourceId = `${item.type}/${item.id}`;
          const decision = await ctx.decisions.decide(
            tx,
            principal,
            { tenantId, action: 'iam:resources:create', resource: { type: 'iam', id: resourceId } },
            true,
          );
          if (!decision.allowed) {
            await ctx.events.audit(
              tx,
              principal,
              'iam:resources:create',
              tenantId,
              resourceId,
              'deny',
            );
            return { denied: resourceId };
          }
          decisions.push(decision);
        }
        const registered: ResourceRecord[] = [];
        for (const [index, item] of items.entries()) {
          registered.push(await registerResource(tx, tenantId, item));
          await ctx.events.audit(
            tx,
            principal,
            'iam:resources:create',
            tenantId,
            `${item.type}/${item.id}`,
            'allow',
            decisions[index]!.reason === 'ROOT_OVERRIDE',
          );
        }
        return { registered };
      });
      if ('denied' in outcome)
        throw new IamError('ACCESS_DENIED', `Access denied for ${outcome.denied}`, 403);
      return { resources: outcome.registered };
    },
    update: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type: string;
        id: string;
        attributes?: Record<string, Json>;
        ownerId?: string | null;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:resources:update',
        resourceKey(input),
        async ({ tx }) => {
          const definition = await catalog.managedDefinition(tx, input.tenantId, input.type);
          const record = await managedResource(tx, input.tenantId, definition.name, input.id);
          if (!record) throw new IamError('NOT_FOUND', 'Resource is not registered', 404);
          const next: ResourceRecord = { ...record, updatedAt: Date.now() };
          if (input.attributes !== undefined)
            next.attributes = attributeValues(definition.attributes, input.attributes);
          if (input.ownerId === null) delete next.ownerId;
          else if (input.ownerId !== undefined) {
            await ctx.scoped(tx, 'identities', input.ownerId, input.tenantId);
            next.ownerId = input.ownerId;
          }
          return tx.put('resources', next);
        },
      ),
    get: async (
      credential: CredentialInput,
      input: { tenantId: string; type: string; id: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:resources:read',
        resourceKey(input),
        async ({ tx }) => {
          const record = await managedResource(tx, input.tenantId, input.type, input.id);
          if (!record) throw new IamError('NOT_FOUND', 'Resource is not registered', 404);
          return record;
        },
      ),
    list: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type?: string;
        parentId?: string;
        ownerId?: string;
        limit?: number;
        offset?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:resources:read',
        input.type !== undefined ? `${text(input.type, 'resource type', 64)}/*` : '*',
        async ({ tx, principal, tenant }) => {
          const filter: Record<string, unknown> = { tenantId: input.tenantId };
          if (input.type !== undefined) filter.type = input.type;
          if (input.parentId !== undefined) filter.parentId = text(input.parentId, 'parentId', 128);
          if (input.ownerId !== undefined) filter.ownerId = text(input.ownerId, 'ownerId');
          const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
          const offset = integer(input.offset ?? 0, 'offset', 0, 1000000);
          // Listing is reading each record: one a policy keeps from the caller (a Deny on iam/document/payroll, an
          // owner condition) is left out, as resources.get would refuse it. A "view as" session sees what both may.
          const readers = [principal, await impersonatingActor(tx, principal)].filter(
            (who) => who !== undefined,
          );
          const prepared = await Promise.all(
            readers.map((who) =>
              ctx.decisions.prepareDecision(tx, who, tenant, 'iam:resources:read'),
            ),
          );
          const readable = (record: ResourceRecord) => {
            const resource = {
              tenantId: record.tenantId,
              type: 'iam',
              id: `${record.type}/${record.resourceId}`,
              attributes: resolvedManaged(record).attributes,
            };
            return prepared.every(
              (ready) => ('fixed' in ready ? ready.fixed : ready.evaluate(resource)).allowed,
            );
          };
          // Order by type/id rather than by opaque record ID so pages are meaningful to callers.
          return (await tx.find<ResourceRecord>('resources', filter))
            .filter(readable)
            .sort(byResourceKey)
            .slice(offset, offset + limit);
        },
      ),
    delete: async (
      credential: CredentialInput,
      input: { tenantId: string; type: string; id: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:resources:delete',
        resourceKey(input),
        async ({ tx }) => {
          const record = await managedResource(tx, input.tenantId, input.type, input.id);
          if (!record) throw new IamError('NOT_FOUND', 'Resource is not registered', 404);
          if (
            (
              await tx.find<ResourceRecord>('resources', {
                tenantId: input.tenantId,
                parentType: record.type,
                parentId: record.resourceId,
              })
            ).length
          )
            throw new IamError('RESOURCE_IN_USE', 'Delete child resources first', 409);
          for (const tuple of await tx.find('relationships', {
            tenantId: input.tenantId,
            type: record.type,
            resourceId: record.resourceId,
          }))
            await tx.delete('relationships', tuple.id);
          await tx.delete('resources', record.id);
          return { deleted: true };
        },
      ),
  };
}
