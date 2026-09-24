import { IamError, type CredentialInput } from '@better-iam/core';
import { managedResource, resolvedManaged } from '../catalog.js';
import type { ServerContext } from '../context.js';
import { impersonatingActor } from '../decisions.js';
import type { Relationship } from '../models.js';
import { byNewest, id } from '../utils.js';
import { text } from '../validation.js';

const subjectTypes = new Set(['identity', 'group']);

/**
 * Relationship tuples: "this identity or group is a {relation} of {type}/{id}". Policies read the relations a
 * principal holds on the evaluated resource as `resource.relations` (and on its parent as `resource.parentRelations`),
 * so a role such as `{ ArrayContains: { 'resource.relations': ['editor'] } }` expresses sharing without listing IDs.
 */
export function createRelationshipsApi(ctx: ServerContext) {
  const { catalog } = ctx;
  const { operation } = ctx.operations;
  const resourceKey = (input: { type: string; id: string }) =>
    `${text(input.type, 'resource type', 64)}/${text(input.id, 'resource id', 128)}`;
  const live = (tuple: Relationship) =>
    tuple.expiresAt === undefined || tuple.expiresAt > ctx.now();
  return {
    /** Grants a declared relation on one resource to an identity or group. Requires iam:relationships:create on `iam/{type}/{id}`. */
    create: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type: string;
        id: string;
        relation: string;
        subjectType: 'identity' | 'group';
        subjectId: string;
        expiresAt?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:relationships:create',
        resourceKey(input),
        async ({ tx, principal }) => {
          const definition = await catalog.resourceTypeDefinition(tx, input.tenantId, input.type);
          if (!definition) throw new IamError('INVALID_RESOURCE_TYPE', 'Unknown resource type');
          const relation = text(input.relation, 'relation', 64);
          if (!definition.relations.includes(relation))
            throw new IamError(
              'INVALID_INPUT',
              `Relation ${relation} is not declared for ${definition.name}`,
            );
          if (
            definition.managed &&
            !(await managedResource(tx, input.tenantId, definition.name, input.id))
          )
            throw new IamError('NOT_FOUND', 'Resource is not registered', 404);
          if (!subjectTypes.has(input.subjectType))
            throw new IamError('INVALID_INPUT', 'Invalid subject type');
          if (input.subjectType === 'identity')
            await ctx.activeIdentity(tx, input.subjectId, input.tenantId);
          else await ctx.scoped(tx, 'groups', input.subjectId, input.tenantId);
          const uniqueKey = `${definition.name}/${input.id}#${relation}@${input.subjectType}:${input.subjectId}`;
          const existing = (
            await tx.find<Relationship>('relationships', { tenantId: input.tenantId, uniqueKey })
          )[0];
          const tuple: Relationship = {
            id: existing?.id ?? id(),
            tenantId: input.tenantId,
            uniqueKey,
            type: definition.name,
            resourceId: input.id,
            relation,
            subjectType: input.subjectType,
            subjectId: input.subjectId,
            createdAt: existing?.createdAt ?? ctx.now(),
            createdBy: principal.identity.id,
          };
          if (input.expiresAt !== undefined) tuple.expiresAt = ctx.bindingExpiry(input.expiresAt);
          return existing ? tx.put('relationships', tuple) : tx.insert('relationships', tuple);
        },
      ),
    /** Relationships of a resource, of a subject, or of the whole tenant; expired tuples are omitted unless requested. */
    list: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        type?: string;
        id?: string;
        relation?: string;
        subjectType?: 'identity' | 'group';
        subjectId?: string;
        includeExpired?: boolean;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:relationships:read',
        input.type !== undefined && input.id !== undefined
          ? resourceKey({ type: input.type, id: input.id })
          : input.type !== undefined
            ? `${text(input.type, 'resource type', 64)}/*`
            : '*',
        async ({ tx, principal, tenant }) => {
          // Listing is reading each resource's tuples: one a policy keeps from the caller (a Deny on
          // iam/document/payroll, an owner condition) is left out. A "view as" session sees what both may.
          const readers = [principal, await impersonatingActor(tx, principal)].filter(
            (who) => who !== undefined,
          );
          const prepared = await Promise.all(
            readers.map((who) =>
              ctx.decisions.prepareDecision(tx, who, tenant, 'iam:relationships:read'),
            ),
          );
          const verdicts = new Map<string, boolean>();
          const readable = async (tuple: Relationship) => {
            const key = `${tuple.type}/${tuple.resourceId}`;
            let verdict = verdicts.get(key);
            if (verdict === undefined) {
              const record = await managedResource(tx, tenant.id, tuple.type, tuple.resourceId);
              const resource = {
                tenantId: tenant.id,
                type: 'iam',
                id: key,
                ...(record ? { attributes: resolvedManaged(record).attributes } : {}),
              };
              verdict = prepared.every(
                (ready) => ('fixed' in ready ? ready.fixed : ready.evaluate(resource)).allowed,
              );
              verdicts.set(key, verdict);
            }
            return verdict;
          };
          const filter: Record<string, unknown> = { tenantId: input.tenantId };
          if (input.type !== undefined) filter.type = input.type;
          if (input.id !== undefined) filter.resourceId = text(input.id, 'resource id', 128);
          if (input.relation !== undefined) filter.relation = text(input.relation, 'relation', 64);
          if (input.subjectType !== undefined) {
            if (!subjectTypes.has(input.subjectType))
              throw new IamError('INVALID_INPUT', 'Invalid subject type');
            filter.subjectType = input.subjectType;
          }
          if (input.subjectId !== undefined) filter.subjectId = text(input.subjectId, 'subjectId');
          const tuples: Relationship[] = [];
          for (const tuple of await tx.find<Relationship>('relationships', filter))
            if ((input.includeExpired === true || live(tuple)) && (await readable(tuple)))
              tuples.push(tuple);
          return tuples.sort(byNewest);
        },
      ),
    /** Removes one tuple. Requires iam:relationships:delete on the tuple's resource. */
    delete: async (
      credential: CredentialInput,
      input: { tenantId: string; relationshipId: string },
    ) => {
      const existing = await ctx.scoped<Relationship>(
        ctx.store,
        'relationships',
        input.relationshipId,
        text(input.tenantId, 'tenantId'),
      );
      return operation(
        credential,
        input.tenantId,
        'iam:relationships:delete',
        `${existing.type}/${existing.resourceId}`,
        async ({ tx }) => {
          await ctx.scoped<Relationship>(tx, 'relationships', input.relationshipId, input.tenantId);
          await tx.delete('relationships', input.relationshipId);
          return { deleted: true };
        },
      );
    },
  };
}
