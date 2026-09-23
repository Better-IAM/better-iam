import {
  IamError,
  findOrdered,
  matchPattern,
  verifyAuditChain,
  type AuditChainHead,
  type AuditEvent,
  type CredentialInput,
  type OutboxMessage,
} from '@better-iam/core';
import type { ServerContext } from '../context.js';
import { publicWebhook, webhookBody } from '../events.js';
import type { Webhook } from '../models.js';
import type { WebhookEvent } from '../options.js';
import { id } from '../utils.js';
import { integer, strings, text } from '../validation.js';

export type DeliveryStatus = 'delivered' | 'failed' | 'pending';

function outcomes(value: unknown): ('allow' | 'deny')[] {
  const items = [...new Set(strings(value, 'outcomes'))];
  if (!items.length || items.some((item) => item !== 'allow' && item !== 'deny'))
    throw new IamError('INVALID_INPUT', 'outcomes must list allow, deny, or both');
  return items as ('allow' | 'deny')[];
}
function resourcePatterns(value: unknown): string[] {
  const items = [...new Set(strings(value, 'resources'))];
  if (!items.length || items.length > 20 || items.some((item) => item.length > 256))
    throw new IamError('INVALID_INPUT', 'resources must contain 1-20 patterns');
  return items;
}

export function createWebhooksApi(ctx: ServerContext) {
  const { auth, events } = ctx;
  const { operation } = ctx.operations;
  return {
    /** Subscribes an HTTPS endpoint to audit events matching the given patterns. The signing secret is returned once. */
    create: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        url: string;
        events: string[];
        description?: string;
        scope?: 'tenant' | 'subtree';
        outcomes?: ('allow' | 'deny')[];
        resources?: string[];
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:webhooks:create',
        input.tenantId,
        async ({ tx, principal, tenant }) => {
          auth.requireRecent(principal);
          const scope = input.scope ?? 'tenant';
          if (!['tenant', 'subtree'].includes(scope))
            throw new IamError('INVALID_INPUT', 'scope must be tenant or subtree');
          if (scope === 'subtree' && !(await ctx.rootPrincipal(tx, principal)))
            throw new IamError(
              'ACCESS_DENIED',
              'Subtree subscriptions are platform controlled',
              403,
            );
          const existing = (await tx.find<Webhook>('webhooks', { tenantId: input.tenantId }))
            .length;
          if (existing >= 50)
            throw new IamError('LIMIT_EXCEEDED', 'At most 50 webhooks per tenant', 409);
          await ctx.enforceLimit(tx, tenant, 'webhooks', async () => existing);
          const hookId = id();
          const { secret, sealed } = events.sealedWebhookSecret(hookId);
          const hook: Webhook = {
            id: hookId,
            tenantId: input.tenantId,
            url: events.webhookUrl(input.url),
            events: events.webhookEvents(input.events),
            active: true,
            scope,
            secretSealed: sealed,
            createdAt: ctx.now(),
            updatedAt: ctx.now(),
            createdBy: principal.identity.id,
          };
          if (input.description !== undefined)
            hook.description = text(input.description, 'description', 512);
          if (input.outcomes !== undefined) hook.outcomes = outcomes(input.outcomes);
          if (input.resources !== undefined) hook.resources = resourcePatterns(input.resources);
          return { webhook: publicWebhook(await tx.insert('webhooks', hook)), secret };
        },
      ),
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:webhooks:read', input.tenantId, async ({ tx }) =>
        (await tx.find<Webhook>('webhooks', { tenantId: input.tenantId })).map(publicWebhook),
      ),
    get: (credential: CredentialInput, input: { tenantId: string; webhookId: string }) =>
      operation(credential, input.tenantId, 'iam:webhooks:read', input.webhookId, async ({ tx }) =>
        publicWebhook(await ctx.scoped<Webhook>(tx, 'webhooks', input.webhookId, input.tenantId)),
      ),
    update: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        webhookId: string;
        url?: string;
        events?: string[];
        description?: string | null;
        active?: boolean;
        outcomes?: ('allow' | 'deny')[] | null;
        resources?: string[] | null;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:webhooks:update',
        input.webhookId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const hook = await ctx.scoped<Webhook>(tx, 'webhooks', input.webhookId, input.tenantId);
          if (
            input.url === undefined &&
            input.events === undefined &&
            input.description === undefined &&
            input.active === undefined &&
            input.outcomes === undefined &&
            input.resources === undefined
          )
            throw new IamError('INVALID_INPUT', 'Nothing to update');
          const next: Webhook = { ...hook, updatedAt: ctx.now() };
          if (input.url !== undefined) next.url = events.webhookUrl(input.url);
          if (input.events !== undefined) next.events = events.webhookEvents(input.events);
          if (input.description === null) delete next.description;
          else if (input.description !== undefined)
            next.description = text(input.description, 'description', 512);
          if (input.outcomes === null) delete next.outcomes;
          else if (input.outcomes !== undefined) next.outcomes = outcomes(input.outcomes);
          if (input.resources === null) delete next.resources;
          else if (input.resources !== undefined)
            next.resources = resourcePatterns(input.resources);
          if (input.active !== undefined) {
            if (typeof input.active !== 'boolean')
              throw new IamError('INVALID_INPUT', 'active must be boolean');
            next.active = input.active;
          }
          return publicWebhook(await tx.put('webhooks', next));
        },
      ),
    /** Issues a new signing secret; deliveries claimed after this point are signed with it. */
    rotateSecret: (credential: CredentialInput, input: { tenantId: string; webhookId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:webhooks:update',
        input.webhookId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const hook = await ctx.scoped<Webhook>(tx, 'webhooks', input.webhookId, input.tenantId);
          const { secret, sealed } = events.sealedWebhookSecret(hook.id);
          return {
            webhook: publicWebhook(
              await tx.put('webhooks', { ...hook, secretSealed: sealed, updatedAt: ctx.now() }),
            ),
            secret,
          };
        },
      ),
    delete: (credential: CredentialInput, input: { tenantId: string; webhookId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:webhooks:delete',
        input.webhookId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          await ctx.scoped<Webhook>(tx, 'webhooks', input.webhookId, input.tenantId);
          await tx.delete('webhooks', input.webhookId);
          for (const message of await tx.find<OutboxMessage>('outbox', {
            tenantId: input.tenantId,
            kind: 'webhook',
            to: input.webhookId,
          }))
            if (!message.deliveredAt && !message.failedAt) await tx.delete('outbox', message.id);
          return { deleted: true };
        },
      ),
    /** Queues a synthetic `webhook:ping` delivery so an endpoint can be verified end to end. */
    ping: (credential: CredentialInput, input: { tenantId: string; webhookId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:webhooks:update',
        input.webhookId,
        async ({ tx, principal }) => {
          const hook = await ctx.scoped<Webhook>(tx, 'webhooks', input.webhookId, input.tenantId);
          if (!hook.active) throw new IamError('INVALID_TRANSITION', 'Webhook is paused');
          const event: WebhookEvent = {
            id: id(),
            type: 'webhook:ping',
            tenantId: hook.tenantId,
            actorId: principal.identity.id,
            resourceId: hook.id,
            outcome: 'allow',
            timestamp: ctx.now(),
          };
          const deliveryId = await auth.enqueueDelivery(tx, {
            tenantId: hook.tenantId,
            kind: 'webhook',
            to: hook.id,
            template: 'webhook:ping',
            payload: { url: hook.url, body: JSON.stringify(event) },
          });
          return { deliveryId };
        },
      ),
    /** Delivery history of one webhook, newest first. Payloads are never returned. */
    listDeliveries: (
      credential: CredentialInput,
      input: { tenantId: string; webhookId: string; limit?: number },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:webhooks:read',
        input.webhookId,
        async ({ tx }) => {
          await ctx.scoped<Webhook>(tx, 'webhooks', input.webhookId, input.tenantId);
          const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
          return (
            await tx.find<OutboxMessage>('outbox', {
              tenantId: input.tenantId,
              kind: 'webhook',
              to: input.webhookId,
            })
          )
            .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? -1 : 1))
            .slice(0, limit)
            .map((message) => ({
              id: message.id,
              event: message.template,
              eventId: message.reference,
              createdAt: message.createdAt,
              attempts: message.attempts,
              deliveredAt: message.deliveredAt,
              failedAt: message.failedAt,
              lastError: message.lastError,
              status: (message.deliveredAt
                ? 'delivered'
                : message.failedAt
                  ? 'failed'
                  : 'pending') as DeliveryStatus,
            }));
        },
      ),
    /**
     * Queues the event behind an earlier delivery again (after an outage, or to replay a delivered event). The body is
     * rebuilt from the audit record and signed with the subscription's current secret at delivery time.
     */
    redeliver: (
      credential: CredentialInput,
      input: { tenantId: string; webhookId: string; deliveryId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:webhooks:update',
        input.webhookId,
        async ({ tx }) => {
          const hook = await ctx.scoped<Webhook>(tx, 'webhooks', input.webhookId, input.tenantId);
          if (!hook.active) throw new IamError('INVALID_TRANSITION', 'Webhook is paused');
          const message = await tx.get<OutboxMessage>(
            'outbox',
            text(input.deliveryId, 'deliveryId'),
          );
          if (
            !message ||
            message.tenantId !== input.tenantId ||
            message.kind !== 'webhook' ||
            message.to !== hook.id
          )
            throw new IamError('NOT_FOUND', 'Delivery not found', 404);
          if (!message.reference)
            throw new IamError('INVALID_TRANSITION', 'This delivery cannot be rebuilt');
          const event = await tx.get<AuditEvent>('audit', message.reference);
          if (!event) throw new IamError('NOT_FOUND', 'The delivered event no longer exists', 404);
          const deliveryId = await auth.enqueueDelivery(tx, {
            tenantId: hook.tenantId,
            kind: 'webhook',
            to: hook.id,
            template: event.action,
            payload: { url: hook.url, body: JSON.stringify(webhookBody(event)) },
            reference: event.id,
          });
          return { deliveryId, eventId: event.id };
        },
      ),
  };
}

export function createAuditApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  return {
    /** Newest first. action accepts a glob pattern; from/to bound the timestamp; actorId, resourceId, and outcome match exactly. */
    list: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        limit?: number;
        offset?: number;
        actorId?: string;
        action?: string;
        resourceId?: string;
        outcome?: 'allow' | 'deny';
        from?: number;
        to?: number;
      },
    ) =>
      operation(credential, input.tenantId, 'iam:audit:read', input.tenantId, async ({ tx }) => {
        const limit = integer(input.limit ?? 100, 'limit', 1, 1000);
        const offset = integer(input.offset ?? 0, 'offset', 0, 1000000);
        const filter: Record<string, unknown> = { tenantId: input.tenantId };
        if (input.actorId !== undefined) filter.actorId = text(input.actorId, 'actorId');
        if (input.resourceId !== undefined)
          filter.resourceId = text(input.resourceId, 'resourceId', 2048);
        if (input.outcome !== undefined) {
          if (!['allow', 'deny'].includes(input.outcome))
            throw new IamError('INVALID_INPUT', 'outcome must be allow or deny');
          filter.outcome = input.outcome;
        }
        const from =
          input.from !== undefined
            ? integer(input.from, 'from', 0, Number.MAX_SAFE_INTEGER)
            : undefined;
        const to =
          input.to !== undefined ? integer(input.to, 'to', 0, Number.MAX_SAFE_INTEGER) : undefined;
        const action = input.action !== undefined ? text(input.action, 'action', 128) : undefined;
        // An action without wildcards is an exact filter the database can use; a glob is applied
        // while reading the log newest first in pages, so the whole log is never loaded.
        const glob = action !== undefined && /[*?]/.test(action);
        if (action !== undefined && !glob) filter.action = action;
        return findOrdered<AuditEvent>(tx, 'audit', filter, {
          field: 'timestamp',
          direction: 'desc',
          from,
          to,
          offset,
          limit,
          ...(glob ? { where: (event: AuditEvent) => matchPattern(action, event.action) } : {}),
        });
      }),
    /**
     * Verifies the tenant's audit hash chain: contiguous sequences, linked hashes, recomputable event hashes, and a
     * chain head that matches the last event. `fromSequence`/`toSequence` verify a window against its own links.
     */
    verify: (
      credential: CredentialInput,
      input: { tenantId: string; fromSequence?: number; toSequence?: number },
    ) =>
      operation(credential, input.tenantId, 'iam:audit:read', input.tenantId, async ({ tx }) => {
        const from =
          input.fromSequence !== undefined
            ? integer(input.fromSequence, 'fromSequence', 1, Number.MAX_SAFE_INTEGER)
            : undefined;
        const to =
          input.toSequence !== undefined
            ? integer(input.toSequence, 'toSequence', 1, Number.MAX_SAFE_INTEGER)
            : undefined;
        const head = await tx.get<AuditChainHead>('auditChains', input.tenantId);
        const events = (await tx.find<AuditEvent>('audit', { tenantId: input.tenantId })).filter(
          (event) =>
            typeof event.sequence !== 'number' ||
            ((from === undefined || event.sequence >= from) &&
              (to === undefined || event.sequence <= to)),
        );
        const partial = from !== undefined || to !== undefined;
        const verification = await verifyAuditChain(events, {
          head: partial || !head ? undefined : { sequence: head.sequence, hash: head.hash },
        });
        return {
          ...verification,
          head: head
            ? { sequence: head.sequence, hash: head.hash, updatedAt: head.updatedAt }
            : null,
        };
      }),
    /**
     * Exports chained events in sequence order as JSON Lines, including `sequence`, `previousHash`, and `hash`, so an
     * archive can be verified later with `verifyAuditChain` (the last line's hash links the next export).
     */
    export: (
      credential: CredentialInput,
      input: { tenantId: string; fromSequence?: number; limit?: number },
    ) =>
      operation(credential, input.tenantId, 'iam:audit:read', input.tenantId, async ({ tx }) => {
        const from =
          input.fromSequence !== undefined
            ? integer(input.fromSequence, 'fromSequence', 1, Number.MAX_SAFE_INTEGER)
            : 1;
        const limit = integer(input.limit ?? 1000, 'limit', 1, 10000);
        // One event past the page tells whether more follow.
        const events = await findOrdered<AuditEvent>(
          tx,
          'audit',
          { tenantId: input.tenantId },
          { field: 'sequence', from, limit: limit + 1 },
        );
        const page = events.slice(0, limit);
        const head = await tx.get<AuditChainHead>('auditChains', input.tenantId);
        return {
          format: 'jsonl' as const,
          count: page.length,
          body: page.map((event) => JSON.stringify(event)).join('\n'),
          firstSequence: page[0]?.sequence,
          lastSequence: page.at(-1)?.sequence,
          nextSequence: events.length > limit ? page.at(-1)!.sequence! + 1 : undefined,
          head: head ? { sequence: head.sequence, hash: head.hash } : null,
        };
      }),
  };
}
