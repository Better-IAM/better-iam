import { createHmac, timingSafeEqual } from 'node:crypto';
import {
  IamError,
  appendAuditEvent,
  matchPattern,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type IamStore,
} from '@better-iam/core';
import { decryptSecret, encryptSecret, type DeliveryMessage } from '@better-iam/auth';
import type { ServerContext } from './context.js';
import type { Webhook } from './models.js';
import { checkFetchUrl, createGuardedFetch } from './safe-fetch.js';
import type { WebhookDelivery, WebhookEvent } from './options.js';
import { auditSessionContext } from './temporary-credentials.js';
import { id, token } from './utils.js';
import { strings, text } from './validation.js';

const webhookEventPattern = /^[a-zA-Z0-9:*?_.-]{1,128}$/;

/** Verifies a webhook signature produced by Better IAM. `signature` is the X-Better-IAM-Signature header value. */
export function verifyWebhookSignature(input: {
  secret: string;
  timestamp: string | number;
  body: string;
  signature: string;
  toleranceSeconds?: number;
  now?: number;
}): boolean {
  const timestamp = Number(input.timestamp);
  if (!Number.isFinite(timestamp)) return false;
  const tolerance = input.toleranceSeconds ?? 300;
  if (Math.abs(Math.floor((input.now ?? Date.now()) / 1000) - timestamp) > tolerance) return false;
  const expected = createHmac('sha256', input.secret).update(`${timestamp}.${input.body}`).digest();
  const provided = input.signature
    .split(',')
    .map((part) => part.trim())
    .find((part) => part.startsWith('v1='))
    ?.slice(3);
  if (!provided || !/^[0-9a-f]{64}$/.test(provided)) return false;
  return timingSafeEqual(expected, Buffer.from(provided, 'hex'));
}

export function webhookBody(event: AuditEvent): WebhookEvent {
  const body: WebhookEvent = {
    id: event.id,
    type: event.action,
    tenantId: event.tenantId,
    actorId: event.actorId,
    resourceId: event.resourceId,
    outcome: event.outcome,
    timestamp: event.timestamp,
  };
  if (event.originalActorId) body.originalActorId = event.originalActorId;
  if (event.impersonatorId) body.impersonatorId = event.impersonatorId;
  if (event.rootOverride) body.rootOverride = true;
  if (event.metadata) body.metadata = event.metadata;
  if (event.sessionContext) body.sessionContext = { ...event.sessionContext };
  if (typeof event.sequence === 'number') body.sequence = event.sequence;
  if (typeof event.hash === 'string') body.hash = event.hash;
  return body;
}

export function publicWebhook(hook: Webhook) {
  const { secretSealed: _sealed, ...safe } = hook;
  return safe;
}

export interface EventService {
  /** Records an audit event and fans it out. Every audit insert in the server goes through here. */
  recordAudit(tx: IamStore, event: AuditEvent): Promise<void>;
  /** Records an audit event attributed to the acting principal, with the session context of its credential. */
  audit(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    resourceId: string,
    outcome: 'allow' | 'deny',
    rootOverride?: boolean,
    metadata?: AuditEvent['metadata'],
  ): Promise<void>;
  /** Queues post-commit dispatch and webhook deliveries inside the recording transaction. */
  fanOut(tx: IamStore, event: AuditEvent): Promise<void>;
  /** Built-in webhook transport: signs the stored body with the subscription's current secret and POSTs it. */
  deliverWebhookMessage(message: DeliveryMessage): Promise<void>;
  /** Post-commit dispatch of queued events to plugins, the configured callback, and in-process subscribers. */
  dispatch(): Promise<{ dispatched: number }>;
  /** Subscribes an in-process handler to audit events whose action matches any pattern. Returns an unsubscribe function. */
  subscribe(
    pattern: string | string[],
    handler: (event: AuditEvent) => Promise<void> | void,
  ): () => void;
  webhookUrl(value: unknown): string;
  webhookEvents(value: unknown): string[];
  sealedWebhookSecret(hookId: string): { secret: string; sealed: string };
}

export function createEvents(ctx: ServerContext): EventService {
  const { options, store, config, plugins, subscribers } = ctx;
  /** Where webhook endpoints may point: public addresses on any https port; loopback over http in development. */
  const webhookAddressRules = {
    anyPort: true,
    allowPrivateNetworks: options.events?.allowPrivateNetworks === true,
    allowInsecureLocalhost: config.baseURL.protocol !== 'https:',
  };
  const webhookFetch = createGuardedFetch(webhookAddressRules);
  const service: EventService = {
    async fanOut(tx, event) {
      if (
        plugins.some((plugin) => plugin.afterAudit) ||
        options.events?.onEvent ||
        subscribers.size
      ) {
        await tx.insert('auditHooks', {
          id: event.id,
          tenantId: event.tenantId,
          event,
          delivered: false,
        });
      }
      const hooks = await tx.find<Webhook>('webhooks', { active: true });
      if (!hooks.length) return;
      let ancestors: string[] | undefined;
      const body = JSON.stringify(webhookBody(event));
      for (const hook of hooks) {
        if (!hook.events.some((pattern) => matchPattern(pattern, event.action))) continue;
        if (hook.outcomes && !hook.outcomes.includes(event.outcome)) continue;
        if (
          hook.resources &&
          !hook.resources.some((pattern) => matchPattern(pattern, event.resourceId))
        )
          continue;
        if (hook.tenantId !== event.tenantId) {
          if (hook.scope !== 'subtree') continue;
          ancestors ??= await ctx.ancestorIds(tx, event.tenantId);
          if (!ancestors.includes(hook.tenantId)) continue;
        }
        await ctx.auth.enqueueDelivery(tx, {
          tenantId: hook.tenantId,
          kind: 'webhook',
          to: hook.id,
          template: event.action,
          payload: { url: hook.url, body },
          reference: event.id,
        });
      }
    },
    async recordAudit(tx, event) {
      await service.fanOut(tx, await appendAuditEvent(tx, event));
    },
    async audit(
      tx,
      principal,
      action,
      tenantId,
      resourceId,
      outcome,
      rootOverride = false,
      metadata,
    ) {
      const event: AuditEvent = {
        id: id(),
        tenantId,
        actorId: principal.identity.id,
        originalActorId: principal.session.originalIdentityId,
        action,
        resourceId,
        outcome,
        rootOverride,
        timestamp: Date.now(),
      };
      if (metadata) event.metadata = metadata;
      if (principal.session.impersonatorId) event.impersonatorId = principal.session.impersonatorId;
      // Which credential acted (and the role, trust and names behind a temporary one); covered by the hash chain.
      const sessionContext = auditSessionContext(principal.session);
      if (sessionContext) event.sessionContext = sessionContext;
      // Hooks are dispatched separately so external code cannot interrupt a committed mutation.
      await service.recordAudit(tx, event);
    },
    async deliverWebhookMessage(message) {
      const hook = await store.get<Webhook>('webhooks', message.to);
      // A removed or paused subscription drops its pending deliveries instead of failing forever.
      if (!hook || !hook.active) return;
      const body = message.payload.body;
      if (typeof body !== 'string')
        throw new IamError('INVALID_SEALED_VALUE', 'Webhook payload is incomplete');
      const secret = decryptSecret(
        hook.secretSealed,
        [options.secret, ...(options.previousSecrets ?? [])],
        `webhook:${hook.id}`,
      );
      const timestamp = Math.floor(ctx.now() / 1000);
      const signature = createHmac('sha256', secret).update(`${timestamp}.${body}`).digest('hex');
      const delivery: WebhookDelivery = {
        id: message.id,
        tenantId: message.tenantId,
        webhookId: hook.id,
        url: hook.url,
        event: message.template,
        body,
        headers: {
          'content-type': 'application/json',
          'user-agent': 'better-iam-webhooks/1',
          'x-better-iam-event': message.template,
          'x-better-iam-delivery': message.id,
          'x-better-iam-webhook': hook.id,
          'x-better-iam-timestamp': String(timestamp),
          'x-better-iam-signature': `v1=${signature}`,
        },
      };
      if (options.events?.deliverWebhook) {
        await options.events.deliverWebhook(delivery);
        return;
      }
      let response: Response;
      try {
        // Tenant administrators choose the URL: the guarded transport refuses private and reserved addresses at
        // connect time (so a hostname cannot be re-pointed at the internal network after validation) and never
        // follows redirects.
        response = await webhookFetch(delivery.url, {
          method: 'POST',
          headers: delivery.headers,
          body,
          redirect: 'error',
          signal: AbortSignal.timeout(config.webhookTimeoutMs),
        });
      } catch (error) {
        // One message for every connection failure, so delivery history cannot map networks or ports.
        throw new IamError(
          'WEBHOOK_UNREACHABLE',
          error instanceof Error && error.name === 'TimeoutError'
            ? 'Webhook endpoint did not answer in time'
            : 'Webhook endpoint could not be reached',
          502,
        );
      }
      // The response body is never read; release the connection.
      await response.body?.cancel().catch(() => undefined);
      if (!response.ok)
        throw new IamError(
          'WEBHOOK_REJECTED',
          `Webhook endpoint responded with status ${response.status}`,
          502,
        );
    },
    async dispatch() {
      let dispatched = 0;
      for (const row of await store.find('auditHooks', { delivered: false })) {
        const event = row.event as AuditEvent;
        for (const plugin of plugins) await plugin.afterAudit?.(event);
        await options.events?.onEvent?.(event);
        for (const subscriber of [...subscribers])
          if (subscriber.patterns.some((pattern) => matchPattern(pattern, event.action)))
            await subscriber.handler(event);
        // Re-read: another dispatcher may have delivered the row and a retention sweep deleted it.
        await store.transaction(async (tx) => {
          const current = await tx.get('auditHooks', row.id);
          if (current && !current.delivered)
            await tx.put('auditHooks', { ...current, delivered: true, deliveredAt: ctx.now() });
        });
        dispatched++;
      }
      return { dispatched };
    },
    subscribe(pattern, handler) {
      const patterns = (Array.isArray(pattern) ? pattern : [pattern]).map((item) =>
        text(item, 'event pattern', 128),
      );
      const subscriber = { patterns, handler };
      subscribers.add(subscriber);
      return () => {
        subscribers.delete(subscriber);
      };
    },
    webhookUrl(value) {
      const raw = text(value, 'url', 2048);
      let url: URL;
      try {
        url = new URL(raw);
      } catch {
        throw new IamError('INVALID_INPUT', 'Webhook URL must be absolute');
      }
      if (url.username || url.password || url.hash)
        throw new IamError('INVALID_INPUT', 'Webhook URLs cannot carry credentials or fragments');
      const loopback = ['localhost', '127.0.0.1', '[::1]'].includes(url.hostname);
      if (
        url.protocol !== 'https:' &&
        !(url.protocol === 'http:' && loopback && config.baseURL.protocol !== 'https:')
      )
        throw new IamError('INVALID_INPUT', 'Webhook URLs must use HTTPS');
      // IP literals are judged now; hostnames are judged again by the transport each time it connects.
      try {
        checkFetchUrl(url, webhookAddressRules);
      } catch {
        throw new IamError(
          'INVALID_INPUT',
          'Webhook URLs must point at a public address (see events.allowPrivateNetworks)',
        );
      }
      return url.toString();
    },
    webhookEvents(value) {
      const patterns = strings(value, 'events');
      if (
        !patterns.length ||
        patterns.length > 50 ||
        patterns.some((pattern) => !webhookEventPattern.test(pattern))
      )
        throw new IamError('INVALID_INPUT', 'events must contain 1-50 event name patterns');
      return [...new Set(patterns)];
    },
    sealedWebhookSecret(hookId) {
      const secret = `whsec_${token()}`;
      return { secret, sealed: encryptSecret(secret, options.secret, `webhook:${hookId}`) };
    },
  };
  return service;
}
