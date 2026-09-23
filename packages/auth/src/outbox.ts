import { IamError, type IamStore, type OutboxMessage } from '@better-iam/core';
import { decryptSecret, encryptSecret, newId } from './crypto.js';
import type { DeliveryMessage } from './types.js';

export interface OutboxContext {
  store: IamStore;
  /** Seals new payloads. */
  secret: string;
  /** Opens payloads: the current secret, then previous ones during a rotation (defaults to `secret`). */
  secrets?: readonly string[];
  now(): number;
  maxAttempts: number;
  /** The callback for a message kind, or undefined when that kind is not configured. */
  deliverer(kind: OutboxMessage['kind']): ((message: DeliveryMessage) => Promise<void>) | undefined;
}
export interface DispatchResult {
  delivered: number;
  failed: number;
  abandoned: number;
}

/** Enqueues a sealed delivery in the caller's transaction and returns the message ID. */
export async function enqueueDelivery(
  ctx: OutboxContext,
  tx: IamStore,
  input: {
    tenantId: string;
    kind: OutboxMessage['kind'];
    to: string;
    template: string;
    payload: Record<string, string>;
    reference?: string;
  },
): Promise<string> {
  const { kind, to, template, payload } = input;
  if (!ctx.deliverer(kind))
    throw new IamError('FEATURE_DISABLED', `${kind} delivery is not configured`);
  const id = newId('out');
  const message: OutboxMessage = {
    id,
    tenantId: input.tenantId,
    kind,
    to,
    template,
    payload: { sealed: encryptSecret(JSON.stringify(payload), ctx.secret, `outbox:${id}`) },
    createdAt: ctx.now(),
    attempts: 0,
  };
  if (input.reference !== undefined) message.reference = input.reference;
  await tx.insert<OutboxMessage>('outbox', message);
  return id;
}

/**
 * At-least-once delivery. Callbacks must deduplicate by message.id. A failed attempt is retried with
 * exponential backoff (30 seconds doubling to one hour) until maxAttempts, then abandoned with failedAt set.
 */
export async function dispatchOutbox(ctx: OutboxContext, limit = 100): Promise<DispatchResult> {
  if (!Number.isInteger(limit) || limit < 1 || limit > 1000)
    throw new IamError('INVALID_INPUT', 'limit must be between 1 and 1000');
  let delivered = 0;
  let failed = 0;
  let abandoned = 0;
  const now = ctx.now();
  const pending = (await ctx.store.find<OutboxMessage>('outbox'))
    .filter(
      (message) =>
        !message.deliveredAt &&
        !message.failedAt &&
        !(typeof message.leaseUntil === 'number' && message.leaseUntil > now),
    )
    .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1))
    .slice(0, limit);
  for (const candidate of pending) {
    const lease = newId('lease');
    // Claiming is its own transaction so two workers never deliver the same message.
    const claimed = await ctx.store.transaction(async (tx) => {
      const message = await tx.get<OutboxMessage>('outbox', candidate.id);
      if (
        !message ||
        message.deliveredAt ||
        message.failedAt ||
        (typeof message.leaseUntil === 'number' && message.leaseUntil > ctx.now())
      )
        return undefined;
      message.lease = lease;
      message.leaseUntil = ctx.now() + 60_000;
      message.attempts++;
      await tx.put('outbox', message);
      return message;
    });
    if (!claimed) continue;
    try {
      const callback = ctx.deliverer(claimed.kind);
      if (!callback) throw new IamError('FEATURE_DISABLED', 'Delivery callback unavailable');
      if (!claimed.payload.sealed)
        throw new IamError('INVALID_SEALED_VALUE', 'Outbox payload is not sealed');
      const payload = JSON.parse(
        decryptSecret(claimed.payload.sealed, ctx.secrets ?? ctx.secret, `outbox:${claimed.id}`),
      ) as Record<string, string>;
      await callback({
        id: claimed.id,
        tenantId: claimed.tenantId,
        to: claimed.to,
        template: claimed.template,
        payload,
      });
      await ctx.store.transaction(async (tx) => {
        const message = await tx.get<OutboxMessage>('outbox', claimed.id);
        if (message?.lease === lease)
          await tx.put('outbox', {
            ...message,
            payload: {},
            deliveredAt: ctx.now(),
            leaseUntil: 0,
            lastError: undefined,
          });
      });
      delivered++;
    } catch (error) {
      failed++;
      const lastError = (
        error instanceof Error ? `${error.name}: ${error.message}` : String(error)
      ).slice(0, 256);
      const exhausted = claimed.attempts >= ctx.maxAttempts;
      if (exhausted) abandoned++;
      const backoff = Math.min(30_000 * 2 ** Math.max(0, claimed.attempts - 1), 60 * 60_000);
      await ctx.store.transaction(async (tx) => {
        const message = await tx.get<OutboxMessage>('outbox', claimed.id);
        if (message?.lease !== lease) return;
        await tx.put(
          'outbox',
          exhausted
            ? { ...message, payload: {}, failedAt: ctx.now(), leaseUntil: 0, lastError }
            : { ...message, leaseUntil: ctx.now() + backoff, lastError },
        );
      });
    }
  }
  return { delivered, failed, abandoned };
}
