import { createServer, type IncomingHttpHeaders } from 'node:http';
import { createRequire } from 'node:module';
import type { AddressInfo } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, verifyWebhookSignature, type WebhookDelivery } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createAuth, createMemoryRateLimiter, type DeliveryMessage } from '@better-iam/auth';
import type { AuditEvent, IamStore, Tenant } from '@better-iam/core';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture(
  options: {
    transport?: (delivery: WebhookDelivery) => Promise<void>;
    onEvent?: (event: AuditEvent) => void;
    https?: boolean;
  } = {},
) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'events-test-secret-with-at-least-32-characters',
    baseURL: options.https ? 'https://iam.example.test' : 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
      maxDeliveryAttempts: 3,
    },
    events: { deliverWebhook: options.transport, onEvent: options.onEvent },
    permissions: { actions: ['documents:read'] },
    resolveResource: async (reference) => reference,
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const credential = { token: session.token };
  const created = await iam.api.tenants.create(credential, {
    parentId: root.tenant.id,
    name: 'Acme',
    type: 'organization',
    ownerEmail: 'owner@acme.test',
  });
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  return {
    iam,
    database,
    root,
    credential,
    tenantId: created.tenant.id,
    owner,
    ownerCredential: { token: owner.token },
    advance: (ms: number) => {
      clock += ms;
    },
    now: () => clock,
  };
}

describe('webhooks', () => {
  it('delivers signed events for matching subscriptions through the outbox and exposes delivery history', async () => {
    const deliveries: WebhookDelivery[] = [];
    let reject = false;
    const f = await fixture({
      transport: async (delivery) => {
        if (reject) throw new Error('endpoint down');
        deliveries.push(delivery);
      },
    });
    await expect(
      f.iam.api.webhooks.create(f.ownerCredential, {
        tenantId: f.tenantId,
        url: 'http://hooks.example.test/iam',
        events: ['*'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.webhooks.create(f.ownerCredential, {
        tenantId: f.tenantId,
        url: 'https://user:pw@hooks.example.test/iam',
        events: ['*'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.webhooks.create(f.ownerCredential, {
        tenantId: f.tenantId,
        url: 'https://hooks.example.test/iam',
        events: ['bad pattern'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.webhooks.create(f.ownerCredential, {
        tenantId: f.tenantId,
        url: 'https://hooks.example.test/iam',
        events: ['*'],
        scope: 'subtree',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const { webhook, secret } = await f.iam.api.webhooks.create(f.ownerCredential, {
      tenantId: f.tenantId,
      url: 'https://hooks.example.test/iam',
      events: ['iam:identities:*', 'auth:session:create'],
      description: 'SIEM',
    });
    expect(secret).toMatch(/^whsec_/);
    expect(webhook).not.toHaveProperty('secretSealed');
    expect(webhook.active).toBe(true);
    expect(
      (await f.iam.api.webhooks.list(f.ownerCredential, { tenantId: f.tenantId })).map(
        (item) => item.id,
      ),
    ).toEqual([webhook.id]);
    expect(JSON.stringify(await f.database.find('webhooks'))).not.toContain(secret);
    const member = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'member@acme.test',
      name: 'Member',
      password: 'a strong member test password',
    });
    await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Not subscribed',
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'member@acme.test',
      password: 'a strong member test password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({ delivered: 2, failed: 0 });
    expect(deliveries.map((delivery) => delivery.event).sort()).toEqual([
      'auth:session:create',
      'iam:identities:create',
    ]);
    const first = deliveries.find((delivery) => delivery.event === 'iam:identities:create')!;
    expect(first).toMatchObject({
      webhookId: webhook.id,
      url: 'https://hooks.example.test/iam',
      tenantId: f.tenantId,
    });
    const body = JSON.parse(first.body) as Record<string, unknown>;
    expect(body).toMatchObject({
      type: 'iam:identities:create',
      tenantId: f.tenantId,
      actorId: f.owner.identity.id,
      resourceId: f.tenantId,
      outcome: 'allow',
    });
    expect(first.headers['x-better-iam-event']).toBe('iam:identities:create');
    expect(first.headers['x-better-iam-webhook']).toBe(webhook.id);
    expect(
      verifyWebhookSignature({
        secret,
        timestamp: first.headers['x-better-iam-timestamp']!,
        body: first.body,
        signature: first.headers['x-better-iam-signature']!,
        now: f.now(),
      }),
    ).toBe(true);
    expect(
      verifyWebhookSignature({
        secret: 'whsec_wrong',
        timestamp: first.headers['x-better-iam-timestamp']!,
        body: first.body,
        signature: first.headers['x-better-iam-signature']!,
        now: f.now(),
      }),
    ).toBe(false);
    expect(
      verifyWebhookSignature({
        secret,
        timestamp: first.headers['x-better-iam-timestamp']!,
        body: first.body,
        signature: first.headers['x-better-iam-signature']!,
        now: f.now() + 10 * 60_000,
      }),
    ).toBe(false);
    expect(
      verifyWebhookSignature({
        secret,
        timestamp: first.headers['x-better-iam-timestamp']!,
        body: `${first.body} `,
        signature: first.headers['x-better-iam-signature']!,
        now: f.now(),
      }),
    ).toBe(false);
    // Failures back off, retry, and are abandoned after the configured attempts; history never carries payloads.
    reject = true;
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: member.id,
      name: 'Renamed',
    });
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({
      delivered: 0,
      failed: 1,
      abandoned: 0,
    });
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({
      delivered: 0,
      failed: 0,
      abandoned: 0,
    });
    f.advance(31_000);
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({
      delivered: 0,
      failed: 1,
      abandoned: 0,
    });
    f.advance(61_000);
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({
      delivered: 0,
      failed: 1,
      abandoned: 1,
    });
    const history = await f.iam.api.webhooks.listDeliveries(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
    });
    expect(history.map((item) => [item.event, item.status, item.attempts]).sort()).toEqual([
      ['auth:session:create', 'delivered', 1],
      ['iam:identities:create', 'delivered', 1],
      ['iam:identities:update', 'failed', 3],
    ]);
    const abandoned = history.find((item) => item.event === 'iam:identities:update')!;
    expect(abandoned.lastError).toContain('endpoint down');
    expect(abandoned).not.toHaveProperty('payload');
    expect(typeof abandoned.failedAt).toBe('number');
    reject = false;
    // Rotation signs later deliveries with the new secret; pausing drops pending deliveries; ping verifies an endpoint.
    const rotated = await f.iam.api.webhooks.rotateSecret(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
    });
    expect(rotated.secret).not.toBe(secret);
    await f.iam.api.webhooks.ping(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
    });
    await f.iam.auth.dispatchOutbox();
    const ping = deliveries.at(-1)!;
    expect(ping.event).toBe('webhook:ping');
    expect(
      verifyWebhookSignature({
        secret: rotated.secret,
        timestamp: ping.headers['x-better-iam-timestamp']!,
        body: ping.body,
        signature: ping.headers['x-better-iam-signature']!,
        now: f.now(),
      }),
    ).toBe(true);
    await f.iam.api.webhooks.update(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
      active: false,
      events: ['*'],
    });
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: member.id,
      name: 'Paused',
    });
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({ delivered: 0, failed: 0 });
    expect(deliveries.at(-1)!.event).toBe('webhook:ping');
    await f.iam.api.webhooks.update(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
      active: true,
    });
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: member.id,
      name: 'Resumed',
    });
    await f.iam.auth.dispatchOutbox();
    // Resuming is itself audited after the subscription is active again, so both events arrive; order within one tick is by creation time then id.
    expect(
      deliveries
        .slice(-2)
        .map((delivery) => delivery.event)
        .sort(),
    ).toEqual(['iam:identities:update', 'iam:webhooks:update']);
    // Another tenant's events are never delivered to this subscription, and deleting the subscription clears its queue.
    await f.iam.api.identities.create(f.credential, {
      tenantId: f.root.tenant.id,
      email: 'other@example.test',
      name: 'Other',
    });
    await f.iam.auth.dispatchOutbox();
    expect(deliveries.filter((delivery) => delivery.tenantId === f.root.tenant.id)).toEqual([]);
    await expect(
      f.iam.api.webhooks.get(
        { token: login.token },
        { tenantId: f.tenantId, webhookId: webhook.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: member.id,
      name: 'Queued',
    });
    await f.iam.api.webhooks.delete(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
    });
    const remaining = await f.database.find('outbox', {
      tenantId: f.tenantId,
      kind: 'webhook',
      to: webhook.id,
    });
    expect(remaining.length).toBeGreaterThan(0);
    expect(remaining.every((message) => message.deliveredAt || message.failedAt)).toBe(true);
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({ delivered: 0, failed: 0 });
  });

  it('lets root subscribe a platform endpoint to a whole subtree and uses the built-in HTTP transport', async () => {
    const requests: { url: string; method: string; headers: IncomingHttpHeaders; body: string }[] =
      [];
    const server = createServer((request, response) => {
      const chunks: Buffer[] = [];
      request.on('data', (chunk: Buffer) => chunks.push(chunk));
      request.on('end', () => {
        requests.push({
          url: request.url ?? '',
          method: request.method ?? '',
          headers: request.headers,
          body: Buffer.concat(chunks).toString('utf8'),
        });
        response.writeHead(requests.length === 1 ? 500 : 204);
        response.end();
      });
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    try {
      // An http baseURL (development) lets webhooks reach loopback endpoints over http.
      const f = await fixture();
      const port = (server.address() as AddressInfo).port;
      const platform = await f.iam.api.webhooks.create(f.credential, {
        tenantId: f.root.tenant.id,
        url: `http://127.0.0.1:${port}/ingest`,
        events: ['iam:groups:create'],
        scope: 'subtree',
      });
      await f.iam.api.groups.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Engineering',
      });
      expect(await f.iam.auth.dispatchOutbox()).toMatchObject({ delivered: 0, failed: 1 });
      f.advance(31_000);
      expect(await f.iam.auth.dispatchOutbox()).toMatchObject({ delivered: 1, failed: 0 });
      expect(requests).toHaveLength(2);
      const { url, method, headers, body } = requests[1]!;
      expect(url).toBe('/ingest');
      expect(method).toBe('POST');
      expect(headers['x-better-iam-event']).toBe('iam:groups:create');
      expect(
        verifyWebhookSignature({
          secret: platform.secret,
          timestamp: String(headers['x-better-iam-timestamp']),
          body,
          signature: String(headers['x-better-iam-signature']),
          now: f.now(),
        }),
      ).toBe(true);
      expect(JSON.parse(body)).toMatchObject({
        type: 'iam:groups:create',
        tenantId: f.tenantId,
      });
    } finally {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });
});

describe('in-process events', () => {
  it('dispatches committed audit events to subscribers and the configured callback, never for rolled-back mutations', async () => {
    const seen: string[] = [];
    const f = await fixture({
      onEvent: (event) => {
        seen.push(`callback:${event.action}`);
      },
    });
    // Every audit event since bootstrap was queued for the callback; drain them before observing.
    expect((await f.iam.events.dispatch()).dispatched).toBeGreaterThan(3);
    expect(seen).toContain('callback:root:bootstrap');
    expect(seen).toContain('callback:auth:session:create');
    seen.length = 0;
    const unsubscribe = f.iam.events.subscribe(['iam:groups:*'], (event) => {
      seen.push(`groups:${event.action}:${event.tenantId === f.tenantId}`);
    });
    f.iam.events.subscribe('access-request:*', () => {
      seen.push('never');
    });
    await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Support' });
    await expect(
      f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: '' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.groups.list(
        { token: 'not-a-real-token-value-at-all-1234567890' },
        { tenantId: f.tenantId },
      ),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(seen).toEqual([]);
    expect(await f.iam.events.dispatch()).toMatchObject({ dispatched: 1 });
    expect(seen).toEqual(['callback:iam:groups:create', `groups:iam:groups:create:true`]);
    unsubscribe();
    await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Sales' });
    await f.iam.dispatchAuditHooks();
    expect(seen).toEqual([
      'callback:iam:groups:create',
      'groups:iam:groups:create:true',
      'callback:iam:groups:create',
    ]);
    expect(await f.iam.dispatchAuditHooks()).toEqual({ dispatched: 0 });
  });
});

describe('configurable rate limits', () => {
  it('applies configured thresholds and windows through a pluggable limiter', async () => {
    const store = sqliteAdapter({ filename: ':memory:' });
    databases.push(store);
    await store.migrate();
    let clock = Date.now();
    const limiter = createMemoryRateLimiter();
    const auth = createAuth({
      store,
      secret: 'rate-limit-test-secret-with-32-characters',
      baseURL: 'http://localhost:3000',
      now: () => clock,
      rateLimits: { attempts: 2, windowMs: 60_000, limiter },
    });
    await store.transaction(async (tx) => {
      await tx.insert<Tenant>('tenants', {
        id: 'org',
        tenantId: 'org',
        name: 'org',
        parentId: null,
        type: 'root',
        status: 'active',
        createdAt: clock,
      });
    });
    const attempt = () =>
      auth.signIn({
        tenantId: 'org',
        email: 'nobody@example.test',
        password: 'a strong wrong password',
      });
    await expect(attempt()).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(attempt()).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(attempt()).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    expect(await store.find('authRateLimits')).toEqual([]);
    clock += 61_000;
    await expect(attempt()).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(() =>
      createAuth({
        store,
        secret: 'rate-limit-test-secret-with-32-characters',
        baseURL: 'http://localhost:3000',
        rateLimits: { attempts: 0 },
      }),
    ).toThrow(/rateLimits.attempts/u);
    expect(() =>
      createAuth({
        store,
        secret: 'rate-limit-test-secret-with-32-characters',
        baseURL: 'http://localhost:3000',
        rateLimits: { windowMs: 10 },
      }),
    ).toThrow(/rateLimits.windowMs/u);
    expect(() =>
      createAuth({
        store,
        secret: 'rate-limit-test-secret-with-32-characters',
        baseURL: 'http://localhost:3000',
        maxDeliveryAttempts: 0,
      }),
    ).toThrow(/maxDeliveryAttempts/u);
  });
});
