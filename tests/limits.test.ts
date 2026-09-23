import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type WebhookDelivery } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const deliveries: WebhookDelivery[] = [];
  const iam = betterIam({
    database,
    secret: 'limits-test-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    events: {
      deliverWebhook: async (delivery) => {
        deliveries.push(delivery);
      },
    },
    permissions: {
      resourceTypes: { folder: { managed: true, actions: ['folders:read'] } },
    },
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
  const rootCredential = { token: session.token };
  const created = await iam.api.tenants.create(rootCredential, {
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
    inbox,
    deliveries,
    tenantId: created.tenant.id,
    rootCredential,
    ownerCredential: { token: owner.token },
  };
}

describe('tenant plan limits and usage', () => {
  it('lets root cap members, service accounts, groups, roles, policies, resources, and webhooks', async () => {
    const f = await fixture();
    // Only root sets limits; validation rejects unknown keys and negative numbers.
    await expect(
      f.iam.api.tenants.setLimits(f.ownerCredential, {
        tenantId: f.tenantId,
        limits: { identities: 5 },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.tenants.setLimits(f.rootCredential, {
        tenantId: f.tenantId,
        limits: { seats: 5 } as never,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.tenants.setLimits(f.rootCredential, {
        tenantId: f.tenantId,
        limits: { identities: -1 },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const limited = await f.iam.api.tenants.setLimits(f.rootCredential, {
      tenantId: f.tenantId,
      limits: {
        identities: 2,
        serviceAccounts: 1,
        groups: 1,
        roles: 2,
        policies: 1,
        resources: 2,
        webhooks: 1,
      },
    });
    expect(limited.limits).toEqual({
      identities: 2,
      serviceAccounts: 1,
      groups: 1,
      roles: 2,
      policies: 1,
      resources: 2,
      webhooks: 1,
    });
    // Members: the owner counts, one more fits, the third is refused on every creation path.
    await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
    });
    await expect(
      f.iam.api.identities.create(f.ownerCredential, {
        tenantId: f.tenantId,
        email: 'bob@acme.test',
        name: 'Bob',
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await expect(
      f.iam.api.identities.createMany(f.ownerCredential, {
        tenantId: f.tenantId,
        identities: [{ email: 'bob@acme.test', name: 'Bob' }],
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await f.iam.api.identities.invite(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'carol@acme.test',
    });
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find(
      (message) => message.template === 'member-invitation' && message.to === 'carol@acme.test',
    )!;
    await expect(
      f.iam.api.identities.acceptInvitation({
        tenantId: f.tenantId,
        token: invitation.payload.token!,
        name: 'Carol',
        password: 'a strong carol password',
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    // Other collections.
    const bot = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'bot',
    });
    await expect(
      f.iam.api.serviceAccounts.create(f.ownerCredential, { tenantId: f.tenantId, name: 'bot2' }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Team' });
    await expect(
      f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Team 2' }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    // The protected Owner role already counts as one role.
    await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers',
      permissions: ['folders:read'],
    });
    await expect(
      f.iam.api.roles.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Writers',
        permissions: ['folders:read'],
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await expect(
      f.iam.api.policies.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Extra',
        document: {
          version: 1,
          statements: [{ effect: 'allow', actions: ['folders:read'], resources: ['*'] }],
        },
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'one',
    });
    await expect(
      f.iam.api.resources.registerMany(f.ownerCredential, {
        tenantId: f.tenantId,
        resources: [
          { type: 'folder', id: 'two' },
          { type: 'folder', id: 'three' },
        ],
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'two',
    });
    await expect(
      f.iam.api.resources.register(f.ownerCredential, {
        tenantId: f.tenantId,
        type: 'folder',
        id: 'three',
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    await f.iam.api.webhooks.create(f.ownerCredential, {
      tenantId: f.tenantId,
      url: 'https://hooks.example.test/a',
      events: ['*'],
    });
    await expect(
      f.iam.api.webhooks.create(f.ownerCredential, {
        tenantId: f.tenantId,
        url: 'https://hooks.example.test/b',
        events: ['*'],
      }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
    // Usage reflects the counts and the limits; deleting frees capacity; clearing limits lifts them.
    const usage = await f.iam.api.tenants.usage(f.ownerCredential, { tenantId: f.tenantId });
    expect(usage).toMatchObject({
      identities: 2,
      serviceAccounts: 1,
      groups: 1,
      roles: 2,
      policies: 1,
      resources: 2,
      webhooks: 1,
      limits: { identities: 2 },
    });
    expect(usage.activeSessions).toBeGreaterThanOrEqual(1);
    await f.iam.api.serviceAccounts.delete(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bot.id,
    });
    await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'bot2',
    });
    const cleared = await f.iam.api.tenants.setLimits(f.rootCredential, {
      tenantId: f.tenantId,
      limits: null,
    });
    expect(cleared.limits).toBeUndefined();
    await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      name: 'Bob',
    });
    const trail = await f.iam.api.audit.list(f.rootCredential, {
      tenantId: f.tenantId,
      action: 'tenant:limits',
    });
    expect(trail).toHaveLength(2);
  });

  it('filters webhook deliveries by outcome and resource pattern', async () => {
    const f = await fixture();
    const group = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team',
    });
    const denials = await f.iam.api.webhooks.create(f.ownerCredential, {
      tenantId: f.tenantId,
      url: 'https://hooks.example.test/denials',
      events: ['*'],
      outcomes: ['deny'],
    });
    await f.iam.api.webhooks.create(f.ownerCredential, {
      tenantId: f.tenantId,
      url: 'https://hooks.example.test/groups',
      events: ['iam:groups:*'],
      resources: [group.id],
    });
    await expect(
      f.iam.api.webhooks.create(f.ownerCredential, {
        tenantId: f.tenantId,
        url: 'https://hooks.example.test/bad',
        events: ['*'],
        outcomes: ['maybe'] as never,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const alice = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    const login = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Other' });
    await expect(
      f.iam.api.groups.delete({ token: login.token }, { tenantId: f.tenantId, groupId: group.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.auth.dispatchOutbox();
    const byUrl = (url: string) =>
      f.deliveries
        .filter((delivery) => delivery.url.endsWith(url))
        .map((delivery) => delivery.event);
    // The denial hook saw only the denied deletion; the group hook ignored the other group's creation (resource mismatch).
    expect(byUrl('/denials')).toEqual(['iam:groups:delete']);
    expect(byUrl('/groups')).toEqual(['iam:groups:delete']);
    // Clearing filters restores everything.
    await f.iam.api.webhooks.update(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: denials.webhook.id,
      outcomes: null,
    });
    await f.iam.api.groups.update(f.ownerCredential, {
      tenantId: f.tenantId,
      groupId: group.id,
      name: 'Team A',
    });
    await f.iam.auth.dispatchOutbox();
    expect(byUrl('/denials')).toContain('iam:groups:update');
    expect(alice.id).toBeTruthy();
  });
});
