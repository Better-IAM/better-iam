import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type WebhookDelivery } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createIamNext } from '@better-iam/next';
import { verifyAssertion } from '@better-iam/server';
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
  let reject = false;
  const iam = betterIam({
    database,
    secret: 'bulk-redelivery-test-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      maxDeliveryAttempts: 1,
    },
    events: {
      deliverWebhook: async (delivery) => {
        if (reject) throw new Error('endpoint down');
        deliveries.push(delivery);
      },
    },
    permissions: {
      identityAttributes: { department: 'string' },
      actions: ['documents:read'],
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
  const created = await iam.api.tenants.create(
    { token: session.token },
    {
      parentId: root.tenant.id,
      name: 'Acme',
      type: 'organization',
      ownerEmail: 'owner@acme.test',
    },
  );
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
    tenantId: created.tenant.id,
    owner,
    ownerCredential: { token: owner.token },
    deliveries,
    setReject: (value: boolean) => {
      reject = value;
    },
  };
}

describe('bulk onboarding, webhook redelivery, and Next assertions', () => {
  it('creates identities in one transaction with attributes, roles, and groups', async () => {
    const f = await fixture();
    const readers = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const team = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team',
    });
    await expect(
      f.iam.api.identities.createMany(f.ownerCredential, { tenantId: f.tenantId, identities: [] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // A bad row rejects the whole batch: nothing is created.
    await expect(
      f.iam.api.identities.createMany(f.ownerCredential, {
        tenantId: f.tenantId,
        identities: [
          { email: 'alice@acme.test', name: 'Alice' },
          { email: 'bob@acme.test', name: 'Bob', attributes: { floor: 3 } },
        ],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      (await f.iam.api.identities.list(f.ownerCredential, { tenantId: f.tenantId })).map(
        (identity) => identity.email,
      ),
    ).toEqual(['owner@acme.test']);
    const result = await f.iam.api.identities.createMany(f.ownerCredential, {
      tenantId: f.tenantId,
      identities: [
        {
          email: 'alice@acme.test',
          name: 'Alice',
          password: 'a strong alice password',
          attributes: { department: 'finance' },
          roleIds: [readers.id],
          groupIds: [team.id],
        },
        { email: 'bob@acme.test', name: 'Bob', roleIds: [readers.id, readers.id] },
      ],
    });
    expect(result.identities.map((identity) => identity.email)).toEqual([
      'alice@acme.test',
      'bob@acme.test',
    ]);
    expect(result.identities[0]!.attributes).toEqual({ department: 'finance' });
    const bindings = await f.iam.api.identities.listBindings(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: result.identities[1]!.id,
    });
    expect(bindings.map((binding) => binding.roleId)).toEqual([readers.id]);
    expect(
      (
        await f.iam.api.identities.listGroups(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: result.identities[0]!.id,
        })
      ).map((group) => group.name),
    ).toEqual(['Team']);
    const login = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    expect('token' in login).toBe(true);
    // Duplicates within the batch or against existing members roll everything back.
    await expect(
      f.iam.api.identities.createMany(f.ownerCredential, {
        tenantId: f.tenantId,
        identities: [
          { email: 'carol@acme.test', name: 'Carol' },
          { email: 'alice@acme.test', name: 'Alice again' },
        ],
      }),
    ).rejects.toMatchObject({ code: 'IDENTITY_EXISTS' });
    expect(
      (await f.iam.api.identities.list(f.ownerCredential, { tenantId: f.tenantId })).some(
        (identity) => identity.email === 'carol@acme.test',
      ),
    ).toBe(false);
  });

  it('redelivers a webhook event from its audit record', async () => {
    const f = await fixture();
    const { webhook } = await f.iam.api.webhooks.create(f.ownerCredential, {
      tenantId: f.tenantId,
      url: 'https://hooks.example.test/iam',
      events: ['iam:groups:*'],
    });
    f.setReject(true);
    const group = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team',
    });
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({ failed: 1, abandoned: 1 });
    const history = await f.iam.api.webhooks.listDeliveries(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
    });
    const failed = history.find((item) => item.event === 'iam:groups:create')!;
    expect(failed.status).toBe('failed');
    expect(typeof failed.eventId).toBe('string');
    f.setReject(false);
    const queued = await f.iam.api.webhooks.redeliver(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
      deliveryId: failed.id,
    });
    expect(queued.eventId).toBe(failed.eventId);
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({ delivered: 1 });
    const replayed = f.deliveries.find((delivery) => delivery.id === queued.deliveryId)!;
    const body = JSON.parse(replayed.body) as { id: string; type: string; resourceId: string };
    expect(body).toMatchObject({
      id: failed.eventId,
      type: 'iam:groups:create',
      resourceId: f.tenantId,
    });
    expect(group.id).toBeTruthy();
    await expect(
      f.iam.api.webhooks.redeliver(f.ownerCredential, {
        tenantId: f.tenantId,
        webhookId: webhook.id,
        deliveryId: 'out_missing',
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });

  it('issues assertions from Next.js server helpers', async () => {
    const f = await fixture();
    const iamNext = createIamNext(() => f.iam, {
      headers: () => new Headers({ authorization: `Bearer ${f.owner.token}` }),
    });
    const issued = await iamNext.assertion({ tenantId: f.tenantId, audience: 'reports' });
    expect(issued.claims.sub).toBe(f.owner.identity.id);
    expect(
      verifyAssertion(issued.token, { key: f.iam.assertionKey(), audience: 'reports' }).tid,
    ).toBe(f.tenantId);
    await expect(
      iamNext.assertion({ tenantId: f.tenantId, audience: 'reports', headers: new Headers() }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });
});
