import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
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
  const iam = betterIam({
    database,
    secret: 'reviews-test-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    permissions: {
      resourceTypes: {
        folder: {
          managed: true,
          actions: ['folders:read', 'folders:write'],
          relations: ['viewer', 'editor'],
        },
      },
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
  const tenantId = created.tenant.id;
  const ownerCredential = { token: owner.token };
  const member = async (name: string) =>
    iam.api.identities.create(ownerCredential, {
      tenantId,
      email: `${name}@acme.test`,
      name,
      password: `a strong ${name} password`,
    });
  return { iam, root, credential, tenantId, ownerCredential, owner, member };
}

describe('access reviews', () => {
  it('lists who can perform an action on a resource and which actions an identity holds there', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const bot = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'bot',
    });
    const readers = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers',
      permissions: ['folders:read'],
    });
    const mfaWriters = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'MFA writers',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['folders:write'],
            resources: ['folder/*'],
            conditions: { Bool: { 'principal.mfa': true } },
          },
        ],
      },
    });
    const sharing = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Sharing',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['folders:read'],
            resources: ['folder/*'],
            conditions: { ArrayContains: { 'resource.relations': ['viewer', 'editor'] } },
          },
        ],
      },
    });
    const bind = (roleId: string, subjectId: string) =>
      f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId,
        subjectType: 'identity',
        subjectId,
      });
    await bind(readers.id, alice.id);
    await bind(mfaWriters.id, alice.id);
    await bind(readers.id, bot.id);
    await bind(sharing.id, carol.id);
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'plans',
    });
    await f.iam.api.relationships.create(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'plans',
      relation: 'viewer',
      subjectType: 'identity',
      subjectId: carol.id,
    });
    // Who can read: owner (Owner role), alice (Readers), bot (Readers), carol (relation). Bob cannot.
    const readersOfPlans = await f.iam.api.policies.whoCan(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'folders:read',
      resource: { type: 'folder', id: 'plans' },
    });
    expect(readersOfPlans.total).toBe(4);
    expect(readersOfPlans.identities.map((item) => item.name).sort()).toEqual([
      'Owner',
      'alice',
      'bot',
      'carol',
    ]);
    expect(readersOfPlans.identities.every((item) => item.reason === 'allowed')).toBe(true);
    expect(readersOfPlans.identities.map((item) => item.identityId)).not.toContain(bob.id);
    // Filters and pagination.
    const people = await f.iam.api.policies.whoCan(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'folders:read',
      resource: { type: 'folder', id: 'plans' },
      kind: 'user',
      limit: 2,
    });
    expect(people.total).toBe(3);
    expect(people.identities).toHaveLength(2);
    // Writing needs MFA: nobody without a simulated MFA session, alice and the owner with one.
    const writers = await f.iam.api.policies.whoCan(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'folders:write',
      resource: { type: 'folder', id: 'plans' },
    });
    expect(writers.identities.map((item) => item.name)).toEqual(['Owner']);
    const mfaWritersReview = await f.iam.api.policies.whoCan(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'folders:write',
      resource: { type: 'folder', id: 'plans' },
      assumeMfa: true,
    });
    expect(mfaWritersReview.identities.map((item) => item.name).sort()).toEqual(['Owner', 'alice']);
    // Unknown actions and unregistered resources are rejected; reviews need iam:policies:simulate.
    await expect(
      f.iam.api.policies.whoCan(f.ownerCredential, {
        tenantId: f.tenantId,
        action: 'folders:burn',
        resource: { type: 'folder', id: 'plans' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    await expect(
      f.iam.api.policies.whoCan(f.ownerCredential, {
        tenantId: f.tenantId,
        action: 'folders:read',
        resource: { type: 'folder', id: 'missing' },
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const aliceLogin = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in aliceLogin)) throw new Error('Unexpected MFA');
    await expect(
      f.iam.api.policies.whoCan(
        { token: aliceLogin.token },
        {
          tenantId: f.tenantId,
          action: 'folders:read',
          resource: { type: 'folder', id: 'plans' },
        },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Effective actions of one identity on the resource, over the whole catalog or a chosen list.
    const aliceActions = await f.iam.api.policies.effectiveActions(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      resource: { type: 'folder', id: 'plans' },
    });
    expect(aliceActions.allowed).toEqual(['folders:read']);
    expect(aliceActions.results.length).toBeGreaterThan(50);
    expect(aliceActions.results.find((item) => item.action === 'iam:tenants:read')).toMatchObject({
      allowed: false,
      reason: 'NO_APPLICABLE_GRANT',
    });
    const aliceWithMfa = await f.iam.api.policies.effectiveActions(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      resource: { type: 'folder', id: 'plans' },
      actions: ['folders:read', 'folders:write', 'iam:groups:read'],
      assumeMfa: true,
    });
    expect(aliceWithMfa.allowed).toEqual(['folders:read', 'folders:write']);
    expect(aliceWithMfa.results.map((item) => item.action)).toEqual([
      'folders:read',
      'folders:write',
      'iam:groups:read',
    ]);
    await expect(
      f.iam.api.policies.effectiveActions(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.id,
        resource: { type: 'folder', id: 'plans' },
        actions: ['nothing:here'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    // The owner holds everything through the protected Owner role.
    const ownerActions = await f.iam.api.policies.effectiveActions(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: f.owner.identity.id,
      resource: { type: 'folder', id: 'plans' },
      actions: ['folders:read', 'folders:write', 'iam:policies:simulate'],
    });
    expect(ownerActions.allowed).toEqual([
      'folders:read',
      'folders:write',
      'iam:policies:simulate',
    ]);
    // Reviews are audited like other administrative reads.
    const audit = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'iam:policies:simulate',
    });
    expect(audit.length).toBeGreaterThanOrEqual(6);
  });
});
