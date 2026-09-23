import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { IamError, type IamPlugin, type IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

/** A plugin that contributes a resource type, trusted context, hooks, and a delivery-sending endpoint. */
function reviewPlugin(log: string[]): IamPlugin {
  return {
    id: 'reviews',
    actions: ['reviews:write'],
    resourceTypes: {
      review: { managed: true, actions: ['reviews:read'], attributes: { stars: 'number' } },
    },
    async resolveContext(principal) {
      return { 'principal.reviewer': principal.identity.name.startsWith('Rev') };
    },
    hooks: {
      async beforeOperation({ action }) {
        log.push(`before:${action}`);
        if (action === 'iam:groups:delete') throw new IamError('BLOCKED', 'Groups are kept');
      },
      async afterOperation({ action }) {
        log.push(`after:${action}`);
      },
    },
    endpoints: [
      {
        method: 'POST',
        path: 'notify',
        action: 'reviews:write',
        validate(value) {
          const input = value as Record<string, unknown>;
          return { tenantId: input.tenantId, to: String(input.to) };
        },
        async handler({ deliver, tenantId }, input) {
          const id = await deliver({
            kind: 'email',
            to: String(input.to),
            template: 'review-request',
            payload: { tenantId },
          });
          return { queued: id };
        },
      },
    ],
  };
}

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const log: string[] = [];
  const iam = betterIam({
    database,
    secret: 'attributes-test-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    plugins: [reviewPlugin(log)],
    permissions: {
      identityAttributes: { department: 'string', clearance: 'number', contractor: 'boolean' },
      resourceTypes: {
        document: {
          managed: true,
          actions: ['documents:read'],
          attributes: { department: 'string', clearance: 'number' },
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
  const member = async (name: string) => {
    const identity = await iam.api.identities.create(ownerCredential, {
      tenantId,
      email: `${name}@acme.test`,
      name,
      password: `a strong ${name} password`,
    });
    const login = await iam.api.auth.signIn({
      tenantId,
      email: `${name}@acme.test`,
      password: `a strong ${name} password`,
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    return { identity, credential: { token: login.token } };
  };
  return { iam, database, root, credential, tenantId, ownerCredential, member, inbox, log };
}

describe('identity attributes and principal context', () => {
  it('exposes declared attributes, groups, roles, and kind to conditions and variables', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    await expect(
      f.iam.api.identities.update(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.identity.id,
        attributes: { department: 'finance', clearance: 'high' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.identities.update(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.identity.id,
        attributes: { level: 1 },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.identities.update(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const updated = await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.identity.id,
      attributes: { department: 'finance', clearance: 3, contractor: false },
    });
    expect(updated.attributes).toEqual({ department: 'finance', clearance: 3, contractor: false });
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bob.identity.id,
      name: 'Bob',
      attributes: { department: 'finance', clearance: 1, contractor: true },
    });
    const auditors = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Auditors',
    });
    await f.iam.api.groups.addMember(f.ownerCredential, {
      tenantId: f.tenantId,
      groupId: auditors.id,
      identityId: alice.identity.id,
    });
    const reader = await f.iam.api.roles
      .create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Department reader',
        document: {
          version: 1,
          statements: [
            {
              sid: 'SameDepartment',
              effect: 'allow',
              actions: ['documents:read'],
              resources: ['document/*'],
              conditions: {
                StringEquals: { 'resource.department': '${principal.department}' },
                NumericLessThanEquals: { 'resource.clearance': '${principal.clearance}' as never },
              },
            },
          ],
        },
      })
      .catch((error: IamError) => error);
    // Variables are strings; numeric comparisons need literal numbers, so the second condition is rejected.
    expect(reader).toMatchObject({ code: 'INVALID_POLICY' });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Department reader',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/*'],
            conditions: {
              StringEquals: { 'resource.department': '${principal.department}' },
              Bool: { 'principal.contractor': false },
              NumericGreaterThanEquals: { 'principal.clearance': 2 },
            },
          },
          {
            effect: 'allow',
            actions: ['reviews:read'],
            resources: ['review/*'],
            conditions: { ArrayContains: { 'principal.groups': [auditors.id] } },
          },
          {
            effect: 'deny',
            actions: ['documents:read'],
            resources: ['document/board-*'],
            conditions: { StringEquals: { 'principal.kind': 'service' } },
          },
        ],
      },
    });
    for (const person of [alice, bob])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: person.identity.id,
      });
    await f.iam.api.resources.registerMany(f.ownerCredential, {
      tenantId: f.tenantId,
      resources: [
        { type: 'document', id: 'budget', attributes: { department: 'finance', clearance: 2 } },
        { type: 'document', id: 'roadmap', attributes: { department: 'product', clearance: 1 } },
        { type: 'review', id: 'q3', attributes: { stars: 4 } },
      ],
    });
    const check = (
      who: { credential: { token: string } },
      action: string,
      type: string,
      id: string,
    ) =>
      f.iam.authorize({ ...who.credential, tenantId: f.tenantId, action, resource: { type, id } });
    expect((await check(alice, 'documents:read', 'document', 'budget')).allowed).toBe(true);
    expect((await check(alice, 'documents:read', 'document', 'roadmap')).allowed).toBe(false);
    // Bob is a contractor with low clearance in the same department.
    expect((await check(bob, 'documents:read', 'document', 'budget')).allowed).toBe(false);
    // Group membership is visible as principal.groups; the plugin's review type is in the catalog.
    expect((await check(alice, 'reviews:read', 'review', 'q3')).allowed).toBe(true);
    expect((await check(bob, 'reviews:read', 'review', 'q3')).allowed).toBe(false);
    // The simulation API sees the same principal context, including roles.
    const simulated = await f.iam.api.policies.simulate(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.identity.id,
      action: 'documents:read',
      resource: { type: 'document', id: 'budget' },
    });
    expect(simulated.allowed).toBe(true);
    expect(
      (
        await f.iam.listAccessible({
          ...alice.credential,
          tenantId: f.tenantId,
          action: 'documents:read',
          type: 'document',
        })
      ).resources.map((resource) => resource.resourceId),
    ).toEqual(['budget']);
    // A service account carries principal.kind = service; deny statements can single it out.
    const bot = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'bot',
    });
    await f.iam.api.serviceAccounts.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bot.id,
      attributes: { department: 'finance', clearance: 5, contractor: false },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: bot.id,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bot.id,
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'document',
      id: 'board-minutes',
      attributes: { department: 'finance', clearance: 1 },
    });
    expect(
      (await check({ credential: { token: key.token } }, 'documents:read', 'document', 'budget'))
        .allowed,
    ).toBe(true);
    expect(
      (
        await check(
          { credential: { token: key.token } },
          'documents:read',
          'document',
          'board-minutes',
        )
      ).allowed,
    ).toBe(false);
    expect((await check(alice, 'documents:read', 'document', 'board-minutes')).allowed).toBe(true);
  });

  it('rejects identity attribute schemas that shadow built-in principal keys or repeat resource types', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    const base = {
      database,
      secret: 'attributes-test-secret-with-at-least-32-characters',
      baseURL: 'http://localhost:3000',
    };
    expect(() =>
      betterIam({ ...base, permissions: { identityAttributes: { groups: 'string' } } }),
    ).toThrow(/principal\.groups/u);
    expect(() =>
      betterIam({ ...base, permissions: { identityAttributes: { level: 'bigint' as 'number' } } }),
    ).toThrow(/string, number, or boolean/u);
    expect(() =>
      betterIam({
        ...base,
        permissions: { resourceTypes: { review: {} } },
        plugins: [reviewPlugin([])],
      }),
    ).toThrow(/declared more than once/u);
  });
});

describe('plugin hooks, context, and deliveries', () => {
  it('runs before/after hooks inside the operation, lets a hook abort, merges plugin context, and queues deliveries', async () => {
    const f = await fixture();
    const reviewer = await f.member('Reviewer');
    f.log.length = 0;
    const group = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Kept',
    });
    expect(f.log).toEqual(['before:iam:groups:create', 'after:iam:groups:create']);
    await expect(
      f.iam.api.groups.delete(f.ownerCredential, { tenantId: f.tenantId, groupId: group.id }),
    ).rejects.toMatchObject({ code: 'BLOCKED' });
    expect(
      (await f.iam.api.groups.list(f.ownerCredential, { tenantId: f.tenantId })).map(
        (item) => item.id,
      ),
    ).toEqual([group.id]);
    // A hook abort rolls the whole operation back, so no audit event was written for it either.
    expect(
      (
        await f.iam.api.audit.list(f.ownerCredential, {
          tenantId: f.tenantId,
          action: 'iam:groups:delete',
        })
      ).length,
    ).toBe(0);
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reviewers',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['reviews:*'],
            resources: ['*'],
            conditions: { Bool: { 'principal.reviewer': true } },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: reviewer.identity.id,
    });
    const alice = await f.member('alice');
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.identity.id,
    });
    const result = (await f.iam.callPlugin(reviewer.credential, {
      pluginId: 'reviews',
      path: 'notify',
      tenantId: f.tenantId,
      input: { to: 'author@acme.test' },
    })) as { queued: string };
    expect(result.queued).toMatch(/^out_/u);
    await expect(
      f.iam.callPlugin(alice.credential, {
        pluginId: 'reviews',
        path: 'notify',
        tenantId: f.tenantId,
        input: { to: 'x@acme.test' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.auth.dispatchOutbox();
    const delivered = f.inbox.find((message) => message.template === 'review-request');
    expect(delivered).toMatchObject({
      id: result.queued,
      to: 'author@acme.test',
      tenantId: f.tenantId,
      payload: { tenantId: f.tenantId },
    });
  });
});
