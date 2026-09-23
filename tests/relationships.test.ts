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
  let clock = Date.now();
  const documents = new Map<string, { tenantId: string; title: string }>();
  const iam = betterIam({
    database,
    secret: 'relationships-test-secret-with-at-least-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
    },
    permissions: {
      mode: 'tenant-defined',
      resourceTypes: {
        folder: {
          managed: true,
          actions: ['folders:read', 'folders:share'],
          relations: ['viewer', 'editor', 'owner'],
        },
        file: {
          managed: true,
          parent: 'folder',
          actions: ['files:read', 'files:write'],
          relations: ['viewer', 'editor'],
        },
        note: { actions: ['notes:read'], relations: ['reader'] },
      },
    },
    async resolveResource(reference) {
      const note = documents.get(reference.id);
      if (!note || reference.type !== 'note') throw new Error('unknown');
      return { ...reference, attributes: { title: note.title } };
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
  return {
    iam,
    database,
    tenantId,
    ownerCredential,
    member,
    documents,
    advance: (ms: number) => {
      clock += ms;
    },
    now: () => clock,
  };
}

describe('relationship tuples', () => {
  it('grants access through held relations on the resource or its parent, for identities and groups, with expiry', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const team = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team',
    });
    await f.iam.api.groups.addMember(f.ownerCredential, {
      tenantId: f.tenantId,
      groupId: team.id,
      identityId: bob.identity.id,
    });
    const sharing = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Sharing',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['folders:read', 'files:read'],
            resources: ['*'],
            conditions: { ArrayContains: { 'resource.relations': ['viewer', 'editor', 'owner'] } },
          },
          {
            effect: 'allow',
            actions: ['files:read'],
            resources: ['file/*'],
            conditions: {
              ArrayContains: { 'resource.parentRelations': ['viewer', 'editor', 'owner'] },
            },
          },
          {
            effect: 'allow',
            actions: ['files:write'],
            resources: ['file/*'],
            conditions: { ArrayContains: { 'resource.relations': ['editor'] } },
          },
          {
            effect: 'allow',
            actions: ['folders:share', 'iam:relationships:create', 'iam:relationships:read'],
            resources: ['*'],
            conditions: { ArrayContains: { 'resource.relations': ['owner'] } },
          },
          {
            effect: 'allow',
            actions: ['iam:relationships:create'],
            resources: ['iam/file/*'],
            conditions: { ArrayContains: { 'resource.parentRelations': ['owner'] } },
          },
          {
            effect: 'allow',
            actions: ['notes:read'],
            resources: ['note/*'],
            conditions: { ArrayContains: { 'resource.relations': ['reader'] } },
          },
        ],
      },
    });
    for (const person of [alice, bob])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: sharing.id,
        subjectType: 'identity',
        subjectId: person.identity.id,
      });
    await f.iam.api.resources.registerMany(f.ownerCredential, {
      tenantId: f.tenantId,
      resources: [
        { type: 'folder', id: 'plans' },
        { type: 'file', id: 'roadmap', parentId: 'plans' },
        { type: 'folder', id: 'private' },
        { type: 'file', id: 'diary', parentId: 'private' },
      ],
    });
    const check = (
      who: { credential: { token: string } },
      action: string,
      type: string,
      id: string,
    ) =>
      f.iam.authorize({ ...who.credential, tenantId: f.tenantId, action, resource: { type, id } });
    expect((await check(alice, 'folders:read', 'folder', 'plans')).allowed).toBe(false);
    // Validation: undeclared relations, unknown types, unregistered managed resources, and wrong subjects.
    await expect(
      f.iam.api.relationships.create(f.ownerCredential, {
        tenantId: f.tenantId,
        type: 'folder',
        id: 'plans',
        relation: 'admin',
        subjectType: 'identity',
        subjectId: alice.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.relationships.create(f.ownerCredential, {
        tenantId: f.tenantId,
        type: 'nothing',
        id: 'x',
        relation: 'viewer',
        subjectType: 'identity',
        subjectId: alice.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
    await expect(
      f.iam.api.relationships.create(f.ownerCredential, {
        tenantId: f.tenantId,
        type: 'folder',
        id: 'missing',
        relation: 'viewer',
        subjectType: 'identity',
        subjectId: alice.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.relationships.create(f.ownerCredential, {
        tenantId: f.tenantId,
        type: 'folder',
        id: 'plans',
        relation: 'viewer',
        subjectType: 'identity',
        subjectId: 'nobody',
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Alice owns the folder; the team can view it. Relations flow to files through the parent.
    const ownerTuple = await f.iam.api.relationships.create(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'plans',
      relation: 'owner',
      subjectType: 'identity',
      subjectId: alice.identity.id,
    });
    await f.iam.api.relationships.create(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'plans',
      relation: 'viewer',
      subjectType: 'group',
      subjectId: team.id,
    });
    expect((await check(alice, 'folders:read', 'folder', 'plans')).allowed).toBe(true);
    expect((await check(alice, 'files:read', 'file', 'roadmap')).allowed).toBe(true);
    expect((await check(alice, 'files:write', 'file', 'roadmap')).allowed).toBe(false);
    expect((await check(bob, 'folders:read', 'folder', 'plans')).allowed).toBe(true);
    expect((await check(bob, 'files:read', 'file', 'roadmap')).allowed).toBe(true);
    expect((await check(bob, 'files:read', 'file', 'diary')).allowed).toBe(false);
    expect((await check(alice, 'folders:read', 'folder', 'private')).allowed).toBe(false);
    // The owner relation lets Alice share the folder herself; Bob cannot.
    await f.iam.api.relationships.create(alice.credential, {
      tenantId: f.tenantId,
      type: 'file',
      id: 'roadmap',
      relation: 'editor',
      subjectType: 'identity',
      subjectId: bob.identity.id,
    });
    await expect(
      f.iam.api.relationships.create(bob.credential, {
        tenantId: f.tenantId,
        type: 'folder',
        id: 'private',
        relation: 'viewer',
        subjectType: 'identity',
        subjectId: bob.identity.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await check(bob, 'files:write', 'file', 'roadmap')).allowed).toBe(true);
    // Reverse queries and listings see relationships.
    expect(
      (
        await f.iam.listAccessible({
          ...bob.credential,
          tenantId: f.tenantId,
          action: 'files:read',
          type: 'file',
        })
      ).resources.map((r) => r.resourceId),
    ).toEqual(['roadmap']);
    const onFolder = await f.iam.api.relationships.list(alice.credential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'plans',
    });
    expect(onFolder.map((tuple) => `${tuple.relation}:${tuple.subjectType}`).sort()).toEqual([
      'owner:identity',
      'viewer:group',
    ]);
    await expect(
      f.iam.api.relationships.list(bob.credential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (
        await f.iam.api.relationships.list(f.ownerCredential, {
          tenantId: f.tenantId,
          subjectType: 'identity',
          subjectId: bob.identity.id,
        })
      ).map((tuple) => tuple.relation),
    ).toEqual(['editor']);
    // Application-owned resources can carry relations too.
    f.documents.set('memo', { tenantId: f.tenantId, title: 'Memo' });
    expect((await check(alice, 'notes:read', 'note', 'memo')).allowed).toBe(false);
    await f.iam.api.relationships.create(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'note',
      id: 'memo',
      relation: 'reader',
      subjectType: 'identity',
      subjectId: alice.identity.id,
      expiresAt: f.now() + 60_000,
    });
    expect((await check(alice, 'notes:read', 'note', 'memo')).allowed).toBe(true);
    f.advance(61_000);
    expect((await check(alice, 'notes:read', 'note', 'memo')).allowed).toBe(false);
    // Deleting a tuple, a group, or a resource removes the access it carried.
    await expect(
      f.iam.api.relationships.delete(bob.credential, {
        tenantId: f.tenantId,
        relationshipId: ownerTuple.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.api.relationships.delete(f.ownerCredential, {
      tenantId: f.tenantId,
      relationshipId: ownerTuple.id,
    });
    expect((await check(alice, 'folders:read', 'folder', 'plans')).allowed).toBe(false);
    await f.iam.api.groups.delete(f.ownerCredential, { tenantId: f.tenantId, groupId: team.id });
    expect((await check(bob, 'folders:read', 'folder', 'plans')).allowed).toBe(false);
    expect((await check(bob, 'files:write', 'file', 'roadmap')).allowed).toBe(true);
    await f.iam.api.resources.delete(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'file',
      id: 'roadmap',
    });
    expect(await f.database.find('relationships', { tenantId: f.tenantId, type: 'file' })).toEqual(
      [],
    );
    // Tenant-defined types declare relations too, and a relation in use cannot be dropped.
    const ticket = await f.iam.api.resourceTypes.register(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ticket',
      actions: ['read'],
      relations: ['assignee'],
    });
    expect(ticket.relations).toEqual(['assignee']);
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'ticket',
      id: 't1',
    });
    await f.iam.api.relationships.create(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'ticket',
      id: 't1',
      relation: 'assignee',
      subjectType: 'identity',
      subjectId: alice.identity.id,
    });
    await expect(
      f.iam.api.resourceTypes.update(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'ticket',
        relations: [],
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    expect(
      (
        await f.iam.api.resourceTypes.update(f.ownerCredential, {
          tenantId: f.tenantId,
          name: 'ticket',
          relations: ['assignee', 'watcher'],
        })
      ).relations,
    ).toEqual(['assignee', 'watcher']);
    await expect(
      f.iam.api.resourceTypes.register(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'bad',
        relations: ['Not Valid'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
