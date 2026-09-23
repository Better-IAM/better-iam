import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createIamClient } from '@better-iam/client';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

/** A product with managed documents whose owner is recorded in the registry, plus an injectable clock. */
async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'access-test-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
    },
    accessRequests: { lifetimeMs: 60 * 60_000 },
    permissions: {
      mode: 'tenant-defined',
      resourceTypes: {
        document: {
          managed: true,
          actions: ['documents:read', 'documents:write'],
          attributes: { classification: 'string' },
        },
        folder: { managed: true, actions: ['folders:read'] },
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
  const member = async (name: string, permissions: string[] = []) => {
    const identity = await iam.api.identities.create(ownerCredential, {
      tenantId,
      email: `${name}@acme.test`,
      name,
      password: `a strong ${name} password`,
    });
    if (permissions.length) {
      const role = await iam.api.roles.create(ownerCredential, {
        tenantId,
        name: `${name} base`,
        permissions,
      });
      await iam.api.bindings.create(ownerCredential, {
        tenantId,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: identity.id,
      });
    }
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
    root,
    credential,
    tenantId,
    owner,
    ownerCredential,
    member,
    advance: (ms: number) => {
      clock += ms;
    },
    now: () => clock,
  };
}

describe('policy variables through the server', () => {
  it('lets a role grant access to the resources a principal owns without an application resolver', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const owners = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Document owners',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read', 'documents:write'],
            resources: ['document/*'],
            conditions: { StringEquals: { 'resource.ownerId': '${principal.id}' } },
          },
          {
            effect: 'allow',
            actions: ['folders:read'],
            resources: ['folder/home-${principal.id}'],
          },
        ],
      },
    });
    for (const person of [alice, bob])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: owners.id,
        subjectType: 'identity',
        subjectId: person.identity.id,
      });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'document',
      id: 'alice-notes',
      ownerId: alice.identity.id,
      attributes: { classification: 'internal' },
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'document',
      id: 'bob-notes',
      ownerId: bob.identity.id,
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: `home-${alice.identity.id}`,
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'home-*',
    });
    const check = (
      who: { credential: { token: string } },
      action: string,
      type: string,
      id: string,
    ) =>
      f.iam.authorize({ ...who.credential, tenantId: f.tenantId, action, resource: { type, id } });
    expect((await check(alice, 'documents:write', 'document', 'alice-notes')).allowed).toBe(true);
    expect((await check(alice, 'documents:read', 'document', 'bob-notes')).allowed).toBe(false);
    expect((await check(bob, 'documents:write', 'document', 'bob-notes')).allowed).toBe(true);
    expect(
      (await check(alice, 'folders:read', 'folder', `home-${alice.identity.id}`)).allowed,
    ).toBe(true);
    expect((await check(bob, 'folders:read', 'folder', `home-${alice.identity.id}`)).allowed).toBe(
      false,
    );
    // A registered id that happens to contain a wildcard never matches a substituted variable.
    expect((await check(alice, 'folders:read', 'folder', 'home-*')).allowed).toBe(false);
    await expect(
      f.iam.api.roles.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Broken',
        document: {
          version: 1,
          statements: [
            {
              effect: 'allow',
              actions: ['documents:read'],
              resources: ['document/${principal.id'],
            },
          ],
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_POLICY' });
  });
});

describe('reverse queries', () => {
  it('lists the registered resources a principal may act on, evaluating grants once per query', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const reader = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Public reader',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/*'],
            conditions: { StringEquals: { 'resource.classification': 'public' } },
          },
          {
            effect: 'allow',
            actions: ['documents:*'],
            resources: ['document/*'],
            conditions: { StringEquals: { 'resource.ownerId': '${principal.id}' } },
          },
          { effect: 'deny', actions: ['documents:read'], resources: ['document/embargoed'] },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.identity.id,
    });
    await f.iam.api.resources.registerMany(f.ownerCredential, {
      tenantId: f.tenantId,
      resources: [
        { type: 'document', id: 'brochure', attributes: { classification: 'public' } },
        { type: 'document', id: 'embargoed', attributes: { classification: 'public' } },
        { type: 'document', id: 'plan', attributes: { classification: 'internal' } },
        {
          type: 'document',
          id: 'mine',
          attributes: { classification: 'internal' },
          ownerId: alice.identity.id,
        },
      ],
    });
    const readable = await f.iam.listAccessible({
      ...alice.credential,
      tenantId: f.tenantId,
      action: 'documents:read',
      type: 'document',
    });
    expect(readable.resources.map((resource) => resource.resourceId)).toEqual(['brochure', 'mine']);
    expect(readable.total).toBe(2);
    const writable = await f.iam.listAccessible({
      ...alice.credential,
      tenantId: f.tenantId,
      action: 'documents:write',
      type: 'document',
    });
    expect(writable.resources.map((resource) => resource.resourceId)).toEqual(['mine']);
    const paged = await f.iam.listAccessible({
      ...alice.credential,
      tenantId: f.tenantId,
      action: 'documents:read',
      type: 'document',
      limit: 1,
      offset: 1,
    });
    expect(paged.resources.map((resource) => resource.resourceId)).toEqual(['mine']);
    expect(paged.total).toBe(2);
    const everything = await f.iam.listAccessible({
      ...f.ownerCredential,
      tenantId: f.tenantId,
      action: 'documents:read',
      type: 'document',
    });
    expect(everything.total).toBe(4);
    expect(
      (
        await f.iam.listAccessible({
          ...f.credential,
          tenantId: f.tenantId,
          action: 'documents:read',
          type: 'document',
        })
      ).total,
    ).toBe(4);
    await expect(
      f.iam.listAccessible({
        ...alice.credential,
        tenantId: f.tenantId,
        action: 'documents:read',
        type: 'iam',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_RESOURCE_TYPE' });
    await expect(
      f.iam.listAccessible({
        ...alice.credential,
        tenantId: f.tenantId,
        action: 'documents:shred',
        type: 'document',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    await expect(
      f.iam.listAccessible({ tenantId: f.tenantId, action: 'documents:read', type: 'document' }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    // The typed client reaches the same route.
    const client = createIamClient<typeof f.iam>({
      baseURL: 'http://localhost:3000',
      token: alice.credential.token,
      fetch: async (input, init) => f.iam.handler(new Request(input, init)),
    });
    expect(
      (
        await client.listAccessible({
          tenantId: f.tenantId,
          action: 'documents:read',
          type: 'document',
        })
      ).resources.map((resource) => resource.resourceId),
    ).toEqual(['brochure', 'mine']);
  });

  it('registers batches atomically and denies the whole batch when one item is not permitted', async () => {
    const f = await fixture();
    const limited = await f.member('limited');
    const registrar = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Folder registrar',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['iam:resources:create'], resources: ['iam/folder/*'] },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: registrar.id,
      subjectType: 'identity',
      subjectId: limited.identity.id,
    });
    await expect(
      f.iam.api.resources.registerMany(limited.credential, {
        tenantId: f.tenantId,
        resources: [
          { type: 'folder', id: 'ok' },
          { type: 'document', id: 'nope' },
        ],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(await f.iam.api.resources.list(f.ownerCredential, { tenantId: f.tenantId })).toEqual([]);
    const result = await f.iam.api.resources.registerMany(limited.credential, {
      tenantId: f.tenantId,
      resources: [
        { type: 'folder', id: 'one' },
        { type: 'folder', id: 'two' },
      ],
    });
    expect(result.resources.map((resource) => resource.resourceId)).toEqual(['one', 'two']);
    await expect(
      f.iam.api.resources.registerMany(limited.credential, {
        tenantId: f.tenantId,
        resources: [
          { type: 'folder', id: 'three' },
          { type: 'folder', id: 'one' },
        ],
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(
      (await f.iam.api.resources.list(f.ownerCredential, { tenantId: f.tenantId })).map(
        (resource) => resource.resourceId,
      ),
    ).toEqual(['one', 'two']);
    await expect(
      f.iam.api.resources.registerMany(f.ownerCredential, { tenantId: f.tenantId, resources: [] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const denied = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      outcome: 'deny',
      action: 'iam:resources:create',
    });
    expect(denied.map((event) => event.resourceId)).toEqual(['document/nope']);
  });
});

describe('temporary bindings', () => {
  it('grants nothing once expired, hides expired bindings from effective views, and is swept by the purge worker', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const editor = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Editor',
      permissions: ['documents:read', 'documents:write'],
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'document',
      id: 'spec',
    });
    await expect(
      f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: editor.id,
        subjectType: 'identity',
        subjectId: alice.identity.id,
        expiresAt: f.now() - 1,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: editor.id,
        subjectType: 'identity',
        subjectId: alice.identity.id,
        expiresAt: f.now() + 11 * 365 * 86400000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const binding = await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: editor.id,
      subjectType: 'identity',
      subjectId: alice.identity.id,
      expiresAt: f.now() + 60 * 60_000,
    });
    expect(binding.expiresAt).toBe(f.now() + 60 * 60_000);
    const check = () =>
      f.iam.authorize({
        ...alice.credential,
        tenantId: f.tenantId,
        action: 'documents:write',
        resource: { type: 'document', id: 'spec' },
      });
    expect((await check()).allowed).toBe(true);
    expect(
      (
        await f.iam.api.identities.listBindings(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: alice.identity.id,
        })
      ).map((item) => item.role?.name),
    ).toEqual(['Editor']);
    f.advance(61 * 60_000);
    expect((await check()).allowed).toBe(false);
    expect(
      await f.iam.api.identities.listBindings(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.identity.id,
      }),
    ).toEqual([]);
    expect(
      await f.iam.api.roles.listBindings(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: editor.id,
      }),
    ).toEqual([]);
    expect(
      await f.iam.api.bindings.list(f.ownerCredential, { tenantId: f.tenantId, roleId: editor.id }),
    ).toEqual([]);
    expect(
      (
        await f.iam.api.bindings.list(f.ownerCredential, {
          tenantId: f.tenantId,
          roleId: editor.id,
          includeExpired: true,
        })
      ).map((item) => item.id),
    ).toEqual([binding.id]);
    // Extending an expired binding revives it; clearing the expiry makes it standing.
    const extended = await f.iam.api.bindings.update(f.ownerCredential, {
      tenantId: f.tenantId,
      bindingId: binding.id,
      expiresAt: f.now() + 5 * 60_000,
    });
    expect(extended.expiresAt).toBe(f.now() + 5 * 60_000);
    expect((await check()).allowed).toBe(true);
    await expect(
      f.iam.api.bindings.update(alice.credential, {
        tenantId: f.tenantId,
        bindingId: binding.id,
        expiresAt: null,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const standing = await f.iam.api.bindings.update(f.ownerCredential, {
      tenantId: f.tenantId,
      bindingId: binding.id,
      expiresAt: null,
    });
    expect(standing).not.toHaveProperty('expiresAt');
    f.advance(2 * 60 * 60_000);
    expect((await check()).allowed).toBe(true);
    await f.iam.api.bindings.update(f.ownerCredential, {
      tenantId: f.tenantId,
      bindingId: binding.id,
      expiresAt: f.now() + 1000,
    });
    f.advance(2000);
    const purge = await f.iam.purgeDeleted();
    expect(purge).toMatchObject({
      purgedTenants: [],
      deletedRecords: 0,
      expiredBindings: 1,
      expiredRequests: 0,
    });
    expect(await f.database.get('bindings', binding.id)).toBeUndefined();
    await expect(
      f.iam.api.bindings.update(f.ownerCredential, {
        tenantId: f.tenantId,
        bindingId: binding.id,
        expiresAt: null,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('access requests', () => {
  it('lets members request roles that a reviewer approves under their own authority as temporary bindings', async () => {
    const f = await fixture();
    const alice = await f.member('alice', ['iam:access-requests:create']);
    const reviewer = await f.member('reviewer', [
      'iam:access-requests:read',
      'iam:access-requests:review',
      'iam:bindings:create',
      'iam:roles:read',
    ]);
    const admin = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Document admin',
      permissions: ['documents:read', 'documents:write'],
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'document',
      id: 'runbook',
    });
    const ownerRole = (
      await f.iam.api.roles.list(f.ownerCredential, { tenantId: f.tenantId })
    ).find((role) => role.protected)!;
    await expect(
      f.iam.api.accessRequests.create(alice.credential, {
        tenantId: f.tenantId,
        roleIds: [ownerRole.id],
      }),
    ).rejects.toMatchObject({ code: 'PROTECTED_RESOURCE' });
    await expect(
      f.iam.api.accessRequests.create(alice.credential, { tenantId: f.tenantId, roleIds: [] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.accessRequests.create(alice.credential, {
        tenantId: f.tenantId,
        roleIds: [admin.id],
        durationSeconds: 10,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.accessRequests.create(reviewer.credential, {
        tenantId: f.tenantId,
        roleIds: [admin.id],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const request = await f.iam.api.accessRequests.create(alice.credential, {
      tenantId: f.tenantId,
      roleIds: [admin.id],
      justification: 'Incident 42',
      durationSeconds: 2 * 3600,
    });
    expect(request).toMatchObject({
      status: 'pending',
      requesterId: alice.identity.id,
      roleIds: [admin.id],
      durationSeconds: 7200,
      justification: 'Incident 42',
    });
    await expect(
      f.iam.api.accessRequests.create(alice.credential, {
        tenantId: f.tenantId,
        roleIds: [admin.id],
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(
      (await f.iam.api.accessRequests.listMine(alice.credential, { tenantId: f.tenantId })).map(
        (item) => item.id,
      ),
    ).toEqual([request.id]);
    await expect(
      f.iam.api.accessRequests.list(alice.credential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (
        await f.iam.api.accessRequests.list(reviewer.credential, {
          tenantId: f.tenantId,
          status: 'pending',
        })
      ).map((item) => item.id),
    ).toEqual([request.id]);
    const check = () =>
      f.iam.authorize({
        ...alice.credential,
        tenantId: f.tenantId,
        action: 'documents:write',
        resource: { type: 'document', id: 'runbook' },
      });
    expect((await check()).allowed).toBe(false);
    // A requester cannot approve their own request even with review permission, and a reviewer needs a grant authority.
    await expect(
      f.iam.api.accessRequests.approve(alice.credential, {
        tenantId: f.tenantId,
        requestId: request.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.accessRequests.approve(reviewer.credential, {
        tenantId: f.tenantId,
        requestId: request.id,
      }),
    ).rejects.toMatchObject({ code: 'GRANT_AUTHORITY_REQUIRED' });
    await f.iam.api.authorities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: reviewer.identity.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
      },
    });
    const approved = await f.iam.api.accessRequests.approve(reviewer.credential, {
      tenantId: f.tenantId,
      requestId: request.id,
      note: 'Approved for the incident',
    });
    expect(approved).toMatchObject({
      status: 'approved',
      reviewerId: reviewer.identity.id,
      note: 'Approved for the incident',
      grantExpiresAt: f.now() + 7200_000,
    });
    expect(approved.bindingIds).toHaveLength(1);
    expect((await check()).allowed).toBe(true);
    const bindings = await f.iam.api.identities.listBindings(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.identity.id,
    });
    expect(bindings.find((item) => item.roleId === admin.id)).toMatchObject({
      expiresAt: f.now() + 7200_000,
      accessRequestId: request.id,
    });
    f.advance(7201_000);
    expect((await check()).allowed).toBe(false);
    await expect(
      f.iam.api.accessRequests.approve(reviewer.credential, {
        tenantId: f.tenantId,
        requestId: request.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // Denial, cancellation, expiry, and the audit trail.
    const second = await f.iam.api.accessRequests.create(alice.credential, {
      tenantId: f.tenantId,
      roleIds: [admin.id],
    });
    const denied = await f.iam.api.accessRequests.deny(reviewer.credential, {
      tenantId: f.tenantId,
      requestId: second.id,
      note: 'Not now',
    });
    expect(denied).toMatchObject({ status: 'denied', note: 'Not now' });
    const third = await f.iam.api.accessRequests.create(alice.credential, {
      tenantId: f.tenantId,
      roleIds: [admin.id],
    });
    await expect(
      f.iam.api.accessRequests.cancel(reviewer.credential, {
        tenantId: f.tenantId,
        requestId: third.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      (
        await f.iam.api.accessRequests.cancel(alice.credential, {
          tenantId: f.tenantId,
          requestId: third.id,
        })
      ).status,
    ).toBe('cancelled');
    const fourth = await f.iam.api.accessRequests.create(alice.credential, {
      tenantId: f.tenantId,
      roleIds: [admin.id],
    });
    f.advance(61 * 60_000);
    expect(
      (
        await f.iam.api.accessRequests.get(reviewer.credential, {
          tenantId: f.tenantId,
          requestId: fourth.id,
        })
      ).status,
    ).toBe('expired');
    await expect(
      f.iam.api.accessRequests.deny(reviewer.credential, {
        tenantId: f.tenantId,
        requestId: fourth.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect(await f.iam.purgeDeleted()).toMatchObject({ expiredBindings: 1, expiredRequests: 1 });
    expect((await f.database.get('accessRequests', fourth.id))!.status).toBe('expired');
    const trail = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'access-request:*',
    });
    expect(trail.map((event) => event.action).sort()).toEqual([
      'access-request:approve',
      'access-request:deny',
    ]);
    expect(
      trail.find((event) => event.action === 'access-request:approve')!.metadata,
    ).toMatchObject({ requesterId: alice.identity.id, roleIds: [admin.id] });
    // Approval reuses an existing standing binding instead of duplicating it, and an approver override shortens the grant.
    await f.iam.api.bindings.create(reviewer.credential, {
      tenantId: f.tenantId,
      roleId: admin.id,
      subjectType: 'identity',
      subjectId: alice.identity.id,
    });
    const fifth = await f.iam.api.accessRequests.create(alice.credential, {
      tenantId: f.tenantId,
      roleIds: [admin.id],
      durationSeconds: 86400,
    });
    const shortened = await f.iam.api.accessRequests.approve(reviewer.credential, {
      tenantId: f.tenantId,
      requestId: fifth.id,
      durationSeconds: 600,
    });
    expect(shortened.grantExpiresAt).toBe(f.now() + 600_000);
    expect(
      (
        await f.iam.api.bindings.list(f.ownerCredential, {
          tenantId: f.tenantId,
          roleId: admin.id,
          subjectId: alice.identity.id,
        })
      ).map((item) => item.expiresAt),
    ).toEqual([f.now() + 600_000]);
  });
});
