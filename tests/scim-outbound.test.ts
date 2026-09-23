import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { randomBytes, randomUUID } from 'node:crypto';
import { createServer } from 'node:http';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createScimProvisioner } from '@better-iam/scim';
import { IamError, type IamStore } from '@better-iam/core';

const TOKEN = 'downstream-provisioning-token';

/** A minimal SCIM 2.0 service provider: users in memory, bearer auth, filter by externalId/userName. */
function fakeScim() {
  const users = new Map<string, Record<string, unknown>>();
  const groups = new Map<string, Record<string, unknown>>();
  const calls: string[] = [];
  let failNext: number | undefined;
  const server = createServer(async (req, res) => {
    let raw = '';
    for await (const chunk of req) raw += String(chunk);
    const url = new URL(req.url!, 'http://scim.test');
    calls.push(`${req.method} ${url.pathname}`);
    const send = (status: number, body?: unknown) => {
      res.writeHead(status, { 'content-type': 'application/scim+json' });
      res.end(body === undefined ? undefined : JSON.stringify(body));
    };
    if (req.headers.authorization !== `Bearer ${TOKEN}`) return send(401, { detail: 'bad token' });
    if (failNext) {
      const status = failNext;
      failNext = undefined;
      return send(status, { detail: 'downstream refused' });
    }
    const group = /^\/scim\/v2\/Groups(?:\/([^/]+))?$/.exec(url.pathname);
    if (group) {
      const groupId = group[1];
      if (!groupId && req.method === 'GET') {
        const [, attribute, value] = /^(\w+) eq "(.*)"$/.exec(
          url.searchParams.get('filter') ?? '',
        )!;
        const matches = [...groups.values()].filter((item) => item[attribute!] === value);
        return send(200, { totalResults: matches.length, Resources: matches });
      }
      if (!groupId && req.method === 'POST') {
        const item = { ...JSON.parse(raw), id: randomUUID() };
        groups.set(item.id, item);
        return send(201, item);
      }
      if (!groupId || !groups.has(groupId)) return send(404, { detail: 'no such group' });
      if (req.method === 'PUT') {
        groups.set(groupId, { ...JSON.parse(raw), id: groupId });
        return send(200, groups.get(groupId));
      }
      if (req.method === 'DELETE') {
        groups.delete(groupId);
        return send(204);
      }
    }
    const id = /^\/scim\/v2\/Users\/([^/]+)$/.exec(url.pathname)?.[1];
    if (url.pathname === '/scim/v2/Users' && req.method === 'GET') {
      const [, attribute, value] = /^(\w+) eq "(.*)"$/.exec(url.searchParams.get('filter') ?? '')!;
      const matches = [...users.values()].filter((user) => user[attribute!] === value);
      return send(200, { totalResults: matches.length, Resources: matches });
    }
    if (url.pathname === '/scim/v2/Users' && req.method === 'POST') {
      const user = { ...JSON.parse(raw), id: randomUUID() };
      users.set(user.id, user);
      return send(201, user);
    }
    if (id && !users.has(id)) return send(404, { detail: 'no such user' });
    if (id && req.method === 'PUT') {
      users.set(id, { ...JSON.parse(raw), id });
      return send(200, users.get(id));
    }
    if (id && req.method === 'PATCH') {
      const patch = JSON.parse(raw);
      users.set(id, { ...users.get(id)!, ...patch.Operations[0].value });
      return send(200, users.get(id));
    }
    if (id && req.method === 'DELETE') {
      users.delete(id);
      return send(204);
    }
    send(404);
  });
  return {
    server,
    users,
    groups,
    calls,
    fail(status: number) {
      failNext = status;
    },
  };
}

describe('outbound SCIM provisioning', () => {
  let store: IamStore;
  let downstream: ReturnType<typeof fakeScim>;
  let origin: string;
  const denied: string[] = [];
  beforeEach(async () => {
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    denied.length = 0;
    await store.transaction(async (tx) => {
      await tx.insert('tenants', {
        id: 'a',
        tenantId: 'a',
        name: 'A',
        type: 'organization',
        parentId: null,
        status: 'active',
        createdAt: Date.now(),
      });
      for (const [id, status, kind] of [
        ['ada', 'active', 'user'],
        ['bob', 'active', 'user'],
        ['cy', 'disabled', 'user'],
        ['robot', 'active', 'service'],
      ] as const)
        await tx.insert('identities', {
          id,
          tenantId: 'a',
          name: id.toUpperCase(),
          kind,
          ...(kind === 'user' ? { email: `${id}@acme.test` } : {}),
          emailVerified: true,
          status,
          rootAdmin: false,
          owner: false,
          createdAt: Date.now(),
          attributes: { department: `${id}-dept` },
        });
      await tx.insert('groupMembers', {
        id: 'm1',
        tenantId: 'a',
        groupId: 'engineering',
        identityId: 'ada',
      });
    });
    downstream = fakeScim();
    await new Promise<void>((resolve) => downstream.server.listen(0, '127.0.0.1', resolve));
    const address = downstream.server.address() as { port: number };
    origin = `http://127.0.0.1:${address.port}`;
  });
  afterEach(async () => {
    downstream.server.closeAllConnections();
    await new Promise<void>((resolve) => downstream.server.close(() => resolve()));
    await store.close();
  });
  const provisioner = () =>
    createScimProvisioner({
      store,
      encryptionKey: randomBytes(32).toString('base64'),
      allowInsecureLocalhost: true,
      authenticate: async () => ({ identity: { id: 'admin' } }),
      authorize: async (credential, action) => {
        const bearer = (credential.headers as Headers | undefined)?.get?.('authorization');
        if (credential.token !== 'admin' && bearer !== 'Bearer admin') {
          denied.push(action);
          throw new IamError('ACCESS_DENIED', 'Forbidden', 403);
        }
      },
    });
  const admin = { token: 'admin' };

  it('keeps downstream tokens usable through an encryption key rotation', async () => {
    const oldKey = randomBytes(32).toString('base64');
    const newKey = randomBytes(32).toString('base64');
    const make = (encryptionKey: string, previousEncryptionKeys?: string[]) =>
      createScimProvisioner({
        store,
        encryptionKey,
        ...(previousEncryptionKeys ? { previousEncryptionKeys } : {}),
        allowInsecureLocalhost: true,
        authenticate: async () => ({ identity: { id: 'admin' } }),
        authorize: async () => undefined,
      });
    const target = await make(oldKey).createTarget(admin, {
      tenantId: 'a',
      name: 'Acme Slack',
      baseUrl: `${origin}/scim/v2/`,
      token: TOKEN,
    });
    // Rotating: the new key seals, the old one still opens.
    const during = make(newKey, [oldKey]);
    expect(await during.syncTarget(admin, { tenantId: 'a', targetId: target.id })).toMatchObject({
      created: 2,
      failed: 0,
    });
    expect(await during.rotateKeys()).toEqual({ resealed: 1, current: 0, unreadable: 0 });
    expect(await during.rotateKeys()).toEqual({ resealed: 0, current: 1, unreadable: 0 });
    // Afterwards the old key can go.
    expect(
      await make(newKey).syncTarget(admin, { tenantId: 'a', targetId: target.id }),
    ).toMatchObject({ failed: 0 });
    expect(await make(randomBytes(32).toString('base64')).rotateKeys()).toEqual({
      resealed: 0,
      current: 0,
      unreadable: 1,
    });
    expect(() => make(newKey, ['c2hvcnQ='])).toThrow('32 bytes');
  });

  it('provisions active members, updates changes, and deactivates people who leave', async () => {
    const service = provisioner();
    const target = await service.createTarget(admin, {
      tenantId: 'a',
      name: 'Acme Slack',
      baseUrl: `${origin}/scim/v2/`,
      token: TOKEN,
      attributeMapping: { department: 'department' },
    });
    expect(target).toMatchObject({
      tenantId: 'a',
      name: 'Acme Slack',
      baseUrl: `${origin}/scim/v2`,
      deprovision: 'deactivate',
      enabled: true,
      provisioned: 0,
    });
    expect(JSON.stringify(target)).not.toContain(TOKEN);
    expect(JSON.stringify(await store.find('provisioningTargets'))).not.toContain(TOKEN);

    let run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run).toMatchObject({ created: 2, updated: 0, deactivated: 0, failed: 0 });
    const byExternal = () =>
      new Map([...downstream.users.values()].map((user) => [user.externalId, user]));
    expect([...byExternal().keys()].sort()).toEqual(['ada', 'bob']);
    expect(byExternal().get('ada')).toMatchObject({
      userName: 'ada@acme.test',
      displayName: 'ADA',
      active: true,
      'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User': { department: 'ada-dept' },
    });

    // A second run with no changes touches nothing downstream.
    const before = downstream.calls.length;
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run).toMatchObject({ created: 0, updated: 0, unchanged: 2 });
    expect(downstream.calls.length).toBe(before);

    // A rename is pushed; a disabled member is deactivated, not deleted.
    await store.transaction(async (tx) => {
      await tx.put('identities', { ...(await tx.get('identities', 'ada'))!, name: 'Ada L.' });
      await tx.put('identities', { ...(await tx.get('identities', 'bob'))!, status: 'disabled' });
    });
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run).toMatchObject({ updated: 1, deactivated: 1, failed: 0 });
    expect(byExternal().get('ada')).toMatchObject({ displayName: 'Ada L.' });
    expect(byExternal().get('bob')).toMatchObject({ active: false });
    expect(
      (await service.getTarget(admin, { tenantId: 'a', targetId: target.id })).provisioned,
    ).toBe(1);

    // Re-enabling reactivates the same downstream account.
    await store.transaction(async (tx) =>
      tx.put('identities', { ...(await tx.get('identities', 'bob'))!, status: 'active' }),
    );
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run).toMatchObject({ created: 0, updated: 1 });
    expect(downstream.users.size).toBe(2);
    expect(byExternal().get('bob')).toMatchObject({ active: true });
    const actions = (await store.find('audit', { tenantId: 'a' })).map((event) => event.action);
    expect(actions).toEqual(
      expect.arrayContaining(['iam:scim:CreateTarget', 'iam:scim:SyncTarget']),
    );
  });

  it('scopes to groups, adopts existing downstream users, deletes when configured, and records failures', async () => {
    // A downstream account created by hand earlier is adopted by userName instead of duplicated.
    downstream.users.set('existing', {
      id: 'existing',
      userName: 'ada@acme.test',
      active: true,
    });
    const service = provisioner();
    const target = await service.createTarget(admin, {
      tenantId: 'a',
      name: 'Engineering tools',
      baseUrl: `${origin}/scim/v2`,
      token: TOKEN,
      groupIds: ['engineering'],
      deprovision: 'delete',
    });
    let run = (await service.syncAll({ tenantId: 'a' }))[target.id]!;
    expect(run).toMatchObject({ created: 0, updated: 1, failed: 0 });
    expect(downstream.users.size).toBe(1);
    expect(downstream.users.get('existing')).toMatchObject({ externalId: 'ada', active: true });

    // Leaving the group deletes the downstream account in delete mode.
    await store.transaction((tx) => tx.delete('groupMembers', 'm1'));
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run).toMatchObject({ deleted: 1 });
    expect(downstream.users.size).toBe(0);
    expect(await store.find('provisioningLinks', { targetId: target.id })).toEqual([]);

    // Downstream refusals are counted and reported without stopping the run.
    await store.transaction((tx) =>
      tx.insert('groupMembers', {
        id: 'm2',
        tenantId: 'a',
        groupId: 'engineering',
        identityId: 'bob',
      }),
    );
    downstream.fail(500);
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run.failed).toBe(1);
    expect(run.errors[0]).toMatchObject({ identityId: 'bob', status: 500 });
    expect(run.errors[0]!.message).toContain('downstream refused');
    const summary = await service.getTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(summary.lastRun).toMatchObject({ failed: 1 });
    // The next run retries.
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run).toMatchObject({ created: 1, failed: 0 });

    // A wrong token fails every call with 401 and is fixed by replacing the token.
    await service.updateTarget(admin, {
      tenantId: 'a',
      targetId: target.id,
      token: 'wrong-token-value',
    });
    await store.transaction(async (tx) =>
      tx.put('identities', { ...(await tx.get('identities', 'bob'))!, name: 'Robert' }),
    );
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run.errors[0]).toMatchObject({ status: 401 });
    await service.updateTarget(admin, { tenantId: 'a', targetId: target.id, token: TOKEN });
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run).toMatchObject({ updated: 1, failed: 0 });
  });

  it('pushes scoped groups with their provisioned members', async () => {
    await store.transaction(async (tx) => {
      await tx.insert('groups', { id: 'engineering', tenantId: 'a', name: 'Engineering' });
      await tx.insert('groups', { id: 'design', tenantId: 'a', name: 'Design' });
    });
    // An existing downstream group with the same name is adopted.
    downstream.groups.set('g-existing', {
      id: 'g-existing',
      displayName: 'Engineering',
      members: [],
    });
    const service = provisioner();
    const target = await service.createTarget(admin, {
      tenantId: 'a',
      name: 'With groups',
      baseUrl: `${origin}/scim/v2`,
      token: TOKEN,
      groupIds: ['engineering', 'design'],
      pushGroups: true,
    });
    expect(target.pushGroups).toBe(true);
    let run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run.groups).toEqual({ created: 1, updated: 1, deleted: 0, unchanged: 0 });
    const remoteId = (externalId: string) =>
      [...downstream.users.values()].find((user) => user.externalId === externalId)!.id;
    const byName = (name: string) =>
      [...downstream.groups.values()].find((item) => item.displayName === name)!;
    expect(byName('Engineering')).toMatchObject({
      id: 'g-existing',
      externalId: 'engineering',
      members: [{ value: remoteId('ada') }],
    });
    expect(byName('Design')).toMatchObject({ members: [] });

    // Membership changes update the group; unchanged groups are left alone.
    await store.transaction((tx) =>
      tx.insert('groupMembers', { id: 'm3', tenantId: 'a', groupId: 'design', identityId: 'bob' }),
    );
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run).toMatchObject({ created: 1, groups: { updated: 1, unchanged: 1 } });
    expect(byName('Design')).toMatchObject({ members: [{ value: remoteId('bob') }] });

    // Groups that leave scope are deleted downstream; turning pushGroups off removes the rest.
    await service.updateTarget(admin, {
      tenantId: 'a',
      targetId: target.id,
      groupIds: ['engineering'],
    });
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run.groups.deleted).toBe(1);
    expect([...downstream.groups.values()].map((item) => item.displayName)).toEqual([
      'Engineering',
    ]);
    await service.updateTarget(admin, { tenantId: 'a', targetId: target.id, pushGroups: false });
    run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run.groups.deleted).toBe(1);
    expect(downstream.groups.size).toBe(0);
    await expect(
      service.updateTarget(admin, {
        tenantId: 'a',
        targetId: target.id,
        groupIds: [],
        pushGroups: true,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('ignores lapsed memberships and syncs after access-package changes', async () => {
    await store.transaction(async (tx) => {
      await tx.insert('groups', { id: 'engineering', tenantId: 'a', name: 'Engineering' });
      // Bob's temporary (or package) membership has already ended but not been purged yet.
      await tx.insert('groupMembers', {
        id: 'm-lapsed',
        tenantId: 'a',
        groupId: 'engineering',
        identityId: 'bob',
        expiresAt: Date.now() - 1000,
      });
    });
    const service = provisioner();
    const target = await service.createTarget(admin, {
      tenantId: 'a',
      name: 'Scoped',
      baseUrl: `${origin}/scim/v2`,
      token: TOKEN,
      groupIds: ['engineering'],
      pushGroups: true,
    });
    await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect([...downstream.users.values()].map((user) => user.externalId)).toEqual(['ada']);
    expect([...downstream.groups.values()][0]!.members).toHaveLength(1);

    const patterns: string[][] = [];
    service.subscribe({
      subscribe: (list) => {
        patterns.push(list);
        return () => undefined;
      },
    })();
    expect(patterns[0]).toEqual(expect.arrayContaining(['iam:packages:*', 'package:*']));
  });

  it('previews the next sync without writing downstream', async () => {
    downstream.users.set('existing', { id: 'existing', userName: 'bob@acme.test', active: true });
    const service = provisioner();
    const target = await service.createTarget(admin, {
      tenantId: 'a',
      name: 'Preview',
      baseUrl: `${origin}/scim/v2`,
      token: TOKEN,
    });
    const writes = () => downstream.calls.filter((call) => !call.startsWith('GET')).length;
    let plan = await service.previewTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(plan.counts).toMatchObject({ create: 1, adopt: 1, unchanged: 0 });
    expect(plan.changes).toEqual(
      expect.arrayContaining([
        { identityId: 'ada', email: 'ada@acme.test', action: 'create' },
        { identityId: 'bob', email: 'bob@acme.test', action: 'adopt' },
      ]),
    );
    expect(writes()).toBe(0);
    expect(await store.find('provisioningLinks')).toEqual([]);
    expect(
      (await service.getTarget(admin, { tenantId: 'a', targetId: target.id })).lastRun,
    ).toBeUndefined();

    await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    const afterSync = writes();
    await store.transaction(async (tx) => {
      await tx.put('identities', { ...(await tx.get('identities', 'ada'))!, name: 'Ada L.' });
      await tx.put('identities', { ...(await tx.get('identities', 'bob'))!, status: 'disabled' });
    });
    plan = await service.previewTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(plan.counts).toMatchObject({ update: 1, deactivate: 1, create: 0 });
    expect(writes()).toBe(afterSync);
    await expect(
      service.previewTarget({ token: 'member' }, { tenantId: 'a', targetId: target.id }),
    ).rejects.toMatchObject({ status: 403 });
  });

  it('serves a JSON management API with the IAM envelope and CSRF rule', async () => {
    const service = provisioner();
    const call = (route: string, body: unknown, headers: Record<string, string> = {}) =>
      service.handler(
        new Request(`https://iam.test/scim/provisioning/${route}`, {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            'x-better-iam': '1',
            authorization: 'Bearer admin',
            ...headers,
          },
          body: JSON.stringify(body),
        }),
      );
    const created = await call('targets/create', {
      tenantId: 'a',
      name: 'Over HTTP',
      baseUrl: `${origin}/scim/v2`,
      token: TOKEN,
    });
    expect(created?.status).toBe(200);
    const { data } = (await created!.json()) as { data: { id: string } };
    const synced = await call('targets/sync', { tenantId: 'a', targetId: data.id });
    expect(((await synced!.json()) as { data: { created: number } }).data.created).toBe(2);
    const listed = (await (await call('targets/list', { tenantId: 'a' }))!.json()) as {
      data: { id: string; provisioned: number }[];
    };
    expect(listed.data).toEqual([expect.objectContaining({ id: data.id, provisioned: 2 })]);
    // Missing CSRF header, wrong caller, unknown route, other paths.
    expect((await call('targets/list', { tenantId: 'a' }, { 'x-better-iam': '0' }))?.status).toBe(
      403,
    );
    const forbidden = await call(
      'targets/list',
      { tenantId: 'a' },
      { authorization: 'Bearer member' },
    );
    expect(forbidden?.status).toBe(403);
    expect(await forbidden!.json()).toEqual({
      error: { code: 'ACCESS_DENIED', message: 'Forbidden' },
    });
    expect((await call('targets/nope', {}))?.status).toBe(404);
    expect(await service.handler(new Request('https://iam.test/elsewhere'))).toBeUndefined();
  });
  it('syncs from IAM events, guards management, and validates input', async () => {
    const service = provisioner();
    const target = await service.createTarget(admin, {
      tenantId: 'a',
      name: 'Events',
      baseUrl: `${origin}/scim/v2`,
      token: TOKEN,
    });
    const handlers: ((event: { tenantId: string; action: string }) => unknown)[] = [];
    const unsubscribe = service.subscribe(
      {
        subscribe: (_patterns, handler) => {
          handlers.push(handler);
          return () => handlers.splice(handlers.indexOf(handler), 1);
        },
      },
      { debounceMs: 10 },
    );
    // Its own audit events never trigger a run; member changes do (debounced).
    handlers[0]!({ tenantId: 'a', action: 'iam:scim:SyncTarget' });
    await new Promise((resolve) => setTimeout(resolve, 50));
    expect(downstream.users.size).toBe(0);
    handlers[0]!({ tenantId: 'a', action: 'iam:identities:update' });
    handlers[0]!({ tenantId: 'a', action: 'iam:groups:update' });
    await new Promise((resolve) => setTimeout(resolve, 200));
    expect(downstream.users.size).toBe(2);
    unsubscribe();
    expect(handlers).toHaveLength(0);

    await expect(
      service.syncTarget({ token: 'member' }, { tenantId: 'a', targetId: target.id }),
    ).rejects.toMatchObject({ status: 403 });
    expect(denied).toContain('iam:scim:targets:sync');
    await expect(
      service.getTarget(admin, { tenantId: 'b', targetId: target.id }),
    ).rejects.toMatchObject({ status: 404 });
    for (const input of [
      { baseUrl: 'http://scim.example.test/v2' },
      { baseUrl: 'not a url' },
      { token: 'short' },
      { deprovision: 'archive' },
      { attributeMapping: { manager: 'boss' } },
      { name: '' },
    ])
      await expect(
        service.createTarget(admin, {
          tenantId: 'a',
          name: 'X',
          baseUrl: `${origin}/scim/v2`,
          token: TOKEN,
          ...(input as object),
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Disabling a target deprovisions everyone on the next run; deleting it leaves downstream accounts alone.
    await service.updateTarget(admin, { tenantId: 'a', targetId: target.id, enabled: false });
    const run = await service.syncTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(run.deactivated).toBe(2);
    await service.deleteTarget(admin, { tenantId: 'a', targetId: target.id });
    expect(await service.listTargets(admin, { tenantId: 'a' })).toEqual([]);
    expect(await store.find('provisioningLinks')).toEqual([]);
    expect(downstream.users.size).toBe(2);
    expect(() =>
      createScimProvisioner({
        store,
        encryptionKey: 'short',
        authenticate: async () => ({ identity: { id: 'x' } }),
        authorize: async () => undefined,
      }),
    ).toThrow(/32 bytes/);
  });
});
