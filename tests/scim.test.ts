import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createScimService, parseScimFilter } from '@better-iam/scim';
import { IamError, type IamStore } from '@better-iam/core';

describe('SCIM tenant isolation and provisioning', () => {
  let store: IamStore;
  let service: ReturnType<typeof createScimService>;
  let a: Awaited<ReturnType<typeof service.createConnection>>;
  let b: Awaited<ReturnType<typeof service.createConnection>>;
  beforeEach(async () => {
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    await store.transaction(async (tx) => {
      for (const id of ['root', 'a', 'b'])
        await tx.insert('tenants', {
          id,
          tenantId: id,
          name: id,
          type: id === 'root' ? 'root' : 'organization',
          parentId: id === 'root' ? null : 'root',
          status: 'active',
          createdAt: Date.now(),
        });
    });
    service = createScimService({
      store,
      authenticate: async (credential) => {
        if (credential.token !== 'admin') throw new IamError('FORBIDDEN', 'Forbidden', 403);
        return { identity: { id: 'administrator' } };
      },
      authorize: async (credential) => {
        if (credential.token !== 'admin') throw new IamError('FORBIDDEN', 'Forbidden', 403);
      },
      mapAttributes: (user) => {
        const attributes: Record<string, unknown> = {};
        if (user.title !== undefined) attributes.title = user.title;
        if (typeof user.enterprise?.department === 'string')
          attributes.department = user.enterprise.department;
        return Object.keys(attributes).length ? attributes : undefined;
      },
      validateIdentityAttributes: (attributes) => {
        for (const key of Object.keys(attributes))
          if (!['title', 'department'].includes(key))
            throw new IamError('INVALID_INPUT', `Attribute ${key} is not declared`);
        return attributes;
      },
    });
    a = await service.createConnection({ token: 'admin' }, { tenantId: 'a', name: 'A' });
    b = await service.createConnection({ token: 'admin' }, { tenantId: 'b', name: 'B' });
  });
  afterEach(async () => {
    await store.close();
  });
  async function request(
    connection: typeof a,
    resource: string,
    method = 'GET',
    body?: unknown,
    extraHeaders?: Record<string, string>,
  ) {
    return (await service.handler(
      new Request(`https://iam.test${connection.path}/${resource}`, {
        method,
        headers: {
          authorization: `Bearer ${connection.token}`,
          'content-type': 'application/scim+json',
          ...extraHeaders,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    ))!;
  }
  it('scopes tokens, resources and same-email accounts to the connection tenant', async () => {
    const createA = await request(a, 'Users', 'POST', {
      userName: 'same@example.test',
      active: true,
    });
    expect(createA.status).toBe(201);
    const userA = await createA.json();
    const createB = await request(b, 'Users', 'POST', {
      userName: 'same@example.test',
      active: true,
    });
    expect(createB.status).toBe(201);
    expect((await createB.json()).id).not.toBe(userA.id);
    expect((await request(b, `Users/${userA.id}`)).status).toBe(404);
    expect((await request({ ...a, token: b.token }, 'Users')).status).toBe(401);
    expect((await store.find('identities', { email: 'same@example.test' })).length).toBe(2);
    expect(
      (await store.find('scimConnections')).some((row) => JSON.stringify(row).includes(a.token)),
    ).toBe(false);
  });
  it('maps the title and enterprise extension to declared identity attributes', async () => {
    const enterprise = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
    const created = await request(a, 'Users', 'POST', {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User', enterprise],
      userName: 'mapped@example.test',
      title: 'Engineer',
      [enterprise]: { department: 'Platform', manager: { value: 'boss', displayName: 'Boss' } },
    });
    expect(created.status).toBe(201);
    const user = await created.json();
    expect(user.title).toBe('Engineer');
    expect(user[enterprise]).toEqual({
      department: 'Platform',
      manager: { value: 'boss', displayName: 'Boss' },
    });
    expect(user.schemas).toContain(enterprise);
    const link = await store.get('scimUsers', user.id);
    const identity = await store.get('identities', String(link!.identityId));
    expect(identity?.attributes).toEqual({ title: 'Engineer', department: 'Platform' });
    // PUT replaces the mapping; unsupported enterprise fields are rejected.
    const replaced = await request(a, `Users/${user.id}`, 'PUT', {
      userName: 'mapped@example.test',
      title: 'Lead',
    });
    expect(replaced.status).toBe(200);
    expect((await store.get('identities', String(link!.identityId)))?.attributes).toEqual({
      title: 'Lead',
    });
    const rejected = await request(a, `Users/${user.id}`, 'PUT', {
      userName: 'mapped@example.test',
      [enterprise]: { badge: 'gold' },
    });
    expect(rejected.status).toBe(400);
  });
  it('deactivation revokes local and assumed sessions while preserving another tenant', async () => {
    const user = await (
      await request(a, 'Users', 'POST', { userName: 'user@example.test' })
    ).json();
    const link = await store.get('scimUsers', user.id);
    await store.transaction(async (tx) => {
      await tx.insert('sessions', { id: 'local', tenantId: 'a', identityId: link!.identityId });
      await tx.insert('sessions', {
        id: 'assumed',
        tenantId: 'b',
        identityId: 'role-user',
        originalIdentityId: link!.identityId,
      });
      await tx.insert('sessions', { id: 'other', tenantId: 'b', identityId: 'other-user' });
    });
    const patched = await request(a, `Users/${user.id}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'replace', path: 'active', value: false }],
    });
    expect(patched.status).toBe(200);
    expect((await patched.json()).active).toBe(false);
    expect(await store.get('sessions', 'local')).toBeUndefined();
    expect(await store.get('sessions', 'assumed')).toBeUndefined();
    expect(await store.get('sessions', 'other')).toBeDefined();
    expect((await store.get('identities', String(link!.identityId)))?.status).toBe('disabled');
  });
  it('supports group PATCH and rejects nested or foreign members atomically', async () => {
    const first = await (
      await request(a, 'Users', 'POST', { userName: 'one@example.test' })
    ).json();
    const second = await (
      await request(a, 'Users', 'POST', { userName: 'two@example.test' })
    ).json();
    const foreign = await (
      await request(b, 'Users', 'POST', { userName: 'foreign@example.test' })
    ).json();
    const group = await (
      await request(a, 'Groups', 'POST', {
        displayName: 'Engineers',
        members: [{ value: first.id }],
      })
    ).json();
    const patch = (Operations: unknown[]) => ({
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations,
    });
    expect(
      (
        await request(
          a,
          `Groups/${group.id}`,
          'PATCH',
          patch([{ op: 'add', path: 'members', value: [{ value: second.id }] }]),
        )
      ).status,
    ).toBe(200);
    expect(
      (
        await request(
          a,
          `Groups/${group.id}`,
          'PATCH',
          patch([{ op: 'add', path: 'members', value: [{ value: foreign.id }] }]),
        )
      ).status,
    ).toBe(400);
    expect(
      (
        await request(
          a,
          `Groups/${group.id}`,
          'PATCH',
          patch([{ op: 'add', path: 'members', value: [{ value: group.id, type: 'Group' }] }]),
        )
      ).status,
    ).toBe(400);
    expect((await (await request(a, `Groups/${group.id}`)).json()).members).toHaveLength(2);
    expect(
      (
        await request(
          a,
          `Groups/${group.id}`,
          'PATCH',
          patch([{ op: 'remove', path: `members[value eq "${first.id}"]` }]),
        )
      ).status,
    ).toBe(200);
    expect(await store.find('groupMembers')).toHaveLength(1);
  });
  it('rejects owner changes, stale ETags and email-based account takeover', async () => {
    const created = await request(a, 'Users', 'POST', { userName: 'owner@example.test' });
    const user = await created.json();
    expect(
      (
        await request(
          a,
          `Users/${user.id}`,
          'PUT',
          { userName: 'owner@example.test' },
          { 'if-match': 'W/"0"' },
        )
      ).status,
    ).toBe(412);
    const link = await store.get('scimUsers', user.id);
    await store.transaction(async (tx) => {
      const identity = await tx.get('identities', String(link!.identityId));
      await tx.put('identities', { ...identity!, owner: true });
    });
    expect((await request(a, `Users/${user.id}`, 'DELETE')).status).toBe(403);
    const secondConnection = await service.createConnection(
      { token: 'admin' },
      { tenantId: 'a', name: 'another' },
    );
    expect(
      (await request(secondConnection, 'Users', 'POST', { userName: 'owner@example.test' })).status,
    ).toBe(409);
  });
  it('filters and pages honestly, and immediately rejects revoked or suspended connections', async () => {
    for (const userName of ['a@example.test', 'b@example.test'])
      expect((await request(a, 'Users', 'POST', { userName })).status).toBe(201);
    const filtered = await (
      await request(a, `Users?filter=${encodeURIComponent('userName eq "A@example.test"')}`)
    ).json();
    expect(filtered.totalResults).toBe(1);
    const page = await (await request(a, 'Users?startIndex=1&count=1')).json();
    expect(page.itemsPerPage).toBe(1);
    expect(page.totalResults).toBe(2);
    expect(
      (await request(a, `Users?filter=${encodeURIComponent('userName eq "a" or bogus(')}`)).status,
    ).toBe(400);
    const discovery = await (await request(a, 'ServiceProviderConfig')).json();
    expect(discovery.bulk).toMatchObject({ supported: true, maxOperations: 100 });
    expect(discovery.sort.supported).toBe(true);
    await service.revokeConnection({ token: 'admin' }, { tenantId: 'a', connectionId: a.id });
    expect((await request(a, 'Users')).status).toBe(401);
    await store.transaction(async (tx) => {
      const root = await tx.get('tenants', 'root');
      await tx.put('tenants', { ...root!, status: 'suspended' });
    });
    expect((await request(b, 'Users')).status).toBe(401);
  });
  it('requires administrator credentials to provision connections', async () => {
    await expect(
      service.createConnection({ token: 'forged' }, { tenantId: 'a', name: 'forged' }),
    ).rejects.toMatchObject({ status: 403 });
    expect(() => parseScimFilter('active eq "false"')).toThrow();
  });
  it('roundtrips supported profile attributes and treats external IDs as case-exact', async () => {
    const input = {
      userName: 'profile',
      externalId: 'CaseSensitiveID',
      name: { givenName: 'Ada', familyName: 'Lovelace' },
      emails: [{ value: 'ada@example.test', primary: true, type: 'work' }],
    };
    const created = await request(a, 'Users', 'POST', input);
    expect(created.status).toBe(201);
    const user = await created.json();
    expect(user.name).toEqual(input.name);
    expect(user.emails).toEqual(input.emails);
    const wrongCase = await (
      await request(a, `Users?filter=${encodeURIComponent('externalId eq "casesensitiveid"')}`)
    ).json();
    expect(wrongCase.totalResults).toBe(0);
    const patch = await request(a, `Users/${user.id}`, 'PATCH', {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'replace', path: 'displayName', value: 'Ada' }],
    });
    expect((await patch.json()).emails).toEqual(input.emails);
  });
});
