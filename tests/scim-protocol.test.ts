import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createScimService, parseScimFilter } from '@better-iam/scim';
import { IamError, type IamStore } from '@better-iam/core';

const ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const BULK = 'urn:ietf:params:scim:api:messages:2.0:BulkRequest';
const SEARCH = 'urn:ietf:params:scim:api:messages:2.0:SearchRequest';

describe('SCIM protocol coverage', () => {
  let store: IamStore;
  let service: ReturnType<typeof createScimService>;
  let connection: Awaited<ReturnType<typeof service.createConnection>>;
  beforeEach(async () => {
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    await store.transaction(async (tx) => {
      await tx.insert('tenants', {
        id: 'a',
        tenantId: 'a',
        name: 'a',
        type: 'organization',
        parentId: null,
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
    });
    connection = await service.createConnection({ token: 'admin' }, { tenantId: 'a', name: 'A' });
  });
  afterEach(async () => {
    await store.close();
  });
  async function request(
    resource: string,
    method = 'GET',
    body?: unknown,
    headers?: Record<string, string>,
    token = connection.token,
  ) {
    return (await service.handler(
      new Request(`https://iam.test${connection.path}/${resource}`, {
        method,
        headers: {
          authorization: `Bearer ${token}`,
          'content-type': 'application/scim+json',
          ...headers,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    ))!;
  }
  const create = async (user: Record<string, unknown>) => {
    const created = await request('Users', 'POST', user);
    expect(created.status).toBe(201);
    return created.json();
  };
  const filter = async (expression: string, extra = '') =>
    (await (await request(`Users?filter=${encodeURIComponent(expression)}${extra}`)).json()) as {
      totalResults: number;
      Resources: Array<Record<string, unknown>>;
    };
  const patch = (id: string, Operations: unknown[], type = 'Users') =>
    request(`${type}/${id}`, 'PATCH', { schemas: [PATCH], Operations });

  it('evaluates logical, grouped, value-path, sub-attribute and schema-qualified filters', async () => {
    await create({
      userName: 'ada',
      name: { givenName: 'Ada', familyName: 'Lovelace' },
      emails: [
        { value: 'ada@work.test', type: 'work', primary: true },
        { value: 'ada@home.test', type: 'home' },
      ],
      [ENTERPRISE]: { department: 'Research' },
    });
    await create({
      userName: 'grace',
      active: false,
      name: { givenName: 'Grace', familyName: 'Hopper' },
      emails: [{ value: 'grace@home.test', type: 'home' }],
      [ENTERPRISE]: { department: 'Navy' },
    });
    await create({ userName: 'linus' });

    expect((await filter('userName eq "ada" or userName eq "grace"')).totalResults).toBe(2);
    expect((await filter('active eq true and not (userName sw "l")')).totalResults).toBe(1);
    expect((await filter('emails[type eq "work" and value co "@work"]')).totalResults).toBe(1);
    expect((await filter('emails.type eq "home"')).totalResults).toBe(2);
    expect((await filter('emails co "home.test"')).totalResults).toBe(2);
    expect((await filter('name.familyName sw "HOP"')).totalResults).toBe(1);
    expect((await filter(`${ENTERPRISE}:department eq "research"`)).totalResults).toBe(1);
    expect(
      (await filter('urn:ietf:params:scim:schemas:core:2.0:User:userName eq "linus"')).totalResults,
    ).toBe(1);
    expect((await filter('emails pr')).totalResults).toBe(2);
    expect((await filter('not (emails pr)')).totalResults).toBe(1);
    expect((await filter('meta.lastModified gt "2000-01-01T00:00:00Z"')).totalResults).toBe(3);
    expect(
      (await filter('(userName eq "ada" or userName eq "grace") and active eq false')).totalResults,
    ).toBe(1);
    // Malformed, unbounded or type-confused filters fail loudly instead of broadening the result.
    for (const bad of [
      'userName eq',
      'userName xx "a"',
      '(userName eq "a"',
      'active gt true',
      'userName co 5',
      'urn:example:custom:attr eq "x"',
      Array.from({ length: 70 }, (_, i) => `userName eq "${i}"`).join(' or '),
    ])
      expect((await request(`Users?filter=${encodeURIComponent(bad)}`)).status, bad).toBe(400);
    expect(() => parseScimFilter('primary eq "true"')).toThrow();
  });

  it('sorts, projects attributes and serves POST /.search', async () => {
    for (const userName of ['bravo', 'alpha', 'charlie'])
      await create({ userName, name: { givenName: userName.toUpperCase() } });
    const sorted = await (await request('Users?sortBy=userName&sortOrder=descending')).json();
    expect(sorted.Resources.map((user: { userName: string }) => user.userName)).toEqual([
      'charlie',
      'bravo',
      'alpha',
    ]);
    const projected = await (
      await request('Users?sortBy=userName&attributes=userName,name.givenName&count=1')
    ).json();
    expect(projected.totalResults).toBe(3);
    expect(Object.keys(projected.Resources[0]).sort()).toEqual([
      'id',
      'name',
      'schemas',
      'userName',
    ]);
    expect(projected.Resources[0].name).toEqual({ givenName: 'ALPHA' });
    const excluded = await (await request('Users?excludedAttributes=meta,name,id')).json();
    expect(excluded.Resources[0].meta).toBeUndefined();
    expect(excluded.Resources[0].name).toBeUndefined();
    expect(excluded.Resources[0].id).toBeDefined();
    expect((await request('Users?attributes=userName&excludedAttributes=name')).status).toBe(400);
    expect((await request('Users?sortOrder=sideways&sortBy=userName')).status).toBe(400);

    const searched = await request('Users/.search', 'POST', {
      schemas: [SEARCH],
      filter: 'userName sw "b" or userName sw "c"',
      sortBy: 'userName',
      startIndex: 2,
      count: 5,
      attributes: ['userName'],
    });
    expect(searched.status).toBe(200);
    const page = await searched.json();
    expect(page.totalResults).toBe(2);
    expect(page.startIndex).toBe(2);
    expect(page.Resources).toEqual([
      { schemas: expect.any(Array), id: expect.any(String), userName: 'charlie' },
    ]);
    expect((await request('Users/.search', 'POST', { filter: 'userName pr' })).status).toBe(400);
    expect((await request('Users/.search')).status).toBe(405);
  });

  it('applies value-path, sub-attribute and extension PATCH paths with Entra and Okta conventions', async () => {
    const user = await create({
      userName: 'patchy',
      title: 'Engineer',
      emails: [{ value: 'p@home.test', type: 'home' }],
      [ENTERPRISE]: { department: 'Platform', costCenter: '42' },
    });
    // Seeding: add to a value path that matches nothing creates the entry with the filter's attribute.
    let response = await patch(user.id, [
      { op: 'add', path: 'emails[type eq "work"].value', value: 'p@work.test' },
      { op: 'Replace', path: 'name.givenName', value: 'Pat' },
      { op: 'replace', path: `${ENTERPRISE}:department`, value: 'Security' },
      { op: 'replace', path: `${ENTERPRISE}:manager.value`, value: 'boss-id' },
      { op: 'Replace', path: 'active', value: 'False' },
    ]);
    expect(response.status).toBe(200);
    let body = await response.json();
    expect(body.emails).toEqual([
      { value: 'p@home.test', type: 'home' },
      { type: 'work', value: 'p@work.test' },
    ]);
    expect(body.name).toEqual({ givenName: 'Pat' });
    expect(body.active).toBe(false);
    expect(body.title).toBe('Engineer');
    expect(body[ENTERPRISE]).toEqual({
      department: 'Security',
      costCenter: '42',
      manager: { value: 'boss-id' },
    });

    // Okta-style pathless replace with schema-qualified keys and a whole extension object.
    response = await patch(user.id, [
      {
        op: 'replace',
        value: {
          active: true,
          [`${ENTERPRISE}:division`]: 'R&D',
          [ENTERPRISE]: { costCenter: '7' },
        },
      },
      { op: 'remove', path: 'emails[type eq "home"]' },
      { op: 'replace', path: 'emails[type eq "work"].primary', value: 'True' },
    ]);
    body = await response.json();
    expect(response.status).toBe(200);
    expect(body.active).toBe(true);
    expect(body.emails).toEqual([{ type: 'work', value: 'p@work.test', primary: true }]);
    expect(body[ENTERPRISE]).toMatchObject({
      division: 'R&D',
      costCenter: '7',
      department: 'Security',
    });

    // Removing the last extension attribute drops the extension schema.
    response = await patch(user.id, [{ op: 'remove', path: ENTERPRISE }]);
    body = await response.json();
    expect(body[ENTERPRISE]).toBeUndefined();
    expect(body.schemas).toEqual(['urn:ietf:params:scim:schemas:core:2.0:User']);

    // replace with an unmatched filter, required-attribute removal and immutable paths are rejected atomically.
    const before = await (await request(`Users/${user.id}`)).json();
    for (const operations of [
      [{ op: 'replace', path: 'emails[type eq "other"].value', value: 'x@y.test' }],
      [{ op: 'remove', path: 'userName' }],
      [{ op: 'replace', path: 'meta.created', value: 'x' }],
      [{ op: 'replace', path: 'name[givenName eq "x"]', value: {} }],
      [
        { op: 'replace', path: 'displayName', value: 'Changed' },
        { op: 'replace', path: 'id', value: 'x' },
      ],
    ]) {
      const rejected = await patch(user.id, operations);
      expect(rejected.status, JSON.stringify(operations)).toBe(400);
    }
    expect((await (await request(`Users/${user.id}`)).json()).meta.version).toBe(
      before.meta.version,
    );
  });

  it('removes listed group members (Entra) and filtered members, and answers If-None-Match', async () => {
    const users = await Promise.all(['m1', 'm2', 'm3'].map((userName) => create({ userName })));
    const group = await (
      await request('Groups', 'POST', {
        displayName: 'Team',
        members: users.map((user) => ({ value: user.id })),
      })
    ).json();
    let response = await patch(
      group.id,
      [{ op: 'remove', path: 'members', value: [{ value: users[0].id }] }],
      'Groups',
    );
    expect((await response.json()).members.map((m: { value: string }) => m.value)).toEqual([
      users[1].id,
      users[2].id,
    ]);
    response = await patch(
      group.id,
      [{ op: 'remove', path: `members[value eq "${users[1].id}" or value eq "${users[2].id}"]` }],
      'Groups',
    );
    const updated = await response.json();
    expect(updated.members).toEqual([]);
    expect(await store.find('groupMembers')).toHaveLength(0);
    const etag = response.headers.get('etag')!;
    expect(
      (await request(`Groups/${group.id}`, 'GET', undefined, { 'if-none-match': etag })).status,
    ).toBe(304);
    expect(
      (await request(`Groups/${group.id}`, 'GET', undefined, { 'if-none-match': 'W/"0"' })).status,
    ).toBe(200);
    const members = await (
      await request(
        `Groups?filter=${encodeURIComponent('displayName eq "team"')}&attributes=displayName`,
      )
    ).json();
    expect(members.Resources[0]).toEqual({
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:Group'],
      id: group.id,
      displayName: 'Team',
    });
  });

  it('processes bulk requests with forward bulkId references, isolation and failOnErrors', async () => {
    const response = await request('Bulk', 'POST', {
      schemas: [BULK],
      Operations: [
        // The group references a user declared later in the request.
        {
          method: 'POST',
          bulkId: 'g1',
          path: '/Groups',
          data: { displayName: 'Bulk Group', members: [{ value: 'bulkId:u1' }] },
        },
        { method: 'POST', bulkId: 'u1', path: '/Users', data: { userName: 'bulk-one' } },
        { method: 'POST', bulkId: 'dup', path: '/Users', data: { userName: 'bulk-one' } },
        {
          method: 'PATCH',
          path: '/Users/bulkId:u1',
          data: {
            schemas: [PATCH],
            Operations: [{ op: 'replace', path: 'displayName', value: 'One' }],
          },
        },
        {
          method: 'POST',
          bulkId: 'orphan',
          path: '/Groups',
          data: { displayName: 'X', members: [{ value: 'bulkId:dup' }] },
        },
        {
          method: 'POST',
          bulkId: 'ghost',
          path: '/Groups',
          data: { displayName: 'Y', members: [{ value: 'bulkId:nope' }] },
        },
        { method: 'DELETE', path: '/Users/missing' },
      ],
    });
    expect(response.status).toBe(200);
    const body = await response.json();
    const byBulkId = Object.fromEntries(
      body.Operations.filter((op: { bulkId?: string }) => op.bulkId).map(
        (op: { bulkId: string }) => [op.bulkId, op],
      ),
    );
    expect(byBulkId.u1.status).toBe('201');
    expect(byBulkId.g1.status).toBe('201');
    expect(byBulkId.dup.status).toBe('409');
    expect(byBulkId.orphan.status).toBe('409');
    expect(byBulkId.ghost.status).toBe('400');
    expect(body.Operations.find((op: { method: string }) => op.method === 'DELETE').status).toBe(
      '404',
    );
    expect(body.Operations.find((op: { method: string }) => op.method === 'PATCH').status).toBe(
      '200',
    );
    const group = await (
      await request(byBulkId.g1.location.replace(/^.*\/Groups\//, 'Groups/'))
    ).json();
    const userId = byBulkId.u1.location.split('/').pop();
    expect(group.members.map((m: { value: string }) => m.value)).toEqual([userId]);
    expect((await (await request(`Users/${userId}`)).json()).displayName).toBe('One');
    // Failed operations leave nothing behind.
    expect(await store.find('scimGroups')).toHaveLength(1);

    const stopped = await (
      await request('Bulk', 'POST', {
        schemas: [BULK],
        failOnErrors: 1,
        Operations: [
          { method: 'POST', bulkId: 'bad', path: '/Users', data: { userName: '' } },
          { method: 'POST', bulkId: 'never', path: '/Users', data: { userName: 'never' } },
        ],
      })
    ).json();
    expect(stopped.Operations).toHaveLength(1);
    expect((await filter('userName eq "never"')).totalResults).toBe(0);

    const cycle = await (
      await request('Bulk', 'POST', {
        schemas: [BULK],
        Operations: [
          {
            method: 'POST',
            bulkId: 'x',
            path: '/Groups',
            data: { displayName: 'X', members: [{ value: 'bulkId:y' }] },
          },
          {
            method: 'POST',
            bulkId: 'y',
            path: '/Groups',
            data: { displayName: 'Y', members: [{ value: 'bulkId:x' }] },
          },
        ],
      })
    ).json();
    expect(cycle.Operations.map((op: { status: string }) => op.status)).toEqual(['409', '409']);

    const version = await (
      await request('Bulk', 'POST', {
        schemas: [BULK],
        Operations: [
          {
            method: 'PUT',
            path: `/Users/${userId}`,
            version: 'W/"999"',
            data: { userName: 'bulk-one' },
          },
        ],
      })
    ).json();
    expect(version.Operations[0].status).toBe('412');

    expect((await request('Bulk', 'POST', { schemas: [BULK], Operations: [] })).status).toBe(400);
    expect(
      (
        await request('Bulk', 'POST', {
          schemas: [BULK],
          Operations: Array.from({ length: 101 }, (_, i) => ({
            method: 'DELETE',
            path: `/Users/${i}`,
          })),
        })
      ).status,
    ).toBe(413);
    expect(
      (
        await request(
          'Bulk',
          'POST',
          { schemas: [BULK], Operations: [{ method: 'DELETE', path: '/Users/x' }] },
          {},
          'forged',
        )
      ).status,
    ).toBe(401);
  });

  it('lists connections with usage and rotates tokens without losing provisioned state', async () => {
    await create({ userName: 'kept' });
    const [listed] = await service.listConnections({ token: 'admin' }, { tenantId: 'a' });
    expect(listed).toMatchObject({
      id: connection.id,
      name: 'A',
      users: 1,
      groups: 0,
      revoked: false,
    });
    expect(listed!.lastUsedAt).toBeTypeOf('number');
    expect(JSON.stringify(listed)).not.toContain(connection.token);
    await expect(
      service.listConnections({ token: 'forged' }, { tenantId: 'a' }),
    ).rejects.toMatchObject({
      status: 403,
    });

    const rotated = await service.rotateToken(
      { token: 'admin' },
      { tenantId: 'a', connectionId: connection.id, expiresIn: 3600 },
    );
    expect(rotated.token).not.toBe(connection.token);
    expect((await request('Users')).status).toBe(401);
    const users = await (await request('Users', 'GET', undefined, {}, rotated.token)).json();
    expect(users.totalResults).toBe(1);
    expect((await store.find('audit', { action: 'iam:scim:RotateToken' })).length).toBe(1);

    await service.revokeConnection(
      { token: 'admin' },
      { tenantId: 'a', connectionId: connection.id },
    );
    await expect(
      service.rotateToken({ token: 'admin' }, { tenantId: 'a', connectionId: connection.id }),
    ).rejects.toMatchObject({ status: 409 });
  });
});
