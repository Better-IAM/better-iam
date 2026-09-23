import { afterEach, describe, expect, it } from 'vitest';
import { createScimService, type ScimUserLink } from '@better-iam/scim';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const ORIGIN = 'http://localhost:3000';

interface Envelope {
  data?: any;
  error?: { code: string; message: string };
}

async function mounted() {
  const f = await organizationFixture();
  const service = createScimService({
    ...f.iam.protocolHost,
    basePath: '/api/iam/scim/v2',
    adminBasePath: '/api/iam/scim-admin',
  });
  f.iam.useProtocol(service);
  /** A console-style JSON call to the administration API through the IAM handler. */
  const call = async (
    route: string,
    body: unknown,
    options: { token?: string; headers?: Record<string, string>; method?: string } = {},
  ) => {
    const method = options.method ?? 'POST';
    const response = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/scim-admin/${route}`, {
        method,
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${options.token ?? f.ownerCredential.token}`,
          ...options.headers,
        },
        body: method === 'GET' ? undefined : typeof body === 'string' ? body : JSON.stringify(body),
      }),
    );
    return {
      status: response.status,
      cacheControl: response.headers.get('cache-control'),
      body: (await response.json()) as Envelope,
    };
  };
  /** An IdP request to the SCIM protocol endpoint, authenticated with the connection token. */
  const scim = (
    connection: { path: string; token: string },
    resource: string,
    method = 'GET',
    body?: unknown,
  ) =>
    f.iam.handler(
      new Request(`${ORIGIN}${connection.path}/${resource}`, {
        method,
        headers: {
          authorization: `Bearer ${connection.token}`,
          'content-type': 'application/scim+json',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    );
  return { f, service, call, scim };
}

describe('SCIM connection administration routes', () => {
  it('creates, lists, maps, rotates, and revokes connections while the protocol keeps working', async () => {
    const { f, call, scim } = await mounted();
    const { tenantId } = f;
    const created = await call('connections/create', { tenantId, name: 'Okta' });
    expect(created.status).toBe(200);
    expect(created.cacheControl).toBe('no-store');
    const connection = created.body.data as { id: string; token: string; path: string };
    expect(connection).toMatchObject({
      tenantId,
      token: expect.any(String),
      path: `/api/iam/scim/v2/${connection.id}`,
    });

    const listed = await call('connections/list', { tenantId });
    expect(listed.body.data).toEqual([
      expect.objectContaining({
        id: connection.id,
        name: 'Okta',
        users: 0,
        groups: 0,
        revoked: false,
      }),
    ]);
    expect(JSON.stringify(listed.body)).not.toContain(connection.token);
    expect(listed.body.data[0]).not.toHaveProperty('tokenHash');

    // The IdP provisions through the protocol endpoint mounted on the same handler.
    const pushed = await scim(connection, 'Users', 'POST', { userName: 'dev@acme.test' });
    expect(pushed.status).toBe(201);
    const user = (await pushed.json()) as { id: string };
    const engineering = (await (
      await scim(connection, 'Groups', 'POST', {
        displayName: 'Engineering',
        externalId: 'eng',
        members: [{ value: user.id }],
      })
    ).json()) as { id: string };
    const admins = (await (
      await scim(connection, 'Groups', 'POST', { displayName: 'Admins' })
    ).json()) as { id: string };
    const users = await (await scim(connection, 'Users')).json();
    expect(users.totalResults).toBe(1);

    const groups = await call('connections/groups', { tenantId, connectionId: connection.id });
    expect(groups.body.data).toEqual([
      {
        id: admins.id,
        groupId: expect.any(String),
        displayName: 'Admins',
        members: 0,
        roleIds: [],
      },
      {
        id: engineering.id,
        groupId: expect.any(String),
        displayName: 'Engineering',
        externalId: 'eng',
        members: 1,
        roleIds: [],
      },
    ]);
    const localGroupId = groups.body.data[1].groupId as string;

    const readers = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const mapped = await call('connections/mappings', {
      tenantId,
      connectionId: connection.id,
      groupId: engineering.id,
      roleIds: [readers.id],
    });
    expect(mapped).toMatchObject({ status: 200, body: { data: null } });
    expect(
      (await call('connections/groups', { tenantId, connectionId: connection.id })).body.data[1]
        .roleIds,
    ).toEqual([readers.id]);
    const identityId = (await f.database.get<ScimUserLink>('scimUsers', user.id))!.identityId;
    const effective = () =>
      f.iam.api.identities.listBindings(f.ownerCredential, { tenantId, identityId });
    expect(await effective()).toEqual([
      expect.objectContaining({ roleId: readers.id, via: { groupId: localGroupId } }),
    ]);
    expect(
      (
        await call('connections/mappings', {
          tenantId,
          connectionId: connection.id,
          groupId: engineering.id,
          roleIds: 'everything',
        })
      ).status,
    ).toBe(400);

    const rotated = await call('connections/rotate', {
      tenantId,
      connectionId: connection.id,
      expiresIn: 3600,
    });
    expect(rotated.status).toBe(200);
    const token = rotated.body.data.token as string;
    expect(token).not.toBe(connection.token);
    expect((await scim(connection, 'Users')).status).toBe(401);
    expect((await scim({ ...connection, token }, 'Users')).status).toBe(200);

    expect(
      await call('connections/revoke', { tenantId, connectionId: connection.id }),
    ).toMatchObject({ status: 200, body: { data: null } });
    expect((await scim({ ...connection, token }, 'Users')).status).toBe(401);
    expect((await call('connections/list', { tenantId })).body.data[0].revoked).toBe(true);
    expect(await effective()).toEqual([]);
  });

  it('refuses cross-site, malformed, unknown, and unauthorized requests', async () => {
    const { f, call } = await mounted();
    const { tenantId } = f;
    const missingHeader = await f.iam.handler(
      new Request(`${ORIGIN}/api/iam/scim-admin/connections/list`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          authorization: `Bearer ${f.ownerCredential.token}`,
        },
        body: JSON.stringify({ tenantId }),
      }),
    );
    expect(missingHeader.status).toBe(403);
    expect(((await missingHeader.json()) as Envelope).error?.code).toBe('CSRF_REJECTED');
    expect(
      (await call('connections/list', { tenantId }, { headers: { 'content-type': 'text/plain' } }))
        .body.error?.code,
    ).toBe('CSRF_REJECTED');
    const crossSite = await call(
      'connections/create',
      { tenantId, name: 'Evil' },
      { headers: { origin: 'https://evil.test' } },
    );
    expect(crossSite).toMatchObject({ status: 403, body: { error: { code: 'CSRF_REJECTED' } } });
    expect(
      (await call('connections/list', { tenantId }, { headers: { origin: ORIGIN } })).status,
    ).toBe(200);

    const get = await call('connections/list', undefined, { method: 'GET' });
    expect(get).toMatchObject({ status: 405, body: { error: { code: 'METHOD_NOT_ALLOWED' } } });
    for (const route of ['connections/nope', 'constructor', 'connections'])
      expect(await call(route, { tenantId }), route).toMatchObject({
        status: 404,
        cacheControl: 'no-store',
        body: { error: { code: 'NOT_FOUND' } },
      });
    expect((await call('connections/list', '[1]')).status).toBe(400);
    expect((await call('connections/list', '{nope')).status).toBe(400);
    expect((await call('connections/list', {})).status).toBe(400);
    expect(
      (await call('connections/create', { tenantId, name: 'x'.repeat(70 * 1024) })).status,
    ).toBe(413);
    expect((await call('connections/groups', { tenantId, connectionId: 'missing' })).status).toBe(
      404,
    );

    // A member without SCIM permissions is denied, and nothing was created on their behalf.
    await f.member('alice');
    const alice = await f.signIn('alice');
    for (const [route, body] of [
      ['connections/list', { tenantId }],
      ['connections/create', { tenantId, name: 'Shadow' }],
    ] as const)
      expect((await call(route, body, { token: alice.token })).status, route).toBe(403);
    expect((await call('connections/list', { tenantId })).body.data).toEqual([]);
  });

  it('hides unexpected failures and validates its paths', async () => {
    const { f } = await mounted();
    const failing = createScimService({
      ...f.iam.protocolHost,
      authorize: async () => {
        throw new Error('database exploded');
      },
    });
    const response = (await failing.handler(
      new Request(`${ORIGIN}/scim/admin/connections/list`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
        body: JSON.stringify({ tenantId: f.tenantId }),
      }),
    ))!;
    expect(response.status).toBe(500);
    const body = (await response.json()) as Envelope;
    expect(body.error?.code).toBe('INTERNAL_ERROR');
    expect(body.error?.message).not.toContain('exploded');
    expect(await failing.handler(new Request(`${ORIGIN}/elsewhere`))).toBeUndefined();

    for (const paths of [
      { basePath: '/scim/v2', adminBasePath: '/scim/v2' },
      { basePath: '/scim/v2', adminBasePath: '/scim/v2/admin' },
      { basePath: '/scim/admin/v2', adminBasePath: '/scim/admin' },
      { basePath: '/scim/v2', adminBasePath: 'scim/admin' },
    ])
      expect(
        () => createScimService({ ...f.iam.protocolHost, ...paths }),
        JSON.stringify(paths),
      ).toThrow(expect.objectContaining({ code: 'configuration' }));
    expect(
      createScimService({ ...f.iam.protocolHost, basePath: '/scim', adminBasePath: '/scim-admin' })
        .adminBasePath,
    ).toBe('/scim-admin');
  });
});
