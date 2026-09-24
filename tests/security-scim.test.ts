import { randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { afterEach, describe, expect, it } from 'vitest';
import { createScimProvisioner, createScimService, type ScimUserLink } from '@better-iam/scim';
import type { Identity } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

/**
 * SCIM in both directions: an identity provider cannot undo an administrator's decisions or go past plan limits, its
 * changes reach webhooks and subscribers, and outbound provisioning never hands someone else's downstream account to a
 * person who merely typed that address.
 */

const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const servers: Server[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await closeFixtures();
});

async function directory() {
  const f = await organizationFixture();
  const service = createScimService({ ...f.iam.protocolHost });
  const connection = await service.createConnection(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Directory',
  });
  const request = async (resource: string, method = 'GET', body?: unknown) =>
    (await service.handler(
      new Request(`https://iam.test${connection.path}/${resource}`, {
        method,
        headers: {
          authorization: `Bearer ${connection.token}`,
          'content-type': 'application/scim+json',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    ))!;
  const identityOf = async (user: { id: string }) => {
    const link = await f.database.get<ScimUserLink>('scimUsers', user.id);
    return (await f.database.get<Identity>('identities', link!.identityId))!;
  };
  return { f, service, connection, request, identityOf };
}

describe('inbound SCIM', () => {
  it('never re-enables someone an administrator disabled, unless the IdP itself deactivated them', async () => {
    const { f, request, identityOf } = await directory();
    const created = (await (
      await request('Users', 'POST', { userName: 'mallory@acme.test', active: true })
    ).json()) as { id: string };
    const identity = await identityOf(created);
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: identity.id,
      status: 'disabled',
    });
    const retitle = await request(`Users/${created.id}`, 'PATCH', {
      schemas: [PATCH],
      Operations: [{ op: 'replace', path: 'title', value: 'Engineer' }],
    });
    expect(retitle.status).toBe(200);
    expect((await identityOf(created)).status).toBe('disabled');

    // The IdP's own deactivation and reactivation still round-trip.
    const other = (await (
      await request('Users', 'POST', { userName: 'olivia@acme.test', active: true })
    ).json()) as { id: string };
    const off = { schemas: [PATCH], Operations: [{ op: 'replace', path: 'active', value: false }] };
    const on = { schemas: [PATCH], Operations: [{ op: 'replace', path: 'active', value: true }] };
    expect((await request(`Users/${other.id}`, 'PATCH', off)).status).toBe(200);
    expect((await identityOf(other)).status).toBe('disabled');
    expect((await request(`Users/${other.id}`, 'PATCH', on)).status).toBe(200);
    expect((await identityOf(other)).status).toBe('active');
  });

  it('keeps to the tenant plan limits for people and groups', async () => {
    const { f, request } = await directory();
    const members = (
      await f.database.find<Identity>('identities', { tenantId: f.tenantId, kind: 'user' })
    ).length;
    await f.iam.api.tenants.setLimits(f.rootCredential, {
      tenantId: f.tenantId,
      limits: { identities: members + 1, groups: 0 },
    });
    expect((await request('Users', 'POST', { userName: 'one@acme.test' })).status).toBe(201);
    expect((await request('Users', 'POST', { userName: 'two@acme.test' })).status).toBe(409);
    expect((await request('Groups', 'POST', { displayName: 'Admins' })).status).toBe(409);
  });

  it('fans its audit events out to subscribers', async () => {
    const { f, request } = await directory();
    const seen: string[] = [];
    const unsubscribe = f.iam.events.subscribe('iam:scim:*', (event) => {
      seen.push(event.action);
    });
    try {
      expect((await request('Users', 'POST', { userName: 'sam@acme.test' })).status).toBe(201);
      await f.iam.events.dispatch();
      expect(seen).toContain('iam:scim:CreateUser');
    } finally {
      unsubscribe();
    }
  });

  it('refuses oversized bodies without buffering them', async () => {
    const { service, connection } = await directory();
    const huge = new ReadableStream<Uint8Array>({
      pull(controller) {
        controller.enqueue(new Uint8Array(256 * 1024).fill(0x20));
      },
    });
    const response = await service.handler(
      new Request(`https://iam.test${connection.path}/Users`, {
        method: 'POST',
        headers: { 'content-type': 'application/scim+json' },
        body: huge,
        duplex: 'half',
      } as RequestInit),
    );
    expect(response!.status).toBe(413);
  });
});

describe('outbound SCIM', () => {
  it('adopts a downstream account by email only for a verified address, escaping filter values', async () => {
    const f = await organizationFixture();
    const users = new Map<string, Record<string, unknown>>([
      ['victim-remote', { id: 'victim-remote', userName: 'victim@acme.test', active: true }],
    ]);
    const filters: string[] = [];
    const server = createServer(async (request, response) => {
      let raw = '';
      for await (const chunk of request) raw += String(chunk);
      const url = new URL(request.url!, 'http://scim.test');
      const send = (status: number, body?: unknown) => {
        response.writeHead(status, { 'content-type': 'application/scim+json' });
        response.end(body === undefined ? undefined : JSON.stringify(body));
      };
      if (request.method === 'GET' && url.pathname === '/scim/Users') {
        const filter = url.searchParams.get('filter') ?? '';
        filters.push(filter);
        const [, attribute, value] = /^(\w+) eq (".*")$/.exec(filter)!;
        const wanted = JSON.parse(value!) as string;
        const matches = [...users.values()].filter((user) => user[attribute!] === wanted);
        return send(200, { totalResults: matches.length, Resources: matches });
      }
      if (request.method === 'POST' && url.pathname === '/scim/Users') {
        const user = { ...(JSON.parse(raw) as Record<string, unknown>), id: randomBytes(4).toString('hex') };
        users.set(String(user.id), user);
        return send(201, user);
      }
      const put = /^\/scim\/Users\/(.+)$/.exec(url.pathname);
      if (request.method === 'PUT' && put) {
        users.set(put[1]!, JSON.parse(raw) as Record<string, unknown>);
        return send(200, users.get(put[1]!));
      }
      send(404, { detail: 'not found' });
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    // Someone signs up with the victim's address plus a quote: unverified, and not the same address.
    await f.database.transaction(async (tx) => {
      await tx.insert('identities', {
        id: 'impostor',
        tenantId: f.tenantId,
        name: 'Impostor',
        kind: 'user',
        email: 'victim"@acme.test',
        emailVerified: false,
        status: 'active',
        rootAdmin: false,
        owner: false,
        createdAt: Date.now(),
      });
    });
    const provisioner = createScimProvisioner({
      ...f.iam.protocolHost,
      encryptionKey: randomBytes(32).toString('base64'),
      allowInsecureLocalhost: true,
    });
    const target = await provisioner.createTarget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'App',
      baseUrl: `${origin}/scim`,
      token: 'downstream-provisioning-token',
    });
    await provisioner.syncTarget(f.ownerCredential, { tenantId: f.tenantId, targetId: target.id });
    // The victim's downstream account is untouched and the impostor got an account of their own.
    expect(users.get('victim-remote')).toMatchObject({ userName: 'victim@acme.test' });
    expect(users.get('victim-remote')!.externalId).toBeUndefined();
    expect(filters).toContain('externalId eq "impostor"');
    expect(filters.some((filter) => filter.startsWith('userName eq') && filter.includes('victim'))).toBe(
      false,
    );
  });
});
