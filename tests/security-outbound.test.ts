import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import { createServer as createTcpServer, type AddressInfo, type Server as TcpServer } from 'node:net';
import { afterEach, describe, expect, it } from 'vitest';
import { createGuardedFetch, isPublicAddress, SafeFetchError } from '@better-iam/auth';
import { IamError } from '@better-iam/core';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createSharedSignalsTransmitter } from '@better-iam/oauth';
import { createScimProvisioner } from '@better-iam/scim';
import { closeFixtures, organizationFixture } from './support/organization.js';

/**
 * Outbound requests to URLs tenants choose (webhooks, SCIM targets, Shared Signals receivers, AI provider base URLs)
 * must not reach the server's own network, and write-only credentials stored with them must not follow a URL change.
 */

const servers: (Server | TcpServer)[] = [];
afterEach(async () => {
  for (const server of servers.splice(0)) {
    if ('closeAllConnections' in server) server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await closeFixtures();
});

async function httpServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
}

/** A raw TCP listener on loopback that counts connection attempts (TLS or not). */
async function tcpListener(): Promise<{ port: number; connections: () => number }> {
  let count = 0;
  const server = createTcpServer((socket) => {
    count++;
    socket.destroy();
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  return { port: (server.address() as AddressInfo).port, connections: () => count };
}

async function refusal(promise: Promise<unknown>): Promise<unknown> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(TypeError);
  return (error as TypeError).cause;
}

describe('guarded fetch', () => {
  it('treats IPv4-translated IPv6 addresses as non-public', () => {
    expect(isPublicAddress('::ffff:0:7f00:1')).toBe(false);
    expect(isPublicAddress('::ffff:0:a9fe:a9fe')).toBe(false);
    // Public IPv4, in either spelling, stays public.
    expect(isPublicAddress('8.8.8.8')).toBe(true);
    expect(isPublicAddress('::ffff:8.8.8.8')).toBe(true);
    expect(isPublicAddress('2606:4700:4700::1111')).toBe(true);
  });

  it('refuses private literals and hosts that resolve to private addresses, before connecting', async () => {
    const guarded = createGuardedFetch({ anyPort: true });
    const listener = await tcpListener();
    for (const url of [
      'https://10.0.0.5:8443/hook',
      'https://169.254.169.254/latest/meta-data',
      'https://[::1]:6443/',
      'https://[::ffff:0:7f00:1]/',
      `https://127.0.0.1:${listener.port}/`,
    ]) {
      const cause = await refusal(guarded(url, { method: 'POST', body: '{}' }));
      expect(cause).toBeInstanceOf(SafeFetchError);
      expect((cause as SafeFetchError).reason).toBe('address');
    }
    // A hostname is judged when it is resolved: localhost is loopback.
    const cause = await refusal(guarded(`https://localhost:${listener.port}/`, { method: 'POST' }));
    expect((cause as SafeFetchError).reason).toBe('address');
    expect(listener.connections()).toBe(0);
    // Plain http and other schemes are refused outright.
    expect(
      ((await refusal(guarded('http://example.com/'))) as SafeFetchError).reason,
    ).toBe('url');
    expect(
      ((await refusal(guarded('file:///etc/passwd'))) as SafeFetchError).reason,
    ).toBe('url');
  });

  it('keeps non-443 ports closed unless anyPort is set', async () => {
    const cause = await refusal(createGuardedFetch()('https://example.com:8443/'));
    expect((cause as SafeFetchError).reason).toBe('url');
  });

  it('works like fetch against an allowed endpoint: method, headers, body, status and streamed body', async () => {
    const seen: { method?: string; type?: string; body?: string } = {};
    const origin = await httpServer(async (request, response) => {
      let body = '';
      for await (const chunk of request) body += String(chunk);
      Object.assign(seen, {
        method: request.method,
        type: request.headers['content-type'],
        body,
      });
      response.writeHead(201, { 'content-type': 'application/json', 'x-reply': 'yes' });
      response.end(JSON.stringify({ ok: true }));
    });
    const guarded = createGuardedFetch({ allowInsecureLocalhost: true });
    const response = await guarded(`${origin}/in`, {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ hello: 'world' }),
    });
    expect(response.status).toBe(201);
    expect(response.headers.get('x-reply')).toBe('yes');
    expect(await response.json()).toEqual({ ok: true });
    expect(seen).toEqual({
      method: 'POST',
      type: 'application/json',
      body: '{"hello":"world"}',
    });
  });

  it('never follows redirects', async () => {
    const origin = await httpServer((_request, response) => {
      response.writeHead(302, { location: 'http://169.254.169.254/' });
      response.end();
    });
    const guarded = createGuardedFetch({ allowInsecureLocalhost: true });
    const manual = await guarded(`${origin}/r`);
    expect(manual.status).toBe(302);
    const cause = await refusal(guarded(`${origin}/r`, { redirect: 'error' }));
    expect((cause as SafeFetchError).reason).toBe('redirect');
  });

  it('bounds response bodies and honours abort signals', async () => {
    const origin = await httpServer((request, response) => {
      if (request.url === '/slow') return void setTimeout(() => response.end('late'), 2000);
      response.writeHead(200, { 'content-type': 'text/plain' });
      response.end('x'.repeat(4096));
    });
    const guarded = createGuardedFetch({ allowInsecureLocalhost: true, maxBytes: 1024 });
    await expect((await guarded(`${origin}/big`)).text()).rejects.toThrow();
    await expect(
      guarded(`${origin}/slow`, { signal: AbortSignal.timeout(100) }),
    ).rejects.toMatchObject({ name: 'TimeoutError' });
  });
});

describe('webhook endpoints', () => {
  it('refuses private and reserved addresses on an https deployment', async () => {
    const f = await organizationFixture({ baseURL: 'https://iam.example.test' });
    for (const url of [
      'https://10.0.0.5:8443/hook',
      'https://169.254.169.254/latest/meta-data',
      'https://127.0.0.1:2379/v2/keys',
      'https://[::1]:6443/',
      'https://[::ffff:10.0.0.1]/',
    ])
      await expect(
        f.iam.api.webhooks.create(f.ownerCredential, {
          tenantId: f.tenantId,
          url,
          events: ['iam:groups:create'],
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('never connects to a hostname that resolves to a private address, and reports no network detail', async () => {
    const f = await organizationFixture({ baseURL: 'https://iam.example.test' });
    const listener = await tcpListener();
    const { webhook } = await f.iam.api.webhooks.create(f.ownerCredential, {
      tenantId: f.tenantId,
      url: `https://localhost:${listener.port}/hook`,
      events: ['iam:groups:create'],
    });
    await f.iam.api.webhooks.ping(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
    });
    expect(await f.iam.auth.dispatchOutbox()).toMatchObject({ delivered: 0, failed: 1 });
    expect(listener.connections()).toBe(0);
    const [delivery] = await f.iam.api.webhooks.listDeliveries(f.ownerCredential, {
      tenantId: f.tenantId,
      webhookId: webhook.id,
    });
    expect(delivery!.lastError).toContain('could not be reached');
  });

  it('lets a deployment opt in to private networks', async () => {
    const f = await organizationFixture({
      baseURL: 'https://iam.example.test',
      events: { allowPrivateNetworks: true },
    });
    const { webhook } = await f.iam.api.webhooks.create(f.ownerCredential, {
      tenantId: f.tenantId,
      url: 'https://10.0.0.5:8443/hook',
      events: ['iam:groups:create'],
    });
    expect(webhook.url).toBe('https://10.0.0.5:8443/hook');
  });
});

describe('outbound SCIM targets', () => {
  const TOKEN = 'downstream-provisioning-token';
  const provisioner = (store: ReturnType<typeof sqliteAdapter>) =>
    createScimProvisioner({
      store,
      encryptionKey: randomBytes(32).toString('base64'),
      allowInsecureLocalhost: true,
      authenticate: async () => ({ identity: { id: 'admin' } }),
      authorize: async (credential) => {
        if (credential.token !== 'admin') throw new IamError('ACCESS_DENIED', 'Forbidden', 403);
      },
    });

  it('refuses private base URLs and keeps the token from following a base URL change', async () => {
    const store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
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
      await tx.insert('identities', {
        id: 'ada',
        tenantId: 'a',
        name: 'Ada',
        kind: 'user',
        email: 'ada@acme.test',
        emailVerified: true,
        status: 'active',
        rootAdmin: false,
        owner: false,
        createdAt: Date.now(),
      });
    });
    try {
      const scim = provisioner(store);
      const admin = { token: 'admin' };
      for (const baseUrl of ['https://10.0.0.1:8443/scim', 'https://[fd00::1]/scim'])
        await expect(
          scim.createTarget(admin, { tenantId: 'a', name: 'Internal', baseUrl, token: TOKEN }),
        ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
      const received: (string | undefined)[] = [];
      const origin = await httpServer((request, response) => {
        received.push(request.headers.authorization);
        response.writeHead(200, { 'content-type': 'application/scim+json' });
        response.end(JSON.stringify({ totalResults: 0, Resources: [] }));
      });
      const target = await scim.createTarget(admin, {
        tenantId: 'a',
        name: 'App',
        baseUrl: 'https://app.example.test/scim/v2',
        token: TOKEN,
      });
      await expect(
        scim.updateTarget(admin, { tenantId: 'a', targetId: target.id, baseUrl: `${origin}/scim` }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
      // Renaming keeps the token; a new URL with a new token is fine.
      await scim.updateTarget(admin, { tenantId: 'a', targetId: target.id, name: 'Renamed' });
      const moved = await scim.updateTarget(admin, {
        tenantId: 'a',
        targetId: target.id,
        baseUrl: `${origin}/scim`,
        token: 'a-new-downstream-token',
      });
      expect(moved.baseUrl).toBe(`${origin}/scim`);
      await scim.previewTarget(admin, { tenantId: 'a', targetId: target.id });
      expect(received.length).toBeGreaterThan(0);
      expect(received.every((value) => value === 'Bearer a-new-downstream-token')).toBe(true);
    } finally {
      await store.close();
    }
  });
});

describe('Shared Signals receivers', () => {
  const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
  const privateJwk = { ...pair.privateKey.export({ format: 'jwk' }), kid: 'k', alg: 'RS256' };

  it('refuses private endpoints and keeps the stored authorization from following an endpoint change', async () => {
    const fixture = await organizationFixture();
    const transmitter = createSharedSignalsTransmitter({
      ...fixture.iam.protocolHost,
      issuer: 'https://id.example.test/oidc',
      jwks: { keys: [privateJwk] },
      encryptionKey: randomBytes(32).toString('base64'),
      allowInsecureLocalhost: true,
    });
    const { tenantId, ownerCredential } = fixture;
    for (const endpointUrl of ['https://10.0.0.1/events', 'https://169.254.169.254/events'])
      await expect(
        transmitter.createStream(ownerCredential, { tenantId, name: 'SIEM', endpointUrl }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const received: (string | undefined)[] = [];
    const origin = await httpServer((request, response) => {
      received.push(request.headers.authorization);
      response.writeHead(202);
      response.end();
    });
    const stream = await transmitter.createStream(ownerCredential, {
      tenantId,
      name: 'SIEM',
      endpointUrl: 'https://siem.example.test/events',
      authorization: 'Bearer receiver-secret',
    });
    await expect(
      transmitter.updateStream(ownerCredential, {
        tenantId,
        streamId: stream.id,
        endpointUrl: `${origin}/events`,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await transmitter.updateStream(ownerCredential, {
      tenantId,
      streamId: stream.id,
      endpointUrl: `${origin}/events`,
      authorization: null,
    });
    expect(
      (await transmitter.verifyStream(ownerCredential, { tenantId, streamId: stream.id }))
        .delivered,
    ).toBe(true);
    expect(received).toEqual([undefined]);
  });
});
