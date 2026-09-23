import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createServer, request, type Server, type IncomingHttpHeaders } from 'node:http';
import { once } from 'node:events';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';

let server: Server;
let store: IamStore;
let port: number;
beforeEach(async () => {
  store = sqliteAdapter({ filename: ':memory:' });
  const iam = betterIam({
    database: store,
    secret: 'node-transport-test-secret-at-least-32-characters',
    baseURL: 'https://iam.example.com',
    authentication: { sendEmail: async () => {} },
    protocols: [
      {
        handle: async (req) =>
          new URL(req.url).pathname === '/federation/callback'
            ? Response.json(
                { token: 'issued-session-token', session: { expiresAt: Date.now() + 60_000 } },
                {
                  headers: {
                    'set-cookie': '__Host-federation-binding=; Path=/; Secure; HttpOnly; Max-Age=0',
                  },
                },
              )
            : undefined,
        nodeHandler: (req) => {
          if (req.url === '/protocol/failure')
            throw new Error('private-driver-detail-must-not-leak');
          return false;
        },
      },
    ],
  });
  await iam.initialize();
  // Use the exported listener directly, as consumers of the Node integration do.
  server = createServer(iam.nodeHandler);
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('Expected local TCP server');
  port = address.port;
});
afterEach(async () => {
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
  await store.close();
});

function send(
  method: string,
  path: string,
): Promise<{ status: number; headers: IncomingHttpHeaders; body: string }> {
  return new Promise((resolve, reject) => {
    const outgoing = request(
      { hostname: '127.0.0.1', port, method, path, agent: false },
      (incoming) => {
        const chunks: Buffer[] = [];
        incoming.on('data', (chunk) => chunks.push(Buffer.from(chunk)));
        incoming.on('error', reject);
        incoming.on('end', () =>
          resolve({
            status: incoming.statusCode!,
            headers: incoming.headers,
            body: Buffer.concat(chunks).toString('utf8'),
          }),
        );
      },
    );
    outgoing.on('error', reject);
    outgoing.end();
  });
}

describe('native Node transport', () => {
  it('preserves every cookie when a federation callback sets the IAM session', async () => {
    const response = await send('POST', '/federation/callback');
    expect(response.status).toBe(200);
    expect(response.headers['set-cookie']).toHaveLength(2);
    expect(response.headers['set-cookie']?.[0]).toContain('__Host-federation-binding=;');
    expect(response.headers['set-cookie']?.[1]).toContain(
      '__Host-better-iam.session=issued-session-token;',
    );
    expect(response.headers['set-cookie']?.[1]).toContain('HttpOnly; Secure; SameSite=Lax');
  });

  it('responds safely to TRACE instead of rejecting the asynchronous listener', async () => {
    const response = await send('TRACE', '/api/iam/auth/signIn');
    expect(response.status).toBe(405);
    expect(JSON.parse(response.body)).toEqual({
      error: { code: 'METHOD_NOT_ALLOWED', message: 'Method is not supported' },
    });
  });

  it('contains protocol errors without leaking details or crashing the listener', async () => {
    const response = await send('GET', '/protocol/failure');
    expect(response.status).toBe(500);
    expect(response.body).not.toContain('private-driver-detail');
    expect(JSON.parse(response.body).error.code).toBe('INTERNAL_ERROR');
    expect((await send('TRACE', '/')).status).toBe(405);
  });

  it('rejects malformed absolute request targets safely', async () => {
    expect((await send('GET', 'http://[')).status).toBe(400);
  });
});
