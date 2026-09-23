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

async function fixture(trustProxy = false) {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'session-metadata-test-secret-with-32-chars!',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
    },
    http: trustProxy
      ? {
          clientInfo: (request) => ({
            ip: request.headers.get('x-forwarded-for')?.split(',')[0]?.trim(),
            userAgent: request.headers.get('user-agent') ?? undefined,
            label: request.headers.get('x-device-name') ?? undefined,
          }),
        }
      : undefined,
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
  const generator = authenticator.clone();
  generator.options = { epoch: clock };
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: generator.generate(enrollment.secret),
  });
  const created = await iam.api.tenants.create(
    { token: session.token },
    {
      parentId: root.tenant.id,
      name: 'Acme',
      type: 'organization',
      ownerEmail: 'owner@acme.test',
    },
  );
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
  await iam.api.identities.create(
    { token: owner.token },
    {
      tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    },
  );
  const http = async (path: string, body: unknown, headers: Record<string, string> = {}) => {
    const response = await iam.handler(
      new Request(`http://localhost:3000/api/iam/${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1', ...headers },
        body: JSON.stringify(body),
      }),
    );
    return { status: response.status, ...((await response.json()) as { data?: any; error?: any }) };
  };
  const signIn = (headers: Record<string, string> = {}) =>
    http(
      'auth/signIn',
      { tenantId, email: 'alice@acme.test', password: 'a strong alice password' },
      headers,
    );
  return {
    iam,
    tenantId,
    http,
    signIn,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('session metadata', () => {
  it('records the user agent by default and proxy-derived details through http.clientInfo', async () => {
    const f = await fixture();
    const phone = await f.signIn({
      'user-agent': 'Acme Mobile/2.1 (iOS)',
      'x-forwarded-for': '203.0.113.9',
    });
    expect(phone.status).toBe(200);
    expect(phone.data.session.client).toEqual({ userAgent: 'Acme Mobile/2.1 (iOS)' });
    const bare = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in bare)) throw new Error('Unexpected MFA');
    expect(bare.session.client).toBeUndefined();
    const sessions = await f.iam.api.auth.listSessions({ token: bare.token });
    expect(sessions.map((item) => item.client?.userAgent ?? null).sort()).toEqual([
      'Acme Mobile/2.1 (iOS)',
      null,
    ]);
    const trusted = await fixture(true);
    const laptop = await trusted.signIn({
      'user-agent': 'Mozilla/5.0 Laptop',
      'x-forwarded-for': '198.51.100.7, 10.0.0.1',
      'x-device-name': 'Work laptop',
    });
    expect(laptop.data.session.client).toEqual({
      ip: '198.51.100.7',
      userAgent: 'Mozilla/5.0 Laptop',
      label: 'Work laptop',
    });
    // Control characters are stripped and long values bounded; empty details are omitted entirely.
    const noisy = await trusted.signIn({
      'user-agent': `bad\u0001agent ${'x'.repeat(600)}`,
      'x-forwarded-for': '   ',
    });
    expect(noisy.data.session.client.userAgent).toHaveLength(512);
    expect(noisy.data.session.client.userAgent.startsWith('badagent')).toBe(true);
    expect(noisy.data.session.client.ip).toBeUndefined();
  });

  it('signs out every other session with recent authentication', async () => {
    const f = await fixture();
    const first = await f.signIn({ 'user-agent': 'first' });
    const second = await f.signIn({ 'user-agent': 'second' });
    const third = await f.signIn({ 'user-agent': 'third' });
    const revoked = await f.http(
      'auth/revokeOtherSessions',
      {},
      {
        authorization: `Bearer ${third.data.token}`,
      },
    );
    expect(revoked.status).toBe(200);
    expect(revoked.data).toEqual({ revoked: 2 });
    for (const gone of [first, second])
      await expect(f.iam.api.auth.getSession({ token: gone.data.token })).rejects.toMatchObject({
        code: 'UNAUTHENTICATED',
      });
    expect((await f.iam.api.auth.getSession({ token: third.data.token })).session.id).toBe(
      third.data.session.id,
    );
    const events = await f.iam.store.find('audit', {
      tenantId: f.tenantId,
      action: 'auth:session:revoke-others',
    });
    expect(events).toHaveLength(1);
    f.advance(6 * 60_000);
    const stale = await f.http(
      'auth/revokeOtherSessions',
      {},
      {
        authorization: `Bearer ${third.data.token}`,
      },
    );
    expect(stale.status).toBe(403);
    expect(stale.error.code).toBe('RECENT_AUTH_REQUIRED');
  });
});
