import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type IamSpan } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

describe('HTTP hygiene and account status', () => {
  it('hardens every JSON response, echoes request IDs into headers and spans, and reports MFA status', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    const spans: IamSpan[] = [];
    const iam = betterIam({
      database,
      secret: 'http-hygiene-test-secret-with-at-least-32-chars',
      baseURL: 'http://localhost:3000',
      observability: { onSpan: (span) => void spans.push(span) },
    });
    await iam.initialize();
    const root = await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const alice = await iam.store.transaction((tx) =>
      iam.auth.createIdentity(tx, {
        tenantId: root.tenant.id,
        email: 'alice@example.test',
        name: 'Alice',
        password: 'a strong alice password',
        emailVerified: true,
      }),
    );
    const post = (path: string, body: unknown, headers: Record<string, string> = {}) =>
      iam.handler(
        new Request(`http://localhost:3000/api/iam/${path}`, {
          method: 'POST',
          headers: { 'content-type': 'application/json', 'x-better-iam': '1', ...headers },
          body: JSON.stringify(body),
        }),
      );
    // A well-formed request ID comes back on success and on errors, and lands on the HTTP span.
    const ok = await post(
      'auth/signIn',
      {
        tenantId: root.tenant.id,
        email: 'alice@example.test',
        password: 'a strong alice password',
      },
      { 'x-request-id': 'req-123.abc' },
    );
    expect(ok.status).toBe(200);
    expect(ok.headers.get('x-request-id')).toBe('req-123.abc');
    expect(ok.headers.get('x-content-type-options')).toBe('nosniff');
    expect(ok.headers.get('referrer-policy')).toBe('no-referrer');
    expect(ok.headers.get('cache-control')).toBe('no-store');
    expect(spans.find((span) => span.kind === 'http')).toMatchObject({
      name: 'auth/signIn',
      requestId: 'req-123.abc',
      outcome: 'ok',
    });
    const denied = await post(
      'groups/create',
      { tenantId: root.tenant.id, name: 'x' },
      { 'x-request-id': 'req-456' },
    );
    expect(denied.status).toBe(401);
    expect(denied.headers.get('x-request-id')).toBe('req-456');
    expect(denied.headers.get('x-content-type-options')).toBe('nosniff');
    // Hostile or oversized IDs are dropped rather than echoed.
    const junk = await post('auth/signIn', {}, { 'x-request-id': 'bad id <script>' });
    expect(junk.headers.get('x-request-id')).toBeNull();
    const long = await post('auth/signIn', {}, { 'x-request-id': 'a'.repeat(200) });
    expect(long.headers.get('x-request-id')).toBeNull();
    // Operational endpoints carry the same hardening.
    const health = await iam.handler(new Request('http://localhost:3000/api/iam/health'));
    expect(health.headers.get('x-content-type-options')).toBe('nosniff');
    // Session lists mark the caller's own session; the MFA status summarizes what is set up.
    const { token } = ((await ok.json()) as { data: { token: string } }).data;
    const other = await iam.api.auth.signIn({
      tenantId: root.tenant.id,
      email: 'alice@example.test',
      password: 'a strong alice password',
    });
    if (!('token' in other)) throw new Error('Unexpected MFA');
    const sessions = await iam.api.auth.listSessions({ token });
    expect(sessions).toHaveLength(2);
    expect(sessions.filter((session) => session.current)).toHaveLength(1);
    expect(sessions.find((session) => session.current)!.id).not.toBe(other.session.id);
    expect(await iam.api.auth.mfaStatus({ token })).toEqual({
      enabled: false,
      recoveryCodesRemaining: 0,
      passkeys: 0,
      trustedDevices: 0,
      sessionMfa: false,
    });
    void alice;
  });
});
