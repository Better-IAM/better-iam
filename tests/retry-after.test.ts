import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { createIamClient } from '@better-iam/client';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';

const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

describe('rate-limit responses', () => {
  it('tell callers when to retry, over HTTP and through the typed client', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    databases.push(database);
    const iam = betterIam({
      database,
      secret: 'retry-after-test-secret-with-at-least-32-chars',
      baseURL: 'http://localhost:3000',
      authentication: { rateLimits: { attempts: 2, windowMs: 90_000 } },
    });
    await iam.initialize();
    const root = await iam.bootstrap({
      email: 'root@example.test',
      name: 'Root',
      password: 'a strong root test password',
    });
    const attempt = () =>
      iam.api.auth.signIn({ tenantId: root.tenant.id, email: 'root@example.test', password: 'no' });
    await expect(attempt()).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(attempt()).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(attempt()).rejects.toMatchObject({
      code: 'RATE_LIMITED',
      status: 429,
      retryAfterMs: 90_000,
    });
    const response = await iam.handler(
      new Request('http://localhost:3000/api/iam/auth/signIn', {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-better-iam': '1' },
        body: JSON.stringify({
          tenantId: root.tenant.id,
          email: 'root@example.test',
          password: 'no',
        }),
      }),
    );
    expect(response.status).toBe(429);
    expect(response.headers.get('retry-after')).toBe('90');
    expect(await response.json()).toEqual({
      error: {
        code: 'RATE_LIMITED',
        message: 'Too many attempts; try again later',
        retryAfterMs: 90_000,
      },
    });
    const client = createIamClient<typeof iam>({
      baseURL: 'http://localhost:3000',
      fetch: async (input, init) => iam.handler(new Request(input, init)),
    });
    await expect(
      client.auth.signIn({ tenantId: root.tenant.id, email: 'root@example.test', password: 'no' }),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED', status: 429, retryAfterMs: 90_000 });
  });
});
