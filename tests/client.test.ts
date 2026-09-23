import { describe, expect, expectTypeOf, it, vi } from 'vitest';
import { createIamClient, IamClientError } from '@better-iam/client';
import type { CredentialInput } from '@better-iam/core';

interface ExampleIam {
  api: {
    auth: {
      signIn(input: {
        tenantId: string;
        email: string;
        password: string;
      }): Promise<{ token: string }>;
      getSession(credential: CredentialInput): Promise<{ identity: { id: string } }>;
      changePassword(
        credential: CredentialInput,
        input: { currentPassword: string; password: string },
      ): Promise<{ success: true }>;
      beginMfa(
        credential: CredentialInput | { tenantId: string; challenge: string },
      ): Promise<{ secret: string; uri: string }>;
      confirmMfa(input: {
        credential: CredentialInput | { tenantId: string; challenge: string };
        code: string;
      }): Promise<{ recoveryCodes: string[] }>;
    };
    tenants: {
      create(
        credential: CredentialInput,
        input: { parentId: string; name: string },
      ): Promise<{ tenant: { id: string } }>;
      acceptInvitation(input: {
        tenantId: string;
        token: string;
        name: string;
        password: string;
      }): Promise<{ tenantId: string }>;
    };
  };
  authorize(
    input: CredentialInput & {
      tenantId: string;
      action: string;
      resource: { type: string; id: string };
    },
  ): Promise<{ allowed: boolean }>;
}

/** A slice of the server's `sts` group, for the typed-namespace check. */
interface StsApi {
  getCallerIdentity(credential: CredentialInput): Promise<{ sessionKind: string }>;
}

describe('typed browser client transport', () => {
  it('sends the server JSON contract with mandatory CSRF headers and cookies', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json({ data: { token: 'new-token' } }));
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      fetch: fetcher,
      headers: { 'x-trace-id': 'trace-1', 'x-better-iam': 'wrong', 'content-type': 'text/plain' },
    });
    const input = { tenantId: 'tenant-1', email: 'a@example.com', password: 'a-long-password' };
    expect(await client.auth.signIn(input)).toEqual({ token: 'new-token' });
    const [url, init] = fetcher.mock.calls[0]!;
    expect(String(url)).toBe('https://app.example.com/api/iam/auth/signIn');
    expect(init).toMatchObject({
      method: 'POST',
      credentials: 'include',
      redirect: 'error',
      cache: 'no-store',
    });
    expect(JSON.parse(init!.body as string)).toEqual(input);
    const headers = new Headers(init!.headers);
    expect(headers.get('content-type')).toBe('application/json');
    expect(headers.get('x-better-iam')).toBe('1');
    expect(headers.get('x-trace-id')).toBe('trace-1');
    expect(headers.has('authorization')).toBe(false);
  });

  it('reads the current bearer token at each request and supports per-call cancellation', async () => {
    let token = 'first-token-abcdefghijklmnop';
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => Response.json({ data: { identity: { id: 'user-1' } } }));
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      basePath: '/custom/iam',
      fetch: fetcher,
      token: async () => token,
    });
    const controller = new AbortController();
    await client.auth.getSession({
      signal: controller.signal,
      headers: { 'x-trace-id': 'trace-2' },
    });
    token = 'second-token-abcdefghijklmnop';
    await client.auth.getSession();
    expect(String(fetcher.mock.calls[0]![0])).toBe(
      'https://app.example.com/custom/iam/auth/getSession',
    );
    expect(fetcher.mock.calls[0]![1]!.signal).toBe(controller.signal);
    expect(JSON.parse(fetcher.mock.calls[0]![1]!.body as string)).toEqual({});
    expect(new Headers(fetcher.mock.calls[0]![1]!.headers).get('authorization')).toContain(
      'first-token',
    );
    expect(new Headers(fetcher.mock.calls[1]![1]!.headers).get('authorization')).toContain(
      'second-token',
    );
  });

  it('sends prefixed tokens and session JWTs as bearers and refuses other shapes before any fetch', async () => {
    let token: string | undefined;
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => Response.json({ data: { identity: { id: 'user-1' } } }));
    const client = createIamClient<ExampleIam & { api: { sts: StsApi } }>({
      baseURL: 'https://app.example.com',
      fetch: fetcher,
      token: () => token,
    });
    const segment = (length: number) => 'aB3_-'.repeat(Math.ceil(length / 5)).slice(0, length);
    const prefixed = `biam_sts_${segment(43)}AbC12_`;
    expect(prefixed).toHaveLength(58);
    const jwt = `${segment(40)}.${segment(300)}.${segment(86)}`;
    // The largest JWT the server issues (4096 characters) still passes.
    const largest = `${segment(1024)}.${segment(4096 - 2048 - 2)}.${segment(1024)}`;
    expect(largest).toHaveLength(4096);
    const sent: string[] = [];
    for (const value of [prefixed, jwt, largest]) {
      token = value;
      await client.auth.getSession();
      sent.push(new Headers(fetcher.mock.calls.at(-1)![1]!.headers).get('authorization')!);
    }
    expect(sent).toEqual([`Bearer ${prefixed}`, `Bearer ${jwt}`, `Bearer ${largest}`]);
    token = jwt;
    await client.sts.getCallerIdentity();
    expect(String(fetcher.mock.calls.at(-1)![0])).toBe(
      'https://app.example.com/api/iam/sts/getCallerIdentity',
    );
    expect(JSON.parse(fetcher.mock.calls.at(-1)![1]!.body as string)).toEqual({});
    expectTypeOf(client.sts.getCallerIdentity).returns.resolves.toEqualTypeOf<{
      sessionKind: string;
    }>();

    const calls = fetcher.mock.calls.length;
    for (const value of [
      'short',
      `${segment(16)} `,
      'Bearer abcdefghijklmnopqrstuvwxyz',
      `${segment(10)}.${segment(10)}`,
      `${segment(10)}.${segment(10)}.${segment(10)}.${segment(10)}`,
      `${segment(10)}..${segment(10)}`,
      `${segment(10)}.${segment(10)}.`,
      `${segment(10)}.${segment(1)}.${segment(10)}`,
      `${segment(10)}.${segment(10)}.${segment(10)}=`,
      `${segment(1025)}.${segment(10)}.${segment(10)}`,
      `${segment(1024)}.${segment(2049)}.${segment(1024)}`,
      segment(513),
    ]) {
      token = value;
      const refused = await client.auth.getSession().catch((error: unknown) => error);
      expect(refused).toBeInstanceOf(IamClientError);
      expect(refused).toMatchObject({ code: 'INVALID_TOKEN', status: 0 });
    }
    expect(fetcher.mock.calls).toHaveLength(calls);
  });

  it('reads the only argument of credential-only methods outside auth as call options', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => Response.json({ data: { sessionKind: 'sts' } }));
    const client = createIamClient<
      ExampleIam & {
        api: {
          sts: StsApi;
          links: { list(credential: CredentialInput): Promise<{ id: string }[]> };
        };
      }
    >({ baseURL: 'https://app.example.com', fetch: fetcher });
    const controller = new AbortController();
    await client.sts.getCallerIdentity({
      signal: controller.signal,
      headers: { 'x-trace': '1' },
    });
    await client.links.list({ signal: controller.signal, headers: { 'x-trace': '2' } });
    for (const [index, path] of ['sts/getCallerIdentity', 'links/list'].entries()) {
      const [url, init] = fetcher.mock.calls[index]!;
      expect(String(url)).toBe(`https://app.example.com/api/iam/${path}`);
      expect(JSON.parse(init!.body as string)).toEqual({});
      expect(init!.signal).toBe(controller.signal);
      expect(new Headers(init!.headers).get('x-trace')).toBe(String(index + 1));
    }
    expectTypeOf(client.sts.getCallerIdentity).parameters.toEqualTypeOf<
      [options?: { signal?: AbortSignal; headers?: HeadersInit }]
    >();
  });

  it('omits authenticated credentials from the client API while retaining public invitation tokens', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => Response.json({ data: {} }));
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      fetch: fetcher,
    });
    await client.tenants.create({ parentId: 'root', name: 'Organization' });
    await client.tenants.acceptInvitation({
      tenantId: 'org',
      token: 'invitation-token',
      name: 'Owner',
      password: 'long-password',
    });
    await client.auth.beginMfa();
    await client.auth.beginMfa({ tenantId: 'org', challenge: 'restricted-challenge' });
    await client.auth.confirmMfa({ code: '123456' });
    await client.auth.confirmMfa({
      credential: { tenantId: 'root', challenge: 'restricted-challenge' },
      code: '123456',
    });
    expect(JSON.parse(fetcher.mock.calls[0]![1]!.body as string)).toEqual({
      parentId: 'root',
      name: 'Organization',
    });
    expect(JSON.parse(fetcher.mock.calls[1]![1]!.body as string).token).toBe('invitation-token');
    expect(JSON.parse(fetcher.mock.calls[2]![1]!.body as string)).toEqual({});
    expect(JSON.parse(fetcher.mock.calls[3]![1]!.body as string).challenge).toBe(
      'restricted-challenge',
    );
    expectTypeOf(client.auth.signIn)
      .parameter(0)
      .toEqualTypeOf<{ tenantId: string; email: string; password: string }>();
    expectTypeOf(client.tenants.create)
      .parameter(0)
      .toEqualTypeOf<{ parentId: string; name: string }>();
    expectTypeOf(client.auth.getSession).returns.resolves.toEqualTypeOf<{
      identity: { id: string };
    }>();
    expectTypeOf(client.tenants.acceptInvitation)
      .parameter(0)
      .toEqualTypeOf<{ tenantId: string; token: string; name: string; password: string }>();
  });

  it('retains structured API errors and rejects malformed responses without echoing their content', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(
        Response.json({ error: { code: 'MFA_REQUIRED', message: 'Use MFA' } }, { status: 403 }),
      )
      .mockResolvedValueOnce(new Response('<html>private upstream details</html>', { status: 502 }))
      .mockResolvedValueOnce(Response.json({ wrong: 'shape' }))
      .mockResolvedValueOnce(Response.json({ data: null }, { status: 503 }));
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      fetch: fetcher,
    });
    await expect(client.auth.getSession()).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
      message: 'Use MFA',
      status: 403,
    });
    await expect(client.auth.getSession()).rejects.toMatchObject({
      code: 'INVALID_RESPONSE',
      status: 502,
    });
    await expect(client.auth.getSession()).rejects.toBeInstanceOf(IamClientError);
    await expect(client.auth.getSession()).rejects.toMatchObject({
      code: 'HTTP_ERROR',
      status: 503,
    });
  });

  it('provides authorize and plugin transports while rejecting URL traversal and thenable properties', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockImplementation(async () => Response.json({ data: { allowed: true } }));
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      fetch: fetcher,
    });
    const result = await client.authorize({
      tenantId: 'org',
      action: 'documents:read',
      resource: { type: 'document', id: 'one' },
    });
    expectTypeOf(result).toEqualTypeOf<{ allowed: boolean }>();
    expect(result.allowed).toBe(true);
    await client.$request('plugins/reporting/summary', { tenantId: 'org' });
    expect(String(fetcher.mock.calls[0]![0])).toContain('/authorize');
    expect(String(fetcher.mock.calls[1]![0])).toContain('/plugins/reporting/summary');
    await expect(client.$request('../secrets')).rejects.toMatchObject({ code: 'INVALID_PATH' });
    await expect(client.$request('https://attacker.example')).rejects.toMatchObject({
      code: 'INVALID_PATH',
    });
    await expect(Promise.resolve(client)).resolves.toBe(client);
    expect(Reflect.get(client, '__proto__')).toBeUndefined();
  });
});
