import { afterEach, describe, expect, it, vi } from 'vitest';
import { createIamClient, IamClientError } from '@better-iam/client';
import type { CredentialInput } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

interface ExampleIam {
  api: {
    auth: {
      signIn(input: {
        tenantId: string;
        email: string;
        password: string;
      }): Promise<{ token: string }>;
      getSession(credential: CredentialInput): Promise<{ identity: { id: string } }>;
    };
  };
}

const failure = (code: string, status: number, extra: Record<string, unknown> = {}, headers = {}) =>
  Response.json({ error: { code, message: code, ...extra } }, { status, headers });

describe('client hooks', () => {
  it('reports lapsed sessions once per request through onUnauthenticated, never credential failures', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(failure('UNAUTHENTICATED', 401))
      .mockResolvedValueOnce(failure('INVALID_CREDENTIALS', 401))
      .mockResolvedValueOnce(Response.json({ data: { identity: { id: 'usr_1' } } }));
    const onUnauthenticated = vi.fn((error: IamClientError) => {
      throw new Error(`hook failure for ${error.code}`);
    });
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      fetch: fetcher,
      onUnauthenticated,
    });
    await expect(client.auth.getSession()).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
      status: 401,
    });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
    // A wrong password is the caller's problem, not a lapsed session.
    await expect(
      client.auth.signIn({ tenantId: 't', email: 'a@example.com', password: 'wrong' }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
    expect(await client.auth.getSession()).toEqual({ identity: { id: 'usr_1' } });
  });

  it('treats a session refused from another network as ended, but not sign-in or step-up refusals', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(failure('SESSION_NETWORK_MISMATCH', 401))
      .mockResolvedValueOnce(failure('MFA_REQUIRED', 403))
      .mockResolvedValueOnce(failure('EMAIL_UNVERIFIED', 403))
      .mockResolvedValueOnce(failure('IP_BLOCKED', 403))
      .mockResolvedValueOnce(failure('INVALID_CREDENTIALS', 401));
    const onUnauthenticated = vi.fn();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      fetch: fetcher,
      onUnauthenticated,
    });
    await expect(client.auth.getSession()).rejects.toMatchObject({
      code: 'SESSION_NETWORK_MISMATCH',
      status: 401,
    });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
    expect(onUnauthenticated.mock.calls[0]![0]).toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
    // These are also raised by sign-in and step-up flows, where a trip to the login page would not help.
    for (const code of ['MFA_REQUIRED', 'EMAIL_UNVERIFIED', 'IP_BLOCKED'])
      await expect(client.auth.getSession()).rejects.toMatchObject({ code });
    await expect(
      client.auth.signIn({ tenantId: 't', email: 'a@example.com', password: 'wrong' }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
  });

  it('reports a network-bound session presented from elsewhere against a real server', async () => {
    const f = await organizationFixture({
      http: {
        clientInfo: (request) => ({ ip: request.headers.get('x-test-ip') ?? undefined }),
      },
    });
    await f.member('alice');
    const session = await f.iam.auth.withClient({ ip: '203.0.113.7' }, () => f.signIn('alice'));
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { bindSessionsToIp: true },
    });
    const onUnauthenticated = vi.fn();
    const from = (ip: string) =>
      createIamClient<typeof f.iam>({
        baseURL: 'http://localhost:3000',
        token: session.token,
        headers: { 'x-test-ip': ip },
        fetch: async (input, init) => f.iam.handler(new Request(input, init)),
        onUnauthenticated,
      });
    expect((await from('203.0.113.7').auth.getSession()).session.id).toBe(session.session.id);
    await expect(from('198.51.100.9').auth.getSession()).rejects.toMatchObject({
      code: 'SESSION_NETWORK_MISMATCH',
      status: 401,
    });
    expect(onUnauthenticated).toHaveBeenCalledTimes(1);
    expect(onUnauthenticated.mock.calls[0]![0]).toMatchObject({ code: 'SESSION_NETWORK_MISMATCH' });
  });

  it('retries a rate-limited call once after the server wait when that wait is short enough', async () => {
    vi.useFakeTimers();
    try {
      const fetcher = vi
        .fn<typeof fetch>()
        .mockResolvedValueOnce(failure('RATE_LIMITED', 429, { retryAfterMs: 1_500 }))
        .mockResolvedValueOnce(Response.json({ data: { identity: { id: 'usr_1' } } }))
        .mockResolvedValueOnce(failure('RATE_LIMITED', 429, { retryAfterMs: 60_000 }))
        .mockResolvedValueOnce(failure('RATE_LIMITED', 429, { retryAfterMs: 1_000 }))
        .mockResolvedValueOnce(failure('RATE_LIMITED', 429, { retryAfterMs: 1_000 }));
      const client = createIamClient<ExampleIam>({
        baseURL: 'https://app.example.com',
        fetch: fetcher,
        retryRateLimited: { maxWaitMs: 2_000 },
      });
      const pending = client.auth.getSession();
      await vi.advanceTimersByTimeAsync(1_500);
      expect(await pending).toEqual({ identity: { id: 'usr_1' } });
      expect(fetcher).toHaveBeenCalledTimes(2);
      // A wait beyond the cap surfaces the error unchanged; a second refusal after the retry does too.
      await expect(client.auth.getSession()).rejects.toMatchObject({
        code: 'RATE_LIMITED',
        retryAfterMs: 60_000,
      });
      expect(fetcher).toHaveBeenCalledTimes(3);
      const twice = client.auth.getSession();
      const settled = expect(twice).rejects.toMatchObject({ code: 'RATE_LIMITED' });
      await vi.advanceTimersByTimeAsync(1_000);
      await settled;
      expect(fetcher).toHaveBeenCalledTimes(5);
      // Off by default.
      const plain = createIamClient<ExampleIam>({
        baseURL: 'https://app.example.com',
        fetch: vi
          .fn<typeof fetch>()
          .mockResolvedValue(failure('RATE_LIMITED', 429, { retryAfterMs: 10 })),
      });
      await expect(plain.auth.getSession()).rejects.toMatchObject({ code: 'RATE_LIMITED' });
    } finally {
      vi.useRealTimers();
    }
  });

  it('stops waiting to retry the moment the call is aborted', async () => {
    vi.useFakeTimers();
    try {
      const limited = () => failure('RATE_LIMITED', 429, { retryAfterMs: 4_000 });
      // The stub ignores the signal, as if the abort landed after the response arrived.
      const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => limited());
      const client = createIamClient<ExampleIam>({
        baseURL: 'https://app.example.com',
        fetch: fetcher,
        retryRateLimited: true,
      });
      // Observes a call without awaiting it, so a call that hangs fails the assertion instead of the timeout.
      const watch = (promise: Promise<unknown>) => {
        const state: { settled: boolean; value?: unknown } = { settled: false };
        const settle = (value: unknown) => Object.assign(state, { settled: true, value });
        promise.then(settle, settle);
        return state;
      };
      // Aborted during the wait: the call rejects at once with the signal's reason and sends nothing more.
      const reason = new Error('search cancelled');
      const controller = new AbortController();
      const cancelled = watch(client.auth.getSession({ signal: controller.signal }));
      await vi.advanceTimersByTimeAsync(100);
      expect(cancelled.settled).toBe(false);
      controller.abort(reason);
      await vi.advanceTimersByTimeAsync(0);
      expect(cancelled).toEqual({ settled: true, value: reason });
      expect(vi.getTimerCount()).toBe(0);
      expect(fetcher).toHaveBeenCalledTimes(1);
      // Without a reason, the rejection is the standard AbortError.
      const bare = new AbortController();
      const plain = watch(client.auth.getSession({ signal: bare.signal }));
      await vi.advanceTimersByTimeAsync(100);
      bare.abort();
      await vi.advanceTimersByTimeAsync(0);
      expect(plain.settled).toBe(true);
      expect(plain.value).toMatchObject({ name: 'AbortError' });
      expect(fetcher).toHaveBeenCalledTimes(2);
      // A signal already aborted when the refusal arrives never starts the wait.
      const early = new AbortController();
      early.abort(reason);
      const preempted = watch(client.auth.getSession({ signal: early.signal }));
      await vi.advanceTimersByTimeAsync(0);
      expect(preempted).toEqual({ settled: true, value: reason });
      expect(vi.getTimerCount()).toBe(0);
      expect(fetcher).toHaveBeenCalledTimes(3);
      // A signal that is never aborted leaves the retry unchanged.
      fetcher
        .mockResolvedValueOnce(limited())
        .mockResolvedValueOnce(Response.json({ data: { identity: { id: 'usr_1' } } }));
      const kept = new AbortController();
      const retried = client.auth.getSession({ signal: kept.signal });
      await vi.advanceTimersByTimeAsync(4_000);
      expect(await retried).toEqual({ identity: { id: 'usr_1' } });
      expect(fetcher).toHaveBeenCalledTimes(5);
    } finally {
      vi.useRealTimers();
    }
  });

  it('tags requests with X-Request-Id and carries it on errors', async () => {
    const fetcher = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(Response.json({ data: { identity: { id: 'usr_1' } } }))
      .mockResolvedValueOnce(failure('ACCESS_DENIED', 403));
    const ids = ['req-one', 'req-two'];
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      fetch: fetcher,
      requestId: () => ids.shift()!,
    });
    await client.auth.getSession();
    expect(new Headers(fetcher.mock.calls[0]![1]!.headers).get('x-request-id')).toBe('req-one');
    const error = await client.auth.getSession().catch((caught: unknown) => caught);
    expect(error).toBeInstanceOf(IamClientError);
    expect((error as IamClientError).requestId).toBe('req-two');
    // Generated identifiers are plain tokens the server accepts.
    const generated = vi
      .fn<typeof fetch>()
      .mockResolvedValue(Response.json({ data: { identity: { id: 'usr_1' } } }));
    await createIamClient<ExampleIam>({
      baseURL: 'https://app.example.com',
      fetch: generated,
      requestId: true,
    }).auth.getSession();
    expect(new Headers(generated.mock.calls[0]![1]!.headers).get('x-request-id')).toMatch(
      /^[A-Za-z0-9._:-]{1,128}$/,
    );
    // An invalid custom identifier is refused before anything is sent.
    await expect(
      createIamClient<ExampleIam>({
        baseURL: 'https://app.example.com',
        fetch: generated,
        requestId: () => 'not valid!',
      }).auth.getSession(),
    ).rejects.toMatchObject({ code: 'INVALID_CONFIG' });
  });
});
