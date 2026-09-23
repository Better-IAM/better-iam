import { get, writable } from 'svelte/store';
import { describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { createIam, type AuthorizeState } from '@better-iam/svelte';

type Check = { action: string; resource: { type: string; id: string } };
interface ExampleIam {
  api: {
    auth: {
      getSession(credential: {
        headers?: HeadersInit;
      }): Promise<{ identity: { id: string; name: string }; session: { tenantId: string } }>;
      signOut(credential: { headers?: HeadersInit }): Promise<{ success: true }>;
    };
  };
  authorizeMany(input: {
    headers?: HeadersInit;
    tenantId: string;
    checks: Check[];
  }): Promise<{ results: (Check & { allowed: boolean; reason: string })[] }>;
  listAccessible(input: {
    headers?: HeadersInit;
    tenantId: string;
    action: string;
    type: string;
    limit?: number;
    offset?: number;
  }): Promise<{
    resources: {
      id: string;
      type: string;
      resourceId: string;
      attributes: Record<string, unknown>;
    }[];
    total: number;
  }>;
}

/** A fake IAM HTTP API answering the routes the stores call; records every request. */
function server() {
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  let user: { id: string; name: string } | null = { id: 'alice', name: 'Alice' };
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    calls.push({ path, body });
    if (path === 'auth/getSession')
      return user
        ? Response.json({ data: { identity: user, session: { tenantId: 'acme' } } })
        : Response.json(
            { error: { code: 'UNAUTHENTICATED', message: 'No session' } },
            { status: 401 },
          );
    if (path === 'auth/signOut') {
      user = null;
      return Response.json({ data: { success: true } });
    }
    if (path === 'authorizeMany')
      return Response.json({
        data: {
          results: (body.checks as Check[]).map((check) => ({
            ...check,
            allowed: check.action.endsWith(':read') || user?.id === 'owner',
            reason: 'test',
          })),
        },
      });
    if (path === 'listAccessible')
      return Response.json({
        data: {
          resources: [
            { id: 'r1', type: String(body.type), resourceId: `${user?.id}-doc`, attributes: {} },
          ],
          total: 1,
        },
      });
    return Response.json({ error: { code: 'NOT_FOUND', message: 'nope' } }, { status: 404 });
  };
  return {
    fetcher,
    count: (path: string) => calls.filter((call) => call.path === path).length,
    setUser: (next: typeof user) => {
      user = next;
    },
  };
}
const settle = async () => {
  for (let i = 0; i < 5; i++) await new Promise((resolve) => setTimeout(resolve, 0));
};
const client = (backend: ReturnType<typeof server>) =>
  createIamClient<ExampleIam>({ baseURL: 'https://app.example.test', fetch: backend.fetcher });

describe('svelte stores', () => {
  it('loads the session in the browser, exposes it as a store, and signs out', async () => {
    const backend = server();
    const iam = createIam({ client: client(backend), server: false, refreshOnFocus: false });
    expect(get(iam.session).status).toBe('loading');
    await settle();
    expect(get(iam.session)).toMatchObject({
      status: 'authenticated',
      session: { identity: { id: 'alice' } },
    });
    const seen: string[] = [];
    const stop = iam.session.subscribe((value) => seen.push(value.status));
    await iam.signOut();
    stop();
    expect(seen).toEqual(['authenticated', 'unauthenticated']);
    expect(backend.count('auth/signOut')).toBe(1);
    iam.dispose();
  });

  it('does not fetch on the server and trusts an initial session', async () => {
    const backend = server();
    const iam = createIam({
      client: client(backend),
      initialSession: { identity: { id: 'alice', name: 'Alice' }, session: { tenantId: 'acme' } },
    });
    await settle();
    expect(backend.count('auth/getSession')).toBe(0);
    expect(get(iam.session).status).toBe('authenticated');
  });

  it('authorizes while subscribed, follows input stores, and re-runs when the identity changes', async () => {
    const backend = server();
    const iam = createIam({ client: client(backend), server: false, refreshOnFocus: false });
    const project = writable('website');
    const decisions = iam.authorize({
      subscribe: (run) =>
        project.subscribe((id) =>
          run({
            tenantId: 'acme',
            checks: [
              { action: 'projects:read', resource: { type: 'project', id } },
              { action: 'projects:manage', resource: { type: 'project', id } },
              { action: 'members:read' },
            ],
          }),
        ),
    });
    // Nothing is fetched until someone subscribes.
    await settle();
    expect(backend.count('authorizeMany')).toBe(0);
    let state!: AuthorizeState;
    const stop = decisions.subscribe((value) => {
      state = value;
    });
    await settle();
    expect(state.status).toBe('ready');
    expect(state.allowed('projects:read', { type: 'project', id: 'website' })).toBe(true);
    expect(state.allowed('projects:manage', { type: 'project', id: 'website' })).toBe(false);
    expect(state.allowed('members:read')).toBe(true);
    expect(backend.count('authorizeMany')).toBe(1);

    // A session refresh for the same identity keeps the results.
    await iam.refresh();
    await settle();
    expect(backend.count('authorizeMany')).toBe(1);

    project.set('api');
    await settle();
    expect(backend.count('authorizeMany')).toBe(2);
    expect(state.results[0]?.resource.id).toBe('api');

    backend.setUser({ id: 'owner', name: 'Owner' });
    await iam.refresh();
    await settle();
    expect(backend.count('authorizeMany')).toBe(3);
    expect(state.allowed('projects:manage', { type: 'project', id: 'api' })).toBe(true);

    await iam.signOut();
    await settle();
    expect(state.status).toBe('ready');
    expect(state.results.every((result) => !result.allowed)).toBe(true);
    expect(state.results[0]?.reason).toBe('UNAUTHENTICATED');
    stop();
    iam.dispose();
  });

  it('seeds can() from a server decision without refetching, and lists accessible resources', async () => {
    const backend = server();
    const iam = createIam({
      client: client(backend),
      initialSession: { identity: { id: 'alice', name: 'Alice' }, session: { tenantId: 'acme' } },
      server: false,
      refreshOnFocus: false,
    });
    const canManage = iam.can({ tenantId: 'acme', action: 'projects:manage' }, { initial: true });
    let manage = get(canManage);
    const stopManage = canManage.subscribe((value) => {
      manage = value;
    });
    await settle();
    expect(manage).toEqual({ status: 'ready', allowed: true });
    expect(backend.count('authorizeMany')).toBe(0);
    await canManage.refresh();
    expect(manage).toEqual({ status: 'ready', allowed: false });
    stopManage();

    const docs = iam.accessible({ tenantId: 'acme', action: 'documents:read', type: 'document' });
    let listed = get(docs);
    const stopDocs = docs.subscribe((value) => {
      listed = value;
    });
    await settle();
    expect(listed).toMatchObject({
      status: 'ready',
      total: 1,
      resources: [{ resourceId: 'alice-doc' }],
    });
    stopDocs();

    const disabled = iam.can({ tenantId: 'acme', action: 'projects:read', enabled: false });
    const stopDisabled = disabled.subscribe(() => {});
    await settle();
    expect(get(disabled)).toEqual({ status: 'idle', allowed: false });
    stopDisabled();
    expect(backend.count('authorizeMany')).toBe(1);
  });
});
