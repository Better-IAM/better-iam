// @vitest-environment happy-dom
import { act, useEffect, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createIamClient, IamClientError } from '@better-iam/client';
import {
  Can,
  IamProvider,
  createSessionStore,
  useAccessible,
  useAuthorize,
  useIamClient,
  useSession,
} from '@better-iam/react';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

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
    checks: { action: string; resource: { type: string; id: string } }[];
  }): Promise<{
    results: {
      action: string;
      resource: { type: string; id: string };
      allowed: boolean;
      reason: string;
    }[];
  }>;
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

/** A fake IAM server: answers the routes the hooks call and records every request. */
function server() {
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  let user: { id: string; name: string } | null = { id: 'alice', name: 'Alice' };
  let failAuthorize = false;
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
    if (path === 'authorizeMany') {
      if (failAuthorize)
        return Response.json(
          { error: { code: 'INTERNAL_ERROR', message: 'boom' } },
          { status: 500 },
        );
      const checks = body.checks as { action: string; resource: { type: string; id: string } }[];
      return Response.json({
        data: {
          results: checks.map((check) => ({
            ...check,
            allowed: check.action.endsWith(':read') || user?.id === 'owner',
            reason: 'test',
          })),
        },
      });
    }
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
    calls,
    fetcher,
    setUser: (next: typeof user) => {
      user = next;
    },
    setFailAuthorize: (value: boolean) => {
      failAuthorize = value;
    },
  };
}

const roots: Root[] = [];
afterEach(async () => {
  for (const root of roots.splice(0))
    await act(async () => {
      root.unmount();
    });
});
async function mount(element: ReactNode): Promise<HTMLElement> {
  const container = document.createElement('div');
  document.body.append(container);
  const root = createRoot(container);
  roots.push(root);
  await act(async () => {
    root.render(element);
  });
  return container;
}
const settle = () =>
  act(async () => {
    await new Promise((resolve) => setTimeout(resolve, 0));
  });

describe('session store', () => {
  it('tracks loading, authenticated, unauthenticated, and error states and shares in-flight refreshes', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    const store = createSessionStore(client);
    const seen: string[] = [];
    store.subscribe(() => seen.push(store.getSnapshot().status));
    expect(store.getSnapshot().status).toBe('loading');
    const [first, second] = await Promise.all([store.refresh(), store.refresh()]);
    expect(first).toBe(second);
    expect(first.status).toBe('authenticated');
    expect(first.session?.identity.name).toBe('Alice');
    expect(backend.calls.filter((call) => call.path === 'auth/getSession')).toHaveLength(1);
    backend.setUser(null);
    expect((await store.refresh()).status).toBe('unauthenticated');
    expect(store.getSnapshot().error).toBeInstanceOf(IamClientError);
    store.set({ identity: { id: 'bob', name: 'Bob' }, session: { tenantId: 'acme' } });
    expect(store.getSnapshot().session?.identity.id).toBe('bob');
    const broken = createSessionStore(
      createIamClient<ExampleIam>({
        baseURL: 'https://app.example.test',
        fetch: async () => {
          throw new TypeError('offline');
        },
      }),
      { initial: { identity: { id: 'x', name: 'X' }, session: { tenantId: 'acme' } } },
    );
    expect(broken.getSnapshot().status).toBe('authenticated');
    expect((await broken.refresh()).status).toBe('error');
    expect(broken.getSnapshot().session?.identity.id).toBe('x');
    await broken.signOut().catch(() => undefined);
    expect(broken.getSnapshot()).toMatchObject({ status: 'unauthenticated', session: null });
    expect(seen).toEqual(['authenticated', 'unauthenticated', 'authenticated']);
  });
});

describe('react hooks', () => {
  it('provides the session, re-runs authorization when the identity changes, and renders Can boundaries', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    function View() {
      const session = useSession<typeof client>();
      const { status, allowed } = useAuthorize({
        tenantId: 'acme',
        checks: [
          { action: 'documents:read', resource: { type: 'document', id: 'a' } },
          { action: 'documents:write', resource: { type: 'document', id: 'a' } },
        ],
      });
      const accessible = useAccessible({
        tenantId: 'acme',
        action: 'documents:read',
        type: 'document',
      });
      const same = useIamClient<typeof client>() === client;
      return (
        <div>
          <p id="session">
            {session.status}:{session.session?.identity.name ?? '-'}:{String(same)}
          </p>
          <p id="authz">
            {status}:{String(allowed('documents:read', { type: 'document', id: 'a' }))}:
            {String(allowed('documents:write', { type: 'document', id: 'a' }))}
          </p>
          <p id="accessible">
            {accessible.status}:
            {accessible.resources.map((resource) => resource.resourceId).join(',')}:
            {accessible.total}
          </p>
          <Can
            tenantId="acme"
            action="documents:write"
            resource={{ type: 'document', id: 'a' }}
            fallback={<span id="can">denied</span>}
            loading={<span id="can">loading</span>}
          >
            <span id="can">allowed</span>
          </Can>
          <button id="signout" onClick={() => void session.signOut()}>
            out
          </button>
          <button
            id="become-owner"
            onClick={() => {
              backend.setUser({ id: 'owner', name: 'Owner' });
              session.setSession({
                identity: { id: 'owner', name: 'Owner' },
                session: { tenantId: 'acme' },
              });
            }}
          >
            owner
          </button>
        </div>
      );
    }
    const container = await mount(
      <IamProvider client={client} refreshOnFocus={false}>
        <View />
      </IamProvider>,
    );
    const text = (id: string) => container.querySelector(`#${id}`)!.textContent;
    await settle();
    await settle();
    expect(text('session')).toBe('authenticated:Alice:true');
    expect(text('authz')).toBe('ready:true:false');
    expect(text('accessible')).toBe('ready:alice-doc:1');
    expect(text('can')).toBe('denied');
    // A new identity re-evaluates every advisory decision.
    await act(async () => {
      container.querySelector<HTMLButtonElement>('#become-owner')!.click();
    });
    await settle();
    await settle();
    expect(text('session')).toBe('authenticated:Owner:true');
    expect(text('authz')).toBe('ready:true:true');
    expect(text('can')).toBe('allowed');
    expect(
      backend.calls.filter((call) => call.path === 'authorizeMany').length,
    ).toBeGreaterThanOrEqual(2);
    // Signing out clears decisions without another server round trip.
    const before = backend.calls.length;
    await act(async () => {
      container.querySelector<HTMLButtonElement>('#signout')!.click();
    });
    await settle();
    expect(text('session')).toBe('unauthenticated:-:true');
    expect(text('authz')).toBe('ready:false:false');
    expect(text('can')).toBe('denied');
    expect(backend.calls.slice(before).map((call) => call.path)).toEqual(['auth/signOut']);
  });

  it('accepts a server-rendered session, exposes authorization errors, and refuses to run outside the provider', async () => {
    const backend = server();
    backend.setFailAuthorize(true);
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    function View() {
      const session = useSession<typeof client>();
      const { status, error } = useAuthorize({
        tenantId: 'acme',
        checks: [{ action: 'documents:read', resource: { type: 'document', id: 'a' } }],
      });
      return (
        <p id="out">
          {session.status}:{session.session?.identity.id}:{status}:{error?.message ?? ''}
        </p>
      );
    }
    const container = await mount(
      <IamProvider
        client={client}
        initialSession={{ identity: { id: 'ssr', name: 'SSR' }, session: { tenantId: 'acme' } }}
        refreshOnFocus={false}
      >
        <View />
      </IamProvider>,
    );
    await settle();
    await settle();
    expect(container.querySelector('#out')!.textContent).toBe('authenticated:ssr:error:boom');
    expect(backend.calls.map((call) => call.path)).toEqual(['authorizeMany']);
    const disabled = await mount(
      <IamProvider client={client} initialSession={null} refreshOnFocus={false}>
        <Disabled />
      </IamProvider>,
    );
    await settle();
    expect(disabled.querySelector('#disabled')!.textContent).toBe('unauthenticated:idle');
    function Disabled() {
      const session = useSession();
      const { status } = useAuthorize({ tenantId: 'acme', checks: [], enabled: false });
      return (
        <p id="disabled">
          {session.status}:{status}
        </p>
      );
    }
    const spy = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    try {
      function Orphan() {
        useSession();
        return null;
      }
      await expect(mount(<Orphan />)).rejects.toThrow(/inside <IamProvider>/u);
    } finally {
      spy.mockRestore();
    }
  });

  it('polls on an interval when asked and stops when unmounted', async () => {
    vi.useFakeTimers();
    try {
      const backend = server();
      const client = createIamClient<ExampleIam>({
        baseURL: 'https://app.example.test',
        fetch: backend.fetcher,
      });
      function Probe() {
        const { status } = useSession();
        useEffect(() => undefined, [status]);
        return <span>{status}</span>;
      }
      await mount(
        <IamProvider client={client} refreshOnFocus={false} refreshIntervalMs={1000}>
          <Probe />
        </IamProvider>,
      );
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3100);
      });
      expect(backend.calls.filter((call) => call.path === 'auth/getSession').length).toBe(4);
      for (const root of roots.splice(0))
        await act(async () => {
          root.unmount();
        });
      await act(async () => {
        await vi.advanceTimersByTimeAsync(3000);
      });
      expect(backend.calls.filter((call) => call.path === 'auth/getSession').length).toBe(4);
    } finally {
      vi.useRealTimers();
    }
  });
});
