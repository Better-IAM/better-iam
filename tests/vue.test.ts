// @vitest-environment happy-dom
import { createApp, createSSRApp, defineComponent, h, nextTick, ref, type Component } from 'vue';
import { renderToString } from 'vue/server-renderer';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { createIamClient } from '@better-iam/client';
import {
  IamCan,
  createHydration,
  createIam,
  useAccessible,
  useAuthorize,
  useCan,
  useIamClient,
  useSession,
} from '@better-iam/vue';

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
type Check = { action: string; resource: { type: string; id: string } };

/** A fake IAM server: answers the routes the composables call and records every request. */
function server() {
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  let user: { id: string; name: string } | null = { id: 'alice', name: 'Alice' };
  const decide = (checks: Check[]) =>
    checks.map((check) => ({
      ...check,
      allowed: check.action.endsWith(':read') || user?.id === 'owner',
      reason: 'test',
    }));
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
      return Response.json({ data: { results: decide(body.checks as Check[]) } });
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
    decide,
    count: (path: string) => calls.filter((call) => call.path === path).length,
    setUser: (next: typeof user) => {
      user = next;
    },
  };
}

const unmounts: (() => void)[] = [];
afterEach(() => {
  for (const unmount of unmounts.splice(0)) unmount();
});
function mount(component: Component, plugin: ReturnType<typeof createIam>): HTMLElement {
  const container = document.createElement('div');
  document.body.append(container);
  const app = createApp(component);
  app.use(plugin);
  app.mount(container);
  unmounts.push(() => {
    app.unmount();
    plugin.dispose();
    container.remove();
  });
  return container;
}
const settle = async () => {
  for (let i = 0; i < 5; i++) {
    await new Promise((resolve) => setTimeout(resolve, 0));
    await nextTick();
  }
};

describe('vue bindings', () => {
  it('provides a reactive session, re-runs decisions on input and identity changes, and renders IamCan slots', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    const target = ref('website');
    let exposed!: {
      session: ReturnType<typeof useSession<typeof client>>;
      decisions: ReturnType<typeof useAuthorize>;
    };
    const View = defineComponent({
      setup() {
        const session = useSession<typeof client>();
        const decisions = useAuthorize(() => ({
          tenantId: 'acme',
          checks: [
            { action: 'projects:read', resource: { type: 'project', id: target.value } },
            { action: 'projects:manage', resource: { type: 'project', id: target.value } },
          ],
        }));
        const manage = useCan(() => ({
          tenantId: 'acme',
          action: 'projects:manage',
          resource: { type: 'project', id: target.value },
        }));
        exposed = { session, decisions };
        expect(useIamClient<typeof client>()).toBe(client);
        return () =>
          h('div', [
            h('p', { id: 'status' }, session.status.value),
            h('p', { id: 'name' }, session.session.value?.identity.name ?? ''),
            h(
              'p',
              { id: 'read' },
              String(decisions.allowed('projects:read', { type: 'project', id: target.value })),
            ),
            h('p', { id: 'manage' }, String(manage.allowed.value)),
            h(
              IamCan,
              {
                tenantId: 'acme',
                action: 'projects:manage',
                resource: { type: 'project', id: 'x' },
              },
              {
                default: () => h('span', { id: 'can' }, 'manage'),
                fallback: () => h('span', { id: 'cannot' }, 'no'),
                loading: () => h('span', { id: 'checking' }, '…'),
              },
            ),
          ]);
      },
    });
    const plugin = createIam({ client, refreshOnFocus: true });
    const root = mount(View, plugin);
    expect(root.querySelector('#status')?.textContent).toBe('loading');
    expect(root.querySelector('#checking')).not.toBeNull();
    await settle();
    expect(root.querySelector('#status')?.textContent).toBe('authenticated');
    expect(root.querySelector('#name')?.textContent).toBe('Alice');
    expect(root.querySelector('#read')?.textContent).toBe('true');
    expect(root.querySelector('#manage')?.textContent).toBe('false');
    expect(root.querySelector('#cannot')).not.toBeNull();
    const batches = backend.count('authorizeMany');
    // A refresh for the same identity does not re-run decisions.
    await exposed.session.refresh();
    await settle();
    expect(backend.count('authorizeMany')).toBe(batches);
    // Reactive input changes re-run the affected queries only.
    target.value = 'intranet';
    await settle();
    expect(backend.count('authorizeMany')).toBe(batches + 2);
    expect(backend.calls.at(-1)?.body.checks as Check[] | undefined).toContainEqual({
      action: 'projects:manage',
      resource: { type: 'project', id: 'intranet' },
    });
    // A different identity re-runs everything.
    backend.setUser({ id: 'owner', name: 'Owner' });
    window.dispatchEvent(new Event('focus'));
    await settle();
    expect(root.querySelector('#name')?.textContent).toBe('Owner');
    expect(root.querySelector('#manage')?.textContent).toBe('true');
    expect(root.querySelector('#can')).not.toBeNull();
    // Signing out resolves every decision to false without asking the server.
    const before = backend.count('authorizeMany');
    await exposed.session.signOut();
    await settle();
    expect(root.querySelector('#status')?.textContent).toBe('unauthenticated');
    expect(root.querySelector('#read')?.textContent).toBe('false');
    expect(root.querySelector('#cannot')).not.toBeNull();
    expect(
      exposed.decisions.results.value.every((result) => result.reason === 'UNAUTHENTICATED'),
    ).toBe(true);
    expect(backend.count('authorizeMany')).toBe(before);
  });

  it('lists accessible resources, honours enabled, and requires the plugin', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    const enabled = ref(false);
    let accessible!: ReturnType<typeof useAccessible>;
    const View = defineComponent({
      setup() {
        accessible = useAccessible(() => ({
          tenantId: 'acme',
          action: 'documents:read',
          type: 'document',
          limit: 5,
          enabled: enabled.value,
        }));
        return () =>
          h(
            'ul',
            accessible.resources.value.map((r) => h('li', r.resourceId)),
          );
      },
    });
    const root = mount(
      View,
      createIam({
        client,
        initialSession: { identity: { id: 'alice', name: 'Alice' }, session: { tenantId: 'acme' } },
      }),
    );
    await settle();
    expect(backend.count('auth/getSession')).toBe(0);
    expect(backend.count('listAccessible')).toBe(0);
    expect(accessible.status.value).toBe('idle');
    enabled.value = true;
    await settle();
    expect(root.textContent).toBe('alice-doc');
    expect(accessible.total.value).toBe(1);
    expect(backend.calls.find((call) => call.path === 'listAccessible')?.body).toMatchObject({
      tenantId: 'acme',
      type: 'document',
      limit: 5,
    });
    const orphan = createApp(
      defineComponent({
        setup() {
          useSession();
          return () => null;
        },
      }),
    );
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    expect(() => orphan.mount(document.createElement('div'))).toThrow(/createIam/);
    warn.mockRestore();
  });

  it('awaits decisions during server rendering and hydrates them without refetching', async () => {
    const backend = server();
    const session = { identity: { id: 'owner', name: 'Owner' }, session: { tenantId: 'acme' } };
    backend.setUser(session.identity);
    // The in-process client a server integration binds per request (Nuxt: event.context.betterIam).
    const serverClient = {
      auth: { getSession: async () => session, signOut: async () => ({ success: true }) },
      authorizeMany: vi.fn(async (input: { tenantId: string; checks: Check[] }) => ({
        results: backend.decide(input.checks),
      })),
      listAccessible: vi.fn(async () => ({ resources: [], total: 0 })),
    };
    const Page = defineComponent({
      setup() {
        const { session: current } = useSession();
        return () =>
          h('main', [
            h('p', (current.value as typeof session | null)?.identity.name ?? 'anonymous'),
            h(
              IamCan,
              { tenantId: 'acme', action: 'projects:manage' },
              { default: () => h('button', 'Manage'), loading: () => h('i', 'loading') },
            ),
          ]);
      },
    });
    const hydration = createHydration();
    const ssr = createSSRApp(Page);
    ssr.use(createIam({ client: serverClient, initialSession: session, hydration, server: true }));
    const html = await renderToString(ssr);
    expect(html).toContain('<button>Manage</button>');
    expect(html).not.toContain('loading');
    expect(serverClient.authorizeMany).toHaveBeenCalledTimes(1);
    const payload = JSON.parse(JSON.stringify(hydration.state)) as Record<string, unknown>;
    expect(Object.keys(payload)).toHaveLength(1);

    const container = document.createElement('div');
    container.innerHTML = html;
    document.body.append(container);
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    const plugin = createIam({
      client,
      initialSession: session,
      hydration: createHydration(payload),
    });
    const browser = createSSRApp(Page);
    browser.use(plugin);
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => undefined);
    const error = vi.spyOn(console, 'error').mockImplementation(() => undefined);
    browser.mount(container);
    await settle();
    expect(warn.mock.calls.flat().join(' ')).not.toMatch(/mismatch/i);
    expect(error.mock.calls.flat().join(' ')).not.toMatch(/mismatch/i);
    warn.mockRestore();
    error.mockRestore();
    unmounts.push(() => {
      browser.unmount();
      plugin.dispose();
      container.remove();
    });
    expect(container.innerHTML).toContain('<button>Manage</button>');
    expect(backend.count('authorizeMany')).toBe(0);
    expect(backend.count('auth/getSession')).toBe(0);
    // The handoff is consumed once: a later mount of the same query asks the server.
    expect(Object.keys(payload)).toHaveLength(0);
  });
});
