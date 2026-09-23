// @vitest-environment happy-dom
import { createApp, defineComponent, h, nextTick, type Component } from 'vue';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { createIam, useAccessPaths, useAgreements, useSession } from '@better-iam/vue';

interface Agreement {
  id: string;
  name: string;
  content: string;
  version: number;
  required: boolean;
  accepted: boolean;
}
interface ExampleIam {
  api: {
    auth: {
      getSession(credential: { headers?: HeadersInit }): Promise<{ identity: { id: string } }>;
      signOut(credential: { headers?: HeadersInit }): Promise<{ success: true }>;
    };
    agreements: {
      listMine(
        credential: { headers?: HeadersInit },
        input: { tenantId: string },
      ): Promise<Agreement[]>;
      accept(
        credential: { headers?: HeadersInit },
        input: { tenantId: string; agreementId: string; version: number },
      ): Promise<unknown>;
    };
    accessPaths: {
      find(
        credential: { headers?: HeadersInit },
        input: { tenantId: string; action: string; resource: { type: string; id: string } },
      ): Promise<{ allowed: boolean; reason: string; paths: { kind: string }[] }>;
    };
  };
}

function server() {
  let signedIn = true;
  const agreements: Agreement[] = [
    {
      id: 'aup',
      name: 'Acceptable use',
      content: 'Be nice.',
      version: 1,
      required: true,
      accepted: false,
    },
  ];
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    if (!signedIn)
      return Response.json(
        { error: { code: 'UNAUTHENTICATED', message: 'No session' } },
        { status: 401 },
      );
    if (path === 'auth/getSession') return Response.json({ data: { identity: { id: 'alice' } } });
    if (path === 'agreements/listMine') return Response.json({ data: agreements });
    if (path === 'agreements/accept') {
      agreements.find((item) => item.id === body.agreementId)!.accepted = true;
      return Response.json({ data: { accepted: true } });
    }
    if (path === 'accessPaths/find')
      return Response.json({
        data: agreements[0]!.accepted
          ? { allowed: true, reason: 'ALLOWED', paths: [] }
          : { allowed: false, reason: 'EXPLICIT_DENY', paths: [{ kind: 'accept-agreements' }] },
      });
    return Response.json({ error: { code: 'NOT_FOUND', message: 'nope' } }, { status: 404 });
  };
  return {
    fetcher,
    signOut: () => {
      signedIn = false;
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

describe('vue self-service composables', () => {
  it('lists and accepts agreements and reports access paths', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    let exposed!: {
      terms: ReturnType<typeof useAgreements>;
      paths: ReturnType<typeof useAccessPaths>;
      session: ReturnType<typeof useSession>;
    };
    const View = defineComponent({
      setup() {
        const terms = useAgreements({ tenantId: 'acme' });
        const paths = useAccessPaths({
          tenantId: 'acme',
          action: 'documents:share',
          resource: { type: 'document', id: 'd1' },
        });
        exposed = { terms, paths, session: useSession() };
        return () =>
          h(
            'p',
            `${terms.pending.value.map((item) => item.name).join(',')}|${paths.allowed.value}:${paths.paths.value
              .map((path) => path.kind)
              .join(',')}`,
          );
      },
    });
    const root = mount(View, createIam({ client }));
    await settle();
    expect(root.textContent).toBe('Acceptable use|false:accept-agreements');
    await exposed.terms.accept(exposed.terms.pending.value[0]!);
    await exposed.paths.refresh();
    await settle();
    expect(root.textContent).toBe('|true:');
    backend.signOut();
    await exposed.session.refresh();
    await settle();
    expect(root.textContent).toBe('|false:');
  });
});
