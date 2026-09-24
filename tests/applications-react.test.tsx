// @vitest-environment happy-dom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { IamProvider, useMyApps, type MemberApp } from '@better-iam/react';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Credential = { headers?: HeadersInit };
interface ExampleIam {
  api: {
    auth: {
      getSession(credential: Credential): Promise<{ identity: { id: string } }>;
      signOut(credential: Credential): Promise<{ success: true }>;
    };
    applications: {
      mine(credential: Credential, input: { tenantId: string }): Promise<MemberApp[]>;
      launch(
        credential: Credential,
        input: { tenantId: string; appId: string },
      ): Promise<{ url: string }>;
    };
  };
}

/** A fake IAM server for the launcher routes. */
function server() {
  const apps: MemberApp[] = [
    { id: 'a1', key: 'wiki', name: 'Wiki', via: 'everyone' },
    { id: 'a2', key: 'ci', name: 'CI', via: 'group' },
    { id: 'a3', key: 'payroll', name: 'Payroll', requestPackageId: 'pkg1' },
  ];
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    if (path === 'auth/getSession') return Response.json({ data: { identity: { id: 'alice' } } });
    if (path === 'applications/mine') return Response.json({ data: apps });
    if (path === 'applications/launch') {
      const app = apps.find((item) => item.id === body.appId && item.via);
      if (!app)
        return Response.json({ error: { code: 'ACCESS_DENIED', message: 'no' } }, { status: 403 });
      app.lastLaunchedAt = 1;
      apps.sort((a, b) => (b.lastLaunchedAt ?? 0) - (a.lastLaunchedAt ?? 0));
      return Response.json({ data: { url: `https://${app.key}.acme.test/` } });
    }
    return Response.json({ error: { code: 'NOT_FOUND', message: 'nope' } }, { status: 404 });
  };
  return { fetcher };
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

describe('useMyApps', () => {
  it('splits launchable and requestable apps and launches', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    let hook: ReturnType<typeof useMyApps> | undefined;
    function Launcher() {
      hook = useMyApps({ tenantId: 'acme' });
      return (
        <p>
          {hook.status}:{hook.apps.map((app) => app.key).join(',')}:
          {hook.requestable.map((app) => app.key).join(',')}
        </p>
      );
    }
    const container = await mount(
      <IamProvider client={client}>
        <Launcher />
      </IamProvider>,
    );
    await settle();
    await settle();
    expect(container.textContent).toBe('ready:wiki,ci:payroll');
    let url: string | undefined;
    await act(async () => {
      url = await hook!.launch('a2');
    });
    await settle();
    expect(url).toBe('https://ci.acme.test/');
    expect(container.textContent).toBe('ready:ci,wiki:payroll');
    await act(async () => {
      await expect(hook!.launch('a3')).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    });
  });
});
