// @vitest-environment happy-dom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { IamProvider, useFeatureFlag, useFeatureFlags, useSession } from '@better-iam/react';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

interface ExampleIam {
  api: {
    auth: {
      getSession(credential: { headers?: HeadersInit }): Promise<{ identity: { id: string } }>;
    };
    features: {
      evaluate(
        credential: { headers?: HeadersInit },
        input: { tenantId: string; keys?: string[] },
      ): Promise<{ tenantId: string; flags: Record<string, boolean> }>;
    };
  };
}

/** A fake IAM server answering `features/evaluate` the way the real one does (unknown requested keys are off). */
function server(flags: Record<string, boolean>) {
  const calls: string[] = [];
  let signedIn = true;
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as { tenantId: string; keys?: string[] };
    calls.push(`${path}:${JSON.stringify(body.keys ?? null)}`);
    if (!signedIn)
      return Response.json(
        { error: { code: 'UNAUTHENTICATED', message: 'No session' } },
        { status: 401 },
      );
    if (path === 'auth/getSession') return Response.json({ data: { identity: { id: 'alice' } } });
    if (path === 'features/evaluate')
      return Response.json({
        data: {
          tenantId: body.tenantId,
          flags: body.keys
            ? Object.fromEntries(body.keys.map((key) => [key, flags[key] === true]))
            : { ...flags },
        },
      });
    return Response.json({ error: { code: 'NOT_FOUND', message: 'nope' } }, { status: 404 });
  };
  return {
    calls,
    fetcher,
    signOut: () => {
      signedIn = false;
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

describe('feature flag hooks', () => {
  it('load the tenant flags, refresh after a change, and settle off when signed out', async () => {
    const flags: Record<string, boolean> = { 'new-editor': true, 'beta-reports': false };
    const backend = server(flags);
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    const refreshers: Array<() => Promise<unknown>> = [];
    function Toolbar() {
      const all = useFeatureFlags({ tenantId: 'acme' });
      const beta = useFeatureFlag({ tenantId: 'acme', key: 'beta-reports' });
      refreshers.splice(0, 3, all.refresh, beta.refresh, useSession().refresh);
      return (
        <p>
          {all.status}:{String(all.isEnabled('new-editor'))}:{String(all.isEnabled('missing'))}:
          {String(all.isEnabled('constructor'))}|{beta.status}:{String(beta.value)}
        </p>
      );
    }
    const container = await mount(
      <IamProvider client={client}>
        <Toolbar />
      </IamProvider>,
    );
    await settle();
    await settle();
    expect(container.textContent).toBe('ready:true:false:false|ready:false');
    // The single-flag hook asks for its key only.
    expect(backend.calls).toContain('features/evaluate:["beta-reports"]');
    expect(backend.calls).toContain('features/evaluate:null');

    flags['beta-reports'] = true;
    await act(async () => {
      await refreshers[0]!();
      await refreshers[1]!();
    });
    await settle();
    expect(container.textContent).toBe('ready:true:false:false|ready:true');

    // Signing out settles both hooks to "off".
    backend.signOut();
    await act(async () => {
      await refreshers[2]!();
    });
    await settle();
    expect(container.textContent).toBe('ready:false:false:false|ready:false');
  });
});
