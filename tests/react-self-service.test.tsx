// @vitest-environment happy-dom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { IamProvider, useAccessPaths, useAgreements, useSession } from '@better-iam/react';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

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

/** A fake IAM server for the self-service routes. */
function server() {
  const calls: string[] = [];
  let signedIn = true;
  const agreements: Agreement[] = [
    {
      id: 'aup',
      name: 'Acceptable use',
      content: 'Be nice.',
      version: 2,
      required: true,
      accepted: false,
    },
    {
      id: 'beta',
      name: 'Beta',
      content: 'May change.',
      version: 1,
      required: false,
      accepted: false,
    },
  ];
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    calls.push(path);
    if (!signedIn)
      return Response.json(
        { error: { code: 'UNAUTHENTICATED', message: 'No session' } },
        { status: 401 },
      );
    if (path === 'auth/getSession') return Response.json({ data: { identity: { id: 'alice' } } });
    if (path === 'agreements/listMine') return Response.json({ data: agreements });
    if (path === 'agreements/accept') {
      const agreement = agreements.find((item) => item.id === body.agreementId)!;
      if (agreement.version !== body.version)
        return Response.json(
          { error: { code: 'VERSION_CONFLICT', message: 'changed' } },
          { status: 409 },
        );
      agreement.accepted = true;
      return Response.json({ data: { accepted: true } });
    }
    if (path === 'accessPaths/find') {
      const accepted = agreements[0]!.accepted;
      return Response.json({
        data: accepted
          ? { allowed: true, reason: 'ALLOWED', paths: [] }
          : { allowed: false, reason: 'EXPLICIT_DENY', paths: [{ kind: 'accept-agreements' }] },
      });
    }
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

describe('self-service hooks', () => {
  it('lists pending agreements, accepts them, and reports access paths', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    let accept: (() => Promise<void>) | undefined;
    let refreshSession: (() => Promise<unknown>) | undefined;
    function Terms() {
      const {
        status,
        pending,
        agreements,
        accept: acceptOne,
      } = useAgreements({ tenantId: 'acme' });
      const paths = useAccessPaths({
        tenantId: 'acme',
        action: 'documents:share',
        resource: { type: 'document', id: 'd1' },
      });
      refreshSession = useSession().refresh;
      accept = () => acceptOne(pending[0]!);
      return (
        <p>
          {status}:{agreements.length}:{pending.map((item) => item.name).join(',')}|{paths.status}:
          {String(paths.allowed)}:{paths.paths.map((path) => path.kind).join(',')}
        </p>
      );
    }
    const container = await mount(
      <IamProvider client={client}>
        <Terms />
      </IamProvider>,
    );
    await settle();
    await settle();
    expect(container.textContent).toBe('ready:2:Acceptable use|ready:false:accept-agreements');

    await act(async () => {
      await accept!();
    });
    await settle();
    expect(container.textContent).toBe('ready:2:|ready:false:accept-agreements');
    expect(backend.calls).toContain('agreements/accept');

    // Signing out settles both hooks to their empty state.
    backend.signOut();
    await act(async () => {
      await refreshSession!();
    });
    await settle();
    expect(container.textContent).toBe('ready:0:|ready:false:');
  });
});
