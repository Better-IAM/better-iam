// @vitest-environment happy-dom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { IamProvider, usePrivacy, type MemberPrivacy } from '@better-iam/react';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Credential = { headers?: HeadersInit };
interface ExampleIam {
  api: {
    auth: {
      getSession(credential: Credential): Promise<{ identity: { id: string } }>;
      signOut(credential: Credential): Promise<{ success: true }>;
    };
    privacy: {
      mine(credential: Credential, input: { tenantId: string }): Promise<MemberPrivacy>;
      decide(
        credential: Credential,
        input: { tenantId: string; purposeKey: string; version: number; granted: boolean },
      ): Promise<unknown>;
      submitRequest(
        credential: Credential,
        input: { tenantId: string; type: string; details?: string },
      ): Promise<MemberPrivacy['requests'][number]>;
      cancelMyRequest(
        credential: Credential,
        input: { tenantId: string; requestId: string },
      ): Promise<unknown>;
    };
  };
}

/** A fake IAM server for the privacy self-service routes. */
function server() {
  const decisions: Array<{ purposeKey: string; version: number; granted: boolean }> = [];
  const state: MemberPrivacy = {
    restricted: false,
    requests: [],
    contact: { email: 'dpo@acme.test' },
    purposes: [
      {
        id: 'p1',
        key: 'newsletter',
        name: 'Newsletter',
        description: 'News by email.',
        legalBasis: 'consent',
        mode: 'opt-in',
        version: 3,
        dataCategories: ['contact'],
        decidable: true,
        state: { allowed: false, reason: 'NO_CONSENT' },
      },
      {
        id: 'p2',
        key: 'billing',
        name: 'Billing',
        description: 'Invoices.',
        legalBasis: 'contract',
        mode: 'opt-in',
        version: 1,
        dataCategories: [],
        decidable: false,
        state: { allowed: true, reason: 'LEGAL_BASIS' },
      },
    ],
  };
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    if (path === 'auth/getSession') return Response.json({ data: { identity: { id: 'alice' } } });
    if (path === 'privacy/mine') return Response.json({ data: state });
    if (path === 'privacy/decide') {
      const purpose = state.purposes.find((item) => item.key === body.purposeKey)!;
      if (purpose.version !== body.version)
        return Response.json(
          { error: { code: 'VERSION_CONFLICT', message: 'changed' } },
          { status: 409 },
        );
      decisions.push({
        purposeKey: String(body.purposeKey),
        version: Number(body.version),
        granted: body.granted === true,
      });
      purpose.state = body.granted
        ? { allowed: true, reason: 'CONSENT_GIVEN' }
        : { allowed: false, reason: 'CONSENT_WITHDRAWN' };
      return Response.json({ data: { receiptId: 'r1' } });
    }
    if (path === 'privacy/submitRequest') {
      const request = {
        id: `q${state.requests.length + 1}`,
        number: 'DSR-TEST0001',
        type: body.type as MemberPrivacy['requests'][number]['type'],
        status: 'open' as const,
        submittedAt: 1,
        dueAt: 2,
      };
      state.requests = [request, ...state.requests];
      return Response.json({ data: request });
    }
    if (path === 'privacy/cancelMyRequest') {
      state.requests = state.requests.map((request) =>
        request.id === body.requestId ? { ...request, status: 'cancelled' as const } : request,
      );
      return Response.json({ data: { status: 'cancelled' } });
    }
    return Response.json({ error: { code: 'NOT_FOUND', message: 'nope' } }, { status: 404 });
  };
  return { fetcher, decisions };
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

describe('usePrivacy', () => {
  it('lists pending consents, decides on the current version, and files requests', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    let hook: ReturnType<typeof usePrivacy> | undefined;
    function Banner() {
      hook = usePrivacy({ tenantId: 'acme' });
      return (
        <p>
          {hook.status}:{hook.pending.map((purpose) => purpose.key).join(',')}:
          {hook.privacy?.requests.map((request) => `${request.type}/${request.status}`).join(',')}
        </p>
      );
    }
    const container = await mount(
      <IamProvider client={client}>
        <Banner />
      </IamProvider>,
    );
    await settle();
    await settle();
    expect(container.textContent).toBe('ready:newsletter:');
    await act(async () => {
      await hook!.decide(hook!.pending[0]!, true);
    });
    await settle();
    expect(backend.decisions).toEqual([{ purposeKey: 'newsletter', version: 3, granted: true }]);
    expect(container.textContent).toBe('ready::');
    let created: { id: string } | undefined;
    await act(async () => {
      created = await hook!.request('access', { details: 'Everything please' });
    });
    await settle();
    expect(container.textContent).toBe('ready::access/open');
    await act(async () => {
      await hook!.cancel(created!.id);
    });
    await settle();
    expect(container.textContent).toBe('ready::access/cancelled');
  });
});
