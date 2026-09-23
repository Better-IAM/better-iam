// @vitest-environment happy-dom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { IamProvider, useMySpend, useSpendCheck } from '@better-iam/react';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

interface ExampleIam {
  api: {
    auth: {
      getSession(credential: { headers?: HeadersInit }): Promise<{ identity: { id: string } }>;
    };
    billing: {
      mySpend(
        credential: { headers?: HeadersInit },
        input: { tenantId: string; period?: string; groupBy?: string },
      ): Promise<unknown>;
      check(
        credential: { headers?: HeadersInit },
        input: { tenantId: string; meter?: string },
      ): Promise<unknown>;
    };
  };
}

const budget = {
  budgetId: 'b1',
  name: 'Staging API calls',
  subjectType: 'identity',
  subjectId: 'alice',
  period: 'month',
  amountMicros: 60_000_000,
  spentMicros: 72_000_000,
  percent: 120,
  reached: [50, 80, 100],
  exceeded: true,
  enforce: true,
};

/** A fake IAM server answering `billing/mySpend` and `billing/check` like the real one. */
function server() {
  const calls: string[] = [];
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, string>;
    calls.push(`${path}:${JSON.stringify(body)}`);
    if (path === 'auth/getSession') return Response.json({ data: { identity: { id: 'alice' } } });
    if (path === 'billing/mySpend')
      return Response.json({
        data: {
          tenantId: body.tenantId,
          currency: 'USD',
          period: body.period ?? '2026-09',
          groupBy: body.groupBy ?? 'meter',
          rows: [
            {
              key: 'api-calls',
              label: 'API calls',
              costMicros: 72_000_000,
              amount: 72,
              share: 100,
              events: 3,
              quantities: { 'api-calls': 180_000 },
            },
          ],
          total: { costMicros: 72_000_000, amount: 72, events: 3 },
          budgets: [budget],
        },
      });
    if (path === 'billing/check')
      return Response.json({ data: { allowed: false, budgets: [budget], blockedBy: budget } });
    return Response.json({ error: { code: 'NOT_FOUND', message: 'nope' } }, { status: 404 });
  };
  return { calls, fetcher };
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

describe('billing hooks', () => {
  it("load the person's own spend and whether an enforced budget blocks them", async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    function Spend() {
      const mine = useMySpend({ tenantId: 'acme', period: '2026-08', groupBy: 'day' });
      const guard = useSpendCheck({ tenantId: 'acme', meter: 'api-calls' });
      return (
        <p>
          {mine.status}:{mine.spend?.total.amount ?? '-'}:{mine.spend?.budgets[0]?.name ?? '-'}|
          {guard.status}:{String(guard.allowed)}:{guard.blockedBy?.name ?? '-'}
        </p>
      );
    }
    const container = await mount(
      <IamProvider client={client}>
        <Spend />
      </IamProvider>,
    );
    await settle();
    await settle();
    expect(container.textContent).toBe('ready:72:Staging API calls|ready:false:Staging API calls');
    expect(backend.calls).toContain(
      'billing/mySpend:{"tenantId":"acme","period":"2026-08","groupBy":"day"}',
    );
    expect(backend.calls).toContain('billing/check:{"tenantId":"acme","meter":"api-calls"}');
  });
});
