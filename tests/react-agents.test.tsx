// @vitest-environment happy-dom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import {
  IamProvider,
  useAgentCatalog,
  useConfirmations,
  useDelegations,
  useModels,
  type MemberConfirmation,
  type MemberDelegation,
} from '@better-iam/react';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Credential = { headers?: HeadersInit };
interface ExampleIam {
  api: {
    auth: { getSession(credential: Credential): Promise<{ identity: { id: string } }> };
    delegations: {
      listMine(credential: Credential, input: { tenantId: string }): Promise<MemberDelegation[]>;
      grant(credential: Credential, input: Record<string, unknown>): Promise<MemberDelegation>;
      approve(credential: Credential, input: Record<string, unknown>): Promise<MemberDelegation>;
      deny(credential: Credential, input: Record<string, unknown>): Promise<MemberDelegation>;
      revoke(credential: Credential, input: Record<string, unknown>): Promise<MemberDelegation>;
      listConfirmations(
        credential: Credential,
        input: Record<string, unknown>,
      ): Promise<MemberConfirmation[]>;
      decideConfirmation(
        credential: Credential,
        input: Record<string, unknown>,
      ): Promise<MemberConfirmation>;
    };
    agents: { catalog(credential: Credential, input: { tenantId: string }): Promise<unknown[]> };
    inference: {
      listMine(credential: Credential, input: { tenantId: string }): Promise<unknown[]>;
    };
  };
}

const delegation = (
  id: string,
  status: MemberDelegation['status'],
  agent: string,
): MemberDelegation => ({
  id,
  status,
  expired: false,
  agent: { id: `agent-${agent}`, name: agent },
  subject: { id: 'alice', name: 'Alice' },
  scopes: ['documents:read'],
  requestedBy: status === 'pending' ? 'agent' : 'subject',
  createdAt: 1,
  expiresAt: 2,
});

/** A fake IAM server for the agent self-service routes. */
function server() {
  const calls: { path: string; body: Record<string, unknown> }[] = [];
  const delegations = [delegation('d1', 'pending', 'Inbox'), delegation('d2', 'active', 'Triage')];
  const confirmations: MemberConfirmation[] = [
    {
      id: 'c1',
      delegationId: 'd2',
      agent: { id: 'agent-Triage', name: 'Triage' },
      action: 'documents:delete',
      resource: { type: 'document', id: 'draft' },
      status: 'pending',
      expired: false,
      createdAt: 1,
      expiresAt: 2,
      validSeconds: 300,
    },
  ];
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    calls.push({ path, body });
    const data = (value: unknown) => Response.json({ data: value });
    switch (path) {
      case 'auth/getSession':
        return data({ identity: { id: 'alice' } });
      case 'delegations/listMine':
        return data(delegations);
      case 'delegations/approve':
      case 'delegations/deny':
      case 'delegations/revoke': {
        const found = delegations.find((item) => item.id === body.delegationId)!;
        found.status =
          path === 'delegations/approve'
            ? 'active'
            : path === 'delegations/deny'
              ? 'denied'
              : 'revoked';
        return data(found);
      }
      case 'delegations/grant': {
        const created = delegation('d3', 'active', 'Calendar');
        delegations.push(created);
        return data(created);
      }
      case 'delegations/listConfirmations':
        return data(confirmations.filter((item) => item.status === body.status));
      case 'delegations/decideConfirmation': {
        const found = confirmations.find((item) => item.id === body.confirmationId)!;
        found.status = body.approve ? 'approved' : 'rejected';
        return data(found);
      }
      case 'agents/catalog':
        return data([{ id: 'agent-Inbox', name: 'Inbox', sponsorName: 'Olivia' }]);
      case 'inference/listMine':
        return data([
          { name: 'haiku', provider: { id: 'p', name: 'Anthropic', kind: 'anthropic' } },
        ]);
      default:
        return Response.json({ error: { code: 'NOT_FOUND', message: path } }, { status: 404 });
    }
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

describe('agent self-service hooks', () => {
  it('lists, approves, revokes and grants delegations, and answers confirmations', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    let actions: ReturnType<typeof useDelegations> | undefined;
    let answers: ReturnType<typeof useConfirmations> | undefined;
    function Agents() {
      actions = useDelegations({ tenantId: 'acme' });
      answers = useConfirmations({ tenantId: 'acme' });
      const catalog = useAgentCatalog({ tenantId: 'acme' });
      const models = useModels({ tenantId: 'acme' });
      return (
        <p>
          {actions.status}|requests:{actions.requests.map((item) => item.agent.name).join(',')}
          |active:
          {actions.active.map((item) => item.agent.name).join(',')}|confirm:
          {answers.pending.map((item) => item.action).join(',')}|catalog:
          {catalog.agents.map((agent) => agent.name).join(',')}|models:
          {models.models.map((model) => model.name).join(',')}
        </p>
      );
    }
    const container = await mount(
      <IamProvider client={client}>
        <Agents />
      </IamProvider>,
    );
    await settle();
    await settle();
    expect(container.textContent).toBe(
      'ready|requests:Inbox|active:Triage|confirm:documents:delete|catalog:Inbox|models:haiku',
    );

    await act(async () => {
      await actions!.approve('d1', { scopes: ['documents:read'], confirm: ['documents:write'] });
    });
    await settle();
    expect(backend.calls.find((call) => call.path === 'delegations/approve')?.body).toEqual({
      tenantId: 'acme',
      delegationId: 'd1',
      scopes: ['documents:read'],
      confirm: ['documents:write'],
    });
    expect(container.textContent).toContain('requests:|active:Inbox,Triage');

    await act(async () => {
      await actions!.revoke('d2');
      await answers!.approve('c1');
    });
    await settle();
    expect(container.textContent).toContain('active:Inbox|confirm:|');
    expect(
      backend.calls.find((call) => call.path === 'delegations/decideConfirmation')?.body,
    ).toEqual({
      tenantId: 'acme',
      confirmationId: 'c1',
      approve: true,
    });

    await act(async () => {
      await actions!.grant({ agentId: 'agent-Calendar', scopes: ['calendar:read'] });
    });
    await settle();
    expect(container.textContent).toContain('active:Inbox,Calendar');
  });
});
