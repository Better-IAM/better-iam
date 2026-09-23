// @vitest-environment happy-dom
import { act, type ReactNode } from 'react';
import { createRoot, type Root } from 'react-dom/client';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { IamProvider, useTeams, type MemberTeams } from '@better-iam/react';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

type Credential = { headers?: HeadersInit };
interface ExampleIam {
  api: {
    auth: {
      getSession(credential: Credential): Promise<{ identity: { id: string } }>;
      signOut(credential: Credential): Promise<{ success: true }>;
    };
    teams: {
      listMine(credential: Credential, input: { tenantId: string }): Promise<MemberTeams>;
      requestToJoin(
        credential: Credential,
        input: { tenantId: string; teamId: string; justification?: string },
      ): Promise<unknown>;
      cancelRequest(
        credential: Credential,
        input: { tenantId: string; requestId: string },
      ): Promise<unknown>;
      leave(credential: Credential, input: { tenantId: string; teamId: string }): Promise<unknown>;
    };
  };
}

/** A fake IAM server for the team self-service routes. */
function server() {
  const calls: Array<[string, Record<string, unknown>]> = [];
  const platform = { id: 't1', name: 'Platform', slug: 'platform' };
  const data: MemberTeams = {
    teams: [{ id: 't2', name: 'SRE', slug: 'sre', role: 'member', parents: [platform] }],
    requests: [],
    joinable: [
      { id: 't3', name: 'Data', slug: 'data', memberCount: 4 },
      { id: 't4', name: 'Design', slug: 'design', memberCount: 2 },
    ],
  };
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    calls.push([path, body]);
    if (path === 'auth/getSession') return Response.json({ data: { identity: { id: 'alice' } } });
    if (path === 'teams/listMine') return Response.json({ data });
    if (path === 'teams/requestToJoin') {
      const team = data.joinable.find((item) => item.id === body.teamId)!;
      data.requests.push({
        id: `r-${team.id}`,
        team: { id: team.id, name: team.name, slug: team.slug },
        status: 'pending',
        requestedAt: 1,
        expiresAt: 2,
        ...(typeof body.justification === 'string' ? { justification: body.justification } : {}),
      });
      return Response.json({ data: data.requests.at(-1) });
    }
    if (path === 'teams/cancelRequest') {
      const request = data.requests.find((item) => item.id === body.requestId)!;
      request.status = 'cancelled';
      return Response.json({ data: request });
    }
    if (path === 'teams/leave') {
      data.teams = data.teams.filter((team) => team.id !== body.teamId);
      return Response.json({ data: { left: true } });
    }
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

describe('useTeams', () => {
  it('lists the person’s teams and joins, withdraws, and leaves', async () => {
    const backend = server();
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: backend.fetcher,
    });
    let hook: ReturnType<typeof useTeams> | undefined;
    function MyTeams() {
      hook = useTeams({ tenantId: 'acme' });
      return (
        <p>
          {hook.status}|
          {hook.teams.map((team) => `${team.name}<${team.parents.map((p) => p.name)}`).join(',')}|
          {hook.pending.map((request) => request.team.name).join(',')}|
          {hook.joinable.map((team) => team.name).join(',')}
        </p>
      );
    }
    const container = await mount(
      <IamProvider client={client}>
        <MyTeams />
      </IamProvider>,
    );
    await settle();
    await settle();
    expect(container.textContent).toBe('ready|SRE<Platform||Data,Design');

    await act(async () => {
      await hook!.requestToJoin('t3', 'Pairing with the data team');
    });
    await settle();
    expect(container.textContent).toBe('ready|SRE<Platform|Data|Design');
    expect(backend.calls.find(([path]) => path === 'teams/requestToJoin')?.[1]).toEqual({
      tenantId: 'acme',
      teamId: 't3',
      justification: 'Pairing with the data team',
    });

    await act(async () => {
      await hook!.cancelRequest('r-t3');
    });
    await settle();
    expect(container.textContent).toBe('ready|SRE<Platform||Data,Design');

    await act(async () => {
      await hook!.leave('t2');
    });
    await settle();
    expect(container.textContent).toBe('ready|||Data,Design');
  });
});
