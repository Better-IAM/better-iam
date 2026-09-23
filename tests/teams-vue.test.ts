// @vitest-environment happy-dom
import { createApp, defineComponent, h, nextTick, type Component } from 'vue';
import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import { createIam, useTeams, type MemberTeams } from '@better-iam/vue';

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

function server() {
  const data: MemberTeams = {
    teams: [{ id: 't2', name: 'SRE', slug: 'sre', role: 'maintainer', parents: [] }],
    requests: [],
    joinable: [{ id: 't3', name: 'Data', slug: 'data', memberCount: 4 }],
  };
  const fetcher: typeof fetch = async (input, init) => {
    const path = new URL(String(input)).pathname.replace('/api/iam/', '');
    const body = JSON.parse(String(init?.body ?? '{}')) as Record<string, unknown>;
    if (path === 'auth/getSession') return Response.json({ data: { identity: { id: 'alice' } } });
    if (path === 'teams/listMine') return Response.json({ data });
    if (path === 'teams/requestToJoin') {
      data.requests.push({
        id: 'r1',
        team: { id: 't3', name: 'Data', slug: 'data' },
        status: 'pending',
        requestedAt: 1,
        expiresAt: 2,
      });
      return Response.json({ data: data.requests[0] });
    }
    if (path === 'teams/leave') {
      data.teams = data.teams.filter((team) => team.id !== body.teamId);
      return Response.json({ data: { left: true } });
    }
    return Response.json({ error: { code: 'NOT_FOUND', message: 'nope' } }, { status: 404 });
  };
  return { fetcher };
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

describe('vue useTeams', () => {
  it('lists the person’s teams, asks to join, and leaves', async () => {
    const client = createIamClient<ExampleIam>({
      baseURL: 'https://app.example.test',
      fetch: server().fetcher,
    });
    let teams!: ReturnType<typeof useTeams>;
    const View = defineComponent({
      setup() {
        teams = useTeams({ tenantId: 'acme' });
        return () =>
          h(
            'p',
            `${teams.teams.value.map((team) => `${team.name}:${team.role}`).join(',')}|${teams.pending.value
              .map((request) => request.team.name)
              .join(',')}|${teams.joinable.value.map((team) => team.name).join(',')}`,
          );
      },
    });
    const root = mount(View, createIam({ client }));
    await settle();
    expect(root.textContent).toBe('SRE:maintainer||Data');
    await teams.requestToJoin('t3');
    await settle();
    expect(root.textContent).toBe('SRE:maintainer|Data|');
    await teams.leave('t2');
    await settle();
    expect(root.textContent).toBe('|Data|');
  });
});
