import { afterEach, describe, expect, it } from 'vitest';
import { createMcpGate, type McpCaller, type McpOAuthVerifier } from '@better-iam/mcp';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const tools = [
  { name: 'search_docs', description: 'Search', inputSchema: { type: 'object' } },
  { name: 'delete_doc', description: 'Delete', inputSchema: { type: 'object' } },
  { name: 'ping', description: 'Ping', inputSchema: { type: 'object' } },
  { name: 'secret_tool', description: 'Not in the rules', inputSchema: { type: 'object' } },
];

/** A stand-in MCP server: answers tools/list (JSON, or SSE when asked) and echoes tools/call with the caller. */
function mcpServer() {
  const calls: { method: string; caller: McpCaller; params?: unknown }[] = [];
  const handle = async (request: Request, caller: McpCaller): Promise<Response> => {
    const message = (await request.json()) as {
      id: number;
      method: string;
      params?: Record<string, unknown>;
    };
    calls.push({ method: message.method, caller, params: message.params });
    if (message.method === 'tools/list') {
      const response = { jsonrpc: '2.0', id: message.id, result: { tools } };
      if (request.headers.get('x-test-sse')) {
        const text = `event: message\ndata: ${JSON.stringify({ jsonrpc: '2.0', method: 'notifications/progress' })}\n\nevent: message\ndata: ${JSON.stringify(response)}\n\n`;
        const bytes = new TextEncoder().encode(text);
        return new Response(
          new ReadableStream({
            start(controller) {
              for (let index = 0; index < bytes.length; index += 23)
                controller.enqueue(bytes.slice(index, index + 23));
              controller.close();
            },
          }),
          { headers: { 'content-type': 'text/event-stream' } },
        );
      }
      return Response.json(response);
    }
    return Response.json({
      jsonrpc: '2.0',
      id: message.id,
      result: { content: [{ type: 'text', text: `ran ${String(message.params?.name)}` }] },
    });
  };
  return { calls, handle };
}

const oauth: McpOAuthVerifier = {
  async verifyRequest(request) {
    if (request.authorization !== 'Bearer oauth-access-token') throw new Error('invalid token');
    return { subject: 'user-1', clientId: 'claude-desktop', scopes: ['docs.search'] };
  },
};

async function setup() {
  const f = await organizationFixture();
  const server = mcpServer();
  const gate = createMcpGate({
    iam: f.iam,
    tenantId: f.tenantId,
    tools: {
      search_docs: {
        action: 'documents:read',
        resource: { type: 'document', id: 'index' },
        scopes: ['docs.search'],
      },
      delete_doc: {
        action: 'documents:write',
        resource: (args) => ({ type: 'document', id: String(args.id) }),
        listAs: { type: 'document', id: 'any' },
        scopes: ['docs.delete'],
      },
      ping: { public: true },
    },
    oauth,
    metadata: {
      resource: 'https://mcp.acme.test/mcp',
      authorizationServers: ['https://iam.acme.test/oauth'],
      scopes: ['docs.search', 'docs.delete'],
    },
  });
  const rpc = async (
    token: string | undefined,
    method: string,
    params?: unknown,
    headers: Record<string, string> = {},
  ) =>
    gate(
      new Request('https://mcp.acme.test/mcp', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          accept: 'application/json, text/event-stream',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          ...headers,
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 7, method, ...(params ? { params } : {}) }),
      }),
      server.handle,
    );
  return { f, server, gate, rpc };
}

async function grantDocuments(f: OrganizationFixture, subjectId: string, actions: string[]) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Docs ${subjectId}`,
    document: { version: 1, statements: [{ effect: 'allow', actions, resources: ['document/*'] }] },
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId,
  });
}

const names = async (response: Response) =>
  ((await response.json()) as { result: { tools: { name: string }[] } }).result.tools.map(
    (tool) => tool.name,
  );

describe('MCP gate', () => {
  it('challenges unauthenticated callers and serves protected resource metadata', async () => {
    const { gate, rpc, server } = await setup();
    const anonymous = await rpc(undefined, 'tools/list');
    expect(anonymous.status).toBe(401);
    expect(anonymous.headers.get('www-authenticate')).toBe(
      'Bearer resource_metadata="https://mcp.acme.test/.well-known/oauth-protected-resource/mcp"',
    );
    const invalid = await rpc(
      'biam_key_not-a-real-key-at-all-0000000000000000000000000',
      'tools/list',
    );
    expect(invalid.status).toBe(401);
    expect(invalid.headers.get('www-authenticate')).toContain('error="invalid_token"');
    const metadata = await gate(
      new Request('https://mcp.acme.test/.well-known/oauth-protected-resource/mcp'),
      server.handle,
    );
    expect(await metadata.json()).toEqual({
      resource: 'https://mcp.acme.test/mcp',
      authorization_servers: ['https://iam.acme.test/oauth'],
      scopes_supported: ['docs.search', 'docs.delete'],
      bearer_methods_supported: ['header'],
    });
    expect(server.calls).toHaveLength(0);
  });

  it('decides an agent’s tool calls with its own grants and filters the tool list', async () => {
    const { f, rpc, server } = await setup();
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Docs agent',
    });
    await grantDocuments(f, agent.id, ['documents:read']);
    const { token } = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });

    expect(await names(await rpc(token, 'tools/list'))).toEqual(['search_docs', 'ping']);
    const allowed = await rpc(token, 'tools/call', { name: 'search_docs', arguments: { q: 'x' } });
    expect(await allowed.json()).toMatchObject({
      result: { content: [{ text: 'ran search_docs' }] },
    });
    expect(server.calls.at(-1)!.caller).toMatchObject({
      kind: 'iam',
      identityKind: 'agent',
      agentId: agent.id,
      tenantId: f.tenantId,
    });

    const refused = await rpc(token, 'tools/call', { name: 'delete_doc', arguments: { id: 'q3' } });
    expect(await refused.json()).toEqual({
      jsonrpc: '2.0',
      id: 7,
      result: {
        content: [{ type: 'text', text: 'Access denied: you may not call delete_doc' }],
        isError: true,
      },
    });
    const unknown = await rpc(token, 'tools/call', { name: 'secret_tool' });
    expect(await unknown.json()).toMatchObject({
      result: { isError: true, content: [{ text: 'Unknown tool: secret_tool' }] },
    });
    // Refused calls never reach the server, and the server audits the denial with the agent attached.
    expect(server.calls.map((call) => call.method)).toEqual(['tools/list', 'tools/call']);
    const denials = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'documents:write',
      outcome: 'deny',
    });
    expect(denials[0]).toMatchObject({ actorId: agent.id, resourceId: 'q3' });

    // The same list arrives filtered inside an event stream.
    const streamed = await rpc(token, 'tools/list', undefined, { 'x-test-sse': '1' });
    const text = await streamed.text();
    expect(text).toContain('notifications/progress');
    const data = text
      .split('\n')
      .filter((line) => line.startsWith('data: ') && line.includes('"tools"'))
      .map((line) => JSON.parse(line.slice(6)) as { result: { tools: { name: string }[] } });
    expect(data[0]!.result.tools.map((tool) => tool.name)).toEqual(['search_docs', 'ping']);
  });

  it('lets a delegated agent act as the person, within the delegation', async () => {
    const { f, rpc } = await setup();
    const alice = await f.member('alice');
    await grantDocuments(f, alice.id, ['documents:read', 'documents:write']);
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Assistant',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:*'],
    });
    const acting = await f.iam.api.delegations.assume(
      { token: key.token },
      { tenantId: f.tenantId, delegationId: delegation.id },
    );
    expect(await names(await rpc(acting.token, 'tools/list'))).toEqual([
      'search_docs',
      'delete_doc',
      'ping',
    ]);
    const deleted = await rpc(acting.token, 'tools/call', {
      name: 'delete_doc',
      arguments: { id: 'draft' },
    });
    expect(await deleted.json()).toMatchObject({
      result: { content: [{ text: 'ran delete_doc' }] },
    });

    // Narrow the delegation to reading and the destructive tool disappears.
    await f.iam.api.delegations.revoke(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect((await rpc(acting.token, 'tools/list')).status).toBe(401);
    const fresh = { token: (await f.signIn('alice')).token };
    const readOnly = await f.iam.api.delegations.grant(fresh, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:read'],
    });
    const reader = await f.iam.api.delegations.assume(
      { token: key.token },
      { tenantId: f.tenantId, delegationId: readOnly.id },
    );
    expect(await names(await rpc(reader.token, 'tools/list'))).toEqual(['search_docs', 'ping']);
  });

  it('asks the person to confirm a held-back tool call, then lets the retry through', async () => {
    const { f, rpc, server } = await setup();
    const alice = await f.member('alice');
    await grantDocuments(f, alice.id, ['documents:read', 'documents:write']);
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Careful agent',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:*'],
      confirm: ['documents:write'],
    });
    const acting = await f.iam.api.delegations.assume(
      { token: key.token },
      { tenantId: f.tenantId, delegationId: delegation.id },
    );
    const first = (await (
      await rpc(acting.token, 'tools/call', { name: 'delete_doc', arguments: { id: 'draft' } })
    ).json()) as {
      result: { isError: boolean; content: { text: string }[]; _meta?: Record<string, unknown> };
    };
    expect(first.result.isError).toBe(true);
    expect(first.result.content[0]!.text).toContain('must confirm this call first');
    const confirmationId = first.result._meta?.['better-iam/confirmationId'] as string;
    expect(confirmationId).toEqual(expect.any(String));
    const pending = await f.iam.api.delegations.listConfirmations(aliceSession, {
      tenantId: f.tenantId,
      status: 'pending',
    });
    expect(pending).toEqual([
      expect.objectContaining({
        id: confirmationId,
        action: 'documents:write',
        resource: { type: 'document', id: 'draft' },
        reason: expect.stringContaining('delete_doc'),
      }),
    ]);
    // Reading is not held back.
    expect(
      await (await rpc(acting.token, 'tools/call', { name: 'search_docs' })).json(),
    ).toMatchObject({ result: { content: [{ text: 'ran search_docs' }] } });

    await f.iam.api.delegations.decideConfirmation(aliceSession, {
      tenantId: f.tenantId,
      confirmationId,
      approve: true,
    });
    const retry = await rpc(acting.token, 'tools/call', {
      name: 'delete_doc',
      arguments: { id: 'draft' },
    });
    expect(await retry.json()).toMatchObject({ result: { content: [{ text: 'ran delete_doc' }] } });
    expect(server.calls.filter((call) => call.method === 'tools/call')).toHaveLength(2);
  });

  it('decides OAuth callers by scope', async () => {
    const { rpc, server } = await setup();
    expect(await names(await rpc('oauth-access-token', 'tools/list'))).toEqual([
      'search_docs',
      'ping',
    ]);
    const refused = await rpc('oauth-access-token', 'tools/call', {
      name: 'delete_doc',
      arguments: { id: 1 },
    });
    expect(await refused.json()).toMatchObject({ result: { isError: true } });
    await rpc('oauth-access-token', 'tools/call', { name: 'search_docs' });
    expect(server.calls.at(-1)!.caller).toEqual({
      kind: 'oauth',
      clientId: 'claude-desktop',
      subject: 'user-1',
      scopes: ['docs.search'],
    });
    // Other methods pass straight through.
    const initialize = await rpc('oauth-access-token', 'initialize', {
      protocolVersion: '2025-11-25',
    });
    expect(initialize.status).toBe(200);
  });

  it('decides in the server’s own tenant, never the caller’s, and bounds request bodies', async () => {
    const { f, server } = await setup();
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Elsewhere',
    });
    await grantDocuments(f, agent.id, ['documents:read']);
    const { token } = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    // A gate that belongs to another tenant (the platform root) does not honour grants the caller holds in Acme.
    const foreign = createMcpGate({
      iam: f.iam,
      tenantId: f.root.tenant.id,
      tools: { search_docs: { action: 'documents:read', resource: { type: 'document', id: 'x' } } },
    });
    const call = (gate: typeof foreign, body: BodyInit, headers: Record<string, string> = {}) =>
      gate(
        new Request('https://mcp.acme.test/mcp', {
          method: 'POST',
          headers: {
            'content-type': 'application/json',
            authorization: `Bearer ${token}`,
            ...headers,
          },
          body,
          ...(body instanceof ReadableStream ? { duplex: 'half' } : {}),
        } as RequestInit),
        server.handle,
      );
    const refused = await call(
      foreign,
      JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/call',
        params: { name: 'search_docs' },
      }),
    );
    expect(await refused.json()).toMatchObject({ result: { isError: true } });
    // A body without a declared length is still cut off at the limit.
    const small = createMcpGate({
      iam: f.iam,
      tenantId: f.tenantId,
      tools: {},
      maxBodyBytes: 1024,
    });
    const chunk = new TextEncoder().encode('x'.repeat(600));
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let index = 0; index < 5; index++) controller.enqueue(chunk);
        controller.close();
      },
    });
    expect((await call(small, stream)).status).toBe(413);
    expect(server.calls).toHaveLength(0);
  });
});
