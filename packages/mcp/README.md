# @better-iam/mcp

Tool-level authorization for [Model Context Protocol](https://modelcontextprotocol.io) servers, backed by Better IAM.

`createMcpGate` sits in front of any Streamable HTTP MCP endpoint:

- authenticates the caller: a Better IAM credential (a person's session, a service account or AI agent key, or a
  delegated agent session acting for a person), or an OAuth access token from the Better IAM authorization server;
- answers unauthenticated requests with `401` and a `WWW-Authenticate` challenge that names the endpoint's protected
  resource metadata (RFC 9728), which the gate serves;
- refuses `tools/call` requests the caller may not make, as an MCP tool error the model can read;
- removes the tools the caller may not use from `tools/list` answers, in JSON and in event streams.

```ts
import { betterIam } from 'better-iam';
import { createMcpGate } from '@better-iam/mcp';

const iam = betterIam({
  /* ... */
});
const gate = createMcpGate({
  iam,
  tenantId, // the organization that runs this server: decisions are made there (required)
  tools: {
    search_tickets: { action: 'tickets:read', resource: { type: 'ticket', id: 'index' } },
    close_ticket: {
      action: 'tickets:update',
      resource: (args) => ({ type: 'ticket', id: String(args.id) }),
      listAs: { type: 'ticket', id: 'any' },
      scopes: ['tickets.write'],
    },
    ping: { public: true },
  },
  metadata: {
    resource: 'https://mcp.example.com/mcp',
    authorizationServers: ['https://iam.example.com/oauth'],
  },
});

export default {
  fetch: (request: Request) => gate(request, (forwarded, caller) => mcpHandler(forwarded, caller)),
};
```

Better IAM credentials are decided by the policy engine in `tenantId`, the organization that runs the server (a
function may pick it per caller, or return undefined to refuse them): `action` on `resource` (a fixed reference, one
derived from the tool's arguments, or `{ type: 'mcp-tool', id: toolName }` by default). OAuth access tokens (pass the
verifier of `@better-iam/oauth` as `oauth`) are decided by each tool's `scopes`, and a token issued for another tenant
is refused. Tools without a rule are hidden and refused unless `unlisted: 'allow'`. Request bodies are read up to
`maxBodyBytes` (4 MiB by default) and passed to the server exactly as the gate parsed them.

When an agent acting for a person (a delegated session) calls a tool whose action the person confirms one call at a
time (the delegation's `confirm` list), the gate files the confirmation request with the person on the agent's behalf
(`delegations.requestConfirmation`) and answers with a tool error telling the model to retry after the approval; the
request id is in `_meta['better-iam/confirmationId']`. Set `confirmations: false` to turn this off, and
`confirmationReason(tool, args)` to word the request.

`createMcpAuthorizer(options)` exposes `authenticate(request)`, `canCall(caller, name, args)`, and
`visibleTools(caller, tools)` for tool handlers written directly with an MCP SDK.

See [AI agents](../../docs/agents.md) for agents, sponsors, and delegation.
