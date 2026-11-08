# better-iam-mcp

Tool-level authorization for Model Context Protocol servers with [Better IAM](https://github.com/Better-IAM/better-iam)
in Rust, the counterpart of the `@better-iam/mcp` npm package.

`McpGate` sits in front of any Streamable HTTP MCP endpoint (an `http::Request` → `http::Response` handler):

- it authenticates the caller: a Better IAM credential (a person's session, a service account or AI agent key, or a
  delegated agent session acting for a person), or an OAuth access token checked by an `McpOAuthVerifier`;
- it answers unauthenticated requests with a `WWW-Authenticate` challenge that points at the endpoint's protected
  resource metadata (RFC 9728), which it serves;
- it refuses `tools/call` requests the caller may not make (Better IAM credentials are decided by the policy engine as
  `action` on `resource` in the MCP server's own tenant; OAuth tokens by each tool's scopes), and asks the person to
  confirm a delegated agent's call when the delegation holds that action back;
- it removes the tools the caller may not use from `tools/list` answers, in JSON bodies and in event streams.

`McpAuthorizer` exposes the same decisions for tool handlers written with an MCP SDK.

```rust,ignore
use better_iam_mcp::{McpAuthorizerOptions, McpGate, McpGateOptions, McpResource, McpResourceRef, McpTenant, McpToolRule};

let mut tools = HashMap::new();
tools.insert("search_docs".into(), McpToolRule {
    action: Some("documents:read".into()),
    resource: Some(McpResource::Fixed(McpResourceRef::new("document", "index"))),
    ..Default::default()
});
let gate = McpGate::new(McpGateOptions {
    authorizer: McpAuthorizerOptions::new(iam.clone(), McpTenant::Fixed(tenant_id), tools),
    metadata: None,
    max_body_bytes: None,
})?;
let response = gate.handle(request, |request, caller| mcp_server.handle(request, caller)).await?;
```

Any `BetterIam` (or a value that borrows one, such as `Arc<BetterIam>`) is an `McpIam`.
