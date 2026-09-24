import { IamError, matchPattern, type CredentialInput } from '@better-iam/core';

/**
 * Tool-level authorization for Model Context Protocol servers.
 *
 * `createMcpGate` sits in front of any Streamable HTTP MCP endpoint (a `Request` → `Response` handler): it
 * authenticates the caller, answers unauthenticated requests with a `WWW-Authenticate` challenge that points at the
 * endpoint's protected resource metadata (RFC 9728, served by the gate), refuses `tools/call` requests the caller may
 * not make, and removes the tools the caller may not use from `tools/list` answers, in JSON and in event streams.
 *
 * Callers present either a Better IAM credential (a person's session, a service account or AI agent key, or a
 * delegated agent session acting for a person), decided by the Better IAM policy engine as `action` on `resource`, or
 * an OAuth access token from the Better IAM authorization server (verified by `@better-iam/oauth`), decided by its
 * scopes. `createMcpAuthorizer` exposes the same decisions for tool handlers written with an MCP SDK.
 */

/** A resource the policy engine decides on. */
export interface McpResourceRef {
  type: string;
  id: string;
}

/** How one tool is authorized. */
export interface McpToolRule {
  /** The Better IAM action a call needs (Better IAM credentials). */
  action?: string;
  /**
   * The resource the call acts on: a fixed reference, or one derived from the call's arguments. Defaults to
   * `{ type: toolResourceType, id: toolName }`. Tools with derived resources are listed for everyone the rule could
   * allow (their `listAs` resource, when given, decides the listing).
   */
  resource?: McpResourceRef | ((args: Record<string, unknown>) => McpResourceRef);
  /** The resource that decides whether a tool with a derived `resource` appears in `tools/list`. */
  listAs?: McpResourceRef;
  /** Scopes an OAuth access token needs for the tool (OAuth callers). */
  scopes?: string[];
  /** Any authenticated caller may use the tool. */
  public?: boolean;
}

/** The part of a Better IAM instance (`betterIam()`) or client the gate needs. */
export interface McpIam {
  authenticate(credential: CredentialInput): Promise<{
    identity: { id: string; tenantId: string; kind: string; name?: string };
    session: {
      id: string;
      tenantId: string;
      kind: string;
      agentId?: string;
      delegationId?: string;
    };
  }>;
  authorize(
    request: CredentialInput & { tenantId: string; action: string; resource: McpResourceRef },
  ): Promise<{ allowed: boolean; reason: string }>;
  authorizeMany(
    request: CredentialInput & {
      tenantId: string;
      checks: { action: string; resource: McpResourceRef }[];
    },
  ): Promise<{ results: { allowed: boolean; reason: string }[] }>;
  /** Present on a `betterIam()` instance: lets the gate ask a person to confirm an agent's action. */
  api?: { delegations?: McpDelegationsApi };
}

/** The part of the `delegations` API the gate uses for per-action confirmations. */
export interface McpDelegationsApi {
  get(
    credential: CredentialInput,
    input: { tenantId: string; delegationId: string },
  ): Promise<{ confirm?: string[] }>;
  requestConfirmation(
    credential: CredentialInput,
    input: { tenantId: string; action: string; resource: McpResourceRef; reason: string },
  ): Promise<{ id: string; status: string; expiresAt: number }>;
}

/** The access-token verifier of `@better-iam/oauth` (`createAccessTokenVerifier` or a resource guard's `verifier`). */
export interface McpOAuthVerifier {
  verifyRequest(
    request: { authorization: string | null; dpop?: string | null; method: string; url: string },
    requirement?: { scopes?: string[] },
  ): Promise<{ subject?: string; clientId: string; tenantId?: string; scopes: string[] }>;
}

/** Who is calling the MCP server. */
export type McpCaller =
  | {
      kind: 'iam';
      credential: CredentialInput;
      /** The tenant decisions are made in. */
      tenantId: string;
      identityId: string;
      identityKind: string;
      sessionKind: string;
      /** The agent behind the credential: its own key, or the agent of a delegated session. */
      agentId?: string;
      delegationId?: string;
    }
  | {
      kind: 'oauth';
      subject?: string;
      clientId: string;
      tenantId?: string;
      scopes: string[];
    };

export interface McpAuthorizerOptions {
  /** The Better IAM instance or client that authenticates credentials and decides. */
  iam: McpIam;
  /** Rules by tool name. */
  tools: Record<string, McpToolRule>;
  /** Tools without a rule: refused and hidden (`deny`, the default) or open to any authenticated caller (`allow`). */
  unlisted?: 'deny' | 'allow';
  /** The resource type of the default per-tool resource (default `mcp-tool`). */
  toolResourceType?: string;
  /**
   * The tenant decisions are made in: the organization that runs this MCP server (required). A function may choose it
   * per caller and returns undefined to refuse the caller. Deciding in each caller's own tenant would let any
   * organization grant itself access.
   */
  tenantId:
    | string
    | ((caller: { identityId: string; sessionTenantId: string }) => string | undefined);
  /**
   * Accepts OAuth access tokens too, decided by each tool's `scopes`. A token naming a tenant other than a fixed
   * `tenantId` is refused.
   */
  oauth?: McpOAuthVerifier;
  /**
   * When an agent acting for a person (a delegated session) calls a tool whose action the person confirms one call at
   * a time (the delegation's `confirm`), ask the person on the agent's behalf (`delegations.requestConfirmation`) and
   * tell the agent to retry after the approval. On by default when `iam.api.delegations` exists; `false` turns it off.
   */
  confirmations?: boolean;
  /** The reason shown to the person in a confirmation request (default: which tool the agent wants to run). */
  confirmationReason?: (tool: string, args: Record<string, unknown>) => string;
}

export interface McpDecision {
  allowed: boolean;
  /**
   * `ALLOWED`, `PUBLIC`, `ACCESS_DENIED`, `UNKNOWN_TOOL`, `NO_RULE_FOR_CALLER`, `INSUFFICIENT_SCOPE`, or
   * `CONFIRMATION_REQUESTED` (the person was asked to confirm; retry after they approve).
   */
  reason: string;
  /** For `CONFIRMATION_REQUESTED`: the request the person decides on. */
  confirmation?: { id: string; expiresAt: number };
}

/** The credential in a request: `Authorization: Bearer …` (or `DPoP …`), else `x-api-key`. */
function presented(request: Request): { token: string; scheme: string } | undefined {
  const match = /^(Bearer|DPoP)\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '');
  if (match) return { scheme: match[1]!, token: match[2]! };
  const key = request.headers.get('x-api-key');
  return key ? { scheme: 'Bearer', token: key } : undefined;
}

/** Decisions shared by the gate and by tool handlers written with an MCP SDK. */
export function createMcpAuthorizer(options: McpAuthorizerOptions) {
  const resourceType = options.toolResourceType ?? 'mcp-tool';
  const rule = (name: string): McpToolRule | undefined =>
    Object.hasOwn(options.tools, name)
      ? options.tools[name]
      : options.unlisted === 'allow'
        ? { public: true }
        : undefined;
  const resourceOf = (name: string, found: McpToolRule, args: Record<string, unknown>) =>
    typeof found.resource === 'function'
      ? found.resource(args)
      : (found.resource ?? { type: resourceType, id: name });

  /**
   * For a delegated caller refused an action its delegation holds back for confirmation: files the confirmation request
   * with the person and returns it. Undefined when that does not apply or the request cannot be made (the call is then
   * simply refused).
   */
  async function requestConfirmation(
    caller: McpCaller,
    tool: string,
    action: string,
    resource: McpResourceRef,
    args: Record<string, unknown>,
  ): Promise<{ id: string; expiresAt: number } | undefined> {
    const delegations = options.iam.api?.delegations;
    if (
      options.confirmations === false ||
      !delegations ||
      caller.kind !== 'iam' ||
      caller.sessionKind !== 'delegated' ||
      !caller.delegationId
    )
      return undefined;
    try {
      const delegation = await delegations.get(caller.credential, {
        tenantId: caller.tenantId,
        delegationId: caller.delegationId,
      });
      if (!delegation.confirm?.some((pattern) => matchPattern(pattern, action))) return undefined;
      const request = await delegations.requestConfirmation(caller.credential, {
        tenantId: caller.tenantId,
        action,
        resource,
        reason:
          options.confirmationReason?.(tool, args) ??
          `Your agent wants to run the tool ${tool} (${action} on ${resource.type}/${resource.id}).`,
      });
      return { id: request.id, expiresAt: request.expiresAt };
    } catch {
      return undefined;
    }
  }

  const authorizer = {
    /**
     * Authenticates a request's credential: a Better IAM credential first, then (with `oauth`) an OAuth access token.
     * Undefined when the request carries none or it is not valid.
     */
    async authenticate(request: Request): Promise<McpCaller | undefined> {
      const found = presented(request);
      if (!found) return undefined;
      if (found.scheme.toLowerCase() === 'bearer') {
        const credential: CredentialInput = { token: found.token, headers: request.headers };
        try {
          const principal = await options.iam.authenticate(credential);
          const tenantId =
            typeof options.tenantId === 'function'
              ? options.tenantId({
                  identityId: principal.identity.id,
                  sessionTenantId: principal.session.tenantId,
                })
              : options.tenantId;
          if (typeof tenantId !== 'string' || !tenantId) return undefined;
          const agentId =
            principal.session.kind === 'delegated'
              ? principal.session.agentId
              : principal.identity.kind === 'agent'
                ? principal.identity.id
                : undefined;
          return {
            kind: 'iam',
            credential,
            tenantId,
            identityId: principal.identity.id,
            identityKind: principal.identity.kind,
            sessionKind: principal.session.kind,
            ...(agentId ? { agentId } : {}),
            ...(principal.session.delegationId
              ? { delegationId: principal.session.delegationId }
              : {}),
          };
        } catch (error) {
          if (!(error instanceof Error) || !options.oauth) return undefined;
        }
      }
      if (!options.oauth) return undefined;
      try {
        const token = await options.oauth.verifyRequest({
          authorization: request.headers.get('authorization'),
          dpop: request.headers.get('dpop'),
          method: request.method,
          url: request.url,
        });
        // A token issued for another organization is not a token for this server.
        if (
          typeof options.tenantId === 'string' &&
          token.tenantId !== undefined &&
          token.tenantId !== options.tenantId
        )
          return undefined;
        return {
          kind: 'oauth',
          clientId: token.clientId,
          scopes: [...token.scopes],
          ...(token.subject ? { subject: token.subject } : {}),
          ...(token.tenantId ? { tenantId: token.tenantId } : {}),
        };
      } catch {
        return undefined;
      }
    },

    /** Whether the caller may call `name` with `args` (Better IAM denials are audited by the server). */
    async canCall(
      caller: McpCaller,
      name: string,
      args: Record<string, unknown> = {},
    ): Promise<McpDecision> {
      const found = rule(name);
      if (!found) return { allowed: false, reason: 'UNKNOWN_TOOL' };
      if (found.public) return { allowed: true, reason: 'PUBLIC' };
      if (caller.kind === 'oauth') {
        if (!found.scopes?.length) return { allowed: false, reason: 'NO_RULE_FOR_CALLER' };
        const missing = found.scopes.some((scope) => !caller.scopes.includes(scope));
        return missing
          ? { allowed: false, reason: 'INSUFFICIENT_SCOPE' }
          : { allowed: true, reason: 'ALLOWED' };
      }
      if (!found.action) return { allowed: false, reason: 'NO_RULE_FOR_CALLER' };
      let resource: McpResourceRef;
      try {
        resource = resourceOf(name, found, args);
      } catch {
        return { allowed: false, reason: 'ACCESS_DENIED' };
      }
      const decision = await options.iam.authorize({
        ...caller.credential,
        tenantId: caller.tenantId,
        action: found.action,
        resource,
      });
      if (decision.allowed) return { allowed: true, reason: 'ALLOWED' };
      const confirmation = await requestConfirmation(caller, name, found.action, resource, args);
      return confirmation
        ? { allowed: false, reason: 'CONFIRMATION_REQUESTED', confirmation }
        : { allowed: false, reason: 'ACCESS_DENIED' };
    },

    /** The tools the caller may see, in their original order (checked 50 at a time). */
    async visibleTools<T extends { name: string }>(caller: McpCaller, tools: T[]): Promise<T[]> {
      const visible = new Set<string>();
      const checks: { name: string; action: string; resource: McpResourceRef }[] = [];
      for (const tool of tools) {
        const found = rule(tool.name);
        if (!found) continue;
        if (found.public) visible.add(tool.name);
        else if (caller.kind === 'oauth') {
          if (found.scopes?.length && found.scopes.every((scope) => caller.scopes.includes(scope)))
            visible.add(tool.name);
        } else if (found.action) {
          if (typeof found.resource === 'function' && !found.listAs) visible.add(tool.name);
          else
            checks.push({
              name: tool.name,
              action: found.action,
              resource:
                typeof found.resource === 'function'
                  ? found.listAs!
                  : (found.resource ?? { type: resourceType, id: tool.name }),
            });
        }
      }
      if (caller.kind === 'iam')
        for (let index = 0; index < checks.length; index += 50) {
          const batch = checks.slice(index, index + 50);
          const { results } = await options.iam.authorizeMany({
            ...caller.credential,
            tenantId: caller.tenantId,
            checks: batch.map(({ action, resource }) => ({ action, resource })),
          });
          batch.forEach((check, position) => {
            if (results[position]?.allowed) visible.add(check.name);
          });
        }
      return tools.filter((tool) => visible.has(tool.name));
    },
  };
  return authorizer;
}
export type McpAuthorizer = ReturnType<typeof createMcpAuthorizer>;

/** RFC 9728 protected resource metadata the gate serves and names in its challenges. */
export interface McpResourceMetadata {
  /** The MCP endpoint's resource identifier (its canonical URL), the audience of OAuth tokens for it. */
  resource: string;
  /** Issuer URLs of the authorization servers that issue tokens for it (the Better IAM OAuth issuer). */
  authorizationServers: string[];
  scopes?: string[];
  resourceName?: string;
  documentation?: string;
}

export interface McpGateOptions extends McpAuthorizerOptions {
  /** Serve protected resource metadata and point 401 challenges at it (for OAuth-capable MCP clients). */
  metadata?: McpResourceMetadata;
  /** Largest accepted JSON-RPC body in bytes (default 4 MiB). */
  maxBodyBytes?: number;
}

/** Where RFC 9728 metadata lives for a resource: `/.well-known/oauth-protected-resource` + the resource path. */
export function protectedResourceMetadataUrl(resource: string): string {
  const url = new URL(resource);
  const path = url.pathname === '/' ? '' : url.pathname.replace(/\/$/, '');
  return `${url.origin}/.well-known/oauth-protected-resource${path}`;
}

interface JsonRpcRequest {
  jsonrpc: '2.0';
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

function jsonRpc(value: unknown): JsonRpcRequest | undefined {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return undefined;
  const message = value as Record<string, unknown>;
  return typeof message.method === 'string' ? (message as unknown as JsonRpcRequest) : undefined;
}

const json = (body: unknown, status = 200, headers: Record<string, string> = {}) =>
  new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });

/**
 * The gate: `gate(request, next)` answers the request itself (metadata, challenges, refused calls) or passes it to
 * `next` (the MCP server's handler) with the authenticated caller, filtering `tools/list` answers on the way back.
 */
export function createMcpGate(options: McpGateOptions) {
  const authorizer = createMcpAuthorizer(options);
  const maxBodyBytes = options.maxBodyBytes ?? 4 * 1024 * 1024;
  const metadataUrl = options.metadata
    ? protectedResourceMetadataUrl(options.metadata.resource)
    : undefined;
  const metadataPath = metadataUrl ? new URL(metadataUrl).pathname : undefined;
  const metadataDocument = options.metadata
    ? JSON.stringify({
        resource: options.metadata.resource,
        authorization_servers: [...options.metadata.authorizationServers],
        ...(options.metadata.scopes?.length
          ? { scopes_supported: [...options.metadata.scopes] }
          : {}),
        bearer_methods_supported: ['header'],
        ...(options.metadata.resourceName ? { resource_name: options.metadata.resourceName } : {}),
        ...(options.metadata.documentation
          ? { resource_documentation: options.metadata.documentation }
          : {}),
      })
    : undefined;

  const challenge = (error?: string) =>
    new Response(
      JSON.stringify({
        error: error ?? 'unauthorized',
        error_description: 'Present a Better IAM credential or an OAuth access token',
      }),
      {
        status: 401,
        headers: {
          'content-type': 'application/json',
          'cache-control': 'no-store',
          'www-authenticate': [
            'Bearer',
            [
              ...(error ? [`error="${error}"`] : []),
              ...(metadataUrl ? [`resource_metadata="${metadataUrl}"`] : []),
            ].join(', '),
          ]
            .filter(Boolean)
            .join(' '),
        },
      },
    );

  /** Removes hidden tools from a `tools/list` result for `id`, in a JSON body or an event stream. */
  async function filterList(
    response: Response,
    id: JsonRpcRequest['id'],
    caller: McpCaller,
  ): Promise<Response> {
    const type = response.headers.get('content-type') ?? '';
    const headers = new Headers(response.headers);
    headers.delete('content-length');
    const rewrite = async (payload: string): Promise<string | undefined> => {
      let message: Record<string, unknown>;
      try {
        message = JSON.parse(payload) as Record<string, unknown>;
      } catch {
        return undefined;
      }
      const result = message.result as { tools?: unknown } | undefined;
      if (message.id !== id || !result || !Array.isArray(result.tools)) return undefined;
      const tools = (result.tools as unknown[]).filter(
        (tool): tool is { name: string } =>
          !!tool &&
          typeof tool === 'object' &&
          typeof (tool as { name?: unknown }).name === 'string',
      );
      return JSON.stringify({
        ...message,
        result: { ...result, tools: await authorizer.visibleTools(caller, tools) },
      });
    };
    if (type.includes('application/json')) {
      const text = await response.text();
      return new Response((await rewrite(text)) ?? text, { status: response.status, headers });
    }
    if (!type.includes('text/event-stream') || !response.body) return response;
    const decoder = new TextDecoder();
    const encoder = new TextEncoder();
    let buffer = '';
    const emit = async (
      event: string,
      controller: TransformStreamDefaultController<Uint8Array>,
    ) => {
      const lines = event.split(/\r?\n/);
      const data = lines
        .filter((line) => line.startsWith('data:'))
        .map((line) => line.slice(5).replace(/^ /, ''));
      const rewritten = data.length ? await rewrite(data.join('\n')) : undefined;
      const out = rewritten
        ? [...lines.filter((line) => !line.startsWith('data:')), `data: ${rewritten}`].join('\n')
        : event;
      controller.enqueue(encoder.encode(`${out}\n\n`));
    };
    const body = response.body.pipeThrough(
      new TransformStream<Uint8Array, Uint8Array>({
        async transform(chunk, controller) {
          buffer += decoder.decode(chunk, { stream: true });
          let boundary: RegExpExecArray | null;
          while ((boundary = /\r?\n\r?\n/.exec(buffer))) {
            const event = buffer.slice(0, boundary.index);
            buffer = buffer.slice(boundary.index + boundary[0].length);
            await emit(event, controller);
          }
        },
        async flush(controller) {
          buffer += decoder.decode();
          if (buffer.trim()) await emit(buffer.replace(/\s+$/, ''), controller);
        },
      }),
    );
    return new Response(body, { status: response.status, headers });
  }

  return async function gate(
    request: Request,
    next: (request: Request, caller: McpCaller) => Promise<Response> | Response,
  ): Promise<Response> {
    const url = new URL(request.url);
    if (metadataDocument && url.pathname === metadataPath) {
      if (request.method === 'OPTIONS')
        return new Response(null, {
          status: 204,
          headers: {
            'access-control-allow-origin': '*',
            'access-control-allow-methods': 'GET, OPTIONS',
          },
        });
      return new Response(metadataDocument, {
        headers: {
          'content-type': 'application/json',
          'access-control-allow-origin': '*',
          'cache-control': 'public, max-age=3600',
        },
      });
    }
    if (!presented(request)) return challenge();
    const caller = await authorizer.authenticate(request);
    if (!caller) return challenge('invalid_token');
    // Streamable HTTP also uses GET (the server's event stream) and DELETE (ending a session): authenticated only.
    if (request.method !== 'POST') return next(request, caller);
    const text = await boundedBody(request, maxBodyBytes);
    if (text === undefined) return json({ error: 'request too large' }, 413);
    let parsed: unknown;
    try {
      parsed = JSON.parse(text);
    } catch {
      return json(
        { jsonrpc: '2.0', id: null, error: { code: -32700, message: 'Parse error' } },
        400,
      );
    }
    // The server receives the request exactly as the gate read it (no duplicate keys a different parser could pick).
    const headers = new Headers(request.headers);
    headers.delete('content-length');
    const forward = new Request(request.url, {
      method: 'POST',
      headers,
      body: JSON.stringify(parsed),
    });
    if (Array.isArray(parsed)) {
      // Batches (dropped from MCP in 2025-06-18) may not carry tool traffic past the gate.
      const tooling = parsed.some((item) => {
        const method = jsonRpc(item)?.method;
        return method === 'tools/call' || method === 'tools/list';
      });
      return tooling
        ? json(
            {
              jsonrpc: '2.0',
              id: null,
              error: { code: -32600, message: 'Batched tool requests are not supported' },
            },
            400,
          )
        : next(forward, caller);
    }
    const message = jsonRpc(parsed);
    if (message?.method === 'tools/call') {
      // A name that is not a string (an array, a number) would be judged as no tool at all (and allowed with
      // `unlisted: 'allow'`) while the server may coerce it to a real tool's name: refuse it.
      if (typeof message.params?.name !== 'string')
        return json(
          {
            jsonrpc: '2.0',
            id: message.id ?? null,
            error: { code: -32602, message: 'The tool name must be a string' },
          },
          400,
        );
      const name = message.params.name;
      const args =
        message.params?.arguments && typeof message.params.arguments === 'object'
          ? (message.params.arguments as Record<string, unknown>)
          : {};
      let decision: McpDecision;
      try {
        decision = await authorizer.canCall(caller, name, args);
      } catch (error) {
        if (error instanceof IamError && (error.status === 401 || error.code === 'UNAUTHENTICATED'))
          return challenge('invalid_token');
        throw error;
      }
      if (!decision.allowed)
        return json({
          jsonrpc: '2.0',
          id: message.id ?? null,
          result: {
            content: [
              {
                type: 'text',
                text:
                  decision.reason === 'UNKNOWN_TOOL'
                    ? `Unknown tool: ${name}`
                    : decision.confirmation
                      ? `The person you act for must confirm this call first. A confirmation request was sent to them (it expires at ${new Date(decision.confirmation.expiresAt).toISOString()}). Call ${name} again once they approve it.`
                      : `Access denied: you may not call ${name}`,
              },
            ],
            isError: true,
            ...(decision.confirmation
              ? {
                  _meta: {
                    'better-iam/confirmationId': decision.confirmation.id,
                    'better-iam/confirmationExpiresAt': decision.confirmation.expiresAt,
                  },
                }
              : {}),
          },
        });
      return next(forward, caller);
    }
    if (message?.method === 'tools/list')
      return filterList(await next(forward, caller), message.id, caller);
    return next(forward, caller);
  };
}
export type McpGate = ReturnType<typeof createMcpGate>;

/** The request body as text, or undefined when it is larger than `maxBytes` (read no further than that). */
async function boundedBody(request: Request, maxBytes: number): Promise<string | undefined> {
  const declared = Number(request.headers.get('content-length') ?? 0);
  if (declared > maxBytes) return undefined;
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return undefined;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(size);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder().decode(bytes);
}
