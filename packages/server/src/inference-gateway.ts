import { randomUUID } from 'node:crypto';
import { IamError, type CredentialInput } from '@better-iam/core';
import { createGuardedFetch } from '@better-iam/auth';
import type { GatewayPermit } from './api/inference.js';
import type {
  InferenceTokenUsage,
  InvocationCheck,
  InvocationRecord,
  PublicModel,
} from './inference.js';

/** What the gateway needs from `iam.inference`. */
export interface GatewayRuntime {
  authorize(
    credential: CredentialInput,
    input: { model: string; tenantId?: string; estimatedTokens?: number; tools?: string[] },
  ): Promise<GatewayPermit | { denied: Exclude<InvocationCheck, { allowed: true }> }>;
  record(
    permit: Pick<GatewayPermit, 'principal' | 'tenantId'>,
    usage: Omit<InvocationRecord, 'tenantId'>,
  ): Promise<unknown>;
  models(credential: CredentialInput): Promise<PublicModel[]>;
  /**
   * Whether an OpenAI Responses API response id was created through the gateway by the same caller (the same person,
   * through the same agent if any) at the permit's provider. Without it the gateway refuses `previous_response_id`.
   */
  ownsResponse?(
    permit: Pick<GatewayPermit, 'principal' | 'tenantId' | 'provider'>,
    responseId: string,
  ): Promise<boolean>;
}

/**
 * The inference gateway: an HTTP handler (`Request` → `Response`) that lets any Better IAM credential (a person's
 * session, a service account or agent key, a delegated agent session) call AI models without ever holding a provider
 * key. It authenticates the caller, checks `inference:invoke` on `model/{name}` and the covering budgets, forwards the
 * request to the provider with the sealed key, streams the answer back unchanged, and meters the tokens the provider
 * reports. Requests pass through in the provider's own wire format: Anthropic Messages (`POST /v1/messages`, and
 * `POST /v1/messages/count_tokens`, checked but not metered) for models on an `anthropic` provider; OpenAI Chat
 * Completions (`POST /v1/chat/completions`), Responses (`POST /v1/responses`) and Embeddings (`POST /v1/embeddings`)
 * for `openai` and `openai-compatible` providers. `GET /v1/models` lists the models the caller may use.
 *
 * Responses API conversations live at the provider under the organization's key, so the gateway keeps them apart:
 * `previous_response_id` must name a response the same caller created through the gateway, and the `conversation`
 * parameter and `background` mode are refused (their state and usage are out of the gateway's sight).
 */
export interface InferenceGatewayOptions {
  /** Path prefix the gateway is mounted under, such as `/ai` (default: none, so routes start at `/v1`). */
  basePath?: string;
  /**
   * Transport for upstream calls; inject one for proxies or tests. By default platform providers use
   * `globalThis.fetch` and base URLs an organization chose use the SSRF guard (`inference.allowPrivateNetworks`); an
   * injected transport replaces both and must enforce its own address rules.
   */
  fetch?: typeof fetch;
  /** Deadline for the upstream response headers, in milliseconds (default 10 minutes). */
  timeoutMs?: number;
  /** `anthropic-version` sent upstream when the client sends none (default `2023-06-01`). */
  anthropicVersion?: string;
  /** Largest accepted request body in bytes (default 20 MiB). */
  maxBodyBytes?: number;
  /** Called when metering after a response fails (the response itself is unaffected). */
  onError?: (error: unknown) => void;
}

type Format = 'anthropic' | 'openai';

/** How a provider reports token usage: Anthropic Messages, OpenAI Chat Completions / Embeddings, OpenAI Responses. */
export type UsageFormat = Format | 'responses';

/** One passthrough route. */
interface Endpoint {
  path: string;
  /** Error shape, and which providers serve it: `anthropic` providers, or `openai` / `openai-compatible` ones. */
  format: Format;
  /** Where usage is reported; undefined for calls that are checked but cost nothing (not metered). */
  usage?: UsageFormat;
  /** Request fields that limit output tokens (capped at the model's `maxOutputTokens`). */
  outputFields: string[];
  /** The field set to the model's cap when the request has none (by provider kind); undefined to leave it unset. */
  defaultOutputField?: (kind: string) => string;
}

const endpoints: Record<string, Endpoint> = {
  '/v1/messages': {
    path: '/v1/messages',
    format: 'anthropic',
    usage: 'anthropic',
    outputFields: ['max_tokens'],
    defaultOutputField: () => 'max_tokens',
  },
  '/v1/messages/count_tokens': {
    path: '/v1/messages/count_tokens',
    format: 'anthropic',
    outputFields: [],
  },
  '/v1/chat/completions': {
    path: '/v1/chat/completions',
    format: 'openai',
    usage: 'openai',
    outputFields: ['max_tokens', 'max_completion_tokens'],
    // OpenAI's own API prefers max_completion_tokens; compatible servers commonly know only max_tokens.
    defaultOutputField: (kind) => (kind === 'openai' ? 'max_completion_tokens' : 'max_tokens'),
  },
  '/v1/responses': {
    path: '/v1/responses',
    format: 'openai',
    usage: 'responses',
    outputFields: ['max_output_tokens'],
    defaultOutputField: () => 'max_output_tokens',
  },
  '/v1/embeddings': { path: '/v1/embeddings', format: 'openai', usage: 'openai', outputFields: [] },
};

/** Provider-side ids of Responses API objects: letters, digits, `_` and `-`. */
const responseIdPattern = /^[A-Za-z0-9_-]{1,200}$/;

/** How many tools and MCP servers a request may list: all of them are read, so more are refused. */
const toolLimits = { tools: 256, mcpServers: 64 };

/**
 * The host of a remote MCP server URL (lowercase, without a trailing dot), or `invalid` for anything but a plain
 * http(s) URL in canonical form: user info, backslashes, encoded hosts or default ports would let the host checked here
 * differ from the one a provider connects to.
 */
function mcpHost(value: unknown): string {
  if (typeof value !== 'string') return 'invalid';
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    return 'invalid';
  }
  const canonical = url.href.toLowerCase();
  const given = value.toLowerCase();
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:') ||
    url.username ||
    url.password ||
    !url.hostname ||
    (canonical !== given && canonical !== `${given}/`)
  )
    return 'invalid';
  return url.hostname
    .toLowerCase()
    .replace(/\.$/, '')
    .replace(/[^a-z0-9.:-]/g, '_')
    .slice(0, 200);
}

/**
 * The first reference in a request to an object stored at the provider under the organization's key, which the gateway
 * cannot tie to the caller: `item_reference` inputs, `file_id`s and `file_ids` wherever they appear (message parts,
 * function outputs, image masks, code-interpreter containers), `vector_store_ids` (file search), `file` sources
 * (Anthropic, including inside tool results), and existing code-execution containers. The whole request is searched
 * (the path is kept for callers), so a reference cannot hide in a shape the gateway does not know; one too large or deep
 * to search counts as a reference. Undefined when there is none.
 */
export function storedReference(_path: string, body: Record<string, unknown>): string | undefined {
  const plainObject = (value: unknown): value is Record<string, unknown> =>
    !!value && typeof value === 'object' && !Array.isArray(value);
  let budget = 50_000;
  const search = (value: unknown, depth: number): string | undefined => {
    if (--budget < 0 || depth > 64) return 'too-complex';
    if (Array.isArray(value)) {
      for (const item of value) {
        const found = search(item, depth + 1);
        if (found) return found;
      }
      return undefined;
    }
    if (!plainObject(value)) return undefined;
    if (value.type === 'item_reference') return 'item_reference';
    if (typeof value.file_id === 'string') return 'file_id';
    if (Array.isArray(value.file_ids) && value.file_ids.length) return 'file_id';
    if (Array.isArray(value.vector_store_ids) && value.vector_store_ids.length)
      return 'vector_store';
    if (plainObject(value.source) && value.source.type === 'file') return 'file_id';
    const container = value.container;
    if (
      typeof container === 'string' ||
      (plainObject(container) && typeof container.id === 'string')
    )
      return 'container';
    for (const [key, item] of Object.entries(value)) {
      // Free text and numbers never hold a reference; only structure is searched.
      if (key === 'text' && typeof item === 'string') continue;
      const found = search(item, depth + 1);
      if (found) return found;
    }
    return undefined;
  };
  return search(body, 0);
}

/** A tool kind as a policy names it: lowercase, without a version date (`web_search_20250305`) or `_preview`. */
function toolKind(type: string): string {
  const kind = type
    .toLowerCase()
    .replace(/_\d{8}$/, '')
    .replace(/_preview(_\d{4}_\d{2}_\d{2})?$/, '')
    .replace(/[^a-z0-9_.-]/g, '_')
    .slice(0, 64);
  return kind || 'unknown';
}

/**
 * The tools a request asks the provider to run (or that the provider defines for the model to drive): Anthropic
 * server and Anthropic-defined tools (`tools[].type` other than `custom`) and remote MCP servers (`mcp_servers`); OpenAI
 * Responses built-in tools (`tools[].type` other than `function` and `custom`, MCP servers as `mcp:{host}` or
 * `mcp:{connector_id}`), and a stored prompt (`prompt`, which may bring tools of its own); Chat Completions web search
 * (`web_search_options`). Functions the caller runs itself are not listed. At most 65 entries are returned (more are
 * refused), from the first 256 tools and 64 MCP servers (the gateway refuses requests with more).
 */
export function providerToolsOf(path: string, body: Record<string, unknown>): string[] {
  const tools = new Set<string>();
  const list = Array.isArray(body.tools) ? (body.tools as unknown[]) : [];
  for (const item of list.slice(0, toolLimits.tools)) {
    if (!item || typeof item !== 'object') continue;
    const tool = item as Record<string, unknown>;
    const type = typeof tool.type === 'string' ? tool.type : undefined;
    if (!type || type === 'function' || type === 'custom') continue;
    if (type === 'mcp')
      tools.add(
        typeof tool.connector_id === 'string' && tool.server_url === undefined
          ? `mcp:${toolKind(tool.connector_id)}`
          : `mcp:${mcpHost(tool.server_url)}`,
      );
    else tools.add(toolKind(type));
  }
  if (path === '/v1/messages' && Array.isArray(body.mcp_servers))
    for (const server of (body.mcp_servers as unknown[]).slice(0, toolLimits.mcpServers))
      tools.add(
        `mcp:${mcpHost(server && typeof server === 'object' ? (server as Record<string, unknown>).url : undefined)}`,
      );
  if (path === '/v1/responses' && body.prompt !== undefined && body.prompt !== null)
    tools.add('prompt');
  if (
    path === '/v1/chat/completions' &&
    body.web_search_options !== undefined &&
    body.web_search_options !== null
  )
    tools.add('web_search');
  return [...tools].slice(0, 65);
}

const errorTypes: Record<Format, Record<number, string>> = {
  anthropic: {
    400: 'invalid_request_error',
    401: 'authentication_error',
    403: 'permission_error',
    404: 'not_found_error',
    413: 'request_too_large',
    429: 'rate_limit_error',
    500: 'api_error',
    502: 'api_error',
  },
  openai: {
    400: 'invalid_request_error',
    401: 'invalid_request_error',
    403: 'insufficient_quota',
    404: 'invalid_request_error',
    413: 'invalid_request_error',
    429: 'rate_limit_exceeded',
    500: 'server_error',
    502: 'server_error',
  },
};

function errorResponse(
  format: Format,
  status: number,
  code: string,
  message: string,
  headers: Record<string, string> = {},
): Response {
  const type =
    errorTypes[format][status] ?? (format === 'anthropic' ? 'api_error' : 'server_error');
  const body =
    format === 'anthropic'
      ? { type: 'error', error: { type, message, code } }
      : { error: { message, type, code } };
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'content-type': 'application/json', ...headers },
  });
}

/** The presented credential: `Authorization: Bearer …`, else `x-api-key` (the Anthropic SDK's header). */
function credentialOf(request: Request): string | undefined {
  const bearer = /^Bearer\s+(\S+)$/i.exec(request.headers.get('authorization') ?? '')?.[1];
  return bearer ?? request.headers.get('x-api-key') ?? undefined;
}

/**
 * Token counts from a provider's usage object (Anthropic, OpenAI Chat Completions / Embeddings, or OpenAI Responses);
 * undefined when there is none. Cached input tokens are counted apart from other input.
 */
export function usageFrom(format: UsageFormat, usage: unknown): InferenceTokenUsage | undefined {
  if (!usage || typeof usage !== 'object') return undefined;
  const value = usage as Record<string, unknown>;
  const count = (item: unknown) =>
    typeof item === 'number' && Number.isSafeInteger(item) && item >= 0 ? item : 0;
  if (format === 'responses') {
    const details = value.input_tokens_details as Record<string, unknown> | undefined;
    const cached = count(details?.cached_tokens);
    const result: InferenceTokenUsage = {
      inputTokens: Math.max(0, count(value.input_tokens) - cached),
      outputTokens: count(value.output_tokens),
    };
    if (cached) result.cacheReadTokens = cached;
    return result;
  }
  if (format === 'anthropic') {
    const result: InferenceTokenUsage = {
      inputTokens: count(value.input_tokens),
      outputTokens: count(value.output_tokens),
    };
    if (count(value.cache_read_input_tokens))
      result.cacheReadTokens = count(value.cache_read_input_tokens);
    if (count(value.cache_creation_input_tokens))
      result.cacheWriteTokens = count(value.cache_creation_input_tokens);
    return result;
  }
  const details = value.prompt_tokens_details as Record<string, unknown> | undefined;
  const cached = count(details?.cached_tokens);
  const result: InferenceTokenUsage = {
    inputTokens: Math.max(0, count(value.prompt_tokens) - cached),
    outputTokens: count(value.completion_tokens),
  };
  if (cached) result.cacheReadTokens = cached;
  return result;
}

/**
 * Follows a server-sent event stream and keeps the latest token counts: Anthropic reports input (and cache) tokens
 * in `message_start` and cumulative output tokens in `message_delta`; OpenAI Chat Completions reports everything in
 * the final chunk when `stream_options.include_usage` is set (the gateway sets it); the Responses API reports it on
 * `response.completed` (or `response.incomplete` / `response.failed`) and names the response from `response.created`.
 * The final counts arrive last, so it also counts the characters of generated deltas: a stream the client closes early
 * is metered from them (`metered`), never as free.
 */
class StreamUsage {
  private buffer = '';
  private readonly decoder = new TextDecoder();
  usage: InferenceTokenUsage | undefined;
  responseId: string | undefined;
  /** Whether the provider's final counts arrived. */
  complete = false;
  /** Characters of generated text, tool arguments and reasoning seen in deltas. */
  private outputChars = 0;
  constructor(private readonly format: UsageFormat) {}
  /**
   * The usage to meter: the provider's counts once complete. Otherwise the input the provider reported so far (or
   * `inputEstimate` when it reported none) and at least a token per four generated characters, so closing a stream
   * before its final event does not avoid metering.
   */
  metered(inputEstimate: number): InferenceTokenUsage {
    if (this.complete && this.usage) return this.usage;
    const seen = this.usage;
    return {
      ...seen,
      inputTokens: seen ? seen.inputTokens : inputEstimate,
      outputTokens: Math.max(seen?.outputTokens ?? 0, Math.ceil(this.outputChars / 4)),
    };
  }
  private count(value: unknown): void {
    if (typeof value === 'string') this.outputChars += value.length;
  }
  push(chunk: Uint8Array): void {
    this.buffer += this.decoder.decode(chunk, { stream: true });
    let newline: number;
    while ((newline = this.buffer.indexOf('\n')) >= 0) {
      const line = this.buffer.slice(0, newline).replace(/\r$/, '');
      this.buffer = this.buffer.slice(newline + 1);
      if (line.startsWith('data:')) this.data(line.slice(5).trim());
    }
    // A line longer than 1 MiB is not an event we need; drop it rather than buffer without bound.
    if (this.buffer.length > 1 << 20) this.buffer = '';
  }
  private data(payload: string): void {
    if (!payload || payload === '[DONE]') return;
    let event: Record<string, unknown>;
    try {
      event = JSON.parse(payload) as Record<string, unknown>;
    } catch {
      return;
    }
    if (this.format === 'openai') {
      for (const choice of Array.isArray(event.choices) ? event.choices : []) {
        const delta = (choice as { delta?: Record<string, unknown> } | null)?.delta;
        if (!delta) continue;
        this.count(delta.content);
        this.count(delta.reasoning_content);
        for (const call of Array.isArray(delta.tool_calls) ? delta.tool_calls : [])
          this.count((call as { function?: { arguments?: unknown } } | null)?.function?.arguments);
      }
      const usage = usageFrom('openai', event.usage);
      if (usage) {
        this.usage = usage;
        this.complete = true;
      }
      return;
    }
    if (this.format === 'responses') {
      if (typeof event.type === 'string' && event.type.endsWith('.delta')) this.count(event.delta);
      const response = event.response as Record<string, unknown> | undefined;
      if (!response || typeof event.type !== 'string' || !event.type.startsWith('response.'))
        return;
      if (typeof response.id === 'string') this.responseId ??= response.id;
      const usage = usageFrom('responses', response.usage);
      if (usage) this.usage = usage;
      if (
        usage &&
        ['response.completed', 'response.incomplete', 'response.failed'].includes(event.type)
      )
        this.complete = true;
      return;
    }
    if (event.type === 'content_block_delta') {
      const delta = event.delta as Record<string, unknown> | undefined;
      this.count(delta?.text);
      this.count(delta?.partial_json);
      this.count(delta?.thinking);
    } else if (event.type === 'message_start') {
      const message = event.message as Record<string, unknown> | undefined;
      const usage = usageFrom('anthropic', message?.usage);
      if (usage) this.usage = usage;
    } else if (event.type === 'message_delta') {
      // Output tokens are cumulative; newer responses repeat the input and cache counts here too.
      const delta = event.usage as Record<string, unknown> | undefined;
      const next = usageFrom('anthropic', delta);
      if (!delta || !next) return;
      this.usage = {
        ...(this.usage ?? { inputTokens: 0, outputTokens: 0 }),
        outputTokens: next.outputTokens,
        ...(typeof delta.input_tokens === 'number' ? { inputTokens: next.inputTokens } : {}),
        ...(next.cacheReadTokens ? { cacheReadTokens: next.cacheReadTokens } : {}),
        ...(next.cacheWriteTokens ? { cacheWriteTokens: next.cacheWriteTokens } : {}),
      };
      // message_delta carries the final output count; message_stop follows.
      this.complete = true;
    }
  }
}

function upstreamUrl(baseUrl: string, path: string): string {
  // Base URLs are stored without the API version; accept one that already ends in /v1.
  return baseUrl.endsWith('/v1') ? `${baseUrl}${path.slice(3)}` : `${baseUrl}${path}`;
}

/** Upstream answers after which the gateway tries a model's fallbacks: rate limits, overload and server errors. */
const retryableStatuses = new Set([429, 500, 502, 503, 504, 529]);

/** The request body as text, or undefined when it is larger than `maxBytes` (read no further than that). */
async function boundedBody(request: Request, maxBytes: number): Promise<string | undefined> {
  if (Number(request.headers.get('content-length') ?? 0) > maxBytes) return undefined;
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
  return new TextDecoder().decode(Buffer.concat(chunks));
}

/** Builds the gateway handler over the inference runtime (see `InferenceGatewayOptions`). */
export function createInferenceGateway(
  runtime: GatewayRuntime,
  options: InferenceGatewayOptions = {},
): (request: Request) => Promise<Response> {
  const base = (options.basePath ?? '').replace(/\/+$/, '');
  const transport = options.fetch ?? globalThis.fetch;
  const timeoutMs = options.timeoutMs ?? 600_000;
  const maxBodyBytes = options.maxBodyBytes ?? 20 * 1024 * 1024;
  const onError = options.onError ?? (() => {});

  const denial = (
    format: Format,
    denied: Exclude<InvocationCheck, { allowed: true }>,
  ): Response => {
    if (denied.reason === 'BUDGET_EXCEEDED') {
      const resetsAt = denied.budget?.resetsAt;
      const retry = resetsAt ? Math.max(1, Math.ceil((resetsAt - Date.now()) / 1000)) : undefined;
      return errorResponse(
        format,
        429,
        'BUDGET_EXCEEDED',
        `Budget "${denied.budget?.name ?? 'inference'}" is exhausted until ${resetsAt ? new Date(resetsAt).toISOString() : 'its next window'}`,
        retry ? { 'retry-after': String(retry) } : {},
      );
    }
    if (denied.reason === 'MODEL_DISABLED')
      return errorResponse(format, 403, 'MODEL_DISABLED', 'This model is disabled');
    if (denied.reason === 'TOOL_NOT_ALLOWED')
      return errorResponse(
        format,
        403,
        'TOOL_NOT_ALLOWED',
        `You may not use the provider tool ${denied.tool ?? ''} with this model`.trim(),
      );
    return errorResponse(format, 403, 'ACCESS_DENIED', 'You may not use this model');
  };

  const failure = (format: Format, error: unknown): Response => {
    if (error instanceof IamError) {
      const status =
        error.status === 401 || error.status === 403 || error.status === 404 ? error.status : 400;
      return errorResponse(format, status, error.code, error.message);
    }
    onError(error);
    return errorResponse(format, 500, 'INTERNAL', 'The gateway failed to handle the request');
  };

  async function listModels(request: Request, credential: CredentialInput): Promise<Response> {
    const anthropic = request.headers.has('anthropic-version');
    const format: Format = anthropic ? 'anthropic' : 'openai';
    try {
      const models = await runtime.models(credential);
      const created = Math.floor(Date.now() / 1000);
      const body = anthropic
        ? {
            data: models.map((model) => ({
              type: 'model',
              id: model.name,
              display_name: model.displayName ?? model.name,
              created_at: new Date(created * 1000).toISOString(),
            })),
            has_more: false,
            first_id: models[0]?.name ?? null,
            last_id: models.at(-1)?.name ?? null,
          }
        : {
            object: 'list',
            data: models.map((model) => ({
              id: model.name,
              object: 'model',
              created,
              owned_by: model.provider.name,
            })),
          };
      return new Response(JSON.stringify(body), {
        headers: { 'content-type': 'application/json' },
      });
    } catch (error) {
      return failure(format, error);
    }
  }

  async function invoke(
    request: Request,
    endpoint: Endpoint,
    credential: CredentialInput,
  ): Promise<Response> {
    const format = endpoint.format;
    const requestId = randomUUID();
    const raw = await boundedBody(request, maxBodyBytes);
    if (raw === undefined)
      return errorResponse(format, 413, 'TOO_LARGE', 'The request body is too large');
    let body: Record<string, unknown>;
    try {
      const parsed: unknown = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed))
        throw new Error('not an object');
      body = parsed as Record<string, unknown>;
    } catch {
      return errorResponse(format, 400, 'INVALID_INPUT', 'The request body must be a JSON object');
    }
    if (typeof body.model !== 'string')
      return errorResponse(format, 400, 'INVALID_INPUT', 'model is required');
    let previousResponseId: string | undefined;
    if (endpoint.usage === 'responses') {
      // Conversation objects and background responses keep state and usage at the provider, out of the gateway's
      // sight; a previous response must be the caller's own (checked once the caller is known).
      if (body.conversation !== undefined && body.conversation !== null)
        return errorResponse(
          format,
          400,
          'UNSUPPORTED_PARAMETER',
          'The gateway does not support conversation; continue with previous_response_id',
        );
      if (body.background === true)
        return errorResponse(
          format,
          400,
          'UNSUPPORTED_PARAMETER',
          'The gateway does not support background responses',
        );
      if (body.previous_response_id !== undefined && body.previous_response_id !== null) {
        if (
          typeof body.previous_response_id !== 'string' ||
          !responseIdPattern.test(body.previous_response_id)
        )
          return errorResponse(format, 400, 'INVALID_INPUT', 'previous_response_id is invalid');
        previousResponseId = body.previous_response_id;
      }
    }
    const maxOutput = endpoint.outputFields
      .map((field) => body[field])
      .find(
        (value): value is number =>
          typeof value === 'number' && Number.isSafeInteger(value) && value > 0,
      );
    // A rough upper bound: four bytes per input token plus the requested output.
    const inputEstimate = Math.ceil(raw.length / 4);
    const estimatedTokens = inputEstimate + (maxOutput ?? 0);
    // Every tool is read, so a request listing more than the gateway reads is refused rather than half checked.
    if (
      (Array.isArray(body.tools) && body.tools.length > toolLimits.tools) ||
      (Array.isArray(body.mcp_servers) && body.mcp_servers.length > toolLimits.mcpServers)
    )
      return errorResponse(
        format,
        400,
        'INVALID_INPUT',
        `A request may list at most ${toolLimits.tools} tools and ${toolLimits.mcpServers} MCP servers`,
      );
    // Objects stored at the provider under the organization's key cannot be tied to the caller.
    const reference = endpoint.usage ? storedReference(endpoint.path, body) : undefined;
    if (reference)
      return errorResponse(
        format,
        400,
        'UNSUPPORTED_PARAMETER',
        `The gateway does not pass on references to stored provider objects (${reference})`,
      );
    // Tools the provider would run, checked by each model's `providerTools` (token counting runs none).
    const tools = endpoint.usage ? providerToolsOf(endpoint.path, body) : [];
    const checked = { estimatedTokens, ...(tools.length ? { tools } : {}) };
    let permit: GatewayPermit;
    try {
      const outcome = await runtime.authorize(credential, { model: body.model, ...checked });
      if ('denied' in outcome) return denial(format, outcome.denied);
      permit = outcome;
    } catch (error) {
      return failure(format, error);
    }
    const kind = permit.provider.kind;
    if ((format === 'anthropic') !== (kind === 'anthropic'))
      return errorResponse(
        format,
        400,
        'WRONG_FORMAT',
        `Model ${permit.check.model.name} is served by an ${kind} provider; use ${kind === 'anthropic' ? 'POST /v1/messages' : 'POST /v1/chat/completions, /v1/responses or /v1/embeddings'}`,
      );
    if (previousResponseId !== undefined) {
      let owned = false;
      try {
        owned = (await runtime.ownsResponse?.(permit, previousResponseId)) ?? false;
      } catch (error) {
        return failure(format, error);
      }
      if (!owned)
        return errorResponse(
          format,
          404,
          'RESPONSE_NOT_FOUND',
          'previous_response_id names no response of yours',
        );
    }
    const stream = body.stream === true;
    const path = endpoint.path;

    /** Sends the request to a permit's provider: the answer, or the error when the provider could not be reached. */
    const send = async (current: GatewayPermit) => {
      const kind = current.provider.kind;
      const upstreamBody: Record<string, unknown> = { ...body, model: current.upstreamModel };
      // The model's `maxOutputTokens` caps every call: larger limits are lowered, and a call without one gets it.
      const cap = current.check.model.maxOutputTokens;
      if (cap !== undefined && endpoint.outputFields.length) {
        let limited = false;
        for (const field of endpoint.outputFields) {
          const value = upstreamBody[field];
          if (typeof value !== 'number') continue;
          limited = true;
          if (value > cap) upstreamBody[field] = cap;
        }
        const field = endpoint.defaultOutputField?.(kind);
        if (!limited && field) upstreamBody[field] = cap;
      }
      const headers = new Headers({
        'content-type': 'application/json',
        accept: stream ? 'text/event-stream' : 'application/json',
      });
      if (format === 'anthropic') {
        headers.set('x-api-key', current.provider.apiKey);
        headers.set(
          'anthropic-version',
          request.headers.get('anthropic-version') ?? options.anthropicVersion ?? '2023-06-01',
        );
        const beta = request.headers.get('anthropic-beta');
        if (beta) headers.set('anthropic-beta', beta);
      } else {
        headers.set('authorization', `Bearer ${current.provider.apiKey}`);
        if (stream && endpoint.usage === 'openai')
          upstreamBody.stream_options = {
            ...(typeof body.stream_options === 'object' && body.stream_options
              ? body.stream_options
              : {}),
            include_usage: true,
          };
      }
      const started = Date.now();
      const abort = new AbortController();
      const timer = setTimeout(() => abort.abort(), timeoutMs);
      try {
        // A base URL an organization chose goes through the SSRF guard: the answer is streamed back to the caller.
        const send =
          options.fetch ??
          (current.provider.guard ? createGuardedFetch(current.provider.guard) : transport);
        const upstream = await send(upstreamUrl(current.provider.baseUrl, path), {
          method: 'POST',
          headers,
          body: JSON.stringify(upstreamBody),
          signal: abort.signal,
          redirect: 'error',
        });
        return { current, started, upstream };
      } catch (error) {
        return { current, started, error };
      } finally {
        clearTimeout(timer);
      }
    };
    const meterFor =
      (current: GatewayPermit, started: number) =>
      async (
        usage: InferenceTokenUsage | undefined,
        status: 'ok' | 'error',
        responseId?: string,
      ): Promise<void> => {
        // Calls that cost nothing (token counting) are checked but not metered.
        if (!endpoint.usage) return;
        await runtime
          .record(current, {
            model: current.check.model.name,
            inputTokens: usage?.inputTokens ?? 0,
            outputTokens: usage?.outputTokens ?? 0,
            ...(usage?.cacheReadTokens ? { cacheReadTokens: usage.cacheReadTokens } : {}),
            ...(usage?.cacheWriteTokens ? { cacheWriteTokens: usage.cacheWriteTokens } : {}),
            status,
            requestId,
            latencyMs: Date.now() - started,
            ...(responseId && responseIdPattern.test(responseId) ? { responseId } : {}),
          })
          .catch(onError);
      };

    // A model's fallbacks, in order, when its provider is unreachable, rate limited or failing: each only if the caller
    // may use it (access, budgets) and it speaks the same wire format.
    let sent = await send(permit);
    const fallbacks = [...(permit.check.model.fallbacks ?? [])];
    const tried = new Set([permit.check.model.name]);
    while ((!sent.upstream || retryableStatuses.has(sent.upstream.status)) && fallbacks.length) {
      let next: GatewayPermit | undefined;
      while (!next && fallbacks.length) {
        const name = fallbacks.shift()!;
        if (tried.has(name)) continue;
        tried.add(name);
        try {
          const outcome = await runtime.authorize(credential, { model: name, ...checked });
          if ('denied' in outcome) continue;
          if ((format === 'anthropic') !== (outcome.provider.kind === 'anthropic')) continue;
          // A continued response exists only at the provider whose ownership was checked.
          if (previousResponseId !== undefined && outcome.provider.id !== permit.provider.id)
            continue;
          next = outcome;
        } catch {
          continue;
        }
      }
      if (!next) break;
      // The failed attempt is metered (no tokens) against the model that failed, then the next one is tried.
      await meterFor(sent.current, sent.started)(undefined, 'error');
      await sent.upstream?.body?.cancel().catch(() => {});
      sent = await send(next);
    }
    const chosen = sent.current;
    const meter = meterFor(chosen, sent.started);
    if (!sent.upstream) {
      await meter(undefined, 'error');
      onError(sent.error);
      return errorResponse(
        format,
        502,
        'UPSTREAM_UNAVAILABLE',
        'The model provider could not be reached',
      );
    }
    const upstream = sent.upstream;
    const responseHeaders = new Headers({
      'content-type': upstream.headers.get('content-type') ?? 'application/json',
      'x-better-iam-request-id': requestId,
      'x-better-iam-model': chosen.check.model.name,
    });
    if (chosen !== permit)
      responseHeaders.set('x-better-iam-fallback-from', permit.check.model.name);
    const upstreamRequestId =
      upstream.headers.get('request-id') ?? upstream.headers.get('x-request-id');
    if (upstreamRequestId) responseHeaders.set('x-upstream-request-id', upstreamRequestId);
    const status = upstream.ok ? 'ok' : 'error';
    const eventStream = (upstream.headers.get('content-type') ?? '').includes('text/event-stream');
    if (!eventStream || !upstream.body) {
      const text = await upstream.text();
      let usage: InferenceTokenUsage | undefined;
      let responseId: string | undefined;
      let payload = text;
      try {
        const parsed = JSON.parse(text) as Record<string, unknown>;
        if (endpoint.usage) usage = usageFrom(endpoint.usage, parsed.usage);
        if (endpoint.usage === 'responses' && typeof parsed.id === 'string') responseId = parsed.id;
        if (typeof parsed.model === 'string') {
          parsed.model = chosen.check.model.name;
          payload = JSON.stringify(parsed);
        }
      } catch {
        /* Not JSON: passed through as is. */
      }
      await meter(usage, status, responseId);
      return new Response(payload, { status: upstream.status, headers: responseHeaders });
    }
    responseHeaders.set('cache-control', 'no-cache');
    const tracker = new StreamUsage(endpoint.usage ?? format);
    let metered = false;
    const finish = () => {
      if (metered) return;
      metered = true;
      // Without the provider's final counts (the client closed early, or the provider sent none), estimated.
      void meter(tracker.metered(inputEstimate), status, tracker.responseId);
    };
    const reader = upstream.body.getReader();
    const forwarded = new ReadableStream<Uint8Array>({
      async pull(controller) {
        try {
          const { done, value } = await reader.read();
          if (done) {
            finish();
            controller.close();
            return;
          }
          tracker.push(value);
          controller.enqueue(value);
        } catch (error) {
          finish();
          controller.error(error);
        }
      },
      async cancel(reason) {
        finish();
        await reader.cancel(reason).catch(() => {});
      },
    });
    return new Response(forwarded, { status: upstream.status, headers: responseHeaders });
  }

  return async (request) => {
    const url = new URL(request.url);
    if (base && !url.pathname.startsWith(`${base}/`))
      return errorResponse('openai', 404, 'NOT_FOUND', 'Not found');
    const path = url.pathname.slice(base.length);
    const endpoint = Object.hasOwn(endpoints, path) ? endpoints[path] : undefined;
    const format: Format =
      endpoint?.format ?? (request.headers.has('anthropic-version') ? 'anthropic' : 'openai');
    const token = credentialOf(request);
    if (!token)
      return errorResponse(
        format,
        401,
        'UNAUTHENTICATED',
        'Send a Better IAM credential as a bearer token or x-api-key',
      );
    const credential: CredentialInput = { token, headers: request.headers };
    if (request.method === 'GET' && path === '/v1/models') return listModels(request, credential);
    if (request.method === 'POST' && endpoint) return invoke(request, endpoint, credential);
    return errorResponse(format, 404, 'NOT_FOUND', 'Not found');
  };
}
