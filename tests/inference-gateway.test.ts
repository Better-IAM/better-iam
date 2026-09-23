import { afterEach, describe, expect, it } from 'vitest';
import { providerToolsOf } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

interface Upstream {
  url: string;
  headers: Headers;
  body: Record<string, unknown>;
}

const sse = (events: [string | undefined, unknown][]) =>
  events
    .map(
      ([event, data]) =>
        `${event ? `event: ${event}\n` : ''}data: ${typeof data === 'string' ? data : JSON.stringify(data)}\n\n`,
    )
    .join('');

/** A fake provider: records each request and answers from the model and `stream` flag. */
function fakeUpstream() {
  const calls: Upstream[] = [];
  const fetch = async (url: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
    calls.push({ url: String(url), headers: new Headers(init?.headers), body });
    if (String(url).endsWith('/v1/messages/count_tokens'))
      return Response.json({ input_tokens: 42 });
    if (String(url).endsWith('/embeddings'))
      return Response.json({
        object: 'list',
        model: body.model,
        data: [{ object: 'embedding', index: 0, embedding: [0.1, 0.2] }],
        usage: { prompt_tokens: 9, total_tokens: 9 },
      });
    if (String(url).endsWith('/responses')) {
      const response = (usage: unknown) => ({
        id: `resp_${calls.length}`,
        object: 'response',
        model: body.model,
        usage,
      });
      const used = {
        input_tokens: 30,
        input_tokens_details: { cached_tokens: 10 },
        output_tokens: 12,
        output_tokens_details: { reasoning_tokens: 4 },
        total_tokens: 42,
      };
      if (!body.stream) return Response.json(response(used));
      return new Response(
        sse([
          ['response.created', { type: 'response.created', response: response(null) }],
          ['response.output_text.delta', { type: 'response.output_text.delta', delta: 'Hi' }],
          ['response.completed', { type: 'response.completed', response: response(used) }],
        ]),
        { headers: { 'content-type': 'text/event-stream' } },
      );
    }
    const anthropic = String(url).endsWith('/v1/messages');
    if (!body.stream)
      return new Response(
        JSON.stringify(
          anthropic
            ? {
                id: 'msg_1',
                type: 'message',
                model: body.model,
                content: [{ type: 'text', text: 'Hello' }],
                usage: { input_tokens: 10, output_tokens: 20, cache_read_input_tokens: 5 },
              }
            : {
                id: 'chatcmpl_1',
                object: 'chat.completion',
                model: body.model,
                choices: [{ index: 0, message: { role: 'assistant', content: 'Hi' } }],
                usage: {
                  prompt_tokens: 12,
                  completion_tokens: 8,
                  prompt_tokens_details: { cached_tokens: 2 },
                },
              },
        ),
        { headers: { 'content-type': 'application/json', 'request-id': 'req_upstream' } },
      );
    const text = anthropic
      ? sse([
          [
            'message_start',
            { type: 'message_start', message: { usage: { input_tokens: 10, output_tokens: 1 } } },
          ],
          [
            'content_block_delta',
            { type: 'content_block_delta', delta: { type: 'text_delta', text: 'Hel' } },
          ],
          ['message_delta', { type: 'message_delta', usage: { output_tokens: 25 } }],
          ['message_stop', { type: 'message_stop' }],
        ])
      : sse([
          [undefined, { choices: [{ delta: { content: 'Hi' } }], usage: null }],
          [undefined, { choices: [], usage: { prompt_tokens: 7, completion_tokens: 3 } }],
          [undefined, '[DONE]'],
        ]);
    // Deliver the stream in small pieces, splitting events across chunks.
    const bytes = new TextEncoder().encode(text);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) {
        for (let index = 0; index < bytes.length; index += 17)
          controller.enqueue(bytes.slice(index, index + 17));
        controller.close();
      },
    });
    return new Response(stream, { headers: { 'content-type': 'text/event-stream' } });
  };
  return { calls, fetch: fetch as typeof globalThis.fetch };
}

async function setup() {
  const f = await organizationFixture({ inference: { allowCustomBaseUrls: true } });
  const anthropic = await f.iam.api.inference.createProvider(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Anthropic',
    kind: 'anthropic',
    apiKey: 'sk-ant-provider-key-9999',
  });
  const openai = await f.iam.api.inference.createProvider(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Router',
    kind: 'openai-compatible',
    apiKey: 'sk-router-key-8888',
    baseUrl: 'https://router.example/api/v1',
  });
  await f.iam.api.inference.createModel(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'sonnet',
    providerId: anthropic.id,
    upstreamModel: 'claude-sonnet-5',
    inputPricePerMTok: 3,
    outputPricePerMTok: 15,
    cachedInputPricePerMTok: 0.3,
  });
  await f.iam.api.inference.createModel(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'open-model',
    providerId: openai.id,
    upstreamModel: 'vendor/open-model-70b',
    inputPricePerMTok: 1,
    outputPricePerMTok: 1,
  });
  const upstream = fakeUpstream();
  const gateway = f.iam.inference.gateway({ basePath: '/ai', fetch: upstream.fetch });
  const call = (
    path: string,
    token: string | undefined,
    body?: unknown,
    headers: Record<string, string> = {},
  ) =>
    gateway(
      new Request(`http://gateway.test/ai${path}`, {
        method: body === undefined ? 'GET' : 'POST',
        headers: {
          ...(token ? { authorization: `Bearer ${token}` } : {}),
          'content-type': 'application/json',
          ...headers,
        },
        ...(body !== undefined ? { body: JSON.stringify(body) } : {}),
      }),
    );
  return { f, upstream, gateway, call };
}

const usage = async (f: Awaited<ReturnType<typeof setup>>['f']) =>
  (await f.iam.api.inference.usage(f.ownerCredential, { tenantId: f.tenantId, groupBy: 'model' }))
    .rows;

describe('inference gateway', () => {
  it('passes Anthropic Messages through with the sealed key and meters the usage', async () => {
    const { f, upstream, call } = await setup();
    const response = await call('/v1/messages', f.ownerCredential.token, {
      model: 'sonnet',
      max_tokens: 256,
      messages: [{ role: 'user', content: 'Hello' }],
    });
    expect(response.status).toBe(200);
    expect(response.headers.get('x-better-iam-model')).toBe('sonnet');
    expect(response.headers.get('x-upstream-request-id')).toBe('req_upstream');
    expect(await response.json()).toMatchObject({ model: 'sonnet', content: [{ text: 'Hello' }] });
    const [sent] = upstream.calls;
    expect(sent!.url).toBe('https://api.anthropic.com/v1/messages');
    expect(sent!.headers.get('x-api-key')).toBe('sk-ant-provider-key-9999');
    expect(sent!.headers.get('anthropic-version')).toBe('2023-06-01');
    expect(sent!.headers.get('authorization')).toBeNull();
    expect(sent!.body.model).toBe('claude-sonnet-5');
    // 10 × $3 + 5 cached × $0.30 + 20 × $15 per million = 331.5 micro-dollars.
    expect(await usage(f)).toEqual([
      expect.objectContaining({
        key: 'sonnet',
        inputTokens: 10,
        outputTokens: 20,
        cacheReadTokens: 5,
        costMicros: 331.5,
      }),
    ]);
  });

  it('streams server-sent events untouched and meters them when the stream ends', async () => {
    const { f, call } = await setup();
    const response = await call(
      '/v1/messages',
      undefined,
      { model: 'sonnet', max_tokens: 64, stream: true, messages: [] },
      { 'x-api-key': f.ownerCredential.token, 'anthropic-version': '2023-06-01' },
    );
    expect(response.headers.get('content-type')).toBe('text/event-stream');
    const text = await response.text();
    expect(text).toContain('event: message_start');
    expect(text).toContain('"output_tokens":25');
    await new Promise((resolve) => setTimeout(resolve, 20));
    expect(await usage(f)).toEqual([
      expect.objectContaining({ key: 'sonnet', inputTokens: 10, outputTokens: 25, requests: 1 }),
    ]);
  });

  it('serves OpenAI chat completions from an OpenAI-compatible provider, streaming usage too', async () => {
    const { f, upstream, call } = await setup();
    const plain = await call('/v1/chat/completions', f.ownerCredential.token, {
      model: 'open-model',
      messages: [{ role: 'user', content: 'Hi' }],
    });
    expect(plain.status).toBe(200);
    expect(upstream.calls[0]!.url).toBe('https://router.example/api/v1/chat/completions');
    expect(upstream.calls[0]!.headers.get('authorization')).toBe('Bearer sk-router-key-8888');
    const streamed = await call('/v1/chat/completions', f.ownerCredential.token, {
      model: 'open-model',
      stream: true,
      messages: [],
    });
    expect(upstream.calls[1]!.body.stream_options).toEqual({ include_usage: true });
    expect(await streamed.text()).toContain('[DONE]');
    await new Promise((resolve) => setTimeout(resolve, 20));
    // 10 + 2 cached input and 8 output, then 7 input and 3 output.
    expect(await usage(f)).toEqual([
      expect.objectContaining({
        key: 'open-model',
        requests: 2,
        inputTokens: 17,
        outputTokens: 11,
        cacheReadTokens: 2,
      }),
    ]);
  });

  it('refuses callers, models, formats and budgets in each API’s own error shape', async () => {
    const { f, upstream, call } = await setup();
    const alice = await f.member('alice');
    const aliceToken = (await f.signIn('alice')).token;

    const anonymous = await call('/v1/messages', undefined, { model: 'sonnet', messages: [] });
    expect(anonymous.status).toBe(401);
    expect(await anonymous.json()).toMatchObject({
      type: 'error',
      error: { type: 'authentication_error' },
    });

    const bogus = await call('/v1/chat/completions', 'not-a-real-credential-token-value-xyz', {
      model: 'open-model',
    });
    expect(bogus.status).toBe(401);
    expect(await bogus.json()).toMatchObject({ error: { code: 'UNAUTHENTICATED' } });

    const denied = await call('/v1/messages', aliceToken, { model: 'sonnet', messages: [] });
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({
      error: { type: 'permission_error', code: 'ACCESS_DENIED' },
    });

    const wrongFormat = await call('/v1/chat/completions', f.ownerCredential.token, {
      model: 'sonnet',
    });
    expect(wrongFormat.status).toBe(400);
    expect(await wrongFormat.json()).toMatchObject({ error: { code: 'WRONG_FORMAT' } });

    const unknown = await call('/v1/messages', f.ownerCredential.token, { model: 'missing' });
    expect(unknown.status).toBe(404);

    await f.iam.api.inference.setBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Tight',
      subjectType: 'identity',
      subjectId: f.ownerId,
      period: 'hour',
      maxTokens: 100,
    });
    const tooBig = await call('/v1/messages', f.ownerCredential.token, {
      model: 'sonnet',
      max_tokens: 4096,
      messages: [],
    });
    expect(tooBig.status).toBe(429);
    expect(Number(tooBig.headers.get('retry-after'))).toBeGreaterThan(0);
    expect(await tooBig.json()).toMatchObject({
      error: { type: 'rate_limit_error', code: 'BUDGET_EXCEEDED' },
    });
    expect(upstream.calls).toHaveLength(0);
    expect(alice.id).toBeDefined();
  });

  it('caps output tokens at the model’s limit and limits requests per minute', async () => {
    const { f, upstream, call } = await setup();
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'sonnet',
      maxOutputTokens: 1000,
    });
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'open-model',
      maxOutputTokens: 500,
    });
    const ask = (model: string, extra: Record<string, unknown>) =>
      call(model === 'sonnet' ? '/v1/messages' : '/v1/chat/completions', f.ownerCredential.token, {
        model,
        messages: [],
        ...extra,
      });
    expect((await ask('sonnet', { max_tokens: 64_000 })).status).toBe(200);
    expect((await ask('sonnet', { max_tokens: 200 })).status).toBe(200);
    expect((await ask('open-model', {})).status).toBe(200);
    expect(upstream.calls.map((sent) => sent.body.max_tokens)).toEqual([1000, 200, 500]);

    // A per-minute budget is a rate limit: the third request in a minute waits for the next one.
    await f.iam.api.inference.setBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Two per minute',
      subjectType: 'identity',
      subjectId: f.ownerId,
      period: 'minute',
      maxRequests: 2,
    });
    f.advance(60_000 - (f.now() % 60_000));
    expect((await ask('sonnet', { max_tokens: 10 })).status).toBe(200);
    expect((await ask('sonnet', { max_tokens: 10 })).status).toBe(200);
    const limited = await ask('sonnet', { max_tokens: 10 });
    expect(limited.status).toBe(429);
    expect(await limited.json()).toMatchObject({ error: { code: 'BUDGET_EXCEEDED' } });
    f.advance(60_000);
    expect((await ask('sonnet', { max_tokens: 10 })).status).toBe(200);
  });

  it('falls back to the next model the caller may use when a provider is overloaded', async () => {
    const { f, upstream } = await setup();
    const anthropic = (
      await f.iam.api.inference.listProviders(f.ownerCredential, { tenantId: f.tenantId })
    ).find((provider) => provider.kind === 'anthropic')!;
    await f.iam.api.inference.createModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'haiku',
      providerId: anthropic.id,
      upstreamModel: 'claude-haiku-4-5',
    });
    await expect(
      f.iam.api.inference.updateModel(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'sonnet',
        fallbacks: ['sonnet'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // open-model speaks the other wire format and is skipped; haiku is next.
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'sonnet',
      fallbacks: ['open-model', 'haiku'],
    });
    const overloaded = (async (url: string | URL | Request, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as { model: string };
      if (body.model === 'claude-sonnet-5')
        return Response.json(
          { type: 'error', error: { type: 'overloaded_error', message: 'Overloaded' } },
          { status: 529 },
        );
      return upstream.fetch(url, init);
    }) as typeof fetch;
    const gateway = f.iam.inference.gateway({ basePath: '/ai', fetch: overloaded });
    const ask = (token: string) =>
      gateway(
        new Request('http://gateway.test/ai/v1/messages', {
          method: 'POST',
          headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
          body: JSON.stringify({ model: 'sonnet', max_tokens: 64, messages: [] }),
        }),
      );
    const response = await ask(f.ownerCredential.token);
    expect(response.status).toBe(200);
    expect(response.headers.get('x-better-iam-model')).toBe('haiku');
    expect(response.headers.get('x-better-iam-fallback-from')).toBe('sonnet');
    expect(await response.json()).toMatchObject({ model: 'haiku' });
    const rows = await usage(f);
    expect(rows.find((row) => row.key === 'sonnet')).toMatchObject({
      requests: 1,
      outputTokens: 0,
    });
    expect(rows.find((row) => row.key === 'haiku')).toMatchObject({
      requests: 1,
      outputTokens: 20,
    });

    // A caller who may not use the fallback gets the provider's answer instead.
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Sonnet only',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Sonnet',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['inference:invoke'], resources: ['model/sonnet'] },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: agent.id,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const refused = await ask(key.token);
    expect(refused.status).toBe(529);
    expect(refused.headers.get('x-better-iam-fallback-from')).toBeNull();
  });

  it('lists the models a caller may use, in either format, for agents too', async () => {
    const { f, call } = await setup();
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Coder',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Open models',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['inference:invoke'], resources: ['model/open-*'] },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: agent.id,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const openai = await call('/v1/models', key.token);
    expect(await openai.json()).toMatchObject({
      object: 'list',
      data: [{ id: 'open-model', object: 'model', owned_by: 'Router' }],
    });
    const anthropic = await call('/v1/models', f.ownerCredential.token, undefined, {
      'anthropic-version': '2023-06-01',
    });
    expect((await anthropic.json()).data.map((model: { id: string }) => model.id)).toEqual([
      'open-model',
      'sonnet',
    ]);
    const completion = await call('/v1/chat/completions', key.token, { model: 'open-model' });
    expect(completion.status).toBe(200);
    const report = await f.iam.api.inference.usage(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'agent',
    });
    expect(report.rows[0]).toMatchObject({ key: agent.id, requests: 1 });
  });

  it('serves the Responses API and embeddings, and keeps each caller’s conversations their own', async () => {
    const { f, upstream, call } = await setup();
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'open-model',
      maxOutputTokens: 500,
    });
    const owner = f.ownerCredential.token;
    const first = await call('/v1/responses', owner, {
      model: 'open-model',
      input: 'Hi',
      max_output_tokens: 9999,
    });
    expect(first.status).toBe(200);
    const created = await first.json();
    expect(created).toMatchObject({ id: 'resp_1', object: 'response', model: 'open-model' });
    expect(upstream.calls[0]!.url).toBe('https://router.example/api/v1/responses');
    expect(upstream.calls[0]!.body).toMatchObject({
      model: 'vendor/open-model-70b',
      max_output_tokens: 500,
    });

    // Streamed, with the id taken from response.created and usage from response.completed.
    const streamed = await call('/v1/responses', owner, {
      model: 'open-model',
      input: 'More',
      stream: true,
      previous_response_id: 'resp_1',
    });
    expect(streamed.status).toBe(200);
    expect(await streamed.text()).toContain('event: response.completed');
    expect(upstream.calls[1]!.body.stream_options).toBeUndefined();
    await new Promise((resolve) => setTimeout(resolve, 20));
    const continued = await call('/v1/responses', owner, {
      model: 'open-model',
      input: 'And again',
      previous_response_id: 'resp_2',
    });
    expect(continued.status).toBe(200);

    // Someone else, even with access to the model, cannot continue the owner's conversation.
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Open model users',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['inference:invoke'], resources: ['model/open-model'] },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const aliceToken = (await f.signIn('alice')).token;
    const sent = upstream.calls.length;
    const stolen = await call('/v1/responses', aliceToken, {
      model: 'open-model',
      input: 'What did they say?',
      previous_response_id: 'resp_1',
    });
    expect(stolen.status).toBe(404);
    expect(await stolen.json()).toMatchObject({ error: { code: 'RESPONSE_NOT_FOUND' } });
    for (const refused of [
      { previous_response_id: '../resp_1' },
      { conversation: 'conv_123' },
      { background: true },
    ]) {
      const answer = await call('/v1/responses', aliceToken, {
        model: 'open-model',
        input: 'x',
        ...refused,
      });
      expect(answer.status).toBe(400);
    }
    expect(upstream.calls).toHaveLength(sent);
    expect(
      (await call('/v1/responses', aliceToken, { model: 'open-model', input: 'Hi' })).status,
    ).toBe(200);

    // Embeddings: input tokens only, and no output limit is added.
    const embedded = await call('/v1/embeddings', owner, { model: 'open-model', input: 'text' });
    expect(embedded.status).toBe(200);
    expect(await embedded.json()).toMatchObject({
      model: 'open-model',
      usage: { prompt_tokens: 9 },
    });
    const embeddingCall = upstream.calls.at(-1)!;
    expect(embeddingCall.url).toBe('https://router.example/api/v1/embeddings');
    expect(Object.keys(embeddingCall.body).sort()).toEqual(['input', 'model']);

    // Three owner responses and one of Alice's (20 input, 10 cached, 12 output each), plus 9 embedding tokens.
    expect(await usage(f)).toEqual([
      expect.objectContaining({
        key: 'open-model',
        requests: 5,
        inputTokens: 4 * 20 + 9,
        cacheReadTokens: 4 * 10,
        outputTokens: 4 * 12,
      }),
    ]);
  });

  it('governs the tools the provider runs itself, per model and by policy', async () => {
    const { f, upstream, call } = await setup();
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'open-model',
      providerTools: 'policy',
    });
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'sonnet',
      providerTools: 'deny',
    });
    expect(
      (await f.iam.api.inference.listModels(f.ownerCredential, { tenantId: f.tenantId })).map(
        (model) => [model.name, model.providerTools],
      ),
    ).toEqual([
      ['open-model', 'policy'],
      ['sonnet', 'deny'],
    ]);
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Researchers',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['inference:invoke'],
            resources: ['model/open-model', 'model/sonnet'],
          },
          {
            effect: 'allow',
            actions: ['inference:use-tool'],
            resources: ['model-tool/web_search', 'model-tool/mcp:*.acme.test'],
          },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const token = (await f.signIn('alice')).token;
    const respond = (tools: unknown[]) =>
      call('/v1/responses', token, { model: 'open-model', input: 'Hi', tools });
    expect((await respond([{ type: 'web_search_preview' }])).status).toBe(200);
    expect(
      (await respond([{ type: 'mcp', server_label: 'kb', server_url: 'https://kb.acme.test/mcp' }]))
        .status,
    ).toBe(200);
    // Functions the caller runs itself are not provider tools.
    expect((await respond([{ type: 'function', name: 'lookup', parameters: {} }])).status).toBe(
      200,
    );
    const sent = upstream.calls.length;
    const interpreter = await respond([{ type: 'code_interpreter', container: { type: 'auto' } }]);
    expect(interpreter.status).toBe(403);
    expect(await interpreter.json()).toMatchObject({
      error: { code: 'TOOL_NOT_ALLOWED', message: expect.stringContaining('code_interpreter') },
    });
    const elsewhere = await respond([
      { type: 'mcp', server_label: 'x', server_url: 'https://tools.evil.example/mcp' },
    ]);
    expect(elsewhere.status).toBe(403);
    expect(upstream.calls).toHaveLength(sent);
    expect(
      (
        await call('/v1/chat/completions', token, {
          model: 'open-model',
          messages: [],
          web_search_options: {},
        })
      ).status,
    ).toBe(200);

    // A model that allows no provider tools: custom tools still pass, server tools and MCP servers do not.
    const messages = (extra: Record<string, unknown>) =>
      call('/v1/messages', token, { model: 'sonnet', max_tokens: 16, messages: [], ...extra });
    expect(
      (await messages({ tools: [{ name: 'lookup', input_schema: { type: 'object' } }] })).status,
    ).toBe(200);
    const search = await messages({
      tools: [{ type: 'web_search_20250305', name: 'web_search', max_uses: 2 }],
    });
    expect(search.status).toBe(403);
    expect(await search.json()).toMatchObject({
      type: 'error',
      error: { type: 'permission_error', code: 'TOOL_NOT_ALLOWED' },
    });
    expect(
      (
        await messages({
          mcp_servers: [{ type: 'url', url: 'https://kb.acme.test/mcp', name: 'kb' }],
        })
      ).status,
    ).toBe(403);
    // Counting tokens runs no tool.
    expect(
      (
        await call('/v1/messages/count_tokens', token, {
          model: 'sonnet',
          messages: [],
          tools: [{ type: 'web_search_20250305', name: 'web_search' }],
        })
      ).status,
    ).toBe(200);
  });

  it('refuses what it cannot check: too many tools, stored provider objects, prompts under a tool policy', async () => {
    const { f, upstream, call } = await setup();
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'open-model',
      providerTools: 'deny',
    });
    const owner = f.ownerCredential.token;
    const respond = (extra: Record<string, unknown>) =>
      call('/v1/responses', owner, { model: 'open-model', input: 'Hi', ...extra });
    const many = Array.from({ length: 257 }, (_, index) => ({
      type: 'function',
      name: `f${index}`,
      parameters: {},
    }));
    expect((await respond({ tools: many })).status).toBe(400);
    expect((await respond({ prompt: { id: 'pmpt_1' } })).status).toBe(403);
    for (const input of [
      [{ type: 'item_reference', id: 'msg_someone_elses' }],
      [{ role: 'user', content: [{ type: 'input_file', file_id: 'file-abc' }] }],
    ]) {
      const refused = await respond({ input });
      expect(refused.status).toBe(400);
      expect(await refused.json()).toMatchObject({ error: { code: 'UNSUPPORTED_PARAMETER' } });
    }
    expect(
      (
        await call('/v1/messages', owner, {
          model: 'sonnet',
          messages: [],
          container: 'container_1',
        })
      ).status,
    ).toBe(400);
    expect(upstream.calls).toHaveLength(0);

    // A response continues only at the provider that answered it.
    const other = await f.iam.api.inference.createProvider(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Echo',
      kind: 'openai-compatible',
      apiKey: 'sk-echo-key-7777',
      baseUrl: 'https://echo.example/v1',
    });
    await f.iam.api.inference.createModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'echo-model',
      providerId: other.id,
      upstreamModel: 'echo',
    });
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'open-model',
      providerTools: null,
    });
    const first = await (await respond({})).json();
    expect((await respond({ previous_response_id: first.id })).status).toBe(200);
    expect(
      (
        await call('/v1/responses', owner, {
          model: 'echo-model',
          input: 'Hi',
          previous_response_id: first.id,
        })
      ).status,
    ).toBe(404);
  });

  it('meters a stream the client closes before its final usage event', async () => {
    const { f } = await setup();
    // A provider that streams the start of an answer and then keeps the connection open.
    const hanging = (async () => {
      const events = new TextEncoder().encode(
        sse([
          [
            'response.created',
            { type: 'response.created', response: { id: 'resp_h', usage: null } },
          ],
          [
            'response.output_text.delta',
            { type: 'response.output_text.delta', delta: 'x'.repeat(400) },
          ],
        ]),
      );
      return new Response(
        new ReadableStream<Uint8Array>({ start: (controller) => controller.enqueue(events) }),
        { headers: { 'content-type': 'text/event-stream' } },
      );
    }) as unknown as typeof fetch;
    const gateway = f.iam.inference.gateway({ basePath: '/ai', fetch: hanging });
    const streamed = await gateway(
      new Request('http://gateway.test/ai/v1/responses', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${f.ownerCredential.token}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ model: 'open-model', input: 'x'.repeat(4000), stream: true }),
      }),
    );
    const reader = streamed.body!.getReader();
    await reader.read();
    await reader.cancel();
    await new Promise((resolve) => setTimeout(resolve, 20));
    const [row] = await usage(f);
    // No final counts: the request's size stands in for the input, the text streamed so far for the output.
    expect(row).toMatchObject({ key: 'open-model', requests: 1, outputTokens: 100 });
    expect(row!.inputTokens).toBeGreaterThanOrEqual(1000);
  });

  it('names provider tools the way policies see them', () => {
    expect(
      providerToolsOf('/v1/responses', {
        tools: [
          { type: 'web_search_preview_2025_03_11' },
          { type: 'function', name: 'x' },
          { type: 'custom', name: 'y' },
          { type: 'mcp', server_url: 'https://KB.Acme.Test:8443/mcp' },
          { type: 'mcp', connector_id: 'connector_googledrive' },
          { type: 'mcp', server_url: 'not a url' },
          { type: 'image_generation' },
        ],
      }),
    ).toEqual([
      'web_search',
      'mcp:kb.acme.test',
      'mcp:connector_googledrive',
      'mcp:invalid',
      'image_generation',
    ]);
    expect(
      providerToolsOf('/v1/messages', {
        tools: [
          { type: 'code_execution_20250825', name: 'code_execution' },
          { name: 'lookup', input_schema: {} },
          { type: 'computer_20250124', name: 'computer' },
        ],
        mcp_servers: [{ type: 'url', url: 'http://[::1]:9000/mcp' }],
      }),
    ).toEqual(['code_execution', 'computer', 'mcp:_::1_']);
    // Only canonical http(s) URLs name a host: tricks that parse differently elsewhere read as invalid.
    expect(
      providerToolsOf('/v1/messages', {
        mcp_servers: [
          { url: 'https://kb.acme.test' },
          { url: 'https://evil.example./mcp' },
          { url: 'https://kb.acme.test\\@evil.example/mcp' },
          { url: 'https://user@kb.acme.test/mcp' },
          { url: 'https://kb.acme.test:443/mcp' },
        ],
      }),
    ).toEqual(['mcp:kb.acme.test', 'mcp:evil.example', 'mcp:invalid']);
    expect(providerToolsOf('/v1/responses', { prompt: { id: 'pmpt_1' } })).toEqual(['prompt']);
  });

  it('counts Anthropic tokens for callers who may use the model, without metering', async () => {
    const { f, upstream, call } = await setup();
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'sonnet',
      maxOutputTokens: 1000,
    });
    const counted = await call('/v1/messages/count_tokens', f.ownerCredential.token, {
      model: 'sonnet',
      messages: [{ role: 'user', content: 'Hello' }],
    });
    expect(counted.status).toBe(200);
    expect(await counted.json()).toEqual({ input_tokens: 42 });
    expect(upstream.calls[0]!.url).toBe('https://api.anthropic.com/v1/messages/count_tokens');
    expect(upstream.calls[0]!.body).toEqual({
      model: 'claude-sonnet-5',
      messages: [{ role: 'user', content: 'Hello' }],
    });
    expect(await usage(f)).toEqual([]);

    await f.member('bob');
    const refused = await call('/v1/messages/count_tokens', (await f.signIn('bob')).token, {
      model: 'sonnet',
      messages: [],
    });
    expect(refused.status).toBe(403);
    expect(await refused.json()).toMatchObject({ type: 'error', error: { code: 'ACCESS_DENIED' } });
    const wrongFormat = await call('/v1/responses', f.ownerCredential.token, {
      model: 'sonnet',
      input: 'x',
    });
    expect(wrongFormat.status).toBe(400);
    expect(await wrongFormat.json()).toMatchObject({ error: { code: 'WRONG_FORMAT' } });
  });
});
