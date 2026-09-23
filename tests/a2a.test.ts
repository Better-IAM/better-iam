import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  A2A_ACCESS_DENIED,
  A2A_CONFIRMATION_REQUESTED,
  AgentCardError,
  agentAttestationUri,
  createA2aGate,
  createCardAttestor,
  discoverAgent,
  handoffMetadataKey,
  handoffOf,
  verifyAgentCard,
  withHandoff,
  type A2aCaller,
  type AgentCard,
} from '@better-iam/a2a';
import { canonicalizeJson, IamError } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

function cardKey(kid: string) {
  const { privateKey } = generateKeyPairSync('ed25519');
  return { ...privateKey.export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig' };
}

const baseCard = (url = 'https://agents.acme.test/a2a'): AgentCard => ({
  protocolVersion: '0.3.0',
  name: 'Triage',
  description: 'Sorts incoming requests',
  url,
  version: '1.2.0',
  capabilities: { streaming: true },
  defaultInputModes: ['text/plain'],
  defaultOutputModes: ['text/plain'],
  skills: [
    { id: 'summarize', name: 'Summarize', description: 'Summarizes a document', tags: ['docs'] },
    { id: 'purge', name: 'Purge', description: 'Deletes archived documents', tags: ['docs'] },
  ],
});

async function setup(options: { lifetime?: number } = {}) {
  const f = await organizationFixture({
    a2a: {
      signingKeys: [cardKey('card-1')],
      jwksUrl: 'https://iam.acme.test/a2a/jwks.json',
      ...(options.lifetime ? { cardLifetimeSeconds: options.lifetime } : {}),
    },
  });
  const agent = await f.iam.api.agents.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Triage agent',
    url: 'https://agents.acme.test/triage',
    model: 'claude-sonnet-5',
    provider: 'Anthropic',
    protocols: ['a2a'],
  });
  const key = await f.iam.api.credentials.create(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId: agent.id,
  });
  const sign = (card: AgentCard, token = key.token) =>
    f.iam.api.agents.signCard({ token }, { tenantId: f.tenantId, agentId: agent.id, card });
  return { f, agent, key, sign };
}

async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(Error);
  return error as IamError & AgentCardError;
}

describe('JSON canonicalization (RFC 8785)', () => {
  it('matches the RFC example and orders members by UTF-16 code units', () => {
    const input = JSON.parse(
      '{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/","literals":[null,true,false]}',
    ) as unknown;
    expect(canonicalizeJson(input)).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
    // Integer-like names sort as strings, not in the engine's numeric order.
    expect(
      canonicalizeJson({ 10: 'a', 9: 'b', b: [undefined, 1], a: { d: undefined, c: -0 } }),
    ).toBe('{"10":"a","9":"b","a":{"c":0},"b":[null,1]}');
    const cyclic: Record<string, unknown> = {};
    cyclic.self = cyclic;
    expect(() => canonicalizeJson(cyclic)).toThrow(TypeError);
    expect(() => canonicalizeJson({ value: Number.NaN })).toThrow(TypeError);
  });
});

describe('IAM-attested A2A agent cards', () => {
  it('signs an agent’s card with an attestation that verifies against the deployment keys', async () => {
    const { f, agent, sign } = await setup();
    const signed = await sign({
      ...baseCard(),
      provider: { organization: 'Somebody else', url: 'https://acme.test' },
      capabilities: {
        streaming: true,
        extensions: [
          { uri: agentAttestationUri, params: { agentId: 'forged' } },
          { uri: 'https://example.test/ext/traceability', required: false },
        ],
      },
      signatures: [{ protected: 'forged', signature: 'forged' }],
    });
    // The provider is the organization at the agent's registered origin, whatever the card claimed.
    expect(signed.card.provider).toEqual({
      organization: 'Acme',
      url: 'https://agents.acme.test',
    });
    expect(signed.card.signatures).toHaveLength(1);
    const extensions = (signed.card.capabilities as AgentCard['capabilities'])!.extensions!;
    expect(extensions.map((item) => item.uri)).toEqual([
      'https://example.test/ext/traceability',
      agentAttestationUri,
    ]);
    expect(signed.attestation).toEqual({
      issuer: 'http://localhost:3000/api/iam',
      tenantId: f.tenantId,
      organization: 'Acme',
      agentId: agent.id,
      agentName: 'Triage agent',
      sponsored: true,
      delegable: true,
      model: 'claude-sonnet-5',
      provider: 'anthropic',
      protocols: ['a2a'],
      issuedAt: new Date(f.now()).toISOString(),
      expiresAt: new Date(f.now() + 3600_000).toISOString(),
    });
    const header = JSON.parse(
      Buffer.from(signed.card.signatures[0]!.protected, 'base64url').toString(),
    ) as Record<string, unknown>;
    expect(header).toEqual({
      alg: 'EdDSA',
      kid: 'card-1',
      typ: 'JOSE',
      jku: 'https://iam.acme.test/a2a/jwks.json',
    });

    const keys = f.iam.a2a.jwks();
    expect(keys.keys).toEqual([
      expect.objectContaining({
        kid: 'card-1',
        kty: 'OKP',
        crv: 'Ed25519',
        alg: 'EdDSA',
        use: 'sig',
      }),
    ]);
    expect(keys.keys[0]).not.toHaveProperty('d');
    const verified = await verifyAgentCard(signed.card, {
      keys,
      tenantId: f.tenantId,
      issuers: ['http://localhost:3000/api/iam'],
      now: f.now,
    });
    expect(verified).toMatchObject({ kid: 'card-1', attestation: { agentId: agent.id } });

    // Any change breaks the signature; an expired attestation, another tenant or unknown keys are refused.
    const tampered = {
      ...signed.card,
      skills: [...(signed.card.skills as unknown[]), { id: 'x' }],
    };
    expect((await refusal(verifyAgentCard(tampered, { keys, now: f.now }))).reason).toBe(
      'signature',
    );
    expect(
      (await refusal(verifyAgentCard(signed.card, { keys, now: () => f.now() + 3 * 3600_000 })))
        .reason,
    ).toBe('expired');
    expect(
      (await refusal(verifyAgentCard(signed.card, { keys, tenantId: 'other', now: f.now }))).reason,
    ).toBe('tenant');
    const { d: _secret, ...stranger } = cardKey('card-1');
    const strangers = { keys: [{ ...stranger, kty: 'OKP' }] };
    expect(
      (await refusal(verifyAgentCard(signed.card, { keys: strangers, now: f.now }))).reason,
    ).toBe('signature');
    const unsigned = { ...signed.card, signatures: [] };
    expect((await refusal(verifyAgentCard(unsigned, { keys, now: f.now }))).reason).toBe(
      'unsigned',
    );

    // Keys fetched from a trusted JWKS URL (the signature's jku) verify too; other URLs are never fetched.
    const fetched: string[] = [];
    const fetcher = (async (input: RequestInfo | URL) => {
      fetched.push(String(input));
      return f.iam.a2a.jwksResponse();
    }) as typeof fetch;
    await expect(
      verifyAgentCard(signed.card, {
        trustedJwksUrls: ['https://iam.acme.test/a2a/jwks.json'],
        fetch: fetcher,
        now: f.now,
      }),
    ).resolves.toMatchObject({ kid: 'card-1' });
    expect(
      (
        await refusal(
          verifyAgentCard(signed.card, {
            trustedJwksUrls: ['https://iam.other.test/jwks.json'],
            fetch: fetcher,
            now: f.now,
          }),
        )
      ).reason,
    ).toBe('untrusted-key');
    expect(fetched).toEqual(['https://iam.acme.test/a2a/jwks.json']);

    const audit = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'agent:card-sign',
    });
    expect(audit[0]).toMatchObject({ actorId: agent.id, resourceId: agent.id });
  });

  it('only attests registered endpoints of agents in good standing, for the agent, its sponsor or administrators', async () => {
    const { f, agent, key, sign } = await setup();
    const offOrigin = await refusal(sign(baseCard('https://elsewhere.test/a2a')));
    expect(offOrigin).toMatchObject({ code: 'INVALID_INPUT' });
    const sideDoor = await refusal(
      sign({
        ...baseCard(),
        additionalInterfaces: [{ url: 'https://elsewhere.test/grpc', transport: 'GRPC' }],
      }),
    );
    expect(sideDoor.message).toContain('additionalInterfaces[0].url');
    const newer = await refusal(
      sign({ ...baseCard(), supportedInterfaces: [{ url: 'https://elsewhere.test/a2a' }] }),
    );
    expect(newer.message).toContain('supportedInterfaces[0].url');

    // A key whose scopes limit it cannot attest the agent, even its own.
    const scoped = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
      scopes: ['documents:read'],
    });
    expect(await refusal(sign(baseCard(), scoped.token))).toMatchObject({ code: 'ACCESS_DENIED' });

    // The owner (an administrator) may sign; another agent's key may not.
    await expect(
      f.iam.api.agents.signCard(f.ownerCredential, {
        tenantId: f.tenantId,
        agentId: agent.id,
        card: baseCard(),
      }),
    ).resolves.toMatchObject({ attestation: { agentId: agent.id } });
    const other = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Other',
      url: 'https://agents.acme.test/other',
    });
    const otherKey = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: other.id,
    });
    expect(await refusal(sign(baseCard(), otherKey.token))).toMatchObject({
      code: 'ACCESS_DENIED',
    });

    // A sponsor signs their own agent's card; an agent without a registered url cannot be attested.
    const sam = await f.member('sam');
    const samSession = { token: (await f.signIn('sam')).token };
    const unregistered = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Unregistered',
      sponsorId: sam.id,
    });
    expect(
      await refusal(
        f.iam.api.agents.signCard(samSession, {
          tenantId: f.tenantId,
          agentId: unregistered.id,
          card: baseCard(),
        }),
      ),
    ).toMatchObject({ code: 'INVALID_INPUT' });

    // A suspended agent is neither attested nor able to ask.
    await f.iam.api.agents.suspend(f.ownerCredential, { tenantId: f.tenantId, agentId: agent.id });
    expect(
      await refusal(
        f.iam.api.agents.signCard(f.ownerCredential, {
          tenantId: f.tenantId,
          agentId: agent.id,
          card: baseCard(),
        }),
      ),
    ).toMatchObject({ code: 'INVALID_IDENTITY' });
    expect(await refusal(sign(baseCard(), key.token))).toMatchObject({ status: 401 });
  });

  it('keeps a directory of the tenant’s attested agents, by skill and protocol', async () => {
    const { f, agent, sign } = await setup();
    await sign(baseCard());
    const helper = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Helper',
      url: 'https://helper.acme.test',
      protocols: ['mcp'],
    });
    const helperKey = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: helper.id,
    });
    await f.iam.api.agents.signCard(
      { token: helperKey.token },
      {
        tenantId: f.tenantId,
        agentId: helper.id,
        card: {
          name: 'Helper',
          url: 'https://helper.acme.test/a2a',
          skills: [{ id: 'translate', name: 'Translate', tags: ['language'] }],
        },
      },
    );
    await f.member('alice');
    const alice = { token: (await f.signIn('alice')).token };
    const names = async (credential: { token: string }, filter: Record<string, string> = {}) =>
      (await f.iam.api.agents.directory(credential, { tenantId: f.tenantId, ...filter })).map(
        (entry) => entry.name,
      );
    expect(await names(alice)).toEqual(['Helper', 'Triage agent']);
    // Entries are the signed cards themselves, ready to verify.
    const [, triage] = await f.iam.api.agents.directory(alice, { tenantId: f.tenantId });
    await expect(
      verifyAgentCard(triage!.card, { keys: f.iam.a2a.jwks(), now: f.now }),
    ).resolves.toMatchObject({ attestation: { agentId: agent.id } });
    expect(await names(alice, { skill: 'summarize' })).toEqual(['Triage agent']);
    expect(await names(alice, { skill: 'language' })).toEqual(['Helper']);
    expect(await names(alice, { protocol: 'a2a' })).toEqual(['Triage agent']);
    // Agents find each other too.
    expect(await names({ token: helperKey.token })).toEqual(['Helper', 'Triage agent']);

    // Suspended agents leave the directory, as do attestations that expire; deleted agents' entries go.
    await f.iam.api.agents.suspend(f.ownerCredential, { tenantId: f.tenantId, agentId: helper.id });
    expect(await names(alice)).toEqual(['Triage agent']);
    await f.iam.api.agents.resume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      agentId: helper.id,
    });
    expect(await names(alice)).toEqual(['Helper', 'Triage agent']);
    await f.iam.api.agents.delete(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      agentId: helper.id,
    });
    expect(await names(alice)).toEqual(['Triage agent']);
    f.advance(2 * 3600_000);
    const later = { token: (await f.signIn('alice')).token };
    expect(await names(later)).toEqual([]);
  });

  it('is off without the a2a option and refuses invalid keys at construction', async () => {
    const f = await organizationFixture();
    expect(f.iam.a2a.enabled).toBe(false);
    expect(f.iam.a2a.jwks()).toEqual({ keys: [] });
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Plain',
      url: 'https://agents.acme.test',
    });
    expect(
      await refusal(
        f.iam.api.agents.signCard(f.ownerCredential, {
          tenantId: f.tenantId,
          agentId: agent.id,
          card: baseCard(),
        }),
      ),
    ).toMatchObject({ code: 'FEATURE_DISABLED' });
    const { d: _private, ...publicOnly } = cardKey('public');
    await expect(organizationFixture({ a2a: { signingKeys: [publicOnly] } })).rejects.toThrow(
      'a2a.signingKeys must contain private keys',
    );
    await expect(
      organizationFixture({ a2a: { signingKeys: [cardKey('k')], cardLifetimeSeconds: 10 } }),
    ).rejects.toThrow('cardLifetimeSeconds');
  });

  it('keeps an agent’s served card attested and lets callers discover and verify it', async () => {
    const { f, agent, sign } = await setup();
    let signings = 0;
    const attested = createCardAttestor({
      card: baseCard(),
      sign: async (card) => {
        signings++;
        return sign(card);
      },
      now: f.now,
    });
    const gate = createA2aGate({
      iam: f.iam,
      tenantId: f.tenantId,
      message: { public: true },
      card: attested,
    });
    const fetcher = (async (input: RequestInfo | URL) =>
      gate(
        new Request(String(input)),
        () => new Response('unexpected', { status: 500 }),
      )) as typeof fetch;
    const discovered = await discoverAgent('https://agents.acme.test', {
      keys: f.iam.a2a.jwks(),
      tenantId: f.tenantId,
      now: f.now,
      fetch: fetcher,
    });
    expect(discovered.attestation.agentId).toBe(agent.id);
    await attested();
    expect(signings).toBe(1);
    // Re-signed once less than a fifth of the hour is left.
    f.advance(50 * 60_000);
    await attested();
    expect(signings).toBe(2);
    await expect(
      discoverAgent('https://impostor.test', {
        keys: f.iam.a2a.jwks(),
        now: f.now,
        fetch: fetcher,
      }),
    ).rejects.toMatchObject({ reason: 'endpoint' });

    // trustedIssuers binds keys to the issuer a card names: the right keys under another issuer's name do not count.
    const issuer = discovered.attestation.issuer;
    await expect(
      verifyAgentCard(discovered.card, {
        trustedIssuers: { [issuer]: f.iam.a2a.jwks() },
        now: f.now,
      }),
    ).resolves.toMatchObject({ attestation: { issuer } });
    await expect(
      verifyAgentCard(discovered.card, {
        trustedIssuers: { 'https://iam.other.test/api/iam': f.iam.a2a.jwks() },
        now: f.now,
      }),
    ).rejects.toMatchObject({ reason: 'issuer' });

    // An attestor whose card builder throws recovers once the builder does.
    let broken = true;
    const flaky = createCardAttestor({
      card: () => {
        if (broken) throw new Error('not ready');
        return baseCard();
      },
      sign: (card) => sign(card),
      now: f.now,
    });
    await expect(flaky()).rejects.toThrow('not ready');
    broken = false;
    await expect(flaky()).resolves.toMatchObject({ name: 'Triage' });
  });
});

/** A stand-in A2A server: creates tasks for messages (JSON or an event stream) and answers task reads. */
function a2aServer() {
  const calls: { method: string; caller: A2aCaller }[] = [];
  let count = 0;
  const handle = async (request: Request, caller: A2aCaller): Promise<Response> => {
    const message = (await request.json()) as {
      id: number;
      method: string;
      params?: Record<string, unknown>;
    };
    calls.push({ method: message.method, caller });
    const sent = message.params?.message as { contextId?: string } | undefined;
    const task = (id: string, state = 'submitted') => ({
      kind: 'task',
      id,
      contextId: sent?.contextId ?? `ctx-${id}`,
      status: { state },
    });
    if (message.method === 'message/send')
      return Response.json({ jsonrpc: '2.0', id: message.id, result: task(`task-${++count}`) });
    if (message.method === 'message/stream') {
      const id = `task-${++count}`;
      const events = [
        { jsonrpc: '2.0', id: message.id, result: task(id) },
        {
          jsonrpc: '2.0',
          id: message.id,
          result: { kind: 'status-update', taskId: id, status: { state: 'working' }, final: true },
        },
      ];
      const bytes = new TextEncoder().encode(
        events.map((event) => `data: ${JSON.stringify(event)}\n\n`).join(''),
      );
      return new Response(
        new ReadableStream({
          start(controller) {
            for (let index = 0; index < bytes.length; index += 17)
              controller.enqueue(bytes.slice(index, index + 17));
            controller.close();
          },
        }),
        { headers: { 'content-type': 'text/event-stream' } },
      );
    }
    if (message.method === 'tasks/get' || message.method === 'tasks/cancel')
      return Response.json({
        jsonrpc: '2.0',
        id: message.id,
        result: task(String(message.params?.id), 'working'),
      });
    return Response.json({ jsonrpc: '2.0', id: message.id, result: {} });
  };
  return { calls, handle };
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

async function gateSetup() {
  const f = await organizationFixture();
  const server = a2aServer();
  const card = baseCard();
  const gate = createA2aGate({
    iam: f.iam,
    tenantId: f.tenantId,
    card,
    extendedCard: card,
    message: { action: 'documents:read', resource: { type: 'document', id: 'inbox' } },
    skills: {
      summarize: { action: 'documents:read', resource: { type: 'document', id: 'inbox' } },
      purge: { action: 'documents:write', resource: { type: 'document', id: 'archive' } },
    },
    taskAdminAction: 'documents:write',
  });
  const rpc = async (token: string | undefined, method: string, params?: unknown) => {
    const response = await gate(
      new Request('https://agents.acme.test/a2a', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          ...(token ? { authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({ jsonrpc: '2.0', id: 3, method, ...(params ? { params } : {}) }),
      }),
      server.handle,
    );
    return response;
  };
  const agentWith = async (name: string, actions: string[]) => {
    const agent = await f.iam.api.agents.create(f.ownerCredential, { tenantId: f.tenantId, name });
    if (actions.length) await grantDocuments(f, agent.id, actions);
    return (
      await f.iam.api.credentials.create(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: agent.id,
      })
    ).token;
  };
  const message = (text: string, extra: Record<string, unknown> = {}) => ({
    message: {
      kind: 'message',
      role: 'user',
      messageId: `m-${text}`,
      parts: [{ kind: 'text', text }],
      ...extra,
    },
  });
  return { f, gate, server, rpc, agentWith, message };
}

describe('A2A gate', () => {
  it('authorizes messages by skill and keeps each task private to its caller', async () => {
    const { f, gate, server, rpc, agentWith, message } = await gateSetup();
    const card = await gate(
      new Request('https://agents.acme.test/.well-known/agent-card.json'),
      server.handle,
    );
    expect(card.status).toBe(200);
    expect(((await card.json()) as AgentCard).name).toBe('Triage');
    expect((await rpc(undefined, 'message/send', message('hi'))).status).toBe(401);

    const reader = await agentWith('Reader', ['documents:read']);
    const neighbour = await agentWith('Neighbour', ['documents:read']);
    const sent = (await (await rpc(reader, 'message/send', message('hi'))).json()) as {
      result: { id: string };
    };
    expect(sent.result.id).toBe('task-1');
    expect(server.calls.at(-1)!.caller).toMatchObject({ kind: 'iam', identityKind: 'agent' });

    expect(await (await rpc(reader, 'tasks/get', { id: 'task-1' })).json()).toMatchObject({
      result: { id: 'task-1' },
    });
    // Another caller cannot read, cancel or continue the task: it does not exist for them.
    for (const [method, params] of [
      ['tasks/get', { id: 'task-1' }],
      ['tasks/cancel', { id: 'task-1' }],
      ['tasks/pushNotificationConfig/set', { taskId: 'task-1', pushNotificationConfig: {} }],
      ['message/send', message('more', { taskId: 'task-1' })],
    ] as const)
      expect(await (await rpc(neighbour, method, params)).json()).toMatchObject({
        error: { code: -32001, message: 'Task not found' },
      });
    // An operator with the task admin action may.
    expect(
      await (await rpc(f.ownerCredential.token, 'tasks/cancel', { id: 'task-1' })).json(),
    ).toMatchObject({
      result: { id: 'task-1' },
    });

    // Tasks started over an event stream are recorded as the events pass by.
    const streamed = await rpc(reader, 'message/stream', message('stream'));
    expect(await streamed.text()).toContain('status-update');
    expect(await (await rpc(reader, 'tasks/get', { id: 'task-2' })).json()).toMatchObject({
      result: { id: 'task-2' },
    });

    // Conversations (contexts) are private the same way: only the caller who started one may add to it.
    expect(
      await (
        await rpc(neighbour, 'message/send', message('join', { contextId: 'ctx-task-1' }))
      ).json(),
    ).toMatchObject({ error: { code: -32602 } });
    expect(
      await (
        await rpc(reader, 'message/send', message('again', { contextId: 'ctx-task-1' }))
      ).json(),
    ).toMatchObject({ result: { id: 'task-3', contextId: 'ctx-task-1' } });
    // Conversations the server never started belong to no one; referenced tasks must be the caller's own.
    expect(
      await (
        await rpc(reader, 'message/send', message('new', { contextId: 'ctx-made-up' }))
      ).json(),
    ).toMatchObject({ error: { code: -32602 } });
    expect(
      await (
        await rpc(neighbour, 'message/send', message('peek', { referenceTaskIds: ['task-1'] }))
      ).json(),
    ).toMatchObject({ error: { code: -32001 } });
    // A request naming two different skills is refused, so the gate and the server cannot disagree on it.
    expect(
      await (
        await rpc(reader, 'message/send', {
          ...message('both', { metadata: { skillId: 'summarize' } }),
          metadata: { skillId: 'purge' },
        })
      ).json(),
    ).toMatchObject({ error: { code: A2A_ACCESS_DENIED, data: { reason: 'AMBIGUOUS_SKILL' } } });
    // Only JSON-RPC over POST reaches the server.
    const get = await gate(
      new Request('https://agents.acme.test/v1/tasks/task-1', {
        headers: { authorization: `Bearer ${neighbour}` },
      }),
      server.handle,
    );
    expect(get.status).toBe(405);

    // Skills: the one the caller may use passes; a denied or unknown one never reaches the server.
    const skill = (id: string) => message(id, { metadata: { skillId: id } });
    expect((await rpc(reader, 'message/send', skill('summarize'))).status).toBe(200);
    const denied = await rpc(reader, 'message/send', skill('purge'));
    expect(denied.status).toBe(403);
    expect(await denied.json()).toMatchObject({
      error: { code: A2A_ACCESS_DENIED, data: { reason: 'ACCESS_DENIED' } },
    });
    expect(await (await rpc(reader, 'message/send', skill('mystery'))).json()).toMatchObject({
      error: { code: A2A_ACCESS_DENIED, data: { reason: 'UNKNOWN_SKILL' } },
    });
    const outsider = await agentWith('Outsider', []);
    expect((await rpc(outsider, 'message/send', message('hi'))).status).toBe(403);

    // The extended card lists only usable skills; unknown methods and batches are refused.
    expect(await (await rpc(reader, 'agent/getAuthenticatedExtendedCard')).json()).toMatchObject({
      result: { skills: [{ id: 'summarize' }] },
    });
    expect(await (await rpc(reader, 'admin/dump')).json()).toMatchObject({
      error: { code: -32601 },
    });
    const batch = await gate(
      new Request('https://agents.acme.test/a2a', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${reader}` },
        body: JSON.stringify([
          { jsonrpc: '2.0', id: 1, method: 'tasks/get', params: { id: 'task-1' } },
        ]),
      }),
      server.handle,
    );
    expect(await batch.json()).toMatchObject({ error: { code: -32600 } });
    expect(server.calls.map((call) => call.method)).toEqual([
      'message/send',
      'tasks/get',
      'tasks/cancel',
      'message/stream',
      'tasks/get',
      'message/send',
      'message/send',
    ]);

    // A gate that belongs to another tenant decides there, not in the caller's own tenant.
    const foreign = createA2aGate({
      iam: f.iam,
      tenantId: f.root.tenant.id,
      message: { action: 'documents:read', resource: { type: 'document', id: 'inbox' } },
    });
    const elsewhere = await foreign(
      new Request('https://agents.acme.test/a2a', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${reader}` },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'message/send',
          params: message('x'),
        }),
      }),
      server.handle,
    );
    expect(elsewhere.status).toBe(403);
  });

  it('carries a hand-off from one agent to the next over A2A', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    await grantDocuments(f, alice.id, ['documents:read']);
    const agent = async (name: string) => {
      const created = await f.iam.api.agents.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name,
      });
      const key = await f.iam.api.credentials.create(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: created.id,
      });
      return { id: created.id, token: key.token };
    };
    const assistant = await agent('Assistant');
    const researcher = await agent('Researcher');
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      scopes: ['documents:read'],
      handoff: { agents: [researcher.id] },
    });
    const acting = await f.iam.api.delegations.assume(
      { token: assistant.token },
      { tenantId: f.tenantId, delegationId: delegation.id },
    );

    // The researcher's A2A server: behind the gate, it takes up the hand-off with its own key and acts for alice.
    let actedAs: { identityId: string; chain: string[] } | undefined;
    const gate = createA2aGate({ iam: f.iam, tenantId: f.tenantId, message: { public: true } });
    const researcherServer = async (request: Request): Promise<Response> => {
      const body = (await request.json()) as { id: number; params: Record<string, unknown> };
      const delegationId = handoffOf(body.params);
      if (!delegationId) return Response.json({ jsonrpc: '2.0', id: body.id, error: { code: -1 } });
      const session = await f.iam.api.delegations.assume(
        { token: researcher.token },
        { tenantId: f.tenantId, delegationId },
      );
      const decision = await f.iam.authorize({
        token: session.token,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'q3' },
      });
      const summary = await f.iam.api.delegations.get(
        { token: session.token },
        { tenantId: f.tenantId, delegationId },
      );
      actedAs = {
        identityId: session.session.identityId,
        chain: [...(summary.chain ?? []).map((item) => item.id), session.session.agentId],
      };
      return Response.json({
        jsonrpc: '2.0',
        id: body.id,
        result: {
          kind: 'task',
          id: 'research-1',
          contextId: 'c1',
          status: { state: decision.allowed ? 'completed' : 'failed' },
        },
      });
    };

    // The assistant hands the work on and says so in the message it sends.
    const handoff = await f.iam.api.delegations.handoff(
      { token: acting.token },
      { tenantId: f.tenantId, agentId: researcher.id, scopes: ['documents:read'] },
    );
    const message = withHandoff(
      {
        kind: 'message',
        role: 'user',
        messageId: 'm1',
        parts: [{ kind: 'text', text: 'Find the Q3 numbers' }],
      },
      handoff.id,
    );
    expect(message.metadata).toEqual({ [handoffMetadataKey]: handoff.id });
    const response = await gate(
      new Request('https://researcher.acme.test/a2a', {
        method: 'POST',
        headers: { 'content-type': 'application/json', authorization: `Bearer ${acting.token}` },
        body: JSON.stringify({
          jsonrpc: '2.0',
          id: 1,
          method: 'message/send',
          params: { message },
        }),
      }),
      researcherServer,
    );
    expect(await response.json()).toMatchObject({ result: { status: { state: 'completed' } } });
    expect(actedAs).toEqual({ identityId: alice.id, chain: [assistant.id, researcher.id] });
  });

  it('asks the person an agent acts for to confirm a held-back skill', async () => {
    const { f, rpc, agentWith, message } = await gateSetup();
    const alice = await f.member('alice');
    await grantDocuments(f, alice.id, ['documents:read', 'documents:write']);
    const agentKey = await agentWith('Assistant', []);
    const agentId = (await f.iam.authenticate({ token: agentKey })).identity.id;
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId,
      scopes: ['documents:*'],
      confirm: ['documents:write'],
    });
    const acting = await f.iam.api.delegations.assume(
      { token: agentKey },
      { tenantId: f.tenantId, delegationId: delegation.id },
    );
    const purge = message('purge', { metadata: { skillId: 'purge' } });
    const first = await rpc(acting.token, 'message/send', purge);
    expect(first.status).toBe(403);
    const body = (await first.json()) as {
      error: { code: number; data: { confirmationId: string } };
    };
    expect(body.error.code).toBe(A2A_CONFIRMATION_REQUESTED);
    await f.iam.api.delegations.decideConfirmation(aliceSession, {
      tenantId: f.tenantId,
      confirmationId: body.error.data.confirmationId,
      approve: true,
    });
    expect((await rpc(acting.token, 'message/send', purge)).status).toBe(200);
  });
});
