import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type GatewayPermit } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const providerKey = 'sk-ant-secret-provider-key-0042';

/** Acme with inference on, one Anthropic provider, a frontier and a small model, and alice limited to small ones. */
async function setup(options: Record<string, unknown> = {}) {
  const f = await organizationFixture({ inference: true, ...options });
  const provider = await f.iam.api.inference.createProvider(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Anthropic',
    kind: 'anthropic',
    apiKey: providerKey,
  });
  await f.iam.api.inference.createModel(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'opus',
    providerId: provider.id,
    upstreamModel: 'claude-opus-5-5',
    tier: 'frontier',
    inputPricePerMTok: 5,
    outputPricePerMTok: 25,
  });
  await f.iam.api.inference.createModel(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'haiku',
    providerId: provider.id,
    upstreamModel: 'claude-haiku-4-5',
    tier: 'small',
    inputPricePerMTok: 1,
    outputPricePerMTok: 5,
  });
  const alice = await f.member('alice');
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Small models',
    document: {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['inference:invoke'],
          resources: ['model/*'],
          conditions: { StringEquals: { 'resource.tier': 'small' } },
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
  const aliceSession = { token: (await f.signIn('alice')).token };
  return { f, provider, alice, aliceSession, role };
}

async function permit(f: OrganizationFixture, token: string, model: string) {
  const outcome = await f.iam.inference.authorize({ token }, { model });
  if ('denied' in outcome) throw new Error(`denied: ${outcome.denied.reason}`);
  return outcome as GatewayPermit;
}

describe('inference catalog and access', () => {
  it('seals provider keys and decides model access with ordinary policies', async () => {
    const { f, provider, aliceSession } = await setup();
    expect(provider).toMatchObject({
      kind: 'anthropic',
      baseUrl: 'https://api.anthropic.com',
      keyHint: '…0042',
    });
    const providers = await f.iam.api.inference.listProviders(f.ownerCredential, {
      tenantId: f.tenantId,
    });
    expect(JSON.stringify(providers)).not.toContain(providerKey);
    const stored = await f.database.get('inferenceProviders', provider.id);
    expect(JSON.stringify(stored)).not.toContain(providerKey);

    const check = (model: string) =>
      f.iam.api.inference.check(aliceSession, { tenantId: f.tenantId, model });
    expect(await check('opus')).toMatchObject({ allowed: false, reason: 'ACCESS_DENIED' });
    const allowed = await check('haiku');
    expect(allowed).toMatchObject({
      allowed: true,
      model: { name: 'haiku', tier: 'small', provider: { name: 'Anthropic', kind: 'anthropic' } },
      ticket: expect.any(String),
    });
    await expect(check('nope')).rejects.toMatchObject({ code: 'NOT_FOUND' });
    expect(
      (await f.iam.api.inference.listMine(aliceSession, { tenantId: f.tenantId })).map(
        (m) => m.name,
      ),
    ).toEqual(['haiku']);
    expect(
      (await f.iam.api.inference.listMine(f.ownerCredential, { tenantId: f.tenantId })).map(
        (m) => m.name,
      ),
    ).toEqual(['haiku', 'opus']);

    // The same decision through the generic authorize API.
    const decision = await f.iam.authorize({
      token: aliceSession.token,
      tenantId: f.tenantId,
      action: 'inference:invoke',
      resource: { type: 'model', id: 'haiku' },
    });
    expect(decision.allowed).toBe(true);

    // Disabling a model stops it for everyone.
    await f.iam.api.inference.updateModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'haiku',
      enabled: false,
    });
    expect(await check('haiku')).toMatchObject({ allowed: false, reason: 'MODEL_DISABLED' });

    // The gateway runtime opens the key server-side only.
    const owner = await permit(f, f.ownerCredential.token, 'opus');
    expect(owner.provider).toMatchObject({ apiKey: providerKey, kind: 'anthropic' });
    expect(owner.upstreamModel).toBe('claude-opus-5-5');
  });

  it('lets only root (or the deployment) point providers at custom URLs, and inherits models', async () => {
    const { f } = await setup();
    await expect(
      f.iam.api.inference.createProvider(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Self hosted',
        kind: 'openai-compatible',
        apiKey: 'local-key-123456',
        baseUrl: 'https://llm.internal.example/v1',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // The platform defines a provider and model once, at the root tenant; organizations inherit them.
    const shared = await f.iam.api.inference.createProvider(f.rootCredential, {
      tenantId: f.root.tenant.id,
      name: 'Platform vLLM',
      kind: 'openai-compatible',
      apiKey: 'platform-key-123456',
      baseUrl: 'https://llm.platform.example/v1',
    });
    await f.iam.api.inference.createModel(f.rootCredential, {
      tenantId: f.root.tenant.id,
      name: 'llama-local',
      providerId: shared.id,
      upstreamModel: 'meta-llama/Llama-4',
      tier: 'small',
    });
    const models = await f.iam.api.inference.listModels(f.ownerCredential, {
      tenantId: f.tenantId,
    });
    expect(models.find((model) => model.name === 'llama-local')).toMatchObject({
      inherited: true,
      provider: { id: shared.id, kind: 'openai-compatible' },
    });
    // An organization may shadow an inherited name with its own model.
    const own = await f.iam.api.inference.listProviders(f.ownerCredential, {
      tenantId: f.tenantId,
    });
    expect(own.map((item) => [item.name, item.inherited])).toEqual([
      ['Anthropic', false],
      ['Platform vLLM', true],
    ]);
  });

  it('re-seals provider keys when the deployment secret rotates', async () => {
    const { f } = await setup();
    const rotated = betterIam({
      database: f.database,
      secret: 'a-brand-new-deployment-secret-of-32-chars',
      previousSecrets: ['organization-fixture-secret-with-32-characters'],
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read', 'documents:write'] },
      inference: true,
    });
    expect((await rotated.rotateSecrets()).resealed).toMatchObject({ inferenceProviders: 1 });
    const outcome = await rotated.inference.authorize(f.ownerCredential, { model: 'opus' });
    expect(outcome).toMatchObject({ provider: { apiKey: providerKey } });
    // Without the previous secret the key is still readable: it was re-sealed with the new one.
    const fresh = betterIam({
      database: f.database,
      secret: 'a-brand-new-deployment-secret-of-32-chars',
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read', 'documents:write'] },
      inference: true,
    });
    expect(await fresh.inference.authorize(f.ownerCredential, { model: 'opus' })).toMatchObject({
      provider: { apiKey: providerKey },
    });
  });

  it('validates its options at construction', async () => {
    const f = await organizationFixture();
    for (const inference of [{ usageRetentionDays: 0 }, { usageRetentionDays: 1.5 }, 'yes'])
      expect(() =>
        betterIam({
          database: f.database,
          secret: 'organization-fixture-secret-with-32-characters',
          baseURL: 'http://localhost:3000',
          inference: inference as never,
        }),
      ).toThrow(expect.objectContaining({ code: 'INVALID_CONFIG' }));
  });

  it('is refused on deployments without the inference option', async () => {
    const f = await organizationFixture();
    await expect(
      f.iam.api.inference.listModels(f.ownerCredential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });
  });
});

describe('budgets and metering', () => {
  it('meters calls, refuses exhausted budgets until the window resets, and reports usage', async () => {
    const { f, alice, aliceSession } = await setup();
    const budget = await f.iam.api.inference.setBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Daily per person',
      subjectType: 'tenant',
      scope: 'each',
      period: 'day',
      maxTokens: 1000,
      alertAtPercent: 80,
    });
    expect(budget).toMatchObject({ subjectId: f.tenantId, scope: 'each', maxTokens: 1000 });
    const used = await permit(f, aliceSession.token, 'haiku');
    expect(used.check.budgets).toEqual([
      expect.objectContaining({ budgetId: budget.id, remainingTokens: 1000 }),
    ]);
    const record = await f.iam.inference.record(used, {
      model: 'haiku',
      inputTokens: 600,
      outputTokens: 300,
    });
    // 600 × $1 + 300 × $5 per million tokens = 2100 micro-dollars.
    expect(record).toMatchObject({ identityId: alice.id, costMicros: 2100, status: 'ok' });

    const check = (estimatedTokens?: number) =>
      f.iam.api.inference.check(aliceSession, {
        tenantId: f.tenantId,
        model: 'haiku',
        ...(estimatedTokens !== undefined ? { estimatedTokens } : {}),
      });
    expect(await check(50)).toMatchObject({ allowed: true });
    const refused = await check(200);
    expect(refused).toMatchObject({
      allowed: false,
      reason: 'BUDGET_EXCEEDED',
      budget: { budgetId: budget.id, usedTokens: 900, remainingTokens: 100 },
    });
    await check(200);
    // The owner has their own share of an `each` budget.
    expect(
      await f.iam.api.inference.check(f.ownerCredential, {
        tenantId: f.tenantId,
        model: 'haiku',
        estimatedTokens: 900,
      }),
    ).toMatchObject({ allowed: true });

    const events = await f.iam.api.audit.list(f.ownerCredential, { tenantId: f.tenantId });
    const actions = events.map((event) => event.action);
    expect(actions.filter((action) => action === 'inference:budget-exceeded')).toHaveLength(1);
    expect(actions).toContain('inference:budget-alert');

    const report = await f.iam.api.inference.usage(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'identity',
    });
    expect(report.rows).toEqual([
      expect.objectContaining({
        key: alice.id,
        label: 'alice@acme.test',
        requests: 1,
        inputTokens: 600,
        outputTokens: 300,
        costMicros: 2100,
      }),
    ]);
    const mine = await f.iam.api.inference.myUsage(aliceSession, { tenantId: f.tenantId });
    expect(mine.totals).toMatchObject({ requests: 1, costUsd: 0.0021 });
    expect(mine.budgets).toEqual([
      expect.objectContaining({ budgetId: budget.id, usedTokens: 900 }),
    ]);

    // The next day starts a fresh window.
    f.advance(86_400_000);
    const fresh = { token: (await f.signIn('alice')).token };
    expect(
      await f.iam.api.inference.check(fresh, {
        tenantId: f.tenantId,
        model: 'haiku',
        estimatedTokens: 900,
      }),
    ).toMatchObject({ allowed: true });
  });

  it('caps an agent across everything it does, including on people’s behalf', async () => {
    const { f, alice, aliceSession, role } = await setup();
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Summarizer',
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
    const cap = await f.iam.api.inference.setBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Summarizer cap',
      subjectType: 'identity',
      subjectId: agent.id,
      period: 'month',
      maxCostUsd: 0.001,
    });
    expect(cap).toMatchObject({ maxCostMicros: 1000, maxCostUsd: 0.001 });
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['inference:invoke'],
    });
    const delegated = await f.iam.api.delegations.assume(
      { token: key.token },
      { tenantId: f.tenantId, delegationId: delegation.id },
    );
    // Acting for alice: alice's access (small models only), metered to alice and to the agent.
    await expect(permit(f, delegated.token, 'opus')).rejects.toThrow('denied: ACCESS_DENIED');
    const onBehalf = await permit(f, delegated.token, 'haiku');
    const record = await f.iam.inference.record(onBehalf, {
      model: 'haiku',
      inputTokens: 500,
      outputTokens: 100,
    });
    expect(record).toMatchObject({
      identityId: alice.id,
      agentId: agent.id,
      delegationId: delegation.id,
      sessionKind: 'delegated',
      costMicros: 1000,
    });
    // The agent's cap is spent, for its own key too; alice herself is not capped.
    expect(await f.iam.inference.authorize({ token: key.token }, { model: 'haiku' })).toMatchObject(
      {
        denied: { reason: 'BUDGET_EXCEEDED', budget: { budgetId: cap.id } },
      },
    );
    expect(await f.iam.inference.authorize(aliceSession, { model: 'haiku' })).not.toHaveProperty(
      'denied',
    );
    // A call without an agent groups under '(none)'.
    await f.iam.inference.record(await permit(f, aliceSession.token, 'haiku'), {
      model: 'haiku',
      inputTokens: 1,
      outputTokens: 0,
    });
    const byAgent = await f.iam.api.inference.usage(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'agent',
    });
    expect(byAgent.rows).toEqual([
      expect.objectContaining({ key: agent.id, label: 'Summarizer', costMicros: 1000 }),
      expect.objectContaining({ key: '(none)', requests: 1 }),
    ]);
  });

  it('rate limits calls per window with maxRequests', async () => {
    const { f, alice, aliceSession } = await setup();
    const limit = await f.iam.api.inference.setBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Three calls an hour',
      subjectType: 'identity',
      subjectId: alice.id,
      period: 'hour',
      maxRequests: 3,
    });
    expect(limit).toMatchObject({
      maxRequests: 3,
      standing: { usedRequests: 0, remainingRequests: 3 },
    });
    for (let call = 0; call < 3; call++)
      await f.iam.inference.record(await permit(f, aliceSession.token, 'haiku'), {
        model: 'haiku',
        inputTokens: 1,
        outputTokens: 1,
      });
    expect(await f.iam.inference.authorize(aliceSession, { model: 'haiku' })).toMatchObject({
      denied: {
        reason: 'BUDGET_EXCEEDED',
        budget: { budgetId: limit.id, usedRequests: 3, remainingRequests: 0 },
      },
    });
    await expect(
      f.iam.api.inference.setBudget(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Empty',
        subjectType: 'tenant',
        period: 'day',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    f.advance(3_600_000);
    const fresh = { token: (await f.signIn('alice')).token };
    expect(await f.iam.inference.authorize(fresh, { model: 'haiku' })).not.toHaveProperty('denied');
  });

  it('lets an external gateway redeem a check ticket once', async () => {
    const { f, alice, aliceSession } = await setup();
    const gateway = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'LLM gateway',
    });
    const recorder = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Inference recorder',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['iam:inference:record'], resources: ['iam/*'] }],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: recorder.id,
      subjectType: 'identity',
      subjectId: gateway.id,
    });
    const gatewayKey = {
      token: (
        await f.iam.api.credentials.create(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: gateway.id,
        })
      ).token,
    };
    const check = await f.iam.api.inference.check(aliceSession, {
      tenantId: f.tenantId,
      model: 'haiku',
    });
    if (!check.allowed || !check.ticket) throw new Error('expected an allowed check');
    // Alice cannot meter her own calls.
    await expect(
      f.iam.api.inference.record(aliceSession, {
        tenantId: f.tenantId,
        ticket: check.ticket,
        inputTokens: 0,
        outputTokens: 0,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await f.iam.api.inference.record(gatewayKey, {
        tenantId: f.tenantId,
        ticket: check.ticket,
        inputTokens: 1000,
        outputTokens: 1000,
      }),
    ).toEqual({ recorded: true, costMicros: 6000 });
    await expect(
      f.iam.api.inference.record(gatewayKey, {
        tenantId: f.tenantId,
        ticket: check.ticket,
        inputTokens: 1,
        outputTokens: 1,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TICKET' });
    const report = await f.iam.api.inference.usage(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(report.totals).toMatchObject({ requests: 1, costMicros: 6000 });
  });
});
