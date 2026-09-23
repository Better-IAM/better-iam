import { afterEach, describe, expect, it } from 'vitest';
import type { TenantConfig } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

async function scenario(options: { inference?: boolean } = {}) {
  const f = await organizationFixture(options.inference === false ? {} : { inference: true });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  await f.member('alice');
  await f.member('bob');
  if (options.inference !== false)
    await f.iam.api.inference.createProvider(owner, {
      tenantId,
      name: 'Anthropic',
      kind: 'anthropic',
      apiKey: 'sk-ant-provider-key-0001',
    });
  return { f, tenantId, owner };
}

const boundary = {
  version: 1 as const,
  statements: [{ effect: 'allow' as const, actions: ['documents:*'], resources: ['document/*'] }],
};

const base: TenantConfig = {
  version: 1,
  groups: [{ name: 'Engineers', members: ['alice@acme.test'] }],
  agents: [
    {
      name: 'Triage',
      sponsor: 'alice@acme.test',
      purpose: 'Sorts incoming tickets',
      model: 'claude-sonnet-5',
      provider: 'anthropic',
      protocols: ['a2a', 'mcp'],
      maxDelegatedSessionSeconds: 1800,
      boundary,
      tokenAudiences: ['https://tickets.example.com'],
    },
    { name: 'Reporter', sponsor: 'bob@acme.test', delegable: false },
  ],
  inferenceModels: [
    {
      name: 'sonnet',
      provider: 'Anthropic',
      upstreamModel: 'claude-sonnet-5',
      tier: 'frontier',
      maxOutputTokens: 8000,
      inputPricePerMTok: 3,
      outputPricePerMTok: 15,
      providerTools: 'policy',
    },
    { name: 'haiku', provider: 'Anthropic', upstreamModel: 'claude-haiku-4-5', enabled: false },
  ],
  inferenceBudgets: [
    {
      name: 'Engineers daily',
      subject: { group: 'Engineers' },
      scope: 'each',
      period: 'day',
      maxCostUsd: 20,
    },
    { name: 'Triage rate', subject: { agent: 'Triage' }, period: 'minute', maxRequests: 30 },
    {
      name: 'Tenant monthly',
      subject: 'tenant',
      period: 'month',
      maxTokens: 10_000_000,
      models: ['sonnet'],
      alertAtPercent: 80,
    },
  ],
};

const ai = (changes: { kind: string; name: string; action: string }[]) =>
  changes
    .filter((change) => ['agent', 'inferenceModel', 'inferenceBudget'].includes(change.kind))
    .map((change) => `${change.kind}:${change.name}:${change.action}`);

describe('configuration as code for AI agents, models and budgets', () => {
  it('applies agents, models and budgets from a document and exports them back unchanged', async () => {
    const s = await scenario();
    const plan = await s.f.iam.api.config.plan(s.owner, { tenantId: s.tenantId, config: base });
    expect(ai(plan.changes)).toEqual([
      'agent:Reporter:create',
      'agent:Triage:create',
      'inferenceModel:haiku:create',
      'inferenceModel:sonnet:create',
      'inferenceBudget:Engineers daily:create',
      'inferenceBudget:Tenant monthly:create',
      'inferenceBudget:Triage rate:create',
    ]);
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: base });

    const agents = await s.f.iam.api.agents.list(s.owner, { tenantId: s.tenantId });
    const triage = agents.find((agent) => agent.name === 'Triage')!;
    expect(triage).toMatchObject({
      standing: 'ok',
      sponsor: { email: 'alice@acme.test' },
      agent: {
        purpose: 'Sorts incoming tickets',
        provider: 'anthropic',
        protocols: ['a2a', 'mcp'],
        maxDelegatedSessionSeconds: 1800,
        boundary,
        tokenAudiences: ['https://tickets.example.com'],
      },
    });
    expect(agents.find((agent) => agent.name === 'Reporter')!.agent.delegable).toBe(false);
    const models = await s.f.iam.api.inference.listModels(s.owner, { tenantId: s.tenantId });
    expect(models.map((model) => [model.name, model.enabled, model.maxOutputTokens])).toEqual([
      ['haiku', false, undefined],
      ['sonnet', true, 8000],
    ]);
    const budgets = await s.f.iam.api.inference.listBudgets(s.owner, { tenantId: s.tenantId });
    expect(
      budgets.map((budget) => [budget.name, budget.subjectType, budget.subjectName, budget.period]),
    ).toEqual([
      ['Engineers daily', 'group', 'Engineers', 'day'],
      ['Tenant monthly', 'tenant', undefined, 'month'],
      ['Triage rate', 'identity', 'Triage', 'minute'],
    ]);

    // The export reads back as the same document: planning it again changes nothing.
    const exported = await s.f.iam.api.config.export(s.owner, { tenantId: s.tenantId });
    expect(exported.agents).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: 'Triage', sponsor: 'alice@acme.test' }),
      ]),
    );
    expect(exported.inferenceBudgets).toEqual(
      expect.arrayContaining([
        { name: 'Triage rate', subject: { agent: 'Triage' }, period: 'minute', maxRequests: 30 },
      ]),
    );
    const again = await s.f.iam.api.config.plan(s.owner, {
      tenantId: s.tenantId,
      config: exported,
    });
    expect(again.changes.filter((change) => change.action !== 'unchanged')).toEqual([]);
  });

  it('updates in place and prunes what the document no longer names', async () => {
    const s = await scenario();
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: base });
    const next: TenantConfig = {
      ...base,
      agents: [{ ...base.agents![0]!, sponsor: 'bob@acme.test', purpose: 'Routes tickets' }],
      inferenceModels: [{ ...base.inferenceModels![0]!, outputPricePerMTok: 12 }],
      inferenceBudgets: [{ ...base.inferenceBudgets![1]!, maxRequests: 10 }],
    };
    const plan = await s.f.iam.api.config.plan(s.owner, {
      tenantId: s.tenantId,
      config: next,
      prune: true,
    });
    expect(
      plan.changes
        .filter((change) => ['agent', 'inferenceModel', 'inferenceBudget'].includes(change.kind))
        .map(
          (change) =>
            `${change.kind}:${change.name}:${change.action}:${change.fields?.join(',') ?? ''}`,
        ),
    ).toEqual([
      'agent:Reporter:delete:',
      'agent:Triage:update:purpose,sponsor',
      'inferenceModel:haiku:delete:',
      'inferenceModel:sonnet:update:outputPricePerMTok',
      'inferenceBudget:Engineers daily:delete:',
      'inferenceBudget:Tenant monthly:delete:',
      'inferenceBudget:Triage rate:update:maxRequests',
    ]);
    await s.f.iam.api.config.apply(s.owner, { tenantId: s.tenantId, config: next, prune: true });
    const agents = await s.f.iam.api.agents.list(s.owner, { tenantId: s.tenantId });
    expect(agents.map((agent) => [agent.name, agent.sponsor?.email, agent.agent.purpose])).toEqual([
      ['Triage', 'bob@acme.test', 'Routes tickets'],
    ]);
    const models = await s.f.iam.api.inference.listModels(s.owner, { tenantId: s.tenantId });
    expect(models.map((model) => [model.name, model.outputPricePerMTok])).toEqual([['sonnet', 12]]);
    const budgets = await s.f.iam.api.inference.listBudgets(s.owner, { tenantId: s.tenantId });
    expect(budgets.map((budget) => [budget.name, budget.maxRequests])).toEqual([
      ['Triage rate', 10],
    ]);
    const audit = await s.f.iam.api.audit.list(s.owner, {
      tenantId: s.tenantId,
      action: 'agent:sponsor-change',
    });
    expect(audit).toHaveLength(1);
  });

  it('refuses documents naming things that do not exist', async () => {
    const s = await scenario();
    const refused = (config: Partial<TenantConfig>) =>
      s.f.iam.api.config.plan(s.owner, { tenantId: s.tenantId, config: { version: 1, ...config } });
    await expect(
      refused({ agents: [{ name: 'Ghost', sponsor: 'nobody@acme.test' }] }),
    ).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringContaining('no person'),
    });
    await expect(
      refused({
        inferenceModels: [{ name: 'x', provider: 'Missing', upstreamModel: 'x-1' }],
      }),
    ).rejects.toMatchObject({ message: expect.stringContaining('no provider named Missing') });
    await expect(
      refused({
        inferenceBudgets: [
          { name: 'B', subject: { agent: 'Nobody' }, period: 'day', maxRequests: 1 },
        ],
      }),
    ).rejects.toMatchObject({ message: expect.stringContaining('no agent Nobody') });
    await expect(
      refused({ inferenceBudgets: [{ name: 'B', subject: 'tenant', period: 'day' } as never] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      refused({
        agents: [
          { name: 'Twin', sponsor: 'alice@acme.test' },
          { name: 'twin', sponsor: 'alice@acme.test' },
        ],
      }),
    ).rejects.toMatchObject({ message: expect.stringContaining('Duplicate agent') });

    const plain = await scenario({ inference: false });
    await expect(
      plain.f.iam.api.config.plan(plain.owner, {
        tenantId: plain.tenantId,
        config: {
          version: 1,
          inferenceModels: [{ name: 'x', provider: 'A', upstreamModel: 'x' }],
        },
      }),
    ).rejects.toMatchObject({ message: expect.stringContaining('inference option') });
  });
});
