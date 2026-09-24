import { afterEach, describe, expect, it } from 'vitest';
import type { GatewayPermit } from '@better-iam/server';
import { storedReference } from '../packages/server/src/inference-gateway.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

/**
 * Inference: an organization cannot run calls on the platform's provider key at prices it picks, lift a cap the
 * platform set, or send a provider's sealed key to a new base URL; base URLs organizations choose go through the SSRF
 * guard. Configuration sync asks for the same fresh sign-in as the direct API.
 */

afterEach(closeFixtures);

async function platform(options: { allowCustomBaseUrls?: boolean } = {}) {
  const f = await organizationFixture({ inference: { ...options } });
  const provider = await f.iam.api.inference.createProvider(f.rootCredential, {
    tenantId: f.root.tenant.id,
    name: 'Platform Anthropic',
    kind: 'anthropic',
    apiKey: 'sk-ant-platform-owned-key-9999',
  });
  return { f, provider };
}

describe('inference administration', () => {
  it('keeps models on a parent organization’s provider in the platform’s hands', async () => {
    const { f, provider } = await platform();
    await expect(
      f.iam.api.inference.createModel(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'opus',
        providerId: provider.id,
        upstreamModel: 'claude-opus-5-5',
        inputPricePerMTok: 0,
        outputPricePerMTok: 0,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // The platform may set one up for the organization; the organization may turn it off, not reprice it.
    await f.iam.api.inference.createModel(f.rootCredential, {
      tenantId: f.tenantId,
      name: 'opus',
      providerId: provider.id,
      upstreamModel: 'claude-opus-5-5',
      inputPricePerMTok: 5,
      outputPricePerMTok: 25,
    });
    await expect(
      f.iam.api.inference.updateModel(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'opus',
        inputPricePerMTok: 0,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.inference.updateModel(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'opus',
        enabled: false,
      }),
    ).resolves.toMatchObject({ enabled: false });
  });

  it('lets only the platform change or remove a budget it set on an organization', async () => {
    const { f } = await platform();
    const cap = await f.iam.api.inference.setBudget(f.rootCredential, {
      tenantId: f.tenantId,
      name: 'Platform cap',
      subjectType: 'tenant',
      period: 'month',
      maxCostUsd: 1,
    });
    await expect(
      f.iam.api.inference.deleteBudget(f.ownerCredential, {
        tenantId: f.tenantId,
        budgetId: cap.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.inference.setBudget(f.ownerCredential, {
        tenantId: f.tenantId,
        budgetId: cap.id,
        name: 'Platform cap',
        subjectType: 'tenant',
        period: 'month',
        maxCostUsd: 1_000_000,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // The organization's own budgets stay its own.
    const own = await f.iam.api.inference.setBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team cap',
      subjectType: 'tenant',
      period: 'day',
      maxTokens: 1000,
    });
    await expect(
      f.iam.api.inference.deleteBudget(f.ownerCredential, { tenantId: f.tenantId, budgetId: own.id }),
    ).resolves.toMatchObject({ deleted: true });
    await expect(
      f.iam.api.inference.deleteBudget(f.rootCredential, { tenantId: f.tenantId, budgetId: cap.id }),
    ).resolves.toMatchObject({ deleted: true });
  });

  it('needs the provider key again to move a provider, and guards base URLs an organization chose', async () => {
    const { f } = await platform({ allowCustomBaseUrls: true });
    const provider = await f.iam.api.inference.createProvider(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Self-hosted',
      kind: 'openai-compatible',
      apiKey: 'org-secret-key-1234',
      baseUrl: 'https://llm.acme.example',
    });
    await expect(
      f.iam.api.inference.updateProvider(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: provider.id,
        baseUrl: 'https://collector.evil.example',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.inference.updateProvider(f.ownerCredential, {
        tenantId: f.tenantId,
        providerId: provider.id,
        baseUrl: 'https://llm2.acme.example',
        apiKey: 'org-secret-key-5678',
      }),
    ).resolves.toMatchObject({ baseUrl: 'https://llm2.acme.example' });
    await f.iam.api.inference.createModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'local',
      providerId: provider.id,
      upstreamModel: 'llama',
    });
    await f.iam.api.policies.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Models',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['inference:invoke'], resources: ['*'] }],
      },
    });
    const permit = (await f.iam.inference.authorize(f.ownerCredential, {
      model: 'local',
    })) as GatewayPermit;
    expect(permit.provider.guard).toMatchObject({ anyPort: true, allowPrivateNetworks: false });
  });
});

describe('stored provider objects', () => {
  it('finds references in every shape the provider accepts them', () => {
    for (const body of [
      { tools: [{ type: 'code_interpreter', container: { type: 'auto', file_ids: ['file-x'] } }] },
      { tools: [{ type: 'file_search', vector_store_ids: ['vs_other_tenant'] }] },
      { tools: [{ type: 'image_generation', input_image_mask: { file_id: 'file-mask' } }] },
      {
        input: [
          {
            type: 'function_call_output',
            call_id: 'c',
            output: [{ type: 'input_file', file_id: 'file-y' }],
          },
        ],
      },
      {
        messages: [
          {
            role: 'user',
            content: [
              {
                type: 'tool_result',
                tool_use_id: 't',
                content: [{ type: 'document', source: { type: 'file', file_id: 'f' } }],
              },
            ],
          },
        ],
      },
      { input: [{ type: 'item_reference', id: 'msg_1' }] },
    ])
      expect(storedReference('/v1/responses', body)).toBeDefined();
    expect(
      storedReference('/v1/responses', {
        model: 'gpt',
        input: [{ role: 'user', content: [{ type: 'input_text', text: 'file_id: nothing here' }] }],
        tools: [
          {
            type: 'function',
            name: 'fetch',
            parameters: { type: 'object', properties: { file_id: { type: 'string' } } },
          },
        ],
      }),
    ).toBeUndefined();
  });
});

describe('inference budgets', () => {
  it('counts what agents do for people against a group budget on the agents', async () => {
    const f = await organizationFixture({ inference: true });
    const { tenantId, ownerCredential: owner } = f;
    const provider = await f.iam.api.inference.createProvider(owner, {
      tenantId,
      name: 'Anthropic',
      kind: 'anthropic',
      apiKey: 'sk-ant-org-key-000000',
    });
    await f.iam.api.inference.createModel(owner, {
      tenantId,
      name: 'haiku',
      providerId: provider.id,
      upstreamModel: 'claude-haiku-4-5',
    });
    const invoke = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Models',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['inference:invoke'], resources: ['model/*'] }],
      },
    });
    const alice = await f.member('alice');
    const agent = await f.iam.api.agents.create(owner, { tenantId, name: 'Looper' });
    for (const subjectId of [alice.id, agent.id])
      await f.iam.api.bindings.create(owner, {
        tenantId,
        roleId: invoke.id,
        subjectType: 'identity',
        subjectId,
      });
    const bots = await f.iam.api.groups.create(owner, { tenantId, name: 'Bots' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: bots.id, identityId: agent.id });
    await f.iam.api.inference.setBudget(owner, {
      tenantId,
      name: 'Bots: 2 calls a day',
      subjectType: 'group',
      subjectId: bots.id,
      period: 'day',
      maxRequests: 2,
    });
    const key = await f.iam.api.credentials.create(owner, { tenantId, identityId: agent.id });
    const own = (await f.iam.inference.authorize(
      { token: key.token },
      { model: 'haiku' },
    )) as GatewayPermit;
    await f.iam.inference.record(own, { model: 'haiku', inputTokens: 10, outputTokens: 10 });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId,
      agentId: agent.id,
      scopes: ['inference:invoke'],
    });
    const delegated = await f.iam.api.delegations.assume(
      { token: key.token },
      { tenantId, delegationId: delegation.id },
    );
    const forAlice = (await f.iam.inference.authorize(
      { token: delegated.token },
      { model: 'haiku' },
    )) as GatewayPermit;
    await f.iam.inference.record(forAlice, { model: 'haiku', inputTokens: 10, outputTokens: 10 });
    // Two calls used the group's allowance, whichever credential made them.
    for (const token of [delegated.token, key.token])
      expect(await f.iam.inference.authorize({ token }, { model: 'haiku' })).toMatchObject({
        denied: { reason: 'BUDGET_EXCEEDED' },
      });
  });
});

describe('configuration sync', () => {
  it('asks for a fresh sign-in to change the access policy, and audits it', async () => {
    const f = await organizationFixture();
    const stale = await f.ownerSignIn();
    f.advance(10 * 60_000);
    const config = { version: 1, accessPolicy: { requireJustification: true } };
    await expect(
      f.iam.api.config.apply(stale, { tenantId: f.tenantId, config }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    const fresh = await f.ownerSignIn();
    await f.iam.api.config.apply(fresh, { tenantId: f.tenantId, config });
    const events = await f.database.find('audit', {
      tenantId: f.tenantId,
      action: 'tenant:access-policy',
    });
    expect(events).toHaveLength(1);
  });
});
