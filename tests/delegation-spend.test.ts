import { afterEach, describe, expect, it } from 'vitest';
import type { GatewayPermit } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/** Acme with inference on, one small model alice may use, and two agents with keys. */
async function setup() {
  const f = await organizationFixture({ inference: true });
  const provider = await f.iam.api.inference.createProvider(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Anthropic',
    kind: 'anthropic',
    apiKey: 'sk-ant-secret-provider-key-0042',
  });
  await f.iam.api.inference.createModel(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'haiku',
    providerId: provider.id,
    upstreamModel: 'claude-haiku-4-5',
    inputPricePerMTok: 1,
    outputPricePerMTok: 5,
  });
  const alice = await f.member('alice');
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Models',
    document: {
      version: 1,
      statements: [{ effect: 'allow', actions: ['inference:invoke'], resources: ['model/*'] }],
    },
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const agent = async (name: string) => {
    const created = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: created.id,
    });
    return { id: created.id, key: { token: key.token } };
  };
  const assistant = await agent('Assistant');
  const helper = await agent('Helper');
  const aliceSession = { token: (await f.signIn('alice')).token };
  return { f, alice, assistant, helper, aliceSession };
}

async function call(f: OrganizationFixture, token: string) {
  const outcome = await f.iam.inference.authorize({ token }, { model: 'haiku' });
  if ('denied' in outcome) return outcome.denied;
  await f.iam.inference.record(outcome as GatewayPermit, {
    model: 'haiku',
    inputTokens: 1000,
    outputTokens: 1000,
  });
  return 'ok' as const;
}

describe('delegation spending caps', () => {
  it('caps what an agent spends on models on a person’s behalf, across hand-offs', async () => {
    const { f, assistant, helper, aliceSession } = await setup();
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      scopes: ['inference:invoke'],
      spend: { period: 'day', maxRequests: 3, maxCostUsd: 1 },
      handoff: {},
    });
    expect(delegation.spend).toMatchObject({
      period: 'day',
      maxRequests: 3,
      maxCostUsd: 1,
      usedRequests: 0,
      usedCostUsd: 0,
    });
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(await call(f, acting.token)).toBe('ok');
    expect(await call(f, acting.token)).toBe('ok');

    // Work handed on counts against the same cap.
    const handoff = await f.iam.api.delegations.handoff(
      { token: acting.token },
      { tenantId: f.tenantId, agentId: helper.id, scopes: ['inference:invoke'] },
    );
    const helping = await f.iam.api.delegations.assume(helper.key, {
      tenantId: f.tenantId,
      delegationId: handoff.id,
    });
    expect(await call(f, helping.token)).toBe('ok');
    expect(await call(f, helping.token)).toMatchObject({
      reason: 'BUDGET_EXCEEDED',
      budget: { name: 'Delegation spending limit', usedRequests: 3 },
    });
    expect(await call(f, acting.token)).toMatchObject({ reason: 'BUDGET_EXCEEDED' });

    // Alice sees what her delegation used: 3 calls of 1000 input and 1000 output tokens each ($0.006 each).
    const seen = await f.iam.api.delegations.get(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(seen.spend).toMatchObject({ usedRequests: 3, usedTokens: 6000, usedCostUsd: 0.018 });
    const exceeded = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'inference:budget-exceeded',
    });
    expect(exceeded[0]).toMatchObject({ resourceId: `delegation:${delegation.id}` });

    // A new day, a new allowance (in a new session: the old one has ended); alice's own calls were never capped.
    f.advance(86_400_000);
    const tomorrow = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(await call(f, tomorrow.token)).toBe('ok');
    expect(await call(f, aliceSession.token)).toBe('ok');
  });

  it('meters gateway tickets after the session ends, and counts hand-offs against the handing agent’s budget', async () => {
    const { f, assistant, helper, aliceSession } = await setup();
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      scopes: ['inference:invoke'],
      spend: { period: 'day', maxRequests: 1 },
      handoff: {},
    });
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
      durationSeconds: 60,
    });
    const check = await f.iam.api.inference.check(
      { token: acting.token },
      { tenantId: f.tenantId, model: 'haiku' },
    );
    expect(check.ticket).toEqual(expect.any(String));
    // The session ends before the external gateway reports the call; it is metered against the cap all the same.
    f.advance(120_000);
    const gateway = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Gateway',
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Recorder',
      permissions: ['iam:inference:record'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: gateway.id,
    });
    const gatewayKey = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: gateway.id,
    });
    await f.iam.api.inference.record(
      { token: gatewayKey.token },
      { tenantId: f.tenantId, ticket: check.ticket!, inputTokens: 10, outputTokens: 10 },
    );
    const seen = await f.iam.api.delegations.get(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(seen.spend).toMatchObject({ usedRequests: 1 });

    // An identity budget on the assistant counts what it hands on to the helper, too.
    await f.iam.api.inference.setBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Assistant',
      subjectType: 'identity',
      subjectId: assistant.id,
      period: 'day',
      maxRequests: 1,
    });
    await f.iam.api.delegations.revoke(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    const fresh = await f.iam.api.delegations.grant(
      { token: (await f.signIn('alice')).token },
      { tenantId: f.tenantId, agentId: assistant.id, scopes: ['inference:invoke'], handoff: {} },
    );
    const again = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: fresh.id,
    });
    const handoff = await f.iam.api.delegations.handoff(
      { token: again.token },
      { tenantId: f.tenantId, agentId: helper.id, scopes: ['inference:invoke'] },
    );
    const helping = await f.iam.api.delegations.assume(helper.key, {
      tenantId: f.tenantId,
      delegationId: handoff.id,
    });
    expect(await call(f, helping.token)).toBe('ok');
    expect(await call(f, helping.token)).toMatchObject({
      reason: 'BUDGET_EXCEEDED',
      budget: { name: 'Assistant' },
    });
  });

  it('is set, changed or removed by the person, and validated', async () => {
    const { f, assistant, helper, aliceSession } = await setup();
    const request = await f.iam.api.delegations.request(assistant.key, {
      tenantId: f.tenantId,
      subjectEmail: 'alice@acme.test',
      scopes: ['inference:invoke'],
      reason: 'Summarize your inbox',
      spend: { period: 'month', maxCostUsd: 50 },
    });
    expect(request.spend).toMatchObject({ period: 'month', maxCostUsd: 50 });
    const approved = await f.iam.api.delegations.approve(aliceSession, {
      tenantId: f.tenantId,
      delegationId: request.id,
      spend: { period: 'minute', maxRequests: 1 },
    });
    expect(approved.spend).toMatchObject({ period: 'minute', maxRequests: 1 });
    expect(approved.spend).not.toHaveProperty('maxCostUsd');
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: request.id,
    });
    expect(await call(f, acting.token)).toBe('ok');
    expect(await call(f, acting.token)).toMatchObject({ reason: 'BUDGET_EXCEEDED' });
    f.advance(60_000);
    expect(await call(f, acting.token)).toBe('ok');

    for (const spend of [
      { period: 'week', maxRequests: 1 },
      { period: 'day' },
      { period: 'day', maxCostUsd: 0 },
      { period: 'day', maxCostUsd: 0.0000001 },
      { period: 'day', maxTokens: 1.5 },
    ])
      await expect(
        f.iam.api.delegations.grant(aliceSession, {
          tenantId: f.tenantId,
          agentId: helper.id,
          scopes: ['inference:invoke'],
          spend: spend as never,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
