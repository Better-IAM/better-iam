import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDocument } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const doc = (actions: string[], resources = ['document/*']): PolicyDocument => ({
  version: 1,
  statements: [{ effect: 'allow', actions, resources }],
});

/** Grants `actions` on documents to an identity through a fresh role. */
async function grant(f: OrganizationFixture, subjectId: string, actions: string[], name: string) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name,
    document: doc(actions),
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId,
  });
}

async function agentWithKey(f: OrganizationFixture, input: Record<string, unknown> = {}) {
  const agent = await f.iam.api.agents.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Research assistant',
    model: 'claude-opus-5-5',
    provider: 'Anthropic',
    purpose: 'Summarizes documents',
    ...input,
  });
  const key = await f.iam.api.credentials.create(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId: agent.id,
    name: 'runtime',
  });
  return { agent, token: key.token };
}

const read = (f: OrganizationFixture, token: string, id: string, action = 'documents:read') =>
  f.iam
    .authorize({ token, tenantId: f.tenantId, action, resource: { type: 'document', id } })
    .then((decision) => decision.allowed);

describe('agents as accounts', () => {
  it('registers an agent with a sponsor and a profile', async () => {
    const f = await organizationFixture();
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Triage bot',
      model: 'claude-sonnet-5',
      provider: 'Anthropic',
      protocols: ['MCP', 'a2a', 'mcp'],
      url: 'https://agents.acme.test/triage',
    });
    expect(agent).toMatchObject({
      name: 'Triage bot',
      status: 'active',
      standing: 'ok',
      agent: {
        sponsorId: f.ownerId,
        model: 'claude-sonnet-5',
        provider: 'anthropic',
        protocols: ['a2a', 'mcp'],
      },
      sponsor: { id: f.ownerId, email: 'owner@acme.test' },
    });
    const listed = await f.iam.api.agents.list(f.ownerCredential, { tenantId: f.tenantId });
    expect(listed.map((item) => item.id)).toEqual([agent.id]);
    const identity = (
      await f.iam.api.identities.list(f.ownerCredential, { tenantId: f.tenantId })
    ).find((item) => item.id === agent.id);
    expect(identity?.kind).toBe('agent');

    await expect(
      f.iam.api.agents.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Bad',
        model: 'has spaces',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.agents.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'Orphan',
        sponsorId: agent.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_SPONSOR' });
  });

  it('acts through its own keys, bounded by its ceiling, and exposes agent context keys', async () => {
    const f = await organizationFixture();
    const { agent, token } = await agentWithKey(f, {
      boundary: doc(['documents:read']),
    });
    await grant(f, agent.id, ['documents:read', 'documents:write'], 'Agent writer');
    expect(await read(f, token, 'a')).toBe(true);
    // The boundary keeps the agent from writing even though its role allows it.
    expect(await read(f, token, 'a', 'documents:write')).toBe(false);

    // Policies can single out agents and their model.
    const guarded = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Only opus agents',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/secret'],
            conditions: {
              StringEquals: {
                'principal.kind': 'agent',
                'principal.agentModel': 'claude-opus-5-5',
                'principal.agentSponsorId': f.ownerId,
              },
              Bool: { 'principal.delegated': false },
            },
          },
        ],
      },
    });
    const other = await agentWithKey(f, { name: 'Other', model: 'small-model' });
    for (const subject of [agent.id, other.agent.id])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: guarded.id,
        subjectType: 'identity',
        subjectId: subject,
      });
    expect(await read(f, token, 'secret')).toBe(true);
    expect(await read(f, other.token, 'secret')).toBe(false);

    const caller = await f.iam.api.sts.getCallerIdentity({ token });
    expect(caller).toMatchObject({ identityKind: 'agent', sessionKind: 'api-key' });

    // Tightening the boundary applies at once.
    await f.iam.api.agents.update(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
      boundary: doc(['documents:write'], ['document/none']),
    });
    expect(await read(f, token, 'a')).toBe(false);
    await f.iam.api.agents.update(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
      boundary: null,
    });
    expect(await read(f, token, 'a', 'documents:write')).toBe(true);
  });

  it('stops working while its sponsor is not an active person', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Alice’s agent',
      sponsorId: alice.id,
    });
    const { token } = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    await grant(f, agent.id, ['documents:read'], 'Reader');
    expect(await read(f, token, 'a')).toBe(true);

    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      status: 'disabled',
    });
    await expect(read(f, token, 'a')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(
      (await f.iam.api.agents.get(f.ownerCredential, { tenantId: f.tenantId, agentId: agent.id }))
        .standing,
    ).toBe('sponsor-inactive');
    // Keys cannot be issued meanwhile either.
    await expect(
      f.iam.api.credentials.create(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: agent.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_IDENTITY' });

    // Handing the agent to another sponsor brings it back.
    await f.iam.api.agents.update(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
      sponsorId: f.ownerId,
    });
    expect(await read(f, token, 'a')).toBe(true);
  });

  it('stops every agent of the organization at once in an emergency', async () => {
    const f = await organizationFixture();
    const first = await agentWithKey(f, { name: 'One' });
    const second = await agentWithKey(f, { name: 'Two' });
    const other = await agentWithKey(f, { name: 'Three', provider: 'openai', model: 'gpt-x' });
    await f.member('alice');
    const alice = { token: (await f.signIn('alice')).token };
    await expect(
      f.iam.api.agents.suspendAll(alice, { tenantId: f.tenantId, reason: 'Incident 42' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const result = await f.iam.api.agents.suspendAll(f.ownerCredential, {
      tenantId: f.tenantId,
      reason: 'Incident 42',
      provider: 'Anthropic',
    });
    expect(result.suspended).toBe(2);
    expect(result.agentIds.sort()).toEqual([first.agent.id, second.agent.id].sort());
    for (const { token } of [first, second])
      await expect(f.iam.authenticate({ token })).rejects.toMatchObject({ status: 401 });
    await expect(f.iam.authenticate({ token: other.token })).resolves.toBeDefined();
    const audit = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'agent:suspend-all',
    });
    expect(audit[0]!.metadata).toMatchObject({ reason: 'Incident 42', suspended: 2 });
    // Already suspended agents are left as they are; the rest stop now.
    const rest = await f.iam.api.agents.suspendAll(f.ownerCredential, {
      tenantId: f.tenantId,
      reason: 'Incident 42, all of them',
    });
    expect(rest.agentIds).toEqual([other.agent.id]);
  });

  it('gives the sponsor a kill switch', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    await f.member('bob');
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Alice’s agent',
      sponsorId: alice.id,
    });
    const { token } = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    await grant(f, agent.id, ['documents:read'], 'Reader');
    const aliceSession = { token: (await f.signIn('alice')).token };
    const bobSession = { token: (await f.signIn('bob')).token };

    expect(
      (await f.iam.api.agents.listMine(aliceSession, { tenantId: f.tenantId })).map(
        (item) => item.id,
      ),
    ).toEqual([agent.id]);
    expect(await f.iam.api.agents.listMine(bobSession, { tenantId: f.tenantId })).toEqual([]);

    // Bob is neither the sponsor nor an administrator.
    await expect(
      f.iam.api.agents.suspend(bobSession, { tenantId: f.tenantId, agentId: agent.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const suspended = await f.iam.api.agents.suspend(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      reason: 'Looping on the wiki',
    });
    expect(suspended).toMatchObject({ status: 'disabled', standing: 'suspended' });
    expect(suspended.agent.suspended).toMatchObject({
      by: alice.id,
      reason: 'Looping on the wiki',
    });
    await expect(read(f, token, 'a')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });

    const resumed = await f.iam.api.agents.resume(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
    });
    expect(resumed.standing).toBe('ok');
    expect(resumed.agent.suspended).toBeUndefined();
    // The key was kept.
    expect(await read(f, token, 'a')).toBe(true);

    // An administrator's suspension is theirs to lift.
    await f.iam.api.agents.suspend(f.ownerCredential, { tenantId: f.tenantId, agentId: agent.id });
    await expect(
      f.iam.api.agents.resume(aliceSession, { tenantId: f.tenantId, agentId: agent.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await f.iam.api.agents.resume(f.ownerCredential, { tenantId: f.tenantId, agentId: agent.id });
    expect(await read(f, token, 'a')).toBe(true);

    const events = await f.iam.api.audit.list(f.ownerCredential, { tenantId: f.tenantId });
    expect(events.map((event) => event.action)).toEqual(
      expect.arrayContaining(['agent:create', 'agent:suspend', 'agent:resume']),
    );
  });

  it('hands a leaver’s agents to their successor and ends their delegations', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Alice’s agent',
      sponsorId: alice.id,
    });
    const other = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Shared agent',
    });
    const { token } = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    await grant(f, agent.id, ['documents:read'], 'Reader');
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: other.id,
      scopes: ['documents:read'],
    });

    const result = await f.iam.api.identities.offboard(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      reason: 'Left the company',
      successorId: bob.id,
    });
    expect(result).toMatchObject({ agentsReassigned: 1, delegationsRevoked: 1 });
    const moved = await f.iam.api.agents.get(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
    });
    expect(moved).toMatchObject({ standing: 'ok', agent: { sponsorId: bob.id } });
    expect(await read(f, token, 'a')).toBe(true);
    expect(
      (
        await f.iam.api.delegations.get(f.ownerCredential, {
          tenantId: f.tenantId,
          delegationId: delegation.id,
        })
      ).status,
    ).toBe('revoked');

    // Without a successor the agent keeps a disabled sponsor and is refused until reassigned.
    const bobSession = { token: (await f.signIn('bob')).token };
    expect((await f.iam.api.agents.listMine(bobSession, { tenantId: f.tenantId })).length).toBe(1);
    const again = await f.iam.api.identities.offboard(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bob.id,
      reason: 'Left too',
    });
    expect(again).toMatchObject({ agentsUnsponsored: 1 });
    await expect(read(f, token, 'a')).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
  });

  it('reports risky agents and delegations in access analysis', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const orphan = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Orphaned',
      sponsorId: bob.id,
    });
    const admin = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Overpowered',
      boundary: doc(['documents:read']),
    });
    const open = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Open',
    });
    const everything = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Everything',
      document: { version: 1, statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }] },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: everything.id,
      subjectType: 'identity',
      subjectId: admin.id,
    });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: open.id,
      scopes: ['*'],
      expiresInSeconds: 365 * 86_400,
    });
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bob.id,
      status: 'disabled',
    });
    f.advance(91 * 86_400_000);
    const { findings } = await f.iam.api.analysis.findings(await f.ownerSignIn(), {
      tenantId: f.tenantId,
    });
    const of = (kind: string) =>
      findings.filter((finding) => finding.kind === kind).map((finding) => finding.subject.id);
    expect(of('agent-without-sponsor')).toEqual([orphan.id]);
    expect(of('agent-admin')).toEqual([admin.id]);
    expect(of('unbounded-agent')).toEqual([open.id]);
    expect(of('broad-delegation')).toEqual([delegation.id]);
    expect(of('unused-delegation')).toEqual([delegation.id]);
    expect(findings.find((finding) => finding.kind === 'broad-delegation')?.subject.name).toBe(
      `alice@acme.test → Open`,
    );
    expect(alice.id).toBeDefined();
  });

  it('reports agents refused over and over, and delegations handed on to any agent', async () => {
    const f = await organizationFixture();
    await f.member('alice');
    const looping = await agentWithKey(f, { name: 'Looping' });
    for (let index = 0; index < 20; index++)
      await f.iam.authorize({
        token: looping.token,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: `d${index}` },
      });
    const handy = await agentWithKey(f, { name: 'Handy' });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: handy.agent.id,
      scopes: ['documents:read'],
      handoff: { depth: 2 },
    });
    const { findings } = await f.iam.api.analysis.findings(await f.ownerSignIn(), {
      tenantId: f.tenantId,
    });
    const denials = findings.filter((finding) => finding.kind === 'agent-denials');
    expect(denials.map((finding) => finding.subject.id)).toEqual([looping.agent.id]);
    expect(denials[0]!.title).toContain('refused 20 times');
    const open = findings.filter((finding) => finding.kind === 'open-handoff');
    expect(open.map((finding) => [finding.subject.id, finding.severity])).toEqual([
      [delegation.id, 'medium'],
    ]);
  });

  it('enforces the tenant agent limit', async () => {
    const f = await organizationFixture();
    await f.iam.api.tenants.setLimits(f.rootCredential, {
      tenantId: f.tenantId,
      limits: { agents: 1 },
    });
    await f.iam.api.agents.create(f.ownerCredential, { tenantId: f.tenantId, name: 'One' });
    await expect(
      f.iam.api.agents.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Two' }),
    ).rejects.toMatchObject({ code: 'LIMIT_EXCEEDED' });
  });
});
