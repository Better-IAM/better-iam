import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDocument } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Acme with alice (read and write on every document, but never document/secret for the research agent) and three
 * agents with keys and no grants of their own: an assistant alice delegates to, and a researcher and a writer the
 * assistant may hand work on to.
 */
async function setup(options: { assistantScopes?: string[] } = {}) {
  const f = await organizationFixture();
  const alice = await f.member('alice');
  const agent = async (name: string) => {
    const created = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: created.id,
      ...(name === 'Assistant' && options.assistantScopes
        ? { scopes: options.assistantScopes }
        : {}),
    });
    return { id: created.id, key: { token: key.token } };
  };
  const assistant = await agent('Assistant');
  const researcher = await agent('Researcher');
  const writer = await agent('Writer');
  const document: PolicyDocument = {
    version: 1,
    statements: [
      {
        effect: 'allow',
        actions: ['documents:read', 'documents:write'],
        resources: ['document/*'],
      },
      {
        effect: 'deny',
        actions: ['documents:read'],
        resources: ['document/secret'],
        conditions: { ArrayContains: { 'principal.delegationChain': [researcher.id] } },
      },
    ],
  };
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Editor',
    document,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const aliceSession = { token: (await f.signIn('alice')).token };
  return { f, alice, assistant, researcher, writer, aliceSession };
}

const allowed = (f: OrganizationFixture, token: string, action: string, id = 'a') =>
  f.iam
    .authorize({ token, tenantId: f.tenantId, action, resource: { type: 'document', id } })
    .then((decision) => decision.allowed);

async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(Error);
  return error as Error & { code: string; status: number };
}

describe('delegation hand-offs', () => {
  it('lets an agent acting for a person hand part of the work on to another agent', async () => {
    const { f, alice, assistant, researcher, aliceSession } = await setup();
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      scopes: ['documents:*'],
      handoff: { agents: [researcher.id] },
    });
    expect(delegation.handoff).toEqual({ agents: [researcher.id], depth: 1 });
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });

    const handoff = await f.iam.api.delegations.handoff(
      { token: acting.token },
      {
        tenantId: f.tenantId,
        agentId: researcher.id,
        scopes: ['documents:read'],
        reason: 'Find the sources for the report',
      },
    );
    expect(handoff).toMatchObject({
      status: 'active',
      requestedBy: 'handoff',
      parentId: delegation.id,
      chain: [{ id: assistant.id, name: 'Assistant' }],
      agent: { id: researcher.id },
      subject: { id: alice.id },
      scopes: ['documents:read'],
    });
    expect(handoff).not.toHaveProperty('handoff');
    expect(handoff.expiresAt).toBe(f.now() + 3600_000);

    // The researcher opens its own sessions for alice with its own key, within the hand-off.
    const research = await f.iam.api.delegations.assume(researcher.key, {
      tenantId: f.tenantId,
      delegationId: handoff.id,
    });
    expect(research.session).toMatchObject({ identityId: alice.id, agentId: researcher.id });
    expect(await allowed(f, research.token, 'documents:read')).toBe(true);
    expect(await allowed(f, research.token, 'documents:write')).toBe(false);
    // Policies see the whole chain: alice keeps document/secret away from anything the researcher does.
    expect(await allowed(f, research.token, 'documents:read', 'secret')).toBe(false);
    expect(await allowed(f, acting.token, 'documents:read', 'secret')).toBe(true);

    // Alice sees the hand-off; the delegation's activity includes the researcher's work.
    const mine = await f.iam.api.delegations.listMine(aliceSession, { tenantId: f.tenantId });
    expect(mine.map((item) => item.id).sort()).toEqual([delegation.id, handoff.id].sort());
    const activity = await f.iam.api.delegations.activity(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(activity.map((event) => event.action)).toEqual(
      expect.arrayContaining(['delegation:handoff', 'documents:read']),
    );
    expect(activity.find((event) => event.sessionContext?.agentId === researcher.id)).toBeDefined();

    // The researcher's own direct delegations are unaffected by the hand-off.
    await expect(
      f.iam.api.delegations.grant(aliceSession, {
        tenantId: f.tenantId,
        agentId: researcher.id,
        scopes: ['documents:read'],
      }),
    ).resolves.toMatchObject({ status: 'active' });

    // Revoking alice's delegation ends the hand-off and its sessions with it.
    const revoked = await f.iam.api.delegations.revoke(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(revoked.status).toBe('revoked');
    expect(
      (
        await f.iam.api.delegations.get(aliceSession, {
          tenantId: f.tenantId,
          delegationId: handoff.id,
        })
      ).status,
    ).toBe('revoked');
    expect(await refusal(f.iam.authenticate({ token: research.token }))).toMatchObject({
      status: 401,
    });
    const audit = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'delegation:revoke',
    });
    expect(audit[0]!.metadata).toMatchObject({ handoffsRevoked: 1 });
  });

  it('only hands on what the person allowed, to whom they allowed, as deep as they allowed', async () => {
    const { f, assistant, researcher, writer, aliceSession } = await setup();
    const plain = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      scopes: ['documents:*'],
    });
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: plain.id,
    });
    const handOn = (token: string, agentId: string, scopes = ['documents:read']) =>
      f.iam.api.delegations.handoff({ token }, { tenantId: f.tenantId, agentId, scopes });
    expect(await refusal(handOn(acting.token, researcher.id))).toMatchObject({
      code: 'DELEGATION_NOT_ALLOWED',
    });
    // Only delegated sessions hand work on.
    expect(await refusal(handOn(assistant.key.token, researcher.id))).toMatchObject({
      code: 'ACCESS_DENIED',
    });
    expect(await refusal(handOn(aliceSession.token, researcher.id))).toMatchObject({
      code: 'ACCESS_DENIED',
    });

    await f.iam.api.delegations.revoke(aliceSession, {
      tenantId: f.tenantId,
      delegationId: plain.id,
    });
    const fresh = { token: (await f.signIn('alice')).token };
    const deep = await f.iam.api.delegations.grant(fresh, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      scopes: ['documents:*'],
      confirm: ['documents:write'],
      handoff: { agents: [researcher.id, writer.id], depth: 2 },
    });
    const assistantSession = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: deep.id,
    });
    const first = await handOn(assistantSession.token, writer.id, ['documents:*']);
    // Depth and the person's confirm list travel down the chain.
    expect(first).toMatchObject({
      handoff: { agents: [researcher.id, writer.id], depth: 1 },
      confirm: ['documents:write'],
    });
    const writerSession = await f.iam.api.delegations.assume(writer.key, {
      tenantId: f.tenantId,
      delegationId: first.id,
    });
    const decision = await f.iam.authorize({
      token: writerSession.token,
      tenantId: f.tenantId,
      action: 'documents:write',
      resource: { type: 'document', id: 'draft' },
    });
    expect(decision.allowed).toBe(false);
    expect(await allowed(f, writerSession.token, 'documents:read')).toBe(true);
    // The writer asks alice to confirm, as her own delegate would have to.
    const confirmation = await f.iam.api.delegations.requestConfirmation(
      { token: writerSession.token },
      {
        tenantId: f.tenantId,
        action: 'documents:write',
        resource: { type: 'document', id: 'draft' },
        reason: 'Save the draft',
      },
    );
    await f.iam.api.delegations.decideConfirmation(fresh, {
      tenantId: f.tenantId,
      confirmationId: confirmation.id,
      approve: true,
    });
    expect(await allowed(f, writerSession.token, 'documents:write', 'draft')).toBe(true);
    // No agent appears twice in a chain.
    expect(await refusal(handOn(writerSession.token, assistant.id))).toMatchObject({
      code: 'DELEGATION_NOT_ALLOWED',
    });
    const second = await handOn(writerSession.token, researcher.id);
    expect(second.chain!.map((agent) => agent.id)).toEqual([assistant.id, writer.id]);
    expect(second).not.toHaveProperty('handoff');
    const researchSession = await f.iam.api.delegations.assume(researcher.key, {
      tenantId: f.tenantId,
      delegationId: second.id,
    });
    expect(await allowed(f, researchSession.token, 'documents:read')).toBe(true);
    // The end of the line: no further hand-offs.
    expect(await refusal(handOn(researchSession.token, writer.id))).toMatchObject({
      code: 'DELEGATION_NOT_ALLOWED',
    });

    // Suspending an agent in the middle of the chain stops everything below it.
    await f.iam.api.agents.suspend(f.ownerCredential, { tenantId: f.tenantId, agentId: writer.id });
    expect(await refusal(f.iam.authenticate({ token: researchSession.token }))).toMatchObject({
      status: 401,
    });
    await f.iam.api.agents.resume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      agentId: writer.id,
    });
    expect(await allowed(f, researchSession.token, 'documents:read')).toBe(true);
  });

  it('ends a hand-off with the key that made it, and credits agents with what they revoke', async () => {
    const { f, alice, assistant, researcher, aliceSession } = await setup();
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      scopes: ['documents:*'],
      handoff: {},
    });
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    const handOn = () =>
      f.iam.api.delegations.handoff(
        { token: acting.token },
        {
          tenantId: f.tenantId,
          agentId: researcher.id,
          scopes: ['documents:read'],
          expiresInSeconds: 300 * 86_400,
        },
      );
    const first = await handOn();
    // Never past the key the assistant acted with (a key lasts 90 days by default).
    const keys = await f.iam.api.credentials.list(f.ownerCredential, { tenantId: f.tenantId });
    const assistantKey = keys.find((key) => key.identityId === assistant.id)!;
    expect(first.expiresAt).toBeLessThanOrEqual(assistantKey.expiresAt);
    const research = await f.iam.api.delegations.assume(researcher.key, {
      tenantId: f.tenantId,
      delegationId: first.id,
    });
    expect(await allowed(f, research.token, 'documents:read')).toBe(true);

    // The assistant revokes its own hand-off from its delegated session: the record names the assistant, not alice.
    const second = await handOn();
    const revoked = await f.iam.api.delegations.revoke(
      { token: acting.token },
      { tenantId: f.tenantId, delegationId: second.id },
    );
    expect(revoked.revokedBy).toBe(assistant.id);
    expect(revoked.revokedBy).not.toBe(alice.id);

    // Revoking the assistant's key (a compromised agent) stops what it handed on at once.
    await f.iam.api.credentials.revoke(f.ownerCredential, {
      tenantId: f.tenantId,
      credentialId: assistantKey.id,
    });
    expect(await refusal(f.iam.authenticate({ token: research.token }))).toMatchObject({
      status: 401,
    });
    expect(
      await refusal(
        f.iam.api.delegations.assume(researcher.key, {
          tenantId: f.tenantId,
          delegationId: first.id,
        }),
      ),
    ).toMatchObject({ code: 'DELEGATION_INACTIVE' });
  });

  it('never hands on more than the handing session could do', async () => {
    // The assistant's key may only read, even though alice's delegation covers writing.
    const { f, assistant, writer, aliceSession } = await setup({
      assistantScopes: ['documents:read'],
    });
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      scopes: ['documents:*'],
      handoff: {},
    });
    expect(delegation.handoff).toEqual({ depth: 1 });
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(await allowed(f, acting.token, 'documents:write')).toBe(false);
    const handoff = await f.iam.api.delegations.handoff(
      { token: acting.token },
      { tenantId: f.tenantId, agentId: writer.id, scopes: ['documents:*'] },
    );
    const writing = await f.iam.api.delegations.assume(writer.key, {
      tenantId: f.tenantId,
      delegationId: handoff.id,
    });
    expect(await allowed(f, writing.token, 'documents:read')).toBe(true);
    expect(await allowed(f, writing.token, 'documents:write')).toBe(false);

    // The approval path: an agent's request may ask for hand-offs, but they count only when the person states them.
    const request = await f.iam.api.delegations.request(writer.key, {
      tenantId: f.tenantId,
      subjectEmail: 'alice@acme.test',
      scopes: ['documents:read'],
      reason: 'Draft the weekly summary',
      handoff: { depth: 2 },
    });
    expect(request.handoff).toEqual({ depth: 2 });
    const approved = await f.iam.api.delegations.approve(aliceSession, {
      tenantId: f.tenantId,
      delegationId: request.id,
    });
    expect(approved).not.toHaveProperty('handoff');
    const other = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Other',
    });
    for (const handoff of [{ agents: ['not-an-agent'] }, { depth: 4 }, { agents: [] }])
      expect(
        await refusal(
          f.iam.api.delegations.grant(aliceSession, {
            tenantId: f.tenantId,
            agentId: other.id,
            scopes: ['documents:read'],
            handoff,
          }),
        ),
      ).toMatchObject({ code: 'INVALID_INPUT' });
  });
});
