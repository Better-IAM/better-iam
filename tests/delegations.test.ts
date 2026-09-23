import { afterEach, describe, expect, it } from 'vitest';
import type { PolicyDocument } from '@better-iam/core';
import { parseCredentialToken, renderDeliveryMessage } from '@better-iam/auth';
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

/**
 * Acme with alice (documents:read and documents:write on every document) and an agent sponsored by the owner with
 * its own key but no grants of its own.
 */
async function setup(agentInput: Record<string, unknown> = {}) {
  const f = await organizationFixture();
  const alice = await f.member('alice');
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Editor',
    document: doc(['documents:read', 'documents:write']),
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const agent = await f.iam.api.agents.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Inbox agent',
    model: 'claude-sonnet-5',
    ...agentInput,
  });
  const key = await f.iam.api.credentials.create(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId: agent.id,
  });
  const aliceSession = { token: (await f.signIn('alice')).token };
  return { f, alice, agent, agentKey: { token: key.token }, aliceSession };
}

const allowed = (f: OrganizationFixture, token: string, action: string, id = 'a') =>
  f.iam
    .authorize({ token, tenantId: f.tenantId, action, resource: { type: 'document', id } })
    .then((decision) => decision.allowed);

describe('delegations', () => {
  it('lets a person delegate part of their access to an agent', async () => {
    const { f, alice, agent, agentKey, aliceSession } = await setup();
    // Without a delegation the agent has nothing.
    expect(await allowed(f, agentKey.token, 'documents:read')).toBe(false);

    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:read'],
      expiresInSeconds: 86_400,
    });
    expect(delegation).toMatchObject({
      status: 'active',
      requestedBy: 'subject',
      scopes: ['documents:read'],
      agent: { id: agent.id, name: 'Inbox agent', model: 'claude-sonnet-5' },
      subject: { id: alice.id, email: 'alice@acme.test' },
    });

    const credential = await f.iam.api.delegations.assume(agentKey, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
      sessionName: 'triage-run',
    });
    expect(parseCredentialToken(credential.token)).toEqual({ type: 'dlg' });
    expect(credential.session).toMatchObject({
      kind: 'delegated',
      identityId: alice.id,
      agentId: agent.id,
      delegationId: delegation.id,
      sessionName: 'triage-run',
    });
    expect(credential.expiresIn).toBe(900);

    // Alice's access, narrowed to the scope.
    expect(await allowed(f, credential.token, 'documents:read')).toBe(true);
    expect(await allowed(f, credential.token, 'documents:write')).toBe(false);

    const caller = await f.iam.api.sts.getCallerIdentity({ token: credential.token });
    expect(caller).toMatchObject({
      identityId: alice.id,
      sessionKind: 'delegated',
      agentId: agent.id,
      delegationId: delegation.id,
    });

    // The audit trail names the person, the agent and the delegation.
    await f.iam.authorize({
      token: credential.token,
      tenantId: f.tenantId,
      action: 'documents:write',
      resource: { type: 'document', id: 'b' },
    });
    const denials = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'documents:write',
    });
    expect(denials[0]).toMatchObject({
      actorId: alice.id,
      outcome: 'deny',
      sessionContext: { kind: 'delegated', agentId: agent.id, delegationId: delegation.id },
    });

    expect(
      (await f.iam.api.delegations.listMine(aliceSession, { tenantId: f.tenantId })).map(
        (item) => item.id,
      ),
    ).toEqual([delegation.id]);
    const mine = await f.iam.api.delegations.listMine(agentKey, { tenantId: f.tenantId });
    expect(mine[0]).toMatchObject({ id: delegation.id, lastUsedAt: expect.any(Number) });
  });

  it('shows the person and the sponsor what the agent did', async () => {
    const { f, alice, agent, agentKey, aliceSession } = await setup();
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:read'],
    });
    const { token } = await f.iam.api.delegations.assume(agentKey, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    // One denied action for alice, one denied action with the agent's own key.
    expect(await allowed(f, token, 'documents:write', 'secret')).toBe(false);
    expect(await allowed(f, agentKey.token, 'documents:read', 'own')).toBe(false);

    const forAlice = await f.iam.api.delegations.activity(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    // Newest first; events in the same millisecond may come in either order.
    expect(forAlice.map((event) => event.action).sort()).toEqual([
      'delegation:assume',
      'delegation:grant',
      'documents:write',
    ]);
    expect(forAlice.find((event) => event.action === 'documents:write')).toMatchObject({
      actorId: alice.id,
      resourceId: 'secret',
      outcome: 'deny',
    });

    // The owner sponsors the agent: they see both, through their own session.
    const bySponsor = await f.iam.api.agents.activity(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
    });
    expect(bySponsor.map((event) => [event.action, event.resourceId])).toEqual(
      expect.arrayContaining([
        ['documents:read', 'own'],
        ['documents:write', 'secret'],
        ['delegation:assume', delegation.id],
      ]),
    );
    expect(
      bySponsor.every(
        (event) => event.actorId === agent.id || event.sessionContext?.agentId === agent.id,
      ),
    ).toBe(true);
    // Another member sees neither.
    await f.member('mallory');
    const mallory = { token: (await f.signIn('mallory')).token };
    await expect(
      f.iam.api.delegations.activity(mallory, {
        tenantId: f.tenantId,
        delegationId: delegation.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.agents.activity(mallory, { tenantId: f.tenantId, agentId: agent.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('holds back sensitive actions until the person confirms each one', async () => {
    const { f, alice, agent, agentKey, aliceSession } = await setup();
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:*'],
      confirm: ['documents:write'],
    });
    expect(delegation.confirm).toEqual(['documents:write']);
    const { token } = await f.iam.api.delegations.assume(agentKey, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    const acting = { token };
    expect(await allowed(f, token, 'documents:read', 'report')).toBe(true);
    expect(await allowed(f, token, 'documents:write', 'report')).toBe(false);

    // Reading needs no confirmation, so asking for it is refused.
    await expect(
      f.iam.api.delegations.requestConfirmation(acting, {
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'report' },
        reason: 'x',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Only the delegated session may ask.
    await expect(
      f.iam.api.delegations.requestConfirmation(agentKey, {
        tenantId: f.tenantId,
        action: 'documents:write',
        resource: { type: 'document', id: 'report' },
        reason: 'x',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const request = await f.iam.api.delegations.requestConfirmation(acting, {
      tenantId: f.tenantId,
      action: 'documents:write',
      resource: { type: 'document', id: 'report' },
      reason: 'Fix the typo in the summary you asked about',
      validSeconds: 120,
    });
    expect(request).toMatchObject({
      status: 'pending',
      action: 'documents:write',
      resource: { type: 'document', id: 'report' },
      agent: { id: agent.id, name: 'Inbox agent' },
      subjectId: alice.id,
    });
    // Asking again returns the same pending request.
    expect(
      (
        await f.iam.api.delegations.requestConfirmation(acting, {
          tenantId: f.tenantId,
          action: 'documents:write',
          resource: { type: 'document', id: 'report' },
          reason: 'again',
        })
      ).id,
    ).toBe(request.id);
    await f.iam.auth.dispatchOutbox();
    const email = f.inbox.find((message) => message.template === 'delegation-confirmation');
    expect(email).toMatchObject({
      to: 'alice@acme.test',
      payload: {
        confirmationId: request.id,
        action: 'documents:write',
        resource: 'document/report',
      },
    });
    expect(renderDeliveryMessage(email!)?.subject).toBe(
      'Inbox agent asks you to confirm an action',
    );

    // Alice sees it; the agent polls it; the owner (not involved) cannot decide it.
    expect(
      (await f.iam.api.delegations.listConfirmations(aliceSession, { tenantId: f.tenantId })).map(
        (item) => item.id,
      ),
    ).toEqual([request.id]);
    expect(
      (
        await f.iam.api.delegations.getConfirmation(acting, {
          tenantId: f.tenantId,
          confirmationId: request.id,
        })
      ).status,
    ).toBe('pending');
    await expect(
      f.iam.api.delegations.decideConfirmation(f.ownerCredential, {
        tenantId: f.tenantId,
        confirmationId: request.id,
        approve: true,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    const approved = await f.iam.api.delegations.decideConfirmation(aliceSession, {
      tenantId: f.tenantId,
      confirmationId: request.id,
      approve: true,
    });
    expect(approved).toMatchObject({ status: 'approved', expiresAt: f.now() + 120_000 });
    // Exactly that action on exactly that resource, for a while.
    expect(await allowed(f, token, 'documents:write', 'report')).toBe(true);
    expect(await allowed(f, token, 'documents:write', 'other')).toBe(false);
    f.advance(121_000);
    expect(await allowed(f, token, 'documents:write', 'report')).toBe(false);

    // A rejection opens nothing, and the trail shows every step.
    const second = await f.iam.api.delegations.requestConfirmation(acting, {
      tenantId: f.tenantId,
      action: 'documents:write',
      resource: { type: 'document', id: 'report' },
      reason: 'One more edit',
    });
    const rejected = await f.iam.api.delegations.decideConfirmation(aliceSession, {
      tenantId: f.tenantId,
      confirmationId: second.id,
      approve: false,
    });
    expect(rejected.status).toBe('rejected');
    expect(await allowed(f, token, 'documents:write', 'report')).toBe(false);
    const trail = await f.iam.api.delegations.activity(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(trail.map((event) => event.action)).toEqual(
      expect.arrayContaining([
        'delegation:confirmation-request',
        'delegation:confirm',
        'delegation:reject',
      ]),
    );
  });

  it('keeps the agent key’s own scopes on the sessions it opens', async () => {
    const { f, agent, aliceSession } = await setup();
    // An administrator issued this key for reading only.
    const readOnly = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
      scopes: ['documents:read', 'iam:*'],
    });
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:*'],
    });
    const { token } = await f.iam.api.delegations.assume(
      { token: readOnly.token },
      { tenantId: f.tenantId, delegationId: delegation.id },
    );
    expect(await allowed(f, token, 'documents:read')).toBe(true);
    // Alice may write and delegated writing, but the key never could.
    expect(await allowed(f, token, 'documents:write')).toBe(false);
  });

  it('never gives the agent more than the person has', async () => {
    const { f, agent, agentKey, aliceSession } = await setup();
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['*'],
    });
    const { token } = await f.iam.api.delegations.assume(agentKey, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(await allowed(f, token, 'documents:write')).toBe(true);
    // Alice cannot read the audit log, so neither can her agent.
    await expect(f.iam.api.audit.list({ token }, { tenantId: f.tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // A delegated session is no substitute for a fresh sign-in or the person's own session.
    await expect(
      f.iam.api.delegations.grant(
        { token },
        {
          tenantId: f.tenantId,
          agentId: agent.id,
          scopes: ['documents:read'],
        },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(f.iam.api.sts.getSessionToken({ token })).rejects.toMatchObject({
      code: 'CREDENTIAL_CHAINING_DISABLED',
    });
    // A delegated token cannot open further delegated sessions.
    await expect(
      f.iam.api.delegations.assume(
        { token },
        { tenantId: f.tenantId, delegationId: delegation.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // The agent's own ceiling bounds delegated sessions as well, live.
    await f.iam.api.agents.update(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
      boundary: doc(['documents:read']),
    });
    expect(await allowed(f, token, 'documents:write')).toBe(false);
    expect(await allowed(f, token, 'documents:read')).toBe(true);

    // A scope-down at assume time narrows one session further.
    const narrow = await f.iam.api.delegations.assume(agentKey, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
      policy: doc(['documents:read'], ['document/only-this']),
    });
    expect(await allowed(f, narrow.token, 'documents:read', 'only-this')).toBe(true);
    expect(await allowed(f, narrow.token, 'documents:read', 'other')).toBe(false);
  });

  it('runs the request and approval flow', async () => {
    const { f, alice, agent, agentKey, aliceSession } = await setup();
    const request = await f.iam.api.delegations.request(agentKey, {
      tenantId: f.tenantId,
      subjectEmail: 'Alice@acme.test',
      scopes: ['documents:read', 'documents:write'],
      reason: 'Draft replies to your inbox',
      expiresInSeconds: 7 * 86_400,
    });
    expect(request).toMatchObject({
      status: 'pending',
      requestedBy: 'agent',
      reason: 'Draft replies to your inbox',
      requestedSeconds: 7 * 86_400,
      subject: { id: alice.id },
    });
    await f.iam.auth.dispatchOutbox();
    const email = f.inbox.find((message) => message.template === 'delegation-request');
    expect(email).toMatchObject({
      to: 'alice@acme.test',
      payload: { delegationId: request.id, agentName: 'Inbox agent', days: '7' },
    });
    const rendered = renderDeliveryMessage(email!, {
      links: {
        delegation: ({ delegationId }) => `https://console.test/delegations/${delegationId}`,
      },
    });
    expect(rendered?.subject).toBe('Inbox agent asks to act on your behalf');
    expect(rendered?.text).toContain('(claude-sonnet-5)');
    expect(rendered?.text).toContain('for 7 days');
    expect(rendered?.text).toContain('Draft replies to your inbox');
    expect(rendered?.html).toContain(`https://console.test/delegations/${request.id}`);

    // Not usable until approved; a second request is refused.
    await expect(
      f.iam.api.delegations.assume(agentKey, { tenantId: f.tenantId, delegationId: request.id }),
    ).rejects.toMatchObject({ code: 'DELEGATION_PENDING' });
    await expect(
      f.iam.api.delegations.request(agentKey, {
        tenantId: f.tenantId,
        subjectId: alice.id,
        scopes: ['documents:read'],
        reason: 'again',
      }),
    ).rejects.toMatchObject({ code: 'DELEGATION_EXISTS' });
    // Only alice decides: not the owner, not the agent.
    await expect(
      f.iam.api.delegations.approve(f.ownerCredential, {
        tenantId: f.tenantId,
        delegationId: request.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // The agent polls while it waits.
    expect(
      (
        await f.iam.api.delegations.get(agentKey, {
          tenantId: f.tenantId,
          delegationId: request.id,
        })
      ).status,
    ).toBe('pending');

    // Alice approves read only.
    const approved = await f.iam.api.delegations.approve(aliceSession, {
      tenantId: f.tenantId,
      delegationId: request.id,
      scopes: ['documents:read'],
    });
    expect(approved).toMatchObject({ status: 'active', scopes: ['documents:read'] });
    expect(approved.expiresAt).toBe(f.now() + 7 * 86_400_000);
    const { token } = await f.iam.api.delegations.assume(agentKey, {
      tenantId: f.tenantId,
      delegationId: request.id,
    });
    expect(await allowed(f, token, 'documents:read')).toBe(true);
    expect(await allowed(f, token, 'documents:write')).toBe(false);
  });

  it('lets people deny requests, and requests lapse', async () => {
    const { f, alice, agentKey, aliceSession } = await setup();
    const first = await f.iam.api.delegations.request(agentKey, {
      tenantId: f.tenantId,
      subjectId: alice.id,
      scopes: ['documents:read'],
      reason: 'Please',
    });
    const denied = await f.iam.api.delegations.deny(aliceSession, {
      tenantId: f.tenantId,
      delegationId: first.id,
    });
    expect(denied.status).toBe('denied');
    const second = await f.iam.api.delegations.request(agentKey, {
      tenantId: f.tenantId,
      subjectId: alice.id,
      scopes: ['documents:read'],
      reason: 'Please, again',
    });
    f.advance(8 * 86_400_000);
    const fresh = { token: (await f.signIn('alice')).token };
    await expect(
      f.iam.api.delegations.approve(fresh, { tenantId: f.tenantId, delegationId: second.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect(
      (await f.iam.api.delegations.get(fresh, { tenantId: f.tenantId, delegationId: second.id }))
        .expired,
    ).toBe(true);
  });

  it('ends delegated sessions the moment anything in the chain goes away', async () => {
    const { f, alice, agent, agentKey, aliceSession } = await setup();
    const grantAndAssume = async () => {
      const fresh = { token: (await f.signIn('alice')).token };
      const delegation = await f.iam.api.delegations.grant(fresh, {
        tenantId: f.tenantId,
        agentId: agent.id,
        scopes: ['documents:read'],
      });
      const { token } = await f.iam.api.delegations.assume(agentKey, {
        tenantId: f.tenantId,
        delegationId: delegation.id,
      });
      expect(await allowed(f, token, 'documents:read')).toBe(true);
      return { delegation, token };
    };
    const unauthenticated = { code: 'UNAUTHENTICATED' };

    // 1. The person revokes.
    let live = await grantAndAssume();
    await f.iam.api.delegations.revoke(aliceSession, {
      tenantId: f.tenantId,
      delegationId: live.delegation.id,
    });
    await expect(allowed(f, live.token, 'documents:read')).rejects.toMatchObject(unauthenticated);

    // 2. The sponsor suspends the agent.
    live = await grantAndAssume();
    await f.iam.api.agents.suspend(f.ownerCredential, { tenantId: f.tenantId, agentId: agent.id });
    await expect(allowed(f, live.token, 'documents:read')).rejects.toMatchObject(unauthenticated);
    await f.iam.api.agents.resume(f.ownerCredential, { tenantId: f.tenantId, agentId: agent.id });
    await f.iam.api.delegations.revoke(f.ownerCredential, {
      tenantId: f.tenantId,
      delegationId: live.delegation.id,
    });

    // 3. The agent stops accepting delegation.
    live = await grantAndAssume();
    await f.iam.api.agents.update(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
      delegable: false,
    });
    await expect(allowed(f, live.token, 'documents:read')).rejects.toMatchObject(unauthenticated);
    await expect(
      f.iam.api.delegations.assume(agentKey, {
        tenantId: f.tenantId,
        delegationId: live.delegation.id,
      }),
    ).rejects.toMatchObject({ code: 'DELEGATION_NOT_ALLOWED' });
    await f.iam.api.agents.update(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
      delegable: true,
    });
    expect(await allowed(f, live.token, 'documents:read')).toBe(true);

    // 4. The agent's key is revoked.
    const keys = await f.iam.api.credentials.list(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    await f.iam.api.credentials.revoke(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      credentialId: keys[0]!.id,
    });
    await expect(allowed(f, live.token, 'documents:read')).rejects.toMatchObject(unauthenticated);

    // 5. The person is disabled.
    const second = await f.iam.api.credentials.create(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const fresh = { token: (await f.signIn('alice')).token };
    const again = await f.iam.api.delegations.assume(
      { token: second.token },
      { tenantId: f.tenantId, delegationId: live.delegation.id },
    );
    expect(await allowed(f, again.token, 'documents:read')).toBe(true);
    await f.iam.api.identities.setStatus(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: alice.id,
      status: 'disabled',
    });
    await expect(allowed(f, again.token, 'documents:read')).rejects.toMatchObject(unauthenticated);
    expect(fresh.token).toBeDefined();
  });

  it('refuses delegation to agents that do not accept it and to non-agents', async () => {
    const { f, alice, aliceSession } = await setup();
    const closed = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Closed',
      delegable: false,
    });
    await expect(
      f.iam.api.delegations.grant(aliceSession, {
        tenantId: f.tenantId,
        agentId: closed.id,
        scopes: ['documents:read'],
      }),
    ).rejects.toMatchObject({ code: 'DELEGATION_NOT_ALLOWED' });
    const service = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci',
    });
    await expect(
      f.iam.api.delegations.grant(aliceSession, {
        tenantId: f.tenantId,
        agentId: service.id,
        scopes: ['documents:read'],
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.delegations.grant(aliceSession, {
        tenantId: f.tenantId,
        agentId: alice.id,
        scopes: ['documents:read'],
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.delegations.grant(aliceSession, {
        tenantId: f.tenantId,
        agentId: closed.id,
        scopes: ['no:such-action'],
      }),
    ).rejects.toMatchObject({ code: 'DELEGATION_NOT_ALLOWED' });
    // A stale sign-in cannot consent.
    f.advance(3_600_000);
    const open = await f.iam.api.agents.create(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      name: 'Open',
    });
    await expect(
      f.iam.api.delegations.grant(aliceSession, {
        tenantId: f.tenantId,
        agentId: open.id,
        scopes: ['documents:read'],
      }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
  });

  it('lets administrators list and revoke delegations, and deleting an agent revokes them', async () => {
    const { f, agent, agentKey, aliceSession } = await setup();
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:read'],
    });
    const { token } = await f.iam.api.delegations.assume(agentKey, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    const listed = await f.iam.api.delegations.list(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
    });
    expect(listed.map((item) => item.id)).toEqual([delegation.id]);
    const detail = await f.iam.api.agents.get(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: agent.id,
    });
    expect(detail).toMatchObject({
      delegations: { active: 1, pending: 0 },
      liveDelegatedSessions: 1,
      keys: [expect.objectContaining({ id: expect.any(String) })],
    });

    await f.iam.api.agents.delete(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      agentId: agent.id,
    });
    await expect(allowed(f, token, 'documents:read')).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect(
      (
        await f.iam.api.delegations.get(f.ownerCredential, {
          tenantId: f.tenantId,
          delegationId: delegation.id,
        })
      ).status,
    ).toBe('revoked');
  });
});
