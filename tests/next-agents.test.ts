import { afterEach, describe, expect, it } from 'vitest';
import { createIamNext, type IamPrincipal } from '@better-iam/next';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const noParams = { params: Promise.resolve({}) };

describe('Next.js API routes called by AI agents', () => {
  it('accepts an agent key and a delegated agent session, naming the agent', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['document/*'] }],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Reader agent',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:read'],
    });
    const acting = await f.iam.api.delegations.assume(
      { token: key.token },
      { tenantId: f.tenantId, delegationId: delegation.id },
    );

    let headers = new Headers();
    const iamNext = createIamNext(f.iam, { headers: () => headers, cache: (fn) => fn });
    const whoami = iamNext.apiRoute((_request, { principal }) => principal);
    const read = iamNext.apiRoute(() => 'ok', {
      authorize: { action: 'documents:read', resource: () => ({ type: 'document', id: 'a' }) },
    });
    const as = async (token: string, handler: typeof whoami) => {
      headers = new Headers({ authorization: `Bearer ${token}` });
      return handler(new Request('http://localhost:3000/api/x', { headers }), noParams);
    };

    const own = (await (await as(key.token, whoami)).json()) as IamPrincipal;
    expect(own.identity).toMatchObject({ id: agent.id, kind: 'agent' });
    expect(own.session).toMatchObject({ kind: 'api-key' });
    // The agent itself has no grants; acting for alice it reads what she may read.
    expect((await as(key.token, read)).status).toBe(403);

    const delegated = (await (await as(acting.token, whoami)).json()) as IamPrincipal;
    expect(delegated.identity).toMatchObject({ id: alice.id, kind: 'user' });
    expect(delegated.session).toMatchObject({
      kind: 'delegated',
      agentId: agent.id,
      delegationId: delegation.id,
    });
    expect((await as(acting.token, read)).status).toBe(200);
  });
});
