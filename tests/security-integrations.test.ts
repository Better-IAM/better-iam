import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import { createA2aAuthorizer, type A2aCaller } from '@better-iam/a2a';
import { createProjectsPlugin, type Project } from '@better-iam/projects';
import { closeFixtures, organizationFixture } from './support/organization.js';

/**
 * Integrations built on the server: plugins honour record-level policies, and a person's confirmation of an agent's
 * held-back action opens one call, not an hour of them.
 */

afterEach(closeFixtures);

describe('A2A skill names', () => {
  it('refuses a skill id that is not a string instead of treating it as no skill', async () => {
    const authorizer = createA2aAuthorizer({
      iam: {} as never,
      tenantId: 'tenant',
      message: { public: true },
      skills: { purge: { action: 'documents:delete' } },
    });
    const caller = {
      kind: 'iam',
      tenantId: 'tenant',
      identityId: 'someone',
      credential: {},
    } as unknown as A2aCaller;
    expect(
      await authorizer.canSend(caller, {
        message: { metadata: { skillId: ['purge'] } },
      }),
    ).toMatchObject({ allowed: false, reason: 'AMBIGUOUS_SKILL' });
  });
});

describe('agent card signatures', () => {
  it('never signs a card that could pass as a delegation token', async () => {
    const { privateKey } = generateKeyPairSync('ed25519');
    const f = await organizationFixture({
      a2a: {
        signingKeys: [{ ...privateKey.export({ format: 'jwk' }), kid: 'card-1', alg: 'EdDSA' }],
        jwksUrl: 'https://iam.acme.test/a2a/jwks.json',
      },
    });
    const agent = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Triage agent',
      url: 'https://agents.acme.test/triage',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const card = {
      protocolVersion: '0.3.0',
      name: 'Triage',
      description: 'Sorts incoming requests',
      url: 'https://agents.acme.test/a2a',
      version: '1.0.0',
      capabilities: {},
      defaultInputModes: ['text/plain'],
      defaultOutputModes: ['text/plain'],
      skills: [],
    };
    await expect(
      f.iam.api.agents.signCard(
        { token: key.token },
        {
          tenantId: f.tenantId,
          agentId: agent.id,
          card: { ...card, sub: f.ownerId, aud: 'https://api.bank.example', exp: 4102444800 },
        },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.agents.signCard(
        { token: key.token },
        { tenantId: f.tenantId, agentId: agent.id, card },
      ),
    ).resolves.toMatchObject({ card: { name: 'Triage' } });
  });
});

describe('delegation confirmations', () => {
  it('lets one approval open exactly one call', async () => {
    const f = await organizationFixture();
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Editor',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['documents:read', 'documents:write'], resources: ['*'] },
        ],
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
      name: 'Payments agent',
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: agent.id,
    });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: agent.id,
      scopes: ['documents:*'],
      confirm: ['documents:write'],
    });
    const { token } = await f.iam.api.delegations.assume(
      { token: key.token },
      { tenantId: f.tenantId, delegationId: delegation.id },
    );
    const write = () =>
      f.iam
        .authorize({
          token,
          tenantId: f.tenantId,
          action: 'documents:write',
          resource: { type: 'document', id: 'invoice' },
        })
        .then((decision) => decision.allowed);
    const request = await f.iam.api.delegations.requestConfirmation(
      { token },
      {
        tenantId: f.tenantId,
        action: 'documents:write',
        resource: { type: 'document', id: 'invoice' },
        reason: 'Pay the invoice',
        validSeconds: 3600,
      },
    );
    await f.iam.api.delegations.decideConfirmation(aliceSession, {
      tenantId: f.tenantId,
      confirmationId: request.id,
      approve: true,
    });
    // Advisory batch checks see the approval without using it up.
    const batch = await f.iam.authorizeMany({
      token,
      tenantId: f.tenantId,
      checks: [{ action: 'documents:write', resource: { type: 'document', id: 'invoice' } }],
    });
    expect(batch.results[0]!.allowed).toBe(true);
    expect(await write()).toBe(true);
    expect(await write()).toBe(false);
    expect(
      (
        await f.iam.api.delegations.getConfirmation(
          { token },
          { tenantId: f.tenantId, confirmationId: request.id },
        )
      ).status,
    ).toBe('used');
  });
});

describe('projects plugin', () => {
  it('authorizes endpoints on one project against that project, so a Deny on it applies', async () => {
    const f = await organizationFixture({ plugins: [createProjectsPlugin()] });
    const call = <T>(
      credential: { token: string },
      path: string,
      input: Record<string, unknown> = {},
    ) =>
      f.iam.callPlugin(credential, {
        pluginId: 'projects',
        path,
        tenantId: f.tenantId,
        input,
      }) as Promise<T>;
    const secret = await call<Project>(f.ownerCredential, 'create', { name: 'Secret' });
    const open = await call<Project>(f.ownerCredential, 'create', { name: 'Open' });
    const policy = await f.iam.api.policies.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Projects except Secret',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['projects:*'], resources: ['*'] },
          {
            effect: 'deny',
            actions: ['projects:*'],
            resources: [`iam/project/${secret.id}`],
          },
        ],
      },
    });
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Project editor',
      policyIds: [policy.id],
    });
    const bob = await f.member('bob');
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const session = { token: (await f.signIn('bob')).token };
    for (const [path, extra] of [
      ['get', {}],
      ['update', { name: 'Renamed' }],
      ['archive', {}],
    ] as const)
      await expect(
        call(session, path, { projectId: secret.id, ...extra }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      call<Project>(session, 'update', { projectId: open.id, name: 'Open, renamed' }),
    ).resolves.toMatchObject({ name: 'Open, renamed' });
    // A wildcard never stands in for a project ID.
    await expect(call(session, 'get', { projectId: '*' })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });
});
