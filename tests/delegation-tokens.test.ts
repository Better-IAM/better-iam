import { generateKeyPairSync } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  createDelegationTokenCache,
  DelegationTokenError,
  verifyDelegationToken,
} from '@better-iam/a2a';
import { delegationActor, readDelegationTokenClaims, type PolicyDocument } from '@better-iam/core';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

function signingKey(kid: string) {
  const { privateKey } = generateKeyPairSync('ed25519');
  return { ...privateKey.export({ format: 'jwk' }), kid, alg: 'EdDSA', use: 'sig' };
}

const calendar = 'https://calendar.example.com';
const files = 'https://files.docs.example.com';

/**
 * Acme with alice (read and write on every document) and three agents with keys: an assistant that may present
 * delegations to the calendar and any docs service, a researcher only to docs services, and one with no audiences.
 */
async function setup(options: { a2a?: boolean } = {}) {
  const f = await organizationFixture(
    options.a2a === false
      ? {}
      : { a2a: { signingKeys: [signingKey('card-1')], jwksUrl: 'https://iam.acme.test/jwks' } },
  );
  const alice = await f.member('alice');
  const agent = async (name: string, tokenAudiences?: string[], keyScopes?: string[]) => {
    const created = await f.iam.api.agents.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name,
      ...(tokenAudiences ? { tokenAudiences } : {}),
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: created.id,
      ...(keyScopes ? { scopes: keyScopes } : {}),
    });
    return { id: created.id, key: { token: key.token } };
  };
  const assistant = await agent('Assistant', [calendar, 'https://*.docs.example.com']);
  const researcher = await agent('Researcher', ['https://*.docs.example.com']);
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Editor',
    document: {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['documents:read', 'documents:write'],
          resources: ['document/*'],
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
  const actFor = async (
    who: { id: string; key: { token: string } },
    grant: {
      scopes?: string[];
      policy?: PolicyDocument;
      handoff?: { agents: string[] };
      confirm?: string[];
    } = {
      scopes: ['documents:read', 'documents:write'],
    },
  ) => {
    const delegation = await f.iam.api.delegations.grant(aliceSession, {
      tenantId: f.tenantId,
      agentId: who.id,
      ...grant,
    });
    const acting = await f.iam.api.delegations.assume(who.key, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    return { delegation, session: { token: acting.token } };
  };
  return { f, alice, agent, assistant, researcher, aliceSession, actFor };
}

const trusted = (f: OrganizationFixture, issuer: string) => ({
  trustedIssuers: { [issuer]: f.iam.a2a.jwks() },
  now: f.now,
});

async function refusal(promise: Promise<unknown>) {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(Error);
  return error as Error & { code: string; status: number; reason: string };
}

const claimsOf = (token: string) =>
  JSON.parse(Buffer.from(token.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>;

describe('delegation tokens', () => {
  it('lets an agent show another service, with a signed token, that it acts for a person', async () => {
    const { f, alice, assistant, aliceSession, actFor } = await setup();
    const { delegation, session } = await actFor(assistant);
    const issued = await f.iam.api.delegations.issueToken(session, {
      tenantId: f.tenantId,
      audience: calendar,
    });
    expect(issued).toMatchObject({
      tokenType: 'biam-delegation+jwt',
      audience: calendar,
      scopes: ['documents:read', 'documents:write'],
      chain: [assistant.id],
      expiresIn: 300,
    });
    const header = JSON.parse(Buffer.from(issued.token.split('.')[0]!, 'base64url').toString());
    expect(header).toEqual({
      alg: 'EdDSA',
      kid: 'card-1',
      typ: 'biam-delegation+jwt',
      jku: 'https://iam.acme.test/jwks',
    });
    expect(claimsOf(issued.token)).toMatchObject({
      iss: issued.issuer,
      sub: alice.id,
      aud: calendar,
      tenant_id: f.tenantId,
      delegation_id: delegation.id,
      act: { sub: assistant.id },
      scope: 'documents:read documents:write',
    });

    // The service verifies it offline with the deployment's published keys.
    const verified = await verifyDelegationToken(issued.token, {
      audience: calendar,
      ...trusted(f, issued.issuer),
    });
    expect(verified).toMatchObject({
      personId: alice.id,
      agentId: assistant.id,
      chain: [assistant.id],
      tenantId: f.tenantId,
      delegationId: delegation.id,
      scopes: ['documents:read', 'documents:write'],
      tokenId: issued.tokenId,
    });
    const reasons = async (token: string, options: Record<string, unknown> = {}) =>
      (
        await refusal(
          verifyDelegationToken(token, {
            audience: calendar,
            ...trusted(f, issued.issuer),
            ...options,
          }),
        )
      ).reason;
    expect(await reasons(issued.token, { audience: files })).toBe('audience');
    expect(await reasons(issued.token, { tenantId: 'another-tenant' })).toBe('tenant');
    expect(
      await reasons(issued.token, {
        trustedIssuers: { [issued.issuer]: { keys: [] } },
      }),
    ).toBe('untrusted-key');
    expect(
      await reasons(issued.token, { trustedIssuers: { 'https://other.example': { keys: [] } } }),
    ).toBe('issuer');
    expect(await reasons(issued.token, { now: () => f.now() + 10 * 60_000 })).toBe('expired');
    const [head, , signature] = issued.token.split('.');
    const forged = Buffer.from(
      JSON.stringify({ ...claimsOf(issued.token), sub: 'someone-else' }),
    ).toString('base64url');
    expect(await reasons(`${head}.${forged}.${signature}`)).toBe('signature');
    const seen = new Set<string>();
    const once = (id: string) => !seen.has(id) && !!seen.add(id);
    await verifyDelegationToken(issued.token, {
      audience: calendar,
      replay: once,
      ...trusted(f, issued.issuer),
    });
    expect(await reasons(issued.token, { replay: once })).toBe('replay');

    // Inside the deployment, a live check also sees revocation before the token expires.
    await expect(
      f.iam.a2a.verifyDelegationToken(issued.token, { audience: calendar, live: true }),
    ).resolves.toMatchObject({ personId: alice.id });
    await f.iam.api.delegations.revoke(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(
      (
        await refusal(
          f.iam.a2a.verifyDelegationToken(issued.token, { audience: calendar, live: true }),
        )
      ).code,
    ).toBe('DELEGATION_TOKEN_INVALID');
    await expect(
      f.iam.a2a.verifyDelegationToken(issued.token, { audience: calendar }),
    ).resolves.toMatchObject({ agentId: assistant.id });

    const activity = await f.iam.api.delegations.activity(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    expect(activity.map((event) => event.action)).toContain('delegation:token-issue');
  });

  it('refuses audiences, scopes and callers outside every limit on the session', async () => {
    const { f, agent, assistant, actFor } = await setup();
    const { session } = await actFor(assistant);
    const issue = (input: Record<string, unknown>, credential = session) =>
      refusal(
        f.iam.api.delegations.issueToken(credential, {
          tenantId: f.tenantId,
          audience: calendar,
          ...input,
        }),
      );
    expect((await issue({ audience: 'https://evil.example.com' })).code).toBe(
      'DELEGATION_NOT_ALLOWED',
    );
    expect((await issue({ audience: 'https://*.docs.example.com' })).code).toBe('INVALID_INPUT');
    expect((await issue({ audience: 'not a uri' })).code).toBe('INVALID_INPUT');
    expect((await issue({ scopes: ['billing:read'] })).code).toBe('DELEGATION_NOT_ALLOWED');
    // A pattern broader than the delegation's scopes, or one with ?, is refused.
    expect((await issue({ scopes: ['documents:*'] })).code).toBe('DELEGATION_NOT_ALLOWED');
    expect((await issue({ scopes: ['documents:rea?'] })).code).toBe('INVALID_INPUT');
    expect((await issue({ lifetimeSeconds: 10 })).code).toBe('INVALID_INPUT');
    const narrow = await f.iam.api.delegations.issueToken(session, {
      tenantId: f.tenantId,
      audience: files,
      scopes: ['documents:read'],
      lifetimeSeconds: 60,
    });
    expect(narrow).toMatchObject({ scopes: ['documents:read'], expiresIn: 60 });

    // The agent's own key is not a delegation.
    expect((await issue({}, assistant.key)).code).toBe('ACCESS_DENIED');

    // A key limited to reading cannot carry the delegation's write scope.
    const scoped = await agent('Scoped', [calendar], ['documents:read']);
    const limited = await actFor(scoped);
    expect((await issue({}, limited.session)).code).toBe('DELEGATION_NOT_ALLOWED');
    await expect(
      f.iam.api.delegations.issueToken(limited.session, {
        tenantId: f.tenantId,
        audience: calendar,
        scopes: ['documents:read'],
      }),
    ).resolves.toMatchObject({ scopes: ['documents:read'] });

    // A delegation given as a resource-limited policy carries no scopes, and cannot claim any.
    const policy = await agent('Team helper', [calendar]);
    const team = await actFor(policy, {
      policy: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['documents:read'], resources: ['document/team-*'] },
        ],
      },
    });
    await expect(
      f.iam.api.delegations.issueToken(team.session, { tenantId: f.tenantId, audience: calendar }),
    ).resolves.toMatchObject({ scopes: [] });
    expect((await issue({ scopes: ['documents:read'] }, team.session)).code).toBe(
      'DELEGATION_NOT_ALLOWED',
    );

    // Without token audiences an agent gets no tokens at all.
    const quiet = await agent('Quiet');
    expect((await issue({}, (await actFor(quiet)).session)).code).toBe('DELEGATION_NOT_ALLOWED');
    await expect(
      f.iam.api.agents.update(f.ownerCredential, {
        tenantId: f.tenantId,
        agentId: quiet.id,
        tokenAudiences: ['https://ok.example', 'with space'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('names every agent a hand-off passed through, in nested act claims', async () => {
    const { f, alice, assistant, researcher, aliceSession, actFor } = await setup();
    const { delegation, session } = await actFor(assistant, {
      scopes: ['documents:read', 'documents:write'],
      handoff: { agents: [researcher.id] },
    });
    const handoff = await f.iam.api.delegations.handoff(session, {
      tenantId: f.tenantId,
      agentId: researcher.id,
      scopes: ['documents:read'],
    });
    const researching = await f.iam.api.delegations.assume(researcher.key, {
      tenantId: f.tenantId,
      delegationId: handoff.id,
    });
    const acting = { token: researching.token };
    const issued = await f.iam.api.delegations.issueToken(acting, {
      tenantId: f.tenantId,
      audience: files,
    });
    expect(issued).toMatchObject({
      chain: [assistant.id, researcher.id],
      scopes: ['documents:read'],
    });
    expect(claimsOf(issued.token)).toMatchObject({
      sub: alice.id,
      delegation_id: handoff.id,
      act: { sub: researcher.id, act: { sub: assistant.id } },
    });
    const verified = await verifyDelegationToken(issued.token, {
      audience: files,
      ...trusted(f, issued.issuer),
    });
    expect(verified).toMatchObject({
      agentId: researcher.id,
      chain: [assistant.id, researcher.id],
    });

    // The researcher may not claim more than it was handed, nor reach a service the assistant may not.
    await expect(
      f.iam.api.delegations.issueToken(acting, {
        tenantId: f.tenantId,
        audience: files,
        scopes: ['documents:write'],
      }),
    ).rejects.toMatchObject({ code: 'DELEGATION_NOT_ALLOWED' });
    await f.iam.api.agents.update(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: researcher.id,
      tokenAudiences: [calendar, 'https://*.docs.example.com'],
    });
    await f.iam.api.agents.update(f.ownerCredential, {
      tenantId: f.tenantId,
      agentId: assistant.id,
      tokenAudiences: ['https://*.docs.example.com'],
    });
    await expect(
      f.iam.api.delegations.issueToken(acting, { tenantId: f.tenantId, audience: calendar }),
    ).rejects.toMatchObject({ code: 'DELEGATION_NOT_ALLOWED' });

    // Revoking the person's own delegation ends the hand-off below it, and live checks see it.
    await f.iam.api.delegations.revoke(aliceSession, {
      tenantId: f.tenantId,
      delegationId: delegation.id,
    });
    await expect(
      f.iam.a2a.verifyDelegationToken(issued.token, { audience: files, live: true }),
    ).rejects.toMatchObject({ code: 'DELEGATION_TOKEN_INVALID' });
  });

  it('needs the a2a signing keys, and caches tokens on the agent side', async () => {
    const { f, assistant, actFor } = await setup({ a2a: false });
    const { session } = await actFor(assistant);
    await expect(
      f.iam.api.delegations.issueToken(session, { tenantId: f.tenantId, audience: calendar }),
    ).rejects.toMatchObject({ code: 'FEATURE_DISABLED' });

    let now = 1_000_000;
    let issued = 0;
    const tokenFor = createDelegationTokenCache({
      now: () => now,
      issue: async (audience, scopes) => {
        issued++;
        return {
          token: `${audience}|${scopes?.join(',') ?? ''}|${issued}`,
          expiresAt: now + 300_000,
        };
      },
    });
    const [first, second] = await Promise.all([tokenFor(calendar), tokenFor(calendar)]);
    expect(first).toBe(second);
    expect(await tokenFor(calendar, ['b', 'a'])).toBe(`${calendar}|b,a|2`);
    expect(await tokenFor(calendar, ['a', 'b'])).toBe(`${calendar}|b,a|2`);
    now += 250_000;
    expect(await tokenFor(calendar)).toBe(`${calendar}||3`);
    expect(issued).toBe(3);
  });

  it('never carries what the person confirms call by call, or what their own denies may touch', async () => {
    const { f, alice, assistant, researcher, actFor } = await setup();
    const confirmed = await actFor(assistant, {
      scopes: ['documents:read', 'documents:write'],
      confirm: ['documents:wri?e'],
    });
    const issue = (session: { token: string }, scopes?: string[]) =>
      f.iam.api.delegations.issueToken(session, {
        tenantId: f.tenantId,
        audience: files,
        ...(scopes ? { scopes } : {}),
      });
    await expect(issue(confirmed.session)).rejects.toMatchObject({
      code: 'DELEGATION_NOT_ALLOWED',
      message: expect.stringContaining('confirms documents:write'),
    });
    await expect(issue(confirmed.session, ['documents:read'])).resolves.toMatchObject({
      scopes: ['documents:read'],
    });

    // A deny among alice's own grants refuses any scope it could touch, whatever its resources or conditions.
    const policy = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'No agent writes',
      document: {
        version: 1,
        statements: [
          {
            effect: 'deny',
            actions: ['documents:write'],
            resources: ['document/*'],
            conditions: { Bool: { 'principal.delegated': true } },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: policy.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const plain = await actFor(researcher);
    await expect(issue(plain.session)).rejects.toMatchObject({
      code: 'DELEGATION_NOT_ALLOWED',
      message: expect.stringContaining('deny'),
    });
    await expect(issue(plain.session, ['documents:read'])).resolves.toMatchObject({
      scopes: ['documents:read'],
    });
  });

  it('keeps honouring a deny whose author’s authority was revoked', async () => {
    const { f, alice, researcher, actFor } = await setup();
    const api = f.iam.api;
    const security = await f.member('security');
    const writer = await api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Security policy writer',
      permissions: ['iam:policies:create', 'iam:policies:read'],
    });
    await api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: writer.id,
      subjectType: 'identity',
      subjectId: security.id,
    });
    const authority = await api.authorities.create(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      identityId: security.id,
      ceiling: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['*'] }],
      },
    });
    const guard = await api.policies.create({ token: (await f.signIn('security')).token }, {
      tenantId: f.tenantId,
      name: 'No agent writes',
      document: {
        version: 1,
        statements: [{ effect: 'deny', actions: ['documents:write'], resources: ['document/*'] }],
      },
    });
    const staff = await api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Staff',
      permissions: ['documents:read'],
    });
    await api.roles.update(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: staff.id,
      policyIds: [guard.id],
    });
    await api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: staff.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    // The security engineer leaves: their authority is revoked, but the deny they wrote still applies, so a token
    // for alice must not carry documents:write either.
    await api.authorities.revoke(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      authorityId: authority.id,
    });
    const acting = await actFor(researcher);
    await expect(
      api.delegations.issueToken(acting.session, { tenantId: f.tenantId, audience: files }),
    ).rejects.toMatchObject({
      code: 'DELEGATION_NOT_ALLOWED',
      message: expect.stringContaining('deny'),
    });
  });

  it('matches audiences by URL structure, quickly, and re-checks everything live', async () => {
    const { f, agent, assistant, actFor } = await setup();
    const wide = await agent('Wide', [
      'https://*.example.com',
      `urn:${'*:'.repeat(12)}x`,
      'https://api.example.org/v1/*',
    ]);
    const { session } = await actFor(wide);
    const issue = (audience: string) =>
      f.iam.api.delegations.issueToken(session, { tenantId: f.tenantId, audience });
    await expect(issue('https://files.example.com')).resolves.toMatchObject({
      audience: 'https://files.example.com',
    });
    await expect(issue('https://api.example.org/v1/events')).resolves.toBeDefined();
    for (const outside of [
      'https://evil.com/.example.com',
      'https://example.com',
      'https://api.example.org/v2',
    ])
      await expect(issue(outside)).rejects.toMatchObject({ code: 'DELEGATION_NOT_ALLOWED' });
    for (const malformed of [
      'https://evil.com#.example.com',
      'https://user@files.example.com',
      'https://files.example.com?x=1',
      'https://*.example.com',
    ])
      await expect(issue(malformed)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // Many wildcards against a long audience finish at once (no backtracking blow-up).
    const started = Date.now();
    await expect(issue(`urn:${'a:'.repeat(240)}y`)).rejects.toMatchObject({
      code: 'DELEGATION_NOT_ALLOWED',
    });
    expect(Date.now() - started).toBeLessThan(2000);

    // Live verification re-checks the agent's key, its delegation switch, its audiences and its ceiling.
    const live = (token: string, audience = calendar) =>
      f.iam.a2a.verifyDelegationToken(token, { audience, live: true });
    const acting = async () => {
      const { session: fresh } = await actFor(assistant);
      return (
        await f.iam.api.delegations.issueToken(fresh, { tenantId: f.tenantId, audience: calendar })
      ).token;
    };
    const update = (changes: Record<string, unknown>) =>
      f.iam.api.agents.update(f.ownerCredential, {
        tenantId: f.tenantId,
        agentId: assistant.id,
        ...changes,
      });
    const first = await acting();
    await expect(live(first)).resolves.toMatchObject({ agentId: assistant.id });
    await update({ tokenAudiences: ['https://*.docs.example.com'] });
    await expect(live(first)).rejects.toMatchObject({ code: 'DELEGATION_TOKEN_INVALID' });
    await update({ tokenAudiences: [calendar] });
    await expect(live(first)).resolves.toBeDefined();
    await update({
      boundary: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['*'] }],
      },
    });
    await expect(live(first)).rejects.toMatchObject({ code: 'DELEGATION_TOKEN_INVALID' });
    await update({ boundary: null });
    await update({ delegable: false });
    await expect(live(first)).rejects.toMatchObject({ code: 'DELEGATION_TOKEN_INVALID' });
    await update({ delegable: true });
    await expect(live(first)).resolves.toBeDefined();
    const keys = await f.iam.api.credentials.list(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: assistant.id,
    });
    for (const key of keys)
      await f.iam.api.credentials.revoke(f.ownerCredential, {
        tenantId: f.tenantId,
        credentialId: key.id,
      });
    await expect(live(first)).rejects.toMatchObject({ code: 'DELEGATION_TOKEN_INVALID' });
    // Offline verification cannot see any of this before the token expires.
    await expect(
      f.iam.a2a.verifyDelegationToken(first, { audience: calendar }),
    ).resolves.toBeDefined();
    // The in-deployment verifier takes a replay check too.
    const seen = new Set<string>();
    const replay = (id: string) => !seen.has(id) && !!seen.add(id);
    await f.iam.a2a.verifyDelegationToken(first, { audience: calendar, replay });
    await expect(
      f.iam.a2a.verifyDelegationToken(first, { audience: calendar, replay }),
    ).rejects.toMatchObject({ code: 'DELEGATION_TOKEN_INVALID' });
  });

  it('reads claims strictly', () => {
    const now = 1_700_000_000_000;
    const iat = now / 1000;
    const claims = {
      iss: 'https://iam.example',
      sub: 'person-1',
      aud: calendar,
      iat,
      nbf: iat,
      exp: iat + 300,
      jti: 'token-1',
      tenant_id: 'tenant-1',
      delegation_id: 'delegation-1',
      act: delegationActor(['agent-a', 'agent-b']),
    };
    const expect_ = { issuer: 'https://iam.example', audience: calendar, now };
    expect(readDelegationTokenClaims(claims, expect_)).toMatchObject({
      token: { agentId: 'agent-b', chain: ['agent-a', 'agent-b'], scopes: [] },
    });
    const rejected = (changes: Record<string, unknown>) =>
      (readDelegationTokenClaims({ ...claims, ...changes }, expect_) as { rejected?: string })
        .rejected;
    expect(rejected({ exp: iat + 3601 })).toBe('lifetime');
    expect(rejected({ act: { sub: 'agent-a', act: { sub: 'agent-a' } } })).toBe('malformed');
    expect(rejected({ act: { sub: 'person-1' } })).toBe('malformed');
    expect(rejected({ act: undefined })).toBe('malformed');
    expect(rejected({ act: delegationActor(['a', 'b', 'c', 'd', 'e']) })).toBe('malformed');
    expect(rejected({ scope: 'documents:read bad?scope' })).toBe('malformed');
    expect(rejected({ nbf: iat + 120, exp: iat + 300 })).toBe('not-yet-valid');
    expect(rejected({ aud: [calendar] })).toBe('malformed');
  });
});
