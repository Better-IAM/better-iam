import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, verifyAssertion } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'impersonation-test-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      sessionLifetimeMs: 7 * 86400000,
      sessionIdleTimeoutMs: 86400000,
      now: () => clock,
    },
    permissions: { actions: ['documents:read'] },
    resolveResource: async (reference) => reference,
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const generator = authenticator.clone();
  generator.options = { epoch: clock };
  const rootSession = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: generator.generate(enrollment.secret),
  });
  const rootCredential = { token: rootSession.token };
  const created = await iam.api.tenants.create(rootCredential, {
    parentId: root.tenant.id,
    name: 'Acme',
    type: 'organization',
    ownerEmail: 'owner@acme.test',
  });
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  const tenantId = created.tenant.id;
  const ownerCredential = { token: owner.token };
  const ownerId = (await iam.api.auth.getSession(ownerCredential)).identity.id;
  const member = async (name: string) =>
    iam.api.identities.create(ownerCredential, {
      tenantId,
      email: `${name}@acme.test`,
      name,
      password: `a strong ${name} password`,
    });
  const signIn = async (name: string) => {
    const result = await iam.api.auth.signIn({
      tenantId,
      email: `${name}@acme.test`,
      password: `a strong ${name} password`,
    });
    if (!('token' in result)) throw new Error('Unexpected MFA');
    return result;
  };
  return {
    iam,
    root,
    rootCredential,
    tenantId,
    ownerCredential,
    ownerId,
    member,
    signIn,
    now: () => clock,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('impersonation', () => {
  it('is off by default, opt-in per tenant, limited to eligible members, and attributed everywhere', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const impersonate = (credential: { token: string }, identityId: string, reason = 'ticket 42') =>
      f.iam.api.identities.impersonate(credential, { tenantId: f.tenantId, identityId, reason });
    await expect(impersonate(f.ownerCredential, alice.id)).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
    });
    await expect(
      f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
        tenantId: f.tenantId,
        authPolicy: { allowImpersonation: 'yes' as never },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    // Eligibility: a reason, permission, and a target who is neither the caller nor an owner.
    await expect(impersonate(f.ownerCredential, alice.id, '')).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(impersonate(f.ownerCredential, f.ownerId)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    const aliceLogin = await f.signIn('alice');
    await expect(impersonate({ token: aliceLogin.token }, bob.id)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // Support staff get a scoped role: read members and impersonate them.
    const support = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Support',
      permissions: ['iam:identities:read', 'iam:identities:impersonate'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: support.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: support.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const bobLogin = await f.signIn('bob');
    await expect(impersonate({ token: bobLogin.token }, f.ownerId)).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    const viewAs = await f.iam.api.identities.impersonate(
      { token: bobLogin.token },
      { tenantId: f.tenantId, identityId: alice.id, reason: 'ticket 42', durationMs: 600_000 },
    );
    expect(viewAs.identity.id).toBe(alice.id);
    expect(viewAs.session).toMatchObject({
      identityId: alice.id,
      method: 'impersonation',
      impersonatorId: bob.id,
      expiresAt: f.now() + 600_000,
    });
    expect(JSON.stringify(viewAs)).not.toContain('tokenHash');
    const seen = await f.iam.api.auth.getSession({ token: viewAs.token });
    expect(seen.identity.id).toBe(alice.id);
    expect(seen.session.impersonatorId).toBe(bob.id);
    // Alice can see the support session among her own.
    const aliceSessions = await f.iam.api.auth.listSessions({ token: aliceLogin.token });
    expect(aliceSessions.filter((session) => session.method === 'impersonation')).toHaveLength(1);
    // Operations run as Alice but every record names Bob as the impersonator.
    expect(
      (
        await f.iam.api.identities.get(
          { token: viewAs.token },
          { tenantId: f.tenantId, identityId: bob.id },
        )
      ).name,
    ).toBe('bob');
    const trail = await f.iam.api.audit.list(f.ownerCredential, { tenantId: f.tenantId });
    const attributed = trail.filter((event) => event.impersonatorId === bob.id);
    expect(attributed.length).toBeGreaterThanOrEqual(2);
    expect(attributed.every((event) => event.actorId === alice.id)).toBe(true);
    expect(attributed.map((event) => event.action)).toEqual(
      expect.arrayContaining(['auth:session:create', 'iam:identities:read']),
    );
    const started = trail.find((event) => event.action === 'identity:impersonate')!;
    expect(started).toMatchObject({
      actorId: bob.id,
      resourceId: alice.id,
      metadata: { reason: 'ticket 42', sessionId: viewAs.session.id },
    });
    // Sensitive operations, re-authentication, nested impersonation, and role assumption are refused.
    await expect(
      f.iam.api.auth.changePassword(
        { token: viewAs.token },
        { currentPassword: 'a strong alice password', password: 'another strong password!' },
      ),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    await expect(
      f.iam.api.auth.reauthenticate(
        { token: viewAs.token },
        { password: 'a strong alice password' },
      ),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    await expect(impersonate({ token: viewAs.token }, bob.id)).rejects.toMatchObject({
      code: 'IMPERSONATION_RESTRICTED',
    });
    await expect(
      f.iam.api.roles.assume({ token: viewAs.token }, { tenantId: f.tenantId, trustId: 'none' }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    // Policies can tell the difference.
    const readers = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['documents:read'], resources: ['document/*'] },
          {
            effect: 'deny',
            actions: ['documents:read'],
            resources: ['document/private-*'],
            conditions: { Bool: { 'principal.impersonated': true } },
          },
        ],
      },
    });
    // A view-as session gets only what both Alice and Bob may do, so both hold the roles used below.
    for (const subjectId of [alice.id, bob.id])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: readers.id,
        subjectType: 'identity',
        subjectId,
      });
    const check = (token: string, id: string) =>
      f.iam.authorize({
        token,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id },
      });
    expect((await check(viewAs.token, 'memo')).allowed).toBe(true);
    expect((await check(viewAs.token, 'private-notes')).allowed).toBe(false);
    expect((await check(aliceLogin.token, 'private-notes')).allowed).toBe(true);
    const asserter = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Asserter',
      permissions: ['iam:assertions:create'],
    });
    for (const subjectId of [alice.id, bob.id])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: asserter.id,
        subjectType: 'identity',
        subjectId,
      });
    const assertion = await f.iam.api.assertions.issue(
      { token: viewAs.token },
      { tenantId: f.tenantId, audience: 'billing' },
    );
    expect(
      verifyAssertion(assertion.token, { key: f.iam.assertionKey(), audience: 'billing' }),
    ).toMatchObject({ sub: alice.id, impersonatorId: bob.id, method: 'impersonation' });
    // Bob signing out ends his support session immediately; Alice's own session is untouched.
    await f.iam.api.auth.signOut({ token: bobLogin.token });
    await expect(f.iam.api.auth.getSession({ token: viewAs.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect((await f.iam.api.auth.getSession({ token: aliceLogin.token })).identity.id).toBe(
      alice.id,
    );
    expect(
      (await f.iam.api.auth.listSessions({ token: aliceLogin.token })).filter(
        (session) => session.method === 'impersonation',
      ),
    ).toHaveLength(0);
  });

  it('never outlives the administrator session, protects owners and services, and issues no cookie', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const bot = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'ci-bot',
    });
    const bob = await f.member('bob');
    const support = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Support',
      permissions: ['iam:identities:read', 'iam:identities:impersonate'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: support.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true, sessionLifetimeMs: 3_600_000, maxSessions: 1 },
    });
    // Bob's session is one hour long; the request asks for eight.
    const bobLogin = await f.signIn('bob');
    await expect(
      f.iam.api.identities.impersonate(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: bot.id,
        reason: 'audit',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.identities.impersonate(f.rootCredential, {
        tenantId: f.tenantId,
        identityId: f.ownerId,
        reason: 'audit',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/identities/impersonate', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${bobLogin.token}`,
        },
        body: JSON.stringify({
          tenantId: f.tenantId,
          identityId: alice.id,
          reason: 'ticket 7',
          durationMs: 8 * 3_600_000,
        }),
      }),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('set-cookie')).toBeNull();
    const { data } = (await response.json()) as {
      data: { token: string; session: { expiresAt: number } };
    };
    expect(data.session.expiresAt).toBe(bobLogin.session.expiresAt);
    // The support session does not count toward Alice's own session cap.
    const aliceLogin = await f.signIn('alice');
    expect((await f.iam.api.auth.getSession({ token: data.token })).identity.id).toBe(alice.id);
    expect((await f.iam.api.auth.listSessions({ token: aliceLogin.token })).length).toBe(2);
    // Disabling the administrator ends the impersonation with them, and the record disappears at once.
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bob.id,
      status: 'disabled',
    });
    expect((await f.iam.api.auth.listSessions({ token: aliceLogin.token })).length).toBe(1);
    await expect(f.iam.api.auth.getSession({ token: data.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
  });

  it('mints no session token while impersonating, in process or over HTTP', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    // Both may mint session tokens in their own right, so only the impersonation can explain a refusal.
    const support = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Support',
      permissions: [
        'iam:identities:read',
        'iam:identities:impersonate',
        'iam:session-tokens:create',
      ],
    });
    for (const subjectId of [alice.id, bob.id])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: support.id,
        subjectType: 'identity',
        subjectId,
      });
    const bobLogin = await f.signIn('bob');
    const viewAs = await f.iam.api.identities.impersonate(
      { token: bobLogin.token },
      { tenantId: f.tenantId, identityId: alice.id, reason: 'ticket 99' },
    );
    // The view-as session reports who it is and who stands behind it.
    expect(await f.iam.api.sts.getCallerIdentity({ token: viewAs.token })).toMatchObject({
      identityId: alice.id,
      sessionKind: 'user',
      method: 'impersonation',
      impersonatorId: bob.id,
    });
    for (const input of [{}, { format: 'opaque' as const, sessionName: 'escape' }])
      await expect(
        f.iam.api.sts.getSessionToken({ token: viewAs.token }, input),
      ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED', status: 403 });
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/sts/getSessionToken', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${viewAs.token}`,
        },
        body: '{}',
      }),
    );
    expect(response.status).toBe(403);
    expect(response.headers.get('set-cookie')).toBeNull();
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      'IMPERSONATION_RESTRICTED',
    );
    expect(await f.iam.store.find('sessions', { kind: 'session-token' })).toEqual([]);
    // Alice and Bob in their own right still can.
    const own = await f.iam.api.sts.getSessionToken({ token: (await f.signIn('alice')).token });
    expect(own.session).toMatchObject({ kind: 'session-token', identityId: alice.id });
    expect(
      (await f.iam.api.sts.getSessionToken({ token: bobLogin.token })).session.identityId,
    ).toBe(bob.id);
  });
});
