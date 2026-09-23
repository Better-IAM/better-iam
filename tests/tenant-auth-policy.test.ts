import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
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
    secret: 'tenant-auth-policy-test-secret-with-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      passwordlessEmail: true,
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
  const totp = (secret: string) => {
    const generator = authenticator.clone();
    generator.options = { epoch: clock };
    return generator.generate(secret);
  };
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: totp(enrollment.secret),
  });
  const credential = { token: session.token };
  const created = await iam.api.tenants.create(credential, {
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
  const member = async (name: string) =>
    iam.api.identities.create(ownerCredential, {
      tenantId,
      email: `${name}@acme.test`,
      name,
      password: `a strong ${name} password`,
    });
  const passwordless = async (email: string) => {
    await iam.api.auth.startPasswordless({
      tenantId,
      destination: email,
      channel: 'email',
      kind: 'code',
    });
    await iam.auth.dispatchOutbox();
    const message = inbox.filter((item) => item.to === email && item.template === 'code').at(-1)!;
    return iam.api.auth.finishPasswordless({
      tenantId,
      destination: email,
      token: message.payload.token!,
    });
  };
  return {
    iam,
    inbox,
    tenantId,
    ownerCredential,
    member,
    passwordless,
    totp,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('tenant authentication policy', () => {
  it('restricts sign-in methods, records the method on sessions, and exposes it to policies', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    // Validation and authorization of the policy itself.
    for (const authPolicy of [
      { allowedMethods: ['telepathy'] },
      { allowedMethods: [] },
      { requireMfa: 'yes' },
      { sessionLifetimeMs: 1000 },
      { sessionLifetimeMs: 120_000, sessionIdleTimeoutMs: 180_000 },
      { unknown: true },
    ])
      await expect(
        f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
          tenantId: f.tenantId,
          authPolicy: authPolicy as never,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const aliceLogin = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in aliceLogin)) throw new Error('Unexpected MFA');
    expect(aliceLogin.session.method).toBe('password');
    await expect(
      f.iam.api.tenants.setAuthPolicy(
        { token: aliceLogin.token },
        { tenantId: f.tenantId, authPolicy: { allowedMethods: ['passwordless-email'] } },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Only passwordless sign-in from now on. Wrong and right passwords fail identically.
    const updated = await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { allowedMethods: ['passwordless-email'] },
    });
    expect(updated.authPolicy).toEqual({ allowedMethods: ['passwordless-email'] });
    for (const password of ['a strong alice password', 'wrong'])
      await expect(
        f.iam.api.auth.signIn({ tenantId: f.tenantId, email: 'alice@acme.test', password }),
      ).rejects.toMatchObject({ code: 'METHOD_NOT_ALLOWED' });
    await expect(
      f.iam.api.auth.reauthenticate(
        { token: aliceLogin.token },
        { password: 'a strong alice password' },
      ),
    ).rejects.toMatchObject({ code: 'METHOD_NOT_ALLOWED' });
    const viaEmail = await f.passwordless('alice@acme.test');
    if (!('token' in viaEmail)) throw new Error('Unexpected MFA');
    expect(viaEmail.session.method).toBe('passwordless-email');
    expect((await f.iam.api.auth.getSession({ token: viaEmail.token })).session.method).toBe(
      'passwordless-email',
    );
    // The method reaches policies as principal.authMethod.
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Email readers',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/*'],
            conditions: { StringEquals: { 'principal.authMethod': 'passwordless-email' } },
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
    const check = (token: string) =>
      f.iam.authorize({
        token,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'memo' },
      });
    expect((await check(viaEmail.token)).allowed).toBe(true);
    expect((await check(aliceLogin.token)).allowed).toBe(false);
    // The audit trail records the policy change; clearing the policy restores password sign-in.
    const events = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'tenant:auth-policy',
    });
    expect(events[0]?.metadata).toEqual({ authPolicy: { allowedMethods: ['passwordless-email'] } });
    const cleared = await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: null,
    });
    expect(cleared.authPolicy).toBeUndefined();
    const again = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    expect('token' in again).toBe(true);
    // Changing the policy requires recent authentication.
    f.advance(6 * 60_000);
    await expect(
      f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
        tenantId: f.tenantId,
        authPolicy: { requireMfa: true },
      }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
  });

  it('caps sign-in attempts and enforces a minimum password length per tenant', async () => {
    const f = await fixture();
    await f.member('alice');
    for (const authPolicy of [
      { maxAttempts: 0 },
      { minPasswordLength: 8 },
      { minPasswordLength: 129 },
    ])
      await expect(
        f.iam.api.tenants.setAuthPolicy(f.ownerCredential, { tenantId: f.tenantId, authPolicy }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { maxAttempts: 2, minPasswordLength: 20 },
    });
    // Two failures exhaust the tenant's window even though the deployment allows ten.
    const attempt = (password: string) =>
      f.iam.api.auth.signIn({ tenantId: f.tenantId, email: 'alice@acme.test', password });
    await expect(attempt('wrong')).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(attempt('wrong')).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(attempt('a strong alice password')).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    // New passwords must satisfy the tenant minimum on every path.
    await expect(
      f.iam.api.identities.create(f.ownerCredential, {
        tenantId: f.tenantId,
        email: 'bob@acme.test',
        name: 'Bob',
        password: 'twelve chars!',
      }),
    ).rejects.toMatchObject({ code: 'WEAK_PASSWORD' });
    const bob = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      name: 'Bob',
      password: 'a much longer password for bob',
    });
    expect(bob.email).toBe('bob@acme.test');
    await expect(
      f.iam.api.auth.changePassword(f.ownerCredential, {
        currentPassword: 'a strong tenant owner password',
        password: 'short but > 12',
      }),
    ).rejects.toMatchObject({ code: 'WEAK_PASSWORD' });
  });

  it('can require MFA for owners only', async () => {
    const f = await fixture();
    await f.member('alice');
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { requireMfaForOwners: true },
    });
    // The owner's own non-MFA session stops working at its next use; members are unaffected.
    await expect(f.iam.api.auth.getSession(f.ownerCredential)).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
    });
    const owner = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'owner@acme.test',
      password: 'a strong tenant owner password',
    });
    expect('mfaRequired' in owner && owner.enrollmentRequired).toBe(true);
    const alice = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    expect('token' in alice).toBe(true);
    // The owner enrolls from the challenge and is back in with an MFA session.
    if (!('mfaRequired' in owner)) throw new Error('unreachable');
    const enrollment = await f.iam.api.auth.beginMfa({
      tenantId: f.tenantId,
      challenge: owner.challenge,
    });
    const confirmed = await f.iam.api.auth.confirmMfa({
      credential: { tenantId: f.tenantId, challenge: owner.challenge },
      code: f.totp(enrollment.secret),
    });
    expect(confirmed.session.mfa).toBe(true);
    await expect(f.iam.api.auth.disableMfa({ token: confirmed.token })).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
    });
    // Usage reports adoption: the owner now has a factor, Alice does not.
    const usage = await f.iam.api.tenants.usage(
      { token: confirmed.token },
      { tenantId: f.tenantId },
    );
    expect(usage).toMatchObject({ identities: 2, mfaEnrolled: 1 });
  });

  it('caps concurrent sessions per member and lets administrators trigger password resets', async () => {
    const f = await fixture();
    const alice = await f.member('alice');
    await expect(
      f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
        tenantId: f.tenantId,
        authPolicy: { maxSessions: 0 },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { maxSessions: 2 },
    });
    const login = async () => {
      const result = await f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'alice@acme.test',
        password: 'a strong alice password',
      });
      if (!('token' in result)) throw new Error('Unexpected MFA');
      return result;
    };
    // The fixture clock is frozen, so step it: the cap evicts by creation time.
    const first = await login();
    f.advance(1000);
    const second = await login();
    f.advance(1000);
    const third = await login();
    await expect(f.iam.api.auth.getSession({ token: first.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect((await f.iam.api.auth.getSession({ token: second.token })).session.id).toBe(
      second.session.id,
    );
    expect((await f.iam.api.auth.listSessions({ token: third.token })).length).toBe(2);
    // An administrator can queue a password-reset email without the member asking for one.
    const queued = await f.iam.api.identities.requestPasswordReset(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(queued).toEqual({ queued: true, email: 'alice@acme.test' });
    await f.iam.auth.dispatchOutbox();
    const reset = f.inbox
      .filter(
        (message) => message.template === 'password-reset' && message.to === 'alice@acme.test',
      )
      .at(-1)!;
    await f.iam.api.auth.resetPassword({
      tenantId: f.tenantId,
      token: reset.payload.token!,
      password: 'a brand new alice password',
    });
    const renewed = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      password: 'a brand new alice password',
    });
    expect('token' in renewed).toBe(true);
    const events = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'identity:password-reset',
    });
    expect(events).toHaveLength(1);
  });

  it('shortens session lifetimes and requires MFA for everyone in the tenant', async () => {
    const f = await fixture();
    await f.member('bob');
    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { sessionLifetimeMs: 10 * 60_000, sessionIdleTimeoutMs: 2 * 60_000 },
    });
    const bob = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      password: 'a strong bob password',
    });
    if (!('token' in bob)) throw new Error('Unexpected MFA');
    expect(bob.session.expiresAt - bob.session.createdAt).toBe(10 * 60_000);
    // Idle timeout: 90 seconds is fine, 2 minutes of silence ends the session.
    f.advance(90_000);
    expect((await f.iam.api.auth.getSession({ token: bob.token })).session.id).toBe(bob.session.id);
    f.advance(2 * 60_000);
    await expect(f.iam.api.auth.getSession({ token: bob.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    await expect(
      f.iam.authorize({
        token: bob.token,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'memo' },
      }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    // Absolute lifetime applies even to an active session.
    const active = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      password: 'a strong bob password',
    });
    if (!('token' in active)) throw new Error('Unexpected MFA');
    for (let minute = 0; minute < 9; minute++) {
      f.advance(60_000);
      await f.iam.api.auth.getSession({ token: active.token });
    }
    f.advance(90_000);
    await expect(f.iam.api.auth.getSession({ token: active.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    // The policy applied to the owner's own session as well: it idled out during the checks above.
    await expect(
      f.iam.api.tenants.get(f.ownerCredential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    const ownerAgain = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'owner@acme.test',
      password: 'a strong tenant owner password',
    });
    if (!('token' in ownerAgain)) throw new Error('Unexpected MFA');
    const ownerCredential = { token: ownerAgain.token };
    // Requiring MFA: new sign-ins must enroll, and the owner's own non-MFA session is locked out until it does.
    await f.iam.api.tenants.setAuthPolicy(ownerCredential, {
      tenantId: f.tenantId,
      authPolicy: { requireMfa: true },
    });
    await expect(
      f.iam.api.tenants.get(ownerCredential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'MFA_REQUIRED' });
    const challenge = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'bob@acme.test',
      password: 'a strong bob password',
    });
    if (!('mfaRequired' in challenge)) throw new Error('MFA should be required');
    expect(challenge.enrollmentRequired).toBe(true);
    const enrollment = await f.iam.api.auth.beginMfa({
      tenantId: f.tenantId,
      challenge: challenge.challenge,
    });
    const enrolled = await f.iam.api.auth.confirmMfa({
      credential: { tenantId: f.tenantId, challenge: challenge.challenge },
      code: f.totp(enrollment.secret),
    });
    expect(enrolled.session.mfa).toBe(true);
    expect(enrolled.session.method).toBe('password');
    // The tenant policy forbids disabling MFA afterwards.
    await expect(f.iam.api.auth.disableMfa({ token: enrolled.token })).rejects.toMatchObject({
      code: 'MFA_REQUIRED',
    });
  });
});
