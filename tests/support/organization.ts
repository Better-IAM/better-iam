import { createRequire } from 'node:module';
import { betterIam, type BetterIamOptions } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(
  new URL('../../packages/auth/package.json', import.meta.url),
)('otplib');

const open: IamStore[] = [];
/** Closes every database a fixture opened; register it with `afterEach`. */
export async function closeFixtures(): Promise<void> {
  for (const database of open.splice(0)) await database.close();
}

/**
 * A bootstrapped platform with one organization ("Acme") whose owner has accepted the invitation: the common
 * starting point for feature tests. The clock is controllable through `advance`; sessions last seven days so
 * tests can jump ahead, and `ownerSignIn` issues a fresh (recently authenticated) owner session after a jump.
 */
export async function organizationFixture(overrides: Partial<BetterIamOptions> = {}) {
  const database = sqliteAdapter({ filename: ':memory:' });
  open.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'organization-fixture-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    permissions: { actions: ['documents:read', 'documents:write'] },
    resolveResource: async (reference) => reference,
    ...overrides,
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      sessionLifetimeMs: 7 * 86400000,
      sessionIdleTimeoutMs: 7 * 86400000,
      now: () => clock,
      ...overrides.authentication,
    },
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
    database,
    inbox,
    root,
    rootCredential,
    tenantId,
    ownerCredential,
    ownerId,
    /** Creates a person `{name}@acme.test` with a password, as the owner. */
    member: (name: string, extra: { expiresAt?: number } = {}) =>
      iam.api.identities.create(ownerCredential, {
        tenantId,
        email: `${name}@acme.test`,
        name,
        password: `a strong ${name} password`,
        ...extra,
      }),
    signIn,
    /** A fresh owner session, recently authenticated. */
    ownerSignIn: async () => {
      const result = await iam.api.auth.signIn({
        tenantId,
        email: 'owner@acme.test',
        password: 'a strong tenant owner password',
      });
      if (!('token' in result)) throw new Error('Unexpected owner MFA');
      return { token: result.token };
    },
    /** A fresh root administrator session (password and TOTP), for tests that move the clock past the first one. */
    rootSignIn: async () => {
      const again = await iam.api.auth.signIn({
        tenantId: root.tenant.id,
        email: 'root@example.test',
        password: 'a strong root test password',
      });
      if (!('mfaRequired' in again)) throw new Error('Root must require MFA');
      const code = authenticator.clone();
      code.options = { epoch: clock };
      const verified = await iam.api.auth.verifyMfa({
        tenantId: root.tenant.id,
        challenge: again.challenge,
        code: code.generate(enrollment.secret),
      });
      return { token: verified.token };
    },
    now: () => clock,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}
export type OrganizationFixture = Awaited<ReturnType<typeof organizationFixture>>;
