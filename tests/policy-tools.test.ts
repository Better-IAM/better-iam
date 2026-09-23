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
    secret: 'policy-tools-test-secret-with-at-least-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
      rateLimits: { attempts: 3 },
    },
    permissions: {
      actions: ['documents:read', 'documents:write'],
    },
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
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: generator.generate(enrollment.secret),
  });
  const created = await iam.api.tenants.create(
    { token: session.token },
    {
      parentId: root.tenant.id,
      name: 'Acme',
      type: 'organization',
      ownerEmail: 'owner@acme.test',
    },
  );
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
  return {
    iam,
    tenantId: created.tenant.id,
    ownerCredential: { token: owner.token },
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('policy tooling and account unlock', () => {
  it('restores earlier policy versions and evaluates candidate documents', async () => {
    const f = await fixture();
    const readOnly = {
      version: 1 as const,
      statements: [{ effect: 'allow' as const, actions: ['documents:read'], resources: ['*'] }],
    };
    const readWrite = {
      version: 1 as const,
      statements: [
        {
          effect: 'allow' as const,
          actions: ['documents:read', 'documents:write'],
          resources: ['document/*'],
        },
      ],
    };
    const policy = await f.iam.api.policies.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Documents',
      document: readOnly,
    });
    await f.iam.api.policies.update(f.ownerCredential, {
      tenantId: f.tenantId,
      policyId: policy.id,
      version: 1,
      document: readWrite,
    });
    await expect(
      f.iam.api.policies.restoreVersion(f.ownerCredential, {
        tenantId: f.tenantId,
        policyId: policy.id,
        version: 2,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.policies.restoreVersion(f.ownerCredential, {
        tenantId: f.tenantId,
        policyId: policy.id,
        version: 9,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const restored = await f.iam.api.policies.restoreVersion(f.ownerCredential, {
      tenantId: f.tenantId,
      policyId: policy.id,
      version: 1,
    });
    expect(restored.version).toBe(3);
    expect(restored.document).toEqual(readOnly);
    const versions = await f.iam.api.policies.listVersions(f.ownerCredential, {
      tenantId: f.tenantId,
      policyId: policy.id,
    });
    expect(versions.map((item) => item.version)).toEqual([1, 2, 3]);
    expect(versions[1]!.document).toEqual(readWrite);
    // Candidate documents evaluate against caller-supplied context without being stored.
    const conditional = {
      version: 1 as const,
      statements: [
        {
          effect: 'allow' as const,
          actions: ['documents:write'],
          resources: ['document/${principal.id}-*'],
          conditions: { Bool: { 'principal.mfa': true } },
        },
      ],
    };
    const allowed = await f.iam.api.policies.test(f.ownerCredential, {
      tenantId: f.tenantId,
      document: conditional,
      action: 'documents:write',
      resource: 'document/alice-notes',
      context: { 'principal.id': 'alice', 'principal.mfa': true },
    });
    expect(allowed.allowed).toBe(true);
    expect(allowed.matched).toHaveLength(1);
    const denied = await f.iam.api.policies.test(f.ownerCredential, {
      tenantId: f.tenantId,
      document: conditional,
      action: 'documents:write',
      resource: 'document/alice-notes',
      context: { 'principal.id': 'alice', 'principal.mfa': false },
    });
    expect(denied.allowed).toBe(false);
    await expect(
      f.iam.api.policies.test(f.ownerCredential, {
        tenantId: f.tenantId,
        document: {
          version: 1,
          statements: [{ effect: 'allow', actions: ['documents:burn'], resources: ['*'] }],
        },
        action: 'documents:burn',
        resource: 'document/x',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    expect(
      (await f.iam.api.policies.list(f.ownerCredential, { tenantId: f.tenantId })).filter(
        (item) => item.name === 'Documents',
      ),
    ).toHaveLength(1);
  });

  it('unlocks an account whose sign-in attempts are rate limited', async () => {
    const f = await fixture();
    const alice = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'alice@acme.test',
      name: 'Alice',
      password: 'a strong alice password',
    });
    const attempt = (password: string) =>
      f.iam.api.auth.signIn({ tenantId: f.tenantId, email: 'alice@acme.test', password });
    for (let index = 0; index < 3; index++)
      await expect(attempt('wrong')).rejects.toMatchObject({ code: 'INVALID_CREDENTIALS' });
    await expect(attempt('a strong alice password')).rejects.toMatchObject({
      code: 'RATE_LIMITED',
    });
    const unlocked = await f.iam.api.identities.unlock(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
    });
    expect(unlocked.supported).toBe(true);
    expect(unlocked.cleared).toBeGreaterThan(10);
    const login = await attempt('a strong alice password');
    expect('token' in login).toBe(true);
    const events = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'identity:unlock',
    });
    expect(events[0]).toMatchObject({ resourceId: alice.id, metadata: { supported: true } });
    f.advance(6 * 60_000);
    await expect(
      f.iam.api.identities.unlock(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: alice.id,
      }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
  });
});
