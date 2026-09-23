import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { AuditEvent, IamStore, Identity } from '@better-iam/core';
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
  const iam = betterIam({
    database,
    secret: 'federated-attributes-test-secret-32-chars!!',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    permissions: { identityAttributes: { department: 'string', level: 'number' } },
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
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
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
  return { iam, database, tenantId: created.tenant.id, ownerCredential: { token: owner.token } };
}

describe('federated identity attributes and audit pruning', () => {
  it('stores mapped attributes on every federated sign-in after validating them', async () => {
    const f = await fixture();
    const login = (attributes?: Record<string, unknown>) =>
      f.iam.protocolHost.completeAuthentication({
        tenantId: f.tenantId,
        providerId: 'corp-sso',
        issuer: 'https://idp.example.test',
        subject: 'u-123',
        email: 'alice@acme.test',
        emailVerified: true,
        name: 'Alice',
        attributes,
      });
    const first = await login({ department: 'finance', level: 2 });
    if (!('token' in first)) throw new Error('Unexpected MFA');
    expect(first.session.method).toBe('federated');
    const stored = async () =>
      (await f.database.get<Identity>('identities', first.session.identityId))!.attributes;
    expect(await stored()).toEqual({ department: 'finance', level: 2 });
    // The next sign-in replaces the attributes; a sign-in without a mapping leaves them alone.
    await login({ department: 'ops' });
    expect(await stored()).toEqual({ department: 'ops' });
    await login();
    expect(await stored()).toEqual({ department: 'ops' });
    // Undeclared or mistyped attributes are rejected and the sign-in fails closed.
    await expect(login({ badge: 'gold' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(login({ level: 'high' })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await stored()).toEqual({ department: 'ops' });
    // Attributes reach policies as principal.{name}.
    expect(
      (
        await f.iam.api.policies.effectiveActions(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: first.session.identityId,
          resource: { type: 'iam', id: f.tenantId },
          actions: ['iam:identities:read'],
        })
      ).results,
    ).toHaveLength(1);
  });

  it('prunes old audit events behind a checkpoint that keeps the chain verifiable', async () => {
    const f = await fixture();
    for (const name of ['One', 'Two', 'Three'])
      await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name });
    const before = (await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId })).length;
    expect(before).toBeGreaterThan(3);
    expect(await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 365 * 86400000 })).toEqual({
      deleted: 0,
    });
    // Events are stamped with millisecond precision; make sure the cutoff is strictly after the last one.
    await new Promise((resolve) => setTimeout(resolve, 5));
    const pruned = await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 });
    expect(pruned.deleted).toBe(before);
    expect(pruned.prunedThroughSequence).toBe(before);
    expect(pruned.prunedThroughHash).toMatch(/^[0-9a-f]{64}$/);
    const remaining = await f.database.find<AuditEvent>('audit', { tenantId: f.tenantId });
    expect(remaining).toHaveLength(1);
    expect(remaining[0]).toMatchObject({
      action: 'audit:prune',
      sequence: before + 1,
      previousHash: pruned.prunedThroughHash,
      metadata: { deleted: before, prunedThroughSequence: before },
    });
    // The chain verifies from the checkpoint onward, and later events keep linking to it.
    await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Four' });
    const verified = await f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId });
    expect(verified).toMatchObject({ valid: true, first: before + 1, unchained: 0 });
    expect(verified.checked).toBeGreaterThanOrEqual(2);
    const exported = await f.iam.api.audit.export(f.ownerCredential, { tenantId: f.tenantId });
    expect(exported.firstSequence).toBe(before + 1);
    await expect(f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: -1 })).rejects.toMatchObject(
      { code: 'INVALID_INPUT' },
    );
  });
});
