import { afterEach, describe, expect, it } from 'vitest';
import { verifyAuditChain, type AuditEvent, type Session } from '@better-iam/core';
import type { WebhookDelivery } from '@better-iam/server';
import { auditSessionContext } from '../packages/server/src/temporary-credentials.js';
import { webhookBody } from '../packages/server/src/events.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/**
 * Audit events (and their webhook bodies) record which session acted: its id and kind, and for role sessions the
 * role, trust, source tenant and session name. Events recorded without a principal carry none, and the hash chain
 * covers the new field.
 */

async function events(f: OrganizationFixture, action: string): Promise<AuditEvent[]> {
  return (await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId })).filter(
    (event) => event.action === action,
  );
}

/** A role in Acme that may create groups, and a same-tenant trust (no MFA) from the owner to it. */
async function groupCreatorTrust(f: OrganizationFixture) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Group creator',
    permissions: ['iam:groups:create'],
  });
  const trust = await f.iam.api.trust.create(f.rootCredential, {
    tenantId: f.tenantId,
    sourceTenantId: f.tenantId,
    sourceIdentityId: f.ownerId,
    roleId: role.id,
    requireMfa: false,
  });
  return { role, trust };
}

describe('audit session context', () => {
  it('records the session behind user, API-key and role actions', async () => {
    const f = await organizationFixture();
    // A user session.
    const owner = await f.ownerSignIn();
    const ownerSession = (await f.iam.authenticate(owner)).session;
    await f.iam.api.groups.create(owner, { tenantId: f.tenantId, name: 'By owner' });
    // An API key of a service account allowed to create groups.
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'provisioner',
    });
    const creator = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Provisioner',
      permissions: ['iam:groups:create'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: creator.id,
      subjectType: 'identity',
      subjectId: account.id,
    });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: account.id,
    });
    await f.iam.api.groups.create({ token: key.token }, { tenantId: f.tenantId, name: 'By key' });
    // A role session with a session name.
    const { role, trust } = await groupCreatorTrust(f);
    const assumed = await f.iam.api.roles.assume(owner, {
      tenantId: f.tenantId,
      trustId: trust.id,
      sessionName: 'nightly-sync',
    });
    await f.iam.api.groups.create(
      { token: assumed.token },
      { tenantId: f.tenantId, name: 'By role' },
    );

    const created = await events(f, 'iam:groups:create');
    expect(created).toHaveLength(3);
    const [byOwner, byKey, byRole] = created.sort((a, b) => a.sequence! - b.sequence!);
    expect(byOwner!.sessionContext).toEqual({ sessionId: ownerSession.id, kind: 'user' });
    expect(byKey!.sessionContext).toEqual({ sessionId: key.credentialId, kind: 'api-key' });
    expect(byRole!.actorId).toBe(f.ownerId);
    expect(byRole!.sessionContext).toEqual({
      sessionId: assumed.session.id,
      kind: 'role',
      roleId: role.id,
      trustId: trust.id,
      sourceTenantId: f.tenantId,
      sessionName: 'nightly-sync',
    });
    // Denials carry the context too.
    await expect(
      f.iam.api.groups.list({ token: key.token }, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await events(f, 'iam:groups:read')).at(-1)).toMatchObject({
      outcome: 'deny',
      sessionContext: { sessionId: key.credentialId, kind: 'api-key' },
    });
    // No hash, policy or authority id ever appears in the context.
    const projection = [
      'sessionId',
      'kind',
      'roleId',
      'trustId',
      'sourceTenantId',
      'sessionName',
      'sourceIdentity',
      'webIdentityProviderId',
      'webIdentitySubject',
      'format',
    ];
    for (const event of await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId }))
      for (const name of Object.keys(event.sessionContext ?? {}))
        expect(projection).toContain(name);
    // The chain covers the new field and stays valid.
    const chain = await f.iam.store.find<AuditEvent>('audit', { tenantId: f.tenantId });
    expect(await verifyAuditChain(chain)).toMatchObject({ valid: true, checked: chain.length });

    // Tampering with a stored event's session context, rewriting or dropping it, breaks the chain at that event.
    const verify = () => f.iam.api.audit.verify(f.ownerCredential, { tenantId: f.tenantId });
    expect(await verify()).toMatchObject({ valid: true });
    const target = byRole!;
    const tampered: AuditEvent[] = [
      { ...target, sessionContext: { ...target.sessionContext!, sessionName: 'forged' } },
      { ...target, sessionContext: { sessionId: target.sessionContext!.sessionId, kind: 'user' } },
    ];
    const stripped: AuditEvent = { ...target };
    delete stripped.sessionContext;
    tampered.push(stripped);
    for (const forged of tampered) {
      await f.database.transaction((tx) => tx.put('audit', forged));
      expect(await verify()).toMatchObject({
        valid: false,
        failure: { sequence: target.sequence, id: target.id, reason: 'hash-mismatch' },
      });
    }
    await f.database.transaction((tx) => tx.put('audit', target));
    expect(await verify()).toMatchObject({ valid: true });
  });

  it('leaves events recorded without a principal without context', async () => {
    const f = await organizationFixture();
    const activation = await events(f, 'tenant:activate');
    expect(activation).toHaveLength(1);
    expect(activation[0]).not.toHaveProperty('sessionContext');
  });

  it('delivers the session context in webhook bodies', async () => {
    const deliveries: WebhookDelivery[] = [];
    const f = await organizationFixture({
      events: {
        deliverWebhook: async (delivery) => {
          deliveries.push(delivery);
        },
      },
    });
    await f.iam.api.webhooks.create(f.ownerCredential, {
      tenantId: f.tenantId,
      url: 'https://hooks.example.test/iam',
      events: ['iam:groups:*', 'role:*'],
    });
    const { role, trust } = await groupCreatorTrust(f);
    const assumed = await f.iam.api.roles.assume(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      trustId: trust.id,
      sessionName: 'webhook-check',
    });
    await f.iam.api.groups.create(
      { token: assumed.token },
      { tenantId: f.tenantId, name: 'Hooked' },
    );
    await f.iam.auth.dispatchOutbox();
    const bodies = deliveries.map(
      (delivery) => JSON.parse(delivery.body) as Record<string, unknown>,
    );
    const expected = {
      sessionId: assumed.session.id,
      kind: 'role',
      roleId: role.id,
      trustId: trust.id,
      sourceTenantId: f.tenantId,
      sessionName: 'webhook-check',
    };
    expect(bodies.find((body) => body.type === 'iam:groups:create')).toMatchObject({
      actorId: f.ownerId,
      sessionContext: expected,
    });
    expect(bodies.find((body) => body.type === 'role:assumed')).toMatchObject({
      resourceId: role.id,
      sessionContext: expected,
    });
  });

  it('projects sessions as an allowlist', () => {
    const base: Session = {
      id: 'session-1',
      tenantId: 'tenant-1',
      identityId: 'identity-1',
      tokenHash: 'a'.repeat(64),
      uniqueKey: 'a'.repeat(64),
      createdAt: 1,
      expiresAt: 2,
      lastSeenAt: 1,
      authenticatedAt: 1,
      mfa: false,
      kind: 'role',
      roleId: 'role-1',
      trustId: 'trust-1',
      sourceSessionId: 'source-1',
      sourceAuthorityIds: ['authority-1'],
      credentialAuthorityId: 'authority-2',
      policy: { version: 1, statements: [] },
      sessionTags: { team: 'secret' },
      format: 'jwt',
      webIdentity: {
        providerId: 'provider-1',
        issuer: 'https://idp.test',
        subject: 's'.repeat(300),
      },
      sessionName: 'ci-run',
      sourceIdentity: 'repo:acme/app',
    };
    expect(auditSessionContext(base)).toEqual({
      sessionId: 'session-1',
      kind: 'role',
      roleId: 'role-1',
      trustId: 'trust-1',
      sessionName: 'ci-run',
      sourceIdentity: 'repo:acme/app',
      webIdentityProviderId: 'provider-1',
      webIdentitySubject: 's'.repeat(256),
      format: 'jwt',
    });
    expect(auditSessionContext({ ...base, id: 'simulation' })).toBeUndefined();
    expect(auditSessionContext(undefined)).toBeUndefined();
    const opaque = { ...base };
    delete opaque.format;
    expect(auditSessionContext(opaque)).not.toHaveProperty('format');
    const event: AuditEvent = {
      id: 'event-1',
      tenantId: 'tenant-1',
      actorId: 'identity-1',
      action: 'iam:groups:create',
      resourceId: 'tenant-1',
      timestamp: 1,
      outcome: 'allow',
    };
    expect(webhookBody(event)).not.toHaveProperty('sessionContext');
    expect(
      webhookBody({ ...event, sessionContext: { sessionId: 'session-1', kind: 'api-key' } }),
    ).toMatchObject({ sessionContext: { sessionId: 'session-1', kind: 'api-key' } });
  });
});
