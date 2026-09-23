import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('access digest', () => {
  it('emails owners of organizations with findings, once per interval, and records it', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    // Nothing to report anywhere yet: every tenant is quiet.
    const quiet = await f.iam.sendAccessDigest({ withinMs: 30 * day });
    expect(quiet.sent).toEqual([]);
    expect(quiet.skipped.quiet).toBe(2);
    const contractor = await f.member('contractor', { expiresAt: f.now() + 10 * day });
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId,
      name: 'ci',
    });
    await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId,
      identityId: account.id,
      name: 'stale',
    });
    f.advance(2 * day);
    const first = await f.iam.sendAccessDigest({ withinMs: 30 * day, unusedForMs: day });
    expect(first.sent).toEqual([
      {
        tenantId,
        recipients: 1,
        expiringIdentities: 1,
        expiringBindings: 0,
        startingBindings: 0,
        expiringMemberships: 0,
        activations: 0,
        pendingRequests: 0,
        unusedKeys: 1,
        expiringKeys: 0,
      },
    ]);
    expect(first.skipped).toEqual({ inactive: 0, recent: 0, quiet: 1, noOwners: 0 });
    await f.iam.auth.dispatchOutbox();
    const digests = f.inbox.filter((message) => message.template === 'access-digest');
    expect(digests).toHaveLength(1);
    expect(digests[0]).toMatchObject({
      to: 'owner@acme.test',
      tenantId,
      payload: { tenantName: 'Acme', expiringIdentities: '1', unusedKeys: '1' },
    });
    const embedded = JSON.parse(digests[0]!.payload.report!);
    expect(embedded.identities.expiring[0].id).toBe(contractor.id);
    const trail = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId,
      action: 'tenant:access-digest',
    });
    expect(trail[0]).toMatchObject({
      actorId: 'deployment-operator',
      metadata: { recipients: 1, expiringIdentities: 1 },
    });
    // Within the interval the tenant is skipped; after it (or with a zero interval) it is digested again.
    const again = await f.iam.sendAccessDigest({ withinMs: 30 * day, unusedForMs: day });
    expect(again.sent).toEqual([]);
    expect(again.skipped.recent).toBe(1);
    const forced = await f.iam.sendAccessDigest({
      tenantId,
      withinMs: 30 * day,
      unusedForMs: day,
      minimumIntervalMs: 0,
    });
    expect(forced.sent).toHaveLength(1);
    expect(forced.skipped.quiet).toBe(0);
    await expect(f.iam.sendAccessDigest({ tenantId, minimumIntervalMs: -1 })).rejects.toMatchObject(
      { code: 'INVALID_INPUT' },
    );
    await expect(f.iam.sendAccessDigest({ tenantId: 'missing' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it('needs an email transport', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    const iam = betterIam({
      database,
      secret: 'access-digest-secret-with-32-characters!',
      baseURL: 'http://localhost:3000',
    });
    try {
      await iam.initialize();
      await expect(iam.sendAccessDigest()).rejects.toMatchObject({ code: 'DELIVERY_REQUIRED' });
    } finally {
      await database.close();
    }
  });
});
