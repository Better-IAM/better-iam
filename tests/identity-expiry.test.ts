import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('identity expiry', () => {
  it('schedules deactivation, refuses expired credentials, and lets the worker disable the identity', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    await expect(f.member('alice', { expiresAt: f.now() - 1 })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(f.member('alice', { expiresAt: f.now() + 11 * 365 * day })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    const alice = await f.member('alice', { expiresAt: f.now() + 2 * day });
    expect(alice.expiresAt).toBe(f.now() + 2 * day);
    const login = await f.signIn('alice');
    const check = (token: string) =>
      f.iam.authorize({
        token,
        tenantId,
        action: 'documents:read',
        resource: { type: 'documents', id: 'a' },
      });
    // Before the expiry the credential resolves (the decision itself is a plain denial: no role yet).
    expect((await check(login.token)).allowed).toBe(false);
    // Expiry reports: who deactivates within three days, and within one.
    expect(
      (
        await f.iam.api.identities.list(f.ownerCredential, {
          tenantId,
          expiresBefore: f.now() + 3 * day,
        })
      ).map((identity) => identity.id),
    ).toEqual([alice.id]);
    expect(
      await f.iam.api.identities.list(f.ownerCredential, {
        tenantId,
        expiresBefore: f.now() + day,
      }),
    ).toEqual([]);
    // Extending and shortening before the deadline.
    const extended = await f.iam.api.identities.update(f.ownerCredential, {
      tenantId,
      identityId: alice.id,
      expiresAt: f.now() + 3 * day,
    });
    expect(extended.expiresAt).toBe(f.now() + 3 * day);
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId,
      identityId: alice.id,
      expiresAt: f.now() + 2 * day,
    });
    f.advance(2 * day + 1);
    // Past the deadline every use of her session is refused, even before the worker runs.
    await expect(check(login.token)).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    const owner = await f.ownerSignIn();
    expect((await f.iam.api.identities.get(owner, { tenantId, identityId: alice.id })).status).toBe(
      'active',
    );
    await expect(
      f.iam.api.identities.setStatus(owner, {
        tenantId,
        identityId: alice.id,
        status: 'active',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const purge = await f.iam.purgeDeleted();
    expect(purge.expiredIdentities).toBe(1);
    expect(purge.expiredActivations).toBe(0);
    expect((await f.iam.api.identities.get(owner, { tenantId, identityId: alice.id })).status).toBe(
      'disabled',
    );
    expect(
      await f.iam.api.identities.listSessions(owner, { tenantId, identityId: alice.id }),
    ).toEqual([]);
    const trail = await f.iam.api.audit.list(owner, { tenantId, action: 'identity:expire' });
    expect(trail).toHaveLength(1);
    expect(trail[0]).toMatchObject({
      actorId: 'deployment-operator',
      resourceId: alice.id,
      metadata: { kind: 'user' },
    });
    // A second run changes nothing.
    expect((await f.iam.purgeDeleted()).expiredIdentities).toBe(0);
    // Clearing the deadline lets an administrator re-enable the account.
    await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: alice.id,
      expiresAt: null,
    });
    const enabled = await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: alice.id,
      status: 'active',
    });
    expect(enabled.status).toBe('active');
    expect(enabled.expiresAt).toBeUndefined();
    const again = await f.signIn('alice');
    expect((await check(again.token)).allowed).toBe(false);
    // The final owner cannot be scheduled away.
    await expect(
      f.iam.api.identities.update(owner, {
        tenantId,
        identityId: f.ownerId,
        expiresAt: f.now() + day,
      }),
    ).rejects.toMatchObject({ code: 'LAST_OWNER' });
    // Nothing else changed on the identity record.
    expect(
      await f.iam.api.identities.update(owner, { tenantId, identityId: alice.id, name: 'Alice' }),
    ).toMatchObject({ name: 'Alice', status: 'active' });
  });

  it('expires service accounts with their keys, and bulk creation accepts a deadline', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const account = await f.iam.api.serviceAccounts.create(f.ownerCredential, {
      tenantId,
      name: 'ci',
      expiresAt: f.now() + 120_000,
    });
    expect(account.expiresAt).toBe(f.now() + 120_000);
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId,
      identityId: account.id,
      name: 'deploy',
    });
    const check = () =>
      f.iam.authorize({
        token: key.token,
        tenantId,
        action: 'documents:read',
        resource: { type: 'documents', id: 'a' },
      });
    expect((await check()).allowed).toBe(false);
    f.advance(120_001);
    await expect(check()).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    await expect(
      f.iam.api.credentials.create(f.ownerCredential, { tenantId, identityId: account.id }),
    ).rejects.toMatchObject({ code: 'INVALID_IDENTITY' });
    await expect(
      f.iam.api.serviceAccounts.setStatus(f.ownerCredential, {
        tenantId,
        identityId: account.id,
        status: 'active',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // Extending the deadline restores the key without reissuing it.
    const updated = await f.iam.api.serviceAccounts.update(f.ownerCredential, {
      tenantId,
      identityId: account.id,
      expiresAt: f.now() + 3_600_000,
    });
    expect(updated.expiresAt).toBe(f.now() + 3_600_000);
    expect((await check()).allowed).toBe(false);
    const cleared = await f.iam.api.serviceAccounts.update(f.ownerCredential, {
      tenantId,
      identityId: account.id,
      expiresAt: null,
    });
    expect(cleared.expiresAt).toBeUndefined();
    const bulk = await f.iam.api.identities.createMany(f.ownerCredential, {
      tenantId,
      identities: [
        { email: 'temp@acme.test', name: 'Temp', expiresAt: f.now() + 60_000 },
        { email: 'perm@acme.test', name: 'Perm' },
      ],
    });
    expect(bulk.identities.map((identity) => identity.expiresAt)).toEqual([
      f.now() + 60_000,
      undefined,
    ]);
    expect(
      (
        await f.iam.api.identities.list(f.ownerCredential, {
          tenantId,
          expiresBefore: f.now() + 60_000,
        })
      ).map((identity) => identity.email),
    ).toEqual(['temp@acme.test']);
  });
});
