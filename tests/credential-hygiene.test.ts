import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('API key hygiene', () => {
  it('labels keys, records their last use, finds unused ones, and relabels or re-expires them', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const account = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'ci' });
    await expect(
      f.iam.api.credentials.create(owner, {
        tenantId,
        identityId: account.id,
        name: 'x'.repeat(129),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const issued = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: account.id,
      name: 'deploy',
      description: 'GitHub Actions',
    });
    expect(issued.name).toBe('deploy');
    const listed = await f.iam.api.credentials.list(owner, { tenantId });
    expect(listed).toHaveLength(1);
    expect(listed[0]).toMatchObject({
      id: issued.credentialId,
      identityId: account.id,
      name: 'deploy',
      description: 'GitHub Actions',
      expired: false,
    });
    expect(listed[0]!.lastUsedAt).toBeUndefined();
    expect(JSON.stringify(listed)).not.toContain('tokenHash');
    const use = () =>
      f.iam.authorize({
        token: issued.token,
        tenantId,
        action: 'documents:read',
        resource: { type: 'documents', id: 'a' },
      });
    await use();
    // Use within a minute of creation is not written back (write throttling).
    const get = () =>
      f.iam.api.credentials.get(owner, { tenantId, credentialId: issued.credentialId });
    expect((await get()).lastUsedAt).toBeUndefined();
    f.advance(61_000);
    await use();
    expect((await get()).lastUsedAt).toBe(f.now());
    // Only API keys are credentials.
    const session = await f.iam.api.auth.getSession(owner);
    await expect(
      f.iam.api.credentials.get(owner, { tenantId, credentialId: session.session.id }),
    ).rejects.toMatchObject({ code: 'INVALID_CREDENTIAL' });
    // Hygiene report: keys that have not been used for a day.
    await f.iam.api.credentials.create(owner, { tenantId, identityId: account.id, name: 'stale' });
    f.advance(day);
    const fresh = await f.ownerSignIn();
    expect(
      (await f.iam.api.credentials.list(fresh, { tenantId, unusedForMs: day }))
        .map((key) => key.name)
        .sort(),
    ).toEqual(['deploy', 'stale']);
    await use();
    expect(
      (await f.iam.api.credentials.list(fresh, { tenantId, unusedForMs: day })).map(
        (key) => key.name,
      ),
    ).toEqual(['stale']);
    expect(
      (await f.iam.api.credentials.list(fresh, { tenantId, identityId: account.id })).map(
        (key) => key.name,
      ),
    ).toEqual(['stale', 'deploy']);
    // Relabeling needs no recent authentication; moving the expiry does, and only into the next year.
    const relabeled = await f.iam.api.credentials.update(owner, {
      tenantId,
      credentialId: issued.credentialId,
      name: 'deploy-prod',
      description: null,
    });
    expect(relabeled).toMatchObject({ name: 'deploy-prod' });
    expect(relabeled.description).toBeUndefined();
    await expect(
      f.iam.api.credentials.update(owner, {
        tenantId,
        credentialId: issued.credentialId,
        expiresAt: f.now() + 3_600_000,
      }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    await expect(
      f.iam.api.credentials.update(fresh, {
        tenantId,
        credentialId: issued.credentialId,
        expiresAt: f.now() - 1,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.credentials.update(fresh, {
        tenantId,
        credentialId: issued.credentialId,
        expiresAt: f.now() + 400 * day,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.credentials.update(fresh, { tenantId, credentialId: issued.credentialId }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const shortened = await f.iam.api.credentials.update(fresh, {
      tenantId,
      credentialId: issued.credentialId,
      expiresAt: f.now() + 3_600_000,
    });
    expect(shortened.expiresAt).toBe(f.now() + 3_600_000);
    f.advance(3_600_001);
    await expect(use()).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
    expect(
      (await f.iam.api.credentials.get(fresh, { tenantId, credentialId: issued.credentialId }))
        .expired,
    ).toBe(true);
    // Rotation keeps the label and expiry but starts the usage history over.
    const admin = await f.ownerSignIn();
    const stale = (await f.iam.api.credentials.list(admin, { tenantId })).find(
      (key) => key.name === 'stale',
    )!;
    const rotated = await f.iam.api.credentials.rotate(admin, {
      tenantId,
      credentialId: stale.id,
    });
    expect(rotated.name).toBe('stale');
    const replacement = await f.iam.api.credentials.get(admin, {
      tenantId,
      credentialId: rotated.credentialId,
    });
    expect(replacement).toMatchObject({ name: 'stale', expiresAt: stale.expiresAt });
    expect(replacement.lastUsedAt).toBeUndefined();
    expect((await f.iam.api.credentials.list(admin, { tenantId })).map((key) => key.id)).toEqual([
      rotated.credentialId,
      issued.credentialId,
    ]);
  });
});
