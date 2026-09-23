import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('API key scopes', () => {
  it('compiles a scopes list into a session policy that bounds the key', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const account = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'ci' });
    const editor = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Editor',
      permissions: ['documents:read', 'documents:write'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: editor.id,
      subjectType: 'identity',
      subjectId: account.id,
    });
    await expect(
      f.iam.api.credentials.create(owner, {
        tenantId,
        identityId: account.id,
        scopes: ['documents:read'],
        policy: { version: 1, statements: [] },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.credentials.create(owner, { tenantId, identityId: account.id, scopes: [] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.credentials.create(owner, {
        tenantId,
        identityId: account.id,
        scopes: ['nope:read'],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_ACTION' });
    const key = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: account.id,
      name: 'reader',
      scopes: ['documents:read'],
    });
    const can = async (action: string) =>
      (
        await f.iam.authorize({
          token: key.token,
          tenantId,
          action,
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed;
    expect(await can('documents:read')).toBe(true);
    expect(await can('documents:write')).toBe(false);
    const summary = await f.iam.api.credentials.get(owner, {
      tenantId,
      credentialId: key.credentialId,
    });
    expect(summary.scopes).toEqual(['documents:read']);
    expect(summary.policy?.statements[0]?.sid).toBe('KeyScopes');
    const custom = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: account.id,
      policy: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:*'], resources: ['documents/a'] }],
      },
    });
    expect(
      (await f.iam.api.credentials.get(owner, { tenantId, credentialId: custom.credentialId }))
        .scopes,
    ).toBeUndefined();
  });
});

describe('expiring bindings report', () => {
  it('lists temporary bindings that end before a given time', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const soon = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
      expiresAt: f.now() + 2 * day,
    });
    const group = await f.iam.api.groups.create(owner, { tenantId, name: 'Everyone' });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'group',
      subjectId: group.id,
      expiresAt: f.now() + 30 * day,
    });
    expect(
      (await f.iam.api.bindings.list(owner, { tenantId, expiresBefore: f.now() + 7 * day })).map(
        (binding) => binding.id,
      ),
    ).toEqual([soon.id]);
    expect(
      (await f.iam.api.bindings.list(owner, { tenantId, expiresBefore: f.now() + 60 * day }))
        .length,
    ).toBe(2);
    expect(
      await f.iam.api.bindings.list(owner, { tenantId, expiresBefore: f.now() + day }),
    ).toEqual([]);
    await expect(
      f.iam.api.bindings.list(owner, { tenantId, expiresBefore: -1 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
