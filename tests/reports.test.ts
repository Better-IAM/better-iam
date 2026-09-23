import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('access report', () => {
  it('collects expiring identities and bindings, live activations, pending requests, and unused keys', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const contractor = await f.member('contractor', { expiresAt: f.now() + 5 * day });
    await f.member('later', { expiresAt: f.now() + 90 * day });
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const member = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Member',
      permissions: ['iam:bindings:activate'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: member.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const temporary = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: contractor.id,
      expiresAt: f.now() + 5 * day,
    });
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      window: { from: '00:00', to: '23:59', timeZone: 'UTC' },
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const account = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'ci' });
    const stale = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: account.id,
      name: 'stale',
      expiresInSeconds: 20 * 86400,
    });
    const fresh = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: account.id,
      name: 'fresh',
    });
    f.advance(2 * day);
    await f.iam.authorize({
      token: fresh.token,
      tenantId,
      action: 'documents:read',
      resource: { type: 'documents', id: 'a' },
    });
    // Activated now, so the one-hour default is still live when the report runs.
    const activation = await f.iam.api.bindings.activate(asAlice, {
      tenantId,
      bindingId: eligible.id,
      justification: 'report',
    });
    const admin = await f.ownerSignIn();
    const report = await f.iam.api.reports.access(admin, {
      tenantId,
      withinMs: 30 * day,
      unusedForMs: day,
    });
    expect(report.omitted).toEqual([]);
    // Owner, alice, contractor, later, and the service account.
    expect(report.identities.total).toBe(5);
    expect(report.identities.expiring.map((item) => [item.id, item.expired])).toEqual([
      [contractor.id, false],
    ]);
    // The owner's protected binding, Member, the temporary Reader, and the eligible Reader.
    expect(report.bindings).toMatchObject({
      total: 4,
      eligible: 1,
      windowed: 1,
      pendingRequests: 0,
    });
    expect(report.bindings!.expiring.map((item) => item.id)).toEqual([temporary.id]);
    expect(report.bindings!.expiring[0]).toMatchObject({
      roleName: 'Reader',
      subjectName: 'contractor',
      eligible: false,
    });
    expect(report.bindings!.activations).toEqual([
      expect.objectContaining({
        id: activation.id,
        identityName: 'alice',
        roleName: 'Reader',
        justification: 'report',
      }),
    ]);
    expect(report.credentials!.total).toBe(2);
    expect(report.credentials!.unused.map((key) => key.name)).toEqual(['stale']);
    expect(report.credentials!.expiring.map((key) => key.name)).toEqual(['stale']);
    expect(report.credentials!.unused[0]!.id).toBe(stale.credentialId);
    // Past the deadline the identity is reported as expired until the worker disables it.
    f.advance(4 * day);
    const later = await f.iam.api.reports.access(await f.ownerSignIn(), { tenantId });
    expect(later.identities.expiring.map((item) => [item.id, item.expired])).toEqual([
      [contractor.id, true],
    ]);
    expect(later.bindings!.activations).toEqual([]);
    // A caller without the binding and credential permissions gets those sections omitted.
    const viewer = await f.iam.api.roles.create(admin, {
      tenantId,
      name: 'Directory viewer',
      permissions: ['iam:identities:read'],
    });
    const bob = await f.member('bob');
    await f.iam.api.bindings.create(admin, {
      tenantId,
      roleId: viewer.id,
      subjectType: 'identity',
      subjectId: bob.id,
    });
    const partial = await f.iam.api.reports.access(
      { token: (await f.signIn('bob')).token },
      { tenantId },
    );
    expect(partial.omitted).toEqual(['bindings', 'credentials']);
    expect(partial.bindings).toBeUndefined();
    expect(partial.identities.total).toBe(6);
    await expect(f.iam.api.reports.access(asAlice, { tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(f.iam.api.reports.access(admin, { tenantId, withinMs: -1 })).rejects.toMatchObject(
      { code: 'INVALID_INPUT' },
    );
  });
});
