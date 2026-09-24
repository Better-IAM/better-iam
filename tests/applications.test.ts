import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const day = 86_400_000;

async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const apps = f.iam.api.applications;
  const engineering = await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
  const alice = await f.member('alice');
  const bob = await f.member('bob');
  await f.iam.api.groups.addMember(owner, {
    tenantId,
    groupId: engineering.id,
    identityId: alice.id,
  });
  const token = async (name: string) => ({ token: (await f.signIn(name)).token });
  return { f, tenantId, owner, apps, engineering, alice, bob, token };
}

describe('application catalog', () => {
  it('shows people the apps assigned to them, their groups, or everyone, and records launches', async () => {
    const s = await scenario();
    const wiki = await s.apps.create(s.owner, {
      tenantId: s.tenantId,
      key: 'wiki',
      name: 'Wiki',
      launchUrl: 'https://wiki.acme.test/login',
      visibility: 'everyone',
      category: 'Knowledge',
    });
    const ci = await s.apps.create(s.owner, {
      tenantId: s.tenantId,
      key: 'ci',
      name: 'CI',
      launchUrl: 'https://ci.acme.test',
    });
    const payroll = await s.apps.create(s.owner, {
      tenantId: s.tenantId,
      key: 'payroll',
      name: 'Payroll',
      launchUrl: 'https://payroll.acme.test',
    });
    await s.apps.assign(s.owner, {
      tenantId: s.tenantId,
      appId: ci.id,
      subjectType: 'group',
      subjectId: s.engineering.id,
    });
    await s.apps.assign(s.owner, {
      tenantId: s.tenantId,
      appId: payroll.id,
      subjectType: 'identity',
      subjectId: s.bob.id,
      expiresAt: s.f.now() + 5 * day,
    });
    const alice = await s.token('alice');
    const bob = await s.token('bob');
    const names = async (credential: { token: string }) =>
      (await s.apps.mine(credential, { tenantId: s.tenantId }))
        .map((app) => `${app.key}:${app.via}`)
        .sort();
    expect(await names(alice)).toEqual(['ci:group', 'wiki:everyone']);
    expect(await names(bob)).toEqual(['payroll:direct', 'wiki:everyone']);
    // Launching needs the app; launches are counted.
    expect(await s.apps.launch(alice, { tenantId: s.tenantId, appId: ci.id })).toEqual({
      url: 'https://ci.acme.test/',
    });
    await expect(
      s.apps.launch(alice, { tenantId: s.tenantId, appId: payroll.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const mine = await s.apps.mine(alice, { tenantId: s.tenantId });
    expect(mine[0]).toMatchObject({ key: 'ci', lastLaunchedAt: s.f.now() });
    // Assignments end.
    s.f.advance(6 * day);
    const later = await s.token('bob');
    expect(await names(later)).toEqual(['wiki:everyone']);
    // Disabled apps disappear.
    const owner = await s.f.ownerSignIn();
    await s.apps.update(owner, { tenantId: s.tenantId, appId: wiki.id, enabled: false });
    expect(await names(later)).toEqual([]);
  });

  it('offers access requests through a requestable package', async () => {
    const s = await scenario();
    const pkg = await s.f.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Engineering tools',
      roleIds: [],
      groupIds: [s.engineering.id],
      requestable: true,
    } as never);
    const ci = await s.apps.create(s.owner, {
      tenantId: s.tenantId,
      key: 'ci',
      name: 'CI',
      launchUrl: 'https://ci.acme.test',
      requestPackageId: pkg.id,
    });
    await s.apps.assign(s.owner, {
      tenantId: s.tenantId,
      appId: ci.id,
      subjectType: 'group',
      subjectId: s.engineering.id,
    });
    const bob = await s.token('bob');
    expect(await s.apps.mine(bob, { tenantId: s.tenantId })).toEqual([
      expect.objectContaining({ key: 'ci', requestPackageId: pkg.id }),
    ]);
    expect((await s.apps.mine(bob, { tenantId: s.tenantId }))[0]!.via).toBeUndefined();
    await expect(
      s.apps.create(s.owner, {
        tenantId: s.tenantId,
        key: 'other',
        name: 'Other',
        launchUrl: 'http://insecure.example.test',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('checks assignments for sign-in pages and reports unused assignments', async () => {
    const s = await scenario();
    const crm = await s.apps.create(s.owner, {
      tenantId: s.tenantId,
      key: 'crm',
      name: 'CRM',
      launchUrl: 'https://crm.acme.test',
    });
    await s.apps.assign(s.owner, {
      tenantId: s.tenantId,
      appId: crm.id,
      subjectType: 'identity',
      subjectId: s.alice.id,
    });
    expect(
      await s.f.iam.applications.allowed({
        tenantId: s.tenantId,
        identityId: s.alice.id,
        appId: crm.id,
      }),
    ).toMatchObject({ allowed: true, governed: true });
    expect(
      await s.f.iam.applications.allowed({
        tenantId: s.tenantId,
        identityId: s.bob.id,
        appId: crm.id,
      }),
    ).toMatchObject({ allowed: false });
    expect(
      await s.f.iam.applications.allowed({
        tenantId: s.tenantId,
        identityId: s.bob.id,
        oauthClientId: 'not-in-catalog',
      }),
    ).toEqual({ allowed: true, governed: false });
    s.f.advance(100 * day);
    const owner = await s.f.ownerSignIn();
    const usage = await s.apps.usage(owner, { tenantId: s.tenantId, unusedDays: 90 });
    expect(usage[0]).toMatchObject({ key: 'crm', people: 1, launchedLast30Days: 0 });
    expect(usage[0]!.unused.map((item) => item.identityId)).toEqual([s.alice.id]);
    expect(
      await s.apps.removeUnused(owner, { tenantId: s.tenantId, appId: crm.id, unusedDays: 90 }),
    ).toEqual({
      removed: 1,
    });
    expect(
      (await s.apps.listAssignments(owner, { tenantId: s.tenantId, appId: crm.id })).length,
    ).toBe(0);
    // Members cannot manage the catalog.
    const alice = await s.token('alice');
    // Expired people have no apps even before the worker disables them.
    await s.apps.assign(owner, {
      tenantId: s.tenantId,
      appId: crm.id,
      subjectType: 'identity',
      subjectId: s.bob.id,
    });
    await s.f.iam.api.identities.update(owner, {
      tenantId: s.tenantId,
      identityId: s.bob.id,
      expiresAt: s.f.now() + 60_000,
    } as never);
    s.f.advance(120_000);
    expect(
      await s.f.iam.applications.allowed({
        tenantId: s.tenantId,
        identityId: s.bob.id,
        appId: crm.id,
      }),
    ).toMatchObject({ allowed: false });
    await expect(
      s.apps.assign(alice, {
        tenantId: s.tenantId,
        appId: crm.id,
        subjectType: 'identity',
        subjectId: s.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('keeps the catalog honest: validation, owners, names, per-app admins, cleanup', async () => {
    const s = await scenario();
    await expect(
      s.apps.create(s.owner, { tenantId: s.tenantId, key: 'x', name: 'X' } as never),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const carol = await s.f.member('carol');
    const wiki = await s.apps.create(s.owner, {
      tenantId: s.tenantId,
      key: 'wiki',
      name: 'Wiki',
      launchUrl: 'https://wiki.acme.test',
      ownerIds: [carol.id],
    });
    // A deleted owner never blocks disabling the app, and leaves the owner list.
    await s.f.iam.api.identities.delete(s.owner, { tenantId: s.tenantId, identityId: carol.id });
    const disabled = await s.apps.update(s.owner, {
      tenantId: s.tenantId,
      appId: wiki.id,
      enabled: false,
    });
    expect(disabled).toMatchObject({ enabled: false, ownerIds: [] });
    await s.apps.update(s.owner, { tenantId: s.tenantId, appId: wiki.id, enabled: true });
    // Group assignments go with the group.
    const temp = await s.f.iam.api.groups.create(s.owner, { tenantId: s.tenantId, name: 'Temp' });
    await s.apps.assign(s.owner, {
      tenantId: s.tenantId,
      appId: wiki.id,
      subjectType: 'group',
      subjectId: temp.id,
    });
    await s.apps.assign(s.owner, {
      tenantId: s.tenantId,
      appId: wiki.id,
      subjectType: 'identity',
      subjectId: s.alice.id,
    });
    await s.f.iam.api.groups.delete(s.owner, { tenantId: s.tenantId, groupId: temp.id });
    const assignments = await s.apps.listAssignments(s.owner, { tenantId: s.tenantId });
    expect(assignments.map((item) => item.subjectType)).toEqual(['identity']);
    expect(assignments[0]!.subjectName).toBe('alice@acme.test');
    // A per-app administrator (assign on this app only) sees no addresses and can remove single assignments.
    const appAdmin = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Wiki admin',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:applications:assign', 'iam:applications:read'],
            resources: [`iam/${wiki.id}`],
          },
          { effect: 'allow', actions: ['iam:applications:read'], resources: [`iam/${s.tenantId}`] },
        ],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: appAdmin.id,
      subjectType: 'identity',
      subjectId: s.bob.id,
    });
    const bob = await s.token('bob');
    const seen = await s.apps.listAssignments(bob, { tenantId: s.tenantId, appId: wiki.id });
    expect(seen[0]!.subjectName).toBeUndefined();
    expect(
      (await s.apps.usage(bob, { tenantId: s.tenantId }))[0]!.unused.every((item) => !item.name),
    ).toBe(true);
    expect(await s.apps.unassign(bob, { tenantId: s.tenantId, assignmentId: seen[0]!.id })).toEqual(
      { removed: true },
    );
    // Launches are refused while an administrator views as the person.
    await s.apps.update(s.owner, { tenantId: s.tenantId, appId: wiki.id, visibility: 'everyone' });
    await s.f.iam.api.tenants.setAuthPolicy(s.owner, {
      tenantId: s.tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const viewing = await s.f.iam.api.identities.impersonate(await s.f.ownerSignIn(), {
      tenantId: s.tenantId,
      identityId: s.alice.id,
      reason: 'ticket 7',
    });
    await expect(
      s.apps.launch({ token: viewing.token }, { tenantId: s.tenantId, appId: wiki.id }),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
  });

  it('governs OAuth clients: one app per client, the provider gate, and no silent release', async () => {
    const s = await scenario();
    // A client of the organization, as the OAuth provider registers it.
    const clientId = 'crm-client';
    await s.f.database.transaction((tx) =>
      tx.insert('oauthClients', {
        id: 'crm-client-row',
        tenantId: s.tenantId,
        clientId,
        revoked: false,
      }),
    );
    const crm = await s.apps.create(s.owner, {
      tenantId: s.tenantId,
      key: 'crm',
      name: 'CRM',
      launchUrl: 'https://crm.acme.test',
      oauthClientId: clientId,
    });
    await expect(
      s.apps.create(s.owner, {
        tenantId: s.tenantId,
        key: 'crm2',
        name: 'CRM again',
        launchUrl: 'https://crm.acme.test',
        oauthClientId: clientId,
        visibility: 'everyone',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await s.apps.assign(s.owner, {
      tenantId: s.tenantId,
      appId: crm.id,
      subjectType: 'identity',
      subjectId: s.alice.id,
    });
    const gate = s.f.iam.protocolHost.clientAllowed;
    expect(await gate(s.alice.id, s.tenantId, clientId)).toBe(true);
    expect(await gate(s.bob.id, s.tenantId, clientId)).toBe(false);
    expect(await gate(s.bob.id, s.tenantId, 'some-other-client')).toBe(true);
    // Disabling keeps refusing; releasing the client is explicit.
    await s.apps.update(s.owner, { tenantId: s.tenantId, appId: crm.id, enabled: false });
    expect(await gate(s.alice.id, s.tenantId, clientId)).toBe(false);
    await expect(
      s.apps.delete(s.owner, { tenantId: s.tenantId, appId: crm.id }),
    ).rejects.toMatchObject({
      code: 'CONFLICT',
    });
    await expect(
      s.apps.update(s.owner, { tenantId: s.tenantId, appId: crm.id, oauthClientId: '' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await s.apps.delete(s.owner, { tenantId: s.tenantId, appId: crm.id, releaseClient: true });
    expect(await gate(s.bob.id, s.tenantId, clientId)).toBe(true);
  });
});
