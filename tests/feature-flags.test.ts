import { afterEach, describe, expect, it } from 'vitest';
import { lintPolicy, rolloutBucket } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/** A project under Acme whose owner has accepted the invitation. */
async function project(f: OrganizationFixture, name = 'Apollo') {
  const created = await f.iam.api.tenants.create(f.ownerCredential, {
    parentId: f.tenantId,
    name,
    type: 'project',
    ownerEmail: `${name.toLowerCase()}@acme.test`,
  });
  await f.iam.auth.dispatchOutbox();
  const invitation = f.inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await f.iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: `${name} owner`,
    password: `a strong ${name} owner password`,
  });
  if (!('token' in owner)) throw new Error('Unexpected MFA');
  return { tenantId: created.tenant.id, credential: { token: owner.token } };
}

describe('platform feature flags', () => {
  it('resolves defaults, tenant overrides, targets, locks, and the kill switch', async () => {
    const f = await organizationFixture();
    const rootId = f.root.tenant.id;
    const flag = await f.iam.api.features.create(f.rootCredential, {
      tenantId: rootId,
      key: 'new-billing',
      description: 'The new billing pages',
      tenantOverridable: true,
    });
    expect(flag).toMatchObject({
      key: 'new-billing',
      scope: 'platform',
      defaultValue: false,
      tenantOverridable: true,
      killSwitch: false,
      internal: false,
    });
    expect(await f.iam.features.isEnabled(f.tenantId, 'new-billing')).toBe(false);
    const [initial] = await f.iam.features.evaluate(f.tenantId, { keys: ['new-billing'] });
    expect(initial).toMatchObject({ reason: 'DEFAULT', overridable: true, locked: false });

    // The organization turns it on for itself.
    const chosen = await f.iam.api.features.setOverride(f.ownerCredential, {
      tenantId: f.tenantId,
      key: 'new-billing',
      value: true,
    });
    expect(chosen).toMatchObject({ value: true, reason: 'OVERRIDE', decidedBy: f.tenantId });
    expect(await f.iam.api.features.evaluate(f.ownerCredential, { tenantId: f.tenantId })).toEqual({
      tenantId: f.tenantId,
      flags: { 'new-billing': true },
    });

    // An unlocked platform target on the same tenant does not beat the tenant's own choice...
    await f.iam.api.features.setTarget(f.rootCredential, {
      tenantId: rootId,
      key: 'new-billing',
      targetTenantId: f.tenantId,
      value: false,
    });
    expect(await f.iam.features.isEnabled(f.tenantId, 'new-billing')).toBe(true);
    // ...a locked one does, and refuses new overrides until it is lifted.
    await f.iam.api.features.setTarget(f.rootCredential, {
      tenantId: rootId,
      key: 'new-billing',
      targetTenantId: f.tenantId,
      value: false,
      locked: true,
      note: 'Invoice migration pending',
    });
    const [locked] = await f.iam.features.evaluate(f.tenantId, { keys: ['new-billing'] });
    expect(locked).toMatchObject({
      value: false,
      reason: 'TARGET',
      locked: true,
      overridable: false,
    });
    await expect(
      f.iam.api.features.setOverride(f.ownerCredential, {
        tenantId: f.tenantId,
        key: 'new-billing',
        value: true,
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_LOCKED' });
    const listed = await f.iam.api.features.list(f.ownerCredential, { tenantId: f.tenantId });
    expect(listed.flags).toHaveLength(1);
    expect(listed.flags[0]).toMatchObject({
      key: 'new-billing',
      scope: 'platform',
      definedBy: rootId,
      override: { value: true },
      target: { value: false, locked: true },
    });
    // Tenants see neither the platform's settings nor its note.
    expect(listed.flags[0]!.definition).toBeUndefined();
    expect(JSON.stringify(listed)).not.toContain('Invoice migration');

    await f.iam.api.features.setTarget(f.rootCredential, {
      tenantId: rootId,
      key: 'new-billing',
      targetTenantId: f.tenantId,
      value: null,
    });
    expect(await f.iam.features.isEnabled(f.tenantId, 'new-billing')).toBe(true);

    // The kill switch wins over everything, and lifting it restores the previous state.
    await f.iam.api.features.update(f.rootCredential, {
      tenantId: rootId,
      key: 'new-billing',
      killSwitch: true,
    });
    const [killed] = await f.iam.features.evaluate(f.tenantId, { keys: ['new-billing'] });
    expect(killed).toMatchObject({ value: false, reason: 'KILL_SWITCH' });
    await f.iam.api.features.update(f.rootCredential, {
      tenantId: rootId,
      key: 'new-billing',
      killSwitch: false,
    });
    expect(await f.iam.features.isEnabled(f.tenantId, 'new-billing')).toBe(true);

    // Flags that do not allow overrides refuse them; withdrawing a choice is always allowed.
    await f.iam.api.features.update(f.rootCredential, {
      tenantId: rootId,
      key: 'new-billing',
      tenantOverridable: false,
    });
    expect(await f.iam.features.isEnabled(f.tenantId, 'new-billing')).toBe(false);
    await expect(
      f.iam.api.features.setOverride(f.ownerCredential, {
        tenantId: f.tenantId,
        key: 'new-billing',
        value: true,
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_LOCKED' });
    await f.iam.api.features.setOverride(f.ownerCredential, {
      tenantId: f.tenantId,
      key: 'new-billing',
      value: null,
    });

    // Unknown keys are off.
    expect(await f.iam.features.isEnabled(f.tenantId, 'nothing-here')).toBe(false);
    expect(
      await f.iam.api.features.evaluate(f.ownerCredential, {
        tenantId: f.tenantId,
        keys: ['nothing-here'],
      }),
    ).toEqual({ tenantId: f.tenantId, flags: { 'nothing-here': false } });
  });

  it('validates keys and settings', async () => {
    const f = await organizationFixture();
    const rootId = f.root.tenant.id;
    for (const key of ['Bad', '1st', 'a--b', 'trailing-', 'x'.repeat(65), '__proto__'])
      await expect(
        f.iam.api.features.create(f.rootCredential, { tenantId: rootId, key }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.features.create(f.rootCredential, {
        tenantId: rootId,
        key: 'on-with-rollout',
        defaultValue: true,
        rolloutPercentage: 10,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.features.create(f.rootCredential, {
        tenantId: rootId,
        key: 'hidden',
        internal: true,
        tenantOverridable: true,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.features.create(f.rootCredential, {
        tenantId: rootId,
        key: 'extra',
        colour: 'blue',
      } as never),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.features.create(f.rootCredential, { tenantId: rootId, key: 'reports.v2' });
    await expect(
      f.iam.api.features.create(f.rootCredential, { tenantId: rootId, key: 'reports.v2' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      f.iam.api.features.update(f.rootCredential, { tenantId: rootId, key: 'missing' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // A target must sit below the defining tenant.
    await expect(
      f.iam.api.features.setTarget(f.rootCredential, {
        tenantId: rootId,
        key: 'reports.v2',
        targetTenantId: rootId,
        value: true,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('tenant feature flags', () => {
  it('reach the tenant subtree, and ancestors own their keys', async () => {
    const f = await organizationFixture();
    const rootId = f.root.tenant.id;
    const apollo = await project(f);
    const flag = await f.iam.api.features.create(f.ownerCredential, {
      tenantId: f.tenantId,
      key: 'beta-reports',
      tenantOverridable: true,
    });
    expect(flag).toMatchObject({ scope: 'tenant', tenantId: f.tenantId });
    await f.iam.api.features.setTarget(f.ownerCredential, {
      tenantId: f.tenantId,
      key: 'beta-reports',
      targetTenantId: apollo.tenantId,
      value: true,
    });
    expect(await f.iam.features.isEnabled(apollo.tenantId, 'beta-reports')).toBe(true);
    expect(await f.iam.features.isEnabled(f.tenantId, 'beta-reports')).toBe(false);
    // The flag never reaches the platform tenant.
    expect(await f.iam.features.isEnabled(rootId, 'beta-reports')).toBe(false);
    // An organization cannot target outside its subtree or itself.
    for (const targetTenantId of [rootId, f.tenantId])
      await expect(
        f.iam.api.features.setTarget(f.ownerCredential, {
          tenantId: f.tenantId,
          key: 'beta-reports',
          targetTenantId,
          value: true,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // The project sees the organization's flag and its target, and may override it.
    const listed = await f.iam.api.features.list(apollo.credential, { tenantId: apollo.tenantId });
    expect(listed.flags[0]).toMatchObject({
      key: 'beta-reports',
      scope: 'tenant',
      definedBy: f.tenantId,
      target: { value: true, locked: false },
      evaluation: { value: true, reason: 'TARGET', decidedBy: apollo.tenantId },
    });
    const opted = await f.iam.api.features.setOverride(apollo.credential, {
      tenantId: apollo.tenantId,
      key: 'beta-reports',
      value: false,
    });
    expect(opted).toMatchObject({ value: false, reason: 'OVERRIDE' });
    // The defining tenant changes its own flag through update, not an override.
    await expect(
      f.iam.api.features.setOverride(f.ownerCredential, {
        tenantId: f.tenantId,
        key: 'beta-reports',
        value: true,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const targets = await f.iam.api.features.listTargets(f.ownerCredential, {
      tenantId: f.tenantId,
      key: 'beta-reports',
    });
    expect(
      targets.map((entry) => [entry.source, entry.tenantName, entry.value, entry.active]),
    ).toEqual(
      expect.arrayContaining([
        ['target', 'Apollo', true, true],
        ['override', 'Apollo', false, true],
      ]),
    );

    // Keys an ancestor defines cannot be defined again below it...
    await f.iam.api.features.create(f.rootCredential, { tenantId: rootId, key: 'sso' });
    await expect(
      f.iam.api.features.create(f.ownerCredential, { tenantId: f.tenantId, key: 'sso' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      f.iam.api.features.create(apollo.credential, {
        tenantId: apollo.tenantId,
        key: 'beta-reports',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    // ...and a platform flag created later shadows a tenant's flag of the same key: tenants cannot switch a
    // platform-gated feature on for themselves.
    await f.iam.api.features.create(f.ownerCredential, {
      tenantId: f.tenantId,
      key: 'audit-export',
      defaultValue: true,
    });
    expect(await f.iam.features.isEnabled(f.tenantId, 'audit-export')).toBe(true);
    await f.iam.api.features.create(f.rootCredential, { tenantId: rootId, key: 'audit-export' });
    expect(await f.iam.features.isEnabled(f.tenantId, 'audit-export')).toBe(false);
    const shadowed = await f.iam.api.features.list(f.ownerCredential, { tenantId: f.tenantId });
    expect(shadowed.shadowed.map((entry) => entry.key)).toEqual(['audit-export']);
    expect(shadowed.flags.find((entry) => entry.key === 'audit-export')).toMatchObject({
      scope: 'platform',
      definedBy: rootId,
    });
  });

  it('lets an organization override a platform flag for its projects', async () => {
    const f = await organizationFixture();
    const rootId = f.root.tenant.id;
    const apollo = await project(f);
    await f.iam.api.features.create(f.rootCredential, {
      tenantId: rootId,
      key: 'new-editor',
      tenantOverridable: true,
    });
    await f.iam.api.features.setOverride(f.ownerCredential, {
      tenantId: f.tenantId,
      key: 'new-editor',
      value: true,
    });
    const [inherited] = await f.iam.features.evaluate(apollo.tenantId, { keys: ['new-editor'] });
    expect(inherited).toMatchObject({ value: true, reason: 'OVERRIDE', decidedBy: f.tenantId });
    // A platform target on the project is closer than the organization's choice.
    await f.iam.api.features.setTarget(f.rootCredential, {
      tenantId: rootId,
      key: 'new-editor',
      targetTenantId: apollo.tenantId,
      value: false,
    });
    expect(await f.iam.features.isEnabled(apollo.tenantId, 'new-editor')).toBe(false);
    // A lock on the organization silences overrides in its whole subtree but not the platform's own closer target.
    await f.iam.api.features.setTarget(f.rootCredential, {
      tenantId: rootId,
      key: 'new-editor',
      targetTenantId: f.tenantId,
      value: true,
      locked: true,
    });
    await expect(
      f.iam.api.features.setOverride(apollo.credential, {
        tenantId: apollo.tenantId,
        key: 'new-editor',
        value: true,
      }),
    ).rejects.toMatchObject({ code: 'FEATURE_LOCKED' });
    expect(await f.iam.features.isEnabled(apollo.tenantId, 'new-editor')).toBe(false);
    await f.iam.api.features.setTarget(f.rootCredential, {
      tenantId: rootId,
      key: 'new-editor',
      targetTenantId: apollo.tenantId,
      value: null,
    });
    const [lockedAbove] = await f.iam.features.evaluate(apollo.tenantId, { keys: ['new-editor'] });
    expect(lockedAbove).toMatchObject({
      value: true,
      reason: 'TARGET',
      decidedBy: f.tenantId,
      locked: true,
    });
  });
});

describe('feature flag rollouts', () => {
  it('buckets whole organizations stably, and raising the percentage only adds tenants', async () => {
    const f = await organizationFixture();
    const rootId = f.root.tenant.id;
    const apollo = await project(f);
    await f.iam.api.features.create(f.rootCredential, {
      tenantId: rootId,
      key: 'fast-search',
      rolloutPercentage: 0,
    });
    const bucket = rolloutBucket('fast-search', f.tenantId);
    expect(bucket).toBeGreaterThanOrEqual(0);
    expect(bucket).toBeLessThan(100);
    expect(rolloutBucket('fast-search', f.tenantId)).toBe(bucket);
    let previous = false;
    for (const percentage of [0, 10, 25, 50, 75, 100]) {
      await f.iam.api.features.update(f.rootCredential, {
        tenantId: rootId,
        key: 'fast-search',
        rolloutPercentage: percentage,
      });
      const [organization] = await f.iam.features.evaluate(f.tenantId, { keys: ['fast-search'] });
      const [child] = await f.iam.features.evaluate(apollo.tenantId, { keys: ['fast-search'] });
      expect(organization).toMatchObject({ reason: 'ROLLOUT', value: bucket < percentage });
      // A project lands on the same side as its organization.
      expect(child!.value).toBe(organization!.value);
      if (previous) expect(organization!.value).toBe(true);
      previous = organization!.value;
    }
    expect(previous).toBe(true);
    // Clearing the rollout falls back to the default.
    await f.iam.api.features.update(f.rootCredential, {
      tenantId: rootId,
      key: 'fast-search',
      rolloutPercentage: null,
    });
    const [fallback] = await f.iam.features.evaluate(f.tenantId, { keys: ['fast-search'] });
    expect(fallback).toMatchObject({ value: false, reason: 'DEFAULT' });
  });
});

describe('feature flags in policies', () => {
  it('exposes the flags that are on as tenant.features, which applications cannot supply', async () => {
    const f = await organizationFixture({
      // An application claiming the flag must not satisfy the condition.
      resolveContext: async () => ({ 'tenant.features': ['exports'] }),
    });
    const rootId = f.root.tenant.id;
    const alice = await f.member('alice');
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Exporter',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['*'],
            conditions: { ArrayContains: { 'tenant.features': 'exports' } },
          },
        ],
      },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const aliceCredential = { token: (await f.signIn('alice')).token };
    const canRead = async () =>
      (
        await f.iam.authorize({
          ...aliceCredential,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'd1' },
        })
      ).allowed;
    expect(await canRead()).toBe(false);
    await f.iam.api.features.create(f.rootCredential, { tenantId: rootId, key: 'exports' });
    expect(await canRead()).toBe(false);
    await f.iam.api.features.setTarget(f.rootCredential, {
      tenantId: rootId,
      key: 'exports',
      targetTenantId: f.tenantId,
      value: true,
    });
    expect(await canRead()).toBe(true);
    await f.iam.api.features.update(f.rootCredential, {
      tenantId: rootId,
      key: 'exports',
      killSwitch: true,
    });
    expect(await canRead()).toBe(false);
  });

  it('is known to policy lint and filled in by policies.test', async () => {
    const f = await organizationFixture();
    const document = {
      version: 1 as const,
      statements: [
        {
          effect: 'allow' as const,
          actions: ['documents:read'],
          resources: ['*'],
          conditions: { ArrayContains: { 'tenant.features': 'exports' } },
        },
      ],
    };
    expect(lintPolicy(document)).toEqual({ valid: true, warnings: [] });
    const test = () =>
      f.iam.api.policies.test(f.ownerCredential, {
        tenantId: f.tenantId,
        document,
        action: 'documents:read',
        resource: 'document/1',
      });
    expect((await test()).allowed).toBe(false);
    await f.iam.api.features.create(f.rootCredential, {
      tenantId: f.root.tenant.id,
      key: 'exports',
      defaultValue: true,
    });
    expect((await test()).allowed).toBe(true);
  });
});

describe('feature flag access', () => {
  it('lets members evaluate their tenant, keeps management to administrators, and hides internal flags', async () => {
    const f = await organizationFixture();
    const rootId = f.root.tenant.id;
    await f.member('alice');
    const alice = { token: (await f.signIn('alice')).token };
    await f.iam.api.features.create(f.rootCredential, {
      tenantId: rootId,
      key: 'public-beta',
      defaultValue: true,
    });
    await f.iam.api.features.create(f.rootCredential, {
      tenantId: rootId,
      key: 'ops-hold',
      internal: true,
      defaultValue: true,
    });
    expect(await f.iam.api.features.evaluate(alice, { tenantId: f.tenantId })).toEqual({
      tenantId: f.tenantId,
      flags: { 'public-beta': true },
    });
    expect(
      await f.iam.api.features.evaluate(alice, { tenantId: f.tenantId, keys: ['ops-hold'] }),
    ).toEqual({ tenantId: f.tenantId, flags: { 'ops-hold': false } });
    // Trusted server code sees internal flags.
    expect(await f.iam.features.values(f.tenantId)).toEqual({
      'ops-hold': true,
      'public-beta': true,
    });
    await expect(f.iam.api.features.evaluate(alice, { tenantId: rootId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(f.iam.api.features.list(alice, { tenantId: f.tenantId })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    await expect(
      f.iam.api.features.create(alice, { tenantId: f.tenantId, key: 'mine' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Owners do not see the platform's internal flags; root administrators do.
    const ownerView = await f.iam.api.features.list(f.ownerCredential, { tenantId: f.tenantId });
    expect(ownerView.flags.map((flag) => flag.key)).toEqual(['public-beta']);
    const rootView = await f.iam.api.features.list(f.rootCredential, { tenantId: f.tenantId });
    expect(rootView.flags.map((flag) => [flag.key, flag.definition?.internal])).toEqual([
      ['ops-hold', true],
      ['public-beta', false],
    ]);
    await expect(
      f.iam.api.features.setOverride(f.ownerCredential, {
        tenantId: f.tenantId,
        key: 'ops-hold',
        value: false,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });

    // Over HTTP with a bearer token.
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/features/evaluate', {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${alice.token}`,
        },
        body: JSON.stringify({ tenantId: f.tenantId }),
      }),
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: unknown }).data).toEqual({
      tenantId: f.tenantId,
      flags: { 'public-beta': true },
    });
  });

  it('lets targets lapse, cleans up on delete, and audits every change', async () => {
    const f = await organizationFixture();
    const rootId = f.root.tenant.id;
    await f.iam.api.features.create(f.rootCredential, { tenantId: rootId, key: 'trial-seats' });
    await f.iam.api.features.setTarget(f.rootCredential, {
      tenantId: rootId,
      key: 'trial-seats',
      targetTenantId: f.tenantId,
      value: true,
      expiresAt: f.now() + 3_600_000,
    });
    const [trial] = await f.iam.features.evaluate(f.tenantId, { keys: ['trial-seats'] });
    expect(trial).toMatchObject({ value: true, reason: 'TARGET', expiresAt: f.now() + 3_600_000 });
    await expect(
      f.iam.api.features.setTarget(f.rootCredential, {
        tenantId: rootId,
        key: 'trial-seats',
        targetTenantId: f.tenantId,
        value: true,
        expiresAt: f.now() - 1,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    f.advance(2 * 3_600_000);
    expect(await f.iam.features.isEnabled(f.tenantId, 'trial-seats')).toBe(false);
    const rootCredential = f.rootCredential;
    const [lapsed] = await f.iam.api.features.listTargets(rootCredential, {
      tenantId: rootId,
      key: 'trial-seats',
    });
    expect(lapsed).toMatchObject({ tenantName: 'Acme', active: false });

    const removed = await f.iam.api.features.delete(rootCredential, {
      tenantId: rootId,
      key: 'trial-seats',
    });
    expect(removed).toEqual({ success: true, removedTargets: 1 });
    const [gone] = await f.iam.features.evaluate(f.tenantId, { keys: ['trial-seats'] });
    expect(gone).toMatchObject({ value: false, reason: 'UNKNOWN' });
    const trail = await f.iam.api.audit.list(rootCredential, {
      tenantId: rootId,
      action: 'feature:*',
    });
    expect(trail.map((event) => event.action).sort()).toEqual([
      'feature:create',
      'feature:delete',
      'feature:target',
    ]);
    expect(trail.find((event) => event.action === 'feature:target')?.metadata).toMatchObject({
      key: 'trial-seats',
      targetTenantId: f.tenantId,
      value: true,
    });
  });
});
