import { afterEach, describe, expect, it } from 'vitest';
import { betterIam, type VaultEngine, type VaultRotator } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const HOUR = 3_600_000;
const DAY = 24 * HOUR;

/** A member holding a role with `statements`, signed in. */
async function memberWith(
  f: OrganizationFixture,
  name: string,
  statements: {
    effect: 'allow' | 'deny';
    actions: string[];
    resources: string[];
    conditions?: Record<string, Record<string, unknown>>;
  }[],
) {
  const identity = await f.member(name);
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `${name} vault role`,
    document: { version: 1, statements } as never,
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identity.id,
  });
  return { identity, credential: { token: (await f.signIn(name)).token } };
}

async function auditActions(f: OrganizationFixture, prefix = 'vault:') {
  return (await f.database.find<{ action: string; outcome: string; tenantId: string }>('audit', {}))
    .filter((event) => event.action.startsWith(prefix))
    .map((event) => `${event.action}:${event.outcome}`);
}

describe('secrets vault', () => {
  it('stores versions, moves stages, reveals, and logs access', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    const created = await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
      description: 'Primary database',
      tags: { environment: 'prod', team: 'payments' },
      value: 'first-password-value',
    });
    expect(created).toMatchObject({
      name: 'prod/db/password',
      kind: 'static',
      format: 'text',
      status: 'active',
      stages: { current: 1 },
      latestVersion: 1,
      tags: { environment: 'prod', team: 'payments' },
    });
    expect(JSON.stringify(created)).not.toContain('first-password-value');

    // Values are sealed at rest.
    const stored = JSON.stringify(await f.database.find('vaultVersions', {}));
    expect(stored).not.toContain('first-password-value');

    await vault.put(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
      value: 'second-password-value',
    });
    const revealed = await vault.reveal(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
    });
    expect(revealed).toMatchObject({ version: 2, stages: ['current'], value: 'second-password-value' });
    expect(
      (await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'prod/db/password', stage: 'previous' }))
        .value,
    ).toBe('first-password-value');

    // Staged values wait for promotion; promote also rolls back.
    const staged = await vault.put(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
      value: 'third-password-value',
      stage: 'pending',
    });
    expect(staged).toMatchObject({ version: 3, stages: ['pending'] });
    const promoted = await vault.promote(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
      version: 3,
    });
    expect(promoted.stages).toEqual({ current: 3, previous: 2 });
    await vault.promote(f.ownerCredential, { tenantId: f.tenantId, name: 'prod/db/password', version: 1 });
    expect(
      (await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'prod/db/password' })).value,
    ).toBe('first-password-value');

    // Disabled and destroyed versions are not revealed; the current version is protected.
    await expect(
      vault.setVersionState(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'prod/db/password',
        version: 1,
        state: 'disabled',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    await vault.setVersionState(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
      version: 2,
      state: 'disabled',
    });
    await expect(
      vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'prod/db/password', version: 2 }),
    ).rejects.toMatchObject({ code: 'VERSION_DISABLED' });
    await vault.destroyVersion(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
      version: 3,
    });
    await expect(
      vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'prod/db/password', version: 3 }),
    ).rejects.toMatchObject({ code: 'VERSION_DESTROYED' });
    const versions = await vault.listVersions(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
    });
    expect(versions.map((version) => [version.version, version.state, version.stages])).toEqual([
      [3, 'destroyed', []],
      [2, 'disabled', []],
      [1, 'enabled', ['current']],
    ]);

    const log = await vault.accessLog(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db/password',
    });
    // Three successful reveals and three new versions (the refused reveals are not uses).
    expect(log.map((entry) => entry.action).sort()).toEqual([
      'put',
      'put',
      'put',
      'reveal',
      'reveal',
      'reveal',
    ]);
    expect(log.every((entry) => entry.identityId === f.ownerId && entry.identityName === 'Owner')).toBe(
      true,
    );
    expect(await auditActions(f)).toEqual(
      expect.arrayContaining(['vault:create:allow', 'vault:reveal:allow', 'vault:promote:allow']),
    );
  });

  it('decides access by name and by tag, and lists only what the caller may read', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    for (const [name, team] of [
      ['team-a/api-key', 'a'],
      ['team-a/db', 'a'],
      ['team-b/api-key', 'b'],
      ['shared/smtp', 'a'],
    ])
      await vault.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name,
        tags: { team },
        value: `value of ${name}`,
      });
    const alice = await memberWith(f, 'alice', [
      { effect: 'allow', actions: ['iam:vault:read', 'iam:vault:reveal'], resources: ['iam/vault/secrets/team-a/*'] },
    ]);
    const bob = await memberWith(f, 'bob', [
      {
        effect: 'allow',
        actions: ['iam:vault:read', 'iam:vault:reveal'],
        resources: ['iam/vault/secrets/*'],
        conditions: { StringEquals: { 'resource.tag.team': 'a' } },
      },
    ]);
    expect(
      (await vault.reveal(alice.credential, { tenantId: f.tenantId, name: 'team-a/db' })).value,
    ).toBe('value of team-a/db');
    await expect(
      vault.reveal(alice.credential, { tenantId: f.tenantId, name: 'team-b/api-key' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const aliceList = await vault.list(alice.credential, { tenantId: f.tenantId });
    expect(aliceList.secrets.map((secret) => secret.name)).toEqual(['team-a/api-key', 'team-a/db']);

    // Tag conditions: bob reads every team-a secret wherever it lives, and nothing else.
    const bobList = await vault.list(bob.credential, { tenantId: f.tenantId });
    expect(bobList.secrets.map((secret) => secret.name)).toEqual([
      'shared/smtp',
      'team-a/api-key',
      'team-a/db',
    ]);
    await expect(
      vault.reveal(bob.credential, { tenantId: f.tenantId, name: 'team-b/api-key' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // A name nobody uses has no tags: the condition fails closed.
    await expect(
      vault.get(bob.credential, { tenantId: f.tenantId, name: 'team-c/new' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // Prefix and tag filters.
    const owned = await vault.list(f.ownerCredential, { tenantId: f.tenantId, prefix: 'team-' });
    expect(owned.total).toBe(3);
    const tagged = await vault.list(f.ownerCredential, { tenantId: f.tenantId, tags: { team: 'b' } });
    expect(tagged.secrets.map((secret) => secret.name)).toEqual(['team-b/api-key']);

    // Reading metadata never reveals values, and the denied reveal was audited.
    expect(JSON.stringify(bobList)).not.toContain('value of');
    expect(await auditActions(f, 'iam:vault:reveal')).toContain('iam:vault:reveal:deny');
  });

  it('rotates with a generator and a rotator, retries failures with the same value, and runs on schedule', async () => {
    const applied: { value: string; previous?: string; version: number }[] = [];
    let failNext = false;
    const rotator: VaultRotator = {
      async rotate(input) {
        if (failNext) {
          failNext = false;
          throw new Error(`database refused password ${input.value}`);
        }
        applied.push({ value: input.value, previous: input.previous, version: input.version });
      },
    };
    const f = await organizationFixture({ vault: { rotators: { postgres: rotator } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'db/app',
      value: 'initial-app-password',
      rotation: {
        intervalDays: 30,
        rotator: 'postgres',
        generator: { length: 24, charset: 'ascii', exclude: '%' },
      },
    });
    const rotated = await vault.rotate(f.ownerCredential, { tenantId: f.tenantId, name: 'db/app' });
    expect(rotated).toMatchObject({ name: 'db/app', version: 2, rotator: 'postgres' });
    expect(applied[0]).toMatchObject({ version: 2, previous: 'initial-app-password' });
    const current = await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'db/app' });
    expect(current.value).toBe(applied[0]!.value);
    expect(current.value).toHaveLength(24);
    expect(current.value).not.toContain('%');
    expect(current.value).toMatch(/[a-z]/);
    expect(current.value).toMatch(/[A-Z]/);
    expect(current.value).toMatch(/[0-9]/);
    expect(current.value).toMatch(/[^a-zA-Z0-9]/);

    // A failing rotator leaves the pending version; the error is stored redacted; the retry reuses the value.
    failNext = true;
    const failure = await vault
      .rotate(f.ownerCredential, { tenantId: f.tenantId, name: 'db/app' })
      .catch((error: unknown) => error);
    expect(failure).toMatchObject({ code: 'ROTATION_FAILED' });
    expect((failure as Error).message).toContain('[redacted]');
    const afterFailure = await vault.get(f.ownerCredential, { tenantId: f.tenantId, name: 'db/app' });
    expect(afterFailure.stages).toMatchObject({ current: 2, pending: 3 });
    expect(afterFailure.rotation).toMatchObject({ failures: 1 });
    expect(afterFailure.rotation!.lastFailure!.message).not.toMatch(/refused password [^[]/);
    await vault.rotate(f.ownerCredential, { tenantId: f.tenantId, name: 'db/app' });
    const pendingValue = applied.at(-1)!;
    expect(pendingValue.version).toBe(3);
    const afterRetry = await vault.get(f.ownerCredential, { tenantId: f.tenantId, name: 'db/app' });
    expect(afterRetry.stages).toEqual({ current: 3, previous: 2 });
    expect(afterRetry.rotation).toMatchObject({ intervalDays: 30, due: false });
    expect(afterRetry.rotation!.lastFailure).toBeUndefined();

    // Nothing is due yet; after 31 days the scheduler rotates it.
    expect((await f.iam.vault.rotateDue()).rotated).toEqual([]);
    f.advance(31 * DAY);
    const run = await f.iam.vault.rotateDue();
    expect(run.rotated).toEqual([{ tenantId: f.tenantId, name: 'db/app', version: 4 }]);
    expect(await auditActions(f)).toEqual(
      expect.arrayContaining(['vault:rotate:allow', 'vault:rotate:deny']),
    );
  });

  it('records a reminder once when a manual rotation is due', async () => {
    const f = await organizationFixture();
    await f.iam.api.vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'vendor/api-key',
      value: 'vendor-issued-key',
      rotation: { intervalDays: 7 },
    });
    f.advance(8 * DAY);
    expect((await f.iam.vault.rotateDue()).reminded).toEqual([
      { tenantId: f.tenantId, name: 'vendor/api-key' },
    ]);
    expect((await f.iam.vault.rotateDue()).reminded).toEqual([]);
    const view = await f.iam.api.vault.get(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      name: 'vendor/api-key',
    });
    expect(view.rotation).toMatchObject({ due: true });
    // A new current version resets the schedule.
    await f.iam.api.vault.put(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      name: 'vendor/api-key',
      value: 'a newly issued key',
    });
    const renewed = await f.iam.api.vault.get(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      name: 'vendor/api-key',
    });
    expect(renewed.rotation).toMatchObject({ due: false });
    expect(await auditActions(f)).toContain('vault:rotation-due:allow');
  });

  it('checks out shared credentials exclusively and rotates them when they come back', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'break-glass/root',
      generate: true,
      checkout: { exclusive: true, rotateOnCheckin: true, requireReason: true, maxDurationMs: 2 * HOUR },
    });
    const operators = [
      { effect: 'allow' as const, actions: ['iam:vault:lease', 'iam:vault:reveal', 'iam:vault:read'], resources: ['iam/vault/secrets/break-glass/*'] },
    ];
    const alice = await memberWith(f, 'alice', operators);
    const bob = await memberWith(f, 'bob', operators);

    await expect(
      vault.reveal(alice.credential, { tenantId: f.tenantId, name: 'break-glass/root' }),
    ).rejects.toMatchObject({ code: 'CHECKOUT_REQUIRED' });
    await expect(
      vault.checkout(alice.credential, { tenantId: f.tenantId, name: 'break-glass/root' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const checkout = await vault.checkout(alice.credential, {
      tenantId: f.tenantId,
      name: 'break-glass/root',
      reason: 'INC-1234 database outage',
    });
    expect(checkout).toMatchObject({ version: 1, stages: ['current'] });
    expect(checkout.value).toHaveLength(32);
    expect(checkout.expiresAt - f.now()).toBe(2 * HOUR);
    // The holder may reveal what they checked out; others wait.
    expect(
      (await vault.reveal(alice.credential, { tenantId: f.tenantId, name: 'break-glass/root' })).value,
    ).toBe(checkout.value);
    await expect(
      vault.checkout(bob.credential, { tenantId: f.tenantId, name: 'break-glass/root', reason: 'me too' }),
    ).rejects.toMatchObject({ code: 'SECRET_CHECKED_OUT' });
    expect(
      (await vault.get(f.ownerCredential, { tenantId: f.tenantId, name: 'break-glass/root' })).checkedOut,
    ).toEqual([{ leaseId: checkout.leaseId, holderId: alice.identity.id, expiresAt: checkout.expiresAt }]);
    // Others cannot return someone else's check-out without iam:vault:manage.
    await expect(
      vault.checkin(bob.credential, { tenantId: f.tenantId, leaseId: checkout.leaseId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const returned = await vault.checkin(alice.credential, {
      tenantId: f.tenantId,
      leaseId: checkout.leaseId,
    });
    expect(returned).toEqual({ leaseId: checkout.leaseId, state: 'ended', rotated: 2 });
    const next = await vault.checkout(bob.credential, {
      tenantId: f.tenantId,
      name: 'break-glass/root',
      reason: 'INC-1235',
      durationMs: HOUR,
    });
    expect(next.version).toBe(2);
    expect(next.value).not.toBe(checkout.value);

    // An expired check-out ends by itself and rotates too.
    f.advance(HOUR + 1);
    const run = await f.iam.vault.expireLeases();
    expect(run).toMatchObject({ expired: 1, rotated: 1 });
    const view = await vault.get(await f.ownerSignIn(), { tenantId: f.tenantId, name: 'break-glass/root' });
    expect(view.stages.current).toBe(3);
    expect(view.checkedOut).toEqual([]);
    expect(await auditActions(f)).toEqual(
      expect.arrayContaining(['vault:checkout:allow', 'vault:checkin:allow', 'vault:checkout-expired:allow']),
    );
  });

  it('mints dynamic credentials per lease and revokes them at the engine', async () => {
    const issued = new Map<string, string>();
    const revoked: string[] = [];
    const renewals: number[] = [];
    let failRevoke = 0;
    let failIssue = false;
    const engine: VaultEngine = {
      async issue(input) {
        if (failIssue) throw new Error('database unavailable');
        const username = `v-${input.holder.name}-${input.leaseId.slice(0, 8)}`;
        issued.set(input.leaseId, username);
        return {
          fields: { username, password: `pw-${input.leaseId}`, role: (input.config as { role: string }).role },
          handle: username,
        };
      },
      async revoke(input) {
        if (failRevoke > 0) {
          failRevoke--;
          throw new Error('revoke refused');
        }
        revoked.push(input.handle!);
      },
      async renew(input) {
        renewals.push(input.ttlMs);
      },
    };
    const f = await organizationFixture({ vault: { engines: { postgres: engine } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'db/readonly',
      kind: 'dynamic',
      format: 'json',
      engine: 'postgres',
      engineConfig: { role: 'readonly' },
      lease: { defaultTtlMs: HOUR, maxTtlMs: 4 * HOUR },
    });
    const alice = await memberWith(f, 'alice', [
      { effect: 'allow', actions: ['iam:vault:lease'], resources: ['iam/vault/secrets/db/*'] },
    ]);
    const lease = await vault.lease(alice.credential, { tenantId: f.tenantId, name: 'db/readonly' });
    expect(lease.fields).toMatchObject({ role: 'readonly', username: issued.get(lease.leaseId) });
    expect(lease.expiresAt - lease.issuedAt).toBe(HOUR);
    expect(lease.renewable).toBe(true);
    // The credential is never stored; only the sealed handle is.
    const rows = JSON.stringify(await f.database.find('vaultLeases', {}));
    expect(rows).not.toContain(`pw-${lease.leaseId}`);
    expect(rows).not.toContain(issued.get(lease.leaseId)!);
    // Static operations do not apply.
    await expect(
      vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'db/readonly' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    const renewed = await vault.renewLease(alice.credential, {
      tenantId: f.tenantId,
      leaseId: lease.leaseId,
      ttlMs: 3 * HOUR,
    });
    expect(renewed.expiresAt - f.now()).toBe(3 * HOUR);
    expect(renewals).toEqual([3 * HOUR]);
    expect(await vault.listMine(alice.credential, { tenantId: f.tenantId })).toHaveLength(1);

    const ended = await vault.revokeLease(alice.credential, {
      tenantId: f.tenantId,
      leaseId: lease.leaseId,
    });
    expect(ended.state).toBe('ended');
    expect(revoked).toEqual([issued.get(lease.leaseId)]);

    // An expiring lease is revoked by the job; a refused revocation is retried.
    const second = await vault.lease(alice.credential, { tenantId: f.tenantId, name: 'db/readonly' });
    failRevoke = 1;
    f.advance(HOUR + 1);
    expect(await f.iam.vault.expireLeases()).toMatchObject({ expired: 0, retrying: 1 });
    // Retries back off: nothing happens until the retry is due.
    expect(await f.iam.vault.expireLeases()).toMatchObject({ expired: 0, retrying: 0 });
    f.advance(2 * 60_000);
    expect(await f.iam.vault.expireLeases()).toMatchObject({ expired: 1, retrying: 0 });
    expect(revoked).toContain(issued.get(second.leaseId));

    // A failing engine fails the call and leaves no live lease.
    failIssue = true;
    await expect(
      vault.lease({ token: (await f.signIn('alice')).token }, { tenantId: f.tenantId, name: 'db/readonly' }),
    ).rejects.toMatchObject({ code: 'ENGINE_FAILED' });
    const history = await vault.listLeases(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      name: 'db/readonly',
      includeEnded: true,
    });
    expect(history.map((entry) => entry.state).sort()).toEqual(['ended', 'expired', 'failed']);
    expect(history.every((entry) => entry.holderName === 'alice')).toBe(true);
  });

  it('keeps deleted secrets restorable during the recovery window, then purges them', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key', value: 'old-key-value' });
    await vault.create(f.ownerCredential, { tenantId: f.tenantId, name: 'tmp/key', value: 'tmp-key-value' });
    const scheduled = await vault.delete(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'old/key',
      recoveryDays: 7,
    });
    expect(scheduled).toMatchObject({ status: 'pending-deletion' });
    await expect(
      vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key' }),
    ).rejects.toMatchObject({ code: 'SECRET_PENDING_DELETION' });
    await expect(
      vault.create(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key', value: 'x-value' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect((await vault.list(f.ownerCredential, { tenantId: f.tenantId })).total).toBe(1);
    expect((await vault.list(f.ownerCredential, { tenantId: f.tenantId, status: 'all' })).total).toBe(2);
    await vault.restore(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key' });
    expect(
      (await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key' })).value,
    ).toBe('old-key-value');

    await vault.delete(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key', recoveryDays: 7 });
    f.advance(6 * DAY);
    expect(await f.iam.vault.purgeDeleted()).toEqual({ purged: 0 });
    f.advance(2 * DAY);
    expect(await f.iam.vault.purgeDeleted()).toEqual({ purged: 1 });
    expect(await f.database.find('vaultVersions', { tenantId: f.tenantId })).toHaveLength(1);

    // Immediate deletion.
    const gone = await vault.delete(await f.ownerSignIn(), {
      tenantId: f.tenantId,
      name: 'tmp/key',
      recoveryDays: 0,
    });
    expect(gone.status).toBe('deleted');
    expect(await f.database.find('vaultSecrets', { tenantId: f.tenantId })).toHaveLength(0);
    expect(await auditActions(f)).toEqual(
      expect.arrayContaining(['vault:delete:allow', 'vault:restore:allow', 'vault:purge:allow']),
    );
  });

  it('serves trusted code, resolves references, and re-seals under a new deployment secret', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'smtp',
      format: 'json',
      fields: { host: 'smtp.acme.test', password: 'smtp-password' },
    });
    await vault.create(f.ownerCredential, { tenantId: f.tenantId, name: 'stripe/key', value: 'sk_test_123456' });
    expect((await f.iam.vault.get(f.tenantId, 'smtp')).fields).toEqual({
      host: 'smtp.acme.test',
      password: 'smtp-password',
    });
    expect(
      await f.iam.vault.resolve(f.tenantId, {
        mail: { host: 'vault://smtp#host', password: 'vault://smtp#password' },
        payments: ['vault://stripe/key', 'plain'],
        retries: 3,
      }),
    ).toEqual({
      mail: { host: 'smtp.acme.test', password: 'smtp-password' },
      payments: ['sk_test_123456', 'plain'],
      retries: 3,
    });
    await expect(f.iam.vault.resolve(f.tenantId, 'vault://smtp#user')).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });

    // A new deployment secret with the old one kept as previous: values still open, then are re-sealed.
    const rotated = betterIam({
      database: f.database,
      secret: 'a brand new deployment secret with 32+ characters',
      previousSecrets: ['organization-fixture-secret-with-32-characters'],
      baseURL: 'http://localhost:3000',
    });
    expect((await rotated.vault.get(f.tenantId, 'stripe/key')).value).toBe('sk_test_123456');
    const result = await rotated.rotateSecrets();
    expect(result.resealed.vaultVersions).toBe(2);
    const fresh = betterIam({
      database: f.database,
      secret: 'a brand new deployment secret with 32+ characters',
      baseURL: 'http://localhost:3000',
    });
    expect((await fresh.vault.get(f.tenantId, 'smtp')).fields!.password).toBe('smtp-password');
  });

  it('encrypts values under a customer-managed key, and disabling the key shreds them', async () => {
    const f = await organizationFixture();
    const { vault, keys } = f.iam.api;
    const key = await keys.create(f.ownerCredential, { tenantId: f.tenantId, alias: 'alias/vault' });
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cmk/api',
      value: 'under-the-customer-key',
      kmsKey: 'alias/vault',
    });
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cmk/later',
      value: 'first-under-deployment-secret',
    });
    await vault.put(f.ownerCredential, { tenantId: f.tenantId, name: 'cmk/later', value: 'second-value' });
    const [row] = await f.database.find<{ sealed: string; kmsKeyId?: string }>('vaultVersions', {
      tenantId: f.tenantId,
      version: 1,
      kmsKeyId: key.id,
    });
    expect(row!.sealed).not.toContain('under-the-customer-key');
    expect(row!.kmsKeyId).toBe(key.id);
    expect(
      (await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'cmk/api' })).value,
    ).toBe('under-the-customer-key');

    // Moving a secret under the key re-encrypts every kept version.
    const moved = await vault.update(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cmk/later',
      kmsKey: key.id,
    });
    expect(moved.kmsKeyId).toBe(key.id);
    const later = await f.database.find<{ kmsKeyId?: string }>('vaultVersions', {
      tenantId: f.tenantId,
      kmsKeyId: key.id,
    });
    expect(later).toHaveLength(3);
    expect(
      (
        await vault.reveal(f.ownerCredential, {
          tenantId: f.tenantId,
          name: 'cmk/later',
          stage: 'previous',
        })
      ).value,
    ).toBe('first-under-deployment-secret');
    // Every use shows on the key's audit trail.
    const kmsEvents = (await f.database.find<{ action: string; metadata?: { via?: string } }>('audit', {}))
      .filter((event) => event.action === 'iam:kms:decrypt' && event.metadata?.via === 'vault');
    expect(kmsEvents.length).toBeGreaterThan(0);

    // Disabling the key makes the values unreadable until it is enabled again.
    await keys.disable(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id });
    await expect(
      vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'cmk/api' }),
    ).rejects.toMatchObject({ code: 'KEY_STATE_INVALID' });
    await keys.enable(f.ownerCredential, { tenantId: f.tenantId, keyId: key.id });
    expect(
      (await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'cmk/api' })).value,
    ).toBe('under-the-customer-key');

    // Vault rights alone do not let someone bind secrets to a key they cannot use.
    const alice = await memberWith(f, 'alice', [
      { effect: 'allow', actions: ['iam:vault:*'], resources: ['iam/vault/secrets/*'] },
    ]);
    await expect(
      vault.create(alice.credential, {
        tenantId: f.tenantId,
        name: 'alice/secret',
        value: 'value',
        kmsKey: key.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Moving back under the deployment secret.
    const back = await vault.update(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cmk/api',
      kmsKey: null,
    });
    expect(back.kmsKeyId).toBeUndefined();
    expect(
      (await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'cmk/api' })).value,
    ).toBe('under-the-customer-key');
  });

  it('validates names, values and settings', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    for (const name of ['../etc', 'a//b', '.hidden', 'a/-b', 'x'.repeat(65)])
      await expect(
        vault.create(f.ownerCredential, { tenantId: f.tenantId, name, value: 'value' }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      vault.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'j',
        format: 'json',
        value: '[1,2]',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      vault.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'r',
        value: 'value',
        rotation: { rotator: 'nope' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      vault.create(f.ownerCredential, { tenantId: f.tenantId, name: 'd', kind: 'dynamic', engine: 'none' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(() =>
      betterIam({
        database: f.database,
        secret: 'organization-fixture-secret-with-32-characters',
        baseURL: 'http://localhost:3000',
        vault: { rotators: { Bad: { rotate: async () => undefined } } },
      }),
    ).toThrow(/rotators/);
    const generated = await vault.generate(f.ownerCredential, {
      generator: { length: 12, charset: 'numeric', eachClass: false },
    });
    expect(generated.value).toMatch(/^[0-9]{12}$/);
  });

  it('serves the vault over HTTP', async () => {
    const f = await organizationFixture();
    await f.iam.api.vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'http/secret',
      value: 'over-the-wire',
    });
    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/vault/reveal', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${f.ownerCredential.token}`,
          'content-type': 'application/json',
          'x-better-iam': '1',
        },
        body: JSON.stringify({ tenantId: f.tenantId, name: 'http/secret' }),
      }),
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: unknown }).data).toMatchObject({
      value: 'over-the-wire',
      version: 1,
    });
  });
});
