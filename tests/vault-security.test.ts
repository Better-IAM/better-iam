import { afterEach, describe, expect, it } from 'vitest';
import type { VaultEngine, VaultRotator } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const HOUR = 3_600_000;

/** Regression tests for the vault's security review. */
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

describe('vault security', () => {
  it('redacts every field of a json value from rotator errors', async () => {
    let fail = true;
    const rotator: VaultRotator = {
      async rotate(input) {
        if (fail) throw new Error(`ALTER ROLE app PASSWORD '${String(input.fields!.password)}' failed`);
      },
    };
    const f = await organizationFixture({ vault: { rotators: { db: rotator } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'db/app',
      format: 'json',
      fields: { username: 'app', password: 'initial-password' },
      rotation: { rotator: 'db', field: 'password', intervalDays: 30 },
    });
    await expect(
      vault.rotate(f.ownerCredential, { tenantId: f.tenantId, name: 'db/app' }),
    ).rejects.toMatchObject({ code: 'ROTATION_FAILED' });
    const reader = await memberWith(f, 'reader', [
      { effect: 'allow', actions: ['iam:vault:read'], resources: ['iam/vault/secrets/*'] },
    ]);
    const seen = await vault.get(reader.credential, { tenantId: f.tenantId, name: 'db/app' });
    expect(seen.rotation!.lastFailure!.message).toContain('[redacted]');
    const pending = await vault.reveal(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'db/app',
      stage: 'pending',
    });
    const password = String(pending.fields!.password);
    expect(JSON.stringify(seen)).not.toContain(password);
    const audit = JSON.stringify(await f.database.find('audit', {}));
    expect(audit).not.toContain(password);
    fail = false;
  });

  it('never hands a pending value someone staged by hand to the rotator', async () => {
    const applied: string[] = [];
    const rotator: VaultRotator = {
      async rotate(input) {
        applied.push(input.value);
      },
    };
    const f = await organizationFixture({ vault: { rotators: { db: rotator } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'shared/root',
      generate: true,
      rotation: { rotator: 'db' },
      checkout: { rotateOnCheckin: true, required: false },
    });
    const writer = await memberWith(f, 'writer', [
      { effect: 'allow', actions: ['iam:vault:write'], resources: ['iam/vault/secrets/*'] },
    ]);
    await vault.put(writer.credential, {
      tenantId: f.tenantId,
      name: 'shared/root',
      value: 'writer-chosen-password',
      stage: 'pending',
    });
    await vault.rotate(f.ownerCredential, { tenantId: f.tenantId, name: 'shared/root' });
    expect(applied).toHaveLength(1);
    expect(applied[0]).not.toBe('writer-chosen-password');
    const current = await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'shared/root' });
    expect(current.value).toBe(applied[0]);
  });

  it('rotates a check-out ended with revokeLease, and needs a policy to check out at all', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'shared/admin',
      generate: true,
      checkout: { rotateOnCheckin: true, required: false },
    });
    await vault.create(f.ownerCredential, { tenantId: f.tenantId, name: 'plain/key', value: 'plain-value' });
    const holder = await memberWith(f, 'holder', [
      { effect: 'allow', actions: ['iam:vault:lease'], resources: ['iam/vault/secrets/*'] },
    ]);
    // A lease grant does not read static secrets without a check-out policy.
    await expect(
      vault.checkout(holder.credential, { tenantId: f.tenantId, name: 'plain/key' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const out = await vault.checkout(holder.credential, { tenantId: f.tenantId, name: 'shared/admin' });
    const ended = await vault.revokeLease(holder.credential, { tenantId: f.tenantId, leaseId: out.leaseId });
    expect(ended).toMatchObject({ state: 'ended', rotated: 2 });
    const now = await vault.reveal(f.ownerCredential, { tenantId: f.tenantId, name: 'shared/admin' });
    expect(now.value).not.toBe(out.value);
  });

  it('refuses re-tagging a secret out of the caller’s reach', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'team-a/secret',
      tags: { team: 'a' },
      value: 'team-a-value',
    });
    const member = await memberWith(f, 'mallory', [
      {
        effect: 'allow',
        actions: ['iam:vault:manage'],
        resources: ['iam/vault/secrets/*'],
        conditions: { StringEquals: { 'resource.tag.team': 'a' } },
      },
      {
        effect: 'allow',
        actions: ['iam:vault:reveal'],
        resources: ['iam/vault/secrets/*'],
        conditions: { StringEquals: { 'resource.tag.team': 'b' } },
      },
    ]);
    await expect(
      vault.update(member.credential, { tenantId: f.tenantId, name: 'team-a/secret', tags: { team: 'b' } }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      vault.reveal(member.credential, { tenantId: f.tenantId, name: 'team-a/secret' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await vault.get(f.ownerCredential, { tenantId: f.tenantId, name: 'team-a/secret' })).tags).toEqual({
      team: 'a',
    });
  });

  it('validates rotation settings that could never rotate', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    await expect(
      vault.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'j/one',
        format: 'json',
        fields: { password: 'p-value' },
        checkout: { rotateOnCheckin: true },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    for (const field of ['__proto__', 'constructor', 'prototype'])
      await expect(
        vault.create(f.ownerCredential, {
          tenantId: f.tenantId,
          name: 'j/two',
          format: 'json',
          fields: { password: 'p-value' },
          rotation: { field, generator: true },
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'j/three',
      format: 'json',
      fields: { password: 'p-value' },
    });
    await expect(f.iam.vault.resolve(f.tenantId, 'vault://j/three#constructor')).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
    await expect(f.iam.vault.resolve(f.tenantId, 'vault://j/three#__proto__')).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it('does not promote a version disabled while the rotator ran', async () => {
    let f!: OrganizationFixture;
    const rotator: VaultRotator = {
      async rotate(input) {
        await f.iam.api.vault.setVersionState(f.ownerCredential, {
          tenantId: f.tenantId,
          name: input.name,
          version: input.version,
          state: 'disabled',
        });
      },
    };
    f = await organizationFixture({ vault: { rotators: { db: rotator } } });
    await f.iam.api.vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'db/x',
      value: 'first-value',
      rotation: { rotator: 'db' },
    });
    await expect(
      f.iam.api.vault.rotate(f.ownerCredential, { tenantId: f.tenantId, name: 'db/x' }),
    ).rejects.toMatchObject({ code: 'ROTATION_FAILED' });
    const view = await f.iam.api.vault.get(f.ownerCredential, { tenantId: f.tenantId, name: 'db/x' });
    expect(view.stages.current).toBe(1);
  });

  it('revokes what an engine minted when the issue fails after the call', async () => {
    const revoked: string[] = [];
    let mode: 'bad-handle' | 'ok' = 'bad-handle';
    const engine: VaultEngine = {
      async issue(input) {
        return mode === 'bad-handle'
          ? { value: `pw-${input.leaseId}`, handle: 'x'.repeat(5000) }
          : { value: `pw-${input.leaseId}`, handle: input.leaseId };
      },
      async revoke(input) {
        revoked.push(input.leaseId);
      },
    };
    const f = await organizationFixture({ vault: { engines: { e: engine } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'dyn/x',
      kind: 'dynamic',
      engine: 'e',
      lease: { defaultTtlMs: HOUR, maxTtlMs: 4 * HOUR },
    });
    await expect(
      vault.lease(f.ownerCredential, { tenantId: f.tenantId, name: 'dyn/x' }),
    ).rejects.toMatchObject({ code: 'ENGINE_FAILED' });
    expect(revoked).toHaveLength(1);
    // Renewals extend by the original length, not by how long the lease has lasted so far.
    mode = 'ok';
    const lease = await vault.lease(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'dyn/x',
      ttlMs: HOUR,
    });
    f.advance(30 * 60_000);
    const first = await vault.renewLease(f.ownerCredential, { tenantId: f.tenantId, leaseId: lease.leaseId });
    expect(first.expiresAt - f.now()).toBe(HOUR);
    f.advance(30 * 60_000);
    const second = await vault.renewLease(f.ownerCredential, { tenantId: f.tenantId, leaseId: lease.leaseId });
    expect(second.expiresAt - f.now()).toBe(HOUR);
  });

  it('keeps customer-managed keys in charge of the values', async () => {
    const f = await organizationFixture();
    const { vault, keys } = f.iam.api;
    const key = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cmk/x',
      value: 'under-the-key',
      kmsKey: key.id,
    });
    const manager = await memberWith(f, 'manager', [
      { effect: 'allow', actions: ['iam:vault:*'], resources: ['iam/vault/secrets/*'] },
    ]);
    // Vault rights alone neither read a key-protected value nor move it off its key.
    await expect(
      vault.reveal(manager.credential, { tenantId: f.tenantId, name: 'cmk/x' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      vault.update(manager.credential, { tenantId: f.tenantId, name: 'cmk/x', kmsKey: null }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Non-AES keys cannot be bound.
    const signing = await keys.create(f.ownerCredential, { tenantId: f.tenantId, keySpec: 'ed25519' } as never);
    await expect(
      vault.create(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'cmk/y',
        value: 'v-value',
        kmsKey: signing.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
