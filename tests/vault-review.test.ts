import { afterEach, describe, expect, it } from 'vitest';
import type { IamPlugin } from '@better-iam/core';
import type { VaultEngine, VaultRotator } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const DAY = 86_400_000;

/** Regression tests for the vault's second security review. */
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

/** An agent acting for `person` under a delegation of `scopes` (held back for confirmation when `confirm` says so). */
async function actingFor(
  f: OrganizationFixture,
  person: { token: string },
  scopes: string[],
  confirm: string[] = [],
  sponsorId?: string,
) {
  const agent = await f.iam.api.agents.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: `Agent ${scopes.join(' ')}`,
    ...(sponsorId ? { sponsorId } : {}),
  });
  const key = await f.iam.api.credentials.create(f.ownerCredential, { tenantId: f.tenantId, identityId: agent.id });
  const delegation = await f.iam.api.delegations.grant(person, {
    tenantId: f.tenantId,
    agentId: agent.id,
    scopes,
    ...(confirm.length ? { confirm } : {}),
  });
  const { token } = await f.iam.api.delegations.assume(
    { token: key.token },
    { tenantId: f.tenantId, delegationId: delegation.id },
  );
  return { agent, agentKey: { token: key.token }, delegation, acting: { token } };
}

describe('vault security, second review', () => {
  it('refuses changes that move a secret into what the caller may reveal, and creations a deny targets', async () => {
    const engine: VaultEngine = { async issue() { return { value: 'minted' }; } };
    const f = await organizationFixture({ vault: { engines: { 'pg-app': engine, 'pg-admin': engine } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db',
      tags: { environment: 'prod' },
      value: 'prod-password',
    });
    const admin = await memberWith(f, 'vaultadmin', [
      { effect: 'allow', actions: ['iam:vault:manage', 'iam:vault:read'], resources: ['iam/vault/secrets/*'] },
      {
        effect: 'allow',
        actions: ['iam:vault:reveal'],
        resources: ['iam/vault/secrets/*'],
        conditions: { StringEquals: { 'resource.tag.environment': 'staging' } },
      },
    ]);
    await expect(
      vault.update(admin.credential, { tenantId: f.tenantId, name: 'prod/db', tags: { environment: 'staging' } }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await vault.get(admin.credential, { tenantId: f.tenantId, name: 'prod/db' })).tags).toEqual({
      environment: 'prod',
    });
    // Changes that open nothing new still pass.
    await vault.update(admin.credential, { tenantId: f.tenantId, name: 'prod/db', description: 'Payments database' });
    await expect(
      vault.reveal(admin.credential, { tenantId: f.tenantId, name: 'prod/db' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    // A deny on an attribute other than tags applies to the creation itself.
    const dev = await memberWith(f, 'dev', [
      { effect: 'allow', actions: ['iam:vault:manage', 'iam:vault:lease'], resources: ['iam/vault/secrets/*'] },
      {
        effect: 'deny',
        actions: ['iam:vault:manage', 'iam:vault:lease'],
        resources: ['iam/vault/secrets/*'],
        conditions: { StringEquals: { 'resource.engine': 'pg-admin' } },
      },
    ]);
    await expect(
      vault.create(dev.credential, { tenantId: f.tenantId, name: 'mine/admin', kind: 'dynamic', engine: 'pg-admin' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      vault.get(f.ownerCredential, { tenantId: f.tenantId, name: 'mine/admin' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await vault.create(dev.credential, { tenantId: f.tenantId, name: 'mine/app', kind: 'dynamic', engine: 'pg-app' });
  });

  it('uses up a confirmation of the customer-managed key with each reveal', async () => {
    const f = await organizationFixture();
    const { vault, keys, delegations } = f.iam.api;
    const alice = await memberWith(f, 'alice', [
      {
        effect: 'allow',
        actions: ['iam:vault:reveal', 'iam:vault:read', 'iam:kms:decrypt', 'iam:kms:encrypt'],
        resources: ['iam/vault/secrets/*', 'iam/kms/*'],
      },
    ]);
    const key = await keys.create(f.ownerCredential, { tenantId: f.tenantId });
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'cmk/db',
      value: 'db-password',
      kmsKey: key.id,
    });
    const { acting } = await actingFor(
      f,
      alice.credential,
      ['iam:vault:reveal', 'iam:kms:decrypt'],
      ['iam:vault:reveal', 'iam:kms:decrypt'],
    );
    const approve = async (action: string, id: string) => {
      const request = await delegations.requestConfirmation(acting, {
        tenantId: f.tenantId,
        action,
        resource: { type: 'iam', id },
        reason: 'Read the database password once',
      });
      await delegations.decideConfirmation(alice.credential, {
        tenantId: f.tenantId,
        confirmationId: request.id,
        approve: true,
      });
    };
    await approve('iam:vault:reveal', 'vault/secrets/cmk/db');
    await approve('iam:kms:decrypt', `kms/${key.id}`);
    expect((await vault.reveal(acting, { tenantId: f.tenantId, name: 'cmk/db' })).value).toBe('db-password');
    // A second reveal approval alone is not enough: the key's approval was used up by the first reveal.
    await approve('iam:vault:reveal', 'vault/secrets/cmk/db');
    await expect(vault.reveal(acting, { tenantId: f.tenantId, name: 'cmk/db' })).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    // The refused call rolled back, so its reveal approval still stands for the next one.
    await approve('iam:kms:decrypt', `kms/${key.id}`);
    expect((await vault.reveal(acting, { tenantId: f.tenantId, name: 'cmk/db' })).value).toBe('db-password');
  });

  it('rotates to a chosen value only for callers who may write and reveal it, never behind check-outs', async () => {
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
      name: 'break-glass/root',
      generate: true,
      rotation: { rotator: 'db', intervalDays: 30 },
      checkout: { required: true, exclusive: true },
    });
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'svc/token',
      value: 'first-token',
      rotation: { rotator: 'db' },
    });
    const operator = await memberWith(f, 'operator', [
      { effect: 'allow', actions: ['iam:vault:rotate', 'iam:vault:read'], resources: ['iam/vault/secrets/*'] },
    ]);
    await expect(
      vault.rotate(operator.credential, { tenantId: f.tenantId, name: 'break-glass/root', value: 'known-to-me' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      vault.rotate(f.ownerCredential, { tenantId: f.tenantId, name: 'break-glass/root', value: 'known-to-me' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      vault.rotate(operator.credential, { tenantId: f.tenantId, name: 'svc/token', value: 'known-to-me' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(applied).toEqual([]);
    // Generated values rotate as before.
    await vault.rotate(operator.credential, { tenantId: f.tenantId, name: 'svc/token' });
    expect(applied).toHaveLength(1);
    const writer = await memberWith(f, 'writer', [
      {
        effect: 'allow',
        actions: ['iam:vault:rotate', 'iam:vault:write', 'iam:vault:reveal'],
        resources: ['iam/vault/secrets/*'],
      },
    ]);
    await vault.rotate(writer.credential, { tenantId: f.tenantId, name: 'svc/token', value: 'chosen-token' });
    expect(applied.at(-1)).toBe('chosen-token');
  });

  it('ends leases when the delegation behind them ends or the agent may no longer act', async () => {
    const revoked: string[] = [];
    const engine: VaultEngine = {
      async issue(input) {
        return { value: `pw-${input.leaseId}`, handle: input.leaseId };
      },
      async revoke(input) {
        revoked.push(input.leaseId);
      },
    };
    const f = await organizationFixture({ vault: { engines: { pg: engine } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db',
      kind: 'dynamic',
      engine: 'pg',
      lease: { defaultTtlMs: 7 * DAY, maxTtlMs: 30 * DAY },
    });
    const lease = [{ effect: 'allow' as const, actions: ['iam:vault:lease'], resources: ['iam/vault/secrets/*'] }];
    const sponsor = await memberWith(f, 'sponsor', []);
    const alice = await memberWith(f, 'alice', lease);
    const { agent, agentKey, delegation, acting } = await actingFor(
      f,
      alice.credential,
      ['iam:vault:lease'],
      [],
      sponsor.identity.id,
    );
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Agent lease',
      document: { version: 1, statements: lease },
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: agent.id,
    });
    const own = await vault.lease(agentKey, { tenantId: f.tenantId, name: 'prod/db' });
    const forAlice = await vault.lease(acting, { tenantId: f.tenantId, name: 'prod/db' });
    const kept = await vault.lease(alice.credential, { tenantId: f.tenantId, name: 'prod/db' });

    await f.iam.api.delegations.revoke(alice.credential, { tenantId: f.tenantId, delegationId: delegation.id });
    await f.iam.vault.expireLeases();
    expect(revoked).toEqual([forAlice.leaseId]);

    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: sponsor.identity.id,
      status: 'disabled',
    });
    await f.iam.vault.expireLeases();
    expect(revoked).toEqual([forAlice.leaseId, own.leaseId]);
    const live = await vault.listLeases(f.ownerCredential, { tenantId: f.tenantId, name: 'prod/db' });
    expect(live.filter((item) => item.state === 'active').map((item) => item.id)).toEqual([kept.leaseId]);
  });

  it('finds a departed holder’s lease however many live leases sort before it', async () => {
    const revoked: string[] = [];
    const engine: VaultEngine = {
      async issue(input) {
        return { value: `pw-${input.leaseId}`, handle: input.leaseId };
      },
      async revoke(input) {
        revoked.push(input.leaseId);
      },
    };
    const f = await organizationFixture({ vault: { engines: { pg: engine } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'prod/db',
      kind: 'dynamic',
      engine: 'pg',
      lease: { defaultTtlMs: 7 * DAY, maxTtlMs: 30 * DAY },
    });
    const holders = new Map<string, string>();
    for (let n = 0; n < 6; n++) {
      const person = await memberWith(f, `p${n}`, [
        { effect: 'allow', actions: ['iam:vault:lease'], resources: ['iam/vault/secrets/*'] },
      ]);
      const taken = await vault.lease(person.credential, { tenantId: f.tenantId, name: 'prod/db' });
      holders.set(taken.leaseId, person.identity.id);
    }
    const order = (await f.database.find<{ id: string }>('vaultLeases', { state: 'active' })).map((item) => item.id);
    const last = order.at(-1)!;
    await f.iam.api.identities.setStatus(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: holders.get(last)!,
      status: 'disabled',
    });
    await f.iam.vault.expireLeases({ limit: 5 });
    expect(revoked).toEqual([last]);
  });

  it('keeps values from plugin hooks, and lets only a session that may lease act on another session’s lease', async () => {
    const seen: string[] = [];
    const spy: IamPlugin = {
      id: 'spy',
      hooks: {
        async afterOperation(input) {
          seen.push(JSON.stringify(input.result ?? null));
        },
      },
    };
    const rotator: VaultRotator = { async rotate() {} };
    const f = await organizationFixture({ plugins: [spy], vault: { rotators: { db: rotator } } });
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'shared/admin',
      value: 'first-admin-password',
      rotation: { rotator: 'db' },
      checkout: { required: false },
    });
    const alice = await memberWith(f, 'alice', [
      { effect: 'allow', actions: ['iam:vault:*'], resources: ['iam/vault/secrets/*'] },
    ]);
    expect((await vault.reveal(alice.credential, { tenantId: f.tenantId, name: 'shared/admin' })).value).toBe(
      'first-admin-password',
    );
    await vault.rotate(alice.credential, { tenantId: f.tenantId, name: 'shared/admin' });
    const out = await vault.checkout(alice.credential, { tenantId: f.tenantId, name: 'shared/admin' });
    const current = await f.iam.vault.get(f.tenantId, 'shared/admin');
    expect(out.value).toBe(current.value);
    expect(seen.length).toBeGreaterThanOrEqual(3);
    for (const result of seen) {
      expect(result).not.toContain('first-admin-password');
      expect(result).not.toContain(current.value);
    }

    // An agent acting for alice without iam:vault:lease cannot end the check-out she took herself.
    const { acting } = await actingFor(f, alice.credential, ['iam:vault:read']);
    await expect(
      vault.checkin(acting, { tenantId: f.tenantId, leaseId: out.leaseId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      vault.revokeLease(acting, { tenantId: f.tenantId, leaseId: out.leaseId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Another session of hers that may lease can.
    const again = { token: (await f.signIn('alice')).token };
    expect(await vault.checkin(again, { tenantId: f.tenantId, leaseId: out.leaseId })).toMatchObject({
      state: 'ended',
    });
  });

  it('destroys values for good only from a recently signed-in session', async () => {
    const f = await organizationFixture();
    const { vault } = f.iam.api;
    await vault.create(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key', value: 'value-one' });
    await vault.put(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key', value: 'value-two' });
    f.advance(10 * 60_000);
    await expect(
      vault.destroyVersion(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key', version: 1 }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    await expect(
      vault.delete(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key', recoveryDays: 0 }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
    // A recovery window needs no fresh sign-in.
    expect(
      await vault.delete(f.ownerCredential, { tenantId: f.tenantId, name: 'old/key', recoveryDays: 7 }),
    ).toMatchObject({ status: 'pending-deletion' });
  });
});
