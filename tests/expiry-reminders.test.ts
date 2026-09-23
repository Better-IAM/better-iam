import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const day = 86400000;

describe('expiry reminders', () => {
  it('emails each person once per ending item, and again when the end moves', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const project = await f.iam.api.groups.create(owner, { tenantId, name: 'Project X' });
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      groupIds: [project.id],
    });
    const alice = await f.member('alice', { expiresAt: f.now() + 3 * day });
    const bob = await f.member('bob');
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
      expiresAt: f.now() + 2 * day,
    });
    const carol = await f.member('carol');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: carol.id,
      expiresAt: f.now() + 5 * day,
    });
    const dave = await f.member('dave');
    await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: kit.id,
      identityId: dave.id,
      expiresAt: f.now() + 4 * day,
    });
    // Erin's binding ends outside the window; a group binding is the owners' business, not a member's.
    const erin = await f.member('erin');
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: erin.id,
      expiresAt: f.now() + 20 * day,
    });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'group',
      subjectId: project.id,
      expiresAt: f.now() + day,
    });
    const first = await f.iam.sendExpiryReminders({ withinMs: 7 * day });
    expect(first.sent.map((entry) => [entry.identityId, entry.items]).sort()).toEqual(
      [
        [alice.id, 1],
        [bob.id, 1],
        [carol.id, 1],
        [dave.id, 1],
      ].sort(),
    );
    expect(first.skipped).toEqual({ inactive: 0, quiet: 1 });
    await f.iam.auth.dispatchOutbox();
    const mails = f.inbox.filter((message) => message.template === 'expiry-reminder');
    expect(mails.map((message) => [message.to, message.payload.count]).sort()).toEqual([
      ['alice@acme.test', '1'],
      ['bob@acme.test', '1'],
      ['carol@acme.test', '1'],
      ['dave@acme.test', '1'],
    ]);
    const itemsOf = (to: string) =>
      JSON.parse(mails.find((message) => message.to === to)!.payload.items!);
    expect(itemsOf('alice@acme.test')).toEqual([
      { kind: 'account', name: 'alice', expiresAt: f.now() + 3 * day },
    ]);
    expect(itemsOf('bob@acme.test')).toEqual([
      { kind: 'role', name: 'Reader', expiresAt: f.now() + 2 * day },
    ]);
    expect(itemsOf('carol@acme.test')).toEqual([
      { kind: 'group', name: 'Project X', expiresAt: f.now() + 5 * day },
    ]);
    expect(itemsOf('dave@acme.test')).toEqual([
      { kind: 'package', name: 'Kit', expiresAt: f.now() + 4 * day },
    ]);
    expect(mails[0]!.payload.tenantName).toBe('Acme');
    // Nothing new: the next run is quiet. Moving an end brings a fresh reminder for that item only.
    expect((await f.iam.sendExpiryReminders({ withinMs: 7 * day })).sent).toEqual([]);
    const extended = await f.iam.api.packages.extend(owner, {
      tenantId,
      packageId: kit.id,
      identityId: dave.id,
      expiresAt: f.now() + 6 * day,
    });
    expect(extended.expiresAt).toBe(f.now() + 6 * day);
    expect(
      (
        await f.database.find<{ expiresAt?: number }>('bindings', {
          tenantId,
          packageAssignmentId: extended.id,
        })
      ).map((binding) => binding.expiresAt),
    ).toEqual([f.now() + 6 * day]);
    expect(
      (
        await f.database.find<{ expiresAt?: number }>('groupMembers', {
          tenantId,
          packageAssignmentId: extended.id,
        })
      ).map((member) => member.expiresAt),
    ).toEqual([f.now() + 6 * day]);
    expect((await f.iam.sendExpiryReminders({ withinMs: 7 * day })).sent).toEqual([
      { tenantId, identityId: dave.id, items: 1 },
    ]);
    expect(
      await f.iam.api.audit.list(owner, { tenantId, action: 'identity:expiry-reminder' }),
    ).toHaveLength(5);
    expect(
      (await f.iam.api.audit.list(owner, { tenantId, action: 'package:extend' }))[0]!.metadata,
    ).toMatchObject({ previousExpiresAt: f.now() + 4 * day, expiresAt: f.now() + 6 * day });
    // A permanent extension clears every end; a capped package refuses one.
    const permanent = await f.iam.api.packages.extend(owner, {
      tenantId,
      packageId: kit.id,
      identityId: dave.id,
      expiresAt: null,
    });
    expect(permanent.expiresAt).toBeUndefined();
    expect(
      (
        await f.database.find<{ expiresAt?: number }>('groupMembers', {
          tenantId,
          packageAssignmentId: extended.id,
        })
      ).map((member) => member.expiresAt),
    ).toEqual([undefined]);
    await expect(
      f.iam.api.packages.extend(owner, {
        tenantId,
        packageId: kit.id,
        identityId: alice.id,
        expiresAt: f.now() + day,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const capped = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Capped',
      groupIds: [project.id],
      maxDurationMs: 2 * day,
    });
    await f.iam.api.packages.assign(owner, {
      tenantId,
      packageId: capped.id,
      identityId: erin.id,
      expiresAt: f.now() + day,
    });
    for (const expiresAt of [null, f.now() + 3 * day])
      await expect(
        f.iam.api.packages.extend(owner, {
          tenantId,
          packageId: capped.id,
          identityId: erin.id,
          expiresAt,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(f.iam.sendExpiryReminders({ withinMs: 0 })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(f.iam.sendExpiryReminders({ tenantId: 'missing' })).rejects.toMatchObject({
      code: 'NOT_FOUND',
    });
  });

  it('needs an email transport', async () => {
    const database = sqliteAdapter({ filename: ':memory:' });
    const iam = betterIam({
      database,
      secret: 'expiry-reminder-secret-with-32-characters',
      baseURL: 'http://localhost:3000',
    });
    try {
      await iam.initialize();
      await expect(iam.sendExpiryReminders()).rejects.toMatchObject({ code: 'DELIVERY_REQUIRED' });
    } finally {
      await database.close();
    }
  });
});
