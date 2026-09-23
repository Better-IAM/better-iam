import { afterEach, describe, expect, it } from 'vitest';
import type { Identity } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

type Fixture = Awaited<ReturnType<typeof organizationFixture>>;

/** Every stored identity of the tenant: nobody manages themselves, and no managerId chain revisits anyone. */
async function expectNoCycles(f: Fixture) {
  const all = await f.database.find<Identity>('identities', { tenantId: f.tenantId });
  const byId = new Map(all.map((identity) => [identity.id, identity]));
  for (const start of all) {
    expect(start.managerId, `${start.name} manages themselves`).not.toBe(start.id);
    const seen = new Set<string>([start.id]);
    let cursor = start.managerId;
    while (cursor !== undefined) {
      expect(seen.has(cursor), `${start.name}'s reporting line loops through ${cursor}`).toBe(
        false,
      );
      seen.add(cursor);
      cursor = byId.get(cursor)?.managerId;
    }
  }
}

async function managerOf(f: Fixture, identityId: string) {
  return (await f.database.get<Identity>('identities', identityId))?.managerId;
}

async function reportIds(f: Fixture, identityId: string) {
  return (
    await f.iam.api.identities.listReports(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId,
    })
  ).map((report) => report.id);
}

async function setManager(f: Fixture, identityId: string, managerId: string | null) {
  return f.iam.api.identities.update(f.ownerCredential, {
    tenantId: f.tenantId,
    identityId,
    managerId,
  });
}

describe('offboarding a manager whose successor is one of their reports', () => {
  it("moves the successor up to the leaver's own manager and hands the other reports to the successor", async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const dave = await f.member('dave');
    const carol = await f.member('carol');
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    await setManager(f, carol.id, dave.id);
    await setManager(f, alice.id, carol.id);
    await setManager(f, bob.id, carol.id);
    const admin = await f.ownerSignIn();
    const result = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: carol.id,
      reason: 'left',
      successorId: alice.id,
    });
    expect(result.reportsReassigned).toBe(2);
    expect(await managerOf(f, alice.id)).toBe(dave.id);
    expect(await managerOf(f, bob.id)).toBe(alice.id);
    expect(
      (await f.iam.api.identities.get(admin, { tenantId, identityId: alice.id })).managerId,
    ).toBe(dave.id);
    const aliceReports = await reportIds(f, alice.id);
    expect(aliceReports).toEqual([bob.id]);
    expect(aliceReports).not.toContain(alice.id);
    // Carol is disabled now, so Dave's only active report is Alice.
    expect(await reportIds(f, dave.id)).toEqual([alice.id]);
    expect(await reportIds(f, carol.id)).toEqual([]);
    await expectNoCycles(f);
  });

  it('clears the successor’s manager when the leaver had none', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const carol = await f.member('carol');
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    await setManager(f, alice.id, carol.id);
    await setManager(f, bob.id, carol.id);
    const admin = await f.ownerSignIn();
    const result = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: carol.id,
      reason: 'left',
      successorId: alice.id,
    });
    expect(result.reportsReassigned).toBe(2);
    expect(await managerOf(f, alice.id)).toBeUndefined();
    expect(await managerOf(f, alice.id)).not.toBe(carol.id);
    expect(await managerOf(f, bob.id)).toBe(alice.id);
    const aliceReports = await reportIds(f, alice.id);
    expect(aliceReports).toEqual([bob.id]);
    expect(aliceReports).not.toContain(alice.id);
    await expectNoCycles(f);
  });

  it('never makes a sole-report successor their own manager', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const carol = await f.member('carol');
    const bob = await f.member('bob');
    await setManager(f, bob.id, carol.id);
    const admin = await f.ownerSignIn();
    expect(
      (
        await f.iam.api.identities.offboard(admin, {
          tenantId,
          identityId: carol.id,
          reason: 'left',
          successorId: bob.id,
        })
      ).reportsReassigned,
    ).toBe(1);
    expect(await managerOf(f, bob.id)).toBeUndefined();
    expect(await reportIds(f, bob.id)).toEqual([]);
    await expectNoCycles(f);
    // With a manager above the leaver, the sole report moves up to them.
    const g = await organizationFixture();
    const erin = await g.member('erin');
    const frank = await g.member('frank');
    const gina = await g.member('gina');
    await setManager(g, frank.id, erin.id);
    await setManager(g, gina.id, frank.id);
    await g.iam.api.identities.offboard(await g.ownerSignIn(), {
      tenantId: g.tenantId,
      identityId: frank.id,
      reason: 'left',
      successorId: gina.id,
    });
    expect(await managerOf(g, gina.id)).toBe(erin.id);
    expect(await reportIds(g, gina.id)).toEqual([]);
    expect(await reportIds(g, erin.id)).toEqual([gina.id]);
    await expectNoCycles(g);
  });
});

describe('offboarding a manager whose successor sits lower in the same line', () => {
  it('leaves the report above the successor without a manager instead of closing a cycle', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const carol = await f.member('carol');
    const bob = await f.member('bob');
    const alice = await f.member('alice');
    const dan = await f.member('dan');
    // Carol manages Bob (and Dan); Bob manages Alice.
    await setManager(f, bob.id, carol.id);
    await setManager(f, alice.id, bob.id);
    await setManager(f, dan.id, carol.id);
    const admin = await f.ownerSignIn();
    const result = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: carol.id,
      reason: 'left',
      successorId: alice.id,
    });
    expect(result.reportsReassigned).toBe(2);
    expect(await managerOf(f, bob.id)).toBeUndefined();
    expect(await managerOf(f, alice.id)).toBe(bob.id);
    // Carol's other report, outside the successor's line, goes to the successor.
    expect(await managerOf(f, dan.id)).toBe(alice.id);
    expect(await reportIds(f, alice.id)).toEqual([dan.id]);
    expect(await reportIds(f, bob.id)).toEqual([alice.id]);
    await expectNoCycles(f);
    // The state is consistent with the update validation: Bob still cannot report to Alice.
    await expect(setManager(f, bob.id, alice.id)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });

  it('keeps every reporting line acyclic when the leaver has a manager above them', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const erin = await f.member('erin');
    const carol = await f.member('carol');
    const bob = await f.member('bob');
    const alice = await f.member('alice');
    await setManager(f, carol.id, erin.id);
    await setManager(f, bob.id, carol.id);
    await setManager(f, alice.id, bob.id);
    await f.iam.api.identities.offboard(await f.ownerSignIn(), {
      tenantId,
      identityId: carol.id,
      reason: 'left',
      successorId: alice.id,
    });
    // Bob sits above the successor, so he is left without a manager: not handed to Alice (a cycle) and not left
    // pointing at the offboarded Carol.
    expect(await managerOf(f, bob.id)).not.toBe(alice.id);
    expect(await managerOf(f, bob.id)).toBeUndefined();
    expect(await managerOf(f, alice.id)).toBe(bob.id);
    expect(await managerOf(f, carol.id)).toBe(erin.id);
    expect(await reportIds(f, alice.id)).not.toContain(bob.id);
    expect(
      await f.database.find<Identity>('identities', { tenantId, managerId: carol.id }),
    ).toEqual([]);
    await expectNoCycles(f);
  });

  it('checks the whole line above the successor, not only their direct manager', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const carol = await f.member('carol');
    const bob = await f.member('bob');
    const xavier = await f.member('xavier');
    const alice = await f.member('alice');
    const dan = await f.member('dan');
    // Carol manages Bob (and Dan); Bob manages Xavier; Xavier manages Alice.
    await setManager(f, bob.id, carol.id);
    await setManager(f, xavier.id, bob.id);
    await setManager(f, alice.id, xavier.id);
    await setManager(f, dan.id, carol.id);
    const result = await f.iam.api.identities.offboard(await f.ownerSignIn(), {
      tenantId,
      identityId: carol.id,
      reason: 'left',
      successorId: alice.id,
    });
    expect(result.reportsReassigned).toBe(2);
    // Bob is two levels above Alice: handing him to her would close Bob -> Alice -> Xavier -> Bob.
    expect(await managerOf(f, bob.id)).toBeUndefined();
    expect(await managerOf(f, xavier.id)).toBe(bob.id);
    expect(await managerOf(f, alice.id)).toBe(xavier.id);
    expect(await managerOf(f, dan.id)).toBe(alice.id);
    expect(await reportIds(f, alice.id)).toEqual([dan.id]);
    await expectNoCycles(f);
  });
});

describe('deleted identities and reporting lines', () => {
  it('a tombstone carries no managerId and is nobody’s manager', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const carol = await f.member('carol');
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    await setManager(f, alice.id, carol.id);
    await setManager(f, carol.id, bob.id);
    const admin = await f.ownerSignIn();
    expect(
      (await f.iam.api.identities.delete(admin, { tenantId, identityId: alice.id })).status,
    ).toBe('deleted');
    const tombstone = await f.database.get<Identity>('identities', alice.id);
    expect(tombstone?.status).toBe('deleted');
    expect(tombstone?.managerId).toBeUndefined();
    expect(tombstone && 'managerId' in tombstone).toBe(false);
    // Deleting a manager unlinks their reports.
    await f.iam.api.identities.delete(admin, { tenantId, identityId: bob.id });
    expect(await managerOf(f, carol.id)).toBeUndefined();
    expect((await f.database.get<Identity>('identities', bob.id))?.managerId).toBeUndefined();
  });

  it('offboarding a manager neither rewrites nor counts a deleted report', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const carol = await f.member('carol');
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const dave = await f.member('dave');
    await setManager(f, alice.id, carol.id);
    await setManager(f, bob.id, carol.id);
    const admin = await f.ownerSignIn();
    await f.iam.api.identities.delete(admin, { tenantId, identityId: alice.id });
    const result = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: carol.id,
      reason: 'left',
      successorId: dave.id,
    });
    expect(result.reportsReassigned).toBe(1);
    expect(await managerOf(f, bob.id)).toBe(dave.id);
    const tombstone = await f.database.get<Identity>('identities', alice.id);
    expect(tombstone?.status).toBe('deleted');
    expect(tombstone?.managerId).toBeUndefined();
    expect(await reportIds(f, dave.id)).toEqual([bob.id]);
    const trail = await f.iam.api.audit.list(admin, { tenantId, action: 'identity:offboard' });
    expect(trail[0]).toMatchObject({ resourceId: carol.id, metadata: { reportsReassigned: 1 } });
  });

  it('skips a legacy tombstone that still points at the leaver', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const carol = await f.member('carol');
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const dave = await f.member('dave');
    await setManager(f, bob.id, carol.id);
    const admin = await f.ownerSignIn();
    await f.iam.api.identities.delete(admin, { tenantId, identityId: alice.id });
    // Data written before tombstones dropped managerId: the deleted record still names Carol.
    const legacy = await f.database.transaction(async (tx) =>
      tx.put<Identity>('identities', {
        ...(await tx.get<Identity>('identities', alice.id))!,
        managerId: carol.id,
      }),
    );
    expect(legacy).toMatchObject({ status: 'deleted', managerId: carol.id });
    const result = await f.iam.api.identities.offboard(admin, {
      tenantId,
      identityId: carol.id,
      reason: 'left',
      successorId: dave.id,
    });
    expect(result.reportsReassigned).toBe(1);
    expect(await managerOf(f, bob.id)).toBe(dave.id);
    // The tombstone is left exactly as it was: not handed to the successor, not rewritten.
    expect(await f.database.get<Identity>('identities', alice.id)).toEqual(legacy);
    expect(await reportIds(f, dave.id)).toEqual([bob.id]);
  });
});

describe('a manager must be an active identity', () => {
  it('refuses a disabled or offboarded identity as manager, on update and on create', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const dave = await f.member('dave');
    const gone = await f.member('gone');
    const admin = await f.ownerSignIn();
    await f.iam.api.identities.setStatus(admin, {
      tenantId,
      identityId: dave.id,
      status: 'disabled',
    });
    await expect(setManager(f, alice.id, dave.id)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringMatching(/active/i),
    });
    expect(await managerOf(f, alice.id)).toBeUndefined();
    await expect(
      f.iam.api.identities.create(owner, {
        tenantId,
        email: 'erin@acme.test',
        name: 'erin',
        password: 'a strong erin password',
        managerId: dave.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: expect.stringMatching(/active/i) });
    // The refused create leaves nothing behind.
    expect(
      await f.database.find<Identity>('identities', { tenantId, email: 'erin@acme.test' }),
    ).toEqual([]);
    // Offboarding disables the identity, so an offboarded person cannot become a manager either.
    await f.iam.api.identities.offboard(admin, { tenantId, identityId: gone.id, reason: 'left' });
    await expect(setManager(f, alice.id, gone.id)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringMatching(/active/i),
    });
    // Re-enabled, the same identity is accepted.
    await f.iam.api.identities.setStatus(admin, {
      tenantId,
      identityId: dave.id,
      status: 'active',
    });
    expect((await setManager(f, alice.id, dave.id)).managerId).toBe(dave.id);
    expect(await reportIds(f, dave.id)).toEqual([alice.id]);
  });
});

describe('updating an identity whose manager has since been disabled', () => {
  it('accepts the unchanged managerId without re-validating it, but validates a change', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    await setManager(f, bob.id, alice.id);
    const admin = await f.ownerSignIn();
    await f.iam.api.identities.setStatus(admin, {
      tenantId,
      identityId: alice.id,
      status: 'disabled',
    });
    await f.iam.api.identities.setStatus(admin, {
      tenantId,
      identityId: carol.id,
      status: 'disabled',
    });
    // A form that resubmits every field, including the unchanged manager.
    const renamed = await f.iam.api.identities.update(owner, {
      tenantId,
      identityId: bob.id,
      name: 'Bobby',
      managerId: alice.id,
    });
    expect(renamed).toMatchObject({ name: 'Bobby', managerId: alice.id });
    expect((await setManager(f, bob.id, alice.id)).managerId).toBe(alice.id);
    expect(await managerOf(f, bob.id)).toBe(alice.id);
    // Changing it still validates: another disabled identity is refused and nothing changes.
    await expect(
      f.iam.api.identities.update(owner, {
        tenantId,
        identityId: bob.id,
        name: 'Robert',
        managerId: carol.id,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT', message: expect.stringMatching(/active/i) });
    expect(await f.database.get<Identity>('identities', bob.id)).toMatchObject({
      name: 'Bobby',
      managerId: alice.id,
    });
    // An active manager is accepted; switching back to the disabled one is now a change and refused.
    expect((await setManager(f, bob.id, dave.id)).managerId).toBe(dave.id);
    await expect(setManager(f, bob.id, alice.id)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringMatching(/active/i),
    });
    expect(await managerOf(f, bob.id)).toBe(dave.id);
    // Self-management is still refused even though it is a change.
    await expect(setManager(f, bob.id, bob.id)).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringMatching(/own manager/i),
    });
    expect(await managerOf(f, bob.id)).toBe(dave.id);
  });
});
