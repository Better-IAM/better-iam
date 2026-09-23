import { afterEach, describe, expect, it } from 'vitest';
import type { StoredRecord } from '@better-iam/core';
import { webIdentityReplayId } from '../packages/server/src/web-identity.js';
import { generateTestKey } from './support/jwt-keys.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const minute = 60_000;
const hour = 3_600_000;
const day = 86400000;

type Tagged = StoredRecord & { packageAssignmentId?: string; expiresAt?: number };
type Mark = StoredRecord & { identityId: string; expiresAt: number };

/** A tenant with a role that lets its holders activate eligible bindings. */
async function activationFixture() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const reader = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Reader',
    permissions: ['documents:read'],
  });
  const writer = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Writer',
    permissions: ['documents:write'],
  });
  const activator = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Activator',
    permissions: ['iam:bindings:activate'],
  });
  const canActivate = (identityId: string) =>
    f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: activator.id,
      subjectType: 'identity',
      subjectId: identityId,
    });
  const report = async () =>
    f.iam.api.reports.access(owner, { tenantId, withinMs: 30 * day, unusedForMs: 30 * day });
  const digest = () =>
    f.iam.sendAccessDigest({ tenantId, withinMs: 30 * day, minimumIntervalMs: 0 });
  return { ...f, reader, writer, canActivate, report, digest };
}

describe('access report after expiry and purge', () => {
  it('lists an identity past its deadline until the worker disables it, then goes quiet', async () => {
    const f = await activationFixture();
    const { tenantId } = f;
    const contractor = await f.member('contractor', { expiresAt: f.now() + day });
    f.advance(day + minute);
    // Past the deadline but still active: a finding, flagged as expired.
    const before = await f.report();
    expect(before.identities.expiring.map((item) => [item.id, item.status, item.expired])).toEqual([
      [contractor.id, 'active', true],
    ]);
    const digested = await f.digest();
    expect(digested.sent).toEqual([
      expect.objectContaining({ tenantId, expiringIdentities: 1, activations: 0, unusedKeys: 0 }),
    ]);
    const purge = await f.iam.purgeDeleted();
    expect(purge.expiredIdentities).toBe(1);
    expect((await f.database.get<StoredRecord>('identities', contractor.id))!.status).toBe(
      'disabled',
    );
    // Disabled by the worker: no longer a finding, and the digest has nothing left to say.
    const after = await f.report();
    expect(after.identities.expiring).toEqual([]);
    expect(after.identities.disabled).toBe(1);
    const quiet = await f.digest();
    expect(quiet.sent).toEqual([]);
    expect(quiet.skipped).toEqual({ inactive: 0, recent: 0, quiet: 1, noOwners: 0 });
  });

  it('leaves lapsed memberships out of expiringMemberships before any purge', async () => {
    const f = await activationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const project = await f.iam.api.groups.create(owner, { tenantId, name: 'Project X' });
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: carol.id,
      expiresAt: f.now() + hour,
    });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: dave.id,
      expiresAt: f.now() + 3 * day,
    });
    const members = async () =>
      (await f.report()).bindings!.expiringMemberships.map((member) => member.identityId);
    expect(await members()).toEqual([carol.id, dave.id]);
    f.advance(2 * hour);
    // Carol's membership has lapsed (its record waits for the worker): only Dave's is still ending.
    expect(await f.database.find('groupMembers', { tenantId, identityId: carol.id })).toHaveLength(
      1,
    );
    expect(await members()).toEqual([dave.id]);
    expect((await f.digest()).sent).toEqual([
      expect.objectContaining({ tenantId, expiringMemberships: 1 }),
    ]);
    f.advance(3 * day);
    // Both lapsed, neither purged yet: nothing is ending, and that was the only finding.
    expect(await f.database.find('groupMembers', { tenantId, groupId: project.id })).toHaveLength(
      2,
    );
    expect(await members()).toEqual([]);
    const quiet = await f.digest();
    expect(quiet.sent).toEqual([]);
    expect(quiet.skipped.quiet).toBe(1);
  });

  it('drops activations and requests of an expired binding, and the purge deletes them', async () => {
    const f = await activationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    await f.canActivate(alice.id);
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      expiresAt: f.now() + 30 * minute,
    });
    const approval = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.writer.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      requireApproval: true,
      expiresAt: f.now() + 30 * minute,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const activation = await f.iam.api.bindings.activate(asAlice, {
      tenantId,
      bindingId: eligible.id,
      durationMs: hour,
    });
    await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: approval.id });
    const before = (await f.report()).bindings!;
    expect(before.activations.map((item) => item.id)).toEqual([activation.id]);
    expect(before.pendingRequests).toBe(1);
    // The bindings end while the activation and the request would still run.
    f.advance(45 * minute);
    const lapsed = (await f.report()).bindings!;
    expect(lapsed.activations).toEqual([]);
    expect(lapsed.pendingRequests).toBe(0);
    expect(lapsed.expiring).toEqual([]);
    const quiet = await f.digest();
    expect(quiet.sent).toEqual([]);
    expect(quiet.skipped.quiet).toBe(1);
    // The worker removes the bindings and, with them, their activations.
    const purge = await f.iam.purgeDeleted();
    expect(purge.expiredBindings).toBe(2);
    expect(purge.expiredActivations).toBe(2);
    expect(await f.database.find('bindingActivations', { tenantId })).toEqual([]);
    const after = (await f.report()).bindings!;
    expect(after.activations).toEqual([]);
    expect(after.pendingRequests).toBe(0);
  });

  it('drops activations whose binding record is gone', async () => {
    const f = await activationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice');
    await f.canActivate(alice.id);
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
    });
    const approval = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.writer.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      requireApproval: true,
    });
    const asAlice = { token: (await f.signIn('alice')).token };
    const activation = await f.iam.api.bindings.activate(asAlice, {
      tenantId,
      bindingId: eligible.id,
    });
    await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: approval.id });
    expect((await f.report()).bindings!.activations.map((item) => item.id)).toEqual([
      activation.id,
    ]);
    // Bindings removed underneath their activations (as the worker used to leave them).
    await f.database.transaction(async (tx) => {
      await tx.delete('bindings', eligible.id);
      await tx.delete('bindings', approval.id);
    });
    expect(await f.database.find('bindingActivations', { tenantId })).toHaveLength(2);
    const orphaned = (await f.report()).bindings!;
    expect(orphaned.activations).toEqual([]);
    expect(orphaned.pendingRequests).toBe(0);
    expect((await f.digest()).sent).toEqual([]);
  });

  it('drops activations of disabled holders, and the purge deletes those of identities it disables', async () => {
    const f = await activationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const alice = await f.member('alice', { expiresAt: f.now() + 30 * minute });
    const bob = await f.member('bob');
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
    });
    const approval = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.writer.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      requireApproval: true,
    });
    const bobEligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
      eligible: true,
    });
    const bobApproval = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.writer.id,
      subjectType: 'identity',
      subjectId: bob.id,
      eligible: true,
      requireApproval: true,
    });
    for (const identity of [alice, bob]) await f.canActivate(identity.id);
    const asAlice = { token: (await f.signIn('alice')).token };
    const asBob = { token: (await f.signIn('bob')).token };
    const aliceActivation = await f.iam.api.bindings.activate(asAlice, {
      tenantId,
      bindingId: eligible.id,
    });
    await f.iam.api.bindings.activate(asAlice, { tenantId, bindingId: approval.id });
    const bobActivation = await f.iam.api.bindings.activate(asBob, {
      tenantId,
      bindingId: bobEligible.id,
    });
    await f.iam.api.bindings.activate(asBob, { tenantId, bindingId: bobApproval.id });
    const before = (await f.report()).bindings!;
    expect(before.activations.map((item) => item.id).sort()).toEqual(
      [aliceActivation.id, bobActivation.id].sort(),
    );
    expect(before.pendingRequests).toBe(2);
    // An administrator disables Bob: his activation records stay, but they grant nothing and are not reported.
    await f.iam.api.identities.setStatus(await f.ownerSignIn(), {
      tenantId,
      identityId: bob.id,
      status: 'disabled',
    });
    expect(
      await f.database.find('bindingActivations', { tenantId, identityId: bob.id }),
    ).toHaveLength(2);
    const withoutBob = (await f.report()).bindings!;
    expect(withoutBob.activations.map((item) => item.id)).toEqual([aliceActivation.id]);
    expect(withoutBob.pendingRequests).toBe(1);
    // Alice's account ends; the worker disables her and deletes her activation and request.
    f.advance(45 * minute);
    const purge = await f.iam.purgeDeleted();
    expect(purge.expiredIdentities).toBe(1);
    expect(purge.expiredActivations).toBe(2);
    expect(await f.database.find('bindingActivations', { tenantId, identityId: alice.id })).toEqual(
      [],
    );
    const after = await f.report();
    expect(after.identities.expiring).toEqual([]);
    expect(after.bindings!.activations).toEqual([]);
    expect(after.bindings!.pendingRequests).toBe(0);
    const quiet = await f.digest();
    expect(quiet.sent).toEqual([]);
    expect(quiet.skipped.quiet).toBe(1);
  });

  it('drops group activations and requests of a holder whose membership lapsed', async () => {
    const f = await activationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const responders = await f.iam.api.groups.create(owner, { tenantId, name: 'Responders' });
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: responders.id,
      identityId: bob.id,
      expiresAt: f.now() + 30 * minute,
    });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: responders.id,
      identityId: carol.id,
    });
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: responders.id,
      identityId: dave.id,
    });
    for (const identity of [bob, carol, dave]) await f.canActivate(identity.id);
    const eligible = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.reader.id,
      subjectType: 'group',
      subjectId: responders.id,
      eligible: true,
    });
    const approval = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: f.writer.id,
      subjectType: 'group',
      subjectId: responders.id,
      eligible: true,
      requireApproval: true,
    });
    const asBob = { token: (await f.signIn('bob')).token };
    const asCarol = { token: (await f.signIn('carol')).token };
    const bobActivation = await f.iam.api.bindings.activate(asBob, {
      tenantId,
      bindingId: eligible.id,
    });
    await f.iam.api.bindings.activate(asBob, { tenantId, bindingId: approval.id });
    const carolActivation = await f.iam.api.bindings.activate(asCarol, {
      tenantId,
      bindingId: eligible.id,
    });
    const asDave = { token: (await f.signIn('dave')).token };
    const daveActivation = await f.iam.api.bindings.activate(asDave, {
      tenantId,
      bindingId: eligible.id,
    });
    const before = (await f.report()).bindings!;
    expect(before.activations.map((item) => item.id).sort()).toEqual(
      [bobActivation.id, carolActivation.id, daveActivation.id].sort(),
    );
    expect(before.pendingRequests).toBe(1);
    // Dave's membership row disappears underneath his activation (removeMember would clean it up; a direct
    // store edit or an import does not): he is no longer in the group, so it is no longer reported.
    const [daveMembership] = await f.database.find<StoredRecord>('groupMembers', {
      tenantId,
      groupId: responders.id,
      identityId: dave.id,
    });
    await f.database.transaction((tx) => tx.delete('groupMembers', daveMembership!.id));
    expect((await f.database.get('bindingActivations', daveActivation.id)) ?? null).not.toBeNull();
    const withoutDave = (await f.report()).bindings!;
    expect(withoutDave.activations.map((item) => item.id).sort()).toEqual(
      [bobActivation.id, carolActivation.id].sort(),
    );
    expect(withoutDave.pendingRequests).toBe(1);
    // Bob's membership lapses while his activation and request would still run.
    f.advance(45 * minute);
    const lapsed = (await f.report()).bindings!;
    expect(lapsed.activations.map((item) => item.id)).toEqual([carolActivation.id]);
    expect(lapsed.pendingRequests).toBe(0);
    expect(lapsed.expiringMemberships).toEqual([]);
    const purge = await f.iam.purgeDeleted();
    expect(purge.expiredMemberships).toBe(1);
    expect(await f.database.find('bindingActivations', { tenantId, identityId: bob.id })).toEqual(
      [],
    );
    const after = (await f.report()).bindings!;
    expect(after.activations.map((item) => item.id)).toEqual([carolActivation.id]);
    expect(after.pendingRequests).toBe(0);
  });
});

describe('expiry reminders for package records', () => {
  async function packageFixture() {
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
    const assign = async (name: string, expiresAt: number) => {
      const identity = await f.member(name);
      await f.iam.api.packages.assign(owner, {
        tenantId,
        packageId: kit.id,
        identityId: identity.id,
        expiresAt,
      });
      const assignment = (
        await f.database.find<StoredRecord>('packageAssignments', {
          tenantId,
          identityId: identity.id,
        })
      )[0]!;
      const binding = (
        await f.database.find<Tagged>('bindings', { tenantId, packageAssignmentId: assignment.id })
      )[0]!;
      const membership = (
        await f.database.find<Tagged>('groupMembers', {
          tenantId,
          packageAssignmentId: assignment.id,
        })
      )[0]!;
      return { identity, assignment, binding, membership };
    };
    const itemsOf = (to: string) => {
      const mails = f.inbox.filter(
        (message) => message.template === 'expiry-reminder' && message.to === to,
      );
      expect(mails).toHaveLength(1);
      return (
        JSON.parse(mails[0]!.payload.items!) as Array<{
          kind: string;
          name: string;
          expiresAt: number;
        }>
      ).sort((a, b) => (a.kind < b.kind ? -1 : a.kind > b.kind ? 1 : 0));
    };
    return { ...f, assign, itemsOf };
  }

  it('reminds records whose assignment no longer exists as role and group items', async () => {
    const f = await packageFixture();
    const { tenantId } = f;
    const dave = await f.assign('dave', f.now() + 4 * day);
    const erin = await f.assign('erin', f.now() + 3 * day);
    const frank = await f.assign('frank', f.now() + 5 * day);
    // Dave's assignment row is gone while its records live on.
    await f.database.transaction((tx) => tx.delete('packageAssignments', dave.assignment.id));
    // Erin's binding carries a tag that points at an assignment that does not exist.
    await f.database.transaction((tx) =>
      tx.put<Tagged>('bindings', { ...erin.binding, packageAssignmentId: 'deleted-assignment' }),
    );
    const run = await f.iam.sendExpiryReminders({ tenantId, withinMs: 7 * day });
    expect(run.sent.map((entry) => [entry.identityId, entry.items]).sort()).toEqual(
      [
        [dave.identity.id, 2],
        [erin.identity.id, 2],
        [frank.identity.id, 1],
      ].sort(),
    );
    await f.iam.auth.dispatchOutbox();
    expect(f.itemsOf('dave@acme.test')).toEqual([
      { kind: 'group', name: 'Project X', expiresAt: f.now() + 4 * day },
      { kind: 'role', name: 'Reader', expiresAt: f.now() + 4 * day },
    ]);
    expect(f.itemsOf('erin@acme.test')).toEqual([
      { kind: 'package', name: 'Kit', expiresAt: f.now() + 3 * day },
      { kind: 'role', name: 'Reader', expiresAt: f.now() + 3 * day },
    ]);
    // An intact assignment is still reminded once, as the package.
    expect(f.itemsOf('frank@acme.test')).toEqual([
      { kind: 'package', name: 'Kit', expiresAt: f.now() + 5 * day },
    ]);
  });

  it('reminds records outliving an ended assignment the worker purged', async () => {
    const f = await packageFixture();
    const { tenantId } = f;
    const gina = await f.assign('gina', f.now() + day);
    // Records that were given a later end without losing their tag (as hand edits used to leave them).
    await f.database.transaction(async (tx) => {
      await tx.put<Tagged>('bindings', { ...gina.binding, expiresAt: f.now() + 4 * day });
      await tx.put<Tagged>('groupMembers', { ...gina.membership, expiresAt: f.now() + 4 * day });
    });
    f.advance(day + minute);
    const purge = await f.iam.purgeDeleted();
    expect(purge.expiredAssignments).toBe(1);
    expect(purge.expiredBindings).toBe(0);
    expect(purge.expiredMemberships).toBe(0);
    expect((await f.database.get('packageAssignments', gina.assignment.id)) ?? null).toBeNull();
    const run = await f.iam.sendExpiryReminders({ tenantId, withinMs: 7 * day });
    expect(run.sent).toEqual([{ tenantId, identityId: gina.identity.id, items: 2 }]);
    await f.iam.auth.dispatchOutbox();
    const end = f.now() - day - minute + 4 * day;
    expect(f.itemsOf('gina@acme.test')).toEqual([
      { kind: 'group', name: 'Project X', expiresAt: end },
      { kind: 'role', name: 'Reader', expiresAt: end },
    ]);
  });
});

describe('expiry reminder marks', () => {
  it('keep reminders from repeating after the audit trail is pruned, until the item ends', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const start = f.now();
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const project = await f.iam.api.groups.create(owner, { tenantId, name: 'Project X' });
    const alice = await f.member('alice', { expiresAt: start + 3 * day });
    const bob = await f.member('bob');
    const binding = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: bob.id,
      expiresAt: start + 2 * day,
    });
    const carol = await f.member('carol');
    const membership = await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: project.id,
      identityId: carol.id,
      expiresAt: start + 5 * day,
    });
    const first = await f.iam.sendExpiryReminders({ tenantId, withinMs: 7 * day });
    expect(first.sent.map((entry) => entry.identityId).sort()).toEqual(
      [alice.id, bob.id, carol.id].sort(),
    );
    const marks = async () =>
      (await f.database.find<Mark>('expiryReminderMarks', { tenantId }))
        .map((mark) => [mark.uniqueKey, mark.identityId, mark.expiresAt])
        .sort();
    const all = [
      [`identity:${alice.id}:${start + 3 * day}`, alice.id, start + 3 * day],
      [`binding:${binding.id}:${start + 2 * day}`, bob.id, start + 2 * day],
      [`membership:${membership.id}:${start + 5 * day}`, carol.id, start + 5 * day],
    ].sort();
    expect(await marks()).toEqual(all);
    expect(
      await f.database.find('audit', { tenantId, action: 'identity:expiry-reminder' }),
    ).toHaveLength(3);
    // Retention drops every event so far, the reminder trail included (the prune uses the wall clock).
    await new Promise((resolve) => setTimeout(resolve, 5));
    const pruned = await f.iam.pruneAudit({ tenantId, retentionMs: 0 });
    expect(pruned.deleted).toBeGreaterThan(0);
    expect(
      await f.database.find('audit', { tenantId, action: 'identity:expiry-reminder' }),
    ).toEqual([]);
    // The marks still remember what was reminded: nothing new is sent and no mark is duplicated.
    const again = await f.iam.sendExpiryReminders({ tenantId, withinMs: 7 * day });
    expect(again.sent).toEqual([]);
    expect(again.skipped).toEqual({ inactive: 0, quiet: 1 });
    expect(await marks()).toEqual(all);
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.filter((message) => message.template === 'expiry-reminder')).toHaveLength(3);
    // The worker drops a mark once its item has ended, and only then.
    f.advance(2 * day + minute);
    await f.iam.purgeDeleted();
    expect(await marks()).toEqual(all.filter(([, identityId]) => identityId !== bob.id));
    f.advance(day);
    await f.iam.purgeDeleted();
    expect(await marks()).toEqual([
      [`membership:${membership.id}:${start + 5 * day}`, carol.id, start + 5 * day],
    ]);
    expect((await f.iam.sendExpiryReminders({ tenantId, withinMs: 7 * day })).sent).toEqual([]);
  });
});

describe('tenant purge and web identity federation', () => {
  it("removes a purged tenant's OIDC providers and replay records, and no other tenant's", async () => {
    const f = await organizationFixture({ sts: { webIdentity: { enabled: true } } });
    const { tenantId } = f;
    const platform = f.root.tenant.id;
    const key = generateTestKey('RS256', 'purge-key');
    const providerInput = (target: string) => ({
      tenantId: target,
      name: 'CI',
      issuer: 'https://token.ci.example.test',
      audiences: ['https://iam.example.test'],
      jwks: { keys: [key.publicJwk as never] },
    });
    const doomed = await f.iam.api.oidcProviders.create(f.ownerCredential, providerInput(tenantId));
    const kept = await f.iam.api.oidcProviders.create(f.rootCredential, providerInput(platform));
    // Replay records as the exchange stores them: keyed by the replay id, scoped to the provider's tenant.
    await f.database.transaction(async (tx) => {
      for (const provider of [doomed, kept])
        await tx.insert('webIdentityReplays', {
          id: webIdentityReplayId(provider.id, 'jti-1', 'unused'),
          tenantId: provider.tenantId,
          providerId: provider.id,
          expiresAt: f.now() + 365 * day,
        });
    });
    const rows = async (collection: string, target: string) =>
      (await f.database.find<StoredRecord>(collection, { tenantId: target })).map((row) => row.id);
    expect(await rows('oidcProviders', tenantId)).toEqual([doomed.id]);
    expect(await rows('webIdentityReplays', tenantId)).toHaveLength(1);

    await f.iam.api.tenants.setStatus(f.rootCredential, { tenantId, status: 'deleted' });
    const purge = await f.iam.purgeDeleted({ retentionMs: 0 });
    expect(purge.purgedTenants).toContain(tenantId);
    expect(await rows('oidcProviders', tenantId)).toEqual([]);
    expect(await rows('webIdentityReplays', tenantId)).toEqual([]);
    expect(await f.database.get('oidcProviders', doomed.id)).toBeUndefined();
    // The platform's provider and its replay record are untouched.
    expect(await rows('oidcProviders', platform)).toEqual([kept.id]);
    expect(await rows('webIdentityReplays', platform)).toEqual([
      webIdentityReplayId(kept.id, 'jti-1', 'unused'),
    ]);
  });
});
