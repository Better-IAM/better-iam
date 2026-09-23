import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { AuditEvent } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';
import { closeFixtures, organizationFixture } from './support/organization.js';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  const iam = betterIam({
    database,
    secret: 'certifications-test-secret-with-32-characters',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
    },
    permissions: { actions: ['documents:read', 'documents:write'] },
    resolveResource: async (reference) => reference,
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: authenticator.generate(enrollment.secret),
  });
  const created = await iam.api.tenants.create(
    { token: session.token },
    { parentId: root.tenant.id, name: 'Acme', type: 'organization', ownerEmail: 'owner@acme.test' },
  );
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  const tenantId = created.tenant.id;
  const ownerCredential = { token: owner.token };
  const member = (name: string) =>
    iam.api.identities.create(ownerCredential, {
      tenantId,
      email: `${name}@acme.test`,
      name,
      password: `a strong ${name} password`,
    });
  const signIn = async (name: string) => {
    const result = await iam.api.auth.signIn({
      tenantId,
      email: `${name}@acme.test`,
      password: `a strong ${name} password`,
    });
    if (!('token' in result)) throw new Error('Unexpected MFA');
    return { token: result.token };
  };
  return {
    iam,
    inbox,
    tenantId,
    owner: ownerCredential,
    root: { token: session.token },
    member,
    signIn,
  };
}

describe('access certification campaigns', () => {
  it('snapshots bindings, collects reviewer decisions, and applies them on close', async () => {
    const f = await fixture();
    const { tenantId, owner } = f;
    const api = f.iam.api;
    const readers = await api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const writers = await api.roles.create(owner, {
      tenantId,
      name: 'Writers',
      permissions: ['documents:write'],
    });
    const reviewers = await api.roles.create(owner, {
      tenantId,
      name: 'Reviewers',
      permissions: ['iam:certifications:read', 'iam:certifications:review'],
    });
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const dave = await f.member('dave');
    const team = await api.groups.create(owner, { tenantId, name: 'Team' });
    await api.groups.addMember(owner, { tenantId, groupId: team.id, identityId: bob.id });
    const bind = (roleId: string, subjectType: 'identity' | 'group', subjectId: string) =>
      api.bindings.create(owner, { tenantId, roleId, subjectType, subjectId });
    await bind(readers.id, 'identity', alice.id);
    await bind(writers.id, 'identity', bob.id);
    await bind(readers.id, 'group', team.id);
    await bind(reviewers.id, 'identity', carol.id);
    await bind(reviewers.id, 'identity', dave.id);
    // A binding issued under root's authority: the owner may not remove it.
    const rootBinding = await api.bindings.create(f.root, {
      tenantId,
      roleId: writers.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });

    await expect(
      api.certifications.create(owner, { tenantId, name: 'Bad', reviewerIds: ['missing'] }),
    ).rejects.toMatchObject({ status: 404 });
    const campaign = await api.certifications.create(owner, {
      tenantId,
      name: 'Q3 access review',
      reviewerIds: [carol.id],
      undecided: 'revoke',
    });
    // Owner bindings (protected roles) are never part of a campaign.
    expect(campaign.items).toBe(6);
    expect(campaign.status).toBe('open');
    // Named reviewers are emailed.
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.filter((message) => message.template === 'certification-review')).toEqual([
      expect.objectContaining({
        to: 'carol@acme.test',
        payload: expect.objectContaining({ campaignName: 'Q3 access review', items: '6' }),
      }),
    ]);

    const carolCredential = await f.signIn('carol');
    const view = await api.certifications.get(carolCredential, {
      tenantId,
      campaignId: campaign.id,
      mine: true,
    });
    expect(view.items).toHaveLength(5);
    const item = (subject: string, role: string) =>
      view.items.find((row) => row.subjectName === subject && row.roleName === role)!;
    const allItems = (await api.certifications.get(owner, { tenantId, campaignId: campaign.id }))
      .items;
    const carolOwn = allItems.find((row) => row.subjectName === 'carol@acme.test')!;
    await expect(
      api.certifications.decide(carolCredential, {
        tenantId,
        campaignId: campaign.id,
        decisions: [{ itemId: carolOwn.id, decision: 'keep' }],
      }),
    ).rejects.toMatchObject({ code: 'SELF_REVIEW' });
    // Dave holds the review permission but is not a reviewer of this campaign.
    await expect(
      api.certifications.decide(await f.signIn('dave'), {
        tenantId,
        campaignId: campaign.id,
        decisions: [{ itemId: item('alice@acme.test', 'Readers').id, decision: 'keep' }],
      }),
    ).rejects.toMatchObject({ status: 403 });
    // Alice lacks iam:certifications:review altogether.
    await expect(
      api.certifications.decide(await f.signIn('alice'), {
        tenantId,
        campaignId: campaign.id,
        decisions: [{ itemId: item('alice@acme.test', 'Readers').id, decision: 'keep' }],
      }),
    ).rejects.toMatchObject({ status: 403 });

    const recorded = await api.certifications.decide(carolCredential, {
      tenantId,
      campaignId: campaign.id,
      decisions: [
        { itemId: item('alice@acme.test', 'Readers').id, decision: 'keep' },
        { itemId: item('alice@acme.test', 'Writers').id, decision: 'revoke', note: 'Left team' },
        { itemId: item('bob@acme.test', 'Writers').id, decision: 'revoke' },
        { itemId: item('dave@acme.test', 'Reviewers').id, decision: 'keep' },
      ],
    });
    expect(recorded).toEqual({ recorded: 4 });
    const listed = await api.certifications.list(owner, { tenantId });
    expect(listed[0]!.progress).toEqual({ total: 6, decided: 4, keep: 2, revoke: 2 });

    const closed = await api.certifications.close(owner, { tenantId, campaignId: campaign.id });
    expect(closed.status).toBe('closed');
    // Kept: alice Readers, dave Reviewers. Revoked: bob Writers, plus undecided Team and carol (undecided = revoke).
    // Alice's Writers binding belongs to root's authority, so the owner cannot remove it.
    expect(closed.outcomes).toEqual({
      kept: 2,
      revoked: 3,
      'already-removed': 0,
      'revocation-failed': 1,
    });
    const after = await api.certifications.get(owner, { tenantId, campaignId: campaign.id });
    const failed = after.items.find((row) => row.outcome === 'revocation-failed')!;
    expect(failed.bindingId).toBe(rootBinding.id);
    expect(failed.outcomeDetail).toBeTruthy();
    const remaining = await f.iam.store.find('bindings', { tenantId });
    const bindingKeys = remaining.map((row) => `${row.subjectId}:${row.roleId}`);
    expect(bindingKeys).toContain(`${alice.id}:${readers.id}`);
    expect(bindingKeys).toContain(`${alice.id}:${writers.id}`);
    expect(bindingKeys).not.toContain(`${bob.id}:${writers.id}`);
    expect(bindingKeys).not.toContain(`${team.id}:${readers.id}`);
    expect(bindingKeys).not.toContain(`${carol.id}:${reviewers.id}`);
    expect(
      (await f.iam.store.find('audit', { tenantId, action: 'iam:bindings:delete' })).length,
    ).toBe(3);

    await expect(
      api.certifications.decide(owner, {
        tenantId,
        campaignId: campaign.id,
        decisions: [{ itemId: failed.id, decision: 'keep' }],
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      api.certifications.close(owner, { tenantId, campaignId: campaign.id }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await api.certifications.delete(owner, { tenantId, campaignId: campaign.id });
    expect(await f.iam.store.find('certificationItems', { tenantId })).toHaveLength(0);
  });

  it('scopes campaigns by role and subject type and keeps undecided access by default', async () => {
    const f = await fixture();
    const { tenantId, owner } = f;
    const api = f.iam.api;
    const readers = await api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const writers = await api.roles.create(owner, {
      tenantId,
      name: 'Writers',
      permissions: ['documents:write'],
    });
    const erin = await f.member('erin');
    const group = await api.groups.create(owner, { tenantId, name: 'Crew' });
    await api.bindings.create(owner, {
      tenantId,
      roleId: readers.id,
      subjectType: 'identity',
      subjectId: erin.id,
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: writers.id,
      subjectType: 'identity',
      subjectId: erin.id,
    });
    await api.bindings.create(owner, {
      tenantId,
      roleId: readers.id,
      subjectType: 'group',
      subjectId: group.id,
    });
    const scoped = await api.certifications.create(owner, {
      tenantId,
      name: 'Readers only',
      roleIds: [readers.id],
      subjectType: 'identity',
    });
    expect(scoped.items).toBe(1);
    const ownerRole = (await f.iam.store.find('roles', { tenantId })).find(
      (role) => role.protected === true,
    )!;
    await expect(
      api.certifications.create(owner, { tenantId, name: 'Owners', roleIds: [ownerRole.id] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const result = await api.certifications.close(owner, { tenantId, campaignId: scoped.id });
    expect(result.outcomes.kept).toBe(1);
    expect(await f.iam.store.find('bindings', { tenantId, subjectId: erin.id })).toHaveLength(2);
    await expect(
      api.certifications.delete(owner, {
        tenantId,
        campaignId: (await api.certifications.create(owner, { tenantId, name: 'Open' })).id,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
  });
});

describe('manager reviews, reminders, and automatic closing', () => {
  afterEach(closeFixtures);
  const day = 86400000;

  it('assigns items to managers, who review them without the review permission', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const readers = await api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const writers = await api.roles.create(owner, {
      tenantId,
      name: 'Writers',
      permissions: ['documents:write'],
    });
    const reviewers = await api.roles.create(owner, {
      tenantId,
      name: 'Reviewers',
      permissions: ['iam:certifications:read', 'iam:certifications:review'],
    });
    // Mia manages Alice and Bob and holds no role at all; Paul manages Dana but is disabled.
    const mia = await f.member('mia');
    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carl = await f.member('carl');
    const dana = await f.member('dana');
    const paul = await f.member('paul');
    const nina = await f.member('nina');
    const rex = await f.member('rex');
    for (const [person, manager] of [
      [alice, mia],
      [bob, mia],
      [dana, paul],
    ] as const)
      await api.identities.update(owner, {
        tenantId,
        identityId: person.id,
        managerId: manager.id,
      });
    await api.identities.setStatus(owner, { tenantId, identityId: paul.id, status: 'disabled' });
    const team = await api.groups.create(owner, { tenantId, name: 'Team' });
    const bind = (roleId: string, subjectType: 'identity' | 'group', subjectId: string) =>
      api.bindings.create(owner, { tenantId, roleId, subjectType, subjectId });
    await bind(readers.id, 'identity', alice.id);
    await bind(writers.id, 'identity', alice.id);
    await bind(readers.id, 'identity', bob.id);
    await bind(readers.id, 'identity', carl.id);
    await bind(readers.id, 'identity', dana.id);
    await bind(readers.id, 'group', team.id);
    await bind(reviewers.id, 'identity', nina.id);
    await bind(reviewers.id, 'identity', rex.id);

    await expect(
      api.certifications.create(owner, {
        tenantId,
        name: 'Bad',
        reviewerMode: 'team' as 'manager',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const dueAt = f.now() + 7 * day;
    const campaign = await api.certifications.create(owner, {
      tenantId,
      name: 'Manager review',
      reviewerMode: 'manager',
      reviewerIds: [nina.id],
      dueAt,
    });
    expect(campaign).toMatchObject({ reviewerMode: 'manager', items: 8 });
    expect(campaign.autoClose).toBeUndefined();
    const all = (await api.certifications.get(owner, { tenantId, campaignId: campaign.id })).items;
    const item = (subject: string, role: string) =>
      all.find((row) => row.subjectName === subject && row.roleName === role)!;
    expect(
      all
        .filter((row) => row.reviewerId === mia.id)
        .map((row) => `${row.subjectName} ${row.roleName}`)
        .sort(),
    ).toEqual(['alice@acme.test Readers', 'alice@acme.test Writers', 'bob@acme.test Readers']);
    // Everything else falls back to the named reviewer: no manager, a disabled manager, or a group.
    expect(all.filter((row) => row.reviewerId === undefined)).toHaveLength(5);
    expect(item('dana@acme.test', 'Readers').reviewerId).toBeUndefined();
    expect(item('Team', 'Readers').reviewerId).toBeUndefined();

    // One email per reviewer with their own item count.
    await f.iam.auth.dispatchOutbox();
    const invitations = f.inbox.filter((message) => message.template === 'certification-review');
    expect(invitations).toHaveLength(2);
    expect(invitations).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          to: 'mia@acme.test',
          payload: expect.objectContaining({
            campaignId: campaign.id,
            campaignName: 'Manager review',
            items: '3',
            dueAt: new Date(dueAt).toISOString(),
          }),
        }),
        expect.objectContaining({
          to: 'nina@acme.test',
          payload: expect.objectContaining({ items: '5' }),
        }),
      ]),
    );

    // The manager's own worklist.
    const miaCredential = { token: (await f.signIn('mia')).token };
    const mine = await api.certifications.listMine(miaCredential, { tenantId });
    expect(mine).toHaveLength(1);
    expect(mine[0]).toMatchObject({
      id: campaign.id,
      name: 'Manager review',
      dueAt,
      reviewerMode: 'manager',
      progress: { total: 3, decided: 0, keep: 0, revoke: 0 },
    });
    expect(mine[0]!.items.map((row) => `${row.subjectName} ${row.roleName}`)).toEqual([
      'alice@acme.test Readers',
      'bob@acme.test Readers',
      'alice@acme.test Writers',
    ]);
    const carlCredential = { token: (await f.signIn('carl')).token };
    expect(await api.certifications.listMine(carlCredential, { tenantId })).toEqual([]);
    await expect(
      api.certifications.listMine(miaCredential, { tenantId: f.root.tenant.id }),
    ).rejects.toMatchObject({ status: 403 });

    // Reminders before anyone decided: Mia for her three, Nina for the five fallback items.
    const ninaCredential = { token: (await f.signIn('nina')).token };
    await expect(
      api.certifications.remind(ninaCredential, { tenantId, campaignId: campaign.id }),
    ).rejects.toMatchObject({ status: 403 });
    expect(await api.certifications.remind(owner, { tenantId, campaignId: campaign.id })).toEqual({
      reminded: 2,
      pending: 8,
    });
    await f.iam.auth.dispatchOutbox();
    expect(
      f.inbox
        .filter((message) => message.template === 'certification-reminder')
        .map((message) => `${message.to} ${message.payload.pending}`)
        .sort(),
    ).toEqual(['mia@acme.test 3', 'nina@acme.test 5']);

    // decide(): manager-assigned items belong to the manager; fallback items to the named reviewers.
    const decideAs = (credential: { token: string }, itemId: string) =>
      api.certifications.decide(credential, {
        tenantId,
        campaignId: campaign.id,
        decisions: [{ itemId, decision: 'keep' }],
      });
    await expect(
      decideAs(miaCredential, item('alice@acme.test', 'Readers').id),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      decideAs(ninaCredential, item('alice@acme.test', 'Readers').id),
    ).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      message: "This item is assigned to the person's manager",
    });
    await expect(
      decideAs(ninaCredential, item('nina@acme.test', 'Reviewers').id),
    ).rejects.toMatchObject({ code: 'SELF_REVIEW' });
    const rexCredential = { token: (await f.signIn('rex')).token };
    await expect(
      decideAs(rexCredential, item('carl@acme.test', 'Readers').id),
    ).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
      message: 'You are not a reviewer of this campaign',
    });
    await expect(
      decideAs(rexCredential, item('bob@acme.test', 'Readers').id),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await api.certifications.decide(ninaCredential, {
        tenantId,
        campaignId: campaign.id,
        decisions: [
          { itemId: item('carl@acme.test', 'Readers').id, decision: 'keep' },
          { itemId: item('dana@acme.test', 'Readers').id, decision: 'revoke' },
        ],
      }),
    ).toEqual({ recorded: 2 });
    // Holders of iam:certifications:manage may still decide a manager's item.
    expect(await decideAs(owner, item('bob@acme.test', 'Readers').id)).toEqual({ recorded: 1 });

    // review(): the manager decides their own items, and only those.
    const review = (
      credential: { token: string },
      decisions: { itemId: string; decision: 'keep' | 'revoke'; note?: string }[],
      tenant = tenantId,
    ) =>
      api.certifications.review(credential, {
        tenantId: tenant,
        campaignId: campaign.id,
        decisions,
      });
    await expect(
      review(miaCredential, [{ itemId: item('carl@acme.test', 'Readers').id, decision: 'keep' }]),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
    await expect(
      review(miaCredential, [{ itemId: 'missing', decision: 'keep' }]),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      review(
        miaCredential,
        [{ itemId: item('alice@acme.test', 'Readers').id, decision: 'keep' }],
        f.root.tenant.id,
      ),
    ).rejects.toMatchObject({ status: 403 });
    await expect(review(miaCredential, [])).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      review(rexCredential, [{ itemId: item('alice@acme.test', 'Readers').id, decision: 'keep' }]),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await review(miaCredential, [
        { itemId: item('alice@acme.test', 'Readers').id, decision: 'keep' },
        { itemId: item('alice@acme.test', 'Writers').id, decision: 'revoke', note: 'Moved team' },
      ]),
    ).toEqual({ recorded: 2 });
    const reviewed = await f.iam.store.find<AuditEvent>('audit', {
      tenantId,
      action: 'certification:review',
    });
    expect(reviewed).toEqual([
      expect.objectContaining({
        actorId: mia.id,
        resourceId: campaign.id,
        outcome: 'allow',
        metadata: { recorded: 2, keep: 1, revoke: 1 },
      }),
    ]);
    const decidedWriters = (
      await api.certifications.get(owner, { tenantId, campaignId: campaign.id })
    ).items.find((row) => row.id === item('alice@acme.test', 'Writers').id)!;
    expect(decidedWriters).toMatchObject({
      decision: 'revoke',
      decidedBy: mia.id,
      note: 'Moved team',
    });
    expect((await api.certifications.listMine(miaCredential, { tenantId }))[0]!.progress).toEqual({
      total: 3,
      decided: 3,
      keep: 2,
      revoke: 1,
    });

    // Only the three unassigned, undecided items remain, all Nina's.
    expect(await api.certifications.remind(owner, { tenantId, campaignId: campaign.id })).toEqual({
      reminded: 1,
      pending: 3,
    });

    const closed = await api.certifications.close(owner, { tenantId, campaignId: campaign.id });
    expect(closed.closedBy).toBe(f.ownerId);
    expect(closed.outcomes).toEqual({
      kept: 6,
      revoked: 2,
      'already-removed': 0,
      'revocation-failed': 0,
    });
    const remaining = (await f.iam.store.find('bindings', { tenantId })).map(
      (row) => `${row.subjectId} ${row.roleId}`,
    );
    expect(remaining).not.toContain(`${alice.id} ${writers.id}`);
    expect(remaining).not.toContain(`${dana.id} ${readers.id}`);
    expect(remaining).toContain(`${alice.id} ${readers.id}`);
    await expect(
      review(miaCredential, [{ itemId: item('bob@acme.test', 'Readers').id, decision: 'keep' }]),
    ).rejects.toMatchObject({ code: 'CONFLICT', status: 409 });
    await expect(
      api.certifications.remind(owner, { tenantId, campaignId: campaign.id }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect(await api.certifications.listMine(miaCredential, { tenantId })).toEqual([]);
  });

  it('reminds nobody for unnamed fallback items and requires email delivery', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const readers = await api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const erin = await f.member('erin');
    await api.bindings.create(owner, {
      tenantId,
      roleId: readers.id,
      subjectType: 'identity',
      subjectId: erin.id,
    });
    const campaign = await api.certifications.create(owner, { tenantId, name: 'Open to all' });
    expect(campaign.reviewerMode).toBe('named');
    expect(await api.certifications.remind(owner, { tenantId, campaignId: campaign.id })).toEqual({
      reminded: 0,
      pending: 1,
    });
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.filter((message) => message.template === 'certification-reminder')).toEqual([]);
    // The same deployment without an email callback cannot send reminders.
    const silent = betterIam({
      database: f.database,
      secret: 'organization-fixture-secret-with-32-characters',
      baseURL: 'http://localhost:3000',
      permissions: { actions: ['documents:read', 'documents:write'] },
      resolveResource: async (reference) => reference,
      authentication: {
        sessionLifetimeMs: 7 * day,
        sessionIdleTimeoutMs: 7 * day,
        now: f.now,
      },
    });
    await expect(
      silent.api.certifications.remind(owner, { tenantId, campaignId: campaign.id }),
    ).rejects.toMatchObject({ code: 'DELIVERY_REQUIRED' });
  });

  it('closes overdue auto-closing campaigns under the creator authority', async () => {
    const f = await organizationFixture();
    const { tenantId, ownerCredential: owner } = f;
    const api = f.iam.api;
    const readers = await api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      permissions: ['documents:read'],
    });
    const writers = await api.roles.create(owner, {
      tenantId,
      name: 'Writers',
      permissions: ['documents:write'],
    });
    const certifiers = await api.roles.create(owner, {
      tenantId,
      name: 'Certifiers',
      permissions: ['iam:certifications:manage'],
    });
    const erin = await f.member('erin');
    const finn = await f.member('finn');
    const gail = await f.member('gail');
    const adam = await f.member('adam');
    const bind = (roleId: string, subjectId: string) =>
      api.bindings.create(owner, { tenantId, roleId, subjectType: 'identity', subjectId });
    await bind(readers.id, erin.id);
    const finnBinding = await bind(readers.id, finn.id);
    const gailBinding = await bind(readers.id, gail.id);
    await bind(writers.id, erin.id);
    await bind(certifiers.id, adam.id);

    await expect(
      api.certifications.create(owner, { tenantId, name: 'No date', autoClose: true }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const due = await api.certifications.create(owner, {
      tenantId,
      name: 'Due',
      roleIds: [readers.id],
      dueAt: f.now() + day,
      autoClose: true,
      undecided: 'revoke',
    });
    expect(due.autoClose).toBe(true);
    const later = await api.certifications.create(owner, {
      tenantId,
      name: 'Later',
      roleIds: [readers.id],
      dueAt: f.now() + 10 * day,
      autoClose: true,
    });
    const manual = await api.certifications.create(owner, {
      tenantId,
      name: 'Manual',
      roleIds: [readers.id],
      dueAt: f.now() + day,
    });
    const erinItem = (
      await api.certifications.get(owner, { tenantId, campaignId: due.id })
    ).items.find((row) => row.subjectId === erin.id)!;
    await api.certifications.decide(owner, {
      tenantId,
      campaignId: due.id,
      decisions: [{ itemId: erinItem.id, decision: 'keep' }],
    });
    // Adam opens a campaign and is deleted before it closes: nothing is revoked on his behalf.
    const orphan = await api.certifications.create(
      { token: (await f.signIn('adam')).token },
      {
        tenantId,
        name: 'Orphan',
        roleIds: [writers.id],
        dueAt: f.now() + day,
        autoClose: true,
        undecided: 'revoke',
      },
    );
    await api.identities.delete(owner, { tenantId, identityId: adam.id });

    expect(await f.iam.closeOverdueCertifications()).toEqual({ closed: [], skipped: 3 });
    f.advance(2 * day);
    const result = await f.iam.closeOverdueCertifications();
    expect(result.skipped).toBe(1);
    expect(result.closed).toHaveLength(2);
    expect(result.closed).toEqual(
      expect.arrayContaining([
        {
          tenantId,
          campaignId: due.id,
          outcomes: { kept: 1, revoked: 2, 'already-removed': 0, 'revocation-failed': 0 },
        },
        {
          tenantId,
          campaignId: orphan.id,
          outcomes: { kept: 0, revoked: 0, 'already-removed': 0, 'revocation-failed': 1 },
        },
      ]),
    );

    const closedDue = await api.certifications.get(owner, { tenantId, campaignId: due.id });
    expect(closedDue).toMatchObject({
      status: 'closed',
      closedBy: 'deployment-operator',
      closedAt: f.now(),
    });
    const orphanItems = (await api.certifications.get(owner, { tenantId, campaignId: orphan.id }))
      .items;
    expect(orphanItems).toEqual([
      expect.objectContaining({
        outcome: 'revocation-failed',
        outcomeDetail: expect.stringContaining('creator'),
      }),
    ]);
    expect((await api.certifications.get(owner, { tenantId, campaignId: manual.id })).status).toBe(
      'open',
    );
    const remaining = (await f.iam.store.find('bindings', { tenantId })).map((row) => row.id);
    expect(remaining).not.toContain(finnBinding.id);
    expect(remaining).not.toContain(gailBinding.id);
    expect(await f.iam.store.find('bindings', { tenantId, subjectId: erin.id })).toHaveLength(2);

    const autoClosed = await f.iam.store.find<AuditEvent>('audit', {
      tenantId,
      action: 'certification:auto-close',
    });
    expect(autoClosed.map((event) => event.resourceId).sort()).toEqual([due.id, orphan.id].sort());
    expect(autoClosed.find((event) => event.resourceId === due.id)).toMatchObject({
      actorId: 'deployment-operator',
      outcome: 'allow',
      metadata: { kept: 1, revoked: 2, 'already-removed': 0, 'revocation-failed': 0 },
    });
    const revocations = (
      await f.iam.store.find<AuditEvent>('audit', { tenantId, action: 'iam:bindings:delete' })
    ).filter((event) => event.actorId === 'deployment-operator');
    expect(revocations.map((event) => event.resourceId).sort()).toEqual(
      [finnBinding.id, gailBinding.id].sort(),
    );
    expect(revocations.every((event) => event.metadata?.campaignId === due.id)).toBe(true);

    // A second run finds nothing new; a tenant filter limits the sweep.
    expect(await f.iam.closeOverdueCertifications()).toEqual({ closed: [], skipped: 1 });
    expect(await f.iam.closeOverdueCertifications({ tenantId: f.root.tenant.id })).toEqual({
      closed: [],
      skipped: 0,
    });
    f.advance(10 * day);
    expect(await f.iam.closeOverdueCertifications({ tenantId })).toEqual({
      closed: [
        {
          tenantId,
          campaignId: later.id,
          outcomes: { kept: 3, revoked: 0, 'already-removed': 0, 'revocation-failed': 0 },
        },
      ],
      skipped: 0,
    });
  });
});
