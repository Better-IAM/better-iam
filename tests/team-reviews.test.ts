import { afterEach, describe, expect, it } from 'vitest';
import { renderDeliveryMessage } from '@better-iam/auth';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const day = 86_400_000;

async function scenario() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const [alice, bob, carol, dave, erin] = [
    await f.member('alice'),
    await f.member('bob'),
    await f.member('carol'),
    await f.member('dave'),
    await f.member('erin'),
  ];
  const contractors = await f.iam.api.groups.create(owner, { tenantId, name: 'Contractors' });
  await f.iam.api.groups.addMember(owner, {
    tenantId,
    groupId: contractors.id,
    identityId: erin.id,
  });
  const team = await f.iam.api.teams.create(owner, {
    tenantId,
    name: 'Platform',
    maintainerIds: [bob.id],
    syncGroupIds: [contractors.id],
  });
  await f.iam.api.teams.addMembers(owner, {
    tenantId,
    teamId: team.id,
    identityIds: [alice.id, carol.id, dave.id],
  });
  const bobSession = { token: (await f.signIn('bob')).token };
  const members = async () =>
    (await f.iam.api.teams.listMembers(owner, { tenantId, teamId: team.id }))
      .map((member) => member.name)
      .sort();
  return { f, tenantId, owner, alice, bob, carol, dave, erin, team, bobSession, members };
}

describe('team membership reviews', () => {
  it('lets maintainers decide who stays, and applies the removals when the review completes', async () => {
    const s = await scenario();
    const review = await s.f.iam.api.teams.startReview(s.owner, {
      tenantId: s.tenantId,
      teamId: s.team.id,
      note: 'Quarterly check',
    });
    // Synced members are reviewed through their source group.
    expect(review.items!.map((item) => item.person.name).sort()).toEqual([
      'alice',
      'bob',
      'carol',
      'dave',
    ]);
    expect(review).toMatchObject({
      status: 'open',
      onUndecided: 'keep',
      dueAt: s.f.now() + 14 * day,
      counts: { total: 4, keep: 0, remove: 0, undecided: 4 },
    });
    await expect(
      s.f.iam.api.teams.startReview(s.owner, { tenantId: s.tenantId, teamId: s.team.id }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await s.f.iam.auth.dispatchOutbox();
    expect(
      s.f.inbox.filter((message) => message.template === 'team-review-requested').map((m) => m.to),
    ).toEqual(['bob@acme.test']);
    const mail = s.f.inbox.find((message) => message.template === 'team-review-requested')!;
    const rendered = renderDeliveryMessage(mail, {
      links: { team: ({ tenantId, teamId }) => `https://app.test/${tenantId}/teams/${teamId}` },
    });
    expect(rendered?.subject).toBe('Review the members of Platform');
    expect(rendered?.text).toContain('(4 people)');
    expect(rendered?.text).toContain('People nobody decides on then stay in the team.');
    expect(rendered?.text).toContain(`https://app.test/${s.tenantId}/teams/${s.team.id}`);

    // The maintainer sees it waiting, without counting their own membership.
    const mine = await s.f.iam.api.teams.listMine(s.bobSession, { tenantId: s.tenantId });
    expect(mine.reviews).toEqual([
      {
        id: review.id,
        team: expect.objectContaining({ id: s.team.id }),
        dueAt: review.dueAt,
        undecided: 3,
      },
    ]);
    const decided = await s.f.iam.api.teams.decideReview(s.bobSession, {
      tenantId: s.tenantId,
      reviewId: review.id,
      decisions: [
        { identityId: s.alice.id, decision: 'keep' },
        { identityId: s.carol.id, decision: 'remove', note: 'Moved to Sales' },
      ],
    });
    expect(decided.counts).toEqual({ total: 4, keep: 1, remove: 1, undecided: 2 });
    expect(decided.items!.find((item) => item.person.name === 'carol')).toMatchObject({
      decision: 'remove',
      note: 'Moved to Sales',
      decidedBy: { name: 'bob' },
    });
    await expect(
      s.f.iam.api.teams.decideReview(s.bobSession, {
        tenantId: s.tenantId,
        reviewId: review.id,
        decisions: [{ identityId: s.bob.id, decision: 'keep' }],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      s.f.iam.api.teams.decideReview(s.bobSession, {
        tenantId: s.tenantId,
        reviewId: review.id,
        decisions: [{ identityId: s.erin.id, decision: 'remove' }],
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Decisions change nothing until the review completes, and a maintainer completes only a fully decided review.
    expect(await s.members()).toEqual(['alice', 'bob', 'carol', 'dave', 'erin']);
    await expect(
      s.f.iam.api.teams.completeReview(s.bobSession, { tenantId: s.tenantId, reviewId: review.id }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });

    // Members cannot read the review; an administrator completes it early (bob and dave stay: onUndecided keep).
    const alice = { token: (await s.f.signIn('alice')).token };
    await expect(
      s.f.iam.api.teams.getReview(alice, { tenantId: s.tenantId, reviewId: review.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const completed = await s.f.iam.api.teams.completeReview(s.owner, {
      tenantId: s.tenantId,
      reviewId: review.id,
    });
    expect(completed).toMatchObject({
      status: 'completed',
      outcome: { kept: 3, removed: 1, undecided: 2, gone: 0 },
    });
    expect(await s.members()).toEqual(['alice', 'bob', 'dave', 'erin']);
    const trail = await s.f.iam.api.audit.list(s.owner, {
      tenantId: s.tenantId,
      action: 'team:member:remove',
    });
    expect(trail[0]?.metadata).toMatchObject({ identityId: s.carol.id, source: 'review' });

    // A new review can start once the last one is closed; cancelling changes nothing.
    s.f.advance(60_000);
    const next = await s.f.iam.api.teams.startReview(s.owner, {
      tenantId: s.tenantId,
      teamId: s.team.id,
    });
    const cancelled = await s.f.iam.api.teams.cancelReview(s.owner, {
      tenantId: s.tenantId,
      reviewId: next.id,
    });
    expect(cancelled.status).toBe('cancelled');
    await expect(
      s.f.iam.api.teams.cancelReview(s.bobSession, { tenantId: s.tenantId, reviewId: next.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const listed = await s.f.iam.api.teams.listReviews(s.bobSession, {
      tenantId: s.tenantId,
      teamId: s.team.id,
    });
    expect(listed.map((item) => item.status)).toEqual(['cancelled', 'completed']);
    expect(await s.members()).toEqual(['alice', 'bob', 'dave', 'erin']);
  });

  it('closes overdue reviews on schedule and removes birthright access with the membership', async () => {
    const s = await scenario();
    const wiki = await s.f.iam.api.groups.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Wiki editors',
    });
    const pkg = await s.f.iam.api.packages.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Platform tools',
      groupIds: [wiki.id],
      autoAssign: {
        include: [
          {
            StringEquals: { 'principal.kind': 'user' },
            ArrayContains: { 'identity.teams': [s.team.id] },
          },
        ],
      },
    });
    const holders = async () =>
      (
        await s.f.iam.api.packages.listAssignments(s.owner, {
          tenantId: s.tenantId,
          packageId: pkg.id,
          source: 'automatic',
        })
      ).length;
    expect(await holders()).toBe(5);
    await expect(
      s.f.iam.api.teams.startReview(s.owner, {
        tenantId: s.tenantId,
        teamId: s.team.id,
        dueAt: s.f.now() + 60_000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const review = await s.f.iam.api.teams.startReview(s.owner, {
      tenantId: s.tenantId,
      teamId: s.team.id,
      dueAt: s.f.now() + 2 * day,
      onUndecided: 'remove',
    });
    await s.f.iam.api.teams.decideReview(s.bobSession, {
      tenantId: s.tenantId,
      reviewId: review.id,
      decisions: [{ identityId: s.alice.id, decision: 'keep' }],
    });
    // Not due yet: nothing happens.
    expect(await s.f.iam.closeOverdueTeamReviews()).toMatchObject({ completed: 0 });
    s.f.advance(3 * day);
    expect(await s.f.iam.closeOverdueTeamReviews()).toEqual({
      completed: 1,
      removed: 3,
      failed: [],
    });
    // Undecided people (bob, carol, dave) left; the synced member stays; birthright access followed at once.
    expect(await s.members()).toEqual(['alice', 'erin']);
    expect(await holders()).toBe(2);
    const [closed] = await s.f.iam.api.teams.listReviews(s.owner, { tenantId: s.tenantId });
    expect(closed).toMatchObject({
      status: 'completed',
      completedBy: 'deployment-operator',
      outcome: { kept: 1, removed: 3, undecided: 3, gone: 0 },
    });
    // Deleting the team deletes its reviews (the package rule has to let go of it first).
    await s.f.iam.api.packages.update(s.owner, {
      tenantId: s.tenantId,
      packageId: pkg.id,
      autoAssign: null,
    });
    await s.f.iam.api.teams.delete(s.owner, { tenantId: s.tenantId, teamId: s.team.id });
    expect(await s.f.iam.api.teams.listReviews(s.owner, { tenantId: s.tenantId })).toEqual([]);
  });
});
