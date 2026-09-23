import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const doc = { type: 'document', id: 'd1' };

describe('certification review recommendations', () => {
  it('suggests keep or revoke from account status, sign-ins, and recorded usage', async () => {
    const f = await organizationFixture({ accessUsage: true });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const [alice, bob, carol, dave] = [
      await f.member('alice'),
      await f.member('bob'),
      await f.member('carol'),
      await f.member('dave'),
    ];
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
    const team = await f.iam.api.groups.create(owner, { tenantId, name: 'Team' });
    const bind = (roleId: string, subjectType: 'identity' | 'group', subjectId: string) =>
      f.iam.api.bindings.create(owner, { tenantId, roleId, subjectType, subjectId });
    await bind(reader.id, 'identity', alice.id);
    await bind(writer.id, 'identity', bob.id);
    await bind(reader.id, 'identity', carol.id);
    await bind(reader.id, 'identity', dave.id);
    await bind(reader.id, 'group', team.id);
    await f.iam.api.identities.setStatus(owner, {
      tenantId,
      identityId: carol.id,
      status: 'disabled',
    });
    const use = async (name: string, action: string) =>
      f.iam.authorize({ token: (await f.signIn(name)).token, tenantId, action, resource: doc });
    await use('alice', 'documents:read');
    await f.signIn('bob');
    // Dave never signs in; support viewing the product as Dave is not Dave signing in.
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    await f.iam.api.identities.impersonate(await f.ownerSignIn(), {
      tenantId,
      identityId: dave.id,
      reason: 'Ticket 1',
    });

    const campaign = await f.iam.api.certifications.create(owner, { tenantId, name: 'Q3' });
    const itemsOf = async () =>
      (
        await f.iam.api.certifications.get(await f.ownerSignIn(), {
          tenantId,
          campaignId: campaign.id,
        })
      ).items;
    const items = await itemsOf();
    const itemFor = (subjectId: string) => items.find((item) => item.subjectId === subjectId)!.id;
    const byItem = (result: { recommendations: { itemId: string }[] }) =>
      new Map(result.recommendations.map((entry) => [entry.itemId, entry]));

    // Usage only just started: sign-ins are the evidence.
    const early = await f.iam.api.roleMining.reviewRecommendations(owner, {
      tenantId,
      campaignId: campaign.id,
      unusedDays: 30,
    });
    expect(early.usageComplete).toBe(false);
    const first = byItem(early);
    expect(first.get(itemFor(alice.id))).toMatchObject({
      recommendation: 'keep',
      basis: 'sign-in',
    });
    expect(first.get(itemFor(bob.id))).toMatchObject({ recommendation: 'keep', basis: 'sign-in' });
    expect(first.get(itemFor(carol.id))).toMatchObject({
      recommendation: 'revoke',
      basis: 'status',
      reason: 'The account is disabled.',
    });
    expect(first.get(itemFor(dave.id))).toMatchObject({
      recommendation: 'revoke',
      basis: 'sign-in',
      reason: 'Has never signed in.',
    });
    expect(first.get(itemFor(team.id))).toMatchObject({ recommendation: 'none' });

    // A month later usage covers the window: Alice used her role again, Bob signed in but never wrote.
    f.advance(31 * 86_400_000);
    await use('alice', 'documents:read');
    await f.signIn('bob');
    const later = byItem(
      await f.iam.api.roleMining.reviewRecommendations(await f.ownerSignIn(), {
        tenantId,
        campaignId: campaign.id,
        unusedDays: 30,
      }),
    );
    expect(later.get(itemFor(alice.id))).toMatchObject({
      recommendation: 'keep',
      basis: 'usage',
      lastUsedAt: f.now(),
    });
    expect(later.get(itemFor(bob.id))).toMatchObject({
      recommendation: 'revoke',
      basis: 'usage',
      reason: "None of the role's actions were used in the last 30 days.",
    });

    await expect(
      f.iam.api.roleMining.reviewRecommendations(await f.ownerSignIn(), {
        tenantId,
        campaignId: 'missing',
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});
