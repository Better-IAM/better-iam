import { afterEach, describe, expect, it } from 'vitest';
import { quotaWindow } from '@better-iam/server';
import { closeFixtures, organizationFixture, type OrganizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const SECOND = 1000;
const HOUR = 3_600_000;
const DAY = 24 * HOUR;

async function auditActions(f: OrganizationFixture) {
  return (await f.database.find<{ action: string; outcome: string }>('audit', {}))
    .filter((event) => event.action.startsWith('quota:'))
    .map((event) => `${event.action}:${event.outcome}`);
}

describe('API usage plans and quotas', () => {
  it('counts use against period limits, refuses past them with the time to retry, and starts over', async () => {
    const f = await organizationFixture();
    const { quotas } = f.iam.api;
    await quotas.createPlan(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'free',
      meter: 'requests',
      limits: [
        { period: 'day', limit: 3 },
        { period: 'month', limit: 100 },
      ],
      alertThresholds: [50, 100],
    });
    const alice = await f.member('alice');
    await quotas.assign(f.ownerCredential, {
      tenantId: f.tenantId,
      plan: 'free',
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const token = { token: (await f.signIn('alice')).token };
    const consume = () =>
      f.iam.quotas.consume({ ...token, tenantId: f.tenantId, meter: 'requests' });
    for (let call = 1; call <= 3; call++) {
      const decision = await consume();
      expect(decision).toMatchObject({ allowed: true, plan: 'free', via: 'identity' });
      expect(decision.limits[0]).toMatchObject({ period: 'day', used: call, remaining: 3 - call });
    }
    const refused = await consume();
    expect(refused).toMatchObject({ allowed: false, reason: 'day' });
    const midnight = quotaWindow('day', f.now(), 'UTC').end;
    expect(refused.retryAfterMs).toBe(midnight - f.now());
    // A refusal counts nothing.
    expect(refused.limits[1]).toMatchObject({ period: 'month', used: 3 });
    await expect(
      f.iam.quotas.enforce({ ...token, tenantId: f.tenantId, meter: 'requests' }),
    ).rejects.toMatchObject({ code: 'QUOTA_EXCEEDED', status: 429, retryAfterMs: midnight - f.now() });
    const status = await quotas.status(token, { tenantId: f.tenantId, meter: 'requests' });
    expect(status.limits[0]).toMatchObject({ used: 3, remaining: 0 });
    // Crossing 50% and 100% of the day's limit, and the first refusal, are each recorded once.
    expect(await auditActions(f)).toEqual(
      expect.arrayContaining(['quota:threshold:allow', 'quota:exceeded:deny']),
    );
    expect((await auditActions(f)).filter((entry) => entry === 'quota:exceeded:deny')).toHaveLength(1);

    f.advance(midnight - f.now() + SECOND);
    const fresh = { token: (await f.signIn('alice')).token };
    expect(
      (await f.iam.quotas.consume({ ...fresh, tenantId: f.tenantId, meter: 'requests' })).allowed,
    ).toBe(true);
    // Meters without a plan are unlimited.
    expect(
      await f.iam.quotas.consume({ ...fresh, tenantId: f.tenantId, meter: 'exports' }),
    ).toMatchObject({ allowed: true, plan: null });
  });

  it('throttles bursts with a token bucket shared by every instance', async () => {
    const f = await organizationFixture();
    await f.iam.api.quotas.createPlan(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'steady',
      meter: 'requests',
      throttle: { ratePerSecond: 1, burst: 2 },
      default: true,
    });
    const request = { ...f.ownerCredential, tenantId: f.tenantId, meter: 'requests' };
    expect((await f.iam.quotas.consume(request)).allowed).toBe(true);
    expect((await f.iam.quotas.consume(request)).allowed).toBe(true);
    const refused = await f.iam.quotas.consume(request);
    expect(refused).toMatchObject({ allowed: false, reason: 'throttle', via: 'default' });
    expect(refused.retryAfterMs).toBe(SECOND);
    f.advance(SECOND);
    expect((await f.iam.quotas.consume(request)).allowed).toBe(true);
    // Another server instance on the same database sees the same bucket.
    expect((await f.iam.quotas.consume(request)).allowed).toBe(false);
    // A cost above the burst can never succeed: no retry time is given.
    const tooBig = await f.iam.quotas.consume({ ...request, cost: 5 });
    expect(tooBig).toMatchObject({ allowed: false, reason: 'throttle' });
    expect(tooBig.retryAfterMs).toBeUndefined();
  });

  it('applies the most specific plan: API key, identity, group, then the tenant default', async () => {
    const f = await organizationFixture();
    const { quotas } = f.iam.api;
    const plan = (name: string, limit: number, extra: { default?: boolean; priority?: number } = {}) =>
      quotas.createPlan(f.ownerCredential, {
        tenantId: f.tenantId,
        name,
        meter: 'requests',
        limits: [{ period: 'day', limit }],
        ...extra,
      });
    await plan('basic', 10, { default: true });
    await plan('team', 100);
    await plan('vip', 1000, { priority: 5 });
    await plan('ci', 5000);
    await expect(plan('other-default', 1, { default: true })).rejects.toMatchObject({ code: 'CONFLICT' });
    const group = await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'Engineers' });
    const vips = await f.iam.api.groups.create(f.ownerCredential, { tenantId: f.tenantId, name: 'VIPs' });
    const alice = await f.member('alice');
    await f.member('bob');
    for (const groupId of [group.id, vips.id])
      await f.iam.api.groups.addMember(f.ownerCredential, {
        tenantId: f.tenantId,
        groupId,
        identityId: alice.id,
      });
    await quotas.assign(f.ownerCredential, { tenantId: f.tenantId, plan: 'team', subjectType: 'group', subjectId: group.id });
    await quotas.assign(f.ownerCredential, { tenantId: f.tenantId, plan: 'vip', subjectType: 'group', subjectId: vips.id });
    const aliceToken = { token: (await f.signIn('alice')).token };
    const bobToken = { token: (await f.signIn('bob')).token };
    const planOf = async (credential: { token: string }) =>
      (await quotas.status(credential, { tenantId: f.tenantId, meter: 'requests' })).plan;
    expect(await planOf(bobToken)).toBe('basic');
    // Of two group plans, the higher priority applies.
    expect(await planOf(aliceToken)).toBe('vip');
    await quotas.assign(f.ownerCredential, {
      tenantId: f.tenantId,
      plan: 'team',
      subjectType: 'identity',
      subjectId: alice.id,
    });
    expect(await planOf(aliceToken)).toBe('team');

    const bot = await f.iam.api.serviceAccounts.create(f.ownerCredential, { tenantId: f.tenantId, name: 'ci-bot' });
    const key = await f.iam.api.credentials.create(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bot.id,
      name: 'deploy',
    });
    await quotas.assign(f.ownerCredential, {
      tenantId: f.tenantId,
      plan: 'ci',
      subjectType: 'apiKey',
      subjectId: key.credentialId,
    });
    expect(await planOf({ token: key.token })).toBe('ci');
    expect(
      (await f.iam.quotas.consumeFor({ tenantId: f.tenantId, identityId: bot.id, apiKeyId: key.credentialId, meter: 'requests' }))
        .plan,
    ).toBe('ci');
    const assignments = await quotas.listAssignments(f.ownerCredential, { tenantId: f.tenantId });
    expect(assignments.map((entry) => `${entry.plan}:${entry.subjectType}:${entry.subjectName}`).sort()).toEqual([
      'ci:apiKey:deploy',
      'team:group:Engineers',
      'team:identity:alice',
      'vip:group:VIPs',
    ]);
    await quotas.unassign(f.ownerCredential, {
      tenantId: f.tenantId,
      meter: 'requests',
      subjectType: 'identity',
      subjectId: alice.id,
    });
    expect(await planOf(aliceToken)).toBe('vip');
  });

  it('shares tenant-scoped counters, reports usage, resets, and cleans up with the plan', async () => {
    const f = await organizationFixture();
    const { quotas } = f.iam.api;
    await quotas.createPlan(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'shared',
      meter: 'exports',
      scope: 'tenant',
      default: true,
      limits: [{ period: 'hour', limit: 3 }],
    });
    await f.member('alice');
    await f.member('bob');
    const alice = { token: (await f.signIn('alice')).token };
    const bob = { token: (await f.signIn('bob')).token };
    await quotas.consume(alice, { tenantId: f.tenantId, meter: 'exports', cost: 2 });
    expect(await quotas.consume(bob, { tenantId: f.tenantId, meter: 'exports', cost: 2 })).toMatchObject({
      allowed: false,
      reason: 'hour',
    });
    expect((await quotas.consume(bob, { tenantId: f.tenantId, meter: 'exports' })).allowed).toBe(true);
    const usage = await quotas.usage(f.ownerCredential, { tenantId: f.tenantId, plan: 'shared' });
    expect(usage).toEqual([
      expect.objectContaining({
        subject: 'tenant',
        limits: [expect.objectContaining({ period: 'hour', used: 3, remaining: 0 })],
      }),
    ]);
    expect(await quotas.reset(f.ownerCredential, { tenantId: f.tenantId, plan: 'shared' })).toEqual({ reset: 1 });
    expect((await quotas.consume(bob, { tenantId: f.tenantId, meter: 'exports', cost: 3 })).allowed).toBe(true);
    expect(await quotas.deletePlan(f.ownerCredential, { tenantId: f.tenantId, name: 'shared' })).toMatchObject({
      deleted: true,
    });
    expect(await f.database.find('quotaCounters', { tenantId: f.tenantId })).toHaveLength(0);
    expect(await auditActions(f)).toEqual(
      expect.arrayContaining(['quota:plan-create:allow', 'quota:reset:allow', 'quota:plan-delete:allow']),
    );
  });

  it('validates plans, refuses other tenants, and serves callers over HTTP', async () => {
    const f = await organizationFixture();
    const { quotas } = f.iam.api;
    await expect(
      quotas.createPlan(f.ownerCredential, { tenantId: f.tenantId, name: 'empty', meter: 'requests' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    for (const limits of [[{ period: 'year', limit: 1 }], [{ period: 'day', limit: 0 }], [{ period: 'day', limit: 1 }, { period: 'day', limit: 2 }]])
      await expect(
        quotas.createPlan(f.ownerCredential, {
          tenantId: f.tenantId,
          name: 'bad',
          meter: 'requests',
          limits: limits as never,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      quotas.createPlan(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'bad',
        meter: 'Requests!',
        limits: [{ period: 'day', limit: 1 }],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await quotas.createPlan(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'free',
      meter: 'requests',
      default: true,
      limits: [{ period: 'minute', limit: 1 }],
    });
    // A session of another tenant cannot count here.
    await expect(
      f.iam.quotas.consume({ ...f.rootCredential, tenantId: f.tenantId, meter: 'requests' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const call = () =>
      f.iam.handler(
        new Request('http://localhost:3000/api/iam/quotas/consume', {
          method: 'POST',
          headers: {
            authorization: `Bearer ${f.ownerCredential.token}`,
            'content-type': 'application/json',
            'x-better-iam': '1',
          },
          body: JSON.stringify({ tenantId: f.tenantId, meter: 'requests' }),
        }),
      );
    const first = await call();
    expect(((await first.json()) as { data: { allowed: boolean } }).data.allowed).toBe(true);
    const second = await call();
    expect(((await second.json()) as { data: { allowed: boolean; reason: string } }).data).toMatchObject({
      allowed: false,
      reason: 'minute',
    });
  });

  it('starts day, week and month windows at local midnight in the plan’s time zone', () => {
    // 2026-03-08 is the day New York moves to daylight saving time.
    const at = Date.parse('2026-03-08T15:00:00Z');
    const day = quotaWindow('day', at, 'America/New_York');
    expect(new Date(day.start).toISOString()).toBe('2026-03-08T05:00:00.000Z');
    expect(new Date(day.end).toISOString()).toBe('2026-03-09T04:00:00.000Z');
    const week = quotaWindow('week', at, 'America/New_York');
    expect(new Date(week.start).toISOString()).toBe('2026-03-02T05:00:00.000Z');
    const month = quotaWindow('month', at, 'Europe/Berlin');
    expect(new Date(month.start).toISOString()).toBe('2026-02-28T23:00:00.000Z');
    expect(new Date(month.end).toISOString()).toBe('2026-03-31T22:00:00.000Z');
    expect(quotaWindow('hour', at, 'UTC').end - quotaWindow('hour', at, 'UTC').start).toBe(HOUR);
    expect(quotaWindow('day', at, 'UTC').end - quotaWindow('day', at, 'UTC').start).toBe(DAY);
  });
});
