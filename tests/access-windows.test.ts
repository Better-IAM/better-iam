import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const pad = (value: number) => String(value).padStart(2, '0');
/** `HH:MM` for a minute of day, wrapping around midnight. */
const clock = (minutes: number) => {
  const wrapped = ((minutes % 1440) + 1440) % 1440;
  return `${pad(Math.floor(wrapped / 60))}:${pad(wrapped % 60)}`;
};
const utcMinutes = (at: number) => new Date(at).getUTCHours() * 60 + new Date(at).getUTCMinutes();

describe('binding access windows', () => {
  it('grants only inside the window, in the named time zone, and validates the window', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const reader = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Reader',
      permissions: ['documents:read'],
    });
    const alice = await f.member('alice');
    const invalid = [
      { from: '09:00', to: '17:00', timeZone: 'Mars/Olympus' },
      { from: '9:00', to: '17:00', timeZone: 'UTC' },
      { from: '09:00', to: '09:00', timeZone: 'UTC' },
      { from: '09:00', to: '17:00', timeZone: 'UTC', days: [7] },
      { from: '09:00', to: '17:00', timeZone: 'UTC', days: [] },
    ];
    for (const window of invalid)
      await expect(
        f.iam.api.bindings.create(owner, {
          tenantId,
          roleId: reader.id,
          subjectType: 'identity',
          subjectId: alice.id,
          window,
        }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // One hour either side of "now" in UTC, possibly wrapping past midnight.
    const now = utcMinutes(f.now());
    const window = { from: clock(now - 60), to: clock(now + 60), timeZone: 'UTC' };
    const binding = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'identity',
      subjectId: alice.id,
      window,
    });
    expect(binding.window).toEqual(window);
    const asAlice = { token: (await f.signIn('alice')).token };
    const can = async () =>
      (
        await f.iam.authorize({
          ...asAlice,
          tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed;
    const inWindow = async () =>
      (await f.iam.api.identities.listBindings(owner, { tenantId, identityId: alice.id })).find(
        (item) => item.id === binding.id,
      )!.inWindow;
    const listed = async () =>
      (
        await f.iam.api.policies.whoCan(owner, {
          tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).identities.some((match) => match.identityId === alice.id);
    expect(await can()).toBe(true);
    expect(await inWindow()).toBe(true);
    expect(await listed()).toBe(true);
    f.advance(2 * 3_600_000);
    expect(await can()).toBe(false);
    expect(await inWindow()).toBe(false);
    expect(await listed()).toBe(false);
    // The window recurs daily.
    f.advance(22 * 3_600_000);
    expect(await can()).toBe(true);
    // Restricting the days: a window on another weekday does not apply today.
    // The day the window opened: past midnight UTC, an overnight window still belongs to the previous day.
    const today = new Date(f.now() - 3_600_000).getUTCDay();
    const admin = await f.ownerSignIn();
    await f.iam.api.bindings.update(admin, {
      tenantId,
      bindingId: binding.id,
      window: { ...window, days: [(today + 3) % 7] },
    });
    expect(await can()).toBe(false);
    await f.iam.api.bindings.update(admin, {
      tenantId,
      bindingId: binding.id,
      window: { ...window, days: [today] },
    });
    expect(await can()).toBe(true);
    // Another time zone shifts the window; New York is never exactly in step with UTC.
    await f.iam.api.bindings.update(admin, {
      tenantId,
      bindingId: binding.id,
      window: { from: clock(now - 60), to: clock(now + 60), timeZone: 'America/New_York' },
    });
    expect(await can()).toBe(false);
    // Clearing the window makes the binding apply at all times again.
    const cleared = await f.iam.api.bindings.update(admin, {
      tenantId,
      bindingId: binding.id,
      window: null,
    });
    expect(cleared.window).toBeUndefined();
    expect(await can()).toBe(true);
    // Configuration sync carries windows on group bindings.
    const group = await f.iam.api.groups.create(admin, { tenantId, name: 'Day shift' });
    await f.iam.api.config.apply(admin, {
      tenantId,
      config: {
        version: 1,
        bindings: [
          {
            group: 'Day shift',
            role: 'Reader',
            window: {
              from: '09:00',
              to: '17:00',
              timeZone: 'Europe/Berlin',
              days: [1, 2, 3, 4, 5],
            },
          },
        ],
      },
    });
    const exported = await f.iam.api.config.export(admin, { tenantId });
    expect(exported.bindings).toEqual([
      {
        group: 'Day shift',
        role: 'Reader',
        window: { from: '09:00', to: '17:00', timeZone: 'Europe/Berlin', days: [1, 2, 3, 4, 5] },
      },
    ]);
    expect(
      (await f.iam.api.bindings.list(admin, { tenantId, subjectId: group.id }))[0]!.window,
    ).toMatchObject({ timeZone: 'Europe/Berlin' });
    expect(
      (
        await f.iam.api.config.plan(admin, {
          tenantId,
          config: {
            version: 1,
            bindings: [{ group: 'Day shift', role: 'Reader' }],
          },
        })
      ).changes[0],
    ).toMatchObject({ action: 'update', fields: ['window'] });
  });
});
