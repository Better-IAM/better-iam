import { afterEach, describe, expect, it } from 'vitest';
import type { GuestSettingsView, GuestView } from '@better-iam/server';
import {
  accountStatusTone,
  batches,
  changesSomething,
  entries,
  guestAttention,
  guestFilterQuery,
  guestFilters,
  guestSummary,
  invitationFilter,
  invitationStatusTone,
  relativeDays,
  settingsChange,
  settingsDraft,
} from '../apps/console/src/lib/guests.js';
import { otherOrganization } from './support/guests.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const hour = 3_600_000;
const day = 24 * hour;
const now = Date.UTC(2026, 8, 24, 12);

const defaults: GuestSettingsView = {
  tenantId: 'tenant-a',
  configured: false,
  inbound: { allowGuests: true, allowedDomains: [], blockedDomains: [], partners: [] },
  outbound: { allowGuestInvitations: true, partners: [] },
  accessDays: 90,
  reviewEveryDays: 90,
};

const boundary = {
  version: 1 as const,
  statements: [
    { effect: 'allow' as const, actions: ['documents:read'], resources: ['document/*'] },
  ],
};

type Timing = Pick<GuestView, 'accountStatus' | 'sponsorMissing' | 'reviewDueAt' | 'expiresAt'>;
const timing = (change: Partial<Timing>): Timing => ({
  accountStatus: 'active',
  sponsorMissing: false,
  reviewDueAt: now + 60 * day,
  expiresAt: now + 60 * day,
  ...change,
});

describe('console guests helpers', () => {
  it('labels statuses and distances in days', () => {
    expect(accountStatusTone('active')).toBe('success');
    expect(accountStatusTone('expired')).toBe('warning');
    expect(accountStatusTone('removed')).toBe('danger');
    expect(accountStatusTone('converted')).toBe('neutral');
    expect(invitationStatusTone('pending')).toBe('warning');
    expect(invitationStatusTone('redeemed')).toBe('success');
    expect(invitationStatusTone('revoked')).toBe('danger');
    expect(invitationStatusTone('expired')).toBe('neutral');
    expect(relativeDays(now + 3.5 * day, now)).toBe('in 3 days');
    expect(relativeDays(now + day, now)).toBe('in 1 day');
    expect(relativeDays(now + hour, now)).toBe('within a day');
    expect(relativeDays(now - 2 * day, now)).toBe('2 days ago');
    expect(relativeDays(now - hour, now)).toBe('less than a day ago');
  });

  it('flags what needs attention and counts it', () => {
    const orphan = timing({
      sponsorMissing: true,
      expiresAt: now + 10 * day,
      reviewDueAt: now + 10 * day,
    });
    // A review due when the access ends anyway is only the access end.
    expect(guestAttention(orphan, now).map((item) => item.label)).toEqual([
      'needs a sponsor',
      'access ends soon',
    ]);
    const reviewSoon = timing({ reviewDueAt: now + 5 * day });
    expect(guestAttention(reviewSoon, now)).toEqual([{ label: 'review due', tone: 'warning' }]);
    const overdue = timing({ reviewDueAt: now - day });
    expect(guestAttention(overdue, now)).toEqual([{ label: 'review overdue', tone: 'danger' }]);
    expect(guestAttention(timing({}), now)).toEqual([]);
    // Only active guests need anything.
    const ended = timing({
      accountStatus: 'expired',
      expiresAt: now - day,
      reviewDueAt: now - day,
    });
    expect(guestAttention(ended, now)).toEqual([]);
    expect(guestAttention(reviewSoon, now, 3)).toEqual([]);
    expect(guestSummary([orphan, reviewSoon, overdue, timing({}), ended], now)).toEqual({
      active: 4,
      needSponsor: 1,
      reviewDue: 2,
      endingSoon: 1,
      ended: 1,
    });
  });

  it('reads and writes the list filters', () => {
    const parsed = guestFilters({ sponsor: ' s1 ', status: 'expired', ending: '30', page: '2' });
    expect(parsed).toEqual({
      filters: { sponsorId: 's1', status: 'expired', expiringWithinDays: 30 },
      page: 2,
    });
    expect(guestFilterQuery(parsed.filters, parsed.page)).toBe(
      '?sponsor=s1&status=expired&ending=30&page=2',
    );
    // Unknown values are ignored rather than refused.
    expect(guestFilters({ status: 'lapsed', ending: '5', page: 'x' })).toEqual({
      filters: {},
      page: 1,
    });
    expect(guestFilterQuery({})).toBe('');
    expect(invitationFilter('pending')).toBe('pending');
    expect(invitationFilter('accepted')).toBeUndefined();
    expect(invitationFilter(undefined)).toBeUndefined();
    const checks = Array.from({ length: 120 }, (_, index) => index);
    expect(batches(checks).map((batch) => batch.length)).toEqual([50, 50, 20]);
    expect(batches([])).toEqual([]);
    expect(entries(' a.example,\nb.example  a.example\n\n')).toEqual(['a.example', 'b.example']);
  });

  it('sends only the settings that changed', () => {
    const untouched = settingsChange(defaults, settingsDraft(defaults));
    expect(untouched).toEqual({});
    expect(changesSomething(untouched)).toBe(false);
    const change = settingsChange(defaults, {
      ...settingsDraft(defaults),
      allowGuests: false,
      allowedDomains: 'Partner.Example.\n@agency.example, partner.example',
      inboundRefused: 'tenant-b',
      accessDays: ' 30 ',
      guestBoundary: JSON.stringify(boundary),
    });
    expect(change).toEqual({
      inbound: {
        allowGuests: false,
        allowedDomains: ['agency.example', 'partner.example'],
        partners: [{ tenantId: 'tenant-b', allow: false }],
      },
      accessDays: 30,
      guestBoundary: boundary,
    });
    expect(changesSomething(change)).toBe(true);

    const configured: GuestSettingsView = {
      ...defaults,
      configured: true,
      inbound: {
        ...defaults.inbound,
        partners: [
          { tenantId: 'tenant-b', allow: true },
          { tenantId: 'tenant-c', allow: false },
        ],
      },
      outbound: { allowGuestInvitations: false, partners: [{ tenantId: 'tenant-d', allow: true }] },
      guestBoundary: boundary,
    };
    const draft = settingsDraft(configured);
    expect(draft).toMatchObject({
      inboundAdmitted: 'tenant-b',
      inboundRefused: 'tenant-c',
      allowGuestInvitations: false,
      outboundAdmitted: 'tenant-d',
    });
    expect(settingsChange(configured, draft)).toEqual({});
    // The same partners typed in another order change nothing; an emptied boundary removes it.
    expect(
      settingsChange(configured, {
        ...draft,
        inboundAdmitted: '\ntenant-b\n',
        guestBoundary: '  ',
      }),
    ).toEqual({ guestBoundary: null });
    expect(
      settingsChange(configured, { ...draft, outboundAdmitted: '', outboundRefused: 'tenant-d' }),
    ).toEqual({ outbound: { partners: [{ tenantId: 'tenant-d', allow: false }] } });
  });

  it('refuses settings the form can tell are wrong', () => {
    const draft = settingsDraft(defaults);
    expect(() =>
      settingsChange(defaults, {
        ...draft,
        inboundAdmitted: 'tenant-b',
        inboundRefused: 'tenant-b',
      }),
    ).toThrow('tenant-b is both admitted and refused');
    expect(() => settingsChange(defaults, { ...draft, accessDays: '12.5' })).toThrow(
      'whole number of days',
    );
    expect(() => settingsChange(defaults, { ...draft, reviewEveryDays: '' })).toThrow(
      'whole number of days',
    );
    expect(() => settingsChange(defaults, { ...draft, guestBoundary: '{' })).toThrow('valid JSON');
    expect(() => settingsChange(defaults, { ...draft, guestBoundary: '[]' })).toThrow(
      'policy document',
    );
  });

  it('sends settings the guests API accepts', async () => {
    const f = await organizationFixture();
    const partner = await otherOrganization(f, 'Partner', 'partner');
    const guests = f.iam.api.guests;
    const owner = await f.ownerSignIn();
    const current = await guests.getSettings(owner, { tenantId: f.tenantId });
    expect(current.configured).toBe(false);
    const saved = await guests.configure(owner, {
      tenantId: f.tenantId,
      ...settingsChange(current, {
        ...settingsDraft(current),
        blockedDomains: 'Competitor.Example',
        inboundAdmitted: partner.tenantId,
        outboundRefused: partner.tenantId,
        reviewEveryDays: '30',
        guestBoundary: JSON.stringify(boundary),
      }),
    });
    expect(saved).toMatchObject({
      configured: true,
      inbound: {
        allowGuests: true,
        blockedDomains: ['competitor.example'],
        partners: [{ tenantId: partner.tenantId, allow: true }],
      },
      outbound: { partners: [{ tenantId: partner.tenantId, allow: false }] },
      reviewEveryDays: 30,
      guestBoundary: boundary,
    });
    // What the server stored reads back as an untouched form.
    expect(settingsChange(saved, settingsDraft(saved))).toEqual({});
    const cleared = await guests.configure(owner, {
      tenantId: f.tenantId,
      ...settingsChange(saved, { ...settingsDraft(saved), guestBoundary: '' }),
    });
    expect(cleared.guestBoundary).toBeUndefined();
    expect(cleared.reviewEveryDays).toBe(30);
  });
});
