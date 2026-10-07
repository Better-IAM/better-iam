// Pure helpers behind the Guests pages (cloud/[org]/guests): labels, badge tones, list filters, what needs a sponsor's
// attention, and the cross-tenant access change the settings form sends. Type-only imports, so tests can load this
// file by relative path.
import type {
  CrossTenantPartner,
  GuestAccountStatus,
  GuestInvitationStatus,
  GuestInvitationView,
  GuestSettingsInput,
  GuestSettingsView,
  GuestView,
} from 'better-iam';
import type { Tone } from '@/components/ui';

const day = 86_400_000;

/** How far ahead the pages flag reviews and access ends: the window the server reminds sponsors in. */
export const attentionDays = 14;

export const accountStatuses: readonly GuestAccountStatus[] = [
  'active',
  'expired',
  'removed',
  'converted',
];
export const invitationStatuses: readonly GuestInvitationStatus[] = [
  'pending',
  'redeemed',
  'revoked',
  'expired',
];

export const accountStatusLabels: Record<GuestAccountStatus, string> = {
  active: 'active',
  expired: 'access ended',
  removed: 'removed',
  converted: 'now a member',
};

export const invitationStatusLabels: Record<GuestInvitationStatus, string> = {
  pending: 'pending',
  redeemed: 'accepted',
  revoked: 'revoked',
  expired: 'lapsed',
};

export function accountStatusTone(status: GuestAccountStatus): Tone {
  return status === 'active'
    ? 'success'
    : status === 'expired'
      ? 'warning'
      : status === 'removed'
        ? 'danger'
        : 'neutral';
}

export function invitationStatusTone(status: GuestInvitationStatus): Tone {
  return status === 'pending'
    ? 'warning'
    : status === 'redeemed'
      ? 'success'
      : status === 'revoked'
        ? 'danger'
        : 'neutral';
}

/** Why an invitation was revoked, when no administrator did it. */
export const revokedReasonLabels: Record<
  NonNullable<GuestInvitationView['revokedReason']>,
  string
> = {
  'inviter-inactive': 'the inviter left or was disabled',
  'sponsor-inactive': 'the sponsor left or was disabled',
};

/** "in 3 days", "within a day", "2 days ago": how far `at` is from `now`, in whole days. */
export function relativeDays(at: number, now: number): string {
  const ahead = at >= now;
  const days = Math.floor(Math.abs(at - now) / day);
  if (days === 0) return ahead ? 'within a day' : 'less than a day ago';
  const count = `${days} day${days === 1 ? '' : 's'}`;
  return ahead ? `in ${count}` : `${count} ago`;
}

export interface GuestAttention {
  label: string;
  tone: Tone;
}

type AttentionFields = Pick<
  GuestView,
  'accountStatus' | 'sponsorMissing' | 'reviewDueAt' | 'expiresAt'
>;

/**
 * What needs someone's attention about an active guest: a missing sponsor, access that ends within `withinDays`, and a
 * review that is overdue or due within `withinDays`. A review due when the access ends anyway is only the access end.
 */
export function guestAttention(
  guest: AttentionFields,
  now: number,
  withinDays = attentionDays,
): GuestAttention[] {
  if (guest.accountStatus !== 'active') return [];
  const horizon = now + withinDays * day;
  const items: GuestAttention[] = [];
  if (guest.sponsorMissing) items.push({ label: 'needs a sponsor', tone: 'danger' });
  if (guest.expiresAt !== undefined && guest.expiresAt <= horizon)
    items.push({ label: 'access ends soon', tone: 'warning' });
  const ownReview = guest.expiresAt === undefined || guest.reviewDueAt < guest.expiresAt;
  if (ownReview && guest.reviewDueAt <= now)
    items.push({ label: 'review overdue', tone: 'danger' });
  else if (ownReview && guest.reviewDueAt <= horizon)
    items.push({ label: 'review due', tone: 'warning' });
  return items;
}

export interface GuestSummary {
  active: number;
  /** Active guests whose sponsor left. */
  needSponsor: number;
  /** Active guests with a review overdue or due within the window (before their access ends). */
  reviewDue: number;
  /** Active guests whose access ends within the window. */
  endingSoon: number;
  /** Guests whose access ended and who were not removed or converted. */
  ended: number;
}

/** The counts on the Guests page tiles. */
export function guestSummary(
  guests: readonly AttentionFields[],
  now: number,
  withinDays = attentionDays,
): GuestSummary {
  const summary: GuestSummary = {
    active: 0,
    needSponsor: 0,
    reviewDue: 0,
    endingSoon: 0,
    ended: 0,
  };
  for (const guest of guests) {
    if (guest.accountStatus === 'expired') summary.ended++;
    if (guest.accountStatus !== 'active') continue;
    summary.active++;
    const labels = guestAttention(guest, now, withinDays).map((item) => item.label);
    if (labels.includes('needs a sponsor')) summary.needSponsor++;
    if (labels.includes('access ends soon')) summary.endingSoon++;
    if (labels.includes('review due') || labels.includes('review overdue')) summary.reviewDue++;
  }
  return summary;
}

// ---------------------------------------------------------------------------------------------------------------
// List filters (query string ⇄ guests.list input)

export interface GuestFilters {
  sponsorId?: string;
  status?: GuestAccountStatus;
  expiringWithinDays?: number;
}

export interface GuestFilterParams {
  sponsor?: string;
  status?: string;
  ending?: string;
  page?: string;
}

/** The "access ends within" choices, in days. */
export const endingOptions: readonly number[] = [7, 14, 30, 90];

/** The guest list filters in a query string; unknown values are ignored rather than refused. */
export function guestFilters(params: GuestFilterParams): { filters: GuestFilters; page: number } {
  const sponsor = params.sponsor?.trim();
  const ending = Number.parseInt(params.ending ?? '', 10);
  const filters: GuestFilters = {
    ...(sponsor ? { sponsorId: sponsor } : {}),
    ...(params.status && (accountStatuses as readonly string[]).includes(params.status)
      ? { status: params.status as GuestAccountStatus }
      : {}),
    ...(endingOptions.includes(ending) ? { expiringWithinDays: ending } : {}),
  };
  const page = Math.max(1, Number.parseInt(params.page ?? '1', 10) || 1);
  return { filters, page };
}

/** The query string (with its `?`, or empty) for guest filters and a page. */
export function guestFilterQuery(filters: GuestFilters, page = 1): string {
  const search = new URLSearchParams();
  if (filters.sponsorId) search.set('sponsor', filters.sponsorId);
  if (filters.status) search.set('status', filters.status);
  if (filters.expiringWithinDays !== undefined)
    search.set('ending', String(filters.expiringWithinDays));
  if (page > 1) search.set('page', String(page));
  const text = search.toString();
  return text ? `?${text}` : '';
}

/** The invitation list's status filter; anything else lists every invitation. */
export function invitationFilter(status: string | undefined): GuestInvitationStatus | undefined {
  return status && (invitationStatuses as readonly string[]).includes(status)
    ? (status as GuestInvitationStatus)
    : undefined;
}

/** Splits advisory permission checks into batches `authorizeMany` accepts (at most 50 each). */
export function batches<T>(items: readonly T[], size = 50): T[][] {
  const result: T[][] = [];
  for (let start = 0; start < items.length; start += size)
    result.push(items.slice(start, start + size));
  return result;
}

// ---------------------------------------------------------------------------------------------------------------
// Cross-tenant access settings (guests.configure)

/** What the settings form holds while it is being edited: lists as typed, numbers as typed. */
export interface GuestSettingsDraft {
  allowGuests: boolean;
  /** Domains, one per line (or comma-separated). */
  allowedDomains: string;
  blockedDomains: string;
  /** Organization IDs admitted over the inbound defaults, one per line. */
  inboundAdmitted: string;
  /** Organization IDs whose people are never admitted. */
  inboundRefused: string;
  allowGuestInvitations: boolean;
  /** Host organization IDs this organization's people may join as guests over the outbound default. */
  outboundAdmitted: string;
  outboundRefused: string;
  accessDays: string;
  reviewEveryDays: string;
  /** The guest boundary as JSON; empty for none. */
  guestBoundary: string;
}

/** The `guests.configure` input without its tenant: only the settings that changed. */
export type GuestSettingsChange = Omit<GuestSettingsInput, 'tenantId'>;

const partnerIds = (partners: readonly CrossTenantPartner[], allow: boolean) =>
  partners.filter((partner) => partner.allow === allow).map((partner) => partner.tenantId);

export function settingsDraft(settings: GuestSettingsView): GuestSettingsDraft {
  return {
    allowGuests: settings.inbound.allowGuests,
    allowedDomains: settings.inbound.allowedDomains.join('\n'),
    blockedDomains: settings.inbound.blockedDomains.join('\n'),
    inboundAdmitted: partnerIds(settings.inbound.partners, true).join('\n'),
    inboundRefused: partnerIds(settings.inbound.partners, false).join('\n'),
    allowGuestInvitations: settings.outbound.allowGuestInvitations,
    outboundAdmitted: partnerIds(settings.outbound.partners, true).join('\n'),
    outboundRefused: partnerIds(settings.outbound.partners, false).join('\n'),
    accessDays: String(settings.accessDays),
    reviewEveryDays: String(settings.reviewEveryDays),
    guestBoundary: settings.guestBoundary ? JSON.stringify(settings.guestBoundary, null, 2) : '',
  };
}

/** Entries typed one per line, or separated by commas or spaces, without blanks or repeats, in order. */
export function entries(value: string): string[] {
  return [
    ...new Set(
      value
        .split(/[\s,]+/)
        .map((item) => item.trim())
        .filter(Boolean),
    ),
  ];
}

const sorted = (items: readonly string[]) => [...items].sort();
const sameList = (a: readonly string[], b: readonly string[]) =>
  JSON.stringify(sorted(a)) === JSON.stringify(sorted(b));

/** Domains as the server keeps them: lowercase, without a leading `@` or a trailing dot, each once, sorted. */
function domains(value: string): string[] {
  return sorted([
    ...new Set(
      entries(value).map((item) => item.replace(/^@/, '').replace(/\.$/, '').toLowerCase()),
    ),
  ]);
}

/** One partner list from the admitted and refused organization IDs; an ID on both is a mistake. */
function partnerList(admitted: string, refused: string, what: string): CrossTenantPartner[] {
  const allow = entries(admitted);
  const deny = entries(refused);
  const both = allow.find((tenantId) => deny.includes(tenantId));
  if (both) throw new Error(`${what}: ${both} is both admitted and refused`);
  return [
    ...allow.map((tenantId) => ({ tenantId, allow: true })),
    ...deny.map((tenantId) => ({ tenantId, allow: false })),
  ].sort((a, b) => (a.tenantId < b.tenantId ? -1 : a.tenantId > b.tenantId ? 1 : 0));
}

const samePartners = (a: readonly CrossTenantPartner[], b: readonly CrossTenantPartner[]) => {
  const key = (list: readonly CrossTenantPartner[]) =>
    JSON.stringify(sorted(list.map((partner) => `${partner.tenantId}:${partner.allow}`)));
  return key(a) === key(b);
};

function wholeDays(value: string, label: string): number {
  const text = value.trim();
  if (!/^\d+$/.test(text)) throw new Error(`${label} must be a whole number of days`);
  return Number(text);
}

/**
 * The `guests.configure` change for a draft: only what differs from the settings in force, so an untouched form
 * changes nothing (and the audit event names exactly what changed). An emptied boundary removes it (null). Throws on
 * input the form can tell is wrong: a number that is not whole days, invalid JSON, an organization both admitted and
 * refused. Everything else (ranges, domain syntax, unknown organizations) is checked by the server.
 */
export function settingsChange(
  settings: GuestSettingsView,
  draft: GuestSettingsDraft,
): GuestSettingsChange {
  const change: GuestSettingsChange = {};
  const inbound: NonNullable<GuestSettingsChange['inbound']> = {};
  if (draft.allowGuests !== settings.inbound.allowGuests) inbound.allowGuests = draft.allowGuests;
  const allowed = domains(draft.allowedDomains);
  if (!sameList(allowed, settings.inbound.allowedDomains)) inbound.allowedDomains = allowed;
  const blocked = domains(draft.blockedDomains);
  if (!sameList(blocked, settings.inbound.blockedDomains)) inbound.blockedDomains = blocked;
  const inboundPartners = partnerList(draft.inboundAdmitted, draft.inboundRefused, 'Guests from');
  if (!samePartners(inboundPartners, settings.inbound.partners)) inbound.partners = inboundPartners;
  if (Object.keys(inbound).length) change.inbound = inbound;

  const outbound: NonNullable<GuestSettingsChange['outbound']> = {};
  if (draft.allowGuestInvitations !== settings.outbound.allowGuestInvitations)
    outbound.allowGuestInvitations = draft.allowGuestInvitations;
  const outboundPartners = partnerList(
    draft.outboundAdmitted,
    draft.outboundRefused,
    'Your people in',
  );
  if (!samePartners(outboundPartners, settings.outbound.partners))
    outbound.partners = outboundPartners;
  if (Object.keys(outbound).length) change.outbound = outbound;

  const accessDays = wholeDays(draft.accessDays, 'Guest access');
  if (accessDays !== settings.accessDays) change.accessDays = accessDays;
  const reviewEveryDays = wholeDays(draft.reviewEveryDays, 'Sponsor reviews');
  if (reviewEveryDays !== settings.reviewEveryDays) change.reviewEveryDays = reviewEveryDays;

  const boundaryText = draft.guestBoundary.trim();
  if (!boundaryText) {
    if (settings.guestBoundary) change.guestBoundary = null;
  } else {
    let boundary: unknown;
    try {
      boundary = JSON.parse(boundaryText);
    } catch {
      throw new Error('The guest boundary must be valid JSON');
    }
    if (typeof boundary !== 'object' || boundary === null || Array.isArray(boundary))
      throw new Error('The guest boundary must be a policy document (a JSON object)');
    if (JSON.stringify(boundary) !== JSON.stringify(settings.guestBoundary ?? null))
      change.guestBoundary = boundary as NonNullable<GuestSettingsChange['guestBoundary']>;
  }
  return change;
}

/** Whether a change would change anything. */
export function changesSomething(change: GuestSettingsChange): boolean {
  return Object.keys(change).length > 0;
}
