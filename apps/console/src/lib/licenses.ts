// Pure helpers behind the Licenses pages (cloud/[org]/licenses) and the member page's Licenses card: labels, badge
// tones, usage figures, select options, and the fields of the license forms. Type-only imports, so tests can load this
// file by relative path.
import type {
  LicenseAssignmentView,
  LicensePoolView,
  LicenseProductStatus,
  LicenseProductView,
  LicenseSeatStatus,
  LicenseSeatView,
  LicenseSettingsView,
  LicenseSubjectType,
  LicenseUsage,
} from 'better-iam/server';
import type { Tone } from '@/components/ui';
import type { FieldOption, FieldSpec } from './form-body';

const DAY = 86_400_000;

/** The range `licenses.configure` accepts for `reclaimAfterDays`. */
export const reclaimDays = { min: 7, max: 365 } as const;
/** People `licenses.assignMany` takes at once. */
export const assignManyLimit = 100;
/** Feature keys one product may list. */
export const featureKeyLimit = 50;

export function seatStatusTone(status: LicenseSeatStatus): Tone {
  return status === 'active' ? 'success' : 'warning';
}

export function productStatusTone(status: LicenseProductStatus): Tone {
  return status === 'active' ? 'success' : 'neutral';
}

/** Who defines a product, as the organization sees it. */
export function scopeLabel(product: Pick<LicenseProductView, 'scope' | 'definedHere'>): string {
  if (product.scope === 'platform') return 'Platform';
  return product.definedHere ? 'This organization' : 'Enclosing organization';
}

/** A seat's status in words: `active`, or its place on the waiting list. */
export function seatLabel(seat: Pick<LicenseSeatView, 'status' | 'position'>): string {
  if (seat.status === 'active') return 'active';
  return seat.position !== undefined ? `waiting #${seat.position}` : 'waiting';
}

export function plural(count: number, noun: string): string {
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}

type UsageFigures = Pick<LicenseUsage, 'capacity' | 'active' | 'waiting'>;

/** The share of capacity active seats take, from 0 to 1; full when people claim a product that has no capacity. */
export function usageRatio(usage: UsageFigures): number {
  if (usage.capacity <= 0) return usage.active + usage.waiting > 0 ? 1 : 0;
  return Math.min(1, usage.active / usage.capacity);
}

/** The usage meter's tone: danger while people wait for a seat, warning from 90% of capacity, success below. */
export function usageTone(usage: UsageFigures): Tone {
  if (usage.waiting > 0) return 'danger';
  if (usage.capacity <= 0) return 'neutral';
  return usage.active >= usage.capacity * 0.9 ? 'warning' : 'success';
}

/** A product's figures besides the seats in use: free seats, the waiting list, live pools, assignments, reclaimable. */
export function usageSummary(usage: LicenseUsage): string {
  return [
    `${usage.available} available`,
    ...(usage.waiting > 0 ? [`${usage.waiting} waiting`] : []),
    plural(usage.pools, 'live pool'),
    plural(usage.assignments, 'assignment'),
    ...(usage.reclaimable > 0 ? [`${usage.reclaimable} reclaimable`] : []),
  ].join(' · ');
}

export interface LicenseTotals {
  /** Active products the organization uses. */
  products: number;
  capacity: number;
  active: number;
  waiting: number;
  available: number;
  reclaimable: number;
  reclaimableThroughGroups: number;
}

/** Seats summed over the active products (retired products hold none). */
export function usageTotals(products: readonly LicenseUsage[]): LicenseTotals {
  const totals: LicenseTotals = {
    products: 0,
    capacity: 0,
    active: 0,
    waiting: 0,
    available: 0,
    reclaimable: 0,
    reclaimableThroughGroups: 0,
  };
  for (const usage of products) {
    if (usage.status !== 'active') continue;
    totals.products++;
    totals.capacity += usage.capacity;
    totals.active += usage.active;
    totals.waiting += usage.waiting;
    totals.available += usage.available;
    totals.reclaimable += usage.reclaimable;
    totals.reclaimableThroughGroups += usage.reclaimableThroughGroups;
  }
  return totals;
}

export type PoolState = 'live' | 'scheduled' | 'ended';

/** Whether a pool gives seats now, will from its start, or has ended. */
export function poolState(
  pool: Pick<LicensePoolView, 'live' | 'startsAt'>,
  now: number,
): PoolState {
  if (pool.live) return 'live';
  return pool.startsAt !== undefined && pool.startsAt > now ? 'scheduled' : 'ended';
}

export function poolStateTone(state: PoolState): Tone {
  return state === 'live' ? 'success' : state === 'scheduled' ? 'accent' : 'neutral';
}

/**
 * Whether an active seat's holder has been inactive for `reclaimAfterDays`, as the last reclaim pass saw them (the pass
 * records each holder's latest sign-in or credential use on the seat). People assigned within the window are never
 * inactive yet.
 */
export function seatInactive(
  seat: Pick<LicenseSeatView, 'status' | 'assignedAt' | 'lastActivityAt'>,
  reclaimAfterDays: number | undefined,
  now: number,
): boolean {
  if (reclaimAfterDays === undefined || seat.status !== 'active') return false;
  const cutoff = now - reclaimAfterDays * DAY;
  return (
    seat.assignedAt <= cutoff && seat.lastActivityAt !== undefined && seat.lastActivityAt <= cutoff
  );
}

interface Named {
  id: string;
  name: string;
}

const byName = (a: Named, b: Named) => a.name.localeCompare(b.name) || a.id.localeCompare(b.id);

/** Where a new pool's seats go: this organization first, then its projects (deleted ones left out). */
export function poolTenantOptions(
  tenant: Named,
  children: readonly (Named & { status: string })[],
): FieldOption[] {
  return [
    { value: tenant.id, label: `${tenant.name} (this organization)` },
    ...children
      .filter((child) => child.status !== 'deleted' && child.id !== tenant.id)
      .sort(byName)
      .map((child) => ({ value: child.id, label: child.name })),
  ];
}

/** Active identities not yet given the product directly. */
export function assignablePeople(
  people: readonly (Named & { email?: string; status: string })[],
  assignments: readonly Pick<LicenseAssignmentView, 'subjectType' | 'subjectId'>[],
): FieldOption[] {
  const taken = new Set(
    assignments
      .filter((assignment) => assignment.subjectType === 'identity')
      .map((assignment) => assignment.subjectId),
  );
  return people
    .filter((person) => person.status === 'active' && !taken.has(person.id))
    .sort(byName)
    .map((person) => ({
      value: person.id,
      label: person.email ? `${person.name} (${person.email})` : person.name,
    }));
}

/** Groups not yet given the product. */
export function assignableGroups(
  groups: readonly Named[],
  assignments: readonly Pick<LicenseAssignmentView, 'subjectType' | 'subjectId'>[],
): FieldOption[] {
  const taken = new Set(
    assignments
      .filter((assignment) => assignment.subjectType === 'group')
      .map((assignment) => assignment.subjectId),
  );
  return groups
    .filter((group) => !taken.has(group.id))
    .sort(byName)
    .map((group) => ({ value: group.id, label: group.name }));
}

/** Active products the person has not been given directly (the member page's Licenses card). */
export function assignableProducts(
  products: readonly Pick<LicenseProductView, 'id' | 'key' | 'name' | 'status'>[],
  directProductIds: Iterable<string>,
): FieldOption[] {
  const taken = new Set(directProductIds);
  return products
    .filter((product) => product.status === 'active' && !taken.has(product.id))
    .map((product) => ({ value: product.id, label: `${product.name} (${product.key})` }));
}

/** Billing subscriptions a pool may reference as how its seats were bought. */
export function subscriptionOptions(
  subscriptions: readonly {
    id: string;
    planName: string;
    accountId: string;
    accountName?: string;
    status: string;
  }[],
): FieldOption[] {
  return subscriptions.map((subscription) => ({
    value: subscription.id,
    label: `${subscription.planName} · ${subscription.accountName ?? subscription.accountId} (${subscription.status})`,
  }));
}

const hidden = (name: string, value: string): FieldSpec => ({
  name,
  label: name,
  type: 'hidden',
  defaultValue: value,
});

/** `licenses.createProduct`. */
export function productFields(tenantId: string): FieldSpec[] {
  return [
    hidden('tenantId', tenantId),
    {
      name: 'key',
      label: 'Key',
      required: true,
      placeholder: 'pro',
      help: 'Lowercase letters, digits, dots, underscores or hyphens. It never changes: policies (principal.licenses) and birthright rules (identity.licenses) name products by key.',
    },
    { name: 'name', label: 'Name', required: true, placeholder: 'Pro plan' },
    { name: 'description', label: 'Description', type: 'textarea', rows: 2 },
    {
      name: 'featureKeys',
      label: 'Feature keys',
      type: 'list',
      placeholder: 'exports, sso',
      help: `Features the people holding an active seat get (iam.licenses.features), comma-separated; at most ${featureKeyLimit}.`,
    },
  ];
}

/** `licenses.updateProduct`: name, description (emptied clears it) and feature keys (emptied keeps them). */
export function productEditFields(
  tenantId: string,
  product: Pick<LicenseProductView, 'id' | 'name' | 'description' | 'featureKeys'>,
): FieldSpec[] {
  return [
    hidden('tenantId', tenantId),
    hidden('productId', product.id),
    { name: 'name', label: 'Name', required: true, defaultValue: product.name },
    {
      name: 'description',
      label: 'Description',
      type: 'textarea',
      rows: 2,
      emptyAsNull: true,
      defaultValue: product.description ?? '',
    },
    {
      name: 'featureKeys',
      label: 'Feature keys',
      type: 'list',
      defaultValue: product.featureKeys,
      help: 'Comma-separated; replaces the current keys. An empty field keeps them (remove them all with the button below).',
    },
  ];
}

/** `licenses.addPool` for a product this organization defines: seats for itself or one of its projects. */
export function poolFields(
  tenantId: string,
  productId: string,
  tenants: readonly FieldOption[],
  subscriptions: readonly FieldOption[],
): FieldSpec[] {
  return [
    hidden('productId', productId),
    tenants.length > 1
      ? {
          name: 'tenantId',
          label: 'Seats for',
          type: 'select',
          required: true,
          defaultValue: tenantId,
          options: [...tenants],
          help: 'This organization, or one of its projects.',
        }
      : hidden('tenantId', tenantId),
    { name: 'quantity', label: 'Seats', type: 'number', required: true, placeholder: '25' },
    {
      name: 'startsAt',
      label: 'Starts',
      type: 'datetime',
      help: 'Leave empty to count the seats from now.',
    },
    {
      name: 'endsAt',
      label: 'Ends',
      type: 'datetime',
      help: 'Leave empty for seats that do not end. When they end, the newest active seats beyond the remaining capacity join the waiting list.',
    },
    { name: 'note', label: 'Note', placeholder: 'PO-1042, annual renewal' },
    ...(subscriptions.length
      ? [
          {
            name: 'subscriptionId',
            label: 'Billing subscription',
            type: 'select',
            options: [...subscriptions],
            help: 'Records that the seats were bought through this subscription; billing itself is not changed.',
          } satisfies FieldSpec,
        ]
      : []),
  ];
}

/** `licenses.updatePool`: the seats, the end (emptied: no end), and the note (emptied clears it). */
export function poolEditFields(
  pool: Pick<LicensePoolView, 'id' | 'tenantId' | 'quantity' | 'endsAt' | 'note'>,
): FieldSpec[] {
  return [
    hidden('tenantId', pool.tenantId),
    hidden('poolId', pool.id),
    {
      name: 'quantity',
      label: 'Seats',
      type: 'number',
      required: true,
      defaultValue: pool.quantity,
    },
    {
      name: 'endsAt',
      label: 'Ends',
      type: 'datetime',
      emptyAsNull: true,
      ...(pool.endsAt !== undefined ? { defaultValue: pool.endsAt } : {}),
      help: 'Empty: the seats do not end. A past time ends them now.',
    },
    { name: 'note', label: 'Note', emptyAsNull: true, defaultValue: pool.note ?? '' },
  ];
}

/** `licenses.configure`: an emptied reclaim period turns reclaim off. */
export function settingsFields(
  tenantId: string,
  settings: Pick<LicenseSettingsView, 'reclaimAfterDays' | 'notifyWaiting'>,
): FieldSpec[] {
  return [
    hidden('tenantId', tenantId),
    {
      name: 'reclaimAfterDays',
      label: 'Reclaim seats after this many days without activity',
      type: 'number',
      emptyAsNull: true,
      defaultValue: settings.reclaimAfterDays ?? '',
      placeholder: '90',
      help: `${reclaimDays.min} to ${reclaimDays.max} days; leave empty to turn reclaim off. Once a day, direct assignments of people with no sign-in or API key use for that long are removed; seats held through groups are only counted.`,
    },
    {
      name: 'notifyWaiting',
      label: 'Email people when they join a waiting list and when their seat becomes active',
      type: 'checkbox',
      defaultValue: settings.notifyWaiting,
    },
  ];
}

/** `licenses.assign` of one product to a person or a group. */
export function assignFields(
  tenantId: string,
  productId: string,
  subjectType: LicenseSubjectType,
  options: readonly FieldOption[],
): FieldSpec[] {
  return [
    hidden('tenantId', tenantId),
    hidden('productId', productId),
    hidden('subjectType', subjectType),
    {
      name: 'subjectId',
      label: subjectType === 'identity' ? 'Person' : 'Group',
      type: 'select',
      required: true,
      options: [...options],
      ...(subjectType === 'group'
        ? { help: 'Every active member claims a seat, and so do people who join later.' }
        : {}),
    },
  ];
}

/** `licenses.assignMany`: several people at once. */
export function assignManyFields(
  tenantId: string,
  productId: string,
  options: readonly FieldOption[],
): FieldSpec[] {
  return [
    hidden('tenantId', tenantId),
    hidden('productId', productId),
    {
      name: 'identityIds',
      label: 'People',
      type: 'multiselect',
      required: true,
      options: [...options],
      help: `Up to ${assignManyLimit} at once (hold Ctrl or Cmd to pick several).`,
    },
  ];
}

/** `licenses.assign` of a product to one person, from their member page. */
export function memberAssignFields(
  tenantId: string,
  identityId: string,
  products: readonly FieldOption[],
): FieldSpec[] {
  return [
    hidden('tenantId', tenantId),
    hidden('subjectType', 'identity'),
    hidden('subjectId', identityId),
    {
      name: 'productId',
      label: 'Product',
      type: 'select',
      required: true,
      options: [...products],
    },
  ];
}
