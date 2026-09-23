import { IamError, type IamStore } from '@better-iam/core';
import {
  amountMicros,
  billingCollections,
  meterKey,
  overlapShare,
  periodBounds,
  periodOf,
  priceSpec,
  roundCents,
  shiftPeriod,
  type BillingInvoiceItem,
  type BillingPlan,
  type BillingSubscription,
  type PlanItem,
  type StatementLine,
} from './billing.js';
import { id } from './utils.js';
import { integer, object, text } from './validation.js';

/**
 * Plans and subscriptions: what an account pays every month besides usage. A plan holds recurring fees, per-seat
 * fees and its own prices for meters; a subscription ties a billing account to a plan with a start, an optional trial,
 * a seat count and an end. Fee and seat items are billed in advance (on the invoice closing the month before, or on a
 * first invoice when the subscription starts) or in arrears (on the month's own invoice), prorated to the part of the
 * month the subscription was live and out of its trial. Seat changes and cancellations of advance-billed items create
 * proration invoice items for the next invoice, as Stripe does.
 */

const itemIdPattern = /^[a-z0-9][a-z0-9_-]{0,63}$/;
const planKeyPattern = /^[a-z][a-z0-9_.-]{0,63}$/;
export const maxPlansPerTenant = 100;

/** A plan key: 1-64 lowercase letters, digits, `.`, `_` or `-`, starting with a letter. */
export function planKey(value: unknown): string {
  if (typeof value !== 'string' || !planKeyPattern.test(value))
    throw new IamError(
      'INVALID_INPUT',
      'plan must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter',
    );
  return value;
}

/** Validates plan items given in currency units (`amount`, `unitAmount`, a usage item's `price`). */
export function planItems(value: unknown): PlanItem[] {
  if (!Array.isArray(value) || value.length === 0 || value.length > 20)
    throw new IamError('INVALID_INPUT', 'items must list 1-20 plan items');
  const ids = new Set<string>();
  const meters = new Set<string>();
  return value.map((raw: unknown) => {
    const input = object(raw);
    const itemId = input.id;
    if (typeof itemId !== 'string' || !itemIdPattern.test(itemId))
      throw new IamError(
        'INVALID_INPUT',
        'Each item needs an id of 1-64 lowercase letters, digits, - or _',
      );
    if (ids.has(itemId)) throw new IamError('INVALID_INPUT', `Duplicate item id ${itemId}`);
    ids.add(itemId);
    const name = text(input.name ?? itemId, 'items.name', 128).trim();
    const billing = input.billing ?? 'advance';
    if (billing !== 'advance' && billing !== 'arrears')
      throw new IamError('INVALID_INPUT', "items.billing must be 'advance' or 'arrears'");
    switch (input.kind) {
      case 'fee':
        return {
          id: itemId,
          kind: 'fee',
          name,
          amountMicros: amountMicros(input.amount, 'items.amount'),
          billing,
        };
      case 'seat': {
        const item: PlanItem = {
          id: itemId,
          kind: 'seat',
          name,
          unitAmountMicros: amountMicros(input.unitAmount, 'items.unitAmount'),
          billing,
        };
        if (input.includedSeats !== undefined && input.includedSeats !== 0)
          item.includedSeats = integer(input.includedSeats, 'items.includedSeats', 0, 1_000_000);
        return item;
      }
      case 'usage': {
        const meter = meterKey(input.meter);
        if (meters.has(meter)) throw new IamError('INVALID_INPUT', `Two items price ${meter}`);
        meters.add(meter);
        return { id: itemId, kind: 'usage', name, meter, price: priceSpec(input.price) };
      }
      default:
        throw new IamError('INVALID_INPUT', "items.kind must be 'fee', 'seat' or 'usage'");
    }
  });
}

/** Validated plan settings; `current` supplies values an update leaves out. */
export function planSettings(
  input: Record<string, unknown>,
  current?: BillingPlan,
): Pick<BillingPlan, 'name' | 'items' | 'selfServe' | 'archived'> & {
  description?: string;
  trialDays?: number;
} {
  const name = input.name === undefined ? current?.name : text(input.name, 'name', 128).trim();
  if (!name) throw new IamError('INVALID_INPUT', 'name is required');
  const items = input.items === undefined ? current?.items : planItems(input.items);
  if (!items) throw new IamError('INVALID_INPUT', 'items are required');
  const flag = (value: unknown, fallback: boolean, field: string) => {
    if (value === undefined) return fallback;
    if (typeof value !== 'boolean')
      throw new IamError('INVALID_INPUT', `${field} must be a boolean`);
    return value;
  };
  const description =
    input.description === null
      ? undefined
      : input.description === undefined
        ? current?.description
        : text(input.description, 'description', 512).trim();
  const trialDays =
    input.trialDays === null
      ? undefined
      : input.trialDays === undefined
        ? current?.trialDays
        : integer(input.trialDays, 'trialDays', 1, 365);
  return {
    name,
    items,
    selfServe: flag(input.selfServe, current?.selfServe ?? false, 'selfServe'),
    archived: flag(input.archived, current?.archived ?? false, 'archived'),
    ...(description !== undefined ? { description } : {}),
    ...(trialDays !== undefined ? { trialDays } : {}),
  };
}

/** The part of `[start, end)` a subscription is billable in: live and past its trial. */
function billableWindow(
  subscription: BillingSubscription,
  start: number,
  end: number,
): { from: number; to: number } | undefined {
  const from = Math.max(start, subscription.startedAt, subscription.trialEndsAt ?? 0);
  const to = Math.min(end, subscription.endsAt ?? Number.POSITIVE_INFINITY);
  return to > from ? { from, to } : undefined;
}

/** Chargeable seats (above the included ones) from the subscription's seat history, weighted by time in `[from, to)`. */
function seatMonths(
  subscription: BillingSubscription,
  item: PlanItem,
  period: { start: number; end: number },
  window: { from: number; to: number },
): number {
  const history = subscription.seatHistory.length
    ? subscription.seatHistory
    : [{ at: subscription.startedAt, seats: subscription.seats }];
  let total = 0;
  history.forEach((entry, index) => {
    const next = history[index + 1]?.at ?? Number.POSITIVE_INFINITY;
    const chargeable = Math.max(0, entry.seats - (item.includedSeats ?? 0));
    if (!chargeable) return;
    const from = Math.max(window.from, entry.at);
    const to = Math.min(window.to, next);
    if (to > from) total += chargeable * overlapShare(period.start, period.end, from, to);
  });
  return Math.round(total * 10_000) / 10_000;
}

/** One fee or seat line for a subscription item over a month and the part of it that is billable. */
function itemLine(
  subscription: BillingSubscription,
  item: PlanItem,
  period: { start: number; end: number },
  window: { from: number; to: number },
): StatementLine | undefined {
  const share = overlapShare(period.start, period.end, window.from, window.to);
  if (share <= 0) return undefined;
  const base = {
    subscriptionId: subscription.id,
    planItemId: item.id,
    servicePeriod: { start: period.start, end: period.end },
    ...(share < 1 ? { proration: share } : {}),
    description: `${subscription.planName}: ${item.name}`,
  };
  if (item.kind === 'fee')
    return {
      kind: 'fee',
      name: item.name,
      unit: 'month',
      quantity: 1,
      unitAmountMicros: item.amountMicros!,
      amountMicros: roundCents(item.amountMicros! * share),
      ...base,
    };
  const seats = seatMonths(subscription, item, period, window);
  if (seats <= 0) return undefined;
  // Seats are shown as seat-months, so the proration is already in the quantity.
  const { proration: _proration, ...rest } = base;
  return {
    kind: 'seat',
    name: item.name,
    unit: 'seat-month',
    quantity: seats,
    unitAmountMicros: item.unitAmountMicros!,
    amountMicros: roundCents(item.unitAmountMicros! * seats),
    ...rest,
  };
}

/**
 * The fee and seat lines an account's invoice for `period` carries: arrears items for `period` itself, advance items
 * for the month after it, and advance items of `period` that no invoice has billed yet (a trial that ended within the
 * month, a voided subscription invoice). `advance` lists the subscription months the invoice pays for in advance,
 * which are marked billed when it is finalized.
 */
export async function subscriptionLines(
  tx: IamStore,
  accountId: string,
  period: string,
  timeZone: string,
): Promise<{ lines: StatementLine[]; advance: { subscriptionId: string; period: string }[] }> {
  const lines: StatementLine[] = [];
  const advance: { subscriptionId: string; period: string }[] = [];
  const here = periodBounds(period, timeZone);
  const subscriptions = (
    await tx.find<BillingSubscription>(billingCollections.subscriptions, { tenantId: accountId })
  ).sort((a, b) => a.startedAt - b.startedAt || (a.id < b.id ? -1 : 1));
  for (const subscription of subscriptions) {
    const plan = await tx.get<BillingPlan>(billingCollections.plans, subscription.planId);
    if (!plan) continue;
    const arrears = billableWindow(subscription, here.start, here.end);
    if (arrears)
      for (const item of plan.items)
        if (item.kind !== 'usage' && item.billing === 'arrears') {
          const line = itemLine(subscription, item, here, arrears);
          if (line) lines.push(line);
        }
    if (!plan.items.some((item) => item.kind !== 'usage' && item.billing !== 'arrears')) continue;
    for (const target of [period, shiftPeriod(period, 1)]) {
      if (subscription.billedAdvance.includes(target)) continue;
      const bounds = periodBounds(target, timeZone);
      // Only months the subscription runs in.
      if (subscription.startedAt >= bounds.end) continue;
      if (subscription.endsAt !== undefined && subscription.endsAt <= bounds.start) continue;
      const window = billableWindow(subscription, bounds.start, bounds.end);
      if (window)
        for (const item of plan.items)
          if (item.kind !== 'usage' && item.billing !== 'arrears') {
            const line = itemLine(subscription, item, bounds, window);
            if (line) lines.push(line);
          }
      // A month with nothing to bill in advance (a trial) still counts as handled.
      advance.push({ subscriptionId: subscription.id, period: target });
    }
  }
  return { lines, advance };
}

/** The advance lines of a new subscription's first month (from its start, or its trial end, to the month's end). */
export function firstPeriodLines(
  subscription: BillingSubscription,
  plan: BillingPlan,
  timeZone: string,
): { period: string; lines: StatementLine[] } {
  const period = periodOf(subscription.startedAt, timeZone);
  const bounds = periodBounds(period, timeZone);
  const window = billableWindow(subscription, bounds.start, bounds.end);
  const lines: StatementLine[] = [];
  if (window)
    for (const item of plan.items)
      if (item.kind !== 'usage' && item.billing !== 'arrears') {
        const line = itemLine(subscription, item, bounds, window);
        if (line) lines.push(line);
      }
  return { period, lines };
}

/**
 * Proration invoice items for a change at `at` to advance-billed items of the current month (already paid for): a
 * credit for what the old state no longer uses and a charge for what the new one adds, as Stripe prorates.
 */
export function prorationItems(input: {
  subscription: BillingSubscription;
  plan: BillingPlan;
  at: number;
  timeZone: string;
  /** Seats before and after (`after: 0` ends every seat charge); undefined for a cancellation of fees too. */
  seats?: { before: number; after: number };
  /** The subscription ends at `at`: fee items are credited too. */
  ending: boolean;
  createdBy: string;
}): BillingInvoiceItem[] {
  const { subscription, plan, at, timeZone } = input;
  const period = periodOf(at, timeZone);
  if (!subscription.billedAdvance.includes(period)) return [];
  const bounds = periodBounds(period, timeZone);
  // Only the part of the month after the change and outside the trial was paid for and changes.
  const from = Math.max(at, subscription.trialEndsAt ?? 0);
  const share = overlapShare(bounds.start, bounds.end, from, bounds.end);
  if (share <= 0) return [];
  const items: BillingInvoiceItem[] = [];
  const make = (description: string, amount: number): BillingInvoiceItem => ({
    id: id(),
    tenantId: subscription.tenantId,
    description,
    quantity: 1,
    unitAmountMicros: amount,
    amountMicros: amount,
    period,
    status: 'pending',
    source: 'proration',
    subscriptionId: subscription.id,
    createdAt: at,
    createdBy: input.createdBy,
  });
  for (const item of plan.items) {
    if (item.kind === 'usage' || item.billing === 'arrears') continue;
    if (item.kind === 'fee' && input.ending) {
      const amount = roundCents(-item.amountMicros! * share);
      if (amount) items.push(make(`Unused time on ${plan.name}: ${item.name}`, amount));
    }
    if (item.kind === 'seat') {
      const before = Math.max(
        0,
        (input.seats?.before ?? subscription.seats) - (item.includedSeats ?? 0),
      );
      const after = input.ending
        ? 0
        : Math.max(0, (input.seats?.after ?? subscription.seats) - (item.includedSeats ?? 0));
      if (before === after) continue;
      const amount = roundCents((after - before) * item.unitAmountMicros! * share);
      items.push(
        make(
          after > before
            ? `${after - before} added seat${after - before === 1 ? '' : 's'} on ${plan.name} for the rest of the month`
            : `Unused time on ${before - after} seat${before - after === 1 ? '' : 's'} of ${plan.name}`,
          amount,
        ),
      );
    }
  }
  return items;
}
