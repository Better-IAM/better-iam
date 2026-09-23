// Formatting helpers for the billing pages (cloud/[org]/billing, admin/billing).

import type { PlanView, PriceView, StatementSummary } from 'better-iam';

/** Micros as money: cents for ordinary amounts, more digits for fractions of a cent (token prices). */
export function money(micros: number, currency = 'USD'): string {
  const units = micros / 1_000_000;
  const digits = micros !== 0 && Math.abs(micros) < 10_000 ? 6 : 2;
  try {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency,
      minimumFractionDigits: digits,
      maximumFractionDigits: digits,
    }).format(units);
  } catch {
    return `${currency} ${units.toFixed(digits)}`;
  }
}

/** A quantity with thousands separators and at most three decimals. */
export const quantity = (value: number) =>
  value.toLocaleString('en-US', { maximumFractionDigits: 3 });

/** `2026-09` as `September 2026`. */
export function periodLabel(period: string): string {
  const [year, month] = period.split('-').map(Number) as [number, number];
  return new Date(Date.UTC(year, month - 1, 15)).toLocaleString('en-US', {
    month: 'long',
    year: 'numeric',
    timeZone: 'UTC',
  });
}

/** The `count` periods ending with `period`, newest first. */
export function recentPeriods(period: string, count: number): string[] {
  const [year, month] = period.split('-').map(Number) as [number, number];
  return Array.from({ length: count }, (_, index) => {
    const value = year * 12 + (month - 1) - index;
    return `${Math.floor(value / 12)}-${String((value % 12) + 1).padStart(2, '0')}`;
  });
}

/** A rate-card price in one line: `$0.01 per request`, `graduated: 2 tiers`, `1000 included`. */
export function priceSummary(view: PriceView['price'], unit: string, currency = 'USD'): string {
  const amount = (value: number | undefined) => money((value ?? 0) * 1_000_000, currency);
  const base =
    view.model === 'per-unit'
      ? `${amount(view.unitAmount)} per ${unit}`
      : view.model === 'package'
        ? `${amount(view.packageAmount)} per ${quantity(view.packageSize ?? 1)} ${unit}s`
        : `${view.model}: ${(view.tiers ?? [])
            .map(
              (tier) =>
                `${tier.upTo === null ? 'then' : `≤${quantity(tier.upTo)}`} ${amount(tier.unitAmount)}`,
            )
            .join(', ')}`;
  return view.includedQuantity ? `${base} (${quantity(view.includedQuantity)} included)` : base;
}

/** A plan's items in one line: `$100.00/month · $10.00 per seat (2 included) · API calls: $0.002 per unit`. */
export function planSummary(plan: PlanView, currency = 'USD'): string {
  return plan.items
    .map((item) =>
      item.kind === 'fee'
        ? `${money((item.amount ?? 0) * 1_000_000, currency)}/month`
        : item.kind === 'seat'
          ? `${money((item.unitAmount ?? 0) * 1_000_000, currency)} per seat${item.includedSeats ? ` (${item.includedSeats} included)` : ''}`
          : `${item.name}: ${item.price ? priceSummary(item.price, 'unit', currency) : 'rate card'}`,
    )
    .join(' · ');
}

/** The badge tone of an invoice status. */
export function invoiceTone(
  status: StatementSummary['status'],
): 'success' | 'neutral' | 'info' | 'warning' | 'danger' {
  switch (status) {
    case 'paid':
      return 'success';
    case 'void':
      return 'neutral';
    case 'uncollectible':
      return 'danger';
    case 'draft':
      return 'warning';
    default:
      return 'info';
  }
}

/** How an invoice is named in lists: its number, or `Draft` before it is finalized. */
export const invoiceName = (statement: { number: string }) => statement.number || 'Draft';
