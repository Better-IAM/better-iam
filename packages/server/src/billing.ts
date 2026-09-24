import { createHash } from 'node:crypto';
import {
  IamError,
  type IamStore,
  type Identity,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import {
  departmentChain,
  departmentOf,
  tenantDepartments,
  type Department,
} from './departments.js';
import { teamChain, teamCollections, teamsOf, type Team } from './teams.js';
import { integer, object, text } from './validation.js';

/**
 * Billing and spend tracking. Meters name what is billed (API calls, seat-days, GB-days, AI inference); a rate card
 * prices them; usage events record how much each tenant, person, agent, team and department used. Spend is computed
 * per billing account (the nearest tenant with a billing profile, else the organization) and period (a calendar month
 * in the billing time zone): each meter's period total is priced once with its tiers, then allocated back to the usage
 * that produced it by share of quantity (a blended rate), so individual, team, department and project spend always add
 * up to the account's charges. Meters with `pricing: 'reported'` carry their cost on each event instead (inference).
 */

/** Collections owned by the billing module. */
export const billingCollections = {
  meters: 'billingMeters',
  prices: 'billingPrices',
  usage: 'billingUsage',
  rollups: 'billingRollups',
  budgets: 'billingBudgets',
  budgetAlerts: 'billingBudgetAlerts',
  credits: 'billingCredits',
  profiles: 'billingProfiles',
  statements: 'billingStatements',
  terms: 'billingTerms',
  invoiceItems: 'billingInvoiceItems',
  creditNotes: 'billingCreditNotes',
  plans: 'billingPlans',
  subscriptions: 'billingSubscriptions',
  coupons: 'billingCoupons',
  discounts: 'billingDiscounts',
} as const;

/** The contract terms of a billing account, if the platform set any. */
export async function termsOf(tx: IamStore, accountId: string): Promise<BillingTerms | undefined> {
  return (
    await tx.find<BillingTerms>(billingCollections.terms, {
      tenantId: accountId,
      uniqueKey: 'terms',
    })
  )[0];
}

/**
 * The contract terms a billing account's invoices use: its own, else the discount and tax of the nearest ancestor with
 * terms, so a sub-account carved out of an organization stays under the organization's contract. A minimum commitment
 * is not inherited (each sub-account would owe it again): it stays with the account it was set on, which is invoiced
 * for it even in a month without usage.
 */
export async function accountTermsOf(
  ctx: ServerContext,
  tx: IamStore,
  account: Tenant,
): Promise<BillingTerms | undefined> {
  for (const [index, realm] of (await ctx.ancestry(tx, account)).entries()) {
    const terms = await termsOf(tx, realm.id);
    if (!terms) continue;
    if (index === 0) return terms;
    const { minimumCommitmentMicros: _commitment, ...inherited } = terms;
    return inherited;
  }
  return undefined;
}

export interface BillingOptions {
  /** ISO 4217 code every amount is stated in (default `USD`). */
  currency?: string;
  /** IANA time zone that billing periods (calendar months) and days follow (default `UTC`). */
  timeZone?: string;
  /** Days raw usage events are kept after their period ends (default 400); daily roll-ups and statements stay. */
  usageRetentionDays?: number;
  /**
   * How a person's cost counts toward their teams: `split` evenly across their direct teams (default), all to their
   * `primary` (oldest) team, or in `full` to each team (team totals may then add up to more than the organization's).
   */
  teamAttribution?: 'split' | 'primary' | 'full';
  /** Days after issue a statement is due when the billing profile sets no terms (default 30). */
  paymentTermsDays?: number;
  /** Statement number prefix (default `INV`); numbers read `{prefix}-{YYYYMM}-{sequence}`. */
  statementPrefix?: string;
  /** Who issues the invoices, printed on every invoice (default: the product name only). */
  issuer?: InvoiceIssuer;
  /**
   * When `billing.sendPaymentReminders` emails the billing contacts of an unpaid invoice, in days relative to its due
   * date (default `[-3, 0, 7, 14]`: three days before, on the day, one and two weeks after). `[]` sends none.
   */
  paymentReminderDays?: number[];
  /**
   * Whether `closePeriod` finalizes monthly invoices right away (default true). With false it keeps them as drafts,
   * refreshed on every run, for an administrator to review, adjust with invoice items, and finalize
   * (`billing.finalizeInvoice`).
   */
  autoFinalize?: boolean;
}

/** Who issues invoices: printed at the top of every invoice (`billing.issuer`). */
export interface InvoiceIssuer {
  name: string;
  address?: string;
  taxId?: string;
  email?: string;
  url?: string;
  /** How to pay: bank details, a payment link, terms (printed under the totals). */
  paymentInstructions?: string;
}

export interface BillingSettings {
  currency: string;
  timeZone: string;
  usageRetentionDays: number;
  teamAttribution: 'split' | 'primary' | 'full';
  paymentTermsDays: number;
  statementPrefix: string;
  issuer?: InvoiceIssuer;
  paymentReminderDays: number[];
  autoFinalize: boolean;
}

/** Validates the `billing` option; a bad value fails construction with INVALID_CONFIG. */
export function billingSettings(options: BillingOptions | undefined): BillingSettings {
  const fail = (message: string): never => {
    throw new IamError('INVALID_CONFIG', `billing.${message}`);
  };
  const settings: BillingSettings = {
    currency: options?.currency ?? 'USD',
    timeZone: options?.timeZone ?? 'UTC',
    usageRetentionDays: options?.usageRetentionDays ?? 400,
    teamAttribution: options?.teamAttribution ?? 'split',
    paymentTermsDays: options?.paymentTermsDays ?? 30,
    statementPrefix: options?.statementPrefix ?? 'INV',
    paymentReminderDays: options?.paymentReminderDays ?? [-3, 0, 7, 14],
    autoFinalize: options?.autoFinalize ?? true,
  };
  if (typeof settings.autoFinalize !== 'boolean') fail('autoFinalize must be a boolean');
  if (options?.issuer !== undefined) {
    const issuer = options.issuer as unknown as Record<string, unknown>;
    if (!issuer || typeof issuer !== 'object') fail('issuer must be an object');
    const field = (key: keyof InvoiceIssuer, max: number, required = false) => {
      const value = issuer[key];
      if (value === undefined && !required) return;
      if (typeof value !== 'string' || !value.trim() || value.length > max)
        fail(`issuer.${key} must be text of 1-${max} characters`);
    };
    field('name', 256, true);
    field('address', 1024);
    field('taxId', 64);
    field('email', 254);
    field('url', 512);
    field('paymentInstructions', 2048);
    settings.issuer = { ...options.issuer };
  }
  if (
    !Array.isArray(settings.paymentReminderDays) ||
    settings.paymentReminderDays.length > 10 ||
    settings.paymentReminderDays.some(
      (value) => !Number.isSafeInteger(value) || value < -60 || value > 365,
    )
  )
    fail('paymentReminderDays must list at most 10 whole days from -60 to 365');
  settings.paymentReminderDays = [...new Set(settings.paymentReminderDays)].sort((a, b) => a - b);
  if (!/^[A-Z]{3}$/.test(settings.currency)) fail('currency must be an ISO 4217 code such as USD');
  try {
    new Intl.DateTimeFormat('en-US', { timeZone: settings.timeZone });
  } catch {
    fail('timeZone must be an IANA time zone');
  }
  if (
    !Number.isSafeInteger(settings.usageRetentionDays) ||
    settings.usageRetentionDays < 1 ||
    settings.usageRetentionDays > 3650
  )
    fail('usageRetentionDays must be 1-3650');
  if (!['split', 'primary', 'full'].includes(settings.teamAttribution))
    fail("teamAttribution must be 'split', 'primary' or 'full'");
  if (
    !Number.isSafeInteger(settings.paymentTermsDays) ||
    settings.paymentTermsDays < 0 ||
    settings.paymentTermsDays > 365
  )
    fail('paymentTermsDays must be 0-365');
  if (!/^[A-Z0-9][A-Z0-9-]{0,15}$/.test(settings.statementPrefix))
    fail('statementPrefix must be 1-16 uppercase letters, digits or hyphens');
  return settings;
}

// ---------------------------------------------------------------------------------------------------------------
// Money and periods

/** One unit of currency in micros. */
export const microsPerUnit = 1_000_000;
/** Rounds micro amounts to a thousandth of a micro (prices per token are fractions of a micro). */
export const roundMicros = (value: number): number => Math.round(value * 1000) / 1000;
/**
 * Micros rounded to a whole cent. Invoice amounts (lines, items, discounts, tax) are kept in cents so what an invoice
 * shows adds up; spend reports keep fractions of a cent.
 */
export const roundCents = (micros: number): number => Math.round(micros / 10_000) * 10_000;
/** Micros as currency units, rounded to the cent. */
export const unitsOf = (micros: number): number => Math.round(micros / 10_000) / 100;

/** An amount in currency units (a price or a budget) as micros: finite, 0 to one billion units. */
export function amountMicros(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 1e9)
    throw new IamError('INVALID_INPUT', `${name} must be an amount from 0 to 1000000000`);
  return roundMicros(value * microsPerUnit);
}

const periodPattern = /^(\d{4})-(0[1-9]|1[0-2])$/;

/** A billing period `YYYY-MM`. */
export function billingPeriod(value: unknown, name = 'period'): string {
  if (typeof value !== 'string' || !periodPattern.test(value))
    throw new IamError('INVALID_INPUT', `${name} must be a month such as 2026-09`);
  return value;
}

const formatters = new Map<string, Intl.DateTimeFormat>();
function zoneParts(at: number, timeZone: string) {
  let formatter = formatters.get(timeZone);
  if (!formatter) {
    formatter = new Intl.DateTimeFormat('en-US', {
      timeZone,
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      second: '2-digit',
      hourCycle: 'h23',
    });
    formatters.set(timeZone, formatter);
  }
  const parts = formatter.formatToParts(new Date(at));
  const read = (type: string) => Number(parts.find((part) => part.type === type)?.value ?? 0);
  return {
    year: read('year'),
    month: read('month'),
    day: read('day'),
    hour: read('hour') % 24,
    minute: read('minute'),
    second: read('second'),
  };
}
/** Local wall-clock time minus UTC at an instant, in milliseconds. */
function zoneOffset(at: number, timeZone: string): number {
  const p = zoneParts(at, timeZone);
  return (
    Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - Math.floor(at / 1000) * 1000
  );
}
/** The instant of local midnight on a date in a time zone. */
function localMidnight(year: number, month: number, day: number, timeZone: string): number {
  const guess = Date.UTC(year, month - 1, day);
  const first = guess - zoneOffset(guess, timeZone);
  return guess - zoneOffset(first, timeZone);
}
const pad = (value: number, width = 2) => String(value).padStart(width, '0');

/** The billing period an instant falls in. */
export function periodOf(at: number, timeZone: string): string {
  const p = zoneParts(at, timeZone);
  return `${pad(p.year, 4)}-${pad(p.month)}`;
}
/** The local day `YYYY-MM-DD` an instant falls on. */
export function dayOf(at: number, timeZone: string): string {
  const p = zoneParts(at, timeZone);
  return `${pad(p.year, 4)}-${pad(p.month)}-${pad(p.day)}`;
}
/** A period `months` after (or before, when negative) another. */
export function shiftPeriod(period: string, months: number): string {
  const [year, month] = period.split('-').map(Number) as [number, number];
  const index = year * 12 + (month - 1) + months;
  return `${pad(Math.floor(index / 12), 4)}-${pad((index % 12) + 1)}`;
}
/** The first instant of a period and of the next one. */
export function periodBounds(period: string, timeZone: string): { start: number; end: number } {
  const [year, month] = billingPeriod(period).split('-').map(Number) as [number, number];
  const next = shiftPeriod(period, 1).split('-').map(Number) as [number, number];
  return {
    start: localMidnight(year, month, 1, timeZone),
    end: localMidnight(next[0], next[1], 1, timeZone),
  };
}

export type BudgetPeriodKind = 'month' | 'quarter' | 'year';
/** The periods of the budget window containing `period`: the month, its calendar quarter, or its year. */
export function windowPeriods(kind: BudgetPeriodKind, period: string): string[] {
  const month = Number(period.slice(5, 7));
  const first =
    kind === 'month'
      ? period
      : kind === 'quarter'
        ? shiftPeriod(period, -((month - 1) % 3))
        : shiftPeriod(period, -(month - 1));
  const length = kind === 'month' ? 1 : kind === 'quarter' ? 3 : 12;
  return Array.from({ length }, (_, index) => shiftPeriod(first, index));
}

// ---------------------------------------------------------------------------------------------------------------
// Meters and prices

/** What a meter counts, and how its usage becomes cost. */
export interface BillingMeter extends StoredRecord {
  /** Unique along a tenant's ancestry; the tenant nearest the root that defines a key owns it (uniqueKey = key). */
  key: string;
  name: string;
  /** Unit label such as `request`, `seat-day`, `GB-day` or `token`. */
  unit: string;
  description?: string;
  /** `sum` adds quantities; `unique` counts the distinct people or agents with usage in the period (active users). */
  aggregation: 'sum' | 'unique';
  /** `rate-card`: priced from the rate card per period; `reported`: every event carries its own cost. */
  pricing: 'rate-card' | 'reported';
  /** Archived meters refuse new usage but keep their history. */
  archived: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

export type PriceModel = 'per-unit' | 'graduated' | 'volume' | 'package';
/** One tier: units up to `upTo` (null = no limit) cost `unitAmountMicros` each, plus `flatAmountMicros` once. */
export interface PriceTier {
  upTo: number | null;
  unitAmountMicros: number;
  flatAmountMicros?: number;
}
/** How a period's quantity turns into an amount. */
export interface PriceSpec {
  model: PriceModel;
  /** `per-unit`: the price of one unit. */
  unitAmountMicros?: number;
  /** `graduated` (each tier prices its own units) and `volume` (the tier the total reaches prices every unit). */
  tiers?: PriceTier[];
  /** `package`: units are sold in packages of this size, each at `packageAmountMicros` (partial packages round up). */
  packageSize?: number;
  packageAmountMicros?: number;
  /** Free units per account and period, taken off before pricing. */
  includedQuantity?: number;
  /** Least a month with usage of the meter is billed (Orb-style minimum). */
  minimumAmountMicros?: number;
  /** Most a month is billed for the meter, however much is used (a cap). */
  maximumAmountMicros?: number;
}

/**
 * A rate card entry: the price of a meter for a tenant's subtree from a period on (until a later entry). The meter's
 * defining tenant sets its list price on itself and negotiated prices for tenants below it; the entry nearest to the
 * billing account wins. Stored in the tenant it applies to (uniqueKey `{meterId}:{effectiveFrom}`).
 */
export interface BillingPrice extends StoredRecord {
  meterId: string;
  meter: string;
  /** The tenant that defines the meter (and set this price). */
  definerId: string;
  /** First period the price applies to. */
  effectiveFrom: string;
  spec: PriceSpec;
  note?: string;
  setAt: number;
  setBy: string;
}

const meterKeyPattern = /^[a-z][a-z0-9_.-]{0,63}$/;
/** A meter key: 1-64 lowercase letters, digits, `.`, `_` or `-`, starting with a letter. */
export function meterKey(value: unknown): string {
  if (typeof value !== 'string' || !meterKeyPattern.test(value))
    throw new IamError(
      'INVALID_INPUT',
      'meter must be 1-64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter',
    );
  return value;
}

/** Meters per defining tenant. */
export const maxMetersPerTenant = 100;

/** Validated meter settings; `current` supplies values an update leaves out. */
export function meterSettings(
  input: Record<string, unknown>,
  current?: BillingMeter,
): Pick<BillingMeter, 'name' | 'unit' | 'aggregation' | 'pricing' | 'archived'> & {
  description?: string;
} {
  const name = input.name === undefined ? current?.name : text(input.name, 'name', 128).trim();
  if (!name) throw new IamError('INVALID_INPUT', 'name is required');
  const unit =
    input.unit === undefined ? (current?.unit ?? 'unit') : text(input.unit, 'unit', 32).trim();
  const aggregation = input.aggregation ?? current?.aggregation ?? 'sum';
  if (aggregation !== 'sum' && aggregation !== 'unique')
    throw new IamError('INVALID_INPUT', "aggregation must be 'sum' or 'unique'");
  if (current && input.aggregation !== undefined && input.aggregation !== current.aggregation)
    throw new IamError('INVALID_INPUT', 'A meter’s aggregation cannot change; create a new meter');
  const pricing = input.pricing ?? current?.pricing ?? 'rate-card';
  if (pricing !== 'rate-card' && pricing !== 'reported')
    throw new IamError('INVALID_INPUT', "pricing must be 'rate-card' or 'reported'");
  if (current && input.pricing !== undefined && input.pricing !== current.pricing)
    throw new IamError('INVALID_INPUT', 'A meter’s pricing cannot change; create a new meter');
  if (pricing === 'reported' && aggregation === 'unique')
    throw new IamError('INVALID_INPUT', 'Reported meters add up their events (aggregation sum)');
  const archived = input.archived ?? current?.archived ?? false;
  if (typeof archived !== 'boolean')
    throw new IamError('INVALID_INPUT', 'archived must be a boolean');
  const description =
    input.description === null
      ? undefined
      : input.description === undefined
        ? current?.description
        : text(input.description, 'description', 512).trim();
  return {
    name,
    unit,
    aggregation,
    pricing,
    archived,
    ...(description !== undefined ? { description } : {}),
  };
}

function quantityLimit(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > 1e15)
    throw new IamError('INVALID_INPUT', `${name} must be a positive number`);
  return value;
}

/**
 * Validates a price given in currency units (`unitAmount`, `tiers[].unitAmount` / `flatAmount`, `packageAmount`) and
 * returns it in micros. Tiers ascend by `upTo`, and the last one has `upTo: null`.
 */
export function priceSpec(value: unknown): PriceSpec {
  const input = object(value);
  const model = input.model;
  if (model !== 'per-unit' && model !== 'graduated' && model !== 'volume' && model !== 'package')
    throw new IamError(
      'INVALID_INPUT',
      "model must be 'per-unit', 'graduated', 'volume' or 'package'",
    );
  const spec: PriceSpec = { model };
  if (input.includedQuantity !== undefined && input.includedQuantity !== 0)
    spec.includedQuantity = quantityLimit(input.includedQuantity, 'includedQuantity');
  if (model === 'per-unit') spec.unitAmountMicros = amountMicros(input.unitAmount, 'unitAmount');
  else if (model === 'package') {
    spec.packageSize = quantityLimit(input.packageSize, 'packageSize');
    spec.packageAmountMicros = amountMicros(input.packageAmount, 'packageAmount');
  } else {
    const tiers: unknown = input.tiers;
    if (!Array.isArray(tiers) || tiers.length === 0 || tiers.length > 20)
      throw new IamError('INVALID_INPUT', 'tiers must list 1-20 tiers');
    let previous = 0;
    spec.tiers = tiers.map((raw: unknown, index: number) => {
      const tier = object(raw);
      const last = index === tiers.length - 1;
      if (last ? tier.upTo !== null : tier.upTo === null)
        throw new IamError('INVALID_INPUT', 'Only the last tier has upTo: null');
      const upTo = tier.upTo === null ? null : quantityLimit(tier.upTo, 'tiers.upTo');
      if (upTo !== null && upTo <= previous)
        throw new IamError('INVALID_INPUT', 'Tier upTo values must ascend');
      if (upTo !== null) previous = upTo;
      const result: PriceTier = {
        upTo,
        unitAmountMicros: amountMicros(tier.unitAmount ?? 0, 'tiers.unitAmount'),
      };
      if (tier.flatAmount !== undefined && tier.flatAmount !== 0)
        result.flatAmountMicros = amountMicros(tier.flatAmount, 'tiers.flatAmount');
      return result;
    });
  }
  if (input.minimumAmount !== undefined && input.minimumAmount !== null)
    spec.minimumAmountMicros = amountMicros(input.minimumAmount, 'minimumAmount');
  if (input.maximumAmount !== undefined && input.maximumAmount !== null)
    spec.maximumAmountMicros = amountMicros(input.maximumAmount, 'maximumAmount');
  if (
    spec.minimumAmountMicros !== undefined &&
    spec.maximumAmountMicros !== undefined &&
    spec.maximumAmountMicros < spec.minimumAmountMicros
  )
    throw new IamError('INVALID_INPUT', 'maximumAmount must not be below minimumAmount');
  return spec;
}

/** The amount, in micros, a period's quantity costs under a price: its tiers, then its minimum and maximum. */
export function priceQuantity(spec: PriceSpec, quantity: number): number {
  const raw = tieredAmount(spec, quantity);
  if (quantity <= 0) return raw;
  let amount = raw;
  if (spec.minimumAmountMicros !== undefined) amount = Math.max(amount, spec.minimumAmountMicros);
  if (spec.maximumAmountMicros !== undefined) amount = Math.min(amount, spec.maximumAmountMicros);
  return roundMicros(amount);
}

/**
 * How a quantity is priced, tier by tier, for invoice sub-lines: the tiers used, the free units, and what the tiers
 * came to before the price's minimum or maximum.
 */
export function priceBreakdown(
  spec: PriceSpec,
  quantity: number,
): { tiers: TierLine[]; includedQuantity?: number; rawMicros: number } {
  const included = Math.min(quantity, spec.includedQuantity ?? 0);
  const units = Math.max(0, quantity - included);
  const tiers: TierLine[] = [];
  if (units > 0 && (spec.model === 'graduated' || spec.model === 'volume')) {
    let lower = 0;
    for (const tier of spec.tiers!) {
      const upper = tier.upTo ?? Number.POSITIVE_INFINITY;
      if (spec.model === 'volume') {
        if (tier.upTo !== null && units > tier.upTo) {
          lower = upper;
          continue;
        }
        tiers.push({
          from: lower + 1,
          to: tier.upTo,
          quantity: units,
          unitAmountMicros: tier.unitAmountMicros,
          ...(tier.flatAmountMicros !== undefined
            ? { flatAmountMicros: tier.flatAmountMicros }
            : {}),
          amountMicros: roundMicros(units * tier.unitAmountMicros + (tier.flatAmountMicros ?? 0)),
        });
        break;
      }
      const inTier = Math.min(units, upper) - lower;
      if (inTier <= 0) break;
      tiers.push({
        from: lower + 1,
        to: tier.upTo,
        quantity: Math.round(inTier * 1e6) / 1e6,
        unitAmountMicros: tier.unitAmountMicros,
        ...(tier.flatAmountMicros !== undefined ? { flatAmountMicros: tier.flatAmountMicros } : {}),
        amountMicros: roundMicros(inTier * tier.unitAmountMicros + (tier.flatAmountMicros ?? 0)),
      });
      lower = upper;
    }
  }
  return {
    tiers,
    ...(included > 0 ? { includedQuantity: included } : {}),
    rawMicros: tieredAmount(spec, quantity),
  };
}

/** A quantity's amount under a price's tiers and free units, before its minimum and maximum. */
function tieredAmount(spec: PriceSpec, quantity: number): number {
  const units = Math.max(0, quantity - (spec.includedQuantity ?? 0));
  if (units === 0) return 0;
  switch (spec.model) {
    case 'per-unit':
      return roundMicros(units * (spec.unitAmountMicros ?? 0));
    case 'package':
      return roundMicros(
        Math.ceil(units / (spec.packageSize ?? 1)) * (spec.packageAmountMicros ?? 0),
      );
    case 'volume': {
      const tier =
        spec.tiers!.find((candidate) => candidate.upTo === null || units <= candidate.upTo) ??
        spec.tiers!.at(-1)!;
      return roundMicros(units * tier.unitAmountMicros + (tier.flatAmountMicros ?? 0));
    }
    case 'graduated': {
      let total = 0;
      let lower = 0;
      for (const tier of spec.tiers!) {
        const upper = tier.upTo ?? Number.POSITIVE_INFINITY;
        const inTier = Math.min(units, upper) - lower;
        if (inTier <= 0) break;
        total += inTier * tier.unitAmountMicros + (tier.flatAmountMicros ?? 0);
        lower = upper;
      }
      return roundMicros(total);
    }
  }
}

/** A price in currency units, as the API shows it. */
export function publicPriceSpec(spec: PriceSpec) {
  const units = (micros: number | undefined) =>
    micros === undefined ? undefined : micros / microsPerUnit;
  return {
    model: spec.model,
    ...(spec.unitAmountMicros !== undefined ? { unitAmount: units(spec.unitAmountMicros) } : {}),
    ...(spec.tiers
      ? {
          tiers: spec.tiers.map((tier) => ({
            upTo: tier.upTo,
            unitAmount: units(tier.unitAmountMicros)!,
            ...(tier.flatAmountMicros !== undefined
              ? { flatAmount: units(tier.flatAmountMicros) }
              : {}),
          })),
        }
      : {}),
    ...(spec.packageSize !== undefined ? { packageSize: spec.packageSize } : {}),
    ...(spec.packageAmountMicros !== undefined
      ? { packageAmount: units(spec.packageAmountMicros) }
      : {}),
    ...(spec.includedQuantity !== undefined ? { includedQuantity: spec.includedQuantity } : {}),
    ...(spec.minimumAmountMicros !== undefined
      ? { minimumAmount: units(spec.minimumAmountMicros) }
      : {}),
    ...(spec.maximumAmountMicros !== undefined
      ? { maximumAmount: units(spec.maximumAmountMicros) }
      : {}),
  };
}

/** The meter a key names for a tenant: the one its ancestor nearest the root defines. */
export async function resolveMeter(
  tx: IamStore,
  chain: Tenant[],
  key: string,
): Promise<BillingMeter | undefined> {
  for (const realm of [...chain].reverse()) {
    const found = (
      await tx.find<BillingMeter>(billingCollections.meters, { tenantId: realm.id, uniqueKey: key })
    )[0];
    if (found) return found;
  }
  return undefined;
}

/** Every meter that reaches a tenant, keyed by key (ancestors nearest the root win a shared key). */
export async function metersFor(tx: IamStore, chain: Tenant[]): Promise<Map<string, BillingMeter>> {
  const meters = new Map<string, BillingMeter>();
  for (const realm of [...chain].reverse())
    for (const meter of await tx.find<BillingMeter>(billingCollections.meters, {
      tenantId: realm.id,
    }))
      if (!meters.has(meter.key)) meters.set(meter.key, meter);
  return meters;
}

/**
 * The price of a meter for a tenant in a period: walking from `chain[0]` up to the meter's defining tenant, the first
 * tenant with an entry effective by then (the latest such entry).
 */
export async function priceFor(
  tx: IamStore,
  meter: BillingMeter,
  chain: Tenant[],
  period: string,
): Promise<BillingPrice | undefined> {
  for (const realm of chain) {
    const entries = (
      await tx.find<BillingPrice>(billingCollections.prices, {
        tenantId: realm.id,
        meterId: meter.id,
      })
    )
      .filter((entry) => entry.effectiveFrom <= period)
      .sort((a, b) => (a.effectiveFrom < b.effectiveFrom ? 1 : -1));
    if (entries[0]) return entries[0];
    if (realm.id === meter.tenantId) break;
  }
  return undefined;
}

// ---------------------------------------------------------------------------------------------------------------
// Usage

/** One usage event (kept `usageRetentionDays` after its period ends). */
export interface BillingUsageRecord extends StoredRecord {
  meterId: string;
  meter: string;
  quantity: number;
  /** Reported meters: the event's cost in micros. */
  costMicros?: number;
  identityId?: string;
  agentId?: string;
  /** The person's direct teams when the usage was recorded (or the team the caller named). */
  teamIds: string[];
  departmentId?: string;
  tags?: Record<string, string>;
  occurredAt: number;
  period: string;
  day: string;
  recordedAt: number;
  /** The identity that recorded it, or `deployment` for trusted server code. */
  recordedBy: string;
  sourceId?: string;
  rollupId: string;
  expiresAt: number;
}

/** A daily bucket of usage with the same meter and attribution; spend is computed from these. */
export interface BillingRollup extends StoredRecord {
  period: string;
  day: string;
  meterId: string;
  meter: string;
  identityId?: string;
  agentId?: string;
  teamIds: string[];
  departmentId?: string;
  tags?: Record<string, string>;
  quantity: number;
  costMicros: number;
  events: number;
  updatedAt: number;
}

/** What `record` needs: where, what and how much, and who to attribute it to. */
export interface UsageInput {
  tenantId: string;
  meter: string;
  /** Default 1. */
  quantity?: number;
  /** Reported meters only: the event's cost in currency units. */
  cost?: number;
  /** The person, service account or agent that used it (an identity of the tenant or an ancestor). */
  identityId?: string;
  /** Attribute to this team instead of the person's own teams. */
  teamId?: string;
  /** Up to 10 labels (`project`, `environment`, `feature`) reports can group by. */
  tags?: Record<string, string>;
  /** When it happened (default now); at most five minutes ahead, and never in a period already invoiced. */
  occurredAt?: number;
  /** Makes retries safe: a repeated key returns the first receipt and records nothing. */
  idempotencyKey?: string;
}

export interface UsageReceipt {
  id: string;
  tenantId: string;
  meter: string;
  quantity: number;
  costMicros?: number;
  period: string;
  occurredAt: number;
  identityId?: string;
  teamIds: string[];
  departmentId?: string;
  /** True when the idempotency key had already been used. */
  duplicate: boolean;
}

const tagKeyPattern = /^[A-Za-z][A-Za-z0-9_.:-]{0,63}$/;
/** Validated tags: at most 10, keys like `project` or `env.name`, values up to 128 characters. */
export function usageTags(value: unknown): Record<string, string> | undefined {
  if (value === undefined) return undefined;
  const input = object(value);
  const entries = Object.entries(input);
  if (entries.length > 10) throw new IamError('INVALID_INPUT', 'tags may hold at most 10 entries');
  if (!entries.length) return undefined;
  const tags: Record<string, string> = {};
  for (const [key, raw] of entries.sort(([a], [b]) => (a < b ? -1 : 1))) {
    if (!tagKeyPattern.test(key)) throw new IamError('INVALID_INPUT', `Invalid tag name ${key}`);
    tags[key] = text(raw, `tags.${key}`, 128);
  }
  return tags;
}

const digest = (value: string) => createHash('sha256').update(value).digest('base64url');

/** Deterministic id of the daily bucket for a usage attribution. */
export function rollupId(
  tenantId: string,
  day: string,
  meterId: string,
  attribution: Pick<BillingRollup, 'identityId' | 'agentId' | 'teamIds' | 'departmentId' | 'tags'>,
): string {
  return `r_${digest(
    JSON.stringify([
      tenantId,
      day,
      meterId,
      attribution.identityId ?? null,
      attribution.agentId ?? null,
      attribution.teamIds,
      attribution.departmentId ?? null,
      attribution.tags ?? null,
    ]),
  ).slice(0, 32)}`;
}

/** Who usage is attributed to: the identity, the agent behind it, their teams and department. */
export interface Attribution {
  identityId?: string;
  agentId?: string;
  teamIds: string[];
  departmentId?: string;
}

/**
 * Resolves attribution for an identity recording or causing usage in `tenant`. The identity must belong to the tenant
 * or one of its ancestors and not be deleted. An agent's usage is attributed to the agent and to its sponsor's teams
 * and department; `teamId` (a team of the identity's tenant) replaces the person's own teams.
 */
export async function attributionFor(
  ctx: ServerContext,
  tx: IamStore,
  chain: Tenant[],
  input: { identityId?: string; agentId?: string; teamId?: string },
  settings: BillingSettings,
): Promise<Attribution> {
  const result: Attribution = { teamIds: [] };
  if (input.identityId === undefined) {
    if (input.teamId !== undefined) result.teamIds = [await teamIn(tx, chain, input.teamId)];
    return result;
  }
  const identity = await tx.get<Identity>('identities', text(input.identityId, 'identityId'));
  if (
    !identity ||
    identity.status === 'deleted' ||
    !chain.some((realm) => realm.id === identity.tenantId)
  )
    throw new IamError('NOT_FOUND', 'Identity not found', 404);
  result.identityId = identity.id;
  if (input.agentId !== undefined) result.agentId = text(input.agentId, 'agentId');
  else if (identity.kind === 'agent') result.agentId = identity.id;
  // Agents count toward the person answerable for them.
  const person =
    identity.kind === 'agent' && identity.agent?.sponsorId ? identity.agent.sponsorId : identity.id;
  const at = ctx.now();
  if (input.teamId !== undefined) result.teamIds = [await teamIn(tx, chain, input.teamId)];
  else {
    const teams = await teamsOf(tx, identity.tenantId, person, { at });
    result.teamIds = settings.teamAttribution === 'primary' ? teams.slice(0, 1) : teams;
  }
  let departmentId = await departmentOf(tx, identity.tenantId, person);
  if (!departmentId && result.teamIds[0]) {
    const team = await tx.get<Team>(teamCollections.teams, result.teamIds[0]);
    departmentId = team?.departmentId;
  }
  if (departmentId) result.departmentId = departmentId;
  return result;
}

async function teamIn(tx: IamStore, chain: Tenant[], teamId: unknown): Promise<string> {
  const team = await tx.get<Team>(teamCollections.teams, text(teamId, 'teamId'));
  if (!team || !chain.some((realm) => realm.id === team.tenantId))
    throw new IamError('NOT_FOUND', 'Team not found', 404);
  return team.id;
}

// ---------------------------------------------------------------------------------------------------------------
// Billing accounts and profiles

/**
 * Who pays: a tenant with a billing profile is a billing account for its subtree (down to tenants with their own
 * profile). Organizations directly below the root are accounts even without a profile.
 */
export interface BillingProfile extends StoredRecord, BillingProfileFields {}

/** A billing profile's details (`billing.getProfile`). */
export interface BillingProfileFields {
  companyName?: string;
  /** Statements and spend alerts go here (in addition to owners when empty). */
  billingEmails: string[];
  taxId?: string;
  address?: string;
  purchaseOrder?: string;
  /** Printed on statements; defaults to nothing. */
  costCenter?: string;
  /** Days after issue a statement is due (overrides `billing.paymentTermsDays`). */
  paymentTermsDays?: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

export async function profileOf(
  tx: IamStore,
  tenantId: string,
): Promise<BillingProfile | undefined> {
  return (
    await tx.find<BillingProfile>(billingCollections.profiles, { tenantId, uniqueKey: 'profile' })
  )[0];
}

/** The billing account of a tenant: the nearest tenant (itself or above) with a profile, else its organization. */
export async function accountOf(ctx: ServerContext, tx: IamStore, tenant: Tenant): Promise<Tenant> {
  const chain = await ctx.ancestry(tx, tenant);
  for (const realm of chain.slice(0, -1)) if (await profileOf(tx, realm.id)) return realm;
  // The organization directly below the root (the root pays for itself).
  return chain.length > 1 ? chain.at(-2)! : chain[0]!;
}

async function children(tx: IamStore, parentId: string): Promise<Tenant[]> {
  return (await tx.find<Tenant>('tenants', { parentId })).sort((a, b) => (a.id < b.id ? -1 : 1));
}

/** A tenant and every tenant below it. */
export async function subtree(ctx: ServerContext, tx: IamStore, tenant: Tenant): Promise<Tenant[]> {
  const result: Tenant[] = [];
  const seen = new Set<string>();
  const queue = [tenant];
  while (queue.length && result.length < 100_000) {
    const next = queue.shift()!;
    if (seen.has(next.id)) continue;
    seen.add(next.id);
    result.push(next);
    queue.push(...(await children(tx, next.id)));
  }
  return result;
}

/** The tenants an account pays for: its subtree, minus subtrees of tenants that have a profile of their own. */
export async function accountTenants(
  tx: IamStore,
  account: Tenant,
  isRoot: boolean,
): Promise<Tenant[]> {
  const result: Tenant[] = [];
  const seen = new Set<string>();
  const queue = [account];
  while (queue.length && result.length < 100_000) {
    const next = queue.shift()!;
    if (seen.has(next.id)) continue;
    seen.add(next.id);
    result.push(next);
    for (const child of await children(tx, next.id)) {
      // Below the root every organization is an account of its own.
      if (isRoot && next.id === account.id) continue;
      if (await profileOf(tx, child.id)) continue;
      queue.push(child);
    }
  }
  return result;
}

// ---------------------------------------------------------------------------------------------------------------
// Spend

/** Usage with its share of cost: a daily roll-up after pricing. */
export interface ChargedRow {
  tenantId: string;
  period: string;
  day: string;
  meterId: string;
  meter: string;
  identityId?: string;
  agentId?: string;
  teamIds: string[];
  departmentId?: string;
  tags?: Record<string, string>;
  quantity: number;
  costMicros: number;
  events: number;
  /** Chargeback only: the meter is defined inside the billing account (never on a statement). */
  internal: boolean;
}

/**
 * A meter's charge for an account and period. A meter used both while a subscription's plan priced it and outside that
 * time has one charge per price (the plan's, the rate card's).
 */
export interface MeterCharge {
  meterId: string;
  meter: string;
  name: string;
  unit: string;
  /** The tenant that defines the meter. */
  definedBy: string;
  internal: boolean;
  aggregation: BillingMeter['aggregation'];
  pricing: BillingMeter['pricing'];
  /** Summed quantity, or distinct people and agents for `unique` meters. */
  quantity: number;
  amountMicros: number;
  price?: {
    effectiveFrom: string;
    setOn: string;
    spec: PriceSpec;
    /** `plan` when a subscription's plan prices the meter for the account. */
    source?: 'rate-card' | 'plan';
    planKey?: string;
  };
  /** A rate-card meter without a price for the account: its usage costs nothing. */
  unpriced?: true;
}

/** A plan's price for a meter over the local days (`YYYY-MM-DD`, inclusive) a subscription to it was live on. */
export interface PlanPriceWindow {
  spec: PriceSpec;
  planKey: string;
  from: string;
  to: string;
}

/**
 * The prices an account's subscriptions give a meter in a period, oldest subscription first: for each subscription whose
 * plan has a usage item for the meter, the days of the period it was live on. A day's usage takes the first window
 * that covers it; usage on days no subscription covers (before it started, after it ended) keeps rate-card prices.
 */
export async function planPricesFor(
  ctx: ServerContext,
  tx: IamStore,
  accountId: string,
  meter: string,
  period: string,
): Promise<PlanPriceWindow[]> {
  const subscriptions = await tx.find<BillingSubscription>(billingCollections.subscriptions, {
    tenantId: accountId,
  });
  if (!subscriptions.length) return [];
  const timeZone = ctx.options.billing?.timeZone ?? 'UTC';
  const bounds = periodBounds(period, timeZone);
  const windows: PlanPriceWindow[] = [];
  for (const subscription of subscriptions.sort(
    (a, b) => a.startedAt - b.startedAt || (a.id < b.id ? -1 : 1),
  )) {
    const from = Math.max(bounds.start, subscription.startedAt);
    const to = Math.min(bounds.end, subscription.endsAt ?? Number.POSITIVE_INFINITY);
    if (to <= from) continue;
    const plan = await tx.get<BillingPlan>(billingCollections.plans, subscription.planId);
    const item = plan?.items.find(
      (candidate) => candidate.kind === 'usage' && candidate.meter === meter,
    );
    if (item?.price)
      windows.push({
        spec: item.price,
        planKey: plan!.key,
        from: dayOf(from, timeZone),
        to: dayOf(to - 1, timeZone),
      });
  }
  return windows;
}

export interface AccountSpend {
  accountId: string;
  period: string;
  charges: MeterCharge[];
  rows: ChargedRow[];
  /** Everything, chargeback meters included. */
  totalMicros: number;
  /** What a statement would bill: meters defined above the account. */
  billableMicros: number;
}

/** Caches account computations within one call (spend for several periods, budgets sharing accounts). */
export type SpendCache = Map<string, Promise<AccountSpend>>;

/** Prices every meter used in an account's tenants during a period and allocates the cost to the usage. */
export async function accountSpend(
  ctx: ServerContext,
  tx: IamStore,
  account: Tenant,
  period: string,
  cache?: SpendCache,
): Promise<AccountSpend> {
  const key = `${account.id}:${period}`;
  const cached = cache?.get(key);
  if (cached) return cached;
  const computing = computeAccountSpend(ctx, tx, account, period);
  cache?.set(key, computing);
  return computing;
}

async function computeAccountSpend(
  ctx: ServerContext,
  tx: IamStore,
  account: Tenant,
  period: string,
): Promise<AccountSpend> {
  const accountChain = await ctx.ancestry(tx, account);
  const tenants = await accountTenants(tx, account, account.parentId === null);
  const byMeter = new Map<string, BillingRollup[]>();
  for (const realm of tenants)
    for (const rollup of await tx.find<BillingRollup>(billingCollections.rollups, {
      tenantId: realm.id,
      period,
    }))
      byMeter.set(rollup.meterId, [...(byMeter.get(rollup.meterId) ?? []), rollup]);
  const charges: MeterCharge[] = [];
  const rows: ChargedRow[] = [];
  for (const [meterId, rollups] of [...byMeter].sort(([a], [b]) => (a < b ? -1 : 1))) {
    const meter = await tx.get<BillingMeter>(billingCollections.meters, meterId);
    const first = rollups[0]!;
    const definedAbove = accountChain.slice(1).some((realm) => realm.id === meter?.tenantId);
    const internal = !definedAbove && account.parentId !== null;
    const charge: MeterCharge = {
      meterId,
      meter: meter?.key ?? first.meter,
      name: meter?.name ?? first.meter,
      unit: meter?.unit ?? 'unit',
      definedBy: meter?.tenantId ?? '',
      internal,
      aggregation: meter?.aggregation ?? 'sum',
      pricing: meter?.pricing ?? 'reported',
      quantity: 0,
      amountMicros: 0,
    };
    const charged = rollups.map(
      (rollup): ChargedRow => ({
        tenantId: rollup.tenantId,
        period,
        day: rollup.day,
        meterId,
        meter: charge.meter,
        ...(rollup.identityId !== undefined ? { identityId: rollup.identityId } : {}),
        ...(rollup.agentId !== undefined ? { agentId: rollup.agentId } : {}),
        teamIds: rollup.teamIds ?? [],
        ...(rollup.departmentId !== undefined ? { departmentId: rollup.departmentId } : {}),
        ...(rollup.tags !== undefined ? { tags: rollup.tags } : {}),
        quantity: rollup.quantity,
        costMicros: 0,
        events: rollup.events,
        internal,
      }),
    );
    const principalOf = (row: ChargedRow) => row.agentId ?? row.identityId;
    const quantityOf = (list: ChargedRow[]) =>
      charge.aggregation === 'unique'
        ? new Set(list.map(principalOf).filter(Boolean)).size
        : list.reduce((sum, row) => sum + row.quantity, 0);
    if (charge.pricing === 'reported' || !meter) {
      charge.quantity = quantityOf(charged);
      charged.forEach((row, index) => (row.costMicros = roundMicros(rollups[index]!.costMicros)));
      charge.amountMicros = roundMicros(charged.reduce((sum, row) => sum + row.costMicros, 0));
      charges.push(charge);
    } else {
      // Tiers apply to the account's period total; the meter's own tenant prices meters defined inside the account.
      const priceChain = definedAbove
        ? accountChain
        : await ctx.ancestry(tx, (await tx.get<Tenant>('tenants', meter.tenantId)) ?? account);
      // A subscription's plan price replaces the rate card for platform meters, for the days it was live only.
      const windows = definedAbove
        ? await planPricesFor(ctx, tx, account.id, meter.key, period)
        : [];
      // Each row's price: the first plan window covering its day, or the rate card (-1). A `unique` meter counts a
      // person once, at the price of the first window they have usage in.
      const groupOf = charged.map((row) =>
        windows.findIndex((window) => row.day >= window.from && row.day <= window.to),
      );
      if (charge.aggregation === 'unique') {
        const earliest = new Map<string, number>();
        charged.forEach((row, index) => {
          const principal = principalOf(row);
          const group = groupOf[index]!;
          const known = principal === undefined ? undefined : earliest.get(principal);
          if (principal && group >= 0 && (known === undefined || group < known))
            earliest.set(principal, group);
        });
        charged.forEach((row, index) => {
          const principal = principalOf(row);
          if (principal) groupOf[index] = earliest.get(principal) ?? -1;
        });
      }
      for (const group of [...new Set(groupOf)].sort((a, b) => a - b)) {
        const list = charged.filter((_, index) => groupOf[index] === group);
        const part: MeterCharge = { ...charge, quantity: quantityOf(list) };
        const planned = windows[group];
        const price = planned ? undefined : await priceFor(tx, meter, priceChain, period);
        if (planned) {
          part.price = {
            effectiveFrom: period,
            setOn: account.id,
            spec: planned.spec,
            source: 'plan',
            planKey: planned.planKey,
          };
          part.amountMicros = priceQuantity(planned.spec, part.quantity);
        } else if (!price) part.unpriced = true;
        else {
          part.price = {
            effectiveFrom: price.effectiveFrom,
            setOn: price.tenantId,
            spec: price.spec,
            source: 'rate-card',
          };
          part.amountMicros = priceQuantity(price.spec, part.quantity);
        }
        if (part.amountMicros > 0 && part.quantity > 0) {
          if (part.aggregation === 'unique') {
            // Each person or agent costs the same; their share is spread over their rows by quantity.
            const each = part.amountMicros / part.quantity;
            const perPrincipal = new Map<string, ChargedRow[]>();
            for (const row of list) {
              const principal = principalOf(row);
              if (principal)
                perPrincipal.set(principal, [...(perPrincipal.get(principal) ?? []), row]);
            }
            for (const rowsOf of perPrincipal.values()) {
              const total = rowsOf.reduce((sum, row) => sum + row.quantity, 0);
              for (const row of rowsOf)
                row.costMicros = roundMicros(
                  total > 0 ? (each * row.quantity) / total : each / rowsOf.length,
                );
            }
          } else
            for (const row of list)
              row.costMicros = roundMicros((part.amountMicros * row.quantity) / part.quantity);
        }
        charges.push(part);
      }
    }
    rows.push(...charged);
  }
  charges.sort((a, b) => b.amountMicros - a.amountMicros || (a.meter < b.meter ? -1 : 1));
  const totalMicros = roundMicros(charges.reduce((sum, charge) => sum + charge.amountMicros, 0));
  const billableMicros = roundMicros(
    charges
      .filter((charge) => !charge.internal)
      .reduce((sum, charge) => sum + charge.amountMicros, 0),
  );
  return { accountId: account.id, period, charges, rows, totalMicros, billableMicros };
}

/**
 * Spend of a tenant's subtree in a period: the charged usage of every tenant below (and including) it, priced within
 * the billing account each tenant belongs to. For the root this is the whole platform.
 */
export async function scopeSpend(
  ctx: ServerContext,
  tx: IamStore,
  scope: Tenant,
  period: string,
  cache?: SpendCache,
): Promise<{ rows: ChargedRow[]; accounts: AccountSpend[] }> {
  const tenants = await subtree(ctx, tx, scope);
  const inScope = new Set(tenants.map((realm) => realm.id));
  const rootId = (await ctx.ancestry(tx, scope)).at(-1)!.id;
  const accountIds = new Map<string, Tenant>();
  const top = await accountOf(ctx, tx, scope);
  accountIds.set(top.id, top);
  // Organizations directly below the root, and tenants with a profile, are accounts of their own.
  for (const realm of tenants.slice(1))
    if (realm.parentId === rootId || (await profileOf(tx, realm.id)))
      accountIds.set(realm.id, realm);
  const accounts: AccountSpend[] = [];
  const rows: ChargedRow[] = [];
  for (const account of accountIds.values()) {
    const spend = await accountSpend(ctx, tx, account, period, cache);
    accounts.push(spend);
    for (const row of spend.rows) if (inScope.has(row.tenantId)) rows.push(row);
  }
  return { rows, accounts };
}

/** Totals of charged rows (cost and per-meter quantity). */
export function sumRows(rows: ChargedRow[]): { costMicros: number; events: number } {
  return {
    costMicros: roundMicros(rows.reduce((sum, row) => sum + row.costMicros, 0)),
    events: rows.reduce((sum, row) => sum + row.events, 0),
  };
}

/** Team and department trees of the tenants in scope, for roll-ups and labels. */
export interface Directory {
  teams: Map<string, Team>;
  departments: Map<string, Department>;
}

export async function directoryFor(tx: IamStore, tenantIds: Iterable<string>): Promise<Directory> {
  const teams = new Map<string, Team>();
  const departments = new Map<string, Department>();
  for (const tenantId of new Set(tenantIds)) {
    for (const team of await tx.find<Team>(teamCollections.teams, { tenantId }))
      teams.set(team.id, team);
    for (const [id, department] of await tenantDepartments(tx, tenantId))
      departments.set(id, department);
  }
  return { teams, departments };
}

/** The share of a row's cost that counts toward `teamId` (and the teams above it when `rollUp`). */
export function teamShare(
  row: ChargedRow,
  teamId: string,
  directory: Directory,
  settings: BillingSettings,
  rollUp: boolean,
): number {
  if (!row.teamIds.length) return 0;
  const matching = row.teamIds.filter((id) =>
    rollUp ? teamChain(directory.teams, id).some((team) => team.id === teamId) : id === teamId,
  ).length;
  if (!matching) return 0;
  return settings.teamAttribution === 'full' ? 1 : matching / row.teamIds.length;
}

/** Whether a row's department is `departmentId` or (with `rollUp`) a department below it. */
export function inDepartment(
  row: ChargedRow,
  departmentId: string,
  directory: Directory,
  rollUp: boolean,
): boolean {
  if (!row.departmentId) return false;
  if (!rollUp) return row.departmentId === departmentId;
  return departmentChain(directory.departments, row.departmentId).some(
    (department) => department.id === departmentId,
  );
}

// ---------------------------------------------------------------------------------------------------------------
// Budgets, credits, statements

export type BudgetSubjectType = 'tenant' | 'team' | 'department' | 'identity';

/** A spend budget: an amount per month, quarter or year for a tenant subtree, a team, a department or a person. */
export interface BillingBudget extends StoredRecord {
  name: string;
  subjectType: BudgetSubjectType;
  /** The tenant (in the budget's subtree), team, department or identity. */
  subjectId: string;
  amountMicros: number;
  period: BudgetPeriodKind;
  /** Only these meter keys count (all when absent). */
  meters?: string[];
  /** Percentages of the amount that trigger an alert, once per window each (default 50, 80, 100). */
  thresholds: number[];
  /** Also alert when the linear month-end (or quarter-end, year-end) projection passes 100%. */
  forecastAlerts: boolean;
  /** Who is told: the tenant's owners, the subject (the person, team maintainers, department heads), extra emails. */
  notify: { owners: boolean; subject: boolean; emails: string[] };
  /** Refuse usage covered by the budget once it is spent (`record` with `enforceBudgets`, `billing.check`). */
  enforce: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

/** Marks a threshold as alerted in a budget window (uniqueKey `{budgetId}:{windowStart}:{kind}:{threshold}`). */
export interface BillingBudgetAlert extends StoredRecord {
  /** Empty for anomaly markers (uniqueKey `anomaly:{dimension}:{key}:{day}`). */
  budgetId: string;
  window: string;
  kind: 'actual' | 'forecast' | 'anomaly';
  threshold: number;
  spentMicros: number;
  alertedAt: number;
}

/** Prepaid or promotional credit a billing account's statements draw on (earliest expiry first). */
export interface BillingCredit extends StoredRecord {
  amountMicros: number;
  remainingMicros: number;
  reason: string;
  expiresAt?: number;
  grantedAt: number;
  grantedBy: string;
  revokedAt?: number;
}

/** How much of a tier a quantity used, as an invoice sub-line. */
export interface TierLine {
  /** First and last unit of the tier (`to` null: no upper bound). */
  from: number;
  to: number | null;
  quantity: number;
  unitAmountMicros: number;
  flatAmountMicros?: number;
  amountMicros: number;
}

/**
 * One invoice line. Usage lines (`kind` absent or `usage`) name a meter; `fee` and `seat` lines come from subscriptions
 * (with the service period they cover and the share of it billed); `item` lines are one-off invoice items.
 */
export interface StatementLine {
  kind?: 'usage' | 'fee' | 'seat' | 'item';
  /** Usage lines: the meter key. */
  meter?: string;
  name: string;
  unit: string;
  quantity: number;
  /** Price of one unit, for fee, seat and item lines and single-tier usage. */
  unitAmountMicros?: number;
  amountMicros: number;
  /** Usage lines: how the meter is priced. */
  pricing?: BillingMeter['pricing'];
  price?: { model: PriceModel; effectiveFrom: string; source?: 'rate-card' | 'plan' };
  unpriced?: true;
  /** Tiers the quantity used (graduated and volume prices). */
  tiers?: TierLine[];
  /** Free units taken off before pricing. */
  includedQuantity?: number;
  /** The price's minimum or maximum changed the amount; this is what the tiers came to. */
  adjustedFromMicros?: number;
  /** Fee and seat lines: the time they pay for. */
  servicePeriod?: { start: number; end: number };
  /** Share of the service period billed (0-1) when a subscription started, ended or changed within it. */
  proration?: number;
  subscriptionId?: string;
  planItemId?: string;
  invoiceItemId?: string;
  description?: string;
}

export interface StatementAllocation {
  id: string;
  name: string;
  costMicros: number;
}

/** What a statement bills: its period, lines, credits, totals, breakdown and bill-to details. */
export interface StatementBody {
  period: string;
  currency: string;
  periodStart: number;
  periodEnd: number;
  lines: StatementLine[];
  /** Why the invoice exists: the monthly close (default), a new subscription's first period, or an invoice made by hand. */
  billingReason?: 'period' | 'subscription' | 'manual';
  /** The sum of the lines. */
  subtotalMicros: number;
  /** Coupon discounts (`billing.redeemCoupon`), after the contract discount. */
  coupons?: { discountId: string; code: string; name: string; amountMicros: number }[];
  /** The account's negotiated discount on usage (`billing.setTerms`). */
  discount?: { percent: number; amountMicros: number };
  /** What the month fell short of the account's minimum monthly commitment, billed on top. */
  commitment?: { minimumMicros: number; trueUpMicros: number };
  creditsMicros: number;
  creditsApplied: { creditId: string; amountMicros: number }[];
  /** Tax on the amount due after discount, commitment and credit. */
  tax?: { label: string; ratePercent: number; amountMicros: number };
  totalMicros: number;
  /** Where the billable spend came from (largest first; teams, departments and people capped at 50). */
  breakdown: {
    tenants: StatementAllocation[];
    teams: StatementAllocation[];
    departments: (StatementAllocation & { costCenter?: string })[];
    identities: StatementAllocation[];
  };
  billTo: {
    name: string;
    companyName?: string;
    taxId?: string;
    address?: string;
    purchaseOrder?: string;
    costCenter?: string;
    emails: string[];
  };
}

/**
 * An invoice's state: a `draft` can still change and has no number; `finalized` is issued and open for payment; `paid`
 * when payments and credit notes cover it; `void` cancelled; `uncollectible` written off (a later payment still settles it).
 */
export type InvoiceStatus = 'draft' | 'finalized' | 'paid' | 'void' | 'uncollectible';

/** A payment received against an invoice (`billing.recordPayment`). */
export interface InvoicePayment {
  id: string;
  amountMicros: number;
  /** How it was paid: `card`, `bank_transfer`, `check`, `manual`, ... (free text, 32 characters). */
  method: string;
  reference?: string;
  receivedAt: number;
  recordedBy: string;
  /** What the payment exceeded the amount due by, kept as account credit (`creditId`). */
  overpaymentMicros?: number;
  creditId?: string;
}

/**
 * An invoice for a billing account (called a statement in earlier releases): the monthly one has uniqueKey
 * `period:{period}` until voided; a new subscription's first invoice `subscription:{id}`.
 */
export interface BillingStatement extends StoredRecord, StatementBody {
  /** Empty while a draft; assigned when the invoice is finalized. */
  number: string;
  status: InvoiceStatus;
  /** When the invoice was finalized (or, for a draft, drawn up). */
  issuedAt: number;
  dueAt: number;
  /** SHA-256 of the invoice's content (lines, totals, bill-to), for tamper evidence; empty while a draft. */
  hash: string;
  /** Payments received; the sum is `amountPaidMicros`. */
  payments?: InvoicePayment[];
  amountPaidMicros?: number;
  /** Credit notes issued against the invoice (`billing.createCreditNote`). */
  creditNotesMicros?: number;
  /** Pending invoice items the invoice will bill (drafts) or billed (finalized). */
  invoiceItemIds?: string[];
  /** Subscription months the invoice bills in advance (released again if it is voided). */
  advanceBilled?: { subscriptionId: string; period: string }[];
  /** Account credit created from a negative balance (credit items larger than the charges). */
  carryForward?: { creditId: string; amountMicros: number };
  /** Payment reminders sent, by day relative to the due date (`billing.paymentReminderDays`). */
  reminders?: { days: number; at: number; recipients: number }[];
  paidAt?: number;
  paidBy?: string;
  paymentReference?: string;
  voidedAt?: number;
  voidedBy?: string;
  voidReason?: string;
  markedUncollectibleAt?: number;
}

/** What is still owed on an invoice: its total less payments and credit notes (never below 0). */
export function amountDue(statement: BillingStatement): number {
  if (statement.status === 'void' || statement.status === 'draft')
    return statement.status === 'draft' ? statement.totalMicros : 0;
  return roundMicros(
    Math.max(0, statement.totalMicros - amountPaid(statement) - (statement.creditNotesMicros ?? 0)),
  );
}

/** Payments received on an invoice; invoices marked paid before payments were recorded count as fully paid. */
export function amountPaid(statement: BillingStatement): number {
  if (statement.amountPaidMicros !== undefined) return statement.amountPaidMicros;
  return statement.status === 'paid' ? statement.totalMicros : 0;
}

/**
 * A one-off charge (or, with a negative amount, a credit) for a billing account's next invoice, like Stripe's pending
 * invoice items: `pending` until an invoice for its period (or the next one) is finalized, then `invoiced`.
 */
export interface BillingInvoiceItem extends StoredRecord {
  description: string;
  quantity: number;
  unitAmountMicros: number;
  amountMicros: number;
  /** Bill it on the invoice for this month (default: the next invoice). */
  period?: string;
  status: 'pending' | 'invoiced';
  statementId?: string;
  /** `proration` items come from subscription changes. */
  source: 'manual' | 'proration';
  subscriptionId?: string;
  metadata?: Record<string, string>;
  createdAt: number;
  createdBy: string;
}

export type CreditNoteReason =
  | 'duplicate'
  | 'fraudulent'
  | 'order_change'
  | 'product_unsatisfactory'
  | 'other';

/**
 * A credit note reduces what a finalized invoice asks for, like Stripe's: first the amount still due; anything beyond
 * (a paid part) becomes account credit or is recorded as refunded.
 */
export interface BillingCreditNote extends StoredRecord {
  number: string;
  statementId: string;
  statementNumber: string;
  amountMicros: number;
  reason: CreditNoteReason;
  memo?: string;
  /** How the amount was used: against the amount due, as account credit, or refunded outside Better IAM. */
  applied: { dueMicros: number; creditMicros: number; refundMicros: number };
  /** The account credit created for `applied.creditMicros`. */
  creditId?: string;
  issuedAt: number;
  issuedBy: string;
}

/** One item of a plan: a recurring fee, a per-seat fee, or the plan's price for a meter. */
export interface PlanItem {
  /** Stable within the plan (1-64 lowercase letters, digits, `-`, `_`). */
  id: string;
  kind: 'fee' | 'seat' | 'usage';
  name: string;
  /** `fee`: the monthly amount. */
  amountMicros?: number;
  /** `seat`: the monthly amount per seat. */
  unitAmountMicros?: number;
  /** `seat`: seats included in the plan before any is charged. */
  includedSeats?: number;
  /** `fee` and `seat`: charged at the start of each month for that month (default) or at its end. */
  billing?: 'advance' | 'arrears';
  /** `usage`: the meter key and the price subscribers pay for it instead of the rate card. */
  meter?: string;
  price?: PriceSpec;
}

/**
 * A plan subscribers pay monthly, like Stripe products with prices or Orb plans: fixed fees, seats, and prices for
 * meters. Defined by a tenant (the platform for organizations) for accounts below it (uniqueKey = key).
 */
export interface BillingPlan extends StoredRecord {
  key: string;
  name: string;
  description?: string;
  items: PlanItem[];
  /** Days a new subscription is free of fee and seat charges. */
  trialDays?: number;
  /** Billing managers of an account may subscribe and cancel it themselves. */
  selfServe: boolean;
  archived: boolean;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
  updatedBy: string;
}

/**
 * A billing account's subscription to a plan (uniqueKey `plan:{planId}` while it lasts). Seats change over time, so
 * `seatHistory` keeps every change for prorated charges.
 */
export interface BillingSubscription extends StoredRecord {
  planId: string;
  planKey: string;
  planName: string;
  startedAt: number;
  trialEndsAt?: number;
  /** Set when the subscription ends (at a period end for `cancelAtPeriodEnd`). */
  endsAt?: number;
  cancelAtPeriodEnd: boolean;
  canceledAt?: number;
  canceledBy?: string;
  seats: number;
  /** Seat counts from each change on, oldest first. */
  seatHistory: { at: number; seats: number }[];
  /** Advance-billed months already invoiced (`YYYY-MM`). */
  billedAdvance: string[];
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

/** A subscription's state at an instant. */
export function subscriptionStatus(
  subscription: BillingSubscription,
  now: number,
): 'trialing' | 'active' | 'ended' {
  if (subscription.endsAt !== undefined && subscription.endsAt <= now) return 'ended';
  if (subscription.trialEndsAt !== undefined && subscription.trialEndsAt > now) return 'trialing';
  return 'active';
}

/**
 * A promotion: a percentage or an amount off invoices, once, for some months, or for good, like Stripe coupons. The
 * platform defines coupons (uniqueKey `code:{CODE}`); accounts redeem them by code.
 */
export interface BillingCoupon extends StoredRecord {
  code: string;
  name: string;
  percentOff?: number;
  amountOffMicros?: number;
  duration: 'once' | 'repeating' | 'forever';
  /** `repeating`: how many monthly invoices it applies to. */
  durationInMonths?: number;
  maxRedemptions?: number;
  redemptions: number;
  /** Last moment it can be redeemed. */
  redeemBy?: number;
  active: boolean;
  createdAt: number;
  createdBy: string;
}

/** A coupon redeemed by a billing account (uniqueKey `coupon:{couponId}`), with how many invoices it has discounted. */
export interface BillingDiscount extends StoredRecord {
  couponId: string;
  code: string;
  name: string;
  percentOff?: number;
  amountOffMicros?: number;
  duration: BillingCoupon['duration'];
  durationInMonths?: number;
  /** Monthly invoices discounted so far. */
  appliedInvoices: number;
  redeemedAt: number;
  redeemedBy: string;
  /** No longer applies (used up or removed). */
  endedAt?: number;
}

/**
 * Whether a redeemed coupon discounts an invoice for `period`: `once` until one invoice used it, `repeating` for the
 * invoices of `durationInMonths` months from the month it was redeemed, `forever` until removed.
 */
export function discountActive(
  discount: BillingDiscount,
  period: string,
  timeZone: string,
): boolean {
  if (discount.endedAt !== undefined) return false;
  if (discount.duration === 'once') return discount.appliedInvoices === 0;
  if (discount.duration === 'repeating') {
    const from = periodOf(discount.redeemedAt, timeZone);
    return period >= from && period < shiftPeriod(from, discount.durationInMonths ?? 1);
  }
  return true;
}

/** The share (0-1, four decimals) of `[start, end)` that `[from, to)` covers. */
export function overlapShare(start: number, end: number, from: number, to: number): number {
  const length = end - start;
  if (length <= 0) return 0;
  const covered = Math.max(0, Math.min(end, to) - Math.max(start, from));
  return Math.round((covered / length) * 10_000) / 10_000;
}

/** Validates budget thresholds: 1-10 distinct percentages from 1 to 1000, ascending. */
export function budgetThresholds(value: unknown): number[] {
  if (value === undefined) return [50, 80, 100];
  if (!Array.isArray(value) || value.length === 0 || value.length > 10)
    throw new IamError('INVALID_INPUT', 'thresholds must list 1-10 percentages');
  // Forms send numbers as text ("50, 80, 100").
  const numeric = (item: unknown) =>
    typeof item === 'string' && /^\d{1,4}$/.test(item.trim()) ? Number(item.trim()) : item;
  return [...new Set(value.map((item) => integer(numeric(item), 'thresholds', 1, 1000)))].sort(
    (a, b) => a - b,
  );
}

/** Retention of a usage event recorded for `period`. */
export function usageExpiry(period: string, settings: BillingSettings): number {
  return periodBounds(period, settings.timeZone).end + settings.usageRetentionDays * 86_400_000;
}

/** Statement content hash: what it bills, to whom, under which number (payment status is left out). */
export function statementHash(
  statement: StatementBody & { number: string; tenantId: string },
): string {
  const { lines, subtotalMicros, creditsMicros, totalMicros, billTo, period, number, currency } =
    statement;
  return createHash('sha256')
    .update(
      JSON.stringify({
        number,
        period,
        currency,
        tenantId: statement.tenantId,
        lines,
        subtotalMicros,
        creditsMicros,
        totalMicros,
        billTo,
        // Contract terms (absent on statements without them, so earlier hashes still verify).
        discount: statement.discount,
        commitment: statement.commitment,
        tax: statement.tax,
        coupons: statement.coupons,
        billingReason: statement.billingReason,
      }),
    )
    .digest('hex');
}

/**
 * Commercial terms of a billing account, which only root administrators set (`billing.setTerms`): a discount on
 * usage, a minimum monthly commitment, and the tax statements add (uniqueKey `terms`).
 */
export interface BillingTerms extends StoredRecord {
  /** Percent off usage at rate-card prices, 0 to 100. */
  discountPercent?: number;
  /** Least a month is billed, in micros; a shortfall is billed as a true-up. */
  minimumCommitmentMicros?: number;
  /** Tax added to the amount due, 0 to 100 percent. */
  taxRatePercent?: number;
  /** How the tax line reads, such as `VAT` (default `Tax`). */
  taxLabel?: string;
  setAt: number;
  setBy: string;
}

/**
 * Turns an invoice's subtotal into its total, in order: the contract discount, the minimum-commitment true-up (monthly
 * invoices only), coupon discounts, credit, and tax on what is left. A negative balance (credit items larger than
 * the charges) comes back as `carryForwardMicros` for account credit, and the total stays 0.
 */
export function invoiceAmounts(input: {
  subtotalMicros: number;
  terms?: BillingTerms;
  /** Whether the minimum commitment applies (the monthly invoice). */
  commitment: boolean;
  discounts?: BillingDiscount[];
  credit: (dueMicros: number) => number;
}): Pick<
  StatementBody,
  'discount' | 'commitment' | 'coupons' | 'tax' | 'creditsMicros' | 'totalMicros'
> & {
  carryForwardMicros: number;
} {
  const { subtotalMicros, terms } = input;
  const contractMicros =
    terms?.discountPercent !== undefined && subtotalMicros > 0
      ? roundCents((subtotalMicros * terms.discountPercent) / 100)
      : 0;
  let net = roundMicros(subtotalMicros - contractMicros);
  const trueUpMicros =
    input.commitment && terms?.minimumCommitmentMicros !== undefined
      ? roundCents(Math.max(0, terms.minimumCommitmentMicros - net))
      : 0;
  net = roundMicros(net + trueUpMicros);
  const coupons: NonNullable<StatementBody['coupons']> = [];
  for (const discount of input.discounts ?? []) {
    if (net <= 0) break;
    const amount = roundCents(
      Math.min(
        net,
        discount.percentOff !== undefined
          ? (net * discount.percentOff) / 100
          : (discount.amountOffMicros ?? 0),
      ),
    );
    if (amount <= 0) continue;
    coupons.push({
      discountId: discount.id,
      code: discount.code,
      name: discount.name,
      amountMicros: amount,
    });
    net = roundMicros(net - amount);
  }
  const carryForwardMicros = net < 0 ? roundMicros(-net) : 0;
  const due = Math.max(0, net);
  const creditsMicros = due > 0 ? roundMicros(Math.min(due, input.credit(due))) : 0;
  const taxable = roundMicros(due - creditsMicros);
  const taxMicros =
    terms?.taxRatePercent !== undefined ? roundCents((taxable * terms.taxRatePercent) / 100) : 0;
  return {
    ...(terms?.discountPercent !== undefined
      ? { discount: { percent: terms.discountPercent, amountMicros: contractMicros } }
      : {}),
    ...(input.commitment && terms?.minimumCommitmentMicros !== undefined
      ? { commitment: { minimumMicros: terms.minimumCommitmentMicros, trueUpMicros } }
      : {}),
    ...(coupons.length ? { coupons } : {}),
    creditsMicros,
    ...(terms?.taxRatePercent !== undefined
      ? {
          tax: {
            label: terms.taxLabel ?? 'Tax',
            ratePercent: terms.taxRatePercent,
            amountMicros: taxMicros,
          },
        }
      : {}),
    totalMicros: roundMicros(taxable + taxMicros),
    carryForwardMicros,
  };
}
