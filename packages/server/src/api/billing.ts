import {
  IamError,
  type AuthenticatedPrincipal,
  type CredentialInput,
  type IamStore,
  type Identity,
  type Json,
  type Tenant,
} from '@better-iam/core';
import {
  accountOf,
  accountSpend,
  amountDue,
  amountMicros,
  amountPaid,
  billingCollections,
  discountActive,
  subscriptionStatus,
  billingPeriod,
  budgetThresholds,
  maxMetersPerTenant,
  meterKey,
  meterSettings,
  metersFor,
  priceFor,
  priceQuantity,
  priceSpec,
  profileOf,
  publicPriceSpec,
  resolveMeter,
  roundMicros,
  shiftPeriod,
  statementHash,
  subtree,
  termsOf,
  unitsOf,
  type BillingBudget,
  type BillingCoupon,
  type BillingCredit,
  type BillingCreditNote,
  type BillingDiscount,
  type BillingInvoiceItem,
  type BillingMeter,
  type BillingPlan,
  type BillingPrice,
  type BillingProfile,
  type BillingProfileFields,
  type BillingStatement,
  type BillingSubscription,
  type BillingTerms,
  type BillingUsageRecord,
  type BudgetPeriodKind,
  type BudgetSubjectType,
  type InvoicePayment,
  type PlanItem,
  type UsageInput,
  type UsageReceipt,
} from '../billing.js';
import {
  couponCode,
  couponSettings,
  invoiceItemInput,
  renderInvoiceHtml,
} from '../billing-invoices.js';
import { maxPlansPerTenant, planKey, planSettings } from '../billing-plans.js';
import {
  billingServiceOf,
  type AnomalyOptions,
  type BudgetStatus,
  type ClosePeriodResult,
  type SpendAnomaly,
  type SpendCheck,
  type SpendFilters,
  type SpendGroupBy,
  type SpendQuery,
  type SpendReport,
  type SpendTrend,
  type StatementDraft,
} from '../billing-service.js';
import type { ServerContext } from '../context.js';
import { departmentHeads, type Department } from '../departments.js';
import { OperationDenied } from '../operations.js';
import { isTeamMaintainer, type Team } from '../teams.js';
import { id } from '../utils.js';
import { email, integer, object, text } from '../validation.js';

const {
  meters: metersCollection,
  prices: pricesCollection,
  usage: usageCollection,
  rollups: rollupsCollection,
  budgets: budgetsCollection,
  budgetAlerts: alertsCollection,
  credits: creditsCollection,
  profiles: profilesCollection,
  statements: statementsCollection,
  terms: termsCollection,
  invoiceItems: invoiceItemsCollection,
  creditNotes: creditNotesCollection,
  plans: plansCollection,
  subscriptions: subscriptionsCollection,
  coupons: couponsCollection,
  discounts: discountsCollection,
} = billingCollections;

export type PublicPriceSpec = ReturnType<typeof publicPriceSpec>;

/** A price entry as the API shows it (amounts in currency units). */
export interface PriceView {
  meter: string;
  /** The tenant (and subtree) the price applies to. */
  targetTenantId: string;
  targetTenantName?: string;
  /** The tenant that defines the meter and set the price. */
  definerId: string;
  effectiveFrom: string;
  price: PublicPriceSpec;
  note?: string;
  setAt: number;
  setBy: string;
}

/** A meter as a tenant sees it. */
export interface MeterView {
  key: string;
  name: string;
  unit: string;
  description?: string;
  aggregation: BillingMeter['aggregation'];
  pricing: BillingMeter['pricing'];
  archived: boolean;
  /** The defining tenant. */
  definedBy: string;
  /** `platform` when the root tenant defines it. */
  scope: 'platform' | 'tenant';
  /** Defined by an ancestor rather than this tenant. */
  inherited: boolean;
  /** The price that applies to this tenant's billing account in the current period. */
  price?: PriceView;
  createdAt: number;
  updatedAt: number;
}

/** A budget's settings with its current standing. */
export interface BillingBudgetView extends BudgetStatus {
  forecastAlerts: boolean;
  notify: BillingBudget['notify'];
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}

export interface CreditView {
  id: string;
  tenantId: string;
  amountMicros: number;
  amount: number;
  remainingMicros: number;
  remaining: number;
  reason: string;
  expiresAt?: number;
  grantedAt: number;
  grantedBy: string;
  revokedAt?: number;
  /** Not revoked, not expired, and something left. */
  active: boolean;
}

export interface ProfileView {
  tenantId: string;
  /** Who pays for this tenant: itself (with a profile or as an organization) or an ancestor. */
  account: { id: string; name: string; inherited: boolean };
  profile: BillingProfileFields | null;
}

export interface StatementSummary {
  id: string;
  tenantId: string;
  tenantName?: string;
  number: string;
  period: string;
  status: BillingStatement['status'];
  currency: string;
  subtotalMicros: number;
  creditsMicros: number;
  totalMicros: number;
  total: number;
  /** Payments received toward it. */
  amountPaidMicros: number;
  /** Still owed: the total less payments and credit notes. */
  amountDueMicros: number;
  amountDue: number;
  creditNotesMicros?: number;
  billingReason: NonNullable<BillingStatement['billingReason']>;
  issuedAt: number;
  dueAt: number;
  paidAt?: number;
  /** Finalized, past its due date, and not paid in full. */
  overdue: boolean;
}

/** A billing account's contract terms as the API shows them (amounts in currency units too). */
export interface TermsView {
  accountId: string;
  /** An ancestor pays for the tenant; its terms apply and are not shown. */
  inherited: boolean;
  discountPercent?: number;
  minimumCommitmentMicros?: number;
  minimumCommitment?: number;
  taxRatePercent?: number;
  taxLabel?: string;
  setAt?: number;
  setBy?: string;
}

function termsView(accountId: string, terms: BillingTerms | undefined): TermsView {
  return {
    accountId,
    inherited: false,
    ...(terms?.discountPercent !== undefined ? { discountPercent: terms.discountPercent } : {}),
    ...(terms?.minimumCommitmentMicros !== undefined
      ? {
          minimumCommitmentMicros: terms.minimumCommitmentMicros,
          minimumCommitment: unitsOf(terms.minimumCommitmentMicros),
        }
      : {}),
    ...(terms?.taxRatePercent !== undefined ? { taxRatePercent: terms.taxRatePercent } : {}),
    ...(terms?.taxLabel !== undefined ? { taxLabel: terms.taxLabel } : {}),
    ...(terms ? { setAt: terms.setAt, setBy: terms.setBy } : {}),
  };
}

/** A CSV download: file name, media type and the RFC 4180 text. */
export interface CsvExport {
  filename: string;
  contentType: string;
  body: string;
}

export interface AccountOverview {
  accountId: string;
  name: string;
  hasProfile: boolean;
  /** Billable spend this period (meters defined above the account). */
  monthToDateMicros: number;
  monthToDate: number;
  /** Including the account's own chargeback meters. */
  totalMicros: number;
  forecastMicros?: number;
  creditsMicros: number;
  /** Still owed on finalized and uncollectible invoices. */
  outstandingMicros: number;
  lastStatement?: StatementSummary;
}

export interface BillingBudgetInput {
  name: string;
  subjectType?: BudgetSubjectType;
  /** The tenant (default: the budget's own), team, department or identity. */
  subjectId?: string;
  /** In currency units. */
  amount: number;
  period?: BudgetPeriodKind;
  meters?: string[];
  thresholds?: number[];
  forecastAlerts?: boolean;
  notify?: { owners?: boolean; subject?: boolean; emails?: string[] };
  enforce?: boolean;
}

/** Trusted, credential-free billing for the deployment's own server code (`iam.billing`). */
export interface IamBilling {
  /** The deployment's billing settings (currency, time zone, ...). */
  readonly settings: Readonly<ReturnType<typeof billingServiceOf>['settings']>;
  /** Records usage without a credential and without an audit event (the hot path for metering). */
  record(input: UsageInput & { enforceBudgets?: boolean }): Promise<UsageReceipt>;
  /** Records up to 1000 events in one transaction. */
  recordMany(events: UsageInput[]): Promise<UsageReceipt[]>;
  /** Whether usage by `identityId` in the tenant is within every enforced budget that covers it. */
  check(input: { tenantId: string; identityId?: string; meter?: string }): Promise<SpendCheck>;
  /** A spend report for a tenant's subtree. */
  spend(
    input: { tenantId: string } & SpendFilters & { period?: string; groupBy?: SpendGroupBy },
  ): Promise<SpendReport>;
  /** Daily seat recording (scheduler job). */
  recordSeats: ReturnType<typeof billingServiceOf>['recordSeats'];
  /** Budget threshold and forecast alerts (scheduler job). */
  checkBudgets: ReturnType<typeof billingServiceOf>['checkBudgets'];
  /** Issues statements for the previous (or a given past) period and sweeps old usage events (scheduler job). */
  closePeriod: ReturnType<typeof billingServiceOf>['closePeriod'];
  /** Spend-spike alerts for every billing account for yesterday (scheduler job, daily). */
  detectAnomalies: ReturnType<typeof billingServiceOf>['detectAnomalies'];
  /** Payment reminders for unpaid invoices at `billing.paymentReminderDays` (scheduler job, daily). */
  sendPaymentReminders: ReturnType<typeof billingServiceOf>['sendPaymentReminders'];
  /**
   * Records a payment from a payment processor (a Stripe webhook, a bank feed) against an invoice by id or number.
   * `idempotencyKey` (the processor's payment id) makes redelivery safe: a known key returns the invoice unchanged.
   */
  recordPayment(input: {
    statementId?: string;
    number?: string;
    amount?: number;
    method?: string;
    reference?: string;
    receivedAt?: number;
    idempotencyKey?: string;
  }): Promise<{ statement: BillingStatement; payment?: InvoicePayment; duplicate: boolean }>;
}

const byName = (a: { name: string }, b: { name: string }) => a.name.localeCompare(b.name);
const maxBudgetsPerTenant = 200;
const budgetPeriods: BudgetPeriodKind[] = ['month', 'quarter', 'year'];
const subjectTypes: BudgetSubjectType[] = ['tenant', 'team', 'department', 'identity'];

function summary(statement: BillingStatement, now: number, tenantName?: string): StatementSummary {
  return {
    id: statement.id,
    tenantId: statement.tenantId,
    ...(tenantName !== undefined ? { tenantName } : {}),
    number: statement.number,
    period: statement.period,
    status: statement.status,
    currency: statement.currency,
    subtotalMicros: statement.subtotalMicros,
    creditsMicros: statement.creditsMicros,
    totalMicros: statement.totalMicros,
    total: unitsOf(statement.totalMicros),
    amountPaidMicros: amountPaid(statement),
    amountDueMicros: amountDue(statement),
    amountDue: unitsOf(amountDue(statement)),
    ...(statement.creditNotesMicros ? { creditNotesMicros: statement.creditNotesMicros } : {}),
    billingReason: statement.billingReason ?? 'period',
    issuedAt: statement.issuedAt,
    dueAt: statement.dueAt,
    ...(statement.paidAt !== undefined ? { paidAt: statement.paidAt } : {}),
    overdue: statement.status === 'finalized' && statement.dueAt < now && amountDue(statement) > 0,
  };
}

function creditView(credit: BillingCredit, now: number): CreditView {
  return {
    id: credit.id,
    tenantId: credit.tenantId,
    amountMicros: credit.amountMicros,
    amount: unitsOf(credit.amountMicros),
    remainingMicros: credit.remainingMicros,
    remaining: unitsOf(credit.remainingMicros),
    reason: credit.reason,
    ...(credit.expiresAt !== undefined ? { expiresAt: credit.expiresAt } : {}),
    grantedAt: credit.grantedAt,
    grantedBy: credit.grantedBy,
    ...(credit.revokedAt !== undefined ? { revokedAt: credit.revokedAt } : {}),
    active:
      credit.revokedAt === undefined &&
      credit.remainingMicros > 0 &&
      (credit.expiresAt === undefined || credit.expiresAt > now),
  };
}

/** A pending or invoiced invoice item (amounts in currency units too). */
export interface InvoiceItemView {
  id: string;
  accountId: string;
  description: string;
  quantity: number;
  unitAmountMicros: number;
  unitAmount: number;
  amountMicros: number;
  amount: number;
  period?: string;
  status: BillingInvoiceItem['status'];
  statementId?: string;
  source: BillingInvoiceItem['source'];
  subscriptionId?: string;
  metadata?: Record<string, string>;
  createdAt: number;
  createdBy: string;
}

export interface CreditNoteView {
  id: string;
  accountId: string;
  number: string;
  statementId: string;
  statementNumber: string;
  amountMicros: number;
  amount: number;
  reason: BillingCreditNote['reason'];
  memo?: string;
  applied: BillingCreditNote['applied'];
  creditId?: string;
  issuedAt: number;
  issuedBy: string;
}

export interface PlanItemView {
  id: string;
  kind: PlanItem['kind'];
  name: string;
  /** `fee`: the monthly amount. */
  amount?: number;
  /** `seat`: the monthly amount per seat. */
  unitAmount?: number;
  includedSeats?: number;
  billing?: PlanItem['billing'];
  meter?: string;
  price?: PublicPriceSpec;
}

export interface PlanView {
  id: string;
  key: string;
  name: string;
  description?: string;
  items: PlanItemView[];
  trialDays?: number;
  selfServe: boolean;
  archived: boolean;
  /** Live subscriptions (root administrators only). */
  subscribers?: number;
  createdAt: number;
  updatedAt: number;
}

export interface SubscriptionView {
  id: string;
  accountId: string;
  accountName?: string;
  planId: string;
  planKey: string;
  planName: string;
  status: ReturnType<typeof subscriptionStatus>;
  startedAt: number;
  trialEndsAt?: number;
  endsAt?: number;
  cancelAtPeriodEnd: boolean;
  canceledAt?: number;
  seats: number;
  /** Months already billed in advance. */
  billedAdvance: string[];
  createdAt: number;
  createdBy: string;
}

export interface CouponView {
  id: string;
  code: string;
  name: string;
  percentOff?: number;
  amountOffMicros?: number;
  amountOff?: number;
  duration: BillingCoupon['duration'];
  durationInMonths?: number;
  maxRedemptions?: number;
  redemptions: number;
  redeemBy?: number;
  active: boolean;
  createdAt: number;
}

export interface DiscountView {
  id: string;
  accountId: string;
  couponId: string;
  code: string;
  name: string;
  percentOff?: number;
  amountOffMicros?: number;
  amountOff?: number;
  duration: BillingCoupon['duration'];
  durationInMonths?: number;
  appliedInvoices: number;
  redeemedAt: number;
  redeemedBy: string;
  endedAt?: number;
  /** Discounts the invoice for the current month. */
  active: boolean;
}

/** An invoice as a printable HTML page. */
export interface InvoiceDocument {
  filename: string;
  contentType: string;
  body: string;
}

function invoiceItemView(item: BillingInvoiceItem): InvoiceItemView {
  return {
    id: item.id,
    accountId: item.tenantId,
    description: item.description,
    quantity: item.quantity,
    unitAmountMicros: item.unitAmountMicros,
    unitAmount: unitsOf(item.unitAmountMicros),
    amountMicros: item.amountMicros,
    amount: unitsOf(item.amountMicros),
    ...(item.period !== undefined ? { period: item.period } : {}),
    status: item.status,
    ...(item.statementId !== undefined ? { statementId: item.statementId } : {}),
    source: item.source,
    ...(item.subscriptionId !== undefined ? { subscriptionId: item.subscriptionId } : {}),
    ...(item.metadata !== undefined ? { metadata: item.metadata } : {}),
    createdAt: item.createdAt,
    createdBy: item.createdBy,
  };
}

function creditNoteView(note: BillingCreditNote): CreditNoteView {
  return {
    id: note.id,
    accountId: note.tenantId,
    number: note.number,
    statementId: note.statementId,
    statementNumber: note.statementNumber,
    amountMicros: note.amountMicros,
    amount: unitsOf(note.amountMicros),
    reason: note.reason,
    ...(note.memo !== undefined ? { memo: note.memo } : {}),
    applied: note.applied,
    ...(note.creditId !== undefined ? { creditId: note.creditId } : {}),
    issuedAt: note.issuedAt,
    issuedBy: note.issuedBy,
  };
}

function planView(plan: BillingPlan, subscribers?: number): PlanView {
  return {
    id: plan.id,
    key: plan.key,
    name: plan.name,
    ...(plan.description !== undefined ? { description: plan.description } : {}),
    items: plan.items.map((item) => ({
      id: item.id,
      kind: item.kind,
      name: item.name,
      ...(item.amountMicros !== undefined ? { amount: item.amountMicros / 1_000_000 } : {}),
      ...(item.unitAmountMicros !== undefined
        ? { unitAmount: item.unitAmountMicros / 1_000_000 }
        : {}),
      ...(item.includedSeats !== undefined ? { includedSeats: item.includedSeats } : {}),
      ...(item.kind !== 'usage' ? { billing: item.billing ?? 'advance' } : {}),
      ...(item.meter !== undefined ? { meter: item.meter } : {}),
      ...(item.price ? { price: publicPriceSpec(item.price) } : {}),
    })),
    ...(plan.trialDays !== undefined ? { trialDays: plan.trialDays } : {}),
    selfServe: plan.selfServe,
    archived: plan.archived,
    ...(subscribers !== undefined ? { subscribers } : {}),
    createdAt: plan.createdAt,
    updatedAt: plan.updatedAt,
  };
}

function subscriptionView(
  subscription: BillingSubscription,
  now: number,
  accountName?: string,
): SubscriptionView {
  return {
    id: subscription.id,
    accountId: subscription.tenantId,
    ...(accountName !== undefined ? { accountName } : {}),
    planId: subscription.planId,
    planKey: subscription.planKey,
    planName: subscription.planName,
    status: subscriptionStatus(subscription, now),
    startedAt: subscription.startedAt,
    ...(subscription.trialEndsAt !== undefined ? { trialEndsAt: subscription.trialEndsAt } : {}),
    ...(subscription.endsAt !== undefined ? { endsAt: subscription.endsAt } : {}),
    cancelAtPeriodEnd: subscription.cancelAtPeriodEnd,
    ...(subscription.canceledAt !== undefined ? { canceledAt: subscription.canceledAt } : {}),
    seats: subscription.seats,
    billedAdvance: subscription.billedAdvance,
    createdAt: subscription.createdAt,
    createdBy: subscription.createdBy,
  };
}

function couponView(coupon: BillingCoupon, now: number): CouponView {
  return {
    id: coupon.id,
    code: coupon.code,
    name: coupon.name,
    ...(coupon.percentOff !== undefined ? { percentOff: coupon.percentOff } : {}),
    ...(coupon.amountOffMicros !== undefined
      ? { amountOffMicros: coupon.amountOffMicros, amountOff: unitsOf(coupon.amountOffMicros) }
      : {}),
    duration: coupon.duration,
    ...(coupon.durationInMonths !== undefined ? { durationInMonths: coupon.durationInMonths } : {}),
    ...(coupon.maxRedemptions !== undefined ? { maxRedemptions: coupon.maxRedemptions } : {}),
    redemptions: coupon.redemptions,
    ...(coupon.redeemBy !== undefined ? { redeemBy: coupon.redeemBy } : {}),
    active:
      coupon.active &&
      (coupon.redeemBy === undefined || coupon.redeemBy > now) &&
      (coupon.maxRedemptions === undefined || coupon.redemptions < coupon.maxRedemptions),
    createdAt: coupon.createdAt,
  };
}

function discountView(discount: BillingDiscount, period: string, timeZone: string): DiscountView {
  return {
    id: discount.id,
    accountId: discount.tenantId,
    couponId: discount.couponId,
    code: discount.code,
    name: discount.name,
    ...(discount.percentOff !== undefined ? { percentOff: discount.percentOff } : {}),
    ...(discount.amountOffMicros !== undefined
      ? {
          amountOffMicros: discount.amountOffMicros,
          amountOff: unitsOf(discount.amountOffMicros),
        }
      : {}),
    duration: discount.duration,
    ...(discount.durationInMonths !== undefined
      ? { durationInMonths: discount.durationInMonths }
      : {}),
    appliedInvoices: discount.appliedInvoices,
    redeemedAt: discount.redeemedAt,
    redeemedBy: discount.redeemedBy,
    ...(discount.endedAt !== undefined ? { endedAt: discount.endedAt } : {}),
    active: discountActive(discount, period, timeZone),
  };
}

function priceView(price: BillingPrice, targetName?: string): PriceView {
  return {
    meter: price.meter,
    targetTenantId: price.tenantId,
    ...(targetName !== undefined ? { targetTenantName: targetName } : {}),
    definerId: price.definerId,
    effectiveFrom: price.effectiveFrom,
    price: publicPriceSpec(price.spec),
    ...(price.note !== undefined ? { note: price.note } : {}),
    setAt: price.setAt,
    setBy: price.setBy,
  };
}

/**
 * The `billing` group: usage-based billing and spend tracking. Billing managers (`iam:billing:manage`) define meters
 * and prices for their subtree, budgets, and the billing profile; `iam:billing:read` reads spend (by person, team,
 * department, project, meter, day or tag), budgets, credits and statements; `iam:billing:record` meters usage (a
 * backend's service account). People read their own spend (`mySpend`), team maintainers their team's (`teamSpend`),
 * department heads their department's (`departmentSpend`). Credits, period closing and payment status are root-only.
 */
export function createBillingApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const service = billingServiceOf(ctx);
  const { settings } = service;

  function writable(realm: Tenant): void {
    if (realm.status === 'deleted')
      throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
  }
  async function ownMeter(tx: IamStore, tenantId: string, key: string): Promise<BillingMeter> {
    const meter = (await tx.find<BillingMeter>(metersCollection, { tenantId, uniqueKey: key }))[0];
    if (!meter) throw new IamError('NOT_FOUND', 'Billing meter not found', 404);
    return meter;
  }
  async function audit(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    action: string,
    tenantId: string,
    resourceId: string,
    metadata: Record<string, Json>,
  ) {
    await ctx.events.audit(tx, principal, action, tenantId, resourceId, 'allow', false, metadata);
  }
  /** The price chain for a tenant's account: from the account up, or from the tenant for meters defined inside it. */
  async function effectivePrice(tx: IamStore, realm: Tenant, meter: BillingMeter, period: string) {
    const account = await accountOf(ctx, tx, realm);
    const accountChain = await ctx.ancestry(tx, account);
    const chain = accountChain.some((tenant) => tenant.id === meter.tenantId)
      ? accountChain
      : await ctx.ancestry(tx, realm);
    return priceFor(tx, meter, chain, period);
  }
  async function meterView(tx: IamStore, realm: Tenant, meter: BillingMeter, rootId: string) {
    const price =
      meter.pricing === 'rate-card'
        ? await effectivePrice(tx, realm, meter, service.currentPeriod())
        : undefined;
    const view: MeterView = {
      key: meter.key,
      name: meter.name,
      unit: meter.unit,
      ...(meter.description !== undefined ? { description: meter.description } : {}),
      aggregation: meter.aggregation,
      pricing: meter.pricing,
      archived: meter.archived,
      definedBy: meter.tenantId,
      scope: meter.tenantId === rootId ? 'platform' : 'tenant',
      inherited: meter.tenantId !== realm.id,
      ...(price ? { price: priceView(price) } : {}),
      createdAt: meter.createdAt,
      updatedAt: meter.updatedAt,
    };
    return view;
  }
  async function inSubtree(tx: IamStore, realm: Tenant, tenantId: string): Promise<boolean> {
    return (await ctx.ancestorIds(tx, tenantId)).includes(realm.id);
  }

  /**
   * A read allowed by `iam:billing:read` or by a role the caller holds over the data (team maintainer, department
   * head): `via` names that role or returns undefined. Impersonation sessions only read through the permission.
   */
  async function readAs<T>(
    credential: CredentialInput,
    tenantId: string,
    resourceId: string,
    via: (
      tx: IamStore,
      principal: AuthenticatedPrincipal,
      realm: Tenant,
    ) => Promise<string | undefined>,
    fn: (tx: IamStore, realm: Tenant) => Promise<T>,
  ): Promise<T> {
    const target = text(tenantId, 'tenantId');
    const authenticated = await ctx.principals.authenticate(credential);
    const outcome = await ctx.store.transaction(async (tx) => {
      const principal = await ctx.principals.currentPrincipal(tx, authenticated);
      const realm = await ctx.tenant(tx, target);
      const role =
        principal.session.impersonatorId === undefined
          ? await via(tx, principal, realm)
          : undefined;
      if (!role) {
        const decision = await ctx.operations.recordedDecision(tx, principal, {
          tenantId: realm.id,
          action: 'iam:billing:read',
          resource: { type: 'iam', id: resourceId },
        });
        if (!decision.allowed) return { denied: true as const };
      }
      const value = await fn(tx, realm);
      await audit(tx, principal, 'iam:billing:read', realm.id, resourceId, {
        via: role ?? 'permission',
      });
      return { denied: false as const, value };
    });
    if (outcome.denied) throw new IamError('ACCESS_DENIED', 'Access denied', 403);
    return outcome.value;
  }

  async function budgetView(tx: IamStore, budget: BillingBudget): Promise<BillingBudgetView> {
    return {
      ...(await service.budgetStatus(tx, budget)),
      forecastAlerts: budget.forecastAlerts,
      notify: budget.notify,
      createdAt: budget.createdAt,
      createdBy: budget.createdBy,
      updatedAt: budget.updatedAt,
    };
  }

  /** Validates a budget subject against the budget's tenant. */
  async function budgetSubject(
    tx: IamStore,
    realm: Tenant,
    type: unknown,
    subjectId: unknown,
  ): Promise<{ subjectType: BudgetSubjectType; subjectId: string }> {
    const subjectType = (type ?? 'tenant') as BudgetSubjectType;
    if (!subjectTypes.includes(subjectType))
      throw new IamError(
        'INVALID_INPUT',
        "subjectType must be 'tenant', 'team', 'department' or 'identity'",
      );
    const inScope = async (tenantId: string) =>
      (await inSubtree(tx, realm, tenantId)) ||
      (await ctx.ancestorIds(tx, realm.id)).includes(tenantId);
    if (subjectType === 'tenant') {
      const target =
        subjectId === undefined ? realm : await ctx.tenant(tx, text(subjectId, 'subjectId'));
      if (!(await inSubtree(tx, realm, target.id)))
        throw new IamError('INVALID_INPUT', 'A tenant budget covers this tenant or one below it');
      return { subjectType, subjectId: target.id };
    }
    const value = text(subjectId, 'subjectId');
    if (subjectType === 'identity') {
      const identity = await tx.get<Identity>('identities', value);
      if (
        !identity ||
        identity.status === 'deleted' ||
        !(await inSubtree(tx, realm, identity.tenantId))
      )
        throw new IamError('NOT_FOUND', 'Identity not found', 404);
    } else if (subjectType === 'team') {
      const team = await tx.get<Team>('teams', value);
      if (!team || !(await inScope(team.tenantId)))
        throw new IamError('NOT_FOUND', 'Team not found', 404);
    } else {
      const department = await tx.get<Department>('departments', value);
      if (!department || !(await inScope(department.tenantId)))
        throw new IamError('NOT_FOUND', 'Department not found', 404);
    }
    return { subjectType, subjectId: value };
  }

  /** Validated budget settings; `current` supplies values an update leaves out. */
  function budgetSettings(input: Record<string, unknown>, current?: BillingBudget) {
    const name = input.name === undefined ? current?.name : text(input.name, 'name', 128).trim();
    if (!name) throw new IamError('INVALID_INPUT', 'name is required');
    const amount =
      input.amount === undefined ? current?.amountMicros : amountMicros(input.amount, 'amount');
    if (!amount || amount <= 0) throw new IamError('INVALID_INPUT', 'amount must be above 0');
    const period = (input.period ?? current?.period ?? 'month') as BudgetPeriodKind;
    if (!budgetPeriods.includes(period))
      throw new IamError('INVALID_INPUT', "period must be 'month', 'quarter' or 'year'");
    let meters: string[] | undefined = current?.meters;
    if (input.meters === null) meters = undefined;
    else if (input.meters !== undefined) {
      if (!Array.isArray(input.meters) || input.meters.length === 0 || input.meters.length > 20)
        throw new IamError('INVALID_INPUT', 'meters must list 1-20 meter keys');
      meters = [...new Set(input.meters.map(meterKey))].sort();
    }
    const thresholds =
      input.thresholds === undefined && current
        ? current.thresholds
        : budgetThresholds(input.thresholds);
    const flag = (value: unknown, fallback: boolean, field: string) => {
      if (value === undefined) return fallback;
      if (typeof value !== 'boolean')
        throw new IamError('INVALID_INPUT', `${field} must be a boolean`);
      return value;
    };
    const notifyInput = input.notify === undefined ? {} : object(input.notify);
    const emails =
      notifyInput.emails === undefined
        ? (current?.notify.emails ?? [])
        : (() => {
            if (!Array.isArray(notifyInput.emails) || notifyInput.emails.length > 10)
              throw new IamError('INVALID_INPUT', 'notify.emails must list at most 10 addresses');
            return [...new Set(notifyInput.emails.map(email))].sort();
          })();
    return {
      name,
      amountMicros: amount,
      period,
      ...(meters ? { meters } : {}),
      thresholds,
      forecastAlerts: flag(input.forecastAlerts, current?.forecastAlerts ?? true, 'forecastAlerts'),
      notify: {
        owners: flag(notifyInput.owners, current?.notify.owners ?? true, 'notify.owners'),
        subject: flag(notifyInput.subject, current?.notify.subject ?? true, 'notify.subject'),
        emails,
      },
      enforce: flag(input.enforce, current?.enforce ?? false, 'enforce'),
    };
  }

  async function ownBudget(tx: IamStore, tenantId: string, budgetId: unknown) {
    return ctx.scoped<BillingBudget>(tx, budgetsCollection, text(budgetId, 'budgetId'), tenantId);
  }

  /** Statements of the accounts in a tenant's subtree (every statement for the root). */
  async function scopeStatements(tx: IamStore, realm: Tenant): Promise<BillingStatement[]> {
    if (realm.parentId === null) return tx.find<BillingStatement>(statementsCollection);
    const result: BillingStatement[] = [];
    for (const tenant of await subtree(ctx, tx, realm))
      result.push(
        ...(await tx.find<BillingStatement>(statementsCollection, { tenantId: tenant.id })),
      );
    return result;
  }

  /** A statement of an account in the tenant's subtree. */
  async function scopedStatement(tx: IamStore, realm: Tenant, statementId: unknown) {
    const statement = await tx.get<BillingStatement>(
      statementsCollection,
      text(statementId, 'statementId'),
    );
    if (!statement || !(await inSubtree(tx, realm, statement.tenantId)))
      throw new IamError('NOT_FOUND', 'Statement not found', 404);
    return statement;
  }

  /** The tenant a profile call is about: the operation's tenant, or `targetTenantId` below it. */
  async function profileTarget(
    tx: IamStore,
    realm: Tenant,
    targetTenantId: unknown,
  ): Promise<Tenant> {
    if (targetTenantId === undefined) return realm;
    const target = await ctx.tenant(tx, text(targetTenantId, 'targetTenantId'));
    if (!(await inSubtree(tx, realm, target.id)))
      throw new IamError('NOT_FOUND', 'Tenant not found', 404);
    return target;
  }

  async function profileView(
    tx: IamStore,
    target: Tenant,
    profile: BillingProfile | undefined,
  ): Promise<ProfileView> {
    const account = await accountOf(ctx, tx, target);
    let fields: BillingProfileFields | null = null;
    if (profile) {
      const { id: _id, tenantId: _tenant, uniqueKey: _key, ...rest } = profile;
      fields = rest as BillingProfileFields;
    }
    return {
      tenantId: target.id,
      account: { id: account.id, name: account.name, inherited: account.id !== target.id },
      profile: fields,
    };
  }

  /** The tenant as a billing account: invoices, subscriptions and discounts belong to accounts. */
  async function ownAccount(tx: IamStore, realm: Tenant): Promise<Tenant> {
    const account = await accountOf(ctx, tx, realm);
    if (account.id !== realm.id || realm.parentId === null)
      throw new IamError(
        'INVALID_INPUT',
        'Only a billing account (an organization or a tenant with a profile) has invoices and subscriptions',
      );
    return account;
  }
  function onRoot(realm: Tenant, what: string): void {
    if (realm.parentId !== null)
      throw new IamError('INVALID_INPUT', `${what} are managed on the platform (root) tenant`);
  }
  async function rootOf(tx: IamStore, realm: Tenant): Promise<Tenant> {
    return (await ctx.ancestry(tx, realm)).find((tenant) => tenant.parentId === null) ?? realm;
  }
  /** A platform plan by id or key. */
  async function planByRef(tx: IamStore, realm: Tenant, ref: unknown): Promise<BillingPlan> {
    const value = text(ref, 'plan', 128);
    const root = await rootOf(tx, realm);
    const plan = (await tx.find<BillingPlan>(plansCollection, { tenantId: root.id })).find(
      (candidate) => candidate.id === value || candidate.key === value,
    );
    if (!plan) throw new IamError('NOT_FOUND', 'Billing plan not found', 404);
    return plan;
  }
  /** Account billing managers act on self-serve plans only; root administrators on any. */
  async function mayManage(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    plans: BillingPlan[],
  ): Promise<boolean> {
    if (await ctx.rootPrincipal(tx, principal)) return true;
    if (plans.some((plan) => !plan.selfServe))
      throw new OperationDenied(
        'Only root administrators manage subscriptions to plans that are not self-serve',
      );
    return false;
  }
  /** The ids of the billing accounts a tenant's reads cover (undefined: every account, for the root). */
  async function coveredAccounts(tx: IamStore, realm: Tenant): Promise<Set<string> | undefined> {
    if (realm.parentId === null) return undefined;
    return new Set((await subtree(ctx, tx, realm)).map((tenant) => tenant.id));
  }
  async function accountName(tx: IamStore, statement: BillingStatement) {
    return (await tx.get<Tenant>('tenants', statement.tenantId))?.name;
  }
  /** An invoice of the tenant's own account or, called on the root tenant, of any account. */
  async function accountStatement(tx: IamStore, realm: Tenant, statementId: unknown) {
    const statement = await tx.get<BillingStatement>(
      statementsCollection,
      text(statementId, 'statementId'),
    );
    if (!statement || (statement.tenantId !== realm.id && realm.parentId !== null))
      throw new IamError('NOT_FOUND', 'Statement not found', 404);
    return statement;
  }

  return {
    // ---------------------------------------------------------------------------------------------------------
    // Meters and prices

    /**
     * The meters that reach the tenant (its own and those of its ancestors), with the price that applies to the
     * tenant's billing account this period. Requires iam:billing:read.
     */
    listMeters: (credential: CredentialInput, input: { tenantId: string }): Promise<MeterView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing',
        async ({ tx, tenant: realm }) => {
          const chain = await ctx.ancestry(tx, realm);
          const rootId = chain.at(-1)!.id;
          const views: MeterView[] = [];
          for (const meter of [...(await metersFor(tx, chain)).values()].sort((a, b) =>
            a.key < b.key ? -1 : 1,
          ))
            views.push(await meterView(tx, realm, meter, rootId));
          return views;
        },
      ),

    /**
     * Defines a meter: on the root tenant a platform meter billed to every organization, elsewhere a meter for the
     * tenant's own subtree (chargeback: it shows in spend but never on a platform statement). Keys may not repeat a
     * key an ancestor defines; at most 100 meters per tenant. Requires iam:billing:manage on `iam/billing/meters/{key}`;
     * audited as `billing:meter-create`.
     */
    createMeter: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        key: string;
        name: string;
        unit?: string;
        description?: string;
        aggregation?: BillingMeter['aggregation'];
        pricing?: BillingMeter['pricing'];
      },
    ): Promise<MeterView> => {
      const key = meterKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        `billing/meters/${key}`,
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const { tenantId: _tenant, key: _key, archived: _archived, ...rest } = object(input);
          const fields = meterSettings(rest);
          const chain = await ctx.ancestry(tx, realm);
          if (await resolveMeter(tx, chain, key))
            throw new IamError(
              'CONFLICT',
              'A meter with this key already reaches this tenant',
              409,
            );
          if (
            (await tx.find(metersCollection, { tenantId: realm.id })).length >= maxMetersPerTenant
          )
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can define at most ${maxMetersPerTenant} meters`,
              409,
            );
          const now = ctx.now();
          const meter = await tx.insert<BillingMeter>(metersCollection, {
            id: id(),
            tenantId: realm.id,
            uniqueKey: key,
            key,
            ...fields,
            archived: false,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          });
          await audit(tx, principal, 'billing:meter-create', realm.id, `billing/meters/${key}`, {
            key,
            name: meter.name,
            unit: meter.unit,
            aggregation: meter.aggregation,
            pricing: meter.pricing,
          });
          return meterView(tx, realm, meter, chain.at(-1)!.id);
        },
      );
    },

    /**
     * Renames a meter, changes its unit or description (`null` clears it), or archives it (`archived: true` refuses new
     * usage and keeps its history). Aggregation and pricing cannot change. Requires iam:billing:manage; audited as
     * `billing:meter-update`.
     */
    updateMeter: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        key: string;
        name?: string;
        unit?: string;
        description?: string | null;
        archived?: boolean;
      },
    ): Promise<MeterView> => {
      const key = meterKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        `billing/meters/${key}`,
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const meter = await ownMeter(tx, realm.id, key);
          const { tenantId: _tenant, key: _key, ...rest } = object(input);
          const fields = meterSettings(rest, meter);
          const { description: _description, ...previous } = meter;
          const next = await tx.put<BillingMeter>(metersCollection, {
            ...previous,
            ...fields,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await audit(tx, principal, 'billing:meter-update', realm.id, `billing/meters/${key}`, {
            key,
            name: next.name,
            unit: next.unit,
            archived: next.archived,
          });
          return meterView(tx, realm, next, (await ctx.ancestry(tx, realm)).at(-1)!.id);
        },
      );
    },

    /**
     * Deletes a meter that has never recorded usage, with its prices; a meter with history can only be archived
     * (RESOURCE_IN_USE). Requires iam:billing:manage; audited as `billing:meter-delete`.
     */
    deleteMeter: async (credential: CredentialInput, input: { tenantId: string; key: string }) => {
      const key = meterKey(input.key);
      return operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        `billing/meters/${key}`,
        async ({ tx, tenant: realm, principal }) => {
          const meter = await ownMeter(tx, realm.id, key);
          if ((await tx.find(rollupsCollection, { meterId: meter.id }, { limit: 1 })).length)
            throw new IamError(
              'RESOURCE_IN_USE',
              'This meter has recorded usage; archive it instead',
              409,
            );
          const prices = await tx.find<BillingPrice>(pricesCollection, { meterId: meter.id });
          for (const price of prices) await tx.delete(pricesCollection, price.id);
          await tx.delete(metersCollection, meter.id);
          await audit(tx, principal, 'billing:meter-delete', realm.id, `billing/meters/${key}`, {
            key,
            removedPrices: prices.length,
          });
          return { success: true as const, removedPrices: prices.length };
        },
      );
    },

    /**
     * Sets a rate-card price for a meter this tenant defines: its list price (on the tenant itself) or a negotiated
     * price for a tenant below it (`targetTenantId`, applying to that subtree). `effectiveFrom` (default the current
     * period; up to 12 periods back while none of them is invoiced for the tenants it reaches) starts it; the latest
     * entry effective by a period prices it. `price` takes amounts in
     * currency units: `{ model: 'per-unit', unitAmount }`, `{ model: 'graduated' | 'volume', tiers: [{ upTo, unitAmount,
     * flatAmount? }] }` (last `upTo: null`), or `{ model: 'package', packageSize, packageAmount }`, each with optional
     * `includedQuantity`; `price: null` removes the entry. Requires iam:billing:manage; audited as `billing:price`.
     */
    setPrice: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        meter: string;
        targetTenantId?: string;
        effectiveFrom?: string;
        price: Record<string, unknown> | null;
        note?: string;
      },
    ): Promise<PriceView | null> => {
      const key = meterKey(input.meter);
      return operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        `billing/meters/${key}`,
        async ({ tx, tenant: definer, principal }) => {
          const meter = await ownMeter(tx, definer.id, key);
          if (meter.pricing !== 'rate-card')
            throw new IamError('INVALID_INPUT', 'Reported meters carry their cost on each event');
          const target =
            input.targetTenantId === undefined
              ? definer
              : await ctx.tenant(tx, text(input.targetTenantId, 'targetTenantId'));
          if (!(await inSubtree(tx, definer, target.id)))
            throw new IamError(
              'INVALID_INPUT',
              'targetTenantId must be the defining tenant or a tenant below it',
            );
          const current = service.currentPeriod();
          const effectiveFrom =
            input.effectiveFrom === undefined
              ? current
              : billingPeriod(input.effectiveFrom, 'effectiveFrom');
          if (effectiveFrom < current) {
            // A past period may still be priced (usage recorded before its price was set) until it is invoiced.
            if (effectiveFrom < shiftPeriod(current, -12))
              throw new IamError(
                'INVALID_INPUT',
                'effectiveFrom may reach back at most 12 periods',
              );
            const affected = new Set([
              ...(await subtree(ctx, tx, target)).map((tenant) => tenant.id),
              (await accountOf(ctx, tx, target)).id,
            ]);
            if (
              (await tx.find<BillingStatement>(statementsCollection)).some(
                (statement) =>
                  statement.status !== 'void' &&
                  statement.status !== 'draft' &&
                  statement.period >= effectiveFrom &&
                  affected.has(statement.tenantId),
              )
            )
              throw new IamError(
                'BILLING_PERIOD_CLOSED',
                'A period from effectiveFrom on has already been invoiced; invoiced periods keep their prices',
                409,
              );
          }
          const uniqueKey = `${meter.id}:${effectiveFrom}`;
          const existing = (
            await tx.find<BillingPrice>(pricesCollection, { tenantId: target.id, uniqueKey })
          )[0];
          if (input.price === null) {
            if (existing) await tx.delete(pricesCollection, existing.id);
            await audit(tx, principal, 'billing:price', definer.id, `billing/meters/${key}`, {
              meter: key,
              targetTenantId: target.id,
              effectiveFrom,
              price: null,
            });
            return null;
          }
          writable(target);
          const spec = priceSpec(input.price);
          const entry: BillingPrice = {
            id: existing?.id ?? id(),
            tenantId: target.id,
            uniqueKey,
            meterId: meter.id,
            meter: key,
            definerId: definer.id,
            effectiveFrom,
            spec,
            ...(input.note !== undefined ? { note: text(input.note, 'note', 512).trim() } : {}),
            setAt: ctx.now(),
            setBy: principal.identity.id,
          };
          if (existing) await tx.put(pricesCollection, entry);
          else await tx.insert(pricesCollection, entry);
          await audit(tx, principal, 'billing:price', definer.id, `billing/meters/${key}`, {
            meter: key,
            targetTenantId: target.id,
            effectiveFrom,
            model: spec.model,
          });
          return priceView(entry, target.name);
        },
      );
    },

    /**
     * A meter's rate card as the tenant may see it: entries for the tenant, its ancestors (list prices) and tenants
     * below it (newest first), and the entry that prices the tenant's account this period. Requires iam:billing:read.
     */
    listPrices: async (credential: CredentialInput, input: { tenantId: string; meter: string }) => {
      const key = meterKey(input.meter);
      return operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        `billing/meters/${key}`,
        async ({ tx, tenant: realm }) => {
          const chain = await ctx.ancestry(tx, realm);
          const meter = await resolveMeter(tx, chain, key);
          if (!meter) throw new IamError('NOT_FOUND', 'Billing meter not found', 404);
          const visible = new Set([
            ...chain.map((tenant) => tenant.id),
            ...(await subtree(ctx, tx, realm)).map((tenant) => tenant.id),
          ]);
          const entries: PriceView[] = [];
          for (const price of await tx.find<BillingPrice>(pricesCollection, { meterId: meter.id }))
            if (visible.has(price.tenantId))
              entries.push(
                priceView(price, (await tx.get<Tenant>('tenants', price.tenantId))?.name),
              );
          entries.sort(
            (a, b) =>
              (a.effectiveFrom < b.effectiveFrom
                ? 1
                : a.effectiveFrom > b.effectiveFrom
                  ? -1
                  : 0) || b.setAt - a.setAt,
          );
          const effective =
            meter.pricing === 'rate-card'
              ? await effectivePrice(tx, realm, meter, service.currentPeriod())
              : undefined;
          return {
            meter: await meterView(tx, realm, meter, chain.at(-1)!.id),
            entries,
            ...(effective ? { effective: priceView(effective) } : {}),
          };
        },
      );
    },

    /**
     * What `quantity` units of a meter cost the tenant's billing account in a period (default: the current one), as a
     * period total with tiers and included units applied. Requires iam:billing:read.
     */
    quote: async (
      credential: CredentialInput,
      input: { tenantId: string; meter: string; quantity: number; period?: string },
    ) => {
      const key = meterKey(input.meter);
      return operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        `billing/meters/${key}`,
        async ({ tx, tenant: realm }) => {
          if (
            typeof input.quantity !== 'number' ||
            !Number.isFinite(input.quantity) ||
            input.quantity < 0
          )
            throw new IamError('INVALID_INPUT', 'quantity must be a number of at least 0');
          const period =
            input.period === undefined ? service.currentPeriod() : billingPeriod(input.period);
          const meter = await resolveMeter(tx, await ctx.ancestry(tx, realm), key);
          if (!meter) throw new IamError('NOT_FOUND', 'Billing meter not found', 404);
          if (meter.pricing !== 'rate-card')
            throw new IamError('INVALID_INPUT', 'Reported meters carry their cost on each event');
          const price = await effectivePrice(tx, realm, meter, period);
          const amount = price ? priceQuantity(price.spec, input.quantity) : 0;
          return {
            meter: key,
            quantity: input.quantity,
            period,
            currency: settings.currency,
            amountMicros: amount,
            amount: unitsOf(amount),
            ...(price ? { price: priceView(price) } : { unpriced: true as const }),
          };
        },
      );
    },

    // ---------------------------------------------------------------------------------------------------------
    // Usage

    /**
     * Records usage of a meter in the tenant, attributed to `identityId` (and their teams and department at that
     * moment, or `teamId`), with optional `tags`. `idempotencyKey` makes retries safe (a repeat returns the first
     * receipt with `duplicate: true`). Reported meters need `cost` (currency units). `enforceBudgets` refuses with
     * SPEND_LIMIT_REACHED (402) once an enforced budget covering the usage is spent. Usage for a period already
     * invoiced fails with BILLING_PERIOD_CLOSED. Requires iam:billing:record on `iam/billing/meters/{key}`; for high
     * volumes prefer the audit-free `iam.billing.record` on the server.
     */
    record: async (
      credential: CredentialInput,
      input: UsageInput & { enforceBudgets?: boolean },
    ): Promise<UsageReceipt> => {
      const key = meterKey(input.meter);
      return operation(
        credential,
        input.tenantId,
        'iam:billing:record',
        `billing/meters/${key}`,
        ({ tx, principal }) =>
          service.record(tx, input, principal.identity.id, {
            ...(input.enforceBudgets === true ? { enforceBudgets: true } : {}),
          }),
      );
    },

    /**
     * Records up to 100 events in one transaction (all or nothing), each in `tenantId` or a tenant below it (their
     * own `tenantId`, default the call's). Requires iam:billing:record in `tenantId`.
     */
    recordMany: async (
      credential: CredentialInput,
      input: { tenantId: string; events: Omit<UsageInput, 'tenantId'> & { tenantId?: string }[] },
    ): Promise<{ receipts: UsageReceipt[] }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:record',
        'billing',
        async ({ tx, tenant: realm, principal }) => {
          if (
            !Array.isArray(input.events) ||
            input.events.length === 0 ||
            input.events.length > 100
          )
            throw new IamError('INVALID_INPUT', 'events must list 1-100 usage events');
          const receipts: UsageReceipt[] = [];
          for (const raw of input.events) {
            const event = object(raw) as unknown as UsageInput;
            const tenantId =
              event.tenantId === undefined ? realm.id : text(event.tenantId, 'tenantId');
            if (tenantId !== realm.id && !(await inSubtree(tx, realm, tenantId)))
              throw new IamError(
                'INVALID_INPUT',
                'Every event must be in this tenant or one below it',
              );
            receipts.push(await service.record(tx, { ...event, tenantId }, principal.identity.id));
          }
          return { receipts };
        },
      ),

    /**
     * Raw usage events recorded in this tenant (not its subtree) for a period (default current), newest first,
     * optionally for one meter or identity; at most `limit` (1-500, default 100). Requires iam:billing:read.
     */
    listUsage: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        period?: string;
        meter?: string;
        identityId?: string;
        limit?: number;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing',
        async ({ tx, tenant: realm }) => {
          const period =
            input.period === undefined ? service.currentPeriod() : billingPeriod(input.period);
          const limit = integer(input.limit ?? 100, 'limit', 1, 500);
          const meter = input.meter === undefined ? undefined : meterKey(input.meter);
          const identityId =
            input.identityId === undefined ? undefined : text(input.identityId, 'identityId');
          const events = (
            await tx.find<BillingUsageRecord>(usageCollection, { tenantId: realm.id, period })
          )
            .filter(
              (record) =>
                (meter === undefined || record.meter === meter) &&
                (identityId === undefined ||
                  record.identityId === identityId ||
                  record.agentId === identityId),
            )
            .sort((a, b) => b.occurredAt - a.occurredAt || (a.id < b.id ? -1 : 1))
            .slice(0, limit)
            .map(({ rollupId: _rollup, expiresAt: _expires, uniqueKey, ...rest }) => ({
              ...rest,
              ...(uniqueKey?.startsWith('idem:') ? { idempotencyKey: uniqueKey.slice(5) } : {}),
            }));
          return { tenantId: realm.id, period, events };
        },
      ),

    // ---------------------------------------------------------------------------------------------------------
    // Spend

    /**
     * Spend of the tenant and every tenant below it in a period (default current), grouped by `meter` (default),
     * `identity`, `agent`, `team`, `department`, `tenant`, `day` or `tag:{name}`, optionally filtered to a meter,
     * identity, team, department or sub-tenant (teams and departments include those below them unless `rollUp` is
     * false). Each meter's period total is priced within its billing account and shared out by quantity, so groups add
     * up to the account's charges. The current period carries a linear `forecast`. Requires iam:billing:read.
     */
    spend: async (
      credential: CredentialInput,
      input: { tenantId: string; period?: string; groupBy?: SpendGroupBy } & SpendFilters,
    ): Promise<SpendReport> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing',
        ({ tx, tenant: realm }) => {
          const { tenantId: _tenant, ...query } = input;
          return service.report(tx, realm, query);
        },
      ),

    /** Monthly totals for the last `months` periods (1-24, default 6), with the same filters as `spend`. */
    trend: async (
      credential: CredentialInput,
      input: { tenantId: string; months?: number } & SpendFilters,
    ): Promise<SpendTrend> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing',
        ({ tx, tenant: realm }) => {
          const { tenantId: _tenant, ...query } = input;
          return service.trend(tx, realm, query);
        },
      ),

    /**
     * The caller's own spend (their usage and that of the agents they sponsor) in their tenant and the tenants below
     * it, grouped by `meter` (default), `day`, `agent`, `tenant` or `tag:{name}`, with the budgets set on them. Any
     * credential of the tenant; needs no permission.
     */
    mySpend: async (
      credential: CredentialInput,
      input: { tenantId: string; period?: string; groupBy?: SpendGroupBy },
    ): Promise<SpendReport & { budgets: BudgetStatus[] }> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const groupBy: unknown = input.groupBy ?? 'meter';
      if (
        typeof groupBy !== 'string' ||
        (!['meter', 'day', 'agent', 'tenant'].includes(groupBy) && !groupBy.startsWith('tag:'))
      )
        throw new IamError(
          'INVALID_INPUT',
          "groupBy must be 'meter', 'day', 'agent', 'tenant' or 'tag:{name}'",
        );
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        if (principal.session.tenantId !== tenantId || principal.identity.tenantId !== tenantId)
          throw new IamError('ACCESS_DENIED', 'Spend is read in the credential’s own tenant', 403);
        const realm = await ctx.tenant(tx, tenantId);
        const own = await service.ownIdentities(tx, principal.identity);
        const report = await service.report(
          tx,
          realm,
          {
            groupBy: groupBy as SpendGroupBy,
            ...(input.period !== undefined ? { period: input.period } : {}),
          },
          new Map(),
          (row) =>
            (row.identityId !== undefined && own.has(row.identityId)) ||
            (row.agentId !== undefined && own.has(row.agentId)),
        );
        const budgets: BudgetStatus[] = [];
        for (const tenant of await ctx.ancestry(tx, realm))
          for (const budget of await tx.find<BillingBudget>(budgetsCollection, {
            tenantId: tenant.id,
            subjectType: 'identity',
            subjectId: principal.identity.id,
          }))
            budgets.push(await service.budgetStatus(tx, budget));
        return { ...report, budgets };
      });
    },

    /**
     * A team's spend (with the teams below it), grouped by `identity` (default), `meter`, `team`, `agent`, `day` or
     * `tag:{name}`. Allowed to the team's maintainers (and those of teams above it) or with iam:billing:read.
     */
    teamSpend: async (
      credential: CredentialInput,
      input: { tenantId: string; teamId: string; period?: string; groupBy?: SpendGroupBy },
    ): Promise<SpendReport> => {
      const teamId = text(input.teamId, 'teamId');
      return readAs(
        credential,
        input.tenantId,
        `billing/teams/${teamId}`,
        async (tx, principal, realm) => {
          const team = await tx.get<Team>('teams', teamId);
          // Maintainers read in the team's own tenant (or a project below it), never elsewhere.
          if (
            !team ||
            principal.identity.tenantId !== team.tenantId ||
            !(await ctx.ancestorIds(tx, realm.id)).includes(team.tenantId)
          )
            return undefined;
          return (await isTeamMaintainer(tx, team.tenantId, team.id, principal.identity.id, {
            at: ctx.now(),
            includeAncestors: true,
          }))
            ? 'team-maintainer'
            : undefined;
        },
        (tx, realm) =>
          service.report(tx, realm, {
            teamId,
            groupBy: input.groupBy ?? 'identity',
            ...(input.period !== undefined ? { period: input.period } : {}),
          }),
      );
    },

    /**
     * A department's spend (with the departments below it), grouped by `identity` (default), `department`, `team`,
     * `meter`, `day` or `tag:{name}`. Allowed to the department's head (and heads above it) or with iam:billing:read.
     */
    departmentSpend: async (
      credential: CredentialInput,
      input: { tenantId: string; departmentId: string; period?: string; groupBy?: SpendGroupBy },
    ): Promise<SpendReport> => {
      const departmentId = text(input.departmentId, 'departmentId');
      return readAs(
        credential,
        input.tenantId,
        `billing/departments/${departmentId}`,
        async (tx, principal, realm) => {
          const department = await tx.get<Department>('departments', departmentId);
          if (
            !department ||
            principal.identity.tenantId !== department.tenantId ||
            !(await ctx.ancestorIds(tx, realm.id)).includes(department.tenantId)
          )
            return undefined;
          return (
            await departmentHeads(tx, department.tenantId, department.id, {
              includeAncestors: true,
            })
          ).includes(principal.identity.id)
            ? 'department-head'
            : undefined;
        },
        (tx, realm) =>
          service.report(tx, realm, {
            departmentId,
            groupBy: input.groupBy ?? 'identity',
            ...(input.period !== undefined ? { period: input.period } : {}),
          }),
      );
    },

    /**
     * The billing accounts in the tenant's subtree (every organization for the root) with this period's billable
     * spend, projection, available credit and latest statement. Requires iam:billing:read.
     */
    accounts: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<AccountOverview[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing',
        async ({ tx, tenant: realm }) => {
          const period = service.currentPeriod();
          const now = ctx.now();
          const report = await service.report(tx, realm, { period, groupBy: 'tenant' });
          const factor =
            report.forecast && report.total.costMicros > 0
              ? report.forecast.costMicros / report.total.costMicros
              : undefined;
          const accounts = new Map<string, Tenant>();
          const top = await accountOf(ctx, tx, realm);
          if (await inSubtree(tx, realm, top.id)) accounts.set(top.id, top);
          for (const tenant of await subtree(ctx, tx, realm)) {
            const account = await accountOf(ctx, tx, tenant);
            if (account.parentId !== null && (await inSubtree(tx, realm, account.id)))
              accounts.set(account.id, account);
          }
          const result: AccountOverview[] = [];
          for (const account of accounts.values()) {
            if (account.parentId === null) continue;
            const spend = await accountSpend(ctx, tx, account, period);
            const statements = (
              await tx.find<BillingStatement>(statementsCollection, { tenantId: account.id })
            )
              .filter((statement) => statement.status !== 'draft')
              .sort((a, b) => (a.period < b.period ? 1 : -1) || b.issuedAt - a.issuedAt);
            const outstandingMicros = roundMicros(
              statements.reduce((sum, statement) => sum + amountDue(statement), 0),
            );
            const credits = (
              await tx.find<BillingCredit>(creditsCollection, { tenantId: account.id })
            )
              .map((credit) => creditView(credit, now))
              .filter((credit) => credit.active);
            result.push({
              accountId: account.id,
              name: account.name,
              hasProfile: Boolean(await profileOf(tx, account.id)),
              monthToDateMicros: spend.billableMicros,
              monthToDate: unitsOf(spend.billableMicros),
              totalMicros: spend.totalMicros,
              ...(factor !== undefined
                ? { forecastMicros: roundMicros(spend.billableMicros * factor) }
                : {}),
              creditsMicros: roundMicros(
                credits.reduce((sum, credit) => sum + credit.remainingMicros, 0),
              ),
              outstandingMicros,
              ...(statements[0]
                ? { lastStatement: summary(statements[0], now, account.name) }
                : {}),
            });
          }
          return result.sort((a, b) => b.monthToDateMicros - a.monthToDateMicros || byName(a, b));
        },
      ),

    /**
     * Spend spikes in the tenant's subtree on `day` (default yesterday): people, teams and meters that spent at least
     * `factor` (3) times their average over the `baselineDays` (14) before, and at least `minimum` (10 currency units)
     * more, plus new spending above `minimum`. Largest increase first, at most 50. Requires iam:billing:read.
     */
    anomalies: async (
      credential: CredentialInput,
      input: { tenantId: string } & AnomalyOptions,
    ): Promise<{ tenantId: string; anomalies: SpendAnomaly[] }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing',
        async ({ tx, tenant: realm }) => {
          const { tenantId: _tenant, ...options } = input;
          return { tenantId: realm.id, anomalies: await service.anomalies(tx, realm, options) };
        },
      ),

    /**
     * A spend report as CSV (the same query as `spend`): one row per group with the amount, share, events and a
     * column per meter's quantity, then a total row. Requires iam:billing:read.
     */
    exportSpend: async (
      credential: CredentialInput,
      input: { tenantId: string } & SpendQuery,
    ): Promise<CsvExport> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing',
        async ({ tx, tenant: realm }) => {
          const { tenantId: _tenant, ...query } = input;
          const report = await service.report(tx, realm, query);
          return {
            filename: `spend-${realm.slug ?? realm.id}-${report.period}-${report.groupBy.replace(':', '-')}.csv`,
            contentType: 'text/csv; charset=utf-8',
            body: service.spendCsv(report),
          };
        },
      ),

    /** A statement as CSV: its lines, credit and total, then the breakdown by project, team, department and person. */
    exportStatement: async (
      credential: CredentialInput,
      input: { tenantId: string; statementId: string },
    ): Promise<CsvExport> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/statements',
        async ({ tx, tenant: realm }) => {
          const statement = await scopedStatement(tx, realm, input.statementId);
          return {
            filename: `${statement.number}.csv`,
            contentType: 'text/csv; charset=utf-8',
            body: service.statementCsv(statement),
          };
        },
      ),

    // ---------------------------------------------------------------------------------------------------------
    // Budgets

    /**
     * Creates a spend budget owned by the tenant: an `amount` (currency units) per `month` (default), `quarter` or
     * `year` for the tenant or one below it, a `team`, a `department` or an `identity`, optionally over some `meters`.
     * Alerts fire at each of `thresholds` (default 50, 80, 100 percent) and, with `forecastAlerts` (default on), when
     * the projection passes 100%, to the owners, the subject (the person, team maintainers or department head) and
     * `notify.emails`. `enforce` makes `billing.check` and `record({ enforceBudgets })` refuse covered usage once the
     * budget is spent. Names are unique per tenant; at most 200. Requires iam:billing:manage; audited as
     * `billing:budget-create`.
     */
    createBudget: async (
      credential: CredentialInput,
      input: { tenantId: string } & BillingBudgetInput,
    ): Promise<BillingBudgetView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/budgets',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const fields = budgetSettings(object(input));
          const subject = await budgetSubject(tx, realm, input.subjectType, input.subjectId);
          const existing = await tx.find<BillingBudget>(budgetsCollection, { tenantId: realm.id });
          if (existing.length >= maxBudgetsPerTenant)
            throw new IamError(
              'LIMIT_EXCEEDED',
              `A tenant can have at most ${maxBudgetsPerTenant} budgets`,
              409,
            );
          const uniqueKey = `name:${fields.name.toLowerCase()}`;
          if (existing.some((budget) => budget.uniqueKey === uniqueKey))
            throw new IamError('CONFLICT', 'A budget with this name already exists', 409);
          const now = ctx.now();
          const budget = await tx.insert<BillingBudget>(budgetsCollection, {
            id: id(),
            tenantId: realm.id,
            uniqueKey,
            ...fields,
            ...subject,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          });
          await audit(
            tx,
            principal,
            'billing:budget-create',
            realm.id,
            `billing/budgets/${budget.id}`,
            {
              budgetId: budget.id,
              name: budget.name,
              subjectType: budget.subjectType,
              subjectId: budget.subjectId,
              amountMicros: budget.amountMicros,
              period: budget.period,
              enforce: budget.enforce,
            },
          );
          return budgetView(tx, budget);
        },
      ),

    /**
     * Changes a budget's name, amount, period, meters (`null` for all), thresholds, alerts or enforcement; its subject
     * stays. Requires iam:billing:manage; audited as `billing:budget-update`.
     */
    updateBudget: async (
      credential: CredentialInput,
      input: { tenantId: string; budgetId: string } & Partial<
        Omit<BillingBudgetInput, 'subjectType' | 'subjectId' | 'meters'>
      > & {
          meters?: string[] | null;
        },
    ): Promise<BillingBudgetView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/budgets',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const budget = await ownBudget(tx, realm.id, input.budgetId);
          const fields = budgetSettings(object(input), budget);
          const uniqueKey = `name:${fields.name.toLowerCase()}`;
          if (
            uniqueKey !== budget.uniqueKey &&
            (await tx.find(budgetsCollection, { tenantId: realm.id, uniqueKey })).length
          )
            throw new IamError('CONFLICT', 'A budget with this name already exists', 409);
          const { meters: _meters, ...previous } = budget;
          const next = await tx.put<BillingBudget>(budgetsCollection, {
            ...previous,
            ...fields,
            uniqueKey,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await audit(
            tx,
            principal,
            'billing:budget-update',
            realm.id,
            `billing/budgets/${budget.id}`,
            {
              budgetId: budget.id,
              name: next.name,
              amountMicros: next.amountMicros,
              period: next.period,
              enforce: next.enforce,
            },
          );
          return budgetView(tx, next);
        },
      ),

    /** Deletes a budget and its alert history. Requires iam:billing:manage; audited as `billing:budget-delete`. */
    deleteBudget: async (
      credential: CredentialInput,
      input: { tenantId: string; budgetId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/budgets',
        async ({ tx, tenant: realm, principal }) => {
          const budget = await ownBudget(tx, realm.id, input.budgetId);
          for (const alert of await tx.find(alertsCollection, {
            tenantId: realm.id,
            budgetId: budget.id,
          }))
            await tx.delete(alertsCollection, alert.id);
          await tx.delete(budgetsCollection, budget.id);
          await audit(
            tx,
            principal,
            'billing:budget-delete',
            realm.id,
            `billing/budgets/${budget.id}`,
            {
              budgetId: budget.id,
              name: budget.name,
            },
          );
          return { success: true as const };
        },
      ),

    /** The tenant's budgets with their spend, projection and thresholds reached this window. Requires iam:billing:read. */
    listBudgets: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<BillingBudgetView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/budgets',
        async ({ tx, tenant: realm }) => {
          const budgets = (
            await tx.find<BillingBudget>(budgetsCollection, { tenantId: realm.id })
          ).sort(byName);
          const views: BillingBudgetView[] = [];
          for (const budget of budgets) views.push(await budgetView(tx, budget));
          return views;
        },
      ),

    /**
     * Whether the caller's own usage (of `meter`, when given) is within every enforced budget that covers it: tenant
     * budgets up the tree, their own, their teams' and their department's. Any credential of the tenant; not audited.
     */
    check: async (
      credential: CredentialInput,
      input: { tenantId: string; meter?: string },
    ): Promise<SpendCheck> => {
      const tenantId = text(input.tenantId, 'tenantId');
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const realm = await ctx.tenant(tx, tenantId);
        const chain = await ctx.ancestry(tx, realm);
        if (!chain.some((tenant) => tenant.id === principal.identity.tenantId))
          throw new IamError(
            'ACCESS_DENIED',
            'Budgets are checked in the credential’s own tenant',
            403,
          );
        return service.check(tx, realm, {
          identityId: principal.identity.id,
          ...(input.meter !== undefined ? { meter: input.meter } : {}),
        });
      });
    },

    // ---------------------------------------------------------------------------------------------------------
    // Credits

    /**
     * Grants credit to a billing account (the tenant must be one): statements draw on it, earliest expiry first.
     * Root administrators only; audited as `billing:credit-grant`.
     */
    grantCredit: async (
      credential: CredentialInput,
      input: { tenantId: string; amount: number; reason: string; expiresAt?: number },
    ): Promise<CreditView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/credits',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          if (realm.parentId === null || (await accountOf(ctx, tx, realm)).id !== realm.id)
            throw new IamError(
              'INVALID_INPUT',
              'Credit is granted to a billing account (an organization or a tenant with a billing profile)',
            );
          const amount = amountMicros(input.amount, 'amount');
          if (amount <= 0) throw new IamError('INVALID_INPUT', 'amount must be above 0');
          const credit = await tx.insert<BillingCredit>(creditsCollection, {
            id: id(),
            tenantId: realm.id,
            amountMicros: amount,
            remainingMicros: amount,
            reason: text(input.reason, 'reason', 256).trim(),
            ...(input.expiresAt !== undefined
              ? { expiresAt: ctx.bindingExpiry(input.expiresAt) }
              : {}),
            grantedAt: ctx.now(),
            grantedBy: principal.identity.id,
          });
          await audit(
            tx,
            principal,
            'billing:credit-grant',
            realm.id,
            `billing/credits/${credit.id}`,
            {
              creditId: credit.id,
              amountMicros: amount,
              reason: credit.reason,
              ...(credit.expiresAt !== undefined ? { expiresAt: credit.expiresAt } : {}),
            },
          );
          return creditView(credit, ctx.now());
        },
        true,
      ),

    /** Withdraws what is left of a credit. Root administrators only; audited as `billing:credit-revoke`. */
    revokeCredit: async (
      credential: CredentialInput,
      input: { tenantId: string; creditId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/credits',
        async ({ tx, tenant: realm, principal }) => {
          const credit = await ctx.scoped<BillingCredit>(
            tx,
            creditsCollection,
            text(input.creditId, 'creditId'),
            realm.id,
          );
          if (credit.revokedAt !== undefined)
            throw new IamError('INVALID_TRANSITION', 'The credit is already revoked', 409);
          const next = await tx.put<BillingCredit>(creditsCollection, {
            ...credit,
            remainingMicros: 0,
            revokedAt: ctx.now(),
          });
          await audit(
            tx,
            principal,
            'billing:credit-revoke',
            realm.id,
            `billing/credits/${credit.id}`,
            {
              creditId: credit.id,
              forfeitedMicros: credit.remainingMicros,
            },
          );
          return creditView(next, ctx.now());
        },
        true,
      ),

    /**
     * The credits of the tenant's billing account with the available balance; empty (with `inherited: true`) when an
     * ancestor pays for the tenant. Requires iam:billing:read.
     */
    listCredits: async (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/credits',
        async ({ tx, tenant: realm }) => {
          const account = await accountOf(ctx, tx, realm);
          const now = ctx.now();
          if (account.id !== realm.id)
            return {
              accountId: account.id,
              inherited: true,
              balanceMicros: 0,
              balance: 0,
              credits: [] as CreditView[],
            };
          const credits = (await tx.find<BillingCredit>(creditsCollection, { tenantId: realm.id }))
            .map((credit) => creditView(credit, now))
            .sort((a, b) => b.grantedAt - a.grantedAt || (a.id < b.id ? -1 : 1));
          const balanceMicros = roundMicros(
            credits
              .filter((credit) => credit.active)
              .reduce((sum, credit) => sum + credit.remainingMicros, 0),
          );
          return {
            accountId: account.id,
            inherited: false,
            balanceMicros,
            balance: unitsOf(balanceMicros),
            credits,
          };
        },
      ),

    /**
     * Sets a billing account's contract terms: `discountPercent` off usage, a `minimumCommitment` per month (currency
     * units; a shortfall is billed as a true-up), and the `taxRatePercent` statements add, labelled `taxLabel`; `null`
     * clears a term. Terms apply to statements issued from then on. Root administrators only; audited as
     * `billing:terms`.
     */
    setTerms: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        discountPercent?: number | null;
        minimumCommitment?: number | null;
        taxRatePercent?: number | null;
        taxLabel?: string | null;
      },
    ): Promise<TermsView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/terms',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          if (realm.parentId === null || (await accountOf(ctx, tx, realm)).id !== realm.id)
            throw new IamError(
              'INVALID_INPUT',
              'Terms belong to a billing account (an organization or a tenant with a billing profile)',
            );
          const existing = await termsOf(tx, realm.id);
          const percent = (value: unknown, current: number | undefined, name: string) => {
            if (value === null) return undefined;
            if (value === undefined) return current;
            if (typeof value !== 'number' || !Number.isFinite(value) || value < 0 || value > 100)
              throw new IamError('INVALID_INPUT', `${name} must be a percentage from 0 to 100`);
            return Math.round(value * 1000) / 1000;
          };
          const discountPercent = percent(
            input.discountPercent,
            existing?.discountPercent,
            'discountPercent',
          );
          const taxRatePercent = percent(
            input.taxRatePercent,
            existing?.taxRatePercent,
            'taxRatePercent',
          );
          const minimumCommitmentMicros =
            input.minimumCommitment === null
              ? undefined
              : input.minimumCommitment === undefined
                ? existing?.minimumCommitmentMicros
                : amountMicros(input.minimumCommitment, 'minimumCommitment');
          const taxLabel =
            input.taxLabel === null
              ? undefined
              : input.taxLabel === undefined
                ? existing?.taxLabel
                : text(input.taxLabel, 'taxLabel', 32).trim();
          const terms: BillingTerms = {
            id: existing?.id ?? id(),
            tenantId: realm.id,
            uniqueKey: 'terms',
            ...(discountPercent !== undefined ? { discountPercent } : {}),
            ...(minimumCommitmentMicros !== undefined ? { minimumCommitmentMicros } : {}),
            ...(taxRatePercent !== undefined ? { taxRatePercent } : {}),
            ...(taxLabel !== undefined ? { taxLabel } : {}),
            setAt: ctx.now(),
            setBy: principal.identity.id,
          };
          if (existing) await tx.put(termsCollection, terms);
          else await tx.insert(termsCollection, terms);
          await audit(tx, principal, 'billing:terms', realm.id, 'billing/terms', {
            discountPercent: terms.discountPercent ?? null,
            minimumCommitmentMicros: terms.minimumCommitmentMicros ?? null,
            taxRatePercent: terms.taxRatePercent ?? null,
          });
          return termsView(realm.id, terms);
        },
        true,
      ),

    /**
     * The contract terms of the tenant's billing account (empty when none are set; `inherited` when an ancestor pays
     * for the tenant). Requires iam:billing:read.
     */
    getTerms: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<TermsView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/terms',
        async ({ tx, tenant: realm }) => {
          const account = await accountOf(ctx, tx, realm);
          if (account.id !== realm.id) return { accountId: account.id, inherited: true };
          return termsView(realm.id, await termsOf(tx, realm.id));
        },
      ),

    // ---------------------------------------------------------------------------------------------------------
    // Profiles

    /**
     * The billing profile of the tenant (or of `targetTenantId`, a tenant below it) and the account that pays for it.
     * Requires iam:billing:read.
     */
    getProfile: async (
      credential: CredentialInput,
      input: { tenantId: string; targetTenantId?: string },
    ): Promise<ProfileView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/profile',
        async ({ tx, tenant: realm }) => {
          const target = await profileTarget(tx, realm, input.targetTenantId);
          return profileView(tx, target, await profileOf(tx, target.id));
        },
      ),

    /**
     * Creates or updates a billing profile: company name, billing emails (statements go there), tax ID, address,
     * purchase order, cost center, payment terms (days); `null` clears a field. The profile belongs to the tenant or to
     * `targetTenantId`, a tenant below it. A profile below an organization makes that tenant its own billing account,
     * which is the parent's decision: it is created from an ancestor (with `targetTenantId`); the tenant's own billing
     * managers may then keep it up to date. Requires iam:billing:manage; audited as `billing:profile`.
     */
    setProfile: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        targetTenantId?: string;
        companyName?: string | null;
        billingEmails?: string[];
        taxId?: string | null;
        address?: string | null;
        purchaseOrder?: string | null;
        costCenter?: string | null;
        paymentTermsDays?: number | null;
      },
    ): Promise<ProfileView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/profile',
        async ({ tx, tenant: realm, principal }) => {
          const target = await profileTarget(tx, realm, input.targetTenantId);
          writable(target);
          if (target.parentId === null)
            throw new IamError('INVALID_INPUT', 'The platform tenant is not billed');
          const existing = await profileOf(tx, target.id);
          if (!existing && target.id === realm.id && (await ctx.ancestry(tx, target)).length > 2)
            throw new OperationDenied(
              'A tenant below an organization becomes its own billing account only from its parent (setProfile with targetTenantId)',
            );
          const optional = (
            value: unknown,
            current: string | undefined,
            name: string,
            max: number,
          ) =>
            value === null
              ? undefined
              : value === undefined
                ? current
                : text(value, name, max).trim();
          const billingEmails =
            input.billingEmails === undefined
              ? (existing?.billingEmails ?? [])
              : (() => {
                  if (!Array.isArray(input.billingEmails) || input.billingEmails.length > 10)
                    throw new IamError(
                      'INVALID_INPUT',
                      'billingEmails must list at most 10 addresses',
                    );
                  return [...new Set(input.billingEmails.map(email))];
                })();
          const paymentTermsDays =
            input.paymentTermsDays === null
              ? undefined
              : input.paymentTermsDays === undefined
                ? existing?.paymentTermsDays
                : integer(input.paymentTermsDays, 'paymentTermsDays', 0, 365);
          const fields = {
            companyName: optional(input.companyName, existing?.companyName, 'companyName', 256),
            taxId: optional(input.taxId, existing?.taxId, 'taxId', 64),
            address: optional(input.address, existing?.address, 'address', 1024),
            purchaseOrder: optional(
              input.purchaseOrder,
              existing?.purchaseOrder,
              'purchaseOrder',
              128,
            ),
            costCenter: optional(input.costCenter, existing?.costCenter, 'costCenter', 128),
          };
          const now = ctx.now();
          const profile: BillingProfile = {
            id: existing?.id ?? id(),
            tenantId: target.id,
            uniqueKey: 'profile',
            billingEmails,
            ...Object.fromEntries(
              Object.entries(fields).filter(([, value]) => value !== undefined),
            ),
            ...(paymentTermsDays !== undefined ? { paymentTermsDays } : {}),
            createdAt: existing?.createdAt ?? now,
            createdBy: existing?.createdBy ?? principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          };
          if (existing) await tx.put(profilesCollection, profile);
          else await tx.insert(profilesCollection, profile);
          await audit(tx, principal, 'billing:profile', realm.id, `billing/profile/${target.id}`, {
            targetTenantId: target.id,
            created: !existing,
            billingEmails: billingEmails.length,
            ...(profile.companyName ? { companyName: profile.companyName } : {}),
          });
          return profileView(tx, target, profile);
        },
      ),

    /**
     * Removes a billing profile (the tenant's own, or `targetTenantId`'s below it). A tenant below an organization then
     * rolls into its parent's account again, which only an ancestor may decide (call it from there). Requires
     * iam:billing:manage; audited as `billing:profile-delete`.
     */
    deleteProfile: async (
      credential: CredentialInput,
      input: { tenantId: string; targetTenantId?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/profile',
        async ({ tx, tenant: realm, principal }) => {
          const target = await profileTarget(tx, realm, input.targetTenantId);
          const existing = await profileOf(tx, target.id);
          if (!existing) throw new IamError('NOT_FOUND', 'This tenant has no billing profile', 404);
          if (target.id === realm.id && (await ctx.ancestry(tx, target)).length > 2)
            throw new OperationDenied(
              'Folding a tenant back into its parent’s billing account is decided from the parent (targetTenantId)',
            );
          await tx.delete(profilesCollection, existing.id);
          await audit(
            tx,
            principal,
            'billing:profile-delete',
            realm.id,
            `billing/profile/${target.id}`,
            {
              targetTenantId: target.id,
            },
          );
          return { success: true as const };
        },
      ),

    // ---------------------------------------------------------------------------------------------------------
    // Statements

    /**
     * Statements of the billing accounts in the tenant's subtree (all for the root), newest period first, optionally
     * by `status` or `period`. Requires iam:billing:read.
     */
    listStatements: async (
      credential: CredentialInput,
      input: { tenantId: string; status?: BillingStatement['status']; period?: string },
    ): Promise<StatementSummary[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/statements',
        async ({ tx, tenant: realm }) => {
          const period = input.period === undefined ? undefined : billingPeriod(input.period);
          const now = ctx.now();
          const names = new Map<string, string | undefined>();
          const result: StatementSummary[] = [];
          for (const statement of await scopeStatements(tx, realm)) {
            if (input.status !== undefined && statement.status !== input.status) continue;
            if (period !== undefined && statement.period !== period) continue;
            if (!names.has(statement.tenantId))
              names.set(
                statement.tenantId,
                (await tx.get<Tenant>('tenants', statement.tenantId))?.name,
              );
            result.push(summary(statement, now, names.get(statement.tenantId)));
          }
          return result.sort(
            (a, b) =>
              (a.period < b.period ? 1 : a.period > b.period ? -1 : 0) || b.issuedAt - a.issuedAt,
          );
        },
      ),

    /**
     * A statement with its lines, credits, allocation breakdown and bill-to details; `verified` re-checks its content
     * hash. Requires iam:billing:read.
     */
    getStatement: async (
      credential: CredentialInput,
      input: { tenantId: string; statementId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/statements',
        async ({ tx, tenant: realm }) => {
          const statement = await scopedStatement(tx, realm, input.statementId);
          return {
            ...statement,
            total: unitsOf(statement.totalMicros),
            overdue: summary(statement, ctx.now()).overdue,
            verified: statementHash(statement) === statement.hash,
          };
        },
      ),

    /**
     * What the tenant's statement for a period (default the current one, so far) would hold, without issuing it. The
     * tenant must be its own billing account or above it. Requires iam:billing:read.
     */
    previewStatement: async (
      credential: CredentialInput,
      input: { tenantId: string; period?: string },
    ): Promise<StatementDraft> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/statements',
        async ({ tx, tenant: realm }) => {
          const period =
            input.period === undefined ? service.currentPeriod() : billingPeriod(input.period);
          const account = await accountOf(ctx, tx, realm);
          if (account.id !== realm.id || realm.parentId === null)
            throw new IamError(
              'INVALID_INPUT',
              'Only a billing account (an organization or a tenant with a profile) has statements',
            );
          return service.draftStatement(tx, account, period);
        },
      ),

    /**
     * Issues statements for a past period (default the previous one) for every billing account, or only `accountId`'s.
     * With `draft` they are kept as drafts to review and finalize (`finalizeInvoice`); the default follows
     * `billing.autoFinalize`. Called on the root tenant; root administrators only (the operation is audited as
     * `iam:billing:manage`, each statement as `billing:statement`). Schedulers call `iam.billing.closePeriod()` instead.
     */
    closePeriod: async (
      credential: CredentialInput,
      input: { tenantId: string; period?: string; accountId?: string; draft?: boolean },
    ): Promise<ClosePeriodResult> => {
      await operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/periods',
        async ({ tenant: realm }) => {
          if (realm.parentId !== null)
            throw new IamError('INVALID_INPUT', 'Periods are closed on the platform (root) tenant');
        },
        true,
      );
      return service.closePeriod({
        ...(input.period !== undefined ? { period: input.period } : {}),
        ...(input.accountId !== undefined ? { tenantId: input.accountId } : {}),
        ...(input.draft !== undefined ? { draft: input.draft } : {}),
      });
    },

    /**
     * Marks a finalized (or uncollectible) statement paid: records a `manual` payment of the amount still due, with an
     * optional `reference`. Root administrators only; audited as `billing:statement-paid`.
     */
    markPaid: async (
      credential: CredentialInput,
      input: { tenantId: string; statementId: string; reference?: string },
    ): Promise<StatementSummary> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/statements',
        async ({ tx, tenant: realm, principal }) => {
          const statement = await accountStatement(tx, realm, input.statementId);
          const { statement: next } = await service.recordPayment(
            tx,
            statement,
            { ...(input.reference !== undefined ? { reference: input.reference } : {}) },
            principal.identity.id,
          );
          await audit(
            tx,
            principal,
            'billing:statement-paid',
            statement.tenantId,
            `billing/statements/${statement.id}`,
            {
              number: statement.number,
              totalMicros: statement.totalMicros,
              ...(next.paymentReference ? { reference: next.paymentReference } : {}),
            },
          );
          return summary(next, ctx.now(), await accountName(tx, next));
        },
        true,
      ),

    /**
     * Voids a statement: its credits are restored and its period reopens for the account (fix usage, then close the
     * period again for a new statement). Root administrators only; audited as `billing:statement-void`.
     */
    voidStatement: async (
      credential: CredentialInput,
      input: { tenantId: string; statementId: string; reason: string },
    ): Promise<StatementSummary> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/statements',
        async ({ tx, tenant: realm, principal }) => {
          const statement = await accountStatement(tx, realm, input.statementId);
          const reason = text(input.reason, 'reason', 512).trim();
          const next = await service.voidStatement(tx, statement, principal, reason);
          await audit(
            tx,
            principal,
            'billing:statement-void',
            statement.tenantId,
            `billing/statements/${statement.id}`,
            {
              number: statement.number,
              reason,
              restoredCreditMicros: statement.creditsMicros,
            },
          );
          return summary(next, ctx.now(), await accountName(tx, next));
        },
        true,
      ),
    // ---------------------------------------------------------------------------------------------------------
    // Invoicing

    /**
     * Finalizes a draft invoice (kept as a draft by `closePeriod({ draft: true })` or `billing.autoFinalize: false`):
     * it is recomputed with the latest usage and invoice items, numbered, and sent. Root administrators only; audited
     * as `billing:statement-finalize` (and `billing:statement`).
     */
    finalizeInvoice: async (
      credential: CredentialInput,
      input: { tenantId: string; statementId: string },
    ): Promise<StatementSummary> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/statements',
        async ({ tx, tenant: realm, principal }) => {
          const statement = await accountStatement(tx, realm, input.statementId);
          const { statement: next, recipients } = await service.finalizeDraft(
            tx,
            statement,
            principal.identity.id,
          );
          await audit(
            tx,
            principal,
            'billing:statement-finalize',
            statement.tenantId,
            `billing/statements/${next.id}`,
            { number: next.number, period: next.period, totalMicros: next.totalMicros, recipients },
          );
          return summary(next, ctx.now(), await accountName(tx, next));
        },
        true,
      ),

    /**
     * Records a payment against a finalized or uncollectible invoice: `amount` (currency units, default the amount
     * due), `method` (`card`, `bank_transfer`, `check`, ...; default `manual`), `reference`, and `receivedAt`. Partial
     * payments leave the rest due; once covered the invoice is paid; an overpayment becomes account credit. Root
     * administrators only (payment processors call `iam.billing.recordPayment`); audited as `billing:payment`.
     */
    recordPayment: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        statementId: string;
        amount?: number;
        method?: string;
        reference?: string;
        receivedAt?: number;
      },
    ): Promise<{ statement: StatementSummary; payment: InvoicePayment }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/statements',
        async ({ tx, tenant: realm, principal }) => {
          const statement = await accountStatement(tx, realm, input.statementId);
          const { statement: next, payment } = await service.recordPayment(
            tx,
            statement,
            input,
            principal.identity.id,
          );
          await audit(
            tx,
            principal,
            'billing:payment',
            statement.tenantId,
            `billing/statements/${next.id}`,
            {
              number: next.number,
              amountMicros: payment.amountMicros,
              method: payment.method,
              ...(payment.reference ? { reference: payment.reference } : {}),
              ...(payment.overpaymentMicros
                ? { overpaymentMicros: payment.overpaymentMicros }
                : {}),
              status: next.status,
            },
          );
          return { statement: summary(next, ctx.now(), await accountName(tx, next)), payment };
        },
        true,
      ),

    /**
     * Writes a finalized invoice off as uncollectible (a later payment still settles it). Root administrators only;
     * audited as `billing:statement-uncollectible`.
     */
    markUncollectible: async (
      credential: CredentialInput,
      input: { tenantId: string; statementId: string },
    ): Promise<StatementSummary> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/statements',
        async ({ tx, tenant: realm, principal }) => {
          const statement = await accountStatement(tx, realm, input.statementId);
          const next = await service.markUncollectible(tx, statement);
          await audit(
            tx,
            principal,
            'billing:statement-uncollectible',
            statement.tenantId,
            `billing/statements/${next.id}`,
            { number: next.number, amountDueMicros: amountDue(next) },
          );
          return summary(next, ctx.now(), await accountName(tx, next));
        },
        true,
      ),

    /**
     * Issues a credit note against an invoice for `amount` (currency units, default everything not yet credited) with
     * a `reason` (`duplicate`, `fraudulent`, `order_change`, `product_unsatisfactory`, `other`) and `memo`. It reduces
     * the amount due first; a part already paid becomes account credit, or with `refund: true` is recorded as refunded
     * outside Better IAM. Root administrators only; audited as `billing:credit-note`.
     */
    createCreditNote: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        statementId: string;
        amount?: number;
        reason?: BillingCreditNote['reason'];
        memo?: string;
        refund?: boolean;
      },
    ): Promise<{ statement: StatementSummary; creditNote: CreditNoteView }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/statements',
        async ({ tx, tenant: realm, principal }) => {
          const statement = await accountStatement(tx, realm, input.statementId);
          const { statement: next, creditNote } = await service.createCreditNote(
            tx,
            statement,
            input,
            principal.identity.id,
          );
          await audit(
            tx,
            principal,
            'billing:credit-note',
            statement.tenantId,
            `billing/statements/${next.id}`,
            {
              number: creditNote.number,
              statementNumber: next.number,
              amountMicros: creditNote.amountMicros,
              reason: creditNote.reason,
              dueMicros: creditNote.applied.dueMicros,
              creditMicros: creditNote.applied.creditMicros,
              refundMicros: creditNote.applied.refundMicros,
            },
          );
          return {
            statement: summary(next, ctx.now(), await accountName(tx, next)),
            creditNote: creditNoteView(creditNote),
          };
        },
        true,
      ),

    /** Credit notes of the billing accounts in the tenant's subtree, or of one `statementId`. Requires iam:billing:read. */
    listCreditNotes: async (
      credential: CredentialInput,
      input: { tenantId: string; statementId?: string },
    ): Promise<CreditNoteView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/statements',
        async ({ tx, tenant: realm }) => {
          let notes: BillingCreditNote[];
          if (input.statementId !== undefined) {
            const statement = await scopedStatement(tx, realm, input.statementId);
            notes = await tx.find<BillingCreditNote>(creditNotesCollection, {
              tenantId: statement.tenantId,
              statementId: statement.id,
            });
          } else {
            const covered = await coveredAccounts(tx, realm);
            notes = (await tx.find<BillingCreditNote>(creditNotesCollection)).filter(
              (note) => !covered || covered.has(note.tenantId),
            );
          }
          return notes
            .sort((a, b) => b.issuedAt - a.issuedAt || (a.number < b.number ? 1 : -1))
            .map(creditNoteView);
        },
      ),

    /**
     * An invoice as a standalone HTML page to print or save as PDF: the issuer (`billing.issuer`), bill-to details,
     * lines with tier sub-lines and service periods, discounts, credit, tax, payments, credit notes and amount due.
     * Requires iam:billing:read.
     */
    renderInvoice: async (
      credential: CredentialInput,
      input: { tenantId: string; statementId: string },
    ): Promise<InvoiceDocument> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/statements',
        async ({ tx, tenant: realm }) => {
          const statement = await scopedStatement(tx, realm, input.statementId);
          const creditNotes = await tx.find<BillingCreditNote>(creditNotesCollection, {
            tenantId: statement.tenantId,
            statementId: statement.id,
          });
          return {
            filename: `${statement.number || `draft-${statement.period}`}.html`,
            contentType: 'text/html; charset=utf-8',
            body: renderInvoiceHtml(statement, {
              ...(settings.issuer ? { issuer: settings.issuer } : {}),
              creditNotes: creditNotes.sort((a, b) => (a.number < b.number ? -1 : 1)),
            }),
          };
        },
      ),

    /**
     * Pending (and invoiced) invoice items of the billing accounts in the tenant's subtree, newest first, optionally
     * by `status`. Requires iam:billing:read.
     */
    listInvoiceItems: async (
      credential: CredentialInput,
      input: { tenantId: string; status?: BillingInvoiceItem['status'] },
    ): Promise<InvoiceItemView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/invoice-items',
        async ({ tx, tenant: realm }) => {
          if (
            input.status !== undefined &&
            input.status !== 'pending' &&
            input.status !== 'invoiced'
          )
            throw new IamError('INVALID_INPUT', "status must be 'pending' or 'invoiced'");
          const covered = await coveredAccounts(tx, realm);
          return (
            await tx.find<BillingInvoiceItem>(invoiceItemsCollection, {
              ...(input.status ? { status: input.status } : {}),
            })
          )
            .filter((item) => !covered || covered.has(item.tenantId))
            .sort((a, b) => b.createdAt - a.createdAt || (a.id < b.id ? 1 : -1))
            .map(invoiceItemView);
        },
      ),

    /**
     * Adds a one-off charge (or, with a negative `amount`, a credit) to the billing account's next invoice, or to the
     * invoice for `period`: `description`, `amount` per unit in currency units, `quantity` (default 1), `metadata`.
     * Root administrators only; audited as `billing:invoice-item`.
     */
    createInvoiceItem: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        description: string;
        amount: number;
        quantity?: number;
        period?: string;
        metadata?: Record<string, string>;
      },
    ): Promise<InvoiceItemView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/invoice-items',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const account = await ownAccount(tx, realm);
          const fields = invoiceItemInput(object(input));
          if (fields.period) {
            const invoiced = await service.statementFor(tx, account.id, fields.period);
            if (invoiced && invoiced.status !== 'draft')
              throw new IamError(
                'BILLING_PERIOD_CLOSED',
                `${fields.period} has already been invoiced; leave period out to bill the next invoice`,
                409,
              );
          }
          const item = await tx.insert<BillingInvoiceItem>(invoiceItemsCollection, {
            id: id(),
            tenantId: account.id,
            ...fields,
            status: 'pending',
            source: 'manual',
            createdAt: ctx.now(),
            createdBy: principal.identity.id,
          });
          await audit(
            tx,
            principal,
            'billing:invoice-item',
            realm.id,
            `billing/invoice-items/${item.id}`,
            {
              description: item.description,
              amountMicros: item.amountMicros,
              ...(item.period ? { period: item.period } : {}),
            },
          );
          return invoiceItemView(item);
        },
        true,
      ),

    /** Deletes a pending invoice item. Root administrators only; audited as `billing:invoice-item-delete`. */
    deleteInvoiceItem: async (
      credential: CredentialInput,
      input: { tenantId: string; itemId: string },
    ): Promise<{ success: true }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/invoice-items',
        async ({ tx, tenant: realm, principal }) => {
          const item = await ctx.scoped<BillingInvoiceItem>(
            tx,
            invoiceItemsCollection,
            text(input.itemId, 'itemId'),
            realm.id,
          );
          if (item.status !== 'pending')
            throw new IamError(
              'INVALID_TRANSITION',
              'The item is on a finalized invoice; issue a credit note instead',
              409,
            );
          await tx.delete(invoiceItemsCollection, item.id);
          await audit(
            tx,
            principal,
            'billing:invoice-item-delete',
            realm.id,
            `billing/invoice-items/${item.id}`,
            { description: item.description, amountMicros: item.amountMicros },
          );
          return { success: true as const };
        },
        true,
      ),

    // ---------------------------------------------------------------------------------------------------------
    // Plans and subscriptions

    /**
     * The platform's plans: fixed monthly fees, per-seat fees and plan prices for meters. Other tenants see plans
     * that are not archived; root administrators also see archived plans (`includeArchived`) and subscriber counts.
     * Requires iam:billing:read.
     */
    listPlans: async (
      credential: CredentialInput,
      input: { tenantId: string; includeArchived?: boolean },
    ): Promise<PlanView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/plans',
        async ({ tx, tenant: realm, principal }) => {
          const root = await rootOf(tx, realm);
          const admin = realm.parentId === null && (await ctx.rootPrincipal(tx, principal));
          const plans = await tx.find<BillingPlan>(plansCollection, { tenantId: root.id });
          const now = ctx.now();
          const live = admin
            ? (await tx.find<BillingSubscription>(subscriptionsCollection)).filter(
                (subscription) => subscriptionStatus(subscription, now) !== 'ended',
              )
            : [];
          return plans
            .filter((plan) => !plan.archived || (admin && input.includeArchived === true))
            .sort(byName)
            .map((plan) =>
              planView(
                plan,
                admin
                  ? live.filter((subscription) => subscription.planId === plan.id).length
                  : undefined,
              ),
            );
        },
      ),

    /**
     * Defines a plan on the platform (root) tenant: `key`, `name`, `items` (`fee` with `amount`, `seat` with
     * `unitAmount` and `includedSeats`, both billed in `advance` (default) or `arrears`; `usage` with a `meter` and
     * `price` that replaces the rate card for subscribers), `trialDays`, `selfServe` (account billing managers may
     * subscribe themselves) and `description`. Root administrators only; audited as `billing:plan`.
     */
    createPlan: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        key: string;
        name: string;
        items: unknown[];
        description?: string;
        trialDays?: number;
        selfServe?: boolean;
      },
    ): Promise<PlanView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/plans',
        async ({ tx, tenant: realm, principal }) => {
          onRoot(realm, 'Plans');
          const key = planKey(input.key);
          const existing = await tx.find<BillingPlan>(plansCollection, { tenantId: realm.id });
          if (existing.some((plan) => plan.key === key))
            throw new IamError('CONFLICT', 'A plan with this key already exists', 409);
          if (existing.length >= maxPlansPerTenant)
            throw new IamError('LIMIT_EXCEEDED', `At most ${maxPlansPerTenant} plans`, 409);
          const fields = planSettings(object(input));
          const now = ctx.now();
          const plan = await tx.insert<BillingPlan>(plansCollection, {
            id: id(),
            tenantId: realm.id,
            uniqueKey: key,
            key,
            ...fields,
            createdAt: now,
            createdBy: principal.identity.id,
            updatedAt: now,
            updatedBy: principal.identity.id,
          });
          await audit(tx, principal, 'billing:plan', realm.id, `billing/plans/${plan.id}`, {
            key,
            name: plan.name,
            items: plan.items.length,
            selfServe: plan.selfServe,
          });
          return planView(plan, 0);
        },
        true,
      ),

    /**
     * Changes a plan (by id or key): any of `name`, `items`, `description` (null clears), `trialDays` (null clears),
     * `selfServe`, `archived` (no new subscriptions). Changes apply to invoices drawn up afterwards. Root administrators
     * only; audited as `billing:plan-update`.
     */
    updatePlan: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        plan: string;
        name?: string;
        items?: unknown[];
        description?: string | null;
        trialDays?: number | null;
        selfServe?: boolean;
        archived?: boolean;
      },
    ): Promise<PlanView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/plans',
        async ({ tx, tenant: realm, principal }) => {
          onRoot(realm, 'Plans');
          const plan = await planByRef(tx, realm, input.plan);
          const fields = planSettings(object(input), plan);
          const { description: _description, trialDays: _trial, ...rest } = plan;
          const next = await tx.put<BillingPlan>(plansCollection, {
            ...rest,
            ...fields,
            updatedAt: ctx.now(),
            updatedBy: principal.identity.id,
          });
          await audit(tx, principal, 'billing:plan-update', realm.id, `billing/plans/${plan.id}`, {
            key: plan.key,
            fields: Object.keys(input).filter((key) => key !== 'tenantId' && key !== 'plan'),
          });
          return planView(next);
        },
        true,
      ),

    /**
     * Subscriptions of the billing accounts in the tenant's subtree (ended ones with `includeEnded`), newest first.
     * Requires iam:billing:read.
     */
    listSubscriptions: async (
      credential: CredentialInput,
      input: { tenantId: string; includeEnded?: boolean },
    ): Promise<SubscriptionView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/subscriptions',
        async ({ tx, tenant: realm }) => {
          const covered = await coveredAccounts(tx, realm);
          const now = ctx.now();
          const names = new Map<string, string | undefined>();
          const result: SubscriptionView[] = [];
          for (const subscription of await tx.find<BillingSubscription>(subscriptionsCollection)) {
            if (covered && !covered.has(subscription.tenantId)) continue;
            if (input.includeEnded !== true && subscriptionStatus(subscription, now) === 'ended')
              continue;
            if (!names.has(subscription.tenantId))
              names.set(
                subscription.tenantId,
                (await tx.get<Tenant>('tenants', subscription.tenantId))?.name,
              );
            result.push(subscriptionView(subscription, now, names.get(subscription.tenantId)));
          }
          return result.sort((a, b) => b.startedAt - a.startedAt);
        },
      ),

    /**
     * Subscribes the billing account to a plan (id or key) with `seats` (default 1). Outside a trial the first month's
     * advance fees and seats are invoiced at once, prorated from today. Account billing managers
     * (`iam:billing:manage`) may subscribe to self-serve plans; root administrators to any plan, and may set
     * `trialDays` (0 for none). Audited as `billing:subscription`.
     */
    subscribe: async (
      credential: CredentialInput,
      input: { tenantId: string; plan: string; seats?: number; trialDays?: number },
    ): Promise<{ subscription: SubscriptionView; invoice?: StatementSummary }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/subscriptions',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const account = await ownAccount(tx, realm);
          const plan = await planByRef(tx, realm, input.plan);
          const admin = await mayManage(tx, principal, [plan]);
          if (input.trialDays !== undefined && !admin)
            throw new OperationDenied('Only root administrators set trial days');
          const seats = input.seats === undefined ? 1 : integer(input.seats, 'seats', 0, 1_000_000);
          const trialDays =
            input.trialDays === undefined
              ? undefined
              : integer(input.trialDays, 'trialDays', 0, 365);
          const { subscription, invoice } = await service.subscribe(
            tx,
            account,
            plan,
            { seats, ...(trialDays !== undefined ? { trialDays } : {}) },
            principal.identity.id,
          );
          await audit(
            tx,
            principal,
            'billing:subscription',
            realm.id,
            `billing/subscriptions/${subscription.id}`,
            {
              plan: plan.key,
              seats,
              ...(subscription.trialEndsAt !== undefined
                ? { trialEndsAt: subscription.trialEndsAt }
                : {}),
              ...(invoice ? { invoice: invoice.number, totalMicros: invoice.totalMicros } : {}),
            },
          );
          const now = ctx.now();
          return {
            subscription: subscriptionView(subscription, now, account.name),
            ...(invoice ? { invoice: summary(invoice, now, account.name) } : {}),
          };
        },
      ),

    /**
     * Changes a subscription's seats; seats already billed in advance for this month are prorated as invoice items on
     * the next invoice. Self-serve plans for account billing managers, any for root administrators. Audited as
     * `billing:subscription-update`.
     */
    updateSubscription: async (
      credential: CredentialInput,
      input: { tenantId: string; subscriptionId: string; seats: number },
    ): Promise<{ subscription: SubscriptionView; invoiceItems: InvoiceItemView[] }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/subscriptions',
        async ({ tx, tenant: realm, principal }) => {
          const subscription = await ctx.scoped<BillingSubscription>(
            tx,
            subscriptionsCollection,
            text(input.subscriptionId, 'subscriptionId'),
            realm.id,
          );
          const plan = await tx.get<BillingPlan>(plansCollection, subscription.planId);
          if (plan) await mayManage(tx, principal, [plan]);
          const seats = integer(input.seats, 'seats', 0, 1_000_000);
          const result = await service.updateSeats(tx, subscription, seats, principal.identity.id);
          await audit(
            tx,
            principal,
            'billing:subscription-update',
            realm.id,
            `billing/subscriptions/${subscription.id}`,
            {
              plan: subscription.planKey,
              seats: { before: subscription.seats, after: seats },
              prorationMicros: roundMicros(
                result.items.reduce((sum, item) => sum + item.amountMicros, 0),
              ),
            },
          );
          return {
            subscription: subscriptionView(result.subscription, ctx.now(), realm.name),
            invoiceItems: result.items.map(invoiceItemView),
          };
        },
      ),

    /**
     * Cancels a subscription at the end of the month (default; it runs until then and can be resumed) or, with
     * `atPeriodEnd: false`, now: the unused part of this month's advance charges is credited on the next invoice.
     * Account billing managers cancel self-serve plans at the end of the month; root administrators any, either way.
     * Audited as `billing:subscription-cancel`.
     */
    cancelSubscription: async (
      credential: CredentialInput,
      input: { tenantId: string; subscriptionId: string; atPeriodEnd?: boolean },
    ): Promise<{ subscription: SubscriptionView; invoiceItems: InvoiceItemView[] }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/subscriptions',
        async ({ tx, tenant: realm, principal }) => {
          const subscription = await ctx.scoped<BillingSubscription>(
            tx,
            subscriptionsCollection,
            text(input.subscriptionId, 'subscriptionId'),
            realm.id,
          );
          if (input.atPeriodEnd !== undefined && typeof input.atPeriodEnd !== 'boolean')
            throw new IamError('INVALID_INPUT', 'atPeriodEnd must be a boolean');
          const atPeriodEnd = input.atPeriodEnd ?? true;
          const plan = await tx.get<BillingPlan>(plansCollection, subscription.planId);
          const admin = plan
            ? await mayManage(tx, principal, [plan])
            : await ctx.rootPrincipal(tx, principal);
          if (!atPeriodEnd && !admin)
            throw new OperationDenied('Only root administrators cancel a subscription immediately');
          const result = await service.cancelSubscription(
            tx,
            subscription,
            atPeriodEnd,
            principal.identity.id,
          );
          await audit(
            tx,
            principal,
            'billing:subscription-cancel',
            realm.id,
            `billing/subscriptions/${subscription.id}`,
            {
              plan: subscription.planKey,
              atPeriodEnd,
              endsAt: result.subscription.endsAt ?? null,
              prorationMicros: roundMicros(
                result.items.reduce((sum, item) => sum + item.amountMicros, 0),
              ),
            },
          );
          return {
            subscription: subscriptionView(result.subscription, ctx.now(), realm.name),
            invoiceItems: result.items.map(invoiceItemView),
          };
        },
      ),

    /** Undoes a cancellation at the end of the month before it takes effect. Audited as `billing:subscription-resume`. */
    resumeSubscription: async (
      credential: CredentialInput,
      input: { tenantId: string; subscriptionId: string },
    ): Promise<SubscriptionView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/subscriptions',
        async ({ tx, tenant: realm, principal }) => {
          const subscription = await ctx.scoped<BillingSubscription>(
            tx,
            subscriptionsCollection,
            text(input.subscriptionId, 'subscriptionId'),
            realm.id,
          );
          const plan = await tx.get<BillingPlan>(plansCollection, subscription.planId);
          if (plan) await mayManage(tx, principal, [plan]);
          const next = await service.resumeSubscription(tx, subscription);
          await audit(
            tx,
            principal,
            'billing:subscription-resume',
            realm.id,
            `billing/subscriptions/${subscription.id}`,
            { plan: subscription.planKey },
          );
          return subscriptionView(next, ctx.now(), realm.name);
        },
      ),

    /**
     * Moves a subscription to another plan (id or key) now, keeping its seats and what is left of its trial; the old
     * plan's unused advance charges are credited and the new plan's charges for the rest of the month added as
     * invoice items for the next invoice. Both plans must be self-serve for account billing managers. Audited as
     * `billing:subscription-plan-change`.
     */
    changePlan: async (
      credential: CredentialInput,
      input: { tenantId: string; subscriptionId: string; plan: string },
    ): Promise<{ subscription: SubscriptionView; invoiceItems: InvoiceItemView[] }> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/subscriptions',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const subscription = await ctx.scoped<BillingSubscription>(
            tx,
            subscriptionsCollection,
            text(input.subscriptionId, 'subscriptionId'),
            realm.id,
          );
          const current = await tx.get<BillingPlan>(plansCollection, subscription.planId);
          const plan = await planByRef(tx, realm, input.plan);
          await mayManage(tx, principal, current ? [current, plan] : [plan]);
          const result = await service.changePlan(tx, subscription, plan, principal.identity.id);
          await audit(
            tx,
            principal,
            'billing:subscription-plan-change',
            realm.id,
            `billing/subscriptions/${result.subscription.id}`,
            {
              from: subscription.planKey,
              to: plan.key,
              previousSubscriptionId: subscription.id,
              prorationMicros: roundMicros(
                result.items.reduce((sum, item) => sum + item.amountMicros, 0),
              ),
            },
          );
          return {
            subscription: subscriptionView(result.subscription, ctx.now(), realm.name),
            invoiceItems: result.items.map(invoiceItemView),
          };
        },
      ),

    // ---------------------------------------------------------------------------------------------------------
    // Coupons and discounts

    /** The platform's coupons, newest first. Called on the root tenant; root administrators only. */
    listCoupons: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<CouponView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/coupons',
        async ({ tx, tenant: realm }) => {
          onRoot(realm, 'Coupons');
          const now = ctx.now();
          return (await tx.find<BillingCoupon>(couponsCollection, { tenantId: realm.id }))
            .sort((a, b) => b.createdAt - a.createdAt)
            .map((coupon) => couponView(coupon, now));
        },
        true,
      ),

    /**
     * Creates a coupon on the platform (root) tenant: a `code` accounts redeem, `percentOff` or `amountOff` (currency
     * units), a `duration` (`once`: the next invoice; `repeating`: invoices for `durationInMonths` months from
     * redemption; `forever`), and optional `maxRedemptions` and `redeemBy`. Root administrators only; audited as
     * `billing:coupon`.
     */
    createCoupon: async (
      credential: CredentialInput,
      input: {
        tenantId: string;
        code: string;
        name?: string;
        percentOff?: number;
        amountOff?: number;
        duration?: BillingCoupon['duration'];
        durationInMonths?: number;
        maxRedemptions?: number;
        redeemBy?: number;
      },
    ): Promise<CouponView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/coupons',
        async ({ tx, tenant: realm, principal }) => {
          onRoot(realm, 'Coupons');
          const now = ctx.now();
          const fields = couponSettings(object(input), now);
          if (
            (
              await tx.find<BillingCoupon>(couponsCollection, {
                tenantId: realm.id,
                uniqueKey: `code:${fields.code}`,
              })
            ).length
          )
            throw new IamError('CONFLICT', 'A coupon with this code already exists', 409);
          const coupon = await tx.insert<BillingCoupon>(couponsCollection, {
            id: id(),
            tenantId: realm.id,
            uniqueKey: `code:${fields.code}`,
            ...fields,
            redemptions: 0,
            active: true,
            createdAt: now,
            createdBy: principal.identity.id,
          });
          await audit(tx, principal, 'billing:coupon', realm.id, `billing/coupons/${coupon.id}`, {
            code: coupon.code,
            ...(coupon.percentOff !== undefined ? { percentOff: coupon.percentOff } : {}),
            ...(coupon.amountOffMicros !== undefined
              ? { amountOffMicros: coupon.amountOffMicros }
              : {}),
            duration: coupon.duration,
          });
          return couponView(coupon, now);
        },
        true,
      ),

    /**
     * Stops a coupon (by code) from being redeemed; accounts that redeemed it keep their discount. Root administrators
     * only; audited as `billing:coupon-deactivate`.
     */
    deactivateCoupon: async (
      credential: CredentialInput,
      input: { tenantId: string; code: string },
    ): Promise<CouponView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/coupons',
        async ({ tx, tenant: realm, principal }) => {
          onRoot(realm, 'Coupons');
          const code = couponCode(input.code);
          const coupon = (
            await tx.find<BillingCoupon>(couponsCollection, {
              tenantId: realm.id,
              uniqueKey: `code:${code}`,
            })
          )[0];
          if (!coupon) throw new IamError('NOT_FOUND', 'Coupon not found', 404);
          const next = await tx.put<BillingCoupon>(couponsCollection, { ...coupon, active: false });
          await audit(
            tx,
            principal,
            'billing:coupon-deactivate',
            realm.id,
            `billing/coupons/${coupon.id}`,
            { code },
          );
          return couponView(next, ctx.now());
        },
        true,
      ),

    /**
     * Redeems a coupon code for the billing account: its discount applies to the account's invoices for the coupon's
     * duration, after the contract discount. Once per coupon per account. Requires iam:billing:manage on the account;
     * audited as `billing:coupon-redeem`.
     */
    redeemCoupon: async (
      credential: CredentialInput,
      input: { tenantId: string; code: string },
    ): Promise<DiscountView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/discounts',
        async ({ tx, tenant: realm, principal }) => {
          writable(realm);
          const account = await ownAccount(tx, realm);
          const code = couponCode(input.code);
          const root = await rootOf(tx, realm);
          const now = ctx.now();
          const coupon = (
            await tx.find<BillingCoupon>(couponsCollection, {
              tenantId: root.id,
              uniqueKey: `code:${code}`,
            })
          )[0];
          if (
            coupon &&
            (
              await tx.find<BillingDiscount>(discountsCollection, {
                tenantId: account.id,
                uniqueKey: `coupon:${coupon.id}`,
              })
            ).length
          )
            throw new IamError('CONFLICT', 'The account has already redeemed this code', 409);
          // Unknown, inactive, expired and used-up codes look the same to the account.
          if (!coupon || !couponView(coupon, now).active)
            throw new IamError('NOT_FOUND', 'This code is not valid', 404);
          await tx.put<BillingCoupon>(couponsCollection, {
            ...coupon,
            redemptions: coupon.redemptions + 1,
          });
          const discount = await tx.insert<BillingDiscount>(discountsCollection, {
            id: id(),
            tenantId: account.id,
            uniqueKey: `coupon:${coupon.id}`,
            couponId: coupon.id,
            code: coupon.code,
            name: coupon.name,
            ...(coupon.percentOff !== undefined ? { percentOff: coupon.percentOff } : {}),
            ...(coupon.amountOffMicros !== undefined
              ? { amountOffMicros: coupon.amountOffMicros }
              : {}),
            duration: coupon.duration,
            ...(coupon.durationInMonths !== undefined
              ? { durationInMonths: coupon.durationInMonths }
              : {}),
            appliedInvoices: 0,
            redeemedAt: now,
            redeemedBy: principal.identity.id,
          });
          await audit(
            tx,
            principal,
            'billing:coupon-redeem',
            realm.id,
            `billing/discounts/${discount.id}`,
            { code, couponId: coupon.id },
          );
          return discountView(discount, service.currentPeriod(), settings.timeZone);
        },
      ),

    /** Discounts (redeemed coupons) of the billing accounts in the tenant's subtree. Requires iam:billing:read. */
    listDiscounts: async (
      credential: CredentialInput,
      input: { tenantId: string },
    ): Promise<DiscountView[]> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:read',
        'billing/discounts',
        async ({ tx, tenant: realm }) => {
          const covered = await coveredAccounts(tx, realm);
          const period = service.currentPeriod();
          return (await tx.find<BillingDiscount>(discountsCollection))
            .filter((discount) => !covered || covered.has(discount.tenantId))
            .sort((a, b) => b.redeemedAt - a.redeemedAt)
            .map((discount) => discountView(discount, period, settings.timeZone));
        },
      ),

    /** Ends a discount of the billing account now. Root administrators only; audited as `billing:discount-remove`. */
    removeDiscount: async (
      credential: CredentialInput,
      input: { tenantId: string; discountId: string },
    ): Promise<DiscountView> =>
      operation(
        credential,
        input.tenantId,
        'iam:billing:manage',
        'billing/discounts',
        async ({ tx, tenant: realm, principal }) => {
          const discount = await ctx.scoped<BillingDiscount>(
            tx,
            discountsCollection,
            text(input.discountId, 'discountId'),
            realm.id,
          );
          if (discount.endedAt !== undefined)
            throw new IamError('INVALID_TRANSITION', 'The discount has already ended', 409);
          const next = await tx.put<BillingDiscount>(discountsCollection, {
            ...discount,
            endedAt: ctx.now(),
          });
          await audit(
            tx,
            principal,
            'billing:discount-remove',
            realm.id,
            `billing/discounts/${discount.id}`,
            { code: discount.code },
          );
          return discountView(next, service.currentPeriod(), settings.timeZone);
        },
        true,
      ),
  };
}

/** `iam.billing`: trusted metering, checks, reports and the scheduler jobs. */
export function createBillingRuntime(ctx: ServerContext): IamBilling {
  const service = billingServiceOf(ctx);
  return {
    settings: service.settings,
    record: (input) =>
      ctx.store.transaction((tx) =>
        service.record(
          tx,
          input,
          'deployment',
          input.enforceBudgets === true ? { enforceBudgets: true } : {},
        ),
      ),
    async recordMany(events) {
      if (!Array.isArray(events) || events.length === 0 || events.length > 1000)
        throw new IamError('INVALID_INPUT', 'events must list 1-1000 usage events');
      return ctx.store.transaction(async (tx) => {
        const receipts: UsageReceipt[] = [];
        for (const event of events) receipts.push(await service.record(tx, event, 'deployment'));
        return receipts;
      });
    },
    check: (input) =>
      ctx.store.transaction(async (tx) =>
        service.check(tx, await ctx.tenant(tx, text(input.tenantId, 'tenantId')), {
          ...(input.identityId !== undefined ? { identityId: input.identityId } : {}),
          ...(input.meter !== undefined ? { meter: input.meter } : {}),
        }),
      ),
    spend: ({ tenantId, ...query }) =>
      ctx.store.transaction(async (tx) =>
        service.report(tx, await ctx.tenant(tx, text(tenantId, 'tenantId')), query),
      ),
    recordSeats: service.recordSeats,
    checkBudgets: service.checkBudgets,
    closePeriod: service.closePeriod,
    detectAnomalies: service.detectAnomalies,
    sendPaymentReminders: service.sendPaymentReminders,
    recordPayment: (input) =>
      ctx.store.transaction(async (tx) => {
        let statement: BillingStatement | undefined;
        if (input.statementId !== undefined)
          statement = await tx.get<BillingStatement>(
            statementsCollection,
            text(input.statementId, 'statementId'),
          );
        else if (input.number !== undefined)
          statement = (
            await tx.find<BillingStatement>(statementsCollection, {
              number: text(input.number, 'number', 64),
            })
          )[0];
        else throw new IamError('INVALID_INPUT', 'Give statementId or number');
        if (!statement) throw new IamError('NOT_FOUND', 'Statement not found', 404);
        const key =
          input.idempotencyKey === undefined
            ? undefined
            : text(input.idempotencyKey, 'idempotencyKey', 128);
        // The processor's payment id doubles as the payment reference.
        if (key !== undefined && statement.payments?.some((payment) => payment.reference === key))
          return { statement, duplicate: true };
        const { idempotencyKey: _key, statementId: _id, number: _number, ...payment } = input;
        const result = await service.recordPayment(
          tx,
          statement,
          { ...payment, ...(key !== undefined ? { reference: key } : {}) },
          'deployment',
        );
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: statement.tenantId,
          actorId: 'deployment-operator',
          action: 'billing:payment',
          resourceId: `billing/statements/${statement.id}`,
          timestamp: ctx.now(),
          outcome: 'allow',
          metadata: {
            number: statement.number,
            amountMicros: result.payment.amountMicros,
            method: result.payment.method,
            ...(result.payment.reference ? { reference: result.payment.reference } : {}),
            status: result.statement.status,
          },
        });
        return { ...result, duplicate: false };
      }),
  };
}
