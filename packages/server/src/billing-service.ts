import {
  IamError,
  findOrdered,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Tenant,
} from '@better-iam/core';
import {
  accountOf,
  accountSpend,
  accountTermsOf,
  amountDue,
  amountMicros,
  amountPaid,
  attributionFor,
  billingCollections,
  billingPeriod,
  billingSettings,
  dayOf,
  directoryFor,
  discountActive,
  inDepartment,
  invoiceAmounts,
  meterKey,
  periodBounds,
  periodOf,
  priceBreakdown,
  profileOf,
  resolveMeter,
  roundCents,
  roundMicros,
  rollupId,
  scopeSpend,
  shiftPeriod,
  statementHash,
  subscriptionStatus,
  subtree,
  teamShare,
  unitsOf,
  usageExpiry,
  usageTags,
  windowPeriods,
  type BillingBudget,
  type BillingBudgetAlert,
  type BillingCredit,
  type BillingCreditNote,
  type BillingDiscount,
  type BillingInvoiceItem,
  type BillingMeter,
  type BillingPlan,
  type BillingRollup,
  type BillingSettings,
  type BillingStatement,
  type BillingSubscription,
  type BillingTerms,
  type BillingUsageRecord,
  type BudgetPeriodKind,
  type BudgetSubjectType,
  type ChargedRow,
  type Directory,
  type InvoicePayment,
  type MeterCharge,
  type SpendCache,
  type StatementAllocation,
  type StatementBody,
  type StatementLine,
  type UsageInput,
  type UsageReceipt,
} from './billing.js';
import { creditNoteReason } from './billing-invoices.js';
import { firstPeriodLines, prorationItems, subscriptionLines } from './billing-plans.js';
import type { ServerContext } from './context.js';
import {
  departmentChain,
  departmentHeads,
  departmentOf,
  departmentPath,
  type Department,
} from './departments.js';
import { teamChain, teamDescendants, teamMaintainers, teamsOf, type Team } from './teams.js';
import { id } from './utils.js';
import { integer, text } from './validation.js';

const {
  meters: metersCollection,
  usage: usageCollection,
  rollups: rollupsCollection,
  budgets: budgetsCollection,
  budgetAlerts: alertsCollection,
  credits: creditsCollection,
  statements: statementsCollection,
  invoiceItems: invoiceItemsCollection,
  creditNotes: creditNotesCollection,
  plans: plansCollection,
  subscriptions: subscriptionsCollection,
  discounts: discountsCollection,
  terms: termsCollection,
} = billingCollections;

/** How spend reports group their rows. `tag:{name}` groups by a usage tag. */
export type SpendGroupBy =
  | 'meter'
  | 'identity'
  | 'agent'
  | 'team'
  | 'department'
  | 'tenant'
  | 'day'
  | `tag:${string}`;

/** Narrows a spend report to part of its scope. */
export interface SpendFilters {
  /** Only this meter key. */
  meter?: string;
  /** Only usage by this person, service account or agent. */
  identityId?: string;
  /** Only usage attributed to this team (and the teams below it unless `rollUp` is false). */
  teamId?: string;
  /** Only usage of people in this department (and those below it unless `rollUp` is false). */
  departmentId?: string;
  /** Only usage in this tenant (a project) and the tenants below it. */
  subTenantId?: string;
  /** Include descendant teams and departments (default true). */
  rollUp?: boolean;
  /** Only what statements bill: leaves out chargeback meters an account defines for itself. */
  billableOnly?: boolean;
}

export interface SpendQuery extends SpendFilters {
  /** `YYYY-MM`; the current period by default. */
  period?: string;
  groupBy?: SpendGroupBy;
  /**
   * Grouped by identity, agent, team or department: spread the spend nobody in that dimension caused (shared
   * services, project-level usage) over the groups that did, in proportion to their spend (showback).
   */
  shareUnattributed?: boolean;
}

/** One group of a spend report. */
export interface SpendRow {
  key: string;
  label?: string;
  costMicros: number;
  /** `costMicros` in currency units, rounded to the cent. */
  amount: number;
  /** Percent of the report's total (0-100, one decimal). */
  share: number;
  events: number;
  /** Quantity per meter key (a row may mix units). */
  quantities: Record<string, number>;
  /** With `shareUnattributed`: the part of `costMicros` that is this group's share of unattributed spend. */
  sharedMicros?: number;
}

export interface SpendReport {
  tenantId: string;
  currency: string;
  period: string;
  periodStart: number;
  periodEnd: number;
  groupBy: SpendGroupBy;
  rows: SpendRow[];
  total: { costMicros: number; amount: number; events: number };
  /** For the current period: the total projected linearly to the end of the period. */
  forecast?: { costMicros: number; amount: number };
  /** With `shareUnattributed`: the unattributed spend that was spread over the groups. */
  sharedMicros?: number;
}

export interface SpendTrend {
  tenantId: string;
  currency: string;
  months: { period: string; costMicros: number; amount: number }[];
  /** Projection of the current period (the last month). */
  forecast?: { costMicros: number; amount: number };
}

/** A budget with its spend in the current window. */
export interface BudgetStatus {
  budgetId: string;
  tenantId: string;
  name: string;
  subjectType: BudgetSubjectType;
  subjectId: string;
  subjectName?: string;
  period: BudgetPeriodKind;
  /** First and last billing period of the current window. */
  windowStart: string;
  windowEnd: string;
  amountMicros: number;
  amount: number;
  spentMicros: number;
  spent: number;
  /** Spent as a percent of the amount (one decimal). */
  percent: number;
  forecastMicros?: number;
  forecastPercent?: number;
  thresholds: number[];
  /** Thresholds already reached in this window. */
  reached: number[];
  exceeded: boolean;
  enforce: boolean;
  meters?: string[];
}

/** Whether usage may go ahead under the enforced budgets that cover it. */
export interface SpendCheck {
  allowed: boolean;
  /** Every enforced budget that covers the usage. */
  budgets: BudgetStatus[];
  /** The first spent budget, when refused. */
  blockedBy?: BudgetStatus;
}

export interface BudgetAlertResult {
  checked: number;
  alerts: {
    budgetId: string;
    tenantId: string;
    name: string;
    kind: 'actual' | 'forecast';
    threshold: number;
    spentMicros: number;
    recipients: number;
  }[];
}

export interface ClosePeriodResult {
  period: string;
  issued: {
    accountId: string;
    statementId: string;
    number: string;
    totalMicros: number;
    recipients: number;
  }[];
  /** Invoices kept (or refreshed) as drafts (`draft`, or `billing.autoFinalize: false`). */
  drafted: { accountId: string; statementId: string; totalMicros: number }[];
  skipped: { existing: number; empty: number };
  /** Raw usage events past their retention that were deleted. */
  sweptUsage: number;
}

export interface SeatRecordResult {
  meter: string;
  day: string;
  recorded: number;
  duplicates: number;
  /** Tenants the meter does not reach (or where it is archived). */
  skippedTenants: number;
  /** Tenants whose seats could not be recorded (the others still are). */
  failedTenants: { tenantId: string; code: string; message: string }[];
}

/** Usage another module has already priced (AI inference): recorded on a `reported` meter. */
export interface PricedUsageInput {
  tenantId: string;
  meter: string;
  /** Cost in micros (fractions allowed). */
  costMicros: number;
  quantity?: number;
  identityId?: string;
  agentId?: string;
  tags?: Record<string, string>;
  /** The source record: makes the push idempotent. */
  sourceId?: string;
  occurredAt?: number;
}

/** What other server modules call to feed the ledger. */
export interface BillingHooks {
  /**
   * Records already-priced usage in the caller's transaction. Never throws: billing problems must not fail the work
   * being billed. A meter the tenant does not have yet is defined on the root tenant for the built-in keys
   * (`inference`); other unknown meters are skipped.
   */
  recordPriced(tx: IamStore, input: PricedUsageInput): Promise<void>;
}

/** Settings of anomaly detection. */
export interface AnomalyOptions {
  /** The day to check, `YYYY-MM-DD` in the billing time zone (default yesterday). */
  day?: string;
  /** Days before it that make the baseline average (3 to 90, default 14). */
  baselineDays?: number;
  /** How many times the baseline counts as a spike (1.1 to 1000, default 3). */
  factor?: number;
  /** Smallest spend and increase worth reporting, in currency units (default 10). */
  minimum?: number;
}

/** A person, team or meter whose spend on one day jumped. */
export interface SpendAnomaly {
  dimension: 'identity' | 'team' | 'meter';
  key: string;
  label?: string;
  day: string;
  costMicros: number;
  /** Average daily spend over the baseline days. */
  baselineMicros: number;
  /** `costMicros / baselineMicros`, rounded; null for new spending (no baseline). */
  factor: number | null;
}

export interface AnomalyAlertResult {
  checked: number;
  anomalies: (SpendAnomaly & { accountId: string; recipients: number })[];
}

/** A statement before it is numbered and stored (`previewStatement`, `closePeriod`). */
export interface StatementDraft extends StatementBody {
  accountId: string;
  paymentTermsDays: number;
  /** Pending invoice items the invoice bills. */
  invoiceItemIds: string[];
  /** Subscription months it bills in advance. */
  advanceBilled: { subscriptionId: string; period: string }[];
  /** A negative balance (credit items above the charges) that becomes account credit when it is finalized. */
  carryForwardMicros: number;
}

/** What `sendPaymentReminders` sent. */
export interface PaymentReminderResult {
  /** Open invoices looked at. */
  checked: number;
  reminders: {
    statementId: string;
    accountId: string;
    number: string;
    /** The reminder step: days relative to the due date. */
    step: number;
    amountDueMicros: number;
    recipients: number;
  }[];
}

interface RecordExtras {
  costMicros?: number;
  agentId?: string;
  sourceId?: string;
  enforceBudgets?: boolean;
  meter?: BillingMeter;
}

/** Built-in reported meters other modules push to; defined on the root tenant the first time they are used. */
const builtInMeters: Record<string, Pick<BillingMeter, 'name' | 'unit' | 'description'>> = {
  inference: {
    name: 'AI inference',
    unit: 'token',
    description: 'Model calls through inference access control, at each model’s token prices.',
  },
};

/** Whether a key names a built-in meter: only the platform (the root tenant) defines those. */
export function builtInMeterKey(key: string): boolean {
  return Object.hasOwn(builtInMeters, key);
}

const statusCacheMs = 30_000;
const unattributed = {
  identity: '(unattributed)',
  agent: '(none)',
  team: '(no team)',
  department: '(no department)',
  tag: '(untagged)',
} as const;

const oneDecimal = (value: number) => Math.round(value * 10) / 10;
/** The group that holds unattributed spend, per dimension that can share it out. */
const sharedPools = {
  identity: unattributed.identity,
  agent: unattributed.agent,
  team: unattributed.team,
  department: unattributed.department,
} as const;

/** Formats micros as money in the deployment currency (for emails). */
export function formatMoney(micros: number, currency: string): string {
  try {
    return new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(unitsOf(micros));
  } catch {
    return `${currency} ${unitsOf(micros).toFixed(2)}`;
  }
}

function spendGroupBy(value: unknown): SpendGroupBy {
  if (
    value === 'meter' ||
    value === 'identity' ||
    value === 'agent' ||
    value === 'team' ||
    value === 'department' ||
    value === 'tenant' ||
    value === 'day'
  )
    return value;
  if (typeof value === 'string' && /^tag:[A-Za-z][A-Za-z0-9_.:-]{0,63}$/.test(value))
    return value as SpendGroupBy;
  throw new IamError(
    'INVALID_INPUT',
    "groupBy must be 'meter', 'identity', 'agent', 'team', 'department', 'tenant', 'day' or 'tag:{name}'",
  );
}

/**
 * The billing engine behind the `billing` API group and `iam.billing`: recording, spend reports, budgets and alerts,
 * statements and credits, and the seat recorder.
 */
export function createBillingService(ctx: ServerContext) {
  const settings: BillingSettings = billingSettings(ctx.options.billing);
  const tz = settings.timeZone;
  const { store } = ctx;
  const currentPeriod = () => periodOf(ctx.now(), tz);
  const statusCache = new Map<string, { at: number; updatedAt: number; status: BudgetStatus }>();

  const receipt = (record: BillingUsageRecord, duplicate: boolean): UsageReceipt => ({
    id: record.id,
    tenantId: record.tenantId,
    meter: record.meter,
    quantity: record.quantity,
    ...(record.costMicros !== undefined ? { costMicros: record.costMicros } : {}),
    period: record.period,
    occurredAt: record.occurredAt,
    ...(record.identityId !== undefined ? { identityId: record.identityId } : {}),
    teamIds: record.teamIds,
    ...(record.departmentId !== undefined ? { departmentId: record.departmentId } : {}),
    duplicate,
  });

  /** The non-void statement of an account for a period, if it has been invoiced. */
  async function statementFor(
    tx: IamStore,
    accountId: string,
    period: string,
  ): Promise<BillingStatement | undefined> {
    return (
      await tx.find<BillingStatement>(statementsCollection, {
        tenantId: accountId,
        uniqueKey: `period:${period}`,
      })
    )[0];
  }

  async function record(
    tx: IamStore,
    input: UsageInput,
    recordedBy: string,
    extra: RecordExtras = {},
  ): Promise<UsageReceipt> {
    const tenant = await ctx.tenant(tx, text(input.tenantId, 'tenantId'));
    if (tenant.status === 'deleted')
      throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot record usage');
    const chain = await ctx.ancestry(tx, tenant);
    const key = meterKey(input.meter);
    const meter = extra.meter ?? (await resolveMeter(tx, chain, key));
    if (!meter) throw new IamError('NOT_FOUND', `Unknown billing meter ${key}`, 404);
    if (meter.archived)
      throw new IamError('METER_ARCHIVED', 'This meter no longer accepts usage', 409);
    const quantity = input.quantity === undefined ? 1 : input.quantity;
    if (
      typeof quantity !== 'number' ||
      !Number.isFinite(quantity) ||
      quantity < 0 ||
      quantity > 1e15
    )
      throw new IamError('INVALID_INPUT', 'quantity must be a number from 0 to 1e15');
    let costMicros: number | undefined;
    if (meter.pricing === 'reported') {
      costMicros =
        extra.costMicros ??
        (input.cost === undefined ? undefined : amountMicros(input.cost, 'cost'));
      if (costMicros === undefined)
        throw new IamError('INVALID_INPUT', 'This meter needs the cost of each event (cost)');
      costMicros = roundMicros(costMicros);
    } else if (input.cost !== undefined || extra.costMicros !== undefined)
      throw new IamError(
        'INVALID_INPUT',
        'This meter is priced from the rate card; leave cost out',
      );
    const now = ctx.now();
    const occurredAt =
      input.occurredAt === undefined
        ? now
        : integer(input.occurredAt, 'occurredAt', 0, Number.MAX_SAFE_INTEGER);
    if (occurredAt > now + 300_000)
      throw new IamError('INVALID_INPUT', 'occurredAt must not be in the future');
    if (occurredAt < now - 366 * 86_400_000)
      throw new IamError('INVALID_INPUT', 'occurredAt must be within the last year');
    const period = periodOf(occurredAt, tz);
    const uniqueKey =
      input.idempotencyKey !== undefined
        ? `idem:${text(input.idempotencyKey, 'idempotencyKey', 200)}`
        : extra.sourceId !== undefined
          ? `src:${meter.key}:${extra.sourceId}`
          : undefined;
    if (uniqueKey) {
      const existing = (
        await tx.find<BillingUsageRecord>(usageCollection, { tenantId: tenant.id, uniqueKey })
      )[0];
      if (existing) {
        if (existing.meterId !== meter.id)
          throw new IamError('CONFLICT', 'This idempotency key was used for another meter', 409);
        return receipt(existing, true);
      }
    }
    const account = await accountOf(ctx, tx, tenant);
    // A draft invoice is recomputed when it is finalized, so its period still takes usage.
    const invoiced = await statementFor(tx, account.id, period);
    if (invoiced && invoiced.status !== 'draft')
      throw new IamError(
        'BILLING_PERIOD_CLOSED',
        `${period} has already been invoiced for this billing account`,
        409,
      );
    // Attribution stays inside the organization: only trusted server code and platform (root tenant) identities
    // attribute usage to the platform's own people and teams, whose budgets and reports it would count toward.
    const recorder =
      recordedBy === 'deployment' ? undefined : await tx.get<Identity>('identities', recordedBy);
    const attributable =
      recordedBy === 'deployment' || recorder?.tenantId === chain.at(-1)!.id
        ? chain
        : chain.slice(0, -1);
    const attribution = await attributionFor(
      ctx,
      tx,
      attributable,
      {
        ...(input.identityId !== undefined ? { identityId: input.identityId } : {}),
        ...(extra.agentId !== undefined ? { agentId: extra.agentId } : {}),
        ...(input.teamId !== undefined ? { teamId: input.teamId } : {}),
      },
      settings,
    );
    if (meter.aggregation === 'unique' && !attribution.identityId)
      throw new IamError('INVALID_INPUT', 'Meters that count people need identityId');
    const tags = usageTags(input.tags);
    if (extra.enforceBudgets) {
      const verdict = await check(tx, tenant, {
        ...(attribution.identityId !== undefined ? { identityId: attribution.identityId } : {}),
        meter: meter.key,
      });
      if (!verdict.allowed)
        throw new IamError(
          'SPEND_LIMIT_REACHED',
          `The budget “${verdict.blockedBy!.name}” is spent`,
          402,
        );
    }
    const day = dayOf(occurredAt, tz);
    const bucket = {
      ...(attribution.identityId !== undefined ? { identityId: attribution.identityId } : {}),
      ...(attribution.agentId !== undefined ? { agentId: attribution.agentId } : {}),
      teamIds: attribution.teamIds,
      ...(attribution.departmentId !== undefined ? { departmentId: attribution.departmentId } : {}),
      ...(tags ? { tags } : {}),
    };
    const bucketId = rollupId(tenant.id, day, meter.id, bucket);
    const existingBucket = await tx.get<BillingRollup>(rollupsCollection, bucketId);
    if (existingBucket)
      await tx.put<BillingRollup>(rollupsCollection, {
        ...existingBucket,
        quantity: existingBucket.quantity + quantity,
        costMicros: roundMicros(existingBucket.costMicros + (costMicros ?? 0)),
        events: existingBucket.events + 1,
        updatedAt: now,
      });
    else
      await tx.insert<BillingRollup>(rollupsCollection, {
        id: bucketId,
        tenantId: tenant.id,
        period,
        day,
        meterId: meter.id,
        meter: meter.key,
        ...bucket,
        quantity,
        costMicros: costMicros ?? 0,
        events: 1,
        updatedAt: now,
      });
    const stored = await tx.insert<BillingUsageRecord>(usageCollection, {
      id: id(),
      tenantId: tenant.id,
      ...(uniqueKey ? { uniqueKey } : {}),
      meterId: meter.id,
      meter: meter.key,
      quantity,
      ...(costMicros !== undefined ? { costMicros } : {}),
      ...bucket,
      occurredAt,
      period,
      day,
      recordedAt: now,
      recordedBy,
      ...(extra.sourceId !== undefined ? { sourceId: extra.sourceId } : {}),
      rollupId: bucketId,
      expiresAt: usageExpiry(period, settings),
    });
    return receipt(stored, false);
  }

  /** Defines a built-in reported meter on the root tenant the first time a module pushes to it. */
  async function builtInMeter(tx: IamStore, chain: Tenant[], key: string) {
    if (!builtInMeterKey(key)) return undefined;
    const known = builtInMeters[key]!;
    const root = chain.at(-1)!;
    const now = ctx.now();
    return tx.insert<BillingMeter>(metersCollection, {
      id: id(),
      tenantId: root.id,
      uniqueKey: key,
      key,
      ...known,
      aggregation: 'sum',
      pricing: 'reported',
      archived: false,
      createdAt: now,
      createdBy: 'deployment',
      updatedAt: now,
      updatedBy: 'deployment',
    });
  }

  const hooks: BillingHooks = {
    async recordPriced(tx, input) {
      try {
        const tenant = await tx.get<Tenant>('tenants', input.tenantId);
        if (!tenant || tenant.status === 'deleted') return;
        const chain = await ctx.ancestry(tx, tenant);
        const key = meterKey(input.meter);
        // A built-in meter is always the platform's, even where a tenant defined a meter with its key.
        const meter = builtInMeterKey(key)
          ? ((await resolveMeter(tx, chain.slice(-1), key)) ?? (await builtInMeter(tx, chain, key)))
          : await resolveMeter(tx, chain, key);
        if (!meter || meter.archived) return;
        const identity =
          input.identityId !== undefined
            ? await tx.get<Identity>('identities', input.identityId)
            : undefined;
        await record(
          tx,
          {
            tenantId: tenant.id,
            meter: key,
            quantity: Math.max(0, input.quantity ?? 1),
            // Identities outside the tenant's ancestry (or gone) leave the usage unattributed.
            ...(identity &&
            identity.status !== 'deleted' &&
            chain.some((realm) => realm.id === identity.tenantId)
              ? { identityId: identity.id }
              : {}),
            ...(input.tags ? { tags: input.tags } : {}),
            ...(input.occurredAt !== undefined ? { occurredAt: input.occurredAt } : {}),
          },
          'deployment',
          {
            meter,
            ...(meter.pricing === 'reported' ? { costMicros: Math.max(0, input.costMicros) } : {}),
            ...(input.agentId !== undefined ? { agentId: input.agentId } : {}),
            ...(input.sourceId !== undefined ? { sourceId: input.sourceId } : {}),
          },
        );
      } catch {
        // Billing never fails the work it bills.
      }
    },
  };

  /** Reads the teams and departments of the tenants in play, for filters, roll-ups and labels. */
  async function directory(tx: IamStore, rows: ChargedRow[], extra: string[] = []) {
    const tenantIds = new Set(extra);
    for (const row of rows) tenantIds.add(row.tenantId);
    // Teams and departments live in the person's tenant, often the organization above a project.
    for (const tenantId of [...tenantIds])
      for (const ancestor of await ctx.ancestorIds(tx, tenantId)) tenantIds.add(ancestor);
    return directoryFor(tx, tenantIds);
  }

  /** The weight (0-1) with which a row counts under the filters. */
  function weigher(
    filters: SpendFilters,
    dir: Directory,
    within: Set<string> | undefined,
  ): (row: ChargedRow) => number {
    const rollUp = filters.rollUp !== false;
    return (row) => {
      if (filters.billableOnly && row.internal) return 0;
      if (filters.meter !== undefined && row.meter !== filters.meter) return 0;
      if (within && !within.has(row.tenantId)) return 0;
      if (
        filters.identityId !== undefined &&
        row.identityId !== filters.identityId &&
        row.agentId !== filters.identityId
      )
        return 0;
      if (
        filters.departmentId !== undefined &&
        !inDepartment(row, filters.departmentId, dir, rollUp)
      )
        return 0;
      if (filters.teamId !== undefined)
        return teamShare(row, filters.teamId, dir, settings, rollUp);
      return 1;
    };
  }

  async function validateFilters(
    tx: IamStore,
    scope: Tenant,
    input: SpendFilters,
  ): Promise<{ filters: SpendFilters; within?: Set<string> }> {
    const filters: SpendFilters = {};
    if (input.meter !== undefined) filters.meter = meterKey(input.meter);
    if (input.identityId !== undefined) filters.identityId = text(input.identityId, 'identityId');
    if (input.rollUp !== undefined) {
      if (typeof input.rollUp !== 'boolean')
        throw new IamError('INVALID_INPUT', 'rollUp must be a boolean');
      filters.rollUp = input.rollUp;
    }
    if (input.billableOnly !== undefined) {
      if (typeof input.billableOnly !== 'boolean')
        throw new IamError('INVALID_INPUT', 'billableOnly must be a boolean');
      filters.billableOnly = input.billableOnly;
    }
    let tenants: Set<string> | undefined;
    const inScope = async () =>
      (tenants ??= new Set((await subtree(ctx, tx, scope)).map((realm) => realm.id)));
    // Teams and departments of the scope, or of the organization a project belongs to.
    const reachable = async (tenantId: string) =>
      (await inScope()).has(tenantId) || (await ctx.ancestorIds(tx, scope.id)).includes(tenantId);
    if (input.teamId !== undefined) {
      const team = await tx.get<Team>('teams', text(input.teamId, 'teamId'));
      if (!team || !(await reachable(team.tenantId)))
        throw new IamError('NOT_FOUND', 'Team not found', 404);
      filters.teamId = team.id;
    }
    if (input.departmentId !== undefined) {
      const department = await tx.get<Department>(
        'departments',
        text(input.departmentId, 'departmentId'),
      );
      if (!department || !(await reachable(department.tenantId)))
        throw new IamError('NOT_FOUND', 'Department not found', 404);
      filters.departmentId = department.id;
    }
    let within: Set<string> | undefined;
    if (input.subTenantId !== undefined) {
      const sub = await ctx.tenant(tx, text(input.subTenantId, 'subTenantId'));
      if (!(await inScope()).has(sub.id)) throw new IamError('NOT_FOUND', 'Tenant not found', 404);
      filters.subTenantId = sub.id;
      within = new Set((await subtree(ctx, tx, sub)).map((realm) => realm.id));
    }
    return { filters, ...(within ? { within } : {}) };
  }

  /** Labels for report keys. */
  async function labelFor(
    tx: IamStore,
    groupBy: SpendGroupBy,
    key: string,
    dir: Directory,
    meterNames: Map<string, string>,
  ): Promise<string | undefined> {
    if (key.startsWith('(')) return undefined;
    switch (groupBy) {
      case 'identity':
      case 'agent': {
        const identity = await tx.get<Identity>('identities', key);
        if (!identity) return undefined;
        return identity.email ? `${identity.name} <${identity.email}>` : identity.name;
      }
      case 'team':
        return dir.teams.get(key)?.name;
      case 'department': {
        const department = dir.departments.get(key);
        return department
          ? department.code
            ? `${department.name} (${department.code})`
            : department.name
          : undefined;
      }
      case 'tenant':
        return (await tx.get<Tenant>('tenants', key))?.name;
      case 'meter':
        return meterNames.get(key);
      default:
        return undefined;
    }
  }

  function forecastOf(period: string, totalMicros: number) {
    if (period !== currentPeriod()) return undefined;
    const bounds = periodBounds(period, tz);
    const elapsed = ctx.now() - bounds.start;
    if (elapsed < 86_400_000) return undefined;
    const costMicros = roundMicros((totalMicros * (bounds.end - bounds.start)) / elapsed);
    return { costMicros, amount: unitsOf(costMicros) };
  }

  /** Weighted rows of a scope and period under validated filters. */
  async function weightedRows(
    tx: IamStore,
    scope: Tenant,
    period: string,
    input: SpendFilters,
    cache: SpendCache,
    rowFilter?: (row: ChargedRow) => boolean,
  ) {
    const { filters, within } = await validateFilters(tx, scope, input);
    const { rows } = await scopeSpend(ctx, tx, scope, period, cache);
    const dir = await directory(tx, rows, [scope.id]);
    const weigh = weigher(filters, dir, within);
    const weighted: { row: ChargedRow; weight: number }[] = [];
    for (const row of rows) {
      if (rowFilter && !rowFilter(row)) continue;
      const weight = weigh(row);
      if (weight > 0) weighted.push({ row, weight });
    }
    return { weighted, dir, filters };
  }

  async function report(
    tx: IamStore,
    scope: Tenant,
    query: SpendQuery,
    cache: SpendCache = new Map(),
    rowFilter?: (row: ChargedRow) => boolean,
  ): Promise<SpendReport> {
    const period = query.period === undefined ? currentPeriod() : billingPeriod(query.period);
    const groupBy = spendGroupBy(query.groupBy ?? 'meter');
    const { weighted, dir, filters } = await weightedRows(
      tx,
      scope,
      period,
      query,
      cache,
      rowFilter,
    );
    const groups = new Map<string, SpendRow>();
    const add = (key: string, row: ChargedRow, weight: number) => {
      const group =
        groups.get(key) ??
        ({ key, costMicros: 0, amount: 0, share: 0, events: 0, quantities: {} } as SpendRow);
      group.costMicros += row.costMicros * weight;
      group.events += row.events;
      group.quantities[row.meter] = (group.quantities[row.meter] ?? 0) + row.quantity * weight;
      groups.set(key, group);
    };
    // Grouping by team under a team filter keeps to the filter's teams.
    const allowedTeams =
      filters.teamId === undefined
        ? undefined
        : new Set([
            filters.teamId,
            ...(filters.rollUp === false
              ? []
              : teamDescendants(dir.teams.values(), filters.teamId).map((team) => team.id)),
          ]);
    let totalMicros = 0;
    let events = 0;
    for (const { row, weight } of weighted) {
      totalMicros += row.costMicros * weight;
      events += row.events;
      switch (groupBy) {
        case 'team': {
          const teams = row.teamIds.filter((team) => !allowedTeams || allowedTeams.has(team));
          if (!row.teamIds.length) add(unattributed.team, row, weight);
          const each = settings.teamAttribution === 'full' ? 1 : 1 / row.teamIds.length;
          for (const team of teams) add(team, row, each);
          break;
        }
        case 'meter':
          add(row.meter, row, weight);
          break;
        case 'identity':
          add(row.identityId ?? unattributed.identity, row, weight);
          break;
        case 'agent':
          add(row.agentId ?? unattributed.agent, row, weight);
          break;
        case 'department':
          add(row.departmentId ?? unattributed.department, row, weight);
          break;
        case 'tenant':
          add(row.tenantId, row, weight);
          break;
        case 'day':
          add(row.day, row, weight);
          break;
        default:
          add(row.tags?.[groupBy.slice(4)] ?? unattributed.tag, row, weight);
      }
    }
    totalMicros = roundMicros(totalMicros);
    const meterNames = new Map<string, string>();
    if (groupBy === 'meter')
      for (const { row } of weighted)
        if (!meterNames.has(row.meter)) {
          const meter = await tx.get<BillingMeter>(metersCollection, row.meterId);
          if (meter) meterNames.set(row.meter, meter.name);
        }
    // Shared costs: what no person, team or department used is spread over those that did, by their share of spend.
    let sharedMicros: number | undefined;
    const pool = sharedPools[groupBy as keyof typeof sharedPools];
    if (query.shareUnattributed === true && pool && groups.has(pool)) {
      const unassigned = groups.get(pool)!;
      const others = [...groups.values()].filter((group) => group.key !== pool);
      const base = others.reduce((sum, group) => sum + group.costMicros, 0);
      if (base > 0) {
        for (const group of others) {
          const extra = (unassigned.costMicros * group.costMicros) / base;
          group.costMicros += extra;
          group.sharedMicros = roundMicros(extra);
        }
        sharedMicros = roundMicros(unassigned.costMicros);
        groups.delete(pool);
      }
    } else if (
      query.shareUnattributed !== undefined &&
      typeof query.shareUnattributed !== 'boolean'
    )
      throw new IamError('INVALID_INPUT', 'shareUnattributed must be a boolean');
    const rows: SpendRow[] = [];
    for (const group of groups.values()) {
      group.costMicros = roundMicros(group.costMicros);
      group.amount = unitsOf(group.costMicros);
      group.share = totalMicros > 0 ? oneDecimal((group.costMicros / totalMicros) * 100) : 0;
      for (const meter of Object.keys(group.quantities))
        group.quantities[meter] = Math.round(group.quantities[meter]! * 1e6) / 1e6;
      const label = await labelFor(tx, groupBy, group.key, dir, meterNames);
      rows.push(label !== undefined ? { ...group, label } : group);
    }
    rows.sort(
      (a, b) =>
        b.costMicros - a.costMicros ||
        (groupBy === 'day' ? (a.key < b.key ? -1 : 1) : a.key < b.key ? -1 : 1),
    );
    if (groupBy === 'day') rows.sort((a, b) => (a.key < b.key ? -1 : 1));
    const bounds = periodBounds(period, tz);
    const forecast = forecastOf(period, totalMicros);
    return {
      tenantId: scope.id,
      currency: settings.currency,
      period,
      periodStart: bounds.start,
      periodEnd: bounds.end,
      groupBy,
      rows,
      total: { costMicros: totalMicros, amount: unitsOf(totalMicros), events },
      ...(forecast ? { forecast } : {}),
      ...(sharedMicros !== undefined ? { sharedMicros } : {}),
    };
  }

  async function trend(
    tx: IamStore,
    scope: Tenant,
    input: SpendFilters & { months?: number },
    rowFilter?: (row: ChargedRow) => boolean,
  ): Promise<SpendTrend> {
    const months = input.months === undefined ? 6 : integer(input.months, 'months', 1, 24);
    const cache: SpendCache = new Map();
    const current = currentPeriod();
    const result: SpendTrend['months'] = [];
    let last: SpendReport | undefined;
    for (let index = months - 1; index >= 0; index--) {
      last = await report(
        tx,
        scope,
        { ...input, period: shiftPeriod(current, -index), groupBy: 'meter' },
        cache,
        rowFilter,
      );
      result.push({
        period: last.period,
        costMicros: last.total.costMicros,
        amount: last.total.amount,
      });
    }
    return {
      tenantId: scope.id,
      currency: settings.currency,
      months: result,
      ...(last?.forecast ? { forecast: last.forecast } : {}),
    };
  }

  // -------------------------------------------------------------------------------------------------------------
  // Budgets

  async function subjectName(
    tx: IamStore,
    type: BudgetSubjectType,
    subjectId: string,
  ): Promise<string | undefined> {
    switch (type) {
      case 'tenant':
        return (await tx.get<Tenant>('tenants', subjectId))?.name;
      case 'identity':
        return (await tx.get<Identity>('identities', subjectId))?.name;
      case 'team':
        return (await tx.get<Team>('teams', subjectId))?.name;
      case 'department':
        return (await tx.get<Department>('departments', subjectId))?.name;
    }
  }

  async function budgetStatus(
    tx: IamStore,
    budget: BillingBudget,
    cache: SpendCache = new Map(),
  ): Promise<BudgetStatus> {
    const current = currentPeriod();
    const periods = windowPeriods(budget.period, current);
    const owner = await ctx.tenant(tx, budget.tenantId);
    const scope =
      budget.subjectType === 'tenant'
        ? ((await tx.get<Tenant>('tenants', budget.subjectId)) ?? owner)
        : owner;
    let spent = 0;
    for (const period of periods) {
      if (period > current) break;
      const { rows, accounts } = await scopeSpend(ctx, tx, scope, period, cache);
      // Chargeback meters an account defines and prices for itself count toward its own budgets, never toward budgets
      // set above it (the platform's), which an organization could otherwise spend with made-up prices.
      const foreign = new Set<ChargedRow>();
      for (const spend of accounts)
        if (
          spend.accountId !== owner.id &&
          (await ctx.ancestorIds(tx, spend.accountId)).includes(owner.id)
        )
          for (const row of spend.rows) if (row.internal) foreign.add(row);
      const dir =
        budget.subjectType === 'team' || budget.subjectType === 'department'
          ? await directory(tx, rows, [owner.id])
          : undefined;
      for (const row of rows) {
        if (budget.meters && !budget.meters.includes(row.meter)) continue;
        if (foreign.has(row)) continue;
        const weight =
          budget.subjectType === 'tenant'
            ? 1
            : budget.subjectType === 'identity'
              ? row.identityId === budget.subjectId || row.agentId === budget.subjectId
                ? 1
                : 0
              : budget.subjectType === 'team'
                ? teamShare(row, budget.subjectId, dir!, settings, true)
                : inDepartment(row, budget.subjectId, dir!, true)
                  ? 1
                  : 0;
        spent += row.costMicros * weight;
      }
    }
    const spentMicros = roundMicros(spent);
    const start = periodBounds(periods[0]!, tz).start;
    const end = periodBounds(periods.at(-1)!, tz).end;
    const elapsed = ctx.now() - start;
    const forecastMicros =
      elapsed >= 86_400_000 ? roundMicros((spentMicros * (end - start)) / elapsed) : undefined;
    const percent = oneDecimal((spentMicros / budget.amountMicros) * 100);
    const name = await subjectName(tx, budget.subjectType, budget.subjectId);
    return {
      budgetId: budget.id,
      tenantId: budget.tenantId,
      name: budget.name,
      subjectType: budget.subjectType,
      subjectId: budget.subjectId,
      ...(name !== undefined ? { subjectName: name } : {}),
      period: budget.period,
      windowStart: periods[0]!,
      windowEnd: periods.at(-1)!,
      amountMicros: budget.amountMicros,
      amount: unitsOf(budget.amountMicros),
      spentMicros,
      spent: unitsOf(spentMicros),
      percent,
      ...(forecastMicros !== undefined
        ? {
            forecastMicros,
            forecastPercent: oneDecimal((forecastMicros / budget.amountMicros) * 100),
          }
        : {}),
      thresholds: budget.thresholds,
      reached: budget.thresholds.filter(
        (threshold) => spentMicros >= (budget.amountMicros * threshold) / 100,
      ),
      exceeded: spentMicros >= budget.amountMicros,
      enforce: budget.enforce,
      ...(budget.meters ? { meters: budget.meters } : {}),
    };
  }

  /** Budget status for enforcement, cached briefly so checks on hot paths stay cheap. */
  async function cachedStatus(tx: IamStore, budget: BillingBudget, cache: SpendCache) {
    const hit = statusCache.get(budget.id);
    const now = ctx.now();
    if (hit && hit.updatedAt === budget.updatedAt && now - hit.at < statusCacheMs)
      return hit.status;
    const status = await budgetStatus(tx, budget, cache);
    statusCache.set(budget.id, { at: now, updatedAt: budget.updatedAt, status });
    if (statusCache.size > 10_000) statusCache.delete(statusCache.keys().next().value!);
    return status;
  }

  /**
   * The enforced budgets covering usage in `tenant` (by `identityId`, of `meter`): tenant budgets on the tenant or an
   * ancestor, the person's own budgets, and budgets of their teams (and parent teams) and departments. Refused once
   * one is spent. Statuses may lag recorded usage by up to 30 seconds.
   */
  async function check(
    tx: IamStore,
    tenant: Tenant,
    input: { identityId?: string; meter?: string },
  ): Promise<SpendCheck> {
    const statuses = await coveringStatuses(tx, tenant, { ...input, enforcedOnly: true });
    const blockedBy = statuses.find((status) => status.exceeded);
    return { allowed: !blockedBy, budgets: statuses, ...(blockedBy ? { blockedBy } : {}) };
  }

  /** The (cached) standing of every budget covering usage in `tenant` by `identityId` (of `meter`). */
  async function coveringStatuses(
    tx: IamStore,
    tenant: Tenant,
    input: { identityId?: string; meter?: string; enforcedOnly: boolean },
  ): Promise<BudgetStatus[]> {
    const chain = await ctx.ancestry(tx, tenant);
    const chainIds = new Set(chain.map((realm) => realm.id));
    let identityIds: string[] = [];
    let teams: string[] = [];
    let departments: string[] = [];
    if (input.identityId !== undefined) {
      const identity = await tx.get<Identity>('identities', text(input.identityId, 'identityId'));
      if (identity) {
        const person =
          identity.kind === 'agent' && identity.agent?.sponsorId
            ? identity.agent.sponsorId
            : identity.id;
        identityIds = [...new Set([identity.id, person])];
        teams = await teamsOf(tx, identity.tenantId, person, {
          at: ctx.now(),
          includeAncestors: true,
        });
        const departmentId = await departmentOf(tx, identity.tenantId, person);
        if (departmentId) departments = await departmentPath(tx, identity.tenantId, departmentId);
      }
    }
    const meter = input.meter === undefined ? undefined : meterKey(input.meter);
    const cache: SpendCache = new Map();
    const statuses: BudgetStatus[] = [];
    for (const realm of chain)
      for (const budget of await tx.find<BillingBudget>(
        budgetsCollection,
        input.enforcedOnly ? { tenantId: realm.id, enforce: true } : { tenantId: realm.id },
      )) {
        if (budget.meters && meter !== undefined && !budget.meters.includes(meter)) continue;
        const covers =
          budget.subjectType === 'tenant'
            ? chainIds.has(budget.subjectId)
            : budget.subjectType === 'identity'
              ? identityIds.includes(budget.subjectId)
              : budget.subjectType === 'team'
                ? teams.includes(budget.subjectId)
                : departments.includes(budget.subjectId);
        if (covers) statuses.push(await cachedStatus(tx, budget, cache));
      }
    return statuses;
  }

  /**
   * Policy context: `principal.budgetsExceeded` names every spent budget that covers the principal in `tenant` (tenant
   * budgets up the tree, and for a person of the tenant their own, their teams' and their department's), and
   * `principal.spendExceeded` is true when one of them is enforced. Statuses may lag usage by up to 30 seconds.
   */
  async function spendContext(
    tx: IamStore,
    tenant: Tenant,
    identityId: string | undefined,
  ): Promise<{ 'principal.spendExceeded': boolean; 'principal.budgetsExceeded': string[] }> {
    const exceeded = (
      await coveringStatuses(tx, tenant, {
        ...(identityId !== undefined ? { identityId } : {}),
        enforcedOnly: false,
      })
    ).filter((status) => status.exceeded);
    return {
      'principal.spendExceeded': exceeded.some((status) => status.enforce),
      'principal.budgetsExceeded': [...new Set(exceeded.map((status) => status.name))].sort(),
    };
  }

  async function emailsOf(tx: IamStore, identityIds: Iterable<string>): Promise<string[]> {
    const result: string[] = [];
    for (const identityId of identityIds) {
      const identity = await tx.get<Identity>('identities', identityId);
      if (identity?.status === 'active' && identity.email) result.push(identity.email);
    }
    return result;
  }

  async function owners(tx: IamStore, tenantId: string): Promise<string[]> {
    return (await tx.find<Identity>('identities', { tenantId, owner: true, status: 'active' }))
      .map((owner) => owner.email)
      .filter((address): address is string => Boolean(address));
  }

  async function budgetRecipients(tx: IamStore, budget: BillingBudget): Promise<string[]> {
    const addresses = new Set<string>(budget.notify.emails);
    if (budget.notify.owners)
      for (const address of await owners(tx, budget.tenantId)) addresses.add(address);
    if (budget.notify.subject) {
      const subjectIds: string[] = [];
      if (budget.subjectType === 'identity') subjectIds.push(budget.subjectId);
      else if (budget.subjectType === 'team') {
        const team = await tx.get<Team>('teams', budget.subjectId);
        if (team)
          subjectIds.push(...(await teamMaintainers(tx, team.tenantId, team.id, ctx.now())));
      } else if (budget.subjectType === 'department') {
        const department = await tx.get<Department>('departments', budget.subjectId);
        if (department)
          subjectIds.push(...(await departmentHeads(tx, department.tenantId, department.id)));
      }
      for (const address of await emailsOf(tx, subjectIds)) addresses.add(address);
    }
    return [...addresses].sort();
  }

  /**
   * Alerts on budgets: every threshold reached in the current window (once each), and a forecast alert when the
   * projection passes 100%. Each alert is audited as `billing:budget-alert` (webhooks can forward it) and, with an
   * email transport, sent to the budget's recipients as `spend-alert`. A scheduler job; `tenantId` limits it to the
   * budgets that tenant owns.
   */
  async function checkBudgets(input: { tenantId?: string } = {}): Promise<BudgetAlertResult> {
    const budgets = await store.transaction((tx) =>
      tx.find<BillingBudget>(
        budgetsCollection,
        input.tenantId === undefined ? {} : { tenantId: text(input.tenantId, 'tenantId') },
      ),
    );
    const result: BudgetAlertResult = { checked: 0, alerts: [] };
    const cache: SpendCache = new Map();
    for (const candidate of budgets.sort((a, b) => (a.id < b.id ? -1 : 1)))
      await store.transaction(async (tx) => {
        const budget = await tx.get<BillingBudget>(budgetsCollection, candidate.id);
        if (!budget) return;
        const owner = await tx.get<Tenant>('tenants', budget.tenantId);
        // Pending and suspended tenants can still spend; only deleted ones are done.
        if (!owner || owner.status === 'deleted') return;
        result.checked++;
        const status = await budgetStatus(tx, budget, cache);
        const due: { kind: 'actual' | 'forecast'; threshold: number }[] = [
          ...status.reached.map((threshold) => ({ kind: 'actual' as const, threshold })),
          ...(budget.forecastAlerts && !status.exceeded && (status.forecastPercent ?? 0) >= 100
            ? [{ kind: 'forecast' as const, threshold: 100 }]
            : []),
        ];
        const fired: typeof due = [];
        for (const alert of due) {
          const uniqueKey = `${budget.id}:${status.windowStart}:${alert.kind}:${alert.threshold}`;
          if ((await tx.find(alertsCollection, { tenantId: budget.tenantId, uniqueKey })).length)
            continue;
          await tx.insert<BillingBudgetAlert>(alertsCollection, {
            id: id(),
            tenantId: budget.tenantId,
            uniqueKey,
            budgetId: budget.id,
            window: status.windowStart,
            kind: alert.kind,
            threshold: alert.threshold,
            spentMicros: status.spentMicros,
            alertedAt: ctx.now(),
          });
          fired.push(alert);
        }
        if (!fired.length) return;
        const recipients = ctx.options.authentication?.sendEmail
          ? await budgetRecipients(tx, budget)
          : [];
        // One email per check: the highest threshold newly reached (or the forecast warning).
        const headline =
          fired
            .filter((alert) => alert.kind === 'actual')
            .sort((a, b) => b.threshold - a.threshold)[0] ?? fired[0]!;
        for (const to of recipients)
          await ctx.auth.enqueueDelivery(tx, {
            tenantId: budget.tenantId,
            kind: 'email',
            to,
            template: 'spend-alert',
            payload: {
              tenantId: budget.tenantId,
              tenantName: owner.name,
              budgetId: budget.id,
              budgetName: budget.name,
              subjectType: budget.subjectType,
              subjectName: status.subjectName ?? budget.subjectId,
              kind: headline.kind,
              threshold: String(headline.threshold),
              percent: String(status.percent),
              spent: formatMoney(status.spentMicros, settings.currency),
              amount: formatMoney(budget.amountMicros, settings.currency),
              ...(status.forecastMicros !== undefined
                ? { forecast: formatMoney(status.forecastMicros, settings.currency) }
                : {}),
              windowStart: status.windowStart,
              windowEnd: status.windowEnd,
            },
          });
        for (const alert of fired) {
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: budget.tenantId,
            actorId: 'deployment-operator',
            action: 'billing:budget-alert',
            resourceId: `billing/budgets/${budget.id}`,
            timestamp: ctx.now(),
            outcome: 'allow',
            metadata: {
              budgetId: budget.id,
              name: budget.name,
              kind: alert.kind,
              threshold: alert.threshold,
              spentMicros: status.spentMicros,
              amountMicros: budget.amountMicros,
              window: status.windowStart,
              recipients: recipients.length,
            },
          });
          result.alerts.push({
            budgetId: budget.id,
            tenantId: budget.tenantId,
            name: budget.name,
            kind: alert.kind,
            threshold: alert.threshold,
            spentMicros: status.spentMicros,
            recipients: recipients.length,
          });
        }
      });
    return result;
  }

  // -------------------------------------------------------------------------------------------------------------
  // Statements

  function allocations(
    rows: ChargedRow[],
    keyOf: (row: ChargedRow) => { key: string; weight: number }[],
    names: (key: string) => string | undefined,
    limit?: number,
  ): StatementAllocation[] {
    const totals = new Map<string, number>();
    for (const row of rows)
      for (const { key, weight } of keyOf(row))
        totals.set(key, (totals.get(key) ?? 0) + row.costMicros * weight);
    const list = [...totals]
      .map(([key, micros]) => ({
        id: key,
        name: names(key) ?? key,
        costMicros: roundMicros(micros),
      }))
      .filter((entry) => entry.costMicros > 0)
      .sort((a, b) => b.costMicros - a.costMicros || (a.id < b.id ? -1 : 1));
    return limit === undefined ? list : list.slice(0, limit);
  }

  /** Usage lines of an invoice: the billable meters, with the tiers and free units their quantity used. */
  function usageLines(charges: MeterCharge[]): StatementLine[] {
    return charges
      .filter((charge) => !charge.internal)
      .map((charge) => {
        const line: StatementLine = {
          meter: charge.meter,
          name: charge.name,
          unit: charge.unit,
          quantity: Math.round(charge.quantity * 1e6) / 1e6,
          // Invoices bill whole cents; the spend reports keep the exact amount.
          amountMicros: roundCents(charge.amountMicros),
          pricing: charge.pricing,
        };
        if (charge.price) {
          const { spec } = charge.price;
          line.price = {
            model: spec.model,
            effectiveFrom: charge.price.effectiveFrom,
            ...(charge.price.source === 'plan' ? { source: 'plan' as const } : {}),
          };
          const breakdown = priceBreakdown(spec, charge.quantity);
          if (spec.model === 'per-unit') line.unitAmountMicros = spec.unitAmountMicros ?? 0;
          if (breakdown.tiers.length) line.tiers = breakdown.tiers;
          if (breakdown.includedQuantity !== undefined)
            line.includedQuantity = breakdown.includedQuantity;
          if (breakdown.rawMicros !== charge.amountMicros)
            line.adjustedFromMicros = breakdown.rawMicros;
        }
        if (charge.unpriced) line.unpriced = true;
        return line;
      });
  }

  /** Pending invoice items the account's invoice for `period` bills: those without a period or for it or before. */
  async function pendingItems(
    tx: IamStore,
    accountId: string,
    period: string,
  ): Promise<BillingInvoiceItem[]> {
    return (
      await tx.find<BillingInvoiceItem>(invoiceItemsCollection, {
        tenantId: accountId,
        status: 'pending',
      })
    )
      .filter((item) => item.period === undefined || item.period <= period)
      .sort((a, b) => a.createdAt - b.createdAt || (a.id < b.id ? -1 : 1));
  }

  function invoiceItemLine(item: BillingInvoiceItem): StatementLine {
    return {
      kind: 'item',
      name: item.description,
      unit: 'unit',
      quantity: item.quantity,
      unitAmountMicros: item.unitAmountMicros,
      amountMicros: item.amountMicros,
      invoiceItemId: item.id,
      ...(item.subscriptionId !== undefined ? { subscriptionId: item.subscriptionId } : {}),
      ...(item.source === 'proration' ? { description: 'Proration' } : {}),
    };
  }

  /**
   * Builds (without storing) an account's invoice. The monthly invoice for `period` bills the month's usage, the
   * subscriptions' fees and seats (arrears for the month, advance for the next), and pending invoice items, and the
   * minimum commitment applies; a subscription's first invoice (`first`) bills its first month's advance lines. Then
   * the contract discount, coupons, credit (earliest expiry first) and tax.
   */
  async function draftStatement(
    tx: IamStore,
    account: Tenant,
    period: string,
    cache: SpendCache = new Map(),
    first?: { lines: StatementLine[]; subscriptionId: string },
  ): Promise<StatementDraft> {
    const bounds = periodBounds(period, tz);
    const lines: StatementLine[] = [];
    let rows: ChargedRow[] = [];
    let invoiceItemIds: string[] = [];
    let advanceBilled: StatementDraft['advanceBilled'] = [];
    if (first) {
      lines.push(...first.lines);
      advanceBilled = [{ subscriptionId: first.subscriptionId, period }];
    } else {
      const spend = await accountSpend(ctx, tx, account, period, cache);
      lines.push(...usageLines(spend.charges));
      rows = spend.rows.filter((row) => !row.internal);
      const recurring = await subscriptionLines(tx, account.id, period, tz);
      lines.push(...recurring.lines);
      advanceBilled = recurring.advance;
      const items = await pendingItems(tx, account.id, period);
      lines.push(...items.map(invoiceItemLine));
      invoiceItemIds = items.map((item) => item.id);
    }
    const subtotalMicros = roundMicros(lines.reduce((sum, line) => sum + line.amountMicros, 0));
    const credits = (await tx.find<BillingCredit>(creditsCollection, { tenantId: account.id }))
      .filter(
        (credit) =>
          // Any credit that is live when the statement is drawn up and was valid at some point in the period.
          credit.revokedAt === undefined &&
          credit.remainingMicros > 0 &&
          (credit.expiresAt === undefined || credit.expiresAt > bounds.start),
      )
      .sort(
        (a, b) =>
          (a.expiresAt ?? Number.MAX_SAFE_INTEGER) - (b.expiresAt ?? Number.MAX_SAFE_INTEGER) ||
          a.grantedAt - b.grantedAt ||
          (a.id < b.id ? -1 : 1),
      );
    const discounts = (
      await tx.find<BillingDiscount>(discountsCollection, { tenantId: account.id })
    )
      .filter((discount) => discountActive(discount, period, tz))
      .sort((a, b) => a.redeemedAt - b.redeemedAt || (a.id < b.id ? -1 : 1));
    const creditsApplied: StatementDraft['creditsApplied'] = [];
    const { carryForwardMicros, ...amounts } = invoiceAmounts({
      subtotalMicros,
      terms: await accountTermsOf(ctx, tx, account),
      commitment: !first,
      discounts,
      credit: (dueMicros) => {
        let due = dueMicros;
        for (const credit of credits) {
          if (due <= 0) break;
          const amount = roundMicros(Math.min(due, credit.remainingMicros));
          creditsApplied.push({ creditId: credit.id, amountMicros: amount });
          due = roundMicros(due - amount);
        }
        return roundMicros(dueMicros - due);
      },
    });
    const dir = await directory(tx, rows, [account.id]);
    const tenantNames = new Map<string, string>();
    for (const row of rows)
      if (!tenantNames.has(row.tenantId))
        tenantNames.set(
          row.tenantId,
          (await tx.get<Tenant>('tenants', row.tenantId))?.name ?? row.tenantId,
        );
    const identityNames = new Map<string, string>();
    for (const row of rows) {
      const key = row.agentId ?? row.identityId;
      if (key && !identityNames.has(key))
        identityNames.set(key, (await tx.get<Identity>('identities', key))?.name ?? key);
    }
    const profile = await profileOf(tx, account.id);
    const emails = profile?.billingEmails.length
      ? profile.billingEmails
      : await owners(tx, account.id);
    return {
      accountId: account.id,
      period,
      currency: settings.currency,
      periodStart: bounds.start,
      periodEnd: bounds.end,
      lines,
      billingReason: first ? 'subscription' : 'period',
      subtotalMicros,
      ...amounts,
      creditsApplied,
      breakdown: {
        tenants: allocations(
          rows,
          (row) => [{ key: row.tenantId, weight: 1 }],
          (key) => tenantNames.get(key),
        ),
        teams: allocations(
          rows,
          (row) =>
            row.teamIds.map((team) => ({
              key: team,
              weight: settings.teamAttribution === 'full' ? 1 : 1 / row.teamIds.length,
            })),
          (key) => dir.teams.get(key)?.name,
          50,
        ),
        departments: allocations(
          rows,
          (row) => (row.departmentId ? [{ key: row.departmentId, weight: 1 }] : []),
          (key) => dir.departments.get(key)?.name,
          50,
        ).map((entry) => {
          const costCenter = dir.departments.get(entry.id)?.costCenter;
          return costCenter ? { ...entry, costCenter } : entry;
        }),
        identities: allocations(
          rows,
          (row) => {
            const key = row.agentId ?? row.identityId;
            return key ? [{ key, weight: 1 }] : [];
          },
          (key) => identityNames.get(key),
          50,
        ),
      },
      billTo: {
        name: account.name,
        ...(profile?.companyName ? { companyName: profile.companyName } : {}),
        ...(profile?.taxId ? { taxId: profile.taxId } : {}),
        ...(profile?.address ? { address: profile.address } : {}),
        ...(profile?.purchaseOrder ? { purchaseOrder: profile.purchaseOrder } : {}),
        ...(profile?.costCenter ? { costCenter: profile.costCenter } : {}),
        emails,
      },
      paymentTermsDays: profile?.paymentTermsDays ?? settings.paymentTermsDays,
      invoiceItemIds,
      advanceBilled,
      carryForwardMicros,
    };
  }

  /** Stores (or refreshes) a monthly invoice as a draft: no number, nothing consumed yet. */
  async function saveDraft(
    tx: IamStore,
    account: Tenant,
    draft: StatementDraft,
    existing?: BillingStatement,
  ): Promise<BillingStatement> {
    const {
      accountId: _account,
      paymentTermsDays,
      carryForwardMicros: _carry,
      invoiceItemIds,
      advanceBilled,
      ...body
    } = draft;
    const now = ctx.now();
    const record: BillingStatement = {
      id: existing?.id ?? id(),
      tenantId: account.id,
      uniqueKey: `period:${draft.period}`,
      number: '',
      status: 'draft',
      issuedAt: now,
      dueAt: now + paymentTermsDays * 86_400_000,
      hash: '',
      ...body,
      ...(invoiceItemIds.length ? { invoiceItemIds } : {}),
      ...(advanceBilled.length ? { advanceBilled } : {}),
    };
    return existing
      ? tx.put<BillingStatement>(statementsCollection, record)
      : tx.insert<BillingStatement>(statementsCollection, record);
  }

  /**
   * Finalizes an invoice: numbers it (`{prefix}-{YYYYMM}-{sequence}`), seals its content hash, draws the credit it
   * uses, turns a negative balance into account credit, marks its invoice items invoiced and its advance months
   * billed, counts its coupons, emails the billing contacts (`billing-statement`) and audits `billing:statement`. An
   * invoice with nothing to pay is paid on issue.
   */
  async function issue(
    tx: IamStore,
    account: Tenant,
    draft: StatementDraft,
    options: { uniqueKey: string; existing?: BillingStatement; actorId?: string },
  ): Promise<{ statement: BillingStatement; recipients: number }> {
    const actorId = options.actorId ?? 'deployment-operator';
    const numbered = (
      await tx.find<BillingStatement>(statementsCollection, { period: draft.period })
    ).filter((statement) => statement.number).length;
    const number = `${settings.statementPrefix}-${draft.period.replace('-', '')}-${String(numbered + 1).padStart(4, '0')}`;
    const issuedAt = ctx.now();
    const {
      accountId: _account,
      paymentTermsDays,
      carryForwardMicros,
      invoiceItemIds,
      advanceBilled,
      ...body
    } = draft;
    const content: StatementBody = body;
    let carryForward: BillingStatement['carryForward'];
    if (carryForwardMicros > 0) {
      const credit = await tx.insert<BillingCredit>(creditsCollection, {
        id: id(),
        tenantId: account.id,
        amountMicros: carryForwardMicros,
        remainingMicros: carryForwardMicros,
        reason: `Credit balance from ${number}`,
        grantedAt: issuedAt,
        grantedBy: actorId,
      });
      carryForward = { creditId: credit.id, amountMicros: carryForwardMicros };
    }
    const settled = content.totalMicros <= 0;
    const record: BillingStatement = {
      id: options.existing?.id ?? id(),
      tenantId: account.id,
      uniqueKey: options.uniqueKey,
      number,
      status: settled ? 'paid' : 'finalized',
      issuedAt,
      dueAt: issuedAt + paymentTermsDays * 86_400_000,
      ...content,
      ...(invoiceItemIds.length ? { invoiceItemIds } : {}),
      ...(advanceBilled.length ? { advanceBilled } : {}),
      ...(carryForward ? { carryForward } : {}),
      ...(settled ? { paidAt: issuedAt } : {}),
      hash: statementHash({ ...content, number, tenantId: account.id }),
    };
    const statement = options.existing
      ? await tx.put<BillingStatement>(statementsCollection, record)
      : await tx.insert<BillingStatement>(statementsCollection, record);
    for (const applied of content.creditsApplied) {
      const credit = await tx.get<BillingCredit>(creditsCollection, applied.creditId);
      if (credit)
        await tx.put<BillingCredit>(creditsCollection, {
          ...credit,
          remainingMicros: roundMicros(Math.max(0, credit.remainingMicros - applied.amountMicros)),
        });
    }
    for (const itemId of invoiceItemIds) {
      const item = await tx.get<BillingInvoiceItem>(invoiceItemsCollection, itemId);
      if (item?.status === 'pending')
        await tx.put<BillingInvoiceItem>(invoiceItemsCollection, {
          ...item,
          status: 'invoiced',
          statementId: statement.id,
        });
    }
    for (const entry of advanceBilled) {
      const subscription = await tx.get<BillingSubscription>(
        subscriptionsCollection,
        entry.subscriptionId,
      );
      if (subscription && !subscription.billedAdvance.includes(entry.period))
        await tx.put<BillingSubscription>(subscriptionsCollection, {
          ...subscription,
          billedAdvance: [...subscription.billedAdvance, entry.period].sort(),
        });
    }
    for (const coupon of content.coupons ?? []) {
      const discount = await tx.get<BillingDiscount>(discountsCollection, coupon.discountId);
      if (discount)
        await tx.put<BillingDiscount>(discountsCollection, {
          ...discount,
          appliedInvoices: discount.appliedInvoices + 1,
          ...(discount.duration === 'once' ? { endedAt: issuedAt } : {}),
        });
    }
    const recipients = ctx.options.authentication?.sendEmail ? content.billTo.emails : [];
    for (const to of recipients)
      await ctx.auth.enqueueDelivery(tx, {
        tenantId: account.id,
        kind: 'email',
        to,
        template: 'billing-statement',
        payload: {
          tenantId: account.id,
          tenantName: account.name,
          statementId: statement.id,
          number,
          period: content.period,
          total: formatMoney(statement.totalMicros, settings.currency),
          subtotal: formatMoney(statement.subtotalMicros, settings.currency),
          credits: formatMoney(statement.creditsMicros, settings.currency),
          dueAt: new Date(statement.dueAt).toISOString().slice(0, 10),
          ...(content.billingReason === 'subscription' ? { reason: 'subscription' } : {}),
        },
      });
    await ctx.events.recordAudit(tx, {
      id: id(),
      tenantId: account.id,
      actorId,
      action: 'billing:statement',
      resourceId: `billing/statements/${statement.id}`,
      timestamp: issuedAt,
      outcome: 'allow',
      metadata: {
        number,
        period: content.period,
        billingReason: content.billingReason ?? 'period',
        subtotalMicros: statement.subtotalMicros,
        creditsMicros: statement.creditsMicros,
        totalMicros: statement.totalMicros,
        invoiceItems: invoiceItemIds.length,
        recipients: recipients.length,
      },
    });
    return { statement, recipients: recipients.length };
  }

  /** Whether a monthly invoice has something to bill: lines, or a minimum commitment the month fell short of. */
  const billable = (draft: StatementDraft) =>
    draft.lines.length > 0 || (draft.commitment?.trueUpMicros ?? 0) > 0;

  /** Finalizes a draft invoice, recomputed first so late usage and new invoice items are on it. */
  async function finalizeDraft(
    tx: IamStore,
    statement: BillingStatement,
    actorId?: string,
  ): Promise<{ statement: BillingStatement; recipients: number }> {
    if (statement.status !== 'draft')
      throw new IamError('INVALID_TRANSITION', `The invoice is ${statement.status}`, 409);
    const account = await ctx.tenant(tx, statement.tenantId);
    const draft = await draftStatement(tx, account, statement.period);
    if (!billable(draft))
      throw new IamError('INVALID_TRANSITION', 'The invoice has nothing left to bill', 409);
    return issue(tx, account, draft, {
      uniqueKey: `period:${statement.period}`,
      existing: statement,
      ...(actorId !== undefined ? { actorId } : {}),
    });
  }

  /** Deletes raw usage events past their retention (daily roll-ups and statements stay). */
  async function sweepUsage(): Promise<number> {
    let swept = 0;
    for (let round = 0; round < 50; round++) {
      const batch = await store.transaction(async (tx) => {
        const due = await findOrdered<BillingUsageRecord>(
          tx,
          usageCollection,
          {},
          {
            field: 'expiresAt',
            to: ctx.now(),
            limit: 500,
          },
        );
        for (const record of due) await tx.delete(usageCollection, record.id);
        return due.length;
      });
      swept += batch;
      if (batch < 500) break;
    }
    return swept;
  }

  /**
   * Invoices a past period (default the previous one): one invoice per billing account with something to bill (usage
   * of meters defined above it, subscription fees and seats, pending invoice items, a minimum commitment the month fell
   * short of). Accounts already invoiced for the
   * period are skipped, so the job can run daily. With `draft` (default: `!billing.autoFinalize`) invoices are kept as
   * drafts, refreshed on every run, until finalized (`finalizeInvoice`, or a run with `draft: false`). Usage for a
   * finalized period is refused afterwards (BILLING_PERIOD_CLOSED); void the invoice to reopen it. Also deletes raw
   * usage events past their retention.
   */
  async function closePeriod(
    input: { period?: string; tenantId?: string; draft?: boolean } = {},
  ): Promise<ClosePeriodResult> {
    const current = currentPeriod();
    const period =
      input.period === undefined ? shiftPeriod(current, -1) : billingPeriod(input.period);
    if (period >= current)
      throw new IamError('INVALID_INPUT', 'Only periods that have ended can be closed');
    if (input.draft !== undefined && typeof input.draft !== 'boolean')
      throw new IamError('INVALID_INPUT', 'draft must be a boolean');
    const draftOnly = input.draft ?? !settings.autoFinalize;
    const bounds = periodBounds(period, tz);
    const next = periodBounds(shiftPeriod(period, 1), tz);
    const accounts = await store.transaction(async (tx) => {
      const found = new Map<string, Tenant>();
      const add = async (tenantId: string) => {
        const realm = await tx.get<Tenant>('tenants', tenantId);
        if (!realm) return;
        const account = await accountOf(ctx, tx, realm);
        found.set(account.id, account);
      };
      if (input.tenantId !== undefined)
        await add((await ctx.tenant(tx, text(input.tenantId, 'tenantId'))).id);
      else {
        const tenantIds = new Set<string>();
        for (const rollup of await tx.find<BillingRollup>(rollupsCollection, { period }))
          tenantIds.add(rollup.tenantId);
        // Subscriptions running in the period or the next (advance billing), and pending invoice items.
        for (const subscription of await tx.find<BillingSubscription>(subscriptionsCollection))
          if (
            subscription.startedAt < next.end &&
            (subscription.endsAt === undefined || subscription.endsAt > bounds.start)
          )
            tenantIds.add(subscription.tenantId);
        for (const item of await tx.find<BillingInvoiceItem>(invoiceItemsCollection, {
          status: 'pending',
        }))
          if (item.period === undefined || item.period <= period) tenantIds.add(item.tenantId);
        // A minimum commitment is owed even for a month without usage (terms apply to invoices issued after them).
        for (const terms of await tx.find<BillingTerms>(termsCollection))
          if (
            terms.minimumCommitmentMicros &&
            (await tx.get<Tenant>('tenants', terms.tenantId))?.status !== 'deleted'
          )
            tenantIds.add(terms.tenantId);
        for (const tenantId of tenantIds) await add(tenantId);
      }
      return [...found.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
    });
    const result: ClosePeriodResult = {
      period,
      issued: [],
      drafted: [],
      skipped: { existing: 0, empty: 0 },
      sweptUsage: 0,
    };
    for (const candidate of accounts) {
      // The platform does not bill itself.
      if (candidate.parentId === null) continue;
      await store.transaction(async (tx) => {
        const account = await ctx.tenant(tx, candidate.id);
        const existing = await statementFor(tx, account.id, period);
        if (existing && existing.status !== 'draft') {
          result.skipped.existing++;
          return;
        }
        const draft = await draftStatement(tx, account, period);
        if (!billable(draft)) {
          if (existing) await tx.delete(statementsCollection, existing.id);
          result.skipped.empty++;
          return;
        }
        if (draftOnly) {
          const saved = await saveDraft(tx, account, draft, existing);
          result.drafted.push({
            accountId: account.id,
            statementId: saved.id,
            totalMicros: saved.totalMicros,
          });
          return;
        }
        const { statement, recipients } = await issue(tx, account, draft, {
          uniqueKey: `period:${period}`,
          ...(existing ? { existing } : {}),
        });
        result.issued.push({
          accountId: account.id,
          statementId: statement.id,
          number: statement.number,
          totalMicros: statement.totalMicros,
          recipients,
        });
      });
    }
    result.sweptUsage = await sweepUsage();
    return result;
  }

  /**
   * Voids a finalized invoice: its credit is restored (and credit it created revoked), its invoice items are pending
   * again, its advance months are unbilled, its coupons count one invoice less, and a monthly invoice's period reopens
   * for the account. Invoices with payments or credit notes cannot be voided; issue a credit note instead. Nor can one
   * whose credit balance (`carryForward`) a later invoice has used, until that invoice is voided.
   */
  async function voidStatement(
    tx: IamStore,
    statement: BillingStatement,
    principal: AuthenticatedPrincipal,
    reason: string,
  ): Promise<BillingStatement> {
    if (statement.status === 'void')
      throw new IamError('INVALID_TRANSITION', 'The statement is already void', 409);
    if (statement.status === 'draft')
      throw new IamError(
        'INVALID_TRANSITION',
        'Drafts are not voided; finalize the invoice or let the next close refresh it',
        409,
      );
    if ((statement.payments ?? []).length || (statement.creditNotesMicros ?? 0) > 0)
      throw new IamError(
        'INVALID_TRANSITION',
        'The invoice has payments or credit notes; issue a credit note instead',
        409,
      );
    // Voiding puts the invoice's credit items back up for the next invoice, so the credit balance they created must
    // still be whole: once a later invoice used it (or it was revoked), voiding would hand the credit out twice.
    const carried = statement.carryForward
      ? await tx.get<BillingCredit>(creditsCollection, statement.carryForward.creditId)
      : undefined;
    if (carried && carried.remainingMicros < carried.amountMicros)
      throw new IamError(
        'INVALID_TRANSITION',
        'The credit balance this invoice created has been used or revoked; void the invoices that used it first',
        409,
      );
    for (const applied of statement.creditsApplied) {
      const credit = await tx.get<BillingCredit>(creditsCollection, applied.creditId);
      if (credit)
        await tx.put<BillingCredit>(creditsCollection, {
          ...credit,
          remainingMicros: roundMicros(
            Math.min(credit.amountMicros, credit.remainingMicros + applied.amountMicros),
          ),
        });
    }
    const now = ctx.now();
    if (statement.carryForward) {
      const credit = await tx.get<BillingCredit>(
        creditsCollection,
        statement.carryForward.creditId,
      );
      if (credit && credit.revokedAt === undefined)
        await tx.put<BillingCredit>(creditsCollection, { ...credit, revokedAt: now });
    }
    for (const itemId of statement.invoiceItemIds ?? []) {
      const item = await tx.get<BillingInvoiceItem>(invoiceItemsCollection, itemId);
      if (item?.statementId === statement.id) {
        const { statementId: _statement, ...rest } = item;
        await tx.put<BillingInvoiceItem>(invoiceItemsCollection, { ...rest, status: 'pending' });
      }
    }
    for (const entry of statement.advanceBilled ?? []) {
      const subscription = await tx.get<BillingSubscription>(
        subscriptionsCollection,
        entry.subscriptionId,
      );
      if (subscription?.billedAdvance.includes(entry.period))
        await tx.put<BillingSubscription>(subscriptionsCollection, {
          ...subscription,
          billedAdvance: subscription.billedAdvance.filter((period) => period !== entry.period),
        });
    }
    for (const coupon of statement.coupons ?? []) {
      const discount = await tx.get<BillingDiscount>(discountsCollection, coupon.discountId);
      if (discount) {
        const { endedAt: _ended, ...rest } = discount;
        await tx.put<BillingDiscount>(discountsCollection, {
          ...(discount.duration === 'once' ? rest : discount),
          appliedInvoices: Math.max(0, discount.appliedInvoices - 1),
        });
      }
    }
    return tx.put<BillingStatement>(statementsCollection, {
      ...statement,
      uniqueKey: `void:${statement.id}`,
      status: 'void',
      voidedAt: now,
      voidedBy: principal.identity.id,
      voidReason: reason,
    });
  }

  /**
   * Records a payment against a finalized (or uncollectible) invoice, the full amount due by default. Once payments
   * and credit notes cover the invoice it is paid; a payment above the amount due keeps the excess as account credit.
   */
  async function recordPayment(
    tx: IamStore,
    statement: BillingStatement,
    input: { amount?: unknown; method?: unknown; reference?: unknown; receivedAt?: unknown },
    actorId: string,
  ): Promise<{ statement: BillingStatement; payment: InvoicePayment }> {
    if (statement.status !== 'finalized' && statement.status !== 'uncollectible')
      throw new IamError('INVALID_TRANSITION', `The invoice is ${statement.status}`, 409);
    const due = amountDue(statement);
    const amount = input.amount === undefined ? due : amountMicros(input.amount, 'amount');
    if (amount <= 0) throw new IamError('INVALID_INPUT', 'amount must be above 0');
    const method = input.method === undefined ? 'manual' : text(input.method, 'method', 32).trim();
    const reference =
      input.reference === undefined ? undefined : text(input.reference, 'reference', 128).trim();
    const now = ctx.now();
    const receivedAt =
      input.receivedAt === undefined
        ? now
        : integer(
            input.receivedAt,
            'receivedAt',
            statement.issuedAt - 366 * 86_400_000,
            now + 60_000,
          );
    const applied = roundMicros(Math.min(amount, due));
    const overpaymentMicros = roundMicros(amount - applied);
    const payment: InvoicePayment = {
      id: id(),
      amountMicros: amount,
      method,
      ...(reference ? { reference } : {}),
      receivedAt,
      recordedBy: actorId,
    };
    if (overpaymentMicros > 0) {
      const credit = await tx.insert<BillingCredit>(creditsCollection, {
        id: id(),
        tenantId: statement.tenantId,
        amountMicros: overpaymentMicros,
        remainingMicros: overpaymentMicros,
        reason: `Overpayment of ${statement.number}`,
        grantedAt: now,
        grantedBy: actorId,
      });
      payment.overpaymentMicros = overpaymentMicros;
      payment.creditId = credit.id;
    }
    const settled = roundMicros(due - applied) <= 0;
    const next = await tx.put<BillingStatement>(statementsCollection, {
      ...statement,
      payments: [...(statement.payments ?? []), payment],
      amountPaidMicros: roundMicros(amountPaid(statement) + applied),
      ...(settled
        ? {
            status: 'paid' as const,
            paidAt: receivedAt,
            paidBy: actorId,
            ...(reference ? { paymentReference: reference } : {}),
          }
        : {}),
    });
    return { statement: next, payment };
  }

  /** Writes a finalized invoice off as uncollectible (a later payment still settles it). */
  async function markUncollectible(
    tx: IamStore,
    statement: BillingStatement,
  ): Promise<BillingStatement> {
    if (statement.status !== 'finalized')
      throw new IamError('INVALID_TRANSITION', `The invoice is ${statement.status}`, 409);
    return tx.put<BillingStatement>(statementsCollection, {
      ...statement,
      status: 'uncollectible',
      markedUncollectibleAt: ctx.now(),
    });
  }

  /**
   * Issues a credit note against a finalized, paid or uncollectible invoice, numbered `{invoice}-CN-{nn}`: it first
   * reduces the amount due; the rest (a part already paid) becomes account credit, or is recorded as refunded outside
   * Better IAM with `refund`. An invoice the credit notes and payments cover is paid.
   */
  async function createCreditNote(
    tx: IamStore,
    statement: BillingStatement,
    input: { amount?: unknown; reason?: unknown; memo?: unknown; refund?: unknown },
    actorId: string,
  ): Promise<{ statement: BillingStatement; creditNote: BillingCreditNote }> {
    if (
      statement.status !== 'finalized' &&
      statement.status !== 'paid' &&
      statement.status !== 'uncollectible'
    )
      throw new IamError('INVALID_TRANSITION', `The invoice is ${statement.status}`, 409);
    const creditable = roundMicros(statement.totalMicros - (statement.creditNotesMicros ?? 0));
    const amount = input.amount === undefined ? creditable : amountMicros(input.amount, 'amount');
    if (amount <= 0) throw new IamError('INVALID_INPUT', 'amount must be above 0');
    if (amount > creditable)
      throw new IamError(
        'INVALID_INPUT',
        `At most ${formatMoney(creditable, settings.currency)} of the invoice can still be credited`,
      );
    const reason = creditNoteReason(input.reason);
    const memo = input.memo === undefined ? undefined : text(input.memo, 'memo', 512).trim();
    if (input.refund !== undefined && typeof input.refund !== 'boolean')
      throw new IamError('INVALID_INPUT', 'refund must be a boolean');
    const dueMicros = roundMicros(Math.min(amount, amountDue(statement)));
    const rest = roundMicros(amount - dueMicros);
    const applied = {
      dueMicros,
      creditMicros: input.refund === true ? 0 : rest,
      refundMicros: input.refund === true ? rest : 0,
    };
    const count = (
      await tx.find<BillingCreditNote>(creditNotesCollection, {
        tenantId: statement.tenantId,
        statementId: statement.id,
      })
    ).length;
    const number = `${statement.number}-CN-${String(count + 1).padStart(2, '0')}`;
    const now = ctx.now();
    let creditId: string | undefined;
    if (applied.creditMicros > 0)
      creditId = (
        await tx.insert<BillingCredit>(creditsCollection, {
          id: id(),
          tenantId: statement.tenantId,
          amountMicros: applied.creditMicros,
          remainingMicros: applied.creditMicros,
          reason: `Credit note ${number}`,
          grantedAt: now,
          grantedBy: actorId,
        })
      ).id;
    const creditNote = await tx.insert<BillingCreditNote>(creditNotesCollection, {
      id: id(),
      tenantId: statement.tenantId,
      uniqueKey: number,
      number,
      statementId: statement.id,
      statementNumber: statement.number,
      amountMicros: amount,
      reason,
      ...(memo ? { memo } : {}),
      applied,
      ...(creditId ? { creditId } : {}),
      issuedAt: now,
      issuedBy: actorId,
    });
    const credited: BillingStatement = {
      ...statement,
      creditNotesMicros: roundMicros((statement.creditNotesMicros ?? 0) + amount),
    };
    const settled = statement.status !== 'paid' && amountDue(credited) <= 0;
    const next = await tx.put<BillingStatement>(statementsCollection, {
      ...credited,
      ...(settled ? { status: 'paid' as const, paidAt: now, paidBy: actorId } : {}),
    });
    return { statement: next, creditNote };
  }

  /**
   * Emails the billing contacts of finalized invoices with an amount due (`payment-reminder`) at each step of
   * `billing.paymentReminderDays` relative to the due date, once per step (a missed step is skipped for the latest one
   * reached). Audited as `billing:payment-reminder`. A scheduler job, run daily.
   */
  async function sendPaymentReminders(): Promise<PaymentReminderResult> {
    const result: PaymentReminderResult = { checked: 0, reminders: [] };
    if (!settings.paymentReminderDays.length) return result;
    const open = await store.transaction((tx) =>
      tx.find<BillingStatement>(statementsCollection, { status: 'finalized' }),
    );
    for (const candidate of open.sort((a, b) => a.dueAt - b.dueAt || (a.id < b.id ? -1 : 1))) {
      result.checked++;
      await store.transaction(async (tx) => {
        const statement = await tx.get<BillingStatement>(statementsCollection, candidate.id);
        if (statement?.status !== 'finalized') return;
        const due = amountDue(statement);
        if (due <= 0) return;
        const now = ctx.now();
        const reached = settings.paymentReminderDays.filter((days) => {
          const at = statement.dueAt + days * 86_400_000;
          return at > statement.issuedAt && at <= now;
        });
        const step = reached.at(-1);
        const sent = (statement.reminders ?? []).map((reminder) => reminder.days);
        if (step === undefined || sent.some((days) => days >= step)) return;
        const account = await tx.get<Tenant>('tenants', statement.tenantId);
        const recipients = ctx.options.authentication?.sendEmail ? statement.billTo.emails : [];
        const days = Math.round((now - statement.dueAt) / 86_400_000);
        for (const to of recipients)
          await ctx.auth.enqueueDelivery(tx, {
            tenantId: statement.tenantId,
            kind: 'email',
            to,
            template: 'payment-reminder',
            payload: {
              tenantId: statement.tenantId,
              tenantName: account?.name ?? statement.billTo.name,
              statementId: statement.id,
              number: statement.number,
              period: statement.period,
              amountDue: formatMoney(due, settings.currency),
              total: formatMoney(statement.totalMicros, settings.currency),
              dueAt: new Date(statement.dueAt).toISOString().slice(0, 10),
              days: String(days),
              overdue: String(now > statement.dueAt),
            },
          });
        await tx.put<BillingStatement>(statementsCollection, {
          ...statement,
          reminders: [
            ...(statement.reminders ?? []),
            { days: step, at: now, recipients: recipients.length },
          ],
        });
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: statement.tenantId,
          actorId: 'deployment-operator',
          action: 'billing:payment-reminder',
          resourceId: `billing/statements/${statement.id}`,
          timestamp: now,
          outcome: 'allow',
          metadata: {
            number: statement.number,
            step,
            amountDueMicros: due,
            recipients: recipients.length,
          },
        });
        result.reminders.push({
          statementId: statement.id,
          accountId: statement.tenantId,
          number: statement.number,
          step,
          amountDueMicros: due,
          recipients: recipients.length,
        });
      });
    }
    return result;
  }

  // -------------------------------------------------------------------------------------------------------------
  // Subscriptions

  async function planOf(tx: IamStore, subscription: BillingSubscription): Promise<BillingPlan> {
    const plan = await tx.get<BillingPlan>(plansCollection, subscription.planId);
    if (!plan) throw new IamError('NOT_FOUND', 'Billing plan not found', 404);
    return plan;
  }

  function assertLive(subscription: BillingSubscription): void {
    if (subscriptionStatus(subscription, ctx.now()) === 'ended')
      throw new IamError('INVALID_TRANSITION', 'The subscription has ended', 409);
  }

  async function insertItems(tx: IamStore, items: BillingInvoiceItem[]): Promise<void> {
    for (const item of items) await tx.insert<BillingInvoiceItem>(invoiceItemsCollection, item);
  }

  /** The live subscription of an account to a plan; an ended one frees the plan for a new subscription. */
  async function liveSubscription(
    tx: IamStore,
    accountId: string,
    planId: string,
  ): Promise<BillingSubscription | undefined> {
    const existing = (
      await tx.find<BillingSubscription>(subscriptionsCollection, {
        tenantId: accountId,
        uniqueKey: `plan:${planId}`,
      })
    )[0];
    if (!existing) return undefined;
    if (subscriptionStatus(existing, ctx.now()) !== 'ended') return existing;
    await tx.put<BillingSubscription>(subscriptionsCollection, {
      ...existing,
      uniqueKey: `ended:${existing.id}`,
    });
    return undefined;
  }

  /**
   * Subscribes a billing account to a plan with `seats` (default 1) and the plan's trial (or `trialDays`; 0 for none).
   * The plan's own trial is granted once per account: an account that subscribed to the plan before starts without
   * one. Outside a trial the first month's advance fees and seats are invoiced at once, prorated from today (a
   * finalized invoice with `billingReason: 'subscription'`); after that each monthly invoice bills the month ahead.
   */
  async function subscribe(
    tx: IamStore,
    account: Tenant,
    plan: BillingPlan,
    input: { seats: number; trialDays?: number },
    actorId: string,
  ): Promise<{ subscription: BillingSubscription; invoice?: BillingStatement }> {
    if (plan.archived) throw new IamError('INVALID_TRANSITION', 'The plan is archived', 409);
    if (await liveSubscription(tx, account.id, plan.id))
      throw new IamError('CONFLICT', 'The account already subscribes to this plan', 409);
    const now = ctx.now();
    const subscribedBefore = (
      await tx.find<BillingSubscription>(subscriptionsCollection, { tenantId: account.id })
    ).some((subscription) => subscription.planId === plan.id);
    const trialDays = input.trialDays ?? (subscribedBefore ? 0 : (plan.trialDays ?? 0));
    const created = await tx.insert<BillingSubscription>(subscriptionsCollection, {
      id: id(),
      tenantId: account.id,
      uniqueKey: `plan:${plan.id}`,
      planId: plan.id,
      planKey: plan.key,
      planName: plan.name,
      startedAt: now,
      ...(trialDays > 0 ? { trialEndsAt: now + trialDays * 86_400_000 } : {}),
      cancelAtPeriodEnd: false,
      seats: input.seats,
      seatHistory: [{ at: now, seats: input.seats }],
      billedAdvance: [],
      createdAt: now,
      createdBy: actorId,
      updatedAt: now,
    });
    let invoice: BillingStatement | undefined;
    if (created.trialEndsAt === undefined) {
      const first = firstPeriodLines(created, plan, tz);
      if (first.lines.length) {
        const draft = await draftStatement(tx, account, first.period, new Map(), {
          lines: first.lines,
          subscriptionId: created.id,
        });
        invoice = (
          await issue(tx, account, draft, {
            uniqueKey: `subscription:${created.id}`,
            actorId,
          })
        ).statement;
      }
    }
    const subscription = (await tx.get<BillingSubscription>(subscriptionsCollection, created.id))!;
    return { subscription, ...(invoice ? { invoice } : {}) };
  }

  /** Changes the seat count; seats billed in advance for this month are prorated as invoice items. */
  async function updateSeats(
    tx: IamStore,
    subscription: BillingSubscription,
    seats: number,
    actorId: string,
  ): Promise<{ subscription: BillingSubscription; items: BillingInvoiceItem[] }> {
    assertLive(subscription);
    if (seats === subscription.seats) return { subscription, items: [] };
    const now = ctx.now();
    const items = prorationItems({
      subscription,
      plan: await planOf(tx, subscription),
      at: now,
      timeZone: tz,
      seats: { before: subscription.seats, after: seats },
      ending: false,
      createdBy: actorId,
    });
    await insertItems(tx, items);
    const next = await tx.put<BillingSubscription>(subscriptionsCollection, {
      ...subscription,
      seats,
      seatHistory: [...subscription.seatHistory, { at: now, seats }],
      updatedAt: now,
    });
    return { subscription: next, items };
  }

  /**
   * Cancels a subscription at the end of the month (it keeps running until then, and can be resumed) or now, when
   * the unused part of the month's advance fees and seats is credited as invoice items for the next invoice.
   */
  async function cancelSubscription(
    tx: IamStore,
    subscription: BillingSubscription,
    atPeriodEnd: boolean,
    actorId: string,
  ): Promise<{ subscription: BillingSubscription; items: BillingInvoiceItem[] }> {
    assertLive(subscription);
    const now = ctx.now();
    if (atPeriodEnd) {
      const next = await tx.put<BillingSubscription>(subscriptionsCollection, {
        ...subscription,
        cancelAtPeriodEnd: true,
        endsAt: periodBounds(periodOf(now, tz), tz).end,
        canceledAt: now,
        canceledBy: actorId,
        updatedAt: now,
      });
      return { subscription: next, items: [] };
    }
    const items = prorationItems({
      subscription,
      plan: await planOf(tx, subscription),
      at: now,
      timeZone: tz,
      ending: true,
      createdBy: actorId,
    });
    await insertItems(tx, items);
    const next = await tx.put<BillingSubscription>(subscriptionsCollection, {
      ...subscription,
      uniqueKey: `ended:${subscription.id}`,
      cancelAtPeriodEnd: false,
      endsAt: now,
      canceledAt: now,
      canceledBy: actorId,
      updatedAt: now,
    });
    return { subscription: next, items };
  }

  /** Undoes a cancellation at the end of the month before it takes effect. */
  async function resumeSubscription(
    tx: IamStore,
    subscription: BillingSubscription,
  ): Promise<BillingSubscription> {
    assertLive(subscription);
    if (!subscription.cancelAtPeriodEnd)
      throw new IamError('INVALID_TRANSITION', 'The subscription is not set to cancel', 409);
    const { endsAt: _ends, canceledAt: _canceled, canceledBy: _by, ...rest } = subscription;
    return tx.put<BillingSubscription>(subscriptionsCollection, {
      ...rest,
      cancelAtPeriodEnd: false,
      updatedAt: ctx.now(),
    });
  }

  /**
   * Moves a subscription to another plan now, keeping its seats and what is left of its trial: the old plan's unused
   * advance charges are credited and the new plan's charges for the rest of the month added, both as proration items
   * for the next invoice.
   */
  async function changePlan(
    tx: IamStore,
    subscription: BillingSubscription,
    plan: BillingPlan,
    actorId: string,
  ): Promise<{ subscription: BillingSubscription; items: BillingInvoiceItem[] }> {
    assertLive(subscription);
    if (plan.id === subscription.planId)
      throw new IamError('INVALID_INPUT', 'The subscription is already on this plan');
    if (plan.archived) throw new IamError('INVALID_TRANSITION', 'The plan is archived', 409);
    if (await liveSubscription(tx, subscription.tenantId, plan.id))
      throw new IamError('CONFLICT', 'The account already subscribes to this plan', 409);
    const now = ctx.now();
    const items = prorationItems({
      subscription,
      plan: await planOf(tx, subscription),
      at: now,
      timeZone: tz,
      ending: true,
      createdBy: actorId,
    });
    await tx.put<BillingSubscription>(subscriptionsCollection, {
      ...subscription,
      uniqueKey: `ended:${subscription.id}`,
      cancelAtPeriodEnd: false,
      endsAt: now,
      canceledAt: now,
      canceledBy: actorId,
      updatedAt: now,
    });
    const trialEndsAt =
      subscription.trialEndsAt !== undefined && subscription.trialEndsAt > now
        ? subscription.trialEndsAt
        : undefined;
    const created: BillingSubscription = {
      id: id(),
      tenantId: subscription.tenantId,
      uniqueKey: `plan:${plan.id}`,
      planId: plan.id,
      planKey: plan.key,
      planName: plan.name,
      startedAt: now,
      ...(trialEndsAt !== undefined ? { trialEndsAt } : {}),
      cancelAtPeriodEnd: false,
      seats: subscription.seats,
      seatHistory: [{ at: now, seats: subscription.seats }],
      billedAdvance: [],
      createdAt: now,
      createdBy: actorId,
      updatedAt: now,
    };
    const first = firstPeriodLines(created, plan, tz);
    for (const line of first.lines)
      items.push({
        id: id(),
        tenantId: subscription.tenantId,
        description: `${plan.name}: ${line.name} for the rest of the month`,
        quantity: 1,
        unitAmountMicros: line.amountMicros,
        amountMicros: line.amountMicros,
        period: first.period,
        status: 'pending',
        source: 'proration',
        subscriptionId: created.id,
        createdAt: now,
        createdBy: actorId,
      });
    // The rest of this month is billed through those items rather than an invoice of its own.
    if (plan.items.some((item) => item.kind !== 'usage' && item.billing !== 'arrears'))
      created.billedAdvance = [first.period];
    await insertItems(tx, items);
    const next = await tx.insert<BillingSubscription>(subscriptionsCollection, created);
    return { subscription: next, items };
  }

  /**
   * Records one seat of `meter` (default `seats`) for every active person (or `kinds`) of every tenant the meter
   * reaches, once per day (idempotent): a `sum` meter then counts seat-days, a `unique` meter active seats per month.
   * Seats are attributed to the person, their teams and department. A tenant that fails is reported in
   * `failedTenants` and the others are still recorded. A scheduler job, run daily.
   */
  async function recordSeats(
    input: { meter?: string; tenantId?: string; kinds?: Identity['kind'][] } = {},
  ): Promise<SeatRecordResult> {
    const key = meterKey(input.meter ?? 'seats');
    const kinds = input.kinds ?? ['user'];
    if (
      !Array.isArray(kinds) ||
      !kinds.length ||
      kinds.some((kind) => kind !== 'user' && kind !== 'service' && kind !== 'agent')
    )
      throw new IamError('INVALID_INPUT', "kinds must list 'user', 'service' or 'agent'");
    const day = dayOf(ctx.now(), tz);
    const tenants = await store.transaction(async (tx) =>
      input.tenantId === undefined
        ? await tx.find<Tenant>('tenants', { status: 'active' })
        : (await subtree(ctx, tx, await ctx.tenant(tx, text(input.tenantId, 'tenantId')))).filter(
            (realm) => realm.status === 'active',
          ),
    );
    const result: SeatRecordResult = {
      meter: key,
      day,
      recorded: 0,
      duplicates: 0,
      skippedTenants: 0,
      failedTenants: [],
    };
    for (const realm of tenants.sort((a, b) => (a.id < b.id ? -1 : 1))) {
      if (realm.parentId === null) continue;
      try {
        const counts = await store.transaction(async (tx) => {
          const meter = await resolveMeter(tx, await ctx.ancestry(tx, realm), key);
          if (!meter || meter.archived) return undefined;
          const people = (
            await tx.find<Identity>('identities', { tenantId: realm.id, status: 'active' })
          )
            .filter((identity) => kinds.includes(identity.kind) && !ctx.identityExpired(identity))
            .sort((a, b) => (a.id < b.id ? -1 : 1));
          let recorded = 0;
          let duplicates = 0;
          for (const identity of people) {
            // Seats recorded under the caller-visible `idem:` key of earlier releases (by this job only) still count.
            const legacy = (
              await tx.find<BillingUsageRecord>(usageCollection, {
                tenantId: realm.id,
                uniqueKey: `idem:seat:${key}:${identity.id}:${day}`,
              })
            )[0];
            if (legacy?.recordedBy === 'deployment' && legacy.meterId === meter.id) {
              duplicates++;
              continue;
            }
            // A source key (`src:`), which callers of `record` cannot claim ahead of the job.
            const seat = await record(
              tx,
              { tenantId: realm.id, meter: key, quantity: 1, identityId: identity.id },
              'deployment',
              { meter, sourceId: `seat:${identity.id}:${day}` },
            );
            if (seat.duplicate) duplicates++;
            else recorded++;
          }
          return { recorded, duplicates };
        });
        if (!counts) result.skippedTenants++;
        else {
          result.recorded += counts.recorded;
          result.duplicates += counts.duplicates;
        }
      } catch (error) {
        // One tenant's failure never stops the platform-wide job.
        result.failedTenants.push({
          tenantId: realm.id,
          code: error instanceof IamError ? error.code : 'INTERNAL_ERROR',
          message: error instanceof Error ? error.message : String(error),
        });
      }
    }
    return result;
  }

  /** Every identity whose spend counts as a person's own: themselves and the agents they sponsor. */
  async function ownIdentities(tx: IamStore, identity: Identity): Promise<Set<string>> {
    const own = new Set([identity.id]);
    for (const agent of await tx.find<Identity>('identities', {
      tenantId: identity.tenantId,
      kind: 'agent',
    }))
      if (agent.agent?.sponsorId === identity.id) own.add(agent.id);
    return own;
  }

  /** Whether a team is `teamId` or below it. */
  const teamWithin = (dir: Directory, candidate: string, teamId: string) =>
    teamChain(dir.teams, candidate).some((team) => team.id === teamId);
  /** Whether a department is `departmentId` or below it. */
  const departmentWithin = (dir: Directory, candidate: string, departmentId: string) =>
    departmentChain(dir.departments, candidate).some(
      (department) => department.id === departmentId,
    );

  // -------------------------------------------------------------------------------------------------------------
  // Anomalies

  /** Validated anomaly settings. */
  function anomalyOptions(input: AnomalyOptions) {
    const now = ctx.now();
    const day =
      input.day === undefined
        ? dayOf(now - 86_400_000, tz)
        : /^\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\d|3[01])$/.test(String(input.day))
          ? String(input.day)
          : (() => {
              throw new IamError('INVALID_INPUT', 'day must be a date such as 2026-09-22');
            })();
    const baselineDays =
      input.baselineDays === undefined ? 14 : integer(input.baselineDays, 'baselineDays', 3, 90);
    const factor = input.factor === undefined ? 3 : input.factor;
    if (typeof factor !== 'number' || !Number.isFinite(factor) || factor < 1.1 || factor > 1000)
      throw new IamError('INVALID_INPUT', 'factor must be a number from 1.1 to 1000');
    const minimumMicros =
      input.minimum === undefined ? 10 * 1_000_000 : amountMicros(input.minimum, 'minimum');
    return { day, baselineDays, factor, minimumMicros };
  }

  /** The days `count` days before `day` (oldest first), as local dates. */
  function daysBefore(day: string, count: number): string[] {
    const [year, month, date] = day.split('-').map(Number) as [number, number, number];
    return Array.from({ length: count }, (_, index) => {
      const at = new Date(Date.UTC(year, month - 1, date - (count - index)));
      return at.toISOString().slice(0, 10);
    });
  }

  /**
   * Spend spikes: people, teams and meters whose spend on `day` (default yesterday) is at least `factor` (3) times
   * their average over the `baselineDays` (14) before it and at least `minimum` (10 currency units) above it, or new
   * spenders above `minimum`. Rows come from `rows` (charged usage of one scope), so costs follow each month's
   * blended rates.
   */
  async function findAnomalies(
    tx: IamStore,
    rowsFor: (period: string) => Promise<ChargedRow[]>,
    input: AnomalyOptions,
    scopeIds: string[],
  ): Promise<SpendAnomaly[]> {
    const { day, baselineDays, factor, minimumMicros } = anomalyOptions(input);
    const baseline = daysBefore(day, baselineDays);
    const window = new Set([...baseline, day]);
    const periods = [...new Set([...window].map((value) => value.slice(0, 7)))];
    const rows: ChargedRow[] = [];
    for (const period of periods)
      for (const row of await rowsFor(period)) if (window.has(row.day)) rows.push(row);
    const dir = await directory(tx, rows, scopeIds);
    const totals = new Map<string, { onDay: number; before: number }>();
    const meterIds = new Map<string, string>();
    const add = (key: string, row: ChargedRow, weight: number) => {
      const entry = totals.get(key) ?? { onDay: 0, before: 0 };
      if (row.day === day) entry.onDay += row.costMicros * weight;
      else entry.before += row.costMicros * weight;
      totals.set(key, entry);
    };
    for (const row of rows) {
      const principal = row.agentId ?? row.identityId;
      if (principal) add(`identity|${principal}`, row, 1);
      add(`meter|${row.meter}`, row, 1);
      meterIds.set(row.meter, row.meterId);
      const share = settings.teamAttribution === 'full' ? 1 : 1 / Math.max(1, row.teamIds.length);
      for (const team of row.teamIds) add(`team|${team}`, row, share);
    }
    const found: SpendAnomaly[] = [];
    for (const [compound, entry] of totals) {
      const costMicros = roundMicros(entry.onDay);
      const baselineMicros = roundMicros(entry.before / baselineDays);
      if (costMicros < minimumMicros || costMicros - baselineMicros < minimumMicros) continue;
      if (baselineMicros > 0 && costMicros < baselineMicros * factor) continue;
      const [dimension, key] = compound.split('|') as [SpendAnomaly['dimension'], string];
      found.push({
        dimension,
        key,
        day,
        costMicros,
        baselineMicros,
        factor: baselineMicros > 0 ? Math.round((costMicros / baselineMicros) * 10) / 10 : null,
      });
    }
    found.sort(
      (a, b) =>
        b.costMicros - b.baselineMicros - (a.costMicros - a.baselineMicros) ||
        (a.key < b.key ? -1 : 1),
    );
    const top = found.slice(0, 50);
    for (const anomaly of top) {
      const label =
        anomaly.dimension === 'team'
          ? dir.teams.get(anomaly.key)?.name
          : anomaly.dimension === 'identity'
            ? (await tx.get<Identity>('identities', anomaly.key))?.name
            : (await tx.get<BillingMeter>(metersCollection, meterIds.get(anomaly.key) ?? ''))?.name;
      if (label !== undefined) anomaly.label = label;
    }
    return top;
  }

  /** Anomalies within a tenant's subtree, for `billing.anomalies`. */
  async function anomalies(tx: IamStore, scope: Tenant, input: AnomalyOptions = {}) {
    const cache: SpendCache = new Map();
    return findAnomalies(
      tx,
      async (period) => (await scopeSpend(ctx, tx, scope, period, cache)).rows,
      input,
      [scope.id],
    );
  }

  /**
   * Checks every billing account for spend spikes on `day` (default yesterday) and alerts once per person, team or
   * meter and day: audited as `billing:anomaly` and, with an email transport, one `spend-anomaly` email per account to
   * its billing emails (or owners). A scheduler job, run daily after midnight in the billing time zone.
   */
  async function detectAnomalies(
    input: AnomalyOptions & { tenantId?: string } = {},
  ): Promise<AnomalyAlertResult> {
    const { tenantId, ...options } = input;
    anomalyOptions(options);
    const accounts = await store.transaction(async (tx) => {
      const found = new Map<string, Tenant>();
      const candidates =
        tenantId === undefined
          ? await tx.find<Tenant>('tenants', { status: 'active' })
          : [await ctx.tenant(tx, text(tenantId, 'tenantId'))];
      for (const realm of candidates) {
        if (realm.parentId === null) continue;
        const account = await accountOf(ctx, tx, realm);
        if (tenantId !== undefined || account.id === realm.id) found.set(account.id, account);
      }
      return [...found.values()].sort((a, b) => (a.id < b.id ? -1 : 1));
    });
    const result: AnomalyAlertResult = { checked: 0, anomalies: [] };
    for (const candidate of accounts)
      await store.transaction(async (tx) => {
        const account = await ctx.tenant(tx, candidate.id);
        if (account.status === 'deleted') return;
        result.checked++;
        const cache: SpendCache = new Map();
        const found = await findAnomalies(
          tx,
          async (period) => (await accountSpend(ctx, tx, account, period, cache)).rows,
          options,
          [account.id],
        );
        const fresh: SpendAnomaly[] = [];
        for (const anomaly of found) {
          const uniqueKey = `anomaly:${anomaly.dimension}:${anomaly.key}:${anomaly.day}`;
          if ((await tx.find(alertsCollection, { tenantId: account.id, uniqueKey })).length)
            continue;
          await tx.insert<BillingBudgetAlert>(alertsCollection, {
            id: id(),
            tenantId: account.id,
            uniqueKey,
            budgetId: '',
            window: anomaly.day,
            kind: 'anomaly',
            threshold: anomaly.factor ?? 0,
            spentMicros: anomaly.costMicros,
            alertedAt: ctx.now(),
          });
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: account.id,
            actorId: 'deployment-operator',
            action: 'billing:anomaly',
            resourceId: `billing/anomalies/${anomaly.dimension}/${anomaly.key}`,
            timestamp: ctx.now(),
            outcome: 'allow',
            metadata: {
              dimension: anomaly.dimension,
              key: anomaly.key,
              ...(anomaly.label !== undefined ? { label: anomaly.label } : {}),
              day: anomaly.day,
              costMicros: anomaly.costMicros,
              baselineMicros: anomaly.baselineMicros,
              factor: anomaly.factor,
            },
          });
          fresh.push(anomaly);
        }
        if (!fresh.length) return;
        const profile = await profileOf(tx, account.id);
        const recipients = ctx.options.authentication?.sendEmail
          ? profile?.billingEmails.length
            ? profile.billingEmails
            : await owners(tx, account.id)
          : [];
        const lines = fresh.slice(0, 5).map((anomaly) => ({
          what: `${anomaly.dimension === 'meter' ? 'Meter' : anomaly.dimension === 'team' ? 'Team' : 'Person'} ${anomaly.label ?? anomaly.key}`,
          spent: formatMoney(anomaly.costMicros, settings.currency),
          usual: formatMoney(anomaly.baselineMicros, settings.currency),
        }));
        for (const to of recipients)
          await ctx.auth.enqueueDelivery(tx, {
            tenantId: account.id,
            kind: 'email',
            to,
            template: 'spend-anomaly',
            payload: {
              tenantId: account.id,
              tenantName: account.name,
              day: fresh[0]!.day,
              count: String(fresh.length),
              items: JSON.stringify(lines),
            },
          });
        for (const anomaly of fresh)
          result.anomalies.push({
            accountId: account.id,
            ...anomaly,
            recipients: recipients.length,
          });
      });
    return result;
  }

  // -------------------------------------------------------------------------------------------------------------
  // CSV

  /** A spend report as CSV: one row per group with amount, share, events and a column per meter's quantity. */
  function spendCsv(report: SpendReport): string {
    const meters = [...new Set(report.rows.flatMap((row) => Object.keys(row.quantities)))].sort();
    const lines = [
      [
        report.groupBy,
        'label',
        `amount_${report.currency.toLowerCase()}`,
        'share_percent',
        'events',
        ...meters.map((meter) => `quantity_${meter}`),
      ],
      ...report.rows.map((row) => [
        row.key,
        row.label ?? '',
        (row.costMicros / 1_000_000).toFixed(6),
        String(row.share),
        String(row.events),
        ...meters.map((meter) => String(row.quantities[meter] ?? 0)),
      ]),
      [
        'total',
        '',
        (report.total.costMicros / 1_000_000).toFixed(6),
        '100',
        String(report.total.events),
        ...meters.map(() => ''),
      ],
    ];
    return csv(lines);
  }

  /** A statement as CSV: its lines, credit and total, then the breakdown sections. */
  function statementCsv(statement: BillingStatement): string {
    const money = (micros: number) => (micros / 1_000_000).toFixed(6);
    const rows: string[][] = [
      ['section', 'id', 'name', 'quantity', 'unit', 'amount', 'cost_center'],
      ...statement.lines.map((line) => [
        line.kind && line.kind !== 'usage' ? line.kind : 'line',
        line.meter ?? line.planItemId ?? line.invoiceItemId ?? '',
        line.name,
        String(line.quantity),
        line.unit,
        money(line.amountMicros),
        '',
      ]),
      ['subtotal', '', '', '', '', money(statement.subtotalMicros), ''],
      ...(statement.discount
        ? [
            [
              'discount',
              '',
              `${statement.discount.percent}%`,
              '',
              '',
              money(-statement.discount.amountMicros),
              '',
            ],
          ]
        : []),
      ...(statement.commitment && statement.commitment.trueUpMicros > 0
        ? [
            [
              'commitment',
              '',
              'minimum commitment true-up',
              '',
              '',
              money(statement.commitment.trueUpMicros),
              '',
            ],
          ]
        : []),
      ...(statement.coupons ?? []).map((coupon) => [
        'coupon',
        coupon.code,
        coupon.name,
        '',
        '',
        money(-coupon.amountMicros),
        '',
      ]),
      ['credit', '', '', '', '', money(-statement.creditsMicros), ''],
      ...(statement.tax
        ? [
            [
              'tax',
              '',
              `${statement.tax.label} ${statement.tax.ratePercent}%`,
              '',
              '',
              money(statement.tax.amountMicros),
              '',
            ],
          ]
        : []),
      [
        'total',
        statement.number,
        statement.period,
        '',
        statement.currency,
        money(statement.totalMicros),
        '',
      ],
      ...statement.breakdown.tenants.map((entry) => [
        'tenant',
        entry.id,
        entry.name,
        '',
        '',
        money(entry.costMicros),
        '',
      ]),
      ...statement.breakdown.teams.map((entry) => [
        'team',
        entry.id,
        entry.name,
        '',
        '',
        money(entry.costMicros),
        '',
      ]),
      ...statement.breakdown.departments.map((entry) => [
        'department',
        entry.id,
        entry.name,
        '',
        '',
        money(entry.costMicros),
        entry.costCenter ?? '',
      ]),
      ...statement.breakdown.identities.map((entry) => [
        'identity',
        entry.id,
        entry.name,
        '',
        '',
        money(entry.costMicros),
        '',
      ]),
    ];
    return csv(rows);
  }

  return {
    settings,
    hooks,
    currentPeriod,
    record,
    report,
    trend,
    check,
    spendContext,
    budgetStatus,
    checkBudgets,
    draftStatement,
    statementFor,
    closePeriod,
    finalizeDraft,
    voidStatement,
    recordPayment,
    markUncollectible,
    createCreditNote,
    sendPaymentReminders,
    subscribe,
    updateSeats,
    cancelSubscription,
    resumeSubscription,
    changePlan,
    recordSeats,
    ownIdentities,
    teamWithin,
    departmentWithin,
    anomalies,
    detectAnomalies,
    spendCsv,
    statementCsv,
  };
}

/** The policy context keys billing derives (`principal.spendExceeded`, `principal.budgetsExceeded`). */
export const spendContextKeys = ['principal.spendExceeded', 'principal.budgetsExceeded'] as const;

/** Whether any statement of the documents names a spend context key, so decisions read budgets only when needed. */
export function mentionsSpend(documents: Iterable<PolicyDocument>): boolean {
  for (const document of documents) {
    const serialized = JSON.stringify(document.statements);
    if (spendContextKeys.some((key) => serialized.includes(key))) return true;
  }
  return false;
}

/**
 * RFC 4180 CSV; cells that spreadsheet programs would read as formulas are prefixed with a quote. Only plain numbers
 * (`-12.5`) keep a leading minus: `-1+cmd|...` is a formula.
 */
function csv(rows: string[][]): string {
  const cell = (value: string) => {
    const safe = /^[=+\-@\t\r]/.test(value) && !/^-?\d+(\.\d+)?$/.test(value) ? `'${value}` : value;
    return /[",\r\n]/.test(safe) ? `"${safe.replace(/"/g, '""')}"` : safe;
  };
  return `${rows.map((row) => row.map(cell).join(',')).join('\r\n')}\r\n`;
}

export type BillingService = ReturnType<typeof createBillingService>;

const services = new WeakMap<ServerContext, BillingService>();
/** The billing service of a server (one per instance, shared by the API group, `iam.billing` and `ctx.billing`). */
export function billingServiceOf(ctx: ServerContext): BillingService {
  let service = services.get(ctx);
  if (!service) {
    service = createBillingService(ctx);
    services.set(ctx, service);
  }
  return service;
}
