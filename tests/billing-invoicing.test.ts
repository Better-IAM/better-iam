import { afterEach, describe, expect, it } from 'vitest';
import { renderDeliveryMessage } from '@better-iam/auth';
import {
  periodBounds,
  periodOf,
  priceBreakdown,
  priceQuantity,
  priceSpec,
  shiftPeriod,
  type BillingOptions,
} from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const day = 86_400_000;
/** Invoices bill whole cents. */
const cents = (micros: number) => Math.round(micros / 10_000) * 10_000;
/** The share of `period` from `from` to its end, as billing rounds it (four decimals). */
const rest = (from: number, period: string) => {
  const { start, end } = periodBounds(period, 'UTC');
  return Math.round(((end - from) / (end - start)) * 10_000) / 10_000;
};
const compact = (period: string) => period.replace('-', '');

/**
 * Acme on the 10th of a month (00:00 UTC, so proration is predictable) with the platform `api-calls` meter: 1000 free
 * calls a month, then $0.01 each up to 10 000. Sessions last a week, so `as` holds root and owner sessions that
 * `refresh` renews after the clock moves.
 */
async function setup(billing: BillingOptions = {}) {
  const f = await organizationFixture({
    billing: {
      issuer: { name: 'Better Cloud Ltd', address: '1 Main Street\nLondon', taxId: 'GB123456789' },
      ...billing,
    },
  });
  const next = periodBounds(shiftPeriod(periodOf(f.now(), 'UTC'), 1), 'UTC').start;
  f.advance(next + 9 * day - f.now());
  const as = { root: await f.rootSignIn(), owner: await f.ownerSignIn() };
  const refresh = async () => {
    f.advance(30_000); // a fresh TOTP step
    as.root = await f.rootSignIn();
    as.owner = await f.ownerSignIn();
  };
  const rootId = f.root.tenant.id;
  await f.iam.api.billing.createMeter(as.root, {
    tenantId: rootId,
    key: 'api-calls',
    name: 'API calls',
    unit: 'request',
  });
  await f.iam.api.billing.setPrice(as.root, {
    tenantId: rootId,
    meter: 'api-calls',
    effectiveFrom: shiftPeriod(periodOf(f.now(), 'UTC'), -1),
    price: {
      model: 'graduated',
      includedQuantity: 1000,
      tiers: [
        { upTo: 10_000, unitAmount: 0.01 },
        { upTo: null, unitAmount: 0.005 },
      ],
    },
  });
  const alice = await f.iam.api.identities.create(as.owner, {
    tenantId: f.tenantId,
    email: 'alice@acme.test',
    name: 'alice',
  });
  const record = (quantity: number, extra: Record<string, unknown> = {}) =>
    f.iam.api.billing.record(as.owner, {
      tenantId: f.tenantId,
      meter: 'api-calls',
      quantity,
      identityId: alice.id,
      ...extra,
    });
  /** Moves the clock to the 2nd of the next month. */
  const nextMonth = async () => {
    const start = periodBounds(shiftPeriod(periodOf(f.now(), 'UTC'), 1), 'UTC').start;
    f.advance(start + day - f.now());
    await refresh();
  };
  return { f, as, refresh, rootId, alice, record, nextMonth };
}

describe('invoice lines', () => {
  it('breaks tiered prices into sub-lines and applies a price minimum and maximum', () => {
    const spec = priceSpec({
      model: 'graduated',
      includedQuantity: 10,
      tiers: [
        { upTo: 100, unitAmount: 1 },
        { upTo: null, unitAmount: 0.5, flatAmount: 10 },
      ],
      minimumAmount: 20,
      maximumAmount: 120,
    });
    // 160 units, 10 free: 100 × $1, then 50 × $0.50 + $10 flat = $135 before the cap.
    expect(priceBreakdown(spec, 160)).toEqual({
      tiers: [
        { from: 1, to: 100, quantity: 100, unitAmountMicros: 1_000_000, amountMicros: 100_000_000 },
        {
          from: 101,
          to: null,
          quantity: 50,
          unitAmountMicros: 500_000,
          flatAmountMicros: 10_000_000,
          amountMicros: 35_000_000,
        },
      ],
      includedQuantity: 10,
      rawMicros: 135_000_000,
    });
    expect(priceQuantity(spec, 160)).toBe(120_000_000);
    // Any usage costs at least the minimum; none costs nothing.
    expect(priceQuantity(spec, 15)).toBe(20_000_000);
    expect(priceQuantity(spec, 0)).toBe(0);
    expect(() =>
      priceSpec({ model: 'per-unit', unitAmount: 1, minimumAmount: 10, maximumAmount: 5 }),
    ).toThrow('maximumAmount must not be below minimumAmount');
  });
});

describe('plans and subscriptions', () => {
  it('bills fees, seats and plan prices, prorates seat changes, and bills the next month in advance', async () => {
    const { f, as, rootId, record, nextMonth } = await setup();
    const month = periodOf(f.now(), 'UTC');
    const started = f.now();
    const team = await f.iam.api.billing.createPlan(as.root, {
      tenantId: rootId,
      key: 'team',
      name: 'Team',
      selfServe: true,
      items: [
        { id: 'platform', kind: 'fee', name: 'Platform fee', amount: 100 },
        { id: 'seats', kind: 'seat', name: 'Seats', unitAmount: 10, includedSeats: 2 },
        {
          id: 'calls',
          kind: 'usage',
          name: 'API calls',
          meter: 'api-calls',
          price: { model: 'per-unit', unitAmount: 0.002 },
        },
      ],
    });
    expect(team).toMatchObject({
      key: 'team',
      subscribers: 0,
      items: [
        { id: 'platform', kind: 'fee', amount: 100, billing: 'advance' },
        { id: 'seats', kind: 'seat', unitAmount: 10, includedSeats: 2, billing: 'advance' },
        { id: 'calls', kind: 'usage', meter: 'api-calls', price: { unitAmount: 0.002 } },
      ],
    });
    await f.iam.api.billing.createPlan(as.root, {
      tenantId: rootId,
      key: 'enterprise',
      name: 'Enterprise',
      items: [{ id: 'platform', kind: 'fee', amount: 1000 }],
    });
    // Only root administrators define plans; organizations read the catalog.
    await expect(
      f.iam.api.billing.createPlan(as.owner, {
        tenantId: f.tenantId,
        key: 'mine',
        name: 'Mine',
        items: [{ id: 'fee', kind: 'fee', amount: 1 }],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.billing.createPlan(as.root, {
        tenantId: rootId,
        key: 'bad',
        name: 'Bad',
        items: [{ id: 'fee', kind: 'rebate', amount: 1 }],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const catalog = await f.iam.api.billing.listPlans(as.owner, { tenantId: f.tenantId });
    expect(catalog.map((plan) => [plan.key, plan.subscribers])).toEqual([
      ['enterprise', undefined],
      ['team', undefined],
    ]);

    // Account billing managers subscribe to self-serve plans only, and never set trials.
    await expect(
      f.iam.api.billing.subscribe(as.owner, { tenantId: f.tenantId, plan: 'enterprise' }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.billing.subscribe(as.owner, {
        tenantId: f.tenantId,
        plan: 'team',
        trialDays: 90,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const subscribed = await f.iam.api.billing.subscribe(as.owner, {
      tenantId: f.tenantId,
      plan: 'team',
      seats: 5,
    });
    // The first invoice bills the rest of this month in advance: the fee and 3 chargeable seats.
    const firstShare = rest(started, month);
    const firstSeats = Math.round(3 * firstShare * 10_000) / 10_000;
    const firstTotal = cents(cents(100_000_000 * firstShare) + cents(10_000_000 * firstSeats));
    expect(subscribed.subscription).toMatchObject({
      status: 'active',
      planKey: 'team',
      seats: 5,
      billedAdvance: [month],
    });
    expect(subscribed.invoice).toMatchObject({
      billingReason: 'subscription',
      status: 'finalized',
      number: `INV-${compact(month)}-0001`,
      totalMicros: firstTotal,
      amountDueMicros: firstTotal,
    });
    const first = await f.iam.api.billing.getStatement(as.owner, {
      tenantId: f.tenantId,
      statementId: subscribed.invoice!.id,
    });
    expect(first.verified).toBe(true);
    expect(first.lines).toEqual([
      expect.objectContaining({
        kind: 'fee',
        name: 'Platform fee',
        quantity: 1,
        unitAmountMicros: 100_000_000,
        proration: firstShare,
        servicePeriod: periodBounds(month, 'UTC'),
        planItemId: 'platform',
      }),
      expect.objectContaining({ kind: 'seat', unit: 'seat-month', quantity: firstSeats }),
    ]);
    await expect(
      f.iam.api.billing.subscribe(as.owner, { tenantId: f.tenantId, plan: 'team' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });

    // Two more seats on the 15th: the rest of the month is charged on the next invoice.
    f.advance(5 * day);
    const grownAt = f.now();
    const grown = await f.iam.api.billing.updateSubscription(as.owner, {
      tenantId: f.tenantId,
      subscriptionId: subscribed.subscription.id,
      seats: 7,
    });
    const prorationMicros = cents(2 * 10_000_000 * rest(grownAt, month));
    expect(grown.subscription.seats).toBe(7);
    expect(grown.invoiceItems).toEqual([
      expect.objectContaining({
        source: 'proration',
        status: 'pending',
        period: month,
        amountMicros: prorationMicros,
      }),
    ]);

    // The plan prices API calls for subscribers: no free calls, $0.002 each.
    await record(1000);
    const preview = await f.iam.api.billing.previewStatement(as.owner, {
      tenantId: f.tenantId,
    });
    expect(preview.lines[0]).toMatchObject({
      meter: 'api-calls',
      amountMicros: 2_000_000,
      unitAmountMicros: 2000,
      price: { model: 'per-unit', source: 'plan' },
    });

    // Cancelling at the end of the month can be undone until then; only root administrators cancel at once.
    const canceling = await f.iam.api.billing.cancelSubscription(as.owner, {
      tenantId: f.tenantId,
      subscriptionId: subscribed.subscription.id,
    });
    expect(canceling.subscription).toMatchObject({
      status: 'active',
      cancelAtPeriodEnd: true,
      endsAt: periodBounds(month, 'UTC').end,
    });
    await expect(
      f.iam.api.billing.cancelSubscription(as.owner, {
        tenantId: f.tenantId,
        subscriptionId: subscribed.subscription.id,
        atPeriodEnd: false,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const resumed = await f.iam.api.billing.resumeSubscription(as.owner, {
      tenantId: f.tenantId,
      subscriptionId: subscribed.subscription.id,
    });
    expect(resumed.cancelAtPeriodEnd).toBe(false);
    expect(resumed.endsAt).toBeUndefined();

    // Closing the month: usage at the plan price, the next month's fee and 5 chargeable seats, and the proration.
    await nextMonth();
    const following = periodOf(f.now(), 'UTC');
    const closed = await f.iam.billing.closePeriod();
    const monthlyTotal = cents(2_000_000 + 100_000_000 + 50_000_000 + prorationMicros);
    expect(closed.issued).toEqual([
      expect.objectContaining({
        accountId: f.tenantId,
        number: `INV-${compact(month)}-0002`,
        totalMicros: monthlyTotal,
      }),
    ]);
    const monthly = await f.iam.api.billing.getStatement(as.owner, {
      tenantId: f.tenantId,
      statementId: closed.issued[0]!.statementId,
    });
    expect(monthly.lines.map((line) => [line.kind ?? 'usage', line.amountMicros])).toEqual([
      ['usage', 2_000_000],
      ['fee', 100_000_000],
      ['seat', 50_000_000],
      ['item', prorationMicros],
    ]);
    expect(monthly.lines[1]!.servicePeriod).toEqual(periodBounds(following, 'UTC'));
    const [subscription] = await f.iam.api.billing.listSubscriptions(as.owner, {
      tenantId: f.tenantId,
    });
    expect(subscription!.billedAdvance).toEqual([month, following]);
    expect(
      await f.iam.api.billing.listInvoiceItems(as.owner, {
        tenantId: f.tenantId,
        status: 'invoiced',
      }),
    ).toEqual([expect.objectContaining({ statementId: monthly.id })]);

    // Cancelling now credits what is left of the month already paid for.
    const canceledAt = f.now();
    const ended = await f.iam.api.billing.cancelSubscription(as.root, {
      tenantId: f.tenantId,
      subscriptionId: subscribed.subscription.id,
      atPeriodEnd: false,
    });
    const left = rest(canceledAt, following);
    expect(ended.subscription.status).toBe('ended');
    expect(ended.invoiceItems.map((item) => item.amountMicros)).toEqual([
      cents(-100_000_000 * left),
      cents(-5 * 10_000_000 * left),
    ]);
    expect(await f.iam.api.billing.listSubscriptions(as.owner, { tenantId: f.tenantId })).toEqual(
      [],
    );
    const plans = await f.iam.api.billing.listPlans(as.root, { tenantId: rootId });
    expect(plans.find((plan) => plan.key === 'team')!.subscribers).toBe(0);
  });

  it('starts trials free of charge, keeps them across plan changes, and bills the rest of the month after', async () => {
    const { f, as, rootId, nextMonth } = await setup();
    const month = periodOf(f.now(), 'UTC');
    const started = f.now();
    for (const [key, amount, trialDays] of [
      ['starter', 20, 14],
      ['growth', 50, undefined],
    ] as const)
      await f.iam.api.billing.createPlan(as.root, {
        tenantId: rootId,
        key,
        name: key,
        selfServe: true,
        ...(trialDays ? { trialDays } : {}),
        items: [{ id: 'fee', kind: 'fee', name: `${key} fee`, amount }],
      });
    const trial = await f.iam.api.billing.subscribe(as.owner, {
      tenantId: f.tenantId,
      plan: 'starter',
    });
    expect(trial.subscription).toMatchObject({
      status: 'trialing',
      trialEndsAt: started + 14 * day,
    });
    expect(trial.invoice).toBeUndefined();

    const moved = await f.iam.api.billing.changePlan(as.owner, {
      tenantId: f.tenantId,
      subscriptionId: trial.subscription.id,
      plan: 'growth',
    });
    const afterTrial = rest(started + 14 * day, month);
    expect(moved.subscription).toMatchObject({
      planKey: 'growth',
      status: 'trialing',
      trialEndsAt: started + 14 * day,
      billedAdvance: [month],
    });
    expect(moved.invoiceItems).toEqual([
      expect.objectContaining({
        source: 'proration',
        amountMicros: cents(50_000_000 * afterTrial),
      }),
    ]);
    const all = await f.iam.api.billing.listSubscriptions(as.owner, {
      tenantId: f.tenantId,
      includeEnded: true,
    });
    expect(all.map((subscription) => [subscription.planKey, subscription.status]).sort()).toEqual([
      ['growth', 'trialing'],
      ['starter', 'ended'],
    ]);

    // An account with no usage is still invoiced for its subscription.
    await nextMonth();
    const closed = await f.iam.billing.closePeriod();
    expect(closed.issued).toEqual([
      expect.objectContaining({
        accountId: f.tenantId,
        totalMicros: cents(cents(50_000_000 * afterTrial) + 50_000_000),
      }),
    ]);
  });
});

describe('invoices', () => {
  it('drafts invoices with items, finalizes them, and takes payments and credit notes', async () => {
    const { f, as, rootId, record } = await setup({ autoFinalize: false });
    const lastMonth = shiftPeriod(periodOf(f.now(), 'UTC'), -1);
    const lastMonthStart = periodBounds(lastMonth, 'UTC').start;
    // 6000 calls last month: 1000 free, then $0.01 each: $50.
    await record(6000, { occurredAt: lastMonthStart + 3_600_000 });
    await f.iam.api.billing.createInvoiceItem(as.root, {
      tenantId: f.tenantId,
      description: 'Onboarding workshop',
      amount: 200,
    });
    await f.iam.api.billing.createInvoiceItem(as.root, {
      tenantId: f.tenantId,
      description: 'Service credit',
      amount: -30,
    });
    await expect(
      f.iam.api.billing.createInvoiceItem(as.owner, {
        tenantId: f.tenantId,
        description: 'Free money',
        amount: -1000,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const pending = await f.iam.api.billing.listInvoiceItems(as.owner, {
      tenantId: f.tenantId,
      status: 'pending',
    });
    expect(pending.map((item) => item.amount).sort((a, b) => a - b)).toEqual([-30, 200]);

    // With autoFinalize off, closing keeps a draft.
    const drafted = await f.iam.api.billing.closePeriod(as.root, { tenantId: rootId });
    expect(drafted).toMatchObject({
      period: lastMonth,
      issued: [],
      drafted: [{ accountId: f.tenantId, totalMicros: 220_000_000 }],
    });
    const draftId = drafted.drafted[0]!.statementId;
    const draft = await f.iam.api.billing.getStatement(as.owner, {
      tenantId: f.tenantId,
      statementId: draftId,
    });
    expect(draft).toMatchObject({
      status: 'draft',
      number: '',
      hash: '',
      subtotalMicros: 220_000_000,
    });
    expect(draft.lines[0]).toMatchObject({
      meter: 'api-calls',
      quantity: 6000,
      includedQuantity: 1000,
      tiers: [
        { from: 1, to: 10_000, quantity: 5000, unitAmountMicros: 10_000, amountMicros: 50_000_000 },
      ],
    });
    // A draft keeps its month open to late usage and new items; finalizing recomputes it.
    await record(1000, { occurredAt: lastMonthStart + 7_200_000 });
    await f.iam.api.billing.createInvoiceItem(as.root, {
      tenantId: f.tenantId,
      description: 'Extra support',
      amount: 25,
      quantity: 2,
    });
    const finalized = await f.iam.api.billing.finalizeInvoice(as.root, {
      tenantId: f.tenantId,
      statementId: draftId,
    });
    const number = `INV-${compact(lastMonth)}-0001`;
    // $60 of usage + $200 − $30 + 2 × $25.
    expect(finalized).toMatchObject({
      status: 'finalized',
      number,
      totalMicros: 280_000_000,
      amountDueMicros: 280_000_000,
    });
    await expect(
      f.iam.api.billing.finalizeInvoice(as.root, {
        tenantId: f.tenantId,
        statementId: draftId,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    expect(
      await f.iam.api.billing.listInvoiceItems(as.owner, {
        tenantId: f.tenantId,
        status: 'pending',
      }),
    ).toEqual([]);
    await expect(record(1, { occurredAt: lastMonthStart + 7_200_000 })).rejects.toMatchObject({
      code: 'BILLING_PERIOD_CLOSED',
    });

    // A partial payment, then a credit note against the amount still due.
    const partial = await f.iam.api.billing.recordPayment(as.root, {
      tenantId: f.tenantId,
      statementId: draftId,
      amount: 100,
      method: 'bank_transfer',
      reference: 'wire-1',
    });
    expect(partial.statement).toMatchObject({
      status: 'finalized',
      amountPaidMicros: 100_000_000,
      amountDueMicros: 180_000_000,
    });
    await expect(
      f.iam.api.billing.voidStatement(as.root, {
        tenantId: f.tenantId,
        statementId: draftId,
        reason: 'x',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    const shortened = await f.iam.api.billing.createCreditNote(as.root, {
      tenantId: f.tenantId,
      statementId: draftId,
      amount: 50,
      reason: 'order_change',
      memo: 'Workshop shortened',
    });
    expect(shortened.creditNote).toMatchObject({
      number: `${number}-CN-01`,
      applied: { dueMicros: 50_000_000, creditMicros: 0, refundMicros: 0 },
    });
    expect(shortened.statement.amountDueMicros).toBe(130_000_000);

    // A payment processor settles the rest with $10 too much, which becomes credit; redelivery is ignored.
    const settled = await f.iam.billing.recordPayment({
      number,
      amount: 140,
      method: 'card',
      idempotencyKey: 'pi_123',
    });
    expect(settled).toMatchObject({
      duplicate: false,
      statement: { status: 'paid' },
      payment: { overpaymentMicros: 10_000_000, reference: 'pi_123' },
    });
    expect(
      (await f.iam.billing.recordPayment({ number, amount: 140, idempotencyKey: 'pi_123' }))
        .duplicate,
    ).toBe(true);

    // Credit notes on a paid invoice become credit, or a refund made elsewhere.
    const refunded = await f.iam.api.billing.createCreditNote(as.root, {
      tenantId: f.tenantId,
      statementId: draftId,
      amount: 20,
      reason: 'product_unsatisfactory',
      refund: true,
    });
    expect(refunded.creditNote.applied).toEqual({
      dueMicros: 0,
      creditMicros: 0,
      refundMicros: 20_000_000,
    });
    const credited = await f.iam.api.billing.createCreditNote(as.root, {
      tenantId: f.tenantId,
      statementId: draftId,
      amount: 5,
    });
    expect(credited.creditNote).toMatchObject({
      number: `${number}-CN-03`,
      reason: 'other',
      applied: { creditMicros: 5_000_000 },
    });
    await expect(
      f.iam.api.billing.createCreditNote(as.root, {
        tenantId: f.tenantId,
        statementId: draftId,
        amount: 1000,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      (await f.iam.api.billing.listCredits(as.owner, { tenantId: f.tenantId })).balanceMicros,
    ).toBe(15_000_000);
    expect(
      await f.iam.api.billing.listCreditNotes(as.owner, {
        tenantId: f.tenantId,
        statementId: draftId,
      }),
    ).toHaveLength(3);

    const page = await f.iam.api.billing.renderInvoice(as.owner, {
      tenantId: f.tenantId,
      statementId: draftId,
    });
    expect(page).toMatchObject({
      filename: `${number}.html`,
      contentType: 'text/html; charset=utf-8',
    });
    for (const text of [
      'Better Cloud Ltd',
      'Tax ID GB123456789',
      `Invoice ${number}`,
      '1,000 included',
      'Onboarding workshop',
      `${number}-CN-01`,
      'wire-1',
      'Amount due',
    ])
      expect(page.body).toContain(text);
  });

  it('reminds billing contacts before and after the due date, and writes invoices off', async () => {
    const { f, as, refresh, rootId, record } = await setup({ paymentReminderDays: [-3, 0, 7] });
    const lastMonth = shiftPeriod(periodOf(f.now(), 'UTC'), -1);
    await record(6000, { occurredAt: periodBounds(lastMonth, 'UTC').start + 3_600_000 });
    const closed = await f.iam.api.billing.closePeriod(as.root, { tenantId: rootId });
    const { statementId, number } = closed.issued[0]!;
    // Due in 30 days: nothing yet.
    expect((await f.iam.billing.sendPaymentReminders()).reminders).toEqual([]);
    f.advance(27 * day);
    expect((await f.iam.billing.sendPaymentReminders()).reminders).toEqual([
      expect.objectContaining({
        statementId,
        step: -3,
        amountDueMicros: 50_000_000,
        recipients: 1,
      }),
    ]);
    expect((await f.iam.billing.sendPaymentReminders()).reminders).toEqual([]);
    // Eight days late: the missed due-date step is skipped for the latest one.
    f.advance(11 * day);
    expect((await f.iam.billing.sendPaymentReminders()).reminders).toEqual([
      expect.objectContaining({ statementId, step: 7 }),
    ]);
    await f.iam.auth.dispatchOutbox();
    const reminders = f.inbox.filter((message) => message.template === 'payment-reminder');
    expect(reminders.map((message) => message.to)).toEqual(['owner@acme.test', 'owner@acme.test']);
    expect(renderDeliveryMessage(reminders[0]!)!.subject).toBe(
      `Invoice ${number} is due in 3 days`,
    );
    expect(renderDeliveryMessage(reminders[1]!)!.subject).toBe(
      `Invoice ${number} is 8 days overdue`,
    );
    await refresh();
    expect(await f.iam.api.billing.listStatements(as.owner, { tenantId: f.tenantId })).toEqual([
      expect.objectContaining({ overdue: true, amountDue: 50 }),
    ]);

    const writtenOff = await f.iam.api.billing.markUncollectible(as.root, {
      tenantId: f.tenantId,
      statementId,
    });
    expect(writtenOff.status).toBe('uncollectible');
    f.advance(30 * day);
    expect((await f.iam.billing.sendPaymentReminders()).checked).toBe(0);
    // A late payment still settles it.
    await refresh();
    const paid = await f.iam.api.billing.markPaid(as.root, {
      tenantId: f.tenantId,
      statementId,
      reference: 'late-wire',
    });
    expect(paid).toMatchObject({
      status: 'paid',
      amountPaidMicros: 50_000_000,
      amountDueMicros: 0,
    });
    await expect(
      organizationFixture({ billing: { paymentReminderDays: [500] } }),
    ).rejects.toMatchObject({ code: 'INVALID_CONFIG' });
    await expect(organizationFixture({ billing: { issuer: { name: '' } } })).rejects.toMatchObject({
      code: 'INVALID_CONFIG',
    });
  });
});

describe('coupons', () => {
  it('applies coupons after the contract discount, once or for months, and gives them back when voided', async () => {
    const { f, as, rootId, record, nextMonth } = await setup();
    const month = periodOf(f.now(), 'UTC');
    const launch = await f.iam.api.billing.createCoupon(as.root, {
      tenantId: rootId,
      code: 'launch50',
      name: 'Launch',
      percentOff: 50,
      duration: 'repeating',
      durationInMonths: 2,
      maxRedemptions: 1,
    });
    expect(launch).toMatchObject({ code: 'LAUNCH50', active: true, redemptions: 0 });
    await f.iam.api.billing.createCoupon(as.root, {
      tenantId: rootId,
      code: 'FLAT10',
      amountOff: 10,
    });
    await expect(
      f.iam.api.billing.createCoupon(as.root, {
        tenantId: rootId,
        code: 'BOTH',
        percentOff: 10,
        amountOff: 5,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.billing.createCoupon(as.owner, {
        tenantId: f.tenantId,
        code: 'MINE',
        percentOff: 100,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const redeemed = await f.iam.api.billing.redeemCoupon(as.owner, {
      tenantId: f.tenantId,
      code: 'launch50',
    });
    expect(redeemed).toMatchObject({ code: 'LAUNCH50', active: true, appliedInvoices: 0 });
    await expect(
      f.iam.api.billing.redeemCoupon(as.owner, { tenantId: f.tenantId, code: 'LAUNCH50' }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    await expect(
      f.iam.api.billing.redeemCoupon(as.owner, { tenantId: f.tenantId, code: 'NOPE1' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    // Coupons apply in the order they were redeemed.
    f.advance(1000);
    await f.iam.api.billing.redeemCoupon(as.owner, { tenantId: f.tenantId, code: 'flat10' });
    const coupons = await f.iam.api.billing.listCoupons(as.root, { tenantId: rootId });
    expect(coupons.find((coupon) => coupon.code === 'LAUNCH50')).toMatchObject({
      redemptions: 1,
      active: false,
    });

    // $50 of usage: half off, then $10 off.
    await record(6000);
    await nextMonth();
    const closed = await f.iam.billing.closePeriod();
    expect(closed.issued).toEqual([expect.objectContaining({ totalMicros: 15_000_000 })]);
    const statement = await f.iam.api.billing.getStatement(as.owner, {
      tenantId: f.tenantId,
      statementId: closed.issued[0]!.statementId,
    });
    expect(statement).toMatchObject({
      verified: true,
      subtotalMicros: 50_000_000,
      coupons: [
        { code: 'LAUNCH50', amountMicros: 25_000_000 },
        { code: 'FLAT10', amountMicros: 10_000_000 },
      ],
    });
    const sheet = await f.iam.api.billing.exportStatement(as.owner, {
      tenantId: f.tenantId,
      statementId: statement.id,
    });
    expect(sheet.body).toContain('coupon,LAUNCH50,Launch,,,-25.000000,');
    const discounts = async () =>
      Object.fromEntries(
        (await f.iam.api.billing.listDiscounts(as.owner, { tenantId: f.tenantId })).map(
          (discount) => [discount.code, [discount.appliedInvoices, discount.active]],
        ),
      );
    // The repeating coupon still covers this month; the one-off is used up.
    expect(await discounts()).toEqual({ LAUNCH50: [1, true], FLAT10: [1, false] });

    // Voiding gives the one-off coupon back, and the invoice is issued again the same way.
    await f.iam.api.billing.voidStatement(as.root, {
      tenantId: f.tenantId,
      statementId: statement.id,
      reason: 'Re-rate',
    });
    expect(await discounts()).toEqual({ LAUNCH50: [0, true], FLAT10: [0, true] });
    const again = await f.iam.billing.closePeriod({ period: month });
    expect(again.issued).toEqual([
      expect.objectContaining({ number: `INV-${compact(month)}-0002`, totalMicros: 15_000_000 }),
    ]);
    const launchDiscount = (
      await f.iam.api.billing.listDiscounts(as.owner, { tenantId: f.tenantId })
    ).find((discount) => discount.code === 'LAUNCH50')!;
    const removed = await f.iam.api.billing.removeDiscount(as.root, {
      tenantId: f.tenantId,
      discountId: launchDiscount.id,
    });
    expect(removed).toMatchObject({ active: false, endedAt: expect.any(Number) });
  });
});
