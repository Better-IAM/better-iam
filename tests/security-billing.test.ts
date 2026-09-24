import { afterEach, describe, expect, it } from 'vitest';
import { periodBounds, periodOf, shiftPeriod } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const day = 86_400_000;
const dayOf = (at: number) => new Date(at).toISOString().slice(0, 10);

/**
 * Acme on day `date` of next month (00:00 UTC, clear of month ends) with a platform `api-calls` meter at $1 a call from
 * last month on. `as` holds fresh root and owner sessions; `refresh` renews them after the clock moves.
 */
async function setup(date = 10) {
  const f = await organizationFixture();
  const next = periodBounds(shiftPeriod(periodOf(f.now(), 'UTC'), 1), 'UTC').start;
  f.advance(next + (date - 1) * day - f.now());
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
  });
  await f.iam.api.billing.setPrice(as.root, {
    tenantId: rootId,
    meter: 'api-calls',
    effectiveFrom: shiftPeriod(periodOf(f.now(), 'UTC'), -1),
    price: { model: 'per-unit', unitAmount: 1 },
  });
  return { f, as, refresh, rootId };
}

/** Moves the clock to `date` of the next month and renews the sessions. */
async function nextMonth(s: Awaited<ReturnType<typeof setup>>, date = 2) {
  const start = periodBounds(shiftPeriod(periodOf(s.f.now(), 'UTC'), 1), 'UTC').start;
  s.f.advance(start + (date - 1) * day - s.f.now());
  await s.refresh();
}

/** A person `{name}@acme.test` with a password (the fixture's own owner session has expired by now). */
function member(s: Awaited<ReturnType<typeof setup>>, name: string) {
  return s.f.iam.api.identities.create(s.as.owner, {
    tenantId: s.f.tenantId,
    email: `${name}@acme.test`,
    name,
    password: `a strong ${name} password`,
  });
}

/** A statement as the platform sees it. */
function statementOf(s: Awaited<ReturnType<typeof setup>>, statementId: string) {
  return s.f.iam.api.billing.getStatement(s.as.root, { tenantId: s.rootId, statementId });
}

describe('plan prices and trials', () => {
  it('prices usage outside a subscription from the rate card, and grants a plan trial once per account', async () => {
    const s = await setup(20);
    const { f, as, rootId } = s;
    await f.iam.api.billing.createPlan(as.root, {
      tenantId: rootId,
      key: 'team',
      name: 'Team',
      selfServe: true,
      trialDays: 14,
      items: [
        { id: 'platform', kind: 'fee', name: 'Platform fee', amount: 99 },
        {
          id: 'calls',
          kind: 'usage',
          name: 'API calls',
          meter: 'api-calls',
          price: { model: 'per-unit', unitAmount: 0.1 },
        },
      ],
    });
    // 1000 calls on the 5th, before any subscription: the rate card prices them.
    await f.iam.api.billing.record(as.owner, {
      tenantId: f.tenantId,
      meter: 'api-calls',
      quantity: 1000,
      occurredAt: f.now() - 15 * day,
    });
    const first = await f.iam.api.billing.subscribe(as.owner, {
      tenantId: f.tenantId,
      plan: 'team',
    });
    expect(first.subscription.status).toBe('trialing');
    expect(first.invoice).toBeUndefined();
    // 100 calls while subscribed: the plan prices them.
    await f.iam.api.billing.record(as.owner, {
      tenantId: f.tenantId,
      meter: 'api-calls',
      quantity: 100,
    });
    const preview = await f.iam.api.billing.previewStatement(as.owner, { tenantId: f.tenantId });
    expect(
      preview.lines
        .filter((line) => line.meter === 'api-calls')
        .map((line) => [line.quantity, line.amountMicros, line.price?.source ?? 'rate-card']),
    ).toEqual([
      [1000, 1_000_000_000, 'rate-card'],
      [100, 10_000_000, 'plan'],
    ]);
    await f.iam.api.billing.cancelSubscription(as.owner, {
      tenantId: f.tenantId,
      subscriptionId: first.subscription.id,
    });

    await nextMonth(s);
    const closed = await f.iam.billing.closePeriod();
    const issued = closed.issued.find((entry) => entry.accountId === f.tenantId)!;
    const statement = await statementOf(s, issued.statementId);
    expect(statement.totalMicros).toBe(1_010_000_000);

    // Subscribing to the plan again starts without a trial: the first month is invoiced at once.
    f.advance(18 * day);
    await s.refresh();
    const again = await f.iam.api.billing.subscribe(as.owner, {
      tenantId: f.tenantId,
      plan: 'team',
    });
    expect(again.subscription.status).toBe('active');
    expect(again.subscription.trialEndsAt).toBeUndefined();
    expect(again.invoice).toMatchObject({ billingReason: 'subscription', status: 'finalized' });
  });
});

describe('seat recording', () => {
  it('records seats under keys callers cannot claim, and one tenant never stops the job', async () => {
    const s = await setup();
    const { f, as, rootId } = s;
    await f.iam.api.billing.createMeter(as.root, {
      tenantId: rootId,
      key: 'seats',
      name: 'Seats',
      unit: 'seat-day',
    });
    await f.iam.api.billing.setPrice(as.root, {
      tenantId: rootId,
      meter: 'seats',
      price: { model: 'per-unit', unitAmount: 10 },
    });
    const alice = await member(s, 'alice');
    const zeta = await f.iam.api.tenants.create(as.root, {
      parentId: rootId,
      name: 'Zeta',
      type: 'organization',
      ownerEmail: 'owner@zeta.test',
    });
    await f.iam.auth.dispatchOutbox();
    const invitation = f.inbox.find(
      (message) => message.tenantId === zeta.tenant.id && message.template === 'owner-invitation',
    )!;
    await f.iam.api.tenants.acceptInvitation({
      tenantId: zeta.tenant.id,
      token: invitation.payload.token!,
      name: 'Zed',
      password: 'a strong zeta owner password',
    });
    await f.iam.api.billing.createMeter(as.owner, {
      tenantId: f.tenantId,
      key: 'decoy',
      name: 'D',
    });
    // The keys the job used to record under, claimed ahead: empty on the seats meter, and on another meter.
    const today = dayOf(f.now());
    await f.iam.api.billing.record(as.owner, {
      tenantId: f.tenantId,
      meter: 'seats',
      quantity: 0,
      identityId: f.ownerId,
      idempotencyKey: `seat:seats:${f.ownerId}:${today}`,
    });
    await f.iam.api.billing.record(as.owner, {
      tenantId: f.tenantId,
      meter: 'decoy',
      quantity: 0,
      idempotencyKey: `seat:seats:${alice.id}:${today}`,
    });
    const result = await f.iam.billing.recordSeats();
    expect(result.failedTenants).toEqual([]);
    const acme = await f.iam.billing.spend({ tenantId: f.tenantId, groupBy: 'meter' });
    expect(acme.rows.find((row) => row.key === 'seats')).toMatchObject({
      costMicros: 20_000_000,
      quantities: { seats: 2 },
    });
    const other = await f.iam.billing.spend({ tenantId: zeta.tenant.id, groupBy: 'meter' });
    expect(other.total.events).toBeGreaterThan(0);
    // Still once a day.
    expect(await f.iam.billing.recordSeats()).toMatchObject({ recorded: 0 });

    // A seat the job recorded under its old key (trusted server code only) still counts for that day.
    f.advance(day);
    await f.iam.billing.record({
      tenantId: f.tenantId,
      meter: 'seats',
      quantity: 1,
      identityId: f.ownerId,
      idempotencyKey: `seat:seats:${f.ownerId}:${dayOf(f.now())}`,
    });
    await f.iam.billing.recordSeats();
    const later = await f.iam.billing.spend({ tenantId: f.tenantId, groupBy: 'meter' });
    expect(later.rows.find((row) => row.key === 'seats')?.quantities).toEqual({ seats: 4 });
  });
});

describe('sub-account contract terms', () => {
  it('keeps a carved-out project under the organization’s tax and discount, and bills the commitment anyway', async () => {
    const s = await setup();
    const { f, as } = s;
    const previous = shiftPeriod(periodOf(f.now(), 'UTC'), -1);
    await f.iam.api.billing.setTerms(as.root, {
      tenantId: f.tenantId,
      taxRatePercent: 20,
      taxLabel: 'VAT',
      discountPercent: 10,
      minimumCommitment: 1000,
    });
    const project = await f.iam.api.tenants.create(as.owner, {
      parentId: f.tenantId,
      name: 'Shadow',
      type: 'project',
      ownerEmail: 'shadow@acme.test',
    });
    await f.iam.api.billing.setProfile(as.owner, {
      tenantId: f.tenantId,
      targetTenantId: project.tenant.id,
      companyName: 'Acme',
    });
    await f.iam.api.billing.recordMany(as.owner, {
      tenantId: f.tenantId,
      events: [
        {
          tenantId: project.tenant.id,
          meter: 'api-calls',
          quantity: 100,
          occurredAt: periodBounds(previous, 'UTC').start + 2 * day,
        },
      ],
    });
    const closed = await f.iam.billing.closePeriod({ period: previous });
    // Acme has no usage of its own but owes its $1000 commitment, plus VAT.
    const acme = closed.issued.find((entry) => entry.accountId === f.tenantId);
    expect(acme).toBeDefined();
    expect(await statementOf(s, acme!.statementId)).toMatchObject({
      lines: [],
      commitment: { minimumMicros: 1_000_000_000, trueUpMicros: 1_000_000_000 },
      tax: { ratePercent: 20, amountMicros: 200_000_000 },
      totalMicros: 1_200_000_000,
    });
    // The project pays Acme's contract rates: $100 − 10%, plus 20% VAT; the commitment is not billed twice.
    const shadow = closed.issued.find((entry) => entry.accountId === project.tenant.id)!;
    const statement = await statementOf(s, shadow.statementId);
    expect(statement).toMatchObject({
      subtotalMicros: 100_000_000,
      discount: { percent: 10, amountMicros: 10_000_000 },
      tax: { label: 'VAT', ratePercent: 20, amountMicros: 18_000_000 },
      totalMicros: 108_000_000,
    });
    expect(statement.commitment).toBeUndefined();
  });
});

describe('usage attribution', () => {
  it('keeps organizations from attributing usage to platform identities or spending platform budgets', async () => {
    const s = await setup();
    const { f, as, rootId } = s;
    const rootAdminId = f.root.identity.id;
    // Who set a platform price stays with the platform.
    const card = await f.iam.api.billing.listPrices(as.owner, {
      tenantId: f.tenantId,
      meter: 'api-calls',
    });
    expect(card.entries[0]!.setBy).toBeUndefined();
    expect(card.effective!.setBy).toBeUndefined();
    const rootCard = await f.iam.api.billing.listPrices(as.root, {
      tenantId: rootId,
      meter: 'api-calls',
    });
    expect(rootCard.entries[0]!.setBy).toBe(rootAdminId);
    await f.iam.api.billing.setTerms(as.root, { tenantId: f.tenantId, taxRatePercent: 5 });
    expect(
      (await f.iam.api.billing.getTerms(as.owner, { tenantId: f.tenantId })).setBy,
    ).toBeUndefined();

    // An enforced platform-wide budget, and an organization chargeback meter at a made-up price.
    await f.iam.api.billing.createBudget(as.root, {
      tenantId: rootId,
      name: 'Platform',
      amount: 100,
      enforce: true,
    });
    await f.iam.api.billing.createMeter(as.owner, {
      tenantId: f.tenantId,
      key: 'decoy',
      name: 'D',
    });
    await f.iam.api.billing.setPrice(as.owner, {
      tenantId: f.tenantId,
      meter: 'decoy',
      price: { model: 'per-unit', unitAmount: 1_000_000 },
    });
    await expect(
      f.iam.api.billing.record(as.owner, {
        tenantId: f.tenantId,
        meter: 'decoy',
        quantity: 1,
        identityId: rootAdminId,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const alice = await member(s, 'alice');
    const receipt = await f.iam.api.billing.record(as.owner, {
      tenantId: f.tenantId,
      meter: 'decoy',
      quantity: 1,
      identityId: alice.id,
    });
    expect(receipt.identityId).toBe(alice.id);
    // Platform administrators still attribute to platform identities.
    const byRoot = await f.iam.api.billing.record(as.root, {
      tenantId: f.tenantId,
      meter: 'api-calls',
      quantity: 1,
      identityId: rootAdminId,
    });
    expect(byRoot.identityId).toBe(rootAdminId);

    // Acme's chargeback spends Acme's own budget, never the platform's.
    await f.iam.api.billing.createBudget(as.owner, {
      tenantId: f.tenantId,
      name: 'Acme',
      amount: 100,
      enforce: true,
    });
    f.advance(31_000); // past the budget status cache
    const verdict = await f.iam.billing.check({ tenantId: f.tenantId });
    expect(verdict.allowed).toBe(false);
    expect(verdict.blockedBy?.name).toBe('Acme');
    expect(verdict.budgets.find((budget) => budget.name === 'Platform')).toMatchObject({
      exceeded: false,
      spentMicros: 1_000_000,
    });
    expect((await f.iam.billing.check({ tenantId: rootId })).allowed).toBe(true);
  });

  it('reserves built-in meter keys for the platform', async () => {
    const { f, as } = await setup();
    await expect(
      f.iam.api.billing.createMeter(as.owner, {
        tenantId: f.tenantId,
        key: 'inference',
        name: 'Mine',
        pricing: 'reported',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
  });
});

describe('billing reads and profiles', () => {
  it('lets team maintainers read team spend only from their own sign-in session', async () => {
    const s = await setup();
    const { f, as } = s;
    const alice = await member(s, 'alice');
    const team = await f.iam.api.teams.create(as.owner, {
      tenantId: f.tenantId,
      name: 'Platform',
      maintainerIds: [alice.id],
    });
    await f.iam.api.billing.record(as.owner, {
      tenantId: f.tenantId,
      meter: 'api-calls',
      quantity: 10,
      identityId: alice.id,
    });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const own = await f.iam.api.billing.teamSpend(aliceSession, {
      tenantId: f.tenantId,
      teamId: team.id,
    });
    expect(own.total.costMicros).toBe(10_000_000);
    // A session token derived from her session is not her acting in her own right.
    const minter = await f.iam.api.roles.create(as.owner, {
      tenantId: f.tenantId,
      name: 'Token minter',
      permissions: ['iam:session-tokens:create'],
    });
    await f.iam.api.bindings.create(as.owner, {
      tenantId: f.tenantId,
      roleId: minter.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    const derived = await f.iam.api.sts.getSessionToken(aliceSession);
    await expect(
      f.iam.api.billing.teamSpend(
        { token: derived.token },
        { tenantId: f.tenantId, teamId: team.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });

  it('keeps payment terms beyond the default for root administrators', async () => {
    const { f, as } = await setup();
    await expect(
      f.iam.api.billing.setProfile(as.owner, { tenantId: f.tenantId, paymentTermsDays: 365 }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const shorter = await f.iam.api.billing.setProfile(as.owner, {
      tenantId: f.tenantId,
      paymentTermsDays: 15,
    });
    expect(shorter.profile?.paymentTermsDays).toBe(15);
    await f.iam.api.billing.setProfile(as.root, { tenantId: f.tenantId, paymentTermsDays: 60 });
    // Saving the profile again keeps what the platform granted; asking for more is refused.
    const resaved = await f.iam.api.billing.setProfile(as.owner, {
      tenantId: f.tenantId,
      companyName: 'Acme Corporation',
      paymentTermsDays: 60,
    });
    expect(resaved.profile?.paymentTermsDays).toBe(60);
    await expect(
      f.iam.api.billing.setProfile(as.owner, { tenantId: f.tenantId, paymentTermsDays: 90 }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});

describe('invoices', () => {
  it('neutralizes formulas in CSV exports but keeps plain negative numbers', async () => {
    const { f, as } = await setup();
    await f.iam.api.billing.createInvoiceItem(as.root, {
      tenantId: f.tenantId,
      description: "-1+cmd|' /C calc'!A0",
      amount: 5,
    });
    await f.iam.api.billing.createInvoiceItem(as.root, {
      tenantId: f.tenantId,
      description: 'Service credit',
      amount: -2,
    });
    const closed = await f.iam.billing.closePeriod();
    const sheet = await f.iam.api.billing.exportStatement(as.owner, {
      tenantId: f.tenantId,
      statementId: closed.issued[0]!.statementId,
    });
    expect(sheet.body).toContain(",'-1+cmd|' /C calc'!A0,");
    expect(sheet.body).not.toMatch(/,-1\+cmd/);
    expect(sheet.body).toContain(',-2.000000,');
  });

  it('refuses to void an invoice whose credit balance a later invoice used, until that one is voided', async () => {
    const s = await setup();
    const { f, as } = s;
    // Last month: $20 of charges and a $100 credit item: $80 of account credit carried forward.
    await f.iam.api.billing.createInvoiceItem(as.root, {
      tenantId: f.tenantId,
      description: 'Setup',
      amount: 20,
    });
    await f.iam.api.billing.createInvoiceItem(as.root, {
      tenantId: f.tenantId,
      description: 'Migration credit',
      amount: -100,
    });
    const first = (await f.iam.billing.closePeriod()).issued[0]!;
    expect((await statementOf(s, first.statementId)).carryForward).toMatchObject({
      amountMicros: 80_000_000,
    });
    // This month's $50 of usage is paid from that credit.
    await f.iam.api.billing.record(as.owner, {
      tenantId: f.tenantId,
      meter: 'api-calls',
      quantity: 50,
    });
    await nextMonth(s);
    const second = (await f.iam.billing.closePeriod()).issued[0]!;
    expect(await statementOf(s, second.statementId)).toMatchObject({
      creditsMicros: 50_000_000,
      totalMicros: 0,
    });
    await expect(
      f.iam.api.billing.voidStatement(as.root, {
        tenantId: f.tenantId,
        statementId: first.statementId,
        reason: 'Re-rate',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
    // Voided in order, the credit is whole again before the credit items go back up for the next invoice.
    await f.iam.api.billing.voidStatement(as.root, {
      tenantId: f.tenantId,
      statementId: second.statementId,
      reason: 'Re-rate',
    });
    await f.iam.api.billing.voidStatement(as.root, {
      tenantId: f.tenantId,
      statementId: first.statementId,
      reason: 'Re-rate',
    });
    expect(
      (await f.iam.api.billing.listCredits(as.owner, { tenantId: f.tenantId })).balanceMicros,
    ).toBe(0);
    expect(
      (
        await f.iam.api.billing.listInvoiceItems(as.owner, {
          tenantId: f.tenantId,
          status: 'pending',
        })
      )
        .map((item) => item.amount)
        .sort((a, b) => a - b),
    ).toEqual([-100, 20]);
  });
});
