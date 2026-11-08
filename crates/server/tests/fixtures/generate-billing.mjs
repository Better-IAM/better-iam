// Reference vectors for the Rust port of billing.ts, billing-plans.ts and billing-invoices.ts, computed by the
// TypeScript implementation. Run from the repository root after building packages/server:
//   node crates/server/tests/fixtures/generate-billing.mjs > crates/server/tests/fixtures/billing.json
const base = process.env.SERVER_DIST_URL ?? new URL('../../../../packages/server/dist/', import.meta.url).href;
const b = await import(base + 'billing.js');
const inv = await import(base + 'billing-invoices.js');
const plans = await import(base + 'billing-plans.js');
const v = {};
v.bounds = ['UTC', 'America/New_York', 'Asia/Kolkata', 'Australia/Lord_Howe'].flatMap((tz) =>
  ['2026-03', '2026-11'].map((period) => ({ tz, period, ...b.periodBounds(period, tz) })),
);
v.days = [
  [1772323199999, 'America/New_York'],
  [1772395200000, 'Asia/Tokyo'],
  [1793505600000, 'Australia/Lord_Howe'],
].map(([at, tz]) => ({ at, tz, period: b.periodOf(at, tz), day: b.dayOf(at, tz) }));
v.rollups = [
  [
    't1',
    '2026-03-04',
    'm1',
    { identityId: 'i1', agentId: 'a1', teamIds: ['a', 'b'], departmentId: 'd', tags: { env: 'prod', project: 'x' } },
  ],
  ['t1', '2026-03-04', 'm1', { teamIds: [] }],
].map(([tenantId, day, meterId, attribution]) => ({
  tenantId,
  day,
  meterId,
  attribution,
  id: b.rollupId(tenantId, day, meterId, attribution),
}));
const stmt = {
  number: 'INV-202603-0001',
  period: '2026-03',
  currency: 'USD',
  tenantId: 'acct',
  lines: [
    {
      kind: 'fee',
      name: 'Base',
      unit: 'month',
      quantity: 1,
      unitAmountMicros: 10_000_000,
      amountMicros: 5_000_000,
      subscriptionId: 's',
      planItemId: 'base',
      servicePeriod: { start: 1, end: 2 },
      proration: 0.5,
      description: 'Pro: Base',
    },
  ],
  subtotalMicros: 5_000_000,
  creditsMicros: 0,
  totalMicros: 5_000_000,
  billTo: { name: 'Acme', emails: ['a@b.c'] },
  tax: { label: 'VAT', ratePercent: 20, amountMicros: 1_000_000 },
  billingReason: 'period',
};
v.hash = { statement: stmt, hash: b.statementHash(stmt) };
const specs = [
  { model: 'volume', tiers: [{ upTo: 10, unitAmount: 1 }, { upTo: null, unitAmount: 0.5, flatAmount: 2 }] },
  {
    model: 'graduated',
    includedQuantity: 5,
    tiers: [
      { upTo: 10, unitAmount: 1, flatAmount: 0 },
      { upTo: null, unitAmount: 0.25, flatAmount: 3 },
    ],
    minimumAmount: 1,
    maximumAmount: null,
  },
  { model: 'package', packageSize: 100, packageAmount: 0.5, includedQuantity: 10.5 },
  { model: 'per-unit', unitAmount: 0.0000025 },
];
v.prices = specs.map((input) => {
  const spec = b.priceSpec(input);
  return {
    input,
    spec,
    public: b.publicPriceSpec(spec),
    quantities: [0, 3, 15, 150.25, 1234567].map((quantity) => ({
      quantity,
      amount: b.priceQuantity(spec, quantity),
      breakdown: b.priceBreakdown(spec, quantity),
    })),
  };
});
v.coupon = {
  input: { code: ' spring-24 ', percentOff: 12.3456, duration: 'repeating', durationInMonths: 3, maxRedemptions: 5 },
  now: 1000,
};
v.coupon.output = inv.couponSettings(v.coupon.input, 1000);
v.item = { input: { description: ' Setup ', amount: -12.345, quantity: 3, period: '2026-04', metadata: { b: '2', a: '1' } } };
v.item.output = inv.invoiceItemInput(v.item.input);
const full = {
  id: 'st1',
  tenantId: 'acct',
  status: 'finalized',
  issuedAt: 1772323200000,
  dueAt: 4102444800000,
  hash: 'abc',
  payments: [
    { id: 'p', amountMicros: 1_000_000, method: 'card', reference: 'R&1', receivedAt: 1772323200000, recordedBy: 'x' },
  ],
  amountPaidMicros: 1_000_000,
  creditNotesMicros: 500_000,
  ...stmt,
  periodStart: 1772323200000,
  periodEnd: 1775001600000,
  lines: [
    ...stmt.lines,
    {
      meter: 'api-calls',
      name: 'API calls',
      unit: 'request',
      quantity: 12345.6789,
      amountMicros: 1234_567_891,
      pricing: 'rate-card',
      price: { model: 'graduated', effectiveFrom: '2026-01', source: 'plan' },
      includedQuantity: 1000,
      tiers: [
        { from: 1, to: 100, quantity: 100, unitAmountMicros: 12.5, amountMicros: 1250 },
        { from: 101, to: null, quantity: 12245.6789, unitAmountMicros: 1_000_000, flatAmountMicros: 2_000_000, amountMicros: -3 },
      ],
      adjustedFromMicros: 0,
    },
    { kind: 'item', name: 'Tokens', unit: 'token', quantity: 2.5, unitAmountMicros: 0.0034, amountMicros: -0.0034 },
  ],
  discount: { percent: 10, amountMicros: 0 },
  commitment: { minimumMicros: 100_000_000, trueUpMicros: 55_000_000 },
  coupons: [
    { discountId: 'd', code: 'SPRING', name: 'Spring sale', amountMicros: 2_000_000 },
    { discountId: 'e', code: 'TEN', name: 'TEN', amountMicros: 1_000_000 },
  ],
  creditsMicros: 20_000_000,
  billTo: {
    name: 'Acme',
    companyName: 'Acme Ltd',
    taxId: 'GB1',
    address: '1 Road\nTown',
    purchaseOrder: 'PO-9',
    emails: ['a@b.c', 'd@e.f'],
  },
  breakdown: { tenants: [], teams: [], departments: [], identities: [] },
  creditsApplied: [],
};
const options = {
  issuer: { name: 'Better Cloud Ltd', address: '1 Main Street\nLondon', taxId: 'GB123', paymentInstructions: 'Pay <now>' },
  creditNotes: [
    {
      id: 'n',
      tenantId: 'acct',
      number: 'CN-1',
      statementId: 'st1',
      statementNumber: 'INV',
      amountMicros: 500_000,
      reason: 'order_change',
      memo: 'Fix',
      applied: { dueMicros: 0, creditMicros: 0, refundMicros: 0 },
      issuedAt: 1,
      issuedBy: 'x',
    },
  ],
};
v.html = [
  { statement: full, options, html: inv.renderInvoiceHtml(full, options) },
  ...['CHF', 'EUR', 'JPY', 'CAD', 'XOF', 'usd'].map((currency) => {
    const statement = JSON.parse(
      JSON.stringify({ ...full, currency, status: 'draft', number: '', hash: '', payments: undefined, amountPaidMicros: undefined }),
    );
    return { statement, options: { appName: 'Acme Cloud' }, html: inv.renderInvoiceHtml(statement, { appName: 'Acme Cloud' }) };
  }),
];
const sub = {
  id: 'sub1',
  tenantId: 'acct',
  planId: 'p',
  planKey: 'pro',
  planName: 'Pro',
  startedAt: Date.UTC(2026, 2, 10),
  cancelAtPeriodEnd: false,
  seats: 5,
  seatHistory: [
    { at: Date.UTC(2026, 2, 10), seats: 5 },
    { at: Date.UTC(2026, 2, 20), seats: 8 },
  ],
  billedAdvance: ['2026-03'],
  createdAt: 0,
  createdBy: 'x',
  updatedAt: 0,
};
const plan = {
  id: 'p',
  tenantId: 'root',
  key: 'pro',
  name: 'Pro',
  items: [
    { id: 'base', kind: 'fee', name: 'Base', amountMicros: 49_000_000, billing: 'advance' },
    { id: 'seats', kind: 'seat', name: 'Seats', unitAmountMicros: 10_000_000, billing: 'advance', includedSeats: 2 },
    { id: 'support', kind: 'fee', name: 'Support', amountMicros: 5_000_000, billing: 'arrears' },
  ],
  selfServe: false,
  archived: false,
  createdAt: 0,
  createdBy: 'x',
  updatedAt: 0,
  updatedBy: 'x',
};
const fresh = { ...sub, seatHistory: [], billedAdvance: [], trialEndsAt: Date.UTC(2026, 2, 12) };
v.plans = { subscription: sub, plan, fresh, first: plans.firstPeriodLines(fresh, plan, 'UTC') };
v.plans.prorations = [
  { subscription: sub, plan, at: Date.UTC(2026, 2, 25), timeZone: 'UTC', seats: { before: 8, after: 3 }, ending: false, createdBy: 'me' },
  { subscription: sub, plan, at: Date.UTC(2026, 2, 25), timeZone: 'UTC', seats: { before: 3, after: 4 }, ending: false, createdBy: 'me' },
  { subscription: sub, plan, at: Date.UTC(2026, 2, 25), timeZone: 'UTC', ending: true, createdBy: 'me' },
  { subscription: sub, plan, at: Date.UTC(2026, 3, 2), timeZone: 'UTC', ending: true, createdBy: 'me' },
].map((input) => ({ input, items: plans.prorationItems(input).map(({ id, ...rest }) => rest) }));
v.planSettings = {
  input: {
    name: ' Pro ',
    items: [
      { id: 'base', kind: 'fee', amount: 49 },
      { id: 'seats', kind: 'seat', name: 'Seats', unitAmount: 10, includedSeats: 2, billing: 'arrears' },
      { id: 'calls', kind: 'usage', meter: 'api-calls', price: { model: 'per-unit', unitAmount: 0.001 } },
    ],
    trialDays: 14,
    description: ' The plan ',
  },
};
v.planSettings.output = plans.planSettings(v.planSettings.input);
v.meterSettings = { input: { name: ' API calls ', unit: 'request', description: null } };
v.meterSettings.output = b.meterSettings(v.meterSettings.input);
v.amounts = {
  input: {
    subtotalMicros: 50_000_000,
    terms: { id: 't', tenantId: 'a', discountPercent: 10, minimumCommitmentMicros: 100_000_000, taxRatePercent: 20, taxLabel: 'VAT', setAt: 0, setBy: 'x' },
    commitment: true,
    discounts: [
      { id: 'd1', tenantId: 'a', couponId: 'c', code: 'TEN', name: 'Ten', percentOff: 10, duration: 'once', appliedInvoices: 0, redeemedAt: 0, redeemedBy: 'x' },
      { id: 'd2', tenantId: 'a', couponId: 'c2', code: 'FIVE', name: 'Five', amountOffMicros: 5_000_000, duration: 'forever', appliedInvoices: 0, redeemedAt: 0, redeemedBy: 'x' },
    ],
  },
  creditAvailable: 20_000_000,
};
v.amounts.output = b.invoiceAmounts({ ...v.amounts.input, credit: (due) => Math.min(due, 20_000_000) });
v.amountsNegative = b.invoiceAmounts({ subtotalMicros: -3_000_000, commitment: false, credit: () => 0 });
process.stdout.write(JSON.stringify(v, null, 1) + '\n');
