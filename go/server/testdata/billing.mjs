// Writes billing.json: billing.ts, billing-plans.ts and billing-invoices.ts (packages/server/src) over pure inputs and
// over a small store (tenants, meters, prices, roll-ups, plans, subscriptions, teams, departments), for the Go billing
// differential test (billing_test.go). The store here returns `find` results in ID order, as the SQL adapters do.
// Regenerate (after building the TypeScript packages): node go/server/testdata/billing.mjs > go/server/testdata/billing.json
import * as b from '../../../packages/server/dist/billing.js';
import * as inv from '../../../packages/server/dist/billing-invoices.js';
import * as plans from '../../../packages/server/dist/billing-plans.js';

const out = {};
const day = (y, m, d, h = 0, min = 0) => Date.UTC(y, m - 1, d, h, min);

// --- pure functions ------------------------------------------------------------------------------------------------

out.periodOf = [b.periodOf(day(2026, 3, 1, 3), 'America/New_York'), b.periodOf(day(2026, 3, 1, 6), 'America/New_York')];
out.dayOf = b.dayOf(day(2026, 11, 1, 4, 30), 'Asia/Kolkata');
out.bounds = [b.periodBounds('2026-03', 'America/New_York'), b.periodBounds('2026-11', 'Europe/London'), b.periodBounds('2026-12', 'UTC')];
out.shift = [b.shiftPeriod('2026-01', -1), b.shiftPeriod('2026-12', 1), b.shiftPeriod('2026-05', -17)];
out.windows = [b.windowPeriods('quarter', '2026-05'), b.windowPeriods('year', '2026-05'), b.windowPeriods('month', '2026-05')];
out.rollup = b.rollupId('t1', '2026-09-01', 'm1', { identityId: 'i1', teamIds: ['a', 'b'], tags: { env: 'prod', project: 'x' } });
out.rollup2 = b.rollupId('t1', '2026-09-01', 'm1', { teamIds: [] });
out.hashInput = {
  number: 'INV-202609-0001', period: '2026-09', currency: 'USD', tenantId: 'org',
  lines: [{ meter: 'api-calls', name: 'API calls', unit: 'request', quantity: 1500, amountMicros: 5000000 }],
  subtotalMicros: 5000000, creditsMicros: 0, totalMicros: 5000000, billTo: { name: 'Acme', emails: ['a@acme.test'] },
  tax: { label: 'VAT', ratePercent: 20, amountMicros: 1000000 }, status: 'paid',
};
out.hash = b.statementHash(out.hashInput);
out.amountsInput = {
  subtotalMicros: 12345678,
  terms: { discountPercent: 10, minimumCommitmentMicros: 20000000, taxRatePercent: 8.25, taxLabel: 'Sales tax' },
  commitment: true,
  discounts: [{ id: 'd1', code: 'TEN', name: 'Ten off', percentOff: 10 }, { id: 'd2', code: 'FIVE', name: 'FIVE', amountOffMicros: 5000000 }],
};
out.amounts = b.invoiceAmounts({ ...out.amountsInput, credit: (due) => Math.min(due, 3000000) });
out.amounts2 = b.invoiceAmounts({ subtotalMicros: -2500000, commitment: false, credit: () => 0 });
out.settingsInput = { paymentReminderDays: [7, -3, 7, 0], issuer: { name: 'X', extra: 1 } };
out.settings = b.billingSettings(out.settingsInput);
out.defaultSettings = b.billingSettings(undefined);
out.volumeInput = { model: 'volume', includedQuantity: 5, tiers: [{ upTo: 10, unitAmount: 0.5, flatAmount: 1 }, { upTo: null, unitAmount: 0.25 }], minimumAmount: 0 };
const volume = b.priceSpec(out.volumeInput);
out.volume = { spec: volume, breakdown: b.priceBreakdown(volume, 30), quantity: b.priceQuantity(volume, 30), public: b.publicPriceSpec(volume) };

const statement = {
  id: 's1', tenantId: 'org', number: 'INV-202609-0001', status: 'finalized', period: '2026-09', currency: 'EUR', periodStart: 0, periodEnd: 1,
  issuedAt: day(2026, 10, 1), dueAt: day(2026, 10, 31), hash: 'abc', billingReason: 'period',
  lines: [
    {
      meter: 'api-calls', name: 'API <calls>', unit: 'request', quantity: 12500.5, amountMicros: 117502500,
      tiers: [
        { from: 1, to: 10000, quantity: 10000, unitAmountMicros: 10000, amountMicros: 100000000 },
        { from: 10001, to: null, quantity: 2500.5, unitAmountMicros: 7000, flatAmountMicros: 5000000, amountMicros: 22503500 },
      ],
      includedQuantity: 1000, price: { model: 'graduated', effectiveFrom: '2026-08', source: 'plan' }, adjustedFromMicros: 120000000,
    },
    {
      kind: 'fee', name: 'Platform fee', unit: 'month', quantity: 1, unitAmountMicros: 99000000, amountMicros: 66000000,
      servicePeriod: { start: day(2026, 10, 1), end: day(2026, 11, 1) }, proration: 0.6667,
    },
  ],
  subtotalMicros: 183502500, discount: { percent: 10, amountMicros: 0 }, commitment: { minimumMicros: 200000000, trueUpMicros: 16497500 },
  coupons: [{ discountId: 'd', code: 'SAVE', name: 'Save more', amountMicros: 1000000 }, { discountId: 'e', code: 'X1', name: 'X1', amountMicros: 2500 }],
  creditsMicros: 500000, tax: { label: 'VAT', ratePercent: 19, amountMicros: 37620000 }, totalMicros: 235620000,
  billTo: { name: 'Acme', companyName: 'Acme & Co', address: '1 Road\nTown', taxId: 'DE1', purchaseOrder: 'PO-1', costCenter: 'CC', emails: ['a@acme.test', 'b@acme.test'] },
  payments: [{ id: 'p', amountMicros: 100000000, method: 'bank_transfer', reference: 'REF "1"', receivedAt: day(2026, 10, 5), recordedBy: 'x' }],
  amountPaidMicros: 100000000, creditNotesMicros: 20000000,
};
out.invoice = statement;
out.invoiceOptions = {
  issuer: { name: 'Better Cloud Ltd', address: '1 Main Street\nLondon', taxId: 'GB123', email: 'billing@x.test', paymentInstructions: 'Pay to IBAN <X>' },
  creditNotes: [{ number: 'CN-1', reason: 'product_unsatisfactory', memo: 'sorry', amountMicros: 20000000 }],
};
// Rendered after the due date (overdue).
out.html = inv.renderInvoiceHtml(statement, out.invoiceOptions);
const draft = { ...statement, status: 'draft', number: '', hash: '', currency: 'usd', lines: [{ name: 'Tiny', unit: 'token', quantity: 3, unitAmountMicros: 0.5, amountMicros: 1.5 }] };
for (const key of ['payments', 'amountPaidMicros', 'discount', 'commitment', 'coupons', 'tax', 'creditNotesMicros']) delete draft[key];
out.draft = draft;
out.htmlDraft = inv.renderInvoiceHtml(draft, { appName: 'Acme IAM' });

const sub = {
  id: 'sub1', tenantId: 'org', planId: 'p1', planKey: 'pro', planName: 'Pro', startedAt: day(2026, 9, 10), trialEndsAt: day(2026, 9, 15),
  cancelAtPeriodEnd: false, seats: 5, seatHistory: [{ at: day(2026, 9, 10), seats: 5 }, { at: day(2026, 9, 20), seats: 8 }],
  billedAdvance: ['2026-09'], createdAt: 0, createdBy: 'x', updatedAt: 0,
};
const plan = {
  id: 'p1', tenantId: 'root', key: 'pro', name: 'Pro', selfServe: true, archived: false,
  items: [
    { id: 'base', kind: 'fee', name: 'Base', amountMicros: 49000000, billing: 'advance' },
    { id: 'seats', kind: 'seat', name: 'Seats', unitAmountMicros: 10000000, includedSeats: 2, billing: 'advance' },
    { id: 'support', kind: 'fee', name: 'Support', amountMicros: 5000000, billing: 'arrears' },
  ],
};
out.subscription = sub;
out.plan = plan;
out.first = plans.firstPeriodLines(sub, plan, 'UTC');
const withoutId = (items) => items.map(({ id, ...rest }) => rest);
out.proration = withoutId(plans.prorationItems({ subscription: sub, plan, at: day(2026, 9, 25), timeZone: 'UTC', seats: { before: 8, after: 4 }, ending: false, createdBy: 'me' }));
out.prorationEnding = withoutId(plans.prorationItems({ subscription: sub, plan, at: day(2026, 9, 25), timeZone: 'UTC', ending: true, createdBy: 'me' }));
out.planInput = {
  name: ' Pro ',
  items: [
    { id: 'base', kind: 'fee', amount: 49 },
    { id: 'seats', kind: 'seat', name: 'Seats', unitAmount: 10, includedSeats: 2, billing: 'arrears' },
    { id: 'calls', kind: 'usage', meter: 'api-calls', price: { model: 'per-unit', unitAmount: 0.001 } },
  ],
  trialDays: 14, description: 'The pro plan',
};
out.planSettings = plans.planSettings(out.planInput);
out.couponInput = { code: ' straße-1 ', percentOff: 12.34567, duration: 'repeating', durationInMonths: 3, maxRedemptions: 10 };
out.coupon = inv.couponSettings(out.couponInput, 0);
out.itemInput = { description: ' Setup ', amount: -12.345, quantity: 3, period: '2026-09', metadata: { b: '2', a: '1' } };
out.item = inv.invoiceItemInput(out.itemInput);

// --- a store ---------------------------------------------------------------------------------------------------------

const records = {};
const add = (collection, ...list) => (records[collection] ??= []).push(...list);
const tenant = (id, parentId, type) => ({ id, tenantId: id, name: id, type, parentId, status: 'active', createdAt: 1 });
add('tenants', tenant('root', null, 'root'), tenant('org', 'root', 'organization'), tenant('org2', 'root', 'organization'),
  tenant('proj', 'org', 'project'), tenant('proj2', 'org', 'project'));
add('billingProfiles', { id: 'bp1', tenantId: 'proj2', uniqueKey: 'profile', billingEmails: [], createdAt: 1, createdBy: 'x', updatedAt: 1, updatedBy: 'x' });
add('billingTerms', { id: 'bt1', tenantId: 'org', uniqueKey: 'terms', discountPercent: 10, minimumCommitmentMicros: 50000000, taxRatePercent: 20, setAt: 1, setBy: 'x' });
const meter = (id, tenantId, key, aggregation, pricing) => ({
  id, tenantId, uniqueKey: key, key, name: key.toUpperCase(), unit: 'unit', aggregation, pricing, archived: false,
  createdAt: 1, createdBy: 'x', updatedAt: 1, updatedBy: 'x',
});
add('billingMeters', meter('m1', 'root', 'api-calls', 'sum', 'rate-card'), meter('m2', 'root', 'active-users', 'unique', 'rate-card'),
  meter('m3', 'root', 'inference', 'sum', 'reported'), meter('m4', 'org', 'builds', 'sum', 'rate-card'),
  meter('m5', 'root', 'storage', 'sum', 'rate-card'));
const price = (id, tenantId, meterId, effectiveFrom, spec) => ({
  id, tenantId, uniqueKey: `${meterId}:${effectiveFrom}`, meterId, meter: meterId, definerId: 'root', effectiveFrom, spec, setAt: 1, setBy: 'x',
});
add('billingPrices',
  price('p1', 'root', 'm1', '2026-01', { model: 'graduated', includedQuantity: 1000, tiers: [{ upTo: 10000, unitAmountMicros: 10000 }, { upTo: null, unitAmountMicros: 5000 }] }),
  price('p2', 'org2', 'm1', '2026-08', { model: 'per-unit', unitAmountMicros: 2000 }),
  price('p3', 'root', 'm1', '2026-10', { model: 'per-unit', unitAmountMicros: 1 }),
  price('p4', 'root', 'm2', '2026-01', { model: 'per-unit', unitAmountMicros: 5000000 }),
  price('p5', 'org', 'm4', '2026-01', { model: 'per-unit', unitAmountMicros: 100000, minimumAmountMicros: 1000000 }));
add('billingPlans', {
  id: 'pl1', tenantId: 'root', uniqueKey: 'pro', key: 'pro', name: 'Pro', selfServe: false, archived: false,
  items: [
    { id: 'base', kind: 'fee', name: 'Base', amountMicros: 49000000, billing: 'advance' },
    { id: 'seats', kind: 'seat', name: 'Seats', unitAmountMicros: 10000000, includedSeats: 2, billing: 'advance' },
    { id: 'users', kind: 'usage', name: 'Active users', meter: 'active-users', price: { model: 'per-unit', unitAmountMicros: 3000000 } },
    { id: 'support', kind: 'fee', name: 'Support', amountMicros: 5000000, billing: 'arrears' },
  ],
  createdAt: 1, createdBy: 'x', updatedAt: 1, updatedBy: 'x',
});
add('billingSubscriptions', {
  id: 's1', tenantId: 'org', uniqueKey: 'plan:pl1', planId: 'pl1', planKey: 'pro', planName: 'Pro', startedAt: day(2026, 9, 15),
  cancelAtPeriodEnd: false, seats: 6, seatHistory: [{ at: day(2026, 9, 15), seats: 4 }, { at: day(2026, 9, 25), seats: 6 }],
  billedAdvance: [], createdAt: 1, createdBy: 'x', updatedAt: 1,
});
let rollupNumber = 0;
const rollup = (tenantId, date, meterId, quantity, extra = {}) => ({
  id: `r${String(++rollupNumber).padStart(2, '0')}`, tenantId, period: date.slice(0, 7), day: date, meterId, meter: meterId,
  teamIds: [], ...extra, quantity, costMicros: extra.costMicros ?? 0, events: quantity, updatedAt: 1,
});
add('billingRollups',
  rollup('org', '2026-09-02', 'm1', 4000, { identityId: 'alice', teamIds: ['t1'], departmentId: 'd1' }),
  rollup('org', '2026-09-20', 'm1', 9000, { identityId: 'bob', tags: { project: 'apollo' } }),
  rollup('proj', '2026-09-05', 'm1', 2500, { identityId: 'carol', teamIds: ['t1', 't2'] }),
  rollup('proj2', '2026-09-06', 'm1', 3000, { identityId: 'dave' }),
  rollup('org2', '2026-09-07', 'm1', 1500, { identityId: 'erin' }),
  rollup('org', '2026-09-03', 'm2', 1, { identityId: 'alice', teamIds: ['t1'] }),
  rollup('org', '2026-09-16', 'm2', 2, { identityId: 'alice', teamIds: ['t1'] }),
  rollup('org', '2026-09-10', 'm2', 1, { identityId: 'bob' }),
  rollup('proj', '2026-09-18', 'm2', 1, { identityId: 'bot', agentId: 'bot', teamIds: ['t2'] }),
  rollup('org', '2026-09-04', 'm3', 100, { identityId: 'alice', costMicros: 1234.5678 }),
  rollup('org', '2026-09-04', 'm4', 3, { identityId: 'alice' }),
  rollup('proj', '2026-09-08', 'm5', 10, { identityId: 'carol' }),
  rollup('org', '2026-08-30', 'm1', 5000, { identityId: 'alice' }));
add('identities',
  { id: 'alice', tenantId: 'org', kind: 'user', name: 'alice', status: 'active', createdAt: 1 },
  { id: 'bob', tenantId: 'org', kind: 'user', name: 'bob', status: 'active', createdAt: 1 },
  { id: 'bot', tenantId: 'org', kind: 'agent', name: 'bot', status: 'active', agent: { sponsorId: 'alice' }, createdAt: 1 },
  { id: 'gone', tenantId: 'org', kind: 'user', name: 'gone', status: 'deleted', createdAt: 1 },
  { id: 'erin', tenantId: 'org2', kind: 'user', name: 'erin', status: 'active', createdAt: 1 });
add('teams',
  { id: 't1', tenantId: 'org', name: 'Platform', departmentId: 'd1', createdAt: 1 },
  { id: 't2', tenantId: 'org', name: 'Web', parentId: 't1', createdAt: 2 },
  { id: 't3', tenantId: 'org', name: 'Data', departmentId: 'd0', createdAt: 3 });
add('teamMembers',
  { id: 'tm1', tenantId: 'org', teamId: 't3', identityId: 'alice', addedAt: 5 },
  { id: 'tm2', tenantId: 'org', teamId: 't1', identityId: 'alice', addedAt: 2 },
  { id: 'tm3', tenantId: 'org', teamId: 't2', identityId: 'alice', addedAt: 3, expiresAt: 4 },
  { id: 'tm4', tenantId: 'org', teamId: 't3', identityId: 'bob', addedAt: 1 });
add('departments',
  { id: 'd0', tenantId: 'org', name: 'Engineering', createdAt: 1 },
  { id: 'd1', tenantId: 'org', name: 'Platform', parentId: 'd0', createdAt: 2 });
add('departmentMembers', { id: 'dm1', tenantId: 'org', uniqueKey: 'identity:bot', departmentId: 'd0', identityId: 'bot' });
out.records = records;

const byId = (a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0);
const copy = (value) => structuredClone(value);
const tx = {
  async find(collection, filter = {}) {
    return (records[collection] ?? [])
      .filter((record) => Object.entries(filter).every(([key, value]) => record[key] === value))
      .sort(byId)
      .map(copy);
  },
  async get(collection, id) {
    const found = (records[collection] ?? []).find((record) => record.id === id);
    return found ? copy(found) : undefined;
  },
};
const now = day(2026, 9, 28);
const tenantOf = async (id) => tx.get('tenants', id);
const ctx = {
  now: () => now,
  options: { billing: { timeZone: 'UTC' } },
  async ancestry(_tx, target) {
    const list = [target];
    while (list.at(-1).parentId) list.push(await tenantOf(list.at(-1).parentId));
    return list;
  },
};
const settings = b.billingSettings({});
const store = {};
const attempt = async (fn) => {
  try {
    return { value: await fn() };
  } catch (error) {
    return { error: { code: error.code, message: error.message } };
  }
};
for (const id of ['org', 'org2', 'proj2', 'root'])
  store[`accountSpend:${id}`] = await b.accountSpend(ctx, tx, await tenantOf(id), '2026-09');
for (const id of ['root', 'org', 'proj'])
  store[`scopeSpend:${id}`] = await b.scopeSpend(ctx, tx, await tenantOf(id), '2026-09');
for (const id of ['root', 'org', 'proj', 'proj2'])
  store[`accountOf:${id}`] = (await b.accountOf(ctx, tx, await tenantOf(id))).id;
for (const id of ['org', 'proj', 'proj2', 'org2'])
  store[`accountTermsOf:${id}`] = (await b.accountTermsOf(ctx, tx, await tenantOf(id))) ?? null;
store['subtree:org'] = (await b.subtree(ctx, tx, await tenantOf('org'))).map((realm) => realm.id);
for (const period of ['2026-09', '2026-10'])
  store[`subscriptionLines:${period}`] = await plans.subscriptionLines(tx, 'org', period, 'UTC');
const chain = await ctx.ancestry(tx, await tenantOf('proj'));
store.metersFor = Object.fromEntries([...(await b.metersFor(tx, chain))].map(([key, value]) => [key, value.id]).sort());
store.resolveMeter = (await b.resolveMeter(tx, chain, 'builds'))?.id ?? null;
const m1 = await tx.get('billingMeters', 'm1');
store.priceForOrg2 = (await b.priceFor(tx, m1, await ctx.ancestry(tx, await tenantOf('org2')), '2026-09'))?.id ?? null;
store.priceForProj = (await b.priceFor(tx, m1, chain, '2026-09'))?.id ?? null;
store.priceForOld = (await b.priceFor(tx, m1, chain, '2025-12'))?.id ?? null;
const directory = await b.directoryFor(tx, ['org', 'org']);
store.directory = { teams: [...directory.teams.keys()], departments: [...directory.departments.keys()] };
const rows = store['scopeSpend:org'].rows;
store.shares = rows.map((row) => [
  b.teamShare(row, 't1', directory, settings, false),
  b.teamShare(row, 't1', directory, settings, true),
  b.teamShare(row, 't1', directory, { ...settings, teamAttribution: 'full' }, true),
  b.inDepartment(row, 'd0', directory, false),
  b.inDepartment(row, 'd0', directory, true),
]);
const orgChain = await ctx.ancestry(tx, await tenantOf('proj'));
store.attributionInputs = [
  { identityId: 'alice' }, { identityId: 'bot' }, { identityId: 'bob' }, { identityId: 'alice', teamId: 't2' },
  { identityId: 'bot', agentId: 'helper' }, { teamId: 't3' }, {}, { identityId: 'gone' }, { identityId: 'erin' },
  { teamId: 'nope' }, { identityId: 5 },
];
store.attributions = [];
for (const input of store.attributionInputs)
  store.attributions.push(await attempt(() => b.attributionFor(ctx, tx, orgChain, input, settings)));
store.attributionsPrimary = await attempt(() => b.attributionFor(ctx, tx, orgChain, { identityId: 'alice' }, { ...settings, teamAttribution: 'primary' }));
store.now = now;
out.store = store;

console.log(JSON.stringify(out, null, 1));
