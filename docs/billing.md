# Billing and spend tracking

Better IAM knows who everyone is, which organization and project they work in, which teams they belong to, and which
department they report into. Billing uses that to answer the questions finance and team leads ask every month: what
did we spend, on what, and who spent it?

- **Meters** name what is billed: API calls, seat-days, GB-days of storage, CI builds, AI inference.
- A **rate card** prices each meter (per unit, graduated or volume tiers, packages, free allowances), with negotiated
  prices for individual organizations.
- **Usage** is recorded against a meter and attributed, when it happens, to the person or agent behind it, their teams
  and their department, plus any tags you add.
- **Spend** is reported by person, team, department, project, meter, day or tag, for an organization, a team lead, a
  department head, or each person themselves.
- **Budgets** alert at thresholds and on projections, and can refuse usage once spent.
- **Invoices** (statements) bill each billing account monthly, with credits applied and a breakdown of where the money
  went. Like Stripe and Orb, they carry **plans and subscriptions** (fixed fees, seats, plan prices, trials,
  prorations), one-off **invoice items**, **coupons**, **payments**, **credit notes**, drafts, reminders, and a
  printable invoice page.

Billing is always available; the `billing` option only tunes it:

```ts
const iam = betterIam({
  // ...
  billing: {
    currency: 'EUR', // ISO 4217, default USD
    timeZone: 'Europe/Berlin', // billing months follow this zone (default UTC)
    teamAttribution: 'split', // 'split' (default), 'primary' or 'full', see below
    paymentTermsDays: 30,
    statementPrefix: 'INV', // statement numbers read INV-202609-0001
    usageRetentionDays: 400, // raw events; daily roll-ups and statements stay
    issuer: { name: 'Acme Cloud Ltd', address: '1 Main Street, London', taxId: 'GB123456789' },
    paymentReminderDays: [-3, 0, 7, 14], // relative to the due date
    autoFinalize: true, // false keeps monthly invoices as drafts to review
  },
});
```

## Meters and prices

Meters are defined like feature flags: the root tenant defines **platform meters**, billed to every organization;
an organization (or project) can define meters for its own subtree for **internal chargeback** (a cloud bill, licences,
support hours). Keys belong to the tenant nearest the root, so an organization can never redefine a platform meter.
Chargeback meters show in the organization's spend but never on a platform statement.

```ts
await iam.api.billing.createMeter(root, {
  tenantId: rootTenantId,
  key: 'api-calls',
  name: 'API calls',
  unit: 'request',
});
await iam.api.billing.setPrice(root, {
  tenantId: rootTenantId,
  meter: 'api-calls',
  price: {
    model: 'graduated',
    includedQuantity: 10_000, // free every month
    tiers: [
      { upTo: 1_000_000, unitAmount: 0.0004 },
      { upTo: null, unitAmount: 0.0002 },
    ],
  },
});
// A negotiated price for one organization (and its projects), from next month:
await iam.api.billing.setPrice(root, {
  tenantId: rootTenantId,
  meter: 'api-calls',
  targetTenantId: acmeId,
  effectiveFrom: '2026-10',
  price: { model: 'per-unit', unitAmount: 0.0003 },
  note: 'Enterprise agreement',
});
```

| Meter setting           | Meaning                                                                                              |
| ----------------------- | ---------------------------------------------------------------------------------------------------- |
| `aggregation: 'sum'`    | Quantities add up (the default).                                                                     |
| `aggregation: 'unique'` | Counts the distinct people and agents with usage in the month: monthly active users or active seats. |
| `pricing: 'rate-card'`  | Priced from the rate card (the default).                                                             |
| `pricing: 'reported'`   | Each event carries its own cost (`cost` in currency units); used for AI inference and chargeback.    |

Price models take amounts in currency units: `per-unit` (`unitAmount`), `graduated` (each tier prices its own
units), `volume` (the tier the total reaches prices every unit), and `package` (`packageSize`, `packageAmount`,
partial packages round up), each with an optional `includedQuantity`. A price applies from `effectiveFrom` (a month)
until a later entry; the entry nearest the billing account wins. Past months can be priced until they are invoiced.

## Recording usage

Applications record usage on the server without a credential, which is the hot path (no audit event per call):

```ts
await iam.billing.record({
  tenantId: projectId,
  meter: 'api-calls',
  quantity: 1,
  identityId: session.identity.id, // person, service account or agent
  tags: { endpoint: 'search', env: 'production' },
  idempotencyKey: requestId, // retries record nothing twice
});
```

Backends without the instance use `billing.record` / `billing.recordMany` with a service account that holds
`iam:billing:record`. At record time the event is attributed to the identity, the teams they belong to directly
(`teamId` overrides that), and their department (or their first team's department). An agent's usage counts toward its
sponsor's teams and department, and toward the sponsor in `mySpend`. Usage for a month that has been invoiced is refused
with `BILLING_PERIOD_CLOSED`; void the statement to reopen it.

AI inference feeds the ledger by itself: every metered model call is recorded on the built-in reported meter
`inference`, tagged with the model and provider.

For seat-based pricing, run `iam.billing.recordSeats()` daily: it records one unit of the `seats` meter for every active
person of every tenant the meter reaches. A `sum` meter then counts seat-days, a `unique` meter active seats per month;
either way each seat is attributed to its person, team and department.

## How spend is computed

Spend is computed per **billing account** and month. A billing account is an organization, or any tenant below it with
a billing profile of its own. Each meter's month total for the account is priced once, with tiers and free units
applied, and the cost is then shared out to the usage that produced it by quantity (for `unique` meters, equally per
person). Individual, team, department and project spend therefore always add up to the account's charges.

People in several teams count toward each of their teams in equal parts (`teamAttribution: 'split'`); `'primary'`
attributes everything to their oldest team, `'full'` counts it in full for every team (team totals then add up to
more than the organization's). Teams roll up into their parent teams, departments into the departments above them.

```ts
// Everything this organization and its projects spent this month, by team.
const byTeam = await iam.api.billing.spend(admin, { tenantId, groupBy: 'team' });
// byTeam.rows: [{ key, label, costMicros, amount, share, events, quantities }], byTeam.forecast

// Last month, only the Platform team (with its sub-teams), by person.
await iam.api.billing.spend(admin, { tenantId, period: '2026-08', teamId, groupBy: 'identity' });

// Six months of totals for a chart.
await iam.api.billing.trend(admin, { tenantId, months: 6 });
```

`groupBy` is `meter` (default), `identity`, `agent`, `team`, `department`, `tenant` (projects), `day`, or `tag:{name}`.
Filters: `meter`, `identityId`, `teamId`, `departmentId`, `subTenantId`, `rollUp: false` (no sub-teams or
sub-departments), and `billableOnly` (leave out chargeback meters). The current month carries a linear `forecast`.

| Who              | Reads                                            | Needs                           |
| ---------------- | ------------------------------------------------ | ------------------------------- |
| Billing managers | `spend`, `trend`, budgets, credits, statements   | `iam:billing:read`              |
| Team maintainers | `teamSpend` for their team (and teams below it)  | nothing: maintaining the team   |
| Department heads | `departmentSpend` for their department and below | nothing: heading the department |
| Everyone         | `mySpend`: their own usage and their agents'     | a session of the tenant         |

Reads through a team or department role are audited with `metadata.via` (`team-maintainer`, `department-head`).

## Budgets

```ts
await iam.api.billing.createBudget(admin, {
  tenantId,
  name: 'Platform team monthly',
  subjectType: 'team', // 'tenant' (default), 'team', 'department' or 'identity'
  subjectId: platformTeamId,
  amount: 600, // currency units
  period: 'month', // 'month', 'quarter' or 'year'
  thresholds: [50, 80, 100], // the default
  forecastAlerts: true, // also alert when the projection passes the budget (default)
  notify: { owners: true, subject: true, emails: ['finance@acme.test'] },
  enforce: false,
});
```

`iam.billing.checkBudgets()` (hourly) alerts once per threshold and window: an audit event `billing:budget-alert` (so
webhooks can forward it) and, with an email transport, a `spend-alert` email to the owners, the subject (the person, the
team's maintainers or the department head) and `notify.emails`. `listBudgets` shows each budget's spend, projection
and thresholds reached.

An `enforce`d budget refuses covered usage once it is spent: `iam.billing.check({ tenantId, identityId, meter })` and
`billing.check` (the caller's own) report it, and `record({ enforceBudgets: true })` fails with `SPEND_LIMIT_REACHED`
(402). A budget covers usage in its tenant subtree by its subject: the person (or their agents), a team with its
sub-teams, a department with those below it. Enforcement reads spend cached for up to 30 seconds.

Inference budgets (`docs/inference.md`) remain the hard, per-call caps on model tokens and cost; billing budgets watch
money across every meter.

### Spend in policies

Budgets reach authorization too. Two context keys describe the budgets that cover the principal in the decision's
tenant (tenant budgets up the tree and, for a person of the tenant, their own, their teams' and their department's):

| Key                         | Type    | Meaning                                                |
| --------------------------- | ------- | ------------------------------------------------------ |
| `principal.spendExceeded`   | boolean | An **enforced** budget covering the principal is spent |
| `principal.budgetsExceeded` | list    | Names of every spent budget covering the principal     |

```json
{
  "effect": "deny",
  "actions": ["reports:export", "models:fine-tune"],
  "resources": ["*"],
  "conditions": { "Bool": { "principal.spendExceeded": true } }
}
```

Decisions read budgets only when a policy names one of the keys, and standings are cached for up to 30 seconds. An
assumed role sees only the tenant's budgets. Identity attributes cannot use the names `spendExceeded` or
`budgetsExceeded`.

## Spend spikes

Budgets catch spend that adds up; spikes catch spend that jumps. `billing.anomalies` lists the people, teams and meters
whose spend on a day (yesterday by default) is at least `factor` (3) times their average over the `baselineDays` (14)
before it and at least `minimum` (10 currency units) more, plus new spending above `minimum`: a looping CI pipeline, a
leaked key, an agent stuck in a retry loop.

```ts
const { anomalies } = await iam.api.billing.anomalies(admin, { tenantId });
// [{ dimension: 'identity', key, label: 'Bob', day: '2026-09-22', costMicros: 45_000_000, baselineMicros: 2_000_000, factor: 22.5 }]
```

`iam.billing.detectAnomalies()` (daily, shortly after midnight in the billing time zone) checks every billing account
and alerts once per spike: an audit event `billing:anomaly` and, with an email transport, one `spend-anomaly` email per
account to its billing emails (or owners) listing the largest five.

## Showback and exports

Spend nobody in a dimension caused (a project's shared services, usage recorded without an identity) shows as its own
row. For showback, `shareUnattributed: true` on a report grouped by `identity`, `agent`, `team` or `department` spreads
it over the groups that did cause spend, in proportion to their spend; each row then carries `sharedMicros` and the
report `sharedMicros`, and the rows still add up to the total.

```ts
await iam.api.billing.spend(admin, { tenantId, groupBy: 'team', shareUnattributed: true });
```

Finance takes spend to spreadsheets: `billing.exportSpend` (the same query as `spend`) and `billing.exportStatement`
return `{ filename, contentType, body }` with RFC 4180 CSV (cells that would run as spreadsheet formulas are escaped).
The console's Billing and statement pages offer them as downloads.

## Billing profiles, credits and statements

A billing profile names who pays: company name, billing emails (statements go there, else to the owners), tax ID,
address, purchase order, cost center, payment terms. A profile on a project makes the project a billing account of its
own; that is its parent's decision, so it is created from an ancestor with `targetTenantId`:

```ts
await iam.api.billing.setProfile(orgAdmin, {
  tenantId: orgId,
  targetTenantId: projectId,
  companyName: 'Apollo Ltd',
  billingEmails: ['ap@apollo.test'],
});
```

Root administrators grant **credit** to billing accounts (`billing.grantCredit`, optionally expiring); statements draw
on it, earliest expiry first.

Root administrators also set each account's **contract terms** with `billing.setTerms`: a `discountPercent` off the
subtotal, a `minimumCommitment` per month (a shortfall is billed as a true-up line), and a `taxRatePercent` with a
`taxLabel` such as `VAT`. Invoices apply them in this order: the subtotal of the lines, minus the discount, plus the
commitment true-up (monthly invoices only), minus [coupons](#coupons), minus credit, plus tax on the rest.
`billing.getTerms` shows an account its terms. Spend reports stay at rate-card prices; for per-meter negotiated prices
use `setPrice` with `targetTenantId`.

```ts
await iam.api.billing.setTerms(root, {
  tenantId: acmeId,
  discountPercent: 10,
  minimumCommitment: 1000,
  taxRatePercent: 20,
  taxLabel: 'VAT',
});
```

`iam.billing.closePeriod()` (daily) issues an invoice for last month for every billing account with something to
bill (usage of platform meters, subscription fees and seats, pending invoice items), skipping accounts already
invoiced: lines per platform meter (with the tiers the quantity used), plan charges, items, coupons, credit applied,
total, due date, bill-to details, and a breakdown of usage by project, team, department (with cost centers) and
person. Invoices carry a content hash (`getStatement` returns `verified`). `previewStatement` shows a billing account
its invoice so far. Invoice amounts are whole cents, so the lines add up to what the invoice shows; spend reports keep
fractions of a cent.

## Invoicing

Invoices follow Stripe's lifecycle:

| Status          | Meaning                                                                                                      |
| --------------- | ------------------------------------------------------------------------------------------------------------ |
| `draft`         | Recomputed until finalized; no number yet; its month still takes late usage.                                 |
| `finalized`     | Numbered, sealed with its content hash, emailed, open for payment. Late usage for the month is refused.      |
| `paid`          | Payments and credit notes cover it (an invoice with nothing to pay is paid on issue).                        |
| `uncollectible` | Written off (`markUncollectible`); a later payment still settles it.                                         |
| `void`          | Cancelled (`voidStatement`): credit, invoice items, coupons and advance months come back; the month reopens. |

Monthly invoices are finalized when the month is closed unless `billing.autoFinalize` is `false` or `closePeriod`
gets `draft: true`: they then stay drafts, refreshed on every run, until a root administrator finalizes them
(`billing.finalizeInvoice`), which recomputes them one last time. Only root administrators change invoices; the
account's billing readers see every invoice, drafts included.

### Invoice items

One-off charges, or credits with a negative `amount`, for an account's next invoice (or the one for `period`), like
Stripe's pending invoice items:

```ts
await iam.api.billing.createInvoiceItem(root, {
  tenantId: acmeId,
  description: 'Onboarding workshop',
  amount: 500, // per unit, in currency units
  quantity: 1,
});
```

`listInvoiceItems` shows them (`pending` until an invoice bills them, then `invoiced` with its `statementId`);
`deleteInvoiceItem` removes a pending one. Subscription changes add `proration` items on their own. When credit items
exceed the charges, the invoice totals 0 and the rest becomes account credit (`carryForward`).

### Payments and credit notes

```ts
// A partial payment; the rest stays due. An overpayment becomes account credit.
await iam.api.billing.recordPayment(root, {
  tenantId: acmeId,
  statementId,
  amount: 300,
  method: 'bank_transfer',
  reference: 'wire-88213',
});
// From a payment processor's webhook, without a credential; the idempotency key makes redelivery safe:
await iam.billing.recordPayment({
  number: 'INV-202609-0007',
  amount: 99,
  method: 'card',
  idempotencyKey: 'pi_3Nx...',
});
// A credit note: first off the amount due, the rest (a part already paid) as account credit or, with refund, refunded.
await iam.api.billing.createCreditNote(root, {
  tenantId: acmeId,
  statementId,
  amount: 25,
  reason: 'product_unsatisfactory', // duplicate, fraudulent, order_change, product_unsatisfactory, other
  memo: 'Latency incident',
});
```

Every summary carries `amountPaidMicros`, `amountDueMicros` and `overdue` (finalized, past due, not covered).
`markPaid` records a payment of the amount due. Invoices with payments or credit notes cannot be voided: issue a credit
note. Credit notes are numbered `{invoice}-CN-01`, `-CN-02`, ... and listed by `listCreditNotes`.

`iam.billing.sendPaymentReminders()` (daily) emails the billing contacts of unpaid invoices as `payment-reminder` at
each step of `billing.paymentReminderDays` (default 3 days before the due date, on it, and 7 and 14 days after), once
per step; a step missed while the job was not running is skipped for the latest one reached.

`billing.renderInvoice` returns the invoice as a self-contained HTML page (`{ filename, contentType, body }`) to print
or save as PDF: the issuer from `billing.issuer` (with `paymentInstructions`), bill-to details, lines with tier
sub-lines, service periods and prorations, discounts, coupons, credit, tax, payments, credit notes and the amount due.
The console links it as "Print or save as PDF".

### Plans and subscriptions

Plans, defined by root administrators on the platform tenant, bundle what an account pays every month besides usage,
like Stripe products with prices or Orb plans:

```ts
await iam.api.billing.createPlan(root, {
  tenantId: rootTenantId,
  key: 'team',
  name: 'Team',
  selfServe: true, // account billing managers may subscribe themselves
  trialDays: 14,
  items: [
    { id: 'platform', kind: 'fee', name: 'Platform fee', amount: 99 }, // per month, in advance
    { id: 'seats', kind: 'seat', name: 'Seats', unitAmount: 12, includedSeats: 3 },
    { id: 'support', kind: 'fee', name: 'Premium support', amount: 200, billing: 'arrears' },
    {
      id: 'calls',
      kind: 'usage',
      name: 'API calls',
      meter: 'api-calls',
      price: { model: 'per-unit', unitAmount: 0.0003 }, // replaces the rate card for subscribers
    },
  ],
});
const { subscription, invoice } = await iam.api.billing.subscribe(orgAdmin, {
  tenantId: acmeId,
  plan: 'team',
  seats: 8,
});
```

- **Fees and seats** bill in `advance` (default: each monthly invoice bills the month ahead) or in `arrears` (the
  month itself). Seats above `includedSeats` are billed as seat-months, weighted by how long each seat count lasted.
- **Starting.** Outside a trial the first month is invoiced at once from today (`billingReason: 'subscription'`). A
  trial (the plan's `trialDays`, or `trialDays` from a root administrator) bills nothing until it ends; the part of
  the month after it is billed on that month's invoice.
- **Changes.** `updateSubscription({ seats })` and `cancelSubscription({ atPeriodEnd: false })` prorate what was
  already billed in advance as invoice items on the next invoice: added seats for the rest of the month, credit for
  unused time. `cancelSubscription` ends at the month's end by default and `resumeSubscription` undoes that until then.
  `changePlan` moves to another plan now, crediting the old plan's unused time and charging the new one's rest of the
  month, keeping seats and what is left of a trial.
- **Plan prices.** A usage item replaces the rate card for its meter while the subscription runs in the month (lines
  show `price.source: 'plan'`).
- **Who.** Account billing managers (`iam:billing:manage`) subscribe, change seats, change plans and cancel at the
  month's end for self-serve plans; root administrators for any plan, and they end subscriptions at once. Archived
  plans take no new subscriptions; plan changes apply to invoices drawn up afterwards.

### Coupons

```ts
await iam.api.billing.createCoupon(root, {
  tenantId: rootTenantId,
  code: 'LAUNCH20',
  percentOff: 20, // or amountOff (currency units)
  duration: 'repeating', // 'once' (the next invoice), 'repeating' (durationInMonths), 'forever'
  durationInMonths: 3,
  maxRedemptions: 100,
});
await iam.api.billing.redeemCoupon(orgAdmin, { tenantId: acmeId, code: 'launch20' });
```

Accounts redeem codes themselves (`iam:billing:manage`), once per coupon. A redeemed coupon (a discount,
`listDiscounts`) applies after the contract discount, in the order codes were redeemed: `once` to the next invoice,
`repeating` to invoices for `durationInMonths` months from the month of redemption, `forever` until a root
administrator removes it (`removeDiscount`). Voiding an invoice gives a one-off coupon back. Unknown, inactive,
expired and used-up codes all answer `NOT_FOUND`. `deactivateCoupon` stops new redemptions.

## Scheduler jobs

| Job                                  | CLI                 | When   |
| ------------------------------------ | ------------------- | ------ |
| `iam.billing.checkBudgets()`         | `billing-alerts`    | hourly |
| `iam.billing.recordSeats()`          | `billing-seats`     | daily  |
| `iam.billing.closePeriod()`          | `billing-close`     | daily  |
| `iam.billing.sendPaymentReminders()` | `billing-reminders` | daily  |
| `iam.billing.detectAnomalies()`      | `billing-anomalies` | daily  |

`billing-close --draft` keeps the month's invoices as drafts.

`better-iam spend --tenant ID [--period YYYY-MM] [--group-by team]` prints a spend report as `BETTER_IAM_TOKEN`.

## Errors

| Code                    | Status | When                                                              |
| ----------------------- | ------ | ----------------------------------------------------------------- |
| `BILLING_PERIOD_CLOSED` | 409    | Usage or a price for a month already invoiced for the account     |
| `METER_ARCHIVED`        | 409    | Usage on an archived meter                                        |
| `SPEND_LIMIT_REACHED`   | 402    | `record({ enforceBudgets: true })` under a spent, enforced budget |

Audit events are listed in [events](events.md) (`billing:*`).
