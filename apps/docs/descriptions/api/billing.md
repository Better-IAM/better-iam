# billing

Billing tells an organization what it spends, on what, and who spent it: usage recorded on meters is priced from a
rate card per billing account and month, then shared out to the people, agents, teams, departments and projects that
produced it. Budgets alert and can refuse usage, and the platform issues monthly invoices (statements) with credit
applied. Invoicing works like Stripe or Orb: drafts, finalized, paid, uncollectible and void invoices; one-off invoice
items; payments and credit notes; plans with fees, seats and meter prices; subscriptions with trials and prorations;
coupons; payment reminders and a printable invoice. Server code records usage, takes payments and runs the jobs
through `iam.billing` (no credential). The repository guide is `docs/billing.md`.

## How spend is computed

A **billing account** is an organization, or a tenant below it with a billing profile of its own. For each account and
month, every meter's total is priced once (tiers and free units apply to the account's total), and the cost is shared
out to the daily roll-ups of usage by quantity; for `unique` meters every person or agent costs the same. Reported
meters carry their own cost per event. Person, team, department and project spend therefore add up to the account's
charges. Meters an account defines for itself are chargeback only (`internal`) and never appear on a statement.

Usage is attributed when it is recorded: the identity, its direct teams (split evenly by default, see the `billing`
option `teamAttribution`), and its department (or its first team's). An agent's usage counts toward its sponsor's
teams and department. Money is in micros of the deployment currency (`costMicros`), with rounded `amount` fields in
currency units.

## Permissions

`iam:billing:read` reads spend, budgets, credits, profiles, invoices, plans, subscriptions and discounts;
`iam:billing:manage` defines meters and prices in the tenant, budgets and profiles, and lets an account's billing
managers subscribe to self-serve plans and redeem coupon codes; `iam:billing:record` records usage. Resources are
`iam/billing`, `iam/billing/meters/{key}`, `iam/billing/budgets`, `iam/billing/profile`, `iam/billing/credits`,
`iam/billing/statements`, `iam/billing/invoice-items`, `iam/billing/plans`, `iam/billing/subscriptions`,
`iam/billing/coupons` and `iam/billing/discounts`. Credits, closing a month, invoice items, payments, credit notes,
plans and coupons are for root administrators only; they act on any account's invoice by calling on the root tenant.

## accounts

Lists the billing accounts in the tenant's subtree with this month's billable spend, projection, available credit and latest statement.

- **Permission:** `iam:billing:read` on `iam/billing`.
- **Audited as:** `iam:billing:read`.

On the root tenant this is every organization: the platform's receivables view. `monthToDateMicros` counts only
meters defined above the account (what a statement would bill); `totalMicros` includes the account's own chargeback
meters.

## anomalies

Lists the people, teams and meters whose spend on one day jumped far above their usual daily spend.

- **Permission:** `iam:billing:read` on `iam/billing`.
- **Audited as:** `iam:billing:read`.
- **Errors:** `INVALID_INPUT` for a malformed `day`, `baselineDays` outside 3 to 90, `factor` outside 1.1 to 1000, or a
  negative `minimum`.

`day` defaults to yesterday in the billing time zone. A spike is spend at least `factor` (3) times the average over the
`baselineDays` (14) before it and at least `minimum` (10 currency units) more; spending with no baseline counts when it
reaches `minimum` (`factor: null`). The largest increases come first, at most 50. The daily job
`iam.billing.detectAnomalies()` alerts on them once each (`billing:anomaly`, `spend-anomaly` email).

```ts
const { anomalies } = await iam.api.billing.anomalies(admin, { tenantId, factor: 5 });
```

## check

Reports whether the caller's own usage is within every enforced budget that covers it.

- **Permission:** The caller's own session; the tenant must be the caller's tenant or one below it.
- **Audited as:** not audited.
- **Errors:** `ACCESS_DENIED` (403) for a tenant outside the caller's.

Covering budgets are enforced tenant budgets on the tenant or an ancestor, and the caller's own, their teams' (with
parent teams) and their department's (with the departments above it); `meter` narrows to budgets that count it.
`blockedBy` names the first spent budget. Statuses may lag recorded usage by up to 30 seconds. Server code checks any
identity with `iam.billing.check`.

```ts
const verdict = await client.billing.check({ tenantId, meter: 'api-calls' });
if (!verdict.allowed) showBudgetBanner(verdict.blockedBy);
```

## closePeriod

Issues statements for a month that has ended, for every billing account or only `accountId`'s.

- **Permission:** Root administrators only, called on the root tenant (`iam:billing:manage` on `iam/billing/periods`).
- **Audited as:** `iam:billing:manage`; each statement as `billing:statement`.
- **Errors:** `INVALID_INPUT` for the current or a future month, or when called on another tenant.

`period` defaults to last month. Each invoice bills the month's usage of platform meters, the subscriptions' fees
and seats (the month itself for arrears items, the next month for advance ones), and pending invoice items. Accounts
already invoiced for the month and accounts with nothing to bill are skipped (`skipped.existing`, `skipped.empty`), so
the job is safe to repeat. Coupons apply after the contract discount, credit earliest expiry first; invoices are
emailed (`billing-statement`) to the profile's billing emails or the owners, and raw usage events past their retention
are deleted (`sweptUsage`). With `draft: true` (or the option `billing.autoFinalize: false`) invoices are kept as
drafts, refreshed on every run, and listed in `drafted`; finalize them with `finalizeInvoice`. Schedulers call
`iam.billing.closePeriod()` instead.

## createBudget

Creates a spend budget for the tenant, a tenant below it, a team, a department or a person, per month, quarter or year.

- **Permission:** `iam:billing:manage` on `iam/billing/budgets`.
- **Audited as:** `billing:budget-create`.
- **Errors:** `CONFLICT` (409) for a name already used (case-insensitive); `LIMIT_EXCEEDED` (409) past 200 budgets;
  `NOT_FOUND` for a subject outside the tenant; `INVALID_INPUT` for an amount of 0, a malformed meter key, more than 10
  thresholds or notification addresses.

`amount` is in currency units. `thresholds` (default 50, 80, 100 percent) and `forecastAlerts` (default on) drive the
alerts that `iam.billing.checkBudgets()` sends once per window to the owners, the subject (the person, the team's
maintainers or the department head) and `notify.emails`. `enforce` makes covered usage fail once the budget is spent.
The result is the budget with its current standing.

```ts
await iam.api.billing.createBudget(admin, {
  tenantId,
  name: 'Platform team monthly',
  subjectType: 'team',
  subjectId: platformTeamId,
  amount: 600,
  notify: { emails: ['finance@acme.test'] },
});
```

## createMeter

Defines a usage meter: a platform meter on the root tenant, a chargeback meter for the tenant's subtree elsewhere.

- **Permission:** `iam:billing:manage` on `iam/billing/meters/{key}`.
- **Audited as:** `billing:meter-create`.
- **Errors:** `CONFLICT` (409) when a meter with the key already reaches the tenant; `LIMIT_EXCEEDED` (409) past 100
  meters; `INVALID_INPUT` for a malformed key or a `unique` reported meter.

Keys are 1 to 64 lowercase letters, digits, dots, underscores or hyphens, starting with a letter. `aggregation` is
`sum` (default) or `unique` (distinct people and agents per month); `pricing` is `rate-card` (default) or `reported`
(each event carries its cost). Neither can change later.

## deleteBudget

Deletes a budget and its alert history.

- **Permission:** `iam:billing:manage` on `iam/billing/budgets`.
- **Audited as:** `billing:budget-delete`.
- **Errors:** `NOT_FOUND` for a budget of another tenant.

## deleteMeter

Deletes a meter that has never recorded usage, with its prices.

- **Permission:** `iam:billing:manage` on `iam/billing/meters/{key}`.
- **Audited as:** `billing:meter-delete`.
- **Errors:** `RESOURCE_IN_USE` (409) once the meter has recorded usage (archive it with `updateMeter` instead);
  `NOT_FOUND` when the tenant does not define the key.

## deleteProfile

Removes a billing profile, so the tenant's usage rolls into its parent's account again.

- **Permission:** `iam:billing:manage` on `iam/billing/profile`; below an organization, called from an ancestor with
  `targetTenantId`.
- **Audited as:** `billing:profile-delete`.
- **Errors:** `NOT_FOUND` without a profile; `ACCESS_DENIED` (403) when a tenant below an organization removes its own.

## departmentSpend

Reports a department's spend, with the departments below it, grouped by `identity` by default.

- **Permission:** The department's head (or the head of a department above it), or `iam:billing:read`.
- **Audited as:** `iam:billing:read`, with `metadata.via` `department-head` or `permission`.
- **Errors:** `ACCESS_DENIED` (403) for anyone else; `NOT_FOUND` for a department outside the tenant.

## exportSpend

Returns a spend report as a CSV file: one row per group with the amount, share, events and a column per meter's quantity.

- **Permission:** `iam:billing:read` on `iam/billing`.
- **Audited as:** `iam:billing:read`.
- **Errors:** as `spend`.

It takes the same input as `spend` and returns `filename`, `contentType` and `body` (RFC 4180, CRLF line endings, a
final total row). Cells that a spreadsheet would run as a formula are prefixed with a quote.

## exportStatement

Returns a statement as a CSV file: its lines, credit and total, then the breakdown by project, team, department and person.

- **Permission:** `iam:billing:read` on `iam/billing/statements`; the statement's account must be the tenant or below it.
- **Audited as:** `iam:billing:read`.
- **Errors:** `NOT_FOUND` for a statement outside the tenant's subtree.

The file is named after the statement number. Department rows carry their cost center.

## getProfile

Returns the billing profile of the tenant (or of `targetTenantId` below it) and the account that pays for it.

- **Permission:** `iam:billing:read` on `iam/billing/profile`.
- **Audited as:** `iam:billing:read`.

`account.inherited` is true when an ancestor pays; `profile` is null without a profile of its own.

## getStatement

Returns one statement with its lines, credit, breakdown and bill-to details, re-checking its content hash.

- **Permission:** `iam:billing:read` on `iam/billing/statements`; the statement's account must be the tenant or below it.
- **Audited as:** `iam:billing:read`.
- **Errors:** `NOT_FOUND` for a statement outside the tenant's subtree.

`verified` is false when the stored content no longer matches the hash computed at issue. `overdue` is true for a
finalized statement past its due date.

## grantCredit

Grants credit to a billing account, which its statements draw on, earliest expiry first.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/credits`).
- **Audited as:** `billing:credit-grant`.
- **Errors:** `INVALID_INPUT` when the tenant is not a billing account (an organization or a tenant with a profile), for
  an amount of 0, or an `expiresAt` in the past.

```ts
await iam.api.billing.grantCredit(root, { tenantId: acmeId, amount: 100, reason: 'Launch promotion' });
```

## listBudgets

Lists the tenant's budgets with their spend, projection and the thresholds reached in the current window.

- **Permission:** `iam:billing:read` on `iam/billing/budgets`.
- **Audited as:** `iam:billing:read`.

## listCredits

Lists the credit of the tenant's billing account with the available balance.

- **Permission:** `iam:billing:read` on `iam/billing/credits`.
- **Audited as:** `iam:billing:read`.

When an ancestor pays for the tenant the list is empty and `inherited` is true.

## listMeters

Lists the meters that reach the tenant with the price that applies to its billing account this month.

- **Permission:** `iam:billing:read` on `iam/billing`.
- **Audited as:** `iam:billing:read`.

`scope` is `platform` for root meters; `inherited` marks meters an ancestor defines.

## listPrices

Returns a meter's rate card as the tenant may see it, and the entry that prices its account this month.

- **Permission:** `iam:billing:read` on `iam/billing/meters/{key}`.
- **Audited as:** `iam:billing:read`.
- **Errors:** `NOT_FOUND` when no meter with the key reaches the tenant.

Entries for the tenant, its ancestors (list prices) and tenants below it are listed, newest first; negotiated prices
for other organizations are not.

## listStatements

Lists the statements of the billing accounts in the tenant's subtree (all of them for the root), newest month first.

- **Permission:** `iam:billing:read` on `iam/billing/statements`.
- **Audited as:** `iam:billing:read`.

Filter by `status` (`finalized`, `paid`, `void`) or `period`.

## listUsage

Lists raw usage events recorded in the tenant for a month, newest first.

- **Permission:** `iam:billing:read` on `iam/billing`.
- **Audited as:** `iam:billing:read`.

Only the tenant itself (not its subtree), at most `limit` (1 to 500, default 100) events, optionally for one `meter`
or identity. Events are kept `usageRetentionDays` after their month; reports use daily roll-ups and outlive them.

## markPaid

Marks a finalized or uncollectible statement paid by recording a `manual` payment of the amount due, with an optional reference.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/statements`), called on the account
  or the root tenant.
- **Audited as:** `billing:statement-paid`.
- **Errors:** `INVALID_TRANSITION` (409) for a draft, paid or void statement.

## mySpend

Reports the caller's own spend: their usage and that of the agents they sponsor, with the budgets set on them.

- **Permission:** The caller's own session in their own tenant.
- **Audited as:** not audited.
- **Errors:** `ACCESS_DENIED` (403) for another tenant; `INVALID_INPUT` for a `groupBy` other than `meter`, `day`,
  `agent`, `tenant` or `tag:{name}`.

## previewStatement

Builds the statement a billing account would receive for a month (the current one so far by default), without issuing it.

- **Permission:** `iam:billing:read` on `iam/billing/statements`.
- **Audited as:** `iam:billing:read`.
- **Errors:** `INVALID_INPUT` when the tenant is not a billing account.

## quote

Prices a quantity of a meter as a month total for the tenant's billing account.

- **Permission:** `iam:billing:read` on `iam/billing/meters/{key}`.
- **Audited as:** `iam:billing:read`.
- **Errors:** `NOT_FOUND` for an unknown meter; `INVALID_INPUT` for a reported meter or a negative quantity.

Tiers and free units apply as they would to the account's month total; `unpriced` is true without a price.

## record

Records usage of a meter in the tenant, attributed to an identity, their teams and department, with optional tags.

- **Permission:** `iam:billing:record` on `iam/billing/meters/{key}`.
- **Audited as:** `iam:billing:record`.
- **Errors:** `NOT_FOUND` for an unknown meter or an identity outside the tenant and its ancestors; `METER_ARCHIVED`
  (409); `BILLING_PERIOD_CLOSED` (409) for a month already invoiced; `SPEND_LIMIT_REACHED` (402) with
  `enforceBudgets` under a spent enforced budget; `CONFLICT` (409) for an idempotency key used on another meter;
  `INVALID_INPUT` for a negative quantity, `cost` on a rate-card meter or none on a reported one, or `occurredAt` more
  than five minutes ahead or a year back.

`idempotencyKey` makes retries safe: a repeat returns the first receipt with `duplicate: true`. `teamId` attributes the
usage to one team instead of the person's own. Server code records without an audit event per call through
`iam.billing.record`, the usual choice for metering.

```ts
await client.billing.record({
  tenantId,
  meter: 'api-calls',
  quantity: 1,
  identityId,
  tags: { endpoint: 'search' },
  idempotencyKey: requestId,
});
```

## recordMany

Records up to 100 usage events in one transaction, all or nothing.

- **Permission:** `iam:billing:record` on `iam/billing` in the call's tenant.
- **Audited as:** `iam:billing:record`.
- **Errors:** as `record`; `INVALID_INPUT` for an event outside the tenant's subtree or more than 100 events.

## revokeCredit

Withdraws what is left of a credit.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/credits`).
- **Audited as:** `billing:credit-revoke`.
- **Errors:** `INVALID_TRANSITION` (409) for a credit already revoked.

## getTerms

Returns the contract terms of the tenant's billing account: discount, minimum monthly commitment and tax.

- **Permission:** `iam:billing:read` on `iam/billing/terms`.
- **Audited as:** `iam:billing:read`.

When an ancestor pays for the tenant the result only says `inherited: true`; without terms it lists none.

## setTerms

Sets a billing account's contract terms: a discount off the subtotal, a minimum monthly commitment, and the tax invoices add.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/terms`), called on the account.
- **Audited as:** `billing:terms`.
- **Errors:** `INVALID_INPUT` when the tenant is not a billing account, for a percentage outside 0 to 100, or a
  negative commitment.

Invoices issued from then on take the subtotal of their lines, subtract `discountPercent`, add the shortfall below
`minimumCommitment` (currency units per month, monthly invoices only) as a true-up, subtract coupons and credit, and
add `taxRatePercent` (labelled `taxLabel`, `Tax` by default) on the rest. `null` clears a term. Spend reports stay at
rate-card prices.

```ts
await iam.api.billing.setTerms(root, {
  tenantId: acmeId,
  discountPercent: 10,
  minimumCommitment: 1000,
  taxRatePercent: 20,
  taxLabel: 'VAT',
});
```

## setPrice

Sets or removes a rate-card price for a meter the tenant defines: its list price, or a negotiated price for a tenant below it.

- **Permission:** `iam:billing:manage` on `iam/billing/meters/{key}` in the defining tenant.
- **Audited as:** `billing:price`.
- **Errors:** `NOT_FOUND` when the tenant does not define the meter; `INVALID_INPUT` for a reported meter, a target
  outside the subtree, malformed tiers, or `effectiveFrom` more than 12 months back; `BILLING_PERIOD_CLOSED` (409) when
  a month from `effectiveFrom` on is already invoiced for the tenants it reaches.

`price` takes currency units: `per-unit` (`unitAmount`), `graduated` or `volume` (`tiers` of `upTo` and `unitAmount`,
optional `flatAmount`, the last `upTo: null`), or `package` (`packageSize`, `packageAmount`), each with an optional
`includedQuantity`. `effectiveFrom` (default this month) starts the price; `price: null` removes that entry.

```ts
await iam.api.billing.setPrice(root, {
  tenantId: rootTenantId,
  meter: 'api-calls',
  targetTenantId: acmeId,
  price: { model: 'per-unit', unitAmount: 0.0003 },
  note: 'Enterprise agreement',
});
```

## setProfile

Creates or updates a billing profile: company, billing emails, tax ID, address, purchase order, cost center, payment terms.

- **Permission:** `iam:billing:manage` on `iam/billing/profile`; a new profile below an organization is created from an
  ancestor with `targetTenantId`.
- **Audited as:** `billing:profile`.
- **Errors:** `ACCESS_DENIED` (403) when a tenant below an organization creates its own; `INVALID_INPUT` on the root
  tenant or for more than 10 emails.

A profile below an organization makes that tenant a billing account of its own, a decision for its parent; afterwards
the tenant's own billing managers may keep it up to date. `null` clears a field.

## spend

Reports the spend of the tenant and every tenant below it for a month, grouped and filtered.

- **Permission:** `iam:billing:read` on `iam/billing`.
- **Audited as:** `iam:billing:read`.
- **Errors:** `NOT_FOUND` for a team, department or sub-tenant outside the scope; `INVALID_INPUT` for an unknown
  `groupBy` or a malformed month.

`groupBy` is `meter` (default), `identity`, `agent`, `team`, `department`, `tenant`, `day` or `tag:{name}`. Filters:
`meter`, `identityId`, `teamId`, `departmentId`, `subTenantId`, `rollUp: false` (no sub-teams or sub-departments) and
`billableOnly` (leave out chargeback meters). Each row has `costMicros`, `amount`, `share` (percent) and `quantities`
per meter; the current month carries a linear `forecast`. For showback, `shareUnattributed: true` (grouped by
`identity`, `agent`, `team` or `department`) spreads the unattributed row over the other groups by their share of
spend, reported as `sharedMicros` per row and for the report.

```ts
const report = await iam.api.billing.spend(admin, { tenantId, groupBy: 'team' });
```

## teamSpend

Reports a team's spend, with the teams below it, grouped by `identity` by default.

- **Permission:** The team's maintainers (and those of teams above it), or `iam:billing:read`.
- **Audited as:** `iam:billing:read`, with `metadata.via` `team-maintainer` or `permission`.
- **Errors:** `ACCESS_DENIED` (403) for anyone else; `NOT_FOUND` for a team outside the tenant.

## trend

Returns monthly totals for the last `months` months (1 to 24, default 6), with the filters of `spend`.

- **Permission:** `iam:billing:read` on `iam/billing`.
- **Audited as:** `iam:billing:read`.

## updateBudget

Changes a budget's name, amount, period, meters, thresholds, alerts or enforcement; its subject stays.

- **Permission:** `iam:billing:manage` on `iam/billing/budgets`.
- **Audited as:** `billing:budget-update`.
- **Errors:** `CONFLICT` (409) for a name another budget uses; `NOT_FOUND` for a budget of another tenant.

`meters: null` counts every meter again.

## updateMeter

Renames a meter, changes its unit or description, or archives it.

- **Permission:** `iam:billing:manage` on `iam/billing/meters/{key}`.
- **Audited as:** `billing:meter-update`.
- **Errors:** `NOT_FOUND` when the tenant does not define the key; `INVALID_INPUT` when changing `aggregation` or
  `pricing`.

An archived meter refuses new usage (`METER_ARCHIVED`) and keeps its history; `archived: false` restores it.

## voidStatement

Voids a finalized statement: its credit, invoice items, coupons and advance-billed months come back and the month reopens.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/statements`), called on the account
  or the root tenant.
- **Audited as:** `billing:statement-void`.
- **Errors:** `INVALID_TRANSITION` (409) for a statement already void, a draft, or one with payments or credit notes
  (issue a credit note instead).

Fix the usage, then close the month again: the new statement gets a new number. Credit the invoice created from a
negative balance is revoked.

## finalizeInvoice

Finalizes a draft invoice: recomputes it with the latest usage and invoice items, numbers it, seals it and emails it.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/statements`), called on the account
  or the root tenant.
- **Audited as:** `billing:statement-finalize` and `billing:statement`.
- **Errors:** `INVALID_TRANSITION` (409) for an invoice that is not a draft, or a draft with nothing left to bill.

The invoice then consumes its credit, marks its invoice items `invoiced`, its subscriptions' advance months billed, and
its coupons used. An invoice with nothing to pay is `paid` on issue.

## recordPayment

Records a payment against a finalized or uncollectible invoice.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/statements`), called on the account
  or the root tenant.
- **Audited as:** `billing:payment`.
- **Errors:** `INVALID_TRANSITION` (409) for a draft, paid or void invoice; `INVALID_INPUT` for an amount of 0 or a
  `receivedAt` in the future.

`amount` (currency units) defaults to the amount due; `method` (default `manual`) and `reference` describe it. A
partial payment leaves the rest due; once payments and credit notes cover the invoice it is `paid`. A payment above
the amount due keeps the excess as account credit (`payment.overpaymentMicros`, `payment.creditId`). Payment
processors report payments through `iam.billing.recordPayment({ statementId | number, amount, idempotencyKey })`
instead, where the idempotency key makes webhook redelivery safe.

```ts
await iam.api.billing.recordPayment(root, {
  tenantId: acmeId,
  statementId,
  amount: 300,
  method: 'bank_transfer',
  reference: 'wire-88213',
});
```

## markUncollectible

Writes a finalized invoice off as uncollectible; a later payment still settles it.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/statements`).
- **Audited as:** `billing:statement-uncollectible`.
- **Errors:** `INVALID_TRANSITION` (409) for an invoice that is not finalized.

Uncollectible invoices get no payment reminders.

## createCreditNote

Issues a credit note against a finalized, paid or uncollectible invoice.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/statements`).
- **Audited as:** `billing:credit-note`.
- **Errors:** `INVALID_INPUT` for an amount above what is left to credit, an unknown `reason`, or a non-boolean
  `refund`; `INVALID_TRANSITION` (409) for a draft or void invoice.

`amount` defaults to everything not yet credited. The note first reduces the amount due; the rest (a part already
paid) becomes account credit, or with `refund: true` is recorded as refunded outside Better IAM. `applied` shows the
split. Notes are numbered `{invoice}-CN-01`, `-CN-02`, ...; `reason` is `duplicate`, `fraudulent`, `order_change`,
`product_unsatisfactory` or `other` (default), with an optional `memo`. An invoice the notes and payments cover is paid.

## listCreditNotes

Lists the credit notes of the billing accounts in the tenant's subtree, or of one `statementId`, newest first.

- **Permission:** `iam:billing:read` on `iam/billing/statements`.
- **Audited as:** `iam:billing:read`.

## renderInvoice

Returns an invoice as a standalone HTML page to print or save as PDF.

- **Permission:** `iam:billing:read` on `iam/billing/statements`.
- **Audited as:** `iam:billing:read`.
- **Errors:** `NOT_FOUND` for an invoice outside the tenant's subtree.

The result is `{ filename, contentType, body }`. The page names the issuer (the `billing.issuer` option: name,
address, tax ID, contact, and `paymentInstructions` under the totals), the bill-to details, every line with its tier
sub-lines, service period and proration, then discounts, coupons, credit, tax, payments, credit notes and the amount
due. It has no scripts and only inline styles, so it can be served with a strict content security policy.

## listInvoiceItems

Lists invoice items of the billing accounts in the tenant's subtree, newest first, optionally by `status`.

- **Permission:** `iam:billing:read` on `iam/billing/invoice-items`.
- **Audited as:** `iam:billing:read`.
- **Errors:** `INVALID_INPUT` for a `status` other than `pending` or `invoiced`.

`pending` items wait for the account's next invoice (or the one for their `period`); `invoiced` items carry the
`statementId` that billed them. `source: 'proration'` items come from subscription changes.

## createInvoiceItem

Adds a one-off charge, or with a negative `amount` a credit, to the billing account's next invoice.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/invoice-items`), called on the account.
- **Audited as:** `billing:invoice-item`.
- **Errors:** `INVALID_INPUT` when the tenant is not a billing account, for an empty description, an amount beyond one
  billion, a quantity of 0, or more than 20 metadata entries; `BILLING_PERIOD_CLOSED` (409) for a `period` already
  invoiced.

`amount` is per unit in currency units and `quantity` defaults to 1; the item's total is rounded to the cent. `period`
bills it on the invoice for that month instead of the next one. When credit items exceed an invoice's charges the
invoice totals 0 and the rest becomes account credit.

```ts
await iam.api.billing.createInvoiceItem(root, {
  tenantId: acmeId,
  description: 'Onboarding workshop',
  amount: 500,
});
```

## deleteInvoiceItem

Deletes a pending invoice item.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/invoice-items`), called on the account.
- **Audited as:** `billing:invoice-item-delete`.
- **Errors:** `INVALID_TRANSITION` (409) for an item already on a finalized invoice (issue a credit note instead).

## listPlans

Lists the platform's plans with their fees, seats and meter prices.

- **Permission:** `iam:billing:read` on `iam/billing/plans`.
- **Audited as:** `iam:billing:read`.

Tenants see plans that are not archived. Root administrators on the root tenant also get `subscribers` (live
subscriptions) and, with `includeArchived`, archived plans. Amounts are in currency units.

## createPlan

Defines a plan on the platform (root) tenant.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/plans`), called on the root tenant.
- **Audited as:** `billing:plan`.
- **Errors:** `CONFLICT` (409) for a key already used; `LIMIT_EXCEEDED` (409) past 100 plans; `INVALID_INPUT` for a
  malformed key, 0 or more than 20 items, duplicate item ids, two items pricing one meter, or a malformed price.

`items` are `fee` (`amount` per month), `seat` (`unitAmount` per seat and month, `includedSeats`), both billed in
`advance` (default) or `arrears`, and `usage` (`meter` with a `price` that replaces the rate card for subscribers).
`trialDays` (1 to 365) starts subscriptions with a free trial; `selfServe` lets account billing managers subscribe.

```ts
await iam.api.billing.createPlan(root, {
  tenantId: rootTenantId,
  key: 'team',
  name: 'Team',
  selfServe: true,
  items: [
    { id: 'platform', kind: 'fee', name: 'Platform fee', amount: 99 },
    { id: 'seats', kind: 'seat', name: 'Seats', unitAmount: 12, includedSeats: 3 },
  ],
});
```

## updatePlan

Changes a plan, by id or key: name, items, description, trial, self-serve, archived.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/plans`), called on the root tenant.
- **Audited as:** `billing:plan-update`.
- **Errors:** `NOT_FOUND` for an unknown plan; `INVALID_INPUT` as for `createPlan`.

`null` clears `description` or `trialDays`. An archived plan takes no new subscriptions. Changes apply to invoices
drawn up afterwards.

## listSubscriptions

Lists the subscriptions of the billing accounts in the tenant's subtree, newest first.

- **Permission:** `iam:billing:read` on `iam/billing/subscriptions`.
- **Audited as:** `iam:billing:read`.

Ended subscriptions are left out unless `includeEnded`. `status` is `trialing`, `active` or `ended`; `billedAdvance`
lists the months already billed in advance.

## subscribe

Subscribes the billing account to a plan (id or key).

- **Permission:** `iam:billing:manage` on `iam/billing/subscriptions`: self-serve plans for the account's billing
  managers, any plan for root administrators.
- **Audited as:** `billing:subscription`.
- **Errors:** `ACCESS_DENIED` (403) for a plan that is not self-serve, or `trialDays` from anyone but a root
  administrator; `CONFLICT` (409) when the account already subscribes to the plan; `INVALID_TRANSITION` (409) for an
  archived plan; `INVALID_INPUT` when the tenant is not a billing account.

`seats` defaults to 1. Outside a trial the rest of this month's advance fees and seats are invoiced at once (the
result's `invoice`, `billingReason: 'subscription'`); after that each monthly invoice bills the month ahead. A trial
bills nothing until it ends; the part of the month after it is billed on that month's invoice.

```ts
const { subscription, invoice } = await iam.api.billing.subscribe(orgAdmin, {
  tenantId: acmeId,
  plan: 'team',
  seats: 8,
});
```

## updateSubscription

Changes a subscription's seats.

- **Permission:** `iam:billing:manage` on `iam/billing/subscriptions` (self-serve plans), or a root administrator.
- **Audited as:** `billing:subscription-update`.
- **Errors:** `INVALID_TRANSITION` (409) for an ended subscription; `INVALID_INPUT` for seats outside 0 to 1000000.

Seats billed in advance for this month are prorated as invoice items on the next invoice (`invoiceItems`): added seats
for the rest of the month, credit for removed ones. Arrears seats follow the seat history on their own.

## cancelSubscription

Cancels a subscription at the end of the month (default) or now.

- **Permission:** `iam:billing:manage` on `iam/billing/subscriptions` (self-serve plans, at the month's end only), or
  a root administrator.
- **Audited as:** `billing:subscription-cancel`.
- **Errors:** `ACCESS_DENIED` (403) for an immediate cancellation by anyone but a root administrator;
  `INVALID_TRANSITION` (409) for an ended subscription.

At the month's end the subscription keeps running and `resumeSubscription` can undo it. With `atPeriodEnd: false` it
ends now and the unused part of this month's advance fees and seats is credited as invoice items; arrears items bill
the part of the month it ran.

## resumeSubscription

Undoes a cancellation at the end of the month before it takes effect.

- **Permission:** `iam:billing:manage` on `iam/billing/subscriptions` (self-serve plans), or a root administrator.
- **Audited as:** `billing:subscription-resume`.
- **Errors:** `INVALID_TRANSITION` (409) for a subscription that is not set to cancel, or has ended.

## changePlan

Moves a subscription to another plan now, keeping its seats and what is left of its trial.

- **Permission:** `iam:billing:manage` on `iam/billing/subscriptions` when both plans are self-serve, or a root
  administrator.
- **Audited as:** `billing:subscription-plan-change`.
- **Errors:** `CONFLICT` (409) when the account already subscribes to the new plan; `INVALID_TRANSITION` (409) for an
  ended subscription or an archived plan; `INVALID_INPUT` for the same plan.

The old subscription ends and a new one starts. The old plan's unused advance charges are credited and the new plan's
charges for the rest of the month added, both as invoice items for the next invoice (`invoiceItems`).

## listCoupons

Lists the platform's coupons, newest first, with their redemptions.

- **Permission:** Root administrators only (`iam:billing:read` on `iam/billing/coupons`), called on the root tenant.
- **Audited as:** `iam:billing:read`.

`active` is false for deactivated coupons, those past `redeemBy`, and those out of redemptions.

## createCoupon

Creates a coupon accounts can redeem by code.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/coupons`), called on the root tenant.
- **Audited as:** `billing:coupon`.
- **Errors:** `CONFLICT` (409) for a code already used; `INVALID_INPUT` for a code that is not 3 to 32 letters, digits,
  `-` or `_`, both or neither of `percentOff` and `amountOff`, a percentage outside 0 to 100, `durationInMonths`
  without `duration: 'repeating'`, or a `redeemBy` in the past.

Codes are stored in upper case. `duration` is `once` (default: the next invoice), `repeating` (invoices for
`durationInMonths` months from the month of redemption) or `forever`. `maxRedemptions` caps how many accounts may
redeem it.

```ts
await iam.api.billing.createCoupon(root, {
  tenantId: rootTenantId,
  code: 'LAUNCH20',
  percentOff: 20,
  duration: 'repeating',
  durationInMonths: 3,
});
```

## deactivateCoupon

Stops a coupon (by code) from being redeemed; accounts that redeemed it keep their discount.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/coupons`), called on the root tenant.
- **Audited as:** `billing:coupon-deactivate`.
- **Errors:** `NOT_FOUND` for an unknown code.

## redeemCoupon

Redeems a coupon code for the billing account.

- **Permission:** `iam:billing:manage` on `iam/billing/discounts` in the account.
- **Audited as:** `billing:coupon-redeem`.
- **Errors:** `CONFLICT` (409) when the account already redeemed the coupon; `NOT_FOUND` for a code that is unknown,
  inactive, past `redeemBy` or out of redemptions (all answer the same); `INVALID_INPUT` when the tenant is not a
  billing account.

The resulting discount applies to the account's invoices after the contract discount, in the order codes were
redeemed. Voiding an invoice gives a one-off discount back.

## listDiscounts

Lists the discounts (redeemed coupons) of the billing accounts in the tenant's subtree.

- **Permission:** `iam:billing:read` on `iam/billing/discounts`.
- **Audited as:** `iam:billing:read`.

`appliedInvoices` counts the invoices a discount reduced; `active` says whether it applies to this month's invoice.

## removeDiscount

Ends a billing account's discount now.

- **Permission:** Root administrators only (`iam:billing:manage` on `iam/billing/discounts`), called on the account.
- **Audited as:** `billing:discount-remove`.
- **Errors:** `INVALID_TRANSITION` (409) for a discount that has already ended.