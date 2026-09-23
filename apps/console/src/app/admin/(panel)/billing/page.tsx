import type { Tenant } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import {
  invoiceName,
  invoiceTone,
  money,
  periodLabel,
  planSummary,
  priceSummary,
  recentPeriods,
} from '@/lib/billing';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession, rootTenant } from '@/lib/session';

/**
 * Platform billing: the meters and list prices every organization is billed on, negotiated prices, each billing
 * account's spend this month, credits, and statements (closing a month, marking paid, voiding).
 */
export default async function PlatformBilling() {
  await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  const root = await rootTenant();
  if (!root) return <Alert tone="warning">No root tenant.</Alert>;
  const tenantId = root.id;
  const [
    meters,
    accounts,
    statements,
    byMeter,
    tenants,
    plans,
    subscriptions,
    coupons,
    pendingItems,
  ] = await Promise.all([
    iam.api.billing.listMeters(auth, { tenantId }),
    iam.api.billing.accounts(auth, { tenantId }),
    iam.api.billing.listStatements(auth, { tenantId }),
    iam.api.billing.spend(auth, { tenantId, groupBy: 'meter', billableOnly: true }),
    iam.store.find<Tenant>('tenants'),
    iam.api.billing.listPlans(auth, { tenantId, includeArchived: true }),
    iam.api.billing.listSubscriptions(auth, { tenantId }),
    iam.api.billing.listCoupons(auth, { tenantId }),
    iam.api.billing.listInvoiceItems(auth, { tenantId, status: 'pending' }),
  ]);
  const { currency } = byMeter;
  const tenantById = new Map(tenants.map((tenant) => [tenant.id, tenant]));
  const pathOf = (tenant: Tenant): string => {
    const parent = tenant.parentId ? tenantById.get(tenant.parentId) : undefined;
    return parent && parent.parentId ? `${pathOf(parent)} / ${tenant.name}` : tenant.name;
  };
  const tenantChoices = tenants
    .filter((tenant) => tenant.parentId !== null && tenant.status !== 'deleted')
    .map((tenant) => ({ value: tenant.id, label: `${pathOf(tenant)} (${tenant.type})` }))
    .sort((a, b) => a.label.localeCompare(b.label));
  const platformMeters = meters.filter((meter) => !meter.inherited);
  const billable = accounts.reduce((sum, account) => sum + account.monthToDateMicros, 0);
  const projected = accounts.reduce(
    (sum, account) => sum + (account.forecastMicros ?? account.monthToDateMicros),
    0,
  );
  const outstanding = statements.filter(
    (statement) => statement.status === 'finalized' || statement.status === 'uncollectible',
  );
  const creditable = statements.filter(
    (statement) => statement.status !== 'draft' && statement.status !== 'void',
  );
  const accountOptions = accounts.map((account) => ({
    value: account.accountId,
    label: account.name,
  }));
  const invoiceLabel = (statement: (typeof statements)[number]) =>
    `${invoiceName(statement)} · ${statement.tenantName ?? statement.tenantId} · ${money(statement.amountDueMicros, statement.currency)} due`;
  const lastMonth = recentPeriods(byMeter.period, 2)[1]!;
  return (
    <>
      <PageHeader
        title="Billing"
        description="Platform meters and list prices, what each organization owes this month, credits, and statements. Organizations see their own spend, budgets and statements on their Billing page."
      />
      <div className="tiles">
        <Stat
          label={`Billable, ${periodLabel(byMeter.period)}`}
          value={money(billable, currency)}
        />
        <Stat label="Projected this month" value={money(projected, currency)} />
        <Stat label="Billing accounts" value={String(accounts.length)} />
        <Stat
          label="Unpaid invoices"
          value={String(outstanding.length)}
          hint={`${money(
            outstanding.reduce((sum, statement) => sum + statement.amountDueMicros, 0),
            currency,
          )} due`}
        />
        <Stat
          label="Subscriptions"
          value={String(subscriptions.length)}
          hint={`${subscriptions.filter((subscription) => subscription.status === 'trialing').length} trialing`}
        />
      </div>
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card title="Accounts this month" flush>
            <Table
              head={['Account', 'Billable', 'Projected', 'Credit', 'Last statement']}
              rows={accounts.map((account) => [
                <span key="n" className="row">
                  <strong>{account.name}</strong>
                  {account.hasProfile && <Badge tone="info">profile</Badge>}
                </span>,
                money(account.monthToDateMicros, currency),
                account.forecastMicros !== undefined
                  ? money(account.forecastMicros, currency)
                  : '—',
                account.creditsMicros ? money(account.creditsMicros, currency) : '—',
                account.lastStatement ? (
                  <span key="s" className="row">
                    <code className="small">{account.lastStatement.number}</code>
                    <Badge
                      tone={
                        account.lastStatement.overdue
                          ? 'danger'
                          : account.lastStatement.status === 'paid'
                            ? 'success'
                            : 'neutral'
                      }
                    >
                      {account.lastStatement.overdue ? 'overdue' : account.lastStatement.status}
                    </Badge>
                  </span>
                ) : (
                  <span key="s" className="muted">
                    none
                  </span>
                ),
              ])}
              empty="No usage recorded this month."
            />
          </Card>
          <Card title="Platform spend by meter" flush>
            <Table
              head={['Meter', 'Spend', 'Share']}
              rows={byMeter.rows.map((row) => [
                row.label ?? row.key,
                money(row.costMicros, currency),
                `${row.share}%`,
              ])}
              empty="No usage this month."
            />
          </Card>
          <Card title="Invoices" flush>
            <Table
              head={['Invoice', 'Account', 'Month', 'Total', 'Amount due', 'Due', 'Status', '']}
              rows={statements.map((statement) => [
                <span key="n" className="stack" style={{ gap: 2 }}>
                  <code className="small">{invoiceName(statement)}</code>
                  {statement.billingReason !== 'period' && (
                    <span className="small muted">{statement.billingReason}</span>
                  )}
                </span>,
                statement.tenantName ?? statement.tenantId,
                periodLabel(statement.period),
                money(statement.totalMicros, statement.currency),
                statement.status === 'draft' || statement.status === 'void'
                  ? '—'
                  : money(statement.amountDueMicros, statement.currency),
                <Time key="d" value={statement.dueAt} />,
                <span key="s" className="row">
                  <Badge tone={invoiceTone(statement.status)}>{statement.status}</Badge>
                  {statement.overdue && <Badge tone="danger">overdue</Badge>}
                </span>,
                <span key="a" className="actions">
                  {statement.status === 'draft' && (
                    <ApiButton
                      path="billing/finalizeInvoice"
                      body={{ tenantId, statementId: statement.id }}
                      label="Finalize"
                      confirm="Finalize this draft? It is recomputed, numbered and emailed to the billing contacts."
                      tenantId={tenantId}
                    />
                  )}
                  {(statement.status === 'finalized' || statement.status === 'uncollectible') && (
                    <ApiButton
                      path="billing/markPaid"
                      body={{ tenantId, statementId: statement.id }}
                      label="Mark paid"
                      tenantId={tenantId}
                    />
                  )}
                  {statement.status === 'finalized' && (
                    <ApiButton
                      path="billing/markUncollectible"
                      body={{ tenantId, statementId: statement.id }}
                      label="Write off"
                      confirm={`Write ${statement.number} off as uncollectible? A later payment still settles it.`}
                      tenantId={tenantId}
                    />
                  )}
                  {statement.status === 'finalized' && statement.amountPaidMicros === 0 && (
                    <ApiButton
                      path="billing/voidStatement"
                      body={{
                        tenantId,
                        statementId: statement.id,
                        reason: 'Voided from the administration panel',
                      }}
                      label="Void"
                      tone="danger"
                      confirm={`Void ${statement.number}? Its credit and invoice items are restored and the month reopens for the account.`}
                      tenantId={tenantId}
                    />
                  )}
                </span>,
              ])}
              empty="No invoices yet. Close a month to issue them."
            />
          </Card>
          <Card
            title="Plans"
            description="Subscribers pay the fees and seats monthly (in advance unless an item says arrears), and the plan's meter prices instead of the rate card."
            flush
          >
            <Table
              head={['Plan', 'Items', 'Subscribers', '']}
              rows={plans.map((plan) => [
                <span key="n" className="stack" style={{ gap: 2 }}>
                  <span className="row">
                    <strong>{plan.name}</strong>
                    <code className="small">{plan.key}</code>
                    {plan.selfServe && <Badge tone="info">self-serve</Badge>}
                    {plan.trialDays && <Badge tone="accent">{`${plan.trialDays}-day trial`}</Badge>}
                    {plan.archived && <Badge tone="warning">archived</Badge>}
                  </span>
                  {plan.description && <span className="small muted">{plan.description}</span>}
                </span>,
                <span key="i" className="small">
                  {planSummary(plan, currency)}
                </span>,
                String(plan.subscribers ?? 0),
                <ApiButton
                  key="a"
                  path="billing/updatePlan"
                  body={{ tenantId, plan: plan.key, archived: !plan.archived }}
                  label={plan.archived ? 'Restore' : 'Archive'}
                  tenantId={tenantId}
                />,
              ])}
              empty="No plans yet. Accounts are billed for usage at list prices."
            />
          </Card>
          <Card title="Subscriptions" flush>
            <Table
              head={['Account', 'Plan', 'Status', 'Seats', 'Started', '']}
              rows={subscriptions.map((subscription) => [
                subscription.accountName ?? subscription.accountId,
                subscription.planName,
                <span key="s" className="row">
                  <Badge tone={subscription.status === 'trialing' ? 'accent' : 'success'}>
                    {subscription.status}
                  </Badge>
                  {subscription.cancelAtPeriodEnd && <Badge tone="warning">cancels</Badge>}
                </span>,
                String(subscription.seats),
                <Time key="t" value={subscription.startedAt} />,
                <ApiButton
                  key="c"
                  path="billing/cancelSubscription"
                  body={{
                    tenantId: subscription.accountId,
                    subscriptionId: subscription.id,
                    atPeriodEnd: false,
                  }}
                  label="End now"
                  tone="danger"
                  confirm={`End ${subscription.accountName ?? 'the account'}'s ${subscription.planName} subscription now? Unused time already billed is credited on the next invoice.`}
                  tenantId={tenantId}
                />,
              ])}
              empty="No subscriptions."
            />
          </Card>
          <Card title="Coupons" flush>
            <Table
              head={['Code', 'Discount', 'Redeemed', 'Status', '']}
              rows={coupons.map((coupon) => [
                <span key="c" className="stack" style={{ gap: 2 }}>
                  <code>{coupon.code}</code>
                  <span className="small muted">{coupon.name}</span>
                </span>,
                `${coupon.percentOff !== undefined ? `${coupon.percentOff}%` : money(coupon.amountOffMicros ?? 0, currency)} off, ${
                  coupon.duration === 'repeating'
                    ? `${coupon.durationInMonths} months`
                    : coupon.duration
                }`,
                `${coupon.redemptions}${coupon.maxRedemptions ? ` of ${coupon.maxRedemptions}` : ''}`,
                <Badge key="s" tone={coupon.active ? 'success' : 'neutral'}>
                  {coupon.active ? 'active' : 'inactive'}
                </Badge>,
                coupon.active ? (
                  <ApiButton
                    key="d"
                    path="billing/deactivateCoupon"
                    body={{ tenantId, code: coupon.code }}
                    label="Deactivate"
                    tenantId={tenantId}
                  />
                ) : (
                  ''
                ),
              ])}
              empty="No coupons."
            />
          </Card>
          {pendingItems.length > 0 && (
            <Card title="Pending invoice items" flush>
              <Table
                head={['Account', 'Item', 'Invoice', 'Amount', '']}
                rows={pendingItems.map((item) => [
                  accounts.find((account) => account.accountId === item.accountId)?.name ??
                    item.accountId,
                  <span key="d" className="row">
                    {item.description}
                    {item.source === 'proration' && <Badge tone="info">proration</Badge>}
                  </span>,
                  item.period ? periodLabel(item.period) : 'next',
                  money(item.amountMicros, currency),
                  <ApiButton
                    key="x"
                    path="billing/deleteInvoiceItem"
                    body={{ tenantId: item.accountId, itemId: item.id }}
                    label="Delete"
                    tone="danger"
                    confirm={`Delete “${item.description}”?`}
                    tenantId={tenantId}
                  />,
                ])}
              />
            </Card>
          )}
          <Card title="Platform meters" flush>
            <Table
              head={['Meter', 'Counts', 'List price', '']}
              rows={platformMeters.map((meter) => [
                <span key="n" className="stack" style={{ gap: 2 }}>
                  <span className="row">
                    <code>{meter.key}</code>
                    {meter.archived && <Badge tone="warning">archived</Badge>}
                  </span>
                  <span className="small muted">{meter.name}</span>
                </span>,
                meter.aggregation === 'unique' ? 'distinct people per month' : `${meter.unit}s`,
                meter.pricing === 'reported'
                  ? 'reported with each event'
                  : meter.price
                    ? priceSummary(meter.price.price, meter.unit, currency)
                    : 'not priced',
                <ApiButton
                  key="a"
                  path="billing/updateMeter"
                  body={{ tenantId, key: meter.key, archived: !meter.archived }}
                  label={meter.archived ? 'Restore' : 'Archive'}
                  tenantId={tenantId}
                />,
              ])}
              empty="No platform meters yet."
            />
          </Card>
        </div>
        <div className="stack">
          <Card
            title="Close a month"
            description="Invoices every billing account with usage, subscription charges or pending items (skipping those already invoiced) and emails them. Schedule iam.billing.closePeriod() and iam.billing.sendPaymentReminders() daily to do this automatically."
          >
            <ApiForm
              path="billing/closePeriod"
              tenantId={tenantId}
              submitLabel="Issue invoices"
              showResult
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'period',
                  label: 'Month',
                  type: 'select',
                  required: true,
                  options: recentPeriods(lastMonth, 12).map((period) => ({
                    value: period,
                    label: periodLabel(period),
                  })),
                },
                {
                  name: 'draft',
                  label: 'Keep as drafts to review and finalize',
                  type: 'checkbox',
                },
              ]}
            />
          </Card>
          {outstanding.length > 0 && (
            <Card
              title="Record a payment"
              description="A partial payment leaves the rest due; an overpayment becomes account credit. Payment processors call iam.billing.recordPayment() instead."
            >
              <ApiForm
                path="billing/recordPayment"
                tenantId={tenantId}
                submitLabel="Record payment"
                successMessage="Payment recorded."
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'statementId',
                    label: 'Invoice',
                    type: 'select',
                    required: true,
                    options: outstanding.map((statement) => ({
                      value: statement.id,
                      label: invoiceLabel(statement),
                    })),
                  },
                  {
                    name: 'amount',
                    label: `Amount (${currency})`,
                    type: 'number',
                    help: 'Leave empty for the full amount due.',
                  },
                  {
                    name: 'method',
                    label: 'Method',
                    type: 'select',
                    options: [
                      { value: 'bank_transfer', label: 'Bank transfer' },
                      { value: 'card', label: 'Card' },
                      { value: 'check', label: 'Check' },
                      { value: 'manual', label: 'Other' },
                    ],
                  },
                  { name: 'reference', label: 'Reference', placeholder: 'wire-2231' },
                ]}
              />
            </Card>
          )}
          {creditable.length > 0 && (
            <Card
              title="Issue a credit note"
              description="Reduces what an invoice asks for; any part already paid becomes account credit, or is recorded as refunded."
            >
              <ApiForm
                path="billing/createCreditNote"
                tenantId={tenantId}
                submitLabel="Issue credit note"
                successMessage="Credit note issued."
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'statementId',
                    label: 'Invoice',
                    type: 'select',
                    required: true,
                    options: creditable.map((statement) => ({
                      value: statement.id,
                      label: invoiceLabel(statement),
                    })),
                  },
                  {
                    name: 'amount',
                    label: `Amount (${currency})`,
                    type: 'number',
                    help: 'Leave empty to credit everything not yet credited.',
                  },
                  {
                    name: 'reason',
                    label: 'Reason',
                    type: 'select',
                    options: [
                      { value: 'order_change', label: 'Order change' },
                      { value: 'product_unsatisfactory', label: 'Product unsatisfactory' },
                      { value: 'duplicate', label: 'Duplicate' },
                      { value: 'fraudulent', label: 'Fraudulent' },
                      { value: 'other', label: 'Other' },
                    ],
                  },
                  { name: 'memo', label: 'Memo', placeholder: 'Outage on 12 March' },
                  {
                    name: 'refund',
                    label: 'Refund the paid part instead of keeping it as credit',
                    type: 'checkbox',
                  },
                ]}
              />
            </Card>
          )}
          <Card
            title="Add an invoice item"
            description="A one-off charge, or with a negative amount a credit, on an account's next invoice (or the invoice for the chosen month)."
          >
            <ApiForm
              path="billing/createInvoiceItem"
              tenantId={tenantId}
              submitLabel="Add item"
              successMessage="Invoice item added."
              resetOnSuccess
              fields={[
                {
                  name: 'tenantId',
                  label: 'Account',
                  type: 'select',
                  required: true,
                  options: accountOptions,
                },
                {
                  name: 'description',
                  label: 'Description',
                  required: true,
                  placeholder: 'Onboarding workshop',
                },
                {
                  name: 'amount',
                  label: `Unit amount (${currency})`,
                  type: 'number',
                  required: true,
                },
                { name: 'quantity', label: 'Quantity', type: 'number' },
                {
                  name: 'period',
                  label: 'Invoice for',
                  type: 'select',
                  options: recentPeriods(byMeter.period, 3).map((period) => ({
                    value: period,
                    label: periodLabel(period),
                  })),
                  help: 'Leave empty for the next invoice.',
                },
              ]}
            />
          </Card>
          <Card
            title="New plan"
            description='Items as JSON: fees ({ "id": "platform", "kind": "fee", "amount": 99 }), seats ({ "kind": "seat", "unitAmount": 10, "includedSeats": 3 }), or plan prices for meters ({ "kind": "usage", "meter": "api-calls", "price": { "model": "per-unit", "unitAmount": 0.001 } }). Fees and seats bill in advance unless "billing": "arrears".'
          >
            <ApiForm
              path="billing/createPlan"
              tenantId={tenantId}
              submitLabel="Create plan"
              successMessage="Plan created."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'key', label: 'Key', required: true, placeholder: 'team' },
                { name: 'name', label: 'Name', required: true, placeholder: 'Team' },
                { name: 'description', label: 'Description' },
                {
                  name: 'items',
                  label: 'Items (JSON)',
                  type: 'json',
                  rows: 5,
                  required: true,
                  placeholder:
                    '[{ "id": "platform", "kind": "fee", "name": "Platform fee", "amount": 99 },\n { "id": "seats", "kind": "seat", "name": "Seats", "unitAmount": 10, "includedSeats": 3 }]',
                },
                { name: 'trialDays', label: 'Trial (days)', type: 'number' },
                {
                  name: 'selfServe',
                  label: 'Self-serve: organizations may subscribe themselves',
                  type: 'checkbox',
                },
              ]}
            />
          </Card>
          <Card title="Subscribe an account">
            <ApiForm
              path="billing/subscribe"
              tenantId={tenantId}
              submitLabel="Subscribe"
              successMessage="Subscribed."
              resetOnSuccess
              fields={[
                {
                  name: 'tenantId',
                  label: 'Account',
                  type: 'select',
                  required: true,
                  options: accountOptions,
                },
                {
                  name: 'plan',
                  label: 'Plan',
                  type: 'select',
                  required: true,
                  options: plans
                    .filter((plan) => !plan.archived)
                    .map((plan) => ({ value: plan.key, label: plan.name })),
                },
                { name: 'seats', label: 'Seats', type: 'number' },
                {
                  name: 'trialDays',
                  label: 'Trial (days)',
                  type: 'number',
                  help: "Leave empty for the plan's trial; 0 for none.",
                },
              ]}
            />
          </Card>
          <Card
            title="New coupon"
            description="Accounts redeem the code on their Billing page. Percent or amount off; once (the next invoice), for some months, or forever."
          >
            <ApiForm
              path="billing/createCoupon"
              tenantId={tenantId}
              submitLabel="Create coupon"
              successMessage="Coupon created."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'code', label: 'Code', required: true, placeholder: 'LAUNCH50' },
                { name: 'name', label: 'Name', placeholder: 'Launch offer' },
                { name: 'percentOff', label: 'Percent off', type: 'number' },
                { name: 'amountOff', label: `Or amount off (${currency})`, type: 'number' },
                {
                  name: 'duration',
                  label: 'Applies to',
                  type: 'select',
                  options: [
                    { value: 'once', label: 'The next invoice' },
                    { value: 'repeating', label: 'Invoices for some months' },
                    { value: 'forever', label: 'Every invoice' },
                  ],
                },
                { name: 'durationInMonths', label: 'Months (repeating)', type: 'number' },
                { name: 'maxRedemptions', label: 'Redemptions allowed', type: 'number' },
              ]}
            />
          </Card>
          <Card
            title="Contract terms"
            description="Per billing account, applied to statements issued from now on: a discount off usage, a minimum monthly commitment (a shortfall is billed as a true-up), and tax. Leave a field empty to clear it."
          >
            <ApiForm
              path="billing/setTerms"
              tenantId={tenantId}
              submitLabel="Save terms"
              successMessage="Terms saved."
              fields={[
                {
                  name: 'tenantId',
                  label: 'Account',
                  type: 'select',
                  required: true,
                  options: accounts.map((account) => ({
                    value: account.accountId,
                    label: account.name,
                  })),
                },
                {
                  name: 'discountPercent',
                  label: 'Discount (%)',
                  type: 'number',
                  emptyAsNull: true,
                },
                {
                  name: 'minimumCommitment',
                  label: `Minimum per month (${currency})`,
                  type: 'number',
                  emptyAsNull: true,
                },
                { name: 'taxRatePercent', label: 'Tax (%)', type: 'number', emptyAsNull: true },
                { name: 'taxLabel', label: 'Tax label', placeholder: 'VAT', emptyAsNull: true },
              ]}
            />
          </Card>
          <Card
            title="Grant credit"
            description="Statements draw on credit, earliest expiry first."
          >
            <ApiForm
              path="billing/grantCredit"
              tenantId={tenantId}
              submitLabel="Grant credit"
              successMessage="Credit granted."
              resetOnSuccess
              fields={[
                {
                  name: 'tenantId',
                  label: 'Account',
                  type: 'select',
                  required: true,
                  options: accounts.map((account) => ({
                    value: account.accountId,
                    label: account.name,
                  })),
                },
                { name: 'amount', label: `Amount (${currency})`, type: 'number', required: true },
                {
                  name: 'reason',
                  label: 'Reason',
                  required: true,
                  placeholder: 'Launch promotion',
                },
                { name: 'expiresAt', label: 'Expires', type: 'datetime' },
              ]}
            />
          </Card>
          <Card title="New platform meter">
            <ApiForm
              path="billing/createMeter"
              tenantId={tenantId}
              submitLabel="Create meter"
              successMessage="Meter created."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'key', label: 'Key', required: true, placeholder: 'api-calls' },
                { name: 'name', label: 'Name', required: true, placeholder: 'API calls' },
                { name: 'unit', label: 'Unit', placeholder: 'request' },
                {
                  name: 'aggregation',
                  label: 'Counts',
                  type: 'select',
                  options: [
                    { value: 'sum', label: 'Sum of quantities' },
                    { value: 'unique', label: 'Distinct people per month (active users)' },
                  ],
                },
                {
                  name: 'pricing',
                  label: 'Pricing',
                  type: 'select',
                  options: [
                    { value: 'rate-card', label: 'Rate card' },
                    { value: 'reported', label: 'Cost reported with each event' },
                  ],
                },
              ]}
            />
          </Card>
          {platformMeters.some((meter) => meter.pricing === 'rate-card') && (
            <Card
              title="Set a price"
              description="Leave the organization empty for the list price; pick one for a negotiated price that applies to it and its projects."
            >
              <ApiForm
                path="billing/setPrice"
                tenantId={tenantId}
                submitLabel="Save price"
                successMessage="Price saved."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'meter',
                    label: 'Meter',
                    type: 'select',
                    required: true,
                    options: platformMeters
                      .filter((meter) => meter.pricing === 'rate-card')
                      .map((meter) => ({ value: meter.key, label: meter.name })),
                  },
                  {
                    name: 'targetTenantId',
                    label: 'Organization or project',
                    type: 'select',
                    options: tenantChoices,
                  },
                  {
                    name: 'effectiveFrom',
                    label: 'From month',
                    type: 'select',
                    options: recentPeriods(byMeter.period, 2).map((period) => ({
                      value: period,
                      label: periodLabel(period),
                    })),
                  },
                  {
                    name: 'model',
                    label: 'Model',
                    type: 'select',
                    required: true,
                    group: 'price',
                    options: [
                      { value: 'per-unit', label: 'Per unit' },
                      { value: 'graduated', label: 'Graduated tiers' },
                      { value: 'volume', label: 'Volume tiers' },
                      { value: 'package', label: 'Packages' },
                    ],
                  },
                  { name: 'unitAmount', label: 'Unit price', type: 'number', group: 'price' },
                  {
                    name: 'tiers',
                    label: 'Tiers (JSON)',
                    type: 'json',
                    rows: 3,
                    group: 'price',
                    placeholder:
                      '[{ "upTo": 10000, "unitAmount": 0.01 }, { "upTo": null, "unitAmount": 0.005 }]',
                  },
                  { name: 'packageSize', label: 'Package size', type: 'number', group: 'price' },
                  { name: 'packageAmount', label: 'Package price', type: 'number', group: 'price' },
                  {
                    name: 'includedQuantity',
                    label: 'Included per month',
                    type: 'number',
                    group: 'price',
                  },
                  { name: 'note', label: 'Note', placeholder: 'Enterprise agreement 2026' },
                ]}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
