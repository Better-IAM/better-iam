import Link from 'next/link';
import type { BillingBudgetView, SpendGroupBy, SpendReport } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { SubscriptionCards } from '@/components/billing-subscriptions';
import { Alert, Badge, Card, KeyValues, PageHeader, Stat, Table, Time } from '@/components/ui';
import {
  invoiceName,
  invoiceTone,
  money,
  periodLabel,
  priceSummary,
  quantity,
  recentPeriods,
} from '@/lib/billing';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const views: { key: SpendGroupBy; label: string; column: string }[] = [
  { key: 'meter', label: 'Meters', column: 'Meter' },
  { key: 'identity', label: 'People', column: 'Person or account' },
  { key: 'team', label: 'Teams', column: 'Team' },
  { key: 'department', label: 'Departments', column: 'Department' },
  { key: 'tenant', label: 'Projects', column: 'Organization or project' },
  { key: 'day', label: 'Days', column: 'Day' },
];

function Share({ percent, tone }: { percent: number; tone?: 'success' | 'warning' | 'danger' }) {
  const width = Math.max(0, Math.min(100, percent));
  return (
    <span className="row">
      <span className={`meter ${tone ?? 'success'}`} style={{ width: 90, display: 'inline-block' }}>
        <span style={{ width: `${width}%` }} />
      </span>
      <span className="small">{percent}%</span>
    </span>
  );
}

function Quantities({ values }: { values: Record<string, number> }) {
  const entries = Object.entries(values);
  if (!entries.length) return <span className="muted">—</span>;
  return (
    <span className="small muted">
      {entries.map(([meter, value]) => `${quantity(value)} ${meter}`).join(' · ')}
    </span>
  );
}

function SpendTable({ report, column }: { report: SpendReport; column: string }) {
  return (
    <Table
      head={[column, 'Spend', 'Share', 'Usage']}
      rows={report.rows.map((row) => [
        row.key.startsWith('(') ? (
          <span key="k" className="muted">
            {row.key.slice(1, -1)}
          </span>
        ) : (
          (row.label ?? <code key="k">{row.key}</code>)
        ),
        money(row.costMicros, report.currency),
        <Share key="s" percent={row.share} />,
        <Quantities key="q" values={row.quantities} />,
      ])}
      empty="No usage in this period."
    />
  );
}

function BudgetStanding({ budget, currency }: { budget: BillingBudgetView; currency: string }) {
  const tone = budget.exceeded ? 'danger' : budget.percent >= 80 ? 'warning' : 'success';
  return (
    <span className="stack" style={{ gap: 2 }}>
      <Share percent={budget.percent} tone={tone} />
      <span className="small muted">
        {money(budget.spentMicros, currency)} of {money(budget.amountMicros, currency)}
        {budget.forecastMicros !== undefined &&
          ` · projected ${money(budget.forecastMicros, currency)}`}
      </span>
    </span>
  );
}

const subjectLabel: Record<string, string> = {
  tenant: 'Organization',
  team: 'Team',
  department: 'Department',
  identity: 'Person',
};

/**
 * Billing: what this organization (and its projects) spends, by meter, person, team, department, project or day;
 * spend budgets with alerts; statements; the meters and prices that apply; the billing profile. People without
 * billing permissions see their own spend.
 */
export default async function Billing({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ period?: string; view?: string; shared?: string }>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const { iam, auth, tenantId, base, tenant } = await orgPage(org);
  const period = /^\d{4}-(0[1-9]|1[0-2])$/.test(query.period ?? '') ? query.period : undefined;
  const view = views.find((candidate) => candidate.key === query.view) ?? views[1]!;
  // Showback: spread unattributed spend over people, teams or departments.
  const shareable = ['identity', 'team', 'department'].includes(view.key);
  const shared = shareable && query.shared === '1';
  const [
    spend,
    trend,
    budgets,
    statements,
    meters,
    credits,
    profile,
    mine,
    teams,
    departments,
    people,
    spikes,
  ] = await Promise.all([
    tryRead(() =>
      iam.api.billing.spend(auth, {
        tenantId,
        groupBy: view.key,
        ...(period ? { period } : {}),
        ...(shared ? { shareUnattributed: true } : {}),
      }),
    ),
    tryRead(() => iam.api.billing.trend(auth, { tenantId, months: 6 })),
    tryRead(() => iam.api.billing.listBudgets(auth, { tenantId })),
    tryRead(() => iam.api.billing.listStatements(auth, { tenantId })),
    tryRead(() => iam.api.billing.listMeters(auth, { tenantId })),
    tryRead(() => iam.api.billing.listCredits(auth, { tenantId })),
    tryRead(() => iam.api.billing.getProfile(auth, { tenantId })),
    tryRead(() => iam.api.billing.mySpend(auth, { tenantId, ...(period ? { period } : {}) })),
    tryRead(() => iam.api.teams.list(auth, { tenantId })),
    tryRead(() => iam.api.departments.list(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
    tryRead(() => iam.api.billing.anomalies(auth, { tenantId })),
  ]);
  const [terms, subscriptions, plans, discounts, pendingItems] = await Promise.all([
    tryRead(() => iam.api.billing.getTerms(auth, { tenantId })),
    tryRead(() => iam.api.billing.listSubscriptions(auth, { tenantId })),
    tryRead(() => iam.api.billing.listPlans(auth, { tenantId })),
    tryRead(() => iam.api.billing.listDiscounts(auth, { tenantId })),
    tryRead(() => iam.api.billing.listInvoiceItems(auth, { tenantId, status: 'pending' })),
  ]);
  const outstanding = (statements ?? []).filter(
    (statement) => statement.status === 'finalized' || statement.status === 'uncollectible',
  );
  const currency = spend?.currency ?? mine?.currency ?? 'USD';
  const shownPeriod = spend?.period ?? mine?.period;
  const currentPeriod = trend?.months.at(-1)?.period ?? shownPeriod;
  const periods = currentPeriod ? recentPeriods(currentPeriod, 12) : [];
  const href = (next: { period?: string; view?: string; shared?: boolean }) => {
    const search = new URLSearchParams();
    const chosenPeriod = next.period ?? period;
    if (chosenPeriod) search.set('period', chosenPeriod);
    search.set('view', next.view ?? view.key);
    if (next.shared ?? shared) search.set('shared', '1');
    return `${base}/billing?${search.toString()}`;
  };
  const exportHref = (() => {
    const search = new URLSearchParams({ org, kind: 'spend', view: view.key });
    if (period) search.set('period', period);
    if (shared) search.set('shared', '1');
    return `/api/console/billing-export?${search.toString()}`;
  })();
  const trendMax = Math.max(1, ...(trend?.months.map((month) => month.costMicros) ?? [0]));
  const atRisk = (budgets ?? []).filter(
    (budget) => budget.exceeded || budget.percent >= 80 || (budget.forecastPercent ?? 0) >= 100,
  );
  const ownMeters = (meters ?? []).filter((meter) => !meter.inherited);
  const activePeople = (people ?? []).filter((person) => person.status === 'active');
  const subjectOptions = [
    { value: tenantId, label: `Organization: ${tenant.name}` },
    ...(teams ?? []).map((team) => ({ value: team.id, label: `Team: ${team.name}` })),
    ...(departments ?? []).map((department) => ({
      value: department.id,
      label: `Department: ${department.name}`,
    })),
    ...activePeople.map((person) => ({
      value: person.id,
      label: `${person.kind === 'agent' ? 'Agent' : person.kind === 'service' ? 'Service' : 'Person'}: ${person.email ?? person.name}`,
    })),
  ];

  if (!spend && mine) {
    // Members without billing permissions: their own spend only.
    return (
      <>
        <PageHeader
          title="Your spend"
          description="What your usage (and that of agents you sponsor) cost this organization."
        />
        <div className="tiles">
          <Stat label={periodLabel(mine.period)} value={money(mine.total.costMicros, currency)} />
          {mine.forecast && (
            <Stat label="Projected this month" value={money(mine.forecast.costMicros, currency)} />
          )}
        </div>
        <Card title="By meter" flush>
          <SpendTable report={mine} column="Meter" />
        </Card>
        {mine.budgets.length > 0 && (
          <Card title="Your budgets" flush>
            <Table
              head={['Budget', 'Per', 'Standing']}
              rows={mine.budgets.map((budget) => [
                budget.name,
                budget.period,
                <Share
                  key="s"
                  percent={budget.percent}
                  tone={budget.exceeded ? 'danger' : budget.percent >= 80 ? 'warning' : 'success'}
                />,
              ])}
            />
          </Card>
        )}
      </>
    );
  }

  return (
    <>
      <PageHeader
        title="Billing"
        description="Spend of this organization and its projects: priced once per billing account and month, then shared out to the people, teams, departments and projects that used it."
        actions={
          <form method="get" className="row">
            <input type="hidden" name="view" value={view.key} />
            <select className="select" name="period" defaultValue={shownPeriod}>
              {periods.map((value) => (
                <option key={value} value={value}>
                  {periodLabel(value)}
                </option>
              ))}
            </select>
            <button className="btn small secondary">Show</button>
          </form>
        }
      />
      {!spend && (
        <Alert tone="warning">
          Billing needs <code>iam:billing:read</code>.
        </Alert>
      )}
      {spend && (
        <div className="tiles">
          <Stat
            label={shownPeriod ? periodLabel(shownPeriod) : 'This period'}
            value={money(spend.total.costMicros, currency)}
            hint={`${quantity(spend.total.events)} usage events`}
          />
          <Stat
            label="Projected"
            value={spend.forecast ? money(spend.forecast.costMicros, currency) : '—'}
            hint={spend.forecast ? 'linear, to the end of the month' : 'for the current month'}
          />
          <Stat
            label="Credit"
            value={credits ? money(credits.balanceMicros, currency) : '—'}
            hint={credits?.inherited ? 'held by the paying account' : 'available on statements'}
          />
          <Stat
            label="Budgets at risk"
            value={String(atRisk.length)}
            hint={`of ${budgets?.length ?? 0}`}
          />
          <Stat
            label="Amount due"
            value={money(
              outstanding.reduce((sum, statement) => sum + statement.amountDueMicros, 0),
              currency,
            )}
            hint={
              outstanding.some((statement) => statement.overdue)
                ? `${outstanding.filter((statement) => statement.overdue).length} overdue`
                : `${outstanding.length} open invoice${outstanding.length === 1 ? '' : 's'}`
            }
          />
        </div>
      )}
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          {spend && (
            <Card
              title={`Spend by ${view.label.toLowerCase()}`}
              description={
                view.key === 'team'
                  ? 'A person in several teams counts toward each of them in equal parts.'
                  : view.key === 'identity'
                    ? 'Agents are listed on their own; their usage also counts toward their sponsor’s teams.'
                    : undefined
              }
              actions={
                <span className="row">
                  {views.map((candidate) => (
                    <Link
                      key={candidate.key}
                      href={href({ view: candidate.key })}
                      className={`btn small ${candidate.key === view.key ? '' : 'ghost'}`}
                    >
                      {candidate.label}
                    </Link>
                  ))}
                </span>
              }
              flush
            >
              <SpendTable report={spend} column={view.column} />
              <div
                className="row"
                style={{ padding: '10px 16px', justifyContent: 'space-between' }}
              >
                <span className="small muted">
                  {shareable &&
                    (shared ? (
                      <>
                        {money(spend.sharedMicros ?? 0, currency)} of unattributed spend is shared
                        out by each group&apos;s share.{' '}
                        <Link href={href({ shared: false })}>Show it apart</Link>
                      </>
                    ) : (
                      <Link href={href({ shared: true })}>
                        Share unattributed spend out (showback)
                      </Link>
                    ))}
                </span>
                <a className="btn small secondary" href={exportHref}>
                  Download CSV
                </a>
              </div>
            </Card>
          )}
          {spikes && spikes.anomalies.length > 0 && (
            <Card
              title="Spend spikes yesterday"
              description="People, teams and meters that spent at least three times their usual daily amount. Owners and billing contacts get these by email each morning."
              flush
            >
              <Table
                head={['What', 'Yesterday', 'Usual per day', 'Change']}
                rows={spikes.anomalies.map((anomaly) => [
                  <span key="w" className="row">
                    <Badge>{anomaly.dimension === 'identity' ? 'person' : anomaly.dimension}</Badge>
                    {anomaly.label ?? anomaly.key}
                  </span>,
                  money(anomaly.costMicros, currency),
                  money(anomaly.baselineMicros, currency),
                  anomaly.factor === null ? (
                    <Badge key="c" tone="warning">
                      new
                    </Badge>
                  ) : (
                    <Badge key="c" tone="danger">
                      {`${anomaly.factor}×`}
                    </Badge>
                  ),
                ])}
              />
            </Card>
          )}
          {trend && (
            <Card title="Last six months">
              <div className="stack" style={{ gap: 6 }}>
                {trend.months.map((month) => (
                  <div key={month.period} className="row" style={{ gap: 12 }}>
                    <Link
                      href={href({ period: month.period })}
                      className="small"
                      style={{ width: 130 }}
                    >
                      {periodLabel(month.period)}
                    </Link>
                    <span className="meter success" style={{ flex: 1, display: 'inline-block' }}>
                      <span style={{ width: `${(month.costMicros / trendMax) * 100}%` }} />
                    </span>
                    <span className="small mono" style={{ width: 110, textAlign: 'right' }}>
                      {money(month.costMicros, currency)}
                    </span>
                  </div>
                ))}
              </div>
            </Card>
          )}
          <Card
            title="Budgets"
            description="Alerts go to the owners, the budget's subject (the person, the team's maintainers or the department head) and any extra addresses, once per threshold and window. Enforced budgets refuse covered usage once spent."
            flush
          >
            {budgets ? (
              <Table
                head={['Budget', 'Covers', 'Standing', 'Alerts', '']}
                rows={budgets.map((budget) => [
                  <span key="n" className="stack" style={{ gap: 2 }}>
                    <strong>{budget.name}</strong>
                    <span className="row">
                      <Badge>{budget.period}</Badge>
                      {budget.enforce && <Badge tone="danger">enforced</Badge>}
                      {budget.meters && <Badge tone="info">{budget.meters.join(', ')}</Badge>}
                    </span>
                  </span>,
                  `${subjectLabel[budget.subjectType]}: ${budget.subjectName ?? budget.subjectId}`,
                  <BudgetStanding key="s" budget={budget} currency={currency} />,
                  <span key="t" className="small muted">
                    {budget.thresholds
                      .map((threshold) =>
                        budget.reached.includes(threshold) ? `${threshold}% ✓` : `${threshold}%`,
                      )
                      .join(' · ')}
                  </span>,
                  <ApiButton
                    key="d"
                    path="billing/deleteBudget"
                    body={{ tenantId, budgetId: budget.budgetId }}
                    label="Delete"
                    tone="danger"
                    confirm={`Delete the budget ${budget.name}?`}
                    tenantId={tenantId}
                  />,
                ])}
                empty="No budgets yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:billing:read</code>.
              </div>
            )}
          </Card>
          <Card
            title="Invoices"
            description="Issued by the platform: monthly for usage, subscription fees and seats, and one-off items; when a subscription starts, for its first month."
            flush
          >
            {statements ? (
              <Table
                head={['Invoice', 'Month', 'Account', 'Status', 'Total', 'Amount due', 'Due']}
                rows={statements.map((statement) => [
                  <Link key="n" href={`${base}/billing/statements/${statement.id}`}>
                    <code>{invoiceName(statement)}</code>
                  </Link>,
                  <span key="m" className="stack" style={{ gap: 2 }}>
                    {periodLabel(statement.period)}
                    {statement.billingReason === 'subscription' && (
                      <span className="small muted">new subscription</span>
                    )}
                  </span>,
                  statement.tenantName ?? statement.tenantId,
                  <span key="s" className="row">
                    <Badge tone={invoiceTone(statement.status)}>{statement.status}</Badge>
                    {statement.overdue && <Badge tone="danger">overdue</Badge>}
                  </span>,
                  money(statement.totalMicros, statement.currency),
                  statement.status === 'void' || statement.status === 'draft'
                    ? '—'
                    : money(statement.amountDueMicros, statement.currency),
                  <Time key="d" value={statement.dueAt} />,
                ])}
                empty="No invoices yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:billing:read</code>.
              </div>
            )}
          </Card>
          <Card
            title="Meters and prices"
            description="Platform meters are billed to this organization; meters it defines itself are for internal chargeback and never appear on a statement."
            flush
          >
            {meters ? (
              <Table
                head={['Meter', 'Counts', 'Price', '']}
                rows={meters.map((meter) => [
                  <span key="n" className="stack" style={{ gap: 2 }}>
                    <span className="row">
                      <code>{meter.key}</code>
                      {meter.scope === 'platform' ? (
                        <Badge tone="accent">platform</Badge>
                      ) : meter.inherited ? (
                        <Badge>inherited</Badge>
                      ) : (
                        <Badge tone="info">chargeback</Badge>
                      )}
                      {meter.archived && <Badge tone="warning">archived</Badge>}
                    </span>
                    <span className="small muted">{meter.name}</span>
                  </span>,
                  `${meter.aggregation === 'unique' ? 'distinct people per month' : `${meter.unit}s`}`,
                  meter.pricing === 'reported' ? (
                    <span key="p" className="muted small">
                      cost reported with each event
                    </span>
                  ) : meter.price ? (
                    <span key="p" className="small">
                      {priceSummary(meter.price.price, meter.unit, currency)}
                    </span>
                  ) : (
                    <span key="p" className="muted small">
                      not priced
                    </span>
                  ),
                  meter.inherited ? (
                    ''
                  ) : (
                    <ApiButton
                      key="a"
                      path="billing/updateMeter"
                      body={{ tenantId, key: meter.key, archived: !meter.archived }}
                      label={meter.archived ? 'Restore' : 'Archive'}
                      tenantId={tenantId}
                    />
                  ),
                ])}
                empty="No meters reach this organization yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:billing:read</code>.
              </div>
            )}
          </Card>
        </div>
        <div className="stack">
          {mine && (
            <Card title="Your spend" description={periodLabel(mine.period)}>
              <p>
                <strong>{money(mine.total.costMicros, currency)}</strong>
                {mine.forecast && (
                  <span className="muted small">
                    {' '}
                    · projected {money(mine.forecast.costMicros, currency)}
                  </span>
                )}
              </p>
              {mine.rows.length > 0 && (
                <ul className="small">
                  {mine.rows.map((row) => (
                    <li key={row.key}>
                      {row.label ?? row.key}: {money(row.costMicros, currency)}
                    </li>
                  ))}
                </ul>
              )}
              {mine.budgets.map((budget) => (
                <div key={budget.budgetId} className="small">
                  {budget.name}: <Share percent={budget.percent} />
                </div>
              ))}
            </Card>
          )}
          {spend && (
            <SubscriptionCards
              tenantId={tenantId}
              currency={currency}
              subscriptions={subscriptions}
              plans={plans}
              discounts={discounts}
              pendingItems={pendingItems}
            />
          )}
          <Card title="New budget" description="Requires iam:billing:manage.">
            <ApiForm
              path="billing/createBudget"
              tenantId={tenantId}
              submitLabel="Create budget"
              successMessage="Budget created."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'name',
                  label: 'Name',
                  required: true,
                  placeholder: 'Platform team monthly',
                },
                {
                  name: 'subjectType',
                  label: 'Covers',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'tenant', label: 'The organization (or a project)' },
                    { value: 'team', label: 'A team (with its sub-teams)' },
                    { value: 'department', label: 'A department (with those below it)' },
                    { value: 'identity', label: 'One person, service account or agent' },
                  ],
                },
                {
                  name: 'subjectId',
                  label: 'Which one',
                  type: 'select',
                  required: true,
                  options: subjectOptions,
                  help: 'Pick an entry of the kind chosen above.',
                },
                { name: 'amount', label: `Amount (${currency})`, type: 'number', required: true },
                {
                  name: 'period',
                  label: 'Per',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'month', label: 'Month' },
                    { value: 'quarter', label: 'Quarter' },
                    { value: 'year', label: 'Year' },
                  ],
                },
                {
                  name: 'thresholds',
                  label: 'Alert at (%)',
                  type: 'list',
                  placeholder: '50, 80, 100',
                },
                {
                  name: 'meters',
                  label: 'Only these meters',
                  type: 'list',
                  placeholder: 'api-calls, inference',
                },
                {
                  name: 'emails',
                  label: 'Also notify',
                  type: 'list',
                  group: 'notify',
                  placeholder: 'finance@example.com',
                },
                {
                  name: 'forecastAlerts',
                  label: 'Alert when the projection passes the budget',
                  type: 'checkbox',
                  defaultValue: true,
                },
                {
                  name: 'enforce',
                  label: 'Enforce: refuse covered usage once spent',
                  type: 'checkbox',
                },
              ]}
            />
          </Card>
          <Card
            title="Billing profile"
            description={
              profile?.account.inherited
                ? `Billed through ${profile.account.name}. A project gets its own account when its parent sets a profile for it.`
                : 'Statements go to the billing emails (or the owners when there are none).'
            }
          >
            {profile && (
              <KeyValues
                items={[
                  ['Paying account', profile.account.name],
                  ['Updated', <Time key="u" value={profile.profile?.updatedAt} />],
                  ...(terms && !terms.inherited
                    ? ([
                        [
                          'Contract terms',
                          [
                            terms.discountPercent !== undefined
                              ? `${terms.discountPercent}% discount`
                              : undefined,
                            terms.minimumCommitmentMicros !== undefined
                              ? `${money(terms.minimumCommitmentMicros, currency)} minimum per month`
                              : undefined,
                            terms.taxRatePercent !== undefined
                              ? `${terms.taxLabel ?? 'Tax'} ${terms.taxRatePercent}%`
                              : undefined,
                          ]
                            .filter(Boolean)
                            .join(' · ') || 'standard (set by the platform)',
                        ],
                      ] as [string, string][])
                    : []),
                ]}
              />
            )}
            <ApiForm
              path="billing/setProfile"
              tenantId={tenantId}
              submitLabel="Save profile"
              successMessage="Profile saved."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'companyName',
                  label: 'Company name',
                  defaultValue: profile?.profile?.companyName ?? '',
                  emptyAsNull: true,
                },
                {
                  name: 'billingEmails',
                  label: 'Billing emails',
                  type: 'list',
                  defaultValue: profile?.profile?.billingEmails ?? [],
                },
                {
                  name: 'taxId',
                  label: 'Tax ID',
                  defaultValue: profile?.profile?.taxId ?? '',
                  emptyAsNull: true,
                },
                {
                  name: 'address',
                  label: 'Address',
                  type: 'textarea',
                  rows: 3,
                  defaultValue: profile?.profile?.address ?? '',
                  emptyAsNull: true,
                },
                {
                  name: 'purchaseOrder',
                  label: 'Purchase order',
                  defaultValue: profile?.profile?.purchaseOrder ?? '',
                  emptyAsNull: true,
                },
                {
                  name: 'costCenter',
                  label: 'Cost center',
                  defaultValue: profile?.profile?.costCenter ?? '',
                  emptyAsNull: true,
                },
                {
                  name: 'paymentTermsDays',
                  label: 'Payment terms (days)',
                  type: 'number',
                  defaultValue:
                    profile?.profile?.paymentTermsDays !== undefined
                      ? String(profile.profile.paymentTermsDays)
                      : '',
                  emptyAsNull: true,
                },
              ]}
            />
          </Card>
          {credits && credits.credits.length > 0 && (
            <Card title="Credit" flush>
              <Table
                head={['Reason', 'Left', 'Expires']}
                rows={credits.credits.map((credit) => [
                  <span key="r" className="row">
                    {credit.reason}
                    {!credit.active && <Badge>used up</Badge>}
                  </span>,
                  `${money(credit.remainingMicros, currency)} of ${money(credit.amountMicros, currency)}`,
                  <Time key="e" value={credit.expiresAt} />,
                ])}
              />
            </Card>
          )}
          <Card
            title="Record usage"
            description="Enter usage by hand, such as a team's share of a cloud bill on a chargeback meter. Requires iam:billing:record; applications meter through the API or iam.billing.record."
          >
            <ApiForm
              path="billing/record"
              tenantId={tenantId}
              submitLabel="Record"
              successMessage="Recorded."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'meter',
                  label: 'Meter',
                  type: 'select',
                  required: true,
                  options: (meters ?? [])
                    .filter((meter) => !meter.archived)
                    .map((meter) => ({ value: meter.key, label: `${meter.name} (${meter.key})` })),
                },
                { name: 'quantity', label: 'Quantity', type: 'number', required: true },
                {
                  name: 'cost',
                  label: `Cost (${currency}, reported meters only)`,
                  type: 'number',
                },
                {
                  name: 'identityId',
                  label: 'Attribute to',
                  type: 'select',
                  options: activePeople.map((person) => ({
                    value: person.id,
                    label: person.email ?? person.name,
                  })),
                },
                {
                  name: 'teamId',
                  label: 'Or to a team',
                  type: 'select',
                  options: (teams ?? []).map((team) => ({ value: team.id, label: team.name })),
                },
                {
                  name: 'tags',
                  label: 'Tags (JSON)',
                  type: 'json',
                  rows: 2,
                  placeholder: '{ "project": "apollo" }',
                },
              ]}
            />
          </Card>
          <Card
            title="Chargeback meter"
            description="A meter for this organization's own cost allocation (cloud bills, licences, support hours). Reported meters take a cost with each entry; rate-card meters are priced below."
          >
            <ApiForm
              path="billing/createMeter"
              tenantId={tenantId}
              submitLabel="Create meter"
              successMessage="Meter created."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'key', label: 'Key', required: true, placeholder: 'cloud-compute' },
                { name: 'name', label: 'Name', required: true, placeholder: 'Cloud compute' },
                { name: 'unit', label: 'Unit', placeholder: 'vCPU-hour' },
                {
                  name: 'pricing',
                  label: 'Pricing',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'reported', label: 'Cost reported with each entry' },
                    { value: 'rate-card', label: 'Priced from a rate card' },
                  ],
                },
                {
                  name: 'aggregation',
                  label: 'Counts',
                  type: 'select',
                  options: [
                    { value: 'sum', label: 'Sum of quantities' },
                    { value: 'unique', label: 'Distinct people per month' },
                  ],
                },
              ]}
            />
          </Card>
          {ownMeters.some((meter) => meter.pricing === 'rate-card') && (
            <Card
              title="Price a meter"
              description="From the current month on, for this organization and its projects."
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
                    options: ownMeters
                      .filter((meter) => meter.pricing === 'rate-card')
                      .map((meter) => ({ value: meter.key, label: meter.name })),
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
                      '[{ "upTo": 1000, "unitAmount": 0.01 }, { "upTo": null, "unitAmount": 0.005 }]',
                  },
                  { name: 'packageSize', label: 'Package size', type: 'number', group: 'price' },
                  { name: 'packageAmount', label: 'Package price', type: 'number', group: 'price' },
                  {
                    name: 'includedQuantity',
                    label: 'Included per month',
                    type: 'number',
                    group: 'price',
                  },
                ]}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
