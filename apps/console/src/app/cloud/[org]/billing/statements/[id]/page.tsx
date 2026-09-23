import Link from 'next/link';
import type { ReactNode } from 'react';
import type { StatementAllocation, StatementLine } from 'better-iam';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { invoiceTone, money, periodLabel, quantity } from '@/lib/billing';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

function Allocations({
  entries,
  currency,
  empty,
  costCenters,
}: {
  entries: (StatementAllocation & { costCenter?: string })[];
  currency: string;
  empty: string;
  costCenters?: boolean;
}) {
  return (
    <Table
      head={costCenters ? ['Name', 'Cost center', 'Amount'] : ['Name', 'Amount']}
      rows={entries.map((entry) =>
        costCenters
          ? [entry.name, entry.costCenter ?? '—', money(entry.costMicros, currency)]
          : [entry.name, money(entry.costMicros, currency)],
      )}
      empty={empty}
    />
  );
}

const day = (at: number) => new Date(at).toISOString().slice(0, 10);

/** One invoice line with what explains it, then its tier sub-lines. */
function lineRows(line: StatementLine, currency: string): ReactNode[][] {
  const details: string[] = [];
  if (line.servicePeriod)
    details.push(`${day(line.servicePeriod.start)} to ${day(line.servicePeriod.end - 1)}`);
  if (line.proration !== undefined)
    details.push(`${Math.round(line.proration * 1000) / 10}% of the month`);
  if (line.includedQuantity) details.push(`${quantity(line.includedQuantity)} included`);
  if (line.price)
    details.push(
      line.price.source === 'plan'
        ? `plan price (${line.price.model})`
        : `${line.price.model}, from ${periodLabel(line.price.effectiveFrom)}`,
    );
  if (line.adjustedFromMicros !== undefined)
    details.push(`price minimum or maximum applied to ${money(line.adjustedFromMicros, currency)}`);
  const unitPrice =
    line.unitAmountMicros !== undefined
      ? money(line.unitAmountMicros, currency)
      : line.tiers?.length === 1
        ? money(line.tiers[0]!.unitAmountMicros, currency)
        : '';
  const main: ReactNode[] = [
    <span key="d" className="stack" style={{ gap: 2 }}>
      <span className="row">
        {line.name}
        {line.kind === 'fee' && <Badge tone="accent">fee</Badge>}
        {line.kind === 'seat' && <Badge tone="accent">seats</Badge>}
        {line.kind === 'item' && (
          <Badge tone="info">{line.description === 'Proration' ? 'proration' : 'item'}</Badge>
        )}
        {line.unpriced && <Badge tone="warning">not priced</Badge>}
      </span>
      {line.meter && <code className="small">{line.meter}</code>}
      {details.length > 0 && <span className="small muted">{details.join(' · ')}</span>}
    </span>,
    `${quantity(line.quantity)} ${line.unit}${line.quantity === 1 ? '' : 's'}`,
    unitPrice,
    money(line.amountMicros, currency),
  ];
  const tiers =
    line.tiers && line.tiers.length > 1
      ? line.tiers.map((tier) => [
          <span key="t" className="small muted" style={{ paddingLeft: 16 }}>
            {`Units ${quantity(tier.from)}${tier.to === null ? ' and above' : `–${quantity(tier.to)}`}`}
            {tier.flatAmountMicros ? ` (plus ${money(tier.flatAmountMicros, currency)} flat)` : ''}
          </span>,
          <span key="q" className="small muted">
            {quantity(tier.quantity)}
          </span>,
          <span key="u" className="small muted">
            {money(tier.unitAmountMicros, currency)}
          </span>,
          <span key="a" className="small muted">
            {money(tier.amountMicros, currency)}
          </span>,
        ])
      : [];
  return [main, ...tiers];
}

/** One invoice: its lines, discounts, credit, tax, payments, credit notes, bill-to details, and where usage came from. */
export default async function Statement({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const statement = await tryRead(() =>
    iam.api.billing.getStatement(auth, { tenantId, statementId: id }),
  );
  if (!statement)
    return (
      <Alert tone="warning">
        Invoice not found, or it needs <code>iam:billing:read</code>.
      </Alert>
    );
  const creditNotes =
    (await tryRead(() =>
      iam.api.billing.listCreditNotes(auth, { tenantId, statementId: statement.id }),
    )) ?? [];
  const { currency } = statement;
  const draft = statement.status === 'draft';
  const paidMicros =
    statement.amountPaidMicros ?? (statement.status === 'paid' ? statement.totalMicros : 0);
  const dueMicros =
    statement.status === 'void'
      ? 0
      : Math.max(0, statement.totalMicros - paidMicros - (statement.creditNotesMicros ?? 0));
  const exportHref = (kind: 'statement' | 'invoice') =>
    `/api/console/billing-export?${new URLSearchParams({ org, kind, statement: statement.id }).toString()}`;
  const totals: ReactNode[][] = [
    ['', '', <strong key="s">Subtotal</strong>, money(statement.subtotalMicros, currency)],
    ...(statement.discount
      ? [
          [
            '',
            '',
            `Discount (${statement.discount.percent}%)`,
            `− ${money(statement.discount.amountMicros, currency)}`,
          ],
        ]
      : []),
    ...(statement.commitment && statement.commitment.trueUpMicros > 0
      ? [
          [
            '',
            '',
            `Minimum commitment (${money(statement.commitment.minimumMicros, currency)}) true-up`,
            money(statement.commitment.trueUpMicros, currency),
          ],
        ]
      : []),
    ...(statement.coupons ?? []).map((coupon) => [
      '',
      '',
      coupon.name === coupon.code ? coupon.code : `${coupon.name} (${coupon.code})`,
      `− ${money(coupon.amountMicros, currency)}`,
    ]),
    ...(statement.creditsMicros
      ? [['', '', 'Credit applied', `− ${money(statement.creditsMicros, currency)}`]]
      : []),
    ...(statement.tax
      ? [
          [
            '',
            '',
            `${statement.tax.label} (${statement.tax.ratePercent}%)`,
            money(statement.tax.amountMicros, currency),
          ],
        ]
      : []),
    [
      '',
      '',
      <strong key="t">Total</strong>,
      <strong key="v">{money(statement.totalMicros, currency)}</strong>,
    ],
    ...(paidMicros ? [['', '', 'Paid', `− ${money(paidMicros, currency)}`]] : []),
    ...(statement.creditNotesMicros
      ? [['', '', 'Credit notes', `− ${money(statement.creditNotesMicros, currency)}`]]
      : []),
    ...(!draft && statement.status !== 'void'
      ? [
          [
            '',
            '',
            <strong key="d">Amount due</strong>,
            <strong key="v">{money(dueMicros, currency)}</strong>,
          ],
        ]
      : []),
  ];
  const usage = statement.lines.some((line) => (line.kind ?? 'usage') === 'usage');
  return (
    <>
      <PageHeader
        title={draft ? 'Draft invoice' : `Invoice ${statement.number}`}
        description={`${statement.billTo.name} · ${periodLabel(statement.period)}${statement.billingReason === 'subscription' ? ' · new subscription' : ''}`}
        actions={
          <>
            <a
              className="btn small secondary"
              href={exportHref('invoice')}
              target="_blank"
              rel="noreferrer"
            >
              Print or save as PDF
            </a>
            <a className="btn small secondary" href={exportHref('statement')}>
              Download CSV
            </a>
            <Link className="btn small secondary" href={`${base}/billing`}>
              Back to billing
            </Link>
          </>
        }
      />
      {draft && (
        <Alert tone="info">
          This invoice is a draft: it is recomputed with the latest usage and invoice items until
          the platform finalizes it, so amounts may still change.
        </Alert>
      )}
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card title="Charges" flush>
            <Table
              head={['Description', 'Quantity', 'Unit price', 'Amount']}
              rows={[...statement.lines.flatMap((line) => lineRows(line, currency)), ...totals]}
              empty="Nothing billed."
            />
          </Card>
          {(statement.payments ?? []).length > 0 && (
            <Card title="Payments" flush>
              <Table
                head={['Received', 'Method', 'Reference', 'Amount']}
                rows={statement.payments!.map((payment) => [
                  <Time key="r" value={payment.receivedAt} />,
                  payment.method,
                  payment.reference ?? '—',
                  <span key="a" className="stack" style={{ gap: 2 }}>
                    {money(payment.amountMicros, currency)}
                    {payment.overpaymentMicros ? (
                      <span className="small muted">
                        {money(payment.overpaymentMicros, currency)} kept as credit
                      </span>
                    ) : null}
                  </span>,
                ])}
              />
            </Card>
          )}
          {creditNotes.length > 0 && (
            <Card title="Credit notes" flush>
              <Table
                head={['Number', 'Reason', 'Applied', 'Amount']}
                rows={creditNotes.map((note) => [
                  <span key="n" className="stack" style={{ gap: 2 }}>
                    <code className="small">{note.number}</code>
                    <Time value={note.issuedAt} />
                  </span>,
                  <span key="r" className="stack" style={{ gap: 2 }}>
                    {note.reason.replace('_', ' ')}
                    {note.memo && <span className="small muted">{note.memo}</span>}
                  </span>,
                  <span key="a" className="small">
                    {[
                      note.applied.dueMicros
                        ? `${money(note.applied.dueMicros, currency)} off the amount due`
                        : '',
                      note.applied.creditMicros
                        ? `${money(note.applied.creditMicros, currency)} as credit`
                        : '',
                      note.applied.refundMicros
                        ? `${money(note.applied.refundMicros, currency)} refunded`
                        : '',
                    ]
                      .filter(Boolean)
                      .join(' · ')}
                  </span>,
                  money(note.amountMicros, currency),
                ])}
              />
            </Card>
          )}
          {usage && (
            <>
              <Card title="Usage by project" flush>
                <Allocations entries={statement.breakdown.tenants} currency={currency} empty="—" />
              </Card>
              <Card
                title="Usage by team"
                description="Shared evenly for people in several teams."
                flush
              >
                <Allocations
                  entries={statement.breakdown.teams}
                  currency={currency}
                  empty="No usage by team members."
                />
              </Card>
              <Card title="Usage by department" flush>
                <Allocations
                  entries={statement.breakdown.departments}
                  currency={currency}
                  empty="No usage by people with a department."
                  costCenters
                />
              </Card>
              <Card title="Usage by person or account" description="The 50 largest." flush>
                <Allocations
                  entries={statement.breakdown.identities}
                  currency={currency}
                  empty="No attributed usage."
                />
              </Card>
            </>
          )}
        </div>
        <div className="stack">
          <Card title="Status">
            <KeyValues
              items={[
                [
                  'Status',
                  <span key="s" className="row">
                    <Badge tone={invoiceTone(statement.status)}>{statement.status}</Badge>
                    {statement.overdue && <Badge tone="danger">overdue</Badge>}
                  </span>,
                ],
                ...(!draft && statement.status !== 'void'
                  ? ([['Amount due', money(dueMicros, currency)]] as [string, string][])
                  : []),
                [draft ? 'Drawn up' : 'Issued', <Time key="i" value={statement.issuedAt} />],
                ['Due', <Time key="d" value={statement.dueAt} />],
                ['Paid', <Time key="p" value={statement.paidAt} />],
                ...(statement.paymentReference
                  ? [['Reference', statement.paymentReference] as [string, string]]
                  : []),
                ...(statement.markedUncollectibleAt
                  ? [
                      ['Written off', <Time key="u" value={statement.markedUncollectibleAt} />] as [
                        string,
                        ReactNode,
                      ],
                    ]
                  : []),
                ...(statement.voidReason
                  ? [['Void because', statement.voidReason] as [string, string]]
                  : []),
                ...((statement.reminders ?? []).length
                  ? [
                      [
                        'Reminders',
                        statement
                          .reminders!.map((reminder) =>
                            reminder.days < 0
                              ? `${-reminder.days} days before`
                              : reminder.days === 0
                                ? 'on the due date'
                                : `${reminder.days} days late`,
                          )
                          .join(', '),
                      ] as [string, string],
                    ]
                  : []),
                [
                  'Integrity',
                  draft ? (
                    <span key="v" className="muted">
                      sealed when finalized
                    </span>
                  ) : statement.verified ? (
                    <Badge key="v" tone="success">
                      content hash verified
                    </Badge>
                  ) : (
                    <Badge key="v" tone="danger">
                      content changed after issue
                    </Badge>
                  ),
                ],
              ]}
            />
          </Card>
          <Card title="Billed to">
            <KeyValues
              items={[
                ['Account', statement.billTo.name],
                ['Company', statement.billTo.companyName ?? '—'],
                ['Tax ID', statement.billTo.taxId ?? '—'],
                ['Purchase order', statement.billTo.purchaseOrder ?? '—'],
                ['Cost center', statement.billTo.costCenter ?? '—'],
                ['Address', statement.billTo.address ?? '—'],
                ['Sent to', statement.billTo.emails.join(', ') || '—'],
              ]}
            />
          </Card>
          {statement.creditsApplied.length > 0 && (
            <Card title="Credit drawn" flush>
              <Table
                head={['Credit', 'Amount']}
                rows={statement.creditsApplied.map((entry) => [
                  <code key="c" className="small">
                    {entry.creditId.slice(0, 8)}
                  </code>,
                  money(entry.amountMicros, currency),
                ])}
              />
            </Card>
          )}
          {statement.carryForward && (
            <Alert tone="info">
              Credit items exceeded the charges:{' '}
              {money(statement.carryForward.amountMicros, currency)} was added to the account&apos;s
              credit for later invoices.
            </Alert>
          )}
        </div>
      </div>
    </>
  );
}
