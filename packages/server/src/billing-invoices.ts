import { IamError } from '@better-iam/core';
import {
  amountDue,
  amountPaid,
  billingPeriod,
  roundCents,
  roundMicros,
  unitsOf,
  type BillingCoupon,
  type BillingCreditNote,
  type BillingStatement,
  type CreditNoteReason,
  type InvoiceIssuer,
  type StatementLine,
} from './billing.js';
import { integer, object, text } from './validation.js';

/**
 * Invoicing helpers without storage: validation of invoice items, coupons and credit notes, and the printable invoice
 * (HTML a browser can save as PDF, like a hosted invoice page). The transactional side lives in billing-service.ts.
 */

/** An amount in currency units that may be negative (a credit item), as micros. */
export function signedAmountMicros(value: unknown, name: string): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || Math.abs(value) > 1e9)
    throw new IamError('INVALID_INPUT', `${name} must be an amount from -1000000000 to 1000000000`);
  return roundMicros(value * 1_000_000);
}

/** Validated invoice item input: description, unit amount (currency units, negative for a credit), quantity, period. */
export function invoiceItemInput(input: Record<string, unknown>) {
  const description = text(input.description, 'description', 256).trim();
  const unitAmountMicros = signedAmountMicros(input.amount, 'amount');
  const quantity = input.quantity === undefined ? 1 : input.quantity;
  if (typeof quantity !== 'number' || !Number.isFinite(quantity) || quantity <= 0 || quantity > 1e9)
    throw new IamError('INVALID_INPUT', 'quantity must be a positive number');
  const period = input.period === undefined ? undefined : billingPeriod(input.period);
  let metadata: Record<string, string> | undefined;
  if (input.metadata !== undefined) {
    const entries = Object.entries(object(input.metadata));
    if (entries.length > 20)
      throw new IamError('INVALID_INPUT', 'metadata may hold at most 20 entries');
    metadata = Object.fromEntries(
      entries.map(([key, raw]) => [
        text(key, 'metadata key', 64),
        text(raw, `metadata.${key}`, 256),
      ]),
    );
  }
  return {
    description,
    quantity,
    unitAmountMicros,
    amountMicros: roundCents(unitAmountMicros * quantity),
    ...(period ? { period } : {}),
    ...(metadata ? { metadata } : {}),
  };
}

const couponCodePattern = /^[A-Z0-9][A-Z0-9_-]{2,31}$/;
/** A coupon code: 3-32 letters, digits, `-` or `_` (stored in upper case). */
export function couponCode(value: unknown): string {
  const code = typeof value === 'string' ? value.trim().toUpperCase() : '';
  if (!couponCodePattern.test(code))
    throw new IamError('INVALID_INPUT', 'code must be 3-32 letters, digits, - or _');
  return code;
}

/** Validated coupon settings: `percentOff` or `amountOff`, a duration, and redemption limits. */
export function couponSettings(
  input: Record<string, unknown>,
  now: number,
): Pick<
  BillingCoupon,
  | 'code'
  | 'name'
  | 'duration'
  | 'percentOff'
  | 'amountOffMicros'
  | 'durationInMonths'
  | 'maxRedemptions'
  | 'redeemBy'
> {
  const code = couponCode(input.code);
  const name = input.name === undefined ? code : text(input.name, 'name', 128).trim();
  const hasPercent = input.percentOff !== undefined && input.percentOff !== null;
  const hasAmount = input.amountOff !== undefined && input.amountOff !== null;
  if (hasPercent === hasAmount)
    throw new IamError('INVALID_INPUT', 'Give either percentOff or amountOff');
  let percentOff: number | undefined;
  if (hasPercent) {
    const value = input.percentOff;
    if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0 || value > 100)
      throw new IamError('INVALID_INPUT', 'percentOff must be above 0 and at most 100');
    percentOff = Math.round(value * 1000) / 1000;
  }
  let amountOffMicros: number | undefined;
  if (hasAmount) {
    const micros = signedAmountMicros(input.amountOff, 'amountOff');
    if (micros <= 0) throw new IamError('INVALID_INPUT', 'amountOff must be above 0');
    amountOffMicros = micros;
  }
  const duration = input.duration ?? 'once';
  if (duration !== 'once' && duration !== 'repeating' && duration !== 'forever')
    throw new IamError('INVALID_INPUT', "duration must be 'once', 'repeating' or 'forever'");
  const durationInMonths =
    duration === 'repeating'
      ? integer(input.durationInMonths, 'durationInMonths', 1, 120)
      : undefined;
  if (duration !== 'repeating' && input.durationInMonths !== undefined)
    throw new IamError('INVALID_INPUT', 'durationInMonths is only for repeating coupons');
  const maxRedemptions =
    input.maxRedemptions === undefined
      ? undefined
      : integer(input.maxRedemptions, 'maxRedemptions', 1, 1_000_000);
  const redeemBy =
    input.redeemBy === undefined
      ? undefined
      : integer(input.redeemBy, 'redeemBy', now + 1, Number.MAX_SAFE_INTEGER);
  return {
    code,
    name,
    duration,
    ...(percentOff !== undefined ? { percentOff } : {}),
    ...(amountOffMicros !== undefined ? { amountOffMicros } : {}),
    ...(durationInMonths !== undefined ? { durationInMonths } : {}),
    ...(maxRedemptions !== undefined ? { maxRedemptions } : {}),
    ...(redeemBy !== undefined ? { redeemBy } : {}),
  };
}

const creditNoteReasons: CreditNoteReason[] = [
  'duplicate',
  'fraudulent',
  'order_change',
  'product_unsatisfactory',
  'other',
];
/** A credit note reason (Stripe's list). */
export function creditNoteReason(value: unknown): CreditNoteReason {
  const reason = (value ?? 'other') as CreditNoteReason;
  if (!creditNoteReasons.includes(reason))
    throw new IamError('INVALID_INPUT', `reason must be one of ${creditNoteReasons.join(', ')}`);
  return reason;
}

const escape = (value: string) =>
  value.replace(
    /[&<>"']/g,
    (character) =>
      ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]!,
  );

/** Money for invoices: cents, or six decimals for fractions of a cent (per-token and per-call prices). */
function formatter(currency: string) {
  return (micros: number) => {
    const digits = micros !== 0 && Math.abs(micros) < 10_000 ? 6 : 2;
    const units = digits === 2 ? unitsOf(micros) : micros / 1_000_000;
    try {
      return new Intl.NumberFormat('en-US', {
        style: 'currency',
        currency,
        minimumFractionDigits: digits,
        maximumFractionDigits: digits,
      }).format(units);
    } catch {
      return `${currency} ${units.toFixed(digits)}`;
    }
  };
}

const day = (at: number) => new Date(at).toISOString().slice(0, 10);
const quantityText = (value: number) => value.toLocaleString('en-US', { maximumFractionDigits: 4 });

function lineRows(line: StatementLine, money: (micros: number) => string): string {
  const unit =
    line.unitAmountMicros !== undefined
      ? money(line.unitAmountMicros)
      : line.tiers?.length === 1
        ? money(line.tiers[0]!.unitAmountMicros)
        : '';
  const details: string[] = [];
  if (line.servicePeriod)
    details.push(`${day(line.servicePeriod.start)} to ${day(line.servicePeriod.end - 1)}`);
  if (line.proration !== undefined)
    details.push(`${Math.round(line.proration * 1000) / 10}% of the month`);
  if (line.includedQuantity) details.push(`${quantityText(line.includedQuantity)} included`);
  if (line.price?.source === 'plan') details.push('plan price');
  if (line.adjustedFromMicros !== undefined)
    details.push(`adjusted from ${money(line.adjustedFromMicros)}`);
  const main = `<tr><td>${escape(line.name)}${details.length ? `<div class="muted">${escape(details.join(' · '))}</div>` : ''}</td><td class="num">${escape(quantityText(line.quantity))} ${escape(line.unit)}</td><td class="num">${escape(unit)}</td><td class="num">${escape(money(line.amountMicros))}</td></tr>`;
  const tiers =
    line.tiers && line.tiers.length > 1
      ? line.tiers
          .map(
            (tier) =>
              `<tr class="tier"><td>${escape(`Units ${quantityText(tier.from)}${tier.to === null ? ' and above' : `–${quantityText(tier.to)}`}`)}${tier.flatAmountMicros ? `<div class="muted">${escape(`plus ${money(tier.flatAmountMicros)} flat`)}</div>` : ''}</td><td class="num">${escape(quantityText(tier.quantity))}</td><td class="num">${escape(money(tier.unitAmountMicros))}</td><td class="num">${escape(money(tier.amountMicros))}</td></tr>`,
          )
          .join('')
      : '';
  return main + tiers;
}

/**
 * The invoice as a standalone HTML page (print it or save it as PDF): issuer, bill-to, number and dates, lines with
 * tier sub-lines and service periods, discounts, commitment, credit, tax, payments, credit notes, and amount due.
 */
export function renderInvoiceHtml(
  statement: BillingStatement,
  options: { issuer?: InvoiceIssuer; appName?: string; creditNotes?: BillingCreditNote[] } = {},
): string {
  const money = formatter(statement.currency);
  const issuer = options.issuer ?? { name: options.appName ?? 'Better IAM' };
  const title =
    statement.status === 'draft'
      ? `Draft invoice · ${statement.period}`
      : `Invoice ${statement.number}`;
  const totals: [string, string, string?][] = [['Subtotal', money(statement.subtotalMicros)]];
  if (statement.discount)
    totals.push([
      `Discount (${statement.discount.percent}%)`,
      money(-statement.discount.amountMicros),
    ]);
  if (statement.commitment && statement.commitment.trueUpMicros > 0)
    totals.push([
      `Minimum commitment (${money(statement.commitment.minimumMicros)}) true-up`,
      money(statement.commitment.trueUpMicros),
    ]);
  for (const coupon of statement.coupons ?? [])
    totals.push([
      coupon.name === coupon.code ? coupon.code : `${coupon.name} (${coupon.code})`,
      money(-coupon.amountMicros),
    ]);
  if (statement.creditsMicros) totals.push(['Credit applied', money(-statement.creditsMicros)]);
  if (statement.tax)
    totals.push([
      `${statement.tax.label} (${statement.tax.ratePercent}%)`,
      money(statement.tax.amountMicros),
    ]);
  totals.push(['Total', money(statement.totalMicros), 'strong']);
  const paid = amountPaid(statement);
  if (paid) totals.push(['Paid', money(-paid)]);
  if (statement.creditNotesMicros)
    totals.push(['Credit notes', money(-statement.creditNotesMicros)]);
  totals.push(['Amount due', money(amountDue(statement)), 'strong']);
  const billTo = statement.billTo;
  const status =
    statement.status === 'finalized'
      ? statement.dueAt < Date.now()
        ? 'Overdue'
        : 'Open'
      : statement.status[0]!.toUpperCase() + statement.status.slice(1);
  const block = (lines: (string | undefined)[]) =>
    lines
      .filter((line): line is string => Boolean(line))
      .map((line) => escape(line).replace(/\n/g, '<br>'))
      .join('<br>');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>${escape(title)}</title><meta name="viewport" content="width=device-width, initial-scale=1"><style>
body{font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#111;margin:0;background:#f5f6f8}
main{max-width:800px;margin:24px auto;background:#fff;padding:40px;border-radius:8px}
h1{font-size:22px;margin:0}header{display:flex;justify-content:space-between;gap:24px;margin-bottom:32px}
.muted{color:#666;font-size:12px}.parties{display:flex;justify-content:space-between;gap:24px;margin-bottom:24px;font-size:14px}
table{width:100%;border-collapse:collapse;font-size:14px}th{text-align:left;border-bottom:1px solid #ddd;padding:8px 4px;font-weight:600}
td{padding:8px 4px;border-bottom:1px solid #f0f0f0;vertical-align:top}.num{text-align:right;white-space:nowrap}
tr.tier td{color:#555;font-size:12px;padding-left:20px}.totals{margin-left:auto;width:320px;margin-top:16px}
.totals td{border:none;padding:4px}.totals .strong td{font-weight:700;border-top:1px solid #ddd}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;background:#eef;font-size:12px}
.notes{margin-top:24px;font-size:13px;white-space:pre-wrap}@media print{body{background:#fff}main{margin:0;box-shadow:none}}
</style></head><body><main>
<header><div><h1>${escape(title)}</h1><div class="muted">${escape(`${statement.period} · issued ${day(statement.issuedAt)} · due ${day(statement.dueAt)}`)}</div></div><div><span class="badge">${escape(status)}</span></div></header>
<section class="parties"><div><strong>${escape(issuer.name)}</strong><br>${block([issuer.address, issuer.taxId ? `Tax ID ${issuer.taxId}` : undefined, issuer.email, issuer.url])}</div>
<div><span class="muted">Bill to</span><br><strong>${escape(billTo.companyName ?? billTo.name)}</strong><br>${block([billTo.address, billTo.taxId ? `Tax ID ${billTo.taxId}` : undefined, billTo.purchaseOrder ? `PO ${billTo.purchaseOrder}` : undefined, billTo.costCenter ? `Cost center ${billTo.costCenter}` : undefined, billTo.emails.join(', ') || undefined])}</div></section>
<table><thead><tr><th>Description</th><th class="num">Quantity</th><th class="num">Unit price</th><th class="num">Amount</th></tr></thead><tbody>
${statement.lines.map((line) => lineRows(line, money)).join('\n')}
</tbody></table>
<table class="totals"><tbody>${totals
    .map(
      ([label, value, strong]) =>
        `<tr${strong ? ' class="strong"' : ''}><td>${escape(label)}</td><td class="num">${escape(value)}</td></tr>`,
    )
    .join('')}</tbody></table>
${(statement.payments ?? []).length ? `<h3>Payments</h3><table><tbody>${statement.payments!.map((payment) => `<tr><td>${escape(day(payment.receivedAt))}</td><td>${escape(payment.method)}${payment.reference ? ` · ${escape(payment.reference)}` : ''}</td><td class="num">${escape(money(payment.amountMicros))}</td></tr>`).join('')}</tbody></table>` : ''}
${(options.creditNotes ?? []).length ? `<h3>Credit notes</h3><table><tbody>${options.creditNotes!.map((note) => `<tr><td>${escape(note.number)}</td><td>${escape(note.reason.replace('_', ' '))}${note.memo ? ` · ${escape(note.memo)}` : ''}</td><td class="num">${escape(money(note.amountMicros))}</td></tr>`).join('')}</tbody></table>` : ''}
${issuer.paymentInstructions ? `<div class="notes">${escape(issuer.paymentInstructions)}</div>` : ''}
${statement.hash ? `<p class="muted">Content hash ${escape(statement.hash)}</p>` : ''}
</main></body></html>`;
}
