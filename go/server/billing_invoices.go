package server

// Skeleton of packages/server/src/billing-invoices.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"github.com/Better-IAM/better-iam/go/core"
)

// CouponCode (billing-invoices.ts couponCode): A coupon code: 3-32 letters, digits, `-` or `_` (stored in upper
// case).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CouponCode(value any) (result string, err error) {
	err = notImplemented("billing-invoices.ts couponCode")
	return
}

// CouponSettings (billing-invoices.ts couponSettings): Validated coupon settings: `percentOff` or `amountOff`, a
// duration, and redemption limits.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CouponSettings(input *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("billing-invoices.ts couponSettings")
	return
}

// CreditNoteReason (billing-invoices.ts creditNoteReason): A credit note reason (Stripe's list).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CreditNoteReason(value any) (result string, err error) {
	err = notImplemented("billing-invoices.ts creditNoteReason")
	return
}

// InvoiceItemInput (billing-invoices.ts invoiceItemInput): Validated invoice item input: description, unit amount
// (currency units, negative for a credit), quantity, period.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func InvoiceItemInput(input *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing-invoices.ts invoiceItemInput")
	return
}

// RenderInvoiceHtml (billing-invoices.ts renderInvoiceHtml): The invoice as a standalone HTML page (print it or save
// it as PDF): issuer, bill-to, number and dates, lines with tier sub-lines and service periods, discounts,
// commitment, credit, tax, payments, credit notes, and amount due.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RenderInvoiceHtml(statement *core.Object, options *core.Object) (result string, err error) {
	err = notImplemented("billing-invoices.ts renderInvoiceHtml")
	return
}
