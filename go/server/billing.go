package server

// Skeleton of packages/server/src/billing.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AccountOf (billing.ts accountOf): The billing account of a tenant: the nearest tenant (itself or above) with a
// profile, else its organization.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AccountOf(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing.ts accountOf")
	return
}

// AccountSpend (billing.ts accountSpend): Prices every meter used in an account's tenants during a period and
// allocates the cost to the usage.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AccountSpend(ctx context.Context, server *ServerContext, tx core.IamStore, account *core.Object, period string, cache map[string]any) (result *core.Object, err error) {
	err = notImplemented("billing.ts accountSpend")
	return
}

// AccountTermsOf (billing.ts accountTermsOf): The contract terms a billing account's invoices use: its own, else the
// discount and tax of the nearest ancestor with terms, so a sub-account carved out of an organization stays under
// the organization's contract. A minimum commitment is not inherited (each sub-account would owe it again): it stays
// with the account it was set on, which is invoiced for it even in a month without usage.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AccountTermsOf(ctx context.Context, server *ServerContext, tx core.IamStore, account *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing.ts accountTermsOf")
	return
}

// AmountDue (billing.ts amountDue): What is still owed on an invoice: its total less payments and credit notes
// (never below 0).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AmountDue(statement *core.Object) (result float64, err error) {
	err = notImplemented("billing.ts amountDue")
	return
}

// AmountMicros (billing.ts amountMicros): An amount in currency units (a price or a budget) as micros: finite, 0 to
// one billion units.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AmountMicros(value any, name string) (result float64, err error) {
	err = notImplemented("billing.ts amountMicros")
	return
}

// AmountPaid (billing.ts amountPaid): Payments received on an invoice; invoices marked paid before payments were
// recorded count as fully paid.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AmountPaid(statement *core.Object) (result float64, err error) {
	err = notImplemented("billing.ts amountPaid")
	return
}

// AttributionFor (billing.ts attributionFor): Resolves attribution for an identity recording or causing usage in
// `tenant`. The identity must belong to the tenant or one of its ancestors and not be deleted. An agent's usage is
// attributed to the agent and to its sponsor's teams and department; `teamId` (a team of the identity's tenant)
// replaces the person's own teams.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AttributionFor(ctx context.Context, server *ServerContext, tx core.IamStore, chain []*core.Object, input *core.Object, settings *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing.ts attributionFor")
	return
}

// BillingPeriod (billing.ts billingPeriod): A billing period `YYYY-MM`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BillingPeriod(value any, name string) (result string, err error) {
	err = notImplemented("billing.ts billingPeriod")
	return
}

// BillingSettings (billing.ts billingSettings): Validates the `billing` option; a bad value fails construction with
// INVALID_CONFIG.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BillingSettings(options *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing.ts billingSettings")
	return
}

// BudgetThresholds (billing.ts budgetThresholds): Validates budget thresholds: 1-10 distinct percentages from 1 to
// 1000, ascending.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func BudgetThresholds(value any) (result []float64, err error) {
	err = notImplemented("billing.ts budgetThresholds")
	return
}

// DayOf (billing.ts dayOf): The local day `YYYY-MM-DD` an instant falls on.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DayOf(at int64, timeZone string) (result string, err error) {
	err = notImplemented("billing.ts dayOf")
	return
}

// DirectoryFor (billing.ts directoryFor): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DirectoryFor(ctx context.Context, tx core.IamStore, tenantIDs []string) (result *core.Object, err error) {
	err = notImplemented("billing.ts directoryFor")
	return
}

// DiscountActive (billing.ts discountActive): Whether a redeemed coupon discounts an invoice for `period`: `once`
// until one invoice used it, `repeating` for the invoices of `durationInMonths` months from the month it was
// redeemed, `forever` until removed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func DiscountActive(discount *core.Object, period string, timeZone string) (result bool, err error) {
	err = notImplemented("billing.ts discountActive")
	return
}

// InDepartment (billing.ts inDepartment): Whether a row's department is `departmentId` or (with `rollUp`) a
// department below it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func InDepartment(row *core.Object, departmentID string, directory *core.Object, rollUp bool) (result bool, err error) {
	err = notImplemented("billing.ts inDepartment")
	return
}

// InvoiceAmounts (billing.ts invoiceAmounts): Turns an invoice's subtotal into its total, in order: the contract
// discount, the minimum-commitment true-up (monthly invoices only), coupon discounts, credit, and tax on what is
// left. A negative balance (credit items larger than the charges) comes back as `carryForwardMicros` for account
// credit, and the total stays 0.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func InvoiceAmounts(input any) (result *core.Object, err error) {
	err = notImplemented("billing.ts invoiceAmounts")
	return
}

// MeterKey (billing.ts meterKey): A meter key: 1-64 lowercase letters, digits, `.`, `_` or `-`, starting with a
// letter.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MeterKey(value any) (result string, err error) {
	err = notImplemented("billing.ts meterKey")
	return
}

// MeterSettings (billing.ts meterSettings): Validated meter settings; `current` supplies values an update leaves
// out.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MeterSettings(input *core.Object, current *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing.ts meterSettings")
	return
}

// MetersFor (billing.ts metersFor): Every meter that reaches a tenant, keyed by key (ancestors nearest the root win
// a shared key).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MetersFor(ctx context.Context, tx core.IamStore, chain []*core.Object) (result map[string]*core.Object, err error) {
	err = notImplemented("billing.ts metersFor")
	return
}

// OverlapShare (billing.ts overlapShare): The share (0-1, four decimals) of `[start, end)` that `[from, to)` covers.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OverlapShare(start float64, end float64, from float64, to float64) (result float64, err error) {
	err = notImplemented("billing.ts overlapShare")
	return
}

// PeriodBounds (billing.ts periodBounds): The first instant of a period and of the next one.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PeriodBounds(period string, timeZone string) (result *core.Object, err error) {
	err = notImplemented("billing.ts periodBounds")
	return
}

// PeriodOf (billing.ts periodOf): The billing period an instant falls in.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PeriodOf(at int64, timeZone string) (result string, err error) {
	err = notImplemented("billing.ts periodOf")
	return
}

// PriceBreakdown (billing.ts priceBreakdown): How a quantity is priced, tier by tier, for invoice sub-lines: the
// tiers used, the free units, and what the tiers came to before the price's minimum or maximum.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PriceBreakdown(spec *core.Object, quantity float64) (result *core.Object, err error) {
	err = notImplemented("billing.ts priceBreakdown")
	return
}

// PriceFor (billing.ts priceFor): The price of a meter for a tenant in a period: walking from `chain[0]` up to the
// meter's defining tenant, the first tenant with an entry effective by then (the latest such entry).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PriceFor(ctx context.Context, tx core.IamStore, meter *core.Object, chain []*core.Object, period string) (result *core.Object, err error) {
	err = notImplemented("billing.ts priceFor")
	return
}

// PriceQuantity (billing.ts priceQuantity): The amount, in micros, a period's quantity costs under a price: its
// tiers, then its minimum and maximum.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PriceQuantity(spec *core.Object, quantity float64) (result float64, err error) {
	err = notImplemented("billing.ts priceQuantity")
	return
}

// PriceSpec (billing.ts priceSpec): Validates a price given in currency units (`unitAmount`, `tiers[].unitAmount` /
// `flatAmount`, `packageAmount`) and returns it in micros. Tiers ascend by `upTo`, and the last one has `upTo:
// null`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PriceSpec(value any) (result *core.Object, err error) {
	err = notImplemented("billing.ts priceSpec")
	return
}

// ProfileOf (billing.ts profileOf): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ProfileOf(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("billing.ts profileOf")
	return
}

// PublicPriceSpec (billing.ts publicPriceSpec): A price in currency units, as the API shows it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PublicPriceSpec(spec *core.Object) (result *core.Object, err error) {
	err = notImplemented("billing.ts publicPriceSpec")
	return
}

// ResolveMeter (billing.ts resolveMeter): The meter a key names for a tenant: the one its ancestor nearest the root
// defines.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ResolveMeter(ctx context.Context, tx core.IamStore, chain []*core.Object, key string) (result *core.Object, err error) {
	err = notImplemented("billing.ts resolveMeter")
	return
}

// RollupID (billing.ts rollupId): Deterministic id of the daily bucket for a usage attribution.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RollupID(tenantID string, day string, meterID string, attribution *core.Object) (result string, err error) {
	err = notImplemented("billing.ts rollupId")
	return
}

// RoundCents (billing.ts roundCents): Micros rounded to a whole cent. Invoice amounts (lines, items, discounts, tax)
// are kept in cents so what an invoice shows adds up; spend reports keep fractions of a cent.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RoundCents(micros float64) (result float64, err error) {
	err = notImplemented("billing.ts roundCents")
	return
}

// RoundMicros (billing.ts roundMicros): Rounds micro amounts to a thousandth of a micro (prices per token are
// fractions of a micro).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RoundMicros(value float64) (result float64, err error) {
	err = notImplemented("billing.ts roundMicros")
	return
}

// ScopeSpend (billing.ts scopeSpend): Spend of a tenant's subtree in a period: the charged usage of every tenant
// below (and including) it, priced within the billing account each tenant belongs to. For the root this is the whole
// platform.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ScopeSpend(ctx context.Context, server *ServerContext, tx core.IamStore, scope *core.Object, period string, cache map[string]any) (result *core.Object, err error) {
	err = notImplemented("billing.ts scopeSpend")
	return
}

// ShiftPeriod (billing.ts shiftPeriod): A period `months` after (or before, when negative) another.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ShiftPeriod(period string, months float64) (result string, err error) {
	err = notImplemented("billing.ts shiftPeriod")
	return
}

// StatementHash (billing.ts statementHash): Statement content hash: what it bills, to whom, under which number
// (payment status is left out).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func StatementHash(statement *core.Object) (result string, err error) {
	err = notImplemented("billing.ts statementHash")
	return
}

// SubscriptionStatus (billing.ts subscriptionStatus): A subscription's state at an instant.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SubscriptionStatus(subscription *core.Object, now int64) (result string, err error) {
	err = notImplemented("billing.ts subscriptionStatus")
	return
}

// Subtree (billing.ts subtree): A tenant and every tenant below it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Subtree(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object) (result []*core.Object, err error) {
	err = notImplemented("billing.ts subtree")
	return
}

// TeamShare (billing.ts teamShare): The share of a row's cost that counts toward `teamId` (and the teams above it
// when `rollUp`).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TeamShare(row *core.Object, teamID string, directory *core.Object, settings *core.Object, rollUp bool) (result float64, err error) {
	err = notImplemented("billing.ts teamShare")
	return
}

// TermsOf (billing.ts termsOf): The contract terms of a billing account, if the platform set any.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TermsOf(ctx context.Context, tx core.IamStore, accountID string) (result *core.Object, err error) {
	err = notImplemented("billing.ts termsOf")
	return
}

// UnitsOf (billing.ts unitsOf): Micros as currency units, rounded to the cent.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UnitsOf(micros float64) (result float64, err error) {
	err = notImplemented("billing.ts unitsOf")
	return
}

// UsageExpiry (billing.ts usageExpiry): Retention of a usage event recorded for `period`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UsageExpiry(period string, settings *core.Object) (result float64, err error) {
	err = notImplemented("billing.ts usageExpiry")
	return
}

// UsageTags (billing.ts usageTags): Validated tags: at most 10, keys like `project` or `env.name`, values up to 128
// characters.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func UsageTags(value any) (result *core.Object, err error) {
	err = notImplemented("billing.ts usageTags")
	return
}

// WindowPeriods (billing.ts windowPeriods): The periods of the budget window containing `period`: the month, its
// calendar quarter, or its year.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WindowPeriods(kind string, period string) (result []string, err error) {
	err = notImplemented("billing.ts windowPeriods")
	return
}

// BillingCollections is billing.ts billingCollections.
var BillingCollections = struct {
	Meters        string
	Prices        string
	Usage         string
	Rollups       string
	Budgets       string
	BudgetAlerts  string
	Credits       string
	Profiles      string
	Statements    string
	Terms         string
	InvoiceItems  string
	CreditNotes   string
	Plans         string
	Subscriptions string
	Coupons       string
	Discounts     string
}{"billingMeters", "billingPrices", "billingUsage", "billingRollups", "billingBudgets", "billingBudgetAlerts", "billingCredits", "billingProfiles", "billingStatements", "billingTerms", "billingInvoiceItems", "billingCreditNotes", "billingPlans", "billingSubscriptions", "billingCoupons", "billingDiscounts"}

// MaxMetersPerTenant is billing.ts maxMetersPerTenant.
const MaxMetersPerTenant = 100
